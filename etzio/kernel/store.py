"""Durable append-only SQLite storage for canonical Etzio mission events."""

from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Final

from ..evidence import (
    MAX_AUTHORITY_EVIDENCE_BYTES_V1,
    EvidenceError,
    FileEvidenceStore,
)
from ..protocol import ProtocolError
from .events_v1 import GENESIS_DIGEST, EventIntegrityError, EventV1
from .evidence_vault import (
    AUTHORITY_EVIDENCE_ROLE_V1,
    DEFAULT_MAX_VAULT_BYTES_V1,
    GENERIC_IDENTITY_SCHEME_V1,
    GENERIC_TYPE_TAG_V1,
    MAX_EVENT_ARTIFACT_ROLES_V1,
    MAX_VAULT_ARTIFACT_BYTES_V1,
    MAX_VAULT_BATCH_REQUESTS_V1,
    NON_RECEIPT_EVIDENCE_EVENT_KINDS_V1,
    PROTECTED_EVIDENCE_EVENT_KINDS_V1,
    SINGLETON_VAULT_ROLES_V1,
    TARGET_SOURCE_ROLE_V1,
    TYPED_IDENTITY_SCHEME_V1,
    VAULT_ROLES_V1,
    VERIFICATION_EFFECT_ORACLE_SPEC_ROLE_V1,
    VERIFICATION_EFFECT_OUTPUT_ROLE_V1,
    VERIFICATION_ENVIRONMENT_SPEC_ROLE_V1,
    VERIFICATION_EXECUTION_OUTPUT_ROLE_V1,
    VERIFICATION_MEASURED_ENVIRONMENT_OUTPUT_ROLE_V1,
    VERIFICATION_POC_INPUT_ROLE_V1,
    VERIFICATION_SUPPORTING_EVIDENCE_INPUT_ROLE_V1,
    VERIFICATION_TERMINATION_OUTPUT_ROLE_V1,
    EvidenceVaultArtifactMissing,
    EvidenceVaultError,
    VaultArtifactRefV1,
    VaultArtifactResolutionRequestV1,
    VaultBackedFileEvidenceStore,
    VaultEventArtifactSelectorV1,
    derive_event_artifact_manifest_v1,
    digest_bytes_v1,
    digest_hasher_v1,
    vault_identity_for_role_v1,
)

TERMINAL_KINDS: Final = frozenset(
    {
        "mission_closed",
        "mission_admission_refused",
        "scan_failed",
        "scan_cancelled",
        "scan_timed_out",
        "budget_exhausted",
    }
)
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SQLITE_HEADER_MAGIC: Final = b"SQLite format 3\x00"
_SQLITE_HEADER_SIZE: Final = 100
_SQLITE_APPLICATION_ID: Final = 0x45545A31  # ASCII "ETZ1".
_SQLITE_SCHEMA_VERSION: Final = 1
_SET_SQLITE_APPLICATION_ID: Final = "PRAGMA application_id = 1163156017"
_SET_SQLITE_SCHEMA_VERSION: Final = "PRAGMA user_version = 1"
_SQLITE_SCHEMA_CONTRACT_SHA256: Final = "9d29c7abe7aef05db290cef46687eb19833c073d256558ff5ec555bbe9a04b90"
_VAULT_READ_CHUNK_BYTES: Final = 1024 * 1024
_CONCRETE_PATH_TYPE: Final = type(Path())


@dataclass(frozen=True, slots=True)
class _SQLiteJournalPolicy:
    journal_mode: str
    synchronous_name: str
    synchronous_value: int
    wal_reset_bug_fixed: bool


def _sqlite_wal_reset_bug_fixed(
    version_info: tuple[int, int, int],
) -> bool:
    """Return whether this SQLite release contains the 2026 WAL-reset fix.

    SQLite fixed the race in 3.51.3 and later, with explicit backports to the
    3.44.6 and 3.50.7 patch lines. Other releases in Etzio's supported 3.x
    range through 3.51.2 remain affected.
    """

    if (
        type(version_info) is not tuple
        or len(version_info) != 3
        or any(type(component) is not int or component < 0 for component in version_info)
    ):
        raise EventStoreError("SQLite exposed an invalid version tuple")
    if version_info[0] != 3 or version_info < (3, 37, 0):
        raise EventStoreError("SQLite exposed an unsupported library version")
    return (
        version_info >= (3, 51, 3) or (3, 50, 7) <= version_info < (3, 51, 0) or (3, 44, 6) <= version_info < (3, 45, 0)
    )


def _sqlite_journal_policy(
    version_info: tuple[int, int, int],
) -> _SQLiteJournalPolicy:
    """Select one safe journal policy for every supported Etzio runtime.

    Journal mode is persistent database state but cached per connection. Etzio therefore
    cannot safely mix WAL-capable and WAL-affected accessors against one database. Until
    every declared runtime contains the upstream fix, all accessors use rollback journaling.
    """

    return _SQLiteJournalPolicy(
        journal_mode="delete",
        synchronous_name="EXTRA",
        synchronous_value=3,
        wal_reset_bug_fixed=_sqlite_wal_reset_bug_fixed(version_info),
    )


class EventStoreError(ProtocolError):
    """Base class for durable event-store failures."""


class EventStoreCorruptionError(EventStoreError):
    """Raised when retained rows cannot reconstruct a valid canonical stream."""


class StoreBusyError(EventStoreError):
    """Raised when bounded SQLite lock acquisition ends in retryable contention."""


class StoreCapacityError(EventStoreError):
    """Raised when SQLite reports a storage, memory, or configured value-size limit."""


class EvidenceVaultCapacityError(StoreCapacityError):
    """Raised when new unique evidence would exceed the database vault ceiling."""


class StoreOperationalError(EventStoreError):
    """Raised for a non-corruption SQLite runtime or storage-operation failure.

    Unlike ``StoreBusyError``, this category is not automatically retryable. The caller
    must preserve the failure as operational state and escalate according to the concrete
    deployment adapter.
    """


class EvidenceVaultRequestError(EventStoreError):
    """Raised when one exact member of a vault-first batch cannot be resolved."""

    def __init__(self, request_index: int, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.request_index = request_index
        self.reason_code = reason_code


class StaleHeadError(EventStoreError):
    """Raised when compare-and-append observes a different mission head."""


class ClosedStreamError(EventStoreError):
    """Raised when an append targets a terminal mission stream."""


def _sqlite_store_failure(
    context: str,
    error: sqlite3.DatabaseError,
) -> EventStoreError:
    error_code = getattr(error, "sqlite_errorcode", None)
    if type(error_code) is int:
        primary_code = error_code & 0xFF
        if primary_code in {
            sqlite3.SQLITE_BUSY,
            sqlite3.SQLITE_LOCKED,
        }:
            return StoreBusyError(f"{context}: SQLite storage is busy")
        if primary_code in {
            sqlite3.SQLITE_FULL,
            sqlite3.SQLITE_NOMEM,
            sqlite3.SQLITE_TOOBIG,
        }:
            return StoreCapacityError(
                f"{context}: SQLite storage, memory, or value-size capacity was reached"
            )
        if primary_code in {
            sqlite3.SQLITE_CORRUPT,
            sqlite3.SQLITE_FORMAT,
            sqlite3.SQLITE_NOTADB,
        }:
            return EventStoreCorruptionError(f"{context}: {error}")
    return StoreOperationalError(f"{context}: SQLite operation failed: {error}")


@dataclass(frozen=True, slots=True)
class SignedCheckpoint:
    """Opaque signature data over a retained event head.

    Storage does not authenticate the signer, verify the signature, or claim external
    anchoring.  A later authority component can verify this data under an admitted key
    policy.
    """

    mission_id: str
    event_digest: str
    signer_id: str
    algorithm: str
    signed_at: int
    signature: bytes

    def __post_init__(self) -> None:
        if type(self.mission_id) is not str or _DIGEST_RE.fullmatch(self.mission_id) is None:
            raise EventStoreError("mission_id must be a full lowercase sha256 digest")
        for name in ("signer_id", "algorithm"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value or value != value.strip():
                raise EventStoreError(f"{name} must be non-empty text without edge whitespace")
        if not isinstance(self.event_digest, str) or _DIGEST_RE.fullmatch(self.event_digest) is None:
            raise EventStoreError("event_digest must be a full lowercase sha256 digest")
        if type(self.signed_at) is not int or self.signed_at < 0:
            raise EventStoreError("signed_at must be a non-negative integer")
        if type(self.signature) is not bytes or not self.signature:
            raise EventStoreError("signature must be non-empty immutable bytes")


@dataclass(frozen=True, slots=True)
class StoreDiagnostics:
    """A fixed, immutable read-only view of security-relevant store settings."""

    sqlite_version: str
    wal_reset_bug_fixed: bool
    journal_mode: str
    synchronous: int
    foreign_keys: bool
    trusted_schema: bool
    database_mode: int


@dataclass(frozen=True, slots=True)
class _PreparedStorePath:
    path: Path
    descriptor: int
    device: int
    inode: int


class SQLiteEventStore:
    """Mission-local compare-and-append streams in one explicit SQLite database.

    Every supported runtime uses rollback-journal ``DELETE`` mode with
    ``synchronous=EXTRA``. This uniform database-wide policy prevents a fixed-runtime
    Etzio accessor from placing shared state in WAL underneath an accessor whose SQLite
    release remains exposed to the 2026 WAL-reset defect. Every append obtains a
    ``BEGIN IMMEDIATE`` writer lock, verifies the complete existing mission stream and the
    proposed lifecycle transition, compares the caller's expected head, and commits one
    exact canonical event BLOB.

    The containing directory must already be private (owned by this process and mode
    ``0700``).  User-owned ancestors may not be group/world writable or symbolic links.
    The pre-open descriptor identity is checked against SQLite's path immediately after
    connection.  This narrows pathname replacement races, but Python's SQLite API cannot
    connect from an already-open file descriptor; a hostile process running as the same OS
    user can still race pathname operations.  Production deployment must therefore place
    the store under an isolated service identity and protected mount.
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        max_vault_bytes: int = DEFAULT_MAX_VAULT_BYTES_V1,
    ) -> None:
        if type(max_vault_bytes) is not int or max_vault_bytes <= 0 or max_vault_bytes > (2**63) - 1:
            raise EventStoreError("max_vault_bytes must be a positive signed-int64 byte ceiling")
        self._max_vault_bytes = max_vault_bytes
        self._journal_policy = _sqlite_journal_policy(
            sqlite3.sqlite_version_info,
        )
        prepared = self._prepare_path(path)
        self.path = prepared.path
        try:
            self._refuse_preexisting_wal(prepared.descriptor)
            self._connection = sqlite3.connect(str(self.path), isolation_level=None)
            self._verify_post_connect_identity(prepared)
            self._connection.execute("PRAGMA busy_timeout = 5000")
            initial_journal_mode = self._connection.execute("PRAGMA journal_mode").fetchone()
            if initial_journal_mode is None or str(initial_journal_mode[0]).lower() != "delete":
                raise EventStoreError("Etzio state must be in rollback-journal DELETE mode before use")
            journal_mode = self._connection.execute("PRAGMA journal_mode = DELETE").fetchone()
            if journal_mode is None or str(journal_mode[0]).lower() != self._journal_policy.journal_mode:
                raise EventStoreError("SQLite refused the required safe journal mode")
            self._connection.execute("PRAGMA synchronous = EXTRA")
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA trusted_schema = OFF")
            if self._connection.execute("PRAGMA foreign_keys").fetchone() != (1,):
                raise EventStoreError("SQLite foreign-key enforcement is unavailable")
            if self._connection.execute("PRAGMA trusted_schema").fetchone() != (0,):
                raise EventStoreError("SQLite trusted-schema hardening is unavailable")
            if self._connection.execute("PRAGMA synchronous").fetchone() != (self._journal_policy.synchronous_value,):
                raise EventStoreError("SQLite refused the required safe synchronous mode")
            if str(journal_mode[0]).lower() == "wal":
                raise EventStoreError("Etzio does not admit WAL under the declared runtime matrix")
            self._initialize_schema()
            retained_vault_bytes = self._vault_used_bytes_locked()
            if retained_vault_bytes > self._max_vault_bytes:
                raise EvidenceVaultCapacityError(
                    "retained unique evidence exceeds the configured database vault byte ceiling"
                )
            self._verify_post_connect_identity(prepared)
        except sqlite3.DatabaseError as exc:
            connection = getattr(self, "_connection", None)
            if connection is not None:
                connection.close()
            raise _sqlite_store_failure(
                "could not initialize event store",
                exc,
            ) from exc
        except Exception:
            connection = getattr(self, "_connection", None)
            if connection is not None:
                connection.close()
            raise
        finally:
            os.close(prepared.descriptor)

    @staticmethod
    def _refuse_preexisting_wal(descriptor: int) -> None:
        """Refuse persistent WAL state before SQLite opens the database path."""

        try:
            file_size = os.fstat(descriptor).st_size
            if file_size == 0:
                return
            header = os.pread(descriptor, _SQLITE_HEADER_SIZE, 0)
        except OSError as exc:
            raise EventStoreError(f"cannot inspect event-store journal header: {exc}") from exc
        if len(header) != _SQLITE_HEADER_SIZE:
            raise EventStoreCorruptionError("existing event store has a truncated SQLite header")
        if header[: len(_SQLITE_HEADER_MAGIC)] != _SQLITE_HEADER_MAGIC:
            raise EventStoreCorruptionError("existing event store has an invalid SQLite header")
        journal_versions = header[18:20]
        if 2 in journal_versions:
            raise EventStoreError("preexisting WAL state requires an explicit offline migration")
        if journal_versions != b"\x01\x01":
            raise EventStoreCorruptionError("existing event store has invalid journal-format bytes")

    @classmethod
    def _prepare_path(cls, path: str | os.PathLike[str]) -> _PreparedStorePath:
        if isinstance(path, str) and (path == ":memory:" or path.startswith("file:")):
            raise EventStoreError("an explicit filesystem database path is required")
        try:
            database_path = Path(path)
        except (TypeError, ValueError) as exc:
            raise EventStoreError("an explicit filesystem database path is required") from exc
        if not str(database_path) or "\x00" in str(database_path):
            raise EventStoreError("an explicit filesystem database path is required")
        database_path = Path(os.path.abspath(database_path))
        parent = database_path.parent
        cls._validate_private_directory_chain(parent)
        try:
            path_metadata = os.lstat(database_path)
        except FileNotFoundError:
            path_metadata = None
        except OSError as exc:
            raise EventStoreError(f"cannot inspect event-store path: {exc}") from exc
        if path_metadata is not None and stat.S_ISLNK(path_metadata.st_mode):
            raise EventStoreError("database path must not be a symbolic link")

        flags = os.O_RDWR | os.O_CREAT
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(database_path, flags, 0o600)
        except OSError as exc:
            raise EventStoreError(f"could not securely open event store: {exc}") from exc
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise EventStoreError("event store path must be a regular file")
            if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
                raise EventStoreError("event store must be owned by the current service user")
            if metadata.st_nlink != 1:
                raise EventStoreError("event store must have exactly one filesystem link")
            os.fchmod(fd, 0o600)
            metadata = os.fstat(fd)
            return _PreparedStorePath(
                path=database_path,
                descriptor=fd,
                device=metadata.st_dev,
                inode=metadata.st_ino,
            )
        except Exception:
            os.close(fd)
            raise

    @staticmethod
    def _is_trusted_sticky_root(
        *,
        directory_uid: int,
        directory_mode: int,
        effective_uid: int | None,
    ) -> bool:
        """Recognize a root-owned sticky temp root that another user cannot replace."""

        return (
            effective_uid is not None
            and effective_uid != 0
            and directory_uid == 0
            and bool(directory_mode & stat.S_ISVTX)
            and bool(stat.S_IMODE(directory_mode) & 0o022)
        )

    @classmethod
    def _validate_private_directory_chain(cls, parent: Path) -> None:
        """Validate the path chain up to a protected system trust boundary."""

        current = parent
        immediate = True
        effective_uid = os.geteuid() if hasattr(os, "geteuid") else None
        while True:
            try:
                metadata = os.lstat(current)
            except FileNotFoundError as exc:
                raise EventStoreError("database parent directory must already exist") from exc
            except OSError as exc:
                raise EventStoreError(f"cannot inspect database directory chain: {exc}") from exc
            if stat.S_ISLNK(metadata.st_mode):
                raise EventStoreError("database directory chain must not contain symbolic links")
            if not stat.S_ISDIR(metadata.st_mode):
                raise EventStoreError("database parent chain must contain only directories")

            permissions = stat.S_IMODE(metadata.st_mode)
            trusted_sticky_root = cls._is_trusted_sticky_root(
                directory_uid=metadata.st_uid,
                directory_mode=metadata.st_mode,
                effective_uid=effective_uid,
            )
            if immediate:
                if effective_uid is not None and metadata.st_uid != effective_uid:
                    raise EventStoreError("database parent directory must be owned by the current service user")
                if permissions != 0o700:
                    raise EventStoreError("database parent directory must have mode 0700")
            if permissions & 0o022 and not trusted_sticky_root:
                raise EventStoreError("database directory chain must not be group/world writable")

            # Stop at either a non-user-owned, non-writable directory or the conventional
            # root-owned sticky temp root. Sticky deletion rules prevent other unprivileged
            # users from replacing this service user's private child directory.
            if (
                effective_uid is not None
                and metadata.st_uid != effective_uid
                and (not permissions & 0o022 or trusted_sticky_root)
            ):
                return
            if current.parent == current:
                return
            current = current.parent
            immediate = False

    def _verify_post_connect_identity(self, prepared: _PreparedStorePath) -> None:
        self._validate_private_directory_chain(self.path.parent)
        try:
            descriptor_metadata = os.fstat(prepared.descriptor)
            path_metadata = os.lstat(self.path)
            database_row = self._connection.execute("PRAGMA database_list").fetchone()
            if (
                database_row is None
                or len(database_row) < 3
                or not isinstance(database_row[2], str)
                or not database_row[2]
            ):
                raise EventStoreError("SQLite did not expose its main database path")
            sqlite_metadata = os.lstat(database_row[2])
        except OSError as exc:
            raise EventStoreError(f"event-store identity could not be verified: {exc}") from exc

        expected = (prepared.device, prepared.inode)
        if (
            (descriptor_metadata.st_dev, descriptor_metadata.st_ino) != expected
            or (path_metadata.st_dev, path_metadata.st_ino) != expected
            or (sqlite_metadata.st_dev, sqlite_metadata.st_ino) != expected
        ):
            raise EventStoreError("event-store path identity changed during SQLite open")
        if not stat.S_ISREG(path_metadata.st_mode):
            raise EventStoreError("event store path must remain a regular file")
        if descriptor_metadata.st_nlink != 1 or path_metadata.st_nlink != 1 or sqlite_metadata.st_nlink != 1:
            raise EventStoreError("event store must retain exactly one filesystem link")
        if stat.S_IMODE(path_metadata.st_mode) != 0o600:
            raise EventStoreError("event store file must have mode 0600")
        if hasattr(os, "geteuid") and path_metadata.st_uid != os.geteuid():
            raise EventStoreError("event store must remain owned by the service user")

    def _table_exists(self, table_name: str) -> bool:
        row = self._connection.execute(
            """
            SELECT 1
            FROM sqlite_schema
            WHERE type = 'table' AND name = ?
            """,
            (table_name,),
        ).fetchone()
        return row == (1,)

    def _table_has_rows(self, table_name: str) -> bool:
        if not self._table_exists(table_name):
            return False
        inspection_query_by_table = {
            "events": "SELECT 1 FROM events LIMIT 1",
            "signed_checkpoints": "SELECT 1 FROM signed_checkpoints LIMIT 1",
            "evidence_artifacts": "SELECT 1 FROM evidence_artifacts LIMIT 1",
            "event_artifact_roles": "SELECT 1 FROM event_artifact_roles LIMIT 1",
        }
        inspection_query = inspection_query_by_table.get(table_name)
        if inspection_query is None:
            raise EventStoreError("refusing an unrecognized schema-inspection table")
        return self._connection.execute(inspection_query).fetchone() is not None

    def _initialize_schema(self) -> None:
        application_id = self._connection.execute("PRAGMA application_id").fetchone()
        user_version = self._connection.execute("PRAGMA user_version").fetchone()
        if application_id is None or user_version is None:
            raise EventStoreError("SQLite omitted its application schema identity")
        identity = (int(application_id[0]), int(user_version[0]))
        expected = (_SQLITE_APPLICATION_ID, _SQLITE_SCHEMA_VERSION)
        if identity == expected:
            self._validate_schema()
            return
        if identity != (0, 0):
            raise EventStoreError("event store has an unsupported application or schema version")
        legacy_allowed_objects = {
            ("index", "events_mission_head"),
            ("table", "events"),
            ("table", "signed_checkpoints"),
            ("trigger", "checkpoints_reject_delete"),
            ("trigger", "checkpoints_reject_update"),
            ("trigger", "events_reject_delete"),
            ("trigger", "events_reject_update"),
            ("trigger", "events_validate_insert"),
        }
        legacy_objects = set(
            self._connection.execute(
                """
                SELECT type, name
                FROM sqlite_schema
                WHERE name NOT LIKE 'sqlite_%'
                """
            ).fetchall()
        )
        if not legacy_objects.issubset(legacy_allowed_objects):
            raise EventStoreError("unversioned event store contains unknown schema objects")
        if any(self._table_has_rows(table_name) for table_name in ("events", "signed_checkpoints")):
            raise EventStoreError("nonempty pre-vault event state requires an explicit offline migration")
        self._create_schema()

    def _create_schema(self) -> None:
        genesis = GENESIS_DIGEST.replace("'", "''")
        terminal_sql = ", ".join(f"'{kind}'" for kind in sorted(TERMINAL_KINDS))
        typed_types_sql = ", ".join(
            f"'{value}'"
            for value in sorted(
                {
                    "modeled_effect_oracle_spec",
                    "modeled_effect_output",
                    "modeled_environment_spec",
                    "modeled_execution_output",
                    "modeled_measured_environment_output",
                    "modeled_poc_input",
                    "modeled_supporting_evidence_input",
                    "modeled_termination_output",
                }
            )
        )
        protected_kinds_sql = ", ".join(f"'{value}'" for value in sorted(PROTECTED_EVIDENCE_EVENT_KINDS_V1))
        roles_sql = ", ".join(f"'{value}'" for value in sorted(VAULT_ROLES_V1))
        singleton_roles_sql = ", ".join(f"'{value}'" for value in sorted(SINGLETON_VAULT_ROLES_V1))
        try:
            self._connection.executescript(
                f"""
            BEGIN IMMEDIATE;

            CREATE TABLE IF NOT EXISTS events (
                mission_id TEXT NOT NULL,
                seq INTEGER NOT NULL CHECK (seq >= 0),
                digest TEXT NOT NULL,
                prev_digest TEXT NOT NULL,
                kind TEXT NOT NULL,
                canonical BLOB NOT NULL CHECK (typeof(canonical) = 'blob'),
                PRIMARY KEY (mission_id, seq),
                UNIQUE (mission_id, digest),
                UNIQUE (digest)
            ) STRICT;

            CREATE INDEX IF NOT EXISTS events_mission_head
                ON events (mission_id, seq DESC);

            CREATE TABLE IF NOT EXISTS evidence_artifacts (
                artifact_rowid INTEGER PRIMARY KEY,
                identity_scheme TEXT NOT NULL CHECK (
                    identity_scheme IN (
                        '{GENERIC_IDENTITY_SCHEME_V1}',
                        '{TYPED_IDENTITY_SCHEME_V1}'
                    )
                ),
                type_tag TEXT NOT NULL,
                digest TEXT NOT NULL CHECK (
                    length(digest) = 71
                    AND substr(digest, 1, 7) = 'sha256:'
                    AND substr(digest, 8) NOT GLOB '*[^0-9a-f]*'
                ),
                byte_size INTEGER NOT NULL CHECK (
                    byte_size >= 0
                    AND byte_size <= {MAX_VAULT_ARTIFACT_BYTES_V1}
                ),
                origin_event_digest TEXT NOT NULL,
                content BLOB NOT NULL CHECK (
                    typeof(content) = 'blob'
                    AND length(content) = byte_size
                ),
                CHECK (
                    (
                        identity_scheme = '{GENERIC_IDENTITY_SCHEME_V1}'
                        AND type_tag = '{GENERIC_TYPE_TAG_V1}'
                    )
                    OR (
                        identity_scheme = '{TYPED_IDENTITY_SCHEME_V1}'
                        AND type_tag IN ({typed_types_sql})
                        AND byte_size > 0
                    )
                ),
                UNIQUE (identity_scheme, type_tag, digest),
                UNIQUE (identity_scheme, type_tag, digest, byte_size),
                FOREIGN KEY (origin_event_digest)
                    REFERENCES events (digest)
                    ON UPDATE RESTRICT ON DELETE RESTRICT
                    DEFERRABLE INITIALLY DEFERRED
            ) STRICT;

            CREATE TABLE IF NOT EXISTS event_artifact_roles (
                event_digest TEXT NOT NULL,
                event_kind TEXT NOT NULL CHECK (
                    event_kind IN ({protected_kinds_sql})
                ),
                slot INTEGER NOT NULL CHECK (
                    slot >= 0 AND slot < {MAX_EVENT_ARTIFACT_ROLES_V1}
                ),
                role TEXT NOT NULL CHECK (role IN ({roles_sql})),
                ordinal INTEGER NOT NULL CHECK (
                    ordinal >= 0
                    AND ordinal < 256
                    AND (
                        role NOT IN ({singleton_roles_sql})
                        OR ordinal = 0
                    )
                ),
                locator TEXT NOT NULL CHECK (
                    (
                        role = '{TARGET_SOURCE_ROLE_V1}'
                        AND length(locator) > 0
                        AND length(locator) <= 1000000
                    )
                    OR (
                        role != '{TARGET_SOURCE_ROLE_V1}'
                        AND locator = ''
                    )
                ),
                identity_scheme TEXT NOT NULL,
                type_tag TEXT NOT NULL,
                artifact_digest TEXT NOT NULL,
                byte_size INTEGER NOT NULL,
                PRIMARY KEY (event_digest, slot),
                UNIQUE (event_digest, role, ordinal),
                FOREIGN KEY (event_digest)
                    REFERENCES events (digest)
                    ON UPDATE RESTRICT ON DELETE RESTRICT
                    DEFERRABLE INITIALLY DEFERRED,
                FOREIGN KEY (
                    identity_scheme,
                    type_tag,
                    artifact_digest,
                    byte_size
                ) REFERENCES evidence_artifacts (
                    identity_scheme,
                    type_tag,
                    digest,
                    byte_size
                ) ON UPDATE RESTRICT ON DELETE RESTRICT,
                CHECK (
                    (
                        role IN (
                            '{AUTHORITY_EVIDENCE_ROLE_V1}',
                            '{TARGET_SOURCE_ROLE_V1}'
                        )
                        AND identity_scheme = '{GENERIC_IDENTITY_SCHEME_V1}'
                        AND type_tag = '{GENERIC_TYPE_TAG_V1}'
                    )
                    OR (
                        role NOT IN (
                            '{AUTHORITY_EVIDENCE_ROLE_V1}',
                            '{TARGET_SOURCE_ROLE_V1}'
                        )
                        AND identity_scheme = '{TYPED_IDENTITY_SCHEME_V1}'
                    )
                ),
                CHECK (
                    (role = '{VERIFICATION_POC_INPUT_ROLE_V1}'
                        AND type_tag = 'modeled_poc_input')
                    OR (role = '{VERIFICATION_SUPPORTING_EVIDENCE_INPUT_ROLE_V1}'
                        AND type_tag = 'modeled_supporting_evidence_input')
                    OR (role = '{VERIFICATION_ENVIRONMENT_SPEC_ROLE_V1}'
                        AND type_tag = 'modeled_environment_spec')
                    OR (role = '{VERIFICATION_EFFECT_ORACLE_SPEC_ROLE_V1}'
                        AND type_tag = 'modeled_effect_oracle_spec')
                    OR (role = '{VERIFICATION_EXECUTION_OUTPUT_ROLE_V1}'
                        AND type_tag = 'modeled_execution_output')
                    OR (role = '{VERIFICATION_EFFECT_OUTPUT_ROLE_V1}'
                        AND type_tag = 'modeled_effect_output')
                    OR (role = '{VERIFICATION_MEASURED_ENVIRONMENT_OUTPUT_ROLE_V1}'
                        AND type_tag = 'modeled_measured_environment_output')
                    OR (role = '{VERIFICATION_TERMINATION_OUTPUT_ROLE_V1}'
                        AND type_tag = 'modeled_termination_output')
                    OR role IN (
                        '{AUTHORITY_EVIDENCE_ROLE_V1}',
                        '{TARGET_SOURCE_ROLE_V1}'
                    )
                ),
                CHECK (
                    (event_kind = 'authority_admitted'
                        AND role = '{AUTHORITY_EVIDENCE_ROLE_V1}')
                    OR (event_kind = 'mission_opened'
                        AND role = '{TARGET_SOURCE_ROLE_V1}')
                    OR (event_kind = 'verification_artifacts_resolved'
                        AND role IN (
                            '{TARGET_SOURCE_ROLE_V1}',
                            '{VERIFICATION_POC_INPUT_ROLE_V1}',
                            '{VERIFICATION_SUPPORTING_EVIDENCE_INPUT_ROLE_V1}',
                            '{VERIFICATION_ENVIRONMENT_SPEC_ROLE_V1}',
                            '{VERIFICATION_EFFECT_ORACLE_SPEC_ROLE_V1}'
                        ))
                    OR (event_kind = 'verifier_receipt_admitted'
                        AND role IN (
                            '{VERIFICATION_EXECUTION_OUTPUT_ROLE_V1}',
                            '{VERIFICATION_EFFECT_OUTPUT_ROLE_V1}',
                            '{VERIFICATION_MEASURED_ENVIRONMENT_OUTPUT_ROLE_V1}',
                            '{VERIFICATION_TERMINATION_OUTPUT_ROLE_V1}'
                        ))
                )
            ) STRICT, WITHOUT ROWID;

            CREATE INDEX IF NOT EXISTS event_artifact_roles_artifact_identity
                ON event_artifact_roles (
                    identity_scheme,
                    type_tag,
                    artifact_digest,
                    byte_size,
                    event_digest
                );

            CREATE TABLE IF NOT EXISTS signed_checkpoints (
                mission_id TEXT NOT NULL,
                event_digest TEXT NOT NULL,
                signer_id TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                signed_at INTEGER NOT NULL CHECK (signed_at >= 0),
                signature BLOB NOT NULL CHECK (
                    typeof(signature) = 'blob' AND length(signature) > 0
                ),
                PRIMARY KEY (mission_id, event_digest, signer_id),
                FOREIGN KEY (mission_id, event_digest)
                    REFERENCES events (mission_id, digest)
                    ON UPDATE RESTRICT ON DELETE RESTRICT
            ) STRICT;

            CREATE TRIGGER IF NOT EXISTS events_validate_insert
            BEFORE INSERT ON events
            BEGIN
                SELECT CASE
                    WHEN EXISTS (
                        SELECT 1 FROM events
                        WHERE mission_id = NEW.mission_id
                          AND kind IN ({terminal_sql})
                    )
                    THEN RAISE(ABORT, 'mission stream is terminal')
                END;
                SELECT CASE
                    WHEN NEW.seq != COALESCE(
                        (
                            SELECT seq + 1 FROM events
                            WHERE mission_id = NEW.mission_id
                            ORDER BY seq DESC LIMIT 1
                        ),
                        0
                    )
                    THEN RAISE(ABORT, 'mission sequence gap or fork')
                END;
                SELECT CASE
                    WHEN NEW.prev_digest != COALESCE(
                        (
                            SELECT digest FROM events
                            WHERE mission_id = NEW.mission_id
                            ORDER BY seq DESC LIMIT 1
                        ),
                        '{genesis}'
                    )
                    THEN RAISE(ABORT, 'mission predecessor mismatch')
                END;
            END;

            CREATE TRIGGER IF NOT EXISTS events_reject_update
            BEFORE UPDATE ON events
            BEGIN
                SELECT RAISE(ABORT, 'events are append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS events_reject_delete
            BEFORE DELETE ON events
            BEGIN
                SELECT RAISE(ABORT, 'events are append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS evidence_artifacts_reject_update
            BEFORE UPDATE ON evidence_artifacts
            BEGIN
                SELECT RAISE(ABORT, 'evidence artifacts are append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS evidence_artifacts_reject_delete
            BEFORE DELETE ON evidence_artifacts
            BEGIN
                SELECT RAISE(ABORT, 'evidence artifacts are append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS event_artifact_roles_reject_update
            BEFORE UPDATE ON event_artifact_roles
            BEGIN
                SELECT RAISE(ABORT, 'event artifact roles are append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS event_artifact_roles_reject_delete
            BEFORE DELETE ON event_artifact_roles
            BEGIN
                SELECT RAISE(ABORT, 'event artifact roles are append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS event_artifact_roles_reject_late_insert
            BEFORE INSERT ON event_artifact_roles
            WHEN EXISTS (
                SELECT 1 FROM events WHERE digest = NEW.event_digest
            )
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'event artifact roles must precede their event'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS events_require_matching_artifact_kind
            BEFORE INSERT ON events
            WHEN EXISTS (
                SELECT 1 FROM event_artifact_roles
                WHERE event_digest = NEW.digest
                  AND event_kind != NEW.kind
            )
            BEGIN
                SELECT RAISE(ABORT, 'event artifact kind mismatch');
            END;

            CREATE TRIGGER IF NOT EXISTS events_require_authority_evidence
            BEFORE INSERT ON events
            WHEN NEW.kind = 'authority_admitted'
                 AND (
                    (SELECT count(*) FROM event_artifact_roles
                     WHERE event_digest = NEW.digest) != 1
                    OR NOT EXISTS (
                        SELECT 1 FROM event_artifact_roles
                        WHERE event_digest = NEW.digest
                          AND role = '{AUTHORITY_EVIDENCE_ROLE_V1}'
                          AND ordinal = 0
                    )
                 )
            BEGIN
                SELECT RAISE(ABORT, 'authority evidence manifest is incomplete');
            END;

            CREATE TRIGGER IF NOT EXISTS events_require_target_evidence
            BEFORE INSERT ON events
            WHEN NEW.kind = 'mission_opened'
                 AND (
                    (SELECT count(*) FROM event_artifact_roles
                     WHERE event_digest = NEW.digest) < 1
                    OR (SELECT count(*) FROM event_artifact_roles
                        WHERE event_digest = NEW.digest) > 256
                    OR EXISTS (
                        SELECT 1 FROM event_artifact_roles
                        WHERE event_digest = NEW.digest
                          AND role != '{TARGET_SOURCE_ROLE_V1}'
                    )
                 )
            BEGIN
                SELECT RAISE(ABORT, 'target evidence manifest is incomplete');
            END;

            CREATE TRIGGER IF NOT EXISTS events_require_resolution_evidence
            BEFORE INSERT ON events
            WHEN NEW.kind = 'verification_artifacts_resolved'
                 AND (
                    (SELECT count(*) FROM event_artifact_roles
                     WHERE event_digest = NEW.digest
                       AND role = '{TARGET_SOURCE_ROLE_V1}') NOT BETWEEN 1 AND 256
                    OR (SELECT count(*) FROM event_artifact_roles
                        WHERE event_digest = NEW.digest
                          AND role = '{VERIFICATION_SUPPORTING_EVIDENCE_INPUT_ROLE_V1}')
                       NOT BETWEEN 1 AND 256
                    OR (SELECT count(*) FROM event_artifact_roles
                        WHERE event_digest = NEW.digest
                          AND role = '{VERIFICATION_POC_INPUT_ROLE_V1}') != 1
                    OR (SELECT count(*) FROM event_artifact_roles
                        WHERE event_digest = NEW.digest
                          AND role = '{VERIFICATION_ENVIRONMENT_SPEC_ROLE_V1}') != 1
                    OR (SELECT count(*) FROM event_artifact_roles
                        WHERE event_digest = NEW.digest
                          AND role = '{VERIFICATION_EFFECT_ORACLE_SPEC_ROLE_V1}') != 1
                 )
            BEGIN
                SELECT RAISE(ABORT, 'resolution evidence manifest is incomplete');
            END;

            CREATE TRIGGER IF NOT EXISTS events_require_receipt_evidence
            BEFORE INSERT ON events
            WHEN NEW.kind = 'verifier_receipt_admitted'
                 AND (
                    (SELECT count(*) FROM event_artifact_roles
                     WHERE event_digest = NEW.digest) != 4
                    OR (SELECT count(*) FROM event_artifact_roles
                        WHERE event_digest = NEW.digest
                          AND role = '{VERIFICATION_EXECUTION_OUTPUT_ROLE_V1}') != 1
                    OR (SELECT count(*) FROM event_artifact_roles
                        WHERE event_digest = NEW.digest
                          AND role = '{VERIFICATION_EFFECT_OUTPUT_ROLE_V1}') != 1
                    OR (SELECT count(*) FROM event_artifact_roles
                        WHERE event_digest = NEW.digest
                          AND role = '{VERIFICATION_MEASURED_ENVIRONMENT_OUTPUT_ROLE_V1}') != 1
                    OR (SELECT count(*) FROM event_artifact_roles
                        WHERE event_digest = NEW.digest
                          AND role = '{VERIFICATION_TERMINATION_OUTPUT_ROLE_V1}') != 1
                 )
            BEGIN
                SELECT RAISE(ABORT, 'receipt evidence manifest is incomplete');
            END;

            CREATE TRIGGER IF NOT EXISTS events_reject_unexpected_evidence
            BEFORE INSERT ON events
            WHEN NEW.kind NOT IN ({protected_kinds_sql})
                 AND EXISTS (
                    SELECT 1 FROM event_artifact_roles
                    WHERE event_digest = NEW.digest
                 )
            BEGIN
                SELECT RAISE(ABORT, 'ordinary event has an evidence manifest');
            END;

            CREATE TRIGGER IF NOT EXISTS checkpoints_reject_update
            BEFORE UPDATE ON signed_checkpoints
            BEGIN
                SELECT RAISE(ABORT, 'checkpoints are append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS checkpoints_reject_delete
            BEFORE DELETE ON signed_checkpoints
            BEGIN
                SELECT RAISE(ABORT, 'checkpoints are append-only');
            END;

            """
            )
            self._require_writer_transaction()
            self._connection.execute(_SET_SQLITE_APPLICATION_ID)
            self._require_writer_transaction()
            self._connection.execute(_SET_SQLITE_SCHEMA_VERSION)
            self._validate_schema()
            self._require_writer_transaction()
            self._connection.execute("COMMIT")
        except BaseException:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise

    def _validate_schema(self) -> None:
        application_id = self._connection.execute("PRAGMA application_id").fetchone()
        user_version = self._connection.execute("PRAGMA user_version").fetchone()
        if application_id != (_SQLITE_APPLICATION_ID,) or user_version != (_SQLITE_SCHEMA_VERSION,):
            raise EventStoreCorruptionError("event-store schema identity is invalid")
        required_objects = {
            ("index", "event_artifact_roles_artifact_identity"),
            ("index", "events_mission_head"),
            ("table", "event_artifact_roles"),
            ("table", "events"),
            ("table", "evidence_artifacts"),
            ("table", "signed_checkpoints"),
            ("trigger", "checkpoints_reject_delete"),
            ("trigger", "checkpoints_reject_update"),
            ("trigger", "event_artifact_roles_reject_delete"),
            ("trigger", "event_artifact_roles_reject_late_insert"),
            ("trigger", "event_artifact_roles_reject_update"),
            ("trigger", "events_reject_delete"),
            ("trigger", "events_reject_unexpected_evidence"),
            ("trigger", "events_reject_update"),
            ("trigger", "events_require_authority_evidence"),
            ("trigger", "events_require_matching_artifact_kind"),
            ("trigger", "events_require_receipt_evidence"),
            ("trigger", "events_require_resolution_evidence"),
            ("trigger", "events_require_target_evidence"),
            ("trigger", "events_validate_insert"),
            ("trigger", "evidence_artifacts_reject_delete"),
            ("trigger", "evidence_artifacts_reject_update"),
        }
        schema_rows = self._connection.execute(
            """
            SELECT type, name, sql
            FROM sqlite_schema
            WHERE name NOT LIKE 'sqlite_%'
            ORDER BY type ASC, name ASC
            """
        ).fetchall()
        retained_objects = {(row[0], row[1]) for row in schema_rows}
        if retained_objects != required_objects:
            raise EventStoreCorruptionError(
                "event-store schema objects differ from the vault contract"
            )
        schema_contract = "\n".join(f"{object_type}\0{name}\0{sql}" for object_type, name, sql in schema_rows).encode(
            "utf-8"
        )
        if hashlib.sha256(schema_contract).hexdigest() != _SQLITE_SCHEMA_CONTRACT_SHA256:
            raise EventStoreCorruptionError(
                "event-store schema definitions differ from the vault contract"
            )
        table_rows = {row[1]: row for row in self._connection.execute("PRAGMA table_list").fetchall()}
        artifacts = table_rows.get("evidence_artifacts")
        roles = table_rows.get("event_artifact_roles")
        if (
            artifacts is None
            or roles is None
            or artifacts[-1] != 1
            or artifacts[-2] != 0
            or roles[-1] != 1
            or roles[-2] != 1
        ):
            raise EventStoreCorruptionError(
                "event-store vault tables do not retain their STRICT/rowid contract"
            )
        expected_columns = {
            "events": (
                (0, "mission_id", "TEXT", 1, None, 1, 0),
                (1, "seq", "INTEGER", 1, None, 2, 0),
                (2, "digest", "TEXT", 1, None, 0, 0),
                (3, "prev_digest", "TEXT", 1, None, 0, 0),
                (4, "kind", "TEXT", 1, None, 0, 0),
                (5, "canonical", "BLOB", 1, None, 0, 0),
            ),
            "signed_checkpoints": (
                (0, "mission_id", "TEXT", 1, None, 1, 0),
                (1, "event_digest", "TEXT", 1, None, 2, 0),
                (2, "signer_id", "TEXT", 1, None, 3, 0),
                (3, "algorithm", "TEXT", 1, None, 0, 0),
                (4, "signed_at", "INTEGER", 1, None, 0, 0),
                (5, "signature", "BLOB", 1, None, 0, 0),
            ),
            "evidence_artifacts": (
                (0, "artifact_rowid", "INTEGER", 0, None, 1, 0),
                (1, "identity_scheme", "TEXT", 1, None, 0, 0),
                (2, "type_tag", "TEXT", 1, None, 0, 0),
                (3, "digest", "TEXT", 1, None, 0, 0),
                (4, "byte_size", "INTEGER", 1, None, 0, 0),
                (5, "origin_event_digest", "TEXT", 1, None, 0, 0),
                (6, "content", "BLOB", 1, None, 0, 0),
            ),
            "event_artifact_roles": (
                (0, "event_digest", "TEXT", 1, None, 1, 0),
                (1, "event_kind", "TEXT", 1, None, 0, 0),
                (2, "slot", "INTEGER", 1, None, 2, 0),
                (3, "role", "TEXT", 1, None, 0, 0),
                (4, "ordinal", "INTEGER", 1, None, 0, 0),
                (5, "locator", "TEXT", 1, None, 0, 0),
                (6, "identity_scheme", "TEXT", 1, None, 0, 0),
                (7, "type_tag", "TEXT", 1, None, 0, 0),
                (8, "artifact_digest", "TEXT", 1, None, 0, 0),
                (9, "byte_size", "INTEGER", 1, None, 0, 0),
            ),
        }
        for table_name, expected_table_columns in expected_columns.items():
            actual_columns = tuple(
                self._connection.execute(
                    """
                    SELECT cid, name, type, "notnull", dflt_value, pk, hidden
                    FROM pragma_table_xinfo(?)
                    """,
                    (table_name,),
                ).fetchall()
            )
            if actual_columns != expected_table_columns:
                raise EventStoreCorruptionError(
                    f"{table_name} columns differ from the vault schema contract"
                )
        signed_foreign_keys = {
            tuple(row[2:]) for row in self._connection.execute("PRAGMA foreign_key_list(signed_checkpoints)").fetchall()
        }
        if signed_foreign_keys != {
            ("events", "mission_id", "mission_id", "RESTRICT", "RESTRICT", "NONE"),
            ("events", "event_digest", "digest", "RESTRICT", "RESTRICT", "NONE"),
        }:
            raise EventStoreCorruptionError(
                "checkpoint foreign keys differ from the schema contract"
            )
        role_foreign_keys = {
            tuple(row[2:])
            for row in self._connection.execute("PRAGMA foreign_key_list(event_artifact_roles)").fetchall()
        }
        if role_foreign_keys != {
            ("events", "event_digest", "digest", "RESTRICT", "RESTRICT", "NONE"),
            (
                "evidence_artifacts",
                "identity_scheme",
                "identity_scheme",
                "RESTRICT",
                "RESTRICT",
                "NONE",
            ),
            (
                "evidence_artifacts",
                "type_tag",
                "type_tag",
                "RESTRICT",
                "RESTRICT",
                "NONE",
            ),
            (
                "evidence_artifacts",
                "artifact_digest",
                "digest",
                "RESTRICT",
                "RESTRICT",
                "NONE",
            ),
            (
                "evidence_artifacts",
                "byte_size",
                "byte_size",
                "RESTRICT",
                "RESTRICT",
                "NONE",
            ),
        }:
            raise EventStoreCorruptionError(
                "event-artifact foreign keys differ from the schema contract"
            )
        artifact_foreign_keys = {
            tuple(row[2:])
            for row in self._connection.execute("PRAGMA foreign_key_list(evidence_artifacts)").fetchall()
        }
        if artifact_foreign_keys != {
            ("events", "origin_event_digest", "digest", "RESTRICT", "RESTRICT", "NONE"),
        }:
            raise EventStoreCorruptionError(
                "evidence-artifact foreign keys differ from the schema contract"
            )
        head_index = tuple(
            row
            for row in self._connection.execute("PRAGMA index_xinfo(events_mission_head)").fetchall()
            if row[-1] == 1
        )
        if head_index != (
            (0, 0, "mission_id", 0, "BINARY", 1),
            (1, 1, "seq", 1, "BINARY", 1),
        ):
            raise EventStoreCorruptionError(
                "mission-head index differs from the schema contract"
            )
        artifact_identity_index = tuple(
            self._connection.execute(
                "PRAGMA index_info(event_artifact_roles_artifact_identity)"
            ).fetchall()
        )
        if artifact_identity_index != (
            (0, 6, "identity_scheme"),
            (1, 7, "type_tag"),
            (2, 8, "artifact_digest"),
            (3, 9, "byte_size"),
            (4, 0, "event_digest"),
        ):
            raise EventStoreCorruptionError(
                "artifact-identity index differs from the schema contract"
            )
        if self._connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise EventStoreCorruptionError(
                "event-store schema has foreign-key violations"
            )

    def diagnostics(self) -> StoreDiagnostics:
        """Return fixed diagnostics without exposing a writable SQL connection."""

        try:
            journal = self._connection.execute("PRAGMA journal_mode").fetchone()
            synchronous = self._connection.execute("PRAGMA synchronous").fetchone()
            foreign_keys = self._connection.execute("PRAGMA foreign_keys").fetchone()
            trusted_schema = self._connection.execute("PRAGMA trusted_schema").fetchone()
            mode = stat.S_IMODE(os.lstat(self.path).st_mode)
        except sqlite3.DatabaseError as exc:
            raise _sqlite_store_failure(
                "could not read store diagnostics",
                exc,
            ) from exc
        except OSError as exc:
            raise EventStoreCorruptionError(f"could not read store diagnostics: {exc}") from exc
        if journal is None or synchronous is None or foreign_keys is None or trusted_schema is None:
            raise EventStoreCorruptionError("SQLite returned incomplete diagnostics")
        journal_value = str(journal[0]).lower()
        synchronous_value = int(synchronous[0])
        if (
            journal_value != self._journal_policy.journal_mode
            or synchronous_value != self._journal_policy.synchronous_value
            or journal_value == "wal"
            or foreign_keys != (1,)
            or trusted_schema != (0,)
        ):
            raise EventStoreCorruptionError("SQLite security settings differ from the admitted journal policy")
        return StoreDiagnostics(
            sqlite_version=sqlite3.sqlite_version,
            wal_reset_bug_fixed=(self._journal_policy.wal_reset_bug_fixed),
            journal_mode=journal_value,
            synchronous=synchronous_value,
            foreign_keys=bool(foreign_keys[0]),
            trusted_schema=bool(trusted_schema[0]),
            database_mode=mode,
        )

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> SQLiteEventStore:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    @staticmethod
    def _trusted_staging_store(evidence_store: object) -> FileEvidenceStore:
        """Snapshot caller configuration into a fresh, non-overridable CAS reader."""

        if type(evidence_store) is not FileEvidenceStore:
            raise EventStoreError("evidence staging requires an exact FileEvidenceStore")
        root = evidence_store.root
        maximum = evidence_store.max_artifact_bytes
        if type(root) is not _CONCRETE_PATH_TYPE:
            raise EventStoreError("evidence staging root must retain its concrete Path type")
        if type(maximum) is not int or maximum <= 0:
            raise EventStoreError("evidence staging limit must remain a positive exact integer")
        absolute_root = root if root.is_absolute() else Path.cwd() / root
        try:
            return FileEvidenceStore(
                absolute_root,
                max_artifact_bytes=maximum,
            )
        except EvidenceError as exc:
            raise EventStoreError(f"evidence staging configuration is invalid: {exc}") from exc

    def _require_writer_transaction(self) -> None:
        if not self._connection.in_transaction:
            raise EventStoreError("SQLite writer transaction ended before the protected operation")

    def _artifact_row_locked(
        self,
        *,
        identity_scheme: str,
        type_tag: str,
        digest: str,
    ) -> tuple[int, int, str] | None:
        try:
            row = self._connection.execute(
                """
                SELECT artifact_rowid, byte_size, origin_event_digest
                FROM evidence_artifacts
                WHERE identity_scheme = ?
                  AND type_tag = ?
                  AND digest = ?
                """,
                (identity_scheme, type_tag, digest),
            ).fetchone()
        except sqlite3.DatabaseError as exc:
            raise _sqlite_store_failure(
                "could not inspect canonical vault identity",
                exc,
            ) from exc
        if row is None:
            return None
        if (
            type(row[0]) is not int
            or row[0] <= 0
            or type(row[1]) is not int
            or row[1] < 0
            or row[1] > MAX_VAULT_ARTIFACT_BYTES_V1
            or type(row[2]) is not str
            or _DIGEST_RE.fullmatch(row[2]) is None
        ):
            raise EventStoreCorruptionError("vault artifact metadata is invalid")
        return (row[0], row[1], row[2])

    def _read_vault_identity_locked(
        self,
        identity_scheme: str,
        type_tag: str,
        digest: str,
        maximum: int | None = None,
        *,
        expected_size: int | None = None,
    ) -> bytes:
        row = self._artifact_row_locked(
            identity_scheme=identity_scheme,
            type_tag=type_tag,
            digest=digest,
        )
        if row is None:
            raise EvidenceVaultArtifactMissing("artifact identity is absent from the canonical vault")
        artifact_rowid, byte_size, _ = row
        if expected_size is not None and byte_size != expected_size:
            raise EventStoreCorruptionError("vault artifact size differs from its event manifest")
        if maximum is not None:
            if type(maximum) is not int or maximum < 0:
                raise EvidenceError("artifact read maximum must be a nonnegative integer")
            if byte_size > maximum:
                raise EvidenceError("evidence artifact exceeds configured limit")
        try:
            chunks: list[bytes] = []
            hasher = digest_hasher_v1(identity_scheme, type_tag)
            with self._connection.blobopen(
                "evidence_artifacts",
                "content",
                artifact_rowid,
                readonly=True,
            ) as blob:
                if len(blob) != byte_size:
                    raise EventStoreCorruptionError("vault BLOB length differs from retained metadata")
                remaining = byte_size
                while remaining:
                    chunk = blob.read(min(_VAULT_READ_CHUNK_BYTES, remaining))
                    if not chunk:
                        raise EventStoreCorruptionError("vault BLOB ended before its retained size")
                    chunks.append(chunk)
                    hasher.update(chunk)
                    remaining -= len(chunk)
            retained_digest = f"sha256:{hasher.hexdigest()}"
            if retained_digest != digest:
                raise EventStoreCorruptionError("vault BLOB fails its retained content identity")
            return b"".join(chunks)
        except sqlite3.DatabaseError as exc:
            raise _sqlite_store_failure(
                "could not read canonical vault artifact",
                exc,
            ) from exc

    def resolve_evidence_artifact(
        self,
        role: str,
        digest: str,
        maximum: int,
        evidence_store: FileEvidenceStore,
    ) -> bytes:
        """Resolve one artifact through the exact bounded batch boundary."""

        try:
            request = VaultArtifactResolutionRequestV1(
                role=role,
                digest=digest,
                maximum=maximum,
            )
        except EvidenceVaultError as exc:
            raise EventStoreError(f"invalid evidence resolution request: {exc}") from exc
        return self.resolve_evidence_artifacts(
            (request,),
            evidence_store,
            maximum_total=request.effective_maximum,
        )[0]

    def resolve_evidence_artifacts(
        self,
        requests: tuple[VaultArtifactResolutionRequestV1, ...],
        evidence_store: FileEvidenceStore,
        *,
        maximum_total: int,
    ) -> tuple[bytes, ...]:
        """Resolve one bounded batch with one origin-validation and unique-BLOB pass."""

        if (
            type(requests) is not tuple
            or not requests
            or len(requests) > MAX_VAULT_BATCH_REQUESTS_V1
            or any(type(request) is not VaultArtifactResolutionRequestV1 for request in requests)
        ):
            raise EventStoreError("evidence resolution requires one bounded tuple of exact vault requests")
        if type(evidence_store) is not FileEvidenceStore:
            raise EventStoreError("evidence resolution requires an exact FileEvidenceStore")
        if (
            type(maximum_total) is not int
            or maximum_total < 0
            or maximum_total > DEFAULT_MAX_VAULT_BYTES_V1
        ):
            raise EventStoreError("evidence batch maximum_total is outside the fixed vault bound")

        unique_requests: dict[
            tuple[str, str, str],
            tuple[int, int],
        ] = {}
        for request_index, request in enumerate(requests):
            key = request.identity_key
            prior = unique_requests.get(key)
            if prior is None:
                unique_requests[key] = (
                    request_index,
                    request.effective_maximum,
                )
            else:
                if request.effective_maximum < prior[1]:
                    unique_requests[key] = (
                        request_index,
                        request.effective_maximum,
                    )

        canonical: dict[
            tuple[str, str, str],
            tuple[int, str],
        ] = {}
        absent: list[tuple[str, str, str]] = []
        origin_missions: set[str] = set()
        for key, (request_index, effective_maximum) in unique_requests.items():
            identity_scheme, type_tag, artifact_digest = key
            artifact_row = self._artifact_row_locked(
                identity_scheme=identity_scheme,
                type_tag=type_tag,
                digest=artifact_digest,
            )
            if artifact_row is None:
                absent.append(key)
                continue
            _, byte_size, origin_event_digest = artifact_row
            if byte_size > effective_maximum:
                raise EvidenceVaultRequestError(
                    request_index,
                    "artifact_limit",
                    f"evidence request {request_index} exceeds its configured limit",
                )
            try:
                origin_rows = self._connection.execute(
                    """
                    SELECT event.mission_id
                    FROM event_artifact_roles AS role
                    INDEXED BY event_artifact_roles_artifact_identity
                    JOIN events AS event
                      ON event.digest = role.event_digest
                    WHERE role.identity_scheme = ?
                      AND role.type_tag = ?
                      AND role.artifact_digest = ?
                      AND role.byte_size = ?
                      AND role.event_digest = ?
                    """,
                    (
                        identity_scheme,
                        type_tag,
                        artifact_digest,
                        byte_size,
                        origin_event_digest,
                    ),
                ).fetchall()
            except sqlite3.DatabaseError as exc:
                raise _sqlite_store_failure(
                    "could not inspect canonical vault origin",
                    exc,
                ) from exc
            if (
                not origin_rows
                or any(
                    type(row[0]) is not str
                    or _DIGEST_RE.fullmatch(row[0]) is None
                    for row in origin_rows
                )
                or len({row[0] for row in origin_rows}) != 1
            ):
                raise EventStoreCorruptionError(
                    "canonical vault origin does not own the retained identity"
                )
            mission_id = origin_rows[0][0]
            canonical[key] = (byte_size, mission_id)
            origin_missions.add(mission_id)

        selected_bytes = sum(byte_size for byte_size, _ in canonical.values())
        if selected_bytes > maximum_total:
            raise EvidenceVaultRequestError(
                0,
                "batch_limit",
                "canonical evidence batch exceeds its aggregate byte ceiling",
            )
        resolved_by_identity: dict[tuple[str, str, str], bytes] = {}
        if origin_missions:
            requested_cache_keys = frozenset(
                (*key, byte_size)
                for key, (byte_size, _) in canonical.items()
            )
            canonical_cache = self._load_missions_with_shared_evidence_validation(
                tuple(sorted(origin_missions)),
                cache_keys=requested_cache_keys,
            )
            for key, (byte_size, _) in canonical.items():
                cached = canonical_cache.get((*key, byte_size))
                if cached is None:
                    raise EventStoreCorruptionError(
                        "canonical vault origin manifest did not validate the requested identity"
                    )
                resolved_by_identity[key] = cached

        if absent:
            staging = self._trusted_staging_store(evidence_store)
            for key in absent:
                identity_scheme, type_tag, artifact_digest = key
                request_index, effective_maximum = unique_requests[key]
                try:
                    read_maximum = min(
                        effective_maximum,
                        maximum_total - selected_bytes,
                    )
                    if identity_scheme == GENERIC_IDENTITY_SCHEME_V1:
                        data = staging.get(
                            artifact_digest,
                            maximum=read_maximum,
                        )
                    else:
                        data = staging.get_typed(
                            artifact_digest,
                            expected_type=type_tag,
                            maximum=read_maximum,
                        )
                except EvidenceError as exc:
                    reason_code = (
                        "artifact_limit"
                        if "exceeds configured limit" in str(exc)
                        else "artifact_unavailable"
                    )
                    raise EvidenceVaultRequestError(
                        request_index,
                        reason_code,
                        f"evidence request {request_index} is absent from the vault and staging CAS: {exc}",
                    ) from exc
                resolved_by_identity[key] = data
                selected_bytes += len(data)

        return tuple(
            resolved_by_identity[request.identity_key]
            for request in requests
        )

    @staticmethod
    def _read_staged_artifact(
        artifact: VaultArtifactRefV1,
        evidence_store: FileEvidenceStore,
    ) -> tuple[VaultArtifactRefV1, bytes]:
        maximum = MAX_AUTHORITY_EVIDENCE_BYTES_V1 if artifact.role == AUTHORITY_EVIDENCE_ROLE_V1 else artifact.byte_size
        if maximum is None:
            raise EventStoreError("vault artifact omitted a bounded read ceiling")
        try:
            if artifact.identity_scheme == GENERIC_IDENTITY_SCHEME_V1:
                data = evidence_store.get(
                    artifact.digest,
                    maximum=maximum,
                )
            else:
                data = evidence_store.get_typed(
                    artifact.digest,
                    expected_type=artifact.type_tag,
                    maximum=maximum,
                )
        except EvidenceError as exc:
            raise EventStoreError(f"required staged evidence is unavailable: {exc}") from exc
        resolved = artifact.with_observed_size(len(data))
        if (
            digest_bytes_v1(
                data,
                identity_scheme=resolved.identity_scheme,
                type_tag=resolved.type_tag,
            )
            != resolved.digest
        ):
            raise EventStoreError("staged evidence fails its code-owned content identity")
        return resolved, data

    def _vault_used_bytes_locked(self) -> int:
        row = self._connection.execute("SELECT COALESCE(sum(byte_size), 0) FROM evidence_artifacts").fetchone()
        if row is None or type(row[0]) is not int or row[0] < 0:
            raise EventStoreCorruptionError("vault logical-byte accounting is invalid")
        return row[0]

    def _retain_artifact_locked(
        self,
        artifact: VaultArtifactRefV1,
        evidence_store: FileEvidenceStore,
        *,
        origin_event_digest: str,
        used_bytes: int,
    ) -> tuple[VaultArtifactRefV1, int]:
        self._require_writer_transaction()
        if type(origin_event_digest) is not str or _DIGEST_RE.fullmatch(origin_event_digest) is None:
            raise EventStoreError("vault origin event must be a full lowercase sha256 ID")
        existing = self._artifact_row_locked(
            identity_scheme=artifact.identity_scheme,
            type_tag=artifact.type_tag,
            digest=artifact.digest,
        )
        if existing is not None:
            retained = self._read_vault_identity_locked(
                artifact.identity_scheme,
                artifact.type_tag,
                artifact.digest,
                expected_size=artifact.byte_size,
            )
            return artifact.with_observed_size(len(retained)), used_bytes

        resolved, staged = self._read_staged_artifact(
            artifact,
            evidence_store,
        )
        if resolved.byte_size is None:
            raise EventStoreError("resolved vault artifact omitted its size")
        if used_bytes + resolved.byte_size > self._max_vault_bytes:
            raise EvidenceVaultCapacityError("new unique evidence exceeds the database vault byte ceiling")
        self._require_writer_transaction()
        cursor = self._connection.execute(
            """
            INSERT INTO evidence_artifacts (
                identity_scheme,
                type_tag,
                digest,
                byte_size,
                origin_event_digest,
                content
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (identity_scheme, type_tag, digest) DO NOTHING
            """,
            (
                resolved.identity_scheme,
                resolved.type_tag,
                resolved.digest,
                resolved.byte_size,
                origin_event_digest,
                sqlite3.Binary(staged),
            ),
        )
        inserted = cursor.rowcount == 1
        retained = self._read_vault_identity_locked(
            resolved.identity_scheme,
            resolved.type_tag,
            resolved.digest,
            expected_size=resolved.byte_size,
        )
        if retained != staged:
            raise EventStoreCorruptionError("vault identity collision retained different exact bytes")
        if not inserted:
            return resolved, used_bytes
        return resolved, used_bytes + resolved.byte_size

    def _insert_event_artifact_roles_locked(
        self,
        event: EventV1,
        manifest: tuple[VaultArtifactRefV1, ...],
    ) -> None:
        for artifact in manifest:
            if artifact.byte_size is None:
                raise EventStoreError("vault mapping omitted its observed byte size")
            self._require_writer_transaction()
            self._connection.execute(
                """
                INSERT INTO event_artifact_roles (
                    event_digest,
                    event_kind,
                    slot,
                    role,
                    ordinal,
                    locator,
                    identity_scheme,
                    type_tag,
                    artifact_digest,
                    byte_size
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_digest,
                    event.kind,
                    artifact.slot,
                    artifact.role,
                    artifact.ordinal,
                    artifact.locator,
                    artifact.identity_scheme,
                    artifact.type_tag,
                    artifact.digest,
                    artifact.byte_size,
                ),
            )

    def _stored_event_manifest_locked(
        self,
        event_digest: str,
    ) -> tuple[tuple[str, VaultArtifactRefV1], ...]:
        try:
            rows = self._connection.execute(
                """
                SELECT
                    event_kind,
                    slot,
                    role,
                    ordinal,
                    locator,
                    identity_scheme,
                    type_tag,
                    artifact_digest,
                    byte_size
                FROM event_artifact_roles
                WHERE event_digest = ?
                ORDER BY slot ASC
                """,
                (event_digest,),
            ).fetchall()
        except sqlite3.DatabaseError as exc:
            raise _sqlite_store_failure(
                "could not read retained event-artifact manifest",
                exc,
            ) from exc
        try:
            return tuple(
                (
                    row[0],
                    VaultArtifactRefV1(
                        slot=row[1],
                        role=row[2],
                        ordinal=row[3],
                        locator=row[4],
                        identity_scheme=row[5],
                        type_tag=row[6],
                        digest=row[7],
                        byte_size=row[8],
                    ),
                )
                for row in rows
            )
        except (EvidenceVaultError, IndexError, TypeError) as exc:
            raise EventStoreCorruptionError("retained event-artifact manifest is invalid") from exc

    def _verify_event_manifest_locked(
        self,
        event: EventV1,
        *,
        rehashed: set[tuple[str, str, str, int]] | None = None,
        artifact_cache: dict[tuple[str, str, str, int], bytes] | None = None,
        cache_keys: frozenset[tuple[str, str, str, int]] | None = None,
    ) -> tuple[VaultArtifactRefV1, ...]:
        try:
            expected = derive_event_artifact_manifest_v1(event)
        except EvidenceVaultError as exc:
            raise EventStoreCorruptionError(
                "retained event-artifact manifest is invalid"
            ) from exc
        stored_with_kinds = self._stored_event_manifest_locked(event.event_digest)
        if event.kind not in PROTECTED_EVIDENCE_EVENT_KINDS_V1:
            if stored_with_kinds:
                raise EventStoreCorruptionError("ordinary event retains an unexpected artifact manifest")
            return ()
        if len(stored_with_kinds) != len(expected):
            raise EventStoreCorruptionError("protected event artifact manifest is incomplete")
        resolved_expected: list[VaultArtifactRefV1] = []
        stored: list[VaultArtifactRefV1] = []
        for expected_value, (event_kind, stored_value) in zip(
            expected,
            stored_with_kinds,
            strict=True,
        ):
            if event_kind != event.kind:
                raise EventStoreCorruptionError("event-artifact manifest kind differs from its event")
            try:
                resolved_expected.append(
                    expected_value.with_observed_size(stored_value.byte_size)
                )
            except EvidenceVaultError as exc:
                raise EventStoreCorruptionError(
                    "retained event-artifact manifest is invalid"
                ) from exc
            stored.append(stored_value)
        if tuple(resolved_expected) != tuple(stored):
            raise EventStoreCorruptionError("retained artifact manifest differs from canonical event semantics")
        observed = rehashed if rehashed is not None else set()
        for artifact in stored:
            if artifact.byte_size is None:
                raise EventStoreCorruptionError("retained artifact manifest omitted its byte size")
            key = (*artifact.identity_key, artifact.byte_size)
            if key in observed:
                continue
            try:
                data = self._read_vault_identity_locked(
                    artifact.identity_scheme,
                    artifact.type_tag,
                    artifact.digest,
                    expected_size=artifact.byte_size,
                )
            except EvidenceVaultArtifactMissing as exc:
                raise EventStoreCorruptionError(
                    "retained event artifact is absent from the canonical vault"
                ) from exc
            observed.add(key)
            if (
                artifact_cache is not None
                and cache_keys is not None
                and key in cache_keys
            ):
                artifact_cache[key] = data
        return tuple(stored)

    def _validate_retained_evidence_locked(
        self,
        events: tuple[EventV1, ...],
        *,
        rehashed: set[tuple[str, str, str, int]] | None = None,
        artifact_cache: dict[tuple[str, str, str, int], bytes] | None = None,
        cache_keys: frozenset[tuple[str, str, str, int]] | None = None,
        validate_orphans: bool = True,
    ) -> None:
        observed = rehashed if rehashed is not None else set()
        for event in events:
            self._verify_event_manifest_locked(
                event,
                rehashed=observed,
                artifact_cache=artifact_cache,
                cache_keys=cache_keys,
            )
        if validate_orphans:
            self._validate_no_orphan_artifacts_locked()

    def _validate_no_orphan_artifacts_locked(self) -> None:
        try:
            orphan = self._connection.execute(
                """
                SELECT 1
                FROM evidence_artifacts AS artifact
                WHERE NOT EXISTS (
                    SELECT 1
                    FROM event_artifact_roles AS role
                    WHERE role.identity_scheme = artifact.identity_scheme
                      AND role.type_tag = artifact.type_tag
                      AND role.artifact_digest = artifact.digest
                      AND role.byte_size = artifact.byte_size
                      AND role.event_digest = artifact.origin_event_digest
                )
                LIMIT 1
                """
            ).fetchone()
        except sqlite3.DatabaseError as exc:
            raise _sqlite_store_failure(
                "could not validate canonical vault ownership",
                exc,
            ) from exc
        if orphan is not None:
            raise EventStoreCorruptionError("canonical vault contains an orphan artifact BLOB")

    def _load_missions_with_shared_evidence_validation(
        self,
        mission_ids: tuple[str, ...],
        *,
        cache_keys: frozenset[tuple[str, str, str, int]],
    ) -> dict[tuple[str, str, str, int], bytes]:
        """Validate each exact mission once and rehash each shared BLOB at most once."""

        if (
            type(mission_ids) is not tuple
            or not mission_ids
            or len(mission_ids) > MAX_VAULT_BATCH_REQUESTS_V1
            or any(
                type(mission_id) is not str
                or _DIGEST_RE.fullmatch(mission_id) is None
                for mission_id in mission_ids
            )
            or len(set(mission_ids)) != len(mission_ids)
        ):
            raise EventStoreError("vault origin missions require one bounded exact unique tuple")
        if (
            type(cache_keys) is not frozenset
            or not cache_keys
            or len(cache_keys) > MAX_VAULT_BATCH_REQUESTS_V1
            or any(
                type(key) is not tuple
                or len(key) != 4
                or type(key[0]) is not str
                or type(key[1]) is not str
                or type(key[2]) is not str
                or _DIGEST_RE.fullmatch(key[2]) is None
                or type(key[3]) is not int
                or key[3] < 0
                or key[3] > MAX_VAULT_ARTIFACT_BYTES_V1
                for key in cache_keys
            )
        ):
            raise EventStoreError("vault cache keys require one bounded exact immutable set")
        rehashed: set[tuple[str, str, str, int]] = set()
        artifact_cache: dict[tuple[str, str, str, int], bytes] = {}
        for mission_id in mission_ids:
            events = self._decode_rows(mission_id, self._rows(mission_id))
            if not events:
                raise EventStoreCorruptionError("vault origin mission has no retained event stream")
            self._validate_retained_lifecycle(events)
            self._validate_retained_evidence_locked(
                events,
                rehashed=rehashed,
                artifact_cache=artifact_cache,
                cache_keys=cache_keys,
                validate_orphans=False,
            )
        self._validate_no_orphan_artifacts_locked()
        return artifact_cache

    def load_event_artifact(
        self,
        event_digest: str,
        role: str,
        ordinal: int = 0,
    ) -> bytes:
        """Load one event-owned artifact through the exact bounded batch boundary."""

        try:
            selector = VaultEventArtifactSelectorV1(
                event_digest=event_digest,
                role=role,
                ordinal=ordinal,
            )
        except EvidenceVaultError as exc:
            raise EventStoreError(f"invalid event artifact selector: {exc}") from exc
        return self.load_event_artifacts(
            (selector,),
            maximum_total=DEFAULT_MAX_VAULT_BYTES_V1,
        )[0]

    def load_event_artifacts(
        self,
        selectors: tuple[VaultEventArtifactSelectorV1, ...],
        *,
        maximum_total: int,
    ) -> tuple[bytes, ...]:
        """Load a bounded ordered batch, validating each owner mission only once."""

        if (
            type(selectors) is not tuple
            or not selectors
            or len(selectors) > MAX_VAULT_BATCH_REQUESTS_V1
            or any(type(selector) is not VaultEventArtifactSelectorV1 for selector in selectors)
        ):
            raise EventStoreError("event artifact loading requires one bounded tuple of exact selectors")
        if (
            type(maximum_total) is not int
            or maximum_total < 0
            or maximum_total > DEFAULT_MAX_VAULT_BYTES_V1
        ):
            raise EventStoreError("event artifact batch maximum_total is outside the fixed vault bound")

        event_missions: dict[str, str] = {}
        for event_digest in dict.fromkeys(
            selector.event_digest for selector in selectors
        ):
            try:
                event_row = self._connection.execute(
                    "SELECT mission_id FROM events WHERE digest = ?",
                    (event_digest,),
                ).fetchone()
            except sqlite3.DatabaseError as exc:
                raise _sqlite_store_failure(
                    "could not read event-artifact owner",
                    exc,
                ) from exc
            if (
                event_row is None
                or type(event_row[0]) is not str
                or _DIGEST_RE.fullmatch(event_row[0]) is None
            ):
                raise EventStoreError("event artifact owner is not retained")
            event_missions[event_digest] = event_row[0]

        selected_rows: dict[
            VaultEventArtifactSelectorV1,
            tuple[str, str, str, int],
        ] = {}
        for selector in dict.fromkeys(selectors):
            try:
                row = self._connection.execute(
                    """
                    SELECT identity_scheme, type_tag, artifact_digest, byte_size
                    FROM event_artifact_roles
                    WHERE event_digest = ? AND role = ? AND ordinal = ?
                    """,
                    (
                        selector.event_digest,
                        selector.role,
                        selector.ordinal,
                    ),
                ).fetchone()
            except sqlite3.DatabaseError as exc:
                raise _sqlite_store_failure(
                    "could not read retained event artifact",
                    exc,
                ) from exc
            if row is None:
                raise EventStoreError("event artifact role is not retained")
            identity_scheme, type_tag = vault_identity_for_role_v1(selector.role)
            if (
                row[0] != identity_scheme
                or row[1] != type_tag
                or type(row[2]) is not str
                or _DIGEST_RE.fullmatch(row[2]) is None
                or type(row[3]) is not int
                or row[3] < 0
                or row[3] > MAX_VAULT_ARTIFACT_BYTES_V1
            ):
                raise EventStoreCorruptionError(
                    "retained event artifact differs from its code-owned selector"
                )
            selected_rows[selector] = (row[0], row[1], row[2], row[3])

        cache_keys = frozenset(selected_rows.values())
        if sum(key[3] for key in cache_keys) > maximum_total:
            raise EvidenceVaultRequestError(
                0,
                "batch_limit",
                "event artifact batch exceeds its aggregate byte ceiling",
            )
        artifact_cache = self._load_missions_with_shared_evidence_validation(
            tuple(sorted(set(event_missions.values()))),
            cache_keys=cache_keys,
        )
        selected: dict[VaultEventArtifactSelectorV1, bytes] = {}
        for selector, key in selected_rows.items():
            data = artifact_cache.get(key)
            if data is None:
                raise EventStoreCorruptionError(
                    "retained event artifact was not verified with its owner mission"
                )
            selected[selector] = data
        return tuple(selected[selector] for selector in selectors)

    def _rows(self, mission_id: str) -> list[tuple[int, str, str, str, bytes]]:
        if type(mission_id) is not str or _DIGEST_RE.fullmatch(mission_id) is None:
            raise EventStoreError("mission_id must be a full lowercase sha256 digest")
        try:
            rows = self._connection.execute(
                """
                SELECT seq, digest, prev_digest, kind, canonical
                FROM events
                WHERE mission_id = ?
                ORDER BY seq ASC
                """,
                (mission_id,),
            ).fetchall()
        except sqlite3.DatabaseError as exc:
            raise _sqlite_store_failure("could not read mission stream", exc) from exc
        return rows

    @staticmethod
    def _decode_rows(mission_id: str, rows: list[tuple[int, str, str, str, bytes]]) -> tuple[EventV1, ...]:
        events: list[EventV1] = []
        expected_prev = GENESIS_DIGEST
        for expected_seq, row in enumerate(rows):
            seq, digest, prev_digest, kind, canonical = row
            if type(canonical) is not bytes:
                raise EventStoreCorruptionError("retained event representation is not a BLOB")
            try:
                event = EventV1.from_canonical_bytes(canonical)
            except (ProtocolError, TypeError, ValueError) as exc:
                raise EventStoreCorruptionError(
                    f"invalid canonical event at {mission_id}:{expected_seq}: {exc}"
                ) from exc
            if event.to_canonical_bytes() != canonical:
                raise EventStoreCorruptionError("retained event bytes changed during decoding")
            if (
                type(seq) is not int
                or seq != expected_seq
                or event.seq != expected_seq
                or event.mission_id != mission_id
                or digest != event.event_digest
                or prev_digest != event.prev_digest
                or kind != event.kind
                or event.prev_digest != expected_prev
            ):
                raise EventStoreCorruptionError(
                    f"event metadata or predecessor mismatch at {mission_id}:{expected_seq}"
                )
            expected_prev = event.event_digest
            events.append(event)
        return tuple(events)

    def load(self, mission_id: str) -> tuple[EventV1, ...]:
        """Load and fully verify one mission-local event stream and lifecycle."""

        events = self._decode_rows(mission_id, self._rows(mission_id))
        if events:
            self._validate_retained_lifecycle(events)
        self._validate_retained_evidence_locked(events)
        return events

    @staticmethod
    def _validate_retained_lifecycle(events: tuple[EventV1, ...]) -> None:
        # Local import keeps the persistence and projection modules independently
        # importable while still making lifecycle validation mandatory at the boundary.
        from .reducer import ReductionError, reduce_events

        try:
            reduce_events(events)
        except ReductionError as exc:
            raise EventStoreCorruptionError(f"retained mission lifecycle is invalid: {exc}") from exc

    @staticmethod
    def _validate_proposed_lifecycle(events: tuple[EventV1, ...]) -> None:
        from .reducer import ReductionError, reduce_events

        try:
            reduce_events(events)
        except ReductionError as exc:
            raise EventStoreError(f"illegal mission lifecycle: {exc}") from exc

    def head(self, mission_id: str) -> str:
        """Return the verified mission head, or the fixed genesis digest when absent."""

        events = self.load(mission_id)
        return events[-1].event_digest if events else GENESIS_DIGEST

    @staticmethod
    def _validate_append_request(event: EventV1, expected_head: str) -> None:
        if type(event) is not EventV1:
            raise EventStoreError("append requires an exact EventV1")
        if type(expected_head) is not str or _DIGEST_RE.fullmatch(expected_head) is None:
            raise EventStoreError("expected_head must be a full lowercase sha256 digest")
        try:
            event.verify()
        except EventIntegrityError as exc:
            raise EventStoreError(f"refusing invalid event: {exc}") from exc

    def _prepare_append_locked(
        self,
        event: EventV1,
        *,
        expected_head: str,
    ) -> tuple[EventV1, ...]:
        events = self._decode_rows(
            event.mission_id,
            self._rows(event.mission_id),
        )
        if events:
            self._validate_retained_lifecycle(events)
        self._validate_retained_evidence_locked(events)
        actual_head = events[-1].event_digest if events else GENESIS_DIGEST
        if expected_head != actual_head:
            raise StaleHeadError(f"stale mission head: expected {expected_head}, retained {actual_head}")
        if events and events[-1].kind in TERMINAL_KINDS:
            raise ClosedStreamError(f"mission ended with {events[-1].kind}")
        expected_seq = len(events)
        if event.seq != expected_seq:
            raise EventStoreError(f"event sequence gap or fork: expected {expected_seq}, got {event.seq}")
        if event.prev_digest != actual_head:
            raise StaleHeadError(f"event predecessor {event.prev_digest} does not match head {actual_head}")
        self._validate_proposed_lifecycle((*events, event))
        return events

    def _insert_event_locked(self, event: EventV1) -> None:
        canonical = event.to_canonical_bytes()
        self._require_writer_transaction()
        self._connection.execute(
            """
            INSERT INTO events (
                mission_id, seq, digest, prev_digest, kind, canonical
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                event.mission_id,
                event.seq,
                event.event_digest,
                event.prev_digest,
                event.kind,
                sqlite3.Binary(canonical),
            ),
        )

    def _append_verified_event(
        self,
        event: EventV1,
        *,
        expected_head: str,
        evidence_store: FileEvidenceStore | None = None,
    ) -> EventV1:
        self._validate_append_request(event, expected_head)
        is_protected = event.kind in PROTECTED_EVIDENCE_EVENT_KINDS_V1
        if is_protected != (evidence_store is not None):
            raise EventStoreError("protected evidence events and vault retention must be paired")
        trusted_staging = self._trusted_staging_store(evidence_store) if evidence_store is not None else None
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            self._require_writer_transaction()
            events = self._prepare_append_locked(
                event,
                expected_head=expected_head,
            )
            if event.kind == "verifier_receipt_admitted":
                from .receipt_admission import (
                    validate_retained_receipt_admission_event,
                )

                if trusted_staging is None:
                    raise EventStoreError("receipt admission omitted its staging evidence store")
                overlay = VaultBackedFileEvidenceStore(
                    trusted_staging,
                    self._read_vault_identity_locked,
                )
                try:
                    validate_retained_receipt_admission_event(
                        retained=events,
                        event=event,
                        evidence_store=overlay,
                    )
                except EventStoreError:
                    raise
                except (ProtocolError, KeyError, TypeError, ValueError) as exc:
                    reason_code = getattr(
                        exc,
                        "reason_code",
                        "invalid_receipt_admission",
                    )
                    raise EventStoreError(
                        f"receipt admission evidence-view validation failed ({reason_code}): {exc}"
                    ) from exc

            if trusted_staging is not None:
                try:
                    expected_manifest = derive_event_artifact_manifest_v1(event)
                    used_bytes = self._vault_used_bytes_locked()
                    retained_manifest: list[VaultArtifactRefV1] = []
                    for artifact in expected_manifest:
                        retained_artifact, used_bytes = self._retain_artifact_locked(
                            artifact,
                            trusted_staging,
                            origin_event_digest=event.event_digest,
                            used_bytes=used_bytes,
                        )
                        retained_manifest.append(retained_artifact)
                    self._insert_event_artifact_roles_locked(
                        event,
                        tuple(retained_manifest),
                    )
                except EvidenceVaultError as exc:
                    raise EventStoreError(f"protected evidence retention failed: {exc}") from exc
            self._insert_event_locked(event)
            if trusted_staging is not None:
                self._verify_event_manifest_locked(event)
                orphan = self._connection.execute(
                    """
                    SELECT 1
                    FROM evidence_artifacts AS artifact
                    WHERE NOT EXISTS (
                        SELECT 1
                        FROM event_artifact_roles AS role
                        WHERE role.identity_scheme = artifact.identity_scheme
                          AND role.type_tag = artifact.type_tag
                          AND role.artifact_digest = artifact.digest
                          AND role.byte_size = artifact.byte_size
                          AND role.event_digest = artifact.origin_event_digest
                    )
                    LIMIT 1
                    """
                ).fetchone()
                if orphan is not None:
                    raise EventStoreCorruptionError("protected append would retain an orphan artifact")
            self._require_writer_transaction()
            self._connection.execute("COMMIT")
            return event
        except (StaleHeadError, ClosedStreamError, EventStoreError):
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise
        except sqlite3.IntegrityError as exc:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            message = str(exc)
            if "terminal" in message:
                raise ClosedStreamError(message) from exc
            raise EventStoreError(f"SQLite rejected event append: {message}") from exc
        except sqlite3.DatabaseError as exc:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise _sqlite_store_failure("event append failed", exc) from exc
        except BaseException:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise

    def append(self, event: EventV1, *, expected_head: str) -> EventV1:
        """Atomically append one ordinary event.

        The four byte-claiming event kinds are reserved because their exact BLOBs and
        code-owned role manifests must commit with the canonical event.
        """

        self._validate_append_request(event, expected_head)
        if event.kind in PROTECTED_EVIDENCE_EVENT_KINDS_V1:
            raise EventStoreError(f"{event.kind} requires a dedicated evidence-retaining append")
        return self._append_verified_event(
            event,
            expected_head=expected_head,
        )

    def append_evidence_event(
        self,
        event: EventV1,
        *,
        expected_head: str,
        evidence_store: FileEvidenceStore,
    ) -> EventV1:
        """Atomically retain one non-receipt byte-claiming event and its BLOBs."""

        self._validate_append_request(event, expected_head)
        if event.kind not in NON_RECEIPT_EVIDENCE_EVENT_KINDS_V1:
            raise EventStoreError("append_evidence_event requires a non-receipt protected event")
        trusted_staging = self._trusted_staging_store(evidence_store)
        return self._append_verified_event(
            event,
            expected_head=expected_head,
            evidence_store=trusted_staging,
        )

    def append_receipt_admission(
        self,
        event: EventV1,
        *,
        expected_head: str,
        evidence_store: object,
    ) -> EventV1:
        """Atomically validate vault-first evidence and retain one receipt admission."""

        self._validate_append_request(event, expected_head)
        if event.kind != "verifier_receipt_admitted":
            raise EventStoreError("append_receipt_admission requires verifier_receipt_admitted")
        trusted_staging = self._trusted_staging_store(evidence_store)
        return self._append_verified_event(
            event,
            expected_head=expected_head,
            evidence_store=trusted_staging,
        )

    def store_checkpoint(self, checkpoint: SignedCheckpoint) -> SignedCheckpoint:
        """Retain opaque signed-head data without claiming that it has been verified."""

        if type(checkpoint) is not SignedCheckpoint:
            raise EventStoreError("store_checkpoint requires an exact SignedCheckpoint")
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            self._require_writer_transaction()
            events = self._decode_rows(
                checkpoint.mission_id,
                self._rows(checkpoint.mission_id),
            )
            if events:
                self._validate_retained_lifecycle(events)
            self._validate_retained_evidence_locked(events)
            row = self._connection.execute(
                """
                SELECT 1 FROM events
                WHERE mission_id = ? AND digest = ?
                """,
                (checkpoint.mission_id, checkpoint.event_digest),
            ).fetchone()
            if row is None:
                raise EventStoreError("checkpoint must reference a retained mission event")
            self._require_writer_transaction()
            self._connection.execute(
                """
                INSERT INTO signed_checkpoints (
                    mission_id, event_digest, signer_id, algorithm, signed_at, signature
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    checkpoint.mission_id,
                    checkpoint.event_digest,
                    checkpoint.signer_id,
                    checkpoint.algorithm,
                    checkpoint.signed_at,
                    sqlite3.Binary(checkpoint.signature),
                ),
            )
            self._require_writer_transaction()
            self._connection.execute("COMMIT")
            return checkpoint
        except EventStoreError:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise
        except sqlite3.IntegrityError as exc:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise EventStoreError(f"SQLite rejected checkpoint: {exc}") from exc
        except sqlite3.DatabaseError as exc:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise _sqlite_store_failure("checkpoint storage failed", exc) from exc

    def load_checkpoints(self, mission_id: str) -> tuple[SignedCheckpoint, ...]:
        """Load retained signature data in deterministic order."""

        if type(mission_id) is not str or _DIGEST_RE.fullmatch(mission_id) is None:
            raise EventStoreError("mission_id must be a full lowercase sha256 digest")
        self.load(mission_id)
        try:
            rows = self._connection.execute(
                """
                SELECT mission_id, event_digest, signer_id, algorithm, signed_at, signature
                FROM signed_checkpoints
                WHERE mission_id = ?
                ORDER BY signed_at ASC, event_digest ASC, signer_id ASC
                """,
                (mission_id,),
            ).fetchall()
        except sqlite3.DatabaseError as exc:
            raise _sqlite_store_failure("could not read checkpoints", exc) from exc
        try:
            return tuple(SignedCheckpoint(*row) for row in rows)
        except (ProtocolError, TypeError, ValueError) as exc:
            raise EventStoreCorruptionError(f"invalid retained checkpoint: {exc}") from exc
