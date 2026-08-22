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
from ..protocol import ProtocolError, canonical_dumps, content_id, strict_loads
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
_SQLITE_SCHEMA_VERSION: Final = 4
_SQLITE_LEGACY_BLOCKED_SCHEMA_VERSION: Final = 3
_SQLITE_LEGACY_INTEGRITY_SCHEMA_VERSION: Final = 2
_SQLITE_LEGACY_VAULT_SCHEMA_VERSION: Final = 1
_INTEGRITY_IDENTITY_RE: Final = re.compile(
    r"^[A-Za-z][A-Za-z0-9_.:-]{1,127}$",
    re.ASCII,
)
_SET_SQLITE_APPLICATION_ID: Final = "PRAGMA application_id = 1163156017"
_SET_SQLITE_SCHEMA_VERSION: Final = "PRAGMA user_version = 4"
_SQLITE_LEGACY_VAULT_SCHEMA_CONTRACT_SHA256: Final = (
    "9d29c7abe7aef05db290cef46687eb19833c073d256558ff5ec555bbe9a04b90"
)
# The exact schema-version-2 contract this release migrates forward from.
_SQLITE_LEGACY_INTEGRITY_V2_SCHEMA_CONTRACT_SHA256: Final = (
    "8fca39b7027ae6df3f6044d064a7c9346bc0d617c174839197ba334355db34f2"
)
# The exact schema-version-3 contract this release migrates forward from.
_SQLITE_LEGACY_INTEGRITY_V3_SCHEMA_CONTRACT_SHA256: Final = (
    "b058187a96486d979ae6988e86a0118f2c846c3624abadadb903fe54d4ce10ae"
)
# Recomputed from SQLite's retained canonical schema SQL after every intentional
# schema change.  The temporary sentinel makes an incomplete migration fail closed.
_SQLITE_SCHEMA_CONTRACT_SHA256: Final = (
    "96a1ce21d28ece41299055f4d2f5f13809a0a121eff92fc47add8210f0f1e4b3"
)
_LEGACY_STORE_PROFILE_V1: Final = "legacy_fixture_v1"
_MODELED_INTEGRITY_STORE_PROFILE_V1: Final = "modeled_integrity_fixture_v1"
_ACCEPTANCE_MODE_MODELED_UNSIGNED_V1: Final = "modeled_unsigned_code_derived"
_ACCEPTANCE_MODE_QUALIFIED_SIGNED_V1: Final = "qualified_signed_fixture"


def _qualified_evidence_refusals() -> tuple[type[BaseException], ...]:
    """The qualification-layer refusal family surfaced by the qualified accept primitives.

    All three carry a ``reason_code`` and mean the same thing at the store boundary: the
    qualified evidence did not authenticate.  Imported lazily to avoid an import cycle
    (``integrity_adapters`` imports from ``integrity_transition``, which imports this module).
    """

    from .head_authority_adapters_v1 import HeadAuthorityAdapterError
    from .integrity_adapters_v1 import IntegrityAdapterError
    from .qualified_evidence_v1 import QualifiedEvidenceError

    return (QualifiedEvidenceError, IntegrityAdapterError, HeadAuthorityAdapterError)
_INTEGRITY_PHASES_V1: Final = frozenset(
    {"pending", "anchor_statement", "checkpoint_candidate", "finalization"}
)
_MAX_INTEGRITY_RECORD_BYTES_V1: Final = 16 * 1024 * 1024
_MAX_INTEGRITY_EVIDENCE_BYTES_V1: Final = 1024 * 1024
_MAX_INTEGRITY_TRANSITION_EVIDENCE_BYTES_V1: Final = 16 * 1024 * 1024
_BLOCKED_FINALITY_DISPOSITIONS_SQL_V1: Final = (
    "'instance_sealed', 'retry_authorized'"
)
_INTEGRITY_FINALITY_CAPACITY_RESERVE_BYTES_V1: Final = (
    (6 * _MAX_INTEGRITY_RECORD_BYTES_V1)
    + _MAX_INTEGRITY_TRANSITION_EVIDENCE_BYTES_V1
)
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


class IntegrityFinalityRequiredError(EventStoreError):
    """Raised when an integrity-enrolled store receives an ordinary append."""


class PendingIntegrityTransitionError(EventStoreError):
    """Raised when an unfinalized instance-global transition blocks progress."""


class IntegrityTransitionConflictError(EventStoreError):
    """Raised when an idempotency identity is reused with different bytes."""


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
    ignore_check_constraints: bool
    read_uncommitted: bool
    writable_schema: bool
    database_mode: int


@dataclass(frozen=True, slots=True)
class _PreparedStorePath:
    path: Path
    descriptor: int
    device: int
    inode: int


@dataclass(frozen=True, slots=True)
class _IntegrityValidationCacheKey:
    """SQLite change signals for one fully authenticated retained-state replay."""

    total_changes: int
    data_version: int
    schema_version: int
    journal_mode: str
    synchronous: int
    foreign_keys: int
    trusted_schema: int
    ignore_check_constraints: int
    read_uncommitted: int
    writable_schema: int


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
        self._integrity_validation_cache: _IntegrityValidationCacheKey | None = (
            None
        )
        self._validated_schema_version: int | None = None
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
            self._connection.execute(
                "PRAGMA ignore_check_constraints = OFF"
            )
            self._connection.execute("PRAGMA read_uncommitted = OFF")
            self._connection.execute("PRAGMA writable_schema = OFF")
            if self._connection.execute("PRAGMA foreign_keys").fetchone() != (1,):
                raise EventStoreError("SQLite foreign-key enforcement is unavailable")
            if self._connection.execute("PRAGMA trusted_schema").fetchone() != (0,):
                raise EventStoreError("SQLite trusted-schema hardening is unavailable")
            if self._connection.execute(
                "PRAGMA ignore_check_constraints"
            ).fetchone() != (0,):
                raise EventStoreError(
                    "SQLite CHECK-constraint enforcement is unavailable"
                )
            if self._connection.execute(
                "PRAGMA read_uncommitted"
            ).fetchone() != (0,):
                raise EventStoreError(
                    "SQLite refused committed-only reads"
                )
            if self._connection.execute(
                "PRAGMA writable_schema"
            ).fetchone() != (0,):
                raise EventStoreError(
                    "SQLite writable-schema hardening is unavailable"
                )
            if self._connection.execute("PRAGMA synchronous").fetchone() != (self._journal_policy.synchronous_value,):
                raise EventStoreError("SQLite refused the required safe synchronous mode")
            if str(journal_mode[0]).lower() == "wal":
                raise EventStoreError("Etzio does not admit WAL under the declared runtime matrix")
            self._initialize_schema()
            self._refresh_validated_schema_version_locked()
            retained_vault_bytes = self._vault_used_bytes_locked()
            if retained_vault_bytes > self._max_vault_bytes:
                raise EvidenceVaultCapacityError(
                    "retained unique evidence exceeds the configured database vault byte ceiling"
                )
            self._validate_integrity_state_locked()
            if (
                self._logical_evidence_storage_used_locked()
                > self._max_vault_bytes
            ):
                raise EvidenceVaultCapacityError(
                    "retained vault plus integrity evidence exceeds the configured byte ceiling"
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
        if identity == (
            _SQLITE_APPLICATION_ID,
            _SQLITE_LEGACY_BLOCKED_SCHEMA_VERSION,
        ):
            self._migrate_blocked_v3_to_qualified_v4()
            return
        if identity == (
            _SQLITE_APPLICATION_ID,
            _SQLITE_LEGACY_INTEGRITY_SCHEMA_VERSION,
        ):
            self._migrate_integrity_v2_to_blocked_v3()
            return
        if identity == (
            _SQLITE_APPLICATION_ID,
            _SQLITE_LEGACY_VAULT_SCHEMA_VERSION,
        ):
            self._migrate_vault_v1_to_integrity_v2()
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

    @staticmethod
    def _integrity_schema_sql() -> str:
        digest_check = """
            length({column}) = 71
            AND substr({column}, 1, 7) = 'sha256:'
            AND substr({column}, 8) NOT GLOB '*[^0-9a-f]*'
        """

        def checked(column: str) -> str:
            return digest_check.format(column=column)

        identity_check = """
            length({column}) BETWEEN 2 AND 128
            AND substr({column}, 1, 1) GLOB '[A-Za-z]'
            AND {column} NOT GLOB '*[^A-Za-z0-9_.:-]*'
        """

        def identity_checked(column: str) -> str:
            return identity_check.format(column=column)

        phases_sql = ", ".join(
            f"'{phase}'" for phase in sorted(_INTEGRITY_PHASES_V1)
        )
        return f"""
            CREATE TABLE IF NOT EXISTS store_profile (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                profile TEXT NOT NULL CHECK (
                    profile IN (
                        '{_LEGACY_STORE_PROFILE_V1}',
                        '{_MODELED_INTEGRITY_STORE_PROFILE_V1}'
                    )
                ),
                service_instance_id TEXT,
                environment_id TEXT,
                validation_policy_id TEXT,
                validation_policy_wire BLOB,
                authority_binding_id TEXT,
                authority_binding_wire BLOB,
                CHECK (
                    (
                        profile = '{_LEGACY_STORE_PROFILE_V1}'
                        AND service_instance_id IS NULL
                        AND environment_id IS NULL
                        AND validation_policy_id IS NULL
                        AND validation_policy_wire IS NULL
                        AND authority_binding_id IS NULL
                        AND authority_binding_wire IS NULL
                    )
                    OR (
                        profile = '{_MODELED_INTEGRITY_STORE_PROFILE_V1}'
                        AND typeof(service_instance_id) = 'text'
                        AND {identity_checked("service_instance_id")}
                        AND typeof(environment_id) = 'text'
                        AND {identity_checked("environment_id")}
                        AND typeof(validation_policy_id) = 'text'
                        AND {checked("validation_policy_id")}
                        AND typeof(validation_policy_wire) = 'blob'
                        AND length(validation_policy_wire)
                            BETWEEN 1 AND {_MAX_INTEGRITY_RECORD_BYTES_V1}
                        AND typeof(authority_binding_id) = 'text'
                        AND {checked("authority_binding_id")}
                        AND typeof(authority_binding_wire) = 'blob'
                        AND length(authority_binding_wire)
                            BETWEEN 1 AND {_MAX_INTEGRITY_RECORD_BYTES_V1}
                    )
                )
            ) STRICT;

            INSERT OR IGNORE INTO store_profile (
                singleton,
                profile,
                service_instance_id,
                environment_id,
                validation_policy_id,
                validation_policy_wire,
                authority_binding_id,
                authority_binding_wire
            ) VALUES (
                1,
                '{_LEGACY_STORE_PROFILE_V1}',
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL
            );

            CREATE TABLE IF NOT EXISTS integrity_evidence_artifacts (
                evidence_id TEXT PRIMARY KEY CHECK ({checked("evidence_id")}),
                byte_size INTEGER NOT NULL CHECK (
                    byte_size >= 0
                    AND byte_size <= {_MAX_INTEGRITY_EVIDENCE_BYTES_V1}
                ),
                content BLOB NOT NULL CHECK (
                    typeof(content) = 'blob'
                    AND length(content) = byte_size
                )
            ) STRICT, WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS integrity_pending_transitions (
                event_digest TEXT PRIMARY KEY CHECK ({checked("event_digest")}),
                mission_id TEXT NOT NULL CHECK ({checked("mission_id")}),
                event_seq INTEGER NOT NULL CHECK (event_seq >= 0),
                instance_sequence INTEGER NOT NULL UNIQUE CHECK (
                    instance_sequence >= 0
                ),
                record_id TEXT NOT NULL UNIQUE CHECK ({checked("record_id")}),
                record BLOB NOT NULL CHECK (
                    typeof(record) = 'blob'
                    AND length(record) BETWEEN 1 AND {_MAX_INTEGRITY_RECORD_BYTES_V1}
                ),
                UNIQUE (mission_id, event_seq),
                FOREIGN KEY (event_digest)
                    REFERENCES events (digest)
                    ON UPDATE RESTRICT ON DELETE RESTRICT
                    DEFERRABLE INITIALLY DEFERRED
            ) STRICT, WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS integrity_anchor_statements (
                event_digest TEXT PRIMARY KEY,
                record_id TEXT NOT NULL UNIQUE CHECK ({checked("record_id")}),
                anchor_statement_id TEXT NOT NULL UNIQUE CHECK (
                    {checked("anchor_statement_id")}
                ),
                record BLOB NOT NULL CHECK (
                    typeof(record) = 'blob'
                    AND length(record) BETWEEN 1 AND {_MAX_INTEGRITY_RECORD_BYTES_V1}
                ),
                FOREIGN KEY (event_digest)
                    REFERENCES integrity_pending_transitions (event_digest)
                    ON UPDATE RESTRICT ON DELETE RESTRICT
            ) STRICT, WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS integrity_checkpoint_candidates (
                event_digest TEXT PRIMARY KEY,
                record_id TEXT NOT NULL UNIQUE CHECK ({checked("record_id")}),
                checkpoint_id TEXT NOT NULL UNIQUE CHECK (
                    {checked("checkpoint_id")}
                ),
                checkpoint_attestation_id TEXT NOT NULL UNIQUE CHECK (
                    {checked("checkpoint_attestation_id")}
                ),
                record BLOB NOT NULL CHECK (
                    typeof(record) = 'blob'
                    AND length(record) BETWEEN 1 AND {_MAX_INTEGRITY_RECORD_BYTES_V1}
                ),
                FOREIGN KEY (event_digest)
                    REFERENCES integrity_anchor_statements (event_digest)
                    ON UPDATE RESTRICT ON DELETE RESTRICT
            ) STRICT, WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS integrity_finalizations (
                event_digest TEXT PRIMARY KEY,
                record_id TEXT NOT NULL UNIQUE CHECK ({checked("record_id")}),
                record BLOB NOT NULL CHECK (
                    typeof(record) = 'blob'
                    AND length(record) BETWEEN 1 AND {_MAX_INTEGRITY_RECORD_BYTES_V1}
                ),
                FOREIGN KEY (event_digest)
                    REFERENCES integrity_checkpoint_candidates (event_digest)
                    ON UPDATE RESTRICT ON DELETE RESTRICT
            ) STRICT, WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS integrity_transition_evidence (
                event_digest TEXT NOT NULL,
                phase TEXT NOT NULL CHECK (phase IN ({phases_sql})),
                slot INTEGER NOT NULL CHECK (slot BETWEEN 0 AND 255),
                evidence_kind TEXT NOT NULL CHECK (
                    evidence_kind IN (
                        'trusted_time',
                        'revocation_metadata',
                        'head_anchor_receipt',
                        'external_floor'
                    )
                ),
                source_id TEXT NOT NULL CHECK (
                    length(source_id) BETWEEN 1 AND 256
                ),
                evidence_id TEXT NOT NULL,
                PRIMARY KEY (event_digest, phase, slot),
                UNIQUE (
                    event_digest,
                    phase,
                    evidence_kind,
                    source_id,
                    evidence_id
                ),
                FOREIGN KEY (event_digest)
                    REFERENCES integrity_pending_transitions (event_digest)
                    ON UPDATE RESTRICT ON DELETE RESTRICT
                    DEFERRABLE INITIALLY DEFERRED,
                FOREIGN KEY (evidence_id)
                    REFERENCES integrity_evidence_artifacts (evidence_id)
                    ON UPDATE RESTRICT ON DELETE RESTRICT
            ) STRICT, WITHOUT ROWID;

            CREATE INDEX IF NOT EXISTS integrity_finalized_mission_head
                ON integrity_pending_transitions (
                    mission_id,
                    event_seq DESC,
                    instance_sequence DESC
                );

            CREATE INDEX IF NOT EXISTS integrity_transition_evidence_identity
                ON integrity_transition_evidence (
                    evidence_id,
                    event_digest,
                    phase,
                    slot
                );

            CREATE TRIGGER IF NOT EXISTS store_profile_reject_delete
            BEFORE DELETE ON store_profile
            BEGIN
                SELECT RAISE(ABORT, 'store profile is permanent');
            END;

            CREATE TRIGGER IF NOT EXISTS store_profile_validate_update
            BEFORE UPDATE ON store_profile
            WHEN NOT (
                OLD.singleton = 1
                AND OLD.profile = '{_LEGACY_STORE_PROFILE_V1}'
                AND OLD.service_instance_id IS NULL
                AND OLD.environment_id IS NULL
                AND OLD.validation_policy_id IS NULL
                AND OLD.validation_policy_wire IS NULL
                AND OLD.authority_binding_id IS NULL
                AND OLD.authority_binding_wire IS NULL
                AND NEW.singleton = 1
                AND NEW.profile = '{_MODELED_INTEGRITY_STORE_PROFILE_V1}'
                AND NOT EXISTS (SELECT 1 FROM events)
                AND NOT EXISTS (SELECT 1 FROM signed_checkpoints)
                AND NOT EXISTS (SELECT 1 FROM evidence_artifacts)
                AND NOT EXISTS (SELECT 1 FROM event_artifact_roles)
                AND NOT EXISTS (
                    SELECT 1 FROM integrity_pending_transitions
                )
            )
            BEGIN
                SELECT RAISE(ABORT, 'store profile transition is forbidden');
            END;

            CREATE TRIGGER IF NOT EXISTS integrity_pending_require_profile
            BEFORE INSERT ON integrity_pending_transitions
            WHEN (
                SELECT profile FROM store_profile WHERE singleton = 1
            ) != '{_MODELED_INTEGRITY_STORE_PROFILE_V1}'
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'typed integrity requires the modeled integrity profile'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS integrity_pending_require_next_global
            BEFORE INSERT ON integrity_pending_transitions
            WHEN NEW.instance_sequence != (
                SELECT count(*) FROM integrity_finalizations
            )
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'integrity instance sequence is not the finalized successor'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS integrity_pending_reject_open_transition
            BEFORE INSERT ON integrity_pending_transitions
            WHEN EXISTS (
                SELECT 1
                FROM integrity_pending_transitions AS pending
                LEFT JOIN integrity_finalizations AS finalized
                  ON finalized.event_digest = pending.event_digest
                WHERE finalized.event_digest IS NULL
            )
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'an instance-global integrity transition is pending'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS events_require_integrity_pending
            BEFORE INSERT ON events
            WHEN (
                SELECT profile FROM store_profile WHERE singleton = 1
            ) = '{_MODELED_INTEGRITY_STORE_PROFILE_V1}'
            AND NOT EXISTS (
                SELECT 1
                FROM integrity_pending_transitions AS pending
                WHERE pending.event_digest = NEW.digest
                  AND pending.mission_id = NEW.mission_id
                  AND pending.event_seq = NEW.seq
            )
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'modeled integrity event omitted its pending transition'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS events_reject_while_integrity_pending
            BEFORE INSERT ON events
            WHEN EXISTS (
                SELECT 1
                FROM integrity_pending_transitions AS pending
                LEFT JOIN integrity_finalizations AS finalized
                  ON finalized.event_digest = pending.event_digest
                WHERE finalized.event_digest IS NULL
                  AND pending.event_digest != NEW.digest
            )
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'an instance-global integrity transition is pending'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS integrity_evidence_reject_update
            BEFORE UPDATE ON integrity_evidence_artifacts
            BEGIN
                SELECT RAISE(ABORT, 'integrity evidence is append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS integrity_evidence_reject_delete
            BEFORE DELETE ON integrity_evidence_artifacts
            BEGIN
                SELECT RAISE(ABORT, 'integrity evidence is append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS integrity_transition_evidence_reject_update
            BEFORE UPDATE ON integrity_transition_evidence
            BEGIN
                SELECT RAISE(ABORT, 'integrity evidence mappings are append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS integrity_transition_evidence_reject_delete
            BEFORE DELETE ON integrity_transition_evidence
            BEGIN
                SELECT RAISE(ABORT, 'integrity evidence mappings are append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS integrity_pending_reject_update
            BEFORE UPDATE ON integrity_pending_transitions
            BEGIN
                SELECT RAISE(ABORT, 'integrity pending transitions are append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS integrity_pending_reject_delete
            BEFORE DELETE ON integrity_pending_transitions
            BEGIN
                SELECT RAISE(ABORT, 'integrity pending transitions are append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS integrity_anchor_reject_update
            BEFORE UPDATE ON integrity_anchor_statements
            BEGIN
                SELECT RAISE(ABORT, 'integrity anchor statements are append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS integrity_anchor_reject_delete
            BEFORE DELETE ON integrity_anchor_statements
            BEGIN
                SELECT RAISE(ABORT, 'integrity anchor statements are append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS integrity_checkpoint_reject_update
            BEFORE UPDATE ON integrity_checkpoint_candidates
            BEGIN
                SELECT RAISE(ABORT, 'integrity checkpoint candidates are append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS integrity_checkpoint_reject_delete
            BEFORE DELETE ON integrity_checkpoint_candidates
            BEGIN
                SELECT RAISE(ABORT, 'integrity checkpoint candidates are append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS integrity_finalization_reject_update
            BEFORE UPDATE ON integrity_finalizations
            BEGIN
                SELECT RAISE(ABORT, 'integrity finalizations are append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS integrity_finalization_reject_delete
            BEFORE DELETE ON integrity_finalizations
            BEGIN
                SELECT RAISE(ABORT, 'integrity finalizations are append-only');
            END;
        """


    @staticmethod
    def _blocked_finality_schema_sql() -> str:
        digest_check = """
            length({column}) = 71
            AND substr({column}, 1, 7) = 'sha256:'
            AND substr({column}, 8) NOT GLOB '*[^0-9a-f]*'
        """

        def checked(column: str) -> str:
            return digest_check.format(column=column)

        return f"""
            CREATE TABLE IF NOT EXISTS integrity_recovery_profile (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                recovery_profile_id TEXT NOT NULL CHECK (
                    {checked('recovery_profile_id')}
                ),
                recovery_profile_wire BLOB NOT NULL CHECK (
                    typeof(recovery_profile_wire) = 'blob'
                    AND length(recovery_profile_wire)
                        BETWEEN 1 AND {_MAX_INTEGRITY_RECORD_BYTES_V1}
                )
            ) STRICT;

            CREATE TABLE IF NOT EXISTS integrity_blocked_observations (
                event_digest TEXT NOT NULL CHECK ({checked('event_digest')}),
                attempt_ordinal INTEGER NOT NULL CHECK (attempt_ordinal > 0),
                observation_id TEXT NOT NULL UNIQUE CHECK (
                    {checked('observation_id')}
                ),
                unresolved_phase TEXT NOT NULL CHECK (
                    unresolved_phase IN (
                        'anchor_statement_ready',
                        'checkpoint_candidate_retained',
                        'local_pending'
                    )
                ),
                record BLOB NOT NULL CHECK (
                    typeof(record) = 'blob'
                    AND length(record)
                        BETWEEN 1 AND {_MAX_INTEGRITY_RECORD_BYTES_V1}
                ),
                PRIMARY KEY (event_digest, attempt_ordinal),
                FOREIGN KEY (event_digest)
                    REFERENCES integrity_pending_transitions (event_digest)
                    ON UPDATE RESTRICT ON DELETE RESTRICT
            ) STRICT, WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS integrity_recovery_decisions (
                decision_id TEXT PRIMARY KEY CHECK ({checked('decision_id')}),
                event_digest TEXT NOT NULL CHECK ({checked('event_digest')}),
                blocked_observation_id TEXT NOT NULL UNIQUE CHECK (
                    {checked('blocked_observation_id')}
                ),
                disposition TEXT NOT NULL CHECK (
                    disposition IN ({_BLOCKED_FINALITY_DISPOSITIONS_SQL_V1})
                ),
                record BLOB NOT NULL CHECK (
                    typeof(record) = 'blob'
                    AND length(record)
                        BETWEEN 1 AND {_MAX_INTEGRITY_RECORD_BYTES_V1}
                ),
                FOREIGN KEY (blocked_observation_id)
                    REFERENCES integrity_blocked_observations (observation_id)
                    ON UPDATE RESTRICT ON DELETE RESTRICT
            ) STRICT, WITHOUT ROWID;

            CREATE INDEX IF NOT EXISTS integrity_blocked_latest_attempt
                ON integrity_blocked_observations (
                    event_digest,
                    attempt_ordinal DESC
                );

            CREATE TRIGGER IF NOT EXISTS integrity_recovery_profile_reject_update
            BEFORE UPDATE ON integrity_recovery_profile
            BEGIN
                SELECT RAISE(ABORT, 'the integrity recovery profile is immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS integrity_recovery_profile_reject_delete
            BEFORE DELETE ON integrity_recovery_profile
            BEGIN
                SELECT RAISE(ABORT, 'the integrity recovery profile is immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS integrity_blocked_reject_update
            BEFORE UPDATE ON integrity_blocked_observations
            BEGIN
                SELECT RAISE(ABORT, 'blocked finality observations are append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS integrity_blocked_reject_delete
            BEFORE DELETE ON integrity_blocked_observations
            BEGIN
                SELECT RAISE(ABORT, 'blocked finality observations are append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS integrity_recovery_decision_reject_update
            BEFORE UPDATE ON integrity_recovery_decisions
            BEGIN
                SELECT RAISE(ABORT, 'governed recovery decisions are append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS integrity_recovery_decision_reject_delete
            BEFORE DELETE ON integrity_recovery_decisions
            BEGIN
                SELECT RAISE(ABORT, 'governed recovery decisions are append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS integrity_blocked_reject_finalized
            BEFORE INSERT ON integrity_blocked_observations
            WHEN EXISTS (
                SELECT 1
                FROM integrity_finalizations
                WHERE event_digest = NEW.event_digest
            )
            BEGIN
                SELECT RAISE(ABORT, 'a finalized integrity transition cannot be blocked');
            END;

            CREATE TRIGGER IF NOT EXISTS integrity_blocked_reject_after_seal
            BEFORE INSERT ON integrity_blocked_observations
            WHEN EXISTS (
                SELECT 1
                FROM integrity_recovery_decisions
                WHERE disposition = 'instance_sealed'
            )
            BEGIN
                SELECT RAISE(ABORT, 'a sealed instance admits no further blocked observation');
            END;

            CREATE TRIGGER IF NOT EXISTS integrity_recovery_reject_after_seal
            BEFORE INSERT ON integrity_recovery_decisions
            WHEN EXISTS (
                SELECT 1
                FROM integrity_recovery_decisions
                WHERE disposition = 'instance_sealed'
            )
            BEGIN
                SELECT RAISE(ABORT, 'a sealed instance admits no further recovery decision');
            END;

            CREATE TRIGGER IF NOT EXISTS integrity_recovery_require_latest_observation
            BEFORE INSERT ON integrity_recovery_decisions
            WHEN NOT EXISTS (
                SELECT 1
                FROM integrity_blocked_observations AS latest
                WHERE latest.observation_id = NEW.blocked_observation_id
                  AND latest.event_digest = NEW.event_digest
                  AND latest.attempt_ordinal = (
                        SELECT max(attempt_ordinal)
                        FROM integrity_blocked_observations
                        WHERE event_digest = NEW.event_digest
                  )
            )
            BEGIN
                SELECT RAISE(ABORT, 'a recovery decision must answer the latest blocked observation');
            END;
        """


    @staticmethod
    def _qualified_acceptance_schema_sql() -> str:
        digest_check = """
            length({column}) = 71
            AND substr({column}, 1, 7) = 'sha256:'
            AND substr({column}, 8) NOT GLOB '*[^0-9a-f]*'
        """

        def checked(column: str) -> str:
            return digest_check.format(column=column)

        return f"""
            CREATE TABLE IF NOT EXISTS integrity_acceptance_profile (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                acceptance_mode TEXT NOT NULL CHECK (
                    acceptance_mode IN ('{_ACCEPTANCE_MODE_QUALIFIED_SIGNED_V1}')
                ),
                qualified_time_profile_id TEXT NOT NULL CHECK (
                    {checked('qualified_time_profile_id')}
                ),
                qualified_time_profile_wire BLOB NOT NULL CHECK (
                    typeof(qualified_time_profile_wire) = 'blob'
                    AND length(qualified_time_profile_wire)
                        BETWEEN 1 AND {_MAX_INTEGRITY_RECORD_BYTES_V1}
                ),
                qualified_head_profile_id TEXT NOT NULL CHECK (
                    {checked('qualified_head_profile_id')}
                ),
                qualified_head_profile_wire BLOB NOT NULL CHECK (
                    typeof(qualified_head_profile_wire) = 'blob'
                    AND length(qualified_head_profile_wire)
                        BETWEEN 1 AND {_MAX_INTEGRITY_RECORD_BYTES_V1}
                )
            ) STRICT;

            CREATE TRIGGER IF NOT EXISTS integrity_acceptance_profile_reject_update
            BEFORE UPDATE ON integrity_acceptance_profile
            BEGIN
                SELECT RAISE(ABORT, 'the integrity acceptance profile is immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS integrity_acceptance_profile_reject_delete
            BEFORE DELETE ON integrity_acceptance_profile
            BEGIN
                SELECT RAISE(ABORT, 'the integrity acceptance profile is immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS integrity_acceptance_require_modeled_profile
            BEFORE INSERT ON integrity_acceptance_profile
            WHEN NOT EXISTS (
                SELECT 1 FROM store_profile
                WHERE profile = '{_MODELED_INTEGRITY_STORE_PROFILE_V1}'
            )
            BEGIN
                SELECT RAISE(ABORT, 'qualified acceptance requires an enrolled modeled profile');
            END;

            CREATE TRIGGER IF NOT EXISTS integrity_acceptance_require_empty_history
            BEFORE INSERT ON integrity_acceptance_profile
            WHEN EXISTS (SELECT 1 FROM events)
            BEGIN
                SELECT RAISE(ABORT, 'qualified acceptance must be enrolled before any event');
            END;
        """

    def _migrate_blocked_v3_to_qualified_v4(self) -> None:
        schema_rows = self._connection.execute(
            """
            SELECT type, name, sql
            FROM sqlite_schema
            WHERE name NOT LIKE 'sqlite_%'
            ORDER BY type ASC, name ASC
            """
        ).fetchall()
        schema_contract = "\n".join(
            f"{object_type}\0{name}\0{sql}"
            for object_type, name, sql in schema_rows
        ).encode("utf-8")
        if (
            hashlib.sha256(schema_contract).hexdigest()
            != _SQLITE_LEGACY_INTEGRITY_V3_SCHEMA_CONTRACT_SHA256
        ):
            raise EventStoreCorruptionError(
                "legacy blocked-finality schema differs from its exact migration contract"
            )
        try:
            self._connection.executescript(
                f"""
                BEGIN IMMEDIATE;
                {self._qualified_acceptance_schema_sql()}
                {_SET_SQLITE_SCHEMA_VERSION};
                """
            )
            self._validate_schema()
            self._require_writer_transaction()
            self._connection.execute("COMMIT")
        except BaseException:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise

    def _migrate_vault_v1_to_integrity_v2(self) -> None:
        schema_rows = self._connection.execute(
            """
            SELECT type, name, sql
            FROM sqlite_schema
            WHERE name NOT LIKE 'sqlite_%'
            ORDER BY type ASC, name ASC
            """
        ).fetchall()
        schema_contract = "\n".join(
            f"{object_type}\0{name}\0{sql}"
            for object_type, name, sql in schema_rows
        ).encode("utf-8")
        if (
            hashlib.sha256(schema_contract).hexdigest()
            != _SQLITE_LEGACY_VAULT_SCHEMA_CONTRACT_SHA256
        ):
            raise EventStoreCorruptionError(
                "legacy vault schema differs from its exact migration contract"
            )
        try:
            self._connection.executescript(
                f"""
                BEGIN IMMEDIATE;
                {self._integrity_schema_sql()}
                {self._blocked_finality_schema_sql()}
                {self._qualified_acceptance_schema_sql()}
                {_SET_SQLITE_SCHEMA_VERSION};
                """
            )
            self._validate_schema()
            self._require_writer_transaction()
            self._connection.execute("COMMIT")
        except BaseException:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise

    def _migrate_integrity_v2_to_blocked_v3(self) -> None:
        schema_rows = self._connection.execute(
            """
            SELECT type, name, sql
            FROM sqlite_schema
            WHERE name NOT LIKE 'sqlite_%'
            ORDER BY type ASC, name ASC
            """
        ).fetchall()
        schema_contract = "\n".join(
            f"{object_type}\0{name}\0{sql}"
            for object_type, name, sql in schema_rows
        ).encode("utf-8")
        if (
            hashlib.sha256(schema_contract).hexdigest()
            != _SQLITE_LEGACY_INTEGRITY_V2_SCHEMA_CONTRACT_SHA256
        ):
            raise EventStoreCorruptionError(
                "legacy integrity schema differs from its exact migration contract"
            )
        try:
            self._connection.executescript(
                f"""
                BEGIN IMMEDIATE;
                {self._blocked_finality_schema_sql()}
                {self._qualified_acceptance_schema_sql()}
                {_SET_SQLITE_SCHEMA_VERSION};
                """
            )
            self._validate_schema()
            self._require_writer_transaction()
            self._connection.execute("COMMIT")
        except BaseException:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise

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

            {self._integrity_schema_sql()}

            {self._blocked_finality_schema_sql()}

            {self._qualified_acceptance_schema_sql()}

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

    def _schema_contract_locked(
        self,
    ) -> tuple[tuple[tuple[str, str, str], ...], str]:
        schema_rows = tuple(
            self._connection.execute(
                """
                SELECT type, name, sql
                FROM sqlite_schema
                WHERE name NOT LIKE 'sqlite_%'
                ORDER BY type ASC, name ASC
                """
            ).fetchall()
        )
        if any(
            type(object_type) is not str
            or type(name) is not str
            or type(sql) is not str
            for object_type, name, sql in schema_rows
        ):
            raise EventStoreCorruptionError(
                "event-store schema contains an invalid retained definition"
            )
        schema_contract = "\n".join(
            f"{object_type}\0{name}\0{sql}"
            for object_type, name, sql in schema_rows
        ).encode("utf-8")
        return (
            schema_rows,
            hashlib.sha256(schema_contract).hexdigest(),
        )

    def _validate_schema(self) -> None:
        application_id = self._connection.execute("PRAGMA application_id").fetchone()
        user_version = self._connection.execute("PRAGMA user_version").fetchone()
        if application_id != (_SQLITE_APPLICATION_ID,) or user_version != (_SQLITE_SCHEMA_VERSION,):
            raise EventStoreCorruptionError("event-store schema identity is invalid")
        required_objects = {
            ("index", "event_artifact_roles_artifact_identity"),
            ("index", "events_mission_head"),
            ("index", "integrity_blocked_latest_attempt"),
            ("index", "integrity_finalized_mission_head"),
            ("index", "integrity_transition_evidence_identity"),
            ("table", "event_artifact_roles"),
            ("table", "events"),
            ("table", "evidence_artifacts"),
            ("table", "integrity_acceptance_profile"),
            ("table", "integrity_anchor_statements"),
            ("table", "integrity_blocked_observations"),
            ("table", "integrity_checkpoint_candidates"),
            ("table", "integrity_evidence_artifacts"),
            ("table", "integrity_finalizations"),
            ("table", "integrity_pending_transitions"),
            ("table", "integrity_recovery_decisions"),
            ("table", "integrity_recovery_profile"),
            ("table", "integrity_transition_evidence"),
            ("table", "signed_checkpoints"),
            ("table", "store_profile"),
            ("trigger", "checkpoints_reject_delete"),
            ("trigger", "checkpoints_reject_update"),
            ("trigger", "event_artifact_roles_reject_delete"),
            ("trigger", "event_artifact_roles_reject_late_insert"),
            ("trigger", "event_artifact_roles_reject_update"),
            ("trigger", "events_reject_while_integrity_pending"),
            ("trigger", "events_reject_delete"),
            ("trigger", "events_reject_unexpected_evidence"),
            ("trigger", "events_reject_update"),
            ("trigger", "events_require_authority_evidence"),
            ("trigger", "events_require_integrity_pending"),
            ("trigger", "events_require_matching_artifact_kind"),
            ("trigger", "events_require_receipt_evidence"),
            ("trigger", "events_require_resolution_evidence"),
            ("trigger", "events_require_target_evidence"),
            ("trigger", "events_validate_insert"),
            ("trigger", "evidence_artifacts_reject_delete"),
            ("trigger", "evidence_artifacts_reject_update"),
            ("trigger", "integrity_acceptance_profile_reject_delete"),
            ("trigger", "integrity_acceptance_profile_reject_update"),
            ("trigger", "integrity_acceptance_require_empty_history"),
            ("trigger", "integrity_acceptance_require_modeled_profile"),
            ("trigger", "integrity_anchor_reject_delete"),
            ("trigger", "integrity_anchor_reject_update"),
            ("trigger", "integrity_blocked_reject_after_seal"),
            ("trigger", "integrity_blocked_reject_delete"),
            ("trigger", "integrity_blocked_reject_finalized"),
            ("trigger", "integrity_blocked_reject_update"),
            ("trigger", "integrity_checkpoint_reject_delete"),
            ("trigger", "integrity_checkpoint_reject_update"),
            ("trigger", "integrity_evidence_reject_delete"),
            ("trigger", "integrity_evidence_reject_update"),
            ("trigger", "integrity_finalization_reject_delete"),
            ("trigger", "integrity_finalization_reject_update"),
            ("trigger", "integrity_pending_reject_delete"),
            ("trigger", "integrity_pending_reject_open_transition"),
            ("trigger", "integrity_pending_reject_update"),
            ("trigger", "integrity_pending_require_next_global"),
            ("trigger", "integrity_pending_require_profile"),
            ("trigger", "integrity_recovery_decision_reject_delete"),
            ("trigger", "integrity_recovery_decision_reject_update"),
            ("trigger", "integrity_recovery_profile_reject_delete"),
            ("trigger", "integrity_recovery_profile_reject_update"),
            ("trigger", "integrity_recovery_reject_after_seal"),
            ("trigger", "integrity_recovery_require_latest_observation"),
            ("trigger", "integrity_transition_evidence_reject_delete"),
            ("trigger", "integrity_transition_evidence_reject_update"),
            ("trigger", "store_profile_reject_delete"),
            ("trigger", "store_profile_validate_update"),
        }
        schema_rows, schema_contract_digest = (
            self._schema_contract_locked()
        )
        retained_objects = {(row[0], row[1]) for row in schema_rows}
        if retained_objects != required_objects:
            raise EventStoreCorruptionError(
                "event-store schema objects differ from the vault contract"
            )
        if schema_contract_digest != _SQLITE_SCHEMA_CONTRACT_SHA256:
            raise EventStoreCorruptionError(
                "event-store schema definitions differ from the vault contract "
                f"({schema_contract_digest})"
            )
        table_rows = {row[1]: row for row in self._connection.execute("PRAGMA table_list").fetchall()}
        expected_table_shape = {
            "events": (0, 1),
            "signed_checkpoints": (0, 1),
            "evidence_artifacts": (0, 1),
            "event_artifact_roles": (1, 1),
            "store_profile": (0, 1),
            "integrity_evidence_artifacts": (1, 1),
            "integrity_pending_transitions": (1, 1),
            "integrity_anchor_statements": (1, 1),
            "integrity_checkpoint_candidates": (1, 1),
            "integrity_finalizations": (1, 1),
            "integrity_transition_evidence": (1, 1),
        }
        for table_name, (without_rowid, strict) in expected_table_shape.items():
            retained = table_rows.get(table_name)
            if (
                retained is None
                or retained[-2] != without_rowid
                or retained[-1] != strict
            ):
                raise EventStoreCorruptionError(
                    f"{table_name} differs from its STRICT/rowid contract"
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
            "store_profile": (
                (0, "singleton", "INTEGER", 0, None, 1, 0),
                (1, "profile", "TEXT", 1, None, 0, 0),
                (2, "service_instance_id", "TEXT", 0, None, 0, 0),
                (3, "environment_id", "TEXT", 0, None, 0, 0),
                (4, "validation_policy_id", "TEXT", 0, None, 0, 0),
                (5, "validation_policy_wire", "BLOB", 0, None, 0, 0),
                (6, "authority_binding_id", "TEXT", 0, None, 0, 0),
                (7, "authority_binding_wire", "BLOB", 0, None, 0, 0),
            ),
            "integrity_evidence_artifacts": (
                (0, "evidence_id", "TEXT", 1, None, 1, 0),
                (1, "byte_size", "INTEGER", 1, None, 0, 0),
                (2, "content", "BLOB", 1, None, 0, 0),
            ),
            "integrity_pending_transitions": (
                (0, "event_digest", "TEXT", 1, None, 1, 0),
                (1, "mission_id", "TEXT", 1, None, 0, 0),
                (2, "event_seq", "INTEGER", 1, None, 0, 0),
                (3, "instance_sequence", "INTEGER", 1, None, 0, 0),
                (4, "record_id", "TEXT", 1, None, 0, 0),
                (5, "record", "BLOB", 1, None, 0, 0),
            ),
            "integrity_anchor_statements": (
                (0, "event_digest", "TEXT", 1, None, 1, 0),
                (1, "record_id", "TEXT", 1, None, 0, 0),
                (2, "anchor_statement_id", "TEXT", 1, None, 0, 0),
                (3, "record", "BLOB", 1, None, 0, 0),
            ),
            "integrity_checkpoint_candidates": (
                (0, "event_digest", "TEXT", 1, None, 1, 0),
                (1, "record_id", "TEXT", 1, None, 0, 0),
                (2, "checkpoint_id", "TEXT", 1, None, 0, 0),
                (3, "checkpoint_attestation_id", "TEXT", 1, None, 0, 0),
                (4, "record", "BLOB", 1, None, 0, 0),
            ),
            "integrity_finalizations": (
                (0, "event_digest", "TEXT", 1, None, 1, 0),
                (1, "record_id", "TEXT", 1, None, 0, 0),
                (2, "record", "BLOB", 1, None, 0, 0),
            ),
            "integrity_transition_evidence": (
                (0, "event_digest", "TEXT", 1, None, 1, 0),
                (1, "phase", "TEXT", 1, None, 2, 0),
                (2, "slot", "INTEGER", 1, None, 3, 0),
                (3, "evidence_kind", "TEXT", 1, None, 0, 0),
                (4, "source_id", "TEXT", 1, None, 0, 0),
                (5, "evidence_id", "TEXT", 1, None, 0, 0),
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
        integrity_foreign_keys = {
            "integrity_pending_transitions": {
                (
                    "events",
                    "event_digest",
                    "digest",
                    "RESTRICT",
                    "RESTRICT",
                    "NONE",
                ),
            },
            "integrity_anchor_statements": {
                (
                    "integrity_pending_transitions",
                    "event_digest",
                    "event_digest",
                    "RESTRICT",
                    "RESTRICT",
                    "NONE",
                ),
            },
            "integrity_checkpoint_candidates": {
                (
                    "integrity_anchor_statements",
                    "event_digest",
                    "event_digest",
                    "RESTRICT",
                    "RESTRICT",
                    "NONE",
                ),
            },
            "integrity_finalizations": {
                (
                    "integrity_checkpoint_candidates",
                    "event_digest",
                    "event_digest",
                    "RESTRICT",
                    "RESTRICT",
                    "NONE",
                ),
            },
            "integrity_transition_evidence": {
                (
                    "integrity_pending_transitions",
                    "event_digest",
                    "event_digest",
                    "RESTRICT",
                    "RESTRICT",
                    "NONE",
                ),
                (
                    "integrity_evidence_artifacts",
                    "evidence_id",
                    "evidence_id",
                    "RESTRICT",
                    "RESTRICT",
                    "NONE",
                ),
            },
        }
        for table_name, expected_foreign_keys in integrity_foreign_keys.items():
            retained_foreign_keys = {
                tuple(row[2:])
                for row in self._connection.execute(
                    "SELECT * FROM pragma_foreign_key_list(?)",
                    (table_name,),
                ).fetchall()
            }
            if retained_foreign_keys != expected_foreign_keys:
                raise EventStoreCorruptionError(
                    f"{table_name} foreign keys differ from the integrity schema contract"
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
        integrity_mission_index = tuple(
            self._connection.execute(
                "PRAGMA index_info(integrity_finalized_mission_head)"
            ).fetchall()
        )
        if integrity_mission_index != (
            (0, 1, "mission_id"),
            (1, 2, "event_seq"),
            (2, 3, "instance_sequence"),
        ):
            raise EventStoreCorruptionError(
                "integrity mission-head index differs from the schema contract"
            )
        integrity_evidence_index = tuple(
            self._connection.execute(
                "PRAGMA index_info(integrity_transition_evidence_identity)"
            ).fetchall()
        )
        if integrity_evidence_index != (
            (0, 5, "evidence_id"),
            (1, 0, "event_digest"),
            (2, 1, "phase"),
            (3, 2, "slot"),
        ):
            raise EventStoreCorruptionError(
                "integrity-evidence index differs from the schema contract"
            )
        profile_rows = self._connection.execute(
            """
            SELECT
                singleton,
                profile,
                service_instance_id,
                environment_id,
                validation_policy_id,
                validation_policy_wire,
                authority_binding_id,
                authority_binding_wire
            FROM store_profile
            """
        ).fetchall()
        if len(profile_rows) != 1 or profile_rows[0][0] != 1:
            raise EventStoreCorruptionError(
                "event store does not retain one exact profile row"
            )
        foreign_key_violation = self._connection.execute(
            "PRAGMA foreign_key_check"
        ).fetchone()
        if foreign_key_violation is not None:
            if (
                len(foreign_key_violation) >= 3
                and foreign_key_violation[2] == "evidence_artifacts"
            ):
                raise EventStoreCorruptionError(
                    "retained event artifact is absent from the canonical vault"
                )
            raise EventStoreCorruptionError(
                "event-store schema has foreign-key violations"
            )

    def _authenticated_connection_settings_locked(
        self,
    ) -> tuple[str, int, int, int, int, int, int]:
        """Return the exact admitted connection-local SQLite security settings."""

        journal = self._connection.execute(
            "PRAGMA journal_mode"
        ).fetchone()
        synchronous = self._connection.execute(
            "PRAGMA synchronous"
        ).fetchone()
        foreign_keys = self._connection.execute(
            "PRAGMA foreign_keys"
        ).fetchone()
        trusted_schema = self._connection.execute(
            "PRAGMA trusted_schema"
        ).fetchone()
        ignore_check_constraints = self._connection.execute(
            "PRAGMA ignore_check_constraints"
        ).fetchone()
        read_uncommitted = self._connection.execute(
            "PRAGMA read_uncommitted"
        ).fetchone()
        writable_schema = self._connection.execute(
            "PRAGMA writable_schema"
        ).fetchone()
        if (
            journal is None
            or len(journal) != 1
            or type(journal[0]) is not str
            or synchronous is None
            or len(synchronous) != 1
            or type(synchronous[0]) is not int
            or foreign_keys is None
            or len(foreign_keys) != 1
            or type(foreign_keys[0]) is not int
            or trusted_schema is None
            or len(trusted_schema) != 1
            or type(trusted_schema[0]) is not int
            or ignore_check_constraints is None
            or len(ignore_check_constraints) != 1
            or type(ignore_check_constraints[0]) is not int
            or read_uncommitted is None
            or len(read_uncommitted) != 1
            or type(read_uncommitted[0]) is not int
            or writable_schema is None
            or len(writable_schema) != 1
            or type(writable_schema[0]) is not int
        ):
            self._integrity_validation_cache = None
            raise EventStoreCorruptionError(
                "SQLite returned incomplete connection security settings"
            )
        settings = (
            journal[0].lower(),
            synchronous[0],
            foreign_keys[0],
            trusted_schema[0],
            ignore_check_constraints[0],
            read_uncommitted[0],
            writable_schema[0],
        )
        if settings != (
            self._journal_policy.journal_mode,
            self._journal_policy.synchronous_value,
            1,
            0,
            0,
            0,
            0,
        ):
            self._integrity_validation_cache = None
            raise EventStoreCorruptionError(
                "SQLite security settings differ from the admitted journal policy"
            )
        return settings

    def _integrity_validation_cache_key_locked(
        self,
    ) -> _IntegrityValidationCacheKey:
        application_id = self._connection.execute(
            "PRAGMA application_id"
        ).fetchone()
        user_version = self._connection.execute(
            "PRAGMA user_version"
        ).fetchone()
        if (
            application_id != (_SQLITE_APPLICATION_ID,)
            or user_version != (_SQLITE_SCHEMA_VERSION,)
        ):
            self._integrity_validation_cache = None
            raise EventStoreCorruptionError(
                "event-store schema identity is invalid"
            )
        (
            journal_mode,
            synchronous_value,
            foreign_keys_value,
            trusted_schema_value,
            ignore_check_constraints_value,
            read_uncommitted_value,
            writable_schema_value,
        ) = self._authenticated_connection_settings_locked()
        data_version = self._connection.execute(
            "PRAGMA data_version"
        ).fetchone()
        schema_version = self._connection.execute(
            "PRAGMA schema_version"
        ).fetchone()
        total_changes = self._connection.total_changes
        if (
            data_version is None
            or len(data_version) != 1
            or type(data_version[0]) is not int
            or data_version[0] < 0
            or schema_version is None
            or len(schema_version) != 1
            or type(schema_version[0]) is not int
            or schema_version[0] < 0
            or type(total_changes) is not int
            or total_changes < 0
        ):
            raise EventStoreCorruptionError(
                "SQLite returned invalid authenticated-state change signals"
            )
        return _IntegrityValidationCacheKey(
            total_changes=total_changes,
            data_version=data_version[0],
            schema_version=schema_version[0],
            journal_mode=journal_mode,
            synchronous=synchronous_value,
            foreign_keys=foreign_keys_value,
            trusted_schema=trusted_schema_value,
            ignore_check_constraints=ignore_check_constraints_value,
            read_uncommitted=read_uncommitted_value,
            writable_schema=writable_schema_value,
        )

    def _refresh_validated_schema_version_locked(self) -> None:
        """Authenticate the exact schema and bind that result to one version."""

        before = self._integrity_validation_cache_key_locked()
        self._validate_schema()
        after = self._integrity_validation_cache_key_locked()
        if before.schema_version != after.schema_version:
            self._integrity_validation_cache = None
            self._validated_schema_version = None
            raise EventStoreCorruptionError(
                "event-store schema changed while it was being authenticated"
            )
        self._validated_schema_version = after.schema_version

    def _store_profile_locked(
        self,
    ) -> tuple[
        str,
        str | None,
        str | None,
        str | None,
        bytes | None,
        str | None,
        bytes | None,
        object | None,
    ]:
        try:
            row = self._connection.execute(
                """
                SELECT
                    profile,
                    service_instance_id,
                    environment_id,
                    validation_policy_id,
                    validation_policy_wire,
                    authority_binding_id,
                    authority_binding_wire
                FROM store_profile
                WHERE singleton = 1
                """
            ).fetchone()
        except sqlite3.DatabaseError as exc:
            raise _sqlite_store_failure(
                "could not read the event-store profile",
                exc,
            ) from exc
        if row is None or len(row) != 7:
            raise EventStoreCorruptionError(
                "event store omitted its exact profile"
            )
        (
            profile,
            service_instance_id,
            environment_id,
            policy_id,
            policy_wire,
            authority_binding_id,
            authority_binding_wire,
        ) = row
        if profile == _LEGACY_STORE_PROFILE_V1:
            if any(
                value is not None
                for value in (
                    service_instance_id,
                    environment_id,
                    policy_id,
                    policy_wire,
                    authority_binding_id,
                    authority_binding_wire,
                )
            ):
                raise EventStoreCorruptionError(
                    "legacy store profile retained modeled integrity fields"
                )
            return (
                profile,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
        if (
            profile != _MODELED_INTEGRITY_STORE_PROFILE_V1
            or type(service_instance_id) is not str
            or _INTEGRITY_IDENTITY_RE.fullmatch(service_instance_id) is None
            or type(environment_id) is not str
            or _INTEGRITY_IDENTITY_RE.fullmatch(environment_id) is None
            or type(policy_id) is not str
            or _DIGEST_RE.fullmatch(policy_id) is None
            or type(policy_wire) is not bytes
            or type(authority_binding_id) is not str
            or _DIGEST_RE.fullmatch(authority_binding_id) is None
            or type(authority_binding_wire) is not bytes
        ):
            raise EventStoreCorruptionError(
                "modeled integrity store profile is malformed"
            )
        try:
            from ..integrity_v1 import IntegrityValidationPolicyV1
            from .integrity_transition import (
                ModeledIntegrityAuthorityBindingV1,
            )

            body = strict_loads(policy_wire)
            policy = IntegrityValidationPolicyV1.from_body(body)
            authority_binding = (
                ModeledIntegrityAuthorityBindingV1.from_canonical_bytes(
                    authority_binding_wire
                )
            )
        except (ProtocolError, TypeError, ValueError) as exc:
            raise EventStoreCorruptionError(
                f"modeled integrity profile cannot be reconstructed: {exc}"
            ) from exc
        if (
            canonical_dumps(policy.to_body()) != policy_wire
            or content_id("integrity_validation_policy", policy.to_body())
            != policy_id
            or authority_binding.to_canonical_bytes()
            != authority_binding_wire
            or authority_binding.binding_id != authority_binding_id
        ):
            raise EventStoreCorruptionError(
                "modeled integrity profile identity is inconsistent"
            )
        return (
            profile,
            service_instance_id,
            environment_id,
            policy_id,
            policy_wire,
            authority_binding_id,
            authority_binding_wire,
            authority_binding,
        )

    def _unresolved_integrity_digest_locked(self) -> str | None:
        rows = self._connection.execute(
            """
            SELECT pending.event_digest
            FROM integrity_pending_transitions AS pending
            LEFT JOIN integrity_finalizations AS finalized
              ON finalized.event_digest = pending.event_digest
            WHERE finalized.event_digest IS NULL
            ORDER BY pending.instance_sequence ASC
            LIMIT 2
            """
        ).fetchall()
        if len(rows) > 1:
            raise EventStoreCorruptionError(
                "multiple instance-global integrity transitions are unresolved"
            )
        if not rows:
            return None
        event_digest = rows[0][0]
        if type(event_digest) is not str or _DIGEST_RE.fullmatch(event_digest) is None:
            raise EventStoreCorruptionError(
                "unresolved integrity transition has an invalid event identity"
            )
        return event_digest

    def _validate_integrity_state_locked(self) -> None:
        observed = self._integrity_validation_cache_key_locked()
        _schema_rows, schema_contract_digest = (
            self._schema_contract_locked()
        )
        if schema_contract_digest != _SQLITE_SCHEMA_CONTRACT_SHA256:
            self._integrity_validation_cache = None
            raise EventStoreCorruptionError(
                "event-store schema definitions differ from the vault contract "
                f"({schema_contract_digest})"
            )
        if self._validated_schema_version != observed.schema_version:
            self._integrity_validation_cache = None
            self._refresh_validated_schema_version_locked()
            observed = self._integrity_validation_cache_key_locked()
        if self._integrity_validation_cache == observed:
            return

        self._integrity_validation_cache = None
        self._validate_integrity_state_uncached_locked()
        validated = self._integrity_validation_cache_key_locked()
        if (
            validated == observed
            and validated.schema_version
            == self._validated_schema_version
        ):
            self._integrity_validation_cache = validated

    def _publish_owned_integrity_validation_cache_locked(self) -> None:
        """Advance a validated cache across one exact store-owned append."""

        self._require_writer_transaction()
        prior = self._integrity_validation_cache
        current = self._integrity_validation_cache_key_locked()
        _schema_rows, schema_contract_digest = (
            self._schema_contract_locked()
        )
        if schema_contract_digest != _SQLITE_SCHEMA_CONTRACT_SHA256:
            self._integrity_validation_cache = None
            raise EventStoreCorruptionError(
                "event-store schema definitions differ from the vault contract "
                f"({schema_contract_digest})"
            )
        if (
            prior is None
            or prior.data_version != current.data_version
            or prior.schema_version != current.schema_version
            or prior.schema_version != self._validated_schema_version
            or current.total_changes < prior.total_changes
        ):
            self._integrity_validation_cache = None
            raise EventStoreError(
                "owned write did not extend one fully authenticated SQLite state"
            )
        self._integrity_validation_cache = current

    def _validate_integrity_state_uncached_locked(self) -> None:
        (
            profile,
            _service_instance_id,
            _environment_id,
            _policy_id,
            _policy_wire,
            _authority_binding_id,
            _authority_binding_wire,
            authority_binding,
        ) = self._store_profile_locked()
        integrity_tables = (
            "integrity_pending_transitions",
            "integrity_anchor_statements",
            "integrity_checkpoint_candidates",
            "integrity_finalizations",
            "integrity_evidence_artifacts",
            "integrity_transition_evidence",
        )
        count_row = self._connection.execute(
            """
            SELECT
                (SELECT count(*) FROM integrity_pending_transitions),
                (SELECT count(*) FROM integrity_anchor_statements),
                (SELECT count(*) FROM integrity_checkpoint_candidates),
                (SELECT count(*) FROM integrity_finalizations),
                (SELECT count(*) FROM integrity_evidence_artifacts),
                (SELECT count(*) FROM integrity_transition_evidence)
            """
        ).fetchone()
        if (
            count_row is None
            or len(count_row) != len(integrity_tables)
            or any(type(value) is not int for value in count_row)
        ):
            raise EventStoreCorruptionError(
                "SQLite omitted an integrity-state table count"
            )
        counts = dict(zip(integrity_tables, count_row, strict=True))
        foreign_key_violation = self._connection.execute(
            "PRAGMA foreign_key_check"
        ).fetchone()
        if foreign_key_violation is not None:
            raise EventStoreCorruptionError(
                "modeled integrity state has a foreign-key violation"
            )
        if profile == _LEGACY_STORE_PROFILE_V1:
            if any(counts.values()):
                raise EventStoreCorruptionError(
                    "legacy store profile contains typed integrity state"
                )
            return
        event_count = int(
            self._connection.execute("SELECT count(*) FROM events").fetchone()[0]
        )
        pending_count = counts["integrity_pending_transitions"]
        if event_count != pending_count:
            raise EventStoreCorruptionError(
                "modeled integrity profile has an event without one pending dossier"
            )
        missing = self._connection.execute(
            """
            SELECT 1
            FROM events AS event
            LEFT JOIN integrity_pending_transitions AS pending
              ON pending.event_digest = event.digest
             AND pending.mission_id = event.mission_id
             AND pending.event_seq = event.seq
            WHERE pending.event_digest IS NULL
            LIMIT 1
            """
        ).fetchone()
        if missing is not None:
            raise EventStoreCorruptionError(
                "modeled integrity event metadata differs from its pending dossier"
            )
        sequence_gap = self._connection.execute(
            """
            SELECT 1
            FROM integrity_pending_transitions AS pending
            WHERE pending.instance_sequence != (
                SELECT count(*)
                FROM integrity_pending_transitions AS earlier
                WHERE earlier.instance_sequence < pending.instance_sequence
            )
            LIMIT 1
            """
        ).fetchone()
        if sequence_gap is not None:
            raise EventStoreCorruptionError(
                "modeled integrity instance sequence has a gap"
            )
        finalized_count = counts["integrity_finalizations"]
        if (
            counts["integrity_anchor_statements"] > pending_count
            or counts["integrity_anchor_statements"] < finalized_count
            or counts["integrity_checkpoint_candidates"] < finalized_count
            or counts["integrity_anchor_statements"]
            < counts["integrity_checkpoint_candidates"]
            or pending_count - finalized_count not in {0, 1}
        ):
            raise EventStoreCorruptionError(
                "modeled integrity phase cardinalities are inconsistent"
            )
        phase_parent_gap = self._connection.execute(
            """
            SELECT 1
            WHERE EXISTS (
                SELECT 1
                FROM integrity_anchor_statements AS anchor
                LEFT JOIN integrity_pending_transitions AS pending
                  ON pending.event_digest = anchor.event_digest
                WHERE pending.event_digest IS NULL
            )
            OR EXISTS (
                SELECT 1
                FROM integrity_checkpoint_candidates AS candidate
                LEFT JOIN integrity_anchor_statements AS anchor
                  ON anchor.event_digest = candidate.event_digest
                WHERE anchor.event_digest IS NULL
            )
            OR EXISTS (
                SELECT 1
                FROM integrity_finalizations AS finalized
                LEFT JOIN integrity_checkpoint_candidates AS candidate
                  ON candidate.event_digest = finalized.event_digest
                WHERE candidate.event_digest IS NULL
            )
            LIMIT 1
            """
        ).fetchone()
        if phase_parent_gap is not None:
            raise EventStoreCorruptionError(
                "modeled integrity phase record omitted its exact parent"
            )
        finalized_gap = self._connection.execute(
            """
            SELECT 1
            FROM integrity_pending_transitions AS pending
            LEFT JOIN integrity_finalizations AS finalized
              ON finalized.event_digest = pending.event_digest
            WHERE pending.instance_sequence < (
                SELECT count(*) FROM integrity_finalizations
            )
              AND finalized.event_digest IS NULL
            LIMIT 1
            """
        ).fetchone()
        if finalized_gap is not None:
            raise EventStoreCorruptionError(
                "modeled integrity finalizations are not a global prefix"
            )
        orphan_evidence = self._connection.execute(
            """
            SELECT 1
            FROM integrity_evidence_artifacts AS artifact
            WHERE NOT EXISTS (
                SELECT 1
                FROM integrity_transition_evidence AS mapping
                WHERE mapping.evidence_id = artifact.evidence_id
            )
            LIMIT 1
            """
        ).fetchone()
        if orphan_evidence is not None:
            raise EventStoreCorruptionError(
                "modeled integrity state retains orphan provider evidence"
            )
        phase_mapping_gap = self._connection.execute(
            """
            SELECT 1
            FROM integrity_transition_evidence AS mapping
            WHERE (
                mapping.phase = 'pending'
                AND NOT EXISTS (
                    SELECT 1
                    FROM integrity_pending_transitions AS pending
                    WHERE pending.event_digest = mapping.event_digest
                )
            )
            OR (
                mapping.phase = 'anchor_statement'
                AND NOT EXISTS (
                    SELECT 1
                    FROM integrity_anchor_statements AS anchor
                    WHERE anchor.event_digest = mapping.event_digest
                )
            )
            OR (
                mapping.phase = 'checkpoint_candidate'
                AND NOT EXISTS (
                    SELECT 1
                    FROM integrity_checkpoint_candidates AS candidate
                    WHERE candidate.event_digest = mapping.event_digest
                )
            )
            OR (
                mapping.phase = 'finalization'
                AND NOT EXISTS (
                    SELECT 1
                    FROM integrity_finalizations AS finalized
                    WHERE finalized.event_digest = mapping.event_digest
                )
            )
            LIMIT 1
            """
        ).fetchone()
        if phase_mapping_gap is not None:
            raise EventStoreCorruptionError(
                "integrity provider evidence precedes its immutable phase record"
            )
        self._unresolved_integrity_digest_locked()
        from .integrity_transition import (
            validate_anchor_statement,
            validate_checkpoint_candidate,
            validate_finalized_integrity_transition,
            validate_pending_transition,
        )

        try:
            from ..integrity_v1 import IntegrityValidationPolicyV1

            validation_policy = IntegrityValidationPolicyV1.from_body(
                strict_loads(_policy_wire)
            )
        except (ProtocolError, TypeError, ValueError) as exc:
            raise EventStoreCorruptionError(
                f"retained integrity policy cannot be reconstructed: {exc}"
            ) from exc
        previous_global = None
        previous_by_mission: dict[str, object] = {}
        for (event_digest,) in self._connection.execute(
            """
            SELECT event_digest
            FROM integrity_pending_transitions
            ORDER BY instance_sequence ASC
            """
        ).fetchall():
            lineage = self._load_integrity_lineage_locked(event_digest)
            if lineage is None:
                raise EventStoreCorruptionError(
                    "integrity transition index names no retained lineage"
                )
            event = self._event_for_integrity_digest_locked(event_digest)
            previous_mission = previous_by_mission.get(event.mission_id)
            try:
                if not self._integrity_lineage_matches_authority_binding(
                    pending=lineage.pending,
                    checkpoint_candidate=lineage.checkpoint_candidate,
                    authority_binding=authority_binding,
                ):
                    raise EventStoreCorruptionError(
                        "retained integrity lineage differs from its enrolled "
                        "authority binding"
                    )
                validate_pending_transition(
                    event,
                    lineage.pending,
                    previous_global=previous_global,
                    previous_mission=previous_mission,
                    service_instance_id=_service_instance_id,
                    environment_id=_environment_id,
                    validation_policy=validation_policy,
                )
                if lineage.anchor_statement is not None:
                    validate_anchor_statement(
                        lineage.pending,
                        lineage.anchor_statement,
                        previous_mission=previous_mission,
                    )
                if lineage.checkpoint_candidate is not None:
                    if lineage.anchor_statement is None:
                        raise EventStoreCorruptionError(
                            "checkpoint candidate omitted its anchor statement"
                        )
                    validate_checkpoint_candidate(
                        event,
                        lineage.pending,
                        lineage.anchor_statement,
                        lineage.checkpoint_candidate,
                        previous_global=previous_global,
                        previous_mission=previous_mission,
                    )
                if lineage.finalization is not None:
                    validate_finalized_integrity_transition(
                        lineage,
                        event=event,
                        previous_global=previous_global,
                        previous_mission=previous_mission,
                    )
            except EventStoreCorruptionError:
                raise
            except (ProtocolError, TypeError, ValueError) as exc:
                reason_code = getattr(
                    exc,
                    "reason_code",
                    "invalid_retained_integrity_lineage",
                )
                raise EventStoreCorruptionError(
                    "retained integrity lineage failed authenticated replay "
                    f"({reason_code}): {exc}"
                ) from exc
            if lineage.finalization is not None:
                previous_global = lineage
                previous_by_mission[event.mission_id] = lineage

    def enroll_modeled_integrity(
        self,
        *,
        service_instance_id: str,
        environment_id: str,
        validation_policy: object,
        authority_binding: object,
    ) -> None:
        """Irreversibly enroll one empty store in the modeled-integrity profile."""

        try:
            from ..integrity_v1 import IntegrityValidationPolicyV1
            from .integrity_transition import (
                ModeledIntegrityAuthorityBindingV1,
            )

            if type(validation_policy) is not IntegrityValidationPolicyV1:
                raise EventStoreError(
                    "modeled integrity enrollment requires an exact validation policy"
                )
            if (
                type(authority_binding)
                is not ModeledIntegrityAuthorityBindingV1
            ):
                raise EventStoreError(
                    "modeled integrity enrollment requires an exact authority binding"
                )
            policy = IntegrityValidationPolicyV1.from_body(
                validation_policy.to_body()
            )
            policy_wire = canonical_dumps(policy.to_body())
            policy_id = content_id(
                "integrity_validation_policy",
                policy.to_body(),
            )
            authority_binding_wire = (
                authority_binding.to_canonical_bytes()
            )
            retained_authority_binding = (
                ModeledIntegrityAuthorityBindingV1.from_canonical_bytes(
                    authority_binding_wire
                )
            )
            authority_binding_id = retained_authority_binding.binding_id
        except EventStoreError:
            raise
        except (AttributeError, ProtocolError, TypeError, ValueError) as exc:
            raise EventStoreError(
                f"invalid modeled integrity enrollment profile: {exc}"
            ) from exc
        if (
            type(service_instance_id) is not str
            or _INTEGRITY_IDENTITY_RE.fullmatch(service_instance_id) is None
            or type(environment_id) is not str
            or _INTEGRITY_IDENTITY_RE.fullmatch(environment_id) is None
        ):
            raise EventStoreError(
                "modeled integrity scope requires canonical ASCII identities"
            )
        requested = (
            _MODELED_INTEGRITY_STORE_PROFILE_V1,
            service_instance_id,
            environment_id,
            policy_id,
            policy_wire,
            authority_binding_id,
            authority_binding_wire,
            retained_authority_binding,
        )
        requested_profile_bytes = (
            self._modeled_integrity_profile_storage_bytes(
                service_instance_id=service_instance_id,
                environment_id=environment_id,
                validation_policy_id=policy_id,
                validation_policy_wire=policy_wire,
                authority_binding_id=authority_binding_id,
                authority_binding_wire=authority_binding_wire,
            )
        )
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            self._require_writer_transaction()
            self._validate_integrity_state_locked()
            retained = self._store_profile_locked()
            if retained[:7] == requested[:7]:
                self._require_integrity_enrollment_capacity_locked(
                    additional_profile_bytes=0
                )
                self._connection.execute("COMMIT")
                return
            if retained[0] != _LEGACY_STORE_PROFILE_V1:
                raise EventStoreError(
                    "modeled integrity enrollment conflicts with the retained profile"
                )
            if any(
                self._table_has_rows(table_name)
                for table_name in (
                    "events",
                    "signed_checkpoints",
                    "evidence_artifacts",
                    "event_artifact_roles",
                )
            ):
                raise EventStoreError(
                    "nonempty legacy history cannot be promoted to pre-transition integrity"
                )
            self._require_integrity_enrollment_capacity_locked(
                additional_profile_bytes=requested_profile_bytes
            )
            self._require_writer_transaction()
            self._connection.execute(
                """
                UPDATE store_profile
                SET
                    profile = ?,
                    service_instance_id = ?,
                    environment_id = ?,
                    validation_policy_id = ?,
                    validation_policy_wire = ?,
                    authority_binding_id = ?,
                    authority_binding_wire = ?
                WHERE singleton = 1
                """,
                (
                    _MODELED_INTEGRITY_STORE_PROFILE_V1,
                    service_instance_id,
                    environment_id,
                    policy_id,
                    sqlite3.Binary(policy_wire),
                    authority_binding_id,
                    sqlite3.Binary(authority_binding_wire),
                ),
            )
            if self._store_profile_locked()[:7] != requested[:7]:
                raise EventStoreCorruptionError(
                    "modeled integrity enrollment did not retain its exact profile"
                )
            self._require_integrity_enrollment_capacity_locked(
                additional_profile_bytes=0
            )
            self._publish_owned_integrity_validation_cache_locked()
            self._require_writer_transaction()
            self._connection.execute("COMMIT")
        except EventStoreError:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise
        except sqlite3.IntegrityError as exc:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise EventStoreError(
                f"SQLite rejected modeled integrity enrollment: {exc}"
            ) from exc
        except sqlite3.DatabaseError as exc:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise _sqlite_store_failure(
                "modeled integrity enrollment failed",
                exc,
            ) from exc

    def diagnostics(self) -> StoreDiagnostics:
        """Return fixed diagnostics without exposing a writable SQL connection."""

        try:
            (
                journal_value,
                synchronous_value,
                foreign_keys_value,
                trusted_schema_value,
                ignore_check_constraints_value,
                read_uncommitted_value,
                writable_schema_value,
            ) = self._authenticated_connection_settings_locked()
            mode = stat.S_IMODE(os.lstat(self.path).st_mode)
        except sqlite3.DatabaseError as exc:
            raise _sqlite_store_failure(
                "could not read store diagnostics",
                exc,
            ) from exc
        except OSError as exc:
            raise EventStoreCorruptionError(f"could not read store diagnostics: {exc}") from exc
        return StoreDiagnostics(
            sqlite_version=sqlite3.sqlite_version,
            wal_reset_bug_fixed=(self._journal_policy.wal_reset_bug_fixed),
            journal_mode=journal_value,
            synchronous=synchronous_value,
            foreign_keys=bool(foreign_keys_value),
            trusted_schema=bool(trusted_schema_value),
            ignore_check_constraints=bool(
                ignore_check_constraints_value
            ),
            read_uncommitted=bool(read_uncommitted_value),
            writable_schema=bool(writable_schema_value),
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
        self._authenticated_connection_settings_locked()

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

        if type(mission_id) is not str or _DIGEST_RE.fullmatch(mission_id) is None:
            raise EventStoreError(
                "mission_id must be a full lowercase sha256 digest"
            )
        self._validate_integrity_state_locked()
        if self._unresolved_integrity_digest_locked() is not None:
            raise PendingIntegrityTransitionError(
                "generic mission replay is unavailable while an integrity "
                "transition is pending"
            )
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

    @staticmethod
    def _snapshot_integrity_record(record: object, expected_type: type) -> object:
        if type(record) is not expected_type:
            raise EventStoreError(
                f"integrity phase requires an exact {expected_type.__name__}"
            )
        try:
            wire = record.to_canonical_bytes()
            if (
                type(wire) is not bytes
                or not wire
                or len(wire) > _MAX_INTEGRITY_RECORD_BYTES_V1
            ):
                raise EventStoreError(
                    "integrity recovery record exceeds its canonical byte ceiling"
                )
            return expected_type.from_canonical_bytes(wire)
        except EventStoreError:
            raise
        except (AttributeError, ProtocolError, TypeError, ValueError) as exc:
            raise EventStoreError(
                f"invalid {expected_type.__name__}: {exc}"
            ) from exc

    @staticmethod
    def _integrity_lineage_matches_authority_binding(
        *,
        pending: object,
        checkpoint_candidate: object | None,
        authority_binding: object,
    ) -> bool:
        try:
            decision_trust_store = pending.decision_trust_store
            decision_key = decision_trust_store.keys.get(
                authority_binding.decision_key_id
            )
            if (
                decision_trust_store.snapshot_id
                != authority_binding.trust_snapshot_id
                or decision_trust_store.to_snapshot_body()
                != authority_binding.trust_store.to_snapshot_body()
                or pending.signed_decision.key_id
                != authority_binding.decision_key_id
                or decision_key is None
                or decision_key.principal_id
                != authority_binding.decision_principal_id
            ):
                return False
            if checkpoint_candidate is None:
                return True
            checkpoint_trust_store = (
                checkpoint_candidate.checkpoint_trust_store
            )
            checkpoint_key = checkpoint_trust_store.keys.get(
                authority_binding.checkpoint_key_id
            )
            return (
                checkpoint_trust_store.snapshot_id
                == authority_binding.trust_snapshot_id
                and checkpoint_trust_store.to_snapshot_body()
                == authority_binding.trust_store.to_snapshot_body()
                and checkpoint_candidate.signed_checkpoint.key_id
                == authority_binding.checkpoint_key_id
                and checkpoint_key is not None
                and checkpoint_key.principal_id
                == authority_binding.checkpoint_principal_id
            )
        except (AttributeError, TypeError, ValueError):
            return False

    @staticmethod
    def _modeled_integrity_profile_storage_bytes(
        *,
        service_instance_id: str,
        environment_id: str,
        validation_policy_id: str,
        validation_policy_wire: bytes,
        authority_binding_id: str,
        authority_binding_wire: bytes,
    ) -> int:
        text_values = (
            _MODELED_INTEGRITY_STORE_PROFILE_V1,
            service_instance_id,
            environment_id,
            validation_policy_id,
            authority_binding_id,
        )
        return (
            sum(len(value.encode("ascii")) for value in text_values)
            + len(validation_policy_wire)
            + len(authority_binding_wire)
        )

    def _logical_evidence_storage_used_locked(self) -> int:
        integrity_row = self._connection.execute(
            """
            SELECT
                (
                    SELECT COALESCE(sum(byte_size), 0)
                    FROM integrity_evidence_artifacts
                )
                + (
                    SELECT COALESCE(sum(length(record)), 0)
                    FROM integrity_pending_transitions
                )
                + (
                    SELECT COALESCE(sum(length(record)), 0)
                    FROM integrity_anchor_statements
                )
                + (
                    SELECT COALESCE(sum(length(record)), 0)
                    FROM integrity_checkpoint_candidates
                )
                + (
                    SELECT COALESCE(sum(length(record)), 0)
                    FROM integrity_finalizations
                )
                + (
                    SELECT COALESCE(sum(length(record)), 0)
                    FROM integrity_blocked_observations
                )
                + (
                    SELECT COALESCE(sum(length(record)), 0)
                    FROM integrity_recovery_decisions
                )
                + (
                    SELECT COALESCE(
                        sum(
                            length(recovery_profile_id)
                            + length(recovery_profile_wire)
                        ),
                        0
                    )
                    FROM integrity_recovery_profile
                )
                + (
                    SELECT COALESCE(
                        sum(
                            length(acceptance_mode)
                            + length(qualified_time_profile_id)
                            + length(qualified_time_profile_wire)
                            + length(qualified_head_profile_id)
                            + length(qualified_head_profile_wire)
                        ),
                        0
                    )
                    FROM integrity_acceptance_profile
                )
                + (
                    SELECT COALESCE(
                        sum(
                            CASE
                                WHEN profile = ?
                                THEN
                                    length(profile)
                                    + length(service_instance_id)
                                    + length(environment_id)
                                    + length(validation_policy_id)
                                    + length(validation_policy_wire)
                                    + length(authority_binding_id)
                                    + length(authority_binding_wire)
                                ELSE 0
                            END
                        ),
                        0
                    )
                    FROM store_profile
                )
            """,
            (_MODELED_INTEGRITY_STORE_PROFILE_V1,),
        ).fetchone()
        if integrity_row is None or type(integrity_row[0]) is not int:
            raise EventStoreCorruptionError(
                "SQLite omitted the integrity evidence storage total"
            )
        return self._vault_used_bytes_locked() + integrity_row[0]

    def _require_integrity_enrollment_capacity_locked(
        self,
        *,
        additional_profile_bytes: int,
    ) -> None:
        if (
            type(additional_profile_bytes) is not int
            or additional_profile_bytes < 0
        ):
            raise EventStoreError(
                "integrity enrollment capacity delta is invalid"
            )
        if (
            self._logical_evidence_storage_used_locked()
            + additional_profile_bytes
            + _INTEGRITY_FINALITY_CAPACITY_RESERVE_BYTES_V1
            > self._max_vault_bytes
        ):
            raise EvidenceVaultCapacityError(
                "modeled integrity enrollment lacks exact profile and "
                "worst-case finality capacity"
            )

    def _reserve_integrity_finality_capacity_locked(self) -> None:
        if (
            self._logical_evidence_storage_used_locked()
            + _INTEGRITY_FINALITY_CAPACITY_RESERVE_BYTES_V1
            > self._max_vault_bytes
        ):
            raise EvidenceVaultCapacityError(
                "integrity transition lacks worst-case finality evidence capacity"
            )

    def _retain_integrity_evidence_locked(
        self,
        *,
        event_digest: str,
        phase: str,
        provider_evidence: tuple[object, ...],
    ) -> None:
        if phase not in _INTEGRITY_PHASES_V1:
            raise EventStoreError("integrity evidence has an unsupported phase")
        if type(provider_evidence) is not tuple or len(provider_evidence) > 256:
            raise EventStoreError(
                "integrity provider evidence must be a bounded tuple"
            )
        existing_rows = self._connection.execute(
            """
            SELECT DISTINCT evidence_id
            FROM integrity_transition_evidence
            WHERE event_digest = ?
            """,
            (event_digest,),
        ).fetchall()
        existing_ids = {row[0] for row in existing_rows}
        requested: list[tuple[str, str, str, bytes]] = []
        for blob in provider_evidence:
            try:
                evidence_kind = blob.evidence_kind
                source_id = blob.source_id
                evidence_id = blob.evidence_id
                content = blob.content
            except AttributeError as exc:
                raise EventStoreError(
                    "integrity provider evidence is malformed"
                ) from exc
            if (
                type(evidence_kind) is not str
                or evidence_kind
                not in {
                    "trusted_time",
                    "revocation_metadata",
                    "head_anchor_receipt",
                    "external_floor",
                }
                or type(source_id) is not str
                or not source_id
                or len(source_id) > 256
                or type(evidence_id) is not str
                or _DIGEST_RE.fullmatch(evidence_id) is None
                or type(content) is not bytes
                or not content
                or len(content) > _MAX_INTEGRITY_EVIDENCE_BYTES_V1
                or evidence_id
                != "sha256:" + hashlib.sha256(content).hexdigest()
            ):
                raise EventStoreError(
                    "integrity provider evidence violates its typed BLOB contract"
                )
            requested.append(
                (evidence_kind, source_id, evidence_id, bytes(content))
            )
        canonical = sorted(
            requested,
            key=lambda value: (value[0], value[1], value[2]),
        )
        if requested != canonical or len(
            {(kind, source, evidence_id) for kind, source, evidence_id, _ in requested}
        ) != len(requested):
            raise EventStoreError(
                "integrity provider evidence must be canonical and unique"
            )
        new_by_id = {
            evidence_id: content
            for _, _, evidence_id, content in requested
            if evidence_id not in existing_ids
        }
        globally_retained_ids = {
            evidence_id
            for evidence_id in new_by_id
            if self._connection.execute(
                """
                SELECT 1
                FROM integrity_evidence_artifacts
                WHERE evidence_id = ?
                """,
                (evidence_id,),
            ).fetchone()
            == (1,)
        }
        new_global_bytes = sum(
            len(content)
            for evidence_id, content in new_by_id.items()
            if evidence_id not in globally_retained_ids
        )
        if (
            self._logical_evidence_storage_used_locked()
            + new_global_bytes
            > self._max_vault_bytes
        ):
            raise EvidenceVaultCapacityError(
                "integrity finality evidence exceeds logical database capacity"
            )
        retained_total_row = self._connection.execute(
            """
            SELECT COALESCE(sum(artifact.byte_size), 0)
            FROM integrity_evidence_artifacts AS artifact
            WHERE artifact.evidence_id IN (
                SELECT DISTINCT mapping.evidence_id
                FROM integrity_transition_evidence AS mapping
                WHERE mapping.event_digest = ?
            )
            """,
            (event_digest,),
        ).fetchone()
        retained_total = int(retained_total_row[0])
        if retained_total + sum(len(value) for value in new_by_id.values()) > (
            _MAX_INTEGRITY_TRANSITION_EVIDENCE_BYTES_V1
        ):
            raise StoreCapacityError(
                "integrity transition evidence exceeds its aggregate byte ceiling"
            )
        self._require_writer_transaction()
        for evidence_id, content in new_by_id.items():
            self._connection.execute(
                """
                INSERT INTO integrity_evidence_artifacts (
                    evidence_id,
                    byte_size,
                    content
                ) VALUES (?, ?, ?)
                ON CONFLICT(evidence_id) DO NOTHING
                """,
                (
                    evidence_id,
                    len(content),
                    sqlite3.Binary(content),
                ),
            )
            retained = self._connection.execute(
                """
                SELECT byte_size, content
                FROM integrity_evidence_artifacts
                WHERE evidence_id = ?
                """,
                (evidence_id,),
            ).fetchone()
            if retained != (len(content), content):
                raise IntegrityTransitionConflictError(
                    "provider evidence identity names different retained bytes"
                )
        for slot, (kind, source, evidence_id, _content) in enumerate(requested):
            self._connection.execute(
                """
                INSERT INTO integrity_transition_evidence (
                    event_digest,
                    phase,
                    slot,
                    evidence_kind,
                    source_id,
                    evidence_id
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(event_digest, phase, slot) DO NOTHING
                """,
                (
                    event_digest,
                    phase,
                    slot,
                    kind,
                    source,
                    evidence_id,
                ),
            )
            retained = self._connection.execute(
                """
                SELECT evidence_kind, source_id, evidence_id
                FROM integrity_transition_evidence
                WHERE event_digest = ? AND phase = ? AND slot = ?
                """,
                (event_digest, phase, slot),
            ).fetchone()
            if retained != (kind, source, evidence_id):
                raise IntegrityTransitionConflictError(
                    "integrity evidence slot was reused with different material"
                )
        count = self._connection.execute(
            """
            SELECT count(*)
            FROM integrity_transition_evidence
            WHERE event_digest = ? AND phase = ?
            """,
            (event_digest, phase),
        ).fetchone()
        if count != (len(requested),):
            raise IntegrityTransitionConflictError(
                "integrity evidence phase has additional retained material"
            )

    def _verify_integrity_evidence_locked(
        self,
        *,
        event_digest: str,
        phase: str,
        provider_evidence: tuple[object, ...],
    ) -> None:
        rows = self._connection.execute(
            """
            SELECT
                mapping.evidence_kind,
                mapping.source_id,
                mapping.evidence_id,
                artifact.byte_size,
                artifact.content
            FROM integrity_transition_evidence AS mapping
            JOIN integrity_evidence_artifacts AS artifact
              ON artifact.evidence_id = mapping.evidence_id
            WHERE mapping.event_digest = ? AND mapping.phase = ?
            ORDER BY mapping.slot ASC
            """,
            (event_digest, phase),
        ).fetchall()
        expected = []
        for blob in provider_evidence:
            expected.append(
                (
                    blob.evidence_kind,
                    blob.source_id,
                    blob.evidence_id,
                    len(blob.content),
                    blob.content,
                )
            )
        if rows != expected:
            raise EventStoreCorruptionError(
                f"retained {phase} provider evidence differs from its canonical record"
            )

    def _load_integrity_lineage_locked(
        self,
        event_digest: str,
    ) -> object | None:
        from .integrity_transition import (
            AnchorStatementRecordV1,
            CheckpointCandidateRecordV1,
            FinalizedIntegrityTransitionV1,
            IntegrityLineageV1,
            PendingIntegrityTransitionV1,
        )

        pending_row = self._connection.execute(
            """
            SELECT
                mission_id,
                event_seq,
                instance_sequence,
                record_id,
                record
            FROM integrity_pending_transitions
            WHERE event_digest = ?
            """,
            (event_digest,),
        ).fetchone()
        if pending_row is None:
            return None
        try:
            pending = PendingIntegrityTransitionV1.from_canonical_bytes(
                pending_row[4]
            )
        except (ProtocolError, TypeError, ValueError) as exc:
            raise EventStoreCorruptionError(
                f"retained pending integrity record is invalid: {exc}"
            ) from exc
        if (
            pending.event_digest != event_digest
            or pending.mission_id != pending_row[0]
            or pending.event_seq != pending_row[1]
            or pending.instance_sequence != pending_row[2]
            or pending.record_id != pending_row[3]
            or pending.to_canonical_bytes() != pending_row[4]
        ):
            raise EventStoreCorruptionError(
                "pending integrity row differs from its canonical record"
            )
        event_row = self._connection.execute(
            """
            SELECT mission_id, seq
            FROM events
            WHERE digest = ?
            """,
            (event_digest,),
        ).fetchone()
        if event_row != (pending.mission_id, pending.event_seq):
            raise EventStoreCorruptionError(
                "pending integrity record differs from its retained event"
            )
        self._verify_integrity_evidence_locked(
            event_digest=event_digest,
            phase="pending",
            provider_evidence=pending.provider_evidence,
        )

        anchor_row = self._connection.execute(
            """
            SELECT record_id, anchor_statement_id, record
            FROM integrity_anchor_statements
            WHERE event_digest = ?
            """,
            (event_digest,),
        ).fetchone()
        anchor = None
        if anchor_row is not None:
            try:
                anchor = AnchorStatementRecordV1.from_canonical_bytes(
                    anchor_row[2]
                )
            except (ProtocolError, TypeError, ValueError) as exc:
                raise EventStoreCorruptionError(
                    f"retained anchor statement record is invalid: {exc}"
                ) from exc
            if (
                anchor.event_digest != event_digest
                or anchor.record_id != anchor_row[0]
                or anchor.anchor_statement_id != anchor_row[1]
                or anchor.to_canonical_bytes() != anchor_row[2]
            ):
                raise EventStoreCorruptionError(
                    "anchor statement row differs from its canonical record"
                )
            self._verify_integrity_evidence_locked(
                event_digest=event_digest,
                phase="anchor_statement",
                provider_evidence=anchor.provider_evidence,
            )

        candidate_row = self._connection.execute(
            """
            SELECT
                record_id,
                checkpoint_id,
                checkpoint_attestation_id,
                record
            FROM integrity_checkpoint_candidates
            WHERE event_digest = ?
            """,
            (event_digest,),
        ).fetchone()
        candidate = None
        if candidate_row is not None:
            try:
                candidate = (
                    CheckpointCandidateRecordV1.from_canonical_bytes(
                        candidate_row[3]
                    )
                )
            except (ProtocolError, TypeError, ValueError) as exc:
                raise EventStoreCorruptionError(
                    f"retained checkpoint candidate is invalid: {exc}"
                ) from exc
            checkpoint = candidate.checkpoint
            from ..integrity_v1 import signed_head_checkpoint_attestation_id

            if (
                candidate.event_digest != event_digest
                or candidate.record_id != candidate_row[0]
                or checkpoint.checkpoint_id != candidate_row[1]
                or signed_head_checkpoint_attestation_id(
                    candidate.signed_checkpoint
                )
                != candidate_row[2]
                or candidate.to_canonical_bytes() != candidate_row[3]
            ):
                raise EventStoreCorruptionError(
                    "checkpoint candidate row differs from its canonical record"
                )
            self._verify_integrity_evidence_locked(
                event_digest=event_digest,
                phase="checkpoint_candidate",
                provider_evidence=candidate.provider_evidence,
            )

        finalization_row = self._connection.execute(
            """
            SELECT record_id, record
            FROM integrity_finalizations
            WHERE event_digest = ?
            """,
            (event_digest,),
        ).fetchone()
        finalization = None
        if finalization_row is not None:
            try:
                finalization = (
                    FinalizedIntegrityTransitionV1.from_canonical_bytes(
                        finalization_row[1]
                    )
                )
            except (ProtocolError, TypeError, ValueError) as exc:
                raise EventStoreCorruptionError(
                    f"retained integrity finalization is invalid: {exc}"
                ) from exc
            if (
                finalization.event_digest != event_digest
                or finalization.record_id != finalization_row[0]
                or finalization.to_canonical_bytes() != finalization_row[1]
            ):
                raise EventStoreCorruptionError(
                    "integrity finalization row differs from its canonical record"
                )
            self._verify_integrity_evidence_locked(
                event_digest=event_digest,
                phase="finalization",
                provider_evidence=finalization.provider_evidence,
            )
        try:
            return IntegrityLineageV1(
                pending=pending,
                anchor_statement=anchor,
                checkpoint_candidate=candidate,
                finalization=finalization,
            )
        except (ProtocolError, TypeError, ValueError) as exc:
            raise EventStoreCorruptionError(
                f"retained integrity lineage is invalid: {exc}"
            ) from exc

    def _previous_integrity_lineages_locked(
        self,
        mission_id: str,
    ) -> tuple[object | None, object | None]:
        global_row = self._connection.execute(
            """
            SELECT pending.event_digest
            FROM integrity_pending_transitions AS pending
            JOIN integrity_finalizations AS finalized
              ON finalized.event_digest = pending.event_digest
            ORDER BY pending.instance_sequence DESC
            LIMIT 1
            """
        ).fetchone()
        mission_row = self._connection.execute(
            """
            SELECT pending.event_digest
            FROM integrity_pending_transitions AS pending
            JOIN integrity_finalizations AS finalized
              ON finalized.event_digest = pending.event_digest
            WHERE pending.mission_id = ?
            ORDER BY pending.event_seq DESC
            LIMIT 1
            """,
            (mission_id,),
        ).fetchone()
        previous_global = (
            None
            if global_row is None
            else self._load_integrity_lineage_locked(global_row[0])
        )
        previous_mission = (
            None
            if mission_row is None
            else self._load_integrity_lineage_locked(mission_row[0])
        )
        if (
            previous_global is not None
            and previous_global.finalization is None
        ) or (
            previous_mission is not None
            and previous_mission.finalization is None
        ):
            raise EventStoreCorruptionError(
                "finalized integrity predecessor omitted its finalization record"
            )
        return previous_global, previous_mission

    def _insert_integrity_pending_locked(
        self,
        event: EventV1,
        pending_record: object,
    ) -> object:
        from .integrity_transition import (
            PendingIntegrityTransitionV1,
            validate_pending_transition,
        )

        pending = self._snapshot_integrity_record(
            pending_record,
            PendingIntegrityTransitionV1,
        )
        if (
            pending.event_digest != event.event_digest
            or pending.mission_id != event.mission_id
            or pending.event_seq != event.seq
        ):
            raise EventStoreError(
                "pending integrity dossier does not bind the proposed event"
            )
        (
            profile,
            service_instance_id,
            environment_id,
            policy_id,
            policy_wire,
            _authority_binding_id,
            _authority_binding_wire,
            authority_binding,
        ) = self._store_profile_locked()
        decision = pending.decision
        retained_policy_wire = canonical_dumps(
            pending.validation_policy.to_body()
        )
        if (
            profile != _MODELED_INTEGRITY_STORE_PROFILE_V1
            or decision.service_instance_id != service_instance_id
            or decision.environment_id != environment_id
            or retained_policy_wire != policy_wire
            or content_id(
                "integrity_validation_policy",
                pending.validation_policy.to_body(),
            )
            != policy_id
            or not self._integrity_lineage_matches_authority_binding(
                pending=pending,
                checkpoint_candidate=None,
                authority_binding=authority_binding,
            )
        ):
            raise EventStoreError(
                "pending integrity dossier differs from the enrolled store profile"
            )
        previous_global, previous_mission = (
            self._previous_integrity_lineages_locked(event.mission_id)
        )
        try:
            validate_pending_transition(
                event,
                pending,
                previous_global=previous_global,
                previous_mission=previous_mission,
                service_instance_id=service_instance_id,
                environment_id=environment_id,
                validation_policy=pending.validation_policy,
            )
        except (ProtocolError, TypeError, ValueError) as exc:
            reason_code = getattr(
                exc,
                "reason_code",
                "invalid_pending_integrity_transition",
            )
            raise EventStoreError(
                f"pending integrity validation failed ({reason_code}): {exc}"
            ) from exc
        self._reserve_integrity_finality_capacity_locked()
        self._require_writer_transaction()
        self._connection.execute(
            """
            INSERT INTO integrity_pending_transitions (
                event_digest,
                mission_id,
                event_seq,
                instance_sequence,
                record_id,
                record
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                pending.event_digest,
                pending.mission_id,
                pending.event_seq,
                pending.instance_sequence,
                pending.record_id,
                sqlite3.Binary(pending.to_canonical_bytes()),
            ),
        )
        self._retain_integrity_evidence_locked(
            event_digest=pending.event_digest,
            phase="pending",
            provider_evidence=pending.provider_evidence,
        )
        return pending

    def _append_verified_event(
        self,
        event: EventV1,
        *,
        expected_head: str,
        evidence_store: FileEvidenceStore | None = None,
        integrity_pending: object | None = None,
    ) -> EventV1:
        self._validate_append_request(event, expected_head)
        is_protected = event.kind in PROTECTED_EVIDENCE_EVENT_KINDS_V1
        if is_protected != (evidence_store is not None):
            raise EventStoreError("protected evidence events and vault retention must be paired")
        trusted_staging = self._trusted_staging_store(evidence_store) if evidence_store is not None else None
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            self._require_writer_transaction()
            self._validate_integrity_state_locked()
            profile = self._store_profile_locked()[0]
            unresolved = self._unresolved_integrity_digest_locked()
            if unresolved is not None and unresolved != event.event_digest:
                raise PendingIntegrityTransitionError(
                    "an instance-global integrity transition is pending"
                )
            if profile == _MODELED_INTEGRITY_STORE_PROFILE_V1:
                if integrity_pending is None:
                    raise IntegrityFinalityRequiredError(
                        "modeled integrity profile requires an atomic pending dossier"
                    )
            elif integrity_pending is not None:
                raise EventStoreError(
                    "typed integrity pending state requires modeled profile enrollment"
                )
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
            retained_pending = None
            if integrity_pending is not None:
                retained_pending = self._insert_integrity_pending_locked(
                    event,
                    integrity_pending,
                )
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
            retained_event = self._event_for_integrity_digest_locked(
                event.event_digest
            )
            if retained_event != event:
                raise EventStoreCorruptionError(
                    "retained event did not replay exactly after append"
                )
            if retained_pending is not None:
                lineage = self._load_integrity_lineage_locked(
                    event.event_digest
                )
                if (
                    lineage is None
                    or lineage.pending != retained_pending
                    or lineage.anchor_statement is not None
                    or lineage.checkpoint_candidate is not None
                    or lineage.finalization is not None
                ):
                    raise EventStoreCorruptionError(
                        "retained pending integrity extension did not replay exactly"
                    )
            self._publish_owned_integrity_validation_cache_locked()
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

    def append_pending_integrity_event(
        self,
        event: EventV1,
        *,
        expected_head: str,
        pending: object,
        evidence_store: FileEvidenceStore | None = None,
    ) -> EventV1:
        """Atomically retain one event, its claimed BLOBs, and its pending dossier."""

        from .integrity_transition import PendingIntegrityTransitionV1

        # ADR-0019 step 4: the pending record's declared acceptance mode must match the
        # enrolled acceptance profile exactly, and in qualified mode the sealed time and
        # revocation bundles must accompany the freshly submitted record so the store can
        # reauthenticate the decision's time and revocation inputs under the enrolled roots.
        # The acceptance profile is immutable once enrolled, so reading it here (before the
        # append transaction) is race-free.
        if type(pending) is not PendingIntegrityTransitionV1:
            raise EventStoreError(
                "integrity pending append requires an exact PendingIntegrityTransitionV1"
            )
        enrolled_mode = self.resolve_acceptance_mode()
        if pending.acceptance_mode != enrolled_mode:
            raise EventStoreError(
                "pending transition acceptance mode "
                f"({pending.acceptance_mode}) differs from the enrolled acceptance "
                f"profile ({enrolled_mode})"
            )
        if enrolled_mode == _ACCEPTANCE_MODE_QUALIFIED_SIGNED_V1:
            if pending.time_bundle is None or pending.revocation_bundles is None:
                raise EventStoreError(
                    "a qualified pending transition requires its sealed qualified time and "
                    "revocation bundles for store-side reauthentication"
                )
            _QUALIFIED_EVIDENCE_REFUSALS_V1 = _qualified_evidence_refusals()
            try:
                self.verify_qualified_revocation_evidence(
                    pending_record=pending,
                    time_bundle=pending.time_bundle,
                    revocation_bundles=pending.revocation_bundles,
                )
            except _QUALIFIED_EVIDENCE_REFUSALS_V1 as exc:
                raise EventStoreError(
                    "qualified pending revocation evidence failed reauthentication "
                    f"({getattr(exc, 'reason_code', 'unknown')}): {exc}"
                ) from exc

        self._validate_append_request(event, expected_head)
        is_protected = event.kind in PROTECTED_EVIDENCE_EVENT_KINDS_V1
        if is_protected:
            if type(evidence_store) is not FileEvidenceStore:
                raise EventStoreError(
                    "protected integrity append requires an exact FileEvidenceStore"
                )
            trusted_staging = self._trusted_staging_store(evidence_store)
        else:
            if evidence_store is not None:
                raise EventStoreError(
                    "ordinary integrity append cannot receive an evidence store"
                )
            trusted_staging = None
        try:
            return self._append_verified_event(
                event,
                expected_head=expected_head,
                evidence_store=trusted_staging,
                integrity_pending=pending,
            )
        except StaleHeadError as exc:
            from .integrity_transition import PendingIntegrityTransitionV1

            requested = self._snapshot_integrity_record(
                pending,
                PendingIntegrityTransitionV1,
            )
            lineage = self.load_integrity_lineage(event.event_digest)
            retained = self.load_integrity_event(
                event.event_digest
            )
            if (
                expected_head == event.prev_digest
                and retained == event
                and lineage is not None
                and lineage.pending == requested
            ):
                return retained
            if retained == event and lineage is not None:
                raise IntegrityTransitionConflictError(
                    "retained event has a different pending integrity dossier"
                ) from exc
            raise

    def load_integrity_event(
        self,
        event_digest: str,
    ) -> EventV1 | None:
        """Load one exact modeled-integrity event without exposing mission replay."""

        if type(event_digest) is not str or _DIGEST_RE.fullmatch(event_digest) is None:
            raise EventStoreError(
                "event_digest must be a full lowercase sha256 digest"
            )
        self._validate_integrity_state_locked()
        if (
            self._store_profile_locked()[0]
            != _MODELED_INTEGRITY_STORE_PROFILE_V1
        ):
            raise IntegrityFinalityRequiredError(
                "exact integrity event reads require modeled profile enrollment"
            )
        retained = self._connection.execute(
            """
            SELECT 1
            FROM integrity_pending_transitions
            WHERE event_digest = ?
            """,
            (event_digest,),
        ).fetchone()
        if retained is None:
            return None
        return self._event_for_integrity_digest_locked(event_digest)

    def load_latest_finalized_integrity_lineages(
        self,
        mission_id: str,
    ) -> tuple[object | None, object | None]:
        """Return authenticated latest global and mission-local finality."""

        if type(mission_id) is not str or _DIGEST_RE.fullmatch(mission_id) is None:
            raise EventStoreError(
                "mission_id must be a full lowercase sha256 digest"
            )
        self._validate_integrity_state_locked()
        if (
            self._store_profile_locked()[0]
            != _MODELED_INTEGRITY_STORE_PROFILE_V1
        ):
            raise IntegrityFinalityRequiredError(
                "integrity lineage reads require modeled profile enrollment"
            )
        return self._previous_integrity_lineages_locked(mission_id)

    def load_integrity_predecessor_lineages(
        self,
        event_digest: str,
    ) -> tuple[object | None, object | None]:
        """Return exact finalized global and mission predecessors of one event."""

        if type(event_digest) is not str or _DIGEST_RE.fullmatch(event_digest) is None:
            raise EventStoreError(
                "event_digest must be a full lowercase sha256 digest"
            )
        self._validate_integrity_state_locked()
        if (
            self._store_profile_locked()[0]
            != _MODELED_INTEGRITY_STORE_PROFILE_V1
        ):
            raise IntegrityFinalityRequiredError(
                "integrity predecessor reads require modeled profile enrollment"
            )
        retained = self._connection.execute(
            """
            SELECT mission_id, event_seq, instance_sequence
            FROM integrity_pending_transitions
            WHERE event_digest = ?
            """,
            (event_digest,),
        ).fetchone()
        if retained is None:
            raise EventStoreError(
                "integrity predecessor read requires a retained event digest"
            )
        mission_id, event_seq, instance_sequence = retained
        if (
            type(mission_id) is not str
            or _DIGEST_RE.fullmatch(mission_id) is None
            or type(event_seq) is not int
            or event_seq < 0
            or type(instance_sequence) is not int
            or instance_sequence < 0
        ):
            raise EventStoreCorruptionError(
                "integrity predecessor index is malformed"
            )
        global_row = self._connection.execute(
            """
            SELECT pending.event_digest
            FROM integrity_pending_transitions AS pending
            JOIN integrity_finalizations AS finalized
              ON finalized.event_digest = pending.event_digest
            WHERE pending.instance_sequence = ?
            """,
            (instance_sequence - 1,),
        ).fetchone()
        mission_row = self._connection.execute(
            """
            SELECT pending.event_digest
            FROM integrity_pending_transitions AS pending
            JOIN integrity_finalizations AS finalized
              ON finalized.event_digest = pending.event_digest
            WHERE
                pending.mission_id = ?
                AND pending.event_seq = ?
            """,
            (mission_id, event_seq - 1),
        ).fetchone()
        if (
            (instance_sequence == 0) != (global_row is None)
            or (event_seq == 0) != (mission_row is None)
        ):
            raise EventStoreCorruptionError(
                "integrity event omitted an exact finalized predecessor"
            )
        previous_global = (
            None
            if global_row is None
            else self._load_integrity_lineage_locked(global_row[0])
        )
        previous_mission = (
            None
            if mission_row is None
            else self._load_integrity_lineage_locked(mission_row[0])
        )
        if (
            previous_global is not None
            and previous_global.finalization is None
        ) or (
            previous_mission is not None
            and previous_mission.finalization is None
        ):
            raise EventStoreCorruptionError(
                "integrity predecessor omitted its finalization"
            )
        return previous_global, previous_mission

    def load_integrity_lineage(self, event_digest: str) -> object | None:
        """Load and reconstruct one exact append-only integrity lineage."""

        if type(event_digest) is not str or _DIGEST_RE.fullmatch(event_digest) is None:
            raise EventStoreError(
                "event_digest must be a full lowercase sha256 digest"
            )
        self._validate_integrity_state_locked()
        return self._load_integrity_lineage_locked(event_digest)

    def load_unresolved_integrity_transition(self) -> object | None:
        """Return the singleton unresolved lineage, if present."""

        self._validate_integrity_state_locked()
        event_digest = self._unresolved_integrity_digest_locked()
        if event_digest is None:
            return None
        lineage = self._load_integrity_lineage_locked(event_digest)
        if lineage is None or lineage.finalization is not None:
            raise EventStoreCorruptionError(
                "unresolved integrity transition cannot be reconstructed"
            )
        return lineage

    def load_integrity_anchor_statement(
        self,
        event_digest: str,
    ) -> object | None:
        lineage = self.load_integrity_lineage(event_digest)
        return None if lineage is None else lineage.anchor_statement

    def load_integrity_checkpoint_candidate(
        self,
        event_digest: str,
    ) -> object | None:
        lineage = self.load_integrity_lineage(event_digest)
        return None if lineage is None else lineage.checkpoint_candidate

    def load_integrity_finalization(
        self,
        event_digest: str,
    ) -> object | None:
        lineage = self.load_integrity_lineage(event_digest)
        return None if lineage is None else lineage.finalization

    def _event_for_integrity_digest_locked(
        self,
        event_digest: str,
    ) -> EventV1:
        row = self._connection.execute(
            """
            SELECT canonical
            FROM events
            WHERE digest = ?
            """,
            (event_digest,),
        ).fetchone()
        if row is None or type(row[0]) is not bytes:
            raise EventStoreCorruptionError(
                "integrity transition does not reference one retained event"
            )
        try:
            event = EventV1.from_canonical_bytes(row[0])
        except (ProtocolError, TypeError, ValueError) as exc:
            raise EventStoreCorruptionError(
                f"integrity event bytes are invalid: {exc}"
            ) from exc
        if (
            event.event_digest != event_digest
            or event.to_canonical_bytes() != row[0]
        ):
            raise EventStoreCorruptionError(
                "integrity event identity differs from its canonical bytes"
            )
        return event

    # ------------------------------------------------------------------
    # Durable blocked finality (ADR-0014 contract, ADR-0015 storage)
    # ------------------------------------------------------------------

    def enroll_blocked_finality_recovery(self, profile: object) -> str:
        """Retain the exact enrolled recovery profile once, or reconcile it.

        This never releases the barrier and never resolves a transition.  Store-domain
        failures keep their exact classification; they are not adapter refusals.
        """

        from .blocked_finality_v1 import BlockedFinalityRecoveryProfileV1

        if type(profile) is not BlockedFinalityRecoveryProfileV1:
            raise EventStoreError(
                "recovery enrollment requires an exact BlockedFinalityRecoveryProfileV1"
            )
        wire = profile.to_canonical_bytes()
        profile_id = profile.profile_id
        if len(wire) > _MAX_INTEGRITY_RECORD_BYTES_V1:
            raise StoreCapacityError("the recovery profile exceeds its record ceiling")
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            self._require_writer_transaction()
            self._validate_integrity_state_locked()
            retained = self._connection.execute(
                "SELECT recovery_profile_id, recovery_profile_wire "
                "FROM integrity_recovery_profile WHERE singleton = 1"
            ).fetchone()
            if retained is not None:
                if retained[0] != profile_id or bytes(retained[1]) != wire:
                    raise IntegrityTransitionConflictError(
                        "a different recovery profile is already enrolled"
                    )
                self._connection.execute("COMMIT")
                return profile_id
            used = self._logical_evidence_storage_used_locked()
            if used + len(profile_id) + len(wire) > self._max_vault_bytes:
                raise EvidenceVaultCapacityError(
                    "recovery enrollment exceeds logical database capacity"
                )
            self._connection.execute(
                "INSERT INTO integrity_recovery_profile "
                "(singleton, recovery_profile_id, recovery_profile_wire) "
                "VALUES (1, ?, ?)",
                (profile_id, wire),
            )
            self._require_writer_transaction()
            self._connection.execute("COMMIT")
            return profile_id
        except sqlite3.DatabaseError as error:
            self._rollback_quietly()
            raise _sqlite_store_failure("recovery enrollment", error) from error
        except BaseException:
            self._rollback_quietly()
            raise

    def retain_blocked_finality_observation(self, observation: object) -> object:
        """Retain one durable blocked observation without resolving anything."""

        from .blocked_finality_v1 import BlockedFinalityObservationV1

        if type(observation) is not BlockedFinalityObservationV1:
            raise EventStoreError(
                "a durable block requires an exact BlockedFinalityObservationV1"
            )
        record = BlockedFinalityObservationV1.from_canonical_bytes(
            observation.to_canonical_bytes()
        )
        wire = record.to_canonical_bytes()
        if len(wire) > _MAX_INTEGRITY_RECORD_BYTES_V1:
            raise StoreCapacityError("the blocked observation exceeds its record ceiling")
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            self._require_writer_transaction()
            self._validate_integrity_state_locked()
            self._require_enrolled_recovery_profile_locked()
            retained = self._connection.execute(
                "SELECT observation_id, record FROM integrity_blocked_observations "
                "WHERE event_digest = ? AND attempt_ordinal = ?",
                (record.event_digest, record.attempt_ordinal),
            ).fetchone()
            if retained is not None:
                if retained[0] != record.observation_id or bytes(retained[1]) != wire:
                    raise IntegrityTransitionConflictError(
                        "one blocked attempt ordinal was reused with different bytes"
                    )
                self._connection.execute("COMMIT")
                return record
            highest = self._connection.execute(
                "SELECT COALESCE(max(attempt_ordinal), 0) "
                "FROM integrity_blocked_observations WHERE event_digest = ?",
                (record.event_digest,),
            ).fetchone()[0]
            if record.attempt_ordinal <= int(highest):
                raise IntegrityTransitionConflictError(
                    "a blocked attempt ordinal cannot regress"
                )
            used = self._logical_evidence_storage_used_locked()
            if used + len(wire) > self._max_vault_bytes:
                raise EvidenceVaultCapacityError(
                    "the blocked observation exceeds logical database capacity"
                )
            self._connection.execute(
                "INSERT INTO integrity_blocked_observations "
                "(event_digest, attempt_ordinal, observation_id, unresolved_phase, record) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    record.event_digest,
                    record.attempt_ordinal,
                    record.observation_id,
                    record.unresolved_phase,
                    wire,
                ),
            )
            self._require_writer_transaction()
            self._connection.execute("COMMIT")
            return record
        except sqlite3.DatabaseError as error:
            self._rollback_quietly()
            raise _sqlite_store_failure("blocked observation", error) from error
        except BaseException:
            self._rollback_quietly()
            raise

    def retain_governed_recovery_decision(self, signed_decision: object) -> str:
        """Retain one signed governed recovery decision answering the latest block."""

        from .blocked_finality_v1 import (
            GovernedRecoveryDecisionV1,
            SignedGovernedRecoveryDecisionV1,
            authenticate_recovery_decision_v1,
        )

        if type(signed_decision) is not SignedGovernedRecoveryDecisionV1:
            raise EventStoreError(
                "a governed recovery decision requires an exact signed wrapper"
            )
        wire = signed_decision.to_canonical_bytes()
        if len(wire) > _MAX_INTEGRITY_RECORD_BYTES_V1:
            raise StoreCapacityError("the recovery decision exceeds its record ceiling")
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            self._require_writer_transaction()
            self._validate_integrity_state_locked()
            profile = self._require_enrolled_recovery_profile_locked()
            authenticated = authenticate_recovery_decision_v1(
                profile=profile,
                signed_decision=signed_decision,
            )
            decision: GovernedRecoveryDecisionV1 = authenticated.decision
            retained = self._connection.execute(
                "SELECT record FROM integrity_recovery_decisions WHERE decision_id = ?",
                (decision.decision_id,),
            ).fetchone()
            if retained is not None:
                if bytes(retained[0]) != wire:
                    raise IntegrityTransitionConflictError(
                        "one recovery decision identity was reused with different bytes"
                    )
                self._connection.execute("COMMIT")
                return decision.decision_id
            used = self._logical_evidence_storage_used_locked()
            if used + len(wire) > self._max_vault_bytes:
                raise EvidenceVaultCapacityError(
                    "the recovery decision exceeds logical database capacity"
                )
            self._connection.execute(
                "INSERT INTO integrity_recovery_decisions "
                "(decision_id, event_digest, blocked_observation_id, disposition, record) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    decision.decision_id,
                    decision.event_digest,
                    decision.blocked_observation_id,
                    decision.disposition,
                    wire,
                ),
            )
            self._require_writer_transaction()
            self._connection.execute("COMMIT")
            return decision.decision_id
        except sqlite3.DatabaseError as error:
            self._rollback_quietly()
            raise _sqlite_store_failure("recovery decision", error) from error
        except BaseException:
            self._rollback_quietly()
            raise

    def load_blocked_finality_observations(self, event_digest: str) -> tuple[object, ...]:
        """Return one transition's retained blocked observations in ordinal order."""

        from .blocked_finality_v1 import BlockedFinalityObservationV1

        if type(event_digest) is not str or _DIGEST_RE.fullmatch(event_digest) is None:
            raise EventStoreError("event_digest must be a full lowercase sha256 digest")
        self._validate_integrity_state_locked()
        rows = self._connection.execute(
            "SELECT record FROM integrity_blocked_observations "
            "WHERE event_digest = ? ORDER BY attempt_ordinal ASC",
            (event_digest,),
        ).fetchall()
        return tuple(
            BlockedFinalityObservationV1.from_canonical_bytes(bytes(row[0]))
            for row in rows
        )

    def enroll_qualified_acceptance(
        self,
        *,
        qualified_time_profile: object,
        qualified_head_profile: object,
    ) -> str:
        """Pin the qualified time and head-authority adapter roots, once, permanently.

        Enrollment is empty-history only and requires an enrolled modeled profile.  It
        selects the qualified_signed_fixture acceptance mode; nothing consumes it yet.
        Store-domain failures keep their exact classification.
        """

        from etzio.kernel.head_authority_adapters_v1 import HeadAuthorityTrustProfileV1
        from etzio.kernel.integrity_adapters_v1 import IntegrityAdapterTrustProfileV1

        if type(qualified_time_profile) is not IntegrityAdapterTrustProfileV1:
            raise EventStoreError(
                "qualified acceptance requires an exact IntegrityAdapterTrustProfileV1"
            )
        if type(qualified_head_profile) is not HeadAuthorityTrustProfileV1:
            raise EventStoreError(
                "qualified acceptance requires an exact HeadAuthorityTrustProfileV1"
            )
        time_wire = qualified_time_profile.to_canonical_bytes()
        time_id = qualified_time_profile.profile_id
        head_wire = qualified_head_profile.to_canonical_bytes()
        head_id = qualified_head_profile.profile_id
        for wire in (time_wire, head_wire):
            if len(wire) > _MAX_INTEGRITY_RECORD_BYTES_V1:
                raise StoreCapacityError(
                    "a qualified acceptance profile exceeds its record ceiling"
                )
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            self._require_writer_transaction()
            self._validate_integrity_state_locked()
            retained = self._connection.execute(
                "SELECT qualified_time_profile_id, qualified_time_profile_wire, "
                "qualified_head_profile_id, qualified_head_profile_wire "
                "FROM integrity_acceptance_profile WHERE singleton = 1"
            ).fetchone()
            if retained is not None:
                if (
                    retained[0] != time_id
                    or bytes(retained[1]) != time_wire
                    or retained[2] != head_id
                    or bytes(retained[3]) != head_wire
                ):
                    raise IntegrityTransitionConflictError(
                        "a different qualified acceptance profile is already enrolled"
                    )
                self._connection.execute("COMMIT")
                return _ACCEPTANCE_MODE_QUALIFIED_SIGNED_V1
            used = self._logical_evidence_storage_used_locked()
            additional = (
                len(_ACCEPTANCE_MODE_QUALIFIED_SIGNED_V1)
                + len(time_id)
                + len(time_wire)
                + len(head_id)
                + len(head_wire)
            )
            if used + additional > self._max_vault_bytes:
                raise EvidenceVaultCapacityError(
                    "qualified acceptance enrollment exceeds logical database capacity"
                )
            self._connection.execute(
                "INSERT INTO integrity_acceptance_profile "
                "(singleton, acceptance_mode, qualified_time_profile_id, "
                "qualified_time_profile_wire, qualified_head_profile_id, "
                "qualified_head_profile_wire) VALUES (1, ?, ?, ?, ?, ?)",
                (
                    _ACCEPTANCE_MODE_QUALIFIED_SIGNED_V1,
                    time_id,
                    time_wire,
                    head_id,
                    head_wire,
                ),
            )
            self._require_writer_transaction()
            self._connection.execute("COMMIT")
            return _ACCEPTANCE_MODE_QUALIFIED_SIGNED_V1
        except sqlite3.DatabaseError as error:
            self._rollback_quietly()
            raise _sqlite_store_failure("qualified acceptance enrollment", error) from error
        except BaseException:
            self._rollback_quietly()
            raise

    def resolve_acceptance_mode(self) -> str:
        """Return the enrolled provider-evidence acceptance mode.

        Absence of a qualified acceptance row is the modeled-unsigned default.
        """

        self._validate_integrity_state_locked()
        row = self._connection.execute(
            "SELECT acceptance_mode FROM integrity_acceptance_profile WHERE singleton = 1"
        ).fetchone()
        if row is None:
            return _ACCEPTANCE_MODE_MODELED_UNSIGNED_V1
        if row[0] != _ACCEPTANCE_MODE_QUALIFIED_SIGNED_V1:
            raise EventStoreCorruptionError(
                "the retained acceptance mode is not a supported value"
            )
        return _ACCEPTANCE_MODE_QUALIFIED_SIGNED_V1

    def load_qualified_acceptance_profiles(self) -> tuple[object, object] | None:
        """Return the exact retained qualified time and head-authority profiles, if any."""

        from etzio.kernel.head_authority_adapters_v1 import HeadAuthorityTrustProfileV1
        from etzio.kernel.integrity_adapters_v1 import IntegrityAdapterTrustProfileV1

        self._validate_integrity_state_locked()
        row = self._connection.execute(
            "SELECT qualified_time_profile_id, qualified_time_profile_wire, "
            "qualified_head_profile_id, qualified_head_profile_wire "
            "FROM integrity_acceptance_profile WHERE singleton = 1"
        ).fetchone()
        if row is None:
            return None
        time_profile = IntegrityAdapterTrustProfileV1.from_canonical_bytes(bytes(row[1]))
        head_profile = HeadAuthorityTrustProfileV1.from_canonical_bytes(bytes(row[3]))
        if time_profile.profile_id != row[0] or head_profile.profile_id != row[2]:
            raise EventStoreCorruptionError(
                "a retained qualified acceptance profile does not match its identity"
            )
        return (time_profile, head_profile)

    def verify_qualified_anchor_evidence(
        self,
        *,
        anchor_bundle: object,
        time_bundle: object,
        claimed_anchor_statement_id: str,
        claimed_anchor_evidence: object,
        claimed_evidence_blobs: object,
    ) -> object:
        """Consume a checkpoint's anchor evidence against the enrolled qualified roots.

        This is the first lifecycle consumption of qualified signed evidence: the enrolled
        schema-version-4 time and head-authority profiles drive the ADR-0018 acceptance
        primitive, which reauthenticates the retained bundle from its signed packages before
        accepting the claim. A store with no qualified acceptance profile refuses; it never
        silently falls back to the unsigned modeled gate.
        """

        from etzio.kernel.qualified_evidence_v1 import (
            accept_qualified_anchor_evidence_v1,
        )

        profiles = self.load_qualified_acceptance_profiles()
        if profiles is None:
            raise IntegrityFinalityRequiredError(
                "qualified anchor consumption requires an enrolled qualified acceptance "
                "profile"
            )
        time_profile, head_profile = profiles
        return accept_qualified_anchor_evidence_v1(
            head_profile=head_profile,
            time_profile=time_profile,
            time_bundle=time_bundle,  # type: ignore[arg-type]
            anchor_bundle=anchor_bundle,  # type: ignore[arg-type]
            claimed_anchor_statement_id=claimed_anchor_statement_id,
            claimed_anchor_evidence=claimed_anchor_evidence,  # type: ignore[arg-type]
            claimed_evidence_blobs=claimed_evidence_blobs,  # type: ignore[arg-type]
        )

    def verify_qualified_revocation_evidence(
        self,
        *,
        pending_record: object,
        time_bundle: object,
        revocation_bundles: object,
    ) -> object:
        """Consume a pending decision's time and revocation evidence against enrolled roots.

        The pending/revocation analogue of ``verify_qualified_anchor_evidence`` (ADR-0019
        step 4): the enrolled schema-version-4 time-adapter profile drives
        ``accept_qualified_revocation_evidence_v1``, which reauthenticates the retained time
        and revocation bundles from their signed packages before accepting the decision's
        claimed time hull, evidence, views, and floors.  Only the decision's time,
        revocation-metadata, and revocation-floor blobs are consumed here; the predecessor
        head-floor evidence a pending record also carries is the finalization phase's concern
        (ADR-0019 step 5).  A store with no qualified acceptance profile refuses.
        """

        from .integrity_transition import PendingIntegrityTransitionV1
        from .qualified_evidence_v1 import accept_qualified_revocation_evidence_v1

        if type(pending_record) is not PendingIntegrityTransitionV1:
            raise EventStoreError(
                "qualified revocation consumption requires an exact "
                "PendingIntegrityTransitionV1"
            )
        profiles = self.load_qualified_acceptance_profiles()
        if profiles is None:
            raise IntegrityFinalityRequiredError(
                "qualified revocation consumption requires an enrolled qualified "
                "acceptance profile"
            )
        time_profile, _head_profile = profiles
        decision = pending_record.decision
        floors = pending_record.revocation_floors
        # Partition the decision's time+revocation evidence out of the record's full
        # provider evidence by exact evidence identity, leaving the predecessor head-floor
        # blobs for the finalization phase.  Evidence identities are content digests, so this
        # partition is exact and collision-free.
        revocation_ids: set[str] = set()
        for reference in decision.time_evidence:
            revocation_ids.add(reference.evidence_id)
        for view in decision.revocation_views:
            revocation_ids.add(view.evidence.evidence_id)
        for floor in floors:
            for reference in floor.evidence:
                revocation_ids.add(reference.evidence_id)
        subset = tuple(
            blob
            for blob in pending_record.provider_evidence
            if blob.evidence_id in revocation_ids
        )
        return accept_qualified_revocation_evidence_v1(
            profile=time_profile,  # type: ignore[arg-type]
            time_bundle=time_bundle,  # type: ignore[arg-type]
            revocation_bundles=revocation_bundles,  # type: ignore[arg-type]
            claimed_time_lower_bound=decision.time_lower_bound,
            claimed_time_upper_bound=decision.time_upper_bound,
            claimed_time_policy_id=decision.time_policy_id,
            claimed_time_evidence=decision.time_evidence,
            claimed_revocation_views=decision.revocation_views,
            claimed_external_floors=floors,
            claimed_evidence_blobs=subset,
        )

    def load_governed_recovery_decision(self, observation_id: str) -> object | None:
        """Return the retained decision answering one observation, if present."""

        from .blocked_finality_v1 import SignedGovernedRecoveryDecisionV1

        if type(observation_id) is not str or _DIGEST_RE.fullmatch(observation_id) is None:
            raise EventStoreError("observation_id must be a full lowercase sha256 digest")
        self._validate_integrity_state_locked()
        row = self._connection.execute(
            "SELECT record FROM integrity_recovery_decisions "
            "WHERE blocked_observation_id = ?",
            (observation_id,),
        ).fetchone()
        if row is None:
            return None
        return SignedGovernedRecoveryDecisionV1.from_canonical_bytes(bytes(row[0]))

    def instance_is_sealed(self) -> bool:
        """Return whether a terminal sealing decision is retained."""

        self._validate_integrity_state_locked()
        row = self._connection.execute(
            "SELECT 1 FROM integrity_recovery_decisions "
            "WHERE disposition = 'instance_sealed' LIMIT 1"
        ).fetchone()
        return row is not None

    def _require_enrolled_recovery_profile_locked(self) -> object:
        from .blocked_finality_v1 import BlockedFinalityRecoveryProfileV1

        row = self._connection.execute(
            "SELECT recovery_profile_id, recovery_profile_wire "
            "FROM integrity_recovery_profile WHERE singleton = 1"
        ).fetchone()
        if row is None:
            raise EventStoreError("no governed recovery profile is enrolled")
        profile = BlockedFinalityRecoveryProfileV1.from_canonical_bytes(bytes(row[1]))
        if profile.profile_id != row[0]:
            raise EventStoreCorruptionError(
                "the retained recovery profile does not match its identity"
            )
        return profile

    def _rollback_quietly(self) -> None:
        if self._connection.in_transaction:
            try:
                self._connection.execute("ROLLBACK")
            except sqlite3.DatabaseError:
                pass

    def retain_integrity_anchor_statement(
        self,
        record: object,
    ) -> object:
        """Persist the exact pre-receipt statement before its external registration."""

        from .integrity_transition import (
            AnchorStatementRecordV1,
            validate_anchor_statement,
        )

        anchor = self._snapshot_integrity_record(
            record,
            AnchorStatementRecordV1,
        )
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            self._require_writer_transaction()
            self._validate_integrity_state_locked()
            lineage = self._load_integrity_lineage_locked(
                anchor.event_digest
            )
            if lineage is None:
                raise EventStoreCorruptionError(
                    "anchor statement omitted its pending transition"
                )
            if lineage.anchor_statement is not None:
                if lineage.anchor_statement != anchor:
                    raise IntegrityTransitionConflictError(
                        "anchor statement identity was reused with different bytes"
                    )
                self._connection.execute("COMMIT")
                return lineage.anchor_statement
            unresolved = self._unresolved_integrity_digest_locked()
            if unresolved != anchor.event_digest:
                raise PendingIntegrityTransitionError(
                    "anchor statement must extend the singleton pending transition"
                )
            _previous_global, previous_mission = (
                self._previous_integrity_lineages_locked(
                    lineage.pending.mission_id
                )
            )
            try:
                validate_anchor_statement(
                    lineage.pending,
                    anchor,
                    previous_mission=previous_mission,
                )
            except (ProtocolError, TypeError, ValueError) as exc:
                reason_code = getattr(
                    exc,
                    "reason_code",
                    "invalid_anchor_statement",
                )
                raise EventStoreError(
                    f"anchor statement validation failed ({reason_code}): {exc}"
                ) from exc
            self._require_writer_transaction()
            self._connection.execute(
                """
                INSERT INTO integrity_anchor_statements (
                    event_digest,
                    record_id,
                    anchor_statement_id,
                    record
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    anchor.event_digest,
                    anchor.record_id,
                    anchor.anchor_statement_id,
                    sqlite3.Binary(anchor.to_canonical_bytes()),
                ),
            )
            self._retain_integrity_evidence_locked(
                event_digest=anchor.event_digest,
                phase="anchor_statement",
                provider_evidence=anchor.provider_evidence,
            )
            retained = self._load_integrity_lineage_locked(
                anchor.event_digest
            )
            if retained is None or retained.anchor_statement != anchor:
                raise EventStoreCorruptionError(
                    "retained anchor statement did not replay exactly"
                )
            self._publish_owned_integrity_validation_cache_locked()
            self._require_writer_transaction()
            self._connection.execute("COMMIT")
            return retained.anchor_statement
        except (
            EventStoreError,
            PendingIntegrityTransitionError,
            IntegrityTransitionConflictError,
        ):
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise
        except sqlite3.IntegrityError as exc:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise IntegrityTransitionConflictError(
                f"SQLite rejected anchor statement retention: {exc}"
            ) from exc
        except sqlite3.DatabaseError as exc:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise _sqlite_store_failure(
                "anchor statement retention failed",
                exc,
            ) from exc

    def retain_integrity_checkpoint_candidate(
        self,
        record: object,
    ) -> object:
        """Persist one exact signed checkpoint before external publication."""

        from ..integrity_v1 import signed_head_checkpoint_attestation_id
        from .integrity_transition import (
            CheckpointCandidateRecordV1,
            validate_checkpoint_candidate,
        )

        candidate = self._snapshot_integrity_record(
            record,
            CheckpointCandidateRecordV1,
        )
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            self._require_writer_transaction()
            self._validate_integrity_state_locked()
            # ADR-0019 step 3: the record's declared acceptance mode must match the
            # enrolled acceptance profile exactly.  A qualified record on a modeled/legacy
            # store and a modeled record on a qualified store are both refused before any
            # lineage work.  In qualified mode the sealed bundles must accompany the freshly
            # submitted record so the store can reauthenticate them under the enrolled roots.
            enrolled_mode = self.resolve_acceptance_mode()
            if candidate.acceptance_mode != enrolled_mode:
                raise EventStoreError(
                    "checkpoint candidate acceptance mode "
                    f"({candidate.acceptance_mode}) differs from the enrolled acceptance "
                    f"profile ({enrolled_mode})"
                )
            lineage = self._load_integrity_lineage_locked(
                candidate.event_digest
            )
            if lineage is None or lineage.anchor_statement is None:
                raise EventStoreError(
                    "checkpoint candidate requires its retained anchor statement"
                )
            if lineage.checkpoint_candidate is not None:
                if lineage.checkpoint_candidate != candidate:
                    raise IntegrityTransitionConflictError(
                        "checkpoint candidate identity was reused with different bytes"
                    )
                self._connection.execute("COMMIT")
                return lineage.checkpoint_candidate
            unresolved = self._unresolved_integrity_digest_locked()
            if unresolved != candidate.event_digest:
                raise PendingIntegrityTransitionError(
                    "checkpoint candidate must extend the singleton pending transition"
                )
            event = self._event_for_integrity_digest_locked(
                candidate.event_digest
            )
            authority_binding = self._store_profile_locked()[-1]
            if not self._integrity_lineage_matches_authority_binding(
                pending=lineage.pending,
                checkpoint_candidate=candidate,
                authority_binding=authority_binding,
            ):
                raise EventStoreError(
                    "checkpoint candidate differs from the enrolled "
                    "authority binding"
                )
            previous_global, previous_mission = (
                self._previous_integrity_lineages_locked(
                    lineage.pending.mission_id
                )
            )
            try:
                validate_checkpoint_candidate(
                    event,
                    lineage.pending,
                    lineage.anchor_statement,
                    candidate,
                    previous_global=previous_global,
                    previous_mission=previous_mission,
                )
            except (ProtocolError, TypeError, ValueError) as exc:
                reason_code = getattr(
                    exc,
                    "reason_code",
                    "invalid_checkpoint_candidate",
                )
                raise EventStoreError(
                    f"checkpoint candidate validation failed ({reason_code}): {exc}"
                ) from exc
            checkpoint = candidate.checkpoint
            if enrolled_mode == _ACCEPTANCE_MODE_QUALIFIED_SIGNED_V1:
                # ADR-0019 step 3: reauthenticate the checkpoint's claimed anchor statement,
                # references, and signed-package blobs from the record's retained sealed
                # bundles under the enrolled roots.  Unsigned or non-authenticating evidence
                # is refused here; the store never falls back to the modeled gate.  The
                # sealed bundles are non-serializable, so this fresh-insert path requires the
                # freshly submitted record to carry them; an idempotent retry of an already
                # retained candidate returns above without reaching this reauthentication.
                if record.anchor_bundle is None or record.time_bundle is None:
                    raise EventStoreError(
                        "a qualified checkpoint candidate requires its sealed qualified "
                        "anchor and time bundles for store-side reauthentication"
                    )
                _QUALIFIED_EVIDENCE_REFUSALS_V1 = _qualified_evidence_refusals()
                try:
                    self.verify_qualified_anchor_evidence(
                        anchor_bundle=record.anchor_bundle,
                        time_bundle=record.time_bundle,
                        claimed_anchor_statement_id=checkpoint.anchor_statement_id,
                        claimed_anchor_evidence=checkpoint.anchor_evidence,
                        claimed_evidence_blobs=candidate.provider_evidence,
                    )
                except _QUALIFIED_EVIDENCE_REFUSALS_V1 as exc:
                    raise EventStoreError(
                        "qualified checkpoint anchor evidence failed reauthentication "
                        f"({getattr(exc, 'reason_code', 'unknown')}): {exc}"
                    ) from exc
            attestation_id = signed_head_checkpoint_attestation_id(
                candidate.signed_checkpoint
            )
            self._require_writer_transaction()
            self._connection.execute(
                """
                INSERT INTO integrity_checkpoint_candidates (
                    event_digest,
                    record_id,
                    checkpoint_id,
                    checkpoint_attestation_id,
                    record
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    candidate.event_digest,
                    candidate.record_id,
                    checkpoint.checkpoint_id,
                    attestation_id,
                    sqlite3.Binary(candidate.to_canonical_bytes()),
                ),
            )
            self._retain_integrity_evidence_locked(
                event_digest=candidate.event_digest,
                phase="checkpoint_candidate",
                provider_evidence=candidate.provider_evidence,
            )
            retained = self._load_integrity_lineage_locked(
                candidate.event_digest
            )
            if retained is None or retained.checkpoint_candidate != candidate:
                raise EventStoreCorruptionError(
                    "retained checkpoint candidate did not replay exactly"
                )
            self._publish_owned_integrity_validation_cache_locked()
            self._require_writer_transaction()
            self._connection.execute("COMMIT")
            return retained.checkpoint_candidate
        except (
            EventStoreError,
            PendingIntegrityTransitionError,
            IntegrityTransitionConflictError,
        ):
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise
        except sqlite3.IntegrityError as exc:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise IntegrityTransitionConflictError(
                f"SQLite rejected checkpoint candidate retention: {exc}"
            ) from exc
        except sqlite3.DatabaseError as exc:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise _sqlite_store_failure(
                "checkpoint candidate retention failed",
                exc,
            ) from exc

    def finalize_integrity_transition(
        self,
        record: object,
    ) -> object:
        """Commit finality only after the monitor floor names the exact checkpoint."""

        from .integrity_transition import (
            FinalizedIntegrityTransitionV1,
            validate_finalization,
            validate_finalized_integrity_transition,
        )

        finalization = self._snapshot_integrity_record(
            record,
            FinalizedIntegrityTransitionV1,
        )
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            self._require_writer_transaction()
            self._validate_integrity_state_locked()
            unresolved = self._unresolved_integrity_digest_locked()
            lineage = self._load_integrity_lineage_locked(
                finalization.event_digest
            )
            if lineage is None or lineage.checkpoint_candidate is None:
                raise EventStoreError(
                    "integrity finalization requires one retained checkpoint candidate"
                )
            if lineage.finalization is not None:
                if lineage.finalization != finalization:
                    raise IntegrityTransitionConflictError(
                        "finalization identity was reused with different bytes"
                    )
                self._connection.execute("COMMIT")
                return lineage.finalization
            if unresolved != finalization.event_digest:
                raise PendingIntegrityTransitionError(
                    "finalization must close the singleton pending transition"
                )
            event = self._event_for_integrity_digest_locked(
                finalization.event_digest
            )
            previous_global, previous_mission = (
                self._previous_integrity_lineages_locked(
                    lineage.pending.mission_id
                )
            )
            try:
                validate_finalization(
                    event,
                    lineage,
                    finalization,
                    previous_global=previous_global,
                    previous_mission=previous_mission,
                )
            except (ProtocolError, TypeError, ValueError) as exc:
                reason_code = getattr(
                    exc,
                    "reason_code",
                    "invalid_integrity_finalization",
                )
                raise EventStoreError(
                    f"integrity finalization validation failed ({reason_code}): {exc}"
                ) from exc
            self._require_writer_transaction()
            self._connection.execute(
                """
                INSERT INTO integrity_finalizations (
                    event_digest,
                    record_id,
                    record
                ) VALUES (?, ?, ?)
                """,
                (
                    finalization.event_digest,
                    finalization.record_id,
                    sqlite3.Binary(finalization.to_canonical_bytes()),
                ),
            )
            self._retain_integrity_evidence_locked(
                event_digest=finalization.event_digest,
                phase="finalization",
                provider_evidence=finalization.provider_evidence,
            )
            retained = self._load_integrity_lineage_locked(
                finalization.event_digest
            )
            if retained is None or retained.finalization != finalization:
                raise EventStoreCorruptionError(
                    "retained integrity finalization did not replay exactly"
                )
            try:
                validate_finalized_integrity_transition(
                    retained,
                    event=event,
                    previous_global=previous_global,
                    previous_mission=previous_mission,
                )
            except (ProtocolError, TypeError, ValueError) as exc:
                reason_code = getattr(
                    exc,
                    "reason_code",
                    "invalid_retained_integrity_finalization",
                )
                raise EventStoreCorruptionError(
                    "retained integrity finalization failed authenticated replay "
                    f"({reason_code}): {exc}"
                ) from exc
            self._publish_owned_integrity_validation_cache_locked()
            self._require_writer_transaction()
            self._connection.execute("COMMIT")
            return retained.finalization
        except (
            EventStoreError,
            PendingIntegrityTransitionError,
            IntegrityTransitionConflictError,
        ):
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise
        except sqlite3.IntegrityError as exc:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise IntegrityTransitionConflictError(
                f"SQLite rejected integrity finalization: {exc}"
            ) from exc
        except sqlite3.DatabaseError as exc:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise _sqlite_store_failure(
                "integrity finalization failed",
                exc,
            ) from exc

    def store_checkpoint(self, checkpoint: SignedCheckpoint) -> SignedCheckpoint:
        """Retain opaque signed-head data without claiming that it has been verified."""

        if type(checkpoint) is not SignedCheckpoint:
            raise EventStoreError("store_checkpoint requires an exact SignedCheckpoint")
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            self._require_writer_transaction()
            self._validate_integrity_state_locked()
            if (
                self._store_profile_locked()[0]
                == _MODELED_INTEGRITY_STORE_PROFILE_V1
            ):
                raise IntegrityFinalityRequiredError(
                    "opaque legacy checkpoints are forbidden in the modeled integrity profile"
                )
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
            retained_row = self._connection.execute(
                """
                SELECT
                    mission_id,
                    event_digest,
                    signer_id,
                    algorithm,
                    signed_at,
                    signature
                FROM signed_checkpoints
                WHERE
                    mission_id = ?
                    AND event_digest = ?
                    AND signer_id = ?
                """,
                (
                    checkpoint.mission_id,
                    checkpoint.event_digest,
                    checkpoint.signer_id,
                ),
            ).fetchone()
            if retained_row is None or SignedCheckpoint(*retained_row) != checkpoint:
                raise EventStoreCorruptionError(
                    "stored checkpoint differs from its exact retained representation"
                )
            self._publish_owned_integrity_validation_cache_locked()
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
