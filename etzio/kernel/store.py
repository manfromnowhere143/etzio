"""Durable append-only SQLite storage for canonical Etzio mission events."""

from __future__ import annotations

import os
import re
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Final

from ..protocol import ProtocolError
from .events_v1 import GENESIS_DIGEST, EventIntegrityError, EventV1

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
        or any(
            type(component) is not int or component < 0
            for component in version_info
        )
    ):
        raise EventStoreError("SQLite exposed an invalid version tuple")
    if version_info[0] != 3 or version_info < (3, 37, 0):
        raise EventStoreError("SQLite exposed an unsupported library version")
    return (
        version_info >= (3, 51, 3)
        or (3, 50, 7) <= version_info < (3, 51, 0)
        or (3, 44, 6) <= version_info < (3, 45, 0)
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


class StaleHeadError(EventStoreError):
    """Raised when compare-and-append observes a different mission head."""


class ClosedStreamError(EventStoreError):
    """Raised when an append targets a terminal mission stream."""


def _sqlite_store_failure(
    context: str,
    error: sqlite3.DatabaseError,
) -> EventStoreError:
    error_code = getattr(error, "sqlite_errorcode", None)
    if type(error_code) is int and (error_code & 0xFF) in {
        sqlite3.SQLITE_BUSY,
        sqlite3.SQLITE_LOCKED,
    }:
        return StoreBusyError(f"{context}: SQLite storage is busy")
    return EventStoreCorruptionError(f"{context}: {error}")


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
        if (
            type(self.mission_id) is not str
            or _DIGEST_RE.fullmatch(self.mission_id) is None
        ):
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

    def __init__(self, path: str | os.PathLike[str]) -> None:
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
            initial_journal_mode = self._connection.execute(
                "PRAGMA journal_mode"
            ).fetchone()
            if (
                initial_journal_mode is None
                or str(initial_journal_mode[0]).lower() != "delete"
            ):
                raise EventStoreError(
                    "Etzio state must be in rollback-journal DELETE mode before use"
                )
            journal_mode = self._connection.execute(
                "PRAGMA journal_mode = DELETE"
            ).fetchone()
            if (
                journal_mode is None
                or str(journal_mode[0]).lower()
                != self._journal_policy.journal_mode
            ):
                raise EventStoreError(
                    "SQLite refused the required safe journal mode"
                )
            self._connection.execute("PRAGMA synchronous = EXTRA")
            self._connection.execute("PRAGMA foreign_keys = ON")
            if self._connection.execute("PRAGMA foreign_keys").fetchone() != (1,):
                raise EventStoreError("SQLite foreign-key enforcement is unavailable")
            if self._connection.execute("PRAGMA synchronous").fetchone() != (
                self._journal_policy.synchronous_value,
            ):
                raise EventStoreError(
                    "SQLite refused the required safe synchronous mode"
                )
            if str(journal_mode[0]).lower() == "wal":
                raise EventStoreError(
                    "Etzio does not admit WAL under the declared runtime matrix"
                )
            self._create_schema()
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
            raise EventStoreError(
                f"cannot inspect event-store journal header: {exc}"
            ) from exc
        if len(header) != _SQLITE_HEADER_SIZE:
            raise EventStoreCorruptionError(
                "existing event store has a truncated SQLite header"
            )
        if header[: len(_SQLITE_HEADER_MAGIC)] != _SQLITE_HEADER_MAGIC:
            raise EventStoreCorruptionError(
                "existing event store has an invalid SQLite header"
            )
        journal_versions = header[18:20]
        if 2 in journal_versions:
            raise EventStoreError(
                "preexisting WAL state requires an explicit offline migration"
            )
        if journal_versions != b"\x01\x01":
            raise EventStoreCorruptionError(
                "existing event store has invalid journal-format bytes"
            )

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
                raise EventStoreError(
                    "event store must have exactly one filesystem link"
                )
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
                raise EventStoreError(
                    "database parent directory must already exist"
                ) from exc
            except OSError as exc:
                raise EventStoreError(
                    f"cannot inspect database directory chain: {exc}"
                ) from exc
            if stat.S_ISLNK(metadata.st_mode):
                raise EventStoreError(
                    "database directory chain must not contain symbolic links"
                )
            if not stat.S_ISDIR(metadata.st_mode):
                raise EventStoreError(
                    "database parent chain must contain only directories"
                )

            permissions = stat.S_IMODE(metadata.st_mode)
            trusted_sticky_root = cls._is_trusted_sticky_root(
                directory_uid=metadata.st_uid,
                directory_mode=metadata.st_mode,
                effective_uid=effective_uid,
            )
            if immediate:
                if effective_uid is not None and metadata.st_uid != effective_uid:
                    raise EventStoreError(
                        "database parent directory must be owned by the current service user"
                    )
                if permissions != 0o700:
                    raise EventStoreError(
                        "database parent directory must have mode 0700"
                    )
            if permissions & 0o022 and not trusted_sticky_root:
                raise EventStoreError(
                    "database directory chain must not be group/world writable"
                )

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
            raise EventStoreError(
                f"event-store identity could not be verified: {exc}"
            ) from exc

        expected = (prepared.device, prepared.inode)
        if (
            (descriptor_metadata.st_dev, descriptor_metadata.st_ino) != expected
            or (path_metadata.st_dev, path_metadata.st_ino) != expected
            or (sqlite_metadata.st_dev, sqlite_metadata.st_ino) != expected
        ):
            raise EventStoreError("event-store path identity changed during SQLite open")
        if not stat.S_ISREG(path_metadata.st_mode):
            raise EventStoreError("event store path must remain a regular file")
        if (
            descriptor_metadata.st_nlink != 1
            or path_metadata.st_nlink != 1
            or sqlite_metadata.st_nlink != 1
        ):
            raise EventStoreError(
                "event store must retain exactly one filesystem link"
            )
        if stat.S_IMODE(path_metadata.st_mode) != 0o600:
            raise EventStoreError("event store file must have mode 0600")
        if hasattr(os, "geteuid") and path_metadata.st_uid != os.geteuid():
            raise EventStoreError("event store must remain owned by the service user")

    def _create_schema(self) -> None:
        genesis = GENESIS_DIGEST.replace("'", "''")
        terminal_sql = ", ".join(f"'{kind}'" for kind in sorted(TERMINAL_KINDS))
        self._connection.executescript(
            f"""
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

    def diagnostics(self) -> StoreDiagnostics:
        """Return fixed diagnostics without exposing a writable SQL connection."""

        try:
            journal = self._connection.execute("PRAGMA journal_mode").fetchone()
            synchronous = self._connection.execute("PRAGMA synchronous").fetchone()
            foreign_keys = self._connection.execute("PRAGMA foreign_keys").fetchone()
            mode = stat.S_IMODE(os.lstat(self.path).st_mode)
        except sqlite3.DatabaseError as exc:
            raise _sqlite_store_failure(
                "could not read store diagnostics",
                exc,
            ) from exc
        except OSError as exc:
            raise EventStoreCorruptionError(
                f"could not read store diagnostics: {exc}"
            ) from exc
        if journal is None or synchronous is None or foreign_keys is None:
            raise EventStoreCorruptionError("SQLite returned incomplete diagnostics")
        journal_value = str(journal[0]).lower()
        synchronous_value = int(synchronous[0])
        if (
            journal_value != self._journal_policy.journal_mode
            or synchronous_value
            != self._journal_policy.synchronous_value
            or journal_value == "wal"
        ):
            raise EventStoreCorruptionError(
                "SQLite security settings differ from the admitted journal policy"
            )
        return StoreDiagnostics(
            sqlite_version=sqlite3.sqlite_version,
            wal_reset_bug_fixed=(
                self._journal_policy.wal_reset_bug_fixed
            ),
            journal_mode=journal_value,
            synchronous=synchronous_value,
            foreign_keys=bool(foreign_keys[0]),
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

    def _rows(self, mission_id: str) -> list[tuple[int, str, str, str, bytes]]:
        if (
            type(mission_id) is not str
            or _DIGEST_RE.fullmatch(mission_id) is None
        ):
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
        return events

    @staticmethod
    def _validate_retained_lifecycle(events: tuple[EventV1, ...]) -> None:
        # Local import keeps the persistence and projection modules independently
        # importable while still making lifecycle validation mandatory at the boundary.
        from .reducer import ReductionError, reduce_events

        try:
            reduce_events(events)
        except ReductionError as exc:
            raise EventStoreCorruptionError(
                f"retained mission lifecycle is invalid: {exc}"
            ) from exc

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
        if not isinstance(event, EventV1):
            raise EventStoreError("append requires EventV1")
        if (
            not isinstance(expected_head, str)
            or _DIGEST_RE.fullmatch(expected_head) is None
        ):
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
        actual_head = events[-1].event_digest if events else GENESIS_DIGEST
        if expected_head != actual_head:
            raise StaleHeadError(
                f"stale mission head: expected {expected_head}, retained {actual_head}"
            )
        if events and events[-1].kind in TERMINAL_KINDS:
            raise ClosedStreamError(f"mission ended with {events[-1].kind}")
        expected_seq = len(events)
        if event.seq != expected_seq:
            raise EventStoreError(
                f"event sequence gap or fork: expected {expected_seq}, got {event.seq}"
            )
        if event.prev_digest != actual_head:
            raise StaleHeadError(
                f"event predecessor {event.prev_digest} does not match head {actual_head}"
            )
        self._validate_proposed_lifecycle((*events, event))
        return events

    def _insert_event_locked(self, event: EventV1) -> None:
        canonical = event.to_canonical_bytes()
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
        receipt_evidence_store: object | None = None,
    ) -> EventV1:
        is_receipt_admission = event.kind == "verifier_receipt_admitted"
        has_receipt_evidence_store = receipt_evidence_store is not None
        if is_receipt_admission != has_receipt_evidence_store:
            raise EventStoreError(
                "receipt-admission events and current-CAS validation must be paired"
            )
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            events = self._prepare_append_locked(
                event,
                expected_head=expected_head,
            )
            if receipt_evidence_store is not None:
                from .receipt_admission import (
                    validate_retained_receipt_admission_event,
                )

                try:
                    validate_retained_receipt_admission_event(
                        retained=events,
                        event=event,
                        evidence_store=receipt_evidence_store,
                    )
                except (ProtocolError, KeyError, TypeError, ValueError) as exc:
                    reason_code = getattr(
                        exc,
                        "reason_code",
                        "invalid_receipt_admission",
                    )
                    raise EventStoreError(
                        "receipt admission current-CAS validation failed "
                        f"({reason_code}): {exc}"
                    ) from exc
            self._insert_event_locked(event)
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

        Receipt admissions are reserved because their current CAS validation must execute
        under the same writer transaction as the canonical event insertion.
        """

        self._validate_append_request(event, expected_head)
        if event.kind == "verifier_receipt_admitted":
            raise EventStoreError(
                "verifier_receipt_admitted requires append_receipt_admission"
            )
        return self._append_verified_event(
            event,
            expected_head=expected_head,
        )

    def append_receipt_admission(
        self,
        event: EventV1,
        *,
        expected_head: str,
        evidence_store: object,
    ) -> EventV1:
        """Atomically validate current CAS and retain one receipt admission."""

        from ..evidence import FileEvidenceStore

        self._validate_append_request(event, expected_head)
        if event.kind != "verifier_receipt_admitted":
            raise EventStoreError(
                "append_receipt_admission requires verifier_receipt_admitted"
            )
        if not isinstance(evidence_store, FileEvidenceStore):
            raise EventStoreError(
                "append_receipt_admission requires a FileEvidenceStore"
            )
        return self._append_verified_event(
            event,
            expected_head=expected_head,
            receipt_evidence_store=evidence_store,
        )

    def store_checkpoint(self, checkpoint: SignedCheckpoint) -> SignedCheckpoint:
        """Retain opaque signed-head data without claiming that it has been verified."""

        if not isinstance(checkpoint, SignedCheckpoint):
            raise EventStoreError("store_checkpoint requires SignedCheckpoint")
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            events = self._decode_rows(
                checkpoint.mission_id,
                self._rows(checkpoint.mission_id),
            )
            if events:
                self._validate_retained_lifecycle(events)
            row = self._connection.execute(
                """
                SELECT 1 FROM events
                WHERE mission_id = ? AND digest = ?
                """,
                (checkpoint.mission_id, checkpoint.event_digest),
            ).fetchone()
            if row is None:
                raise EventStoreError("checkpoint must reference a retained mission event")
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

        if (
            type(mission_id) is not str
            or _DIGEST_RE.fullmatch(mission_id) is None
        ):
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
