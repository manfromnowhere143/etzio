"""Offline single-request custody experiment. No transport or dispatch authority.

See ADR-0023. Documentary scope/terms references are not admitted grants. SQLite
atomicity is assumed here; physical durability and cross-copy budgets are unqualified.
"""

from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from etzio.kernel.store import _sqlite_journal_policy
from etzio.protocol import ProtocolError, canonical_dumps, content_id, strict_loads

APP_ID = 0x45544131
MAX_RECORD = 8192
MAX_REQUEST = 16384
MAX_RESPONSE = 65536
_ID = re.compile(r"sha256:[0-9a-f]{64}")
_SHA = re.compile(r"[0-9a-f]{64}")
_INTENT = "etzio.acquisition-custody.intent.v1"
_OUTCOME = "etzio.acquisition-custody.outcome.v1"
_REASONS = frozenset({"transport_error", "timeout", "body_limit", "operator_stop"})
_DDL = (
    "CREATE TABLE intent (id INTEGER PRIMARY KEY CHECK(id=1), wire BLOB NOT NULL, request BLOB NOT NULL) STRICT",
    "CREATE TABLE debit (id INTEGER PRIMARY KEY CHECK(id=1) REFERENCES intent(id), binding TEXT NOT NULL) STRICT",
    "CREATE TABLE outcome (id INTEGER PRIMARY KEY CHECK(id=1) REFERENCES debit(id), "
    "wire BLOB NOT NULL, body BLOB NOT NULL) STRICT",
    *(
        f"CREATE TRIGGER {table}_once BEFORE INSERT ON {table} "
        f"WHEN EXISTS(SELECT 1 FROM {table}) BEGIN SELECT RAISE(ABORT, 'existing custody row'); END"
        for table in ("intent", "debit", "outcome")
    ),
    *(
        f"CREATE TRIGGER {table}_parent BEFORE INSERT ON {table} "
        f"WHEN NOT EXISTS(SELECT 1 FROM {parent} WHERE id=1) "
        "BEGIN SELECT RAISE(ABORT, 'missing custody parent'); END"
        for table, parent in [("debit", "intent"), ("outcome", "debit")]
    ),
    *(
        f"CREATE TRIGGER {table}_{action.lower()} BEFORE {action} ON {table} "
        "BEGIN SELECT RAISE(ABORT, 'immutable custody row'); END"
        for table in ("intent", "debit", "outcome")
        for action in ("UPDATE", "DELETE")
    ),
)
_FIELDS = frozenset(
    {
        "schema",
        "service_id",
        "endpoint",
        "scope_reference_id",
        "terms_reference_id",
        "request_sha256",
        "request_size",
        "response_limit_bytes",
    }
)


class CustodyError(ValueError):
    """Deterministic fixture-custody refusal; storage exceptions retain their type."""


def _require(condition: object, reason: str) -> None:
    if not condition:
        raise CustodyError(reason)


def _bytes(value, bound, reason, *, empty=False):
    _require(type(value) is bytes and (0 if empty else 1) <= len(value) <= bound, reason)


def _decode(wire, schema, fields):
    _bytes(wire, MAX_RECORD, "record_size")
    try:
        value = strict_loads(wire)
    except ProtocolError as error:
        raise CustodyError("record_encoding") from error
    _require(type(value) is dict and set(value) == fields, "record_shape")
    _require(value["schema"] == schema and canonical_dumps(value) == wire, "record_encoding")
    return value


def _intent(wire):
    value = _decode(wire, _INTENT, _FIELDS)
    for key in ("scope_reference_id", "terms_reference_id"):
        item = value[key]
        _require(type(item) is str and _ID.fullmatch(item) is not None, "reference_identity")
    service = value["service_id"]
    _require(
        type(service) is str and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]{1,127}", service) is not None, "service_id"
    )
    endpoint = value["endpoint"]
    _require(type(endpoint) is str and 1 <= len(endpoint) <= 512 and endpoint.isascii(), "endpoint")
    _require(not any(ord(c) <= 32 or ord(c) == 127 for c in endpoint), "endpoint")
    try:
        parsed = urlsplit(endpoint)
        port = parsed.port
    except ValueError as error:
        raise CustodyError("endpoint") from error
    _require(
        parsed.scheme in ("http", "https")
        and parsed.netloc
        and parsed.hostname
        and parsed.username is None
        and parsed.password is None
        and not parsed.query
        and not parsed.fragment,
        "endpoint",
    )
    # This verifies documentary shape, not endpoint ownership, DNS or egress authority.
    _require(port is None or 1 <= port <= 65535, "endpoint")
    digest = value["request_sha256"]
    _require(type(digest) is str and _SHA.fullmatch(digest) is not None, "request_digest")
    _require(type(value["request_size"]) is int and 1 <= value["request_size"] <= MAX_REQUEST, "request_size")
    _require(
        type(value["response_limit_bytes"]) is int and 1 <= value["response_limit_bytes"] <= MAX_RESPONSE,
        "response_limit",
    )
    return value


def intent_wire(
    *,
    service_id: str,
    endpoint: str,
    scope_reference_id: str,
    terms_reference_id: str,
    request: bytes,
    response_limit_bytes: int = MAX_RESPONSE,
) -> bytes:
    """Construct a documentary intent; this function grants no permission."""
    _bytes(request, MAX_REQUEST, "request_size")
    value = {
        "schema": _INTENT,
        "service_id": service_id,
        "endpoint": endpoint,
        "scope_reference_id": scope_reference_id,
        "terms_reference_id": terms_reference_id,
        "request_sha256": hashlib.sha256(request).hexdigest(),
        "request_size": len(request),
        "response_limit_bytes": response_limit_bytes,
    }
    wire = canonical_dumps(value)
    _intent(wire)
    return wire


def _intent_id(value):
    return content_id("acquisition_custody_intent_v1", value)


def _attempt_id(value):
    return content_id("acquisition_custody_attempt_v1", {"intent_id": _intent_id(value), "ordinal": 1})


def _commit(connection: sqlite3.Connection) -> None:
    connection.execute("COMMIT")


def _schema(connection):
    return tuple(
        connection.execute(f"SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name LIMIT {len(_DDL) + 1}")
    )


def _expected_schema():
    connection = sqlite3.connect(":memory:")
    try:
        for statement in _DDL:
            connection.execute(statement)
        return _schema(connection)
    finally:
        connection.close()


_EXPECTED_SCHEMA = _expected_schema()


@dataclass(frozen=True, slots=True)
class CustodySnapshot:
    status: str
    intent_id: str
    intent_wire: bytes
    request_wire: bytes
    attempt_id: str | None
    outcome_wire: bytes | None
    response_wire: bytes | None


def _read(connection: sqlite3.Connection) -> CustodySnapshot:
    _require(connection.execute("PRAGMA application_id").fetchone() == (APP_ID,), "application_id")
    _require(connection.execute("PRAGMA user_version").fetchone() == (1,), "schema_version")
    _require(_schema(connection) == _EXPECTED_SCHEMA, "schema_shape")
    # Bound stored values before fetching BLOBs from the untrusted journal.
    rows = connection.execute("SELECT id,length(wire),length(request) FROM intent LIMIT 2").fetchall()
    _require(len(rows) == 1, "intent_roster")
    _require(rows[0][0] == 1 and 0 < rows[0][1] <= MAX_RECORD and 0 < rows[0][2] <= MAX_REQUEST, "stored_intent_size")
    wire, request = connection.execute("SELECT wire,request FROM intent WHERE id=1").fetchone()
    value = _intent(wire)
    _bytes(request, MAX_REQUEST, "stored_request_size")
    _require(
        len(request) == value["request_size"] and hashlib.sha256(request).hexdigest() == value["request_sha256"],
        "request_binding",
    )
    debits = connection.execute("SELECT id,length(binding) FROM debit LIMIT 2").fetchall()
    _require(len(debits) <= 1 and (not debits or debits[0] == (1, 71)), "debit_roster")
    attempt = connection.execute("SELECT binding FROM debit WHERE id=1").fetchone()
    _require(attempt is None or attempt == (_attempt_id(value),), "attempt_binding")
    outcomes = connection.execute("SELECT id,length(wire),length(body) FROM outcome LIMIT 2").fetchall()
    _require(len(outcomes) <= 1, "outcome_roster")
    terminal = body = None
    status = "prepared" if attempt is None else "attempt_indeterminate"
    if outcomes:
        row = outcomes[0]
        _require(attempt is not None and row[0] == 1, "outcome_without_attempt")
        _require(0 < row[1] <= MAX_RECORD and 0 <= row[2] <= value["response_limit_bytes"], "stored_outcome_size")
        terminal, body = connection.execute("SELECT wire,body FROM outcome WHERE id=1").fetchone()
        result = _decode(
            terminal, _OUTCOME, {"schema", "intent_id", "attempt_id", "kind", "reason", "body_size", "body_sha256"}
        )
        _require(result["intent_id"] == _intent_id(value) and result["attempt_id"] == attempt[0], "outcome_binding")
        _bytes(body, value["response_limit_bytes"], "stored_body", empty=True)
        _require(
            type(result["body_size"]) is int
            and result["body_size"] == len(body)
            and result["body_sha256"] == hashlib.sha256(body).hexdigest(),
            "body_binding",
        )
        if result["kind"] == "response_captured":
            _require(result["reason"] == "opaque_response" and len(body) > 0, "capture_shape")
        else:
            _require(
                result["kind"] == "capture_indeterminate"
                and type(result["reason"]) is str
                and result["reason"] in _REASONS
                and body == b"",
                "capture_shape",
            )
        status = result["kind"]
    return CustodySnapshot(status, _intent_id(value), wire, request, attempt[0] if attempt else None, terminal, body)


class AcquisitionJournal:
    """One fixture experiment per journal. A debit never authorizes external use."""

    def __init__(self, path: str | Path):
        self.path = Path(path).absolute()

    @classmethod
    def create(cls, path: str | Path, wire: bytes, request: bytes) -> AcquisitionJournal:
        value = _intent(wire)
        _bytes(request, MAX_REQUEST, "request_size")
        _require(
            len(request) == value["request_size"] and hashlib.sha256(request).hexdigest() == value["request_sha256"],
            "request_binding",
        )
        journal = cls(path)
        # Existing and interrupted files are never silently adopted or recreated.
        descriptor = os.open(journal.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        with journal._transaction(initializing=True) as connection:
            connection.execute(f"PRAGMA application_id={APP_ID}")
            connection.execute("PRAGMA user_version=1")
            for statement in _DDL:
                connection.execute(statement)
            connection.execute("INSERT INTO intent VALUES(1,?,?)", (wire, request))
            _read(connection)
        return journal

    @contextmanager
    def _transaction(self, *, initializing=False, write=True):
        _sqlite_journal_policy(sqlite3.sqlite_version_info)
        # Refuse persistent WAL before SQLite can open/recover it on affected runtimes.
        descriptor = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(descriptor)
            _require(
                stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_mode & 0o077 == 0,
                "private_regular_file",
            )
            header = os.read(descriptor, 20)
            _require(2 not in header[18:20], "persistent_wal")
            _require(
                (initializing and info.st_size == 0)
                or (header[:16] == b"SQLite format 3\x00" and header[18:20] == b"\x01\x01"),
                "database_header",
            )
        finally:
            os.close(descriptor)
        connection = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, isolation_level=None, timeout=0)
        try:
            _require(connection.execute("PRAGMA journal_mode").fetchone() == ("delete",), "journal_mode")
            connection.execute("PRAGMA synchronous=EXTRA")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA ignore_check_constraints=OFF")
            connection.execute("PRAGMA read_uncommitted=OFF")
            connection.execute("PRAGMA writable_schema=OFF")
            _require(
                all(
                    connection.execute("PRAGMA " + key).fetchone() == (expected,)
                    for key, expected in [
                        ("synchronous", 3),
                        ("foreign_keys", 1),
                        ("trusted_schema", 0),
                        ("ignore_check_constraints", 0),
                        ("read_uncommitted", 0),
                        ("writable_schema", 0),
                    ]
                ),
                "connection_settings",
            )
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            if not initializing:
                _read(connection)
            yield connection
            _commit(connection)
        finally:
            connection.close()

    def inspect(self) -> CustodySnapshot:
        with self._transaction(write=False) as connection:
            return _read(connection)

    def debit(self) -> str:
        with self._transaction() as connection:
            state = _read(connection)
            _require(state.status == "prepared", "attempt_already_spent")
            attempt = _attempt_id(_intent(state.intent_wire))
            connection.execute("INSERT INTO debit VALUES(1,?)", (attempt,))
        # Return only after the context manager's COMMIT has acknowledged success.
        return attempt

    def retain_response(self, response: bytes) -> CustodySnapshot:
        return self._retain("response_captured", "opaque_response", response)

    def retain_indeterminate(self, reason: str) -> CustodySnapshot:
        _require(type(reason) is str and reason in _REASONS, "indeterminate_reason")
        return self._retain("capture_indeterminate", reason, b"")

    def _retain(self, kind: str, reason: str, body: bytes) -> CustodySnapshot:
        with self._transaction() as connection:
            state = _read(connection)
            _require(state.attempt_id is not None, "attempt_missing")
            value = _intent(state.intent_wire)
            _bytes(body, value["response_limit_bytes"], "response_size", empty=kind == "capture_indeterminate")
            wire = canonical_dumps(
                {
                    "schema": _OUTCOME,
                    "intent_id": state.intent_id,
                    "attempt_id": state.attempt_id,
                    "kind": kind,
                    "reason": reason,
                    "body_size": len(body),
                    "body_sha256": hashlib.sha256(body).hexdigest(),
                }
            )
            if state.outcome_wire is None:
                connection.execute("INSERT INTO outcome VALUES(1,?,?)", (wire, body))
            else:
                _require(state.outcome_wire == wire and state.response_wire == body, "conflicting_capture")
            result = _read(connection)
        return result
