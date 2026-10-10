"""Offline custody controls: replay, row corruption, contention and real process death."""

from __future__ import annotations

import hashlib
import os
import signal
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from threading import Barrier

import pytest

from etzio.protocol import canonical_dumps, strict_loads
from etzio.qualification import acquisition_custody_v1 as custody

REQUEST = b"repository-owned request fixture; no network operation"
RESPONSE = b"opaque repository-owned response fixture"
REFERENCE = "sha256:" + "a" * 64


def _wire(**changes):
    value = dict(
        service_id="fixture.tsa",
        endpoint="https://fixture.invalid/timestamp",
        scope_reference_id=REFERENCE,
        terms_reference_id="sha256:" + "b" * 64,
        request=REQUEST,
        response_limit_bytes=1024,
    )
    value.update(changes)
    return custody.intent_wire(**value)


def _journal(tmp_path):
    return custody.AcquisitionJournal.create(tmp_path / "custody.sqlite3", _wire(), REQUEST)


def _sql(path, sql, parameters=()):
    with closing(sqlite3.connect(path)) as connection:
        connection.execute(sql, parameters)
        connection.commit()


def _tamper(journal, table, sql, parameters=()):
    """Model raw stored corruption while restoring the exact expected schema."""
    with closing(sqlite3.connect(journal.path)) as connection:
        guards = [s for s in custody._DDL if s.startswith("CREATE TRIGGER " + table + "_")]
        for guard in guards:
            connection.execute("DROP TRIGGER " + guard.split()[2])
        connection.execute(sql, parameters)
        for guard in guards:
            connection.execute(guard)
        connection.commit()


def _child(journal, code):
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(Path(custody.__file__).resolve().parents[2])
    return subprocess.run(
        [sys.executable, "-c", code, str(journal.path)],
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )


def test_exact_bytes_cold_replay_and_terminal_retention(tmp_path):
    journal = _journal(tmp_path)
    prepared = journal.inspect()
    assert prepared.status == "prepared" and prepared.attempt_id is None
    assert prepared.intent_wire == _wire() and prepared.request_wire == REQUEST
    assert prepared.outcome_wire is None and prepared.response_wire is None
    assert journal.path.stat().st_mode & 0o777 == 0o600
    attempt = journal.debit()
    pending = custody.AcquisitionJournal(journal.path).inspect()
    assert pending.status == "attempt_indeterminate" and pending.attempt_id == attempt
    captured = journal.retain_response(RESPONSE)
    assert captured.status == "response_captured" and captured.response_wire == RESPONSE
    assert strict_loads(captured.outcome_wire)["body_sha256"] == hashlib.sha256(RESPONSE).hexdigest()
    assert journal.retain_response(RESPONSE) == captured
    child = _child(
        journal,
        """
import sys
from etzio.qualification.acquisition_custody_v1 import AcquisitionJournal, CustodyError
journal = AcquisitionJournal(sys.argv[1])
state = journal.inspect()
print(state.status, state.request_wire.hex(), state.response_wire.hex())
try:
    journal.debit()
except CustodyError as error:
    print(str(error))
else:
    raise AssertionError('a cold process got another debit')
""",
    )
    assert child.returncode == 0, child.stderr
    assert child.stdout.splitlines() == [f"response_captured {REQUEST.hex()} {RESPONSE.hex()}", "attempt_already_spent"]


@pytest.mark.parametrize("reason", ["transport_error", "timeout", "body_limit", "operator_stop"])
def test_indeterminate_capture_preserves_spent_attempt(tmp_path, reason):
    journal = _journal(tmp_path)
    journal.debit()
    state = journal.retain_indeterminate(reason)
    assert state.status == "capture_indeterminate" and state.response_wire == b""
    assert strict_loads(state.outcome_wire)["reason"] == reason
    assert journal.retain_indeterminate(reason) == state
    with pytest.raises(custody.CustodyError, match="attempt_already_spent"):
        journal.debit()
    with pytest.raises(custody.CustodyError, match="conflicting_capture"):
        journal.retain_response(RESPONSE)


@pytest.mark.parametrize("terminal", [False, True])
def test_second_debit_never_reissued(tmp_path, terminal):
    journal = _journal(tmp_path)
    journal.debit()
    if terminal:
        journal.retain_response(RESPONSE)
    with pytest.raises(custody.CustodyError, match="attempt_already_spent"):
        journal.debit()


@pytest.mark.parametrize("payload", [b"", b"x" * 1025, bytearray(b"x"), "response", None])
def test_invalid_response_cannot_reset_attempt(tmp_path, payload):
    journal = _journal(tmp_path)
    journal.debit()
    with pytest.raises(custody.CustodyError, match="response_size"):
        journal.retain_response(payload)
    assert journal.inspect().status == "attempt_indeterminate"
    with pytest.raises(custody.CustodyError, match="attempt_already_spent"):
        journal.debit()


@pytest.mark.parametrize("reason", ["retry", "", None, [], 1])
def test_invalid_indeterminate_reason(tmp_path, reason):
    journal = _journal(tmp_path)
    journal.debit()
    with pytest.raises(custody.CustodyError, match="indeterminate_reason"):
        journal.retain_indeterminate(reason)
    assert journal.inspect().status == "attempt_indeterminate"


@pytest.mark.parametrize("capture", ["response", "indeterminate"])
def test_capture_needs_committed_attempt(tmp_path, capture):
    journal = _journal(tmp_path)
    with pytest.raises(custody.CustodyError, match="attempt_missing"):
        if capture == "response":
            journal.retain_response(RESPONSE)
        else:
            journal.retain_indeterminate("timeout")
    assert journal.inspect().status == "prepared"


@pytest.mark.parametrize("change", ["body", "kind", "reason"])
def test_conflicting_terminal_retention_refuses(tmp_path, change):
    journal = _journal(tmp_path)
    journal.debit()
    if change == "reason":
        original = journal.retain_indeterminate("timeout")
    else:
        original = journal.retain_response(RESPONSE)
    with pytest.raises(custody.CustodyError, match="conflicting_capture"):
        if change == "body":
            journal.retain_response(RESPONSE + b"changed")
        else:
            journal.retain_indeterminate("operator_stop")
    assert journal.inspect() == original


@pytest.mark.parametrize(
    "key,value,reason",
    [
        ("service_id", "!invalid", "service_id"),
        ("service_id", None, "service_id"),
        ("scope_reference_id", "sha256:" + "A" * 64, "reference_identity"),
        ("terms_reference_id", 12, "reference_identity"),
        ("response_limit_bytes", True, "response_limit"),
        ("response_limit_bytes", 0, "response_limit"),
        ("response_limit_bytes", 65537, "response_limit"),
        ("request_size", True, "request_size"),
        ("request_size", 16385, "request_size"),
        ("request_sha256", "0" * 63, "request_digest"),
        ("schema", "foreign", "record_encoding"),
    ],
)
def test_intent_closed_types_and_limits(tmp_path, key, value, reason):
    parsed = strict_loads(_wire())
    parsed[key] = value
    with pytest.raises(custody.CustodyError, match=reason):
        custody.AcquisitionJournal.create(tmp_path / "bad.sqlite3", canonical_dumps(parsed), REQUEST)
    assert not (tmp_path / "bad.sqlite3").exists()


@pytest.mark.parametrize(
    "endpoint",
    [
        "ftp://fixture.invalid",
        "https://user@fixture.invalid",
        "https://@fixture.invalid",
        "https://fixture.invalid/?secret=x",
        "https://fixture.invalid/#fragment",
        "https:///missing",
        "https://fixture.invalid:99999",
        "https://fixture.invalid:abc",
        "https://[bad",
        "https://fixture.invalid/\npath",
        "https://fixture.invalid/é",
        "https://" + "a" * 512,
    ],
)
def test_documentary_endpoint_shape(endpoint):
    with pytest.raises(custody.CustodyError, match="endpoint"):
        _wire(endpoint=endpoint)


@pytest.mark.parametrize("mutation", ["missing", "extra", "spacing", "duplicate", "array", "oversize"])
def test_noncanonical_or_open_intent_refuses(tmp_path, mutation):
    parsed = strict_loads(_wire())
    if mutation == "missing":
        del parsed["scope_reference_id"]
        wire = canonical_dumps(parsed)
    elif mutation == "extra":
        wire = canonical_dumps({**parsed, "authority": True})
    elif mutation == "spacing":
        wire = b" " + _wire()
    elif mutation == "duplicate":
        wire = _wire()[:-1] + b',"service_id":"duplicate"}'
    elif mutation == "array":
        wire = b"[]"
    else:
        wire = b" " * 8193
    with pytest.raises(custody.CustodyError):
        custody.AcquisitionJournal.create(tmp_path / "bad.sqlite3", wire, REQUEST)
    assert not (tmp_path / "bad.sqlite3").exists()


@pytest.mark.parametrize("request_bytes", [b"", b"x" * 16385, bytearray(REQUEST), None, REQUEST + b"x"])
def test_request_binding_precedes_file_creation(tmp_path, request_bytes):
    with pytest.raises(custody.CustodyError):
        custody.AcquisitionJournal.create(tmp_path / "bad.sqlite3", _wire(), request_bytes)
    assert not (tmp_path / "bad.sqlite3").exists()


@pytest.mark.parametrize("table", ["intent", "debit", "outcome"])
@pytest.mark.parametrize("operation", ["update", "delete", "replace"])
def test_raw_append_only_guards_even_with_foreign_keys_and_recursive_triggers_off(tmp_path, table, operation):
    journal = _journal(tmp_path)
    journal.debit()
    original = journal.retain_response(RESPONSE)
    statements = {
        "update": f"UPDATE {table} SET id=id",
        "delete": f"DELETE FROM {table}",
        "replace": f"INSERT OR REPLACE INTO {table} SELECT * FROM {table}",
    }
    with closing(sqlite3.connect(journal.path)) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute("PRAGMA recursive_triggers=OFF")
        with pytest.raises(sqlite3.IntegrityError, match="custody row"):
            connection.execute(statements[operation])
    assert journal.inspect() == original


@pytest.mark.parametrize("table", ["debit", "outcome"])
def test_raw_missing_parent_refuses_without_foreign_keys(tmp_path, table):
    journal = _journal(tmp_path)
    if table == "debit":
        _tamper(journal, "intent", "DELETE FROM intent")
        statement, params = "INSERT INTO debit VALUES(1,?)", ("sha256:" + "c" * 64,)
    else:
        statement, params = "INSERT INTO outcome VALUES(1,?,?)", (b"{}", b"")
    with closing(sqlite3.connect(journal.path)) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        with pytest.raises(sqlite3.IntegrityError, match="missing custody parent"):
            connection.execute(statement, params)


@pytest.mark.parametrize(
    "statement,reason",
    [
        ("PRAGMA application_id=0", "application_id"),
        ("PRAGMA user_version=2", "schema_version"),
        ("CREATE TABLE sqliteXhidden(x)", "schema_shape"),
        ("DROP TRIGGER debit_once", "schema_shape"),
    ],
)
def test_schema_identity_and_complete_roster(tmp_path, statement, reason):
    journal = _journal(tmp_path)
    _sql(journal.path, statement)
    with pytest.raises(custody.CustodyError, match=reason):
        journal.inspect()
    with pytest.raises(custody.CustodyError, match=reason):
        journal.debit()


@pytest.mark.parametrize("field", ["request", "intent", "debit", "body", "outcome", "missing"])
def test_fresh_reconstruction_detects_changed_retained_bytes(tmp_path, field):
    journal = _journal(tmp_path)
    journal.debit()
    original = journal.retain_response(RESPONSE)
    if field == "request":
        _tamper(journal, "intent", "UPDATE intent SET request=?", (b"z" * len(REQUEST),))
    elif field == "intent":
        value = strict_loads(original.intent_wire)
        value["scope_reference_id"] = "sha256:" + "c" * 64
        _tamper(journal, "intent", "UPDATE intent SET wire=?", (canonical_dumps(value),))
    elif field == "debit":
        _tamper(journal, "debit", "UPDATE debit SET binding=?", ("sha256:" + "c" * 64,))
    elif field == "body":
        _tamper(journal, "outcome", "UPDATE outcome SET body=?", (b"z" * len(RESPONSE),))
    elif field == "outcome":
        value = strict_loads(original.outcome_wire)
        value["intent_id"] = "sha256:" + "c" * 64
        _tamper(journal, "outcome", "UPDATE outcome SET wire=?", (canonical_dumps(value),))
    else:
        _tamper(journal, "intent", "DELETE FROM intent")
    with pytest.raises(custody.CustodyError):
        journal.inspect()
    with pytest.raises(custody.CustodyError):
        journal.retain_response(RESPONSE)


@pytest.mark.parametrize(
    "key,value",
    [
        ("body_size", True),
        ("body_sha256", "0" * 64),
        ("kind", "accepted_provider"),
        ("reason", "validated"),
        ("schema", "foreign"),
        ("new_authority", True),
    ],
)
def test_stored_outcome_is_closed_and_semantic(tmp_path, key, value):
    journal = _journal(tmp_path)
    journal.debit()
    outcome = strict_loads(journal.retain_response(RESPONSE).outcome_wire)
    outcome[key] = value
    _tamper(journal, "outcome", "UPDATE outcome SET wire=?", (canonical_dumps(outcome),))
    with pytest.raises(custody.CustodyError):
        journal.inspect()


@pytest.mark.parametrize(
    "table,column,size",
    [
        ("intent", "wire", 8193),
        ("intent", "request", 16385),
        ("outcome", "wire", 8193),
        ("outcome", "body", 1025),
    ],
)
def test_stored_size_refuses_before_fetching_blob(tmp_path, monkeypatch, table, column, size):
    journal = _journal(tmp_path)
    journal.debit()
    journal.retain_response(RESPONSE)
    _tamper(journal, table, f"UPDATE {table} SET {column}=zeroblob(?)", (size,))
    real_connect = sqlite3.connect
    queries = []

    def connect(*args, **kwargs):
        connection = real_connect(*args, **kwargs)
        connection.set_trace_callback(queries.append)
        return connection

    monkeypatch.setattr(custody.sqlite3, "connect", connect)
    with pytest.raises(custody.CustodyError, match="stored_.*_size"):
        journal.inspect()
    forbidden = "SELECT wire,request FROM intent" if table == "intent" else "SELECT wire,body FROM outcome"
    assert not any(query.startswith(forbidden) for query in queries)


def test_existing_file_never_adopted_and_missing_file_never_created(tmp_path):
    path = tmp_path / "existing.sqlite3"
    path.write_bytes(b"")
    path.chmod(0o600)
    with pytest.raises(FileExistsError):
        custody.AcquisitionJournal.create(path, _wire(), REQUEST)
    assert path.read_bytes() == b""
    with pytest.raises(custody.CustodyError, match="database_header"):
        custody.AcquisitionJournal(path).inspect()
    path.unlink()
    with pytest.raises(FileNotFoundError):
        custody.AcquisitionJournal(path).inspect()
    assert not path.exists()


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604])
def test_nonprivate_file_refuses(tmp_path, mode):
    journal = _journal(tmp_path)
    journal.path.chmod(mode)
    with pytest.raises(custody.CustodyError, match="private_regular_file"):
        journal.inspect()


@pytest.mark.parametrize("kind", ["symlink", "directory", "fifo"])
def test_nonregular_and_symlink_paths_refuse(tmp_path, kind):
    journal = _journal(tmp_path)
    path = tmp_path / "not-custody"
    if kind == "symlink":
        path.symlink_to(journal.path)
    elif kind == "directory":
        path.mkdir(mode=0o700)
    else:
        os.mkfifo(path, 0o600)
    with pytest.raises((OSError, custody.CustodyError)):
        custody.AcquisitionJournal(path).inspect()


@pytest.mark.parametrize("header", [b"\x02\x02", b"\x01\x02", b"\x02\x01", b"\x00\x01"])
def test_wal_and_bad_header_refuse_before_sqlite_open(tmp_path, monkeypatch, header):
    journal = _journal(tmp_path)
    original = journal.path.read_bytes()
    changed = original[:18] + header + original[20:]
    journal.path.write_bytes(changed)

    def forbidden(*args, **kwargs):
        pytest.fail("SQLite opened an unadmitted header")

    monkeypatch.setattr(custody.sqlite3, "connect", forbidden)
    with pytest.raises(custody.CustodyError, match="persistent_wal|database_header"):
        journal.inspect()
    assert journal.path.read_bytes() == changed


def test_foreign_database_is_not_adopted(tmp_path):
    path = tmp_path / "foreign.sqlite3"
    _sql(path, "CREATE TABLE other(x)")
    path.chmod(0o600)
    with pytest.raises(custody.CustodyError, match="application_id"):
        custody.AcquisitionJournal(path).inspect()


def test_concurrent_debits_have_one_fresh_return(tmp_path):
    journal = _journal(tmp_path)
    barrier = Barrier(4)

    def debit(_):
        barrier.wait(timeout=10)
        try:
            return "fresh", custody.AcquisitionJournal(journal.path).debit()
        except custody.CustodyError as error:
            assert str(error) == "attempt_already_spent"
            return "spent", None
        except sqlite3.OperationalError as error:
            assert error.sqlite_errorcode in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED)
            return "busy", None

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(debit, range(4)))
    assert sum(kind == "fresh" for kind, _ in results) == 1
    assert journal.inspect().attempt_id == next(value for kind, value in results if kind == "fresh")
    with pytest.raises(custody.CustodyError, match="attempt_already_spent"):
        journal.debit()


def test_lock_contention_stays_a_storage_error(tmp_path):
    journal = _journal(tmp_path)
    with closing(sqlite3.connect(journal.path)) as locker:
        locker.execute("BEGIN IMMEDIATE")
        with pytest.raises(sqlite3.OperationalError) as caught:
            journal.debit()
        assert caught.value.sqlite_errorcode == sqlite3.SQLITE_BUSY
        locker.rollback()
    assert journal.inspect().status == "prepared"
    journal.debit()


@pytest.mark.parametrize("stage", ["debit", "capture"])
def test_lost_commit_acknowledgement_never_returns_fresh_budget(tmp_path, monkeypatch, stage):
    journal = _journal(tmp_path)
    if stage == "capture":
        journal.debit()
    real_commit = custody._commit

    def lost_ack(connection):
        real_commit(connection)
        raise OSError("injected acknowledgement loss after commit")

    with monkeypatch.context() as patch:
        patch.setattr(custody, "_commit", lost_ack)
        with pytest.raises(OSError, match="acknowledgement loss"):
            if stage == "debit":
                journal.debit()
            else:
                journal.retain_response(RESPONSE)
    cold = custody.AcquisitionJournal(journal.path)
    assert cold.inspect().status == ("attempt_indeterminate" if stage == "debit" else "response_captured")
    with pytest.raises(custody.CustodyError, match="attempt_already_spent"):
        cold.debit()
    if stage == "capture":
        assert cold.retain_response(RESPONSE).response_wire == RESPONSE


@pytest.mark.parametrize("after_commit", [False, True])
@pytest.mark.parametrize("stage", ["debit", "capture"])
def test_real_process_death_on_both_sides_of_commit(tmp_path, after_commit, stage):
    journal = _journal(tmp_path)
    if stage == "capture":
        journal.debit()
    child = _child(
        journal,
        f"""
import os, signal, sys
from etzio.qualification import acquisition_custody_v1 as custody
original = custody._commit
def die(connection):
    if {after_commit!r}:
        original(connection)
    os.kill(os.getpid(), signal.SIGKILL)
custody._commit = die
journal = custody.AcquisitionJournal(sys.argv[1])
if {stage!r} == 'debit':
    journal.debit()
else:
    journal.retain_response({RESPONSE!r})
print('returned', flush=True)
""",
    )
    assert child.returncode == -signal.SIGKILL, child.stderr
    assert "returned" not in child.stdout
    state = custody.AcquisitionJournal(journal.path).inspect()
    if stage == "debit" and not after_commit:
        assert state.status == "prepared"
        journal.debit()
    else:
        expected = "response_captured" if stage == "capture" and after_commit else "attempt_indeterminate"
        assert state.status == expected
        with pytest.raises(custody.CustodyError, match="attempt_already_spent"):
            journal.debit()
    if stage == "capture":
        assert journal.retain_response(RESPONSE).response_wire == RESPONSE


def test_connection_setting_drift_refuses_before_debit(tmp_path, monkeypatch):
    journal = _journal(tmp_path)
    real_connect = custody.sqlite3.connect

    class Unsafe(sqlite3.Connection):
        def execute(self, sql, *args, **kwargs):
            if sql == "PRAGMA synchronous=EXTRA":
                sql = "PRAGMA synchronous=OFF"
            return super().execute(sql, *args, **kwargs)

    def connect(*args, **kwargs):
        return real_connect(*args, **kwargs, factory=Unsafe)

    with monkeypatch.context() as patch:
        patch.setattr(custody.sqlite3, "connect", connect)
        with pytest.raises(custody.CustodyError, match="connection_settings"):
            journal.debit()
    assert journal.inspect().status == "prepared"


def test_maximum_documented_request_and_response_bounds(tmp_path):
    request, response = b"q" * 16384, b"r" * 65536
    wire = _wire(request=request, response_limit_bytes=65536)
    journal = custody.AcquisitionJournal.create(tmp_path / "maximum.sqlite3", wire, request)
    journal.debit()
    state = journal.retain_response(response)
    assert state.request_wire == request and state.response_wire == response
    assert custody.AcquisitionJournal(journal.path).inspect() == state


def test_recreate_cannot_renew_existing_spent_journal(tmp_path):
    journal = _journal(tmp_path)
    journal.debit()
    original = journal.inspect()
    with pytest.raises(FileExistsError):
        custody.AcquisitionJournal.create(journal.path, _wire(), REQUEST)
    assert journal.inspect() == original


def test_outcome_without_retained_debit_is_corruption(tmp_path):
    journal = _journal(tmp_path)
    journal.debit()
    journal.retain_response(RESPONSE)
    _tamper(journal, "debit", "DELETE FROM debit")
    with pytest.raises(custody.CustodyError, match="outcome_without_attempt"):
        journal.inspect()
    with pytest.raises(custody.CustodyError, match="outcome_without_attempt"):
        journal.debit()
