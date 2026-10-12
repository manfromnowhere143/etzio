"""Failed construction must release owned handles and preserve committed schema."""

import os
import sqlite3
from contextlib import contextmanager

import pytest
from test_integrity_store_v2 import (
    _downgrade_exact_empty_integrity_schema_to_v1,
    _downgrade_exact_empty_integrity_schema_to_v2,
    _downgrade_exact_empty_integrity_schema_to_v3,
)

from etzio.kernel.events_v1 import GENESIS_DIGEST
from etzio.kernel.store import SQLiteEventStore, StoreOperationalError


def _state(path):
    if not path.exists():
        return (0,), (0,), ()
    connection = sqlite3.connect(path, isolation_level=None, timeout=0)
    try:
        return (
            connection.execute("PRAGMA application_id").fetchone(),
            connection.execute("PRAGMA user_version").fetchone(),
            tuple(connection.iterdump()),
        )
    finally:
        connection.close()


def _prepare(path, version):
    if version:
        with SQLiteEventStore(path):
            pass
        {
            1: _downgrade_exact_empty_integrity_schema_to_v1,
            2: _downgrade_exact_empty_integrity_schema_to_v2,
            3: _downgrade_exact_empty_integrity_schema_to_v3,
        }[version](path)


@contextmanager
def _fault_connection(monkeypatch, *, original=None, after_commit=False,
                      rollback_error=None, close_error=None, after_close=False):
    real_connect = sqlite3.connect
    connections = []

    class Connection(sqlite3.Connection):
        fail_commit = original
        close_calls = 0

        def execute(self, sql, parameters=()):
            if sql == "COMMIT" and self.fail_commit is not None:
                error, self.fail_commit = self.fail_commit, None
                if after_commit:
                    super().execute(sql, parameters)
                raise error
            if sql == "ROLLBACK" and rollback_error is not None:
                raise rollback_error
            return super().execute(sql, parameters)

        def close(self):
            self.close_calls += 1
            if close_error is not None:
                if after_close:
                    super().close()
                raise close_error
            super().close()

    def connect(*args, **kwargs):
        connection = real_connect(*args, **kwargs, factory=Connection)
        connections.append(connection)
        return connection

    try:
        with monkeypatch.context() as patch:
            patch.setattr(sqlite3, "connect", connect)
            yield connections
    finally:
        # Keep raw handles alive deliberately; garbage collection must not make the
        # cleanup assertion pass. Release a failed implementation's locks afterward.
        for connection in connections:
            sqlite3.Connection.close(connection)


@pytest.mark.parametrize("version", [0, 1, 2, 3])
@pytest.mark.parametrize("fault", ["pre_commit", "post_commit", "rollback"])
def test_failed_schema_opening_closes_handle_and_preserves_commit_boundary(
    tmp_path, monkeypatch, version, fault,
):
    path = tmp_path / "owned.sqlite3"
    _prepare(path, version)
    before = _state(path)
    original = KeyboardInterrupt("owned opening interruption")
    rollback_error = MemoryError("owned rollback failure") if fault == "rollback" else None
    peer_connect = sqlite3.connect
    with _fault_connection(monkeypatch, original=original, after_commit=fault == "post_commit",
                           rollback_error=rollback_error) as connections:
        with pytest.raises(BaseException) as caught:
            SQLiteEventStore(path)
        assert caught.value is original
        assert len(connections) == 1
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connections[0].execute("SELECT 1")
        # A distinct connection can reserve the writer slot while the failed opening
        # and its traceback remain alive. This checks actual SQLite lock release.
        peer = peer_connect(path, isolation_level=None, timeout=0)
        try:
            peer.execute("BEGIN IMMEDIATE")
            peer.execute("ROLLBACK")
        finally:
            peer.close()
    retained = _state(path)
    if fault == "post_commit":
        assert retained[1] == (4,)
        assert retained != before
    elif version:
        assert retained == before
    else:
        assert retained[:2] == ((0,), (0,))
        assert retained[2] == ("BEGIN TRANSACTION;", "COMMIT;")
    with SQLiteEventStore(path) as fresh:
        assert fresh.load(GENESIS_DIGEST) == ()
        assert fresh._connection.execute("PRAGMA user_version").fetchone() == (4,)
    if fault == "post_commit":
        assert _state(path) == retained


@pytest.mark.parametrize("stage", ["first_identity", "initialize", "read_validation", "last_identity"])
def test_interruption_at_each_opening_stage_discards_connection(tmp_path, monkeypatch, stage):
    path = tmp_path / "owned.sqlite3"
    with SQLiteEventStore(path):
        pass
    before = _state(path)
    original = KeyboardInterrupt("owned opening-stage interruption")
    seen = []
    method_name = {
        "first_identity": "_verify_post_connect_identity",
        "initialize": "_initialize_schema",
        "read_validation": "_refresh_validated_schema_version_locked",
        "last_identity": "_verify_post_connect_identity",
    }[stage]
    real_method = getattr(SQLiteEventStore, method_name)

    def interrupted(store, *args):
        seen.append(store)
        if stage != "last_identity" or len(seen) == 2:
            raise original
        return real_method(store, *args)

    with _fault_connection(monkeypatch) as connections:
        with monkeypatch.context() as patch:
            patch.setattr(SQLiteEventStore, method_name, interrupted)
            with pytest.raises(KeyboardInterrupt) as caught:
                SQLiteEventStore(path)
        assert caught.value is original
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connections[0].execute("SELECT 1")
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            seen[-1].load(GENESIS_DIGEST)
    assert _state(path) == before


@pytest.mark.parametrize("after_close", [False, True])
@pytest.mark.parametrize("database_error", [False, True])
def test_opening_close_failure_preserves_primary_error_and_discards_store(
    tmp_path, monkeypatch, after_close, database_error,
):
    path = tmp_path / "owned.sqlite3"
    original = (sqlite3.OperationalError if database_error else RuntimeError)("owned initial failure")
    seen = []

    def fail(store, prepared):
        seen.append(store)
        raise original

    with _fault_connection(monkeypatch, close_error=KeyboardInterrupt("owned close interruption"),
                           after_close=after_close) as connections:
        with monkeypatch.context() as patch:
            patch.setattr(SQLiteEventStore, "_verify_post_connect_identity", fail)
            with pytest.raises(BaseException) as caught:
                SQLiteEventStore(path)
        if database_error:
            assert type(caught.value) is StoreOperationalError
            assert caught.value.__cause__ is original
        else:
            assert caught.value is original
        assert connections[0].close_calls == 1
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            seen[0].load(GENESIS_DIGEST)
        seen[0].close()


@pytest.mark.parametrize("version", [0, 3])
def test_failed_schema_rollback_and_close_cannot_mask_original(tmp_path, monkeypatch, version):
    path = tmp_path / "owned.sqlite3"
    _prepare(path, version)
    before = _state(path)
    original = RuntimeError("owned schema failure")
    seen = []
    validate = SQLiteEventStore._validate_schema

    def capture(store):
        seen.append(store)
        return validate(store)

    with _fault_connection(monkeypatch, original=original,
                           rollback_error=KeyboardInterrupt("owned rollback interruption"),
                           close_error=MemoryError("owned close failure")) as connections:
        with monkeypatch.context() as patch:
            patch.setattr(SQLiteEventStore, "_validate_schema", capture)
            with pytest.raises(BaseException) as caught:
                SQLiteEventStore(path)
        assert caught.value is original
        assert connections[0].close_calls == 1
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            seen[-1].load(GENESIS_DIGEST)
        # Physical release is deliberately not promised if close itself fails.
        assert connections[0].in_transaction
    retained = _state(path)
    if version:
        assert retained == before
    else:
        assert retained[:2] == ((0,), (0,))
        assert retained[2] == ("BEGIN TRANSACTION;", "COMMIT;")


def test_connect_failure_before_handle_assignment_preserves_error(tmp_path, monkeypatch):
    original = KeyboardInterrupt("owned connect interruption")

    def fail(*args, **kwargs):
        raise original

    with monkeypatch.context() as patch:
        patch.setattr(sqlite3, "connect", fail)
        with pytest.raises(KeyboardInterrupt) as caught:
            SQLiteEventStore(tmp_path / "owned.sqlite3")
    assert caught.value is original
    with SQLiteEventStore(tmp_path / "owned.sqlite3") as fresh:
        assert fresh.load(GENESIS_DIGEST) == ()


@contextmanager
def _descriptor_faults(monkeypatch, *, preparation_error=None, close_error=None, after_close=False):
    real_close, real_fchmod = os.close, os.fchmod
    observed = {"fd": None, "closed": False, "close_calls": 0}

    def fchmod(fd, mode):
        observed["fd"] = fd
        if preparation_error is not None:
            raise preparation_error
        return real_fchmod(fd, mode)

    def close(fd):
        if fd != observed["fd"]:
            return real_close(fd)
        observed["close_calls"] += 1
        if close_error is None or after_close:
            real_close(fd)
            observed["closed"] = True
        if close_error is not None:
            raise close_error

    try:
        with monkeypatch.context() as patch:
            patch.setattr(os, "fchmod", fchmod)
            patch.setattr(os, "close", close)
            yield observed
    finally:
        if observed["fd"] is not None and not observed["closed"]:
            real_close(observed["fd"])


@pytest.mark.parametrize("fault", ["interruption", "close_before", "close_after"])
def test_path_preparation_cleans_descriptor_without_masking_failure(tmp_path, monkeypatch, fault):
    original = (KeyboardInterrupt if fault == "interruption" else RuntimeError)("owned preparation failure")
    close_error = MemoryError("owned descriptor close failure") if fault != "interruption" else None
    with _descriptor_faults(monkeypatch, preparation_error=original, close_error=close_error,
                            after_close=fault == "close_after") as observed:
        with pytest.raises(BaseException) as caught:
            SQLiteEventStore(tmp_path / "owned.sqlite3")
        assert caught.value is original
        assert observed["close_calls"] == 1
        assert observed["closed"] == (fault != "close_before")
        if observed["closed"]:
            with pytest.raises(OSError):
                os.fstat(observed["fd"])


@pytest.mark.parametrize("after_close", [False, True])
@pytest.mark.parametrize("database_error", [False, True])
def test_descriptor_cleanup_preserves_opening_failure(tmp_path, monkeypatch, after_close, database_error):
    original = (sqlite3.OperationalError if database_error else RuntimeError)("owned opening failure")

    def fail(store, prepared):
        raise original

    with _fault_connection(monkeypatch) as connections:
        with _descriptor_faults(monkeypatch, close_error=KeyboardInterrupt("owned descriptor close"),
                                after_close=after_close) as observed:
            with monkeypatch.context() as patch:
                patch.setattr(SQLiteEventStore, "_verify_post_connect_identity", fail)
                with pytest.raises(BaseException) as caught:
                    SQLiteEventStore(tmp_path / "owned.sqlite3")
            if database_error:
                assert type(caught.value) is StoreOperationalError
                assert caught.value.__cause__ is original
            else:
                assert caught.value is original
            assert observed["close_calls"] == 1
            with pytest.raises(sqlite3.ProgrammingError, match="closed"):
                connections[0].execute("SELECT 1")


@pytest.mark.parametrize("after_close", [False, True])
def test_descriptor_close_failure_after_successful_opening_discards_connection(tmp_path, monkeypatch, after_close):
    path = tmp_path / "owned.sqlite3"
    original = KeyboardInterrupt("owned final descriptor close")
    with _fault_connection(monkeypatch) as connections:
        with _descriptor_faults(monkeypatch, close_error=original, after_close=after_close) as observed:
            with pytest.raises(KeyboardInterrupt) as caught:
                SQLiteEventStore(path)
            assert caught.value is original
            assert observed["close_calls"] == 1
            with pytest.raises(sqlite3.ProgrammingError, match="closed"):
                connections[0].execute("SELECT 1")
    with SQLiteEventStore(path) as fresh:
        assert fresh.load(GENESIS_DIGEST) == ()
