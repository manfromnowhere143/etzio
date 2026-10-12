"""Failed cleanup must not expose speculative state through a usable store."""

import sqlite3

import pytest
from test_store_interruption_cleanup import _dump, _InterruptedConnection, _operation

from etzio.kernel.events_v1 import GENESIS_DIGEST
from etzio.kernel.store import PendingIntegrityTransitionError, SQLiteEventStore


class _CleanupFailureConnection(_InterruptedConnection):
    rollback_failure = None
    close_failure = None
    after_close = False

    def execute(self, sql, parameters=()):
        if sql == "ROLLBACK" and self.rollback_failure is not None:
            failure, self.rollback_failure = self.rollback_failure, None
            raise failure
        return super().execute(sql, parameters)

    def close(self):
        if self.close_failure is not None:
            failure, self.close_failure = self.close_failure, None
            if self.after_close:
                super().close()
            raise failure
        return super().close()


@pytest.fixture
def cleanup_connect(monkeypatch):
    original = sqlite3.connect

    def connect(*args, **kwargs):
        return original(*args, **kwargs, factory=_CleanupFailureConnection)

    monkeypatch.setattr(sqlite3, "connect", connect)


@pytest.mark.usefixtures("cleanup_connect")
@pytest.mark.parametrize("mode", ["modeled", "qualified"])
@pytest.mark.parametrize("cleanup_error", [RuntimeError, MemoryError, KeyboardInterrupt, SystemExit])
def test_failed_rollback_discards_write_handle(tmp_path, mode, cleanup_error):
    path = tmp_path / "owned.sqlite3"
    with SQLiteEventStore(path) as store:
        action, event = _operation(store, mode + ":finalization")
        before = _dump(store)
        original = RuntimeError("owned failed finalization")
        store._connection.failure = original
        store._connection.rollback_failure = cleanup_error("owned failed rollback")
        with pytest.raises(BaseException) as caught:
            action()
        assert caught.value is original
        assert store._integrity_validation_cache is None
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            store.load(event.mission_id)
        with SQLiteEventStore(path) as cold:
            assert _dump(cold) == before
            with pytest.raises(PendingIntegrityTransitionError):
                cold.load(event.mission_id)


@pytest.mark.usefixtures("cleanup_connect")
@pytest.mark.parametrize("cleanup_error", [MemoryError, KeyboardInterrupt])
def test_failed_rollback_discards_read_handle(tmp_path, monkeypatch, cleanup_error):
    path = tmp_path / "owned.sqlite3"
    with SQLiteEventStore(path) as store:
        original = RuntimeError("owned failed read")

        def interrupted_rows(mission_id):
            raise original

        monkeypatch.setattr(store, "_rows", interrupted_rows)
        store._connection.rollback_failure = cleanup_error("owned failed rollback")
        with pytest.raises(BaseException) as caught:
            store.load(GENESIS_DIGEST)
        assert caught.value is original
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            store.load(GENESIS_DIGEST)
    with SQLiteEventStore(path) as cold:
        assert cold.load(GENESIS_DIGEST) == ()


@pytest.mark.usefixtures("cleanup_connect")
@pytest.mark.parametrize("mode", ["modeled", "qualified"])
@pytest.mark.parametrize("after_close", [False, True])
def test_failed_close_cannot_restore_discarded_handle(tmp_path, mode, after_close):
    path = tmp_path / "owned.sqlite3"
    with SQLiteEventStore(path) as store:
        action, event = _operation(store, mode + ":finalization")
        before = _dump(store)
        raw_connection = store._connection
        original = RuntimeError("owned failed finalization")
        raw_connection.failure = original
        raw_connection.rollback_failure = sqlite3.OperationalError("owned failed rollback")
        raw_connection.close_failure = KeyboardInterrupt("owned interrupted close")
        raw_connection.after_close = after_close
        try:
            with pytest.raises(BaseException) as caught:
                action()
            assert caught.value is original
            with pytest.raises(sqlite3.ProgrammingError, match="closed"):
                store.load(event.mission_id)
            with pytest.raises(sqlite3.ProgrammingError, match="closed"):
                store._connection.execute("COMMIT")
            store.close()
        finally:
            # The retained test reference deliberately keeps the underlying handle
            # alive. Discarding the store does not claim release of its SQLite locks.
            raw_connection.close_failure = None
            raw_connection.close()
    with SQLiteEventStore(path) as cold:
        assert _dump(cold) == before
        with pytest.raises(PendingIntegrityTransitionError):
            cold.load(event.mission_id)
