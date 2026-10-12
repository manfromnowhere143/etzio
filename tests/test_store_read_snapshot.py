"""One public read must not combine rows from different committed states."""

import sqlite3

import pytest
from test_store_interruption_cleanup import _operation, interrupted_connect  # noqa: F401

from etzio.kernel.events_v1 import GENESIS_DIGEST
from etzio.kernel.store import (
    EventStoreError,
    PendingIntegrityTransitionError,
    SQLiteEventStore,
    StoreBusyError,
)


@pytest.mark.parametrize("mode", ["modeled", "qualified"])
@pytest.mark.parametrize("read", ["load", "head"])
def test_pending_append_cannot_cross_replay_barrier(tmp_path, monkeypatch, mode, read):
    path = tmp_path / "owned.sqlite3"
    with SQLiteEventStore(path) as writer:
        append_pending, event = _operation(writer, mode + ":pending")
        writer._connection.execute("PRAGMA busy_timeout = 0")
        with SQLiteEventStore(path) as reader:
            rows = reader._rows
            outcomes = []

            def interleave(mission_id):
                # The normal writer runs after the normal reader's barrier check.
                try:
                    append_pending()
                except StoreBusyError:
                    outcomes.append("contended")
                else:
                    outcomes.append("committed")
                return rows(mission_id)

            with monkeypatch.context() as patch:
                patch.setattr(reader, "_rows", interleave)
                result = getattr(reader, read)(event.mission_id)
            assert result == (() if read == "load" else GENESIS_DIGEST)
            assert outcomes == ["contended"]
            assert not reader._connection.in_transaction
            assert not writer._connection.in_transaction
            append_pending()
            with pytest.raises(PendingIntegrityTransitionError):
                getattr(reader, read)(event.mission_id)
            assert not reader._connection.in_transaction
        with SQLiteEventStore(path) as cold:
            with pytest.raises(PendingIntegrityTransitionError):
                cold.load(event.mission_id)


@pytest.mark.parametrize("mode", ["modeled", "qualified"])
def test_pending_inspection_does_not_mix_later_finalization(tmp_path, monkeypatch, mode):
    path = tmp_path / "owned.sqlite3"
    with SQLiteEventStore(path) as writer:
        finalize, event = _operation(writer, mode + ":finalization")
        writer._connection.execute("PRAGMA busy_timeout = 0")
        with SQLiteEventStore(path) as reader:
            pending = reader.load_unresolved_integrity_transition()
            load_lineage = reader._load_integrity_lineage_locked
            outcomes = []

            def interleave(digest):
                try:
                    finalize()
                except StoreBusyError:
                    outcomes.append("contended")
                else:
                    outcomes.append("committed")
                return load_lineage(digest)

            with monkeypatch.context() as patch:
                patch.setattr(reader, "_load_integrity_lineage_locked", interleave)
                assert reader.load_unresolved_integrity_transition() == pending
            assert outcomes == ["contended"]
            assert not reader._connection.in_transaction
            finalize()
            assert reader.load_unresolved_integrity_transition() is None
            assert reader.load(event.mission_id) == (event,)


@pytest.mark.parametrize("failure_type", [RuntimeError, KeyboardInterrupt, MemoryError])
def test_failed_read_releases_snapshot_and_discards_validation(tmp_path, monkeypatch, failure_type):
    with SQLiteEventStore(tmp_path / "owned.sqlite3") as store:
        failure = failure_type("owned read interruption")

        def interrupted_rows(mission_id):
            raise failure

        with monkeypatch.context() as patch:
            patch.setattr(store, "_rows", interrupted_rows)
            with pytest.raises(failure_type) as caught:
                store.load(GENESIS_DIGEST)
        assert caught.value is failure
        assert not store._connection.in_transaction
        assert store._integrity_validation_cache is None
        assert store.load(GENESIS_DIGEST) == ()


@pytest.mark.parametrize("after_commit", [False, True])
@pytest.mark.usefixtures("interrupted_connect")
def test_read_commit_interruption_is_cleaned_up(tmp_path, after_commit):
    with SQLiteEventStore(tmp_path / "owned.sqlite3") as store:
        failure = KeyboardInterrupt("owned read commit interruption")
        store._connection.failure = failure
        store._connection.after_commit = after_commit
        with pytest.raises(KeyboardInterrupt) as caught:
            store.load(GENESIS_DIGEST)
        assert caught.value is failure
        assert not store._connection.in_transaction
        assert store._integrity_validation_cache is None
        assert store.load(GENESIS_DIGEST) == ()


@pytest.mark.parametrize("fails", [False, True])
def test_nested_read_never_ends_callers_transaction(tmp_path, fails):
    with SQLiteEventStore(tmp_path / "owned.sqlite3") as store:
        store._connection.execute("BEGIN IMMEDIATE")
        if fails:
            with pytest.raises(EventStoreError, match="mission_id"):
                store.load("invalid")
        else:
            assert store.load_checkpoints(GENESIS_DIGEST) == ()
        assert store._connection.in_transaction
        store._connection.execute("ROLLBACK")


def test_read_snapshot_does_not_reserve_writer_lock(tmp_path, monkeypatch):
    path = tmp_path / "owned.sqlite3"
    with SQLiteEventStore(path) as reader, SQLiteEventStore(path) as peer:
        peer._connection.execute("PRAGMA busy_timeout = 0")
        rows = reader._rows

        def interleave(mission_id):
            # A deferred reader permits another reader and a writer reservation.
            assert peer.load(mission_id) == ()
            peer._connection.execute("BEGIN IMMEDIATE")
            peer._connection.execute("ROLLBACK")
            return rows(mission_id)

        monkeypatch.setattr(reader, "_rows", interleave)
        assert reader.load(GENESIS_DIGEST) == ()
        assert not reader._connection.in_transaction


def test_read_rollback_refusal_closes_handle(tmp_path, monkeypatch):
    original_connect = sqlite3.connect

    class BrokenRollback(sqlite3.Connection):
        refuse = False

        def execute(self, sql, parameters=()):
            if self.refuse and sql == "ROLLBACK":
                raise sqlite3.OperationalError("owned rollback refusal")
            return super().execute(sql, parameters)

    def connect(*args, **kwargs):
        return original_connect(*args, **kwargs, factory=BrokenRollback)

    monkeypatch.setattr(sqlite3, "connect", connect)
    with SQLiteEventStore(tmp_path / "owned.sqlite3") as store:
        failure = KeyboardInterrupt("owned read failure")

        def interrupted_rows(mission_id):
            raise failure

        store._connection.refuse = True
        monkeypatch.setattr(store, "_rows", interrupted_rows)
        with pytest.raises(KeyboardInterrupt) as caught:
            store.load(GENESIS_DIGEST)
        assert caught.value is failure
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            store._connection.execute("SELECT 1")


@pytest.mark.parametrize("mode", ["modeled", "qualified"])
def test_global_and_mission_heads_share_one_snapshot(tmp_path, monkeypatch, mode):
    original_connect = sqlite3.connect

    class InterleavedConnection(sqlite3.Connection):
        after_global = None

        def execute(self, sql, parameters=()):
            cursor = super().execute(sql, parameters)
            if self.after_global is None or "ORDER BY pending.instance_sequence DESC" not in sql:
                return cursor
            callback, self.after_global = self.after_global, None

            class RowBoundary:
                def fetchone(self):
                    row = cursor.fetchone()
                    callback()
                    return row

            return RowBoundary()

    def connect(*args, **kwargs):
        return original_connect(*args, **kwargs, factory=InterleavedConnection)

    monkeypatch.setattr(sqlite3, "connect", connect)
    path = tmp_path / "owned.sqlite3"
    with SQLiteEventStore(path) as writer:
        finalize, event = _operation(writer, mode + ":finalization")
        writer._connection.execute("PRAGMA busy_timeout = 0")
        with SQLiteEventStore(path) as reader:
            outcomes = []

            def after_global():
                try:
                    finalize()
                except StoreBusyError:
                    outcomes.append("contended")
                else:
                    outcomes.append("committed")

            reader._connection.after_global = after_global
            assert reader.load_latest_finalized_integrity_lineages(event.mission_id) == (None, None)
            assert outcomes == ["contended"]
            assert not reader._connection.in_transaction
            finalize()
            global_head, mission_head = reader.load_latest_finalized_integrity_lineages(event.mission_id)
            assert global_head == mission_head
            assert global_head.finalization is not None
