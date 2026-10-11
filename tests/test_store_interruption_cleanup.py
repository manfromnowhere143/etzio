"""A caught interruption cannot expose uncommitted progress as retained state."""

import sqlite3

import pytest
from test_integrity_recovery_matrix_v1 import _event as _modeled_event
from test_integrity_recovery_matrix_v1 import _service as _modeled_service
from test_qualified_anchor_consumption_v1 import _head_fixture
from test_qualified_cold_replay_v1 import _prepare_phase, _retain
from test_qualified_fixture_lifecycle_v1 import _enroll_store, _event, _service

from etzio.kernel.store import (
    PendingIntegrityTransitionError,
    SignedCheckpoint,
    SQLiteEventStore,
    StoreOperationalError,
)


class _InterruptedConnection(sqlite3.Connection):
    failure = None
    after_commit = False

    def execute(self, sql, parameters=()):
        if sql == "COMMIT" and self.failure is not None:
            failure, self.failure = self.failure, None
            if self.after_commit:
                super().execute(sql, parameters)
            raise failure
        return super().execute(sql, parameters)


@pytest.fixture
def interrupted_connect(monkeypatch):
    original = sqlite3.connect

    def connect(*args, **kwargs):
        return original(*args, **kwargs, factory=_InterruptedConnection)

    monkeypatch.setattr(sqlite3, "connect", connect)


def _enroll(store, service):
    return store.enroll_modeled_integrity(
        service_instance_id=service.service_instance_id,
        environment_id=service.environment_id,
        validation_policy=service.validation_policy,
        authority_binding=service.authority_binding,
    )


def _operation(store, case):
    service = _modeled_service()
    event = _modeled_event("interrupted-write")
    if case == "enrollment":
        return lambda: _enroll(store, service), event
    if case == "legacy_checkpoint":
        store.append(event, expected_head=event.prev_digest)
        checkpoint = SignedCheckpoint(event.mission_id, event.event_digest,
                                      "fixture.signer", "opaque", event.decision_time, b"fixture")
        return lambda: store.store_checkpoint(checkpoint), event
    mode, phase = case.split(":")
    if mode == "qualified":
        fixture = _head_fixture()
        service, event = _service(fixture), _event(fixture)
        _enroll_store(store, service)
    else:
        _enroll(store, service)
    # This existing constructor uses the qualified-only pending parameter for anchor
    # registration, so adapt that call for the separately supported modeled service.
    if mode == "modeled":
        original = service.register_anchor_statement

        class Adapter:
            def __getattr__(self, name):
                return getattr(service, name)

            def register_anchor_statement(self, anchor, *, pending):
                return original(anchor)

        prepared_service = Adapter()
    else:
        prepared_service = service
    if phase == "finalization" and mode == "modeled":
        # The shared helper constructs a qualified finalization; retain the same
        # provider bytes under the actual modeled acceptance mode instead.
        from dataclasses import replace

        record = replace(_prepare_phase(store, prepared_service, event, phase),
                         acceptance_mode="modeled_unsigned_code_derived")
    else:
        record = _prepare_phase(store, prepared_service, event, phase)
    return lambda: _retain(store, event, phase, record), event


def _dump(store):
    return tuple(store._connection.iterdump())


_CASES = ["enrollment", "legacy_checkpoint", *(
    f"{mode}:{phase}" for mode in ("modeled", "qualified")
    for phase in ("pending", "anchor_statement", "checkpoint_candidate", "finalization")
)]


@pytest.mark.parametrize("case", _CASES)
def test_interrupted_write_restores_exact_state_and_allows_retry(tmp_path, interrupted_connect, case):
    path = tmp_path / "owned.sqlite3"
    with SQLiteEventStore(path) as store:
        action, event = _operation(store, case)
        before = _dump(store)
        failure = KeyboardInterrupt("owned pre-commit interruption")
        store._connection.failure = failure
        with pytest.raises(KeyboardInterrupt) as caught:
            action()
        assert caught.value is failure
        assert not store._connection.in_transaction
        assert store._integrity_validation_cache is None
        assert _dump(store) == before
        if case.endswith(":finalization"):
            assert store.load_integrity_lineage(event.event_digest).finalization is None
            assert store.load_unresolved_integrity_transition() is not None
            with pytest.raises(PendingIntegrityTransitionError):
                store.load(event.mission_id)
        with SQLiteEventStore(path) as cold:
            assert _dump(cold) == before
        action()
        committed = _dump(store)
        assert committed != before
    with SQLiteEventStore(path) as cold:
        assert _dump(cold) == committed


@pytest.mark.parametrize("failure_type", [RuntimeError, MemoryError, SystemExit])
def test_unexpected_finalization_failure_preserves_barrier(tmp_path, interrupted_connect, failure_type):
    with SQLiteEventStore(tmp_path / "owned.sqlite3") as store:
        action, event = _operation(store, "qualified:finalization")
        before = _dump(store)
        failure = failure_type("owned pre-commit failure")
        store._connection.failure = failure
        with pytest.raises(failure_type) as caught:
            action()
        assert caught.value is failure
        assert not store._connection.in_transaction
        assert _dump(store) == before
        assert store.load_unresolved_integrity_transition().pending.event_digest == event.event_digest
        with pytest.raises(PendingIntegrityTransitionError):
            store.load(event.mission_id)


@pytest.mark.parametrize("failure_type", [RuntimeError, KeyboardInterrupt])
def test_postcommit_interruption_keeps_committed_finality(tmp_path, interrupted_connect, failure_type):
    path = tmp_path / "owned.sqlite3"
    with SQLiteEventStore(path) as store:
        action, event = _operation(store, "qualified:finalization")
        store._connection.after_commit = True
        failure = failure_type("owned lost response after commit")
        store._connection.failure = failure
        with pytest.raises(failure_type) as caught:
            action()
        assert caught.value is failure
        assert not store._connection.in_transaction
        assert store.load(event.mission_id) == (event,)
        assert store.load_unresolved_integrity_transition() is None
        committed = _dump(store)
        action()
        assert _dump(store) == committed
    with SQLiteEventStore(path) as cold:
        assert _dump(cold) == committed
        assert cold.load(event.mission_id) == (event,)


@pytest.mark.parametrize("failure_type", [RuntimeError, KeyboardInterrupt, sqlite3.OperationalError])
def test_refused_rollback_closes_handle_and_preserves_original_failure(tmp_path, interrupted_connect, failure_type):
    path = tmp_path / "owned.sqlite3"
    with SQLiteEventStore(path) as store:
        action, event = _operation(store, "qualified:finalization")
        before = _dump(store)
        failure = failure_type("owned interrupted write")
        store._connection.failure = failure

        def deny_rollback(operation, first, _second, _database, _trigger):
            if operation == sqlite3.SQLITE_TRANSACTION and first == "ROLLBACK":
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        store._connection.set_authorizer(deny_rollback)
        expected = StoreOperationalError if failure_type is sqlite3.OperationalError else failure_type
        with pytest.raises(expected) as caught:
            action()
        assert (caught.value.__cause__ if expected is StoreOperationalError else caught.value) is failure
        with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
            store._connection.execute("SELECT 1")
    with SQLiteEventStore(path) as cold:
        assert _dump(cold) == before
        assert cold.load_unresolved_integrity_transition() is not None
        with pytest.raises(PendingIntegrityTransitionError):
            cold.load(event.mission_id)
