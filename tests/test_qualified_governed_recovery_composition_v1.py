"""Governed authority changes across signed-fixture recovery and actual store writes."""

from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest
from test_blocked_finality_lifecycle_v1 import _time_source
from test_blocked_finality_storage_v3 import _recovery_profile, _sign
from test_qualified_fixture_lifecycle_v1 import (
    _enroll_store,
    _event,
    _head_fixture,
    _InterruptedPort,
    _service,
)

from etzio.kernel.integrity_transition import (
    GovernedBlockedFinalityBindingV1,
    IntegrityFinalityBlockedError,
    IntegrityInstanceSealedError,
    IntegrityRecoveryNotAuthorizedError,
    ModeledIntegrityFinalizingEventStoreV1,
)
from etzio.kernel.store import (
    IntegrityTransitionConflictError,
    PendingIntegrityTransitionError,
    SQLiteEventStore,
)


class _RefusingService:
    def __init__(self, delegate, operation):
        self.delegate, self.operation = delegate, operation

    def __getattr__(self, name):
        value = getattr(self.delegate, name)
        if name != self.operation:
            return value

        def refuse(*args, **kwargs):
            raise IntegrityFinalityBlockedError(
                "modeled_integrity_adapter_contract_failure", "owned composition refusal")

        return refuse


class _PausedStore:
    """Stop immediately before the real transaction, after facade authorization."""

    def __init__(self, delegate, operation, reached, resume):
        self.delegate, self.operation = delegate, operation
        self.reached, self.resume = reached, resume

    def __getattr__(self, name):
        value = getattr(self.delegate, name)
        if name != self.operation:
            return value

        def call(*args, **kwargs):
            self.reached.set()
            assert self.resume.wait(timeout=30), "controller did not release paused writer"
            return value(*args, **kwargs)

        return call


def _start_blocked(path, fixture, refused_operation):
    service = _service(fixture)
    profile, signer = _recovery_profile(
        service.service_instance_id, service.environment_id, service.authority_binding)
    binding = GovernedBlockedFinalityBindingV1(profile=profile, time_source=_time_source())
    event = _event(fixture)
    with SQLiteEventStore(path) as store:
        _enroll_store(store, service)
        facade = ModeledIntegrityFinalizingEventStoreV1(
            store, _RefusingService(service, refused_operation), blocked_finality=binding)
        with pytest.raises(IntegrityFinalityBlockedError):
            facade.append(event, expected_head=event.prev_digest)
        observation, = store.load_blocked_finality_observations(event.event_digest)
        signed = _sign(profile, signer, observation, "retry_authorized")
        store.retain_governed_recovery_decision(signed)
    return event, profile, signer, binding, observation, signed


def _assert_prefix_unchanged(earlier, later):
    for name in ("pending", "anchor_statement", "checkpoint_candidate", "finalization"):
        record = getattr(earlier, name)
        if record is not None:
            assert record.to_canonical_bytes() == getattr(later, name).to_canonical_bytes()


@pytest.mark.parametrize("operation", [
    "retain_integrity_anchor_statement", "retain_integrity_checkpoint_candidate",
])
def test_cold_qualified_retry_after_second_interruption_needs_current_phase_grant(tmp_path, operation):
    fixture = _head_fixture()
    path = tmp_path / "cold.sqlite3"
    event, profile, signer, binding, first, signed = _start_blocked(
        path, fixture, "prepare_anchor_statement")
    with SQLiteEventStore(path) as store:
        interrupted = _InterruptedPort(store, operation, True, KeyboardInterrupt)
        facade = ModeledIntegrityFinalizingEventStoreV1(
            interrupted, _service(fixture), blocked_finality=binding)
        with pytest.raises(KeyboardInterrupt, match="injected interruption"):
            facade.recover_pending_transition()
        retained = store.load_integrity_lineage(event.event_digest)
        assert retained.phase != first.unresolved_phase
        assert store.load_blocked_finality_observations(event.event_digest) == (first,)

    with SQLiteEventStore(path) as store:
        facade = ModeledIntegrityFinalizingEventStoreV1(
            store, _service(_head_fixture()), blocked_finality=binding)
        with pytest.raises(IntegrityFinalityBlockedError) as error:
            facade.recover_pending_transition()
        assert error.value.reason_code == "modeled_integrity_recovery_phase_changed"
        observations = store.load_blocked_finality_observations(event.event_digest)
        assert [entry.attempt_ordinal for entry in observations] == [1, 2]
        latest = observations[-1]
        assert latest.unresolved_phase == retained.phase
        assert latest.unresolved_phase_record_id == retained.phase_record_id
        assert latest.blocked_operation == "recover_lineage"
        assert store.load_integrity_lineage(event.event_digest) == retained
        assert store.load_governed_recovery_decision(first.observation_id) == signed
        with pytest.raises(IntegrityRecoveryNotAuthorizedError):
            facade.recover_pending_transition()
        assert store.load_blocked_finality_observations(event.event_digest) == observations
        with pytest.raises(PendingIntegrityTransitionError):
            store.load(event.mission_id)
        store.retain_governed_recovery_decision(_sign(profile, signer, latest, "retry_authorized"))
        assert facade.recover_pending_transition() is not None
        _assert_prefix_unchanged(retained, store.load_integrity_lineage(event.event_digest))
        assert store.load_unresolved_integrity_transition() is None
    with SQLiteEventStore(path) as store:
        assert store.load(event.mission_id) == (event,)
        assert store.load_blocked_finality_observations(event.event_digest) == observations


@pytest.mark.parametrize("operation,refusal,phase", [
    ("retain_integrity_anchor_statement", "prepare_anchor_statement", "local_pending"),
    ("retain_integrity_checkpoint_candidate", "prepare_checkpoint_candidate", "anchor_statement_ready"),
    ("finalize_integrity_transition", "observe_current_floor", "checkpoint_candidate_retained"),
])
@pytest.mark.parametrize("disposition", [None, "instance_sealed", "retry_authorized"])
def test_qualified_write_rechecks_concurrent_latest_decision(tmp_path, operation, refusal, phase, disposition):
    fixture = _head_fixture()
    path = tmp_path / "race.sqlite3"
    event, profile, signer, binding, first, signed = _start_blocked(path, fixture, refusal)
    assert first.unresolved_phase == phase
    reached, resume = Event(), Event()

    def older_recoverer():
        # Each connection is constructed and used only by its owning thread.
        with SQLiteEventStore(path) as store:
            facade = ModeledIntegrityFinalizingEventStoreV1(
                _PausedStore(store, operation, reached, resume),
                _service(_head_fixture()), blocked_finality=binding)
            return facade.recover_pending_transition()

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(older_recoverer)
        try:
            assert reached.wait(timeout=30), "older recovery never reached its phase write"
            with SQLiteEventStore(path) as store:
                before = store.load_integrity_lineage(event.event_digest)
                assert before.phase == phase
                second = ModeledIntegrityFinalizingEventStoreV1(
                    store, _RefusingService(_service(fixture), refusal), blocked_finality=binding)
                with pytest.raises(IntegrityFinalityBlockedError):
                    second.recover_pending_transition()
                observations = store.load_blocked_finality_observations(event.event_digest)
                assert [entry.attempt_ordinal for entry in observations] == [1, 2]
                latest = observations[-1]
                assert latest.unresolved_phase_record_id == before.phase_record_id
                if disposition is not None:
                    store.retain_governed_recovery_decision(_sign(profile, signer, latest, disposition))
                assert store.load_integrity_lineage(event.event_digest) == before
        finally:
            # An assertion failure must not strand the worker or hide the real error.
            resume.set()
        if disposition == "retry_authorized":
            assert future.result(timeout=30) is not None
        else:
            expected = "sealed instance" if disposition == "instance_sealed" else "latest blocked observation"
            with pytest.raises(IntegrityTransitionConflictError, match=expected):
                future.result(timeout=30)

    with SQLiteEventStore(path) as store:
        after = store.load_integrity_lineage(event.event_digest)
        _assert_prefix_unchanged(before, after)
        assert store.load_governed_recovery_decision(first.observation_id) == signed
        # A store refusal cannot be relabeled as a third adapter block.
        assert store.load_blocked_finality_observations(event.event_digest) == observations
        fresh = ModeledIntegrityFinalizingEventStoreV1(
            store, _service(_head_fixture()), blocked_finality=binding)
        if disposition == "retry_authorized":
            assert after.finalization is not None
            assert fresh.recover_pending_transition() is None
            assert store.load(event.mission_id) == (event,)
        else:
            assert after.to_canonical_bytes() == before.to_canonical_bytes()
            assert store.load_unresolved_integrity_transition() == before
            assert store.load_integrity_event(event.event_digest) == event
            with pytest.raises(PendingIntegrityTransitionError):
                store.load(event.mission_id)
            if disposition == "instance_sealed":
                assert store.instance_is_sealed()
                with pytest.raises(IntegrityInstanceSealedError):
                    fresh.recover_pending_transition()
            else:
                with pytest.raises(IntegrityRecoveryNotAuthorizedError):
                    fresh.recover_pending_transition()
                store.retain_governed_recovery_decision(_sign(profile, signer, latest, "retry_authorized"))
                assert fresh.recover_pending_transition() is not None
                _assert_prefix_unchanged(before, store.load_integrity_lineage(event.event_digest))
                assert store.load(event.mission_id) == (event,)
