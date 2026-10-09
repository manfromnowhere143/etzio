"""Qualified lifecycle composition: signed packages survive canonical phase boundaries."""

import pytest
from test_qualified_anchor_consumption_v1 import _head_fixture
from test_qualified_pending_record_wiring_v1 import _profile_aligned_service

from etzio.kernel.events_v1 import GENESIS_DIGEST, EventV1
from etzio.kernel.integrity_transition import (
    INTEGRITY_ACCEPTANCE_MODE_QUALIFIED_SIGNED_V1,
    AnchorStatementRecordV1,
    CheckpointCandidateRecordV1,
    FinalizedIntegrityTransitionV1,
    IntegrityLineageV1,
    PendingIntegrityTransitionV1,
    validate_finalized_integrity_transition,
)
from etzio.kernel.qualified_fixture_service_v1 import RepositoryOwnedQualifiedFixtureIntegrityServiceV1
from etzio.kernel.qualified_lifecycle_v1 import reconstruct_qualified_lineage_v1


def _service(fixture):
    return RepositoryOwnedQualifiedFixtureIntegrityServiceV1(core=_profile_aligned_service(fixture), fixture=fixture)


def _event(fixture, previous=None):
    vector = fixture.time_fixture.vector
    return EventV1.create(
        mission_id=vector.mission_id, seq=0 if previous is None else previous.seq + 1,
        kind="mission_admission_refused", unit="AQUILA", authority_id=vector.authority_id, target_id=vector.target_id,
        decision_time=2_000_000_000 if previous is None else previous.decision_time + 1,
        payload={"reason_code": "authority_expired", "stage": "admission"},
        prev_digest=GENESIS_DIGEST if previous is None else previous.event_digest,
    )


def _cold(record):
    return type(record).from_canonical_bytes(record.to_canonical_bytes())


def test_all_four_phases_reconstruct_from_canonical_bytes():
    fixture = _head_fixture()
    previous = None
    event = None
    for _ in range(3):
        service = _service(fixture)
        event = _event(fixture, event)
        service.prime_catalog(previous_global=previous, previous_mission=previous)
        pending = _cold(service.prepare_pending_transition(event, previous_global=previous, previous_mission=previous))
        assert type(pending) is PendingIntegrityTransitionV1 and pending.time_bundle is None
        anchor = _cold(service.prepare_anchor_statement(pending))
        assert type(anchor) is AnchorStatementRecordV1
        receipts = service.register_anchor_statement(anchor, pending=pending)
        candidate = _cold(service.prepare_checkpoint_candidate(pending, anchor, anchor_receipts=receipts))
        assert type(candidate) is CheckpointCandidateRecordV1 and candidate.anchor_bundle is None
        service.publish_checkpoint(candidate)
        floor, blobs = service.observe_current_floor(pending, candidate)
        final = _cold(FinalizedIntegrityTransitionV1(
            pending_record_id=pending.record_id, checkpoint_candidate_record_id=candidate.record_id,
            event_digest=event.event_digest, external_head_floor=floor, provider_evidence=blobs,
            acceptance_mode=INTEGRITY_ACCEPTANCE_MODE_QUALIFIED_SIGNED_V1,
        ))
        phases = (
            IntegrityLineageV1(pending=pending),
            IntegrityLineageV1(pending=pending, anchor_statement=anchor),
            IntegrityLineageV1(pending=pending, anchor_statement=anchor, checkpoint_candidate=candidate),
            IntegrityLineageV1(pending=pending, anchor_statement=anchor, checkpoint_candidate=candidate,
                               finalization=final),
        )
        for lineage in phases:
            fresh = reconstruct_qualified_lineage_v1(time_profile=fixture.time_fixture.profile,
                head_profile=fixture.profile, lineage=lineage, previous_global=previous)
            assert fresh.decision_time.event_digest == event.event_digest
        assert fresh.current_catalog.external_floor == final.external_head_floor
        validate_finalized_integrity_transition(phases[-1], event=event,
            previous_global=previous, previous_mission=previous)
        previous = phases[-1]


def test_qualified_facade_finalizes_and_cold_store_reauthenticates(tmp_path, monkeypatch):
    from etzio.kernel.integrity_transition import ModeledIntegrityFinalizingEventStoreV1
    from etzio.kernel.store import SQLiteEventStore

    fixture = _head_fixture()
    path = tmp_path / "state.sqlite3"
    events = []
    for index in range(2):
        service = _service(fixture)
        with SQLiteEventStore(path) as store:
            store.enroll_modeled_integrity(service_instance_id=service.service_instance_id,
                environment_id=service.environment_id, validation_policy=service.validation_policy,
                authority_binding=service.authority_binding)
            store.enroll_qualified_acceptance(qualified_time_profile=service.time_profile,
                                              qualified_head_profile=service.head_profile)
            facade = ModeledIntegrityFinalizingEventStoreV1(store, service)
            from etzio.protocol import content_id

            template = _event(fixture)
            event = EventV1.create(mission_id=content_id("qualified_test_mission", {"index": index}),
                seq=0, kind=template.kind, unit=template.unit, authority_id=template.authority_id,
                target_id=template.target_id, decision_time=template.decision_time + index,
                payload=dict(template.payload), prev_digest=GENESIS_DIGEST)
            events.append(event)
            assert facade.append(event, expected_head=event.prev_digest) == event
            assert store.load_integrity_lineage(event.event_digest).finalization is not None

    def no_acquisition(*args, **kwargs):
        raise AssertionError("cold replay must not call the fixture service")

    monkeypatch.setattr(RepositoryOwnedQualifiedFixtureIntegrityServiceV1, "prepare_pending_transition", no_acquisition)
    with SQLiteEventStore(path) as store:
        assert all(store.load(value.mission_id) == (value,) for value in events)
        assert store.load_integrity_lineage(event.event_digest).finalization is not None


def test_complete_qualified_receipt_vertical_and_staging_free_restart(tmp_path):
    import shutil

    from test_integrity_receipt_vertical_v1 import _admit, _prepare_to_receipt

    from etzio.kernel.integrity_transition import ModeledIntegrityFinalizingEventStoreV1
    from etzio.kernel.store import SQLiteEventStore

    fixture = _head_fixture()
    service = _service(fixture)
    path = tmp_path / "receipt.sqlite3"
    with SQLiteEventStore(path) as store:
        store.enroll_modeled_integrity(service_instance_id=service.service_instance_id,
            environment_id=service.environment_id, validation_policy=service.validation_policy,
            authority_binding=service.authority_binding)
        store.enroll_qualified_acceptance(qualified_time_profile=service.time_profile,
                                          qualified_head_profile=service.head_profile)
        facade = ModeledIntegrityFinalizingEventStoreV1(store, service)
        prepared = _prepare_to_receipt(tmp_path / "receipt", facade)
        # Interleave another mission before returning to the receipt mission. Its global
        # predecessor and mission predecessor now name different signed checkpoints.
        side = _event(fixture)
        side = EventV1.create(mission_id=side.mission_id, seq=0, kind=side.kind, unit=side.unit,
            authority_id=side.authority_id, target_id=side.target_id, decision_time=2_000_000_002,
            payload=dict(side.payload), prev_digest=GENESIS_DIGEST)
        assert facade.append(side, expected_head=side.prev_digest) == side
        admitted = _admit(prepared, event_store=facade)
        assert not admitted.admission.replayed
        retained = tuple(store.load_integrity_lineage(event.event_digest) for event in store.load(prepared.mission_id))
        assert len(retained) == 14
        assert all(lineage.finalization is not None for lineage in retained)
        assert [lineage.pending.instance_sequence for lineage in retained] == [*range(13), 14]
        assert [lineage.pending.event_seq for lineage in retained] == list(range(14))
        last = retained[-1].checkpoint_candidate.checkpoint
        side_checkpoint = store.load_integrity_lineage(side.event_digest).checkpoint_candidate.checkpoint
        assert last.previous_checkpoint_id == side_checkpoint.checkpoint_id
        assert last.previous_mission_checkpoint_id == retained[-2].checkpoint_candidate.checkpoint.checkpoint_id
    shutil.rmtree(tmp_path / "receipt" / "evidence")
    import subprocess
    import sys

    script = """
import sys
from etzio.kernel.store import SQLiteEventStore
from etzio.kernel.integrity_adapters_v1 import (
    RepositoryOwnedDeterministicTrustedTimeAdapterV1, RepositoryOwnedDeterministicRevocationAdapterV1)
from etzio.kernel.head_authority_adapters_v1 import (
    RepositoryOwnedDeterministicHeadAnchorAdapterV1, RepositoryOwnedDeterministicHeadCatalogAdapterV1,
    RepositoryOwnedDeterministicHeadMonitorAdapterV1)
def forbidden(*args, **kwargs):
    raise AssertionError('cold replay attempted provider acquisition')
for cls in (RepositoryOwnedDeterministicTrustedTimeAdapterV1, RepositoryOwnedDeterministicRevocationAdapterV1,
            RepositoryOwnedDeterministicHeadAnchorAdapterV1, RepositoryOwnedDeterministicHeadCatalogAdapterV1,
            RepositoryOwnedDeterministicHeadMonitorAdapterV1):
    cls.acquire = forbidden
with SQLiteEventStore(sys.argv[1]) as store:
    events = store.load(sys.argv[2])
    assert len(events) == 14
    assert store.load_integrity_lineage(events[-1].event_digest).finalization is not None
    print(events[-1].event_digest)
"""
    child = subprocess.run([sys.executable, "-c", script, str(path), prepared.mission_id],
                           check=True, capture_output=True, text=True, timeout=90)
    assert child.stdout.strip() == admitted.admission.event.event_digest
    with SQLiteEventStore(path) as store:
        facade = ModeledIntegrityFinalizingEventStoreV1(store, _service(fixture))
        assert len(facade.load(prepared.mission_id)) == 14
        for lineage in retained:
            assert store.load_integrity_lineage(lineage.pending.event_digest) == lineage
        replayed = _admit(prepared, event_store=facade)
        assert replayed.admission.replayed
        assert replayed.finalization == admitted.finalization


def _enroll_store(store, service):
    store.enroll_modeled_integrity(service_instance_id=service.service_instance_id,
        environment_id=service.environment_id, validation_policy=service.validation_policy,
        authority_binding=service.authority_binding)
    store.enroll_qualified_acceptance(qualified_time_profile=service.time_profile,
                                      qualified_head_profile=service.head_profile)


class _InterruptedPort:
    def __init__(self, delegate, operation, after, error_type=RuntimeError):
        self.delegate, self.operation, self.after = delegate, operation, after
        self.error_type = error_type
        self.fired = False
        self.result = None

    def __getattr__(self, name):
        value = getattr(self.delegate, name)
        if name != self.operation:
            return value

        def call(*args, **kwargs):
            if not self.fired:
                self.fired = True
                if self.after:
                    self.result = value(*args, **kwargs)
                raise self.error_type("qualified fixture injected interruption")
            return value(*args, **kwargs)

        return call



@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("port,operation", [
    ("store", "append_pending_integrity_event"),
    ("store", "retain_integrity_anchor_statement"),
    ("store", "retain_integrity_checkpoint_candidate"),
    ("store", "finalize_integrity_transition"),
    ("service", "register_anchor_statement"),
    ("service", "publish_checkpoint"),
])
def test_interrupted_phase_recovers_with_a_fresh_service(tmp_path, port, operation, after):
    from etzio.kernel.integrity_transition import IntegrityFinalityPendingError, ModeledIntegrityFinalizingEventStoreV1
    from etzio.kernel.store import EventStoreError, PendingIntegrityTransitionError, SQLiteEventStore

    fixture = _head_fixture()
    path = tmp_path / "crash.sqlite3"
    service = _service(fixture)
    event = _event(fixture)
    with SQLiteEventStore(path) as store:
        _enroll_store(store, service)
        interrupted = _InterruptedPort(store if port == "store" else service, operation, after,
                                       EventStoreError if port == "store" else RuntimeError)
        facade = ModeledIntegrityFinalizingEventStoreV1(
            interrupted if port == "store" else store, interrupted if port == "service" else service)
        expected = EventStoreError if port == "store" else IntegrityFinalityPendingError
        with pytest.raises(expected):
            facade.append(event, expected_head=event.prev_digest)
        retained = store.load_integrity_lineage(event.event_digest)
        if retained is not None and retained.finalization is None:
            with pytest.raises(PendingIntegrityTransitionError):
                store.load(event.mission_id)
    with SQLiteEventStore(path) as store:
        facade = ModeledIntegrityFinalizingEventStoreV1(store, _service(fixture))
        assert facade.append(event, expected_head=event.prev_digest) == event
        completed = store.load_integrity_lineage(event.event_digest)
        assert completed.finalization is not None
        if retained is not None:
            for attribute in ("pending", "anchor_statement", "checkpoint_candidate", "finalization"):
                record = getattr(retained, attribute)
                if record is not None:
                    assert record.to_canonical_bytes() == getattr(completed, attribute).to_canonical_bytes()
        if port == "service" and after and operation == "register_anchor_statement":
            assert completed.checkpoint_candidate.provider_evidence == interrupted.result
        assert facade.append(event, expected_head=event.prev_digest) == event
        assert store.load(event.mission_id) == (event,)


@pytest.mark.parametrize("disposition", ["retry_authorized", "instance_sealed"])
def test_qualified_finality_preserves_governed_recovery(tmp_path, disposition):
    from test_blocked_finality_lifecycle_v1 import _time_source
    from test_blocked_finality_storage_v3 import _recovery_profile, _sign

    from etzio.kernel.integrity_transition import (
        GovernedBlockedFinalityBindingV1,
        IntegrityFinalityBlockedError,
        IntegrityInstanceSealedError,
        IntegrityRecoveryNotAuthorizedError,
        ModeledIntegrityFinalizingEventStoreV1,
    )
    from etzio.kernel.store import PendingIntegrityTransitionError, SQLiteEventStore

    fixture = _head_fixture()
    service = _service(fixture)
    profile, signer = _recovery_profile(service.service_instance_id, service.environment_id, service.authority_binding)
    binding = GovernedBlockedFinalityBindingV1(profile=profile, time_source=_time_source())
    event = _event(fixture)

    class Blocking:
        def __getattr__(self, name):
            return getattr(service, name)

        def register_anchor_statement(self, *args, **kwargs):
            raise IntegrityFinalityBlockedError("modeled_anchor_equivocation", "deterministic fixture block")

    with SQLiteEventStore(tmp_path / "governed.sqlite3") as store:
        _enroll_store(store, service)
        facade = ModeledIntegrityFinalizingEventStoreV1(store, Blocking(), blocked_finality=binding)
        with pytest.raises(IntegrityFinalityBlockedError):
            facade.append(event, expected_head=event.prev_digest)
        observation = store.load_blocked_finality_observations(event.event_digest)[-1]
        assert observation.unresolved_phase == "anchor_statement_ready"
        assert observation.blocked_operation == "register_anchor_statement"
        with pytest.raises(IntegrityRecoveryNotAuthorizedError):
            facade.recover_pending_transition()
        with pytest.raises(PendingIntegrityTransitionError):
            store.load(event.mission_id)
        store.retain_governed_recovery_decision(_sign(profile, signer, observation, disposition))
        recovered = ModeledIntegrityFinalizingEventStoreV1(store, _service(fixture), blocked_finality=binding)
        if disposition == "retry_authorized":
            assert recovered.load(event.mission_id) == (event,)
            assert store.load_integrity_lineage(event.event_digest).finalization is not None
        else:
            with pytest.raises(IntegrityInstanceSealedError):
                recovered.load(event.mission_id)
            assert store.load_integrity_lineage(event.event_digest).finalization is None
            assert store.load_integrity_event(event.event_digest) == event


def test_two_qualified_facades_converge_after_cold_recovery(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    from test_integrity_recovery_matrix_v1 import _SynchronizedRecoveryStore

    from etzio.kernel.integrity_transition import ModeledIntegrityFinalizingEventStoreV1
    from etzio.kernel.store import SQLiteEventStore

    fixture = _head_fixture()
    event = _event(fixture)
    path = tmp_path / "concurrent.sqlite3"
    with SQLiteEventStore(path) as store:
        service = _service(fixture)
        _enroll_store(store, service)
        pending = service.prepare_pending_transition(event, previous_global=None, previous_mission=None)
        store.append_pending_integrity_event(event, expected_head=event.prev_digest, pending=_cold(pending))
    barrier = Barrier(2)

    def recover():
        with SQLiteEventStore(path) as store:
            facade = ModeledIntegrityFinalizingEventStoreV1(
                _SynchronizedRecoveryStore(store, barrier), _service(fixture))
            final = facade.recover_pending_transition()
            assert final is not None
            return store.load_integrity_lineage(event.event_digest).to_canonical_bytes()

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(recover) for _ in range(2)]
        results = [future.result(timeout=60) for future in futures]
    assert results[0] == results[1]
    with SQLiteEventStore(path) as store:
        assert store.load(event.mission_id) == (event,)
        assert store.load_unresolved_integrity_transition() is None
