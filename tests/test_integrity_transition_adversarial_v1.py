"""Deterministic known-bads for modeled integrity providers and recovery."""

from __future__ import annotations

import base64
import copy
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import pytest

from etzio.integrity_v1 import (
    EXTERNAL_FLOOR_EVIDENCE_KIND,
    HEAD_ANCHOR_RECEIPT_EVIDENCE_KIND,
    MAX_REVOCATION_VIEWS,
    HeadCheckpointFloorV1,
    IntegrityValidationPolicyV1,
    SignedHeadCheckpointV1,
)
from etzio.kernel.events_v1 import GENESIS_DIGEST, EventV1
from etzio.kernel.integrity_transition import (
    AnchorStatementRecordV1,
    CheckpointCandidateRecordV1,
    FinalizedIntegrityTransitionV1,
    IntegrityFinalityBlockedError,
    IntegrityFinalityPendingError,
    IntegrityLineageV1,
    IntegrityTransitionError,
    ModeledIntegrityAuthorityBindingV1,
    ModeledIntegrityFinalizingEventStoreV1,
    PendingIntegrityTransitionV1,
    ProviderEvidenceBlobV1,
    RepositoryOwnedDeterministicModeledIntegrityServiceV1,
    validate_finalization,
)
from etzio.kernel.store import (
    EvidenceVaultCapacityError,
    PendingIntegrityTransitionError,
    SQLiteEventStore,
    StoreBusyError,
    StoreCapacityError,
    StoreOperationalError,
)
from etzio.protocol import canonical_dumps, content_id

_SERVICE_INSTANCE_ID = "Etzio.adversarial-fixture"
_ENVIRONMENT_ID = "fixture.adversarial-control-plane"
_PROVIDER_METHODS = frozenset(
    {
        "observe_current_floor",
        "prepare_anchor_statement",
        "prepare_checkpoint_candidate",
        "prepare_pending_transition",
        "prime_catalog",
        "publish_checkpoint",
        "register_anchor_statement",
    }
)


class _InstrumentedService:
    """Observe provider transaction state and inject deterministic failures."""

    def __init__(
        self,
        delegate: RepositoryOwnedDeterministicModeledIntegrityServiceV1,
        store: SQLiteEventStore,
        *,
        fail_method: str | None = None,
        failure_factory: Callable[[], BaseException] | None = None,
        failures_remaining: int | None = 0,
    ) -> None:
        self._delegate = delegate
        self._store = store
        self._fail_method = fail_method
        self._failure_factory = failure_factory
        self._failures_remaining = failures_remaining
        self.calls: list[tuple[str, bool]] = []
        self.service_instance_id = delegate.service_instance_id
        self.environment_id = delegate.environment_id
        self.validation_policy = delegate.validation_policy

    def __getattr__(self, name: str) -> object:
        target = getattr(self._delegate, name)
        if name not in _PROVIDER_METHODS or not callable(target):
            return target

        def observed(*args: object, **kwargs: object) -> object:
            self.calls.append(
                (name, self._store._connection.in_transaction)  # noqa: SLF001
            )
            should_fail = (
                name == self._fail_method
                and self._failure_factory is not None
                and (self._failures_remaining is None or self._failures_remaining > 0)
            )
            if should_fail:
                if self._failures_remaining is not None:
                    self._failures_remaining -= 1
                raise self._failure_factory()
            return target(*args, **kwargs)

        return observed


class _MalformedReturnService:
    def __init__(
        self,
        delegate: RepositoryOwnedDeterministicModeledIntegrityServiceV1,
        *,
        method: str,
        result: object,
    ) -> None:
        self._delegate = delegate
        self._method = method
        self._result = result

    def __getattr__(self, name: str) -> object:
        if name == self._method:
            return lambda *args, **kwargs: self._result
        return getattr(self._delegate, name)


class _LostPublicationResponseService:
    def __init__(
        self,
        delegate: RepositoryOwnedDeterministicModeledIntegrityServiceV1,
    ) -> None:
        self._delegate = delegate
        self._lose_response_once = True

    def __getattr__(self, name: str) -> object:
        return getattr(self._delegate, name)

    def publish_checkpoint(
        self,
        candidate: CheckpointCandidateRecordV1,
    ) -> None:
        self._delegate.publish_checkpoint(candidate)
        if self._lose_response_once:
            self._lose_response_once = False
            raise RuntimeError("simulated lost response after publication")


def _digest(label: str) -> str:
    return content_id(
        "integrity_transition_adversarial_test",
        {"label": label},
    )


def _policy() -> IntegrityValidationPolicyV1:
    return IntegrityValidationPolicyV1(
        decision_policy_id=_digest("decision-policy"),
        decision_time_policy_id=_digest("decision-time-policy"),
        checkpoint_time_policy_id=_digest("checkpoint-time-policy"),
        anchor_policy_id=_digest("anchor-policy"),
        required_revocation_namespaces=frozenset({"authority", "verifier"}),
        max_decision_uncertainty_seconds=0,
        max_checkpoint_uncertainty_seconds=0,
    )


def _service(
    *,
    seed: bytes = b"integrity-transition-adversarial-v1",
) -> RepositoryOwnedDeterministicModeledIntegrityServiceV1:
    return RepositoryOwnedDeterministicModeledIntegrityServiceV1.deterministic(
        seed=seed,
        service_instance_id=_SERVICE_INSTANCE_ID,
        environment_id=_ENVIRONMENT_ID,
        validation_policy=_policy(),
    )


def _event(label: str) -> EventV1:
    return EventV1.create(
        mission_id=_digest(f"{label}-mission"),
        seq=0,
        kind="mission_admission_refused",
        unit="AQUILA",
        authority_id=_digest(f"{label}-authority"),
        target_id=_digest(f"{label}-target"),
        decision_time=2_000_000_000,
        payload={
            "reason_code": "authority_expired",
            "stage": "admission",
        },
        prev_digest=GENESIS_DIGEST,
    )


def _successor_event(previous: EventV1) -> EventV1:
    return EventV1.create(
        mission_id=previous.mission_id,
        seq=previous.seq + 1,
        kind="mission_admission_refused",
        unit="AQUILA",
        authority_id=previous.authority_id,
        target_id=previous.target_id,
        decision_time=previous.decision_time + 1,
        payload={
            "reason_code": "authority_expired",
            "stage": "admission",
        },
        prev_digest=previous.event_digest,
    )


def _prepare_candidate(
    service: RepositoryOwnedDeterministicModeledIntegrityServiceV1,
    event: EventV1,
) -> tuple[
    PendingIntegrityTransitionV1,
    AnchorStatementRecordV1,
    CheckpointCandidateRecordV1,
]:
    pending = service.prepare_pending_transition(
        event,
        previous_global=None,
        previous_mission=None,
    )
    anchor = service.prepare_anchor_statement(pending)
    receipts = service.register_anchor_statement(anchor)
    candidate = service.prepare_checkpoint_candidate(
        pending,
        anchor,
        anchor_receipts=receipts,
    )
    return pending, anchor, candidate


def _finalize_candidate(
    service: RepositoryOwnedDeterministicModeledIntegrityServiceV1,
    event: EventV1,
    pending: PendingIntegrityTransitionV1,
    anchor: AnchorStatementRecordV1,
    candidate: CheckpointCandidateRecordV1,
) -> IntegrityLineageV1:
    service.publish_checkpoint(candidate)
    floor, evidence = service.observe_current_floor(pending, candidate)
    return IntegrityLineageV1(
        pending=pending,
        anchor_statement=anchor,
        checkpoint_candidate=candidate,
        finalization=FinalizedIntegrityTransitionV1(
            pending_record_id=pending.record_id,
            checkpoint_candidate_record_id=candidate.record_id,
            event_digest=event.event_digest,
            external_head_floor=floor,
            provider_evidence=evidence,
        ),
    )


def _modeled_provider_content(
    *,
    evidence_kind: str,
    source_id: str,
    claim: dict[str, object],
) -> bytes:
    return canonical_dumps(
        {
            "claim": claim,
            "evidence_kind": evidence_kind,
            "qualification": "repository_owned_deterministic_fixture_only",
            "source_id": source_id,
            "trust_boundary": ("not_trustworthy_utc_external_durability_or_independence"),
        }
    )


def _state_path(tmp_path: Path, label: str) -> Path:
    parent = tmp_path / label
    parent.mkdir(mode=0o700)
    return parent / "events.sqlite3"


def _facade(
    store: SQLiteEventStore,
    service: object,
) -> ModeledIntegrityFinalizingEventStoreV1:
    return ModeledIntegrityFinalizingEventStoreV1(store, service)


def test_anchor_registration_binds_exact_idempotency_key_to_request() -> None:
    service = _service()
    pending = service.prepare_pending_transition(
        _event("anchor-equivocation"),
        previous_global=None,
        previous_mission=None,
    )
    anchor = service.prepare_anchor_statement(pending)
    receipts = service.register_anchor_statement(anchor)
    assert service.register_anchor_statement(anchor) == receipts

    conflicting_body = anchor.registration_body
    conflicting_body["target_id"] = _digest("substituted-target")
    conflicting_request = canonical_dumps(conflicting_body)
    with pytest.raises(IntegrityTransitionError) as malformed:
        replace(
            anchor,
            registration_request=conflicting_request,
        )
    assert malformed.value.reason_code == "anchor_statement_binding_mismatch"

    # Simulate a hostile provider transport that bypassed local construction.  The
    # provider's retained idempotency-key mapping must independently catch the byte
    # conflict and preserve the original receipts.
    equivocating_anchor = copy.copy(anchor)
    object.__setattr__(
        equivocating_anchor,
        "registration_request",
        conflicting_request,
    )
    with pytest.raises(IntegrityFinalityBlockedError) as equivocation:
        service.register_anchor_statement(equivocating_anchor)
    assert equivocation.value.reason_code == "modeled_anchor_equivocation"
    assert service.register_anchor_statement(anchor) == receipts


def test_checkpoint_publication_rejects_identity_and_lineage_conflicts() -> None:
    service = _service()
    pending, _anchor, candidate = _prepare_candidate(
        service,
        _event("checkpoint-primary"),
    )
    service.publish_checkpoint(candidate)
    service.publish_checkpoint(candidate)

    conflicting_signed = SignedHeadCheckpointV1(
        envelope_bytes=candidate.signed_checkpoint.envelope_bytes,
        key_id=candidate.signed_checkpoint.key_id,
        signature_b64=base64.b64encode(b"\x00" * 64).decode("ascii"),
    )
    conflicting_candidate = CheckpointCandidateRecordV1(
        pending_record_id=candidate.pending_record_id,
        anchor_statement_record_id=candidate.anchor_statement_record_id,
        event_digest=candidate.event_digest,
        signed_checkpoint=conflicting_signed,
        checkpoint_trust_store=candidate.checkpoint_trust_store,
        provider_evidence=candidate.provider_evidence,
    )
    with pytest.raises(IntegrityFinalityBlockedError) as identity_conflict:
        service.publish_checkpoint(conflicting_candidate)
    assert identity_conflict.value.reason_code == "modeled_checkpoint_identity_conflict"

    isolated_clone = _service()
    _other_pending, _other_anchor, competing = _prepare_candidate(
        isolated_clone,
        _event("checkpoint-competing-lineage"),
    )
    assert competing.checkpoint.checkpoint_id != candidate.checkpoint.checkpoint_id
    with pytest.raises(IntegrityFinalityBlockedError) as lineage_conflict:
        service.publish_checkpoint(competing)
    assert lineage_conflict.value.reason_code == "modeled_catalog_compare_and_set_failed"

    floor, _ = service.observe_current_floor(pending, candidate)
    assert floor.checkpoint_id == candidate.checkpoint.checkpoint_id


def test_stale_and_substituted_floor_claims_fail_before_finalization() -> None:
    service = _service()
    event = _event("floor-known-bads")
    pending, anchor, candidate = _prepare_candidate(service, event)
    service.publish_checkpoint(candidate)
    current_floor, current_evidence = service.observe_current_floor(
        pending,
        candidate,
    )
    stale_evidence_ids = {reference.evidence_id for reference in pending.prior_head_floor.evidence}
    stale_evidence = tuple(blob for blob in pending.provider_evidence if blob.evidence_id in stale_evidence_ids)
    substituted_floor = replace(
        current_floor,
        checkpoint_id=_digest("substituted-global-checkpoint"),
        mission_checkpoint_id=_digest("substituted-mission-checkpoint"),
    )
    known_bads: tuple[
        tuple[
            HeadCheckpointFloorV1,
            tuple[ProviderEvidenceBlobV1, ...],
        ],
        ...,
    ] = (
        (
            pending.prior_head_floor,
            stale_evidence,
        ),
        (
            substituted_floor,
            current_evidence,
        ),
    )
    for floor, evidence in known_bads:
        with pytest.raises(IntegrityTransitionError) as refused:
            FinalizedIntegrityTransitionV1(
                pending_record_id=pending.record_id,
                checkpoint_candidate_record_id=candidate.record_id,
                event_digest=event.event_digest,
                external_head_floor=floor,
                provider_evidence=evidence,
            )
        assert refused.value.reason_code == "modeled_provider_evidence_claim_mismatch"


def test_arbitrary_unsigned_floor_blobs_cannot_model_current_head() -> None:
    service = _service()
    event = _event("arbitrary-floor-claims")
    pending, _anchor, candidate = _prepare_candidate(service, event)
    service.publish_checkpoint(candidate)
    current_floor, _current_evidence = service.observe_current_floor(
        pending,
        candidate,
    )
    fake_evidence = tuple(
        ProviderEvidenceBlobV1.from_content(
            evidence_kind=EXTERNAL_FLOOR_EVIDENCE_KIND,
            source_id=f"fixture.head-floor.{suffix}",
            content=_modeled_provider_content(
                evidence_kind=EXTERNAL_FLOOR_EVIDENCE_KIND,
                source_id=f"fixture.head-floor.{suffix}",
                claim={"attacker_assertion": "current"},
            ),
        )
        for suffix in ("a", "b")
    )
    fake_floor = replace(
        current_floor,
        evidence=tuple(blob.reference for blob in fake_evidence),
    )

    with pytest.raises(IntegrityTransitionError) as refused:
        FinalizedIntegrityTransitionV1(
            pending_record_id=pending.record_id,
            checkpoint_candidate_record_id=candidate.record_id,
            event_digest=event.event_digest,
            external_head_floor=fake_floor,
            provider_evidence=fake_evidence,
        )
    assert refused.value.reason_code == "modeled_provider_evidence_claim_mismatch"


def test_fake_anchor_receipt_blobs_cannot_be_signed_into_checkpoint() -> None:
    service = _service()
    event = _event("fake-anchor-receipts")
    pending = service.prepare_pending_transition(
        event,
        previous_global=None,
        previous_mission=None,
    )
    anchor = service.prepare_anchor_statement(pending)
    fake_receipts = tuple(
        ProviderEvidenceBlobV1.from_content(
            evidence_kind=HEAD_ANCHOR_RECEIPT_EVIDENCE_KIND,
            source_id=f"fixture.anchor.{suffix}",
            content=_modeled_provider_content(
                evidence_kind=HEAD_ANCHOR_RECEIPT_EVIDENCE_KIND,
                source_id=f"fixture.anchor.{suffix}",
                claim={"attacker_assertion": "included"},
            ),
        )
        for suffix in ("a", "b")
    )

    with pytest.raises(IntegrityTransitionError) as refused:
        service.prepare_checkpoint_candidate(
            pending,
            anchor,
            anchor_receipts=fake_receipts,
        )
    assert refused.value.reason_code == "modeled_provider_evidence_claim_mismatch"


def test_malformed_modeled_provider_blob_is_not_an_opaque_receipt() -> None:
    service = _service()
    event = _event("malformed-anchor-receipts")
    pending = service.prepare_pending_transition(
        event,
        previous_global=None,
        previous_mission=None,
    )
    anchor = service.prepare_anchor_statement(pending)
    malformed = tuple(
        ProviderEvidenceBlobV1.from_content(
            evidence_kind=HEAD_ANCHOR_RECEIPT_EVIDENCE_KIND,
            source_id=f"fixture.anchor.{suffix}",
            content=f"not-json-{suffix}".encode("ascii"),
        )
        for suffix in ("a", "b")
    )

    with pytest.raises(IntegrityTransitionError) as refused:
        service.prepare_checkpoint_candidate(
            pending,
            anchor,
            anchor_receipts=malformed,
        )
    assert refused.value.reason_code == "invalid_modeled_provider_evidence"


class _NeverIterateRevocationFloors:
    def __iter__(self) -> object:
        raise AssertionError("hostile revocation floors were iterated")


@pytest.mark.parametrize(
    "revocation_floors",
    (
        [],
        _NeverIterateRevocationFloors(),
    ),
)
def test_revocation_floor_container_is_exact_tuple_before_iteration(
    revocation_floors: object,
) -> None:
    pending = _service().prepare_pending_transition(
        _event("revocation-container"),
        previous_global=None,
        previous_mission=None,
    )
    with pytest.raises(IntegrityTransitionError) as refused:
        replace(
            pending,
            revocation_floors=revocation_floors,
        )
    assert refused.value.reason_code == "invalid_revocation_floor_set"


def test_revocation_floor_tuple_count_is_bounded_before_entries_are_read() -> None:
    pending = _service().prepare_pending_transition(
        _event("revocation-count"),
        previous_global=None,
        previous_mission=None,
    )
    hostile = (object(),) * (MAX_REVOCATION_VIEWS + 1)
    with pytest.raises(IntegrityTransitionError) as refused:
        replace(
            pending,
            revocation_floors=hostile,
        )
    assert refused.value.reason_code == "invalid_revocation_floor_set"


def test_anchor_time_evidence_count_is_rejected_before_entries_are_read() -> None:
    service = _service()
    pending = service.prepare_pending_transition(
        _event("anchor-time-evidence-count"),
        previous_global=None,
        previous_mission=None,
    )
    anchor = service.prepare_anchor_statement(pending)
    hostile = (object(),) * (len(anchor.time_evidence) + 1)
    with pytest.raises(IntegrityTransitionError) as refused:
        replace(
            anchor,
            time_evidence=hostile,
        )
    assert refused.value.reason_code == "invalid_checkpoint_time_evidence"


def test_modeled_authority_binding_retains_and_cross_checks_full_trust() -> None:
    service = _service(seed=b"modeled-authority-binding-primary")
    binding = service.authority_binding
    reconstructed = ModeledIntegrityAuthorityBindingV1.from_canonical_bytes(binding.to_canonical_bytes())
    assert reconstructed == binding
    assert reconstructed.binding_id == binding.binding_id
    assert reconstructed.trust_snapshot_id == service.trust_store.snapshot_id

    different_seed = _service(seed=b"modeled-authority-binding-substituted")
    assert different_seed.service_instance_id == service.service_instance_id
    assert different_seed.environment_id == service.environment_id
    assert different_seed.validation_policy == service.validation_policy
    assert different_seed.authority_binding.binding_id != binding.binding_id

    body = reconstructed.to_body()
    body["trust_snapshot_id"] = _digest("substituted-trust-snapshot")
    with pytest.raises(IntegrityTransitionError) as refused:
        ModeledIntegrityAuthorityBindingV1.from_canonical_bytes(canonical_dumps(body))
    assert refused.value.reason_code == "invalid_modeled_integrity_authority_binding"


def test_second_mission_event_zero_extends_exact_instance_global_head() -> None:
    service = _service(seed=b"modeled-cross-mission-global-continuity")
    first_event = _event("cross-mission-first")
    first_pending, first_anchor, first_candidate = _prepare_candidate(
        service,
        first_event,
    )
    service.publish_checkpoint(first_candidate)
    first_floor, first_floor_evidence = service.observe_current_floor(
        first_pending,
        first_candidate,
    )
    first_partial = IntegrityLineageV1(
        pending=first_pending,
        anchor_statement=first_anchor,
        checkpoint_candidate=first_candidate,
    )
    first_finalization = FinalizedIntegrityTransitionV1(
        pending_record_id=first_pending.record_id,
        checkpoint_candidate_record_id=first_candidate.record_id,
        event_digest=first_event.event_digest,
        external_head_floor=first_floor,
        provider_evidence=first_floor_evidence,
    )
    validate_finalization(
        first_event,
        first_partial,
        first_finalization,
        previous_global=None,
        previous_mission=None,
    )
    first_lineage = IntegrityLineageV1(
        pending=first_pending,
        anchor_statement=first_anchor,
        checkpoint_candidate=first_candidate,
        finalization=first_finalization,
    )

    second_event = _event("cross-mission-second")
    second_pending = service.prepare_pending_transition(
        second_event,
        previous_global=first_lineage,
        previous_mission=None,
    )
    assert second_pending.instance_sequence == 1
    assert second_pending.prior_head_floor.checkpoint_id == first_candidate.checkpoint.checkpoint_id
    assert second_pending.prior_head_floor.instance_sequence == 0
    assert second_pending.prior_head_floor.mission_event_seq == -1

    second_anchor = service.prepare_anchor_statement(second_pending)
    second_candidate = service.prepare_checkpoint_candidate(
        second_pending,
        second_anchor,
        anchor_receipts=service.register_anchor_statement(second_anchor),
    )
    service.publish_checkpoint(second_candidate)
    assert second_candidate.checkpoint.instance_sequence == 1
    assert second_candidate.checkpoint.previous_checkpoint_id == first_candidate.checkpoint.checkpoint_id


def test_catalog_prime_reconciles_only_exact_published_direct_successor() -> None:
    seed = b"modeled-catalog-lost-publication-response"
    service = _service(seed=seed)
    first_event = _event("catalog-recovery-first")
    first_pending, first_anchor, first_candidate = _prepare_candidate(
        service,
        first_event,
    )
    first_lineage = _finalize_candidate(
        service,
        first_event,
        first_pending,
        first_anchor,
        first_candidate,
    )

    second_event = _successor_event(first_event)
    second_pending = service.prepare_pending_transition(
        second_event,
        previous_global=first_lineage,
        previous_mission=first_lineage,
    )
    second_anchor = service.prepare_anchor_statement(second_pending)
    second_candidate = service.prepare_checkpoint_candidate(
        second_pending,
        second_anchor,
        anchor_receipts=service.register_anchor_statement(second_anchor),
    )
    service.publish_checkpoint(second_candidate)

    # A response can be lost after publication. Recovery primes from the retained
    # predecessor without rolling the catalog back over the exact current successor.
    service.prime_catalog(
        previous_global=first_lineage,
        previous_mission=first_lineage,
    )
    service.publish_checkpoint(second_candidate)
    floor, _ = service.observe_current_floor(
        second_pending,
        second_candidate,
    )
    assert floor.checkpoint_id == second_candidate.checkpoint.checkpoint_id

    unrelated_service = _service(seed=seed)
    unrelated_event = _event("catalog-unrelated-predecessor")
    unrelated_pending, unrelated_anchor, unrelated_candidate = _prepare_candidate(
        unrelated_service,
        unrelated_event,
    )
    unrelated_lineage = _finalize_candidate(
        unrelated_service,
        unrelated_event,
        unrelated_pending,
        unrelated_anchor,
        unrelated_candidate,
    )
    with pytest.raises(IntegrityFinalityBlockedError) as blocked:
        service.prime_catalog(
            previous_global=unrelated_lineage,
            previous_mission=unrelated_lineage,
        )
    assert blocked.value.reason_code == "modeled_catalog_global_conflict"


def test_facade_never_calls_provider_inside_sqlite_transaction(
    tmp_path: Path,
) -> None:
    event = _event("provider-transaction-state")
    with SQLiteEventStore(_state_path(tmp_path, "provider-transaction-state")) as store:
        observed = _InstrumentedService(_service(), store)
        facade = _facade(store, observed)
        assert facade.append(event, expected_head=GENESIS_DIGEST) == event

        assert [name for name, _ in observed.calls] == [
            "prepare_pending_transition",
            "prime_catalog",
            "prepare_anchor_statement",
            "register_anchor_statement",
            "prepare_checkpoint_candidate",
            "publish_checkpoint",
            "observe_current_floor",
        ]
        assert all(not in_transaction for _, in_transaction in observed.calls)
        assert facade.require_finalized(event.event_digest).event_digest == event.event_digest


def test_facade_load_recovers_anchor_phase_before_exposing_history(
    tmp_path: Path,
) -> None:
    event = _event("load-recovers-anchor")
    with SQLiteEventStore(_state_path(tmp_path, "load-recovers-anchor")) as store:
        interrupted = _InstrumentedService(
            _service(),
            store,
            fail_method="register_anchor_statement",
            failure_factory=lambda: RuntimeError("simulated provider interruption"),
            failures_remaining=1,
        )
        facade = _facade(store, interrupted)
        with pytest.raises(IntegrityFinalityPendingError) as initial:
            facade.append(event, expected_head=GENESIS_DIGEST)
        assert initial.value.reason_code == "modeled_integrity_adapter_response_uncertain"
        assert isinstance(initial.value.__cause__, RuntimeError)

        unresolved = store.load_unresolved_integrity_transition()
        assert unresolved is not None
        assert unresolved.phase == "anchor_statement_ready"
        assert unresolved.pending.event_digest == event.event_digest

        assert facade.load(event.mission_id) == (event,)
        assert store.load_unresolved_integrity_transition() is None
        finalized = store.load_integrity_lineage(event.event_digest)
        assert finalized is not None
        assert finalized.phase == "finalized"
        assert [
            in_transaction for name, in_transaction in interrupted.calls if name == "register_anchor_statement"
        ] == [False, False]


@pytest.mark.parametrize(
    "failure_factory",
    (
        lambda: TimeoutError("simulated modeled-provider timeout"),
        lambda: ConnectionError("simulated modeled-provider connection loss"),
        lambda: RuntimeError("simulated modeled-provider lost response"),
    ),
)
def test_uncertain_adapter_failure_is_typed_and_exactly_recoverable(
    tmp_path: Path,
    failure_factory: Callable[[], BaseException],
) -> None:
    event = _event(failure_factory().__class__.__name__)
    with SQLiteEventStore(_state_path(tmp_path, failure_factory().__class__.__name__)) as store:
        interrupted = _InstrumentedService(
            _service(),
            store,
            fail_method="publish_checkpoint",
            failure_factory=failure_factory,
            failures_remaining=1,
        )
        facade = _facade(store, interrupted)
        with pytest.raises(IntegrityFinalityPendingError) as initial:
            facade.append(event, expected_head=GENESIS_DIGEST)
        assert initial.value.reason_code == "modeled_integrity_adapter_response_uncertain"
        unresolved = store.load_unresolved_integrity_transition()
        assert unresolved is not None
        assert unresolved.phase == "checkpoint_candidate_retained"

        assert facade.load(event.mission_id) == (event,)
        assert store.load_unresolved_integrity_transition() is None
        assert facade.require_finalized(event.event_digest).event_digest == (event.event_digest)


class _SimulatedProcessKill(BaseException):
    pass


@pytest.mark.parametrize(
    "failure",
    (
        StoreBusyError("simulated retained-state contention"),
        StoreCapacityError("simulated SQLite capacity exhaustion"),
        EvidenceVaultCapacityError("simulated evidence-vault capacity exhaustion"),
        StoreOperationalError("simulated SQLite operational failure"),
    ),
)
def test_store_failure_class_survives_finality_recovery(
    failure: Exception,
) -> None:
    facade = object.__new__(ModeledIntegrityFinalizingEventStoreV1)

    def fail_recovery(_lineage: object) -> IntegrityLineageV1:
        raise failure

    facade._recover_lineage = fail_recovery  # type: ignore[method-assign]
    with pytest.raises(type(failure)) as caught:
        facade._advance_finality(object())  # type: ignore[arg-type]
    assert caught.value is failure


def test_unexpected_recovery_exception_remains_typed_adapter_block() -> None:
    facade = object.__new__(ModeledIntegrityFinalizingEventStoreV1)
    failure = LookupError("simulated malformed adapter result")

    def fail_recovery(_lineage: object) -> IntegrityLineageV1:
        raise failure

    facade._recover_lineage = fail_recovery  # type: ignore[method-assign]
    with pytest.raises(IntegrityFinalityBlockedError) as caught:
        facade._advance_finality(object())  # type: ignore[arg-type]
    assert caught.value.reason_code == "modeled_integrity_adapter_contract_failure"
    assert caught.value.__cause__ is failure


def test_process_kill_is_not_normalized_or_swallowed(
    tmp_path: Path,
) -> None:
    event = _event("simulated-process-kill")
    with SQLiteEventStore(_state_path(tmp_path, "simulated-process-kill")) as store:
        interrupted = _InstrumentedService(
            _service(),
            store,
            fail_method="publish_checkpoint",
            failure_factory=lambda: _SimulatedProcessKill(),
            failures_remaining=1,
        )
        facade = _facade(store, interrupted)
        with pytest.raises(_SimulatedProcessKill):
            facade.append(event, expected_head=GENESIS_DIGEST)
        unresolved = store.load_unresolved_integrity_transition()
        assert unresolved is not None
        assert unresolved.phase == "checkpoint_candidate_retained"


@pytest.mark.parametrize(
    ("method", "malformed_result", "expected_phase"),
    (
        ("prepare_pending_transition", object(), None),
        ("observe_current_floor", 7, "checkpoint_candidate_retained"),
    ),
)
def test_malformed_adapter_return_is_typed_blocked_at_public_facade(
    tmp_path: Path,
    method: str,
    malformed_result: object,
    expected_phase: str | None,
) -> None:
    event = _event(f"malformed-{method}")
    with SQLiteEventStore(_state_path(tmp_path, f"malformed-{method}")) as store:
        malformed = _MalformedReturnService(
            _service(),
            method=method,
            result=malformed_result,
        )
        facade = _facade(store, malformed)
        with pytest.raises(IntegrityFinalityBlockedError) as blocked:
            facade.append(event, expected_head=GENESIS_DIGEST)
        expected_reason = (
            "modeled_integrity_adapter_contract_failure"
            if method == "observe_current_floor"
            else "invalid_modeled_integrity_adapter_result"
        )
        assert blocked.value.reason_code == expected_reason
        unresolved = store.load_unresolved_integrity_transition()
        if expected_phase is None:
            assert unresolved is None
            assert store.load(event.mission_id) == ()
        else:
            assert unresolved is not None
            assert unresolved.phase == expected_phase
            assert store.load_integrity_event(event.event_digest) == event


def test_direct_facade_retry_recovers_lost_publication_response_exactly(
    tmp_path: Path,
) -> None:
    event = _event("direct-facade-exact-retry")
    with SQLiteEventStore(_state_path(tmp_path, "direct-facade-exact-retry")) as store:
        lost_response = _LostPublicationResponseService(_service())
        facade = _facade(store, lost_response)
        with pytest.raises(IntegrityFinalityPendingError) as interrupted:
            facade.append(event, expected_head=GENESIS_DIGEST)
        assert interrupted.value.reason_code == "modeled_integrity_adapter_response_uncertain"
        unresolved = store.load_unresolved_integrity_transition()
        assert unresolved is not None
        assert unresolved.phase == "checkpoint_candidate_retained"

        assert facade.append(event, expected_head=GENESIS_DIGEST) == event
        assert facade.append(event, expected_head=GENESIS_DIGEST) == event
        assert store.load_unresolved_integrity_transition() is None
        with pytest.raises(IntegrityFinalityBlockedError) as conflict:
            facade.append(event, expected_head=event.event_digest)
        assert conflict.value.reason_code == "modeled_integrity_retry_conflict"


@pytest.mark.parametrize(
    ("error_type", "reason_code"),
    (
        (
            IntegrityFinalityPendingError,
            "fixture_provider_temporarily_unavailable",
        ),
        (
            IntegrityFinalityBlockedError,
            "fixture_provider_policy_blocked",
        ),
    ),
)
def test_provider_refusal_stays_typed_and_cannot_expose_success(
    tmp_path: Path,
    error_type: type[IntegrityTransitionError],
    reason_code: str,
) -> None:
    event = _event(reason_code)
    with SQLiteEventStore(_state_path(tmp_path, reason_code)) as store:
        refusing = _InstrumentedService(
            _service(),
            store,
            fail_method="publish_checkpoint",
            failure_factory=lambda: error_type(
                reason_code,
                "simulated typed provider refusal",
            ),
            failures_remaining=None,
        )
        facade = _facade(store, refusing)
        with pytest.raises(error_type) as initial:
            facade.append(event, expected_head=GENESIS_DIGEST)
        assert initial.value.reason_code == reason_code

        unresolved = store.load_unresolved_integrity_transition()
        assert unresolved is not None
        assert unresolved.phase == "checkpoint_candidate_retained"
        assert unresolved.finalization is None
        with pytest.raises(PendingIntegrityTransitionError):
            store.load(event.mission_id)
        assert store.load_integrity_event(event.event_digest) == event

        with pytest.raises(error_type) as replay:
            facade.load(event.mission_id)
        assert replay.value.reason_code == reason_code
        still_unresolved = store.load_unresolved_integrity_transition()
        assert still_unresolved is not None
        assert still_unresolved.phase == "checkpoint_candidate_retained"
        assert all(not in_transaction for name, in_transaction in refusing.calls if name == "publish_checkpoint")
