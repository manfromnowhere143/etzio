"""End-to-end evidence for integrity-finalized modeled receipt admission."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from etzio.authority import (
    AuthorityGrantV1,
    AuthoritySigner,
    TrustedAuthorityKey,
    TrustStore,
)
from etzio.evidence import (
    VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1,
    VERIFICATION_OUTPUT_ARTIFACT_TYPE_BY_ROLE_V1,
    FileEvidenceStore,
    TargetSnapshotV1,
    read_etzio_fixture,
    retain_snapshot,
)
from etzio.integrity_v1 import IntegrityValidationPolicyV1
from etzio.kernel.artifact_resolution import (
    resolve_modeled_fixture_verification_artifacts,
)
from etzio.kernel.fixture_scan import prepare_fixture_scan_for_verification
from etzio.kernel.integrity_transition import (
    CheckpointCandidateRecordV1,
    IntegrityFinalityPendingError,
    ModeledIntegrityFinalizingEventStoreV1,
    RepositoryOwnedDeterministicModeledIntegrityServiceV1,
)
from etzio.kernel.receipt_admission import (
    IntegrityFinalizedVerificationReceiptAdmission,
    VerificationReceiptAdmissionError,
    admit_modeled_fixture_verifier_receipt_with_integrity,
)
from etzio.kernel.store import SQLiteEventStore
from etzio.kernel.verification_lease import (
    issue_modeled_fixture_verification_lease,
)
from etzio.protocol import canonical_dumps, content_id, thaw_json
from etzio.verification import (
    MODELED_FIXTURE_TIER,
    VERIFIER_ROLE,
    SignedVerifierReceiptV1,
    TrustedVerifierKey,
    VerificationLeaseV1,
    VerifierReceiptV1,
    VerifierSigner,
    VerifierTrustStore,
)

NOW = 2_000_000_000


@dataclass(frozen=True, slots=True)
class _PreparedReceipt:
    evidence_store: FileEvidenceStore
    mission_id: str
    lease: VerificationLeaseV1
    resolution_event_digest: str
    signed_receipt: SignedVerifierReceiptV1
    decision_trust: VerifierTrustStore


class _CrashAfterNthCheckpointPublication:
    """Delegate the modeled provider and interrupt once after publication."""

    def __init__(
        self,
        delegate: RepositoryOwnedDeterministicModeledIntegrityServiceV1,
        *,
        crash_on_publish: int,
    ) -> None:
        self._delegate = delegate
        self._crash_on_publish = crash_on_publish
        self._crashed = False
        self.publish_calls = 0
        self.service_instance_id = delegate.service_instance_id
        self.environment_id = delegate.environment_id
        self.validation_policy = delegate.validation_policy

    def __getattr__(self, name: str) -> object:
        return getattr(self._delegate, name)

    def publish_checkpoint(
        self,
        candidate: CheckpointCandidateRecordV1,
    ) -> None:
        self.publish_calls += 1
        self._delegate.publish_checkpoint(candidate)
        if self.publish_calls == self._crash_on_publish and not self._crashed:
            self._crashed = True
            raise RuntimeError("simulated interruption after external checkpoint publication")


def _digest(label: str) -> str:
    return content_id("integrity_receipt_vertical_test", {"label": label})


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


def _service() -> RepositoryOwnedDeterministicModeledIntegrityServiceV1:
    return RepositoryOwnedDeterministicModeledIntegrityServiceV1.deterministic(
        seed=b"integrity-receipt-vertical-v1",
        service_instance_id="Etzio.receipt-fixture",
        environment_id="fixture.receipt-control-plane",
        validation_policy=_policy(),
    )


def _put_inputs(
    evidence_store: FileEvidenceStore,
) -> tuple[dict[str, object], int]:
    singular = {
        "poc": evidence_store.put_typed(
            b"inert-poc",
            artifact_type=VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["poc"],
        ),
        "environment": evidence_store.put_typed(
            b"modeled-environment",
            artifact_type=VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["environment"],
        ),
        "effect_oracle": evidence_store.put_typed(
            b"modeled-effect-oracle",
            artifact_type=VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["effect_oracle"],
        ),
    }
    supporting = tuple(
        sorted(
            (
                evidence_store.put_typed(
                    b"supporting-evidence-a",
                    artifact_type=VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["evidence"],
                ),
                evidence_store.put_typed(
                    b"supporting-evidence-b",
                    artifact_type=VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["evidence"],
                ),
            ),
            key=lambda value: value.digest,
        )
    )
    bindings: dict[str, object] = {
        "poc_artifact_digest": singular["poc"].digest,
        "evidence_artifact_digests": tuple(value.digest for value in supporting),
        "environment_digest": singular["environment"].digest,
        "effect_oracle_id": singular["effect_oracle"].digest,
    }
    total = sum(value.size for value in singular.values()) + sum(value.size for value in supporting)
    return bindings, total


def _put_outputs(
    evidence_store: FileEvidenceStore,
) -> tuple[dict[str, tuple[str, int]], int]:
    outputs: dict[str, tuple[str, int]] = {}
    total = 0
    for role, value in (
        ("execution_output", b"modeled-execution-transcript"),
        ("effect_output", b"modeled-effect-observation"),
        ("measured_environment_output", b"modeled-measured-environment"),
        ("termination_output", b"modeled-termination-record"),
    ):
        retained = evidence_store.put_typed(
            value,
            artifact_type=VERIFICATION_OUTPUT_ARTIFACT_TYPE_BY_ROLE_V1[role],
        )
        outputs[role] = (retained.digest, retained.size)
        total += retained.size
    return outputs, total


def _signed_receipt(
    *,
    signer: VerifierSigner,
    lease: VerificationLeaseV1,
    artifact_resolution_id: str,
    outputs: dict[str, tuple[str, int]],
) -> SignedVerifierReceiptV1:
    return signer.sign(
        VerifierReceiptV1.for_lease(
            lease,
            artifact_resolution_id=artifact_resolution_id,
            execution_output_digest=outputs["execution_output"][0],
            execution_output_size=outputs["execution_output"][1],
            effect_output_digest=outputs["effect_output"][0],
            effect_output_size=outputs["effect_output"][1],
            measured_environment_output_digest=outputs["measured_environment_output"][0],
            measured_environment_output_size=outputs["measured_environment_output"][1],
            termination_output_digest=outputs["termination_output"][0],
            termination_output_size=outputs["termination_output"][1],
            evidence_tier=MODELED_FIXTURE_TIER,
            verdict="confirmed",
            effect_observed=True,
            oracle_satisfied=True,
            completed_at=NOW + 3,
        )
    )


def _prepare_to_receipt(
    root: Path,
    event_store: ModeledIntegrityFinalizingEventStoreV1,
) -> _PreparedReceipt:
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    evidence_store = FileEvidenceStore(root / "evidence")
    relative_path, fixture_bytes = read_etzio_fixture(
        "vulnerable_app.py",
        maximum=64 * 1024,
    )
    snapshot: TargetSnapshotV1 = retain_snapshot(
        "repository_fixture",
        {relative_path: fixture_bytes},
        evidence_store,
    )
    inputs, input_bytes = _put_inputs(evidence_store)
    outputs, output_bytes = _put_outputs(evidence_store)
    authority_evidence = evidence_store.put(
        canonical_dumps(
            {
                "fixture": relative_path,
                "kind": "repository_owned_benchmark_authority",
            }
        )
    )
    authority_signer = AuthoritySigner.generate()
    grant = AuthorityGrantV1.issue(
        issuer="operator:daniel",
        subject="benchmark:integrity-finalized-receipt",
        target_snapshot_id=snapshot.object_id,
        assets=(f"fixture://{relative_path}",),
        permitted_actions=("modeled_fixture_verification", "static_analysis"),
        evidence_digest=authority_evidence.digest,
        issued_at=NOW - 1,
        not_before=NOW,
        expires_at=NOW + 300,
        max_bytes=(len(fixture_bytes) + input_bytes + output_bytes + 4096),
        max_candidates=100,
        max_wallclock_seconds=120,
    )
    signed_grant = authority_signer.sign(grant)
    authority_trust = TrustStore.from_keys(
        (
            TrustedAuthorityKey(
                public_key_bytes=authority_signer.public_key_bytes,
                roles=frozenset({"operator"}),
                issuers=frozenset({"operator:daniel"}),
            ),
        )
    )
    verifier_signer = VerifierSigner.generate()
    decision_trust = VerifierTrustStore.from_keys(
        (
            TrustedVerifierKey(
                verifier_id="CATO",
                public_key_bytes=verifier_signer.public_key_bytes,
                roles=frozenset({VERIFIER_ROLE}),
            ),
        )
    )
    mission_id = content_id(
        "mission",
        {"fixture": relative_path, "test": root.name},
    )
    prepared = prepare_fixture_scan_for_verification(
        mission_id=mission_id,
        snapshot=snapshot,
        signed_authority=signed_grant,
        trust_store=authority_trust,
        evidence_store=evidence_store,
        event_store=event_store,
        decision_time=NOW,
    )
    assert len(prepared.candidate_events) == 7
    candidate_id = thaw_json(prepared.candidate_events[0].payload)["candidate"]["object_id"]
    issuance = issue_modeled_fixture_verification_lease(
        event_store=event_store,
        mission_id=mission_id,
        expected_head=prepared.events[-1].event_digest,
        candidate_id=candidate_id,
        **inputs,
        verifier_key_id=verifier_signer.key_id,
        verifier_trust_store=decision_trust,
        decision_time=NOW + 1,
        requested_wallclock_seconds=60,
    )
    resolution = resolve_modeled_fixture_verification_artifacts(
        event_store=event_store,
        evidence_store=evidence_store,
        mission_id=mission_id,
        expected_head=issuance.event.event_digest,
        verification_lease_id=issuance.lease.lease_id,
        decision_time=NOW + 2,
    )
    return _PreparedReceipt(
        evidence_store=evidence_store,
        mission_id=mission_id,
        lease=issuance.lease,
        resolution_event_digest=resolution.event.event_digest,
        signed_receipt=_signed_receipt(
            signer=verifier_signer,
            lease=issuance.lease,
            artifact_resolution_id=resolution.resolution.resolution_id,
            outputs=outputs,
        ),
        decision_trust=decision_trust,
    )


def _admit(
    prepared: _PreparedReceipt,
    *,
    event_store: ModeledIntegrityFinalizingEventStoreV1,
) -> IntegrityFinalizedVerificationReceiptAdmission:
    return admit_modeled_fixture_verifier_receipt_with_integrity(
        event_store=event_store,
        evidence_store=prepared.evidence_store,
        mission_id=prepared.mission_id,
        expected_head=prepared.resolution_event_digest,
        verification_lease_id=prepared.lease.lease_id,
        signed_receipt=prepared.signed_receipt,
        decision_trust_store=prepared.decision_trust,
        decision_time=NOW + 4,
    )


def _assert_finalized_contiguous_stream(
    raw_store: SQLiteEventStore,
    mission_id: str,
) -> None:
    events = raw_store.load(mission_id)
    assert [event.kind for event in events] == [
        "authority_admitted",
        "mission_opened",
        "analysis_lease_issued",
        *(["candidate_recorded"] * 7),
        "scan_completed",
        "verification_lease_issued",
        "verification_artifacts_resolved",
        "verifier_receipt_admitted",
    ]
    previous_checkpoint_id: str | None = None
    for sequence, event in enumerate(events):
        lineage = raw_store.load_integrity_lineage(event.event_digest)
        assert lineage is not None
        assert lineage.phase == "finalized"
        assert lineage.pending.event_digest == event.event_digest
        assert lineage.pending.event_seq == sequence
        assert lineage.pending.instance_sequence == sequence
        assert lineage.anchor_statement is not None
        assert lineage.checkpoint_candidate is not None
        assert lineage.finalization is not None
        checkpoint = lineage.checkpoint_candidate.checkpoint
        finalization = lineage.finalization
        floor = finalization.external_head_floor
        assert checkpoint.event_digest == event.event_digest
        assert checkpoint.event_seq == sequence
        assert checkpoint.instance_sequence == sequence
        assert floor.instance_sequence == sequence
        assert floor.mission_event_seq == sequence
        assert floor.checkpoint_id == checkpoint.checkpoint_id
        assert floor.mission_checkpoint_id == checkpoint.checkpoint_id
        assert finalization.checkpoint_candidate_record_id == lineage.checkpoint_candidate.record_id
        if previous_checkpoint_id is not None:
            assert checkpoint.previous_checkpoint_id == previous_checkpoint_id
            assert checkpoint.previous_mission_checkpoint_id == previous_checkpoint_id
        previous_checkpoint_id = checkpoint.checkpoint_id


def test_fresh_receipt_vertical_finalizes_all_fourteen_events(
    tmp_path: Path,
) -> None:
    root = tmp_path / "success"
    root.mkdir(mode=0o700)
    with SQLiteEventStore(root / "events.sqlite3") as raw_store:
        facade = ModeledIntegrityFinalizingEventStoreV1(
            raw_store,
            _service(),
        )
        prepared = _prepare_to_receipt(root, facade)
        result = _admit(prepared, event_store=facade)

        assert not result.admission.replayed
        assert result.admission.event.kind == "verifier_receipt_admitted"
        assert result.finalization.event_digest == result.admission.event.event_digest
        _assert_finalized_contiguous_stream(
            raw_store,
            prepared.mission_id,
        )


def test_receipt_replay_recovers_after_checkpoint_publication_interruption(
    tmp_path: Path,
) -> None:
    root = tmp_path / "publication-crash"
    root.mkdir(mode=0o700)
    base_service = _service()
    crashing_service = _CrashAfterNthCheckpointPublication(
        base_service,
        crash_on_publish=14,
    )
    with SQLiteEventStore(root / "events.sqlite3") as raw_store:
        facade = ModeledIntegrityFinalizingEventStoreV1(
            raw_store,
            crashing_service,
        )
        prepared = _prepare_to_receipt(root, facade)
        assert crashing_service.publish_calls == 13

        with pytest.raises(IntegrityFinalityPendingError) as interrupted:
            _admit(prepared, event_store=facade)
        assert interrupted.value.reason_code == "modeled_integrity_adapter_response_uncertain"
        assert isinstance(interrupted.value.__cause__, RuntimeError)

        unresolved = raw_store.load_unresolved_integrity_transition()
        assert unresolved is not None
        assert unresolved.phase == "checkpoint_candidate_retained"
        assert unresolved.pending.event_seq == 13
        assert unresolved.checkpoint_candidate is not None
        published_floor, _ = base_service.observe_current_floor(
            unresolved.pending,
            unresolved.checkpoint_candidate,
        )
        assert published_floor.checkpoint_id == unresolved.checkpoint_candidate.checkpoint.checkpoint_id
        assert published_floor.instance_sequence == 13
        assert published_floor.mission_event_seq == 13

        recovered = _admit(prepared, event_store=facade)
        assert recovered.admission.replayed
        assert raw_store.load_unresolved_integrity_transition() is None
        assert crashing_service.publish_calls == 15
        assert recovered.finalization.event_digest == recovered.admission.event.event_digest

        replayed = _admit(prepared, event_store=facade)
        assert replayed.admission.replayed
        assert replayed.admission.event == recovered.admission.event
        assert replayed.finalization == recovered.finalization
        assert crashing_service.publish_calls == 15
        _assert_finalized_contiguous_stream(
            raw_store,
            prepared.mission_id,
        )


def test_integrity_receipt_boundary_rejects_facade_subclasses() -> None:
    class _Subclass(ModeledIntegrityFinalizingEventStoreV1):
        pass

    facade_subclass = object.__new__(_Subclass)
    with pytest.raises(
        VerificationReceiptAdmissionError,
        match="exact ModeledIntegrityFinalizingEventStoreV1",
    ) as refused:
        admit_modeled_fixture_verifier_receipt_with_integrity(
            event_store=facade_subclass,
            evidence_store=object(),  # type: ignore[arg-type]
            mission_id="not-reached",
            expected_head="not-reached",
            verification_lease_id="not-reached",
            signed_receipt=object(),
            decision_trust_store=object(),  # type: ignore[arg-type]
            decision_time=-1,
        )
    assert refused.value.reason_code == "invalid_integrity_event_store"
