"""Adversarial contract tests for trusted-time, revocation, and head evidence."""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Mapping
from dataclasses import replace
from types import MappingProxyType

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import etzio.integrity_v1 as integrity_contract
from etzio.integrity_v1 import (
    EXTERNAL_FLOOR_EVIDENCE_KIND,
    HEAD_ANCHOR_RECEIPT_EVIDENCE_KIND,
    HEAD_CHECKPOINT_ROLE,
    INTEGRITY_DECISION_ROLE,
    REVOCATION_METADATA_EVIDENCE_KIND,
    TRUSTED_TIME_EVIDENCE_KIND,
    AuthenticatedHeadCheckpointV1,
    AuthenticatedIntegrityDecisionV1,
    EvidenceReferenceV1,
    HeadCheckpointFloorV1,
    HeadCheckpointV1,
    IntegrityDecisionV1,
    IntegrityError,
    IntegritySigner,
    IntegrityTrustStore,
    IntegrityValidationPolicyV1,
    RevocationFloorV1,
    RevocationViewV1,
    SignedHeadCheckpointV1,
    SignedIntegrityDecisionV1,
    TrustedIntegrityKey,
    authenticate_head_checkpoint,
    authenticate_integrity_decision,
    classify_deadline,
    head_checkpoint_genesis_id,
    mission_checkpoint_genesis_id,
    require_interval_within,
    signed_head_checkpoint_attestation_id,
    signed_integrity_decision_attestation_id,
    validate_checkpoint_advance,
    validate_checkpoint_binding,
    validate_revocation_advance,
)
from etzio.kernel.events_v1 import GENESIS_DIGEST, EventV1
from etzio.protocol import EnvelopeV1, parse_semantic_bytes, thaw_json

NOW = 2_000_000_000


def _digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("ascii")).hexdigest()


def _reference(
    evidence_kind: str,
    source: str,
    label: str,
) -> EvidenceReferenceV1:
    return EvidenceReferenceV1(evidence_kind, source, _digest(label))


def _time_evidence() -> tuple[EvidenceReferenceV1, ...]:
    return (
        _reference(TRUSTED_TIME_EVIDENCE_KIND, "time.nts-a", "time-a"),
        _reference(TRUSTED_TIME_EVIDENCE_KIND, "time.tsa-b", "time-b"),
    )


def _anchor_evidence() -> tuple[EvidenceReferenceV1, ...]:
    return (
        _reference(
            HEAD_ANCHOR_RECEIPT_EVIDENCE_KIND,
            "anchor.log-a",
            "anchor-a",
        ),
        _reference(
            HEAD_ANCHOR_RECEIPT_EVIDENCE_KIND,
            "anchor.log-b",
            "anchor-b",
        ),
    )


def _floor_evidence() -> tuple[EvidenceReferenceV1, ...]:
    return (
        _reference(
            EXTERNAL_FLOOR_EVIDENCE_KIND,
            "floor.monitor-a",
            "floor-a",
        ),
        _reference(
            EXTERNAL_FLOOR_EVIDENCE_KIND,
            "floor.monitor-b",
            "floor-b",
        ),
    )


def _revocation_views(
    *,
    authority_root: int = 1,
    authority_version: int = 7,
    authority_snapshot: str | None = None,
    authority_evidence: str | None = None,
    verifier_root: int = 1,
    verifier_version: int = 11,
    verifier_snapshot: str | None = None,
    verifier_evidence: str | None = None,
    valid_from: int = NOW - 60,
    valid_until: int = NOW + 60,
) -> tuple[RevocationViewV1, ...]:
    return (
        RevocationViewV1(
            namespace="authority",
            root_version=authority_root,
            version=authority_version,
            snapshot_id=authority_snapshot or _digest("authority-snapshot"),
            evidence=_reference(
                REVOCATION_METADATA_EVIDENCE_KIND,
                "revocation.authority",
                authority_evidence or "authority-evidence",
            )
            if authority_evidence is None
            else EvidenceReferenceV1(
                REVOCATION_METADATA_EVIDENCE_KIND,
                "revocation.authority",
                authority_evidence,
            ),
            valid_from=valid_from,
            valid_until=valid_until,
        ),
        RevocationViewV1(
            namespace="verifier",
            root_version=verifier_root,
            version=verifier_version,
            snapshot_id=verifier_snapshot or _digest("verifier-snapshot"),
            evidence=_reference(
                REVOCATION_METADATA_EVIDENCE_KIND,
                "revocation.verifier",
                verifier_evidence or "verifier-evidence",
            )
            if verifier_evidence is None
            else EvidenceReferenceV1(
                REVOCATION_METADATA_EVIDENCE_KIND,
                "revocation.verifier",
                verifier_evidence,
            ),
            valid_from=valid_from,
            valid_until=valid_until,
        ),
    )


def _decision(**overrides: object) -> IntegrityDecisionV1:
    values: dict[str, object] = {
        "service_instance_id": "Etzio.fixture-instance",
        "environment_id": "fixture.control-plane",
        "mission_id": _digest("mission"),
        "authority_id": _digest("authority"),
        "target_id": _digest("target"),
        "prior_event_seq": -1,
        "prior_event_digest": GENESIS_DIGEST,
        "event_kind": "scan_failed",
        "transition_intent_id": _digest("transition-intent"),
        "request_nonce": hashlib.sha256(b"request-nonce").hexdigest(),
        "time_lower_bound": NOW,
        "time_upper_bound": NOW + 1,
        "time_policy_id": _digest("time-policy"),
        "time_evidence": _time_evidence(),
        "revocation_views": _revocation_views(),
        "decision_policy_id": _digest("decision-policy"),
    }
    values.update(overrides)
    if "prior_global_checkpoint_sequence" not in overrides:
        values["prior_global_checkpoint_sequence"] = -1
    if "prior_global_checkpoint_id" not in overrides:
        values["prior_global_checkpoint_id"] = (
            head_checkpoint_genesis_id(
                service_instance_id=values["service_instance_id"],  # type: ignore[arg-type]
                environment_id=values["environment_id"],  # type: ignore[arg-type]
            )
            if values["prior_global_checkpoint_sequence"] == -1
            else _digest("prior-global-checkpoint")
        )
    if "prior_global_checkpoint_attestation_id" not in overrides:
        values["prior_global_checkpoint_attestation_id"] = None
    if "prior_global_checkpoint_principal_id" not in overrides:
        values["prior_global_checkpoint_principal_id"] = None
    if "prior_global_checkpoint_trust_snapshot_id" not in overrides:
        values["prior_global_checkpoint_trust_snapshot_id"] = None
    if "time_lower_bound" not in overrides:
        prior_global_sequence = values["prior_global_checkpoint_sequence"]
        values["time_lower_bound"] = (
            NOW if prior_global_sequence == -1 else NOW + (2 * (prior_global_sequence + 1))  # type: ignore[operator]
        )
    if "time_upper_bound" not in overrides:
        values["time_upper_bound"] = values["time_lower_bound"] + 1  # type: ignore[operator]
    if "prior_event_digest" not in overrides:
        values["prior_event_digest"] = GENESIS_DIGEST if values["prior_event_seq"] == -1 else _digest("prior-event")
    if "proposed_event_digest" not in overrides:
        values["proposed_event_digest"] = _event_from_values(values).event_digest
    return IntegrityDecisionV1.issue(**values)  # type: ignore[arg-type]


def _event_from_values(values: dict[str, object]) -> EventV1:
    return EventV1.create(
        mission_id=values["mission_id"],  # type: ignore[arg-type]
        seq=values["prior_event_seq"] + 1,  # type: ignore[operator]
        kind=values["event_kind"],  # type: ignore[arg-type]
        unit="ETZIO",
        authority_id=values["authority_id"],  # type: ignore[arg-type]
        target_id=values["target_id"],  # type: ignore[arg-type]
        decision_time=values["time_upper_bound"],  # type: ignore[arg-type]
        payload={"reason_code": "integrity_contract_fixture"},
        prev_digest=values["prior_event_digest"],  # type: ignore[arg-type]
    )


def _proposed_event(decision: IntegrityDecisionV1) -> EventV1:
    return EventV1.create(
        mission_id=decision.mission_id,
        seq=decision.prior_event_seq + 1,
        kind=decision.event_kind,
        unit="ETZIO",
        authority_id=decision.authority_id,
        target_id=decision.target_id,
        decision_time=decision.time_upper_bound,
        payload={"reason_code": "integrity_contract_fixture"},
        prev_digest=decision.prior_event_digest,
    )


def _checkpoint(
    decision: IntegrityDecisionV1,
    *,
    authenticated_decision: AuthenticatedIntegrityDecisionV1 | None = None,
    instance_sequence: int = 0,
    event_seq: int | None = None,
    event_digest: str | None = None,
    previous_checkpoint_id: str | None = None,
    previous_mission_checkpoint_id: str | None = None,
    previous_global: AuthenticatedHeadCheckpointV1 | None = None,
    previous_mission: AuthenticatedHeadCheckpointV1 | None = None,
    **overrides: object,
) -> HeadCheckpointV1:
    if authenticated_decision is not None and authenticated_decision.decision != decision:
        raise AssertionError("authenticated decision fixture is incoherent")
    values: dict[str, object] = {
        "service_instance_id": decision.service_instance_id,
        "environment_id": decision.environment_id,
        "instance_sequence": instance_sequence,
        "previous_checkpoint_id": previous_checkpoint_id
        or (
            previous_global.checkpoint.checkpoint_id
            if previous_global is not None
            else head_checkpoint_genesis_id(
                service_instance_id=decision.service_instance_id,
                environment_id=decision.environment_id,
            )
        ),
        "previous_checkpoint_attestation_id": (
            None
            if previous_global is None
            else signed_head_checkpoint_attestation_id(previous_global.signed_checkpoint)
        ),
        "previous_checkpoint_principal_id": (None if previous_global is None else previous_global.signer_principal_id),
        "previous_checkpoint_trust_snapshot_id": (
            None if previous_global is None else previous_global.trust_snapshot_id
        ),
        "previous_mission_checkpoint_id": previous_mission_checkpoint_id
        or (
            previous_mission.checkpoint.checkpoint_id
            if previous_mission is not None
            else mission_checkpoint_genesis_id(
                service_instance_id=decision.service_instance_id,
                environment_id=decision.environment_id,
                mission_id=decision.mission_id,
            )
        ),
        "previous_mission_checkpoint_attestation_id": (
            None
            if previous_mission is None
            else signed_head_checkpoint_attestation_id(previous_mission.signed_checkpoint)
        ),
        "previous_mission_checkpoint_principal_id": (
            None if previous_mission is None else previous_mission.signer_principal_id
        ),
        "previous_mission_checkpoint_trust_snapshot_id": (
            None if previous_mission is None else previous_mission.trust_snapshot_id
        ),
        "mission_id": decision.mission_id,
        "authority_id": decision.authority_id,
        "target_id": decision.target_id,
        "event_seq": (decision.prior_event_seq + 1 if event_seq is None else event_seq),
        "event_digest": event_digest or decision.proposed_event_digest,
        "integrity_decision_id": decision.decision_id,
        "integrity_decision_attestation_id": (
            _digest("fixture-decision-attestation")
            if authenticated_decision is None
            else signed_integrity_decision_attestation_id(authenticated_decision.signed_decision)
        ),
        "integrity_decision_principal_id": (
            "fixture.integrity-principal"
            if authenticated_decision is None
            else authenticated_decision.signer_principal_id
        ),
        "integrity_decision_trust_snapshot_id": (
            _digest("fixture-integrity-trust-snapshot")
            if authenticated_decision is None
            else authenticated_decision.trust_snapshot_id
        ),
        "time_lower_bound": decision.time_upper_bound,
        "time_upper_bound": decision.time_upper_bound + 1,
        "time_policy_id": decision.time_policy_id,
        "time_evidence": _time_evidence(),
        "anchor_policy_id": _digest("anchor-policy"),
        "anchor_evidence": _anchor_evidence(),
    }
    values.update(overrides)
    if (
        values["event_seq"] > values["instance_sequence"]  # type: ignore[operator]
        and "instance_sequence" not in overrides
    ):
        values["instance_sequence"] = values["event_seq"]
    if (
        values["instance_sequence"] > 0  # type: ignore[operator]
        and previous_checkpoint_id is None
        and previous_global is None
        and values["previous_checkpoint_id"]
        == head_checkpoint_genesis_id(
            service_instance_id=decision.service_instance_id,
            environment_id=decision.environment_id,
        )
    ):
        values["previous_checkpoint_id"] = _digest("fixture-missing-previous-global")
    if values["instance_sequence"] == 0 and previous_checkpoint_id is None and previous_global is None:
        values["previous_checkpoint_id"] = head_checkpoint_genesis_id(
            service_instance_id=values["service_instance_id"],  # type: ignore[arg-type]
            environment_id=values["environment_id"],  # type: ignore[arg-type]
        )
    if values["event_seq"] == 0 and previous_mission_checkpoint_id is None and previous_mission is None:
        values["previous_mission_checkpoint_id"] = mission_checkpoint_genesis_id(
            service_instance_id=values["service_instance_id"],  # type: ignore[arg-type]
            environment_id=values["environment_id"],  # type: ignore[arg-type]
            mission_id=values["mission_id"],  # type: ignore[arg-type]
        )
    if (
        values["event_seq"] > 0  # type: ignore[operator]
        and previous_mission is None
        and values["previous_mission_checkpoint_id"]
        == mission_checkpoint_genesis_id(
            service_instance_id=decision.service_instance_id,
            environment_id=decision.environment_id,
            mission_id=decision.mission_id,
        )
    ):
        values["previous_mission_checkpoint_id"] = _digest("fixture-missing-previous-mission")
    if (
        values["instance_sequence"] > 0  # type: ignore[operator]
        and values["previous_checkpoint_attestation_id"] is None
        and values["previous_checkpoint_principal_id"] is None
        and values["previous_checkpoint_trust_snapshot_id"] is None
    ):
        values["previous_checkpoint_attestation_id"] = _digest("fixture-previous-global-attestation")
        values["previous_checkpoint_principal_id"] = "fixture.previous-global-principal"
        values["previous_checkpoint_trust_snapshot_id"] = _digest("fixture-previous-global-trust")
    if (
        values["event_seq"] > 0  # type: ignore[operator]
        and values["previous_mission_checkpoint_attestation_id"] is None
        and values["previous_mission_checkpoint_principal_id"] is None
        and values["previous_mission_checkpoint_trust_snapshot_id"] is None
    ):
        if values["previous_mission_checkpoint_id"] == values["previous_checkpoint_id"]:
            values["previous_mission_checkpoint_attestation_id"] = values["previous_checkpoint_attestation_id"]
            values["previous_mission_checkpoint_principal_id"] = values["previous_checkpoint_principal_id"]
            values["previous_mission_checkpoint_trust_snapshot_id"] = values["previous_checkpoint_trust_snapshot_id"]
        else:
            values["previous_mission_checkpoint_attestation_id"] = _digest("fixture-previous-mission-attestation")
            values["previous_mission_checkpoint_principal_id"] = "fixture.previous-mission-principal"
            values["previous_mission_checkpoint_trust_snapshot_id"] = _digest("fixture-previous-mission-trust")
    return HeadCheckpointV1.issue(**values)  # type: ignore[arg-type]


@pytest.fixture
def decision_signer() -> IntegritySigner:
    return IntegritySigner.generate(INTEGRITY_DECISION_ROLE)


@pytest.fixture
def checkpoint_signer() -> IntegritySigner:
    return IntegritySigner.generate(HEAD_CHECKPOINT_ROLE)


def _trust_store(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
    *,
    revoked_key_ids: tuple[str, ...] = (),
) -> IntegrityTrustStore:
    return IntegrityTrustStore.from_keys(
        (
            TrustedIntegrityKey(
                "integrity.control-principal",
                decision_signer.public_key_bytes,
                INTEGRITY_DECISION_ROLE,
            ),
            TrustedIntegrityKey(
                "integrity.anchor-principal",
                checkpoint_signer.public_key_bytes,
                HEAD_CHECKPOINT_ROLE,
            ),
        ),
        revoked_key_ids=revoked_key_ids,
    )


def _authenticate(
    decision: IntegrityDecisionV1,
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> AuthenticatedIntegrityDecisionV1:
    return authenticate_integrity_decision(
        decision_signer.sign_decision(decision),
        _trust_store(decision_signer, checkpoint_signer),
        **_decision_auth_kwargs(decision),
    )


def _decision_auth_kwargs(decision: IntegrityDecisionV1) -> dict[str, object]:
    return {
        "forbidden_key_ids": (),
        "expected_service_instance_id": decision.service_instance_id,
        "expected_environment_id": decision.environment_id,
        "expected_mission_id": decision.mission_id,
        "expected_authority_id": decision.authority_id,
        "expected_target_id": decision.target_id,
        "expected_prior_global_checkpoint_sequence": (decision.prior_global_checkpoint_sequence),
        "expected_prior_global_checkpoint_id": (decision.prior_global_checkpoint_id),
        "expected_prior_global_checkpoint_attestation_id": (decision.prior_global_checkpoint_attestation_id),
        "expected_prior_global_checkpoint_principal_id": (decision.prior_global_checkpoint_principal_id),
        "expected_prior_global_checkpoint_trust_snapshot_id": (decision.prior_global_checkpoint_trust_snapshot_id),
        "expected_prior_event_seq": decision.prior_event_seq,
        "expected_prior_event_digest": decision.prior_event_digest,
        "expected_event_kind": decision.event_kind,
        "expected_proposed_event_digest": decision.proposed_event_digest,
        "expected_transition_intent_id": decision.transition_intent_id,
        "expected_request_nonce": decision.request_nonce,
        "expected_time_policy_id": decision.time_policy_id,
        "expected_decision_policy_id": decision.decision_policy_id,
        "required_revocation_namespaces": ("authority", "verifier"),
        "max_time_uncertainty_seconds": 2,
    }


def _authenticate_checkpoint(
    checkpoint: HeadCheckpointV1,
    decision: AuthenticatedIntegrityDecisionV1,
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
):
    return authenticate_head_checkpoint(
        checkpoint_signer.sign_checkpoint(checkpoint),
        _trust_store(decision_signer, checkpoint_signer),
        **_checkpoint_auth_kwargs(
            checkpoint,
            forbidden_key_ids=(decision.signed_decision.key_id,),
            forbidden_principal_ids=(decision.signer_principal_id,),
        ),
    )


def _global_predecessor(
    checkpoint: AuthenticatedHeadCheckpointV1,
) -> dict[str, object]:
    return {
        "prior_global_checkpoint_sequence": (checkpoint.checkpoint.instance_sequence),
        "prior_global_checkpoint_id": checkpoint.checkpoint.checkpoint_id,
        "prior_global_checkpoint_attestation_id": (signed_head_checkpoint_attestation_id(checkpoint.signed_checkpoint)),
        "prior_global_checkpoint_principal_id": (checkpoint.signer_principal_id),
        "prior_global_checkpoint_trust_snapshot_id": (checkpoint.trust_snapshot_id),
    }


def _checkpoint_auth_kwargs(
    checkpoint: HeadCheckpointV1,
    *,
    forbidden_key_ids: tuple[str, ...] = (),
    forbidden_principal_ids: tuple[str, ...] = (),
) -> dict[str, object]:
    return {
        "forbidden_key_ids": forbidden_key_ids,
        "forbidden_principal_ids": forbidden_principal_ids,
        "expected_service_instance_id": checkpoint.service_instance_id,
        "expected_environment_id": checkpoint.environment_id,
        "expected_time_policy_id": checkpoint.time_policy_id,
        "expected_anchor_policy_id": checkpoint.anchor_policy_id,
        "expected_anchor_statement_id": checkpoint.anchor_statement_id,
        "max_time_uncertainty_seconds": 2,
    }


def _binding_context(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
    *,
    previous_mission: AuthenticatedHeadCheckpointV1 | None = None,
) -> dict[str, object]:
    trust_store = _trust_store(decision_signer, checkpoint_signer)
    return {
        "checkpoint_trust_store": trust_store,
        "decision_trust_store": trust_store,
        "previous_mission": previous_mission,
        "previous_mission_trust_store": (None if previous_mission is None else trust_store),
        "validation_policy": _validation_policy(),
    }


def _advance_context(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
    *,
    current_decision: AuthenticatedIntegrityDecisionV1,
    previous_global: AuthenticatedHeadCheckpointV1 | None,
    previous_mission: AuthenticatedHeadCheckpointV1 | None,
) -> dict[str, object]:
    trust_store = _trust_store(decision_signer, checkpoint_signer)
    return {
        "current_trust_store": trust_store,
        "current_decision": current_decision,
        "current_decision_trust_store": trust_store,
        "previous_global": previous_global,
        "previous_global_trust_store": (None if previous_global is None else trust_store),
        "previous_mission": previous_mission,
        "previous_mission_trust_store": (None if previous_mission is None else trust_store),
        "validation_policy": _validation_policy(),
    }


def _revocation_context(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
    *,
    previous_global_decision: AuthenticatedIntegrityDecisionV1 | None,
    previous_global_checkpoint: AuthenticatedHeadCheckpointV1 | None,
) -> dict[str, object]:
    trust_store = _trust_store(decision_signer, checkpoint_signer)
    return {
        "previous_global_decision_trust_store": (None if previous_global_decision is None else trust_store),
        "previous_global_checkpoint": previous_global_checkpoint,
        "previous_global_checkpoint_trust_store": (None if previous_global_checkpoint is None else trust_store),
        "current_trust_store": trust_store,
        "validation_policy": _validation_policy(),
    }


def _validation_policy(
    *,
    decision_policy_id: str | None = None,
    decision_time_policy_id: str | None = None,
    checkpoint_time_policy_id: str | None = None,
    anchor_policy_id: str | None = None,
    required_revocation_namespaces: frozenset[str] = frozenset({"authority", "verifier"}),
    max_decision_uncertainty_seconds: int = 2,
    max_checkpoint_uncertainty_seconds: int = 2,
) -> IntegrityValidationPolicyV1:
    return IntegrityValidationPolicyV1(
        decision_policy_id=decision_policy_id or _digest("decision-policy"),
        decision_time_policy_id=decision_time_policy_id or _digest("time-policy"),
        checkpoint_time_policy_id=checkpoint_time_policy_id or _digest("time-policy"),
        anchor_policy_id=anchor_policy_id or _digest("anchor-policy"),
        required_revocation_namespaces=required_revocation_namespaces,
        max_decision_uncertainty_seconds=(max_decision_uncertainty_seconds),
        max_checkpoint_uncertainty_seconds=(max_checkpoint_uncertainty_seconds),
    )


def _revocation_floors(
    decision: IntegrityDecisionV1,
) -> tuple[RevocationFloorV1, ...]:
    return tuple(
        RevocationFloorV1(
            service_instance_id=decision.service_instance_id,
            environment_id=decision.environment_id,
            decision_policy_id=decision.decision_policy_id,
            namespace=view.namespace,
            root_version=view.root_version,
            version=view.version,
            snapshot_id=view.snapshot_id,
            evidence=_floor_evidence(),
        )
        for view in decision.revocation_views
    )


def _genesis_head_floor(decision: IntegrityDecisionV1) -> HeadCheckpointFloorV1:
    return HeadCheckpointFloorV1(
        service_instance_id=decision.service_instance_id,
        environment_id=decision.environment_id,
        instance_sequence=-1,
        checkpoint_id=head_checkpoint_genesis_id(
            service_instance_id=decision.service_instance_id,
            environment_id=decision.environment_id,
        ),
        checkpoint_attestation_id=None,
        checkpoint_principal_id=None,
        checkpoint_trust_snapshot_id=None,
        mission_id=decision.mission_id,
        mission_event_seq=-1,
        mission_checkpoint_id=mission_checkpoint_genesis_id(
            service_instance_id=decision.service_instance_id,
            environment_id=decision.environment_id,
            mission_id=decision.mission_id,
        ),
        mission_checkpoint_attestation_id=None,
        mission_checkpoint_principal_id=None,
        mission_checkpoint_trust_snapshot_id=None,
        evidence=_floor_evidence(),
    )


def _head_floor(
    checkpoint: AuthenticatedHeadCheckpointV1,
) -> HeadCheckpointFloorV1:
    return HeadCheckpointFloorV1(
        service_instance_id=checkpoint.checkpoint.service_instance_id,
        environment_id=checkpoint.checkpoint.environment_id,
        instance_sequence=checkpoint.checkpoint.instance_sequence,
        checkpoint_id=checkpoint.checkpoint.checkpoint_id,
        checkpoint_attestation_id=signed_head_checkpoint_attestation_id(checkpoint.signed_checkpoint),
        checkpoint_principal_id=checkpoint.signer_principal_id,
        checkpoint_trust_snapshot_id=checkpoint.trust_snapshot_id,
        mission_id=checkpoint.checkpoint.mission_id,
        mission_event_seq=checkpoint.checkpoint.event_seq,
        mission_checkpoint_id=checkpoint.checkpoint.checkpoint_id,
        mission_checkpoint_attestation_id=(signed_head_checkpoint_attestation_id(checkpoint.signed_checkpoint)),
        mission_checkpoint_principal_id=checkpoint.signer_principal_id,
        mission_checkpoint_trust_snapshot_id=checkpoint.trust_snapshot_id,
        evidence=_floor_evidence(),
    )


def test_signed_integrity_objects_round_trip_and_dispatch(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> None:
    decision = _decision()
    signed_decision = decision_signer.sign_decision(decision)
    assert SignedIntegrityDecisionV1.from_bytes(signed_decision.to_bytes()) == signed_decision
    assert parse_semantic_bytes(signed_decision.to_bytes()) == signed_decision

    checkpoint = _checkpoint(decision)
    signed_checkpoint = checkpoint_signer.sign_checkpoint(checkpoint)
    assert SignedHeadCheckpointV1.from_bytes(signed_checkpoint.to_bytes()) == signed_checkpoint
    assert parse_semantic_bytes(signed_checkpoint.to_bytes()) == signed_checkpoint


def test_integrity_semantics_are_content_addressed_and_deeply_immutable() -> None:
    decision = _decision()
    assert IntegrityDecisionV1.from_envelope(decision.to_envelope()) == decision
    assert HeadCheckpointV1.from_envelope(_checkpoint(decision).to_envelope()) == _checkpoint(decision)
    with pytest.raises(IntegrityError, match="decision_id"):
        replace(decision, decision_id=_digest("detached"))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("service_instance_id", "other.instance"),
        ("environment_id", "other.environment"),
        ("mission_id", _digest("other-mission")),
        ("authority_id", _digest("other-authority")),
        ("target_id", _digest("other-target")),
        ("prior_global_checkpoint_sequence", 13),
        ("prior_global_checkpoint_id", _digest("other-global-head")),
        (
            "prior_global_checkpoint_attestation_id",
            _digest("other-global-attestation"),
        ),
        (
            "prior_global_checkpoint_principal_id",
            "other.global-principal",
        ),
        (
            "prior_global_checkpoint_trust_snapshot_id",
            _digest("other-global-trust"),
        ),
        ("prior_event_seq", 13),
        ("prior_event_digest", _digest("other-head")),
        ("event_kind", "verification_lease_expired"),
        ("proposed_event_digest", _digest("other-proposed-event")),
        ("transition_intent_id", _digest("other-intent")),
        ("request_nonce", "f" * 64),
        ("time_policy_id", _digest("other-time-policy")),
        ("decision_policy_id", _digest("other-decision-policy")),
    ],
)
def test_every_expected_transition_binding_fails_closed(
    field: str,
    value: object,
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> None:
    decision = _decision()
    kwargs = _decision_auth_kwargs(decision)
    expected_name = {
        "service_instance_id": "expected_service_instance_id",
        "environment_id": "expected_environment_id",
        "mission_id": "expected_mission_id",
        "authority_id": "expected_authority_id",
        "target_id": "expected_target_id",
        "prior_global_checkpoint_sequence": ("expected_prior_global_checkpoint_sequence"),
        "prior_global_checkpoint_id": ("expected_prior_global_checkpoint_id"),
        "prior_global_checkpoint_attestation_id": ("expected_prior_global_checkpoint_attestation_id"),
        "prior_global_checkpoint_principal_id": ("expected_prior_global_checkpoint_principal_id"),
        "prior_global_checkpoint_trust_snapshot_id": ("expected_prior_global_checkpoint_trust_snapshot_id"),
        "prior_event_seq": "expected_prior_event_seq",
        "prior_event_digest": "expected_prior_event_digest",
        "event_kind": "expected_event_kind",
        "proposed_event_digest": "expected_proposed_event_digest",
        "transition_intent_id": "expected_transition_intent_id",
        "request_nonce": "expected_request_nonce",
        "time_policy_id": "expected_time_policy_id",
        "decision_policy_id": "expected_decision_policy_id",
    }[field]
    kwargs[expected_name] = value
    with pytest.raises(IntegrityError, match="does not bind"):
        authenticate_integrity_decision(
            decision_signer.sign_decision(decision),
            _trust_store(decision_signer, checkpoint_signer),
            **kwargs,
        )


def test_evidence_quorum_requires_sorted_independent_sources() -> None:
    with pytest.raises(IntegrityError, match="2..16"):
        _decision(
            time_evidence=(
                _reference(
                    TRUSTED_TIME_EVIDENCE_KIND,
                    "time.only",
                    "only",
                ),
            )
        )
    with pytest.raises(IntegrityError, match="source-sorted"):
        _decision(time_evidence=tuple(reversed(_time_evidence())))
    with pytest.raises(IntegrityError, match="unique sources"):
        _decision(
            time_evidence=(
                _reference(TRUSTED_TIME_EVIDENCE_KIND, "time.same", "one"),
                _reference(TRUSTED_TIME_EVIDENCE_KIND, "time.same", "two"),
            )
        )
    with pytest.raises(IntegrityError, match="evidence IDs"):
        _decision(
            time_evidence=(
                _reference(TRUSTED_TIME_EVIDENCE_KIND, "time.a", "same"),
                _reference(TRUSTED_TIME_EVIDENCE_KIND, "time.b", "same"),
            )
        )
    oversized = tuple(
        _reference(
            TRUSTED_TIME_EVIDENCE_KIND,
            f"time.source-{index}",
            f"time-evidence-{index}",
        )
        for index in range(integrity_contract.MAX_EVIDENCE_REFS + 1)
    )
    with pytest.raises(IntegrityError) as caught:
        _decision(time_evidence=oversized)
    assert caught.value.reason_code == "invalid_time_evidence"


def test_time_interval_and_revocation_validity_fail_closed() -> None:
    with pytest.raises(IntegrityError, match="lower bound"):
        _decision(time_lower_bound=NOW + 2, time_upper_bound=NOW + 1)
    with pytest.raises(IntegrityError) as caught:
        _decision(
            revocation_views=_revocation_views(
                valid_from=NOW + 1,
                valid_until=NOW + 60,
            )
        )
    assert "straddles_not_before" in caught.value.reason_code
    with pytest.raises(IntegrityError) as caught:
        _decision(
            revocation_views=_revocation_views(
                valid_from=NOW - 60,
                valid_until=NOW + 1,
            )
        )
    assert "straddles_expiry" in caught.value.reason_code


def test_conservative_interval_boundary_semantics() -> None:
    require_interval_within(_decision(), not_before=NOW, expires_at=NOW + 2)

    with pytest.raises(IntegrityError) as caught:
        require_interval_within(
            _decision(time_lower_bound=NOW - 1),
            not_before=NOW,
            expires_at=NOW + 2,
        )
    assert caught.value.reason_code == "decision_time_interval_straddles_not_before"

    with pytest.raises(IntegrityError) as caught:
        require_interval_within(
            _decision(time_upper_bound=NOW + 2),
            not_before=NOW,
            expires_at=NOW + 2,
        )
    assert caught.value.reason_code == "decision_time_interval_straddles_expiry"

    assert (
        classify_deadline(
            time_lower_bound=NOW,
            time_upper_bound=NOW + 1,
            deadline=NOW + 2,
        )
        == "before"
    )
    assert (
        classify_deadline(
            time_lower_bound=NOW + 2,
            time_upper_bound=NOW + 3,
            deadline=NOW + 2,
        )
        == "at_or_after"
    )
    with pytest.raises(IntegrityError) as caught:
        classify_deadline(
            time_lower_bound=NOW,
            time_upper_bound=NOW + 1,
            deadline=NOW + 1,
        )
    assert caught.value.reason_code == "time_interval_straddles_deadline"


def test_uncertainty_policy_is_caller_owned_and_fail_closed(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> None:
    decision = _decision(time_upper_bound=NOW + 3)
    with pytest.raises(IntegrityError) as caught:
        authenticate_integrity_decision(
            decision_signer.sign_decision(decision),
            _trust_store(decision_signer, checkpoint_signer),
            **{
                **_decision_auth_kwargs(decision),
                "max_time_uncertainty_seconds": 2,
            },
        )
    assert caught.value.reason_code == "time_uncertainty_exceeded"


def test_consequential_validation_reapplies_narrower_caller_policy(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> None:
    trust_store = _trust_store(decision_signer, checkpoint_signer)
    wide_decision = _decision(time_upper_bound=NOW + 4)
    authenticated_wide_decision = authenticate_integrity_decision(
        decision_signer.sign_decision(wide_decision),
        trust_store,
        **{
            **_decision_auth_kwargs(wide_decision),
            "max_time_uncertainty_seconds": 4,
        },
    )
    with pytest.raises(IntegrityError) as caught:
        validate_revocation_advance(
            None,
            authenticated_wide_decision,
            previous_global_decision_trust_store=None,
            previous_global_checkpoint=None,
            previous_global_checkpoint_trust_store=None,
            current_trust_store=trust_store,
            external_floors=_revocation_floors(wide_decision),
            validation_policy=_validation_policy(max_decision_uncertainty_seconds=2),
        )
    assert caught.value.reason_code == "time_uncertainty_exceeded"

    decision = _decision()
    authenticated_decision = _authenticate(
        decision,
        decision_signer,
        checkpoint_signer,
    )
    wide_checkpoint = _checkpoint(
        decision,
        authenticated_decision=authenticated_decision,
        time_upper_bound=NOW + 5,
    )
    authenticated_wide_checkpoint = authenticate_head_checkpoint(
        checkpoint_signer.sign_checkpoint(wide_checkpoint),
        trust_store,
        **{
            **_checkpoint_auth_kwargs(wide_checkpoint),
            "forbidden_key_ids": (authenticated_decision.signed_decision.key_id,),
            "forbidden_principal_ids": (authenticated_decision.signer_principal_id,),
            "max_time_uncertainty_seconds": 4,
        },
    )
    with pytest.raises(IntegrityError) as caught:
        validate_checkpoint_binding(
            authenticated_wide_checkpoint,
            authenticated_decision,
            event=_proposed_event(decision),
            checkpoint_trust_store=trust_store,
            decision_trust_store=trust_store,
            previous_mission=None,
            previous_mission_trust_store=None,
            validation_policy=_validation_policy(max_checkpoint_uncertainty_seconds=2),
        )
    assert caught.value.reason_code == "time_uncertainty_exceeded"

    with pytest.raises(IntegrityError) as caught:
        validate_revocation_advance(
            None,
            authenticated_decision,
            previous_global_decision_trust_store=None,
            previous_global_checkpoint=None,
            previous_global_checkpoint_trust_store=None,
            current_trust_store=trust_store,
            external_floors=_revocation_floors(decision),
            validation_policy=_validation_policy(decision_policy_id=_digest("unaccepted-decision-policy")),
        )
    assert caught.value.reason_code == "decision_policy_mismatch"


def test_historical_checkpoints_must_satisfy_current_composition_policy(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> None:
    trust_store = _trust_store(decision_signer, checkpoint_signer)
    first_decision = _decision()
    authenticated_first_decision = _authenticate(
        first_decision,
        decision_signer,
        checkpoint_signer,
    )
    first_checkpoint = _checkpoint(
        first_decision,
        authenticated_decision=authenticated_first_decision,
        anchor_policy_id=_digest("retired-anchor-policy"),
    )
    authenticated_first_checkpoint = _authenticate_checkpoint(
        first_checkpoint,
        authenticated_first_decision,
        decision_signer,
        checkpoint_signer,
    )
    second_decision = _decision(
        **_global_predecessor(authenticated_first_checkpoint),
        prior_event_seq=first_checkpoint.event_seq,
        prior_event_digest=first_checkpoint.event_digest,
        request_nonce=hashlib.sha256(b"policy-successor").hexdigest(),
        revocation_views=_revocation_views(
            authority_version=8,
            authority_snapshot=_digest("authority-snapshot-8"),
            authority_evidence=_digest("authority-evidence-8"),
        ),
    )
    authenticated_second_decision = _authenticate(
        second_decision,
        decision_signer,
        checkpoint_signer,
    )

    with pytest.raises(IntegrityError) as caught:
        validate_revocation_advance(
            authenticated_first_decision,
            authenticated_second_decision,
            previous_global_decision_trust_store=trust_store,
            previous_global_checkpoint=authenticated_first_checkpoint,
            previous_global_checkpoint_trust_store=trust_store,
            current_trust_store=trust_store,
            external_floors=_revocation_floors(first_decision),
            validation_policy=_validation_policy(),
        )
    assert caught.value.reason_code == "anchor_policy_mismatch"

    second_checkpoint = _checkpoint(
        second_decision,
        authenticated_decision=authenticated_second_decision,
        instance_sequence=1,
        previous_global=authenticated_first_checkpoint,
        previous_mission=authenticated_first_checkpoint,
    )
    authenticated_second_checkpoint = _authenticate_checkpoint(
        second_checkpoint,
        authenticated_second_decision,
        decision_signer,
        checkpoint_signer,
    )
    with pytest.raises(IntegrityError) as caught:
        validate_checkpoint_binding(
            authenticated_second_checkpoint,
            authenticated_second_decision,
            event=_proposed_event(second_decision),
            checkpoint_trust_store=trust_store,
            decision_trust_store=trust_store,
            previous_mission=authenticated_first_checkpoint,
            previous_mission_trust_store=trust_store,
            validation_policy=_validation_policy(),
        )
    assert caught.value.reason_code == "anchor_policy_mismatch"

    with pytest.raises(IntegrityError) as caught:
        validate_checkpoint_advance(
            authenticated_second_checkpoint,
            current_trust_store=trust_store,
            current_decision=authenticated_second_decision,
            current_decision_trust_store=trust_store,
            previous_global=authenticated_first_checkpoint,
            previous_global_trust_store=trust_store,
            previous_mission=authenticated_first_checkpoint,
            previous_mission_trust_store=trust_store,
            external_floor=_head_floor(authenticated_first_checkpoint),
            validation_policy=_validation_policy(),
        )
    assert caught.value.reason_code == "anchor_policy_mismatch"


def test_successor_intervals_cannot_precede_their_checkpoint_baseline(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> None:
    trust_store = _trust_store(decision_signer, checkpoint_signer)
    first_decision = _decision()
    authenticated_first_decision = _authenticate(
        first_decision,
        decision_signer,
        checkpoint_signer,
    )
    first_checkpoint = _checkpoint(
        first_decision,
        authenticated_decision=authenticated_first_decision,
        time_lower_bound=NOW + 10,
        time_upper_bound=NOW + 11,
    )
    authenticated_first_checkpoint = _authenticate_checkpoint(
        first_checkpoint,
        authenticated_first_decision,
        decision_signer,
        checkpoint_signer,
    )
    stale_decision = _decision(
        **_global_predecessor(authenticated_first_checkpoint),
        prior_event_seq=first_checkpoint.event_seq,
        prior_event_digest=first_checkpoint.event_digest,
        request_nonce=hashlib.sha256(b"stale-successor-time").hexdigest(),
        time_lower_bound=NOW + 1,
        time_upper_bound=NOW + 2,
        revocation_views=_revocation_views(
            authority_version=8,
            authority_snapshot=_digest("authority-snapshot-8"),
            authority_evidence=_digest("authority-evidence-8"),
        ),
    )
    authenticated_stale_decision = _authenticate(
        stale_decision,
        decision_signer,
        checkpoint_signer,
    )
    stale_checkpoint = _checkpoint(
        stale_decision,
        authenticated_decision=authenticated_stale_decision,
        instance_sequence=1,
        previous_global=authenticated_first_checkpoint,
        previous_mission=authenticated_first_checkpoint,
    )
    authenticated_stale_checkpoint = _authenticate_checkpoint(
        stale_checkpoint,
        authenticated_stale_decision,
        decision_signer,
        checkpoint_signer,
    )

    with pytest.raises(IntegrityError) as caught:
        validate_revocation_advance(
            authenticated_first_decision,
            authenticated_stale_decision,
            previous_global_decision_trust_store=trust_store,
            previous_global_checkpoint=authenticated_first_checkpoint,
            previous_global_checkpoint_trust_store=trust_store,
            current_trust_store=trust_store,
            external_floors=_revocation_floors(first_decision),
            validation_policy=_validation_policy(),
        )
    assert caught.value.reason_code == "decision_time_precedes_checkpoint"

    with pytest.raises(IntegrityError) as caught:
        validate_checkpoint_binding(
            authenticated_stale_checkpoint,
            authenticated_stale_decision,
            event=_proposed_event(stale_decision),
            checkpoint_trust_store=trust_store,
            decision_trust_store=trust_store,
            previous_mission=authenticated_first_checkpoint,
            previous_mission_trust_store=trust_store,
            validation_policy=_validation_policy(),
        )
    assert caught.value.reason_code == "decision_time_precedes_checkpoint"

    with pytest.raises(IntegrityError) as caught:
        validate_checkpoint_advance(
            authenticated_stale_checkpoint,
            current_trust_store=trust_store,
            current_decision=authenticated_stale_decision,
            current_decision_trust_store=trust_store,
            previous_global=authenticated_first_checkpoint,
            previous_global_trust_store=trust_store,
            previous_mission=authenticated_first_checkpoint,
            previous_mission_trust_store=trust_store,
            external_floor=_head_floor(authenticated_first_checkpoint),
            validation_policy=_validation_policy(),
        )
    assert caught.value.reason_code == "decision_time_precedes_checkpoint"


def test_authentication_rejects_forged_unknown_revoked_and_wrong_role_keys(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> None:
    decision = _decision()
    signed = decision_signer.sign_decision(decision)
    other = IntegritySigner.generate(INTEGRITY_DECISION_ROLE)
    forged_signature = other.private_key.sign(b"etzio.integrity-decision.signature.v1\x00" + signed.envelope_bytes)
    forged = SignedIntegrityDecisionV1(
        signed.envelope_bytes,
        signed.key_id,
        base64.b64encode(forged_signature).decode("ascii"),
    )
    with pytest.raises(IntegrityError) as caught:
        authenticate_integrity_decision(
            forged,
            _trust_store(decision_signer, checkpoint_signer),
            **_decision_auth_kwargs(decision),
        )
    assert caught.value.reason_code == "invalid_signature"

    unknown_store = IntegrityTrustStore.from_keys(
        (
            TrustedIntegrityKey(
                "anchor.only",
                checkpoint_signer.public_key_bytes,
                HEAD_CHECKPOINT_ROLE,
            ),
        )
    )
    with pytest.raises(IntegrityError) as caught:
        authenticate_integrity_decision(
            signed,
            unknown_store,
            **_decision_auth_kwargs(decision),
        )
    assert caught.value.reason_code == "unknown_key"

    revoked_store = _trust_store(
        decision_signer,
        checkpoint_signer,
        revoked_key_ids=(decision_signer.key_id,),
    )
    with pytest.raises(IntegrityError) as caught:
        authenticate_integrity_decision(
            signed,
            revoked_store,
            **_decision_auth_kwargs(decision),
        )
    assert caught.value.reason_code == "key_revoked"

    wrong_role_store = IntegrityTrustStore.from_keys(
        (
            TrustedIntegrityKey(
                "wrong.role",
                decision_signer.public_key_bytes,
                HEAD_CHECKPOINT_ROLE,
            ),
        )
    )
    with pytest.raises(IntegrityError) as caught:
        authenticate_integrity_decision(
            signed,
            wrong_role_store,
            **_decision_auth_kwargs(decision),
        )
    assert caught.value.reason_code == "key_role_mismatch"


def test_signature_precedes_attacker_controlled_semantic_interpretation(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> None:
    valid = _decision()
    arbitrary = EnvelopeV1.create(
        "integrity_decision",
        {"attacker_controlled": True},
    ).to_bytes()
    invalid_signature = SignedIntegrityDecisionV1(
        arbitrary,
        decision_signer.key_id,
        base64.b64encode(b"\x00" * 64).decode("ascii"),
    )
    with pytest.raises(IntegrityError) as caught:
        authenticate_integrity_decision(
            invalid_signature,
            _trust_store(decision_signer, checkpoint_signer),
            **_decision_auth_kwargs(valid),
        )
    assert caught.value.reason_code == "invalid_signature"

    valid_signature = decision_signer.private_key.sign(b"etzio.integrity-decision.signature.v1\x00" + arbitrary)
    semantically_invalid = SignedIntegrityDecisionV1(
        arbitrary,
        decision_signer.key_id,
        base64.b64encode(valid_signature).decode("ascii"),
    )
    with pytest.raises(IntegrityError) as caught:
        authenticate_integrity_decision(
            semantically_invalid,
            _trust_store(decision_signer, checkpoint_signer),
            **_decision_auth_kwargs(valid),
        )
    assert caught.value.reason_code == "invalid_integrity_decision"


def test_checkpoint_requires_separate_principal_and_signature_domain(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> None:
    decision = _decision()
    checkpoint = _checkpoint(decision)
    signed = checkpoint_signer.sign_checkpoint(checkpoint)
    trust_store = _trust_store(decision_signer, checkpoint_signer)

    with pytest.raises(IntegrityError) as caught:
        authenticate_head_checkpoint(
            signed,
            trust_store,
            **_checkpoint_auth_kwargs(
                checkpoint,
                forbidden_key_ids=(checkpoint_signer.key_id,),
            ),
        )
    assert caught.value.reason_code == "principal_separation_violation"

    wrong_domain_signature = checkpoint_signer.private_key.sign(
        b"etzio.integrity-decision.signature.v1\x00" + signed.envelope_bytes
    )
    wrong_domain = SignedHeadCheckpointV1(
        signed.envelope_bytes,
        signed.key_id,
        base64.b64encode(wrong_domain_signature).decode("ascii"),
    )
    with pytest.raises(IntegrityError) as caught:
        authenticate_head_checkpoint(
            wrong_domain,
            trust_store,
            **_checkpoint_auth_kwargs(checkpoint),
        )
    assert caught.value.reason_code == "invalid_signature"


def test_unattested_or_multiply_attested_required_objects_do_not_dispatch(
    decision_signer: IntegritySigner,
) -> None:
    decision = _decision()
    with pytest.raises(IntegrityError, match="exactly one"):
        SignedIntegrityDecisionV1.from_bytes(decision.to_envelope().to_bytes())

    signed = decision_signer.sign_decision(decision)
    attestation = signed.to_envelope().to_dict()["attestations"][0]
    doubled = EnvelopeV1.create(
        "integrity_decision",
        decision.to_envelope().body,
        attestations=[attestation, attestation],
    )
    with pytest.raises(IntegrityError, match="exactly one"):
        SignedIntegrityDecisionV1.from_bytes(doubled.to_bytes())


def test_small_order_integrity_keys_are_rejected() -> None:
    with pytest.raises(IntegrityError) as caught:
        TrustedIntegrityKey(
            "invalid.key",
            b"\x00" * 32,
            INTEGRITY_DECISION_ROLE,
        )
    assert caught.value.reason_code == "invalid_public_key"


def test_revocation_floor_rejects_namespace_removal_rollback_and_mutation(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> None:
    previous_value = _decision()
    previous = _authenticate(
        previous_value,
        decision_signer,
        checkpoint_signer,
    )
    previous_checkpoint = _authenticate_checkpoint(
        _checkpoint(
            previous_value,
            authenticated_decision=previous,
        ),
        previous,
        decision_signer,
        checkpoint_signer,
    )
    predecessor = _global_predecessor(previous_checkpoint)
    advanced_value = _decision(
        **predecessor,
        revocation_views=_revocation_views(
            authority_version=8,
            authority_snapshot=_digest("authority-snapshot-8"),
            authority_evidence=_digest("authority-evidence-8"),
        ),
    )
    validate_revocation_advance(
        previous,
        _authenticate(
            advanced_value,
            decision_signer,
            checkpoint_signer,
        ),
        external_floors=_revocation_floors(previous_value),
        **_revocation_context(
            decision_signer,
            checkpoint_signer,
            previous_global_decision=previous,
            previous_global_checkpoint=previous_checkpoint,
        ),
    )

    removed_value = _decision(
        **predecessor,
        revocation_views=(_revocation_views()[0],),
    )
    removed_kwargs = {
        **_decision_auth_kwargs(removed_value),
        "required_revocation_namespaces": ("authority",),
    }
    with pytest.raises(IntegrityError) as caught:
        removed_context = _revocation_context(
            decision_signer,
            checkpoint_signer,
            previous_global_decision=previous,
            previous_global_checkpoint=previous_checkpoint,
        )
        removed_context["validation_policy"] = _validation_policy(
            required_revocation_namespaces=frozenset({"authority"})
        )
        validate_revocation_advance(
            previous,
            authenticate_integrity_decision(
                decision_signer.sign_decision(removed_value),
                _trust_store(decision_signer, checkpoint_signer),
                **removed_kwargs,
            ),
            external_floors=_revocation_floors(removed_value),
            **removed_context,
        )
    assert caught.value.reason_code == "revocation_namespace_removed"

    with pytest.raises(IntegrityError) as caught:
        _decision(revocation_views=_revocation_views(authority_root=0))
    assert caught.value.reason_code == "invalid_root_version"

    rollback_value = _decision(**predecessor, revocation_views=_revocation_views(authority_version=6))
    with pytest.raises(IntegrityError) as caught:
        validate_revocation_advance(
            previous,
            _authenticate(
                rollback_value,
                decision_signer,
                checkpoint_signer,
            ),
            external_floors=_revocation_floors(rollback_value),
            **_revocation_context(
                decision_signer,
                checkpoint_signer,
                previous_global_decision=previous,
                previous_global_checkpoint=previous_checkpoint,
            ),
        )
    assert caught.value.reason_code == "revocation_version_rollback"

    mutation_value = _decision(
        **predecessor, revocation_views=_revocation_views(authority_snapshot=_digest("same-version-different-snapshot"))
    )
    with pytest.raises(IntegrityError) as caught:
        validate_revocation_advance(
            previous,
            _authenticate(
                mutation_value,
                decision_signer,
                checkpoint_signer,
            ),
            external_floors=_revocation_floors(mutation_value),
            **_revocation_context(
                decision_signer,
                checkpoint_signer,
                previous_global_decision=previous,
                previous_global_checkpoint=previous_checkpoint,
            ),
        )
    assert caught.value.reason_code == "revocation_same_version_mutation"


def test_revocation_root_rollback_is_distinct(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> None:
    previous_value = _decision(revocation_views=_revocation_views(authority_root=2))
    current_value = _decision()
    previous = _authenticate(
        previous_value,
        decision_signer,
        checkpoint_signer,
    )
    previous_checkpoint = _authenticate_checkpoint(
        _checkpoint(
            previous_value,
            authenticated_decision=previous,
        ),
        previous,
        decision_signer,
        checkpoint_signer,
    )
    current_value = _decision(**_global_predecessor(previous_checkpoint))
    with pytest.raises(IntegrityError) as caught:
        validate_revocation_advance(
            previous,
            _authenticate(
                current_value,
                decision_signer,
                checkpoint_signer,
            ),
            external_floors=_revocation_floors(current_value),
            **_revocation_context(
                decision_signer,
                checkpoint_signer,
                previous_global_decision=previous,
                previous_global_checkpoint=previous_checkpoint,
            ),
        )
    assert caught.value.reason_code == "revocation_root_rollback"


def test_revocation_cannot_validate_against_an_older_global_baseline(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> None:
    decision_a = _decision(revocation_views=_revocation_views(authority_version=1))
    authenticated_a = _authenticate(
        decision_a,
        decision_signer,
        checkpoint_signer,
    )
    checkpoint_a = _checkpoint(
        decision_a,
        authenticated_decision=authenticated_a,
    )
    authenticated_checkpoint_a = _authenticate_checkpoint(
        checkpoint_a,
        authenticated_a,
        decision_signer,
        checkpoint_signer,
    )

    decision_b = _decision(
        **_global_predecessor(authenticated_checkpoint_a),
        prior_event_seq=checkpoint_a.event_seq,
        prior_event_digest=checkpoint_a.event_digest,
        request_nonce=hashlib.sha256(b"baseline-b").hexdigest(),
        revocation_views=_revocation_views(
            authority_version=10,
            authority_snapshot=_digest("authority-snapshot-10"),
            authority_evidence=_digest("authority-evidence-10"),
        ),
    )
    authenticated_b = _authenticate(
        decision_b,
        decision_signer,
        checkpoint_signer,
    )
    checkpoint_b = _checkpoint(
        decision_b,
        authenticated_decision=authenticated_b,
        instance_sequence=1,
        previous_global=authenticated_checkpoint_a,
        previous_mission=authenticated_checkpoint_a,
    )
    authenticated_checkpoint_b = _authenticate_checkpoint(
        checkpoint_b,
        authenticated_b,
        decision_signer,
        checkpoint_signer,
    )

    decision_c = _decision(
        **_global_predecessor(authenticated_checkpoint_b),
        prior_event_seq=checkpoint_b.event_seq,
        prior_event_digest=checkpoint_b.event_digest,
        request_nonce=hashlib.sha256(b"baseline-c").hexdigest(),
        revocation_views=_revocation_views(
            authority_version=2,
            authority_snapshot=_digest("authority-snapshot-2"),
            authority_evidence=_digest("authority-evidence-2"),
        ),
    )
    authenticated_c = _authenticate(
        decision_c,
        decision_signer,
        checkpoint_signer,
    )
    assert authenticated_c.decision.prior_global_checkpoint_id == authenticated_checkpoint_b.checkpoint.checkpoint_id

    with pytest.raises(IntegrityError) as caught:
        validate_revocation_advance(
            authenticated_a,
            authenticated_c,
            previous_global_decision_trust_store=_trust_store(
                decision_signer,
                checkpoint_signer,
            ),
            previous_global_checkpoint=authenticated_checkpoint_a,
            previous_global_checkpoint_trust_store=_trust_store(
                decision_signer,
                checkpoint_signer,
            ),
            current_trust_store=_trust_store(
                decision_signer,
                checkpoint_signer,
            ),
            external_floors=_revocation_floors(decision_a),
            validation_policy=_validation_policy(),
        )
    assert caught.value.reason_code == "current_global_predecessor_mismatch"


def test_external_revocation_floor_cannot_lag_retained_local_history(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> None:
    previous_value = _decision(
        revocation_views=_revocation_views(
            authority_version=10,
            authority_snapshot=_digest("authority-snapshot-10"),
            authority_evidence=_digest("authority-evidence-10"),
            verifier_version=10,
            verifier_snapshot=_digest("verifier-snapshot-10"),
            verifier_evidence=_digest("verifier-evidence-10"),
        )
    )
    previous = _authenticate(
        previous_value,
        decision_signer,
        checkpoint_signer,
    )
    previous_checkpoint = _authenticate_checkpoint(
        _checkpoint(
            previous_value,
            authenticated_decision=previous,
        ),
        previous,
        decision_signer,
        checkpoint_signer,
    )
    current_value = _decision(
        **_global_predecessor(previous_checkpoint),
        revocation_views=_revocation_views(
            authority_version=11,
            authority_snapshot=_digest("authority-snapshot-11"),
            authority_evidence=_digest("authority-evidence-11"),
            verifier_version=11,
            verifier_snapshot=_digest("verifier-snapshot-11"),
            verifier_evidence=_digest("verifier-evidence-11"),
        ),
    )
    stale_floor_value = _decision(
        revocation_views=_revocation_views(
            authority_version=1,
            authority_snapshot=_digest("authority-snapshot-1"),
            authority_evidence=_digest("authority-evidence-1"),
            verifier_version=1,
            verifier_snapshot=_digest("verifier-snapshot-1"),
            verifier_evidence=_digest("verifier-evidence-1"),
        )
    )

    with pytest.raises(IntegrityError) as caught:
        validate_revocation_advance(
            previous,
            _authenticate(
                current_value,
                decision_signer,
                checkpoint_signer,
            ),
            external_floors=_revocation_floors(stale_floor_value),
            **_revocation_context(
                decision_signer,
                checkpoint_signer,
                previous_global_decision=previous,
                previous_global_checkpoint=previous_checkpoint,
            ),
        )
    assert caught.value.reason_code == "external_revocation_floor_rollback"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("service_instance_id", "Etzio.other-instance"),
        ("environment_id", "other.environment"),
        ("mission_id", _digest("other-mission")),
        ("authority_id", _digest("other-authority")),
        ("target_id", _digest("other-target")),
        ("integrity_decision_id", _digest("other-decision")),
        ("event_seq", 16),
        ("event_digest", _digest("other-event")),
    ],
)
def test_checkpoint_binding_rejects_every_substitution(
    field: str,
    value: object,
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> None:
    decision = _decision()
    authenticated = _authenticate(decision, decision_signer, checkpoint_signer)
    checkpoint = _checkpoint(
        decision,
        authenticated_decision=authenticated,
        **{field: value},
    )
    authenticated_checkpoint = _authenticate_checkpoint(
        checkpoint,
        authenticated,
        decision_signer,
        checkpoint_signer,
    )
    with pytest.raises(IntegrityError) as caught:
        validate_checkpoint_binding(
            authenticated_checkpoint,
            authenticated,
            event=_proposed_event(decision),
            **_binding_context(decision_signer, checkpoint_signer),
        )
    assert caught.value.reason_code == "checkpoint_binding_mismatch"


def test_checkpoint_binds_the_exact_canonical_event_and_conservative_time(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> None:
    decision = _decision()
    authenticated_decision = _authenticate(
        decision,
        decision_signer,
        checkpoint_signer,
    )
    checkpoint = _checkpoint(
        decision,
        authenticated_decision=authenticated_decision,
    )
    authenticated_checkpoint = _authenticate_checkpoint(
        checkpoint,
        authenticated_decision,
        decision_signer,
        checkpoint_signer,
    )
    event = _proposed_event(decision)
    validate_checkpoint_binding(
        authenticated_checkpoint,
        authenticated_decision,
        event=event,
        **_binding_context(decision_signer, checkpoint_signer),
    )

    substituted_event = EventV1.create(
        mission_id=event.mission_id,
        seq=event.seq,
        kind=event.kind,
        unit=event.unit,
        authority_id=event.authority_id,
        target_id=event.target_id,
        decision_time=event.decision_time,
        payload={"reason_code": "substituted_payload"},
        prev_digest=event.prev_digest,
    )
    with pytest.raises(IntegrityError) as caught:
        validate_checkpoint_binding(
            authenticated_checkpoint,
            authenticated_decision,
            event=substituted_event,
            **_binding_context(decision_signer, checkpoint_signer),
        )
    assert caught.value.reason_code == "checkpoint_binding_mismatch"

    early_checkpoint = _checkpoint(
        decision,
        authenticated_decision=authenticated_decision,
        time_lower_bound=NOW,
        time_upper_bound=NOW + 2,
    )
    authenticated_early_checkpoint = _authenticate_checkpoint(
        early_checkpoint,
        authenticated_decision,
        decision_signer,
        checkpoint_signer,
    )
    with pytest.raises(IntegrityError) as caught:
        validate_checkpoint_binding(
            authenticated_early_checkpoint,
            authenticated_decision,
            event=event,
            **_binding_context(decision_signer, checkpoint_signer),
        )
    assert caught.value.reason_code == "checkpoint_time_precedes_decision"
    with pytest.raises(IntegrityError) as caught:
        validate_checkpoint_advance(
            authenticated_early_checkpoint,
            external_floor=_genesis_head_floor(decision),
            **_advance_context(
                decision_signer,
                checkpoint_signer,
                current_decision=authenticated_decision,
                previous_global=None,
                previous_mission=None,
            ),
        )
    assert caught.value.reason_code == "checkpoint_time_precedes_decision"


def test_anchor_statement_has_no_receipt_hash_cycle() -> None:
    decision = _decision()
    first = _checkpoint(decision)
    second = _checkpoint(
        decision,
        anchor_evidence=(
            _reference(
                HEAD_ANCHOR_RECEIPT_EVIDENCE_KIND,
                "anchor.log-a",
                "replacement-a",
            ),
            _reference(
                HEAD_ANCHOR_RECEIPT_EVIDENCE_KIND,
                "anchor.log-b",
                "replacement-b",
            ),
        ),
    )
    assert first.anchor_statement_id == second.anchor_statement_id
    assert first.checkpoint_id != second.checkpoint_id


def test_evidence_kinds_are_not_interchangeable() -> None:
    with pytest.raises(IntegrityError) as caught:
        _decision(time_evidence=_anchor_evidence())
    assert caught.value.reason_code == "invalid_time_evidence"


def test_required_context_rejects_empty_namespace_and_bool_sequence_alias(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> None:
    decision = _decision(prior_event_seq=1)
    kwargs = {
        **_decision_auth_kwargs(decision),
        "required_revocation_namespaces": (),
    }
    with pytest.raises(IntegrityError) as caught:
        authenticate_integrity_decision(
            decision_signer.sign_decision(decision),
            _trust_store(decision_signer, checkpoint_signer),
            **kwargs,
        )
    assert caught.value.reason_code == "missing_revocation_namespace"

    kwargs = {
        **_decision_auth_kwargs(decision),
        "expected_prior_event_seq": True,
    }
    with pytest.raises(IntegrityError) as caught:
        authenticate_integrity_decision(
            decision_signer.sign_decision(decision),
            _trust_store(decision_signer, checkpoint_signer),
            **kwargs,
        )
    assert caught.value.reason_code == "prior_event_seq_mismatch"


def test_rotated_keys_do_not_bypass_principal_separation() -> None:
    decision_signer = IntegritySigner.generate(INTEGRITY_DECISION_ROLE)
    checkpoint_signer = IntegritySigner.generate(HEAD_CHECKPOINT_ROLE)
    trust_store = IntegrityTrustStore.from_keys(
        (
            TrustedIntegrityKey(
                "shared.control-principal",
                decision_signer.public_key_bytes,
                INTEGRITY_DECISION_ROLE,
            ),
            TrustedIntegrityKey(
                "shared.control-principal",
                checkpoint_signer.public_key_bytes,
                HEAD_CHECKPOINT_ROLE,
            ),
        )
    )
    decision = _decision()
    authenticated_decision = authenticate_integrity_decision(
        decision_signer.sign_decision(decision),
        trust_store,
        **_decision_auth_kwargs(decision),
    )
    checkpoint = _checkpoint(decision)
    with pytest.raises(IntegrityError) as caught:
        authenticate_head_checkpoint(
            checkpoint_signer.sign_checkpoint(checkpoint),
            trust_store,
            **_checkpoint_auth_kwargs(
                checkpoint,
                forbidden_principal_ids=(authenticated_decision.signer_principal_id,),
            ),
        )
    assert caught.value.reason_code == "principal_separation_violation"


def test_external_revocation_floor_detects_rollback_and_equivocation(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> None:
    value = _decision()
    current = _authenticate(value, decision_signer, checkpoint_signer)
    floors = list(_revocation_floors(value))
    floors[0] = replace(floors[0], version=floors[0].version + 1)
    with pytest.raises(IntegrityError) as caught:
        validate_revocation_advance(
            None,
            current,
            external_floors=tuple(floors),
            **_revocation_context(
                decision_signer,
                checkpoint_signer,
                previous_global_decision=None,
                previous_global_checkpoint=None,
            ),
        )
    assert caught.value.reason_code == "external_revocation_version_rollback"

    floors = list(_revocation_floors(value))
    floors[0] = replace(floors[0], snapshot_id=_digest("external-fork"))
    with pytest.raises(IntegrityError) as caught:
        validate_revocation_advance(
            None,
            current,
            external_floors=tuple(floors),
            **_revocation_context(
                decision_signer,
                checkpoint_signer,
                previous_global_decision=None,
                previous_global_checkpoint=None,
            ),
        )
    assert caught.value.reason_code == "external_revocation_equivocation"


def test_external_head_floor_detects_whole_local_history_rollback(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> None:
    decision = _decision(prior_event_seq=-1)
    authenticated_decision = _authenticate(
        decision,
        decision_signer,
        checkpoint_signer,
    )
    first = _checkpoint(
        decision,
        authenticated_decision=authenticated_decision,
        event_seq=0,
    )
    authenticated_first = _authenticate_checkpoint(
        first,
        authenticated_decision,
        decision_signer,
        checkpoint_signer,
    )
    external_ahead = HeadCheckpointFloorV1(
        service_instance_id=decision.service_instance_id,
        environment_id=decision.environment_id,
        instance_sequence=0,
        checkpoint_id=_digest("externally-retained-checkpoint"),
        checkpoint_attestation_id=_digest("external-checkpoint-attestation"),
        checkpoint_principal_id="external.checkpoint-principal",
        checkpoint_trust_snapshot_id=_digest("external-checkpoint-trust"),
        mission_id=decision.mission_id,
        mission_event_seq=0,
        mission_checkpoint_id=_digest("externally-retained-mission-head"),
        mission_checkpoint_attestation_id=_digest("external-mission-checkpoint-attestation"),
        mission_checkpoint_principal_id="external.mission-principal",
        mission_checkpoint_trust_snapshot_id=_digest("external-mission-checkpoint-trust"),
        evidence=_floor_evidence(),
    )
    with pytest.raises(IntegrityError) as caught:
        validate_checkpoint_advance(
            authenticated_first,
            external_floor=external_ahead,
            **_advance_context(
                decision_signer,
                checkpoint_signer,
                current_decision=authenticated_decision,
                previous_global=None,
                previous_mission=None,
            ),
        )
    assert caught.value.reason_code == "external_head_floor_equivocation"


def test_checkpoint_continuity_covers_global_and_mission_heads(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> None:
    first_decision = _decision(prior_event_seq=-1)
    authenticated_first_decision = _authenticate(
        first_decision,
        decision_signer,
        checkpoint_signer,
    )
    first = _checkpoint(
        first_decision,
        authenticated_decision=authenticated_first_decision,
        event_seq=0,
    )
    authenticated_first = _authenticate_checkpoint(
        first,
        authenticated_first_decision,
        decision_signer,
        checkpoint_signer,
    )
    validate_checkpoint_advance(
        authenticated_first,
        external_floor=_genesis_head_floor(first_decision),
        **_advance_context(
            decision_signer,
            checkpoint_signer,
            current_decision=authenticated_first_decision,
            previous_global=None,
            previous_mission=None,
        ),
    )
    validate_checkpoint_advance(
        authenticated_first,
        external_floor=_head_floor(authenticated_first),
        **_advance_context(
            decision_signer,
            checkpoint_signer,
            current_decision=authenticated_first_decision,
            previous_global=None,
            previous_mission=None,
        ),
    )

    second_decision = _decision(
        **_global_predecessor(authenticated_first),
        prior_event_seq=0,
        prior_event_digest=first.event_digest,
        request_nonce=hashlib.sha256(b"next-request").hexdigest(),
    )
    authenticated_second_decision = _authenticate(
        second_decision,
        decision_signer,
        checkpoint_signer,
    )
    second = _checkpoint(
        second_decision,
        authenticated_decision=authenticated_second_decision,
        instance_sequence=1,
        event_seq=1,
        previous_global=authenticated_first,
        previous_mission=authenticated_first,
    )
    authenticated_second = _authenticate_checkpoint(
        second,
        authenticated_second_decision,
        decision_signer,
        checkpoint_signer,
    )
    validate_checkpoint_advance(
        authenticated_second,
        external_floor=_head_floor(authenticated_first),
        **_advance_context(
            decision_signer,
            checkpoint_signer,
            current_decision=authenticated_second_decision,
            previous_global=authenticated_first,
            previous_mission=authenticated_first,
        ),
    )
    validate_checkpoint_advance(
        authenticated_second,
        external_floor=_head_floor(authenticated_second),
        **_advance_context(
            decision_signer,
            checkpoint_signer,
            current_decision=authenticated_second_decision,
            previous_global=authenticated_first,
            previous_mission=authenticated_first,
        ),
    )

    branched_decision = _decision(
        prior_global_checkpoint_sequence=first.instance_sequence,
        prior_global_checkpoint_id=_digest("wrong-global-head"),
        prior_global_checkpoint_attestation_id=_digest("wrong-global-attestation"),
        prior_global_checkpoint_principal_id="wrong.global-principal",
        prior_global_checkpoint_trust_snapshot_id=_digest("wrong-global-trust"),
        prior_event_seq=0,
        prior_event_digest=first.event_digest,
        request_nonce=hashlib.sha256(b"branched-request").hexdigest(),
    )
    authenticated_branched_decision = _authenticate(
        branched_decision,
        decision_signer,
        checkpoint_signer,
    )
    branched = _checkpoint(
        branched_decision,
        authenticated_decision=authenticated_branched_decision,
        instance_sequence=1,
        event_seq=1,
        previous_checkpoint_id=_digest("wrong-global-head"),
        previous_checkpoint_attestation_id=(branched_decision.prior_global_checkpoint_attestation_id),
        previous_checkpoint_principal_id=(branched_decision.prior_global_checkpoint_principal_id),
        previous_checkpoint_trust_snapshot_id=(branched_decision.prior_global_checkpoint_trust_snapshot_id),
        previous_mission=authenticated_first,
    )
    authenticated_branched = _authenticate_checkpoint(
        branched,
        authenticated_branched_decision,
        decision_signer,
        checkpoint_signer,
    )
    with pytest.raises(IntegrityError) as caught:
        validate_checkpoint_advance(
            authenticated_branched,
            external_floor=_head_floor(authenticated_first),
            **_advance_context(
                decision_signer,
                checkpoint_signer,
                current_decision=authenticated_branched_decision,
                previous_global=authenticated_first,
                previous_mission=authenticated_first,
            ),
        )
    assert caught.value.reason_code == "checkpoint_global_branch"


def test_equal_position_global_and_mission_projections_cannot_splice_forks(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> None:
    global_decision = _decision(mission_id=_digest("global-mission"))
    authenticated_global_decision = _authenticate(
        global_decision,
        decision_signer,
        checkpoint_signer,
    )
    global_checkpoint = _checkpoint(
        global_decision,
        authenticated_decision=authenticated_global_decision,
    )
    authenticated_global_checkpoint = _authenticate_checkpoint(
        global_checkpoint,
        authenticated_global_decision,
        decision_signer,
        checkpoint_signer,
    )

    mission_decision = _decision(mission_id=_digest("selected-mission"))
    authenticated_mission_decision = _authenticate(
        mission_decision,
        decision_signer,
        checkpoint_signer,
    )
    mission_checkpoint = _checkpoint(
        mission_decision,
        authenticated_decision=authenticated_mission_decision,
    )
    authenticated_mission_checkpoint = _authenticate_checkpoint(
        mission_checkpoint,
        authenticated_mission_decision,
        decision_signer,
        checkpoint_signer,
    )
    assert global_checkpoint.instance_sequence == mission_checkpoint.instance_sequence == 0
    assert global_checkpoint.checkpoint_id != mission_checkpoint.checkpoint_id

    current_decision = _decision(
        **_global_predecessor(authenticated_global_checkpoint),
        mission_id=mission_decision.mission_id,
        prior_event_seq=mission_checkpoint.event_seq,
        prior_event_digest=mission_checkpoint.event_digest,
        request_nonce=hashlib.sha256(b"projection-splice").hexdigest(),
    )
    authenticated_current_decision = _authenticate(
        current_decision,
        decision_signer,
        checkpoint_signer,
    )
    current_checkpoint = _checkpoint(
        current_decision,
        authenticated_decision=authenticated_current_decision,
        instance_sequence=1,
        previous_global=authenticated_global_checkpoint,
        previous_mission=authenticated_mission_checkpoint,
    )
    authenticated_current_checkpoint = _authenticate_checkpoint(
        current_checkpoint,
        authenticated_current_decision,
        decision_signer,
        checkpoint_signer,
    )
    inconsistent_floor = HeadCheckpointFloorV1(
        service_instance_id=global_checkpoint.service_instance_id,
        environment_id=global_checkpoint.environment_id,
        instance_sequence=global_checkpoint.instance_sequence,
        checkpoint_id=global_checkpoint.checkpoint_id,
        checkpoint_attestation_id=signed_head_checkpoint_attestation_id(
            authenticated_global_checkpoint.signed_checkpoint
        ),
        checkpoint_principal_id=(authenticated_global_checkpoint.signer_principal_id),
        checkpoint_trust_snapshot_id=(authenticated_global_checkpoint.trust_snapshot_id),
        mission_id=mission_checkpoint.mission_id,
        mission_event_seq=mission_checkpoint.event_seq,
        mission_checkpoint_id=mission_checkpoint.checkpoint_id,
        mission_checkpoint_attestation_id=(
            signed_head_checkpoint_attestation_id(authenticated_mission_checkpoint.signed_checkpoint)
        ),
        mission_checkpoint_principal_id=(authenticated_mission_checkpoint.signer_principal_id),
        mission_checkpoint_trust_snapshot_id=(authenticated_mission_checkpoint.trust_snapshot_id),
        evidence=_floor_evidence(),
    )

    with pytest.raises(IntegrityError) as caught:
        validate_checkpoint_advance(
            authenticated_current_checkpoint,
            current_trust_store=_trust_store(
                decision_signer,
                checkpoint_signer,
            ),
            current_decision=authenticated_current_decision,
            current_decision_trust_store=_trust_store(
                decision_signer,
                checkpoint_signer,
            ),
            previous_global=authenticated_global_checkpoint,
            previous_global_trust_store=_trust_store(
                decision_signer,
                checkpoint_signer,
            ),
            previous_mission=authenticated_mission_checkpoint,
            previous_mission_trust_store=_trust_store(
                decision_signer,
                checkpoint_signer,
            ),
            external_floor=inconsistent_floor,
            validation_policy=_validation_policy(),
        )
    assert caught.value.reason_code == "checkpoint_projection_branch"


def test_first_checkpoint_rejects_valid_prefix_and_mission_gaps(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> None:
    global_gap_decision = _decision(
        prior_global_checkpoint_sequence=0,
        prior_global_checkpoint_id=_digest("missing-global-checkpoint"),
        prior_global_checkpoint_attestation_id=_digest("missing-global-attestation"),
        prior_global_checkpoint_principal_id="missing.global-principal",
        prior_global_checkpoint_trust_snapshot_id=_digest("missing-global-trust"),
        prior_event_seq=0,
    )
    authenticated_global_gap_decision = _authenticate(
        global_gap_decision,
        decision_signer,
        checkpoint_signer,
    )
    global_gap = _checkpoint(
        global_gap_decision,
        authenticated_decision=authenticated_global_gap_decision,
        instance_sequence=1,
        event_seq=1,
        previous_checkpoint_id=_digest("missing-global-checkpoint"),
        previous_checkpoint_attestation_id=(global_gap_decision.prior_global_checkpoint_attestation_id),
        previous_checkpoint_principal_id=(global_gap_decision.prior_global_checkpoint_principal_id),
        previous_checkpoint_trust_snapshot_id=(global_gap_decision.prior_global_checkpoint_trust_snapshot_id),
    )
    with pytest.raises(IntegrityError) as caught:
        validate_checkpoint_advance(
            _authenticate_checkpoint(
                global_gap,
                authenticated_global_gap_decision,
                decision_signer,
                checkpoint_signer,
            ),
            external_floor=_genesis_head_floor(global_gap_decision),
            **_advance_context(
                decision_signer,
                checkpoint_signer,
                current_decision=authenticated_global_gap_decision,
                previous_global=None,
                previous_mission=None,
            ),
        )
    assert caught.value.reason_code == "checkpoint_global_gap"

    other_mission_decision = _decision(mission_id=_digest("other-global-mission"))
    authenticated_other_mission_decision = _authenticate(
        other_mission_decision,
        decision_signer,
        checkpoint_signer,
    )
    other_mission_checkpoint = _checkpoint(
        other_mission_decision,
        authenticated_decision=authenticated_other_mission_decision,
    )
    authenticated_other_mission_checkpoint = _authenticate_checkpoint(
        other_mission_checkpoint,
        authenticated_other_mission_decision,
        decision_signer,
        checkpoint_signer,
    )
    mission_gap_decision = _decision(
        **_global_predecessor(authenticated_other_mission_checkpoint),
        prior_event_seq=0,
        prior_event_digest=_digest("missing-mission-event"),
    )
    authenticated_mission_gap_decision = _authenticate(
        mission_gap_decision,
        decision_signer,
        checkpoint_signer,
    )
    mission_gap = _checkpoint(
        mission_gap_decision,
        authenticated_decision=authenticated_mission_gap_decision,
        instance_sequence=1,
        event_seq=1,
        previous_global=authenticated_other_mission_checkpoint,
    )
    mission_genesis = mission_checkpoint_genesis_id(
        service_instance_id=mission_gap_decision.service_instance_id,
        environment_id=mission_gap_decision.environment_id,
        mission_id=mission_gap_decision.mission_id,
    )
    mission_gap_floor = HeadCheckpointFloorV1(
        service_instance_id=other_mission_checkpoint.service_instance_id,
        environment_id=other_mission_checkpoint.environment_id,
        instance_sequence=other_mission_checkpoint.instance_sequence,
        checkpoint_id=other_mission_checkpoint.checkpoint_id,
        checkpoint_attestation_id=signed_head_checkpoint_attestation_id(
            authenticated_other_mission_checkpoint.signed_checkpoint
        ),
        checkpoint_principal_id=(authenticated_other_mission_checkpoint.signer_principal_id),
        checkpoint_trust_snapshot_id=(authenticated_other_mission_checkpoint.trust_snapshot_id),
        mission_id=mission_gap_decision.mission_id,
        mission_event_seq=-1,
        mission_checkpoint_id=mission_genesis,
        mission_checkpoint_attestation_id=None,
        mission_checkpoint_principal_id=None,
        mission_checkpoint_trust_snapshot_id=None,
        evidence=_floor_evidence(),
    )
    with pytest.raises(IntegrityError) as caught:
        validate_checkpoint_advance(
            _authenticate_checkpoint(
                mission_gap,
                authenticated_mission_gap_decision,
                decision_signer,
                checkpoint_signer,
            ),
            external_floor=mission_gap_floor,
            **_advance_context(
                decision_signer,
                checkpoint_signer,
                current_decision=authenticated_mission_gap_decision,
                previous_global=authenticated_other_mission_checkpoint,
                previous_mission=None,
            ),
        )
    assert caught.value.reason_code == "checkpoint_mission_gap"


def test_genesis_ids_are_domain_and_scope_separated() -> None:
    decision = _decision()
    global_id = head_checkpoint_genesis_id(
        service_instance_id=decision.service_instance_id,
        environment_id=decision.environment_id,
    )
    mission_id = mission_checkpoint_genesis_id(
        service_instance_id=decision.service_instance_id,
        environment_id=decision.environment_id,
        mission_id=decision.mission_id,
    )
    assert global_id != mission_id
    assert global_id != head_checkpoint_genesis_id(
        service_instance_id="Etzio.other-instance",
        environment_id=decision.environment_id,
    )


def test_local_checkpoint_authentication_is_explicitly_not_external_retention(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> None:
    decision = _decision()
    checkpoint = _checkpoint(decision)
    authenticated_decision = _authenticate(
        decision,
        decision_signer,
        checkpoint_signer,
    )
    authenticated = _authenticate_checkpoint(
        checkpoint,
        authenticated_decision,
        decision_signer,
        checkpoint_signer,
    )
    assert authenticated.checkpoint == checkpoint
    assert authenticated.signer_principal_id == "integrity.anchor-principal"
    assert "external" not in type(authenticated).__name__.lower()


def test_signer_roles_are_noninterchangeable(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> None:
    decision = _decision()
    with pytest.raises(IntegrityError) as caught:
        checkpoint_signer.sign_decision(decision)
    assert caught.value.reason_code == "signer_role_mismatch"
    with pytest.raises(IntegrityError) as caught:
        decision_signer.sign_checkpoint(_checkpoint(decision))
    assert caught.value.reason_code == "signer_role_mismatch"


def test_noncanonical_signature_and_private_key_types_are_rejected() -> None:
    with pytest.raises(IntegrityError) as caught:
        IntegritySigner(object(), INTEGRITY_DECISION_ROLE)  # type: ignore[arg-type]
    assert caught.value.reason_code == "invalid_private_key"

    decision = _decision()
    with pytest.raises(IntegrityError) as caught:
        SignedIntegrityDecisionV1(
            decision.to_envelope().to_bytes(),
            "ed25519:sha256:" + ("0" * 64),
            base64.b64encode(b"\x00" * 63).decode("ascii"),
        )
    assert caught.value.reason_code == "malformed_signature"


def test_trust_store_rejects_duplicate_key_and_role_aliasing() -> None:
    signer = IntegritySigner.generate(INTEGRITY_DECISION_ROLE)
    key = TrustedIntegrityKey(
        "integrity.principal",
        signer.public_key_bytes,
        INTEGRITY_DECISION_ROLE,
    )
    with pytest.raises(IntegrityError) as caught:
        IntegrityTrustStore.from_keys((key, key))
    assert caught.value.reason_code == "invalid_trust_store"

    with pytest.raises(IntegrityError) as caught:
        TrustedIntegrityKey(
            "integrity.principal",
            Ed25519PrivateKey.generate().public_key().public_bytes_raw(),
            "operator",
        )
    assert caught.value.reason_code == "invalid_integrity_role"


def test_trust_store_iterables_are_bounded_and_fail_deterministically() -> None:
    trusted_keys = tuple(
        TrustedIntegrityKey(
            f"integrity.principal-{index}",
            IntegritySigner.generate(INTEGRITY_DECISION_ROLE).public_key_bytes,
            INTEGRITY_DECISION_ROLE,
        )
        for index in range(integrity_contract.MAX_INTEGRITY_KEYS + 1)
    )
    with pytest.raises(IntegrityError) as caught:
        IntegrityTrustStore.from_keys(iter(trusted_keys))
    assert caught.value.reason_code == "invalid_trust_store"

    with pytest.raises(IntegrityError) as caught:
        IntegrityTrustStore.from_keys(None)  # type: ignore[arg-type]
    assert caught.value.reason_code == "invalid_trust_store"

    with pytest.raises(IntegrityError) as caught:
        IntegrityTrustStore.from_keys(
            trusted_keys[:1],
            revoked_key_ids=None,  # type: ignore[arg-type]
        )
    assert caught.value.reason_code == "invalid_key_ids"


def test_policy_snapshot_bounds_a_hostile_namespace_iterable(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> None:
    class HostileNamespaces:
        def __init__(self) -> None:
            self.reads = 0

        def __iter__(self):
            for _index in range(integrity_contract.MAX_REVOCATION_VIEWS + 2):
                self.reads += 1
                yield "authority"

    hostile_namespaces = HostileNamespaces()
    policy = _validation_policy()
    object.__setattr__(
        policy,
        "required_revocation_namespaces",
        hostile_namespaces,
    )
    decision = _decision()
    authenticated_decision = _authenticate(
        decision,
        decision_signer,
        checkpoint_signer,
    )

    with pytest.raises(IntegrityError) as caught:
        validate_revocation_advance(
            None,
            authenticated_decision,
            previous_global_decision_trust_store=None,
            previous_global_checkpoint=None,
            previous_global_checkpoint_trust_store=None,
            current_trust_store=_trust_store(
                decision_signer,
                checkpoint_signer,
            ),
            external_floors=_revocation_floors(decision),
            validation_policy=policy,
        )
    assert caught.value.reason_code == "invalid_validation_policy"
    assert hostile_namespaces.reads == integrity_contract.MAX_REVOCATION_VIEWS + 1


def test_trust_store_snapshot_bounds_a_hostile_mapping_proxy(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> None:
    trusted_key = TrustedIntegrityKey(
        "integrity.control-principal",
        decision_signer.public_key_bytes,
        INTEGRITY_DECISION_ROLE,
    )

    class HostileKeyMapping(Mapping[str, TrustedIntegrityKey]):
        def __init__(self) -> None:
            self.reads = 0

        def __getitem__(self, key: str) -> TrustedIntegrityKey:
            if key != trusted_key.key_id:
                raise KeyError(key)
            return trusted_key

        def __iter__(self):
            for _index in range(integrity_contract.MAX_INTEGRITY_KEYS + 2):
                self.reads += 1
                yield trusted_key.key_id

        def __len__(self) -> int:
            return integrity_contract.MAX_INTEGRITY_KEYS + 2

    hostile_keys = HostileKeyMapping()
    trust_store = _trust_store(decision_signer, checkpoint_signer)
    object.__setattr__(
        trust_store,
        "keys",
        MappingProxyType(hostile_keys),
    )
    decision = _decision()

    with pytest.raises(IntegrityError) as caught:
        authenticate_integrity_decision(
            decision_signer.sign_decision(decision),
            trust_store,
            **_decision_auth_kwargs(decision),
        )
    assert caught.value.reason_code == "invalid_trust_store"
    assert hostile_keys.reads == 2
    assert hostile_keys.reads <= integrity_contract.MAX_INTEGRITY_KEYS + 1


def test_consequential_validators_reauthenticate_directly_constructed_results(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> None:
    trust_store = _trust_store(decision_signer, checkpoint_signer)
    decision = _decision()
    authenticated_decision = _authenticate(
        decision,
        decision_signer,
        checkpoint_signer,
    )
    zero_signature = base64.b64encode(b"\x00" * 64).decode("ascii")
    forged_signed_decision = SignedIntegrityDecisionV1(
        decision.to_envelope().to_bytes(),
        decision_signer.key_id,
        zero_signature,
    )
    with pytest.raises(IntegrityError) as caught:
        AuthenticatedIntegrityDecisionV1(
            forged_signed_decision,
            decision,
            "integrity.control-principal",
            trust_store.snapshot_id,
        )
    assert caught.value.reason_code == "unauthenticated_result_construction"
    forged_decision = object.__new__(AuthenticatedIntegrityDecisionV1)
    object.__setattr__(
        forged_decision,
        "signed_decision",
        forged_signed_decision,
    )
    object.__setattr__(forged_decision, "decision", decision)
    object.__setattr__(
        forged_decision,
        "signer_principal_id",
        "integrity.control-principal",
    )
    object.__setattr__(
        forged_decision,
        "trust_snapshot_id",
        trust_store.snapshot_id,
    )
    with pytest.raises(IntegrityError) as caught:
        validate_revocation_advance(
            None,
            forged_decision,
            previous_global_decision_trust_store=None,
            previous_global_checkpoint=None,
            previous_global_checkpoint_trust_store=None,
            current_trust_store=trust_store,
            external_floors=_revocation_floors(decision),
            validation_policy=_validation_policy(),
        )
    assert caught.value.reason_code == "invalid_authenticated_decision"

    checkpoint = _checkpoint(
        decision,
        authenticated_decision=authenticated_decision,
    )
    forged_signed_checkpoint = SignedHeadCheckpointV1(
        checkpoint.to_envelope().to_bytes(),
        checkpoint_signer.key_id,
        zero_signature,
    )
    with pytest.raises(IntegrityError) as caught:
        AuthenticatedHeadCheckpointV1(
            forged_signed_checkpoint,
            checkpoint,
            "integrity.anchor-principal",
            trust_store.snapshot_id,
        )
    assert caught.value.reason_code == "unauthenticated_result_construction"
    forged_checkpoint = object.__new__(AuthenticatedHeadCheckpointV1)
    object.__setattr__(
        forged_checkpoint,
        "signed_checkpoint",
        forged_signed_checkpoint,
    )
    object.__setattr__(forged_checkpoint, "checkpoint", checkpoint)
    object.__setattr__(
        forged_checkpoint,
        "signer_principal_id",
        "integrity.anchor-principal",
    )
    object.__setattr__(
        forged_checkpoint,
        "trust_snapshot_id",
        trust_store.snapshot_id,
    )
    with pytest.raises(IntegrityError) as caught:
        validate_checkpoint_binding(
            forged_checkpoint,
            authenticated_decision,
            event=_proposed_event(decision),
            **_binding_context(decision_signer, checkpoint_signer),
        )
    assert caught.value.reason_code == "invalid_authenticated_checkpoint"
    with pytest.raises(IntegrityError) as caught:
        validate_checkpoint_advance(
            forged_checkpoint,
            external_floor=_genesis_head_floor(decision),
            **_advance_context(
                decision_signer,
                checkpoint_signer,
                current_decision=authenticated_decision,
                previous_global=None,
                previous_mission=None,
            ),
        )
    assert caught.value.reason_code == "invalid_authenticated_checkpoint"


def test_stateful_authenticated_subclasses_cannot_cross_composition_boundaries(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> None:
    trust_store = _trust_store(decision_signer, checkpoint_signer)
    decision = _decision()
    authenticated_decision = _authenticate(
        decision,
        decision_signer,
        checkpoint_signer,
    )
    substituted_decision = _decision(request_nonce="f" * 64)
    decision_reads: list[IntegrityDecisionV1] = []

    class StatefulDecisionResult(AuthenticatedIntegrityDecisionV1):
        @property
        def _authentication_seal(self) -> object:
            return integrity_contract._AUTHENTICATED_RESULT_SEAL

        @property
        def signed_decision(self) -> SignedIntegrityDecisionV1:
            return authenticated_decision.signed_decision

        @property
        def decision(self) -> IntegrityDecisionV1:
            result = decision if not decision_reads else substituted_decision
            decision_reads.append(result)
            return result

        @property
        def signer_principal_id(self) -> str:
            return authenticated_decision.signer_principal_id

        @property
        def trust_snapshot_id(self) -> str:
            return authenticated_decision.trust_snapshot_id

    stateful_decision = object.__new__(StatefulDecisionResult)
    with pytest.raises(IntegrityError) as caught:
        validate_revocation_advance(
            None,
            stateful_decision,
            previous_global_decision_trust_store=None,
            previous_global_checkpoint=None,
            previous_global_checkpoint_trust_store=None,
            current_trust_store=trust_store,
            external_floors=_revocation_floors(decision),
            validation_policy=_validation_policy(),
        )
    assert caught.value.reason_code == "invalid_integrity_decision"
    assert decision_reads == []

    checkpoint = _checkpoint(
        decision,
        authenticated_decision=authenticated_decision,
    )
    authenticated_checkpoint = _authenticate_checkpoint(
        checkpoint,
        authenticated_decision,
        decision_signer,
        checkpoint_signer,
    )
    substituted_checkpoint = _checkpoint(
        decision,
        authenticated_decision=authenticated_decision,
        anchor_evidence=(
            _reference(
                HEAD_ANCHOR_RECEIPT_EVIDENCE_KIND,
                "anchor.log-a",
                "stateful-replacement-a",
            ),
            _reference(
                HEAD_ANCHOR_RECEIPT_EVIDENCE_KIND,
                "anchor.log-b",
                "stateful-replacement-b",
            ),
        ),
    )
    checkpoint_reads: list[HeadCheckpointV1] = []

    class StatefulCheckpointResult(AuthenticatedHeadCheckpointV1):
        @property
        def _authentication_seal(self) -> object:
            return integrity_contract._AUTHENTICATED_RESULT_SEAL

        @property
        def signed_checkpoint(self) -> SignedHeadCheckpointV1:
            return authenticated_checkpoint.signed_checkpoint

        @property
        def checkpoint(self) -> HeadCheckpointV1:
            result = checkpoint if not checkpoint_reads else substituted_checkpoint
            checkpoint_reads.append(result)
            return result

        @property
        def signer_principal_id(self) -> str:
            return authenticated_checkpoint.signer_principal_id

        @property
        def trust_snapshot_id(self) -> str:
            return authenticated_checkpoint.trust_snapshot_id

    stateful_checkpoint = object.__new__(StatefulCheckpointResult)
    with pytest.raises(IntegrityError) as caught:
        validate_checkpoint_binding(
            stateful_checkpoint,
            authenticated_decision,
            event=_proposed_event(decision),
            **_binding_context(decision_signer, checkpoint_signer),
        )
    assert caught.value.reason_code == "invalid_checkpoint_binding"
    assert checkpoint_reads == []

    refreshed_decision = integrity_contract._reauthenticate_decision_result(
        authenticated_decision,
        trust_store,
    )
    refreshed_checkpoint = integrity_contract._reauthenticate_checkpoint_result(
        authenticated_checkpoint,
        trust_store,
    )
    assert refreshed_decision is not authenticated_decision
    assert refreshed_decision.decision == decision
    assert refreshed_checkpoint is not authenticated_checkpoint
    assert refreshed_checkpoint.checkpoint == checkpoint


def test_signed_malformed_evidence_types_fail_with_contract_errors(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> None:
    trust_store = _trust_store(decision_signer, checkpoint_signer)
    decision = _decision()
    decision_body = thaw_json(decision.to_envelope().body)
    assert type(decision_body) is dict
    decision_body["time_evidence"][0]["evidence_kind"] = ["trusted_time"]
    malformed_decision = EnvelopeV1.create(
        "integrity_decision",
        decision_body,
    )
    malformed_decision_bytes = malformed_decision.to_bytes()
    signed_malformed_decision = SignedIntegrityDecisionV1(
        malformed_decision_bytes,
        decision_signer.key_id,
        base64.b64encode(
            decision_signer.private_key.sign(integrity_contract._DECISION_SIGNATURE_DOMAIN + malformed_decision_bytes)
        ).decode("ascii"),
    )
    with pytest.raises(IntegrityError) as caught:
        authenticate_integrity_decision(
            signed_malformed_decision,
            trust_store,
            **_decision_auth_kwargs(decision),
        )
    assert caught.value.reason_code == "invalid_integrity_decision"

    authenticated_decision = _authenticate(
        decision,
        decision_signer,
        checkpoint_signer,
    )
    checkpoint = _checkpoint(
        decision,
        authenticated_decision=authenticated_decision,
    )
    checkpoint_body = thaw_json(checkpoint.to_envelope().body)
    assert type(checkpoint_body) is dict
    checkpoint_body["anchor_evidence"][0]["evidence_kind"] = ["head_anchor_receipt"]
    malformed_checkpoint = EnvelopeV1.create(
        "head_checkpoint",
        checkpoint_body,
    )
    malformed_checkpoint_bytes = malformed_checkpoint.to_bytes()
    signed_malformed_checkpoint = SignedHeadCheckpointV1(
        malformed_checkpoint_bytes,
        checkpoint_signer.key_id,
        base64.b64encode(
            checkpoint_signer.private_key.sign(
                integrity_contract._CHECKPOINT_SIGNATURE_DOMAIN + malformed_checkpoint_bytes
            )
        ).decode("ascii"),
    )
    with pytest.raises(IntegrityError) as caught:
        authenticate_head_checkpoint(
            signed_malformed_checkpoint,
            trust_store,
            **_checkpoint_auth_kwargs(checkpoint),
        )
    assert caught.value.reason_code == "invalid_head_checkpoint"


def test_revocation_floors_reject_cross_scope_policy_and_unbounded_sets(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> None:
    first_scope = _decision()
    other_scope = _decision(
        service_instance_id="Etzio.other-instance",
        environment_id="other.control-plane",
    )
    authenticated_other = _authenticate(
        other_scope,
        decision_signer,
        checkpoint_signer,
    )
    context = _revocation_context(
        decision_signer,
        checkpoint_signer,
        previous_global_decision=None,
        previous_global_checkpoint=None,
    )
    with pytest.raises(IntegrityError) as caught:
        validate_revocation_advance(
            None,
            authenticated_other,
            external_floors=_revocation_floors(first_scope),
            **context,
        )
    assert caught.value.reason_code == "external_revocation_floor_scope_mismatch"

    authenticated_first = _authenticate(
        first_scope,
        decision_signer,
        checkpoint_signer,
    )
    wrong_policy_floors = tuple(
        replace(floor, decision_policy_id=_digest("other-policy")) for floor in _revocation_floors(first_scope)
    )
    with pytest.raises(IntegrityError) as caught:
        validate_revocation_advance(
            None,
            authenticated_first,
            external_floors=wrong_policy_floors,
            **context,
        )
    assert caught.value.reason_code == "external_revocation_floor_scope_mismatch"

    oversized = _revocation_floors(first_scope) * 9
    with pytest.raises(IntegrityError) as caught:
        validate_revocation_advance(
            None,
            authenticated_first,
            external_floors=oversized,
            **context,
        )
    assert caught.value.reason_code == "missing_external_revocation_floor"


def test_checkpoint_and_event_lineages_cannot_splice_predecessors(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> None:
    first_decision = _decision()
    authenticated_first_decision = _authenticate(
        first_decision,
        decision_signer,
        checkpoint_signer,
    )
    first_checkpoint = _checkpoint(
        first_decision,
        authenticated_decision=authenticated_first_decision,
    )
    authenticated_first_checkpoint = _authenticate_checkpoint(
        first_checkpoint,
        authenticated_first_decision,
        decision_signer,
        checkpoint_signer,
    )

    spliced_decision = _decision(
        **_global_predecessor(authenticated_first_checkpoint),
        prior_event_seq=0,
        prior_event_digest=_digest("unrelated-prior-event"),
        request_nonce=hashlib.sha256(b"spliced-request").hexdigest(),
    )
    authenticated_spliced_decision = _authenticate(
        spliced_decision,
        decision_signer,
        checkpoint_signer,
    )
    spliced_checkpoint = _checkpoint(
        spliced_decision,
        authenticated_decision=authenticated_spliced_decision,
        instance_sequence=1,
        previous_global=authenticated_first_checkpoint,
        previous_mission=authenticated_first_checkpoint,
    )
    authenticated_spliced_checkpoint = _authenticate_checkpoint(
        spliced_checkpoint,
        authenticated_spliced_decision,
        decision_signer,
        checkpoint_signer,
    )
    with pytest.raises(IntegrityError) as caught:
        validate_checkpoint_binding(
            authenticated_spliced_checkpoint,
            authenticated_spliced_decision,
            event=_proposed_event(spliced_decision),
            **_binding_context(
                decision_signer,
                checkpoint_signer,
                previous_mission=authenticated_first_checkpoint,
            ),
        )
    assert caught.value.reason_code == "checkpoint_mission_branch"

    with pytest.raises(IntegrityError) as caught:
        validate_checkpoint_advance(
            authenticated_spliced_checkpoint,
            external_floor=_head_floor(authenticated_first_checkpoint),
            **_advance_context(
                decision_signer,
                checkpoint_signer,
                current_decision=authenticated_spliced_decision,
                previous_global=authenticated_first_checkpoint,
                previous_mission=authenticated_first_checkpoint,
            ),
        )
    assert caught.value.reason_code == "checkpoint_mission_branch"

    with pytest.raises(IntegrityError) as caught:
        _decision(
            prior_event_seq=0,
            prior_event_digest=GENESIS_DIGEST,
        )
    assert caught.value.reason_code == "invalid_genesis_binding"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("authority_id", _digest("rebound-authority")),
        ("target_id", _digest("rebound-target")),
    ],
)
def test_mission_checkpoint_lineage_cannot_rebind_authority_or_target(
    field: str,
    value: str,
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> None:
    first_decision = _decision()
    authenticated_first_decision = _authenticate(
        first_decision,
        decision_signer,
        checkpoint_signer,
    )
    first_checkpoint = _checkpoint(
        first_decision,
        authenticated_decision=authenticated_first_decision,
    )
    authenticated_first_checkpoint = _authenticate_checkpoint(
        first_checkpoint,
        authenticated_first_decision,
        decision_signer,
        checkpoint_signer,
    )
    rebound_decision = _decision(
        **_global_predecessor(authenticated_first_checkpoint),
        prior_event_seq=first_checkpoint.event_seq,
        prior_event_digest=first_checkpoint.event_digest,
        request_nonce=hashlib.sha256(f"rebound-{field}".encode("ascii")).hexdigest(),
        **{field: value},
    )
    authenticated_rebound_decision = _authenticate(
        rebound_decision,
        decision_signer,
        checkpoint_signer,
    )
    rebound_checkpoint = _checkpoint(
        rebound_decision,
        authenticated_decision=authenticated_rebound_decision,
        instance_sequence=1,
        previous_global=authenticated_first_checkpoint,
        previous_mission=authenticated_first_checkpoint,
    )
    authenticated_rebound_checkpoint = _authenticate_checkpoint(
        rebound_checkpoint,
        authenticated_rebound_decision,
        decision_signer,
        checkpoint_signer,
    )

    with pytest.raises(IntegrityError) as caught:
        validate_checkpoint_binding(
            authenticated_rebound_checkpoint,
            authenticated_rebound_decision,
            event=_proposed_event(rebound_decision),
            **_binding_context(
                decision_signer,
                checkpoint_signer,
                previous_mission=authenticated_first_checkpoint,
            ),
        )
    assert caught.value.reason_code == "checkpoint_mission_branch"

    with pytest.raises(IntegrityError) as caught:
        validate_checkpoint_advance(
            authenticated_rebound_checkpoint,
            external_floor=_head_floor(authenticated_first_checkpoint),
            **_advance_context(
                decision_signer,
                checkpoint_signer,
                current_decision=authenticated_rebound_decision,
                previous_global=authenticated_first_checkpoint,
                previous_mission=authenticated_first_checkpoint,
            ),
        )
    assert caught.value.reason_code == "checkpoint_mission_branch"


def test_attestation_provenance_prevents_trusted_signature_substitution(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> None:
    alternate_decision_signer = IntegritySigner.generate(INTEGRITY_DECISION_ROLE)
    trust_store = IntegrityTrustStore.from_keys(
        (
            TrustedIntegrityKey(
                "integrity.primary-decision",
                decision_signer.public_key_bytes,
                INTEGRITY_DECISION_ROLE,
            ),
            TrustedIntegrityKey(
                "integrity.alternate-decision",
                alternate_decision_signer.public_key_bytes,
                INTEGRITY_DECISION_ROLE,
            ),
            TrustedIntegrityKey(
                "integrity.checkpoint",
                checkpoint_signer.public_key_bytes,
                HEAD_CHECKPOINT_ROLE,
            ),
        )
    )
    decision = _decision()
    primary = authenticate_integrity_decision(
        decision_signer.sign_decision(decision),
        trust_store,
        **_decision_auth_kwargs(decision),
    )
    alternate = authenticate_integrity_decision(
        alternate_decision_signer.sign_decision(decision),
        trust_store,
        **_decision_auth_kwargs(decision),
    )
    assert primary.decision.decision_id == alternate.decision.decision_id
    assert signed_integrity_decision_attestation_id(
        primary.signed_decision
    ) != signed_integrity_decision_attestation_id(alternate.signed_decision)
    checkpoint = _checkpoint(
        decision,
        authenticated_decision=primary,
    )
    authenticated_checkpoint = authenticate_head_checkpoint(
        checkpoint_signer.sign_checkpoint(checkpoint),
        trust_store,
        **_checkpoint_auth_kwargs(
            checkpoint,
            forbidden_key_ids=(primary.signed_decision.key_id,),
            forbidden_principal_ids=(primary.signer_principal_id,),
        ),
    )
    with pytest.raises(IntegrityError) as caught:
        validate_checkpoint_binding(
            authenticated_checkpoint,
            alternate,
            event=_proposed_event(decision),
            checkpoint_trust_store=trust_store,
            decision_trust_store=trust_store,
            previous_mission=None,
            previous_mission_trust_store=None,
            validation_policy=_validation_policy(),
        )
    assert caught.value.reason_code == "checkpoint_binding_mismatch"

    advanced = _decision(
        **_global_predecessor(authenticated_checkpoint),
        revocation_views=_revocation_views(
            authority_version=8,
            authority_snapshot=_digest("authority-snapshot-8"),
            authority_evidence=_digest("authority-evidence-8"),
        ),
        request_nonce=hashlib.sha256(b"advanced-request").hexdigest(),
    )
    authenticated_advanced = authenticate_integrity_decision(
        decision_signer.sign_decision(advanced),
        trust_store,
        **_decision_auth_kwargs(advanced),
    )
    with pytest.raises(IntegrityError) as caught:
        validate_revocation_advance(
            alternate,
            authenticated_advanced,
            previous_global_decision_trust_store=trust_store,
            previous_global_checkpoint=authenticated_checkpoint,
            previous_global_checkpoint_trust_store=trust_store,
            current_trust_store=trust_store,
            external_floors=_revocation_floors(decision),
            validation_policy=_validation_policy(),
        )
    assert caught.value.reason_code == "previous_global_decision_mismatch"


def test_external_head_floor_binds_exact_checkpoint_attestation_provenance(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> None:
    alternate_checkpoint_signer = IntegritySigner.generate(HEAD_CHECKPOINT_ROLE)
    trust_store = IntegrityTrustStore.from_keys(
        (
            TrustedIntegrityKey(
                "integrity.decision",
                decision_signer.public_key_bytes,
                INTEGRITY_DECISION_ROLE,
            ),
            TrustedIntegrityKey(
                "integrity.primary-checkpoint",
                checkpoint_signer.public_key_bytes,
                HEAD_CHECKPOINT_ROLE,
            ),
            TrustedIntegrityKey(
                "integrity.alternate-checkpoint",
                alternate_checkpoint_signer.public_key_bytes,
                HEAD_CHECKPOINT_ROLE,
            ),
        )
    )
    decision = _decision()
    authenticated_decision = authenticate_integrity_decision(
        decision_signer.sign_decision(decision),
        trust_store,
        **_decision_auth_kwargs(decision),
    )
    checkpoint = _checkpoint(
        decision,
        authenticated_decision=authenticated_decision,
    )
    authentication_kwargs = _checkpoint_auth_kwargs(
        checkpoint,
        forbidden_key_ids=(authenticated_decision.signed_decision.key_id,),
        forbidden_principal_ids=(authenticated_decision.signer_principal_id,),
    )
    primary = authenticate_head_checkpoint(
        checkpoint_signer.sign_checkpoint(checkpoint),
        trust_store,
        **authentication_kwargs,
    )
    alternate = authenticate_head_checkpoint(
        alternate_checkpoint_signer.sign_checkpoint(checkpoint),
        trust_store,
        **authentication_kwargs,
    )
    assert primary.checkpoint.checkpoint_id == alternate.checkpoint.checkpoint_id
    assert signed_head_checkpoint_attestation_id(primary.signed_checkpoint) != signed_head_checkpoint_attestation_id(
        alternate.signed_checkpoint
    )
    with pytest.raises(IntegrityError) as caught:
        validate_checkpoint_advance(
            alternate,
            current_trust_store=trust_store,
            current_decision=authenticated_decision,
            current_decision_trust_store=trust_store,
            previous_global=None,
            previous_global_trust_store=None,
            previous_mission=None,
            previous_mission_trust_store=None,
            external_floor=_head_floor(primary),
            validation_policy=_validation_policy(),
        )
    assert caught.value.reason_code == "external_head_floor_equivocation"


def test_historical_checkpoint_provenance_cannot_be_resigned_or_mixed(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> None:
    alternate_checkpoint_signer = IntegritySigner.generate(HEAD_CHECKPOINT_ROLE)
    trust_store = IntegrityTrustStore.from_keys(
        (
            TrustedIntegrityKey(
                "integrity.decision",
                decision_signer.public_key_bytes,
                INTEGRITY_DECISION_ROLE,
            ),
            TrustedIntegrityKey(
                "integrity.primary-checkpoint",
                checkpoint_signer.public_key_bytes,
                HEAD_CHECKPOINT_ROLE,
            ),
            TrustedIntegrityKey(
                "integrity.alternate-checkpoint",
                alternate_checkpoint_signer.public_key_bytes,
                HEAD_CHECKPOINT_ROLE,
            ),
        )
    )
    first_decision = _decision()
    authenticated_first_decision = authenticate_integrity_decision(
        decision_signer.sign_decision(first_decision),
        trust_store,
        **_decision_auth_kwargs(first_decision),
    )
    first_checkpoint = _checkpoint(
        first_decision,
        authenticated_decision=authenticated_first_decision,
    )
    checkpoint_auth_kwargs = _checkpoint_auth_kwargs(
        first_checkpoint,
        forbidden_key_ids=(authenticated_first_decision.signed_decision.key_id,),
        forbidden_principal_ids=(authenticated_first_decision.signer_principal_id,),
    )
    primary_first = authenticate_head_checkpoint(
        checkpoint_signer.sign_checkpoint(first_checkpoint),
        trust_store,
        **checkpoint_auth_kwargs,
    )
    alternate_first = authenticate_head_checkpoint(
        alternate_checkpoint_signer.sign_checkpoint(first_checkpoint),
        trust_store,
        **checkpoint_auth_kwargs,
    )
    assert primary_first.checkpoint.checkpoint_id == alternate_first.checkpoint.checkpoint_id

    second_decision = _decision(
        **_global_predecessor(primary_first),
        prior_event_seq=first_checkpoint.event_seq,
        prior_event_digest=first_checkpoint.event_digest,
        request_nonce=hashlib.sha256(b"provenance-successor").hexdigest(),
        revocation_views=_revocation_views(
            authority_version=8,
            authority_snapshot=_digest("authority-snapshot-8"),
            authority_evidence=_digest("authority-evidence-8"),
        ),
    )
    authenticated_second_decision = authenticate_integrity_decision(
        decision_signer.sign_decision(second_decision),
        trust_store,
        **_decision_auth_kwargs(second_decision),
    )

    with pytest.raises(IntegrityError) as caught:
        _checkpoint(
            second_decision,
            authenticated_decision=authenticated_second_decision,
            instance_sequence=1,
            previous_global=primary_first,
            previous_mission=alternate_first,
        )
    assert caught.value.reason_code == "checkpoint_predecessor_provenance_mismatch"

    with pytest.raises(IntegrityError) as caught:
        HeadCheckpointFloorV1(
            service_instance_id=first_checkpoint.service_instance_id,
            environment_id=first_checkpoint.environment_id,
            instance_sequence=first_checkpoint.instance_sequence,
            checkpoint_id=first_checkpoint.checkpoint_id,
            checkpoint_attestation_id=(signed_head_checkpoint_attestation_id(primary_first.signed_checkpoint)),
            checkpoint_principal_id=primary_first.signer_principal_id,
            checkpoint_trust_snapshot_id=primary_first.trust_snapshot_id,
            mission_id=first_checkpoint.mission_id,
            mission_event_seq=first_checkpoint.event_seq,
            mission_checkpoint_id=first_checkpoint.checkpoint_id,
            mission_checkpoint_attestation_id=(
                signed_head_checkpoint_attestation_id(alternate_first.signed_checkpoint)
            ),
            mission_checkpoint_principal_id=(alternate_first.signer_principal_id),
            mission_checkpoint_trust_snapshot_id=(alternate_first.trust_snapshot_id),
            evidence=_floor_evidence(),
        )
    assert caught.value.reason_code == "external_floor_mismatch"

    second_checkpoint = _checkpoint(
        second_decision,
        authenticated_decision=authenticated_second_decision,
        instance_sequence=1,
        previous_global=primary_first,
        previous_mission=primary_first,
    )
    authenticated_second_checkpoint = authenticate_head_checkpoint(
        checkpoint_signer.sign_checkpoint(second_checkpoint),
        trust_store,
        **_checkpoint_auth_kwargs(
            second_checkpoint,
            forbidden_key_ids=(authenticated_second_decision.signed_decision.key_id,),
            forbidden_principal_ids=(authenticated_second_decision.signer_principal_id,),
        ),
    )

    with pytest.raises(IntegrityError) as caught:
        validate_revocation_advance(
            authenticated_first_decision,
            authenticated_second_decision,
            previous_global_decision_trust_store=trust_store,
            previous_global_checkpoint=alternate_first,
            previous_global_checkpoint_trust_store=trust_store,
            current_trust_store=trust_store,
            external_floors=_revocation_floors(first_decision),
            validation_policy=_validation_policy(),
        )
    assert caught.value.reason_code == "current_global_predecessor_mismatch"

    with pytest.raises(IntegrityError) as caught:
        validate_checkpoint_binding(
            authenticated_second_checkpoint,
            authenticated_second_decision,
            event=_proposed_event(second_decision),
            checkpoint_trust_store=trust_store,
            decision_trust_store=trust_store,
            previous_mission=alternate_first,
            previous_mission_trust_store=trust_store,
            validation_policy=_validation_policy(),
        )
    assert caught.value.reason_code == "checkpoint_mission_branch"

    with pytest.raises(IntegrityError) as caught:
        validate_checkpoint_advance(
            authenticated_second_checkpoint,
            current_trust_store=trust_store,
            current_decision=authenticated_second_decision,
            current_decision_trust_store=trust_store,
            previous_global=alternate_first,
            previous_global_trust_store=trust_store,
            previous_mission=alternate_first,
            previous_mission_trust_store=trust_store,
            external_floor=_head_floor(authenticated_second_checkpoint),
            validation_policy=_validation_policy(),
        )
    assert caught.value.reason_code == "checkpoint_global_branch"


def test_constructor_and_wire_refusals_have_exact_known_bads() -> None:
    with pytest.raises(IntegrityError) as caught:
        EvidenceReferenceV1.from_body({})
    assert caught.value.reason_code == "invalid_evidence_reference"

    with pytest.raises(IntegrityError) as caught:
        EvidenceReferenceV1(
            "unsupported_evidence",
            "evidence.source",
            _digest("evidence"),
        )
    assert caught.value.reason_code == "invalid_evidence_kind"

    with pytest.raises(IntegrityError) as caught:
        RevocationViewV1.from_body({})
    assert caught.value.reason_code == "invalid_revocation_view"

    with pytest.raises(IntegrityError) as caught:
        RevocationViewV1(
            namespace="authority",
            root_version=1,
            version=1,
            snapshot_id=_digest("revocation"),
            evidence=_reference(
                REVOCATION_METADATA_EVIDENCE_KIND,
                "revocation.authority",
                "revocation",
            ),
            valid_from=NOW,
            valid_until=NOW,
        )
    assert caught.value.reason_code == "invalid_revocation_window"

    with pytest.raises(IntegrityError) as caught:
        RevocationViewV1(
            namespace="authority",
            root_version=1,
            version=1,
            snapshot_id=_digest("revocation"),
            evidence=_reference(
                TRUSTED_TIME_EVIDENCE_KIND,
                "time.authority",
                "wrong-kind",
            ),
            valid_from=NOW,
            valid_until=NOW + 1,
        )
    assert caught.value.reason_code == "invalid_revocation_evidence"

    decision_cases = (
        (
            {
                "prior_global_checkpoint_sequence": -2,
                "proposed_event_digest": _digest("proposed"),
            },
            "invalid_prior_global_checkpoint_sequence",
        ),
        (
            {
                "prior_global_checkpoint_sequence": (integrity_contract.MAX_EPOCH_SECOND),
                "prior_global_checkpoint_id": _digest("terminal-global"),
                "prior_global_checkpoint_attestation_id": _digest("terminal-global-attestation"),
                "prior_global_checkpoint_principal_id": ("terminal.global-principal"),
                "prior_global_checkpoint_trust_snapshot_id": _digest("terminal-global-trust"),
                "proposed_event_digest": _digest("proposed"),
                "time_lower_bound": NOW,
                "time_upper_bound": NOW + 1,
            },
            "invalid_prior_global_checkpoint_sequence",
        ),
        (
            {"prior_global_checkpoint_id": _digest("not-global-genesis")},
            "invalid_global_checkpoint_binding",
        ),
        (
            {"prior_global_checkpoint_attestation_id": _digest("impossible-genesis-attestation")},
            "invalid_checkpoint_provenance",
        ),
        (
            {
                "prior_event_seq": -2,
                "proposed_event_digest": _digest("proposed"),
            },
            "invalid_prior_event_seq",
        ),
        (
            {
                "prior_event_seq": integrity_contract.MAX_EPOCH_SECOND,
                "prior_event_digest": _digest("terminal-event"),
                "proposed_event_digest": _digest("proposed"),
            },
            "invalid_prior_event_seq",
        ),
        (
            {
                "event_kind": "NotCanonical",
                "proposed_event_digest": _digest("proposed"),
            },
            "invalid_event_kind",
        ),
        ({"request_nonce": "not-a-256-bit-nonce"}, "invalid_request_nonce"),
        ({"revocation_views": ()}, "invalid_revocation_views"),
        (
            {"time_lower_bound": NOW + 2, "time_upper_bound": NOW + 1},
            "invalid_time_interval",
        ),
    )
    for overrides, reason_code in decision_cases:
        with pytest.raises(IntegrityError) as caught:
            _decision(**overrides)
        assert caught.value.reason_code == reason_code

    checkpoint = _checkpoint(_decision())
    checkpoint_cases = (
        (
            lambda: replace(checkpoint, event_seq=1),
            "invalid_checkpoint_sequence",
        ),
        (
            lambda: replace(
                checkpoint,
                previous_mission_checkpoint_id=_digest("not-mission-genesis"),
            ),
            "invalid_mission_checkpoint_binding",
        ),
        (
            lambda: replace(
                checkpoint,
                anchor_statement_id=_digest("wrong-anchor-statement"),
            ),
            "anchor_statement_mismatch",
        ),
    )
    for operation, reason_code in checkpoint_cases:
        with pytest.raises(IntegrityError) as caught:
            operation()
        assert caught.value.reason_code == reason_code

    with pytest.raises(IntegrityError) as caught:
        signed_integrity_decision_attestation_id(object())  # type: ignore[arg-type]
    assert caught.value.reason_code == "invalid_signed_integrity_decision"

    with pytest.raises(IntegrityError) as caught:
        signed_head_checkpoint_attestation_id(object())  # type: ignore[arg-type]
    assert caught.value.reason_code == "invalid_signed_head_checkpoint"

    with pytest.raises(IntegrityError) as caught:
        integrity_contract._signed_attestation_id(
            "integrity_test",
            "not-bytes",  # type: ignore[arg-type]
        )
    assert caught.value.reason_code == "invalid_signed_integrity_wire"

    signer = IntegritySigner.generate(INTEGRITY_DECISION_ROLE)
    signed = signer.sign_decision(_decision())
    with pytest.raises(IntegrityError) as caught:
        SignedIntegrityDecisionV1(
            signed.envelope_bytes,
            "malformed-key-id",
            signed.signature_b64,
        )
    assert caught.value.reason_code == "malformed_key_id"

    oversized_wire = b"x" * (integrity_contract.MAX_INTEGRITY_ENVELOPE_BYTES + 1)
    with pytest.raises(IntegrityError) as caught:
        SignedIntegrityDecisionV1.from_bytes(oversized_wire)
    assert caught.value.reason_code == "integrity_envelope_too_large"
    with pytest.raises(IntegrityError) as caught:
        SignedIntegrityDecisionV1.from_bytes("x" * (integrity_contract.MAX_INTEGRITY_ENVELOPE_BYTES + 1))
    assert caught.value.reason_code == "integrity_envelope_too_large"

    assert {
        "signed_head_checkpoint_attestation_id",
        "signed_integrity_decision_attestation_id",
    } <= set(integrity_contract.__all__)

    with pytest.raises(IntegrityError) as caught:
        require_interval_within(
            _decision(),
            not_before=NOW + 2,
            expires_at=NOW + 2,
        )
    assert caught.value.reason_code == "invalid_validity_window"

    with pytest.raises(IntegrityError) as caught:
        integrity_contract._validate_decision_against_policy(
            _decision(),
            object(),  # type: ignore[arg-type]
        )
    assert caught.value.reason_code == "invalid_validation_policy"

    with pytest.raises(IntegrityError) as caught:
        validate_checkpoint_binding(
            object(),  # type: ignore[arg-type]
            object(),  # type: ignore[arg-type]
            event=object(),
            checkpoint_trust_store=object(),  # type: ignore[arg-type]
            decision_trust_store=object(),  # type: ignore[arg-type]
            previous_mission=None,
            previous_mission_trust_store=None,
            validation_policy=object(),  # type: ignore[arg-type]
        )
    assert caught.value.reason_code == "invalid_checkpoint_binding"


def test_revocation_composition_refusals_have_exact_known_bads(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> None:
    decision = _decision()
    authenticated = _authenticate(
        decision,
        decision_signer,
        checkpoint_signer,
    )
    context = _revocation_context(
        decision_signer,
        checkpoint_signer,
        previous_global_decision=None,
        previous_global_checkpoint=None,
    )
    floors = _revocation_floors(decision)

    with pytest.raises(IntegrityError) as caught:
        validate_revocation_advance(
            None,
            authenticated,
            external_floors=tuple(reversed(floors)),
            **context,
        )
    assert caught.value.reason_code == "invalid_external_revocation_floor"

    with pytest.raises(IntegrityError) as caught:
        validate_revocation_advance(
            None,
            authenticated,
            external_floors=floors[:1],
            **context,
        )
    assert caught.value.reason_code == "external_revocation_floor_set_mismatch"

    root_ahead = tuple(
        replace(floor, root_version=floor.root_version + 1) if floor.namespace == "authority" else floor
        for floor in floors
    )
    with pytest.raises(IntegrityError) as caught:
        validate_revocation_advance(
            None,
            authenticated,
            external_floors=root_ahead,
            **context,
        )
    assert caught.value.reason_code == "external_revocation_root_rollback"

    missing_predecessor = _decision(
        prior_global_checkpoint_sequence=0,
        prior_global_checkpoint_id=_digest("missing-global-checkpoint"),
        prior_global_checkpoint_attestation_id=_digest("missing-global-attestation"),
        prior_global_checkpoint_principal_id="missing.global-principal",
        prior_global_checkpoint_trust_snapshot_id=_digest("missing-global-trust"),
    )
    with pytest.raises(IntegrityError) as caught:
        validate_revocation_advance(
            None,
            _authenticate(
                missing_predecessor,
                decision_signer,
                checkpoint_signer,
            ),
            external_floors=_revocation_floors(missing_predecessor),
            **context,
        )
    assert caught.value.reason_code == "previous_global_checkpoint_missing"

    first_checkpoint = _checkpoint(
        decision,
        authenticated_decision=authenticated,
    )
    authenticated_first_checkpoint = _authenticate_checkpoint(
        first_checkpoint,
        authenticated,
        decision_signer,
        checkpoint_signer,
    )
    cross_scope = _decision(
        **_global_predecessor(authenticated_first_checkpoint),
        service_instance_id="Etzio.other-instance",
        prior_event_seq=first_checkpoint.event_seq,
        prior_event_digest=first_checkpoint.event_digest,
        request_nonce=hashlib.sha256(b"cross-scope").hexdigest(),
    )
    authenticated_cross_scope = _authenticate(
        cross_scope,
        decision_signer,
        checkpoint_signer,
    )
    with pytest.raises(IntegrityError) as caught:
        validate_revocation_advance(
            authenticated,
            authenticated_cross_scope,
            external_floors=_revocation_floors(cross_scope),
            **_revocation_context(
                decision_signer,
                checkpoint_signer,
                previous_global_decision=authenticated,
                previous_global_checkpoint=authenticated_first_checkpoint,
            ),
        )
    assert caught.value.reason_code == "integrity_scope_mismatch"


def test_external_head_floor_refusals_have_exact_known_bads(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> None:
    first_decision = _decision()
    authenticated_first_decision = _authenticate(
        first_decision,
        decision_signer,
        checkpoint_signer,
    )
    first_checkpoint = _checkpoint(
        first_decision,
        authenticated_decision=authenticated_first_decision,
    )
    authenticated_first_checkpoint = _authenticate_checkpoint(
        first_checkpoint,
        authenticated_first_decision,
        decision_signer,
        checkpoint_signer,
    )
    first_context = _advance_context(
        decision_signer,
        checkpoint_signer,
        current_decision=authenticated_first_decision,
        previous_global=None,
        previous_mission=None,
    )

    with pytest.raises(IntegrityError) as caught:
        validate_checkpoint_advance(
            authenticated_first_checkpoint,
            external_floor=None,  # type: ignore[arg-type]
            **first_context,
        )
    assert caught.value.reason_code == "missing_external_head_floor"

    wrong_scope_floor = replace(
        _head_floor(authenticated_first_checkpoint),
        service_instance_id="Etzio.other-instance",
    )
    with pytest.raises(IntegrityError) as caught:
        validate_checkpoint_advance(
            authenticated_first_checkpoint,
            external_floor=wrong_scope_floor,
            **first_context,
        )
    assert caught.value.reason_code == "external_head_floor_scope_mismatch"

    ahead_floor = HeadCheckpointFloorV1(
        service_instance_id=first_decision.service_instance_id,
        environment_id=first_decision.environment_id,
        instance_sequence=1,
        checkpoint_id=_digest("ahead-global-checkpoint"),
        checkpoint_attestation_id=_digest("ahead-global-attestation"),
        checkpoint_principal_id="ahead.global-principal",
        checkpoint_trust_snapshot_id=_digest("ahead-global-trust"),
        mission_id=first_decision.mission_id,
        mission_event_seq=1,
        mission_checkpoint_id=_digest("ahead-mission-checkpoint"),
        mission_checkpoint_attestation_id=_digest("ahead-mission-attestation"),
        mission_checkpoint_principal_id="ahead.mission-principal",
        mission_checkpoint_trust_snapshot_id=_digest("ahead-mission-trust"),
        evidence=_floor_evidence(),
    )
    with pytest.raises(IntegrityError) as caught:
        validate_checkpoint_advance(
            authenticated_first_checkpoint,
            external_floor=ahead_floor,
            **first_context,
        )
    assert caught.value.reason_code == "local_head_below_external_floor"

    partial_floor = HeadCheckpointFloorV1(
        service_instance_id=first_decision.service_instance_id,
        environment_id=first_decision.environment_id,
        instance_sequence=first_checkpoint.instance_sequence,
        checkpoint_id=first_checkpoint.checkpoint_id,
        checkpoint_attestation_id=signed_head_checkpoint_attestation_id(
            authenticated_first_checkpoint.signed_checkpoint
        ),
        checkpoint_principal_id=(authenticated_first_checkpoint.signer_principal_id),
        checkpoint_trust_snapshot_id=(authenticated_first_checkpoint.trust_snapshot_id),
        mission_id=first_decision.mission_id,
        mission_event_seq=-1,
        mission_checkpoint_id=mission_checkpoint_genesis_id(
            service_instance_id=first_decision.service_instance_id,
            environment_id=first_decision.environment_id,
            mission_id=first_decision.mission_id,
        ),
        mission_checkpoint_attestation_id=None,
        mission_checkpoint_principal_id=None,
        mission_checkpoint_trust_snapshot_id=None,
        evidence=_floor_evidence(),
    )
    with pytest.raises(IntegrityError) as caught:
        validate_checkpoint_advance(
            authenticated_first_checkpoint,
            external_floor=partial_floor,
            **first_context,
        )
    assert caught.value.reason_code == "external_head_floor_inconsistent"

    second_decision = _decision(
        **_global_predecessor(authenticated_first_checkpoint),
        prior_event_seq=first_checkpoint.event_seq,
        prior_event_digest=first_checkpoint.event_digest,
        request_nonce=hashlib.sha256(b"head-floor-successor").hexdigest(),
    )
    authenticated_second_decision = _authenticate(
        second_decision,
        decision_signer,
        checkpoint_signer,
    )
    second_checkpoint = _checkpoint(
        second_decision,
        authenticated_decision=authenticated_second_decision,
        instance_sequence=1,
        previous_global=authenticated_first_checkpoint,
        previous_mission=authenticated_first_checkpoint,
    )
    authenticated_second_checkpoint = _authenticate_checkpoint(
        second_checkpoint,
        authenticated_second_decision,
        decision_signer,
        checkpoint_signer,
    )
    with pytest.raises(IntegrityError) as caught:
        validate_checkpoint_advance(
            authenticated_second_checkpoint,
            external_floor=_genesis_head_floor(second_decision),
            **_advance_context(
                decision_signer,
                checkpoint_signer,
                current_decision=authenticated_second_decision,
                previous_global=authenticated_first_checkpoint,
                previous_mission=authenticated_first_checkpoint,
            ),
        )
    assert caught.value.reason_code == "external_head_floor_rollback"

    cross_scope_decision = _decision(
        **_global_predecessor(authenticated_first_checkpoint),
        service_instance_id="Etzio.other-instance",
        request_nonce=hashlib.sha256(b"checkpoint-cross-scope").hexdigest(),
    )
    authenticated_cross_scope_decision = _authenticate(
        cross_scope_decision,
        decision_signer,
        checkpoint_signer,
    )
    cross_scope_checkpoint = _checkpoint(
        cross_scope_decision,
        authenticated_decision=authenticated_cross_scope_decision,
        instance_sequence=1,
        previous_global=authenticated_first_checkpoint,
    )
    authenticated_cross_scope_checkpoint = _authenticate_checkpoint(
        cross_scope_checkpoint,
        authenticated_cross_scope_decision,
        decision_signer,
        checkpoint_signer,
    )
    with pytest.raises(IntegrityError) as caught:
        validate_checkpoint_advance(
            authenticated_cross_scope_checkpoint,
            external_floor=_genesis_head_floor(cross_scope_decision),
            **_advance_context(
                decision_signer,
                checkpoint_signer,
                current_decision=authenticated_cross_scope_decision,
                previous_global=authenticated_first_checkpoint,
                previous_mission=None,
            ),
        )
    assert caught.value.reason_code == "checkpoint_scope_mismatch"


def test_checkpoint_binding_rejects_an_exact_type_forged_event(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> None:
    decision = _decision()
    authenticated_decision = _authenticate(
        decision,
        decision_signer,
        checkpoint_signer,
    )
    checkpoint = _checkpoint(
        decision,
        authenticated_decision=authenticated_decision,
    )
    authenticated_checkpoint = _authenticate_checkpoint(
        checkpoint,
        authenticated_decision,
        decision_signer,
        checkpoint_signer,
    )
    event = _proposed_event(decision)
    forged_event = object.__new__(EventV1)
    for field in EventV1.__dataclass_fields__:
        object.__setattr__(forged_event, field, getattr(event, field))
    object.__setattr__(
        forged_event,
        "protocol_version",
        event.protocol_version + 1,
    )

    with pytest.raises(IntegrityError) as caught:
        validate_checkpoint_binding(
            authenticated_checkpoint,
            authenticated_decision,
            event=forged_event,
            **_binding_context(decision_signer, checkpoint_signer),
        )
    assert caught.value.reason_code == "invalid_checkpoint_binding"


def test_floor_snapshots_reconstruct_nested_evidence_without_aliases() -> None:
    decision = _decision()
    floor_evidence = _floor_evidence()
    revocation_floor = RevocationFloorV1(
        service_instance_id=decision.service_instance_id,
        environment_id=decision.environment_id,
        decision_policy_id=decision.decision_policy_id,
        namespace="authority",
        root_version=1,
        version=7,
        snapshot_id=_digest("authority-snapshot"),
        evidence=floor_evidence,
    )
    head_floor = HeadCheckpointFloorV1(
        service_instance_id=decision.service_instance_id,
        environment_id=decision.environment_id,
        instance_sequence=-1,
        checkpoint_id=head_checkpoint_genesis_id(
            service_instance_id=decision.service_instance_id,
            environment_id=decision.environment_id,
        ),
        checkpoint_attestation_id=None,
        checkpoint_principal_id=None,
        checkpoint_trust_snapshot_id=None,
        mission_id=decision.mission_id,
        mission_event_seq=-1,
        mission_checkpoint_id=mission_checkpoint_genesis_id(
            service_instance_id=decision.service_instance_id,
            environment_id=decision.environment_id,
            mission_id=decision.mission_id,
        ),
        mission_checkpoint_attestation_id=None,
        mission_checkpoint_principal_id=None,
        mission_checkpoint_trust_snapshot_id=None,
        evidence=floor_evidence,
    )

    revocation_snapshot = integrity_contract._snapshot_revocation_floor(revocation_floor)
    head_snapshot = integrity_contract._snapshot_head_checkpoint_floor(head_floor)
    assert revocation_snapshot is not revocation_floor
    assert head_snapshot is not head_floor
    assert revocation_snapshot.evidence[0] is not revocation_floor.evidence[0]
    assert head_snapshot.evidence[0] is not head_floor.evidence[0]
    assert revocation_floor.evidence[0] is not floor_evidence[0]
    assert head_floor.evidence[0] is not floor_evidence[0]

    object.__setattr__(
        floor_evidence[0],
        "evidence_id",
        _digest("mutated-caller-floor-evidence"),
    )
    object.__setattr__(
        revocation_floor.evidence[0],
        "evidence_id",
        _digest("mutated-revocation-floor-evidence"),
    )
    object.__setattr__(
        head_floor.evidence[0],
        "evidence_id",
        _digest("mutated-head-floor-evidence"),
    )

    assert revocation_snapshot.evidence[0].evidence_id == _digest("floor-a")
    assert head_snapshot.evidence[0].evidence_id == _digest("floor-a")


def test_nested_decision_and_checkpoint_inputs_do_not_alias_callers() -> None:
    time_evidence = _time_evidence()
    revocation_views = _revocation_views()
    decision = _decision(
        time_evidence=time_evidence,
        revocation_views=revocation_views,
    )
    checkpoint_time_evidence = _time_evidence()
    anchor_evidence = _anchor_evidence()
    checkpoint = _checkpoint(
        decision,
        time_evidence=checkpoint_time_evidence,
        anchor_evidence=anchor_evidence,
    )
    decision_wire = decision.to_envelope().to_bytes()
    checkpoint_wire = checkpoint.to_envelope().to_bytes()

    assert decision.time_evidence[0] is not time_evidence[0]
    assert decision.revocation_views[0] is not revocation_views[0]
    assert decision.revocation_views[0].evidence is not revocation_views[0].evidence
    assert checkpoint.time_evidence[0] is not checkpoint_time_evidence[0]
    assert checkpoint.anchor_evidence[0] is not anchor_evidence[0]

    object.__setattr__(
        time_evidence[0],
        "evidence_id",
        _digest("mutated-decision-time-evidence"),
    )
    object.__setattr__(
        revocation_views[0],
        "snapshot_id",
        _digest("mutated-revocation-view"),
    )
    object.__setattr__(
        checkpoint_time_evidence[0],
        "evidence_id",
        _digest("mutated-checkpoint-time-evidence"),
    )
    object.__setattr__(
        anchor_evidence[0],
        "evidence_id",
        _digest("mutated-anchor-evidence"),
    )

    assert decision.to_envelope().to_bytes() == decision_wire
    assert checkpoint.to_envelope().to_bytes() == checkpoint_wire


def test_stateful_and_unhashable_role_subclasses_fail_closed() -> None:
    class StatefulRole(str):
        def __eq__(self, other: object) -> bool:
            raise AssertionError("stateful role equality must not run")

        __hash__ = str.__hash__

    class UnhashableRole(str):
        __hash__ = None  # type: ignore[assignment]

    valid_signer = IntegritySigner.generate(INTEGRITY_DECISION_ROLE)
    for role in (
        StatefulRole(INTEGRITY_DECISION_ROLE),
        UnhashableRole(INTEGRITY_DECISION_ROLE),
    ):
        with pytest.raises(IntegrityError) as caught:
            IntegritySigner.generate(role)
        assert caught.value.reason_code == "invalid_integrity_role"

        with pytest.raises(IntegrityError) as caught:
            TrustedIntegrityKey(
                "integrity.subclass-role",
                valid_signer.public_key_bytes,
                role,
            )
        assert caught.value.reason_code == "invalid_integrity_role"

        mutated_signer = IntegritySigner.generate(INTEGRITY_DECISION_ROLE)
        object.__setattr__(mutated_signer, "role", role)
        with pytest.raises(IntegrityError) as caught:
            mutated_signer.sign_decision(_decision())
        assert caught.value.reason_code == "signer_role_mismatch"


def test_signer_outputs_remain_canonical_after_caller_alias_mutation(
    decision_signer: IntegritySigner,
    checkpoint_signer: IntegritySigner,
) -> None:
    decision_time_evidence = _time_evidence()
    revocation_views = _revocation_views()
    decision = _decision(
        time_evidence=decision_time_evidence,
        revocation_views=revocation_views,
    )
    decision_snapshot = IntegrityDecisionV1.from_envelope(decision.to_envelope())
    object.__setattr__(
        decision_time_evidence[0],
        "evidence_id",
        _digest("late-decision-evidence-mutation"),
    )
    object.__setattr__(
        revocation_views[0],
        "snapshot_id",
        _digest("late-revocation-view-mutation"),
    )
    signed_decision = decision_signer.sign_decision(decision)
    signed_decision_wire = signed_decision.to_bytes()
    assert IntegrityDecisionV1.from_envelope(EnvelopeV1.from_bytes(signed_decision.envelope_bytes)) == decision_snapshot

    checkpoint_time_evidence = _time_evidence()
    anchor_evidence = _anchor_evidence()
    checkpoint = _checkpoint(
        decision_snapshot,
        time_evidence=checkpoint_time_evidence,
        anchor_evidence=anchor_evidence,
    )
    checkpoint_snapshot = HeadCheckpointV1.from_envelope(checkpoint.to_envelope())
    object.__setattr__(
        checkpoint_time_evidence[0],
        "evidence_id",
        _digest("late-checkpoint-evidence-mutation"),
    )
    object.__setattr__(
        anchor_evidence[0],
        "evidence_id",
        _digest("late-anchor-evidence-mutation"),
    )
    signed_checkpoint = checkpoint_signer.sign_checkpoint(checkpoint)
    signed_checkpoint_wire = signed_checkpoint.to_bytes()
    assert (
        HeadCheckpointV1.from_envelope(EnvelopeV1.from_bytes(signed_checkpoint.envelope_bytes)) == checkpoint_snapshot
    )

    object.__setattr__(decision, "request_nonce", "f" * 64)
    object.__setattr__(
        checkpoint,
        "anchor_policy_id",
        _digest("mutated-after-signing"),
    )
    assert signed_decision.to_bytes() == signed_decision_wire
    assert signed_checkpoint.to_bytes() == signed_checkpoint_wire
    assert SignedIntegrityDecisionV1.from_bytes(signed_decision_wire) == signed_decision
    assert SignedHeadCheckpointV1.from_bytes(signed_checkpoint_wire) == signed_checkpoint


@pytest.mark.parametrize(
    ("field", "value"),
    [
        pytest.param(
            "service_instance_id",
            object(),
            id="unsupported-type",
        ),
        pytest.param(
            "service_instance_id",
            "\ud800",
            id="protocol-unicode",
        ),
        pytest.param(
            "prior_event_seq",
            integrity_contract.MAX_EPOCH_SECOND + 1,
            id="protocol-int64-overflow",
        ),
    ],
)
def test_decision_issue_normalizes_protocol_representation_failures(
    field: str,
    value: object,
) -> None:
    decision = _decision()
    values = {
        name: getattr(decision, name) for name in IntegrityDecisionV1.__dataclass_fields__ if name != "decision_id"
    }
    values[field] = value

    with pytest.raises(IntegrityError) as caught:
        IntegrityDecisionV1.issue(**values)  # type: ignore[arg-type]
    assert caught.value.reason_code == "invalid_integrity_decision"


def test_require_interval_within_rejects_a_reversed_forged_interval() -> None:
    decision = _decision()
    object.__setattr__(
        decision,
        "time_lower_bound",
        decision.time_upper_bound + 1,
    )

    with pytest.raises(IntegrityError) as caught:
        require_interval_within(
            decision,
            not_before=NOW - 1,
            expires_at=NOW + 10,
        )
    assert caught.value.reason_code == "invalid_time_interval"


@pytest.mark.parametrize(
    ("semantic_type", "object_kind", "reason_code"),
    [
        (
            IntegrityDecisionV1,
            "integrity_decision",
            "invalid_integrity_decision",
        ),
        (
            HeadCheckpointV1,
            "head_checkpoint",
            "invalid_head_checkpoint",
        ),
    ],
)
def test_from_envelope_normalizes_forged_body_failures(
    semantic_type: type[IntegrityDecisionV1] | type[HeadCheckpointV1],
    object_kind: str,
    reason_code: str,
) -> None:
    missing_slots = object.__new__(EnvelopeV1)
    with pytest.raises(IntegrityError) as caught:
        semantic_type.from_envelope(missing_slots)
    assert caught.value.reason_code == reason_code

    forged_envelope = object.__new__(EnvelopeV1)
    object.__setattr__(forged_envelope, "object_kind", object_kind)
    object.__setattr__(forged_envelope, "attestations", ())
    object.__setattr__(forged_envelope, "body", object())
    object.__setattr__(
        forged_envelope,
        "object_id",
        _digest("forged-envelope"),
    )

    with pytest.raises(IntegrityError) as caught:
        semantic_type.from_envelope(forged_envelope)
    assert caught.value.reason_code == reason_code


@pytest.mark.parametrize(
    ("signed_type", "reason_code"),
    [
        (SignedIntegrityDecisionV1, "malformed_signed_object"),
        (SignedHeadCheckpointV1, "malformed_signed_object"),
    ],
)
def test_signed_wrapper_inputs_normalize_malformed_transport(
    signed_type: type[SignedIntegrityDecisionV1] | type[SignedHeadCheckpointV1],
    reason_code: str,
) -> None:
    with pytest.raises(IntegrityError) as caught:
        signed_type.from_bytes(object())  # type: ignore[arg-type]
    assert caught.value.reason_code == reason_code

    missing_slots = object.__new__(signed_type)
    with pytest.raises(IntegrityError):
        missing_slots.to_envelope()

    forged_signed = object.__new__(signed_type)
    object.__setattr__(forged_signed, "envelope_bytes", object())
    object.__setattr__(
        forged_signed,
        "key_id",
        "ed25519:sha256:" + ("0" * 64),
    )
    object.__setattr__(
        forged_signed,
        "signature_b64",
        base64.b64encode(b"\x00" * 64).decode("ascii"),
    )
    with pytest.raises(IntegrityError) as caught:
        forged_signed.to_envelope()
    assert caught.value.reason_code == "invalid_envelope"


@pytest.mark.parametrize(
    ("object_kind", "field", "oversized_value", "reason_code"),
    [
        (
            "integrity_decision",
            "time_evidence",
            [_time_evidence()[0].to_body()] * (integrity_contract.MAX_EVIDENCE_REFS + 1),
            "invalid_integrity_decision",
        ),
        (
            "integrity_decision",
            "revocation_views",
            [_revocation_views()[0].to_body()] * (integrity_contract.MAX_REVOCATION_VIEWS + 1),
            "invalid_integrity_decision",
        ),
        (
            "head_checkpoint",
            "time_evidence",
            [_time_evidence()[0].to_body()] * (integrity_contract.MAX_EVIDENCE_REFS + 1),
            "invalid_head_checkpoint",
        ),
        (
            "head_checkpoint",
            "anchor_evidence",
            [_anchor_evidence()[0].to_body()] * (integrity_contract.MAX_EVIDENCE_REFS + 1),
            "invalid_head_checkpoint",
        ),
    ],
)
def test_semantic_wire_rejects_oversized_integrity_evidence_arrays(
    object_kind: str,
    field: str,
    oversized_value: list[dict[str, object]],
    reason_code: str,
) -> None:
    semantic = _decision() if object_kind == "integrity_decision" else _checkpoint(_decision())
    body = thaw_json(semantic.to_envelope().body)
    assert type(body) is dict
    body[field] = oversized_value
    envelope = EnvelopeV1.create(object_kind, body)

    parser = (
        IntegrityDecisionV1.from_envelope if object_kind == "integrity_decision" else HeadCheckpointV1.from_envelope
    )
    with pytest.raises(IntegrityError) as caught:
        parser(envelope)
    assert caught.value.reason_code == reason_code
