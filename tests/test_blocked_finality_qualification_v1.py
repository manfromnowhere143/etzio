"""Adversarial conformance for durable blocked finality and governed recovery."""

from __future__ import annotations

import hashlib
import socket
import time
from dataclasses import replace

import pytest

from etzio.integrity_v1 import (
    HEAD_CHECKPOINT_ROLE,
    INTEGRITY_DECISION_ROLE,
    INTEGRITY_ROLES_V1,
    IntegrityTrustStore,
    TrustedIntegrityKey,
)
from etzio.kernel.blocked_finality_v1 import (
    ANCHOR_STATEMENT_READY_PHASE_V1,
    BLOCKABLE_PHASES_V1,
    BLOCKED_FINALITY_CONTRACT_VERSION_V1,
    BLOCKED_FINALITY_RECOVERY_ROLE_V1,
    CHECKPOINT_CANDIDATE_RETAINED_PHASE_V1,
    FINALIZED_PHASE_V1,
    INSTANCE_SEALED_DISPOSITION_V1,
    LOCAL_PENDING_PHASE_V1,
    REPOSITORY_OWNED_BLOCKED_FINALITY_PROFILE_V1,
    RETRY_AUTHORIZED_DISPOSITION_V1,
    AuthenticatedRecoveryDecisionV1,
    BlockedFinalityError,
    BlockedFinalityObservationV1,
    BlockedFinalityQualificationReportV1,
    BlockedFinalityRecoveryProfileV1,
    BlockedFinalityResolutionV1,
    GovernedRecoveryDecisionV1,
    RecoveryDecisionSignerV1,
    SignedGovernedRecoveryDecisionV1,
    TrustedRecoveryKeyV1,
    append_blocked_observation_v1,
    authenticate_recovery_decision_v1,
    create_repository_owned_blocked_finality_fixture_v1,
    fixture_observation_v1,
    fixture_time_bundle_v1,
    qualify_repository_blocked_finality_v1,
    resolve_blocked_finality_v1,
)

SEED = b"etzio-blocked-finality-known-bad-corpus-v1"


def _digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def _fixture():
    return create_repository_owned_blocked_finality_fixture_v1(seed=SEED)


def _setup():
    fixture = _fixture()
    bundle = fixture_time_bundle_v1(fixture)
    observation = fixture_observation_v1(fixture, bundle)
    retained = append_blocked_observation_v1(retained=(), observation=observation)
    return fixture, bundle, observation, retained


def _signed(fixture, observation, bundle, disposition=RETRY_AUTHORIZED_DISPOSITION_V1):
    return fixture.recovery_signer.sign(
        GovernedRecoveryDecisionV1.issue(
            profile=fixture.profile,
            observation=observation,
            disposition=disposition,
            time_bundle=bundle,
            request_nonce=fixture.vector.request_nonce,
        )
    )


def _resolve(fixture, retained, signed, **overrides):
    kwargs = {
        "profile": fixture.profile,
        "retained": retained,
        "current_phase": fixture.blocked_phase,
        "current_phase_record_id": fixture.blocked_phase_record_id,
        "signed_decision": signed,
    }
    kwargs.update(overrides)
    return resolve_blocked_finality_v1(**kwargs)


# ---------------------------------------------------------------------------
# The blockable phase set
# ---------------------------------------------------------------------------


def test_finalized_is_not_a_blockable_phase() -> None:
    assert FINALIZED_PHASE_V1 not in BLOCKABLE_PHASES_V1
    assert BLOCKABLE_PHASES_V1 == (
        LOCAL_PENDING_PHASE_V1,
        ANCHOR_STATEMENT_READY_PHASE_V1,
        CHECKPOINT_CANDIDATE_RETAINED_PHASE_V1,
    )


def test_observation_naming_the_finalized_phase_is_refused() -> None:
    fixture, bundle, _, _ = _setup()
    with pytest.raises(BlockedFinalityError) as exc:
        fixture_observation_v1(fixture, bundle, unresolved_phase=FINALIZED_PHASE_V1)
    assert exc.value.reason_code == "blocked_phase_is_resolved"


def test_observation_naming_an_unknown_phase_is_refused() -> None:
    fixture, bundle, _, _ = _setup()
    with pytest.raises(BlockedFinalityError) as exc:
        fixture_observation_v1(fixture, bundle, unresolved_phase="half_finalized")
    assert exc.value.reason_code == "invalid_blocked_phase"


# ---------------------------------------------------------------------------
# Observation record
# ---------------------------------------------------------------------------


def test_observation_is_canonical_and_identity_bound() -> None:
    _, _, observation, _ = _setup()
    rebuilt = BlockedFinalityObservationV1.from_canonical_bytes(
        observation.to_canonical_bytes()
    )
    assert rebuilt.to_body() == observation.to_body()
    assert rebuilt.observation_id == observation.observation_id


@pytest.mark.parametrize(
    "field",
    [
        "attempt_ordinal",
        "blocked_operation",
        "blocked_reason_code",
        "unresolved_phase",
        "unresolved_phase_record_id",
        "pending_record_id",
        "event_digest",
    ],
)
def test_observation_identity_binds_every_consequential_field(field: str) -> None:
    _, _, observation, _ = _setup()
    substitutions = {
        "attempt_ordinal": 9,
        "blocked_operation": "publish_checkpoint",
        "blocked_reason_code": "modeled_anchor_equivocation",
        "unresolved_phase": LOCAL_PENDING_PHASE_V1,
        "unresolved_phase_record_id": _digest("other-phase-record"),
        "pending_record_id": _digest("other-pending"),
        "event_digest": _digest("other-event"),
    }
    with pytest.raises(BlockedFinalityError) as exc:
        replace(observation, **{field: substitutions[field]})
    assert exc.value.reason_code == "blocked_observation_id_mismatch"


def test_observation_rejects_an_unsupported_operation_or_reason() -> None:
    fixture, bundle, observation, _ = _setup()
    with pytest.raises(BlockedFinalityError) as exc:
        BlockedFinalityObservationV1.record(
            profile=fixture.profile,
            mission_id=observation.mission_id,
            authority_id=observation.authority_id,
            target_id=observation.target_id,
            event_digest=observation.event_digest,
            event_seq=observation.event_seq,
            instance_sequence=observation.instance_sequence,
            pending_record_id=observation.pending_record_id,
            unresolved_phase=observation.unresolved_phase,
            unresolved_phase_record_id=observation.unresolved_phase_record_id,
            blocked_operation="delete_everything",
            blocked_reason_code=observation.blocked_reason_code,
            attempt_ordinal=1,
            time_bundle=bundle,
        )
    assert exc.value.reason_code == "invalid_blocked_operation"

    with pytest.raises(BlockedFinalityError) as exc:
        BlockedFinalityObservationV1.record(
            profile=fixture.profile,
            mission_id=observation.mission_id,
            authority_id=observation.authority_id,
            target_id=observation.target_id,
            event_digest=observation.event_digest,
            event_seq=observation.event_seq,
            instance_sequence=observation.instance_sequence,
            pending_record_id=observation.pending_record_id,
            unresolved_phase=observation.unresolved_phase,
            unresolved_phase_record_id=observation.unresolved_phase_record_id,
            blocked_operation=observation.blocked_operation,
            blocked_reason_code="store_is_busy",
            attempt_ordinal=1,
            time_bundle=bundle,
        )
    assert exc.value.reason_code == "invalid_blocked_reason_code"


def test_observation_carries_no_resolution_or_status_field() -> None:
    _, _, observation, _ = _setup()
    body = observation.to_body()
    for forbidden in ("disposition", "resolved", "status", "barrier_released"):
        assert forbidden not in body


def test_observation_time_comes_only_from_a_qualified_hull() -> None:
    fixture, bundle, observation, _ = _setup()
    assert observation.time_bundle_id == bundle.bundle_id
    assert observation.time_lower_bound == bundle.time_lower_bound
    assert observation.time_upper_bound == bundle.time_upper_bound
    assert observation.time_evidence == bundle.evidence
    with pytest.raises(BlockedFinalityError) as exc:
        BlockedFinalityObservationV1.record(
            profile=fixture.profile,
            mission_id=observation.mission_id,
            authority_id=observation.authority_id,
            target_id=observation.target_id,
            event_digest=observation.event_digest,
            event_seq=observation.event_seq,
            instance_sequence=observation.instance_sequence,
            pending_record_id=observation.pending_record_id,
            unresolved_phase=observation.unresolved_phase,
            unresolved_phase_record_id=observation.unresolved_phase_record_id,
            blocked_operation=observation.blocked_operation,
            blocked_reason_code=observation.blocked_reason_code,
            attempt_ordinal=1,
            time_bundle=object(),
        )
    assert exc.value.reason_code == "invalid_blocked_time_bundle"


def test_observation_refuses_a_mission_head_above_the_global_head() -> None:
    fixture, bundle, observation, _ = _setup()
    with pytest.raises(BlockedFinalityError) as exc:
        BlockedFinalityObservationV1.record(
            profile=fixture.profile,
            mission_id=observation.mission_id,
            authority_id=observation.authority_id,
            target_id=observation.target_id,
            event_digest=observation.event_digest,
            event_seq=9,
            instance_sequence=3,
            pending_record_id=observation.pending_record_id,
            unresolved_phase=observation.unresolved_phase,
            unresolved_phase_record_id=observation.unresolved_phase_record_id,
            blocked_operation=observation.blocked_operation,
            blocked_reason_code=observation.blocked_reason_code,
            attempt_ordinal=1,
            time_bundle=bundle,
        )
    assert exc.value.reason_code == "invalid_blocked_observation"


@pytest.mark.parametrize("ordinal", [0, -1])
def test_observation_refuses_a_nonpositive_attempt_ordinal(ordinal: int) -> None:
    fixture, bundle, observation, _ = _setup()
    with pytest.raises(BlockedFinalityError) as exc:
        fixture_observation_v1(fixture, bundle, attempt_ordinal=ordinal)
    assert exc.value.reason_code == "invalid_blocked_attempt_ordinal"


# ---------------------------------------------------------------------------
# Append-only observation history
# ---------------------------------------------------------------------------


def test_exact_duplicate_observation_reconciles() -> None:
    fixture, bundle, _, retained = _setup()
    again = append_blocked_observation_v1(
        retained=retained,
        observation=fixture_observation_v1(fixture, bundle),
    )
    assert again == retained
    assert len(again) == 1


def test_same_ordinal_with_a_different_body_is_equivocation() -> None:
    fixture, bundle, _, retained = _setup()
    conflicting = fixture_observation_v1(
        fixture,
        bundle,
        unresolved_phase=LOCAL_PENDING_PHASE_V1,
        unresolved_phase_record_id=_digest("pending-phase-record"),
    )
    with pytest.raises(BlockedFinalityError) as exc:
        append_blocked_observation_v1(retained=retained, observation=conflicting)
    assert exc.value.reason_code == "blocked_observation_equivocation"


def test_ordinals_strictly_increase() -> None:
    fixture, bundle, _, retained = _setup()
    grown = append_blocked_observation_v1(
        retained=retained,
        observation=fixture_observation_v1(fixture, bundle, attempt_ordinal=3),
    )
    assert [entry.attempt_ordinal for entry in grown] == [1, 3]
    # An ordinal below the retained head that fills a gap is a regression, not a retry.
    with pytest.raises(BlockedFinalityError) as exc:
        append_blocked_observation_v1(
            retained=grown,
            observation=fixture_observation_v1(fixture, bundle, attempt_ordinal=2),
        )
    assert exc.value.reason_code == "blocked_observation_ordinal_regression"


def test_reappending_an_exact_earlier_observation_reconciles() -> None:
    fixture, bundle, observation, retained = _setup()
    grown = append_blocked_observation_v1(
        retained=retained,
        observation=fixture_observation_v1(fixture, bundle, attempt_ordinal=3),
    )
    assert append_blocked_observation_v1(retained=grown, observation=observation) == grown


def test_observation_cannot_join_another_transitions_history() -> None:
    fixture, bundle, _, retained = _setup()
    other = BlockedFinalityObservationV1.record(
        profile=fixture.profile,
        mission_id=fixture.vector.mission_id,
        authority_id=fixture.vector.authority_id,
        target_id=fixture.vector.target_id,
        event_digest=_digest("a-different-event"),
        event_seq=fixture.vector.event_seq,
        instance_sequence=fixture.vector.instance_sequence,
        pending_record_id=fixture.vector.pending_record_id,
        unresolved_phase=fixture.blocked_phase,
        unresolved_phase_record_id=fixture.blocked_phase_record_id,
        blocked_operation=fixture.blocked_operation,
        blocked_reason_code=fixture.blocked_reason_code,
        attempt_ordinal=2,
        time_bundle=bundle,
    )
    with pytest.raises(BlockedFinalityError) as exc:
        append_blocked_observation_v1(retained=retained, observation=other)
    assert exc.value.reason_code == "blocked_transition_mismatch"


# ---------------------------------------------------------------------------
# Recovery profile and role separation
# ---------------------------------------------------------------------------


def test_recovery_profile_is_canonical_and_binding_bound() -> None:
    fixture = _fixture()
    profile = fixture.profile
    assert profile.profile == REPOSITORY_OWNED_BLOCKED_FINALITY_PROFILE_V1
    assert profile.contract_version == BLOCKED_FINALITY_CONTRACT_VERSION_V1
    rebuilt = BlockedFinalityRecoveryProfileV1.from_canonical_bytes(
        profile.to_canonical_bytes()
    )
    assert rebuilt.profile_id == profile.profile_id
    assert rebuilt.to_body() == profile.to_body()


def test_recovery_profile_rejects_a_substituted_authority_binding_identity() -> None:
    profile = _fixture().profile
    with pytest.raises(BlockedFinalityError) as exc:
        replace(profile, authority_binding_id=_digest("another-binding"))
    assert exc.value.reason_code == "recovery_authority_binding_mismatch"


def test_recovery_key_cannot_be_the_decision_or_checkpoint_key() -> None:
    fixture = _fixture()
    profile = fixture.profile
    binding = profile.authority_binding
    decision_signer = fixture.decision_authority_signer
    assert decision_signer.key_id == binding.decision_key_id
    with pytest.raises(BlockedFinalityError) as exc:
        replace(
            profile,
            recovery_key=TrustedRecoveryKeyV1(
                principal_id="fixture.integrity-recovery.principal",
                role=BLOCKED_FINALITY_RECOVERY_ROLE_V1,
                public_key_bytes=decision_signer.public_key_bytes,
            ),
        )
    assert exc.value.reason_code == "recovery_role_not_separated"


def test_recovery_principal_cannot_be_the_decision_or_checkpoint_principal() -> None:
    fixture = _fixture()
    profile = fixture.profile
    binding = profile.authority_binding
    alien = RecoveryDecisionSignerV1.from_seed(
        principal_id=binding.decision_principal_id,
        seed=b"unrelated-recovery-seed",
    )
    with pytest.raises(BlockedFinalityError) as exc:
        replace(
            profile,
            recovery_key=TrustedRecoveryKeyV1(
                principal_id=binding.decision_principal_id,
                role=BLOCKED_FINALITY_RECOVERY_ROLE_V1,
                public_key_bytes=alien.public_key_bytes,
            ),
        )
    assert exc.value.reason_code == "recovery_role_not_separated"


def test_a_distinct_key_under_the_same_principal_is_still_refused() -> None:
    """A rotated key held by the same party is rotation, not separation of duty."""

    fixture = _fixture()
    binding = fixture.profile.authority_binding
    rotated = RecoveryDecisionSignerV1.from_seed(
        principal_id=binding.checkpoint_principal_id,
        seed=b"rotated-key-same-principal",
    )
    assert rotated.key_id != binding.checkpoint_key_id
    with pytest.raises(BlockedFinalityError) as exc:
        replace(
            fixture.profile,
            recovery_key=TrustedRecoveryKeyV1(
                principal_id=binding.checkpoint_principal_id,
                role=BLOCKED_FINALITY_RECOVERY_ROLE_V1,
                public_key_bytes=rotated.public_key_bytes,
            ),
        )
    assert exc.value.reason_code == "recovery_role_not_separated"


def test_recovery_role_is_outside_the_enrolled_integrity_roles() -> None:
    """The enrolled trust store admits only decision and checkpoint authorities."""

    assert INTEGRITY_ROLES_V1 == frozenset({INTEGRITY_DECISION_ROLE, HEAD_CHECKPOINT_ROLE})
    assert BLOCKED_FINALITY_RECOVERY_ROLE_V1 not in INTEGRITY_ROLES_V1
    profile = _fixture().profile
    assert profile.recovery_key_id not in profile.authority_binding.trust_store.keys


def test_recovery_key_requires_the_exact_recovery_role() -> None:
    fixture = _fixture()
    with pytest.raises(BlockedFinalityError) as exc:
        TrustedRecoveryKeyV1(
            principal_id="fixture.integrity-recovery.principal",
            role=INTEGRITY_DECISION_ROLE,
            public_key_bytes=fixture.recovery_signer.public_key_bytes,
        )
    assert exc.value.reason_code == "invalid_recovery_role"


def test_recovery_key_requires_a_prime_subgroup_ed25519_key() -> None:
    with pytest.raises(BlockedFinalityError) as exc:
        TrustedRecoveryKeyV1(
            principal_id="fixture.integrity-recovery.principal",
            role=BLOCKED_FINALITY_RECOVERY_ROLE_V1,
            public_key_bytes=bytes(32),
        )
    assert exc.value.reason_code == "invalid_recovery_public_key"


def test_recovery_key_that_is_also_an_enrolled_integrity_key_is_refused() -> None:
    fixture = _fixture()
    binding = fixture.profile.authority_binding
    extra = RecoveryDecisionSignerV1.from_seed(
        principal_id="fixture.integrity-recovery.principal",
        seed=SEED,
    )
    store = IntegrityTrustStore(
        keys={
            **dict(binding.trust_store.keys),
            extra.key_id: TrustedIntegrityKey(
                principal_id="fixture.smuggled.principal",
                public_key_bytes=extra.public_key_bytes,
                role=INTEGRITY_DECISION_ROLE,
            ),
        }
    )
    smuggled = replace(
        binding,
        trust_store=store,
        trust_snapshot_id=store.snapshot_id,
    )
    with pytest.raises(BlockedFinalityError) as exc:
        replace(
            fixture.profile,
            authority_binding=smuggled,
            authority_binding_id=smuggled.binding_id,
        )
    assert exc.value.reason_code == "recovery_role_not_separated"


# ---------------------------------------------------------------------------
# Governed recovery decision
# ---------------------------------------------------------------------------


def test_decision_restates_the_complete_observation_binding() -> None:
    fixture, bundle, observation, _ = _setup()
    decision = GovernedRecoveryDecisionV1.issue(
        profile=fixture.profile,
        observation=observation,
        disposition=RETRY_AUTHORIZED_DISPOSITION_V1,
        time_bundle=bundle,
        request_nonce=fixture.vector.request_nonce,
    )
    assert decision.blocked_observation_id == observation.observation_id
    assert decision.unresolved_phase == observation.unresolved_phase
    assert decision.unresolved_phase_record_id == observation.unresolved_phase_record_id
    assert decision.blocked_operation == observation.blocked_operation
    assert decision.blocked_reason_code == observation.blocked_reason_code
    assert decision.attempt_ordinal == observation.attempt_ordinal


@pytest.mark.parametrize(
    "field",
    ["disposition", "attempt_ordinal", "unresolved_phase", "blocked_reason_code"],
)
def test_decision_identity_binds_every_consequential_field(field: str) -> None:
    fixture, bundle, observation, _ = _setup()
    decision = GovernedRecoveryDecisionV1.issue(
        profile=fixture.profile,
        observation=observation,
        disposition=RETRY_AUTHORIZED_DISPOSITION_V1,
        time_bundle=bundle,
        request_nonce=fixture.vector.request_nonce,
    )
    substitutions = {
        "disposition": INSTANCE_SEALED_DISPOSITION_V1,
        "attempt_ordinal": 5,
        "unresolved_phase": LOCAL_PENDING_PHASE_V1,
        "blocked_reason_code": "modeled_anchor_equivocation",
    }
    with pytest.raises(BlockedFinalityError) as exc:
        replace(decision, **{field: substitutions[field]})
    assert exc.value.reason_code == "recovery_decision_id_mismatch"


def test_decision_rejects_an_unsupported_disposition() -> None:
    fixture, bundle, observation, _ = _setup()
    with pytest.raises(BlockedFinalityError) as exc:
        GovernedRecoveryDecisionV1.issue(
            profile=fixture.profile,
            observation=observation,
            disposition="force_finalize",
            time_bundle=bundle,
            request_nonce=fixture.vector.request_nonce,
        )
    assert exc.value.reason_code == "invalid_recovery_disposition"


def test_only_two_dispositions_are_admissible() -> None:
    from etzio.kernel.blocked_finality_v1 import BLOCKED_FINALITY_DISPOSITIONS_V1

    assert BLOCKED_FINALITY_DISPOSITIONS_V1 == frozenset(
        {RETRY_AUTHORIZED_DISPOSITION_V1, INSTANCE_SEALED_DISPOSITION_V1}
    )
    for forbidden in (
        "force_finalize",
        "discard_transition",
        "rewind_phase",
        "release_barrier",
    ):
        assert forbidden not in BLOCKED_FINALITY_DISPOSITIONS_V1


def test_signature_domain_separates_recovery_from_every_other_artifact() -> None:
    fixture, bundle, observation, _ = _setup()
    decision = GovernedRecoveryDecisionV1.issue(
        profile=fixture.profile,
        observation=observation,
        disposition=RETRY_AUTHORIZED_DISPOSITION_V1,
        time_bundle=bundle,
        request_nonce=fixture.vector.request_nonce,
    )
    signer = fixture.recovery_signer
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    undomained = Ed25519PrivateKey.from_private_bytes(signer.private_key_bytes).sign(
        decision.to_canonical_bytes()
    )
    with pytest.raises(BlockedFinalityError) as exc:
        authenticate_recovery_decision_v1(
            profile=fixture.profile,
            signed_decision=SignedGovernedRecoveryDecisionV1(
                key_id=signer.key_id,
                decision_bytes=decision.to_canonical_bytes(),
                signature_bytes=undomained,
            ),
        )
    assert exc.value.reason_code == "recovery_signature_invalid"


def test_authentication_rejects_the_integrity_decision_key() -> None:
    fixture, bundle, observation, _ = _setup()
    signed = _signed(fixture, observation, bundle)
    with pytest.raises(BlockedFinalityError) as exc:
        authenticate_recovery_decision_v1(
            profile=fixture.profile,
            signed_decision=SignedGovernedRecoveryDecisionV1(
                key_id=fixture.decision_authority_signer.key_id,
                decision_bytes=signed.decision_bytes,
                signature_bytes=signed.signature_bytes,
            ),
        )
    assert exc.value.reason_code == "recovery_key_mismatch"


def test_authentication_rejects_an_invalid_signature() -> None:
    fixture, bundle, observation, _ = _setup()
    signed = _signed(fixture, observation, bundle)
    with pytest.raises(BlockedFinalityError) as exc:
        authenticate_recovery_decision_v1(
            profile=fixture.profile,
            signed_decision=replace(signed, signature_bytes=bytes(64)),
        )
    assert exc.value.reason_code == "recovery_signature_invalid"


def test_authentication_rejects_a_foreign_profile_scope() -> None:
    fixture, bundle, observation, _ = _setup()
    signed = _signed(fixture, observation, bundle)
    other = create_repository_owned_blocked_finality_fixture_v1(seed=b"another-seed")
    with pytest.raises(BlockedFinalityError) as exc:
        authenticate_recovery_decision_v1(
            profile=other.profile,
            signed_decision=signed,
        )
    assert exc.value.reason_code == "recovery_key_mismatch"


def test_signed_decision_rejects_a_foreign_algorithm() -> None:
    fixture, bundle, observation, _ = _setup()
    signed = _signed(fixture, observation, bundle)
    body = signed.to_body()
    body["algorithm"] = "ed448"
    with pytest.raises(BlockedFinalityError) as exc:
        SignedGovernedRecoveryDecisionV1.from_canonical_bytes(
            __import__("json").dumps(body, sort_keys=True, separators=(",", ":")).encode()
        )
    assert exc.value.reason_code == "unsupported_recovery_algorithm"


def test_signer_refuses_a_decision_for_another_principal() -> None:
    fixture, bundle, observation, _ = _setup()
    decision = GovernedRecoveryDecisionV1.issue(
        profile=fixture.profile,
        observation=observation,
        disposition=RETRY_AUTHORIZED_DISPOSITION_V1,
        time_bundle=bundle,
        request_nonce=fixture.vector.request_nonce,
    )
    with pytest.raises(BlockedFinalityError) as exc:
        fixture.decision_authority_signer.sign(decision)
    assert exc.value.reason_code == "recovery_signer_binding_mismatch"


# ---------------------------------------------------------------------------
# Resolution and the barrier invariant
# ---------------------------------------------------------------------------


def test_authorized_retry_holds_the_barrier_and_names_the_exact_phase() -> None:
    fixture, bundle, observation, retained = _setup()
    resolution = _resolve(fixture, retained, _signed(fixture, observation, bundle))
    assert resolution.disposition == RETRY_AUTHORIZED_DISPOSITION_V1
    assert resolution.resume_phase == fixture.blocked_phase
    assert resolution.barrier_released is False
    assert resolution.instance_sealed is False


def test_sealing_holds_the_barrier_and_offers_no_resume_phase() -> None:
    fixture, bundle, observation, retained = _setup()
    resolution = _resolve(
        fixture,
        retained,
        _signed(fixture, observation, bundle, INSTANCE_SEALED_DISPOSITION_V1),
    )
    assert resolution.disposition == INSTANCE_SEALED_DISPOSITION_V1
    assert resolution.resume_phase is None
    assert resolution.barrier_released is False
    assert resolution.instance_sealed is True


def test_no_admissible_disposition_releases_the_barrier() -> None:
    fixture, bundle, observation, retained = _setup()
    for disposition in (RETRY_AUTHORIZED_DISPOSITION_V1, INSTANCE_SEALED_DISPOSITION_V1):
        resolution = _resolve(
            fixture,
            retained,
            _signed(fixture, observation, bundle, disposition),
        )
        assert resolution.barrier_released is False
        assert resolution.to_body()["barrier_released"] is False


def test_no_disposition_mints_a_checkpoint_or_finalization() -> None:
    fixture, bundle, observation, retained = _setup()
    resolution = _resolve(fixture, retained, _signed(fixture, observation, bundle))
    body = resolution.to_body()
    for forbidden in ("checkpoint_id", "finalization_id", "finalized", "instance_sequence"):
        assert forbidden not in body


def test_decision_for_another_observation_is_refused() -> None:
    fixture, bundle, _, retained = _setup()
    other = fixture_observation_v1(fixture, bundle, attempt_ordinal=2)
    with pytest.raises(BlockedFinalityError) as exc:
        _resolve(fixture, retained, _signed(fixture, other, bundle))
    assert exc.value.reason_code == "recovery_observation_mismatch"


def test_decision_answering_a_stale_phase_is_refused() -> None:
    fixture, bundle, observation, retained = _setup()
    with pytest.raises(BlockedFinalityError) as exc:
        _resolve(
            fixture,
            retained,
            _signed(fixture, observation, bundle),
            current_phase=CHECKPOINT_CANDIDATE_RETAINED_PHASE_V1,
            current_phase_record_id=_digest("advanced-candidate-record"),
        )
    assert exc.value.reason_code == "blocked_observation_stale"


def test_decision_must_answer_the_latest_retained_observation() -> None:
    fixture, bundle, observation, retained = _setup()
    grown = append_blocked_observation_v1(
        retained=retained,
        observation=fixture_observation_v1(fixture, bundle, attempt_ordinal=2),
    )
    with pytest.raises(BlockedFinalityError) as exc:
        _resolve(fixture, grown, _signed(fixture, observation, bundle))
    assert exc.value.reason_code == "recovery_observation_mismatch"


def test_a_sealed_instance_admits_nothing_further() -> None:
    fixture, bundle, observation, retained = _setup()
    for disposition in (RETRY_AUTHORIZED_DISPOSITION_V1, INSTANCE_SEALED_DISPOSITION_V1):
        with pytest.raises(BlockedFinalityError) as exc:
            _resolve(
                fixture,
                retained,
                _signed(fixture, observation, bundle, disposition),
                sealed=True,
            )
        assert exc.value.reason_code == "instance_already_sealed"


def test_resolution_requires_a_nonempty_retained_history() -> None:
    fixture, bundle, observation, _ = _setup()
    with pytest.raises(BlockedFinalityError) as exc:
        _resolve(fixture, (), _signed(fixture, observation, bundle))
    assert exc.value.reason_code == "invalid_blocked_observation"


def test_sealed_results_refuse_public_construction() -> None:
    for sealed_type in (
        AuthenticatedRecoveryDecisionV1,
        BlockedFinalityResolutionV1,
        BlockedFinalityQualificationReportV1,
    ):
        with pytest.raises(BlockedFinalityError) as exc:
            sealed_type()
        assert exc.value.reason_code == "unauthenticated_blocked_result_construction"


# ---------------------------------------------------------------------------
# Deterministic harness
# ---------------------------------------------------------------------------


def test_repository_harness_qualifies_every_ordered_case() -> None:
    report = qualify_repository_blocked_finality_v1(_fixture())
    assert report.passed
    assert report.overall_disposition == "qualified"
    assert [case.case_id for case in report.cases] == [
        "observation_retained_and_retry_stable",
        "finalized_phase_observation_refused",
        "ordinal_equivocation_refused",
        "retry_authorized_holds_the_barrier",
        "decision_for_another_observation_refused",
        "decision_signed_by_integrity_authority_refused",
        "instance_sealed_holds_the_barrier",
        "action_after_seal_refused",
    ]


def test_repository_harness_is_byte_identical_across_runs() -> None:
    first = qualify_repository_blocked_finality_v1(_fixture())
    second = qualify_repository_blocked_finality_v1(_fixture())
    assert first.report_id == second.report_id
    assert first.to_body() == second.to_body()


def test_corpus_manifest_binds_every_outcome_affecting_input() -> None:
    fixture = _fixture()
    with pytest.raises(BlockedFinalityError) as exc:
        replace(fixture, corpus_manifest_id=_digest("substituted-manifest"))
    assert exc.value.reason_code == "blocked_qualification_manifest_mismatch"
    with pytest.raises(BlockedFinalityError) as exc:
        replace(fixture, blocked_reason_code="modeled_anchor_equivocation")
    assert exc.value.reason_code == "blocked_qualification_manifest_mismatch"
    with pytest.raises(BlockedFinalityError) as exc:
        replace(fixture, blocked_phase=LOCAL_PENDING_PHASE_V1)
    assert exc.value.reason_code == "blocked_qualification_manifest_mismatch"


def test_fixture_refuses_a_recovery_signer_that_is_not_the_retained_key() -> None:
    fixture = _fixture()
    alien = RecoveryDecisionSignerV1.from_seed(
        principal_id="fixture.integrity-recovery.principal",
        seed=b"a-different-recovery-seed",
    )
    with pytest.raises(BlockedFinalityError) as exc:
        replace(fixture, recovery_signer=alien)
    assert exc.value.reason_code == "invalid_blocked_qualification_fixture"


def test_harness_has_no_clock_or_network_dependency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _no_clock(*_args: object, **_kwargs: object) -> float:
        raise AssertionError("blocked-finality qualification must not read an ambient clock")

    def _no_socket(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("blocked-finality qualification must not open a socket")

    monkeypatch.setattr(time, "time", _no_clock)
    monkeypatch.setattr(time, "time_ns", _no_clock)
    monkeypatch.setattr(socket, "socket", _no_socket)
    monkeypatch.setattr(socket, "create_connection", _no_socket)
    assert qualify_repository_blocked_finality_v1(_fixture()).passed


def test_reason_taxonomy_matches_the_implemented_recovery_path() -> None:
    """Every admitted reason is one the implemented finality path actually produces."""

    from pathlib import Path

    from etzio.kernel.blocked_finality_v1 import BLOCKED_REASON_CODES_V1

    source = (
        Path(__file__).resolve().parents[1]
        / "etzio"
        / "kernel"
        / "integrity_transition.py"
    ).read_text(encoding="utf-8")
    for reason_code in BLOCKED_REASON_CODES_V1:
        assert f'"{reason_code}"' in source


def test_blocked_operations_match_the_implemented_adapter_surface() -> None:
    from pathlib import Path

    from etzio.kernel.blocked_finality_v1 import BLOCKED_OPERATIONS_V1

    source = (
        Path(__file__).resolve().parents[1]
        / "etzio"
        / "kernel"
        / "integrity_transition.py"
    ).read_text(encoding="utf-8")
    for operation in BLOCKED_OPERATIONS_V1 - {"recover_lineage", "propose_transition"}:
        assert operation in source
