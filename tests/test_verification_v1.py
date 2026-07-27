from __future__ import annotations

import base64
from dataclasses import FrozenInstanceError, replace

import pytest

import etzio.verification as verification
from etzio.protocol import EnvelopeV1, canonical_dumps, strict_loads, thaw_json
from etzio.verification import (
    MODELED_FIXTURE_TIER,
    VERIFIER_ROLE,
    SignedVerifierReceiptV1,
    TrustedVerifierKey,
    VerificationDecision,
    VerificationError,
    VerificationLeaseV1,
    VerifierReceiptV1,
    VerifierSigner,
    VerifierTrustStore,
    validate_verifier_receipt,
)

NOW = 2_000_000_000


def digest(character: str) -> str:
    return "sha256:" + character * 64


MISSION_ID = digest("1")
AUTHORITY_ID = digest("2")
TARGET_ID = digest("3")
CANDIDATE_ID = digest("4")
POC_DIGEST = digest("5")
EVIDENCE_DIGESTS = (digest("6"), digest("7"))
ENVIRONMENT_DIGEST = digest("8")
ORACLE_ID = digest("9")
PRODUCER_ID = "VELITES"
VERIFIER_ID = "CATO"


@pytest.fixture
def signer() -> VerifierSigner:
    return VerifierSigner.generate()


def issue_lease(signer: VerifierSigner, **overrides: object) -> VerificationLeaseV1:
    values: dict[str, object] = {
        "lease_nonce": "a" * 32,
        "mission_id": MISSION_ID,
        "authority_id": AUTHORITY_ID,
        "target_snapshot_id": TARGET_ID,
        "candidate_id": CANDIDATE_ID,
        "candidate_producer_id": PRODUCER_ID,
        "poc_artifact_digest": POC_DIGEST,
        "evidence_artifact_digests": EVIDENCE_DIGESTS,
        "environment_digest": ENVIRONMENT_DIGEST,
        "effect_oracle_id": ORACLE_ID,
        "verifier_id": VERIFIER_ID,
        "verifier_key_id": signer.key_id,
        "issued_at": NOW,
        "expires_at": NOW + 100,
    }
    values.update(overrides)
    return VerificationLeaseV1.issue(**values)  # type: ignore[arg-type]


def receipt_values(
    lease: VerificationLeaseV1,
    **overrides: object,
) -> dict[str, object]:
    values: dict[str, object] = {
        "lease_id": lease.lease_id,
        "mission_id": lease.mission_id,
        "authority_id": lease.authority_id,
        "target_snapshot_id": lease.target_snapshot_id,
        "candidate_id": lease.candidate_id,
        "candidate_producer_id": lease.candidate_producer_id,
        "poc_artifact_digest": lease.poc_artifact_digest,
        "evidence_artifact_digests": lease.evidence_artifact_digests,
        "environment_digest": lease.environment_digest,
        "effect_oracle_id": lease.effect_oracle_id,
        "verifier_id": lease.verifier_id,
        "verifier_key_id": lease.verifier_key_id,
        "evidence_tier": MODELED_FIXTURE_TIER,
        "verdict": "confirmed",
        "effect_observed": True,
        "oracle_satisfied": True,
        "completed_at": NOW + 10,
    }
    values.update(overrides)
    return values


def issue_receipt(lease: VerificationLeaseV1, **overrides: object) -> VerifierReceiptV1:
    return VerifierReceiptV1.issue(**receipt_values(lease, **overrides))  # type: ignore[arg-type]


def trusted_store(
    signer: VerifierSigner,
    *,
    verifier_id: str = VERIFIER_ID,
    roles: frozenset[str] = frozenset({VERIFIER_ROLE}),
    revoked_key_ids: tuple[str, ...] = (),
    revoked_receipt_ids: tuple[str, ...] = (),
    revoked_lease_ids: tuple[str, ...] = (),
) -> VerifierTrustStore:
    key = TrustedVerifierKey(
        verifier_id=verifier_id,
        public_key_bytes=signer.public_key_bytes,
        roles=roles,
    )
    return VerifierTrustStore.from_keys(
        (key,),
        revoked_key_ids=revoked_key_ids,
        revoked_receipt_ids=revoked_receipt_ids,
        revoked_lease_ids=revoked_lease_ids,
    )


def retained_evidence(lease: VerificationLeaseV1) -> frozenset[str]:
    return frozenset(
        {
            lease.poc_artifact_digest,
            *lease.evidence_artifact_digests,
            lease.environment_digest,
            lease.effect_oracle_id,
        }
    )


def decide(
    signed: SignedVerifierReceiptV1 | dict[str, object] | bytes | str,
    store: VerifierTrustStore,
    lease: VerificationLeaseV1,
    *,
    decision_time: int = NOW + 11,
    expected_verdict: str = "confirmed",
    consumed_lease_ids: frozenset[str] = frozenset(),
    retained_evidence_digests: frozenset[str] | None = None,
) -> VerificationDecision:
    return validate_verifier_receipt(
        signed,
        store,
        lease=lease,
        decision_time=decision_time,
        expected_verdict=expected_verdict,
        consumed_lease_ids=consumed_lease_ids,
        retained_evidence_digests=(
            retained_evidence(lease) if retained_evidence_digests is None else retained_evidence_digests
        ),
    )


def sign_raw(
    signer: VerifierSigner,
    envelope_bytes: bytes,
    *,
    key_id: str | None = None,
) -> SignedVerifierReceiptV1:
    signature = signer.private_key.sign(verification._SIGNATURE_DOMAIN + envelope_bytes)
    return SignedVerifierReceiptV1(
        envelope_bytes=envelope_bytes,
        key_id=key_id or signer.key_id,
        signature_b64=base64.b64encode(signature).decode("ascii"),
    )


def sign_envelope(signer: VerifierSigner, envelope: EnvelopeV1) -> SignedVerifierReceiptV1:
    return sign_raw(signer, envelope.to_bytes())


def test_valid_modeled_fixture_receipt_is_exactly_bound_and_does_not_mint_finding(
    signer: VerifierSigner,
) -> None:
    lease = issue_lease(signer)
    receipt = VerifierReceiptV1.for_lease(
        lease,
        evidence_tier=MODELED_FIXTURE_TIER,
        verdict="confirmed",
        effect_observed=True,
        oracle_satisfied=True,
        completed_at=NOW + 10,
    )

    decision = decide(signer.sign(receipt), trusted_store(signer), lease)

    assert decision == VerificationDecision(
        accepted=True,
        lease_id=lease.lease_id,
        receipt_id=receipt.receipt_id,
        verdict="confirmed",
        reason_code="accepted",
        trust_snapshot_id=trusted_store(signer).snapshot_id,
    )
    assert not hasattr(decision, "finding_id")
    assert lease.lease_id == lease.to_envelope().object_id
    assert receipt.receipt_id == receipt.to_envelope().object_id
    assert signer.sign(receipt).envelope_bytes == canonical_dumps(strict_loads(signer.sign(receipt).envelope_bytes))


def test_signed_receipt_has_one_canonical_attestation_and_round_trips(
    signer: VerifierSigner,
) -> None:
    lease = issue_lease(signer)
    receipt = issue_receipt(lease)
    signed = signer.sign(receipt)

    wire = signed.to_bytes()
    envelope = EnvelopeV1.from_bytes(wire)
    restored = SignedVerifierReceiptV1.from_bytes(wire)

    assert envelope.object_kind == "verifier_receipt"
    assert envelope.object_id == receipt.receipt_id
    assert len(envelope.attestations) == 1
    assert thaw_json(envelope.attestations[0]) == {
        "algorithm": "ed25519",
        "key_id": signer.key_id,
        "signature_b64": signed.signature_b64,
    }
    assert restored == signed
    assert restored.to_bytes() == wire
    assert decide(wire, trusted_store(signer), lease).accepted


def test_signed_receipt_wire_rejects_missing_multiple_or_malformed_attestations(
    signer: VerifierSigner,
) -> None:
    lease = issue_lease(signer)
    receipt = issue_receipt(lease)
    signed = signer.sign(receipt)
    attestation = thaw_json(signed.to_envelope().attestations[0])

    missing = receipt.to_envelope().to_bytes()
    with pytest.raises(VerificationError) as no_attestation:
        SignedVerifierReceiptV1.from_bytes(missing)
    assert no_attestation.value.reason_code == "malformed_signed_receipt"

    multiple = EnvelopeV1.create(
        "verifier_receipt",
        receipt.to_envelope().body,
        attestations=[attestation, attestation],
    )
    with pytest.raises(VerificationError) as two_attestations:
        SignedVerifierReceiptV1.from_bytes(multiple.to_bytes())
    assert two_attestations.value.reason_code == "malformed_signed_receipt"

    malformed = EnvelopeV1.create(
        "verifier_receipt",
        receipt.to_envelope().body,
        attestations=[{**attestation, "unknown": True}],
    )
    with pytest.raises(VerificationError) as unknown_field:
        SignedVerifierReceiptV1.from_bytes(malformed.to_bytes())
    assert unknown_field.value.reason_code == "malformed_signed_receipt"

    wrong_algorithm = EnvelopeV1.create(
        "verifier_receipt",
        receipt.to_envelope().body,
        attestations=[{**attestation, "algorithm": "rsa"}],
    )
    with pytest.raises(VerificationError) as algorithm:
        SignedVerifierReceiptV1.from_bytes(wrong_algorithm.to_bytes())
    assert algorithm.value.reason_code == "malformed_signed_receipt"


def test_lease_and_receipt_are_deeply_immutable_and_have_exact_v1_fields(
    signer: VerifierSigner,
) -> None:
    lease = issue_lease(signer)
    receipt = issue_receipt(lease)
    signed = signer.sign(receipt)
    store = trusted_store(signer)

    with pytest.raises(FrozenInstanceError):
        lease.mission_id = digest("a")  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        receipt.verdict = "invalid"  # type: ignore[misc]
    with pytest.raises(TypeError):
        signed.as_raw()["key_id"] = signer.key_id  # type: ignore[index]
    with pytest.raises(TypeError):
        store.keys[signer.key_id] = store.keys[signer.key_id]  # type: ignore[index]

    assert tuple(VerificationLeaseV1.__dataclass_fields__) == (
        "lease_id",
        "lease_nonce",
        "mission_id",
        "authority_id",
        "target_snapshot_id",
        "candidate_id",
        "candidate_producer_id",
        "poc_artifact_digest",
        "evidence_artifact_digests",
        "environment_digest",
        "effect_oracle_id",
        "verifier_id",
        "verifier_key_id",
        "issued_at",
        "expires_at",
    )


def test_lease_id_changes_with_nonce_and_rejects_detached_semantics(signer: VerifierSigner) -> None:
    first = issue_lease(signer)
    second = issue_lease(signer, lease_nonce="b" * 32)

    assert first.lease_id != second.lease_id
    with pytest.raises(VerificationError) as caught:
        replace(first, lease_id=digest("f"))
    assert caught.value.reason_code == "object_id_mismatch"


def test_unsigned_unknown_transport_fields_and_forged_signature_fail_closed(
    signer: VerifierSigner,
) -> None:
    lease = issue_lease(signer)
    signed = signer.sign(issue_receipt(lease))
    store = trusted_store(signer)

    assert decide({"verdict": "confirmed"}, store, lease).reason_code == "unsigned_receipt"
    assert (
        decide(
            {"envelope_bytes": signed.envelope_bytes, "key_id": signed.key_id},
            store,
            lease,
        ).reason_code
        == "unsigned_receipt"
    )
    assert decide({**dict(signed.as_raw()), "unknown": "field"}, store, lease).reason_code == "malformed_signed_receipt"

    forger = VerifierSigner.generate()
    forged_signature = forger.private_key.sign(verification._SIGNATURE_DOMAIN + signed.envelope_bytes)
    forged = {
        **dict(signed.as_raw()),
        "signature_b64": base64.b64encode(forged_signature).decode("ascii"),
    }
    assert decide(forged, store, lease).reason_code == "invalid_signature"
    assert decide({**dict(signed.as_raw()), "signature_b64": "not-base64!"}, store, lease).reason_code == (
        "malformed_signature"
    )


def test_self_verification_is_rejected_even_with_a_valid_signature(signer: VerifierSigner) -> None:
    lease = issue_lease(signer, candidate_producer_id=VERIFIER_ID)
    signed = signer.sign(issue_receipt(lease))

    decision = decide(signed, trusted_store(signer), lease)

    assert decision.reason_code == "self_verification"


def test_caller_snapshot_rejects_an_already_consumed_lease_sequentially(
    signer: VerifierSigner,
) -> None:
    lease = issue_lease(signer)
    signed = signer.sign(issue_receipt(lease))
    store = trusted_store(signer)

    assert decide(signed, store, lease).accepted
    replay = decide(signed, store, lease, consumed_lease_ids=frozenset({lease.lease_id}))

    assert replay == VerificationDecision(
        accepted=False,
        lease_id=None,
        receipt_id=None,
        verdict=None,
        reason_code="lease_already_consumed",
    )


def test_unknown_revoked_and_wrong_role_keys_fail_closed(signer: VerifierSigner) -> None:
    lease = issue_lease(signer)
    signed = signer.sign(issue_receipt(lease))

    assert decide(signed, VerifierTrustStore.from_keys(()), lease).reason_code == "unknown_key"
    assert decide(signed, trusted_store(signer, revoked_key_ids=(signer.key_id,)), lease).reason_code == "key_revoked"
    assert (
        decide(signed, trusted_store(signer, roles=frozenset({"auditor"})), lease).reason_code
        == "key_missing_verifier_role"
    )


def test_small_order_ed25519_trust_key_is_rejected_before_it_can_forge_receipts() -> None:
    identity_encoding = b"\x01" + (b"\x00" * 31)

    with pytest.raises(VerificationError) as caught:
        TrustedVerifierKey(
            verifier_id=VERIFIER_ID,
            public_key_bytes=identity_encoding,
            roles=frozenset({VERIFIER_ROLE}),
        )

    assert caught.value.reason_code == "invalid_public_key"


def test_verifier_trust_snapshot_is_deterministic_strict_and_content_bound(
    signer: VerifierSigner,
) -> None:
    other = VerifierSigner.generate()
    first = TrustedVerifierKey(
        verifier_id=VERIFIER_ID,
        public_key_bytes=signer.public_key_bytes,
        roles=frozenset({VERIFIER_ROLE, "auditor"}),
    )
    second = TrustedVerifierKey(
        verifier_id="CATO_SECONDARY",
        public_key_bytes=other.public_key_bytes,
        roles=frozenset({VERIFIER_ROLE}),
    )
    revoked_receipts = (digest("c"), digest("b"))
    revoked_leases = (digest("e"), digest("d"))
    left = VerifierTrustStore.from_keys(
        (second, first),
        revoked_key_ids=(other.key_id,),
        revoked_receipt_ids=revoked_receipts,
        revoked_lease_ids=revoked_leases,
    )
    right = VerifierTrustStore.from_keys(
        (first, second),
        revoked_key_ids=(other.key_id,),
        revoked_receipt_ids=reversed(revoked_receipts),
        revoked_lease_ids=reversed(revoked_leases),
    )

    body = left.to_snapshot_body()
    restored = VerifierTrustStore.from_snapshot_body(
        body,
        expected_snapshot_id=left.snapshot_id,
    )

    assert body == right.to_snapshot_body()
    assert left.snapshot_id == right.snapshot_id
    assert restored == left
    with pytest.raises(VerificationError) as mismatch:
        VerifierTrustStore.from_snapshot_body(body, expected_snapshot_id=digest("f"))
    assert mismatch.value.reason_code == "trust_snapshot_mismatch"

    body["unknown"] = True
    with pytest.raises(VerificationError) as unknown:
        VerifierTrustStore.from_snapshot_body(body)
    assert unknown.value.reason_code == "invalid_trust_snapshot"


def test_trust_snapshot_rejects_small_order_ed25519_key_bytes(
    signer: VerifierSigner,
) -> None:
    body = trusted_store(signer).to_snapshot_body()
    keys = body["keys"]
    assert type(keys) is list and type(keys[0]) is dict
    identity_encoding = b"\x01" + (b"\x00" * 31)
    keys[0]["public_key_b64"] = base64.b64encode(identity_encoding).decode("ascii")
    keys[0]["key_id"] = verification.verifier_key_id(identity_encoding)

    with pytest.raises(VerificationError) as caught:
        VerifierTrustStore.from_snapshot_body(body)

    assert caught.value.reason_code == "invalid_trust_snapshot"


def test_trust_snapshot_rejects_noncanonical_nested_collections(
    signer: VerifierSigner,
) -> None:
    body = trusted_store(signer).to_snapshot_body()
    keys = body["keys"]
    assert type(keys) is list and type(keys[0]) is dict
    keys[0]["roles"] = [VERIFIER_ROLE, VERIFIER_ROLE]

    with pytest.raises(VerificationError) as roles:
        VerifierTrustStore.from_snapshot_body(body)
    assert roles.value.reason_code == "invalid_trust_snapshot"

    body = trusted_store(
        signer,
        revoked_receipt_ids=(digest("a"), digest("b")),
    ).to_snapshot_body()
    body["revoked_receipt_ids"] = [digest("b"), digest("a")]
    with pytest.raises(VerificationError) as revocations:
        VerifierTrustStore.from_snapshot_body(body)
    assert revocations.value.reason_code == "invalid_trust_snapshot"


def test_revoked_receipt_and_lease_fail_closed(signer: VerifierSigner) -> None:
    lease = issue_lease(signer)
    receipt = issue_receipt(lease)
    signed = signer.sign(receipt)

    assert (
        decide(
            signed,
            trusted_store(signer, revoked_receipt_ids=(receipt.receipt_id,)),
            lease,
        ).reason_code
        == "receipt_revoked"
    )
    assert (
        decide(
            signed,
            trusted_store(signer, revoked_lease_ids=(lease.lease_id,)),
            lease,
        ).reason_code
        == "lease_revoked"
    )


@pytest.mark.parametrize(
    ("decision_time", "reason"),
    [
        (NOW - 1, "lease_not_yet_valid"),
        (NOW, "accepted"),
        (NOW + 99, "accepted"),
        (NOW + 100, "lease_expired"),
    ],
)
def test_lease_window_is_half_open(
    signer: VerifierSigner,
    decision_time: int,
    reason: str,
) -> None:
    lease = issue_lease(signer)
    receipt = issue_receipt(lease, completed_at=NOW)

    decision = decide(
        signer.sign(receipt),
        trusted_store(signer),
        lease,
        decision_time=decision_time,
    )

    assert decision.reason_code == reason


@pytest.mark.parametrize(
    ("completed_at", "decision_time", "reason"),
    [
        (NOW - 1, NOW + 1, "receipt_before_lease"),
        (NOW + 100, NOW + 50, "receipt_after_expiry"),
        (NOW + 20, NOW + 10, "receipt_from_future"),
    ],
)
def test_receipt_completion_time_must_be_inside_lease_and_not_future(
    signer: VerifierSigner,
    completed_at: int,
    decision_time: int,
    reason: str,
) -> None:
    lease = issue_lease(signer)
    receipt = issue_receipt(lease, completed_at=completed_at)

    assert (
        decide(
            signer.sign(receipt),
            trusted_store(signer),
            lease,
            decision_time=decision_time,
        ).reason_code
        == reason
    )


@pytest.mark.parametrize(
    ("field", "replacement", "reason"),
    [
        ("lease_id", digest("a"), "lease_mismatch"),
        ("mission_id", digest("a"), "mission_mismatch"),
        ("authority_id", digest("a"), "authority_mismatch"),
        ("target_snapshot_id", digest("a"), "target_mismatch"),
        ("candidate_id", digest("a"), "candidate_mismatch"),
        ("candidate_producer_id", "MARCELLUS", "candidate_producer_mismatch"),
        ("poc_artifact_digest", digest("a"), "poc_artifact_mismatch"),
        ("evidence_artifact_digests", (digest("a"),), "evidence_artifacts_mismatch"),
        ("environment_digest", digest("a"), "environment_mismatch"),
        ("effect_oracle_id", digest("a"), "effect_oracle_mismatch"),
    ],
)
def test_signed_receipt_substitution_is_rejected(
    signer: VerifierSigner,
    field: str,
    replacement: object,
    reason: str,
) -> None:
    lease = issue_lease(signer)
    receipt = issue_receipt(lease, **{field: replacement})

    decision = decide(signer.sign(receipt), trusted_store(signer), lease)

    assert decision.reason_code == reason


def test_verifier_identity_and_key_are_bound_to_lease_trust_and_signature(
    signer: VerifierSigner,
) -> None:
    lease = issue_lease(signer)

    wrong_identity = issue_receipt(lease, verifier_id="FABRICIUS")
    assert (
        decide(
            signer.sign(wrong_identity),
            trusted_store(signer),
            lease,
        ).reason_code
        == "verifier_identity_mismatch"
    )

    other_signer = VerifierSigner.generate()
    other_key_receipt = issue_receipt(lease, verifier_key_id=other_signer.key_id)
    signed_by_assigned_transport_key = sign_envelope(signer, other_key_receipt.to_envelope())
    assert (
        decide(
            signed_by_assigned_transport_key,
            trusted_store(signer),
            lease,
        ).reason_code
        == "signer_key_mismatch"
    )


def test_exact_event_verdict_must_match_signed_receipt(signer: VerifierSigner) -> None:
    lease = issue_lease(signer)
    receipt = issue_receipt(
        lease,
        verdict="not_reproduced",
        effect_observed=False,
        oracle_satisfied=False,
    )

    decision = decide(
        signer.sign(receipt),
        trusted_store(signer),
        lease,
        expected_verdict="confirmed",
    )

    assert decision.reason_code == "verdict_mismatch"


@pytest.mark.parametrize(
    ("verdict", "effect_observed", "oracle_satisfied", "reason"),
    [
        ("confirmed", False, True, "confirmed_without_effect"),
        ("confirmed", True, False, "confirmed_without_oracle"),
        ("not_reproduced", True, False, "not_reproduced_with_positive_observation"),
        ("not_reproduced", False, True, "not_reproduced_with_positive_observation"),
        ("invalid", True, False, "invalid_with_positive_observation"),
        ("inconclusive", True, True, "inconclusive_with_confirmed_observation"),
    ],
)
def test_verdict_observation_combinations_fail_closed(
    signer: VerifierSigner,
    verdict: str,
    effect_observed: bool,
    oracle_satisfied: bool,
    reason: str,
) -> None:
    lease = issue_lease(signer)
    receipt = issue_receipt(
        lease,
        verdict=verdict,
        effect_observed=effect_observed,
        oracle_satisfied=oracle_satisfied,
    )

    decision = decide(
        signer.sign(receipt),
        trusted_store(signer),
        lease,
        expected_verdict=verdict,
    )

    assert decision.reason_code == reason


def test_every_referenced_digest_must_exist_in_the_caller_membership_snapshot(
    signer: VerifierSigner,
) -> None:
    lease = issue_lease(signer)
    signed = signer.sign(issue_receipt(lease))
    required = retained_evidence(lease)

    for missing in required:
        decision = decide(
            signed,
            trusted_store(signer),
            lease,
            retained_evidence_digests=required - {missing},
        )
        assert decision.reason_code == "referenced_evidence_missing"


def test_claimed_kvm_or_production_tier_is_rejected_despite_trusted_signature(
    signer: VerifierSigner,
) -> None:
    lease = issue_lease(signer)
    body = receipt_values(lease)
    body["evidence_artifact_digests"] = list(EVIDENCE_DIGESTS)
    body["evidence_tier"] = "kvm_isolated"
    envelope = EnvelopeV1.create("verifier_receipt", body)

    decision = decide(sign_envelope(signer, envelope), trusted_store(signer), lease)

    assert decision.reason_code == "unsupported_evidence_tier"


def test_unknown_receipt_field_is_rejected_despite_trusted_signature(
    signer: VerifierSigner,
) -> None:
    lease = issue_lease(signer)
    body = receipt_values(lease)
    body["evidence_artifact_digests"] = list(EVIDENCE_DIGESTS)
    body["claimed_isolation"] = "kvm"
    envelope = EnvelopeV1.create("verifier_receipt", body)

    assert decide(sign_envelope(signer, envelope), trusted_store(signer), lease).reason_code == "malformed_receipt"


def test_body_float_and_noninteger_api_values_are_rejected(signer: VerifierSigner) -> None:
    with pytest.raises(VerificationError) as lease_error:
        issue_lease(signer, issued_at=NOW + 0.5)
    assert lease_error.value.reason_code == "invalid_lease_time"

    lease = issue_lease(signer)
    with pytest.raises(VerificationError) as receipt_error:
        issue_receipt(lease, completed_at=NOW + 0.5)
    assert receipt_error.value.reason_code == "invalid_completed_at"

    malformed_float_json = b'{"completed_at":2000000000.5}'
    signed = sign_raw(signer, malformed_float_json)
    assert decide(signed, trusted_store(signer), lease).reason_code == "invalid_envelope"


def test_time_values_require_exact_bounded_integers(signer: VerifierSigner) -> None:
    for invalid_time in (True, verification.MAX_EPOCH_SECOND + 1):
        with pytest.raises(VerificationError) as lease_error:
            issue_lease(signer, issued_at=invalid_time)
        assert lease_error.value.reason_code == "invalid_lease_time"

    lease = issue_lease(signer)
    for invalid_time in (False, verification.MAX_EPOCH_SECOND + 1):
        with pytest.raises(VerificationError) as receipt_error:
            issue_receipt(lease, completed_at=invalid_time)
        assert receipt_error.value.reason_code == "invalid_completed_at"

    signed = signer.sign(issue_receipt(lease))
    for invalid_time in (True, verification.MAX_EPOCH_SECOND + 1):
        assert (
            decide(
                signed,
                trusted_store(signer),
                lease,
                decision_time=invalid_time,
            ).reason_code
            == "invalid_decision_time"
        )


def test_fixed_collection_ceilings_fail_closed_before_signature_verification(
    signer: VerifierSigner,
) -> None:
    too_many_evidence = tuple(f"sha256:{index:064x}" for index in range(verification.MAX_EVIDENCE_ARTIFACTS + 1))
    with pytest.raises(VerificationError) as evidence:
        issue_lease(signer, evidence_artifact_digests=too_many_evidence)
    assert evidence.value.reason_code == "too_many_evidence_artifacts"

    trusted_keys = tuple(
        TrustedVerifierKey(
            verifier_id=f"CATO_{index}",
            public_key_bytes=VerifierSigner.generate().public_key_bytes,
            roles=frozenset({VERIFIER_ROLE}),
        )
        for index in range(verification.MAX_TRUSTED_VERIFIER_KEYS + 1)
    )
    with pytest.raises(VerificationError) as keys:
        VerifierTrustStore.from_keys(trusted_keys)
    assert keys.value.reason_code == "invalid_trust_store"

    with pytest.raises(VerificationError) as revocations:
        VerifierTrustStore.from_keys(
            (),
            revoked_receipt_ids=(f"sha256:{index:064x}" for index in range(verification.MAX_VERIFIER_REVOCATIONS + 1)),
        )
    assert revocations.value.reason_code == "invalid_trust_store"

    lease = issue_lease(signer)
    signed = signer.sign(issue_receipt(lease))

    class OversizedSet(set[str]):
        def __len__(self) -> int:
            return verification.MAX_CONSUMED_LEASE_IDS + 1

    assert (
        decide(
            signed,
            trusted_store(signer),
            lease,
            consumed_lease_ids=OversizedSet(),
        ).reason_code
        == "invalid_consumed_lease_ids"
    )

    class OversizedEvidenceSet(set[str]):
        def __len__(self) -> int:
            return verification.MAX_RETAINED_EVIDENCE_DIGESTS + 1

    assert (
        decide(
            signed,
            trusted_store(signer),
            lease,
            retained_evidence_digests=OversizedEvidenceSet(),
        ).reason_code
        == "invalid_retained_evidence"
    )


def test_signed_receipt_wire_and_signature_have_fixed_tight_ceilings(
    signer: VerifierSigner,
) -> None:
    lease = issue_lease(signer)
    signed = signer.sign(issue_receipt(lease))

    with pytest.raises(VerificationError) as oversized:
        SignedVerifierReceiptV1(
            envelope_bytes=b"x" * (verification.MAX_VERIFIER_RECEIPT_ENVELOPE_BYTES + 1),
            key_id=signer.key_id,
            signature_b64=signed.signature_b64,
        )
    assert oversized.value.reason_code == "receipt_envelope_too_large"

    with pytest.raises(VerificationError) as malformed:
        SignedVerifierReceiptV1(
            envelope_bytes=signed.envelope_bytes,
            key_id=signer.key_id,
            signature_b64="A" * 88,
        )
    assert malformed.value.reason_code == "malformed_signature"

    with pytest.raises(VerificationError) as oversized_wire:
        SignedVerifierReceiptV1.from_bytes(b"x" * (verification.MAX_VERIFIER_RECEIPT_ENVELOPE_BYTES + 1))
    assert oversized_wire.value.reason_code == "receipt_envelope_too_large"


def test_envelope_unknown_fields_and_wrong_purpose_are_rejected(signer: VerifierSigner) -> None:
    lease = issue_lease(signer)
    lease_body = thaw_json(lease.to_envelope().body)
    assert type(lease_body) is dict
    assert lease.to_envelope().object_kind == "verification_lease"

    with_unknown = {**lease_body, "unknown": "field"}
    unknown_envelope = EnvelopeV1.create("verification_lease", with_unknown)
    with pytest.raises(VerificationError) as unknown:
        VerificationLeaseV1.from_envelope(unknown_envelope)
    assert unknown.value.reason_code == "malformed_lease"

    wrong_purpose = {**lease_body, "purpose": "static_analysis"}
    purpose_envelope = EnvelopeV1.create("verification_lease", wrong_purpose)
    with pytest.raises(VerificationError) as purpose:
        VerificationLeaseV1.from_envelope(purpose_envelope)
    assert purpose.value.reason_code == "wrong_lease_purpose"

    analysis_envelope = EnvelopeV1.create("analysis_lease", lease_body)
    with pytest.raises(VerificationError) as wrong_kind:
        VerificationLeaseV1.from_envelope(analysis_envelope)
    assert wrong_kind.value.reason_code == "wrong_object_kind"


def test_noncanonical_or_duplicate_evidence_lists_and_invalid_nonce_fail(
    signer: VerifierSigner,
) -> None:
    with pytest.raises(VerificationError) as duplicate:
        issue_lease(signer, evidence_artifact_digests=(digest("6"), digest("6")))
    assert duplicate.value.reason_code == "duplicate_evidence_artifact"

    with pytest.raises(VerificationError) as order:
        issue_lease(signer, evidence_artifact_digests=tuple(reversed(EVIDENCE_DIGESTS)))
    assert order.value.reason_code == "noncanonical_evidence_order"

    with pytest.raises(VerificationError) as nonce:
        issue_lease(signer, lease_nonce="not-random")
    assert nonce.value.reason_code == "invalid_lease_nonce"


def test_receipt_and_key_revocations_are_full_content_ids(signer: VerifierSigner) -> None:
    with pytest.raises(VerificationError) as invalid_receipt:
        trusted_store(signer, revoked_receipt_ids=("short",))
    assert invalid_receipt.value.reason_code == "invalid_trust_store"

    with pytest.raises(VerificationError) as invalid_key:
        trusted_store(signer, revoked_key_ids=("ed25519:short",))
    assert invalid_key.value.reason_code == "invalid_trust_store"


def test_signer_refuses_receipt_assigned_to_another_key(signer: VerifierSigner) -> None:
    lease = issue_lease(signer)
    other = VerifierSigner.generate()
    receipt = issue_receipt(lease, verifier_key_id=other.key_id)

    with pytest.raises(VerificationError) as caught:
        signer.sign(receipt)

    assert caught.value.reason_code == "signer_key_mismatch"
