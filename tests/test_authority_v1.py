from __future__ import annotations

import base64
from dataclasses import FrozenInstanceError, replace

import pytest
from cryptography.exceptions import InvalidSignature

import etzio.authority as authority
from etzio.authority import (
    MAX_BYTES_HARD_CEILING,
    MAX_CANDIDATES_HARD_CEILING,
    MAX_WALLCLOCK_SECONDS_HARD_CEILING,
    AdmissionDecision,
    AuthorityAdmissionV1,
    AuthorityError,
    AuthorityGrantV1,
    AuthoritySigner,
    SignedAuthorityGrantV1,
    TrustedAuthorityKey,
    TrustStore,
    admit_authority,
)
from etzio.protocol import EnvelopeV1, canonical_dumps, content_id, strict_loads, thaw_json

NOW = 2_000_000_000
TARGET_ID = "sha256:" + "1" * 64
OTHER_TARGET_ID = "sha256:" + "2" * 64
EVIDENCE_ID = "sha256:" + "3" * 64


def grant_values(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "issuer": "operator:daniel",
        "subject": "benchmark:fixture-v1",
        "target_snapshot_id": TARGET_ID,
        "assets": ("fixture://vulnerable_app.py",),
        "permitted_actions": ("modeled_fixture_verification", "static_analysis"),
        "evidence_digest": EVIDENCE_ID,
        "issued_at": NOW - 10,
        "not_before": NOW,
        "expires_at": NOW + 300,
        "max_bytes": 1_000_000,
        "max_candidates": 100,
        "max_wallclock_seconds": 60,
    }
    values.update(overrides)
    return values


def issue_grant(**overrides: object) -> AuthorityGrantV1:
    return AuthorityGrantV1.issue(**grant_values(**overrides))  # type: ignore[arg-type]


def trusted_store(
    signer: AuthoritySigner,
    *,
    roles: frozenset[str] = frozenset({"operator"}),
    revoked_key_ids: tuple[str, ...] = (),
    revoked_grant_ids: tuple[str, ...] = (),
) -> TrustStore:
    trusted_key = TrustedAuthorityKey(
        public_key_bytes=signer.public_key_bytes,
        roles=roles,
        issuers=frozenset({"operator:daniel"}),
    )
    return TrustStore.from_keys(
        (trusted_key,),
        revoked_key_ids=revoked_key_ids,
        revoked_grant_ids=revoked_grant_ids,
    )


def decide(
    signed: SignedAuthorityGrantV1 | dict[str, object],
    store: TrustStore,
    *,
    decision_time: int = NOW,
    expected_target_snapshot_id: str = TARGET_ID,
    required_actions: tuple[str, ...] = ("static_analysis",),
) -> AdmissionDecision:
    return admit_authority(
        signed,
        store,
        decision_time=decision_time,
        expected_target_snapshot_id=expected_target_snapshot_id,
        required_actions=required_actions,
    )


def sign_envelope_bytes(
    signer: AuthoritySigner,
    envelope_bytes: bytes,
    *,
    key_id: str | None = None,
) -> SignedAuthorityGrantV1:
    signature = signer.private_key.sign(authority._SIGNATURE_DOMAIN + envelope_bytes)
    return SignedAuthorityGrantV1(
        envelope_bytes=envelope_bytes,
        key_id=key_id or signer.key_id,
        signature_b64=base64.b64encode(signature).decode("ascii"),
    )


def sign_body(signer: AuthoritySigner, body: dict[str, object]) -> SignedAuthorityGrantV1:
    envelope = EnvelopeV1.create("authority_grant", body)
    return sign_envelope_bytes(signer, envelope.to_bytes())


def test_signed_grant_admits_at_exact_not_before_boundary() -> None:
    signer = AuthoritySigner.generate()
    grant = issue_grant()
    signed = signer.sign(grant)

    decision = decide(signed, trusted_store(signer))

    assert decision.accepted
    assert decision.authority_id == grant.grant_id
    assert decision.reason_code == "accepted"
    assert decision.key_id == signer.key_id
    assert decision.grant == grant
    assert decision.admission is not None
    assert AuthorityAdmissionV1.from_envelope(
        decision.admission.to_envelope()
    ) == decision.admission
    assert grant.grant_id == grant.to_envelope().object_id
    assert (
        signer.key_id
        == TrustedAuthorityKey(
            public_key_bytes=signer.public_key_bytes,
            roles=frozenset({"operator"}),
            issuers=frozenset({"operator:daniel"}),
        ).key_id
    )


def test_admission_record_revalidates_embedded_signature_scope_clock_and_trust() -> None:
    signer = AuthoritySigner.generate()
    decision = decide(signer.sign(issue_grant()), trusted_store(signer))
    assert decision.admission is not None
    admission = decision.admission

    with pytest.raises(AuthorityError, match="admission"):
        replace(admission, decision_time=NOW - 1)
    with pytest.raises(AuthorityError, match="admission"):
        replace(admission, signer_key_id=AuthoritySigner.generate().key_id)

    body = thaw_json(admission.to_envelope().body)
    body["trust_snapshot"]["keys"] = []
    body["trust_snapshot_id"] = content_id(
        "authority_trust_snapshot",
        body["trust_snapshot"],
    )
    forged = EnvelopeV1.create("authority_admission", body)
    with pytest.raises(AuthorityError, match="trusted"):
        AuthorityAdmissionV1.from_envelope(forged)


def test_grant_and_signed_object_have_only_the_v1_fields() -> None:
    assert tuple(AuthorityGrantV1.__dataclass_fields__) == (
        "grant_id",
        "issuer",
        "subject",
        "target_snapshot_id",
        "assets",
        "permitted_actions",
        "evidence_digest",
        "issued_at",
        "not_before",
        "expires_at",
        "max_bytes",
        "max_candidates",
        "max_wallclock_seconds",
    )
    assert tuple(SignedAuthorityGrantV1.__dataclass_fields__) == (
        "envelope_bytes",
        "key_id",
        "signature_b64",
    )


def test_grant_id_cannot_be_detached_from_canonical_semantics() -> None:
    with pytest.raises(AuthorityError) as caught:
        AuthorityGrantV1(grant_id="sha256:" + "f" * 64, **grant_values())  # type: ignore[arg-type]
    assert caught.value.reason_code == "object_id_mismatch"


def test_signature_is_domain_separated_and_covers_canonical_envelope_bytes() -> None:
    signer = AuthoritySigner.generate()
    signed = signer.sign(issue_grant())
    public_key = signer.private_key.public_key()
    signature = base64.b64decode(signed.signature_b64, validate=True)

    public_key.verify(signature, authority._SIGNATURE_DOMAIN + signed.envelope_bytes)
    with pytest.raises(InvalidSignature):
        public_key.verify(signature, signed.envelope_bytes)
    assert signed.envelope_bytes == canonical_dumps(strict_loads(signed.envelope_bytes))


def test_signed_grant_has_one_canonical_protocol_wire_representation() -> None:
    signer = AuthoritySigner.generate()
    signed = signer.sign(issue_grant())

    wire = signed.to_bytes()
    restored = SignedAuthorityGrantV1.from_bytes(wire)

    assert restored == signed
    assert restored.to_bytes() == wire
    assert decide(wire, trusted_store(signer)).accepted
    attested = EnvelopeV1.from_bytes(wire)
    assert attested.object_kind == "authority_grant"
    assert attested.object_id == EnvelopeV1.from_bytes(signed.envelope_bytes).object_id
    assert len(attested.attestations) == 1


def test_signed_grant_wire_producers_require_valid_grant_semantics() -> None:
    signer = AuthoritySigner.generate()
    signed = sign_body(signer, {"arbitrary": True})
    attested = EnvelopeV1.create(
        "authority_grant",
        {"arbitrary": True},
        attestations=[
            {
                "algorithm": "ed25519",
                "key_id": signed.key_id,
                "signature_b64": signed.signature_b64,
            }
        ],
    )

    with pytest.raises(AuthorityError) as emitted:
        signed.to_bytes()
    assert emitted.value.reason_code == "malformed_grant"
    with pytest.raises(AuthorityError) as parsed:
        SignedAuthorityGrantV1.from_bytes(attested.to_bytes())
    assert parsed.value.reason_code == "malformed_grant"

    empty_store = TrustStore.from_keys(())
    assert decide(signed, empty_store).reason_code == "unknown_key"
    assert decide(attested.to_bytes(), empty_store).reason_code == "unknown_key"
    store = trusted_store(signer)
    assert decide(signed, store).reason_code == "malformed_grant"
    assert decide(attested.to_bytes(), store).reason_code == "malformed_grant"


def test_signed_grant_wire_rejects_unknown_attestation_fields_and_noncanonical_bytes() -> None:
    signer = AuthoritySigner.generate()
    signed = signer.sign(issue_grant())
    envelope = signed.to_envelope()
    attestation = thaw_json(envelope.attestations[0])
    attestation["ambient_authority"] = True
    malformed = EnvelopeV1.create(
        "authority_grant",
        envelope.body,
        attestations=[attestation],
    )
    with pytest.raises(AuthorityError, match="unknown"):
        SignedAuthorityGrantV1.from_bytes(malformed.to_bytes())
    with pytest.raises(AuthorityError, match="invalid"):
        SignedAuthorityGrantV1.from_bytes(b" " + signed.to_bytes())


def test_unsigned_and_malformed_transport_objects_fail_closed() -> None:
    signer = AuthoritySigner.generate()
    store = trusted_store(signer)
    valid = signer.sign(issue_grant())

    assert decide({"issuer": "operator:daniel"}, store).reason_code == "unsigned_object"
    missing_signature = {"envelope_bytes": valid.envelope_bytes, "key_id": valid.key_id}
    assert decide(missing_signature, store).reason_code == "unsigned_object"
    assert decide({**dict(valid.as_raw()), "unknown": "field"}, store).reason_code == "malformed_signed_object"
    assert (
        decide(
            {
                "envelope_bytes": "not-bytes",
                "key_id": valid.key_id,
                "signature_b64": valid.signature_b64,
            },
            store,
        ).reason_code
        == "malformed_signed_object"
    )


def test_forged_signature_and_malformed_signature_are_distinct_refusals() -> None:
    trusted_signer = AuthoritySigner.generate()
    forger = AuthoritySigner.generate()
    signed = trusted_signer.sign(issue_grant())
    forged_signature = forger.private_key.sign(authority._SIGNATURE_DOMAIN + signed.envelope_bytes)
    forged = {
        **dict(signed.as_raw()),
        "signature_b64": base64.b64encode(forged_signature).decode("ascii"),
    }

    assert decide(forged, trusted_store(trusted_signer)).reason_code == "invalid_signature"
    assert (
        decide({**dict(signed.as_raw()), "signature_b64": "not base64!"}, trusted_store(trusted_signer)).reason_code
        == "malformed_signature"
    )


def test_unknown_revoked_and_non_operator_keys_fail_closed() -> None:
    signer = AuthoritySigner.generate()
    signed = signer.sign(issue_grant())

    assert decide(signed, TrustStore.from_keys(())).reason_code == "unknown_key"
    assert (
        decide(
            signed,
            trusted_store(signer, revoked_key_ids=(signer.key_id,)),
        ).reason_code
        == "key_revoked"
    )
    wrong_role = decide(signed, trusted_store(signer, roles=frozenset({"auditor"})))
    assert wrong_role.reason_code == "key_missing_operator_role"


def test_small_order_ed25519_trust_key_is_rejected_before_it_can_forge_authority() -> None:
    identity_encoding = b"\x01" + (b"\x00" * 31)

    with pytest.raises(AuthorityError) as caught:
        TrustedAuthorityKey(
            public_key_bytes=identity_encoding,
            roles=frozenset({"operator"}),
            issuers=frozenset({"operator:daniel"}),
        )

    assert caught.value.reason_code == "invalid_public_key"


def test_small_order_key_is_rejected_inside_historical_admission_snapshot() -> None:
    signer = AuthoritySigner.generate()
    decision = decide(signer.sign(issue_grant()), trusted_store(signer))
    assert decision.admission is not None
    body = thaw_json(decision.admission.to_envelope().body)
    identity_encoding = b"\x01" + (b"\x00" * 31)
    identity_key_id = authority.authority_key_id(identity_encoding)
    body["trust_snapshot"]["keys"][0]["public_key_b64"] = base64.b64encode(
        identity_encoding
    ).decode("ascii")
    body["trust_snapshot"]["keys"][0]["key_id"] = identity_key_id
    body["trust_snapshot_id"] = content_id(
        "authority_trust_snapshot",
        body["trust_snapshot"],
    )
    body["signer_key_id"] = identity_key_id

    with pytest.raises(AuthorityError, match="trust snapshot"):
        AuthorityAdmissionV1.from_envelope(
            EnvelopeV1.create("authority_admission", body)
        )


def test_trusted_signer_cannot_claim_an_unconfigured_issuer() -> None:
    signer = AuthoritySigner.generate()
    signed = signer.sign(issue_grant(issuer="operator:mallory"))

    assert decide(signed, trusted_store(signer)).reason_code == "issuer_not_allowed"


def test_revoked_grant_fails_after_successful_authentication() -> None:
    signer = AuthoritySigner.generate()
    grant = issue_grant()

    decision = decide(
        signer.sign(grant),
        trusted_store(signer, revoked_grant_ids=(grant.grant_id,)),
    )

    assert decision == AdmissionDecision(accepted=False, authority_id=None, reason_code="grant_revoked")


@pytest.mark.parametrize(
    ("decision_time", "reason"),
    [
        (NOW - 1, "not_yet_valid"),
        (NOW + 299, "accepted"),
        (NOW + 300, "expired"),
        (NOW + 301, "expired"),
    ],
)
def test_validity_window_is_half_open(decision_time: int, reason: str) -> None:
    signer = AuthoritySigner.generate()
    decision = decide(signer.sign(issue_grant()), trusted_store(signer), decision_time=decision_time)
    assert decision.reason_code == reason


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"issuer": ""}, "blank_issuer"),
        ({"subject": "   "}, "blank_subject"),
        ({"target_snapshot_id": ""}, "blank_target_snapshot_id"),
        ({"evidence_digest": ""}, "blank_evidence_digest"),
        ({"assets": ("asset:a", "asset:a")}, "duplicate_asset"),
        ({"permitted_actions": ("static_analysis", "static_analysis")}, "duplicate_action"),
        ({"permitted_actions": ("network_probe",)}, "unknown_action"),
        ({"issued_at": NOW + 1}, "invalid_time_window"),
        ({"not_before": NOW + 300}, "invalid_time_window"),
        ({"expires_at": NOW}, "invalid_time_window"),
    ],
)
def test_invalid_grant_semantics_are_rejected_before_signing(
    overrides: dict[str, object],
    reason: str,
) -> None:
    with pytest.raises(AuthorityError) as caught:
        issue_grant(**overrides)
    assert caught.value.reason_code == reason


@pytest.mark.parametrize("field", ["max_bytes", "max_candidates", "max_wallclock_seconds"])
@pytest.mark.parametrize("value", [-1, 1.5, True])
def test_negative_float_and_boolean_budgets_are_rejected(field: str, value: object) -> None:
    with pytest.raises(AuthorityError) as caught:
        issue_grant(**{field: value})
    assert caught.value.reason_code == "invalid_budget"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_bytes", MAX_BYTES_HARD_CEILING + 1),
        ("max_candidates", MAX_CANDIDATES_HARD_CEILING + 1),
        ("max_wallclock_seconds", MAX_WALLCLOCK_SECONDS_HARD_CEILING + 1),
    ],
)
def test_every_signed_budget_has_a_fixed_hard_ceiling(field: str, value: int) -> None:
    with pytest.raises(AuthorityError) as caught:
        issue_grant(**{field: value})
    assert caught.value.reason_code == "budget_exceeds_hard_ceiling"


def test_zero_budgets_and_exact_hard_ceilings_are_valid_boundaries() -> None:
    zero = issue_grant(max_bytes=0, max_candidates=0, max_wallclock_seconds=0)
    exact = issue_grant(
        max_bytes=MAX_BYTES_HARD_CEILING,
        max_candidates=MAX_CANDIDATES_HARD_CEILING,
        max_wallclock_seconds=MAX_WALLCLOCK_SECONDS_HARD_CEILING,
    )
    assert zero.max_bytes == 0
    assert exact.max_wallclock_seconds == MAX_WALLCLOCK_SECONDS_HARD_CEILING


def test_wrong_target_and_missing_action_have_precise_refusal_codes() -> None:
    signer = AuthoritySigner.generate()
    store = trusted_store(signer)
    static_only = issue_grant(permitted_actions=("static_analysis",))
    signed = signer.sign(static_only)

    assert decide(signed, store, expected_target_snapshot_id=OTHER_TARGET_ID).reason_code == "target_mismatch"
    assert (
        decide(signed, store, required_actions=("modeled_fixture_verification",)).reason_code
        == "missing_required_action"
    )


def test_invalid_caller_decision_inputs_fail_closed() -> None:
    signer = AuthoritySigner.generate()
    signed = signer.sign(issue_grant())
    store = trusted_store(signer)

    assert decide(signed, store, decision_time=True).reason_code == "invalid_decision_time"
    assert decide(signed, store, expected_target_snapshot_id="").reason_code == "invalid_expected_target"
    assert decide(signed, store, required_actions=("unknown",)).reason_code == "invalid_required_actions"
    assert (
        decide(signed, store, required_actions=("static_analysis", "static_analysis")).reason_code
        == "invalid_required_actions"
    )


def test_unknown_grant_fields_are_refused_even_with_a_valid_operator_signature() -> None:
    signer = AuthoritySigner.generate()
    body = thaw_json(issue_grant().to_envelope().body)
    body["ambient_credentials"] = True
    signed = sign_body(signer, body)

    assert decide(signed, trusted_store(signer)).reason_code == "malformed_grant"


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"evidence_digest": ""}, "blank_evidence_digest"),
        ({"assets": ["fixture://a", "fixture://a"]}, "duplicate_asset"),
        ({"permitted_actions": ["network_probe"]}, "unknown_action"),
        ({"max_bytes": -1}, "invalid_budget"),
        ({"max_bytes": MAX_BYTES_HARD_CEILING + 1}, "budget_exceeds_hard_ceiling"),
    ],
)
def test_operator_signature_cannot_bypass_grant_semantics(
    change: dict[str, object],
    reason: str,
) -> None:
    signer = AuthoritySigner.generate()
    body = thaw_json(issue_grant().to_envelope().body)
    body.update(change)
    assert decide(sign_body(signer, body), trusted_store(signer)).reason_code == reason


def test_malformed_envelope_is_refused_even_when_signed_by_a_trusted_operator() -> None:
    signer = AuthoritySigner.generate()
    signed = sign_envelope_bytes(signer, b'{"not":"an envelope"}')
    assert decide(signed, trusted_store(signer)).reason_code == "invalid_envelope"


def test_noncanonical_envelope_bytes_are_refused_even_when_validly_signed() -> None:
    signer = AuthoritySigner.generate()
    canonical = signer.sign(issue_grant()).envelope_bytes
    signed = sign_envelope_bytes(signer, b" " + canonical)
    assert decide(signed, trusted_store(signer)).reason_code == "noncanonical_envelope"


def test_body_and_object_id_tampering_are_detected_after_valid_resigning() -> None:
    signer = AuthoritySigner.generate()
    valid = signer.sign(issue_grant())
    wire = strict_loads(valid.envelope_bytes)
    wire["body"]["subject"] = "benchmark:substituted"
    tampered_body = sign_envelope_bytes(signer, canonical_dumps(wire))
    assert decide(tampered_body, trusted_store(signer)).reason_code == "object_id_mismatch"

    wire = strict_loads(valid.envelope_bytes)
    wire["object_id"] = "sha256:" + "f" * 64
    tampered_id = sign_envelope_bytes(signer, canonical_dumps(wire))
    assert decide(tampered_id, trusted_store(signer)).reason_code == "object_id_mismatch"


def test_envelope_or_signature_byte_tampering_never_admits() -> None:
    signer = AuthoritySigner.generate()
    valid = signer.sign(issue_grant())
    store = trusted_store(signer)

    changed_envelope = {
        **dict(valid.as_raw()),
        "envelope_bytes": valid.envelope_bytes.replace(b"operator:daniel", b"operator:mallory"),
    }
    assert decide(changed_envelope, store).reason_code == "invalid_signature"

    signature = bytearray(base64.b64decode(valid.signature_b64))
    signature[0] ^= 1
    changed_signature = {
        **dict(valid.as_raw()),
        "signature_b64": base64.b64encode(signature).decode("ascii"),
    }
    assert decide(changed_signature, store).reason_code == "invalid_signature"


def test_trust_store_and_decisions_are_immutable_snapshots() -> None:
    signer = AuthoritySigner.generate()
    trusted_key = TrustedAuthorityKey(
        signer.public_key_bytes,
        frozenset({"operator"}),
        frozenset({"operator:daniel"}),
    )
    mutable_keys = {trusted_key.key_id: trusted_key}
    store = TrustStore(keys=mutable_keys)
    mutable_keys.clear()

    assert trusted_key.key_id in store.keys
    with pytest.raises(TypeError):
        store.keys[trusted_key.key_id] = trusted_key  # type: ignore[index]
    decision = decide(signer.sign(issue_grant()), store)
    with pytest.raises(FrozenInstanceError):
        decision.accepted = False  # type: ignore[misc]


def test_trust_store_rejects_non_content_derived_key_aliases() -> None:
    signer = AuthoritySigner.generate()
    trusted_key = TrustedAuthorityKey(
        signer.public_key_bytes,
        frozenset({"operator"}),
        frozenset({"operator:daniel"}),
    )
    alias = "ed25519:sha256:" + "f" * 64
    with pytest.raises(AuthorityError) as caught:
        TrustStore(keys={alias: trusted_key})
    assert caught.value.reason_code == "invalid_trust_store"


def test_signature_does_not_change_grant_identity() -> None:
    grant = issue_grant()
    first = AuthoritySigner.generate().sign(grant)
    second = AuthoritySigner.generate().sign(grant)

    assert EnvelopeV1.from_bytes(first.envelope_bytes).object_id == grant.grant_id
    assert EnvelopeV1.from_bytes(second.envelope_bytes).object_id == grant.grant_id
    assert first.key_id != second.key_id
