from __future__ import annotations

import base64
import tempfile
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

import etzio.verification as verification
from etzio.evidence import (
    VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1,
    VERIFICATION_OUTPUT_ARTIFACT_TYPE_BY_ROLE_V1,
    FileEvidenceStore,
    SnapshotFileV1,
    TargetSnapshotV1,
    evidence_digest,
    read_etzio_fixture,
    typed_evidence_digest,
)
from etzio.protocol import EnvelopeV1, canonical_dumps, strict_loads, thaw_json
from etzio.verification import (
    MAX_TYPED_VERIFICATION_OUTPUT_BYTES_V1,
    MODELED_FIXTURE_TIER,
    VERIFIER_ROLE,
    AuthenticatedVerifierReceiptV1,
    SignedVerifierReceiptV1,
    TrustedVerifierKey,
    VerificationError,
    VerificationLeaseV1,
    VerificationOutputArtifactsV1,
    VerificationProposal,
    VerifierReceiptV1,
    VerifierSigner,
    VerifierTrustStore,
    authenticate_verifier_receipt,
    revalidate_verifier_receipt_artifacts,
    validate_verifier_receipt,
)
from etzio.verification_artifacts import (
    TARGET_ARTIFACT_TYPE_V1,
    TargetArtifactBindingV1,
    VerificationArtifactBindingV1,
    VerificationArtifactResolutionV1,
)

NOW = 2_000_000_000


def digest(character: str) -> str:
    return "sha256:" + character * 64


MISSION_ID = digest("1")
AUTHORITY_ID = digest("2")
CANDIDATE_ID = digest("4")
PRODUCER_ID = "VELITES"
VERIFIER_ID = "CATO"

TARGET_PATH, TARGET_BYTES = read_etzio_fixture(
    "vulnerable_app.py",
    maximum=1024 * 1024,
)
TARGET_FILE = SnapshotFileV1(
    relative_path=TARGET_PATH,
    artifact_digest=evidence_digest(TARGET_BYTES),
    size=len(TARGET_BYTES),
)
TARGET_SNAPSHOT = TargetSnapshotV1.create(
    "repository_fixture",
    (TARGET_FILE,),
)
TARGET_ID = TARGET_SNAPSHOT.object_id

POC_BYTES = b"modeled fixture poc input"
ENVIRONMENT_BYTES = b"modeled fixture environment specification"
ORACLE_BYTES = b"modeled fixture effect oracle specification"
EVIDENCE_BYTES = (
    b"modeled fixture supporting evidence alpha",
    b"modeled fixture supporting evidence beta",
)
OUTPUT_BYTES_BY_ROLE = {
    "execution_output": b"modeled verifier execution output",
    "effect_output": b"modeled verifier effect output",
    "measured_environment_output": b"modeled measured-environment output",
    "termination_output": b"modeled verifier termination output",
}
OUTPUT_DIGEST_BY_ROLE = {
    role: typed_evidence_digest(
        data,
        artifact_type=VERIFICATION_OUTPUT_ARTIFACT_TYPE_BY_ROLE_V1[role],
    )
    for role, data in OUTPUT_BYTES_BY_ROLE.items()
}
OUTPUT_SIZE_BY_ROLE = {
    role: len(data)
    for role, data in OUTPUT_BYTES_BY_ROLE.items()
}
POC_DIGEST = typed_evidence_digest(
    POC_BYTES,
    artifact_type=VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["poc"],
)
ENVIRONMENT_DIGEST = typed_evidence_digest(
    ENVIRONMENT_BYTES,
    artifact_type=VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["environment"],
)
ORACLE_ID = typed_evidence_digest(
    ORACLE_BYTES,
    artifact_type=VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["effect_oracle"],
)
_EVIDENCE_BY_DIGEST = {
    typed_evidence_digest(
        data,
        artifact_type=VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["evidence"],
    ): data
    for data in EVIDENCE_BYTES
}
EVIDENCE_DIGESTS = tuple(sorted(_EVIDENCE_BY_DIGEST))
_TYPED_BYTES_BY_DIGEST = {
    POC_DIGEST: POC_BYTES,
    ENVIRONMENT_DIGEST: ENVIRONMENT_BYTES,
    ORACLE_ID: ORACLE_BYTES,
    **_EVIDENCE_BY_DIGEST,
}


def expected_output_artifacts() -> VerificationOutputArtifactsV1:
    def binding(role: str) -> VerificationArtifactBindingV1:
        return VerificationArtifactBindingV1(
            artifact_digest=OUTPUT_DIGEST_BY_ROLE[role],
            artifact_type=VERIFICATION_OUTPUT_ARTIFACT_TYPE_BY_ROLE_V1[role],
            size=OUTPUT_SIZE_BY_ROLE[role],
        )

    return VerificationOutputArtifactsV1(
        execution_output_artifact=binding("execution_output"),
        effect_output_artifact=binding("effect_output"),
        measured_environment_output_artifact=binding("measured_environment_output"),
        termination_output_artifact=binding("termination_output"),
    )


def install_raw_cas_file(
    store: FileEvidenceStore,
    artifact_digest: str,
    *,
    size: int,
) -> None:
    hexadecimal = artifact_digest.removeprefix("sha256:")
    shard = store.root / hexadecimal[:2]
    shard.mkdir(mode=0o700, exist_ok=True)
    shard.chmod(0o700)
    artifact = shard / hexadecimal[2:]
    artifact.touch(mode=0o600)
    artifact.chmod(0o600)
    with artifact.open("r+b") as stream:
        stream.truncate(size)


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
        "issuance_trust_snapshot_id": trusted_store(signer).snapshot_id,
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
        "artifact_resolution_id": resolution_for_lease(lease).resolution_id,
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
        "execution_output_digest": OUTPUT_DIGEST_BY_ROLE["execution_output"],
        "execution_output_size": OUTPUT_SIZE_BY_ROLE["execution_output"],
        "effect_output_digest": OUTPUT_DIGEST_BY_ROLE["effect_output"],
        "effect_output_size": OUTPUT_SIZE_BY_ROLE["effect_output"],
        "measured_environment_output_digest": OUTPUT_DIGEST_BY_ROLE["measured_environment_output"],
        "measured_environment_output_size": OUTPUT_SIZE_BY_ROLE[
            "measured_environment_output"
        ],
        "termination_output_digest": OUTPUT_DIGEST_BY_ROLE["termination_output"],
        "termination_output_size": OUTPUT_SIZE_BY_ROLE["termination_output"],
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


def resolution_for_lease(
    lease: VerificationLeaseV1,
    **overrides: object,
) -> VerificationArtifactResolutionV1:
    def binding(digest_value: str, role: str) -> VerificationArtifactBindingV1:
        retained = _TYPED_BYTES_BY_DIGEST.get(digest_value)
        return VerificationArtifactBindingV1(
            artifact_digest=digest_value,
            artifact_type=VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1[role],
            size=1 if retained is None else len(retained),
        )

    values: dict[str, object] = {
        "authority_id": lease.authority_id,
        "candidate_id": lease.candidate_id,
        "effect_oracle_artifact": binding(
            lease.effect_oracle_id,
            "effect_oracle",
        ),
        "environment_artifact": binding(
            lease.environment_digest,
            "environment",
        ),
        "evidence_artifacts": tuple(binding(value, "evidence") for value in lease.evidence_artifact_digests),
        "mission_id": lease.mission_id,
        "poc_artifact": binding(lease.poc_artifact_digest, "poc"),
        "resolved_at": NOW,
        "target_artifacts": (
            TargetArtifactBindingV1(
                artifact_digest=TARGET_FILE.artifact_digest,
                artifact_type=TARGET_ARTIFACT_TYPE_V1,
                relative_path=TARGET_FILE.relative_path,
                size=TARGET_FILE.size,
            ),
        ),
        "target_snapshot_id": lease.target_snapshot_id,
        "verification_lease_id": lease.lease_id,
    }
    values.update(overrides)
    return VerificationArtifactResolutionV1.issue(**values)  # type: ignore[arg-type]


def populate_resolution_bytes(
    store: FileEvidenceStore,
    lease: VerificationLeaseV1,
    *,
    omitted_digests: frozenset[str] = frozenset(),
) -> None:
    if TARGET_FILE.artifact_digest not in omitted_digests:
        assert store.put(TARGET_BYTES).digest == TARGET_FILE.artifact_digest
    typed_roles = (
        ("poc", lease.poc_artifact_digest),
        *(("evidence", value) for value in lease.evidence_artifact_digests),
        ("environment", lease.environment_digest),
        ("effect_oracle", lease.effect_oracle_id),
    )
    for role, digest_value in typed_roles:
        data = _TYPED_BYTES_BY_DIGEST.get(digest_value)
        if data is None or digest_value in omitted_digests:
            continue
        receipt = store.put_typed(
            data,
            artifact_type=VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1[role],
        )
        assert receipt.digest == digest_value
    for role in (
        "execution_output",
        "effect_output",
        "measured_environment_output",
        "termination_output",
    ):
        digest_value = OUTPUT_DIGEST_BY_ROLE[role]
        if digest_value in omitted_digests:
            continue
        receipt = store.put_typed(
            OUTPUT_BYTES_BY_ROLE[role],
            artifact_type=VERIFICATION_OUTPUT_ARTIFACT_TYPE_BY_ROLE_V1[role],
        )
        assert receipt.digest == digest_value


def decide(
    signed: SignedVerifierReceiptV1 | dict[str, object] | bytes | str,
    store: VerifierTrustStore,
    lease: VerificationLeaseV1,
    *,
    decision_time: int = NOW + 11,
    expected_verdict: str = "confirmed",
    consumed_lease_ids: frozenset[str] = frozenset(),
    artifact_resolution: VerificationArtifactResolutionV1 | None = None,
    target_snapshot: TargetSnapshotV1 = TARGET_SNAPSHOT,
    evidence_store: FileEvidenceStore | None = None,
    omitted_digests: frozenset[str] = frozenset(),
    maximum_output_bytes: int = MAX_TYPED_VERIFICATION_OUTPUT_BYTES_V1,
) -> VerificationProposal:
    def run(local_store: FileEvidenceStore) -> VerificationProposal:
        populate_resolution_bytes(
            local_store,
            lease,
            omitted_digests=omitted_digests,
        )
        return validate_verifier_receipt(
            signed,
            store,
            lease=lease,
            decision_time=decision_time,
            expected_verdict=expected_verdict,
            consumed_lease_ids=consumed_lease_ids,
            artifact_resolution=(resolution_for_lease(lease) if artifact_resolution is None else artifact_resolution),
            target_snapshot=target_snapshot,
            evidence_store=local_store,
            maximum_output_bytes=maximum_output_bytes,
        )

    if evidence_store is not None:
        return run(evidence_store)
    with tempfile.TemporaryDirectory() as temporary:
        return run(FileEvidenceStore(temporary))


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


def test_valid_receipt_produces_a_context_bound_proposal_and_no_finding(
    signer: VerifierSigner,
) -> None:
    lease = issue_lease(signer)
    resolution = resolution_for_lease(lease)
    receipt = VerifierReceiptV1.for_lease(
        lease,
        artifact_resolution_id=resolution.resolution_id,
        execution_output_digest=OUTPUT_DIGEST_BY_ROLE["execution_output"],
        execution_output_size=OUTPUT_SIZE_BY_ROLE["execution_output"],
        effect_output_digest=OUTPUT_DIGEST_BY_ROLE["effect_output"],
        effect_output_size=OUTPUT_SIZE_BY_ROLE["effect_output"],
        measured_environment_output_digest=OUTPUT_DIGEST_BY_ROLE["measured_environment_output"],
        measured_environment_output_size=OUTPUT_SIZE_BY_ROLE[
            "measured_environment_output"
        ],
        termination_output_digest=OUTPUT_DIGEST_BY_ROLE["termination_output"],
        termination_output_size=OUTPUT_SIZE_BY_ROLE["termination_output"],
        evidence_tier=MODELED_FIXTURE_TIER,
        verdict="confirmed",
        effect_observed=True,
        oracle_satisfied=True,
        completed_at=NOW + 10,
    )

    decision = decide(signer.sign(receipt), trusted_store(signer), lease)

    assert decision == VerificationProposal(
        eligible=True,
        lease_id=lease.lease_id,
        receipt_id=receipt.receipt_id,
        verdict="confirmed",
        reason_code="proposal_valid",
        issuance_trust_snapshot_id=lease.issuance_trust_snapshot_id,
        decision_trust_snapshot_id=trusted_store(signer).snapshot_id,
        artifact_resolution_id=resolution.resolution_id,
        output_artifacts=expected_output_artifacts(),
    )
    assert not hasattr(decision, "finding_id")
    assert lease.lease_id == lease.to_envelope().object_id
    assert receipt.receipt_id == receipt.to_envelope().object_id
    assert signer.sign(receipt).envelope_bytes == canonical_dumps(strict_loads(signer.sign(receipt).envelope_bytes))


def test_pure_authentication_binds_resolution_and_outputs_without_cas(
    signer: VerifierSigner,
) -> None:
    lease = issue_lease(signer)
    resolution = resolution_for_lease(lease)
    receipt = issue_receipt(lease)

    authenticated = authenticate_verifier_receipt(
        signer.sign(receipt),
        trusted_store(signer),
        lease=lease,
        artifact_resolution=resolution,
        decision_time=NOW + 10,
        expected_verdict=None,
    )

    assert authenticated == AuthenticatedVerifierReceiptV1(
        signed_receipt=signer.sign(receipt),
        receipt=receipt,
        lease=lease,
        artifact_resolution=resolution,
        decision_trust_snapshot_id=trusted_store(signer).snapshot_id,
    )
    assert authenticated.receipt.artifact_resolution_id == resolution.resolution_id
    assert authenticated.receipt.execution_output_digest == OUTPUT_DIGEST_BY_ROLE["execution_output"]
    assert authenticated.receipt.execution_output_size == OUTPUT_SIZE_BY_ROLE["execution_output"]


def test_authenticated_result_rejects_incoherent_direct_construction(
    signer: VerifierSigner,
) -> None:
    lease = issue_lease(signer)
    receipt = issue_receipt(lease)
    authenticated = authenticate_verifier_receipt(
        signer.sign(receipt),
        trusted_store(signer),
        lease=lease,
        artifact_resolution=resolution_for_lease(lease),
        decision_time=NOW + 11,
    )
    alternate = issue_receipt(
        lease,
        execution_output_digest=digest("a"),
    )

    with pytest.raises(VerificationError) as caught:
        replace(authenticated, receipt=alternate)

    assert caught.value.reason_code == "invalid_authenticated_receipt"


def test_receipt_output_roles_are_required_unique_and_disjoint_from_inputs(
    signer: VerifierSigner,
) -> None:
    lease = issue_lease(signer)

    with pytest.raises(VerificationError) as duplicate:
        issue_receipt(
            lease,
            execution_output_digest=OUTPUT_DIGEST_BY_ROLE["effect_output"],
        )
    assert duplicate.value.reason_code == "output_artifact_role_collision"

    with pytest.raises(VerificationError) as input_alias:
        issue_receipt(
            lease,
            execution_output_digest=lease.poc_artifact_digest,
        )
    assert input_alias.value.reason_code == "output_input_artifact_collision"

    body = receipt_values(lease)
    body.pop("termination_output_digest")
    with pytest.raises(VerificationError) as missing:
        VerifierReceiptV1.from_envelope(
            EnvelopeV1.create(
                "verifier_receipt",
                {
                    **body,
                    "evidence_artifact_digests": list(lease.evidence_artifact_digests),
                },
            )
        )
    assert missing.value.reason_code == "malformed_receipt"

    missing_size_body = receipt_values(lease)
    missing_size_body.pop("termination_output_size")
    with pytest.raises(VerificationError) as missing_size:
        VerifierReceiptV1.from_envelope(
            EnvelopeV1.create(
                "verifier_receipt",
                {
                    **missing_size_body,
                    "evidence_artifact_digests": list(
                        lease.evidence_artifact_digests
                    ),
                },
            )
        )
    assert missing_size.value.reason_code == "malformed_receipt"


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        (0, "invalid_execution_output_size"),
        (True, "invalid_execution_output_size"),
        (
            MAX_TYPED_VERIFICATION_OUTPUT_BYTES_V1 + 1,
            "invalid_execution_output_size",
        ),
    ],
)
def test_signed_output_sizes_are_strict_positive_bounded_integers(
    signer: VerifierSigner,
    value: object,
    reason: str,
) -> None:
    lease = issue_lease(signer)

    with pytest.raises(VerificationError) as caught:
        issue_receipt(
            lease,
            execution_output_size=value,
        )

    assert caught.value.reason_code == reason


def test_authentication_rejects_a_signed_invalid_output_size(
    signer: VerifierSigner,
) -> None:
    lease = issue_lease(signer)
    body = receipt_values(lease)
    body["execution_output_size"] = False
    body["evidence_artifact_digests"] = list(lease.evidence_artifact_digests)
    signed = sign_envelope(
        signer,
        EnvelopeV1.create("verifier_receipt", body),
    )

    with pytest.raises(VerificationError) as caught:
        authenticate_verifier_receipt(
            signed,
            trusted_store(signer),
            lease=lease,
            artifact_resolution=resolution_for_lease(lease),
            decision_time=NOW + 11,
        )

    assert caught.value.reason_code == "invalid_execution_output_size"


def test_signed_output_size_aggregate_has_one_64_mib_ceiling(
    signer: VerifierSigner,
) -> None:
    lease = issue_lease(signer)
    per_role = (MAX_TYPED_VERIFICATION_OUTPUT_BYTES_V1 // 4) + 1

    with pytest.raises(VerificationError) as caught:
        issue_receipt(
            lease,
            execution_output_size=per_role,
            effect_output_size=per_role,
            measured_environment_output_size=per_role,
            termination_output_size=per_role,
        )

    assert caught.value.reason_code == "verification_output_byte_ceiling_exceeded"


def test_signed_output_digest_may_not_alias_a_resolved_target_artifact(
    signer: VerifierSigner,
) -> None:
    lease = issue_lease(signer)
    receipt = issue_receipt(
        lease,
        execution_output_digest=TARGET_FILE.artifact_digest,
    )

    with pytest.raises(VerificationError) as caught:
        authenticate_verifier_receipt(
            signer.sign(receipt),
            trusted_store(signer),
            lease=lease,
            artifact_resolution=resolution_for_lease(lease),
            decision_time=NOW + 11,
        )

    assert caught.value.reason_code == "output_resolution_artifact_collision"


@pytest.mark.parametrize(
    ("role", "reason"),
    [
        (
            "execution_output",
            "resolved_execution_output_artifact_unavailable",
        ),
        ("effect_output", "resolved_effect_output_artifact_unavailable"),
        (
            "measured_environment_output",
            "resolved_measured_environment_output_artifact_unavailable",
        ),
        (
            "termination_output",
            "resolved_termination_output_artifact_unavailable",
        ),
    ],
)
def test_every_signed_output_digest_must_resolve_under_its_code_owned_type(
    signer: VerifierSigner,
    role: str,
    reason: str,
) -> None:
    lease = issue_lease(signer)

    decision = decide(
        signer.sign(issue_receipt(lease)),
        trusted_store(signer),
        lease,
        omitted_digests=frozenset({OUTPUT_DIGEST_BY_ROLE[role]}),
    )

    assert decision.reason_code == reason


def test_swapped_signed_output_roles_fail_the_typed_cas_domain(
    signer: VerifierSigner,
) -> None:
    lease = issue_lease(signer)
    receipt = issue_receipt(
        lease,
        execution_output_digest=OUTPUT_DIGEST_BY_ROLE["effect_output"],
        effect_output_digest=OUTPUT_DIGEST_BY_ROLE["execution_output"],
    )

    decision = decide(
        signer.sign(receipt),
        trusted_store(signer),
        lease,
    )

    assert decision.reason_code == "resolved_execution_output_artifact_unavailable"


def test_output_resolution_uses_fixed_role_order_and_exact_derived_bindings(
    signer: VerifierSigner,
    tmp_path: Path,
) -> None:
    class OrderedStore(FileEvidenceStore):
        def __init__(self, root: str) -> None:
            super().__init__(root)
            self.typed_reads: list[str] = []

        def get_typed(
            self,
            digest_value: str,
            *,
            expected_type: str,
            maximum: int | None = None,
        ) -> bytes:
            self.typed_reads.append(expected_type)
            return super().get_typed(
                digest_value,
                expected_type=expected_type,
                maximum=maximum,
            )

    lease = issue_lease(signer)
    store = OrderedStore(str(tmp_path))
    receipt = issue_receipt(lease)
    populate_resolution_bytes(store, lease)
    authenticated = authenticate_verifier_receipt(
        signer.sign(receipt),
        trusted_store(signer),
        lease=lease,
        artifact_resolution=resolution_for_lease(lease),
        decision_time=NOW + 11,
        expected_verdict=None,
    )
    output_artifacts = revalidate_verifier_receipt_artifacts(
        authenticated,
        target_snapshot=TARGET_SNAPSHOT,
        evidence_store=store,
    )

    assert output_artifacts == expected_output_artifacts()
    assert store.typed_reads[-4:] == [
        VERIFICATION_OUTPUT_ARTIFACT_TYPE_BY_ROLE_V1["execution_output"],
        VERIFICATION_OUTPUT_ARTIFACT_TYPE_BY_ROLE_V1["effect_output"],
        VERIFICATION_OUTPUT_ARTIFACT_TYPE_BY_ROLE_V1["measured_environment_output"],
        VERIFICATION_OUTPUT_ARTIFACT_TYPE_BY_ROLE_V1["termination_output"],
    ]


def test_output_aggregate_uses_one_nonresetting_byte_allowance(
    signer: VerifierSigner,
) -> None:
    lease = issue_lease(signer)
    total = sum(len(value) for value in OUTPUT_BYTES_BY_ROLE.values())

    decision = decide(
        signer.sign(issue_receipt(lease)),
        trusted_store(signer),
        lease,
        maximum_output_bytes=total - 1,
    )

    assert decision.reason_code == "verification_output_byte_ceiling_exceeded"


@pytest.mark.parametrize(
    "signed_size",
    [
        OUTPUT_SIZE_BY_ROLE["execution_output"] - 1,
        OUTPUT_SIZE_BY_ROLE["execution_output"] + 1,
    ],
)
def test_cas_output_size_must_exactly_equal_the_signed_size(
    signer: VerifierSigner,
    signed_size: int,
) -> None:
    lease = issue_lease(signer)

    decision = decide(
        signer.sign(
            issue_receipt(
                lease,
                execution_output_size=signed_size,
            )
        ),
        trusted_store(signer),
        lease,
    )

    assert decision.reason_code == "resolved_execution_output_artifact_size_mismatch"


def test_empty_signed_output_cannot_become_a_positive_binding(
    signer: VerifierSigner,
    tmp_path: Path,
) -> None:
    lease = issue_lease(signer)
    store = FileEvidenceStore(tmp_path)
    empty_output_digest = typed_evidence_digest(
        b"",
        artifact_type=VERIFICATION_OUTPUT_ARTIFACT_TYPE_BY_ROLE_V1[
            "execution_output"
        ],
    )
    install_raw_cas_file(store, empty_output_digest, size=0)

    decision = decide(
        signer.sign(
            issue_receipt(
                lease,
                execution_output_digest=empty_output_digest,
            )
        ),
        trusted_store(signer),
        lease,
        evidence_store=store,
    )

    assert decision.reason_code == "resolved_execution_output_artifact_size_mismatch"


def test_single_signed_output_cannot_exceed_the_fixed_64_mib_ceiling(
    signer: VerifierSigner,
) -> None:
    lease = issue_lease(signer)

    with pytest.raises(VerificationError) as caught:
        issue_receipt(
            lease,
            execution_output_size=MAX_TYPED_VERIFICATION_OUTPUT_BYTES_V1 + 1,
        )

    assert caught.value.reason_code == "invalid_execution_output_size"


def test_one_signed_receipt_binds_exactly_one_resolution_context(
    signer: VerifierSigner,
) -> None:
    lease = issue_lease(signer)
    signed = signer.sign(issue_receipt(lease))
    first = decide(
        signed,
        trusted_store(signer),
        lease,
        artifact_resolution=resolution_for_lease(
            lease,
            resolved_at=NOW,
        ),
    )
    second = decide(
        signed,
        trusted_store(signer),
        lease,
        artifact_resolution=resolution_for_lease(
            lease,
            resolved_at=NOW + 1,
        ),
    )

    assert first.eligible
    assert second.reason_code == "artifact_resolution_mismatch"
    assert not hasattr(first, "accepted")


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"verification_lease_id": digest("a")}, "resolution_lease_mismatch"),
        ({"mission_id": digest("a")}, "resolution_mission_mismatch"),
        ({"authority_id": digest("a")}, "resolution_authority_mismatch"),
        ({"target_snapshot_id": digest("a")}, "resolution_target_mismatch"),
        ({"candidate_id": digest("a")}, "resolution_candidate_mismatch"),
        ({"resolved_at": NOW - 1}, "resolution_before_lease"),
        ({"resolved_at": NOW + 100}, "resolution_after_expiry"),
    ],
)
def test_modeled_receipt_requires_the_exact_lease_resolution(
    signer: VerifierSigner,
    overrides: dict[str, object],
    reason: str,
) -> None:
    lease = issue_lease(signer)
    resolution = resolution_for_lease(lease, **overrides)

    decision = decide(
        signer.sign(
            issue_receipt(
                lease,
                artifact_resolution_id=resolution.resolution_id,
            )
        ),
        trusted_store(signer),
        lease,
        artifact_resolution=resolution,
    )

    assert decision.reason_code == reason


@pytest.mark.parametrize("resolved_at", (NOW + 1, NOW + 2))
def test_resolution_must_strictly_precede_receipt_completion(
    signer: VerifierSigner,
    resolved_at: int,
) -> None:
    lease = issue_lease(signer)
    resolution = resolution_for_lease(lease, resolved_at=resolved_at)
    receipt = issue_receipt(
        lease,
        artifact_resolution_id=resolution.resolution_id,
        completed_at=NOW + 1,
    )

    decision = decide(
        signer.sign(receipt),
        trusted_store(signer),
        lease,
        artifact_resolution=resolution,
        decision_time=NOW + 3,
    )

    assert decision.reason_code == "resolution_after_receipt"


def test_resolution_artifact_and_target_substitution_fail_before_positive_proposal(
    signer: VerifierSigner,
) -> None:
    lease = issue_lease(signer)
    wrong_poc = VerificationArtifactBindingV1(
        artifact_digest=digest("a"),
        artifact_type=VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["poc"],
        size=1,
    )
    wrong_target = TargetArtifactBindingV1(
        artifact_digest=digest("b"),
        artifact_type=TARGET_ARTIFACT_TYPE_V1,
        relative_path=TARGET_FILE.relative_path,
        size=TARGET_FILE.size,
    )
    wrong_poc_resolution = resolution_for_lease(
        lease,
        poc_artifact=wrong_poc,
    )
    wrong_target_resolution = resolution_for_lease(
        lease,
        target_artifacts=(wrong_target,),
    )

    assert (
        decide(
            signer.sign(
                issue_receipt(
                    lease,
                    artifact_resolution_id=wrong_poc_resolution.resolution_id,
                )
            ),
            trusted_store(signer),
            lease,
            artifact_resolution=wrong_poc_resolution,
        ).reason_code
        == "resolution_poc_digest_mismatch"
    )
    assert (
        decide(
            signer.sign(
                issue_receipt(
                    lease,
                    artifact_resolution_id=(wrong_target_resolution.resolution_id),
                )
            ),
            trusted_store(signer),
            lease,
            artifact_resolution=wrong_target_resolution,
        ).reason_code
        == "resolution_target_artifacts_mismatch"
    )


def test_signature_and_receipt_binding_checks_precede_all_cas_reads(
    signer: VerifierSigner,
) -> None:
    class CountingStore(FileEvidenceStore):
        def __init__(self, root: str) -> None:
            super().__init__(root)
            self.read_count = 0

        def get(self, digest_value: str, *, maximum: int | None = None) -> bytes:
            self.read_count += 1
            return super().get(digest_value, maximum=maximum)

        def get_typed(
            self,
            digest_value: str,
            *,
            expected_type: str,
            maximum: int | None = None,
        ) -> bytes:
            self.read_count += 1
            return super().get_typed(
                digest_value,
                expected_type=expected_type,
                maximum=maximum,
            )

    lease = issue_lease(signer)
    resolution = resolution_for_lease(lease)
    receipt = issue_receipt(lease)
    signed = signer.sign(receipt)
    forger = VerifierSigner.generate()
    forged = {
        **dict(signed.as_raw()),
        "signature_b64": base64.b64encode(
            forger.private_key.sign(verification._SIGNATURE_DOMAIN + signed.envelope_bytes)
        ).decode("ascii"),
    }
    substituted = signer.sign(issue_receipt(lease, candidate_id=digest("a")))
    substituted_resolution = signer.sign(issue_receipt(lease, artifact_resolution_id=digest("a")))
    other_signer = VerifierSigner.generate()
    signer_mismatch = sign_envelope(
        signer,
        issue_receipt(
            lease,
            verifier_key_id=other_signer.key_id,
        ).to_envelope(),
    )
    unsupported_tier_body = receipt_values(lease)
    unsupported_tier_body["evidence_artifact_digests"] = list(EVIDENCE_DIGESTS)
    unsupported_tier_body["evidence_tier"] = "kvm_isolated"
    unsupported_tier = sign_envelope(
        signer,
        EnvelopeV1.create("verifier_receipt", unsupported_tier_body),
    )
    wrong_verdict = signer.sign(
        issue_receipt(
            lease,
            verdict="not_reproduced",
            effect_observed=False,
            oracle_satisfied=False,
        )
    )
    future_receipt = signer.sign(issue_receipt(lease, completed_at=NOW + 20))
    cases = (
        (
            forged,
            trusted_store(signer),
            NOW + 11,
            "confirmed",
            frozenset(),
            "invalid_signature",
        ),
        (
            signed,
            trusted_store(signer, revoked_key_ids=(signer.key_id,)),
            NOW + 11,
            "confirmed",
            frozenset(),
            "key_revoked",
        ),
        (
            signed,
            trusted_store(signer, roles=frozenset({"auditor"})),
            NOW + 11,
            "confirmed",
            frozenset(),
            "key_missing_verifier_role",
        ),
        (
            signed,
            trusted_store(signer, revoked_lease_ids=(lease.lease_id,)),
            NOW + 11,
            "confirmed",
            frozenset(),
            "lease_revoked",
        ),
        (
            signed,
            trusted_store(signer),
            NOW + 11,
            "confirmed",
            frozenset({lease.lease_id}),
            "lease_already_consumed",
        ),
        (
            signed,
            trusted_store(signer),
            NOW + 100,
            "confirmed",
            frozenset(),
            "lease_expired",
        ),
        (
            signed,
            trusted_store(
                signer,
                revoked_receipt_ids=(receipt.receipt_id,),
            ),
            NOW + 11,
            "confirmed",
            frozenset(),
            "receipt_revoked",
        ),
        (
            signer_mismatch,
            trusted_store(signer),
            NOW + 11,
            "confirmed",
            frozenset(),
            "signer_key_mismatch",
        ),
        (
            substituted,
            trusted_store(signer),
            NOW + 11,
            "confirmed",
            frozenset(),
            "candidate_mismatch",
        ),
        (
            substituted_resolution,
            trusted_store(signer),
            NOW + 11,
            "confirmed",
            frozenset(),
            "artifact_resolution_mismatch",
        ),
        (
            unsupported_tier,
            trusted_store(signer),
            NOW + 11,
            "confirmed",
            frozenset(),
            "unsupported_evidence_tier",
        ),
        (
            wrong_verdict,
            trusted_store(signer),
            NOW + 11,
            "confirmed",
            frozenset(),
            "verdict_mismatch",
        ),
        (
            future_receipt,
            trusted_store(signer),
            NOW + 10,
            "confirmed",
            frozenset(),
            "receipt_from_future",
        ),
    )

    with tempfile.TemporaryDirectory() as temporary:
        evidence_store = CountingStore(temporary)
        reasons = tuple(
            validate_verifier_receipt(
                raw_receipt,
                trust,
                lease=lease,
                decision_time=decision_time,
                expected_verdict=expected_verdict,
                consumed_lease_ids=consumed,
                artifact_resolution=resolution,
                target_snapshot=TARGET_SNAPSHOT,
                evidence_store=evidence_store,
            ).reason_code
            for (
                raw_receipt,
                trust,
                decision_time,
                expected_verdict,
                consumed,
                _,
            ) in cases
        )

    assert reasons == tuple(case[-1] for case in cases)
    assert evidence_store.read_count == 0


def test_receipt_proposal_distinguishes_issuance_and_later_trust_snapshots(
    signer: VerifierSigner,
) -> None:
    issuance_store = trusted_store(signer)
    lease = issue_lease(
        signer,
        issuance_trust_snapshot_id=issuance_store.snapshot_id,
    )
    receipt = issue_receipt(lease)
    additional_signer = VerifierSigner.generate()
    decision_store = VerifierTrustStore.from_keys(
        (
            issuance_store.keys[signer.key_id],
            TrustedVerifierKey(
                verifier_id="MARCELLUS",
                public_key_bytes=additional_signer.public_key_bytes,
                roles=frozenset({VERIFIER_ROLE}),
            ),
        )
    )

    decision = decide(signer.sign(receipt), decision_store, lease)

    assert decision.eligible
    assert decision.issuance_trust_snapshot_id == issuance_store.snapshot_id
    assert decision.decision_trust_snapshot_id == decision_store.snapshot_id
    assert decision.issuance_trust_snapshot_id != decision.decision_trust_snapshot_id


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
    assert decide(wire, trusted_store(signer), lease).eligible


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
        "issuance_trust_snapshot_id",
        "issued_at",
        "expires_at",
    )
    assert tuple(VerifierReceiptV1.__dataclass_fields__) == (
        "receipt_id",
        "artifact_resolution_id",
        "lease_id",
        "mission_id",
        "authority_id",
        "target_snapshot_id",
        "candidate_id",
        "candidate_producer_id",
        "poc_artifact_digest",
        "evidence_artifact_digests",
        "environment_digest",
        "effect_oracle_id",
        "execution_output_digest",
        "execution_output_size",
        "effect_output_digest",
        "effect_output_size",
        "measured_environment_output_digest",
        "measured_environment_output_size",
        "termination_output_digest",
        "termination_output_size",
        "verifier_id",
        "verifier_key_id",
        "evidence_tier",
        "verdict",
        "effect_observed",
        "oracle_satisfied",
        "completed_at",
    )


def test_lease_id_changes_with_nonce_and_rejects_detached_semantics(signer: VerifierSigner) -> None:
    first = issue_lease(signer)
    second = issue_lease(signer, lease_nonce="b" * 32)

    assert first.lease_id != second.lease_id
    with pytest.raises(VerificationError) as caught:
        replace(first, lease_id=digest("f"))
    assert caught.value.reason_code == "object_id_mismatch"


def test_lease_identity_binds_the_exact_issuance_trust_snapshot(
    signer: VerifierSigner,
) -> None:
    first = issue_lease(signer)
    additional_signer = VerifierSigner.generate()
    alternate_store = VerifierTrustStore.from_keys(
        (
            trusted_store(signer).keys[signer.key_id],
            TrustedVerifierKey(
                verifier_id="MARCELLUS",
                public_key_bytes=additional_signer.public_key_bytes,
                roles=frozenset({VERIFIER_ROLE}),
            ),
        )
    )
    second = issue_lease(
        signer,
        issuance_trust_snapshot_id=alternate_store.snapshot_id,
    )

    assert first.issuance_trust_snapshot_id != (second.issuance_trust_snapshot_id)
    assert first.lease_nonce == second.lease_nonce
    assert first.lease_id != second.lease_id


def test_verification_lease_rejects_cross_role_artifact_aliasing(
    signer: VerifierSigner,
) -> None:
    with pytest.raises(VerificationError) as caught:
        issue_lease(
            signer,
            environment_digest=POC_DIGEST,
        )

    assert caught.value.reason_code == "artifact_role_collision"


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

    assert decide(signed, store, lease).eligible
    replay = decide(signed, store, lease, consumed_lease_ids=frozenset({lease.lease_id}))

    assert replay == VerificationProposal(
        eligible=False,
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
        (NOW, "receipt_from_future"),
        (NOW + 1, "proposal_valid"),
        (NOW + 99, "proposal_valid"),
        (NOW + 100, "lease_expired"),
    ],
)
def test_lease_window_is_half_open(
    signer: VerifierSigner,
    decision_time: int,
    reason: str,
) -> None:
    lease = issue_lease(signer)
    receipt = issue_receipt(lease, completed_at=NOW + 1)

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


def test_every_resolved_reference_must_be_re_read_from_the_exact_cas_domain(
    signer: VerifierSigner,
) -> None:
    lease = issue_lease(signer)
    signed = signer.sign(issue_receipt(lease))
    required = (
        (
            TARGET_FILE.artifact_digest,
            "resolved_target_unavailable",
        ),
        (
            lease.poc_artifact_digest,
            "resolved_poc_artifact_unavailable",
        ),
        *tuple(
            (
                value,
                f"resolved_evidence_{index}_artifact_unavailable",
            )
            for index, value in enumerate(lease.evidence_artifact_digests)
        ),
        (
            lease.environment_digest,
            "resolved_environment_artifact_unavailable",
        ),
        (
            lease.effect_oracle_id,
            "resolved_effect_oracle_artifact_unavailable",
        ),
    )

    for missing, reason in required:
        decision = decide(
            signed,
            trusted_store(signer),
            lease,
            omitted_digests=frozenset({missing}),
        )
        assert decision.reason_code == reason


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
