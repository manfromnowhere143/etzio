"""Adversarial evidence for atomic modeled-fixture receipt admission."""

from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from pathlib import Path
from threading import Barrier

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
from etzio.kernel.artifact_resolution import (
    VerificationArtifactResolution,
    resolve_modeled_fixture_verification_artifacts,
)
from etzio.kernel.events_v1 import (
    GENESIS_DIGEST,
    RECEIPT_ADMISSION_PROFILE_V1,
    EventIntegrityError,
    EventV1,
)
from etzio.kernel.fixture_scan import prepare_fixture_scan_for_verification
from etzio.kernel.receipt_admission import (
    VerificationReceiptAdmission,
    VerificationReceiptAdmissionError,
    admit_modeled_fixture_verifier_receipt,
)
from etzio.kernel.reducer import ProjectionPhase, ReductionError, reduce_events
from etzio.kernel.store import (
    EventStoreError,
    SQLiteEventStore,
    StaleHeadError,
    StoreBusyError,
)
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
class _Harness:
    database: Path
    evidence_store: FileEvidenceStore
    snapshot: TargetSnapshotV1
    mission_id: str
    lease: VerificationLeaseV1
    resolution: VerificationArtifactResolution
    signer: VerifierSigner
    decision_trust: VerifierTrustStore
    signed_receipt: SignedVerifierReceiptV1
    output_digests: dict[str, tuple[str, int]]


def _put_inputs(store: FileEvidenceStore, suffix: bytes = b"") -> tuple[dict[str, object], int]:
    values = {
        "poc": store.put_typed(
            b"inert-poc" + suffix,
            artifact_type=VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["poc"],
        ),
        "environment": store.put_typed(
            b"environment-spec" + suffix,
            artifact_type=VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1[
                "environment"
            ],
        ),
        "effect_oracle": store.put_typed(
            b"effect-oracle" + suffix,
            artifact_type=VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1[
                "effect_oracle"
            ],
        ),
    }
    evidence = tuple(
        sorted(
            (
                store.put_typed(
                    b"supporting-a" + suffix,
                    artifact_type=VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1[
                        "evidence"
                    ],
                ),
                store.put_typed(
                    b"supporting-b" + suffix,
                    artifact_type=VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1[
                        "evidence"
                    ],
                ),
            ),
            key=lambda value: value.digest,
        )
    )
    bindings = {
        "poc_artifact_digest": values["poc"].digest,
        "evidence_artifact_digests": tuple(value.digest for value in evidence),
        "environment_digest": values["environment"].digest,
        "effect_oracle_id": values["effect_oracle"].digest,
    }
    total = sum(value.size for value in values.values()) + sum(
        value.size for value in evidence
    )
    return bindings, total


def _put_outputs(
    store: FileEvidenceStore,
    suffix: bytes = b"",
) -> tuple[dict[str, tuple[str, int]], int]:
    values: dict[str, tuple[str, int]] = {}
    total = 0
    for role, data in (
        ("execution_output", b"execution-transcript"),
        ("effect_output", b"effect-observation"),
        ("measured_environment_output", b"measured-environment"),
        ("termination_output", b"termination-record"),
    ):
        retained = store.put_typed(
            data + suffix,
            artifact_type=VERIFICATION_OUTPUT_ARTIFACT_TYPE_BY_ROLE_V1[role],
        )
        values[role] = (retained.digest, retained.size)
        total += retained.size
    return values, total


def _signed_receipt(
    *,
    signer: VerifierSigner,
    lease: VerificationLeaseV1,
    resolution_id: str,
    outputs: dict[str, tuple[str, int]],
    verdict: str = "confirmed",
    effect_observed: bool = True,
    oracle_satisfied: bool = True,
    completed_at: int = NOW + 3,
) -> SignedVerifierReceiptV1:
    receipt = VerifierReceiptV1.for_lease(
        lease,
        artifact_resolution_id=resolution_id,
        execution_output_digest=outputs["execution_output"][0],
        execution_output_size=outputs["execution_output"][1],
        effect_output_digest=outputs["effect_output"][0],
        effect_output_size=outputs["effect_output"][1],
        measured_environment_output_digest=outputs[
            "measured_environment_output"
        ][0],
        measured_environment_output_size=outputs[
            "measured_environment_output"
        ][1],
        termination_output_digest=outputs["termination_output"][0],
        termination_output_size=outputs["termination_output"][1],
        evidence_tier=MODELED_FIXTURE_TIER,
        verdict=verdict,
        effect_observed=effect_observed,
        oracle_satisfied=oracle_satisfied,
        completed_at=completed_at,
    )
    return signer.sign(receipt)


def _setup(
    root: Path,
    *,
    output_allowance: int = 4096,
) -> _Harness:
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.chmod(0o700)
    evidence_store = FileEvidenceStore(root / "evidence")
    relative_path, fixture_bytes = read_etzio_fixture(
        "vulnerable_app.py",
        maximum=64 * 1024,
    )
    snapshot = retain_snapshot(
        "repository_fixture",
        {relative_path: fixture_bytes},
        evidence_store,
    )
    inputs, input_bytes = _put_inputs(evidence_store)
    outputs, _ = _put_outputs(evidence_store)
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
        subject="benchmark:atomic-receipt-admission",
        target_snapshot_id=snapshot.object_id,
        assets=(f"fixture://{relative_path}",),
        permitted_actions=(
            "modeled_fixture_verification",
            "static_analysis",
        ),
        evidence_digest=authority_evidence.digest,
        issued_at=NOW - 1,
        not_before=NOW,
        expires_at=NOW + 300,
        max_bytes=len(fixture_bytes) + input_bytes + output_allowance,
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
    signer = VerifierSigner.generate()
    decision_trust = VerifierTrustStore.from_keys(
        (
            TrustedVerifierKey(
                verifier_id="CATO",
                public_key_bytes=signer.public_key_bytes,
                roles=frozenset({VERIFIER_ROLE}),
            ),
        )
    )
    mission_id = content_id(
        "mission",
        {"fixture": relative_path, "nonce": root.name},
    )
    database = root / "events.sqlite3"
    with SQLiteEventStore(database) as event_store:
        prepared = prepare_fixture_scan_for_verification(
            mission_id=mission_id,
            snapshot=snapshot,
            signed_authority=signed_grant,
            trust_store=authority_trust,
            evidence_store=evidence_store,
            event_store=event_store,
            decision_time=NOW,
        )
        candidate_id = thaw_json(
            prepared.candidate_events[0].payload
        )["candidate"]["object_id"]
        issuance = issue_modeled_fixture_verification_lease(
            event_store=event_store,
            mission_id=mission_id,
            expected_head=prepared.events[-1].event_digest,
            candidate_id=candidate_id,
            **inputs,
            verifier_key_id=signer.key_id,
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
    signed_receipt = _signed_receipt(
        signer=signer,
        lease=issuance.lease,
        resolution_id=resolution.resolution.resolution_id,
        outputs=outputs,
    )
    return _Harness(
        database=database,
        evidence_store=evidence_store,
        snapshot=snapshot,
        mission_id=mission_id,
        lease=issuance.lease,
        resolution=resolution,
        signer=signer,
        decision_trust=decision_trust,
        signed_receipt=signed_receipt,
        output_digests=outputs,
    )


def _admit(
    harness: _Harness,
    *,
    event_store,
    signed_receipt: object | None = None,
    decision_trust: VerifierTrustStore | None = None,
    decision_time: int = NOW + 4,
    expected_head: str | None = None,
) -> VerificationReceiptAdmission:
    return admit_modeled_fixture_verifier_receipt(
        event_store=event_store,
        evidence_store=harness.evidence_store,
        mission_id=harness.mission_id,
        expected_head=expected_head or harness.resolution.event.event_digest,
        verification_lease_id=harness.lease.lease_id,
        signed_receipt=(
            harness.signed_receipt
            if signed_receipt is None
            else signed_receipt
        ),
        decision_trust_store=decision_trust or harness.decision_trust,
        decision_time=decision_time,
    )


def _second_resolution(
    harness: _Harness,
    *,
    event_store,
    expected_head: str,
) -> tuple[VerificationLeaseV1, VerificationArtifactResolution]:
    inputs, _ = _put_inputs(harness.evidence_store, suffix=b"-second")
    projection = reduce_events(event_store.load(harness.mission_id))
    candidate_id = thaw_json(
        projection.candidate_events[1].payload
    )["candidate"]["object_id"]
    issuance = issue_modeled_fixture_verification_lease(
        event_store=event_store,
        mission_id=harness.mission_id,
        expected_head=expected_head,
        candidate_id=candidate_id,
        **inputs,
        verifier_key_id=harness.signer.key_id,
        verifier_trust_store=harness.decision_trust,
        decision_time=NOW + 5,
        requested_wallclock_seconds=60,
    )
    resolution = resolve_modeled_fixture_verification_artifacts(
        event_store=event_store,
        evidence_store=harness.evidence_store,
        mission_id=harness.mission_id,
        expected_head=issuance.event.event_digest,
        verification_lease_id=issuance.lease.lease_id,
        decision_time=NOW + 6,
    )
    return issuance.lease, resolution


def test_admission_is_one_atomic_self_loop_without_a_finding(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    with SQLiteEventStore(harness.database) as store:
        result = _admit(harness, event_store=store)
        replayed = reduce_events(store.load(harness.mission_id))

    assert result.event.kind == "verifier_receipt_admitted"
    assert result.event.unit == "ETZIO"
    assert result.projection.phase is ProjectionPhase.AWAITING_VERIFICATION
    assert replayed.verification_receipt_admission_events == (result.event,)
    assert replayed.consumed_verification_lease_ids == frozenset(
        {harness.lease.lease_id}
    )
    assert not result.replayed
    assert thaw_json(result.event.payload)["adjudication_profile"] == (
        RECEIPT_ADMISSION_PROFILE_V1
    )
    assert not hasattr(result, "finding")
    assert replayed.terminal_event is None


def test_exact_retry_is_cas_free_after_loss_and_ignores_advanced_head(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    with SQLiteEventStore(harness.database) as store:
        first = _admit(harness, event_store=store)
        _, advanced = _second_resolution(
            harness,
            event_store=store,
            expected_head=first.event.event_digest,
        )

    harness.evidence_store._path_for(
        harness.output_digests["execution_output"][0]
    ).unlink()
    harness.evidence_store._path_for(
        harness.snapshot.files[0].artifact_digest
    ).unlink()

    with SQLiteEventStore(harness.database) as store:
        replay = _admit(harness, event_store=store)

    assert replay.replayed
    assert replay.event == first.event
    assert replay.output_artifacts == first.output_artifacts
    assert advanced.event.event_digest != first.event.event_digest
    assert replay.projection.events[-1] == advanced.event


def test_forged_signature_fails_before_any_cas_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _setup(tmp_path)
    forged = replace(
        harness.signed_receipt,
        signature_b64=base64.b64encode(bytes(64)).decode("ascii"),
    )
    reads = 0
    original = FileEvidenceStore.get_typed

    def observed_get_typed(self, *args, **kwargs):
        nonlocal reads
        reads += 1
        return original(self, *args, **kwargs)

    monkeypatch.setattr(FileEvidenceStore, "get_typed", observed_get_typed)
    with SQLiteEventStore(harness.database) as store:
        with pytest.raises(VerificationReceiptAdmissionError) as caught:
            _admit(harness, event_store=store, signed_receipt=forged)

    assert caught.value.reason_code == "invalid_signature"
    assert reads == 0


def test_consumed_retry_context_changes_conflict_without_cas(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _setup(tmp_path)
    with SQLiteEventStore(harness.database) as store:
        first = _admit(harness, event_store=store)

    changed_trust = VerifierTrustStore.from_keys(
        (
            TrustedVerifierKey(
                verifier_id="CATO",
                public_key_bytes=harness.signer.public_key_bytes,
                roles=frozenset({VERIFIER_ROLE}),
            ),
        ),
        revoked_lease_ids=("sha256:" + "f" * 64,),
    )
    reads = 0
    original = FileEvidenceStore.get_typed

    def observed_get_typed(self, *args, **kwargs):
        nonlocal reads
        reads += 1
        return original(self, *args, **kwargs)

    monkeypatch.setattr(FileEvidenceStore, "get_typed", observed_get_typed)
    with SQLiteEventStore(harness.database) as store:
        with pytest.raises(VerificationReceiptAdmissionError) as changed_time:
            _admit(
                harness,
                event_store=store,
                expected_head=first.event.event_digest,
                decision_time=NOW + 5,
            )
        with pytest.raises(VerificationReceiptAdmissionError) as changed_snapshot:
            _admit(
                harness,
                event_store=store,
                expected_head=first.event.event_digest,
                decision_trust=changed_trust,
            )

    assert changed_time.value.reason_code == (
        "verification_lease_consumed_conflict"
    )
    assert changed_snapshot.value.reason_code == (
        "verification_lease_consumed_conflict"
    )
    assert reads == 0


def test_resolution_and_time_substitutions_append_nothing(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    wrong_resolution = _signed_receipt(
        signer=harness.signer,
        lease=harness.lease,
        resolution_id="sha256:" + "f" * 64,
        outputs=harness.output_digests,
    )
    with SQLiteEventStore(harness.database) as store:
        with pytest.raises(VerificationReceiptAdmissionError) as resolution:
            _admit(
                harness,
                event_store=store,
                signed_receipt=wrong_resolution,
            )
        with pytest.raises(VerificationReceiptAdmissionError) as future:
            _admit(harness, event_store=store, decision_time=NOW + 2)
        projection = reduce_events(store.load(harness.mission_id))

    assert resolution.value.reason_code == "artifact_resolution_mismatch"
    assert future.value.reason_code == "receipt_from_future"
    assert projection.verification_receipt_admission_events == ()


def test_revoked_lease_and_inconsistent_verdict_are_refused(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    key = TrustedVerifierKey(
        verifier_id="CATO",
        public_key_bytes=harness.signer.public_key_bytes,
        roles=frozenset({VERIFIER_ROLE}),
    )
    revoked = VerifierTrustStore.from_keys(
        (key,),
        revoked_lease_ids=(harness.lease.lease_id,),
    )
    inconsistent = _signed_receipt(
        signer=harness.signer,
        lease=harness.lease,
        resolution_id=harness.resolution.resolution.resolution_id,
        outputs=harness.output_digests,
        effect_observed=False,
    )
    with SQLiteEventStore(harness.database) as store:
        with pytest.raises(VerificationReceiptAdmissionError) as revoked_error:
            _admit(harness, event_store=store, decision_trust=revoked)
        with pytest.raises(VerificationReceiptAdmissionError) as verdict_error:
            _admit(
                harness,
                event_store=store,
                signed_receipt=inconsistent,
            )

    assert revoked_error.value.reason_code == "lease_revoked"
    assert verdict_error.value.reason_code == "confirmed_without_effect"


def test_missing_or_wrong_type_output_fails_without_an_event(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    missing_digest = harness.output_digests["effect_output"][0]
    harness.evidence_store._path_for(missing_digest).unlink()
    with SQLiteEventStore(harness.database) as store:
        with pytest.raises(VerificationReceiptAdmissionError) as missing:
            _admit(harness, event_store=store)
        projection = reduce_events(store.load(harness.mission_id))

    assert missing.value.reason_code == "resolved_effect_output_artifact_unavailable"
    assert projection.verification_receipt_admission_events == ()

    other = _setup(tmp_path / "wrong-type")
    wrong = other.evidence_store.put_typed(
        b"wrong typed execution",
        artifact_type=VERIFICATION_OUTPUT_ARTIFACT_TYPE_BY_ROLE_V1[
            "effect_output"
        ],
    )
    substituted = dict(other.output_digests)
    substituted["execution_output"] = (wrong.digest, wrong.size)
    signed = _signed_receipt(
        signer=other.signer,
        lease=other.lease,
        resolution_id=other.resolution.resolution.resolution_id,
        outputs=substituted,
    )
    with SQLiteEventStore(other.database) as store:
        with pytest.raises(VerificationReceiptAdmissionError) as wrong_type:
            _admit(other, event_store=store, signed_receipt=signed)

    assert wrong_type.value.reason_code == (
        "resolved_execution_output_artifact_unavailable"
    )


def test_signed_cumulative_budget_includes_resolution_and_outputs(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path, output_allowance=1)
    with SQLiteEventStore(harness.database) as store:
        with pytest.raises(VerificationReceiptAdmissionError) as caught:
            _admit(harness, event_store=store)
        projection = reduce_events(store.load(harness.mission_id))

    assert caught.value.reason_code == "verification_output_byte_ceiling_exceeded"
    assert projection.verification_receipt_admission_events == ()


def test_direct_duplicate_append_is_rejected_by_reducer_and_store(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    with SQLiteEventStore(harness.database) as store:
        first = _admit(harness, event_store=store)
        duplicate = EventV1.create(
            mission_id=harness.mission_id,
            seq=len(first.projection.events),
            kind="verifier_receipt_admitted",
            unit="ETZIO",
            authority_id=first.projection.authority_id,
            target_id=first.projection.target_id,
            decision_time=first.event.decision_time,
            payload=thaw_json(first.event.payload),
            prev_digest=first.event.event_digest,
        )
        with pytest.raises(ReductionError, match="already consumed"):
            reduce_events((*first.projection.events, duplicate))
        with pytest.raises(
            EventStoreError,
            match="requires append_receipt_admission",
        ):
            store.append(duplicate, expected_head=first.event.event_digest)
        retained = store.load(harness.mission_id)

    assert retained == first.projection.events


def _forged_admission_event(
    prefix: tuple[EventV1, ...],
    payload: dict[str, object],
) -> EventV1:
    return EventV1.create(
        mission_id=prefix[0].mission_id,
        seq=len(prefix),
        kind="verifier_receipt_admitted",
        unit="ETZIO",
        authority_id=prefix[0].authority_id,
        target_id=prefix[0].target_id,
        decision_time=NOW + 4,
        payload=payload,
        prev_digest=prefix[-1].event_digest,
    )


def _retain_prefix(
    root: Path,
    prefix: tuple[EventV1, ...],
) -> Path:
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.chmod(0o700)
    database = root / "events.sqlite3"
    expected_head = GENESIS_DIGEST
    with SQLiteEventStore(database) as store:
        for event in prefix:
            store.append(event, expected_head=expected_head)
            expected_head = event.event_digest
    return database


def test_generic_append_rejects_an_otherwise_valid_receipt_admission(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path / "source")
    with SQLiteEventStore(harness.database) as store:
        admitted = _admit(harness, event_store=store)
    prefix = admitted.projection.events[:-1]
    assert reduce_events((*prefix, admitted.event)).events[-1] == admitted.event
    database = _retain_prefix(tmp_path / "generic-direct", prefix)

    with SQLiteEventStore(database) as store:
        before = store.load(harness.mission_id)
        with pytest.raises(
            EventStoreError,
            match="requires append_receipt_admission",
        ):
            store.append(
                admitted.event,
                expected_head=prefix[-1].event_digest,
            )
        with pytest.raises(
            EventStoreError,
            match="current-CAS validation must be paired",
        ):
            store._append_verified_event(
                admitted.event,
                expected_head=prefix[-1].event_digest,
            )
        after = store.load(harness.mission_id)

    assert before == prefix
    assert after == prefix


def test_internal_append_rejects_receipt_validation_for_an_ordinary_event(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    with SQLiteEventStore(harness.database) as store:
        retained = store.load(harness.mission_id)
        with pytest.raises(
            EventStoreError,
            match="current-CAS validation must be paired",
        ):
            store._append_verified_event(
                retained[-1],
                expected_head=retained[-1].event_digest,
                receipt_evidence_store=harness.evidence_store,
            )
        after = store.load(harness.mission_id)

    assert after == retained


def test_dedicated_receipt_append_rejects_every_other_event_kind(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    with SQLiteEventStore(harness.database) as store:
        retained = store.load(harness.mission_id)
        with pytest.raises(
            EventStoreError,
            match="requires verifier_receipt_admitted",
        ):
            store.append_receipt_admission(
                retained[-1],
                expected_head=retained[-1].event_digest,
                evidence_store=harness.evidence_store,
            )
        after = store.load(harness.mission_id)

    assert after == retained


def test_dedicated_append_revalidates_signed_sizes_before_insertion(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path / "source")
    with SQLiteEventStore(harness.database) as store:
        admitted = _admit(harness, event_store=store)
    prefix = admitted.projection.events[:-1]
    undersized_outputs = dict(harness.output_digests)
    execution_digest, execution_size = undersized_outputs["execution_output"]
    undersized_outputs["execution_output"] = (
        execution_digest,
        execution_size - 1,
    )
    undersized_receipt = _signed_receipt(
        signer=harness.signer,
        lease=harness.lease,
        resolution_id=harness.resolution.resolution.resolution_id,
        outputs=undersized_outputs,
    )
    payload = thaw_json(admitted.event.payload)
    payload["receipt"] = undersized_receipt.to_envelope().to_dict()
    payload["execution_output_artifact"]["size"] = execution_size - 1
    undersized_event = _forged_admission_event(prefix, payload)
    assert reduce_events((*prefix, undersized_event)).events[-1] == (
        undersized_event
    )
    database = _retain_prefix(tmp_path / "dedicated-direct", prefix)

    with SQLiteEventStore(database) as store:
        before = store.load(harness.mission_id)
        with pytest.raises(
            EventStoreError,
            match=(
                "receipt admission current-CAS validation failed "
                r"\(resolved_execution_output_artifact_size_mismatch\)"
            ),
        ):
            store.append_receipt_admission(
                undersized_event,
                expected_head=prefix[-1].event_digest,
                evidence_store=harness.evidence_store,
            )
        after = store.load(harness.mission_id)

    assert before == prefix
    assert after == prefix


def test_pure_reducer_reauthenticates_snapshot_receipt_and_budget(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    with SQLiteEventStore(harness.database) as store:
        admitted = _admit(harness, event_store=store)
    prefix = admitted.projection.events[:-1]
    original_payload = thaw_json(admitted.event.payload)

    revoked = VerifierTrustStore.from_keys(
        (
            TrustedVerifierKey(
                verifier_id="CATO",
                public_key_bytes=harness.signer.public_key_bytes,
                roles=frozenset({VERIFIER_ROLE}),
            ),
        ),
        revoked_lease_ids=(harness.lease.lease_id,),
    )
    revoked_payload = dict(original_payload)
    revoked_payload["decision_trust_snapshot"] = revoked.to_snapshot_body()
    revoked_payload["decision_trust_snapshot_id"] = revoked.snapshot_id
    revoked_event = _forged_admission_event(prefix, revoked_payload)
    with pytest.raises(ReductionError, match="lease is revoked"):
        reduce_events((*prefix, revoked_event))

    wrong_resolution = _signed_receipt(
        signer=harness.signer,
        lease=harness.lease,
        resolution_id="sha256:" + "f" * 64,
        outputs=harness.output_digests,
    )
    wrong_receipt_payload = dict(original_payload)
    wrong_receipt_payload["receipt"] = (
        wrong_resolution.to_envelope().to_dict()
    )
    wrong_receipt_event = _forged_admission_event(
        prefix,
        wrong_receipt_payload,
    )
    with pytest.raises(ReductionError, match="exact verification artifact"):
        reduce_events((*prefix, wrong_receipt_event))

    oversized_outputs = dict(harness.output_digests)
    oversized_outputs["execution_output"] = (
        oversized_outputs["execution_output"][0],
        1_000_000,
    )
    oversized_receipt = _signed_receipt(
        signer=harness.signer,
        lease=harness.lease,
        resolution_id=harness.resolution.resolution.resolution_id,
        outputs=oversized_outputs,
    )
    oversized_payload = thaw_json(admitted.event.payload)
    oversized_payload["receipt"] = oversized_receipt.to_envelope().to_dict()
    oversized_payload["execution_output_artifact"]["size"] = 1_000_000
    oversized_event = _forged_admission_event(prefix, oversized_payload)
    with pytest.raises(ReductionError, match="admitted byte ceiling"):
        reduce_events((*prefix, oversized_event))


def test_event_rejects_output_digest_and_type_substitution(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    with SQLiteEventStore(harness.database) as store:
        admitted = _admit(harness, event_store=store)
    prefix = admitted.projection.events[:-1]

    digest_payload = thaw_json(admitted.event.payload)
    digest_payload["execution_output_artifact"]["artifact_digest"] = (
        "sha256:" + "f" * 64
    )
    with pytest.raises(EventIntegrityError, match="output bindings differ"):
        _forged_admission_event(prefix, digest_payload)

    type_payload = thaw_json(admitted.event.payload)
    type_payload["execution_output_artifact"]["artifact_type"] = (
        VERIFICATION_OUTPUT_ARTIFACT_TYPE_BY_ROLE_V1["effect_output"]
    )
    with pytest.raises(EventIntegrityError):
        _forged_admission_event(prefix, type_payload)

    undersized_payload = thaw_json(admitted.event.payload)
    undersized_payload["execution_output_artifact"]["size"] -= 1
    with pytest.raises(EventIntegrityError, match="output bindings differ"):
        _forged_admission_event(prefix, undersized_payload)


def test_identical_race_converges_and_conflicting_race_has_one_winner(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    barrier = Barrier(2)

    def identical_worker() -> VerificationReceiptAdmission:
        with SQLiteEventStore(harness.database) as store:
            barrier.wait()
            return _admit(harness, event_store=store)

    with ThreadPoolExecutor(max_workers=2) as executor:
        identical = list(executor.map(lambda _: identical_worker(), range(2)))
    assert identical[0].event == identical[1].event
    assert {value.replayed for value in identical} == {False, True}

    other = _setup(tmp_path / "conflict")
    alternate_outputs, _ = _put_outputs(
        other.evidence_store,
        suffix=b"-alternate",
    )
    alternate = _signed_receipt(
        signer=other.signer,
        lease=other.lease,
        resolution_id=other.resolution.resolution.resolution_id,
        outputs=alternate_outputs,
        verdict="not_reproduced",
        effect_observed=False,
        oracle_satisfied=False,
    )
    proposals = (other.signed_receipt, alternate)
    conflict_barrier = Barrier(2)

    def conflict_worker(receipt):
        with SQLiteEventStore(other.database) as store:
            conflict_barrier.wait()
            return _admit(
                other,
                event_store=store,
                signed_receipt=receipt,
            )

    outcomes: list[object] = []
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(conflict_worker, value) for value in proposals]
        for future in futures:
            try:
                outcomes.append(future.result())
            except VerificationReceiptAdmissionError as exc:
                outcomes.append(exc)
    assert sum(
        isinstance(value, VerificationReceiptAdmission) for value in outcomes
    ) == 1
    assert [
        value.reason_code
        for value in outcomes
        if isinstance(value, VerificationReceiptAdmissionError)
    ] == ["verification_lease_consumed_conflict"]


def test_distinct_leases_from_one_head_require_stale_retry(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    with SQLiteEventStore(harness.database) as store:
        second_lease, second_resolution = _second_resolution(
            harness,
            event_store=store,
            expected_head=harness.resolution.event.event_digest,
        )
    second_outputs, _ = _put_outputs(
        harness.evidence_store,
        suffix=b"-second-lease",
    )
    second_receipt = _signed_receipt(
        signer=harness.signer,
        lease=second_lease,
        resolution_id=second_resolution.resolution.resolution_id,
        outputs=second_outputs,
        completed_at=NOW + 7,
    )
    shared_head = second_resolution.event.event_digest
    barrier = Barrier(2)
    submissions = (
        (harness.lease.lease_id, harness.signed_receipt),
        (second_lease.lease_id, second_receipt),
    )

    def worker(submission):
        lease_id, receipt = submission
        with SQLiteEventStore(harness.database) as store:
            barrier.wait()
            return admit_modeled_fixture_verifier_receipt(
                event_store=store,
                evidence_store=harness.evidence_store,
                mission_id=harness.mission_id,
                expected_head=shared_head,
                verification_lease_id=lease_id,
                signed_receipt=receipt,
                decision_trust_store=harness.decision_trust,
                decision_time=NOW + 8,
            )

    outcomes: list[object] = []
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(worker, value) for value in submissions]
        for future in futures:
            try:
                outcomes.append(future.result())
            except StaleHeadError as exc:
                outcomes.append(exc)
    with SQLiteEventStore(harness.database) as store:
        projection = reduce_events(store.load(harness.mission_id))

    assert sum(
        isinstance(value, VerificationReceiptAdmission) for value in outcomes
    ) == 1
    assert sum(isinstance(value, StaleHeadError) for value in outcomes) == 1
    assert len(projection.verification_receipt_admission_events) == 1
    assert len(projection.consumed_verification_lease_ids) == 1


class _CrashAfterReceiptAppend:
    def __init__(self, store: SQLiteEventStore) -> None:
        self.store = store
        self.crashed = False

    def load(self, mission_id: str):
        return self.store.load(mission_id)

    def append_receipt_admission(
        self,
        event: EventV1,
        *,
        expected_head: str,
        evidence_store: FileEvidenceStore,
    ):
        result = self.store.append_receipt_admission(
            event,
            expected_head=expected_head,
            evidence_store=evidence_store,
        )
        if not self.crashed:
            self.crashed = True
            raise RuntimeError("simulated process loss after durable admission")
        return result


class _ReleaseOnBusyStore(SQLiteEventStore):
    def __init__(
        self,
        path: Path,
        *,
        release_validation: Barrier,
    ) -> None:
        super().__init__(path)
        self._release_validation = release_validation
        self.busy_count = 0
        self._connection.execute("PRAGMA busy_timeout = 25")

    def append_receipt_admission(
        self,
        event: EventV1,
        *,
        expected_head: str,
        evidence_store: FileEvidenceStore,
    ) -> EventV1:
        try:
            return super().append_receipt_admission(
                event,
                expected_head=expected_head,
                evidence_store=evidence_store,
            )
        except StoreBusyError:
            self.busy_count += 1
            self._connection.execute("PRAGMA busy_timeout = 5000")
            self._release_validation.wait(timeout=10)
            raise


def test_bounded_writer_contention_reconciles_an_identical_submission(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import etzio.kernel.receipt_admission as receipt_admission

    harness = _setup(tmp_path)
    validation_entered = Barrier(2)
    release_validation = Barrier(2)
    original = receipt_admission.validate_retained_receipt_admission_event
    first_validation = True

    def delayed_validation(*, retained, event, evidence_store):
        nonlocal first_validation
        if first_validation:
            first_validation = False
            validation_entered.wait(timeout=10)
            release_validation.wait(timeout=10)
        return original(
            retained=retained,
            event=event,
            evidence_store=evidence_store,
        )

    monkeypatch.setattr(
        receipt_admission,
        "validate_retained_receipt_admission_event",
        delayed_validation,
    )

    def winner() -> VerificationReceiptAdmission:
        with SQLiteEventStore(harness.database) as store:
            return _admit(harness, event_store=store)

    with _ReleaseOnBusyStore(
        harness.database,
        release_validation=release_validation,
    ) as contender_store:
        with ThreadPoolExecutor(max_workers=2) as executor:
            winning_future = executor.submit(winner)
            validation_entered.wait(timeout=10)
            contender = _admit(harness, event_store=contender_store)
            busy_count = contender_store.busy_count
            winning = winning_future.result(timeout=10)

    assert not winning.replayed
    assert contender.replayed
    assert contender.event == winning.event
    assert busy_count == 1


class _AlwaysBusyReceiptStore:
    def __init__(self, store: SQLiteEventStore) -> None:
        self.store = store
        self.append_attempts = 0

    def load(self, mission_id: str):
        return self.store.load(mission_id)

    def append_receipt_admission(
        self,
        event: EventV1,
        *,
        expected_head: str,
        evidence_store: FileEvidenceStore,
    ) -> EventV1:
        self.append_attempts += 1
        raise StoreBusyError("simulated bounded writer contention")


def test_writer_contention_retry_is_bounded(tmp_path: Path) -> None:
    harness = _setup(tmp_path)
    with SQLiteEventStore(harness.database) as store:
        busy = _AlwaysBusyReceiptStore(store)
        with pytest.raises(StoreBusyError):
            _admit(harness, event_store=busy)

    assert busy.append_attempts == 2


def test_crash_after_commit_recovers_one_admission(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    with SQLiteEventStore(harness.database) as store:
        with pytest.raises(RuntimeError, match="simulated process loss"):
            _admit(
                harness,
                event_store=_CrashAfterReceiptAppend(store),
            )
    with SQLiteEventStore(harness.database) as store:
        recovered = _admit(harness, event_store=store)
        projection = reduce_events(store.load(harness.mission_id))

    assert recovered.replayed
    assert len(projection.verification_receipt_admission_events) == 1


def test_stale_head_before_first_admission_is_not_auto_rebased(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _setup(tmp_path)
    stale = harness.resolution.projection.events[-2].event_digest
    reads = 0
    original = FileEvidenceStore.get_typed

    def observed_get_typed(self, *args, **kwargs):
        nonlocal reads
        reads += 1
        return original(self, *args, **kwargs)

    monkeypatch.setattr(FileEvidenceStore, "get_typed", observed_get_typed)
    with SQLiteEventStore(harness.database) as store:
        with pytest.raises(StaleHeadError):
            _admit(harness, event_store=store, expected_head=stale)
    assert reads == 0
