"""Adversarial evidence for kernel-issued modeled-fixture verification leases."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from threading import Barrier

import pytest

from etzio.authority import (
    AuthorityAdmissionV1,
    AuthorityGrantV1,
    AuthoritySigner,
    SignedAuthorityGrantV1,
    TrustedAuthorityKey,
    TrustStore,
)
from etzio.evidence import (
    FileEvidenceStore,
    TargetSnapshotV1,
    read_etzio_fixture,
    retain_snapshot,
)
from etzio.kernel.events_v1 import (
    GENESIS_DIGEST,
    EventIntegrityError,
    EventV1,
)
from etzio.kernel.fixture_scan import (
    FixtureMissionError,
    prepare_fixture_scan_for_verification,
    run_fixture_scan,
)
from etzio.kernel.reducer import (
    ProjectionPhase,
    ReductionError,
    reduce_events,
)
from etzio.kernel.store import SQLiteEventStore
from etzio.kernel.verification_lease import (
    VerificationLeaseIssuance,
    VerificationLeaseIssuanceError,
    issue_modeled_fixture_verification_lease,
)
from etzio.protocol import (
    EnvelopeV1,
    canonical_dumps,
    content_id,
    thaw_json,
)
from etzio.verification import (
    VERIFIER_ROLE,
    TrustedVerifierKey,
    VerificationLeaseV1,
    VerifierSigner,
    VerifierTrustStore,
    derive_verification_lease_nonce,
)

NOW = 2_000_000_000


@dataclass(frozen=True, slots=True)
class _Harness:
    evidence_store: FileEvidenceStore
    snapshot: TargetSnapshotV1
    signed_authority: SignedAuthorityGrantV1
    authority_trust: TrustStore
    mission_id: str


def _setup(
    root: Path,
    *,
    fixture_name: str = "vulnerable_app.py",
    permitted_actions: tuple[str, ...] = (
        "modeled_fixture_verification",
        "static_analysis",
    ),
    max_wallclock_seconds: int = 60,
    nonce: str = "verification-run",
) -> _Harness:
    evidence_store = FileEvidenceStore(root / "evidence")
    relative_path, fixture_bytes = read_etzio_fixture(
        fixture_name,
        maximum=64 * 1024,
    )
    snapshot = retain_snapshot(
        "repository_fixture",
        {relative_path: fixture_bytes},
        evidence_store,
    )
    authority_evidence = evidence_store.put(
        canonical_dumps(
            {
                "fixture": fixture_name,
                "kind": "repository_owned_benchmark_authority",
            }
        )
    )
    signer = AuthoritySigner.generate()
    grant = AuthorityGrantV1.issue(
        issuer="operator:daniel",
        subject="benchmark:kernel-verification-lease",
        target_snapshot_id=snapshot.object_id,
        assets=(f"fixture://{relative_path}",),
        permitted_actions=permitted_actions,
        evidence_digest=authority_evidence.digest,
        issued_at=NOW - 1,
        not_before=NOW,
        expires_at=NOW + 300,
        max_bytes=len(fixture_bytes),
        max_candidates=100,
        max_wallclock_seconds=max_wallclock_seconds,
    )
    signed = signer.sign(grant)
    authority_trust = TrustStore.from_keys(
        (
            TrustedAuthorityKey(
                public_key_bytes=signer.public_key_bytes,
                roles=frozenset({"operator"}),
                issuers=frozenset({"operator:daniel"}),
            ),
        )
    )
    return _Harness(
        evidence_store=evidence_store,
        snapshot=snapshot,
        signed_authority=signed,
        authority_trust=authority_trust,
        mission_id=content_id(
            "mission",
            {"fixture": fixture_name, "nonce": nonce},
        ),
    )


def _prepare(
    store: SQLiteEventStore,
    harness: _Harness,
):
    return prepare_fixture_scan_for_verification(
        mission_id=harness.mission_id,
        snapshot=harness.snapshot,
        signed_authority=harness.signed_authority,
        trust_store=harness.authority_trust,
        evidence_store=harness.evidence_store,
        event_store=store,
        decision_time=NOW,
    )


def _candidate_id(projection, index: int = 0) -> str:
    return thaw_json(
        projection.candidate_events[index].payload
    )["candidate"]["object_id"]


def _bindings(
    evidence_store: FileEvidenceStore,
    *,
    suffix: bytes = b"",
) -> dict[str, object]:
    poc = evidence_store.put(b"inert PoC description" + suffix).digest
    evidence = tuple(
        sorted(
            (
                evidence_store.put(b"inert trace A" + suffix).digest,
                evidence_store.put(b"inert trace B" + suffix).digest,
            )
        )
    )
    environment = evidence_store.put(
        b"inert environment manifest" + suffix
    ).digest
    oracle = evidence_store.put(
        b"inert effect oracle description" + suffix
    ).digest
    return {
        "poc_artifact_digest": poc,
        "evidence_artifact_digests": evidence,
        "environment_digest": environment,
        "effect_oracle_id": oracle,
    }


def _verifier(
    *,
    verifier_id: str = "CATO",
    roles: frozenset[str] = frozenset({VERIFIER_ROLE}),
    revoked_key: bool = False,
    revoked_lease_ids: tuple[str, ...] = (),
) -> tuple[VerifierSigner, VerifierTrustStore]:
    signer = VerifierSigner.generate()
    key = TrustedVerifierKey(
        verifier_id=verifier_id,
        public_key_bytes=signer.public_key_bytes,
        roles=roles,
    )
    return signer, VerifierTrustStore.from_keys(
        (key,),
        revoked_key_ids=(signer.key_id,) if revoked_key else (),
        revoked_lease_ids=revoked_lease_ids,
    )


def _issue_args(
    *,
    store,
    harness: _Harness,
    projection,
    signer: VerifierSigner,
    verifier_trust: VerifierTrustStore,
    bindings: dict[str, object],
    candidate_index: int = 0,
    decision_time: int = NOW + 1,
    requested_wallclock_seconds: int = 30,
) -> dict[str, object]:
    return {
        "event_store": store,
        "mission_id": harness.mission_id,
        "expected_head": projection.events[-1].event_digest,
        "candidate_id": _candidate_id(projection, candidate_index),
        **bindings,
        "verifier_key_id": signer.key_id,
        "verifier_trust_store": verifier_trust,
        "decision_time": decision_time,
        "requested_wallclock_seconds": requested_wallclock_seconds,
    }


def _admission(event: EventV1) -> AuthorityAdmissionV1:
    payload = thaw_json(event.payload)
    return AuthorityAdmissionV1.from_envelope(
        EnvelopeV1.from_bytes(canonical_dumps(payload["admission"]))
    )


def _rechain(
    events: tuple[EventV1, ...],
    *,
    first_payload: dict[str, object],
) -> tuple[EventV1, ...]:
    rebuilt: list[EventV1] = []
    previous = GENESIS_DIGEST
    for old in events:
        event = EventV1.create(
            mission_id=old.mission_id,
            seq=old.seq,
            kind=old.kind,
            unit=old.unit,
            authority_id=old.authority_id,
            target_id=old.target_id,
            decision_time=old.decision_time,
            payload=first_payload if old.seq == 0 else thaw_json(old.payload),
            prev_digest=previous,
        )
        rebuilt.append(event)
        previous = event.event_digest
    return tuple(rebuilt)


def _manual_verification_event(
    projection,
    *,
    signer: VerifierSigner,
    verifier_trust: VerifierTrustStore,
    bindings: dict[str, object],
    decision_time: int = NOW + 1,
    expires_at: int = NOW + 30,
    candidate_producer_id: str | None = None,
) -> EventV1:
    candidate_id = _candidate_id(projection)
    producer = (
        projection.candidate_events[0].unit
        if candidate_producer_id is None
        else candidate_producer_id
    )
    previous = projection.events[-1].event_digest
    nonce = derive_verification_lease_nonce(
        prior_event_digest=previous,
        mission_id=projection.mission_id,
        authority_id=projection.authority_id,
        target_snapshot_id=projection.target_id,
        candidate_id=candidate_id,
        candidate_producer_id=producer,
        poc_artifact_digest=bindings["poc_artifact_digest"],
        evidence_artifact_digests=bindings[
            "evidence_artifact_digests"
        ],
        environment_digest=bindings["environment_digest"],
        effect_oracle_id=bindings["effect_oracle_id"],
        verifier_id="CATO",
        verifier_key_id=signer.key_id,
        issued_at=decision_time,
        expires_at=expires_at,
        issuance_trust_snapshot_id=verifier_trust.snapshot_id,
    )
    lease = VerificationLeaseV1.issue(
        lease_nonce=nonce,
        mission_id=projection.mission_id,
        authority_id=projection.authority_id,
        target_snapshot_id=projection.target_id,
        candidate_id=candidate_id,
        candidate_producer_id=producer,
        poc_artifact_digest=bindings["poc_artifact_digest"],
        evidence_artifact_digests=bindings[
            "evidence_artifact_digests"
        ],
        environment_digest=bindings["environment_digest"],
        effect_oracle_id=bindings["effect_oracle_id"],
        verifier_id="CATO",
        verifier_key_id=signer.key_id,
        issuance_trust_snapshot_id=verifier_trust.snapshot_id,
        issued_at=decision_time,
        expires_at=expires_at,
    )
    return EventV1.create(
        mission_id=projection.mission_id,
        seq=len(projection.events),
        kind="verification_lease_issued",
        unit="AQUILA",
        authority_id=projection.authority_id,
        target_id=projection.target_id,
        decision_time=decision_time,
        payload={
            "lease": lease.to_envelope().to_dict(),
            "verifier_trust_snapshot": verifier_trust.to_snapshot_body(),
            "verifier_trust_snapshot_id": verifier_trust.snapshot_id,
        },
        prev_digest=previous,
    )


def test_kernel_issuance_is_authority_bound_replayable_and_idempotent(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    signer, verifier_trust = _verifier()
    bindings = _bindings(harness.evidence_store)
    with SQLiteEventStore(tmp_path / "events.sqlite3") as store:
        prepared = _prepare(store, harness)
        scan_head = prepared.events[-1].event_digest
        args = _issue_args(
            store=store,
            harness=harness,
            projection=prepared,
            signer=signer,
            verifier_trust=verifier_trust,
            bindings=bindings,
        )
        issued = issue_modeled_fixture_verification_lease(**args)
        replayed = issue_modeled_fixture_verification_lease(**args)
        reloaded = reduce_events(store.load(harness.mission_id))

    assert prepared.phase is ProjectionPhase.SCAN_COMPLETED
    assert not prepared.is_terminal
    assert _admission(prepared.events[0]).required_actions == (
        "modeled_fixture_verification",
        "static_analysis",
    )
    assert issued.projection.phase is ProjectionPhase.AWAITING_VERIFICATION
    assert issued.event.kind == "verification_lease_issued"
    assert issued.event.unit == "AQUILA"
    assert issued.event.prev_digest == scan_head
    assert issued.lease.candidate_id == _candidate_id(prepared)
    assert issued.lease.candidate_producer_id == "VELITES"
    assert issued.lease.verifier_id == "CATO"
    assert issued.lease.issued_at == NOW + 1
    assert issued.lease.expires_at == NOW + 31
    assert not issued.replayed
    assert replayed.replayed
    assert replayed.event == issued.event
    assert replayed.lease == issued.lease
    assert reloaded == issued.projection
    assert len(reloaded.verification_lease_events) == 1
    assert all(
        event.kind not in {"verifier_receipt_accepted", "finding_admitted"}
        for event in reloaded.events
    )


def test_zero_candidate_verification_intent_closes_without_a_lease(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path, fixture_name="clean_app.py")
    with SQLiteEventStore(tmp_path / "events.sqlite3") as store:
        projection = _prepare(store, harness)

    assert projection.phase is ProjectionPhase.CLOSED
    assert projection.candidate_events == ()
    assert projection.verification_lease_events == ()


def test_verification_preparation_refuses_a_static_only_grant(
    tmp_path: Path,
) -> None:
    harness = _setup(
        tmp_path,
        permitted_actions=("static_analysis",),
    )
    with SQLiteEventStore(tmp_path / "events.sqlite3") as store:
        projection = _prepare(store, harness)

    assert projection.phase is ProjectionPhase.REFUSED
    assert thaw_json(projection.refusal.payload)["reason_code"] == (
        "missing_required_action"
    )


@pytest.mark.parametrize(
    "kind",
    ("verifier_receipt_accepted", "finding_admitted"),
)
def test_receipt_acceptance_and_finding_events_remain_unsupported(
    kind: str,
) -> None:
    with pytest.raises(EventIntegrityError, match="unsupported event kind"):
        EventV1.create(
            mission_id="sha256:" + "1" * 64,
            seq=0,
            kind=kind,
            unit="AQUILA",
            authority_id="sha256:" + "2" * 64,
            target_id="sha256:" + "3" * 64,
            decision_time=NOW,
            payload={},
            prev_digest=GENESIS_DIGEST,
        )


@pytest.mark.parametrize(
    ("mutation", "reason_code"),
    (
        (
            {"evidence_artifact_digests": ("sha256:" + "f" * 64,) * 2},
            "invalid_evidence_artifact_digests",
        ),
        ({"decision_time": True}, "invalid_decision_time"),
        ({"requested_wallclock_seconds": 0}, "invalid_requested_wallclock"),
        (
            {"candidate_id": "sha256:not-a-candidate"},
            "invalid_candidate_id",
        ),
    ),
)
def test_malformed_requests_fail_before_appending(
    tmp_path: Path,
    mutation: dict[str, object],
    reason_code: str,
) -> None:
    harness = _setup(tmp_path, nonce=reason_code)
    signer, verifier_trust = _verifier()
    bindings = _bindings(harness.evidence_store)
    with SQLiteEventStore(tmp_path / "events.sqlite3") as store:
        prepared = _prepare(store, harness)
        before = store.load(harness.mission_id)
        args = _issue_args(
            store=store,
            harness=harness,
            projection=prepared,
            signer=signer,
            verifier_trust=verifier_trust,
            bindings=bindings,
        )
        args.update(mutation)
        with pytest.raises(VerificationLeaseIssuanceError) as caught:
            issue_modeled_fixture_verification_lease(**args)
        after = store.load(harness.mission_id)

    assert caught.value.reason_code == reason_code
    assert after == before


def test_cross_role_digest_alias_is_rejected_without_append(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    signer, verifier_trust = _verifier()
    bindings = _bindings(harness.evidence_store)
    bindings["environment_digest"] = bindings["poc_artifact_digest"]
    with SQLiteEventStore(tmp_path / "events.sqlite3") as store:
        prepared = _prepare(store, harness)
        args = _issue_args(
            store=store,
            harness=harness,
            projection=prepared,
            signer=signer,
            verifier_trust=verifier_trust,
            bindings=bindings,
        )
        with pytest.raises(VerificationLeaseIssuanceError) as caught:
            issue_modeled_fixture_verification_lease(**args)

    assert caught.value.reason_code == "artifact_role_collision"


@pytest.mark.parametrize(
    ("verifier_id", "roles", "revoked_key", "reason_code"),
    (
        ("VELITES", frozenset({VERIFIER_ROLE}), False, "self_verification"),
        ("CATO", frozenset({"observer"}), False, "verifier_role_missing"),
        ("CATO", frozenset({VERIFIER_ROLE}), True, "verifier_key_revoked"),
    ),
)
def test_ineligible_verifier_assignments_fail_closed(
    tmp_path: Path,
    verifier_id: str,
    roles: frozenset[str],
    revoked_key: bool,
    reason_code: str,
) -> None:
    harness = _setup(tmp_path, nonce=reason_code)
    signer, verifier_trust = _verifier(
        verifier_id=verifier_id,
        roles=roles,
        revoked_key=revoked_key,
    )
    bindings = _bindings(harness.evidence_store)
    with SQLiteEventStore(tmp_path / "events.sqlite3") as store:
        prepared = _prepare(store, harness)
        before = store.load(harness.mission_id)
        args = _issue_args(
            store=store,
            harness=harness,
            projection=prepared,
            signer=signer,
            verifier_trust=verifier_trust,
            bindings=bindings,
        )
        with pytest.raises(VerificationLeaseIssuanceError) as caught:
            issue_modeled_fixture_verification_lease(**args)
        assert store.load(harness.mission_id) == before

    assert caught.value.reason_code == reason_code


def test_unknown_verifier_key_fails_closed(tmp_path: Path) -> None:
    harness = _setup(tmp_path)
    assigned_signer = VerifierSigner.generate()
    _, different_trust = _verifier()
    with SQLiteEventStore(tmp_path / "events.sqlite3") as store:
        prepared = _prepare(store, harness)
        args = _issue_args(
            store=store,
            harness=harness,
            projection=prepared,
            signer=assigned_signer,
            verifier_trust=different_trust,
            bindings=_bindings(harness.evidence_store),
        )
        with pytest.raises(VerificationLeaseIssuanceError) as caught:
            issue_modeled_fixture_verification_lease(**args)

    assert caught.value.reason_code == "unknown_verifier_key"


def test_missing_candidate_and_exhausted_time_are_rejected(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path, max_wallclock_seconds=2)
    signer, verifier_trust = _verifier()
    bindings = _bindings(harness.evidence_store)
    with SQLiteEventStore(tmp_path / "events.sqlite3") as store:
        prepared = _prepare(store, harness)
        missing_args = _issue_args(
            store=store,
            harness=harness,
            projection=prepared,
            signer=signer,
            verifier_trust=verifier_trust,
            bindings=bindings,
            requested_wallclock_seconds=1,
        )
        missing_args["candidate_id"] = "sha256:" + "f" * 64
        with pytest.raises(VerificationLeaseIssuanceError) as missing:
            issue_modeled_fixture_verification_lease(**missing_args)

        expired_args = _issue_args(
            store=store,
            harness=harness,
            projection=prepared,
            signer=signer,
            verifier_trust=verifier_trust,
            bindings=bindings,
            decision_time=NOW + 2,
            requested_wallclock_seconds=2,
        )
        with pytest.raises(VerificationLeaseIssuanceError) as expired:
            issue_modeled_fixture_verification_lease(**expired_args)

    assert missing.value.reason_code == "candidate_not_retained"
    assert expired.value.reason_code == "verification_window_exhausted"


def test_issuance_is_rejected_before_scan_completion_and_after_closure(
    tmp_path: Path,
) -> None:
    before_root = tmp_path / "before"
    before_root.mkdir(mode=0o700)
    before = _setup(before_root, nonce="before-scan")
    signer, verifier_trust = _verifier()

    class _CrashAtMissionOpen:
        def __init__(self, store: SQLiteEventStore) -> None:
            self.store = store

        def load(self, mission_id: str):
            return self.store.load(mission_id)

        def append(self, event: EventV1, *, expected_head: str):
            result = self.store.append(event, expected_head=expected_head)
            if event.kind == "mission_opened":
                raise RuntimeError("stop before scan")
            return result

    with SQLiteEventStore(before_root / "events.sqlite3") as store:
        with pytest.raises(RuntimeError, match="stop before scan"):
            prepare_fixture_scan_for_verification(
                mission_id=before.mission_id,
                snapshot=before.snapshot,
                signed_authority=before.signed_authority,
                trust_store=before.authority_trust,
                evidence_store=before.evidence_store,
                event_store=_CrashAtMissionOpen(store),
                decision_time=NOW,
            )
        with pytest.raises(VerificationLeaseIssuanceError) as premature:
            issue_modeled_fixture_verification_lease(
                event_store=store,
                mission_id=before.mission_id,
                expected_head=store.head(before.mission_id),
                candidate_id="sha256:" + "f" * 64,
                **_bindings(before.evidence_store),
                verifier_key_id=signer.key_id,
                verifier_trust_store=verifier_trust,
                decision_time=NOW + 1,
                requested_wallclock_seconds=30,
            )

    closed_root = tmp_path / "closed"
    closed_root.mkdir(mode=0o700)
    closed = _setup(
        closed_root,
        permitted_actions=("static_analysis",),
        nonce="closed",
    )
    with SQLiteEventStore(closed_root / "events.sqlite3") as store:
        projection = run_fixture_scan(
            mission_id=closed.mission_id,
            snapshot=closed.snapshot,
            signed_authority=closed.signed_authority,
            trust_store=closed.authority_trust,
            evidence_store=closed.evidence_store,
            event_store=store,
            decision_time=NOW,
        )
        with pytest.raises(FixtureMissionError, match="intent differs"):
            prepare_fixture_scan_for_verification(
                mission_id=closed.mission_id,
                snapshot=closed.snapshot,
                signed_authority=closed.signed_authority,
                trust_store=closed.authority_trust,
                evidence_store=closed.evidence_store,
                event_store=store,
                decision_time=NOW + 1,
            )
        with pytest.raises(VerificationLeaseIssuanceError) as terminal:
            issue_modeled_fixture_verification_lease(
                event_store=store,
                mission_id=closed.mission_id,
                expected_head=projection.events[-1].event_digest,
                candidate_id=_candidate_id(projection),
                **_bindings(closed.evidence_store),
                verifier_key_id=signer.key_id,
                verifier_trust_store=verifier_trust,
                decision_time=NOW + 1,
                requested_wallclock_seconds=30,
            )

    assert premature.value.reason_code == "scan_not_completed"
    assert terminal.value.reason_code == "mission_terminal"


def test_alternate_issuance_snapshot_and_oversized_window_fail_closed(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    signer, initial_trust = _verifier()
    bindings = _bindings(harness.evidence_store)
    with SQLiteEventStore(tmp_path / "events.sqlite3") as store:
        prepared = _prepare(store, harness)
        oversized_args = _issue_args(
            store=store,
            harness=harness,
            projection=prepared,
            signer=signer,
            verifier_trust=initial_trust,
            bindings=bindings,
            requested_wallclock_seconds=61,
        )
        with pytest.raises(VerificationLeaseIssuanceError) as oversized:
            issue_modeled_fixture_verification_lease(**oversized_args)
        issued = issue_modeled_fixture_verification_lease(
            **_issue_args(
                store=store,
                harness=harness,
                projection=prepared,
                signer=signer,
                verifier_trust=initial_trust,
                bindings=bindings,
            )
        )
        extra_signer = VerifierSigner.generate()
        extra_key = TrustedVerifierKey(
            verifier_id="MARCELLUS",
            public_key_bytes=extra_signer.public_key_bytes,
            roles=frozenset({VERIFIER_ROLE}),
        )
        alternate_trust = VerifierTrustStore.from_keys(
            (
                initial_trust.keys[signer.key_id],
                extra_key,
            )
        )
        alternate_args = _issue_args(
            store=store,
            harness=harness,
            projection=prepared,
            signer=signer,
            verifier_trust=alternate_trust,
            bindings=bindings,
        )
        with pytest.raises(VerificationLeaseIssuanceError) as alternate:
            issue_modeled_fixture_verification_lease(**alternate_args)

    assert issued.lease.issuance_trust_snapshot_id == initial_trust.snapshot_id
    assert alternate_trust.snapshot_id != initial_trust.snapshot_id
    assert alternate.value.reason_code == "candidate_lease_conflict"
    assert oversized.value.reason_code == "requested_wallclock_exceeds_grant"


def test_conflicting_second_lease_for_one_candidate_is_rejected(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    signer, verifier_trust = _verifier()
    with SQLiteEventStore(tmp_path / "events.sqlite3") as store:
        prepared = _prepare(store, harness)
        first_args = _issue_args(
            store=store,
            harness=harness,
            projection=prepared,
            signer=signer,
            verifier_trust=verifier_trust,
            bindings=_bindings(harness.evidence_store),
        )
        first = issue_modeled_fixture_verification_lease(**first_args)
        conflicting = _issue_args(
            store=store,
            harness=harness,
            projection=first.projection,
            signer=signer,
            verifier_trust=verifier_trust,
            bindings=_bindings(harness.evidence_store, suffix=b"-other"),
        )
        with pytest.raises(VerificationLeaseIssuanceError) as caught:
            issue_modeled_fixture_verification_lease(**conflicting)
        retained = store.load(harness.mission_id)

    assert caught.value.reason_code == "candidate_lease_conflict"
    assert len(
        [event for event in retained if event.kind == "verification_lease_issued"]
    ) == 1


def test_window_clips_to_global_deadline_and_second_lease_time_cannot_regress(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    signer, verifier_trust = _verifier()
    with SQLiteEventStore(tmp_path / "events.sqlite3") as store:
        prepared = _prepare(store, harness)
        first = issue_modeled_fixture_verification_lease(
            **_issue_args(
                store=store,
                harness=harness,
                projection=prepared,
                signer=signer,
                verifier_trust=verifier_trust,
                bindings=_bindings(
                    harness.evidence_store,
                    suffix=b"-late-first",
                ),
                decision_time=NOW + 50,
                requested_wallclock_seconds=60,
            )
        )
        regressed = _issue_args(
            store=store,
            harness=harness,
            projection=first.projection,
            signer=signer,
            verifier_trust=verifier_trust,
            bindings=_bindings(
                harness.evidence_store,
                suffix=b"-regressed-second",
            ),
            candidate_index=1,
            decision_time=NOW + 49,
            requested_wallclock_seconds=10,
        )
        with pytest.raises(VerificationLeaseIssuanceError) as caught:
            issue_modeled_fixture_verification_lease(**regressed)

    assert first.lease.expires_at == NOW + 60
    assert caught.value.reason_code == "decision_time_regressed"


class _CrashAfterLeaseAppend:
    def __init__(self, store: SQLiteEventStore) -> None:
        self.store = store
        self.crashed = False

    def load(self, mission_id: str):
        return self.store.load(mission_id)

    def append(self, event: EventV1, *, expected_head: str):
        result = self.store.append(event, expected_head=expected_head)
        if event.kind == "verification_lease_issued" and not self.crashed:
            self.crashed = True
            raise RuntimeError("simulated process loss after durable lease append")
        return result


def test_crash_after_commit_recovers_the_same_single_lease(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    signer, verifier_trust = _verifier()
    database = tmp_path / "events.sqlite3"
    with SQLiteEventStore(database) as store:
        prepared = _prepare(store, harness)
        args = _issue_args(
            store=_CrashAfterLeaseAppend(store),
            harness=harness,
            projection=prepared,
            signer=signer,
            verifier_trust=verifier_trust,
            bindings=_bindings(harness.evidence_store),
        )
        with pytest.raises(RuntimeError, match="simulated process loss"):
            issue_modeled_fixture_verification_lease(**args)
    with SQLiteEventStore(database) as store:
        args["event_store"] = store
        recovered = issue_modeled_fixture_verification_lease(**args)
        retained = store.load(harness.mission_id)

    assert recovered.replayed
    assert recovered.projection.phase is ProjectionPhase.AWAITING_VERIFICATION
    assert len(
        [event for event in retained if event.kind == "verification_lease_issued"]
    ) == 1


def test_identical_two_writer_race_commits_one_event(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    signer, verifier_trust = _verifier()
    database = tmp_path / "events.sqlite3"
    with SQLiteEventStore(database) as store:
        prepared = _prepare(store, harness)
    expected_head = prepared.events[-1].event_digest
    candidate_id = _candidate_id(prepared)
    bindings = _bindings(harness.evidence_store)
    barrier = Barrier(2)

    def worker() -> VerificationLeaseIssuance:
        with SQLiteEventStore(database) as worker_store:
            barrier.wait()
            return issue_modeled_fixture_verification_lease(
                event_store=worker_store,
                mission_id=harness.mission_id,
                expected_head=expected_head,
                candidate_id=candidate_id,
                **bindings,
                verifier_key_id=signer.key_id,
                verifier_trust_store=verifier_trust,
                decision_time=NOW + 1,
                requested_wallclock_seconds=30,
            )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: worker(), range(2)))
    with SQLiteEventStore(database) as store:
        projection = reduce_events(store.load(harness.mission_id))

    assert results[0].event == results[1].event
    assert {result.replayed for result in results} == {False, True}
    assert len(projection.verification_lease_events) == 1


def test_conflicting_two_writer_race_has_one_winner_and_one_refusal(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    signer, verifier_trust = _verifier()
    database = tmp_path / "events.sqlite3"
    with SQLiteEventStore(database) as store:
        prepared = _prepare(store, harness)
    expected_head = prepared.events[-1].event_digest
    candidate_id = _candidate_id(prepared)
    proposals = (
        _bindings(harness.evidence_store, suffix=b"-left"),
        _bindings(harness.evidence_store, suffix=b"-right"),
    )
    barrier = Barrier(2)

    def worker(bindings: dict[str, object]):
        with SQLiteEventStore(database) as worker_store:
            barrier.wait()
            return issue_modeled_fixture_verification_lease(
                event_store=worker_store,
                mission_id=harness.mission_id,
                expected_head=expected_head,
                candidate_id=candidate_id,
                **bindings,
                verifier_key_id=signer.key_id,
                verifier_trust_store=verifier_trust,
                decision_time=NOW + 1,
                requested_wallclock_seconds=30,
            )

    outcomes: list[object] = []
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(worker, proposal) for proposal in proposals]
        for future in futures:
            try:
                outcomes.append(future.result())
            except VerificationLeaseIssuanceError as exc:
                outcomes.append(exc)
    with SQLiteEventStore(database) as store:
        projection = reduce_events(store.load(harness.mission_id))

    assert sum(
        isinstance(outcome, VerificationLeaseIssuance)
        for outcome in outcomes
    ) == 1
    refusals = [
        outcome
        for outcome in outcomes
        if isinstance(outcome, VerificationLeaseIssuanceError)
    ]
    assert [refusal.reason_code for refusal in refusals] == [
        "candidate_lease_conflict"
    ]
    assert len(projection.verification_lease_events) == 1


def test_post_commit_reload_finds_its_event_after_another_candidate_advances(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    signer, verifier_trust = _verifier()
    database = tmp_path / "events.sqlite3"
    with SQLiteEventStore(database) as store:
        prepared = _prepare(store, harness)

        class _InterleavingStore:
            def __init__(self) -> None:
                self.appended_event: EventV1 | None = None
                self.interleaved = False
                self.second_result: VerificationLeaseIssuance | None = None

            def append(self, event: EventV1, *, expected_head: str):
                result = store.append(event, expected_head=expected_head)
                self.appended_event = event
                return result

            def load(self, mission_id: str):
                if self.appended_event is not None and not self.interleaved:
                    self.interleaved = True
                    with SQLiteEventStore(database) as second_store:
                        self.second_result = (
                            issue_modeled_fixture_verification_lease(
                                event_store=second_store,
                                mission_id=harness.mission_id,
                                expected_head=(
                                    self.appended_event.event_digest
                                ),
                                candidate_id=_candidate_id(prepared, 1),
                                **_bindings(
                                    harness.evidence_store,
                                    suffix=b"-second-candidate",
                                ),
                                verifier_key_id=signer.key_id,
                                verifier_trust_store=verifier_trust,
                                decision_time=NOW + 2,
                                requested_wallclock_seconds=30,
                            )
                        )
                return store.load(mission_id)

        interleaving_store = _InterleavingStore()
        first_result = issue_modeled_fixture_verification_lease(
            **_issue_args(
                store=interleaving_store,
                harness=harness,
                projection=prepared,
                signer=signer,
                verifier_trust=verifier_trust,
                bindings=_bindings(
                    harness.evidence_store,
                    suffix=b"-first-candidate",
                ),
                candidate_index=0,
            )
        )
        replayed = reduce_events(store.load(harness.mission_id))

    assert interleaving_store.second_result is not None
    assert first_result.lease.candidate_id == _candidate_id(prepared, 0)
    assert interleaving_store.second_result.lease.candidate_id == (
        _candidate_id(prepared, 1)
    )
    assert first_result.event != replayed.verification_lease_events[-1]
    assert len(replayed.verification_lease_events) == 2
    assert replayed.phase is ProjectionPhase.AWAITING_VERIFICATION


def test_reducer_requires_retained_verification_intent_and_blocks_early_close(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    signer, verifier_trust = _verifier()
    bindings = _bindings(harness.evidence_store)
    with SQLiteEventStore(tmp_path / "events.sqlite3") as store:
        prepared = _prepare(store, harness)

    first_payload = thaw_json(prepared.events[0].payload)
    grant = AuthorityGrantV1.from_envelope(
        EnvelopeV1.from_bytes(canonical_dumps(first_payload["grant"]))
    )
    static_only_admission = AuthorityAdmissionV1.issue(
        grant=grant,
        signed_grant=harness.signed_authority,
        signer_key_id=harness.signed_authority.key_id,
        trust_store=harness.authority_trust,
        decision_time=NOW,
        required_actions=("static_analysis",),
        target_snapshot_id=harness.snapshot.object_id,
    )
    first_payload["admission"] = (
        static_only_admission.to_envelope().to_dict()
    )
    rewritten = _rechain(
        prepared.events,
        first_payload=first_payload,
    )
    rewritten_projection = reduce_events(rewritten)
    unauthorized = _manual_verification_event(
        rewritten_projection,
        signer=signer,
        verifier_trust=verifier_trust,
        bindings=bindings,
    )
    with pytest.raises(ReductionError, match="lacks admitted"):
        reduce_events((*rewritten, unauthorized))

    wrong_producer = _manual_verification_event(
        prepared,
        signer=signer,
        verifier_trust=verifier_trust,
        bindings=bindings,
        candidate_producer_id="FABIUS",
    )
    with pytest.raises(ReductionError, match="mission bindings"):
        reduce_events((*prepared.events, wrong_producer))

    excessive_expiry = _manual_verification_event(
        prepared,
        signer=signer,
        verifier_trust=verifier_trust,
        bindings=bindings,
        expires_at=NOW + 61,
    )
    with pytest.raises(ReductionError, match="authority window"):
        reduce_events((*prepared.events, excessive_expiry))

    summary = thaw_json(prepared.scan_summary.payload)
    close = EventV1.create(
        mission_id=prepared.mission_id,
        seq=len(prepared.events),
        kind="mission_closed",
        unit="ETZIO",
        authority_id=prepared.authority_id,
        target_id=prepared.target_id,
        decision_time=NOW + 1,
        payload={
            "candidate_count": summary["candidate_count"],
            "parse_failure_count": summary["parse_failure_count"],
            "status": "completed",
        },
        prev_digest=prepared.events[-1].event_digest,
    )
    with pytest.raises(ReductionError, match="cannot close"):
        reduce_events((*prepared.events, close))


def test_event_and_reducer_reject_nonce_unit_snapshot_and_authority_substitution(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    signer, verifier_trust = _verifier()
    bindings = _bindings(harness.evidence_store)
    with SQLiteEventStore(tmp_path / "events.sqlite3") as store:
        prepared = _prepare(store, harness)
        issued = issue_modeled_fixture_verification_lease(
            **_issue_args(
                store=store,
                harness=harness,
                projection=prepared,
                signer=signer,
                verifier_trust=verifier_trust,
                bindings=bindings,
            )
        )

    payload = thaw_json(issued.event.payload)
    with pytest.raises(EventIntegrityError, match="AQUILA"):
        EventV1.create(
            mission_id=issued.event.mission_id,
            seq=issued.event.seq,
            kind=issued.event.kind,
            unit="ETZIO",
            authority_id=issued.event.authority_id,
            target_id=issued.event.target_id,
            decision_time=issued.event.decision_time,
            payload=payload,
            prev_digest=issued.event.prev_digest,
        )

    wrong_snapshot = dict(payload)
    wrong_snapshot["verifier_trust_snapshot_id"] = "sha256:" + "f" * 64
    with pytest.raises(EventIntegrityError, match="verification evidence"):
        EventV1.create(
            mission_id=issued.event.mission_id,
            seq=issued.event.seq,
            kind=issued.event.kind,
            unit=issued.event.unit,
            authority_id=issued.event.authority_id,
            target_id=issued.event.target_id,
            decision_time=issued.event.decision_time,
            payload=wrong_snapshot,
            prev_digest=issued.event.prev_digest,
        )

    extra_signer = VerifierSigner.generate()
    alternate_trust = VerifierTrustStore.from_keys(
        (
            verifier_trust.keys[signer.key_id],
            TrustedVerifierKey(
                verifier_id="MARCELLUS",
                public_key_bytes=extra_signer.public_key_bytes,
                roles=frozenset({VERIFIER_ROLE}),
            ),
        )
    )
    alternate_nonce = derive_verification_lease_nonce(
        prior_event_digest=issued.event.prev_digest,
        mission_id=issued.lease.mission_id,
        authority_id=issued.lease.authority_id,
        target_snapshot_id=issued.lease.target_snapshot_id,
        candidate_id=issued.lease.candidate_id,
        candidate_producer_id=issued.lease.candidate_producer_id,
        poc_artifact_digest=issued.lease.poc_artifact_digest,
        evidence_artifact_digests=issued.lease.evidence_artifact_digests,
        environment_digest=issued.lease.environment_digest,
        effect_oracle_id=issued.lease.effect_oracle_id,
        verifier_id=issued.lease.verifier_id,
        verifier_key_id=issued.lease.verifier_key_id,
        issued_at=issued.lease.issued_at,
        expires_at=issued.lease.expires_at,
        issuance_trust_snapshot_id=alternate_trust.snapshot_id,
    )
    alternate_lease = VerificationLeaseV1.issue(
        lease_nonce=alternate_nonce,
        mission_id=issued.lease.mission_id,
        authority_id=issued.lease.authority_id,
        target_snapshot_id=issued.lease.target_snapshot_id,
        candidate_id=issued.lease.candidate_id,
        candidate_producer_id=issued.lease.candidate_producer_id,
        poc_artifact_digest=issued.lease.poc_artifact_digest,
        evidence_artifact_digests=issued.lease.evidence_artifact_digests,
        environment_digest=issued.lease.environment_digest,
        effect_oracle_id=issued.lease.effect_oracle_id,
        verifier_id=issued.lease.verifier_id,
        verifier_key_id=issued.lease.verifier_key_id,
        issuance_trust_snapshot_id=alternate_trust.snapshot_id,
        issued_at=issued.lease.issued_at,
        expires_at=issued.lease.expires_at,
    )
    mismatched_issuance_snapshot = dict(payload)
    mismatched_issuance_snapshot["lease"] = (
        alternate_lease.to_envelope().to_dict()
    )
    with pytest.raises(EventIntegrityError, match="does not bind"):
        EventV1.create(
            mission_id=issued.event.mission_id,
            seq=issued.event.seq,
            kind=issued.event.kind,
            unit=issued.event.unit,
            authority_id=issued.event.authority_id,
            target_id=issued.event.target_id,
            decision_time=issued.event.decision_time,
            payload=mismatched_issuance_snapshot,
            prev_digest=issued.event.prev_digest,
        )

    wrong_nonce_lease = VerificationLeaseV1.issue(
        lease_nonce="f" * 32,
        mission_id=issued.lease.mission_id,
        authority_id=issued.lease.authority_id,
        target_snapshot_id=issued.lease.target_snapshot_id,
        candidate_id=issued.lease.candidate_id,
        candidate_producer_id=issued.lease.candidate_producer_id,
        poc_artifact_digest=issued.lease.poc_artifact_digest,
        evidence_artifact_digests=issued.lease.evidence_artifact_digests,
        environment_digest=issued.lease.environment_digest,
        effect_oracle_id=issued.lease.effect_oracle_id,
        verifier_id=issued.lease.verifier_id,
        verifier_key_id=issued.lease.verifier_key_id,
        issuance_trust_snapshot_id=(
            issued.lease.issuance_trust_snapshot_id
        ),
        issued_at=issued.lease.issued_at,
        expires_at=issued.lease.expires_at,
    )
    wrong_nonce = dict(payload)
    wrong_nonce["lease"] = wrong_nonce_lease.to_envelope().to_dict()
    with pytest.raises(EventIntegrityError, match="kernel-derived"):
        EventV1.create(
            mission_id=issued.event.mission_id,
            seq=issued.event.seq,
            kind=issued.event.kind,
            unit=issued.event.unit,
            authority_id=issued.event.authority_id,
            target_id=issued.event.target_id,
            decision_time=issued.event.decision_time,
            payload=wrong_nonce,
            prev_digest=issued.event.prev_digest,
        )

    static_root = tmp_path / "static"
    static_root.mkdir()
    static_root.chmod(0o700)
    static_harness = _setup(
        static_root,
        permitted_actions=("static_analysis",),
        nonce="static-only",
    )
    with SQLiteEventStore(static_root / "events.sqlite3") as static_store:
        class _CrashAtScan:
            def load(self, mission_id: str):
                return static_store.load(mission_id)

            def append(self, event: EventV1, *, expected_head: str):
                result = static_store.append(event, expected_head=expected_head)
                if event.kind == "scan_completed":
                    raise RuntimeError("stop after scan")
                return result

        with pytest.raises(RuntimeError, match="stop after scan"):
            run_fixture_scan(
                mission_id=static_harness.mission_id,
                snapshot=static_harness.snapshot,
                signed_authority=static_harness.signed_authority,
                trust_store=static_harness.authority_trust,
                evidence_store=static_harness.evidence_store,
                event_store=_CrashAtScan(),
                decision_time=NOW,
            )
        static_projection = reduce_events(
            static_store.load(static_harness.mission_id)
        )
        static_candidate = _candidate_id(static_projection)
        static_head = static_projection.events[-1].event_digest
        expires_at = NOW + 30
        nonce = derive_verification_lease_nonce(
            prior_event_digest=static_head,
            mission_id=static_projection.mission_id,
            authority_id=static_projection.authority_id,
            target_snapshot_id=static_projection.target_id,
            candidate_id=static_candidate,
            candidate_producer_id="VELITES",
            poc_artifact_digest=bindings["poc_artifact_digest"],
            evidence_artifact_digests=bindings[
                "evidence_artifact_digests"
            ],
            environment_digest=bindings["environment_digest"],
            effect_oracle_id=bindings["effect_oracle_id"],
            verifier_id="CATO",
            verifier_key_id=signer.key_id,
            issued_at=NOW + 1,
            expires_at=expires_at,
            issuance_trust_snapshot_id=verifier_trust.snapshot_id,
        )
        lease = VerificationLeaseV1.issue(
            lease_nonce=nonce,
            mission_id=static_projection.mission_id,
            authority_id=static_projection.authority_id,
            target_snapshot_id=static_projection.target_id,
            candidate_id=static_candidate,
            candidate_producer_id="VELITES",
            poc_artifact_digest=bindings["poc_artifact_digest"],
            evidence_artifact_digests=bindings[
                "evidence_artifact_digests"
            ],
            environment_digest=bindings["environment_digest"],
            effect_oracle_id=bindings["effect_oracle_id"],
            verifier_id="CATO",
            verifier_key_id=signer.key_id,
            issuance_trust_snapshot_id=verifier_trust.snapshot_id,
            issued_at=NOW + 1,
            expires_at=expires_at,
        )
        unauthorized_event = EventV1.create(
            mission_id=static_projection.mission_id,
            seq=len(static_projection.events),
            kind="verification_lease_issued",
            unit="AQUILA",
            authority_id=static_projection.authority_id,
            target_id=static_projection.target_id,
            decision_time=NOW + 1,
            payload={
                "lease": lease.to_envelope().to_dict(),
                "verifier_trust_snapshot": (
                    verifier_trust.to_snapshot_body()
                ),
                "verifier_trust_snapshot_id": verifier_trust.snapshot_id,
            },
            prev_digest=static_head,
        )
        with pytest.raises(ReductionError, match="lacks admitted"):
            reduce_events(
                (*static_projection.events, unauthorized_event)
            )
