"""Adversarial evidence for replayable typed verification-artifact resolution."""

from __future__ import annotations

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
    FileEvidenceStore,
    TargetSnapshotV1,
    read_etzio_fixture,
    retain_snapshot,
)
from etzio.kernel.artifact_resolution import (
    VerificationArtifactResolution,
    VerificationArtifactResolutionError,
    resolve_modeled_fixture_verification_artifacts,
)
from etzio.kernel.events_v1 import EventIntegrityError, EventV1
from etzio.kernel.fixture_scan import prepare_fixture_scan_for_verification
from etzio.kernel.reducer import ProjectionPhase, ReductionError, reduce_events
from etzio.kernel.store import (
    SQLiteEventStore,
    StaleHeadError,
    StoreCapacityError,
)
from etzio.kernel.verification_lease import (
    issue_modeled_fixture_verification_lease,
)
from etzio.kernel.verification_recovery import (
    cancel_modeled_fixture_verification_lease,
    reassign_modeled_fixture_verification_lease,
)
from etzio.protocol import EnvelopeV1, canonical_dumps, content_id, thaw_json
from etzio.verification import (
    VERIFIER_ROLE,
    TrustedVerifierKey,
    VerificationLeaseV1,
    VerifierSigner,
    VerifierTrustStore,
)
from etzio.verification_artifacts import (
    RESOLUTION_PROFILE_V1,
    TARGET_ARTIFACT_TYPE_V1,
    TargetArtifactBindingV1,
    VerificationArtifactBindingV1,
    VerificationArtifactError,
    VerificationArtifactResolutionV1,
)

NOW = 2_000_000_000


def _digest(character: str) -> str:
    return "sha256:" + character * 64


@dataclass(frozen=True, slots=True)
class _Harness:
    database: Path
    evidence_store: FileEvidenceStore
    mission_id: str
    lease: VerificationLeaseV1
    lease_head: str
    pre_resolution_events: tuple[EventV1, ...]
    bindings: dict[str, object]
    verifier_signer: VerifierSigner
    verifier_trust: VerifierTrustStore


def _typed_bindings(
    evidence_store: FileEvidenceStore,
    *,
    suffix: bytes = b"",
    large_poc: bytes | None = None,
) -> dict[str, object]:
    poc = evidence_store.put_typed(
        large_poc if large_poc is not None else b"inert-poc" + suffix,
        artifact_type=VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["poc"],
    )
    evidence = tuple(
        sorted(
            (
                evidence_store.put_typed(
                    b"supporting-a" + suffix,
                    artifact_type=(VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["evidence"]),
                ).digest,
                evidence_store.put_typed(
                    b"supporting-b" + suffix,
                    artifact_type=(VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["evidence"]),
                ).digest,
            )
        )
    )
    environment = evidence_store.put_typed(
        b"environment-spec" + suffix,
        artifact_type=VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["environment"],
    )
    oracle = evidence_store.put_typed(
        b"effect-oracle" + suffix,
        artifact_type=VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["effect_oracle"],
    )
    return {
        "poc_artifact_digest": poc.digest,
        "evidence_artifact_digests": evidence,
        "environment_digest": environment.digest,
        "effect_oracle_id": oracle.digest,
    }


def _setup(
    root: Path,
    *,
    grant_max_bytes: int = 1024 * 1024,
    bindings_mutator=None,
) -> _Harness:
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
        subject="benchmark:typed-artifact-resolution",
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
        max_bytes=grant_max_bytes,
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
    mission_id = content_id(
        "mission",
        {"fixture": relative_path, "nonce": root.name},
    )
    database = root / "events.sqlite3"
    bindings = _typed_bindings(evidence_store)
    if bindings_mutator is not None:
        bindings = bindings_mutator(evidence_store, bindings)
    verifier_signer = VerifierSigner.generate()
    verifier_trust = VerifierTrustStore.from_keys(
        (
            TrustedVerifierKey(
                verifier_id="CATO",
                public_key_bytes=verifier_signer.public_key_bytes,
                roles=frozenset({VERIFIER_ROLE}),
            ),
        )
    )
    with SQLiteEventStore(database) as store:
        prepared = prepare_fixture_scan_for_verification(
            mission_id=mission_id,
            snapshot=snapshot,
            signed_authority=signed_grant,
            trust_store=authority_trust,
            evidence_store=evidence_store,
            event_store=store,
            decision_time=NOW,
        )
        candidate_id = thaw_json(prepared.candidate_events[0].payload)["candidate"]["object_id"]
        issued = issue_modeled_fixture_verification_lease(
            event_store=store,
            mission_id=mission_id,
            expected_head=prepared.events[-1].event_digest,
            candidate_id=candidate_id,
            **bindings,
            verifier_key_id=verifier_signer.key_id,
            verifier_trust_store=verifier_trust,
            decision_time=NOW + 1,
            requested_wallclock_seconds=60,
        )
    return _Harness(
        database=database,
        evidence_store=evidence_store,
        mission_id=mission_id,
        lease=issued.lease,
        lease_head=issued.event.event_digest,
        pre_resolution_events=issued.projection.events,
        bindings=bindings,
        verifier_signer=verifier_signer,
        verifier_trust=verifier_trust,
    )


def _resolve(
    harness: _Harness,
    *,
    event_store,
    expected_head: str | None = None,
    decision_time: int = NOW + 2,
) -> VerificationArtifactResolution:
    return resolve_modeled_fixture_verification_artifacts(
        event_store=event_store,
        evidence_store=harness.evidence_store,
        mission_id=harness.mission_id,
        expected_head=expected_head or harness.lease_head,
        verification_lease_id=harness.lease.lease_id,
        decision_time=decision_time,
    )


def test_typed_resolution_propagates_vault_capacity_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _setup(tmp_path)

    def capacity_failure(self, requests, evidence_store, *, maximum_total):
        raise StoreCapacityError("simulated resolution vault capacity failure")

    monkeypatch.setattr(
        SQLiteEventStore,
        "resolve_evidence_artifacts",
        capacity_failure,
    )
    with SQLiteEventStore(harness.database) as store:
        with pytest.raises(
            StoreCapacityError,
            match="simulated resolution vault capacity failure",
        ):
            _resolve(harness, event_store=store)


def test_resolution_is_content_bound_replayable_and_nonconsequential(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    with SQLiteEventStore(harness.database) as store:
        result = _resolve(harness, event_store=store)
        replayed = reduce_events(store.load(harness.mission_id))

    assert result.event.kind == "verification_artifacts_resolved"
    assert result.event.unit == "ETZIO"
    assert result.resolution.resolution_profile == RESOLUTION_PROFILE_V1
    assert result.resolution.resolution_id == (result.resolution.to_envelope().object_id)
    assert result.projection.phase is ProjectionPhase.AWAITING_VERIFICATION
    assert replayed.phase is ProjectionPhase.AWAITING_VERIFICATION
    assert replayed.verification_artifact_resolution_events == (result.event,)
    assert result.resolution.poc_artifact.artifact_type == (VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["poc"])
    assert (
        tuple(item.artifact_digest for item in result.resolution.evidence_artifacts)
        == harness.lease.evidence_artifact_digests
    )
    assert all(item.artifact_type == TARGET_ARTIFACT_TYPE_V1 for item in result.resolution.target_artifacts)
    assert not hasattr(result.resolution, "receipt_id")
    assert not hasattr(result.resolution, "verdict")
    assert not hasattr(result.resolution, "finding_id")
    assert not hasattr(result.resolution, "consumed")


def test_resolution_identity_and_evidence_order_are_canonical(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    with SQLiteEventStore(harness.database) as store:
        result = _resolve(harness, event_store=store)

    with pytest.raises(VerificationArtifactError) as identity_error:
        replace(result.resolution, resolution_id=_digest("f"))
    assert identity_error.value.reason_code == "object_id_mismatch"

    with pytest.raises(VerificationArtifactError) as binding_error:
        replace(result.resolution, poc_artifact=None)
    assert binding_error.value.reason_code == "invalid_artifact_binding"

    body = thaw_json(result.resolution.to_envelope().body)
    body["evidence_artifacts"] = list(reversed(body["evidence_artifacts"]))
    reordered = EnvelopeV1.create(
        "verification_artifact_resolution",
        body,
    )
    with pytest.raises(VerificationArtifactError) as order_error:
        VerificationArtifactResolutionV1.from_envelope(reordered)
    assert order_error.value.reason_code == ("noncanonical_evidence_artifacts")


def test_resolution_value_enforces_the_fixed_typed_input_ceiling() -> None:
    mib = 1024 * 1024
    with pytest.raises(VerificationArtifactError) as caught:
        VerificationArtifactResolutionV1.issue(
            authority_id=_digest("1"),
            candidate_id=_digest("2"),
            effect_oracle_artifact=VerificationArtifactBindingV1(
                artifact_digest=_digest("3"),
                artifact_type=VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["effect_oracle"],
                size=16 * mib,
            ),
            environment_artifact=VerificationArtifactBindingV1(
                artifact_digest=_digest("4"),
                artifact_type=VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["environment"],
                size=16 * mib,
            ),
            evidence_artifacts=(
                VerificationArtifactBindingV1(
                    artifact_digest=_digest("5"),
                    artifact_type=VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["evidence"],
                    size=1,
                ),
            ),
            mission_id=_digest("6"),
            poc_artifact=VerificationArtifactBindingV1(
                artifact_digest=_digest("7"),
                artifact_type=VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["poc"],
                size=32 * mib,
            ),
            resolved_at=NOW,
            target_artifacts=(
                TargetArtifactBindingV1(
                    artifact_digest=_digest("8"),
                    artifact_type=TARGET_ARTIFACT_TYPE_V1,
                    relative_path="vulnerable_app.py",
                    size=0,
                ),
            ),
            target_snapshot_id=_digest("9"),
            verification_lease_id=_digest("a"),
        )

    assert caught.value.reason_code == "resolution_byte_ceiling_exceeded"


def test_missing_typed_artifact_appends_no_partial_state(
    tmp_path: Path,
) -> None:
    def missing_poc(
        _store: FileEvidenceStore,
        bindings: dict[str, object],
    ) -> dict[str, object]:
        return {**bindings, "poc_artifact_digest": _digest("f")}

    harness = _setup(tmp_path, bindings_mutator=missing_poc)
    with SQLiteEventStore(harness.database) as store:
        with pytest.raises(VerificationArtifactResolutionError) as caught:
            _resolve(harness, event_store=store)
        projection = reduce_events(store.load(harness.mission_id))

    assert caught.value.reason_code == "poc_artifact_unavailable"
    assert projection.verification_artifact_resolution_events == ()


@pytest.mark.parametrize("position", (0, 1, 2), ids=("first", "middle", "last"))
@pytest.mark.parametrize("failure_mode", ("missing", "wrong_type"))
def test_each_evidence_position_fails_closed_for_missing_or_wrong_typed_bytes(
    tmp_path: Path,
    position: int,
    failure_mode: str,
) -> None:
    def invalid_evidence(
        store: FileEvidenceStore,
        bindings: dict[str, object],
    ) -> dict[str, object]:
        if failure_mode == "missing":
            invalid_digest = (_digest("0"), _digest("8"), _digest("f"))[position]
        else:
            invalid_digest = store.put_typed(
                f"wrong-evidence-role-{position}".encode(),
                artifact_type=VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["environment"],
            ).digest

        below: list[str] = []
        above: list[str] = []
        nonce = 0
        while (
            (position == 0 and len(above) < 2)
            or (position == 1 and (not below or not above))
            or (position == 2 and len(below) < 2)
        ):
            candidate = store.put_typed(
                f"positioned-evidence-{position}-{failure_mode}-{nonce}".encode(),
                artifact_type=VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["evidence"],
            ).digest
            if candidate < invalid_digest and len(below) < 2:
                below.append(candidate)
            elif candidate > invalid_digest and len(above) < 2:
                above.append(candidate)
            nonce += 1
            assert nonce < 10_000

        if position == 0:
            valid_digests = above[:2]
        elif position == 1:
            valid_digests = [below[0], above[0]]
        else:
            valid_digests = below[:2]
        evidence_digests = tuple(sorted((*valid_digests, invalid_digest)))
        assert evidence_digests[position] == invalid_digest
        return {
            **bindings,
            "evidence_artifact_digests": evidence_digests,
        }

    harness = _setup(tmp_path, bindings_mutator=invalid_evidence)
    with SQLiteEventStore(harness.database) as store:
        with pytest.raises(VerificationArtifactResolutionError) as caught:
            _resolve(harness, event_store=store)
        projection = reduce_events(store.load(harness.mission_id))

    assert caught.value.reason_code == "evidence_artifact_unavailable"
    assert projection.verification_artifact_resolution_events == ()


def test_wrong_typed_role_appends_no_partial_state(
    tmp_path: Path,
) -> None:
    def wrong_poc(
        store: FileEvidenceStore,
        bindings: dict[str, object],
    ) -> dict[str, object]:
        wrong = store.put_typed(
            b"wrong-role",
            artifact_type=VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["environment"],
        )
        return {**bindings, "poc_artifact_digest": wrong.digest}

    harness = _setup(tmp_path, bindings_mutator=wrong_poc)
    with SQLiteEventStore(harness.database) as store:
        with pytest.raises(VerificationArtifactResolutionError) as caught:
            _resolve(harness, event_store=store)
        projection = reduce_events(store.load(harness.mission_id))

    assert caught.value.reason_code == "poc_artifact_unavailable"
    assert projection.verification_artifact_resolution_events == ()


def test_canonical_target_vault_wins_over_staging_substitution_before_resolution(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    with SQLiteEventStore(harness.database) as store:
        snapshot_event = next(event for event in store.load(harness.mission_id) if event.kind == "mission_opened")
    snapshot = TargetSnapshotV1.from_envelope(
        EnvelopeV1.from_bytes(canonical_dumps(thaw_json(snapshot_event.payload)["target_snapshot"]))
    )
    target_digest = snapshot.files[0].artifact_digest
    harness.evidence_store._path_for(target_digest).write_bytes(b"substituted-target")

    with SQLiteEventStore(harness.database) as store:
        resolved = _resolve(harness, event_store=store)
        projection = reduce_events(store.load(harness.mission_id))

    assert not resolved.replayed
    assert resolved.resolution.target_artifacts[0].artifact_digest == target_digest
    assert projection.verification_artifact_resolution_events == (resolved.event,)


def test_typed_inputs_cannot_exceed_the_budget_remaining_after_target_bytes(
    tmp_path: Path,
) -> None:
    def oversized_inputs(
        store: FileEvidenceStore,
        bindings: dict[str, object],
    ) -> dict[str, object]:
        oversized = store.put_typed(
            b"x" * 965,
            artifact_type=VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["poc"],
        )
        return {**bindings, "poc_artifact_digest": oversized.digest}

    harness = _setup(
        tmp_path,
        grant_max_bytes=1928,
        bindings_mutator=oversized_inputs,
    )
    with SQLiteEventStore(harness.database) as store:
        with pytest.raises(VerificationArtifactResolutionError) as caught:
            _resolve(harness, event_store=store)
        projection = reduce_events(store.load(harness.mission_id))

    assert caught.value.reason_code == "resolution_byte_ceiling_exceeded"
    assert projection.verification_artifact_resolution_events == ()


def test_target_and_typed_inputs_share_the_signed_grant_byte_budget(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path, grant_max_bytes=964)
    with SQLiteEventStore(harness.database) as store:
        with pytest.raises(VerificationArtifactResolutionError) as caught:
            _resolve(harness, event_store=store)
        projection = reduce_events(store.load(harness.mission_id))

    assert caught.value.reason_code == "resolution_byte_ceiling_exceeded"
    assert projection.verification_artifact_resolution_events == ()


@pytest.mark.parametrize(
    ("decision_time", "reason_code"),
    (
        (NOW, "decision_time_regressed"),
        (NOW + 61, "verification_lease_expired"),
    ),
)
def test_resolution_requires_monotonic_time_inside_the_lease(
    tmp_path: Path,
    decision_time: int,
    reason_code: str,
) -> None:
    harness = _setup(tmp_path)
    with SQLiteEventStore(harness.database) as store:
        with pytest.raises(VerificationArtifactResolutionError) as caught:
            _resolve(
                harness,
                event_store=store,
                decision_time=decision_time,
            )

    assert caught.value.reason_code == reason_code


def test_exact_retry_revalidates_cas_and_returns_one_event(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    with SQLiteEventStore(harness.database) as store:
        first = _resolve(harness, event_store=store)
        retry = _resolve(harness, event_store=store)
        projection = reduce_events(store.load(harness.mission_id))

    assert not first.replayed
    assert retry.replayed
    assert retry.event == first.event
    assert retry.resolution == first.resolution
    assert len(projection.verification_artifact_resolution_events) == 1


def test_stale_head_is_rejected_before_first_resolution(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    stale = harness.pre_resolution_events[-2].event_digest
    with SQLiteEventStore(harness.database) as store:
        with pytest.raises(StaleHeadError):
            _resolve(
                harness,
                event_store=store,
                expected_head=stale,
            )


def test_unknown_lease_is_rejected_without_an_event(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    with SQLiteEventStore(harness.database) as store:
        with pytest.raises(VerificationArtifactResolutionError) as caught:
            resolve_modeled_fixture_verification_artifacts(
                event_store=store,
                evidence_store=harness.evidence_store,
                mission_id=harness.mission_id,
                expected_head=harness.lease_head,
                verification_lease_id=_digest("f"),
                decision_time=NOW + 2,
            )
        projection = reduce_events(store.load(harness.mission_id))

    assert caught.value.reason_code == "verification_lease_not_retained"
    assert projection.verification_artifact_resolution_events == ()


def test_conflicting_retry_time_is_rejected_without_a_second_event(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    with SQLiteEventStore(harness.database) as store:
        first = _resolve(harness, event_store=store)
        with pytest.raises(VerificationArtifactResolutionError) as caught:
            _resolve(
                harness,
                event_store=store,
                decision_time=NOW + 3,
            )
        projection = reduce_events(store.load(harness.mission_id))

    assert caught.value.reason_code == ("verification_lease_resolution_conflict")
    assert projection.verification_artifact_resolution_events == (first.event,)


def test_identical_two_writer_race_converges_to_one_resolution(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    barrier = Barrier(2)

    def worker() -> VerificationArtifactResolution:
        with SQLiteEventStore(harness.database) as store:
            barrier.wait()
            return _resolve(harness, event_store=store)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: worker(), range(2)))
    with SQLiteEventStore(harness.database) as store:
        projection = reduce_events(store.load(harness.mission_id))

    assert results[0].event == results[1].event
    assert {result.replayed for result in results} == {False, True}
    assert len(projection.verification_artifact_resolution_events) == 1


def test_different_lease_race_requires_stale_retry_for_second_resolution(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    second_bindings = _typed_bindings(
        harness.evidence_store,
        suffix=b"-second-lease",
    )
    second_signer = VerifierSigner.generate()
    second_trust = VerifierTrustStore.from_keys(
        (
            TrustedVerifierKey(
                verifier_id="VIGILES",
                public_key_bytes=second_signer.public_key_bytes,
                roles=frozenset({VERIFIER_ROLE}),
            ),
        )
    )
    with SQLiteEventStore(harness.database) as store:
        projection = reduce_events(store.load(harness.mission_id))
        second_candidate_id = thaw_json(projection.candidate_events[1].payload)["candidate"]["object_id"]
        second_issuance = issue_modeled_fixture_verification_lease(
            event_store=store,
            mission_id=harness.mission_id,
            expected_head=harness.lease_head,
            candidate_id=second_candidate_id,
            **second_bindings,
            verifier_key_id=second_signer.key_id,
            verifier_trust_store=second_trust,
            decision_time=NOW + 2,
            requested_wallclock_seconds=60,
        )

    shared_head = second_issuance.event.event_digest
    lease_ids = (harness.lease.lease_id, second_issuance.lease.lease_id)
    barrier = Barrier(2)

    def worker(
        lease_id: str,
    ) -> tuple[str, VerificationArtifactResolution | StaleHeadError]:
        with SQLiteEventStore(harness.database) as store:
            barrier.wait()
            try:
                outcome: VerificationArtifactResolution | StaleHeadError = (
                    resolve_modeled_fixture_verification_artifacts(
                        event_store=store,
                        evidence_store=harness.evidence_store,
                        mission_id=harness.mission_id,
                        expected_head=shared_head,
                        verification_lease_id=lease_id,
                        decision_time=NOW + 3,
                    )
                )
            except StaleHeadError as exc:
                outcome = exc
            return lease_id, outcome

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(worker, lease_ids))

    successes = [
        (lease_id, outcome)
        for lease_id, outcome in outcomes
        if isinstance(outcome, VerificationArtifactResolution)
    ]
    stale = [
        (lease_id, outcome)
        for lease_id, outcome in outcomes
        if isinstance(outcome, StaleHeadError)
    ]
    assert len(successes) == 1
    assert len(stale) == 1
    assert not successes[0][1].replayed

    with SQLiteEventStore(harness.database) as store:
        second_resolution = resolve_modeled_fixture_verification_artifacts(
            event_store=store,
            evidence_store=harness.evidence_store,
            mission_id=harness.mission_id,
            expected_head=successes[0][1].event.event_digest,
            verification_lease_id=stale[0][0],
            decision_time=NOW + 3,
        )
        projection = reduce_events(store.load(harness.mission_id))

    resolutions = tuple(
        VerificationArtifactResolutionV1.from_envelope(
            EnvelopeV1.from_bytes(
                canonical_dumps(thaw_json(event.payload)["resolution"])
            )
        )
        for event in projection.verification_artifact_resolution_events
    )
    assert not second_resolution.replayed
    assert len(resolutions) == 2
    assert {resolution.verification_lease_id for resolution in resolutions} == set(lease_ids)
    assert len({resolution.resolution_id for resolution in resolutions}) == 2


class _CrashAfterResolutionAppend:
    def __init__(self, store: SQLiteEventStore) -> None:
        self.store = store
        self.crashed = False

    def load(self, mission_id: str):
        return self.store.load(mission_id)

    def load_event_artifact(
        self,
        event_digest: str,
        role: str,
        ordinal: int = 0,
    ):
        return self.store.load_event_artifact(event_digest, role, ordinal)

    def load_event_artifacts(self, selectors, *, maximum_total: int):
        return self.store.load_event_artifacts(
            selectors,
            maximum_total=maximum_total,
        )

    def resolve_evidence_artifact(
        self,
        role: str,
        digest: str,
        maximum: int,
        evidence_store: FileEvidenceStore,
    ):
        return self.store.resolve_evidence_artifact(
            role,
            digest,
            maximum,
            evidence_store,
        )

    def resolve_evidence_artifacts(
        self,
        requests,
        evidence_store: FileEvidenceStore,
        *,
        maximum_total: int,
    ):
        return self.store.resolve_evidence_artifacts(
            requests,
            evidence_store,
            maximum_total=maximum_total,
        )

    def append_evidence_event(
        self,
        event: EventV1,
        *,
        expected_head: str,
        evidence_store: FileEvidenceStore,
    ):
        result = self.store.append_evidence_event(
            event,
            expected_head=expected_head,
            evidence_store=evidence_store,
        )
        if event.kind == "verification_artifacts_resolved" and not self.crashed:
            self.crashed = True
            raise RuntimeError("simulated process loss after durable resolution")
        return result


def test_crash_after_append_reopens_as_the_same_resolution(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    with SQLiteEventStore(harness.database) as store:
        crashing = _CrashAfterResolutionAppend(store)
        with pytest.raises(RuntimeError, match="simulated process loss"):
            _resolve(harness, event_store=crashing)

    with SQLiteEventStore(harness.database) as store:
        recovered = _resolve(harness, event_store=store)
        projection = reduce_events(store.load(harness.mission_id))

    assert recovered.replayed
    assert len(projection.verification_artifact_resolution_events) == 1


def test_forged_target_binding_is_rejected_by_pure_replay(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    with SQLiteEventStore(harness.database) as store:
        result = _resolve(harness, event_store=store)

    prefix = result.projection.events[:-1]
    body = thaw_json(result.resolution.to_envelope().body)
    body["target_artifacts"][0]["artifact_digest"] = _digest("f")
    forged_resolution = VerificationArtifactResolutionV1.from_envelope(
        EnvelopeV1.create(
            "verification_artifact_resolution",
            body,
        )
    )
    forged_event = EventV1.create(
        mission_id=harness.mission_id,
        seq=len(prefix),
        kind="verification_artifacts_resolved",
        unit="ETZIO",
        authority_id=prefix[0].authority_id,
        target_id=prefix[0].target_id,
        decision_time=NOW + 2,
        payload={"resolution": forged_resolution.to_envelope().to_dict()},
        prev_digest=prefix[-1].event_digest,
    )

    with pytest.raises(
        ReductionError,
        match="target bindings differ",
    ):
        reduce_events((*prefix, forged_event))


def test_tampered_event_digest_is_rejected(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    with SQLiteEventStore(harness.database) as store:
        result = _resolve(harness, event_store=store)

    with pytest.raises(EventIntegrityError):
        replace(result.event, event_digest=_digest("f"))


def test_exact_retry_uses_canonical_vault_when_staging_bytes_disappear(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    with SQLiteEventStore(harness.database) as store:
        result = _resolve(harness, event_store=store)
    poc_digest = result.resolution.poc_artifact.artifact_digest
    harness.evidence_store._path_for(poc_digest).unlink()

    with SQLiteEventStore(harness.database) as store:
        replayed = _resolve(harness, event_store=store)
        historical = reduce_events(store.load(harness.mission_id))

    assert replayed.replayed
    assert replayed.event == result.event
    assert replayed.resolution == result.resolution
    assert historical.verification_artifact_resolution_events == (result.event,)


def test_new_resolution_reuses_canonical_typed_inputs_after_staging_loss(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    with SQLiteEventStore(harness.database) as store:
        first = _resolve(harness, event_store=store)
        projection = reduce_events(store.load(harness.mission_id))
        second_candidate_id = thaw_json(
            projection.candidate_events[1].payload
        )["candidate"]["object_id"]
        second_lease = issue_modeled_fixture_verification_lease(
            event_store=store,
            mission_id=harness.mission_id,
            expected_head=first.event.event_digest,
            candidate_id=second_candidate_id,
            **harness.bindings,
            verifier_key_id=harness.verifier_signer.key_id,
            verifier_trust_store=harness.verifier_trust,
            decision_time=NOW + 3,
            requested_wallclock_seconds=60,
        )
        typed_digests = (
            harness.bindings["poc_artifact_digest"],
            *harness.bindings["evidence_artifact_digests"],
            harness.bindings["environment_digest"],
            harness.bindings["effect_oracle_id"],
        )
        for digest in typed_digests:
            assert isinstance(digest, str)
            harness.evidence_store._path_for(digest).unlink()

        reused = resolve_modeled_fixture_verification_artifacts(
            event_store=store,
            evidence_store=harness.evidence_store,
            mission_id=harness.mission_id,
            expected_head=second_lease.event.event_digest,
            verification_lease_id=second_lease.lease.lease_id,
            decision_time=NOW + 4,
        )

    assert not reused.replayed
    assert reused.resolution.poc_artifact == first.resolution.poc_artifact
    assert reused.resolution.evidence_artifacts == (
        first.resolution.evidence_artifacts
    )
    assert reused.resolution.environment_artifact == (
        first.resolution.environment_artifact
    )
    assert reused.resolution.effect_oracle_artifact == (
        first.resolution.effect_oracle_artifact
    )


def test_cancelled_lease_rejects_even_an_exact_historical_resolution_retry(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    with SQLiteEventStore(harness.database) as store:
        resolved = _resolve(harness, event_store=store)
        cancelled = cancel_modeled_fixture_verification_lease(
            event_store=store,
            mission_id=harness.mission_id,
            expected_head=resolved.event.event_digest,
            verification_lease_id=harness.lease.lease_id,
            reason_code="operator_cancelled",
            decision_time=NOW + 3,
        )
        with pytest.raises(VerificationArtifactResolutionError) as caught:
            _resolve(
                harness,
                event_store=store,
                expected_head=cancelled.event.event_digest,
            )

    assert caught.value.reason_code == "verification_lease_inactive"


def test_successor_requires_and_retains_its_own_fresh_resolution(
    tmp_path: Path,
) -> None:
    harness = _setup(tmp_path)
    successor_signer = VerifierSigner.generate()
    successor_trust = VerifierTrustStore.from_keys(
        (
            TrustedVerifierKey(
                verifier_id="CATO-2",
                public_key_bytes=successor_signer.public_key_bytes,
                roles=frozenset({VERIFIER_ROLE}),
            ),
        )
    )
    with SQLiteEventStore(harness.database) as store:
        predecessor_resolution = _resolve(harness, event_store=store)
        reassigned = reassign_modeled_fixture_verification_lease(
            event_store=store,
            mission_id=harness.mission_id,
            expected_head=predecessor_resolution.event.event_digest,
            predecessor_verification_lease_id=harness.lease.lease_id,
            verifier_key_id=successor_signer.key_id,
            verifier_trust_store=successor_trust,
            decision_time=NOW + 3,
            requested_wallclock_seconds=30,
        )
        with pytest.raises(VerificationArtifactResolutionError) as old:
            resolve_modeled_fixture_verification_artifacts(
                event_store=store,
                evidence_store=harness.evidence_store,
                mission_id=harness.mission_id,
                expected_head=reassigned.event.event_digest,
                verification_lease_id=harness.lease.lease_id,
                decision_time=NOW + 4,
            )
        successor_resolution = (
            resolve_modeled_fixture_verification_artifacts(
                event_store=store,
                evidence_store=harness.evidence_store,
                mission_id=harness.mission_id,
                expected_head=reassigned.event.event_digest,
                verification_lease_id=reassigned.lease.lease_id,
                decision_time=NOW + 4,
            )
        )
        projection = reduce_events(store.load(harness.mission_id))

    assert old.value.reason_code == "verification_lease_inactive"
    assert successor_resolution.resolution.verification_lease_id == (
        reassigned.lease.lease_id
    )
    assert successor_resolution.resolution.resolution_id != (
        predecessor_resolution.resolution.resolution_id
    )
    assert len(projection.verification_artifact_resolution_events) == 2
