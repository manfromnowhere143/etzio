"""End-to-end evidence for the governed, fixture-only static-analysis mission."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from etzio.authority import (
    AuthorityGrantV1,
    AuthoritySigner,
    TrustedAuthorityKey,
    TrustStore,
)
from etzio.evidence import (
    FileEvidenceStore,
    read_etzio_fixture,
    retain_snapshot,
)
from etzio.kernel.fixture_scan import (
    UNADMITTED_AUTHORITY_ID,
    FixtureMissionError,
    run_fixture_scan,
)
from etzio.kernel.reducer import ProjectionPhase
from etzio.kernel.store import SQLiteEventStore, StoreCapacityError
from etzio.mission_v1 import StaticCandidateV1
from etzio.protocol import EnvelopeV1, canonical_dumps, content_id, thaw_json

NOW = 2_000_000_000


def _setup(
    root: Path,
    *,
    fixture_name: str = "vulnerable_app.py",
    grant_overrides: dict[str, object] | None = None,
    signer: AuthoritySigner | None = None,
    mission_nonce: str = "run-1",
):
    evidence_store = FileEvidenceStore(root / "evidence")
    relative_path, fixture_bytes = read_etzio_fixture(fixture_name, maximum=64 * 1024)
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
    signer = signer or AuthoritySigner.generate()
    values: dict[str, object] = {
        "issuer": "operator:daniel",
        "subject": "benchmark:etzio-python-fixture-v1",
        "target_snapshot_id": snapshot.object_id,
        "assets": (f"fixture://{relative_path}",),
        "permitted_actions": ("static_analysis",),
        "evidence_digest": authority_evidence.digest,
        "issued_at": NOW - 1,
        "not_before": NOW,
        "expires_at": NOW + 300,
        "max_bytes": len(fixture_bytes),
        "max_candidates": 100,
        "max_wallclock_seconds": 60,
    }
    values.update(grant_overrides or {})
    grant = AuthorityGrantV1.issue(**values)  # type: ignore[arg-type]
    signed = signer.sign(grant)
    trusted_key = TrustedAuthorityKey(
        signer.public_key_bytes,
        frozenset({"operator"}),
        frozenset({"operator:daniel"}),
    )
    trust_store = TrustStore.from_keys((trusted_key,))
    mission_id = content_id(
        "mission",
        {"fixture": fixture_name, "nonce": mission_nonce},
    )
    return (
        evidence_store,
        snapshot,
        signed,
        trust_store,
        mission_id,
        fixture_bytes,
    )


def _run(
    store,
    setup,
    *,
    decision_time: int = NOW,
    cancel_requested: bool = False,
    monotonic_ns: Callable[[], int] | None = None,
):
    evidence_store, snapshot, signed, trust_store, mission_id, _ = setup
    kwargs = {}
    if monotonic_ns is not None:
        kwargs["monotonic_ns"] = monotonic_ns
    return run_fixture_scan(
        mission_id=mission_id,
        snapshot=snapshot,
        signed_authority=signed,
        trust_store=trust_store,
        evidence_store=evidence_store,
        event_store=store,
        decision_time=decision_time,
        cancel_requested=cancel_requested,
        **kwargs,
    )


def test_vulnerable_fixture_runs_end_to_end_without_minting_findings_or_leaking_source(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    with SQLiteEventStore(tmp_path / "events.sqlite3") as store:
        projection = _run(store, setup)
        reloaded = store.load(setup[4])

    assert projection.phase is ProjectionPhase.CLOSED
    assert projection.events == reloaded
    assert len(projection.candidate_events) == 7
    assert projection.parse_failures == ()
    assert [event.kind for event in projection.events[:3]] == [
        "authority_admitted",
        "mission_opened",
        "analysis_lease_issued",
    ]
    assert projection.events[-2].kind == "scan_completed"
    assert projection.events[-1].kind == "mission_closed"

    candidates = []
    for event in projection.candidate_events:
        envelope = EnvelopeV1.from_bytes(
            canonical_dumps(thaw_json(event.payload)["candidate"])
        )
        candidates.append(StaticCandidateV1.from_envelope(envelope))
    assert len({candidate.candidate_id for candidate in candidates}) == 7
    assert len({candidate.claim_id for candidate in candidates}) == 7
    retained_event_bytes = b"\n".join(
        event.to_canonical_bytes() for event in projection.events
    )
    assert b"hunter2-not-real" not in retained_event_bytes
    assert b"snippet" not in retained_event_bytes
    assert all(not hasattr(candidate, "finding_id") for candidate in candidates)


def test_clean_fixture_closes_with_zero_candidates(tmp_path: Path) -> None:
    setup = _setup(tmp_path, fixture_name="clean_app.py")
    with SQLiteEventStore(tmp_path / "events.sqlite3") as store:
        projection = _run(store, setup)

    assert projection.phase is ProjectionPhase.CLOSED
    assert projection.candidate_events == ()
    assert thaw_json(projection.scan_summary.payload)["candidate_count"] == 0


def test_fixture_preflight_propagates_vault_capacity_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    setup = _setup(tmp_path)

    def capacity_failure(self, requests, evidence_store, *, maximum_total):
        raise StoreCapacityError("simulated fixture vault capacity failure")

    monkeypatch.setattr(
        SQLiteEventStore,
        "resolve_evidence_artifacts",
        capacity_failure,
    )
    with SQLiteEventStore(tmp_path / "events.sqlite3") as store:
        with pytest.raises(
            StoreCapacityError,
            match="simulated fixture vault capacity failure",
        ):
            _run(store, setup)


def test_expired_authority_is_refused_before_mission_open(tmp_path: Path) -> None:
    setup = _setup(
        tmp_path,
        grant_overrides={
            "issued_at": NOW - 20,
            "not_before": NOW - 10,
            "expires_at": NOW,
        },
    )
    with SQLiteEventStore(tmp_path / "events.sqlite3") as store:
        projection = _run(store, setup)

    assert projection.phase is ProjectionPhase.REFUSED
    assert len(projection.events) == 1
    assert projection.events[0].kind == "mission_admission_refused"
    assert projection.authority_id == UNADMITTED_AUTHORITY_ID
    assert thaw_json(projection.refusal.payload)["reason_code"] == "expired"


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"max_bytes": 1}, "target_exceeds_byte_budget"),
        ({"max_candidates": 0}, "candidate_budget_is_zero"),
        ({"max_wallclock_seconds": 0}, "wallclock_budget_is_zero"),
        ({"assets": ("fixture://clean_app.py",)}, "asset_scope_mismatch"),
    ],
)
def test_preflight_policy_refuses_before_mission_open(
    tmp_path: Path,
    overrides: dict[str, object],
    reason: str,
) -> None:
    setup = _setup(tmp_path, grant_overrides=overrides)
    with SQLiteEventStore(tmp_path / "events.sqlite3") as store:
        projection = _run(store, setup)

    assert projection.phase is ProjectionPhase.REFUSED
    assert len(projection.events) == 1
    assert thaw_json(projection.refusal.payload) == {
        "reason_code": reason,
        "stage": "preflight",
    }


def test_unmanifested_caller_bytes_are_refused_before_mission_open(tmp_path: Path) -> None:
    evidence_store = FileEvidenceStore(tmp_path / "evidence")
    snapshot = retain_snapshot(
        "repository_fixture",
        {"caller.py": b"import os\nos.system(input())\n"},
        evidence_store,
    )
    authority_evidence = evidence_store.put(b"local fixture statement")
    signer = AuthoritySigner.generate()
    grant = AuthorityGrantV1.issue(
        issuer="operator:daniel",
        subject="benchmark:caller",
        target_snapshot_id=snapshot.object_id,
        assets=("fixture://caller.py",),
        permitted_actions=("static_analysis",),
        evidence_digest=authority_evidence.digest,
        issued_at=NOW - 1,
        not_before=NOW,
        expires_at=NOW + 60,
        max_bytes=1024,
        max_candidates=10,
        max_wallclock_seconds=10,
    )
    trust_store = TrustStore.from_keys(
        (
            TrustedAuthorityKey(
                signer.public_key_bytes,
                frozenset({"operator"}),
                frozenset({"operator:daniel"}),
            ),
        )
    )
    with SQLiteEventStore(tmp_path / "events.sqlite3") as store:
        projection = run_fixture_scan(
            mission_id=content_id("mission", {"nonce": "caller"}),
            snapshot=snapshot,
            signed_authority=signer.sign(grant),
            trust_store=trust_store,
            evidence_store=evidence_store,
            event_store=store,
            decision_time=NOW,
        )

    assert projection.phase is ProjectionPhase.REFUSED
    assert thaw_json(projection.refusal.payload)["reason_code"] == (
        "target_not_in_fixture_manifest"
    )


def test_candidate_budget_and_wallclock_have_distinct_terminal_states(
    tmp_path: Path,
) -> None:
    budget_root = tmp_path / "budget"
    budget_root.mkdir(mode=0o700)
    budget_setup = _setup(
        budget_root,
        grant_overrides={"max_candidates": 1},
    )
    with SQLiteEventStore(budget_root / "events.sqlite3") as store:
        budget = _run(store, budget_setup)
    assert budget.phase is ProjectionPhase.BUDGET_EXHAUSTED
    assert budget.candidate_events == ()

    timeout_root = tmp_path / "timeout"
    timeout_root.mkdir(mode=0o700)
    timeout_setup = _setup(timeout_root)
    ticks = iter((0, 61_000_000_001))
    with SQLiteEventStore(timeout_root / "events.sqlite3") as store:
        timed_out = _run(store, timeout_setup, monotonic_ns=lambda: next(ticks))
    assert timed_out.phase is ProjectionPhase.TIMED_OUT
    assert timed_out.candidate_events == ()


def test_operator_cancellation_is_retained_after_admission(tmp_path: Path) -> None:
    setup = _setup(tmp_path)
    with SQLiteEventStore(tmp_path / "events.sqlite3") as store:
        projection = _run(store, setup, cancel_requested=True)

    assert projection.phase is ProjectionPhase.CANCELLED
    assert [event.kind for event in projection.events] == [
        "authority_admitted",
        "scan_cancelled",
    ]


class _CrashAfterAppend:
    def __init__(self, store: SQLiteEventStore, kind: str) -> None:
        self.store = store
        self.kind = kind
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

    def _after_committed_append(self, event, result):
        if event.kind == self.kind and not self.crashed:
            self.crashed = True
            raise RuntimeError("simulated process loss after durable append")
        return result

    def append(self, event, *, expected_head: str):
        result = self.store.append(event, expected_head=expected_head)
        return self._after_committed_append(event, result)

    def append_evidence_event(
        self,
        event,
        *,
        expected_head: str,
        evidence_store: FileEvidenceStore,
    ):
        result = self.store.append_evidence_event(
            event,
            expected_head=expected_head,
            evidence_store=evidence_store,
        )
        return self._after_committed_append(event, result)


@pytest.mark.parametrize("crash_kind", ("candidate_recorded", "scan_completed"))
def test_interrupted_mission_resumes_from_durable_events_without_duplicates(
    tmp_path: Path,
    crash_kind: str,
) -> None:
    setup = _setup(tmp_path)
    with SQLiteEventStore(tmp_path / "events.sqlite3") as store:
        crashing = _CrashAfterAppend(store, crash_kind)
        with pytest.raises(RuntimeError, match="simulated"):
            _run(crashing, setup)
        interrupted_count = len(store.load(setup[4]))

        resumed = _run(store, setup)
        assert resumed.phase is ProjectionPhase.CLOSED
        assert len(resumed.events) > interrupted_count
        assert len(resumed.candidate_events) == 7
        candidate_ids = [
            thaw_json(event.payload)["candidate"]["object_id"]
            for event in resumed.candidate_events
        ]
        assert len(candidate_ids) == len(set(candidate_ids))


def test_delayed_resume_after_mission_open_times_out_before_lease_issuance(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    with SQLiteEventStore(tmp_path / "events.sqlite3") as store:
        crashing = _CrashAfterAppend(store, "mission_opened")
        with pytest.raises(RuntimeError, match="simulated"):
            _run(crashing, setup)

        retained = store.load(setup[4])
        admitted_grant = AuthorityGrantV1.from_envelope(
            EnvelopeV1.from_bytes(
                canonical_dumps(thaw_json(retained[0].payload)["grant"])
            )
        )
        setup[0]._path_for(admitted_grant.evidence_digest).unlink()
        for snapshot_file in setup[1].files:
            setup[0]._path_for(snapshot_file.artifact_digest).unlink()

        resumed = _run(store, setup, decision_time=NOW + 60)

    assert resumed.phase is ProjectionPhase.TIMED_OUT
    assert [event.kind for event in resumed.events] == [
        "authority_admitted",
        "mission_opened",
        "scan_timed_out",
    ]
    assert thaw_json(resumed.terminal_event.payload)["reason_code"] == (
        "lease_expired_before_issuance"
    )


@pytest.mark.parametrize(
    ("decision_time", "replace_trust"),
    (
        pytest.param(NOW + 300, False, id="grant-expired"),
        pytest.param(NOW + 60, True, id="trust-key-removed"),
    ),
)
def test_completed_scan_closes_without_reexecution_or_retroactive_readmission(
    tmp_path: Path,
    decision_time: int,
    replace_trust: bool,
) -> None:
    setup = _setup(tmp_path)

    def unexpected_clock() -> int:
        raise AssertionError("completed scan recovery must not execute analysis")

    with SQLiteEventStore(tmp_path / "events.sqlite3") as store:
        crashing = _CrashAfterAppend(store, "scan_completed")
        with pytest.raises(RuntimeError, match="simulated"):
            _run(crashing, setup)

        resume_setup = list(setup)
        if replace_trust:
            resume_setup[3] = TrustStore.from_keys(())
        resumed = _run(
            store,
            tuple(resume_setup),
            decision_time=decision_time,
            monotonic_ns=unexpected_clock,
        )

    assert resumed.phase is ProjectionPhase.CLOSED
    assert resumed.events[-2].kind == "scan_completed"
    assert resumed.events[-1].kind == "mission_closed"


def test_mission_id_cannot_be_rebound_to_another_target(tmp_path: Path) -> None:
    setup = _setup(tmp_path, fixture_name="vulnerable_app.py")
    with SQLiteEventStore(tmp_path / "events.sqlite3") as store:
        _run(store, setup)
        other_root = tmp_path / "other"
        other_root.mkdir()
        other = list(_setup(other_root, fixture_name="clean_app.py"))
        other[4] = setup[4]
        with pytest.raises(FixtureMissionError, match="another target"):
            _run(store, tuple(other))
