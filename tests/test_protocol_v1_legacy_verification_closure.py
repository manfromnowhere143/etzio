"""Compatibility evidence for the pre-recovery verification closure shape."""

from __future__ import annotations

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
from etzio.kernel.events_v1 import GENESIS_DIGEST, EventV1
from etzio.kernel.fixture_scan import prepare_fixture_scan_for_verification
from etzio.kernel.reducer import ProjectionPhase, ReductionError, reduce_events
from etzio.kernel.store import SQLiteEventStore
from etzio.kernel.verification_recovery import (
    close_modeled_fixture_verification_mission,
)
from etzio.protocol import canonical_dumps, content_id, thaw_json

NOW = 2_000_000_000


def _prepare_verification_fixture(
    root: Path,
    *,
    fixture_name: str,
    nonce: str,
):
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
                "fixture": relative_path,
                "kind": "repository_owned_benchmark_authority",
            }
        )
    )
    signer = AuthoritySigner.generate()
    grant = AuthorityGrantV1.issue(
        issuer="operator:daniel",
        subject="benchmark:legacy-verification-closure",
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
        max_bytes=len(fixture_bytes),
        max_candidates=100,
        max_wallclock_seconds=60,
    )
    signed_grant = signer.sign(grant)
    authority_trust = TrustStore.from_keys(
        (
            TrustedAuthorityKey(
                public_key_bytes=signer.public_key_bytes,
                roles=frozenset({"operator"}),
                issuers=frozenset({"operator:daniel"}),
            ),
        )
    )
    mission_id = content_id(
        "mission",
        {"fixture": relative_path, "nonce": nonce},
    )
    database = root / "events.sqlite3"
    with SQLiteEventStore(database) as store:
        projection = prepare_fixture_scan_for_verification(
            mission_id=mission_id,
            snapshot=snapshot,
            signed_authority=signed_grant,
            trust_store=authority_trust,
            evidence_store=evidence_store,
            event_store=store,
            decision_time=NOW,
        )
    return mission_id, projection


def _legacy_completed_event(event: EventV1) -> EventV1:
    payload = thaw_json(event.payload)
    payload["status"] = "completed"
    return EventV1.create(
        mission_id=event.mission_id,
        seq=event.seq,
        kind=event.kind,
        unit=event.unit,
        authority_id=event.authority_id,
        target_id=event.target_id,
        decision_time=event.decision_time,
        payload=payload,
        prev_digest=event.prev_digest,
    )


def test_current_zero_candidate_emission_uses_receipt_coverage_status(
    tmp_path: Path,
) -> None:
    mission_id, projection = _prepare_verification_fixture(
        tmp_path,
        fixture_name="clean_app.py",
        nonce="current-zero-candidate",
    )

    assert projection.mission_id == mission_id
    assert projection.phase is ProjectionPhase.CLOSED
    assert projection.candidate_events == ()
    assert thaw_json(projection.terminal_event.payload)["status"] == (
        "receipt_coverage_complete"
    )


def test_legacy_zero_candidate_completion_replays_reopens_and_retries(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir(mode=0o700)
    source.chmod(0o700)
    mission_id, current = _prepare_verification_fixture(
        source,
        fixture_name="clean_app.py",
        nonce="legacy-zero-candidate",
    )
    legacy_terminal = _legacy_completed_event(current.events[-1])
    legacy_events = (*current.events[:-1], legacy_terminal)

    replayed = reduce_events(legacy_events)
    assert replayed.phase is ProjectionPhase.CLOSED
    assert replayed.candidate_events == ()
    assert replayed.verification_lease_events == ()
    assert thaw_json(replayed.terminal_event.payload)["status"] == "completed"

    retained_root = tmp_path / "retained"
    retained_root.mkdir(mode=0o700)
    retained_root.chmod(0o700)
    database = retained_root / "events.sqlite3"
    expected_head = GENESIS_DIGEST
    with SQLiteEventStore(database) as store:
        for event in legacy_events:
            store.append(event, expected_head=expected_head)
            expected_head = event.event_digest

    with SQLiteEventStore(database) as reopened:
        loaded = reopened.load(mission_id)
        retried = close_modeled_fixture_verification_mission(
            event_store=reopened,
            mission_id=mission_id,
            expected_head=legacy_terminal.prev_digest,
            decision_time=legacy_terminal.decision_time,
        )

    assert loaded[-1].to_canonical_bytes() == (
        legacy_terminal.to_canonical_bytes()
    )
    assert retried.replayed
    assert retried.event == legacy_terminal
    assert retried.status == "completed"


def test_nonempty_verification_completion_cannot_use_legacy_alias(
    tmp_path: Path,
) -> None:
    _, projection = _prepare_verification_fixture(
        tmp_path,
        fixture_name="vulnerable_app.py",
        nonce="nonempty-near-neighbor",
    )
    assert projection.phase is ProjectionPhase.SCAN_COMPLETED
    assert projection.candidate_events
    summary = thaw_json(projection.scan_summary.payload)
    completed = EventV1.create(
        mission_id=projection.mission_id,
        seq=len(projection.events),
        kind="mission_closed",
        unit="ETZIO",
        authority_id=projection.authority_id,
        target_id=projection.target_id,
        decision_time=NOW + 1,
        payload={
            "candidate_count": summary["candidate_count"],
            "parse_failure_count": summary["parse_failure_count"],
            "status": "completed",
        },
        prev_digest=projection.events[-1].event_digest,
    )

    with pytest.raises(ReductionError, match="receipt coverage"):
        reduce_events((*projection.events, completed))
