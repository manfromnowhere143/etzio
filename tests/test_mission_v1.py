"""Known-good and known-bad protocol objects for the governed fixture mission."""

from __future__ import annotations

from dataclasses import replace

import pytest

from etzio.analysis import StaticFinding
from etzio.mission_v1 import AnalysisLeaseV1, MissionProtocolError, StaticCandidateV1
from etzio.protocol import EnvelopeV1

MISSION_ID = "sha256:" + ("1" * 64)
AUTHORITY_ID = "sha256:" + ("2" * 64)
TARGET_ID = "sha256:" + ("3" * 64)
ARTIFACT_ID = "sha256:" + ("4" * 64)


def lease(**overrides: object) -> AnalysisLeaseV1:
    values: dict[str, object] = {
        "mission_id": MISSION_ID,
        "authority_id": AUTHORITY_ID,
        "target_snapshot_id": TARGET_ID,
        "issued_at": 100,
        "expires_at": 160,
        "max_bytes": 4096,
        "max_candidates": 10,
        "max_wallclock_seconds": 60,
        "lease_nonce": "a" * 32,
    }
    values.update(overrides)
    return AnalysisLeaseV1.issue(**values)  # type: ignore[arg-type]


def finding() -> StaticFinding:
    return StaticFinding(
        rule_id="PY-CMD-INJECTION",
        severity="high",
        message="generic detector explanation",
        file="fixture.py",
        line=7,
        column=4,
        symbol="os.system",
        snippet="os.system(secret_value)",
    )


def candidate(**overrides: object) -> StaticCandidateV1:
    values: dict[str, object] = {
        "mission_id": MISSION_ID,
        "authority_id": AUTHORITY_ID,
        "analysis_lease_id": lease().lease_id,
        "target_snapshot_id": TARGET_ID,
        "source_artifact_digest": ARTIFACT_ID,
    }
    values.update(overrides)
    return StaticCandidateV1.from_finding(finding(), **values)  # type: ignore[arg-type]


def test_analysis_lease_round_trip_and_identity_are_stable() -> None:
    first = lease()
    second = lease()

    assert first == second
    assert first.lease_id == second.lease_id
    assert AnalysisLeaseV1.from_envelope(first.to_envelope()) == first


@pytest.mark.parametrize(
    "overrides",
    (
        {"mission_id": "short"},
        {"issued_at": 160},
        {"expires_at": 100},
        {"max_bytes": 0},
        {"max_candidates": -1},
        {"max_wallclock_seconds": True},
        {"lease_nonce": "A" * 32},
    ),
)
def test_invalid_analysis_lease_is_rejected(overrides: dict[str, object]) -> None:
    with pytest.raises(MissionProtocolError):
        lease(**overrides)


def test_direct_lease_identity_forgery_is_rejected() -> None:
    valid = lease()
    with pytest.raises(MissionProtocolError, match="lease_id"):
        replace(valid, lease_id="sha256:" + ("f" * 64))


def test_static_candidate_is_stable_and_excludes_source_snippet() -> None:
    first = candidate()
    second = candidate()

    assert first == second
    assert first.claim_id == second.claim_id
    assert first.candidate_id == second.candidate_id
    assert StaticCandidateV1.from_envelope(first.to_envelope()) == first
    assert "secret_value" not in first.to_envelope().to_bytes().decode("utf-8")
    assert "snippet" not in first.to_envelope().body
    assert "message" not in first.to_envelope().body


def test_claim_identity_is_mission_independent_but_candidate_identity_is_not() -> None:
    first = candidate()
    other_mission = "sha256:" + ("9" * 64)
    other_lease = lease(mission_id=other_mission)
    second = candidate(mission_id=other_mission, analysis_lease_id=other_lease.lease_id)

    assert first.claim_id == second.claim_id
    assert first.candidate_id != second.candidate_id


def test_candidate_identity_changes_on_source_or_location_substitution() -> None:
    original = candidate()
    other_source = candidate(source_artifact_digest="sha256:" + ("8" * 64))
    shifted_finding = replace(finding(), line=8)
    shifted = StaticCandidateV1.from_finding(
        shifted_finding,
        mission_id=MISSION_ID,
        authority_id=AUTHORITY_ID,
        analysis_lease_id=lease().lease_id,
        target_snapshot_id=TARGET_ID,
        source_artifact_digest=ARTIFACT_ID,
    )

    assert original.claim_id != other_source.claim_id
    assert original.claim_id != shifted.claim_id


def test_direct_candidate_claim_or_object_identity_forgery_is_rejected() -> None:
    valid = candidate()
    with pytest.raises(MissionProtocolError, match="claim_id"):
        replace(valid, claim_id="sha256:" + ("f" * 64))
    with pytest.raises(MissionProtocolError, match="candidate_id"):
        replace(valid, candidate_id="sha256:" + ("f" * 64))


def test_unknown_candidate_or_lease_body_fields_are_rejected() -> None:
    candidate_body = dict(candidate().to_envelope().body)
    candidate_body["unexpected"] = True
    with pytest.raises(MissionProtocolError, match="unknown"):
        StaticCandidateV1.from_envelope(EnvelopeV1.create("candidate", candidate_body))

    lease_body = dict(lease().to_envelope().body)
    lease_body["unexpected"] = True
    with pytest.raises(MissionProtocolError, match="unknown"):
        AnalysisLeaseV1.from_envelope(EnvelopeV1.create("analysis_lease", lease_body))
