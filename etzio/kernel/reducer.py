"""Pure deterministic reducer for the first durable mission lifecycle."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

from ..protocol import EnvelopeV1, ProtocolError, canonical_dumps, thaw_json
from .events_v1 import GENESIS_DIGEST, EventIntegrityError, EventV1


class ReductionError(ProtocolError):
    """Raised when a mission stream is invalid or has an illegal transition."""


class ProjectionPhase(str, Enum):
    """Observable recovery phase derived only from retained events."""

    ADMITTED = "admitted"
    OPEN = "open"
    ANALYZING = "analyzing"
    SCAN_COMPLETED = "scan_completed"
    AWAITING_VERIFICATION = "awaiting_verification"
    CLOSED = "closed"
    REFUSED = "refused"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    BUDGET_EXHAUSTED = "budget_exhausted"


@dataclass(frozen=True, slots=True)
class MissionProjection:
    """Deeply immutable mission state reconstructed from an ordered event stream."""

    mission_id: str
    authority_id: str
    target_id: str
    phase: ProjectionPhase
    events: tuple[EventV1, ...]
    candidate_events: tuple[EventV1, ...]
    parse_failures: tuple[EventV1, ...]
    verification_lease_events: tuple[EventV1, ...]
    verification_artifact_resolution_events: tuple[EventV1, ...]
    refusal: EventV1 | None
    failure_event: EventV1 | None
    scan_summary: EventV1 | None
    terminal_event: EventV1 | None

    @property
    def is_terminal(self) -> bool:
        return self.phase in {
            ProjectionPhase.CLOSED,
            ProjectionPhase.REFUSED,
            ProjectionPhase.FAILED,
            ProjectionPhase.CANCELLED,
            ProjectionPhase.TIMED_OUT,
            ProjectionPhase.BUDGET_EXHAUSTED,
        }


_FAILURE_PHASES = {
    "scan_failed": "failed",
    "scan_cancelled": "cancelled",
    "scan_timed_out": "timed_out",
    "budget_exhausted": "budget_exhausted",
}


def _transition(phase: str, kind: str) -> str:
    if phase == "start":
        if kind == "authority_admitted":
            return "admitted"
        if kind == "mission_admission_refused":
            return "refused"
    elif phase == "admitted":
        if kind == "mission_opened":
            return "open"
        if kind in _FAILURE_PHASES:
            return _FAILURE_PHASES[kind]
    elif phase == "open":
        if kind == "analysis_lease_issued":
            return "analyzing"
        if kind in _FAILURE_PHASES:
            return _FAILURE_PHASES[kind]
    elif phase == "analyzing":
        if kind in {"candidate_recorded", "parse_failed"}:
            return "analyzing"
        if kind == "scan_completed":
            return "scan_completed"
        if kind in _FAILURE_PHASES:
            return _FAILURE_PHASES[kind]
    elif phase == "scan_completed":
        if kind == "verification_lease_issued":
            return "awaiting_verification"
        if kind == "mission_closed":
            return "closed"
        if kind in _FAILURE_PHASES:
            return _FAILURE_PHASES[kind]
    elif phase == "awaiting_verification":
        if kind in {
            "verification_lease_issued",
            "verification_artifacts_resolved",
        }:
            return "awaiting_verification"
    raise ReductionError(f"illegal event transition: {phase} -> {kind}")


def _nested_envelope(event: EventV1, field: str) -> EnvelopeV1:
    """Decode a nested envelope already structurally checked by ``EventV1``."""

    value = event.payload[field]
    try:
        return EnvelopeV1.from_bytes(canonical_dumps(thaw_json(value)))
    except ProtocolError as exc:  # defensive: EventV1 validation should catch this first
        raise ReductionError(
            f"invalid {field} envelope at sequence {event.seq}: {exc}"
        ) from exc


def reduce_events(events: Iterable[EventV1]) -> MissionProjection:
    """Rebuild one mission projection, rejecting gaps, forks, and illegal transitions.

    Partial nonterminal streams are valid recovery points.  Admission refusal is valid only
    as the first and sole event.  The successful minimal lifecycle is:

    ``authority_admitted → mission_opened → analysis_lease_issued → outputs* →
    scan_completed → mission_closed``. A verification-intended stream instead continues
    through one or more ``verification_lease_issued`` events and remains nonterminal
    pending a later receipt-admission tranche.
    """

    retained = tuple(events)
    if not retained:
        raise ReductionError("cannot infer a mission projection from an empty stream")
    if any(not isinstance(event, EventV1) for event in retained):
        raise ReductionError("mission stream contains a non-EventV1 value")

    first = retained[0]
    mission_id = first.mission_id
    authority_id = first.authority_id
    target_id = first.target_id
    expected_prev = GENESIS_DIGEST
    previous_decision_time: int | None = None
    phase = "start"
    candidates: list[EventV1] = []
    failures: list[EventV1] = []
    candidate_ids: set[str] = set()
    candidate_events_by_id: dict[str, EventV1] = {}
    verification_lease_events: list[EventV1] = []
    verification_artifact_resolution_events: list[EventV1] = []
    verification_lease_ids: set[str] = set()
    verification_leases_by_id: dict[str, object] = {}
    resolved_verification_lease_ids: set[str] = set()
    leased_candidate_ids: set[str] = set()
    admitted_grant: object | None = None
    admitted_admission: object | None = None
    target_snapshot: object | None = None
    analysis_lease: object | None = None
    refusal: EventV1 | None = None
    failure: EventV1 | None = None
    scan_summary: EventV1 | None = None
    terminal: EventV1 | None = None

    for expected_seq, event in enumerate(retained):
        try:
            event.verify()
        except EventIntegrityError as exc:
            raise ReductionError(f"invalid event at sequence {expected_seq}: {exc}") from exc
        if event.seq != expected_seq:
            raise ReductionError(f"event sequence gap or fork: expected {expected_seq}, got {event.seq}")
        if event.prev_digest != expected_prev:
            raise ReductionError(f"predecessor mismatch at sequence {expected_seq}")
        if event.mission_id != mission_id:
            raise ReductionError("cross-mission event in reducer input")
        if event.authority_id != authority_id:
            raise ReductionError("authority identity changed within mission stream")
        if event.target_id != target_id:
            raise ReductionError("target identity changed within mission stream")
        if (
            previous_decision_time is not None
            and event.decision_time < previous_decision_time
        ):
            raise ReductionError(
                f"decision_time regressed at sequence {expected_seq}"
            )

        phase = _transition(phase, event.kind)
        if event.kind == "authority_admitted":
            from ..authority import AuthorityAdmissionV1, AuthorityGrantV1

            admitted_grant = AuthorityGrantV1.from_envelope(
                _nested_envelope(event, "grant")
            )
            admitted_admission = AuthorityAdmissionV1.from_envelope(
                _nested_envelope(event, "admission")
            )
            if (
                "static_analysis" not in admitted_admission.required_actions
                or "static_analysis" not in admitted_grant.permitted_actions
            ):
                raise ReductionError(
                    "admitted authority does not permit exact static_analysis"
                )
        elif event.kind == "mission_opened":
            from ..evidence import TargetSnapshotV1

            target_snapshot = TargetSnapshotV1.from_envelope(
                _nested_envelope(event, "target_snapshot")
            )
        elif event.kind == "analysis_lease_issued":
            from ..mission_v1 import AnalysisLeaseV1

            analysis_lease = AnalysisLeaseV1.from_envelope(
                _nested_envelope(event, "lease")
            )
            if admitted_grant is None:
                raise ReductionError("analysis lease has no admitted authority grant")
            if (
                admitted_admission is None
                or "static_analysis" not in admitted_admission.required_actions
                or "static_analysis" not in admitted_grant.permitted_actions
                or analysis_lease.action != "static_analysis"
            ):
                raise ReductionError(
                    "analysis lease lacks admitted static_analysis authority"
                )
            if (
                analysis_lease.expires_at > admitted_grant.expires_at
                or analysis_lease.max_bytes > admitted_grant.max_bytes
                or analysis_lease.max_candidates > admitted_grant.max_candidates
                or analysis_lease.max_wallclock_seconds
                > admitted_grant.max_wallclock_seconds
            ):
                raise ReductionError(
                    "analysis lease exceeds the admitted authority grant"
                )
            if (
                analysis_lease.expires_at
                > analysis_lease.issued_at
                + analysis_lease.max_wallclock_seconds
            ):
                raise ReductionError(
                    "analysis lease expiry exceeds its wallclock ceiling"
                )
            if target_snapshot is None:
                raise ReductionError("analysis lease has no retained target snapshot")
            if (
                sum(file.size for file in target_snapshot.files)
                > analysis_lease.max_bytes
            ):
                raise ReductionError(
                    "analysis lease byte budget is smaller than the target snapshot"
                )
            if not (
                analysis_lease.issued_at
                <= event.decision_time
                < analysis_lease.expires_at
            ):
                raise ReductionError(
                    "analysis lease issuance event is outside the lease window"
                )
        elif event.kind == "candidate_recorded":
            from ..mission_v1 import StaticCandidateV1

            candidate_envelope = _nested_envelope(event, "candidate")
            candidate = StaticCandidateV1.from_envelope(candidate_envelope)
            if candidate.candidate_id in candidate_ids:
                raise ReductionError("duplicate candidate identity in mission stream")
            if analysis_lease is None:
                raise ReductionError("candidate has no admitted analysis lease")
            if candidate.analysis_lease_id != analysis_lease.lease_id:
                raise ReductionError(
                    "candidate does not reference the admitted analysis lease"
                )
            if (
                event.decision_time - analysis_lease.issued_at
                > analysis_lease.max_wallclock_seconds
            ):
                raise ReductionError(
                    "candidate exceeded the retained epoch wallclock ceiling"
                )
            if not (
                analysis_lease.issued_at
                <= event.decision_time
                < analysis_lease.expires_at
            ):
                raise ReductionError("candidate was recorded outside the lease window")
            if len(candidates) + len(failures) + 1 > analysis_lease.max_candidates:
                raise ReductionError(
                    "candidate exceeded the analysis output budget"
                )
            if target_snapshot is None:
                raise ReductionError("candidate has no retained target snapshot")
            if (
                target_snapshot.artifacts_by_path().get(candidate.relative_path)
                != candidate.source_artifact_digest
            ):
                raise ReductionError(
                    "candidate source artifact is absent from the target snapshot"
                )
            candidate_ids.add(candidate.candidate_id)
            candidate_events_by_id[candidate.candidate_id] = event
            candidates.append(event)
        elif event.kind == "parse_failed":
            if analysis_lease is None:
                raise ReductionError("parse failure has no admitted analysis lease")
            if event.payload["analysis_lease_id"] != analysis_lease.lease_id:
                raise ReductionError(
                    "parse failure does not reference the admitted analysis lease"
                )
            if (
                event.decision_time - analysis_lease.issued_at
                > analysis_lease.max_wallclock_seconds
            ):
                raise ReductionError(
                    "parse failure exceeded the retained epoch wallclock ceiling"
                )
            if not (
                analysis_lease.issued_at
                <= event.decision_time
                < analysis_lease.expires_at
            ):
                raise ReductionError(
                    "parse failure was recorded outside the lease window"
                )
            if len(candidates) + len(failures) + 1 > analysis_lease.max_candidates:
                raise ReductionError(
                    "parse failure exceeded the analysis output budget"
                )
            if target_snapshot is None:
                raise ReductionError("parse failure has no retained target snapshot")
            parse_failure = event.payload["parse_failure"]
            if (
                target_snapshot.artifacts_by_path().get(
                    parse_failure["relative_path"]
                )
                != event.payload["source_artifact_digest"]
            ):
                raise ReductionError(
                    "parse-failure source artifact is absent from the target snapshot"
                )
            failures.append(event)
        elif event.kind == "mission_admission_refused":
            refusal = event
            terminal = event
        elif event.kind in _FAILURE_PHASES:
            failure = event
            terminal = event
        elif event.kind == "scan_completed":
            from ..analysis import PYTHON_SAST_VERSION

            if analysis_lease is None or target_snapshot is None:
                raise ReductionError(
                    "scan_completed requires a retained target and analysis lease"
                )
            if not (
                analysis_lease.issued_at
                <= event.decision_time
                < analysis_lease.expires_at
            ):
                raise ReductionError("scan_completed is outside the lease window")
            if event.payload["candidate_count"] != len(candidates):
                raise ReductionError(
                    "scan_completed candidate_count does not match retained candidates"
                )
            if event.payload["parse_failure_count"] != len(failures):
                raise ReductionError(
                    "scan_completed parse_failure_count does not match retained failures"
                )
            if event.payload["file_count"] != len(target_snapshot.files):
                raise ReductionError(
                    "scan_completed file_count does not match the target snapshot"
                )
            if event.payload["bytes_scanned"] != sum(
                file.size for file in target_snapshot.files
            ):
                raise ReductionError(
                    "scan_completed bytes_scanned does not match the target snapshot"
                )
            if event.payload["analyzer_version"] != PYTHON_SAST_VERSION:
                raise ReductionError("scan_completed analyzer_version is unsupported")
            if (
                event.payload["bytes_scanned"] > analysis_lease.max_bytes
                or len(candidates) + len(failures)
                > analysis_lease.max_candidates
                or event.decision_time - analysis_lease.issued_at
                > analysis_lease.max_wallclock_seconds
            ):
                raise ReductionError("scan_completed exceeds its analysis lease")
            scan_summary = event
        elif event.kind == "verification_lease_issued":
            from ..verification import (
                VERIFIER_ROLE,
                VerificationLeaseV1,
                VerifierTrustStore,
            )

            lease = VerificationLeaseV1.from_envelope(
                _nested_envelope(event, "lease")
            )
            verifier_trust = VerifierTrustStore.from_snapshot_body(
                thaw_json(event.payload)["verifier_trust_snapshot"],
                expected_snapshot_id=event.payload[
                    "verifier_trust_snapshot_id"
                ],
            )
            if admitted_grant is None or admitted_admission is None:
                raise ReductionError(
                    "verification lease has no admitted authority evidence"
                )
            if (
                "modeled_fixture_verification"
                not in admitted_admission.required_actions
                or "modeled_fixture_verification"
                not in admitted_grant.permitted_actions
            ):
                raise ReductionError(
                    "verification lease lacks admitted "
                    "modeled_fixture_verification authority"
                )
            candidate_event = candidate_events_by_id.get(lease.candidate_id)
            if candidate_event is None:
                raise ReductionError(
                    "verification lease references no retained candidate"
                )
            if (
                lease.mission_id != mission_id
                or lease.authority_id != authority_id
                or lease.target_snapshot_id != target_id
                or lease.candidate_producer_id != candidate_event.unit
            ):
                raise ReductionError(
                    "verification lease differs from retained mission bindings"
                )
            if lease.issued_at != event.decision_time:
                raise ReductionError(
                    "verification lease issued_at differs from its event"
                )
            grant_deadline = min(
                admitted_grant.expires_at,
                admitted_admission.decision_time
                + admitted_grant.max_wallclock_seconds,
            )
            if not (
                admitted_admission.decision_time
                <= lease.issued_at
                < lease.expires_at
                <= grant_deadline
            ):
                raise ReductionError(
                    "verification lease exceeds the admitted authority window"
                )
            if lease.candidate_producer_id == lease.verifier_id:
                raise ReductionError(
                    "verification lease assigns the candidate producer"
                )
            trusted_key = verifier_trust.keys.get(lease.verifier_key_id)
            if (
                trusted_key is None
                or lease.verifier_key_id in verifier_trust.revoked_key_ids
                or VERIFIER_ROLE not in trusted_key.roles
                or trusted_key.verifier_id != lease.verifier_id
                or lease.issuance_trust_snapshot_id
                != event.payload["verifier_trust_snapshot_id"]
            ):
                raise ReductionError(
                    "verification lease lacks an eligible retained verifier"
                )
            if lease.lease_id in verification_lease_ids:
                raise ReductionError(
                    "duplicate verification lease identity in mission stream"
                )
            if lease.candidate_id in leased_candidate_ids:
                raise ReductionError(
                    "candidate already has a verification lease"
                )
            if (
                len(verification_lease_events) + 1
                > admitted_grant.max_candidates
            ):
                raise ReductionError(
                    "verification lease count exceeds the admitted candidate ceiling"
                )
            verification_lease_ids.add(lease.lease_id)
            verification_leases_by_id[lease.lease_id] = lease
            leased_candidate_ids.add(lease.candidate_id)
            verification_lease_events.append(event)
        elif event.kind == "verification_artifacts_resolved":
            from ..verification import VerificationLeaseV1
            from ..verification_artifacts import (
                MAX_RESOLUTION_ARTIFACT_BYTES_V1,
                MAX_TYPED_VERIFICATION_INPUT_BYTES_V1,
                VerificationArtifactResolutionV1,
            )

            resolution = VerificationArtifactResolutionV1.from_envelope(
                _nested_envelope(event, "resolution")
            )
            lease_value = verification_leases_by_id.get(
                resolution.verification_lease_id
            )
            if not isinstance(lease_value, VerificationLeaseV1):
                raise ReductionError(
                    "artifact resolution references no prior verification lease"
                )
            lease = lease_value
            if resolution.verification_lease_id in resolved_verification_lease_ids:
                raise ReductionError(
                    "verification lease already has an artifact resolution"
                )
            if (
                resolution.mission_id != mission_id
                or resolution.authority_id != authority_id
                or resolution.target_snapshot_id != target_id
                or resolution.candidate_id != lease.candidate_id
            ):
                raise ReductionError(
                    "artifact resolution differs from retained mission bindings"
                )
            if resolution.resolved_at != event.decision_time:
                raise ReductionError("artifact resolution time differs from its event")
            if not (lease.issued_at <= resolution.resolved_at < lease.expires_at):
                raise ReductionError(
                    "artifact resolution is outside the verification lease window"
                )
            if target_snapshot is None:
                raise ReductionError(
                    "artifact resolution has no retained target snapshot"
                )
            expected_targets = tuple(
                (
                    snapshot_file.artifact_digest,
                    snapshot_file.relative_path,
                    snapshot_file.size,
                )
                for snapshot_file in target_snapshot.files
            )
            actual_targets = tuple(
                (
                    binding.artifact_digest,
                    binding.relative_path,
                    binding.size,
                )
                for binding in resolution.target_artifacts
            )
            if actual_targets != expected_targets:
                raise ReductionError(
                    "artifact resolution target bindings differ from the retained snapshot"
                )
            if (
                resolution.poc_artifact.artifact_digest != lease.poc_artifact_digest
                or resolution.environment_artifact.artifact_digest
                != lease.environment_digest
                or resolution.effect_oracle_artifact.artifact_digest
                != lease.effect_oracle_id
                or tuple(
                    artifact.artifact_digest
                    for artifact in resolution.evidence_artifacts
                )
                != lease.evidence_artifact_digests
            ):
                raise ReductionError(
                    "artifact resolution differs from verification lease artifacts"
                )
            if admitted_grant is None:
                raise ReductionError(
                    "artifact resolution has no admitted authority grant"
                )
            if (
                resolution.total_bytes > admitted_grant.max_bytes
                or resolution.typed_input_bytes > MAX_TYPED_VERIFICATION_INPUT_BYTES_V1
                or resolution.total_bytes > MAX_RESOLUTION_ARTIFACT_BYTES_V1
            ):
                raise ReductionError(
                    "artifact resolution exceeds the admitted byte ceiling"
                )
            resolved_verification_lease_ids.add(resolution.verification_lease_id)
            verification_artifact_resolution_events.append(event)
        elif event.kind == "mission_closed":
            if (
                admitted_admission is not None
                and "modeled_fixture_verification"
                in admitted_admission.required_actions
                and candidates
            ):
                raise ReductionError(
                    "verification-intended mission with candidates cannot close "
                    "before receipt adjudication"
                )
            if event.payload["candidate_count"] != len(candidates):
                raise ReductionError(
                    "mission_closed candidate_count does not match retained candidates"
                )
            if event.payload["parse_failure_count"] != len(failures):
                raise ReductionError(
                    "mission_closed parse_failure_count does not match retained failures"
                )
            if scan_summary is None:
                raise ReductionError("mission_closed requires a retained scan summary")
            if (
                event.payload["candidate_count"]
                != scan_summary.payload["candidate_count"]
                or event.payload["parse_failure_count"]
                != scan_summary.payload["parse_failure_count"]
            ):
                raise ReductionError(
                    "mission_closed counts do not match scan_completed"
                )
            terminal = event
        expected_prev = event.event_digest
        previous_decision_time = event.decision_time

    phase_by_internal = {
        "admitted": ProjectionPhase.ADMITTED,
        "open": ProjectionPhase.OPEN,
        "analyzing": ProjectionPhase.ANALYZING,
        "scan_completed": ProjectionPhase.SCAN_COMPLETED,
        "awaiting_verification": ProjectionPhase.AWAITING_VERIFICATION,
        "closed": ProjectionPhase.CLOSED,
        "refused": ProjectionPhase.REFUSED,
        "failed": ProjectionPhase.FAILED,
        "cancelled": ProjectionPhase.CANCELLED,
        "timed_out": ProjectionPhase.TIMED_OUT,
        "budget_exhausted": ProjectionPhase.BUDGET_EXHAUSTED,
    }
    return MissionProjection(
        mission_id=mission_id,
        authority_id=authority_id,
        target_id=target_id,
        phase=phase_by_internal[phase],
        events=retained,
        candidate_events=tuple(candidates),
        parse_failures=tuple(failures),
        verification_lease_events=tuple(verification_lease_events),
        verification_artifact_resolution_events=tuple(
            verification_artifact_resolution_events
        ),
        refusal=refusal,
        failure_event=failure,
        scan_summary=scan_summary,
        terminal_event=terminal,
    )
