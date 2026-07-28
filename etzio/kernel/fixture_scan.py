"""Recoverable, authority-gated execution of Etzio's protocol-v1 fixture scan.

The runner accepts retained ``TargetSnapshotV1`` bytes, never an arbitrary filesystem path.
It emits static candidates only. No event in this path can mint a finding or authorize
network, credential, exploit-execution, disclosure, or publication effects.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable

from ..analysis import PYTHON_SAST_VERSION, analyze_python_bytes
from ..authority import (
    AdmissionDecision,
    AuthorityAdmissionV1,
    SignedAuthorityGrantV1,
    TrustStore,
    admit_authority,
)
from ..evidence import (
    EvidenceError,
    FileEvidenceStore,
    TargetSnapshotV1,
    validate_etzio_fixture_snapshot,
)
from ..mission_v1 import AnalysisLeaseV1, StaticCandidateV1
from ..protocol import (
    EnvelopeV1,
    ProtocolError,
    canonical_dumps,
    content_id,
    thaw_json,
)
from .events_v1 import GENESIS_DIGEST, EventV1
from .reducer import MissionProjection, ProjectionPhase, reduce_events
from .store import SQLiteEventStore

_FULL_SHA = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
UNADMITTED_AUTHORITY_ID = content_id(
    "unadmitted_authority",
    {"meaning": "no_authority_was_admitted"},
)
_STATIC_ANALYSIS_ACTIONS = ("static_analysis",)
_FIXTURE_VERIFICATION_ACTIONS = (
    "modeled_fixture_verification",
    "static_analysis",
)


class FixtureMissionError(ProtocolError):
    """The governed fixture mission cannot safely continue."""


def _require_mission_id(mission_id: object) -> str:
    if type(mission_id) is not str or _FULL_SHA.fullmatch(mission_id) is None:
        raise FixtureMissionError("mission_id must be a full sha256 identifier")
    return mission_id


def _coerce_signed_grant(
    signed_authority: SignedAuthorityGrantV1 | bytes | str,
) -> SignedAuthorityGrantV1:
    if isinstance(signed_authority, SignedAuthorityGrantV1):
        return signed_authority
    return SignedAuthorityGrantV1.from_bytes(signed_authority)


def _append_checked(
    store: SQLiteEventStore,
    retained: tuple[EventV1, ...],
    *,
    mission_id: str,
    kind: str,
    unit: str,
    authority_id: str,
    target_id: str,
    decision_time: int,
    payload: dict[str, object],
) -> tuple[EventV1, ...]:
    head = retained[-1].event_digest if retained else GENESIS_DIGEST
    event = EventV1.create(
        mission_id=mission_id,
        seq=len(retained),
        kind=kind,
        unit=unit,
        authority_id=authority_id,
        target_id=target_id,
        decision_time=decision_time,
        payload=payload,
        prev_digest=head,
    )
    # Keep lifecycle validation at the command boundary as defense in depth. The durable
    # store independently performs the same reduction inside its append transaction.
    reduce_events((*retained, event))
    store.append(event, expected_head=head)
    return (*retained, event)


def _refuse_initial_mission(
    store: SQLiteEventStore,
    *,
    mission_id: str,
    target_id: str,
    authority_id: str,
    decision_time: int,
    reason_code: str,
    stage: str,
) -> MissionProjection:
    retained = _append_checked(
        store,
        (),
        mission_id=mission_id,
        kind="mission_admission_refused",
        unit="AQUILA",
        authority_id=authority_id,
        target_id=target_id,
        decision_time=decision_time,
        payload={"reason_code": reason_code, "stage": stage},
    )
    return reduce_events(retained)


def _preflight(
    snapshot: TargetSnapshotV1,
    decision: AdmissionDecision,
    evidence_store: FileEvidenceStore,
) -> tuple[str | None, dict[str, bytes]]:
    if (
        not decision.accepted
        or decision.grant is None
        or decision.admission is None
        or decision.authority_id is None
    ):
        raise FixtureMissionError("preflight requires one admitted authority snapshot")
    grant = decision.grant
    try:
        validate_etzio_fixture_snapshot(snapshot, evidence_store)
    except EvidenceError:
        return "target_not_in_fixture_manifest", {}
    expected_assets = tuple(
        sorted(f"fixture://{snapshot_file.relative_path}" for snapshot_file in snapshot.files)
    )
    if grant.assets != expected_assets:
        return "asset_scope_mismatch", {}
    if grant.max_candidates <= 0:
        return "candidate_budget_is_zero", {}
    if grant.max_wallclock_seconds <= 0:
        return "wallclock_budget_is_zero", {}
    total_bytes = sum(snapshot_file.size for snapshot_file in snapshot.files)
    if total_bytes > grant.max_bytes:
        return "target_exceeds_byte_budget", {}
    try:
        evidence_store.get(grant.evidence_digest)
    except EvidenceError:
        return "authority_evidence_unavailable", {}

    source_bytes: dict[str, bytes] = {}
    try:
        for snapshot_file in snapshot.files:
            data = evidence_store.get(snapshot_file.artifact_digest)
            if len(data) != snapshot_file.size:
                return "target_size_mismatch", {}
            source_bytes[snapshot_file.relative_path] = data
    except EvidenceError:
        return "target_evidence_unavailable", {}
    return None, source_bytes


def _lease_for(
    mission_id: str,
    decision: AdmissionDecision,
    snapshot: TargetSnapshotV1,
    *,
    issued_at: int,
) -> AnalysisLeaseV1:
    if decision.grant is None or decision.authority_id is None:
        raise FixtureMissionError("analysis lease requires admitted grant details")
    grant = decision.grant
    expires_at = min(
        grant.expires_at,
        issued_at + grant.max_wallclock_seconds,
    )
    nonce = content_id(
        "analysis_lease_nonce",
        {
            "authority_id": decision.authority_id,
            "mission_id": mission_id,
            "target_snapshot_id": snapshot.object_id,
        },
    ).removeprefix("sha256:")[:32]
    return AnalysisLeaseV1.issue(
        mission_id=mission_id,
        authority_id=decision.authority_id,
        target_snapshot_id=snapshot.object_id,
        issued_at=issued_at,
        expires_at=expires_at,
        max_bytes=grant.max_bytes,
        max_candidates=grant.max_candidates,
        max_wallclock_seconds=grant.max_wallclock_seconds,
        lease_nonce=nonce,
    )


def _expected_outputs(
    *,
    snapshot: TargetSnapshotV1,
    source_bytes: dict[str, bytes],
    mission_id: str,
    authority_id: str,
    lease: AnalysisLeaseV1,
) -> tuple[list[tuple[str, str, dict[str, object]]], int, int]:
    outputs: list[tuple[str, str, dict[str, object]]] = []
    candidate_count = 0
    parse_failure_count = 0
    for snapshot_file in snapshot.files:
        analysis = analyze_python_bytes(
            snapshot_file.relative_path,
            source_bytes[snapshot_file.relative_path],
        )
        if analysis.parse_failure is not None:
            outputs.append(
                (
                    "parse_failed",
                    "VELITES",
                    {
                        "analysis_lease_id": lease.lease_id,
                        "parse_failure": analysis.parse_failure.to_dict(),
                        "source_artifact_digest": snapshot_file.artifact_digest,
                    },
                )
            )
            parse_failure_count += 1
            continue
        candidates = [
            StaticCandidateV1.from_finding(
                finding,
                mission_id=mission_id,
                authority_id=authority_id,
                analysis_lease_id=lease.lease_id,
                target_snapshot_id=snapshot.object_id,
                source_artifact_digest=snapshot_file.artifact_digest,
            )
            for finding in analysis.findings
        ]
        candidates.sort(
            key=lambda candidate: (
                candidate.relative_path,
                candidate.line,
                candidate.column,
                candidate.rule_id,
                candidate.symbol,
                candidate.candidate_id,
            )
        )
        for candidate in candidates:
            outputs.append(
                (
                    "candidate_recorded",
                    "VELITES",
                    {"candidate": candidate.to_envelope().to_dict()},
                )
            )
            candidate_count += 1
    return outputs, candidate_count, parse_failure_count


def _assert_retained_prefix(
    retained: tuple[EventV1, ...],
    expected_outputs: list[tuple[str, str, dict[str, object]]],
) -> int:
    retained_outputs = [
        event
        for event in retained
        if event.kind in {"candidate_recorded", "parse_failed"}
    ]
    if len(retained_outputs) > len(expected_outputs):
        raise FixtureMissionError("retained output stream is longer than deterministic replay")
    for event, (kind, unit, payload) in zip(
        retained_outputs,
        expected_outputs,
        strict=False,
    ):
        if event.kind != kind or event.unit != unit or thaw_json(event.payload) != payload:
            raise FixtureMissionError("retained scan output differs from deterministic replay")
    return len(retained_outputs)


def run_fixture_scan(
    *,
    mission_id: str,
    snapshot: TargetSnapshotV1,
    signed_authority: SignedAuthorityGrantV1 | bytes | str,
    trust_store: TrustStore,
    evidence_store: FileEvidenceStore,
    event_store: SQLiteEventStore,
    decision_time: int,
    cancel_requested: bool = False,
    monotonic_ns: Callable[[], int] = time.monotonic_ns,
) -> MissionProjection:
    """Run a candidate-only fixture scan and close it after scan completion."""

    return _run_fixture_scan(
        mission_id=mission_id,
        snapshot=snapshot,
        signed_authority=signed_authority,
        trust_store=trust_store,
        evidence_store=evidence_store,
        event_store=event_store,
        decision_time=decision_time,
        required_actions=_STATIC_ANALYSIS_ACTIONS,
        retain_for_verification=False,
        cancel_requested=cancel_requested,
        monotonic_ns=monotonic_ns,
    )


def prepare_fixture_scan_for_verification(
    *,
    mission_id: str,
    snapshot: TargetSnapshotV1,
    signed_authority: SignedAuthorityGrantV1 | bytes | str,
    trust_store: TrustStore,
    evidence_store: FileEvidenceStore,
    event_store: SQLiteEventStore,
    decision_time: int,
    cancel_requested: bool = False,
    monotonic_ns: Callable[[], int] = time.monotonic_ns,
) -> MissionProjection:
    """Run an explicitly verification-authorized scan and retain its candidates.

    A scan with candidates remains at ``scan_completed`` until the kernel issues
    verification leases. A zero-candidate scan closes normally. This function executes
    no proof artifact and cannot mint a receipt or finding.
    """

    return _run_fixture_scan(
        mission_id=mission_id,
        snapshot=snapshot,
        signed_authority=signed_authority,
        trust_store=trust_store,
        evidence_store=evidence_store,
        event_store=event_store,
        decision_time=decision_time,
        required_actions=_FIXTURE_VERIFICATION_ACTIONS,
        retain_for_verification=True,
        cancel_requested=cancel_requested,
        monotonic_ns=monotonic_ns,
    )


def _retained_required_actions(retained: tuple[EventV1, ...]) -> tuple[str, ...]:
    payload = thaw_json(retained[0].payload)
    admission = AuthorityAdmissionV1.from_envelope(
        EnvelopeV1.from_bytes(canonical_dumps(payload["admission"]))
    )
    return admission.required_actions


def _run_fixture_scan(
    *,
    mission_id: str,
    snapshot: TargetSnapshotV1,
    signed_authority: SignedAuthorityGrantV1 | bytes | str,
    trust_store: TrustStore,
    evidence_store: FileEvidenceStore,
    event_store: SQLiteEventStore,
    decision_time: int,
    required_actions: tuple[str, ...],
    retain_for_verification: bool,
    cancel_requested: bool,
    monotonic_ns: Callable[[], int],
) -> MissionProjection:
    """Shared implementation for the two explicit fixture-scan mission contracts."""

    mission_id = _require_mission_id(mission_id)
    if not isinstance(snapshot, TargetSnapshotV1):
        raise FixtureMissionError("snapshot must be a TargetSnapshotV1")
    if not isinstance(trust_store, TrustStore):
        raise FixtureMissionError("trust_store must be a TrustStore")
    if not isinstance(evidence_store, FileEvidenceStore):
        raise FixtureMissionError("evidence_store must be a FileEvidenceStore")
    if type(decision_time) is not int or decision_time < 0:
        raise FixtureMissionError("decision_time must be a nonnegative integer")
    if type(cancel_requested) is not bool:
        raise FixtureMissionError("cancel_requested must be a bool")

    retained = event_store.load(mission_id)
    if retained:
        projection = reduce_events(retained)
        if projection.target_id != snapshot.object_id:
            raise FixtureMissionError("mission ID is already bound to another target snapshot")
        if projection.is_terminal:
            if (
                projection.phase is ProjectionPhase.CLOSED
                and _retained_required_actions(retained) != required_actions
            ):
                raise FixtureMissionError(
                    "resume mission intent differs from the retained admission"
                )
            return projection
        if _retained_required_actions(retained) != required_actions:
            raise FixtureMissionError(
                "resume mission intent differs from the retained admission"
            )
        if projection.phase is ProjectionPhase.AWAITING_VERIFICATION:
            return projection
        if projection.phase is ProjectionPhase.SCAN_COMPLETED:
            if retain_for_verification and projection.candidate_events:
                return projection
            if projection.scan_summary is None:
                raise FixtureMissionError("completed scan omitted its retained summary")
            retained = _append_checked(
                event_store,
                retained,
                mission_id=mission_id,
                kind="mission_closed",
                unit="ETZIO",
                authority_id=projection.authority_id,
                target_id=snapshot.object_id,
                decision_time=decision_time,
                payload={
                    "candidate_count": projection.scan_summary.payload[
                        "candidate_count"
                    ],
                    "parse_failure_count": projection.scan_summary.payload[
                        "parse_failure_count"
                    ],
                    "status": (
                        "receipt_coverage_complete"
                        if "modeled_fixture_verification" in required_actions
                        else "completed"
                    ),
                },
            )
            return reduce_events(retained)

    decision = admit_authority(
        signed_authority,
        trust_store,
        decision_time=decision_time,
        expected_target_snapshot_id=snapshot.object_id,
        required_actions=required_actions,
    )
    if not retained and not decision.accepted:
        return _refuse_initial_mission(
            event_store,
            mission_id=mission_id,
            target_id=snapshot.object_id,
            authority_id=UNADMITTED_AUTHORITY_ID,
            decision_time=decision_time,
            reason_code=decision.reason_code,
            stage="admission",
        )
    if retained and not decision.accepted:
        first_authority_id = retained[0].authority_id
        retained = _append_checked(
            event_store,
            retained,
            mission_id=mission_id,
            kind="scan_cancelled",
            unit="AQUILA",
            authority_id=first_authority_id,
            target_id=snapshot.object_id,
            decision_time=decision_time,
            payload={"reason_code": f"authority_{decision.reason_code}"},
        )
        return reduce_events(retained)

    if (
        decision.authority_id is None
        or decision.key_id is None
        or decision.grant is None
        or decision.admission is None
    ):
        raise FixtureMissionError("accepted authority omitted its enforceable admission record")
    signed = _coerce_signed_grant(signed_authority)

    if retained:
        if retained[0].authority_id != decision.authority_id:
            raise FixtureMissionError("mission ID is already bound to another authority")
        admitted_payload = thaw_json(retained[0].payload)
        if (
            admitted_payload["grant"]
            != decision.grant.to_envelope().to_dict()
            or admitted_payload["key_id"] != signed.key_id
            or admitted_payload["signature_b64"] != signed.signature_b64
        ):
            raise FixtureMissionError("resume authority differs from the retained admission")

    preflight_reason, source_bytes = _preflight(snapshot, decision, evidence_store)
    if not retained and preflight_reason is not None:
        return _refuse_initial_mission(
            event_store,
            mission_id=mission_id,
            target_id=snapshot.object_id,
            authority_id=decision.authority_id,
            decision_time=decision_time,
            reason_code=preflight_reason,
            stage="preflight",
        )
    if retained and preflight_reason is not None:
        retained = _append_checked(
            event_store,
            retained,
            mission_id=mission_id,
            kind="scan_failed",
            unit="ETZIO",
            authority_id=decision.authority_id,
            target_id=snapshot.object_id,
            decision_time=decision_time,
            payload={"reason_code": preflight_reason},
        )
        return reduce_events(retained)

    if not retained:
        retained = _append_checked(
            event_store,
            retained,
            mission_id=mission_id,
            kind="authority_admitted",
            unit="AQUILA",
            authority_id=decision.authority_id,
            target_id=snapshot.object_id,
            decision_time=decision_time,
            payload={
                "admission": decision.admission.to_envelope().to_dict(),
                "grant": decision.grant.to_envelope().to_dict(),
                "key_id": signed.key_id,
                "signature_b64": signed.signature_b64,
            },
        )

    if cancel_requested:
        retained = _append_checked(
            event_store,
            retained,
            mission_id=mission_id,
            kind="scan_cancelled",
            unit="AQUILA",
            authority_id=decision.authority_id,
            target_id=snapshot.object_id,
            decision_time=decision_time,
            payload={"reason_code": "operator_cancelled"},
        )
        return reduce_events(retained)

    projection = reduce_events(retained)
    if projection.phase is ProjectionPhase.ADMITTED:
        retained = _append_checked(
            event_store,
            retained,
            mission_id=mission_id,
            kind="mission_opened",
            unit="ETZIO",
            authority_id=decision.authority_id,
            target_id=snapshot.object_id,
            decision_time=decision_time,
            payload={"target_snapshot": snapshot.to_envelope().to_dict()},
        )

    admission_time = retained[0].decision_time
    lease = _lease_for(
        mission_id,
        decision,
        snapshot,
        issued_at=admission_time,
    )
    projection = reduce_events(retained)
    if projection.phase is ProjectionPhase.OPEN:
        if decision_time >= lease.expires_at:
            retained = _append_checked(
                event_store,
                retained,
                mission_id=mission_id,
                kind="scan_timed_out",
                unit="ETZIO",
                authority_id=decision.authority_id,
                target_id=snapshot.object_id,
                decision_time=decision_time,
                payload={"reason_code": "lease_expired_before_issuance"},
            )
            return reduce_events(retained)
        retained = _append_checked(
            event_store,
            retained,
            mission_id=mission_id,
            kind="analysis_lease_issued",
            unit="AQUILA",
            authority_id=decision.authority_id,
            target_id=snapshot.object_id,
            decision_time=decision_time,
            payload={"lease": lease.to_envelope().to_dict()},
        )
    else:
        lease_events = [event for event in retained if event.kind == "analysis_lease_issued"]
        if len(lease_events) != 1 or thaw_json(lease_events[0].payload)["lease"] != (
            lease.to_envelope().to_dict()
        ):
            raise FixtureMissionError("retained analysis lease differs from deterministic replay")

    projection = reduce_events(retained)
    if (
        projection.phase is ProjectionPhase.ANALYZING
        and decision_time >= lease.expires_at
    ):
        retained = _append_checked(
            event_store,
            retained,
            mission_id=mission_id,
            kind="scan_timed_out",
            unit="ETZIO",
            authority_id=decision.authority_id,
            target_id=snapshot.object_id,
            decision_time=decision_time,
            payload={"reason_code": "lease_expired"},
        )
        return reduce_events(retained)

    started_ns = monotonic_ns()
    try:
        outputs, candidate_count, parse_failure_count = _expected_outputs(
            snapshot=snapshot,
            source_bytes=source_bytes,
            mission_id=mission_id,
            authority_id=decision.authority_id,
            lease=lease,
        )
    except (EvidenceError, OSError, SyntaxError, UnicodeError, ValueError):
        retained = _append_checked(
            event_store,
            retained,
            mission_id=mission_id,
            kind="scan_failed",
            unit="ETZIO",
            authority_id=decision.authority_id,
            target_id=snapshot.object_id,
            decision_time=decision_time,
            payload={"reason_code": "analyzer_failed"},
        )
        return reduce_events(retained)
    elapsed_ns = monotonic_ns() - started_ns
    if elapsed_ns < 0:
        raise FixtureMissionError("monotonic clock moved backward")
    if elapsed_ns > lease.max_wallclock_seconds * 1_000_000_000:
        retained = _append_checked(
            event_store,
            retained,
            mission_id=mission_id,
            kind="scan_timed_out",
            unit="ETZIO",
            authority_id=decision.authority_id,
            target_id=snapshot.object_id,
            decision_time=decision_time,
            payload={"reason_code": "wallclock_budget_exhausted"},
        )
        return reduce_events(retained)
    if candidate_count > lease.max_candidates:
        retained = _append_checked(
            event_store,
            retained,
            mission_id=mission_id,
            kind="budget_exhausted",
            unit="AQUILA",
            authority_id=decision.authority_id,
            target_id=snapshot.object_id,
            decision_time=decision_time,
            payload={"reason_code": "candidate_budget_exhausted"},
        )
        return reduce_events(retained)

    retained_output_count = _assert_retained_prefix(retained, outputs)
    for kind, unit, payload in outputs[retained_output_count:]:
        retained = _append_checked(
            event_store,
            retained,
            mission_id=mission_id,
            kind=kind,
            unit=unit,
            authority_id=decision.authority_id,
            target_id=snapshot.object_id,
            decision_time=decision_time,
            payload=payload,
        )

    summary = {
        "analyzer_version": PYTHON_SAST_VERSION,
        "bytes_scanned": sum(snapshot_file.size for snapshot_file in snapshot.files),
        "candidate_count": candidate_count,
        "file_count": len(snapshot.files),
        "parse_failure_count": parse_failure_count,
    }
    projection = reduce_events(retained)
    if projection.phase is ProjectionPhase.ANALYZING:
        retained = _append_checked(
            event_store,
            retained,
            mission_id=mission_id,
            kind="scan_completed",
            unit="VELITES",
            authority_id=decision.authority_id,
            target_id=snapshot.object_id,
            decision_time=decision_time,
            payload=summary,
        )
    elif projection.phase is ProjectionPhase.SCAN_COMPLETED:
        if projection.scan_summary is None or thaw_json(projection.scan_summary.payload) != summary:
            raise FixtureMissionError("retained scan summary differs from deterministic replay")
    else:
        raise FixtureMissionError(f"cannot complete fixture scan from phase {projection.phase.value}")

    if retain_for_verification and candidate_count:
        return reduce_events(retained)

    retained = _append_checked(
        event_store,
        retained,
        mission_id=mission_id,
        kind="mission_closed",
        unit="ETZIO",
        authority_id=decision.authority_id,
        target_id=snapshot.object_id,
        decision_time=decision_time,
        payload={
            "candidate_count": candidate_count,
            "parse_failure_count": parse_failure_count,
            "status": (
                "receipt_coverage_complete"
                if "modeled_fixture_verification" in required_actions
                else "completed"
            ),
        },
    )
    return reduce_events(retained)
