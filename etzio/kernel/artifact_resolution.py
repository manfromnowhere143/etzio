"""Kernel resolution of modeled verification artifacts from retained CAS bytes.

This command derives every reference and expected type from canonical mission history,
reads and rehashes the referenced bytes, and appends one historical resolution event.  It
does not accept a receipt, consume a lease, execute an artifact, evaluate an oracle,
adjudicate a verdict, or mint a finding.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import NoReturn, Protocol

from ..authority import AuthorityGrantV1
from ..evidence import (
    VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1,
    EvidenceError,
    FileEvidenceStore,
    TargetSnapshotV1,
    validate_etzio_fixture_snapshot,
)
from ..mission_v1 import StaticCandidateV1
from ..protocol import EnvelopeV1, ProtocolError, canonical_dumps, thaw_json
from ..verification import MAX_EPOCH_SECOND, VerificationLeaseV1
from ..verification_artifacts import (
    MAX_RESOLUTION_ARTIFACT_BYTES_V1,
    MAX_TYPED_VERIFICATION_INPUT_BYTES_V1,
    TARGET_ARTIFACT_TYPE_V1,
    TargetArtifactBindingV1,
    VerificationArtifactBindingV1,
    VerificationArtifactError,
    VerificationArtifactResolutionV1,
)
from .events_v1 import EventV1
from .reducer import MissionProjection, ProjectionPhase, reduce_events
from .store import SQLiteEventStore, StaleHeadError

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)


class _EventStorePort(Protocol):
    def load(self, mission_id: str) -> tuple[EventV1, ...]: ...

    def append(self, event: EventV1, *, expected_head: str) -> EventV1: ...


class VerificationArtifactResolutionError(ProtocolError):
    """A typed artifact resolution cannot enter canonical mission history."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class VerificationArtifactResolution:
    """The retained event and resolution reconstructed after command completion."""

    projection: MissionProjection
    event: EventV1
    resolution: VerificationArtifactResolutionV1
    replayed: bool


def _reject(reason_code: str, message: str) -> NoReturn:
    raise VerificationArtifactResolutionError(reason_code, message)


def _require_digest(name: str, value: object) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        _reject(f"invalid_{name}", f"{name} must be a full sha256 content ID")
    return value


def _validate_request(
    *,
    event_store: object,
    evidence_store: object,
    mission_id: object,
    expected_head: object,
    verification_lease_id: object,
    decision_time: object,
) -> tuple[
    _EventStorePort,
    FileEvidenceStore,
    str,
    str,
    str,
    int,
]:
    if not callable(getattr(event_store, "load", None)) or not callable(getattr(event_store, "append", None)):
        _reject(
            "invalid_event_store",
            "event_store must provide load and append operations",
        )
    if not isinstance(evidence_store, FileEvidenceStore):
        _reject(
            "invalid_evidence_store",
            "evidence_store must be a FileEvidenceStore",
        )
    mission = _require_digest("mission_id", mission_id)
    head = _require_digest("expected_head", expected_head)
    lease_id = _require_digest(
        "verification_lease_id",
        verification_lease_id,
    )
    if type(decision_time) is not int or decision_time < 0 or decision_time > MAX_EPOCH_SECOND:
        _reject(
            "invalid_decision_time",
            "decision_time must be a nonnegative int64 epoch second",
        )
    return (
        event_store,
        evidence_store,
        mission,
        head,
        lease_id,
        decision_time,
    )


def _nested_envelope(event: EventV1, field: str) -> EnvelopeV1:
    return EnvelopeV1.from_bytes(canonical_dumps(thaw_json(event.payload)[field]))


def _grant(projection: MissionProjection) -> AuthorityGrantV1:
    first = projection.events[0]
    if first.kind != "authority_admitted":
        _reject(
            "mission_not_admitted",
            "artifact resolution requires retained authority admission",
        )
    return AuthorityGrantV1.from_envelope(_nested_envelope(first, "grant"))


def _target_snapshot(projection: MissionProjection) -> TargetSnapshotV1:
    for event in projection.events:
        if event.kind == "mission_opened":
            return TargetSnapshotV1.from_envelope(_nested_envelope(event, "target_snapshot"))
    _reject(
        "target_not_retained",
        "artifact resolution requires a retained target snapshot",
    )


def _verification_lease(
    projection: MissionProjection,
    verification_lease_id: str,
) -> VerificationLeaseV1:
    for event in projection.verification_lease_events:
        lease = VerificationLeaseV1.from_envelope(_nested_envelope(event, "lease"))
        if lease.lease_id == verification_lease_id:
            return lease
    _reject(
        "verification_lease_not_retained",
        "verification_lease_id is absent from canonical mission history",
    )


def _assert_candidate_retained(
    projection: MissionProjection,
    candidate_id: str,
) -> None:
    for event in projection.candidate_events:
        candidate = StaticCandidateV1.from_envelope(_nested_envelope(event, "candidate"))
        if candidate.candidate_id == candidate_id:
            return
    _reject(
        "candidate_not_retained",
        "verification lease candidate is absent from canonical mission history",
    )


def _resolution_from_event(
    event: EventV1,
) -> VerificationArtifactResolutionV1:
    return VerificationArtifactResolutionV1.from_envelope(_nested_envelope(event, "resolution"))


def _existing_resolution(
    projection: MissionProjection,
    verification_lease_id: str,
) -> tuple[EventV1, VerificationArtifactResolutionV1] | None:
    found: tuple[EventV1, VerificationArtifactResolutionV1] | None = None
    for event in projection.verification_artifact_resolution_events:
        resolution = _resolution_from_event(event)
        if resolution.verification_lease_id != verification_lease_id:
            continue
        if found is not None:
            _reject(
                "duplicate_retained_resolution",
                "verification lease has multiple retained artifact resolutions",
            )
        found = (event, resolution)
    return found


def _read_generic(
    evidence_store: FileEvidenceStore,
    *,
    digest: str,
    expected_size: int,
    maximum: int,
) -> bytes:
    if expected_size > maximum:
        _reject(
            "resolution_byte_ceiling_exceeded",
            "target artifacts exceed the available resolution byte budget",
        )
    try:
        data = evidence_store.get(digest, maximum=expected_size)
    except EvidenceError as exc:
        _reject(
            "target_artifact_unavailable",
            f"target artifact cannot be resolved: {exc}",
        )
    if len(data) != expected_size:
        _reject(
            "target_artifact_size_mismatch",
            "target artifact size differs from the retained snapshot",
        )
    return data


def _read_typed(
    evidence_store: FileEvidenceStore,
    *,
    digest: str,
    artifact_type: str,
    role: str,
    maximum: int,
) -> bytes:
    try:
        return evidence_store.get_typed(
            digest,
            expected_type=artifact_type,
            maximum=maximum,
        )
    except EvidenceError as exc:
        if str(exc) == "evidence artifact exceeds configured limit":
            _reject(
                "resolution_byte_ceiling_exceeded",
                "typed verification inputs exceed the admitted byte ceiling",
            )
        _reject(
            f"{role}_artifact_unavailable",
            f"{role} artifact cannot be resolved under its expected type: {exc}",
        )


def _resolve_from_cas(
    *,
    evidence_store: FileEvidenceStore,
    projection: MissionProjection,
    lease: VerificationLeaseV1,
    resolved_at: int,
    grant: AuthorityGrantV1,
) -> VerificationArtifactResolutionV1:
    snapshot = _target_snapshot(projection)
    if snapshot.object_id != lease.target_snapshot_id:
        _reject(
            "target_mismatch",
            "verification lease target differs from the retained snapshot",
        )
    try:
        validate_etzio_fixture_snapshot(snapshot, evidence_store)
    except EvidenceError as exc:
        _reject(
            "target_manifest_mismatch",
            f"target snapshot no longer matches the immutable fixture manifest: {exc}",
        )

    target_bytes = sum(value.size for value in snapshot.files)
    if target_bytes > grant.max_bytes:
        _reject(
            "resolution_byte_ceiling_exceeded",
            "target bytes exhaust the signed resolution byte ceiling",
        )

    target_bindings: list[TargetArtifactBindingV1] = []
    for snapshot_file in snapshot.files:
        data = _read_generic(
            evidence_store,
            digest=snapshot_file.artifact_digest,
            expected_size=snapshot_file.size,
            maximum=snapshot_file.size,
        )
        target_bindings.append(
            TargetArtifactBindingV1(
                artifact_digest=snapshot_file.artifact_digest,
                artifact_type=TARGET_ARTIFACT_TYPE_V1,
                relative_path=snapshot_file.relative_path,
                size=len(data),
            )
        )

    typed_limit = min(
        grant.max_bytes - target_bytes,
        MAX_TYPED_VERIFICATION_INPUT_BYTES_V1,
    )
    remaining = typed_limit

    def resolve_singleton(
        *,
        digest: str,
        role: str,
    ) -> VerificationArtifactBindingV1:
        nonlocal remaining
        artifact_type = VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1[role]
        data = _read_typed(
            evidence_store,
            digest=digest,
            artifact_type=artifact_type,
            role=role,
            maximum=remaining,
        )
        remaining -= len(data)
        return VerificationArtifactBindingV1(
            artifact_digest=digest,
            artifact_type=artifact_type,
            size=len(data),
        )

    poc = resolve_singleton(
        digest=lease.poc_artifact_digest,
        role="poc",
    )
    environment = resolve_singleton(
        digest=lease.environment_digest,
        role="environment",
    )
    effect_oracle = resolve_singleton(
        digest=lease.effect_oracle_id,
        role="effect_oracle",
    )
    evidence: list[VerificationArtifactBindingV1] = []
    for digest in lease.evidence_artifact_digests:
        evidence.append(resolve_singleton(digest=digest, role="evidence"))

    try:
        resolution = VerificationArtifactResolutionV1.issue(
            authority_id=lease.authority_id,
            candidate_id=lease.candidate_id,
            effect_oracle_artifact=effect_oracle,
            environment_artifact=environment,
            evidence_artifacts=tuple(evidence),
            mission_id=lease.mission_id,
            poc_artifact=poc,
            resolved_at=resolved_at,
            target_artifacts=tuple(target_bindings),
            target_snapshot_id=lease.target_snapshot_id,
            verification_lease_id=lease.lease_id,
        )
    except VerificationArtifactError as exc:
        _reject(exc.reason_code, str(exc))
    if (
        resolution.typed_input_bytes > typed_limit
        or resolution.total_bytes > grant.max_bytes
    ):
        _reject(
            "resolution_byte_ceiling_exceeded",
            "resolved artifacts exceed the signed byte ceiling",
        )
    if resolution.total_bytes > MAX_RESOLUTION_ARTIFACT_BYTES_V1:
        _reject(
            "resolution_byte_ceiling_exceeded",
            "resolved artifacts exceed the fixed overall byte ceiling",
        )
    return resolution


def _replay_existing(
    *,
    projection: MissionProjection,
    existing_event: EventV1,
    existing_resolution: VerificationArtifactResolutionV1,
    evidence_store: FileEvidenceStore,
    lease: VerificationLeaseV1,
    grant: AuthorityGrantV1,
    decision_time: int,
) -> VerificationArtifactResolution:
    if existing_resolution.resolved_at != decision_time:
        _reject(
            "verification_lease_resolution_conflict",
            "verification lease already has a resolution at a different time",
        )
    current = _resolve_from_cas(
        evidence_store=evidence_store,
        projection=projection,
        lease=lease,
        resolved_at=decision_time,
        grant=grant,
    )
    if current.to_envelope().to_bytes() != existing_resolution.to_envelope().to_bytes():
        _reject(
            "retained_resolution_mismatch",
            "retained artifact resolution differs from current typed CAS bytes",
        )
    return VerificationArtifactResolution(
        projection=projection,
        event=existing_event,
        resolution=existing_resolution,
        replayed=True,
    )


def resolve_modeled_fixture_verification_artifacts(
    *,
    event_store: SQLiteEventStore,
    evidence_store: FileEvidenceStore,
    mission_id: str,
    expected_head: str,
    verification_lease_id: str,
    decision_time: int,
) -> VerificationArtifactResolution:
    """Resolve and retain one exact typed artifact set for a prior verification lease."""

    (
        event_store,
        evidence_store,
        mission_id,
        expected_head,
        verification_lease_id,
        decision_time,
    ) = _validate_request(
        event_store=event_store,
        evidence_store=evidence_store,
        mission_id=mission_id,
        expected_head=expected_head,
        verification_lease_id=verification_lease_id,
        decision_time=decision_time,
    )
    retained = event_store.load(mission_id)
    if not retained:
        _reject(
            "mission_not_found",
            "artifact resolution requires a retained mission stream",
        )
    projection = reduce_events(retained)
    lease = _verification_lease(projection, verification_lease_id)
    _assert_candidate_retained(projection, lease.candidate_id)
    grant = _grant(projection)

    if (
        verification_lease_id
        not in projection.active_verification_lease_ids
    ):
        _reject(
            "verification_lease_inactive",
            "artifact resolution requires the active candidate-lineage lease",
        )

    existing = _existing_resolution(projection, verification_lease_id)
    if existing is not None:
        return _replay_existing(
            projection=projection,
            existing_event=existing[0],
            existing_resolution=existing[1],
            evidence_store=evidence_store,
            lease=lease,
            grant=grant,
            decision_time=decision_time,
        )

    if projection.is_terminal:
        _reject(
            "mission_terminal",
            "artifacts cannot be resolved after mission termination",
        )
    if projection.phase is not ProjectionPhase.AWAITING_VERIFICATION:
        _reject(
            "verification_lease_not_issued",
            "artifact resolution requires an issued verification lease",
        )
    actual_head = retained[-1].event_digest
    if actual_head != expected_head:
        raise StaleHeadError(f"stale mission head: expected {expected_head}, retained {actual_head}")
    if decision_time < retained[-1].decision_time:
        _reject(
            "decision_time_regressed",
            "artifact resolution time precedes the retained mission head",
        )
    if decision_time < lease.issued_at:
        _reject(
            "resolution_before_lease",
            "artifact resolution cannot precede verification lease issuance",
        )
    if decision_time >= lease.expires_at:
        _reject(
            "verification_lease_expired",
            "artifact resolution requires an unexpired verification lease",
        )

    resolution = _resolve_from_cas(
        evidence_store=evidence_store,
        projection=projection,
        lease=lease,
        resolved_at=decision_time,
        grant=grant,
    )
    event = EventV1.create(
        mission_id=projection.mission_id,
        seq=len(retained),
        kind="verification_artifacts_resolved",
        unit="ETZIO",
        authority_id=projection.authority_id,
        target_id=projection.target_id,
        decision_time=decision_time,
        payload={"resolution": resolution.to_envelope().to_dict()},
        prev_digest=actual_head,
    )
    reduce_events((*retained, event))
    try:
        event_store.append(event, expected_head=expected_head)
    except StaleHeadError:
        raced_projection = reduce_events(event_store.load(mission_id))
        raced_existing = _existing_resolution(
            raced_projection,
            verification_lease_id,
        )
        if raced_existing is None:
            raise
        return _replay_existing(
            projection=raced_projection,
            existing_event=raced_existing[0],
            existing_resolution=raced_existing[1],
            evidence_store=evidence_store,
            lease=_verification_lease(
                raced_projection,
                verification_lease_id,
            ),
            grant=_grant(raced_projection),
            decision_time=decision_time,
        )

    committed_projection = reduce_events(event_store.load(mission_id))
    committed_event = next(
        (
            retained_event
            for retained_event in (committed_projection.verification_artifact_resolution_events)
            if retained_event.event_digest == event.event_digest
        ),
        None,
    )
    if committed_event is None:
        _reject(
            "committed_event_missing",
            "appended artifact resolution event is absent from replay",
        )
    committed_resolution = _resolution_from_event(committed_event)
    if committed_resolution.resolution_id != resolution.resolution_id:
        _reject(
            "committed_resolution_mismatch",
            "appended artifact resolution differs after replay",
        )
    return VerificationArtifactResolution(
        projection=committed_projection,
        event=committed_event,
        resolution=committed_resolution,
        replayed=False,
    )
