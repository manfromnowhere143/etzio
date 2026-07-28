"""Explicit modeled-fixture verification-lease recovery commands.

These commands retain lifecycle decisions for an already-issued verification lease.
They do not observe a trusted clock, terminate a worker, prove control-plane identity,
execute an artifact, adjudicate a receipt, or mint a finding.  Their caller-supplied
``decision_time`` and AQUILA control decisions remain modeled until later authority and
clock gates retain stronger evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import NoReturn

from ..authority import AuthorityAdmissionV1, AuthorityGrantV1
from ..protocol import EnvelopeV1, ProtocolError, canonical_dumps, thaw_json
from ..verification import (
    MAX_EPOCH_SECOND,
    VERIFIER_ROLE,
    VerificationError,
    VerificationLeaseV1,
    VerifierTrustStore,
    derive_verification_lease_nonce,
)
from .events_v1 import (
    ACTIVE_LEASE_REASSIGNMENT_REASON_V1,
    CANCELLED_LEASE_REASSIGNMENT_REASON_V1,
    EXPIRED_LEASE_REASSIGNMENT_REASON_V1,
    VERIFICATION_LEASE_CANCELLATION_REASON_V1,
    EventV1,
)
from .reducer import MissionProjection, ProjectionPhase, reduce_events
from .store import SQLiteEventStore, StaleHeadError

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
_KEY_ID = re.compile(r"^ed25519:sha256:[0-9a-f]{64}$", re.ASCII)

class VerificationLeaseRecoveryError(ProtocolError):
    """A verification recovery decision cannot enter canonical mission history."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class VerificationLeaseDisposition:
    """One retained expiry or cancellation and its referenced lease."""

    projection: MissionProjection
    event: EventV1
    lease: VerificationLeaseV1
    replayed: bool


@dataclass(frozen=True, slots=True)
class VerificationLeaseReassignment:
    """One retained predecessor-to-successor lease transition."""

    projection: MissionProjection
    event: EventV1
    predecessor_lease: VerificationLeaseV1
    lease: VerificationLeaseV1
    replayed: bool


@dataclass(frozen=True, slots=True)
class VerificationMissionClosure:
    """One retained verification-intent mission closure."""

    projection: MissionProjection
    event: EventV1
    status: str
    replayed: bool


def _reject(reason_code: str, message: str) -> NoReturn:
    raise VerificationLeaseRecoveryError(reason_code, message)


def _require_digest(name: str, value: object) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        _reject(f"invalid_{name}", f"{name} must be a full sha256 content ID")
    return value


def _require_time(value: object) -> int:
    if type(value) is not int or value < 0 or value > MAX_EPOCH_SECOND:
        _reject(
            "invalid_decision_time",
            "decision_time must be a nonnegative int64 epoch second",
        )
    return value


def _require_store(value: object) -> SQLiteEventStore:
    if not callable(getattr(value, "load", None)) or not callable(
        getattr(value, "append", None)
    ):
        _reject(
            "invalid_event_store",
            "event_store must provide load and append operations",
        )
    return value  # type: ignore[return-value]


def _nested_envelope(event: EventV1, field: str) -> EnvelopeV1:
    return EnvelopeV1.from_bytes(
        canonical_dumps(thaw_json(event.payload)[field])
    )


def _lease_from_event(event: EventV1) -> VerificationLeaseV1:
    return VerificationLeaseV1.from_envelope(_nested_envelope(event, "lease"))


def _lease_by_id(
    projection: MissionProjection,
    verification_lease_id: str,
) -> VerificationLeaseV1:
    for event in projection.verification_lease_events:
        lease = _lease_from_event(event)
        if lease.lease_id == verification_lease_id:
            return lease
    _reject(
        "verification_lease_not_retained",
        "verification_lease_id is absent from canonical mission history",
    )


def _authority_evidence(
    projection: MissionProjection,
) -> tuple[AuthorityGrantV1, AuthorityAdmissionV1]:
    first = projection.events[0]
    if first.kind != "authority_admitted":
        _reject(
            "mission_not_admitted",
            "verification recovery requires retained authority admission",
        )
    grant = AuthorityGrantV1.from_envelope(_nested_envelope(first, "grant"))
    admission = AuthorityAdmissionV1.from_envelope(
        _nested_envelope(first, "admission")
    )
    if (
        "modeled_fixture_verification" not in admission.required_actions
        or "modeled_fixture_verification" not in grant.permitted_actions
    ):
        _reject(
            "verification_not_authorized",
            "retained authority does not authorize modeled fixture verification",
        )
    return grant, admission


def _load(
    event_store: SQLiteEventStore,
    mission_id: str,
) -> tuple[tuple[EventV1, ...], MissionProjection]:
    retained = event_store.load(mission_id)
    if not retained:
        _reject(
            "mission_not_found",
            "verification recovery requires a retained mission stream",
        )
    return retained, reduce_events(retained)


def _assert_appendable(
    *,
    retained: tuple[EventV1, ...],
    projection: MissionProjection,
    expected_head: str,
    decision_time: int,
) -> str:
    if projection.is_terminal:
        _reject(
            "mission_terminal",
            "verification recovery cannot change a terminal mission",
        )
    if projection.phase is not ProjectionPhase.AWAITING_VERIFICATION:
        _reject(
            "verification_not_awaiting_recovery",
            "lease recovery requires awaiting_verification state",
        )
    actual_head = retained[-1].event_digest
    if actual_head != expected_head:
        raise StaleHeadError(
            f"stale mission head: expected {expected_head}, retained {actual_head}"
        )
    if decision_time < retained[-1].decision_time:
        _reject(
            "decision_time_regressed",
            "recovery decision time precedes the retained mission head",
        )
    return actual_head


def _existing_disposition(
    *,
    projection: MissionProjection,
    kind: str,
    verification_lease_id: str,
    decision_time: int,
    reason_code: str | None,
) -> VerificationLeaseDisposition | None:
    events = (
        projection.verification_lease_expiry_events
        if kind == "verification_lease_expired"
        else projection.verification_lease_cancellation_events
    )
    for event in events:
        payload = thaw_json(event.payload)
        if payload["verification_lease_id"] != verification_lease_id:
            continue
        exact = event.decision_time == decision_time
        if reason_code is not None:
            exact = exact and payload["reason_code"] == reason_code
        if not exact:
            _reject(
                "verification_lease_disposition_conflict",
                "verification lease already has a different terminal disposition",
            )
        return VerificationLeaseDisposition(
            projection=projection,
            event=event,
            lease=_lease_by_id(projection, verification_lease_id),
            replayed=True,
        )
    return None


def _committed_disposition(
    *,
    event_store: SQLiteEventStore,
    mission_id: str,
    event: EventV1,
    verification_lease_id: str,
) -> VerificationLeaseDisposition:
    projection = reduce_events(event_store.load(mission_id))
    events = (
        projection.verification_lease_expiry_events
        if event.kind == "verification_lease_expired"
        else projection.verification_lease_cancellation_events
    )
    retained_event = next(
        (
            candidate
            for candidate in events
            if candidate.event_digest == event.event_digest
        ),
        None,
    )
    if retained_event is None:
        _reject(
            "committed_event_missing",
            "appended recovery event is absent from replay",
        )
    return VerificationLeaseDisposition(
        projection=projection,
        event=retained_event,
        lease=_lease_by_id(projection, verification_lease_id),
        replayed=False,
    )


def expire_modeled_fixture_verification_lease(
    *,
    event_store: SQLiteEventStore,
    mission_id: str,
    expected_head: str,
    verification_lease_id: str,
    decision_time: int,
) -> VerificationLeaseDisposition:
    """Explicitly retain that a modeled lease reached its caller-supplied deadline."""

    event_store = _require_store(event_store)
    mission_id = _require_digest("mission_id", mission_id)
    expected_head = _require_digest("expected_head", expected_head)
    verification_lease_id = _require_digest(
        "verification_lease_id",
        verification_lease_id,
    )
    decision_time = _require_time(decision_time)
    retained, projection = _load(event_store, mission_id)
    lease = _lease_by_id(projection, verification_lease_id)
    existing = _existing_disposition(
        projection=projection,
        kind="verification_lease_expired",
        verification_lease_id=verification_lease_id,
        decision_time=decision_time,
        reason_code=None,
    )
    if existing is not None:
        return existing
    _authority_evidence(projection)
    actual_head = _assert_appendable(
        retained=retained,
        projection=projection,
        expected_head=expected_head,
        decision_time=decision_time,
    )
    if verification_lease_id not in projection.active_verification_lease_ids:
        _reject(
            "verification_lease_inactive",
            "only the active lineage tip can expire",
        )
    if decision_time < lease.expires_at:
        _reject(
            "verification_lease_not_expired",
            "expiry cannot be retained before the lease deadline",
        )
    event = EventV1.create(
        mission_id=projection.mission_id,
        seq=len(retained),
        kind="verification_lease_expired",
        unit="ETZIO",
        authority_id=projection.authority_id,
        target_id=projection.target_id,
        decision_time=decision_time,
        payload={"verification_lease_id": verification_lease_id},
        prev_digest=actual_head,
    )
    reduce_events((*retained, event))
    try:
        event_store.append(event, expected_head=expected_head)
    except StaleHeadError:
        raced = reduce_events(event_store.load(mission_id))
        match = _existing_disposition(
            projection=raced,
            kind=event.kind,
            verification_lease_id=verification_lease_id,
            decision_time=decision_time,
            reason_code=None,
        )
        if match is not None:
            return match
        raise
    return _committed_disposition(
        event_store=event_store,
        mission_id=mission_id,
        event=event,
        verification_lease_id=verification_lease_id,
    )


def cancel_modeled_fixture_verification_lease(
    *,
    event_store: SQLiteEventStore,
    mission_id: str,
    expected_head: str,
    verification_lease_id: str,
    reason_code: str,
    decision_time: int,
) -> VerificationLeaseDisposition:
    """Retain one modeled AQUILA cancellation before a lease deadline."""

    event_store = _require_store(event_store)
    mission_id = _require_digest("mission_id", mission_id)
    expected_head = _require_digest("expected_head", expected_head)
    verification_lease_id = _require_digest(
        "verification_lease_id",
        verification_lease_id,
    )
    if reason_code != VERIFICATION_LEASE_CANCELLATION_REASON_V1:
        _reject(
            "unsupported_cancellation_reason",
            "modeled lease cancellation supports only operator_cancelled",
        )
    decision_time = _require_time(decision_time)
    retained, projection = _load(event_store, mission_id)
    lease = _lease_by_id(projection, verification_lease_id)
    existing = _existing_disposition(
        projection=projection,
        kind="verification_lease_cancelled",
        verification_lease_id=verification_lease_id,
        decision_time=decision_time,
        reason_code=reason_code,
    )
    if existing is not None:
        return existing
    _authority_evidence(projection)
    actual_head = _assert_appendable(
        retained=retained,
        projection=projection,
        expected_head=expected_head,
        decision_time=decision_time,
    )
    if verification_lease_id not in projection.active_verification_lease_ids:
        _reject(
            "verification_lease_inactive",
            "only the active lineage tip can be cancelled",
        )
    if decision_time >= lease.expires_at:
        _reject(
            "verification_lease_expiry_not_recorded",
            "an expired lease requires an explicit expiry event, not cancellation",
        )
    event = EventV1.create(
        mission_id=projection.mission_id,
        seq=len(retained),
        kind="verification_lease_cancelled",
        unit="AQUILA",
        authority_id=projection.authority_id,
        target_id=projection.target_id,
        decision_time=decision_time,
        payload={
            "verification_lease_id": verification_lease_id,
            "reason_code": reason_code,
        },
        prev_digest=actual_head,
    )
    reduce_events((*retained, event))
    try:
        event_store.append(event, expected_head=expected_head)
    except StaleHeadError:
        raced = reduce_events(event_store.load(mission_id))
        match = _existing_disposition(
            projection=raced,
            kind=event.kind,
            verification_lease_id=verification_lease_id,
            decision_time=decision_time,
            reason_code=reason_code,
        )
        if match is not None:
            return match
        raise
    return _committed_disposition(
        event_store=event_store,
        mission_id=mission_id,
        event=event,
        verification_lease_id=verification_lease_id,
    )


def _existing_reassignment(
    *,
    projection: MissionProjection,
    predecessor: VerificationLeaseV1,
    verifier_key_id: str,
    verifier_trust_store: VerifierTrustStore,
    decision_time: int,
    expires_at: int,
) -> VerificationLeaseReassignment | None:
    for event in projection.verification_lease_reassignment_events:
        payload = thaw_json(event.payload)
        if (
            payload["predecessor_verification_lease_id"]
            != predecessor.lease_id
        ):
            continue
        successor = _lease_from_event(event)
        exact = (
            event.decision_time == decision_time
            and successor.verifier_key_id == verifier_key_id
            and successor.issuance_trust_snapshot_id
            == verifier_trust_store.snapshot_id
            and successor.issued_at == decision_time
            and successor.expires_at == expires_at
            and payload["verifier_trust_snapshot_id"]
            == verifier_trust_store.snapshot_id
            and payload["verifier_trust_snapshot"]
            == verifier_trust_store.to_snapshot_body()
        )
        if not exact:
            _reject(
                "verification_lease_reassignment_conflict",
                "predecessor lease already has a different successor",
            )
        return VerificationLeaseReassignment(
            projection=projection,
            event=event,
            predecessor_lease=predecessor,
            lease=successor,
            replayed=True,
        )
    return None


def _reassignment_reason(
    projection: MissionProjection,
    predecessor_lease_id: str,
) -> str:
    if predecessor_lease_id in projection.active_verification_lease_ids:
        return ACTIVE_LEASE_REASSIGNMENT_REASON_V1
    if predecessor_lease_id in projection.expired_verification_lease_ids:
        return EXPIRED_LEASE_REASSIGNMENT_REASON_V1
    if predecessor_lease_id in projection.cancelled_verification_lease_ids:
        return CANCELLED_LEASE_REASSIGNMENT_REASON_V1
    if predecessor_lease_id in projection.consumed_verification_lease_ids:
        _reject(
            "verification_lease_consumed",
            "a consumed verification lease cannot be reassigned",
        )
    _reject(
        "verification_lease_not_lineage_tip",
        "only the current active, expired, or cancelled lineage tip can be reassigned",
    )


def reassign_modeled_fixture_verification_lease(
    *,
    event_store: SQLiteEventStore,
    mission_id: str,
    expected_head: str,
    predecessor_verification_lease_id: str,
    verifier_key_id: str,
    verifier_trust_store: VerifierTrustStore,
    decision_time: int,
    requested_wallclock_seconds: int,
) -> VerificationLeaseReassignment:
    """Atomically supersede or recover one lineage tip and issue its successor."""

    event_store = _require_store(event_store)
    mission_id = _require_digest("mission_id", mission_id)
    expected_head = _require_digest("expected_head", expected_head)
    predecessor_verification_lease_id = _require_digest(
        "predecessor_verification_lease_id",
        predecessor_verification_lease_id,
    )
    if type(verifier_key_id) is not str or _KEY_ID.fullmatch(verifier_key_id) is None:
        _reject(
            "invalid_verifier_key_id",
            "verifier_key_id must identify an Ed25519 public key",
        )
    if not isinstance(verifier_trust_store, VerifierTrustStore):
        _reject(
            "invalid_verifier_trust_store",
            "verifier_trust_store must be a VerifierTrustStore",
        )
    decision_time = _require_time(decision_time)
    if (
        type(requested_wallclock_seconds) is not int
        or requested_wallclock_seconds <= 0
        or requested_wallclock_seconds > MAX_EPOCH_SECOND
    ):
        _reject(
            "invalid_requested_wallclock",
            "requested_wallclock_seconds must be a positive int64",
        )

    retained, projection = _load(event_store, mission_id)
    predecessor = _lease_by_id(
        projection,
        predecessor_verification_lease_id,
    )
    grant, admission = _authority_evidence(projection)
    if requested_wallclock_seconds > grant.max_wallclock_seconds:
        _reject(
            "requested_wallclock_exceeds_grant",
            "requested successor window exceeds the admitted ceiling",
        )
    grant_deadline = min(
        grant.expires_at,
        admission.decision_time + grant.max_wallclock_seconds,
    )
    expires_at = min(
        grant_deadline,
        decision_time + requested_wallclock_seconds,
    )
    existing = _existing_reassignment(
        projection=projection,
        predecessor=predecessor,
        verifier_key_id=verifier_key_id,
        verifier_trust_store=verifier_trust_store,
        decision_time=decision_time,
        expires_at=expires_at,
    )
    if existing is not None:
        return existing
    actual_head = _assert_appendable(
        retained=retained,
        projection=projection,
        expected_head=expected_head,
        decision_time=decision_time,
    )
    latest = dict(projection.latest_verification_lease_by_candidate).get(
        predecessor.candidate_id
    )
    if latest != predecessor.lease_id:
        _reject(
            "verification_lease_not_lineage_tip",
            "predecessor is not the candidate's current lineage tip",
        )
    reason_code = _reassignment_reason(
        projection,
        predecessor.lease_id,
    )
    if (
        reason_code == ACTIVE_LEASE_REASSIGNMENT_REASON_V1
        and decision_time >= predecessor.expires_at
    ):
        _reject(
            "verification_lease_expiry_not_recorded",
            "an expired active lease must first receive an explicit expiry event",
        )
    if decision_time >= expires_at:
        _reject(
            "verification_window_exhausted",
            "no admitted successor verification time remains",
        )
    if len(projection.verification_lease_events) >= grant.max_candidates:
        _reject(
            "verification_lease_budget_exhausted",
            "verification lease count reached the admitted candidate ceiling",
        )
    if verifier_key_id in verifier_trust_store.revoked_key_ids:
        _reject(
            "verifier_key_revoked",
            "successor verifier key is revoked in the retained snapshot",
        )
    trusted_key = verifier_trust_store.keys.get(verifier_key_id)
    if trusted_key is None:
        _reject(
            "unknown_verifier_key",
            "successor verifier key is absent from the trust snapshot",
        )
    if VERIFIER_ROLE not in trusted_key.roles:
        _reject(
            "verifier_role_missing",
            "successor verifier key lacks the modeled fixture verifier role",
        )
    if trusted_key.verifier_id == predecessor.verifier_id:
        _reject(
            "verifier_not_reassigned",
            "successor must assign a different verifier identity",
        )
    if predecessor.candidate_producer_id == trusted_key.verifier_id:
        _reject(
            "self_verification",
            "candidate producer cannot verify its own candidate",
        )

    snapshot_id = verifier_trust_store.snapshot_id
    nonce = derive_verification_lease_nonce(
        prior_event_digest=actual_head,
        mission_id=predecessor.mission_id,
        authority_id=predecessor.authority_id,
        target_snapshot_id=predecessor.target_snapshot_id,
        candidate_id=predecessor.candidate_id,
        candidate_producer_id=predecessor.candidate_producer_id,
        poc_artifact_digest=predecessor.poc_artifact_digest,
        evidence_artifact_digests=predecessor.evidence_artifact_digests,
        environment_digest=predecessor.environment_digest,
        effect_oracle_id=predecessor.effect_oracle_id,
        verifier_id=trusted_key.verifier_id,
        verifier_key_id=verifier_key_id,
        issued_at=decision_time,
        expires_at=expires_at,
        issuance_trust_snapshot_id=snapshot_id,
    )
    try:
        lease = VerificationLeaseV1.issue(
            lease_nonce=nonce,
            mission_id=predecessor.mission_id,
            authority_id=predecessor.authority_id,
            target_snapshot_id=predecessor.target_snapshot_id,
            candidate_id=predecessor.candidate_id,
            candidate_producer_id=predecessor.candidate_producer_id,
            poc_artifact_digest=predecessor.poc_artifact_digest,
            evidence_artifact_digests=predecessor.evidence_artifact_digests,
            environment_digest=predecessor.environment_digest,
            effect_oracle_id=predecessor.effect_oracle_id,
            verifier_id=trusted_key.verifier_id,
            verifier_key_id=verifier_key_id,
            issuance_trust_snapshot_id=snapshot_id,
            issued_at=decision_time,
            expires_at=expires_at,
        )
    except VerificationError as exc:
        _reject(exc.reason_code, str(exc))
    event = EventV1.create(
        mission_id=projection.mission_id,
        seq=len(retained),
        kind="verification_lease_reassigned",
        unit="AQUILA",
        authority_id=projection.authority_id,
        target_id=projection.target_id,
        decision_time=decision_time,
        payload={
            "predecessor_verification_lease_id": predecessor.lease_id,
            "lease": lease.to_envelope().to_dict(),
            "reason_code": reason_code,
            "verifier_trust_snapshot": verifier_trust_store.to_snapshot_body(),
            "verifier_trust_snapshot_id": snapshot_id,
        },
        prev_digest=actual_head,
    )
    reduce_events((*retained, event))
    try:
        event_store.append(event, expected_head=expected_head)
    except StaleHeadError:
        raced = reduce_events(event_store.load(mission_id))
        match = _existing_reassignment(
            projection=raced,
            predecessor=predecessor,
            verifier_key_id=verifier_key_id,
            verifier_trust_store=verifier_trust_store,
            decision_time=decision_time,
            expires_at=expires_at,
        )
        if match is not None:
            return match
        raise

    committed = reduce_events(event_store.load(mission_id))
    retained_event = next(
        (
            candidate
            for candidate in committed.verification_lease_reassignment_events
            if candidate.event_digest == event.event_digest
        ),
        None,
    )
    if retained_event is None:
        _reject(
            "committed_event_missing",
            "appended reassignment event is absent from replay",
        )
    return VerificationLeaseReassignment(
        projection=committed,
        event=retained_event,
        predecessor_lease=predecessor,
        lease=_lease_from_event(retained_event),
        replayed=False,
    )


def _verification_closure_status(projection: MissionProjection) -> str:
    if projection.active_verification_lease_ids:
        _reject(
            "verification_leases_active",
            "verification mission cannot close while any lease remains active",
        )
    candidate_ids = {
        thaw_json(event.payload)["candidate"]["object_id"]
        for event in projection.candidate_events
    }
    partition = (
        projection.receipt_covered_candidate_ids
        | projection.never_assigned_verification_candidate_ids
        | projection.latest_expired_verification_candidate_ids
        | projection.latest_cancelled_verification_candidate_ids
    )
    if partition != candidate_ids:
        _reject(
            "verification_coverage_incomplete_partition",
            "candidate recovery partition is not exhaustive",
        )
    if projection.receipt_covered_candidate_ids == candidate_ids:
        return "receipt_coverage_complete"
    return "receipt_coverage_incomplete"


def _existing_closure(
    *,
    projection: MissionProjection,
    decision_time: int,
) -> VerificationMissionClosure | None:
    event = projection.terminal_event
    if event is None or event.kind != "mission_closed":
        return None
    status = thaw_json(event.payload)["status"]
    legacy_zero_candidate_completion = (
        status == "completed"
        and not projection.candidate_events
        and not projection.verification_lease_events
        and not projection.verification_lease_expiry_events
        and not projection.verification_lease_cancellation_events
        and not projection.verification_lease_reassignment_events
        and not projection.verification_artifact_resolution_events
        and not projection.verification_receipt_admission_events
    )
    if status not in {
        "receipt_coverage_complete",
        "receipt_coverage_incomplete",
    } and not legacy_zero_candidate_completion:
        _reject(
            "verification_closure_conflict",
            "retained closure is not a verification-coverage closure",
        )
    if event.decision_time != decision_time:
        _reject(
            "verification_closure_conflict",
            "mission already closed at a different decision time",
        )
    return VerificationMissionClosure(
        projection=projection,
        event=event,
        status=status,
        replayed=True,
    )


def close_modeled_fixture_verification_mission(
    *,
    event_store: SQLiteEventStore,
    mission_id: str,
    expected_head: str,
    decision_time: int,
) -> VerificationMissionClosure:
    """Close verification intent with exact complete or incomplete receipt coverage."""

    event_store = _require_store(event_store)
    mission_id = _require_digest("mission_id", mission_id)
    expected_head = _require_digest("expected_head", expected_head)
    decision_time = _require_time(decision_time)
    retained, projection = _load(event_store, mission_id)
    _authority_evidence(projection)
    existing = _existing_closure(
        projection=projection,
        decision_time=decision_time,
    )
    if existing is not None:
        return existing
    if projection.is_terminal:
        _reject(
            "mission_terminal",
            "verification closure cannot replace another terminal outcome",
        )
    if projection.phase not in {
        ProjectionPhase.SCAN_COMPLETED,
        ProjectionPhase.AWAITING_VERIFICATION,
    }:
        _reject(
            "scan_not_completed",
            "verification closure requires a completed fixture scan",
        )
    actual_head = retained[-1].event_digest
    if actual_head != expected_head:
        raise StaleHeadError(
            f"stale mission head: expected {expected_head}, retained {actual_head}"
        )
    if decision_time < retained[-1].decision_time:
        _reject(
            "decision_time_regressed",
            "closure decision time precedes the retained mission head",
        )
    status = _verification_closure_status(projection)
    if projection.scan_summary is None:
        _reject(
            "scan_summary_missing",
            "verification closure requires a retained scan summary",
        )
    event = EventV1.create(
        mission_id=projection.mission_id,
        seq=len(retained),
        kind="mission_closed",
        unit="ETZIO",
        authority_id=projection.authority_id,
        target_id=projection.target_id,
        decision_time=decision_time,
        payload={
            "candidate_count": len(projection.candidate_events),
            "parse_failure_count": len(projection.parse_failures),
            "status": status,
        },
        prev_digest=actual_head,
    )
    reduce_events((*retained, event))
    try:
        event_store.append(event, expected_head=expected_head)
    except StaleHeadError:
        raced = reduce_events(event_store.load(mission_id))
        match = _existing_closure(
            projection=raced,
            decision_time=decision_time,
        )
        if match is not None:
            return match
        raise
    committed = reduce_events(event_store.load(mission_id))
    retained_event = committed.terminal_event
    if (
        retained_event is None
        or retained_event.event_digest != event.event_digest
    ):
        _reject(
            "committed_event_missing",
            "appended verification closure is absent from replay",
        )
    return VerificationMissionClosure(
        projection=committed,
        event=retained_event,
        status=status,
        replayed=False,
    )
