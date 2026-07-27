"""Kernel issuance of authority-bound modeled-fixture verification leases.

This command commits one nondispatchable lease assignment to canonical mission history.
It does not resolve artifact bytes, execute a proof, accept or consume a receipt, or mint
a finding. Those remain separate fail-closed gates.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import NoReturn

from ..authority import AuthorityAdmissionV1, AuthorityGrantV1
from ..mission_v1 import StaticCandidateV1
from ..protocol import (
    EnvelopeV1,
    ProtocolError,
    canonical_dumps,
    thaw_json,
)
from ..verification import (
    MAX_EPOCH_SECOND,
    MAX_EVIDENCE_ARTIFACTS,
    VERIFIER_ROLE,
    VerificationError,
    VerificationLeaseV1,
    VerifierTrustStore,
    derive_verification_lease_nonce,
)
from .events_v1 import EventV1
from .reducer import MissionProjection, ProjectionPhase, reduce_events
from .store import SQLiteEventStore, StaleHeadError

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
_KEY_ID = re.compile(r"^ed25519:sha256:[0-9a-f]{64}$", re.ASCII)


class VerificationLeaseIssuanceError(ProtocolError):
    """A verification-lease proposal cannot enter canonical mission history."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class VerificationLeaseIssuance:
    """The single retained event and lease reconstructed after issuance."""

    projection: MissionProjection
    event: EventV1
    lease: VerificationLeaseV1
    replayed: bool


def _reject(reason_code: str, message: str) -> NoReturn:
    raise VerificationLeaseIssuanceError(reason_code, message)


def _require_digest(name: str, value: object) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        _reject(f"invalid_{name}", f"{name} must be a full sha256 content ID")
    return value


def _validate_request(
    *,
    mission_id: object,
    expected_head: object,
    candidate_id: object,
    poc_artifact_digest: object,
    evidence_artifact_digests: object,
    environment_digest: object,
    effect_oracle_id: object,
    verifier_key_id: object,
    verifier_trust_store: object,
    decision_time: object,
    requested_wallclock_seconds: object,
) -> tuple[str, str, str, str, tuple[str, ...], str, str, str, int, int]:
    mission = _require_digest("mission_id", mission_id)
    head = _require_digest("expected_head", expected_head)
    candidate = _require_digest("candidate_id", candidate_id)
    poc = _require_digest("poc_artifact_digest", poc_artifact_digest)
    environment = _require_digest("environment_digest", environment_digest)
    oracle = _require_digest("effect_oracle_id", effect_oracle_id)
    if (
        type(verifier_key_id) is not str
        or _KEY_ID.fullmatch(verifier_key_id) is None
    ):
        _reject(
            "invalid_verifier_key_id",
            "verifier_key_id must identify an Ed25519 public key",
        )
    if not isinstance(verifier_trust_store, VerifierTrustStore):
        _reject(
            "invalid_verifier_trust_store",
            "verifier_trust_store must be a VerifierTrustStore",
        )
    if (
        type(evidence_artifact_digests) is not tuple
        or not evidence_artifact_digests
        or len(evidence_artifact_digests) > MAX_EVIDENCE_ARTIFACTS
        or any(
            type(digest) is not str or _DIGEST.fullmatch(digest) is None
            for digest in evidence_artifact_digests
        )
        or evidence_artifact_digests
        != tuple(sorted(evidence_artifact_digests))
        or len(set(evidence_artifact_digests))
        != len(evidence_artifact_digests)
    ):
        _reject(
            "invalid_evidence_artifact_digests",
            "evidence digests must be a nonempty, unique, sorted tuple of sha256 IDs",
        )
    artifact_roles = (
        poc,
        *evidence_artifact_digests,
        environment,
        oracle,
    )
    if len(set(artifact_roles)) != len(artifact_roles):
        _reject(
            "artifact_role_collision",
            "verification artifact roles must use distinct content identities",
        )
    if (
        type(decision_time) is not int
        or decision_time < 0
        or decision_time > MAX_EPOCH_SECOND
    ):
        _reject(
            "invalid_decision_time",
            "decision_time must be a nonnegative int64 epoch second",
        )
    if (
        type(requested_wallclock_seconds) is not int
        or requested_wallclock_seconds <= 0
        or requested_wallclock_seconds > MAX_EPOCH_SECOND
    ):
        _reject(
            "invalid_requested_wallclock",
            "requested_wallclock_seconds must be a positive int64",
        )
    return (
        mission,
        head,
        candidate,
        poc,
        evidence_artifact_digests,
        environment,
        oracle,
        verifier_key_id,
        decision_time,
        requested_wallclock_seconds,
    )


def _nested_envelope(event: EventV1, field: str) -> EnvelopeV1:
    return EnvelopeV1.from_bytes(
        canonical_dumps(thaw_json(event.payload)[field])
    )


def _authority_evidence(
    projection: MissionProjection,
) -> tuple[AuthorityGrantV1, AuthorityAdmissionV1]:
    first = projection.events[0]
    if first.kind != "authority_admitted":
        _reject(
            "mission_not_admitted",
            "verification leases require retained authority admission",
        )
    grant = AuthorityGrantV1.from_envelope(_nested_envelope(first, "grant"))
    admission = AuthorityAdmissionV1.from_envelope(
        _nested_envelope(first, "admission")
    )
    return grant, admission


def _candidate_event(
    projection: MissionProjection,
    candidate_id: str,
) -> EventV1:
    for event in projection.candidate_events:
        candidate = StaticCandidateV1.from_envelope(
            _nested_envelope(event, "candidate")
        )
        if candidate.candidate_id == candidate_id:
            return event
    _reject(
        "candidate_not_retained",
        "candidate_id is absent from canonical mission history",
    )


def _lease_from_event(event: EventV1) -> VerificationLeaseV1:
    return VerificationLeaseV1.from_envelope(
        _nested_envelope(event, "lease")
    )


def _matching_existing(
    *,
    projection: MissionProjection,
    candidate_id: str,
    poc_artifact_digest: str,
    evidence_artifact_digests: tuple[str, ...],
    environment_digest: str,
    effect_oracle_id: str,
    verifier_id: str,
    verifier_key_id: str,
    verifier_trust_store: VerifierTrustStore,
    decision_time: int,
    expires_at: int,
) -> VerificationLeaseIssuance | None:
    for event in projection.verification_lease_events:
        lease = _lease_from_event(event)
        if lease.candidate_id != candidate_id:
            continue
        payload = thaw_json(event.payload)
        exact = (
            lease.poc_artifact_digest == poc_artifact_digest
            and lease.evidence_artifact_digests
            == evidence_artifact_digests
            and lease.environment_digest == environment_digest
            and lease.effect_oracle_id == effect_oracle_id
            and lease.verifier_id == verifier_id
            and lease.verifier_key_id == verifier_key_id
            and lease.issuance_trust_snapshot_id
            == verifier_trust_store.snapshot_id
            and lease.issued_at == decision_time
            and lease.expires_at == expires_at
            and payload["verifier_trust_snapshot_id"]
            == verifier_trust_store.snapshot_id
            and payload["verifier_trust_snapshot"]
            == verifier_trust_store.to_snapshot_body()
        )
        if not exact:
            _reject(
                "candidate_lease_conflict",
                "candidate already has a different verification lease",
            )
        return VerificationLeaseIssuance(
            projection=projection,
            event=event,
            lease=lease,
            replayed=True,
        )
    return None


def issue_modeled_fixture_verification_lease(
    *,
    event_store: SQLiteEventStore,
    mission_id: str,
    expected_head: str,
    candidate_id: str,
    poc_artifact_digest: str,
    evidence_artifact_digests: tuple[str, ...],
    environment_digest: str,
    effect_oracle_id: str,
    verifier_key_id: str,
    verifier_trust_store: VerifierTrustStore,
    decision_time: int,
    requested_wallclock_seconds: int,
) -> VerificationLeaseIssuance:
    """Compare-and-append one authority-bound, nondispatchable verification lease."""

    (
        mission_id,
        expected_head,
        candidate_id,
        poc_artifact_digest,
        evidence_artifact_digests,
        environment_digest,
        effect_oracle_id,
        verifier_key_id,
        decision_time,
        requested_wallclock_seconds,
    ) = _validate_request(
        mission_id=mission_id,
        expected_head=expected_head,
        candidate_id=candidate_id,
        poc_artifact_digest=poc_artifact_digest,
        evidence_artifact_digests=evidence_artifact_digests,
        environment_digest=environment_digest,
        effect_oracle_id=effect_oracle_id,
        verifier_key_id=verifier_key_id,
        verifier_trust_store=verifier_trust_store,
        decision_time=decision_time,
        requested_wallclock_seconds=requested_wallclock_seconds,
    )
    retained = event_store.load(mission_id)
    if not retained:
        _reject(
            "mission_not_found",
            "verification lease requires a retained mission stream",
        )
    projection = reduce_events(retained)
    if projection.is_terminal:
        _reject(
            "mission_terminal",
            "verification lease cannot be issued after mission termination",
        )
    if projection.phase not in {
        ProjectionPhase.SCAN_COMPLETED,
        ProjectionPhase.AWAITING_VERIFICATION,
    }:
        _reject(
            "scan_not_completed",
            "verification lease requires a completed fixture scan",
        )
    grant, admission = _authority_evidence(projection)
    if (
        "modeled_fixture_verification" not in admission.required_actions
        or "modeled_fixture_verification" not in grant.permitted_actions
    ):
        _reject(
            "verification_not_authorized",
            "retained admission and grant must authorize modeled fixture verification",
        )
    if requested_wallclock_seconds > grant.max_wallclock_seconds:
        _reject(
            "requested_wallclock_exceeds_grant",
            "requested verification window exceeds the admitted ceiling",
        )
    candidate_event = _candidate_event(projection, candidate_id)
    if verifier_key_id in verifier_trust_store.revoked_key_ids:
        _reject(
            "verifier_key_revoked",
            "assigned verifier key is revoked in the retained snapshot",
        )
    trusted_key = verifier_trust_store.keys.get(verifier_key_id)
    if trusted_key is None:
        _reject(
            "unknown_verifier_key",
            "assigned verifier key is absent from the trust snapshot",
        )
    if VERIFIER_ROLE not in trusted_key.roles:
        _reject(
            "verifier_role_missing",
            "assigned verifier key lacks the modeled fixture verifier role",
        )
    if candidate_event.unit == trusted_key.verifier_id:
        _reject(
            "self_verification",
            "candidate producer cannot verify its own candidate",
        )
    grant_deadline = min(
        grant.expires_at,
        admission.decision_time + grant.max_wallclock_seconds,
    )
    expires_at = min(
        grant_deadline,
        decision_time + requested_wallclock_seconds,
    )
    if decision_time < admission.decision_time:
        _reject(
            "decision_before_admission",
            "verification issuance cannot precede authority admission",
        )
    if decision_time >= expires_at:
        _reject(
            "verification_window_exhausted",
            "no admitted verification time remains",
        )

    existing = _matching_existing(
        projection=projection,
        candidate_id=candidate_id,
        poc_artifact_digest=poc_artifact_digest,
        evidence_artifact_digests=evidence_artifact_digests,
        environment_digest=environment_digest,
        effect_oracle_id=effect_oracle_id,
        verifier_id=trusted_key.verifier_id,
        verifier_key_id=verifier_key_id,
        verifier_trust_store=verifier_trust_store,
        decision_time=decision_time,
        expires_at=expires_at,
    )
    if existing is not None:
        return existing

    actual_head = retained[-1].event_digest
    if actual_head != expected_head:
        raise StaleHeadError(
            f"stale mission head: expected {expected_head}, retained {actual_head}"
        )
    if decision_time < retained[-1].decision_time:
        _reject(
            "decision_time_regressed",
            "verification issuance time precedes the retained mission head",
        )
    if len(projection.verification_lease_events) >= grant.max_candidates:
        _reject(
            "verification_lease_budget_exhausted",
            "verification lease count reached the admitted candidate ceiling",
        )

    snapshot_id = verifier_trust_store.snapshot_id
    nonce = derive_verification_lease_nonce(
        prior_event_digest=actual_head,
        mission_id=projection.mission_id,
        authority_id=projection.authority_id,
        target_snapshot_id=projection.target_id,
        candidate_id=candidate_id,
        candidate_producer_id=candidate_event.unit,
        poc_artifact_digest=poc_artifact_digest,
        evidence_artifact_digests=evidence_artifact_digests,
        environment_digest=environment_digest,
        effect_oracle_id=effect_oracle_id,
        verifier_id=trusted_key.verifier_id,
        verifier_key_id=verifier_key_id,
        issued_at=decision_time,
        expires_at=expires_at,
        issuance_trust_snapshot_id=snapshot_id,
    )
    try:
        lease = VerificationLeaseV1.issue(
            lease_nonce=nonce,
            mission_id=projection.mission_id,
            authority_id=projection.authority_id,
            target_snapshot_id=projection.target_id,
            candidate_id=candidate_id,
            candidate_producer_id=candidate_event.unit,
            poc_artifact_digest=poc_artifact_digest,
            evidence_artifact_digests=evidence_artifact_digests,
            environment_digest=environment_digest,
            effect_oracle_id=effect_oracle_id,
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
        kind="verification_lease_issued",
        unit="AQUILA",
        authority_id=projection.authority_id,
        target_id=projection.target_id,
        decision_time=decision_time,
        payload={
            "lease": lease.to_envelope().to_dict(),
            "verifier_trust_snapshot": verifier_trust_store.to_snapshot_body(),
            "verifier_trust_snapshot_id": snapshot_id,
        },
        prev_digest=actual_head,
    )
    reduce_events((*retained, event))
    try:
        event_store.append(event, expected_head=expected_head)
    except StaleHeadError:
        raced_projection = reduce_events(event_store.load(mission_id))
        raced_existing = _matching_existing(
            projection=raced_projection,
            candidate_id=candidate_id,
            poc_artifact_digest=poc_artifact_digest,
            evidence_artifact_digests=evidence_artifact_digests,
            environment_digest=environment_digest,
            effect_oracle_id=effect_oracle_id,
            verifier_id=trusted_key.verifier_id,
            verifier_key_id=verifier_key_id,
            verifier_trust_store=verifier_trust_store,
            decision_time=decision_time,
            expires_at=expires_at,
        )
        if raced_existing is not None:
            return raced_existing
        raise

    committed_projection = reduce_events(event_store.load(mission_id))
    committed_event = next(
        (
            retained_event
            for retained_event in committed_projection.verification_lease_events
            if retained_event.event_digest == event.event_digest
        ),
        None,
    )
    if committed_event is None:
        _reject(
            "committed_event_missing",
            "appended verification lease event is absent from replay",
        )
    committed_lease = _lease_from_event(committed_event)
    return VerificationLeaseIssuance(
        projection=committed_projection,
        event=committed_event,
        lease=committed_lease,
        replayed=False,
    )
