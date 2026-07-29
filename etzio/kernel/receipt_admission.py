"""Atomic admission of one authenticated modeled-fixture verifier receipt.

The single retained event is both the receipt-admission decision and the durable
single-use consumption marker for its verification lease.  This command does not execute
verification work, mint a finding, close the mission, or authorize an external effect.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import NoReturn, Protocol

from ..authority import AuthorityGrantV1
from ..evidence import (
    VERIFICATION_OUTPUT_ARTIFACT_TYPE_BY_ROLE_V1,
    EvidenceError,
    FileEvidenceStore,
    TargetSnapshotV1,
)
from ..mission_v1 import StaticCandidateV1
from ..protocol import EnvelopeV1, ProtocolError, canonical_dumps, thaw_json
from ..verification import (
    MAX_EPOCH_SECOND,
    MAX_TYPED_VERIFICATION_OUTPUT_BYTES_V1,
    AuthenticatedVerifierReceiptV1,
    SignedVerifierReceiptV1,
    VerificationError,
    VerificationLeaseV1,
    VerificationOutputArtifactsV1,
    VerifierReceiptV1,
    VerifierTrustStore,
    authenticate_verifier_receipt,
    revalidate_verifier_receipt_artifacts,
)
from ..verification_artifacts import (
    VerificationArtifactBindingV1,
    VerificationArtifactError,
    VerificationArtifactResolutionV1,
)
from .events_v1 import RECEIPT_ADMISSION_PROFILE_V1, EventV1
from .evidence_vault import (
    VERIFICATION_EFFECT_OUTPUT_ROLE_V1,
    VERIFICATION_EXECUTION_OUTPUT_ROLE_V1,
    VERIFICATION_MEASURED_ENVIRONMENT_OUTPUT_ROLE_V1,
    VERIFICATION_TERMINATION_OUTPUT_ROLE_V1,
    VaultArtifactResolutionRequestV1,
)
from .integrity_transition import (
    FinalizedIntegrityTransitionV1,
    ModeledIntegrityFinalizingEventStoreV1,
)
from .reducer import MissionProjection, ProjectionPhase, reduce_events
from .store import (
    EventStoreCorruptionError,
    EventStoreError,
    EvidenceVaultRequestError,
    SQLiteEventStore,
    StaleHeadError,
    StoreBusyError,
    StoreCapacityError,
    StoreOperationalError,
)

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)


class _EventStorePort(Protocol):
    def load(self, mission_id: str) -> tuple[EventV1, ...]: ...

    def resolve_evidence_artifacts(
        self,
        requests: tuple[VaultArtifactResolutionRequestV1, ...],
        evidence_store: FileEvidenceStore,
        *,
        maximum_total: int,
    ) -> tuple[bytes, ...]: ...

    def append_receipt_admission(
        self,
        event: EventV1,
        *,
        expected_head: str,
        evidence_store: FileEvidenceStore,
    ) -> EventV1: ...


class VerificationReceiptAdmissionError(ProtocolError):
    """A verifier receipt cannot enter canonical mission history."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class VerificationReceiptAdmission:
    """The canonical admission event and its reconstructed decision values."""

    projection: MissionProjection
    event: EventV1
    authenticated_receipt: AuthenticatedVerifierReceiptV1
    output_artifacts: VerificationOutputArtifactsV1
    replayed: bool


@dataclass(frozen=True, slots=True)
class IntegrityFinalizedVerificationReceiptAdmission:
    """One admitted receipt paired with its exact current-head finalization."""

    admission: VerificationReceiptAdmission
    finalization: FinalizedIntegrityTransitionV1


def _reject(reason_code: str, message: str) -> NoReturn:
    raise VerificationReceiptAdmissionError(reason_code, message)


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
    signed_receipt: object,
    decision_trust_store: object,
    decision_time: object,
) -> tuple[
    _EventStorePort,
    FileEvidenceStore,
    str,
    str,
    str,
    object,
    VerifierTrustStore,
    int,
]:
    if (
        not callable(getattr(event_store, "load", None))
        or not callable(
            getattr(event_store, "append_receipt_admission", None)
        )
        or not callable(
            getattr(event_store, "resolve_evidence_artifacts", None)
        )
    ):
        _reject(
            "invalid_event_store",
            "event_store must provide load, vault resolution, and receipt append operations",
        )
    if type(evidence_store) is not FileEvidenceStore:
        _reject(
            "invalid_evidence_store",
            "evidence_store must be an exact FileEvidenceStore",
        )
    mission = _require_digest("mission_id", mission_id)
    head = _require_digest("expected_head", expected_head)
    lease_id = _require_digest("verification_lease_id", verification_lease_id)
    if not isinstance(decision_trust_store, VerifierTrustStore):
        _reject(
            "invalid_decision_trust_store",
            "decision_trust_store must be a VerifierTrustStore",
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
    return (
        event_store,
        evidence_store,
        mission,
        head,
        lease_id,
        signed_receipt,
        decision_trust_store,
        decision_time,
    )


def _nested_envelope(event: EventV1, field: str) -> EnvelopeV1:
    return EnvelopeV1.from_bytes(canonical_dumps(thaw_json(event.payload)[field]))


def _grant(projection: MissionProjection) -> AuthorityGrantV1:
    first = projection.events[0]
    if first.kind != "authority_admitted":
        _reject(
            "mission_not_admitted",
            "receipt admission requires retained authority admission",
        )
    return AuthorityGrantV1.from_envelope(_nested_envelope(first, "grant"))


def _target_snapshot(projection: MissionProjection) -> TargetSnapshotV1:
    for event in projection.events:
        if event.kind == "mission_opened":
            return TargetSnapshotV1.from_envelope(
                _nested_envelope(event, "target_snapshot")
            )
    _reject(
        "target_not_retained",
        "receipt admission requires a retained target snapshot",
    )


def _verification_lease(
    projection: MissionProjection,
    verification_lease_id: str,
) -> VerificationLeaseV1:
    for event in projection.verification_lease_events:
        lease = VerificationLeaseV1.from_envelope(
            _nested_envelope(event, "lease")
        )
        if lease.lease_id == verification_lease_id:
            return lease
    _reject(
        "verification_lease_not_retained",
        "verification_lease_id is absent from canonical mission history",
    )


def _artifact_resolution(
    projection: MissionProjection,
    verification_lease_id: str,
) -> VerificationArtifactResolutionV1:
    found: VerificationArtifactResolutionV1 | None = None
    for event in projection.verification_artifact_resolution_events:
        resolution = VerificationArtifactResolutionV1.from_envelope(
            _nested_envelope(event, "resolution")
        )
        if resolution.verification_lease_id != verification_lease_id:
            continue
        if found is not None:
            _reject(
                "duplicate_retained_resolution",
                "verification lease has multiple retained artifact resolutions",
            )
        found = resolution
    if found is None:
        _reject(
            "verification_artifacts_not_resolved",
            "receipt admission requires a retained artifact resolution",
        )
    return found


def _assert_candidate_retained(
    projection: MissionProjection,
    candidate_id: str,
) -> None:
    for event in projection.candidate_events:
        candidate = StaticCandidateV1.from_envelope(
            _nested_envelope(event, "candidate")
        )
        if candidate.candidate_id == candidate_id:
            return
    _reject(
        "candidate_not_retained",
        "verification lease candidate is absent from canonical mission history",
    )


def _signed_receipt_from_event(event: EventV1) -> SignedVerifierReceiptV1:
    try:
        return SignedVerifierReceiptV1.from_bytes(
            canonical_dumps(thaw_json(event.payload)["receipt"])
        )
    except (VerificationError, ProtocolError) as exc:
        _reject(
            "retained_receipt_invalid",
            f"retained receipt admission contains invalid signed bytes: {exc}",
        )


def _outputs_from_event(event: EventV1) -> VerificationOutputArtifactsV1:
    payload = thaw_json(event.payload)
    try:
        return VerificationOutputArtifactsV1(
            execution_output_artifact=VerificationArtifactBindingV1.from_dict(
                payload["execution_output_artifact"]
            ),
            effect_output_artifact=VerificationArtifactBindingV1.from_dict(
                payload["effect_output_artifact"]
            ),
            measured_environment_output_artifact=(
                VerificationArtifactBindingV1.from_dict(
                    payload["measured_environment_output_artifact"]
                )
            ),
            termination_output_artifact=VerificationArtifactBindingV1.from_dict(
                payload["termination_output_artifact"]
            ),
        )
    except (VerificationError, VerificationArtifactError) as exc:
        _reject(
            "retained_output_bindings_invalid",
            f"retained output bindings are invalid: {exc}",
        )


def _resolve_new_output_artifacts(
    authenticated_receipt: AuthenticatedVerifierReceiptV1,
    *,
    event_store: _EventStorePort,
    evidence_store: FileEvidenceStore,
    maximum_output_bytes: int,
) -> VerificationOutputArtifactsV1:
    """Resolve only the four outputs first introduced by this admission."""

    receipt = authenticated_receipt.receipt
    output_specs = (
        (
            "execution_output",
            VERIFICATION_EXECUTION_OUTPUT_ROLE_V1,
            receipt.execution_output_digest,
            receipt.execution_output_size,
        ),
        (
            "effect_output",
            VERIFICATION_EFFECT_OUTPUT_ROLE_V1,
            receipt.effect_output_digest,
            receipt.effect_output_size,
        ),
        (
            "measured_environment_output",
            VERIFICATION_MEASURED_ENVIRONMENT_OUTPUT_ROLE_V1,
            receipt.measured_environment_output_digest,
            receipt.measured_environment_output_size,
        ),
        (
            "termination_output",
            VERIFICATION_TERMINATION_OUTPUT_ROLE_V1,
            receipt.termination_output_digest,
            receipt.termination_output_size,
        ),
    )
    signed_output_bytes = sum(size for _, _, _, size in output_specs)
    if signed_output_bytes > min(
        maximum_output_bytes,
        MAX_TYPED_VERIFICATION_OUTPUT_BYTES_V1,
    ):
        _reject(
            "verification_output_byte_ceiling_exceeded",
            "signed verification outputs exceed the available byte allowance",
        )

    try:
        resolved_bytes = event_store.resolve_evidence_artifacts(
            tuple(
                VaultArtifactResolutionRequestV1(
                    role=vault_role,
                    digest=digest,
                    maximum=signed_size,
                )
                for _, vault_role, digest, signed_size in output_specs
            ),
            evidence_store,
            maximum_total=signed_output_bytes,
        )
    except (
        EventStoreCorruptionError,
        StoreBusyError,
        StoreCapacityError,
        StoreOperationalError,
    ):
        raise
    except EvidenceVaultRequestError as exc:
        role = output_specs[exc.request_index][0]
        if exc.reason_code in {"artifact_limit", "batch_limit"}:
            _reject(
                f"resolved_{role}_artifact_size_mismatch",
                f"{role} bytes differ from the signed size",
            )
        _reject(
            f"resolved_{role}_artifact_unavailable",
            f"{role} cannot be resolved under its code-owned type",
        )
    except (EvidenceError, EventStoreError) as exc:
        _reject(
            "resolved_output_artifact_unavailable",
            f"verification outputs cannot be resolved: {exc}",
        )

    resolved: dict[str, VerificationArtifactBindingV1] = {}
    for (role, _, digest, signed_size), data in zip(
        output_specs,
        resolved_bytes,
        strict=True,
    ):
        artifact_type = VERIFICATION_OUTPUT_ARTIFACT_TYPE_BY_ROLE_V1[role]
        if len(data) != signed_size:
            _reject(
                f"resolved_{role}_artifact_size_mismatch",
                f"{role} bytes differ from the signed size",
            )
        try:
            resolved[role] = VerificationArtifactBindingV1(
                artifact_digest=digest,
                artifact_type=artifact_type,
                size=signed_size,
            )
        except VerificationArtifactError as exc:
            _reject(exc.reason_code, str(exc))

    try:
        return VerificationOutputArtifactsV1(
            execution_output_artifact=resolved["execution_output"],
            effect_output_artifact=resolved["effect_output"],
            measured_environment_output_artifact=resolved[
                "measured_environment_output"
            ],
            termination_output_artifact=resolved["termination_output"],
        )
    except VerificationError as exc:
        _reject(exc.reason_code, str(exc))


def _existing_admission(
    *,
    projection: MissionProjection,
    authenticated_receipt: AuthenticatedVerifierReceiptV1,
    decision_trust_store: VerifierTrustStore,
    decision_time: int,
) -> VerificationReceiptAdmission | None:
    requested_signed_wire = authenticated_receipt.signed_receipt.to_bytes()
    requested_snapshot = decision_trust_store.to_snapshot_body()
    requested_snapshot_id = decision_trust_store.snapshot_id
    requested_lease_id = authenticated_receipt.lease.lease_id
    requested_receipt_id = authenticated_receipt.receipt.receipt_id

    for event in projection.verification_receipt_admission_events:
        payload = thaw_json(event.payload)
        retained_signed = _signed_receipt_from_event(event)
        try:
            retained_receipt = retained_signed.to_envelope()
        except VerificationError as exc:
            _reject(
                "retained_receipt_invalid",
                f"retained signed receipt cannot be reconstructed: {exc}",
            )
        retained_receipt_id = retained_receipt.object_id
        retained_body = EnvelopeV1.from_bytes(
            retained_signed.envelope_bytes
        ).body
        retained_lease_field = thaw_json(retained_body)["lease_id"]

        if retained_lease_field == requested_lease_id:
            exact = (
                event.decision_time == decision_time
                and payload["adjudication_profile"]
                == RECEIPT_ADMISSION_PROFILE_V1
                and payload["decision_trust_snapshot_id"]
                == requested_snapshot_id
                and payload["decision_trust_snapshot"] == requested_snapshot
                and retained_signed.to_bytes() == requested_signed_wire
                and retained_receipt_id == requested_receipt_id
            )
            if not exact:
                _reject(
                    "verification_lease_consumed_conflict",
                    "verification lease is already consumed by a different admission",
                )
            return VerificationReceiptAdmission(
                projection=projection,
                event=event,
                authenticated_receipt=authenticated_receipt,
                output_artifacts=_outputs_from_event(event),
                replayed=True,
            )
        if retained_receipt_id == requested_receipt_id:
            _reject(
                "verifier_receipt_admission_conflict",
                "verifier receipt is already retained for another lease",
            )
    return None


def _event_payload(
    *,
    authenticated_receipt: AuthenticatedVerifierReceiptV1,
    output_artifacts: VerificationOutputArtifactsV1,
    decision_trust_store: VerifierTrustStore,
) -> dict[str, object]:
    return {
        "adjudication_profile": RECEIPT_ADMISSION_PROFILE_V1,
        "decision_trust_snapshot": decision_trust_store.to_snapshot_body(),
        "decision_trust_snapshot_id": decision_trust_store.snapshot_id,
        "effect_output_artifact": (
            output_artifacts.effect_output_artifact.to_dict()
        ),
        "execution_output_artifact": (
            output_artifacts.execution_output_artifact.to_dict()
        ),
        "measured_environment_output_artifact": (
            output_artifacts.measured_environment_output_artifact.to_dict()
        ),
        "receipt": authenticated_receipt.signed_receipt.to_envelope().to_dict(),
        "termination_output_artifact": (
            output_artifacts.termination_output_artifact.to_dict()
        ),
    }


def validate_retained_receipt_admission_event(
    *,
    retained: tuple[EventV1, ...],
    event: EventV1,
    evidence_store: FileEvidenceStore,
) -> tuple[AuthenticatedVerifierReceiptV1, VerificationOutputArtifactsV1]:
    """Revalidate one exact proposal against history and its supplied evidence view.

    This helper changes no state. The canonical store invokes it under ``BEGIN IMMEDIATE``
    with a vault-first overlay that consults staging only when an identity is genuinely
    absent, after validating lifecycle, compare-and-append head, and proposed transition.
    A standalone caller supplies only a non-authoritative filesystem evidence view.
    """

    if (
        type(retained) is not tuple
        or not retained
        or any(not isinstance(value, EventV1) for value in retained)
    ):
        _reject(
            "invalid_retained_history",
            "receipt admission requires a nonempty tuple of retained events",
        )
    if not isinstance(event, EventV1) or event.kind != "verifier_receipt_admitted":
        _reject(
            "invalid_receipt_admission_event",
            "current evidence validation requires verifier_receipt_admitted",
        )
    if not isinstance(evidence_store, FileEvidenceStore):
        _reject(
            "invalid_evidence_store",
            "evidence_store must be a FileEvidenceStore",
        )

    projection = reduce_events(retained)
    payload = thaw_json(event.payload)
    if payload["adjudication_profile"] != RECEIPT_ADMISSION_PROFILE_V1:
        _reject(
            "unsupported_adjudication_profile",
            "receipt admission uses an unsupported adjudication profile",
        )
    try:
        decision_trust = VerifierTrustStore.from_snapshot_body(
            payload["decision_trust_snapshot"],
            expected_snapshot_id=payload["decision_trust_snapshot_id"],
        )
        signed_receipt = _signed_receipt_from_event(event)
        receipt = VerifierReceiptV1.from_envelope(
            EnvelopeV1.from_bytes(signed_receipt.envelope_bytes)
        )
    except (VerificationError, ProtocolError) as exc:
        _reject(
            "retained_receipt_invalid",
            f"receipt admission decision evidence is invalid: {exc}",
        )

    lease = _verification_lease(projection, receipt.lease_id)
    _assert_candidate_retained(projection, lease.candidate_id)
    if receipt.lease_id not in projection.active_verification_lease_ids:
        _reject(
            "verification_lease_inactive",
            "receipt admission requires the active candidate-lineage lease",
        )
    resolution = _artifact_resolution(projection, receipt.lease_id)
    try:
        authenticated = authenticate_verifier_receipt(
            signed_receipt,
            decision_trust,
            lease=lease,
            artifact_resolution=resolution,
            decision_time=event.decision_time,
        )
    except VerificationError as exc:
        _reject(exc.reason_code, str(exc))
    if (
        authenticated.decision_trust_snapshot_id
        != payload["decision_trust_snapshot_id"]
    ):
        _reject(
            "decision_trust_snapshot_mismatch",
            "receipt authentication used a different decision trust snapshot",
        )

    grant = _grant(projection)
    target_snapshot = _target_snapshot(projection)
    remaining = grant.max_bytes - resolution.total_bytes
    if remaining <= 0:
        _reject(
            "verification_output_byte_ceiling_exceeded",
            "the signed byte ceiling leaves no allowance for verifier outputs",
        )
    try:
        output_artifacts = revalidate_verifier_receipt_artifacts(
            authenticated,
            target_snapshot=target_snapshot,
            evidence_store=evidence_store,
            maximum_output_bytes=remaining,
        )
    except VerificationError as exc:
        _reject(exc.reason_code, str(exc))
    if output_artifacts != _outputs_from_event(event):
        _reject(
            "retained_output_bindings_mismatch",
            "current evidence-derived output bindings differ from the proposed event",
        )
    if resolution.total_bytes + output_artifacts.total_bytes > grant.max_bytes:
        _reject(
            "verification_output_byte_ceiling_exceeded",
            "resolved inputs and verifier outputs exceed the signed byte ceiling",
        )
    return authenticated, output_artifacts


def admit_modeled_fixture_verifier_receipt(
    *,
    event_store: SQLiteEventStore,
    evidence_store: FileEvidenceStore,
    mission_id: str,
    expected_head: str,
    verification_lease_id: str,
    signed_receipt: object,
    decision_trust_store: VerifierTrustStore,
    decision_time: int,
) -> VerificationReceiptAdmission:
    """Authenticate, vault-check, and atomically admit one single-use receipt."""

    (
        event_store,
        evidence_store,
        mission_id,
        expected_head,
        verification_lease_id,
        signed_receipt,
        decision_trust_store,
        decision_time,
    ) = _validate_request(
        event_store=event_store,
        evidence_store=evidence_store,
        mission_id=mission_id,
        expected_head=expected_head,
        verification_lease_id=verification_lease_id,
        signed_receipt=signed_receipt,
        decision_trust_store=decision_trust_store,
        decision_time=decision_time,
    )
    retained = event_store.load(mission_id)
    if not retained:
        _reject(
            "mission_not_found",
            "receipt admission requires a retained mission stream",
        )
    projection = reduce_events(retained)
    lease = _verification_lease(projection, verification_lease_id)
    _assert_candidate_retained(projection, lease.candidate_id)
    if (
        verification_lease_id
        not in projection.active_verification_lease_ids
        and verification_lease_id
        not in projection.consumed_verification_lease_ids
    ):
        _reject(
            "verification_lease_inactive",
            "receipt admission requires the active candidate-lineage lease",
        )
    resolution = _artifact_resolution(projection, verification_lease_id)
    try:
        authenticated = authenticate_verifier_receipt(
            signed_receipt,
            decision_trust_store,
            lease=lease,
            artifact_resolution=resolution,
            decision_time=decision_time,
        )
    except VerificationError as exc:
        _reject(exc.reason_code, str(exc))

    existing = _existing_admission(
        projection=projection,
        authenticated_receipt=authenticated,
        decision_trust_store=decision_trust_store,
        decision_time=decision_time,
    )
    if existing is not None:
        return existing
    if projection.is_terminal:
        _reject(
            "mission_terminal",
            "receipt cannot be admitted after mission termination",
        )
    if projection.phase is not ProjectionPhase.AWAITING_VERIFICATION:
        _reject(
            "verification_not_awaiting_receipt",
            "receipt admission requires awaiting_verification state",
        )
    actual_head = retained[-1].event_digest
    if actual_head != expected_head:
        raise StaleHeadError(
            f"stale mission head: expected {expected_head}, retained {actual_head}"
        )
    if decision_time < retained[-1].decision_time:
        _reject(
            "decision_time_regressed",
            "receipt admission time precedes the retained mission head",
        )

    grant = _grant(projection)
    remaining = grant.max_bytes - resolution.total_bytes
    if remaining <= 0:
        _reject(
            "verification_output_byte_ceiling_exceeded",
            "the signed byte ceiling leaves no allowance for verifier outputs",
        )
    output_artifacts = _resolve_new_output_artifacts(
        authenticated,
        event_store=event_store,
        evidence_store=evidence_store,
        maximum_output_bytes=remaining,
    )
    if resolution.total_bytes + output_artifacts.total_bytes > grant.max_bytes:
        _reject(
            "verification_output_byte_ceiling_exceeded",
            "resolved inputs and verifier outputs exceed the signed byte ceiling",
        )

    event = EventV1.create(
        mission_id=projection.mission_id,
        seq=len(retained),
        kind="verifier_receipt_admitted",
        unit="ETZIO",
        authority_id=projection.authority_id,
        target_id=projection.target_id,
        decision_time=decision_time,
        payload=_event_payload(
            authenticated_receipt=authenticated,
            output_artifacts=output_artifacts,
            decision_trust_store=decision_trust_store,
        ),
        prev_digest=actual_head,
    )
    reduce_events((*retained, event))
    try:
        try:
            event_store.append_receipt_admission(
                event,
                expected_head=expected_head,
                evidence_store=evidence_store,
            )
        except StoreBusyError:
            # One bounded lock-contention retry lets an in-flight identical append
            # become a stale-head reconciliation without an unbounded retry loop.
            event_store.append_receipt_admission(
                event,
                expected_head=expected_head,
                evidence_store=evidence_store,
            )
    except (StaleHeadError, StoreBusyError) as append_error:
        raced_projection = reduce_events(event_store.load(mission_id))
        raced_existing = _existing_admission(
            projection=raced_projection,
            authenticated_receipt=authenticated,
            decision_trust_store=decision_trust_store,
            decision_time=decision_time,
        )
        if raced_existing is not None:
            return raced_existing
        if (
            isinstance(append_error, StoreBusyError)
            and raced_projection.events[-1].event_digest != expected_head
        ):
            raise StaleHeadError(
                "mission head advanced while receipt admission waited for "
                "the SQLite writer lock"
            ) from append_error
        raise

    committed_projection = reduce_events(event_store.load(mission_id))
    committed_event = next(
        (
            retained_event
            for retained_event in committed_projection.verification_receipt_admission_events
            if retained_event.event_digest == event.event_digest
        ),
        None,
    )
    if committed_event is None:
        _reject(
            "committed_event_missing",
            "appended receipt admission event is absent from replay",
        )
    return VerificationReceiptAdmission(
        projection=committed_projection,
        event=committed_event,
        authenticated_receipt=authenticated,
        output_artifacts=_outputs_from_event(committed_event),
        replayed=False,
    )


def admit_modeled_fixture_verifier_receipt_with_integrity(
    *,
    event_store: ModeledIntegrityFinalizingEventStoreV1,
    evidence_store: FileEvidenceStore,
    mission_id: str,
    expected_head: str,
    verification_lease_id: str,
    signed_receipt: object,
    decision_trust_store: VerifierTrustStore,
    decision_time: int,
) -> IntegrityFinalizedVerificationReceiptAdmission:
    """Admit one receipt only after its modeled checkpoint is exactly current.

    Recovery deliberately precedes the underlying command.  That ordering closes the
    replay path where the receipt event was committed and externally published before
    local finalization, but a retry would otherwise return the existing admission
    without finishing its integrity lineage.
    """

    if type(event_store) is not ModeledIntegrityFinalizingEventStoreV1:
        _reject(
            "invalid_integrity_event_store",
            "integrity receipt admission requires an exact ModeledIntegrityFinalizingEventStoreV1",
        )
    event_store.recover()
    admission = admit_modeled_fixture_verifier_receipt(
        event_store=event_store,
        evidence_store=evidence_store,
        mission_id=mission_id,
        expected_head=expected_head,
        verification_lease_id=verification_lease_id,
        signed_receipt=signed_receipt,
        decision_trust_store=decision_trust_store,
        decision_time=decision_time,
    )
    finalization = event_store.require_finalized(admission.event.event_digest)
    return IntegrityFinalizedVerificationReceiptAdmission(
        admission=admission,
        finalization=finalization,
    )
