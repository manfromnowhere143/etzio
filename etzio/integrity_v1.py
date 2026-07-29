"""Authenticated integrity-decision and head-checkpoint contracts for Etzio.

This module defines the provider-neutral boundary between Etzio's lifecycle kernel and
separately operated trusted-time, revocation, and durable-head services.  It verifies
Etzio Ed25519 attestations, exact transition bindings, conservative time intervals,
monotonic revocation views, and nonbranching checkpoint continuity.

The contracts do not themselves establish trustworthy UTC, current real revocation
state, external durability, independent administration, transparency-log consistency, or
non-equivocation.  Those properties require qualified external adapters and retained
provider evidence.  Repository-owned signers and fixtures prove only this contract.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from etzio.crypto_v1 import is_valid_ed25519_public_key
from etzio.kernel.events_v1 import GENESIS_DIGEST
from etzio.protocol import (
    SEMANTIC_BODY_FIELDS_BY_KIND_V1,
    EnvelopeV1,
    ProtocolError,
    content_id,
    thaw_json,
)

INTEGRITY_DECISION_OBJECT_KIND: Final = "integrity_decision"
HEAD_CHECKPOINT_OBJECT_KIND: Final = "head_checkpoint"
INTEGRITY_DECISION_ROLE: Final = "integrity_decision_authority"
HEAD_CHECKPOINT_ROLE: Final = "head_checkpoint_authority"
INTEGRITY_ROLES_V1: Final = frozenset(
    {INTEGRITY_DECISION_ROLE, HEAD_CHECKPOINT_ROLE}
)
TRUSTED_TIME_EVIDENCE_KIND: Final = "trusted_time"
REVOCATION_METADATA_EVIDENCE_KIND: Final = "revocation_metadata"
HEAD_ANCHOR_RECEIPT_EVIDENCE_KIND: Final = "head_anchor_receipt"
EXTERNAL_FLOOR_EVIDENCE_KIND: Final = "external_floor"
INTEGRITY_EVIDENCE_KINDS_V1: Final = frozenset(
    {
        EXTERNAL_FLOOR_EVIDENCE_KIND,
        HEAD_ANCHOR_RECEIPT_EVIDENCE_KIND,
        REVOCATION_METADATA_EVIDENCE_KIND,
        TRUSTED_TIME_EVIDENCE_KIND,
    }
)

MAX_INTEGRITY_ENVELOPE_BYTES: Final = 1 << 20
MAX_INTEGRITY_KEYS: Final = 64
MAX_INTEGRITY_REVOCATIONS: Final = 10_000
MAX_EVIDENCE_REFS: Final = 16
MAX_REVOCATION_VIEWS: Final = 16
MAX_EPOCH_SECOND: Final = (2**63) - 1

_DECISION_SIGNATURE_DOMAIN: Final = b"etzio.integrity-decision.signature.v1\x00"
_CHECKPOINT_SIGNATURE_DOMAIN: Final = b"etzio.head-checkpoint.signature.v1\x00"
_AUTHENTICATED_RESULT_SEAL: Final = object()
_FULL_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
_KEY_ID = re.compile(r"^ed25519:sha256:[0-9a-f]{64}$", re.ASCII)
_NONCE_256 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_IDENTITY = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{1,127}$", re.ASCII)
_EVENT_KIND = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$", re.ASCII)
_ATTESTATION_FIELDS: Final = frozenset(
    {"algorithm", "key_id", "signature_b64"}
)
_EVIDENCE_REF_FIELDS: Final = frozenset(
    {"evidence_id", "evidence_kind", "source_id"}
)
_REVOCATION_VIEW_FIELDS: Final = frozenset(
    {
        "evidence",
        "namespace",
        "root_version",
        "snapshot_id",
        "valid_from",
        "valid_until",
        "version",
    }
)
_DECISION_BODY_FIELDS: Final = SEMANTIC_BODY_FIELDS_BY_KIND_V1[
    INTEGRITY_DECISION_OBJECT_KIND
]
_CHECKPOINT_BODY_FIELDS: Final = SEMANTIC_BODY_FIELDS_BY_KIND_V1[
    HEAD_CHECKPOINT_OBJECT_KIND
]
_INTEGRITY_TRUST_SNAPSHOT_FIELDS: Final = frozenset(
    {"keys", "revoked_key_ids"}
)
_INTEGRITY_TRUST_KEY_FIELDS: Final = frozenset(
    {"key_id", "principal_id", "public_key_b64", "role"}
)
_VALIDATION_POLICY_FIELDS: Final = frozenset(
    {
        "anchor_policy_id",
        "checkpoint_time_policy_id",
        "decision_policy_id",
        "decision_time_policy_id",
        "max_checkpoint_uncertainty_seconds",
        "max_decision_uncertainty_seconds",
        "required_revocation_namespaces",
    }
)
_REVOCATION_FLOOR_FIELDS: Final = frozenset(
    {
        "decision_policy_id",
        "environment_id",
        "evidence",
        "namespace",
        "root_version",
        "service_instance_id",
        "snapshot_id",
        "version",
    }
)
_HEAD_CHECKPOINT_FLOOR_FIELDS: Final = frozenset(
    {
        "checkpoint_attestation_id",
        "checkpoint_id",
        "checkpoint_principal_id",
        "checkpoint_trust_snapshot_id",
        "environment_id",
        "evidence",
        "instance_sequence",
        "mission_checkpoint_attestation_id",
        "mission_checkpoint_id",
        "mission_checkpoint_principal_id",
        "mission_checkpoint_trust_snapshot_id",
        "mission_event_seq",
        "mission_id",
        "service_instance_id",
    }
)


class IntegrityError(ValueError):
    """A deterministic integrity-contract construction or validation failure."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class EvidenceReferenceV1:
    """Content identity of retained provider evidence and its declared source label."""

    evidence_kind: str
    source_id: str
    evidence_id: str

    def __post_init__(self) -> None:
        if (
            type(self.evidence_kind) is not str
            or self.evidence_kind not in INTEGRITY_EVIDENCE_KINDS_V1
        ):
            raise IntegrityError(
                "invalid_evidence_kind",
                "evidence reference has an unsupported integrity evidence kind",
            )
        _require_identity(self.source_id, "source_id")
        _require_digest(self.evidence_id, "evidence_id")

    @classmethod
    def from_body(cls, body: object) -> EvidenceReferenceV1:
        if type(body) is not dict or set(body) != _EVIDENCE_REF_FIELDS:
            raise IntegrityError(
                "invalid_evidence_reference",
                "evidence reference has missing or unknown fields",
            )
        return cls(
            evidence_kind=body["evidence_kind"],
            source_id=body["source_id"],
            evidence_id=body["evidence_id"],
        )

    def to_body(self) -> dict[str, object]:
        return {
            "evidence_id": self.evidence_id,
            "evidence_kind": self.evidence_kind,
            "source_id": self.source_id,
        }


@dataclass(frozen=True, slots=True)
class RevocationViewV1:
    """One externally evaluated complete revocation namespace at an exact version."""

    namespace: str
    root_version: int
    version: int
    snapshot_id: str
    evidence: EvidenceReferenceV1
    valid_from: int
    valid_until: int

    def __post_init__(self) -> None:
        _require_identity(self.namespace, "namespace")
        _require_positive_int(self.root_version, "root_version")
        _require_positive_int(self.version, "version")
        _require_digest(self.snapshot_id, "snapshot_id")
        if (
            type(self.evidence) is not EvidenceReferenceV1
        ):
            raise IntegrityError(
                "invalid_revocation_evidence",
                "revocation view requires typed revocation-metadata evidence",
            )
        try:
            evidence = EvidenceReferenceV1(
                evidence_kind=self.evidence.evidence_kind,
                source_id=self.evidence.source_id,
                evidence_id=self.evidence.evidence_id,
            )
        except (AttributeError, IntegrityError, TypeError, ValueError) as exc:
            raise IntegrityError(
                "invalid_revocation_evidence",
                "revocation view requires typed revocation-metadata evidence",
            ) from exc
        if evidence.evidence_kind != REVOCATION_METADATA_EVIDENCE_KIND:
            raise IntegrityError(
                "invalid_revocation_evidence",
                "revocation view requires typed revocation-metadata evidence",
            )
        _require_epoch(self.valid_from, "valid_from")
        _require_epoch(self.valid_until, "valid_until")
        if self.valid_from >= self.valid_until:
            raise IntegrityError(
                "invalid_revocation_window",
                "revocation validity must be a nonempty half-open interval",
            )
        object.__setattr__(self, "evidence", evidence)

    @classmethod
    def from_body(cls, body: object) -> RevocationViewV1:
        if type(body) is not dict or set(body) != _REVOCATION_VIEW_FIELDS:
            raise IntegrityError(
                "invalid_revocation_view",
                "revocation view has missing or unknown fields",
            )
        return cls(
            namespace=body["namespace"],
            root_version=body["root_version"],
            version=body["version"],
            snapshot_id=body["snapshot_id"],
            evidence=EvidenceReferenceV1.from_body(body["evidence"]),
            valid_from=body["valid_from"],
            valid_until=body["valid_until"],
        )

    def to_body(self) -> dict[str, object]:
        return {
            "evidence": self.evidence.to_body(),
            "namespace": self.namespace,
            "root_version": self.root_version,
            "snapshot_id": self.snapshot_id,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "version": self.version,
        }


@dataclass(frozen=True, slots=True)
class IntegrityDecisionV1:
    """Exact pre-transition evidence summary attested by an integrity authority."""

    decision_id: str
    service_instance_id: str
    environment_id: str
    mission_id: str
    authority_id: str
    target_id: str
    prior_global_checkpoint_sequence: int
    prior_global_checkpoint_id: str
    prior_global_checkpoint_attestation_id: str | None
    prior_global_checkpoint_principal_id: str | None
    prior_global_checkpoint_trust_snapshot_id: str | None
    prior_event_seq: int
    prior_event_digest: str
    event_kind: str
    proposed_event_digest: str
    transition_intent_id: str
    request_nonce: str
    time_lower_bound: int
    time_upper_bound: int
    time_policy_id: str
    time_evidence: tuple[EvidenceReferenceV1, ...]
    revocation_views: tuple[RevocationViewV1, ...]
    decision_policy_id: str

    def __post_init__(self) -> None:
        _require_digest(self.decision_id, "decision_id")
        _require_identity(self.service_instance_id, "service_instance_id")
        _require_identity(self.environment_id, "environment_id")
        for field in ("mission_id", "authority_id", "target_id"):
            _require_digest(getattr(self, field), field)
        if (
            type(self.prior_global_checkpoint_sequence) is not int
            or self.prior_global_checkpoint_sequence < -1
            or self.prior_global_checkpoint_sequence >= MAX_EPOCH_SECOND
        ):
            raise IntegrityError(
                "invalid_prior_global_checkpoint_sequence",
                "prior global checkpoint sequence must leave room for one int64 successor",
            )
        _require_digest(
            self.prior_global_checkpoint_id,
            "prior_global_checkpoint_id",
        )
        global_genesis = head_checkpoint_genesis_id(
            service_instance_id=self.service_instance_id,
            environment_id=self.environment_id,
        )
        if (
            self.prior_global_checkpoint_sequence == -1
            and self.prior_global_checkpoint_id != global_genesis
        ) or (
            self.prior_global_checkpoint_sequence >= 0
            and self.prior_global_checkpoint_id == global_genesis
        ):
            raise IntegrityError(
                "invalid_global_checkpoint_binding",
                "prior global sequence and checkpoint identity disagree",
            )
        _validate_predecessor_provenance(
            sequence=self.prior_global_checkpoint_sequence,
            attestation_id=self.prior_global_checkpoint_attestation_id,
            principal_id=self.prior_global_checkpoint_principal_id,
            trust_snapshot_id=(
                self.prior_global_checkpoint_trust_snapshot_id
            ),
            label="prior_global_checkpoint",
        )
        if (
            type(self.prior_event_seq) is not int
            or self.prior_event_seq < -1
            or self.prior_event_seq >= MAX_EPOCH_SECOND
        ):
            raise IntegrityError(
                "invalid_prior_event_seq",
                "prior_event_seq must leave room for one signed int64 successor",
            )
        _require_digest(self.prior_event_digest, "prior_event_digest")
        if (
            self.prior_event_seq == -1
            and self.prior_event_digest != GENESIS_DIGEST
        ):
            raise IntegrityError(
                "invalid_genesis_binding",
                "sequence -1 must bind the fixed event genesis digest",
            )
        if (
            self.prior_event_seq >= 0
            and self.prior_event_digest == GENESIS_DIGEST
        ):
            raise IntegrityError(
                "invalid_genesis_binding",
                "non-genesis sequence cannot bind the event genesis digest",
            )
        if (
            type(self.event_kind) is not str
            or _EVENT_KIND.fullmatch(self.event_kind) is None
        ):
            raise IntegrityError(
                "invalid_event_kind",
                "event_kind must be an ASCII snake_case identifier",
            )
        _require_digest(self.proposed_event_digest, "proposed_event_digest")
        _require_digest(self.transition_intent_id, "transition_intent_id")
        if (
            type(self.request_nonce) is not str
            or _NONCE_256.fullmatch(self.request_nonce) is None
        ):
            raise IntegrityError(
                "invalid_request_nonce",
                "request_nonce must contain 256 bits of lowercase hexadecimal material",
            )
        _validate_time_interval(self.time_lower_bound, self.time_upper_bound)
        _require_digest(self.time_policy_id, "time_policy_id")
        _require_digest(self.decision_policy_id, "decision_policy_id")
        evidence = _validated_evidence_references(
            self.time_evidence,
            field="time_evidence",
            minimum=2,
            evidence_kind=TRUSTED_TIME_EVIDENCE_KIND,
        )
        views = _validated_revocation_views(self.revocation_views)
        for view in views:
            _require_interval_within(
                self.time_lower_bound,
                self.time_upper_bound,
                view.valid_from,
                view.valid_until,
                prefix=f"revocation_{view.namespace}",
            )
        object.__setattr__(self, "time_evidence", evidence)
        object.__setattr__(self, "revocation_views", views)

        envelope = EnvelopeV1.create(
            INTEGRITY_DECISION_OBJECT_KIND,
            self._body(),
        )
        if envelope.object_id != self.decision_id:
            raise IntegrityError(
                "object_id_mismatch",
                "decision_id does not match canonical integrity-decision semantics",
            )

    @classmethod
    def issue(
        cls,
        *,
        service_instance_id: str,
        environment_id: str,
        mission_id: str,
        authority_id: str,
        target_id: str,
        prior_global_checkpoint_sequence: int,
        prior_global_checkpoint_id: str,
        prior_global_checkpoint_attestation_id: str | None,
        prior_global_checkpoint_principal_id: str | None,
        prior_global_checkpoint_trust_snapshot_id: str | None,
        prior_event_seq: int,
        prior_event_digest: str,
        event_kind: str,
        proposed_event_digest: str,
        transition_intent_id: str,
        request_nonce: str,
        time_lower_bound: int,
        time_upper_bound: int,
        time_policy_id: str,
        time_evidence: tuple[EvidenceReferenceV1, ...],
        revocation_views: tuple[RevocationViewV1, ...],
        decision_policy_id: str,
    ) -> IntegrityDecisionV1:
        try:
            body = _decision_body(
                service_instance_id=service_instance_id,
                environment_id=environment_id,
                mission_id=mission_id,
                authority_id=authority_id,
                target_id=target_id,
                prior_global_checkpoint_sequence=(
                    prior_global_checkpoint_sequence
                ),
                prior_global_checkpoint_id=prior_global_checkpoint_id,
                prior_global_checkpoint_attestation_id=(
                    prior_global_checkpoint_attestation_id
                ),
                prior_global_checkpoint_principal_id=(
                    prior_global_checkpoint_principal_id
                ),
                prior_global_checkpoint_trust_snapshot_id=(
                    prior_global_checkpoint_trust_snapshot_id
                ),
                prior_event_seq=prior_event_seq,
                prior_event_digest=prior_event_digest,
                event_kind=event_kind,
                proposed_event_digest=proposed_event_digest,
                transition_intent_id=transition_intent_id,
                request_nonce=request_nonce,
                time_lower_bound=time_lower_bound,
                time_upper_bound=time_upper_bound,
                time_policy_id=time_policy_id,
                time_evidence=time_evidence,
                revocation_views=revocation_views,
                decision_policy_id=decision_policy_id,
            )
            envelope = EnvelopeV1.create(
                INTEGRITY_DECISION_OBJECT_KIND,
                body,
            )
        except IntegrityError:
            raise
        except (AttributeError, ProtocolError, TypeError, ValueError) as exc:
            raise IntegrityError(
                "invalid_integrity_decision",
                "integrity decision cannot be represented by protocol v1",
            ) from exc
        return cls(decision_id=envelope.object_id, **_decision_values(body))

    @classmethod
    def from_envelope(cls, envelope: EnvelopeV1) -> IntegrityDecisionV1:
        if type(envelope) is not EnvelopeV1:
            raise IntegrityError(
                "invalid_integrity_decision",
                "expected an unattested integrity_decision envelope",
            )
        try:
            valid_framing = (
                envelope.object_kind == INTEGRITY_DECISION_OBJECT_KIND
                and not envelope.attestations
            )
        except AttributeError as exc:
            raise IntegrityError(
                "invalid_integrity_decision",
                "integrity decision envelope framing is malformed",
            ) from exc
        if not valid_framing:
            raise IntegrityError(
                "invalid_integrity_decision",
                "expected an unattested integrity_decision envelope",
            )
        try:
            body = thaw_json(envelope.body)
        except (AttributeError, ProtocolError, TypeError, ValueError) as exc:
            raise IntegrityError(
                "invalid_integrity_decision",
                "integrity decision body is not valid protocol-v1 semantics",
            ) from exc
        if type(body) is not dict or set(body) != _DECISION_BODY_FIELDS:
            raise IntegrityError(
                "invalid_integrity_decision",
                "integrity decision has missing or unknown fields",
            )
        return cls(decision_id=envelope.object_id, **_decision_values(body))

    def _body(self) -> dict[str, object]:
        return _decision_body(
            service_instance_id=self.service_instance_id,
            environment_id=self.environment_id,
            mission_id=self.mission_id,
            authority_id=self.authority_id,
            target_id=self.target_id,
            prior_global_checkpoint_sequence=(
                self.prior_global_checkpoint_sequence
            ),
            prior_global_checkpoint_id=self.prior_global_checkpoint_id,
            prior_global_checkpoint_attestation_id=(
                self.prior_global_checkpoint_attestation_id
            ),
            prior_global_checkpoint_principal_id=(
                self.prior_global_checkpoint_principal_id
            ),
            prior_global_checkpoint_trust_snapshot_id=(
                self.prior_global_checkpoint_trust_snapshot_id
            ),
            prior_event_seq=self.prior_event_seq,
            prior_event_digest=self.prior_event_digest,
            event_kind=self.event_kind,
            proposed_event_digest=self.proposed_event_digest,
            transition_intent_id=self.transition_intent_id,
            request_nonce=self.request_nonce,
            time_lower_bound=self.time_lower_bound,
            time_upper_bound=self.time_upper_bound,
            time_policy_id=self.time_policy_id,
            time_evidence=self.time_evidence,
            revocation_views=self.revocation_views,
            decision_policy_id=self.decision_policy_id,
        )

    def to_envelope(self) -> EnvelopeV1:
        envelope = EnvelopeV1.create(INTEGRITY_DECISION_OBJECT_KIND, self._body())
        if envelope.object_id != self.decision_id:
            raise IntegrityError(
                "object_id_mismatch",
                "decision_id does not match canonical integrity-decision semantics",
            )
        return envelope

    def revocation_view(self, namespace: str) -> RevocationViewV1:
        _require_identity(namespace, "namespace")
        for view in self.revocation_views:
            if view.namespace == namespace:
                return view
        raise IntegrityError(
            "missing_revocation_namespace",
            f"integrity decision lacks revocation namespace {namespace!r}",
        )


@dataclass(frozen=True, slots=True)
class HeadCheckpointV1:
    """One typed instance-global and mission-local event-head checkpoint statement."""

    checkpoint_id: str
    service_instance_id: str
    environment_id: str
    instance_sequence: int
    previous_checkpoint_id: str
    previous_checkpoint_attestation_id: str | None
    previous_checkpoint_principal_id: str | None
    previous_checkpoint_trust_snapshot_id: str | None
    previous_mission_checkpoint_id: str
    previous_mission_checkpoint_attestation_id: str | None
    previous_mission_checkpoint_principal_id: str | None
    previous_mission_checkpoint_trust_snapshot_id: str | None
    mission_id: str
    authority_id: str
    target_id: str
    event_seq: int
    event_digest: str
    integrity_decision_id: str
    integrity_decision_attestation_id: str
    integrity_decision_principal_id: str
    integrity_decision_trust_snapshot_id: str
    time_lower_bound: int
    time_upper_bound: int
    time_policy_id: str
    time_evidence: tuple[EvidenceReferenceV1, ...]
    anchor_policy_id: str
    anchor_statement_id: str
    anchor_evidence: tuple[EvidenceReferenceV1, ...]

    def __post_init__(self) -> None:
        for field in (
            "checkpoint_id",
            "previous_checkpoint_id",
            "previous_mission_checkpoint_id",
            "mission_id",
            "authority_id",
            "target_id",
            "event_digest",
            "integrity_decision_id",
            "integrity_decision_attestation_id",
            "integrity_decision_trust_snapshot_id",
            "time_policy_id",
            "anchor_policy_id",
            "anchor_statement_id",
        ):
            _require_digest(getattr(self, field), field)
        _require_identity(self.service_instance_id, "service_instance_id")
        _require_identity(self.environment_id, "environment_id")
        _require_identity(
            self.integrity_decision_principal_id,
            "integrity_decision_principal_id",
        )
        _require_nonnegative_int(self.instance_sequence, "instance_sequence")
        _require_nonnegative_int(self.event_seq, "event_seq")
        if self.event_seq > self.instance_sequence:
            raise IntegrityError(
                "invalid_checkpoint_sequence",
                "mission event sequence cannot exceed the instance-global sequence",
            )
        global_genesis = head_checkpoint_genesis_id(
            service_instance_id=self.service_instance_id,
            environment_id=self.environment_id,
        )
        mission_genesis = mission_checkpoint_genesis_id(
            service_instance_id=self.service_instance_id,
            environment_id=self.environment_id,
            mission_id=self.mission_id,
        )
        if (
            self.instance_sequence == 0
            and self.previous_checkpoint_id != global_genesis
        ) or (
            self.instance_sequence > 0
            and self.previous_checkpoint_id == global_genesis
        ):
            raise IntegrityError(
                "invalid_global_checkpoint_binding",
                "checkpoint sequence and global predecessor identity disagree",
            )
        if (
            self.event_seq == 0
            and self.previous_mission_checkpoint_id != mission_genesis
        ) or (
            self.event_seq > 0
            and self.previous_mission_checkpoint_id == mission_genesis
        ):
            raise IntegrityError(
                "invalid_mission_checkpoint_binding",
                "event sequence and mission predecessor identity disagree",
            )
        _validate_predecessor_provenance(
            sequence=self.instance_sequence - 1,
            attestation_id=self.previous_checkpoint_attestation_id,
            principal_id=self.previous_checkpoint_principal_id,
            trust_snapshot_id=(
                self.previous_checkpoint_trust_snapshot_id
            ),
            label="previous_checkpoint",
        )
        _validate_predecessor_provenance(
            sequence=self.event_seq - 1,
            attestation_id=(
                self.previous_mission_checkpoint_attestation_id
            ),
            principal_id=self.previous_mission_checkpoint_principal_id,
            trust_snapshot_id=(
                self.previous_mission_checkpoint_trust_snapshot_id
            ),
            label="previous_mission_checkpoint",
        )
        if (
            self.previous_checkpoint_id
            == self.previous_mission_checkpoint_id
            and (
                self.previous_checkpoint_attestation_id,
                self.previous_checkpoint_principal_id,
                self.previous_checkpoint_trust_snapshot_id,
            )
            != (
                self.previous_mission_checkpoint_attestation_id,
                self.previous_mission_checkpoint_principal_id,
                self.previous_mission_checkpoint_trust_snapshot_id,
            )
        ):
            raise IntegrityError(
                "checkpoint_predecessor_provenance_mismatch",
                "one predecessor identity must have one exact attestation provenance",
            )
        _validate_time_interval(self.time_lower_bound, self.time_upper_bound)
        time_evidence = _validated_evidence_references(
            self.time_evidence,
            field="time_evidence",
            minimum=2,
            evidence_kind=TRUSTED_TIME_EVIDENCE_KIND,
        )
        anchor_evidence = _validated_evidence_references(
            self.anchor_evidence,
            field="anchor_evidence",
            minimum=2,
            evidence_kind=HEAD_ANCHOR_RECEIPT_EVIDENCE_KIND,
        )
        object.__setattr__(self, "time_evidence", time_evidence)
        object.__setattr__(self, "anchor_evidence", anchor_evidence)
        expected_statement_id = derive_anchor_statement_id(
            service_instance_id=self.service_instance_id,
            environment_id=self.environment_id,
            instance_sequence=self.instance_sequence,
            previous_checkpoint_id=self.previous_checkpoint_id,
            previous_checkpoint_attestation_id=(
                self.previous_checkpoint_attestation_id
            ),
            previous_checkpoint_principal_id=(
                self.previous_checkpoint_principal_id
            ),
            previous_checkpoint_trust_snapshot_id=(
                self.previous_checkpoint_trust_snapshot_id
            ),
            previous_mission_checkpoint_id=self.previous_mission_checkpoint_id,
            previous_mission_checkpoint_attestation_id=(
                self.previous_mission_checkpoint_attestation_id
            ),
            previous_mission_checkpoint_principal_id=(
                self.previous_mission_checkpoint_principal_id
            ),
            previous_mission_checkpoint_trust_snapshot_id=(
                self.previous_mission_checkpoint_trust_snapshot_id
            ),
            mission_id=self.mission_id,
            authority_id=self.authority_id,
            target_id=self.target_id,
            event_seq=self.event_seq,
            event_digest=self.event_digest,
            integrity_decision_id=self.integrity_decision_id,
            integrity_decision_attestation_id=(
                self.integrity_decision_attestation_id
            ),
            integrity_decision_principal_id=(
                self.integrity_decision_principal_id
            ),
            integrity_decision_trust_snapshot_id=(
                self.integrity_decision_trust_snapshot_id
            ),
            time_lower_bound=self.time_lower_bound,
            time_upper_bound=self.time_upper_bound,
            time_policy_id=self.time_policy_id,
            time_evidence=self.time_evidence,
            anchor_policy_id=self.anchor_policy_id,
        )
        if self.anchor_statement_id != expected_statement_id:
            raise IntegrityError(
                "anchor_statement_mismatch",
                "anchor_statement_id does not match the pre-receipt head statement",
            )

        envelope = EnvelopeV1.create(HEAD_CHECKPOINT_OBJECT_KIND, self._body())
        if envelope.object_id != self.checkpoint_id:
            raise IntegrityError(
                "object_id_mismatch",
                "checkpoint_id does not match canonical head-checkpoint semantics",
            )

    @classmethod
    def issue(
        cls,
        *,
        service_instance_id: str,
        environment_id: str,
        instance_sequence: int,
        previous_checkpoint_id: str,
        previous_checkpoint_attestation_id: str | None,
        previous_checkpoint_principal_id: str | None,
        previous_checkpoint_trust_snapshot_id: str | None,
        previous_mission_checkpoint_id: str,
        previous_mission_checkpoint_attestation_id: str | None,
        previous_mission_checkpoint_principal_id: str | None,
        previous_mission_checkpoint_trust_snapshot_id: str | None,
        mission_id: str,
        authority_id: str,
        target_id: str,
        event_seq: int,
        event_digest: str,
        integrity_decision_id: str,
        integrity_decision_attestation_id: str,
        integrity_decision_principal_id: str,
        integrity_decision_trust_snapshot_id: str,
        time_lower_bound: int,
        time_upper_bound: int,
        time_policy_id: str,
        time_evidence: tuple[EvidenceReferenceV1, ...],
        anchor_policy_id: str,
        anchor_evidence: tuple[EvidenceReferenceV1, ...],
    ) -> HeadCheckpointV1:
        anchor_statement_id = derive_anchor_statement_id(
            service_instance_id=service_instance_id,
            environment_id=environment_id,
            instance_sequence=instance_sequence,
            previous_checkpoint_id=previous_checkpoint_id,
            previous_checkpoint_attestation_id=(
                previous_checkpoint_attestation_id
            ),
            previous_checkpoint_principal_id=(
                previous_checkpoint_principal_id
            ),
            previous_checkpoint_trust_snapshot_id=(
                previous_checkpoint_trust_snapshot_id
            ),
            previous_mission_checkpoint_id=previous_mission_checkpoint_id,
            previous_mission_checkpoint_attestation_id=(
                previous_mission_checkpoint_attestation_id
            ),
            previous_mission_checkpoint_principal_id=(
                previous_mission_checkpoint_principal_id
            ),
            previous_mission_checkpoint_trust_snapshot_id=(
                previous_mission_checkpoint_trust_snapshot_id
            ),
            mission_id=mission_id,
            authority_id=authority_id,
            target_id=target_id,
            event_seq=event_seq,
            event_digest=event_digest,
            integrity_decision_id=integrity_decision_id,
            integrity_decision_attestation_id=(
                integrity_decision_attestation_id
            ),
            integrity_decision_principal_id=integrity_decision_principal_id,
            integrity_decision_trust_snapshot_id=(
                integrity_decision_trust_snapshot_id
            ),
            time_lower_bound=time_lower_bound,
            time_upper_bound=time_upper_bound,
            time_policy_id=time_policy_id,
            time_evidence=time_evidence,
            anchor_policy_id=anchor_policy_id,
        )
        body = _checkpoint_body(
            service_instance_id=service_instance_id,
            environment_id=environment_id,
            instance_sequence=instance_sequence,
            previous_checkpoint_id=previous_checkpoint_id,
            previous_checkpoint_attestation_id=(
                previous_checkpoint_attestation_id
            ),
            previous_checkpoint_principal_id=(
                previous_checkpoint_principal_id
            ),
            previous_checkpoint_trust_snapshot_id=(
                previous_checkpoint_trust_snapshot_id
            ),
            previous_mission_checkpoint_id=previous_mission_checkpoint_id,
            previous_mission_checkpoint_attestation_id=(
                previous_mission_checkpoint_attestation_id
            ),
            previous_mission_checkpoint_principal_id=(
                previous_mission_checkpoint_principal_id
            ),
            previous_mission_checkpoint_trust_snapshot_id=(
                previous_mission_checkpoint_trust_snapshot_id
            ),
            mission_id=mission_id,
            authority_id=authority_id,
            target_id=target_id,
            event_seq=event_seq,
            event_digest=event_digest,
            integrity_decision_id=integrity_decision_id,
            integrity_decision_attestation_id=(
                integrity_decision_attestation_id
            ),
            integrity_decision_principal_id=integrity_decision_principal_id,
            integrity_decision_trust_snapshot_id=(
                integrity_decision_trust_snapshot_id
            ),
            time_lower_bound=time_lower_bound,
            time_upper_bound=time_upper_bound,
            time_policy_id=time_policy_id,
            time_evidence=time_evidence,
            anchor_policy_id=anchor_policy_id,
            anchor_statement_id=anchor_statement_id,
            anchor_evidence=anchor_evidence,
        )
        envelope = EnvelopeV1.create(HEAD_CHECKPOINT_OBJECT_KIND, body)
        return cls(checkpoint_id=envelope.object_id, **_checkpoint_values(body))

    @classmethod
    def from_envelope(cls, envelope: EnvelopeV1) -> HeadCheckpointV1:
        if type(envelope) is not EnvelopeV1:
            raise IntegrityError(
                "invalid_head_checkpoint",
                "expected an unattested head_checkpoint envelope",
            )
        try:
            valid_framing = (
                envelope.object_kind == HEAD_CHECKPOINT_OBJECT_KIND
                and not envelope.attestations
            )
        except AttributeError as exc:
            raise IntegrityError(
                "invalid_head_checkpoint",
                "head checkpoint envelope framing is malformed",
            ) from exc
        if not valid_framing:
            raise IntegrityError(
                "invalid_head_checkpoint",
                "expected an unattested head_checkpoint envelope",
            )
        try:
            body = thaw_json(envelope.body)
        except (AttributeError, ProtocolError, TypeError, ValueError) as exc:
            raise IntegrityError(
                "invalid_head_checkpoint",
                "head checkpoint body is not valid protocol-v1 semantics",
            ) from exc
        if type(body) is not dict or set(body) != _CHECKPOINT_BODY_FIELDS:
            raise IntegrityError(
                "invalid_head_checkpoint",
                "head checkpoint has missing or unknown fields",
            )
        return cls(checkpoint_id=envelope.object_id, **_checkpoint_values(body))

    def _body(self) -> dict[str, object]:
        return _checkpoint_body(
            service_instance_id=self.service_instance_id,
            environment_id=self.environment_id,
            instance_sequence=self.instance_sequence,
            previous_checkpoint_id=self.previous_checkpoint_id,
            previous_checkpoint_attestation_id=(
                self.previous_checkpoint_attestation_id
            ),
            previous_checkpoint_principal_id=(
                self.previous_checkpoint_principal_id
            ),
            previous_checkpoint_trust_snapshot_id=(
                self.previous_checkpoint_trust_snapshot_id
            ),
            previous_mission_checkpoint_id=self.previous_mission_checkpoint_id,
            previous_mission_checkpoint_attestation_id=(
                self.previous_mission_checkpoint_attestation_id
            ),
            previous_mission_checkpoint_principal_id=(
                self.previous_mission_checkpoint_principal_id
            ),
            previous_mission_checkpoint_trust_snapshot_id=(
                self.previous_mission_checkpoint_trust_snapshot_id
            ),
            mission_id=self.mission_id,
            authority_id=self.authority_id,
            target_id=self.target_id,
            event_seq=self.event_seq,
            event_digest=self.event_digest,
            integrity_decision_id=self.integrity_decision_id,
            integrity_decision_attestation_id=(
                self.integrity_decision_attestation_id
            ),
            integrity_decision_principal_id=(
                self.integrity_decision_principal_id
            ),
            integrity_decision_trust_snapshot_id=(
                self.integrity_decision_trust_snapshot_id
            ),
            time_lower_bound=self.time_lower_bound,
            time_upper_bound=self.time_upper_bound,
            time_policy_id=self.time_policy_id,
            time_evidence=self.time_evidence,
            anchor_policy_id=self.anchor_policy_id,
            anchor_statement_id=self.anchor_statement_id,
            anchor_evidence=self.anchor_evidence,
        )

    def to_envelope(self) -> EnvelopeV1:
        envelope = EnvelopeV1.create(HEAD_CHECKPOINT_OBJECT_KIND, self._body())
        if envelope.object_id != self.checkpoint_id:
            raise IntegrityError(
                "object_id_mismatch",
                "checkpoint_id does not match canonical head-checkpoint semantics",
            )
        return envelope


@dataclass(frozen=True, slots=True)
class SignedIntegrityDecisionV1:
    """Canonical integrity-decision bytes plus one detached Ed25519 signature."""

    envelope_bytes: bytes
    key_id: str
    signature_b64: str

    def __post_init__(self) -> None:
        _validate_signed_fields(
            self.envelope_bytes,
            self.key_id,
            self.signature_b64,
        )

    def to_envelope(self) -> EnvelopeV1:
        try:
            envelope_bytes = self.envelope_bytes
            key_id = self.key_id
            signature_b64 = self.signature_b64
        except AttributeError as exc:
            raise IntegrityError(
                "malformed_signed_object",
                "signed integrity decision transport is incomplete",
            ) from exc
        return _signed_to_envelope(
            envelope_bytes,
            key_id,
            signature_b64,
            object_kind=INTEGRITY_DECISION_OBJECT_KIND,
            parser=IntegrityDecisionV1.from_envelope,
        )

    def to_bytes(self) -> bytes:
        return self.to_envelope().to_bytes()

    @classmethod
    def from_bytes(cls, data: bytes | str) -> SignedIntegrityDecisionV1:
        envelope_bytes, key_id, signature_b64 = _signed_from_bytes(
            data,
            object_kind=INTEGRITY_DECISION_OBJECT_KIND,
            parser=IntegrityDecisionV1.from_envelope,
        )
        return cls(envelope_bytes, key_id, signature_b64)


@dataclass(frozen=True, slots=True)
class SignedHeadCheckpointV1:
    """Canonical head-checkpoint bytes plus one detached Ed25519 signature."""

    envelope_bytes: bytes
    key_id: str
    signature_b64: str

    def __post_init__(self) -> None:
        _validate_signed_fields(
            self.envelope_bytes,
            self.key_id,
            self.signature_b64,
        )

    def to_envelope(self) -> EnvelopeV1:
        try:
            envelope_bytes = self.envelope_bytes
            key_id = self.key_id
            signature_b64 = self.signature_b64
        except AttributeError as exc:
            raise IntegrityError(
                "malformed_signed_object",
                "signed head checkpoint transport is incomplete",
            ) from exc
        return _signed_to_envelope(
            envelope_bytes,
            key_id,
            signature_b64,
            object_kind=HEAD_CHECKPOINT_OBJECT_KIND,
            parser=HeadCheckpointV1.from_envelope,
        )

    def to_bytes(self) -> bytes:
        return self.to_envelope().to_bytes()

    @classmethod
    def from_bytes(cls, data: bytes | str) -> SignedHeadCheckpointV1:
        envelope_bytes, key_id, signature_b64 = _signed_from_bytes(
            data,
            object_kind=HEAD_CHECKPOINT_OBJECT_KIND,
            parser=HeadCheckpointV1.from_envelope,
        )
        return cls(envelope_bytes, key_id, signature_b64)


def _snapshot_integrity_decision_value(
    value: object,
) -> IntegrityDecisionV1:
    """Rebuild one exact decision through canonical protocol semantics."""

    if type(value) is not IntegrityDecisionV1:
        raise IntegrityError(
            "invalid_integrity_decision",
            "an exact IntegrityDecisionV1 is required",
        )
    try:
        envelope = value.to_envelope()
        return IntegrityDecisionV1.from_envelope(
            EnvelopeV1.from_bytes(envelope.to_bytes())
        )
    except (AttributeError, IntegrityError, ProtocolError, TypeError, ValueError) as exc:
        raise IntegrityError(
            "invalid_integrity_decision",
            "integrity decision is not a valid canonical value",
        ) from exc


def _snapshot_head_checkpoint_value(
    value: object,
) -> HeadCheckpointV1:
    """Rebuild one exact checkpoint through canonical protocol semantics."""

    if type(value) is not HeadCheckpointV1:
        raise IntegrityError(
            "invalid_head_checkpoint",
            "an exact HeadCheckpointV1 is required",
        )
    try:
        envelope = value.to_envelope()
        return HeadCheckpointV1.from_envelope(
            EnvelopeV1.from_bytes(envelope.to_bytes())
        )
    except (AttributeError, IntegrityError, ProtocolError, TypeError, ValueError) as exc:
        raise IntegrityError(
            "invalid_head_checkpoint",
            "head checkpoint is not a valid canonical value",
        ) from exc


def _snapshot_signed_decision(
    value: object,
) -> SignedIntegrityDecisionV1:
    """Copy exact signed-decision transport fields without interpreting its body."""

    if type(value) is not SignedIntegrityDecisionV1:
        raise IntegrityError(
            "invalid_signed_integrity_decision",
            "an exact signed integrity decision is required",
        )
    try:
        return SignedIntegrityDecisionV1(
            envelope_bytes=value.envelope_bytes,
            key_id=value.key_id,
            signature_b64=value.signature_b64,
        )
    except (AttributeError, IntegrityError, TypeError, ValueError) as exc:
        raise IntegrityError(
            "invalid_signed_integrity_decision",
            "signed integrity decision transport is malformed",
        ) from exc


def _snapshot_signed_checkpoint(
    value: object,
) -> SignedHeadCheckpointV1:
    """Copy exact signed-checkpoint transport fields without interpreting its body."""

    if type(value) is not SignedHeadCheckpointV1:
        raise IntegrityError(
            "invalid_signed_head_checkpoint",
            "an exact signed head checkpoint is required",
        )
    try:
        return SignedHeadCheckpointV1(
            envelope_bytes=value.envelope_bytes,
            key_id=value.key_id,
            signature_b64=value.signature_b64,
        )
    except (AttributeError, IntegrityError, TypeError, ValueError) as exc:
        raise IntegrityError(
            "invalid_signed_head_checkpoint",
            "signed head checkpoint transport is malformed",
        ) from exc


def signed_integrity_decision_attestation_id(
    signed: SignedIntegrityDecisionV1,
) -> str:
    """Commit to the exact canonical signed-decision wire, including its signature."""

    signed = _snapshot_signed_decision(signed)
    try:
        wire_bytes = signed.to_bytes()
    except (AttributeError, IntegrityError, ProtocolError, TypeError, ValueError) as exc:
        raise IntegrityError(
            "invalid_signed_integrity_decision",
            "attestation identity requires a canonical signed integrity decision",
        ) from exc
    return _signed_attestation_id(
        "signed_integrity_decision_attestation",
        wire_bytes,
    )


def signed_head_checkpoint_attestation_id(
    signed: SignedHeadCheckpointV1,
) -> str:
    """Commit to the exact canonical signed-checkpoint wire, including its signature."""

    signed = _snapshot_signed_checkpoint(signed)
    try:
        wire_bytes = signed.to_bytes()
    except (AttributeError, IntegrityError, ProtocolError, TypeError, ValueError) as exc:
        raise IntegrityError(
            "invalid_signed_head_checkpoint",
            "attestation identity requires a canonical signed head checkpoint",
        ) from exc
    return _signed_attestation_id(
        "signed_head_checkpoint_attestation",
        wire_bytes,
    )


@dataclass(frozen=True, slots=True)
class IntegritySigner:
    """Controlled fixture/tooling signer; not evidence of independent key custody."""

    private_key: Ed25519PrivateKey  # gitleaks:allow -- type only, never key material
    role: str

    def __post_init__(self) -> None:
        if not isinstance(self.private_key, Ed25519PrivateKey):
            raise IntegrityError(
                "invalid_private_key",
                "integrity signer requires an Ed25519 private key",
            )
        if (
            type(self.role) is not str
            or self.role not in INTEGRITY_ROLES_V1
        ):
            raise IntegrityError(
                "invalid_integrity_role",
                "integrity signer requires one exact integrity role",
            )

    @classmethod
    def generate(cls, role: str) -> IntegritySigner:
        return cls(Ed25519PrivateKey.generate(), role)

    @property
    def public_key_bytes(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @property
    def key_id(self) -> str:
        return integrity_key_id(self.public_key_bytes)

    def sign_decision(
        self, decision: IntegrityDecisionV1
    ) -> SignedIntegrityDecisionV1:
        if (
            type(self.role) is not str
            or self.role != INTEGRITY_DECISION_ROLE
        ):
            raise IntegrityError(
                "signer_role_mismatch",
                "only an integrity-decision signer can sign a decision",
            )
        decision = _snapshot_integrity_decision_value(decision)
        envelope_bytes = decision.to_envelope().to_bytes()
        signature = self.private_key.sign(
            _DECISION_SIGNATURE_DOMAIN + envelope_bytes
        )
        return SignedIntegrityDecisionV1(
            envelope_bytes,
            self.key_id,
            base64.b64encode(signature).decode("ascii"),
        )

    def sign_checkpoint(
        self, checkpoint: HeadCheckpointV1
    ) -> SignedHeadCheckpointV1:
        if (
            type(self.role) is not str
            or self.role != HEAD_CHECKPOINT_ROLE
        ):
            raise IntegrityError(
                "signer_role_mismatch",
                "only a head-checkpoint signer can sign a checkpoint",
            )
        checkpoint = _snapshot_head_checkpoint_value(checkpoint)
        envelope_bytes = checkpoint.to_envelope().to_bytes()
        signature = self.private_key.sign(
            _CHECKPOINT_SIGNATURE_DOMAIN + envelope_bytes
        )
        return SignedHeadCheckpointV1(
            envelope_bytes,
            self.key_id,
            base64.b64encode(signature).decode("ascii"),
        )


@dataclass(frozen=True, slots=True)
class TrustedIntegrityKey:
    """One configured integrity principal and one exact role."""

    principal_id: str
    public_key_bytes: bytes
    role: str

    def __post_init__(self) -> None:
        _require_identity(self.principal_id, "principal_id")
        if not is_valid_ed25519_public_key(self.public_key_bytes):
            raise IntegrityError(
                "invalid_public_key",
                "Ed25519 public keys must be canonical prime-subgroup points",
            )
        try:
            Ed25519PublicKey.from_public_bytes(self.public_key_bytes)
        except ValueError as exc:
            raise IntegrityError(
                "invalid_public_key",
                "invalid Ed25519 public key",
            ) from exc
        if (
            type(self.role) is not str
            or self.role not in INTEGRITY_ROLES_V1
        ):
            raise IntegrityError(
                "invalid_integrity_role",
                "trusted integrity key requires one exact role",
            )

    @property
    def key_id(self) -> str:
        return integrity_key_id(self.public_key_bytes)


@dataclass(frozen=True, slots=True)
class IntegrityTrustStore:
    """Immutable bootstrap trust for integrity-decision and checkpoint attestations."""

    keys: Mapping[str, TrustedIntegrityKey]
    revoked_key_ids: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not isinstance(self.keys, Mapping):
            raise IntegrityError(
                "invalid_trust_store",
                "integrity keys must be a mapping",
            )
        copied: dict[str, TrustedIntegrityKey] = {}
        try:
            for index, entry in enumerate(self.keys.items()):
                if index >= MAX_INTEGRITY_KEYS:
                    raise IntegrityError(
                        "invalid_trust_store",
                        "integrity trust store exceeds the key-count ceiling",
                    )
                try:
                    key_id, trusted_key = entry
                except (TypeError, ValueError) as exc:
                    raise IntegrityError(
                        "invalid_trust_store",
                        "integrity trust-store entry is malformed",
                    ) from exc
                if (
                    type(key_id) is not str
                    or _KEY_ID.fullmatch(key_id) is None
                    or type(trusted_key) is not TrustedIntegrityKey
                    or key_id in copied
                ):
                    raise IntegrityError(
                        "invalid_trust_store",
                        "integrity trust-store entry is malformed",
                    )
                copied_key = TrustedIntegrityKey(
                    principal_id=trusted_key.principal_id,
                    public_key_bytes=trusted_key.public_key_bytes,
                    role=trusted_key.role,
                )
                if copied_key.key_id != key_id:
                    raise IntegrityError(
                        "invalid_trust_store",
                        "integrity trust-store key identity is inconsistent",
                    )
                copied[key_id] = copied_key
        except IntegrityError:
            raise
        except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
            raise IntegrityError(
                "invalid_trust_store",
                "integrity trust-store entries are malformed",
            ) from exc
        revoked = _validated_key_ids(
            self.revoked_key_ids,
            maximum=MAX_INTEGRITY_REVOCATIONS,
        )
        if len(revoked) > MAX_INTEGRITY_REVOCATIONS:
            raise IntegrityError(
                "invalid_trust_store",
                "integrity trust store exceeds the revocation-count ceiling",
            )
        object.__setattr__(self, "keys", MappingProxyType(copied))
        object.__setattr__(self, "revoked_key_ids", revoked)

    @classmethod
    def from_keys(
        cls,
        trusted_keys: Iterable[TrustedIntegrityKey],
        *,
        revoked_key_ids: Iterable[str] = (),
    ) -> IntegrityTrustStore:
        if isinstance(trusted_keys, (str, bytes)):
            raise IntegrityError(
                "invalid_trust_store",
                "trusted_keys must be an iterable of TrustedIntegrityKey",
            )
        keys: dict[str, TrustedIntegrityKey] = {}
        try:
            for trusted_key in trusted_keys:
                if len(keys) >= MAX_INTEGRITY_KEYS:
                    raise IntegrityError(
                        "invalid_trust_store",
                        "trusted_keys exceeds the fixed key-count ceiling",
                    )
                if type(trusted_key) is not TrustedIntegrityKey:
                    raise IntegrityError(
                        "invalid_trust_store",
                        "trusted_keys contains an invalid entry",
                    )
                if trusted_key.key_id in keys:
                    raise IntegrityError(
                        "invalid_trust_store",
                        "duplicate trusted integrity key",
                    )
                keys[trusted_key.key_id] = trusted_key
        except TypeError as exc:
            raise IntegrityError(
                "invalid_trust_store",
                "trusted_keys must be iterable",
            ) from exc
        revoked = _validated_key_ids(
            revoked_key_ids,
            maximum=MAX_INTEGRITY_REVOCATIONS,
        )
        return cls(keys, revoked)

    @classmethod
    def from_snapshot_body(
        cls,
        body: object,
        *,
        expected_snapshot_id: str | None = None,
    ) -> IntegrityTrustStore:
        """Strictly reconstruct one canonical integrity trust snapshot."""

        if (
            type(body) is not dict
            or len(body) != len(_INTEGRITY_TRUST_SNAPSHOT_FIELDS)
            or set(body) != _INTEGRITY_TRUST_SNAPSHOT_FIELDS
        ):
            raise IntegrityError(
                "invalid_trust_snapshot",
                "integrity trust snapshot has missing or unknown fields",
            )
        keys = body["keys"]
        revoked_key_ids = body["revoked_key_ids"]
        if type(keys) is not list or type(revoked_key_ids) is not list:
            raise IntegrityError(
                "invalid_trust_snapshot",
                "integrity trust snapshot collections must be arrays",
            )
        if len(keys) > MAX_INTEGRITY_KEYS:
            raise IntegrityError(
                "invalid_trust_snapshot",
                "integrity trust snapshot exceeds the key-count ceiling",
            )
        if len(revoked_key_ids) > MAX_INTEGRITY_REVOCATIONS:
            raise IntegrityError(
                "invalid_trust_snapshot",
                "integrity trust snapshot exceeds the revocation-count ceiling",
            )

        trusted_keys: list[TrustedIntegrityKey] = []
        observed_key_ids: list[str] = []
        for entry in keys:
            if (
                type(entry) is not dict
                or len(entry) != len(_INTEGRITY_TRUST_KEY_FIELDS)
                or set(entry) != _INTEGRITY_TRUST_KEY_FIELDS
            ):
                raise IntegrityError(
                    "invalid_trust_snapshot",
                    "integrity trust snapshot key entry is malformed",
                )
            key_id = entry["key_id"]
            principal_id = entry["principal_id"]
            public_key_b64 = entry["public_key_b64"]
            role = entry["role"]
            if (
                type(key_id) is not str
                or _KEY_ID.fullmatch(key_id) is None
                or type(principal_id) is not str
                or _IDENTITY.fullmatch(principal_id) is None
                or principal_id != principal_id.strip()
                or type(public_key_b64) is not str
                or len(public_key_b64) != 44
                or type(role) is not str
                or role not in INTEGRITY_ROLES_V1
            ):
                raise IntegrityError(
                    "invalid_trust_snapshot",
                    "integrity trust snapshot key identity or role is noncanonical",
                )
            try:
                public_key_bytes = base64.b64decode(
                    public_key_b64,
                    validate=True,
                )
            except (binascii.Error, ValueError) as exc:
                raise IntegrityError(
                    "invalid_trust_snapshot",
                    "integrity trust snapshot public key is malformed",
                ) from exc
            if (
                len(public_key_bytes) != 32
                or base64.b64encode(public_key_bytes).decode("ascii")
                != public_key_b64
                or integrity_key_id(public_key_bytes) != key_id
                or not is_valid_ed25519_public_key(public_key_bytes)
            ):
                raise IntegrityError(
                    "invalid_trust_snapshot",
                    "integrity trust snapshot public key identity is malformed",
                )
            try:
                trusted_key = TrustedIntegrityKey(
                    principal_id=principal_id,
                    public_key_bytes=public_key_bytes,
                    role=role,
                )
            except (IntegrityError, TypeError, ValueError) as exc:
                raise IntegrityError(
                    "invalid_trust_snapshot",
                    "integrity trust snapshot contains an invalid trusted key",
                ) from exc
            observed_key_ids.append(key_id)
            trusted_keys.append(trusted_key)
        if observed_key_ids != sorted(set(observed_key_ids)):
            raise IntegrityError(
                "invalid_trust_snapshot",
                "integrity trust snapshot keys are not in unique canonical order",
            )
        if (
            any(
                type(key_id) is not str
                or _KEY_ID.fullmatch(key_id) is None
                for key_id in revoked_key_ids
            )
            or revoked_key_ids != sorted(set(revoked_key_ids))
        ):
            raise IntegrityError(
                "invalid_trust_snapshot",
                "integrity trust snapshot revocations are noncanonical",
            )
        try:
            store = IntegrityTrustStore.from_keys(
                trusted_keys,
                revoked_key_ids=revoked_key_ids,
            )
        except (IntegrityError, TypeError, ValueError) as exc:
            raise IntegrityError(
                "invalid_trust_snapshot",
                "integrity trust snapshot cannot be reconstructed",
            ) from exc
        if store.to_snapshot_body() != body:
            raise IntegrityError(
                "invalid_trust_snapshot",
                "integrity trust snapshot body is not canonical",
            )
        if expected_snapshot_id is not None:
            if (
                type(expected_snapshot_id) is not str
                or _FULL_DIGEST.fullmatch(expected_snapshot_id) is None
            ):
                raise IntegrityError(
                    "invalid_trust_snapshot",
                    "expected snapshot ID must be a full sha256 content ID",
                )
            if store.snapshot_id != expected_snapshot_id:
                raise IntegrityError(
                    "trust_snapshot_mismatch",
                    "integrity trust snapshot ID does not match its canonical body",
                )
        return store

    def to_snapshot_body(self) -> dict[str, object]:
        keys = [
            {
                "key_id": key_id,
                "principal_id": trusted_key.principal_id,
                "public_key_b64": base64.b64encode(
                    trusted_key.public_key_bytes
                ).decode("ascii"),
                "role": trusted_key.role,
            }
            for key_id, trusted_key in sorted(self.keys.items())
        ]
        return {
            "keys": keys,
            "revoked_key_ids": sorted(self.revoked_key_ids),
        }

    @property
    def snapshot_id(self) -> str:
        return content_id("integrity_trust_snapshot", self.to_snapshot_body())


@dataclass(frozen=True, slots=True)
class IntegrityValidationPolicyV1:
    """Caller-owned policy reapplied at every consequential composition boundary."""

    decision_policy_id: str
    decision_time_policy_id: str
    checkpoint_time_policy_id: str
    anchor_policy_id: str
    required_revocation_namespaces: frozenset[str]
    max_decision_uncertainty_seconds: int
    max_checkpoint_uncertainty_seconds: int

    def __post_init__(self) -> None:
        for field in (
            "decision_policy_id",
            "decision_time_policy_id",
            "checkpoint_time_policy_id",
            "anchor_policy_id",
        ):
            _require_digest(getattr(self, field), field)
        namespaces = _validated_identity_set(
            self.required_revocation_namespaces,
            "required_revocation_namespaces",
            maximum=MAX_REVOCATION_VIEWS,
        )
        if not namespaces:
            raise IntegrityError(
                "missing_revocation_namespace",
                "validation policy requires at least one revocation namespace",
            )
        _require_nonnegative_int(
            self.max_decision_uncertainty_seconds,
            "max_decision_uncertainty_seconds",
        )
        _require_nonnegative_int(
            self.max_checkpoint_uncertainty_seconds,
            "max_checkpoint_uncertainty_seconds",
        )
        object.__setattr__(
            self,
            "required_revocation_namespaces",
            namespaces,
        )

    @classmethod
    def from_body(cls, body: object) -> IntegrityValidationPolicyV1:
        """Reconstruct one exact canonical integrity validation policy."""

        if (
            type(body) is not dict
            or len(body) != len(_VALIDATION_POLICY_FIELDS)
            or set(body) != _VALIDATION_POLICY_FIELDS
        ):
            raise IntegrityError(
                "invalid_validation_policy",
                "integrity validation policy has missing or unknown fields",
            )
        namespaces = body["required_revocation_namespaces"]
        if (
            type(namespaces) is not list
            or not namespaces
            or len(namespaces) > MAX_REVOCATION_VIEWS
            or any(type(namespace) is not str for namespace in namespaces)
            or namespaces != sorted(set(namespaces))
        ):
            raise IntegrityError(
                "invalid_validation_policy",
                "policy revocation namespaces must be a nonempty canonical array",
            )
        try:
            policy = IntegrityValidationPolicyV1(
                decision_policy_id=body["decision_policy_id"],
                decision_time_policy_id=body["decision_time_policy_id"],
                checkpoint_time_policy_id=body[
                    "checkpoint_time_policy_id"
                ],
                anchor_policy_id=body["anchor_policy_id"],
                required_revocation_namespaces=frozenset(namespaces),
                max_decision_uncertainty_seconds=body[
                    "max_decision_uncertainty_seconds"
                ],
                max_checkpoint_uncertainty_seconds=body[
                    "max_checkpoint_uncertainty_seconds"
                ],
            )
        except (IntegrityError, TypeError, ValueError) as exc:
            raise IntegrityError(
                "invalid_validation_policy",
                "integrity validation policy cannot be reconstructed",
            ) from exc
        if policy.to_body() != body:
            raise IntegrityError(
                "invalid_validation_policy",
                "integrity validation policy body is not canonical",
            )
        return policy

    def to_body(self) -> dict[str, object]:
        """Return one detached deterministic validation-policy body."""

        return {
            "anchor_policy_id": self.anchor_policy_id,
            "checkpoint_time_policy_id": self.checkpoint_time_policy_id,
            "decision_policy_id": self.decision_policy_id,
            "decision_time_policy_id": self.decision_time_policy_id,
            "max_checkpoint_uncertainty_seconds": (
                self.max_checkpoint_uncertainty_seconds
            ),
            "max_decision_uncertainty_seconds": (
                self.max_decision_uncertainty_seconds
            ),
            "required_revocation_namespaces": sorted(
                self.required_revocation_namespaces
            ),
        }


@dataclass(frozen=True, slots=True)
class RevocationFloorV1:
    """Adapter-verified external anti-rollback floor for one revocation namespace.

    Direct construction validates shape only.  The caller must obtain this value from a
    qualified adapter that verifies the retained external evidence references.
    """

    service_instance_id: str
    environment_id: str
    decision_policy_id: str
    namespace: str
    root_version: int
    version: int
    snapshot_id: str
    evidence: tuple[EvidenceReferenceV1, ...]

    def __post_init__(self) -> None:
        _require_identity(self.service_instance_id, "service_instance_id")
        _require_identity(self.environment_id, "environment_id")
        _require_digest(self.decision_policy_id, "decision_policy_id")
        _require_identity(self.namespace, "namespace")
        _require_positive_int(self.root_version, "root_version")
        _require_positive_int(self.version, "version")
        _require_digest(self.snapshot_id, "snapshot_id")
        object.__setattr__(
            self,
            "evidence",
            _validated_evidence_references(
                self.evidence,
                field="external_floor_evidence",
                minimum=2,
                evidence_kind=EXTERNAL_FLOOR_EVIDENCE_KIND,
            ),
        )

    @classmethod
    def from_body(cls, body: object) -> RevocationFloorV1:
        """Reconstruct one exact canonical external revocation floor."""

        if (
            type(body) is not dict
            or len(body) != len(_REVOCATION_FLOOR_FIELDS)
            or set(body) != _REVOCATION_FLOOR_FIELDS
        ):
            raise IntegrityError(
                "invalid_external_revocation_floor",
                "external revocation floor has missing or unknown fields",
            )
        evidence = body["evidence"]
        if (
            type(evidence) is not list
            or len(evidence) < 2
            or len(evidence) > MAX_EVIDENCE_REFS
        ):
            raise IntegrityError(
                "invalid_external_revocation_floor",
                "external revocation floor evidence is not a bounded quorum",
            )
        try:
            floor = RevocationFloorV1(
                service_instance_id=body["service_instance_id"],
                environment_id=body["environment_id"],
                decision_policy_id=body["decision_policy_id"],
                namespace=body["namespace"],
                root_version=body["root_version"],
                version=body["version"],
                snapshot_id=body["snapshot_id"],
                evidence=tuple(
                    EvidenceReferenceV1.from_body(reference)
                    for reference in evidence
                ),
            )
        except (IntegrityError, TypeError, ValueError) as exc:
            raise IntegrityError(
                "invalid_external_revocation_floor",
                "external revocation floor cannot be reconstructed",
            ) from exc
        if floor.to_body() != body:
            raise IntegrityError(
                "invalid_external_revocation_floor",
                "external revocation floor body is not canonical",
            )
        return floor

    def to_body(self) -> dict[str, object]:
        """Return one detached deterministic revocation-floor body."""

        return {
            "decision_policy_id": self.decision_policy_id,
            "environment_id": self.environment_id,
            "evidence": [reference.to_body() for reference in self.evidence],
            "namespace": self.namespace,
            "root_version": self.root_version,
            "service_instance_id": self.service_instance_id,
            "snapshot_id": self.snapshot_id,
            "version": self.version,
        }


@dataclass(frozen=True, slots=True)
class HeadCheckpointFloorV1:
    """Adapter-verified external instance catalog and mission-head floor.

    Sequence ``-1`` denotes the corresponding domain-separated genesis identity.
    Construction alone does not authenticate the external catalog or its evidence.
    """

    service_instance_id: str
    environment_id: str
    instance_sequence: int
    checkpoint_id: str
    checkpoint_attestation_id: str | None
    checkpoint_principal_id: str | None
    checkpoint_trust_snapshot_id: str | None
    mission_id: str
    mission_event_seq: int
    mission_checkpoint_id: str
    mission_checkpoint_attestation_id: str | None
    mission_checkpoint_principal_id: str | None
    mission_checkpoint_trust_snapshot_id: str | None
    evidence: tuple[EvidenceReferenceV1, ...]

    def __post_init__(self) -> None:
        _require_identity(self.service_instance_id, "service_instance_id")
        _require_identity(self.environment_id, "environment_id")
        for field in ("instance_sequence", "mission_event_seq"):
            value = getattr(self, field)
            if type(value) is not int or value < -1 or value > MAX_EPOCH_SECOND:
                raise IntegrityError(
                    f"invalid_{field}",
                    f"{field} must be an int64 sequence at or above -1",
                )
        _require_digest(self.checkpoint_id, "checkpoint_id")
        _require_digest(self.mission_id, "mission_id")
        _require_digest(self.mission_checkpoint_id, "mission_checkpoint_id")
        self._validate_attestation_provenance(
            sequence=self.instance_sequence,
            attestation_id=self.checkpoint_attestation_id,
            principal_id=self.checkpoint_principal_id,
            trust_snapshot_id=self.checkpoint_trust_snapshot_id,
            label="global",
        )
        self._validate_attestation_provenance(
            sequence=self.mission_event_seq,
            attestation_id=self.mission_checkpoint_attestation_id,
            principal_id=self.mission_checkpoint_principal_id,
            trust_snapshot_id=self.mission_checkpoint_trust_snapshot_id,
            label="mission",
        )
        expected_global = head_checkpoint_genesis_id(
            service_instance_id=self.service_instance_id,
            environment_id=self.environment_id,
        )
        expected_mission = mission_checkpoint_genesis_id(
            service_instance_id=self.service_instance_id,
            environment_id=self.environment_id,
            mission_id=self.mission_id,
        )
        if (
            self.instance_sequence == -1
            and self.checkpoint_id != expected_global
        ):
            raise IntegrityError(
                "external_floor_mismatch",
                "global genesis floor has the wrong checkpoint identity",
            )
        if (
            self.instance_sequence >= 0
            and self.checkpoint_id == expected_global
        ):
            raise IntegrityError(
                "external_floor_mismatch",
                "non-genesis global floor cannot use the genesis identity",
            )
        if (
            self.mission_event_seq == -1
            and self.mission_checkpoint_id != expected_mission
        ):
            raise IntegrityError(
                "external_floor_mismatch",
                "mission genesis floor has the wrong checkpoint identity",
            )
        if (
            self.mission_event_seq >= 0
            and self.mission_checkpoint_id == expected_mission
        ):
            raise IntegrityError(
                "external_floor_mismatch",
                "non-genesis mission floor cannot use the genesis identity",
            )
        if (
            self.instance_sequence == -1
            and self.mission_event_seq >= 0
        ) or (
            self.instance_sequence >= 0
            and self.mission_event_seq > self.instance_sequence
        ):
            raise IntegrityError(
                "external_floor_mismatch",
                "mission floor cannot be ahead of the instance-global floor",
            )
        if (
            self.checkpoint_id == self.mission_checkpoint_id
            and (
                self.checkpoint_attestation_id,
                self.checkpoint_principal_id,
                self.checkpoint_trust_snapshot_id,
            )
            != (
                self.mission_checkpoint_attestation_id,
                self.mission_checkpoint_principal_id,
                self.mission_checkpoint_trust_snapshot_id,
            )
        ):
            raise IntegrityError(
                "external_floor_mismatch",
                "one checkpoint identity must have one exact attestation provenance",
            )
        object.__setattr__(
            self,
            "evidence",
            _validated_evidence_references(
                self.evidence,
                field="external_floor_evidence",
                minimum=2,
                evidence_kind=EXTERNAL_FLOOR_EVIDENCE_KIND,
            ),
        )

    @classmethod
    def from_body(cls, body: object) -> HeadCheckpointFloorV1:
        """Reconstruct one exact canonical external head-catalog floor."""

        if (
            type(body) is not dict
            or len(body) != len(_HEAD_CHECKPOINT_FLOOR_FIELDS)
            or set(body) != _HEAD_CHECKPOINT_FLOOR_FIELDS
        ):
            raise IntegrityError(
                "invalid_external_head_floor",
                "external head floor has missing or unknown fields",
            )
        evidence = body["evidence"]
        if (
            type(evidence) is not list
            or len(evidence) < 2
            or len(evidence) > MAX_EVIDENCE_REFS
        ):
            raise IntegrityError(
                "invalid_external_head_floor",
                "external head floor evidence is not a bounded quorum",
            )
        try:
            floor = HeadCheckpointFloorV1(
                service_instance_id=body["service_instance_id"],
                environment_id=body["environment_id"],
                instance_sequence=body["instance_sequence"],
                checkpoint_id=body["checkpoint_id"],
                checkpoint_attestation_id=body[
                    "checkpoint_attestation_id"
                ],
                checkpoint_principal_id=body["checkpoint_principal_id"],
                checkpoint_trust_snapshot_id=body[
                    "checkpoint_trust_snapshot_id"
                ],
                mission_id=body["mission_id"],
                mission_event_seq=body["mission_event_seq"],
                mission_checkpoint_id=body["mission_checkpoint_id"],
                mission_checkpoint_attestation_id=body[
                    "mission_checkpoint_attestation_id"
                ],
                mission_checkpoint_principal_id=body[
                    "mission_checkpoint_principal_id"
                ],
                mission_checkpoint_trust_snapshot_id=body[
                    "mission_checkpoint_trust_snapshot_id"
                ],
                evidence=tuple(
                    EvidenceReferenceV1.from_body(reference)
                    for reference in evidence
                ),
            )
        except (IntegrityError, TypeError, ValueError) as exc:
            raise IntegrityError(
                "invalid_external_head_floor",
                "external head floor cannot be reconstructed",
            ) from exc
        if floor.to_body() != body:
            raise IntegrityError(
                "invalid_external_head_floor",
                "external head floor body is not canonical",
            )
        return floor

    def to_body(self) -> dict[str, object]:
        """Return one detached deterministic external-head-floor body."""

        return {
            "checkpoint_attestation_id": self.checkpoint_attestation_id,
            "checkpoint_id": self.checkpoint_id,
            "checkpoint_principal_id": self.checkpoint_principal_id,
            "checkpoint_trust_snapshot_id": (
                self.checkpoint_trust_snapshot_id
            ),
            "environment_id": self.environment_id,
            "evidence": [reference.to_body() for reference in self.evidence],
            "instance_sequence": self.instance_sequence,
            "mission_checkpoint_attestation_id": (
                self.mission_checkpoint_attestation_id
            ),
            "mission_checkpoint_id": self.mission_checkpoint_id,
            "mission_checkpoint_principal_id": (
                self.mission_checkpoint_principal_id
            ),
            "mission_checkpoint_trust_snapshot_id": (
                self.mission_checkpoint_trust_snapshot_id
            ),
            "mission_event_seq": self.mission_event_seq,
            "mission_id": self.mission_id,
            "service_instance_id": self.service_instance_id,
        }

    @staticmethod
    def _validate_attestation_provenance(
        *,
        sequence: int,
        attestation_id: str | None,
        principal_id: str | None,
        trust_snapshot_id: str | None,
        label: str,
    ) -> None:
        values = (attestation_id, principal_id, trust_snapshot_id)
        if sequence == -1:
            if any(value is not None for value in values):
                raise IntegrityError(
                    "external_floor_mismatch",
                    f"{label} genesis cannot claim checkpoint attestation provenance",
                )
            return
        if any(value is None for value in values):
            raise IntegrityError(
                "external_floor_mismatch",
                f"{label} checkpoint floor requires complete attestation provenance",
            )
        _require_digest(attestation_id, f"{label}_checkpoint_attestation_id")
        _require_identity(principal_id, f"{label}_checkpoint_principal_id")
        _require_digest(
            trust_snapshot_id,
            f"{label}_checkpoint_trust_snapshot_id",
        )


@dataclass(frozen=True, slots=True, init=False)
class AuthenticatedIntegrityDecisionV1:
    """Sealed authentication result, without any external-provider claim."""

    signed_decision: SignedIntegrityDecisionV1
    decision: IntegrityDecisionV1
    signer_principal_id: str
    trust_snapshot_id: str
    _authentication_seal: object

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise IntegrityError(
            "unauthenticated_result_construction",
            "authenticated decisions are created only by the authentication boundary",
        )

    @classmethod
    def _from_authentication(
        cls,
        signed_decision: SignedIntegrityDecisionV1,
        decision: IntegrityDecisionV1,
        signer_principal_id: str,
        trust_snapshot_id: str,
        *,
        seal: object,
    ) -> AuthenticatedIntegrityDecisionV1:
        if seal is not _AUTHENTICATED_RESULT_SEAL:
            raise IntegrityError(
                "unauthenticated_result_construction",
                "authenticated decision seal is invalid",
            )
        instance = object.__new__(cls)
        object.__setattr__(instance, "signed_decision", signed_decision)
        object.__setattr__(instance, "decision", decision)
        object.__setattr__(
            instance,
            "signer_principal_id",
            signer_principal_id,
        )
        object.__setattr__(instance, "trust_snapshot_id", trust_snapshot_id)
        object.__setattr__(instance, "_authentication_seal", seal)
        instance.__post_init__()
        return instance

    def __post_init__(self) -> None:
        if (
            type(self.signed_decision) is not SignedIntegrityDecisionV1
            or type(self.decision) is not IntegrityDecisionV1
            or self.signed_decision.envelope_bytes
            != self.decision.to_envelope().to_bytes()
        ):
            raise IntegrityError(
                "invalid_authenticated_decision",
                "authenticated decision material is incoherent",
            )
        _require_identity(self.signer_principal_id, "signer_principal_id")
        _require_digest(self.trust_snapshot_id, "trust_snapshot_id")


@dataclass(frozen=True, slots=True, init=False)
class AuthenticatedHeadCheckpointV1:
    """Sealed checkpoint-authentication result, not proof of external retention."""

    signed_checkpoint: SignedHeadCheckpointV1
    checkpoint: HeadCheckpointV1
    signer_principal_id: str
    trust_snapshot_id: str
    _authentication_seal: object

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise IntegrityError(
            "unauthenticated_result_construction",
            "authenticated checkpoints are created only by the authentication boundary",
        )

    @classmethod
    def _from_authentication(
        cls,
        signed_checkpoint: SignedHeadCheckpointV1,
        checkpoint: HeadCheckpointV1,
        signer_principal_id: str,
        trust_snapshot_id: str,
        *,
        seal: object,
    ) -> AuthenticatedHeadCheckpointV1:
        if seal is not _AUTHENTICATED_RESULT_SEAL:
            raise IntegrityError(
                "unauthenticated_result_construction",
                "authenticated checkpoint seal is invalid",
            )
        instance = object.__new__(cls)
        object.__setattr__(instance, "signed_checkpoint", signed_checkpoint)
        object.__setattr__(instance, "checkpoint", checkpoint)
        object.__setattr__(
            instance,
            "signer_principal_id",
            signer_principal_id,
        )
        object.__setattr__(instance, "trust_snapshot_id", trust_snapshot_id)
        object.__setattr__(instance, "_authentication_seal", seal)
        instance.__post_init__()
        return instance

    def __post_init__(self) -> None:
        if (
            type(self.signed_checkpoint) is not SignedHeadCheckpointV1
            or type(self.checkpoint) is not HeadCheckpointV1
            or self.signed_checkpoint.envelope_bytes
            != self.checkpoint.to_envelope().to_bytes()
        ):
            raise IntegrityError(
                "invalid_authenticated_checkpoint",
                "authenticated checkpoint material is incoherent",
            )
        _require_identity(self.signer_principal_id, "signer_principal_id")
        _require_digest(self.trust_snapshot_id, "trust_snapshot_id")


def integrity_key_id(public_key_bytes: bytes) -> str:
    """Derive the only accepted integrity-key identity."""

    if type(public_key_bytes) is not bytes or len(public_key_bytes) != 32:
        raise IntegrityError(
            "invalid_public_key",
            "Ed25519 public keys must contain exactly 32 bytes",
        )
    return "ed25519:sha256:" + hashlib.sha256(public_key_bytes).hexdigest()


def _snapshot_trust_store(value: object) -> IntegrityTrustStore:
    """Copy one exact constructed trust store before consequential use."""

    if type(value) is not IntegrityTrustStore:
        raise IntegrityError(
            "invalid_trust_store",
            "trust_store must be an exact constructed IntegrityTrustStore",
        )
    try:
        keys = value.keys
        revoked_key_ids = value.revoked_key_ids
    except AttributeError as exc:
        raise IntegrityError(
            "invalid_trust_store",
            "trust_store is missing constructed integrity material",
        ) from exc
    if (
        type(keys) is not MappingProxyType
        or type(revoked_key_ids) is not frozenset
    ):
        raise IntegrityError(
            "invalid_trust_store",
            "trust_store must contain immutable constructed integrity material",
        )
    try:
        return IntegrityTrustStore(
            keys,
            revoked_key_ids,
        )
    except (IntegrityError, TypeError, ValueError) as exc:
        raise IntegrityError(
            "invalid_trust_store",
            "trust_store contains invalid integrity material",
        ) from exc


def authenticate_integrity_decision(
    raw_signed_decision: SignedIntegrityDecisionV1 | bytes | str,
    trust_store: IntegrityTrustStore,
    *,
    forbidden_key_ids: Iterable[str],
    expected_service_instance_id: str,
    expected_environment_id: str,
    expected_mission_id: str,
    expected_authority_id: str,
    expected_target_id: str,
    expected_prior_global_checkpoint_sequence: int,
    expected_prior_global_checkpoint_id: str,
    expected_prior_global_checkpoint_attestation_id: str | None,
    expected_prior_global_checkpoint_principal_id: str | None,
    expected_prior_global_checkpoint_trust_snapshot_id: str | None,
    expected_prior_event_seq: int,
    expected_prior_event_digest: str,
    expected_event_kind: str,
    expected_proposed_event_digest: str,
    expected_transition_intent_id: str,
    expected_request_nonce: str,
    expected_time_policy_id: str,
    expected_decision_policy_id: str,
    required_revocation_namespaces: Iterable[str],
    max_time_uncertainty_seconds: int,
) -> AuthenticatedIntegrityDecisionV1:
    """Authenticate one exact pre-transition decision and its conservative interval."""

    trust_store = _snapshot_trust_store(trust_store)
    supplied_signed = _coerce_signed_decision(raw_signed_decision)
    signed = _snapshot_signed_decision(supplied_signed)
    trusted_key = _authenticate_signed(
        signed.envelope_bytes,
        signed.key_id,
        signed.signature_b64,
        trust_store,
        role=INTEGRITY_DECISION_ROLE,
        signature_domain=_DECISION_SIGNATURE_DOMAIN,
        forbidden_key_ids=forbidden_key_ids,
    )
    try:
        decision = IntegrityDecisionV1.from_envelope(
            EnvelopeV1.from_bytes(signed.envelope_bytes)
        )
    except (ProtocolError, IntegrityError, TypeError) as exc:
        raise IntegrityError(
            "invalid_integrity_decision",
            "signed integrity decision is semantically invalid",
        ) from exc

    _check_expected(decision.service_instance_id, expected_service_instance_id, "service_instance")
    _check_expected(decision.environment_id, expected_environment_id, "environment")
    _check_expected(decision.mission_id, expected_mission_id, "mission")
    _check_expected(decision.authority_id, expected_authority_id, "authority")
    _check_expected(decision.target_id, expected_target_id, "target")
    _check_expected(
        decision.prior_global_checkpoint_sequence,
        expected_prior_global_checkpoint_sequence,
        "prior_global_checkpoint_sequence",
    )
    _check_expected(
        decision.prior_global_checkpoint_id,
        expected_prior_global_checkpoint_id,
        "prior_global_checkpoint_id",
    )
    _check_expected(
        decision.prior_global_checkpoint_attestation_id,
        expected_prior_global_checkpoint_attestation_id,
        "prior_global_checkpoint_attestation_id",
    )
    _check_expected(
        decision.prior_global_checkpoint_principal_id,
        expected_prior_global_checkpoint_principal_id,
        "prior_global_checkpoint_principal_id",
    )
    _check_expected(
        decision.prior_global_checkpoint_trust_snapshot_id,
        expected_prior_global_checkpoint_trust_snapshot_id,
        "prior_global_checkpoint_trust_snapshot_id",
    )
    _check_expected(decision.prior_event_seq, expected_prior_event_seq, "prior_event_seq")
    _check_expected(
        decision.prior_event_digest,
        expected_prior_event_digest,
        "prior_event_digest",
    )
    _check_expected(decision.event_kind, expected_event_kind, "event_kind")
    _check_expected(
        decision.proposed_event_digest,
        expected_proposed_event_digest,
        "proposed_event_digest",
    )
    _check_expected(
        decision.transition_intent_id,
        expected_transition_intent_id,
        "transition_intent",
    )
    _check_expected(decision.request_nonce, expected_request_nonce, "request_nonce")
    _check_expected(
        decision.time_policy_id,
        expected_time_policy_id,
        "time_policy",
    )
    _check_expected(
        decision.decision_policy_id,
        expected_decision_policy_id,
        "decision_policy",
    )
    _require_max_uncertainty(
        decision.time_lower_bound,
        decision.time_upper_bound,
        max_time_uncertainty_seconds,
    )
    required_namespaces = _validated_identity_set(
        required_revocation_namespaces,
        "required_revocation_namespaces",
        maximum=MAX_REVOCATION_VIEWS,
    )
    if not required_namespaces:
        raise IntegrityError(
            "missing_revocation_namespace",
            "consequential integrity decisions require a revocation namespace",
        )
    observed_namespaces = {view.namespace for view in decision.revocation_views}
    missing = sorted(required_namespaces - observed_namespaces)
    if missing:
        raise IntegrityError(
            "missing_revocation_namespace",
            "integrity decision lacks required revocation namespaces: "
            + ", ".join(missing),
        )
    return AuthenticatedIntegrityDecisionV1._from_authentication(
        signed,
        decision,
        trusted_key.principal_id,
        trust_store.snapshot_id,
        seal=_AUTHENTICATED_RESULT_SEAL,
    )


def authenticate_head_checkpoint(
    raw_signed_checkpoint: SignedHeadCheckpointV1 | bytes | str,
    trust_store: IntegrityTrustStore,
    *,
    forbidden_key_ids: Iterable[str],
    forbidden_principal_ids: Iterable[str],
    expected_service_instance_id: str,
    expected_environment_id: str,
    expected_time_policy_id: str,
    expected_anchor_policy_id: str,
    expected_anchor_statement_id: str,
    max_time_uncertainty_seconds: int,
) -> AuthenticatedHeadCheckpointV1:
    """Authenticate one exact checkpoint statement under a distinct checkpoint role."""

    trust_store = _snapshot_trust_store(trust_store)
    supplied_signed = _coerce_signed_checkpoint(raw_signed_checkpoint)
    signed = _snapshot_signed_checkpoint(supplied_signed)
    trusted_key = _authenticate_signed(
        signed.envelope_bytes,
        signed.key_id,
        signed.signature_b64,
        trust_store,
        role=HEAD_CHECKPOINT_ROLE,
        signature_domain=_CHECKPOINT_SIGNATURE_DOMAIN,
        forbidden_key_ids=forbidden_key_ids,
    )
    forbidden_principals = _validated_identity_set(
        forbidden_principal_ids,
        "forbidden_principal_ids",
        maximum=MAX_INTEGRITY_KEYS,
    )
    if trusted_key.principal_id in forbidden_principals:
        raise IntegrityError(
            "principal_separation_violation",
            "checkpoint signer principal is forbidden for this decision",
        )
    try:
        checkpoint = HeadCheckpointV1.from_envelope(
            EnvelopeV1.from_bytes(signed.envelope_bytes)
        )
    except (ProtocolError, IntegrityError, TypeError) as exc:
        raise IntegrityError(
            "invalid_head_checkpoint",
            "signed head checkpoint is semantically invalid",
        ) from exc
    _check_expected(
        checkpoint.service_instance_id,
        expected_service_instance_id,
        "service_instance",
    )
    _check_expected(
        checkpoint.environment_id,
        expected_environment_id,
        "environment",
    )
    _check_expected(
        checkpoint.time_policy_id,
        expected_time_policy_id,
        "time_policy",
    )
    _check_expected(
        checkpoint.anchor_policy_id,
        expected_anchor_policy_id,
        "anchor_policy",
    )
    _check_expected(
        checkpoint.anchor_statement_id,
        expected_anchor_statement_id,
        "anchor_statement",
    )
    _require_max_uncertainty(
        checkpoint.time_lower_bound,
        checkpoint.time_upper_bound,
        max_time_uncertainty_seconds,
    )
    return AuthenticatedHeadCheckpointV1._from_authentication(
        signed,
        checkpoint,
        trusted_key.principal_id,
        trust_store.snapshot_id,
        seal=_AUTHENTICATED_RESULT_SEAL,
    )


def _reauthenticate_decision_result(
    value: AuthenticatedIntegrityDecisionV1,
    trust_store: IntegrityTrustStore,
) -> AuthenticatedIntegrityDecisionV1:
    """Reverify and snapshot a purported result at a consequential boundary."""

    if (
        type(value) is not AuthenticatedIntegrityDecisionV1
        or getattr(value, "_authentication_seal", None)
        is not _AUTHENTICATED_RESULT_SEAL
        or type(getattr(value, "signed_decision", None))
        is not SignedIntegrityDecisionV1
        or type(getattr(value, "decision", None))
        is not IntegrityDecisionV1
        or type(getattr(value, "signer_principal_id", None)) is not str
        or type(getattr(value, "trust_snapshot_id", None)) is not str
        or type(trust_store) is not IntegrityTrustStore
    ):
        raise IntegrityError(
            "invalid_authenticated_decision",
            "decision result and historical trust store are required",
        )
    trust_store = _snapshot_trust_store(trust_store)
    claimed_signed = getattr(value, "signed_decision", None)
    claimed_decision = getattr(value, "decision", None)
    claimed_principal_id = getattr(value, "signer_principal_id", None)
    claimed_trust_snapshot_id = getattr(value, "trust_snapshot_id", None)
    try:
        signed = _snapshot_signed_decision(claimed_signed)
    except IntegrityError as exc:
        raise IntegrityError(
            "invalid_authenticated_decision",
            "authenticated decision transport is malformed",
        ) from exc
    trusted_key = _authenticate_signed(
        signed.envelope_bytes,
        signed.key_id,
        signed.signature_b64,
        trust_store,
        role=INTEGRITY_DECISION_ROLE,
        signature_domain=_DECISION_SIGNATURE_DOMAIN,
        forbidden_key_ids=(),
    )
    try:
        parsed = IntegrityDecisionV1.from_envelope(
            EnvelopeV1.from_bytes(signed.envelope_bytes)
        )
        claimed_value = _snapshot_integrity_decision_value(
            claimed_decision
        )
    except (
        AttributeError,
        ProtocolError,
        IntegrityError,
        TypeError,
        ValueError,
    ) as exc:
        raise IntegrityError(
            "invalid_authenticated_decision",
            "authenticated decision semantics are invalid",
        ) from exc
    if (
        parsed != claimed_value
        or trusted_key.principal_id != claimed_principal_id
        or trust_store.snapshot_id != claimed_trust_snapshot_id
    ):
        raise IntegrityError(
            "invalid_authenticated_decision",
            "decision result does not match its verified signer or trust snapshot",
        )
    return AuthenticatedIntegrityDecisionV1._from_authentication(
        signed,
        parsed,
        trusted_key.principal_id,
        trust_store.snapshot_id,
        seal=_AUTHENTICATED_RESULT_SEAL,
    )


def _reauthenticate_checkpoint_result(
    value: AuthenticatedHeadCheckpointV1,
    trust_store: IntegrityTrustStore,
) -> AuthenticatedHeadCheckpointV1:
    """Reverify and snapshot a purported checkpoint at a consequential boundary."""

    if (
        type(value) is not AuthenticatedHeadCheckpointV1
        or getattr(value, "_authentication_seal", None)
        is not _AUTHENTICATED_RESULT_SEAL
        or type(getattr(value, "signed_checkpoint", None))
        is not SignedHeadCheckpointV1
        or type(getattr(value, "checkpoint", None))
        is not HeadCheckpointV1
        or type(getattr(value, "signer_principal_id", None)) is not str
        or type(getattr(value, "trust_snapshot_id", None)) is not str
        or type(trust_store) is not IntegrityTrustStore
    ):
        raise IntegrityError(
            "invalid_authenticated_checkpoint",
            "checkpoint result and historical trust store are required",
        )
    trust_store = _snapshot_trust_store(trust_store)
    claimed_signed = getattr(value, "signed_checkpoint", None)
    claimed_checkpoint = getattr(value, "checkpoint", None)
    claimed_principal_id = getattr(value, "signer_principal_id", None)
    claimed_trust_snapshot_id = getattr(value, "trust_snapshot_id", None)
    try:
        signed = _snapshot_signed_checkpoint(claimed_signed)
    except IntegrityError as exc:
        raise IntegrityError(
            "invalid_authenticated_checkpoint",
            "authenticated checkpoint transport is malformed",
        ) from exc
    trusted_key = _authenticate_signed(
        signed.envelope_bytes,
        signed.key_id,
        signed.signature_b64,
        trust_store,
        role=HEAD_CHECKPOINT_ROLE,
        signature_domain=_CHECKPOINT_SIGNATURE_DOMAIN,
        forbidden_key_ids=(),
    )
    try:
        parsed = HeadCheckpointV1.from_envelope(
            EnvelopeV1.from_bytes(signed.envelope_bytes)
        )
        claimed_value = _snapshot_head_checkpoint_value(
            claimed_checkpoint
        )
    except (
        AttributeError,
        ProtocolError,
        IntegrityError,
        TypeError,
        ValueError,
    ) as exc:
        raise IntegrityError(
            "invalid_authenticated_checkpoint",
            "authenticated checkpoint semantics are invalid",
        ) from exc
    if (
        parsed != claimed_value
        or trusted_key.principal_id != claimed_principal_id
        or trust_store.snapshot_id != claimed_trust_snapshot_id
    ):
        raise IntegrityError(
            "invalid_authenticated_checkpoint",
            "checkpoint result does not match its verified signer or trust snapshot",
        )
    return AuthenticatedHeadCheckpointV1._from_authentication(
        signed,
        parsed,
        trusted_key.principal_id,
        trust_store.snapshot_id,
        seal=_AUTHENTICATED_RESULT_SEAL,
    )


def _snapshot_validation_policy(
    value: object,
) -> IntegrityValidationPolicyV1:
    """Copy one exact caller policy before applying it to multiple inputs."""

    if type(value) is not IntegrityValidationPolicyV1:
        raise IntegrityError(
            "invalid_validation_policy",
            "a typed integrity validation policy is required",
        )
    try:
        return IntegrityValidationPolicyV1(
            decision_policy_id=value.decision_policy_id,
            decision_time_policy_id=value.decision_time_policy_id,
            checkpoint_time_policy_id=value.checkpoint_time_policy_id,
            anchor_policy_id=value.anchor_policy_id,
            required_revocation_namespaces=(
                value.required_revocation_namespaces
            ),
            max_decision_uncertainty_seconds=(
                value.max_decision_uncertainty_seconds
            ),
            max_checkpoint_uncertainty_seconds=(
                value.max_checkpoint_uncertainty_seconds
            ),
        )
    except (AttributeError, IntegrityError, TypeError) as exc:
        raise IntegrityError(
            "invalid_validation_policy",
            "integrity validation policy is malformed",
        ) from exc


def _snapshot_revocation_floor(
    value: object,
) -> RevocationFloorV1:
    """Rebuild one adapter floor and its nested evidence before comparison."""

    if type(value) is not RevocationFloorV1:
        raise IntegrityError(
            "invalid_external_revocation_floor",
            "an exact external revocation floor is required",
        )
    try:
        return RevocationFloorV1(
            service_instance_id=value.service_instance_id,
            environment_id=value.environment_id,
            decision_policy_id=value.decision_policy_id,
            namespace=value.namespace,
            root_version=value.root_version,
            version=value.version,
            snapshot_id=value.snapshot_id,
            evidence=value.evidence,
        )
    except (AttributeError, IntegrityError, TypeError, ValueError) as exc:
        raise IntegrityError(
            "invalid_external_revocation_floor",
            "external revocation floor is malformed",
        ) from exc


def _snapshot_head_checkpoint_floor(
    value: object,
) -> HeadCheckpointFloorV1:
    """Rebuild one external catalog floor and its nested evidence."""

    if type(value) is not HeadCheckpointFloorV1:
        raise IntegrityError(
            "invalid_external_head_floor",
            "an exact external head floor is required",
        )
    try:
        return HeadCheckpointFloorV1(
            service_instance_id=value.service_instance_id,
            environment_id=value.environment_id,
            instance_sequence=value.instance_sequence,
            checkpoint_id=value.checkpoint_id,
            checkpoint_attestation_id=value.checkpoint_attestation_id,
            checkpoint_principal_id=value.checkpoint_principal_id,
            checkpoint_trust_snapshot_id=(
                value.checkpoint_trust_snapshot_id
            ),
            mission_id=value.mission_id,
            mission_event_seq=value.mission_event_seq,
            mission_checkpoint_id=value.mission_checkpoint_id,
            mission_checkpoint_attestation_id=(
                value.mission_checkpoint_attestation_id
            ),
            mission_checkpoint_principal_id=(
                value.mission_checkpoint_principal_id
            ),
            mission_checkpoint_trust_snapshot_id=(
                value.mission_checkpoint_trust_snapshot_id
            ),
            evidence=value.evidence,
        )
    except (AttributeError, IntegrityError, TypeError, ValueError) as exc:
        raise IntegrityError(
            "invalid_external_head_floor",
            "external head floor is malformed",
        ) from exc


def _snapshot_event(value: object) -> object:
    """Rebuild one exact EventV1 so every field and payload is revalidated."""

    from etzio.kernel.events_v1 import EventV1

    if type(value) is not EventV1:
        raise IntegrityError(
            "invalid_checkpoint_binding",
            "checkpoint binding requires one exact canonical event",
        )
    try:
        return EventV1(
            protocol_version=value.protocol_version,
            event_version=value.event_version,
            mission_id=value.mission_id,
            seq=value.seq,
            kind=value.kind,
            unit=value.unit,
            authority_id=value.authority_id,
            target_id=value.target_id,
            decision_time=value.decision_time,
            payload_bytes=value.payload_bytes,
            prev_digest=value.prev_digest,
            event_digest=value.event_digest,
        )
    except (AttributeError, ProtocolError, TypeError, ValueError) as exc:
        raise IntegrityError(
            "invalid_checkpoint_binding",
            "checkpoint binding event is not canonical",
        ) from exc


def _validate_decision_against_policy(
    decision: IntegrityDecisionV1,
    policy: IntegrityValidationPolicyV1,
) -> None:
    """Reapply caller-owned eligibility policy after cryptographic authentication."""

    if type(policy) is not IntegrityValidationPolicyV1:
        raise IntegrityError(
            "invalid_validation_policy",
            "a typed integrity validation policy is required",
        )
    _check_expected(
        decision.decision_policy_id,
        policy.decision_policy_id,
        "decision_policy",
    )
    _check_expected(
        decision.time_policy_id,
        policy.decision_time_policy_id,
        "time_policy",
    )
    _require_max_uncertainty(
        decision.time_lower_bound,
        decision.time_upper_bound,
        policy.max_decision_uncertainty_seconds,
    )
    observed_namespaces = {
        view.namespace for view in decision.revocation_views
    }
    missing = sorted(
        policy.required_revocation_namespaces - observed_namespaces
    )
    if missing:
        raise IntegrityError(
            "missing_revocation_namespace",
            "integrity decision lacks policy-required revocation namespaces: "
            + ", ".join(missing),
        )


def _validate_checkpoint_against_policy(
    checkpoint: HeadCheckpointV1,
    policy: IntegrityValidationPolicyV1,
) -> None:
    """Reapply caller-owned checkpoint eligibility policy after authentication."""

    if type(policy) is not IntegrityValidationPolicyV1:
        raise IntegrityError(
            "invalid_validation_policy",
            "a typed integrity validation policy is required",
        )
    _check_expected(
        checkpoint.time_policy_id,
        policy.checkpoint_time_policy_id,
        "time_policy",
    )
    _check_expected(
        checkpoint.anchor_policy_id,
        policy.anchor_policy_id,
        "anchor_policy",
    )
    _require_max_uncertainty(
        checkpoint.time_lower_bound,
        checkpoint.time_upper_bound,
        policy.max_checkpoint_uncertainty_seconds,
    )


def require_interval_within(
    decision: IntegrityDecisionV1,
    *,
    not_before: int,
    expires_at: int,
) -> None:
    """Require the whole trusted interval inside a half-open validity window."""

    if type(decision) is not IntegrityDecisionV1:
        raise IntegrityError(
            "invalid_integrity_decision",
            "decision must be an IntegrityDecisionV1",
        )
    lower = getattr(decision, "time_lower_bound", None)
    upper = getattr(decision, "time_upper_bound", None)
    _validate_time_interval(lower, upper)
    _require_epoch(not_before, "not_before")
    _require_epoch(expires_at, "expires_at")
    if not_before >= expires_at:
        raise IntegrityError(
            "invalid_validity_window",
            "validity window must be nonempty and half-open",
        )
    _require_interval_within(
        lower,
        upper,
        not_before,
        expires_at,
        prefix="decision",
    )


def classify_deadline(
    *,
    time_lower_bound: int,
    time_upper_bound: int,
    deadline: int,
) -> Literal["before", "at_or_after"]:
    """Classify a deadline only when the complete interval lies on one side."""

    _validate_time_interval(time_lower_bound, time_upper_bound)
    _require_epoch(deadline, "deadline")
    if time_upper_bound < deadline:
        return "before"
    if time_lower_bound >= deadline:
        return "at_or_after"
    raise IntegrityError(
        "time_interval_straddles_deadline",
        "trusted time uncertainty crosses the consequential deadline",
    )


def validate_revocation_advance(
    previous_global_decision: AuthenticatedIntegrityDecisionV1 | None,
    current: AuthenticatedIntegrityDecisionV1,
    *,
    previous_global_decision_trust_store: IntegrityTrustStore | None,
    previous_global_checkpoint: AuthenticatedHeadCheckpointV1 | None,
    previous_global_checkpoint_trust_store: IntegrityTrustStore | None,
    current_trust_store: IntegrityTrustStore,
    external_floors: tuple[RevocationFloorV1, ...],
    validation_policy: IntegrityValidationPolicyV1,
) -> None:
    """Reject local or externally retained revocation rollback and mutation."""

    if (
        previous_global_decision is not None
        and type(previous_global_decision)
        is not AuthenticatedIntegrityDecisionV1
    ) or type(current) is not AuthenticatedIntegrityDecisionV1:
        raise IntegrityError(
            "invalid_integrity_decision",
            "revocation continuity requires authenticated integrity decisions",
        )
    validation_policy = _snapshot_validation_policy(validation_policy)
    current = _reauthenticate_decision_result(current, current_trust_store)
    _validate_decision_against_policy(current.decision, validation_policy)
    if previous_global_decision is None:
        if (
            previous_global_decision_trust_store is not None
            or previous_global_checkpoint is not None
            or previous_global_checkpoint_trust_store is not None
        ):
            raise IntegrityError(
                "invalid_trust_store",
                "genesis revocation validation cannot claim a previous global head",
            )
        if current.decision.prior_global_checkpoint_sequence != -1:
            raise IntegrityError(
                "previous_global_checkpoint_missing",
                "non-genesis decision requires its exact previous global checkpoint",
            )
    else:
        if (
            type(previous_global_decision_trust_store)
            is not IntegrityTrustStore
            or type(previous_global_checkpoint)
            is not AuthenticatedHeadCheckpointV1
            or type(previous_global_checkpoint_trust_store)
            is not IntegrityTrustStore
        ):
            raise IntegrityError(
                "invalid_trust_store",
                "previous global decision and checkpoint require exact trust stores",
            )
        previous_global_decision = _reauthenticate_decision_result(
            previous_global_decision,
            previous_global_decision_trust_store,
        )
        _validate_decision_against_policy(
            previous_global_decision.decision,
            validation_policy,
        )
        previous_global_checkpoint = _reauthenticate_checkpoint_result(
            previous_global_checkpoint,
            previous_global_checkpoint_trust_store,
        )
        _validate_checkpoint_against_policy(
            previous_global_checkpoint.checkpoint,
            validation_policy,
        )
        if (
            previous_global_checkpoint.signer_principal_id
            == previous_global_decision.signer_principal_id
            or previous_global_checkpoint.signed_checkpoint.key_id
            == previous_global_decision.signed_decision.key_id
        ):
            raise IntegrityError(
                "principal_separation_violation",
                "previous decision and checkpoint must have distinct principals",
            )
        if not _checkpoint_binds_decision_provenance(
            previous_global_checkpoint.checkpoint,
            previous_global_decision,
        ):
            raise IntegrityError(
                "previous_global_decision_mismatch",
                "previous decision is not the one retained by the global checkpoint",
            )
        _validate_checkpoint_decision_semantics(
            previous_global_checkpoint.checkpoint,
            previous_global_decision,
        )
        if (
            current.decision.prior_global_checkpoint_sequence
            != previous_global_checkpoint.checkpoint.instance_sequence
            or not _checkpoint_reference_matches(
                checkpoint_id=(
                    current.decision.prior_global_checkpoint_id
                ),
                attestation_id=(
                    current.decision.prior_global_checkpoint_attestation_id
                ),
                principal_id=(
                    current.decision.prior_global_checkpoint_principal_id
                ),
                trust_snapshot_id=(
                    current.decision.prior_global_checkpoint_trust_snapshot_id
                ),
                checkpoint=previous_global_checkpoint,
            )
        ):
            raise IntegrityError(
                "current_global_predecessor_mismatch",
                "current decision does not extend the supplied previous global checkpoint",
            )
        _require_decision_follows_checkpoint(
            current.decision,
            previous_global_checkpoint.checkpoint,
        )
    if (
        type(external_floors) is not tuple
        or not external_floors
        or len(external_floors) > MAX_REVOCATION_VIEWS
        or any(
            type(floor) is not RevocationFloorV1
            for floor in external_floors
        )
    ):
        raise IntegrityError(
            "missing_external_revocation_floor",
            "revocation continuity requires typed external floors",
        )
    external_floors = tuple(
        _snapshot_revocation_floor(floor) for floor in external_floors
    )
    canonical_floors = tuple(
        sorted(external_floors, key=lambda floor: floor.namespace)
    )
    namespaces = [floor.namespace for floor in canonical_floors]
    if (
        external_floors != canonical_floors
        or len(set(namespaces)) != len(namespaces)
    ):
        raise IntegrityError(
            "invalid_external_revocation_floor",
            "external revocation floors must be namespace-sorted and unique",
        )
    current_value = current.decision
    if any(
        floor.service_instance_id != current_value.service_instance_id
        or floor.environment_id != current_value.environment_id
        or floor.decision_policy_id != current_value.decision_policy_id
        for floor in external_floors
    ):
        raise IntegrityError(
            "external_revocation_floor_scope_mismatch",
            "external revocation floor belongs to another service or policy scope",
        )
    floor_by_namespace = {
        floor.namespace: floor for floor in external_floors
    }
    current_views = {
        view.namespace: view for view in current_value.revocation_views
    }
    missing_floors = sorted(set(current_views) - set(floor_by_namespace))
    unexpected_floors = sorted(set(floor_by_namespace) - set(current_views))
    if missing_floors or unexpected_floors:
        details = []
        if missing_floors:
            details.append("missing " + ", ".join(missing_floors))
        if unexpected_floors:
            details.append("unexpected " + ", ".join(unexpected_floors))
        raise IntegrityError(
            "external_revocation_floor_set_mismatch",
            "external revocation floor namespaces differ: " + "; ".join(details),
        )
    if previous_global_decision is None:
        _validate_current_revocation_against_external_floors(
            current_views,
            floor_by_namespace,
        )
        return
    previous_value = previous_global_decision.decision
    if (
        previous_value.service_instance_id != current_value.service_instance_id
        or previous_value.environment_id != current_value.environment_id
    ):
        raise IntegrityError(
            "integrity_scope_mismatch",
            "revocation decisions belong to different service scopes",
        )
    previous_views = {
        view.namespace: view for view in previous_value.revocation_views
    }
    missing = sorted(set(previous_views) - set(current_views))
    if missing:
        raise IntegrityError(
            "revocation_namespace_removed",
            "revocation namespaces cannot disappear: " + ", ".join(missing),
        )
    for namespace, prior in previous_views.items():
        candidate = current_views[namespace]
        if candidate.root_version < prior.root_version:
            raise IntegrityError(
                "revocation_root_rollback",
                f"revocation root version regressed for {namespace!r}",
            )
        if candidate.version < prior.version:
            raise IntegrityError(
                "revocation_version_rollback",
                f"revocation version regressed for {namespace!r}",
            )
        if candidate.version == prior.version and candidate != prior:
            raise IntegrityError(
                "revocation_same_version_mutation",
                f"revocation version changed bytes for {namespace!r}",
            )
        floor = floor_by_namespace[namespace]
        if (
            floor.root_version < prior.root_version
            or floor.version < prior.version
        ):
            raise IntegrityError(
                "external_revocation_floor_rollback",
                f"external revocation floor is behind retained history for {namespace!r}",
            )
        if floor.version == prior.version and (
            floor.root_version != prior.root_version
            or floor.snapshot_id != prior.snapshot_id
        ):
            raise IntegrityError(
                "external_revocation_equivocation",
                f"external floor rewrites retained revocation state for {namespace!r}",
            )
    _validate_current_revocation_against_external_floors(
        current_views,
        floor_by_namespace,
    )


def _validate_current_revocation_against_external_floors(
    current_views: Mapping[str, RevocationViewV1],
    floor_by_namespace: Mapping[str, RevocationFloorV1],
) -> None:
    for namespace, view in current_views.items():
        floor = floor_by_namespace[namespace]
        if view.root_version < floor.root_version:
            raise IntegrityError(
                "external_revocation_root_rollback",
                f"revocation root is below the external floor for {namespace!r}",
            )
        if view.version < floor.version:
            raise IntegrityError(
                "external_revocation_version_rollback",
                f"revocation version is below the external floor for {namespace!r}",
            )
        if (
            view.version == floor.version
            and view.snapshot_id != floor.snapshot_id
        ):
            raise IntegrityError(
                "external_revocation_equivocation",
                f"revocation snapshot differs at the external floor for {namespace!r}",
            )


def head_checkpoint_genesis_id(
    *,
    service_instance_id: str,
    environment_id: str,
) -> str:
    """Derive the fixed predecessor for an instance-global checkpoint chain."""

    _require_identity(service_instance_id, "service_instance_id")
    _require_identity(environment_id, "environment_id")
    return content_id(
        "head_checkpoint_genesis",
        {
            "environment_id": environment_id,
            "service_instance_id": service_instance_id,
        },
    )


def mission_checkpoint_genesis_id(
    *,
    service_instance_id: str,
    environment_id: str,
    mission_id: str,
) -> str:
    """Derive the fixed predecessor for one mission's checkpoint lineage."""

    _require_identity(service_instance_id, "service_instance_id")
    _require_identity(environment_id, "environment_id")
    _require_digest(mission_id, "mission_id")
    return content_id(
        "mission_checkpoint_genesis",
        {
            "environment_id": environment_id,
            "mission_id": mission_id,
            "service_instance_id": service_instance_id,
        },
    )


def derive_anchor_statement_id(
    *,
    service_instance_id: str,
    environment_id: str,
    instance_sequence: int,
    previous_checkpoint_id: str,
    previous_checkpoint_attestation_id: str | None,
    previous_checkpoint_principal_id: str | None,
    previous_checkpoint_trust_snapshot_id: str | None,
    previous_mission_checkpoint_id: str,
    previous_mission_checkpoint_attestation_id: str | None,
    previous_mission_checkpoint_principal_id: str | None,
    previous_mission_checkpoint_trust_snapshot_id: str | None,
    mission_id: str,
    authority_id: str,
    target_id: str,
    event_seq: int,
    event_digest: str,
    integrity_decision_id: str,
    integrity_decision_attestation_id: str,
    integrity_decision_principal_id: str,
    integrity_decision_trust_snapshot_id: str,
    time_lower_bound: int,
    time_upper_bound: int,
    time_policy_id: str,
    time_evidence: tuple[EvidenceReferenceV1, ...],
    anchor_policy_id: str,
) -> str:
    """Derive the exact pre-receipt statement that external anchors must register."""

    for field, value in (
        ("previous_checkpoint_id", previous_checkpoint_id),
        ("previous_mission_checkpoint_id", previous_mission_checkpoint_id),
        ("mission_id", mission_id),
        ("authority_id", authority_id),
        ("target_id", target_id),
        ("event_digest", event_digest),
        ("integrity_decision_id", integrity_decision_id),
        (
            "integrity_decision_attestation_id",
            integrity_decision_attestation_id,
        ),
        (
            "integrity_decision_trust_snapshot_id",
            integrity_decision_trust_snapshot_id,
        ),
        ("time_policy_id", time_policy_id),
        ("anchor_policy_id", anchor_policy_id),
    ):
        _require_digest(value, field)
    _require_identity(service_instance_id, "service_instance_id")
    _require_identity(environment_id, "environment_id")
    _require_identity(
        integrity_decision_principal_id,
        "integrity_decision_principal_id",
    )
    _require_nonnegative_int(instance_sequence, "instance_sequence")
    _require_nonnegative_int(event_seq, "event_seq")
    _validate_predecessor_provenance(
        sequence=instance_sequence - 1,
        attestation_id=previous_checkpoint_attestation_id,
        principal_id=previous_checkpoint_principal_id,
        trust_snapshot_id=previous_checkpoint_trust_snapshot_id,
        label="previous_checkpoint",
    )
    _validate_predecessor_provenance(
        sequence=event_seq - 1,
        attestation_id=previous_mission_checkpoint_attestation_id,
        principal_id=previous_mission_checkpoint_principal_id,
        trust_snapshot_id=previous_mission_checkpoint_trust_snapshot_id,
        label="previous_mission_checkpoint",
    )
    _validate_time_interval(time_lower_bound, time_upper_bound)
    references = _validated_evidence_references(
        time_evidence,
        field="time_evidence",
        minimum=2,
        evidence_kind=TRUSTED_TIME_EVIDENCE_KIND,
    )
    return content_id(
        "head_anchor_statement",
        {
            "anchor_policy_id": anchor_policy_id,
            "authority_id": authority_id,
            "environment_id": environment_id,
            "event_digest": event_digest,
            "event_seq": event_seq,
            "instance_sequence": instance_sequence,
            "integrity_decision_attestation_id": (
                integrity_decision_attestation_id
            ),
            "integrity_decision_id": integrity_decision_id,
            "integrity_decision_principal_id": (
                integrity_decision_principal_id
            ),
            "integrity_decision_trust_snapshot_id": (
                integrity_decision_trust_snapshot_id
            ),
            "mission_id": mission_id,
            "previous_checkpoint_id": previous_checkpoint_id,
            "previous_checkpoint_attestation_id": (
                previous_checkpoint_attestation_id
            ),
            "previous_checkpoint_principal_id": (
                previous_checkpoint_principal_id
            ),
            "previous_checkpoint_trust_snapshot_id": (
                previous_checkpoint_trust_snapshot_id
            ),
            "previous_mission_checkpoint_id": previous_mission_checkpoint_id,
            "previous_mission_checkpoint_attestation_id": (
                previous_mission_checkpoint_attestation_id
            ),
            "previous_mission_checkpoint_principal_id": (
                previous_mission_checkpoint_principal_id
            ),
            "previous_mission_checkpoint_trust_snapshot_id": (
                previous_mission_checkpoint_trust_snapshot_id
            ),
            "service_instance_id": service_instance_id,
            "target_id": target_id,
            "time_evidence": [reference.to_body() for reference in references],
            "time_lower_bound": time_lower_bound,
            "time_policy_id": time_policy_id,
            "time_upper_bound": time_upper_bound,
        },
    )


def _validate_checkpoint_decision_semantics(
    checkpoint: HeadCheckpointV1,
    decision: AuthenticatedIntegrityDecisionV1,
) -> None:
    value = decision.decision
    if (
        checkpoint.service_instance_id != value.service_instance_id
        or checkpoint.environment_id != value.environment_id
        or checkpoint.mission_id != value.mission_id
        or checkpoint.authority_id != value.authority_id
        or checkpoint.target_id != value.target_id
        or not _checkpoint_binds_decision_provenance(checkpoint, decision)
        or checkpoint.instance_sequence
        != value.prior_global_checkpoint_sequence + 1
        or checkpoint.previous_checkpoint_id
        != value.prior_global_checkpoint_id
        or checkpoint.previous_checkpoint_attestation_id
        != value.prior_global_checkpoint_attestation_id
        or checkpoint.previous_checkpoint_principal_id
        != value.prior_global_checkpoint_principal_id
        or checkpoint.previous_checkpoint_trust_snapshot_id
        != value.prior_global_checkpoint_trust_snapshot_id
        or checkpoint.event_seq != value.prior_event_seq + 1
        or checkpoint.event_digest != value.proposed_event_digest
    ):
        raise IntegrityError(
            "checkpoint_binding_mismatch",
            "checkpoint does not bind the exact authenticated decision",
        )
    if checkpoint.time_lower_bound < value.time_upper_bound:
        raise IntegrityError(
            "checkpoint_time_precedes_decision",
            "checkpoint interval does not conservatively follow the decision interval",
        )


def _validate_decision_mission_predecessor(
    checkpoint: HeadCheckpointV1,
    decision: IntegrityDecisionV1,
    previous_mission: AuthenticatedHeadCheckpointV1 | None,
) -> None:
    mission_genesis = mission_checkpoint_genesis_id(
        service_instance_id=checkpoint.service_instance_id,
        environment_id=checkpoint.environment_id,
        mission_id=checkpoint.mission_id,
    )
    if decision.prior_event_seq == -1:
        if (
            previous_mission is not None
            or checkpoint.previous_mission_checkpoint_id != mission_genesis
        ):
            raise IntegrityError(
                "checkpoint_mission_branch",
                "event zero must extend the exact mission genesis",
            )
        return
    if previous_mission is None:
        raise IntegrityError(
            "checkpoint_mission_gap",
            "non-genesis event requires the previous mission checkpoint",
        )
    previous_value = previous_mission.checkpoint
    _require_checkpoint_scope(checkpoint, previous_value)
    if (
        previous_value.mission_id != checkpoint.mission_id
        or previous_value.authority_id != checkpoint.authority_id
        or previous_value.target_id != checkpoint.target_id
        or decision.prior_event_seq != previous_value.event_seq
        or decision.prior_event_digest != previous_value.event_digest
        or not _checkpoint_reference_matches(
            checkpoint_id=checkpoint.previous_mission_checkpoint_id,
            attestation_id=(
                checkpoint.previous_mission_checkpoint_attestation_id
            ),
            principal_id=checkpoint.previous_mission_checkpoint_principal_id,
            trust_snapshot_id=(
                checkpoint.previous_mission_checkpoint_trust_snapshot_id
            ),
            checkpoint=previous_mission,
        )
    ):
        raise IntegrityError(
            "checkpoint_mission_branch",
            "decision and checkpoint must extend the same exact mission head",
        )


def validate_checkpoint_binding(
    checkpoint: AuthenticatedHeadCheckpointV1,
    decision: AuthenticatedIntegrityDecisionV1,
    *,
    event: object,
    checkpoint_trust_store: IntegrityTrustStore,
    decision_trust_store: IntegrityTrustStore,
    previous_mission: AuthenticatedHeadCheckpointV1 | None,
    previous_mission_trust_store: IntegrityTrustStore | None,
    validation_policy: IntegrityValidationPolicyV1,
) -> None:
    """Bind a post-transition checkpoint to one authenticated pre-transition decision."""

    from etzio.kernel.events_v1 import EventV1

    if (
        type(checkpoint) is not AuthenticatedHeadCheckpointV1
        or type(decision) is not AuthenticatedIntegrityDecisionV1
        or type(event) is not EventV1
    ):
        raise IntegrityError(
            "invalid_checkpoint_binding",
            "binding requires authenticated checkpoint, decision, and canonical event",
        )
    event = _snapshot_event(event)
    validation_policy = _snapshot_validation_policy(validation_policy)
    checkpoint = _reauthenticate_checkpoint_result(
        checkpoint,
        checkpoint_trust_store,
    )
    decision = _reauthenticate_decision_result(
        decision,
        decision_trust_store,
    )
    _validate_checkpoint_against_policy(
        checkpoint.checkpoint,
        validation_policy,
    )
    _validate_decision_against_policy(decision.decision, validation_policy)
    if previous_mission is None:
        if previous_mission_trust_store is not None:
            raise IntegrityError(
                "invalid_trust_store",
                "no mission trust store is valid without a previous checkpoint",
            )
    else:
        if type(previous_mission_trust_store) is not IntegrityTrustStore:
            raise IntegrityError(
                "invalid_trust_store",
                "previous mission checkpoint requires its exact trust store",
            )
        previous_mission = _reauthenticate_checkpoint_result(
            previous_mission,
            previous_mission_trust_store,
        )
        _validate_checkpoint_against_policy(
            previous_mission.checkpoint,
            validation_policy,
        )
    if (
        checkpoint.signer_principal_id == decision.signer_principal_id
        or checkpoint.signed_checkpoint.key_id == decision.signed_decision.key_id
    ):
        raise IntegrityError(
            "principal_separation_violation",
            "one principal or key cannot decide and checkpoint the same transition",
        )
    value = checkpoint.checkpoint
    _validate_checkpoint_decision_semantics(value, decision)
    if (
        value.event_seq != event.seq
        or value.event_digest != event.event_digest
        or event.event_digest != decision.decision.proposed_event_digest
        or event.mission_id != decision.decision.mission_id
        or event.authority_id != decision.decision.authority_id
        or event.target_id != decision.decision.target_id
        or event.prev_digest != decision.decision.prior_event_digest
        or event.seq != decision.decision.prior_event_seq + 1
        or event.kind != decision.decision.event_kind
        or event.decision_time != decision.decision.time_upper_bound
    ):
        raise IntegrityError(
            "checkpoint_binding_mismatch",
            "head checkpoint does not bind the exact decision and resulting event",
        )
    _validate_decision_mission_predecessor(
        value,
        decision.decision,
        previous_mission,
    )
    if previous_mission is not None:
        _require_decision_follows_checkpoint(
            decision.decision,
            previous_mission.checkpoint,
        )


def validate_checkpoint_advance(
    current: AuthenticatedHeadCheckpointV1,
    *,
    current_trust_store: IntegrityTrustStore,
    current_decision: AuthenticatedIntegrityDecisionV1,
    current_decision_trust_store: IntegrityTrustStore,
    previous_global: AuthenticatedHeadCheckpointV1 | None,
    previous_global_trust_store: IntegrityTrustStore | None,
    previous_mission: AuthenticatedHeadCheckpointV1 | None,
    previous_mission_trust_store: IntegrityTrustStore | None,
    external_floor: HeadCheckpointFloorV1,
    validation_policy: IntegrityValidationPolicyV1,
) -> None:
    """Validate checkpoint continuity above an externally retained catalog floor."""

    if type(current) is not AuthenticatedHeadCheckpointV1:
        raise IntegrityError(
            "invalid_head_checkpoint",
            "current must be an AuthenticatedHeadCheckpointV1",
        )
    validation_policy = _snapshot_validation_policy(validation_policy)
    current = _reauthenticate_checkpoint_result(
        current,
        current_trust_store,
    )
    current_decision = _reauthenticate_decision_result(
        current_decision,
        current_decision_trust_store,
    )
    _validate_checkpoint_against_policy(
        current.checkpoint,
        validation_policy,
    )
    _validate_decision_against_policy(
        current_decision.decision,
        validation_policy,
    )
    if (
        current.signer_principal_id == current_decision.signer_principal_id
        or current.signed_checkpoint.key_id
        == current_decision.signed_decision.key_id
    ):
        raise IntegrityError(
            "principal_separation_violation",
            "one principal or key cannot decide and checkpoint the same transition",
        )
    if (
        previous_global is not None
        and type(previous_global) is not AuthenticatedHeadCheckpointV1
    ):
        raise IntegrityError(
            "invalid_head_checkpoint",
            "previous global checkpoint must be authenticated",
        )
    if previous_global is None:
        if previous_global_trust_store is not None:
            raise IntegrityError(
                "invalid_trust_store",
                "no global trust store is valid without a previous checkpoint",
            )
    else:
        if type(previous_global_trust_store) is not IntegrityTrustStore:
            raise IntegrityError(
                "invalid_trust_store",
                "previous global checkpoint requires its exact trust store",
            )
        previous_global = _reauthenticate_checkpoint_result(
            previous_global,
            previous_global_trust_store,
        )
        _validate_checkpoint_against_policy(
            previous_global.checkpoint,
            validation_policy,
        )
    if (
        previous_mission is not None
        and type(previous_mission) is not AuthenticatedHeadCheckpointV1
    ):
        raise IntegrityError(
            "invalid_head_checkpoint",
            "previous mission checkpoint must be authenticated",
        )
    if previous_mission is None:
        if previous_mission_trust_store is not None:
            raise IntegrityError(
                "invalid_trust_store",
                "no mission trust store is valid without a previous checkpoint",
            )
    else:
        if type(previous_mission_trust_store) is not IntegrityTrustStore:
            raise IntegrityError(
                "invalid_trust_store",
                "previous mission checkpoint requires its exact trust store",
            )
        previous_mission = _reauthenticate_checkpoint_result(
            previous_mission,
            previous_mission_trust_store,
        )
        _validate_checkpoint_against_policy(
            previous_mission.checkpoint,
            validation_policy,
        )
    _require_checkpoint_projection_consistency(
        previous_global,
        previous_mission,
    )
    if type(external_floor) is not HeadCheckpointFloorV1:
        raise IntegrityError(
            "missing_external_head_floor",
            "checkpoint continuity requires an external catalog floor",
        )
    external_floor = _snapshot_head_checkpoint_floor(external_floor)
    current_value = current.checkpoint
    _validate_checkpoint_decision_semantics(
        current_value,
        current_decision,
    )
    if (
        external_floor.service_instance_id
        != current_value.service_instance_id
        or external_floor.environment_id != current_value.environment_id
        or external_floor.mission_id != current_value.mission_id
    ):
        raise IntegrityError(
            "external_head_floor_scope_mismatch",
            "external head floor belongs to another service scope or mission",
        )
    previous_global_value = (
        None if previous_global is None else previous_global.checkpoint
    )
    previous_mission_value = (
        None if previous_mission is None else previous_mission.checkpoint
    )

    global_genesis = head_checkpoint_genesis_id(
        service_instance_id=current_value.service_instance_id,
        environment_id=current_value.environment_id,
    )
    if previous_global_value is None:
        if (
            current_value.instance_sequence != 0
            or current_value.previous_checkpoint_id != global_genesis
        ):
            raise IntegrityError(
                "checkpoint_global_gap",
                "first global checkpoint must extend the instance genesis",
            )
    else:
        _require_checkpoint_scope(current_value, previous_global_value)
        if (
            current_value.instance_sequence
            != previous_global_value.instance_sequence + 1
            or not _checkpoint_reference_matches(
                checkpoint_id=current_value.previous_checkpoint_id,
                attestation_id=(
                    current_value.previous_checkpoint_attestation_id
                ),
                principal_id=(
                    current_value.previous_checkpoint_principal_id
                ),
                trust_snapshot_id=(
                    current_value.previous_checkpoint_trust_snapshot_id
                ),
                checkpoint=previous_global,
            )
        ):
            raise IntegrityError(
                "checkpoint_global_branch",
                "checkpoint does not extend the exact global head",
            )
        _require_decision_follows_checkpoint(
            current_decision.decision,
            previous_global_value,
        )

    _validate_decision_mission_predecessor(
        current_value,
        current_decision.decision,
        previous_mission,
    )
    mission_genesis = mission_checkpoint_genesis_id(
        service_instance_id=current_value.service_instance_id,
        environment_id=current_value.environment_id,
        mission_id=current_value.mission_id,
    )
    if previous_mission_value is None:
        if (
            current_value.event_seq != 0
            or current_value.previous_mission_checkpoint_id != mission_genesis
        ):
            raise IntegrityError(
                "checkpoint_mission_gap",
                "first mission checkpoint must cover event zero and extend mission genesis",
            )
    else:
        _require_checkpoint_scope(current_value, previous_mission_value)
        if (
            current_value.event_seq != previous_mission_value.event_seq + 1
            or current_value.previous_mission_checkpoint_id
            != previous_mission_value.checkpoint_id
        ):
            raise IntegrityError(
                "checkpoint_mission_branch",
                "checkpoint does not extend the exact mission head",
            )

    global_floor_is_current = _global_floor_matches_checkpoint(
        external_floor,
        current,
    )
    mission_floor_is_current = _mission_floor_matches_checkpoint(
        external_floor,
        current,
    )
    global_floor_is_predecessor = (
        external_floor.instance_sequence == -1
        and external_floor.checkpoint_id == global_genesis
        if previous_global is None
        else _global_floor_matches_checkpoint(
            external_floor,
            previous_global,
        )
    )
    mission_floor_is_predecessor = (
        external_floor.mission_event_seq == -1
        and external_floor.mission_checkpoint_id == mission_genesis
        if previous_mission is None
        else _mission_floor_matches_checkpoint(
            external_floor,
            previous_mission,
        )
    )
    if (
        global_floor_is_current
        and mission_floor_is_current
    ) or (
        global_floor_is_predecessor
        and mission_floor_is_predecessor
    ):
        return

    if (
        external_floor.instance_sequence > current_value.instance_sequence
        or external_floor.mission_event_seq > current_value.event_seq
    ):
        raise IntegrityError(
            "local_head_below_external_floor",
            "externally retained checkpoint is ahead of local history",
        )
    if (
        global_floor_is_current
        or mission_floor_is_current
        or global_floor_is_predecessor
        or mission_floor_is_predecessor
    ):
        raise IntegrityError(
            "external_head_floor_inconsistent",
            "external global and mission floors do not describe one catalog state",
        )
    if (
        external_floor.instance_sequence == current_value.instance_sequence
        or external_floor.mission_event_seq == current_value.event_seq
        or (
            previous_global_value is not None
            and external_floor.instance_sequence
            == previous_global_value.instance_sequence
        )
        or (
            previous_mission_value is not None
            and external_floor.mission_event_seq
            == previous_mission_value.event_seq
        )
    ):
        raise IntegrityError(
            "external_head_floor_equivocation",
            "external floor has different identity or provenance at a retained sequence",
        )
    if (
        previous_global_value is not None
        and external_floor.instance_sequence
        < previous_global_value.instance_sequence
    ) or (
        previous_mission_value is not None
        and external_floor.mission_event_seq
        < previous_mission_value.event_seq
    ):
        raise IntegrityError(
            "external_head_floor_rollback",
            "external floor is behind a retained checkpoint predecessor",
        )
    raise IntegrityError(
        "external_head_floor_inconsistent",
        "external floor cannot be reconciled with local checkpoint continuity",
    )


def require_external_floor_is_current(
    checkpoint: AuthenticatedHeadCheckpointV1,
    trust_store: IntegrityTrustStore,
    external_floor: HeadCheckpointFloorV1,
    validation_policy: IntegrityValidationPolicyV1,
) -> None:
    """Require an external catalog floor to name this exact checkpoint twice.

    This is the strict command-finality predicate.  Unlike checkpoint-advance
    validation, an exact predecessor floor is not a reconciliation success: both the
    instance-global and selected mission projections must name the supplied checkpoint
    with its exact attestation, principal, and historical trust provenance.
    """

    if type(checkpoint) is not AuthenticatedHeadCheckpointV1:
        raise IntegrityError(
            "invalid_head_checkpoint",
            "current external-floor validation requires an authenticated checkpoint",
        )
    policy = _snapshot_validation_policy(validation_policy)
    authenticated = _reauthenticate_checkpoint_result(
        checkpoint,
        trust_store,
    )
    _validate_checkpoint_against_policy(
        authenticated.checkpoint,
        policy,
    )
    if type(external_floor) is not HeadCheckpointFloorV1:
        raise IntegrityError(
            "missing_external_head_floor",
            "command finality requires an exact external catalog floor",
        )
    floor = _snapshot_head_checkpoint_floor(external_floor)
    value = authenticated.checkpoint
    if (
        floor.service_instance_id != value.service_instance_id
        or floor.environment_id != value.environment_id
        or floor.mission_id != value.mission_id
    ):
        raise IntegrityError(
            "external_head_floor_scope_mismatch",
            "external head floor belongs to another service scope or mission",
        )
    if not (
        _global_floor_matches_checkpoint(floor, authenticated)
        and _mission_floor_matches_checkpoint(floor, authenticated)
    ):
        raise IntegrityError(
            "external_head_floor_not_current",
            "external global and mission floors must both name the exact current checkpoint",
        )


def _decision_body(**values: object) -> dict[str, object]:
    time_evidence = _validated_evidence_references(
        values["time_evidence"],
        field="time_evidence",
        minimum=2,
        evidence_kind=TRUSTED_TIME_EVIDENCE_KIND,
    )
    revocation_views = _validated_revocation_views(
        values["revocation_views"]
    )
    return {
        "authority_id": values["authority_id"],
        "decision_policy_id": values["decision_policy_id"],
        "environment_id": values["environment_id"],
        "event_kind": values["event_kind"],
        "mission_id": values["mission_id"],
        "prior_global_checkpoint_attestation_id": values[
            "prior_global_checkpoint_attestation_id"
        ],
        "prior_global_checkpoint_id": values[
            "prior_global_checkpoint_id"
        ],
        "prior_global_checkpoint_principal_id": values[
            "prior_global_checkpoint_principal_id"
        ],
        "prior_global_checkpoint_sequence": values[
            "prior_global_checkpoint_sequence"
        ],
        "prior_global_checkpoint_trust_snapshot_id": values[
            "prior_global_checkpoint_trust_snapshot_id"
        ],
        "prior_event_digest": values["prior_event_digest"],
        "prior_event_seq": values["prior_event_seq"],
        "proposed_event_digest": values["proposed_event_digest"],
        "request_nonce": values["request_nonce"],
        "revocation_views": [view.to_body() for view in revocation_views],
        "service_instance_id": values["service_instance_id"],
        "target_id": values["target_id"],
        "time_evidence": [reference.to_body() for reference in time_evidence],
        "time_lower_bound": values["time_lower_bound"],
        "time_policy_id": values["time_policy_id"],
        "time_upper_bound": values["time_upper_bound"],
        "transition_intent_id": values["transition_intent_id"],
    }


def _decision_values(body: dict[str, object]) -> dict[str, object]:
    if (
        type(body["time_evidence"]) is not list
        or type(body["revocation_views"]) is not list
        or not 2 <= len(body["time_evidence"]) <= MAX_EVIDENCE_REFS
        or not 1 <= len(body["revocation_views"]) <= MAX_REVOCATION_VIEWS
    ):
        raise IntegrityError(
            "invalid_integrity_decision",
            "decision evidence and revocation views must be bounded arrays",
        )
    return {
        **body,
        "time_evidence": tuple(
            EvidenceReferenceV1.from_body(value)
            for value in body["time_evidence"]
        ),
        "revocation_views": tuple(
            RevocationViewV1.from_body(value)
            for value in body["revocation_views"]
        ),
    }


def _checkpoint_body(**values: object) -> dict[str, object]:
    time_evidence = _validated_evidence_references(
        values["time_evidence"],
        field="time_evidence",
        minimum=2,
        evidence_kind=TRUSTED_TIME_EVIDENCE_KIND,
    )
    anchor_evidence = _validated_evidence_references(
        values["anchor_evidence"],
        field="anchor_evidence",
        minimum=2,
        evidence_kind=HEAD_ANCHOR_RECEIPT_EVIDENCE_KIND,
    )
    return {
        "anchor_evidence": [reference.to_body() for reference in anchor_evidence],
        "anchor_policy_id": values["anchor_policy_id"],
        "anchor_statement_id": values["anchor_statement_id"],
        "authority_id": values["authority_id"],
        "environment_id": values["environment_id"],
        "event_digest": values["event_digest"],
        "event_seq": values["event_seq"],
        "instance_sequence": values["instance_sequence"],
        "integrity_decision_attestation_id": values[
            "integrity_decision_attestation_id"
        ],
        "integrity_decision_id": values["integrity_decision_id"],
        "integrity_decision_principal_id": values[
            "integrity_decision_principal_id"
        ],
        "integrity_decision_trust_snapshot_id": values[
            "integrity_decision_trust_snapshot_id"
        ],
        "mission_id": values["mission_id"],
        "previous_checkpoint_attestation_id": values[
            "previous_checkpoint_attestation_id"
        ],
        "previous_checkpoint_id": values["previous_checkpoint_id"],
        "previous_checkpoint_principal_id": values[
            "previous_checkpoint_principal_id"
        ],
        "previous_checkpoint_trust_snapshot_id": values[
            "previous_checkpoint_trust_snapshot_id"
        ],
        "previous_mission_checkpoint_attestation_id": values[
            "previous_mission_checkpoint_attestation_id"
        ],
        "previous_mission_checkpoint_id": values[
            "previous_mission_checkpoint_id"
        ],
        "previous_mission_checkpoint_principal_id": values[
            "previous_mission_checkpoint_principal_id"
        ],
        "previous_mission_checkpoint_trust_snapshot_id": values[
            "previous_mission_checkpoint_trust_snapshot_id"
        ],
        "service_instance_id": values["service_instance_id"],
        "target_id": values["target_id"],
        "time_evidence": [reference.to_body() for reference in time_evidence],
        "time_lower_bound": values["time_lower_bound"],
        "time_policy_id": values["time_policy_id"],
        "time_upper_bound": values["time_upper_bound"],
    }


def _checkpoint_values(body: dict[str, object]) -> dict[str, object]:
    if (
        type(body["time_evidence"]) is not list
        or type(body["anchor_evidence"]) is not list
        or not 2 <= len(body["time_evidence"]) <= MAX_EVIDENCE_REFS
        or not 2 <= len(body["anchor_evidence"]) <= MAX_EVIDENCE_REFS
    ):
        raise IntegrityError(
            "invalid_head_checkpoint",
            "checkpoint evidence must be bounded arrays",
        )
    return {
        **body,
        "time_evidence": tuple(
            EvidenceReferenceV1.from_body(value)
            for value in body["time_evidence"]
        ),
        "anchor_evidence": tuple(
            EvidenceReferenceV1.from_body(value)
            for value in body["anchor_evidence"]
        ),
    }


def _signed_attestation_id(kind: str, wire_bytes: bytes) -> str:
    if type(wire_bytes) is not bytes:
        raise IntegrityError(
            "invalid_signed_integrity_wire",
            "signed attestation identity requires canonical bytes",
        )
    wire_digest = "sha256:" + hashlib.sha256(wire_bytes).hexdigest()
    return content_id(kind, {"wire_digest": wire_digest})


def _validate_signed_fields(
    envelope_bytes: object,
    key_id: object,
    signature_b64: object,
) -> None:
    if (
        type(envelope_bytes) is not bytes
        or not envelope_bytes
        or len(envelope_bytes) > MAX_INTEGRITY_ENVELOPE_BYTES
    ):
        raise IntegrityError(
            "malformed_signed_object",
            "signed integrity envelope bytes are missing or oversized",
        )
    if type(key_id) is not str or _KEY_ID.fullmatch(key_id) is None:
        raise IntegrityError(
            "malformed_key_id",
            "integrity key ID must be content-derived from Ed25519 bytes",
        )
    _decode_signature(signature_b64)


def _signed_to_envelope(
    envelope_bytes: bytes,
    key_id: str,
    signature_b64: str,
    *,
    object_kind: str,
    parser: object,
) -> EnvelopeV1:
    try:
        envelope = EnvelopeV1.from_bytes(envelope_bytes)
    except ProtocolError as exc:
        raise IntegrityError(
            "invalid_envelope",
            "signed integrity envelope is invalid",
        ) from exc
    if envelope.object_kind != object_kind or envelope.attestations:
        raise IntegrityError(
            "invalid_envelope",
            f"signed input must contain one unattested {object_kind} envelope",
        )
    parser(envelope)  # type: ignore[operator]
    attested = EnvelopeV1.create(
        object_kind,
        envelope.body,
        attestations=[
            {
                "algorithm": "ed25519",
                "key_id": key_id,
                "signature_b64": signature_b64,
            }
        ],
    )
    if len(attested.to_bytes()) > MAX_INTEGRITY_ENVELOPE_BYTES:
        raise IntegrityError(
            "integrity_envelope_too_large",
            "attested integrity envelope exceeds its fixed byte ceiling",
        )
    return attested


def _signed_from_bytes(
    data: bytes | str,
    *,
    object_kind: str,
    parser: object,
) -> tuple[bytes, str, str]:
    envelope_bytes, key_id, signature_b64 = _extract_signed_transport(
        data,
        object_kind=object_kind,
    )
    unattested = EnvelopeV1.from_bytes(envelope_bytes)
    parser(unattested)  # type: ignore[operator]
    return envelope_bytes, key_id, signature_b64


def _extract_signed_transport(
    data: bytes | str,
    *,
    object_kind: str,
) -> tuple[bytes, str, str]:
    """Extract signed framing without interpreting attacker-controlled semantics."""

    if type(data) is bytes:
        encoded = data
    elif type(data) is str:
        if len(data) > MAX_INTEGRITY_ENVELOPE_BYTES:
            raise IntegrityError(
                "integrity_envelope_too_large",
                "signed integrity wire exceeds its fixed byte ceiling",
            )
        try:
            encoded = data.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise IntegrityError(
                "invalid_envelope",
                "signed integrity wire must be valid UTF-8",
            ) from exc
    else:
        raise IntegrityError(
            "malformed_signed_object",
            "signed integrity transport must be bytes or str",
        )
    if len(encoded) > MAX_INTEGRITY_ENVELOPE_BYTES:
        raise IntegrityError(
            "integrity_envelope_too_large",
            "signed integrity wire exceeds its fixed byte ceiling",
        )
    try:
        envelope = EnvelopeV1.from_bytes(encoded)
    except ProtocolError as exc:
        raise IntegrityError(
            "invalid_envelope",
            "signed integrity wire is invalid",
        ) from exc
    if envelope.object_kind != object_kind or len(envelope.attestations) != 1:
        raise IntegrityError(
            "malformed_signed_object",
            f"signed {object_kind} requires exactly one attestation",
        )
    attestation = thaw_json(envelope.attestations[0])
    if (
        type(attestation) is not dict
        or set(attestation) != _ATTESTATION_FIELDS
        or attestation["algorithm"] != "ed25519"
    ):
        raise IntegrityError(
            "malformed_signed_object",
            "integrity attestation is malformed or uses an unsupported algorithm",
        )
    unattested = EnvelopeV1.create(object_kind, envelope.body)
    return (
        unattested.to_bytes(),
        attestation["key_id"],
        attestation["signature_b64"],
    )


def _authenticate_signed(
    envelope_bytes: bytes,
    key_id: str,
    signature_b64: str,
    trust_store: IntegrityTrustStore,
    *,
    role: str,
    signature_domain: bytes,
    forbidden_key_ids: Iterable[str],
) -> TrustedIntegrityKey:
    _validate_signed_fields(envelope_bytes, key_id, signature_b64)
    forbidden = _validated_key_ids(
        forbidden_key_ids,
        maximum=MAX_INTEGRITY_KEYS,
    )
    if key_id in forbidden:
        raise IntegrityError(
            "principal_separation_violation",
            "integrity signer key is forbidden for this decision",
        )
    if key_id in trust_store.revoked_key_ids:
        raise IntegrityError("key_revoked", "integrity signer key is revoked")
    trusted_key = trust_store.keys.get(key_id)
    if trusted_key is None:
        raise IntegrityError("unknown_key", "integrity signer key is unknown")
    if trusted_key.role != role:
        raise IntegrityError(
            "key_role_mismatch",
            "integrity signer key lacks the exact required role",
        )
    signature = _decode_signature(signature_b64)
    try:
        Ed25519PublicKey.from_public_bytes(trusted_key.public_key_bytes).verify(
            signature,
            signature_domain + envelope_bytes,
        )
    except (InvalidSignature, ValueError) as exc:
        raise IntegrityError(
            "invalid_signature",
            "integrity signature is invalid",
        ) from exc
    return trusted_key


def _coerce_signed_decision(
    value: SignedIntegrityDecisionV1 | bytes | str,
) -> SignedIntegrityDecisionV1:
    if type(value) is SignedIntegrityDecisionV1:
        return value
    if type(value) in {bytes, str}:
        return SignedIntegrityDecisionV1(
            *_extract_signed_transport(
                value,
                object_kind=INTEGRITY_DECISION_OBJECT_KIND,
            )
        )
    raise IntegrityError(
        "malformed_signed_object",
        "integrity decision must be signed wire or SignedIntegrityDecisionV1",
    )


def _coerce_signed_checkpoint(
    value: SignedHeadCheckpointV1 | bytes | str,
) -> SignedHeadCheckpointV1:
    if type(value) is SignedHeadCheckpointV1:
        return value
    if type(value) in {bytes, str}:
        return SignedHeadCheckpointV1(
            *_extract_signed_transport(
                value,
                object_kind=HEAD_CHECKPOINT_OBJECT_KIND,
            )
        )
    raise IntegrityError(
        "malformed_signed_object",
        "head checkpoint must be signed wire or SignedHeadCheckpointV1",
    )


def _decode_signature(value: object) -> bytes:
    if type(value) is not str or len(value) != 88:
        raise IntegrityError(
            "malformed_signature",
            "signature must be one canonical Ed25519 Base64 value",
        )
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise IntegrityError(
            "malformed_signature",
            "signature must be one canonical Ed25519 Base64 value",
        ) from exc
    if (
        len(decoded) != 64
        or base64.b64encode(decoded).decode("ascii") != value
    ):
        raise IntegrityError(
            "malformed_signature",
            "signature must be one canonical Ed25519 Base64 value",
        )
    return decoded


def _validated_evidence_references(
    values: object,
    *,
    field: str,
    minimum: int,
    evidence_kind: str,
) -> tuple[EvidenceReferenceV1, ...]:
    if (
        type(values) is not tuple
        or len(values) < minimum
        or len(values) > MAX_EVIDENCE_REFS
    ):
        raise IntegrityError(
            f"invalid_{field}",
            f"{field} must contain {minimum}..{MAX_EVIDENCE_REFS} typed references",
        )
    copied: list[EvidenceReferenceV1] = []
    for value in values:
        if type(value) is not EvidenceReferenceV1:
            raise IntegrityError(
                f"invalid_{field}",
                f"{field} contains an invalid evidence reference",
            )
        try:
            copied.append(
                EvidenceReferenceV1(
                    evidence_kind=value.evidence_kind,
                    source_id=value.source_id,
                    evidence_id=value.evidence_id,
                )
            )
        except (AttributeError, IntegrityError, TypeError, ValueError) as exc:
            raise IntegrityError(
                f"invalid_{field}",
                f"{field} contains an invalid evidence reference",
            ) from exc
    copied_values = tuple(copied)
    canonical = tuple(
        sorted(copied_values, key=lambda value: value.source_id)
    )
    if any(value.evidence_kind != evidence_kind for value in canonical):
        raise IntegrityError(
            f"invalid_{field}",
            f"{field} requires only {evidence_kind!r} evidence",
        )
    source_ids = [value.source_id for value in canonical]
    evidence_ids = [value.evidence_id for value in canonical]
    if (
        copied_values != canonical
        or len(set(source_ids)) != len(source_ids)
        or len(set(evidence_ids)) != len(evidence_ids)
    ):
        raise IntegrityError(
            f"invalid_{field}",
            f"{field} must be source-sorted with unique sources and evidence IDs",
        )
    return canonical


def _validated_revocation_views(
    values: object,
) -> tuple[RevocationViewV1, ...]:
    if (
        type(values) is not tuple
        or not values
        or len(values) > MAX_REVOCATION_VIEWS
    ):
        raise IntegrityError(
            "invalid_revocation_views",
            "revocation_views must be a nonempty bounded tuple",
        )
    copied: list[RevocationViewV1] = []
    for value in values:
        if type(value) is not RevocationViewV1:
            raise IntegrityError(
                "invalid_revocation_views",
                "revocation_views contains an invalid view",
            )
        try:
            copied.append(
                RevocationViewV1(
                    namespace=value.namespace,
                    root_version=value.root_version,
                    version=value.version,
                    snapshot_id=value.snapshot_id,
                    evidence=value.evidence,
                    valid_from=value.valid_from,
                    valid_until=value.valid_until,
                )
            )
        except (AttributeError, IntegrityError, TypeError, ValueError) as exc:
            raise IntegrityError(
                "invalid_revocation_views",
                "revocation_views contains an invalid view",
            ) from exc
    copied_values = tuple(copied)
    canonical = tuple(
        sorted(copied_values, key=lambda value: value.namespace)
    )
    namespaces = [view.namespace for view in canonical]
    if (
        copied_values != canonical
        or len(set(namespaces)) != len(namespaces)
    ):
        raise IntegrityError(
            "invalid_revocation_views",
            "revocation views must be namespace-sorted and unique",
        )
    return canonical


def _validated_key_ids(
    values: Iterable[str],
    *,
    maximum: int,
) -> frozenset[str]:
    if isinstance(values, (str, bytes)):
        raise IntegrityError(
            "invalid_key_ids",
            "key IDs must be an iterable of complete identifiers",
        )
    result: set[str] = set()
    try:
        for index, value in enumerate(values):
            if index >= maximum:
                raise IntegrityError(
                    "invalid_key_ids",
                    "key ID iterable exceeds its fixed item ceiling",
                )
            if type(value) is not str or _KEY_ID.fullmatch(value) is None:
                raise IntegrityError(
                    "invalid_key_ids",
                    "key IDs must be complete Ed25519 content identifiers",
                )
            result.add(value)
    except TypeError as exc:
        raise IntegrityError(
            "invalid_key_ids",
            "key IDs must be iterable",
        ) from exc
    return frozenset(result)


def _validated_identity_set(
    values: Iterable[str],
    field: str,
    *,
    maximum: int,
) -> frozenset[str]:
    if isinstance(values, (str, bytes)):
        raise IntegrityError(
            f"invalid_{field}",
            f"{field} must be an iterable of identities",
        )
    result: set[str] = set()
    try:
        for index, value in enumerate(values):
            if index >= maximum:
                raise IntegrityError(
                    f"invalid_{field}",
                    f"{field} exceeds its fixed item ceiling",
                )
            _require_identity(value, field)
            result.add(value)
    except TypeError as exc:
        raise IntegrityError(
            f"invalid_{field}",
            f"{field} must be iterable",
        ) from exc
    return frozenset(result)


def _validate_predecessor_provenance(
    *,
    sequence: int,
    attestation_id: str | None,
    principal_id: str | None,
    trust_snapshot_id: str | None,
    label: str,
) -> None:
    values = (attestation_id, principal_id, trust_snapshot_id)
    if sequence == -1:
        if any(value is not None for value in values):
            raise IntegrityError(
                "invalid_checkpoint_provenance",
                f"{label} genesis must not claim attestation provenance",
            )
        return
    if any(value is None for value in values):
        raise IntegrityError(
            "invalid_checkpoint_provenance",
            f"{label} requires complete attestation provenance",
        )
    _require_digest(attestation_id, f"{label}_attestation_id")
    _require_identity(principal_id, f"{label}_principal_id")
    _require_digest(trust_snapshot_id, f"{label}_trust_snapshot_id")


def _validate_time_interval(lower: object, upper: object) -> None:
    _require_epoch(lower, "time_lower_bound")
    _require_epoch(upper, "time_upper_bound")
    if lower > upper:
        raise IntegrityError(
            "invalid_time_interval",
            "trusted time lower bound cannot exceed its upper bound",
        )


def _require_max_uncertainty(lower: int, upper: int, maximum: object) -> None:
    _require_nonnegative_int(maximum, "max_time_uncertainty_seconds")
    if upper - lower > maximum:
        raise IntegrityError(
            "time_uncertainty_exceeded",
            "trusted time interval exceeds the caller's fail-closed policy",
        )


def _require_interval_within(
    lower: int,
    upper: int,
    not_before: int,
    expires_at: int,
    *,
    prefix: str,
) -> None:
    if lower < not_before:
        reason = (
            "not_yet_valid"
            if upper < not_before
            else "time_interval_straddles_not_before"
        )
        raise IntegrityError(
            f"{prefix}_{reason}",
            "trusted time interval is not wholly inside the validity window",
        )
    if upper >= expires_at:
        reason = (
            "expired"
            if lower >= expires_at
            else "time_interval_straddles_expiry"
        )
        raise IntegrityError(
            f"{prefix}_{reason}",
            "trusted time interval is not wholly inside the validity window",
        )


def _checkpoint_binds_decision_provenance(
    checkpoint: HeadCheckpointV1,
    decision: AuthenticatedIntegrityDecisionV1,
) -> bool:
    return (
        checkpoint.service_instance_id == decision.decision.service_instance_id
        and checkpoint.environment_id == decision.decision.environment_id
        and checkpoint.integrity_decision_id == decision.decision.decision_id
        and checkpoint.integrity_decision_attestation_id
        == signed_integrity_decision_attestation_id(decision.signed_decision)
        and checkpoint.integrity_decision_principal_id
        == decision.signer_principal_id
        and checkpoint.integrity_decision_trust_snapshot_id
        == decision.trust_snapshot_id
    )


def _checkpoint_reference_matches(
    *,
    checkpoint_id: str,
    attestation_id: str | None,
    principal_id: str | None,
    trust_snapshot_id: str | None,
    checkpoint: AuthenticatedHeadCheckpointV1,
) -> bool:
    return (
        checkpoint_id == checkpoint.checkpoint.checkpoint_id
        and attestation_id
        == signed_head_checkpoint_attestation_id(
            checkpoint.signed_checkpoint
        )
        and principal_id == checkpoint.signer_principal_id
        and trust_snapshot_id == checkpoint.trust_snapshot_id
    )


def _global_floor_matches_checkpoint(
    floor: HeadCheckpointFloorV1,
    checkpoint: AuthenticatedHeadCheckpointV1,
) -> bool:
    return (
        floor.instance_sequence == checkpoint.checkpoint.instance_sequence
        and floor.checkpoint_id == checkpoint.checkpoint.checkpoint_id
        and floor.checkpoint_attestation_id
        == signed_head_checkpoint_attestation_id(checkpoint.signed_checkpoint)
        and floor.checkpoint_principal_id == checkpoint.signer_principal_id
        and floor.checkpoint_trust_snapshot_id == checkpoint.trust_snapshot_id
    )


def _mission_floor_matches_checkpoint(
    floor: HeadCheckpointFloorV1,
    checkpoint: AuthenticatedHeadCheckpointV1,
) -> bool:
    return (
        floor.mission_event_seq == checkpoint.checkpoint.event_seq
        and floor.mission_checkpoint_id == checkpoint.checkpoint.checkpoint_id
        and floor.mission_checkpoint_attestation_id
        == signed_head_checkpoint_attestation_id(checkpoint.signed_checkpoint)
        and floor.mission_checkpoint_principal_id
        == checkpoint.signer_principal_id
        and floor.mission_checkpoint_trust_snapshot_id
        == checkpoint.trust_snapshot_id
    )


def _require_checkpoint_scope(
    current: HeadCheckpointV1,
    previous: HeadCheckpointV1,
) -> None:
    if (
        current.service_instance_id != previous.service_instance_id
        or current.environment_id != previous.environment_id
    ):
        raise IntegrityError(
            "checkpoint_scope_mismatch",
            "checkpoint predecessor belongs to another service instance or environment",
        )


def _require_decision_follows_checkpoint(
    decision: IntegrityDecisionV1,
    checkpoint: HeadCheckpointV1,
) -> None:
    if decision.time_lower_bound < checkpoint.time_upper_bound:
        raise IntegrityError(
            "decision_time_precedes_checkpoint",
            "decision interval does not conservatively follow its checkpoint predecessor",
        )


def _require_checkpoint_projection_consistency(
    previous_global: AuthenticatedHeadCheckpointV1 | None,
    previous_mission: AuthenticatedHeadCheckpointV1 | None,
) -> None:
    if previous_mission is None:
        return
    if previous_global is None:
        raise IntegrityError(
            "checkpoint_projection_branch",
            "a mission checkpoint cannot exist without an instance-global head",
        )
    global_value = previous_global.checkpoint
    mission_value = previous_mission.checkpoint
    if mission_value.instance_sequence > global_value.instance_sequence:
        raise IntegrityError(
            "checkpoint_projection_branch",
            "mission checkpoint cannot be ahead of the instance-global head",
        )
    if (
        mission_value.instance_sequence == global_value.instance_sequence
        and not _checkpoint_reference_matches(
            checkpoint_id=global_value.checkpoint_id,
            attestation_id=signed_head_checkpoint_attestation_id(
                previous_global.signed_checkpoint
            ),
            principal_id=previous_global.signer_principal_id,
            trust_snapshot_id=previous_global.trust_snapshot_id,
            checkpoint=previous_mission,
        )
    ):
        raise IntegrityError(
            "checkpoint_projection_branch",
            "global and mission projections conflict at one instance sequence",
        )


def _check_expected(actual: object, expected: object, label: str) -> None:
    if type(actual) is not type(expected) or actual != expected:
        raise IntegrityError(
            f"{label}_mismatch",
            f"integrity evidence does not bind the expected {label}",
        )


def _require_digest(value: object, field: str) -> None:
    if type(value) is not str or _FULL_DIGEST.fullmatch(value) is None:
        raise IntegrityError(
            f"invalid_{field}",
            f"{field} must be a complete sha256 content identifier",
        )


def _require_identity(value: object, field: str) -> None:
    if type(value) is not str or _IDENTITY.fullmatch(value) is None:
        raise IntegrityError(
            f"invalid_{field}",
            f"{field} must be a canonical identity string",
        )


def _require_epoch(value: object, field: str) -> None:
    if type(value) is not int or value < 0 or value > MAX_EPOCH_SECOND:
        raise IntegrityError(
            f"invalid_{field}",
            f"{field} must be a nonnegative int64 epoch second",
        )


def _require_nonnegative_int(value: object, field: str) -> None:
    if type(value) is not int or value < 0 or value > MAX_EPOCH_SECOND:
        raise IntegrityError(
            f"invalid_{field}",
            f"{field} must be a nonnegative int64 integer",
        )


def _require_positive_int(value: object, field: str) -> None:
    if type(value) is not int or value <= 0 or value > MAX_EPOCH_SECOND:
        raise IntegrityError(
            f"invalid_{field}",
            f"{field} must be a positive int64 integer",
        )


__all__ = [
    "AuthenticatedHeadCheckpointV1",
    "AuthenticatedIntegrityDecisionV1",
    "EXTERNAL_FLOOR_EVIDENCE_KIND",
    "EvidenceReferenceV1",
    "HEAD_ANCHOR_RECEIPT_EVIDENCE_KIND",
    "HEAD_CHECKPOINT_OBJECT_KIND",
    "HEAD_CHECKPOINT_ROLE",
    "HeadCheckpointFloorV1",
    "HeadCheckpointV1",
    "INTEGRITY_EVIDENCE_KINDS_V1",
    "INTEGRITY_DECISION_OBJECT_KIND",
    "INTEGRITY_DECISION_ROLE",
    "INTEGRITY_ROLES_V1",
    "IntegrityDecisionV1",
    "IntegrityError",
    "IntegritySigner",
    "IntegrityTrustStore",
    "IntegrityValidationPolicyV1",
    "REVOCATION_METADATA_EVIDENCE_KIND",
    "RevocationFloorV1",
    "RevocationViewV1",
    "SignedHeadCheckpointV1",
    "SignedIntegrityDecisionV1",
    "TrustedIntegrityKey",
    "TRUSTED_TIME_EVIDENCE_KIND",
    "authenticate_head_checkpoint",
    "authenticate_integrity_decision",
    "classify_deadline",
    "derive_anchor_statement_id",
    "head_checkpoint_genesis_id",
    "integrity_key_id",
    "mission_checkpoint_genesis_id",
    "require_external_floor_is_current",
    "require_interval_within",
    "signed_head_checkpoint_attestation_id",
    "signed_integrity_decision_attestation_id",
    "validate_checkpoint_advance",
    "validate_checkpoint_binding",
    "validate_revocation_advance",
]
