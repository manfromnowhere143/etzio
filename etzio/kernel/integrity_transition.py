"""Crash-recoverable modeled integrity finality for one Etzio event transition.

This module is deliberately fixture-scoped.  It composes the provider-neutral
``IntegrityDecisionV1`` and ``HeadCheckpointV1`` contracts with an append-only sequence
of local recovery records, and exposes a store facade whose append methods do not return
until the modeled external catalog reports the exact checkpoint as current.

The repository-owned service at the bottom of this module is deterministic test
infrastructure.  Its source labels, signatures, time statements, revocation statements,
anchor receipts, and monitor floors prove protocol composition and crash recovery only.
They do *not* establish trustworthy UTC, fresh real revocation state, external durability,
independent operators, non-equivocation, or production authority.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final, Literal, Protocol, TypeVar

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..evidence import FileEvidenceStore
from ..integrity_v1 import (
    EXTERNAL_FLOOR_EVIDENCE_KIND,
    HEAD_ANCHOR_RECEIPT_EVIDENCE_KIND,
    HEAD_CHECKPOINT_ROLE,
    INTEGRITY_DECISION_ROLE,
    MAX_REVOCATION_VIEWS,
    REVOCATION_METADATA_EVIDENCE_KIND,
    TRUSTED_TIME_EVIDENCE_KIND,
    AuthenticatedHeadCheckpointV1,
    AuthenticatedIntegrityDecisionV1,
    EvidenceReferenceV1,
    HeadCheckpointFloorV1,
    HeadCheckpointV1,
    IntegrityDecisionV1,
    IntegrityError,
    IntegritySigner,
    IntegrityTrustStore,
    IntegrityValidationPolicyV1,
    RevocationFloorV1,
    RevocationViewV1,
    SignedHeadCheckpointV1,
    SignedIntegrityDecisionV1,
    TrustedIntegrityKey,
    authenticate_head_checkpoint,
    authenticate_integrity_decision,
    derive_anchor_statement_id,
    head_checkpoint_genesis_id,
    mission_checkpoint_genesis_id,
    require_external_floor_is_current,
    signed_head_checkpoint_attestation_id,
    signed_integrity_decision_attestation_id,
    validate_checkpoint_advance,
    validate_checkpoint_binding,
    validate_revocation_advance,
)
from ..protocol import (
    EnvelopeV1,
    ProtocolError,
    canonical_dumps,
    content_id,
    strict_loads,
)
from .events_v1 import GENESIS_DIGEST, EventV1
from .store import EventStoreError

INTEGRITY_TRANSITION_RECORD_VERSION_V1: Final = 1
MODELED_INTEGRITY_PROFILE_V1: Final = "modeled_integrity_fixture_v1"
MODELED_INTEGRITY_ADAPTER_PROFILE_V1: Final = "repository_owned_deterministic_modeled_integrity_service"
MODELED_INTEGRITY_ADAPTER_VERSION_V1: Final = 1
MAX_PROVIDER_EVIDENCE_BLOB_BYTES_V1: Final = 1 << 20
MAX_PROVIDER_EVIDENCE_TOTAL_BYTES_V1: Final = 8 << 20
MAX_PROVIDER_EVIDENCE_BLOBS_V1: Final = 64
_MODELED_PROVIDER_SUFFIXES_V1: Final = ("a", "b")

__all__: Final = (
    "AnchorStatementRecordV1",
    "CheckpointCandidateRecordV1",
    "FinalizedIntegrityTransitionV1",
    "INTEGRITY_TRANSITION_RECORD_VERSION_V1",
    "IntegrityFinalityBlockedError",
    "IntegrityFinalityPendingError",
    "IntegrityLineageV1",
    "IntegrityTransitionError",
    "MAX_PROVIDER_EVIDENCE_BLOBS_V1",
    "MAX_PROVIDER_EVIDENCE_BLOB_BYTES_V1",
    "MAX_PROVIDER_EVIDENCE_TOTAL_BYTES_V1",
    "MODELED_INTEGRITY_PROFILE_V1",
    "MODELED_INTEGRITY_ADAPTER_PROFILE_V1",
    "MODELED_INTEGRITY_ADAPTER_VERSION_V1",
    "ModeledIntegrityFinalizingEventStoreV1",
    "ModeledIntegrityAuthorityBindingV1",
    "ModeledIntegrityServiceError",
    "PendingIntegrityTransitionV1",
    "ProviderEvidenceBlobV1",
    "RepositoryOwnedDeterministicModeledIntegrityServiceV1",
    "authenticate_checkpoint_candidate",
    "authenticate_pending_integrity_transition",
    "validate_anchor_statement",
    "validate_anchor_statement_record",
    "validate_checkpoint_candidate",
    "validate_finalization",
    "validate_finalized_integrity_transition",
    "validate_pending_transition",
)
_GOVERNED_BLOCKED_FINALITY_EXPORTS_V1: Final = (
    "GovernedBlockedFinalityBindingV1",
    "IntegrityInstanceSealedError",
    "IntegrityRecoveryNotAuthorizedError",
)
__all__ = __all__ + _GOVERNED_BLOCKED_FINALITY_EXPORTS_V1

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
_KEY_ID = re.compile(r"^ed25519:sha256:[0-9a-f]{64}$", re.ASCII)
_IDENTITY = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{1,127}$", re.ASCII)


class IntegrityTransitionError(ProtocolError):
    """One modeled integrity transition or retained recovery record is invalid."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class IntegrityFinalityPendingError(IntegrityTransitionError):
    """The local event is durable but modeled finality is not yet complete."""


class IntegrityFinalityBlockedError(IntegrityTransitionError):
    """Finality cannot advance without resolving contradictory retained material."""


class IntegrityInstanceSealedError(IntegrityTransitionError):
    """A terminal governed seal forbids every further consequential command."""


class IntegrityRecoveryNotAuthorizedError(IntegrityTransitionError):
    """A durable block requires an authorized governed retry before advancing."""


def _reject(reason_code: str, message: str) -> None:
    raise IntegrityTransitionError(reason_code, message)


def _require_digest(value: object, field: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        _reject(f"invalid_{field}", f"{field} must be a full lowercase sha256 digest")
    return value


def _require_identity(value: object, field: str) -> str:
    if type(value) is not str or _IDENTITY.fullmatch(value) is None:
        _reject(f"invalid_{field}", f"{field} must be a bounded ASCII identity")
    return value


def _require_key_id(value: object, field: str) -> str:
    if type(value) is not str or _KEY_ID.fullmatch(value) is None:
        _reject(f"invalid_{field}", f"{field} must be a full Ed25519 key identity")
    return value


def _require_nonnegative_int(value: object, field: str) -> int:
    if type(value) is not int or value < 0 or value > (2**63) - 1:
        _reject(f"invalid_{field}", f"{field} must be a nonnegative signed-int64")
    return value


def _require_exact_dict(
    value: object,
    fields: frozenset[str],
    label: str,
) -> dict[str, object]:
    if type(value) is not dict or set(value) != fields:
        _reject(
            f"invalid_{label}",
            f"{label} has missing or unknown fields",
        )
    return value


def _decode_b64(value: object, field: str, *, maximum: int) -> bytes:
    if type(value) is not str or not value:
        _reject(f"invalid_{field}", f"{field} must be canonical Base64 text")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise IntegrityTransitionError(
            f"invalid_{field}",
            f"{field} is not canonical Base64",
        ) from exc
    if not decoded or len(decoded) > maximum or base64.b64encode(decoded).decode("ascii") != value:
        _reject(
            f"invalid_{field}",
            f"{field} is empty, oversized, or noncanonical",
        )
    return decoded


def _record_bytes(body: dict[str, object]) -> bytes:
    try:
        return canonical_dumps(body)
    except (ProtocolError, TypeError, ValueError) as exc:
        raise IntegrityTransitionError(
            "invalid_integrity_record",
            "integrity recovery record is not canonical protocol JSON",
        ) from exc


def _record_body(data: bytes | str, kind: str) -> dict[str, object]:
    try:
        parsed = strict_loads(data)
    except (ProtocolError, TypeError, ValueError) as exc:
        raise IntegrityTransitionError(
            "invalid_integrity_record",
            "integrity recovery record is not canonical JSON",
        ) from exc
    if type(parsed) is not dict:
        _reject("invalid_integrity_record", "integrity recovery record must be an object")
    if parsed.get("record_kind") != kind or parsed.get("record_version") != INTEGRITY_TRANSITION_RECORD_VERSION_V1:
        _reject(
            "invalid_integrity_record",
            "integrity recovery record has an unsupported kind or version",
        )
    if _record_bytes(parsed) != (data.encode("utf-8") if type(data) is str else data):
        _reject(
            "noncanonical_integrity_record",
            "integrity recovery record bytes are not canonical",
        )
    return parsed


def _snapshot_reference(value: object) -> EvidenceReferenceV1:
    if type(value) is not EvidenceReferenceV1:
        _reject(
            "invalid_evidence_reference",
            "provider evidence requires exact EvidenceReferenceV1 values",
        )
    try:
        return EvidenceReferenceV1(
            evidence_kind=value.evidence_kind,
            source_id=value.source_id,
            evidence_id=value.evidence_id,
        )
    except (AttributeError, IntegrityError, TypeError, ValueError) as exc:
        raise IntegrityTransitionError(
            "invalid_evidence_reference",
            "provider evidence reference is malformed",
        ) from exc


@dataclass(frozen=True, slots=True)
class ProviderEvidenceBlobV1:
    """One exact bounded provider-evidence BLOB and its typed reference.

    The identity is the raw SHA-256 digest of ``content``.  A source label is only a
    deterministic binding; this fixture type does not claim that labels denote independent
    operators.
    """

    evidence_kind: str
    source_id: str
    evidence_id: str
    content: bytes

    def __post_init__(self) -> None:
        reference = _snapshot_reference(
            EvidenceReferenceV1(
                evidence_kind=self.evidence_kind,
                source_id=self.source_id,
                evidence_id=self.evidence_id,
            )
        )
        if (
            type(self.content) is not bytes
            or not self.content
            or len(self.content) > MAX_PROVIDER_EVIDENCE_BLOB_BYTES_V1
        ):
            _reject(
                "invalid_provider_evidence_blob",
                "provider evidence must be a nonempty bounded immutable BLOB",
            )
        expected = "sha256:" + hashlib.sha256(self.content).hexdigest()
        if reference.evidence_id != expected:
            _reject(
                "provider_evidence_digest_mismatch",
                "provider evidence identity does not match its exact bytes",
            )
        object.__setattr__(self, "evidence_kind", reference.evidence_kind)
        object.__setattr__(self, "source_id", reference.source_id)
        object.__setattr__(self, "evidence_id", reference.evidence_id)
        object.__setattr__(self, "content", bytes(self.content))

    @classmethod
    def from_content(
        cls,
        *,
        evidence_kind: str,
        source_id: str,
        content: bytes,
    ) -> ProviderEvidenceBlobV1:
        if type(content) is not bytes:
            _reject(
                "invalid_provider_evidence_blob",
                "provider evidence content must be immutable bytes",
            )
        return cls(
            evidence_kind=evidence_kind,
            source_id=source_id,
            evidence_id="sha256:" + hashlib.sha256(content).hexdigest(),
            content=content,
        )

    @property
    def reference(self) -> EvidenceReferenceV1:
        return EvidenceReferenceV1(
            evidence_kind=self.evidence_kind,
            source_id=self.source_id,
            evidence_id=self.evidence_id,
        )

    def to_body(self) -> dict[str, object]:
        return {
            "content_b64": base64.b64encode(self.content).decode("ascii"),
            "evidence_id": self.evidence_id,
            "evidence_kind": self.evidence_kind,
            "source_id": self.source_id,
        }

    @classmethod
    def from_body(cls, value: object) -> ProviderEvidenceBlobV1:
        body = _require_exact_dict(
            value,
            frozenset(
                {
                    "content_b64",
                    "evidence_id",
                    "evidence_kind",
                    "source_id",
                }
            ),
            "provider_evidence_blob",
        )
        return cls(
            evidence_kind=body["evidence_kind"],  # type: ignore[arg-type]
            source_id=body["source_id"],  # type: ignore[arg-type]
            evidence_id=body["evidence_id"],  # type: ignore[arg-type]
            content=_decode_b64(
                body["content_b64"],
                "provider_evidence_content",
                maximum=MAX_PROVIDER_EVIDENCE_BLOB_BYTES_V1,
            ),
        )


def _validated_evidence_blobs(
    values: object,
) -> tuple[ProviderEvidenceBlobV1, ...]:
    if type(values) is not tuple or len(values) > MAX_PROVIDER_EVIDENCE_BLOBS_V1:
        _reject(
            "invalid_provider_evidence_set",
            "provider evidence must be a bounded tuple",
        )
    copied = tuple(
        ProviderEvidenceBlobV1(
            evidence_kind=value.evidence_kind,
            source_id=value.source_id,
            evidence_id=value.evidence_id,
            content=value.content,
        )
        if type(value) is ProviderEvidenceBlobV1
        else _invalid_provider_blob()
        for value in values
    )
    canonical = tuple(
        sorted(
            copied,
            key=lambda item: (
                item.evidence_kind,
                item.source_id,
                item.evidence_id,
            ),
        )
    )
    keys = [(item.evidence_kind, item.source_id, item.evidence_id) for item in canonical]
    if (
        copied != canonical
        or len(keys) != len(set(keys))
        or sum(len(item.content) for item in canonical) > MAX_PROVIDER_EVIDENCE_TOTAL_BYTES_V1
    ):
        _reject(
            "invalid_provider_evidence_set",
            "provider evidence must be sorted, unique, and within the aggregate ceiling",
        )
    identities: dict[str, bytes] = {}
    for item in canonical:
        prior = identities.setdefault(item.evidence_id, item.content)
        if prior != item.content:
            _reject(
                "provider_evidence_identity_collision",
                "one provider evidence identity names different bytes",
            )
    return canonical


def _invalid_provider_blob() -> ProviderEvidenceBlobV1:
    _reject(
        "invalid_provider_evidence_blob",
        "provider evidence set contains a non-ProviderEvidenceBlobV1 value",
    )


def _reference_key(
    value: EvidenceReferenceV1,
) -> tuple[str, str, str]:
    return (value.evidence_kind, value.source_id, value.evidence_id)


def _require_exact_evidence_coverage(
    references: tuple[EvidenceReferenceV1, ...],
    blobs: tuple[ProviderEvidenceBlobV1, ...],
    *,
    label: str,
) -> None:
    expected = {_reference_key(_snapshot_reference(value)) for value in references}
    observed = {(value.evidence_kind, value.source_id, value.evidence_id) for value in blobs}
    if observed != expected:
        missing = sorted(expected - observed)
        unexpected = sorted(observed - expected)
        _reject(
            f"{label}_evidence_coverage_mismatch",
            f"{label} provider evidence differs: missing={missing}, unexpected={unexpected}",
        )


def _trust_store_body(value: IntegrityTrustStore) -> dict[str, object]:
    if type(value) is not IntegrityTrustStore:
        _reject("invalid_integrity_trust_store", "exact IntegrityTrustStore required")
    try:
        return value.to_snapshot_body()
    except (AttributeError, IntegrityError, TypeError, ValueError) as exc:
        raise IntegrityTransitionError(
            "invalid_integrity_trust_store",
            "integrity trust-store snapshot is invalid",
        ) from exc


def _trust_store_from_body(value: object) -> IntegrityTrustStore:
    try:
        return IntegrityTrustStore.from_snapshot_body(value)
    except (IntegrityError, TypeError, ValueError) as exc:
        raise IntegrityTransitionError(
            "invalid_integrity_trust_store",
            "integrity trust-store snapshot is invalid",
        ) from exc


def _snapshot_trust_store(value: object) -> IntegrityTrustStore:
    return _trust_store_from_body(_trust_store_body(value))  # type: ignore[arg-type]


_MODELED_AUTHORITY_BINDING_FIELDS: Final = frozenset(
    {
        "adapter_profile",
        "adapter_version",
        "checkpoint_key_id",
        "checkpoint_principal_id",
        "decision_key_id",
        "decision_principal_id",
        "trust_snapshot",
        "trust_snapshot_id",
    }
)


@dataclass(frozen=True, slots=True)
class ModeledIntegrityAuthorityBindingV1:
    """Canonical fixture-adapter authority pinned at modeled-store enrollment.

    The complete trust snapshot is retained with its derived identity so enrollment
    cannot accept a structurally plausible binding whose key and principal claims are
    unverifiable.  This remains repository-owned fixture authority, not evidence of
    independent key custody or external administration.
    """

    adapter_profile: str
    adapter_version: int
    trust_snapshot_id: str
    trust_store: IntegrityTrustStore
    decision_key_id: str
    decision_principal_id: str
    checkpoint_key_id: str
    checkpoint_principal_id: str

    def __post_init__(self) -> None:
        if (
            type(self.adapter_profile) is not str
            or self.adapter_profile != MODELED_INTEGRITY_ADAPTER_PROFILE_V1
            or type(self.adapter_version) is not int
            or self.adapter_version != MODELED_INTEGRITY_ADAPTER_VERSION_V1
        ):
            _reject(
                "invalid_modeled_integrity_authority_binding",
                "modeled authority binding requires the exact adapter profile and version",
            )
        trust_store = _snapshot_trust_store(self.trust_store)
        trust_snapshot_id = _require_digest(
            self.trust_snapshot_id,
            "trust_snapshot_id",
        )
        decision_key_id = _require_key_id(
            self.decision_key_id,
            "decision_key_id",
        )
        checkpoint_key_id = _require_key_id(
            self.checkpoint_key_id,
            "checkpoint_key_id",
        )
        decision_principal_id = _require_identity(
            self.decision_principal_id,
            "decision_principal_id",
        )
        checkpoint_principal_id = _require_identity(
            self.checkpoint_principal_id,
            "checkpoint_principal_id",
        )
        decision_key = trust_store.keys.get(decision_key_id)
        checkpoint_key = trust_store.keys.get(checkpoint_key_id)
        if (
            trust_store.snapshot_id != trust_snapshot_id
            or decision_key is None
            or checkpoint_key is None
            or decision_key.role != INTEGRITY_DECISION_ROLE
            or checkpoint_key.role != HEAD_CHECKPOINT_ROLE
            or decision_key.principal_id != decision_principal_id
            or checkpoint_key.principal_id != checkpoint_principal_id
            or decision_key_id in trust_store.revoked_key_ids
            or checkpoint_key_id in trust_store.revoked_key_ids
            or decision_key_id == checkpoint_key_id
            or decision_principal_id == checkpoint_principal_id
        ):
            _reject(
                "invalid_modeled_integrity_authority_binding",
                "modeled authority binding disagrees with its exact usable trust snapshot",
            )
        object.__setattr__(self, "trust_store", trust_store)
        object.__setattr__(self, "trust_snapshot_id", trust_snapshot_id)
        object.__setattr__(self, "decision_key_id", decision_key_id)
        object.__setattr__(self, "decision_principal_id", decision_principal_id)
        object.__setattr__(self, "checkpoint_key_id", checkpoint_key_id)
        object.__setattr__(
            self,
            "checkpoint_principal_id",
            checkpoint_principal_id,
        )

    @property
    def binding_id(self) -> str:
        return content_id(
            "modeled_integrity_authority_binding",
            self.to_body(),
        )

    def to_body(self) -> dict[str, object]:
        return {
            "adapter_profile": self.adapter_profile,
            "adapter_version": self.adapter_version,
            "checkpoint_key_id": self.checkpoint_key_id,
            "checkpoint_principal_id": self.checkpoint_principal_id,
            "decision_key_id": self.decision_key_id,
            "decision_principal_id": self.decision_principal_id,
            "trust_snapshot": _trust_store_body(self.trust_store),
            "trust_snapshot_id": self.trust_snapshot_id,
        }

    def to_canonical_bytes(self) -> bytes:
        return _record_bytes(self.to_body())

    @classmethod
    def from_canonical_bytes(
        cls,
        data: bytes | str,
    ) -> ModeledIntegrityAuthorityBindingV1:
        try:
            parsed = strict_loads(data)
        except (ProtocolError, TypeError, ValueError) as exc:
            raise IntegrityTransitionError(
                "invalid_modeled_integrity_authority_binding",
                "modeled authority binding is not canonical JSON",
            ) from exc
        body = _require_exact_dict(
            parsed,
            _MODELED_AUTHORITY_BINDING_FIELDS,
            "modeled_integrity_authority_binding",
        )
        wire = data.encode("utf-8") if type(data) is str else data
        if type(wire) is not bytes or _record_bytes(body) != wire:
            _reject(
                "invalid_modeled_integrity_authority_binding",
                "modeled authority binding bytes are noncanonical",
            )
        return cls(
            adapter_profile=body["adapter_profile"],  # type: ignore[arg-type]
            adapter_version=body["adapter_version"],  # type: ignore[arg-type]
            trust_snapshot_id=body["trust_snapshot_id"],  # type: ignore[arg-type]
            trust_store=_trust_store_from_body(body["trust_snapshot"]),
            decision_key_id=body["decision_key_id"],  # type: ignore[arg-type]
            decision_principal_id=body["decision_principal_id"],  # type: ignore[arg-type]
            checkpoint_key_id=body["checkpoint_key_id"],  # type: ignore[arg-type]
            checkpoint_principal_id=body["checkpoint_principal_id"],  # type: ignore[arg-type]
        )


def _snapshot_modeled_authority_binding(
    value: object,
) -> ModeledIntegrityAuthorityBindingV1:
    if type(value) is not ModeledIntegrityAuthorityBindingV1:
        _reject(
            "invalid_modeled_integrity_authority_binding",
            "exact ModeledIntegrityAuthorityBindingV1 required",
        )
    return ModeledIntegrityAuthorityBindingV1.from_canonical_bytes(value.to_canonical_bytes())


def _policy_body(value: IntegrityValidationPolicyV1) -> dict[str, object]:
    if type(value) is not IntegrityValidationPolicyV1:
        _reject(
            "invalid_integrity_validation_policy",
            "exact IntegrityValidationPolicyV1 required",
        )
    try:
        return value.to_body()
    except (AttributeError, IntegrityError, TypeError, ValueError) as exc:
        raise IntegrityTransitionError(
            "invalid_integrity_validation_policy",
            "integrity validation policy snapshot is invalid",
        ) from exc


def _policy_from_body(value: object) -> IntegrityValidationPolicyV1:
    try:
        return IntegrityValidationPolicyV1.from_body(value)
    except (IntegrityError, TypeError, ValueError) as exc:
        raise IntegrityTransitionError(
            "invalid_integrity_validation_policy",
            "integrity validation policy snapshot is invalid",
        ) from exc


def _snapshot_policy(value: object) -> IntegrityValidationPolicyV1:
    return _policy_from_body(_policy_body(value))  # type: ignore[arg-type]


def _revocation_floor_body(value: RevocationFloorV1) -> dict[str, object]:
    if type(value) is not RevocationFloorV1:
        _reject(
            "invalid_revocation_floor",
            "exact RevocationFloorV1 required",
        )
    try:
        return value.to_body()
    except (AttributeError, IntegrityError, TypeError, ValueError) as exc:
        raise IntegrityTransitionError(
            "invalid_revocation_floor",
            "revocation floor snapshot is invalid",
        ) from exc


def _revocation_floor_from_body(value: object) -> RevocationFloorV1:
    try:
        return RevocationFloorV1.from_body(value)
    except (IntegrityError, TypeError, ValueError) as exc:
        raise IntegrityTransitionError(
            "invalid_revocation_floor",
            "revocation floor snapshot is invalid",
        ) from exc


def _head_floor_body(value: HeadCheckpointFloorV1) -> dict[str, object]:
    if type(value) is not HeadCheckpointFloorV1:
        _reject(
            "invalid_head_checkpoint_floor",
            "exact HeadCheckpointFloorV1 required",
        )
    try:
        return value.to_body()
    except (AttributeError, IntegrityError, TypeError, ValueError) as exc:
        raise IntegrityTransitionError(
            "invalid_head_checkpoint_floor",
            "head checkpoint floor snapshot is invalid",
        ) from exc


def _head_floor_from_body(value: object) -> HeadCheckpointFloorV1:
    try:
        return HeadCheckpointFloorV1.from_body(value)
    except (IntegrityError, TypeError, ValueError) as exc:
        raise IntegrityTransitionError(
            "invalid_head_checkpoint_floor",
            "head checkpoint floor snapshot is invalid",
        ) from exc


def _snapshot_signed_decision(value: object) -> SignedIntegrityDecisionV1:
    if type(value) is not SignedIntegrityDecisionV1:
        _reject(
            "invalid_signed_integrity_decision",
            "exact SignedIntegrityDecisionV1 required",
        )
    try:
        return SignedIntegrityDecisionV1(
            envelope_bytes=value.envelope_bytes,
            key_id=value.key_id,
            signature_b64=value.signature_b64,
        )
    except (AttributeError, IntegrityError, ProtocolError, TypeError, ValueError) as exc:
        raise IntegrityTransitionError(
            "invalid_signed_integrity_decision",
            "signed integrity decision is malformed",
        ) from exc


def _decision_from_signed(
    value: SignedIntegrityDecisionV1,
) -> IntegrityDecisionV1:
    try:
        return IntegrityDecisionV1.from_envelope(EnvelopeV1.from_bytes(value.envelope_bytes))
    except (IntegrityError, ProtocolError, TypeError, ValueError) as exc:
        raise IntegrityTransitionError(
            "invalid_signed_integrity_decision",
            "signed integrity decision semantics are invalid",
        ) from exc


def _snapshot_signed_checkpoint(value: object) -> SignedHeadCheckpointV1:
    if type(value) is not SignedHeadCheckpointV1:
        _reject(
            "invalid_signed_head_checkpoint",
            "exact SignedHeadCheckpointV1 required",
        )
    try:
        return SignedHeadCheckpointV1(
            envelope_bytes=value.envelope_bytes,
            key_id=value.key_id,
            signature_b64=value.signature_b64,
        )
    except (AttributeError, IntegrityError, ProtocolError, TypeError, ValueError) as exc:
        raise IntegrityTransitionError(
            "invalid_signed_head_checkpoint",
            "signed head checkpoint is malformed",
        ) from exc


def _checkpoint_from_signed(
    value: SignedHeadCheckpointV1,
) -> HeadCheckpointV1:
    try:
        return HeadCheckpointV1.from_envelope(EnvelopeV1.from_bytes(value.envelope_bytes))
    except (IntegrityError, ProtocolError, TypeError, ValueError) as exc:
        raise IntegrityTransitionError(
            "invalid_signed_head_checkpoint",
            "signed head checkpoint semantics are invalid",
        ) from exc


def _evidence_blobs_from_body(
    value: object,
) -> tuple[ProviderEvidenceBlobV1, ...]:
    if type(value) is not list:
        _reject(
            "invalid_provider_evidence_set",
            "provider evidence must be a canonical array",
        )
    return _validated_evidence_blobs(tuple(ProviderEvidenceBlobV1.from_body(item) for item in value))


@dataclass(frozen=True, slots=True)
class PendingIntegrityTransitionV1:
    """The exact decision dossier committed atomically with one local event."""

    event_digest: str
    mission_id: str
    event_seq: int
    instance_sequence: int
    signed_decision: SignedIntegrityDecisionV1
    decision_trust_store: IntegrityTrustStore
    validation_policy: IntegrityValidationPolicyV1
    revocation_floors: tuple[RevocationFloorV1, ...]
    prior_head_floor: HeadCheckpointFloorV1
    provider_evidence: tuple[ProviderEvidenceBlobV1, ...]

    def __post_init__(self) -> None:
        _require_digest(self.event_digest, "event_digest")
        _require_digest(self.mission_id, "mission_id")
        _require_nonnegative_int(self.event_seq, "event_seq")
        _require_nonnegative_int(self.instance_sequence, "instance_sequence")
        signed = _snapshot_signed_decision(self.signed_decision)
        decision = _decision_from_signed(signed)
        trust_store = _snapshot_trust_store(self.decision_trust_store)
        policy = _snapshot_policy(self.validation_policy)
        if (
            decision.proposed_event_digest != self.event_digest
            or decision.mission_id != self.mission_id
            or decision.prior_event_seq + 1 != self.event_seq
            or decision.prior_global_checkpoint_sequence + 1 != self.instance_sequence
            or decision.decision_policy_id != policy.decision_policy_id
            or decision.time_policy_id != policy.decision_time_policy_id
        ):
            _reject(
                "pending_transition_binding_mismatch",
                "pending decision differs from the retained transition coordinates",
            )
        if type(self.revocation_floors) is not tuple or len(self.revocation_floors) > MAX_REVOCATION_VIEWS:
            _reject(
                "invalid_revocation_floor_set",
                "revocation floors must be an exact bounded tuple",
            )
        floors: list[RevocationFloorV1] = []
        for value in self.revocation_floors:
            try:
                floors.append(_revocation_floor_from_body(_revocation_floor_body(value)))
            except (IntegrityError, TypeError, ValueError) as exc:
                raise IntegrityTransitionError(
                    "invalid_revocation_floor",
                    "pending transition contains an invalid revocation floor",
                ) from exc
        canonical_floors = tuple(sorted(floors, key=lambda value: value.namespace))
        if tuple(floors) != canonical_floors or len({value.namespace for value in floors}) != len(floors):
            _reject(
                "invalid_revocation_floor_set",
                "revocation floors must be namespace-sorted and unique",
            )
        views = {value.namespace: value for value in decision.revocation_views}
        if set(views) != {value.namespace for value in canonical_floors}:
            _reject(
                "revocation_floor_set_mismatch",
                "pending decision and external revocation floors cover different namespaces",
            )
        for floor in canonical_floors:
            view = views[floor.namespace]
            if (
                floor.service_instance_id != decision.service_instance_id
                or floor.environment_id != decision.environment_id
                or floor.decision_policy_id != decision.decision_policy_id
                or floor.root_version != view.root_version
                or floor.version != view.version
                or floor.snapshot_id != view.snapshot_id
            ):
                _reject(
                    "revocation_floor_mismatch",
                    "modeled revocation floor differs from its decision view",
                )
        head_floor = _head_floor_from_body(_head_floor_body(self.prior_head_floor))
        if (
            head_floor.service_instance_id != decision.service_instance_id
            or head_floor.environment_id != decision.environment_id
            or head_floor.mission_id != decision.mission_id
            or head_floor.instance_sequence != decision.prior_global_checkpoint_sequence
            or head_floor.checkpoint_id != decision.prior_global_checkpoint_id
            or head_floor.checkpoint_attestation_id != decision.prior_global_checkpoint_attestation_id
            or head_floor.checkpoint_principal_id != decision.prior_global_checkpoint_principal_id
            or head_floor.checkpoint_trust_snapshot_id != decision.prior_global_checkpoint_trust_snapshot_id
            or head_floor.mission_event_seq != decision.prior_event_seq
        ):
            _reject(
                "prior_head_floor_mismatch",
                "modeled external head floor differs from the decision predecessors",
            )
        blobs = _validated_evidence_blobs(self.provider_evidence)
        references = (
            *decision.time_evidence,
            *(view.evidence for view in decision.revocation_views),
            *(reference for floor in canonical_floors for reference in floor.evidence),
            *head_floor.evidence,
        )
        _require_exact_evidence_coverage(
            tuple(references),
            blobs,
            label="pending_transition",
        )
        _validate_modeled_pending_provider_evidence(
            decision=decision,
            revocation_floors=canonical_floors,
            prior_head_floor=head_floor,
            blobs=blobs,
        )
        object.__setattr__(self, "signed_decision", signed)
        object.__setattr__(self, "decision_trust_store", trust_store)
        object.__setattr__(self, "validation_policy", policy)
        object.__setattr__(self, "revocation_floors", canonical_floors)
        object.__setattr__(self, "prior_head_floor", head_floor)
        object.__setattr__(self, "provider_evidence", blobs)

    @property
    def decision(self) -> IntegrityDecisionV1:
        return _decision_from_signed(self.signed_decision)

    @property
    def record_id(self) -> str:
        return content_id("pending_integrity_transition_record", self.to_body())

    def to_body(self) -> dict[str, object]:
        return {
            "decision_trust_store": _trust_store_body(self.decision_trust_store),
            "event_digest": self.event_digest,
            "event_seq": self.event_seq,
            "instance_sequence": self.instance_sequence,
            "mission_id": self.mission_id,
            "provider_evidence": [value.to_body() for value in self.provider_evidence],
            "prior_head_floor": _head_floor_body(self.prior_head_floor),
            "record_kind": "pending_integrity_transition",
            "record_version": INTEGRITY_TRANSITION_RECORD_VERSION_V1,
            "revocation_floors": [_revocation_floor_body(value) for value in self.revocation_floors],
            "signed_decision_b64": base64.b64encode(self.signed_decision.to_bytes()).decode("ascii"),
            "validation_policy": _policy_body(self.validation_policy),
        }

    def to_canonical_bytes(self) -> bytes:
        return _record_bytes(self.to_body())

    @classmethod
    def from_canonical_bytes(
        cls,
        data: bytes | str,
    ) -> PendingIntegrityTransitionV1:
        body = _require_exact_dict(
            _record_body(data, "pending_integrity_transition"),
            frozenset(
                {
                    "decision_trust_store",
                    "event_digest",
                    "event_seq",
                    "instance_sequence",
                    "mission_id",
                    "provider_evidence",
                    "prior_head_floor",
                    "record_kind",
                    "record_version",
                    "revocation_floors",
                    "signed_decision_b64",
                    "validation_policy",
                }
            ),
            "pending_integrity_transition",
        )
        floors = body["revocation_floors"]
        if type(floors) is not list:
            _reject(
                "invalid_revocation_floor_set",
                "revocation floors must be a canonical array",
            )
        signed_wire = _decode_b64(
            body["signed_decision_b64"],
            "signed_decision",
            maximum=1 << 20,
        )
        return cls(
            event_digest=body["event_digest"],  # type: ignore[arg-type]
            mission_id=body["mission_id"],  # type: ignore[arg-type]
            event_seq=body["event_seq"],  # type: ignore[arg-type]
            instance_sequence=body["instance_sequence"],  # type: ignore[arg-type]
            signed_decision=SignedIntegrityDecisionV1.from_bytes(signed_wire),
            decision_trust_store=_trust_store_from_body(body["decision_trust_store"]),
            validation_policy=_policy_from_body(body["validation_policy"]),
            revocation_floors=tuple(_revocation_floor_from_body(value) for value in floors),
            prior_head_floor=_head_floor_from_body(body["prior_head_floor"]),
            provider_evidence=_evidence_blobs_from_body(body["provider_evidence"]),
        )


_ANCHOR_REGISTRATION_FIELDS: Final = frozenset(
    {
        "anchor_policy_id",
        "authority_id",
        "environment_id",
        "event_digest",
        "event_seq",
        "instance_sequence",
        "integrity_decision_attestation_id",
        "integrity_decision_id",
        "integrity_decision_principal_id",
        "integrity_decision_trust_snapshot_id",
        "mission_id",
        "previous_checkpoint_attestation_id",
        "previous_checkpoint_id",
        "previous_checkpoint_principal_id",
        "previous_checkpoint_trust_snapshot_id",
        "previous_mission_checkpoint_attestation_id",
        "previous_mission_checkpoint_id",
        "previous_mission_checkpoint_principal_id",
        "previous_mission_checkpoint_trust_snapshot_id",
        "service_instance_id",
        "target_id",
        "time_evidence",
        "time_lower_bound",
        "time_policy_id",
        "time_upper_bound",
    }
)


def _anchor_registration_body_from_bytes(
    data: bytes,
) -> dict[str, object]:
    if type(data) is not bytes or not data or len(data) > (1 << 20):
        _reject(
            "invalid_anchor_registration_request",
            "anchor registration request must be nonempty bounded canonical bytes",
        )
    try:
        parsed = strict_loads(data)
    except (ProtocolError, TypeError, ValueError) as exc:
        raise IntegrityTransitionError(
            "invalid_anchor_registration_request",
            "anchor registration request is not canonical JSON",
        ) from exc
    body = _require_exact_dict(
        parsed,
        _ANCHOR_REGISTRATION_FIELDS,
        "anchor_registration_request",
    )
    if _record_bytes(body) != data:
        _reject(
            "invalid_anchor_registration_request",
            "anchor registration request bytes are noncanonical",
        )
    return body


@dataclass(frozen=True, slots=True)
class AnchorStatementRecordV1:
    """The persisted pre-receipt anchor statement prepared after local commit."""

    pending_record_id: str
    event_digest: str
    previous_mission_checkpoint_id: str
    previous_mission_checkpoint_attestation_id: str | None
    previous_mission_checkpoint_principal_id: str | None
    previous_mission_checkpoint_trust_snapshot_id: str | None
    time_lower_bound: int
    time_upper_bound: int
    time_policy_id: str
    time_evidence: tuple[EvidenceReferenceV1, ...]
    anchor_policy_id: str
    anchor_statement_id: str
    registration_request: bytes
    provider_evidence: tuple[ProviderEvidenceBlobV1, ...]

    def __post_init__(self) -> None:
        _require_digest(self.pending_record_id, "pending_record_id")
        _require_digest(self.event_digest, "event_digest")
        _require_digest(
            self.previous_mission_checkpoint_id,
            "previous_mission_checkpoint_id",
        )
        values = (
            self.previous_mission_checkpoint_attestation_id,
            self.previous_mission_checkpoint_principal_id,
            self.previous_mission_checkpoint_trust_snapshot_id,
        )
        if any(value is None for value in values) and any(value is not None for value in values):
            _reject(
                "incomplete_mission_checkpoint_provenance",
                "mission checkpoint predecessor provenance must be all present or all absent",
            )
        if values[0] is not None:
            _require_digest(
                values[0],
                "previous_mission_checkpoint_attestation_id",
            )
            _require_identity(
                values[1],
                "previous_mission_checkpoint_principal_id",
            )
            _require_digest(
                values[2],
                "previous_mission_checkpoint_trust_snapshot_id",
            )
        lower = _require_nonnegative_int(
            self.time_lower_bound,
            "time_lower_bound",
        )
        upper = _require_nonnegative_int(
            self.time_upper_bound,
            "time_upper_bound",
        )
        if lower > upper:
            _reject(
                "invalid_checkpoint_time_interval",
                "checkpoint time lower bound exceeds its upper bound",
            )
        _require_digest(self.time_policy_id, "time_policy_id")
        _require_digest(self.anchor_policy_id, "anchor_policy_id")
        _require_digest(self.anchor_statement_id, "anchor_statement_id")
        if type(self.registration_request) is not bytes:
            _reject(
                "invalid_anchor_registration_request",
                "anchor registration request must be immutable bytes",
            )
        registration_request = bytes(self.registration_request)
        registration_body = _anchor_registration_body_from_bytes(registration_request)
        if content_id("head_anchor_statement", registration_body) != self.anchor_statement_id:
            _reject(
                "anchor_statement_binding_mismatch",
                "anchor statement identity differs from its exact registration request",
            )
        if (
            type(self.time_evidence) is not tuple
            or len(self.time_evidence)
            != len(_MODELED_PROVIDER_SUFFIXES_V1)
        ):
            _reject(
                "invalid_checkpoint_time_evidence",
                "checkpoint time evidence must be an exact modeled-source pair",
            )
        references = tuple(_snapshot_reference(value) for value in self.time_evidence)
        if (
            references != tuple(sorted(references, key=lambda value: value.source_id))
            or len({value.source_id for value in references}) != len(references)
            or len({value.evidence_id for value in references}) != len(references)
            or any(value.evidence_kind != TRUSTED_TIME_EVIDENCE_KIND for value in references)
        ):
            _reject(
                "invalid_checkpoint_time_evidence",
                "checkpoint time evidence must be sorted, typed, and source-distinct",
            )
        if (
            registration_body["event_digest"] != self.event_digest
            or registration_body["previous_mission_checkpoint_id"] != self.previous_mission_checkpoint_id
            or registration_body["previous_mission_checkpoint_attestation_id"]
            != self.previous_mission_checkpoint_attestation_id
            or registration_body["previous_mission_checkpoint_principal_id"]
            != self.previous_mission_checkpoint_principal_id
            or registration_body["previous_mission_checkpoint_trust_snapshot_id"]
            != self.previous_mission_checkpoint_trust_snapshot_id
            or registration_body["time_lower_bound"] != self.time_lower_bound
            or registration_body["time_upper_bound"] != self.time_upper_bound
            or registration_body["time_policy_id"] != self.time_policy_id
            or registration_body["time_evidence"] != [reference.to_body() for reference in references]
            or registration_body["anchor_policy_id"] != self.anchor_policy_id
        ):
            _reject(
                "anchor_statement_binding_mismatch",
                "anchor record fields differ from its exact registration request",
            )
        blobs = _validated_evidence_blobs(self.provider_evidence)
        _require_exact_evidence_coverage(
            references,
            blobs,
            label="anchor_statement",
        )
        _validate_modeled_anchor_provider_evidence(
            registration_body=registration_body,
            references=references,
            blobs=blobs,
        )
        object.__setattr__(self, "time_evidence", references)
        object.__setattr__(
            self,
            "registration_request",
            registration_request,
        )
        object.__setattr__(self, "provider_evidence", blobs)

    @property
    def registration_body(self) -> dict[str, object]:
        """Return a detached exact pre-receipt request body."""

        return _anchor_registration_body_from_bytes(self.registration_request)

    @property
    def record_id(self) -> str:
        return content_id("anchor_statement_record", self.to_body())

    def to_body(self) -> dict[str, object]:
        return {
            "anchor_policy_id": self.anchor_policy_id,
            "anchor_statement_id": self.anchor_statement_id,
            "event_digest": self.event_digest,
            "pending_record_id": self.pending_record_id,
            "previous_mission_checkpoint_attestation_id": (self.previous_mission_checkpoint_attestation_id),
            "previous_mission_checkpoint_id": (self.previous_mission_checkpoint_id),
            "previous_mission_checkpoint_principal_id": (self.previous_mission_checkpoint_principal_id),
            "previous_mission_checkpoint_trust_snapshot_id": (self.previous_mission_checkpoint_trust_snapshot_id),
            "provider_evidence": [value.to_body() for value in self.provider_evidence],
            "registration_request_b64": base64.b64encode(self.registration_request).decode("ascii"),
            "record_kind": "anchor_statement",
            "record_version": INTEGRITY_TRANSITION_RECORD_VERSION_V1,
            "time_evidence": [value.to_body() for value in self.time_evidence],
            "time_lower_bound": self.time_lower_bound,
            "time_policy_id": self.time_policy_id,
            "time_upper_bound": self.time_upper_bound,
        }

    def to_canonical_bytes(self) -> bytes:
        return _record_bytes(self.to_body())

    @classmethod
    def from_canonical_bytes(
        cls,
        data: bytes | str,
    ) -> AnchorStatementRecordV1:
        body = _require_exact_dict(
            _record_body(data, "anchor_statement"),
            frozenset(
                {
                    "anchor_policy_id",
                    "anchor_statement_id",
                    "event_digest",
                    "pending_record_id",
                    "previous_mission_checkpoint_attestation_id",
                    "previous_mission_checkpoint_id",
                    "previous_mission_checkpoint_principal_id",
                    "previous_mission_checkpoint_trust_snapshot_id",
                    "provider_evidence",
                    "registration_request_b64",
                    "record_kind",
                    "record_version",
                    "time_evidence",
                    "time_lower_bound",
                    "time_policy_id",
                    "time_upper_bound",
                }
            ),
            "anchor_statement",
        )
        evidence = body["time_evidence"]
        if type(evidence) is not list:
            _reject(
                "invalid_checkpoint_time_evidence",
                "checkpoint time evidence must be an array",
            )
        return cls(
            pending_record_id=body["pending_record_id"],  # type: ignore[arg-type]
            event_digest=body["event_digest"],  # type: ignore[arg-type]
            previous_mission_checkpoint_id=body["previous_mission_checkpoint_id"],  # type: ignore[arg-type]
            previous_mission_checkpoint_attestation_id=body["previous_mission_checkpoint_attestation_id"],  # type: ignore[arg-type]
            previous_mission_checkpoint_principal_id=body["previous_mission_checkpoint_principal_id"],  # type: ignore[arg-type]
            previous_mission_checkpoint_trust_snapshot_id=body["previous_mission_checkpoint_trust_snapshot_id"],  # type: ignore[arg-type]
            time_lower_bound=body["time_lower_bound"],  # type: ignore[arg-type]
            time_upper_bound=body["time_upper_bound"],  # type: ignore[arg-type]
            time_policy_id=body["time_policy_id"],  # type: ignore[arg-type]
            time_evidence=tuple(EvidenceReferenceV1.from_body(value) for value in evidence),
            anchor_policy_id=body["anchor_policy_id"],  # type: ignore[arg-type]
            anchor_statement_id=body["anchor_statement_id"],  # type: ignore[arg-type]
            registration_request=_decode_b64(
                body["registration_request_b64"],
                "anchor_registration_request",
                maximum=1 << 20,
            ),
            provider_evidence=_evidence_blobs_from_body(body["provider_evidence"]),
        )


@dataclass(frozen=True, slots=True)
class CheckpointCandidateRecordV1:
    """The exact signed checkpoint retained before modeled catalog publication."""

    pending_record_id: str
    anchor_statement_record_id: str
    event_digest: str
    signed_checkpoint: SignedHeadCheckpointV1
    checkpoint_trust_store: IntegrityTrustStore
    provider_evidence: tuple[ProviderEvidenceBlobV1, ...]

    def __post_init__(self) -> None:
        _require_digest(self.pending_record_id, "pending_record_id")
        _require_digest(
            self.anchor_statement_record_id,
            "anchor_statement_record_id",
        )
        _require_digest(self.event_digest, "event_digest")
        signed = _snapshot_signed_checkpoint(self.signed_checkpoint)
        checkpoint = _checkpoint_from_signed(signed)
        trust_store = _snapshot_trust_store(self.checkpoint_trust_store)
        if checkpoint.event_digest != self.event_digest:
            _reject(
                "checkpoint_candidate_binding_mismatch",
                "checkpoint candidate differs from its retained event digest",
            )
        blobs = _validated_evidence_blobs(self.provider_evidence)
        _require_exact_evidence_coverage(
            checkpoint.anchor_evidence,
            blobs,
            label="checkpoint_candidate",
        )
        _validate_modeled_checkpoint_provider_evidence(
            checkpoint=checkpoint,
            blobs=blobs,
        )
        object.__setattr__(self, "signed_checkpoint", signed)
        object.__setattr__(self, "checkpoint_trust_store", trust_store)
        object.__setattr__(self, "provider_evidence", blobs)

    @property
    def checkpoint(self) -> HeadCheckpointV1:
        return _checkpoint_from_signed(self.signed_checkpoint)

    @property
    def record_id(self) -> str:
        return content_id("checkpoint_candidate_record", self.to_body())

    def to_body(self) -> dict[str, object]:
        return {
            "anchor_statement_record_id": self.anchor_statement_record_id,
            "checkpoint_trust_store": _trust_store_body(self.checkpoint_trust_store),
            "event_digest": self.event_digest,
            "pending_record_id": self.pending_record_id,
            "provider_evidence": [value.to_body() for value in self.provider_evidence],
            "record_kind": "checkpoint_candidate",
            "record_version": INTEGRITY_TRANSITION_RECORD_VERSION_V1,
            "signed_checkpoint_b64": base64.b64encode(self.signed_checkpoint.to_bytes()).decode("ascii"),
        }

    def to_canonical_bytes(self) -> bytes:
        return _record_bytes(self.to_body())

    @classmethod
    def from_canonical_bytes(
        cls,
        data: bytes | str,
    ) -> CheckpointCandidateRecordV1:
        body = _require_exact_dict(
            _record_body(data, "checkpoint_candidate"),
            frozenset(
                {
                    "anchor_statement_record_id",
                    "checkpoint_trust_store",
                    "event_digest",
                    "pending_record_id",
                    "provider_evidence",
                    "record_kind",
                    "record_version",
                    "signed_checkpoint_b64",
                }
            ),
            "checkpoint_candidate",
        )
        signed_wire = _decode_b64(
            body["signed_checkpoint_b64"],
            "signed_checkpoint",
            maximum=1 << 20,
        )
        return cls(
            pending_record_id=body["pending_record_id"],  # type: ignore[arg-type]
            anchor_statement_record_id=body["anchor_statement_record_id"],  # type: ignore[arg-type]
            event_digest=body["event_digest"],  # type: ignore[arg-type]
            signed_checkpoint=SignedHeadCheckpointV1.from_bytes(signed_wire),
            checkpoint_trust_store=_trust_store_from_body(body["checkpoint_trust_store"]),
            provider_evidence=_evidence_blobs_from_body(body["provider_evidence"]),
        )


@dataclass(frozen=True, slots=True)
class FinalizedIntegrityTransitionV1:
    """A current modeled external floor over one retained checkpoint candidate."""

    pending_record_id: str
    checkpoint_candidate_record_id: str
    event_digest: str
    external_head_floor: HeadCheckpointFloorV1
    provider_evidence: tuple[ProviderEvidenceBlobV1, ...]

    def __post_init__(self) -> None:
        _require_digest(self.pending_record_id, "pending_record_id")
        _require_digest(
            self.checkpoint_candidate_record_id,
            "checkpoint_candidate_record_id",
        )
        _require_digest(self.event_digest, "event_digest")
        floor = _head_floor_from_body(_head_floor_body(self.external_head_floor))
        blobs = _validated_evidence_blobs(self.provider_evidence)
        _require_exact_evidence_coverage(
            floor.evidence,
            blobs,
            label="finalized_transition",
        )
        _validate_modeled_finalization_provider_evidence(
            floor=floor,
            blobs=blobs,
        )
        object.__setattr__(self, "external_head_floor", floor)
        object.__setattr__(self, "provider_evidence", blobs)

    @property
    def record_id(self) -> str:
        return content_id("finalized_integrity_transition_record", self.to_body())

    def to_body(self) -> dict[str, object]:
        return {
            "checkpoint_candidate_record_id": (self.checkpoint_candidate_record_id),
            "event_digest": self.event_digest,
            "external_head_floor": _head_floor_body(self.external_head_floor),
            "pending_record_id": self.pending_record_id,
            "provider_evidence": [value.to_body() for value in self.provider_evidence],
            "record_kind": "finalized_integrity_transition",
            "record_version": INTEGRITY_TRANSITION_RECORD_VERSION_V1,
        }

    def to_canonical_bytes(self) -> bytes:
        return _record_bytes(self.to_body())

    @classmethod
    def from_canonical_bytes(
        cls,
        data: bytes | str,
    ) -> FinalizedIntegrityTransitionV1:
        body = _require_exact_dict(
            _record_body(data, "finalized_integrity_transition"),
            frozenset(
                {
                    "checkpoint_candidate_record_id",
                    "event_digest",
                    "external_head_floor",
                    "pending_record_id",
                    "provider_evidence",
                    "record_kind",
                    "record_version",
                }
            ),
            "finalized_integrity_transition",
        )
        return cls(
            pending_record_id=body["pending_record_id"],  # type: ignore[arg-type]
            checkpoint_candidate_record_id=body["checkpoint_candidate_record_id"],  # type: ignore[arg-type]
            event_digest=body["event_digest"],  # type: ignore[arg-type]
            external_head_floor=_head_floor_from_body(body["external_head_floor"]),
            provider_evidence=_evidence_blobs_from_body(body["provider_evidence"]),
        )


def _snapshot_pending_record(
    value: object,
) -> PendingIntegrityTransitionV1:
    if type(value) is not PendingIntegrityTransitionV1:
        _reject(
            "invalid_integrity_lineage",
            "integrity lineage requires one exact pending record",
        )
    return PendingIntegrityTransitionV1(
        event_digest=value.event_digest,
        mission_id=value.mission_id,
        event_seq=value.event_seq,
        instance_sequence=value.instance_sequence,
        signed_decision=value.signed_decision,
        decision_trust_store=value.decision_trust_store,
        validation_policy=value.validation_policy,
        revocation_floors=value.revocation_floors,
        prior_head_floor=value.prior_head_floor,
        provider_evidence=value.provider_evidence,
    )


def _snapshot_anchor_record(
    value: object,
) -> AnchorStatementRecordV1:
    if type(value) is not AnchorStatementRecordV1:
        _reject(
            "invalid_integrity_lineage",
            "integrity lineage anchor record has the wrong type",
        )
    return AnchorStatementRecordV1(
        pending_record_id=value.pending_record_id,
        event_digest=value.event_digest,
        previous_mission_checkpoint_id=value.previous_mission_checkpoint_id,
        previous_mission_checkpoint_attestation_id=(value.previous_mission_checkpoint_attestation_id),
        previous_mission_checkpoint_principal_id=(value.previous_mission_checkpoint_principal_id),
        previous_mission_checkpoint_trust_snapshot_id=(value.previous_mission_checkpoint_trust_snapshot_id),
        time_lower_bound=value.time_lower_bound,
        time_upper_bound=value.time_upper_bound,
        time_policy_id=value.time_policy_id,
        time_evidence=value.time_evidence,
        anchor_policy_id=value.anchor_policy_id,
        anchor_statement_id=value.anchor_statement_id,
        registration_request=value.registration_request,
        provider_evidence=value.provider_evidence,
    )


def _snapshot_candidate_record(
    value: object,
) -> CheckpointCandidateRecordV1:
    if type(value) is not CheckpointCandidateRecordV1:
        _reject(
            "invalid_integrity_lineage",
            "integrity lineage checkpoint record has the wrong type",
        )
    return CheckpointCandidateRecordV1(
        pending_record_id=value.pending_record_id,
        anchor_statement_record_id=value.anchor_statement_record_id,
        event_digest=value.event_digest,
        signed_checkpoint=value.signed_checkpoint,
        checkpoint_trust_store=value.checkpoint_trust_store,
        provider_evidence=value.provider_evidence,
    )


def _snapshot_finalization_record(
    value: object,
) -> FinalizedIntegrityTransitionV1:
    if type(value) is not FinalizedIntegrityTransitionV1:
        _reject(
            "invalid_integrity_lineage",
            "integrity lineage finalization record has the wrong type",
        )
    return FinalizedIntegrityTransitionV1(
        pending_record_id=value.pending_record_id,
        checkpoint_candidate_record_id=value.checkpoint_candidate_record_id,
        event_digest=value.event_digest,
        external_head_floor=value.external_head_floor,
        provider_evidence=value.provider_evidence,
    )


@dataclass(frozen=True, slots=True)
class IntegrityLineageV1:
    """One immutable, gap-free local recovery lineage for an event transition."""

    pending: PendingIntegrityTransitionV1
    anchor_statement: AnchorStatementRecordV1 | None = None
    checkpoint_candidate: CheckpointCandidateRecordV1 | None = None
    finalization: FinalizedIntegrityTransitionV1 | None = None

    def __post_init__(self) -> None:
        if type(self.pending) is not PendingIntegrityTransitionV1:
            _reject(
                "invalid_integrity_lineage",
                "integrity lineage requires one exact pending record",
            )
        # Snapshot exact constructed records field-by-field.  Their constructors copy
        # every nested mapping, set, reference, signed transport, and BLOB, preserving
        # the anti-aliasing boundary without repeating full JSON/base64 round-trips.
        pending = _snapshot_pending_record(self.pending)
        pending_record_id = pending.record_id
        anchor = self.anchor_statement
        candidate = self.checkpoint_candidate
        finalization = self.finalization
        if anchor is None and (candidate is not None or finalization is not None):
            _reject(
                "integrity_lineage_gap",
                "checkpoint or finalization cannot exist without an anchor statement",
            )
        if candidate is None and finalization is not None:
            _reject(
                "integrity_lineage_gap",
                "finalization cannot exist without a checkpoint candidate",
            )
        if anchor is not None:
            anchor = _snapshot_anchor_record(anchor)
            if anchor.pending_record_id != pending_record_id or anchor.event_digest != pending.event_digest:
                _reject(
                    "integrity_lineage_binding_mismatch",
                    "anchor statement does not extend the pending transition",
                )
        if candidate is not None:
            candidate = _snapshot_candidate_record(candidate)
            if (
                anchor is None
                or candidate.pending_record_id != pending_record_id
                or candidate.anchor_statement_record_id != anchor.record_id
                or candidate.event_digest != pending.event_digest
            ):
                _reject(
                    "integrity_lineage_binding_mismatch",
                    "checkpoint candidate does not extend the exact anchor statement",
                )
        if finalization is not None:
            finalization = _snapshot_finalization_record(finalization)
            if (
                candidate is None
                or finalization.pending_record_id != pending_record_id
                or finalization.checkpoint_candidate_record_id != candidate.record_id
                or finalization.event_digest != pending.event_digest
            ):
                _reject(
                    "integrity_lineage_binding_mismatch",
                    "finalization does not extend the exact checkpoint candidate",
                )
        object.__setattr__(self, "pending", pending)
        object.__setattr__(self, "anchor_statement", anchor)
        object.__setattr__(self, "checkpoint_candidate", candidate)
        object.__setattr__(self, "finalization", finalization)

    @property
    def phase(
        self,
    ) -> Literal[
        "local_pending",
        "anchor_statement_ready",
        "checkpoint_candidate_retained",
        "finalized",
    ]:
        if self.finalization is not None:
            return "finalized"
        if self.checkpoint_candidate is not None:
            return "checkpoint_candidate_retained"
        if self.anchor_statement is not None:
            return "anchor_statement_ready"
        return "local_pending"

    @property
    def lineage_id(self) -> str:
        return content_id("integrity_lineage", self.to_body())

    def to_body(self) -> dict[str, object]:
        return {
            "anchor_statement": (None if self.anchor_statement is None else self.anchor_statement.to_body()),
            "checkpoint_candidate": (
                None if self.checkpoint_candidate is None else self.checkpoint_candidate.to_body()
            ),
            "finalization": (None if self.finalization is None else self.finalization.to_body()),
            "pending": self.pending.to_body(),
            "record_kind": "integrity_lineage",
            "record_version": INTEGRITY_TRANSITION_RECORD_VERSION_V1,
        }

    def to_canonical_bytes(self) -> bytes:
        return _record_bytes(self.to_body())

    @classmethod
    def from_canonical_bytes(
        cls,
        data: bytes | str,
    ) -> IntegrityLineageV1:
        body = _require_exact_dict(
            _record_body(data, "integrity_lineage"),
            frozenset(
                {
                    "anchor_statement",
                    "checkpoint_candidate",
                    "finalization",
                    "pending",
                    "record_kind",
                    "record_version",
                }
            ),
            "integrity_lineage",
        )
        return cls(
            pending=PendingIntegrityTransitionV1.from_canonical_bytes(
                _record_bytes(body["pending"])  # type: ignore[arg-type]
            ),
            anchor_statement=(
                None
                if body["anchor_statement"] is None
                else AnchorStatementRecordV1.from_canonical_bytes(
                    _record_bytes(
                        body["anchor_statement"]  # type: ignore[arg-type]
                    )
                )
            ),
            checkpoint_candidate=(
                None
                if body["checkpoint_candidate"] is None
                else CheckpointCandidateRecordV1.from_canonical_bytes(
                    _record_bytes(
                        body["checkpoint_candidate"]  # type: ignore[arg-type]
                    )
                )
            ),
            finalization=(
                None
                if body["finalization"] is None
                else FinalizedIntegrityTransitionV1.from_canonical_bytes(
                    _record_bytes(
                        body["finalization"]  # type: ignore[arg-type]
                    )
                )
            ),
        )


def _authenticated_decision_self(
    pending: PendingIntegrityTransitionV1,
) -> AuthenticatedIntegrityDecisionV1:
    decision = pending.decision
    policy = pending.validation_policy
    try:
        return authenticate_integrity_decision(
            pending.signed_decision,
            pending.decision_trust_store,
            forbidden_key_ids=(),
            expected_service_instance_id=decision.service_instance_id,
            expected_environment_id=decision.environment_id,
            expected_mission_id=decision.mission_id,
            expected_authority_id=decision.authority_id,
            expected_target_id=decision.target_id,
            expected_prior_global_checkpoint_sequence=(decision.prior_global_checkpoint_sequence),
            expected_prior_global_checkpoint_id=(decision.prior_global_checkpoint_id),
            expected_prior_global_checkpoint_attestation_id=(decision.prior_global_checkpoint_attestation_id),
            expected_prior_global_checkpoint_principal_id=(decision.prior_global_checkpoint_principal_id),
            expected_prior_global_checkpoint_trust_snapshot_id=(decision.prior_global_checkpoint_trust_snapshot_id),
            expected_prior_event_seq=decision.prior_event_seq,
            expected_prior_event_digest=decision.prior_event_digest,
            expected_event_kind=decision.event_kind,
            expected_proposed_event_digest=decision.proposed_event_digest,
            expected_transition_intent_id=decision.transition_intent_id,
            expected_request_nonce=decision.request_nonce,
            expected_time_policy_id=policy.decision_time_policy_id,
            expected_decision_policy_id=policy.decision_policy_id,
            required_revocation_namespaces=(policy.required_revocation_namespaces),
            max_time_uncertainty_seconds=(policy.max_decision_uncertainty_seconds),
        )
    except IntegrityError as exc:
        raise IntegrityTransitionError(
            exc.reason_code,
            f"pending integrity decision authentication failed: {exc}",
        ) from exc


def _anchor_registration_body(
    pending: PendingIntegrityTransitionV1,
    *,
    decision_auth: AuthenticatedIntegrityDecisionV1,
    previous_mission_checkpoint_id: str,
    previous_mission_checkpoint_attestation_id: str | None,
    previous_mission_checkpoint_principal_id: str | None,
    previous_mission_checkpoint_trust_snapshot_id: str | None,
    time_lower_bound: int,
    time_upper_bound: int,
    time_policy_id: str,
    time_evidence: tuple[EvidenceReferenceV1, ...],
    anchor_policy_id: str,
) -> dict[str, object]:
    """Reconstruct the exact bytes submitted to the modeled anchor registry."""

    decision = pending.decision
    references = tuple(_snapshot_reference(value) for value in time_evidence)
    return {
        "anchor_policy_id": anchor_policy_id,
        "authority_id": decision.authority_id,
        "environment_id": decision.environment_id,
        "event_digest": pending.event_digest,
        "event_seq": pending.event_seq,
        "instance_sequence": pending.instance_sequence,
        "integrity_decision_attestation_id": (signed_integrity_decision_attestation_id(pending.signed_decision)),
        "integrity_decision_id": decision.decision_id,
        "integrity_decision_principal_id": decision_auth.signer_principal_id,
        "integrity_decision_trust_snapshot_id": decision_auth.trust_snapshot_id,
        "mission_id": decision.mission_id,
        "previous_checkpoint_attestation_id": (decision.prior_global_checkpoint_attestation_id),
        "previous_checkpoint_id": decision.prior_global_checkpoint_id,
        "previous_checkpoint_principal_id": (decision.prior_global_checkpoint_principal_id),
        "previous_checkpoint_trust_snapshot_id": (decision.prior_global_checkpoint_trust_snapshot_id),
        "previous_mission_checkpoint_attestation_id": (previous_mission_checkpoint_attestation_id),
        "previous_mission_checkpoint_id": previous_mission_checkpoint_id,
        "previous_mission_checkpoint_principal_id": (previous_mission_checkpoint_principal_id),
        "previous_mission_checkpoint_trust_snapshot_id": (previous_mission_checkpoint_trust_snapshot_id),
        "service_instance_id": decision.service_instance_id,
        "target_id": decision.target_id,
        "time_evidence": [reference.to_body() for reference in references],
        "time_lower_bound": time_lower_bound,
        "time_policy_id": time_policy_id,
        "time_upper_bound": time_upper_bound,
    }


def _authenticated_checkpoint_self(
    candidate: CheckpointCandidateRecordV1,
    *,
    decision: AuthenticatedIntegrityDecisionV1,
    policy: IntegrityValidationPolicyV1,
) -> AuthenticatedHeadCheckpointV1:
    checkpoint = candidate.checkpoint
    try:
        return authenticate_head_checkpoint(
            candidate.signed_checkpoint,
            candidate.checkpoint_trust_store,
            forbidden_key_ids=(decision.signed_decision.key_id,),
            forbidden_principal_ids=(decision.signer_principal_id,),
            expected_service_instance_id=checkpoint.service_instance_id,
            expected_environment_id=checkpoint.environment_id,
            expected_time_policy_id=policy.checkpoint_time_policy_id,
            expected_anchor_policy_id=policy.anchor_policy_id,
            expected_anchor_statement_id=checkpoint.anchor_statement_id,
            max_time_uncertainty_seconds=(policy.max_checkpoint_uncertainty_seconds),
        )
    except IntegrityError as exc:
        raise IntegrityTransitionError(
            exc.reason_code,
            f"checkpoint candidate authentication failed: {exc}",
        ) from exc


def _authenticated_lineage_values(
    lineage: IntegrityLineageV1 | None,
) -> tuple[
    AuthenticatedIntegrityDecisionV1 | None,
    AuthenticatedHeadCheckpointV1 | None,
]:
    if lineage is None:
        return None, None
    if type(lineage) is not IntegrityLineageV1:
        _reject(
            "invalid_integrity_lineage",
            "predecessor must be an exact IntegrityLineageV1",
        )
    lineage = IntegrityLineageV1(
        pending=lineage.pending,
        anchor_statement=lineage.anchor_statement,
        checkpoint_candidate=lineage.checkpoint_candidate,
        finalization=lineage.finalization,
    )
    pending = lineage.pending
    anchor = lineage.anchor_statement
    candidate = lineage.checkpoint_candidate
    finalization = lineage.finalization
    if (
        type(pending) is not PendingIntegrityTransitionV1
        or type(anchor) is not AnchorStatementRecordV1
        or type(candidate) is not CheckpointCandidateRecordV1
        or type(finalization) is not FinalizedIntegrityTransitionV1
    ):
        _reject(
            "unfinalized_integrity_predecessor",
            "a successor requires a completely finalized predecessor",
        )
    pending_record_id = pending.record_id
    if (
        anchor.pending_record_id != pending_record_id
        or anchor.event_digest != pending.event_digest
        or candidate.pending_record_id != pending_record_id
        or candidate.anchor_statement_record_id != anchor.record_id
        or candidate.event_digest != pending.event_digest
        or finalization.pending_record_id != pending_record_id
        or finalization.checkpoint_candidate_record_id != candidate.record_id
        or finalization.event_digest != pending.event_digest
    ):
        _reject(
            "integrity_lineage_binding_mismatch",
            "predecessor recovery records do not form one exact lineage",
        )
    decision = _authenticated_decision_self(pending)
    checkpoint = _authenticated_checkpoint_self(
        candidate,
        decision=decision,
        policy=pending.validation_policy,
    )
    return decision, checkpoint


def authenticate_pending_integrity_transition(
    pending: PendingIntegrityTransitionV1,
    *,
    event: EventV1,
    previous_global: IntegrityLineageV1 | None,
) -> AuthenticatedIntegrityDecisionV1:
    """Reauthenticate one pending decision and its pre-commit rollback floors."""

    if type(pending) is not PendingIntegrityTransitionV1:
        _reject(
            "invalid_pending_integrity_transition",
            "exact PendingIntegrityTransitionV1 required",
        )
    if type(event) is not EventV1:
        _reject(
            "invalid_integrity_event",
            "pending integrity transition requires an exact EventV1",
        )
    try:
        event = EventV1.from_canonical_bytes(event.to_canonical_bytes())
    except (ProtocolError, TypeError, ValueError) as exc:
        raise IntegrityTransitionError(
            "invalid_integrity_event",
            "integrity transition event is not canonical",
        ) from exc
    decision = pending.decision
    if (
        pending.event_digest != event.event_digest
        or pending.mission_id != event.mission_id
        or pending.event_seq != event.seq
        or decision.authority_id != event.authority_id
        or decision.target_id != event.target_id
        or decision.event_kind != event.kind
        or decision.proposed_event_digest != event.event_digest
        or decision.prior_event_seq != event.seq - 1
        or decision.prior_event_digest != event.prev_digest
        or decision.time_upper_bound != event.decision_time
    ):
        _reject(
            "pending_transition_event_mismatch",
            "pending decision does not bind the exact proposed event",
        )
    current = _authenticated_decision_self(pending)
    previous_decision, previous_checkpoint = _authenticated_lineage_values(previous_global)
    previous_trust = None if previous_global is None else previous_global.pending.decision_trust_store
    previous_checkpoint_trust = (
        None if previous_global is None else previous_global.checkpoint_candidate.checkpoint_trust_store  # type: ignore[union-attr]
    )
    try:
        validate_revocation_advance(
            previous_decision,
            current,
            previous_global_decision_trust_store=previous_trust,
            previous_global_checkpoint=previous_checkpoint,
            previous_global_checkpoint_trust_store=(previous_checkpoint_trust),
            current_trust_store=pending.decision_trust_store,
            external_floors=pending.revocation_floors,
            validation_policy=pending.validation_policy,
        )
    except IntegrityError as exc:
        raise IntegrityTransitionError(
            exc.reason_code,
            f"pending revocation continuity failed: {exc}",
        ) from exc
    return current


def validate_anchor_statement_record(
    pending: PendingIntegrityTransitionV1,
    anchor: AnchorStatementRecordV1,
) -> None:
    """Recompute the exact pre-receipt anchor statement from retained decision bytes."""

    if type(pending) is not PendingIntegrityTransitionV1 or type(anchor) is not AnchorStatementRecordV1:
        _reject(
            "invalid_anchor_statement_record",
            "exact pending and anchor statement records are required",
        )
    decision = pending.decision
    if (
        anchor.pending_record_id != pending.record_id
        or anchor.event_digest != pending.event_digest
        or anchor.time_policy_id != pending.validation_policy.checkpoint_time_policy_id
        or anchor.anchor_policy_id != pending.validation_policy.anchor_policy_id
        or anchor.time_lower_bound < decision.time_upper_bound
    ):
        _reject(
            "anchor_statement_binding_mismatch",
            "anchor statement differs from its pending transition or policy",
        )
    decision_auth = _authenticated_decision_self(pending)
    expected = derive_anchor_statement_id(
        service_instance_id=decision.service_instance_id,
        environment_id=decision.environment_id,
        instance_sequence=pending.instance_sequence,
        previous_checkpoint_id=decision.prior_global_checkpoint_id,
        previous_checkpoint_attestation_id=(decision.prior_global_checkpoint_attestation_id),
        previous_checkpoint_principal_id=(decision.prior_global_checkpoint_principal_id),
        previous_checkpoint_trust_snapshot_id=(decision.prior_global_checkpoint_trust_snapshot_id),
        previous_mission_checkpoint_id=(anchor.previous_mission_checkpoint_id),
        previous_mission_checkpoint_attestation_id=(anchor.previous_mission_checkpoint_attestation_id),
        previous_mission_checkpoint_principal_id=(anchor.previous_mission_checkpoint_principal_id),
        previous_mission_checkpoint_trust_snapshot_id=(anchor.previous_mission_checkpoint_trust_snapshot_id),
        mission_id=decision.mission_id,
        authority_id=decision.authority_id,
        target_id=decision.target_id,
        event_seq=pending.event_seq,
        event_digest=pending.event_digest,
        integrity_decision_id=decision.decision_id,
        integrity_decision_attestation_id=(signed_integrity_decision_attestation_id(pending.signed_decision)),
        integrity_decision_principal_id=decision_auth.signer_principal_id,
        integrity_decision_trust_snapshot_id=decision_auth.trust_snapshot_id,
        time_lower_bound=anchor.time_lower_bound,
        time_upper_bound=anchor.time_upper_bound,
        time_policy_id=anchor.time_policy_id,
        time_evidence=anchor.time_evidence,
        anchor_policy_id=anchor.anchor_policy_id,
    )
    expected_body = _anchor_registration_body(
        pending,
        decision_auth=decision_auth,
        previous_mission_checkpoint_id=anchor.previous_mission_checkpoint_id,
        previous_mission_checkpoint_attestation_id=(anchor.previous_mission_checkpoint_attestation_id),
        previous_mission_checkpoint_principal_id=(anchor.previous_mission_checkpoint_principal_id),
        previous_mission_checkpoint_trust_snapshot_id=(anchor.previous_mission_checkpoint_trust_snapshot_id),
        time_lower_bound=anchor.time_lower_bound,
        time_upper_bound=anchor.time_upper_bound,
        time_policy_id=anchor.time_policy_id,
        time_evidence=anchor.time_evidence,
        anchor_policy_id=anchor.anchor_policy_id,
    )
    expected_request = _record_bytes(expected_body)
    if (
        anchor.anchor_statement_id != expected
        or content_id("head_anchor_statement", expected_body) != expected
        or anchor.registration_request != expected_request
    ):
        _reject(
            "anchor_statement_binding_mismatch",
            "retained anchor identity or exact registration request is not code-derived",
        )


def authenticate_checkpoint_candidate(
    pending: PendingIntegrityTransitionV1,
    anchor: AnchorStatementRecordV1,
    candidate: CheckpointCandidateRecordV1,
    *,
    event: EventV1,
    previous_global: IntegrityLineageV1 | None,
    previous_mission: IntegrityLineageV1 | None,
    external_floor: HeadCheckpointFloorV1 | None = None,
) -> AuthenticatedHeadCheckpointV1:
    """Reauthenticate and compose one retained checkpoint candidate."""

    validate_anchor_statement_record(pending, anchor)
    if (
        type(candidate) is not CheckpointCandidateRecordV1
        or candidate.pending_record_id != pending.record_id
        or candidate.anchor_statement_record_id != anchor.record_id
        or candidate.event_digest != event.event_digest
    ):
        _reject(
            "checkpoint_candidate_binding_mismatch",
            "checkpoint candidate differs from its retained lineage",
        )
    decision = authenticate_pending_integrity_transition(
        pending,
        event=event,
        previous_global=previous_global,
    )
    checkpoint = _authenticated_checkpoint_self(
        candidate,
        decision=decision,
        policy=pending.validation_policy,
    )
    previous_global_decision, previous_global_checkpoint = _authenticated_lineage_values(previous_global)
    del previous_global_decision
    _, previous_mission_checkpoint = _authenticated_lineage_values(previous_mission)
    try:
        validate_checkpoint_binding(
            checkpoint,
            decision,
            event=event,
            checkpoint_trust_store=candidate.checkpoint_trust_store,
            decision_trust_store=pending.decision_trust_store,
            previous_mission=previous_mission_checkpoint,
            previous_mission_trust_store=(
                None if previous_mission is None else previous_mission.checkpoint_candidate.checkpoint_trust_store  # type: ignore[union-attr]
            ),
            validation_policy=pending.validation_policy,
        )
        validate_checkpoint_advance(
            checkpoint,
            current_trust_store=candidate.checkpoint_trust_store,
            current_decision=decision,
            current_decision_trust_store=pending.decision_trust_store,
            previous_global=previous_global_checkpoint,
            previous_global_trust_store=(
                None if previous_global is None else previous_global.checkpoint_candidate.checkpoint_trust_store  # type: ignore[union-attr]
            ),
            previous_mission=previous_mission_checkpoint,
            previous_mission_trust_store=(
                None if previous_mission is None else previous_mission.checkpoint_candidate.checkpoint_trust_store  # type: ignore[union-attr]
            ),
            external_floor=(pending.prior_head_floor if external_floor is None else external_floor),
            validation_policy=pending.validation_policy,
        )
    except IntegrityError as exc:
        raise IntegrityTransitionError(
            exc.reason_code,
            f"checkpoint candidate composition failed: {exc}",
        ) from exc
    return checkpoint


def validate_finalized_integrity_transition(
    lineage: IntegrityLineageV1,
    *,
    event: EventV1,
    previous_global: IntegrityLineageV1 | None,
    previous_mission: IntegrityLineageV1 | None,
) -> AuthenticatedHeadCheckpointV1:
    """Require a finalization floor to equal the exact current checkpoint."""

    if (
        type(lineage) is not IntegrityLineageV1
        or lineage.anchor_statement is None
        or lineage.checkpoint_candidate is None
        or lineage.finalization is None
    ):
        _reject(
            "integrity_finality_incomplete",
            "complete pending, anchor, checkpoint, and finalization records are required",
        )
    candidate = lineage.checkpoint_candidate
    finalization = lineage.finalization
    authenticated = authenticate_checkpoint_candidate(
        lineage.pending,
        lineage.anchor_statement,
        candidate,
        event=event,
        previous_global=previous_global,
        previous_mission=previous_mission,
        external_floor=finalization.external_head_floor,
    )
    floor = finalization.external_head_floor
    try:
        require_external_floor_is_current(
            authenticated,
            candidate.checkpoint_trust_store,
            floor,
            lineage.pending.validation_policy,
        )
    except IntegrityError as exc:
        raise IntegrityTransitionError(
            exc.reason_code,
            f"finalized external floor is not current: {exc}",
        ) from exc
    return authenticated


class ModeledIntegrityServiceError(IntegrityTransitionError):
    """Repository-owned modeled service refused a deterministic operation."""


_MODELED_PROVIDER_QUALIFICATION_V1: Final = "repository_owned_deterministic_fixture_only"
_MODELED_PROVIDER_TRUST_BOUNDARY_V1: Final = "not_trustworthy_utc_external_durability_or_independence"
_MODELED_PROVIDER_CONTENT_FIELDS_V1: Final = frozenset(
    {
        "claim",
        "evidence_kind",
        "qualification",
        "source_id",
        "trust_boundary",
    }
)
_ModeledProviderClaimSpec = tuple[str, str, dict[str, object]]
_AdapterResult = TypeVar("_AdapterResult")


def _modeled_provider_content(
    *,
    evidence_kind: str,
    source_id: str,
    claim: dict[str, object],
) -> bytes:
    return canonical_dumps(
        {
            "claim": claim,
            "evidence_kind": evidence_kind,
            "qualification": _MODELED_PROVIDER_QUALIFICATION_V1,
            "source_id": source_id,
            "trust_boundary": _MODELED_PROVIDER_TRUST_BOUNDARY_V1,
        }
    )


def _call_modeled_integrity_adapter(
    operation: str,
    call: Callable[[], _AdapterResult],
) -> _AdapterResult:
    """Normalize fixture-adapter failures without catching process termination."""

    try:
        return call()
    except IntegrityFinalityPendingError:
        raise
    except IntegrityFinalityBlockedError:
        raise
    except IntegrityTransitionError as exc:
        raise IntegrityFinalityBlockedError(
            exc.reason_code,
            f"modeled integrity adapter {operation} is deterministically blocked",
        ) from exc
    except (TimeoutError, ConnectionError, RuntimeError) as exc:
        raise IntegrityFinalityPendingError(
            "modeled_integrity_adapter_response_uncertain",
            f"modeled integrity adapter {operation} has an uncertain retryable outcome",
        ) from exc
    except Exception as exc:
        raise IntegrityFinalityBlockedError(
            "modeled_integrity_adapter_contract_failure",
            f"modeled integrity adapter {operation} violated its local fixture contract",
        ) from exc


def _modeled_provider_blob(
    *,
    evidence_kind: str,
    source_id: str,
    claim: dict[str, object],
) -> ProviderEvidenceBlobV1:
    return ProviderEvidenceBlobV1.from_content(
        evidence_kind=evidence_kind,
        source_id=source_id,
        content=_modeled_provider_content(
            evidence_kind=evidence_kind,
            source_id=source_id,
            claim=claim,
        ),
    )


def _require_exact_modeled_provider_claims(
    blobs: tuple[ProviderEvidenceBlobV1, ...],
    specs: tuple[_ModeledProviderClaimSpec, ...],
    *,
    label: str,
) -> dict[tuple[str, str], ProviderEvidenceBlobV1]:
    """Validate exact fixture-source identities and code-derived canonical claims."""

    observed: dict[tuple[str, str], ProviderEvidenceBlobV1] = {}
    for blob in blobs:
        key = (blob.evidence_kind, blob.source_id)
        if key in observed:
            _reject(
                "modeled_provider_evidence_source_collision",
                f"{label} repeats one modeled provider source",
            )
        observed[key] = blob
    expected_keys = {(kind, source_id) for kind, source_id, _ in specs}
    if len(expected_keys) != len(specs) or set(observed) != expected_keys:
        _reject(
            "modeled_provider_evidence_source_mismatch",
            f"{label} does not contain the exact code-owned fixture sources",
        )
    for evidence_kind, source_id, claim in specs:
        blob = observed[(evidence_kind, source_id)]
        expected_content = _modeled_provider_content(
            evidence_kind=evidence_kind,
            source_id=source_id,
            claim=claim,
        )
        try:
            body = strict_loads(blob.content)
        except (ProtocolError, TypeError, ValueError) as exc:
            raise IntegrityTransitionError(
                "invalid_modeled_provider_evidence",
                f"{label} contains malformed modeled provider evidence",
            ) from exc
        if (
            type(body) is not dict
            or set(body) != _MODELED_PROVIDER_CONTENT_FIELDS_V1
            or blob.content != expected_content
        ):
            _reject(
                "modeled_provider_evidence_claim_mismatch",
                f"{label} provider claim is not the exact code-derived fixture assertion",
            )
    return observed


def _modeled_pair_references(
    observed: dict[tuple[str, str], ProviderEvidenceBlobV1],
    *,
    evidence_kind: str,
    source_prefix: str,
) -> tuple[EvidenceReferenceV1, ...]:
    return tuple(
        observed[(evidence_kind, f"{source_prefix}.{suffix}")].reference for suffix in _MODELED_PROVIDER_SUFFIXES_V1
    )


def _validate_modeled_pending_provider_evidence(
    *,
    decision: IntegrityDecisionV1,
    revocation_floors: tuple[RevocationFloorV1, ...],
    prior_head_floor: HeadCheckpointFloorV1,
    blobs: tuple[ProviderEvidenceBlobV1, ...],
) -> None:
    specs: list[_ModeledProviderClaimSpec] = [
        (
            TRUSTED_TIME_EVIDENCE_KIND,
            f"fixture.time.{suffix}",
            {
                "epoch_second": decision.time_upper_bound,
                "event_digest": decision.proposed_event_digest,
                "purpose": "decision",
                "service_instance_id": decision.service_instance_id,
            },
        )
        for suffix in _MODELED_PROVIDER_SUFFIXES_V1
    ]
    floors_by_namespace = {floor.namespace: floor for floor in revocation_floors}
    for view in decision.revocation_views:
        metadata_source = f"fixture.revocation.{view.namespace}"
        specs.append(
            (
                REVOCATION_METADATA_EVIDENCE_KIND,
                metadata_source,
                {
                    "namespace": view.namespace,
                    "root_version": view.root_version,
                    "service_instance_id": decision.service_instance_id,
                    "version": view.version,
                },
            )
        )
        for suffix in _MODELED_PROVIDER_SUFFIXES_V1:
            specs.append(
                (
                    EXTERNAL_FLOOR_EVIDENCE_KIND,
                    f"fixture.revocation-floor.{view.namespace}.{suffix}",
                    {
                        "namespace": view.namespace,
                        "root_version": view.root_version,
                        "service_instance_id": decision.service_instance_id,
                        "snapshot_id": view.snapshot_id,
                        "version": view.version,
                    },
                )
            )
    for suffix in _MODELED_PROVIDER_SUFFIXES_V1:
        specs.append(
            (
                EXTERNAL_FLOOR_EVIDENCE_KIND,
                f"fixture.head-floor.{suffix}",
                {
                    "checkpoint_id": prior_head_floor.checkpoint_id,
                    "instance_sequence": prior_head_floor.instance_sequence,
                    "mission_event_seq": prior_head_floor.mission_event_seq,
                    "mission_id": prior_head_floor.mission_id,
                    "purpose": "predecessor",
                    "service_instance_id": decision.service_instance_id,
                },
            )
        )
    observed = _require_exact_modeled_provider_claims(
        blobs,
        tuple(specs),
        label="pending transition",
    )
    expected_time = _modeled_pair_references(
        observed,
        evidence_kind=TRUSTED_TIME_EVIDENCE_KIND,
        source_prefix="fixture.time",
    )
    if decision.time_evidence != expected_time:
        _reject(
            "modeled_provider_evidence_reference_mismatch",
            "decision time references differ from the exact modeled fixture assertions",
        )
    for view in decision.revocation_views:
        floor = floors_by_namespace[view.namespace]
        metadata = observed[
            (
                REVOCATION_METADATA_EVIDENCE_KIND,
                f"fixture.revocation.{view.namespace}",
            )
        ]
        floor_references = _modeled_pair_references(
            observed,
            evidence_kind=EXTERNAL_FLOOR_EVIDENCE_KIND,
            source_prefix=f"fixture.revocation-floor.{view.namespace}",
        )
        if (
            view.evidence != metadata.reference
            or view.snapshot_id != metadata.evidence_id
            or floor.evidence != floor_references
        ):
            _reject(
                "modeled_provider_evidence_reference_mismatch",
                "revocation references differ from the exact modeled fixture assertions",
            )
    expected_head = _modeled_pair_references(
        observed,
        evidence_kind=EXTERNAL_FLOOR_EVIDENCE_KIND,
        source_prefix="fixture.head-floor",
    )
    if prior_head_floor.evidence != expected_head:
        _reject(
            "modeled_provider_evidence_reference_mismatch",
            "predecessor-head references differ from the exact modeled fixture assertions",
        )


def _validate_modeled_anchor_provider_evidence(
    *,
    registration_body: dict[str, object],
    references: tuple[EvidenceReferenceV1, ...],
    blobs: tuple[ProviderEvidenceBlobV1, ...],
) -> None:
    specs = tuple(
        (
            TRUSTED_TIME_EVIDENCE_KIND,
            f"fixture.time.{suffix}",
            {
                "epoch_second": registration_body["time_upper_bound"],
                "event_digest": registration_body["event_digest"],
                "purpose": "checkpoint",
                "service_instance_id": registration_body["service_instance_id"],
            },
        )
        for suffix in _MODELED_PROVIDER_SUFFIXES_V1
    )
    observed = _require_exact_modeled_provider_claims(
        blobs,
        specs,
        label="anchor statement",
    )
    if references != _modeled_pair_references(
        observed,
        evidence_kind=TRUSTED_TIME_EVIDENCE_KIND,
        source_prefix="fixture.time",
    ):
        _reject(
            "modeled_provider_evidence_reference_mismatch",
            "checkpoint time references differ from the exact modeled fixture assertions",
        )


def _validate_modeled_checkpoint_provider_evidence(
    *,
    checkpoint: HeadCheckpointV1,
    blobs: tuple[ProviderEvidenceBlobV1, ...],
) -> None:
    specs = tuple(
        (
            HEAD_ANCHOR_RECEIPT_EVIDENCE_KIND,
            f"fixture.anchor.{suffix}",
            {
                "anchor_statement_id": checkpoint.anchor_statement_id,
                "registration": "included",
                "service_instance_id": checkpoint.service_instance_id,
            },
        )
        for suffix in _MODELED_PROVIDER_SUFFIXES_V1
    )
    observed = _require_exact_modeled_provider_claims(
        blobs,
        specs,
        label="checkpoint candidate",
    )
    if checkpoint.anchor_evidence != _modeled_pair_references(
        observed,
        evidence_kind=HEAD_ANCHOR_RECEIPT_EVIDENCE_KIND,
        source_prefix="fixture.anchor",
    ):
        _reject(
            "modeled_provider_evidence_reference_mismatch",
            "anchor receipt references differ from the exact modeled fixture assertions",
        )


def _validate_modeled_finalization_provider_evidence(
    *,
    floor: HeadCheckpointFloorV1,
    blobs: tuple[ProviderEvidenceBlobV1, ...],
) -> None:
    specs = tuple(
        (
            EXTERNAL_FLOOR_EVIDENCE_KIND,
            f"fixture.head-floor.{suffix}",
            {
                "checkpoint_id": floor.checkpoint_id,
                "instance_sequence": floor.instance_sequence,
                "mission_event_seq": floor.mission_event_seq,
                "mission_id": floor.mission_id,
                "purpose": "current",
                "service_instance_id": floor.service_instance_id,
            },
        )
        for suffix in _MODELED_PROVIDER_SUFFIXES_V1
    )
    observed = _require_exact_modeled_provider_claims(
        blobs,
        specs,
        label="finalized transition",
    )
    if floor.evidence != _modeled_pair_references(
        observed,
        evidence_kind=EXTERNAL_FLOOR_EVIDENCE_KIND,
        source_prefix="fixture.head-floor",
    ):
        _reject(
            "modeled_provider_evidence_reference_mismatch",
            "current-head references differ from the exact modeled fixture assertions",
        )


def _sorted_blobs(
    *groups: tuple[ProviderEvidenceBlobV1, ...],
) -> tuple[ProviderEvidenceBlobV1, ...]:
    return _validated_evidence_blobs(
        tuple(
            sorted(
                (value for group in groups for value in group),
                key=lambda item: (
                    item.evidence_kind,
                    item.source_id,
                    item.evidence_id,
                ),
            )
        )
    )


class RepositoryOwnedDeterministicModeledIntegrityServiceV1:
    """Deterministic fixture service for integrity/recovery qualification.

    Decision and checkpoint keys map to separate principals, but both live in this one
    repository-owned Python object.  Its in-memory statement registry and catalog model
    idempotency and compare-and-set publication.  They are neither external nor durable
    across loss of this object and must never be described as a production anchor,
    monitor, clock, revocation service, or independent authority.
    """

    def __init__(
        self,
        *,
        service_instance_id: str,
        environment_id: str,
        validation_policy: IntegrityValidationPolicyV1,
        decision_signer: IntegritySigner,
        checkpoint_signer: IntegritySigner,
        trust_store: IntegrityTrustStore,
    ) -> None:
        self.service_instance_id = _require_identity(
            service_instance_id,
            "service_instance_id",
        )
        self.environment_id = _require_identity(
            environment_id,
            "environment_id",
        )
        self.validation_policy = _snapshot_policy(validation_policy)
        if (
            type(decision_signer) is not IntegritySigner
            or decision_signer.role != INTEGRITY_DECISION_ROLE
            or type(checkpoint_signer) is not IntegritySigner
            or checkpoint_signer.role != HEAD_CHECKPOINT_ROLE
        ):
            _reject(
                "invalid_modeled_integrity_signer",
                "modeled service requires exact decision and checkpoint signers",
            )
        copied_trust = _snapshot_trust_store(trust_store)
        decision_key = copied_trust.keys.get(decision_signer.key_id)
        checkpoint_key = copied_trust.keys.get(checkpoint_signer.key_id)
        if (
            decision_key is None
            or checkpoint_key is None
            or decision_key.role != INTEGRITY_DECISION_ROLE
            or checkpoint_key.role != HEAD_CHECKPOINT_ROLE
            or decision_key.principal_id == checkpoint_key.principal_id
            or decision_signer.key_id == checkpoint_signer.key_id
        ):
            _reject(
                "invalid_modeled_integrity_trust",
                "modeled signers require distinct trusted principals and keys",
            )
        self.authority_binding = ModeledIntegrityAuthorityBindingV1(
            adapter_profile=MODELED_INTEGRITY_ADAPTER_PROFILE_V1,
            adapter_version=MODELED_INTEGRITY_ADAPTER_VERSION_V1,
            trust_snapshot_id=copied_trust.snapshot_id,
            trust_store=copied_trust,
            decision_key_id=decision_signer.key_id,
            decision_principal_id=decision_key.principal_id,
            checkpoint_key_id=checkpoint_signer.key_id,
            checkpoint_principal_id=checkpoint_key.principal_id,
        )
        self._decision_signer = decision_signer
        self._checkpoint_signer = checkpoint_signer
        self.trust_store = copied_trust
        self._lock = threading.RLock()
        self._registered_statement_requests: dict[str, bytes] = {}
        self._global_statement_slots: dict[
            tuple[str, str, int],
            tuple[str, bytes],
        ] = {}
        self._mission_statement_slots: dict[
            tuple[str, str, str, int],
            tuple[str, bytes],
        ] = {}
        self._statement_receipts: dict[str, tuple[ProviderEvidenceBlobV1, ...]] = {}
        self._published_by_id: dict[str, bytes] = {}
        self._global_checkpoint: CheckpointCandidateRecordV1 | None = None
        self._mission_checkpoints: dict[str, CheckpointCandidateRecordV1] = {}

    @classmethod
    def deterministic(
        cls,
        *,
        seed: bytes,
        service_instance_id: str,
        environment_id: str,
        validation_policy: IntegrityValidationPolicyV1,
    ) -> RepositoryOwnedDeterministicModeledIntegrityServiceV1:
        """Create repeatable fixture keys from an explicit non-secret test seed."""

        if type(seed) is not bytes or not seed or len(seed) > 1024:
            _reject(
                "invalid_modeled_integrity_seed",
                "modeled integrity seed must be nonempty bounded bytes",
            )
        decision_private = Ed25519PrivateKey.from_private_bytes(
            hashlib.sha256(b"etzio.modeled-integrity.decision.v1\x00" + seed).digest()
        )
        checkpoint_private = Ed25519PrivateKey.from_private_bytes(
            hashlib.sha256(b"etzio.modeled-integrity.checkpoint.v1\x00" + seed).digest()
        )
        decision_signer = IntegritySigner(
            decision_private,
            INTEGRITY_DECISION_ROLE,
        )
        checkpoint_signer = IntegritySigner(
            checkpoint_private,
            HEAD_CHECKPOINT_ROLE,
        )
        trust_store = IntegrityTrustStore.from_keys(
            (
                TrustedIntegrityKey(
                    principal_id="fixture.integrity-decision-principal",
                    public_key_bytes=decision_signer.public_key_bytes,
                    role=INTEGRITY_DECISION_ROLE,
                ),
                TrustedIntegrityKey(
                    principal_id="fixture.head-checkpoint-principal",
                    public_key_bytes=checkpoint_signer.public_key_bytes,
                    role=HEAD_CHECKPOINT_ROLE,
                ),
            )
        )
        return cls(
            service_instance_id=service_instance_id,
            environment_id=environment_id,
            validation_policy=validation_policy,
            decision_signer=decision_signer,
            checkpoint_signer=checkpoint_signer,
            trust_store=trust_store,
        )

    def _time_evidence(
        self,
        *,
        purpose: str,
        event_digest: str,
        epoch_second: int,
    ) -> tuple[ProviderEvidenceBlobV1, ...]:
        return tuple(
            _modeled_provider_blob(
                evidence_kind=TRUSTED_TIME_EVIDENCE_KIND,
                source_id=f"fixture.time.{suffix}",
                claim={
                    "epoch_second": epoch_second,
                    "event_digest": event_digest,
                    "purpose": purpose,
                    "service_instance_id": self.service_instance_id,
                },
            )
            for suffix in ("a", "b")
        )

    def _revocation_material(
        self,
    ) -> tuple[
        tuple[RevocationViewV1, ...],
        tuple[RevocationFloorV1, ...],
        tuple[ProviderEvidenceBlobV1, ...],
    ]:
        views: list[RevocationViewV1] = []
        floors: list[RevocationFloorV1] = []
        blobs: list[ProviderEvidenceBlobV1] = []
        for namespace in sorted(self.validation_policy.required_revocation_namespaces):
            metadata = _modeled_provider_blob(
                evidence_kind=REVOCATION_METADATA_EVIDENCE_KIND,
                source_id=f"fixture.revocation.{namespace}",
                claim={
                    "namespace": namespace,
                    "root_version": 1,
                    "service_instance_id": self.service_instance_id,
                    "version": 1,
                },
            )
            floor_blobs = tuple(
                _modeled_provider_blob(
                    evidence_kind=EXTERNAL_FLOOR_EVIDENCE_KIND,
                    source_id=f"fixture.revocation-floor.{namespace}.{suffix}",
                    claim={
                        "namespace": namespace,
                        "root_version": 1,
                        "service_instance_id": self.service_instance_id,
                        "snapshot_id": metadata.evidence_id,
                        "version": 1,
                    },
                )
                for suffix in ("a", "b")
            )
            view = RevocationViewV1(
                namespace=namespace,
                root_version=1,
                version=1,
                snapshot_id=metadata.evidence_id,
                evidence=metadata.reference,
                valid_from=0,
                valid_until=(2**63) - 1,
            )
            floor = RevocationFloorV1(
                service_instance_id=self.service_instance_id,
                environment_id=self.environment_id,
                decision_policy_id=(self.validation_policy.decision_policy_id),
                namespace=namespace,
                root_version=1,
                version=1,
                snapshot_id=metadata.evidence_id,
                evidence=tuple(value.reference for value in floor_blobs),
            )
            views.append(view)
            floors.append(floor)
            blobs.extend((metadata, *floor_blobs))
        return tuple(views), tuple(floors), _sorted_blobs(tuple(blobs))

    def _head_floor_evidence(
        self,
        *,
        checkpoint_id: str,
        instance_sequence: int,
        mission_id: str,
        mission_event_seq: int,
        purpose: str,
    ) -> tuple[ProviderEvidenceBlobV1, ...]:
        return tuple(
            _modeled_provider_blob(
                evidence_kind=EXTERNAL_FLOOR_EVIDENCE_KIND,
                source_id=f"fixture.head-floor.{suffix}",
                claim={
                    "checkpoint_id": checkpoint_id,
                    "instance_sequence": instance_sequence,
                    "mission_event_seq": mission_event_seq,
                    "mission_id": mission_id,
                    "purpose": purpose,
                    "service_instance_id": self.service_instance_id,
                },
            )
            for suffix in ("a", "b")
        )

    def _floor_for_predecessor(
        self,
        *,
        event: EventV1,
        previous_global: IntegrityLineageV1 | None,
        previous_mission: IntegrityLineageV1 | None,
    ) -> tuple[HeadCheckpointFloorV1, tuple[ProviderEvidenceBlobV1, ...]]:
        if event.seq == 0:
            if previous_mission is not None:
                _reject(
                    "modeled_head_floor_mismatch",
                    "event zero cannot claim a mission checkpoint predecessor",
                )
            mission_checkpoint_id = mission_checkpoint_genesis_id(
                service_instance_id=self.service_instance_id,
                environment_id=self.environment_id,
                mission_id=event.mission_id,
            )
            if previous_global is None:
                checkpoint_id = head_checkpoint_genesis_id(
                    service_instance_id=self.service_instance_id,
                    environment_id=self.environment_id,
                )
                instance_sequence = -1
                checkpoint_attestation_id = None
                checkpoint_principal_id = None
                checkpoint_trust_snapshot_id = None
            else:
                _, global_checkpoint = _authenticated_lineage_values(previous_global)
                if global_checkpoint is None:
                    _reject(
                        "modeled_head_floor_missing",
                        "new mission requires an exact finalized global predecessor",
                    )
                checkpoint_id = global_checkpoint.checkpoint.checkpoint_id
                instance_sequence = global_checkpoint.checkpoint.instance_sequence
                checkpoint_attestation_id = signed_head_checkpoint_attestation_id(global_checkpoint.signed_checkpoint)
                checkpoint_principal_id = global_checkpoint.signer_principal_id
                checkpoint_trust_snapshot_id = global_checkpoint.trust_snapshot_id
            evidence = self._head_floor_evidence(
                checkpoint_id=checkpoint_id,
                instance_sequence=instance_sequence,
                mission_id=event.mission_id,
                mission_event_seq=-1,
                purpose="predecessor",
            )
            return (
                HeadCheckpointFloorV1(
                    service_instance_id=self.service_instance_id,
                    environment_id=self.environment_id,
                    instance_sequence=instance_sequence,
                    checkpoint_id=checkpoint_id,
                    checkpoint_attestation_id=checkpoint_attestation_id,
                    checkpoint_principal_id=checkpoint_principal_id,
                    checkpoint_trust_snapshot_id=checkpoint_trust_snapshot_id,
                    mission_id=event.mission_id,
                    mission_event_seq=-1,
                    mission_checkpoint_id=mission_checkpoint_id,
                    mission_checkpoint_attestation_id=None,
                    mission_checkpoint_principal_id=None,
                    mission_checkpoint_trust_snapshot_id=None,
                    evidence=tuple(value.reference for value in evidence),
                ),
                evidence,
            )
        if (
            previous_global is None
            or previous_mission is None
            or previous_global.checkpoint_candidate is None
            or previous_global.finalization is None
            or previous_mission.checkpoint_candidate is None
            or previous_mission.finalization is None
        ):
            _reject(
                "modeled_head_floor_missing",
                "non-genesis event requires finalized global and mission predecessors",
            )
        global_candidate = previous_global.checkpoint_candidate
        mission_candidate = previous_mission.checkpoint_candidate
        global_decision = _authenticated_decision_self(previous_global.pending)
        mission_decision = _authenticated_decision_self(previous_mission.pending)
        global_checkpoint = _authenticated_checkpoint_self(
            global_candidate,
            decision=global_decision,
            policy=previous_global.pending.validation_policy,
        )
        mission_checkpoint = _authenticated_checkpoint_self(
            mission_candidate,
            decision=mission_decision,
            policy=previous_mission.pending.validation_policy,
        )
        if mission_checkpoint.checkpoint.event_digest != event.prev_digest:
            _reject(
                "modeled_head_floor_mismatch",
                "mission checkpoint predecessor does not cover the event predecessor",
            )
        evidence = self._head_floor_evidence(
            checkpoint_id=global_checkpoint.checkpoint.checkpoint_id,
            instance_sequence=(global_checkpoint.checkpoint.instance_sequence),
            mission_id=event.mission_id,
            mission_event_seq=mission_checkpoint.checkpoint.event_seq,
            purpose="predecessor",
        )
        return (
            HeadCheckpointFloorV1(
                service_instance_id=self.service_instance_id,
                environment_id=self.environment_id,
                instance_sequence=(global_checkpoint.checkpoint.instance_sequence),
                checkpoint_id=global_checkpoint.checkpoint.checkpoint_id,
                checkpoint_attestation_id=(signed_head_checkpoint_attestation_id(global_checkpoint.signed_checkpoint)),
                checkpoint_principal_id=(global_checkpoint.signer_principal_id),
                checkpoint_trust_snapshot_id=(global_checkpoint.trust_snapshot_id),
                mission_id=event.mission_id,
                mission_event_seq=mission_checkpoint.checkpoint.event_seq,
                mission_checkpoint_id=(mission_checkpoint.checkpoint.checkpoint_id),
                mission_checkpoint_attestation_id=(
                    signed_head_checkpoint_attestation_id(mission_checkpoint.signed_checkpoint)
                ),
                mission_checkpoint_principal_id=(mission_checkpoint.signer_principal_id),
                mission_checkpoint_trust_snapshot_id=(mission_checkpoint.trust_snapshot_id),
                evidence=tuple(value.reference for value in evidence),
            ),
            evidence,
        )

    def prepare_pending_transition(
        self,
        event: EventV1,
        *,
        previous_global: IntegrityLineageV1 | None,
        previous_mission: IntegrityLineageV1 | None,
    ) -> PendingIntegrityTransitionV1:
        """Produce one signed fixture decision and exact modeled provider dossier."""

        if type(event) is not EventV1:
            _reject(
                "invalid_integrity_event",
                "modeled decision service requires an exact EventV1",
            )
        if event.decision_time >= (2**63) - 1:
            _reject(
                "invalid_modeled_time",
                "modeled fixture time must leave one representable validity successor",
            )
        time_blobs = self._time_evidence(
            purpose="decision",
            event_digest=event.event_digest,
            epoch_second=event.decision_time,
        )
        views, floors, revocation_blobs = self._revocation_material()
        head_floor, head_floor_blobs = self._floor_for_predecessor(
            event=event,
            previous_global=previous_global,
            previous_mission=previous_mission,
        )
        transition_intent_id = content_id(
            "modeled_integrity_transition_intent",
            {
                "event_kind": event.kind,
                "profile": MODELED_INTEGRITY_PROFILE_V1,
                "unit": event.unit,
            },
        )
        instance_sequence = head_floor.instance_sequence + 1
        request_nonce = hashlib.sha256(
            canonical_dumps(
                {
                    "environment_id": self.environment_id,
                    "event_digest": event.event_digest,
                    "instance_sequence": instance_sequence,
                    "service_instance_id": self.service_instance_id,
                }
            )
        ).hexdigest()
        decision = IntegrityDecisionV1.issue(
            service_instance_id=self.service_instance_id,
            environment_id=self.environment_id,
            mission_id=event.mission_id,
            authority_id=event.authority_id,
            target_id=event.target_id,
            prior_global_checkpoint_sequence=(head_floor.instance_sequence),
            prior_global_checkpoint_id=head_floor.checkpoint_id,
            prior_global_checkpoint_attestation_id=(head_floor.checkpoint_attestation_id),
            prior_global_checkpoint_principal_id=(head_floor.checkpoint_principal_id),
            prior_global_checkpoint_trust_snapshot_id=(head_floor.checkpoint_trust_snapshot_id),
            prior_event_seq=event.seq - 1,
            prior_event_digest=event.prev_digest,
            event_kind=event.kind,
            proposed_event_digest=event.event_digest,
            transition_intent_id=transition_intent_id,
            request_nonce=request_nonce,
            time_lower_bound=event.decision_time,
            time_upper_bound=event.decision_time,
            time_policy_id=(self.validation_policy.decision_time_policy_id),
            time_evidence=tuple(value.reference for value in time_blobs),
            revocation_views=views,
            decision_policy_id=self.validation_policy.decision_policy_id,
        )
        pending = PendingIntegrityTransitionV1(
            event_digest=event.event_digest,
            mission_id=event.mission_id,
            event_seq=event.seq,
            instance_sequence=instance_sequence,
            signed_decision=self._decision_signer.sign_decision(decision),
            decision_trust_store=self.trust_store,
            validation_policy=self.validation_policy,
            revocation_floors=floors,
            prior_head_floor=head_floor,
            provider_evidence=_sorted_blobs(
                time_blobs,
                revocation_blobs,
                head_floor_blobs,
            ),
        )
        authenticate_pending_integrity_transition(
            pending,
            event=event,
            previous_global=previous_global,
        )
        return pending

    def prepare_anchor_statement(
        self,
        pending: PendingIntegrityTransitionV1,
    ) -> AnchorStatementRecordV1:
        """Prepare and persistable exact statement inputs after local event commit."""

        if type(pending) is not PendingIntegrityTransitionV1:
            _reject(
                "invalid_pending_integrity_transition",
                "anchor preparation requires an exact pending transition",
            )
        decision = pending.decision
        time_blobs = self._time_evidence(
            purpose="checkpoint",
            event_digest=pending.event_digest,
            epoch_second=decision.time_upper_bound,
        )
        decision_auth = _authenticated_decision_self(pending)
        prior_floor = pending.prior_head_floor
        checkpoint_time_evidence = tuple(value.reference for value in time_blobs)
        registration_body = _anchor_registration_body(
            pending,
            decision_auth=decision_auth,
            previous_mission_checkpoint_id=prior_floor.mission_checkpoint_id,
            previous_mission_checkpoint_attestation_id=(prior_floor.mission_checkpoint_attestation_id),
            previous_mission_checkpoint_principal_id=(prior_floor.mission_checkpoint_principal_id),
            previous_mission_checkpoint_trust_snapshot_id=(prior_floor.mission_checkpoint_trust_snapshot_id),
            time_lower_bound=decision.time_upper_bound,
            time_upper_bound=decision.time_upper_bound,
            time_policy_id=self.validation_policy.checkpoint_time_policy_id,
            time_evidence=checkpoint_time_evidence,
            anchor_policy_id=self.validation_policy.anchor_policy_id,
        )
        registration_request = _record_bytes(registration_body)
        statement_id = derive_anchor_statement_id(
            service_instance_id=decision.service_instance_id,
            environment_id=decision.environment_id,
            instance_sequence=pending.instance_sequence,
            previous_checkpoint_id=decision.prior_global_checkpoint_id,
            previous_checkpoint_attestation_id=(decision.prior_global_checkpoint_attestation_id),
            previous_checkpoint_principal_id=(decision.prior_global_checkpoint_principal_id),
            previous_checkpoint_trust_snapshot_id=(decision.prior_global_checkpoint_trust_snapshot_id),
            previous_mission_checkpoint_id=(prior_floor.mission_checkpoint_id),
            previous_mission_checkpoint_attestation_id=(prior_floor.mission_checkpoint_attestation_id),
            previous_mission_checkpoint_principal_id=(prior_floor.mission_checkpoint_principal_id),
            previous_mission_checkpoint_trust_snapshot_id=(prior_floor.mission_checkpoint_trust_snapshot_id),
            mission_id=decision.mission_id,
            authority_id=decision.authority_id,
            target_id=decision.target_id,
            event_seq=pending.event_seq,
            event_digest=pending.event_digest,
            integrity_decision_id=decision.decision_id,
            integrity_decision_attestation_id=(signed_integrity_decision_attestation_id(pending.signed_decision)),
            integrity_decision_principal_id=(decision_auth.signer_principal_id),
            integrity_decision_trust_snapshot_id=(decision_auth.trust_snapshot_id),
            time_lower_bound=decision.time_upper_bound,
            time_upper_bound=decision.time_upper_bound,
            time_policy_id=(self.validation_policy.checkpoint_time_policy_id),
            time_evidence=checkpoint_time_evidence,
            anchor_policy_id=self.validation_policy.anchor_policy_id,
        )
        if content_id("head_anchor_statement", registration_body) != statement_id:
            raise ModeledIntegrityServiceError(
                "modeled_anchor_derivation_mismatch",
                "modeled anchor request differs from the protocol-derived statement",
            )
        anchor = AnchorStatementRecordV1(
            pending_record_id=pending.record_id,
            event_digest=pending.event_digest,
            previous_mission_checkpoint_id=(prior_floor.mission_checkpoint_id),
            previous_mission_checkpoint_attestation_id=(prior_floor.mission_checkpoint_attestation_id),
            previous_mission_checkpoint_principal_id=(prior_floor.mission_checkpoint_principal_id),
            previous_mission_checkpoint_trust_snapshot_id=(prior_floor.mission_checkpoint_trust_snapshot_id),
            time_lower_bound=decision.time_upper_bound,
            time_upper_bound=decision.time_upper_bound,
            time_policy_id=(self.validation_policy.checkpoint_time_policy_id),
            time_evidence=checkpoint_time_evidence,
            anchor_policy_id=self.validation_policy.anchor_policy_id,
            anchor_statement_id=statement_id,
            registration_request=registration_request,
            provider_evidence=_sorted_blobs(time_blobs),
        )
        validate_anchor_statement_record(pending, anchor)
        return anchor

    def register_anchor_statement(
        self,
        anchor: AnchorStatementRecordV1,
    ) -> tuple[ProviderEvidenceBlobV1, ...]:
        """Idempotently model registration of one pre-receipt statement."""

        if type(anchor) is not AnchorStatementRecordV1:
            _reject(
                "invalid_anchor_statement_record",
                "anchor registration requires an exact statement record",
            )
        request = anchor.registration_request
        body = anchor.registration_body
        service_instance_id = _require_identity(
            body["service_instance_id"],
            "service_instance_id",
        )
        environment_id = _require_identity(
            body["environment_id"],
            "environment_id",
        )
        mission_id = _require_digest(body["mission_id"], "mission_id")
        instance_sequence = _require_nonnegative_int(
            body["instance_sequence"],
            "instance_sequence",
        )
        event_seq = _require_nonnegative_int(body["event_seq"], "event_seq")
        if service_instance_id != self.service_instance_id or environment_id != self.environment_id:
            raise IntegrityFinalityBlockedError(
                "modeled_anchor_scope_mismatch",
                "modeled anchor statement belongs to another service scope",
            )
        statement_value = (anchor.anchor_statement_id, request)
        global_slot = (
            service_instance_id,
            environment_id,
            instance_sequence,
        )
        mission_slot = (
            service_instance_id,
            environment_id,
            mission_id,
            event_seq,
        )
        receipts = tuple(
            _modeled_provider_blob(
                evidence_kind=HEAD_ANCHOR_RECEIPT_EVIDENCE_KIND,
                source_id=f"fixture.anchor.{suffix}",
                claim={
                    "anchor_statement_id": anchor.anchor_statement_id,
                    "registration": "included",
                    "service_instance_id": self.service_instance_id,
                },
            )
            for suffix in ("a", "b")
        )
        with self._lock:
            registered_request = self._registered_statement_requests.get(anchor.anchor_statement_id)
            if registered_request is not None and registered_request != request:
                raise IntegrityFinalityBlockedError(
                    "modeled_anchor_equivocation",
                    "modeled anchor statement identity was registered with different bytes",
                )
            registered_global = self._global_statement_slots.get(global_slot)
            registered_mission = self._mission_statement_slots.get(mission_slot)
            if (registered_global is not None and registered_global != statement_value) or (
                registered_mission is not None and registered_mission != statement_value
            ):
                raise IntegrityFinalityBlockedError(
                    "modeled_anchor_sequence_conflict",
                    "modeled anchor sequence slot already reserves another exact statement",
                )
            existing = self._statement_receipts.get(anchor.anchor_statement_id)
            if existing is None:
                self._registered_statement_requests[anchor.anchor_statement_id] = request
                self._global_statement_slots[global_slot] = statement_value
                self._mission_statement_slots[mission_slot] = statement_value
                self._statement_receipts[anchor.anchor_statement_id] = receipts
                return receipts
            if existing != receipts:
                raise IntegrityFinalityBlockedError(
                    "modeled_anchor_equivocation",
                    "modeled anchor returned different receipts for one statement",
                )
            self._registered_statement_requests[anchor.anchor_statement_id] = request
            self._global_statement_slots[global_slot] = statement_value
            self._mission_statement_slots[mission_slot] = statement_value
            return existing

    def prepare_checkpoint_candidate(
        self,
        pending: PendingIntegrityTransitionV1,
        anchor: AnchorStatementRecordV1,
        *,
        anchor_receipts: tuple[ProviderEvidenceBlobV1, ...],
    ) -> CheckpointCandidateRecordV1:
        """Create one deterministic signed checkpoint from retained receipts."""

        validate_anchor_statement_record(pending, anchor)
        receipts = _validated_evidence_blobs(anchor_receipts)
        if len(receipts) < 2 or any(value.evidence_kind != HEAD_ANCHOR_RECEIPT_EVIDENCE_KIND for value in receipts):
            _reject(
                "invalid_anchor_receipts",
                "checkpoint requires at least two typed anchor receipts",
            )
        decision = pending.decision
        decision_auth = _authenticated_decision_self(pending)
        checkpoint = HeadCheckpointV1.issue(
            service_instance_id=decision.service_instance_id,
            environment_id=decision.environment_id,
            instance_sequence=pending.instance_sequence,
            previous_checkpoint_id=decision.prior_global_checkpoint_id,
            previous_checkpoint_attestation_id=(decision.prior_global_checkpoint_attestation_id),
            previous_checkpoint_principal_id=(decision.prior_global_checkpoint_principal_id),
            previous_checkpoint_trust_snapshot_id=(decision.prior_global_checkpoint_trust_snapshot_id),
            previous_mission_checkpoint_id=(anchor.previous_mission_checkpoint_id),
            previous_mission_checkpoint_attestation_id=(anchor.previous_mission_checkpoint_attestation_id),
            previous_mission_checkpoint_principal_id=(anchor.previous_mission_checkpoint_principal_id),
            previous_mission_checkpoint_trust_snapshot_id=(anchor.previous_mission_checkpoint_trust_snapshot_id),
            mission_id=decision.mission_id,
            authority_id=decision.authority_id,
            target_id=decision.target_id,
            event_seq=pending.event_seq,
            event_digest=pending.event_digest,
            integrity_decision_id=decision.decision_id,
            integrity_decision_attestation_id=(signed_integrity_decision_attestation_id(pending.signed_decision)),
            integrity_decision_principal_id=(decision_auth.signer_principal_id),
            integrity_decision_trust_snapshot_id=(decision_auth.trust_snapshot_id),
            time_lower_bound=anchor.time_lower_bound,
            time_upper_bound=anchor.time_upper_bound,
            time_policy_id=anchor.time_policy_id,
            time_evidence=anchor.time_evidence,
            anchor_policy_id=anchor.anchor_policy_id,
            anchor_evidence=tuple(value.reference for value in receipts),
        )
        return CheckpointCandidateRecordV1(
            pending_record_id=pending.record_id,
            anchor_statement_record_id=anchor.record_id,
            event_digest=pending.event_digest,
            signed_checkpoint=self._checkpoint_signer.sign_checkpoint(checkpoint),
            checkpoint_trust_store=self.trust_store,
            provider_evidence=receipts,
        )

    def prime_catalog(
        self,
        *,
        previous_global: IntegrityLineageV1 | None,
        previous_mission: IntegrityLineageV1 | None,
    ) -> None:
        """Rehydrate the process-local modeled catalog from finalized local records.

        This is a recovery convenience for deterministic tests, not external evidence.
        The retained finalization records are still revalidated by the caller before use.
        """

        global_candidate = None if previous_global is None else previous_global.checkpoint_candidate
        mission_candidate = None if previous_mission is None else previous_mission.checkpoint_candidate
        if previous_global is not None and (global_candidate is None or previous_global.finalization is None):
            _reject(
                "unfinalized_integrity_predecessor",
                "modeled catalog can prime only from a finalized global predecessor",
            )
        if previous_mission is not None and (mission_candidate is None or previous_mission.finalization is None):
            _reject(
                "unfinalized_integrity_predecessor",
                "modeled catalog can prime only from a finalized mission predecessor",
            )
        with self._lock:
            if global_candidate is not None:
                current_global = self._global_checkpoint
                current_is_direct_successor = (
                    current_global is not None
                    and current_global.checkpoint.instance_sequence == global_candidate.checkpoint.instance_sequence + 1
                    and current_global.checkpoint.previous_checkpoint_id == global_candidate.checkpoint.checkpoint_id
                )
                if (
                    current_global is not None
                    and current_global.record_id != global_candidate.record_id
                    and not current_is_direct_successor
                ):
                    raise IntegrityFinalityBlockedError(
                        "modeled_catalog_global_conflict",
                        "modeled catalog is neither at the retained global predecessor nor its direct successor",
                    )
                if current_global is None:
                    self._global_checkpoint = global_candidate
                self._retain_published_checkpoint_wire(
                    global_candidate,
                )
            if mission_candidate is not None:
                mission_id = mission_candidate.checkpoint.mission_id
                existing = self._mission_checkpoints.get(mission_id)
                existing_is_direct_successor = (
                    existing is not None
                    and existing.checkpoint.event_seq == mission_candidate.checkpoint.event_seq + 1
                    and existing.checkpoint.previous_mission_checkpoint_id == mission_candidate.checkpoint.checkpoint_id
                )
                if (
                    existing is not None
                    and existing.record_id != mission_candidate.record_id
                    and not existing_is_direct_successor
                ):
                    raise IntegrityFinalityBlockedError(
                        "modeled_catalog_mission_conflict",
                        "modeled catalog is neither at the retained mission predecessor nor its direct successor",
                    )
                if existing is None:
                    self._mission_checkpoints[mission_id] = mission_candidate
                self._retain_published_checkpoint_wire(
                    mission_candidate,
                )

    def _retain_published_checkpoint_wire(
        self,
        candidate: CheckpointCandidateRecordV1,
    ) -> None:
        """Retain one exact signed fixture checkpoint without allowing equivocation."""

        checkpoint_id = candidate.checkpoint.checkpoint_id
        signed_wire = candidate.signed_checkpoint.to_bytes()
        existing_wire = self._published_by_id.get(checkpoint_id)
        if existing_wire is not None and existing_wire != signed_wire:
            raise IntegrityFinalityBlockedError(
                "modeled_checkpoint_identity_conflict",
                "one checkpoint identity maps to different signed bytes",
            )
        self._published_by_id[checkpoint_id] = signed_wire

    def publish_checkpoint(
        self,
        candidate: CheckpointCandidateRecordV1,
    ) -> None:
        """Idempotently compare-and-publish one exact signed checkpoint."""

        if type(candidate) is not CheckpointCandidateRecordV1:
            _reject(
                "invalid_checkpoint_candidate",
                "modeled publication requires an exact checkpoint candidate",
            )
        checkpoint = candidate.checkpoint
        signed_wire = candidate.signed_checkpoint.to_bytes()
        with self._lock:
            existing_wire = self._published_by_id.get(checkpoint.checkpoint_id)
            if existing_wire is not None:
                if existing_wire != signed_wire:
                    raise IntegrityFinalityBlockedError(
                        "modeled_checkpoint_identity_conflict",
                        "one checkpoint identity maps to different signed bytes",
                    )
                return
            previous_global = self._global_checkpoint
            previous_mission = self._mission_checkpoints.get(checkpoint.mission_id)
            if previous_global is None:
                expected_global = head_checkpoint_genesis_id(
                    service_instance_id=self.service_instance_id,
                    environment_id=self.environment_id,
                )
                global_ok = checkpoint.instance_sequence == 0 and checkpoint.previous_checkpoint_id == expected_global
            else:
                global_ok = (
                    checkpoint.instance_sequence == previous_global.checkpoint.instance_sequence + 1
                    and checkpoint.previous_checkpoint_id == previous_global.checkpoint.checkpoint_id
                )
            if previous_mission is None:
                expected_mission = mission_checkpoint_genesis_id(
                    service_instance_id=self.service_instance_id,
                    environment_id=self.environment_id,
                    mission_id=checkpoint.mission_id,
                )
                mission_ok = checkpoint.event_seq == 0 and checkpoint.previous_mission_checkpoint_id == expected_mission
            else:
                mission_ok = (
                    checkpoint.event_seq == previous_mission.checkpoint.event_seq + 1
                    and checkpoint.previous_mission_checkpoint_id == previous_mission.checkpoint.checkpoint_id
                )
            if not global_ok or not mission_ok:
                raise IntegrityFinalityBlockedError(
                    "modeled_catalog_compare_and_set_failed",
                    "checkpoint does not extend the modeled catalog heads",
                )
            self._retain_published_checkpoint_wire(candidate)
            self._global_checkpoint = candidate
            self._mission_checkpoints[checkpoint.mission_id] = candidate

    def observe_current_floor(
        self,
        pending: PendingIntegrityTransitionV1,
        candidate: CheckpointCandidateRecordV1,
    ) -> tuple[HeadCheckpointFloorV1, tuple[ProviderEvidenceBlobV1, ...]]:
        """Return a modeled current floor only for the exact published checkpoint."""

        if (
            type(pending) is not PendingIntegrityTransitionV1
            or type(candidate) is not CheckpointCandidateRecordV1
            or candidate.pending_record_id != pending.record_id
        ):
            _reject(
                "invalid_checkpoint_candidate",
                "modeled monitor requires an exact pending-bound checkpoint candidate",
            )
        checkpoint = candidate.checkpoint
        with self._lock:
            if (
                self._global_checkpoint is None
                or self._global_checkpoint.record_id != candidate.record_id
                or self._mission_checkpoints.get(checkpoint.mission_id) is None
                or self._mission_checkpoints[checkpoint.mission_id].record_id != candidate.record_id
            ):
                raise IntegrityFinalityPendingError(
                    "modeled_checkpoint_not_current",
                    "modeled catalog has not made this checkpoint current",
                )
        decision = _authenticated_decision_self(pending)
        authenticated = _authenticated_checkpoint_self(
            candidate,
            decision=decision,
            policy=pending.validation_policy,
        )
        evidence = self._head_floor_evidence(
            checkpoint_id=checkpoint.checkpoint_id,
            instance_sequence=checkpoint.instance_sequence,
            mission_id=checkpoint.mission_id,
            mission_event_seq=checkpoint.event_seq,
            purpose="current",
        )
        attestation_id = signed_head_checkpoint_attestation_id(authenticated.signed_checkpoint)
        floor = HeadCheckpointFloorV1(
            service_instance_id=checkpoint.service_instance_id,
            environment_id=checkpoint.environment_id,
            instance_sequence=checkpoint.instance_sequence,
            checkpoint_id=checkpoint.checkpoint_id,
            checkpoint_attestation_id=attestation_id,
            checkpoint_principal_id=authenticated.signer_principal_id,
            checkpoint_trust_snapshot_id=authenticated.trust_snapshot_id,
            mission_id=checkpoint.mission_id,
            mission_event_seq=checkpoint.event_seq,
            mission_checkpoint_id=checkpoint.checkpoint_id,
            mission_checkpoint_attestation_id=attestation_id,
            mission_checkpoint_principal_id=(authenticated.signer_principal_id),
            mission_checkpoint_trust_snapshot_id=(authenticated.trust_snapshot_id),
            evidence=tuple(value.reference for value in evidence),
        )
        return floor, evidence


def validate_pending_transition(
    event: EventV1,
    pending: PendingIntegrityTransitionV1,
    *,
    previous_global: IntegrityLineageV1 | None,
    previous_mission: IntegrityLineageV1 | None,
    service_instance_id: str,
    environment_id: str,
    validation_policy: IntegrityValidationPolicyV1,
) -> AuthenticatedIntegrityDecisionV1:
    """Store-facing locked validator for a proposed pending transition."""

    service_instance_id = _require_identity(
        service_instance_id,
        "service_instance_id",
    )
    environment_id = _require_identity(
        environment_id,
        "environment_id",
    )
    policy = _snapshot_policy(validation_policy)
    if (
        pending.decision.service_instance_id != service_instance_id
        or pending.decision.environment_id != environment_id
        or _policy_body(pending.validation_policy) != _policy_body(policy)
    ):
        _reject(
            "integrity_enrollment_mismatch",
            "pending transition differs from the enrolled scope or policy",
        )
    authenticated = authenticate_pending_integrity_transition(
        pending,
        event=event,
        previous_global=previous_global,
    )
    floor = pending.prior_head_floor
    if previous_mission is None:
        expected_mission_genesis = mission_checkpoint_genesis_id(
            service_instance_id=service_instance_id,
            environment_id=environment_id,
            mission_id=event.mission_id,
        )
        if event.seq != 0 or floor.mission_event_seq != -1 or floor.mission_checkpoint_id != expected_mission_genesis:
            _reject(
                "prior_mission_head_floor_mismatch",
                "first mission event must extend its exact modeled mission genesis",
            )
    else:
        _, previous_checkpoint = _authenticated_lineage_values(previous_mission)
        if previous_checkpoint is None:
            _reject(
                "prior_mission_head_floor_mismatch",
                "non-genesis event requires a finalized mission predecessor",
            )
        attestation_id = signed_head_checkpoint_attestation_id(previous_checkpoint.signed_checkpoint)
        expected = (
            previous_checkpoint.checkpoint.event_seq,
            previous_checkpoint.checkpoint.checkpoint_id,
            attestation_id,
            previous_checkpoint.signer_principal_id,
            previous_checkpoint.trust_snapshot_id,
            previous_checkpoint.checkpoint.event_digest,
        )
        observed = (
            floor.mission_event_seq,
            floor.mission_checkpoint_id,
            floor.mission_checkpoint_attestation_id,
            floor.mission_checkpoint_principal_id,
            floor.mission_checkpoint_trust_snapshot_id,
            event.prev_digest,
        )
        if observed != expected:
            _reject(
                "prior_mission_head_floor_mismatch",
                "modeled mission floor differs from the exact retained predecessor",
            )
    return authenticated


def validate_anchor_statement(
    pending: PendingIntegrityTransitionV1,
    record: AnchorStatementRecordV1,
    *,
    previous_mission: IntegrityLineageV1 | None,
) -> None:
    """Store-facing validator for the post-commit pre-registration statement."""

    validate_anchor_statement_record(pending, record)
    floor = pending.prior_head_floor
    expected = (
        floor.mission_checkpoint_id,
        floor.mission_checkpoint_attestation_id,
        floor.mission_checkpoint_principal_id,
        floor.mission_checkpoint_trust_snapshot_id,
    )
    observed = (
        record.previous_mission_checkpoint_id,
        record.previous_mission_checkpoint_attestation_id,
        record.previous_mission_checkpoint_principal_id,
        record.previous_mission_checkpoint_trust_snapshot_id,
    )
    if observed != expected:
        _reject(
            "anchor_mission_predecessor_mismatch",
            "anchor statement differs from the pending external mission floor",
        )
    if previous_mission is None and floor.mission_event_seq != -1:
        _reject(
            "anchor_mission_predecessor_mismatch",
            "anchor claims a non-genesis mission predecessor that was not supplied",
        )
    if previous_mission is not None:
        _, checkpoint = _authenticated_lineage_values(previous_mission)
        if checkpoint is None or checkpoint.checkpoint.checkpoint_id != record.previous_mission_checkpoint_id:
            _reject(
                "anchor_mission_predecessor_mismatch",
                "anchor does not extend the supplied finalized mission predecessor",
            )


def validate_checkpoint_candidate(
    event: EventV1,
    pending: PendingIntegrityTransitionV1,
    anchor: AnchorStatementRecordV1,
    record: CheckpointCandidateRecordV1,
    *,
    previous_global: IntegrityLineageV1 | None,
    previous_mission: IntegrityLineageV1 | None,
) -> AuthenticatedHeadCheckpointV1:
    """Store-facing locked validator for a retained signed checkpoint candidate."""

    return authenticate_checkpoint_candidate(
        pending,
        anchor,
        record,
        event=event,
        previous_global=previous_global,
        previous_mission=previous_mission,
    )


def validate_finalization(
    event: EventV1,
    lineage: IntegrityLineageV1,
    record: FinalizedIntegrityTransitionV1,
    *,
    previous_global: IntegrityLineageV1 | None,
    previous_mission: IntegrityLineageV1 | None,
) -> AuthenticatedHeadCheckpointV1:
    """Store-facing locked validator requiring the exact checkpoint as current."""

    if type(lineage) is not IntegrityLineageV1 or lineage.finalization is not None:
        _reject(
            "invalid_finalization_lineage",
            "finalization requires an exact not-yet-finalized lineage",
        )
    completed = IntegrityLineageV1(
        pending=lineage.pending,
        anchor_statement=lineage.anchor_statement,
        checkpoint_candidate=lineage.checkpoint_candidate,
        finalization=record,
    )
    return validate_finalized_integrity_transition(
        completed,
        event=event,
        previous_global=previous_global,
        previous_mission=previous_mission,
    )


def _require_pending_authority_binding(
    pending: PendingIntegrityTransitionV1,
    binding: ModeledIntegrityAuthorityBindingV1,
) -> None:
    if type(pending) is not PendingIntegrityTransitionV1:
        _reject(
            "invalid_modeled_integrity_adapter_result",
            "modeled decision adapter must return an exact pending transition",
        )
    binding = _snapshot_modeled_authority_binding(binding)
    if (
        pending.decision_trust_store.snapshot_id != binding.trust_snapshot_id
        or pending.signed_decision.key_id != binding.decision_key_id
        or _trust_store_body(pending.decision_trust_store) != _trust_store_body(binding.trust_store)
    ):
        _reject(
            "modeled_integrity_authority_binding_mismatch",
            "pending transition differs from the enrolled modeled fixture authority",
        )


def _require_checkpoint_authority_binding(
    candidate: CheckpointCandidateRecordV1,
    binding: ModeledIntegrityAuthorityBindingV1,
) -> None:
    if type(candidate) is not CheckpointCandidateRecordV1:
        _reject(
            "invalid_modeled_integrity_adapter_result",
            "modeled checkpoint adapter must return an exact candidate",
        )
    binding = _snapshot_modeled_authority_binding(binding)
    if (
        candidate.checkpoint_trust_store.snapshot_id != binding.trust_snapshot_id
        or candidate.signed_checkpoint.key_id != binding.checkpoint_key_id
        or _trust_store_body(candidate.checkpoint_trust_store) != _trust_store_body(binding.trust_store)
    ):
        _reject(
            "modeled_integrity_authority_binding_mismatch",
            "checkpoint candidate differs from the enrolled modeled fixture authority",
        )


class _ModeledIntegrityServicePort(Protocol):
    service_instance_id: str
    environment_id: str
    validation_policy: IntegrityValidationPolicyV1
    authority_binding: ModeledIntegrityAuthorityBindingV1

    def prepare_pending_transition(
        self,
        event: EventV1,
        *,
        previous_global: IntegrityLineageV1 | None,
        previous_mission: IntegrityLineageV1 | None,
    ) -> PendingIntegrityTransitionV1: ...

    def prepare_anchor_statement(
        self,
        pending: PendingIntegrityTransitionV1,
    ) -> AnchorStatementRecordV1: ...

    def register_anchor_statement(
        self,
        anchor: AnchorStatementRecordV1,
    ) -> tuple[ProviderEvidenceBlobV1, ...]: ...

    def prepare_checkpoint_candidate(
        self,
        pending: PendingIntegrityTransitionV1,
        anchor: AnchorStatementRecordV1,
        *,
        anchor_receipts: tuple[ProviderEvidenceBlobV1, ...],
    ) -> CheckpointCandidateRecordV1: ...

    def prime_catalog(
        self,
        *,
        previous_global: IntegrityLineageV1 | None,
        previous_mission: IntegrityLineageV1 | None,
    ) -> None: ...

    def publish_checkpoint(
        self,
        candidate: CheckpointCandidateRecordV1,
    ) -> None: ...

    def observe_current_floor(
        self,
        pending: PendingIntegrityTransitionV1,
        candidate: CheckpointCandidateRecordV1,
    ) -> tuple[
        HeadCheckpointFloorV1,
        tuple[ProviderEvidenceBlobV1, ...],
    ]: ...


class _IntegrityTransitionStorePort(Protocol):
    def enroll_modeled_integrity(
        self,
        *,
        service_instance_id: str,
        environment_id: str,
        validation_policy: IntegrityValidationPolicyV1,
        authority_binding: ModeledIntegrityAuthorityBindingV1,
    ) -> None: ...

    def load(self, mission_id: str) -> tuple[EventV1, ...]: ...

    def load_event_artifacts(
        self,
        selectors: object,
        *,
        maximum_total: int,
    ) -> tuple[bytes, ...]: ...

    def resolve_evidence_artifact(
        self,
        role: str,
        digest: str,
        maximum: int,
        evidence_store: FileEvidenceStore,
    ) -> bytes: ...

    def resolve_evidence_artifacts(
        self,
        requests: object,
        evidence_store: FileEvidenceStore,
        *,
        maximum_total: int,
    ) -> tuple[bytes, ...]: ...

    def load_integrity_lineage(
        self,
        event_digest: str,
    ) -> IntegrityLineageV1 | None: ...

    def load_integrity_event(
        self,
        event_digest: str,
    ) -> EventV1 | None: ...

    def load_latest_finalized_integrity_lineages(
        self,
        mission_id: str,
    ) -> tuple[IntegrityLineageV1 | None, IntegrityLineageV1 | None]: ...

    def load_integrity_predecessor_lineages(
        self,
        event_digest: str,
    ) -> tuple[IntegrityLineageV1 | None, IntegrityLineageV1 | None]: ...

    def append_pending_integrity_event(
        self,
        event: EventV1,
        *,
        expected_head: str,
        pending: PendingIntegrityTransitionV1,
        evidence_store: FileEvidenceStore | None,
    ) -> EventV1: ...

    def load_unresolved_integrity_transition(
        self,
    ) -> IntegrityLineageV1 | None: ...

    def retain_integrity_anchor_statement(
        self,
        record: AnchorStatementRecordV1,
    ) -> AnchorStatementRecordV1: ...

    def load_integrity_anchor_statement(
        self,
        event_digest: str,
    ) -> AnchorStatementRecordV1 | None: ...

    def retain_integrity_checkpoint_candidate(
        self,
        record: CheckpointCandidateRecordV1,
    ) -> CheckpointCandidateRecordV1: ...

    def load_integrity_checkpoint_candidate(
        self,
        event_digest: str,
    ) -> CheckpointCandidateRecordV1 | None: ...

    def finalize_integrity_transition(
        self,
        record: FinalizedIntegrityTransitionV1,
    ) -> FinalizedIntegrityTransitionV1: ...

    def load_integrity_finalization(
        self,
        event_digest: str,
    ) -> FinalizedIntegrityTransitionV1 | None: ...


def _require_store_port(value: object) -> _IntegrityTransitionStorePort:
    methods = (
        "append_pending_integrity_event",
        "enroll_modeled_integrity",
        "finalize_integrity_transition",
        "load",
        "load_event_artifacts",
        "load_integrity_anchor_statement",
        "load_integrity_checkpoint_candidate",
        "load_integrity_finalization",
        "load_integrity_event",
        "load_integrity_lineage",
        "load_integrity_predecessor_lineages",
        "load_latest_finalized_integrity_lineages",
        "load_unresolved_integrity_transition",
        "resolve_evidence_artifact",
        "resolve_evidence_artifacts",
        "retain_integrity_anchor_statement",
        "retain_integrity_checkpoint_candidate",
    )
    if any(not callable(getattr(value, method, None)) for method in methods):
        _reject(
            "invalid_integrity_store",
            "modeled integrity facade requires the complete explicit store port",
        )
    return value  # type: ignore[return-value]


def _require_service_port(value: object) -> _ModeledIntegrityServicePort:
    methods = (
        "observe_current_floor",
        "prepare_anchor_statement",
        "prepare_checkpoint_candidate",
        "prepare_pending_transition",
        "prime_catalog",
        "publish_checkpoint",
        "register_anchor_statement",
    )
    if (
        any(not callable(getattr(value, method, None)) for method in methods)
        or type(getattr(value, "service_instance_id", None)) is not str
        or type(getattr(value, "environment_id", None)) is not str
        or type(getattr(value, "validation_policy", None)) is not IntegrityValidationPolicyV1
        or type(getattr(value, "authority_binding", None)) is not ModeledIntegrityAuthorityBindingV1
    ):
        _reject(
            "invalid_modeled_integrity_service",
            "modeled integrity facade requires the complete explicit service port",
        )
    return value  # type: ignore[return-value]


@dataclass(frozen=True, slots=True)
class GovernedBlockedFinalityBindingV1:
    """Opt-in governed blocked-finality wiring for the modeled facade.

    ``time_source`` must return a freshly qualified ADR-0012 time bundle.  A local clock
    never records when finality stopped.
    """

    profile: object
    time_source: object

    def __post_init__(self) -> None:
        from .blocked_finality_v1 import BlockedFinalityRecoveryProfileV1

        if type(self.profile) is not BlockedFinalityRecoveryProfileV1:
            _reject(
                "invalid_governed_blocked_finality_binding",
                "governed blocked finality requires an exact recovery profile",
            )
        if not callable(self.time_source):
            _reject(
                "invalid_governed_blocked_finality_binding",
                "governed blocked finality requires a callable qualified-time source",
            )

    def qualified_time(self) -> object:
        """Return one freshly qualified time bundle for a durable observation."""

        from etzio.kernel.integrity_adapters_v1 import QualifiedTimeBundleV1

        bundle = self.time_source()
        if type(bundle) is not QualifiedTimeBundleV1:
            _reject(
                "invalid_governed_blocked_finality_binding",
                "the qualified-time source did not return a sealed time bundle",
            )
        return bundle


def _snapshot_governed_blocked_finality(
    value: object,
) -> GovernedBlockedFinalityBindingV1 | None:
    if value is None:
        return None
    if type(value) is not GovernedBlockedFinalityBindingV1:
        _reject(
            "invalid_governed_blocked_finality_binding",
            "an exact GovernedBlockedFinalityBindingV1 is required",
        )
    return value  # type: ignore[return-value]


class ModeledIntegrityFinalizingEventStoreV1:
    """Explicit modeled-finality facade over the SQLite event-store port.

    Each append first recovers any older pending transition, commits the new event and
    signed decision through ``append_pending_integrity_event``, performs modeled provider
    calls only after that store method returns, and returns the event only after the exact
    current external-floor record is retained and revalidated.

    ``load`` first recovers the globally serialized pending transition before exposing
    history.  This is intentional for the modeled command facade: existing fixture,
    lease, resolution, and receipt commands may otherwise take a replay shortcut before
    reaching an append method.  Recovery itself uses the underlying store directly, so
    the load-triggered recovery path does not recurse.
    """

    # Governed blocked finality is opt-in.  The class default keeps every existing
    # construction ungoverned, including deliberate ``__init__`` bypasses that exercise
    # ``_advance_finality`` in isolation.
    _blocked_finality: object | None = None

    def __init__(
        self,
        store: object,
        services: object,
        *,
        blocked_finality: object | None = None,
    ) -> None:
        self._store = _require_store_port(store)
        self._services = _require_service_port(services)
        self._blocked_finality = _snapshot_governed_blocked_finality(blocked_finality)
        self.service_instance_id = _require_identity(
            services.service_instance_id,
            "service_instance_id",
        )
        self.environment_id = _require_identity(
            services.environment_id,
            "environment_id",
        )
        self.validation_policy = _snapshot_policy(services.validation_policy)
        self.authority_binding = _snapshot_modeled_authority_binding(services.authority_binding)
        self._store.enroll_modeled_integrity(
            service_instance_id=self.service_instance_id,
            environment_id=self.environment_id,
            validation_policy=self.validation_policy,
            authority_binding=self.authority_binding,
        )
        if self._blocked_finality is not None:
            self._store.enroll_blocked_finality_recovery(
                self._blocked_finality.profile
            )

    def load(self, mission_id: str) -> tuple[EventV1, ...]:
        self._require_unsealed_instance()
        self.recover_pending_transition()
        return self._store.load(mission_id)

    def _require_unsealed_instance(self) -> None:
        """Refuse every consequential command once a governed seal is retained."""

        if self._blocked_finality is None:
            return
        if self._store.instance_is_sealed():
            raise IntegrityInstanceSealedError(
                "modeled_integrity_instance_sealed",
                "a governed seal forbids every further consequential command",
            )

    def _require_recovery_authorization(
        self,
        lineage: IntegrityLineageV1,
    ) -> None:
        """Require an authorized governed retry once a block is durably retained.

        Without this gate a deterministic block would be retried without bound.  The
        authorization must answer the exact latest retained observation.
        """

        from .blocked_finality_v1 import (
            RETRY_AUTHORIZED_DISPOSITION_V1,
            GovernedRecoveryDecisionV1,
        )

        if self._blocked_finality is None:
            return
        observations = self._store.load_blocked_finality_observations(
            lineage.pending.event_digest
        )
        if not observations:
            return
        latest = observations[-1]
        signed = self._store.load_governed_recovery_decision(latest.observation_id)
        retained_context = (
            f"attempt {latest.attempt_ordinal} was blocked at "
            f"{latest.unresolved_phase} during {latest.blocked_operation} "
            f"with reason {latest.blocked_reason_code}"
        )
        if signed is None:
            raise IntegrityRecoveryNotAuthorizedError(
                "modeled_integrity_recovery_unauthorized",
                "a retained blocked observation has no governed recovery decision: "
                f"{retained_context}",
            )
        decision = GovernedRecoveryDecisionV1.from_canonical_bytes(signed.decision_bytes)
        if decision.disposition != RETRY_AUTHORIZED_DISPOSITION_V1:
            raise IntegrityRecoveryNotAuthorizedError(
                "modeled_integrity_recovery_unauthorized",
                "the retained governed decision does not authorize a retry: "
                f"{retained_context}",
            )

    def blocked_finality_status(self) -> dict[str, object] | None:
        """Return a non-consequential view of the retained blocked state.

        This inspection interface cannot append, authorize, resolve, or return command
        success, and it never projects the pending event as a finalized head.
        """

        if self._blocked_finality is None:
            return None
        lineage = self._store.load_unresolved_integrity_transition()
        if lineage is None:
            return None
        observations = self._store.load_blocked_finality_observations(
            lineage.pending.event_digest
        )
        latest = observations[-1] if observations else None
        signed = (
            self._store.load_governed_recovery_decision(latest.observation_id)
            if latest is not None
            else None
        )
        disposition: str | None = None
        if signed is not None:
            from .blocked_finality_v1 import GovernedRecoveryDecisionV1

            disposition = GovernedRecoveryDecisionV1.from_canonical_bytes(
                signed.decision_bytes
            ).disposition
        return {
            "attempt_count": len(observations),
            "event_digest": lineage.pending.event_digest,
            "instance_sealed": self._store.instance_is_sealed(),
            "latest_attempt_ordinal": (
                latest.attempt_ordinal if latest is not None else None
            ),
            "latest_blocked_operation": (
                latest.blocked_operation if latest is not None else None
            ),
            "latest_blocked_reason_code": (
                latest.blocked_reason_code if latest is not None else None
            ),
            "latest_disposition": disposition,
            "mission_id": lineage.pending.mission_id,
            "unresolved_phase": lineage.phase,
        }

    def _retain_blocked_observation(
        self,
        lineage: IntegrityLineageV1,
        blocked: IntegrityFinalityBlockedError,
    ) -> None:
        """Retain one durable observation of an exact deterministic block.

        This runs outside every blocked classifier.  A store failure here keeps its own
        domain and propagates: recording that finality is blocked must never itself be
        reclassified as a deterministic adapter refusal.
        """

        from .blocked_finality_v1 import (
            BLOCKED_REASON_CODES_V1,
            BlockedFinalityObservationV1,
        )

        binding = self._blocked_finality
        if binding is None:
            return
        phase = lineage.phase
        if phase == "finalized":
            return
        if phase == "checkpoint_candidate_retained":
            phase_record_id = lineage.checkpoint_candidate.record_id
            operation = "observe_current_floor"
        elif phase == "anchor_statement_ready":
            phase_record_id = lineage.anchor_statement.record_id
            operation = "prepare_checkpoint_candidate"
        else:
            phase_record_id = lineage.pending.record_id
            operation = "prepare_anchor_statement"
        reason_code = blocked.reason_code
        if reason_code not in BLOCKED_REASON_CODES_V1:
            # An unclassifiable refusal is retained as a contract failure rather than
            # widening the closed taxonomy with provider-controlled text.
            reason_code = "modeled_integrity_adapter_contract_failure"
        retained = self._store.load_blocked_finality_observations(
            lineage.pending.event_digest
        )
        decision = lineage.pending.decision
        observation = BlockedFinalityObservationV1.record(
            profile=binding.profile,
            mission_id=lineage.pending.mission_id,
            authority_id=decision.authority_id,
            target_id=decision.target_id,
            event_digest=lineage.pending.event_digest,
            event_seq=lineage.pending.event_seq,
            instance_sequence=lineage.pending.instance_sequence,
            pending_record_id=lineage.pending.record_id,
            unresolved_phase=phase,
            unresolved_phase_record_id=phase_record_id,
            blocked_operation=operation,
            blocked_reason_code=reason_code,
            attempt_ordinal=(
                retained[-1].attempt_ordinal + 1 if retained else 1
            ),
            time_bundle=binding.qualified_time(),
        )
        self._store.retain_blocked_finality_observation(observation)

    def load_event_artifacts(
        self,
        selectors: object,
        *,
        maximum_total: int,
    ) -> tuple[bytes, ...]:
        return self._store.load_event_artifacts(
            selectors,
            maximum_total=maximum_total,
        )

    def resolve_evidence_artifact(
        self,
        role: str,
        digest: str,
        maximum: int,
        evidence_store: FileEvidenceStore,
    ) -> bytes:
        return self._store.resolve_evidence_artifact(
            role,
            digest,
            maximum,
            evidence_store,
        )

    def resolve_evidence_artifacts(
        self,
        requests: object,
        evidence_store: FileEvidenceStore,
        *,
        maximum_total: int,
    ) -> tuple[bytes, ...]:
        return self._store.resolve_evidence_artifacts(
            requests,
            evidence_store,
            maximum_total=maximum_total,
        )

    def load_integrity_lineage(
        self,
        event_digest: str,
    ) -> IntegrityLineageV1 | None:
        return self._store.load_integrity_lineage(event_digest)

    def _event_for_lineage(self, lineage: IntegrityLineageV1) -> EventV1:
        event = self._store.load_integrity_event(lineage.pending.event_digest)
        if event is None or event.mission_id != lineage.pending.mission_id or event.seq != lineage.pending.event_seq:
            _reject(
                "integrity_event_missing",
                "retained integrity lineage has no canonical event",
            )
        return event

    @staticmethod
    def _validated_predecessors(
        event: EventV1,
        previous_global: IntegrityLineageV1 | None,
        previous_mission: IntegrityLineageV1 | None,
    ) -> tuple[
        IntegrityLineageV1 | None,
        IntegrityLineageV1 | None,
    ]:
        if event.seq == 0:
            if event.prev_digest != GENESIS_DIGEST:
                _reject(
                    "invalid_integrity_event_predecessor",
                    "event zero must extend the fixed event genesis",
                )
            if previous_mission is not None:
                _reject(
                    "invalid_integrity_event_predecessor",
                    "first mission event cannot have a finalized mission predecessor",
                )
            return previous_global, None
        if (
            previous_global is None
            or previous_mission is None
            or previous_mission.pending.event_digest != event.prev_digest
        ):
            _reject(
                "uncheckpointed_integrity_prefix",
                "modeled integrity requires exact finalized global and mission predecessors",
            )
        return previous_global, previous_mission

    def _latest_predecessors_for_new_event(
        self,
        event: EventV1,
    ) -> tuple[
        IntegrityLineageV1 | None,
        IntegrityLineageV1 | None,
    ]:
        previous_global, previous_mission = self._store.load_latest_finalized_integrity_lineages(event.mission_id)
        return self._validated_predecessors(
            event,
            previous_global,
            previous_mission,
        )

    def _retained_predecessors(
        self,
        lineage: IntegrityLineageV1,
    ) -> tuple[
        IntegrityLineageV1 | None,
        IntegrityLineageV1 | None,
    ]:
        event = self._event_for_lineage(lineage)
        previous_global, previous_mission = self._store.load_integrity_predecessor_lineages(
            lineage.pending.event_digest
        )
        return self._validated_predecessors(
            event,
            previous_global,
            previous_mission,
        )

    def _recover_lineage(
        self,
        lineage: IntegrityLineageV1,
    ) -> IntegrityLineageV1:
        event = self._event_for_lineage(lineage)
        previous_global, previous_mission = self._retained_predecessors(lineage)
        _require_pending_authority_binding(
            lineage.pending,
            self.authority_binding,
        )
        validate_pending_transition(
            event,
            lineage.pending,
            previous_global=previous_global,
            previous_mission=previous_mission,
            service_instance_id=self.service_instance_id,
            environment_id=self.environment_id,
            validation_policy=self.validation_policy,
        )
        _call_modeled_integrity_adapter(
            "prime_catalog",
            lambda: self._services.prime_catalog(
                previous_global=previous_global,
                previous_mission=previous_mission,
            ),
        )

        anchor = lineage.anchor_statement
        if anchor is None:
            # Provider-side preparation is complete before the local retention
            # transaction begins.
            proposed_anchor = _call_modeled_integrity_adapter(
                "prepare_anchor_statement",
                lambda: self._services.prepare_anchor_statement(lineage.pending),
            )
            validate_anchor_statement(
                lineage.pending,
                proposed_anchor,
                previous_mission=previous_mission,
            )
            anchor = self._store.retain_integrity_anchor_statement(proposed_anchor)
        else:
            validate_anchor_statement(
                lineage.pending,
                anchor,
                previous_mission=previous_mission,
            )
        lineage = IntegrityLineageV1(
            pending=lineage.pending,
            anchor_statement=anchor,
            checkpoint_candidate=lineage.checkpoint_candidate,
            finalization=lineage.finalization,
        )

        candidate = lineage.checkpoint_candidate
        if candidate is None:
            # The modeled registration call is outside every store transaction.  Its
            # idempotency key is the already-retained anchor_statement_id.
            receipts = _call_modeled_integrity_adapter(
                "register_anchor_statement",
                lambda: self._services.register_anchor_statement(anchor),
            )
            proposed_candidate = _call_modeled_integrity_adapter(
                "prepare_checkpoint_candidate",
                lambda: self._services.prepare_checkpoint_candidate(
                    lineage.pending,
                    anchor,
                    anchor_receipts=receipts,
                ),
            )
            _require_checkpoint_authority_binding(
                proposed_candidate,
                self.authority_binding,
            )
            validate_checkpoint_candidate(
                event,
                lineage.pending,
                anchor,
                proposed_candidate,
                previous_global=previous_global,
                previous_mission=previous_mission,
            )
            candidate = self._store.retain_integrity_checkpoint_candidate(proposed_candidate)
        else:
            _require_checkpoint_authority_binding(
                candidate,
                self.authority_binding,
            )
            validate_checkpoint_candidate(
                event,
                lineage.pending,
                anchor,
                candidate,
                previous_global=previous_global,
                previous_mission=previous_mission,
            )
        lineage = IntegrityLineageV1(
            pending=lineage.pending,
            anchor_statement=anchor,
            checkpoint_candidate=candidate,
            finalization=lineage.finalization,
        )

        finalization = lineage.finalization
        if finalization is None:
            # Publication and monitoring are both outside SQLite transactions.  The
            # candidate was retained first, so recovery always republishes identical
            # signed bytes.
            _call_modeled_integrity_adapter(
                "publish_checkpoint",
                lambda: self._services.publish_checkpoint(candidate),
            )
            floor, floor_evidence = _call_modeled_integrity_adapter(
                "observe_current_floor",
                lambda: self._services.observe_current_floor(
                    lineage.pending,
                    candidate,
                ),
            )
            proposed_finalization = FinalizedIntegrityTransitionV1(
                pending_record_id=lineage.pending.record_id,
                checkpoint_candidate_record_id=candidate.record_id,
                event_digest=lineage.pending.event_digest,
                external_head_floor=floor,
                provider_evidence=floor_evidence,
            )
            validate_finalization(
                event,
                lineage,
                proposed_finalization,
                previous_global=previous_global,
                previous_mission=previous_mission,
            )
            finalization = self._store.finalize_integrity_transition(proposed_finalization)
        completed = IntegrityLineageV1(
            pending=lineage.pending,
            anchor_statement=anchor,
            checkpoint_candidate=candidate,
            finalization=finalization,
        )
        validate_finalized_integrity_transition(
            completed,
            event=event,
            previous_global=previous_global,
            previous_mission=previous_mission,
        )
        return completed

    def _advance_finality(
        self,
        lineage: IntegrityLineageV1,
    ) -> IntegrityLineageV1:
        """Share deterministic local-integrity normalization across append and replay."""

        self._require_unsealed_instance()
        self._require_recovery_authorization(lineage)
        try:
            return self._classified_advance_finality(lineage)
        except IntegrityFinalityBlockedError as blocked:
            # Retention runs outside the classifier below, so a store failure keeps its
            # own domain instead of becoming a deterministic adapter refusal.
            self._retain_blocked_observation(lineage, blocked)
            raise

    def _classified_advance_finality(
        self,
        lineage: IntegrityLineageV1,
    ) -> IntegrityLineageV1:
        try:
            return self._recover_lineage(lineage)
        except IntegrityFinalityPendingError:
            raise
        except IntegrityFinalityBlockedError:
            raise
        except EventStoreError:
            # SQLite contention, capacity, corruption, and operational failures
            # retain their store-domain classification.  Recasting them as an
            # adapter-contract violation would turn a retryable or operational
            # recovery condition into a deterministic trust failure.
            raise
        except IntegrityTransitionError as exc:
            raise IntegrityFinalityBlockedError(
                exc.reason_code,
                f"modeled integrity recovery is blocked: {exc}",
            ) from exc
        except Exception as exc:
            raise IntegrityFinalityBlockedError(
                "modeled_integrity_adapter_contract_failure",
                "modeled integrity recovery encountered a malformed adapter result",
            ) from exc

    def recover_pending_transition(
        self,
    ) -> FinalizedIntegrityTransitionV1 | None:
        """Recover the one globally serialized pending transition, if present."""

        lineage = self._store.load_unresolved_integrity_transition()
        if lineage is None:
            return None
        if type(lineage) is not IntegrityLineageV1:
            _reject(
                "invalid_integrity_lineage",
                "store returned a malformed unresolved integrity lineage",
            )
        completed = self._advance_finality(lineage)
        if completed.finalization is None:
            raise IntegrityFinalityPendingError(
                "integrity_finality_pending",
                "modeled integrity recovery did not reach finality",
            )
        return completed.finalization

    def recover(self) -> FinalizedIntegrityTransitionV1 | None:
        """Alias used by composed commands before any replay shortcut."""

        return self.recover_pending_transition()

    def _append_and_finalize(
        self,
        event: EventV1,
        *,
        expected_head: str,
        evidence_store: FileEvidenceStore | None,
    ) -> EventV1:
        if type(event) is not EventV1:
            raise IntegrityFinalityBlockedError(
                "invalid_integrity_event",
                "modeled integrity append requires an exact EventV1",
            )
        _require_digest(expected_head, "expected_head")
        self.recover_pending_transition()
        retained = self._store.load_integrity_event(event.event_digest)
        if retained is not None:
            if retained != event or expected_head != event.prev_digest:
                raise IntegrityFinalityBlockedError(
                    "modeled_integrity_retry_conflict",
                    "retained event retry differs from the exact event or its original predecessor",
                )
            lineage = self._store.load_integrity_lineage(event.event_digest)
            if (
                lineage is None
                or lineage.pending.event_digest != event.event_digest
                or lineage.finalization is None
                or lineage.checkpoint_candidate is None
            ):
                raise IntegrityFinalityPendingError(
                    "integrity_finality_pending",
                    "exact retained event retry has no complete modeled finality lineage",
                )
            previous_global, previous_mission = self._retained_predecessors(lineage)
            _require_pending_authority_binding(
                lineage.pending,
                self.authority_binding,
            )
            _require_checkpoint_authority_binding(
                lineage.checkpoint_candidate,
                self.authority_binding,
            )
            validate_finalized_integrity_transition(
                lineage,
                event=retained,
                previous_global=previous_global,
                previous_mission=previous_mission,
            )
            return retained
        previous_global, previous_mission = self._latest_predecessors_for_new_event(event)
        # Modeled evidence production and signing are outside the locked append.
        try:
            pending = _call_modeled_integrity_adapter(
                "prepare_pending_transition",
                lambda: self._services.prepare_pending_transition(
                    event,
                    previous_global=previous_global,
                    previous_mission=previous_mission,
                ),
            )
            _require_pending_authority_binding(
                pending,
                self.authority_binding,
            )
            validate_pending_transition(
                event,
                pending,
                previous_global=previous_global,
                previous_mission=previous_mission,
                service_instance_id=self.service_instance_id,
                environment_id=self.environment_id,
                validation_policy=self.validation_policy,
            )
        except IntegrityFinalityPendingError:
            raise
        except IntegrityFinalityBlockedError:
            raise
        except IntegrityTransitionError as exc:
            raise IntegrityFinalityBlockedError(
                exc.reason_code,
                f"modeled integrity proposal is blocked: {exc}",
            ) from exc
        except Exception as exc:
            raise IntegrityFinalityBlockedError(
                "modeled_integrity_adapter_contract_failure",
                "modeled integrity proposal encountered a malformed adapter result",
            ) from exc
        retained_event = self._store.append_pending_integrity_event(
            event,
            expected_head=expected_head,
            pending=pending,
            evidence_store=evidence_store,
        )
        lineage = self._store.load_integrity_lineage(retained_event.event_digest)
        if lineage is None:
            _reject(
                "pending_integrity_lineage_missing",
                "committed event has no retained pending integrity lineage",
            )
        completed = self._advance_finality(lineage)
        if completed.finalization is None:
            raise IntegrityFinalityPendingError(
                "integrity_finality_pending",
                "local event committed without modeled current-head finality",
            )
        return retained_event

    def append(
        self,
        event: EventV1,
        *,
        expected_head: str,
    ) -> EventV1:
        return self._append_and_finalize(
            event,
            expected_head=expected_head,
            evidence_store=None,
        )

    def append_evidence_event(
        self,
        event: EventV1,
        *,
        expected_head: str,
        evidence_store: FileEvidenceStore,
    ) -> EventV1:
        if type(evidence_store) is not FileEvidenceStore:
            _reject(
                "invalid_evidence_store",
                "protected event append requires an exact FileEvidenceStore",
            )
        return self._append_and_finalize(
            event,
            expected_head=expected_head,
            evidence_store=evidence_store,
        )

    def append_receipt_admission(
        self,
        event: EventV1,
        *,
        expected_head: str,
        evidence_store: FileEvidenceStore,
    ) -> EventV1:
        if type(evidence_store) is not FileEvidenceStore:
            _reject(
                "invalid_evidence_store",
                "receipt append requires an exact FileEvidenceStore",
            )
        return self._append_and_finalize(
            event,
            expected_head=expected_head,
            evidence_store=evidence_store,
        )

    def require_finalized(
        self,
        event_digest: str,
    ) -> FinalizedIntegrityTransitionV1:
        """Return a revalidated exact finalization or fail closed."""

        _require_digest(event_digest, "event_digest")
        lineage = self._store.load_integrity_lineage(event_digest)
        if lineage is None or lineage.finalization is None:
            raise IntegrityFinalityPendingError(
                "integrity_finality_pending",
                "event lacks a retained modeled current-head finalization",
            )
        event = self._event_for_lineage(lineage)
        previous_global, previous_mission = self._retained_predecessors(lineage)
        _require_pending_authority_binding(
            lineage.pending,
            self.authority_binding,
        )
        if lineage.checkpoint_candidate is None:
            raise IntegrityFinalityPendingError(
                "integrity_finality_pending",
                "event lacks a retained modeled checkpoint candidate",
            )
        _require_checkpoint_authority_binding(
            lineage.checkpoint_candidate,
            self.authority_binding,
        )
        validate_finalized_integrity_transition(
            lineage,
            event=event,
            previous_global=previous_global,
            previous_mission=previous_mission,
        )
        return lineage.finalization
