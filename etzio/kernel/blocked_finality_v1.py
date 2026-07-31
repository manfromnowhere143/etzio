"""Networkless V1 contract for durable blocked finality and governed recovery.

ADR-0011 leaves a blocked finality attempt attempt-local: the typed error carries one
reason string, nothing is retained, and the next attempt re-enters at the same phase with
no memory of the block.  This module defines the exact closed record that makes a block
durable, the role-separated signed decision that is the only thing able to change its
disposition, and a deterministic qualification harness for both.

A block is an observation, not a resolution.  No admissible disposition finalizes a
transition, deletes or rewrites a retained phase, mints a checkpoint, or releases the
database-global barrier.  This module changes no SQLite schema, store method, or lifecycle
command, and it uses no network, credential, ambient clock, or third-party service.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, TypeVar

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from etzio.crypto_v1 import is_valid_ed25519_public_key
from etzio.integrity_v1 import (
    MAX_EPOCH_SECOND,
    EvidenceReferenceV1,
    IntegrityTrustStore,
    integrity_key_id,
)
from etzio.kernel.integrity_adapters_v1 import (
    QualifiedTimeBundleV1,
    RepositoryOwnedDeterministicAdapterFixtureV1,
    TrustedTimeRequestV1,
    create_repository_owned_adapter_fixture_v1,
    qualify_time_bundle_v1,
)
from etzio.kernel.integrity_transition import ModeledIntegrityAuthorityBindingV1
from etzio.protocol import (
    ProtocolError,
    canonical_dumps,
    content_id,
    strict_loads,
)

BLOCKED_FINALITY_CONTRACT_VERSION_V1: Final = 1
REPOSITORY_OWNED_BLOCKED_FINALITY_PROFILE_V1: Final = "repository_owned_networkless_blocked_finality_v1"

_RECOVERY_SIGNATURE_DOMAIN_V1: Final = b"etzio.blocked-finality.governed-recovery.signature.v1\x00"

BLOCKED_FINALITY_RECOVERY_ROLE_V1: Final = "integrity_recovery"

RETRY_AUTHORIZED_DISPOSITION_V1: Final = "retry_authorized"
INSTANCE_SEALED_DISPOSITION_V1: Final = "instance_sealed"
BLOCKED_FINALITY_DISPOSITIONS_V1: Final = frozenset(
    {
        RETRY_AUTHORIZED_DISPOSITION_V1,
        INSTANCE_SEALED_DISPOSITION_V1,
    }
)

LOCAL_PENDING_PHASE_V1: Final = "local_pending"
ANCHOR_STATEMENT_READY_PHASE_V1: Final = "anchor_statement_ready"
CHECKPOINT_CANDIDATE_RETAINED_PHASE_V1: Final = "checkpoint_candidate_retained"
FINALIZED_PHASE_V1: Final = "finalized"

# A finalized transition is resolved.  It is deliberately absent from the blockable set.
BLOCKABLE_PHASES_V1: Final = (
    LOCAL_PENDING_PHASE_V1,
    ANCHOR_STATEMENT_READY_PHASE_V1,
    CHECKPOINT_CANDIDATE_RETAINED_PHASE_V1,
)

BLOCKED_OPERATIONS_V1: Final = frozenset(
    {
        "observe_current_floor",
        "prepare_anchor_statement",
        "prepare_checkpoint_candidate",
        "propose_transition",
        "publish_checkpoint",
        "recover_lineage",
        "register_anchor_statement",
    }
)

# Exactly the deterministic reason codes the implemented recovery path produces.
BLOCKED_REASON_CODES_V1: Final = frozenset(
    {
        "invalid_integrity_event",
        "modeled_anchor_equivocation",
        "modeled_anchor_scope_mismatch",
        "modeled_anchor_sequence_conflict",
        "modeled_catalog_compare_and_set_failed",
        "modeled_catalog_global_conflict",
        "modeled_catalog_mission_conflict",
        "modeled_checkpoint_identity_conflict",
        "modeled_integrity_adapter_contract_failure",
        "modeled_integrity_retry_conflict",
    }
)

MAX_BLOCKED_ATTEMPT_ORDINAL_V1: Final = 1 << 20
MAX_BLOCKED_OBSERVATIONS_V1: Final = 256
MAX_BLOCKED_PACKAGE_BYTES_V1: Final = 1 << 20
MAX_BLOCKED_SEED_BYTES_V1: Final = 1024

_IDENTITY = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{1,127}$", re.ASCII)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
_KEY_ID = re.compile(r"^ed25519:sha256:[0-9a-f]{64}$", re.ASCII)
_NONCE_256 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)

_RECOVERY_PROFILE_FIELDS: Final = frozenset(
    {
        "authority_binding",
        "authority_binding_id",
        "contract_version",
        "environment_id",
        "profile",
        "recovery_key_id",
        "recovery_policy_id",
        "recovery_principal_id",
        "recovery_public_key_b64",
        "service_instance_id",
    }
)
_OBSERVATION_FIELDS: Final = frozenset(
    {
        "attempt_ordinal",
        "authority_id",
        "blocked_operation",
        "blocked_reason_code",
        "contract_version",
        "environment_id",
        "event_digest",
        "event_seq",
        "instance_sequence",
        "mission_id",
        "observation_id",
        "pending_record_id",
        "profile_id",
        "service_instance_id",
        "target_id",
        "time_bundle_id",
        "time_evidence",
        "time_lower_bound",
        "time_policy_id",
        "time_upper_bound",
        "trust_root_id",
        "unresolved_phase",
        "unresolved_phase_record_id",
    }
)
_DECISION_FIELDS: Final = frozenset(
    {
        "attempt_ordinal",
        "authority_id",
        "blocked_observation_id",
        "blocked_operation",
        "blocked_reason_code",
        "contract_version",
        "decision_id",
        "disposition",
        "environment_id",
        "event_digest",
        "mission_id",
        "pending_record_id",
        "profile_id",
        "recovery_policy_id",
        "recovery_principal_id",
        "request_nonce",
        "service_instance_id",
        "target_id",
        "time_bundle_id",
        "time_evidence",
        "time_lower_bound",
        "time_policy_id",
        "time_upper_bound",
        "trust_root_id",
        "unresolved_phase",
        "unresolved_phase_record_id",
    }
)
_SIGNED_DECISION_FIELDS: Final = frozenset(
    {
        "algorithm",
        "decision_b64",
        "key_id",
        "signature_b64",
    }
)
_VECTOR_FIELDS: Final = frozenset(
    {
        "authority_id",
        "environment_id",
        "event_digest",
        "event_seq",
        "expected_epoch_second",
        "instance_sequence",
        "mission_id",
        "pending_record_id",
        "request_nonce",
        "service_instance_id",
        "target_id",
    }
)

_AUTHENTICATED_DECISION_SEAL: Final = object()
_RESOLUTION_SEAL: Final = object()
_QUALIFICATION_REPORT_SEAL: Final = object()

_SealedResultT = TypeVar("_SealedResultT")


class BlockedFinalityError(ValueError):
    """One deterministic blocked-finality contract or qualification refusal."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


def _reject(reason_code: str, message: str) -> None:
    raise BlockedFinalityError(reason_code, message)


def _construct_sealed_result(
    cls: type[_SealedResultT],
    *,
    seal: object,
    values: Mapping[str, object],
) -> _SealedResultT:
    """Construct one private sealed result without exposing a public initializer."""

    fields = getattr(cls, "__dataclass_fields__", None)
    if type(fields) is not dict or set(values) != set(fields) - {"_seal"}:
        _reject(
            "internal_sealed_result_error",
            "sealed result factory received incomplete internal values",
        )
    instance = object.__new__(cls)
    for field, value in values.items():
        object.__setattr__(instance, field, value)
    object.__setattr__(instance, "_seal", seal)
    post_init = getattr(instance, "__post_init__", None)
    if not callable(post_init):
        _reject(
            "internal_sealed_result_error",
            "sealed result lacks its internal validator",
        )
    post_init()
    return instance


def _require_identity(value: object, field: str) -> str:
    if type(value) is not str or _IDENTITY.fullmatch(value) is None:
        _reject("invalid_blocked_identity", f"{field} must be one bounded ASCII identity")
    return value  # type: ignore[return-value]


def _require_digest(value: object, field: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        _reject("invalid_blocked_digest", f"{field} must be one sha256 content digest")
    return value  # type: ignore[return-value]


def _require_key_id(value: object, field: str) -> str:
    if type(value) is not str or _KEY_ID.fullmatch(value) is None:
        _reject("invalid_blocked_key_id", f"{field} must be one ed25519 key identity")
    return value  # type: ignore[return-value]


def _require_nonce(value: object, field: str = "request_nonce") -> str:
    if type(value) is not str or _NONCE_256.fullmatch(value) is None:
        _reject("invalid_blocked_nonce", f"{field} must be 256 lowercase hexadecimal bits")
    return value  # type: ignore[return-value]


def _require_nonnegative_int(value: object, field: str) -> int:
    if type(value) is not int or value < 0 or value > MAX_EPOCH_SECOND:
        _reject("invalid_blocked_integer", f"{field} must be a bounded nonnegative integer")
    return value  # type: ignore[return-value]


def _require_epoch(value: object, field: str) -> int:
    if type(value) is not int or value < 0 or value > MAX_EPOCH_SECOND:
        _reject("invalid_blocked_integer", f"{field} must be a bounded epoch second")
    return value  # type: ignore[return-value]


def _require_attempt_ordinal(value: object, field: str = "attempt_ordinal") -> int:
    if (
        type(value) is not int
        or value <= 0
        or value > MAX_BLOCKED_ATTEMPT_ORDINAL_V1
    ):
        _reject(
            "invalid_blocked_attempt_ordinal",
            f"{field} must be a bounded positive attempt ordinal",
        )
    return value  # type: ignore[return-value]


def _require_exact_dict(
    value: object,
    fields: frozenset[str],
    label: str,
) -> dict[str, object]:
    if type(value) is not dict or set(value) != fields:
        _reject(f"invalid_{label}", f"{label} has missing or unknown fields")
    return dict(value)  # type: ignore[arg-type]


def _canonical_record_bytes(body: object) -> bytes:
    try:
        return canonical_dumps(body)
    except (ProtocolError, TypeError, ValueError) as exc:
        raise BlockedFinalityError(
            "invalid_blocked_record",
            "blocked-finality record cannot be represented as canonical JSON",
        ) from exc


def _canonical_record_body(
    data: bytes | str,
    *,
    fields: frozenset[str],
    label: str,
) -> dict[str, object]:
    try:
        body = strict_loads(data)
    except (ProtocolError, TypeError, ValueError) as exc:
        raise BlockedFinalityError(
            f"invalid_{label}",
            f"{label} is not strict canonical JSON",
        ) from exc
    body = _require_exact_dict(body, fields, label)
    wire = data.encode("utf-8") if type(data) is str else data
    if type(wire) is not bytes or _canonical_record_bytes(body) != wire:
        _reject(f"invalid_{label}", f"{label} bytes are noncanonical")
    return body


def _decode_b64(value: object, field: str, *, maximum: int) -> bytes:
    if type(value) is not str:
        _reject("invalid_blocked_base64", f"{field} must be one Base64 string")
    try:
        decoded = base64.b64decode(value, validate=True)  # type: ignore[arg-type]
    except (binascii.Error, ValueError) as exc:
        raise BlockedFinalityError(
            "invalid_blocked_base64",
            f"{field} is not strict Base64",
        ) from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        _reject("invalid_blocked_base64", f"{field} is not canonical Base64")
    if not decoded or len(decoded) > maximum:
        _reject("invalid_blocked_base64", f"{field} must decode to bounded nonempty bytes")
    return decoded


def _fixture_content_id(label: str, value: object) -> str:
    return content_id(
        "blocked_finality_repository_fixture",
        {"label": label, "value": value},
    )


def _fixture_nonce(seed: bytes, label: str) -> str:
    return hashlib.sha256(
        b"etzio.blocked-finality.fixture-nonce.v1\x00" + label.encode("ascii") + b"\x00" + seed
    ).hexdigest()


def _validated_time_references(value: object, field: str) -> tuple[EvidenceReferenceV1, ...]:
    if type(value) is not tuple or len(value) < 2 or len(value) > MAX_BLOCKED_OBSERVATIONS_V1:
        _reject("invalid_blocked_evidence_references", f"{field} must be a bounded quorum")
    for reference in value:
        if type(reference) is not EvidenceReferenceV1:
            _reject(
                "invalid_blocked_evidence_references",
                f"{field} requires exact EvidenceReferenceV1 values",
            )
    ordered = tuple(sorted(value, key=lambda ref: (ref.source_id, ref.evidence_id)))
    if len({(ref.source_id, ref.evidence_id) for ref in ordered}) != len(ordered):
        _reject("invalid_blocked_evidence_references", f"{field} cannot repeat one reference")
    return ordered


def _require_blockable_phase(value: object, field: str = "unresolved_phase") -> str:
    if type(value) is not str or value not in BLOCKABLE_PHASES_V1:
        if value == FINALIZED_PHASE_V1:
            _reject(
                "blocked_phase_is_resolved",
                "a finalized transition is resolved and cannot be blocked",
            )
        _reject("invalid_blocked_phase", f"{field} is not one blockable lineage phase")
    return value  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Recovery profile and role separation
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TrustedRecoveryKeyV1:
    """One admitted recovery key bound to its exact principal and role."""

    principal_id: str
    role: str
    public_key_bytes: bytes

    def __post_init__(self) -> None:
        _require_identity(self.principal_id, "principal_id")
        if self.role != BLOCKED_FINALITY_RECOVERY_ROLE_V1:
            _reject(
                "invalid_recovery_role",
                "a recovery key requires the exact integrity_recovery role",
            )
        if type(self.public_key_bytes) is not bytes or not is_valid_ed25519_public_key(
            self.public_key_bytes
        ):
            _reject(
                "invalid_recovery_public_key",
                "a recovery key requires a valid prime-subgroup Ed25519 public key",
            )
        object.__setattr__(self, "public_key_bytes", bytes(self.public_key_bytes))

    @property
    def key_id(self) -> str:
        return integrity_key_id(self.public_key_bytes)


@dataclass(frozen=True, slots=True)
class BlockedFinalityRecoveryProfileV1:
    """One copied profile binding enrolled integrity authority plus separated recovery."""

    profile: str
    contract_version: int
    service_instance_id: str
    environment_id: str
    authority_binding: ModeledIntegrityAuthorityBindingV1
    authority_binding_id: str
    recovery_key: TrustedRecoveryKeyV1
    recovery_policy_id: str

    def __post_init__(self) -> None:
        if self.profile != REPOSITORY_OWNED_BLOCKED_FINALITY_PROFILE_V1:
            _reject(
                "invalid_recovery_profile",
                "blocked-finality profile label is not the exact V1 profile",
            )
        if self.contract_version != BLOCKED_FINALITY_CONTRACT_VERSION_V1:
            _reject(
                "invalid_blocked_profile_version",
                "blocked-finality profile requires the exact V1 contract version",
            )
        _require_identity(self.service_instance_id, "service_instance_id")
        _require_identity(self.environment_id, "environment_id")
        _require_digest(self.recovery_policy_id, "recovery_policy_id")
        if type(self.recovery_key) is not TrustedRecoveryKeyV1:
            _reject(
                "invalid_recovery_profile",
                "blocked-finality profile requires an exact TrustedRecoveryKeyV1",
            )

        binding = self.authority_binding
        if type(binding) is not ModeledIntegrityAuthorityBindingV1:
            _reject(
                "invalid_recovery_profile",
                "blocked-finality profile requires the exact enrolled authority binding",
            )
        copied = ModeledIntegrityAuthorityBindingV1.from_canonical_bytes(
            binding.to_canonical_bytes()
        )
        if copied.binding_id != _require_digest(
            self.authority_binding_id,
            "authority_binding_id",
        ):
            _reject(
                "recovery_authority_binding_mismatch",
                "authority binding identity does not match the copied binding",
            )

        # Separation of duty: a distinct key under one principal is rotation, not
        # separation.  Both the key and the principal must differ from the integrity
        # decision and head-checkpoint authorities.
        if self.recovery_key.key_id in {copied.decision_key_id, copied.checkpoint_key_id}:
            _reject(
                "recovery_role_not_separated",
                "the recovery key cannot be the decision or checkpoint key",
            )
        if self.recovery_key.principal_id in {
            copied.decision_principal_id,
            copied.checkpoint_principal_id,
        }:
            _reject(
                "recovery_role_not_separated",
                "the recovery principal cannot be the decision or checkpoint principal",
            )

        trust_store = copied.trust_store
        if type(trust_store) is not IntegrityTrustStore:
            _reject(
                "invalid_recovery_profile",
                "the enrolled authority binding requires an exact trust snapshot",
            )
        # The recovery authority is deliberately outside the enrolled integrity trust
        # store, whose roles are exactly the decision and checkpoint authorities.
        if self.recovery_key.key_id in trust_store.keys:
            _reject(
                "recovery_role_not_separated",
                "the recovery key cannot also be an enrolled integrity key",
            )
        object.__setattr__(self, "authority_binding", copied)

    @property
    def profile_id(self) -> str:
        return content_id("blocked_finality_recovery_profile", self.to_body())

    @property
    def recovery_key_id(self) -> str:
        return self.recovery_key.key_id

    @property
    def recovery_principal_id(self) -> str:
        return self.recovery_key.principal_id

    def to_body(self) -> dict[str, object]:
        return {
            "authority_binding": self.authority_binding.to_body(),
            "authority_binding_id": self.authority_binding_id,
            "contract_version": self.contract_version,
            "environment_id": self.environment_id,
            "profile": self.profile,
            "recovery_key_id": self.recovery_key.key_id,
            "recovery_policy_id": self.recovery_policy_id,
            "recovery_principal_id": self.recovery_key.principal_id,
            "recovery_public_key_b64": base64.b64encode(
                self.recovery_key.public_key_bytes
            ).decode("ascii"),
            "service_instance_id": self.service_instance_id,
        }

    def to_canonical_bytes(self) -> bytes:
        return _canonical_record_bytes(self.to_body())

    @classmethod
    def from_canonical_bytes(cls, data: bytes | str) -> BlockedFinalityRecoveryProfileV1:
        body = _canonical_record_body(
            data,
            fields=_RECOVERY_PROFILE_FIELDS,
            label="recovery_profile",
        )
        recovery_key = TrustedRecoveryKeyV1(
            principal_id=body["recovery_principal_id"],  # type: ignore[arg-type]
            role=BLOCKED_FINALITY_RECOVERY_ROLE_V1,
            public_key_bytes=_decode_b64(
                body["recovery_public_key_b64"],
                "recovery_public_key_b64",
                maximum=32,
            ),
        )
        if recovery_key.key_id != body["recovery_key_id"]:
            _reject(
                "invalid_recovery_profile",
                "recovery key identity does not match its exact public key",
            )
        return cls(
            profile=body["profile"],  # type: ignore[arg-type]
            contract_version=body["contract_version"],  # type: ignore[arg-type]
            service_instance_id=body["service_instance_id"],  # type: ignore[arg-type]
            environment_id=body["environment_id"],  # type: ignore[arg-type]
            authority_binding=ModeledIntegrityAuthorityBindingV1.from_canonical_bytes(
                _canonical_record_bytes(body["authority_binding"])
            ),
            authority_binding_id=body["authority_binding_id"],  # type: ignore[arg-type]
            recovery_key=recovery_key,
            recovery_policy_id=body["recovery_policy_id"],  # type: ignore[arg-type]
        )

    def recovery_public_key(self) -> bytes:
        """Return the exact admitted recovery public key bytes."""

        return self.recovery_key.public_key_bytes


def _snapshot_profile(value: object) -> BlockedFinalityRecoveryProfileV1:
    if type(value) is not BlockedFinalityRecoveryProfileV1:
        _reject(
            "invalid_recovery_profile",
            "an exact BlockedFinalityRecoveryProfileV1 is required",
        )
    return BlockedFinalityRecoveryProfileV1.from_canonical_bytes(
        value.to_canonical_bytes()  # type: ignore[union-attr]
    )


# ---------------------------------------------------------------------------
# Durable blocked observation
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BlockedFinalityObservationV1:
    """One durable record that a finality attempt was deterministically refused.

    Retaining this record advances nothing.  It names the exact transition, the exact
    highest retained immutable phase, the refused operation, the exact reason, and the
    attempt ordinal.  It carries no resolution field and no mutable status.
    """

    contract_version: int
    profile_id: str
    trust_root_id: str
    service_instance_id: str
    environment_id: str
    mission_id: str
    authority_id: str
    target_id: str
    event_digest: str
    event_seq: int
    instance_sequence: int
    pending_record_id: str
    unresolved_phase: str
    unresolved_phase_record_id: str
    blocked_operation: str
    blocked_reason_code: str
    attempt_ordinal: int
    time_bundle_id: str
    time_lower_bound: int
    time_upper_bound: int
    time_policy_id: str
    time_evidence: tuple[EvidenceReferenceV1, ...]
    observation_id: str

    def __post_init__(self) -> None:
        if self.contract_version != BLOCKED_FINALITY_CONTRACT_VERSION_V1:
            _reject(
                "invalid_blocked_profile_version",
                "blocked observation requires the exact V1 contract version",
            )
        for field in (
            "profile_id",
            "trust_root_id",
            "mission_id",
            "authority_id",
            "target_id",
            "event_digest",
            "pending_record_id",
            "unresolved_phase_record_id",
            "time_bundle_id",
            "time_policy_id",
        ):
            _require_digest(getattr(self, field), field)
        _require_identity(self.service_instance_id, "service_instance_id")
        _require_identity(self.environment_id, "environment_id")
        _require_nonnegative_int(self.event_seq, "event_seq")
        _require_nonnegative_int(self.instance_sequence, "instance_sequence")
        if self.event_seq > self.instance_sequence:
            _reject(
                "invalid_blocked_observation",
                "mission event sequence cannot exceed the instance-global sequence",
            )
        _require_blockable_phase(self.unresolved_phase)
        if (
            type(self.blocked_operation) is not str
            or self.blocked_operation not in BLOCKED_OPERATIONS_V1
        ):
            _reject(
                "invalid_blocked_operation",
                "blocked observation names an unsupported finality operation",
            )
        if (
            type(self.blocked_reason_code) is not str
            or self.blocked_reason_code not in BLOCKED_REASON_CODES_V1
        ):
            _reject(
                "invalid_blocked_reason_code",
                "blocked observation names an unsupported deterministic reason",
            )
        _require_attempt_ordinal(self.attempt_ordinal)
        _require_epoch(self.time_lower_bound, "time_lower_bound")
        _require_epoch(self.time_upper_bound, "time_upper_bound")
        if self.time_lower_bound > self.time_upper_bound:
            _reject("invalid_blocked_observation", "observation time hull is reversed")
        object.__setattr__(
            self,
            "time_evidence",
            _validated_time_references(self.time_evidence, "time_evidence"),
        )
        derived = content_id("blocked_finality_observation", self._semantics())
        if _require_digest(self.observation_id, "observation_id") != derived:
            _reject(
                "blocked_observation_id_mismatch",
                "blocked observation identity does not match its exact semantics",
            )

    @classmethod
    def record(
        cls,
        *,
        profile: BlockedFinalityRecoveryProfileV1,
        mission_id: str,
        authority_id: str,
        target_id: str,
        event_digest: str,
        event_seq: int,
        instance_sequence: int,
        pending_record_id: str,
        unresolved_phase: str,
        unresolved_phase_record_id: str,
        blocked_operation: str,
        blocked_reason_code: str,
        attempt_ordinal: int,
        time_bundle: QualifiedTimeBundleV1,
    ) -> BlockedFinalityObservationV1:
        """Derive one exact blocked observation from retained bindings and qualified time."""

        copied = _snapshot_profile(profile)
        if type(time_bundle) is not QualifiedTimeBundleV1:
            _reject(
                "invalid_blocked_time_bundle",
                "a blocked observation requires an exact sealed QualifiedTimeBundleV1",
            )
        values: dict[str, object] = {
            "attempt_ordinal": attempt_ordinal,
            "authority_id": authority_id,
            "blocked_operation": blocked_operation,
            "blocked_reason_code": blocked_reason_code,
            "contract_version": BLOCKED_FINALITY_CONTRACT_VERSION_V1,
            "environment_id": copied.environment_id,
            "event_digest": event_digest,
            "event_seq": event_seq,
            "instance_sequence": instance_sequence,
            "mission_id": mission_id,
            "pending_record_id": pending_record_id,
            "profile_id": copied.profile_id,
            "service_instance_id": copied.service_instance_id,
            "target_id": target_id,
            "time_bundle_id": time_bundle.bundle_id,
            "time_evidence": time_bundle.evidence,
            "time_lower_bound": time_bundle.time_lower_bound,
            "time_policy_id": time_bundle.time_policy_id,
            "time_upper_bound": time_bundle.time_upper_bound,
            "trust_root_id": copied.authority_binding.trust_snapshot_id,
            "unresolved_phase": unresolved_phase,
            "unresolved_phase_record_id": unresolved_phase_record_id,
        }
        semantics = dict(values)
        semantics["time_evidence"] = [
            reference.to_body() for reference in time_bundle.evidence
        ]
        values["observation_id"] = content_id("blocked_finality_observation", semantics)
        return cls(**values)  # type: ignore[arg-type]

    def _semantics(self) -> dict[str, object]:
        body = self.to_body()
        del body["observation_id"]
        return body

    @property
    def transition_key(self) -> tuple[str, str]:
        """Return the exact transition this observation describes."""

        return (self.service_instance_id, self.event_digest)

    def to_body(self) -> dict[str, object]:
        return {
            "attempt_ordinal": self.attempt_ordinal,
            "authority_id": self.authority_id,
            "blocked_operation": self.blocked_operation,
            "blocked_reason_code": self.blocked_reason_code,
            "contract_version": self.contract_version,
            "environment_id": self.environment_id,
            "event_digest": self.event_digest,
            "event_seq": self.event_seq,
            "instance_sequence": self.instance_sequence,
            "mission_id": self.mission_id,
            "observation_id": self.observation_id,
            "pending_record_id": self.pending_record_id,
            "profile_id": self.profile_id,
            "service_instance_id": self.service_instance_id,
            "target_id": self.target_id,
            "time_bundle_id": self.time_bundle_id,
            "time_evidence": [reference.to_body() for reference in self.time_evidence],
            "time_lower_bound": self.time_lower_bound,
            "time_policy_id": self.time_policy_id,
            "time_upper_bound": self.time_upper_bound,
            "trust_root_id": self.trust_root_id,
            "unresolved_phase": self.unresolved_phase,
            "unresolved_phase_record_id": self.unresolved_phase_record_id,
        }

    def to_canonical_bytes(self) -> bytes:
        return _canonical_record_bytes(self.to_body())

    @classmethod
    def from_canonical_bytes(cls, data: bytes | str) -> BlockedFinalityObservationV1:
        body = _canonical_record_body(
            data,
            fields=_OBSERVATION_FIELDS,
            label="blocked_observation",
        )
        evidence = body["time_evidence"]
        if type(evidence) is not list:
            _reject(
                "invalid_blocked_evidence_references",
                "blocked observation time evidence must be an ordered list",
            )
        body["time_evidence"] = tuple(
            EvidenceReferenceV1.from_body(reference) for reference in evidence
        )
        return cls(**body)  # type: ignore[arg-type]


def append_blocked_observation_v1(
    *,
    retained: tuple[BlockedFinalityObservationV1, ...],
    observation: BlockedFinalityObservationV1,
) -> tuple[BlockedFinalityObservationV1, ...]:
    """Append one observation to an append-only per-transition history or refuse.

    Ordinals strictly increase.  An exact duplicate reconciles; the same ordinal with a
    different body is equivocation.  Nothing here resolves the transition.
    """

    if type(observation) is not BlockedFinalityObservationV1:
        _reject(
            "invalid_blocked_observation",
            "an exact BlockedFinalityObservationV1 is required",
        )
    if type(retained) is not tuple:
        _reject(
            "invalid_blocked_observation",
            "retained blocked observations must be an ordered tuple",
        )
    for entry in retained:
        if type(entry) is not BlockedFinalityObservationV1:
            _reject(
                "invalid_blocked_observation",
                "retained blocked observations must be exact records",
            )
    if len(retained) >= MAX_BLOCKED_OBSERVATIONS_V1:
        _reject(
            "blocked_observation_limit_exceeded",
            "retained blocked observations exceed their bounded history",
        )
    if retained:
        first = retained[0]
        if observation.transition_key != first.transition_key:
            _reject(
                "blocked_transition_mismatch",
                "a blocked observation cannot join another transition's history",
            )
        ordinals = [entry.attempt_ordinal for entry in retained]
        if ordinals != sorted(ordinals) or len(set(ordinals)) != len(ordinals):
            _reject(
                "blocked_observation_equivocation",
                "retained blocked observations are not a strict ordinal sequence",
            )
        for entry in retained:
            if entry.attempt_ordinal == observation.attempt_ordinal:
                if entry.to_body() == observation.to_body():
                    return retained
                _reject(
                    "blocked_observation_equivocation",
                    "one attempt ordinal cannot carry two different observations",
                )
        if observation.attempt_ordinal <= ordinals[-1]:
            _reject(
                "blocked_observation_ordinal_regression",
                "a blocked observation ordinal cannot regress",
            )
    return (*retained, observation)


# ---------------------------------------------------------------------------
# Governed recovery decision
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class GovernedRecoveryDecisionV1:
    """One authorization that changes a blocked transition's disposition.

    The complete observation binding is restated so the signature covers the exact claim
    being authorized rather than an opaque identity.
    """

    contract_version: int
    profile_id: str
    trust_root_id: str
    service_instance_id: str
    environment_id: str
    mission_id: str
    authority_id: str
    target_id: str
    event_digest: str
    pending_record_id: str
    blocked_observation_id: str
    unresolved_phase: str
    unresolved_phase_record_id: str
    blocked_operation: str
    blocked_reason_code: str
    attempt_ordinal: int
    disposition: str
    recovery_policy_id: str
    recovery_principal_id: str
    request_nonce: str
    time_bundle_id: str
    time_lower_bound: int
    time_upper_bound: int
    time_policy_id: str
    time_evidence: tuple[EvidenceReferenceV1, ...]
    decision_id: str

    def __post_init__(self) -> None:
        if self.contract_version != BLOCKED_FINALITY_CONTRACT_VERSION_V1:
            _reject(
                "invalid_blocked_profile_version",
                "recovery decision requires the exact V1 contract version",
            )
        for field in (
            "profile_id",
            "trust_root_id",
            "mission_id",
            "authority_id",
            "target_id",
            "event_digest",
            "pending_record_id",
            "blocked_observation_id",
            "unresolved_phase_record_id",
            "recovery_policy_id",
            "time_bundle_id",
            "time_policy_id",
        ):
            _require_digest(getattr(self, field), field)
        _require_identity(self.service_instance_id, "service_instance_id")
        _require_identity(self.environment_id, "environment_id")
        _require_identity(self.recovery_principal_id, "recovery_principal_id")
        _require_blockable_phase(self.unresolved_phase)
        if (
            type(self.blocked_operation) is not str
            or self.blocked_operation not in BLOCKED_OPERATIONS_V1
        ):
            _reject(
                "invalid_blocked_operation",
                "recovery decision names an unsupported finality operation",
            )
        if (
            type(self.blocked_reason_code) is not str
            or self.blocked_reason_code not in BLOCKED_REASON_CODES_V1
        ):
            _reject(
                "invalid_blocked_reason_code",
                "recovery decision names an unsupported deterministic reason",
            )
        if (
            type(self.disposition) is not str
            or self.disposition not in BLOCKED_FINALITY_DISPOSITIONS_V1
        ):
            _reject(
                "invalid_recovery_disposition",
                "recovery decision names an unsupported disposition",
            )
        _require_attempt_ordinal(self.attempt_ordinal)
        _require_nonce(self.request_nonce)
        _require_epoch(self.time_lower_bound, "time_lower_bound")
        _require_epoch(self.time_upper_bound, "time_upper_bound")
        if self.time_lower_bound > self.time_upper_bound:
            _reject("invalid_recovery_decision", "recovery decision time hull is reversed")
        object.__setattr__(
            self,
            "time_evidence",
            _validated_time_references(self.time_evidence, "time_evidence"),
        )
        derived = content_id("blocked_finality_recovery_decision", self._semantics())
        if _require_digest(self.decision_id, "decision_id") != derived:
            _reject(
                "recovery_decision_id_mismatch",
                "recovery decision identity does not match its exact semantics",
            )

    @classmethod
    def issue(
        cls,
        *,
        profile: BlockedFinalityRecoveryProfileV1,
        observation: BlockedFinalityObservationV1,
        disposition: str,
        time_bundle: QualifiedTimeBundleV1,
        request_nonce: str,
    ) -> GovernedRecoveryDecisionV1:
        """Derive one exact decision restating the complete observation binding."""

        copied = _snapshot_profile(profile)
        if type(observation) is not BlockedFinalityObservationV1:
            _reject(
                "invalid_blocked_observation",
                "a recovery decision requires an exact blocked observation",
            )
        if observation.profile_id != copied.profile_id:
            _reject(
                "recovery_profile_mismatch",
                "the observation does not bind the retained recovery profile",
            )
        if type(time_bundle) is not QualifiedTimeBundleV1:
            _reject(
                "invalid_blocked_time_bundle",
                "a recovery decision requires an exact sealed QualifiedTimeBundleV1",
            )
        values: dict[str, object] = {
            "attempt_ordinal": observation.attempt_ordinal,
            "authority_id": observation.authority_id,
            "blocked_observation_id": observation.observation_id,
            "blocked_operation": observation.blocked_operation,
            "blocked_reason_code": observation.blocked_reason_code,
            "contract_version": BLOCKED_FINALITY_CONTRACT_VERSION_V1,
            "disposition": disposition,
            "environment_id": copied.environment_id,
            "event_digest": observation.event_digest,
            "mission_id": observation.mission_id,
            "pending_record_id": observation.pending_record_id,
            "profile_id": copied.profile_id,
            "recovery_policy_id": copied.recovery_policy_id,
            "recovery_principal_id": copied.recovery_principal_id,
            "request_nonce": request_nonce,
            "service_instance_id": copied.service_instance_id,
            "target_id": observation.target_id,
            "time_bundle_id": time_bundle.bundle_id,
            "time_evidence": time_bundle.evidence,
            "time_lower_bound": time_bundle.time_lower_bound,
            "time_policy_id": time_bundle.time_policy_id,
            "time_upper_bound": time_bundle.time_upper_bound,
            "trust_root_id": copied.authority_binding.trust_snapshot_id,
            "unresolved_phase": observation.unresolved_phase,
            "unresolved_phase_record_id": observation.unresolved_phase_record_id,
        }
        semantics = dict(values)
        semantics["time_evidence"] = [
            reference.to_body() for reference in time_bundle.evidence
        ]
        values["decision_id"] = content_id(
            "blocked_finality_recovery_decision",
            semantics,
        )
        return cls(**values)  # type: ignore[arg-type]

    def _semantics(self) -> dict[str, object]:
        body = self.to_body()
        del body["decision_id"]
        return body

    def to_body(self) -> dict[str, object]:
        return {
            "attempt_ordinal": self.attempt_ordinal,
            "authority_id": self.authority_id,
            "blocked_observation_id": self.blocked_observation_id,
            "blocked_operation": self.blocked_operation,
            "blocked_reason_code": self.blocked_reason_code,
            "contract_version": self.contract_version,
            "decision_id": self.decision_id,
            "disposition": self.disposition,
            "environment_id": self.environment_id,
            "event_digest": self.event_digest,
            "mission_id": self.mission_id,
            "pending_record_id": self.pending_record_id,
            "profile_id": self.profile_id,
            "recovery_policy_id": self.recovery_policy_id,
            "recovery_principal_id": self.recovery_principal_id,
            "request_nonce": self.request_nonce,
            "service_instance_id": self.service_instance_id,
            "target_id": self.target_id,
            "time_bundle_id": self.time_bundle_id,
            "time_evidence": [reference.to_body() for reference in self.time_evidence],
            "time_lower_bound": self.time_lower_bound,
            "time_policy_id": self.time_policy_id,
            "time_upper_bound": self.time_upper_bound,
            "trust_root_id": self.trust_root_id,
            "unresolved_phase": self.unresolved_phase,
            "unresolved_phase_record_id": self.unresolved_phase_record_id,
        }

    def to_canonical_bytes(self) -> bytes:
        return _canonical_record_bytes(self.to_body())

    @classmethod
    def from_canonical_bytes(cls, data: bytes | str) -> GovernedRecoveryDecisionV1:
        body = _canonical_record_body(
            data,
            fields=_DECISION_FIELDS,
            label="recovery_decision",
        )
        evidence = body["time_evidence"]
        if type(evidence) is not list:
            _reject(
                "invalid_blocked_evidence_references",
                "recovery decision time evidence must be an ordered list",
            )
        body["time_evidence"] = tuple(
            EvidenceReferenceV1.from_body(reference) for reference in evidence
        )
        return cls(**body)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class SignedGovernedRecoveryDecisionV1:
    """One bounded outer wrapper over exact signed recovery-decision bytes."""

    key_id: str
    decision_bytes: bytes
    signature_bytes: bytes
    algorithm: str = "ed25519"

    def __post_init__(self) -> None:
        _require_key_id(self.key_id, "key_id")
        if self.algorithm != "ed25519":
            _reject(
                "unsupported_recovery_algorithm",
                "a signed recovery decision must declare the exact ed25519 algorithm",
            )
        if (
            type(self.decision_bytes) is not bytes
            or not self.decision_bytes
            or len(self.decision_bytes) > MAX_BLOCKED_PACKAGE_BYTES_V1
        ):
            _reject(
                "invalid_signed_recovery_decision",
                "a signed recovery decision requires bounded nonempty decision bytes",
            )
        if type(self.signature_bytes) is not bytes or len(self.signature_bytes) != 64:
            _reject(
                "invalid_signed_recovery_decision",
                "a signed recovery decision requires a 64-byte Ed25519 signature",
            )
        object.__setattr__(self, "decision_bytes", bytes(self.decision_bytes))
        object.__setattr__(self, "signature_bytes", bytes(self.signature_bytes))

    def to_body(self) -> dict[str, object]:
        return {
            "algorithm": self.algorithm,
            "decision_b64": base64.b64encode(self.decision_bytes).decode("ascii"),
            "key_id": self.key_id,
            "signature_b64": base64.b64encode(self.signature_bytes).decode("ascii"),
        }

    def to_canonical_bytes(self) -> bytes:
        return _canonical_record_bytes(self.to_body())

    @classmethod
    def from_canonical_bytes(cls, data: bytes | str) -> SignedGovernedRecoveryDecisionV1:
        body = _canonical_record_body(
            data,
            fields=_SIGNED_DECISION_FIELDS,
            label="signed_recovery_decision",
        )
        return cls(
            key_id=body["key_id"],  # type: ignore[arg-type]
            decision_bytes=_decode_b64(
                body["decision_b64"],
                "decision_b64",
                maximum=MAX_BLOCKED_PACKAGE_BYTES_V1,
            ),
            signature_bytes=_decode_b64(body["signature_b64"], "signature_b64", maximum=64),
            algorithm=body["algorithm"],  # type: ignore[arg-type]
        )


@dataclass(frozen=True, slots=True)
class RecoveryDecisionSignerV1:
    """One deterministic repository-owned recovery signer."""

    principal_id: str
    private_key_bytes: bytes

    def __post_init__(self) -> None:
        _require_identity(self.principal_id, "principal_id")
        if type(self.private_key_bytes) is not bytes or len(self.private_key_bytes) != 32:
            _reject("invalid_recovery_signer", "a recovery signer requires 32 private bytes")
        object.__setattr__(self, "private_key_bytes", bytes(self.private_key_bytes))

    @classmethod
    def from_seed(cls, *, principal_id: str, seed: bytes) -> RecoveryDecisionSignerV1:
        if type(seed) is not bytes or not seed or len(seed) > MAX_BLOCKED_SEED_BYTES_V1:
            _reject(
                "invalid_blocked_seed",
                "blocked-finality fixture seed must be nonempty immutable bounded bytes",
            )
        private_bytes = hashlib.sha256(
            b"etzio.blocked-finality.fixture-key.v1\x00"
            + principal_id.encode("ascii")
            + b"\x00"
            + seed
        ).digest()
        return cls(principal_id=principal_id, private_key_bytes=private_bytes)

    @property
    def public_key_bytes(self) -> bytes:
        return (
            Ed25519PrivateKey.from_private_bytes(self.private_key_bytes)
            .public_key()
            .public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        )

    @property
    def key_id(self) -> str:
        return integrity_key_id(self.public_key_bytes)

    def sign(self, decision: GovernedRecoveryDecisionV1) -> SignedGovernedRecoveryDecisionV1:
        if type(decision) is not GovernedRecoveryDecisionV1:
            _reject(
                "invalid_recovery_decision",
                "a recovery signer requires an exact GovernedRecoveryDecisionV1",
            )
        if decision.recovery_principal_id != self.principal_id:
            _reject(
                "recovery_signer_binding_mismatch",
                "a recovery signer requires its exact principal decision",
            )
        decision_bytes = decision.to_canonical_bytes()
        signature = Ed25519PrivateKey.from_private_bytes(self.private_key_bytes).sign(
            _RECOVERY_SIGNATURE_DOMAIN_V1 + decision_bytes
        )
        return SignedGovernedRecoveryDecisionV1(
            key_id=self.key_id,
            decision_bytes=decision_bytes,
            signature_bytes=signature,
        )


# ---------------------------------------------------------------------------
# Authentication and resolution
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, init=False)
class AuthenticatedRecoveryDecisionV1:
    """Sealed decision whose exact retained bytes authenticated before interpretation."""

    profile_id: str
    signed_decision: SignedGovernedRecoveryDecisionV1
    decision: GovernedRecoveryDecisionV1
    recovery_key_id: str
    recovery_principal_id: str
    _seal: object

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        _reject(
            "unauthenticated_blocked_result_construction",
            "authenticated recovery decision construction is private",
        )

    def __post_init__(self) -> None:
        if (
            type(self) is not AuthenticatedRecoveryDecisionV1
            or self._seal is not _AUTHENTICATED_DECISION_SEAL
        ):
            _reject(
                "unauthenticated_blocked_result_construction",
                "authenticated recovery decision construction is private",
            )


def authenticate_recovery_decision_v1(
    *,
    profile: BlockedFinalityRecoveryProfileV1,
    signed_decision: SignedGovernedRecoveryDecisionV1,
) -> AuthenticatedRecoveryDecisionV1:
    """Authenticate one exact signed recovery decision before interpreting its claim."""

    copied = _snapshot_profile(profile)
    if type(signed_decision) is not SignedGovernedRecoveryDecisionV1:
        _reject(
            "invalid_signed_recovery_decision",
            "an exact SignedGovernedRecoveryDecisionV1 wrapper is required",
        )
    signed = SignedGovernedRecoveryDecisionV1.from_canonical_bytes(
        signed_decision.to_canonical_bytes()
    )
    if signed.key_id != copied.recovery_key_id:
        _reject(
            "recovery_key_mismatch",
            "the signed decision key is not the retained recovery key",
        )
    binding = copied.authority_binding
    if signed.key_id in {binding.decision_key_id, binding.checkpoint_key_id}:
        _reject(
            "recovery_role_not_separated",
            "an integrity decision or checkpoint key cannot authorize recovery",
        )

    try:
        Ed25519PublicKey.from_public_bytes(copied.recovery_public_key()).verify(
            signed.signature_bytes,
            _RECOVERY_SIGNATURE_DOMAIN_V1 + signed.decision_bytes,
        )
    except (InvalidSignature, ValueError) as exc:
        raise BlockedFinalityError(
            "recovery_signature_invalid",
            "recovery decision signature is invalid for the exact retained bytes",
        ) from exc

    decision = GovernedRecoveryDecisionV1.from_canonical_bytes(signed.decision_bytes)
    if decision.profile_id != copied.profile_id:
        _reject("recovery_profile_mismatch", "the decision binds another recovery profile")
    if decision.trust_root_id != binding.trust_snapshot_id:
        _reject("recovery_root_mismatch", "the decision binds another trust snapshot")
    if (
        decision.service_instance_id != copied.service_instance_id
        or decision.environment_id != copied.environment_id
    ):
        _reject("recovery_scope_mismatch", "the decision binds another service scope")
    if decision.recovery_policy_id != copied.recovery_policy_id:
        _reject("recovery_policy_mismatch", "the decision binds another recovery policy")
    if decision.recovery_principal_id != copied.recovery_principal_id:
        _reject(
            "recovery_principal_mismatch",
            "the decision binds another recovery principal",
        )
    if decision.recovery_principal_id in {
        binding.decision_principal_id,
        binding.checkpoint_principal_id,
    }:
        _reject(
            "recovery_role_not_separated",
            "an integrity decision or checkpoint principal cannot authorize recovery",
        )

    return _construct_sealed_result(
        AuthenticatedRecoveryDecisionV1,
        seal=_AUTHENTICATED_DECISION_SEAL,
        values={
            "profile_id": copied.profile_id,
            "signed_decision": signed,
            "decision": decision,
            "recovery_key_id": copied.recovery_key_id,
            "recovery_principal_id": copied.recovery_principal_id,
        },
    )


@dataclass(frozen=True, slots=True, init=False)
class BlockedFinalityResolutionV1:
    """Sealed outcome of applying one authenticated decision to one observation.

    ``barrier_released`` is retained as an explicit field so the central safety invariant
    is visible and testable rather than implicit in the absence of code.  No admissible
    disposition sets it.
    """

    profile_id: str
    event_digest: str
    observation: BlockedFinalityObservationV1
    authenticated_decision: AuthenticatedRecoveryDecisionV1
    disposition: str
    resume_phase: str | None
    barrier_released: bool
    instance_sealed: bool
    _seal: object

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        _reject(
            "unauthenticated_blocked_result_construction",
            "blocked-finality resolution construction is private",
        )

    def __post_init__(self) -> None:
        if (
            type(self) is not BlockedFinalityResolutionV1
            or self._seal is not _RESOLUTION_SEAL
        ):
            _reject(
                "unauthenticated_blocked_result_construction",
                "blocked-finality resolution construction is private",
            )
        if self.barrier_released is not False:
            _reject(
                "blocked_barrier_release_refused",
                "no admissible disposition releases the unresolved-transition barrier",
            )

    @property
    def resolution_id(self) -> str:
        return content_id("blocked_finality_resolution", self.to_body())

    def to_body(self) -> dict[str, object]:
        return {
            "barrier_released": self.barrier_released,
            "disposition": self.disposition,
            "event_digest": self.event_digest,
            "instance_sealed": self.instance_sealed,
            "observation_id": self.observation.observation_id,
            "profile_id": self.profile_id,
            "recovery_decision_id": self.authenticated_decision.decision.decision_id,
            "resume_phase": self.resume_phase,
        }


def resolve_blocked_finality_v1(
    *,
    profile: BlockedFinalityRecoveryProfileV1,
    retained: tuple[BlockedFinalityObservationV1, ...],
    current_phase: str,
    current_phase_record_id: str,
    signed_decision: SignedGovernedRecoveryDecisionV1,
    sealed: bool = False,
) -> BlockedFinalityResolutionV1:
    """Apply one authenticated recovery decision to the current blocked lineage.

    The decision must answer the exact latest retained observation and must name the
    lineage phase that is actually current.  A sealed instance admits nothing further.

    ``retained``, ``current_phase``, ``current_phase_record_id``, and ``sealed`` are
    caller-supplied in this tranche because nothing is persisted yet.  The storage tranche
    derives all four from retained rows rather than from caller input.
    """

    copied = _snapshot_profile(profile)
    if sealed is not False:
        _reject(
            "instance_already_sealed",
            "a sealed instance admits no further blocked observation or decision",
        )
    if type(retained) is not tuple or not retained:
        _reject(
            "invalid_blocked_observation",
            "resolution requires a nonempty retained observation history",
        )
    for entry in retained:
        if type(entry) is not BlockedFinalityObservationV1:
            _reject(
                "invalid_blocked_observation",
                "retained blocked observations must be exact records",
            )
    latest = retained[-1]
    ordinals = [entry.attempt_ordinal for entry in retained]
    if ordinals != sorted(ordinals) or len(set(ordinals)) != len(ordinals):
        _reject(
            "blocked_observation_equivocation",
            "retained blocked observations are not a strict ordinal sequence",
        )

    authenticated = authenticate_recovery_decision_v1(
        profile=copied,
        signed_decision=signed_decision,
    )
    decision = authenticated.decision

    if decision.blocked_observation_id != latest.observation_id:
        _reject(
            "recovery_observation_mismatch",
            "the decision does not answer the latest retained blocked observation",
        )
    # The restated binding must match the observation exactly, so a signature cannot be
    # moved onto a different phase, operation, reason, or attempt.
    if (
        decision.event_digest != latest.event_digest
        or decision.mission_id != latest.mission_id
        or decision.authority_id != latest.authority_id
        or decision.target_id != latest.target_id
        or decision.pending_record_id != latest.pending_record_id
        or decision.unresolved_phase != latest.unresolved_phase
        or decision.unresolved_phase_record_id != latest.unresolved_phase_record_id
        or decision.blocked_operation != latest.blocked_operation
        or decision.blocked_reason_code != latest.blocked_reason_code
        or decision.attempt_ordinal != latest.attempt_ordinal
    ):
        _reject(
            "recovery_observation_binding_mismatch",
            "the decision restates a binding the observation does not carry",
        )

    _require_blockable_phase(current_phase, "current_phase")
    _require_digest(current_phase_record_id, "current_phase_record_id")
    if (
        latest.unresolved_phase != current_phase
        or latest.unresolved_phase_record_id != current_phase_record_id
    ):
        _reject(
            "blocked_observation_stale",
            "the retained observation no longer describes the current lineage phase",
        )

    if decision.disposition == RETRY_AUTHORIZED_DISPOSITION_V1:
        resume_phase: str | None = current_phase
        instance_sealed = False
    else:
        resume_phase = None
        instance_sealed = True

    return _construct_sealed_result(
        BlockedFinalityResolutionV1,
        seal=_RESOLUTION_SEAL,
        values={
            "profile_id": copied.profile_id,
            "event_digest": latest.event_digest,
            "observation": latest,
            "authenticated_decision": authenticated,
            "disposition": decision.disposition,
            "resume_phase": resume_phase,
            "barrier_released": False,
            "instance_sealed": instance_sealed,
        },
    )


# ---------------------------------------------------------------------------
# Deterministic repository-owned harness
# ---------------------------------------------------------------------------


_BLOCKED_QUALIFICATION_CASE_IDS: Final = (
    "observation_retained_and_retry_stable",
    "finalized_phase_observation_refused",
    "ordinal_equivocation_refused",
    "retry_authorized_holds_the_barrier",
    "decision_for_another_observation_refused",
    "decision_signed_by_integrity_authority_refused",
    "instance_sealed_holds_the_barrier",
    "action_after_seal_refused",
)


@dataclass(frozen=True, slots=True)
class BlockedFinalityQualificationVectorV1:
    """One deterministic blocked-finality qualification scope."""

    service_instance_id: str
    environment_id: str
    mission_id: str
    authority_id: str
    target_id: str
    event_digest: str
    event_seq: int
    instance_sequence: int
    pending_record_id: str
    request_nonce: str
    expected_epoch_second: int

    def __post_init__(self) -> None:
        _require_identity(self.service_instance_id, "service_instance_id")
        _require_identity(self.environment_id, "environment_id")
        for field in (
            "mission_id",
            "authority_id",
            "target_id",
            "event_digest",
            "pending_record_id",
        ):
            _require_digest(getattr(self, field), field)
        _require_nonnegative_int(self.event_seq, "event_seq")
        _require_nonnegative_int(self.instance_sequence, "instance_sequence")
        _require_nonce(self.request_nonce)
        _require_epoch(self.expected_epoch_second, "expected_epoch_second")

    @property
    def vector_id(self) -> str:
        return content_id("blocked_finality_qualification_vector", self.to_body())

    def to_body(self) -> dict[str, object]:
        return {
            "authority_id": self.authority_id,
            "environment_id": self.environment_id,
            "event_digest": self.event_digest,
            "event_seq": self.event_seq,
            "expected_epoch_second": self.expected_epoch_second,
            "instance_sequence": self.instance_sequence,
            "mission_id": self.mission_id,
            "pending_record_id": self.pending_record_id,
            "request_nonce": self.request_nonce,
            "service_instance_id": self.service_instance_id,
            "target_id": self.target_id,
        }

    def to_canonical_bytes(self) -> bytes:
        return _canonical_record_bytes(self.to_body())

    @classmethod
    def from_canonical_bytes(cls, data: bytes | str) -> BlockedFinalityQualificationVectorV1:
        body = _canonical_record_body(
            data,
            fields=_VECTOR_FIELDS,
            label="blocked_qualification_vector",
        )
        return cls(**body)  # type: ignore[arg-type]


def _blocked_qualification_manifest_id(
    *,
    adapter_implementation_id: str,
    profile: BlockedFinalityRecoveryProfileV1,
    vector: BlockedFinalityQualificationVectorV1,
    blocked_phase: str,
    blocked_phase_record_id: str,
    blocked_operation: str,
    blocked_reason_code: str,
) -> str:
    return _fixture_content_id(
        "blocked-qualification-corpus",
        {
            "adapter_implementation_id": adapter_implementation_id,
            "blocked_operation": blocked_operation,
            "blocked_phase": blocked_phase,
            "blocked_phase_record_id": blocked_phase_record_id,
            "blocked_reason_code": blocked_reason_code,
            "case_ids": list(_BLOCKED_QUALIFICATION_CASE_IDS),
            "profile_id": profile.profile_id,
            "vector_id": vector.vector_id,
        },
    )


@dataclass(frozen=True, slots=True)
class RepositoryOwnedDeterministicBlockedFinalityFixtureV1:
    """One content-bound deterministic blocked-finality qualification corpus."""

    adapter_implementation_id: str
    corpus_manifest_id: str
    profile: BlockedFinalityRecoveryProfileV1
    vector: BlockedFinalityQualificationVectorV1
    time_fixture: RepositoryOwnedDeterministicAdapterFixtureV1
    recovery_signer: RecoveryDecisionSignerV1
    decision_authority_signer: RecoveryDecisionSignerV1
    blocked_phase: str
    blocked_phase_record_id: str
    blocked_operation: str
    blocked_reason_code: str

    def __post_init__(self) -> None:
        _require_digest(self.adapter_implementation_id, "adapter_implementation_id")
        if type(self.profile) is not BlockedFinalityRecoveryProfileV1:
            _reject("invalid_blocked_qualification_fixture", "fixture requires an exact profile")
        if type(self.vector) is not BlockedFinalityQualificationVectorV1:
            _reject("invalid_blocked_qualification_fixture", "fixture requires an exact vector")
        if type(self.time_fixture) is not RepositoryOwnedDeterministicAdapterFixtureV1:
            _reject(
                "invalid_blocked_qualification_fixture",
                "fixture requires the exact ADR-0012 time fixture",
            )
        for signer in (self.recovery_signer, self.decision_authority_signer):
            if type(signer) is not RecoveryDecisionSignerV1:
                _reject(
                    "invalid_blocked_qualification_fixture",
                    "fixture requires exact deterministic signers",
                )
        if self.recovery_signer.key_id != self.profile.recovery_key_id:
            _reject(
                "invalid_blocked_qualification_fixture",
                "the fixture recovery signer does not match the retained recovery key",
            )
        _require_blockable_phase(self.blocked_phase, "blocked_phase")
        _require_digest(self.blocked_phase_record_id, "blocked_phase_record_id")
        derived = _blocked_qualification_manifest_id(
            adapter_implementation_id=self.adapter_implementation_id,
            profile=self.profile,
            vector=self.vector,
            blocked_phase=self.blocked_phase,
            blocked_phase_record_id=self.blocked_phase_record_id,
            blocked_operation=self.blocked_operation,
            blocked_reason_code=self.blocked_reason_code,
        )
        if _require_digest(self.corpus_manifest_id, "corpus_manifest_id") != derived:
            _reject(
                "blocked_qualification_manifest_mismatch",
                "the corpus manifest does not match its exact deterministic inputs",
            )


@dataclass(frozen=True, slots=True)
class BlockedFinalityQualificationCaseV1:
    """One deterministic blocked-finality qualification case outcome."""

    case_id: str
    expected_disposition: str
    observed_disposition: str
    reason_code: str
    result_id: str

    def __post_init__(self) -> None:
        if self.case_id not in _BLOCKED_QUALIFICATION_CASE_IDS:
            _reject("invalid_blocked_qualification_case", "unknown qualification case identity")
        for field in ("expected_disposition", "observed_disposition"):
            if getattr(self, field) not in {"qualified", "refused"}:
                _reject(
                    "invalid_blocked_qualification_case",
                    f"{field} must be qualified or refused",
                )
        _require_identity(self.reason_code, "reason_code")
        _require_digest(self.result_id, "result_id")

    @property
    def passed(self) -> bool:
        return self.expected_disposition == self.observed_disposition

    def to_body(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "expected_disposition": self.expected_disposition,
            "observed_disposition": self.observed_disposition,
            "reason_code": self.reason_code,
            "result_id": self.result_id,
        }


@dataclass(frozen=True, slots=True, init=False)
class BlockedFinalityQualificationReportV1:
    """Sealed deterministic report over the exact ordered qualification roster."""

    contract_version: int
    adapter_implementation_id: str
    profile_id: str
    vector_id: str
    corpus_manifest_id: str
    cases: tuple[BlockedFinalityQualificationCaseV1, ...]
    overall_disposition: str
    _seal: object

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        _reject(
            "unauthenticated_blocked_result_construction",
            "blocked-finality qualification report construction is private",
        )

    def __post_init__(self) -> None:
        if (
            type(self) is not BlockedFinalityQualificationReportV1
            or self._seal is not _QUALIFICATION_REPORT_SEAL
        ):
            _reject(
                "unauthenticated_blocked_result_construction",
                "blocked-finality qualification report construction is private",
            )
        if tuple(case.case_id for case in self.cases) != _BLOCKED_QUALIFICATION_CASE_IDS:
            _reject(
                "blocked_qualification_case_coverage_mismatch",
                "the report does not cover the exact ordered case roster",
            )

    @property
    def passed(self) -> bool:
        return self.overall_disposition == "qualified" and all(
            case.passed for case in self.cases
        )

    @property
    def report_id(self) -> str:
        return content_id("blocked_finality_qualification_report", self.to_body())

    def to_body(self) -> dict[str, object]:
        return {
            "adapter_implementation_id": self.adapter_implementation_id,
            "cases": [case.to_body() for case in self.cases],
            "contract_version": self.contract_version,
            "corpus_manifest_id": self.corpus_manifest_id,
            "overall_disposition": self.overall_disposition,
            "profile_id": self.profile_id,
            "vector_id": self.vector_id,
        }


def create_repository_owned_blocked_finality_fixture_v1(
    *,
    seed: bytes,
) -> RepositoryOwnedDeterministicBlockedFinalityFixtureV1:
    """Build deterministic keys, enrolled authority, recovery profile, and vector."""

    if type(seed) is not bytes or not seed or len(seed) > MAX_BLOCKED_SEED_BYTES_V1:
        _reject(
            "invalid_blocked_seed",
            "blocked-finality fixture seed must be nonempty immutable bounded bytes",
        )
    from etzio.integrity_v1 import (
        HEAD_CHECKPOINT_ROLE,
        INTEGRITY_DECISION_ROLE,
        TrustedIntegrityKey,
    )
    from etzio.kernel.integrity_transition import (
        MODELED_INTEGRITY_ADAPTER_PROFILE_V1,
        MODELED_INTEGRITY_ADAPTER_VERSION_V1,
    )

    time_fixture = create_repository_owned_adapter_fixture_v1(seed=seed)
    time_vector = time_fixture.vector

    decision_signer = RecoveryDecisionSignerV1.from_seed(
        principal_id="fixture.integrity-decision.principal",
        seed=seed,
    )
    checkpoint_signer = RecoveryDecisionSignerV1.from_seed(
        principal_id="fixture.head-checkpoint.principal",
        seed=seed,
    )
    recovery_signer = RecoveryDecisionSignerV1.from_seed(
        principal_id="fixture.integrity-recovery.principal",
        seed=seed,
    )

    trust_store = IntegrityTrustStore(
        keys={
            decision_signer.key_id: TrustedIntegrityKey(
                principal_id=decision_signer.principal_id,
                public_key_bytes=decision_signer.public_key_bytes,
                role=INTEGRITY_DECISION_ROLE,
            ),
            checkpoint_signer.key_id: TrustedIntegrityKey(
                principal_id=checkpoint_signer.principal_id,
                public_key_bytes=checkpoint_signer.public_key_bytes,
                role=HEAD_CHECKPOINT_ROLE,
            ),
        }
    )
    authority_binding = ModeledIntegrityAuthorityBindingV1(
        adapter_profile=MODELED_INTEGRITY_ADAPTER_PROFILE_V1,
        adapter_version=MODELED_INTEGRITY_ADAPTER_VERSION_V1,
        trust_snapshot_id=trust_store.snapshot_id,
        trust_store=trust_store,
        decision_key_id=decision_signer.key_id,
        decision_principal_id=decision_signer.principal_id,
        checkpoint_key_id=checkpoint_signer.key_id,
        checkpoint_principal_id=checkpoint_signer.principal_id,
    )
    profile = BlockedFinalityRecoveryProfileV1(
        profile=REPOSITORY_OWNED_BLOCKED_FINALITY_PROFILE_V1,
        contract_version=BLOCKED_FINALITY_CONTRACT_VERSION_V1,
        service_instance_id="Etzio.blocked-finality-qualification-fixture",
        environment_id="fixture.networkless-control-plane",
        authority_binding=authority_binding,
        authority_binding_id=authority_binding.binding_id,
        recovery_key=TrustedRecoveryKeyV1(
            principal_id=recovery_signer.principal_id,
            role=BLOCKED_FINALITY_RECOVERY_ROLE_V1,
            public_key_bytes=recovery_signer.public_key_bytes,
        ),
        recovery_policy_id=_fixture_content_id("recovery-policy", "blocked-finality"),
    )
    vector = BlockedFinalityQualificationVectorV1(
        service_instance_id=profile.service_instance_id,
        environment_id=profile.environment_id,
        mission_id=time_vector.mission_id,
        authority_id=time_vector.authority_id,
        target_id=time_vector.target_id,
        event_digest=time_vector.event_digest,
        event_seq=3,
        instance_sequence=7,
        pending_record_id=_fixture_content_id("pending-record", "blocked-finality"),
        request_nonce=_fixture_nonce(seed, "blocked-qualification-vector"),
        expected_epoch_second=time_vector.expected_epoch_second,
    )
    blocked_phase = ANCHOR_STATEMENT_READY_PHASE_V1
    blocked_phase_record_id = _fixture_content_id("anchor-statement-record", "blocked-finality")
    blocked_operation = "prepare_checkpoint_candidate"
    blocked_reason_code = "modeled_catalog_compare_and_set_failed"
    adapter_implementation_id = _fixture_content_id(
        "adapter-implementation",
        {
            "contract_version": BLOCKED_FINALITY_CONTRACT_VERSION_V1,
            "profile": REPOSITORY_OWNED_BLOCKED_FINALITY_PROFILE_V1,
        },
    )
    return RepositoryOwnedDeterministicBlockedFinalityFixtureV1(
        adapter_implementation_id=adapter_implementation_id,
        corpus_manifest_id=_blocked_qualification_manifest_id(
            adapter_implementation_id=adapter_implementation_id,
            profile=profile,
            vector=vector,
            blocked_phase=blocked_phase,
            blocked_phase_record_id=blocked_phase_record_id,
            blocked_operation=blocked_operation,
            blocked_reason_code=blocked_reason_code,
        ),
        profile=profile,
        vector=vector,
        time_fixture=time_fixture,
        recovery_signer=recovery_signer,
        decision_authority_signer=decision_signer,
        blocked_phase=blocked_phase,
        blocked_phase_record_id=blocked_phase_record_id,
        blocked_operation=blocked_operation,
        blocked_reason_code=blocked_reason_code,
    )


def fixture_time_bundle_v1(
    fixture: RepositoryOwnedDeterministicBlockedFinalityFixtureV1,
) -> QualifiedTimeBundleV1:
    """Qualify the deterministic ADR-0012 time hull used by every fixture record."""

    time_fixture = fixture.time_fixture
    vector = time_fixture.vector
    requests = {
        adapter.source_id: TrustedTimeRequestV1.issue(
            profile=time_fixture.profile,
            source_id=adapter.source_id,
            purpose="decision",
            mission_id=vector.mission_id,
            authority_id=vector.authority_id,
            target_id=vector.target_id,
            event_digest=vector.event_digest,
            transition_intent_id=vector.transition_intent_id,
            imprint_id=_fixture_content_id("blocked-finality-imprint", "decision"),
            request_nonce=vector.request_nonce,
        )
        for adapter in time_fixture.time_adapters
    }
    return qualify_time_bundle_v1(
        profile=time_fixture.profile,
        requests=requests,
        signed_evidence={
            adapter.source_id: adapter.acquire(requests[adapter.source_id])
            for adapter in time_fixture.time_adapters
        },
    )


def fixture_observation_v1(
    fixture: RepositoryOwnedDeterministicBlockedFinalityFixtureV1,
    time_bundle: QualifiedTimeBundleV1,
    *,
    attempt_ordinal: int = 1,
    unresolved_phase: str | None = None,
    unresolved_phase_record_id: str | None = None,
) -> BlockedFinalityObservationV1:
    """Derive one deterministic blocked observation for the fixture transition."""

    vector = fixture.vector
    return BlockedFinalityObservationV1.record(
        profile=fixture.profile,
        mission_id=vector.mission_id,
        authority_id=vector.authority_id,
        target_id=vector.target_id,
        event_digest=vector.event_digest,
        event_seq=vector.event_seq,
        instance_sequence=vector.instance_sequence,
        pending_record_id=vector.pending_record_id,
        unresolved_phase=unresolved_phase or fixture.blocked_phase,
        unresolved_phase_record_id=(
            unresolved_phase_record_id or fixture.blocked_phase_record_id
        ),
        blocked_operation=fixture.blocked_operation,
        blocked_reason_code=fixture.blocked_reason_code,
        attempt_ordinal=attempt_ordinal,
        time_bundle=time_bundle,
    )


def _blocked_case_result_id(case_id: str, reason_code: str, detail: object) -> str:
    return _fixture_content_id(
        "blocked-case-result",
        {"case_id": case_id, "detail": detail, "reason_code": reason_code},
    )


def _qualified_case(case_id: str, detail: object) -> BlockedFinalityQualificationCaseV1:
    return BlockedFinalityQualificationCaseV1(
        case_id=case_id,
        expected_disposition="qualified",
        observed_disposition="qualified",
        reason_code="blocked_qualification_success",
        result_id=_blocked_case_result_id(case_id, "blocked_qualification_success", detail),
    )


def _refused_case(
    case_id: str,
    expected_reason: str,
    operation: object,
) -> BlockedFinalityQualificationCaseV1:
    try:
        operation()  # type: ignore[operator]
    except BlockedFinalityError as exc:
        if exc.reason_code != expected_reason:
            raise BlockedFinalityError(
                "blocked_qualification_case_failed",
                f"{case_id} refused with an unexpected reason code",
            ) from exc
        return BlockedFinalityQualificationCaseV1(
            case_id=case_id,
            expected_disposition="refused",
            observed_disposition="refused",
            reason_code=exc.reason_code,
            result_id=_blocked_case_result_id(case_id, exc.reason_code, None),
        )
    _reject("blocked_expected_refusal", f"{case_id} did not refuse")
    raise AssertionError("unreachable")


def qualify_repository_blocked_finality_v1(
    fixture: RepositoryOwnedDeterministicBlockedFinalityFixtureV1,
) -> BlockedFinalityQualificationReportV1:
    """Execute the fixed deterministic blocked-finality qualification roster."""

    if type(fixture) is not RepositoryOwnedDeterministicBlockedFinalityFixtureV1:
        _reject(
            "invalid_blocked_qualification_fixture",
            "qualification requires an exact deterministic blocked-finality fixture",
        )
    profile = fixture.profile
    vector = fixture.vector
    time_bundle = fixture_time_bundle_v1(fixture)
    cases: list[BlockedFinalityQualificationCaseV1] = []

    observation = fixture_observation_v1(fixture, time_bundle)
    retained = append_blocked_observation_v1(retained=(), observation=observation)
    repeated = append_blocked_observation_v1(
        retained=retained,
        observation=fixture_observation_v1(fixture, time_bundle),
    )
    if repeated != retained or len(repeated) != 1:
        _reject(
            "blocked_exact_retry_result",
            "an exact duplicate observation did not reconcile",
        )
    cases.append(
        _qualified_case("observation_retained_and_retry_stable", observation.observation_id)
    )

    cases.append(
        _refused_case(
            "finalized_phase_observation_refused",
            "blocked_phase_is_resolved",
            lambda: fixture_observation_v1(
                fixture,
                time_bundle,
                unresolved_phase=FINALIZED_PHASE_V1,
            ),
        )
    )

    cases.append(
        _refused_case(
            "ordinal_equivocation_refused",
            "blocked_observation_equivocation",
            lambda: append_blocked_observation_v1(
                retained=retained,
                observation=fixture_observation_v1(
                    fixture,
                    time_bundle,
                    unresolved_phase=LOCAL_PENDING_PHASE_V1,
                    unresolved_phase_record_id=_fixture_content_id(
                        "pending-phase-record",
                        "blocked-finality",
                    ),
                ),
            ),
        )
    )

    retry_decision = fixture.recovery_signer.sign(
        GovernedRecoveryDecisionV1.issue(
            profile=profile,
            observation=observation,
            disposition=RETRY_AUTHORIZED_DISPOSITION_V1,
            time_bundle=time_bundle,
            request_nonce=vector.request_nonce,
        )
    )
    retry_resolution = resolve_blocked_finality_v1(
        profile=profile,
        retained=retained,
        current_phase=fixture.blocked_phase,
        current_phase_record_id=fixture.blocked_phase_record_id,
        signed_decision=retry_decision,
    )
    if (
        retry_resolution.barrier_released is not False
        or retry_resolution.instance_sealed is not False
        or retry_resolution.resume_phase != fixture.blocked_phase
    ):
        _reject(
            "blocked_barrier_release_refused",
            "authorized retry must hold the barrier and resume the exact phase",
        )
    cases.append(
        _qualified_case(
            "retry_authorized_holds_the_barrier",
            retry_resolution.resolution_id,
        )
    )

    other_observation = fixture_observation_v1(fixture, time_bundle, attempt_ordinal=2)
    foreign_decision = fixture.recovery_signer.sign(
        GovernedRecoveryDecisionV1.issue(
            profile=profile,
            observation=other_observation,
            disposition=RETRY_AUTHORIZED_DISPOSITION_V1,
            time_bundle=time_bundle,
            request_nonce=vector.request_nonce,
        )
    )
    cases.append(
        _refused_case(
            "decision_for_another_observation_refused",
            "recovery_observation_mismatch",
            lambda: resolve_blocked_finality_v1(
                profile=profile,
                retained=retained,
                current_phase=fixture.blocked_phase,
                current_phase_record_id=fixture.blocked_phase_record_id,
                signed_decision=foreign_decision,
            ),
        )
    )

    cases.append(
        _refused_case(
            "decision_signed_by_integrity_authority_refused",
            "recovery_key_mismatch",
            lambda: authenticate_recovery_decision_v1(
                profile=profile,
                signed_decision=SignedGovernedRecoveryDecisionV1(
                    key_id=fixture.decision_authority_signer.key_id,
                    decision_bytes=retry_decision.decision_bytes,
                    signature_bytes=retry_decision.signature_bytes,
                ),
            ),
        )
    )

    seal_decision = fixture.recovery_signer.sign(
        GovernedRecoveryDecisionV1.issue(
            profile=profile,
            observation=observation,
            disposition=INSTANCE_SEALED_DISPOSITION_V1,
            time_bundle=time_bundle,
            request_nonce=vector.request_nonce,
        )
    )
    seal_resolution = resolve_blocked_finality_v1(
        profile=profile,
        retained=retained,
        current_phase=fixture.blocked_phase,
        current_phase_record_id=fixture.blocked_phase_record_id,
        signed_decision=seal_decision,
    )
    if (
        seal_resolution.barrier_released is not False
        or seal_resolution.instance_sealed is not True
        or seal_resolution.resume_phase is not None
    ):
        _reject(
            "blocked_barrier_release_refused",
            "sealing must hold the barrier and offer no resume phase",
        )
    cases.append(
        _qualified_case("instance_sealed_holds_the_barrier", seal_resolution.resolution_id)
    )

    cases.append(
        _refused_case(
            "action_after_seal_refused",
            "instance_already_sealed",
            lambda: resolve_blocked_finality_v1(
                profile=profile,
                retained=retained,
                current_phase=fixture.blocked_phase,
                current_phase_record_id=fixture.blocked_phase_record_id,
                signed_decision=retry_decision,
                sealed=True,
            ),
        )
    )

    ordered = tuple(cases)
    return _construct_sealed_result(
        BlockedFinalityQualificationReportV1,
        seal=_QUALIFICATION_REPORT_SEAL,
        values={
            "contract_version": BLOCKED_FINALITY_CONTRACT_VERSION_V1,
            "adapter_implementation_id": fixture.adapter_implementation_id,
            "profile_id": profile.profile_id,
            "vector_id": vector.vector_id,
            "corpus_manifest_id": fixture.corpus_manifest_id,
            "cases": ordered,
            "overall_disposition": (
                "qualified" if all(case.passed for case in ordered) else "refused"
            ),
        },
    )


__all__ = (
    "ANCHOR_STATEMENT_READY_PHASE_V1",
    "BLOCKABLE_PHASES_V1",
    "BLOCKED_FINALITY_CONTRACT_VERSION_V1",
    "BLOCKED_FINALITY_DISPOSITIONS_V1",
    "BLOCKED_FINALITY_RECOVERY_ROLE_V1",
    "BLOCKED_OPERATIONS_V1",
    "BLOCKED_REASON_CODES_V1",
    "CHECKPOINT_CANDIDATE_RETAINED_PHASE_V1",
    "FINALIZED_PHASE_V1",
    "INSTANCE_SEALED_DISPOSITION_V1",
    "LOCAL_PENDING_PHASE_V1",
    "REPOSITORY_OWNED_BLOCKED_FINALITY_PROFILE_V1",
    "RETRY_AUTHORIZED_DISPOSITION_V1",
    "AuthenticatedRecoveryDecisionV1",
    "BlockedFinalityError",
    "BlockedFinalityObservationV1",
    "BlockedFinalityQualificationCaseV1",
    "BlockedFinalityQualificationReportV1",
    "BlockedFinalityQualificationVectorV1",
    "BlockedFinalityRecoveryProfileV1",
    "BlockedFinalityResolutionV1",
    "GovernedRecoveryDecisionV1",
    "RecoveryDecisionSignerV1",
    "RepositoryOwnedDeterministicBlockedFinalityFixtureV1",
    "SignedGovernedRecoveryDecisionV1",
    "TrustedRecoveryKeyV1",
    "append_blocked_observation_v1",
    "authenticate_recovery_decision_v1",
    "create_repository_owned_blocked_finality_fixture_v1",
    "fixture_observation_v1",
    "fixture_time_bundle_v1",
    "qualify_repository_blocked_finality_v1",
    "resolve_blocked_finality_v1",
)
