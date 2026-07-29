"""Networkless V1 qualification contract for trusted-time and revocation adapters.

This module is deliberately separate from the modeled-finality facade.  It authenticates
repository-owned signed fixture packages under a pinned source roster, fuses conservative
time intervals, evaluates revocation freshness and rollback floors, and maps the exact
signed bytes to the provider-evidence types already understood by the integrity contract.

The qualification result is not lifecycle authority.  It does not establish truthful UTC,
current real-world revocation, independent administration, external durability,
non-equivocation, RFC 3161 conformance, TUF conformance, or a finding.  No adapter in this
module uses the network, credentials, an ambient clock, or a third-party service.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Protocol, TypeVar

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from etzio.crypto_v1 import is_valid_ed25519_public_key
from etzio.integrity_v1 import (
    EXTERNAL_FLOOR_EVIDENCE_KIND,
    MAX_EPOCH_SECOND,
    REVOCATION_METADATA_EVIDENCE_KIND,
    TRUSTED_TIME_EVIDENCE_KIND,
    EvidenceReferenceV1,
    IntegrityValidationPolicyV1,
    RevocationFloorV1,
    RevocationViewV1,
    integrity_key_id,
)
from etzio.kernel.integrity_transition import ProviderEvidenceBlobV1
from etzio.protocol import (
    ProtocolError,
    canonical_dumps,
    content_id,
    freeze_json,
    strict_loads,
    thaw_json,
)

INTEGRITY_ADAPTER_CONTRACT_VERSION_V1: Final = 1
REPOSITORY_OWNED_ADAPTER_PROFILE_V1: Final = "repository_owned_networkless_time_revocation_v1"

TRUSTED_TIME_ADAPTER_ROLE_V1: Final = "trusted_time"
REVOCATION_METADATA_ADAPTER_ROLE_V1: Final = "revocation_metadata"
REVOCATION_FLOOR_ADAPTER_ROLE_V1: Final = "revocation_floor"
INTEGRITY_ADAPTER_ROLES_V1: Final = frozenset(
    {
        TRUSTED_TIME_ADAPTER_ROLE_V1,
        REVOCATION_METADATA_ADAPTER_ROLE_V1,
        REVOCATION_FLOOR_ADAPTER_ROLE_V1,
    }
)

_ROLE_TO_EVIDENCE_KIND_V1: Final = MappingProxyType(
    {
        TRUSTED_TIME_ADAPTER_ROLE_V1: TRUSTED_TIME_EVIDENCE_KIND,
        REVOCATION_METADATA_ADAPTER_ROLE_V1: (REVOCATION_METADATA_EVIDENCE_KIND),
        REVOCATION_FLOOR_ADAPTER_ROLE_V1: EXTERNAL_FLOOR_EVIDENCE_KIND,
    }
)
_ROLE_TO_CODEC_V1: Final = MappingProxyType(
    {
        TRUSTED_TIME_ADAPTER_ROLE_V1: "etzio.fixture.signed-time.v1",
        REVOCATION_METADATA_ADAPTER_ROLE_V1: ("etzio.fixture.signed-revocation-metadata.v1"),
        REVOCATION_FLOOR_ADAPTER_ROLE_V1: ("etzio.fixture.signed-revocation-floor.v1"),
    }
)
_ROLE_SIGNATURE_DOMAINS_V1: Final = MappingProxyType(
    {
        TRUSTED_TIME_ADAPTER_ROLE_V1: (b"etzio.integrity-adapter.trusted-time.signature.v1\x00"),
        REVOCATION_METADATA_ADAPTER_ROLE_V1: (b"etzio.integrity-adapter.revocation-metadata.signature.v1\x00"),
        REVOCATION_FLOOR_ADAPTER_ROLE_V1: (b"etzio.integrity-adapter.revocation-floor.signature.v1\x00"),
    }
)

MAX_ADAPTER_KEYS_V1: Final = 64
MAX_ADAPTER_SOURCES_V1: Final = 32
MAX_ADAPTER_REVOCATIONS_V1: Final = 10_000
MAX_ADAPTER_PACKAGE_BYTES_V1: Final = 1 << 20
MAX_ADAPTER_TOTAL_EVIDENCE_BYTES_V1: Final = 16 << 20
MAX_ADAPTER_SEED_BYTES_V1: Final = 1024
_MAPPING_PROXY_TYPE: Final = type(MappingProxyType({}))

_IDENTITY = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{1,127}$", re.ASCII)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
_KEY_ID = re.compile(r"^ed25519:sha256:[0-9a-f]{64}$", re.ASCII)
_NONCE_256 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)

_TRUST_KEY_FIELDS: Final = frozenset(
    {
        "key_id",
        "principal_id",
        "public_key_b64",
        "role",
        "source_id",
    }
)
_TRUST_ROOT_FIELDS: Final = frozenset({"keys", "revoked_key_ids"})
_SOURCE_BINDING_FIELDS: Final = frozenset(
    {
        "codec_profile",
        "key_id",
        "namespace",
        "principal_id",
        "provider_policy_id",
        "role",
        "source_id",
    }
)
_TRUST_PROFILE_FIELDS: Final = frozenset(
    {
        "adapter_profile",
        "contract_version",
        "environment_id",
        "max_revocation_staleness_seconds",
        "service_instance_id",
        "source_bindings",
        "trust_root",
        "trust_root_id",
        "validation_policy",
        "validation_policy_id",
    }
)
_TIME_REQUEST_FIELDS: Final = frozenset(
    {
        "authority_id",
        "contract_version",
        "environment_id",
        "event_digest",
        "imprint_id",
        "mission_id",
        "profile_id",
        "purpose",
        "request_id",
        "request_nonce",
        "service_instance_id",
        "source_id",
        "target_id",
        "time_policy_id",
        "transition_intent_id",
        "trust_root_id",
    }
)
_REVOCATION_REQUEST_FIELDS: Final = frozenset(
    {
        "authority_id",
        "contract_version",
        "decision_policy_id",
        "environment_id",
        "event_digest",
        "evidence_role",
        "mission_id",
        "namespace",
        "prior_root_version",
        "prior_snapshot_id",
        "prior_version",
        "profile_id",
        "request_id",
        "request_nonce",
        "service_instance_id",
        "source_id",
        "target_id",
        "time_evidence",
        "time_lower_bound",
        "time_upper_bound",
        "time_bundle_id",
        "transition_intent_id",
        "trust_root_id",
    }
)
_STATEMENT_FIELDS: Final = frozenset(
    {
        "claim",
        "contract_version",
        "environment_id",
        "evidence_role",
        "profile_id",
        "provider_policy_id",
        "request_id",
        "service_instance_id",
        "source_id",
        "trust_root_id",
    }
)
_SIGNED_EVIDENCE_FIELDS: Final = frozenset(
    {
        "algorithm",
        "evidence_role",
        "key_id",
        "signature_b64",
        "statement_b64",
    }
)
_TIME_CLAIM_FIELDS: Final = frozenset(
    {
        "accuracy_authenticated",
        "authority_id",
        "event_digest",
        "imprint_id",
        "mission_id",
        "purpose",
        "target_id",
        "time_lower_bound",
        "time_policy_id",
        "time_upper_bound",
        "transition_intent_id",
    }
)
_REVOCATION_CLAIM_FIELDS: Final = frozenset(
    {
        "authority_id",
        "decision_policy_id",
        "event_digest",
        "mission_id",
        "namespace",
        "published_at",
        "root_version",
        "snapshot_id",
        "target_id",
        "time_bundle_id",
        "transition_intent_id",
        "valid_from",
        "valid_until",
        "version",
    }
)
_EXPECTED_REVOCATION_FIELDS: Final = frozenset(
    {
        "expected_root_version",
        "expected_published_at",
        "expected_snapshot_id",
        "expected_valid_from",
        "expected_valid_until",
        "expected_version",
        "namespace",
        "prior_root_version",
        "prior_snapshot_id",
        "prior_version",
    }
)
_QUALIFICATION_VECTOR_FIELDS: Final = frozenset(
    {
        "authority_id",
        "environment_id",
        "event_digest",
        "expected_epoch_second",
        "expected_revocation",
        "mission_id",
        "request_nonce",
        "service_instance_id",
        "target_id",
        "transition_intent_id",
    }
)

_AUTHENTICATED_PACKAGE_SEAL: Final = object()
_QUALIFIED_TIME_SEAL: Final = object()
_QUALIFIED_REVOCATION_SEAL: Final = object()
_QUALIFIED_INPUTS_SEAL: Final = object()
_QUALIFICATION_REPORT_SEAL: Final = object()

_SealedResultT = TypeVar("_SealedResultT")


class IntegrityAdapterError(ValueError):
    """One deterministic adapter-contract or qualification refusal."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


def _reject(reason_code: str, message: str) -> None:
    raise IntegrityAdapterError(reason_code, message)


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
        _reject("invalid_adapter_identity", f"{field} must be a bounded ASCII identity")
    return value


def _require_digest(value: object, field: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        _reject("invalid_adapter_digest", f"{field} must be a full SHA-256 content identity")
    return value


def _require_key_id(value: object, field: str) -> str:
    if type(value) is not str or _KEY_ID.fullmatch(value) is None:
        _reject("invalid_adapter_key_id", f"{field} must be a canonical Ed25519 key identity")
    return value


def _require_nonce(value: object, field: str = "request_nonce") -> str:
    if type(value) is not str or _NONCE_256.fullmatch(value) is None:
        _reject("invalid_adapter_nonce", f"{field} must contain 256 lowercase hexadecimal bits")
    return value


def _require_nonnegative_int(value: object, field: str) -> int:
    if type(value) is not int or value < 0 or value > MAX_EPOCH_SECOND:
        _reject("invalid_adapter_integer", f"{field} must be a nonnegative signed-int64 integer")
    return value


def _require_positive_int(value: object, field: str) -> int:
    value = _require_nonnegative_int(value, field)
    if value == 0:
        _reject("invalid_adapter_integer", f"{field} must be positive")
    return value


def _require_epoch(value: object, field: str) -> int:
    return _require_nonnegative_int(value, field)


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


def _canonical_record_bytes(body: object) -> bytes:
    try:
        return canonical_dumps(body)
    except (ProtocolError, TypeError, ValueError) as exc:
        raise IntegrityAdapterError(
            "invalid_adapter_record",
            "adapter record cannot be represented as canonical JSON",
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
        raise IntegrityAdapterError(
            f"invalid_{label}",
            f"{label} is not strict canonical JSON",
        ) from exc
    body = _require_exact_dict(body, fields, label)
    wire = data.encode("utf-8") if type(data) is str else data
    if type(wire) is not bytes or _canonical_record_bytes(body) != wire:
        _reject(f"invalid_{label}", f"{label} bytes are noncanonical")
    return body


def _decode_b64(
    value: object,
    field: str,
    *,
    maximum: int,
) -> bytes:
    if type(value) is not str or not value or len(value) > ((maximum + 2) // 3) * 4:
        _reject("invalid_adapter_base64", f"{field} is not bounded canonical Base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise IntegrityAdapterError(
            "invalid_adapter_base64",
            f"{field} is not canonical Base64",
        ) from exc
    if not decoded or len(decoded) > maximum or base64.b64encode(decoded).decode("ascii") != value:
        _reject("invalid_adapter_base64", f"{field} is not bounded canonical Base64")
    return decoded


def _copy_json_object(value: object, label: str) -> MappingProxyType:
    try:
        frozen = freeze_json(value)
        thawed = thaw_json(frozen)
    except (ProtocolError, TypeError, ValueError) as exc:
        raise IntegrityAdapterError(
            f"invalid_{label}",
            f"{label} must be an exact protocol JSON object",
        ) from exc
    if type(thawed) is not dict:
        _reject(f"invalid_{label}", f"{label} must be an exact JSON object")
    return freeze_json(thawed)  # type: ignore[return-value]


def _validation_policy_id(policy: IntegrityValidationPolicyV1) -> str:
    if type(policy) is not IntegrityValidationPolicyV1:
        _reject(
            "invalid_adapter_validation_policy",
            "adapter profile requires an exact IntegrityValidationPolicyV1",
        )
    return content_id("integrity_validation_policy", policy.to_body())


def _snapshot_validation_policy(
    policy: object,
) -> IntegrityValidationPolicyV1:
    if type(policy) is not IntegrityValidationPolicyV1:
        _reject(
            "invalid_adapter_validation_policy",
            "adapter profile requires an exact IntegrityValidationPolicyV1",
        )
    try:
        return IntegrityValidationPolicyV1.from_body(policy.to_body())
    except (AttributeError, TypeError, ValueError) as exc:
        raise IntegrityAdapterError(
            "invalid_adapter_validation_policy",
            "adapter validation policy cannot be reconstructed",
        ) from exc


@dataclass(frozen=True, slots=True)
class TrustedAdapterKeyV1:
    """One source-specific fixture evidence key and logical principal."""

    source_id: str
    principal_id: str
    role: str
    public_key_bytes: bytes

    def __post_init__(self) -> None:
        _require_identity(self.source_id, "source_id")
        _require_identity(self.principal_id, "principal_id")
        if type(self.role) is not str or self.role not in INTEGRITY_ADAPTER_ROLES_V1:
            _reject("invalid_adapter_role", "trusted adapter key has an unsupported role")
        if type(self.public_key_bytes) is not bytes or not is_valid_ed25519_public_key(self.public_key_bytes):
            _reject(
                "invalid_adapter_public_key",
                "adapter key must be a canonical prime-subgroup Ed25519 key",
            )
        try:
            Ed25519PublicKey.from_public_bytes(self.public_key_bytes)
        except ValueError as exc:
            raise IntegrityAdapterError(
                "invalid_adapter_public_key",
                "adapter key is not a valid Ed25519 public key",
            ) from exc
        object.__setattr__(self, "public_key_bytes", bytes(self.public_key_bytes))

    @property
    def key_id(self) -> str:
        try:
            return integrity_key_id(self.public_key_bytes)
        except ValueError as exc:
            raise IntegrityAdapterError(
                "invalid_adapter_public_key",
                "adapter key identity cannot be derived",
            ) from exc

    def to_body(self) -> dict[str, object]:
        return {
            "key_id": self.key_id,
            "principal_id": self.principal_id,
            "public_key_b64": base64.b64encode(self.public_key_bytes).decode("ascii"),
            "role": self.role,
            "source_id": self.source_id,
        }

    @classmethod
    def from_body(cls, value: object) -> TrustedAdapterKeyV1:
        body = _require_exact_dict(value, _TRUST_KEY_FIELDS, "trusted_adapter_key")
        key = cls(
            source_id=body["source_id"],  # type: ignore[arg-type]
            principal_id=body["principal_id"],  # type: ignore[arg-type]
            role=body["role"],  # type: ignore[arg-type]
            public_key_bytes=_decode_b64(
                body["public_key_b64"],
                "public_key_b64",
                maximum=32,
            ),
        )
        if key.key_id != body["key_id"]:
            _reject(
                "invalid_adapter_key_id",
                "adapter key ID differs from its exact public key",
            )
        return key


@dataclass(frozen=True, slots=True)
class IntegrityAdapterTrustStoreV1:
    """Immutable bootstrap trust for signed adapter fixture packages."""

    keys: Mapping[str, TrustedAdapterKeyV1]
    revoked_key_ids: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not isinstance(self.keys, Mapping):
            _reject("invalid_adapter_trust_root", "adapter keys must be a mapping")
        copied: dict[str, TrustedAdapterKeyV1] = {}
        try:
            for index, (key_id, key) in enumerate(self.keys.items()):
                if index >= MAX_ADAPTER_KEYS_V1:
                    _reject(
                        "invalid_adapter_trust_root",
                        "adapter trust root exceeds the fixed key ceiling",
                    )
                if (
                    type(key_id) is not str
                    or _KEY_ID.fullmatch(key_id) is None
                    or type(key) is not TrustedAdapterKeyV1
                    or key_id in copied
                ):
                    _reject(
                        "invalid_adapter_trust_root",
                        "adapter trust-root entry is malformed",
                    )
                snapshot = TrustedAdapterKeyV1.from_body(key.to_body())
                if snapshot.key_id != key_id:
                    _reject(
                        "invalid_adapter_trust_root",
                        "adapter trust-root key identity is inconsistent",
                    )
                copied[key_id] = snapshot
        except IntegrityAdapterError:
            raise
        except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
            raise IntegrityAdapterError(
                "invalid_adapter_trust_root",
                "adapter trust-root entries are malformed",
            ) from exc
        if (
            type(self.revoked_key_ids) is not frozenset
            or len(self.revoked_key_ids) > MAX_ADAPTER_REVOCATIONS_V1
            or any(type(value) is not str or _KEY_ID.fullmatch(value) is None for value in self.revoked_key_ids)
        ):
            _reject(
                "invalid_adapter_trust_root",
                "adapter revoked-key set is malformed or unbounded",
            )
        object.__setattr__(self, "keys", MappingProxyType(dict(sorted(copied.items()))))
        object.__setattr__(
            self,
            "revoked_key_ids",
            frozenset(self.revoked_key_ids),
        )

    @classmethod
    def from_keys(
        cls,
        keys: Iterable[TrustedAdapterKeyV1],
        *,
        revoked_key_ids: Iterable[str] = (),
    ) -> IntegrityAdapterTrustStoreV1:
        if isinstance(keys, (str, bytes)):
            _reject("invalid_adapter_trust_root", "adapter keys must be iterable")
        copied: dict[str, TrustedAdapterKeyV1] = {}
        try:
            for key in keys:
                if type(key) is not TrustedAdapterKeyV1 or key.key_id in copied:
                    _reject(
                        "invalid_adapter_trust_root",
                        "adapter keys contain an invalid or duplicate entry",
                    )
                if len(copied) >= MAX_ADAPTER_KEYS_V1:
                    _reject(
                        "invalid_adapter_trust_root",
                        "adapter keys exceed the fixed key ceiling",
                    )
                copied[key.key_id] = key
            revoked = frozenset(revoked_key_ids)
        except TypeError as exc:
            raise IntegrityAdapterError(
                "invalid_adapter_trust_root",
                "adapter keys and revocations must be iterable",
            ) from exc
        return cls(copied, revoked)

    @property
    def root_id(self) -> str:
        return content_id("integrity_adapter_trust_root", self.to_body())

    def to_body(self) -> dict[str, object]:
        return {
            "keys": [key.to_body() for key in self.keys.values()],
            "revoked_key_ids": sorted(self.revoked_key_ids),
        }

    @classmethod
    def from_body(cls, value: object) -> IntegrityAdapterTrustStoreV1:
        body = _require_exact_dict(value, _TRUST_ROOT_FIELDS, "adapter_trust_root")
        keys = body["keys"]
        revoked = body["revoked_key_ids"]
        if (
            type(keys) is not list
            or not keys
            or len(keys) > MAX_ADAPTER_KEYS_V1
            or type(revoked) is not list
            or revoked != sorted(set(revoked))
        ):
            _reject(
                "invalid_adapter_trust_root",
                "adapter trust root is not canonical and bounded",
            )
        store = cls.from_keys(
            (TrustedAdapterKeyV1.from_body(item) for item in keys),
            revoked_key_ids=revoked,  # type: ignore[arg-type]
        )
        if store.to_body() != body:
            _reject("invalid_adapter_trust_root", "adapter trust-root body is noncanonical")
        return store


def _snapshot_trust_store(value: object) -> IntegrityAdapterTrustStoreV1:
    if type(value) is not IntegrityAdapterTrustStoreV1:
        _reject(
            "invalid_adapter_trust_root",
            "exact IntegrityAdapterTrustStoreV1 required",
        )
    return IntegrityAdapterTrustStoreV1.from_body(value.to_body())


@dataclass(frozen=True, slots=True)
class AdapterSourceBindingV1:
    """One fixed source-to-key, parser profile, policy, role, and namespace binding."""

    source_id: str
    role: str
    namespace: str | None
    key_id: str
    principal_id: str
    provider_policy_id: str
    codec_profile: str

    def __post_init__(self) -> None:
        _require_identity(self.source_id, "source_id")
        _require_identity(self.principal_id, "principal_id")
        _require_key_id(self.key_id, "key_id")
        _require_digest(self.provider_policy_id, "provider_policy_id")
        if type(self.role) is not str or self.role not in INTEGRITY_ADAPTER_ROLES_V1:
            _reject("invalid_adapter_role", "source binding has an unsupported role")
        if type(self.codec_profile) is not str or self.codec_profile != _ROLE_TO_CODEC_V1[self.role]:
            _reject(
                "invalid_adapter_codec_profile",
                "source binding has the wrong exact codec profile for its role",
            )
        if self.role == TRUSTED_TIME_ADAPTER_ROLE_V1:
            if self.namespace is not None:
                _reject(
                    "invalid_adapter_namespace",
                    "trusted-time source cannot claim a revocation namespace",
                )
        else:
            _require_identity(self.namespace, "namespace")

    def to_body(self) -> dict[str, object]:
        return {
            "codec_profile": self.codec_profile,
            "key_id": self.key_id,
            "namespace": self.namespace,
            "principal_id": self.principal_id,
            "provider_policy_id": self.provider_policy_id,
            "role": self.role,
            "source_id": self.source_id,
        }

    @classmethod
    def from_body(cls, value: object) -> AdapterSourceBindingV1:
        body = _require_exact_dict(
            value,
            _SOURCE_BINDING_FIELDS,
            "adapter_source_binding",
        )
        return cls(
            source_id=body["source_id"],  # type: ignore[arg-type]
            role=body["role"],  # type: ignore[arg-type]
            namespace=body["namespace"],  # type: ignore[arg-type]
            key_id=body["key_id"],  # type: ignore[arg-type]
            principal_id=body["principal_id"],  # type: ignore[arg-type]
            provider_policy_id=body["provider_policy_id"],  # type: ignore[arg-type]
            codec_profile=body["codec_profile"],  # type: ignore[arg-type]
        )


@dataclass(frozen=True, slots=True)
class IntegrityAdapterTrustProfileV1:
    """Complete immutable qualification authority and fixed required source roster."""

    adapter_profile: str
    contract_version: int
    service_instance_id: str
    environment_id: str
    validation_policy: IntegrityValidationPolicyV1
    validation_policy_id: str
    trust_store: IntegrityAdapterTrustStoreV1
    trust_root_id: str
    source_bindings: tuple[AdapterSourceBindingV1, ...]
    max_revocation_staleness_seconds: int

    def __post_init__(self) -> None:
        if (
            self.adapter_profile != REPOSITORY_OWNED_ADAPTER_PROFILE_V1
            or type(self.contract_version) is not int
            or self.contract_version != INTEGRITY_ADAPTER_CONTRACT_VERSION_V1
        ):
            _reject(
                "invalid_adapter_profile_version",
                "adapter profile requires the exact repository V1 contract",
            )
        _require_identity(self.service_instance_id, "service_instance_id")
        _require_identity(self.environment_id, "environment_id")
        policy = _snapshot_validation_policy(self.validation_policy)
        if _validation_policy_id(policy) != _require_digest(
            self.validation_policy_id,
            "validation_policy_id",
        ):
            _reject(
                "adapter_policy_binding_mismatch",
                "adapter validation-policy ID differs from its exact body",
            )
        trust_store = _snapshot_trust_store(self.trust_store)
        if trust_store.root_id != _require_digest(self.trust_root_id, "trust_root_id"):
            _reject(
                "adapter_trust_root_binding_mismatch",
                "adapter trust-root ID differs from its exact body",
            )
        if (
            type(self.source_bindings) is not tuple
            or not self.source_bindings
            or len(self.source_bindings) > MAX_ADAPTER_SOURCES_V1
            or any(type(value) is not AdapterSourceBindingV1 for value in self.source_bindings)
        ):
            _reject(
                "invalid_adapter_source_roster",
                "adapter source roster must be a bounded exact tuple",
            )
        bindings = tuple(AdapterSourceBindingV1.from_body(value.to_body()) for value in self.source_bindings)
        canonical = tuple(
            sorted(
                bindings,
                key=lambda value: (
                    value.role,
                    value.namespace or "",
                    value.source_id,
                ),
            )
        )
        if bindings != canonical:
            _reject(
                "invalid_adapter_source_roster",
                "adapter source roster must be canonically sorted",
            )
        source_ids = [value.source_id for value in bindings]
        key_ids = [value.key_id for value in bindings]
        principals = [value.principal_id for value in bindings]
        if (
            len(source_ids) != len(set(source_ids))
            or len(key_ids) != len(set(key_ids))
            or len(principals) != len(set(principals))
        ):
            _reject(
                "adapter_source_independence_confusion",
                "logical sources require distinct labels, keys, and principals",
            )
        if set(key_ids) != set(trust_store.keys):
            _reject(
                "adapter_trust_root_roster_mismatch",
                "adapter trust root must contain exactly the fixed source-roster keys",
            )
        for binding in bindings:
            key = trust_store.keys.get(binding.key_id)
            if (
                key is None
                or key.source_id != binding.source_id
                or key.principal_id != binding.principal_id
                or key.role != binding.role
            ):
                _reject(
                    "adapter_trust_root_roster_mismatch",
                    "source binding differs from its exact usable trust-root key",
                )
        time_bindings = [value for value in bindings if value.role == TRUSTED_TIME_ADAPTER_ROLE_V1]
        if len(time_bindings) < 2:
            _reject(
                "missing_trusted_time_source",
                "adapter profile requires at least two exact trusted-time sources",
            )
        required_namespaces = policy.required_revocation_namespaces
        for namespace in sorted(required_namespaces):
            metadata = [
                value
                for value in bindings
                if value.role == REVOCATION_METADATA_ADAPTER_ROLE_V1 and value.namespace == namespace
            ]
            floors = [
                value
                for value in bindings
                if value.role == REVOCATION_FLOOR_ADAPTER_ROLE_V1 and value.namespace == namespace
            ]
            if len(metadata) != 1 or len(floors) < 2:
                _reject(
                    "invalid_revocation_source_roster",
                    "each namespace requires one metadata source and at least two floor witnesses",
                )
        roster_namespaces = {value.namespace for value in bindings if value.role != TRUSTED_TIME_ADAPTER_ROLE_V1}
        if roster_namespaces != set(required_namespaces):
            _reject(
                "invalid_revocation_source_roster",
                "revocation source namespaces differ from the validation policy",
            )
        max_staleness = _require_nonnegative_int(
            self.max_revocation_staleness_seconds,
            "max_revocation_staleness_seconds",
        )
        object.__setattr__(self, "validation_policy", policy)
        object.__setattr__(self, "trust_store", trust_store)
        object.__setattr__(self, "source_bindings", bindings)
        object.__setattr__(
            self,
            "max_revocation_staleness_seconds",
            max_staleness,
        )

    @property
    def profile_id(self) -> str:
        return content_id("integrity_adapter_trust_profile", self.to_body())

    def binding_for(
        self,
        *,
        role: str,
        source_id: str,
        namespace: str | None,
    ) -> AdapterSourceBindingV1:
        matches = tuple(
            value
            for value in self.source_bindings
            if value.role == role and value.source_id == source_id and value.namespace == namespace
        )
        if len(matches) != 1:
            _reject(
                "adapter_source_binding_mismatch",
                "request source does not have one exact profile binding",
            )
        return matches[0]

    def to_body(self) -> dict[str, object]:
        return {
            "adapter_profile": self.adapter_profile,
            "contract_version": self.contract_version,
            "environment_id": self.environment_id,
            "max_revocation_staleness_seconds": (self.max_revocation_staleness_seconds),
            "service_instance_id": self.service_instance_id,
            "source_bindings": [value.to_body() for value in self.source_bindings],
            "trust_root": self.trust_store.to_body(),
            "trust_root_id": self.trust_root_id,
            "validation_policy": self.validation_policy.to_body(),
            "validation_policy_id": self.validation_policy_id,
        }

    def to_canonical_bytes(self) -> bytes:
        return _canonical_record_bytes(self.to_body())

    @classmethod
    def from_canonical_bytes(
        cls,
        data: bytes | str,
    ) -> IntegrityAdapterTrustProfileV1:
        body = _canonical_record_body(
            data,
            fields=_TRUST_PROFILE_FIELDS,
            label="adapter_trust_profile",
        )
        bindings = body["source_bindings"]
        if type(bindings) is not list or not bindings or len(bindings) > MAX_ADAPTER_SOURCES_V1:
            _reject(
                "invalid_adapter_source_roster",
                "adapter source roster is not a bounded canonical array",
            )
        try:
            policy = IntegrityValidationPolicyV1.from_body(body["validation_policy"])
        except (TypeError, ValueError) as exc:
            raise IntegrityAdapterError(
                "invalid_adapter_validation_policy",
                "adapter validation policy cannot be reconstructed",
            ) from exc
        return cls(
            adapter_profile=body["adapter_profile"],  # type: ignore[arg-type]
            contract_version=body["contract_version"],  # type: ignore[arg-type]
            service_instance_id=body["service_instance_id"],  # type: ignore[arg-type]
            environment_id=body["environment_id"],  # type: ignore[arg-type]
            validation_policy=policy,
            validation_policy_id=body["validation_policy_id"],  # type: ignore[arg-type]
            trust_store=IntegrityAdapterTrustStoreV1.from_body(body["trust_root"]),
            trust_root_id=body["trust_root_id"],  # type: ignore[arg-type]
            source_bindings=tuple(AdapterSourceBindingV1.from_body(value) for value in bindings),
            max_revocation_staleness_seconds=body["max_revocation_staleness_seconds"],  # type: ignore[arg-type]
        )


def _snapshot_profile(value: object) -> IntegrityAdapterTrustProfileV1:
    if type(value) is not IntegrityAdapterTrustProfileV1:
        _reject(
            "invalid_adapter_trust_profile",
            "exact IntegrityAdapterTrustProfileV1 required",
        )
    return IntegrityAdapterTrustProfileV1.from_canonical_bytes(value.to_canonical_bytes())


def _sorted_references(
    values: Iterable[EvidenceReferenceV1],
    *,
    evidence_kind: str,
    minimum: int,
) -> tuple[EvidenceReferenceV1, ...]:
    if isinstance(values, (str, bytes)):
        _reject(
            "invalid_adapter_evidence_references",
            "evidence references must be an exact bounded iterable",
        )
    copied: list[EvidenceReferenceV1] = []
    try:
        for value in values:
            if type(value) is not EvidenceReferenceV1:
                _reject(
                    "invalid_adapter_evidence_references",
                    "evidence references require exact EvidenceReferenceV1 values",
                )
            copied.append(EvidenceReferenceV1.from_body(value.to_body()))
    except IntegrityAdapterError:
        raise
    except (AttributeError, TypeError, ValueError) as exc:
        raise IntegrityAdapterError(
            "invalid_adapter_evidence_references",
            "evidence references are malformed",
        ) from exc
    canonical = tuple(
        sorted(
            copied,
            key=lambda value: (
                value.evidence_kind,
                value.source_id,
                value.evidence_id,
            ),
        )
    )
    identities = {(value.evidence_kind, value.source_id, value.evidence_id) for value in canonical}
    if (
        len(canonical) < minimum
        or len(canonical) > MAX_ADAPTER_SOURCES_V1
        or len(identities) != len(canonical)
        or any(value.evidence_kind != evidence_kind for value in canonical)
    ):
        _reject(
            "invalid_adapter_evidence_references",
            "evidence references have wrong coverage, kind, or uniqueness",
        )
    return canonical


@dataclass(frozen=True, slots=True)
class TrustedTimeRequestV1:
    """One source-specific, nonce-bound trusted-time qualification request."""

    contract_version: int
    profile_id: str
    trust_root_id: str
    service_instance_id: str
    environment_id: str
    mission_id: str
    authority_id: str
    target_id: str
    event_digest: str
    transition_intent_id: str
    source_id: str
    purpose: str
    time_policy_id: str
    imprint_id: str
    request_nonce: str
    request_id: str

    def __post_init__(self) -> None:
        if type(self.contract_version) is not int or self.contract_version != INTEGRITY_ADAPTER_CONTRACT_VERSION_V1:
            _reject(
                "invalid_time_request",
                "trusted-time request requires adapter contract V1",
            )
        for field in (
            "profile_id",
            "trust_root_id",
            "mission_id",
            "authority_id",
            "target_id",
            "event_digest",
            "transition_intent_id",
            "time_policy_id",
            "imprint_id",
            "request_id",
        ):
            _require_digest(getattr(self, field), field)
        for field in (
            "service_instance_id",
            "environment_id",
            "source_id",
        ):
            _require_identity(getattr(self, field), field)
        if self.purpose not in {"decision", "checkpoint"}:
            _reject(
                "invalid_time_request",
                "trusted-time request purpose must be decision or checkpoint",
            )
        _require_nonce(self.request_nonce)
        if self.request_id != content_id(
            "trusted_time_adapter_request",
            self._identity_body(),
        ):
            _reject(
                "time_request_id_mismatch",
                "trusted-time request ID differs from its exact semantics",
            )

    def _identity_body(self) -> dict[str, object]:
        body = self.to_body()
        del body["request_id"]
        return body

    def to_body(self) -> dict[str, object]:
        return {
            "authority_id": self.authority_id,
            "contract_version": self.contract_version,
            "environment_id": self.environment_id,
            "event_digest": self.event_digest,
            "imprint_id": self.imprint_id,
            "mission_id": self.mission_id,
            "profile_id": self.profile_id,
            "purpose": self.purpose,
            "request_id": self.request_id,
            "request_nonce": self.request_nonce,
            "service_instance_id": self.service_instance_id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "time_policy_id": self.time_policy_id,
            "transition_intent_id": self.transition_intent_id,
            "trust_root_id": self.trust_root_id,
        }

    def to_canonical_bytes(self) -> bytes:
        return _canonical_record_bytes(self.to_body())

    @classmethod
    def issue(
        cls,
        *,
        profile: IntegrityAdapterTrustProfileV1,
        source_id: str,
        purpose: str,
        mission_id: str,
        authority_id: str,
        target_id: str,
        event_digest: str,
        transition_intent_id: str,
        imprint_id: str,
        request_nonce: str,
    ) -> TrustedTimeRequestV1:
        profile = _snapshot_profile(profile)
        profile.binding_for(
            role=TRUSTED_TIME_ADAPTER_ROLE_V1,
            source_id=source_id,
            namespace=None,
        )
        if purpose == "decision":
            time_policy_id = profile.validation_policy.decision_time_policy_id
        elif purpose == "checkpoint":
            time_policy_id = profile.validation_policy.checkpoint_time_policy_id
        else:
            _reject(
                "invalid_time_request",
                "trusted-time request purpose must be decision or checkpoint",
            )
        values: dict[str, object] = {
            "authority_id": authority_id,
            "contract_version": INTEGRITY_ADAPTER_CONTRACT_VERSION_V1,
            "environment_id": profile.environment_id,
            "event_digest": event_digest,
            "imprint_id": imprint_id,
            "mission_id": mission_id,
            "profile_id": profile.profile_id,
            "purpose": purpose,
            "request_nonce": request_nonce,
            "service_instance_id": profile.service_instance_id,
            "source_id": source_id,
            "target_id": target_id,
            "time_policy_id": time_policy_id,
            "transition_intent_id": transition_intent_id,
            "trust_root_id": profile.trust_root_id,
        }
        request_id = content_id("trusted_time_adapter_request", values)
        return cls(request_id=request_id, **values)  # type: ignore[arg-type]

    @classmethod
    def from_canonical_bytes(
        cls,
        data: bytes | str,
    ) -> TrustedTimeRequestV1:
        body = _canonical_record_body(
            data,
            fields=_TIME_REQUEST_FIELDS,
            label="time_request",
        )
        return cls(**body)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class RevocationRequestV1:
    """One source-specific revocation request bound to a qualified time hull."""

    contract_version: int
    profile_id: str
    trust_root_id: str
    service_instance_id: str
    environment_id: str
    mission_id: str
    authority_id: str
    target_id: str
    event_digest: str
    transition_intent_id: str
    source_id: str
    evidence_role: str
    namespace: str
    decision_policy_id: str
    time_bundle_id: str
    time_lower_bound: int
    time_upper_bound: int
    time_evidence: tuple[EvidenceReferenceV1, ...]
    prior_root_version: int
    prior_version: int
    prior_snapshot_id: str
    request_nonce: str
    request_id: str

    def __post_init__(self) -> None:
        if type(self.contract_version) is not int or self.contract_version != INTEGRITY_ADAPTER_CONTRACT_VERSION_V1:
            _reject(
                "invalid_revocation_request",
                "revocation request requires adapter contract V1",
            )
        if self.evidence_role not in {
            REVOCATION_METADATA_ADAPTER_ROLE_V1,
            REVOCATION_FLOOR_ADAPTER_ROLE_V1,
        }:
            _reject(
                "invalid_revocation_request",
                "revocation request has a non-revocation evidence role",
            )
        for field in (
            "profile_id",
            "trust_root_id",
            "mission_id",
            "authority_id",
            "target_id",
            "event_digest",
            "transition_intent_id",
            "decision_policy_id",
            "time_bundle_id",
            "prior_snapshot_id",
            "request_id",
        ):
            _require_digest(getattr(self, field), field)
        for field in (
            "service_instance_id",
            "environment_id",
            "source_id",
            "namespace",
        ):
            _require_identity(getattr(self, field), field)
        lower = _require_epoch(self.time_lower_bound, "time_lower_bound")
        upper = _require_epoch(self.time_upper_bound, "time_upper_bound")
        if lower > upper:
            _reject(
                "invalid_revocation_request",
                "revocation request has a reversed trusted-time interval",
            )
        _require_nonnegative_int(self.prior_root_version, "prior_root_version")
        _require_nonnegative_int(self.prior_version, "prior_version")
        _require_nonce(self.request_nonce)
        evidence = _sorted_references(
            self.time_evidence,
            evidence_kind=TRUSTED_TIME_EVIDENCE_KIND,
            minimum=2,
        )
        object.__setattr__(self, "time_evidence", evidence)
        if self.request_id != content_id(
            "revocation_adapter_request",
            self._identity_body(),
        ):
            _reject(
                "revocation_request_id_mismatch",
                "revocation request ID differs from its exact semantics",
            )

    def _identity_body(self) -> dict[str, object]:
        body = self.to_body()
        del body["request_id"]
        return body

    def to_body(self) -> dict[str, object]:
        return {
            "authority_id": self.authority_id,
            "contract_version": self.contract_version,
            "decision_policy_id": self.decision_policy_id,
            "environment_id": self.environment_id,
            "event_digest": self.event_digest,
            "evidence_role": self.evidence_role,
            "mission_id": self.mission_id,
            "namespace": self.namespace,
            "prior_root_version": self.prior_root_version,
            "prior_snapshot_id": self.prior_snapshot_id,
            "prior_version": self.prior_version,
            "profile_id": self.profile_id,
            "request_id": self.request_id,
            "request_nonce": self.request_nonce,
            "service_instance_id": self.service_instance_id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "time_bundle_id": self.time_bundle_id,
            "time_evidence": [value.to_body() for value in self.time_evidence],
            "time_lower_bound": self.time_lower_bound,
            "time_upper_bound": self.time_upper_bound,
            "transition_intent_id": self.transition_intent_id,
            "trust_root_id": self.trust_root_id,
        }

    def to_canonical_bytes(self) -> bytes:
        return _canonical_record_bytes(self.to_body())

    @classmethod
    def issue(
        cls,
        *,
        profile: IntegrityAdapterTrustProfileV1,
        source_id: str,
        evidence_role: str,
        namespace: str,
        time_bundle: QualifiedTimeBundleV1,
        prior_root_version: int,
        prior_version: int,
        prior_snapshot_id: str,
        request_nonce: str,
    ) -> RevocationRequestV1:
        profile = _snapshot_profile(profile)
        if type(time_bundle) is not QualifiedTimeBundleV1:
            _reject(
                "invalid_revocation_request",
                "revocation request requires a sealed qualified time bundle",
            )
        profile.binding_for(
            role=evidence_role,
            source_id=source_id,
            namespace=namespace,
        )
        values: dict[str, object] = {
            "authority_id": time_bundle.authority_id,
            "contract_version": INTEGRITY_ADAPTER_CONTRACT_VERSION_V1,
            "decision_policy_id": (profile.validation_policy.decision_policy_id),
            "environment_id": profile.environment_id,
            "event_digest": time_bundle.event_digest,
            "evidence_role": evidence_role,
            "mission_id": time_bundle.mission_id,
            "namespace": namespace,
            "prior_root_version": prior_root_version,
            "prior_snapshot_id": prior_snapshot_id,
            "prior_version": prior_version,
            "profile_id": profile.profile_id,
            "request_nonce": request_nonce,
            "service_instance_id": profile.service_instance_id,
            "source_id": source_id,
            "target_id": time_bundle.target_id,
            "time_bundle_id": time_bundle.bundle_id,
            "time_evidence": time_bundle.evidence,
            "time_lower_bound": time_bundle.time_lower_bound,
            "time_upper_bound": time_bundle.time_upper_bound,
            "transition_intent_id": time_bundle.transition_intent_id,
            "trust_root_id": profile.trust_root_id,
        }
        identity_values = dict(values)
        identity_values["time_evidence"] = [value.to_body() for value in time_bundle.evidence]
        request_id = content_id(
            "revocation_adapter_request",
            identity_values,
        )
        return cls(request_id=request_id, **values)  # type: ignore[arg-type]

    @classmethod
    def from_canonical_bytes(
        cls,
        data: bytes | str,
    ) -> RevocationRequestV1:
        body = _canonical_record_body(
            data,
            fields=_REVOCATION_REQUEST_FIELDS,
            label="revocation_request",
        )
        evidence = body["time_evidence"]
        if type(evidence) is not list:
            _reject(
                "invalid_revocation_request",
                "revocation request time evidence must be an array",
            )
        body["time_evidence"] = tuple(EvidenceReferenceV1.from_body(value) for value in evidence)
        return cls(**body)  # type: ignore[arg-type]


AdapterRequestV1 = TrustedTimeRequestV1 | RevocationRequestV1


@dataclass(frozen=True, slots=True)
class ProviderEvidenceStatementV1:
    """Authenticated inner semantics, parsed only after outer signature success."""

    contract_version: int
    profile_id: str
    trust_root_id: str
    service_instance_id: str
    environment_id: str
    source_id: str
    evidence_role: str
    provider_policy_id: str
    request_id: str
    claim: Mapping[str, object]

    def __post_init__(self) -> None:
        if type(self.contract_version) is not int or self.contract_version != INTEGRITY_ADAPTER_CONTRACT_VERSION_V1:
            _reject(
                "invalid_provider_statement",
                "provider statement requires adapter contract V1",
            )
        for field in (
            "profile_id",
            "trust_root_id",
            "provider_policy_id",
            "request_id",
        ):
            _require_digest(getattr(self, field), field)
        for field in (
            "service_instance_id",
            "environment_id",
            "source_id",
        ):
            _require_identity(getattr(self, field), field)
        if self.evidence_role not in INTEGRITY_ADAPTER_ROLES_V1:
            _reject(
                "invalid_provider_statement",
                "provider statement has an unsupported role",
            )
        object.__setattr__(
            self,
            "claim",
            _copy_json_object(self.claim, "provider_claim"),
        )

    def to_body(self) -> dict[str, object]:
        return {
            "claim": thaw_json(self.claim),
            "contract_version": self.contract_version,
            "environment_id": self.environment_id,
            "evidence_role": self.evidence_role,
            "profile_id": self.profile_id,
            "provider_policy_id": self.provider_policy_id,
            "request_id": self.request_id,
            "service_instance_id": self.service_instance_id,
            "source_id": self.source_id,
            "trust_root_id": self.trust_root_id,
        }

    def to_canonical_bytes(self) -> bytes:
        return _canonical_record_bytes(self.to_body())

    @classmethod
    def from_canonical_bytes(
        cls,
        data: bytes | str,
    ) -> ProviderEvidenceStatementV1:
        body = _canonical_record_body(
            data,
            fields=_STATEMENT_FIELDS,
            label="provider_statement",
        )
        return cls(**body)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class SignedProviderEvidenceV1:
    """Opaque signed provider statement; its inner claim is not parsed here."""

    evidence_role: str
    key_id: str
    statement_bytes: bytes
    signature_bytes: bytes
    algorithm: str = "ed25519"

    def __post_init__(self) -> None:
        if self.evidence_role not in INTEGRITY_ADAPTER_ROLES_V1:
            _reject(
                "invalid_signed_provider_evidence",
                "signed provider evidence has an unsupported role",
            )
        _require_key_id(self.key_id, "key_id")
        if self.algorithm != "ed25519":
            _reject(
                "unsupported_provider_algorithm",
                "signed provider evidence requires exact Ed25519",
            )
        if (
            type(self.statement_bytes) is not bytes
            or not self.statement_bytes
            or len(self.statement_bytes) > MAX_ADAPTER_PACKAGE_BYTES_V1
            or type(self.signature_bytes) is not bytes
            or len(self.signature_bytes) != 64
        ):
            _reject(
                "invalid_signed_provider_evidence",
                "provider statement or signature bytes are malformed or unbounded",
            )
        object.__setattr__(
            self,
            "statement_bytes",
            bytes(self.statement_bytes),
        )
        object.__setattr__(
            self,
            "signature_bytes",
            bytes(self.signature_bytes),
        )

    def to_body(self) -> dict[str, object]:
        return {
            "algorithm": self.algorithm,
            "evidence_role": self.evidence_role,
            "key_id": self.key_id,
            "signature_b64": base64.b64encode(self.signature_bytes).decode("ascii"),
            "statement_b64": base64.b64encode(self.statement_bytes).decode("ascii"),
        }

    def to_canonical_bytes(self) -> bytes:
        return _canonical_record_bytes(self.to_body())

    @classmethod
    def from_canonical_bytes(
        cls,
        data: bytes | str,
    ) -> SignedProviderEvidenceV1:
        body = _canonical_record_body(
            data,
            fields=_SIGNED_EVIDENCE_FIELDS,
            label="signed_provider_evidence",
        )
        return cls(
            algorithm=body["algorithm"],  # type: ignore[arg-type]
            evidence_role=body["evidence_role"],  # type: ignore[arg-type]
            key_id=body["key_id"],  # type: ignore[arg-type]
            signature_bytes=_decode_b64(
                body["signature_b64"],
                "signature_b64",
                maximum=64,
            ),
            statement_bytes=_decode_b64(
                body["statement_b64"],
                "statement_b64",
                maximum=MAX_ADAPTER_PACKAGE_BYTES_V1,
            ),
        )


@dataclass(frozen=True, slots=True)
class AdapterEvidenceSignerV1:
    """Deterministic repository-fixture signer; never a production key holder."""

    source_id: str
    principal_id: str
    role: str
    private_key_bytes: bytes

    def __post_init__(self) -> None:
        _require_identity(self.source_id, "source_id")
        _require_identity(self.principal_id, "principal_id")
        if self.role not in INTEGRITY_ADAPTER_ROLES_V1:
            _reject("invalid_adapter_signer", "adapter signer has an unsupported role")
        if type(self.private_key_bytes) is not bytes or len(self.private_key_bytes) != 32:
            _reject(
                "invalid_adapter_signer",
                "adapter fixture signer requires exactly 32 private-key bytes",
            )
        try:
            Ed25519PrivateKey.from_private_bytes(self.private_key_bytes)
        except ValueError as exc:
            raise IntegrityAdapterError(
                "invalid_adapter_signer",
                "adapter fixture signer key is invalid",
            ) from exc
        object.__setattr__(
            self,
            "private_key_bytes",
            bytes(self.private_key_bytes),
        )

    @classmethod
    def from_seed(
        cls,
        *,
        source_id: str,
        principal_id: str,
        role: str,
        seed: bytes,
    ) -> AdapterEvidenceSignerV1:
        if type(seed) is not bytes or not seed or len(seed) > MAX_ADAPTER_SEED_BYTES_V1:
            _reject(
                "invalid_adapter_seed",
                "adapter fixture seed must be nonempty immutable bounded bytes",
            )
        private_bytes = hashlib.sha256(
            b"etzio.integrity-adapter.fixture-key.v1\x00"
            + role.encode("ascii")
            + b"\x00"
            + source_id.encode("ascii")
            + b"\x00"
            + seed
        ).digest()
        return cls(
            source_id=source_id,
            principal_id=principal_id,
            role=role,
            private_key_bytes=private_bytes,
        )

    @property
    def trusted_key(self) -> TrustedAdapterKeyV1:
        private_key = Ed25519PrivateKey.from_private_bytes(self.private_key_bytes)
        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return TrustedAdapterKeyV1(
            source_id=self.source_id,
            principal_id=self.principal_id,
            role=self.role,
            public_key_bytes=public_bytes,
        )

    def sign(
        self,
        statement: ProviderEvidenceStatementV1,
    ) -> SignedProviderEvidenceV1:
        if (
            type(statement) is not ProviderEvidenceStatementV1
            or statement.source_id != self.source_id
            or statement.evidence_role != self.role
        ):
            _reject(
                "adapter_signer_binding_mismatch",
                "fixture signer requires its exact source and role statement",
            )
        statement_bytes = statement.to_canonical_bytes()
        signature = Ed25519PrivateKey.from_private_bytes(self.private_key_bytes).sign(
            _ROLE_SIGNATURE_DOMAINS_V1[self.role] + statement_bytes
        )
        return SignedProviderEvidenceV1(
            evidence_role=self.role,
            key_id=self.trusted_key.key_id,
            statement_bytes=statement_bytes,
            signature_bytes=signature,
        )


@dataclass(frozen=True, slots=True, init=False)
class AuthenticatedProviderEvidencePackageV1:
    """Sealed package whose exact retained bytes authenticated before parsing."""

    profile_id: str
    request: AdapterRequestV1
    signed_evidence: SignedProviderEvidenceV1
    statement: ProviderEvidenceStatementV1
    source_binding: AdapterSourceBindingV1
    provider_evidence: ProviderEvidenceBlobV1
    claim: Mapping[str, object]
    _seal: object

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        _reject(
            "unauthenticated_result_construction",
            "authenticated provider package construction is private",
        )

    def __post_init__(self) -> None:
        if type(self) is not AuthenticatedProviderEvidencePackageV1 or self._seal is not _AUTHENTICATED_PACKAGE_SEAL:
            _reject(
                "unauthenticated_result_construction",
                "authenticated provider package construction is private",
            )
        _require_digest(self.profile_id, "profile_id")
        if (
            type(self.request) not in {TrustedTimeRequestV1, RevocationRequestV1}
            or type(self.signed_evidence) is not SignedProviderEvidenceV1
            or type(self.statement) is not ProviderEvidenceStatementV1
            or type(self.source_binding) is not AdapterSourceBindingV1
            or type(self.provider_evidence) is not ProviderEvidenceBlobV1
        ):
            _reject(
                "unauthenticated_result_construction",
                "authenticated provider package contains inexact values",
            )
        object.__setattr__(
            self,
            "claim",
            _copy_json_object(self.claim, "provider_claim"),
        )


def _validate_time_claim(
    request: TrustedTimeRequestV1,
    claim: Mapping[str, object],
) -> None:
    body = _require_exact_dict(
        thaw_json(claim),
        _TIME_CLAIM_FIELDS,
        "trusted_time_claim",
    )
    expected: dict[str, object] = {
        "accuracy_authenticated": True,
        "authority_id": request.authority_id,
        "event_digest": request.event_digest,
        "imprint_id": request.imprint_id,
        "mission_id": request.mission_id,
        "purpose": request.purpose,
        "target_id": request.target_id,
        "time_policy_id": request.time_policy_id,
        "transition_intent_id": request.transition_intent_id,
    }
    for field, value in expected.items():
        if body[field] != value:
            _reject(
                f"provider_{field}_mismatch",
                f"trusted-time provider claim differs at {field}",
            )
    if type(body["accuracy_authenticated"]) is not bool:
        _reject(
            "provider_accuracy_unauthenticated",
            "trusted-time accuracy must be an authenticated boolean",
        )
    lower = _require_epoch(body["time_lower_bound"], "time_lower_bound")
    upper = _require_epoch(body["time_upper_bound"], "time_upper_bound")
    if lower > upper:
        _reject(
            "trusted_time_interval_reversed",
            "trusted-time provider interval is reversed",
        )


def _validate_revocation_claim(
    request: RevocationRequestV1,
    claim: Mapping[str, object],
) -> None:
    body = _require_exact_dict(
        thaw_json(claim),
        _REVOCATION_CLAIM_FIELDS,
        "revocation_claim",
    )
    expected: dict[str, object] = {
        "authority_id": request.authority_id,
        "decision_policy_id": request.decision_policy_id,
        "event_digest": request.event_digest,
        "mission_id": request.mission_id,
        "namespace": request.namespace,
        "target_id": request.target_id,
        "time_bundle_id": request.time_bundle_id,
        "transition_intent_id": request.transition_intent_id,
    }
    for field, value in expected.items():
        if body[field] != value:
            _reject(
                f"provider_{field}_mismatch",
                f"revocation provider claim differs at {field}",
            )
    _require_positive_int(body["root_version"], "root_version")
    _require_positive_int(body["version"], "version")
    _require_digest(body["snapshot_id"], "snapshot_id")
    published_at = _require_epoch(body["published_at"], "published_at")
    valid_from = _require_epoch(body["valid_from"], "valid_from")
    valid_until = _require_epoch(body["valid_until"], "valid_until")
    if valid_from >= valid_until or published_at >= valid_until:
        _reject(
            "invalid_revocation_window",
            "revocation claim validity window is empty or inconsistent",
        )


def authenticate_provider_evidence_v1(
    *,
    profile: IntegrityAdapterTrustProfileV1,
    request: AdapterRequestV1,
    signed_evidence: SignedProviderEvidenceV1,
) -> AuthenticatedProviderEvidencePackageV1:
    """Authenticate exact signed bytes before parsing provider-controlled claims."""

    profile = _snapshot_profile(profile)
    if type(request) is TrustedTimeRequestV1:
        request = TrustedTimeRequestV1.from_canonical_bytes(request.to_canonical_bytes())
        expected_role = TRUSTED_TIME_ADAPTER_ROLE_V1
        namespace = None
    elif type(request) is RevocationRequestV1:
        request = RevocationRequestV1.from_canonical_bytes(request.to_canonical_bytes())
        expected_role = request.evidence_role
        namespace = request.namespace
    else:
        _reject(
            "invalid_adapter_request",
            "provider authentication requires an exact adapter request",
        )
    if (
        request.profile_id != profile.profile_id
        or request.trust_root_id != profile.trust_root_id
        or request.service_instance_id != profile.service_instance_id
        or request.environment_id != profile.environment_id
    ):
        _reject(
            "provider_profile_mismatch",
            "adapter request differs from the complete trust profile",
        )
    binding = profile.binding_for(
        role=expected_role,
        source_id=request.source_id,
        namespace=namespace,
    )
    if type(signed_evidence) is not SignedProviderEvidenceV1:
        _reject(
            "invalid_signed_provider_evidence",
            "provider authentication requires exact signed evidence",
        )
    signed = SignedProviderEvidenceV1.from_canonical_bytes(signed_evidence.to_canonical_bytes())
    if signed.evidence_role != expected_role:
        _reject(
            "provider_role_mismatch",
            "provider package role differs from the request-bound role",
        )
    if signed.key_id != binding.key_id:
        _reject(
            "unknown_adapter_key",
            "provider package does not use the source-bound trust anchor",
        )
    if signed.key_id in profile.trust_store.revoked_key_ids:
        _reject("revoked_adapter_key", "provider package key is revoked")
    trusted_key = profile.trust_store.keys.get(signed.key_id)
    if trusted_key is None:
        _reject("unknown_adapter_key", "provider package key is not trusted")
    try:
        Ed25519PublicKey.from_public_bytes(trusted_key.public_key_bytes).verify(
            signed.signature_bytes,
            _ROLE_SIGNATURE_DOMAINS_V1[expected_role] + signed.statement_bytes,
        )
    except (InvalidSignature, ValueError) as exc:
        raise IntegrityAdapterError(
            "provider_signature_invalid",
            "provider package signature is invalid for the exact retained bytes",
        ) from exc

    statement = ProviderEvidenceStatementV1.from_canonical_bytes(signed.statement_bytes)
    framing_expected: dict[str, object] = {
        "contract_version": INTEGRITY_ADAPTER_CONTRACT_VERSION_V1,
        "environment_id": profile.environment_id,
        "evidence_role": expected_role,
        "profile_id": profile.profile_id,
        "provider_policy_id": binding.provider_policy_id,
        "request_id": request.request_id,
        "service_instance_id": profile.service_instance_id,
        "source_id": binding.source_id,
        "trust_root_id": profile.trust_root_id,
    }
    reason_for_field = {
        "environment_id": "provider_scope_mismatch",
        "evidence_role": "provider_role_mismatch",
        "profile_id": "provider_profile_mismatch",
        "provider_policy_id": "provider_policy_mismatch",
        "request_id": "provider_request_mismatch",
        "service_instance_id": "provider_scope_mismatch",
        "source_id": "provider_source_mismatch",
        "trust_root_id": "provider_root_mismatch",
    }
    for field, expected in framing_expected.items():
        if getattr(statement, field) != expected:
            _reject(
                reason_for_field.get(field, "provider_contract_mismatch"),
                f"provider statement differs at {field}",
            )
    if type(request) is TrustedTimeRequestV1:
        _validate_time_claim(request, statement.claim)
    else:
        _validate_revocation_claim(request, statement.claim)
    provider_evidence = ProviderEvidenceBlobV1.from_content(
        evidence_kind=_ROLE_TO_EVIDENCE_KIND_V1[expected_role],
        source_id=binding.source_id,
        content=signed.to_canonical_bytes(),
    )
    return _construct_sealed_result(
        AuthenticatedProviderEvidencePackageV1,
        seal=_AUTHENTICATED_PACKAGE_SEAL,
        values={
            "profile_id": profile.profile_id,
            "request": request,
            "signed_evidence": signed,
            "statement": statement,
            "source_binding": AdapterSourceBindingV1.from_body(binding.to_body()),
            "provider_evidence": provider_evidence,
            "claim": statement.claim,
        },
    )


@dataclass(frozen=True, slots=True, init=False)
class QualifiedTimeBundleV1:
    """Sealed all-source trusted-time result with a conservative outer hull."""

    profile_id: str
    service_instance_id: str
    environment_id: str
    mission_id: str
    authority_id: str
    target_id: str
    event_digest: str
    transition_intent_id: str
    purpose: str
    time_policy_id: str
    imprint_id: str
    request_nonce: str
    requests: tuple[TrustedTimeRequestV1, ...]
    signed_evidence: tuple[SignedProviderEvidenceV1, ...]
    authenticated_packages: tuple[AuthenticatedProviderEvidencePackageV1, ...]
    time_lower_bound: int
    time_upper_bound: int
    evidence_blobs: tuple[ProviderEvidenceBlobV1, ...]
    _seal: object

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        _reject(
            "unauthenticated_result_construction",
            "qualified time construction is private",
        )

    def __post_init__(self) -> None:
        if type(self) is not QualifiedTimeBundleV1 or self._seal is not _QUALIFIED_TIME_SEAL:
            _reject(
                "unauthenticated_result_construction",
                "qualified time construction is private",
            )
        for field in (
            "profile_id",
            "mission_id",
            "authority_id",
            "target_id",
            "event_digest",
            "transition_intent_id",
            "time_policy_id",
            "imprint_id",
        ):
            _require_digest(getattr(self, field), field)
        _require_identity(self.service_instance_id, "service_instance_id")
        _require_identity(self.environment_id, "environment_id")
        _require_nonce(self.request_nonce)
        if self.purpose not in {"decision", "checkpoint"}:
            _reject(
                "invalid_qualified_time",
                "qualified time has an unsupported purpose",
            )
        lower = _require_epoch(self.time_lower_bound, "time_lower_bound")
        upper = _require_epoch(self.time_upper_bound, "time_upper_bound")
        if lower > upper:
            _reject(
                "invalid_qualified_time",
                "qualified time has a reversed outer hull",
            )
        if (
            type(self.requests) is not tuple
            or type(self.signed_evidence) is not tuple
            or type(self.authenticated_packages) is not tuple
            or type(self.evidence_blobs) is not tuple
            or not self.requests
            or not (
                len(self.requests)
                == len(self.signed_evidence)
                == len(self.authenticated_packages)
                == len(self.evidence_blobs)
            )
            or any(type(value) is not TrustedTimeRequestV1 for value in self.requests)
            or any(type(value) is not SignedProviderEvidenceV1 for value in self.signed_evidence)
            or any(type(value) is not AuthenticatedProviderEvidencePackageV1 for value in self.authenticated_packages)
            or any(type(value) is not ProviderEvidenceBlobV1 for value in self.evidence_blobs)
        ):
            _reject(
                "unauthenticated_result_construction",
                "qualified time has incomplete or inexact retained evidence",
            )

    @property
    def evidence(self) -> tuple[EvidenceReferenceV1, ...]:
        return tuple(value.reference for value in self.evidence_blobs)

    @property
    def bundle_id(self) -> str:
        return content_id("qualified_time_bundle", self.to_body())

    def to_body(self) -> dict[str, object]:
        return {
            "authority_id": self.authority_id,
            "environment_id": self.environment_id,
            "event_digest": self.event_digest,
            "evidence": [value.to_body() for value in self.evidence],
            "imprint_id": self.imprint_id,
            "mission_id": self.mission_id,
            "profile_id": self.profile_id,
            "purpose": self.purpose,
            "request_ids": [value.request_id for value in self.requests],
            "request_nonce": self.request_nonce,
            "service_instance_id": self.service_instance_id,
            "target_id": self.target_id,
            "time_lower_bound": self.time_lower_bound,
            "time_policy_id": self.time_policy_id,
            "time_upper_bound": self.time_upper_bound,
            "transition_intent_id": self.transition_intent_id,
        }


def _exact_source_mapping(
    value: object,
    *,
    expected_sources: tuple[str, ...],
    exact_type: type,
    label: str,
) -> dict[str, object]:
    if type(value) not in {dict, _MAPPING_PROXY_TYPE}:
        _reject(
            "provider_source_set_mismatch",
            f"{label} must be an exact dictionary or immutable dictionary view",
        )
    try:
        copied = dict(value.items())
    except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
        raise IntegrityAdapterError(
            "provider_source_set_mismatch",
            f"{label} cannot be copied",
        ) from exc
    if (
        set(copied) != set(expected_sources)
        or any(type(key) is not str for key in copied)
        or any(type(item) is not exact_type for item in copied.values())
    ):
        _reject(
            "provider_source_set_mismatch",
            f"{label} differs from the complete fixed source roster",
        )
    return copied


def qualify_time_bundle_v1(
    *,
    profile: IntegrityAdapterTrustProfileV1,
    requests: Mapping[str, TrustedTimeRequestV1],
    signed_evidence: Mapping[str, SignedProviderEvidenceV1],
) -> QualifiedTimeBundleV1:
    """Reauthenticate every required time source and retain the outer hull."""

    profile = _snapshot_profile(profile)
    expected_sources = tuple(
        value.source_id for value in profile.source_bindings if value.role == TRUSTED_TIME_ADAPTER_ROLE_V1
    )
    request_map = _exact_source_mapping(
        requests,
        expected_sources=expected_sources,
        exact_type=TrustedTimeRequestV1,
        label="trusted-time requests",
    )
    signed_map = _exact_source_mapping(
        signed_evidence,
        expected_sources=expected_sources,
        exact_type=SignedProviderEvidenceV1,
        label="trusted-time packages",
    )
    retained_requests: list[TrustedTimeRequestV1] = []
    retained_signed: list[SignedProviderEvidenceV1] = []
    authenticated: list[AuthenticatedProviderEvidencePackageV1] = []
    intervals: list[tuple[int, int]] = []
    for source_id in expected_sources:
        request = request_map[source_id]
        if request.source_id != source_id:
            _reject(
                "provider_source_mismatch",
                "trusted-time mapping key differs from its exact request source",
            )
        package = authenticate_provider_evidence_v1(
            profile=profile,
            request=request,
            signed_evidence=signed_map[source_id],
        )
        claim = thaw_json(package.claim)
        if type(claim) is not dict:
            _reject(
                "invalid_trusted_time_claim",
                "authenticated time claim is not an object",
            )
        intervals.append(
            (
                claim["time_lower_bound"],  # type: ignore[arg-type]
                claim["time_upper_bound"],  # type: ignore[arg-type]
            )
        )
        retained_requests.append(package.request)  # type: ignore[arg-type]
        retained_signed.append(package.signed_evidence)
        authenticated.append(package)

    first = retained_requests[0]
    context_fields = (
        "profile_id",
        "trust_root_id",
        "service_instance_id",
        "environment_id",
        "mission_id",
        "authority_id",
        "target_id",
        "event_digest",
        "transition_intent_id",
        "purpose",
        "time_policy_id",
        "imprint_id",
        "request_nonce",
    )
    if any(
        any(getattr(value, field) != getattr(first, field) for field in context_fields)
        for value in retained_requests[1:]
    ):
        _reject(
            "provider_request_mismatch",
            "trusted-time requests do not share one exact bundle context",
        )
    overlap_lower = max(lower for lower, _ in intervals)
    overlap_upper = min(upper for _, upper in intervals)
    if overlap_lower > overlap_upper:
        _reject(
            "trusted_time_intervals_disjoint",
            "trusted-time source intervals have no common overlap",
        )
    outer_lower = min(lower for lower, _ in intervals)
    outer_upper = max(upper for _, upper in intervals)
    if first.purpose == "decision":
        maximum_width = profile.validation_policy.max_decision_uncertainty_seconds
    else:
        maximum_width = profile.validation_policy.max_checkpoint_uncertainty_seconds
    if any(upper - lower > maximum_width for lower, upper in intervals):
        _reject(
            "trusted_time_source_uncertainty_exceeded",
            "one trusted-time source exceeds the purpose policy",
        )
    if outer_upper - outer_lower > maximum_width:
        _reject(
            "trusted_time_uncertainty_exceeded",
            "trusted-time outer hull exceeds the purpose policy",
        )
    evidence_blobs = tuple(value.provider_evidence for value in authenticated)
    if sum(len(value.content) for value in evidence_blobs) > MAX_ADAPTER_TOTAL_EVIDENCE_BYTES_V1:
        _reject(
            "adapter_evidence_limit_exceeded",
            "trusted-time evidence exceeds the aggregate byte ceiling",
        )
    return _construct_sealed_result(
        QualifiedTimeBundleV1,
        seal=_QUALIFIED_TIME_SEAL,
        values={
            "profile_id": profile.profile_id,
            "service_instance_id": first.service_instance_id,
            "environment_id": first.environment_id,
            "mission_id": first.mission_id,
            "authority_id": first.authority_id,
            "target_id": first.target_id,
            "event_digest": first.event_digest,
            "transition_intent_id": first.transition_intent_id,
            "purpose": first.purpose,
            "time_policy_id": first.time_policy_id,
            "imprint_id": first.imprint_id,
            "request_nonce": first.request_nonce,
            "requests": tuple(retained_requests),
            "signed_evidence": tuple(retained_signed),
            "authenticated_packages": tuple(authenticated),
            "time_lower_bound": outer_lower,
            "time_upper_bound": outer_upper,
            "evidence_blobs": evidence_blobs,
        },
    )


def reauthenticate_time_bundle_v1(
    *,
    profile: IntegrityAdapterTrustProfileV1,
    bundle: QualifiedTimeBundleV1,
) -> QualifiedTimeBundleV1:
    """Rebuild a fresh bundle exclusively from retained requests and package bytes."""

    if type(bundle) is not QualifiedTimeBundleV1:
        _reject(
            "unauthenticated_result_construction",
            "time reauthentication requires an exact sealed bundle",
        )
    fresh = qualify_time_bundle_v1(
        profile=profile,
        requests={value.source_id: value for value in bundle.requests},
        signed_evidence={
            request.source_id: signed
            for request, signed in zip(
                bundle.requests,
                bundle.signed_evidence,
                strict=True,
            )
        },
    )
    if fresh.to_body() != bundle.to_body():
        _reject(
            "qualified_time_mutation",
            "retained qualified time differs after fresh reauthentication",
        )
    return fresh


@dataclass(frozen=True, slots=True)
class ExpectedRevocationStateV1:
    """Deterministic fixture expectation and retained predecessor for one namespace."""

    namespace: str
    prior_root_version: int
    prior_version: int
    prior_snapshot_id: str
    expected_root_version: int
    expected_version: int
    expected_snapshot_id: str
    expected_valid_from: int
    expected_valid_until: int
    expected_published_at: int

    def __post_init__(self) -> None:
        _require_identity(self.namespace, "namespace")
        _require_nonnegative_int(self.prior_root_version, "prior_root_version")
        _require_nonnegative_int(self.prior_version, "prior_version")
        _require_digest(self.prior_snapshot_id, "prior_snapshot_id")
        _require_positive_int(
            self.expected_root_version,
            "expected_root_version",
        )
        _require_positive_int(self.expected_version, "expected_version")
        _require_digest(self.expected_snapshot_id, "expected_snapshot_id")
        valid_from = _require_epoch(
            self.expected_valid_from,
            "expected_valid_from",
        )
        valid_until = _require_epoch(
            self.expected_valid_until,
            "expected_valid_until",
        )
        published_at = _require_epoch(
            self.expected_published_at,
            "expected_published_at",
        )
        if valid_from >= valid_until or published_at >= valid_until:
            _reject(
                "invalid_expected_revocation",
                "expected revocation window is empty or inconsistent",
            )

    def to_body(self) -> dict[str, object]:
        return {
            "expected_published_at": self.expected_published_at,
            "expected_root_version": self.expected_root_version,
            "expected_snapshot_id": self.expected_snapshot_id,
            "expected_valid_from": self.expected_valid_from,
            "expected_valid_until": self.expected_valid_until,
            "expected_version": self.expected_version,
            "namespace": self.namespace,
            "prior_root_version": self.prior_root_version,
            "prior_snapshot_id": self.prior_snapshot_id,
            "prior_version": self.prior_version,
        }

    @classmethod
    def from_body(cls, value: object) -> ExpectedRevocationStateV1:
        body = _require_exact_dict(
            value,
            _EXPECTED_REVOCATION_FIELDS,
            "expected_revocation",
        )
        return cls(**body)  # type: ignore[arg-type]


class TrustedTimeAdapterV1(Protocol):
    """Narrow acquisition port; qualification remains kernel-owned."""

    source_id: str

    def acquire(
        self,
        request: TrustedTimeRequestV1,
    ) -> SignedProviderEvidenceV1: ...


class RevocationAdapterV1(Protocol):
    """Narrow revocation acquisition port; no network authority is implied."""

    source_id: str
    role: str
    namespace: str

    def acquire(
        self,
        request: RevocationRequestV1,
    ) -> SignedProviderEvidenceV1: ...


@dataclass(frozen=True, slots=True)
class RepositoryOwnedDeterministicTrustedTimeAdapterV1:
    """Pure repository fixture adapter with a fixed authenticated interval."""

    profile: IntegrityAdapterTrustProfileV1
    binding: AdapterSourceBindingV1
    signer: AdapterEvidenceSignerV1
    time_lower_bound: int
    time_upper_bound: int

    def __post_init__(self) -> None:
        profile = _snapshot_profile(self.profile)
        if type(self.binding) is not AdapterSourceBindingV1 or type(self.signer) is not AdapterEvidenceSignerV1:
            _reject(
                "invalid_fixture_adapter",
                "time fixture adapter requires exact binding and signer",
            )
        binding = AdapterSourceBindingV1.from_body(self.binding.to_body())
        profile_binding = profile.binding_for(
            role=TRUSTED_TIME_ADAPTER_ROLE_V1,
            source_id=binding.source_id,
            namespace=None,
        )
        if (
            binding != profile_binding
            or self.signer.trusted_key.key_id != binding.key_id
            or self.signer.source_id != binding.source_id
            or self.signer.principal_id != binding.principal_id
            or self.signer.role != binding.role
        ):
            _reject(
                "invalid_fixture_adapter",
                "time fixture adapter differs from its complete profile binding",
            )
        lower = _require_epoch(self.time_lower_bound, "time_lower_bound")
        upper = _require_epoch(self.time_upper_bound, "time_upper_bound")
        if lower > upper:
            _reject(
                "invalid_fixture_adapter",
                "time fixture adapter has a reversed interval",
            )
        object.__setattr__(self, "profile", profile)
        object.__setattr__(self, "binding", binding)

    @property
    def source_id(self) -> str:
        return self.binding.source_id

    def acquire(
        self,
        request: TrustedTimeRequestV1,
    ) -> SignedProviderEvidenceV1:
        if (
            type(request) is not TrustedTimeRequestV1
            or request.source_id != self.source_id
            or request.profile_id != self.profile.profile_id
        ):
            _reject(
                "provider_request_mismatch",
                "time fixture adapter received a different source or profile request",
            )
        statement = ProviderEvidenceStatementV1(
            contract_version=INTEGRITY_ADAPTER_CONTRACT_VERSION_V1,
            profile_id=self.profile.profile_id,
            trust_root_id=self.profile.trust_root_id,
            service_instance_id=self.profile.service_instance_id,
            environment_id=self.profile.environment_id,
            source_id=self.source_id,
            evidence_role=TRUSTED_TIME_ADAPTER_ROLE_V1,
            provider_policy_id=self.binding.provider_policy_id,
            request_id=request.request_id,
            claim={
                "accuracy_authenticated": True,
                "authority_id": request.authority_id,
                "event_digest": request.event_digest,
                "imprint_id": request.imprint_id,
                "mission_id": request.mission_id,
                "purpose": request.purpose,
                "target_id": request.target_id,
                "time_lower_bound": self.time_lower_bound,
                "time_policy_id": request.time_policy_id,
                "time_upper_bound": self.time_upper_bound,
                "transition_intent_id": request.transition_intent_id,
            },
        )
        return self.signer.sign(statement)


@dataclass(frozen=True, slots=True)
class RepositoryOwnedDeterministicRevocationAdapterV1:
    """Pure fixture adapter that signs one fixed metadata or floor state."""

    profile: IntegrityAdapterTrustProfileV1
    binding: AdapterSourceBindingV1
    signer: AdapterEvidenceSignerV1
    state: ExpectedRevocationStateV1

    def __post_init__(self) -> None:
        profile = _snapshot_profile(self.profile)
        if (
            type(self.binding) is not AdapterSourceBindingV1
            or type(self.signer) is not AdapterEvidenceSignerV1
            or type(self.state) is not ExpectedRevocationStateV1
        ):
            _reject(
                "invalid_fixture_adapter",
                "revocation fixture adapter requires exact retained values",
            )
        binding = AdapterSourceBindingV1.from_body(self.binding.to_body())
        state = ExpectedRevocationStateV1.from_body(self.state.to_body())
        profile_binding = profile.binding_for(
            role=binding.role,
            source_id=binding.source_id,
            namespace=binding.namespace,
        )
        if (
            binding.role
            not in {
                REVOCATION_METADATA_ADAPTER_ROLE_V1,
                REVOCATION_FLOOR_ADAPTER_ROLE_V1,
            }
            or binding != profile_binding
            or binding.namespace != state.namespace
            or self.signer.trusted_key.key_id != binding.key_id
            or self.signer.source_id != binding.source_id
            or self.signer.principal_id != binding.principal_id
            or self.signer.role != binding.role
        ):
            _reject(
                "invalid_fixture_adapter",
                "revocation fixture adapter differs from its profile binding",
            )
        object.__setattr__(self, "profile", profile)
        object.__setattr__(self, "binding", binding)
        object.__setattr__(self, "state", state)

    @property
    def source_id(self) -> str:
        return self.binding.source_id

    @property
    def role(self) -> str:
        return self.binding.role

    @property
    def namespace(self) -> str:
        namespace = self.binding.namespace
        if namespace is None:
            _reject(
                "invalid_fixture_adapter",
                "revocation fixture binding lacks its namespace",
            )
        return namespace

    def acquire(
        self,
        request: RevocationRequestV1,
    ) -> SignedProviderEvidenceV1:
        state = self.state
        if (
            type(request) is not RevocationRequestV1
            or request.source_id != self.source_id
            or request.evidence_role != self.role
            or request.namespace != self.namespace
            or request.profile_id != self.profile.profile_id
            or request.prior_root_version != state.prior_root_version
            or request.prior_version != state.prior_version
            or request.prior_snapshot_id != state.prior_snapshot_id
        ):
            _reject(
                "provider_request_mismatch",
                "revocation fixture adapter received a different exact request",
            )
        statement = ProviderEvidenceStatementV1(
            contract_version=INTEGRITY_ADAPTER_CONTRACT_VERSION_V1,
            profile_id=self.profile.profile_id,
            trust_root_id=self.profile.trust_root_id,
            service_instance_id=self.profile.service_instance_id,
            environment_id=self.profile.environment_id,
            source_id=self.source_id,
            evidence_role=self.role,
            provider_policy_id=self.binding.provider_policy_id,
            request_id=request.request_id,
            claim={
                "authority_id": request.authority_id,
                "decision_policy_id": request.decision_policy_id,
                "event_digest": request.event_digest,
                "mission_id": request.mission_id,
                "namespace": request.namespace,
                "published_at": state.expected_published_at,
                "root_version": state.expected_root_version,
                "snapshot_id": state.expected_snapshot_id,
                "target_id": request.target_id,
                "time_bundle_id": request.time_bundle_id,
                "transition_intent_id": request.transition_intent_id,
                "valid_from": state.expected_valid_from,
                "valid_until": state.expected_valid_until,
                "version": state.expected_version,
            },
        )
        return self.signer.sign(statement)


@dataclass(frozen=True, slots=True, init=False)
class QualifiedRevocationBundleV1:
    """Sealed unanimous metadata-and-floor result for one namespace."""

    profile_id: str
    namespace: str
    time_bundle_id: str
    requests: tuple[RevocationRequestV1, ...]
    signed_evidence: tuple[SignedProviderEvidenceV1, ...]
    authenticated_packages: tuple[AuthenticatedProviderEvidencePackageV1, ...]
    root_version: int
    version: int
    snapshot_id: str
    valid_from: int
    valid_until: int
    published_at: int
    revocation_view: RevocationViewV1
    external_floor: RevocationFloorV1
    evidence_blobs: tuple[ProviderEvidenceBlobV1, ...]
    _seal: object

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        _reject(
            "unauthenticated_result_construction",
            "qualified revocation construction is private",
        )

    def __post_init__(self) -> None:
        if type(self) is not QualifiedRevocationBundleV1 or self._seal is not _QUALIFIED_REVOCATION_SEAL:
            _reject(
                "unauthenticated_result_construction",
                "qualified revocation construction is private",
            )
        _require_digest(self.profile_id, "profile_id")
        _require_identity(self.namespace, "namespace")
        _require_digest(self.time_bundle_id, "time_bundle_id")
        _require_positive_int(self.root_version, "root_version")
        _require_positive_int(self.version, "version")
        _require_digest(self.snapshot_id, "snapshot_id")
        _require_epoch(self.valid_from, "valid_from")
        _require_epoch(self.valid_until, "valid_until")
        _require_epoch(self.published_at, "published_at")
        if (
            type(self.requests) is not tuple
            or type(self.signed_evidence) is not tuple
            or type(self.authenticated_packages) is not tuple
            or type(self.evidence_blobs) is not tuple
            or not (
                len(self.requests)
                == len(self.signed_evidence)
                == len(self.authenticated_packages)
                == len(self.evidence_blobs)
            )
            or any(type(value) is not RevocationRequestV1 for value in self.requests)
            or any(type(value) is not SignedProviderEvidenceV1 for value in self.signed_evidence)
            or any(type(value) is not AuthenticatedProviderEvidencePackageV1 for value in self.authenticated_packages)
            or any(type(value) is not ProviderEvidenceBlobV1 for value in self.evidence_blobs)
            or type(self.revocation_view) is not RevocationViewV1
            or type(self.external_floor) is not RevocationFloorV1
        ):
            _reject(
                "unauthenticated_result_construction",
                "qualified revocation contains incomplete or inexact values",
            )

    @property
    def evidence(self) -> tuple[EvidenceReferenceV1, ...]:
        return tuple(value.reference for value in self.evidence_blobs)

    @property
    def bundle_id(self) -> str:
        return content_id("qualified_revocation_bundle", self.to_body())

    def to_body(self) -> dict[str, object]:
        return {
            "evidence": [value.to_body() for value in self.evidence],
            "external_floor": self.external_floor.to_body(),
            "namespace": self.namespace,
            "profile_id": self.profile_id,
            "published_at": self.published_at,
            "request_ids": [value.request_id for value in self.requests],
            "revocation_view": self.revocation_view.to_body(),
            "root_version": self.root_version,
            "snapshot_id": self.snapshot_id,
            "time_bundle_id": self.time_bundle_id,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "version": self.version,
        }


def qualify_revocation_bundle_v1(
    *,
    profile: IntegrityAdapterTrustProfileV1,
    namespace: str,
    time_bundle: QualifiedTimeBundleV1,
    requests: Mapping[str, RevocationRequestV1],
    signed_evidence: Mapping[str, SignedProviderEvidenceV1],
) -> QualifiedRevocationBundleV1:
    """Require complete-hull freshness and unanimous fixed floor witnesses."""

    profile = _snapshot_profile(profile)
    _require_identity(namespace, "namespace")
    if namespace not in profile.validation_policy.required_revocation_namespaces:
        _reject(
            "revocation_namespace_coverage_mismatch",
            "revocation namespace is not required by the exact profile",
        )
    fresh_time = reauthenticate_time_bundle_v1(
        profile=profile,
        bundle=time_bundle,
    )
    if fresh_time.purpose != "decision":
        _reject(
            "revocation_time_bundle_mismatch",
            "revocation qualification requires the decision-time bundle",
        )
    expected_bindings = tuple(
        value
        for value in profile.source_bindings
        if value.namespace == namespace
        and value.role
        in {
            REVOCATION_METADATA_ADAPTER_ROLE_V1,
            REVOCATION_FLOOR_ADAPTER_ROLE_V1,
        }
    )
    expected_sources = tuple(value.source_id for value in expected_bindings)
    request_map = _exact_source_mapping(
        requests,
        expected_sources=expected_sources,
        exact_type=RevocationRequestV1,
        label="revocation requests",
    )
    signed_map = _exact_source_mapping(
        signed_evidence,
        expected_sources=expected_sources,
        exact_type=SignedProviderEvidenceV1,
        label="revocation packages",
    )
    retained_requests: list[RevocationRequestV1] = []
    retained_signed: list[SignedProviderEvidenceV1] = []
    authenticated: list[AuthenticatedProviderEvidencePackageV1] = []
    claims: list[dict[str, object]] = []
    for binding in expected_bindings:
        request = request_map[binding.source_id]
        if (
            request.source_id != binding.source_id
            or request.evidence_role != binding.role
            or request.namespace != namespace
            or request.profile_id != profile.profile_id
            or request.trust_root_id != profile.trust_root_id
            or request.decision_policy_id != profile.validation_policy.decision_policy_id
            or request.time_bundle_id != fresh_time.bundle_id
            or request.time_lower_bound != fresh_time.time_lower_bound
            or request.time_upper_bound != fresh_time.time_upper_bound
            or request.time_evidence != fresh_time.evidence
        ):
            _reject(
                "revocation_time_bundle_mismatch",
                "revocation request differs from its exact profile or time bundle",
            )
        package = authenticate_provider_evidence_v1(
            profile=profile,
            request=request,
            signed_evidence=signed_map[binding.source_id],
        )
        claim = thaw_json(package.claim)
        if type(claim) is not dict:
            _reject(
                "invalid_revocation_claim",
                "authenticated revocation claim is not an object",
            )
        retained_requests.append(package.request)  # type: ignore[arg-type]
        retained_signed.append(package.signed_evidence)
        authenticated.append(package)
        claims.append(claim)

    first_request = retained_requests[0]
    predecessor = (
        first_request.prior_root_version,
        first_request.prior_version,
        first_request.prior_snapshot_id,
    )
    if any(
        (
            request.prior_root_version,
            request.prior_version,
            request.prior_snapshot_id,
        )
        != predecessor
        for request in retained_requests[1:]
    ):
        _reject(
            "provider_request_mismatch",
            "revocation sources do not share one exact predecessor",
        )
    state_fields = (
        "root_version",
        "version",
        "snapshot_id",
        "valid_from",
        "valid_until",
        "published_at",
    )
    state = tuple(claims[0][field] for field in state_fields)
    if any(tuple(claim[field] for field in state_fields) != state for claim in claims[1:]):
        _reject(
            "revocation_floor_disagreement",
            "metadata and every fixed floor witness must name one exact state",
        )
    (
        root_version,
        version,
        snapshot_id,
        valid_from,
        valid_until,
        published_at,
    ) = state
    root_version = _require_positive_int(root_version, "root_version")
    version = _require_positive_int(version, "version")
    snapshot_id = _require_digest(snapshot_id, "snapshot_id")
    valid_from = _require_epoch(valid_from, "valid_from")
    valid_until = _require_epoch(valid_until, "valid_until")
    published_at = _require_epoch(published_at, "published_at")
    if fresh_time.time_lower_bound < valid_from or fresh_time.time_upper_bound >= valid_until:
        _reject(
            "revocation_validity_outside_window",
            "the complete closed time hull does not fit the half-open validity window",
        )
    if (
        published_at > fresh_time.time_lower_bound
        or fresh_time.time_upper_bound - published_at > profile.max_revocation_staleness_seconds
    ):
        _reject(
            "revocation_metadata_stale",
            "revocation publication time is future or stale for the complete hull",
        )
    prior_root_version, prior_version, prior_snapshot_id = predecessor
    if root_version < prior_root_version:
        _reject(
            "revocation_root_rollback",
            "revocation root version is behind retained history",
        )
    if prior_root_version > 0 and root_version > prior_root_version + 1:
        _reject(
            "revocation_root_update_skipped",
            "revocation root update skips a retained version",
        )
    if version < prior_version:
        _reject(
            "revocation_version_rollback",
            "revocation metadata version is behind retained history",
        )
    if version == prior_version and (root_version != prior_root_version or snapshot_id != prior_snapshot_id):
        _reject(
            "revocation_same_version_mutation",
            "equal metadata versions require the same root and snapshot",
        )

    metadata_packages = tuple(
        value for value in authenticated if value.source_binding.role == REVOCATION_METADATA_ADAPTER_ROLE_V1
    )
    floor_packages = tuple(
        value for value in authenticated if value.source_binding.role == REVOCATION_FLOOR_ADAPTER_ROLE_V1
    )
    if len(metadata_packages) != 1 or len(floor_packages) < 2:
        _reject(
            "revocation_namespace_coverage_mismatch",
            "revocation qualification lacks its fixed metadata or floor set",
        )
    try:
        revocation_view = RevocationViewV1(
            namespace=namespace,
            root_version=root_version,
            version=version,
            snapshot_id=snapshot_id,
            evidence=metadata_packages[0].provider_evidence.reference,
            valid_from=valid_from,
            valid_until=valid_until,
        )
        external_floor = RevocationFloorV1(
            service_instance_id=profile.service_instance_id,
            environment_id=profile.environment_id,
            decision_policy_id=profile.validation_policy.decision_policy_id,
            namespace=namespace,
            root_version=root_version,
            version=version,
            snapshot_id=snapshot_id,
            evidence=tuple(value.provider_evidence.reference for value in floor_packages),
        )
    except (TypeError, ValueError) as exc:
        raise IntegrityAdapterError(
            "invalid_revocation_mapping",
            "qualified revocation cannot map to provider-neutral values",
        ) from exc
    evidence_blobs = tuple(
        sorted(
            (value.provider_evidence for value in authenticated),
            key=lambda value: (
                value.evidence_kind,
                value.source_id,
                value.evidence_id,
            ),
        )
    )
    if sum(len(value.content) for value in evidence_blobs) > MAX_ADAPTER_TOTAL_EVIDENCE_BYTES_V1:
        _reject(
            "adapter_evidence_limit_exceeded",
            "revocation evidence exceeds the aggregate byte ceiling",
        )
    return _construct_sealed_result(
        QualifiedRevocationBundleV1,
        seal=_QUALIFIED_REVOCATION_SEAL,
        values={
            "profile_id": profile.profile_id,
            "namespace": namespace,
            "time_bundle_id": fresh_time.bundle_id,
            "requests": tuple(retained_requests),
            "signed_evidence": tuple(retained_signed),
            "authenticated_packages": tuple(authenticated),
            "root_version": root_version,
            "version": version,
            "snapshot_id": snapshot_id,
            "valid_from": valid_from,
            "valid_until": valid_until,
            "published_at": published_at,
            "revocation_view": revocation_view,
            "external_floor": external_floor,
            "evidence_blobs": evidence_blobs,
        },
    )


def reauthenticate_revocation_bundle_v1(
    *,
    profile: IntegrityAdapterTrustProfileV1,
    time_bundle: QualifiedTimeBundleV1,
    bundle: QualifiedRevocationBundleV1,
) -> QualifiedRevocationBundleV1:
    """Rebuild a fresh namespace result from retained exact signed packages."""

    if type(bundle) is not QualifiedRevocationBundleV1:
        _reject(
            "unauthenticated_result_construction",
            "revocation reauthentication requires an exact sealed bundle",
        )
    fresh = qualify_revocation_bundle_v1(
        profile=profile,
        namespace=bundle.namespace,
        time_bundle=time_bundle,
        requests={value.source_id: value for value in bundle.requests},
        signed_evidence={
            request.source_id: signed
            for request, signed in zip(
                bundle.requests,
                bundle.signed_evidence,
                strict=True,
            )
        },
    )
    if fresh.to_body() != bundle.to_body():
        _reject(
            "qualified_revocation_mutation",
            "retained revocation differs after fresh reauthentication",
        )
    return fresh


@dataclass(frozen=True, slots=True, init=False)
class QualifiedIntegrityInputsV1:
    """Sealed exact provider-neutral mapping plus every covering signed BLOB."""

    profile_id: str
    time_bundle_id: str
    time_lower_bound: int
    time_upper_bound: int
    time_policy_id: str
    time_evidence: tuple[EvidenceReferenceV1, ...]
    revocation_views: tuple[RevocationViewV1, ...]
    external_floors: tuple[RevocationFloorV1, ...]
    evidence_blobs: tuple[ProviderEvidenceBlobV1, ...]
    _seal: object

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        _reject(
            "unauthenticated_result_construction",
            "qualified integrity-input construction is private",
        )

    def __post_init__(self) -> None:
        if type(self) is not QualifiedIntegrityInputsV1 or self._seal is not _QUALIFIED_INPUTS_SEAL:
            _reject(
                "unauthenticated_result_construction",
                "qualified integrity-input construction is private",
            )
        _require_digest(self.profile_id, "profile_id")
        _require_digest(self.time_bundle_id, "time_bundle_id")
        _require_epoch(self.time_lower_bound, "time_lower_bound")
        _require_epoch(self.time_upper_bound, "time_upper_bound")
        _require_digest(self.time_policy_id, "time_policy_id")
        if (
            type(self.time_evidence) is not tuple
            or type(self.revocation_views) is not tuple
            or type(self.external_floors) is not tuple
            or type(self.evidence_blobs) is not tuple
        ):
            _reject(
                "unauthenticated_result_construction",
                "qualified integrity inputs require exact immutable tuples",
            )

    @property
    def mapping_id(self) -> str:
        return content_id("qualified_integrity_inputs", self.to_body())

    def to_body(self) -> dict[str, object]:
        return {
            "evidence": [value.to_body() for value in self.evidence_blobs],
            "external_floors": [value.to_body() for value in self.external_floors],
            "profile_id": self.profile_id,
            "revocation_views": [value.to_body() for value in self.revocation_views],
            "time_bundle_id": self.time_bundle_id,
            "time_evidence": [value.to_body() for value in self.time_evidence],
            "time_lower_bound": self.time_lower_bound,
            "time_policy_id": self.time_policy_id,
            "time_upper_bound": self.time_upper_bound,
        }


def map_qualified_integrity_inputs_v1(
    *,
    profile: IntegrityAdapterTrustProfileV1,
    time_bundle: QualifiedTimeBundleV1,
    revocation_bundles: Mapping[str, QualifiedRevocationBundleV1],
) -> QualifiedIntegrityInputsV1:
    """Freshly reauthenticate and map only complete, byte-covered sealed values."""

    profile = _snapshot_profile(profile)
    fresh_time = reauthenticate_time_bundle_v1(
        profile=profile,
        bundle=time_bundle,
    )
    required_namespaces = tuple(sorted(profile.validation_policy.required_revocation_namespaces))
    bundle_map = _exact_source_mapping(
        revocation_bundles,
        expected_sources=required_namespaces,
        exact_type=QualifiedRevocationBundleV1,
        label="qualified revocation namespace bundles",
    )
    fresh_revocation_values: list[QualifiedRevocationBundleV1] = []
    for namespace in required_namespaces:
        retained_bundle = bundle_map[namespace]
        if type(retained_bundle) is not QualifiedRevocationBundleV1 or retained_bundle.namespace != namespace:
            _reject(
                "revocation_namespace_coverage_mismatch",
                "revocation mapping key differs from its sealed namespace",
            )
        fresh_revocation_values.append(
            reauthenticate_revocation_bundle_v1(
                profile=profile,
                time_bundle=fresh_time,
                bundle=retained_bundle,
            )
        )
    fresh_revocations = tuple(fresh_revocation_values)
    revocation_views = tuple(value.revocation_view for value in fresh_revocations)
    external_floors = tuple(value.external_floor for value in fresh_revocations)
    if (
        tuple(value.namespace for value in revocation_views) != required_namespaces
        or tuple(value.namespace for value in external_floors) != required_namespaces
    ):
        _reject(
            "revocation_namespace_coverage_mismatch",
            "mapped revocation values are not the exact canonical namespace set",
        )
    evidence_blobs = tuple(
        sorted(
            (
                *fresh_time.evidence_blobs,
                *(blob for bundle in fresh_revocations for blob in bundle.evidence_blobs),
            ),
            key=lambda value: (
                value.evidence_kind,
                value.source_id,
                value.evidence_id,
            ),
        )
    )
    references = {
        (
            value.evidence_kind,
            value.source_id,
            value.evidence_id,
        )
        for value in (
            *fresh_time.evidence,
            *(view.evidence for view in revocation_views),
            *(reference for floor in external_floors for reference in floor.evidence),
        )
    }
    retained = {
        (
            value.evidence_kind,
            value.source_id,
            value.evidence_id,
        )
        for value in evidence_blobs
    }
    if references != retained or len(retained) != len(evidence_blobs):
        _reject(
            "qualified_evidence_coverage_mismatch",
            "mapped provider references and retained exact BLOBs differ",
        )
    if sum(len(value.content) for value in evidence_blobs) > MAX_ADAPTER_TOTAL_EVIDENCE_BYTES_V1:
        _reject(
            "adapter_evidence_limit_exceeded",
            "mapped provider evidence exceeds the aggregate byte ceiling",
        )
    return _construct_sealed_result(
        QualifiedIntegrityInputsV1,
        seal=_QUALIFIED_INPUTS_SEAL,
        values={
            "profile_id": profile.profile_id,
            "time_bundle_id": fresh_time.bundle_id,
            "time_lower_bound": fresh_time.time_lower_bound,
            "time_upper_bound": fresh_time.time_upper_bound,
            "time_policy_id": fresh_time.time_policy_id,
            "time_evidence": fresh_time.evidence,
            "revocation_views": revocation_views,
            "external_floors": external_floors,
            "evidence_blobs": evidence_blobs,
        },
    )


@dataclass(frozen=True, slots=True)
class IntegrityAdapterQualificationVectorV1:
    """One content-addressed deterministic success vector and expected state."""

    service_instance_id: str
    environment_id: str
    mission_id: str
    authority_id: str
    target_id: str
    event_digest: str
    transition_intent_id: str
    request_nonce: str
    expected_epoch_second: int
    expected_revocation: tuple[ExpectedRevocationStateV1, ...]

    def __post_init__(self) -> None:
        _require_identity(self.service_instance_id, "service_instance_id")
        _require_identity(self.environment_id, "environment_id")
        for field in (
            "mission_id",
            "authority_id",
            "target_id",
            "event_digest",
            "transition_intent_id",
        ):
            _require_digest(getattr(self, field), field)
        _require_nonce(self.request_nonce)
        _require_epoch(
            self.expected_epoch_second,
            "expected_epoch_second",
        )
        if (
            type(self.expected_revocation) is not tuple
            or not self.expected_revocation
            or any(type(value) is not ExpectedRevocationStateV1 for value in self.expected_revocation)
        ):
            _reject(
                "invalid_qualification_vector",
                "qualification vector needs exact expected revocation states",
            )
        states = tuple(ExpectedRevocationStateV1.from_body(value.to_body()) for value in self.expected_revocation)
        canonical = tuple(sorted(states, key=lambda value: value.namespace))
        if states != canonical or len({value.namespace for value in states}) != len(states):
            _reject(
                "invalid_qualification_vector",
                "qualification namespaces must be unique and sorted",
            )
        object.__setattr__(self, "expected_revocation", states)

    @property
    def vector_id(self) -> str:
        return content_id("integrity_adapter_qualification_vector", self.to_body())

    def to_body(self) -> dict[str, object]:
        return {
            "authority_id": self.authority_id,
            "environment_id": self.environment_id,
            "event_digest": self.event_digest,
            "expected_epoch_second": self.expected_epoch_second,
            "expected_revocation": [value.to_body() for value in self.expected_revocation],
            "mission_id": self.mission_id,
            "request_nonce": self.request_nonce,
            "service_instance_id": self.service_instance_id,
            "target_id": self.target_id,
            "transition_intent_id": self.transition_intent_id,
        }

    def to_canonical_bytes(self) -> bytes:
        return _canonical_record_bytes(self.to_body())

    @classmethod
    def from_canonical_bytes(
        cls,
        data: bytes | str,
    ) -> IntegrityAdapterQualificationVectorV1:
        body = _canonical_record_body(
            data,
            fields=_QUALIFICATION_VECTOR_FIELDS,
            label="qualification_vector",
        )
        states = body["expected_revocation"]
        if type(states) is not list:
            _reject(
                "invalid_qualification_vector",
                "expected revocation states must be a canonical array",
            )
        body["expected_revocation"] = tuple(ExpectedRevocationStateV1.from_body(value) for value in states)
        return cls(**body)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class RepositoryOwnedDeterministicAdapterFixtureV1:
    """Complete networkless fixture corpus inputs; no acquisition capability."""

    adapter_implementation_id: str
    corpus_manifest_id: str
    profile: IntegrityAdapterTrustProfileV1
    vector: IntegrityAdapterQualificationVectorV1
    time_adapters: tuple[RepositoryOwnedDeterministicTrustedTimeAdapterV1, ...]
    revocation_adapters: tuple[RepositoryOwnedDeterministicRevocationAdapterV1, ...]

    def __post_init__(self) -> None:
        _require_digest(
            self.adapter_implementation_id,
            "adapter_implementation_id",
        )
        _require_digest(self.corpus_manifest_id, "corpus_manifest_id")
        profile = _snapshot_profile(self.profile)
        if type(self.vector) is not IntegrityAdapterQualificationVectorV1:
            _reject(
                "invalid_qualification_fixture",
                "fixture requires an exact qualification vector",
            )
        vector = IntegrityAdapterQualificationVectorV1.from_canonical_bytes(self.vector.to_canonical_bytes())
        if (
            vector.service_instance_id != profile.service_instance_id
            or vector.environment_id != profile.environment_id
            or {value.namespace for value in vector.expected_revocation}
            != set(profile.validation_policy.required_revocation_namespaces)
            or type(self.time_adapters) is not tuple
            or type(self.revocation_adapters) is not tuple
            or any(type(value) is not RepositoryOwnedDeterministicTrustedTimeAdapterV1 for value in self.time_adapters)
            or any(
                type(value) is not RepositoryOwnedDeterministicRevocationAdapterV1 for value in self.revocation_adapters
            )
        ):
            _reject(
                "invalid_qualification_fixture",
                "fixture vector or adapters differ from the exact profile",
            )
        expected_time = tuple(
            value.source_id for value in profile.source_bindings if value.role == TRUSTED_TIME_ADAPTER_ROLE_V1
        )
        expected_revocation = tuple(
            value.source_id
            for value in profile.source_bindings
            if value.role
            in {
                REVOCATION_METADATA_ADAPTER_ROLE_V1,
                REVOCATION_FLOOR_ADAPTER_ROLE_V1,
            }
        )
        if (
            tuple(value.source_id for value in self.time_adapters) != expected_time
            or tuple(value.source_id for value in self.revocation_adapters) != expected_revocation
            or any(value.profile.profile_id != profile.profile_id for value in self.time_adapters)
            or any(value.profile.profile_id != profile.profile_id for value in self.revocation_adapters)
        ):
            _reject(
                "provider_source_set_mismatch",
                "fixture adapters differ from the complete source roster",
            )
        expected_states = {value.namespace: value.to_body() for value in vector.expected_revocation}
        if any(value.state.to_body() != expected_states.get(value.namespace) for value in self.revocation_adapters):
            _reject(
                "invalid_qualification_fixture",
                "fixture revocation adapters differ from the expected vector",
            )
        expected_manifest_id = _qualification_manifest_id(
            adapter_implementation_id=self.adapter_implementation_id,
            profile=profile,
            vector=vector,
            time_adapters=self.time_adapters,
            revocation_adapters=self.revocation_adapters,
        )
        if self.corpus_manifest_id != expected_manifest_id:
            _reject(
                "qualification_manifest_mismatch",
                "fixture corpus identity differs from its exact adapter inputs",
            )
        object.__setattr__(self, "profile", profile)
        object.__setattr__(self, "vector", vector)


def _fixture_content_id(label: str, value: object) -> str:
    return content_id(
        "integrity_adapter_repository_fixture",
        {"label": label, "value": value},
    )


def _fixture_nonce(seed: bytes, label: str) -> str:
    return hashlib.sha256(
        b"etzio.integrity-adapter.fixture-nonce.v1\x00" + label.encode("ascii") + b"\x00" + seed
    ).hexdigest()


def _qualification_case_ids(
    namespaces: tuple[str, ...],
) -> tuple[str, ...]:
    cases = [
        "decision-time-exact-retry",
        "decision-time-qualification",
        "checkpoint-time-exact-retry",
        "checkpoint-time-qualification",
        "cross-request-replay-refused",
    ]
    for namespace in namespaces:
        cases.extend(
            (
                f"revocation-{namespace}-exact-retry",
                f"revocation-{namespace}-qualification",
            )
        )
    cases.append("provider-neutral-mapping")
    return tuple(cases)


def _qualification_manifest_id(
    *,
    adapter_implementation_id: str,
    profile: IntegrityAdapterTrustProfileV1,
    vector: IntegrityAdapterQualificationVectorV1,
    time_adapters: tuple[RepositoryOwnedDeterministicTrustedTimeAdapterV1, ...],
    revocation_adapters: tuple[RepositoryOwnedDeterministicRevocationAdapterV1, ...],
) -> str:
    """Bind every deterministic corpus input that may affect an outcome."""

    namespaces = tuple(value.namespace for value in vector.expected_revocation)
    return _fixture_content_id(
        "qualification-corpus",
        {
            "adapter_implementation_id": adapter_implementation_id,
            "case_ids": list(_qualification_case_ids(namespaces)),
            "profile_id": profile.profile_id,
            "revocation_adapter_inputs": [
                {
                    "role": value.role,
                    "source_id": value.source_id,
                    "state": value.state.to_body(),
                }
                for value in revocation_adapters
            ],
            "time_adapter_inputs": [
                {
                    "source_id": value.source_id,
                    "time_lower_bound": value.time_lower_bound,
                    "time_upper_bound": value.time_upper_bound,
                }
                for value in time_adapters
            ],
            "vector_id": vector.vector_id,
        },
    )


def create_repository_owned_adapter_fixture_v1(
    *,
    seed: bytes,
    namespaces: tuple[str, ...] = ("authority", "verifier"),
    expected_epoch_second: int = 2_000_000_000,
) -> RepositoryOwnedDeterministicAdapterFixtureV1:
    """Build complete deterministic keys, profile, adapters, and vector from a seed."""

    if type(seed) is not bytes or not seed or len(seed) > MAX_ADAPTER_SEED_BYTES_V1:
        _reject(
            "invalid_adapter_seed",
            "fixture seed must be nonempty immutable bounded bytes",
        )
    if type(namespaces) is not tuple or not namespaces or tuple(sorted(set(namespaces))) != namespaces:
        _reject(
            "invalid_adapter_namespaces",
            "fixture namespaces must be a nonempty unique sorted tuple",
        )
    for namespace in namespaces:
        _require_identity(namespace, "namespace")
    epoch = _require_epoch(
        expected_epoch_second,
        "expected_epoch_second",
    )
    if epoch < 120 or epoch > MAX_EPOCH_SECOND - 120:
        _reject(
            "invalid_qualification_vector",
            "fixture epoch lacks room for deterministic validity bounds",
        )
    validation_policy = IntegrityValidationPolicyV1(
        decision_policy_id=_fixture_content_id(
            "decision-policy",
            namespaces,
        ),
        decision_time_policy_id=_fixture_content_id(
            "decision-time-policy",
            namespaces,
        ),
        checkpoint_time_policy_id=_fixture_content_id(
            "checkpoint-time-policy",
            namespaces,
        ),
        anchor_policy_id=_fixture_content_id(
            "anchor-policy",
            namespaces,
        ),
        required_revocation_namespaces=frozenset(namespaces),
        max_decision_uncertainty_seconds=4,
        max_checkpoint_uncertainty_seconds=4,
    )
    service_instance_id = "Etzio.adapter-qualification-fixture"
    environment_id = "fixture.networkless-control-plane"
    specs: list[tuple[str, str, str | None]] = [
        ("fixture.time.a", TRUSTED_TIME_ADAPTER_ROLE_V1, None),
        ("fixture.time.b", TRUSTED_TIME_ADAPTER_ROLE_V1, None),
    ]
    for namespace in namespaces:
        specs.extend(
            (
                (
                    f"fixture.revocation-metadata.{namespace}",
                    REVOCATION_METADATA_ADAPTER_ROLE_V1,
                    namespace,
                ),
                (
                    f"fixture.revocation-floor.{namespace}.a",
                    REVOCATION_FLOOR_ADAPTER_ROLE_V1,
                    namespace,
                ),
                (
                    f"fixture.revocation-floor.{namespace}.b",
                    REVOCATION_FLOOR_ADAPTER_ROLE_V1,
                    namespace,
                ),
            )
        )
    specs.sort(key=lambda value: (value[1], value[2] or "", value[0]))
    signers: dict[str, AdapterEvidenceSignerV1] = {}
    bindings: list[AdapterSourceBindingV1] = []
    trusted_keys: list[TrustedAdapterKeyV1] = []
    for source_id, role, namespace in specs:
        signer = AdapterEvidenceSignerV1.from_seed(
            source_id=source_id,
            principal_id=f"{source_id}.principal",
            role=role,
            seed=seed,
        )
        signers[source_id] = signer
        trusted_keys.append(signer.trusted_key)
        bindings.append(
            AdapterSourceBindingV1(
                source_id=source_id,
                role=role,
                namespace=namespace,
                key_id=signer.trusted_key.key_id,
                principal_id=signer.principal_id,
                provider_policy_id=_fixture_content_id(
                    "provider-policy",
                    {
                        "role": role,
                        "source_id": source_id,
                    },
                ),
                codec_profile=_ROLE_TO_CODEC_V1[role],
            )
        )
    trust_store = IntegrityAdapterTrustStoreV1.from_keys(trusted_keys)
    profile = IntegrityAdapterTrustProfileV1(
        adapter_profile=REPOSITORY_OWNED_ADAPTER_PROFILE_V1,
        contract_version=INTEGRITY_ADAPTER_CONTRACT_VERSION_V1,
        service_instance_id=service_instance_id,
        environment_id=environment_id,
        validation_policy=validation_policy,
        validation_policy_id=_validation_policy_id(validation_policy),
        trust_store=trust_store,
        trust_root_id=trust_store.root_id,
        source_bindings=tuple(bindings),
        max_revocation_staleness_seconds=30,
    )
    expected_states = tuple(
        ExpectedRevocationStateV1(
            namespace=namespace,
            prior_root_version=1,
            prior_version=1,
            prior_snapshot_id=_fixture_content_id(
                "prior-revocation-snapshot",
                namespace,
            ),
            expected_root_version=2,
            expected_version=2,
            expected_snapshot_id=_fixture_content_id(
                "current-revocation-snapshot",
                namespace,
            ),
            expected_valid_from=epoch - 60,
            expected_valid_until=epoch + 61,
            expected_published_at=epoch - 10,
        )
        for namespace in namespaces
    )
    vector = IntegrityAdapterQualificationVectorV1(
        service_instance_id=service_instance_id,
        environment_id=environment_id,
        mission_id=_fixture_content_id("mission", namespaces),
        authority_id=_fixture_content_id("authority", namespaces),
        target_id=_fixture_content_id("target", namespaces),
        event_digest=_fixture_content_id("event", namespaces),
        transition_intent_id=_fixture_content_id(
            "transition-intent",
            namespaces,
        ),
        request_nonce=_fixture_nonce(seed, "qualification-vector"),
        expected_epoch_second=epoch,
        expected_revocation=expected_states,
    )
    time_intervals = {
        "fixture.time.a": (epoch - 2, epoch + 1),
        "fixture.time.b": (epoch - 1, epoch + 2),
    }
    binding_by_source = {value.source_id: value for value in profile.source_bindings}
    time_adapters = tuple(
        RepositoryOwnedDeterministicTrustedTimeAdapterV1(
            profile=profile,
            binding=binding_by_source[source_id],
            signer=signers[source_id],
            time_lower_bound=time_intervals[source_id][0],
            time_upper_bound=time_intervals[source_id][1],
        )
        for source_id in sorted(time_intervals)
    )
    state_by_namespace = {value.namespace: value for value in expected_states}
    revocation_adapters = tuple(
        RepositoryOwnedDeterministicRevocationAdapterV1(
            profile=profile,
            binding=binding,
            signer=signers[binding.source_id],
            state=state_by_namespace[binding.namespace],  # type: ignore[index]
        )
        for binding in profile.source_bindings
        if binding.role
        in {
            REVOCATION_METADATA_ADAPTER_ROLE_V1,
            REVOCATION_FLOOR_ADAPTER_ROLE_V1,
        }
    )
    adapter_implementation_id = _fixture_content_id(
        "adapter-implementation",
        {
            "contract_version": INTEGRITY_ADAPTER_CONTRACT_VERSION_V1,
            "profile": REPOSITORY_OWNED_ADAPTER_PROFILE_V1,
        },
    )
    corpus_manifest_id = _qualification_manifest_id(
        adapter_implementation_id=adapter_implementation_id,
        profile=profile,
        vector=vector,
        time_adapters=time_adapters,
        revocation_adapters=revocation_adapters,
    )
    return RepositoryOwnedDeterministicAdapterFixtureV1(
        adapter_implementation_id=adapter_implementation_id,
        corpus_manifest_id=corpus_manifest_id,
        profile=profile,
        vector=vector,
        time_adapters=time_adapters,
        revocation_adapters=revocation_adapters,
    )


@dataclass(frozen=True, slots=True)
class IntegrityAdapterQualificationCaseV1:
    """One exact expected and observed deterministic harness disposition."""

    case_id: str
    expected_disposition: str
    observed_disposition: str
    reason_code: str
    result_id: str

    def __post_init__(self) -> None:
        _require_identity(self.case_id, "case_id")
        if self.expected_disposition not in {"success", "refused"}:
            _reject(
                "invalid_qualification_case",
                "qualification expected disposition is unsupported",
            )
        if self.observed_disposition not in {"success", "refused"}:
            _reject(
                "invalid_qualification_case",
                "qualification observed disposition is unsupported",
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
class IntegrityAdapterQualificationReportV1:
    """Sealed deterministic harness report; never lifecycle authority."""

    contract_version: int
    adapter_implementation_id: str
    profile_id: str
    vector_id: str
    corpus_manifest_id: str
    cases: tuple[IntegrityAdapterQualificationCaseV1, ...]
    overall_disposition: str
    _seal: object

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        _reject(
            "unauthenticated_result_construction",
            "qualification report construction is private",
        )

    def __post_init__(self) -> None:
        if type(self) is not IntegrityAdapterQualificationReportV1 or self._seal is not _QUALIFICATION_REPORT_SEAL:
            _reject(
                "unauthenticated_result_construction",
                "qualification report construction is private",
            )
        if self.contract_version != INTEGRITY_ADAPTER_CONTRACT_VERSION_V1:
            _reject(
                "invalid_qualification_report",
                "qualification report requires adapter contract V1",
            )
        for field in (
            "adapter_implementation_id",
            "profile_id",
            "vector_id",
            "corpus_manifest_id",
        ):
            _require_digest(getattr(self, field), field)
        if (
            type(self.cases) is not tuple
            or not self.cases
            or any(type(value) is not IntegrityAdapterQualificationCaseV1 for value in self.cases)
            or len({value.case_id for value in self.cases}) != len(self.cases)
        ):
            _reject(
                "invalid_qualification_report",
                "qualification report cases are incomplete or duplicated",
            )
        expected_overall = "passed" if all(value.passed for value in self.cases) else "failed"
        if self.overall_disposition != expected_overall:
            _reject(
                "invalid_qualification_report",
                "qualification report overall disposition is inconsistent",
            )

    @property
    def passed(self) -> bool:
        return self.overall_disposition == "passed"

    @property
    def report_id(self) -> str:
        return content_id("integrity_adapter_qualification_report", self.to_body())

    def to_body(self) -> dict[str, object]:
        return {
            "adapter_implementation_id": self.adapter_implementation_id,
            "cases": [value.to_body() for value in self.cases],
            "contract_version": self.contract_version,
            "corpus_manifest_id": self.corpus_manifest_id,
            "overall_disposition": self.overall_disposition,
            "profile_id": self.profile_id,
            "vector_id": self.vector_id,
        }


def _qualification_success(
    case_id: str,
    result_id: str,
) -> IntegrityAdapterQualificationCaseV1:
    return IntegrityAdapterQualificationCaseV1(
        case_id=case_id,
        expected_disposition="success",
        observed_disposition="success",
        reason_code="qualification_success",
        result_id=result_id,
    )


def qualify_repository_time_revocation_adapters_v1(
    fixture: RepositoryOwnedDeterministicAdapterFixtureV1,
) -> IntegrityAdapterQualificationReportV1:
    """Run the fixed networkless corpus with exact retry and replay proofs."""

    if type(fixture) is not RepositoryOwnedDeterministicAdapterFixtureV1:
        _reject(
            "invalid_qualification_fixture",
            "harness requires an exact repository-owned deterministic fixture",
        )
    fixture = RepositoryOwnedDeterministicAdapterFixtureV1(
        adapter_implementation_id=fixture.adapter_implementation_id,
        corpus_manifest_id=fixture.corpus_manifest_id,
        profile=fixture.profile,
        vector=fixture.vector,
        time_adapters=fixture.time_adapters,
        revocation_adapters=fixture.revocation_adapters,
    )
    profile = fixture.profile
    vector = fixture.vector
    namespaces = tuple(sorted(profile.validation_policy.required_revocation_namespaces))
    expected_manifest_id = _qualification_manifest_id(
        adapter_implementation_id=fixture.adapter_implementation_id,
        profile=profile,
        vector=vector,
        time_adapters=fixture.time_adapters,
        revocation_adapters=fixture.revocation_adapters,
    )
    if fixture.corpus_manifest_id != expected_manifest_id:
        _reject(
            "qualification_manifest_mismatch",
            "fixture corpus manifest differs from the fixed case roster",
        )
    time_adapter_map = {value.source_id: value for value in fixture.time_adapters}
    cases: list[IntegrityAdapterQualificationCaseV1] = []
    time_bundles: dict[str, QualifiedTimeBundleV1] = {}
    time_packages_by_purpose: dict[str, dict[str, SignedProviderEvidenceV1]] = {}
    for purpose in ("decision", "checkpoint"):
        requests = {
            source_id: TrustedTimeRequestV1.issue(
                profile=profile,
                source_id=source_id,
                purpose=purpose,
                mission_id=vector.mission_id,
                authority_id=vector.authority_id,
                target_id=vector.target_id,
                event_digest=vector.event_digest,
                transition_intent_id=vector.transition_intent_id,
                imprint_id=_fixture_content_id(
                    f"{purpose}-time-imprint",
                    vector.event_digest,
                ),
                request_nonce=vector.request_nonce,
            )
            for source_id in sorted(time_adapter_map)
        }
        packages: dict[str, SignedProviderEvidenceV1] = {}
        for source_id, request in requests.items():
            first = time_adapter_map[source_id].acquire(request)
            second = time_adapter_map[source_id].acquire(request)
            if first.to_canonical_bytes() != second.to_canonical_bytes():
                _reject(
                    "adapter_retry_nondeterministic",
                    "same-request trusted-time retry changed exact bytes",
                )
            packages[source_id] = first
        retry_result_id = content_id(
            "adapter_exact_retry_result",
            {
                "package_ids": [
                    "sha256:" + hashlib.sha256(packages[source_id].to_canonical_bytes()).hexdigest()
                    for source_id in sorted(packages)
                ],
                "purpose": purpose,
            },
        )
        cases.append(
            _qualification_success(
                f"{purpose}-time-exact-retry",
                retry_result_id,
            )
        )
        bundle = qualify_time_bundle_v1(
            profile=profile,
            requests=requests,
            signed_evidence=packages,
        )
        if not (bundle.time_lower_bound <= vector.expected_epoch_second <= bundle.time_upper_bound):
            _reject(
                "qualification_expected_time_missing",
                "qualified outer hull does not contain the fixture expectation",
            )
        cases.append(
            _qualification_success(
                f"{purpose}-time-qualification",
                bundle.bundle_id,
            )
        )
        time_bundles[purpose] = bundle
        time_packages_by_purpose[purpose] = packages

    first_source = sorted(time_adapter_map)[0]
    replay_request = TrustedTimeRequestV1.issue(
        profile=profile,
        source_id=first_source,
        purpose="decision",
        mission_id=vector.mission_id,
        authority_id=vector.authority_id,
        target_id=vector.target_id,
        event_digest=vector.event_digest,
        transition_intent_id=vector.transition_intent_id,
        imprint_id=time_bundles["decision"].imprint_id,
        request_nonce=_fixture_nonce(
            bytes.fromhex(vector.request_nonce),
            "cross-request-replay",
        ),
    )
    replay_reason = ""
    try:
        authenticate_provider_evidence_v1(
            profile=profile,
            request=replay_request,
            signed_evidence=time_packages_by_purpose["decision"][first_source],
        )
    except IntegrityAdapterError as exc:
        replay_reason = exc.reason_code
    if replay_reason != "provider_request_mismatch":
        _reject(
            "qualification_replay_case_failed",
            "cross-request replay did not reach the exact request-binding refusal",
        )
    cases.append(
        IntegrityAdapterQualificationCaseV1(
            case_id="cross-request-replay-refused",
            expected_disposition="refused",
            observed_disposition="refused",
            reason_code=replay_reason,
            result_id=content_id(
                "adapter_expected_refusal",
                {
                    "case_id": "cross-request-replay-refused",
                    "reason_code": replay_reason,
                },
            ),
        )
    )

    revocation_adapter_map = {value.source_id: value for value in fixture.revocation_adapters}
    revocation_bundles: dict[str, QualifiedRevocationBundleV1] = {}
    decision_time = time_bundles["decision"]
    for state in vector.expected_revocation:
        namespace_bindings = tuple(value for value in profile.source_bindings if value.namespace == state.namespace)
        request_nonce = _fixture_nonce(
            bytes.fromhex(vector.request_nonce),
            f"revocation-{state.namespace}",
        )
        requests = {
            binding.source_id: RevocationRequestV1.issue(
                profile=profile,
                source_id=binding.source_id,
                evidence_role=binding.role,
                namespace=state.namespace,
                time_bundle=decision_time,
                prior_root_version=state.prior_root_version,
                prior_version=state.prior_version,
                prior_snapshot_id=state.prior_snapshot_id,
                request_nonce=request_nonce,
            )
            for binding in namespace_bindings
        }
        packages: dict[str, SignedProviderEvidenceV1] = {}
        for source_id, request in requests.items():
            adapter = revocation_adapter_map[source_id]
            first = adapter.acquire(request)
            second = adapter.acquire(request)
            if first.to_canonical_bytes() != second.to_canonical_bytes():
                _reject(
                    "adapter_retry_nondeterministic",
                    "same-request revocation retry changed exact bytes",
                )
            packages[source_id] = first
        cases.append(
            _qualification_success(
                f"revocation-{state.namespace}-exact-retry",
                content_id(
                    "adapter_exact_retry_result",
                    {
                        "namespace": state.namespace,
                        "package_ids": [
                            "sha256:" + hashlib.sha256(packages[source_id].to_canonical_bytes()).hexdigest()
                            for source_id in sorted(packages)
                        ],
                    },
                ),
            )
        )
        bundle = qualify_revocation_bundle_v1(
            profile=profile,
            namespace=state.namespace,
            time_bundle=decision_time,
            requests=requests,
            signed_evidence=packages,
        )
        if (
            bundle.root_version != state.expected_root_version
            or bundle.version != state.expected_version
            or bundle.snapshot_id != state.expected_snapshot_id
            or bundle.valid_from != state.expected_valid_from
            or bundle.valid_until != state.expected_valid_until
            or bundle.published_at != state.expected_published_at
        ):
            _reject(
                "qualification_expected_revocation_mismatch",
                "qualified revocation differs from the fixture expectation",
            )
        cases.append(
            _qualification_success(
                f"revocation-{state.namespace}-qualification",
                bundle.bundle_id,
            )
        )
        revocation_bundles[state.namespace] = bundle

    mapped = map_qualified_integrity_inputs_v1(
        profile=profile,
        time_bundle=decision_time,
        revocation_bundles=revocation_bundles,
    )
    cases.append(
        _qualification_success(
            "provider-neutral-mapping",
            mapped.mapping_id,
        )
    )
    if tuple(value.case_id for value in cases) != _qualification_case_ids(namespaces):
        _reject(
            "qualification_case_coverage_mismatch",
            "harness case outcomes differ from the fixed manifest roster",
        )
    return _construct_sealed_result(
        IntegrityAdapterQualificationReportV1,
        seal=_QUALIFICATION_REPORT_SEAL,
        values={
            "contract_version": INTEGRITY_ADAPTER_CONTRACT_VERSION_V1,
            "adapter_implementation_id": (fixture.adapter_implementation_id),
            "profile_id": profile.profile_id,
            "vector_id": vector.vector_id,
            "corpus_manifest_id": fixture.corpus_manifest_id,
            "cases": tuple(cases),
            "overall_disposition": "passed",
        },
    )


__all__ = (
    "INTEGRITY_ADAPTER_CONTRACT_VERSION_V1",
    "INTEGRITY_ADAPTER_ROLES_V1",
    "REPOSITORY_OWNED_ADAPTER_PROFILE_V1",
    "REVOCATION_FLOOR_ADAPTER_ROLE_V1",
    "REVOCATION_METADATA_ADAPTER_ROLE_V1",
    "TRUSTED_TIME_ADAPTER_ROLE_V1",
    "AdapterEvidenceSignerV1",
    "AdapterSourceBindingV1",
    "AuthenticatedProviderEvidencePackageV1",
    "ExpectedRevocationStateV1",
    "IntegrityAdapterError",
    "IntegrityAdapterQualificationCaseV1",
    "IntegrityAdapterQualificationReportV1",
    "IntegrityAdapterQualificationVectorV1",
    "IntegrityAdapterTrustProfileV1",
    "IntegrityAdapterTrustStoreV1",
    "ProviderEvidenceStatementV1",
    "QualifiedIntegrityInputsV1",
    "QualifiedRevocationBundleV1",
    "QualifiedTimeBundleV1",
    "RepositoryOwnedDeterministicAdapterFixtureV1",
    "RepositoryOwnedDeterministicRevocationAdapterV1",
    "RepositoryOwnedDeterministicTrustedTimeAdapterV1",
    "RevocationAdapterV1",
    "RevocationRequestV1",
    "SignedProviderEvidenceV1",
    "TrustedAdapterKeyV1",
    "TrustedTimeAdapterV1",
    "TrustedTimeRequestV1",
    "authenticate_provider_evidence_v1",
    "create_repository_owned_adapter_fixture_v1",
    "map_qualified_integrity_inputs_v1",
    "qualify_repository_time_revocation_adapters_v1",
    "qualify_revocation_bundle_v1",
    "qualify_time_bundle_v1",
    "reauthenticate_revocation_bundle_v1",
    "reauthenticate_time_bundle_v1",
)
