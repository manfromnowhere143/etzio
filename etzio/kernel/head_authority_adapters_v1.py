"""Networkless V1 qualification contract for anchor, catalog, and monitor adapters.

This module extends the ADR-0012 boundary to the two remaining ADR-0008 integrity evidence
kinds.  It authenticates repository-owned signed fixture packages under a pinned source
roster, recomputes RFC 9162 inclusion and consistency proofs, requires unanimous monitor
agreement on one catalog head, and maps the exact signed bytes to the provider-evidence and
external-head-floor types already understood by the integrity contract.

The qualification result is not lifecycle authority.  It does not establish truthful UTC,
real publication time, independent administration, external durability, survival of local
loss, real-world non-equivocation, RFC 9162 conformance, SCITT conformance, or a finding.
No adapter in this module uses the network, credentials, an ambient clock, or a third-party
service.
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
    HEAD_ANCHOR_RECEIPT_EVIDENCE_KIND,
    MAX_EPOCH_SECOND,
    EvidenceReferenceV1,
    HeadCheckpointFloorV1,
    IntegrityValidationPolicyV1,
    integrity_key_id,
)
from etzio.kernel.integrity_adapters_v1 import (
    IntegrityAdapterTrustProfileV1,
    QualifiedTimeBundleV1,
    RepositoryOwnedDeterministicAdapterFixtureV1,
    TrustedTimeRequestV1,
    create_repository_owned_adapter_fixture_v1,
    qualify_time_bundle_v1,
    reauthenticate_time_bundle_v1,
)
from etzio.kernel.integrity_transition import ProviderEvidenceBlobV1
from etzio.protocol import (
    ProtocolError,
    canonical_dumps,
    content_id,
    strict_loads,
)

HEAD_AUTHORITY_CONTRACT_VERSION_V1: Final = 1
REPOSITORY_OWNED_HEAD_AUTHORITY_PROFILE_V1: Final = "repository_owned_networkless_head_authority_v1"

HEAD_ANCHOR_ADAPTER_ROLE_V1: Final = "head_anchor"
HEAD_CATALOG_ADAPTER_ROLE_V1: Final = "head_catalog"
HEAD_MONITOR_ADAPTER_ROLE_V1: Final = "head_monitor"
HEAD_AUTHORITY_ADAPTER_ROLES_V1: Final = frozenset(
    {
        HEAD_ANCHOR_ADAPTER_ROLE_V1,
        HEAD_CATALOG_ADAPTER_ROLE_V1,
        HEAD_MONITOR_ADAPTER_ROLE_V1,
    }
)

_ROLE_TO_EVIDENCE_KIND_V1: Final = MappingProxyType(
    {
        HEAD_ANCHOR_ADAPTER_ROLE_V1: HEAD_ANCHOR_RECEIPT_EVIDENCE_KIND,
        HEAD_CATALOG_ADAPTER_ROLE_V1: EXTERNAL_FLOOR_EVIDENCE_KIND,
        HEAD_MONITOR_ADAPTER_ROLE_V1: EXTERNAL_FLOOR_EVIDENCE_KIND,
    }
)
_ROLE_TO_CODEC_V1: Final = MappingProxyType(
    {
        HEAD_ANCHOR_ADAPTER_ROLE_V1: "etzio.fixture.signed-anchor-receipt.v1",
        HEAD_CATALOG_ADAPTER_ROLE_V1: "etzio.fixture.signed-head-catalog.v1",
        HEAD_MONITOR_ADAPTER_ROLE_V1: "etzio.fixture.signed-head-monitor.v1",
    }
)
_ROLE_SIGNATURE_DOMAINS_V1: Final = MappingProxyType(
    {
        HEAD_ANCHOR_ADAPTER_ROLE_V1: (b"etzio.integrity-adapter.head-anchor.signature.v1\x00"),
        HEAD_CATALOG_ADAPTER_ROLE_V1: (b"etzio.integrity-adapter.head-catalog.signature.v1\x00"),
        HEAD_MONITOR_ADAPTER_ROLE_V1: (b"etzio.integrity-adapter.head-monitor.signature.v1\x00"),
    }
)

_MERKLE_LEAF_PREFIX: Final = b"\x00"
_MERKLE_NODE_PREFIX: Final = b"\x01"

MAX_HEAD_KEYS_V1: Final = 64
MAX_HEAD_SOURCES_V1: Final = 32
MAX_HEAD_PROOF_NODES_V1: Final = 64
MAX_HEAD_TREE_SIZE_V1: Final = 1 << 48
MAX_HEAD_FIXTURE_LEAVES_V1: Final = 256
MAX_HEAD_PACKAGE_BYTES_V1: Final = 1 << 20
MAX_HEAD_TOTAL_EVIDENCE_BYTES_V1: Final = 16 << 20
MAX_HEAD_SEED_BYTES_V1: Final = 1024

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
        "log_origin",
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
        "max_head_staleness_seconds",
        "service_instance_id",
        "source_bindings",
        "trust_root",
        "trust_root_id",
        "validation_policy",
        "validation_policy_id",
    }
)
_ANCHOR_LEAF_FIELDS: Final = frozenset(
    {
        "anchor_policy_id",
        "anchor_statement_id",
        "contract_version",
        "environment_id",
        "instance_sequence",
        "mission_id",
        "service_instance_id",
    }
)
_ANCHOR_REQUEST_FIELDS: Final = frozenset(
    {
        "anchor_leaf_hash",
        "anchor_policy_id",
        "anchor_statement_id",
        "authority_id",
        "contract_version",
        "environment_id",
        "event_digest",
        "instance_sequence",
        "mission_id",
        "prior_tree_size",
        "profile_id",
        "request_id",
        "request_nonce",
        "service_instance_id",
        "source_id",
        "target_id",
        "time_bundle_id",
        "time_evidence",
        "time_lower_bound",
        "time_upper_bound",
        "transition_intent_id",
        "trust_root_id",
    }
)
_CATALOG_REQUEST_FIELDS: Final = frozenset(
    {
        "authority_id",
        "contract_version",
        "environment_id",
        "event_digest",
        "evidence_role",
        "mission_id",
        "prior_checkpoint_id",
        "prior_instance_sequence",
        "prior_log_root_hash",
        "prior_mission_checkpoint_id",
        "prior_mission_event_seq",
        "prior_tree_size",
        "profile_id",
        "request_id",
        "request_nonce",
        "service_instance_id",
        "source_id",
        "target_id",
        "time_bundle_id",
        "time_evidence",
        "time_lower_bound",
        "time_upper_bound",
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
_ANCHOR_CLAIM_FIELDS: Final = frozenset(
    {
        "anchor_statement_id",
        "inclusion_proof",
        "leaf_hash",
        "leaf_index",
        "log_origin",
        "log_root_hash",
        "registered_at",
        "tree_size",
    }
)
_CATALOG_CLAIM_FIELDS: Final = frozenset(
    {
        "checkpoint_attestation_id",
        "checkpoint_id",
        "checkpoint_principal_id",
        "checkpoint_trust_snapshot_id",
        "consistency_proof",
        "instance_sequence",
        "log_origin",
        "log_root_hash",
        "mission_checkpoint_attestation_id",
        "mission_checkpoint_id",
        "mission_checkpoint_principal_id",
        "mission_checkpoint_trust_snapshot_id",
        "mission_event_seq",
        "mission_id",
        "published_at",
        "tree_size",
    }
)
_MONITOR_CLAIM_FIELDS: Final = frozenset(
    {
        "log_origin",
        "log_root_hash",
        "observed_at",
        "tree_size",
        "witnessed_source_id",
    }
)
_EXPECTED_HEAD_FIELDS: Final = frozenset(
    {
        "checkpoint_attestation_id",
        "checkpoint_id",
        "checkpoint_principal_id",
        "checkpoint_trust_snapshot_id",
        "instance_sequence",
        "mission_checkpoint_attestation_id",
        "mission_checkpoint_id",
        "mission_checkpoint_principal_id",
        "mission_checkpoint_trust_snapshot_id",
        "mission_event_seq",
        "prior_checkpoint_id",
        "prior_instance_sequence",
        "prior_mission_checkpoint_id",
        "prior_mission_event_seq",
    }
)
_QUALIFICATION_VECTOR_FIELDS: Final = frozenset(
    {
        "anchor_policy_id",
        "anchor_statement_id",
        "authority_id",
        "environment_id",
        "event_digest",
        "expected_epoch_second",
        "expected_head",
        "mission_id",
        "request_nonce",
        "service_instance_id",
        "target_id",
        "transition_intent_id",
    }
)

_AUTHENTICATED_PACKAGE_SEAL: Final = object()
_QUALIFIED_ANCHOR_SEAL: Final = object()
_QUALIFIED_CATALOG_SEAL: Final = object()
_QUALIFIED_INPUTS_SEAL: Final = object()
_QUALIFICATION_REPORT_SEAL: Final = object()

_SealedResultT = TypeVar("_SealedResultT")


class HeadAuthorityAdapterError(ValueError):
    """One deterministic head-authority contract or qualification refusal."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


def _reject(reason_code: str, message: str) -> None:
    raise HeadAuthorityAdapterError(reason_code, message)


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
        _reject("invalid_head_identity", f"{field} must be one bounded ASCII identity")
    return value  # type: ignore[return-value]


def _require_digest(value: object, field: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        _reject("invalid_head_digest", f"{field} must be one sha256 content digest")
    return value  # type: ignore[return-value]


def _require_key_id(value: object, field: str) -> str:
    if type(value) is not str or _KEY_ID.fullmatch(value) is None:
        _reject("invalid_head_key_id", f"{field} must be one ed25519 key identity")
    return value  # type: ignore[return-value]


def _require_nonce(value: object, field: str = "request_nonce") -> str:
    if type(value) is not str or _NONCE_256.fullmatch(value) is None:
        _reject("invalid_head_nonce", f"{field} must be 256 lowercase hexadecimal bits")
    return value  # type: ignore[return-value]


def _require_nonnegative_int(value: object, field: str) -> int:
    if type(value) is not int or value < 0 or value > MAX_EPOCH_SECOND:
        _reject("invalid_head_integer", f"{field} must be a bounded nonnegative integer")
    return value  # type: ignore[return-value]


def _require_positive_int(value: object, field: str) -> int:
    if type(value) is not int or value <= 0 or value > MAX_EPOCH_SECOND:
        _reject("invalid_head_integer", f"{field} must be a bounded positive integer")
    return value  # type: ignore[return-value]


def _require_epoch(value: object, field: str) -> int:
    if type(value) is not int or value < 0 or value > MAX_EPOCH_SECOND:
        _reject("invalid_head_integer", f"{field} must be a bounded epoch second")
    return value  # type: ignore[return-value]


def _require_tree_size(value: object, field: str) -> int:
    if type(value) is not int or value <= 0 or value > MAX_HEAD_TREE_SIZE_V1:
        _reject("invalid_head_tree_size", f"{field} must be a bounded positive tree size")
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
        raise HeadAuthorityAdapterError(
            "invalid_head_record",
            "head-authority record cannot be represented as canonical JSON",
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
        raise HeadAuthorityAdapterError(
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
        _reject("invalid_head_base64", f"{field} must be one Base64 string")
    try:
        decoded = base64.b64decode(value, validate=True)  # type: ignore[arg-type]
    except (binascii.Error, ValueError) as exc:
        raise HeadAuthorityAdapterError(
            "invalid_head_base64",
            f"{field} is not strict Base64",
        ) from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        _reject("invalid_head_base64", f"{field} is not canonical Base64")
    if not decoded or len(decoded) > maximum:
        _reject("invalid_head_base64", f"{field} must decode to bounded nonempty bytes")
    return decoded


def _validation_policy_id(policy: IntegrityValidationPolicyV1) -> str:
    if type(policy) is not IntegrityValidationPolicyV1:
        _reject(
            "invalid_head_validation_policy",
            "head-authority profile requires an exact IntegrityValidationPolicyV1",
        )
    return content_id("integrity_validation_policy", policy.to_body())


def _snapshot_validation_policy(policy: object) -> IntegrityValidationPolicyV1:
    if type(policy) is not IntegrityValidationPolicyV1:
        _reject(
            "invalid_head_validation_policy",
            "head-authority profile requires an exact IntegrityValidationPolicyV1",
        )
    return IntegrityValidationPolicyV1.from_body(policy.to_body())  # type: ignore[union-attr]


def _fixture_content_id(label: str, value: object) -> str:
    return content_id(
        "head_authority_repository_fixture",
        {"label": label, "value": value},
    )


def _fixture_nonce(seed: bytes, label: str) -> str:
    return hashlib.sha256(
        b"etzio.head-authority.fixture-nonce.v1\x00" + label.encode("ascii") + b"\x00" + seed
    ).hexdigest()


# ---------------------------------------------------------------------------
# RFC 9162 Merkle hashing and proof verification
# ---------------------------------------------------------------------------


def _digest_to_bytes(value: object, field: str) -> bytes:
    return bytes.fromhex(_require_digest(value, field)[len("sha256:") :])


def _bytes_to_digest(value: bytes) -> str:
    return "sha256:" + value.hex()


def merkle_leaf_hash_v1(data: bytes) -> bytes:
    """Return the RFC 9162 leaf hash of exact record bytes."""

    if type(data) is not bytes or not data:
        _reject("invalid_head_record", "a Merkle leaf requires nonempty immutable bytes")
    return hashlib.sha256(_MERKLE_LEAF_PREFIX + data).digest()


def _merkle_node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_MERKLE_NODE_PREFIX + left + right).digest()


def _largest_power_of_two_below(size: int) -> int:
    return 1 << (size.bit_length() - 1) if size & (size - 1) else size >> 1


def merkle_root_v1(leaf_hashes: tuple[bytes, ...]) -> bytes:
    """Return the RFC 9162 Merkle tree head of an ordered leaf-hash tuple."""

    if type(leaf_hashes) is not tuple:
        _reject("invalid_head_record", "a Merkle tree requires an ordered leaf tuple")
    if not leaf_hashes:
        return hashlib.sha256(b"").digest()
    if len(leaf_hashes) == 1:
        return leaf_hashes[0]
    split = _largest_power_of_two_below(len(leaf_hashes))
    return _merkle_node_hash(
        merkle_root_v1(leaf_hashes[:split]),
        merkle_root_v1(leaf_hashes[split:]),
    )


def merkle_inclusion_proof_v1(
    leaf_hashes: tuple[bytes, ...],
    leaf_index: int,
) -> tuple[bytes, ...]:
    """Return the RFC 9162 audit path for one leaf of an ordered leaf tuple."""

    size = len(leaf_hashes)
    if type(leaf_index) is not int or leaf_index < 0 or leaf_index >= size:
        _reject("invalid_head_proof", "inclusion proof requires an in-range leaf index")
    if size == 1:
        return ()
    split = _largest_power_of_two_below(size)
    if leaf_index < split:
        return (
            *merkle_inclusion_proof_v1(leaf_hashes[:split], leaf_index),
            merkle_root_v1(leaf_hashes[split:]),
        )
    return (
        *merkle_inclusion_proof_v1(leaf_hashes[split:], leaf_index - split),
        merkle_root_v1(leaf_hashes[:split]),
    )


def _merkle_subproof(
    leaf_hashes: tuple[bytes, ...],
    first_size: int,
    complete: bool,
) -> tuple[bytes, ...]:
    size = len(leaf_hashes)
    if first_size == size:
        return () if complete else (merkle_root_v1(leaf_hashes),)
    split = _largest_power_of_two_below(size)
    if first_size <= split:
        return (
            *_merkle_subproof(leaf_hashes[:split], first_size, complete),
            merkle_root_v1(leaf_hashes[split:]),
        )
    return (
        *_merkle_subproof(leaf_hashes[split:], first_size - split, False),
        merkle_root_v1(leaf_hashes[:split]),
    )


def merkle_consistency_proof_v1(
    leaf_hashes: tuple[bytes, ...],
    first_size: int,
) -> tuple[bytes, ...]:
    """Return the RFC 9162 consistency proof between a prefix and the full tree."""

    size = len(leaf_hashes)
    if type(first_size) is not int or first_size <= 0 or first_size > size:
        _reject(
            "invalid_head_proof",
            "consistency proof requires a positive prefix within the tree",
        )
    return _merkle_subproof(leaf_hashes, first_size, True)


def _validated_proof(value: object, field: str) -> tuple[bytes, ...]:
    if type(value) is not list or len(value) > MAX_HEAD_PROOF_NODES_V1:
        _reject("invalid_head_proof", f"{field} must be a bounded ordered proof list")
    return tuple(_digest_to_bytes(node, f"{field}_node") for node in value)  # type: ignore[union-attr]


def verify_merkle_inclusion_v1(
    *,
    leaf_hash: bytes,
    leaf_index: int,
    tree_size: int,
    proof: tuple[bytes, ...],
    root_hash: bytes,
) -> None:
    """Verify one RFC 9162 section 2.1.3.2 inclusion proof or refuse.

    The recomputed root must equal ``root_hash`` exactly.  A proof that is shorter or
    longer than the ``(leaf_index, tree_size)`` geometry requires is refused, so a caller
    cannot pad or truncate a proof into agreement.
    """

    if type(leaf_hash) is not bytes or len(leaf_hash) != 32:
        _reject("invalid_head_proof", "inclusion proof requires one 32-byte leaf hash")
    if type(root_hash) is not bytes or len(root_hash) != 32:
        _reject("invalid_head_proof", "inclusion proof requires one 32-byte root hash")
    if type(tree_size) is not int or tree_size <= 0:
        _reject("invalid_head_proof", "inclusion proof requires a positive tree size")
    if type(leaf_index) is not int or leaf_index < 0 or leaf_index >= tree_size:
        _reject(
            "head_inclusion_proof_invalid",
            "inclusion proof leaf index is outside the claimed tree",
        )
    if type(proof) is not tuple or len(proof) > MAX_HEAD_PROOF_NODES_V1:
        _reject("invalid_head_proof", "inclusion proof must be a bounded ordered tuple")

    node_index = leaf_index
    last_index = tree_size - 1
    computed = leaf_hash
    for node in proof:
        if type(node) is not bytes or len(node) != 32:
            _reject("invalid_head_proof", "inclusion proof nodes must be 32-byte hashes")
        if last_index == 0:
            _reject(
                "head_inclusion_proof_invalid",
                "inclusion proof is longer than the claimed tree geometry allows",
            )
        if node_index & 1 or node_index == last_index:
            computed = _merkle_node_hash(node, computed)
            while node_index & 1 == 0 and node_index != 0:
                node_index >>= 1
                last_index >>= 1
        else:
            computed = _merkle_node_hash(computed, node)
        node_index >>= 1
        last_index >>= 1
    if last_index != 0:
        _reject(
            "head_inclusion_proof_invalid",
            "inclusion proof is shorter than the claimed tree geometry requires",
        )
    if computed != root_hash:
        _reject(
            "head_inclusion_proof_invalid",
            "inclusion proof does not recompute the claimed log root",
        )


def verify_merkle_consistency_v1(
    *,
    first_size: int,
    first_root: bytes,
    second_size: int,
    second_root: bytes,
    proof: tuple[bytes, ...],
) -> None:
    """Verify one RFC 9162 section 2.1.4.2 consistency proof or refuse.

    Both the retained predecessor root and the claimed successor root must be recomputed
    from the same proof.  Equal sizes require an empty proof and identical roots, so a
    same-size root change is a refusal rather than an update.
    """

    if type(first_root) is not bytes or len(first_root) != 32:
        _reject("invalid_head_proof", "consistency proof requires one 32-byte first root")
    if type(second_root) is not bytes or len(second_root) != 32:
        _reject("invalid_head_proof", "consistency proof requires one 32-byte second root")
    if type(first_size) is not int or first_size <= 0:
        _reject(
            "invalid_head_proof",
            "consistency proof requires a positive retained tree size",
        )
    if type(second_size) is not int or second_size <= 0:
        _reject("invalid_head_proof", "consistency proof requires a positive tree size")
    if type(proof) is not tuple or len(proof) > MAX_HEAD_PROOF_NODES_V1:
        _reject("invalid_head_proof", "consistency proof must be a bounded ordered tuple")
    if first_size > second_size:
        _reject(
            "head_catalog_tree_rollback",
            "catalog tree size regressed below the retained predecessor",
        )
    if first_size == second_size:
        if proof:
            _reject(
                "head_consistency_proof_invalid",
                "an unchanged tree size cannot carry a consistency proof",
            )
        if first_root != second_root:
            _reject(
                "head_catalog_equivocation",
                "an unchanged tree size cannot change its log root",
            )
        return
    if not proof:
        _reject(
            "head_consistency_proof_invalid",
            "a grown tree requires a consistency proof from the retained root",
        )

    shift = (first_size & -first_size).bit_length() - 1
    node_index = first_size >> shift
    last_index = (second_size - 1) >> shift
    if node_index == 1:
        computed_first = first_root
        remaining = proof
    else:
        computed_first = proof[0]
        remaining = proof[1:]
        if type(computed_first) is not bytes or len(computed_first) != 32:
            _reject("invalid_head_proof", "consistency proof nodes must be 32-byte hashes")
    computed_second = computed_first
    node_index -= 1

    for node in remaining:
        if type(node) is not bytes or len(node) != 32:
            _reject("invalid_head_proof", "consistency proof nodes must be 32-byte hashes")
        if last_index == 0:
            _reject(
                "head_consistency_proof_invalid",
                "consistency proof is longer than the claimed tree geometry allows",
            )
        if node_index & 1 or node_index == last_index:
            computed_first = _merkle_node_hash(node, computed_first)
            computed_second = _merkle_node_hash(node, computed_second)
            while node_index & 1 == 0 and node_index != 0:
                node_index >>= 1
                last_index >>= 1
        else:
            computed_second = _merkle_node_hash(computed_second, node)
        node_index >>= 1
        last_index >>= 1

    if last_index != 0:
        _reject(
            "head_consistency_proof_invalid",
            "consistency proof is shorter than the claimed tree geometry requires",
        )
    if computed_first != first_root:
        _reject(
            "head_consistency_proof_invalid",
            "consistency proof does not recompute the retained predecessor root",
        )
    if computed_second != second_root:
        _reject(
            "head_consistency_proof_invalid",
            "consistency proof does not recompute the claimed log root",
        )


# ---------------------------------------------------------------------------
# Trust profile
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TrustedHeadAuthorityKeyV1:
    """One admitted fixture key bound to its exact source, principal, and role."""

    source_id: str
    principal_id: str
    role: str
    public_key_bytes: bytes

    def __post_init__(self) -> None:
        _require_identity(self.source_id, "source_id")
        _require_identity(self.principal_id, "principal_id")
        if type(self.role) is not str or self.role not in HEAD_AUTHORITY_ADAPTER_ROLES_V1:
            _reject("invalid_head_role", "trusted key has an unsupported adapter role")
        if type(self.public_key_bytes) is not bytes or not is_valid_ed25519_public_key(
            self.public_key_bytes
        ):
            _reject(
                "invalid_head_public_key",
                "trusted key requires a valid prime-subgroup Ed25519 public key",
            )
        object.__setattr__(self, "public_key_bytes", bytes(self.public_key_bytes))

    @property
    def key_id(self) -> str:
        return integrity_key_id(self.public_key_bytes)

    def to_body(self) -> dict[str, object]:
        return {
            "key_id": self.key_id,
            "principal_id": self.principal_id,
            "public_key_b64": base64.b64encode(self.public_key_bytes).decode("ascii"),
            "role": self.role,
            "source_id": self.source_id,
        }

    @classmethod
    def from_body(cls, value: object) -> TrustedHeadAuthorityKeyV1:
        body = _require_exact_dict(value, _TRUST_KEY_FIELDS, "head_trusted_key")
        key = cls(
            source_id=body["source_id"],  # type: ignore[arg-type]
            principal_id=body["principal_id"],  # type: ignore[arg-type]
            role=body["role"],  # type: ignore[arg-type]
            public_key_bytes=_decode_b64(body["public_key_b64"], "public_key_b64", maximum=32),
        )
        if key.key_id != body["key_id"]:
            _reject(
                "invalid_head_key_id",
                "trusted key identity does not match its exact public key",
            )
        return key


@dataclass(frozen=True, slots=True)
class HeadAuthorityTrustStoreV1:
    """One copied bounded fixture trust root with a content-derived identity."""

    keys: Mapping[str, TrustedHeadAuthorityKeyV1]
    revoked_key_ids: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not isinstance(self.keys, Mapping) or not self.keys:
            _reject("invalid_head_trust_root", "trust root requires a nonempty key mapping")
        if len(self.keys) > MAX_HEAD_KEYS_V1:
            _reject("invalid_head_trust_root", "trust root exceeds its key ceiling")
        copied: dict[str, TrustedHeadAuthorityKeyV1] = {}
        for key_id, key in sorted(self.keys.items()):
            _require_key_id(key_id, "key_id")
            if type(key) is not TrustedHeadAuthorityKeyV1 or key.key_id != key_id:
                _reject(
                    "invalid_head_trust_root",
                    "trust root requires exact keys stored under their own identity",
                )
            copied[key_id] = key
        revoked = frozenset(self.revoked_key_ids)
        if len(revoked) > MAX_HEAD_KEYS_V1:
            _reject("invalid_head_trust_root", "trust root exceeds its revocation ceiling")
        for key_id in sorted(revoked):
            _require_key_id(key_id, "revoked_key_id")
        object.__setattr__(self, "keys", MappingProxyType(copied))
        object.__setattr__(self, "revoked_key_ids", revoked)

    @classmethod
    def from_keys(
        cls,
        keys: Iterable[TrustedHeadAuthorityKeyV1],
        *,
        revoked_key_ids: Iterable[str] = (),
    ) -> HeadAuthorityTrustStoreV1:
        mapping: dict[str, TrustedHeadAuthorityKeyV1] = {}
        for key in keys:
            if type(key) is not TrustedHeadAuthorityKeyV1:
                _reject("invalid_head_trust_root", "trust root requires exact trusted keys")
            if key.key_id in mapping:
                _reject("invalid_head_trust_root", "trust root cannot admit a duplicate key")
            mapping[key.key_id] = key
        return cls(keys=mapping, revoked_key_ids=frozenset(revoked_key_ids))

    @property
    def root_id(self) -> str:
        return content_id("head_authority_trust_root", self.to_body())

    def to_body(self) -> dict[str, object]:
        return {
            "keys": [self.keys[key_id].to_body() for key_id in sorted(self.keys)],
            "revoked_key_ids": sorted(self.revoked_key_ids),
        }

    @classmethod
    def from_body(cls, value: object) -> HeadAuthorityTrustStoreV1:
        body = _require_exact_dict(value, _TRUST_ROOT_FIELDS, "head_trust_root")
        keys = body["keys"]
        revoked = body["revoked_key_ids"]
        if type(keys) is not list or type(revoked) is not list:
            _reject("invalid_head_trust_root", "trust root fields must be ordered lists")
        return cls.from_keys(
            (TrustedHeadAuthorityKeyV1.from_body(entry) for entry in keys),
            revoked_key_ids=revoked,  # type: ignore[arg-type]
        )


@dataclass(frozen=True, slots=True)
class HeadAuthoritySourceBindingV1:
    """One pinned source, role, log origin, key, principal, policy, and codec."""

    source_id: str
    role: str
    log_origin: str
    key_id: str
    principal_id: str
    provider_policy_id: str
    codec_profile: str

    def __post_init__(self) -> None:
        _require_identity(self.source_id, "source_id")
        _require_identity(self.log_origin, "log_origin")
        _require_identity(self.principal_id, "principal_id")
        _require_key_id(self.key_id, "key_id")
        _require_digest(self.provider_policy_id, "provider_policy_id")
        if type(self.role) is not str or self.role not in HEAD_AUTHORITY_ADAPTER_ROLES_V1:
            _reject("invalid_head_role", "source binding has an unsupported adapter role")
        if self.codec_profile != _ROLE_TO_CODEC_V1[self.role]:
            _reject(
                "invalid_head_codec_profile",
                "source binding codec does not match its exact role",
            )

    @property
    def evidence_kind(self) -> str:
        return _ROLE_TO_EVIDENCE_KIND_V1[self.role]

    def to_body(self) -> dict[str, object]:
        return {
            "codec_profile": self.codec_profile,
            "key_id": self.key_id,
            "log_origin": self.log_origin,
            "principal_id": self.principal_id,
            "provider_policy_id": self.provider_policy_id,
            "role": self.role,
            "source_id": self.source_id,
        }

    @classmethod
    def from_body(cls, value: object) -> HeadAuthoritySourceBindingV1:
        body = _require_exact_dict(value, _SOURCE_BINDING_FIELDS, "head_source_binding")
        return cls(
            source_id=body["source_id"],  # type: ignore[arg-type]
            role=body["role"],  # type: ignore[arg-type]
            log_origin=body["log_origin"],  # type: ignore[arg-type]
            key_id=body["key_id"],  # type: ignore[arg-type]
            principal_id=body["principal_id"],  # type: ignore[arg-type]
            provider_policy_id=body["provider_policy_id"],  # type: ignore[arg-type]
            codec_profile=body["codec_profile"],  # type: ignore[arg-type]
        )


@dataclass(frozen=True, slots=True)
class HeadAuthorityTrustProfileV1:
    """One copied profile binding the complete head-authority acceptance surface."""

    adapter_profile: str
    contract_version: int
    service_instance_id: str
    environment_id: str
    validation_policy: IntegrityValidationPolicyV1
    validation_policy_id: str
    trust_store: HeadAuthorityTrustStoreV1
    trust_root_id: str
    source_bindings: tuple[HeadAuthoritySourceBindingV1, ...]
    max_head_staleness_seconds: int

    def __post_init__(self) -> None:
        if self.adapter_profile != REPOSITORY_OWNED_HEAD_AUTHORITY_PROFILE_V1:
            _reject(
                "invalid_head_trust_profile",
                "head-authority profile label is not the exact V1 profile",
            )
        if self.contract_version != HEAD_AUTHORITY_CONTRACT_VERSION_V1:
            _reject(
                "invalid_head_profile_version",
                "head-authority profile requires the exact V1 contract version",
            )
        _require_identity(self.service_instance_id, "service_instance_id")
        _require_identity(self.environment_id, "environment_id")
        _require_positive_int(self.max_head_staleness_seconds, "max_head_staleness_seconds")

        policy = _snapshot_validation_policy(self.validation_policy)
        if _validation_policy_id(policy) != _require_digest(
            self.validation_policy_id, "validation_policy_id"
        ):
            _reject(
                "head_policy_binding_mismatch",
                "validation policy identity does not match the copied policy",
            )
        store = HeadAuthorityTrustStoreV1.from_body(
            _snapshot_trust_store(self.trust_store).to_body()
        )
        if store.root_id != _require_digest(self.trust_root_id, "trust_root_id"):
            _reject(
                "head_trust_root_binding_mismatch",
                "trust root identity does not match the copied trust store",
            )

        bindings = self.source_bindings
        if type(bindings) is not tuple or not bindings or len(bindings) > MAX_HEAD_SOURCES_V1:
            _reject(
                "invalid_head_source_roster",
                "head-authority profile requires a bounded nonempty source roster",
            )
        for binding in bindings:
            if type(binding) is not HeadAuthoritySourceBindingV1:
                _reject(
                    "invalid_head_source_roster",
                    "head-authority profile requires exact source bindings",
                )
        if tuple(sorted(bindings, key=lambda entry: (entry.role, entry.source_id))) != bindings:
            _reject(
                "invalid_head_source_roster",
                "head-authority source roster is not canonically ordered",
            )
        source_ids = {binding.source_id for binding in bindings}
        key_ids = {binding.key_id for binding in bindings}
        principal_ids = {binding.principal_id for binding in bindings}
        if (
            len(source_ids) != len(bindings)
            or len(key_ids) != len(bindings)
            or len(principal_ids) != len(bindings)
        ):
            _reject(
                "head_source_independence_confusion",
                "each head-authority source requires a distinct label, key, and principal",
            )
        if key_ids != set(store.keys):
            _reject(
                "head_trust_root_roster_mismatch",
                "the trust root must contain exactly the roster's keys",
            )
        for binding in bindings:
            key = store.keys[binding.key_id]
            if (
                key.source_id != binding.source_id
                or key.principal_id != binding.principal_id
                or key.role != binding.role
            ):
                _reject(
                    "head_source_binding_mismatch",
                    "a source binding disagrees with its admitted trust-root key",
                )

        anchors = tuple(
            binding for binding in bindings if binding.role == HEAD_ANCHOR_ADAPTER_ROLE_V1
        )
        catalogs = tuple(
            binding for binding in bindings if binding.role == HEAD_CATALOG_ADAPTER_ROLE_V1
        )
        monitors = tuple(
            binding for binding in bindings if binding.role == HEAD_MONITOR_ADAPTER_ROLE_V1
        )
        if len(anchors) < 2:
            _reject(
                "invalid_head_source_roster",
                "head-authority qualification requires at least two anchor sources",
            )
        if len({binding.log_origin for binding in anchors}) != len(anchors):
            _reject(
                "head_source_independence_confusion",
                "each anchor source requires a distinct log origin",
            )
        if len(catalogs) != 1:
            _reject(
                "invalid_head_source_roster",
                "head-authority qualification requires exactly one catalog source",
            )
        if len(monitors) < 2:
            _reject(
                "invalid_head_source_roster",
                "head-authority qualification requires at least two monitor sources",
            )
        catalog_origin = catalogs[0].log_origin
        if any(binding.log_origin != catalog_origin for binding in monitors):
            _reject(
                "head_monitor_origin_mismatch",
                "every monitor must witness the exact catalog log origin",
            )

        object.__setattr__(self, "validation_policy", policy)
        object.__setattr__(self, "trust_store", store)

    @property
    def profile_id(self) -> str:
        return content_id("head_authority_trust_profile", self.to_body())

    @property
    def catalog_binding(self) -> HeadAuthoritySourceBindingV1:
        for binding in self.source_bindings:
            if binding.role == HEAD_CATALOG_ADAPTER_ROLE_V1:
                return binding
        raise AssertionError("validated profile always retains one catalog binding")

    def sources_for(self, role: str) -> tuple[str, ...]:
        """Return the exact ordered source roster for one role."""

        if type(role) is not str or role not in HEAD_AUTHORITY_ADAPTER_ROLES_V1:
            _reject("invalid_head_role", "unsupported head-authority adapter role")
        return tuple(
            binding.source_id for binding in self.source_bindings if binding.role == role
        )

    def binding_for(self, *, role: str, source_id: str) -> HeadAuthoritySourceBindingV1:
        """Resolve one exact retained source binding or refuse."""

        if type(role) is not str or role not in HEAD_AUTHORITY_ADAPTER_ROLES_V1:
            _reject("invalid_head_role", "unsupported head-authority adapter role")
        for binding in self.source_bindings:
            if binding.source_id == source_id and binding.role == role:
                return binding
        _reject(
            "head_source_mismatch",
            "the requested source and role are not in the retained roster",
        )
        raise AssertionError("unreachable")

    def to_body(self) -> dict[str, object]:
        return {
            "adapter_profile": self.adapter_profile,
            "contract_version": self.contract_version,
            "environment_id": self.environment_id,
            "max_head_staleness_seconds": self.max_head_staleness_seconds,
            "service_instance_id": self.service_instance_id,
            "source_bindings": [binding.to_body() for binding in self.source_bindings],
            "trust_root": self.trust_store.to_body(),
            "trust_root_id": self.trust_root_id,
            "validation_policy": self.validation_policy.to_body(),
            "validation_policy_id": self.validation_policy_id,
        }

    def to_canonical_bytes(self) -> bytes:
        return _canonical_record_bytes(self.to_body())

    @classmethod
    def from_canonical_bytes(cls, data: bytes | str) -> HeadAuthorityTrustProfileV1:
        body = _canonical_record_body(
            data,
            fields=_TRUST_PROFILE_FIELDS,
            label="head_trust_profile",
        )
        bindings = body["source_bindings"]
        if type(bindings) is not list:
            _reject(
                "invalid_head_source_roster",
                "head-authority source roster must be an ordered list",
            )
        return cls(
            adapter_profile=body["adapter_profile"],  # type: ignore[arg-type]
            contract_version=body["contract_version"],  # type: ignore[arg-type]
            service_instance_id=body["service_instance_id"],  # type: ignore[arg-type]
            environment_id=body["environment_id"],  # type: ignore[arg-type]
            validation_policy=IntegrityValidationPolicyV1.from_body(body["validation_policy"]),
            validation_policy_id=body["validation_policy_id"],  # type: ignore[arg-type]
            trust_store=HeadAuthorityTrustStoreV1.from_body(body["trust_root"]),
            trust_root_id=body["trust_root_id"],  # type: ignore[arg-type]
            source_bindings=tuple(
                HeadAuthoritySourceBindingV1.from_body(entry) for entry in bindings
            ),
            max_head_staleness_seconds=body["max_head_staleness_seconds"],  # type: ignore[arg-type]
        )


def _snapshot_trust_store(value: object) -> HeadAuthorityTrustStoreV1:
    if type(value) is not HeadAuthorityTrustStoreV1:
        _reject(
            "invalid_head_trust_root",
            "head-authority profile requires an exact HeadAuthorityTrustStoreV1",
        )
    return value  # type: ignore[return-value]


def _snapshot_profile(value: object) -> HeadAuthorityTrustProfileV1:
    if type(value) is not HeadAuthorityTrustProfileV1:
        _reject(
            "invalid_head_trust_profile",
            "an exact HeadAuthorityTrustProfileV1 is required",
        )
    return HeadAuthorityTrustProfileV1.from_canonical_bytes(
        value.to_canonical_bytes()  # type: ignore[union-attr]
    )


# ---------------------------------------------------------------------------
# Byte-bound anchor registration leaf
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AnchorRegistrationLeafV1:
    """The exact closed record whose bytes must appear in an anchor log."""

    contract_version: int
    service_instance_id: str
    environment_id: str
    mission_id: str
    instance_sequence: int
    anchor_policy_id: str
    anchor_statement_id: str

    def __post_init__(self) -> None:
        if self.contract_version != HEAD_AUTHORITY_CONTRACT_VERSION_V1:
            _reject(
                "invalid_head_profile_version",
                "anchor registration leaf requires the exact V1 contract version",
            )
        _require_identity(self.service_instance_id, "service_instance_id")
        _require_identity(self.environment_id, "environment_id")
        _require_digest(self.mission_id, "mission_id")
        _require_digest(self.anchor_policy_id, "anchor_policy_id")
        _require_digest(self.anchor_statement_id, "anchor_statement_id")
        _require_nonnegative_int(self.instance_sequence, "instance_sequence")

    def to_body(self) -> dict[str, object]:
        return {
            "anchor_policy_id": self.anchor_policy_id,
            "anchor_statement_id": self.anchor_statement_id,
            "contract_version": self.contract_version,
            "environment_id": self.environment_id,
            "instance_sequence": self.instance_sequence,
            "mission_id": self.mission_id,
            "service_instance_id": self.service_instance_id,
        }

    def to_canonical_bytes(self) -> bytes:
        return _canonical_record_bytes(self.to_body())

    @property
    def leaf_hash(self) -> bytes:
        return merkle_leaf_hash_v1(self.to_canonical_bytes())

    @property
    def leaf_hash_digest(self) -> str:
        return _bytes_to_digest(self.leaf_hash)

    @classmethod
    def from_canonical_bytes(cls, data: bytes | str) -> AnchorRegistrationLeafV1:
        body = _canonical_record_body(
            data,
            fields=_ANCHOR_LEAF_FIELDS,
            label="anchor_registration_leaf",
        )
        return cls(
            contract_version=body["contract_version"],  # type: ignore[arg-type]
            service_instance_id=body["service_instance_id"],  # type: ignore[arg-type]
            environment_id=body["environment_id"],  # type: ignore[arg-type]
            mission_id=body["mission_id"],  # type: ignore[arg-type]
            instance_sequence=body["instance_sequence"],  # type: ignore[arg-type]
            anchor_policy_id=body["anchor_policy_id"],  # type: ignore[arg-type]
            anchor_statement_id=body["anchor_statement_id"],  # type: ignore[arg-type]
        )


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------


def _validated_time_references(value: object, field: str) -> tuple[EvidenceReferenceV1, ...]:
    if type(value) is not tuple or len(value) < 2 or len(value) > MAX_HEAD_SOURCES_V1:
        _reject("invalid_head_evidence_references", f"{field} must be a bounded quorum")
    for reference in value:
        if type(reference) is not EvidenceReferenceV1:
            _reject(
                "invalid_head_evidence_references",
                f"{field} requires exact EvidenceReferenceV1 values",
            )
    ordered = tuple(sorted(value, key=lambda ref: (ref.source_id, ref.evidence_id)))
    if len({(ref.source_id, ref.evidence_id) for ref in ordered}) != len(ordered):
        _reject("invalid_head_evidence_references", f"{field} cannot repeat one reference")
    return ordered


@dataclass(frozen=True, slots=True)
class HeadAnchorRequestV1:
    """One source-specific anchor-registration request bound to exact leaf bytes."""

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
    anchor_policy_id: str
    instance_sequence: int
    anchor_statement_id: str
    anchor_leaf_hash: str
    time_bundle_id: str
    time_lower_bound: int
    time_upper_bound: int
    time_evidence: tuple[EvidenceReferenceV1, ...]
    prior_tree_size: int
    request_nonce: str
    request_id: str

    def __post_init__(self) -> None:
        if self.contract_version != HEAD_AUTHORITY_CONTRACT_VERSION_V1:
            _reject(
                "invalid_head_profile_version",
                "anchor request requires the exact V1 contract version",
            )
        for field in (
            "profile_id",
            "trust_root_id",
            "mission_id",
            "authority_id",
            "target_id",
            "event_digest",
            "transition_intent_id",
            "anchor_policy_id",
            "anchor_statement_id",
            "anchor_leaf_hash",
            "time_bundle_id",
        ):
            _require_digest(getattr(self, field), field)
        _require_identity(self.service_instance_id, "service_instance_id")
        _require_identity(self.environment_id, "environment_id")
        _require_identity(self.source_id, "source_id")
        _require_nonnegative_int(self.instance_sequence, "instance_sequence")
        _require_tree_size(self.prior_tree_size, "prior_tree_size")
        _require_epoch(self.time_lower_bound, "time_lower_bound")
        _require_epoch(self.time_upper_bound, "time_upper_bound")
        if self.time_lower_bound > self.time_upper_bound:
            _reject("invalid_head_request", "anchor request time hull is reversed")
        _require_nonce(self.request_nonce)
        object.__setattr__(
            self,
            "time_evidence",
            _validated_time_references(self.time_evidence, "time_evidence"),
        )
        expected_leaf = AnchorRegistrationLeafV1(
            contract_version=HEAD_AUTHORITY_CONTRACT_VERSION_V1,
            service_instance_id=self.service_instance_id,
            environment_id=self.environment_id,
            mission_id=self.mission_id,
            instance_sequence=self.instance_sequence,
            anchor_policy_id=self.anchor_policy_id,
            anchor_statement_id=self.anchor_statement_id,
        ).leaf_hash_digest
        if self.anchor_leaf_hash != expected_leaf:
            _reject(
                "head_anchor_leaf_mismatch",
                "anchor request leaf hash does not match its exact registration record",
            )
        derived = content_id("head_anchor_adapter_request", self._semantics())
        if _require_digest(self.request_id, "request_id") != derived:
            _reject(
                "head_anchor_request_id_mismatch",
                "anchor request identity does not match its exact semantics",
            )

    @classmethod
    def issue(
        cls,
        *,
        profile: HeadAuthorityTrustProfileV1,
        source_id: str,
        mission_id: str,
        authority_id: str,
        target_id: str,
        event_digest: str,
        transition_intent_id: str,
        anchor_statement_id: str,
        instance_sequence: int,
        time_bundle: QualifiedTimeBundleV1,
        prior_tree_size: int,
        request_nonce: str,
    ) -> HeadAnchorRequestV1:
        """Derive one exact source-specific anchor request from retained bindings."""

        copied = _snapshot_profile(profile)
        copied.binding_for(role=HEAD_ANCHOR_ADAPTER_ROLE_V1, source_id=source_id)
        if type(time_bundle) is not QualifiedTimeBundleV1:
            _reject(
                "invalid_head_time_bundle",
                "an anchor request requires an exact sealed QualifiedTimeBundleV1",
            )
        anchor_policy_id = copied.validation_policy.anchor_policy_id
        leaf = AnchorRegistrationLeafV1(
            contract_version=HEAD_AUTHORITY_CONTRACT_VERSION_V1,
            service_instance_id=copied.service_instance_id,
            environment_id=copied.environment_id,
            mission_id=mission_id,
            instance_sequence=instance_sequence,
            anchor_policy_id=anchor_policy_id,
            anchor_statement_id=anchor_statement_id,
        )
        values: dict[str, object] = {
            "anchor_leaf_hash": leaf.leaf_hash_digest,
            "anchor_policy_id": anchor_policy_id,
            "anchor_statement_id": anchor_statement_id,
            "authority_id": authority_id,
            "contract_version": HEAD_AUTHORITY_CONTRACT_VERSION_V1,
            "environment_id": copied.environment_id,
            "event_digest": event_digest,
            "instance_sequence": instance_sequence,
            "mission_id": mission_id,
            "prior_tree_size": prior_tree_size,
            "profile_id": copied.profile_id,
            "request_nonce": request_nonce,
            "service_instance_id": copied.service_instance_id,
            "source_id": source_id,
            "target_id": target_id,
            "time_bundle_id": time_bundle.bundle_id,
            "time_evidence": time_bundle.evidence,
            "time_lower_bound": time_bundle.time_lower_bound,
            "time_upper_bound": time_bundle.time_upper_bound,
            "transition_intent_id": transition_intent_id,
            "trust_root_id": copied.trust_root_id,
        }
        semantics = dict(values)
        semantics["time_evidence"] = [
            reference.to_body() for reference in time_bundle.evidence
        ]
        values["request_id"] = content_id("head_anchor_adapter_request", semantics)
        return cls(**values)  # type: ignore[arg-type]

    def _semantics(self) -> dict[str, object]:
        body = self.to_body()
        del body["request_id"]
        return body

    def to_body(self) -> dict[str, object]:
        return {
            "anchor_leaf_hash": self.anchor_leaf_hash,
            "anchor_policy_id": self.anchor_policy_id,
            "anchor_statement_id": self.anchor_statement_id,
            "authority_id": self.authority_id,
            "contract_version": self.contract_version,
            "environment_id": self.environment_id,
            "event_digest": self.event_digest,
            "instance_sequence": self.instance_sequence,
            "mission_id": self.mission_id,
            "prior_tree_size": self.prior_tree_size,
            "profile_id": self.profile_id,
            "request_id": self.request_id,
            "request_nonce": self.request_nonce,
            "service_instance_id": self.service_instance_id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "time_bundle_id": self.time_bundle_id,
            "time_evidence": [reference.to_body() for reference in self.time_evidence],
            "time_lower_bound": self.time_lower_bound,
            "time_upper_bound": self.time_upper_bound,
            "transition_intent_id": self.transition_intent_id,
            "trust_root_id": self.trust_root_id,
        }

    def to_canonical_bytes(self) -> bytes:
        return _canonical_record_bytes(self.to_body())

    @classmethod
    def from_canonical_bytes(cls, data: bytes | str) -> HeadAnchorRequestV1:
        body = _canonical_record_body(
            data,
            fields=_ANCHOR_REQUEST_FIELDS,
            label="head_anchor_request",
        )
        evidence = body["time_evidence"]
        if type(evidence) is not list:
            _reject(
                "invalid_head_evidence_references",
                "anchor request time evidence must be an ordered list",
            )
        return cls(
            contract_version=body["contract_version"],  # type: ignore[arg-type]
            profile_id=body["profile_id"],  # type: ignore[arg-type]
            trust_root_id=body["trust_root_id"],  # type: ignore[arg-type]
            service_instance_id=body["service_instance_id"],  # type: ignore[arg-type]
            environment_id=body["environment_id"],  # type: ignore[arg-type]
            mission_id=body["mission_id"],  # type: ignore[arg-type]
            authority_id=body["authority_id"],  # type: ignore[arg-type]
            target_id=body["target_id"],  # type: ignore[arg-type]
            event_digest=body["event_digest"],  # type: ignore[arg-type]
            transition_intent_id=body["transition_intent_id"],  # type: ignore[arg-type]
            source_id=body["source_id"],  # type: ignore[arg-type]
            anchor_policy_id=body["anchor_policy_id"],  # type: ignore[arg-type]
            instance_sequence=body["instance_sequence"],  # type: ignore[arg-type]
            anchor_statement_id=body["anchor_statement_id"],  # type: ignore[arg-type]
            anchor_leaf_hash=body["anchor_leaf_hash"],  # type: ignore[arg-type]
            time_bundle_id=body["time_bundle_id"],  # type: ignore[arg-type]
            time_lower_bound=body["time_lower_bound"],  # type: ignore[arg-type]
            time_upper_bound=body["time_upper_bound"],  # type: ignore[arg-type]
            time_evidence=tuple(
                EvidenceReferenceV1.from_body(reference) for reference in evidence
            ),
            prior_tree_size=body["prior_tree_size"],  # type: ignore[arg-type]
            request_nonce=body["request_nonce"],  # type: ignore[arg-type]
            request_id=body["request_id"],  # type: ignore[arg-type]
        )


@dataclass(frozen=True, slots=True)
class HeadCatalogRequestV1:
    """One source-specific catalog or monitor request bound to the retained head."""

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
    time_bundle_id: str
    time_lower_bound: int
    time_upper_bound: int
    time_evidence: tuple[EvidenceReferenceV1, ...]
    prior_tree_size: int
    prior_log_root_hash: str
    prior_instance_sequence: int
    prior_checkpoint_id: str
    prior_mission_event_seq: int
    prior_mission_checkpoint_id: str
    request_nonce: str
    request_id: str

    def __post_init__(self) -> None:
        if self.contract_version != HEAD_AUTHORITY_CONTRACT_VERSION_V1:
            _reject(
                "invalid_head_profile_version",
                "catalog request requires the exact V1 contract version",
            )
        for field in (
            "profile_id",
            "trust_root_id",
            "mission_id",
            "authority_id",
            "target_id",
            "event_digest",
            "transition_intent_id",
            "time_bundle_id",
            "prior_log_root_hash",
            "prior_checkpoint_id",
            "prior_mission_checkpoint_id",
        ):
            _require_digest(getattr(self, field), field)
        _require_identity(self.service_instance_id, "service_instance_id")
        _require_identity(self.environment_id, "environment_id")
        _require_identity(self.source_id, "source_id")
        if self.evidence_role not in {
            HEAD_CATALOG_ADAPTER_ROLE_V1,
            HEAD_MONITOR_ADAPTER_ROLE_V1,
        }:
            _reject(
                "invalid_head_role",
                "catalog request requires a catalog or monitor evidence role",
            )
        _require_tree_size(self.prior_tree_size, "prior_tree_size")
        _require_nonnegative_int(self.prior_instance_sequence, "prior_instance_sequence")
        _require_nonnegative_int(self.prior_mission_event_seq, "prior_mission_event_seq")
        if self.prior_mission_event_seq > self.prior_instance_sequence:
            _reject(
                "invalid_head_request",
                "retained mission head cannot exceed the retained instance-global head",
            )
        _require_epoch(self.time_lower_bound, "time_lower_bound")
        _require_epoch(self.time_upper_bound, "time_upper_bound")
        if self.time_lower_bound > self.time_upper_bound:
            _reject("invalid_head_request", "catalog request time hull is reversed")
        _require_nonce(self.request_nonce)
        object.__setattr__(
            self,
            "time_evidence",
            _validated_time_references(self.time_evidence, "time_evidence"),
        )
        derived = content_id("head_catalog_adapter_request", self._semantics())
        if _require_digest(self.request_id, "request_id") != derived:
            _reject(
                "head_catalog_request_id_mismatch",
                "catalog request identity does not match its exact semantics",
            )

    @classmethod
    def issue(
        cls,
        *,
        profile: HeadAuthorityTrustProfileV1,
        source_id: str,
        evidence_role: str,
        mission_id: str,
        authority_id: str,
        target_id: str,
        event_digest: str,
        transition_intent_id: str,
        time_bundle: QualifiedTimeBundleV1,
        prior_tree_size: int,
        prior_log_root_hash: str,
        prior_instance_sequence: int,
        prior_checkpoint_id: str,
        prior_mission_event_seq: int,
        prior_mission_checkpoint_id: str,
        request_nonce: str,
    ) -> HeadCatalogRequestV1:
        """Derive one exact source-specific catalog or monitor request."""

        copied = _snapshot_profile(profile)
        if evidence_role not in {
            HEAD_CATALOG_ADAPTER_ROLE_V1,
            HEAD_MONITOR_ADAPTER_ROLE_V1,
        }:
            _reject(
                "invalid_head_role",
                "catalog request requires a catalog or monitor evidence role",
            )
        copied.binding_for(role=evidence_role, source_id=source_id)
        if type(time_bundle) is not QualifiedTimeBundleV1:
            _reject(
                "invalid_head_time_bundle",
                "a catalog request requires an exact sealed QualifiedTimeBundleV1",
            )
        values: dict[str, object] = {
            "authority_id": authority_id,
            "contract_version": HEAD_AUTHORITY_CONTRACT_VERSION_V1,
            "environment_id": copied.environment_id,
            "event_digest": event_digest,
            "evidence_role": evidence_role,
            "mission_id": mission_id,
            "prior_checkpoint_id": prior_checkpoint_id,
            "prior_instance_sequence": prior_instance_sequence,
            "prior_log_root_hash": prior_log_root_hash,
            "prior_mission_checkpoint_id": prior_mission_checkpoint_id,
            "prior_mission_event_seq": prior_mission_event_seq,
            "prior_tree_size": prior_tree_size,
            "profile_id": copied.profile_id,
            "request_nonce": request_nonce,
            "service_instance_id": copied.service_instance_id,
            "source_id": source_id,
            "target_id": target_id,
            "time_bundle_id": time_bundle.bundle_id,
            "time_evidence": time_bundle.evidence,
            "time_lower_bound": time_bundle.time_lower_bound,
            "time_upper_bound": time_bundle.time_upper_bound,
            "transition_intent_id": transition_intent_id,
            "trust_root_id": copied.trust_root_id,
        }
        semantics = dict(values)
        semantics["time_evidence"] = [
            reference.to_body() for reference in time_bundle.evidence
        ]
        values["request_id"] = content_id("head_catalog_adapter_request", semantics)
        return cls(**values)  # type: ignore[arg-type]

    def _semantics(self) -> dict[str, object]:
        body = self.to_body()
        del body["request_id"]
        return body

    def to_body(self) -> dict[str, object]:
        return {
            "authority_id": self.authority_id,
            "contract_version": self.contract_version,
            "environment_id": self.environment_id,
            "event_digest": self.event_digest,
            "evidence_role": self.evidence_role,
            "mission_id": self.mission_id,
            "prior_checkpoint_id": self.prior_checkpoint_id,
            "prior_instance_sequence": self.prior_instance_sequence,
            "prior_log_root_hash": self.prior_log_root_hash,
            "prior_mission_checkpoint_id": self.prior_mission_checkpoint_id,
            "prior_mission_event_seq": self.prior_mission_event_seq,
            "prior_tree_size": self.prior_tree_size,
            "profile_id": self.profile_id,
            "request_id": self.request_id,
            "request_nonce": self.request_nonce,
            "service_instance_id": self.service_instance_id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "time_bundle_id": self.time_bundle_id,
            "time_evidence": [reference.to_body() for reference in self.time_evidence],
            "time_lower_bound": self.time_lower_bound,
            "time_upper_bound": self.time_upper_bound,
            "transition_intent_id": self.transition_intent_id,
            "trust_root_id": self.trust_root_id,
        }

    def to_canonical_bytes(self) -> bytes:
        return _canonical_record_bytes(self.to_body())

    @classmethod
    def from_canonical_bytes(cls, data: bytes | str) -> HeadCatalogRequestV1:
        body = _canonical_record_body(
            data,
            fields=_CATALOG_REQUEST_FIELDS,
            label="head_catalog_request",
        )
        evidence = body["time_evidence"]
        if type(evidence) is not list:
            _reject(
                "invalid_head_evidence_references",
                "catalog request time evidence must be an ordered list",
            )
        return cls(
            contract_version=body["contract_version"],  # type: ignore[arg-type]
            profile_id=body["profile_id"],  # type: ignore[arg-type]
            trust_root_id=body["trust_root_id"],  # type: ignore[arg-type]
            service_instance_id=body["service_instance_id"],  # type: ignore[arg-type]
            environment_id=body["environment_id"],  # type: ignore[arg-type]
            mission_id=body["mission_id"],  # type: ignore[arg-type]
            authority_id=body["authority_id"],  # type: ignore[arg-type]
            target_id=body["target_id"],  # type: ignore[arg-type]
            event_digest=body["event_digest"],  # type: ignore[arg-type]
            transition_intent_id=body["transition_intent_id"],  # type: ignore[arg-type]
            source_id=body["source_id"],  # type: ignore[arg-type]
            evidence_role=body["evidence_role"],  # type: ignore[arg-type]
            time_bundle_id=body["time_bundle_id"],  # type: ignore[arg-type]
            time_lower_bound=body["time_lower_bound"],  # type: ignore[arg-type]
            time_upper_bound=body["time_upper_bound"],  # type: ignore[arg-type]
            time_evidence=tuple(
                EvidenceReferenceV1.from_body(reference) for reference in evidence
            ),
            prior_tree_size=body["prior_tree_size"],  # type: ignore[arg-type]
            prior_log_root_hash=body["prior_log_root_hash"],  # type: ignore[arg-type]
            prior_instance_sequence=body["prior_instance_sequence"],  # type: ignore[arg-type]
            prior_checkpoint_id=body["prior_checkpoint_id"],  # type: ignore[arg-type]
            prior_mission_event_seq=body["prior_mission_event_seq"],  # type: ignore[arg-type]
            prior_mission_checkpoint_id=body["prior_mission_checkpoint_id"],  # type: ignore[arg-type]
            request_nonce=body["request_nonce"],  # type: ignore[arg-type]
            request_id=body["request_id"],  # type: ignore[arg-type]
        )


HeadAuthorityRequestV1 = HeadAnchorRequestV1 | HeadCatalogRequestV1


# ---------------------------------------------------------------------------
# Signed provider statements
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class HeadProviderStatementV1:
    """The exact signed inner statement of one head-authority fixture package."""

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
        if self.contract_version != HEAD_AUTHORITY_CONTRACT_VERSION_V1:
            _reject(
                "invalid_head_profile_version",
                "provider statement requires the exact V1 contract version",
            )
        for field in ("profile_id", "trust_root_id", "provider_policy_id", "request_id"):
            _require_digest(getattr(self, field), field)
        _require_identity(self.service_instance_id, "service_instance_id")
        _require_identity(self.environment_id, "environment_id")
        _require_identity(self.source_id, "source_id")
        if (
            type(self.evidence_role) is not str
            or self.evidence_role not in HEAD_AUTHORITY_ADAPTER_ROLES_V1
        ):
            _reject("invalid_head_role", "provider statement has an unsupported role")
        if not isinstance(self.claim, Mapping):
            _reject("invalid_head_provider_statement", "provider claim must be a JSON object")
        claim = dict(self.claim)
        for key in claim:
            if type(key) is not str:
                _reject(
                    "invalid_head_provider_statement",
                    "provider claim keys must be exact strings",
                )
        object.__setattr__(self, "claim", MappingProxyType(claim))

    def to_body(self) -> dict[str, object]:
        return {
            "claim": dict(self.claim),
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
    def from_canonical_bytes(cls, data: bytes | str) -> HeadProviderStatementV1:
        body = _canonical_record_body(
            data,
            fields=_STATEMENT_FIELDS,
            label="head_provider_statement",
        )
        return cls(
            contract_version=body["contract_version"],  # type: ignore[arg-type]
            profile_id=body["profile_id"],  # type: ignore[arg-type]
            trust_root_id=body["trust_root_id"],  # type: ignore[arg-type]
            service_instance_id=body["service_instance_id"],  # type: ignore[arg-type]
            environment_id=body["environment_id"],  # type: ignore[arg-type]
            source_id=body["source_id"],  # type: ignore[arg-type]
            evidence_role=body["evidence_role"],  # type: ignore[arg-type]
            provider_policy_id=body["provider_policy_id"],  # type: ignore[arg-type]
            request_id=body["request_id"],  # type: ignore[arg-type]
            claim=body["claim"],  # type: ignore[arg-type]
        )


@dataclass(frozen=True, slots=True)
class SignedHeadEvidenceV1:
    """One bounded outer wrapper over exact signed statement bytes."""

    evidence_role: str
    key_id: str
    statement_bytes: bytes
    signature_bytes: bytes
    algorithm: str = "ed25519"

    def __post_init__(self) -> None:
        if (
            type(self.evidence_role) is not str
            or self.evidence_role not in HEAD_AUTHORITY_ADAPTER_ROLES_V1
        ):
            _reject("invalid_head_role", "signed evidence has an unsupported role")
        _require_key_id(self.key_id, "key_id")
        if self.algorithm != "ed25519":
            _reject(
                "unsupported_head_algorithm",
                "signed head evidence must declare the exact ed25519 algorithm",
            )
        if (
            type(self.statement_bytes) is not bytes
            or not self.statement_bytes
            or len(self.statement_bytes) > MAX_HEAD_PACKAGE_BYTES_V1
        ):
            _reject(
                "invalid_signed_head_evidence",
                "signed head evidence requires bounded nonempty statement bytes",
            )
        if type(self.signature_bytes) is not bytes or len(self.signature_bytes) != 64:
            _reject(
                "invalid_signed_head_evidence",
                "signed head evidence requires a 64-byte Ed25519 signature",
            )
        object.__setattr__(self, "statement_bytes", bytes(self.statement_bytes))
        object.__setattr__(self, "signature_bytes", bytes(self.signature_bytes))

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
    def from_canonical_bytes(cls, data: bytes | str) -> SignedHeadEvidenceV1:
        body = _canonical_record_body(
            data,
            fields=_SIGNED_EVIDENCE_FIELDS,
            label="signed_head_evidence",
        )
        return cls(
            evidence_role=body["evidence_role"],  # type: ignore[arg-type]
            key_id=body["key_id"],  # type: ignore[arg-type]
            statement_bytes=_decode_b64(
                body["statement_b64"],
                "statement_b64",
                maximum=MAX_HEAD_PACKAGE_BYTES_V1,
            ),
            signature_bytes=_decode_b64(body["signature_b64"], "signature_b64", maximum=64),
            algorithm=body["algorithm"],  # type: ignore[arg-type]
        )


@dataclass(frozen=True, slots=True)
class HeadEvidenceSignerV1:
    """One deterministic repository-owned fixture signer for a single role."""

    source_id: str
    principal_id: str
    role: str
    private_key_bytes: bytes

    def __post_init__(self) -> None:
        _require_identity(self.source_id, "source_id")
        _require_identity(self.principal_id, "principal_id")
        if type(self.role) is not str or self.role not in HEAD_AUTHORITY_ADAPTER_ROLES_V1:
            _reject("invalid_head_signer", "fixture signer has an unsupported role")
        if type(self.private_key_bytes) is not bytes or len(self.private_key_bytes) != 32:
            _reject("invalid_head_signer", "fixture signer requires 32 private key bytes")
        object.__setattr__(self, "private_key_bytes", bytes(self.private_key_bytes))

    @classmethod
    def from_seed(
        cls,
        *,
        source_id: str,
        principal_id: str,
        role: str,
        seed: bytes,
    ) -> HeadEvidenceSignerV1:
        if type(seed) is not bytes or not seed or len(seed) > MAX_HEAD_SEED_BYTES_V1:
            _reject(
                "invalid_head_seed",
                "head-authority fixture seed must be nonempty immutable bounded bytes",
            )
        private_bytes = hashlib.sha256(
            b"etzio.head-authority.fixture-key.v1\x00"
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
    def trusted_key(self) -> TrustedHeadAuthorityKeyV1:
        public_bytes = (
            Ed25519PrivateKey.from_private_bytes(self.private_key_bytes)
            .public_key()
            .public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        )
        return TrustedHeadAuthorityKeyV1(
            source_id=self.source_id,
            principal_id=self.principal_id,
            role=self.role,
            public_key_bytes=public_bytes,
        )

    def sign(self, statement: HeadProviderStatementV1) -> SignedHeadEvidenceV1:
        if (
            type(statement) is not HeadProviderStatementV1
            or statement.source_id != self.source_id
            or statement.evidence_role != self.role
        ):
            _reject(
                "head_signer_binding_mismatch",
                "fixture signer requires its exact source and role statement",
            )
        statement_bytes = statement.to_canonical_bytes()
        signature = Ed25519PrivateKey.from_private_bytes(self.private_key_bytes).sign(
            _ROLE_SIGNATURE_DOMAINS_V1[self.role] + statement_bytes
        )
        return SignedHeadEvidenceV1(
            evidence_role=self.role,
            key_id=self.trusted_key.key_id,
            statement_bytes=statement_bytes,
            signature_bytes=signature,
        )


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, init=False)
class AuthenticatedHeadEvidencePackageV1:
    """Sealed package whose exact retained bytes authenticated before parsing."""

    profile_id: str
    request: HeadAuthorityRequestV1
    signed_evidence: SignedHeadEvidenceV1
    statement: HeadProviderStatementV1
    source_binding: HeadAuthoritySourceBindingV1
    provider_evidence: ProviderEvidenceBlobV1
    claim: Mapping[str, object]
    _seal: object

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        _reject(
            "unauthenticated_head_result_construction",
            "authenticated head package construction is private",
        )

    def __post_init__(self) -> None:
        if (
            type(self) is not AuthenticatedHeadEvidencePackageV1
            or self._seal is not _AUTHENTICATED_PACKAGE_SEAL
        ):
            _reject(
                "unauthenticated_head_result_construction",
                "authenticated head package construction is private",
            )

    @property
    def evidence_reference(self) -> EvidenceReferenceV1:
        return EvidenceReferenceV1(
            evidence_kind=self.provider_evidence.evidence_kind,
            source_id=self.provider_evidence.source_id,
            evidence_id=self.provider_evidence.evidence_id,
        )


def _validate_anchor_claim(
    request: HeadAnchorRequestV1,
    binding: HeadAuthoritySourceBindingV1,
    claim: Mapping[str, object],
) -> None:
    body = _require_exact_dict(dict(claim), _ANCHOR_CLAIM_FIELDS, "head_anchor_claim")
    if _require_identity(body["log_origin"], "log_origin") != binding.log_origin:
        _reject(
            "head_log_origin_mismatch",
            "anchor claim log origin does not match its retained source binding",
        )
    if _require_digest(body["anchor_statement_id"], "anchor_statement_id") != (
        request.anchor_statement_id
    ):
        _reject(
            "head_anchor_statement_mismatch",
            "anchor claim does not register the requested anchor statement",
        )
    if _require_digest(body["leaf_hash"], "leaf_hash") != request.anchor_leaf_hash:
        _reject(
            "head_anchor_leaf_mismatch",
            "anchor claim leaf hash does not match the exact requested registration record",
        )
    _require_digest(body["log_root_hash"], "log_root_hash")
    _require_tree_size(body["tree_size"], "tree_size")
    _require_nonnegative_int(body["leaf_index"], "leaf_index")
    _require_epoch(body["registered_at"], "registered_at")
    _validated_proof(body["inclusion_proof"], "inclusion_proof")


def _validate_catalog_claim(
    request: HeadCatalogRequestV1,
    binding: HeadAuthoritySourceBindingV1,
    claim: Mapping[str, object],
) -> None:
    body = _require_exact_dict(dict(claim), _CATALOG_CLAIM_FIELDS, "head_catalog_claim")
    if _require_identity(body["log_origin"], "log_origin") != binding.log_origin:
        _reject(
            "head_log_origin_mismatch",
            "catalog claim log origin does not match its retained source binding",
        )
    _require_digest(body["log_root_hash"], "log_root_hash")
    _require_tree_size(body["tree_size"], "tree_size")
    _require_epoch(body["published_at"], "published_at")
    _validated_proof(body["consistency_proof"], "consistency_proof")
    if _require_digest(body["mission_id"], "mission_id") != request.mission_id:
        _reject(
            "head_scope_mismatch",
            "catalog claim mission does not match the requested scope",
        )
    _require_nonnegative_int(body["instance_sequence"], "instance_sequence")
    _require_nonnegative_int(body["mission_event_seq"], "mission_event_seq")
    _require_digest(body["checkpoint_id"], "checkpoint_id")
    _require_digest(body["mission_checkpoint_id"], "mission_checkpoint_id")
    for field in (
        "checkpoint_attestation_id",
        "checkpoint_trust_snapshot_id",
        "mission_checkpoint_attestation_id",
        "mission_checkpoint_trust_snapshot_id",
    ):
        value = body[field]
        if value is not None:
            _require_digest(value, field)
    for field in ("checkpoint_principal_id", "mission_checkpoint_principal_id"):
        value = body[field]
        if value is not None:
            _require_identity(value, field)


def _validate_monitor_claim(
    request: HeadCatalogRequestV1,
    binding: HeadAuthoritySourceBindingV1,
    claim: Mapping[str, object],
) -> None:
    body = _require_exact_dict(dict(claim), _MONITOR_CLAIM_FIELDS, "head_monitor_claim")
    if _require_identity(body["log_origin"], "log_origin") != binding.log_origin:
        _reject(
            "head_log_origin_mismatch",
            "monitor claim log origin does not match its retained source binding",
        )
    _require_digest(body["log_root_hash"], "log_root_hash")
    _require_tree_size(body["tree_size"], "tree_size")
    _require_epoch(body["observed_at"], "observed_at")
    _require_identity(body["witnessed_source_id"], "witnessed_source_id")


def authenticate_head_evidence_v1(
    *,
    profile: HeadAuthorityTrustProfileV1,
    request: HeadAuthorityRequestV1,
    signed_evidence: SignedHeadEvidenceV1,
) -> AuthenticatedHeadEvidencePackageV1:
    """Authenticate one exact signed fixture package before parsing its claim."""

    copied_profile = _snapshot_profile(profile)
    if type(request) is HeadAnchorRequestV1:
        expected_role = HEAD_ANCHOR_ADAPTER_ROLE_V1
        copied_request: HeadAuthorityRequestV1 = HeadAnchorRequestV1.from_canonical_bytes(
            request.to_canonical_bytes()
        )
    elif type(request) is HeadCatalogRequestV1:
        copied_request = HeadCatalogRequestV1.from_canonical_bytes(request.to_canonical_bytes())
        expected_role = copied_request.evidence_role
    else:
        _reject("invalid_head_request", "an exact V1 head-authority request is required")
        raise AssertionError("unreachable")

    if type(signed_evidence) is not SignedHeadEvidenceV1:
        _reject(
            "invalid_signed_head_evidence",
            "an exact SignedHeadEvidenceV1 wrapper is required",
        )
    signed = SignedHeadEvidenceV1.from_canonical_bytes(signed_evidence.to_canonical_bytes())

    if copied_request.profile_id != copied_profile.profile_id:
        _reject(
            "head_profile_mismatch",
            "the request does not bind the retained head-authority profile",
        )
    if copied_request.trust_root_id != copied_profile.trust_root_id:
        _reject(
            "head_root_mismatch",
            "the request does not bind the retained head-authority trust root",
        )
    if signed.evidence_role != expected_role:
        _reject(
            "head_role_mismatch",
            "signed evidence role does not match the requested role",
        )

    binding = copied_profile.binding_for(role=expected_role, source_id=copied_request.source_id)
    if signed.key_id != binding.key_id:
        _reject(
            "head_source_mismatch",
            "signed evidence key is not the retained key for this source",
        )
    if signed.key_id in copied_profile.trust_store.revoked_key_ids:
        _reject("revoked_head_key", "signed evidence uses a revoked fixture key")
    trusted_key = copied_profile.trust_store.keys.get(signed.key_id)
    if trusted_key is None:
        _reject("unknown_head_key", "signed evidence key is not in the retained trust root")

    try:
        Ed25519PublicKey.from_public_bytes(trusted_key.public_key_bytes).verify(  # type: ignore[union-attr]
            signed.signature_bytes,
            _ROLE_SIGNATURE_DOMAINS_V1[expected_role] + signed.statement_bytes,
        )
    except (InvalidSignature, ValueError) as exc:
        raise HeadAuthorityAdapterError(
            "head_signature_invalid",
            "head package signature is invalid for the exact retained bytes",
        ) from exc

    statement = HeadProviderStatementV1.from_canonical_bytes(signed.statement_bytes)
    if statement.profile_id != copied_profile.profile_id:
        _reject("head_profile_mismatch", "provider statement binds another profile")
    if statement.trust_root_id != copied_profile.trust_root_id:
        _reject("head_root_mismatch", "provider statement binds another trust root")
    if (
        statement.service_instance_id != copied_profile.service_instance_id
        or statement.environment_id != copied_profile.environment_id
    ):
        _reject("head_scope_mismatch", "provider statement binds another service scope")
    if statement.source_id != binding.source_id:
        _reject("head_source_mismatch", "provider statement binds another source")
    if statement.evidence_role != expected_role:
        _reject("head_role_mismatch", "provider statement binds another role")
    if statement.provider_policy_id != binding.provider_policy_id:
        _reject("head_policy_mismatch", "provider statement binds another provider policy")
    if statement.request_id != copied_request.request_id:
        _reject("head_request_mismatch", "provider statement answers another request")

    if expected_role == HEAD_ANCHOR_ADAPTER_ROLE_V1:
        _validate_anchor_claim(copied_request, binding, statement.claim)  # type: ignore[arg-type]
    elif expected_role == HEAD_CATALOG_ADAPTER_ROLE_V1:
        _validate_catalog_claim(copied_request, binding, statement.claim)  # type: ignore[arg-type]
    else:
        _validate_monitor_claim(copied_request, binding, statement.claim)  # type: ignore[arg-type]

    provider_evidence = ProviderEvidenceBlobV1.from_content(
        evidence_kind=binding.evidence_kind,
        source_id=binding.source_id,
        content=signed.to_canonical_bytes(),
    )
    return _construct_sealed_result(
        AuthenticatedHeadEvidencePackageV1,
        seal=_AUTHENTICATED_PACKAGE_SEAL,
        values={
            "profile_id": copied_profile.profile_id,
            "request": copied_request,
            "signed_evidence": signed,
            "statement": statement,
            "source_binding": binding,
            "provider_evidence": provider_evidence,
            "claim": statement.claim,
        },
    )


# ---------------------------------------------------------------------------
# Shared qualification helpers
# ---------------------------------------------------------------------------


def _exact_source_mapping(
    value: object,
    *,
    expected_sources: tuple[str, ...],
    exact_type: type,
    label: str,
) -> dict[str, object]:
    if not isinstance(value, Mapping):
        _reject(f"invalid_{label}", f"{label} must be one exact source mapping")
    collected: dict[str, object] = {}
    for source_id, entry in value.items():  # type: ignore[union-attr]
        if type(source_id) is not str or source_id in collected:
            _reject(
                "head_source_set_mismatch",
                f"{label} cannot repeat or misname a source",
            )
        if type(entry) is not exact_type:
            _reject(f"invalid_{label}", f"{label} requires exact {exact_type.__name__} values")
        collected[source_id] = entry
    if tuple(sorted(collected)) != tuple(sorted(expected_sources)):
        _reject(
            "head_source_set_mismatch",
            f"{label} must contain exactly the retained source roster",
        )
    return collected


def _require_fresh_head(
    *,
    observed_at: int,
    time_lower_bound: int,
    time_upper_bound: int,
    max_staleness: int,
    field: str,
) -> None:
    if observed_at > time_lower_bound:
        _reject(
            "head_publication_not_established",
            f"{field} is not established before the complete qualified time hull",
        )
    if time_upper_bound - observed_at > max_staleness:
        _reject(
            "head_evidence_stale",
            f"{field} exceeds the exact retained head-staleness ceiling",
        )


def _reauthenticated_time_bundle(
    *,
    time_profile: IntegrityAdapterTrustProfileV1,
    time_bundle: QualifiedTimeBundleV1,
) -> QualifiedTimeBundleV1:
    if type(time_profile) is not IntegrityAdapterTrustProfileV1:
        _reject(
            "invalid_head_time_bundle",
            "head qualification requires the exact ADR-0012 time profile",
        )
    if type(time_bundle) is not QualifiedTimeBundleV1:
        _reject(
            "invalid_head_time_bundle",
            "head qualification requires an exact sealed QualifiedTimeBundleV1",
        )
    return reauthenticate_time_bundle_v1(profile=time_profile, bundle=time_bundle)


def _require_time_binding(
    request: HeadAuthorityRequestV1,
    bundle: QualifiedTimeBundleV1,
) -> None:
    if (
        request.time_bundle_id != bundle.bundle_id
        or request.time_lower_bound != bundle.time_lower_bound
        or request.time_upper_bound != bundle.time_upper_bound
        or request.time_evidence != bundle.evidence
    ):
        _reject(
            "head_time_bundle_mismatch",
            "the request does not bind the exact freshly reauthenticated time hull",
        )


def _require_shared_scope(
    requests: tuple[HeadAuthorityRequestV1, ...],
    fields: tuple[str, ...],
) -> None:
    first = requests[0]
    for request in requests[1:]:
        for field in fields:
            if getattr(request, field) != getattr(first, field):
                _reject(
                    "head_scope_mismatch",
                    f"every source request must share the exact {field}",
                )


def _sorted_references(
    values: Iterable[EvidenceReferenceV1],
    *,
    evidence_kind: str,
    minimum: int,
) -> tuple[EvidenceReferenceV1, ...]:
    collected = tuple(values)
    for reference in collected:
        if type(reference) is not EvidenceReferenceV1 or reference.evidence_kind != evidence_kind:
            _reject(
                "invalid_head_evidence_references",
                "evidence references must be exact values of the expected kind",
            )
    ordered = tuple(sorted(collected, key=lambda ref: (ref.source_id, ref.evidence_id)))
    if len(ordered) < minimum:
        _reject(
            "invalid_head_evidence_references",
            "evidence references do not reach the required quorum",
        )
    if len({(ref.source_id, ref.evidence_id) for ref in ordered}) != len(ordered):
        _reject(
            "invalid_head_evidence_references",
            "evidence references cannot repeat one entry",
        )
    return ordered


def _require_bounded_evidence(blobs: tuple[ProviderEvidenceBlobV1, ...]) -> None:
    total = 0
    for blob in blobs:
        total += len(blob.content)
    if total > MAX_HEAD_TOTAL_EVIDENCE_BYTES_V1:
        _reject(
            "head_evidence_limit_exceeded",
            "retained head evidence exceeds its aggregate ceiling",
        )


# ---------------------------------------------------------------------------
# Anchor qualification
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, init=False)
class QualifiedAnchorBundleV1:
    """Sealed anchor registration proved by recomputed RFC 9162 inclusion proofs."""

    profile_id: str
    anchor_policy_id: str
    anchor_statement_id: str
    anchor_leaf_hash: str
    instance_sequence: int
    time_bundle_id: str
    requests: Mapping[str, HeadAnchorRequestV1]
    signed_evidence: Mapping[str, SignedHeadEvidenceV1]
    authenticated_packages: Mapping[str, AuthenticatedHeadEvidencePackageV1]
    log_roots: Mapping[str, str]
    evidence_blobs: tuple[ProviderEvidenceBlobV1, ...]
    _seal: object

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        _reject(
            "unauthenticated_head_result_construction",
            "qualified anchor construction is private",
        )

    def __post_init__(self) -> None:
        if type(self) is not QualifiedAnchorBundleV1 or self._seal is not _QUALIFIED_ANCHOR_SEAL:
            _reject(
                "unauthenticated_head_result_construction",
                "qualified anchor construction is private",
            )

    @property
    def evidence(self) -> tuple[EvidenceReferenceV1, ...]:
        return _sorted_references(
            (
                EvidenceReferenceV1(
                    evidence_kind=blob.evidence_kind,
                    source_id=blob.source_id,
                    evidence_id=blob.evidence_id,
                )
                for blob in self.evidence_blobs
            ),
            evidence_kind=HEAD_ANCHOR_RECEIPT_EVIDENCE_KIND,
            minimum=2,
        )

    @property
    def bundle_id(self) -> str:
        return content_id("head_anchor_bundle", self.to_body())

    def to_body(self) -> dict[str, object]:
        return {
            "anchor_leaf_hash": self.anchor_leaf_hash,
            "anchor_policy_id": self.anchor_policy_id,
            "anchor_statement_id": self.anchor_statement_id,
            "evidence": [reference.to_body() for reference in self.evidence],
            "instance_sequence": self.instance_sequence,
            "log_roots": [
                {"log_origin": origin, "log_root_hash": root}
                for origin, root in sorted(self.log_roots.items())
            ],
            "profile_id": self.profile_id,
            "time_bundle_id": self.time_bundle_id,
        }


def qualify_anchor_bundle_v1(
    *,
    profile: HeadAuthorityTrustProfileV1,
    time_profile: IntegrityAdapterTrustProfileV1,
    time_bundle: QualifiedTimeBundleV1,
    requests: Mapping[str, HeadAnchorRequestV1],
    signed_evidence: Mapping[str, SignedHeadEvidenceV1],
) -> QualifiedAnchorBundleV1:
    """Qualify the complete anchor roster against recomputed inclusion proofs."""

    copied_profile = _snapshot_profile(profile)
    bundle = _reauthenticated_time_bundle(time_profile=time_profile, time_bundle=time_bundle)
    expected_sources = copied_profile.sources_for(HEAD_ANCHOR_ADAPTER_ROLE_V1)

    copied_requests = _exact_source_mapping(
        requests,
        expected_sources=expected_sources,
        exact_type=HeadAnchorRequestV1,
        label="head_anchor_requests",
    )
    copied_signed = _exact_source_mapping(
        signed_evidence,
        expected_sources=expected_sources,
        exact_type=SignedHeadEvidenceV1,
        label="head_anchor_evidence",
    )

    ordered = tuple(sorted(expected_sources))
    for source_id in ordered:
        if copied_requests[source_id].source_id != source_id:  # type: ignore[union-attr]
            _reject(
                "head_source_set_mismatch",
                "an anchor request is filed under another source label",
            )
    request_tuple = tuple(copied_requests[source_id] for source_id in ordered)  # type: ignore[misc]
    _require_shared_scope(
        request_tuple,  # type: ignore[arg-type]
        (
            "profile_id",
            "trust_root_id",
            "service_instance_id",
            "environment_id",
            "mission_id",
            "authority_id",
            "target_id",
            "event_digest",
            "transition_intent_id",
            "anchor_policy_id",
            "instance_sequence",
            "anchor_statement_id",
            "anchor_leaf_hash",
            "time_bundle_id",
            "request_nonce",
        ),
    )

    packages: dict[str, AuthenticatedHeadEvidencePackageV1] = {}
    log_roots: dict[str, str] = {}
    blobs: list[ProviderEvidenceBlobV1] = []
    for source_id in ordered:
        request = copied_requests[source_id]
        _require_time_binding(request, bundle)  # type: ignore[arg-type]
        package = authenticate_head_evidence_v1(
            profile=copied_profile,
            request=request,  # type: ignore[arg-type]
            signed_evidence=copied_signed[source_id],  # type: ignore[arg-type]
        )
        claim = package.claim
        tree_size = claim["tree_size"]
        leaf_index = claim["leaf_index"]
        if tree_size < request.prior_tree_size:  # type: ignore[operator,union-attr]
            _reject(
                "head_anchor_tree_rollback",
                "anchor tree size regressed below the retained predecessor",
            )
        verify_merkle_inclusion_v1(
            leaf_hash=_digest_to_bytes(claim["leaf_hash"], "leaf_hash"),
            leaf_index=leaf_index,  # type: ignore[arg-type]
            tree_size=tree_size,  # type: ignore[arg-type]
            proof=_validated_proof(claim["inclusion_proof"], "inclusion_proof"),
            root_hash=_digest_to_bytes(claim["log_root_hash"], "log_root_hash"),
        )
        _require_fresh_head(
            observed_at=claim["registered_at"],  # type: ignore[arg-type]
            time_lower_bound=bundle.time_lower_bound,
            time_upper_bound=bundle.time_upper_bound,
            max_staleness=copied_profile.max_head_staleness_seconds,
            field="anchor registration time",
        )
        packages[source_id] = package
        log_roots[package.source_binding.log_origin] = claim["log_root_hash"]  # type: ignore[assignment]
        blobs.append(package.provider_evidence)

    _require_bounded_evidence(tuple(blobs))
    first = request_tuple[0]
    return _construct_sealed_result(
        QualifiedAnchorBundleV1,
        seal=_QUALIFIED_ANCHOR_SEAL,
        values={
            "profile_id": copied_profile.profile_id,
            "anchor_policy_id": first.anchor_policy_id,  # type: ignore[union-attr]
            "anchor_statement_id": first.anchor_statement_id,  # type: ignore[union-attr]
            "anchor_leaf_hash": first.anchor_leaf_hash,  # type: ignore[union-attr]
            "instance_sequence": first.instance_sequence,  # type: ignore[union-attr]
            "time_bundle_id": bundle.bundle_id,
            "requests": MappingProxyType(dict(copied_requests)),  # type: ignore[arg-type]
            "signed_evidence": MappingProxyType(dict(copied_signed)),  # type: ignore[arg-type]
            "authenticated_packages": MappingProxyType(packages),
            "log_roots": MappingProxyType(log_roots),
            "evidence_blobs": tuple(blobs),
        },
    )


def reauthenticate_anchor_bundle_v1(
    *,
    profile: HeadAuthorityTrustProfileV1,
    time_profile: IntegrityAdapterTrustProfileV1,
    time_bundle: QualifiedTimeBundleV1,
    bundle: QualifiedAnchorBundleV1,
) -> QualifiedAnchorBundleV1:
    """Rebuild one sealed anchor bundle from its exact retained bytes."""

    if type(bundle) is not QualifiedAnchorBundleV1:
        _reject(
            "invalid_head_anchor_bundle",
            "reauthentication requires an exact sealed QualifiedAnchorBundleV1",
        )
    rebuilt = qualify_anchor_bundle_v1(
        profile=profile,
        time_profile=time_profile,
        time_bundle=time_bundle,
        requests=bundle.requests,
        signed_evidence=bundle.signed_evidence,
    )
    if rebuilt.to_body() != bundle.to_body():
        _reject(
            "qualified_head_anchor_mutation",
            "the retained anchor bundle does not reproduce its derived body",
        )
    return rebuilt


# ---------------------------------------------------------------------------
# Catalog and monitor qualification
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, init=False)
class QualifiedHeadCatalogBundleV1:
    """Sealed catalog head proved by consistency and unanimous monitor agreement."""

    profile_id: str
    log_origin: str
    time_bundle_id: str
    catalog_source_id: str
    tree_size: int
    log_root_hash: str
    published_at: int
    catalog_request: HeadCatalogRequestV1
    monitor_requests: Mapping[str, HeadCatalogRequestV1]
    signed_evidence: Mapping[str, SignedHeadEvidenceV1]
    authenticated_packages: Mapping[str, AuthenticatedHeadEvidencePackageV1]
    external_floor: HeadCheckpointFloorV1
    evidence_blobs: tuple[ProviderEvidenceBlobV1, ...]
    _seal: object

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        _reject(
            "unauthenticated_head_result_construction",
            "qualified head catalog construction is private",
        )

    def __post_init__(self) -> None:
        if (
            type(self) is not QualifiedHeadCatalogBundleV1
            or self._seal is not _QUALIFIED_CATALOG_SEAL
        ):
            _reject(
                "unauthenticated_head_result_construction",
                "qualified head catalog construction is private",
            )

    @property
    def bundle_id(self) -> str:
        return content_id("head_catalog_bundle", self.to_body())

    def to_body(self) -> dict[str, object]:
        return {
            "catalog_source_id": self.catalog_source_id,
            "external_floor": self.external_floor.to_body(),
            "log_origin": self.log_origin,
            "log_root_hash": self.log_root_hash,
            "profile_id": self.profile_id,
            "published_at": self.published_at,
            "time_bundle_id": self.time_bundle_id,
            "tree_size": self.tree_size,
        }


def qualify_head_catalog_bundle_v1(
    *,
    profile: HeadAuthorityTrustProfileV1,
    time_profile: IntegrityAdapterTrustProfileV1,
    time_bundle: QualifiedTimeBundleV1,
    requests: Mapping[str, HeadCatalogRequestV1],
    signed_evidence: Mapping[str, SignedHeadEvidenceV1],
) -> QualifiedHeadCatalogBundleV1:
    """Qualify one catalog head under unanimous monitor agreement."""

    copied_profile = _snapshot_profile(profile)
    bundle = _reauthenticated_time_bundle(time_profile=time_profile, time_bundle=time_bundle)
    catalog_binding = copied_profile.catalog_binding
    monitor_sources = copied_profile.sources_for(HEAD_MONITOR_ADAPTER_ROLE_V1)
    expected_sources = (catalog_binding.source_id, *monitor_sources)

    copied_requests = _exact_source_mapping(
        requests,
        expected_sources=expected_sources,
        exact_type=HeadCatalogRequestV1,
        label="head_catalog_requests",
    )
    copied_signed = _exact_source_mapping(
        signed_evidence,
        expected_sources=expected_sources,
        exact_type=SignedHeadEvidenceV1,
        label="head_catalog_evidence",
    )
    for source_id in expected_sources:
        request = copied_requests[source_id]
        if request.source_id != source_id:  # type: ignore[union-attr]
            _reject(
                "head_source_set_mismatch",
                "a catalog request is filed under another source label",
            )
        expected_role = (
            HEAD_CATALOG_ADAPTER_ROLE_V1
            if source_id == catalog_binding.source_id
            else HEAD_MONITOR_ADAPTER_ROLE_V1
        )
        if request.evidence_role != expected_role:  # type: ignore[union-attr]
            _reject(
                "head_role_mismatch",
                "a catalog request declares the wrong evidence role for its source",
            )

    ordered = (catalog_binding.source_id, *sorted(monitor_sources))
    request_tuple = tuple(copied_requests[source_id] for source_id in ordered)  # type: ignore[misc]
    _require_shared_scope(
        request_tuple,  # type: ignore[arg-type]
        (
            "profile_id",
            "trust_root_id",
            "service_instance_id",
            "environment_id",
            "mission_id",
            "authority_id",
            "target_id",
            "event_digest",
            "transition_intent_id",
            "time_bundle_id",
            "prior_tree_size",
            "prior_log_root_hash",
            "prior_instance_sequence",
            "prior_checkpoint_id",
            "prior_mission_event_seq",
            "prior_mission_checkpoint_id",
            "request_nonce",
        ),
    )

    packages: dict[str, AuthenticatedHeadEvidencePackageV1] = {}
    blobs: list[ProviderEvidenceBlobV1] = []
    for source_id in ordered:
        request = copied_requests[source_id]
        _require_time_binding(request, bundle)  # type: ignore[arg-type]
        package = authenticate_head_evidence_v1(
            profile=copied_profile,
            request=request,  # type: ignore[arg-type]
            signed_evidence=copied_signed[source_id],  # type: ignore[arg-type]
        )
        packages[source_id] = package
        blobs.append(package.provider_evidence)

    catalog_request = copied_requests[catalog_binding.source_id]
    catalog_claim = packages[catalog_binding.source_id].claim
    tree_size = catalog_claim["tree_size"]
    log_root_hash = catalog_claim["log_root_hash"]

    verify_merkle_consistency_v1(
        first_size=catalog_request.prior_tree_size,  # type: ignore[union-attr]
        first_root=_digest_to_bytes(
            catalog_request.prior_log_root_hash,  # type: ignore[union-attr]
            "prior_log_root_hash",
        ),
        second_size=tree_size,  # type: ignore[arg-type]
        second_root=_digest_to_bytes(log_root_hash, "log_root_hash"),
        proof=_validated_proof(catalog_claim["consistency_proof"], "consistency_proof"),
    )
    _require_fresh_head(
        observed_at=catalog_claim["published_at"],  # type: ignore[arg-type]
        time_lower_bound=bundle.time_lower_bound,
        time_upper_bound=bundle.time_upper_bound,
        max_staleness=copied_profile.max_head_staleness_seconds,
        field="catalog publication time",
    )
    if catalog_claim["instance_sequence"] < catalog_request.prior_instance_sequence:  # type: ignore[operator,union-attr]
        _reject(
            "head_catalog_head_rollback",
            "catalog instance-global head regressed below the retained predecessor",
        )
    if catalog_claim["mission_event_seq"] < catalog_request.prior_mission_event_seq:  # type: ignore[operator,union-attr]
        _reject(
            "head_catalog_head_rollback",
            "catalog mission head regressed below the retained predecessor",
        )

    for source_id in sorted(monitor_sources):
        monitor_claim = packages[source_id].claim
        if monitor_claim["witnessed_source_id"] != catalog_binding.source_id:
            _reject(
                "head_monitor_witness_mismatch",
                "a monitor does not witness the exact retained catalog source",
            )
        if (
            monitor_claim["log_origin"] != catalog_claim["log_origin"]
            or monitor_claim["tree_size"] != tree_size
            or monitor_claim["log_root_hash"] != log_root_hash
        ):
            _reject(
                "head_catalog_equivocation",
                "a monitor witnessed a different head than the catalog published",
            )
        _require_fresh_head(
            observed_at=monitor_claim["observed_at"],  # type: ignore[arg-type]
            time_lower_bound=bundle.time_lower_bound,
            time_upper_bound=bundle.time_upper_bound,
            max_staleness=copied_profile.max_head_staleness_seconds,
            field="monitor observation time",
        )

    _require_bounded_evidence(tuple(blobs))
    floor_evidence = _sorted_references(
        (package.evidence_reference for package in packages.values()),
        evidence_kind=EXTERNAL_FLOOR_EVIDENCE_KIND,
        minimum=2,
    )
    try:
        external_floor = HeadCheckpointFloorV1(
            service_instance_id=copied_profile.service_instance_id,
            environment_id=copied_profile.environment_id,
            instance_sequence=catalog_claim["instance_sequence"],  # type: ignore[arg-type]
            checkpoint_id=catalog_claim["checkpoint_id"],  # type: ignore[arg-type]
            checkpoint_attestation_id=catalog_claim["checkpoint_attestation_id"],  # type: ignore[arg-type]
            checkpoint_principal_id=catalog_claim["checkpoint_principal_id"],  # type: ignore[arg-type]
            checkpoint_trust_snapshot_id=catalog_claim["checkpoint_trust_snapshot_id"],  # type: ignore[arg-type]
            mission_id=catalog_claim["mission_id"],  # type: ignore[arg-type]
            mission_event_seq=catalog_claim["mission_event_seq"],  # type: ignore[arg-type]
            mission_checkpoint_id=catalog_claim["mission_checkpoint_id"],  # type: ignore[arg-type]
            mission_checkpoint_attestation_id=catalog_claim[  # type: ignore[arg-type]
                "mission_checkpoint_attestation_id"
            ],
            mission_checkpoint_principal_id=catalog_claim[  # type: ignore[arg-type]
                "mission_checkpoint_principal_id"
            ],
            mission_checkpoint_trust_snapshot_id=catalog_claim[  # type: ignore[arg-type]
                "mission_checkpoint_trust_snapshot_id"
            ],
            evidence=floor_evidence,
        )
    except ValueError as exc:
        raise HeadAuthorityAdapterError(
            "head_catalog_floor_invalid",
            "the qualified catalog head is not an admissible external head floor",
        ) from exc

    return _construct_sealed_result(
        QualifiedHeadCatalogBundleV1,
        seal=_QUALIFIED_CATALOG_SEAL,
        values={
            "profile_id": copied_profile.profile_id,
            "log_origin": catalog_binding.log_origin,
            "time_bundle_id": bundle.bundle_id,
            "catalog_source_id": catalog_binding.source_id,
            "tree_size": tree_size,
            "log_root_hash": log_root_hash,
            "published_at": catalog_claim["published_at"],
            "catalog_request": catalog_request,
            "monitor_requests": MappingProxyType(
                {source_id: copied_requests[source_id] for source_id in sorted(monitor_sources)}  # type: ignore[misc]
            ),
            "signed_evidence": MappingProxyType(dict(copied_signed)),  # type: ignore[arg-type]
            "authenticated_packages": MappingProxyType(packages),
            "external_floor": external_floor,
            "evidence_blobs": tuple(blobs),
        },
    )


def reauthenticate_head_catalog_bundle_v1(
    *,
    profile: HeadAuthorityTrustProfileV1,
    time_profile: IntegrityAdapterTrustProfileV1,
    time_bundle: QualifiedTimeBundleV1,
    bundle: QualifiedHeadCatalogBundleV1,
) -> QualifiedHeadCatalogBundleV1:
    """Rebuild one sealed catalog bundle from its exact retained bytes."""

    if type(bundle) is not QualifiedHeadCatalogBundleV1:
        _reject(
            "invalid_head_catalog_bundle",
            "reauthentication requires an exact sealed QualifiedHeadCatalogBundleV1",
        )
    requests = {bundle.catalog_request.source_id: bundle.catalog_request}
    requests.update(bundle.monitor_requests)
    rebuilt = qualify_head_catalog_bundle_v1(
        profile=profile,
        time_profile=time_profile,
        time_bundle=time_bundle,
        requests=requests,
        signed_evidence=bundle.signed_evidence,
    )
    if rebuilt.to_body() != bundle.to_body():
        _reject(
            "qualified_head_catalog_mutation",
            "the retained catalog bundle does not reproduce its derived body",
        )
    return rebuilt


# ---------------------------------------------------------------------------
# Provider-neutral mapping
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, init=False)
class QualifiedHeadAuthorityInputsV1:
    """Sealed provider-neutral anchor evidence and external head floor."""

    profile_id: str
    time_bundle_id: str
    anchor_policy_id: str
    anchor_statement_id: str
    anchor_evidence: tuple[EvidenceReferenceV1, ...]
    external_floor: HeadCheckpointFloorV1
    evidence_blobs: tuple[ProviderEvidenceBlobV1, ...]
    _seal: object

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        _reject(
            "unauthenticated_head_result_construction",
            "qualified head-authority input construction is private",
        )

    def __post_init__(self) -> None:
        if (
            type(self) is not QualifiedHeadAuthorityInputsV1
            or self._seal is not _QUALIFIED_INPUTS_SEAL
        ):
            _reject(
                "unauthenticated_head_result_construction",
                "qualified head-authority input construction is private",
            )

    @property
    def mapping_id(self) -> str:
        return content_id("head_authority_qualified_inputs", self.to_body())

    def to_body(self) -> dict[str, object]:
        return {
            "anchor_evidence": [reference.to_body() for reference in self.anchor_evidence],
            "anchor_policy_id": self.anchor_policy_id,
            "anchor_statement_id": self.anchor_statement_id,
            "external_floor": self.external_floor.to_body(),
            "profile_id": self.profile_id,
            "time_bundle_id": self.time_bundle_id,
        }


def map_qualified_head_authority_inputs_v1(
    *,
    profile: HeadAuthorityTrustProfileV1,
    time_profile: IntegrityAdapterTrustProfileV1,
    time_bundle: QualifiedTimeBundleV1,
    anchor_bundle: QualifiedAnchorBundleV1,
    catalog_bundle: QualifiedHeadCatalogBundleV1,
) -> QualifiedHeadAuthorityInputsV1:
    """Map freshly reauthenticated bundles to provider-neutral integrity values."""

    copied_profile = _snapshot_profile(profile)
    fresh_time = _reauthenticated_time_bundle(
        time_profile=time_profile,
        time_bundle=time_bundle,
    )
    fresh_anchor = reauthenticate_anchor_bundle_v1(
        profile=copied_profile,
        time_profile=time_profile,
        time_bundle=fresh_time,
        bundle=anchor_bundle,
    )
    fresh_catalog = reauthenticate_head_catalog_bundle_v1(
        profile=copied_profile,
        time_profile=time_profile,
        time_bundle=fresh_time,
        bundle=catalog_bundle,
    )
    if (
        fresh_anchor.time_bundle_id != fresh_time.bundle_id
        or fresh_catalog.time_bundle_id != fresh_time.bundle_id
    ):
        _reject(
            "head_time_bundle_mismatch",
            "anchor and catalog bundles must share the exact qualified time hull",
        )

    blobs = tuple(fresh_anchor.evidence_blobs) + tuple(fresh_catalog.evidence_blobs)
    _require_bounded_evidence(blobs)
    retained = {(blob.source_id, blob.evidence_id) for blob in blobs}
    if len(retained) != len(blobs):
        _reject(
            "qualified_head_evidence_coverage_mismatch",
            "retained head evidence cannot repeat one BLOB reference",
        )

    anchor_evidence = fresh_anchor.evidence
    mapped = {(ref.source_id, ref.evidence_id) for ref in anchor_evidence} | {
        (ref.source_id, ref.evidence_id) for ref in fresh_catalog.external_floor.evidence
    }
    if mapped != retained:
        _reject(
            "qualified_head_evidence_coverage_mismatch",
            "mapped head evidence does not exactly cover the retained signed BLOBs",
        )

    return _construct_sealed_result(
        QualifiedHeadAuthorityInputsV1,
        seal=_QUALIFIED_INPUTS_SEAL,
        values={
            "profile_id": copied_profile.profile_id,
            "time_bundle_id": fresh_time.bundle_id,
            "anchor_policy_id": fresh_anchor.anchor_policy_id,
            "anchor_statement_id": fresh_anchor.anchor_statement_id,
            "anchor_evidence": anchor_evidence,
            "external_floor": fresh_catalog.external_floor,
            "evidence_blobs": blobs,
        },
    )


# ---------------------------------------------------------------------------
# Deterministic repository-owned harness
# ---------------------------------------------------------------------------


_HEAD_QUALIFICATION_CASE_IDS: Final = (
    "anchor_registration_qualifies",
    "anchor_exact_retry_is_byte_stable",
    "anchor_cross_request_replay_refused",
    "anchor_foreign_statement_receipt_refused",
    "catalog_head_qualifies",
    "catalog_exact_retry_is_byte_stable",
    "catalog_tree_rollback_refused",
    "monitor_split_view_refused",
    "provider_neutral_mapping_complete",
)


@dataclass(frozen=True, slots=True)
class ExpectedHeadStateV1:
    """The deterministic fixture's retained predecessor and expected head projection."""

    prior_instance_sequence: int
    prior_checkpoint_id: str
    prior_mission_event_seq: int
    prior_mission_checkpoint_id: str
    instance_sequence: int
    checkpoint_id: str
    checkpoint_attestation_id: str | None
    checkpoint_principal_id: str | None
    checkpoint_trust_snapshot_id: str | None
    mission_event_seq: int
    mission_checkpoint_id: str
    mission_checkpoint_attestation_id: str | None
    mission_checkpoint_principal_id: str | None
    mission_checkpoint_trust_snapshot_id: str | None

    def __post_init__(self) -> None:
        for field in (
            "prior_checkpoint_id",
            "prior_mission_checkpoint_id",
            "checkpoint_id",
            "mission_checkpoint_id",
        ):
            _require_digest(getattr(self, field), field)
        for field in (
            "prior_instance_sequence",
            "prior_mission_event_seq",
            "instance_sequence",
            "mission_event_seq",
        ):
            _require_nonnegative_int(getattr(self, field), field)
        if self.mission_event_seq > self.instance_sequence:
            _reject(
                "invalid_expected_head",
                "expected mission head cannot exceed the expected instance-global head",
            )
        if self.prior_mission_event_seq > self.prior_instance_sequence:
            _reject(
                "invalid_expected_head",
                "retained mission head cannot exceed the retained instance-global head",
            )
        for field in (
            "checkpoint_attestation_id",
            "checkpoint_trust_snapshot_id",
            "mission_checkpoint_attestation_id",
            "mission_checkpoint_trust_snapshot_id",
        ):
            value = getattr(self, field)
            if value is not None:
                _require_digest(value, field)
        for field in ("checkpoint_principal_id", "mission_checkpoint_principal_id"):
            value = getattr(self, field)
            if value is not None:
                _require_identity(value, field)

    def to_body(self) -> dict[str, object]:
        return {
            "checkpoint_attestation_id": self.checkpoint_attestation_id,
            "checkpoint_id": self.checkpoint_id,
            "checkpoint_principal_id": self.checkpoint_principal_id,
            "checkpoint_trust_snapshot_id": self.checkpoint_trust_snapshot_id,
            "instance_sequence": self.instance_sequence,
            "mission_checkpoint_attestation_id": self.mission_checkpoint_attestation_id,
            "mission_checkpoint_id": self.mission_checkpoint_id,
            "mission_checkpoint_principal_id": self.mission_checkpoint_principal_id,
            "mission_checkpoint_trust_snapshot_id": (
                self.mission_checkpoint_trust_snapshot_id
            ),
            "mission_event_seq": self.mission_event_seq,
            "prior_checkpoint_id": self.prior_checkpoint_id,
            "prior_instance_sequence": self.prior_instance_sequence,
            "prior_mission_checkpoint_id": self.prior_mission_checkpoint_id,
            "prior_mission_event_seq": self.prior_mission_event_seq,
        }

    @classmethod
    def from_body(cls, value: object) -> ExpectedHeadStateV1:
        body = _require_exact_dict(value, _EXPECTED_HEAD_FIELDS, "expected_head")
        return cls(**body)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class HeadAuthorityQualificationVectorV1:
    """One deterministic qualification scope and expected head projection."""

    service_instance_id: str
    environment_id: str
    mission_id: str
    authority_id: str
    target_id: str
    event_digest: str
    transition_intent_id: str
    anchor_policy_id: str
    anchor_statement_id: str
    request_nonce: str
    expected_epoch_second: int
    expected_head: ExpectedHeadStateV1

    def __post_init__(self) -> None:
        _require_identity(self.service_instance_id, "service_instance_id")
        _require_identity(self.environment_id, "environment_id")
        for field in (
            "mission_id",
            "authority_id",
            "target_id",
            "event_digest",
            "transition_intent_id",
            "anchor_policy_id",
            "anchor_statement_id",
        ):
            _require_digest(getattr(self, field), field)
        _require_nonce(self.request_nonce)
        _require_epoch(self.expected_epoch_second, "expected_epoch_second")
        if type(self.expected_head) is not ExpectedHeadStateV1:
            _reject(
                "invalid_head_qualification_vector",
                "qualification vector requires an exact ExpectedHeadStateV1",
            )

    @property
    def vector_id(self) -> str:
        return content_id("head_authority_qualification_vector", self.to_body())

    def to_body(self) -> dict[str, object]:
        return {
            "anchor_policy_id": self.anchor_policy_id,
            "anchor_statement_id": self.anchor_statement_id,
            "authority_id": self.authority_id,
            "environment_id": self.environment_id,
            "event_digest": self.event_digest,
            "expected_epoch_second": self.expected_epoch_second,
            "expected_head": self.expected_head.to_body(),
            "mission_id": self.mission_id,
            "request_nonce": self.request_nonce,
            "service_instance_id": self.service_instance_id,
            "target_id": self.target_id,
            "transition_intent_id": self.transition_intent_id,
        }

    def to_canonical_bytes(self) -> bytes:
        return _canonical_record_bytes(self.to_body())

    @classmethod
    def from_canonical_bytes(cls, data: bytes | str) -> HeadAuthorityQualificationVectorV1:
        body = _canonical_record_body(
            data,
            fields=_QUALIFICATION_VECTOR_FIELDS,
            label="head_qualification_vector",
        )
        body["expected_head"] = ExpectedHeadStateV1.from_body(body["expected_head"])
        return cls(**body)  # type: ignore[arg-type]


class HeadAnchorAdapterV1(Protocol):
    """Narrow acquisition protocol for one anchor-registration source."""

    source_id: str

    def acquire(self, request: HeadAnchorRequestV1) -> SignedHeadEvidenceV1: ...


class HeadCatalogAdapterV1(Protocol):
    """Narrow acquisition protocol for one catalog or monitor source."""

    source_id: str
    role: str

    def acquire(self, request: HeadCatalogRequestV1) -> SignedHeadEvidenceV1: ...


def _fixture_statement(
    *,
    profile: HeadAuthorityTrustProfileV1,
    binding: HeadAuthoritySourceBindingV1,
    request_id: str,
    claim: dict[str, object],
) -> HeadProviderStatementV1:
    return HeadProviderStatementV1(
        contract_version=HEAD_AUTHORITY_CONTRACT_VERSION_V1,
        profile_id=profile.profile_id,
        trust_root_id=profile.trust_root_id,
        service_instance_id=profile.service_instance_id,
        environment_id=profile.environment_id,
        source_id=binding.source_id,
        evidence_role=binding.role,
        provider_policy_id=binding.provider_policy_id,
        request_id=request_id,
        claim=claim,
    )


@dataclass(frozen=True, slots=True)
class RepositoryOwnedDeterministicHeadAnchorAdapterV1:
    """One repository-owned anchor log that computes genuine inclusion proofs."""

    profile: HeadAuthorityTrustProfileV1
    binding: HeadAuthoritySourceBindingV1
    signer: HeadEvidenceSignerV1
    prefix_leaf_hashes: tuple[bytes, ...]
    suffix_leaf_hashes: tuple[bytes, ...]
    registered_at: int

    def __post_init__(self) -> None:
        if self.binding.role != HEAD_ANCHOR_ADAPTER_ROLE_V1:
            _reject("invalid_head_fixture_adapter", "anchor adapter requires an anchor binding")
        if self.signer.source_id != self.binding.source_id:
            _reject(
                "invalid_head_fixture_adapter",
                "anchor adapter signer does not match its source binding",
            )
        for field in ("prefix_leaf_hashes", "suffix_leaf_hashes"):
            values = getattr(self, field)
            if type(values) is not tuple or len(values) > MAX_HEAD_FIXTURE_LEAVES_V1:
                _reject("invalid_head_fixture_adapter", f"{field} must be a bounded tuple")
            for entry in values:
                if type(entry) is not bytes or len(entry) != 32:
                    _reject(
                        "invalid_head_fixture_adapter",
                        f"{field} entries must be 32-byte leaf hashes",
                    )
        _require_epoch(self.registered_at, "registered_at")

    @property
    def source_id(self) -> str:
        return self.binding.source_id

    def acquire(self, request: HeadAnchorRequestV1) -> SignedHeadEvidenceV1:
        """Return one deterministic signed receipt with a real inclusion proof."""

        if type(request) is not HeadAnchorRequestV1 or request.source_id != self.source_id:
            _reject(
                "head_source_mismatch",
                "anchor adapter received a request for another source",
            )
        leaf = _digest_to_bytes(request.anchor_leaf_hash, "anchor_leaf_hash")
        leaves = (*self.prefix_leaf_hashes, leaf, *self.suffix_leaf_hashes)
        leaf_index = len(self.prefix_leaf_hashes)
        claim: dict[str, object] = {
            "anchor_statement_id": request.anchor_statement_id,
            "inclusion_proof": [
                _bytes_to_digest(node)
                for node in merkle_inclusion_proof_v1(leaves, leaf_index)
            ],
            "leaf_hash": request.anchor_leaf_hash,
            "leaf_index": leaf_index,
            "log_origin": self.binding.log_origin,
            "log_root_hash": _bytes_to_digest(merkle_root_v1(leaves)),
            "registered_at": self.registered_at,
            "tree_size": len(leaves),
        }
        return self.signer.sign(
            _fixture_statement(
                profile=self.profile,
                binding=self.binding,
                request_id=request.request_id,
                claim=claim,
            )
        )


@dataclass(frozen=True, slots=True)
class RepositoryOwnedDeterministicHeadCatalogAdapterV1:
    """One repository-owned catalog log that computes genuine consistency proofs."""

    profile: HeadAuthorityTrustProfileV1
    binding: HeadAuthoritySourceBindingV1
    signer: HeadEvidenceSignerV1
    leaf_hashes: tuple[bytes, ...]
    mission_id: str
    head: ExpectedHeadStateV1
    published_at: int

    def __post_init__(self) -> None:
        if self.binding.role != HEAD_CATALOG_ADAPTER_ROLE_V1:
            _reject(
                "invalid_head_fixture_adapter",
                "catalog adapter requires a catalog binding",
            )
        if self.signer.source_id != self.binding.source_id:
            _reject(
                "invalid_head_fixture_adapter",
                "catalog adapter signer does not match its source binding",
            )
        if (
            type(self.leaf_hashes) is not tuple
            or not self.leaf_hashes
            or len(self.leaf_hashes) > MAX_HEAD_FIXTURE_LEAVES_V1
        ):
            _reject(
                "invalid_head_fixture_adapter",
                "catalog adapter requires a bounded nonempty leaf tuple",
            )
        _require_digest(self.mission_id, "mission_id")
        _require_epoch(self.published_at, "published_at")

    @property
    def source_id(self) -> str:
        return self.binding.source_id

    @property
    def role(self) -> str:
        return self.binding.role

    def acquire(self, request: HeadCatalogRequestV1) -> SignedHeadEvidenceV1:
        """Return one deterministic signed head with a real consistency proof."""

        if type(request) is not HeadCatalogRequestV1 or request.source_id != self.source_id:
            _reject(
                "head_source_mismatch",
                "catalog adapter received a request for another source",
            )
        tree_size = len(self.leaf_hashes)
        proof: tuple[bytes, ...] = ()
        if 0 < request.prior_tree_size <= tree_size:
            proof = merkle_consistency_proof_v1(self.leaf_hashes, request.prior_tree_size)
        head = self.head
        claim: dict[str, object] = {
            "checkpoint_attestation_id": head.checkpoint_attestation_id,
            "checkpoint_id": head.checkpoint_id,
            "checkpoint_principal_id": head.checkpoint_principal_id,
            "checkpoint_trust_snapshot_id": head.checkpoint_trust_snapshot_id,
            "consistency_proof": [_bytes_to_digest(node) for node in proof],
            "instance_sequence": head.instance_sequence,
            "log_origin": self.binding.log_origin,
            "log_root_hash": _bytes_to_digest(merkle_root_v1(self.leaf_hashes)),
            "mission_checkpoint_attestation_id": head.mission_checkpoint_attestation_id,
            "mission_checkpoint_id": head.mission_checkpoint_id,
            "mission_checkpoint_principal_id": head.mission_checkpoint_principal_id,
            "mission_checkpoint_trust_snapshot_id": (
                head.mission_checkpoint_trust_snapshot_id
            ),
            "mission_event_seq": head.mission_event_seq,
            "mission_id": self.mission_id,
            "published_at": self.published_at,
            "tree_size": tree_size,
        }
        return self.signer.sign(
            _fixture_statement(
                profile=self.profile,
                binding=self.binding,
                request_id=request.request_id,
                claim=claim,
            )
        )


@dataclass(frozen=True, slots=True)
class RepositoryOwnedDeterministicHeadMonitorAdapterV1:
    """One repository-owned monitor that recomputes the witnessed head itself."""

    profile: HeadAuthorityTrustProfileV1
    binding: HeadAuthoritySourceBindingV1
    signer: HeadEvidenceSignerV1
    leaf_hashes: tuple[bytes, ...]
    witnessed_source_id: str
    observed_at: int

    def __post_init__(self) -> None:
        if self.binding.role != HEAD_MONITOR_ADAPTER_ROLE_V1:
            _reject(
                "invalid_head_fixture_adapter",
                "monitor adapter requires a monitor binding",
            )
        if self.signer.source_id != self.binding.source_id:
            _reject(
                "invalid_head_fixture_adapter",
                "monitor adapter signer does not match its source binding",
            )
        if (
            type(self.leaf_hashes) is not tuple
            or not self.leaf_hashes
            or len(self.leaf_hashes) > MAX_HEAD_FIXTURE_LEAVES_V1
        ):
            _reject(
                "invalid_head_fixture_adapter",
                "monitor adapter requires a bounded nonempty leaf tuple",
            )
        _require_identity(self.witnessed_source_id, "witnessed_source_id")
        _require_epoch(self.observed_at, "observed_at")

    @property
    def source_id(self) -> str:
        return self.binding.source_id

    @property
    def role(self) -> str:
        return self.binding.role

    def acquire(self, request: HeadCatalogRequestV1) -> SignedHeadEvidenceV1:
        """Return one deterministic signed witness over an independently computed root."""

        if type(request) is not HeadCatalogRequestV1 or request.source_id != self.source_id:
            _reject(
                "head_source_mismatch",
                "monitor adapter received a request for another source",
            )
        claim: dict[str, object] = {
            "log_origin": self.binding.log_origin,
            "log_root_hash": _bytes_to_digest(merkle_root_v1(self.leaf_hashes)),
            "observed_at": self.observed_at,
            "tree_size": len(self.leaf_hashes),
            "witnessed_source_id": self.witnessed_source_id,
        }
        return self.signer.sign(
            _fixture_statement(
                profile=self.profile,
                binding=self.binding,
                request_id=request.request_id,
                claim=claim,
            )
        )


def _head_qualification_manifest_id(
    *,
    adapter_implementation_id: str,
    profile: HeadAuthorityTrustProfileV1,
    vector: HeadAuthorityQualificationVectorV1,
    anchor_adapters: tuple[RepositoryOwnedDeterministicHeadAnchorAdapterV1, ...],
    catalog_adapter: RepositoryOwnedDeterministicHeadCatalogAdapterV1,
    monitor_adapters: tuple[RepositoryOwnedDeterministicHeadMonitorAdapterV1, ...],
    prior_tree_size: int,
    prior_log_root_hash: str,
    anchor_prior_tree_size: int,
) -> str:
    return _fixture_content_id(
        "head-qualification-corpus",
        {
            "adapter_implementation_id": adapter_implementation_id,
            "anchor_adapters": [
                {
                    "log_origin": adapter.binding.log_origin,
                    "prefix_leaf_hashes": [
                        _bytes_to_digest(leaf) for leaf in adapter.prefix_leaf_hashes
                    ],
                    "registered_at": adapter.registered_at,
                    "source_id": adapter.source_id,
                    "suffix_leaf_hashes": [
                        _bytes_to_digest(leaf) for leaf in adapter.suffix_leaf_hashes
                    ],
                }
                for adapter in anchor_adapters
            ],
            "anchor_prior_tree_size": anchor_prior_tree_size,
            "case_ids": list(_HEAD_QUALIFICATION_CASE_IDS),
            "catalog_adapter": {
                "head": catalog_adapter.head.to_body(),
                "leaf_hashes": [
                    _bytes_to_digest(leaf) for leaf in catalog_adapter.leaf_hashes
                ],
                "log_origin": catalog_adapter.binding.log_origin,
                "mission_id": catalog_adapter.mission_id,
                "published_at": catalog_adapter.published_at,
                "source_id": catalog_adapter.source_id,
            },
            "monitor_adapters": [
                {
                    "leaf_hashes": [
                        _bytes_to_digest(leaf) for leaf in adapter.leaf_hashes
                    ],
                    "log_origin": adapter.binding.log_origin,
                    "observed_at": adapter.observed_at,
                    "source_id": adapter.source_id,
                    "witnessed_source_id": adapter.witnessed_source_id,
                }
                for adapter in monitor_adapters
            ],
            "prior_log_root_hash": prior_log_root_hash,
            "prior_tree_size": prior_tree_size,
            "profile_id": profile.profile_id,
            "vector_id": vector.vector_id,
        },
    )


@dataclass(frozen=True, slots=True)
class RepositoryOwnedDeterministicHeadAuthorityFixtureV1:
    """One content-bound deterministic head-authority qualification corpus."""

    adapter_implementation_id: str
    corpus_manifest_id: str
    profile: HeadAuthorityTrustProfileV1
    vector: HeadAuthorityQualificationVectorV1
    time_fixture: RepositoryOwnedDeterministicAdapterFixtureV1
    anchor_adapters: tuple[RepositoryOwnedDeterministicHeadAnchorAdapterV1, ...]
    catalog_adapter: RepositoryOwnedDeterministicHeadCatalogAdapterV1
    monitor_adapters: tuple[RepositoryOwnedDeterministicHeadMonitorAdapterV1, ...]
    prior_tree_size: int
    prior_log_root_hash: str
    anchor_prior_tree_size: int

    def __post_init__(self) -> None:
        _require_digest(self.adapter_implementation_id, "adapter_implementation_id")
        if type(self.profile) is not HeadAuthorityTrustProfileV1:
            _reject("invalid_head_qualification_fixture", "fixture requires an exact profile")
        if type(self.vector) is not HeadAuthorityQualificationVectorV1:
            _reject("invalid_head_qualification_fixture", "fixture requires an exact vector")
        if type(self.time_fixture) is not RepositoryOwnedDeterministicAdapterFixtureV1:
            _reject(
                "invalid_head_qualification_fixture",
                "fixture requires the exact ADR-0012 time fixture",
            )
        expected_anchors = self.profile.sources_for(HEAD_ANCHOR_ADAPTER_ROLE_V1)
        expected_monitors = self.profile.sources_for(HEAD_MONITOR_ADAPTER_ROLE_V1)
        if type(self.anchor_adapters) is not tuple or tuple(
            adapter.source_id for adapter in self.anchor_adapters
        ) != expected_anchors:
            _reject(
                "invalid_head_fixture_adapter",
                "anchor adapters must appear exactly once in retained roster order",
            )
        if type(self.monitor_adapters) is not tuple or tuple(
            adapter.source_id for adapter in self.monitor_adapters
        ) != expected_monitors:
            _reject(
                "invalid_head_fixture_adapter",
                "monitor adapters must appear exactly once in retained roster order",
            )
        if self.catalog_adapter.source_id != self.profile.catalog_binding.source_id:
            _reject(
                "invalid_head_fixture_adapter",
                "the catalog adapter does not match the retained catalog binding",
            )
        profile_body = self.profile.to_body()
        for adapter in (
            *self.anchor_adapters,
            self.catalog_adapter,
            *self.monitor_adapters,
        ):
            if adapter.profile.to_body() != profile_body:
                _reject(
                    "invalid_head_fixture_adapter",
                    "every fixture adapter must retain the exact fixture profile",
                )
        _require_tree_size(self.prior_tree_size, "prior_tree_size")
        _require_tree_size(self.anchor_prior_tree_size, "anchor_prior_tree_size")
        _require_digest(self.prior_log_root_hash, "prior_log_root_hash")
        if self.prior_tree_size > len(self.catalog_adapter.leaf_hashes):
            _reject(
                "invalid_head_qualification_fixture",
                "the retained catalog prefix cannot exceed the fixture tree",
            )
        expected_prior_root = _bytes_to_digest(
            merkle_root_v1(self.catalog_adapter.leaf_hashes[: self.prior_tree_size])
        )
        if expected_prior_root != self.prior_log_root_hash:
            _reject(
                "invalid_head_qualification_fixture",
                "the retained catalog root does not match its own leaf prefix",
            )
        derived = _head_qualification_manifest_id(
            adapter_implementation_id=self.adapter_implementation_id,
            profile=self.profile,
            vector=self.vector,
            anchor_adapters=self.anchor_adapters,
            catalog_adapter=self.catalog_adapter,
            monitor_adapters=self.monitor_adapters,
            prior_tree_size=self.prior_tree_size,
            prior_log_root_hash=self.prior_log_root_hash,
            anchor_prior_tree_size=self.anchor_prior_tree_size,
        )
        if _require_digest(self.corpus_manifest_id, "corpus_manifest_id") != derived:
            _reject(
                "head_qualification_manifest_mismatch",
                "the corpus manifest does not match its exact deterministic inputs",
            )


@dataclass(frozen=True, slots=True)
class HeadAuthorityQualificationCaseV1:
    """One deterministic qualification case outcome."""

    case_id: str
    expected_disposition: str
    observed_disposition: str
    reason_code: str
    result_id: str

    def __post_init__(self) -> None:
        if self.case_id not in _HEAD_QUALIFICATION_CASE_IDS:
            _reject("invalid_head_qualification_case", "unknown qualification case identity")
        for field in ("expected_disposition", "observed_disposition"):
            if getattr(self, field) not in {"qualified", "refused"}:
                _reject(
                    "invalid_head_qualification_case",
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
class HeadAuthorityQualificationReportV1:
    """Sealed deterministic report over the exact ordered qualification roster."""

    contract_version: int
    adapter_implementation_id: str
    profile_id: str
    vector_id: str
    corpus_manifest_id: str
    cases: tuple[HeadAuthorityQualificationCaseV1, ...]
    overall_disposition: str
    _seal: object

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        _reject(
            "unauthenticated_head_result_construction",
            "head qualification report construction is private",
        )

    def __post_init__(self) -> None:
        if (
            type(self) is not HeadAuthorityQualificationReportV1
            or self._seal is not _QUALIFICATION_REPORT_SEAL
        ):
            _reject(
                "unauthenticated_head_result_construction",
                "head qualification report construction is private",
            )
        if tuple(case.case_id for case in self.cases) != _HEAD_QUALIFICATION_CASE_IDS:
            _reject(
                "head_qualification_case_coverage_mismatch",
                "the report does not cover the exact ordered case roster",
            )

    @property
    def passed(self) -> bool:
        return self.overall_disposition == "qualified" and all(
            case.passed for case in self.cases
        )

    @property
    def report_id(self) -> str:
        return content_id("head_authority_qualification_report", self.to_body())

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


def _fixture_leaf(seed: bytes, label: str) -> bytes:
    return hashlib.sha256(
        b"etzio.head-authority.fixture-leaf.v1\x00" + label.encode("ascii") + b"\x00" + seed
    ).digest()


def create_repository_owned_head_authority_fixture_v1(
    *,
    seed: bytes,
    catalog_tree_size: int = 6,
    catalog_prior_tree_size: int = 4,
) -> RepositoryOwnedDeterministicHeadAuthorityFixtureV1:
    """Build complete deterministic keys, profile, logs, adapters, and vector from a seed."""

    if type(seed) is not bytes or not seed or len(seed) > MAX_HEAD_SEED_BYTES_V1:
        _reject(
            "invalid_head_seed",
            "head-authority fixture seed must be nonempty immutable bounded bytes",
        )
    if (
        type(catalog_tree_size) is not int
        or type(catalog_prior_tree_size) is not int
        or catalog_tree_size < 2
        or catalog_tree_size > MAX_HEAD_FIXTURE_LEAVES_V1
        or catalog_prior_tree_size < 1
        or catalog_prior_tree_size >= catalog_tree_size
    ):
        _reject(
            "invalid_head_qualification_fixture",
            "the fixture catalog tree requires a positive prefix below its size",
        )

    time_fixture = create_repository_owned_adapter_fixture_v1(seed=seed)
    time_vector = time_fixture.vector
    epoch = time_vector.expected_epoch_second

    validation_policy = IntegrityValidationPolicyV1(
        decision_policy_id=_fixture_content_id("decision-policy", "head-authority"),
        decision_time_policy_id=_fixture_content_id("decision-time-policy", "head-authority"),
        checkpoint_time_policy_id=_fixture_content_id(
            "checkpoint-time-policy", "head-authority"
        ),
        anchor_policy_id=_fixture_content_id("anchor-policy", "head-authority"),
        required_revocation_namespaces=frozenset({"authority"}),
        max_decision_uncertainty_seconds=4,
        max_checkpoint_uncertainty_seconds=4,
    )
    service_instance_id = "Etzio.head-authority-qualification-fixture"
    environment_id = "fixture.networkless-control-plane"
    catalog_log_origin = "fixture.catalog-log"

    specs: list[tuple[str, str, str]] = [
        ("fixture.anchor.a", HEAD_ANCHOR_ADAPTER_ROLE_V1, "fixture.anchor-log.a"),
        ("fixture.anchor.b", HEAD_ANCHOR_ADAPTER_ROLE_V1, "fixture.anchor-log.b"),
        ("fixture.catalog", HEAD_CATALOG_ADAPTER_ROLE_V1, catalog_log_origin),
        ("fixture.monitor.a", HEAD_MONITOR_ADAPTER_ROLE_V1, catalog_log_origin),
        ("fixture.monitor.b", HEAD_MONITOR_ADAPTER_ROLE_V1, catalog_log_origin),
    ]
    specs.sort(key=lambda value: (value[1], value[0]))

    signers: dict[str, HeadEvidenceSignerV1] = {}
    trusted_keys: list[TrustedHeadAuthorityKeyV1] = []
    bindings: list[HeadAuthoritySourceBindingV1] = []
    for source_id, role, log_origin in specs:
        signer = HeadEvidenceSignerV1.from_seed(
            source_id=source_id,
            principal_id=f"{source_id}.principal",
            role=role,
            seed=seed,
        )
        signers[source_id] = signer
        trusted_key = signer.trusted_key
        trusted_keys.append(trusted_key)
        bindings.append(
            HeadAuthoritySourceBindingV1(
                source_id=source_id,
                role=role,
                log_origin=log_origin,
                key_id=trusted_key.key_id,
                principal_id=trusted_key.principal_id,
                provider_policy_id=_fixture_content_id(
                    "provider-policy",
                    {"role": role, "source_id": source_id},
                ),
                codec_profile=_ROLE_TO_CODEC_V1[role],
            )
        )

    trust_store = HeadAuthorityTrustStoreV1.from_keys(trusted_keys)
    profile = HeadAuthorityTrustProfileV1(
        adapter_profile=REPOSITORY_OWNED_HEAD_AUTHORITY_PROFILE_V1,
        contract_version=HEAD_AUTHORITY_CONTRACT_VERSION_V1,
        service_instance_id=service_instance_id,
        environment_id=environment_id,
        validation_policy=validation_policy,
        validation_policy_id=_validation_policy_id(validation_policy),
        trust_store=trust_store,
        trust_root_id=trust_store.root_id,
        source_bindings=tuple(bindings),
        max_head_staleness_seconds=30,
    )

    expected_head = ExpectedHeadStateV1(
        prior_instance_sequence=6,
        prior_checkpoint_id=_fixture_content_id("prior-global-checkpoint", "head-authority"),
        prior_mission_event_seq=2,
        prior_mission_checkpoint_id=_fixture_content_id(
            "prior-mission-checkpoint", "head-authority"
        ),
        instance_sequence=7,
        checkpoint_id=_fixture_content_id("global-checkpoint", "head-authority"),
        checkpoint_attestation_id=_fixture_content_id(
            "global-checkpoint-attestation", "head-authority"
        ),
        checkpoint_principal_id="fixture.checkpoint.principal",
        checkpoint_trust_snapshot_id=_fixture_content_id(
            "checkpoint-trust-snapshot", "head-authority"
        ),
        mission_event_seq=3,
        mission_checkpoint_id=_fixture_content_id("mission-checkpoint", "head-authority"),
        mission_checkpoint_attestation_id=_fixture_content_id(
            "mission-checkpoint-attestation", "head-authority"
        ),
        mission_checkpoint_principal_id="fixture.mission-checkpoint.principal",
        mission_checkpoint_trust_snapshot_id=_fixture_content_id(
            "mission-checkpoint-trust-snapshot", "head-authority"
        ),
    )
    vector = HeadAuthorityQualificationVectorV1(
        service_instance_id=service_instance_id,
        environment_id=environment_id,
        mission_id=time_vector.mission_id,
        authority_id=time_vector.authority_id,
        target_id=time_vector.target_id,
        event_digest=time_vector.event_digest,
        transition_intent_id=time_vector.transition_intent_id,
        anchor_policy_id=validation_policy.anchor_policy_id,
        anchor_statement_id=_fixture_content_id("anchor-statement", "head-authority"),
        request_nonce=_fixture_nonce(seed, "head-qualification-vector"),
        expected_epoch_second=epoch,
        expected_head=expected_head,
    )

    catalog_leaves = tuple(
        _fixture_leaf(seed, f"catalog-{index}") for index in range(catalog_tree_size)
    )
    anchor_adapters: list[RepositoryOwnedDeterministicHeadAnchorAdapterV1] = []
    for binding in bindings:
        if binding.role != HEAD_ANCHOR_ADAPTER_ROLE_V1:
            continue
        anchor_adapters.append(
            RepositoryOwnedDeterministicHeadAnchorAdapterV1(
                profile=profile,
                binding=binding,
                signer=signers[binding.source_id],
                prefix_leaf_hashes=(
                    _fixture_leaf(seed, f"{binding.source_id}-prefix-0"),
                    _fixture_leaf(seed, f"{binding.source_id}-prefix-1"),
                ),
                suffix_leaf_hashes=(_fixture_leaf(seed, f"{binding.source_id}-suffix-0"),),
                registered_at=epoch - 10,
            )
        )

    catalog_binding = profile.catalog_binding
    catalog_adapter = RepositoryOwnedDeterministicHeadCatalogAdapterV1(
        profile=profile,
        binding=catalog_binding,
        signer=signers[catalog_binding.source_id],
        leaf_hashes=catalog_leaves,
        mission_id=vector.mission_id,
        head=expected_head,
        published_at=epoch - 10,
    )
    monitor_adapters: list[RepositoryOwnedDeterministicHeadMonitorAdapterV1] = []
    for binding in bindings:
        if binding.role != HEAD_MONITOR_ADAPTER_ROLE_V1:
            continue
        monitor_adapters.append(
            RepositoryOwnedDeterministicHeadMonitorAdapterV1(
                profile=profile,
                binding=binding,
                signer=signers[binding.source_id],
                leaf_hashes=catalog_leaves,
                witnessed_source_id=catalog_binding.source_id,
                observed_at=epoch - 5,
            )
        )

    adapter_implementation_id = _fixture_content_id(
        "adapter-implementation",
        {
            "contract_version": HEAD_AUTHORITY_CONTRACT_VERSION_V1,
            "profile": REPOSITORY_OWNED_HEAD_AUTHORITY_PROFILE_V1,
        },
    )
    prior_log_root_hash = _bytes_to_digest(
        merkle_root_v1(catalog_leaves[:catalog_prior_tree_size])
    )
    return RepositoryOwnedDeterministicHeadAuthorityFixtureV1(
        adapter_implementation_id=adapter_implementation_id,
        corpus_manifest_id=_head_qualification_manifest_id(
            adapter_implementation_id=adapter_implementation_id,
            profile=profile,
            vector=vector,
            anchor_adapters=tuple(anchor_adapters),
            catalog_adapter=catalog_adapter,
            monitor_adapters=tuple(monitor_adapters),
            prior_tree_size=catalog_prior_tree_size,
            prior_log_root_hash=prior_log_root_hash,
            anchor_prior_tree_size=1,
        ),
        profile=profile,
        vector=vector,
        time_fixture=time_fixture,
        anchor_adapters=tuple(anchor_adapters),
        catalog_adapter=catalog_adapter,
        monitor_adapters=tuple(monitor_adapters),
        prior_tree_size=catalog_prior_tree_size,
        prior_log_root_hash=prior_log_root_hash,
        anchor_prior_tree_size=1,
    )


def _head_case_result_id(case_id: str, reason_code: str, detail: object) -> str:
    return _fixture_content_id(
        "head-case-result",
        {"case_id": case_id, "detail": detail, "reason_code": reason_code},
    )


def _qualified_case(
    case_id: str,
    detail: object,
) -> HeadAuthorityQualificationCaseV1:
    return HeadAuthorityQualificationCaseV1(
        case_id=case_id,
        expected_disposition="qualified",
        observed_disposition="qualified",
        reason_code="head_qualification_success",
        result_id=_head_case_result_id(case_id, "head_qualification_success", detail),
    )


def _refused_case(
    case_id: str,
    expected_reason: str,
    operation: object,
) -> HeadAuthorityQualificationCaseV1:
    try:
        operation()  # type: ignore[operator]
    except HeadAuthorityAdapterError as exc:
        if exc.reason_code != expected_reason:
            raise HeadAuthorityAdapterError(
                "head_qualification_case_failed",
                f"{case_id} refused with an unexpected reason code",
            ) from exc
        return HeadAuthorityQualificationCaseV1(
            case_id=case_id,
            expected_disposition="refused",
            observed_disposition="refused",
            reason_code=exc.reason_code,
            result_id=_head_case_result_id(case_id, exc.reason_code, None),
        )
    _reject("head_expected_refusal", f"{case_id} did not refuse")
    raise AssertionError("unreachable")


def _fixture_time_bundle(
    fixture: RepositoryOwnedDeterministicHeadAuthorityFixtureV1,
) -> QualifiedTimeBundleV1:
    time_fixture = fixture.time_fixture
    vector = time_fixture.vector
    requests = {
        adapter.source_id: TrustedTimeRequestV1.issue(
            profile=time_fixture.profile,
            source_id=adapter.source_id,
            purpose="checkpoint",
            mission_id=vector.mission_id,
            authority_id=vector.authority_id,
            target_id=vector.target_id,
            event_digest=vector.event_digest,
            transition_intent_id=vector.transition_intent_id,
            imprint_id=_fixture_content_id("head-authority-imprint", "checkpoint"),
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


def _anchor_requests(
    fixture: RepositoryOwnedDeterministicHeadAuthorityFixtureV1,
    time_bundle: QualifiedTimeBundleV1,
    *,
    anchor_statement_id: str | None = None,
) -> dict[str, HeadAnchorRequestV1]:
    vector = fixture.vector
    return {
        adapter.source_id: HeadAnchorRequestV1.issue(
            profile=fixture.profile,
            source_id=adapter.source_id,
            mission_id=vector.mission_id,
            authority_id=vector.authority_id,
            target_id=vector.target_id,
            event_digest=vector.event_digest,
            transition_intent_id=vector.transition_intent_id,
            anchor_statement_id=anchor_statement_id or vector.anchor_statement_id,
            instance_sequence=vector.expected_head.instance_sequence,
            time_bundle=time_bundle,
            prior_tree_size=fixture.anchor_prior_tree_size,
            request_nonce=vector.request_nonce,
        )
        for adapter in fixture.anchor_adapters
    }


def _catalog_requests(
    fixture: RepositoryOwnedDeterministicHeadAuthorityFixtureV1,
    time_bundle: QualifiedTimeBundleV1,
    *,
    prior_tree_size: int | None = None,
) -> dict[str, HeadCatalogRequestV1]:
    vector = fixture.vector
    head = vector.expected_head
    sources: list[tuple[str, str]] = [
        (fixture.catalog_adapter.source_id, HEAD_CATALOG_ADAPTER_ROLE_V1)
    ]
    sources.extend(
        (adapter.source_id, HEAD_MONITOR_ADAPTER_ROLE_V1)
        for adapter in fixture.monitor_adapters
    )
    return {
        source_id: HeadCatalogRequestV1.issue(
            profile=fixture.profile,
            source_id=source_id,
            evidence_role=role,
            mission_id=vector.mission_id,
            authority_id=vector.authority_id,
            target_id=vector.target_id,
            event_digest=vector.event_digest,
            transition_intent_id=vector.transition_intent_id,
            time_bundle=time_bundle,
            prior_tree_size=(
                fixture.prior_tree_size if prior_tree_size is None else prior_tree_size
            ),
            prior_log_root_hash=fixture.prior_log_root_hash,
            prior_instance_sequence=head.prior_instance_sequence,
            prior_checkpoint_id=head.prior_checkpoint_id,
            prior_mission_event_seq=head.prior_mission_event_seq,
            prior_mission_checkpoint_id=head.prior_mission_checkpoint_id,
            request_nonce=vector.request_nonce,
        )
        for source_id, role in sources
    }


def _catalog_adapters(
    fixture: RepositoryOwnedDeterministicHeadAuthorityFixtureV1,
) -> dict[str, object]:
    adapters: dict[str, object] = {
        fixture.catalog_adapter.source_id: fixture.catalog_adapter
    }
    for adapter in fixture.monitor_adapters:
        adapters[adapter.source_id] = adapter
    return adapters


def qualify_repository_head_authority_adapters_v1(
    fixture: RepositoryOwnedDeterministicHeadAuthorityFixtureV1,
) -> HeadAuthorityQualificationReportV1:
    """Execute the fixed deterministic head-authority qualification roster."""

    if type(fixture) is not RepositoryOwnedDeterministicHeadAuthorityFixtureV1:
        _reject(
            "invalid_head_qualification_fixture",
            "qualification requires an exact deterministic head-authority fixture",
        )
    profile = fixture.profile
    time_profile = fixture.time_fixture.profile
    time_bundle = _fixture_time_bundle(fixture)
    cases: list[HeadAuthorityQualificationCaseV1] = []

    anchor_requests = _anchor_requests(fixture, time_bundle)
    anchor_signed = {
        adapter.source_id: adapter.acquire(anchor_requests[adapter.source_id])
        for adapter in fixture.anchor_adapters
    }
    anchor_bundle = qualify_anchor_bundle_v1(
        profile=profile,
        time_profile=time_profile,
        time_bundle=time_bundle,
        requests=anchor_requests,
        signed_evidence=anchor_signed,
    )
    cases.append(
        _qualified_case("anchor_registration_qualifies", anchor_bundle.bundle_id)
    )

    retry_signed = {
        adapter.source_id: adapter.acquire(anchor_requests[adapter.source_id])
        for adapter in fixture.anchor_adapters
    }
    for source_id, signed in retry_signed.items():
        if signed.to_canonical_bytes() != anchor_signed[source_id].to_canonical_bytes():
            _reject(
                "head_retry_nondeterministic",
                "an anchor adapter produced different bytes for the exact same request",
            )
    retry_bundle = qualify_anchor_bundle_v1(
        profile=profile,
        time_profile=time_profile,
        time_bundle=time_bundle,
        requests=anchor_requests,
        signed_evidence=retry_signed,
    )
    if retry_bundle.to_body() != anchor_bundle.to_body():
        _reject(
            "head_exact_retry_result",
            "exact anchor retry did not reproduce the qualified bundle",
        )
    cases.append(
        _qualified_case("anchor_exact_retry_is_byte_stable", retry_bundle.bundle_id)
    )

    anchor_sources = tuple(sorted(anchor_signed))
    swapped = dict(anchor_signed)
    swapped[anchor_sources[0]] = anchor_signed[anchor_sources[1]]
    swapped[anchor_sources[1]] = anchor_signed[anchor_sources[0]]
    cases.append(
        _refused_case(
            "anchor_cross_request_replay_refused",
            "head_source_mismatch",
            lambda: qualify_anchor_bundle_v1(
                profile=profile,
                time_profile=time_profile,
                time_bundle=time_bundle,
                requests=anchor_requests,
                signed_evidence=swapped,
            ),
        )
    )

    foreign_requests = _anchor_requests(
        fixture,
        time_bundle,
        anchor_statement_id=_fixture_content_id("foreign-anchor-statement", "head-authority"),
    )
    foreign_signed = {
        adapter.source_id: adapter.acquire(foreign_requests[adapter.source_id])
        for adapter in fixture.anchor_adapters
    }
    cases.append(
        _refused_case(
            "anchor_foreign_statement_receipt_refused",
            "head_request_mismatch",
            lambda: qualify_anchor_bundle_v1(
                profile=profile,
                time_profile=time_profile,
                time_bundle=time_bundle,
                requests=anchor_requests,
                signed_evidence=foreign_signed,
            ),
        )
    )

    adapters = _catalog_adapters(fixture)
    catalog_requests = _catalog_requests(fixture, time_bundle)
    catalog_signed = {
        source_id: adapter.acquire(catalog_requests[source_id])  # type: ignore[union-attr]
        for source_id, adapter in adapters.items()
    }
    catalog_bundle = qualify_head_catalog_bundle_v1(
        profile=profile,
        time_profile=time_profile,
        time_bundle=time_bundle,
        requests=catalog_requests,
        signed_evidence=catalog_signed,
    )
    cases.append(_qualified_case("catalog_head_qualifies", catalog_bundle.bundle_id))

    catalog_retry = {
        source_id: adapter.acquire(catalog_requests[source_id])  # type: ignore[union-attr]
        for source_id, adapter in adapters.items()
    }
    for source_id, signed in catalog_retry.items():
        if signed.to_canonical_bytes() != catalog_signed[source_id].to_canonical_bytes():
            _reject(
                "head_retry_nondeterministic",
                "a catalog adapter produced different bytes for the exact same request",
            )
    retry_catalog_bundle = qualify_head_catalog_bundle_v1(
        profile=profile,
        time_profile=time_profile,
        time_bundle=time_bundle,
        requests=catalog_requests,
        signed_evidence=catalog_retry,
    )
    if retry_catalog_bundle.to_body() != catalog_bundle.to_body():
        _reject(
            "head_exact_retry_result",
            "exact catalog retry did not reproduce the qualified bundle",
        )
    cases.append(
        _qualified_case("catalog_exact_retry_is_byte_stable", retry_catalog_bundle.bundle_id)
    )

    rollback_requests = _catalog_requests(
        fixture,
        time_bundle,
        prior_tree_size=len(fixture.catalog_adapter.leaf_hashes) + 3,
    )
    rollback_signed = {
        source_id: adapter.acquire(rollback_requests[source_id])  # type: ignore[union-attr]
        for source_id, adapter in adapters.items()
    }
    cases.append(
        _refused_case(
            "catalog_tree_rollback_refused",
            "head_catalog_tree_rollback",
            lambda: qualify_head_catalog_bundle_v1(
                profile=profile,
                time_profile=time_profile,
                time_bundle=time_bundle,
                requests=rollback_requests,
                signed_evidence=rollback_signed,
            ),
        )
    )

    split_monitor = fixture.monitor_adapters[0]
    split_view_adapter = RepositoryOwnedDeterministicHeadMonitorAdapterV1(
        profile=split_monitor.profile,
        binding=split_monitor.binding,
        signer=split_monitor.signer,
        leaf_hashes=(
            *fixture.catalog_adapter.leaf_hashes,
            _fixture_leaf(b"etzio-head-authority-split-view", "extra"),
        ),
        witnessed_source_id=split_monitor.witnessed_source_id,
        observed_at=split_monitor.observed_at,
    )
    split_signed = dict(catalog_signed)
    split_signed[split_monitor.source_id] = split_view_adapter.acquire(
        catalog_requests[split_monitor.source_id]
    )
    cases.append(
        _refused_case(
            "monitor_split_view_refused",
            "head_catalog_equivocation",
            lambda: qualify_head_catalog_bundle_v1(
                profile=profile,
                time_profile=time_profile,
                time_bundle=time_bundle,
                requests=catalog_requests,
                signed_evidence=split_signed,
            ),
        )
    )

    mapping = map_qualified_head_authority_inputs_v1(
        profile=profile,
        time_profile=time_profile,
        time_bundle=time_bundle,
        anchor_bundle=anchor_bundle,
        catalog_bundle=catalog_bundle,
    )
    cases.append(
        _qualified_case("provider_neutral_mapping_complete", mapping.mapping_id)
    )

    ordered = tuple(cases)
    return _construct_sealed_result(
        HeadAuthorityQualificationReportV1,
        seal=_QUALIFICATION_REPORT_SEAL,
        values={
            "contract_version": HEAD_AUTHORITY_CONTRACT_VERSION_V1,
            "adapter_implementation_id": fixture.adapter_implementation_id,
            "profile_id": profile.profile_id,
            "vector_id": fixture.vector.vector_id,
            "corpus_manifest_id": fixture.corpus_manifest_id,
            "cases": ordered,
            "overall_disposition": (
                "qualified" if all(case.passed for case in ordered) else "refused"
            ),
        },
    )


__all__ = (
    "HEAD_ANCHOR_ADAPTER_ROLE_V1",
    "HEAD_AUTHORITY_ADAPTER_ROLES_V1",
    "HEAD_AUTHORITY_CONTRACT_VERSION_V1",
    "HEAD_CATALOG_ADAPTER_ROLE_V1",
    "HEAD_MONITOR_ADAPTER_ROLE_V1",
    "REPOSITORY_OWNED_HEAD_AUTHORITY_PROFILE_V1",
    "AnchorRegistrationLeafV1",
    "AuthenticatedHeadEvidencePackageV1",
    "ExpectedHeadStateV1",
    "HeadAnchorAdapterV1",
    "HeadAnchorRequestV1",
    "HeadAuthorityAdapterError",
    "HeadAuthorityQualificationCaseV1",
    "HeadAuthorityQualificationReportV1",
    "HeadAuthorityQualificationVectorV1",
    "HeadAuthoritySourceBindingV1",
    "HeadAuthorityTrustProfileV1",
    "HeadAuthorityTrustStoreV1",
    "HeadCatalogAdapterV1",
    "HeadCatalogRequestV1",
    "HeadEvidenceSignerV1",
    "HeadProviderStatementV1",
    "QualifiedAnchorBundleV1",
    "QualifiedHeadAuthorityInputsV1",
    "QualifiedHeadCatalogBundleV1",
    "RepositoryOwnedDeterministicHeadAnchorAdapterV1",
    "RepositoryOwnedDeterministicHeadAuthorityFixtureV1",
    "RepositoryOwnedDeterministicHeadCatalogAdapterV1",
    "RepositoryOwnedDeterministicHeadMonitorAdapterV1",
    "SignedHeadEvidenceV1",
    "TrustedHeadAuthorityKeyV1",
    "authenticate_head_evidence_v1",
    "create_repository_owned_head_authority_fixture_v1",
    "map_qualified_head_authority_inputs_v1",
    "merkle_consistency_proof_v1",
    "merkle_inclusion_proof_v1",
    "merkle_leaf_hash_v1",
    "merkle_root_v1",
    "qualify_anchor_bundle_v1",
    "qualify_head_catalog_bundle_v1",
    "qualify_repository_head_authority_adapters_v1",
    "reauthenticate_anchor_bundle_v1",
    "reauthenticate_head_catalog_bundle_v1",
    "verify_merkle_consistency_v1",
    "verify_merkle_inclusion_v1",
)
