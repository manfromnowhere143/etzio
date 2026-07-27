"""Strict canonicalization and the common Etzio protocol-v1 envelope."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final, TypeAlias

import unicodedata2 as unicodedata

JsonScalar: TypeAlias = None | bool | int | str
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
FrozenJsonValue: TypeAlias = JsonScalar | tuple["FrozenJsonValue", ...] | MappingProxyType

PROTOCOL_VERSION = 1
OBJECT_VERSION = 1
UNICODE_VERSION = "17.0.0"
MAX_WIRE_BYTES = 16 * 1024 * 1024
MAX_STRING_CODEPOINTS = 1_000_000
MAX_KEY_CODEPOINTS = 128
MAX_CONTAINER_ITEMS = 10_000
MAX_TOTAL_NODES = 100_000
MAX_NESTING_DEPTH = 64
MIN_INTEGER = -(2**63)
MAX_INTEGER = (2**63) - 1
RESERVED_OBJECT_KINDS = frozenset({"head_checkpoint"})
SEMANTIC_OBJECT_KINDS = frozenset(
    {
        "analysis_lease",
        "authority_admission",
        "authority_grant",
        "candidate",
        "event",
        "target_snapshot",
        "verification_lease",
        "verifier_receipt",
    }
)
SUPPORTED_OBJECT_KINDS = SEMANTIC_OBJECT_KINDS
OPTIONALLY_ATTESTED_OBJECT_KINDS_V1: Final = frozenset(
    {"authority_grant", "verifier_receipt"}
)
ENVELOPE_FIELDS_V1: Final = frozenset(
    {
        "attestations",
        "body",
        "object_id",
        "object_kind",
        "object_version",
        "protocol_version",
    }
)
SEMANTIC_BODY_FIELDS_BY_KIND_V1: Final = MappingProxyType(
    {
        "analysis_lease": frozenset(
            {
                "action",
                "authority_id",
                "expires_at",
                "issued_at",
                "lease_nonce",
                "max_bytes",
                "max_candidates",
                "max_wallclock_seconds",
                "mission_id",
                "target_snapshot_id",
                "worker_identity",
            }
        ),
        "authority_admission": frozenset(
            {
                "authority_id",
                "decision_time",
                "grant_expires_at",
                "required_actions",
                "signer_key_id",
                "signed_grant",
                "target_snapshot_id",
                "trust_snapshot",
                "trust_snapshot_id",
            }
        ),
        "authority_grant": frozenset(
            {
                "assets",
                "evidence_digest",
                "expires_at",
                "issued_at",
                "issuer",
                "max_bytes",
                "max_candidates",
                "max_wallclock_seconds",
                "not_before",
                "permitted_actions",
                "subject",
                "target_snapshot_id",
            }
        ),
        "candidate": frozenset(
            {
                "analysis_lease_id",
                "analyzer_version",
                "authority_id",
                "claim_id",
                "column",
                "line",
                "mission_id",
                "producer_identity",
                "relative_path",
                "rule_id",
                "severity",
                "source_artifact_digest",
                "symbol",
                "target_snapshot_id",
            }
        ),
        "event": frozenset(
            {
                "authority_id",
                "decision_time",
                "kind",
                "mission_id",
                "payload",
                "prev_digest",
                "seq",
                "target_id",
                "unit",
            }
        ),
        "target_snapshot": frozenset({"files", "source"}),
        "verification_lease": frozenset(
            {
                "authority_id",
                "candidate_id",
                "candidate_producer_id",
                "effect_oracle_id",
                "environment_digest",
                "evidence_artifact_digests",
                "expires_at",
                "issued_at",
                "lease_nonce",
                "mission_id",
                "poc_artifact_digest",
                "purpose",
                "target_snapshot_id",
                "verifier_id",
                "verifier_key_id",
            }
        ),
        "verifier_receipt": frozenset(
            {
                "authority_id",
                "candidate_id",
                "candidate_producer_id",
                "completed_at",
                "effect_observed",
                "effect_oracle_id",
                "environment_digest",
                "evidence_artifact_digests",
                "evidence_tier",
                "lease_id",
                "mission_id",
                "oracle_satisfied",
                "poc_artifact_digest",
                "target_snapshot_id",
                "verdict",
                "verifier_id",
                "verifier_key_id",
            }
        ),
    }
)

_CONTENT_DOMAIN = b"etzio.protocol.v1\x00"
_KEY_PATTERN = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$", re.ASCII)
_CONTENT_ID_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
if unicodedata.unidata_version != UNICODE_VERSION:  # pragma: no cover - dependency invariant
    raise RuntimeError(f"Etzio protocol v1 requires Unicode {UNICODE_VERSION}, got {unicodedata.unidata_version}")


class ProtocolError(ValueError):
    """A value or wire representation violates Etzio protocol v1."""

    def __init__(self, message: str, *, code: str = "invalid_protocol") -> None:
        super().__init__(message)
        self.code = code


def _validate_string(value: str, path: str) -> str:
    if len(value) > MAX_STRING_CODEPOINTS:
        raise ProtocolError(f"{path}: string exceeds the protocol length ceiling")
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise ProtocolError(f"{path}: Unicode surrogate code points are forbidden")
    if unicodedata.normalize("NFC", value) != value:
        raise ProtocolError(f"{path}: strings must already be NFC-normalized")
    return value


def _validate_key(key: object, path: str) -> str:
    if type(key) is not str:
        raise ProtocolError(f"{path}: object keys must be strings")
    _validate_string(key, path)
    if len(key) > MAX_KEY_CODEPOINTS:
        raise ProtocolError(f"{path}: object key exceeds the protocol length ceiling")
    if _KEY_PATTERN.fullmatch(key) is None:
        raise ProtocolError(f"{path}: object keys must be ASCII snake_case")
    return key


def _normalize_json(
    value: object,
    path: str = "$",
    *,
    _depth: int = 0,
    _node_count: list[int] | None = None,
) -> JsonValue:
    if _depth > MAX_NESTING_DEPTH:
        raise ProtocolError(f"{path}: value exceeds the protocol nesting ceiling")
    if _node_count is None:
        _node_count = [0]
    _node_count[0] += 1
    if _node_count[0] > MAX_TOTAL_NODES:
        raise ProtocolError(f"{path}: value exceeds the protocol node-count ceiling")
    if value is None or type(value) is bool:
        return value  # type: ignore[return-value]
    if type(value) is int:
        if value < MIN_INTEGER or value > MAX_INTEGER:
            raise ProtocolError(f"{path}: integer exceeds the signed 64-bit protocol range")
        return value
    if type(value) is str:
        return _validate_string(value, path)
    if type(value) in {list, tuple}:
        if len(value) > MAX_CONTAINER_ITEMS:
            raise ProtocolError(f"{path}: array exceeds the protocol item-count ceiling")
        return [
            _normalize_json(
                item,
                f"{path}[{index}]",
                _depth=_depth + 1,
                _node_count=_node_count,
            )
            for index, item in enumerate(value)
        ]
    if type(value) in {dict, MappingProxyType}:
        if len(value) > MAX_CONTAINER_ITEMS:
            raise ProtocolError(f"{path}: object exceeds the protocol member-count ceiling")
        normalized: dict[str, JsonValue] = {}
        for raw_key, item in value.items():  # type: ignore[union-attr]
            key = _validate_key(raw_key, f"{path}.<key>")
            normalized[key] = _normalize_json(
                item,
                f"{path}.{key}",
                _depth=_depth + 1,
                _node_count=_node_count,
            )
        return {key: normalized[key] for key in sorted(normalized)}
    raise ProtocolError(f"{path}: unsupported JSON value type {type(value).__name__!r}")


def canonical_dumps(value: object) -> bytes:
    """Return the one canonical UTF-8 representation of a protocol JSON value."""

    try:
        normalized = _normalize_json(value)
        text = json.dumps(
            normalized,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        encoded = text.encode("utf-8")
        if len(encoded) > MAX_WIRE_BYTES:
            raise ProtocolError("canonical JSON exceeds the protocol wire-byte ceiling")
        return encoded
    except ProtocolError:
        raise
    except (RecursionError, UnicodeError, ValueError) as error:
        raise ProtocolError("value cannot be represented as protocol JSON") from error


def _reject_float(token: str) -> Any:
    raise ProtocolError(f"floating-point number {token!r} is forbidden")


def _reject_constant(token: str) -> Any:
    raise ProtocolError(f"non-standard numeric constant {token!r} is forbidden")


def _parse_int(token: str) -> int:
    digits = token[1:] if token.startswith("-") else token
    if len(digits) > 19:
        raise ProtocolError("integer exceeds the signed 64-bit protocol range")
    value = int(token)
    if value < MIN_INTEGER or value > MAX_INTEGER:
        raise ProtocolError("integer exceeds the signed 64-bit protocol range")
    return value


def _unique_object(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    value: dict[str, JsonValue] = {}
    for key, item in pairs:
        if key in value:
            raise ProtocolError(f"duplicate object key {key!r}")
        value[key] = item
    return value


def strict_loads(data: bytes | str) -> JsonValue:
    """Decode JSON while rejecting ambiguous or non-protocol representations."""

    if type(data) is bytes:
        if len(data) > MAX_WIRE_BYTES:
            raise ProtocolError("wire input exceeds the protocol byte ceiling")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ProtocolError("wire bytes must be valid UTF-8") from error
    elif type(data) is str:
        try:
            encoded = data.encode("utf-8")
        except UnicodeEncodeError as error:
            raise ProtocolError("wire text must be valid Unicode") from error
        if len(encoded) > MAX_WIRE_BYTES:
            raise ProtocolError("wire input exceeds the protocol byte ceiling")
        text = data
    else:
        raise ProtocolError("wire input must be bytes or str")

    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=_reject_float,
            parse_int=_parse_int,
        )
        return _normalize_json(value)
    except ProtocolError:
        raise
    except (json.JSONDecodeError, RecursionError, UnicodeError, ValueError) as error:
        raise ProtocolError("invalid protocol JSON") from error


def _freeze_normalized(value: JsonValue) -> FrozenJsonValue:
    if type(value) is dict:
        return MappingProxyType({key: _freeze_normalized(item) for key, item in value.items()})
    if type(value) is list:
        return tuple(_freeze_normalized(item) for item in value)
    return value  # type: ignore[return-value]


def freeze_json(value: object) -> FrozenJsonValue:
    """Validate and return a deeply immutable protocol JSON value."""

    try:
        return _freeze_normalized(_normalize_json(value))
    except RecursionError as error:
        raise ProtocolError("value is too deeply nested") from error


def thaw_json(value: object) -> JsonValue:
    """Return a fresh mutable JSON representation of a protocol value."""

    try:
        return _normalize_json(value)
    except RecursionError as error:
        raise ProtocolError("value is too deeply nested") from error


def _validate_kind(kind: object, *, supported_only: bool) -> str:
    if type(kind) is not str or _KEY_PATTERN.fullmatch(kind) is None:
        raise ProtocolError("object kind must be an ASCII snake_case string")
    if supported_only and kind not in SUPPORTED_OBJECT_KINDS:
        raise ProtocolError(f"unsupported protocol-v1 object kind {kind!r}")
    return kind


def content_id(kind: str, value: object) -> str:
    """Return a full, v1-and-kind-domain-separated SHA-256 content identity."""

    valid_kind = _validate_kind(kind, supported_only=False)
    semantic_bytes = canonical_dumps(value)
    digest = hashlib.sha256(_CONTENT_DOMAIN + valid_kind.encode("ascii") + b"\x00" + semantic_bytes).hexdigest()
    return f"sha256:{digest}"


@dataclass(frozen=True, slots=True, init=False)
class EnvelopeV1:
    """Deeply immutable common envelope for an Etzio protocol-v1 object."""

    protocol_version: int
    object_kind: str
    object_version: int
    object_id: str
    body: MappingProxyType
    attestations: tuple[MappingProxyType, ...]

    @classmethod
    def _build(
        cls,
        *,
        object_kind: str,
        object_id: str,
        body: MappingProxyType,
        attestations: tuple[MappingProxyType, ...],
    ) -> EnvelopeV1:
        envelope = object.__new__(cls)
        object.__setattr__(envelope, "protocol_version", PROTOCOL_VERSION)
        object.__setattr__(envelope, "object_kind", object_kind)
        object.__setattr__(envelope, "object_version", OBJECT_VERSION)
        object.__setattr__(envelope, "object_id", object_id)
        object.__setattr__(envelope, "body", body)
        object.__setattr__(envelope, "attestations", attestations)
        return envelope

    @classmethod
    def create(
        cls,
        object_kind: str,
        body: object,
        *,
        attestations: object = (),
    ) -> EnvelopeV1:
        """Validate values, compute the semantic ID, and create an envelope."""

        kind = _validate_kind(object_kind, supported_only=True)
        frozen_body = freeze_json(body)
        if type(frozen_body) is not MappingProxyType:
            raise ProtocolError("envelope body must be a JSON object")

        frozen_attestations = freeze_json(attestations)
        if type(frozen_attestations) is not tuple or any(
            type(attestation) is not MappingProxyType for attestation in frozen_attestations
        ):
            raise ProtocolError("envelope attestations must be an array of JSON objects")
        if len(frozen_attestations) > 16:
            raise ProtocolError("envelope exceeds the attestation-count ceiling")

        envelope = cls._build(
            object_kind=kind,
            object_id=content_id(kind, frozen_body),
            body=frozen_body,
            attestations=frozen_attestations,
        )
        # Revalidate the complete envelope under one node/size budget; validating body and
        # attestations independently must not permit a combined object over the v1 ceiling.
        canonical_dumps(envelope.to_dict())
        return envelope

    @classmethod
    def from_bytes(cls, data: bytes | str) -> EnvelopeV1:
        """Parse and validate a complete envelope, including its semantic ID."""

        if type(data) is bytes:
            supplied_bytes = data
        elif type(data) is str:
            try:
                supplied_bytes = data.encode("utf-8")
            except UnicodeEncodeError as error:
                raise ProtocolError("wire text must be valid Unicode") from error
        else:
            raise ProtocolError("wire input must be bytes or str")
        decoded = strict_loads(data)
        if type(decoded) is not dict:
            raise ProtocolError("protocol envelope must be a JSON object")

        fields = frozenset(decoded)
        unknown = sorted(fields - ENVELOPE_FIELDS_V1)
        missing = sorted(ENVELOPE_FIELDS_V1 - fields)
        if unknown:
            raise ProtocolError(f"unknown envelope fields: {', '.join(unknown)}")
        if missing:
            raise ProtocolError(f"missing envelope fields: {', '.join(missing)}")

        if type(decoded["protocol_version"]) is not int or decoded["protocol_version"] != PROTOCOL_VERSION:
            raise ProtocolError("unsupported protocol version")
        if type(decoded["object_version"]) is not int or decoded["object_version"] != OBJECT_VERSION:
            raise ProtocolError("unsupported object version")

        kind = _validate_kind(decoded["object_kind"], supported_only=True)
        supplied_id = decoded["object_id"]
        if type(supplied_id) is not str or _CONTENT_ID_PATTERN.fullmatch(supplied_id) is None:
            raise ProtocolError("malformed object_id")
        if type(decoded["body"]) is not dict:
            raise ProtocolError("envelope body must be a JSON object")
        if type(decoded["attestations"]) is not list or any(
            type(attestation) is not dict for attestation in decoded["attestations"]
        ):
            raise ProtocolError("envelope attestations must be an array of JSON objects")

        envelope = cls.create(
            kind,
            decoded["body"],
            attestations=decoded["attestations"],
        )
        if not hmac.compare_digest(supplied_id, envelope.object_id):
            raise ProtocolError(
                "object_id does not match the canonical semantic body",
                code="object_id_mismatch",
            )
        if supplied_bytes != envelope.to_bytes():
            raise ProtocolError(
                "protocol envelope bytes are not canonical",
                code="noncanonical_envelope",
            )
        return envelope

    def to_dict(self) -> dict[str, JsonValue]:
        """Return a fresh mutable wire object."""

        return {
            "protocol_version": self.protocol_version,
            "object_kind": self.object_kind,
            "object_version": self.object_version,
            "object_id": self.object_id,
            "body": thaw_json(self.body),
            "attestations": thaw_json(self.attestations),
        }

    def to_bytes(self) -> bytes:
        """Return the canonical wire bytes for this envelope."""

        return canonical_dumps(self.to_dict())
