"""Signed, fail-closed authority admission for the Etzio foundation.

An admitted signature proves only that a configured Etzio operator key captured this
exact grant envelope. It does not prove that a bug-bounty program, asset owner, court, or
other third party granted permission, and it is not a substitute for legal review.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from etzio.crypto_v1 import is_valid_ed25519_public_key
from etzio.protocol import (
    SEMANTIC_BODY_FIELDS_BY_KIND_V1,
    EnvelopeV1,
    ProtocolError,
    canonical_dumps,
    content_id,
    strict_loads,
    thaw_json,
)

AUTHORITY_OBJECT_KIND: Final = "authority_grant"
OPERATOR_ROLE: Final = "operator"
PERMITTED_ACTIONS: Final = frozenset({"static_analysis", "modeled_fixture_verification"})

# Foundation limits are absolute admission ceilings, not defaults or recommendations.
MAX_BYTES_HARD_CEILING: Final = 1 << 30
MAX_CANDIDATES_HARD_CEILING: Final = 100_000
MAX_WALLCLOCK_SECONDS_HARD_CEILING: Final = 86_400
MAX_AUTHORITY_ENVELOPE_BYTES: Final = 1 << 20
MAX_TRUSTED_AUTHORITY_KEYS: Final = 64
MAX_AUTHORITY_REVOCATIONS: Final = 10_000

_SIGNATURE_DOMAIN: Final = b"etzio.authority-grant.signature.v1\x00"
_FULL_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_KEY_ID = re.compile(r"^ed25519:sha256:[0-9a-f]{64}$")
_GRANT_BODY_FIELDS: Final = SEMANTIC_BODY_FIELDS_BY_KIND_V1["authority_grant"]
_SIGNED_FIELDS: Final = frozenset({"envelope_bytes", "key_id", "signature_b64"})
_ATTESTATION_FIELDS: Final = frozenset({"algorithm", "key_id", "signature_b64"})
_ADMISSION_BODY_FIELDS: Final = SEMANTIC_BODY_FIELDS_BY_KIND_V1["authority_admission"]


class AuthorityError(ValueError):
    """A deterministic authority construction or validation failure."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class AuthorityGrantV1:
    """One exact, expiring authority snapshot bound to a protocol object ID."""

    grant_id: str
    issuer: str
    subject: str
    target_snapshot_id: str
    assets: tuple[str, ...]
    permitted_actions: tuple[str, ...]
    evidence_digest: str
    issued_at: int
    not_before: int
    expires_at: int
    max_bytes: int
    max_candidates: int
    max_wallclock_seconds: int

    def __post_init__(self) -> None:
        if type(self.grant_id) is not str or not _FULL_DIGEST.fullmatch(self.grant_id):
            raise AuthorityError("invalid_grant_id", "grant_id must be a full sha256 content ID")
        _validate_semantics(self._body())
        try:
            canonical_id = EnvelopeV1.create(AUTHORITY_OBJECT_KIND, _wire_body(self._body())).object_id
        except ProtocolError as exc:
            raise AuthorityError("invalid_grant", "grant cannot be represented by protocol v1") from exc
        if self.grant_id != canonical_id:
            raise AuthorityError("object_id_mismatch", "grant_id does not match canonical grant semantics")

    @classmethod
    def issue(
        cls,
        *,
        issuer: str,
        subject: str,
        target_snapshot_id: str,
        assets: tuple[str, ...],
        permitted_actions: tuple[str, ...],
        evidence_digest: str,
        issued_at: int,
        not_before: int,
        expires_at: int,
        max_bytes: int,
        max_candidates: int,
        max_wallclock_seconds: int,
    ) -> AuthorityGrantV1:
        """Create a grant whose identity is the canonical protocol-envelope identity."""

        values = {
            "issuer": issuer,
            "subject": subject,
            "target_snapshot_id": target_snapshot_id,
            "assets": assets,
            "permitted_actions": permitted_actions,
            "evidence_digest": evidence_digest,
            "issued_at": issued_at,
            "not_before": not_before,
            "expires_at": expires_at,
            "max_bytes": max_bytes,
            "max_candidates": max_candidates,
            "max_wallclock_seconds": max_wallclock_seconds,
        }
        if type(assets) is tuple and all(type(asset) is str for asset in assets):
            values["assets"] = tuple(sorted(assets))
        if type(permitted_actions) is tuple and all(
            type(action) is str for action in permitted_actions
        ):
            values["permitted_actions"] = tuple(sorted(permitted_actions))
        _validate_semantics(values)
        try:
            envelope = EnvelopeV1.create(AUTHORITY_OBJECT_KIND, _wire_body(values))
        except ProtocolError as exc:
            raise AuthorityError("invalid_grant", "grant cannot be represented by protocol v1") from exc
        return cls(grant_id=envelope.object_id, **values)

    @classmethod
    def from_envelope(cls, envelope: EnvelopeV1) -> AuthorityGrantV1:
        if envelope.object_kind != AUTHORITY_OBJECT_KIND:
            raise AuthorityError("wrong_object_kind", "envelope is not an authority grant")
        if envelope.attestations:
            raise AuthorityError("unexpected_attestations", "authority grant envelope attestations must be empty")

        raw_body = thaw_json(envelope.body)
        if type(raw_body) is not dict or set(raw_body) != _GRANT_BODY_FIELDS:
            raise AuthorityError("malformed_grant", "authority grant body has missing or unknown fields")
        if type(raw_body["assets"]) is not list or type(raw_body["permitted_actions"]) is not list:
            raise AuthorityError("malformed_grant", "authority grant scopes must be JSON arrays")

        values = {
            **raw_body,
            "assets": tuple(raw_body["assets"]),
            "permitted_actions": tuple(raw_body["permitted_actions"]),
        }
        _validate_semantics(values)
        return cls(grant_id=envelope.object_id, **values)

    def to_envelope(self) -> EnvelopeV1:
        envelope = EnvelopeV1.create(AUTHORITY_OBJECT_KIND, _wire_body(self._body()))
        if envelope.object_id != self.grant_id:
            raise AuthorityError("object_id_mismatch", "grant_id does not match canonical grant semantics")
        return envelope

    def _body(self) -> dict[str, object]:
        return {
            "issuer": self.issuer,
            "subject": self.subject,
            "target_snapshot_id": self.target_snapshot_id,
            "assets": self.assets,
            "permitted_actions": self.permitted_actions,
            "evidence_digest": self.evidence_digest,
            "issued_at": self.issued_at,
            "not_before": self.not_before,
            "expires_at": self.expires_at,
            "max_bytes": self.max_bytes,
            "max_candidates": self.max_candidates,
            "max_wallclock_seconds": self.max_wallclock_seconds,
        }


@dataclass(frozen=True, slots=True)
class SignedAuthorityGrantV1:
    """Canonical grant envelope bytes plus a detached Ed25519 signature."""

    envelope_bytes: bytes
    key_id: str
    signature_b64: str

    def __post_init__(self) -> None:
        if type(self.envelope_bytes) is not bytes or not self.envelope_bytes:
            raise AuthorityError("malformed_signed_object", "envelope_bytes must be non-empty bytes")
        if len(self.envelope_bytes) > MAX_AUTHORITY_ENVELOPE_BYTES:
            raise AuthorityError(
                "authority_envelope_too_large",
                "authority envelope exceeds the fixed byte ceiling",
            )
        if type(self.key_id) is not str or not _KEY_ID.fullmatch(self.key_id):
            raise AuthorityError("malformed_key_id", "key_id must be content-derived from an Ed25519 public key")
        if type(self.signature_b64) is not str or len(self.signature_b64) != 88:
            raise AuthorityError(
                "malformed_signature",
                "signature_b64 must be one canonical Ed25519 signature",
            )
        try:
            signature = base64.b64decode(self.signature_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise AuthorityError(
                "malformed_signature",
                "signature_b64 must be one canonical Ed25519 signature",
            ) from exc
        if (
            len(signature) != 64
            or base64.b64encode(signature).decode("ascii") != self.signature_b64
        ):
            raise AuthorityError(
                "malformed_signature",
                "signature_b64 must be one canonical Ed25519 signature",
            )

    def as_raw(self) -> Mapping[str, object]:
        """Return the legacy in-process shape accepted by :func:`admit_authority`."""

        return MappingProxyType(
            {
                "envelope_bytes": self.envelope_bytes,
                "key_id": self.key_id,
                "signature_b64": self.signature_b64,
            }
        )

    def to_envelope(self) -> EnvelopeV1:
        """Return the canonical protocol envelope with one detached-signature attestation."""
        try:
            grant_envelope = EnvelopeV1.from_bytes(self.envelope_bytes)
        except ProtocolError as exc:
            raise AuthorityError("invalid_envelope", "signed grant envelope is invalid") from exc
        if grant_envelope.object_kind != AUTHORITY_OBJECT_KIND or grant_envelope.attestations:
            raise AuthorityError(
                "invalid_envelope",
                "signed authority input must contain one unattested grant envelope",
            )
        AuthorityGrantV1.from_envelope(grant_envelope)
        return EnvelopeV1.create(
            AUTHORITY_OBJECT_KIND,
            grant_envelope.body,
            attestations=[
                {
                    "algorithm": "ed25519",
                    "key_id": self.key_id,
                    "signature_b64": self.signature_b64,
                }
            ],
        )

    def to_bytes(self) -> bytes:
        return self.to_envelope().to_bytes()

    @classmethod
    def _from_transport_bytes(
        cls,
        data: bytes | str,
        *,
        validate_grant: bool,
    ) -> SignedAuthorityGrantV1:
        try:
            envelope = EnvelopeV1.from_bytes(data)
        except ProtocolError as exc:
            raise AuthorityError("invalid_envelope", "signed authority wire is invalid") from exc
        if envelope.object_kind != AUTHORITY_OBJECT_KIND or len(envelope.attestations) != 1:
            raise AuthorityError(
                "malformed_signed_object",
                "signed authority wire requires exactly one grant attestation",
            )
        attestation = thaw_json(envelope.attestations[0])
        if type(attestation) is not dict or set(attestation) != _ATTESTATION_FIELDS:
            raise AuthorityError(
                "malformed_signed_object",
                "authority signature attestation has missing or unknown fields",
            )
        if attestation["algorithm"] != "ed25519":
            raise AuthorityError("malformed_signed_object", "unsupported signature algorithm")
        unattested = EnvelopeV1.create(AUTHORITY_OBJECT_KIND, envelope.body)
        if unattested.object_id != envelope.object_id:
            raise AuthorityError("object_id_mismatch", "attested grant identity changed")
        if validate_grant:
            AuthorityGrantV1.from_envelope(unattested)
        return cls(
            envelope_bytes=unattested.to_bytes(),
            key_id=attestation["key_id"],
            signature_b64=attestation["signature_b64"],
        )

    @classmethod
    def from_bytes(cls, data: bytes | str) -> SignedAuthorityGrantV1:
        """Parse one canonical, semantically valid signed authority-grant wire."""

        return cls._from_transport_bytes(data, validate_grant=True)


@dataclass(frozen=True, slots=True)
class AuthoritySigner:
    """A local signing helper for controlled tests and operator tooling.

    Possession of this key does not establish third-party permission or legal authority.
    Production key custody is deliberately outside this foundation helper.
    """

    private_key: Ed25519PrivateKey  # gitleaks:allow -- type annotation, never key material

    def __post_init__(self) -> None:
        if not isinstance(self.private_key, Ed25519PrivateKey):
            raise AuthorityError("invalid_private_key", "signer requires an Ed25519 private key")

    @classmethod
    def generate(cls) -> AuthoritySigner:
        return cls(Ed25519PrivateKey.generate())

    @property
    def public_key_bytes(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @property
    def key_id(self) -> str:
        return authority_key_id(self.public_key_bytes)

    def sign(self, grant: AuthorityGrantV1) -> SignedAuthorityGrantV1:
        envelope_bytes = _envelope_bytes(grant.to_envelope())
        signature = self.private_key.sign(_SIGNATURE_DOMAIN + envelope_bytes)
        return SignedAuthorityGrantV1(
            envelope_bytes=envelope_bytes,
            key_id=self.key_id,
            signature_b64=base64.b64encode(signature).decode("ascii"),
        )


@dataclass(frozen=True, slots=True)
class TrustedAuthorityKey:
    """An immutable public key and its explicitly configured Etzio roles."""

    public_key_bytes: bytes
    roles: frozenset[str]
    issuers: frozenset[str]

    def __post_init__(self) -> None:
        if not is_valid_ed25519_public_key(self.public_key_bytes):
            raise AuthorityError(
                "invalid_public_key",
                "Ed25519 public keys must be canonical prime-subgroup points",
            )
        try:
            Ed25519PublicKey.from_public_bytes(self.public_key_bytes)
        except ValueError as exc:
            raise AuthorityError("invalid_public_key", "invalid Ed25519 public key") from exc
        if type(self.roles) is not frozenset or not self.roles:
            raise AuthorityError("invalid_roles", "trusted keys require an explicit non-empty role set")
        if any(type(role) is not str or not role or role != role.strip() for role in self.roles):
            raise AuthorityError("invalid_roles", "roles must be non-blank canonical strings")
        if type(self.issuers) is not frozenset or not self.issuers:
            raise AuthorityError(
                "invalid_issuers",
                "trusted keys require an explicit non-empty issuer set",
            )
        if any(
            type(issuer) is not str or not issuer or issuer != issuer.strip()
            for issuer in self.issuers
        ):
            raise AuthorityError(
                "invalid_issuers",
                "issuers must be non-blank canonical strings",
            )

    @property
    def key_id(self) -> str:
        return authority_key_id(self.public_key_bytes)


@dataclass(frozen=True, slots=True)
class TrustStore:
    """Immutable operator trust and revocation snapshot used for one admission decision."""

    keys: Mapping[str, TrustedAuthorityKey]
    revoked_key_ids: frozenset[str] = frozenset()
    revoked_grant_ids: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not isinstance(self.keys, Mapping):
            raise AuthorityError("invalid_trust_store", "keys must be a mapping")
        copied: dict[str, TrustedAuthorityKey] = {}
        for key_id, trusted_key in self.keys.items():
            if type(key_id) is not str or not _KEY_ID.fullmatch(key_id):
                raise AuthorityError("invalid_trust_store", "trust-store key IDs must be content-derived")
            if not isinstance(trusted_key, TrustedAuthorityKey):
                raise AuthorityError("invalid_trust_store", "trust-store values must be TrustedAuthorityKey objects")
            if key_id != trusted_key.key_id:
                raise AuthorityError("invalid_trust_store", "trust-store key ID does not match public key")
            copied[key_id] = trusted_key
        if len(copied) > MAX_TRUSTED_AUTHORITY_KEYS:
            raise AuthorityError("invalid_trust_store", "trust store exceeds the key-count ceiling")

        revoked_keys = _validated_frozenset(self.revoked_key_ids, _KEY_ID, "invalid_trust_store")
        revoked_grants = _validated_frozenset(self.revoked_grant_ids, _FULL_DIGEST, "invalid_trust_store")
        if len(revoked_keys) + len(revoked_grants) > MAX_AUTHORITY_REVOCATIONS:
            raise AuthorityError(
                "invalid_trust_store",
                "trust store exceeds the revocation-count ceiling",
            )
        object.__setattr__(self, "keys", MappingProxyType(copied))
        object.__setattr__(self, "revoked_key_ids", revoked_keys)
        object.__setattr__(self, "revoked_grant_ids", revoked_grants)

    @classmethod
    def from_keys(
        cls,
        trusted_keys: Iterable[TrustedAuthorityKey],
        *,
        revoked_key_ids: Iterable[str] = (),
        revoked_grant_ids: Iterable[str] = (),
    ) -> TrustStore:
        keys: dict[str, TrustedAuthorityKey] = {}
        for trusted_key in trusted_keys:
            if not isinstance(trusted_key, TrustedAuthorityKey):
                raise AuthorityError("invalid_trust_store", "trusted_keys contains an invalid entry")
            if trusted_key.key_id in keys:
                raise AuthorityError("invalid_trust_store", "duplicate trusted key")
            keys[trusted_key.key_id] = trusted_key
        return cls(
            keys=keys,
            revoked_key_ids=frozenset(revoked_key_ids),
            revoked_grant_ids=frozenset(revoked_grant_ids),
        )

    def to_snapshot_body(self) -> dict[str, object]:
        """Return the complete deterministic trust/revocation view used for admission."""
        keys = []
        for key_id, trusted_key in sorted(self.keys.items()):
            keys.append(
                {
                    "issuers": sorted(trusted_key.issuers),
                    "key_id": key_id,
                    "public_key_b64": base64.b64encode(
                        trusted_key.public_key_bytes
                    ).decode("ascii"),
                    "roles": sorted(trusted_key.roles),
                }
            )
        return {
            "keys": keys,
            "revoked_grant_ids": sorted(self.revoked_grant_ids),
            "revoked_key_ids": sorted(self.revoked_key_ids),
        }

    @property
    def snapshot_id(self) -> str:
        return content_id("authority_trust_snapshot", self.to_snapshot_body())


@dataclass(frozen=True, slots=True)
class AuthorityAdmissionV1:
    """Self-verifying historical record of one admission predicate.

    The record authenticates its embedded signature under its embedded trust snapshot. It
    does not prove that the supplied clock or revocation snapshot was fresh, nor that the
    represented third-party permission was legally valid.
    """

    admission_id: str
    authority_id: str
    signer_key_id: str
    target_snapshot_id: str
    decision_time: int
    required_actions: tuple[str, ...]
    grant_expires_at: int
    trust_snapshot_id: str
    trust_snapshot_bytes: bytes
    signed_grant_bytes: bytes

    def __post_init__(self) -> None:
        for field in ("admission_id", "authority_id", "target_snapshot_id", "trust_snapshot_id"):
            value = getattr(self, field)
            if type(value) is not str or _FULL_DIGEST.fullmatch(value) is None:
                raise AuthorityError("invalid_admission", f"{field} must be a full sha256 ID")
        if type(self.signer_key_id) is not str or _KEY_ID.fullmatch(self.signer_key_id) is None:
            raise AuthorityError("invalid_admission", "signer_key_id is malformed")
        if type(self.decision_time) is not int or self.decision_time < 0:
            raise AuthorityError("invalid_admission", "decision_time must be nonnegative")
        if type(self.grant_expires_at) is not int or self.decision_time >= self.grant_expires_at:
            raise AuthorityError("invalid_admission", "admission must precede grant expiry")
        required = _required_action_tuple(self.required_actions)
        if required != self.required_actions:
            raise AuthorityError("invalid_admission", "required actions must use canonical order")
        if type(self.trust_snapshot_bytes) is not bytes:
            raise AuthorityError("invalid_admission", "trust snapshot must use canonical bytes")
        try:
            loaded = strict_loads(self.trust_snapshot_bytes)
        except ProtocolError as exc:
            raise AuthorityError("invalid_admission", "trust snapshot bytes are invalid") from exc
        if type(loaded) is not dict or canonical_dumps(loaded) != self.trust_snapshot_bytes:
            raise AuthorityError("invalid_admission", "trust snapshot must be a JSON object")
        _validate_trust_snapshot_body(loaded)
        if content_id("authority_trust_snapshot", loaded) != self.trust_snapshot_id:
            raise AuthorityError("invalid_admission", "trust snapshot ID does not match its bytes")
        _validate_historical_admission(self, loaded)
        envelope = EnvelopeV1.create("authority_admission", self._body(loaded))
        if envelope.object_id != self.admission_id:
            raise AuthorityError("invalid_admission", "admission ID does not match its content")

    @classmethod
    def issue(
        cls,
        *,
        grant: AuthorityGrantV1,
        signed_grant: SignedAuthorityGrantV1,
        signer_key_id: str,
        trust_store: TrustStore,
        decision_time: int,
        required_actions: tuple[str, ...],
        target_snapshot_id: str,
    ) -> AuthorityAdmissionV1:
        required = _required_action_tuple(required_actions)
        trust_body = trust_store.to_snapshot_body()
        trust_bytes = canonical_dumps(trust_body)
        trust_id = content_id("authority_trust_snapshot", trust_body)
        body = {
            "authority_id": grant.grant_id,
            "decision_time": decision_time,
            "grant_expires_at": grant.expires_at,
            "required_actions": list(required),
            "signer_key_id": signer_key_id,
            "signed_grant": signed_grant.to_envelope().to_dict(),
            "target_snapshot_id": target_snapshot_id,
            "trust_snapshot": trust_body,
            "trust_snapshot_id": trust_id,
        }
        envelope = EnvelopeV1.create("authority_admission", body)
        return cls(
            admission_id=envelope.object_id,
            authority_id=grant.grant_id,
            signer_key_id=signer_key_id,
            target_snapshot_id=target_snapshot_id,
            decision_time=decision_time,
            required_actions=required,
            grant_expires_at=grant.expires_at,
            trust_snapshot_id=trust_id,
            trust_snapshot_bytes=trust_bytes,
            signed_grant_bytes=signed_grant.to_bytes(),
        )

    @classmethod
    def from_envelope(cls, envelope: EnvelopeV1) -> AuthorityAdmissionV1:
        if envelope.object_kind != "authority_admission" or envelope.attestations:
            raise AuthorityError(
                "invalid_admission",
                "expected an unattested authority_admission envelope",
            )
        body = thaw_json(envelope.body)
        if type(body) is not dict or set(body) != _ADMISSION_BODY_FIELDS:
            raise AuthorityError("invalid_admission", "admission has missing or unknown fields")
        if (
            type(body["required_actions"]) is not list
            or type(body["trust_snapshot"]) is not dict
            or type(body["signed_grant"]) is not dict
        ):
            raise AuthorityError("invalid_admission", "admission arrays or objects are malformed")
        return cls(
            admission_id=envelope.object_id,
            authority_id=body["authority_id"],
            signer_key_id=body["signer_key_id"],
            target_snapshot_id=body["target_snapshot_id"],
            decision_time=body["decision_time"],
            required_actions=tuple(body["required_actions"]),
            grant_expires_at=body["grant_expires_at"],
            trust_snapshot_id=body["trust_snapshot_id"],
            trust_snapshot_bytes=canonical_dumps(body["trust_snapshot"]),
            signed_grant_bytes=canonical_dumps(body["signed_grant"]),
        )

    def _body(self, trust_snapshot: dict[str, object] | None = None) -> dict[str, object]:
        if trust_snapshot is None:
            loaded = strict_loads(self.trust_snapshot_bytes)
            if type(loaded) is not dict:
                raise AuthorityError("invalid_admission", "trust snapshot must be a JSON object")
            trust_snapshot = loaded
        return {
            "authority_id": self.authority_id,
            "decision_time": self.decision_time,
            "grant_expires_at": self.grant_expires_at,
            "required_actions": list(self.required_actions),
            "signer_key_id": self.signer_key_id,
            "signed_grant": strict_loads(self.signed_grant_bytes),
            "target_snapshot_id": self.target_snapshot_id,
            "trust_snapshot": trust_snapshot,
            "trust_snapshot_id": self.trust_snapshot_id,
        }

    def to_envelope(self) -> EnvelopeV1:
        envelope = EnvelopeV1.create("authority_admission", self._body())
        if envelope.object_id != self.admission_id:
            raise AuthorityError("invalid_admission", "admission ID does not match its content")
        return envelope


def _validate_trust_snapshot_body(body: dict[str, object]) -> None:
    if set(body) != {"keys", "revoked_grant_ids", "revoked_key_ids"}:
        raise AuthorityError("invalid_admission", "trust snapshot has missing or unknown fields")
    keys = body["keys"]
    revoked_grants = body["revoked_grant_ids"]
    revoked_keys = body["revoked_key_ids"]
    if type(keys) is not list or type(revoked_grants) is not list or type(revoked_keys) is not list:
        raise AuthorityError("invalid_admission", "trust snapshot collections must be arrays")
    if len(keys) > MAX_TRUSTED_AUTHORITY_KEYS:
        raise AuthorityError("invalid_admission", "trust snapshot exceeds the key-count ceiling")
    if len(revoked_grants) + len(revoked_keys) > MAX_AUTHORITY_REVOCATIONS:
        raise AuthorityError("invalid_admission", "trust snapshot exceeds the revocation ceiling")
    observed_key_ids: list[str] = []
    for entry in keys:
        if type(entry) is not dict or set(entry) != {
            "issuers",
            "key_id",
            "public_key_b64",
            "roles",
        }:
            raise AuthorityError("invalid_admission", "trust snapshot key entry is malformed")
        if type(entry["roles"]) is not list or type(entry["issuers"]) is not list:
            raise AuthorityError("invalid_admission", "trust snapshot roles and issuers must be arrays")
        try:
            public_bytes = base64.b64decode(entry["public_key_b64"], validate=True)
        except (binascii.Error, TypeError, ValueError) as exc:
            raise AuthorityError("invalid_admission", "trust snapshot public key is malformed") from exc
        if (
            len(public_bytes) != 32
            or not is_valid_ed25519_public_key(public_bytes)
            or base64.b64encode(public_bytes).decode("ascii") != entry["public_key_b64"]
            or authority_key_id(public_bytes) != entry["key_id"]
        ):
            raise AuthorityError("invalid_admission", "trust snapshot key identity is malformed")
        for values in (entry["roles"], entry["issuers"]):
            if (
                not values
                or any(type(value) is not str or not value or value != value.strip() for value in values)
                or values != sorted(set(values))
            ):
                raise AuthorityError("invalid_admission", "trust snapshot labels are noncanonical")
        observed_key_ids.append(entry["key_id"])
    if observed_key_ids != sorted(set(observed_key_ids)):
        raise AuthorityError("invalid_admission", "trust snapshot keys are noncanonical")
    if (
        any(type(value) is not str or _FULL_DIGEST.fullmatch(value) is None for value in revoked_grants)
        or revoked_grants != sorted(set(revoked_grants))
        or any(type(value) is not str or _KEY_ID.fullmatch(value) is None for value in revoked_keys)
        or revoked_keys != sorted(set(revoked_keys))
    ):
        raise AuthorityError("invalid_admission", "trust snapshot revocations are noncanonical")


def _validate_historical_admission(
    admission: AuthorityAdmissionV1,
    trust_snapshot: dict[str, object],
) -> None:
    if type(admission.signed_grant_bytes) is not bytes:
        raise AuthorityError("invalid_admission", "signed grant must use canonical bytes")
    try:
        signed = SignedAuthorityGrantV1.from_bytes(admission.signed_grant_bytes)
        grant = AuthorityGrantV1.from_envelope(EnvelopeV1.from_bytes(signed.envelope_bytes))
    except (AuthorityError, ProtocolError) as exc:
        raise AuthorityError("invalid_admission", "embedded signed grant is invalid") from exc
    if signed.to_bytes() != admission.signed_grant_bytes:
        raise AuthorityError("invalid_admission", "embedded signed grant is noncanonical")
    if (
        signed.key_id != admission.signer_key_id
        or grant.grant_id != admission.authority_id
        or grant.target_snapshot_id != admission.target_snapshot_id
        or grant.expires_at != admission.grant_expires_at
        or admission.decision_time < grant.not_before
        or admission.decision_time >= grant.expires_at
        or not set(admission.required_actions).issubset(grant.permitted_actions)
    ):
        raise AuthorityError("invalid_admission", "embedded grant does not satisfy the admission")
    if (
        signed.key_id in trust_snapshot["revoked_key_ids"]
        or grant.grant_id in trust_snapshot["revoked_grant_ids"]
    ):
        raise AuthorityError("invalid_admission", "embedded trust snapshot revokes the admission")
    key_entry = next(
        (
            entry
            for entry in trust_snapshot["keys"]
            if entry["key_id"] == signed.key_id
        ),
        None,
    )
    if (
        key_entry is None
        or OPERATOR_ROLE not in key_entry["roles"]
        or grant.issuer not in key_entry["issuers"]
    ):
        raise AuthorityError("invalid_admission", "embedded signer is not trusted for this issuer")
    try:
        public_key_bytes = base64.b64decode(key_entry["public_key_b64"], validate=True)
        signature = base64.b64decode(signed.signature_b64, validate=True)
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
            signature,
            _SIGNATURE_DOMAIN + signed.envelope_bytes,
        )
    except (binascii.Error, InvalidSignature, TypeError, ValueError) as exc:
        raise AuthorityError("invalid_admission", "embedded grant signature is invalid") from exc


@dataclass(frozen=True, slots=True)
class AdmissionDecision:
    """A frozen admission snapshot carrying every lease-enforceable grant field."""

    accepted: bool
    authority_id: str | None
    reason_code: str
    key_id: str | None = None
    grant: AuthorityGrantV1 | None = None
    admission: AuthorityAdmissionV1 | None = None

    def __post_init__(self) -> None:
        if type(self.accepted) is not bool:
            raise AuthorityError("invalid_decision", "accepted must be a bool")
        if self.accepted:
            if self.authority_id is None or not _FULL_DIGEST.fullmatch(self.authority_id):
                raise AuthorityError("invalid_decision", "accepted decisions require an authority ID")
            if self.reason_code != "accepted":
                raise AuthorityError("invalid_decision", "accepted decisions require the accepted reason code")
            if self.key_id is None or not _KEY_ID.fullmatch(self.key_id):
                raise AuthorityError("invalid_decision", "accepted decisions require a signer key ID")
            if not isinstance(self.grant, AuthorityGrantV1):
                raise AuthorityError("invalid_decision", "accepted decisions require the admitted grant")
            if self.grant.grant_id != self.authority_id:
                raise AuthorityError("invalid_decision", "admitted grant and authority ID differ")
            if not isinstance(self.admission, AuthorityAdmissionV1):
                raise AuthorityError("invalid_decision", "accepted decisions require an admission record")
            if (
                self.admission.authority_id != self.authority_id
                or self.admission.signer_key_id != self.key_id
                or self.admission.target_snapshot_id != self.grant.target_snapshot_id
                or self.admission.grant_expires_at != self.grant.expires_at
            ):
                raise AuthorityError("invalid_decision", "admission record and decision differ")
        elif (
            self.authority_id is not None
            or self.key_id is not None
            or self.grant is not None
            or self.admission is not None
        ):
            raise AuthorityError(
                "invalid_decision",
                "refused decisions cannot carry admitted authority material",
            )


def authority_key_id(public_key_bytes: bytes) -> str:
    """Derive the only accepted key identifier from raw Ed25519 public-key bytes."""

    if type(public_key_bytes) is not bytes or len(public_key_bytes) != 32:
        raise AuthorityError("invalid_public_key", "Ed25519 public keys must contain exactly 32 bytes")
    return "ed25519:sha256:" + hashlib.sha256(public_key_bytes).hexdigest()


def admit_authority(
    raw_signed_object: SignedAuthorityGrantV1 | Mapping[str, object] | bytes | str,
    trust_store: TrustStore,
    *,
    decision_time: int,
    expected_target_snapshot_id: str,
    required_actions: Iterable[str],
) -> AdmissionDecision:
    """Authenticate and admit one exact operator-captured authority grant.

    All untrusted-input failures become deterministic refusals. A successful decision
    authenticates configured operator capture of the grant only; callers must separately
    establish the underlying program permission and legal validity represented by the
    signed evidence digest.
    """

    if type(decision_time) is not int or decision_time < 0:
        return _refuse("invalid_decision_time")
    if type(expected_target_snapshot_id) is not str or not _FULL_DIGEST.fullmatch(expected_target_snapshot_id):
        return _refuse("invalid_expected_target")
    try:
        required = _required_action_tuple(required_actions)
        signed = _parse_signed_object(raw_signed_object)
    except AuthorityError as exc:
        return _refuse(exc.reason_code)

    if signed.key_id in trust_store.revoked_key_ids:
        return _refuse("key_revoked")
    trusted_key = trust_store.keys.get(signed.key_id)
    if trusted_key is None:
        return _refuse("unknown_key")
    if OPERATOR_ROLE not in trusted_key.roles:
        return _refuse("key_missing_operator_role")

    try:
        signature = base64.b64decode(signed.signature_b64, validate=True)
    except (binascii.Error, ValueError):
        return _refuse("malformed_signature")
    if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != signed.signature_b64:
        return _refuse("malformed_signature")
    try:
        trusted_public_key = Ed25519PublicKey.from_public_bytes(trusted_key.public_key_bytes)
        trusted_public_key.verify(signature, _SIGNATURE_DOMAIN + signed.envelope_bytes)
    except (InvalidSignature, ValueError):
        return _refuse("invalid_signature")

    try:
        envelope = EnvelopeV1.from_bytes(signed.envelope_bytes)
        if signed.envelope_bytes != envelope.to_bytes():
            return _refuse("noncanonical_envelope")
        grant = AuthorityGrantV1.from_envelope(envelope)
    except ProtocolError as exc:
        return _refuse(_protocol_reason(exc))
    except AuthorityError as exc:
        return _refuse(exc.reason_code)

    if grant.grant_id in trust_store.revoked_grant_ids:
        return _refuse("grant_revoked")
    if grant.issuer not in trusted_key.issuers:
        return _refuse("issuer_not_allowed")
    if decision_time < grant.not_before:
        return _refuse("not_yet_valid")
    if decision_time >= grant.expires_at:
        return _refuse("expired")
    if grant.target_snapshot_id != expected_target_snapshot_id:
        return _refuse("target_mismatch")
    if not set(required).issubset(grant.permitted_actions):
        return _refuse("missing_required_action")
    admission = AuthorityAdmissionV1.issue(
        grant=grant,
        signed_grant=signed,
        signer_key_id=signed.key_id,
        trust_store=trust_store,
        decision_time=decision_time,
        required_actions=required,
        target_snapshot_id=expected_target_snapshot_id,
    )
    return AdmissionDecision(
        accepted=True,
        authority_id=grant.grant_id,
        reason_code="accepted",
        key_id=signed.key_id,
        grant=grant,
        admission=admission,
    )


def _validate_semantics(values: Mapping[str, object]) -> None:
    if set(values) != _GRANT_BODY_FIELDS:
        raise AuthorityError("malformed_grant", "authority grant has missing or unknown fields")

    for field in ("issuer", "subject"):
        value = values[field]
        if type(value) is not str or not value or value != value.strip():
            raise AuthorityError(f"blank_{field}", f"{field} must be a non-blank canonical string")
    for field in ("target_snapshot_id", "evidence_digest"):
        value = values[field]
        if type(value) is not str or not value:
            raise AuthorityError(f"blank_{field}", f"{field} must be non-blank")
        if not _FULL_DIGEST.fullmatch(value):
            raise AuthorityError(f"invalid_{field}", f"{field} must be a full sha256 content ID")

    assets = values["assets"]
    if type(assets) is not tuple or not assets:
        raise AuthorityError("invalid_assets", "assets must be a non-empty tuple")
    if any(type(asset) is not str or not asset or asset != asset.strip() for asset in assets):
        raise AuthorityError("blank_asset", "assets must contain non-blank canonical strings")
    if len(set(assets)) != len(assets):
        raise AuthorityError("duplicate_asset", "assets must not contain duplicates")
    if assets != tuple(sorted(assets)):
        raise AuthorityError("noncanonical_assets", "assets must use canonical lexical order")

    actions = values["permitted_actions"]
    if type(actions) is not tuple or not actions:
        raise AuthorityError("invalid_actions", "permitted_actions must be a non-empty tuple")
    if any(type(action) is not str or not action or action != action.strip() for action in actions):
        raise AuthorityError("blank_action", "permitted_actions must contain canonical strings")
    if len(set(actions)) != len(actions):
        raise AuthorityError("duplicate_action", "permitted_actions must not contain duplicates")
    if actions != tuple(sorted(actions)):
        raise AuthorityError(
            "noncanonical_actions",
            "permitted_actions must use canonical lexical order",
        )
    if not set(actions).issubset(PERMITTED_ACTIONS):
        raise AuthorityError("unknown_action", "permitted_actions contains an unsupported action")

    for field in ("issued_at", "not_before", "expires_at"):
        value = values[field]
        if type(value) is not int or value < 0:
            raise AuthorityError("invalid_time", f"{field} must be a nonnegative integer epoch second")
    if values["issued_at"] > values["not_before"] or values["not_before"] >= values["expires_at"]:
        raise AuthorityError("invalid_time_window", "time ordering must be issued_at <= not_before < expires_at")

    ceilings = {
        "max_bytes": MAX_BYTES_HARD_CEILING,
        "max_candidates": MAX_CANDIDATES_HARD_CEILING,
        "max_wallclock_seconds": MAX_WALLCLOCK_SECONDS_HARD_CEILING,
    }
    for field, ceiling in ceilings.items():
        value = values[field]
        if type(value) is not int or value < 0:
            raise AuthorityError("invalid_budget", f"{field} must be a nonnegative integer")
        if value > ceiling:
            raise AuthorityError("budget_exceeds_hard_ceiling", f"{field} exceeds the foundation hard ceiling")


def _wire_body(values: Mapping[str, object]) -> dict[str, object]:
    return {
        **values,
        "assets": list(values["assets"]),
        "permitted_actions": list(values["permitted_actions"]),
    }


def _envelope_bytes(envelope: EnvelopeV1) -> bytes:
    return canonical_dumps(envelope.to_dict())


def _parse_signed_object(
    raw_signed_object: SignedAuthorityGrantV1 | Mapping[str, object] | bytes | str,
) -> SignedAuthorityGrantV1:
    if isinstance(raw_signed_object, SignedAuthorityGrantV1):
        return raw_signed_object
    if type(raw_signed_object) in {bytes, str}:
        # Admission authenticates the carrier before surfacing grant semantics. The public
        # wire parser remains strict, while this private path preserves representation-
        # independent refusal precedence for untrusted admission input.
        return SignedAuthorityGrantV1._from_transport_bytes(
            raw_signed_object,
            validate_grant=False,
        )
    if not isinstance(raw_signed_object, Mapping):
        raise AuthorityError("unsigned_object", "authority input must be a signed object")
    raw = dict(raw_signed_object)
    if "signature_b64" not in raw:
        raise AuthorityError("unsigned_object", "authority input has no detached signature")
    if set(raw) != _SIGNED_FIELDS:
        raise AuthorityError("malformed_signed_object", "signed authority object has missing or unknown fields")
    try:
        return SignedAuthorityGrantV1(
            envelope_bytes=raw["envelope_bytes"],
            key_id=raw["key_id"],
            signature_b64=raw["signature_b64"],
        )
    except AuthorityError:
        raise
    except (TypeError, ValueError) as exc:
        raise AuthorityError("malformed_signed_object", "signed authority object is malformed") from exc


def _required_action_tuple(actions: Iterable[str]) -> tuple[str, ...]:
    if isinstance(actions, (str, bytes)):
        raise AuthorityError("invalid_required_actions", "required_actions must be an iterable of action names")
    try:
        result = tuple(actions)
    except TypeError as exc:
        raise AuthorityError("invalid_required_actions", "required_actions must be iterable") from exc
    if any(type(action) is not str or action not in PERMITTED_ACTIONS for action in result):
        raise AuthorityError("invalid_required_actions", "required_actions contains an unsupported action")
    if len(set(result)) != len(result):
        raise AuthorityError("invalid_required_actions", "required_actions must not contain duplicates")
    return tuple(sorted(result))


def _validated_frozenset(values: Iterable[str], pattern: re.Pattern[str], reason: str) -> frozenset[str]:
    try:
        result = frozenset(values)
    except TypeError as exc:
        raise AuthorityError(reason, "revocation entries must be iterable strings") from exc
    if any(type(value) is not str or not pattern.fullmatch(value) for value in result):
        raise AuthorityError(reason, "revocation entry has an invalid identifier")
    return result


def _protocol_reason(exc: ProtocolError) -> str:
    code = getattr(exc, "code", "")
    if code in {"object_id_mismatch", "noncanonical_envelope"}:
        return code
    return "invalid_envelope"


def _refuse(reason_code: str) -> AdmissionDecision:
    return AdmissionDecision(accepted=False, authority_id=None, reason_code=reason_code)
