"""Fail-closed modeled-fixture verification receipts for Etzio protocol v1.

This module authenticates a configured verifier identity and binds its signed result to
one exact, expiring verification lease.  It does not prove that the result is true, that
the lease was kernel-issued or admitted under a grant, that referenced digests resolve to
retained CAS bytes, or that the signer was actually independent.  It does not claim
process, container, VM, KVM, or hardware isolation.  The only evidence tier admitted by
this foundation boundary is ``modeled_fixture``.

Lease consumption must be committed atomically by the lifecycle kernel alongside the
accepted receipt event.  :func:`validate_verifier_receipt` observes the caller-supplied
set of already-consumed lease IDs but deliberately does not mutate external state.
Verifier trust snapshots are deterministic retrospective evidence; this module does not
establish that a supplied snapshot or clock was fresh at decision time.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections.abc import Iterable, Mapping, Set
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from etzio.crypto_v1 import is_valid_ed25519_public_key
from etzio.protocol import EnvelopeV1, ProtocolError, content_id, thaw_json

LEASE_OBJECT_KIND: Final = "verification_lease"
RECEIPT_OBJECT_KIND: Final = "verifier_receipt"
LEASE_PURPOSE: Final = "modeled_fixture_verification"
MODELED_FIXTURE_TIER: Final = "modeled_fixture"
VERIFIER_ROLE: Final = "modeled_fixture_verifier"
VERDICTS: Final = frozenset({"confirmed", "not_reproduced", "inconclusive", "invalid"})

# Foundation ceilings bound all attacker-controlled collections and signed wire objects.
MAX_VERIFIER_RECEIPT_ENVELOPE_BYTES: Final = 256 * 1024
MAX_EVIDENCE_ARTIFACTS: Final = 256
MAX_TRUSTED_VERIFIER_KEYS: Final = 64
MAX_VERIFIER_ROLES: Final = 16
MAX_VERIFIER_REVOCATIONS: Final = 10_000
MAX_CONSUMED_LEASE_IDS: Final = 100_000
MAX_RETAINED_EVIDENCE_DIGESTS: Final = 100_000
MAX_EPOCH_SECOND: Final = (2**63) - 1

_SIGNATURE_DOMAIN: Final = b"etzio.verifier-receipt.signature.v1\x00"
_FULL_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
_KEY_ID = re.compile(r"^ed25519:sha256:[0-9a-f]{64}$", re.ASCII)
_NONCE = re.compile(r"^[0-9a-f]{32}$", re.ASCII)
_IDENTITY = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{1,127}$", re.ASCII)
_LEASE_BODY_FIELDS: Final = frozenset(
    {
        "purpose",
        "lease_nonce",
        "mission_id",
        "authority_id",
        "target_snapshot_id",
        "candidate_id",
        "candidate_producer_id",
        "poc_artifact_digest",
        "evidence_artifact_digests",
        "environment_digest",
        "effect_oracle_id",
        "verifier_id",
        "verifier_key_id",
        "issued_at",
        "expires_at",
    }
)
_RECEIPT_BODY_FIELDS: Final = frozenset(
    {
        "lease_id",
        "mission_id",
        "authority_id",
        "target_snapshot_id",
        "candidate_id",
        "candidate_producer_id",
        "poc_artifact_digest",
        "evidence_artifact_digests",
        "environment_digest",
        "effect_oracle_id",
        "verifier_id",
        "verifier_key_id",
        "evidence_tier",
        "verdict",
        "effect_observed",
        "oracle_satisfied",
        "completed_at",
    }
)
_SIGNED_FIELDS: Final = frozenset({"envelope_bytes", "key_id", "signature_b64"})
_ATTESTATION_FIELDS: Final = frozenset({"algorithm", "key_id", "signature_b64"})
_TRUST_SNAPSHOT_FIELDS: Final = frozenset({"keys", "revoked_key_ids", "revoked_lease_ids", "revoked_receipt_ids"})
_TRUST_SNAPSHOT_KEY_FIELDS: Final = frozenset({"key_id", "public_key_b64", "roles", "verifier_id"})


class VerificationError(ValueError):
    """A deterministic verification-object construction or validation failure."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class VerificationLeaseV1:
    """One immutable, content-addressed assignment to a named verifier key.

    ``lease_nonce`` is a caller-generated 128-bit uniqueness value represented by
    exactly 32 lowercase hexadecimal characters.  It is public uniqueness material,
    not a secret or an authentication token.
    """

    lease_id: str
    lease_nonce: str
    mission_id: str
    authority_id: str
    target_snapshot_id: str
    candidate_id: str
    candidate_producer_id: str
    poc_artifact_digest: str
    evidence_artifact_digests: tuple[str, ...]
    environment_digest: str
    effect_oracle_id: str
    verifier_id: str
    verifier_key_id: str
    issued_at: int
    expires_at: int

    def __post_init__(self) -> None:
        if type(self.lease_id) is not str or _FULL_DIGEST.fullmatch(self.lease_id) is None:
            raise VerificationError("invalid_lease_id", "lease_id must be a full sha256 content ID")
        _validate_lease_values(self._body_values())
        canonical_id = _create_envelope(LEASE_OBJECT_KIND, self._wire_body()).object_id
        if self.lease_id != canonical_id:
            raise VerificationError("object_id_mismatch", "lease_id does not match canonical lease semantics")

    @classmethod
    def issue(
        cls,
        *,
        lease_nonce: str,
        mission_id: str,
        authority_id: str,
        target_snapshot_id: str,
        candidate_id: str,
        candidate_producer_id: str,
        poc_artifact_digest: str,
        evidence_artifact_digests: tuple[str, ...],
        environment_digest: str,
        effect_oracle_id: str,
        verifier_id: str,
        verifier_key_id: str,
        issued_at: int,
        expires_at: int,
    ) -> VerificationLeaseV1:
        """Issue a deterministic lease for caller-supplied, non-secret nonce material."""

        values = {
            "lease_nonce": lease_nonce,
            "mission_id": mission_id,
            "authority_id": authority_id,
            "target_snapshot_id": target_snapshot_id,
            "candidate_id": candidate_id,
            "candidate_producer_id": candidate_producer_id,
            "poc_artifact_digest": poc_artifact_digest,
            "evidence_artifact_digests": evidence_artifact_digests,
            "environment_digest": environment_digest,
            "effect_oracle_id": effect_oracle_id,
            "verifier_id": verifier_id,
            "verifier_key_id": verifier_key_id,
            "issued_at": issued_at,
            "expires_at": expires_at,
        }
        _validate_lease_values(values)
        envelope = _create_envelope(
            LEASE_OBJECT_KIND,
            {
                "purpose": LEASE_PURPOSE,
                **values,
                "evidence_artifact_digests": list(evidence_artifact_digests),
            },
        )
        return cls(lease_id=envelope.object_id, **values)

    @classmethod
    def from_envelope(cls, envelope: EnvelopeV1) -> VerificationLeaseV1:
        if envelope.object_kind != LEASE_OBJECT_KIND:
            raise VerificationError("wrong_object_kind", "envelope is not a verification lease")
        if envelope.attestations:
            raise VerificationError("unexpected_attestations", "verification lease attestations must be empty")
        body = thaw_json(envelope.body)
        if type(body) is not dict or set(body) != _LEASE_BODY_FIELDS:
            raise VerificationError("malformed_lease", "lease body has missing or unknown fields")
        if body["purpose"] != LEASE_PURPOSE:
            raise VerificationError("wrong_lease_purpose", "lease is not for modeled fixture verification")
        if type(body["evidence_artifact_digests"]) is not list:
            raise VerificationError("malformed_lease", "evidence_artifact_digests must be an array")
        values = {key: value for key, value in body.items() if key not in {"purpose", "evidence_artifact_digests"}}
        values["evidence_artifact_digests"] = tuple(body["evidence_artifact_digests"])
        try:
            return cls(lease_id=envelope.object_id, **values)
        except TypeError as exc:
            raise VerificationError("malformed_lease", "lease body has invalid field types") from exc

    def to_envelope(self) -> EnvelopeV1:
        envelope = _create_envelope(LEASE_OBJECT_KIND, self._wire_body())
        if envelope.object_id != self.lease_id:
            raise VerificationError("object_id_mismatch", "lease_id does not match canonical lease semantics")
        return envelope

    def _body_values(self) -> dict[str, object]:
        return {
            "lease_nonce": self.lease_nonce,
            "mission_id": self.mission_id,
            "authority_id": self.authority_id,
            "target_snapshot_id": self.target_snapshot_id,
            "candidate_id": self.candidate_id,
            "candidate_producer_id": self.candidate_producer_id,
            "poc_artifact_digest": self.poc_artifact_digest,
            "evidence_artifact_digests": self.evidence_artifact_digests,
            "environment_digest": self.environment_digest,
            "effect_oracle_id": self.effect_oracle_id,
            "verifier_id": self.verifier_id,
            "verifier_key_id": self.verifier_key_id,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }

    def _wire_body(self) -> dict[str, object]:
        return {
            "purpose": LEASE_PURPOSE,
            **self._body_values(),
            "evidence_artifact_digests": list(self.evidence_artifact_digests),
        }


@dataclass(frozen=True, slots=True)
class VerifierReceiptV1:
    """A verifier's exact claim about one modeled-fixture lease."""

    receipt_id: str
    lease_id: str
    mission_id: str
    authority_id: str
    target_snapshot_id: str
    candidate_id: str
    candidate_producer_id: str
    poc_artifact_digest: str
    evidence_artifact_digests: tuple[str, ...]
    environment_digest: str
    effect_oracle_id: str
    verifier_id: str
    verifier_key_id: str
    evidence_tier: str
    verdict: str
    effect_observed: bool
    oracle_satisfied: bool
    completed_at: int

    def __post_init__(self) -> None:
        if type(self.receipt_id) is not str or _FULL_DIGEST.fullmatch(self.receipt_id) is None:
            raise VerificationError("invalid_receipt_id", "receipt_id must be a full sha256 content ID")
        _validate_receipt_values(self._body_values())
        canonical_id = _create_envelope(RECEIPT_OBJECT_KIND, self._wire_body()).object_id
        if self.receipt_id != canonical_id:
            raise VerificationError("object_id_mismatch", "receipt_id does not match canonical receipt semantics")

    @classmethod
    def issue(
        cls,
        *,
        lease_id: str,
        mission_id: str,
        authority_id: str,
        target_snapshot_id: str,
        candidate_id: str,
        candidate_producer_id: str,
        poc_artifact_digest: str,
        evidence_artifact_digests: tuple[str, ...],
        environment_digest: str,
        effect_oracle_id: str,
        verifier_id: str,
        verifier_key_id: str,
        evidence_tier: str,
        verdict: str,
        effect_observed: bool,
        oracle_satisfied: bool,
        completed_at: int,
    ) -> VerifierReceiptV1:
        values = {
            "lease_id": lease_id,
            "mission_id": mission_id,
            "authority_id": authority_id,
            "target_snapshot_id": target_snapshot_id,
            "candidate_id": candidate_id,
            "candidate_producer_id": candidate_producer_id,
            "poc_artifact_digest": poc_artifact_digest,
            "evidence_artifact_digests": evidence_artifact_digests,
            "environment_digest": environment_digest,
            "effect_oracle_id": effect_oracle_id,
            "verifier_id": verifier_id,
            "verifier_key_id": verifier_key_id,
            "evidence_tier": evidence_tier,
            "verdict": verdict,
            "effect_observed": effect_observed,
            "oracle_satisfied": oracle_satisfied,
            "completed_at": completed_at,
        }
        _validate_receipt_values(values)
        envelope = _create_envelope(
            RECEIPT_OBJECT_KIND,
            {**values, "evidence_artifact_digests": list(evidence_artifact_digests)},
        )
        return cls(receipt_id=envelope.object_id, **values)

    @classmethod
    def for_lease(
        cls,
        lease: VerificationLeaseV1,
        *,
        evidence_tier: str,
        verdict: str,
        effect_observed: bool,
        oracle_satisfied: bool,
        completed_at: int,
    ) -> VerifierReceiptV1:
        """Create a receipt by copying every binding directly from an immutable lease."""

        if not isinstance(lease, VerificationLeaseV1):
            raise VerificationError("invalid_lease", "lease must be a VerificationLeaseV1")
        return cls.issue(
            lease_id=lease.lease_id,
            mission_id=lease.mission_id,
            authority_id=lease.authority_id,
            target_snapshot_id=lease.target_snapshot_id,
            candidate_id=lease.candidate_id,
            candidate_producer_id=lease.candidate_producer_id,
            poc_artifact_digest=lease.poc_artifact_digest,
            evidence_artifact_digests=lease.evidence_artifact_digests,
            environment_digest=lease.environment_digest,
            effect_oracle_id=lease.effect_oracle_id,
            verifier_id=lease.verifier_id,
            verifier_key_id=lease.verifier_key_id,
            evidence_tier=evidence_tier,
            verdict=verdict,
            effect_observed=effect_observed,
            oracle_satisfied=oracle_satisfied,
            completed_at=completed_at,
        )

    @classmethod
    def from_envelope(cls, envelope: EnvelopeV1) -> VerifierReceiptV1:
        if envelope.object_kind != RECEIPT_OBJECT_KIND:
            raise VerificationError("wrong_object_kind", "envelope is not a verifier receipt")
        if envelope.attestations:
            raise VerificationError("unexpected_attestations", "verifier receipt attestations must be empty")
        body = thaw_json(envelope.body)
        if type(body) is not dict or set(body) != _RECEIPT_BODY_FIELDS:
            raise VerificationError("malformed_receipt", "receipt body has missing or unknown fields")
        if type(body["evidence_artifact_digests"]) is not list:
            raise VerificationError("malformed_receipt", "evidence_artifact_digests must be an array")
        body["evidence_artifact_digests"] = tuple(body["evidence_artifact_digests"])
        try:
            return cls(receipt_id=envelope.object_id, **body)
        except TypeError as exc:
            raise VerificationError("malformed_receipt", "receipt body has invalid field types") from exc

    def to_envelope(self) -> EnvelopeV1:
        envelope = _create_envelope(RECEIPT_OBJECT_KIND, self._wire_body())
        if envelope.object_id != self.receipt_id:
            raise VerificationError("object_id_mismatch", "receipt_id does not match canonical receipt semantics")
        return envelope

    def _body_values(self) -> dict[str, object]:
        return {
            "lease_id": self.lease_id,
            "mission_id": self.mission_id,
            "authority_id": self.authority_id,
            "target_snapshot_id": self.target_snapshot_id,
            "candidate_id": self.candidate_id,
            "candidate_producer_id": self.candidate_producer_id,
            "poc_artifact_digest": self.poc_artifact_digest,
            "evidence_artifact_digests": self.evidence_artifact_digests,
            "environment_digest": self.environment_digest,
            "effect_oracle_id": self.effect_oracle_id,
            "verifier_id": self.verifier_id,
            "verifier_key_id": self.verifier_key_id,
            "evidence_tier": self.evidence_tier,
            "verdict": self.verdict,
            "effect_observed": self.effect_observed,
            "oracle_satisfied": self.oracle_satisfied,
            "completed_at": self.completed_at,
        }

    def _wire_body(self) -> dict[str, object]:
        return {
            **self._body_values(),
            "evidence_artifact_digests": list(self.evidence_artifact_digests),
        }


@dataclass(frozen=True, slots=True)
class SignedVerifierReceiptV1:
    """Canonical receipt bytes plus one Ed25519 attestation.

    ``as_raw`` preserves the legacy in-process detached shape. ``to_bytes`` is the
    protocol wire form and contains exactly one attestation on the common envelope.
    """

    envelope_bytes: bytes
    key_id: str
    signature_b64: str

    def __post_init__(self) -> None:
        if type(self.envelope_bytes) is not bytes or not self.envelope_bytes:
            raise VerificationError("malformed_signed_receipt", "envelope_bytes must be non-empty bytes")
        if len(self.envelope_bytes) > MAX_VERIFIER_RECEIPT_ENVELOPE_BYTES:
            raise VerificationError(
                "receipt_envelope_too_large",
                "verifier receipt envelope exceeds the fixed byte ceiling",
            )
        if type(self.key_id) is not str or _KEY_ID.fullmatch(self.key_id) is None:
            raise VerificationError("malformed_key_id", "key_id must identify an Ed25519 public key")
        _decode_canonical_signature(self.signature_b64)

    def as_raw(self) -> Mapping[str, object]:
        """Return the legacy detached shape accepted by receipt validation."""

        return MappingProxyType(
            {
                "envelope_bytes": self.envelope_bytes,
                "key_id": self.key_id,
                "signature_b64": self.signature_b64,
            }
        )

    def to_envelope(self) -> EnvelopeV1:
        """Return the canonical receipt envelope with exactly one attestation."""

        try:
            receipt_envelope = EnvelopeV1.from_bytes(self.envelope_bytes)
        except ProtocolError as exc:
            raise VerificationError("invalid_envelope", "signed receipt envelope is invalid") from exc
        if receipt_envelope.object_kind != RECEIPT_OBJECT_KIND or receipt_envelope.attestations:
            raise VerificationError(
                "invalid_envelope",
                "signed verifier input must contain one unattested receipt envelope",
            )
        VerifierReceiptV1.from_envelope(receipt_envelope)
        envelope = EnvelopeV1.create(
            RECEIPT_OBJECT_KIND,
            receipt_envelope.body,
            attestations=[
                {
                    "algorithm": "ed25519",
                    "key_id": self.key_id,
                    "signature_b64": self.signature_b64,
                }
            ],
        )
        if len(envelope.to_bytes()) > MAX_VERIFIER_RECEIPT_ENVELOPE_BYTES:
            raise VerificationError(
                "receipt_envelope_too_large",
                "signed verifier receipt exceeds the fixed byte ceiling",
            )
        return envelope

    def to_bytes(self) -> bytes:
        """Return the canonical attested protocol wire representation."""

        return self.to_envelope().to_bytes()

    @classmethod
    def from_bytes(cls, data: bytes | str) -> SignedVerifierReceiptV1:
        """Parse a canonical receipt envelope containing one Ed25519 attestation."""

        if type(data) is bytes:
            byte_length = len(data)
        elif type(data) is str:
            try:
                byte_length = len(data.encode("utf-8"))
            except UnicodeEncodeError as exc:
                raise VerificationError("invalid_envelope", "signed receipt wire is invalid") from exc
        else:
            raise VerificationError("invalid_envelope", "signed receipt wire must be bytes or str")
        if byte_length > MAX_VERIFIER_RECEIPT_ENVELOPE_BYTES:
            raise VerificationError(
                "receipt_envelope_too_large",
                "signed verifier receipt exceeds the fixed byte ceiling",
            )
        try:
            envelope = EnvelopeV1.from_bytes(data)
        except ProtocolError as exc:
            raise VerificationError("invalid_envelope", "signed receipt wire is invalid") from exc
        if envelope.object_kind != RECEIPT_OBJECT_KIND or len(envelope.attestations) != 1:
            raise VerificationError(
                "malformed_signed_receipt",
                "signed verifier wire requires exactly one receipt attestation",
            )
        attestation = thaw_json(envelope.attestations[0])
        if type(attestation) is not dict or set(attestation) != _ATTESTATION_FIELDS:
            raise VerificationError(
                "malformed_signed_receipt",
                "receipt signature attestation has missing or unknown fields",
            )
        if attestation["algorithm"] != "ed25519":
            raise VerificationError(
                "malformed_signed_receipt",
                "unsupported receipt signature algorithm",
            )
        unattested = EnvelopeV1.create(RECEIPT_OBJECT_KIND, envelope.body)
        if unattested.object_id != envelope.object_id:
            raise VerificationError("object_id_mismatch", "attested receipt identity changed")
        VerifierReceiptV1.from_envelope(unattested)
        return cls(
            envelope_bytes=unattested.to_bytes(),
            key_id=attestation["key_id"],
            signature_b64=attestation["signature_b64"],
        )


@dataclass(frozen=True, slots=True)
class VerifierSigner:
    """Controlled signing helper; key possession is not proof of isolation or truth."""

    private_key: Ed25519PrivateKey  # gitleaks:allow -- type annotation, never key material

    def __post_init__(self) -> None:
        if not isinstance(self.private_key, Ed25519PrivateKey):
            raise VerificationError("invalid_private_key", "signer requires an Ed25519 private key")

    @classmethod
    def generate(cls) -> VerifierSigner:
        return cls(Ed25519PrivateKey.generate())

    @property
    def public_key_bytes(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @property
    def key_id(self) -> str:
        return verifier_key_id(self.public_key_bytes)

    def sign(self, receipt: VerifierReceiptV1) -> SignedVerifierReceiptV1:
        if not isinstance(receipt, VerifierReceiptV1):
            raise VerificationError("invalid_receipt", "signer requires a VerifierReceiptV1")
        if receipt.verifier_key_id != self.key_id:
            raise VerificationError("signer_key_mismatch", "receipt is assigned to a different verifier key")
        envelope_bytes = receipt.to_envelope().to_bytes()
        signature = self.private_key.sign(_SIGNATURE_DOMAIN + envelope_bytes)
        return SignedVerifierReceiptV1(
            envelope_bytes=envelope_bytes,
            key_id=self.key_id,
            signature_b64=base64.b64encode(signature).decode("ascii"),
        )


@dataclass(frozen=True, slots=True)
class TrustedVerifierKey:
    """An immutable public key, verifier identity, and explicit role snapshot."""

    verifier_id: str
    public_key_bytes: bytes
    roles: frozenset[str]

    def __post_init__(self) -> None:
        _validate_identity(self.verifier_id, "verifier_id")
        if not is_valid_ed25519_public_key(self.public_key_bytes):
            raise VerificationError(
                "invalid_public_key",
                "Ed25519 public keys must be canonical prime-subgroup points",
            )
        try:
            Ed25519PublicKey.from_public_bytes(self.public_key_bytes)
        except ValueError as exc:
            raise VerificationError("invalid_public_key", "invalid Ed25519 public key") from exc
        if type(self.roles) is not frozenset or not self.roles:
            raise VerificationError("invalid_roles", "trusted keys require a non-empty frozen role set")
        if len(self.roles) > MAX_VERIFIER_ROLES:
            raise VerificationError("invalid_roles", "trusted key exceeds the role-count ceiling")
        if any(
            type(role) is not str or not role or role != role.strip() or _IDENTITY.fullmatch(role) is None
            for role in self.roles
        ):
            raise VerificationError("invalid_roles", "roles must be non-blank canonical identity strings")

    @property
    def key_id(self) -> str:
        return verifier_key_id(self.public_key_bytes)


@dataclass(frozen=True, slots=True)
class VerifierTrustStore:
    """Immutable verifier-key trust and revocation snapshot for one decision."""

    keys: Mapping[str, TrustedVerifierKey]
    revoked_key_ids: frozenset[str] = frozenset()
    revoked_receipt_ids: frozenset[str] = frozenset()
    revoked_lease_ids: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not isinstance(self.keys, Mapping):
            raise VerificationError("invalid_trust_store", "keys must be a mapping")
        copied: dict[str, TrustedVerifierKey] = {}
        for key_id, trusted_key in self.keys.items():
            if len(copied) >= MAX_TRUSTED_VERIFIER_KEYS:
                raise VerificationError(
                    "invalid_trust_store",
                    "trust store exceeds the key-count ceiling",
                )
            if type(key_id) is not str or _KEY_ID.fullmatch(key_id) is None:
                raise VerificationError("invalid_trust_store", "trust-store key IDs must be content-derived")
            if not isinstance(trusted_key, TrustedVerifierKey):
                raise VerificationError("invalid_trust_store", "trust-store values must be TrustedVerifierKey objects")
            if key_id != trusted_key.key_id:
                raise VerificationError("invalid_trust_store", "trust-store key ID does not match public key")
            copied[key_id] = trusted_key
        revoked_key_ids = _validated_identifier_frozenset(
            self.revoked_key_ids,
            _KEY_ID,
            "invalid_trust_store",
            MAX_VERIFIER_REVOCATIONS,
        )
        revoked_receipt_ids = _validated_identifier_frozenset(
            self.revoked_receipt_ids,
            _FULL_DIGEST,
            "invalid_trust_store",
            MAX_VERIFIER_REVOCATIONS,
        )
        revoked_lease_ids = _validated_identifier_frozenset(
            self.revoked_lease_ids,
            _FULL_DIGEST,
            "invalid_trust_store",
            MAX_VERIFIER_REVOCATIONS,
        )
        if len(revoked_key_ids) + len(revoked_receipt_ids) + len(revoked_lease_ids) > (MAX_VERIFIER_REVOCATIONS):
            raise VerificationError(
                "invalid_trust_store",
                "trust store exceeds the combined revocation-count ceiling",
            )
        object.__setattr__(self, "keys", MappingProxyType(copied))
        object.__setattr__(self, "revoked_key_ids", revoked_key_ids)
        object.__setattr__(self, "revoked_receipt_ids", revoked_receipt_ids)
        object.__setattr__(self, "revoked_lease_ids", revoked_lease_ids)

    @classmethod
    def from_keys(
        cls,
        trusted_keys: Iterable[TrustedVerifierKey],
        *,
        revoked_key_ids: Iterable[str] = (),
        revoked_receipt_ids: Iterable[str] = (),
        revoked_lease_ids: Iterable[str] = (),
    ) -> VerifierTrustStore:
        keys: dict[str, TrustedVerifierKey] = {}
        if isinstance(trusted_keys, (str, bytes)):
            raise VerificationError("invalid_trust_store", "trusted_keys must be iterable")
        try:
            for trusted_key in trusted_keys:
                if len(keys) >= MAX_TRUSTED_VERIFIER_KEYS:
                    raise VerificationError(
                        "invalid_trust_store",
                        "trust store exceeds the key-count ceiling",
                    )
                if not isinstance(trusted_key, TrustedVerifierKey):
                    raise VerificationError("invalid_trust_store", "trusted_keys contains an invalid entry")
                if trusted_key.key_id in keys:
                    raise VerificationError("invalid_trust_store", "duplicate trusted verifier key")
                keys[trusted_key.key_id] = trusted_key
        except TypeError as exc:
            raise VerificationError("invalid_trust_store", "trusted_keys must be iterable") from exc
        return cls(
            keys=keys,
            revoked_key_ids=_validated_identifier_frozenset(
                revoked_key_ids,
                _KEY_ID,
                "invalid_trust_store",
                MAX_VERIFIER_REVOCATIONS,
            ),
            revoked_receipt_ids=_validated_identifier_frozenset(
                revoked_receipt_ids,
                _FULL_DIGEST,
                "invalid_trust_store",
                MAX_VERIFIER_REVOCATIONS,
            ),
            revoked_lease_ids=_validated_identifier_frozenset(
                revoked_lease_ids,
                _FULL_DIGEST,
                "invalid_trust_store",
                MAX_VERIFIER_REVOCATIONS,
            ),
        )

    def to_snapshot_body(self) -> dict[str, object]:
        """Return the complete deterministic verifier trust/revocation view."""

        keys: list[dict[str, object]] = []
        for key_id, trusted_key in sorted(self.keys.items()):
            keys.append(
                {
                    "key_id": key_id,
                    "public_key_b64": base64.b64encode(trusted_key.public_key_bytes).decode("ascii"),
                    "roles": sorted(trusted_key.roles),
                    "verifier_id": trusted_key.verifier_id,
                }
            )
        return {
            "keys": keys,
            "revoked_key_ids": sorted(self.revoked_key_ids),
            "revoked_lease_ids": sorted(self.revoked_lease_ids),
            "revoked_receipt_ids": sorted(self.revoked_receipt_ids),
        }

    @property
    def snapshot_id(self) -> str:
        """Return the content identity of the exact trust view used for a decision."""

        return content_id("verifier_trust_snapshot", self.to_snapshot_body())

    @classmethod
    def from_snapshot_body(
        cls,
        body: object,
        *,
        expected_snapshot_id: str | None = None,
    ) -> VerifierTrustStore:
        """Strictly reconstruct a trust store from its canonical JSON snapshot body."""

        store = _trust_store_from_snapshot_body(body)
        if expected_snapshot_id is not None:
            if type(expected_snapshot_id) is not str or _FULL_DIGEST.fullmatch(expected_snapshot_id) is None:
                raise VerificationError(
                    "invalid_trust_snapshot",
                    "expected snapshot ID must be a full sha256 content ID",
                )
            if store.snapshot_id != expected_snapshot_id:
                raise VerificationError(
                    "trust_snapshot_mismatch",
                    "trust snapshot ID does not match its canonical body",
                )
        return store


@dataclass(frozen=True, slots=True)
class VerificationDecision:
    """A minimal receipt-admission result; this type never represents a finding.

    The accepted result identifies the exact verifier trust snapshot. The lifecycle
    kernel must retain that snapshot body with any future atomic receipt admission.
    """

    accepted: bool
    lease_id: str | None
    receipt_id: str | None
    verdict: str | None
    reason_code: str
    trust_snapshot_id: str | None = None

    def __post_init__(self) -> None:
        if type(self.accepted) is not bool:
            raise VerificationError("invalid_decision", "accepted must be a bool")
        if self.accepted:
            if (
                self.lease_id is None
                or _FULL_DIGEST.fullmatch(self.lease_id) is None
                or self.receipt_id is None
                or _FULL_DIGEST.fullmatch(self.receipt_id) is None
                or self.verdict not in VERDICTS
                or self.reason_code != "accepted"
                or self.trust_snapshot_id is None
                or _FULL_DIGEST.fullmatch(self.trust_snapshot_id) is None
            ):
                raise VerificationError("invalid_decision", "accepted decision fields are inconsistent")
        elif any(
            value is not None
            for value in (
                self.lease_id,
                self.receipt_id,
                self.verdict,
                self.trust_snapshot_id,
            )
        ):
            raise VerificationError("invalid_decision", "refused decisions cannot expose untrusted receipt claims")


def verifier_key_id(public_key_bytes: bytes) -> str:
    """Derive a full content identifier from raw Ed25519 public-key bytes."""

    if type(public_key_bytes) is not bytes or len(public_key_bytes) != 32:
        raise VerificationError("invalid_public_key", "Ed25519 public keys must contain exactly 32 bytes")
    return "ed25519:sha256:" + hashlib.sha256(public_key_bytes).hexdigest()


def validate_verifier_receipt(
    raw_signed_receipt: SignedVerifierReceiptV1 | Mapping[str, object] | bytes | str,
    trust_store: VerifierTrustStore,
    *,
    lease: VerificationLeaseV1,
    decision_time: int,
    expected_verdict: str,
    consumed_lease_ids: Set[str],
    retained_evidence_digests: Set[str],
) -> VerificationDecision:
    """Authenticate and validate one exact modeled-fixture verifier receipt.

    Acceptance authenticates the configured verifier's signature and validates the
    receipt/lease/evidence bindings.  It does not prove the scientific claim and does
    not mint a finding.  The caller must atomically persist lease consumption with any
    accepted receipt event; a pre-read set alone is not a concurrency primitive.
    """

    if not isinstance(trust_store, VerifierTrustStore):
        return _refuse("invalid_trust_store")
    if not isinstance(lease, VerificationLeaseV1):
        return _refuse("invalid_lease")
    if type(decision_time) is not int or decision_time < 0 or decision_time > MAX_EPOCH_SECOND:
        return _refuse("invalid_decision_time")
    if type(expected_verdict) is not str or expected_verdict not in VERDICTS:
        return _refuse("invalid_expected_verdict")
    try:
        consumed = _validated_digest_set(
            consumed_lease_ids,
            "invalid_consumed_lease_ids",
            MAX_CONSUMED_LEASE_IDS,
        )
        retained = _validated_digest_set(
            retained_evidence_digests,
            "invalid_retained_evidence",
            MAX_RETAINED_EVIDENCE_DIGESTS,
        )
        signed = _parse_signed_receipt(raw_signed_receipt)
    except VerificationError as exc:
        return _refuse(exc.reason_code)

    if lease.candidate_producer_id == lease.verifier_id:
        return _refuse("self_verification")
    if lease.lease_id in trust_store.revoked_lease_ids:
        return _refuse("lease_revoked")
    if lease.lease_id in consumed:
        return _refuse("lease_already_consumed")
    if decision_time < lease.issued_at:
        return _refuse("lease_not_yet_valid")
    if decision_time >= lease.expires_at:
        return _refuse("lease_expired")

    if signed.key_id in trust_store.revoked_key_ids:
        return _refuse("key_revoked")
    trusted_key = trust_store.keys.get(signed.key_id)
    if trusted_key is None:
        return _refuse("unknown_key")
    if VERIFIER_ROLE not in trusted_key.roles:
        return _refuse("key_missing_verifier_role")

    try:
        signature = _decode_canonical_signature(signed.signature_b64)
    except VerificationError:
        return _refuse("malformed_signature")
    try:
        Ed25519PublicKey.from_public_bytes(trusted_key.public_key_bytes).verify(
            signature,
            _SIGNATURE_DOMAIN + signed.envelope_bytes,
        )
    except (InvalidSignature, ValueError):
        return _refuse("invalid_signature")

    try:
        envelope = EnvelopeV1.from_bytes(signed.envelope_bytes)
        if envelope.to_bytes() != signed.envelope_bytes:
            return _refuse("noncanonical_envelope")
        receipt = VerifierReceiptV1.from_envelope(envelope)
    except ProtocolError as exc:
        return _refuse(_protocol_reason(exc))
    except VerificationError as exc:
        return _refuse(exc.reason_code)

    if receipt.receipt_id in trust_store.revoked_receipt_ids:
        return _refuse("receipt_revoked")
    if receipt.verifier_key_id != signed.key_id:
        return _refuse("signer_key_mismatch")
    if receipt.verifier_id != trusted_key.verifier_id:
        return _refuse("verifier_identity_mismatch")

    comparisons = (
        ("lease_id", "lease_mismatch"),
        ("mission_id", "mission_mismatch"),
        ("authority_id", "authority_mismatch"),
        ("target_snapshot_id", "target_mismatch"),
        ("candidate_id", "candidate_mismatch"),
        ("candidate_producer_id", "candidate_producer_mismatch"),
        ("poc_artifact_digest", "poc_artifact_mismatch"),
        ("evidence_artifact_digests", "evidence_artifacts_mismatch"),
        ("environment_digest", "environment_mismatch"),
        ("effect_oracle_id", "effect_oracle_mismatch"),
        ("verifier_id", "verifier_mismatch"),
        ("verifier_key_id", "verifier_key_mismatch"),
    )
    for field, reason in comparisons:
        if getattr(receipt, field) != getattr(lease, field):
            return _refuse(reason)

    if receipt.completed_at < lease.issued_at:
        return _refuse("receipt_before_lease")
    if receipt.completed_at >= lease.expires_at:
        return _refuse("receipt_after_expiry")
    if receipt.completed_at > decision_time:
        return _refuse("receipt_from_future")
    if receipt.evidence_tier != MODELED_FIXTURE_TIER:
        return _refuse("unsupported_evidence_tier")
    if receipt.verdict != expected_verdict:
        return _refuse("verdict_mismatch")
    verdict_reason = _verdict_consistency_reason(
        receipt.verdict,
        effect_observed=receipt.effect_observed,
        oracle_satisfied=receipt.oracle_satisfied,
    )
    if verdict_reason is not None:
        return _refuse(verdict_reason)

    referenced_evidence = {
        receipt.poc_artifact_digest,
        *receipt.evidence_artifact_digests,
        receipt.environment_digest,
        receipt.effect_oracle_id,
    }
    if not referenced_evidence.issubset(retained):
        return _refuse("referenced_evidence_missing")

    return VerificationDecision(
        accepted=True,
        lease_id=lease.lease_id,
        receipt_id=receipt.receipt_id,
        verdict=receipt.verdict,
        reason_code="accepted",
        trust_snapshot_id=trust_store.snapshot_id,
    )


def _validate_lease_values(values: Mapping[str, object]) -> None:
    expected = _LEASE_BODY_FIELDS - {"purpose"}
    if set(values) != expected:
        raise VerificationError("malformed_lease", "lease has missing or unknown fields")
    if type(values["lease_nonce"]) is not str or _NONCE.fullmatch(values["lease_nonce"]) is None:
        raise VerificationError("invalid_lease_nonce", "lease_nonce must be 128 bits of lowercase hexadecimal")
    for field in (
        "mission_id",
        "authority_id",
        "target_snapshot_id",
        "candidate_id",
        "poc_artifact_digest",
        "environment_digest",
        "effect_oracle_id",
    ):
        _validate_digest(values[field], field)
    _validate_identity(values["candidate_producer_id"], "candidate_producer_id")
    _validate_identity(values["verifier_id"], "verifier_id")
    _validate_key_id(values["verifier_key_id"], "verifier_key_id")
    _validate_evidence_tuple(values["evidence_artifact_digests"])
    _validate_times(values["issued_at"], values["expires_at"])


def _validate_receipt_values(values: Mapping[str, object]) -> None:
    if set(values) != _RECEIPT_BODY_FIELDS:
        raise VerificationError("malformed_receipt", "receipt has missing or unknown fields")
    for field in (
        "lease_id",
        "mission_id",
        "authority_id",
        "target_snapshot_id",
        "candidate_id",
        "poc_artifact_digest",
        "environment_digest",
        "effect_oracle_id",
    ):
        _validate_digest(values[field], field)
    _validate_identity(values["candidate_producer_id"], "candidate_producer_id")
    _validate_identity(values["verifier_id"], "verifier_id")
    _validate_key_id(values["verifier_key_id"], "verifier_key_id")
    _validate_evidence_tuple(values["evidence_artifact_digests"])
    if type(values["evidence_tier"]) is not str:
        raise VerificationError("invalid_evidence_tier", "evidence_tier must be a string")
    if values["evidence_tier"] != MODELED_FIXTURE_TIER:
        raise VerificationError("unsupported_evidence_tier", "only modeled_fixture evidence is admitted")
    if type(values["verdict"]) is not str or values["verdict"] not in VERDICTS:
        raise VerificationError("invalid_verdict", "unsupported verifier verdict")
    if type(values["effect_observed"]) is not bool or type(values["oracle_satisfied"]) is not bool:
        raise VerificationError("invalid_observation", "effect and oracle observations must be booleans")
    completed_at = values["completed_at"]
    if type(completed_at) is not int or completed_at < 0 or completed_at > MAX_EPOCH_SECOND:
        raise VerificationError("invalid_completed_at", "completed_at must be a nonnegative integer epoch second")


def _validate_digest(value: object, field: str) -> None:
    if type(value) is not str or _FULL_DIGEST.fullmatch(value) is None:
        raise VerificationError(f"invalid_{field}", f"{field} must be a full sha256 content ID")


def _validate_key_id(value: object, field: str) -> None:
    if type(value) is not str or _KEY_ID.fullmatch(value) is None:
        raise VerificationError(f"invalid_{field}", f"{field} must be a content-derived Ed25519 key ID")


def _validate_identity(value: object, field: str) -> None:
    if type(value) is not str or _IDENTITY.fullmatch(value) is None:
        raise VerificationError(f"invalid_{field}", f"{field} must be a canonical identity string")


def _validate_evidence_tuple(value: object) -> None:
    if type(value) is not tuple or not value:
        raise VerificationError(
            "invalid_evidence_artifact_digests",
            "evidence_artifact_digests must be a non-empty tuple",
        )
    if len(value) > MAX_EVIDENCE_ARTIFACTS:
        raise VerificationError(
            "too_many_evidence_artifacts",
            "evidence artifacts exceed the fixed count ceiling",
        )
    if any(type(digest) is not str or _FULL_DIGEST.fullmatch(digest) is None for digest in value):
        raise VerificationError(
            "invalid_evidence_artifact_digests",
            "each evidence artifact must have a full sha256 content ID",
        )
    if len(set(value)) != len(value):
        raise VerificationError("duplicate_evidence_artifact", "evidence artifact digests must be unique")
    if value != tuple(sorted(value)):
        raise VerificationError("noncanonical_evidence_order", "evidence artifact digests must be sorted")


def _validate_times(issued_at: object, expires_at: object) -> None:
    if (
        type(issued_at) is not int
        or type(expires_at) is not int
        or issued_at < 0
        or expires_at < 0
        or issued_at > MAX_EPOCH_SECOND
        or expires_at > MAX_EPOCH_SECOND
    ):
        raise VerificationError("invalid_lease_time", "lease times must be nonnegative integer epoch seconds")
    if issued_at >= expires_at:
        raise VerificationError("invalid_lease_window", "lease interval must satisfy issued_at < expires_at")


def _create_envelope(kind: str, body: object) -> EnvelopeV1:
    try:
        return EnvelopeV1.create(kind, body)
    except ProtocolError as exc:
        raise VerificationError("invalid_protocol_value", "object cannot be represented by protocol v1") from exc


def _parse_signed_receipt(
    raw_signed_receipt: SignedVerifierReceiptV1 | Mapping[str, object] | bytes | str,
) -> SignedVerifierReceiptV1:
    if isinstance(raw_signed_receipt, SignedVerifierReceiptV1):
        return raw_signed_receipt
    if type(raw_signed_receipt) in {bytes, str}:
        return SignedVerifierReceiptV1.from_bytes(raw_signed_receipt)
    if not isinstance(raw_signed_receipt, Mapping):
        raise VerificationError("unsigned_receipt", "verification input must be a signed receipt")
    raw = dict(raw_signed_receipt)
    if "signature_b64" not in raw:
        raise VerificationError("unsigned_receipt", "verification input has no detached signature")
    if set(raw) != _SIGNED_FIELDS:
        raise VerificationError(
            "malformed_signed_receipt",
            "signed receipt has missing or unknown fields",
        )
    try:
        return SignedVerifierReceiptV1(
            envelope_bytes=raw["envelope_bytes"],
            key_id=raw["key_id"],
            signature_b64=raw["signature_b64"],
        )
    except VerificationError:
        raise
    except (TypeError, ValueError) as exc:
        raise VerificationError("malformed_signed_receipt", "signed receipt is malformed") from exc


def _decode_canonical_signature(value: object) -> bytes:
    if type(value) is not str or len(value) != 88:
        raise VerificationError(
            "malformed_signature",
            "signature_b64 must be one canonical Ed25519 signature",
        )
    try:
        signature = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise VerificationError(
            "malformed_signature",
            "signature_b64 must be one canonical Ed25519 signature",
        ) from exc
    if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != value:
        raise VerificationError(
            "malformed_signature",
            "signature_b64 must be one canonical Ed25519 signature",
        )
    return signature


def _trust_store_from_snapshot_body(body: object) -> VerifierTrustStore:
    if type(body) is not dict or len(body) != len(_TRUST_SNAPSHOT_FIELDS) or set(body) != _TRUST_SNAPSHOT_FIELDS:
        raise VerificationError(
            "invalid_trust_snapshot",
            "trust snapshot has missing or unknown fields",
        )
    keys = body["keys"]
    revoked_key_ids = body["revoked_key_ids"]
    revoked_lease_ids = body["revoked_lease_ids"]
    revoked_receipt_ids = body["revoked_receipt_ids"]
    if (
        type(keys) is not list
        or type(revoked_key_ids) is not list
        or type(revoked_lease_ids) is not list
        or type(revoked_receipt_ids) is not list
    ):
        raise VerificationError(
            "invalid_trust_snapshot",
            "trust snapshot collections must be arrays",
        )
    if len(keys) > MAX_TRUSTED_VERIFIER_KEYS:
        raise VerificationError(
            "invalid_trust_snapshot",
            "trust snapshot exceeds the key-count ceiling",
        )
    if len(revoked_key_ids) + len(revoked_lease_ids) + len(revoked_receipt_ids) > (MAX_VERIFIER_REVOCATIONS):
        raise VerificationError(
            "invalid_trust_snapshot",
            "trust snapshot exceeds the revocation-count ceiling",
        )

    trusted_keys: list[TrustedVerifierKey] = []
    observed_key_ids: list[str] = []
    for entry in keys:
        if (
            type(entry) is not dict
            or len(entry) != len(_TRUST_SNAPSHOT_KEY_FIELDS)
            or set(entry) != _TRUST_SNAPSHOT_KEY_FIELDS
        ):
            raise VerificationError(
                "invalid_trust_snapshot",
                "trust snapshot key entry is malformed",
            )
        key_id = entry["key_id"]
        public_key_b64 = entry["public_key_b64"]
        roles = entry["roles"]
        verifier_id = entry["verifier_id"]
        if (
            type(key_id) is not str
            or _KEY_ID.fullmatch(key_id) is None
            or type(public_key_b64) is not str
            or len(public_key_b64) != 44
            or type(roles) is not list
            or not roles
            or len(roles) > MAX_VERIFIER_ROLES
            or any(type(role) is not str or _IDENTITY.fullmatch(role) is None or role != role.strip() for role in roles)
            or roles != sorted(set(roles))
            or type(verifier_id) is not str
            or _IDENTITY.fullmatch(verifier_id) is None
            or verifier_id != verifier_id.strip()
        ):
            raise VerificationError(
                "invalid_trust_snapshot",
                "trust snapshot key identity or roles are noncanonical",
            )
        try:
            public_key_bytes = base64.b64decode(public_key_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise VerificationError(
                "invalid_trust_snapshot",
                "trust snapshot public key is malformed",
            ) from exc
        if (
            len(public_key_bytes) != 32
            or base64.b64encode(public_key_bytes).decode("ascii") != public_key_b64
            or verifier_key_id(public_key_bytes) != key_id
            or not is_valid_ed25519_public_key(public_key_bytes)
        ):
            raise VerificationError(
                "invalid_trust_snapshot",
                "trust snapshot public key identity is malformed",
            )
        try:
            trusted_key = TrustedVerifierKey(
                verifier_id=verifier_id,
                public_key_bytes=public_key_bytes,
                roles=frozenset(roles),
            )
        except VerificationError as exc:
            raise VerificationError(
                "invalid_trust_snapshot",
                "trust snapshot contains an invalid trusted key",
            ) from exc
        observed_key_ids.append(key_id)
        trusted_keys.append(trusted_key)
    if observed_key_ids != sorted(set(observed_key_ids)):
        raise VerificationError(
            "invalid_trust_snapshot",
            "trust snapshot keys are not in unique canonical order",
        )

    for values, pattern in (
        (revoked_key_ids, _KEY_ID),
        (revoked_lease_ids, _FULL_DIGEST),
        (revoked_receipt_ids, _FULL_DIGEST),
    ):
        if any(type(value) is not str or pattern.fullmatch(value) is None for value in values) or values != sorted(
            set(values)
        ):
            raise VerificationError(
                "invalid_trust_snapshot",
                "trust snapshot revocations are noncanonical",
            )
    try:
        store = VerifierTrustStore.from_keys(
            trusted_keys,
            revoked_key_ids=revoked_key_ids,
            revoked_lease_ids=revoked_lease_ids,
            revoked_receipt_ids=revoked_receipt_ids,
        )
    except VerificationError as exc:
        raise VerificationError(
            "invalid_trust_snapshot",
            "trust snapshot cannot be reconstructed",
        ) from exc
    if store.to_snapshot_body() != body:
        raise VerificationError(
            "invalid_trust_snapshot",
            "trust snapshot body is not canonical",
        )
    return store


def _validated_identifier_frozenset(
    values: Iterable[str],
    pattern: re.Pattern[str],
    reason: str,
    maximum_items: int,
) -> frozenset[str]:
    if isinstance(values, (str, bytes)):
        raise VerificationError(reason, "identifier collection must not be a string")
    try:
        result: set[str] = set()
        for index, value in enumerate(values):
            if index >= maximum_items:
                raise VerificationError(reason, "identifier collection exceeds its fixed count ceiling")
            if type(value) is not str or pattern.fullmatch(value) is None:
                raise VerificationError(reason, "identifier collection contains an invalid value")
            if value in result:
                raise VerificationError(reason, "identifier collection contains a duplicate")
            result.add(value)
    except TypeError as exc:
        raise VerificationError(reason, "identifier collection must be iterable") from exc
    return frozenset(result)


def _validated_digest_set(
    values: Set[str],
    reason: str,
    maximum_items: int,
) -> frozenset[str]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Set):
        raise VerificationError(reason, "digest collection must be a set")
    if len(values) > maximum_items:
        raise VerificationError(reason, "digest collection exceeds its fixed count ceiling")
    return _validated_identifier_frozenset(values, _FULL_DIGEST, reason, maximum_items)


def _verdict_consistency_reason(
    verdict: str,
    *,
    effect_observed: bool,
    oracle_satisfied: bool,
) -> str | None:
    if verdict == "confirmed":
        if not effect_observed:
            return "confirmed_without_effect"
        if not oracle_satisfied:
            return "confirmed_without_oracle"
        return None
    if verdict == "not_reproduced":
        if effect_observed or oracle_satisfied:
            return "not_reproduced_with_positive_observation"
        return None
    if verdict == "invalid":
        if effect_observed or oracle_satisfied:
            return "invalid_with_positive_observation"
        return None
    if verdict == "inconclusive" and effect_observed and oracle_satisfied:
        return "inconclusive_with_confirmed_observation"
    return None


def _protocol_reason(exc: ProtocolError) -> str:
    if getattr(exc, "code", "") == "object_id_mismatch":
        return "object_id_mismatch"
    return "invalid_envelope"


def _refuse(reason_code: str) -> VerificationDecision:
    return VerificationDecision(
        accepted=False,
        lease_id=None,
        receipt_id=None,
        verdict=None,
        reason_code=reason_code,
    )
