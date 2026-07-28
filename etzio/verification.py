"""Fail-closed modeled-fixture verification receipts for Etzio protocol v1.

This module authenticates a configured verifier identity and binds its signed result to
one exact, expiring verification lease.  It does not prove that the result is true, that
the lease or artifact resolution was kernel-issued and retained, or that the signer was
actually independent. It requires the exact modeled resolution and revalidates its current
CAS bytes, but that establishes byte identity and assigned input role only. It does not
claim process, container, VM, KVM, or hardware isolation. The only evidence tier admitted
by this foundation boundary is ``modeled_fixture``.

The receipt signs the exact artifact-resolution identity and four separately typed output
identities and byte counts. :func:`validate_verifier_receipt` still produces only a
standalone non-authoritative proposal; it observes a caller-supplied consumed-lease set and
does not mutate mission history. The lifecycle kernel separately loads the canonical
resolution, derives output role/type/size bindings, and can atomically admit the receipt
with single-use lease consumption.
The lease binds its issuance-trust snapshot identity, while receipt proposals separately
identify the supplied proposal-time revocation view. These are deterministic retrospective
identities; this module does not establish snapshot continuity, freshness, or trusted time.
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
from etzio.evidence import (
    VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1,
    VERIFICATION_OUTPUT_ARTIFACT_TYPE_BY_ROLE_V1,
    EvidenceError,
    FileEvidenceStore,
    TargetSnapshotV1,
    validate_etzio_fixture_snapshot,
)
from etzio.protocol import (
    SEMANTIC_BODY_FIELDS_BY_KIND_V1,
    EnvelopeV1,
    ProtocolError,
    content_id,
    thaw_json,
)
from etzio.verification_artifacts import (
    TARGET_ARTIFACT_TYPE_V1,
    VerificationArtifactBindingV1,
    VerificationArtifactResolutionV1,
)

LEASE_OBJECT_KIND: Final = "verification_lease"
RECEIPT_OBJECT_KIND: Final = "verifier_receipt"
LEASE_PURPOSE: Final = "modeled_fixture_verification"
MODELED_FIXTURE_TIER: Final = "modeled_fixture"
VERIFIER_ROLE: Final = "modeled_fixture_verifier"
VERDICTS: Final = frozenset({"confirmed", "not_reproduced", "inconclusive", "invalid"})

# Foundation ceilings bound all attacker-controlled collections and signed wire objects.
MAX_VERIFIER_RECEIPT_ENVELOPE_BYTES: Final = 256 * 1024
MAX_EVIDENCE_ARTIFACTS: Final = 256
MAX_TYPED_VERIFICATION_OUTPUT_BYTES_V1: Final = 64 * 1024 * 1024
MAX_TRUSTED_VERIFIER_KEYS: Final = 64
MAX_VERIFIER_ROLES: Final = 16
MAX_VERIFIER_REVOCATIONS: Final = 10_000
MAX_CONSUMED_LEASE_IDS: Final = 100_000
MAX_EPOCH_SECOND: Final = (2**63) - 1

_SIGNATURE_DOMAIN: Final = b"etzio.verifier-receipt.signature.v1\x00"
_FULL_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
_KEY_ID = re.compile(r"^ed25519:sha256:[0-9a-f]{64}$", re.ASCII)
_NONCE = re.compile(r"^[0-9a-f]{32}$", re.ASCII)
_IDENTITY = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{1,127}$", re.ASCII)
_LEASE_BODY_FIELDS: Final = SEMANTIC_BODY_FIELDS_BY_KIND_V1["verification_lease"]
_RECEIPT_BODY_FIELDS: Final = SEMANTIC_BODY_FIELDS_BY_KIND_V1["verifier_receipt"]
_SIGNED_FIELDS: Final = frozenset({"envelope_bytes", "key_id", "signature_b64"})
_ATTESTATION_FIELDS: Final = frozenset({"algorithm", "key_id", "signature_b64"})
_OUTPUT_FIELDS_BY_ROLE_V1: Final = (
    (
        "execution_output",
        "execution_output_digest",
        "execution_output_size",
    ),
    (
        "effect_output",
        "effect_output_digest",
        "effect_output_size",
    ),
    (
        "measured_environment_output",
        "measured_environment_output_digest",
        "measured_environment_output_size",
    ),
    (
        "termination_output",
        "termination_output_digest",
        "termination_output_size",
    ),
)
VERIFIER_TRUST_SNAPSHOT_FIELDS_V1: Final = frozenset(
    {
        "keys",
        "revoked_key_ids",
        "revoked_lease_ids",
        "revoked_receipt_ids",
    }
)
VERIFIER_TRUST_KEY_FIELDS_V1: Final = frozenset({"key_id", "public_key_b64", "roles", "verifier_id"})


class VerificationError(ValueError):
    """A deterministic verification-object construction or validation failure."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


def derive_verification_lease_nonce(
    *,
    prior_event_digest: str,
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
    issuance_trust_snapshot_id: str,
) -> str:
    """Derive public nonce material for one canonical kernel issuance event."""

    digest = content_id(
        "verification_lease_nonce",
        {
            "authority_id": authority_id,
            "candidate_id": candidate_id,
            "candidate_producer_id": candidate_producer_id,
            "effect_oracle_id": effect_oracle_id,
            "environment_digest": environment_digest,
            "evidence_artifact_digests": list(evidence_artifact_digests),
            "expires_at": expires_at,
            "issued_at": issued_at,
            "mission_id": mission_id,
            "poc_artifact_digest": poc_artifact_digest,
            "prior_event_digest": prior_event_digest,
            "target_snapshot_id": target_snapshot_id,
            "verifier_id": verifier_id,
            "verifier_key_id": verifier_key_id,
            "issuance_trust_snapshot_id": issuance_trust_snapshot_id,
        },
    )
    return digest.removeprefix("sha256:")[:32]


@dataclass(frozen=True, slots=True)
class VerificationLeaseV1:
    """One immutable, content-addressed modeled assignment value.

    Construction alone grants no authority. A lease is kernel-issued only when the
    lifecycle reducer accepts its canonical ``verification_lease_issued`` event.
    ``lease_nonce`` is public 128-bit uniqueness material, not a secret or an
    authentication token.
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
    issuance_trust_snapshot_id: str
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
        issuance_trust_snapshot_id: str,
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
            "issuance_trust_snapshot_id": issuance_trust_snapshot_id,
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
            "issuance_trust_snapshot_id": self.issuance_trust_snapshot_id,
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
    artifact_resolution_id: str
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
    execution_output_digest: str
    execution_output_size: int
    effect_output_digest: str
    effect_output_size: int
    measured_environment_output_digest: str
    measured_environment_output_size: int
    termination_output_digest: str
    termination_output_size: int
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
        artifact_resolution_id: str,
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
        execution_output_digest: str,
        execution_output_size: int,
        effect_output_digest: str,
        effect_output_size: int,
        measured_environment_output_digest: str,
        measured_environment_output_size: int,
        termination_output_digest: str,
        termination_output_size: int,
        verifier_id: str,
        verifier_key_id: str,
        evidence_tier: str,
        verdict: str,
        effect_observed: bool,
        oracle_satisfied: bool,
        completed_at: int,
    ) -> VerifierReceiptV1:
        values = {
            "artifact_resolution_id": artifact_resolution_id,
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
            "execution_output_digest": execution_output_digest,
            "execution_output_size": execution_output_size,
            "effect_output_digest": effect_output_digest,
            "effect_output_size": effect_output_size,
            "measured_environment_output_digest": measured_environment_output_digest,
            "measured_environment_output_size": measured_environment_output_size,
            "termination_output_digest": termination_output_digest,
            "termination_output_size": termination_output_size,
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
        artifact_resolution_id: str,
        execution_output_digest: str,
        execution_output_size: int,
        effect_output_digest: str,
        effect_output_size: int,
        measured_environment_output_digest: str,
        measured_environment_output_size: int,
        termination_output_digest: str,
        termination_output_size: int,
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
            artifact_resolution_id=artifact_resolution_id,
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
            execution_output_digest=execution_output_digest,
            execution_output_size=execution_output_size,
            effect_output_digest=effect_output_digest,
            effect_output_size=effect_output_size,
            measured_environment_output_digest=measured_environment_output_digest,
            measured_environment_output_size=measured_environment_output_size,
            termination_output_digest=termination_output_digest,
            termination_output_size=termination_output_size,
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
            "artifact_resolution_id": self.artifact_resolution_id,
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
            "execution_output_digest": self.execution_output_digest,
            "execution_output_size": self.execution_output_size,
            "effect_output_digest": self.effect_output_digest,
            "effect_output_size": self.effect_output_size,
            "measured_environment_output_digest": self.measured_environment_output_digest,
            "measured_environment_output_size": self.measured_environment_output_size,
            "termination_output_digest": self.termination_output_digest,
            "termination_output_size": self.termination_output_size,
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
class AuthenticatedVerifierReceiptV1:
    """A pure authenticated receipt result with no CAS or lifecycle authority.

    Only an instance returned by :func:`authenticate_verifier_receipt` carries evidence
    that signature and trust checks ran. Direct construction is coherence-checked but
    cannot itself establish cryptographic authentication.
    """

    signed_receipt: SignedVerifierReceiptV1
    receipt: VerifierReceiptV1
    lease: VerificationLeaseV1
    artifact_resolution: VerificationArtifactResolutionV1
    decision_trust_snapshot_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.signed_receipt, SignedVerifierReceiptV1):
            raise VerificationError(
                "invalid_authenticated_receipt",
                "signed_receipt must be a SignedVerifierReceiptV1",
            )
        if not isinstance(self.receipt, VerifierReceiptV1):
            raise VerificationError(
                "invalid_authenticated_receipt",
                "receipt must be a VerifierReceiptV1",
            )
        if not isinstance(self.lease, VerificationLeaseV1):
            raise VerificationError(
                "invalid_authenticated_receipt",
                "lease must be a VerificationLeaseV1",
            )
        if not isinstance(
            self.artifact_resolution,
            VerificationArtifactResolutionV1,
        ):
            raise VerificationError(
                "invalid_authenticated_receipt",
                "artifact_resolution must be a VerificationArtifactResolutionV1",
            )
        _validate_digest(
            self.decision_trust_snapshot_id,
            "decision_trust_snapshot_id",
        )
        if (
            self.signed_receipt.key_id != self.receipt.verifier_key_id
            or self.signed_receipt.envelope_bytes
            != self.receipt.to_envelope().to_bytes()
        ):
            raise VerificationError(
                "invalid_authenticated_receipt",
                "signed_receipt and receipt do not describe the same attested value",
            )
        binding_reason = _artifact_resolution_binding_reason(
            self.artifact_resolution,
            lease=self.lease,
            receipt=self.receipt,
            decision_time=MAX_EPOCH_SECOND,
        )
        if binding_reason is not None:
            raise VerificationError(
                "invalid_authenticated_receipt",
                "receipt, lease, and artifact resolution are internally incoherent",
            )


@dataclass(frozen=True, slots=True)
class VerificationOutputArtifactsV1:
    """Code-owned typed bindings reconstructed from signed output digests and sizes."""

    execution_output_artifact: VerificationArtifactBindingV1
    effect_output_artifact: VerificationArtifactBindingV1
    measured_environment_output_artifact: VerificationArtifactBindingV1
    termination_output_artifact: VerificationArtifactBindingV1

    def __post_init__(self) -> None:
        expected = (
            (
                self.execution_output_artifact,
                VERIFICATION_OUTPUT_ARTIFACT_TYPE_BY_ROLE_V1["execution_output"],
            ),
            (
                self.effect_output_artifact,
                VERIFICATION_OUTPUT_ARTIFACT_TYPE_BY_ROLE_V1["effect_output"],
            ),
            (
                self.measured_environment_output_artifact,
                VERIFICATION_OUTPUT_ARTIFACT_TYPE_BY_ROLE_V1["measured_environment_output"],
            ),
            (
                self.termination_output_artifact,
                VERIFICATION_OUTPUT_ARTIFACT_TYPE_BY_ROLE_V1["termination_output"],
            ),
        )
        if any(
            not isinstance(binding, VerificationArtifactBindingV1) or binding.artifact_type != artifact_type
            for binding, artifact_type in expected
        ):
            raise VerificationError(
                "invalid_verification_output_binding",
                "verification output binding has the wrong code-owned type",
            )
        digests = tuple(binding.artifact_digest for binding, _ in expected)
        if len(set(digests)) != len(digests):
            raise VerificationError(
                "output_artifact_role_collision",
                "verification output roles must use distinct content identities",
            )
        if self.total_bytes > MAX_TYPED_VERIFICATION_OUTPUT_BYTES_V1:
            raise VerificationError(
                "verification_output_byte_ceiling_exceeded",
                "verification outputs exceed the fixed aggregate byte ceiling",
            )

    @property
    def total_bytes(self) -> int:
        return sum(
            binding.size
            for binding in (
                self.execution_output_artifact,
                self.effect_output_artifact,
                self.measured_environment_output_artifact,
                self.termination_output_artifact,
            )
        )


@dataclass(frozen=True, slots=True)
class VerificationProposal:
    """A non-authoritative modeled receipt-validation proposal.

    An eligible proposal distinguishes the lease's issuance-trust identity from the
    proposal-time revocation view and records the supplied resolution context. It does not
    prove that the lease, grant, or resolution was retained. The lifecycle kernel must load
    those values from canonical history and independently repeat authentication, CAS, and
    byte-budget checks before atomic receipt admission.
    """

    eligible: bool
    lease_id: str | None
    receipt_id: str | None
    verdict: str | None
    reason_code: str
    issuance_trust_snapshot_id: str | None = None
    decision_trust_snapshot_id: str | None = None
    artifact_resolution_id: str | None = None
    output_artifacts: VerificationOutputArtifactsV1 | None = None

    def __post_init__(self) -> None:
        if type(self.eligible) is not bool:
            raise VerificationError("invalid_proposal", "eligible must be a bool")
        if self.eligible:
            if (
                self.lease_id is None
                or _FULL_DIGEST.fullmatch(self.lease_id) is None
                or self.receipt_id is None
                or _FULL_DIGEST.fullmatch(self.receipt_id) is None
                or self.verdict not in VERDICTS
                or self.reason_code != "proposal_valid"
                or self.issuance_trust_snapshot_id is None
                or _FULL_DIGEST.fullmatch(self.issuance_trust_snapshot_id) is None
                or self.decision_trust_snapshot_id is None
                or _FULL_DIGEST.fullmatch(self.decision_trust_snapshot_id) is None
                or self.artifact_resolution_id is None
                or _FULL_DIGEST.fullmatch(self.artifact_resolution_id) is None
                or not isinstance(
                    self.output_artifacts,
                    VerificationOutputArtifactsV1,
                )
            ):
                raise VerificationError(
                    "invalid_proposal",
                    "eligible proposal fields are inconsistent",
                )
        elif any(
            value is not None
            for value in (
                self.lease_id,
                self.receipt_id,
                self.verdict,
                self.issuance_trust_snapshot_id,
                self.decision_trust_snapshot_id,
                self.artifact_resolution_id,
                self.output_artifacts,
            )
        ):
            raise VerificationError(
                "invalid_proposal",
                "ineligible proposals cannot expose untrusted receipt claims",
            )


def verifier_key_id(public_key_bytes: bytes) -> str:
    """Derive a full content identifier from raw Ed25519 public-key bytes."""

    if type(public_key_bytes) is not bytes or len(public_key_bytes) != 32:
        raise VerificationError("invalid_public_key", "Ed25519 public keys must contain exactly 32 bytes")
    return "ed25519:sha256:" + hashlib.sha256(public_key_bytes).hexdigest()


def authenticate_verifier_receipt(
    raw_signed_receipt: SignedVerifierReceiptV1 | Mapping[str, object] | bytes | str,
    trust_store: VerifierTrustStore,
    *,
    lease: VerificationLeaseV1,
    artifact_resolution: VerificationArtifactResolutionV1,
    decision_time: int,
    expected_verdict: str | None = None,
) -> AuthenticatedVerifierReceiptV1:
    """Purely authenticate one receipt and its exact lease/resolution bindings.

    This function performs no CAS reads and changes no lifecycle state. A successful
    result authenticates a modeled statement; it is not receipt admission or a finding.
    """

    if not isinstance(trust_store, VerifierTrustStore):
        raise VerificationError("invalid_trust_store", "invalid verifier trust store")
    if not isinstance(lease, VerificationLeaseV1):
        raise VerificationError("invalid_lease", "invalid verification lease")
    if not isinstance(artifact_resolution, VerificationArtifactResolutionV1):
        raise VerificationError(
            "invalid_artifact_resolution",
            "invalid verification artifact resolution",
        )
    if type(decision_time) is not int or decision_time < 0 or decision_time > MAX_EPOCH_SECOND:
        raise VerificationError(
            "invalid_decision_time",
            "decision_time must be a nonnegative int64 epoch second",
        )
    if expected_verdict is not None and (type(expected_verdict) is not str or expected_verdict not in VERDICTS):
        raise VerificationError(
            "invalid_expected_verdict",
            "expected_verdict must be None or a supported verdict",
        )
    try:
        signed = _parse_signed_receipt(raw_signed_receipt)
    except VerificationError:
        raise

    if lease.candidate_producer_id == lease.verifier_id:
        raise VerificationError(
            "self_verification",
            "candidate producer cannot verify its own candidate",
        )
    if lease.lease_id in trust_store.revoked_lease_ids:
        raise VerificationError("lease_revoked", "verification lease is revoked")
    if decision_time < lease.issued_at:
        raise VerificationError(
            "lease_not_yet_valid",
            "verification lease is not yet valid",
        )
    if decision_time >= lease.expires_at:
        raise VerificationError("lease_expired", "verification lease is expired")

    if signed.key_id in trust_store.revoked_key_ids:
        raise VerificationError("key_revoked", "verifier key is revoked")
    trusted_key = trust_store.keys.get(signed.key_id)
    if trusted_key is None:
        raise VerificationError("unknown_key", "verifier key is not trusted")
    if VERIFIER_ROLE not in trusted_key.roles:
        raise VerificationError(
            "key_missing_verifier_role",
            "verifier key lacks the required role",
        )

    try:
        signature = _decode_canonical_signature(signed.signature_b64)
    except VerificationError as exc:
        raise VerificationError(
            "malformed_signature",
            "verifier signature is malformed",
        ) from exc
    try:
        Ed25519PublicKey.from_public_bytes(trusted_key.public_key_bytes).verify(
            signature,
            _SIGNATURE_DOMAIN + signed.envelope_bytes,
        )
    except (InvalidSignature, ValueError) as exc:
        raise VerificationError(
            "invalid_signature",
            "verifier signature is invalid",
        ) from exc

    try:
        envelope = EnvelopeV1.from_bytes(signed.envelope_bytes)
        if envelope.to_bytes() != signed.envelope_bytes:
            raise VerificationError(
                "noncanonical_envelope",
                "receipt envelope bytes are noncanonical",
            )
        receipt = VerifierReceiptV1.from_envelope(envelope)
    except ProtocolError as exc:
        raise VerificationError(
            _protocol_reason(exc),
            "receipt envelope violates protocol v1",
        ) from exc

    if receipt.receipt_id in trust_store.revoked_receipt_ids:
        raise VerificationError("receipt_revoked", "verifier receipt is revoked")
    if receipt.verifier_key_id != signed.key_id:
        raise VerificationError(
            "signer_key_mismatch",
            "receipt verifier key differs from its attestation",
        )
    if receipt.verifier_id != trusted_key.verifier_id:
        raise VerificationError(
            "verifier_identity_mismatch",
            "receipt verifier identity differs from the trusted key",
        )

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
            raise VerificationError(
                reason,
                f"receipt {field} differs from the verification lease",
            )

    if receipt.completed_at < lease.issued_at:
        raise VerificationError(
            "receipt_before_lease",
            "receipt completion precedes lease issuance",
        )
    if receipt.completed_at >= lease.expires_at:
        raise VerificationError(
            "receipt_after_expiry",
            "receipt completion is outside the lease window",
        )
    if receipt.completed_at > decision_time:
        raise VerificationError(
            "receipt_from_future",
            "receipt completion is later than decision time",
        )
    if receipt.evidence_tier != MODELED_FIXTURE_TIER:
        raise VerificationError(
            "unsupported_evidence_tier",
            "only modeled_fixture evidence is admitted",
        )
    if expected_verdict is not None and receipt.verdict != expected_verdict:
        raise VerificationError(
            "verdict_mismatch",
            "signed receipt verdict differs from the expected verdict",
        )
    verdict_reason = _verdict_consistency_reason(
        receipt.verdict,
        effect_observed=receipt.effect_observed,
        oracle_satisfied=receipt.oracle_satisfied,
    )
    if verdict_reason is not None:
        raise VerificationError(
            verdict_reason,
            "receipt verdict and observations are inconsistent",
        )

    resolution_reason = _artifact_resolution_binding_reason(
        artifact_resolution,
        lease=lease,
        receipt=receipt,
        decision_time=decision_time,
    )
    if resolution_reason is not None:
        raise VerificationError(
            resolution_reason,
            "receipt does not bind the exact verification artifact resolution",
        )

    return AuthenticatedVerifierReceiptV1(
        signed_receipt=signed,
        receipt=receipt,
        lease=lease,
        artifact_resolution=artifact_resolution,
        decision_trust_snapshot_id=trust_store.snapshot_id,
    )


def _artifact_resolution_binding_reason(
    resolution: VerificationArtifactResolutionV1,
    *,
    lease: VerificationLeaseV1,
    receipt: VerifierReceiptV1,
    decision_time: int,
) -> str | None:
    """Validate receipt/lease/resolution semantics without reading mutable CAS."""

    identity_comparisons = (
        (
            receipt.artifact_resolution_id,
            resolution.resolution_id,
            "artifact_resolution_mismatch",
        ),
        (resolution.verification_lease_id, lease.lease_id, "resolution_lease_mismatch"),
        (resolution.mission_id, lease.mission_id, "resolution_mission_mismatch"),
        (resolution.authority_id, lease.authority_id, "resolution_authority_mismatch"),
        (resolution.target_snapshot_id, lease.target_snapshot_id, "resolution_target_mismatch"),
        (resolution.candidate_id, lease.candidate_id, "resolution_candidate_mismatch"),
    )
    for actual, expected, reason in identity_comparisons:
        if actual != expected:
            return reason
    if resolution.resolved_at < lease.issued_at:
        return "resolution_before_lease"
    if resolution.resolved_at >= lease.expires_at:
        return "resolution_after_expiry"
    if resolution.resolved_at >= receipt.completed_at:
        return "resolution_after_receipt"
    if resolution.resolved_at > decision_time:
        return "resolution_from_future"

    if len(resolution.evidence_artifacts) != len(lease.evidence_artifact_digests):
        return "resolution_evidence_artifacts_mismatch"
    binding_values: list[tuple[str, VerificationArtifactBindingV1, str, str]] = [
        (
            "poc",
            resolution.poc_artifact,
            lease.poc_artifact_digest,
            VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["poc"],
        ),
    ]
    binding_values.extend(
        (
            f"evidence_{index}",
            binding,
            expected_digest,
            VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["evidence"],
        )
        for index, (binding, expected_digest) in enumerate(
            zip(
                resolution.evidence_artifacts,
                lease.evidence_artifact_digests,
                strict=True,
            )
        )
    )
    binding_values.extend(
        [
            (
                "environment",
                resolution.environment_artifact,
                lease.environment_digest,
                VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["environment"],
            ),
            (
                "effect_oracle",
                resolution.effect_oracle_artifact,
                lease.effect_oracle_id,
                VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["effect_oracle"],
            ),
        ]
    )
    bindings = tuple(binding_values)
    for role, binding, expected_digest, expected_type in bindings:
        if binding.artifact_digest != expected_digest:
            return f"resolution_{role}_digest_mismatch"
        if binding.artifact_type != expected_type:
            return f"resolution_{role}_type_mismatch"
        if binding.size <= 0:
            return f"resolution_{role}_empty"
    output_digests = {
        receipt.execution_output_digest,
        receipt.effect_output_digest,
        receipt.measured_environment_output_digest,
        receipt.termination_output_digest,
    }
    resolved_digests = {
        *(value.artifact_digest for value in resolution.target_artifacts),
        *(binding.artifact_digest for _, binding, _, _ in bindings),
    }
    if output_digests.intersection(resolved_digests):
        return "output_resolution_artifact_collision"
    return None


def _artifact_resolution_cas_reason(
    resolution: VerificationArtifactResolutionV1,
    *,
    target_snapshot: TargetSnapshotV1,
    evidence_store: FileEvidenceStore,
) -> str | None:
    """Re-read the target and every predeclared typed input from current CAS."""

    if target_snapshot.object_id != resolution.target_snapshot_id:
        return "target_snapshot_mismatch"
    target_metadata = tuple(
        (
            value.artifact_digest,
            value.artifact_type,
            value.relative_path,
            value.size,
        )
        for value in resolution.target_artifacts
    )
    expected_target_metadata = tuple(
        (
            value.artifact_digest,
            TARGET_ARTIFACT_TYPE_V1,
            value.relative_path,
            value.size,
        )
        for value in target_snapshot.files
    )
    if target_metadata != expected_target_metadata:
        return "resolution_target_artifacts_mismatch"

    bindings = (
        ("poc", resolution.poc_artifact),
        *tuple((f"evidence_{index}", binding) for index, binding in enumerate(resolution.evidence_artifacts)),
        ("environment", resolution.environment_artifact),
        ("effect_oracle", resolution.effect_oracle_artifact),
    )

    try:
        validate_etzio_fixture_snapshot(target_snapshot, evidence_store)
    except EvidenceError:
        return "resolved_target_unavailable"

    for role, binding in bindings:
        try:
            data = evidence_store.get_typed(
                binding.artifact_digest,
                expected_type=binding.artifact_type,
                maximum=binding.size,
            )
        except EvidenceError:
            return f"resolved_{role}_artifact_unavailable"
        if len(data) != binding.size:
            return f"resolved_{role}_artifact_size_mismatch"
    return None


def _resolve_verifier_output_artifacts(
    authenticated_receipt: AuthenticatedVerifierReceiptV1,
    *,
    evidence_store: FileEvidenceStore,
    maximum_output_bytes: int,
) -> VerificationOutputArtifactsV1:
    receipt = authenticated_receipt.receipt
    output_specs = tuple(
        (
            role,
            getattr(receipt, digest_field),
            getattr(receipt, size_field),
        )
        for role, digest_field, size_field in _OUTPUT_FIELDS_BY_ROLE_V1
    )
    signed_output_bytes = sum(size for _, _, size in output_specs)
    if signed_output_bytes > min(
        maximum_output_bytes,
        MAX_TYPED_VERIFICATION_OUTPUT_BYTES_V1,
    ):
        raise VerificationError(
            "verification_output_byte_ceiling_exceeded",
            "signed verification outputs exceed the available byte allowance",
        )
    resolved: dict[str, VerificationArtifactBindingV1] = {}
    for role, digest, signed_size in output_specs:
        artifact_type = VERIFICATION_OUTPUT_ARTIFACT_TYPE_BY_ROLE_V1[role]
        try:
            data = evidence_store.get_typed(
                digest,
                expected_type=artifact_type,
                maximum=signed_size,
            )
        except EvidenceError as exc:
            if str(exc) in {
                "evidence artifact exceeds configured limit",
                "typed evidence must be nonempty",
            }:
                raise VerificationError(
                    f"resolved_{role}_artifact_size_mismatch",
                    f"{role} bytes differ from the signed size",
                ) from exc
            raise VerificationError(
                f"resolved_{role}_artifact_unavailable",
                f"{role} cannot be resolved under its code-owned type",
            ) from exc
        if len(data) != signed_size:
            raise VerificationError(
                f"resolved_{role}_artifact_size_mismatch",
                f"{role} bytes differ from the signed size",
            )
        binding = VerificationArtifactBindingV1(
            artifact_digest=digest,
            artifact_type=artifact_type,
            size=signed_size,
        )
        resolved[role] = binding
    return VerificationOutputArtifactsV1(
        execution_output_artifact=resolved["execution_output"],
        effect_output_artifact=resolved["effect_output"],
        measured_environment_output_artifact=resolved["measured_environment_output"],
        termination_output_artifact=resolved["termination_output"],
    )


def revalidate_verifier_receipt_artifacts(
    authenticated_receipt: AuthenticatedVerifierReceiptV1,
    *,
    target_snapshot: TargetSnapshotV1,
    evidence_store: FileEvidenceStore,
    maximum_output_bytes: int = MAX_TYPED_VERIFICATION_OUTPUT_BYTES_V1,
) -> VerificationOutputArtifactsV1:
    """Revalidate current input CAS and derive exact output role/type/size bindings."""

    if not isinstance(
        authenticated_receipt,
        AuthenticatedVerifierReceiptV1,
    ):
        raise VerificationError(
            "invalid_authenticated_receipt",
            "artifact validation requires an authenticated receipt",
        )
    if not isinstance(target_snapshot, TargetSnapshotV1):
        raise VerificationError(
            "invalid_target_snapshot",
            "target_snapshot must be a TargetSnapshotV1",
        )
    if not isinstance(evidence_store, FileEvidenceStore):
        raise VerificationError(
            "invalid_evidence_store",
            "evidence_store must be a FileEvidenceStore",
        )
    if type(maximum_output_bytes) is not int or maximum_output_bytes < 0 or maximum_output_bytes > MAX_EPOCH_SECOND:
        raise VerificationError(
            "invalid_output_byte_ceiling",
            "maximum_output_bytes must be a nonnegative int64",
        )
    if sum(
        getattr(authenticated_receipt.receipt, size_field)
        for _, _, size_field in _OUTPUT_FIELDS_BY_ROLE_V1
    ) > min(
        maximum_output_bytes,
        MAX_TYPED_VERIFICATION_OUTPUT_BYTES_V1,
    ):
        raise VerificationError(
            "verification_output_byte_ceiling_exceeded",
            "signed verification outputs exceed the available byte allowance",
        )
    resolution_reason = _artifact_resolution_cas_reason(
        authenticated_receipt.artifact_resolution,
        target_snapshot=target_snapshot,
        evidence_store=evidence_store,
    )
    if resolution_reason is not None:
        raise VerificationError(
            resolution_reason,
            "current CAS differs from the authenticated artifact resolution",
        )
    return _resolve_verifier_output_artifacts(
        authenticated_receipt,
        evidence_store=evidence_store,
        maximum_output_bytes=maximum_output_bytes,
    )


def validate_verifier_receipt(
    raw_signed_receipt: SignedVerifierReceiptV1 | Mapping[str, object] | bytes | str,
    trust_store: VerifierTrustStore,
    *,
    lease: VerificationLeaseV1,
    decision_time: int,
    expected_verdict: str | None,
    consumed_lease_ids: Set[str],
    artifact_resolution: VerificationArtifactResolutionV1,
    target_snapshot: TargetSnapshotV1,
    evidence_store: FileEvidenceStore,
    maximum_output_bytes: int = MAX_TYPED_VERIFICATION_OUTPUT_BYTES_V1,
) -> VerificationProposal:
    """Return a proposal after pure authentication and current-CAS revalidation."""

    try:
        consumed = _validated_digest_set(
            consumed_lease_ids,
            "invalid_consumed_lease_ids",
            MAX_CONSUMED_LEASE_IDS,
        )
        authenticated = authenticate_verifier_receipt(
            raw_signed_receipt,
            trust_store,
            lease=lease,
            artifact_resolution=artifact_resolution,
            decision_time=decision_time,
            expected_verdict=expected_verdict,
        )
        if lease.lease_id in consumed:
            raise VerificationError(
                "lease_already_consumed",
                "verification lease is already consumed",
            )
        output_artifacts = revalidate_verifier_receipt_artifacts(
            authenticated,
            target_snapshot=target_snapshot,
            evidence_store=evidence_store,
            maximum_output_bytes=maximum_output_bytes,
        )
    except VerificationError as exc:
        return _refuse(exc.reason_code)

    receipt = authenticated.receipt
    return VerificationProposal(
        eligible=True,
        lease_id=lease.lease_id,
        receipt_id=receipt.receipt_id,
        verdict=receipt.verdict,
        reason_code="proposal_valid",
        issuance_trust_snapshot_id=lease.issuance_trust_snapshot_id,
        decision_trust_snapshot_id=authenticated.decision_trust_snapshot_id,
        artifact_resolution_id=artifact_resolution.resolution_id,
        output_artifacts=output_artifacts,
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
        "issuance_trust_snapshot_id",
    ):
        _validate_digest(values[field], field)
    _validate_identity(values["candidate_producer_id"], "candidate_producer_id")
    _validate_identity(values["verifier_id"], "verifier_id")
    _validate_key_id(values["verifier_key_id"], "verifier_key_id")
    _validate_evidence_tuple(values["evidence_artifact_digests"])
    artifact_roles = (
        values["poc_artifact_digest"],
        *values["evidence_artifact_digests"],
        values["environment_digest"],
        values["effect_oracle_id"],
    )
    if len(set(artifact_roles)) != len(artifact_roles):
        raise VerificationError(
            "artifact_role_collision",
            "verification artifact roles must use distinct content identities",
        )
    _validate_times(values["issued_at"], values["expires_at"])


def _validate_receipt_values(values: Mapping[str, object]) -> None:
    if set(values) != _RECEIPT_BODY_FIELDS:
        raise VerificationError("malformed_receipt", "receipt has missing or unknown fields")
    for field in (
        "artifact_resolution_id",
        "lease_id",
        "mission_id",
        "authority_id",
        "target_snapshot_id",
        "candidate_id",
        "poc_artifact_digest",
        "environment_digest",
        "effect_oracle_id",
        "execution_output_digest",
        "effect_output_digest",
        "measured_environment_output_digest",
        "termination_output_digest",
    ):
        _validate_digest(values[field], field)
    _validate_identity(values["candidate_producer_id"], "candidate_producer_id")
    _validate_identity(values["verifier_id"], "verifier_id")
    _validate_key_id(values["verifier_key_id"], "verifier_key_id")
    _validate_evidence_tuple(values["evidence_artifact_digests"])
    output_digests = (
        values["execution_output_digest"],
        values["effect_output_digest"],
        values["measured_environment_output_digest"],
        values["termination_output_digest"],
    )
    if len(set(output_digests)) != len(output_digests):
        raise VerificationError(
            "output_artifact_role_collision",
            "verification output roles must use distinct content identities",
        )
    input_digests = (
        values["poc_artifact_digest"],
        *values["evidence_artifact_digests"],
        values["environment_digest"],
        values["effect_oracle_id"],
    )
    if set(output_digests).intersection(input_digests):
        raise VerificationError(
            "output_input_artifact_collision",
            "verification outputs must be distinct from predeclared inputs",
        )
    output_sizes = tuple(
        values[size_field]
        for _, _, size_field in _OUTPUT_FIELDS_BY_ROLE_V1
    )
    for (_, _, size_field), size in zip(
        _OUTPUT_FIELDS_BY_ROLE_V1,
        output_sizes,
        strict=True,
    ):
        if (
            type(size) is not int
            or size <= 0
            or size > MAX_TYPED_VERIFICATION_OUTPUT_BYTES_V1
        ):
            raise VerificationError(
                f"invalid_{size_field}",
                f"{size_field} must be an integer from 1 through 64 MiB",
            )
    if sum(output_sizes) > MAX_TYPED_VERIFICATION_OUTPUT_BYTES_V1:
        raise VerificationError(
            "verification_output_byte_ceiling_exceeded",
            "signed verification output sizes exceed the fixed aggregate byte ceiling",
        )
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
    if (
        type(body) is not dict
        or len(body) != len(VERIFIER_TRUST_SNAPSHOT_FIELDS_V1)
        or set(body) != VERIFIER_TRUST_SNAPSHOT_FIELDS_V1
    ):
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
            or len(entry) != len(VERIFIER_TRUST_KEY_FIELDS_V1)
            or set(entry) != VERIFIER_TRUST_KEY_FIELDS_V1
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


def _refuse(reason_code: str) -> VerificationProposal:
    return VerificationProposal(
        eligible=False,
        lease_id=None,
        receipt_id=None,
        verdict=None,
        reason_code=reason_code,
    )
