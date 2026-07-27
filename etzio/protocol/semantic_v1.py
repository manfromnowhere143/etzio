"""One fail-closed dispatcher for Etzio's typed protocol-v1 wire objects."""

from __future__ import annotations

from .v1 import EnvelopeV1, ProtocolError


class SemanticProtocolError(ProtocolError):
    """A canonical envelope has no valid typed protocol-v1 interpretation."""


def parse_semantic_envelope(envelope: EnvelopeV1) -> object:
    """Return the typed interpretation of one canonical protocol-v1 envelope.

    Imports remain local so domain modules can depend on the common envelope without
    creating an import cycle. Signed authority grants are deliberately parsed twice:
    once for their grant body and once for their attestation wire.
    """

    if not isinstance(envelope, EnvelopeV1):
        raise SemanticProtocolError("semantic parsing requires an EnvelopeV1")

    try:
        if envelope.object_kind == "authority_grant":
            from etzio.authority import AuthorityGrantV1, SignedAuthorityGrantV1

            unattested = EnvelopeV1.create("authority_grant", envelope.body)
            grant = AuthorityGrantV1.from_envelope(unattested)
            if not envelope.attestations:
                return grant
            return SignedAuthorityGrantV1.from_bytes(envelope.to_bytes())

        if envelope.object_kind == "authority_admission":
            from etzio.authority import AuthorityAdmissionV1

            return AuthorityAdmissionV1.from_envelope(envelope)

        if envelope.object_kind == "target_snapshot":
            from etzio.evidence import TargetSnapshotV1

            return TargetSnapshotV1.from_envelope(envelope)

        if envelope.object_kind == "analysis_lease":
            from etzio.mission_v1 import AnalysisLeaseV1

            return AnalysisLeaseV1.from_envelope(envelope)

        if envelope.object_kind == "verification_lease":
            from etzio.verification import VerificationLeaseV1

            return VerificationLeaseV1.from_envelope(envelope)

        if envelope.object_kind == "verification_artifact_resolution":
            from etzio.verification_artifacts import VerificationArtifactResolutionV1

            return VerificationArtifactResolutionV1.from_envelope(envelope)

        if envelope.object_kind == "candidate":
            from etzio.mission_v1 import StaticCandidateV1

            return StaticCandidateV1.from_envelope(envelope)

        if envelope.object_kind == "verifier_receipt":
            from etzio.verification import SignedVerifierReceiptV1, VerifierReceiptV1

            if not envelope.attestations:
                return VerifierReceiptV1.from_envelope(envelope)
            return SignedVerifierReceiptV1.from_bytes(envelope.to_bytes())

        if envelope.object_kind == "event":
            from etzio.kernel.events_v1 import EventV1

            return EventV1.from_canonical_bytes(envelope.to_bytes())
    except (ProtocolError, ValueError, TypeError) as exc:
        raise SemanticProtocolError(
            f"invalid {envelope.object_kind} semantic object: {exc}",
            code="invalid_semantic_object",
        ) from exc

    raise SemanticProtocolError(
        f"protocol-v1 object kind {envelope.object_kind!r} has no semantic parser",
        code="unsupported_semantic_object",
    )


def parse_semantic_bytes(data: bytes | str) -> object:
    """Parse canonical wire bytes and return their typed protocol-v1 object."""

    return parse_semantic_envelope(EnvelopeV1.from_bytes(data))
