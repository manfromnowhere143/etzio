"""Canonical historical records of modeled verification-artifact resolution.

The objects in this module describe bytes that a kernel command resolved from Etzio's
content-addressed evidence store under exact, role-derived types.  They do not accept a
verifier receipt, consume a lease, execute an artifact, establish an observed effect, or
mint a finding.  A retained resolution records a historical check; current CAS
availability must be revalidated by the kernel command.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Final

from .evidence import VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1
from .protocol import EnvelopeV1, ProtocolError, thaw_json

RESOLUTION_OBJECT_KIND: Final = "verification_artifact_resolution"
RESOLUTION_PROFILE_V1: Final = "modeled_fixture_typed_cas_v1"
TARGET_ARTIFACT_TYPE_V1: Final = "repository_fixture_source"
MAX_RESOLUTION_SINGLE_ARTIFACT_BYTES_V1: Final = 64 * 1024 * 1024
MAX_TYPED_VERIFICATION_INPUT_BYTES_V1: Final = 64 * 1024 * 1024
MAX_RESOLUTION_ARTIFACT_BYTES_V1: Final = 128 * 1024 * 1024
MAX_RESOLUTION_ARTIFACTS_PER_ROLE_V1: Final = 256
MAX_RESOLUTION_EPOCH_SECOND_V1: Final = (2**63) - 1

VERIFICATION_ARTIFACT_BINDING_FIELDS_V1: Final = frozenset({"artifact_digest", "artifact_type", "size"})
TARGET_ARTIFACT_BINDING_FIELDS_V1: Final = frozenset({"artifact_digest", "artifact_type", "relative_path", "size"})
RESOLUTION_BODY_FIELDS_V1: Final = frozenset(
    {
        "authority_id",
        "candidate_id",
        "effect_oracle_artifact",
        "environment_artifact",
        "evidence_artifacts",
        "mission_id",
        "poc_artifact",
        "resolution_profile",
        "resolved_at",
        "target_artifacts",
        "target_snapshot_id",
        "verification_lease_id",
    }
)

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)


class VerificationArtifactError(ProtocolError):
    """A typed verification-artifact resolution violates protocol v1."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


def _reject(reason_code: str, message: str) -> None:
    raise VerificationArtifactError(reason_code, message)


def _require_digest(name: str, value: object) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        _reject(f"invalid_{name}", f"{name} must be a full sha256 content ID")
    return value


def _require_size(value: object) -> int:
    if type(value) is not int or value < 0 or value > MAX_RESOLUTION_SINGLE_ARTIFACT_BYTES_V1:
        _reject(
            "invalid_artifact_size",
            "artifact size must be a bounded nonnegative integer",
        )
    return value


def _require_relative_path(value: object) -> str:
    if type(value) is not str or not value or value != value.strip():
        _reject(
            "invalid_relative_path",
            "relative_path must be nonempty text without edge whitespace",
        )
    path = PurePosixPath(value)
    if (
        value == "."
        or path.is_absolute()
        or path.as_posix() != value
        or "." in path.parts
        or ".." in path.parts
        or "\\" in value
        or "\x00" in value
    ):
        _reject(
            "invalid_relative_path",
            "relative_path must be normalized and relative",
        )
    return value


@dataclass(frozen=True, slots=True)
class VerificationArtifactBindingV1:
    """One exact typed verification input resolved from the evidence CAS."""

    artifact_digest: str
    artifact_type: str
    size: int

    def __post_init__(self) -> None:
        _require_digest("artifact_digest", self.artifact_digest)
        if (
            type(self.artifact_type) is not str
            or self.artifact_type not in VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1.values()
        ):
            _reject(
                "invalid_artifact_type",
                "verification artifact type is not in the closed protocol-v1 registry",
            )
        _require_size(self.size)
        if self.size == 0:
            _reject(
                "invalid_artifact_size",
                "typed verification artifact size must be positive",
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "artifact_digest": self.artifact_digest,
            "artifact_type": self.artifact_type,
            "size": self.size,
        }

    @classmethod
    def from_dict(cls, value: object) -> VerificationArtifactBindingV1:
        if type(value) is not dict or set(value) != VERIFICATION_ARTIFACT_BINDING_FIELDS_V1:
            _reject(
                "malformed_artifact_binding",
                "verification artifact binding has missing or unknown fields",
            )
        try:
            return cls(
                artifact_digest=value["artifact_digest"],
                artifact_type=value["artifact_type"],
                size=value["size"],
            )
        except TypeError as exc:
            raise VerificationArtifactError(
                "malformed_artifact_binding",
                "verification artifact binding has invalid field types",
            ) from exc


@dataclass(frozen=True, slots=True)
class TargetArtifactBindingV1:
    """One raw repository-fixture source resolved from the generic evidence CAS."""

    artifact_digest: str
    artifact_type: str
    relative_path: str
    size: int

    def __post_init__(self) -> None:
        _require_digest("artifact_digest", self.artifact_digest)
        if self.artifact_type != TARGET_ARTIFACT_TYPE_V1:
            _reject(
                "invalid_target_artifact_type",
                "target artifacts must use the repository fixture source type",
            )
        _require_relative_path(self.relative_path)
        _require_size(self.size)

    def to_dict(self) -> dict[str, object]:
        return {
            "artifact_digest": self.artifact_digest,
            "artifact_type": self.artifact_type,
            "relative_path": self.relative_path,
            "size": self.size,
        }

    @classmethod
    def from_dict(cls, value: object) -> TargetArtifactBindingV1:
        if type(value) is not dict or set(value) != TARGET_ARTIFACT_BINDING_FIELDS_V1:
            _reject(
                "malformed_target_artifact_binding",
                "target artifact binding has missing or unknown fields",
            )
        try:
            return cls(
                artifact_digest=value["artifact_digest"],
                artifact_type=value["artifact_type"],
                relative_path=value["relative_path"],
                size=value["size"],
            )
        except TypeError as exc:
            raise VerificationArtifactError(
                "malformed_target_artifact_binding",
                "target artifact binding has invalid field types",
            ) from exc


@dataclass(frozen=True, slots=True)
class VerificationArtifactResolutionV1:
    """One immutable, content-addressed historical resolution for one lease."""

    resolution_id: str
    authority_id: str
    candidate_id: str
    effect_oracle_artifact: VerificationArtifactBindingV1
    environment_artifact: VerificationArtifactBindingV1
    evidence_artifacts: tuple[VerificationArtifactBindingV1, ...]
    mission_id: str
    poc_artifact: VerificationArtifactBindingV1
    resolution_profile: str
    resolved_at: int
    target_artifacts: tuple[TargetArtifactBindingV1, ...]
    target_snapshot_id: str
    verification_lease_id: str

    def __post_init__(self) -> None:
        _require_digest("resolution_id", self.resolution_id)
        self._validate_values()
        try:
            canonical_id = EnvelopeV1.create(
                RESOLUTION_OBJECT_KIND,
                self._body(),
            ).object_id
        except ProtocolError as exc:
            raise VerificationArtifactError(
                "invalid_resolution",
                "artifact resolution cannot be represented by protocol v1",
            ) from exc
        if self.resolution_id != canonical_id:
            _reject(
                "object_id_mismatch",
                "resolution_id does not match canonical resolution semantics",
            )

    @classmethod
    def issue(
        cls,
        *,
        authority_id: str,
        candidate_id: str,
        effect_oracle_artifact: VerificationArtifactBindingV1,
        environment_artifact: VerificationArtifactBindingV1,
        evidence_artifacts: tuple[VerificationArtifactBindingV1, ...],
        mission_id: str,
        poc_artifact: VerificationArtifactBindingV1,
        resolved_at: int,
        target_artifacts: tuple[TargetArtifactBindingV1, ...],
        target_snapshot_id: str,
        verification_lease_id: str,
    ) -> VerificationArtifactResolutionV1:
        values = {
            "authority_id": authority_id,
            "candidate_id": candidate_id,
            "effect_oracle_artifact": effect_oracle_artifact,
            "environment_artifact": environment_artifact,
            "evidence_artifacts": evidence_artifacts,
            "mission_id": mission_id,
            "poc_artifact": poc_artifact,
            "resolution_profile": RESOLUTION_PROFILE_V1,
            "resolved_at": resolved_at,
            "target_artifacts": target_artifacts,
            "target_snapshot_id": target_snapshot_id,
            "verification_lease_id": verification_lease_id,
        }
        try:
            body = {
                "authority_id": authority_id,
                "candidate_id": candidate_id,
                "effect_oracle_artifact": effect_oracle_artifact.to_dict(),
                "environment_artifact": environment_artifact.to_dict(),
                "evidence_artifacts": [value.to_dict() for value in evidence_artifacts],
                "mission_id": mission_id,
                "poc_artifact": poc_artifact.to_dict(),
                "resolution_profile": RESOLUTION_PROFILE_V1,
                "resolved_at": resolved_at,
                "target_artifacts": [value.to_dict() for value in target_artifacts],
                "target_snapshot_id": target_snapshot_id,
                "verification_lease_id": verification_lease_id,
            }
            envelope = EnvelopeV1.create(RESOLUTION_OBJECT_KIND, body)
            return cls(resolution_id=envelope.object_id, **values)
        except VerificationArtifactError:
            raise
        except (AttributeError, ProtocolError, TypeError) as exc:
            raise VerificationArtifactError(
                "invalid_resolution",
                "artifact resolution cannot be represented by protocol v1",
            ) from exc

    @classmethod
    def from_envelope(
        cls,
        envelope: EnvelopeV1,
    ) -> VerificationArtifactResolutionV1:
        if envelope.object_kind != RESOLUTION_OBJECT_KIND:
            _reject(
                "wrong_object_kind",
                "envelope is not a verification artifact resolution",
            )
        if envelope.attestations:
            _reject(
                "unexpected_attestations",
                "artifact resolution attestations must be empty",
            )
        body = thaw_json(envelope.body)
        if type(body) is not dict or set(body) != RESOLUTION_BODY_FIELDS_V1:
            _reject(
                "malformed_resolution",
                "artifact resolution body has missing or unknown fields",
            )
        if type(body["evidence_artifacts"]) is not list or type(body["target_artifacts"]) is not list:
            _reject(
                "malformed_resolution",
                "artifact resolution collections must be arrays",
            )
        try:
            return cls(
                resolution_id=envelope.object_id,
                authority_id=body["authority_id"],
                candidate_id=body["candidate_id"],
                effect_oracle_artifact=VerificationArtifactBindingV1.from_dict(body["effect_oracle_artifact"]),
                environment_artifact=VerificationArtifactBindingV1.from_dict(body["environment_artifact"]),
                evidence_artifacts=tuple(
                    VerificationArtifactBindingV1.from_dict(value) for value in body["evidence_artifacts"]
                ),
                mission_id=body["mission_id"],
                poc_artifact=VerificationArtifactBindingV1.from_dict(body["poc_artifact"]),
                resolution_profile=body["resolution_profile"],
                resolved_at=body["resolved_at"],
                target_artifacts=tuple(TargetArtifactBindingV1.from_dict(value) for value in body["target_artifacts"]),
                target_snapshot_id=body["target_snapshot_id"],
                verification_lease_id=body["verification_lease_id"],
            )
        except TypeError as exc:
            raise VerificationArtifactError(
                "malformed_resolution",
                "artifact resolution body has invalid field types",
            ) from exc

    def to_envelope(self) -> EnvelopeV1:
        try:
            envelope = EnvelopeV1.create(
                RESOLUTION_OBJECT_KIND,
                self._body(),
            )
        except ProtocolError as exc:
            raise VerificationArtifactError(
                "invalid_resolution",
                "artifact resolution cannot be represented by protocol v1",
            ) from exc
        if envelope.object_id != self.resolution_id:
            _reject(
                "object_id_mismatch",
                "resolution_id does not match canonical resolution semantics",
            )
        return envelope

    @property
    def total_bytes(self) -> int:
        return sum(
            binding.size
            for binding in (
                *self.target_artifacts,
                self.poc_artifact,
                self.environment_artifact,
                self.effect_oracle_artifact,
                *self.evidence_artifacts,
            )
        )

    @property
    def typed_input_bytes(self) -> int:
        return sum(
            binding.size
            for binding in (
                self.poc_artifact,
                self.environment_artifact,
                self.effect_oracle_artifact,
                *self.evidence_artifacts,
            )
        )

    def _validate_values(self) -> None:
        for field in (
            "authority_id",
            "candidate_id",
            "mission_id",
            "target_snapshot_id",
            "verification_lease_id",
        ):
            _require_digest(field, getattr(self, field))
        if self.resolution_profile != RESOLUTION_PROFILE_V1:
            _reject(
                "unsupported_resolution_profile",
                "artifact resolution profile is unsupported",
            )
        if (
            type(self.resolved_at) is not int
            or self.resolved_at < 0
            or self.resolved_at > MAX_RESOLUTION_EPOCH_SECOND_V1
        ):
            _reject(
                "invalid_resolved_at",
                "resolved_at must be a nonnegative int64 epoch second",
            )
        if (
            type(self.target_artifacts) is not tuple
            or not self.target_artifacts
            or len(self.target_artifacts) > MAX_RESOLUTION_ARTIFACTS_PER_ROLE_V1
            or any(not isinstance(value, TargetArtifactBindingV1) for value in self.target_artifacts)
        ):
            _reject(
                "invalid_target_artifacts",
                "target_artifacts must be a nonempty tuple of typed bindings",
            )
        target_paths = tuple(value.relative_path for value in self.target_artifacts)
        if target_paths != tuple(sorted(target_paths)) or len(set(target_paths)) != len(target_paths):
            _reject(
                "noncanonical_target_artifacts",
                "target artifacts must use unique canonical path order",
            )
        if (
            type(self.evidence_artifacts) is not tuple
            or not self.evidence_artifacts
            or len(self.evidence_artifacts) > MAX_RESOLUTION_ARTIFACTS_PER_ROLE_V1
            or any(not isinstance(value, VerificationArtifactBindingV1) for value in self.evidence_artifacts)
        ):
            _reject(
                "invalid_evidence_artifacts",
                "evidence_artifacts must be a nonempty tuple of typed bindings",
            )
        evidence_digests = tuple(value.artifact_digest for value in self.evidence_artifacts)
        if evidence_digests != tuple(sorted(evidence_digests)) or len(set(evidence_digests)) != len(evidence_digests):
            _reject(
                "noncanonical_evidence_artifacts",
                "evidence artifacts must use unique canonical digest order",
            )
        if any(
            not isinstance(value, VerificationArtifactBindingV1)
            for value in (
                self.poc_artifact,
                self.environment_artifact,
                self.effect_oracle_artifact,
            )
        ):
            _reject(
                "invalid_artifact_binding",
                "singleton verification artifacts must use typed bindings",
            )
        expected_types = (
            (
                self.poc_artifact.artifact_type,
                VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["poc"],
            ),
            (
                self.environment_artifact.artifact_type,
                VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["environment"],
            ),
            (
                self.effect_oracle_artifact.artifact_type,
                VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["effect_oracle"],
            ),
        )
        if any(actual != expected for actual, expected in expected_types):
            _reject(
                "artifact_role_mismatch",
                "singleton artifact type does not match its fixed role",
            )
        if any(
            value.artifact_type != VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["evidence"]
            for value in self.evidence_artifacts
        ):
            _reject(
                "artifact_role_mismatch",
                "evidence artifact type does not match its fixed role",
            )
        singleton_and_evidence = (
            self.poc_artifact.artifact_digest,
            self.environment_artifact.artifact_digest,
            self.effect_oracle_artifact.artifact_digest,
            *evidence_digests,
        )
        if len(set(singleton_and_evidence)) != len(singleton_and_evidence):
            _reject(
                "artifact_role_collision",
                "verification artifact roles must use distinct digests",
            )
        if set(value.artifact_digest for value in self.target_artifacts).intersection(singleton_and_evidence):
            _reject(
                "artifact_role_collision",
                "target and verification artifact roles must use distinct digests",
            )
        if self.typed_input_bytes > MAX_TYPED_VERIFICATION_INPUT_BYTES_V1:
            _reject(
                "resolution_byte_ceiling_exceeded",
                "typed verification inputs exceed the fixed protocol-v1 ceiling",
            )
        if self.total_bytes > MAX_RESOLUTION_ARTIFACT_BYTES_V1:
            _reject(
                "resolution_byte_ceiling_exceeded",
                "resolved artifact bytes exceed the fixed protocol-v1 ceiling",
            )

    def _body(self) -> dict[str, object]:
        return {
            "authority_id": self.authority_id,
            "candidate_id": self.candidate_id,
            "effect_oracle_artifact": self.effect_oracle_artifact.to_dict(),
            "environment_artifact": self.environment_artifact.to_dict(),
            "evidence_artifacts": [value.to_dict() for value in self.evidence_artifacts],
            "mission_id": self.mission_id,
            "poc_artifact": self.poc_artifact.to_dict(),
            "resolution_profile": self.resolution_profile,
            "resolved_at": self.resolved_at,
            "target_artifacts": [value.to_dict() for value in self.target_artifacts],
            "target_snapshot_id": self.target_snapshot_id,
            "verification_lease_id": self.verification_lease_id,
        }
