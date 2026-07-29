"""Code-owned manifests for evidence retained with canonical mission events.

The filesystem evidence store is a bounded staging and cache surface.  It is not the
canonical retention boundary.  This module derives every vault role, identity domain,
type, digest, size, and ordering position from an already verified protocol event.
Callers never supply a vault manifest.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Final

from ..authority import AuthorityGrantV1
from ..evidence import (
    MAX_AUTHORITY_EVIDENCE_BYTES_V1,
    VERIFICATION_ARTIFACT_TYPES_V1,
    FileEvidenceStore,
    TargetSnapshotV1,
)
from ..protocol import EnvelopeV1, ProtocolError, canonical_dumps, thaw_json
from ..verification_artifacts import (
    MAX_RESOLUTION_ARTIFACTS_PER_ROLE_V1,
    MAX_RESOLUTION_SINGLE_ARTIFACT_BYTES_V1,
    VerificationArtifactBindingV1,
    VerificationArtifactResolutionV1,
)
from .events_v1 import EventV1

GENERIC_IDENTITY_SCHEME_V1: Final = "generic_v1"
TYPED_IDENTITY_SCHEME_V1: Final = "typed_v1"
GENERIC_TYPE_TAG_V1: Final = ""

AUTHORITY_EVIDENCE_ROLE_V1: Final = "authority_evidence"
TARGET_SOURCE_ROLE_V1: Final = "target_source"
VERIFICATION_POC_INPUT_ROLE_V1: Final = "verification_poc_input"
VERIFICATION_SUPPORTING_EVIDENCE_INPUT_ROLE_V1: Final = "verification_supporting_evidence_input"
VERIFICATION_ENVIRONMENT_SPEC_ROLE_V1: Final = "verification_environment_spec"
VERIFICATION_EFFECT_ORACLE_SPEC_ROLE_V1: Final = "verification_effect_oracle_spec"
VERIFICATION_EXECUTION_OUTPUT_ROLE_V1: Final = "verification_execution_output"
VERIFICATION_EFFECT_OUTPUT_ROLE_V1: Final = "verification_effect_output"
VERIFICATION_MEASURED_ENVIRONMENT_OUTPUT_ROLE_V1: Final = "verification_measured_environment_output"
VERIFICATION_TERMINATION_OUTPUT_ROLE_V1: Final = "verification_termination_output"

PROTECTED_EVIDENCE_EVENT_KINDS_V1: Final = frozenset(
    {
        "authority_admitted",
        "mission_opened",
        "verification_artifacts_resolved",
        "verifier_receipt_admitted",
    }
)
NON_RECEIPT_EVIDENCE_EVENT_KINDS_V1: Final = PROTECTED_EVIDENCE_EVENT_KINDS_V1 - {"verifier_receipt_admitted"}
VAULT_ROLES_V1: Final = frozenset(
    {
        AUTHORITY_EVIDENCE_ROLE_V1,
        TARGET_SOURCE_ROLE_V1,
        VERIFICATION_POC_INPUT_ROLE_V1,
        VERIFICATION_SUPPORTING_EVIDENCE_INPUT_ROLE_V1,
        VERIFICATION_ENVIRONMENT_SPEC_ROLE_V1,
        VERIFICATION_EFFECT_ORACLE_SPEC_ROLE_V1,
        VERIFICATION_EXECUTION_OUTPUT_ROLE_V1,
        VERIFICATION_EFFECT_OUTPUT_ROLE_V1,
        VERIFICATION_MEASURED_ENVIRONMENT_OUTPUT_ROLE_V1,
        VERIFICATION_TERMINATION_OUTPUT_ROLE_V1,
    }
)
SINGLETON_VAULT_ROLES_V1: Final = VAULT_ROLES_V1 - {
    TARGET_SOURCE_ROLE_V1,
    VERIFICATION_SUPPORTING_EVIDENCE_INPUT_ROLE_V1,
}
VAULT_IDENTITY_BY_ROLE_V1: Final = MappingProxyType(
    {
        AUTHORITY_EVIDENCE_ROLE_V1: (
            GENERIC_IDENTITY_SCHEME_V1,
            GENERIC_TYPE_TAG_V1,
        ),
        TARGET_SOURCE_ROLE_V1: (
            GENERIC_IDENTITY_SCHEME_V1,
            GENERIC_TYPE_TAG_V1,
        ),
        VERIFICATION_POC_INPUT_ROLE_V1: (
            TYPED_IDENTITY_SCHEME_V1,
            "modeled_poc_input",
        ),
        VERIFICATION_SUPPORTING_EVIDENCE_INPUT_ROLE_V1: (
            TYPED_IDENTITY_SCHEME_V1,
            "modeled_supporting_evidence_input",
        ),
        VERIFICATION_ENVIRONMENT_SPEC_ROLE_V1: (
            TYPED_IDENTITY_SCHEME_V1,
            "modeled_environment_spec",
        ),
        VERIFICATION_EFFECT_ORACLE_SPEC_ROLE_V1: (
            TYPED_IDENTITY_SCHEME_V1,
            "modeled_effect_oracle_spec",
        ),
        VERIFICATION_EXECUTION_OUTPUT_ROLE_V1: (
            TYPED_IDENTITY_SCHEME_V1,
            "modeled_execution_output",
        ),
        VERIFICATION_EFFECT_OUTPUT_ROLE_V1: (
            TYPED_IDENTITY_SCHEME_V1,
            "modeled_effect_output",
        ),
        VERIFICATION_MEASURED_ENVIRONMENT_OUTPUT_ROLE_V1: (
            TYPED_IDENTITY_SCHEME_V1,
            "modeled_measured_environment_output",
        ),
        VERIFICATION_TERMINATION_OUTPUT_ROLE_V1: (
            TYPED_IDENTITY_SCHEME_V1,
            "modeled_termination_output",
        ),
    }
)

MAX_VAULT_ARTIFACT_BYTES_V1: Final = MAX_RESOLUTION_SINGLE_ARTIFACT_BYTES_V1
MAX_EVENT_ARTIFACT_ROLES_V1: Final = (2 * MAX_RESOLUTION_ARTIFACTS_PER_ROLE_V1) + 3
DEFAULT_MAX_VAULT_BYTES_V1: Final = 1 << 30
MAX_VAULT_BATCH_REQUESTS_V1: Final = MAX_EVENT_ARTIFACT_ROLES_V1
MAX_VAULT_REQUEST_MAXIMUM_V1: Final = DEFAULT_MAX_VAULT_BYTES_V1

_GENERIC_DIGEST_DOMAIN_V1: Final = b"etzio:evidence:v1\x00"
_TYPED_DIGEST_DOMAIN_V1: Final = b"etzio:evidence:typed:v1\x00"
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)


class EvidenceVaultError(ProtocolError):
    """A vault manifest, retained identity, or staged artifact is invalid."""


class EvidenceVaultArtifactMissing(EvidenceVaultError):
    """A requested identity is not retained in the transactional vault."""


@dataclass(frozen=True, slots=True)
class VaultEventArtifactSelectorV1:
    """One exact event-owned artifact selector for a bounded vault batch."""

    event_digest: str
    role: str
    ordinal: int = 0

    def __post_init__(self) -> None:
        if type(self.event_digest) is not str or _DIGEST_RE.fullmatch(self.event_digest) is None:
            raise EvidenceVaultError("event artifact selector requires a full lowercase sha256 event ID")
        if type(self.role) is not str or self.role not in VAULT_ROLES_V1:
            raise EvidenceVaultError("event artifact selector role is not in the closed registry")
        if (
            type(self.ordinal) is not int
            or self.ordinal < 0
            or self.ordinal >= MAX_RESOLUTION_ARTIFACTS_PER_ROLE_V1
        ):
            raise EvidenceVaultError("event artifact selector ordinal is outside the fixed bound")
        if self.role in SINGLETON_VAULT_ROLES_V1 and self.ordinal != 0:
            raise EvidenceVaultError("singleton event artifact selectors require ordinal zero")


@dataclass(frozen=True, slots=True)
class VaultArtifactResolutionRequestV1:
    """One exact role-derived identity request for a bounded vault-first batch."""

    role: str
    digest: str
    maximum: int

    def __post_init__(self) -> None:
        if type(self.role) is not str or self.role not in VAULT_ROLES_V1:
            raise EvidenceVaultError("vault resolution request role is not in the closed registry")
        if type(self.digest) is not str or _DIGEST_RE.fullmatch(self.digest) is None:
            raise EvidenceVaultError("vault resolution request requires a full lowercase sha256 ID")
        if (
            type(self.maximum) is not int
            or self.maximum < 0
            or self.maximum > MAX_VAULT_REQUEST_MAXIMUM_V1
        ):
            raise EvidenceVaultError("vault resolution request maximum is outside the fixed bound")

    @property
    def identity_key(self) -> tuple[str, str, str]:
        identity_scheme, type_tag = vault_identity_for_role_v1(self.role)
        return (identity_scheme, type_tag, self.digest)

    @property
    def effective_maximum(self) -> int:
        role_ceiling = (
            MAX_AUTHORITY_EVIDENCE_BYTES_V1
            if self.role == AUTHORITY_EVIDENCE_ROLE_V1
            else MAX_VAULT_ARTIFACT_BYTES_V1
        )
        return min(self.maximum, role_ceiling)


@dataclass(frozen=True, slots=True)
class VaultArtifactRefV1:
    """One canonical event-to-artifact role.

    ``byte_size`` is unknown only for generic authority evidence because the signed grant
    binds its digest but protocol v1 does not carry its size.  In that one case the
    observed bounded byte length becomes the retained manifest size.
    """

    slot: int
    role: str
    ordinal: int
    locator: str
    identity_scheme: str
    type_tag: str
    digest: str
    byte_size: int | None

    def __post_init__(self) -> None:
        if type(self.slot) is not int or self.slot < 0 or self.slot >= MAX_EVENT_ARTIFACT_ROLES_V1:
            raise EvidenceVaultError("vault slot is outside the fixed event bound")
        if self.role not in VAULT_ROLES_V1:
            raise EvidenceVaultError("vault role is not in the closed registry")
        if type(self.ordinal) is not int or self.ordinal < 0 or self.ordinal >= MAX_RESOLUTION_ARTIFACTS_PER_ROLE_V1:
            raise EvidenceVaultError("vault role ordinal is outside the fixed bound")
        if self.role in SINGLETON_VAULT_ROLES_V1 and self.ordinal != 0:
            raise EvidenceVaultError("singleton vault roles require ordinal zero")
        if type(self.locator) is not str:
            raise EvidenceVaultError("vault locator must be text")
        if self.role == TARGET_SOURCE_ROLE_V1:
            if not self.locator:
                raise EvidenceVaultError("target-source vault roles require a path")
        elif self.locator:
            raise EvidenceVaultError("non-target vault roles forbid a locator")
        if _DIGEST_RE.fullmatch(self.digest) is None:
            raise EvidenceVaultError("vault digest must be a full lowercase sha256 ID")
        if self.identity_scheme == GENERIC_IDENTITY_SCHEME_V1:
            if self.type_tag != GENERIC_TYPE_TAG_V1:
                raise EvidenceVaultError("generic vault identities forbid a type tag")
        elif self.identity_scheme == TYPED_IDENTITY_SCHEME_V1:
            if self.type_tag not in VERIFICATION_ARTIFACT_TYPES_V1:
                raise EvidenceVaultError("typed vault identity has an unknown type tag")
        else:
            raise EvidenceVaultError("vault identity scheme is unsupported")
        if self.byte_size is not None:
            if type(self.byte_size) is not int or self.byte_size < 0 or self.byte_size > MAX_VAULT_ARTIFACT_BYTES_V1:
                raise EvidenceVaultError("vault byte size is outside the fixed bound")
            if self.identity_scheme == TYPED_IDENTITY_SCHEME_V1 and self.byte_size == 0:
                raise EvidenceVaultError("typed vault artifacts must be nonempty")
        elif self.role != AUTHORITY_EVIDENCE_ROLE_V1:
            raise EvidenceVaultError("only authority evidence may omit its event-declared size")

    @property
    def identity_key(self) -> tuple[str, str, str]:
        return (self.identity_scheme, self.type_tag, self.digest)

    def with_observed_size(self, byte_size: int) -> VaultArtifactRefV1:
        if self.byte_size is not None and self.byte_size != byte_size:
            raise EvidenceVaultError("artifact bytes differ from the event-declared size")
        limit = (
            MAX_AUTHORITY_EVIDENCE_BYTES_V1 if self.role == AUTHORITY_EVIDENCE_ROLE_V1 else MAX_VAULT_ARTIFACT_BYTES_V1
        )
        if type(byte_size) is not int or byte_size < 0 or byte_size > limit:
            raise EvidenceVaultError("artifact exceeds its vault ingestion ceiling")
        return replace(self, byte_size=byte_size)


def _nested_envelope(event: EventV1, field: str) -> EnvelopeV1:
    payload = thaw_json(event.payload)
    try:
        return EnvelopeV1.from_bytes(canonical_dumps(payload[field]))
    except (KeyError, ProtocolError, TypeError, ValueError) as exc:
        raise EvidenceVaultError(f"{event.kind} omitted a valid {field} envelope") from exc


def _generic_ref(
    *,
    slot: int,
    role: str,
    ordinal: int,
    digest: str,
    byte_size: int | None,
    locator: str = "",
) -> VaultArtifactRefV1:
    return VaultArtifactRefV1(
        slot=slot,
        role=role,
        ordinal=ordinal,
        locator=locator,
        identity_scheme=GENERIC_IDENTITY_SCHEME_V1,
        type_tag=GENERIC_TYPE_TAG_V1,
        digest=digest,
        byte_size=byte_size,
    )


def _typed_ref(
    *,
    slot: int,
    role: str,
    ordinal: int,
    binding: VerificationArtifactBindingV1,
) -> VaultArtifactRefV1:
    return VaultArtifactRefV1(
        slot=slot,
        role=role,
        ordinal=ordinal,
        locator="",
        identity_scheme=TYPED_IDENTITY_SCHEME_V1,
        type_tag=binding.artifact_type,
        digest=binding.artifact_digest,
        byte_size=binding.size,
    )


def derive_event_artifact_manifest_v1(
    event: EventV1,
) -> tuple[VaultArtifactRefV1, ...]:
    """Derive the complete canonical artifact manifest for one event."""

    if not isinstance(event, EventV1):
        raise EvidenceVaultError("vault manifest derivation requires EventV1")
    if event.kind not in PROTECTED_EVIDENCE_EVENT_KINDS_V1:
        return ()

    if event.kind == "authority_admitted":
        try:
            grant = AuthorityGrantV1.from_envelope(_nested_envelope(event, "grant"))
        except ProtocolError as exc:
            raise EvidenceVaultError("authority event contains an invalid grant") from exc
        return (
            _generic_ref(
                slot=0,
                role=AUTHORITY_EVIDENCE_ROLE_V1,
                ordinal=0,
                digest=grant.evidence_digest,
                byte_size=None,
            ),
        )

    if event.kind == "mission_opened":
        try:
            snapshot = TargetSnapshotV1.from_envelope(_nested_envelope(event, "target_snapshot"))
        except ProtocolError as exc:
            raise EvidenceVaultError("mission-opened event contains an invalid target snapshot") from exc
        return tuple(
            _generic_ref(
                slot=slot,
                role=TARGET_SOURCE_ROLE_V1,
                ordinal=slot,
                digest=value.artifact_digest,
                byte_size=value.size,
                locator=value.relative_path,
            )
            for slot, value in enumerate(snapshot.files)
        )

    if event.kind == "verification_artifacts_resolved":
        try:
            resolution = VerificationArtifactResolutionV1.from_envelope(_nested_envelope(event, "resolution"))
        except ProtocolError as exc:
            raise EvidenceVaultError("resolution event contains an invalid artifact resolution") from exc
        manifest: list[VaultArtifactRefV1] = []
        for ordinal, value in enumerate(resolution.target_artifacts):
            manifest.append(
                _generic_ref(
                    slot=len(manifest),
                    role=TARGET_SOURCE_ROLE_V1,
                    ordinal=ordinal,
                    digest=value.artifact_digest,
                    byte_size=value.size,
                    locator=value.relative_path,
                )
            )
        manifest.append(
            _typed_ref(
                slot=len(manifest),
                role=VERIFICATION_POC_INPUT_ROLE_V1,
                ordinal=0,
                binding=resolution.poc_artifact,
            )
        )
        for ordinal, value in enumerate(resolution.evidence_artifacts):
            manifest.append(
                _typed_ref(
                    slot=len(manifest),
                    role=VERIFICATION_SUPPORTING_EVIDENCE_INPUT_ROLE_V1,
                    ordinal=ordinal,
                    binding=value,
                )
            )
        manifest.append(
            _typed_ref(
                slot=len(manifest),
                role=VERIFICATION_ENVIRONMENT_SPEC_ROLE_V1,
                ordinal=0,
                binding=resolution.environment_artifact,
            )
        )
        manifest.append(
            _typed_ref(
                slot=len(manifest),
                role=VERIFICATION_EFFECT_ORACLE_SPEC_ROLE_V1,
                ordinal=0,
                binding=resolution.effect_oracle_artifact,
            )
        )
        return tuple(manifest)

    payload = thaw_json(event.payload)
    output_fields = (
        (
            "execution_output_artifact",
            VERIFICATION_EXECUTION_OUTPUT_ROLE_V1,
        ),
        ("effect_output_artifact", VERIFICATION_EFFECT_OUTPUT_ROLE_V1),
        (
            "measured_environment_output_artifact",
            VERIFICATION_MEASURED_ENVIRONMENT_OUTPUT_ROLE_V1,
        ),
        (
            "termination_output_artifact",
            VERIFICATION_TERMINATION_OUTPUT_ROLE_V1,
        ),
    )
    try:
        return tuple(
            _typed_ref(
                slot=slot,
                role=role,
                ordinal=0,
                binding=VerificationArtifactBindingV1.from_dict(payload[field]),
            )
            for slot, (field, role) in enumerate(output_fields)
        )
    except (KeyError, ProtocolError, TypeError, ValueError) as exc:
        raise EvidenceVaultError("receipt-admission event contains invalid output bindings") from exc


def digest_hasher_v1(identity_scheme: str, type_tag: str) -> hashlib._Hash:
    """Return the exact protocol-v1 hasher for one retained identity domain."""

    if identity_scheme == GENERIC_IDENTITY_SCHEME_V1:
        if type_tag != GENERIC_TYPE_TAG_V1:
            raise EvidenceVaultError("generic digest hashing forbids a type tag")
        hasher = hashlib.sha256()
        hasher.update(_GENERIC_DIGEST_DOMAIN_V1)
        return hasher
    if identity_scheme == TYPED_IDENTITY_SCHEME_V1 and type_tag in VERIFICATION_ARTIFACT_TYPES_V1:
        hasher = hashlib.sha256()
        hasher.update(_TYPED_DIGEST_DOMAIN_V1)
        hasher.update(type_tag.encode("ascii"))
        hasher.update(b"\x00")
        return hasher
    raise EvidenceVaultError("cannot hash an unsupported vault identity")


def digest_bytes_v1(
    data: bytes,
    *,
    identity_scheme: str,
    type_tag: str,
) -> str:
    if type(data) is not bytes:
        raise EvidenceVaultError("vault artifacts must be immutable bytes")
    hasher = digest_hasher_v1(identity_scheme, type_tag)
    hasher.update(data)
    return f"sha256:{hasher.hexdigest()}"


def vault_identity_for_role_v1(role: str) -> tuple[str, str]:
    """Return the code-owned digest domain and type for one closed vault role."""

    if type(role) is not str:
        raise EvidenceVaultError("vault role must be exact text")
    try:
        return VAULT_IDENTITY_BY_ROLE_V1[role]
    except KeyError as exc:
        raise EvidenceVaultError("vault role is not in the closed registry") from exc


class VaultBackedFileEvidenceStore(FileEvidenceStore):
    """A receipt-validation view that prefers immutable vault bytes.

    The current receipt validator deliberately requires ``FileEvidenceStore``.  This exact
    subclass preserves that closed boundary while making already committed target and
    input bytes authoritative.  Missing output identities fall back to the bounded
    filesystem staging store.
    """

    def __init__(self, staging: FileEvidenceStore, lookup: object) -> None:
        if type(staging) is not FileEvidenceStore or not callable(lookup):
            raise EvidenceVaultError("invalid vault-backed evidence view")
        self._staging = staging
        self._lookup = lookup
        self.root = staging.root
        self.max_artifact_bytes = staging.max_artifact_bytes

    def get(
        self,
        digest: str,
        *,
        maximum: int | None = None,
    ) -> bytes:
        try:
            return self._lookup(
                GENERIC_IDENTITY_SCHEME_V1,
                GENERIC_TYPE_TAG_V1,
                digest,
                maximum,
            )
        except EvidenceVaultArtifactMissing:
            return self._staging.get(digest, maximum=maximum)

    def get_typed(
        self,
        digest: str,
        *,
        expected_type: str,
        maximum: int | None = None,
    ) -> bytes:
        try:
            return self._lookup(
                TYPED_IDENTITY_SCHEME_V1,
                expected_type,
                digest,
                maximum,
            )
        except EvidenceVaultArtifactMissing:
            return self._staging.get_typed(
                digest,
                expected_type=expected_type,
                maximum=maximum,
            )
