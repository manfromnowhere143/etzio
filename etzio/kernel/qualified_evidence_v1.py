"""Networkless acceptance of qualified signed evidence for the modeled lifecycle.

ADR-0011 accepts provider evidence only as unsigned code-derived content byte-compared
against `_modeled_provider_content`.  ADR-0012 and ADR-0013 qualify signed fixture
packages but stop before consumption.  This module is the first consumer: it accepts a
checkpoint's claimed anchor statement and evidence from a freshly reauthenticated qualified
anchor bundle, under a distinct `qualified_signed_fixture` mode.

Acceptance reauthenticates from the retained bundles rather than trusting a sealed inputs
object, and requires the claimed evidence to be the exact signed packages.  It changes no
protocol kind, store profile, record identity, or lifecycle command, and it uses no
network, credential, ambient clock, or third-party service.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, TypeVar

from etzio.integrity_v1 import (
    HEAD_ANCHOR_RECEIPT_EVIDENCE_KIND,
    EvidenceReferenceV1,
    RevocationFloorV1,
    RevocationViewV1,
)
from etzio.kernel.head_authority_adapters_v1 import (
    HeadAuthorityTrustProfileV1,
    QualifiedAnchorBundleV1,
    reauthenticate_anchor_bundle_v1,
)
from etzio.kernel.integrity_adapters_v1 import (
    IntegrityAdapterTrustProfileV1,
    QualifiedRevocationBundleV1,
    QualifiedTimeBundleV1,
    map_qualified_integrity_inputs_v1,
)
from etzio.kernel.integrity_transition import ProviderEvidenceBlobV1
from etzio.protocol import content_id

QUALIFIED_EVIDENCE_MODE_MODELED_UNSIGNED_V1: Final = "modeled_unsigned_code_derived"
QUALIFIED_EVIDENCE_MODE_QUALIFIED_SIGNED_V1: Final = "qualified_signed_fixture"
QUALIFIED_EVIDENCE_MODES_V1: Final = frozenset(
    {
        QUALIFIED_EVIDENCE_MODE_MODELED_UNSIGNED_V1,
        QUALIFIED_EVIDENCE_MODE_QUALIFIED_SIGNED_V1,
    }
)

_ACCEPTANCE_SEAL: Final = object()
_SealedResultT = TypeVar("_SealedResultT")


class QualifiedEvidenceError(ValueError):
    """One deterministic refusal to accept qualified signed evidence."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


def _reject(reason_code: str, message: str) -> None:
    raise QualifiedEvidenceError(reason_code, message)


def _construct_sealed_result(
    cls: type[_SealedResultT],
    *,
    values: Mapping[str, object],
) -> _SealedResultT:
    fields = getattr(cls, "__dataclass_fields__", None)
    if type(fields) is not dict or set(values) != set(fields) - {"_seal"}:
        _reject(
            "internal_sealed_result_error",
            "sealed acceptance factory received incomplete internal values",
        )
    instance = object.__new__(cls)
    for field, value in values.items():
        object.__setattr__(instance, field, value)
    object.__setattr__(instance, "_seal", _ACCEPTANCE_SEAL)
    instance.__post_init__()  # type: ignore[attr-defined]
    return instance


@dataclass(frozen=True, slots=True, init=False)
class QualifiedAnchorEvidenceAcceptanceV1:
    """Sealed acceptance of a checkpoint's anchor evidence from a qualified bundle."""

    mode: str
    anchor_statement_id: str
    anchor_evidence: tuple[EvidenceReferenceV1, ...]
    evidence_blobs: tuple[ProviderEvidenceBlobV1, ...]
    _seal: object

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        _reject(
            "unauthenticated_acceptance_construction",
            "qualified anchor-evidence acceptance construction is private",
        )

    def __post_init__(self) -> None:
        if (
            type(self) is not QualifiedAnchorEvidenceAcceptanceV1
            or self._seal is not _ACCEPTANCE_SEAL
        ):
            _reject(
                "unauthenticated_acceptance_construction",
                "qualified anchor-evidence acceptance construction is private",
            )

    @property
    def acceptance_id(self) -> str:
        return content_id("qualified_anchor_evidence_acceptance", self.to_body())

    def to_body(self) -> dict[str, object]:
        return {
            "anchor_evidence": [
                reference.to_body() for reference in self.anchor_evidence
            ],
            "anchor_statement_id": self.anchor_statement_id,
            "evidence_blobs": [
                blob.reference.to_body() for blob in self.evidence_blobs
            ],
            "mode": self.mode,
        }


def _validated_claimed_references(value: object) -> tuple[EvidenceReferenceV1, ...]:
    if type(value) is not tuple or len(value) < 2:
        _reject(
            "invalid_claimed_anchor_evidence",
            "claimed anchor evidence must be a bounded quorum of references",
        )
    for reference in value:
        if (
            type(reference) is not EvidenceReferenceV1
            or reference.evidence_kind != HEAD_ANCHOR_RECEIPT_EVIDENCE_KIND
        ):
            _reject(
                "invalid_claimed_anchor_evidence",
                "claimed anchor evidence must be exact head-anchor-receipt references",
            )
    ordered = tuple(sorted(value, key=lambda ref: (ref.source_id, ref.evidence_id)))
    if len({(ref.source_id, ref.evidence_id) for ref in ordered}) != len(ordered):
        _reject(
            "invalid_claimed_anchor_evidence",
            "claimed anchor evidence cannot repeat one reference",
        )
    return ordered


def _validated_claimed_reference_tuple(
    value: object,
    *,
    field: str,
) -> tuple[EvidenceReferenceV1, ...]:
    if type(value) is not tuple or not value:
        _reject("invalid_claimed_time_evidence", f"{field} must be a nonempty tuple")
    for reference in value:
        if type(reference) is not EvidenceReferenceV1:
            _reject(
                "invalid_claimed_time_evidence",
                f"{field} must be exact EvidenceReferenceV1 values",
            )
    return value  # type: ignore[return-value]


def _validated_claimed_blobs(value: object) -> tuple[ProviderEvidenceBlobV1, ...]:
    if type(value) is not tuple or not value:
        _reject(
            "invalid_claimed_anchor_blobs",
            "claimed anchor evidence blobs must be a nonempty tuple",
        )
    for blob in value:
        if type(blob) is not ProviderEvidenceBlobV1:
            _reject(
                "invalid_claimed_anchor_blobs",
                "claimed anchor evidence blobs must be exact ProviderEvidenceBlobV1 values",
            )
    return value  # type: ignore[return-value]


def accept_qualified_anchor_evidence_v1(
    *,
    head_profile: HeadAuthorityTrustProfileV1,
    time_profile: IntegrityAdapterTrustProfileV1,
    time_bundle: QualifiedTimeBundleV1,
    anchor_bundle: QualifiedAnchorBundleV1,
    claimed_anchor_statement_id: str,
    claimed_anchor_evidence: tuple[EvidenceReferenceV1, ...],
    claimed_evidence_blobs: tuple[ProviderEvidenceBlobV1, ...],
) -> QualifiedAnchorEvidenceAcceptanceV1:
    """Accept a checkpoint's anchor evidence from a freshly reauthenticated bundle.

    The sealed anchor bundle is not trusted directly.  It is reauthenticated from its
    retained requests and signed packages, and the checkpoint's claimed statement,
    references, and BLOB bytes must match the freshly derived result exactly.  A BLOB
    carrying unsigned modeled content is refused because its bytes are not the signed
    package.
    """

    if type(anchor_bundle) is not QualifiedAnchorBundleV1:
        _reject(
            "invalid_qualified_anchor_bundle",
            "acceptance requires an exact sealed QualifiedAnchorBundleV1",
        )
    # Fresh reauthentication from the retained request and signed-package bytes.
    fresh = reauthenticate_anchor_bundle_v1(
        profile=head_profile,
        time_profile=time_profile,
        time_bundle=time_bundle,
        bundle=anchor_bundle,
    )

    claimed_references = _validated_claimed_references(claimed_anchor_evidence)
    claimed_blobs = _validated_claimed_blobs(claimed_evidence_blobs)

    if claimed_anchor_statement_id != fresh.anchor_statement_id:
        _reject(
            "qualified_anchor_statement_mismatch",
            "the claimed anchor statement is not the freshly reauthenticated statement",
        )
    if claimed_references != fresh.evidence:
        _reject(
            "qualified_anchor_evidence_mismatch",
            "the claimed anchor references are not the freshly reauthenticated references",
        )

    retained = {
        blob.reference.evidence_id: blob for blob in fresh.evidence_blobs
    }
    if len(retained) != len(fresh.evidence_blobs):
        _reject(
            "qualified_anchor_evidence_mismatch",
            "the reauthenticated anchor bundle repeats one evidence identity",
        )
    claimed_by_id = {blob.reference.evidence_id: blob for blob in claimed_blobs}
    if set(claimed_by_id) != set(retained):
        _reject(
            "qualified_anchor_blob_coverage_mismatch",
            "the claimed evidence blobs do not exactly cover the retained signed packages",
        )
    for evidence_id, retained_blob in retained.items():
        claimed_blob = claimed_by_id[evidence_id]
        # The claimed BLOB must be the exact signed package.  Unsigned modeled content
        # hashes to a different identity and is rejected here.
        if claimed_blob.content != retained_blob.content:
            _reject(
                "qualified_anchor_blob_coverage_mismatch",
                "a claimed evidence blob is not the exact retained signed package",
            )
        if claimed_blob.evidence_kind != HEAD_ANCHOR_RECEIPT_EVIDENCE_KIND:
            _reject(
                "qualified_anchor_blob_coverage_mismatch",
                "a claimed evidence blob is not a head-anchor-receipt package",
            )

    ordered_blobs = tuple(
        retained[reference.evidence_id] for reference in claimed_references
    )
    return _construct_sealed_result(
        QualifiedAnchorEvidenceAcceptanceV1,
        values={
            "mode": QUALIFIED_EVIDENCE_MODE_QUALIFIED_SIGNED_V1,
            "anchor_statement_id": fresh.anchor_statement_id,
            "anchor_evidence": fresh.evidence,
            "evidence_blobs": ordered_blobs,
        },
    )


@dataclass(frozen=True, slots=True, init=False)
class QualifiedRevocationEvidenceAcceptanceV1:
    """Sealed acceptance of a decision's time and revocation inputs from a bundle."""

    mode: str
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
            "unauthenticated_acceptance_construction",
            "qualified revocation-evidence acceptance construction is private",
        )

    def __post_init__(self) -> None:
        if (
            type(self) is not QualifiedRevocationEvidenceAcceptanceV1
            or self._seal is not _ACCEPTANCE_SEAL
        ):
            _reject(
                "unauthenticated_acceptance_construction",
                "qualified revocation-evidence acceptance construction is private",
            )

    @property
    def acceptance_id(self) -> str:
        return content_id("qualified_revocation_evidence_acceptance", self.to_body())

    def to_body(self) -> dict[str, object]:
        return {
            "evidence_blobs": [
                blob.reference.to_body() for blob in self.evidence_blobs
            ],
            "external_floors": [floor.to_body() for floor in self.external_floors],
            "mode": self.mode,
            "revocation_views": [view.to_body() for view in self.revocation_views],
            "time_evidence": [
                reference.to_body() for reference in self.time_evidence
            ],
            "time_lower_bound": self.time_lower_bound,
            "time_policy_id": self.time_policy_id,
            "time_upper_bound": self.time_upper_bound,
        }


def _validated_view_tuple(value: object) -> tuple[RevocationViewV1, ...]:
    if type(value) is not tuple or not value:
        _reject(
            "invalid_claimed_revocation_views",
            "claimed revocation views must be a nonempty tuple",
        )
    for view in value:
        if type(view) is not RevocationViewV1:
            _reject(
                "invalid_claimed_revocation_views",
                "claimed revocation views must be exact RevocationViewV1 values",
            )
    return value  # type: ignore[return-value]


def _validated_floor_tuple(value: object) -> tuple[RevocationFloorV1, ...]:
    if type(value) is not tuple or not value:
        _reject(
            "invalid_claimed_revocation_floors",
            "claimed revocation floors must be a nonempty tuple",
        )
    for floor in value:
        if type(floor) is not RevocationFloorV1:
            _reject(
                "invalid_claimed_revocation_floors",
                "claimed revocation floors must be exact RevocationFloorV1 values",
            )
    return value  # type: ignore[return-value]


def accept_qualified_revocation_evidence_v1(
    *,
    profile: IntegrityAdapterTrustProfileV1,
    time_bundle: QualifiedTimeBundleV1,
    revocation_bundles: Mapping[str, QualifiedRevocationBundleV1],
    claimed_time_lower_bound: int,
    claimed_time_upper_bound: int,
    claimed_time_policy_id: str,
    claimed_time_evidence: tuple[EvidenceReferenceV1, ...],
    claimed_revocation_views: tuple[RevocationViewV1, ...],
    claimed_external_floors: tuple[RevocationFloorV1, ...],
    claimed_evidence_blobs: tuple[ProviderEvidenceBlobV1, ...],
) -> QualifiedRevocationEvidenceAcceptanceV1:
    """Accept a decision's time and revocation inputs from a reauthenticated mapping.

    ``map_qualified_integrity_inputs_v1`` reauthenticates the time and revocation bundles
    from their retained request and signed-package bytes.  The decision's claimed time
    hull, policy, evidence, views, and floors must match the freshly derived mapping
    exactly, and the claimed BLOBs must be the exact signed packages.
    """

    # Fresh reauthentication of every time and revocation bundle from retained bytes.
    fresh = map_qualified_integrity_inputs_v1(
        profile=profile,
        time_bundle=time_bundle,
        revocation_bundles=revocation_bundles,
    )

    claimed_views = _validated_view_tuple(claimed_revocation_views)
    claimed_floors = _validated_floor_tuple(claimed_external_floors)
    claimed_time_refs = _validated_claimed_reference_tuple(
        claimed_time_evidence,
        field="claimed time evidence",
    )
    claimed_blobs = _validated_claimed_blobs(claimed_evidence_blobs)

    if (
        claimed_time_lower_bound != fresh.time_lower_bound
        or claimed_time_upper_bound != fresh.time_upper_bound
        or claimed_time_policy_id != fresh.time_policy_id
    ):
        _reject(
            "qualified_time_binding_mismatch",
            "the claimed time hull or policy is not the freshly reauthenticated hull",
        )
    if claimed_time_refs != fresh.time_evidence:
        _reject(
            "qualified_time_evidence_mismatch",
            "the claimed time evidence is not the freshly reauthenticated evidence",
        )
    if claimed_views != fresh.revocation_views:
        _reject(
            "qualified_revocation_view_mismatch",
            "the claimed revocation views are not the freshly reauthenticated views",
        )
    if claimed_floors != fresh.external_floors:
        _reject(
            "qualified_revocation_floor_mismatch",
            "the claimed revocation floors are not the freshly reauthenticated floors",
        )

    retained = {blob.reference.evidence_id: blob for blob in fresh.evidence_blobs}
    if len(retained) != len(fresh.evidence_blobs):
        _reject(
            "qualified_revocation_view_mismatch",
            "the reauthenticated mapping repeats one evidence identity",
        )
    claimed_by_id = {blob.reference.evidence_id: blob for blob in claimed_blobs}
    if set(claimed_by_id) != set(retained):
        _reject(
            "qualified_revocation_blob_coverage_mismatch",
            "the claimed evidence blobs do not exactly cover the retained signed packages",
        )
    for evidence_id, retained_blob in retained.items():
        if claimed_by_id[evidence_id].content != retained_blob.content:
            _reject(
                "qualified_revocation_blob_coverage_mismatch",
                "a claimed evidence blob is not the exact retained signed package",
            )

    ordered_blobs = tuple(
        retained[blob.reference.evidence_id]
        for blob in sorted(
            fresh.evidence_blobs,
            key=lambda value: (
                value.evidence_kind,
                value.source_id,
                value.evidence_id,
            ),
        )
    )
    return _construct_sealed_result(
        QualifiedRevocationEvidenceAcceptanceV1,
        values={
            "mode": QUALIFIED_EVIDENCE_MODE_QUALIFIED_SIGNED_V1,
            "time_lower_bound": fresh.time_lower_bound,
            "time_upper_bound": fresh.time_upper_bound,
            "time_policy_id": fresh.time_policy_id,
            "time_evidence": fresh.time_evidence,
            "revocation_views": fresh.revocation_views,
            "external_floors": fresh.external_floors,
            "evidence_blobs": ordered_blobs,
        },
    )


__all__ = (
    "QUALIFIED_EVIDENCE_MODES_V1",
    "QUALIFIED_EVIDENCE_MODE_MODELED_UNSIGNED_V1",
    "QUALIFIED_EVIDENCE_MODE_QUALIFIED_SIGNED_V1",
    "QualifiedAnchorEvidenceAcceptanceV1",
    "QualifiedEvidenceError",
    "QualifiedRevocationEvidenceAcceptanceV1",
    "accept_qualified_anchor_evidence_v1",
    "accept_qualified_revocation_evidence_v1",
)
