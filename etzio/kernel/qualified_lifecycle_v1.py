"""Deterministic reconstruction of qualified fixture requests from retained records.

These functions acquire no provider data. The store supplies pinned profiles and
canonical records; signed-package qualification remains the verification boundary.
"""

from __future__ import annotations

from dataclasses import dataclass

from etzio.integrity_v1 import TRUSTED_TIME_EVIDENCE_KIND, EvidenceReferenceV1, IntegrityDecisionV1
from etzio.kernel.head_authority_adapters_v1 import (
    HEAD_ANCHOR_ADAPTER_ROLE_V1,
    HEAD_CATALOG_ADAPTER_ROLE_V1,
    HEAD_MONITOR_ADAPTER_ROLE_V1,
    HeadAnchorRequestV1,
    HeadAuthorityTrustProfileV1,
    HeadCatalogRequestV1,
    HeadProviderStatementV1,
    QualifiedAnchorBundleV1,
    QualifiedHeadCatalogBundleV1,
    SignedHeadEvidenceV1,
    catalog_projection_leaf_bytes_v1,
    merkle_leaf_hash_v1,
    qualify_anchor_bundle_v1,
    qualify_head_catalog_bundle_v1,
)
from etzio.kernel.integrity_adapters_v1 import (
    TRUSTED_TIME_ADAPTER_ROLE_V1,
    IntegrityAdapterTrustProfileV1,
    QualifiedRevocationBundleV1,
    QualifiedTimeBundleV1,
    RevocationRequestV1,
    SignedProviderEvidenceV1,
    TrustedTimeRequestV1,
    qualify_revocation_bundle_v1,
    qualify_time_bundle_v1,
)
from etzio.kernel.integrity_transition import (
    INTEGRITY_ACCEPTANCE_MODE_QUALIFIED_SIGNED_V1,
    AnchorStatementRecordV1,
    IntegrityLineageV1,
    PendingIntegrityTransitionV1,
    ProviderEvidenceBlobV1,
)
from etzio.kernel.merkle_frontier_v1 import MerkleAppendStateV1
from etzio.kernel.qualified_evidence_v1 import qualified_decision_time_imprint_v1
from etzio.protocol import canonical_dumps, content_id


class QualifiedLifecycleError(ValueError):
    """The retained bytes do not establish the required qualified lifecycle claim."""

    def __init__(self, reason_code: str, message: str):
        super().__init__(message)
        self.reason_code = reason_code


def _reject(reason: str, message: str) -> None:
    raise QualifiedLifecycleError(reason, message)


def qualified_checkpoint_time_imprint_v1(pending_record_id: str) -> str:
    return content_id("qualified_checkpoint_time_imprint_v1", {"pending_record_id": pending_record_id})


def qualified_revocation_nonce_v1(namespace: str, time_bundle_id: str) -> str:
    return content_id("qualified_fixture_revocation_request_v1", {
        "namespace": namespace, "time_bundle_id": time_bundle_id,
    }).removeprefix("sha256:")


def qualified_anchor_nonce_v1(anchor_statement_id: str, time_bundle_id: str) -> str:
    return content_id("qualified_fixture_anchor_request_v1", {
        "anchor_statement_id": anchor_statement_id, "time_bundle_id": time_bundle_id,
    }).removeprefix("sha256:")


def qualified_catalog_nonce_v1(phase: str, time_bundle_id: str, checkpoint_id: str) -> str:
    if phase not in {"prior", "current"}:
        _reject("invalid_qualified_phase", "catalog phase must be prior or current")
    return content_id("qualified_fixture_catalog_request_v1", {
        "phase": phase, "time_bundle_id": time_bundle_id, "checkpoint_id": checkpoint_id,
    }).removeprefix("sha256:")


def qualified_log_genesis_leaf_v1(profile: HeadAuthorityTrustProfileV1, source_id: str) -> bytes:
    if type(profile) is not HeadAuthorityTrustProfileV1:
        _reject("invalid_qualified_profile", "an exact head profile is required")
    copied = HeadAuthorityTrustProfileV1.from_canonical_bytes(profile.to_canonical_bytes())
    bindings = tuple(binding for binding in copied.source_bindings if binding.source_id == source_id)
    if len(bindings) != 1:
        _reject("invalid_qualified_source", "the genesis log requires one enrolled source")
    return canonical_dumps({
        "leaf_schema": "etzio.qualified-fixture-log-genesis.v1", "profile_id": copied.profile_id,
        "source_id": source_id, "log_origin": bindings[0].log_origin,
    })


def _select_evidence(
    references: tuple[EvidenceReferenceV1, ...], blobs: tuple[ProviderEvidenceBlobV1, ...],
) -> tuple[ProviderEvidenceBlobV1, ...]:
    if type(references) is not tuple or type(blobs) is not tuple:
        _reject("invalid_qualified_evidence", "exact tuples of references and provider BLOBs are required")
    selected = {}
    for blob in blobs:
        if type(blob) is not ProviderEvidenceBlobV1:
            _reject("invalid_qualified_evidence", "provider BLOBs must have the exact type")
        copied = ProviderEvidenceBlobV1(blob.evidence_kind, blob.source_id, blob.evidence_id, blob.content)
        identity = (copied.evidence_kind, copied.source_id, copied.evidence_id)
        if identity in selected:
            _reject("qualified_evidence_coverage_mismatch", "provider BLOB identities cannot repeat")
        selected[identity] = copied
    result = []
    for reference in references:
        if type(reference) is not EvidenceReferenceV1:
            _reject("invalid_qualified_evidence", "evidence references must have the exact type")
        identity = (reference.evidence_kind, reference.source_id, reference.evidence_id)
        if identity not in selected:
            _reject("qualified_evidence_coverage_mismatch", "a referenced provider package is missing")
        result.append(selected.pop(identity))
    return tuple(result)


def _reconstruct_time(
    *, profile: IntegrityAdapterTrustProfileV1, decision: IntegrityDecisionV1, purpose: str,
    imprint_id: str, lower: int, upper: int, policy_id: str,
    references: tuple[EvidenceReferenceV1, ...], blobs: tuple[ProviderEvidenceBlobV1, ...],
) -> QualifiedTimeBundleV1:
    if type(profile) is not IntegrityAdapterTrustProfileV1 or type(decision) is not IntegrityDecisionV1:
        _reject("invalid_qualified_time_context", "exact profile and decision records are required")
    profile = IntegrityAdapterTrustProfileV1.from_canonical_bytes(profile.to_canonical_bytes())
    decision = IntegrityDecisionV1.from_envelope(decision.to_envelope())
    if (decision.service_instance_id, decision.environment_id) != (profile.service_instance_id, profile.environment_id):
        _reject("qualified_time_scope_mismatch", "the decision differs from its enrolled time scope")
    sources = tuple(binding.source_id for binding in profile.source_bindings
                    if binding.role == TRUSTED_TIME_ADAPTER_ROLE_V1)
    selected = _select_evidence(references, blobs)
    if (
        len(selected) != len(sources)
        or {blob.source_id for blob in selected} != set(sources)
        or any(blob.evidence_kind != TRUSTED_TIME_EVIDENCE_KIND for blob in selected)
    ):
        _reject("qualified_time_source_mismatch", "the time packages must cover the exact enrolled roster")
    requests = {source: TrustedTimeRequestV1.issue(
        profile=profile, source_id=source, purpose=purpose, mission_id=decision.mission_id,
        authority_id=decision.authority_id, target_id=decision.target_id, event_digest=decision.proposed_event_digest,
        transition_intent_id=decision.transition_intent_id, imprint_id=imprint_id, request_nonce=decision.request_nonce,
    ) for source in sources}
    fresh = qualify_time_bundle_v1(profile=profile, requests=requests, signed_evidence={
        blob.source_id: SignedProviderEvidenceV1.from_canonical_bytes(blob.content) for blob in selected
    })
    if (fresh.time_lower_bound, fresh.time_upper_bound, fresh.time_policy_id, fresh.evidence) != (
        lower, upper, policy_id, references,
    ):
        _reject("qualified_time_claim_mismatch", "retained time fields differ from authenticated provider packages")
    return fresh


def reconstruct_decision_time_v1(
    *, profile: IntegrityAdapterTrustProfileV1, pending: PendingIntegrityTransitionV1,
) -> QualifiedTimeBundleV1:
    if type(pending) is not PendingIntegrityTransitionV1:
        _reject("invalid_qualified_pending", "an exact pending record is required")
    pending = PendingIntegrityTransitionV1.from_canonical_bytes(pending.to_canonical_bytes())
    decision = pending.decision
    return _reconstruct_time(
        profile=profile, decision=decision, purpose="decision", imprint_id=qualified_decision_time_imprint_v1(decision),
        lower=decision.time_lower_bound, upper=decision.time_upper_bound, policy_id=decision.time_policy_id,
        references=decision.time_evidence, blobs=pending.provider_evidence,
    )


def reconstruct_checkpoint_time_v1(
    *, profile: IntegrityAdapterTrustProfileV1, pending: PendingIntegrityTransitionV1, anchor: AnchorStatementRecordV1,
) -> QualifiedTimeBundleV1:
    if type(pending) is not PendingIntegrityTransitionV1 or type(anchor) is not AnchorStatementRecordV1:
        _reject("invalid_qualified_anchor", "exact pending and anchor records are required")
    pending = PendingIntegrityTransitionV1.from_canonical_bytes(pending.to_canonical_bytes())
    anchor = AnchorStatementRecordV1.from_canonical_bytes(anchor.to_canonical_bytes())
    if anchor.pending_record_id != pending.record_id or anchor.event_digest != pending.event_digest:
        _reject("qualified_anchor_scope_mismatch", "the anchor names another pending transition")
    return _reconstruct_time(
        profile=profile, decision=pending.decision, purpose="checkpoint",
        imprint_id=qualified_checkpoint_time_imprint_v1(pending.record_id),
        lower=anchor.time_lower_bound, upper=anchor.time_upper_bound, policy_id=anchor.time_policy_id,
        references=anchor.time_evidence, blobs=anchor.provider_evidence,
    )


def qualified_revocation_requests_v1(
    *, profile: IntegrityAdapterTrustProfileV1, time_bundle: QualifiedTimeBundleV1, namespace: str,
    previous_global: IntegrityLineageV1 | None,
) -> dict[str, RevocationRequestV1]:
    """Derive requests from an already validated global predecessor, or explicit genesis."""
    if previous_global is None:
        root, version, snapshot = 0, 0, content_id("qualified_fixture_revocation_genesis_v1", {
            "profile_id": profile.profile_id, "namespace": namespace,
        })
    else:
        floors = tuple(value for value in previous_global.pending.revocation_floors if value.namespace == namespace)
        if len(floors) != 1:
            _reject("qualified_revocation_predecessor_missing", "one retained predecessor floor is required")
        root, version, snapshot = floors[0].root_version, floors[0].version, floors[0].snapshot_id
    return {binding.source_id: RevocationRequestV1.issue(
        profile=profile, source_id=binding.source_id, evidence_role=binding.role, namespace=namespace,
        time_bundle=time_bundle, prior_root_version=root, prior_version=version, prior_snapshot_id=snapshot,
        request_nonce=qualified_revocation_nonce_v1(namespace, time_bundle.bundle_id),
    ) for binding in profile.source_bindings if binding.namespace == namespace}


def qualified_anchor_requests_v1(
    *, profile: HeadAuthorityTrustProfileV1, time_bundle: QualifiedTimeBundleV1,
    pending: PendingIntegrityTransitionV1, anchor: AnchorStatementRecordV1,
) -> dict[str, HeadAnchorRequestV1]:
    decision = pending.decision
    return {source: HeadAnchorRequestV1.issue(
        profile=profile, source_id=source, mission_id=decision.mission_id, authority_id=decision.authority_id,
        target_id=decision.target_id, event_digest=pending.event_digest,
        transition_intent_id=decision.transition_intent_id, anchor_statement_id=anchor.anchor_statement_id,
        instance_sequence=pending.instance_sequence, time_bundle=time_bundle,
        prior_tree_size=pending.instance_sequence + 1,
        request_nonce=qualified_anchor_nonce_v1(anchor.anchor_statement_id, time_bundle.bundle_id),
    ) for source in profile.sources_for(HEAD_ANCHOR_ADAPTER_ROLE_V1)}


def qualified_catalog_requests_v1(
    *, profile: HeadAuthorityTrustProfileV1, time_bundle: QualifiedTimeBundleV1,
    pending: PendingIntegrityTransitionV1, phase: str, checkpoint_id: str, prior_log: MerkleAppendStateV1,
) -> dict[str, HeadCatalogRequestV1]:
    floor = pending.prior_head_floor
    decision = pending.decision
    return {binding.source_id: HeadCatalogRequestV1.issue(
        profile=profile, source_id=binding.source_id, evidence_role=binding.role,
        mission_id=decision.mission_id, authority_id=decision.authority_id, target_id=decision.target_id,
        event_digest=pending.event_digest, transition_intent_id=decision.transition_intent_id,
        time_bundle=time_bundle, prior_tree_size=prior_log.tree_size,
        prior_log_root_hash="sha256:" + prior_log.root_hash.hex(), prior_instance_sequence=floor.instance_sequence,
        prior_checkpoint_id=floor.checkpoint_id, prior_mission_event_seq=floor.mission_event_seq,
        prior_mission_checkpoint_id=floor.mission_checkpoint_id,
        request_nonce=qualified_catalog_nonce_v1(phase, time_bundle.bundle_id, checkpoint_id),
    ) for binding in profile.source_bindings
      if binding.role in {HEAD_CATALOG_ADAPTER_ROLE_V1, HEAD_MONITOR_ADAPTER_ROLE_V1}}


def _digest_bytes(value: str) -> bytes:
    if type(value) is not str or not value.startswith("sha256:") or len(value) != 71:
        _reject("invalid_qualified_log_hash", "a complete SHA-256 log hash is required")
    return bytes.fromhex(value[7:])


def _retained_head_claim(blobs, source):
    """Decode a predecessor already authenticated by ordered replay; never acquire bytes."""
    selected = tuple(blob for blob in blobs if blob.source_id == source)
    if len(selected) != 1:
        _reject("qualified_log_predecessor_missing", "one retained log package is required")
    signed = SignedHeadEvidenceV1.from_canonical_bytes(selected[0].content)
    return HeadProviderStatementV1.from_canonical_bytes(signed.statement_bytes).claim


def qualified_log_state_v1(*, profile, source, blobs=None, floor=None):
    """Recover append mathematics from an authenticated last leaf, or a pinned genesis.

    The caller must authenticate the retained predecessor before using this state in a
    consequential transition. This pure mathematical value grants no provider authority.
    """
    if blobs is None:
        return MerkleAppendStateV1(1, (merkle_leaf_hash_v1(qualified_log_genesis_leaf_v1(profile, source)),))
    claim = _retained_head_claim(blobs, source)
    if floor is None:
        leaf = _digest_bytes(claim["leaf_hash"])
        proof = claim["inclusion_proof"]
        if claim["leaf_index"] != claim["tree_size"] - 1:
            _reject("qualified_anchor_append_mismatch", "the lifecycle anchor must occupy the last leaf")
    else:
        leaf = merkle_leaf_hash_v1(catalog_projection_leaf_bytes_v1(
            profile=profile, mission_id=floor.mission_id, head=floor,
        ))
        proof = claim["projection_inclusion_proof"]
    return MerkleAppendStateV1.from_last_leaf(
        tree_size=claim["tree_size"], leaf_hash=leaf, proof=tuple(_digest_bytes(node) for node in proof),
        root_hash=_digest_bytes(claim["log_root_hash"]),
    )


def qualified_prior_catalog_state_v1(
    *, profile: HeadAuthorityTrustProfileV1, previous_global: IntegrityLineageV1 | None,
) -> MerkleAppendStateV1:
    source = profile.catalog_binding.source_id
    if previous_global is None:
        return qualified_log_state_v1(profile=profile, source=source)
    final = previous_global.finalization
    if final is None:
        _reject("qualified_log_predecessor_missing", "the previous global transition must be finalized")
    return qualified_log_state_v1(profile=profile, source=source,
                                  blobs=final.provider_evidence, floor=final.external_head_floor)


def _require_coverage(actual, *groups):
    expected = tuple(blob for group in groups for blob in group)

    def key(blob):
        return blob.evidence_kind, blob.source_id, blob.evidence_id

    if tuple(sorted(actual, key=key)) != tuple(sorted(expected, key=key)):
        _reject("qualified_evidence_coverage_mismatch", "the phase must retain exactly its authenticated packages")


def _require_catalog_append(
    profile: HeadAuthorityTrustProfileV1, prior_log: MerkleAppendStateV1, catalog: QualifiedHeadCatalogBundleV1,
) -> None:
    floor = catalog.external_floor
    leaf = merkle_leaf_hash_v1(catalog_projection_leaf_bytes_v1(
        profile=profile, mission_id=floor.mission_id, head=floor,
    ))
    expected, _inclusion, _consistency = prior_log.append(leaf)
    if (catalog.tree_size, catalog.log_root_hash) != (expected.tree_size, "sha256:" + expected.root_hash.hex()):
        _reject("qualified_catalog_append_mismatch", "each observation must append exactly its head projection")


def _require_transient(value, fresh):
    if value is not None and (type(value) is not type(fresh) or value.to_body() != fresh.to_body()):
        _reject("qualified_transient_mismatch", "a supplied transient bundle contradicts reconstruction")


@dataclass(frozen=True, slots=True)
class ReconstructedQualifiedLineageV1:
    decision_time: QualifiedTimeBundleV1
    revocation: tuple[QualifiedRevocationBundleV1, ...]
    prior_catalog: QualifiedHeadCatalogBundleV1
    checkpoint_time: QualifiedTimeBundleV1 | None = None
    anchor: QualifiedAnchorBundleV1 | None = None
    current_catalog: QualifiedHeadCatalogBundleV1 | None = None


def reconstruct_qualified_lineage_v1(
    *, time_profile: IntegrityAdapterTrustProfileV1, head_profile: HeadAuthorityTrustProfileV1,
    lineage: IntegrityLineageV1, previous_global: IntegrityLineageV1 | None,
) -> ReconstructedQualifiedLineageV1:
    """Authenticate every present phase from bytes after its global predecessor was validated.

    Store replay calls this in global order; admission calls it after validating retained
    history. No transient mapping, acquisition service, staging file or ambient time is
    authority. The surrounding kernel separately authenticates decision/checkpoint signers
    and global/mission continuity.
    """
    if type(lineage) is not IntegrityLineageV1:
        _reject("invalid_qualified_lineage", "an exact lifecycle record is required")
    pending = lineage.pending
    for record in (pending, lineage.anchor_statement, lineage.checkpoint_candidate, lineage.finalization):
        if record is not None and record.acceptance_mode != INTEGRITY_ACCEPTANCE_MODE_QUALIFIED_SIGNED_V1:
            _reject("qualified_phase_mode_mismatch", "every retained phase must use the enrolled qualified mode")
    decision_time = reconstruct_decision_time_v1(profile=time_profile, pending=pending)
    _require_transient(pending.time_bundle, decision_time)
    revocation = []
    for namespace in sorted(time_profile.validation_policy.required_revocation_namespaces):
        requests = qualified_revocation_requests_v1(
            profile=time_profile, time_bundle=decision_time, namespace=namespace, previous_global=previous_global,
        )
        selected = tuple(blob for blob in pending.provider_evidence if blob.source_id in requests)
        if len(selected) != len(requests):
            _reject("qualified_evidence_coverage_mismatch", "revocation source coverage differs from enrollment")
        bundle = qualify_revocation_bundle_v1(
            profile=time_profile, namespace=namespace, time_bundle=decision_time, requests=requests,
            signed_evidence={blob.source_id: SignedProviderEvidenceV1.from_canonical_bytes(blob.content)
                             for blob in selected},
        )
        revocation.append(bundle)
    revocation = tuple(revocation)
    if (tuple(bundle.revocation_view for bundle in revocation) != pending.decision.revocation_views
            or tuple(bundle.external_floor for bundle in revocation) != pending.revocation_floors):
        _reject("qualified_revocation_claim_mismatch", "authenticated revocation differs from the pending claims")
    if pending.revocation_bundles is not None:
        if len(pending.revocation_bundles) != len(revocation):
            _reject("qualified_transient_mismatch", "transient revocation coverage differs")
        for fresh in revocation:
            _require_transient(pending.revocation_bundles.get(fresh.namespace), fresh)
    prior_log = qualified_prior_catalog_state_v1(profile=head_profile, previous_global=previous_global)
    requests = qualified_catalog_requests_v1(
        profile=head_profile, time_bundle=decision_time, pending=pending, phase="prior",
        checkpoint_id=pending.prior_head_floor.checkpoint_id, prior_log=prior_log,
    )
    selected = _select_evidence(pending.prior_head_floor.evidence, pending.provider_evidence)
    prior_catalog = qualify_head_catalog_bundle_v1(
        profile=head_profile, time_profile=time_profile, time_bundle=decision_time, requests=requests,
        signed_evidence={blob.source_id: SignedHeadEvidenceV1.from_canonical_bytes(blob.content) for blob in selected},
    )
    if prior_catalog.external_floor != pending.prior_head_floor:
        _reject("qualified_prior_head_mismatch", "the signed prior catalog differs from the pending head")
    _require_catalog_append(head_profile, prior_log, prior_catalog)
    _require_coverage(pending.provider_evidence, decision_time.evidence_blobs,
                      *(bundle.evidence_blobs for bundle in revocation), prior_catalog.evidence_blobs)
    result = dict(decision_time=decision_time, revocation=revocation, prior_catalog=prior_catalog)
    anchor = lineage.anchor_statement
    if anchor is None:
        return ReconstructedQualifiedLineageV1(**result)
    checkpoint_time = reconstruct_checkpoint_time_v1(profile=time_profile, pending=pending, anchor=anchor)
    _require_coverage(anchor.provider_evidence, checkpoint_time.evidence_blobs)
    result["checkpoint_time"] = checkpoint_time
    candidate = lineage.checkpoint_candidate
    if candidate is None:
        return ReconstructedQualifiedLineageV1(**result)
    requests = qualified_anchor_requests_v1(
        profile=head_profile, time_bundle=checkpoint_time, pending=pending, anchor=anchor,
    )
    anchor_bundle = qualify_anchor_bundle_v1(
        profile=head_profile, time_profile=time_profile, time_bundle=checkpoint_time, requests=requests,
        signed_evidence={blob.source_id: SignedHeadEvidenceV1.from_canonical_bytes(blob.content)
                         for blob in candidate.provider_evidence},
    )
    if (anchor_bundle.anchor_statement_id != candidate.checkpoint.anchor_statement_id
            or anchor_bundle.evidence != candidate.checkpoint.anchor_evidence):
        _reject("qualified_anchor_claim_mismatch", "the checkpoint differs from its authenticated anchor")
    for source, package in anchor_bundle.authenticated_packages.items():
        prior_blobs = None if previous_global is None else previous_global.checkpoint_candidate.provider_evidence
        prior_state = qualified_log_state_v1(profile=head_profile, source=source, blobs=prior_blobs)
        expected, _inclusion, _consistency = prior_state.append(_digest_bytes(anchor_bundle.anchor_leaf_hash))
        claim = package.claim
        if (prior_state.tree_size != pending.instance_sequence + 1
                or claim["tree_size"] != expected.tree_size or claim["leaf_index"] != expected.tree_size - 1
                or claim["log_root_hash"] != "sha256:" + expected.root_hash.hex()):
            _reject("qualified_anchor_append_mismatch", "anchor registration must append to its retained log head")
    _require_coverage(candidate.provider_evidence, anchor_bundle.evidence_blobs)
    _require_transient(candidate.time_bundle, checkpoint_time)
    _require_transient(candidate.anchor_bundle, anchor_bundle)
    result["anchor"] = anchor_bundle
    final = lineage.finalization
    if final is None:
        return ReconstructedQualifiedLineageV1(**result)
    prior_log = qualified_log_state_v1(profile=head_profile, source=head_profile.catalog_binding.source_id,
                                      blobs=prior_catalog.evidence_blobs, floor=prior_catalog.external_floor)
    requests = qualified_catalog_requests_v1(
        profile=head_profile, time_bundle=checkpoint_time, pending=pending, phase="current",
        checkpoint_id=candidate.checkpoint.checkpoint_id, prior_log=prior_log,
    )
    current = qualify_head_catalog_bundle_v1(
        profile=head_profile, time_profile=time_profile, time_bundle=checkpoint_time, requests=requests,
        signed_evidence={blob.source_id: SignedHeadEvidenceV1.from_canonical_bytes(blob.content)
                         for blob in final.provider_evidence},
    )
    if current.external_floor != final.external_head_floor:
        _reject("qualified_current_head_mismatch", "the signed current catalog differs from finalization")
    _require_catalog_append(head_profile, prior_log, current)
    _require_coverage(final.provider_evidence, current.evidence_blobs)
    _require_transient(final.time_bundle, checkpoint_time)
    _require_transient(final.catalog_bundle, current)
    result["current_catalog"] = current
    return ReconstructedQualifiedLineageV1(**result)


def validate_qualified_transients_v1(
    *, record: object, reconstructed: ReconstructedQualifiedLineageV1,
    time_profile: IntegrityAdapterTrustProfileV1, head_profile: HeadAuthorityTrustProfileV1,
) -> None:
    """Optional runtime bundles must reauthenticate and agree with byte reconstruction."""
    from .head_authority_adapters_v1 import (
        reauthenticate_anchor_bundle_v1,
        reauthenticate_head_catalog_bundle_v1,
    )
    from .integrity_adapters_v1 import reauthenticate_revocation_bundle_v1, reauthenticate_time_bundle_v1
    from .integrity_transition import CheckpointCandidateRecordV1, FinalizedIntegrityTransitionV1

    fresh_time = (reconstructed.decision_time if type(record) is PendingIntegrityTransitionV1
                  else reconstructed.checkpoint_time)
    supplied_time = getattr(record, "time_bundle", None)
    if supplied_time is not None:
        supplied_time = reauthenticate_time_bundle_v1(profile=time_profile, bundle=supplied_time)
        _require_transient(supplied_time, fresh_time)
    if type(record) is PendingIntegrityTransitionV1 and record.revocation_bundles is not None:
        supplied = dict(record.revocation_bundles)
        if set(supplied) != {bundle.namespace for bundle in reconstructed.revocation}:
            _reject("qualified_transient_mismatch", "transient revocation coverage differs from reconstructed bytes")
        for bundle in reconstructed.revocation:
            checked = reauthenticate_revocation_bundle_v1(
                profile=time_profile, time_bundle=fresh_time, bundle=supplied[bundle.namespace],
            )
            _require_transient(checked, bundle)
    if type(record) is CheckpointCandidateRecordV1 and record.anchor_bundle is not None:
        checked = reauthenticate_anchor_bundle_v1(profile=head_profile, time_profile=time_profile,
            time_bundle=fresh_time, bundle=record.anchor_bundle)
        _require_transient(checked, reconstructed.anchor)
    if type(record) is FinalizedIntegrityTransitionV1 and record.catalog_bundle is not None:
        checked = reauthenticate_head_catalog_bundle_v1(profile=head_profile, time_profile=time_profile,
            time_bundle=fresh_time, bundle=record.catalog_bundle)
        _require_transient(checked, reconstructed.current_catalog)
