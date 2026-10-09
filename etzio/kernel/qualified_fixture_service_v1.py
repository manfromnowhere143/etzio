"""Networkless signed-fixture finality service; no external durability or real UTC claim.

The service proposes bytes. The store independently reconstructs and authenticates them
under enrolled public profiles, including after process loss. All private keys here are
explicit repository fixture keys, never production provider credentials.
"""

from __future__ import annotations

import hashlib
from dataclasses import fields, replace

from etzio.integrity_v1 import IntegrityDecisionV1
from etzio.kernel.head_authority_adapters_v1 import (
    HEAD_AUTHORITY_CONTRACT_VERSION_V1,
    HeadProviderStatementV1,
    RepositoryOwnedDeterministicHeadAuthorityFixtureV1,
    SignedHeadEvidenceV1,
    catalog_projection_leaf_bytes_v1,
    merkle_leaf_hash_v1,
    qualify_anchor_bundle_v1,
    qualify_head_catalog_bundle_v1,
)
from etzio.kernel.integrity_adapters_v1 import (
    ExpectedRevocationStateV1,
    TrustedTimeRequestV1,
    qualify_revocation_bundle_v1,
    qualify_time_bundle_v1,
)
from etzio.kernel.integrity_transition import (
    INTEGRITY_ACCEPTANCE_MODE_QUALIFIED_SIGNED_V1,
    MODELED_INTEGRITY_PROFILE_V1,
    PendingIntegrityTransitionV1,
    RepositoryOwnedDeterministicModeledIntegrityServiceV1,
    authenticate_pending_integrity_transition,
    validate_anchor_statement_record,
)
from etzio.kernel.qualified_evidence_v1 import qualified_decision_time_imprint_v1
from etzio.kernel.qualified_lifecycle_v1 import (
    qualified_anchor_requests_v1,
    qualified_catalog_requests_v1,
    qualified_checkpoint_time_imprint_v1,
    qualified_log_state_v1,
    qualified_prior_catalog_state_v1,
    qualified_revocation_requests_v1,
    reconstruct_checkpoint_time_v1,
)
from etzio.protocol import canonical_dumps, content_id


def _sorted_blobs(*groups):
    return tuple(sorted((blob for group in groups for blob in group),
                        key=lambda blob: (blob.evidence_kind, blob.source_id, blob.evidence_id)))


def _digest(value):
    return "sha256:" + value.hex()


class RepositoryOwnedQualifiedFixtureIntegrityServiceV1:
    """Compose fixture kernel signers with separately enrolled signed-provider fixtures."""

    def __init__(
        self, *, core: RepositoryOwnedDeterministicModeledIntegrityServiceV1,
        fixture: RepositoryOwnedDeterministicHeadAuthorityFixtureV1,
    ) -> None:
        if (type(core) is not RepositoryOwnedDeterministicModeledIntegrityServiceV1
                or type(fixture) is not RepositoryOwnedDeterministicHeadAuthorityFixtureV1):
            raise ValueError("qualified fixture service requires exact repository fixture implementations")
        profile = fixture.time_fixture.profile
        head = fixture.profile
        if (core.service_instance_id, core.environment_id, core.validation_policy.to_body()) != (
            profile.service_instance_id, profile.environment_id, profile.validation_policy.to_body(),
        ) or (head.service_instance_id, head.environment_id, head.validation_policy.to_body()) != (
            profile.service_instance_id, profile.environment_id, profile.validation_policy.to_body(),
        ):
            raise ValueError("qualified fixture profiles must match the kernel scope and policy")
        self._core = core
        self._fixture = fixture
        self.time_profile = profile
        self.head_profile = head
        self.service_instance_id = core.service_instance_id
        self.environment_id = core.environment_id
        self.validation_policy = core.validation_policy
        self.authority_binding = core.authority_binding
        self._previous_global = None

    def _time(self, decision, *, purpose, imprint_id, epoch_second):
        requests = {adapter.source_id: TrustedTimeRequestV1.issue(
            profile=self.time_profile, source_id=adapter.source_id, purpose=purpose,
            mission_id=decision.mission_id, authority_id=decision.authority_id, target_id=decision.target_id,
            event_digest=decision.proposed_event_digest, transition_intent_id=decision.transition_intent_id,
            imprint_id=imprint_id, request_nonce=decision.request_nonce,
        ) for adapter in self._fixture.time_fixture.time_adapters}
        signed = {adapter.source_id: replace(adapter, time_lower_bound=epoch_second, time_upper_bound=epoch_second)
                  .acquire(requests[adapter.source_id]) for adapter in self._fixture.time_fixture.time_adapters}
        return qualify_time_bundle_v1(profile=self.time_profile, requests=requests, signed_evidence=signed)

    def _revocation(self, time_bundle, previous_global, instance_sequence):
        result = {}
        for namespace in sorted(self.validation_policy.required_revocation_namespaces):
            requests = qualified_revocation_requests_v1(
                profile=self.time_profile, time_bundle=time_bundle, namespace=namespace,
                previous_global=previous_global,
            )
            prior = next(iter(requests.values()))
            state = ExpectedRevocationStateV1(
                namespace=namespace, prior_root_version=prior.prior_root_version, prior_version=prior.prior_version,
                prior_snapshot_id=prior.prior_snapshot_id, expected_root_version=1,
                expected_version=instance_sequence + 1,
                expected_snapshot_id=content_id("qualified_fixture_revocation_snapshot_v1", {
                    "namespace": namespace, "profile_id": self.time_profile.profile_id,
                    "instance_sequence": instance_sequence, "event_digest": time_bundle.event_digest,
                }), expected_valid_from=time_bundle.time_lower_bound,
                expected_valid_until=time_bundle.time_upper_bound + 1,
                expected_published_at=time_bundle.time_lower_bound,
            )
            signed = {adapter.source_id: replace(adapter, state=state).acquire(requests[adapter.source_id])
                      for adapter in self._fixture.time_fixture.revocation_adapters if adapter.namespace == namespace}
            result[namespace] = qualify_revocation_bundle_v1(
                profile=self.time_profile, namespace=namespace, time_bundle=time_bundle,
                requests=requests, signed_evidence=signed,
            )
        return result

    def _sign_head(self, adapter, request, claim):
        binding = adapter.binding
        return adapter.signer.sign(HeadProviderStatementV1(
            contract_version=HEAD_AUTHORITY_CONTRACT_VERSION_V1, profile_id=self.head_profile.profile_id,
            trust_root_id=self.head_profile.trust_root_id, service_instance_id=self.service_instance_id,
            environment_id=self.environment_id, source_id=binding.source_id, evidence_role=binding.role,
            provider_policy_id=binding.provider_policy_id, request_id=request.request_id, claim=claim,
        ))

    def _catalog(self, *, pending, time_bundle, phase, floor, prior_log):
        requests = qualified_catalog_requests_v1(
            profile=self.head_profile, time_bundle=time_bundle, pending=pending, phase=phase,
            checkpoint_id=floor.checkpoint_id, prior_log=prior_log,
        )
        leaf = merkle_leaf_hash_v1(catalog_projection_leaf_bytes_v1(
            profile=self.head_profile, mission_id=floor.mission_id, head=floor,
        ))
        current, inclusion, consistency = prior_log.append(leaf)
        adapter = self._fixture.catalog_adapter
        claim = {key: value for key, value in floor.to_body().items()
                 if key not in {"service_instance_id", "environment_id", "evidence"}}
        claim.update(log_origin=adapter.binding.log_origin, log_root_hash=_digest(current.root_hash),
                     tree_size=current.tree_size, published_at=time_bundle.time_lower_bound,
                     consistency_proof=[_digest(node) for node in consistency],
                     projection_inclusion_proof=[_digest(node) for node in inclusion])
        signed = {adapter.source_id: self._sign_head(adapter, requests[adapter.source_id], claim)}
        for monitor in self._fixture.monitor_adapters:
            signed[monitor.source_id] = self._sign_head(monitor, requests[monitor.source_id], {
                "log_origin": monitor.binding.log_origin, "log_root_hash": _digest(current.root_hash),
                "tree_size": current.tree_size, "observed_at": time_bundle.time_lower_bound,
                "witnessed_source_id": adapter.source_id,
            })
        return qualify_head_catalog_bundle_v1(
            profile=self.head_profile, time_profile=self.time_profile, time_bundle=time_bundle,
            requests=requests, signed_evidence=signed,
        )

    def prepare_pending_transition(self, event, *, previous_global, previous_mission):
        # The modeled core supplies only predecessor identities and placeholder inputs.
        # Every placeholder provider package is replaced before a qualified proposal exists.
        floor, floor_blobs = self._core._floor_for_predecessor(
            event=event, previous_global=previous_global, previous_mission=previous_mission,
        )
        sequence = floor.instance_sequence + 1
        views, _floors, _revocation_blobs = self._core._revocation_material()
        time_blobs = self._core._time_evidence(
            purpose="decision", event_digest=event.event_digest, epoch_second=event.decision_time,
        )
        decision = IntegrityDecisionV1.issue(
            service_instance_id=self.service_instance_id, environment_id=self.environment_id,
            mission_id=event.mission_id, authority_id=event.authority_id, target_id=event.target_id,
            prior_global_checkpoint_sequence=floor.instance_sequence, prior_global_checkpoint_id=floor.checkpoint_id,
            prior_global_checkpoint_attestation_id=floor.checkpoint_attestation_id,
            prior_global_checkpoint_principal_id=floor.checkpoint_principal_id,
            prior_global_checkpoint_trust_snapshot_id=floor.checkpoint_trust_snapshot_id,
            prior_event_seq=event.seq - 1, prior_event_digest=event.prev_digest, event_kind=event.kind,
            proposed_event_digest=event.event_digest,
            transition_intent_id=content_id("modeled_integrity_transition_intent", {
                "event_kind": event.kind, "profile": MODELED_INTEGRITY_PROFILE_V1, "unit": event.unit,
            }), request_nonce=hashlib.sha256(canonical_dumps({
                "environment_id": self.environment_id, "event_digest": event.event_digest,
                "instance_sequence": sequence, "service_instance_id": self.service_instance_id,
            })).hexdigest(), time_lower_bound=event.decision_time, time_upper_bound=event.decision_time,
            time_policy_id=self.validation_policy.decision_time_policy_id,
            time_evidence=tuple(blob.reference for blob in time_blobs), revocation_views=views,
            decision_policy_id=self.validation_policy.decision_policy_id,
        )
        time_bundle = self._time(decision, purpose="decision", imprint_id=qualified_decision_time_imprint_v1(decision),
                                 epoch_second=event.decision_time)
        revocation = self._revocation(time_bundle, previous_global, sequence)
        values = {field.name: getattr(decision, field.name) for field in fields(decision)
                  if field.name != "decision_id"}
        values.update(time_evidence=time_bundle.evidence,
                      revocation_views=tuple(bundle.revocation_view for bundle in revocation.values()))
        decision = IntegrityDecisionV1.issue(**values)
        # A structurally closed proposal supplies deterministic catalog request context;
        # unsigned predecessor placeholders never reach the store or the reconstructor.
        pending = PendingIntegrityTransitionV1(
            event_digest=event.event_digest, mission_id=event.mission_id, event_seq=event.seq,
            instance_sequence=sequence, signed_decision=self._core._decision_signer.sign_decision(decision),
            decision_trust_store=self._core.trust_store, validation_policy=self.validation_policy,
            revocation_floors=tuple(bundle.external_floor for bundle in revocation.values()), prior_head_floor=floor,
            provider_evidence=_sorted_blobs(time_bundle.evidence_blobs,
                *(bundle.evidence_blobs for bundle in revocation.values()), floor_blobs),
            acceptance_mode=INTEGRITY_ACCEPTANCE_MODE_QUALIFIED_SIGNED_V1,
        )
        catalog = self._catalog(pending=pending, time_bundle=time_bundle, phase="prior", floor=floor,
            prior_log=qualified_prior_catalog_state_v1(profile=self.head_profile, previous_global=previous_global))
        pending = replace(pending, prior_head_floor=catalog.external_floor,
            provider_evidence=_sorted_blobs(time_bundle.evidence_blobs,
                *(bundle.evidence_blobs for bundle in revocation.values()), catalog.evidence_blobs),
            time_bundle=time_bundle, revocation_bundles=revocation)
        authenticate_pending_integrity_transition(pending, event=event, previous_global=previous_global)
        return pending

    def prepare_anchor_statement(self, pending):
        time_bundle = self._time(pending.decision, purpose="checkpoint",
            imprint_id=qualified_checkpoint_time_imprint_v1(pending.record_id),
            epoch_second=pending.decision.time_upper_bound)
        modeled = self._core.prepare_anchor_statement(pending)
        body = modeled.registration_body
        body.update(time_evidence=[reference.to_body() for reference in time_bundle.evidence],
                    time_lower_bound=time_bundle.time_lower_bound, time_upper_bound=time_bundle.time_upper_bound,
                    time_policy_id=time_bundle.time_policy_id)
        anchor = replace(modeled, time_lower_bound=time_bundle.time_lower_bound,
            time_upper_bound=time_bundle.time_upper_bound, time_policy_id=time_bundle.time_policy_id,
            time_evidence=time_bundle.evidence, anchor_statement_id=content_id("head_anchor_statement", body),
            registration_request=canonical_dumps(body), provider_evidence=_sorted_blobs(time_bundle.evidence_blobs),
            acceptance_mode=INTEGRITY_ACCEPTANCE_MODE_QUALIFIED_SIGNED_V1)
        validate_anchor_statement_record(pending, anchor)
        return anchor

    def prime_catalog(self, *, previous_global, previous_mission):
        self._core.prime_catalog(previous_global=previous_global, previous_mission=previous_mission)
        self._previous_global = previous_global

    def register_anchor_statement(self, anchor, *, pending):
        time_bundle = reconstruct_checkpoint_time_v1(profile=self.time_profile, pending=pending, anchor=anchor)
        requests = qualified_anchor_requests_v1(
            profile=self.head_profile, time_bundle=time_bundle, pending=pending, anchor=anchor,
        )
        signed = {}
        for adapter in self._fixture.anchor_adapters:
            source = adapter.source_id
            blobs = (None if self._previous_global is None
                     else self._previous_global.checkpoint_candidate.provider_evidence)
            previous = qualified_log_state_v1(profile=self.head_profile, source=source, blobs=blobs)
            request = requests[source]
            current, inclusion, _consistency = previous.append(bytes.fromhex(request.anchor_leaf_hash[7:]))
            signed[source] = self._sign_head(adapter, request, {
                "anchor_statement_id": anchor.anchor_statement_id, "leaf_hash": request.anchor_leaf_hash,
                "inclusion_proof": [_digest(node) for node in inclusion], "leaf_index": current.tree_size - 1,
                "tree_size": current.tree_size, "log_origin": adapter.binding.log_origin,
                "log_root_hash": _digest(current.root_hash), "registered_at": time_bundle.time_lower_bound,
            })
        bundle = qualify_anchor_bundle_v1(profile=self.head_profile, time_profile=self.time_profile,
            time_bundle=time_bundle, requests=requests, signed_evidence=signed)
        return _sorted_blobs(bundle.evidence_blobs)

    def prepare_checkpoint_candidate(self, pending, anchor, *, anchor_receipts):
        time_bundle = reconstruct_checkpoint_time_v1(profile=self.time_profile, pending=pending, anchor=anchor)
        bundle = qualify_anchor_bundle_v1(profile=self.head_profile, time_profile=self.time_profile,
            time_bundle=time_bundle, requests=qualified_anchor_requests_v1(
                profile=self.head_profile, time_bundle=time_bundle, pending=pending, anchor=anchor),
            signed_evidence={blob.source_id: SignedHeadEvidenceV1.from_canonical_bytes(blob.content)
                             for blob in anchor_receipts})
        return self._core.prepare_checkpoint_candidate(pending, anchor, anchor_receipts=anchor_receipts,
            acceptance_mode=INTEGRITY_ACCEPTANCE_MODE_QUALIFIED_SIGNED_V1,
            anchor_bundle=bundle, time_bundle=time_bundle)

    def publish_checkpoint(self, candidate):
        return self._core.publish_checkpoint(candidate)

    def observe_current_floor(self, pending, candidate):
        floor, _blobs = self._core.observe_current_floor(pending, candidate)
        # The checkpoint carries the exact anchor time fields; regenerate their immutable
        # anchor envelope deterministically rather than depending on a transient bundle.
        anchor = self.prepare_anchor_statement(pending)
        if anchor.record_id != candidate.anchor_statement_record_id:
            raise ValueError("checkpoint differs from the deterministic qualified anchor")
        time_bundle = reconstruct_checkpoint_time_v1(profile=self.time_profile, pending=pending, anchor=anchor)
        prior_log = qualified_log_state_v1(profile=self.head_profile,
            source=self.head_profile.catalog_binding.source_id, blobs=pending.provider_evidence,
            floor=pending.prior_head_floor)
        catalog = self._catalog(pending=pending, time_bundle=time_bundle, phase="current", floor=floor,
                                 prior_log=prior_log)
        return catalog.external_floor, _sorted_blobs(catalog.evidence_blobs)
