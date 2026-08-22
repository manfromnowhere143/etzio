"""Record wiring for qualified signed revocation evidence (ADR-0019 step 4).

``PendingIntegrityTransitionV1`` now carries an ``acceptance_mode`` and, in qualified mode,
transient sealed time and revocation bundles.  ``append_pending_integrity_event`` cross-checks
the declared mode against the enrolled acceptance profile and, in qualified mode,
reauthenticates the decision's time and revocation inputs under the enrolled roots via
``store.verify_qualified_revocation_evidence`` before any append work.

Boundary: because the pending append-verify runs before the append transaction (no lineage is
required), this file proves the field, the mode-branching record gate, the canonical
round-trip that drops the transient bundles, the store cross-check in both directions, the
sealed bundle-presence gate, and a *live* reauthentication that refuses a pending whose
decision the qualified bundles do not authenticate.  A coherent qualified decision whose time
and revocation inputs the bundles do authenticate (the positive) is produced by the
qualified-mode modeled service (ADR-0019 step 6); the store's positive revocation acceptance
primitive itself is proved in ``test_qualified_revocation_acceptance_v1``.
"""

from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path

import pytest
from test_integrity_store_v2 import (
    _enroll,
    _policy,
    _refusal_event,
    _service,
    _state_path,
)
from test_qualified_anchor_consumption_v1 import _head_fixture

from etzio.integrity_v1 import IntegrityDecisionV1
from etzio.kernel.events_v1 import GENESIS_DIGEST, EventV1
from etzio.kernel.integrity_adapters_v1 import (
    RevocationRequestV1,
    TrustedTimeRequestV1,
    map_qualified_integrity_inputs_v1,
    qualify_revocation_bundle_v1,
    qualify_time_bundle_v1,
)
from etzio.kernel.integrity_transition import (
    INTEGRITY_ACCEPTANCE_MODE_MODELED_UNSIGNED_V1,
    INTEGRITY_ACCEPTANCE_MODE_QUALIFIED_SIGNED_V1,
    PendingIntegrityTransitionV1,
    RepositoryOwnedDeterministicModeledIntegrityServiceV1,
)
from etzio.kernel.store import EventStoreError, SQLiteEventStore


def _digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def _nonce(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Coherent qualified time + revocation bundles from the enrolled fixture roots
# ---------------------------------------------------------------------------


def _decision_time_bundle(hfx):
    tfx = hfx.time_fixture
    vector = tfx.vector
    requests = {
        adapter.source_id: TrustedTimeRequestV1.issue(
            profile=tfx.profile,
            source_id=adapter.source_id,
            purpose="decision",
            mission_id=vector.mission_id,
            authority_id=vector.authority_id,
            target_id=vector.target_id,
            event_digest=vector.event_digest,
            transition_intent_id=vector.transition_intent_id,
            imprint_id=_digest("pending-decision-imprint"),
            request_nonce=vector.request_nonce,
        )
        for adapter in tfx.time_adapters
    }
    return qualify_time_bundle_v1(
        profile=tfx.profile,
        requests=requests,
        signed_evidence={
            adapter.source_id: adapter.acquire(requests[adapter.source_id])
            for adapter in tfx.time_adapters
        },
    )


def _revocation_bundles(hfx, time_bundle):
    tfx = hfx.time_fixture
    namespaces = sorted(tfx.profile.validation_policy.required_revocation_namespaces)
    bundles = {}
    for namespace in namespaces:
        state = next(
            s for s in tfx.vector.expected_revocation if s.namespace == namespace
        )
        adapters = [a for a in tfx.revocation_adapters if a.namespace == namespace]
        requests = {
            adapter.source_id: RevocationRequestV1.issue(
                profile=tfx.profile,
                source_id=adapter.source_id,
                evidence_role=adapter.role,
                namespace=namespace,
                time_bundle=time_bundle,
                prior_root_version=state.prior_root_version,
                prior_version=state.prior_version,
                prior_snapshot_id=state.prior_snapshot_id,
                request_nonce=_nonce(f"pending-revocation-{namespace}"),
            )
            for adapter in adapters
        }
        bundles[namespace] = qualify_revocation_bundle_v1(
            profile=tfx.profile,
            namespace=namespace,
            time_bundle=time_bundle,
            requests={a.source_id: requests[a.source_id] for a in adapters},
            signed_evidence={
                a.source_id: a.acquire(requests[a.source_id]) for a in adapters
            },
        )
    return bundles


# ---------------------------------------------------------------------------
# Stores and pending records
# ---------------------------------------------------------------------------


def _modeled_store(tmp_path: Path, name: str = "state"):
    store = SQLiteEventStore(_state_path(tmp_path, name))
    service = _enroll(store, _policy())
    return store, service


def _qualified_store(tmp_path: Path, hfx, name: str = "state"):
    store, service = _modeled_store(tmp_path, name)
    store.enroll_qualified_acceptance(
        qualified_time_profile=hfx.time_fixture.profile,
        qualified_head_profile=hfx.profile,
    )
    return store, service


def _aligned_qualified_store(tmp_path: Path, hfx, name: str = "state"):
    """A qualified store whose enrolled modeled binding matches the profile-aligned service."""

    tfx = hfx.time_fixture
    service = _profile_aligned_service(hfx)
    store = SQLiteEventStore(_state_path(tmp_path, name))
    _enroll(
        store,
        tfx.profile.validation_policy,
        service=service,
        service_instance_id=tfx.profile.service_instance_id,
        environment_id=tfx.profile.environment_id,
    )
    store.enroll_qualified_acceptance(
        qualified_time_profile=tfx.profile,
        qualified_head_profile=hfx.profile,
    )
    return store, service


def _modeled_pending(service, label: str):
    event = _refusal_event(label)
    pending = service.prepare_pending_transition(
        event,
        previous_global=None,
        previous_mission=None,
    )
    return event, pending


def _qualified_pending(service, hfx, label: str, *, bundles: bool = True):
    """A pending record flipped into qualified mode, optionally carrying its sealed bundles."""

    event, pending = _modeled_pending(service, label)
    tb = _decision_time_bundle(hfx)
    rev = _revocation_bundles(hfx, tb)
    qualified = replace(
        pending,
        acceptance_mode=INTEGRITY_ACCEPTANCE_MODE_QUALIFIED_SIGNED_V1,
        time_bundle=tb if bundles else None,
        revocation_bundles=rev if bundles else None,
    )
    return event, qualified


def _profile_aligned_service(hfx):
    """A modeled service whose service/environment/policy match the qualified time roots.

    This is the alignment the qualified-mode modeled service (ADR-0019 step 6) needs: the
    harness-produced ``RevocationFloorV1`` values carry the profile's service, environment,
    and decision policy, so a coherent qualified decision must be issued under the same scope.
    """

    tfx = hfx.time_fixture
    return RepositoryOwnedDeterministicModeledIntegrityServiceV1.deterministic(
        seed=b"qualified-pending-service-v1",
        service_instance_id=tfx.profile.service_instance_id,
        environment_id=tfx.profile.environment_id,
        validation_policy=tfx.profile.validation_policy,
    )


def _coherent_qualified_pending(service, hfx):
    """Build a coherent qualified pending whose decision the enrolled bundles authenticate.

    The decision reuses the modeled service's scope, predecessors, transition intent, and
    nonce for the genesis event, and swaps in the qualified time hull, time evidence,
    revocation views, and external floors from the freshly mapped qualified inputs.  The
    event's ``decision_time`` is fixed to the qualified hull's upper bound so
    ``authenticate_pending_integrity_transition`` binds it.  The predecessor head floor stays
    the modeled genesis floor, whose evidence the pending phase does not reauthenticate (that
    is the finalization phase's concern).
    """

    tfx = hfx.time_fixture
    policy = tfx.profile.validation_policy
    tb = _decision_time_bundle(hfx)
    rev = _revocation_bundles(hfx, tb)
    inputs = map_qualified_integrity_inputs_v1(
        profile=tfx.profile, time_bundle=tb, revocation_bundles=rev
    )
    vector = tfx.vector
    event = EventV1.create(
        mission_id=vector.mission_id,
        seq=0,
        kind="mission_admission_refused",
        unit="AQUILA",
        authority_id=vector.authority_id,
        target_id=vector.target_id,
        decision_time=inputs.time_upper_bound,
        payload={"reason_code": "authority_expired", "stage": "admission"},
        prev_digest=GENESIS_DIGEST,
    )
    modeled = service.prepare_pending_transition(
        event, previous_global=None, previous_mission=None
    )
    md = modeled.decision
    head_floor, head_floor_blobs = service._floor_for_predecessor(  # noqa: SLF001
        event=event, previous_global=None, previous_mission=None
    )
    decision = IntegrityDecisionV1.issue(
        service_instance_id=md.service_instance_id,
        environment_id=md.environment_id,
        mission_id=md.mission_id,
        authority_id=md.authority_id,
        target_id=md.target_id,
        prior_global_checkpoint_sequence=md.prior_global_checkpoint_sequence,
        prior_global_checkpoint_id=md.prior_global_checkpoint_id,
        prior_global_checkpoint_attestation_id=md.prior_global_checkpoint_attestation_id,
        prior_global_checkpoint_principal_id=md.prior_global_checkpoint_principal_id,
        prior_global_checkpoint_trust_snapshot_id=(
            md.prior_global_checkpoint_trust_snapshot_id
        ),
        prior_event_seq=md.prior_event_seq,
        prior_event_digest=md.prior_event_digest,
        event_kind=md.event_kind,
        proposed_event_digest=md.proposed_event_digest,
        transition_intent_id=md.transition_intent_id,
        request_nonce=md.request_nonce,
        time_lower_bound=inputs.time_lower_bound,
        time_upper_bound=inputs.time_upper_bound,
        time_policy_id=inputs.time_policy_id,
        time_evidence=inputs.time_evidence,
        revocation_views=inputs.revocation_views,
        decision_policy_id=md.decision_policy_id,
    )
    provider_evidence = tuple(
        sorted(
            (*inputs.evidence_blobs, *head_floor_blobs),
            key=lambda b: (b.evidence_kind, b.source_id, b.evidence_id),
        )
    )
    pending = PendingIntegrityTransitionV1(
        event_digest=event.event_digest,
        mission_id=event.mission_id,
        event_seq=event.seq,
        instance_sequence=modeled.instance_sequence,
        signed_decision=service._decision_signer.sign_decision(decision),  # noqa: SLF001
        decision_trust_store=service.trust_store,
        validation_policy=policy,
        revocation_floors=inputs.external_floors,
        prior_head_floor=head_floor,
        provider_evidence=provider_evidence,
        acceptance_mode=INTEGRITY_ACCEPTANCE_MODE_QUALIFIED_SIGNED_V1,
        time_bundle=tb,
        revocation_bundles=rev,
    )
    return event, pending


# ---------------------------------------------------------------------------
# Record-level: the field, the mode branch, and canonical form
# ---------------------------------------------------------------------------


def test_default_mode_is_modeled_unsigned_and_carries_no_bundles() -> None:
    service = _service(_policy())
    _event, pending = _modeled_pending(service, "default-mode")
    assert pending.acceptance_mode == INTEGRITY_ACCEPTANCE_MODE_MODELED_UNSIGNED_V1
    assert pending.time_bundle is None
    assert pending.revocation_bundles is None
    assert pending.to_body()["acceptance_mode"] == (
        INTEGRITY_ACCEPTANCE_MODE_MODELED_UNSIGNED_V1
    )


def test_acceptance_mode_changes_record_id_and_survives_round_trip() -> None:
    service = _service(_policy())
    hfx = _head_fixture()
    _event, modeled = _modeled_pending(service, "record-id")
    _event2, qualified = _qualified_pending(service, hfx, "record-id")

    assert modeled.record_id != qualified.record_id

    reloaded = PendingIntegrityTransitionV1.from_canonical_bytes(
        qualified.to_canonical_bytes()
    )
    assert reloaded.acceptance_mode == INTEGRITY_ACCEPTANCE_MODE_QUALIFIED_SIGNED_V1
    assert reloaded.time_bundle is None
    assert reloaded.revocation_bundles is None
    assert reloaded == qualified


def test_from_canonical_bytes_requires_the_acceptance_mode_field() -> None:
    from etzio.protocol import canonical_dumps, strict_loads

    service = _service(_policy())
    _event, pending = _modeled_pending(service, "missing-mode")
    body = strict_loads(pending.to_canonical_bytes())
    del body["acceptance_mode"]
    with pytest.raises(ValueError):
        PendingIntegrityTransitionV1.from_canonical_bytes(canonical_dumps(body))


def test_an_unsupported_acceptance_mode_is_refused() -> None:
    service = _service(_policy())
    _event, pending = _modeled_pending(service, "bad-mode")
    with pytest.raises(ValueError):
        replace(pending, acceptance_mode="forged_mode")


def test_a_modeled_record_may_not_carry_qualified_bundles() -> None:
    service = _service(_policy())
    hfx = _head_fixture()
    _event, pending = _modeled_pending(service, "modeled-bundles")
    tb = _decision_time_bundle(hfx)
    rev = _revocation_bundles(hfx, tb)
    with pytest.raises(ValueError):
        replace(pending, time_bundle=tb, revocation_bundles=rev)


def test_the_modeled_provider_gate_is_unchanged() -> None:
    """A modeled pending whose provider evidence is tampered is still refused."""

    from etzio.kernel.integrity_transition import ProviderEvidenceBlobV1
    from etzio.protocol import canonical_dumps

    service = _service(_policy())
    _event, pending = _modeled_pending(service, "modeled-gate")
    forged = tuple(
        ProviderEvidenceBlobV1.from_content(
            evidence_kind=blob.evidence_kind,
            source_id=blob.source_id,
            content=canonical_dumps({"forged": blob.source_id}),
        )
        for blob in pending.provider_evidence
    )
    with pytest.raises(ValueError):
        replace(pending, provider_evidence=forged)


# ---------------------------------------------------------------------------
# Store cross-check: the declared mode must match the enrolled profile
# ---------------------------------------------------------------------------


def test_a_modeled_store_refuses_a_qualified_pending(tmp_path: Path) -> None:
    hfx = _head_fixture()
    store, service = _modeled_store(tmp_path)
    with store:
        event, qualified = _qualified_pending(service, hfx, "modeled-store")
        with pytest.raises(EventStoreError) as exc:
            store.append_pending_integrity_event(
                event, expected_head=GENESIS_DIGEST, pending=qualified
            )
        assert "acceptance mode" in str(exc.value)


def test_a_qualified_store_refuses_a_modeled_pending(tmp_path: Path) -> None:
    hfx = _head_fixture()
    store, service = _qualified_store(tmp_path, hfx)
    with store:
        event, modeled = _modeled_pending(service, "qualified-store")
        with pytest.raises(EventStoreError) as exc:
            store.append_pending_integrity_event(
                event, expected_head=GENESIS_DIGEST, pending=modeled
            )
        assert "acceptance mode" in str(exc.value)


def test_a_qualified_pending_without_bundles_is_refused(tmp_path: Path) -> None:
    hfx = _head_fixture()
    store, service = _qualified_store(tmp_path, hfx)
    with store:
        event, qualified = _qualified_pending(
            service, hfx, "no-bundles", bundles=False
        )
        assert qualified.time_bundle is None
        with pytest.raises(EventStoreError) as exc:
            store.append_pending_integrity_event(
                event, expected_head=GENESIS_DIGEST, pending=qualified
            )
        assert "sealed qualified" in str(exc.value)


# ---------------------------------------------------------------------------
# The append path calls verify_qualified_revocation_evidence live
# ---------------------------------------------------------------------------


def test_append_reauthenticates_and_refuses_a_mismatched_decision(
    tmp_path: Path,
) -> None:
    """The qualified append path drives store reauthentication under the enrolled roots.

    The pending decision's time hull, evidence, views, and floors are the modeled service's,
    which the qualified bundles do not authenticate, so the freshly reauthenticated mapping
    does not match and the append is refused before any event is retained.  This proves the
    reauthentication is live, not dead code.
    """

    hfx = _head_fixture()
    store, service = _qualified_store(tmp_path, hfx)
    with store:
        event, qualified = _qualified_pending(service, hfx, "verify-live")
        with pytest.raises(EventStoreError) as exc:
            store.append_pending_integrity_event(
                event, expected_head=GENESIS_DIGEST, pending=qualified
            )
        assert "reauthentication" in str(exc.value)
        # Nothing was retained: the event never entered the store.
        assert store.load_integrity_event(event.event_digest) is None


# ---------------------------------------------------------------------------
# The positive: a coherent qualified pending appends and is retained
# ---------------------------------------------------------------------------


def test_a_coherent_qualified_pending_appends_and_is_retained(tmp_path: Path) -> None:
    """A qualified pending whose decision the enrolled bundles authenticate is accepted.

    This exercises the full step-4 positive path: the append cross-check passes, the sealed
    bundles are present, ``verify_qualified_revocation_evidence`` reauthenticates the time and
    revocation inputs under the enrolled roots and matches the decision's claim, and the event
    plus its pending dossier are atomically retained.  The qualified time and revocation
    evidence is the exact signed-package evidence; the event binding is enforced separately by
    ``authenticate_pending_integrity_transition`` (decision hull upper == event decision time).
    """

    hfx = _head_fixture()
    store, service = _aligned_qualified_store(tmp_path, hfx)
    with store:
        event, pending = _coherent_qualified_pending(service, hfx)
        retained = store.append_pending_integrity_event(
            event, expected_head=GENESIS_DIGEST, pending=pending
        )
        assert retained == event
        # The event and its exact pending dossier are retained and replay identically.
        assert store.load_integrity_event(event.event_digest) == event
        lineage = store.load_integrity_lineage(event.event_digest)
        assert lineage is not None
        assert lineage.pending == pending
        assert (
            lineage.pending.acceptance_mode
            == INTEGRITY_ACCEPTANCE_MODE_QUALIFIED_SIGNED_V1
        )


def test_a_coherent_qualified_pending_is_idempotent_on_replay(tmp_path: Path) -> None:
    """Re-submitting the exact coherent qualified pending reconciles rather than duplicating."""

    hfx = _head_fixture()
    store, service = _aligned_qualified_store(tmp_path, hfx)
    with store:
        event, pending = _coherent_qualified_pending(service, hfx)
        assert store.append_pending_integrity_event(
            event, expected_head=GENESIS_DIGEST, pending=pending
        ) == event
        # Exact re-submission reconciles to the same retained event.
        assert store.append_pending_integrity_event(
            event, expected_head=GENESIS_DIGEST, pending=pending
        ) == event
        lineage = store.load_integrity_lineage(event.event_digest)
        assert lineage is not None and lineage.pending == pending
