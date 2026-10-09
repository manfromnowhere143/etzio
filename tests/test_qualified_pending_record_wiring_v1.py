"""Record wiring for qualified signed revocation evidence (ADR-0019).

Pending records declare the enrolled acceptance mode. Store admission reconstructs and
reauthenticates canonical provider packages inside its writer transaction. Optional transient
time and revocation bundles must authenticate and agree with those bytes. These tests cover
record shape, mode separation, unsigned-package refusal and a coherent qualified pending
that appends and retries idempotently. The complete lifecycle and cold-replay controls live
in test_qualified_fixture_lifecycle_v1 and test_qualified_cold_replay_v1.
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

from etzio.kernel.events_v1 import GENESIS_DIGEST, EventV1
from etzio.kernel.integrity_adapters_v1 import (
    RevocationRequestV1,
    TrustedTimeRequestV1,
    qualify_revocation_bundle_v1,
    qualify_time_bundle_v1,
)
from etzio.kernel.integrity_transition import (
    INTEGRITY_ACCEPTANCE_MODE_MODELED_UNSIGNED_V1,
    INTEGRITY_ACCEPTANCE_MODE_QUALIFIED_SIGNED_V1,
    PendingIntegrityTransitionV1,
    RepositoryOwnedDeterministicModeledIntegrityServiceV1,
)
from etzio.kernel.qualified_evidence_v1 import qualified_decision_time_imprint_v1
from etzio.kernel.store import EventStoreError, SQLiteEventStore


def _digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def _nonce(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Coherent qualified time + revocation bundles from the enrolled fixture roots
# ---------------------------------------------------------------------------


def _decision_time_bundle(hfx, decision=None):
    tfx = hfx.time_fixture
    vector = tfx.vector
    requests = {
        adapter.source_id: TrustedTimeRequestV1.issue(
            profile=tfx.profile,
            source_id=adapter.source_id,
            purpose="decision",
            mission_id=vector.mission_id if decision is None else decision.mission_id,
            authority_id=vector.authority_id if decision is None else decision.authority_id,
            target_id=vector.target_id if decision is None else decision.target_id,
            event_digest=vector.event_digest if decision is None else decision.proposed_event_digest,
            transition_intent_id=vector.transition_intent_id if decision is None else decision.transition_intent_id,
            imprint_id=(
                _digest("pending-decision-imprint") if decision is None
                else qualified_decision_time_imprint_v1(decision)
            ),
            request_nonce=vector.request_nonce if decision is None else decision.request_nonce,
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
    return _aligned_qualified_store(tmp_path, hfx, name)



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
    """A complete qualified pending, including its signed predecessor catalog."""
    from etzio.kernel.qualified_fixture_service_v1 import RepositoryOwnedQualifiedFixtureIntegrityServiceV1

    vector = hfx.time_fixture.vector
    event = EventV1.create(
        mission_id=vector.mission_id, seq=0, kind="mission_admission_refused", unit="AQUILA",
        authority_id=vector.authority_id, target_id=vector.target_id,
        decision_time=max(adapter.time_upper_bound for adapter in hfx.time_fixture.time_adapters),
        payload={"reason_code": "authority_expired", "stage": "admission"}, prev_digest=GENESIS_DIGEST,
    )
    qualified = RepositoryOwnedQualifiedFixtureIntegrityServiceV1(core=service, fixture=hfx)
    return event, qualified.prepare_pending_transition(event, previous_global=None, previous_mission=None)



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


def test_unsigned_pending_bytes_are_refused_even_without_transient_bundles(tmp_path: Path) -> None:
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
        assert "reauthentication" in str(exc.value)


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
