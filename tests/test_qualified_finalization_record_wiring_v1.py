"""Record wiring for qualified signed head-floor evidence (ADR-0019 step 5).

``FinalizedIntegrityTransitionV1`` now carries an ``acceptance_mode`` and, in qualified mode,
transient sealed head-catalog and time bundles.  ``finalize_integrity_transition`` cross-checks
the declared mode against the enrolled acceptance profile and, in qualified mode,
reauthenticates the finalization's external head floor under the enrolled roots via
``store.verify_qualified_head_floor_evidence`` before committing finality.

This file proves the record gates (mode field, mode branch, canonical round-trip dropping the
transient bundles, modeled gate unchanged) and the store mode cross-check in both directions.
The end-to-end reauthentication (positive is deferred to the facade-driven step-6 service
because the fixed fixture catalog head cannot be scoped to a produced checkpoint; the live
refusal is proved on the coherent lineage in ``test_qualified_finality_lineage_v1``).
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from test_integrity_store_v2 import (
    _append_pending,
    _enroll,
    _policy,
    _refusal_event,
    _state_path,
)
from test_qualified_head_floor_acceptance_v1 import _built

from etzio.kernel.integrity_transition import (
    INTEGRITY_ACCEPTANCE_MODE_MODELED_UNSIGNED_V1,
    INTEGRITY_ACCEPTANCE_MODE_QUALIFIED_SIGNED_V1,
    FinalizedIntegrityTransitionV1,
)
from etzio.kernel.store import EventStoreError, SQLiteEventStore


def _bundles():
    """A fixture head-catalog bundle and its checkpoint-purpose time bundle."""

    _fixture, time_bundle, catalog_bundle = _built()
    return time_bundle, catalog_bundle


def _modeled_lineage(store, service, label: str):
    """Drive a modeled lineage to the observed floor; return (event, modeled finalization)."""

    event = _refusal_event(label)
    pending = _append_pending(store, event, service)
    anchor = service.prepare_anchor_statement(pending)
    assert store.retain_integrity_anchor_statement(anchor) == anchor
    receipts = service.register_anchor_statement(anchor)
    candidate = service.prepare_checkpoint_candidate(
        pending, anchor, anchor_receipts=receipts
    )
    assert store.retain_integrity_checkpoint_candidate(candidate) == candidate
    service.publish_checkpoint(candidate)
    floor, floor_evidence = service.observe_current_floor(pending, candidate)
    final = FinalizedIntegrityTransitionV1(
        pending_record_id=pending.record_id,
        checkpoint_candidate_record_id=candidate.record_id,
        event_digest=event.event_digest,
        external_head_floor=floor,
        provider_evidence=floor_evidence,
    )
    return event, final


def _modeled_store(tmp_path: Path, name: str = "state"):
    store = SQLiteEventStore(_state_path(tmp_path, name))
    service = _enroll(store, _policy())
    return store, service


def _qualified_store(tmp_path: Path, name: str = "state"):
    store, service = _modeled_store(tmp_path, name)
    fixture = _built()[0]
    store.enroll_qualified_acceptance(
        qualified_time_profile=fixture.time_fixture.profile,
        qualified_head_profile=fixture.profile,
    )
    return store, service


# ---------------------------------------------------------------------------
# Record-level: the field, the mode branch, and canonical form
# ---------------------------------------------------------------------------


def test_default_mode_is_modeled_unsigned_and_carries_no_bundles(tmp_path: Path) -> None:
    store, service = _modeled_store(tmp_path)
    with store:
        _event, final = _modeled_lineage(store, service, "default-mode")
    assert final.acceptance_mode == INTEGRITY_ACCEPTANCE_MODE_MODELED_UNSIGNED_V1
    assert final.catalog_bundle is None
    assert final.time_bundle is None
    assert final.to_body()["acceptance_mode"] == (
        INTEGRITY_ACCEPTANCE_MODE_MODELED_UNSIGNED_V1
    )


def test_acceptance_mode_changes_record_id_and_survives_round_trip(tmp_path: Path) -> None:
    tb, cb = _bundles()
    store, service = _modeled_store(tmp_path)
    with store:
        _event, modeled = _modeled_lineage(store, service, "record-id")
    qualified = replace(
        modeled,
        acceptance_mode=INTEGRITY_ACCEPTANCE_MODE_QUALIFIED_SIGNED_V1,
        catalog_bundle=cb,
        time_bundle=tb,
    )
    assert modeled.record_id != qualified.record_id
    reloaded = FinalizedIntegrityTransitionV1.from_canonical_bytes(
        qualified.to_canonical_bytes()
    )
    assert reloaded.acceptance_mode == INTEGRITY_ACCEPTANCE_MODE_QUALIFIED_SIGNED_V1
    assert reloaded.catalog_bundle is None
    assert reloaded.time_bundle is None
    assert reloaded == qualified


def test_from_canonical_bytes_requires_the_acceptance_mode_field(tmp_path: Path) -> None:
    from etzio.protocol import canonical_dumps, strict_loads

    store, service = _modeled_store(tmp_path)
    with store:
        _event, modeled = _modeled_lineage(store, service, "missing-mode")
    body = strict_loads(modeled.to_canonical_bytes())
    del body["acceptance_mode"]
    with pytest.raises(ValueError):
        FinalizedIntegrityTransitionV1.from_canonical_bytes(canonical_dumps(body))


def test_an_unsupported_acceptance_mode_is_refused(tmp_path: Path) -> None:
    store, service = _modeled_store(tmp_path)
    with store:
        _event, modeled = _modeled_lineage(store, service, "bad-mode")
    with pytest.raises(ValueError):
        replace(modeled, acceptance_mode="forged_mode")


def test_a_modeled_record_may_not_carry_qualified_bundles(tmp_path: Path) -> None:
    tb, cb = _bundles()
    store, service = _modeled_store(tmp_path)
    with store:
        _event, modeled = _modeled_lineage(store, service, "modeled-bundles")
    with pytest.raises(ValueError):
        replace(modeled, catalog_bundle=cb, time_bundle=tb)


def test_the_modeled_provider_gate_is_unchanged(tmp_path: Path) -> None:
    from etzio.kernel.integrity_transition import ProviderEvidenceBlobV1
    from etzio.protocol import canonical_dumps

    store, service = _modeled_store(tmp_path)
    with store:
        _event, modeled = _modeled_lineage(store, service, "modeled-gate")
    forged = tuple(
        ProviderEvidenceBlobV1.from_content(
            evidence_kind=blob.evidence_kind,
            source_id=blob.source_id,
            content=canonical_dumps({"forged": blob.source_id}),
        )
        for blob in modeled.provider_evidence
    )
    with pytest.raises(ValueError):
        replace(modeled, provider_evidence=forged)


# ---------------------------------------------------------------------------
# Store cross-check: the declared mode must match the enrolled profile
# ---------------------------------------------------------------------------


def test_a_modeled_store_refuses_a_qualified_finalization(tmp_path: Path) -> None:
    tb, cb = _bundles()
    store, service = _modeled_store(tmp_path)
    with store:
        _event, modeled = _modeled_lineage(store, service, "xstore")
        qualified = replace(
            modeled,
            acceptance_mode=INTEGRITY_ACCEPTANCE_MODE_QUALIFIED_SIGNED_V1,
            catalog_bundle=cb,
            time_bundle=tb,
        )
        with pytest.raises(EventStoreError) as exc:
            store.finalize_integrity_transition(qualified)
        assert "acceptance mode" in str(exc.value)


def test_a_qualified_store_refuses_a_modeled_finalization(tmp_path: Path) -> None:
    modeled_store, modeled_service = _modeled_store(tmp_path, name="modeled")
    with modeled_store:
        _event, modeled = _modeled_lineage(modeled_store, modeled_service, "xstore2")
    q_store, _service = _qualified_store(tmp_path, name="qualified")
    with q_store:
        with pytest.raises(EventStoreError) as exc:
            q_store.finalize_integrity_transition(modeled)
        assert "acceptance mode" in str(exc.value)
