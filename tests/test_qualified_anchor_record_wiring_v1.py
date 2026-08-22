"""Record wiring for qualified signed anchor evidence (ADR-0019 step 3).

``CheckpointCandidateRecordV1`` now carries an ``acceptance_mode`` and, in qualified mode,
transient sealed anchor/time bundles.  The store's checkpoint-retention path cross-checks the
declared mode against the enrolled acceptance profile and, in qualified mode, reauthenticates
the anchor evidence under the enrolled roots before persisting.

Boundary: these prove the field, the mode-branching record gate, the store cross-check, the
qualified bundle-presence gate, and that the retention path calls
``verify_qualified_anchor_evidence`` live and refuses non-authenticating evidence.  A fully
coherent qualified lineage whose checkpoint statement the qualified bundle authenticates is
produced by the later qualified-mode modeled service (ADR-0019 step 4+); the positive
store-side acceptance primitive itself is proved in ``test_qualified_anchor_consumption_v1``.
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
from test_qualified_anchor_consumption_v1 import (
    _anchor_bundle,
    _head_fixture,
    _time_bundle,
)

from etzio.kernel.integrity_transition import (
    INTEGRITY_ACCEPTANCE_MODE_MODELED_UNSIGNED_V1,
    INTEGRITY_ACCEPTANCE_MODE_QUALIFIED_SIGNED_V1,
    CheckpointCandidateRecordV1,
)
from etzio.kernel.store import EventStoreError, SQLiteEventStore

# ---------------------------------------------------------------------------
# Lineage builders
# ---------------------------------------------------------------------------


def _modeled_store(tmp_path: Path, name: str = "state"):
    policy = _policy()
    store = SQLiteEventStore(_state_path(tmp_path, name))
    service = _enroll(store, policy)
    return store, service


def _qualified_store(tmp_path: Path, hfx, name: str = "state"):
    policy = _policy()
    store = SQLiteEventStore(_state_path(tmp_path, name))
    service = _enroll(store, policy)
    store.enroll_qualified_acceptance(
        qualified_time_profile=hfx.time_fixture.profile,
        qualified_head_profile=hfx.profile,
    )
    return store, service


def _drive_to_anchor(store, service, label: str):
    """Retain a modeled pending + anchor lineage; return (pending, anchor).

    Pending/anchor retention does not yet cross-check the acceptance mode (ADR-0019 steps
    4-5), so a modeled anchor lineage is legitimately retained on a qualified store here.
    """

    event = _refusal_event(label)
    pending = _append_pending(store, event, service)
    anchor = service.prepare_anchor_statement(pending)
    assert store.retain_integrity_anchor_statement(anchor) == anchor
    return pending, anchor


def _modeled_candidate(service, pending, anchor):
    receipts = service.register_anchor_statement(anchor)
    return service.prepare_checkpoint_candidate(
        pending,
        anchor,
        anchor_receipts=receipts,
    )


def _qualified_candidate(service, pending, anchor, ab, tb):
    """A checkpoint candidate in qualified mode carrying the sealed qualified bundles.

    The signed checkpoint is consistent with the modeled lineage; the record is flipped into
    qualified mode and the sealed anchor/time bundles are attached so the store reauthenticates
    them under the enrolled roots.  A fully coherent lineage whose checkpoint statement the
    bundle authenticates is the later qualified-mode service (ADR-0019 step 4+); here the
    bundle authenticates to a different statement, which is exactly what the store must catch.
    """

    base = _modeled_candidate(service, pending, anchor)
    return replace(
        base,
        acceptance_mode=INTEGRITY_ACCEPTANCE_MODE_QUALIFIED_SIGNED_V1,
        anchor_bundle=ab,
        time_bundle=tb,
    )


# ---------------------------------------------------------------------------
# Record-level: the field, the mode branch, and canonical form
# ---------------------------------------------------------------------------


def test_default_mode_is_modeled_unsigned_and_carries_no_bundles(tmp_path: Path) -> None:
    store, service = _modeled_store(tmp_path)
    with store:
        pending, anchor = _drive_to_anchor(store, service, "default-mode")
        candidate = _modeled_candidate(service, pending, anchor)
    assert candidate.acceptance_mode == INTEGRITY_ACCEPTANCE_MODE_MODELED_UNSIGNED_V1
    assert candidate.anchor_bundle is None
    assert candidate.time_bundle is None
    assert candidate.to_body()["acceptance_mode"] == (
        INTEGRITY_ACCEPTANCE_MODE_MODELED_UNSIGNED_V1
    )


def test_acceptance_mode_changes_record_id_and_survives_round_trip(tmp_path: Path) -> None:
    hfx = _head_fixture()
    tb = _time_bundle(hfx)
    ab = _anchor_bundle(hfx, tb)
    store, service = _qualified_store(tmp_path, hfx)
    with store:
        pending, anchor = _drive_to_anchor(store, service, "record-id")
        modeled = _modeled_candidate(service, pending, anchor)
        qualified = _qualified_candidate(service, pending, anchor, ab, tb)

    # The mode is part of the content identity.
    assert modeled.record_id != qualified.record_id

    # Transient bundles never enter canonical bytes; a reload drops them but the record still
    # equals its freshly submitted original (bundles are excluded from equality).
    reloaded = CheckpointCandidateRecordV1.from_canonical_bytes(
        qualified.to_canonical_bytes()
    )
    assert reloaded.acceptance_mode == INTEGRITY_ACCEPTANCE_MODE_QUALIFIED_SIGNED_V1
    assert reloaded.anchor_bundle is None
    assert reloaded.time_bundle is None
    assert reloaded == qualified


def test_from_canonical_bytes_requires_the_acceptance_mode_field(tmp_path: Path) -> None:
    from etzio.protocol import canonical_dumps, strict_loads

    store, service = _modeled_store(tmp_path)
    with store:
        pending, anchor = _drive_to_anchor(store, service, "missing-mode")
        candidate = _modeled_candidate(service, pending, anchor)
    body = strict_loads(candidate.to_canonical_bytes())
    del body["acceptance_mode"]
    with pytest.raises(ValueError):
        CheckpointCandidateRecordV1.from_canonical_bytes(canonical_dumps(body))


def test_an_unsupported_acceptance_mode_is_refused(tmp_path: Path) -> None:
    store, service = _modeled_store(tmp_path)
    with store:
        pending, anchor = _drive_to_anchor(store, service, "bad-mode")
        candidate = _modeled_candidate(service, pending, anchor)
    with pytest.raises(ValueError):
        replace(candidate, acceptance_mode="forged_mode")


def test_a_modeled_record_may_not_carry_qualified_bundles(tmp_path: Path) -> None:
    hfx = _head_fixture()
    tb = _time_bundle(hfx)
    ab = _anchor_bundle(hfx, tb)
    store, service = _qualified_store(tmp_path, hfx)
    with store:
        pending, anchor = _drive_to_anchor(store, service, "modeled-bundles")
        modeled = _modeled_candidate(service, pending, anchor)
    with pytest.raises(ValueError):
        replace(modeled, anchor_bundle=ab, time_bundle=tb)


def test_the_modeled_provider_gate_is_unchanged(tmp_path: Path) -> None:
    """A modeled candidate whose provider evidence is tampered is still refused."""

    from etzio.kernel.integrity_transition import ProviderEvidenceBlobV1
    from etzio.protocol import canonical_dumps

    store, service = _modeled_store(tmp_path)
    with store:
        pending, anchor = _drive_to_anchor(store, service, "modeled-gate")
        candidate = _modeled_candidate(service, pending, anchor)
    forged = tuple(
        ProviderEvidenceBlobV1.from_content(
            evidence_kind=blob.evidence_kind,
            source_id=blob.source_id,
            content=canonical_dumps({"forged": blob.source_id}),
        )
        for blob in candidate.provider_evidence
    )
    with pytest.raises(ValueError):
        replace(candidate, provider_evidence=forged)


# ---------------------------------------------------------------------------
# Store cross-check: the declared mode must match the enrolled profile
# ---------------------------------------------------------------------------


def test_a_modeled_store_refuses_a_qualified_record(tmp_path: Path) -> None:
    hfx = _head_fixture()
    tb = _time_bundle(hfx)
    ab = _anchor_bundle(hfx, tb)
    q_store, q_service = _qualified_store(tmp_path, hfx, name="qualified")
    with q_store:
        pending, anchor = _drive_to_anchor(q_store, q_service, "xstore")
        qualified = _qualified_candidate(q_service, pending, anchor, ab, tb)

    m_store, _ = _modeled_store(tmp_path, name="modeled")
    with m_store:
        with pytest.raises(EventStoreError) as exc:
            m_store.retain_integrity_checkpoint_candidate(qualified)
        assert "acceptance mode" in str(exc.value)


def test_a_qualified_store_refuses_a_modeled_record(tmp_path: Path) -> None:
    hfx = _head_fixture()
    m_store, m_service = _modeled_store(tmp_path, name="modeled")
    with m_store:
        pending, anchor = _drive_to_anchor(m_store, m_service, "xstore2")
        modeled = _modeled_candidate(m_service, pending, anchor)

    q_store, _ = _qualified_store(tmp_path, hfx, name="qualified")
    with q_store:
        with pytest.raises(EventStoreError) as exc:
            q_store.retain_integrity_checkpoint_candidate(modeled)
        assert "acceptance mode" in str(exc.value)


def test_a_qualified_record_without_bundles_is_refused(tmp_path: Path) -> None:
    hfx = _head_fixture()
    tb = _time_bundle(hfx)
    ab = _anchor_bundle(hfx, tb)
    store, service = _qualified_store(tmp_path, hfx)
    with store:
        pending, anchor = _drive_to_anchor(store, service, "no-bundles")
        qualified = _qualified_candidate(service, pending, anchor, ab, tb)
        # A record reloaded from bytes carries no transient bundles.
        stripped = CheckpointCandidateRecordV1.from_canonical_bytes(
            qualified.to_canonical_bytes()
        )
        assert stripped.anchor_bundle is None
        with pytest.raises(EventStoreError) as exc:
            store.retain_integrity_checkpoint_candidate(stripped)
        assert "sealed qualified" in str(exc.value)


# ---------------------------------------------------------------------------
# The retention path calls verify_qualified_anchor_evidence live
# ---------------------------------------------------------------------------


def test_retention_reauthenticates_and_refuses_a_mismatched_statement(
    tmp_path: Path,
) -> None:
    """The qualified retention path drives store reauthentication under the enrolled roots.

    The checkpoint's claimed anchor statement is the modeled lineage's statement, which the
    qualified bundle does not authenticate, so the freshly reauthenticated statement does not
    match and retention is refused.  This proves the verification is live, not dead code.
    """

    hfx = _head_fixture()
    tb = _time_bundle(hfx)
    ab = _anchor_bundle(hfx, tb)
    store, service = _qualified_store(tmp_path, hfx)
    with store:
        pending, anchor = _drive_to_anchor(store, service, "verify-live")
        qualified = _qualified_candidate(service, pending, anchor, ab, tb)
        # Sanity: the modeled lineage statement is not the qualified bundle's statement.
        assert qualified.checkpoint.anchor_statement_id != ab.anchor_statement_id
        with pytest.raises(EventStoreError) as exc:
            store.retain_integrity_checkpoint_candidate(qualified)
        assert "reauthentication" in str(exc.value)
        # Nothing was persisted: the lineage remains at the anchor phase.
        lineage = store.load_integrity_lineage(pending.event_digest)
        assert lineage is not None
        assert lineage.checkpoint_candidate is None
