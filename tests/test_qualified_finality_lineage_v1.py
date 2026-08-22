"""End-to-end coherent qualified finality lineage (ADR-0019 steps 3-4 positives).

Builds a fully coherent qualified lineage on a qualified store -- a qualified pending whose
decision the enrolled bundles authenticate, a modeled anchor statement, and a qualified
checkpoint candidate whose anchor evidence the enrolled roots reauthenticate -- and proves the
store's checkpoint-retention positive that ADR-0019 step 3 had to defer (the qualified-store
checkpoint path could not be exercised until step 4 made the pending phase enforce
qualified-mode consistency, so a coherent qualified pending is the prerequisite).

The qualified anchor bundle is scoped to the modeled anchor's derived statement identity: the
repository-owned anchor adapters build their Merkle leaves dynamically and recompute a genuine
RFC 9162 inclusion proof, so the bundle authenticates the exact leaf the lineage claims. This
is the construction the step-6 qualified-mode service will own; here it is proved end to end.
"""

from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path

import pytest
from test_qualified_anchor_consumption_v1 import _head_fixture
from test_qualified_pending_record_wiring_v1 import (
    _aligned_qualified_store,
    _coherent_qualified_pending,
)

from etzio.kernel.head_authority_adapters_v1 import (
    HeadAnchorRequestV1,
    qualify_anchor_bundle_v1,
)
from etzio.kernel.integrity_adapters_v1 import (
    TrustedTimeRequestV1,
    qualify_time_bundle_v1,
)
from etzio.kernel.integrity_transition import (
    INTEGRITY_ACCEPTANCE_MODE_QUALIFIED_SIGNED_V1,
    CheckpointCandidateRecordV1,
)
from etzio.kernel.store import EventStoreError
from etzio.protocol import content_id


def _checkpoint_time_bundle(hfx, pending):
    """A checkpoint-purpose qualified time bundle scoped to the pending decision."""

    tfx = hfx.time_fixture
    decision = pending.decision
    requests = {
        adapter.source_id: TrustedTimeRequestV1.issue(
            profile=tfx.profile,
            source_id=adapter.source_id,
            purpose="checkpoint",
            mission_id=pending.mission_id,
            authority_id=decision.authority_id,
            target_id=decision.target_id,
            event_digest=pending.event_digest,
            transition_intent_id=decision.transition_intent_id,
            imprint_id=content_id(
                "qualified_finality_lineage_checkpoint_imprint",
                {"event_digest": pending.event_digest},
            ),
            request_nonce=decision.request_nonce,
        )
        for adapter in tfx.time_adapters
    }
    return qualify_time_bundle_v1(
        profile=tfx.profile,
        requests=requests,
        signed_evidence={
            a.source_id: a.acquire(requests[a.source_id]) for a in tfx.time_adapters
        },
    )


def _scoped_anchor_bundle(hfx, checkpoint_tb, pending, anchor):
    """A qualified anchor bundle for the modeled anchor's exact statement identity."""

    decision = pending.decision
    requests = {
        adapter.source_id: HeadAnchorRequestV1.issue(
            profile=hfx.profile,
            source_id=adapter.source_id,
            mission_id=pending.mission_id,
            authority_id=decision.authority_id,
            target_id=decision.target_id,
            event_digest=pending.event_digest,
            transition_intent_id=decision.transition_intent_id,
            anchor_statement_id=anchor.anchor_statement_id,
            instance_sequence=pending.instance_sequence,
            time_bundle=checkpoint_tb,
            prior_tree_size=hfx.anchor_prior_tree_size,
            request_nonce=hashlib.sha256(
                f"anchor-{anchor.anchor_statement_id}".encode()
            ).hexdigest(),
        )
        for adapter in hfx.anchor_adapters
    }
    return qualify_anchor_bundle_v1(
        profile=hfx.profile,
        time_profile=hfx.time_fixture.profile,
        time_bundle=checkpoint_tb,
        requests=requests,
        signed_evidence={
            a.source_id: a.acquire(requests[a.source_id]) for a in hfx.anchor_adapters
        },
    )


def _drive_pending_and_anchor(store, service, hfx):
    from etzio.kernel.events_v1 import GENESIS_DIGEST

    event, pending = _coherent_qualified_pending(service, hfx)
    assert (
        store.append_pending_integrity_event(
            event, expected_head=GENESIS_DIGEST, pending=pending
        )
        == event
    )
    anchor = service.prepare_anchor_statement(pending)
    assert store.retain_integrity_anchor_statement(anchor) == anchor
    return event, pending, anchor


def _qualified_checkpoint(service, hfx, pending, anchor, checkpoint_tb, anchor_bundle):
    return service.prepare_checkpoint_candidate(
        pending,
        anchor,
        anchor_receipts=anchor_bundle.evidence_blobs,
        acceptance_mode=INTEGRITY_ACCEPTANCE_MODE_QUALIFIED_SIGNED_V1,
        anchor_bundle=anchor_bundle,
        time_bundle=checkpoint_tb,
    )


# ---------------------------------------------------------------------------
# The positive: a coherent qualified checkpoint is retained
# ---------------------------------------------------------------------------


def test_a_coherent_qualified_checkpoint_is_retained(tmp_path: Path) -> None:
    hfx = _head_fixture()
    store, service = _aligned_qualified_store(tmp_path, hfx)
    with store:
        _event, pending, anchor = _drive_pending_and_anchor(store, service, hfx)
        checkpoint_tb = _checkpoint_time_bundle(hfx, pending)
        anchor_bundle = _scoped_anchor_bundle(hfx, checkpoint_tb, pending, anchor)
        candidate = _qualified_checkpoint(
            service, hfx, pending, anchor, checkpoint_tb, anchor_bundle
        )
        # Sanity: the checkpoint claims the exact statement the qualified bundle authenticates.
        assert candidate.checkpoint.anchor_statement_id == anchor_bundle.anchor_statement_id
        retained = store.retain_integrity_checkpoint_candidate(candidate)
        assert retained == candidate
        lineage = store.load_integrity_lineage(pending.event_digest)
        assert lineage is not None
        assert lineage.checkpoint_candidate == candidate
        assert (
            lineage.checkpoint_candidate.acceptance_mode
            == INTEGRITY_ACCEPTANCE_MODE_QUALIFIED_SIGNED_V1
        )


def test_qualified_checkpoint_replay_is_idempotent(tmp_path: Path) -> None:
    hfx = _head_fixture()
    store, service = _aligned_qualified_store(tmp_path, hfx)
    with store:
        _event, pending, anchor = _drive_pending_and_anchor(store, service, hfx)
        checkpoint_tb = _checkpoint_time_bundle(hfx, pending)
        anchor_bundle = _scoped_anchor_bundle(hfx, checkpoint_tb, pending, anchor)
        candidate = _qualified_checkpoint(
            service, hfx, pending, anchor, checkpoint_tb, anchor_bundle
        )
        assert store.retain_integrity_checkpoint_candidate(candidate) == candidate
        # A record reloaded from bytes (no transient bundles) reconciles idempotently,
        # because reauthentication already happened at first retention.
        reloaded = CheckpointCandidateRecordV1.from_canonical_bytes(
            candidate.to_canonical_bytes()
        )
        assert store.retain_integrity_checkpoint_candidate(reloaded) == candidate


# ---------------------------------------------------------------------------
# The deferred negatives, now on a real qualified lineage
# ---------------------------------------------------------------------------


def test_a_qualified_checkpoint_without_bundles_is_refused(tmp_path: Path) -> None:
    hfx = _head_fixture()
    store, service = _aligned_qualified_store(tmp_path, hfx)
    with store:
        _event, pending, anchor = _drive_pending_and_anchor(store, service, hfx)
        checkpoint_tb = _checkpoint_time_bundle(hfx, pending)
        anchor_bundle = _scoped_anchor_bundle(hfx, checkpoint_tb, pending, anchor)
        candidate = _qualified_checkpoint(
            service, hfx, pending, anchor, checkpoint_tb, anchor_bundle
        )
        stripped = CheckpointCandidateRecordV1.from_canonical_bytes(
            candidate.to_canonical_bytes()
        )
        assert stripped.anchor_bundle is None
        with pytest.raises(EventStoreError) as exc:
            store.retain_integrity_checkpoint_candidate(stripped)
        assert "sealed qualified" in str(exc.value)


def test_checkpoint_retention_refuses_a_foreign_anchor_bundle(tmp_path: Path) -> None:
    """A checkpoint carrying a bundle for a different statement fails reauthentication."""

    hfx = _head_fixture()
    other = _head_fixture(seed=b"a-different-anchor-lineage-corpus")
    store, service = _aligned_qualified_store(tmp_path, hfx)
    with store:
        _event, pending, anchor = _drive_pending_and_anchor(store, service, hfx)
        checkpoint_tb = _checkpoint_time_bundle(hfx, pending)
        anchor_bundle = _scoped_anchor_bundle(hfx, checkpoint_tb, pending, anchor)
        candidate = _qualified_checkpoint(
            service, hfx, pending, anchor, checkpoint_tb, anchor_bundle
        )
        # Swap in a bundle from foreign roots for the same claimed checkpoint.
        foreign_tb = _checkpoint_time_bundle(other, pending)
        foreign_ab = _scoped_anchor_bundle(other, foreign_tb, pending, anchor)
        forged = replace(candidate, anchor_bundle=foreign_ab, time_bundle=foreign_tb)
        with pytest.raises(EventStoreError) as exc:
            store.retain_integrity_checkpoint_candidate(forged)
        assert getattr(exc.value, "args", ["", ""]) and "reauthentication" in str(exc.value)
        lineage = store.load_integrity_lineage(pending.event_digest)
        assert lineage is not None and lineage.checkpoint_candidate is None
