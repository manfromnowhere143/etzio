"""Bounded reconstruction and registry checks for modeled integrity records."""

from __future__ import annotations

import copy
from unittest.mock import patch

import pytest

from etzio.kernel.integrity_transition import (
    AnchorStatementRecordV1,
    CheckpointCandidateRecordV1,
    FinalizedIntegrityTransitionV1,
    IntegrityFinalityBlockedError,
    IntegrityLineageV1,
    IntegrityTransitionError,
    PendingIntegrityTransitionV1,
)
from etzio.protocol import canonical_dumps, strict_loads
from tests.test_integrity_transition_adversarial_v1 import (
    _event,
    _prepare_candidate,
    _service,
)


def test_lineage_snapshot_avoids_reparsing_already_validated_record_wires() -> None:
    """Field snapshots retain anti-aliasing without recursive JSON round-trips."""

    service = _service(seed=b"integrity-lineage-reconstruction-v1")
    pending, anchor, candidate = _prepare_candidate(
        service,
        _event("bounded-lineage-reconstruction"),
    )
    service.publish_checkpoint(candidate)
    floor, evidence = service.observe_current_floor(pending, candidate)
    finalization = FinalizedIntegrityTransitionV1(
        pending_record_id=pending.record_id,
        checkpoint_candidate_record_id=candidate.record_id,
        event_digest=pending.event_digest,
        external_head_floor=floor,
        provider_evidence=evidence,
    )

    with (
        patch.object(
            PendingIntegrityTransitionV1,
            "to_canonical_bytes",
            side_effect=AssertionError("pending wire was reparsed"),
        ),
        patch.object(
            AnchorStatementRecordV1,
            "to_canonical_bytes",
            side_effect=AssertionError("anchor wire was reparsed"),
        ),
        patch.object(
            CheckpointCandidateRecordV1,
            "to_canonical_bytes",
            side_effect=AssertionError("checkpoint wire was reparsed"),
        ),
        patch.object(
            FinalizedIntegrityTransitionV1,
            "to_canonical_bytes",
            side_effect=AssertionError("finalization wire was reparsed"),
        ),
    ):
        lineage = IntegrityLineageV1(
            pending=pending,
            anchor_statement=anchor,
            checkpoint_candidate=candidate,
            finalization=finalization,
        )

    assert lineage.pending is not pending
    assert lineage.anchor_statement is not anchor
    assert lineage.checkpoint_candidate is not candidate
    assert lineage.finalization is not finalization
    assert lineage.pending.decision_trust_store is not pending.decision_trust_store
    assert lineage.checkpoint_candidate.checkpoint_trust_store is not candidate.checkpoint_trust_store


def test_anchor_registry_reserves_one_exact_global_sequence_statement() -> None:
    service = _service(seed=b"integrity-anchor-primary-v1")
    pending = service.prepare_pending_transition(
        _event("anchor-primary"),
        previous_global=None,
        previous_mission=None,
    )
    anchor = service.prepare_anchor_statement(pending)
    service.register_anchor_statement(anchor)

    isolated_branch = _service(seed=b"integrity-anchor-competing-v1")
    competing_pending = isolated_branch.prepare_pending_transition(
        _event("anchor-competing"),
        previous_global=None,
        previous_mission=None,
    )
    competing_anchor = isolated_branch.prepare_anchor_statement(competing_pending)
    assert competing_anchor.registration_body["instance_sequence"] == anchor.registration_body["instance_sequence"] == 0
    assert competing_anchor.anchor_statement_id != anchor.anchor_statement_id

    with pytest.raises(IntegrityFinalityBlockedError) as caught:
        service.register_anchor_statement(competing_anchor)
    assert caught.value.reason_code == "modeled_anchor_sequence_conflict"


@pytest.mark.parametrize(
    ("field", "reason_code"),
    (
        ("decision_trust_store", "invalid_integrity_trust_store"),
        ("validation_policy", "invalid_integrity_validation_policy"),
        ("revocation_floors", "invalid_revocation_floor"),
        ("prior_head_floor", "invalid_head_checkpoint_floor"),
    ),
)
def test_core_reconstruction_failures_keep_transition_reason_codes(
    field: str,
    reason_code: str,
) -> None:
    service = _service(seed=b"integrity-core-reconstruction-v1")
    pending = service.prepare_pending_transition(
        _event("core-reconstruction"),
        previous_global=None,
        previous_mission=None,
    )
    body = strict_loads(pending.to_canonical_bytes())
    assert type(body) is dict
    malformed = copy.deepcopy(body)
    nested = malformed[field]
    if field == "revocation_floors":
        assert type(nested) is list and nested
        nested = nested[0]
    assert type(nested) is dict
    nested["unknown_field"] = "rejected"

    with pytest.raises(IntegrityTransitionError) as caught:
        PendingIntegrityTransitionV1.from_canonical_bytes(canonical_dumps(malformed))
    assert caught.value.reason_code == reason_code
