"""Replay a research artifact, without claiming conformance of an Etzio provider."""

from __future__ import annotations

import json
import math
from pathlib import Path

from scripts.replay_recovery_fence_experiment import Policy, chains, replay, schedules, simulate


def test_interleaving_enumerator_has_exact_finite_coverage() -> None:
    for reads in (0, 1, 3):
        left, right = chains(Policy(reads))
        actual = list(schedules(left, right))
        assert len(actual) == len(set(actual)) == math.comb(len(left) + len(right), len(right))
        for schedule in actual:
            assert tuple(event for event in schedule if event in left) == left
            assert tuple(event for event in schedule if event in right) == right


def test_fresh_read_before_commit_does_not_fence_the_commit() -> None:
    schedule = (
        "old_publish", "old_reply", "read_0", "fence", "recover_read", "new_publish",
        "old_local_commit", "old_effect",
    )
    result = simulate(Policy(1), schedule)
    assert result["ledger"] == ["old", "new"]
    assert result["recovery_cut"] == ["old"]
    assert result["violations"] == ["old_effect_after_fence", "old_local_commit_after_fence"]
    assert all(step["accepted"] for step in result["steps"])


def test_local_commit_fence_does_not_fence_a_later_effect() -> None:
    schedule = (
        "old_publish", "old_reply", "old_local_commit", "fence", "recover_read",
        "new_publish", "old_effect",
    )
    result = simulate(Policy(0, local_atomic_fence=True), schedule)
    assert result["old_local_committed"] is True
    assert result["violations"] == ["old_effect_after_fence"]
    guarded = simulate(Policy(0, local_atomic_fence=True, effect_atomic_fence=True), schedule)
    assert guarded["old_local_committed"] is True
    assert guarded["old_effect"] is False
    assert guarded["violations"] == []


def test_retained_finite_report_replays_exactly() -> None:
    path = Path(__file__).resolve().parents[1] / "docs/evidence/recovery-fence-model-2026-10-12.json"
    assert replay() == json.loads(path.read_text(encoding="utf-8"))
