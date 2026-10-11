"""Scientific controls for the owned finite experiment; no target exploitation."""

from __future__ import annotations

import itertools
import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.replay_effect_evidence_experiment import observed_effect, replay, transition


def test_complete_state_space_and_independent_permission_table():
    report = replay()
    assert report["policy_count"] == 16
    assert report["transition_count"] == 256
    assert report["all_permission_table_crosschecks_agree"] is True
    for row in report["policies"]:
        assert {(t["actor"], t["route"], t["before"], t["requested"]) for t in row["transitions"]} == set(
            itertools.product(range(2), repeat=4)
        )
    assert report["full_specification_policies"] == [3]


def test_naive_patch_differential_accepts_seven_counterexamples():
    report = replay()
    assert report["single_differential_accepted_policies"] == [0, 1, 2, 3, 8, 9, 10, 11]
    assert report["false_acceptances_against_full_specification"] == [0, 1, 2, 8, 9, 10, 11]
    assert report["security_preserving_but_nonfunctional_acceptances"] == [0, 1, 2]
    assert report["other_route_security_failure_acceptances"] == [8, 9, 10, 11]


def test_disabling_everything_and_correct_patch_have_same_attack_differential():
    assert transition(15, 1, 0, 0, 1) == 1
    assert transition(0, 1, 0, 0, 1) == transition(3, 1, 0, 0, 1) == 0
    assert transition(0, 0, 0, 0, 1) == 0
    assert transition(3, 0, 0, 0, 1) == 1


def test_distinct_defects_collapse_to_same_effect_and_patch():
    assert [transition(15, 1, route, 0, 1) for route in range(2)] == [1, 1]
    assert transition(7, 1, 0, 0, 1) == transition(11, 1, 1, 0, 1) == 1
    assert transition(7, 1, 1, 0, 1) == transition(11, 1, 0, 0, 1) == 0
    assert [transition(3, 1, route, 0, 1) for route in range(2)] == [0, 0]
    assert replay()["root_cause_ambiguity"]["effect_and_patch_alone_identify_unique_cause"] is False


@pytest.mark.parametrize("before,after,completed", [
    (None, 1, True), (0, None, True), (None, None, True),
    (0, 1, False), (0, 0, False), (None, None, False),
])
def test_missing_or_incomplete_observation_is_never_silent_success(before, after, completed):
    assert observed_effect(before, after, completed=completed) == "unobserved"


def test_observation_distinguishes_effect_from_no_effect():
    assert observed_effect(0, 1, completed=True) == "effect_observed"
    assert observed_effect(1, 0, completed=True) == "effect_observed"
    assert observed_effect(0, 0, completed=True) == "no_effect_observed"


def test_no_op_does_not_certify_security():
    # No state change when the requested value already matches, even with every permission enabled.
    assert transition(15, 1, 0, 1, 1) == 1
    assert transition(15, 1, 0, 1, 0) == 0


def test_repeatable_cli_report_and_no_authority_claim():
    path = Path(__file__).resolve().parents[1] / "scripts/replay_effect_evidence_experiment.py"
    result = subprocess.run([sys.executable, str(path)], check=True, capture_output=True, timeout=10)
    assert not result.stderr
    assert json.loads(result.stdout) == replay()
    assert all(value is False for value in replay()["claims"].values())
