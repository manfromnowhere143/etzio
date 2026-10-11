"""Finite owned counterexamples, not an execution verifier or finding authority."""

from __future__ import annotations

import itertools
import json


def transition(policy: int, actor: int, route: int, before: int, requested: int) -> int:
    """Owned two-actor/two-route bit store; callers below enumerate its entire domain."""
    permitted = policy & (1 << (2 * actor + route))
    return requested if permitted else before


def observed_effect(before: int | None, after: int | None, *, completed: bool) -> str:
    """Observation semantics only; the in-process caller is not an authenticated source."""
    if not completed or before is None or after is None:
        return "unobserved"
    return "effect_observed" if before != after else "no_effect_observed"


def replay() -> dict[str, object]:
    rows = []
    for policy in range(16):
        transitions = []
        for actor, route, before, requested in itertools.product(range(2), repeat=4):
            after = transition(policy, actor, route, before, requested)
            transitions.append({
                "actor": actor, "route": route, "before": before,
                "requested": requested, "after": after,
            })
        protected = all(t["after"] == t["before"] for t in transitions if t["actor"] == 1)
        functional = all(t["after"] == t["requested"] for t in transitions if t["actor"] == 0)
        # Independent algebraic characterization, not a second operational verifier.
        table_agrees = protected == (policy & 12 == 0) and functional == (policy & 3 == 3)
        single = transition(15, 1, 0, 0, 1) == 1 and transition(policy, 1, 0, 0, 1) == 0
        rows.append({
            "policy": policy, "transitions": transitions,
            "single_differential_accepts": single,
            "protected_operations_preserved": protected,
            "legitimate_operations_preserved": functional,
            "full_specification_satisfied": protected and functional,
            "permission_table_agrees": table_agrees,
        })
    accepted = [r for r in rows if r["single_differential_accepts"]]
    return {
        "schema": "etzio.owned-effect-counterexamples.v1",
        "scope": "complete_finite_model_only",
        "actor_meaning": {"0": "owner", "1": "outsider"},
        "policy_count": len(rows),
        "transition_count": sum(len(r["transitions"]) for r in rows),
        "single_differential_accepted_policies": [r["policy"] for r in accepted],
        "false_acceptances_against_full_specification": [
            r["policy"] for r in accepted if not r["full_specification_satisfied"]
        ],
        "security_preserving_but_nonfunctional_acceptances": [
            r["policy"] for r in accepted
            if r["protected_operations_preserved"] and not r["legitimate_operations_preserved"]
        ],
        "other_route_security_failure_acceptances": [
            r["policy"] for r in accepted if not r["protected_operations_preserved"]
        ],
        "full_specification_policies": [r["policy"] for r in rows if r["full_specification_satisfied"]],
        "all_permission_table_crosschecks_agree": all(r["permission_table_agrees"] for r in rows),
        "root_cause_ambiguity": {
            "shared_vulnerable_policy": 15,
            "after_each_route_on_shared_vulnerable_policy": [
                transition(15, 1, route, 0, 1) for route in range(2)
            ],
            "route_0_only_defect_policy": 7,
            "route_1_only_defect_policy": 11,
            "observed_after_from_0_requesting_1": [
                transition(7, 1, 0, 0, 1), transition(11, 1, 1, 0, 1),
            ],
            "combined_patch_policy": 3,
            "after_combined_patch": [transition(3, 1, route, 0, 1) for route in range(2)],
            "effect_and_patch_alone_identify_unique_cause": False,
        },
        "observation_controls": {
            "missing_before": observed_effect(None, 1, completed=True),
            "missing_after": observed_effect(0, None, completed=True),
            "incomplete_with_stale_after": observed_effect(0, 1, completed=False),
            "complete_unchanged": observed_effect(0, 0, completed=True),
            "complete_changed": observed_effect(0, 1, completed=True),
        },
        "claims": {
            "independent_execution": False, "real_target_repair": False,
            "finding": False, "comparative_discovery": False, "kernel_admission": False,
        },
        "policies": rows,
    }


def main() -> None:
    print(json.dumps(replay(), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
