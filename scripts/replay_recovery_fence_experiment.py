"""Exhaustive owned finite schedules; no provider, kernel, network or proof authority."""

from __future__ import annotations

import itertools
import json
from collections.abc import Iterator
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Policy:
    reads: int
    publication_fenced: bool = True
    local_atomic_fence: bool = False
    effect_atomic_fence: bool = False

    @property
    def name(self) -> str:
        return (
            f"reads_{self.reads}_publication_{int(self.publication_fenced)}"
            f"_local_{int(self.local_atomic_fence)}_effect_{int(self.effect_atomic_fence)}"
        )


def schedules(left: tuple[str, ...], right: tuple[str, ...]) -> Iterator[tuple[str, ...]]:
    """Every interleaving preserving each chain's internal order, with no dedup pruning."""
    if not left or not right:
        yield left + right
        return
    for suffix in schedules(left[1:], right):
        yield (left[0],) + suffix
    for suffix in schedules(left, right[1:]):
        yield (right[0],) + suffix


def chains(policy: Policy) -> tuple[tuple[str, ...], tuple[str, ...]]:
    old = ("old_publish", "old_reply") + tuple(f"read_{i}" for i in range(policy.reads))
    return old + ("old_local_commit", "old_effect"), ("fence", "recover_read", "new_publish")


def simulate(policy: Policy, schedule: tuple[str, ...]) -> dict[str, object]:
    """Operational replay. Fence and hypothetical consumer checks are explicit atoms."""
    epoch = 0
    ledger: list[str] = []
    cut: list[str] | None = None
    published = replied = committed = effect = False
    reads_ok = True
    violations: dict[str, list[str]] = {}
    steps = []
    for action in schedule:
        accepted = False
        if action == "fence":
            epoch = 1
            accepted = True
        elif action == "old_publish":
            accepted = not policy.publication_fenced or epoch == 0
            if accepted:
                ledger.append("old")
                published = True
                if epoch:
                    violations.setdefault("old_publication_after_fence", []).append(action)
                if cut is not None and "old" not in cut:
                    violations.setdefault("old_publication_missing_from_recovery_cut", []).append(action)
        elif action == "old_reply":
            replied = accepted = published
        elif action.startswith("read_"):
            accepted = replied and epoch == 0
            reads_ok = reads_ok and accepted
        elif action == "old_local_commit":
            accepted = replied and reads_ok and (not policy.local_atomic_fence or epoch == 0)
            committed = accepted
            if accepted and epoch:
                violations.setdefault("old_local_commit_after_fence", []).append(action)
        elif action == "old_effect":
            accepted = committed and (not policy.effect_atomic_fence or epoch == 0)
            effect = accepted
            if accepted and epoch:
                violations.setdefault("old_effect_after_fence", []).append(action)
        elif action == "recover_read":
            cut = list(ledger)
            accepted = True
        elif action == "new_publish":
            # The recovery chain guarantees epoch 1 and the complete read cut first.
            if epoch != 1 or cut is None:
                raise AssertionError("invalid recovery schedule")
            ledger.append("new")
            accepted = True
        else:
            raise ValueError(action)
        steps.append({"action": action, "accepted": accepted, "epoch": epoch})
    return {
        "old_published": published, "old_local_committed": committed, "old_effect": effect,
        "recovery_cut": cut, "ledger": ledger, "violations": sorted(violations), "steps": steps,
    }


def positional_outcome(policy: Policy, schedule: tuple[str, ...]) -> dict[str, object]:
    """Separate order-inequality calculation; not an independent verifier or proof."""
    pos = {event: i for i, event in enumerate(schedule)}
    fence = pos["fence"]
    publication = not policy.publication_fenced or pos["old_publish"] < fence
    commit = (
        publication and all(pos[f"read_{i}"] < fence for i in range(policy.reads))
        and (not policy.local_atomic_fence or pos["old_local_commit"] < fence)
    )
    effect = commit and (not policy.effect_atomic_fence or pos["old_effect"] < fence)
    failures = {
        "old_publication_after_fence": publication and pos["old_publish"] > fence,
        "old_local_commit_after_fence": commit and pos["old_local_commit"] > fence,
        "old_effect_after_fence": effect and pos["old_effect"] > fence,
        "old_publication_missing_from_recovery_cut": publication and pos["old_publish"] > pos["recover_read"],
    }
    cut = ["old"] if publication and pos["old_publish"] < pos["recover_read"] else []
    return {
        "old_published": publication, "old_local_committed": commit, "old_effect": effect,
        "recovery_cut": cut, "violations": sorted(k for k, v in failures.items() if v),
    }


def explore(policy: Policy) -> dict[str, object]:
    counts = {"schedules": 0, "old_publications": 0, "old_local_commits": 0, "old_effects": 0}
    failure_counts: dict[str, int] = {}
    shortest: dict[str, list[dict[str, object]]] = {}
    for schedule in schedules(*chains(policy)):
        observed = simulate(policy, schedule)
        expected = positional_outcome(policy, schedule)
        if any(observed[key] != value for key, value in expected.items()):
            raise AssertionError((policy, schedule, observed, expected))
        counts["schedules"] += 1
        for field, counter in (
            ("old_published", "old_publications"), ("old_local_committed", "old_local_commits"),
            ("old_effect", "old_effects"),
        ):
            counts[counter] += int(observed[field])
        for failure in observed["violations"]:
            failure_counts[failure] = failure_counts.get(failure, 0) + 1
            # Prefix ending exactly at the first bad event, including paused-writer traces.
            event = {
                "old_publication_after_fence": "old_publish",
                "old_publication_missing_from_recovery_cut": "old_publish",
                "old_local_commit_after_fence": "old_local_commit",
                "old_effect_after_fence": "old_effect",
            }[failure]
            prefix = observed["steps"][:schedule.index(event) + 1]
            if failure not in shortest or len(prefix) < len(shortest[failure]):
                shortest[failure] = prefix
    return {
        "policy": asdict(policy), "policy_id": policy.name, **counts,
        "violating_schedule_counts": failure_counts, "shortest_counterexamples": shortest,
        "positional_crosscheck_agrees": True,
    }


def replay() -> dict[str, object]:
    policies = [
        Policy(reads, True, local, effect)
        for reads, local, effect in itertools.product((0, 1, 3), (False, True), (False, True))
    ]
    # Known-bad controls: remove only the catalog-side admission check in this abstraction.
    policies += [Policy(0, False, False, False), Policy(0, False, True, True)]
    rows = [explore(policy) for policy in policies]
    for policy, row in zip(policies, rows, strict=True):
        failures = row["violating_schedule_counts"]
        required = set()
        if not policy.publication_fenced:
            required.update(("old_publication_after_fence", "old_publication_missing_from_recovery_cut"))
        if not policy.local_atomic_fence:
            required.add("old_local_commit_after_fence")
        if not policy.effect_atomic_fence:
            required.add("old_effect_after_fence")
        successes = (row[k] for k in ("old_publications", "old_local_commits", "old_effects"))
        if set(failures) != required or min(successes) < 1:
            raise AssertionError((policy, row))
    return {
        "schema": "etzio.owned-recovery-fence-experiment.v1",
        "scope": "complete_finite_interleavings_only",
        "bounds": {"old_writers": 1, "recovery_writers": 1, "fences": 1, "precommit_reads": [0, 1, 3]},
        "policy_count": len(rows), "schedule_count": sum(row["schedules"] for row in rows),
        "all_positional_crosschecks_agree": True, "all_expected_counterexamples_present": True,
        "all_positive_controls_present": True,
        "claims": {
            "native_fencing_implemented": False, "kernel_defect_established": False,
            "unbounded_proof": False, "implementation_refinement": False,
            "provider_qualification": False, "external_execution": False, "finding": False,
        },
        "policies": rows,
    }


def main() -> None:
    print(json.dumps(replay(), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
