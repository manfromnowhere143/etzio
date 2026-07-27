"""Repository-owned deterministic fixtures for the modeled foundation loop.

No live target, untrusted execution, or independent verifier is involved.
"""

from __future__ import annotations

from dataclasses import dataclass

from .contracts import TargetContract


@dataclass
class BenchmarkTarget:
    """A tiny deterministic effect model.

    Modeled truth: an unbounded withdrawal returns ``balance_drained``. Nothing else has an
    effect, so a false impact claim follows the negative verdict branch.
    """
    revision: str = "benchmark@0001"

    def run(self, payload: str) -> str:
        if payload == "withdraw(amount=2**256)":
            return "balance_drained"        # the genuine vulnerability
        return "no_effect"                  # everything else is inert


def demo_contract() -> TargetContract:
    return TargetContract(
        program="Etzio first-slice benchmark",
        authorization_kind="benchmark",
        authorization_reference="benchmark://vault-0001",
        in_scope=("vault-0001",),
        permitted_actions=(
            "static_analysis", "dynamic_analysis", "poc_execution", "disclosure_draft",
        ),
        disclosure_channel="benchmark-sink",
        max_usd=0.0,
    )
