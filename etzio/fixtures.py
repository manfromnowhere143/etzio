"""Benchmark fixtures for the first vertical slice. A locally-owned deterministic target
with one planted true bug — so CATO can genuinely re-run a PoC and reject a false positive.
No live target. Authorization kind is 'benchmark'."""

from __future__ import annotations

from dataclasses import dataclass

from .contracts import TargetContract


@dataclass
class BenchmarkTarget:
    """A tiny deterministic sandbox. run(payload) returns the observed effect.

    Planted truth: an unbounded withdraw drains the balance. Nothing else does anything —
    so a candidate that *claims* 'balance_drained' from a benign approve() must fail CATO.
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
