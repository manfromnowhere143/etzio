"""Run the modeled foundation loop on a repository-owned deterministic fixture:

    python -m etzio.cli

This demonstrates branch behavior only. It does not establish authorization enforcement,
independent reproduction, finding validity, or a durable tamper-evident ledger.
"""

from __future__ import annotations

from .engines import default_roster
from .fixtures import BenchmarkTarget, demo_contract
from .kernel import MasterLoop


def main() -> int:
    contract = demo_contract()
    roster = default_roster()
    target = BenchmarkTarget()

    loop = MasterLoop("M-0001", contract, roster, target)
    state = loop.run()

    print("=" * 68)
    print(f"ETZIO mission {loop.mission_id} — {contract.program}")
    print(f"final stage      : {state.stage.value}")
    print(f"ledger events    : {len(loop.ledger)}")
    print(f"ledger chain ok  : {loop.ledger.verify_chain()}")
    print("-" * 68)
    print(f"modeled findings  : {len(state.findings)}")
    for f in state.findings:
        print(f"  [{f.severity_level.upper()}] {f.id}  trigger={f.triggering_input}")
        print(f"        modeled verifier={f.verifier_identity}  poc={f.poc_artifact_digest}")
    print(f"first-class nulls : {len(state.nulls)}")
    for n in state.nulls:
        print(f"  {n.hypothesis_id}: {n.reason}")
    print("=" * 68)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
