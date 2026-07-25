"""First-slice admission tests. The architecture must prove itself before scale.

These assert the load-bearing laws mechanically, not by inspection:
  * exactly one confirmed finding (the genuine overflow),
  * the planted false positive is REJECTED by CATO (not in findings),
  * the empty hypothesis yields a first-class null,
  * the ledger hash-chain is intact,
  * an out-of-scope action fails closed.
"""

from __future__ import annotations

import pytest

from etzio.contracts import Stage
from etzio.engines import default_roster
from etzio.fixtures import BenchmarkTarget, demo_contract
from etzio.kernel import MasterLoop, ScopeError


def run_demo():
    loop = MasterLoop("M-TEST", demo_contract(), default_roster(), BenchmarkTarget())
    state = loop.run()
    return loop, state


def test_exactly_one_confirmed_finding():
    _, state = run_demo()
    assert len(state.findings) == 1
    f = state.findings[0]
    assert f.hypothesis_id == "H1"
    assert f.triggering_input == "withdraw(amount=2**256)"
    assert f.verifier_identity == "CATO"


def test_false_positive_is_rejected():
    loop, state = run_demo()
    # H2's candidate claimed balance_drained but the sandbox observes no_effect -> not a finding.
    finding_hyps = {f.hypothesis_id for f in state.findings}
    assert "H2" not in finding_hyps
    verdicts = [e for e in loop.ledger.of_kind("verdict_recorded")
                if e.payload["candidate_id"] == "C2"]
    assert verdicts and verdicts[0].payload["verdict"] == "not_reproduced"


def test_null_is_first_class():
    _, state = run_demo()
    null_hyps = {n.hypothesis_id for n in state.nulls}
    assert "H3" in null_hyps          # nothing found under H3, recorded not dropped
    assert "H2" in null_hyps          # rejected FP is retained as a non-finding


def test_ledger_chain_is_intact():
    loop, state = run_demo()
    assert loop.ledger.verify_chain()
    assert state.stage is Stage.CLOSED


def test_out_of_scope_fails_closed():
    loop = MasterLoop("M-SCOPE", demo_contract(), default_roster(), BenchmarkTarget())
    with pytest.raises(ScopeError):
        loop._gate("poc_execution", "some-other-asset-not-in-scope")
