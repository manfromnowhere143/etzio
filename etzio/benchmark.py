"""Phase-1 benchmark: a labeled corpus for measuring CATO's false-positive rate.

Each case carries GROUND TRUTH (is the underlying vulnerability real and exploitable?)
independent of what the candidate *claims*. CATO never sees the ground truth — it only
re-executes the PoC. The harness then scores CATO's verdicts against truth.

The corpus deliberately includes the hard shapes:
  * genuine bugs with a working PoC              -> CATO must CONFIRM   (true positive)
  * a claim of impact from a benign action       -> CATO must REJECT    (would-be false positive)
  * a benign action honestly labeled             -> CATO must REJECT    (not impactful)
  * a real bug whose PoC is broken/incomplete    -> CATO must REJECT    (honest miss / recall cost)

A vuln engine's whole worth is precision: it may miss (a false negative just costs a
bounty), but it must not cry wolf (a false positive burns a reviewer and the program).
"""

from __future__ import annotations

from dataclasses import dataclass

from .contracts import Candidate, PoCArtifact, TargetContract

_ASSET = "vault-0002"


@dataclass
class VaultTarget:
    """Deterministic sandbox standing in for a smart-contract vault. run(payload) -> effect."""
    revision: str = "vault-bench@0002"

    _EFFECTS = {
        "withdraw(amount=2**256)": "balance_drained",          # real: integer overflow
        "reentrant_withdraw()": "balance_drained",             # real: reentrancy
        "oracle_set(price=0); borrow()": "price_manipulated",  # real: oracle manipulation
        "withdraw(amount=100)": "normal_withdrawal",           # benign: within balance
        "approve(spender=attacker)": "no_effect",              # benign
        "transfer(to=self)": "no_effect",                      # benign
        "reentrant_withdraw(no_setup)": "no_effect",           # broken PoC: setup missing
    }

    def run(self, payload: str) -> str:
        return self._EFFECTS.get(payload, "no_effect")


@dataclass(frozen=True)
class BenchmarkCase:
    candidate: Candidate
    exploitable: bool     # ground truth, hidden from CATO
    label: str


def _cand(cid: str, payload: str, claim: str) -> Candidate:
    return Candidate(cid, f"H-{cid}", "VELITES", _ASSET, PoCArtifact(payload, claim))


def corpus() -> list[BenchmarkCase]:
    return [
        # --- genuine, well-constructed exploits: CATO should CONFIRM ---
        BenchmarkCase(_cand("TP1", "withdraw(amount=2**256)", "balance_drained"), True, "overflow drain"),
        BenchmarkCase(_cand("TP2", "reentrant_withdraw()", "balance_drained"), True, "reentrancy drain"),
        BenchmarkCase(_cand("TP3", "oracle_set(price=0); borrow()", "price_manipulated"), True, "oracle manip"),
        # --- would-be false positives: CATO MUST reject ---
        BenchmarkCase(_cand("FP1", "approve(spender=attacker)", "balance_drained"), False, "benign claimed as drain"),
        BenchmarkCase(_cand("FP2", "withdraw(amount=100)", "balance_drained"), False, "normal withdrawal mislabeled"),
        BenchmarkCase(_cand("FP3", "transfer(to=self)", "funds_stolen"), False, "no-op claimed as theft"),
        # --- benign, honestly labeled (not impactful): CATO rejects ---
        BenchmarkCase(_cand("TN1", "withdraw(amount=100)", "normal_withdrawal"), False, "honest benign"),
        # --- real bug, broken PoC: CATO correctly cannot reproduce (honest false negative) ---
        BenchmarkCase(_cand("FN1", "reentrant_withdraw(no_setup)", "balance_drained"), True, "real bug, broken PoC"),
    ]


def benchmark_contract() -> TargetContract:
    return TargetContract(
        program="Etzio Phase-1 FPR benchmark",
        authorization_kind="benchmark",
        authorization_reference="benchmark://vault-0002",
        in_scope=(_ASSET,),
        permitted_actions=("static_analysis", "dynamic_analysis", "poc_execution", "disclosure_draft"),
        disclosure_channel="benchmark-sink",
        max_usd=0.0,
    )
