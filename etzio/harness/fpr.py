"""False-positive-rate harness. Runs CATO over a labeled corpus and scores its verdicts
against ground truth. CATO never sees the labels — it only re-executes the PoC.

    python -m etzio.harness.fpr

Phase-1 admission bar: FP == 0 (zero false positives). Recall may be < 1.0 — an honest miss
costs a bounty; a false positive costs the program's trust.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..benchmark import VaultTarget, benchmark_contract, corpus
from ..contracts import VerdictKind
from ..engines import Cato


@dataclass(frozen=True)
class Metrics:
    tp: int
    fp: int
    tn: int
    fn: int

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 1.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 1.0

    @property
    def fpr(self) -> float:
        """False positives among all truly-benign cases."""
        d = self.fp + self.tn
        return self.fp / d if d else 0.0

    @property
    def fdr(self) -> float:
        """False discovery rate: of everything CATO confirmed, how much was wrong."""
        d = self.tp + self.fp
        return self.fp / d if d else 0.0


def evaluate(cato: Cato | None = None) -> tuple[Metrics, list[dict]]:
    cato = cato or Cato()
    contract = benchmark_contract()
    target = VaultTarget()
    tp = fp = tn = fn = 0
    rows: list[dict] = []
    for case in corpus():
        verdict = cato.verify(case.candidate, contract, target)
        predicted = verdict.verdict is VerdictKind.CONFIRMED
        truth = case.exploitable
        if predicted and truth:
            outcome, _ = "TP", tp
            tp += 1
        elif predicted and not truth:
            outcome = "FP"
            fp += 1
        elif not predicted and not truth:
            outcome = "TN"
            tn += 1
        else:
            outcome = "FN"
            fn += 1
        rows.append({
            "id": case.candidate.id,
            "label": case.label,
            "truth": "vuln" if truth else "benign",
            "cato": verdict.verdict.value,
            "outcome": outcome,
        })
    return Metrics(tp, fp, tn, fn), rows


def main() -> int:
    m, rows = evaluate()
    print("=" * 72)
    print("ETZIO · CATO gate · Phase-1 false-positive harness")
    print("=" * 72)
    print(f"{'case':5} {'ground truth':13} {'CATO verdict':16} {'outcome':7}  detail")
    print("-" * 72)
    for r in rows:
        flag = "  <-- FALSE POSITIVE" if r["outcome"] == "FP" else ""
        print(f"{r['id']:5} {r['truth']:13} {r['cato']:16} {r['outcome']:7}  {r['label']}{flag}")
    print("-" * 72)
    print(f"TP={m.tp}  FP={m.fp}  TN={m.tn}  FN={m.fn}")
    print(f"precision={m.precision:.3f}  recall={m.recall:.3f}  "
          f"FPR={m.fpr:.3f}  FDR={m.fdr:.3f}")
    bar = "PASS" if m.fp == 0 else "FAIL"
    print(f"Phase-1 admission bar (FP == 0): {bar}")
    print("=" * 72)
    return 0 if m.fp == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
