"""Modeled false-positive-rate harness.

Runs the in-process CATO stub over a tiny labeled fixture corpus. CATO does not see the
labels, but this is not isolated or real-world exploit reproduction.

    python -m etzio.harness.fpr

The regression condition is a nonempty, fully resolved corpus with FP == 0. Undefined
rates and unresolved verdicts remain explicit. The corpus is too small to establish a
real false-positive rate, and recall remains intentionally incomplete.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..benchmark import VaultTarget, benchmark_contract, corpus
from ..contracts import VerdictKind
from ..engines import Cato


@dataclass(frozen=True)
class Metrics:
    """Resolved-only confusion counts plus unresolved cases by ground-truth class."""

    tp: int
    fp: int
    tn: int
    fn: int
    unresolved_positive: int = 0
    unresolved_negative: int = 0

    def __post_init__(self) -> None:
        for count in (self.tp, self.fp, self.tn, self.fn, self.unresolved_positive, self.unresolved_negative):
            if type(count) is not int or count < 0:
                raise ValueError("fixture counts must be nonnegative integers")

    @property
    def resolved(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def unresolved(self) -> int:
        return self.unresolved_positive + self.unresolved_negative

    @property
    def assigned(self) -> int:
        return self.resolved + self.unresolved

    @property
    def coverage(self) -> float | None:
        return _ratio(self.resolved, self.assigned)

    @property
    def positive_coverage(self) -> float | None:
        return _ratio(self.tp + self.fn, self.tp + self.fn + self.unresolved_positive)

    @property
    def negative_coverage(self) -> float | None:
        return _ratio(self.fp + self.tn, self.fp + self.tn + self.unresolved_negative)

    @property
    def confirmed_positive_yield(self) -> float | None:
        """Confirmed positives among all assigned positives, with no credit for abstention."""
        return _ratio(self.tp, self.tp + self.fn + self.unresolved_positive)

    @property
    def precision(self) -> float | None:
        return _ratio(self.tp, self.tp + self.fp)

    @property
    def recall(self) -> float | None:
        """Recall conditional on resolved positive cases; report positive coverage too."""
        return _ratio(self.tp, self.tp + self.fn)

    @property
    def fpr(self) -> float | None:
        """False positives among resolved truly-benign cases."""
        return _ratio(self.fp, self.fp + self.tn)

    @property
    def fdr(self) -> float | None:
        """False discovery rate: of everything CATO confirmed, how much was wrong."""
        return _ratio(self.fp, self.tp + self.fp)


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _format_ratio(numerator: int, denominator: int) -> str:
    value = _ratio(numerator, denominator)
    rendered = "undefined" if value is None else f"{value:.3f}"
    return f"{rendered} ({numerator}/{denominator})"


def evaluate(cato: Cato | None = None) -> tuple[Metrics, list[dict]]:
    cato = Cato() if cato is None else cato
    contract = benchmark_contract()
    target = VaultTarget()
    tp = fp = tn = fn = 0
    unresolved_positive = unresolved_negative = 0
    rows: list[dict] = []
    for case in corpus():
        verdict = cato.verify(case.candidate, contract, target)
        if verdict.candidate_id != case.candidate.id or type(verdict.verdict) is not VerdictKind:
            raise ValueError("fixture verdict must name the current candidate and a known verdict kind")
        truth = case.exploitable
        if verdict.verdict is VerdictKind.CONFIRMED:
            if truth:
                outcome = "TP"
                tp += 1
            else:
                outcome = "FP"
                fp += 1
        elif verdict.verdict is VerdictKind.NOT_REPRODUCED:
            if truth:
                outcome = "FN"
                fn += 1
            else:
                outcome = "TN"
                tn += 1
        elif verdict.verdict in (VerdictKind.INCONCLUSIVE, VerdictKind.OUT_OF_SCOPE):
            outcome = "UNRESOLVED"
            if truth:
                unresolved_positive += 1
            else:
                unresolved_negative += 1
        else:  # A future enum addition needs an explicit accounting decision.
            raise ValueError("fixture verdict kind has no accounting rule")
        rows.append({
            "id": case.candidate.id,
            "label": case.label,
            "truth": "vuln" if truth else "benign",
            "cato": verdict.verdict.value,
            "outcome": outcome,
            "reasons": verdict.reasons,
        })
    return Metrics(tp, fp, tn, fn, unresolved_positive, unresolved_negative), rows


def main() -> int:
    m, rows = evaluate()
    print("=" * 72)
    print("ETZIO · modeled CATO logic · fixture corpus")
    print("=" * 72)
    print(f"{'case':5} {'ground truth':13} {'CATO verdict':16} {'outcome':10}  detail")
    print("-" * 72)
    for r in rows:
        flag = "  <-- FALSE POSITIVE" if r["outcome"] == "FP" else ""
        print(f"{r['id']:5} {r['truth']:13} {r['cato']:16} {r['outcome']:10}  {r['label']}{flag}")
        if r["outcome"] == "UNRESOLVED":
            print("      " + "; ".join(r["reasons"]))
    print("-" * 72)
    print(f"TP={m.tp}  FP={m.fp}  TN={m.tn}  FN={m.fn}")
    print(f"unresolved_positive={m.unresolved_positive}  unresolved_negative={m.unresolved_negative}")
    print(f"coverage={_format_ratio(m.resolved, m.assigned)}")
    positives = m.tp + m.fn + m.unresolved_positive
    negatives = m.fp + m.tn + m.unresolved_negative
    print(f"positive_coverage={_format_ratio(m.tp + m.fn, positives)}  "
          f"negative_coverage={_format_ratio(m.fp + m.tn, negatives)}")
    print("Metrics conditional on resolved verdicts:")
    print(f"precision={_format_ratio(m.tp, m.tp + m.fp)}  recall={_format_ratio(m.tp, m.tp + m.fn)}  "
          f"FPR={_format_ratio(m.fp, m.fp + m.tn)}  FDR={_format_ratio(m.fp, m.tp + m.fp)}")
    print(f"All-assigned positive_yield={_format_ratio(m.tp, positives)}")
    bar = "FAIL" if m.fp else "INCOMPLETE" if not m.assigned or m.unresolved else "PASS"
    print(f"Fixture regression condition (nonempty, completely resolved, FP == 0): {bar}")
    print("=" * 72)
    return 0 if bar == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
