"""The fixture report must not turn abstention or absent data into success."""

from dataclasses import replace

import pytest

from etzio.benchmark import corpus
from etzio.contracts import VerdictKind
from etzio.engines import Cato
from etzio.harness import fpr


@pytest.mark.parametrize("name", ["precision", "recall", "fpr", "fdr"])
def test_empty_denominators_are_undefined(name):
    assert getattr(fpr.Metrics(0, 0, 0, 0), name) is None


def test_no_confirmations_does_not_claim_perfect_precision():
    metrics = fpr.Metrics(0, 0, 4, 1)
    assert metrics.precision is None
    assert metrics.fdr is None
    assert metrics.recall == 0
    assert metrics.fpr == 0


@pytest.mark.parametrize("value", [-1, True, 0.5])
@pytest.mark.parametrize("field", ["tp", "unresolved_positive"])
def test_invalid_counts_are_refused(field, value):
    args = dict(tp=0, fp=0, tn=0, fn=0)
    args[field] = value
    with pytest.raises(ValueError, match="nonnegative integer"):
        fpr.Metrics(**args)


@pytest.mark.parametrize("mode", ["no_pocs", "out_of_scope"])
def test_actual_cato_unresolved_branches_do_not_become_negatives(monkeypatch, capsys, mode):
    cases = corpus()
    changes = {"poc": None} if mode == "no_pocs" else {"target_asset": "unadmitted"}
    cases = [replace(c, candidate=replace(c.candidate, **changes)) for c in cases]
    monkeypatch.setattr(fpr, "corpus", lambda: cases)
    metrics, rows = fpr.evaluate()
    assert (metrics.tp, metrics.fp, metrics.tn, metrics.fn) == (0, 0, 0, 0)
    assert (metrics.unresolved_positive, metrics.unresolved_negative) == (4, 4)
    assert metrics.resolved == 0
    assert metrics.assigned == 8
    assert metrics.coverage == 0
    assert metrics.positive_coverage == metrics.negative_coverage == 0
    assert metrics.confirmed_positive_yield == 0
    assert metrics.recall is metrics.fpr is None
    expected_kind = "inconclusive" if mode == "no_pocs" else "out_of_scope"
    assert {row["cato"] for row in rows} == {expected_kind}
    assert {row["outcome"] for row in rows} == {"UNRESOLVED"}
    expected_reason = "no PoC to reproduce" if mode == "no_pocs" else "asset outside TargetContract scope"
    assert all(row["reasons"] == (expected_reason,) for row in rows)
    assert fpr.main() == 1
    output = capsys.readouterr().out
    assert "INCOMPLETE" in output and "PASS" not in output
    assert "precision=undefined (0/0)" in output
    assert expected_kind in output and expected_reason in output
    assert "coverage=0.000 (0/8)" in output


def test_empty_corpus_cannot_pass(monkeypatch, capsys):
    monkeypatch.setattr(fpr, "corpus", lambda: [])
    metrics, rows = fpr.evaluate()
    assert rows == []
    assert metrics.assigned == metrics.resolved == 0
    assert metrics.coverage is None
    assert metrics.positive_coverage is metrics.negative_coverage is None
    assert metrics.confirmed_positive_yield is None
    assert fpr.main() == 1
    output = capsys.readouterr().out
    assert "INCOMPLETE" in output and "PASS" not in output
    assert "coverage=undefined (0/0)" in output


def test_selective_abstention_reports_class_coverage_and_full_population_yield(monkeypatch, capsys):
    # Retain one confirmed positive; make all other positive cases unresolved.
    # Keep three resolved negatives and abstain on the fourth negative.
    cases = [replace(c, candidate=replace(c.candidate, poc=None))
             if c.candidate.id in {"TP2", "TP3", "FN1", "FP1"} else c for c in corpus()]
    monkeypatch.setattr(fpr, "corpus", lambda: cases)
    metrics, rows = fpr.evaluate()
    assert (metrics.tp, metrics.fp, metrics.tn, metrics.fn) == (1, 0, 3, 0)
    assert (metrics.unresolved_positive, metrics.unresolved_negative) == (3, 1)
    assert metrics.recall == 1
    assert metrics.coverage == 0.5
    assert metrics.positive_coverage == metrics.confirmed_positive_yield == 0.25
    assert metrics.negative_coverage == 0.75
    assert len(rows) == 8
    assert fpr.main() == 1
    output = capsys.readouterr().out
    assert "recall=1.000 (1/1)" in output
    assert "positive_yield=0.250 (1/4)" in output
    assert "positive_coverage=0.250 (1/4)" in output


class BadVerifier(Cato):
    def __init__(self, change):
        super().__init__()
        self.change = change

    def verify(self, candidate, contract, target):
        return replace(super().verify(candidate, contract, target), **self.change)


@pytest.mark.parametrize("change", [
    {"candidate_id": "other-case"}, {"verdict": "confirmed"}, {"verdict": None},
])
def test_invalid_verdict_cannot_enter_confusion_matrix(change):
    with pytest.raises(ValueError, match="verdict"):
        fpr.evaluate(BadVerifier(change))


def test_verifier_exception_cannot_produce_pass(monkeypatch, capsys):
    class BrokenVerifier(Cato):
        def verify(self, *args):
            raise RuntimeError("fixture verifier unavailable")
    monkeypatch.setattr(fpr, "Cato", BrokenVerifier)
    with pytest.raises(RuntimeError, match="unavailable"):
        fpr.main()
    assert "PASS" not in capsys.readouterr().out


def test_false_positive_fails_even_with_unresolved_cases(monkeypatch, capsys):
    class WrongVerifier(Cato):
        def verify(self, candidate, contract, target):
            result = super().verify(candidate, contract, target)
            kind = VerdictKind.CONFIRMED if candidate.id == "FP1" else VerdictKind.INCONCLUSIVE
            return replace(result, verdict=kind)
    monkeypatch.setattr(fpr, "Cato", WrongVerifier)
    metrics, _ = fpr.evaluate()
    assert metrics.fp == 1 and metrics.unresolved == 7
    assert fpr.main() == 1
    output = capsys.readouterr().out
    assert "FAIL" in output and "PASS" not in output


def test_normal_fixture_counts_and_cli_still_hold(capsys):
    metrics, rows = fpr.evaluate()
    assert (metrics.tp, metrics.fp, metrics.tn, metrics.fn) == (3, 0, 4, 1)
    assert metrics.unresolved == 0
    assert metrics.resolved == metrics.assigned == len(rows) == 8
    assert metrics.coverage == metrics.positive_coverage == metrics.negative_coverage == 1
    assert metrics.recall == metrics.confirmed_positive_yield == 0.75
    assert fpr.main() == 0
    output = capsys.readouterr().out
    assert "PASS" in output and "INCOMPLETE" not in output
    assert "conditional on resolved verdicts" in output
    assert "precision=1.000 (3/3)" in output
    assert "recall=0.750 (3/4)" in output
