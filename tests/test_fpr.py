"""Phase-1 admission: CATO must have ZERO false positives on the labeled corpus, and must
still confirm the genuine, well-constructed exploits. Recall < 1.0 is acceptable (the
broken-PoC case is an honest miss); FP > 0 is not."""

from __future__ import annotations

from etzio.harness.fpr import evaluate


def test_zero_false_positives():
    m, rows = evaluate()
    fps = [r for r in rows if r["outcome"] == "FP"]
    assert m.fp == 0, f"CATO produced false positives: {fps}"
    assert m.precision == 1.0


def test_confirms_genuine_exploits():
    m, rows = evaluate()
    confirmed = {r["id"] for r in rows if r["cato"] == "confirmed"}
    assert {"TP1", "TP2", "TP3"} <= confirmed


def test_rejects_the_planted_false_positives():
    _, rows = evaluate()
    by_id = {r["id"]: r for r in rows}
    for fp_id in ("FP1", "FP2", "FP3"):
        assert by_id[fp_id]["cato"] != "confirmed"


def test_broken_poc_is_an_honest_miss_not_a_false_positive():
    _, rows = evaluate()
    fn = next(r for r in rows if r["id"] == "FN1")
    # the real bug's broken PoC is correctly NOT confirmed -> counts as FN, never FP
    assert fn["cato"] != "confirmed"
    assert fn["outcome"] == "FN"
