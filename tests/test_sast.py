"""SCIPIO/VELITES real static-analysis slice. The bar: find every planted vulnerability in
the vulnerable fixture, and report ZERO on clean code AND on Etzio's own source (the
false-positive discipline that makes a vuln engine trustworthy)."""

from __future__ import annotations

import os

from etzio.analysis import find_findings, scan_surface
from etzio.engines import Cato, Velites
from etzio.fixtures_code import FIXTURES_DIR

VULN = os.path.join(FIXTURES_DIR, "vulnerable_app.py")
CLEAN = os.path.join(FIXTURES_DIR, "clean_app.py")
ETZIO_SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/etzio"

EXPECTED_RULES = {
    "PY-CMD-INJECTION",        # os.system + subprocess shell=True (x2)
    "PY-UNSAFE-DESERIALIZE",   # pickle.loads
    "PY-CODE-INJECTION",       # eval
    "PY-WEAK-CRYPTO",          # hashlib.md5
    "PY-SQL-INJECTION",        # dynamic execute()
    "PY-HARDCODED-SECRET",     # API_KEY literal
}


def test_finds_every_planted_vulnerability():
    rules = {f.rule_id for f in find_findings(VULN)}
    assert EXPECTED_RULES <= rules, f"missed: {EXPECTED_RULES - rules}"


def test_finds_both_command_injections():
    cmd = [f for f in find_findings(VULN) if f.rule_id == "PY-CMD-INJECTION"]
    assert len(cmd) == 2   # os.system(...) and subprocess.run(..., shell=True)


def test_clean_fixture_has_zero_findings():
    assert find_findings(CLEAN) == []


def test_etzio_own_source_is_clean():
    # The analyzer must not cry wolf on the engine's own production code.
    findings = find_findings(ETZIO_SRC)
    culprits = [(f.rule_id, f.file, f.line) for f in findings
                if "fixtures_code" not in f.file]   # exclude the intentional fixture
    assert culprits == [], f"false positives in Etzio source: {culprits}"


def test_surface_maps_real_entrypoints():
    surface = scan_surface(VULN)
    fn_names = {e.split("::")[1] for e in surface.entrypoints}
    assert {"run_cmd", "deserialize", "calc", "get_user"} <= fn_names
    assert "os" in surface.imports and "pickle" in surface.imports


def test_static_candidate_is_not_a_confirmed_finding():
    # Honesty check: a static candidate has no PoC, so CATO must NOT confirm it.
    from etzio.contracts import TargetContract

    candidates = Velites().scan_repo(VULN)
    assert candidates
    contract = TargetContract(
        program="scan", authorization_kind="benchmark", authorization_reference="x",
        in_scope=(candidates[0].target_asset,), permitted_actions=("static_analysis",),
        disclosure_channel="sink", max_usd=0.0,
    )

    class _NoTarget:
        revision = "static-only"
        def run(self, payload):  # never called for a no-PoC candidate
            raise AssertionError("CATO must not execute a candidate that has no PoC")

    verdict = Cato().verify(candidates[0], contract, _NoTarget())
    assert verdict.verdict.value == "inconclusive"
