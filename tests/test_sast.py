"""VELITES byte-bound static-analysis slice and false-positive controls."""

from __future__ import annotations

from pathlib import Path

import etzio
from etzio.analysis import analyze_python_bytes
from etzio.contracts import Candidate
from etzio.engines import Cato
from etzio.evidence import read_etzio_fixture

ETZIO_SRC = Path(etzio.__file__).parent

EXPECTED_RULES = {
    "PY-CMD-INJECTION",        # os.system + subprocess shell=True (x2)
    "PY-UNSAFE-DESERIALIZE",   # pickle.loads
    "PY-CODE-INJECTION",       # eval
    "PY-WEAK-CRYPTO",          # hashlib.md5
    "PY-SQL-INJECTION",        # dynamic execute()
    "PY-HARDCODED-SECRET",     # API_KEY literal
}


def _fixture_analysis(name: str):
    relative_path, source = read_etzio_fixture(name, maximum=64 * 1024)
    return analyze_python_bytes(relative_path, source)


def test_finds_every_planted_vulnerability():
    rules = {finding.rule_id for finding in _fixture_analysis("vulnerable_app.py").findings}
    assert EXPECTED_RULES <= rules, f"missed: {EXPECTED_RULES - rules}"


def test_finds_both_command_injections():
    cmd = [
        finding
        for finding in _fixture_analysis("vulnerable_app.py").findings
        if finding.rule_id == "PY-CMD-INJECTION"
    ]
    assert len(cmd) == 2   # os.system(...) and subprocess.run(..., shell=True)


def test_clean_fixture_has_zero_findings():
    assert _fixture_analysis("clean_app.py").findings == ()


def test_etzio_own_source_is_clean():
    # Test-only traversal: the production analyzer itself has no path-taking API.
    culprits = []
    for path in ETZIO_SRC.rglob("*.py"):
        if "fixtures_code" in path.parts:
            continue
        relative_path = path.relative_to(ETZIO_SRC).as_posix()
        result = analyze_python_bytes(relative_path, path.read_bytes())
        culprits.extend(
            (finding.rule_id, finding.file, finding.line)
            for finding in result.findings
        )
    assert culprits == [], f"false positives in Etzio source: {culprits}"


def test_detector_observations_keep_stable_symbols_and_locations():
    findings = _fixture_analysis("vulnerable_app.py").findings
    observations = {(finding.rule_id, finding.symbol, finding.line) for finding in findings}
    assert ("PY-CMD-INJECTION", "os.system", 11) in observations
    assert ("PY-UNSAFE-DESERIALIZE", "pickle.loads", 19) in observations


def test_static_candidate_is_not_a_confirmed_finding():
    # Honesty check: a static candidate has no PoC, so CATO must NOT confirm it.
    from etzio.contracts import TargetContract

    candidate = Candidate(
        "static-candidate",
        "PY-CMD-INJECTION",
        "VELITES",
        "fixture://vulnerable_app.py",
        poc=None,
        note="protocol candidate without a PoC",
    )
    contract = TargetContract(
        program="scan", authorization_kind="benchmark", authorization_reference="x",
        in_scope=(candidate.target_asset,), permitted_actions=("static_analysis",),
        disclosure_channel="sink", max_usd=0.0,
    )

    class _NoTarget:
        revision = "static-only"
        def run(self, payload):  # never called for a no-PoC candidate
            raise AssertionError("CATO must not execute a candidate that has no PoC")

    verdict = Cato().verify(candidate, contract, _NoTarget())
    assert verdict.verdict.value == "inconclusive"


def test_protocol_scan_reports_syntax_failure_without_source_text():
    source = b"API_KEY = 'must-not-leak'\\ndef broken(:\\n"
    result = analyze_python_bytes("broken.py", source)

    assert result.findings == ()
    assert result.parse_failure is not None
    assert result.parse_failure.reason_code == "python_syntax_error"
    assert "must-not-leak" not in repr(result.parse_failure)


def test_protocol_scan_reports_invalid_utf8_without_silently_passing():
    result = analyze_python_bytes("invalid.py", b"\xff")

    assert result.findings == ()
    assert result.parse_failure is not None
    assert result.parse_failure.reason_code == "invalid_utf8"


def test_protocol_scan_does_not_require_exposing_snippets():
    result = analyze_python_bytes(
        "vulnerable.py",
        b"import os\nAPI_KEY = 'must-not-leak'\ndef run(value):\n    os.system(value)\n",
    )

    assert result.parse_failure is None
    assert {finding.rule_id for finding in result.findings} == {
        "PY-CMD-INJECTION",
        "PY-HARDCODED-SECRET",
    }
    public_shape = [
        {
            "line": finding.line,
            "column": finding.column,
            "message": finding.message,
            "relative_path": finding.file,
            "rule_id": finding.rule_id,
            "severity": finding.severity,
            "symbol": finding.symbol,
        }
        for finding in result.findings
    ]
    assert "must-not-leak" not in repr(public_shape)
