"""Owned end to end controls for scan outcome propagation."""

import pytest

from etzio.analysis.python_sast import SourceAnalysisV1, SourceParseFailureV1
from etzio.scan import main


@pytest.mark.parametrize("retained", [False, True])
@pytest.mark.parametrize("failure", ["analyzer", "parse"])
def test_cli_never_reports_success_for_failed_or_unparsed_scan(
    tmp_path, monkeypatch, capsys, retained, failure,
):
    def analyze(path, source):
        if failure == "analyzer":
            raise ValueError("owned analyzer failure")
        return SourceAnalysisV1(path, (), SourceParseFailureV1(path, "python_syntax_error", 1, 0))

    monkeypatch.setattr("etzio.kernel.fixture_scan.analyze_python_bytes", analyze)
    args = ["--fixture", "clean"]
    if retained:
        args += ["--state-dir", str(tmp_path / "state")]
    code = main(args)
    output = capsys.readouterr()
    assert "terminal phase   : " + ("failed" if failure == "analyzer" else "closed") in output.out
    assert "VELITES candidates: 0" in output.out
    assert code == 3
