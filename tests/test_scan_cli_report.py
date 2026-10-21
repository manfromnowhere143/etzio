"""Machine consumers must see complete analysis, refusals and missing work distinctly."""

from __future__ import annotations

import json
from dataclasses import replace
from importlib.resources import files

import pytest
from jsonschema import Draft202012Validator
from test_fixture_scan_v1 import _run, _setup

from etzio.analysis.python_sast import SourceAnalysisV1, SourceParseFailureV1
from etzio.kernel.reducer import reduce_events
from etzio.kernel.store import SQLiteEventStore
from etzio.protocol import canonical_dumps, thaw_json
from etzio.scan import main


def _read_report(capsys):
    captured = capsys.readouterr()
    assert captured.err == ""
    report = json.loads(captured.out)
    assert captured.out == canonical_dumps(report).decode("utf-8") + "\n"
    schema = json.loads(files("etzio.schemas").joinpath("fixture_scan_report.v1.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(report)
    assert report["claim_level"] == "static_candidates"
    assert report["verification_status"] == "not_performed"
    assert "hunter2-not-real" not in captured.out
    assert "snippet" not in captured.out
    return report


@pytest.mark.parametrize("fixture,count", [("clean", 0), ("vulnerable", 7)])
@pytest.mark.parametrize("retained", [False, True])
def test_json_success_preserves_candidate_identity_and_retention(tmp_path, capsys, fixture, count, retained):
    args = ["--fixture", fixture, "--format", "json"]
    if retained:
        args += ["--state-dir", str(tmp_path / "state")]
    assert main(args) == 0
    report = _read_report(capsys)
    assert report["status"] == "completed"
    assert report["phase"] == "closed"
    assert report["reason_code"] is None
    assert report["candidate_count"] == len(report["candidates"]) == count
    assert report["parse_failure_count"] == 0
    assert report["parse_failures"] == []
    assert report["state_retention"] == ("operator_path" if retained else "ephemeral")
    assert str(tmp_path) not in json.dumps(report)
    if retained:
        with SQLiteEventStore(tmp_path / "state/events.sqlite3") as store:
            projection = reduce_events(store.load(report["mission_id"]))
        assert report["authority_id"] == projection.authority_id
        assert report["target_snapshot_id"] == projection.target_id
        assert report["event_head"] == projection.events[-1].event_digest
        assert report["event_count"] == len(projection.events)
        for candidate, event in zip(report["candidates"], projection.candidate_events, strict=True):
            wire = thaw_json(event.payload)["candidate"]
            assert candidate["candidate_id"] == wire["object_id"]
            for field in candidate.keys() - {"candidate_id"}:
                assert candidate[field] == wire["body"][field]


@pytest.mark.parametrize("retained", [False, True])
@pytest.mark.parametrize("failure", ["analyzer", "parse"])
def test_json_failure_cannot_be_mistaken_for_clean_completion(tmp_path, monkeypatch, capsys, retained, failure):
    def analyze(path, source):
        if failure == "analyzer":
            raise ValueError("owned analyzer failure")
        return SourceAnalysisV1(path, (), SourceParseFailureV1(path, "python_syntax_error", 1, 0))

    monkeypatch.setattr("etzio.kernel.fixture_scan.analyze_python_bytes", analyze)
    args = ["--fixture", "clean", "--format", "json"]
    if retained:
        args += ["--state-dir", str(tmp_path / "state")]
    assert main(args) == 3
    report = _read_report(capsys)
    assert report["status"] == ("failed" if failure == "analyzer" else "incomplete")
    assert report["phase"] == ("failed" if failure == "analyzer" else "closed")
    assert report["reason_code"] == ("analyzer_failed" if failure == "analyzer" else "parse_failures")
    assert report["candidate_count"] == 0
    assert report["parse_failure_count"] == (0 if failure == "analyzer" else 1)
    if failure == "parse":
        assert report["parse_failures"][0]["reason_code"] == "python_syntax_error"


@pytest.mark.parametrize("outcome", ["refused", "cancelled", "timed_out", "budget_exhausted"])
@pytest.mark.parametrize("output_format", ["text", "json"])
def test_other_retained_terminal_states_keep_distinct_status_and_nonzero_exit(
    tmp_path, monkeypatch, capsys, outcome, output_format,
):
    overrides = {"max_candidates": 0 if outcome == "refused" else 1} if outcome in {
        "refused", "budget_exhausted",
    } else None
    setup = _setup(tmp_path, grant_overrides=overrides)
    ticks = iter((0, 61_000_000_001))
    with SQLiteEventStore(tmp_path / "events.sqlite3") as store:
        projection = _run(store, setup, cancel_requested=outcome == "cancelled",
                          monotonic_ns=(lambda: next(ticks)) if outcome == "timed_out" else None)
    assert projection.phase.value == outcome
    monkeypatch.setattr("etzio.scan._execute", lambda *args: (projection, setup[1], "vulnerable_app.py"))
    assert main(["--format", output_format]) == 3
    if output_format == "json":
        report = _read_report(capsys)
        assert report["status"] == outcome
        assert report["reason_code"] == projection.terminal_event.payload["reason_code"]
    else:
        assert f"scan status      : {outcome}" in capsys.readouterr().out


@pytest.mark.parametrize("length", [1, 2, 3, 11])
def test_valid_nonterminal_prefix_never_becomes_success(tmp_path, monkeypatch, capsys, length):
    setup = _setup(tmp_path)
    with SQLiteEventStore(tmp_path / "events.sqlite3") as store:
        completed = _run(store, setup)
    projection = reduce_events(completed.events[:length])
    assert not projection.is_terminal
    monkeypatch.setattr("etzio.scan._execute", lambda *args: (projection, setup[1], "vulnerable_app.py"))
    assert main(["--format", "json"]) == 3
    report = _read_report(capsys)
    assert report["status"] == "incomplete"
    assert report["phase"] == projection.phase.value
    assert report["candidate_count"] == len(projection.candidate_events)


@pytest.mark.parametrize("retained", [False, True])
@pytest.mark.parametrize("error_type", [OSError, RuntimeError, ValueError])
def test_operational_failure_emits_no_result_in_either_retention_mode(
    tmp_path, monkeypatch, capsys, retained, error_type,
):
    def fail(*args):
        raise error_type("owned operational failure")

    monkeypatch.setattr("etzio.scan._execute", fail)
    args = ["--format", "json"]
    if retained:
        args += ["--state-dir", str(tmp_path / "state")]
    assert main(args) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "owned operational failure" in captured.err


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit])
def test_interruption_does_not_turn_into_a_result(monkeypatch, capsys, interruption):
    original = interruption("owned interruption")

    def fail(*args):
        raise original

    monkeypatch.setattr("etzio.scan._execute", fail)
    with pytest.raises(interruption) as caught:
        main(["--format", "json"])
    assert caught.value is original
    assert capsys.readouterr().out == ""


def test_json_output_preserves_scope_refusal(capsys):
    with pytest.raises(SystemExit) as caught:
        main(["--format", "json", "/tmp/unadmitted-target"])
    assert caught.value.code == 2
    assert capsys.readouterr().out == ""


def test_bad_durable_replay_has_no_success_report(monkeypatch, capsys):
    load = SQLiteEventStore.load

    def substituted(store, mission_id):
        events = load(store, mission_id)
        return events[:-1] if events and events[-1].kind == "mission_closed" else events

    monkeypatch.setattr(SQLiteEventStore, "load", substituted)
    assert main(["--format", "json"]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "durable replay differs" in output.err


def test_report_uses_replayed_state_instead_of_a_returned_projection_cache(monkeypatch, capsys):
    from etzio.scan import run_fixture_scan

    def misleading(*args, **kwargs):
        projection = run_fixture_scan(*args, **kwargs)
        return replace(projection, candidate_events=())

    monkeypatch.setattr("etzio.scan.run_fixture_scan", misleading)
    assert main(["--format", "json"]) == 0
    assert _read_report(capsys)["candidate_count"] == 7


def test_ephemeral_cleanup_failure_prevents_report_emission(monkeypatch, capsys):
    import tempfile

    cleanup = tempfile.TemporaryDirectory.cleanup

    def fail_after_cleanup(directory):
        cleanup(directory)
        raise OSError("owned temporary cleanup failure")

    monkeypatch.setattr(tempfile.TemporaryDirectory, "cleanup", fail_after_cleanup)
    assert main(["--fixture", "clean", "--format", "json"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "owned temporary cleanup failure" in captured.err


def test_report_write_failure_does_not_return_success(monkeypatch, capsys):
    import builtins

    original = builtins.print

    def failing_stdout(*args, **kwargs):
        if "file" not in kwargs:
            raise BrokenPipeError("owned report delivery failure")
        return original(*args, **kwargs)

    monkeypatch.setattr(builtins, "print", failing_stdout)
    assert main(["--fixture", "clean", "--format", "json"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "owned report delivery failure" in captured.err
