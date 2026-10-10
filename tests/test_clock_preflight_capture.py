"""Capture recovery is exact and ambiguity-refusing, not host or clock attestation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import extract_clock_preflight as extractor

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "docs/evidence/clock-preflight-2026-10-10.json"
COLLECTOR = ROOT / "scripts/collect_clock_preflight.py"


def retained():
    return json.loads(EVIDENCE.read_bytes())


def test_recover_retained_noisy_frame_and_recompute_observations():
    evidence = retained()
    source = COLLECTOR.read_bytes()
    extraction = extractor.extract(evidence["capture_utf8"].encode(), source)
    observation = extraction.pop("record")
    assert extraction == evidence["extraction"]
    assert extraction["interleaved_lines"] == 19
    assert observation["collector_sha256"] == evidence["collector_sha256"]
    assert observation["ptp_devices"] == evidence["observed"]["ptp_devices"]
    assert observation["boot_id"] == observation["final_boot_id"]
    for clock, expected in evidence["observed"]["clocks"].items():
        readings = [s[clock] for s in observation["samples"]]
        widths = [r[2] - r[0] for r in readings]
        assert expected == {
            "sample_count": len(readings),
            "bracket_width_ns_min": min(widths),
            "bracket_width_ns_max": max(widths),
            "negative_brackets": sum(w < 0 for w in widths),
            "value_regressions": sum(a[1] > b[1] for a, b in zip(readings, readings[1:], strict=False)),
            "ordinary_wait_delta_ns": observation["ordinary_wait"]["after"][clock][1]
            - observation["ordinary_wait"]["before"][clock][1],
        }
    assert evidence["initial_capture_parser"]["controller_exit"] == 1
    assert evidence["status"] == "observation_recovered_resources_deleted"
    assert set(evidence["cleanup"].values()) == {"verified_absent"}
    assert len(evidence["cleanup_readback"]) == 5
    assert [r["argv"][1 : r["argv"].index("list")] for r in evidence["cleanup_readback"]] == [
        ["instances"],
        ["disks"],
        ["firewall-rules"],
        ["networks", "subnets"],
        ["networks"],
    ]
    assert all(r["exit"] == 0 and json.loads(r["stdout"]) == [] for r in evidence["cleanup_readback"])
    assert evidence["cost"]["actual_billed_cost"] is None
    assert not evidence["instance_configuration"]["serviceAccounts"]
    assert not evidence["instance_configuration"]["networkInterfaces"][0]["accessConfigs"]


@pytest.mark.parametrize(
    "change",
    [
        "no_begin",
        "no_end",
        "two_begins",
        "two_ends",
        "reversed",
        "two_records",
        "malformed",
        "wrong_schema",
        "wrong_source",
        "missing_sample",
        "duplicate_key",
        "nan",
        "infinity",
        "oversize_capture",
        "oversize_record",
    ],
)
def test_ambiguous_incomplete_or_changed_capture_refused(change):
    capture = retained()["capture_utf8"].encode()
    source = COLLECTOR.read_bytes()
    original = next(line for line in capture.splitlines() if line.startswith(b"{"))
    if change == "no_begin":
        capture = capture.replace(extractor.BEGIN, b"")
    elif change == "no_end":
        capture = capture.replace(extractor.END, b"")
    elif change == "two_begins":
        capture = extractor.BEGIN + b"\n" + capture
    elif change == "two_ends":
        capture += b"\n" + extractor.END
    elif change == "reversed":
        capture = extractor.END + b"\n" + original + b"\n" + extractor.BEGIN
    elif change == "two_records":
        capture = capture.replace(original, original + b"\n" + original)
    elif change == "malformed":
        capture = capture.replace(original, b"{broken JSON")
    elif change == "wrong_source":
        source += b"\n"
    elif change == "duplicate_key":
        capture = capture.replace(original, b'{"schema":"duplicate",' + original[1:])
    elif change in ("nan", "infinity"):
        capture = capture.replace(b"1e-09", b"NaN" if change == "nan" else b"1e999")
    elif change == "oversize_capture":
        capture = b" " * (extractor.MAX_CAPTURE + 1)
    elif change == "oversize_record":
        capture = extractor.BEGIN + b"\n{" + b" " * 131072 + b"}\n" + extractor.END
    else:
        value = json.loads(original)
        if change == "wrong_schema":
            value["schema"] += ".future"
        else:
            value["samples"].pop()
        capture = capture.replace(original, json.dumps(value).encode())
    with pytest.raises(ValueError):
        extractor.extract(capture, source)
