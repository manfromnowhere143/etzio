"""Owned inert source records exercise documentary identity, never execution."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from scripts import inspect_source_provenance as inspector


def wire(value):
    return json.dumps(value, ensure_ascii=True).encode()


def artifact(data):
    return {"size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "bytes_base64": base64.b64encode(data).decode()}


def manifest(left=b"owned fixture\n", right="owned fixture\n"):
    metadata = {"sources": {"src/Owned.sol": {"content": right}}}
    return {"schema": inspector.SCHEMA, "scope": ["src/Owned.sol"],
            "left": {"label": "owned.snapshot", "kind": "source_bundle",
                     "sources": [{"path": "src/Owned.sol", **artifact(left)}]},
            "right": {"label": "owned.publisher", "kind": "hardhat_deployment",
                      "document": artifact(wire({"metadata": json.dumps(metadata)}))}}


def set_sources(body, sources):
    body["right"]["document"] = artifact(wire({"metadata": json.dumps({"sources": sources})}))


def test_replay_is_networkless_timeless_and_does_not_execute_source(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("documentary inspection used an external effect")

    for owner, names in [(socket, ["socket", "create_connection", "getaddrinfo"]),
                         (subprocess, ["Popen", "run"]), (time, ["time", "monotonic", "perf_counter"])]:
        for name in names:
            monkeypatch.setattr(owner, name, forbidden)
    raw = wire(manifest())
    first = inspector.inspect_source_provenance(raw)
    assert first == inspector.inspect_source_provenance(raw)
    assert first["counts"] == {"equal": 1, "different": 0, "unknown": 0}
    assert first["all_requested_sources_equal"] is True
    for flag in ("kernel_authority", "bytecode_reproduced", "chain_state_verified",
                 "audit_coverage_established", "metadata_keccak_validated"):
        assert first[flag] is False


@pytest.mark.parametrize(("left", "right"), [
    (b"before", "after"), (b"a\r\n", "a\n"), ("e\u0301".encode(), "\u00e9"),
    (b"a ", "a"), (b"// comment\na", "a"), (b"\xff", "\ufffd"),
])
def test_byte_differences_never_disappear_through_normalization(left, right):
    report = inspector.inspect_source_provenance(wire(manifest(left, right)))
    assert report["counts"] == {"equal": 0, "different": 1, "unknown": 0}
    assert report["all_requested_sources_equal"] is False


@pytest.mark.parametrize("availability", ["absent", "url_only", "empty"])
def test_empty_source_missing_entry_and_unavailable_literal_are_distinct(availability):
    body = manifest(b"", "")
    sources = {"src/Owned.sol": {"content": ""}}
    if availability == "absent":
        sources = {}
    elif availability == "url_only":
        sources = {"src/Owned.sol": {"urls": ["https://fixture.invalid/must-not-fetch"]}}
    set_sources(body, sources)
    report = inspector.inspect_source_provenance(wire(body))
    row = report["sources"][0]
    assert row["left"]["state"] == "available" and row["left"]["size_bytes"] == 0
    assert row["right"]["state"] == {"absent": "absent", "url_only": "literal_content_unavailable",
                                      "empty": "available"}[availability]
    assert row["state"] == ("equal" if availability == "empty" else "unknown")
    assert report["all_requested_sources_equal"] is (availability == "empty")


def test_mixed_difference_and_missing_evidence_remain_visible():
    body = manifest(b"first", "second")
    body["scope"].append("src/Missing.sol")
    report = inspector.inspect_source_provenance(wire(body))
    assert report["counts"] == {"equal": 0, "different": 1, "unknown": 1}
    assert report["scope"] == ["src/Missing.sol", "src/Owned.sol"]
    assert report["sources"][0]["left"] == report["sources"][0]["right"] == {"state": "absent"}


def test_changed_scope_and_capture_encoding_have_distinct_identities():
    body = manifest()
    first = inspector.inspect_source_provenance(wire(body))
    second = inspector.inspect_source_provenance(wire(body) + b"\n")
    assert first["sources"] == second["sources"]
    assert first["manifest_sha256"] != second["manifest_sha256"]
    body["scope"].append("src/Absent.sol")
    third = inspector.inspect_source_provenance(wire(body))
    assert third["all_requested_sources_equal"] is False
    assert third["manifest_sha256"] != first["manifest_sha256"]


@pytest.mark.parametrize("damage", ["bytes", "digest", "size", "boolean_size", "base64", "padding"])
def test_bound_artifact_refuses_inconsistent_capture(damage):
    body = manifest(b"\x00", "\x00")
    entry = body["left"]["sources"][0]
    entry.update({"bytes": {"bytes_base64": "AQ=="}, "digest": {"sha256": "0" * 64},
                  "size": {"size_bytes": 2}, "boolean_size": {"size_bytes": True},
                  "base64": {"bytes_base64": "!!!!"}, "padding": {"bytes_base64": "AB=="}}[damage])
    with pytest.raises(inspector.InspectionError):
        inspector.inspect_source_provenance(wire(body))


@pytest.mark.parametrize("path", ["/src/A.sol", "src/../A.sol", "./A.sol", "src//A.sol", "src/A.sol/",
                                 "src\\A.sol", "src/\u00e9.sol", "a\n.sol", "a\x00.sol", "a" * 513])
def test_ambiguous_source_path_refused(path):
    body = manifest()
    body["scope"] = [path]
    with pytest.raises(inspector.InspectionError, match="source_path"):
        inspector.inspect_source_provenance(wire(body))


@pytest.mark.parametrize("damage", ["duplicate_scope", "duplicate_source", "empty_scope", "schema",
                                   "extra_field", "source_kind", "literal_type", "metadata_type"])
def test_closed_shapes_refuse_unsupported_or_vacuous_claims(damage):
    body = manifest()
    if damage == "duplicate_scope":
        body["scope"] *= 2
    elif damage == "duplicate_source":
        body["left"]["sources"] *= 2
    elif damage == "empty_scope":
        body["scope"] = []
    elif damage == "schema":
        body["schema"] = "other"
    elif damage == "extra_field":
        body["kernel_authority"] = True
    elif damage == "source_kind":
        body["right"]["kind"] = "execute"
    elif damage == "literal_type":
        set_sources(body, {"src/Owned.sol": {"content": None}})
    else:
        body["right"]["document"] = artifact(wire({"metadata": {"sources": {}}}))
    with pytest.raises(inspector.InspectionError):
        inspector.inspect_source_provenance(wire(body))


@pytest.mark.parametrize("layer", ["manifest", "document", "metadata"])
def test_duplicate_json_keys_refused_at_every_document_layer(layer):
    body = manifest()
    if layer == "manifest":
        raw = wire(body)[:-1] + b',"scope":[]}'
    elif layer == "document":
        body["right"]["document"] = artifact(b'{"metadata":"{}","metadata":"{}"}')
        raw = wire(body)
    else:
        metadata = '{"sources":{"src/Owned.sol":{"content":"first"},"src/Owned.sol":{"content":"second"}}}'
        body["right"]["document"] = artifact(wire({"metadata": metadata}))
        raw = wire(body)
    with pytest.raises(inspector.InspectionError, match="duplicate_json_key"):
        inspector.inspect_source_provenance(raw)


@pytest.mark.parametrize("raw", [b"\xff", b'{"a":NaN}', b'{"a":1.5}', br'{"a":"\ud800"}',
                                b"[" * 40 + b"0" + b"]" * 40])
def test_malformed_or_excessively_deep_json_refused(raw):
    with pytest.raises(inspector.InspectionError):
        inspector.inspect_source_provenance(raw)


def test_bounded_inputs_sources_and_nodes():
    with pytest.raises(inspector.InspectionError, match="json_size"):
        inspector.inspect_source_provenance(b" " * (inspector.MAX_MANIFEST_BYTES + 1))
    body = manifest()
    body["scope"] = [f"src/{i}.sol" for i in range(inspector.MAX_SOURCES + 1)]
    with pytest.raises(inspector.InspectionError, match="scope_size"):
        inspector.inspect_source_provenance(wire(body))
    body = manifest(b"a" * (inspector.MAX_SOURCE_BYTES + 1))
    with pytest.raises(inspector.InspectionError, match="artifact_size"):
        inspector.inspect_source_provenance(wire(body))
    with pytest.raises(inspector.InspectionError, match="json_nodes"):
        inspector.inspect_source_provenance(wire([None] * inspector.MAX_NODES))


def test_side_order_and_input_hash_changes_are_not_hidden():
    body = manifest(b"left", "right")
    first = inspector.inspect_source_provenance(wire(body))
    swapped = copy.deepcopy(body)
    swapped["left"], swapped["right"] = swapped["right"], swapped["left"]
    second = inspector.inspect_source_provenance(wire(swapped))
    assert first["counts"] == second["counts"] == {"equal": 0, "different": 1, "unknown": 0}
    assert first["manifest_sha256"] != second["manifest_sha256"]
    assert first["sources"][0]["left"] == second["sources"][0]["right"]


@pytest.mark.parametrize("boundary", ["document", "literal", "bundle_count", "metadata_count"])
def test_each_input_adapter_enforces_its_own_bound(boundary):
    body = manifest()
    if boundary == "document":
        body["right"]["document"] = artifact(b" " * (inspector.MAX_ARTIFACT_BYTES + 1))
    elif boundary == "literal":
        set_sources(body, {"src/Owned.sol": {"content": "a" * (inspector.MAX_SOURCE_BYTES + 1)}})
    elif boundary == "bundle_count":
        body["left"]["sources"] = [{"path": f"src/{i}.sol", **artifact(b"")}
                                    for i in range(inspector.MAX_SOURCES + 1)]
    else:
        set_sources(body, {f"src/{i}.sol": {"content": ""}
                           for i in range(inspector.MAX_SOURCES + 1)})
    with pytest.raises(inspector.InspectionError, match="artifact_size|source_size|source_count"):
        inspector.inspect_source_provenance(wire(body))


@pytest.mark.parametrize("missing", [False, True])
def test_cli_retains_difference_or_unknown_and_refuses_invalid_input(tmp_path, missing):
    path = tmp_path / "manifest.json"
    body = manifest(b"one", "two")
    if missing:
        set_sources(body, {})
    path.write_bytes(wire(body))
    script = Path(__file__).resolve().parents[1] / "scripts/inspect_source_provenance.py"
    result = subprocess.run([sys.executable, str(script), str(path)], capture_output=True, check=False)
    assert result.returncode == 0
    assert json.loads(result.stdout) == inspector.inspect_source_provenance(path.read_bytes())
    path.write_bytes(b"{}")
    result = subprocess.run([sys.executable, str(script), str(path)], capture_output=True, check=False)
    assert result.returncode == 2 and result.stdout == b""
