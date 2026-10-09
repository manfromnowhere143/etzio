"""Public artifact diagnostics cannot confer provider or clock authority."""

from __future__ import annotations

import base64
import hashlib
import json
import socket
import subprocess
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature

from scripts import inspect_published_tsa_material as inspector

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs/evidence/published-tsa-material-2026-10-09.json"
COMPARISON = ROOT / "docs/evidence/published-tsa-comparison-2026-10-09.json"


def body():
    return json.loads(MANIFEST.read_bytes())


def wire(value):
    return json.dumps(value).encode()


def replace_der(entry, data):
    entry.update(size=len(data), sha256=hashlib.sha256(data).hexdigest(), der_base64=base64.b64encode(data).decode())


def test_replay_exact_report_without_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("offline inspector attempted network access")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    report = inspector.inspect_material(MANIFEST.read_bytes())
    retained = json.loads(COMPARISON.read_bytes())
    assert report == retained["inspection"]
    assert retained["manifest_sha256"] == inspector.sha(MANIFEST.read_bytes())
    assert retained["inspector_sha256"] == inspector.sha(
        (ROOT / "scripts/inspect_published_tsa_material.py").read_bytes()
    )
    assert retained["dependency_lock_sha256"] == inspector.sha((ROOT / "tools/ci/requirements-ci.lock").read_bytes())
    assert [x["key_bits"] for x in report["certificates"]] == [4096, 3072, 4096]
    assert report["certificates"][-1]["content_commitment"] is True
    assert all(c["covers_reference_half_open"] and not c["subject_serial_listed"] for c in report["crls"])
    assert all(c["expired_certs_on_crl"] == "2020-10-05T00:00:00+00:00" for c in report["crls"])
    for key in ("root_admitted", "current_service_signer_observed", "timestamp_token_verified", "kernel_authority"):
        assert report[key] is False
    assert len(retained["results"]) == 9
    assert [(r["returncode"] == 0) for r in retained["results"]] == [True] + [False] * 8


@pytest.mark.parametrize("index", range(5))
def test_altered_signature_refused_even_with_recomputed_manifest_digest(index):
    manifest = body()
    entry = manifest["artifacts"][index]
    data = base64.b64decode(entry["der_base64"])
    replace_der(entry, data[:-1] + bytes([data[-1] ^ 1]))
    with pytest.raises((ValueError, InvalidSignature)):
        inspector.inspect_material(wire(manifest))


@pytest.mark.parametrize("index", range(5))
def test_appended_der_bytes_refused_with_recomputed_manifest_digest(index):
    manifest = body()
    entry = manifest["artifacts"][index]
    replace_der(entry, base64.b64decode(entry["der_base64"]) + b"\x00")
    with pytest.raises(ValueError):
        inspector.inspect_material(wire(manifest))


@pytest.mark.parametrize("change", ["missing", "extra", "swapped", "duplicate", "foreign_field", "wrong_schema"])
def test_closed_manifest_and_role_coverage(change):
    manifest = body()
    if change == "missing":
        manifest["artifacts"].pop()
    elif change == "extra":
        manifest["artifacts"].append(manifest["artifacts"][0])
    elif change == "swapped":
        manifest["artifacts"][3:5] = manifest["artifacts"][4:2:-1]
    elif change == "duplicate":
        manifest["artifacts"][4] = manifest["artifacts"][3]
    elif change == "foreign_field":
        manifest["kernel_authority"] = True
    else:
        manifest["schema"] += ".future"
    with pytest.raises(ValueError):
        inspector.inspect_material(wire(manifest))


@pytest.mark.parametrize("index", range(5))
def test_role_laundering_refused_after_swapping_only_bytes(index):
    manifest = body()
    entry = manifest["artifacts"][index]
    other = (index + 1) % 5
    replacement = base64.b64decode(manifest["artifacts"][other]["der_base64"])
    replace_der(entry, replacement)
    with pytest.raises(ValueError):
        inspector.inspect_material(wire(manifest))


@pytest.mark.parametrize("change", ["digest", "size", "boolean_size", "oversize", "base64", "extra_field"])
def test_artifact_integrity_and_bounds_before_parser(change, monkeypatch):
    manifest = body()
    entry = manifest["artifacts"][0]
    if change == "digest":
        entry["sha256"] = "0" * 64
    elif change == "size":
        entry["size"] -= 1
    elif change == "boolean_size":
        entry["size"] = True
    elif change == "oversize":
        entry["size"] = inspector.MAX_ARTIFACT_BYTES + 1
    elif change == "base64":
        entry["der_base64"] = "!" + entry["der_base64"][1:]
    else:
        entry["ignored"] = "never"
    monkeypatch.setattr(inspector, "_parse", lambda _: pytest.fail("parser reached before manifest validation"))
    with pytest.raises(ValueError):
        inspector.inspect_material(wire(manifest))


@pytest.mark.parametrize("second", [True, -1, 253402300800, "1791555586", 1.5])
def test_invalid_reference(second):
    manifest = body()
    manifest["reference_second"] = second
    with pytest.raises(ValueError):
        inspector.inspect_material(wire(manifest))


def test_duplicate_json_key_and_oversize_manifest_refused(tmp_path):
    with pytest.raises(ValueError):
        inspector.decode_manifest(b'{"schema":"a","schema":"b"}')
    path = tmp_path / "oversized.json"
    path.write_bytes(b" " * (inspector.MAX_MANIFEST_BYTES + 1))
    with pytest.raises(ValueError):
        inspector.load_manifest(path)


@pytest.mark.parametrize(("second", "expected"), [(1791555585, False), (1791555586, True), (1792129331, False)])
def test_time_is_diagnostic_and_crl_expiry_is_half_open(second, expected):
    manifest = body()
    manifest["reference_second"] = second
    report = inspector.inspect_material(wire(manifest))
    assert all(c["covers_reference_half_open"] for c in report["crls"]) is expected
    assert report["kernel_authority"] is False
    assert report["root_admitted"] is False


def test_wrong_openssl_pin_refused_before_subprocess(monkeypatch, tmp_path):
    executable = tmp_path / "not-a-real-openssl"
    executable.write_bytes(b"does not execute")
    monkeypatch.setattr(inspector.subprocess, "run", lambda *a, **kw: pytest.fail("unverified executable reached"))
    with pytest.raises(ValueError, match="digest differs"):
        inspector.openssl_comparison(MANIFEST.read_bytes(), executable, "0" * 64)


@pytest.mark.parametrize(
    ("returncode", "stderr"),
    [
        (-9, ""),
        (1, "unknown option"),
        (2, "error 12 at 0 depth lookup: CRL has expired\n"),
        (2, "error 7 at 1 depth lookup: certificate signature failure\n"),
        (2, "error 7 at 0 depth lookup: certificate signature failure\nerror 12 at 0 depth lookup: CRL has expired\n"),
    ],
)
def test_tool_failures_and_wrong_reason_are_not_expected_refusals(returncode, stderr):
    result = subprocess.CompletedProcess([], returncode, "", stderr)
    with pytest.raises(ValueError, match="expected verification error"):
        inspector.check_openssl_result(result, (7, 0))


def test_retained_source_bytes_match_the_manifest():
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    source = json.loads((ROOT / "docs/evidence/published-tsa-sources-2026-10-09.json").read_bytes())
    material, _ = inspector.decode_manifest(MANIFEST.read_bytes())
    for captured in (source["search"]["response"], source["tsa_capture"]["response_pem"]):
        data = base64.b64decode(captured["base64"], validate=True)
        assert len(data) == captured["size"] and inspector.sha(data) == captured["sha256"]
    search = json.loads(base64.b64decode(source["search"]["response"]["base64"]))
    assert [row["id"] for row in search] == source["search"]["returned_ids"]
    pem = base64.b64decode(source["tsa_capture"]["response_pem"]["base64"])
    assert x509.load_pem_x509_certificate(pem).public_bytes(serialization.Encoding.DER) == material["tsa_certificate"]
    assert source["tsa_capture"]["der_sha256"] == inspector.sha(material["tsa_certificate"])
    assert source["issuer_crl"]["sha256"] == inspector.sha(material["issuer_issued_crl"])
    prior = json.loads((ROOT / "docs/evidence/provider-preparation-2026-10-09.json").read_bytes())
    for artifact in prior["artifacts"]:
        assert base64.b64decode(artifact["der_base64"]) == material[artifact["role"]]
