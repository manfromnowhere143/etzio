"""Historical authentication must never become a request-freshness or authority claim."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import socket
from pathlib import Path
from types import SimpleNamespace

import pytest
from asn1crypto import cms, tsp
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import Encoding

from scripts import compare_archived_timestamp as comparison
from scripts import inspect_archived_timestamp as inspector

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs/evidence/archived-microsoft-timestamp-2026-10-10.json"
REPORT = ROOT / "docs/evidence/archived-timestamp-comparison-2026-10-10.json"


def body():
    return json.loads(MANIFEST.read_bytes())


def wire(value):
    return json.dumps(value).encode()


def inspect(value):
    return asyncio.run(inspector.inspect_timestamp(wire(value)))


def replace(entry, data):
    entry.update(size=len(data), sha256=inspector.sha(data), der_base64=base64.b64encode(data).decode())


def test_offline_replay_and_local_typing_preserve_native_refusal(monkeypatch):
    # Create the event loop before forbidding sockets (asyncio itself uses a socketpair).
    loop = asyncio.new_event_loop()
    try:

        def forbidden(*args, **kwargs):
            pytest.fail("diagnostic attempted network access")

        monkeypatch.setattr(socket, "socket", forbidden)
        monkeypatch.setattr(socket, "create_connection", forbidden)
        monkeypatch.setattr(socket, "getaddrinfo", forbidden)
        material, _ = inspector.decode_manifest(MANIFEST.read_bytes())
        for _ in range(2):
            with pytest.raises(ValueError):
                inspector._canonical_der(tsp.TimeStampResp, material["response"])
            report = loop.run_until_complete(inspector.inspect_timestamp(MANIFEST.read_bytes()))
        retained = json.loads(REPORT.read_bytes())
        assert report == retained["inspection"]
        assert retained["inspector_sha256"] == inspector.sha(Path(inspector.__file__).read_bytes())
        assert retained["comparator_sha256"] == inspector.sha(Path(comparison.__file__).read_bytes())
        assert retained["dependency_lock_sha256"] == inspector.sha(
            (ROOT / "tools/ci/requirements-ci.lock").read_bytes()
        )
        assert report["claimed_accuracy_microseconds"] == 500000
        assert report["issuance_interval_microseconds"] == [1791547400297000, 1791547401297000]
        for key in (
            "root_admitted",
            "original_request_retained",
            "challenge_freshness_established",
            "current_revocation_established",
            "accuracy_independently_measured",
            "signer_attribute_certificate_trust_checked",
            "kernel_authority",
        ):
            assert report[key] is False
    finally:
        loop.close()


@pytest.mark.parametrize("index", range(6))
def test_signature_mutation_cannot_be_laundered_through_manifest_hash(index):
    value = body()
    entry = value["artifacts"][index]
    data = base64.b64decode(entry["der_base64"])
    replace(entry, data[:-1] + bytes([data[-1] ^ 1]))
    with pytest.raises((ValueError, InvalidSignature)):
        inspect(value)


@pytest.mark.parametrize("index", range(6))
def test_appended_der_refused(index):
    value = body()
    entry = value["artifacts"][index]
    replace(entry, base64.b64decode(entry["der_base64"]) + b"\0")
    with pytest.raises(ValueError):
        inspect(value)


@pytest.mark.parametrize("change", ["missing", "extra", "swapped", "duplicate", "foreign_field", "wrong_schema"])
def test_closed_manifest(change):
    value = body()
    if change == "missing":
        value["artifacts"].pop()
    elif change == "extra":
        value["artifacts"].append(value["artifacts"][0])
    elif change == "swapped":
        value["artifacts"][3:5] = value["artifacts"][4:2:-1]
    elif change == "duplicate":
        value["artifacts"][4] = value["artifacts"][3]
    elif change == "foreign_field":
        value["kernel_authority"] = True
    else:
        value["schema"] += ".future"
    with pytest.raises(ValueError):
        inspect(value)


@pytest.mark.parametrize("change", ["digest", "size", "boolean_size", "oversize", "base64", "extra_field"])
def test_manifest_integrity_before_asn1(change, monkeypatch):
    value = body()
    entry = value["artifacts"][0]
    if change == "digest":
        entry["sha256"] = "0" * 64
    elif change == "size":
        entry["size"] -= 1
    elif change == "boolean_size":
        entry["size"] = True
    elif change == "oversize":
        entry["size"] = 16385
    elif change == "base64":
        entry["der_base64"] = "!" + entry["der_base64"][1:]
    else:
        entry["ignored"] = True
    monkeypatch.setattr(inspector, "_parse", lambda _: pytest.fail("parser reached"))
    with pytest.raises(ValueError):
        inspect(value)


def test_manifest_duplicate_json_and_size_bounds(tmp_path):
    with pytest.raises(ValueError):
        inspector.decode_manifest(b'{"schema":"a","schema":"b"}')
    path = tmp_path / "large.json"
    path.write_bytes(b" " * (inspector.MAX_MANIFEST_BYTES + 1))
    with pytest.raises(ValueError, match="manifest size"):
        inspector.load_manifest(path)


@pytest.mark.parametrize("imprint", ["00" * 32, "F" * 64, True, "00", None])
def test_imprint_refusals(imprint):
    value = body()
    value["expected_imprint_sha256"] = imprint
    with pytest.raises(ValueError):
        inspect(value)


@pytest.mark.parametrize(
    "change",
    [
        "serial",
        "missing_cert",
        "duplicate_cert",
        "extra_cert",
        "unsigned",
        "duplicate_attr",
        "ess_hash",
        "content_digest",
        "signature_algorithm",
        "digest_algorithm",
        "two_certified_attributes",
    ],
)
def test_cms_bindings_refuse_before_signature_validation(change):
    value = body()
    entry = value["artifacts"][-1]
    response = inspector._canonical_response(base64.b64decode(entry["der_base64"]))
    sd = response["time_stamp_token"]["content"]
    si = sd["signer_infos"][0]
    attrs = si["signed_attrs"]
    by_oid = {a["type"].dotted: a for a in attrs}
    if change == "serial":
        si["sid"].chosen["serial_number"] = 1
    elif change == "missing_cert":
        sd["certificates"] = [sd["certificates"][0]]
    elif change == "duplicate_cert":
        sd["certificates"] = [sd["certificates"][0], sd["certificates"][0]]
    elif change == "extra_cert":
        sd["certificates"] = list(sd["certificates"]) + [sd["certificates"][0]]
    elif change == "unsigned":
        si["unsigned_attrs"] = [cms.CMSAttribute({"type": "message_digest", "values": [b"x"]})]
    elif change == "duplicate_attr":
        si["signed_attrs"] = list(attrs) + [attrs[0]]
    elif change == "ess_hash":
        by_oid["1.2.840.113549.1.9.16.2.47"]["values"][0]["certs"][0]["cert_hash"] = b"\0" * 32
    elif change == "content_digest":
        by_oid["1.2.840.113549.1.9.4"]["values"][0] = b"\0" * 32
    elif change == "signature_algorithm":
        si["signature_algorithm"]["algorithm"] = "sha256_rsa"
    elif change == "digest_algorithm":
        si["digest_algorithm"]["algorithm"] = "sha384"
    else:
        attr = by_oid["1.2.840.113549.1.9.16.2.18"]
        inner = attr["values"][0].parsed
        attr["values"] = [inspector.SignerAttribute([inner[0], inner[0]])]
    replace(entry, response.dump(force=True))
    with pytest.raises(ValueError):
        inspect(value)


def test_full_crl_interval_boundaries():
    material, _ = inspector.decode_manifest(MANIFEST.read_bytes())
    _, certs, _, crls = inspector._parse(material)
    lower = max(inspector._micros(c.last_update_utc) for c in crls)
    upper = min(inspector._micros(c.next_update_utc) for c in crls)
    inspector._validity(certs, crls, lower, upper - 1)
    for lo, hi in [(lower - 1, lower), (lower, upper), (upper, lower)]:
        with pytest.raises(ValueError):
            inspector._validity(certs, crls, lo, hi)


def test_contexts_are_fresh_offline_zero_tolerance(monkeypatch):
    original = inspector.ValidationContext
    calls = []

    def context(**kwargs):
        result = original(**kwargs)
        calls.append((result, kwargs))
        return result

    monkeypatch.setattr(inspector, "ValidationContext", context)
    inspect(body())
    assert len(calls) == 2 and calls[0][0] is not calls[1][0]
    for _, kwargs in calls:
        assert kwargs["moment"] == kwargs["best_signature_time"]
        assert not kwargs["allow_fetching"] and not kwargs["retroactive_revinfo"]
        assert kwargs["revocation_mode"] == "require" and kwargs["time_tolerance"].total_seconds() == 0


def test_original_archive_and_publisher_correspondence():
    sources = json.loads((ROOT / "docs/evidence/archived-timestamp-sources-2026-10-10.json").read_bytes())
    archive = (ROOT / sources["archive"]["retained_path"]).read_bytes()
    assert len(archive) == sources["archive"]["size"] < 102400
    assert inspector.sha(archive) == sources["archive"]["sha256"]
    assert (
        hashlib.sha1(b"blob " + str(len(archive)).encode() + b"\0" + archive).hexdigest()
        == sources["archive"]["git_blob_sha1"]
    )
    parsed = json.loads(archive)
    selected = parsed["timestamps"][4]
    material, imprint = inspector.decode_manifest(MANIFEST.read_bytes())
    assert imprint.hex() == parsed["hash"]["digest"]
    assert base64.b64decode(selected["reply"]) == material["response"]
    assert (
        x509.load_pem_x509_certificate(base64.b64decode(selected["ca"])).public_bytes(Encoding.DER)
        == material["root_certificate"]
    )
    assert inspector.sha(material["root_certificate"]) == sources["publisher_root"]["sha256"]
    crls = {x509.load_der_x509_crl(base64.b64decode(c)).public_bytes(Encoding.DER) for c in selected["crls"]}
    assert crls == {material["root_crl"], material["issuer_crl"]}


def test_retained_openssl_outcomes_are_specific():
    retained = json.loads(REPORT.read_bytes())
    assert retained["manifest_sha256"] == inspector.sha(MANIFEST.read_bytes())
    assert retained["openssl_sha256"] == comparison.OPENSSL_SHA256
    assert retained["openssl_version"] == comparison.OPENSSL_VERSION
    assert len(retained["results"]) == 9
    for result, (name, codes, reason) in zip(retained["results"], comparison.CASES, strict=True):
        assert name == result["case"] and codes == result["error_codes"]
        comparison.check_outcome(SimpleNamespace(**result), codes, reason)
    assert [r["command"][-1] for r in retained["results"][:2]] == ["1791547400", "1791547402"]


@pytest.mark.parametrize("change", ["crash", "wrong_code", "wrong_reason", "bad_option", "extra_diagnostic"])
def test_comparator_does_not_count_arbitrary_failures(change):
    result = json.loads(REPORT.read_bytes())["results"][-1]
    if change == "crash":
        result["returncode"] = -9
    elif change == "wrong_code":
        result["stderr"] = result["stderr"].replace("17800064", "17800065")
    elif change == "wrong_reason":
        result["stderr"] = result["stderr"].replace("unable to get certificate CRL", "certificate expired")
    elif change == "bad_option":
        result["stderr"] = "Unknown option"
        result["stdout"] = ""
    else:
        result["stderr"] += "unexpected diagnostic\n"
    with pytest.raises(ValueError):
        comparison.check_outcome(SimpleNamespace(**result), ["17800064"], "Verify error:unable to get certificate CRL")


def test_comparator_refuses_unpinned_binary_before_execution(tmp_path, monkeypatch):
    binary = tmp_path / "openssl"
    binary.write_bytes(b"not the pinned tool")
    monkeypatch.setattr(comparison.subprocess, "run", lambda *a, **k: pytest.fail("untrusted tool invoked"))
    with pytest.raises(ValueError, match="executable digest"):
        comparison.compare(MANIFEST.read_bytes(), binary)
