"""Adversarial native bytes; all keys, certificates and CRLs are repository fixtures."""

from __future__ import annotations

import asyncio
import socket
from dataclasses import replace
from datetime import timedelta

import pytest
from asn1crypto import cms, core
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, ObjectIdentifier
from native_time_fixtures import EPOCH, ROOT_KEY, NativeFixture, certificate, context, der, fixture, oracle_cases

from etzio.protocol import content_id
from etzio.qualification import rfc3161_v1 as native
from etzio.qualification.rfc3161_v1 import NativeTimeError, validate_rfc3161_offline_v1


@pytest.fixture(scope="module")
def material():
    return fixture()


def validate(material, **changes):
    args = dict(profile=material.profile, request=context(), response_der=material.response(), crl_der=material.crl())
    args.update(changes)
    return asyncio.run(validate_rfc3161_offline_v1(**args))


def refused(material, reason, **changes):
    with pytest.raises(NativeTimeError) as exc:
        validate(material, **changes)
    assert exc.value.reason_code == reason


def test_valid_native_timestamp_retains_exact_dossier_and_replays(material):
    first = validate(material)
    assert first == validate(material)
    assert first.response_der == material.response() == fixture().response()
    assert first.crl_der == material.crl() == fixture().crl()
    assert first.lower_second == 1791547199
    assert first.upper_second == 1791547201
    assert first.to_body()["kernel_authority"] is False
    assert first.observation_id == validate(material).observation_id


@pytest.mark.parametrize(
    ("fraction", "accuracy", "lower", "upper"),
    [
        (0, {"micros": 1}, 1791547199, 1791547201),
        (1, {"micros": 1}, 1791547200, 1791547201),
        (999999, {"micros": 1}, 1791547200, 1791547201),
        (999999, {"micros": 2}, 1791547200, 1791547202),
        (0, {"seconds": 0, "millis": 999, "micros": 999}, 1791547199, 1791547201),
    ],
)
def test_outward_rounding_preserves_complete_uncertainty(material, fraction, accuracy, lower, upper):
    response = material.response(
        info_changes={"gen_time": EPOCH + timedelta(microseconds=fraction), "accuracy": accuracy}
    )
    observation = validate(material, response_der=response)
    assert (observation.lower_second, observation.upper_second) == (lower, upper)
    assert lower * 1_000_000 <= observation.lower_microseconds
    assert upper * 1_000_000 >= observation.upper_microseconds


@pytest.mark.parametrize(
    "field",
    [
        "profile_id",
        "trust_root_id",
        "mission_id",
        "authority_id",
        "target_id",
        "event_digest",
        "transition_intent_id",
        "time_policy_id",
        "imprint_id",
        "service_instance_id",
        "environment_id",
        "purpose",
        "request_nonce",
    ],
)
def test_validly_signed_foreign_context_refused(material, field):
    new = {
        "service_instance_id": "Etzio.foreign",
        "environment_id": "fixture.foreign",
        "purpose": "checkpoint",
        "request_nonce": "ab" * 32,
    }.get(field, content_id("native_time_fixture", {"foreign": field}))
    refused(material, "request_binding", request=context(**{field: new}))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("tsa_policy_oid", "1.3.6.1.4.1.55555.2"),
        ("max_accuracy_microseconds", 3_000_000),
        ("max_crl_age_seconds", 7201),
    ],
)
def test_native_profile_is_bound_into_imprint(material, field, value):
    refused(material, "request_binding", profile=replace(material.profile, **{field: value}))


def test_foreign_source_and_changed_source_profile_refused(material):
    req = context(source_id="fixture.foreign")
    refused(material, "request_binding", request=req)
    refused(material, "request_binding", request=req, profile=replace(material.profile, source_id=req.source_id))


def test_zero_nonce_refused(material):
    refused(material, "request_binding", request=context(request_nonce="0" * 64))


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"nonce": None}, "request_binding"),
        ({"nonce": 1}, "request_binding"),
        ({"policy": "1.2.3.4"}, "request_binding"),
        (
            {"message_imprint": {"hash_algorithm": {"algorithm": "sha256"}, "hashed_message": b"\x01" * 32}},
            "request_binding",
        ),
        (
            {"message_imprint": {"hash_algorithm": {"algorithm": "sha1"}, "hashed_message": b"\x01" * 20}},
            "algorithm_profile",
        ),
        ({"accuracy": None}, "accuracy"),
        ({"accuracy": {"seconds": 0}}, "accuracy"),
        ({"accuracy": {"seconds": -1}}, "accuracy"),
        ({"accuracy": {"seconds": 3}}, "accuracy"),
        ({"accuracy": {"millis": 0}}, "accuracy"),
        ({"accuracy": {"millis": 1000}}, "accuracy"),
        ({"accuracy": {"micros": 0}}, "accuracy"),
        ({"accuracy": {"micros": 1000}}, "accuracy"),
        ({"serial_number": 0}, "tst_profile"),
        ({"serial_number": 2**160}, "tst_profile"),
        ({"version": 2}, "tst_profile"),
        ({"tsa": {"dns_name": "foreign.example"}}, "certificate_binding"),
        ({"tsa": {"directory_name": asn1_x509.Name.build({"common_name": "foreign"})}}, "certificate_binding"),
    ],
)
def test_correctly_signed_bad_timestamp_claims(material, changes, reason):
    refused(material, reason, response_der=material.response(info_changes=changes))


@pytest.mark.parametrize(
    "time_value", ["20261009120000.1234567Z", "20261009120000.100Z", "20261009120000+0000", "202610091200Z"]
)
def test_unsupported_time_encodings_never_truncate(material, time_value):
    refused(
        material,
        "time_encoding",
        response_der=material.response(info_changes={"gen_time": core.GeneralizedTime(time_value)}),
    )


def test_ordering_flag_never_shrinks_interval(material):
    first = validate(material)
    other = validate(material, response_der=material.response(info_changes={"ordering": True}))
    assert (first.lower_microseconds, first.upper_microseconds) == (other.lower_microseconds, other.upper_microseconds)


def _attrs_without(attrs, name):
    return cms.CMSAttributes([attr for attr in attrs if attr["type"].native != name])


@pytest.mark.parametrize("name", ["content_type", "message_digest", "signing_certificate_v2"])
def test_missing_required_signed_attribute(material, name):
    refused(material, "cms_shape", response_der=material.response(attrs_mutator=lambda a: _attrs_without(a, name)))


@pytest.mark.parametrize("name", ["content_type", "message_digest", "signing_certificate_v2"])
def test_duplicate_signed_attribute(material, name):
    def mutation(attrs):
        return cms.CMSAttributes([*attrs, next(a for a in attrs if a["type"].native == name)])

    refused(material, "cms_shape", response_der=material.response(attrs_mutator=mutation))


def test_wrong_ess_certificate_hash(material):
    def mutation(attrs):
        for attr in attrs:
            if attr["type"].native == "signing_certificate_v2":
                attr["values"][0]["certs"][0]["cert_hash"] = b"\x01" * 32
        return attrs

    refused(material, "certificate_binding", response_der=material.response(attrs_mutator=mutation))


def test_sha1_ess_fallback_refused(material):
    def mutation(attrs):
        return cms.CMSAttributes(
            [
                *_attrs_without(attrs, "signing_certificate_v2"),
                {"type": "signing_certificate", "values": [{"certs": [{"cert_hash": b"\x01" * 20}]}]},
            ]
        )

    refused(material, "cms_shape", response_der=material.response(attrs_mutator=mutation))


def test_forged_cms_signature(material):
    refused(material, "signature_or_path", response_der=material.response(signer_key=ROOT_KEY))


def test_tampered_signed_content(material):
    def mutation(sd):
        info = sd["encap_content_info"]["content"].parsed.copy()
        info["serial_number"] = 42
        sd["encap_content_info"]["content"] = info

    refused(material, "signature_or_path", response_der=material.response(sd_mutator=mutation))


@pytest.mark.parametrize(
    "kind", ["extra_signer", "extra_certificate", "missing_certificate", "digest_set", "signer_digest", "sid"]
)
def test_cms_ambiguity_and_signer_substitution(material, kind):
    def mutation(sd):
        if kind == "extra_signer":
            sd["signer_infos"] = [sd["signer_infos"][0], sd["signer_infos"][0]]
        elif kind == "extra_certificate":
            sd["certificates"] = [*sd["certificates"], asn1_x509.Certificate.load(der(material.root))]
        elif kind == "missing_certificate":
            sd["certificates"] = []
        elif kind == "digest_set":
            sd["digest_algorithms"] = [{"algorithm": "sha1"}]
        elif kind == "signer_digest":
            sd["signer_infos"][0]["digest_algorithm"] = {"algorithm": "sha1"}
        elif kind == "sid":
            sd["signer_infos"][0]["sid"].chosen["serial_number"] = 99

    reason = "algorithm_profile" if kind in ("digest_set", "signer_digest") else "cms_shape"
    if kind == "sid":
        reason = "malformed_native_evidence"
    refused(material, reason, response_der=material.response(sd_mutator=mutation))


@pytest.mark.parametrize(
    "status", ["granted_with_mods", "rejection", "waiting", "revocation_warning", "revocation_notification"]
)
def test_non_success_status_refused(material, status):
    def mutation(response):
        response["status"]["status"] = status

    refused(material, "response_status", response_der=material.response(response_mutator=mutation))


@pytest.mark.parametrize("side", ["leaf_start", "leaf_end", "root_start", "root_end"])
def test_certificate_must_cover_whole_hull(side):
    changes = {"before": EPOCH} if side.endswith("start") else {"after": EPOCH}
    f = NativeFixture(
        certificate(ca=True, **changes) if side.startswith("root") else certificate(ca=True),
        certificate(**changes) if side.startswith("leaf") else certificate(),
    )
    refused(f, "certificate_interval")


@pytest.mark.parametrize(
    "changes",
    [
        {"critical_eku": False},
        {"eku": [ExtendedKeyUsageOID.SERVER_AUTH]},
        {"eku": [ExtendedKeyUsageOID.TIME_STAMPING, ExtendedKeyUsageOID.SERVER_AUTH]},
        {"extra_extension": x509.UnrecognizedExtension(ObjectIdentifier("1.2.3.4"), b"\x05\x00")},
    ],
)
def test_certificate_usage_profile_refused(changes):
    with pytest.raises(NativeTimeError) as exc:
        _ = fixture(**changes).profile
    assert exc.value.reason_code == "certificate_profile"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"before": EPOCH},
        {"after": EPOCH + timedelta(seconds=1)},
        {"before": EPOCH - timedelta(seconds=7200)},
        {"after": EPOCH},
    ],
)
def test_crl_validity_and_age_use_complete_hull(material, kwargs):
    refused(material, "crl_interval", crl_der=material.crl(**kwargs))


def test_crl_revocation_refuses_even_after_claimed_time(material):
    refused(material, "revoked", crl_der=material.crl(revoked=(2,)))


def test_other_serial_revocation_is_not_tsa_revocation(material):
    validate(material, crl_der=material.crl(revoked=(3,)))


def test_crl_forgery_refused(material):
    from native_time_fixtures import TSA_KEY

    refused(material, "crl_authentication", crl_der=material.crl(signing_key=TSA_KEY))


def test_duplicate_crl_entry_refused(material):
    refused(material, "crl_profile", crl_der=material.crl(revoked=(3, 3)))


def test_scoped_crl_refused(material):
    refused(material, "crl_profile", crl_der=material.crl(extra_extension=x509.DeltaCRLIndicator(1)))


@pytest.mark.parametrize("field", ["response_der", "crl_der"])
@pytest.mark.parametrize("mode", ["missing", "mutable", "oversized", "trailing", "truncated"])
def test_wire_bounds_and_malformed_bytes(material, field, mode):
    value = material.response() if field == "response_der" else material.crl()
    maximum = native.MAX_RESPONSE_BYTES_V1 if field == "response_der" else native.MAX_CRL_BYTES_V1
    value = {
        "missing": b"",
        "mutable": bytearray(value),
        "oversized": b"x" * (maximum + 1),
        "trailing": value + b"\x00",
        "truncated": value[:-1],
    }[mode]
    reason = {
        "missing": "resource_limit",
        "mutable": "input_type",
        "oversized": "resource_limit",
        "trailing": "malformed_native_evidence",
        "truncated": "malformed_native_evidence",
    }[mode]
    refused(material, reason, **{field: value})


def test_no_network_or_ambient_validation_clock(material, monkeypatch):
    import pyhanko_certvalidator.context as contexts

    class NoClock(contexts.datetime):
        @classmethod
        def now(cls, *args, **kwargs):
            raise AssertionError("ambient clock read")

    def denied(*args, **kwargs):
        raise AssertionError("network access")

    monkeypatch.setattr(contexts, "datetime", NoClock)
    monkeypatch.setattr(socket, "getaddrinfo", denied)
    monkeypatch.setattr(socket.socket, "connect", denied)
    validate(material)


@pytest.mark.parametrize("boundary", ["request", "response"])
def test_client_version_substitution_refused(material, monkeypatch, boundary):
    profile, request, response, crl = material.profile, context(), material.response(), material.crl()
    monkeypatch.setattr(native, "version", lambda name: "0.0.0")
    with pytest.raises(NativeTimeError) as exc:
        if boundary == "request":
            native.build_rfc3161_request_v1(profile=profile, request=request)
        else:
            asyncio.run(
                validate_rfc3161_offline_v1(profile=profile, request=request, response_der=response, crl_der=crl)
            )
    assert exc.value.reason_code == "dependency_version"


def test_forged_request_identity_revalidated(material):
    req = context()
    object.__setattr__(req, "event_digest", content_id("native_time_fixture", {"foreign": True}))
    refused(material, "malformed_native_evidence", request=req)


def _with_extra_sequence_field(wire):
    body = core.Sequence.load(wire, strict=True).contents + b"\x05\x00"
    size = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
    return b"\x30" + bytes([0x80 | len(size)]) + size + body


@pytest.mark.parametrize("location", ["response", "tst_info"])
def test_unknown_nested_asn1_field_refused(material, location):
    if location == "response":
        response = _with_extra_sequence_field(material.response())
    else:

        def mutation(sd):
            raw = bytes(sd["encap_content_info"]["content"])
            sd["encap_content_info"]["content"] = cms.ParsableOctetString(_with_extra_sequence_field(raw))

        response = material.response(sd_mutator=mutation)
    refused(material, "asn1_shape", response_der=response)


def test_nonminimal_der_length_refused(material):
    response = material.response()
    assert response[:2] == b"\x30\x82"
    refused(material, "noncanonical_der", response_der=b"\x30\x83\x00" + response[2:])


def test_crl_collection_ceiling_refused(material):
    refused(material, "resource_limit", crl_der=material.crl(revoked=tuple(range(3, 1028))))


@pytest.mark.parametrize("field", ["root_certificate_der", "tsa_certificate_der"])
def test_certificate_byte_ceiling_refused(material, field):
    with pytest.raises(NativeTimeError) as exc:
        replace(material.profile, **{field: b"x" * (native.MAX_CERTIFICATE_BYTES_V1 + 1)})
    assert exc.value.reason_code == "resource_limit"


@pytest.mark.parametrize("field", ["max_accuracy_microseconds", "max_crl_age_seconds"])
@pytest.mark.parametrize("value", [True, 0, -1, 2**63])
def test_policy_ceiling_cannot_be_disabled(material, field, value):
    with pytest.raises(NativeTimeError) as exc:
        replace(material.profile, **{field: value})
    assert exc.value.reason_code == "profile"


def test_forged_profile_revalidated(material):
    profile = material.profile
    object.__setattr__(profile, "max_accuracy_microseconds", True)
    refused(material, "profile", profile=profile)


def test_unsigned_cms_attributes_refused(material):
    def mutation(sd):
        sd["signer_infos"][0]["unsigned_attrs"] = [{"type": "message_digest", "values": [b"x" * 32]}]

    refused(material, "cms_shape", response_der=material.response(sd_mutator=mutation))


def test_multiple_values_in_single_signed_attribute_refused(material):
    def mutation(attrs):
        for attr in attrs:
            if attr["type"].native == "message_digest":
                attr["values"] = [*attr["values"], b"x" * 32]
        return attrs

    refused(material, "cms_shape", response_der=material.response(attrs_mutator=mutation))


def test_crl_without_next_update_refused(material):
    from asn1crypto import crl as asn1_crl
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    crl = asn1_crl.CertificateList.load(material.crl())
    crl["tbs_cert_list"]["next_update"] = None
    crl["signature"] = ROOT_KEY.sign(crl["tbs_cert_list"].dump(), ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    refused(material, "crl_interval", crl_der=crl.dump())


def test_forged_direct_issuer_refused():
    from native_time_fixtures import TSA_KEY

    with pytest.raises(NativeTimeError) as exc:
        _ = fixture(signing_key=TSA_KEY).profile
    assert exc.value.reason_code == "certificate_profile"


def test_critical_root_extension_refused(material):
    root = certificate(ca=True, extra_extension=x509.UnrecognizedExtension(ObjectIdentifier("1.2.3.4"), b"\x05\x00"))
    with pytest.raises(NativeTimeError) as exc:
        replace(material.profile, root_certificate_der=der(root))
    assert exc.value.reason_code == "certificate_profile"


def test_cold_dossier_reconstruction_without_fixture_signers(material):
    import base64
    import json

    from etzio.kernel.integrity_adapters_v1 import TrustedTimeRequestV1

    first = validate(material)
    body = json.loads(first.profile_bytes)
    profile = native.Rfc3161OfflineProfileV1(
        body["source_id"],
        body["tsa_policy_oid"],
        base64.b64decode(body["root_certificate_der_b64"]),
        base64.b64decode(body["tsa_certificate_der_b64"]),
        body["max_accuracy_microseconds"],
        body["max_crl_age_seconds"],
    )
    replay = asyncio.run(
        validate_rfc3161_offline_v1(
            profile=profile,
            request=TrustedTimeRequestV1.from_canonical_bytes(first.context_bytes),
            response_der=first.response_der,
            crl_der=first.crl_der,
        )
    )
    assert replay == first


def test_root_tsa_key_reuse_refused():
    with pytest.raises(NativeTimeError) as exc:
        _ = fixture(key=ROOT_KEY).profile
    assert exc.value.reason_code == "certificate_profile"


@pytest.mark.parametrize("kind", ["certificate", "crl"])
def test_inner_outer_signature_algorithm_mismatch_refused(material, kind):
    from asn1crypto import crl as asn1_crl
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    if kind == "certificate":
        obj = asn1_x509.Certificate.load(der(material.tsa))
        tbs, signature = "tbs_certificate", "signature_value"
    else:
        obj = asn1_crl.CertificateList.load(material.crl())
        tbs, signature = "tbs_cert_list", "signature"
    obj[tbs]["signature"] = {"algorithm": "sha384_ecdsa"}
    obj[signature] = ROOT_KEY.sign(obj[tbs].dump(), ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    if kind == "crl":
        refused(material, "algorithm_profile", crl_der=obj.dump())
    else:
        with pytest.raises(NativeTimeError) as exc:
            replace(material.profile, tsa_certificate_der=obj.dump())
        assert exc.value.reason_code == "algorithm_profile"


def test_noncanonical_boolean_refused(material):
    response = material.response(info_changes={"ordering": core.Boolean.load(b"\x01\x01\x01")})
    refused(material, "noncanonical_der", response_der=response)


def test_retained_corpus_and_comparison_bind_exact_generated_bytes():
    import hashlib
    import json
    from pathlib import Path

    from scripts.qualify_native_time import corpus

    root = Path(__file__).resolve().parents[1]
    retained = (root / "tools/native-time/corpus.json").read_bytes()
    report = json.loads((root / "tools/native-time/openssl-comparison.json").read_bytes())
    assert json.loads(retained) == corpus()
    assert report["corpus_sha256"] == hashlib.sha256(retained).hexdigest()
    assert report["case_count"] == len(report["results"]) == len(corpus()["cases"])
    for relative, digest in report["source_sha256"].items():
        assert hashlib.sha256((root / relative).read_bytes()).hexdigest() == digest


def test_native_dependency_closure_matches_optional_extra_sbom_and_lock():
    import hashlib
    import json
    import tomllib
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    project = tomllib.loads((root / "pyproject.toml").read_text())
    extra = project["project"]["optional-dependencies"]["native-time"]
    assert sorted(extra) == sorted(f"{name}=={pinned}" for name, pinned in native.CLIENT_VERSIONS_V1)
    sbom = json.loads((root / "tools/native-time/sbom.cdx.json").read_text())
    assert sorted((c["name"], c["version"]) for c in sbom["components"]) == list(native.CLIENT_VERSIONS_V1)
    properties = {p["name"]: p["value"] for p in sbom["metadata"]["properties"]}
    lock = (root / "tools/ci/requirements-ci.lock").read_bytes()
    assert properties["etzio:requirements-ci-lock-sha256"] == hashlib.sha256(lock).hexdigest()
    for name, pinned in native.CLIENT_VERSIONS_V1:
        assert f"\n{name}=={pinned} \\\n".encode() in lock


@pytest.mark.parametrize("case", oracle_cases(), ids=lambda case: case.case_id)
def test_independent_comparison_corpus_native_result(material, case):
    if case.native_result == "accepted":
        validate(material, response_der=case.response_der, crl_der=case.crl_der)
    else:
        refused(material, case.native_result, response_der=case.response_der, crl_der=case.crl_der)


@pytest.mark.parametrize("kind", ["cms", "certificate", "crl"])
def test_ecdsa_parameters_must_be_absent_not_null(material, kind):
    from asn1crypto import crl as asn1_crl
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    if kind == "cms":

        def mutation(sd):
            sd["signer_infos"][0]["signature_algorithm"]["parameters"] = core.Null()

        refused(material, "algorithm_profile", response_der=material.response(sd_mutator=mutation))
        return
    if kind == "certificate":
        obj = asn1_x509.Certificate.load(der(material.tsa))
        tbs, signature = "tbs_certificate", "signature_value"
    else:
        obj = asn1_crl.CertificateList.load(material.crl())
        tbs, signature = "tbs_cert_list", "signature"
    obj[tbs]["signature"]["parameters"] = core.Null()
    obj["signature_algorithm"]["parameters"] = core.Null()
    obj[signature] = ROOT_KEY.sign(obj[tbs].dump(), ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    if kind == "crl":
        refused(material, "algorithm_profile", crl_der=obj.dump())
    else:
        with pytest.raises(NativeTimeError) as exc:
            replace(material.profile, tsa_certificate_der=obj.dump())
        assert exc.value.reason_code == "algorithm_profile"
