"""Offline RSA chain controls; no external source or acquisition authority."""

from __future__ import annotations

import asyncio
import socket
from dataclasses import replace
from datetime import timedelta

import pytest
from asn1crypto import cms, core
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, ObjectIdentifier
from native_time_rsa_fixtures import EPOCH, changed_fixture, context, der, fixture, key, oracle_cases, qc_extension

from etzio.protocol import content_id
from etzio.qualification import rfc3161_rsa_chain_v1 as native
from etzio.qualification.rfc3161_rsa_chain_v1 import validate_rfc3161_rsa_chain_offline_v1
from etzio.qualification.rfc3161_v1 import NativeTimeError


def replace_extension(oid, value, critical):
    def mutate(extensions):
        return [(v, c) for v, c in extensions if v.oid != oid] + ([(value, critical)] if value is not None else [])

    return mutate


def profile_refused(reason, role, **changes):
    with pytest.raises(NativeTimeError) as exc:
        _ = changed_fixture(role, **changes).profile
    assert exc.value.reason_code == reason


def test_positive_replay_and_distinct_chain_roles():
    f = fixture()
    first = validate(f)
    assert first == validate(f)
    assert first.response_der == f.response()
    assert first.root_crl_der == f.crl("root") and first.issuer_crl_der == f.crl("issuer")
    assert first.to_body()["kernel_authority"] is False
    assert (first.lower_second, first.upper_second) == (1791547199, 1791547201)


@pytest.mark.parametrize("role", ["root", "issuer", "tsa"])
@pytest.mark.parametrize("side", ["before", "after"])
def test_all_certificate_roles_cover_full_hull(role, side):
    refused(changed_fixture(role, **{side: EPOCH}), "certificate_interval")


@pytest.mark.parametrize("role", ["root", "issuer", "tsa"])
@pytest.mark.parametrize("change", ["foreign_signature", "wrong_issuer", "weak_digest", "key_reuse", "subject_reuse"])
def test_certificate_authentication_and_role_separation(role, change):
    other = "tsa" if role == "root" else "root"
    kwargs = {
        "foreign_signature": {"signer_role": "foreign"},
        "wrong_issuer": {"issuer_role": "foreign"},
        "weak_digest": {"algorithm": hashes.SHA256()},
        "key_reuse": {"key_role": other},
        "subject_reuse": {"subject_role": other},
    }[change]
    profile_refused("algorithm_profile" if change == "weak_digest" else "certificate_profile", role, **kwargs)


@pytest.mark.parametrize("role", ["root", "issuer", "tsa"])
@pytest.mark.parametrize("change", ["missing_ski", "foreign_aki", "noncritical_bc", "wrong_ca", "usage", "unknown"])
def test_certificate_required_extensions(role, change):
    ca = role != "tsa"
    mutations = {
        "missing_ski": replace_extension(ExtensionOID.SUBJECT_KEY_IDENTIFIER, None, False),
        "foreign_aki": replace_extension(
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER, x509.AuthorityKeyIdentifier(b"x" * 20, None, None), False
        ),
        "noncritical_bc": replace_extension(ExtensionOID.BASIC_CONSTRAINTS, x509.BasicConstraints(ca, None), False),
        "wrong_ca": replace_extension(ExtensionOID.BASIC_CONSTRAINTS, x509.BasicConstraints(not ca, None), True),
        "usage": replace_extension(
            ExtensionOID.KEY_USAGE, x509.KeyUsage(True, True, False, False, False, ca, ca, False, False), True
        ),
        "unknown": lambda ext: ext + [(x509.UnrecognizedExtension(ObjectIdentifier("1.2.3.4"), b"\x05\x00"), False)],
    }
    profile_refused("certificate_profile", role, extension_mutator=mutations[change])


@pytest.mark.parametrize(("role", "length"), [("root", 0), ("issuer", 1)])
def test_forbidden_path_lengths(role, length):
    profile_refused(
        "certificate_profile",
        role,
        extension_mutator=replace_extension(ExtensionOID.BASIC_CONSTRAINTS, x509.BasicConstraints(True, length), True),
    )


@pytest.mark.parametrize(
    ("oid", "value", "critical"),
    [
        (ExtensionOID.EXTENDED_KEY_USAGE, x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), False),
        (ExtensionOID.EXTENDED_KEY_USAGE, x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), True),
        (
            ExtensionOID.EXTENDED_KEY_USAGE,
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING, ExtendedKeyUsageOID.SERVER_AUTH]),
            True,
        ),
        (ExtensionOID.CERTIFICATE_POLICIES, None, False),
        (
            ExtensionOID.CERTIFICATE_POLICIES,
            x509.CertificatePolicies([x509.PolicyInformation(ObjectIdentifier("1.2.3"), None)]),
            False,
        ),
    ],
)
def test_tsa_eku_and_certificate_policy(oid, value, critical):
    profile_refused("certificate_profile", "tsa", extension_mutator=replace_extension(oid, value, critical))


@pytest.mark.parametrize(
    "mode",
    [
        "absent",
        "duplicate_extension",
        "critical",
        "foreign",
        "null_info",
        "data_info",
        "empty",
        "duplicate_statement",
        "foreign_extension",
        "trailing",
    ],
)
def test_qualified_statement_closed_shape(material, mode):
    extension = qc_extension()
    changes = {"extensions": [extension]}
    if mode == "absent":
        changes["extensions"] = None
    elif mode == "duplicate_extension":
        changes["extensions"] *= 2
    elif mode == "critical":
        changes["extensions"] = [qc_extension(critical=True)]
    elif mode == "foreign":
        changes["extensions"] = [qc_extension(oid="1.2.3.4")]
    elif mode in ("null_info", "data_info"):
        changes["extensions"] = [qc_extension(info=core.Null() if mode == "null_info" else core.Integer(1))]
    elif mode == "empty":
        extension["extn_value"] = native.QCStatements([]).dump()
    elif mode == "duplicate_statement":
        value = native.QCStatements.load(extension["extn_value"])
        extension["extn_value"] = native.QCStatements([value[0], value[0]]).dump()
    elif mode == "foreign_extension":
        extension["extn_id"] = "1.2.3.4"
    elif mode == "trailing":
        extension["extn_value"] += b"\x00"
    refused(
        material,
        "malformed_native_evidence" if mode == "trailing" else "qualified_statement",
        response_der=material.response(info_changes=changes),
    )


@pytest.mark.parametrize("role", ["root", "issuer"])
@pytest.mark.parametrize("mode", ["lower", "upper", "age", "duplicate", "delta", "aki", "entry", "number", "count"])
def test_each_crl_interval_and_profile(material, role, mode):
    changes = {
        "lower": {"before": EPOCH},
        "upper": {"after": EPOCH + timedelta(seconds=1)},
        "age": {"before": EPOCH - timedelta(seconds=7200)},
        "duplicate": {"revoked": (99, 99)},
        "delta": {"extension_mutator": lambda ext: ext + [(x509.DeltaCRLIndicator(1), True)]},
        "aki": {
            "extension_mutator": replace_extension(
                ExtensionOID.AUTHORITY_KEY_IDENTIFIER, x509.AuthorityKeyIdentifier(b"x" * 20, None, None), False
            )
        },
        "entry": {"revoked": (99,), "entry_extension": x509.CRLReason(x509.ReasonFlags.key_compromise)},
        "number": {"number": 2**160},
        "count": {"revoked": tuple(range(99, 1124))},
    }[mode]
    reason = (
        "crl_interval" if mode in ("lower", "upper", "age") else "resource_limit" if mode == "count" else "crl_profile"
    )
    refused(material, reason, **{role + "_crl_der": material.crl(role, **changes)})


def test_crls_cannot_swap_roles(material):
    refused(material, "crl_authentication", root_crl_der=material.crl("issuer"), issuer_crl_der=material.crl("root"))


@pytest.mark.parametrize("role", ["root", "issuer"])
def test_unrelated_revocation_is_accepted(material, role):
    validate(material, **{role + "_crl_der": material.crl(role, revoked=(99,))})


@pytest.mark.parametrize("mode", ["duplicate", "root", "foreign_intermediate"])
def test_embedded_chain_substitution(material, mode):
    def mutate(sd):
        tsa = asn1_x509.Certificate.load(der(material.tsa))
        other = (
            tsa
            if mode == "duplicate"
            else asn1_x509.Certificate.load(
                der(material.root) if mode == "root" else der(changed_fixture("issuer", key_role="foreign").issuer)
            )
        )
        sd["certificates"] = [tsa, other]

    refused(material, "certificate_binding", response_der=material.response(sd_mutator=mutate))


@pytest.mark.parametrize("algorithm", ["sha384_rsa", "rsassa_pkcs1v15"])
@pytest.mark.parametrize("absent", [True, False])
def test_cms_rsa_identifiers_and_parameter_equivalence(material, algorithm, absent):
    def mutate(sd):
        sd["signer_infos"][0]["signature_algorithm"]["parameters"] = None if absent else core.Null()

    validate(material, response_der=material.response(signature_algorithm=algorithm, sd_mutator=mutate))


@pytest.mark.parametrize("algorithm", ["sha256_rsa", "rsassa_pss", "sha384_ecdsa"])
def test_foreign_cms_algorithms(material, algorithm):
    def mutate(sd):
        sd["signer_infos"][0]["signature_algorithm"] = {"algorithm": algorithm}

    refused(material, "algorithm_profile", response_der=material.response(sd_mutator=mutate))


@pytest.mark.parametrize("boundary", ["request", "response"])
def test_dependency_drift(material, monkeypatch, boundary):
    from etzio.qualification import rfc3161_v1 as shared

    args = dict(
        profile=material.profile,
        request=context(),
        response_der=material.response(),
        root_crl_der=material.crl("root"),
        issuer_crl_der=material.crl("issuer"),
    )
    monkeypatch.setattr(shared, "version", lambda name: "0.0.0")
    with pytest.raises(NativeTimeError, match="pinned closure") as exc:
        if boundary == "request":
            native.build_rfc3161_rsa_chain_request_v1(profile=args["profile"], request=args["request"])
        else:
            asyncio.run(validate_rfc3161_rsa_chain_offline_v1(**args))
    assert exc.value.reason_code == "dependency_version"


@pytest.mark.parametrize("failure", [asyncio.CancelledError, OSError])
def test_operational_failures_not_reclassified(material, monkeypatch, failure):
    async def fail(*args, **kwargs):
        raise failure("injected operational failure")

    monkeypatch.setattr(native, "validate_tst_signed_data", fail)
    with pytest.raises(failure):
        validate(material)


def metadata_extensions():
    from cryptography.x509.oid import AuthorityInformationAccessOID
    from native_time_rsa_fixtures import CERT_POLICY

    return [
        (
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.OCSP,
                        x509.UniformResourceIdentifier("https://fixture.invalid/ocsp"),
                    )
                ]
            ),
            False,
        ),
        (
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        [x509.UniformResourceIdentifier("http://fixture.invalid/crl")], None, None, None
                    )
                ]
            ),
            False,
        ),
        (
            x509.CertificatePolicies(
                [x509.PolicyInformation(ObjectIdentifier(CERT_POLICY), ["https://fixture.invalid/cps"])]
            ),
            False,
        ),
    ]


def test_metadata_is_retained_without_fetch_or_clock(monkeypatch):
    def mutate(ext):
        return [(v, c) for v, c in ext if v.oid != ExtensionOID.CERTIFICATE_POLICIES] + metadata_extensions()

    f = changed_fixture("tsa", extension_mutator=mutate)
    test_no_network_or_ambient_validation_clock(f, monkeypatch)


@pytest.mark.parametrize("mode", ["critical", "ftp", "userinfo", "notice", "scoped", "foreign_aia"])
def test_unsupported_metadata_shapes(mode):
    from cryptography.x509.oid import AuthorityInformationAccessOID

    metadata = metadata_extensions()
    if mode == "critical":
        metadata[0] = (metadata[0][0], True)
    elif mode in ("ftp", "userinfo", "foreign_aia"):
        uri = "ftp://fixture.invalid/a" if mode == "ftp" else "https://user:pw@fixture.invalid/a"
        method = ObjectIdentifier("1.2.3.4") if mode == "foreign_aia" else AuthorityInformationAccessOID.OCSP
        metadata[0] = (
            x509.AuthorityInformationAccess([x509.AccessDescription(method, x509.UniformResourceIdentifier(uri))]),
            False,
        )
    elif mode == "notice":
        metadata[2] = (
            x509.CertificatePolicies(
                [x509.PolicyInformation(metadata[2][0][0].policy_identifier, [x509.UserNotice(None, "notice")])]
            ),
            False,
        )
    else:
        metadata[1] = (
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        [x509.UniformResourceIdentifier("https://fixture.invalid/crl")],
                        None,
                        frozenset({x509.ReasonFlags.key_compromise}),
                        None,
                    )
                ]
            ),
            False,
        )
    profile_refused(
        "certificate_profile",
        "tsa",
        extension_mutator=lambda ext: [(v, c) for v, c in ext if v.oid != ExtensionOID.CERTIFICATE_POLICIES] + metadata,
    )


@pytest.mark.parametrize("kind", ["certificate", "root_crl", "issuer_crl"])
@pytest.mark.parametrize("mode", ["absent_parameters", "algorithm_mismatch"])
def test_certificate_crl_algorithm_binding(material, kind, mode):
    from asn1crypto import crl as asn1_crl

    if kind == "certificate":
        obj = asn1_x509.Certificate.load(der(material.tsa))
        tbs, sig, signer = "tbs_certificate", "signature_value", "issuer"
    else:
        signer = kind.split("_")[0]
        obj = asn1_crl.CertificateList.load(material.crl(signer))
        tbs, sig = "tbs_cert_list", "signature"
    if mode == "absent_parameters":
        obj[tbs]["signature"]["parameters"] = None
        obj["signature_algorithm"]["parameters"] = None
    else:
        obj[tbs]["signature"] = {"algorithm": "sha256_rsa"}
    obj[sig] = key(signer).sign(obj[tbs].dump(), padding.PKCS1v15(), hashes.SHA384())
    if kind == "certificate":
        if mode == "absent_parameters":
            f = replace(material, tsa=x509.load_der_x509_certificate(obj.dump()))
            validate(f)
        else:
            with pytest.raises(NativeTimeError) as exc:
                replace(material.profile, tsa_certificate_der=obj.dump())
            assert exc.value.reason_code == "algorithm_profile"
    elif mode == "absent_parameters":
        validate(material, **{kind + "_der": obj.dump()})
    else:
        refused(material, "algorithm_profile", **{kind + "_der": obj.dump()})


@pytest.mark.parametrize("role", ["root", "issuer"])
@pytest.mark.parametrize("mode", ["no_next", "v1"])
def test_crl_required_metadata(material, role, mode):
    from asn1crypto import crl as asn1_crl

    obj = asn1_crl.CertificateList.load(material.crl(role))
    obj["tbs_cert_list"]["next_update" if mode == "no_next" else "version"] = None
    obj["signature"] = key(role).sign(obj["tbs_cert_list"].dump(), padding.PKCS1v15(), hashes.SHA384())
    refused(material, "crl_interval" if mode == "no_next" else "crl_profile", **{role + "_crl_der": obj.dump()})


@pytest.mark.parametrize("field", ["profile", "request"])
def test_subclass_cannot_supply_semantics(material, field):
    args = {"profile": material.profile, "request": context()}
    obj = args[field]
    subclass = type("ForeignSubclass", (type(obj),), {"to_body": lambda self: {}, "__post_init__": lambda self: None})
    from dataclasses import fields

    args[field] = subclass(**{f.name: getattr(obj, f.name) for f in fields(obj)})
    refused(material, "input_type", **args)


def test_fresh_context_at_each_exact_endpoint(material, monkeypatch):
    actual = native.ValidationContext
    moments = []

    def capture(**kwargs):
        moments.append(kwargs)
        return actual(**kwargs)

    monkeypatch.setattr(native, "ValidationContext", capture)
    response = material.response(
        info_changes={"gen_time": EPOCH + timedelta(microseconds=1), "accuracy": {"micros": 2}}
    )
    observation = validate(material, response_der=response)
    assert [native._micros(c["moment"]) for c in moments] == [
        observation.lower_microseconds,
        observation.upper_microseconds,
    ]
    assert moments[0] is not moments[1]
    assert all(not c["allow_fetching"] and c["revocation_mode"] == "require" and len(c["crls"]) == 2 for c in moments)


def test_cold_process_reconstructs_retained_bytes_without_signers(material, tmp_path):
    import base64
    import json
    import subprocess
    import sys
    from pathlib import Path

    first = validate(material)
    payload = {
        name: base64.b64encode(getattr(first, name)).decode("ascii")
        for name in ("profile_bytes", "context_bytes", "response_der", "root_crl_der", "issuer_crl_der")
    }
    path = tmp_path / "dossier.json"
    path.write_text(json.dumps(payload))
    code = """
import asyncio, base64, json, socket, sys
sys.path.insert(0, sys.argv[1])
from etzio.qualification.rfc3161_rsa_chain_v1 import Rfc3161RsaChainProfileV1, validate_rfc3161_rsa_chain_offline_v1
from etzio.kernel.integrity_adapters_v1 import TrustedTimeRequestV1
def denied(*a, **kw):
    raise AssertionError("network forbidden")
socket.getaddrinfo = denied
socket.socket.connect = denied
data = {k: base64.b64decode(v, validate=True) for k,v in json.load(open(sys.argv[2])).items()}
body = json.loads(data.pop("profile_bytes"))
body.pop("codec"); body.pop("clients")
for key in list(body):
    if key.endswith("_b64"):
        body[key[:-4]] = base64.b64decode(body.pop(key), validate=True)
request = TrustedTimeRequestV1.from_canonical_bytes(data.pop("context_bytes"))
observation = asyncio.run(validate_rfc3161_rsa_chain_offline_v1(
    profile=Rfc3161RsaChainProfileV1(**body), request=request, **data))
print(observation.observation_id)
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", code, str(Path(__file__).resolve().parents[1]), str(path)],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.stdout.strip() == first.observation_id


@pytest.mark.parametrize("mode", ["short_modulus", "exponent", "absent_spki_parameters"])
def test_rsa_key_profile(material, mode):
    obj = asn1_x509.Certificate.load(der(material.tsa))
    spki = obj["tbs_certificate"]["subject_public_key_info"]
    if mode == "absent_spki_parameters":
        spki["algorithm"]["parameters"] = None
    else:
        public = spki["public_key"].parsed.copy()
        public["modulus" if mode == "short_modulus" else "public_exponent"] = (
            2**2047 + 1 if mode == "short_modulus" else 3
        )
        spki["public_key"] = public
    obj["signature_value"] = key("issuer").sign(obj["tbs_certificate"].dump(), padding.PKCS1v15(), hashes.SHA384())
    with pytest.raises(NativeTimeError) as exc:
        replace(material.profile, tsa_certificate_der=obj.dump())
    assert exc.value.reason_code == "algorithm_profile"


@pytest.fixture(scope="module")
def material():
    return fixture()


def validate(material, **changes):
    args = dict(
        profile=material.profile,
        request=context(),
        response_der=material.response(),
        root_crl_der=material.crl("root"),
        issuer_crl_der=material.crl("issuer"),
    )
    args.update(changes)
    return asyncio.run(validate_rfc3161_rsa_chain_offline_v1(**args))


def refused(material, reason, **changes):
    with pytest.raises(NativeTimeError) as exc:
        validate(material, **changes)
    assert exc.value.reason_code == reason


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
    refused(material, "signature_or_path", response_der=material.response(signer_role="foreign"))


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
        reason = "certificate_binding"
    refused(material, reason, response_der=material.response(sd_mutator=mutation))


@pytest.mark.parametrize(
    "status", ["granted_with_mods", "rejection", "waiting", "revocation_warning", "revocation_notification"]
)
def test_non_success_status_refused(material, status):
    def mutation(response):
        response["status"]["status"] = status

    refused(material, "response_status", response_der=material.response(response_mutator=mutation))


@pytest.mark.parametrize("field", ["response_der", "root_crl_der", "issuer_crl_der"])
@pytest.mark.parametrize("mode", ["missing", "mutable", "oversized", "trailing", "truncated"])
def test_wire_bounds_and_malformed_bytes(material, field, mode):
    value = material.response() if field == "response_der" else material.crl(field.split("_")[0])
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


@pytest.mark.parametrize("field", ["root_certificate_der", "issuer_certificate_der", "tsa_certificate_der"])
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


def test_noncanonical_boolean_refused(material):
    response = material.response(info_changes={"ordering": core.Boolean.load(b"\x01\x01\x01")})
    refused(material, "noncanonical_der", response_der=response)


def test_retained_corpus_and_comparison_bind_exact_generated_bytes():
    import hashlib
    import json
    from pathlib import Path

    from scripts.qualify_native_time_rsa import corpus

    root = Path(__file__).resolve().parents[1]
    retained = (root / "tools/native-time-rsa/corpus.json").read_bytes()
    report = json.loads((root / "tools/native-time-rsa/openssl-comparison.json").read_bytes())
    assert json.loads(retained) == corpus()
    assert report["corpus_sha256"] == hashlib.sha256(retained).hexdigest()
    assert report["case_count"] == len(report["results"]) == len(corpus()["cases"])
    for relative, digest in report["source_sha256"].items():
        assert hashlib.sha256((root / relative).read_bytes()).hexdigest() == digest


@pytest.mark.parametrize("case", oracle_cases(), ids=lambda case: case.case_id)
def test_independent_comparison_corpus_native_result(material, case):
    if case.native_result == "accepted":
        validate(
            material, response_der=case.response_der, root_crl_der=case.root_crl_der, issuer_crl_der=case.issuer_crl_der
        )
    else:
        refused(
            material,
            case.native_result,
            response_der=case.response_der,
            root_crl_der=case.root_crl_der,
            issuer_crl_der=case.issuer_crl_der,
        )
