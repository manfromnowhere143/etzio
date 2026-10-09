"""Deliberately PUBLIC RSA fixture factors and identities; never external authority."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from datetime import timedelta
from functools import cache
from pathlib import Path

from asn1crypto import cms, tsp
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from native_time_fixtures import EPOCH, der
from native_time_fixtures import context as base_context

from etzio.qualification.rfc3161_rsa_chain_v1 import (
    QC_EXTENSION_OID,
    QC_STATEMENT_OID,
    QCStatements,
    Rfc3161RsaChainProfileV1,
    build_rfc3161_rsa_chain_request_v1,
)

POLICY = "0.4.0.2023.1.1"
CERT_POLICY = "1.3.6.1.4.1.6449.1.2.1.9"
ROLES = ("root", "issuer", "tsa")
NAMES = {
    role: x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Etzio PUBLIC RSA fixture " + role)])
    for role in (*ROLES, "foreign")
}


@cache
def key(role):
    path = Path(__file__).resolve().parents[1] / "tools/native-time-rsa/fixture-keys.json"
    values = json.loads(path.read_text())["keys"][role]
    p, q = (int(values[name], 16) for name in ("p", "q"))
    e = 65537
    d = pow(e, -1, (p - 1) * (q - 1))
    return rsa.RSAPrivateNumbers(
        p, q, d, rsa.rsa_crt_dmp1(d, p), rsa.rsa_crt_dmq1(d, q), rsa.rsa_crt_iqmp(p, q), rsa.RSAPublicNumbers(e, p * q)
    ).private_key()


def context(**changes):
    return base_context(**({"source_id": "fixture.rsa.tsa"} | changes))


def certificate(
    role,
    *,
    before=None,
    after=None,
    key_role=None,
    signer_role=None,
    subject_role=None,
    issuer_role=None,
    extension_mutator=None,
    algorithm=None,
):
    ca = role != "tsa"
    parent = "issuer" if role == "tsa" else "root"
    public = key(key_role or role).public_key()
    extensions = [
        (x509.BasicConstraints(ca, (1 if role == "root" else 0) if ca else None), True),
        (x509.SubjectKeyIdentifier.from_public_key(public), False),
        (x509.AuthorityKeyIdentifier.from_issuer_public_key(key(parent).public_key()), False),
        (x509.KeyUsage(not ca, False, False, False, False, ca, ca, False, False), True),
    ]
    if not ca:
        extensions += [
            (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), True),
            (x509.CertificatePolicies([x509.PolicyInformation(x509.ObjectIdentifier(CERT_POLICY), None)]), False),
        ]
    if extension_mutator:
        extensions = extension_mutator(extensions)
    builder = (
        x509.CertificateBuilder()
        .subject_name(NAMES[subject_role or role])
        .issuer_name(NAMES[issuer_role or parent])
        .public_key(public)
        .serial_number(ROLES.index(role) + 1)
        .not_valid_before(before or EPOCH - timedelta(days=1))
        .not_valid_after(after or EPOCH + timedelta(days=1))
    )
    for value, critical in extensions:
        builder = builder.add_extension(value, critical)
    return builder.sign(key(signer_role or parent), algorithm or hashes.SHA384())


def qc_extension(*, oid=QC_STATEMENT_OID, info=None, critical=False):
    statement = {"statement_id": oid}
    if info is not None:
        statement["statement_info"] = info
    return {"extn_id": QC_EXTENSION_OID, "critical": critical, "extn_value": QCStatements([statement]).dump()}


@dataclass(frozen=True)
class RsaFixture:
    root: x509.Certificate
    issuer: x509.Certificate
    tsa: x509.Certificate

    @property
    def profile(self):
        return Rfc3161RsaChainProfileV1(
            "fixture.rsa.tsa", POLICY, CERT_POLICY, der(self.root), der(self.issuer), der(self.tsa), 2_000_000, 7200
        )

    def response(
        self,
        *,
        request=None,
        profile=None,
        info_changes=None,
        attrs_mutator=None,
        sd_mutator=None,
        response_mutator=None,
        signer_role="tsa",
        signature_algorithm="sha384_rsa",
    ):
        req = tsp.TimeStampReq.load(
            build_rfc3161_rsa_chain_request_v1(profile=profile or self.profile, request=request or context())
        )
        tsa = asn1_x509.Certificate.load(der(self.tsa))
        info = tsp.TSTInfo(
            {
                "version": "v1",
                "policy": req["req_policy"],
                "message_imprint": req["message_imprint"],
                "serial_number": 1,
                "gen_time": EPOCH,
                "accuracy": {"seconds": 1},
                "nonce": req["nonce"],
                "ordering": False,
                "extensions": [qc_extension()],
            }
            | (info_changes or {})
        )
        attrs = cms.CMSAttributes(
            [
                {"type": "content_type", "values": ["tst_info"]},
                {"type": "message_digest", "values": [hashlib.sha384(info.dump()).digest()]},
                {
                    "type": "signing_certificate_v2",
                    "values": [{"certs": [{"cert_hash": hashlib.sha256(der(self.tsa)).digest()}]}],
                },
            ]
        )
        if attrs_mutator:
            attrs = attrs_mutator(attrs)
        si = cms.SignerInfo(
            {
                "version": "v1",
                "sid": {"issuer_and_serial_number": {"issuer": tsa.issuer, "serial_number": tsa.serial_number}},
                "digest_algorithm": {"algorithm": "sha384"},
                "signature_algorithm": {"algorithm": signature_algorithm},
                "signed_attrs": attrs,
                "signature": key(signer_role).sign(attrs.dump(), padding.PKCS1v15(), hashes.SHA384()),
            }
        )
        sd = cms.SignedData(
            {
                "version": "v3",
                "digest_algorithms": [{"algorithm": "sha384"}],
                "encap_content_info": {"content_type": "tst_info", "content": info},
                "certificates": [tsa, asn1_x509.Certificate.load(der(self.issuer))],
                "signer_infos": [si],
            }
        )
        if sd_mutator:
            sd_mutator(sd)
        response = tsp.TimeStampResp(
            {"status": {"status": "granted"}, "time_stamp_token": {"content_type": "signed_data", "content": sd}}
        )
        if response_mutator:
            response_mutator(response)
        return response.dump()

    def crl(
        self,
        role,
        *,
        before=None,
        after=None,
        revoked=(),
        signer_role=None,
        extension_mutator=None,
        entry_extension=None,
        include_next=True,
        algorithm=None,
        issuer_role=None,
        number=1,
    ):
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(NAMES[issuer_role or role])
            .last_update(before or EPOCH - timedelta(hours=1))
        )
        if include_next:
            builder = builder.next_update(after or EPOCH + timedelta(hours=1))
        extensions = [
            (x509.AuthorityKeyIdentifier.from_issuer_public_key(key(role).public_key()), False),
            (x509.CRLNumber(number), False),
        ]
        for value, critical in extension_mutator(extensions) if extension_mutator else extensions:
            builder = builder.add_extension(value, critical)
        for serial in revoked:
            entry = x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(EPOCH + timedelta(minutes=5))
            if entry_extension:
                entry = entry.add_extension(entry_extension, False)
            builder = builder.add_revoked_certificate(entry.build())
        return der(builder.sign(key(signer_role or role), algorithm or hashes.SHA384()))


@cache
def fixture():
    return RsaFixture(*(certificate(role) for role in ROLES))


def changed_fixture(role, **changes):
    return replace(fixture(), **{role: certificate(role, **changes)})


@dataclass(frozen=True)
class OracleCase:
    case_id: str
    response_der: bytes
    root_crl_der: bytes
    issuer_crl_der: bytes
    native_result: str
    openssl_accepts: bool
    comparison: str = "shared_protocol_checks"


def oracle_cases():
    f = fixture()
    response, root, issuer = f.response(), f.crl("root"), f.crl("issuer")
    cases = [
        OracleCase("valid", response, root, issuer, "accepted", True),
        OracleCase(
            "rsa_encryption_cms", f.response(signature_algorithm="rsassa_pkcs1v15"), root, issuer, "accepted", True
        ),
    ]
    for name, change in (
        ("foreign_nonce", {"nonce": 1}),
        ("missing_nonce", {"nonce": None}),
        ("foreign_policy", {"policy": "1.2.3.4"}),
        (
            "foreign_imprint",
            {"message_imprint": {"hash_algorithm": {"algorithm": "sha256"}, "hashed_message": b"x" * 32}},
        ),
    ):
        cases.append(OracleCase(name, f.response(info_changes=change), root, issuer, "request_binding", False))
    cases.append(OracleCase("forged_cms", f.response(signer_role="foreign"), root, issuer, "signature_or_path", False))
    for role, serial, reason in (("root", 2, "intermediate"), ("issuer", 3, "tsa")):
        for label, changes, result, accepts in (
            ("revoked", {"revoked": (serial,)}, "revoked_" + reason, False),
            ("forged", {"signer_role": "foreign"}, "crl_authentication", False),
            ("expired", {"after": EPOCH}, "crl_interval", False),
            ("future", {"before": EPOCH + timedelta(seconds=2)}, "crl_interval", False),
            ("stale", {"before": EPOCH - timedelta(seconds=7200)}, "crl_interval", True),
        ):
            case_crls = {"root": root, "issuer": issuer} | {role: f.crl(role, **changes)}
            cases.append(
                OracleCase(
                    label + "_" + role,
                    response,
                    case_crls["root"],
                    case_crls["issuer"],
                    result,
                    accepts,
                    "etzio_bounds_crl_age_over_full_hull" if accepts else "shared_protocol_checks",
                )
            )
    for label, change, reason in (
        ("absent_accuracy", {"accuracy": None}, "accuracy"),
        ("absent_qualified_statement", {"extensions": None}, "qualified_statement"),
    ):
        cases.append(
            OracleCase(label, f.response(info_changes=change), root, issuer, reason, True, "etzio_finite_profile")
        )
    return tuple(cases)
