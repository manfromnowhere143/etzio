"""Public, repository-owned P-256 test identities. Never use these keys externally."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from asn1crypto import cms, tsp
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from etzio.kernel.integrity_adapters_v1 import TrustedTimeRequestV1
from etzio.protocol import content_id
from etzio.qualification.rfc3161_v1 import Rfc3161OfflineProfileV1, build_rfc3161_request_v1

EPOCH = datetime(2026, 10, 9, 12, tzinfo=UTC)
POLICY = "1.3.6.1.4.1.55555.1"
ROOT_KEY = ec.derive_private_key(12345, ec.SECP256R1())
TSA_KEY = ec.derive_private_key(67890, ec.SECP256R1())
ROOT_NAME = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Etzio repository fixture root")])
TSA_NAME = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Etzio repository fixture TSA")])


def der(value) -> bytes:
    return value.public_bytes(serialization.Encoding.DER)


def context(**changes) -> TrustedTimeRequestV1:
    values = {
        name: content_id("native_time_fixture", {"field": name})
        for name in (
            "profile_id",
            "trust_root_id",
            "mission_id",
            "authority_id",
            "target_id",
            "event_digest",
            "transition_intent_id",
            "time_policy_id",
            "imprint_id",
        )
    }
    values.update(
        contract_version=1,
        service_instance_id="Etzio.native-time-fixture",
        environment_id="fixture.offline",
        source_id="fixture.tsa",
        purpose="decision",
        request_nonce=hashlib.sha256(b"Etzio native fixture nonce").hexdigest(),
    )
    values.update(changes)
    return TrustedTimeRequestV1(request_id=content_id("trusted_time_adapter_request", values), **values)


def certificate(
    *, ca=False, before=None, after=None, eku=None, critical_eku=True, extra_extension=None, signing_key=None, key=None
) -> x509.Certificate:
    key = key or (ROOT_KEY if ca else TSA_KEY)
    builder = (
        x509.CertificateBuilder()
        .subject_name(ROOT_NAME if ca else TSA_NAME)
        .issuer_name(ROOT_NAME)
        .public_key(key.public_key())
        .serial_number(1 if ca else 2)
        .not_valid_before(before or EPOCH - timedelta(days=1))
        .not_valid_after(after or EPOCH + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ROOT_KEY.public_key()), False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=not ca,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=ca,
                crl_sign=ca,
                encipher_only=False,
                decipher_only=False,
            ),
            True,
        )
    )
    if not ca:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING] if eku is None else eku), critical_eku
        )
    if extra_extension is not None:
        builder = builder.add_extension(extra_extension, True)
    return builder.sign(signing_key or ROOT_KEY, hashes.SHA256(), ecdsa_deterministic=True)


@dataclass(frozen=True)
class NativeFixture:
    root: x509.Certificate
    tsa: x509.Certificate

    @property
    def profile(self) -> Rfc3161OfflineProfileV1:
        return Rfc3161OfflineProfileV1("fixture.tsa", POLICY, der(self.root), der(self.tsa), 2_000_000, 7200)

    def response(
        self,
        *,
        request=None,
        info_changes=None,
        attrs_mutator=None,
        sd_mutator=None,
        response_mutator=None,
        signer_key=None,
    ) -> bytes:
        req = tsp.TimeStampReq.load(build_rfc3161_request_v1(profile=self.profile, request=request or context()))
        tsa = asn1_x509.Certificate.load(der(self.tsa))
        args = {
            "version": "v1",
            "policy": req["req_policy"],
            "message_imprint": req["message_imprint"],
            "serial_number": 1,
            "gen_time": EPOCH,
            "accuracy": {"seconds": 1},
            "nonce": req["nonce"],
            "tsa": {"directory_name": tsa.subject},
        }
        args.update(info_changes or {})
        info = tsp.TSTInfo(args)
        attrs = cms.CMSAttributes(
            [
                {"type": "content_type", "values": ["tst_info"]},
                {"type": "message_digest", "values": [hashlib.sha256(info.dump()).digest()]},
                {
                    "type": "signing_certificate_v2",
                    "values": [{"certs": [{"cert_hash": hashlib.sha256(der(self.tsa)).digest()}]}],
                },
            ]
        )
        if attrs_mutator:
            attrs = attrs_mutator(attrs)
        signature = (signer_key or TSA_KEY).sign(attrs.dump(), ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
        si = cms.SignerInfo(
            {
                "version": "v1",
                "sid": {"issuer_and_serial_number": {"issuer": tsa.issuer, "serial_number": tsa.serial_number}},
                "digest_algorithm": {"algorithm": "sha256"},
                "signature_algorithm": {"algorithm": "sha256_ecdsa"},
                "signed_attrs": attrs,
                "signature": signature,
            }
        )
        sd = cms.SignedData(
            {
                "version": "v3",
                "digest_algorithms": [{"algorithm": "sha256"}],
                "encap_content_info": {"content_type": "tst_info", "content": info},
                "certificates": [tsa],
                "signer_infos": [si],
            }
        )
        if sd_mutator:
            sd_mutator(sd)
        resp = tsp.TimeStampResp(
            {"status": {"status": "granted"}, "time_stamp_token": {"content_type": "signed_data", "content": sd}}
        )
        if response_mutator:
            response_mutator(resp)
        return resp.dump()

    def crl(
        self, *, before=None, after=None, revoked=(), extra_extension=None, signing_key=None, include_next=True
    ) -> bytes:
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(ROOT_NAME)
            .last_update(before or EPOCH - timedelta(hours=1))
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ROOT_KEY.public_key()), False)
            .add_extension(x509.CRLNumber(1), False)
        )
        if include_next:
            builder = builder.next_update(after or EPOCH + timedelta(hours=1))
        if extra_extension is not None:
            builder = builder.add_extension(extra_extension, True)
        for serial in revoked:
            builder = builder.add_revoked_certificate(
                x509.RevokedCertificateBuilder()
                .serial_number(serial)
                .revocation_date(EPOCH + timedelta(minutes=5))
                .build()
            )
        return der(builder.sign(signing_key or ROOT_KEY, hashes.SHA256(), ecdsa_deterministic=True))


def fixture(**tsa_changes) -> NativeFixture:
    return NativeFixture(certificate(ca=True), certificate(**tsa_changes))


@dataclass(frozen=True)
class OracleCase:
    case_id: str
    response_der: bytes
    crl_der: bytes
    native_result: str
    openssl_accepts: bool
    comparison: str = "shared_protocol_checks"


def oracle_cases() -> tuple[OracleCase, ...]:
    """Finite byte corpus compared against a separate protocol/path implementation."""
    f = fixture()
    response, crl = f.response(), f.crl()
    cases = [OracleCase("valid", response, crl, "accepted", True)]
    for name, change in (
        ("foreign_nonce", {"nonce": 1}),
        ("missing_nonce", {"nonce": None}),
        ("foreign_policy", {"policy": "1.2.3.4"}),
        (
            "foreign_imprint",
            {"message_imprint": {"hash_algorithm": {"algorithm": "sha256"}, "hashed_message": b"\x01" * 32}},
        ),
    ):
        cases.append(OracleCase(name, f.response(info_changes=change), crl, "request_binding", False))
    cases.append(OracleCase("forged_cms", f.response(signer_key=ROOT_KEY), crl, "signature_or_path", False))

    def wrong_ess(attrs):
        for attr in attrs:
            if attr["type"].native == "signing_certificate_v2":
                attr["values"][0]["certs"][0]["cert_hash"] = b"\x01" * 32
        return attrs

    cases.append(OracleCase("foreign_ess", f.response(attrs_mutator=wrong_ess), crl, "certificate_binding", False))
    cases.extend(
        [
            OracleCase("revoked_tsa", response, f.crl(revoked=(2,)), "revoked", False),
            OracleCase("forged_crl", response, f.crl(signing_key=TSA_KEY), "crl_authentication", False),
            OracleCase("expired_crl", response, f.crl(after=EPOCH), "crl_interval", False),
            OracleCase("future_crl", response, f.crl(before=EPOCH + timedelta(seconds=2)), "crl_interval", False),
            OracleCase(
                "absent_accuracy",
                f.response(info_changes={"accuracy": None}),
                crl,
                "accuracy",
                True,
                "etzio_requires_explicit_accuracy",
            ),
            OracleCase(
                "excessive_accuracy",
                f.response(info_changes={"accuracy": {"seconds": 3}}),
                crl,
                "accuracy",
                True,
                "etzio_bounds_accuracy",
            ),
            OracleCase(
                "stale_crl",
                response,
                f.crl(before=EPOCH - timedelta(seconds=7200)),
                "crl_interval",
                True,
                "etzio_bounds_crl_age_over_full_hull",
            ),
        ]
    )
    return tuple(cases)
