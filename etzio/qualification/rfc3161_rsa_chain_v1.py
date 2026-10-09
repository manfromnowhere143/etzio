"""Finite offline RSA timestamp chain observations. See ADR-0021.

No acquisition, provider admission or kernel authority conversion is implemented.
The shared parser guards remain bound to ADR-0020's unchanged implementation.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, fields
from datetime import timedelta
from urllib.parse import urlsplit

from asn1crypto import core, tsp
from asn1crypto import crl as asn1_crl
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, ExtensionOID
from pyhanko.sign.validation.generic_cms import validate_tst_signed_data
from pyhanko.sign.validation.status import TimestampSignatureStatus
from pyhanko_certvalidator import ValidationContext

from etzio.kernel.integrity_adapters_v1 import TrustedTimeRequestV1
from etzio.protocol import canonical_dumps, content_id
from etzio.qualification.rfc3161_v1 import (
    _EPOCH,
    _MICROSECONDS,
    _OID,
    _SOURCE,
    CLIENT_VERSIONS_V1,
    MAX_CERTIFICATE_BYTES_V1,
    MAX_CRL_BYTES_V1,
    MAX_CRL_ENTRIES_V1,
    MAX_RESPONSE_BYTES_V1,
    NativeTimeError,
    _bounded_bytes,
    _canonical_der,
    _check_client_versions,
    _micros,
    _require,
    _sha256,
    _sha256_algorithm,
    _time_hull,
)

CODEC_V1 = "etzio.rfc3161.rsa-chain.offline.v1"
QC_EXTENSION_OID = "1.3.6.1.5.5.7.1.3"
QC_STATEMENT_OID = "0.4.0.19422.1.1"


class QCStatement(core.Sequence):
    _fields = [("statement_id", core.ObjectIdentifier), ("statement_info", core.Any, {"optional": True})]


class QCStatements(core.SequenceOf):
    _child_spec = QCStatement


def _rsa_signature(value, *, cms=False) -> None:
    _require(
        value["algorithm"].native in (("sha384_rsa", "rsassa_pkcs1v15") if cms else ("sha384_rsa",))
        and isinstance(value["parameters"], (core.Void, core.Null)),
        "algorithm_profile",
        "RSA PKCS#1 v1.5/SHA-384 with absent or NULL parameters required",
    )


def _sha384_algorithm(value) -> None:
    _require(
        value["algorithm"].native == "sha384" and isinstance(value["parameters"], (core.Void, core.Null)),
        "algorithm_profile",
        "SHA-384 digest with absent or NULL parameters required",
    )


def _certificate(data: bytes) -> x509.Certificate:
    _bounded_bytes(data, MAX_CERTIFICATE_BYTES_V1, "certificate")
    parsed = _canonical_der(asn1_x509.Certificate, data)
    tbs = parsed["tbs_certificate"]
    _rsa_signature(parsed["signature_algorithm"])
    spki = tbs["subject_public_key_info"]["algorithm"]
    _require(
        spki["algorithm"].native == "rsa"
        and isinstance(spki["parameters"], core.Null)
        and tbs["signature"].dump() == parsed["signature_algorithm"].dump(),
        "algorithm_profile",
        "RSA SPKI or certificate signature identifiers differ from profile",
    )
    _require(
        tbs["version"].native == "v3"
        and tbs["issuer_unique_id"].native is None
        and tbs["subject_unique_id"].native is None
        and 0 < tbs["serial_number"].native < 2**160,
        "certificate_profile",
        "unsupported certificate version, unique IDs or serial",
    )
    cert = x509.load_der_x509_certificate(data)
    key = cert.public_key()
    _require(
        isinstance(key, rsa.RSAPublicKey) and key.key_size == 4096 and key.public_numbers().e == 65537,
        "algorithm_profile",
        "RSA-4096 with exponent 65537 required",
    )
    return cert


def _uri(value: object) -> None:
    _require(type(value) is str and 0 < len(value) <= 2048, "certificate_profile", "bounded URI required")
    parsed = urlsplit(value)
    _require(
        value.isascii()
        and not any(ord(c) <= 32 or ord(c) == 127 for c in value)
        and parsed.scheme in {"http", "https"}
        and bool(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
        and not parsed.fragment,
        "certificate_profile",
        "unsupported metadata URI",
    )


def _metadata(cert: x509.Certificate, certificate_policy: str | None) -> None:
    for ext in cert.extensions:
        if ext.oid == ExtensionOID.AUTHORITY_INFORMATION_ACCESS:
            _require(not ext.critical and 0 < len(ext.value) <= 4, "certificate_profile", "unsupported AIA")
            for description in ext.value:
                _require(
                    description.access_method
                    in {AuthorityInformationAccessOID.OCSP, AuthorityInformationAccessOID.CA_ISSUERS}
                    and isinstance(description.access_location, x509.UniformResourceIdentifier),
                    "certificate_profile",
                    "unsupported AIA location",
                )
                _uri(description.access_location.value)
        elif ext.oid == ExtensionOID.CRL_DISTRIBUTION_POINTS:
            _require(not ext.critical and 0 < len(ext.value) <= 4, "certificate_profile", "unsupported CRLDP")
            for point in ext.value:
                _require(
                    point.full_name is not None
                    and 0 < len(point.full_name) <= 4
                    and point.relative_name is None
                    and point.reasons is None
                    and point.crl_issuer is None,
                    "certificate_profile",
                    "unsupported distribution point",
                )
                for name in point.full_name:
                    _require(isinstance(name, x509.UniformResourceIdentifier), "certificate_profile", "URI required")
                    _uri(name.value)
        elif ext.oid == ExtensionOID.CERTIFICATE_POLICIES:
            _require(not ext.critical and len(ext.value) == 1, "certificate_profile", "one certificate policy required")
            policy = ext.value[0]
            if certificate_policy is not None:
                _require(
                    policy.policy_identifier.dotted_string == certificate_policy,
                    "certificate_profile",
                    "TSA certificate policy differs from pin",
                )
            qualifiers = policy.policy_qualifiers or []
            _require(len(qualifiers) <= 4, "certificate_profile", "too many policy qualifiers")
            for qualifier in qualifiers:
                _uri(qualifier)


def _certificate_profile(profile) -> tuple[x509.Certificate, ...]:
    certs = tuple(_certificate(getattr(profile, role + "_certificate_der")) for role in ("root", "issuer", "tsa"))
    root, issuer, tsa = certs
    _require(
        len({cert.subject.public_bytes() for cert in certs}) == 3
        and len({cert.public_key().public_numbers().n for cert in certs}) == 3,
        "certificate_profile",
        "three distinct subjects and keys required",
    )
    common = {
        ExtensionOID.BASIC_CONSTRAINTS,
        ExtensionOID.KEY_USAGE,
        ExtensionOID.SUBJECT_KEY_IDENTIFIER,
        ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
    }
    metadata = {
        ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
        ExtensionOID.CRL_DISTRIBUTION_POINTS,
        ExtensionOID.CERTIFICATE_POLICIES,
    }
    try:
        for index, (cert, parent) in enumerate(zip(certs, (root, root, issuer), strict=True)):
            _require(cert.issuer == parent.subject, "certificate_profile", "certificate names a foreign issuer")
            cert.verify_directly_issued_by(parent)
            required = common | (
                {ExtensionOID.EXTENDED_KEY_USAGE, ExtensionOID.CERTIFICATE_POLICIES} if index == 2 else set()
            )
            present = {ext.oid for ext in cert.extensions}
            _require(
                required <= present <= required | metadata, "certificate_profile", "unsupported certificate extensions"
            )
            ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
            aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
            _require(
                not ski.critical
                and not aki.critical
                and ski.value.digest == x509.SubjectKeyIdentifier.from_public_key(cert.public_key()).digest
                and aki.value.key_identifier == x509.SubjectKeyIdentifier.from_public_key(parent.public_key()).digest
                and aki.value.authority_cert_issuer is None
                and aki.value.authority_cert_serial_number is None,
                "certificate_profile",
                "invalid SKI or AKI",
            )
            bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
            ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
            ca = index != 2
            _require(
                bc.critical
                and bc.value.ca == ca
                and (
                    bc.value.path_length is None
                    or (bc.value.path_length >= 1 if index == 0 else bc.value.path_length == 0)
                )
                and ku.critical
                and ku.value == x509.KeyUsage(not ca, False, False, False, False, ca, ca, False, False)
                and ku.value.digital_signature == (not ca)
                and ku.value.key_cert_sign == ca
                and ku.value.crl_sign == ca
                and not any(
                    (
                        ku.value.content_commitment,
                        ku.value.key_encipherment,
                        ku.value.data_encipherment,
                        ku.value.key_agreement,
                    )
                ),
                "certificate_profile",
                "certificate constraints or usage differ from role",
            )
            _metadata(cert, profile.tsa_certificate_policy_oid if index == 2 else None)
        eku = tsa.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        _require(
            eku.critical and list(eku.value) == [ExtendedKeyUsageOID.TIME_STAMPING],
            "certificate_profile",
            "critical sole timestamping EKU required",
        )
    except (InvalidSignature, x509.ExtensionNotFound) as exc:
        raise NativeTimeError("certificate_profile", "certificate issuer or required extension invalid") from exc
    return certs


@dataclass(frozen=True, slots=True)
class Rfc3161RsaChainProfileV1:
    source_id: str
    tsa_policy_oid: str
    tsa_certificate_policy_oid: str
    root_certificate_der: bytes
    issuer_certificate_der: bytes
    tsa_certificate_der: bytes
    max_accuracy_microseconds: int
    max_crl_age_seconds: int

    def __post_init__(self) -> None:
        try:
            _require(
                type(self.source_id) is str and _SOURCE.fullmatch(self.source_id) is not None,
                "profile",
                "invalid source identity",
            )
            for oid in (self.tsa_policy_oid, self.tsa_certificate_policy_oid):
                _require(
                    type(oid) is str and len(oid) <= 128 and _OID.fullmatch(oid) is not None,
                    "profile",
                    "invalid policy OID",
                )
                _require(
                    core.ObjectIdentifier.load(core.ObjectIdentifier(oid).dump()).dotted == oid,
                    "profile",
                    "noncanonical policy OID",
                )
            for value, maximum in (
                (self.max_accuracy_microseconds, 60 * _MICROSECONDS),
                (self.max_crl_age_seconds, 86400),
            ):
                _require(type(value) is int and 0 < value <= maximum, "profile", "invalid ceiling")
            _certificate_profile(self)
        except NativeTimeError:
            raise
        except (
            ValueError,
            TypeError,
            KeyError,
            IndexError,
            OverflowError,
            RecursionError,
            x509.DuplicateExtension,
            x509.InvalidVersion,
            UnsupportedAlgorithm,
        ) as exc:
            raise NativeTimeError("profile", "malformed RSA chain profile") from exc

    def to_body(self) -> dict[str, object]:
        result = {"codec": CODEC_V1, "clients": [{"distribution": n, "version": v} for n, v in CLIENT_VERSIONS_V1]}
        for field in fields(self):
            value = getattr(self, field.name)
            if field.name.endswith("_der"):
                result[field.name + "_b64"] = base64.b64encode(value).decode("ascii")
            else:
                result[field.name] = value
        return result

    @property
    def profile_id(self) -> str:
        return content_id("rfc3161_rsa_chain_profile_v1", self.to_body())


def _snapshot_inputs(profile, request):
    _require(
        type(profile) is Rfc3161RsaChainProfileV1 and type(request) is TrustedTimeRequestV1,
        "input_type",
        "exact RSA chain profile and trusted-time request required",
    )
    profile = Rfc3161RsaChainProfileV1(**{f.name: getattr(profile, f.name) for f in fields(profile)})
    request = TrustedTimeRequestV1.from_canonical_bytes(request.to_canonical_bytes())
    _require(
        profile.source_id == request.source_id and int(request.request_nonce, 16) > 0,
        "request_binding",
        "foreign source or nonpositive nonce",
    )
    return profile, request


def _request_der(profile, request) -> bytes:
    payload = b"etzio.native-rfc3161.rsa-chain.context.v1\x00" + canonical_dumps(
        {"native_profile_id": profile.profile_id, "request": request.to_body()}
    )
    return tsp.TimeStampReq(
        {
            "version": "v1",
            "message_imprint": {
                "hash_algorithm": {"algorithm": "sha256"},
                "hashed_message": hashlib.sha256(payload).digest(),
            },
            "req_policy": profile.tsa_policy_oid,
            "nonce": int(request.request_nonce, 16),
            "cert_req": True,
        }
    ).dump()


def build_rfc3161_rsa_chain_request_v1(*, profile: Rfc3161RsaChainProfileV1, request: TrustedTimeRequestV1) -> bytes:
    """Build exact offline query bytes without sending them anywhere."""
    _check_client_versions()
    return _request_der(*_snapshot_inputs(profile, request))


def _qualified_statement(info) -> None:
    extensions = info["extensions"]
    _require(len(extensions) == 1, "qualified_statement", "one qualified statement extension required")
    ext = extensions[0]
    _require(
        ext["extn_id"].dotted == QC_EXTENSION_OID and ext["critical"].native is False,
        "qualified_statement",
        "noncritical qcStatements required",
    )
    statements = _canonical_der(QCStatements, ext["extn_value"].native)
    _require(
        len(statements) == 1
        and statements[0]["statement_id"].dotted == QC_STATEMENT_OID
        and isinstance(statements[0]["statement_info"], core.Void),
        "qualified_statement",
        "one EuCompliance statement without information required",
    )


def _response(response_der: bytes, profile: Rfc3161RsaChainProfileV1, request_der: bytes):
    response = _canonical_der(tsp.TimeStampResp, response_der)
    status = response["status"]
    _require(
        status["status"].native == "granted"
        and status["fail_info"].native is None
        and status["status_string"].native is None,
        "response_status",
        "only an unmodified successful response is accepted",
    )
    token = response["time_stamp_token"]
    _require(token["content_type"].native == "signed_data", "cms_shape", "SignedData required")
    sd = token["content"]
    _require(
        sd["version"].native == "v3"
        and len(sd["signer_infos"]) == 1
        and len(sd["digest_algorithms"]) == 1
        and len(sd["certificates"]) == 2
        and sd["crls"].native is None,
        "cms_shape",
        "unsupported CMS cardinalities or version",
    )
    _sha384_algorithm(sd["digest_algorithms"][0])
    certs = sd["certificates"]
    _require(
        all(cert.name == "certificate" for cert in certs)
        and {cert.chosen.dump() for cert in certs} == {profile.tsa_certificate_der, profile.issuer_certificate_der},
        "certificate_binding",
        "CMS must embed exactly the pinned TSA and intermediate",
    )
    si = sd["signer_infos"][0]
    _require(
        si["version"].native == "v1"
        and si["sid"].name == "issuer_and_serial_number"
        and si["unsigned_attrs"].native is None,
        "cms_shape",
        "unsupported SignerInfo",
    )
    _sha384_algorithm(si["digest_algorithm"])
    _rsa_signature(si["signature_algorithm"], cms=True)
    tsa = asn1_x509.Certificate.load(profile.tsa_certificate_der)
    sid = si["sid"].chosen
    _require(
        sid["issuer"] == tsa.issuer and sid["serial_number"].native == tsa.serial_number,
        "certificate_binding",
        "signer identity differs from pinned TSA",
    )
    attrs = si["signed_attrs"]
    _require(
        len(attrs) == 3
        and {attr["type"].native for attr in attrs} == {"content_type", "message_digest", "signing_certificate_v2"}
        and all(len(attr["values"]) == 1 for attr in attrs),
        "cms_shape",
        "exact single-valued signed attribute roster required",
    )
    ess = next(attr["values"][0] for attr in attrs if attr["type"].native == "signing_certificate_v2")
    _require(
        len(ess["certs"]) == 1 and ess["policies"].native is None, "certificate_binding", "one ESSCertIDv2 required"
    )
    _sha256_algorithm(ess["certs"][0]["hash_algorithm"])
    _require(
        ess["certs"][0]["cert_hash"].native == hashlib.sha256(profile.tsa_certificate_der).digest()
        and ess["certs"][0]["issuer_serial"].native is None,
        "certificate_binding",
        "ESSCertIDv2 differs from pinned TSA",
    )
    eci = sd["encap_content_info"]
    _require(eci["content_type"].native == "tst_info", "cms_shape", "TSTInfo required")
    info = _canonical_der(tsp.TSTInfo, bytes(eci["content"]))
    _require(
        info["version"].native == "v1",
        "tst_profile",
        "unsupported TSTInfo version/extensions",
    )
    _qualified_statement(info)
    serial = info["serial_number"].native
    _require(type(serial) is int and 0 < serial < 2**160, "tst_profile", "serial outside profile")
    query = tsp.TimeStampReq.load(request_der, strict=True)
    _sha256_algorithm(info["message_imprint"]["hash_algorithm"])
    _require(
        info["policy"].native == profile.tsa_policy_oid
        and info["nonce"].native == query["nonce"].native
        and info["message_imprint"]["hashed_message"].native == query["message_imprint"]["hashed_message"].native,
        "request_binding",
        "policy, nonce or imprint differs from exact request",
    )
    if info["tsa"].native is not None:
        tsa = asn1_x509.Certificate.load(profile.tsa_certificate_der)
        _require(
            info["tsa"].name == "directory_name" and info["tsa"].chosen == tsa.subject,
            "certificate_binding",
            "TSA name differs from pinned certificate",
        )
    return sd, info, query["message_imprint"]["hashed_message"].native


def _crl_and_interval(profile, crl_der: bytes, parent, subject, role: str, lower: int, upper: int):
    parsed = _canonical_der(asn1_crl.CertificateList, crl_der)
    _require(parsed["tbs_cert_list"]["version"].native == "v2", "crl_profile", "version-2 CRL required")
    _require(
        parsed["tbs_cert_list"]["signature"].dump() == parsed["signature_algorithm"].dump(),
        "algorithm_profile",
        "inner and outer CRL signature algorithms differ",
    )
    _rsa_signature(parsed["signature_algorithm"])
    crl = x509.load_der_x509_crl(crl_der)
    _require(len(crl) <= MAX_CRL_ENTRIES_V1, "resource_limit", "too many CRL entries")
    _require(
        crl.issuer == parent.subject and crl.is_signature_valid(parent.public_key()),
        "crl_authentication",
        "CRL issuer/signature differs from expected issuer",
    )
    _require(
        {ext.oid for ext in crl.extensions} == {ExtensionOID.AUTHORITY_KEY_IDENTIFIER, ExtensionOID.CRL_NUMBER}
        and all(not ext.critical for ext in crl.extensions),
        "crl_profile",
        "unsupported CRL extensions",
    )
    aki = crl.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    _require(
        aki.key_identifier == parent.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
        and aki.authority_cert_issuer is None
        and aki.authority_cert_serial_number is None,
        "crl_profile",
        "CRL authority differs from expected issuer",
    )
    number = crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    _require(0 <= number < 2**160, "crl_profile", "CRL number outside profile")
    _require(
        crl.next_update_utc is not None
        and _micros(crl.last_update_utc) <= lower
        and upper < _micros(crl.next_update_utc)
        and upper - _micros(crl.last_update_utc) <= profile.max_crl_age_seconds * _MICROSECONDS,
        "crl_interval",
        "CRL must be fresh and cover full hull with half-open validity",
    )
    serials: set[int] = set()
    for entry in crl:
        _require(
            len(entry.extensions) == 0 and 0 < entry.serial_number < 2**160 and entry.serial_number not in serials,
            "crl_profile",
            "unsupported/duplicate CRL entry",
        )
        serials.add(entry.serial_number)
    _require(subject.serial_number not in serials, "revoked_" + role, "retained CRL lists the " + role)
    return parsed


@dataclass(frozen=True, slots=True)
class Rfc3161RsaChainObservationV1:
    """Retained offline evidence; intentionally not a kernel-accepted time bundle."""

    profile_bytes: bytes
    context_bytes: bytes
    request_der: bytes
    response_der: bytes
    root_crl_der: bytes
    issuer_crl_der: bytes
    generated_microseconds: int
    accuracy_microseconds: int
    lower_microseconds: int
    upper_microseconds: int

    @property
    def lower_second(self) -> int:
        return self.lower_microseconds // _MICROSECONDS

    @property
    def upper_second(self) -> int:
        return -(-self.upper_microseconds // _MICROSECONDS)

    def to_body(self) -> dict[str, object]:
        return {
            "codec": CODEC_V1,
            "status": "offline_observation",
            "kernel_authority": False,
            "clients": [{"distribution": name, "version": pinned} for name, pinned in CLIENT_VERSIONS_V1],
            "artifacts": {
                name: {"sha256": _sha256(getattr(self, name)), "size": len(getattr(self, name))}
                for name in (
                    "profile_bytes",
                    "context_bytes",
                    "request_der",
                    "response_der",
                    "root_crl_der",
                    "issuer_crl_der",
                )
            },
            "generated_microseconds": self.generated_microseconds,
            "accuracy_microseconds": self.accuracy_microseconds,
            "lower_microseconds": self.lower_microseconds,
            "upper_microseconds": self.upper_microseconds,
            "lower_second": self.lower_second,
            "upper_second": self.upper_second,
        }

    @property
    def observation_id(self) -> str:
        return content_id("rfc3161_rsa_chain_observation_v1", self.to_body())


async def validate_rfc3161_rsa_chain_offline_v1(
    *,
    profile: Rfc3161RsaChainProfileV1,
    request: TrustedTimeRequestV1,
    response_der: bytes,
    root_crl_der: bytes,
    issuer_crl_der: bytes,
) -> Rfc3161RsaChainObservationV1:
    """Reauthenticate retained native bytes under the exact bounded offline profile.

    Unauthenticated time fields are provisional parser inputs to PKIX validation;
    no observation escapes until CMS, path and revocation checks all succeed.
    """
    try:
        _check_client_versions()
        profile, request = _snapshot_inputs(profile, request)
        _bounded_bytes(response_der, MAX_RESPONSE_BYTES_V1, "timestamp response")
        _bounded_bytes(root_crl_der, MAX_CRL_BYTES_V1, "root CRL")
        _bounded_bytes(issuer_crl_der, MAX_CRL_BYTES_V1, "issuer CRL")
        query_der = _request_der(profile, request)
        sd, info, imprint = _response(response_der, profile, query_der)
        generated, accuracy, lower, upper = _time_hull(info, profile)
        root, issuer, tsa = _certificate_profile(profile)
        for cert in (root, issuer, tsa):
            _require(
                _micros(cert.not_valid_before_utc) <= lower and upper <= _micros(cert.not_valid_after_utc),
                "certificate_interval",
                "certificate must cover complete time hull",
            )
        crls = [
            _crl_and_interval(profile, root_crl_der, root, issuer, "intermediate", lower, upper),
            _crl_and_interval(profile, issuer_crl_der, issuer, tsa, "tsa", lower, upper),
        ]
        for endpoint in (lower, upper):
            # Fresh context at each endpoint: no cached point-validation result.
            context = ValidationContext(
                trust_roots=[asn1_x509.Certificate.load(profile.root_certificate_der)],
                moment=_EPOCH + timedelta(microseconds=endpoint),
                best_signature_time=_EPOCH + timedelta(microseconds=endpoint),
                allow_fetching=False,
                crls=crls,
                other_certs=[asn1_x509.Certificate.load(profile.issuer_certificate_der)],
                ocsps=[],
                revocation_mode="require",
                time_tolerance=timedelta(0),
                retroactive_revinfo=False,
            )
            kwargs = await validate_tst_signed_data(sd, context, lambda _algorithm: imprint)
            status = TimestampSignatureStatus(**kwargs)
            _require(
                status.intact and status.valid and status.trusted,
                "signature_or_path",
                "native CMS/path validation failed",
            )
        return Rfc3161RsaChainObservationV1(
            canonical_dumps(profile.to_body()),
            request.to_canonical_bytes(),
            query_der,
            response_der,
            root_crl_der,
            issuer_crl_der,
            generated,
            accuracy,
            lower,
            upper,
        )
    except NativeTimeError:
        raise
    except (
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        OverflowError,
        RecursionError,
        x509.DuplicateExtension,
        x509.InvalidVersion,
        UnsupportedAlgorithm,
    ) as exc:
        raise NativeTimeError("malformed_native_evidence", "native parser or validation refused evidence") from exc
