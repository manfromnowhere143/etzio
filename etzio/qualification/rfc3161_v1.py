"""Bounded RFC 3161/5816 offline observations; no acquisition or kernel authority.

CMS and PKIX validation are delegated to pinned pyHanko. See ADR-0020 for the
strict subset, deterministic fixture boundary and outstanding provider gates.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from importlib.metadata import PackageNotFoundError, version
from typing import Final

from asn1crypto import core, tsp
from asn1crypto import crl as asn1_crl
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, SignatureAlgorithmOID
from pyhanko.sign.validation.generic_cms import validate_tst_signed_data
from pyhanko.sign.validation.status import TimestampSignatureStatus
from pyhanko_certvalidator import ValidationContext

from etzio.kernel.integrity_adapters_v1 import TrustedTimeRequestV1
from etzio.protocol import canonical_dumps, content_id

CODEC_V1: Final = "etzio.rfc3161.offline.v1"
CLIENT_VERSIONS_V1: Final = (
    ("aiohappyeyeballs", "2.7.1"),
    ("aiohttp", "3.14.4"),
    ("aiosignal", "1.4.0"),
    ("asn1crypto", "1.5.1"),
    ("attrs", "26.1.0"),
    ("certifi", "2026.7.22"),
    ("cffi", "2.1.0"),
    ("cryptography", "49.0.0"),
    ("frozenlist", "1.8.0"),
    ("idna", "3.20"),
    ("lxml", "6.1.3"),
    ("multidict", "6.9.1"),
    ("oscrypto", "1.3.0"),
    ("propcache", "0.5.4"),
    ("pycparser", "3.0"),
    ("pyhanko", "0.37.0"),
    ("pyhanko-certvalidator", "0.32.1"),
    ("typing-extensions", "4.16.0"),
    ("tzlocal", "5.4.4"),
    ("uritools", "6.1.3"),
    ("yarl", "1.25.1"),
)
MAX_RESPONSE_BYTES_V1: Final = 64 << 10
MAX_CERTIFICATE_BYTES_V1: Final = 16 << 10
MAX_CRL_BYTES_V1: Final = 256 << 10
MAX_CRL_ENTRIES_V1: Final = 1024
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_MICROSECONDS = 1_000_000
_TIME = re.compile(rb"[0-9]{14}(?:\.[0-9]{0,5}[1-9])?Z")
_SOURCE = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{1,127}", re.ASCII)
_OID = re.compile(r"[0-2](?:\.(?:0|[1-9][0-9]{0,9})){1,31}", re.ASCII)


class NativeTimeError(ValueError):
    """A deterministic offline profile refusal, never a successful observation."""

    def __init__(self, reason_code: str, message: str):
        self.reason_code = reason_code
        super().__init__(message)


def _check_client_versions() -> None:
    try:
        matched = all(version(name) == expected for name, expected in CLIENT_VERSIONS_V1)
    except PackageNotFoundError as exc:
        raise NativeTimeError("dependency_version", "native qualification dependency is missing") from exc
    _require(matched, "dependency_version", "native qualification dependency differs from pinned closure")


def _require(condition: bool, reason: str, message: str) -> None:
    if not condition:
        raise NativeTimeError(reason, message)


def _bounded_bytes(value: object, maximum: int, label: str) -> bytes:
    _require(type(value) is bytes, "input_type", f"{label} requires exact immutable bytes")
    _require(0 < len(value) <= maximum, "resource_limit", f"{label} exceeds byte bounds")
    return value


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _micros(value: datetime) -> int:
    delta = value - _EPOCH
    return (delta.days * 86400 + delta.seconds) * _MICROSECONDS + delta.microseconds


def _closed_asn1_tree(value, *, depth: int = 0, budget: list[int] | None = None) -> None:
    # Walk the library's typed tree; do not decode ASN.1 tags/lengths ourselves.
    if budget is None:
        budget = [32768]
    budget[0] -= 1
    _require(depth <= 32 and budget[0] >= 0, "resource_limit", "ASN.1 tree exceeds structural bounds")
    if isinstance(value, core.GeneralizedTime):
        # Check precision before the dependency can normalise through datetime.
        _require(
            _TIME.fullmatch(value.contents) is not None,
            "time_encoding",
            "unsupported GeneralizedTime precision/encoding",
        )
    if isinstance(value, core.Choice):
        children = (value.chosen,)
    elif isinstance(value, (core.Any, core.ParsableOctetString)):
        children = (value.parsed,)
    elif isinstance(value, core.Sequence):
        _require(len(value) == len(value._fields), "asn1_shape", "unknown ASN.1 sequence fields")
        children = (value[index] for index in range(len(value)))
    elif isinstance(value, (core.SequenceOf, core.SetOf)):
        _require(len(value) <= 1024, "resource_limit", "ASN.1 collection exceeds bound")
        children = iter(value)
    else:
        children = ()
    for child in children:
        _closed_asn1_tree(child, depth=depth + 1, budget=budget)


def _canonical_der(cls, data: bytes):
    parsed = cls.load(data, strict=True)
    _closed_asn1_tree(parsed)
    _require(parsed.dump(force=True) == data, "noncanonical_der", "wire is not canonical DER")
    return parsed


def _p256_signature(value, label: str) -> None:
    _require(
        value.signature_algorithm_oid == SignatureAlgorithmOID.ECDSA_WITH_SHA256,
        "algorithm_profile",
        f"{label} requires ECDSA/SHA-256",
    )


def _certificate(data: bytes, label: str) -> x509.Certificate:
    _bounded_bytes(data, MAX_CERTIFICATE_BYTES_V1, label)
    parsed = _canonical_der(asn1_x509.Certificate, data)
    tbs = parsed["tbs_certificate"]
    _require(
        tbs["signature"].dump() == parsed["signature_algorithm"].dump(),
        "algorithm_profile",
        "inner and outer certificate signature algorithms differ",
    )
    _require(
        isinstance(parsed["signature_algorithm"]["parameters"], core.Void),
        "algorithm_profile",
        "ECDSA certificate algorithm parameters must be absent",
    )
    _require(
        tbs["issuer_unique_id"].native is None
        and tbs["subject_unique_id"].native is None
        and 0 < tbs["serial_number"].native < 2**160,
        "certificate_profile",
        "unsupported certificate unique IDs or serial",
    )
    cert = x509.load_der_x509_certificate(data)
    key = cert.public_key()
    _require(
        isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1),
        "algorithm_profile",
        f"{label} requires P-256",
    )
    _p256_signature(cert, label)
    return cert


def _certificate_profile(root_der: bytes, tsa_der: bytes) -> tuple[x509.Certificate, x509.Certificate]:
    root, tsa = _certificate(root_der, "root"), _certificate(tsa_der, "TSA")
    _require(
        root_der != tsa_der and root.subject == root.issuer and tsa.issuer == root.subject,
        "certificate_profile",
        "one distinct directly issued TSA certificate is required",
    )
    _require(
        root.public_key().public_numbers() != tsa.public_key().public_numbers(),
        "certificate_profile",
        "root and TSA must use distinct keys",
    )
    try:
        root.verify_directly_issued_by(root)
        tsa.verify_directly_issued_by(root)
        common = {
            ExtensionOID.BASIC_CONSTRAINTS,
            ExtensionOID.KEY_USAGE,
            ExtensionOID.SUBJECT_KEY_IDENTIFIER,
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
        }
        for cert, allowed in ((root, common), (tsa, common | {ExtensionOID.EXTENDED_KEY_USAGE})):
            _require(
                {ext.oid for ext in cert.extensions} == allowed,
                "certificate_profile",
                "certificate extensions differ from exact profile",
            )
            ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
            expected = x509.SubjectKeyIdentifier.from_public_key(cert.public_key()).digest
            _require(ski == expected, "certificate_profile", "certificate SKI differs from public key")
            aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
            _require(
                aki.key_identifier == x509.SubjectKeyIdentifier.from_public_key(root.public_key()).digest
                and aki.authority_cert_issuer is None
                and aki.authority_cert_serial_number is None,
                "certificate_profile",
                "certificate AKI differs from direct root",
            )
        root_bc = root.extensions.get_extension_for_class(x509.BasicConstraints)
        tsa_bc = tsa.extensions.get_extension_for_class(x509.BasicConstraints)
        _require(
            root_bc.critical
            and root_bc.value.ca
            and root_bc.value.path_length == 0
            and tsa_bc.critical
            and not tsa_bc.value.ca,
            "certificate_profile",
            "direct root and non-CA TSA constraints required",
        )
        root_ku = root.extensions.get_extension_for_class(x509.KeyUsage)
        tsa_ku = tsa.extensions.get_extension_for_class(x509.KeyUsage)
        _require(
            root_ku.critical
            and root_ku.value.key_cert_sign
            and root_ku.value.crl_sign
            and tsa_ku.critical
            and tsa_ku.value.digital_signature
            and not tsa_ku.value.key_cert_sign
            and not tsa_ku.value.crl_sign,
            "certificate_profile",
            "certificate key usages differ from profile",
        )
        eku = tsa.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        _require(
            eku.critical and list(eku.value) == [ExtendedKeyUsageOID.TIME_STAMPING],
            "certificate_profile",
            "TSA EKU must be critical and contain only timestamping",
        )
    except (InvalidSignature, x509.ExtensionNotFound) as exc:
        raise NativeTimeError("certificate_profile", "invalid direct issuer or certificate usage") from exc
    return root, tsa


@dataclass(frozen=True, slots=True)
class Rfc3161OfflineProfileV1:
    """Pinned offline policy, not an admitted external-provider profile."""

    source_id: str
    tsa_policy_oid: str
    root_certificate_der: bytes
    tsa_certificate_der: bytes
    max_accuracy_microseconds: int
    max_crl_age_seconds: int

    def __post_init__(self) -> None:
        _require(
            type(self.source_id) is str and _SOURCE.fullmatch(self.source_id) is not None,
            "profile",
            "invalid source identity",
        )
        _require(
            type(self.tsa_policy_oid) is str
            and len(self.tsa_policy_oid) <= 128
            and _OID.fullmatch(self.tsa_policy_oid) is not None,
            "profile",
            "invalid TSA policy OID",
        )
        try:
            _require(
                tsp.ObjectIdentifier.load(tsp.ObjectIdentifier(self.tsa_policy_oid).dump()).dotted
                == self.tsa_policy_oid,
                "profile",
                "noncanonical policy OID",
            )
            for value, maximum in (
                (self.max_accuracy_microseconds, 60 * _MICROSECONDS),
                (self.max_crl_age_seconds, 86400),
            ):
                _require(type(value) is int and 0 < value <= maximum, "profile", "invalid policy ceiling")
            _certificate_profile(self.root_certificate_der, self.tsa_certificate_der)
        except NativeTimeError:
            raise
        except (
            ValueError,
            TypeError,
            OverflowError,
            RecursionError,
            x509.DuplicateExtension,
            x509.InvalidVersion,
            UnsupportedAlgorithm,
        ) as exc:
            raise NativeTimeError("profile", "malformed offline profile") from exc

    def to_body(self) -> dict[str, object]:
        return {
            "codec": CODEC_V1,
            "clients": [{"distribution": name, "version": pinned} for name, pinned in CLIENT_VERSIONS_V1],
            "source_id": self.source_id,
            "tsa_policy_oid": self.tsa_policy_oid,
            "root_certificate_der_b64": base64.b64encode(self.root_certificate_der).decode("ascii"),
            "tsa_certificate_der_b64": base64.b64encode(self.tsa_certificate_der).decode("ascii"),
            "max_accuracy_microseconds": self.max_accuracy_microseconds,
            "max_crl_age_seconds": self.max_crl_age_seconds,
        }

    @property
    def profile_id(self) -> str:
        return content_id("rfc3161_offline_profile_v1", self.to_body())


def _snapshot_inputs(profile, request) -> tuple[Rfc3161OfflineProfileV1, TrustedTimeRequestV1]:
    _require(
        type(profile) is Rfc3161OfflineProfileV1 and type(request) is TrustedTimeRequestV1,
        "input_type",
        "exact offline profile and trusted-time request types required",
    )
    profile = Rfc3161OfflineProfileV1(
        profile.source_id,
        profile.tsa_policy_oid,
        profile.root_certificate_der,
        profile.tsa_certificate_der,
        profile.max_accuracy_microseconds,
        profile.max_crl_age_seconds,
    )
    request = TrustedTimeRequestV1.from_canonical_bytes(request.to_canonical_bytes())
    _require(profile.source_id == request.source_id, "request_binding", "foreign request source")
    _require(int(request.request_nonce, 16) > 0, "request_binding", "nonce must be positive")
    return profile, request


def _request_der(profile: Rfc3161OfflineProfileV1, request: TrustedTimeRequestV1) -> bytes:
    payload = b"etzio.native-rfc3161.context.v1\x00" + canonical_dumps(
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


def build_rfc3161_request_v1(*, profile: Rfc3161OfflineProfileV1, request: TrustedTimeRequestV1) -> bytes:
    """Build deterministic request bytes without sending them anywhere."""
    _check_client_versions()
    return _request_der(*_snapshot_inputs(profile, request))


def _sha256_algorithm(value) -> None:
    _require(
        value["algorithm"].native == "sha256" and value["parameters"].native is None,
        "algorithm_profile",
        "only SHA-256 with absent/NULL parameters is accepted",
    )


def _response(response_der: bytes, profile: Rfc3161OfflineProfileV1, request_der: bytes):
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
        and len(sd["certificates"]) == 1
        and sd["crls"].native is None,
        "cms_shape",
        "unsupported CMS cardinalities or version",
    )
    _sha256_algorithm(sd["digest_algorithms"][0])
    cert = sd["certificates"][0]
    _require(
        cert.name == "certificate" and cert.chosen.dump() == profile.tsa_certificate_der,
        "certificate_binding",
        "CMS must embed exactly the pinned TSA certificate",
    )
    si = sd["signer_infos"][0]
    _require(
        si["version"].native == "v1"
        and si["sid"].name == "issuer_and_serial_number"
        and si["unsigned_attrs"].native is None,
        "cms_shape",
        "unsupported SignerInfo",
    )
    _sha256_algorithm(si["digest_algorithm"])
    _require(
        si["signature_algorithm"]["algorithm"].native == "sha256_ecdsa"
        and isinstance(si["signature_algorithm"]["parameters"], core.Void),
        "algorithm_profile",
        "CMS requires ECDSA/SHA-256",
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
        info["version"].native == "v1" and info["extensions"].native is None,
        "tst_profile",
        "unsupported TSTInfo version/extensions",
    )
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


def _time_hull(info, profile: Rfc3161OfflineProfileV1) -> tuple[int, int, int, int]:
    raw_time = info["gen_time"].contents
    _require(_TIME.fullmatch(raw_time) is not None, "time_encoding", "unsupported GeneralizedTime precision/encoding")
    generated = _micros(info["gen_time"].native)
    _require(info["accuracy"].native is not None, "accuracy", "explicit accuracy required")
    accuracy = 0
    for name, scale, maximum in (("seconds", _MICROSECONDS, 60), ("millis", 1000, 999), ("micros", 1, 999)):
        value = info["accuracy"][name].native
        if value is None:
            continue
        _require(
            type(value) is int and (0 if name == "seconds" else 1) <= value <= maximum,
            "accuracy",
            "accuracy component outside profile",
        )
        accuracy += value * scale
    _require(0 < accuracy <= profile.max_accuracy_microseconds, "accuracy", "missing/zero/excessive accuracy")
    lower, upper = generated - accuracy, generated + accuracy
    _require(
        lower >= 0 and upper < _micros(datetime(9999, 1, 1, tzinfo=UTC)),
        "time_bounds",
        "timestamp hull outside supported epoch",
    )
    return generated, accuracy, lower, upper


def _crl_and_interval(profile, crl_der: bytes, lower: int, upper: int):
    root, tsa = _certificate_profile(profile.root_certificate_der, profile.tsa_certificate_der)
    for cert in (root, tsa):
        _require(
            _micros(cert.not_valid_before_utc) <= lower and upper <= _micros(cert.not_valid_after_utc),
            "certificate_interval",
            "certificate does not cover complete time hull",
        )
    parsed = _canonical_der(asn1_crl.CertificateList, crl_der)
    _require(
        parsed["tbs_cert_list"]["signature"].dump() == parsed["signature_algorithm"].dump(),
        "algorithm_profile",
        "inner and outer CRL signature algorithms differ",
    )
    _require(
        isinstance(parsed["signature_algorithm"]["parameters"], core.Void),
        "algorithm_profile",
        "ECDSA CRL algorithm parameters must be absent",
    )
    crl = x509.load_der_x509_crl(crl_der)
    _p256_signature(crl, "CRL")
    _require(len(crl) <= MAX_CRL_ENTRIES_V1, "resource_limit", "too many CRL entries")
    _require(
        crl.issuer == root.subject and crl.is_signature_valid(root.public_key()),
        "crl_authentication",
        "CRL issuer/signature differs from root",
    )
    _require(
        {ext.oid for ext in crl.extensions} == {ExtensionOID.AUTHORITY_KEY_IDENTIFIER, ExtensionOID.CRL_NUMBER}
        and all(not ext.critical for ext in crl.extensions),
        "crl_profile",
        "unsupported CRL extensions",
    )
    aki = crl.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    _require(
        aki.key_identifier == root.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
        and aki.authority_cert_issuer is None
        and aki.authority_cert_serial_number is None,
        "crl_profile",
        "CRL authority differs from root",
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
    _require(tsa.serial_number not in serials, "revoked", "retained CRL lists the TSA")
    return parsed


@dataclass(frozen=True, slots=True)
class Rfc3161OfflineObservationV1:
    """Retained offline evidence; intentionally not a kernel-accepted time bundle."""

    profile_bytes: bytes
    context_bytes: bytes
    request_der: bytes
    response_der: bytes
    crl_der: bytes
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
                for name in ("profile_bytes", "context_bytes", "request_der", "response_der", "crl_der")
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
        return content_id("rfc3161_offline_observation_v1", self.to_body())


async def validate_rfc3161_offline_v1(
    *,
    profile: Rfc3161OfflineProfileV1,
    request: TrustedTimeRequestV1,
    response_der: bytes,
    crl_der: bytes,
) -> Rfc3161OfflineObservationV1:
    """Reauthenticate retained native bytes under the exact bounded offline profile.

    Unauthenticated time fields are provisional parser inputs to PKIX validation;
    no observation escapes until CMS, path and revocation checks all succeed.
    """
    try:
        _check_client_versions()
        profile, request = _snapshot_inputs(profile, request)
        _bounded_bytes(response_der, MAX_RESPONSE_BYTES_V1, "timestamp response")
        _bounded_bytes(crl_der, MAX_CRL_BYTES_V1, "CRL")
        query_der = _request_der(profile, request)
        sd, info, imprint = _response(response_der, profile, query_der)
        generated, accuracy, lower, upper = _time_hull(info, profile)
        crl = _crl_and_interval(profile, crl_der, lower, upper)
        for endpoint in (lower, upper):
            # Fresh context at each endpoint: no cached point-validation result.
            context = ValidationContext(
                trust_roots=[asn1_x509.Certificate.load(profile.root_certificate_der)],
                moment=_EPOCH + timedelta(microseconds=endpoint),
                best_signature_time=_EPOCH + timedelta(microseconds=endpoint),
                allow_fetching=False,
                crls=[crl],
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
        return Rfc3161OfflineObservationV1(
            canonical_dumps(profile.to_body()),
            request.to_canonical_bytes(),
            query_der,
            response_der,
            crl_der,
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
