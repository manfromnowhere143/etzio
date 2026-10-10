"""Bounded historical CMS/path replay. No request, provider or kernel admission."""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import re
import sys
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from asn1crypto import cms, core, tsp  # noqa: E402
from asn1crypto import crl as asn1_crl  # noqa: E402
from asn1crypto import x509 as asn1_x509  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from pyhanko.sign.validation.generic_cms import validate_tst_signed_data  # noqa: E402
from pyhanko.sign.validation.status import TimestampSignatureStatus  # noqa: E402
from pyhanko_certvalidator import ValidationContext  # noqa: E402

from etzio.protocol import strict_loads  # noqa: E402
from etzio.qualification.rfc3161_v1 import (  # noqa: E402
    _EPOCH,
    _canonical_der,
    _check_client_versions,
    _closed_asn1_tree,
    _micros,
    _time_hull,
)

SCHEMA = "etzio.archived-timestamp-material.v1"
ROLES = ("root_certificate", "issuer_certificate", "tsa_certificate", "root_crl", "issuer_crl", "response")
MAX_MANIFEST_BYTES = 131072
SIGNED_ATTRIBUTES = {
    "1.2.840.113549.1.9.3",
    "1.2.840.113549.1.9.4",
    "1.2.840.113549.1.9.5",
    "1.2.840.113549.1.9.16.2.15",
    "1.2.840.113549.1.9.16.2.18",
    "1.2.840.113549.1.9.16.2.47",
}


class CertifiedSignerAttribute(core.Choice):
    _alternatives = [("certified", cms.AttributeCertificateV2, {"explicit": 1})]


class SignerAttribute(core.SequenceOf):
    _child_spec = CertifiedSignerAttribute


def _canonical_response(wire: bytes):
    response = tsp.TimeStampResp.load(wire, strict=True)
    require(response["time_stamp_token"]["content_type"].native == "signed_data", "SignedData required")
    signers = response["time_stamp_token"]["content"]["signer_infos"]
    require(len(signers) == 1, "CMS signer roster")
    attrs = signers[0]["signed_attrs"]
    require(len(attrs) == len(SIGNED_ATTRIBUTES), "signed attribute roster")
    for attr in attrs:
        if attr["type"].dotted == "1.2.840.113549.1.9.16.2.18":
            require(len(attr["values"]) == 1, "signer attribute cardinality")
            # Local parse cache only: no global ASN.1 registry mutation.
            value = attr["values"][0].parse(SignerAttribute)
            require(len(value) == 1, "certified signer attribute cardinality")
    _closed_asn1_tree(response)
    require(response.dump(force=True) == wire, "noncanonical response DER")
    return response


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def decode_manifest(wire: bytes) -> tuple[dict[str, bytes], bytes]:
    require(type(wire) is bytes and 0 < len(wire) <= MAX_MANIFEST_BYTES, "manifest size")
    body = strict_loads(wire)
    require(type(body) is dict and set(body) == {"schema", "expected_imprint_sha256", "artifacts"}, "manifest shape")
    require(body["schema"] == SCHEMA, "manifest schema")
    imprint = body["expected_imprint_sha256"]
    require(type(imprint) is str and re.fullmatch(r"[0-9a-f]{64}", imprint) is not None, "imprint shape")
    entries = body["artifacts"]
    require(type(entries) is list and len(entries) == len(ROLES), "artifact roster")
    material = {}
    for role, entry in zip(ROLES, entries, strict=True):
        require(type(entry) is dict and set(entry) == {"role", "size", "sha256", "der_base64"}, "artifact shape")
        require(entry["role"] == role, "artifact role/order")
        size = entry["size"]
        require(type(size) is int and 0 < size <= (65536 if role == "response" else 16384), "artifact size")
        encoded = entry["der_base64"]
        require(type(encoded) is str and len(encoded) == 4 * ((size + 2) // 3), "base64 size")
        data = base64.b64decode(encoded, validate=True)
        require(base64.b64encode(data).decode() == encoded, "base64 encoding")
        require(len(data) == size and sha(data) == entry["sha256"], "artifact digest/size")
        material[role] = data
    require(len(set(material.values())) == len(ROLES), "artifact reuse")
    return material, bytes.fromhex(imprint)


def load_manifest(path: Path) -> bytes:
    with path.open("rb") as source:
        wire = source.read(MAX_MANIFEST_BYTES + 1)
    decode_manifest(wire)
    return wire


def _parse(material):
    parsed_certs = [_canonical_der(asn1_x509.Certificate, material[role]) for role in ROLES[:3]]
    certs = [x509.load_der_x509_certificate(material[role]) for role in ROLES[:3]]
    require(len({c.subject.hashable for c in parsed_certs}) == 3, "certificate role separation")
    for cert, parent in zip(certs, (certs[0], certs[0], certs[1]), strict=True):
        require(isinstance(cert.public_key(), rsa.RSAPublicKey) and cert.public_key().key_size == 4096, "RSA-4096")
        cert.verify_directly_issued_by(parent)
    parsed_crls = [_canonical_der(asn1_crl.CertificateList, material[role]) for role in ROLES[3:5]]
    crls = [x509.load_der_x509_crl(material[role]) for role in ROLES[3:5]]
    for crl, parent, child in zip(crls, certs[:2], certs[1:], strict=True):
        require(crl.issuer == parent.subject and crl.is_signature_valid(parent.public_key()), "CRL issuer/signature")
        require(crl.next_update_utc is not None, "CRL nextUpdate")
        require(crl.get_revoked_certificate_by_serial_number(child.serial_number) is None, "subject revoked")
    return parsed_certs, certs, parsed_crls, crls


def _validity(certs, crls, lower: int, upper: int):
    require(lower <= upper, "reversed issuance hull")
    for cert in certs:
        require(
            _micros(cert.not_valid_before_utc) <= lower <= upper <= _micros(cert.not_valid_after_utc),
            "certificate interval",
        )
    for crl in crls:
        require(_micros(crl.last_update_utc) <= lower <= upper < _micros(crl.next_update_utc), "CRL interval")


def _sha256_algorithm(value):
    require(
        value["algorithm"].native == "sha256" and isinstance(value["parameters"], (core.Null, core.Void)), "SHA-256"
    )


def _response(material, certificates, imprint):
    response = _canonical_response(material["response"])
    status = response["status"]
    require(status["status"].native == "granted" and status["fail_info"].native is None, "response status")
    require(status["status_string"].native is None, "response status string")
    require(response["time_stamp_token"]["content_type"].native == "signed_data", "SignedData required")
    sd = response["time_stamp_token"]["content"]
    require(sd["version"].native == "v3" and sd["crls"].native is None, "CMS version/CRLs")
    require(len(sd["certificates"]) == 2 and len(sd["signer_infos"]) == 1, "CMS roster")
    require(all(c.name == "certificate" for c in sd["certificates"]), "certificate choice")
    require(
        {c.chosen.dump() for c in sd["certificates"]} == {material["issuer_certificate"], material["tsa_certificate"]},
        "CMS certificate binding",
    )
    require(len(sd["digest_algorithms"]) == 1, "digest roster")
    _sha256_algorithm(sd["digest_algorithms"][0])
    si = sd["signer_infos"][0]
    require(si["version"].native == "v1" and si["sid"].name == "issuer_and_serial_number", "signer identifier")
    require(si["unsigned_attrs"].native is None, "unsigned attributes")
    tsa = certificates[2]
    sid = si["sid"].chosen
    require(sid["issuer"] == tsa.issuer and sid["serial_number"].native == tsa.serial_number, "signer binding")
    _sha256_algorithm(si["digest_algorithm"])
    require(
        si["signature_algorithm"]["algorithm"].native == "rsassa_pkcs1v15"
        and isinstance(si["signature_algorithm"]["parameters"], (core.Null, core.Void)),
        "CMS RSA signature algorithm",
    )
    attrs = si["signed_attrs"]
    require(len(attrs) == len(SIGNED_ATTRIBUTES), "signed attribute roster")
    require({a["type"].dotted for a in attrs} == SIGNED_ATTRIBUTES, "signed attribute roster")
    require(all(len(a["values"]) == 1 for a in attrs), "signed attribute cardinality")
    by_oid = {a["type"].dotted: a["values"][0] for a in attrs}
    require(by_oid["1.2.840.113549.1.9.3"].native == "tst_info", "signed content type")
    eci = sd["encap_content_info"]
    require(eci["content_type"].native == "tst_info", "encapsulated content type")
    info_bytes = bytes(eci["content"])
    require(by_oid["1.2.840.113549.1.9.4"].native == hashlib.sha256(info_bytes).digest(), "signed content digest")
    ess = by_oid["1.2.840.113549.1.9.16.2.47"]
    require(len(ess["certs"]) == 1 and ess["policies"].native is None, "ESS roster")
    certid = ess["certs"][0]
    _sha256_algorithm(certid["hash_algorithm"])
    require(certid["cert_hash"].native == hashlib.sha256(material["tsa_certificate"]).digest(), "ESS certificate hash")
    issuer_serial = certid["issuer_serial"]
    require(issuer_serial.native is not None and len(issuer_serial["issuer"]) == 1, "ESS issuer roster")
    name = issuer_serial["issuer"][0]
    require(
        name.name == "directory_name"
        and name.chosen == tsa.issuer
        and issuer_serial["serial_number"].native == tsa.serial_number,
        "ESS issuer/serial binding",
    )
    info = _canonical_der(tsp.TSTInfo, info_bytes)
    require(info["version"].native == "v1" and info["extensions"].native is None, "TSTInfo shape")
    require(info["tsa"].name == "directory_name" and info["tsa"].chosen == tsa.subject, "TSTInfo TSA binding")
    _sha256_algorithm(info["message_imprint"]["hash_algorithm"])
    require(info["message_imprint"]["hashed_message"].native == imprint, "archive imprint mismatch")
    return sd, info


async def inspect_timestamp(wire: bytes) -> dict:
    """Authenticate a historical dossier under its supplied root, never admit it."""
    _check_client_versions()
    material, imprint = decode_manifest(wire)
    parsed_certs, certs, parsed_crls, crls = _parse(material)
    sd, info = _response(material, parsed_certs, imprint)
    generated, accuracy, lower, upper = _time_hull(info, SimpleNamespace(max_accuracy_microseconds=1_000_000))
    _validity(certs, crls, lower, upper)
    for endpoint in (lower, upper):
        instant = _EPOCH + timedelta(microseconds=endpoint)
        context = ValidationContext(
            trust_roots=[parsed_certs[0]],
            other_certs=parsed_certs[1:],
            crls=parsed_crls,
            ocsps=[],
            moment=instant,
            best_signature_time=instant,
            allow_fetching=False,
            revocation_mode="require",
            time_tolerance=timedelta(0),
            retroactive_revinfo=False,
        )
        kwargs = await validate_tst_signed_data(
            sd, context, lambda algorithm: imprint if algorithm == "sha256" else b""
        )
        status = TimestampSignatureStatus(**kwargs)
        require(status.intact and status.valid and status.trusted and not status.revoked, "CMS signature/path")
        require(
            status.validation_path is not None and status.validation_path.leaf.dump() == material["tsa_certificate"],
            "validated signer differs",
        )
    return {
        "schema": "etzio.archived-timestamp-inspection.v1",
        "status": "authenticated_historical_diagnostic_under_supplied_root",
        "manifest_sha256": sha(wire),
        "artifacts": {role: {"size": len(data), "sha256": sha(data)} for role, data in material.items()},
        "imprint_sha256": imprint.hex(),
        "generated_microseconds": generated,
        "claimed_accuracy_microseconds": accuracy,
        "issuance_interval_microseconds": [lower, upper],
        "policy_oid": info["policy"].native,
        "token_nonce_decimal": str(info["nonce"].native),
        "signed_attribute_oids": sorted(SIGNED_ATTRIBUTES),
        "certificate_subjects": [c.subject.rfc4514_string() for c in certs],
        "crl_intervals_microseconds": [[_micros(c.last_update_utc), _micros(c.next_update_utc)] for c in crls],
        "cms_signature_and_imprint_verified": True,
        "path_and_retained_crls_checked_at_both_endpoints": True,
        "root_admitted": False,
        "original_request_retained": False,
        "challenge_freshness_established": False,
        "current_revocation_established": False,
        "accuracy_independently_measured": False,
        "signer_attribute_certificate_trust_checked": False,
        "kernel_authority": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    print(json.dumps(asyncio.run(inspect_timestamp(load_manifest(args.manifest))), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
