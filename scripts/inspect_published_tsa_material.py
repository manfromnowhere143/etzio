"""Replay a bounded public-material diagnostic; never provider or time authority.

No network, CMS token verification, PKIX policy engine or native-provider enrollment.
An optional explicitly pinned OpenSSL experiment performs separate path checks.
See docs/PUBLISHED_TSA_MATERIAL.md for the exact claims and non-claims.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from asn1crypto import core  # noqa: E402
from asn1crypto import crl as asn1_crl  # noqa: E402
from asn1crypto import x509 as asn1_x509  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

from etzio.protocol import strict_loads  # noqa: E402
from etzio.qualification.rfc3161_v1 import _canonical_der, _check_client_versions  # noqa: E402

SCHEMA = "etzio.published-tsa-material.v1"
ROLES = ("root_certificate", "intermediate_certificate", "tsa_certificate", "root_issued_crl", "issuer_issued_crl")
MAX_MANIFEST_BYTES = 65536
MAX_ARTIFACT_BYTES = 16384
EXPECTED_OPENSSL = "OpenSSL 3.6.3 9 Jun 2026 (Library: OpenSSL 3.6.3 9 Jun 2026)"
EXPIRED_CERTS_OID = x509.ObjectIdentifier("2.5.29.60")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def decode_manifest(wire: bytes) -> tuple[dict[str, bytes], int]:
    require(type(wire) is bytes and 0 < len(wire) <= MAX_MANIFEST_BYTES, "bounded manifest bytes required")
    body = strict_loads(wire)
    require(type(body) is dict and set(body) == {"schema", "reference_second", "artifacts"}, "manifest shape")
    require(body["schema"] == SCHEMA, "manifest schema")
    second = body["reference_second"]
    require(type(second) is int and 0 <= second <= 253402300799, "diagnostic reference second")
    entries = body["artifacts"]
    require(type(entries) is list and len(entries) == len(ROLES), "five positional artifact roles required")
    material = {}
    for role, entry in zip(ROLES, entries, strict=True):
        require(type(entry) is dict and set(entry) == {"role", "size", "sha256", "der_base64"}, "artifact shape")
        require(entry["role"] == role, "artifact role or order")
        size = entry["size"]
        require(type(size) is int and 0 < size <= MAX_ARTIFACT_BYTES, "bounded artifact size")
        encoded = entry["der_base64"]
        require(type(encoded) is str and len(encoded) == 4 * ((size + 2) // 3), "bounded base64 length")
        data = base64.b64decode(encoded, validate=True)
        require(base64.b64encode(data).decode("ascii") == encoded, "canonical base64")
        require(len(data) == size and sha(data) == entry["sha256"], "artifact size or digest differs")
        material[role] = data
    require(len(set(material.values())) == len(ROLES), "artifact bytes reused across roles")
    return material, second


def load_manifest(path: Path) -> bytes:
    with path.open("rb") as source:
        wire = source.read(MAX_MANIFEST_BYTES + 1)
    # Decode before returning so a caller cannot forward an unchecked file.
    decode_manifest(wire)
    return wire


def _parse(material):
    certs = []
    for role in ROLES[:3]:
        _canonical_der(asn1_x509.Certificate, material[role])
        cert = x509.load_der_x509_certificate(material[role])
        require(isinstance(cert.public_key(), rsa.RSAPublicKey), "RSA material diagnostic only")
        require(cert.public_key().key_size in {3072, 4096}, "unsupported RSA size")
        certs.append(cert)
    crls = []
    for role in ROLES[3:]:
        _canonical_der(asn1_crl.CertificateList, material[role])
        crls.append(x509.load_der_x509_crl(material[role]))
    return certs, crls


def inspect_material(wire: bytes) -> dict:
    """Authenticate the named signatures and report fields; not PKIX acceptance."""
    _check_client_versions()
    material, second = decode_manifest(wire)
    certs, crls = _parse(material)
    root, issuer, tsa = certs
    reference = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(seconds=second)
    certificate_reports = []
    for role, cert, parent in zip(ROLES[:3], certs, (root, root, issuer), strict=True):
        cert.verify_directly_issued_by(parent)
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        certificate_reports.append(
            {
                "role": role,
                "sha256": sha(material[role]),
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "key_bits": cert.public_key().key_size,
                "signature_oid": cert.signature_algorithm_oid.dotted_string,
                "signature_under_named_parent": "verified",
                "not_before": cert.not_valid_before_utc.isoformat(),
                "not_after": cert.not_valid_after_utc.isoformat(),
                "covers_reference": cert.not_valid_before_utc <= reference <= cert.not_valid_after_utc,
                "digital_signature": ku.digital_signature,
                "content_commitment": ku.content_commitment,
                "extensions": [{"oid": e.oid.dotted_string, "critical": e.critical} for e in cert.extensions],
            }
        )
    crl_reports = []
    for role, crl, parent, child in zip(ROLES[3:], crls, (root, issuer), (issuer, tsa), strict=True):
        require(crl.issuer == parent.subject and crl.is_signature_valid(parent.public_key()), "CRL issuer/signature")
        expired = None
        for extension in crl.extensions:
            if extension.oid == EXPIRED_CERTS_OID:
                require(not extension.critical, "unsupported critical expiredCertsOnCRL")
                expired = _canonical_der(core.GeneralizedTime, extension.value.value).native.isoformat()
        crl_reports.append(
            {
                "role": role,
                "sha256": sha(material[role]),
                "issuer": crl.issuer.rfc4514_string(),
                "signature_under_named_parent": "verified",
                "this_update": crl.last_update_utc.isoformat(),
                "next_update": crl.next_update_utc.isoformat() if crl.next_update_utc else None,
                "covers_reference_half_open": bool(
                    crl.next_update_utc and crl.last_update_utc <= reference < crl.next_update_utc
                ),
                "entry_count": len(crl),
                "subject_serial_listed": crl.get_revoked_certificate_by_serial_number(child.serial_number) is not None,
                "expired_certs_on_crl": expired,
                "extensions": [{"oid": e.oid.dotted_string, "critical": e.critical} for e in crl.extensions],
            }
        )
    return {
        "schema": "etzio.published-tsa-material.inspection.v1",
        "manifest_sha256": sha(wire),
        "reference_second": second,
        "reference_authority": "caller-selected diagnostic instant; not trusted UTC",
        "root_admitted": False,
        "current_service_signer_observed": False,
        "timestamp_token_verified": False,
        "kernel_authority": False,
        "boundary": "Named signatures and field observations only; no PKIX, CRL scope/freshness or legal acceptance.",
        "certificates": certificate_reports,
        "crls": crl_reports,
    }


def check_openssl_result(result, expected_error: tuple[int, int] | None) -> None:
    errors = [
        (int(code), int(depth))
        for code, depth in re.findall(r"^error ([0-9]+) at ([0-9]+) depth lookup:", result.stderr, re.MULTILINE)
    ]
    if expected_error is None:
        require(
            result.returncode == 0 and result.stdout == "tsa.pem: OK\n" and result.stderr == "",
            "unexpected OpenSSL positive result",
        )
    else:
        require(
            result.returncode == 2 and result.stdout == "" and errors == [expected_error],
            "OpenSSL refusal differs from expected verification error",
        )


def openssl_comparison(wire: bytes, executable: Path, expected_sha256: str) -> dict:
    # Establish the unmodified diagnostic first; mutated cases are created below.
    original = inspect_material(wire)
    material, second = decode_manifest(wire)
    executable = executable.resolve(strict=True)
    require(sha(executable.read_bytes()) == expected_sha256, "OpenSSL executable digest differs")
    results = []
    cases = [("published", None, second, None)]
    cases += [
        ("signature_bit_" + role, role, second, error)
        for role, error in zip(ROLES, ((7, 2), (7, 1), (7, 0), (8, 1), (8, 0)), strict=True)
    ]
    _, crls = _parse(material)
    cases += [
        ("missing_issuer_crl", "omit_crl", second, (3, 0)),
        ("before_root_crl", None, int(crls[0].last_update_utc.timestamp()) - 1, (11, 1)),
        ("at_issuer_crl_expiry", None, int(crls[1].next_update_utc.timestamp()), (12, 0)),
    ]
    with tempfile.TemporaryDirectory(prefix="etzio-public-material-") as directory:
        working = Path(directory)
        env = {"PATH": "/usr/bin:/bin", "OPENSSL_CONF": os.devnull}
        version = subprocess.run(
            [str(executable), "version"], cwd=working, env=env, check=True, capture_output=True, text=True, timeout=10
        ).stdout.strip()
        require(version == EXPECTED_OPENSSL, "OpenSSL version differs")
        for name, mutation, reference, expected in cases:
            variant = dict(material)
            if mutation in ROLES:
                data = variant[mutation]
                variant[mutation] = data[:-1] + bytes([data[-1] ^ 1])
            certs, variant_crls = _parse(variant)
            for filename, cert in zip(("root.pem", "issuer.pem", "tsa.pem"), certs, strict=True):
                (working / filename).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            if mutation == "omit_crl":
                variant_crls = variant_crls[:1]
            (working / "crls.pem").write_bytes(
                b"".join(c.public_bytes(serialization.Encoding.PEM) for c in variant_crls)
            )
            command = [
                "verify",
                "-CAfile",
                "root.pem",
                "-no-CApath",
                "-no-CAstore",
                "-untrusted",
                "issuer.pem",
                "-CRLfile",
                "crls.pem",
                "-crl_check_all",
                "-x509_strict",
                "-check_ss_sig",
                "-purpose",
                "timestampsign",
                "-auth_level",
                "2",
                "-attime",
                str(reference),
                "tsa.pem",
            ]
            result = subprocess.run(
                [str(executable), *command], cwd=working, env=env, capture_output=True, text=True, timeout=10
            )
            check_openssl_result(result, expected)
            results.append(
                {
                    "case": name,
                    "input_sha256": {
                        role: sha(variant[role]) for role in ROLES if not (mutation == "omit_crl" and role == ROLES[-1])
                    },
                    "expected_path_result": expected is None,
                    "expected_verify_error_and_depth": list(expected) if expected is not None else None,
                    "command": ["<pinned-openssl>", *command],
                    "returncode": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                }
            )
    return {
        "schema": "etzio.published-tsa-material.openssl-comparison.v1",
        "manifest_sha256": sha(wire),
        "inspector_sha256": sha(Path(__file__).read_bytes()),
        "dependency_lock_sha256": sha((ROOT / "tools/ci/requirements-ci.lock").read_bytes()),
        "openssl_version": version,
        "openssl_executable_sha256": expected_sha256,
        "boundary": (
            "Local path/purpose/CRL comparison under a downloaded root; "
            "not independently administered trust or full binary provenance."
        ),
        "inspection": original,
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--openssl", type=Path)
    parser.add_argument("--openssl-sha256")
    args = parser.parse_args()
    if bool(args.openssl) != bool(args.openssl_sha256):
        parser.error("OpenSSL path and digest must be supplied together")
    wire = load_manifest(args.manifest)
    report = openssl_comparison(wire, args.openssl, args.openssl_sha256) if args.openssl else inspect_material(wire)
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
