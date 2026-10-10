"""Pinned local OpenSSL comparison of the finite historical timestamp diagnostic."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding  # noqa: E402

from scripts import inspect_archived_timestamp as inspector  # noqa: E402

OPENSSL_SHA256 = "07f19671b4a4528b829f8b7b917df7c42163a79a9646785e85e278c1fdae4478"
OPENSSL_VERSION = "OpenSSL 3.6.3 9 Jun 2026 (Library: OpenSSL 3.6.3 9 Jun 2026)"
PATH_CODES = ["0200008A", "02000072", "1C880004", "06880006", "17800064"]
SIGNATURE_CODES = ["0200008A", "02000072", "1C880004", "030000EA", "10800069", "1780006D"]
CASES = (
    ("lower_outward_second", [], None),
    ("upper_outward_second", [], None),
    ("response_signature_bit", SIGNATURE_CODES, "TS_RESP_verify_signature:signature failure:"),
    ("root_signature_bit", PATH_CODES, "Verify error:certificate signature failure"),
    ("root_crl_signature_bit", PATH_CODES, "Verify error:CRL signature failure"),
    ("issuer_crl_signature_bit", PATH_CODES, "Verify error:CRL signature failure"),
    ("wrong_imprint", ["17800067"], "ts_check_imprints:message imprint mismatch:"),
    ("missing_root_crl", ["17800064"], "Verify error:unable to get certificate CRL"),
    ("missing_issuer_crl", ["17800064"], "Verify error:unable to get certificate CRL"),
)


def check_outcome(result, codes, reason):
    inspector.require(len(result.stdout) <= 4096 and len(result.stderr) <= 16384, "OpenSSL output bound")
    expected = 1 if reason else 0
    inspector.require(result.returncode == expected, "unexpected OpenSSL exit")
    inspector.require(result.stdout == ("Verification: FAILED\n" if reason else "Verification: OK\n"), "OpenSSL result")
    inspector.require(result.stderr.startswith("Using configuration from /dev/null\n"), "OpenSSL configuration")
    actual = re.findall(r":error:([0-9A-Fa-f]{8}):", result.stderr)
    inspector.require(actual == codes, "unexpected OpenSSL error codes")
    if reason:
        inspector.require(reason in result.stderr.splitlines()[-1], "unexpected OpenSSL refusal reason")
    else:
        inspector.require(result.stderr == "Using configuration from /dev/null\n", "unexpected OpenSSL diagnostics")
    return actual


def compare(wire: bytes, executable: Path) -> dict:
    inspector.require(inspector.sha(executable.read_bytes()) == OPENSSL_SHA256, "OpenSSL executable digest")
    inspection = asyncio.run(inspector.inspect_timestamp(wire))
    material, imprint = inspector.decode_manifest(wire)
    lower, upper = inspection["issuance_interval_microseconds"]
    results = []
    with tempfile.TemporaryDirectory(prefix="etzio-archived-ts-") as directory:
        folder = Path(directory)
        (folder / "empty").mkdir()
        env = {
            "PATH": "/usr/bin:/bin",
            "OPENSSL_CONF": os.devnull,
            "SSL_CERT_DIR": str(folder / "empty"),
            "SSL_CERT_FILE": str(folder / "trust.pem"),
        }
        version = subprocess.run(
            [str(executable), "version"], env=env, capture_output=True, text=True, timeout=15, check=True
        )
        inspector.require(version.stdout.strip() == OPENSSL_VERSION and not version.stderr, "OpenSSL version")
        for name, codes, reason in CASES:
            data = material.copy()
            changed = {
                "response_signature_bit": "response",
                "root_signature_bit": "root_certificate",
                "root_crl_signature_bit": "root_crl",
                "issuer_crl_signature_bit": "issuer_crl",
            }.get(name)
            if changed:
                original = data[changed]
                data[changed] = original[:-1] + bytes([original[-1] ^ 1])
            trust = x509.load_der_x509_certificate(data["root_certificate"]).public_bytes(Encoding.PEM)
            for role in ("root_crl", "issuer_crl"):
                if name != "missing_" + role:
                    trust += x509.load_der_x509_crl(data[role]).public_bytes(Encoding.PEM)
            inputs = {
                "trust.pem": trust,
                "response.der": data["response"],
                "issuer.pem": x509.load_der_x509_certificate(data["issuer_certificate"]).public_bytes(Encoding.PEM),
            }
            for filename, value in inputs.items():
                (folder / filename).write_bytes(value)
            instant = (upper + 999999) // 1000000 if name == "upper_outward_second" else lower // 1000000
            command = [
                str(executable),
                "ts",
                "-verify",
                "-in",
                "response.der",
                "-digest",
                "00" * 32 if name == "wrong_imprint" else imprint.hex(),
                "-CAfile",
                "trust.pem",
                "-CApath",
                "empty",
                "-untrusted",
                "issuer.pem",
                "-crl_check_all",
                "-x509_strict",
                "-check_ss_sig",
                "-purpose",
                "timestampsign",
                "-auth_level",
                "2",
                "-attime",
                str(instant),
            ]
            result = subprocess.run(
                command, cwd=folder, env=env, capture_output=True, text=True, timeout=15, check=False
            )
            actual = check_outcome(result, codes, reason)
            results.append(
                {
                    "case": name,
                    "command": ["<pinned-openssl>", *command[1:]],
                    "input_sha256": {k: inspector.sha(v) for k, v in inputs.items()},
                    "returncode": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "error_codes": actual,
                    "expected_reason": reason,
                }
            )
    return {
        "schema": "etzio.archived-timestamp-comparison.v1",
        "manifest_sha256": inspector.sha(wire),
        "inspector_sha256": inspector.sha(Path(inspector.__file__).read_bytes()),
        "comparator_sha256": inspector.sha(Path(__file__).read_bytes()),
        "dependency_lock_sha256": inspector.sha((ROOT / "tools/ci/requirements-ci.lock").read_bytes()),
        "openssl_sha256": OPENSSL_SHA256,
        "openssl_version": OPENSSL_VERSION,
        "inspection": inspection,
        "results": results,
        "boundary": "Local comparison with shared cryptographic ancestry; not independent administration. "
        "OpenSSL uses outward integer seconds, pyHanko uses exact microsecond endpoints. "
        "Explicit CAfile and empty CApath; pinned ts.c does not load default roots or an omitted CAstore. "
        "No provider, clock, request freshness, current revocation or kernel authority admitted.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--openssl", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(compare(inspector.load_manifest(args.manifest), args.openssl.resolve()), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
