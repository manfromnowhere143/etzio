"""Retain an offline native corpus and explicit OpenSSL comparison; no acquisition.

Run with an explicitly selected local OpenSSL 3.6.3 binary and its expected digest.
This is a qualification experiment, not the kernel's verifier or a CI skip path.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from native_time_fixtures import context, fixture, oracle_cases  # noqa: E402

from etzio.qualification.rfc3161_v1 import (  # noqa: E402
    NativeTimeError,
    build_rfc3161_request_v1,
    validate_rfc3161_offline_v1,
)

EXPECTED_VERSION = "OpenSSL 3.6.3 9 Jun 2026 (Library: OpenSSL 3.6.3 9 Jun 2026)"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def artifact(data: bytes) -> dict:
    return {"sha256": sha(data), "size": len(data), "base64": base64.b64encode(data).decode("ascii")}


def corpus() -> dict:
    f = fixture()
    return {
        "schema": "etzio.rfc3161.offline-corpus.v1",
        "boundary": "repository-owned deterministic bytes only; no external authority",
        "profile": f.profile.to_body(),
        "context": context().to_body(),
        "request": artifact(build_rfc3161_request_v1(profile=f.profile, request=context())),
        "cases": [
            {
                "case_id": case.case_id,
                "response": artifact(case.response_der),
                "crl": artifact(case.crl_der),
                "native_expected": case.native_result,
                "openssl_expected_all_endpoints": case.openssl_accepts,
                "comparison": case.comparison,
            }
            for case in oracle_cases()
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openssl", type=Path, required=True)
    parser.add_argument("--openssl-sha256", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    executable = args.openssl.resolve(strict=True)
    if sha(executable.read_bytes()) != args.openssl_sha256:
        raise SystemExit("OpenSSL executable differs from expected digest")
    f = fixture()
    retained_corpus = corpus()
    corpus_bytes = (json.dumps(retained_corpus, indent=2, sort_keys=True) + "\n").encode()
    results = []
    with tempfile.TemporaryDirectory(prefix="etzio-native-time-oracle-") as temporary:
        working = Path(temporary)
        (working / "empty-ca").mkdir()
        env = {
            "PATH": "/usr/bin:/bin",
            "OPENSSL_CONF": os.devnull,
            "SSL_CERT_DIR": str(working / "empty-ca"),
            "SSL_CERT_FILE": str(working / "trust.pem"),
        }
        actual_version = subprocess.run(
            [str(executable), "version"], cwd=working, env=env, check=True, capture_output=True, text=True, timeout=10
        ).stdout.strip()
        if actual_version != EXPECTED_VERSION:
            raise SystemExit("OpenSSL version differs from qualification profile: " + actual_version)
        request = build_rfc3161_request_v1(profile=f.profile, request=context())
        (working / "request.tsq").write_bytes(request)
        for case in oracle_cases():
            try:
                observation = asyncio.run(
                    validate_rfc3161_offline_v1(
                        profile=f.profile, request=context(), response_der=case.response_der, crl_der=case.crl_der
                    )
                )
                outcome = "accepted"
                observation_id = observation.observation_id
            except NativeTimeError as exc:
                outcome, observation_id = exc.reason_code, None
            if outcome != case.native_result:
                raise SystemExit(f"{case.case_id}: unexpected native result {outcome}")
            (working / "response.tsr").write_bytes(case.response_der)
            # OpenSSL's CAfile can contain the exact issuer CRL as well as the root.
            trust = f.root.public_bytes(serialization.Encoding.PEM)
            trust += x509.load_der_x509_crl(case.crl_der).public_bytes(serialization.Encoding.PEM)
            (working / "trust.pem").write_bytes(trust)
            endpoint_results = []
            for endpoint in (1791547199, 1791547201):
                command = [
                    "ts",
                    "-verify",
                    "-in",
                    "response.tsr",
                    "-queryfile",
                    "request.tsq",
                    "-CAfile",
                    "trust.pem",
                    "-CApath",
                    "empty-ca",
                    "-crl_check",
                    "-x509_strict",
                    "-attime",
                    str(endpoint),
                ]
                run = subprocess.run(
                    [str(executable), *command], cwd=working, env=env, capture_output=True, text=True, timeout=10
                )
                endpoint_results.append(
                    {
                        "command": ["<pinned-openssl>", *command],
                        "returncode": run.returncode,
                        "stdout": run.stdout,
                        "stderr": run.stderr,
                    }
                )
            accepted = all(value["returncode"] == 0 for value in endpoint_results)
            if accepted != case.openssl_accepts:
                raise SystemExit(f"{case.case_id}: unexpected OpenSSL result {endpoint_results}")
            results.append(
                {
                    "case_id": case.case_id,
                    "native_result": outcome,
                    "observation_id": observation_id,
                    "openssl": endpoint_results,
                    "comparison": case.comparison,
                }
            )
    report = {
        "schema": "etzio.rfc3161.openssl-comparison.v1",
        "date": "2026-10-09",
        "corpus_sha256": sha(corpus_bytes),
        "python": platform.python_implementation() + " " + platform.python_version(),
        "source_sha256": {
            relative: sha((ROOT / relative).read_bytes())
            for relative in (
                "etzio/qualification/rfc3161_v1.py",
                "tests/native_time_fixtures.py",
                "scripts/qualify_native_time.py",
                "tools/ci/requirements-ci.lock",
            )
        },
        "openssl_version": actual_version,
        "openssl_executable_sha256": args.openssl_sha256,
        "case_count": len(results),
        "boundary": "local protocol/path comparison; not a qualified binary closure or independent administration",
        "results": results,
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "corpus.json").write_bytes(corpus_bytes)
    (args.output_dir / "openssl-comparison.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"{len(results)} native/OpenSSL cases matched explicit expectations; retained in {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
