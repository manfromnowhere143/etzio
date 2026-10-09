# Offline native-time qualification evidence

Status: repository-owned RFC 3161/5816 fixtures only, `2026-10-09`.
[ADR-0020](../../docs/decisions/0020-offline-native-time-qualification.md) defines the
bounded offline profile. No external provider, real UTC, current revocation, lifecycle
admission, or independently administered authority is established.

- `corpus.json` retains the exact profile, scoped request and `14` native response/CRL
  cases, including SHA-256, sizes and complete Base64 bytes.
- `openssl-comparison.json` retains the corpus digest, local OpenSSL `3.6.3` executable
  digest/version, validator/fixture/runner/lock digests, `28` explicit endpoint commands,
  raw outputs and expected outcomes.
  All `11` shared protocol cases agree. The other `3` are deliberate policy differences:
  Etzio requires explicit bounded accuracy and bounds CRL age over the full hull.
- `sbom.cdx.json` inventories the `21` packages in the optional qualification closure,
  the dependency graph, distribution-declared licenses and CI lock digest in CycloneDX
  `1.6` format. It was validated against that version's official JSON schema. It is a
  package inventory, not installed-binary provenance or a vulnerability-free claim.

The comparison uses one positive plus negative fixtures, not a representative external
TSA population. pyHanko and the OpenSSL command are different protocol/path implementations
but share cryptographic ancestry. The recorded executable digest does not qualify its
shared-library, OS or device closure. Raw OpenSSL diagnostic prefixes can vary on rerun;
request, response, CRL and native observation bytes remain deterministic.

Run the native tests through the ordinary hash-locked CI environment:

```bash
.venv/bin/python -m pytest -q tests/test_native_time_qualification_v1.py
```

To repeat the separate OpenSSL experiment, inspect and select a local `3.6.3` binary and
supply its expected executable digest explicitly. The recorded executable was
`07f19671b4a4528b829f8b7b917df7c42163a79a9646785e85e278c1fdae4478` on this macOS host;
a different build needs its own reviewed comparison record, not that digest copied onto it.

```bash
.venv/bin/python scripts/qualify_native_time.py \
  --openssl /absolute/path/to/openssl \
  --openssl-sha256 EXPECTED_EXECUTABLE_SHA256 \
  --output-dir /tmp/etzio-native-time-comparison
.venv/bin/python scripts/native_time_sbom.py
```

The first command only operates on generated local fixture files. It has no acquisition
client or external endpoint. The SBOM command regenerates the repository inventory from
installed package metadata for the CPython `3.11.15`/`3.14.2`, macOS/Linux marker union.
Tests bind the corpus to the generator and comparison digest, and bind the SBOM, optional
extra, runtime profile and dependency lock to one version set. CI reruns native outcomes;
it does not silently substitute its moving system OpenSSL for the separate pinned oracle.
