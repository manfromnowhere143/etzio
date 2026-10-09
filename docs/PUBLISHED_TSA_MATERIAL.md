# Published TSA material inspection

Status: offline research diagnostic, 2026-10-09. No provider, trust root, time source,
storage profile or execution profile is admitted.

## Contract before implementation

This tranche closes a material-discovery gap: the provider's policy links a public
signer-certificate search, and the downloaded signer identifies its issuer's CRL.
Retain those bytes, authenticate the named certificate/CRL signatures, and reproduce
an explicitly configured OpenSSL path check. Do not turn these observations into
kernel time evidence or relax the released RFC 3161 codecs.

The inspector consumes exactly five positional artifacts: root, intermediate, signer,
root-issued CRL and intermediate-issued CRL. Its unsigned manifest binds each artifact's
size and SHA-256. It reads at most 64 KiB of manifest, requires each artifact to be at
most 16 KiB, refuses duplicate JSON keys, extra fields, noncanonical Base64 and
noncanonical DER, and uses the locked native-parser dependency environment. The manifest
is research input, not a signed grant or externally authenticated root selection.

Only named certificate signatures, named CRL signatures and reported fields are checked
by the Python inspector. It reports certificate validity at one caller-selected second,
half-open CRL interval membership, serial membership and exact extension identities.
It is not a PKIX policy engine, does not interpret complete CRL scope, and does not
establish current revocation or freshness. Both a listed serial and an out-of-interval
reference remain visible in its diagnostic output; completing inspection is not
acceptance. No network or implicit AIA/CRL retrieval is implemented.

The optional OpenSSL experiment requires the explicit executable path, SHA-256 and
version `3.6.3`. It uses an empty ambient configuration, the exact downloaded root,
explicit intermediate and CRLs, no default CA path/store, strict X.509 checking,
root self-signature checking, timestamp purpose, security level 2 and an explicit time.
Each subprocess has a ten-second timeout. The pinned executable still depends on its
local libraries and host; cryptography and command-line OpenSSL also share upstream
cryptographic ancestry; this is a local implementation comparison, not independently
administered verification or a qualified binary closure.

Known-bads must include mutation of every certificate/CRL signature even after the
manifest digest is recomputed, missing or swapped roles, size/digest changes, malformed
encoding and time-boundary observations. The OpenSSL comparison additionally removes
the signer CRL, moves the reference before the root CRL and to the issuer CRL's expiry.
Each negative requires exit code 2 and its exact verification error and path depth;
a tool crash, argument error or different refusal cannot satisfy it. Unexpected comparison
results must stop report generation. Test and report provenance
must bind the exact inspector and retained manifest.

## Observed material

[Sectigo TSPPS 1.1.4, section 7.6.4](https://www.sectigo.com/uploads/files/eIDAS/Sectigo_eIDAS_TSPPS_v1.1.4.pdf)
links the [public signer search](https://crt.sh/?q=Sectigo+Qualified+Time+Stamping+Signer).
The retained search returned three entries, with issuance dates in 2020, 2022 and 2023.
The newest returned entry is [signer #3, certificate 9297382517](https://crt.sh/?id=9297382517),
valid from 2023-05-03 through 2034-08-02. Search results do not prove completeness,
current key use, continued private-key availability or service rotation behavior.

The signer has RSA-4096, an RSA/SHA-384 issuer signature, critical sole timestamp EKU
and both `digitalSignature` and `contentCommitment` key usage. The latter is another
mismatch with the released finite Etzio profile, and is allowed by OpenSSL's
[timestamp-purpose rules](https://docs.openssl.org/3.6/man1/openssl-verification-options/).
It is not a provider vulnerability.

Its explicit distribution point supplied the [intermediate-issued CRL](http://crl.sectigo.com/SectigoQualifiedTimeStampingCAR35.crl):
629 bytes, SHA-256 `7c04719903e20a9a96c967b49450379b587fa8e6728400e81394e8b5fd061ff5`,
issuer-declared interval 2026-10-09 05:42:11Z through 2026-10-16 05:42:11Z, zero listed
serials. The HTTP transport is not authenticated; its signature is checked under the
already retained intermediate. This does not independently admit that intermediate.

Both CRLs carry noncritical `2.5.29.60`, `expiredCertsOnCRL`, with encoded value
2020-10-05 00:00:00Z. [ITU-T X.509 (10/2019), certificate extensions](https://www.itu.int/ITU-T/formal-language/itu-t/x/x509/2019/CertificateExtensions.html)
defines its GeneralizedTime syntax. [ETSI TS 119 612 V2.3.1, section 5.5.9.1](https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.03.01_60/ts_119612v020301p.pdf)
explains its relationship to expired-certificate revocation information. It does not
extend the CRL's `nextUpdate` or establish current status. The inspector reports its
value; no runtime codec support or historical-revocation guarantee is added.

The diagnostic reference `1791555586` is the root CRL's declared `thisUpdate`, chosen to
lie within both retained CRL intervals. It is not a measurement of UTC, acquisition
latency or commit time. An actual timestamp token and its request have not been acquired.

## Reproduction and retained evidence

The [manifest](evidence/published-tsa-material-2026-10-09.json) contains all five exact
public DER artifacts. The [source record](evidence/published-tsa-sources-2026-10-09.json)
binds the search response and discovery routes. The
[comparison](evidence/published-tsa-comparison-2026-10-09.json) records the unmodified
path and its eight refusal controls. No private keys or target data are included.

```bash
.venv/bin/python scripts/inspect_published_tsa_material.py \
  docs/evidence/published-tsa-material-2026-10-09.json

.venv/bin/python scripts/inspect_published_tsa_material.py \
  docs/evidence/published-tsa-material-2026-10-09.json \
  --openssl /absolute/path/to/openssl \
  --openssl-sha256 07f19671b4a4528b829f8b7b917df7c42163a79a9646785e85e278c1fdae4478
```

Use the exact executable digest recorded in the comparison for reproduction; a path or
version string alone is insufficient. The script prints a report and never writes to a
provider or the kernel. CI replays the Python diagnostic and adversarial tests; the
explicit local OpenSSL experiment is separately retained and must not be represented
as a Linux CI path-validation result.

## Next dependency

The published historical chain and both CRLs are now available for profile design.
The current endpoint's actual signer, CMS encoding, complete request binding and rotation
remain unobserved. Complete applicable terms and an exact contained acquisition contract,
then collect at most its permitted request count. Where discovery is needed, keep the
untrusted discovery token separate from a later exact-profile qualification request.
Current-service material, independent root administration, qualified time propagation,
full-roster native lifecycle reconstruction and latest-head recovery still require proof.
