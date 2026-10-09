# Offline RSA timestamp-chain evidence

Status: repository-owned deterministic fixtures, `2026-10-09`.
[ADR-0021](../../docs/decisions/0021-offline-rsa-timestamp-chains.md) defines a separate
RSA-4096/SHA-384 root/intermediate/TSA profile. It authenticates an issuer's qualified
timestamp statement without establishing legal qualification, current UTC, independent
administration or kernel authority. No provider has been contacted for a timestamp.

## Retained comparison

`corpus.json` retains exact profile, request, response and two positional CRLs for `19`
cases. `openssl-comparison.json` binds these bytes, source identities, the OpenSSL `3.6.3`
executable and `38` raw endpoint commands. All `15` shared protocol outcomes agree.
Four deliberate policy differences remain: missing accuracy, missing qualified statement,
and excessive root-CRL or intermediate-CRL age. OpenSSL uses `-crl_check_all`; the revoked
intermediate and revoked TSA both refuse. The comparison does not establish provider
interoperability, independent administration or a qualified OS/library/device closure.

`fixture-keys.json` contains deliberately public RSA prime factors, solely to reconstruct
the local fixture PKI deterministically. They are never credentials or trust anchors for
external use. Both complete certificate chains and PKCS#1 v1.5 signatures reproduce across
cold processes. The optional `21`-package closure and its [SBOM](../native-time/sbom.cdx.json)
are unchanged from ADR-0020; its P-256 implementation and retained comparison are unchanged.

```bash
.venv/bin/python -m pytest -q tests/test_native_time_rsa_chain_v1.py
.venv/bin/python scripts/qualify_native_time_rsa.py \
  --openssl /absolute/path/to/openssl \
  --openssl-sha256 EXPECTED_EXECUTABLE_SHA256 \
  --output-dir /tmp/etzio-rsa-chain-comparison
```

The recorded local executable hash is
`07f19671b4a4528b829f8b7b917df7c42163a79a9646785e85e278c1fdae4478`.
Inspect the actual executable before supplying its digest. CI replays native cases and
checks retained source bindings; it does not replace this comparator with a moving system
OpenSSL. Diagnostic prefixes can vary on rerun; fixture and observation bytes do not.

## Documentary provider comparison

The [source ledger](provider-sources.json) retains version, inspected date, resolved URL,
SHA-256, size and section pointers for the exact retrieved documents. Full copyrighted
documents are not redistributed. A later download may differ; a recorded digest is a byte
identity, not proof of a publisher's signature or continued availability.

| Candidate | Documentary evidence | Decision and unresolved evidence |
|---|---|---|
| Sectigo qualified timestamping | [TSPPS 1.1.4, 2026-02-11](https://www.sectigo.com/uploads/files/eIDAS/Sectigo_eIDAS_TSPPS_v1.1.4.pdf): RSA-4096/SHA-384 hierarchy, one-second accuracy, nonce and qualified statement; OCSP described. | Selected as the first offline wire target. Actual response/certificate shape, complete-CRL availability, request-policy behavior, terms and operator custody remain unqualified. Generic Sectigo timestamp endpoints are separate services. |
| DigiCert public code-signing TSA | [Official service page](https://knowledge.digicert.com/general-information/rfc3161-compliant-time-stamp-authority-server): September 2026 rotation, RSA-4096 responder certificates and G4 intermediate/root chain. | Alternative. Exact token policy, accuracy, chain algorithms, revocation and permitted use require a separate profile. No inference of compatibility with this all-SHA-384 chain. |
| DigiCert Europe timestamping | [TSPPS 3.0, 2025-11-07](https://www.digicert.com/content/dam/digicert/pdfs/legal/digicerteurope-tspps.pdf): RSA or P-256, explicit request-field support, stated UTC accuracy and GNSS/NTP sources. Certificate-based access and charges may apply. | Alternative requiring explicit service terms and scope. Affiliated services are not presumed independently administered time sources. |

The [ETSI EN 319 422 V1.1.1 profile](https://www.etsi.org/deliver/etsi_en/319400_319499/319422/01.01.01_60/en_319422v010101p.pdf)
requires support for `reqPolicy`, nonce and `certReq`. Sectigo's request table describes
two of these as unused. This is an unresolved documentary discrepancy, not an observed
failure. Etzio retains strict policy and request binding. This codec pins the 2016 edition;
later draft work is not treated as adopted or as runtime authority.

RSA parameter handling follows [RFC 4055](https://www.rfc-editor.org/rfc/rfc4055.html)
and CMS digest conventions follow [RFC 5754](https://www.rfc-editor.org/rfc/rfc5754.html).
The extension container uses [RFC 3739](https://www.rfc-editor.org/rfc/rfc3739.html)
with the ETSI statement identifier. These are finite-profile inputs, not a general
PKIX/ETSI conformance claim.

## Next falsifying experiment

Correction, 2026-10-09: the service's RSA-4096 timestamp statement does not establish
4096-bit keys throughout its hierarchy. The publisher-listed R45 root has a 4096-bit
key, but its R35 intermediate has a 3072-bit key and is refused by this codec's algorithm
gate. Root AKI, CA key usage and intermediate EKU also differ from the closed profile.
The root-issued CRL route is now observed, but its noncritical `2.5.29.60` extension is
outside this codec's closed CRL profile; the TSA certificate and its issuer's CRL
remain missing. These read-only artifact observations do not establish the current
endpoint chain. The original table is documentary selection history, superseded on these
points by the [acquisition dossier](../../docs/QUALIFICATION_NEXT_STEPS.md) and its exact
public bytes. Preserve the released codec; do not relax it to claim compatibility.

Prepare a bounded acquisition dossier for one exact service: endpoint and method, request
count, permitted digest/nonce metadata, price and terms, credential requirements, trust
anchor provenance, full revocation route, rotation, resource containment, retained intent
before send and lost-response retry semantics. Then seek the scoped acquisition grant.
No such grant is inferred from a fixture test or a public endpoint.

Native integration also needs a complete time/revocation/anchor/catalog/monitor roster,
administrative and clock-dependency evidence, and cold lifecycle reconstruction. The
separate local-loss experiment must recover independently witnessed H1 after deletion of
local state or explicitly block, including when coherent older H0 bytes are restored.
Neither experiment is performed or claimed here. Their concrete controls remain in
ADR-0021 and [ADR-0020](../../docs/decisions/0020-offline-native-time-qualification.md).

The subsequent [published-material inspection](../../docs/PUBLISHED_TSA_MATERIAL.md)
retains signer #3 and the intermediate-issued CRL through the provider's public discovery
route. The signer's `contentCommitment` usage adds another profile mismatch. This is
historical public material and a local path comparison, not the endpoint's current CMS or
an admitted provider. The released codec and corpus remain unchanged.
