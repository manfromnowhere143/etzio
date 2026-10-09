# ADR-0021: Offline RSA timestamp chains and provider selection evidence

- Status: accepted for repository-owned offline qualification only
- Date: 2026-10-09
- Owner: Daniel Wahnich

## Decision and boundary

Extend native-format qualification with a separate finite RSA/SHA-384 profile over a
pinned root, one intermediate CA and one TSA certificate. Preserve ADR-0020's P-256
profile, wire identities, corpus and dependency closure. The new surface is an offline
observation validator, not provider enrollment or a source of kernel time authority.

The first documented wire target is Sectigo's qualified timestamp service, TSPPS `1.1.4`
dated 2026-02-11. Its published format motivates RSA/SHA-384, an intermediate certificate,
nonce binding, a one-second accuracy field and a qualified-timestamp statement. This does
not select an admitted operator. Actual service bytes, full certificate profiles, terms,
administration and operation have not been qualified. In particular, its published
revocation route mentions OCSP; this tranche proves retained complete-CRL processing,
not the availability or suitability of a real provider's CRLs.

The service document's request table labels `reqPolicy` and `certReq` unused, while
ETSI EN 319 422 V1.1.1 clauses 5.1.1–5.1.2 require support. Retain this discrepancy for
an admitted interoperability experiment; do not infer that the service ignores the fields
or relax checks. Requests retain an explicit exact policy, nonce and `certReq=true`.

Public source identities and service comparisons are retained separately from fixture
evidence. Provider policy claims are not independently observed operation. Reading a public
document does not grant service use or establish legal qualification. No timestamp request
is sent, no external certificate is admitted, and no live-target or bounty authority changes.

## Closed cryptographic and path profile

Post-release observation, 2026-10-09: publisher-listed root/intermediate bytes and one
root-issued CRL are now retained in the [acquisition dossier](../QUALIFICATION_NEXT_STEPS.md).
The intermediate is RSA-3072 and the certificate extension profiles also differ. This
falsifies documentary inference of compatibility with the finite profile below; it changes
neither the accepted codec nor the release evidence. The current TSA chain and full
revocation route remain unobserved. Any compatible profile requires a separate decision.

The codec `etzio.rfc3161.rsa-chain.offline.v1` pins the same `21`-distribution optional
closure as ADR-0020. Profile identity binds the codec, closure, source, exact timestamp
policy, TSA certificate policy, all three complete DER certificates and accuracy/CRL-age
ceilings. Exact types and a reconstructed immutable snapshot are required at each public
request/validation boundary; installed dependency versions are checked there.

Keys are RSA `4096` bits with exponent `65537`, using `rsaEncryption` SPKI with NULL
parameters. Certificates and CRLs use SHA-384 with PKCS#1 v1.5. CMS uses a SHA-384 digest
and either its combined RSA identifier or `rsaEncryption`. NULL and absent RSA signature
parameters are equivalent under RFC 4055; other parameters, PSS, OAEP and weaker or foreign
algorithms refuse. Inner/outer certificate and CRL identifiers must also be byte-identical.
SHA-256 remains the request imprint and ESSCertIDv2 certificate hash.

The root is self-issued and authenticates its own signature. It directly issues the exact
intermediate, which directly issues the exact TSA. Keys and subjects are distinct across
all roles. Subject separation uses the pinned ASN.1 library's RFC 5280 name comparison,
including equivalent string encodings, case and space normalization; different DER alone
does not establish different subjects. Root path length is absent or at least one;
intermediate path length is absent or zero; the TSA is not a CA. Basic constraints and key usage are critical. CA key usage
permits certificate and CRL signing only; TSA key usage permits digital signatures only.
SKI is recomputed from each key and AKI binds the expected issuer. The TSA has a critical,
sole timestamping EKU and the exact configured certificate policy. Supported optional
noncritical AIA, distribution-point and policy metadata never cause network access.
Unknown extensions and unsupported metadata shapes refuse.

CMS embeds exactly the pinned TSA and intermediate certificates, never the root or an
alternate chain. One signer and one digest are required. Signer identity and the SHA-256
ESSCertIDv2 bind the exact TSA. Signed attributes are exactly content type, message digest
and SigningCertificateV2, each single-valued. Embedded CRLs, unsigned attributes, duplicate
certificates/signers, extra ESS references, trailing bytes and noncanonical DER refuse.

The existing library-backed ASN.1 byte/depth/node/cardinality guards are reused, without
editing ADR-0020's implementation. Request context and profile identity use a separate
domain before SHA-256 hashing, so different profiles cannot reuse one another's response.

## Timestamp claim and intervals

TSTInfo requires exactly one noncritical `qcStatements` extension (RFC 3739 OID
`1.3.6.1.5.5.7.1.3`). Its DER value contains exactly one statement, OID
`0.4.0.19422.1.1`, with no statement information, as defined in ETSI EN 319 422 V1.1.1
clause 9.1 and Annex B. Missing, duplicated, critical, foreign or ambiguous statements
refuse. Authenticating this extension authenticates an issuer's claim; it does not verify
eIDAS status, a Trusted List entry, an audit or independent administration.

Keep the complete ADR-0020 integer-microsecond uncertainty calculation and outward
second projection. No certificate or revocation decision uses only the center time.
All three certificates must cover the complete closed interval `[lower, upper]`.
No ordering flag narrows uncertainty. The request's complete scope, source, purpose,
policy, imprint and nonce remain bound; deterministic fixture nonces are not freshness.

Two positional retained complete CRLs are mandatory: the root-issued CRL covers the
intermediate, and the intermediate-issued CRL covers the TSA. Each authenticates under its
expected issuer and exact AKI, has a bounded CRL number and unique bounded serial entries,
and satisfies `thisUpdate <= lower <= upper < nextUpdate`. Age is bounded at `upper`.
Missing, swapped, forged, stale or future CRLs refuse. A listed subject serial refuses
regardless of its recorded revocation date. Neither a valid leaf CRL nor a good TSA
signature can hide intermediate revocation. Delta, indirect and scoped CRLs remain outside
this profile; OCSP needs a separate profile and controls.

Fresh pyHanko validation contexts at both exact microsecond endpoints use only the pinned
root, retained intermediate and two CRLs, explicit moments, zero time tolerance, required
revocation, fetching disabled and no OCSP. CMS integrity, signature validity and path trust
must all succeed. Invalid inputs produce a typed refusal; operational failures and
cancellation retain their own domains.

## Retention, bounds and known-bads

The immutable observation retains exact profile, context, query, response and both CRLs,
plus the complete interval. Its content identity covers every artifact digest/size and
result. It is public-constructible evidence, not a sealed kernel authority value. Same-input
retry and cold reconstruction are byte-stable and require no acquisition.

Retain ADR-0020 limits: response `64 KiB`, each certificate `16 KiB`, each CRL `256 KiB`
with at most `1024` entries, ASN.1 depth `32`, nodes `32768` per parsed object and collection
size `1024`. Exactly two CRLs and three pinned certificates bound aggregate inputs. This
is not a hostile-input process sandbox or a worst-case CPU proof. External bytes still
require an admitted execution/resource profile.

Known-bads cover each path role, key reuse, wrong issuer, root/path substitution, path
length, CA/non-CA confusion, EKU/key usage, full-interval validity, both revocation roles,
missing/swapped/forked CRLs, CRL metadata and age, CMS/ESS ambiguity, nonce/policy/context
replay, qualified-statement shape, bounds, immutable snapshot mutation, dependency drift,
network and ambient-clock use. Preserve positive controls and distinct expected reasons.

An independent OpenSSL `3.6.3` comparison retains exact fixture bytes, executable/source
hashes, explicit endpoint times and raw command results. It enables whole-chain revocation
checking. Record deliberate differences for Etzio-specific accuracy, CRL age, exact pins
and statement shape; do not count those as OpenSSL defects. The implementations share
OpenSSL cryptographic ancestry and do not establish independent administration.

## Remaining concrete provider and recovery work

Before native acquisition, retain exact service/endpoint, permitted request and metadata
disclosure, terms and cost, trust-anchor provenance, certificate/algorithm rotation,
complete revocation route, challenge generation, latency bounds, request-before-send
retention, lost-response/retry semantics and a contained parser/resource profile. Resolve
the request-field discrepancy and actual CMS/certificate shape using a separately admitted
bounded experiment. A document or fixture result cannot substitute for that evidence.

The complete time/revocation/anchor/catalog/monitor roster must establish separately
administered custody, infrastructure/clock dependencies, compromise handling and retention.
Two services under one parent are not independent merely because their names differ.
Native dossiers must reconstruct within the existing lifecycle before accepted outputs can
be consumed; no state-machine or authority shortcut is added here.

The local-loss experiment remains the ADR-0020 contract: preserve independently held
bootstrap identity, publish H0 then H1, remove local DB/cache/staging in a disposable
accepted environment, and require H1 recovery or an explicit block. Test coherent H0
replacement, root replacement, stale/revoked time evidence, split views, withheld witnesses,
outage and key rotation. A valid old signature cannot establish the latest head. This
tranche does not perform or claim that external experiment.

## Sources

The accompanying source ledger retains exact public-document versions, byte digests,
retrieval dates and section pointers. It distinguishes the selected offline wire target,
alternative candidates, vendor assertions and open questions. Relevant standards are
RFC 3161 (2001), RFC 3739 (2004), RFC 4055 (2005), RFC 5280 (2008), RFC 5754 and RFC 5816
(2010), and ETSI EN 319 422 V1.1.1 (2016-03). Later ETSI drafts are research inputs, not an
automatic change to this codec. No general PKIX, RFC, ETSI or provider conformance claim
follows from this finite profile.
