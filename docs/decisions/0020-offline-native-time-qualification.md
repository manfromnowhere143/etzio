# ADR-0020: Offline RFC 3161 timestamp qualification

- Status: accepted for repository-owned offline qualification only
- Date: 2026-10-09
- Owner: Daniel Wahnich

## Boundary

The previous signed-fixture codec proves Etzio's contract, not a provider-native wire
format. This tranche adds a separate RFC 3161/5816 offline observation validator using
pinned pyHanko CMS/PKIX validation. The authorized input surface for this tranche is
repository-owned deterministic native fixtures. Byte validation does not itself prove
input ownership or admit a provider. It has no acquisition client, lifecycle adapter, enrollment
mode, network call, clock read, or conversion to `QualifiedTimeBundleV1`. A passing
observation is neither current UTC nor authorization to admit provider evidence.

This decision accepts the bounded offline profile and its tests. It does not accept an
external operator, root, endpoint, dependency closure for production, or live acquisition.
The dependency is an optional qualification extra; the ordinary engine does not import it.

## Exact profile

`etzio.rfc3161.offline.v1` pins pyHanko `0.37.0`, pyhanko-certvalidator `0.32.1`,
asn1crypto `1.5.1`, and cryptography `49.0.0`. The full `21`-package qualification closure is
pinned in the optional extra and profile,
checked at request construction and validation, inventoried in a CycloneDX `1.6` SBOM, and
hash locked in CI; previously locked package versions are preserved. The profile identity
includes those
versions, the complete root and TSA DER bytes, source identity, exact TSA policy OID,
maximum accuracy, maximum CRL age, and this codec identifier. Version mismatch refuses.

The first algorithm and path profile is deliberately finite: ECDSA P-256/SHA-256;
one pinned self-issued root directly issues one pinned non-CA TSA certificate, using
distinct keys and matching inner/outer signature algorithm identifiers. ECDSA algorithm
parameters must be absent in certificates, CRLs and CMS; NULL is not absence. SHA-256
digest identifiers accept either absent or NULL parameters. The root
must authenticate its own certificate; the TSA must authenticate under that root. Root
key usage must permit certificate and CRL signing. The TSA must have digital-signature key
usage and a critical EKU containing exactly `id-kp-timeStamping`. Both certificates must
cover the full returned uncertainty interval. No intermediates, alternate paths, ambient
trust roots, SHA-1 certificate identification, RSA, PSS, OCSP, delta/indirect CRLs, or COSE
placement is silently added. Those need separately versioned profiles and controls.

Accepted wire is DER: one successful, unmodified response with one CMS signer, one embedded
pinned TSA certificate, encapsulated TSTInfo, SHA-256 digest, and exactly the content-type,
message-digest and SigningCertificateV2 signed attributes. ESSCertIDv2 identifies the TSA
using SHA-256. Unsigned attributes, embedded revocation information, unknown extensions,
ambiguous cardinalities, trailing bytes and noncanonical encodings refuse. A TSA name, when
present, must be the certificate's directory name. Unsupported but otherwise legal RFC
encodings are profile refusals, not claims that the RFC forbids them.

## Request binding and time

Build the SHA-256 imprint over the domain-separated canonical object containing the exact
native profile identity and complete `TrustedTimeRequestV1` body. This binds every existing
scope field, source, purpose, policy, transition, imprint and nonce. The request carries the
exact TSA policy, positive 256-bit nonce value from the existing 64-hex-character nonce,
and `certReq = true`. Reconstruct the request from these retained inputs before checking
any response. A supplied request object must be the exact type and survive canonical
reconstruction; source substitution refuses. Predictable fixture nonces are not a freshness
claim. A future acquisition contract must separately retain unpredictable challenges,
latency bounds, request-before-send persistence, retries and lost-response semantics.

GeneralizedTime must use UTC with seconds and at most six fractional decimal places,
without trailing fractional zeroes. Unsupported greater precision and leap-second syntax
refuse rather than truncate. Accuracy must be explicit, positive and bounded; omitted
components mean zero, but present millis/micros must lie in `1..999`. Integer arithmetic
computes `g` and `a` in microseconds and preserves `[g-a, g+a]`. Integer-second projection
rounds outward: `[floor((g-a)/10^6), ceil((g+a)/10^6)]`. Ordering flags never narrow this
interval or establish ordering against other sources.

One retained direct complete CRL must authenticate under the pinned root. It has a CRL
number and matching authority key identifier. Its interval covers the entire hull using
`thisUpdate <= lower <= upper < nextUpdate`; age is evaluated at `upper`. A listed TSA
serial refuses even when its recorded revocation time is later than the claimed timestamp.
Future or stale CRLs, missing nextUpdate, malformed entries and unsupported critical or
scoped/delta extensions refuse. PKIX validation uses only retained roots, certificates and
that CRL at both interval endpoints, strict required revocation, zero tolerance, and
fetching disabled. CMS validation must report intact, valid and trusted at both endpoints.

This is validation of a signed time assertion against retained material. A compromised TSA
can backdate tokens, and an older signed CRL can omit a later revocation. Current revocation
and acquisition freshness need independent evidence; the token's own time cannot establish
those facts. A timestamp also cannot identify the latest catalog head after local loss.

## Resource and error boundary

Inputs are exact immutable bytes: response at most 64 KiB, each certificate at most 16 KiB,
and CRL at most 256 KiB with at most 1024 entries. A bounded walk of the dependency's
typed ASN.1 tree limits depth to `32`, nodes to `32768`, and collections to `1024`, and
refuses undeclared sequence fields. GeneralizedTime precision is checked before library
normalization can pass through a microsecond-resolution datetime. Cardinalities and
supported structures
are checked before expensive validation. ASN.1 parsing and crypto are delegated to the
pinned libraries. These are application bounds, not a hostile-input process sandbox or a
formal worst-case CPU proof. Future externally sourced bytes require their own admitted
execution/resource profile. All invalid inputs yield a typed refusal; operational errors
are not silently converted into successful observations.

The immutable offline observation retains request/context/profile/response/CRL bytes,
client identities, the complete microsecond hull and outward second projection. Its content
identity binds that dossier. It is deliberately not a sealed kernel authority type. Retry
of the same retained inputs is deterministic and requires no staging directory or service.

## Qualification and independent comparison

Repository-owned test keys are derived from public fixed fixture seeds and never used for
external authority. Native certificate, CRL and CMS signatures are deterministic. The
corpus covers valid controls, foreign request/profile fields, forged signatures, cert and
ESS substitution, missing/multiple attributes, encoding ambiguity, uncertainty boundaries,
full-hull certificate/CRL validity, CRL forgery, revocation, missing material, and disabled
network/ambient-time dependencies. Tests must name the expected refusal, not merely catch
any exception.

An independent OpenSSL `ts -verify` comparison uses exact request/response bytes, pinned
fixture CA/CRL files and explicit verification times. Record the OpenSSL version, binary
hash, commands, exact corpus hashes and results. CMS/PKIX outcomes are compared only where
both implementations support the same semantics. OpenSSL accepting a token without
explicit accuracy is expected: Etzio's additional policy refuses it. The two implementations
share cryptographic ancestry through OpenSSL; this is an independent protocol/path oracle,
not independent cryptographic or provider administration. A moving system OpenSSL is not
silently a qualified CI dependency.

## External administration and local-loss experiment — proposed

Before any real provider is admitted, retain exact endpoint, policy, root/certificate and
client closure, ownership and administration evidence, key rotation/revocation procedures,
clock traceability/accuracy evidence, rate/fee/egress terms, availability assumptions,
compromise recovery and retention policy. Two labels or keys do not prove two operators.
Compare shared CAs, infrastructure, clock sources and organizational control. Admit a
complete source roster and test disagreement, absence, stale material and total outage.

Separately pin an external catalog/anchor/monitor profile. Keep bootstrap trust and instance
identity outside the database under independently administered custody. Publish known heads
H0 and H1 and retain exact signed receipts and consistency evidence. Then, in a disposable
qualified environment, remove all local DB/staging/cache state. Recover using only the
external bootstrap and external evidence. The system must recover H1 or explicitly block;
an authenticated H0 must not be accepted as current. Repeat with a coherent H0 snapshot,
local replacement root, stale CRL/time evidence, split views, withheld monitors, provider
loss, and key rotation. Retain raw requests/responses, administration boundaries, execution
identity and every refusal. No fixture rehearsal can prove real durability or independence.

The retained [comparison dossier](../../tools/native-time/README.md) contains `14` cases:
`11` shared protocol outcomes agree and `3` document the stricter Etzio accuracy/CRL-age
policy. Full release evidence is recorded in the handoff.

## Completion gate and next tranche

This tranche closes only bounded native-format offline qualification and its comparison
record. Remaining gates are actual provider/profile suitability; separately administered
freshness and revocation; a complete source roster; resource/isolation qualification for
external bytes; exact canonical native dossier retention and reconstruction inside the
existing four phases; external latest-head recovery; and storage qualification. None may
be inferred from a passing offline observation or from the fixture lifecycle's green tests.

## Sources inspected 2026-10-09

- [RFC 3161, August 2001](https://www.rfc-editor.org/rfc/rfc3161.html): request/response,
  certificate usage, accuracy and nonce semantics.
- [RFC 5816, March 2010](https://www.rfc-editor.org/rfc/rfc5816.html): ESSCertIDv2.
- [pyHanko 0.37.0, 2026-08-31](https://pypi.org/project/pyHanko/0.37.0/): pinned release;
  installed wheel source is reviewed for the actual callable-imprint API.
- [pyhanko-certvalidator 0.32.1, 2026-09-10](https://pypi.org/project/pyhanko-certvalidator/0.32.1/):
  pinned path/revocation implementation.
- [OpenSSL 3.6 timestamp command](https://docs.openssl.org/3.6/man1/openssl-ts/):
  independent request/response verification interface.

- [RFC 5280, May 2008](https://www.rfc-editor.org/rfc/rfc5280.html): certificate and CRL
  semantics; the exact direct-issuer profile is narrower than general PKIX.
- [CycloneDX 1.6 JSON schema](https://github.com/CycloneDX/specification/blob/1.6/schema/bom-1.6.schema.json):
  dependency inventory format, separate from runtime admission.

- [RFC 5758, January 2010](https://www.rfc-editor.org/rfc/rfc5758.html), sections 2 and 3.2:
  SHA-2 digest parameter equivalence and absent ECDSA signature parameters.
