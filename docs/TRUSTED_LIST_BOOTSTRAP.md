# Offline trusted-list signature inspection

Status: bounded documentary inspection contract, 2026-10-11. No provider, trust root,
clock, legal status or kernel authority is admitted by this work.

## Problem and decision

The retained Spanish trusted list contains the publisher's Sectigo R35 intermediate,
but an embedded signing certificate alone cannot authenticate that list. The European
Commission's April 2026 Official Journal notice publishes six LOTL signing certificates
and their SHA-256 fingerprints. Its current LOTL names Spain's XML location and signing
certificates. Check this finite document chain offline, retaining the independent
publication used for each pin. Do not reinterpret a self-signed certificate as a trust root.

The [notice](https://eur-lex.europa.eu/eli/C/2026/1944/oj/eng) and
[pivot procedure](https://ec.europa.eu/tools/lotl/pivot-lotl-explanation.html) require
authentication before consuming a list. A match to the notice's current certificate set
can avoid historical pivots for this snapshot; other snapshots may require the documented
chronological pivot chain. This tool implements no pivot acquisition or rollover policy.

## Inspector contract

`scripts/inspect_trusted_list_signature.py` reads one explicitly named local XML file,
at most 4 MiB, and a caller-supplied lowercase SHA-256 certificate fingerprint. The pin
is an input, not self-authenticating authority. The report binds the complete input bytes
and that pin. The optional `native-time` dependency closure supplies already-pinned lxml
and cryptography; no dependency or production codec changes are needed.

This deliberately narrow profile supports one direct root XML signature on an ETSI
`TrustServiceStatusList`, exclusive C14N 1.0 without comments, RSA PKCS#1 v1.5/SHA-512,
SHA-512 reference digests, and exactly two references: the whole document with empty URI
and enveloped-signature removal, then the unique XAdES SignedProperties in that signature.
The signature's embedded DER certificate must match the caller's pin and the signed
SigningCertificateV2 digest. RSA key sizes are bounded to 2048, 3072 or 4096 bits for this
documentary check; this is not an accepted Etzio algorithm or PKIX profile.

The parser requires UTF-8, bounds nodes/depth and canonical output, disables network and
entity resolution, and refuses DTDs, entities, processing instructions, comments, duplicate
or alternate-spelling ID attributes, nested/additional signatures, external references,
unrecognized transforms and algorithm parameters. References resolve only to the exact
structurally bound nodes. Signature removal preserves tail text. No schema validation,
XSLT, XPath supplied by input, URL fetching, subprocess or ambient clock is used.

Only after both reference digests, the signer binding and SignatureValue verify does the
inspector emit a deterministic report. It emits no parsed service claims and no trusted
tree for consequential use. It is a narrow signature-mathematics inspector, not a general
XMLDSig/XAdES validator, ETSI trusted-list processor, certificate-path validator or trust
enrollment interface. XAdES issuer/serial, signing time and other signed properties are
covered as bytes but are not interpreted as validated semantics.

CLI exit 0 means the stated mathematical checks passed under the supplied pin; exit 2
means refusal. Every report explicitly denies kernel authority, currentness, revocation,
legal qualification and provider admission. A caller can supply an arbitrary key pin and
obtain a true mathematical result; the independent publication chain must be assessed
separately. A valid old document remains valid mathematics and must never become a claim
of the latest head. Publisher times are declarations, not qualified UTC.

## Required controls and evidence

Owned synthetic documents exercise valid replay and signed whitespace, body and property
tampering, wrong pin/key/digest/signature, certificate substitution, wrapping and duplicate
IDs, extra signatures/references, external URIs, DTD/entity input, comments/processing
instructions, unsupported algorithms/transforms/parameters and resource limits. Retained
real documents are inspected offline only. Their original captures, parser observations,
pin provenance and failures remain separately identified; tests do not execute third-party
code or contact providers.

The [W3C security guidance](https://www.w3.org/TR/2013/NOTE-xmldsig-bestpractices-20130411/)
motivates binding what is consumed to what is signed and refusing unnecessary transform
machinery. This limited checker is additional evidence, not independent implementation
agreement. An independent XML signature implementation, authenticated OJ publication seal,
freshness/rollback policy, complete current TSA chain, revocation and native lifecycle
integration remain outside this tranche.

## Retained result and replay

The [2026-10-11 evidence record](evidence/trusted-list-bootstrap-2026-10-11.json) retains
the source identities, initial TLS failures, pin chain and two successful inspections.
All six annex certificates reproduce the notice's printed SHA-256 fingerprints. The
LOTL signer is exactly the notice's second DER certificate. After verification, the exact
Spain XML pointer supplies the retained Spanish signer's DER certificate. After the
Spanish signature check, its Sectigo timestamp-service entry contains the same R35
intermediate fingerprint as the earlier publisher material. This is a checked document
relationship under the stated HTTPS-publication assumption, not legal or provider admission.

Both lists declare format version 6. LOTL sequence 395 and Spain sequence 189 declare
September 24 issue dates and March 2027 next-update dates; those declarations establish
neither fresh acquisition nor currentness. The Spanish bytes are the October 9 capture,
rehash-checked and preserved. The LOTL bytes were downloaded October 11. The first EC
downloads failed the default TLS trust store; the existing pinned certifi bundle succeeded
without disabling verification. Both failures remain in the ledger.

Raw sources are private, ignored artifacts under
`artifacts/checkpoints/2026-10-11-native-provider-continuation/`. A fresh clone lacks them;
new downloads may be different signed snapshots. Preserve the original bytes. Replay:

```bash
.venv/bin/python scripts/inspect_trusted_list_signature.py \
  artifacts/checkpoints/2026-10-11-native-provider-continuation/eu-lotl.source.txt \
  --signer-sha256 e0a620fbb6747362bb933ac44169d676a553444716cf5f31605f12a22b8396b1
.venv/bin/python scripts/inspect_trusted_list_signature.py \
  artifacts/checkpoints/2026-10-11-native-provider-continuation/spanish-tsl-2026-10-09.source.xml \
  --signer-sha256 180cd536dad2b5ac933236d9dcd55d17afcd9949fed08189b8ae86fe7c2bc3a7
```

The tool does not discover these pins or certify their source. Recheck the ledger's exact
document hashes and direct XML paths when reproducing the documentary linkage. Fifty-five
owned tests cover the profile. Complete release results belong to the exact candidate PR
and private `release-validation.json`, not the collection count or these two observations.

The next native-provider milestone still needs an observed complete current TSA chain,
applicable acquisition authority, a separately versioned compatible profile and retained
native lifecycle replay. The separate FreeTSA diagnostic remains prepared and unaccepted.
This result is specific to the Sectigo documentary route and grants no FreeTSA authority.
