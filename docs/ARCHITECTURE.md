# Etzio Architecture

Status: **architecture foundation**, 2026-07-27.

This document distinguishes implemented, modeled, proposed, and blocked behavior. A green
test proves only its named fixture and invariant.

## Architectural verdict

Etzio’s target shape remains sound: a small deterministic control kernel surrounded by
replaceable research workers, with policy authority and independent scientific verification
outside the generative workers.

The first truthful vertical slice now exists. A signed fixture authority is admitted before
mission opening; exact target bytes are retained by digest; VELITES analyzes those bytes
under a bounded lease; canonical events are durably appended and replayed. This is meaningful
foundation progress, but it is candidate generation—not a finding pipeline.

## Target system

```text
                          human / program authority
                                      │
                            exact signed grants
                                      ▼
┌───────────────────────────────────────────────────────────────────────────┐
│ AQUILA · policy plane                                                    │
│ admission · scope · budgets · leases · egress · kill · approvals         │
└──────────────────────────────┬────────────────────────────────────────────┘
                               │ admitted commands
                               ▼
┌───────────────────────────────────────────────────────────────────────────┐
│ ETZIO · deterministic control plane                                      │
│ protocol · reducer · append-only ledger · recovery · evidence graph      │
└──────────────┬───────────────────────────────┬────────────────────────────┘
               │ leased work                   │ authenticated receipts
               ▼                               ▼
┌──────────────────────────────┐     ┌──────────────────────────────────────┐
│ research plane              │     │ independent proof plane              │
│ SCIPIO → FABIUS → VELITES   │     │ MARCELLUS builder → CATO verifier   │
│ domain + technique packs    │     │ separate identities and isolation   │
└──────────────┬───────────────┘     └──────────────────┬───────────────────┘
               └──────────────────────┬─────────────────┘
                                      ▼
                         CAMILLUS → FABRICIUS
                         adjudication   draft
                                      │
                                      ▼
                       MINERVA offline promotion loop
```

Workers return typed proposals. They do not grant authority, mutate canonical state, or
declare a finding.

## Implemented fixture path

The supported executable path is intentionally closed:

```text
repository fixture manifest
  → CAS artifacts + TargetSnapshotV1
  → SignedAuthorityGrantV1
  → AuthorityAdmissionV1
  → mission_opened
  → AnalysisLeaseV1
  → StaticCandidateV1 / explicit parse failure
  → scan terminal
  → mission_closed
```

Only `clean_app.py` and `vulnerable_app.py` from the immutable repository manifest are
admitted. `etzio.scan` has no arbitrary filesystem-target argument. The analyzer itself
takes bytes and owns no filesystem walker.

The path cannot create a PoC or finding. Network access, credentials, spending, disclosure,
publication, and live-target interaction are absent.

## Protocol v1

Every new protocol object uses one common envelope:

```text
EnvelopeV1
  protocol_version = 1
  object_kind
  object_version = 1
  object_id
  body
  attestations
```

`object_id` is a full SHA-256 identity over domain-separated kind and canonical body
semantics. Attestations do not change the object identity.

Canonical JSON enforcement includes:

- UTF-8 only, duplicate-key rejection, and ASCII snake-case field names;
- Unicode 17.0.0 NFC scalar strings through an exact dependency;
- booleans distinct from integers and no floats or non-standard numeric values;
- signed 64-bit integer range;
- fixed wire, string, key, nesting, container, node, and attestation ceilings; and
- rejection of noncanonical wire spellings during parsing.

The checked-in `protocol.v1.schema.json` describes the common framing envelope and supported
kind names. It is not yet a semantic schema for each object body. Python typed parsers are
currently the semantic authority; schema/runtime parity remains an open Gate A item.

## Authority

`AuthorityGrantV1` binds issuer, subject, exact target snapshot, assets, permitted actions,
authority evidence, time interval, and byte/candidate/wall-clock ceilings. An Ed25519
signature is carried as exactly one common-envelope attestation.

Admission checks:

- canonical grant identity and signature;
- trusted key role and configured issuer;
- key/grant revocation snapshot;
- half-open validity interval;
- exact target snapshot and required actions; and
- fixed hard ceilings.

Trusted public keys must be canonical Ed25519 points in the prime-order subgroup. Etzio uses
libsodium point validation before keys enter configured or embedded trust snapshots; this
closes a reproduced small-order-key signature-forgery failure in the underlying generic
verification backend.

`AuthorityAdmissionV1` retains the signed grant, complete trust/revocation snapshot, decision
time, target, required actions, signer, and expiry, and revalidates those historical inputs
when reconstructed.

Limits: the admission record cannot prove that its supplied clock or revocation snapshot
was fresh, or that represented third-party permission was legally valid. A trusted service
clock and external authority-evidence procedure are required before live research.

## Evidence and target identity

`FileEvidenceStore` retains immutable bytes by full SHA-256 digest under private directory
and file modes. Reads reject symlinks, type changes, mode changes, size drift, and digest
drift. Writes use exclusive creation, fsync, and post-write verification.

`TargetSnapshotV1` binds source kind, canonical relative paths, exact artifact digests,
sizes, and aggregate size. The governed runner revalidates the repository fixture against
the checked-in manifest before analysis.

Limits: the current CAS is local filesystem storage, not a multi-tenant access-control,
retention, encryption, or legal-evidence service.

## Event kernel and replay

`EventV1` is itself a protocol-v1 envelope. Each event binds mission, sequence, kind, unit,
authority, target, decision time, typed payload, and previous event digest.

`SQLiteEventStore`:

- requires an explicit private filesystem path;
- uses WAL and `synchronous=FULL`;
- stores exact canonical event bytes;
- validates the full retained stream and proposed transition inside a
  `BEGIN IMMEDIATE` append transaction;
- compares the expected head;
- rejects gaps, forks, duplicate digests, illegal transitions, and post-terminal appends;
- prevents updates and deletes through database triggers; and
- reconstructs state exclusively through the reducer.

The reducer cross-validates embedded authority, target, lease, and candidate objects. It
enforces the exact `static_analysis` action and rejects target-byte, lease-time,
candidate/output-count, and retained-epoch time violations before the offending row is
inserted. Refusal, failure, cancellation, timeout, budget exhaustion, completed scan, and
closed mission remain distinct.

Limits:

- Python’s SQLite API cannot connect through Etzio’s already validated file descriptor, so
  a hostile process under the same OS user retains a pathname-race opportunity;
- a coherent offline database rewrite is not detectable without an external anchor;
- checkpoint storage is opaque and not yet authenticated by an authority component; and
- event time is only as trustworthy as the invoking service’s supplied clock.

Production deployment therefore requires an isolated service identity, protected mount,
trusted clock, and externally anchored event heads.

## Investigation plane

The implemented VELITES technique is a narrow Python `ast` analyzer. It recognizes six
syntactic rule classes across seven planted vulnerable-fixture instances and returns zero
on the one clean fixture.

Protocol candidates bind mission, authority, analysis lease, target snapshot, source
artifact, path, line, column, rule, severity, symbol, producer, and analyzer version. Source
snippets and literal values are excluded from persisted candidate objects. Candidate IDs
are stable within a mission; claim IDs preserve the mission-independent observation
identity.

This does not establish real-world precision or recall. There is no interprocedural taint,
alias analysis, dependency reasoning, dynamic proof, exploit construction, or broad corpus.

## Verification boundary

`VerificationLeaseV1` and `VerifierReceiptV1` model exact bindings for one fixture receipt.
The verification lease has its own `verification_lease` object kind, avoiding type confusion
with analysis leases. Signed receipts have a canonical exactly-one-attestation wire form,
strict size/count limits, verifier trust snapshots, revocations, time checks, verdict
consistency checks, and exact lease/evidence-digest bindings.

This boundary authenticates a configured modeled verifier’s statement. It never mints a
finding.

Still open:

1. the kernel must issue the verification lease under the admitted grant;
2. referenced digests must resolve to typed retained CAS bytes;
3. acceptance and single-use lease consumption must commit atomically;
4. the complete decision inputs and signed receipt must enter canonical mission history;
5. freshness of clock and trust snapshot must be established; and
6. different labels/keys must be replaced by proved process, principal, and isolation
   separation.

## Modeled components

The original `MasterLoop`, ten unit ports, `BenchmarkTarget`, and verdict/FPR corpus remain
useful behavior models. They are deliberately separate from the protocol-v1 path:

- CATO calls a toy target in the host process;
- MARCELLUS passes through an in-memory object;
- FABIUS emits fixed hypotheses;
- CAMILLUS sorts;
- FABRICIUS renders in-memory prose; and
- MINERVA returns counts.

Their findings, environment labels, and hash-linked in-memory events are not evidence of the
target architecture.

## Isolation model

The proposed proof plane has two separately identified workers:

- **builder**: receives candidate evidence and constructs an exploit artifact;
- **verifier**: receives immutable target and artifact bytes, not builder state, and executes
  a versioned effect oracle.

The first candidate profile is Linux/KVM microVM isolation. Required evidence includes
default-deny egress, no ambient credentials, immutable images, read-only inputs, ephemeral
writes, cgroup/resource ceilings, syscall/device restrictions, expiring leases, complete
execution receipts, and a tested out-of-band kill path.

No such execution tier exists in this repository. Exploit execution remains blocked.

## Domain and technique packs

Breadth is an adapter problem:

```text
domain pack
  target/revision resolver
  authority vocabulary
  surface and hypothesis models
  build/execution profile
  effect oracles
  severity/disclosure rules
  benchmark suite

technique pack
  tool declaration
  input and output protocol
  required capabilities and resources
  positive and negative fixtures
  versioned evaluator
```

The first proposed domain wedge is benchmark-first Solidity/EVM and later blockchain
clients. It begins only after the proof-plane gates close.

## Threat model

Etzio assumes hostile target bytes and build systems, prompt injection in research inputs,
deceptive tool output, compromised model workers, forged receipts, verifier gaming,
artifact substitution, event tampering, dependency compromise, credential theft, resource
exhaustion, and operator scope mistakes.

No model, worker, signature, consensus, repository possession, or green CI run is itself
scientific or policy authority.

## Next acceptance gate

Foundation integrity is accepted only when retained evidence shows:

- semantic per-kind schema/runtime parity;
- kernel-issued, authority-bound verification leases;
- typed CAS resolution for every receipt reference;
- atomic receipt acceptance and lease consumption under concurrency;
- trusted time and externally anchored event heads; and
- every new consequential invariant rejecting a known-bad.

Linux/KVM isolation is the next gate after that—not a substitute for it.
