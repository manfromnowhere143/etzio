# Etzio Architecture

Status: **architecture foundation**, 2026-07-28.

This document distinguishes implemented, modeled, proposed, and blocked behavior. A green
test proves only its named fixture and invariant.

## Architectural verdict

Etzio’s target shape remains sound: a small deterministic control kernel surrounded by
replaceable research workers, with policy authority and independent scientific verification
outside the generative workers.

The first truthful vertical slice now exists. A signed fixture authority is admitted before
mission opening; exact target bytes are retained by digest; VELITES analyzes those bytes
under a bounded lease; canonical events are durably appended and replayed; and AQUILA can
issue an authority-bound modeled-fixture verification lease for a retained candidate.
ETZIO can then resolve every predeclared input under a code-owned CAS type and retain the
exact resolution. It can also authenticate one modeled receipt that signs the resolution
and four typed output digest/size pairs, retain the complete decision evidence, and consume
the lease in the same event append. Canonical lease lineages now retain explicit expiry,
modeled cancellation, atomic reassignment, and exact terminal receipt coverage. This is
meaningful foundation progress, but it is candidate generation, verification assignment,
byte resolution, modeled-statement admission, and lifecycle recovery—not a finding
pipeline.

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
  → scan_completed
  ├─ ordinary fixture scan → mission_closed
  └─ verification intent → VerificationLeaseV1
                           ├─ VerificationArtifactResolutionV1
                           │  → signed VerifierReceiptV1
                           │  → verifier_receipt_admitted
                           ├─ verification_lease_expired
                           ├─ verification_lease_cancelled
                           └─ verification_lease_reassigned → successor lease
                           → mission_closed with exact receipt coverage
```

Only `clean_app.py` and `vulnerable_app.py` from the immutable repository manifest are
admitted. `etzio.scan` has no arbitrary filesystem-target argument. The analyzer itself
takes bytes and owns no filesystem walker.

The verification-intent branch records an assignment, resolves its predeclared bytes, and
can admit one authenticated modeled receipt while consuming its lease. Four separately
typed output artifacts must already exist in the fixture evidence store; Etzio binds their
exact signed digests and sizes but does not produce, parse, or execute them. The path cannot
create or execute a PoC, run an oracle, establish an observed effect, or adjudicate a
finding. Explicit lease recovery changes only canonical modeled lifecycle state. Network
access, credentials, spending, disclosure, publication, and live-target interaction are
absent.

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

The installed Draft 2020-12 schema is a semantic wire-shape guard for all eleven supported
typed object kinds. It has exact signed and unsigned grant/receipt forms, required signed
integrity-decision and head-checkpoint forms, plus eighteen event kind, unit, and payload
branches. One immutable runtime registry closes every top-level semantic body field set;
repository policy compares the schema's envelope, body, nested integrity evidence,
attestation, dispatch, event-unit, and event-payload structure against those contracts.
Parity fixtures validate every runtime-produced form plus known-bad mutations.

JSON Schema is not raw-wire, cryptographic, or lifecycle authority. Typed parsers still
enforce canonical UTF-8 and Unicode, derived identities, lexical ordering, field-keyed
uniqueness, aggregate and cross-field limits, Ed25519 validity, nested bindings, authority,
and event transitions. The schema uses an explicit edge-whitespace class instead of
dialect-dependent `\s`/`\S`, freezing the Python protocol's nonblank-string semantics
across Python and ECMA-262-style regex validators.

## Integrity-evidence contract

`IntegrityDecisionV1` is a required-attestation pre-transition contract. It binds the
service instance, environment, mission, authority, target, exact previous head, complete
proposed-event digest, event kind, transition-intent identity, 256-bit request nonce,
decision and time policies, conservative time interval, typed time evidence with distinct
`source_id` labels, and complete versioned revocation views. The previous head includes both the
mission event predecessor and the exact immediately preceding instance-global checkpoint,
including its signed attestation, signer principal, and historical trust snapshot, so a
newer decision cannot be validated against an older checkpoint baseline or a substituted
co-signature over the same semantic body. The proposed event's scalar
`decision_time` is the conservative upper bound. Whole-interval checks reject uncertainty
that crosses an authorization or deadline boundary. A successor decision's lower bound
cannot precede the upper bound of its retained checkpoint predecessor.

`HeadCheckpointV1` is a required-attestation post-transition contract. It binds an
instance-global predecessor and sequence, mission-local predecessor and event sequence,
exact signed-attestation/principal/trust provenance for both predecessors, the exact event,
signed integrity-decision attestation, decision principal and historical trust snapshot,
checkpoint time, anchor policy, and typed anchor receipt references with distinct
`source_id` labels.
External receipts bind a pre-receipt `anchor_statement_id`; the final checkpoint then
commits to those receipt identities without creating a hash cycle or permitting later
trusted co-signing to rewrite decision or historical checkpoint provenance. Identical
global and mission predecessor identities cannot carry mixed provenance, and one mission
lineage cannot change authority or target.

Decision and checkpoint signatures use distinct domains and exact roles. Consequential
validation reauthenticates every wrapper with its exact historical trust store and requires
different principals even after key rotation. Authenticated-result public construction is
refused; consequential composition rejects subclasses and malformed nested objects,
snapshots the exact constructed trust store and caller policy, and rebuilds a fresh
immutable authenticated result from newly verified signed bytes. Validators use only that
snapshot, preventing a stateful caller object from changing semantics after
reauthentication. Decision predecessor sequences also reserve one signed-int64 successor,
so an accepted decision cannot name an event or checkpoint position that cannot be
represented. Composition reapplies the caller's exact policy identities, namespace
requirements, and uncertainty ceilings.
Revocation floors bind service, environment, decision policy, and exact namespaces; their
local predecessor decision must be the one bound by the immediately previous
instance-global checkpoint, and a floor behind that retained decision is rollback. The
external instance catalog floor carries exact
signed-attestation, principal, and trust provenance for both the global and mission head.
A witness ahead of local history is rollback, not a stale-head retry; an exact current
floor is an idempotent reconciliation state. Locally available projections cannot place a
mission checkpoint ahead of the global head or place different checkpoints at the same
global sequence. Older mission-head ancestry and co-residency depend on a qualified
external catalog adapter and retained consistency evidence; directly constructing the
floor value does not prove them.

This is a provider-neutral contract proof. No real trusted-time, revocation, transparency,
monitoring, or anchor service is connected; typed floor construction alone is not external
authentication. The legacy SQLite `SignedCheckpoint` remains opaque and untrusted.

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
and file modes. Reads reject symlinks, type changes, mode changes, size drift, hard-link
aliasing, and digest drift. Writes use exclusive creation, fsync, and post-write
verification.

Repository-fixture target bytes retain their original generic evidence identity. Modeled
verification inputs use a separate type-domain digest:

```text
sha256("etzio:evidence:typed:v1\0" || exact_type || "\0" || raw_bytes)
```

The closed input roles are PoC, supporting evidence, environment specification, and
effect-oracle specification. The closed modeled-output roles are execution, effect,
measured environment, and termination. Generic reads cannot erase typed identity, typed
reads reject generic or wrong-type identities, and the kernel—not a caller—derives the
expected type from each lease or receipt field.

CAS publication is dirfd-relative and atomically no-clobber on supported Darwin
`renameatx_np(RENAME_EXCL)` and Linux libc `renameat2(RENAME_NOREPLACE)` filesystems. Etzio
fails closed when the native primitive or filesystem support is absent; other operating
systems and older/missing libc surfaces are not currently supported by this store.

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

The reducer cross-validates embedded authority, target, lease, candidate, resolution,
verifier trust, signed receipt, and output-binding objects. It reauthenticates receipt
signatures from the retained decision trust snapshot, enforces exact signed output
digest/type/size bindings and one cumulative grant budget, and derives consumed leases
solely from admitted receipt events. It also derives one lease lineage per candidate,
disjoint active/expired/cancelled/superseded/consumed lease states, and exhaustive
candidate receipt-coverage partitions. It rejects lifecycle, identity, role, revocation,
time, duplicate-use, branching, and budget violations before the offending row is
inserted. Refusal, failure, scan cancellation, timeout, budget exhaustion, completed scan,
awaiting verification, and closed mission remain distinct.

Limits:

- Python’s SQLite API cannot connect through Etzio’s already validated file descriptor, so
  a hostile process under the same OS user retains a pathname-race opportunity;
- a coherent offline database rewrite is not detectable without a connected external
  latest-head catalog;
- legacy checkpoint storage is opaque, while typed checkpoints are not yet persisted or
  required by lifecycle commands; and
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

`VerificationLeaseV1` and `VerifierReceiptV1` bind one modeled fixture assignment and
receipt. The verification lease has its own `verification_lease` object kind, avoiding type
confusion with analysis leases. The kernel now issues that lease from retained mission
state only after the exact grant admits `modeled_fixture_verification`. The AQUILA
`verification_lease_issued` event retains the lease, the complete verifier trust and
revocation snapshot, and its content identity. The lease itself binds that
`issuance_trust_snapshot_id`. Replay checks the exact authority, target, candidate,
producer, verifier key, role, issuance-trust identity, issue time, and bounded expiry
before reconstructing nonterminal `awaiting_verification`.

`VerificationArtifactResolutionV1` binds the retained mission, authority, target, candidate,
and lease to every resolved byte. Its ETZIO event records target files in snapshot order
and verification inputs in exact role order with their digest, type, and size. Resolution
is a legal `awaiting_verification` self-loop and is unique per lease. Exact retries
revalidate current CAS availability before returning retained history; pure reducer replay
validates the historical event without treating mutable filesystem availability as a
replay invariant. The target bytes and typed verification inputs share the authority
grant's single signed `max_bytes` ceiling; resolution cannot reinterpret it as a fresh
per-action allowance.

Signed receipts retain a canonical exactly-one-attestation wire form, strict size/count
limits, time and verdict consistency checks, and exact lease bindings. The signed body also
binds the retained resolution identity and four distinct positive output digest/size pairs.
The supported command derives the lease and unique resolution from canonical history,
authenticates the receipt under a complete decision-time trust snapshot before CAS access,
then revalidates the target, resolved inputs, and outputs. Resolution plus output bytes use
the grant's one non-resetting `max_bytes` ceiling.

One ETZIO `verifier_receipt_admitted` event retains the signed receipt, decision trust body
and identity, adjudication profile, and four code-derived typed output bindings. The same
append is the lease-consumption fact, so replay rejects a second receipt for that lease.
Every authenticated allowed verdict consumes the lease and remains visible. On SQLite
`BUSY` or `LOCKED`, the command makes exactly one append retry and then reconciles retained
history. If an identical submission commits during that bounded contention window, both
callers return the same event. Persistent contention remains a retryable `StoreBusyError`,
not corruption; once a competing commit is visible, conflicting-receipt or distinct-lease
stale-head semantics apply. An exact retry after commit returns retained history without
depending on current CAS availability, including after head advancement or byte deletion.

Three recovery events extend the same `awaiting_verification` state. ETZIO explicitly
records expiry only at or after the retained lease deadline. AQUILA can retain one
pre-deadline modeled `operator_cancelled` decision or atomically reassign the candidate's
latest active, expired, or cancelled lease to a different verifier. Reassignment preserves
every work binding, retains successor-issuance trust evidence and a head-derived nonce,
stays under the original absolute authority deadline and total lease-count ceiling, and
requires a successor-specific artifact resolution. An active predecessor becomes
superseded in the same event that issues its successor; an expired or cancelled predecessor
keeps its original disposition.

Only a candidate's active latest lease can receive a first resolution or receipt. Receipt,
expiry, cancellation, and reassignment races therefore serialize at one canonical event
head, and an earlier signed receipt cannot resurrect a lease after another disposition
wins. `mission_closed` terminates verification intent only with zero active leases. Replay
derives `receipt_coverage_complete` when every candidate has an admitted receipt and
`receipt_coverage_incomplete` when any candidate is never assigned, latest-expired, or
latest-cancelled. These are coverage states, not verdict or finding states.

Current canonical command writers always use a receipt-coverage status for verification
intent. The reducer also preserves and accepts the exact zero-candidate,
no-verification-event `completed` shape as a reader-only compatibility alias for
pre-recovery protocol-v1 streams. The retained event bytes and label are not rewritten;
the alias carries only the same vacuous coverage meaning.

This is modeled-statement admission, not scientific finding admission. Typed output bytes
are opaque. Their shared receipt proves that one trusted key signed the group, not that one
measured execution produced them or that their contents are true. The pure reducer can
validate signed descriptors but cannot replay mutable CAS reads. Generic append therefore
reserves and rejects this event kind; a dedicated store path repeats current-CAS validation
against locked history before insertion. That privileged writer path remains a trusted
service boundary until event heads are externally authenticated.

Still open:

1. freshness of clock and trust snapshots must be established;
2. event heads must be authenticated outside the mutable SQLite store;
3. the filesystem CAS and SQLite event commit need shared atomic retention or an equivalent
   replay-safe protocol;
4. the documented same-user SQLite pathname race must be closed;
5. opaque modeled outputs must become structured, independently produced execution
   evidence with an exact run identity; and
6. different labels/keys must be replaced by proved process, principal, and isolation
   separation.

The recovery events remain modeled control decisions. Their caller-supplied
`decision_time` is not trusted clock evidence, and the AQUILA unit plus
`operator_cancelled` reason do not authenticate an external operator. Reassignment proves
canonical lineage and a different configured verifier identity, not a different principal,
process, host, or isolation boundary.

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

Kernel-issued, authority-bound modeled-fixture verification leases, typed input-resolution
history, atomic modeled-receipt admission, single-use consumption, explicit terminal lease
recovery, and the typed integrity-decision/head-checkpoint contract are retained. The next
gate is adapter qualification and crash-safe enforcement of trusted time, revocation
freshness, and authenticated external event-head anchoring. Foundation integrity is
accepted only when retained evidence also shows:

- trusted time and revocation freshness for every consequential transition;
- authenticated, externally anchored event heads;
- atomic retention across filesystem CAS and the SQLite event commit;
- closure of the same-user SQLite pathname race; and
- every new consequential invariant rejecting a known-bad.

Structured Linux/KVM execution evidence and proved MARCELLUS/CATO separation follow; they
are not implied by modeled output artifacts.
