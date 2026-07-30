# Etzio Architecture

Status: **architecture foundation**, 2026-07-29.

This document distinguishes implemented, modeled, proposed, and blocked behavior. A green
test proves only its named fixture and invariant.

## Architectural verdict

Etzio’s target shape remains sound: a small deterministic control kernel surrounded by
replaceable research workers, with policy authority and independent scientific verification
outside the generative workers.

The first truthful vertical slice now exists. A signed fixture authority is admitted before
mission opening; exact authority and target bytes are retained with their claiming events
inside one SQLite transaction; VELITES analyzes those bytes under a bounded lease;
canonical events are durably appended and replayed; and AQUILA can issue an
authority-bound modeled-fixture verification lease for a retained candidate. ETZIO can
then resolve every predeclared input under a code-owned artifact type and retain the exact
resolution, BLOBs, and role mappings atomically. It can also authenticate one modeled
receipt that signs the resolution and four typed output digest/size pairs, retain those
exact output BLOBs with the complete decision evidence, and consume the lease in the same
event append. Canonical lease lineages now retain explicit expiry, modeled cancellation,
atomic reassignment, and exact terminal receipt coverage. An empty-history-only schema-v2
profile can additionally commit every event with a signed decision dossier and recover a
byte-exact anchor statement, signed checkpoint candidate, and exact-current global and
mission floor before the modeled facade returns. This is meaningful foundation progress,
but its providers are deterministic repository fixtures. It is candidate generation,
verification assignment, byte retention, modeled-statement admission, and lifecycle
recovery—not external authority or a finding pipeline.

A separate V1 qualification surface now authenticates signed repository-fixture
trusted-time and revocation statements under an exact copied profile, fuses time
conservatively, checks revocation validity, freshness, and unanimous floors against the
complete time hull, and freshly maps sealed results into the provider-neutral integrity
types. Its deterministic corpus and eighty-one focused tests prove contract and known-bad
behavior only. The surface is not wired to the modeled-finality state machine, and it
qualifies no native or externally administered provider.

## Target system

```text
[human / program authority] ── exact signed grants ──▶ [AQUILA policy plane]

[AQUILA] ── admitted authority and policy decisions ──▶ [ETZIO control kernel]

[ETZIO] ── leases + exact immutable inputs ──▶ [research workers:
                                                SCIPIO / FABIUS / VELITES]
[research workers] ── typed proposals ──▶ [ETZIO]

[ETZIO] ── leases + exact immutable inputs ──▶ [independent proof workers:
                                                MARCELLUS / CATO]
[independent proof workers] ── typed proposals + signed receipts ──▶ [ETZIO]

[ETZIO] ◀── canonical reads / atomic writes ──▶ [canonical SQLite evidence vault]

[ETZIO] ── kernel-accepted evidence only ──▶ [CAMILLUS adjudication]
                                             └──▶ [FABRICIUS draft]

[canonical vault: retained positive + negative outcomes]
  └──▶ [MINERVA offline evaluation and governed promotion proposals]
```

Workers return typed proposals. They do not grant authority, mutate canonical state, or
declare a finding. CAMILLUS never consumes a worker proposal or receipt directly: ETZIO
first authenticates, lifecycle-checks, and retains the evidence. MINERVA evaluates retained
positive and negative outcomes offline; it cannot directly change authority policy,
evaluators, benchmarks, or production bytes.

## Implemented fixture path

The common repository-fixture admission and analysis prefix is intentionally closed:

```text
repository fixture manifest
  → bounded filesystem staging/cache + TargetSnapshotV1
  → SignedAuthorityGrantV1
  → AuthorityAdmissionV1
  → authority_admitted + exact authority-evidence vault BLOB/role
  → mission_opened + exact target vault BLOBs/roles
  → AnalysisLeaseV1
  → StaticCandidateV1 / explicit parse failure
  → scan_completed
  ├─ supported `etzio.scan` CLI
  │    └─ permanent legacy profile, no verification intent
  │       → mission_closed(status = completed)
  │
  └─ explicit fixture-only verification-intent kernel path (not the CLI)
       ├─ candidate remains never assigned
       └─ VerificationLeaseV1
          ├─ VerificationArtifactResolutionV1
          │  → verification_artifacts_resolved + exact input vault BLOBs/roles
          │  → caller-supplied signed VerifierReceiptV1
          │       (modeled statement only; no verifier or artifact execution)
          │  → verifier_receipt_admitted + exact output vault BLOBs/roles
          │       (atomically consumes the lease)
          ├─ verification_lease_expired
          ├─ verification_lease_cancelled
          └─ verification_lease_reassigned → successor VerificationLeaseV1
                                               └──↺ repeat this lease branch with a
                                                    successor-specific resolution
       → mission_closed only when no active lease remains
          ├─ receipt_coverage_complete
          └─ receipt_coverage_incomplete
```

The explicit fixture-only path may optionally be attached to the deterministic finality
qualification surface:

```text
completely empty schema-v2 store
  → irreversible modeled_integrity_fixture_v1 enrollment
  → ModeledIntegrityFinalizingEventStoreV1 facade
  → every event traverses the four-phase modeled-finality state machine
  → facade returns only after exact finalization
```

Only `clean_app.py` and `vulnerable_app.py` from the immutable repository manifest are
admitted. `etzio.scan` has no arbitrary filesystem-target argument. The analyzer itself
takes bytes and owns no filesystem walker.

The verification-intent branch records an assignment, resolves its predeclared bytes, and
can admit one authenticated, caller-supplied modeled statement while consuming its lease.
Four separately typed output artifacts must already exist in the canonical vault or exact
filesystem staging store; first admission imports staged bytes into the transaction. Etzio
binds and retains their exact signed digests and sizes but does not produce, parse, or
execute them. The path cannot create or execute a PoC, run an oracle, establish an observed
effect, or adjudicate a finding. Explicit lease recovery changes only canonical modeled
lifecycle state. The optional finality facade changes commit and recovery semantics, not
the authority or execution surface. The supported CLI, explicit fixture kernel path, and
repository-supplied qualified deterministic finality composition have no network access,
credentials, spending, disclosure, publication, or live-target interaction. The
service-port interfaces do not mechanically prohibit those capabilities in an arbitrary
replacement; structural conformance alone does not admit one.

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

The core objects remain provider-neutral. The modeled integrity facade now persists and
enforces them for an empty repository-fixture history: event plus pending dossier commit
atomically; anchor statement, checkpoint candidate, and finalization are separate
append-only records; the two conceptual modeled protocol writes are retried under retained
byte-exact identities; and command success requires the deterministic fixture floor to
name the exact current global and mission checkpoint. The permanent store profile pins
the exact validation policy, modeled adapter profile, service scope, complete trust
store, and distinct decision/checkpoint identities. One unresolved transition blocks
later events and generic replay across the database, including across missions, and
provider calls never run inside a SQLite transaction.

ADR-0012 now defines a separate, networkless V1 qualification boundary for repository-owned
trusted-time and revocation fixture adapters. The exact copied profile binds the complete
trust root, validation policy, role-separated source roster, provider policies, codecs,
service, and environment. Exact signed statement bytes authenticate before any claim is
parsed; the request binds profile, root, policy, scope, purpose, imprint, and nonce. The
kernel-owned harness also binds its deterministic adapter inputs and ordered cases in a
content-derived corpus manifest and requires byte-identical same-request retries.

ADR-0013 extends that boundary to the remaining two evidence kinds with a separate
networkless V1 head-authority qualification profile. Its fixed roster pins at least two
anchor sources over distinct log origins, exactly one catalog source, and at least two
monitor sources witnessing the catalog's exact log origin. The registered object is one
closed canonical `AnchorRegistrationLeafV1`; the qualifier recomputes its RFC 9162 leaf
hash from the request and refuses any receipt claiming another leaf. Anchor receipts must
carry a verifying RFC 9162 inclusion proof to their own claimed root, and the catalog head
must carry a verifying RFC 9162 consistency proof from the exact retained predecessor root.
An unchanged tree size may not change its root, and every monitor must agree exactly on log
origin, tree size, and root hash. Head freshness is evaluated only against the complete
ADR-0012 qualified time hull, and the sealed result maps to provider-neutral anchor
references plus one `HeadCheckpointFloorV1` whose own constructor reapplies the ADR-0008
genesis, provenance, and mission-not-ahead rules.

Every configured trusted-time source is required. Their closed intervals must have a common
overlap, but the result retains the conservative outer hull rather than claiming the
narrower intersection. Revocation metadata and all configured floor witnesses must agree,
and the complete time hull must fit the half-open metadata validity window and the bounded
freshness interval. Sealed results are freshly reauthenticated before mapping exact signed
BLOBs and references into `ProviderEvidenceBlobV1`, `RevocationViewV1`, and
`RevocationFloorV1`; direct construction, incomplete rosters, substitutions, replay,
staleness, ambiguity, and malformed wire fail closed.

This is contract-and-harness proof, not a lifecycle integration. The existing
`PendingIntegrityTransitionV1` and modeled-finality facade do not consume the qualified
mapping and continue to use their original unsigned, code-derived fixture assertions.

The canonical four-phase modeled-finality state machine is:

```text
proposed EventV1 / exact prior global + mission heads / enrolled profile authority
  → authenticated signed IntegrityDecisionV1
  → TX1 · PHASE 1: event + pending decision/trust dossier + provider assertions
  → process-local catalog rehydration from retained predecessor lineages
       (`prime_catalog`; nondurable and not a protocol write)
  → TX2 · PHASE 2: exact anchor statement + byte-exact registration request
  → modeled anchor registration                         [protocol write 1]
  → TX3 · PHASE 3: exact anchor receipts + signed HeadCheckpointV1 candidate
                    + byte-exact publication request
  → modeled checkpoint publication                     [protocol write 2]
  → exact code-derived current-floor assertion
       (the candidate is both the instance-global and mission head)
  → TX4 · PHASE 4: exact finalization record
  → modeled facade success
```

From TX1 until TX4, the one unresolved transition is an instance-global barrier: every
later append path and generic replay is refused across every mission. Only explicit
integrity inspection and recovery may read or advance the retained lineage, and no facade
command can report success before TX4 has been reloaded and verified.

No real trusted-time, revocation, transparency, monitoring, catalog, or anchor service is
connected. Signed qualification statements authenticate deterministic repository-fixture
producers; they do not establish truthful UTC, current real-world revocation, external
durability, independent administration, or non-equivocation. Modeled-finality floor and
provider-evidence assertions remain exact unsigned code-derived fixture claims. The legacy
SQLite `SignedCheckpoint` remains opaque and untrusted.

The exact next gate is to specify and prove durable blocked-finality disposition, exact
reason, policy-authorized recovery decision, and recovery replay before any external
provider connection. The remaining blocked cluster then includes
qualifying independently administered providers without weakening retained recovery;
closing the same-user pathname and coherent offline-rewrite boundary; production storage
and power-fault qualification plus sensitive-evidence controls; and structured
independently produced execution evidence with proved MARCELLUS/CATO separation. Until
those gates close, live-target work and finding admission remain blocked.

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

`FileEvidenceStore` is the bounded private staging and cache surface before first canonical
ingestion. It stores immutable names by full SHA-256 digest under private directory and
file modes. Reads reject symlinks, type changes, mode changes, size drift, hard-link
aliasing, and digest drift. Writes use exclusive creation, fsync, and post-write
verification. Filesystem availability after commit is not canonical retention and is not
a replay invariant.

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

The SQLite database is the canonical immutable evidence vault. `authority_admitted`,
`mission_opened`, `verification_artifacts_resolved`, and
`verifier_receipt_admitted` are protected byte-claiming boundaries. One
`BEGIN IMMEDIATE` transaction validates locked lifecycle history and the proposed event,
derives the exact artifact manifest in code, resolves an existing canonical identity or
reads a first-seen artifact from exact filesystem staging, rehashes and bounds the bytes,
inserts deduplicated exact BLOBs and complete event-role mappings, and inserts the event.
Generic append rejects all four protected kinds.

The vault preserves generic authority/target and typed verification digest domains as
distinct identities. Exact committed replay and retry read canonical BLOBs and mappings
without staging. Every load compares the retained mapping set with the code-derived event
manifest, verifies type and size, and rehashes each BLOB retained for the loaded stream. A
corrupt canonical identity never falls back to otherwise-valid staging bytes.

Each unique BLOB retains its immutable first-origin event. A covering reverse index proves
that the origin event maps the same identity and size without scanning the role table.
Exact batch APIs admit at most 515 selectors or role-derived requests and at most 1 GiB of
selected unique response identities. Identity resolution follows immutable first-origin
events; selector loads follow exact event owners. Each distinct required mission is
reduced once, and one shared rehash set ensures each distinct BLOB encountered across
those complete histories is read and hashed at most once per batch; only requested
identities remain in the response cache. Production target, verification-input, and
receipt-output paths use these batches. The selected-response ceiling does not bound the
additional integrity I/O needed to validate complete required histories.

The strict schema has Etzio `application_id = 0x45545A31` (ASCII `ETZ1`) and
`user_version = 2`. Empty new databases are initialized transactionally. An exact
version-1 transactional vault is migrated atomically to the version-2 layout under a
permanent legacy profile, preserving its history without assigning integrity finality.
Only a completely empty profile can irreversibly enroll in modeled integrity. Unknown,
malformed, or nonempty pre-vault state is still refused without promotion; importing that
older event-only state requires a separately implemented stop-the-world migration that
reconstructs and proves every protected event's complete byte coverage.

Ingestion remains bounded even when one physical BLOB is deduplicated across events:
authority evidence is limited to 16 MiB; target snapshots retain the existing 256-file and
64 MiB aggregate bounds; one artifact resolution remains at most 128 MiB, including at
most 64 MiB of typed inputs and the grant's tighter signed byte ceiling; receipt output is
exactly four positive artifacts and at most 64 MiB total; and resolution plus output
retains the grant's one non-resetting logical byte ceiling. Each store opening also
enforces an exact configured logical evidence ceiling, defaulting to 1 GiB. It counts each
distinct identity-scheme/type/digest BLOB once and, for the modeled-integrity profile,
also counts exact profile bytes, immutable phase records, and typed provider-evidence
bytes. Enrollment and every transition reserve a conservative worst-case finality
allowance before mutation. This operational setting is not persisted authority and can
differ on a later opening. Direct BLOB insertion is bounded, and streaming access is
read-only; writable incremental BLOB handles are outside the immutable contract.

Staging publication is dirfd-relative and atomically no-clobber on supported Darwin
`renameatx_np(RENAME_EXCL)` and Linux libc `renameat2(RENAME_NOREPLACE)` filesystems. Etzio
fails closed when the native primitive or filesystem support is absent; other operating
systems and older/missing libc surfaces are not currently supported by this store.

`TargetSnapshotV1` binds source kind, canonical relative paths, exact artifact digests,
sizes, and aggregate size. The governed runner revalidates the repository fixture against
the checked-in manifest before analysis.

Limits: neither staging nor the SQLite vault is a multi-tenant access-control, encryption,
or legal-evidence service. The configured logical quota does not bound SQLite pages,
rollback-journal headroom, backups, or device consumption; deployment must bound those
separately.

## Event kernel and replay

`EventV1` is itself a protocol-v1 envelope. Each event binds mission, sequence, kind, unit,
authority, target, decision time, typed payload, and previous event digest.

`SQLiteEventStore`:

- requires an explicit private filesystem path;
- requires every declared runtime to use rollback-journal `DELETE` mode with
  `synchronous=EXTRA`;
- reauthenticates `journal_mode=DELETE`, `synchronous=EXTRA`, `foreign_keys=ON`,
  `trusted_schema=OFF`, `ignore_check_constraints=OFF`, `read_uncommitted=OFF`, and
  `writable_schema=OFF` on every retained-state cache check and protected writer
  boundary;
- refuses a preexisting WAL header before SQLite opens the path, leaving conversion to an
  explicit stop-the-world migration under a fixed runtime;
- rejects SQLite before 3.37.0 and unknown major versions, classifies the exact 2026
  WAL-reset fix lines for diagnostics, and refuses connection settings outside the
  uniform policy;
- requires the exact Etzio application identifier, schema version, schema object set,
  strict-table shape, foreign keys, indexes, and triggers, and refuses nonempty pre-vault
  event state pending an explicit offline migration;
- stores exact canonical event bytes and, for protected events, exact immutable evidence
  BLOBs plus complete code-derived role mappings;
- retains an exact permanent legacy or modeled-integrity profile; only an empty history
  can enter the latter;
- under the modeled profile, requires one signed pending dossier in the same transaction
  as every event and blocks every different append while any transition is unresolved;
- retains append-only anchor, checkpoint-candidate, finalization, and typed provider-
  evidence rows, with exact duplicate reconciliation and conflicting-body refusal;
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
- connection diagnostics are observational rather than a continuous cross-process mode
  monitor; a hostile same-user SQLite connection can race journal state after admission;
- a coherent offline database rewrite is not detectable without a connected external
  latest-head catalog;
- legacy checkpoint storage is opaque; typed checkpoints are persisted and required only
  by the deterministic modeled-integrity facade, not by the ordinary CLI or a qualified
  external-authority profile; and
- event time is only as trustworthy as the invoking service’s supplied clock.

Production deployment therefore requires an isolated service identity, protected mount,
trusted clock, and externally anchored event heads.

The uniform rollback policy closes Etzio-created exposure to SQLite’s disclosed WAL-reset
defect across the declared mixed-runtime matrix. The transactional evidence vault
separately closes the ordinary filesystem-staging/SQLite retention split for the four
implemented byte-claiming events. Neither claim closes same-user state replacement or mode
manipulation, coherent offline rewrites, or other SQLite, filesystem, kernel, device, and
power-loss failure classes.

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
is a legal `awaiting_verification` self-loop and is unique per lease. The command resolves
an already-retained identity from the canonical vault and consults exact filesystem
staging only on true absence; the protected append then retains all first-seen bytes,
code-derived mappings, and the resolution event in one transaction. Exact retries and
replay use the vault after staging deletion. Canonical corruption is an error and never a
reason to fall back. The target bytes and typed verification inputs share the authority
grant's single signed `max_bytes` ceiling; resolution cannot reinterpret it as a fresh
per-action allowance.

Signed receipts retain a canonical exactly-one-attestation wire form, strict size/count
limits, time and verdict consistency checks, and exact lease bindings. The signed body also
binds the retained resolution identity and four distinct positive output digest/size pairs.
The supported command derives the lease and unique resolution from canonical history,
authenticates the receipt under a complete decision-time trust snapshot before evidence
resolution, then resolves the target, retained inputs, and outputs vault-first with exact
staging permitted only for genuinely new output identities. Resolution plus output bytes
use the grant's one non-resetting `max_bytes` ceiling.

One ETZIO `verifier_receipt_admitted` event retains the signed receipt, decision trust body
and identity, adjudication profile, and four code-derived typed output bindings. The same
append is the lease-consumption fact, so replay rejects a second receipt for that lease.
Every authenticated allowed verdict consumes the lease and remains visible. On SQLite
`BUSY` or `LOCKED`, the command makes exactly one append retry and then reconciles retained
history. If an identical submission commits during that bounded contention window, both
callers return the same event. Persistent contention remains a retryable `StoreBusyError`,
not corruption; once a competing commit is visible, conflicting-receipt or distinct-lease
stale-head semantics apply. An exact retry after commit returns retained history without
depending on filesystem staging availability, including after head advancement or staged
byte deletion.

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
validate signed descriptors, while the store validates exact canonical vault BLOBs and
event-role mappings before reduction. Generic append reserves and rejects all four
byte-claiming event kinds; dedicated store paths derive and retain their exact manifests
against locked history before insertion. Those privileged writer paths remain a trusted
service boundary until event heads are externally authenticated.

Still open:

1. freshness of clock and trust snapshots must be established;
2. event heads must be authenticated outside the mutable SQLite store;
3. the documented same-user SQLite pathname and coherent offline-rewrite boundary must be
   closed;
4. the SQLite/VFS/filesystem/device profile, physical and journal quotas, backup/restore,
   process-kill and power-fault recovery, and sensitive-evidence controls must be accepted
   and qualified;
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
recovery, the typed integrity-decision/head-checkpoint contract, and transactional
evidence retention for all four protected event kinds are retained. Under the documented
SQLite assumptions, an empty-history fixture profile now also demonstrates deterministic
injected-interruption recovery, byte-exact two-stage retry, and exact-current-head command
completion for every event. A separate versioned, networkless trusted-time and revocation
qualification harness now proves exact fixture trust-root, policy, profile, source-roster,
request, signature, interval, freshness, unanimous-floor, retry, corpus-manifest, and
provider-evidence mapping behavior. It is not wired to lifecycle finality, whose provider
assertions remain unsigned and code-derived. A second networkless harness proves
byte-bound anchor registration, RFC 9162 inclusion and consistency verification against the
published reference tree, catalog rollback and equivocation refusal, unanimous monitor
agreement, and sealed head-floor mapping. It is likewise not wired to lifecycle finality.

The exact next gate adds durable blocked-finality disposition and governed recovery before
any external provider connection. Independently administered providers are qualified and integrated only
later, without weakening the retained state machine. Foundation integrity is accepted only
when retained evidence also shows:

- trusted time and revocation freshness for every consequential transition;
- authenticated, externally anchored event heads;
- a durable blocked-finality disposition, reason, and governed recovery decision;
- closure of the same-user SQLite pathname and coherent offline-rewrite boundary; and
- an accepted and qualified durable-storage profile, physical and journal quotas,
  backup/restore and fault-recovery evidence, and sensitive-evidence controls; and
- every new consequential invariant rejecting a known-bad.

Structured Linux/KVM execution evidence and proved MARCELLUS/CATO separation follow; they
are not implied by modeled output artifacts.
