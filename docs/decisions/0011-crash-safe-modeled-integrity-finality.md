# ADR-0011: Crash-safe modeled integrity finality

- Status: accepted
- Date: 2026-07-29
- Owner: Daniel Wahnich

## Context

ADR-0008 defines authenticated `IntegrityDecisionV1` and `HeadCheckpointV1` contracts,
including trusted-time intervals, revocation continuity, instance-global and mission-local
heads, pre-receipt anchor statements, and external rollback floors. It deliberately does
not persist those objects or make lifecycle commands require them.

The existing SQLite command boundary cannot be upgraded by calling an anchor after an
ordinary append:

- recording an event and then recording its pending-integrity state in another transaction
  leaves a crash gap;
- checking for another pending event before entering the SQLite writer transaction leaves
  a concurrency gap;
- returning the locally committed event through the ordinary load path lets an exact
  command retry report replayed success before external finality;
- an external timeout does not reveal whether a registration failed or succeeded; and
- holding `BEGIN IMMEDIATE` across a provider call would turn an unavailable network or
  provider into an unbounded database-wide writer lock.

Etzio also cannot activate finality after a stream already contains events. A checkpoint
chain that starts at event 7 cannot prove that events 0 through 6 were subject to the same
admission rule, and no backfill can recreate the external observations that would have
existed at those earlier boundaries.

The current authorized execution surface remains repository-owned deterministic fixtures.
This decision therefore freezes the storage and recovery semantics under a modeled adapter
profile before any real trusted-time, revocation, anchor, transparency, or monitoring
provider is selected.

## Decision

Etzio accepts one empty-history-only, schema-version-2 modeled integrity-finality profile.
Under that profile, every canonical event from event 0 is a pending transition until its
exact signed checkpoint has passed two idempotent modeled protocol-write calls and an
exact code-derived current-floor check.

This ADR operationalizes the ADR-0008 contract for deterministic repository fixtures. It
does not supersede ADR-0008's protocol, authentication, continuity, or external-authority
requirements. It also preserves ADR-0010's atomic event, evidence-BLOB, and role-mapping
retention boundary.

### Schema-version-2 profile gate

Schema version 2 separates storage layout from an explicit permanent profile:

- an exact schema-version-1 transactional vault is upgraded atomically to the
  schema-version-2 layout under the legacy profile, preserving its existing events,
  evidence, mappings, and opaque checkpoints without assigning them integrity finality;
- modeled integrity finality may be enrolled only when every event, evidence, mapping,
  checkpoint, and integrity relation is empty, whether the layout was newly created or
  upgraded from an exact empty version-1 vault;
- a nonempty version-1 history therefore becomes a non-promotable version-2 legacy
  profile; a caller cannot claim that its existing events were historically finalized;
- enrollment permanently retains the exact modeled fixture-adapter profile/version,
  service instance, environment, validation policy, complete trust snapshot and identity,
  and distinct decision/checkpoint key and principal identities. Every pending decision
  and checkpoint candidate is cross-checked against that fixture-adapter authority
  binding. A raw store opening has explicit integrity-inspection and recovery primitives,
  but generic replay refuses while pending and ordinary append paths carry no modeled
  finality authority;
- opening version 2 with a missing, malformed, or substituted profile fails closed; and
- this narrow layout migration is not an integrity backfill. No online or offline
  conversion from nonempty legacy history to modeled finality is accepted in this tranche.

The Etzio SQLite `application_id` remains unchanged. Version 2 retains the transactional
evidence vault and adds exact schema-validated, append-only integrity-finality relations.
Unknown objects, missing triggers or indexes, mutable rows, partial layouts, and version or
profile mismatches fail closed.

Activation applies database-wide. Every event kind, including refusal, null, failure,
timeout, cancellation, recovery, and terminal events, must traverse the same finality
state machine. A caller cannot opt in only for positive outcomes, only for receipt
admission, or only after a mission becomes interesting.

### One instance-global pending transition

At most one transition may be locally pending in the complete database, across all
missions. The constraint is enforced under the same `BEGIN IMMEDIATE` transaction that
validates and inserts the event, not by a facade pre-check.

A later mission's event zero extends the exact latest finalized instance-global
checkpoint while beginning at its own mission-local genesis. Its subsequent events extend
both exact global and mission predecessors. One unresolved transition blocks every
mission; this is local deterministic-fixture continuity, not externally witnessed
cross-mission ancestry.

The pending transition reserves the next instance-global checkpoint sequence and binds:

- the exact mission predecessor and proposed `EventV1`;
- the exact prior instance-global and mission checkpoint provenance;
- the signed integrity decision, its signer, historical trust snapshot, and validation
  policy;
- the complete typed trusted-time and revocation references plus exact code-derived
  fixture assertions and floor;
- the exact service instance, environment, mission, authority, and target;
- deterministic request and transition identities; and
- all evidence required to resume without caller-supplied reconstruction.

For a protected byte-claiming event, the event, exact evidence BLOBs, code-derived role
mappings, and pending-transition record commit atomically. For an ordinary event, the
event and pending-transition record commit atomically. Either transaction leaves the
pre-transition state or one complete pending state.

While a pending transition exists, every later append path is refused before lifecycle
progression, including ordinary append, evidence-retaining append, and receipt-admission
append. This barrier is a store invariant even if a caller bypasses the facade.

### Four immutable local phases

Progress is represented by four immutable, append-only local records. A mutable status row
is not authoritative.

1. **Pending event.** The canonical event, reauthenticated signed decision/trust dossier,
   and exact code-derived fixture assertions are committed locally. This is durable local
   history but not command success.
2. **Anchor statement.** The exact pre-receipt anchor statement, deterministic
   `anchor_statement_id`, first-stage idempotency key, byte-exact registration request,
   and statement-construction evidence are retained before registration. If the process
   crashes after the modeled provider-side effect but before the returned receipts reach
   the next local phase, recovery repeats this retained byte-exact request under the same
   key.
3. **Checkpoint candidate.** After the anchor receipts and checkpoint-time evidence
   validate, Etzio retains those exact receipt bytes, constructs, signs, reauthenticates,
   and retains the exact `HeadCheckpointV1`, its historical trust and policy inputs, its
   second-stage idempotency key, and the modeled catalog publication request. A later
   signature or receipt cannot rewrite this candidate.
4. **Finalization.** Etzio retains exact canonical code-derived floor assertions naming
   the checkpoint candidate as the modeled global and mission head, together with all
   continuity results. Only this record releases the global pending barrier and permits
   modeled command success.

Each phase names the exact identity of its predecessor and the same event and transition.
Duplicate exact phase insertion reconciles; a second body, provider result, event, or
checkpoint under an existing identity is equivocation and blocks the transition. Update
and delete are forbidden. Recovery verifies every retained phase from canonical bytes
before using it.

The local event is never deleted or rewritten because an adapter is unavailable or
returns invalid evidence. After the first local commit, timeout or ambiguity leaves the
last immutable phase unresolved. Invalid deterministic adapter evidence raises a typed
`IntegrityFinalityBlockedError` for that attempt and leaves the same phase unresolved;
schema version 2 does not durably retain a blocked classification or reason. SQLite
busy, capacity, operational, and corruption errors preserve their store classifications.

### Exactly two modeled protocol-write calls

The modeled protocol has two conceptual write calls:

1. register the exact pre-receipt anchor statement with the configured anchor adapter
   set; and
2. publish the exact signed checkpoint candidate to the configured modeled
   catalog/monitor adapter set.

Trusted-time acquisition, revocation update, floor lookup, consistency lookup, and
latest-head confirmation return exact code-derived fixture assertions in this profile.
One conceptual stage may fan out to the bounded quorum fixed by the profile, but no
unrecorded third protocol write is implied.

After the second write, modeled finality still requires a separate exact current-floor
read plus consistency/witness semantics. These fixture assertions carry no provider
signature or external observation. Future qualified adapters must independently
authenticate those reads; a successful HTTP response, provider submission identifier,
timestamp token, inclusion proof, or provider signature alone will not be finalization.

Recovery also invokes process-local `prime_catalog` to reconstruct the deterministic
fixture service's in-memory compare-and-set view from retained predecessor lineages. It is
neither durable nor external and is not a third protocol write.

No adapter call occurs while the SQLite connection is in a transaction. The sequence is
always:

```text
code-derived modeled adapter reads
  -> short SQLite transaction
  -> modeled protocol write
  -> short SQLite transaction
  -> modeled protocol write
  -> exact current-floor read
  -> short SQLite finalization transaction
```

Data obtained before a transaction is rechecked against the locked local predecessor and
profile before insertion. Data obtained after a transaction is bound to the exact durable
request retained before the modeled provider-side effect.

### At-least-once semantic idempotence

Etzio makes no exactly-once network or provider claim. Both modeled protocol writes are
at-least-once:

- the anchor write uses the exact `anchor_statement_id` as its semantic idempotency key;
- the checkpoint publication uses the exact signed checkpoint candidate identity as its
  semantic idempotency key;
- retries send byte-identical requests derived from retained state, never regenerated
  caller input;
- an exact duplicate response or an already-registered exact object reconciles;
- the same key naming different request or response semantics is equivocation and blocks;
- a timeout is an unknown outcome and is retried with the same key; and
- recovery may repeat either modeled write any number of times without authorizing a
  different event or checkpoint.

Adapter qualification must demonstrate these semantics under lost responses, duplicate
delivery, process death before and after each provider-side effect, reordered responses,
stale reads, and concurrent retry. An adapter that offers only best-effort duplicate
suppression is not sufficient.

### Facade recovery and command completion

Consequential lifecycle commands receive an integrity-finality facade, not an unrestricted
raw SQLite store. The facade explicitly implements the required load, bounded evidence
read, ordinary append, evidence append, and receipt-admission append operations; it does
not expose the SQLite connection through open-ended delegation.

Before returning a lifecycle stream, facade `load` checks the instance-global pending
transition. It resumes that transition from its highest fully revalidated immutable phase.
The facade returns ordinary lifecycle history only after finalization, or raises a typed
pending or blocked result. It never lets an unfinalized event satisfy an existing-event
replay shortcut. Under the modeled profile, generic raw `SQLiteEventStore.load()` also
refuses while any transition is unresolved; only explicit integrity-inspection APIs can
read the pending event and lineage. Only the unresolved phase is durable; a typed blocked
reason is attempt-local.

Every append returns only after its own finalization record has been reloaded and verified.
A crash after local finalization but before the caller receives the response is recovered
as an exact finalized replay. A crash at any earlier point resumes the same pending
transition. Provider unavailability is not classified as SQLite contention or a stale
mission head.

Operational inspection may expose the explicit pending phase through a separate
non-consequential status interface. That interface cannot append, return command success,
or project the pending event as an externally finalized head.

### Modeled deterministic adapter profile

The only accepted adapters in this tranche are repository-owned deterministic fixtures.
They use fixed, versioned keys, policies, namespaces, conservative time intervals,
revocation versions, anchor statements, receipts, consistency evidence, and catalog
responses. They perform no network egress, use no credential, incur no spending, and write
to no third-party service.

Fixed keys authenticate decisions and checkpoints only. Provider-evidence BLOBs are
unsigned, canonical, code-derived assertions checked for exact source, kind, claim, and
reference equality. Separate fixture source IDs, keys, and logical roles exercise quorum
and substitution logic but do not prove separate operators, infrastructure, clocks,
storage, or administration. The profile demonstrates under deterministic fixture tests
that Etzio's state machine, signed-object authentication, continuity, idempotence, refusal,
and crash recovery can be reproduced under fault injection. It is not external authority.

## Standards profile

These standards constrain future adapter qualification. They do not authorize a provider
or add a runtime dependency in this decision.

### Trusted time: RFC 3161, RFC 5816, and RFC 9921

[RFC 3161](https://www.rfc-editor.org/rfc/rfc3161.html) defines TSA request/response
semantics, nonce and message-imprint binding, TSA policy, CMS verification, `genTime`, and
the optional `accuracy` value. Etzio converts `genTime` plus and minus the authenticated
accuracy into the conservative interval required by ADR-0008; absence of acceptable
accuracy, policy, nonce, imprint, certificate path, signing-time EKU, or revocation
evidence fails closed.

[RFC 5816](https://www.rfc-editor.org/rfc/rfc5816.html) updates RFC 3161 with
`ESSCertIDv2`/`SigningCertificateV2` algorithm agility. A future adapter must not fall back
to SHA-1 certificate identification merely because the original RFC 3161 form permits
`ESSCertID`.

[RFC 9921](https://www.rfc-editor.org/rfc/rfc9921.html) gives the two RFC 3161 timestamp
placements for COSE distinct meanings. Etzio preserves that distinction:

- COSE-then-timestamp (`3161-ctt`) can evidence existence of the cryptographic signature;
  and
- timestamp-then-COSE (`3161-ttc`) evidences the payload but cannot be promoted to proof
  that a later signature existed before revocation or another deadline.

The adapter policy must state which object and bytes are timestamped. A payload-only
timestamp is never silently interpreted as signature-time evidence.

### Revocation metadata: exact TUF 1.0.35

The revocation baseline is the exact
[TUF Specification 1.0.35](https://theupdateframework.github.io/specification/v1.0.35/),
not the moving `latest` document. Future implementation review must additionally pin and
hash-lock the selected client and its complete dependency closure.

Etzio requires the detailed client workflow, sequential root update, threshold signatures,
metadata version and expiry checks, consistent snapshot behavior, and exact target
hash/length verification. TUF expiry is evaluated against Etzio's conservative trusted
time. A rollbackable local TUF cache is never the external rollback floor, and TUF
metadata alone does not prove that a presented version is the latest version known outside
the database.

This decision installs no TUF client and connects no TUF repository.

### COSE receipts and SCITT: a narrower consistency-and-witness profile

[RFC 9942](https://www.rfc-editor.org/rfc/rfc9942.html) defines COSE Receipts and their
verifiable-data-structure proof framework.
[RFC 9943](https://www.rfc-editor.org/rfc/rfc9943.html) defines SCITT registration,
transparent statements, multiple transparency services, receipts, and auditing roles.
Etzio adopts only the registration and receipt concepts needed by the ADR-0008 anchor
statement and applies a narrower acceptance profile:

- only the exact configured COSE algorithms, issuers, subjects, key IDs, policies, and
  `RFC9162_SHA256` proof forms are admitted;
- inclusion of the exact anchor statement is required but never sufficient;
- a consistency proof from the retained predecessor to the candidate tree head is
  required;
- an independently authenticated catalog/witness floor must confirm the same candidate
  head and global/mission projection;
- receipt, statement, proof, and tree-head bytes are retained exactly; and
- unsupported VDS algorithms, proof types, detached semantics, or optional SCITT
  flexibility fail closed rather than being ignored.

[RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html) supplies the Merkle inclusion and
consistency algorithms, but it does not define a complete gossip protocol for comparing
views. Inclusion and consistency material served by one log can therefore establish one
internally append-only view without proving that every relying party saw that view.
Etzio requires the separate witness/catalog confirmation; a same-operator second endpoint
does not become independent merely by using another `source_id`.

No Python SCITT or COSE-receipt implementation is accepted as canonical authority in this
tranche.

### Rekor is not complete Etzio authority

[Sigstore Rekor](https://docs.sigstore.dev/logging/overview/) may be considered in a
future adapter comparison as one transparency-log evidence source. It is rejected as a
complete Etzio finality authority because one Rekor deployment, receipt, signed tree head,
or operator timestamp does not by itself establish:

- conservative trusted UTC under Etzio's time policy;
- fresh multi-namespace revocation state under the pinned TUF policy;
- an independently witnessed latest instance-global and mission head;
- absence of a split view presented by the same operator; or
- Etzio's exact two-stage idempotent registration and recovery contract.

The public Rekor service is not connected by this profile, and private Etzio evidence is
not submitted to it.

## Consequences and required known-bads

- Under the documented SQLite assumptions, schema version 2 can locally validate that
  every retained event from event zero has one modeled finality lineage; version-1 history
  is not relabeled.
- Local event durability and command success become distinct facts.
- The database serializes one finality transition across missions. This intentionally
  favors an auditable recovery invariant over throughput.
- All exact retries converge on one event, one anchor statement, one checkpoint candidate,
  and one finalization record.
- A permanently unavailable or equivocating adapter blocks all later appends until an
  explicit future recovery decision; it does not imply approval or rollback the event.
- Provider latency occurs outside SQLite transactions, although the global protocol
  remains pending until finality.

Known-bad evidence is required for:

- schema/profile substitution, version-1 promotion, and activation after event 0;
- a second global pending transition, including from another mission;
- later-mission global continuity, own-mission genesis, and exact predecessor recovery;
- bypass attempts through each append variant, direct internal append, and generic raw
  replay;
- a facade load attempting to expose or replay an unfinalized event;
- fixture-adapter authority-binding, provider-claim, source, kind, phase, and reference
  substitution;
- enrollment or pending transition without profile bytes and 80 MiB of worst-case finality
  headroom;
- mutation, deletion, phase skipping, phase reordering, or cross-transition splicing;
- the same idempotency key with different bytes or semantics;
- crash before and after each local phase and each modeled protocol write;
- lost provider responses, duplicate delivery, stale responses, and exact reconciliation;
- any adapter invocation while SQLite reports an active transaction;
- SQLite busy, capacity, operational, and corruption failures being mislabeled as adapter
  contract failures;
- cached replay or any writer proceeding after connection-local journal,
  synchronization, foreign-key, trusted-schema, CHECK-enforcement, read-isolation, or
  writable-schema drift;
- time-imprint, nonce, policy, accuracy, certificate, CTT/TTC, or revocation substitution;
- TUF root/version/snapshot rollback, freeze, expiry, and same-version mutation;
- missing inclusion, predecessor consistency, or independent witness/catalog evidence;
- external latest head behind, ahead of, branched from, or equivocal with local history;
  and
- a provider timeout being mistaken for `BUSY`, stale head, success, null, or approval.

## Claim boundary and blocked work

This decision implements only a modeled repository-fixture finality profile. Its two
modeled protocol-write calls terminate in one process-local deterministic service, and
its provider assertions are unsigned code-derived fixture claims. They do not prove
provider authentication, external persistence, independent administration, trustworthy
UTC, current real-world revocation, transparency-log non-equivocation, or provider
availability.

Still blocked:

- selection, connection, credentialing, operation, or qualification of any real TSA, TUF
  repository, SCITT service, transparency log, Rekor deployment, witness, or monitor;
- acceptance of external provider terms, privacy, retention, availability, cost, and
  incident-response policy;
- a production external catalog or anchor storage profile and proof that it survives local
  database loss;
- a durable blocked disposition, reason, and governed recovery decision;
- closure of the same-user SQLite pathname race or coherent offline rewrite boundary
  against a real external latest-head authority;
- SQLite/VFS/filesystem/device, quota, backup/restore, process-kill, and power-fault
  qualification;
- active-active, distributed-writer, multi-region, or failover operation;
- structured independently produced execution evidence and MARCELLUS/CATO isolation; and
- every live-target, egress, credential, spending, disclosure, submission, publication,
  and deployment action.

Logical crash recovery is claimed only under the already documented SQLite
rollback-journal assumptions and deterministic injected failures. It is not power-loss or
production-storage qualification, and it does not turn a modeled verifier receipt into an
execution fact or finding.

## Rejected alternatives

### Add finality only to receipt admission

That would leave authority, target opening, candidate, recovery, refusal, and terminal
events outside the checkpoint chain and permit a database to present a selectively
anchored history.

### Activate finality on an existing stream

Backfilling signatures over current bytes cannot recreate historical trusted time,
revocation freshness, external registration, or latest-head observations.

### Record one mutable pending row

An in-place status update loses the exact sequence of crash-recovery evidence and permits a
later writer to replace the request or provider result being adjudicated.

### Persist pending state before or after the event in a separate transaction

Either order has a crash state in which the event and its recovery dossier disagree.
Protected event bytes and mappings would also lose ADR-0010 atomicity.

### Hold the SQLite writer transaction across provider calls

Provider latency and failure would hold the database-wide write lock, complicate recovery,
and still could not make a remote side effect atomic with SQLite.

### Treat a timeout as failure and issue a new request

The first request may have succeeded. A new identity can create duplicate or conflicting
external history. Recovery must repeat the same semantic request.

### Accept inclusion as finality

Inclusion proves membership in one tree head. It does not prove predecessor consistency,
latest-head status, a shared view, or an independently witnessed global/mission head.

### Use Rekor as the sole time, revocation, anchor, and monitor authority

Combining distinct trust questions behind one service and operator would defeat the
separation that ADR-0008 requires and would still leave trusted-time, revocation-freshness,
and split-view assumptions unproved.
