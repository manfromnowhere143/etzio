# ADR-0019: Qualified evidence lifecycle consumption

- Status: accepted
- Date: 2026-07-31
- Owner: Daniel Wahnich

## Scope correction, 2026-10-09

Review reproduced acceptance of correctly signed qualified evidence for another event,
transition intent, or nonce. The earlier positive pending fixture itself carried a time
bundle for the qualification vector rather than for its consuming decision. Authenticating
packages and comparing their projected hull and floors does not establish this binding.

Qualification must compare service, environment, mission, authority, target, event, and
transition intent between every revocation or head request and its freshly authenticated
time bundle. Derived requests may use their own nonces; that does not permit another scope.
The repository head fixture now takes its service, environment, and validation policy from
its embedded time fixture. Its previous service label named another service. The resulting
profile and corpus identities change by content; no retained profile is rewritten.

At pending admission, the store must freshly authenticate the decision-time bundle and
compare those seven fields, purpose `decision`, and the decision's exact request nonce.
Its imprint is `content_id("qualified_decision_time_imprint_v1", scope)`, where `scope`
contains exactly the decision's service and environment; mission, authority and target;
prior global checkpoint sequence, identity and all three attestation-provenance fields;
prior event sequence and digest; event kind and proposed event digest; transition intent;
request nonce; time policy and decision policy. Time bounds, returned evidence, revocation
views, and the resulting decision identity are excluded to avoid a dependency cycle.
This pins the pre-acquisition request to its consumer and supports deterministic request
reconstruction. The canonical decision schema remains unchanged.

Known-bads use valid signatures and internally consistent qualified bundles with one foreign
scope field, nonce, or imprint. A valid exact-scope control must still append and reconcile.
This correction does not by itself finish checkpoint time consumption, catalog projection
binding, or cold reconstruction from retained packages. Those remain step-6 obligations;
the transient bundles are not proof of durable reauthentication.

## Step-6 implementation contract, 2026-10-09

Status: implemented; both local and GitHub release suites pass `1366` tests. CI run
`37911789236` validates implementation `8b27c42`; see the handoff for release evidence.
Before this tranche, the three record positives were partial: anchor time was unsigned, transient bundles disappeared
on serialization, and replay did not reconstruct provider requests. The following contract
now governs the service and store; the earlier implementation sequence below remains a
historical record and does not override this reconstruction requirement.

### Deterministic requests and explicit genesis

The fixture lifecycle uses the permanently enrolled time and head profiles. Both must name
the enrolled service and environment and exactly match its validation policy. Enrollment
and cold replay check canonical profile bytes and their indexed identities. No provider
connection or independently administered authority is implied.

Decision-time requests use the scope correction above. Checkpoint-time requests use the
same decision scope and nonce, purpose `checkpoint`, and imprint
`content_id("qualified_checkpoint_time_imprint_v1", {"pending_record_id": pending.record_id})`.
The pending record is already committed when checkpoint time is acquired; using its identity
avoids a cycle through the anchor statement that will contain the returned time evidence.

Derived nonces are the 64 lowercase hexadecimal characters of these content identities:

| Request | Content-identity domain | Exact body |
|---|---|---|
| Revocation | `qualified_fixture_revocation_request_v1` | `namespace`, `time_bundle_id` |
| Anchor | `qualified_fixture_anchor_request_v1` | `anchor_statement_id`, `time_bundle_id` |
| Catalog and its monitors | `qualified_fixture_catalog_request_v1` | `phase` (`prior` or `current`), `time_bundle_id`, `checkpoint_id` |

The `checkpoint_id` in a prior catalog request is the retained global predecessor's identity;
in a current request it is the newly retained candidate's identity. Every request also binds
its exact profile, source, mission, authority, target, event, transition intent, and the typed
predecessor fields required by its adapter contract.

Revocation predecessors come from the previous global pending record's exact namespace
floors. Empty history uses root/version zero and
`content_id("qualified_fixture_revocation_genesis_v1", {"profile_id": time_profile.profile_id,
"namespace": namespace})`. The repository fixture advances metadata version with the global
transition, retaining unanimous configured metadata and floor witnesses.

Each fixture log starts with one fixed genesis leaf: canonical bytes containing exactly
`leaf_schema` = `etzio.qualified-fixture-log-genesis.v1`, the head `profile_id`, enrolled
`source_id`, and `log_origin`. Its RFC 9162 leaf hash is the initial root at tree size one.
Each transition appends one leaf per anchor log, making its prior tree size
`instance_sequence + 1`. The catalog appends a prior-head projection before pending admission
and a current-head projection after checkpoint publication. Its prior root/size always come
from the preceding qualified catalog observation, starting at the explicit genesis leaf.

Qualified catalog requests and fixture heads admit sequence `-1` only for the corresponding
domain-separated global or mission genesis identity, with absent attestation provenance.
They reject smaller sequences, invented genesis identities, mixed provenance, and a mission
head ahead of the global head. `HeadCheckpointFloorV1` already carries this protocol meaning;
the adapter path must preserve it. Genesis observations still require signed qualified
catalog and monitor packages; there is no unsigned-provider fallback.

### Reconstruction and authority

A separate lifecycle reconstruction module rebuilds requests from canonical phase records,
the pinned profiles, and validated predecessor context. It selects exact retained package
BLOBs by typed evidence references, authenticates the outer signed packages before consuming
inner claims, reruns time/revocation/anchor/catalog qualification, and compares every claimed
mapping with the freshly derived result. Unreferenced, missing, substituted, wrongly scoped,
or invalidly signed packages refuse. The same reconstruction governs admission and cold
replay, including an unresolved transition.

Each lifecycle anchor is the last leaf of exactly one append to its validated predecessor
log. Reconstruction derives that predecessor's append frontier and recomputes the new root;
an inclusion proof in a disconnected, same-size or unrelated log is insufficient.

Transient bundles become optional non-authoritative inputs. When supplied, including on an
idempotent retry, they must freshly authenticate and agree with independent reconstruction;
their absence after serialization is valid. Replay never
calls a provider, accesses staging, reads an ambient clock, or falls back to unsigned content.
Unsupported interim qualified records refuse; no historical profile or evidence is rewritten.

The qualified anchor record must retain signed checkpoint-time packages. Its qualified mode
is explicit in its canonical bytes; the legacy modeled form keeps its existing bytes and
identity. Redundant modeled tags and mixed-mode lineages refuse. The store verifies the
checkpoint time's scope, purpose, nonce, imprint, complete hull, policy, and evidence against
the actual pending and anchor before accepting the phase. The checkpoint then uses that
same authenticated anchor time.

The store's private replay path reads and validates qualified profiles without recursively
calling its public validation entrypoint. Provider reconstruction stays inside that trusted
store boundary; provider acquisition remains outside SQLite transactions. A service can
propose signed fixture evidence but cannot select or downgrade the store's enrolled mode.

### Service and restart

The qualified fixture service may compose the existing modeled signer and catalog state
machine. It emits signed packages for every provider claim, including prior head floors,
and leaves kernel decision/checkpoint authority checks intact. A point interval at the
fixture event's declared time is permitted; it is simulated time, never trustworthy UTC.

Qualified anchor registration receives the exact pending record explicitly. The retained
anchor alone lacks the decision's transition intent and nonce and cannot serve as an
implicit process cache. Finalization keeps the existing floor-plus-package service result;
the facade selects the enrolled mode and the store reconstructs the qualified evidence.

The fixture service may reconstruct an append frontier from a verified last-leaf inclusion
proof, its leaf, root, and size. Such a mathematical state carries no authentication or
latest-head authority. Appending must reproduce the same RFC 9162 root, inclusion proof, and
consistency proof as the independent full-tree implementation. This permits deterministic
restart without retaining an entire simulated provider log in process memory.

The construction invariant is the binary partition of a tree of size `n`: its retained
peaks are the roots of complete subtrees in decreasing size order, with exactly
`popcount(n)` peaks. Right-folding their hashes gives the RFC root. A last-leaf proof first
climbs the rightmost complete subtree for `v2(n)` levels (the number of trailing zero bits);
its remaining siblings recover the preceding peaks in reverse order. Appending is binary
addition: combine equal-size rightmost subtrees while carrying, then retain the resulting
peak. Each operation uses `O(log n)` hashes and bounded state. The implementation verifies
the inclusion proof before recovery and checks the reconstructed root again. This is a
construction argument, supported by the `512`-size differential test and refusal cases;
it is not a machine-checked proof or evidence of an honest provider.

The exact-one-append arithmetic and fixed genesis leaves belong to this repository-fixture
lifecycle contract. They are not a universal layout for a shared external transparency log.
A native-provider profile must separately specify its request, predecessor, cursor and
restart semantics and retain the required inclusion, consistency and latest-head authority
proofs. A fixture profile cannot authorize that change by substitution.

Required evidence includes the complete `authority_admitted` to
`verifier_receipt_admitted` vertical; interleaved missions; fresh-process and fresh-service
recovery without transient bundles or staging; byte-identical retry around every phase and
protocol write; invalid signatures and validly signed foreign scope on cold replay; profile
and mode substitution; and preserved governed-recovery, store-error, and unresolved-barrier
behavior. Power loss, independent administration, external durability, real UTC, execution,
finding validity, and live-target authority remain separate gates.

## Context

ADR-0018 built the complete acceptance-primitive layer — anchor, revocation,
and head floor — each freshly reauthenticating a qualified signed bundle and
accepting a claim only as the exact signed packages. Nothing consumes it. The
modeled finality service still produces unsigned code-derived assertions and
the four record constructors still validate provider evidence by byte-equality
against `_modeled_provider_content`.

Making the lifecycle consume qualified signed evidence touches the two largest
and most safety-critical modules in the repository (`store.py`,
`integrity_transition.py`) and changes record identities and the SQLite schema.
It is therefore specified in full here, and implemented as a sequence of small
dependency-complete tranches, before any of that code is touched — the same
discipline by which ADR-0012 specified qualification before ADR-0015 persisted
it.

## The hard question: where does reauthentication happen

The acceptance primitives need the full qualified bundles (requests plus signed
packages), not only the signed-package BLOBs a record already carries. Two
architectures resolve this:

- **Retain whole bundles in each record.** Rejected. It bloats every record
  with request bytes and makes `record_id` depend on the entire bundle.
- **Re-derive requests, reauthenticate from retained scope plus packages.**
  Chosen. Every qualification `request_id` is `content_id` over the request's
  exact scope semantics, so a request is deterministically re-derivable from
  the mission, authority, target, event, transition, nonce, and profile the
  record already retains. In qualified mode a record's `provider_evidence`
  BLOBs *are* the exact signed packages; the validator re-derives the requests,
  rebuilds the bundles, and calls the ADR-0018 primitives.

The trust root is pinned once at enrollment, exactly like the modeled authority
binding, rather than per record.

## Decision

### Schema version 4: a profile-selected acceptance mode

`store_profile` gains an `acceptance_mode` of exactly
`modeled_unsigned_code_derived` or `qualified_signed_fixture`, and, for the
qualified mode only, retains the exact qualified time-adapter and
head-authority trust profiles as wire BLOBs — following the existing
`validation_policy_wire` / `authority_binding_wire` pattern. A `user_version`
3→4 migration adds the columns; it adds columns only and backfills nothing,
because an existing enrolled store has no qualified profile to invent.

Enrollment of the qualified mode is empty-history only, and permanent, exactly
like the modeled profile. A legacy or modeled-unsigned store never silently
acquires a qualified mode.

### The modeled service produces signed-package evidence

In qualified mode, `RepositoryOwnedDeterministicModeledIntegrityServiceV1`
runs the qualification harnesses (time, revocation, anchor, catalog, monitor)
to produce qualified bundles, and uses their signed packages as each record's
`provider_evidence` and their qualified `RevocationFloorV1`,
`HeadCheckpointFloorV1`, and anchor references as the record's floors and
references. The unsigned code-derived path is untouched and remains the default.

### The record validators branch on mode

Each of the four constructors gains a mode-selected provider-evidence check:

- `modeled_unsigned_code_derived` — the exact ADR-0011 gate, unchanged.
- `qualified_signed_fixture` — re-derive the requests from retained scope,
  rebuild the bundles from the retained signed packages, and call the matching
  ADR-0018 primitive:
  - `PendingIntegrityTransitionV1` → `accept_qualified_revocation_evidence_v1`;
  - `CheckpointCandidateRecordV1` → `accept_qualified_anchor_evidence_v1`;
  - `FinalizedIntegrityTransitionV1` → `accept_qualified_head_floor_evidence_v1`.

The `anchor_statement` phase reuses the same time evidence as the checkpoint.

This resolves the two Side-A couplings the seam audit flagged. In qualified
mode the `RevocationFloorV1.snapshot_id` is whatever the qualified bundle
authenticated, not the digest of an unsigned metadata blob, and the
`fixture.revocation-metadata` source identity replaces the modeled
`fixture.revocation`, because the evidence now comes from the harness roster.

### Everything else is preserved

The qualified mode changes only which provider-evidence gate runs. It preserves
every ADR-0012 integration requirement: empty-history activation,
event-plus-pending atomicity, all four immutable phases, the database-global
barrier, byte-identical at-least-once retry, provider calls outside SQLite
transactions, exact global and mission continuity, generic pending-replay
refusal, store-domain error classification, and every governed
blocked-finality guarantee. The signed decision and checkpoint remain the only
real cryptography over the kernel's own records; qualified mode adds
authenticated provider evidence, it does not remove the decision/checkpoint
signatures.

## Layering correction: verification lives at the store, not the record

Implementing step 2 surfaced a constraint the original design glossed. A record's
`__post_init__` is context-free — it holds only its own bytes. It therefore *cannot*
reauthenticate qualified evidence, because reauthentication needs the enrolled trust roots
(the qualified time and head-authority profiles), and those live in the store's
schema-version-4 `integrity_acceptance_profile`, never in the record.

Consumption is therefore split:

- the **store** owns reauthentication. `verify_qualified_anchor_evidence` loads the enrolled
  qualified profiles and drives `accept_qualified_anchor_evidence_v1`, which reauthenticates
  the retained bundle from its signed packages before accepting the checkpoint's claimed
  anchor statement, references, and BLOBs. A store with no qualified acceptance profile
  refuses with `IntegrityFinalityRequiredError` — it never silently falls back to the
  unsigned modeled gate; and
- the **record** (step 3, now implemented) carries `acceptance_mode` and, in qualified mode,
  does only the content-agnostic coverage and kind checks, trusting the store to have
  reauthenticated. The record retains the sealed qualified bundles its phase needs so the
  store can rebuild and reauthenticate them; because those bundles are sealed and
  non-serializable, they ride as transient, equality-excluded fields that never enter the
  record's `record_id` or canonical bytes, and the store reads them from the freshly
  submitted record rather than from any reloaded copy.

Step 2 implements the store side: the first lifecycle consumption of qualified signed
evidence, driven by the enrolled roots, gated by qualified enrollment, with adversarial
refusals for a modeled-only store, a legacy store, a foreign-root bundle, a tampered claim,
and unsigned content. Step 3 wires the anchor-phase record into that store consumption; the
positive end-to-end acceptance of a fully coherent qualified lineage arrives with the
qualified-mode service (step 6), because the modeled service does not yet emit a checkpoint
statement the qualified bundle authenticates.

## Implementation sequence

Each step is its own dependency-complete tranche with `make verify` green on
both runtimes and CI reproduction:

1. **Schema-v4 enrollment.** *(Implemented.)* Add the qualified-profile store
   relation, the 3→4 migration, empty-history qualified enrollment, capacity
   accounting, and known-bads. Mirrors ADR-0015 preceding ADR-0016.
2. **Anchor-phase store consumption.** *(Implemented.)* The store's
   `verify_qualified_anchor_evidence` drives `accept_qualified_anchor_evidence_v1`
   from the enrolled roots; a non-qualified store refuses.
3. **Anchor-phase record wiring.** *(Implemented.)* `CheckpointCandidateRecordV1`
   carries `acceptance_mode` (a content field that changes its `record_id` and
   canonical bytes) and, in qualified mode, carries the sealed qualified anchor
   and time bundles as transient, non-serialized, equality-excluded fields —
   they never enter `record_id` or canonical bytes, because the bundles are
   sealed, non-serializable runtime objects. The record's `__post_init__`
   branches on the mode: the modeled-unsigned gate is unchanged; the qualified
   gate is content-agnostic coverage plus a head-anchor-receipt kind check,
   trusting the store to reauthenticate. `retain_integrity_checkpoint_candidate`
   cross-checks the record's declared mode against the enrolled acceptance
   profile before any lineage work, requires the sealed bundles in qualified
   mode, and — after lineage validation — calls
   `verify_qualified_anchor_evidence` to reauthenticate the checkpoint's claimed
   anchor statement, references, and signed-package blobs under the enrolled
   roots. It never falls back to the modeled gate. The qualified checkpoint
   positive is proved end to end in `tests/test_qualified_finality_lineage_v1.py`
   on a coherent pending+anchor+checkpoint lineage: `prepare_checkpoint_candidate`
   gained optional `acceptance_mode`/`anchor_bundle`/`time_bundle` parameters
   (modeled path byte-identical), and the qualified anchor bundle is scoped to the
   modeled anchor's derived statement identity — the anchor adapters build Merkle
   leaves dynamically and recompute a genuine RFC 9162 inclusion proof, so the
   bundle authenticates the exact leaf the lineage claims.
4. **Revocation-phase consumption.** *(Implemented.)* `PendingIntegrityTransitionV1`
   carries `acceptance_mode` and, in qualified mode, transient sealed time and
   revocation bundles (same non-serialized, equality-excluded discipline as the
   checkpoint record). Its `__post_init__` branches on the mode: the modeled-unsigned
   gate is unchanged; the qualified gate is content-agnostic coverage plus an
   evidence-kind check (trusted-time, revocation-metadata, or external-floor).
   `append_pending_integrity_event` cross-checks the declared mode against the enrolled
   acceptance profile before any append work and, in qualified mode, requires the sealed
   bundles and calls `store.verify_qualified_revocation_evidence`, which drives
   `accept_qualified_revocation_evidence_v1` over the decision's time,
   revocation-metadata, and revocation-floor evidence (partitioned out of the record's
   full provider evidence by exact evidence identity; the predecessor head-floor evidence
   a pending also carries is the finalization phase's concern). Because the append verify
   runs before the append transaction, this needs no lineage. The snapshot-identity
   coupling and the `fixture.revocation` → `fixture.revocation-metadata` source rename are
   resolved automatically because qualified mode consumes the primitive instead of the
   modeled gate. The positive is proved end to end: a coherent qualified pending — built by a
   profile-aligned modeled service (its service, environment, and policy taken from the
   qualified time roots) with the qualified time hull, evidence, views, and floors swapped
   into the decision — appends, is retained, and replays idempotently. That construction is
   the seed of the step-6 qualified-mode service.
5. **Head-floor-phase consumption.** *(Implemented.)* `FinalizedIntegrityTransitionV1`
   carries `acceptance_mode` and, in qualified mode, transient sealed head-catalog
   and time bundles (same discipline as the other records). Its `__post_init__`
   branches: the modeled gate is unchanged; the qualified gate is content-agnostic
   coverage plus an external-floor kind check. `finalize_integrity_transition`
   cross-checks the declared mode against the enrolled profile before any lineage
   work and, in qualified mode, requires the sealed bundles and calls the new
   `store.verify_qualified_head_floor_evidence`, which drives
   `accept_qualified_head_floor_evidence_v1` — rerunning the RFC 9162 consistency
   check and unanimous monitor agreement — before committing finality. The record
   and store-verify wiring, the mode cross-check both ways, the bundle-presence gate,
   and a live foreign-head-floor reauthentication refusal are proved on the coherent
   lineage. The end-to-end *positive* is deferred to the step-6 service: the fixed
   fixture catalog head cannot be scoped to a produced checkpoint (unlike the anchor's
   dynamic leaves), so a full facade-driven qualified vertical that emits a catalog
   head matching its own checkpoint is required.
6. **Qualified fixture service and crash recovery.** *(Implemented; both runtimes pass `1366` tests
   locally and in GitHub, 2026-10-09; implementation `8b27c42`.)*
   `RepositoryOwnedQualifiedFixtureIntegrityServiceV1` composes the
   modeled kernel signer/catalog core with signed fixture providers. The separate
   `qualified_lifecycle_v1` module reconstructs all four phases from canonical bytes and
   exact enrolled roots inside store admission and cold replay. The full receipt path,
   interleaved missions, fresh-process reconstruction, interruption matrix, concurrent
   recovery and coherent offline provider-forgery controls exercise this path. Transient
   bundles are optional and cannot replace retained evidence. No schema migration is
   needed; unsupported interim qualified bytes refuse rather than being rewritten.

## Claim boundary

This decision is implemented by the qualified fixture service, store reconstruction and
its retained tests. Release status is recorded in the handoff. It establishes consumption
of authenticated signed fixture evidence under a permanently enrolled qualified profile. It does
not establish trustworthy UTC, current real-world revocation, real head
non-equivocation, independently administered providers, external durability,
execution, a finding, or live-target authority. The qualified profiles are
repository-owned roots; distinct labels and keys prove no independent operators.
Connecting an independently administered provider remains a separate gate with
its own admitted grant.

## Rejected alternatives

### Retain whole bundles in each record

Bloats records and couples `record_id` to request bytes. Re-deriving requests
from retained scope is exact because `request_id` is `content_id` over that
scope.

### One gate that accepts either content shape

A single gate that accepts unsigned content or a signed package lets a caller
choose the discipline per event. The mode is fixed by the enrolled profile and
the two gates stay mutually exclusive, per ADR-0018.

### Wire all four phases in one tranche

Each phase has distinct coupling. Sequencing them isolates each change to the
crown-jewel state machine and keeps every tranche independently verifiable.

### Implement before specifying

Changing record identities and the SQLite schema across two 175-plus-KB modules
without a settled design would blur a migration with the consumption contract —
the exact mistake ADR-0012 avoided by specifying qualification before ADR-0015
persisted it.
