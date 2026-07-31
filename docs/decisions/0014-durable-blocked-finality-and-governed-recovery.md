# ADR-0014: Durable blocked-finality disposition and governed recovery

- Status: accepted
- Date: 2026-07-31
- Owner: Daniel Wahnich

## Context

ADR-0011 makes modeled integrity finality crash-safe through four immutable
append-only local phases and one database-global unresolved-transition barrier.
It deliberately stops short in one place, and says so explicitly:

> Invalid deterministic adapter evidence raises a typed
> `IntegrityFinalityBlockedError` for that attempt and leaves the same phase
> unresolved; schema version 2 does not durably retain a blocked classification
> or reason.

The retained bytes confirm this. `IntegrityFinalityBlockedError` is an
exception class with one `reason_code` string attribute. It is constructed and
re-raised, never serialized, has no `record_id` and no `to_body`, and appears
zero times in `etzio/kernel/store.py`. No integrity table has a blocked column,
and `integrity_transition_evidence.phase` is `CHECK`-constrained to the four
success phases only.

`ModeledIntegrityFinalizingEventStoreV1._recover_lineage` therefore chooses its
resume point purely by testing `lineage.anchor_statement is None`,
`checkpoint_candidate is None`, and `finalization is None`. A blocked attempt
leaves those rows byte-identical, so the next attempt re-enters at the same
phase and repeats the same adapter calls with no memory of the prior block.

Three consequences follow:

- an operator cannot distinguish "not attempted yet" from "attempted many times
  and deterministically refused", because the only durable trace of an
  unresolved transition is the absence of a row in `integrity_finalizations` —
  an untyped, reasonless bit;
- there is no retained, authenticated statement of *why* finality stopped, so
  nothing can be audited or adjudicated after the fact; and
- there is no governed way to decide what happens next, so the only available
  behaviours are "retry forever" or "operate on the database outside its own
  contract".

The third is the dangerous one. Without an explicit contract, the pressure to
resolve a stuck database is pressure to delete a phase row, forge a
finalization, or rewrite the retained event. Any of those would silently
release the barrier and corrupt the instance-global sequence, because
`integrity_pending_require_next_global` derives the next sequence from
`count(*)` over `integrity_finalizations`.

This decision specifies the durable blocked state and its governed recovery
authority. Following the ADR-0012 and ADR-0013 pattern, it proves the contract
deterministically and networklessly first. It does not change the SQLite
schema, the lifecycle state machine, or any store method in this tranche.

## Decision

Etzio implements the V1 contract in `etzio/kernel/blocked_finality_v1.py`. It
reuses the established shape exactly: closed canonical records, exact copied
profiles, role-separated Ed25519 signatures, authentication before claim
interpretation, sealed results, fresh reauthentication, and a kernel-owned
deterministic harness bound by a content-addressed corpus manifest.

Three principles govern the whole contract.

**A block is an observation, not a resolution.** Recording that an attempt was
refused must never advance, release, or weaken anything. The retained event,
the four phases, and the barrier are untouched.

**Recovery is authorized, not inferred.** No amount of retrying, elapsed time,
or repeated blocking may by itself change the disposition of a transition. A
change requires an exact signed decision from a principal that is separate from
the ones that sign integrity decisions and head checkpoints.

**No disposition may manufacture finality.** There is no admissible outcome in
which a blocked transition becomes finalized without its checkpoint. The
contract offers exactly two dispositions, and neither one mints a checkpoint,
deletes a phase, rewrites an event, or releases the barrier for the blocked
event.

## Durable blocked observation

`BlockedFinalityObservationV1` is one closed canonical record with the exact
fields:

- `contract_version`, `profile_id`, `trust_root_id`;
- `service_instance_id`, `environment_id`;
- `mission_id`, `authority_id`, `target_id`;
- `event_digest`, `event_seq`, `instance_sequence`;
- `pending_record_id`;
- `unresolved_phase`;
- `unresolved_phase_record_id`;
- `blocked_operation`;
- `blocked_reason_code`;
- `attempt_ordinal`;
- `time_bundle_id`, `time_lower_bound`, `time_upper_bound`, `time_policy_id`,
  `time_evidence`; and
- `observation_id`, derived from the complete record semantics.

`unresolved_phase` is one of exactly `local_pending`,
`anchor_statement_ready`, or `checkpoint_candidate_retained`. The fourth
lineage phase, `finalized`, is deliberately not admissible: a finalized
transition is resolved, so a blocked observation naming it is a contradiction
and is refused rather than retained.

`unresolved_phase_record_id` names the exact identity of the highest retained
immutable phase record, so an observation is bound to the lineage it actually
described. If a later attempt advances the lineage, the earlier observation no
longer matches and cannot be presented as current.

`blocked_operation` is one of exactly `prepare_anchor_statement`,
`register_anchor_statement`, `prepare_checkpoint_candidate`,
`publish_checkpoint`, `observe_current_floor`, `recover_lineage`, or
`propose_transition`. `blocked_reason_code` is a closed set taken from the
reason codes the implemented recovery path actually produces:
`modeled_anchor_scope_mismatch`, `modeled_anchor_equivocation`,
`modeled_anchor_sequence_conflict`, `modeled_catalog_global_conflict`,
`modeled_catalog_mission_conflict`, `modeled_checkpoint_identity_conflict`,
`modeled_catalog_compare_and_set_failed`,
`modeled_integrity_adapter_contract_failure`,
`modeled_integrity_retry_conflict`, and `invalid_integrity_event`.

A retryable uncertain outcome is not a block. `IntegrityFinalityPendingError`
and every `EventStoreError` classification keep their existing domains and
produce no observation, because turning SQLite contention or an ambiguous
provider response into a durable trust failure would be a false record.

`attempt_ordinal` is a positive integer that strictly increases per transition.
Observations are append-only. Two observations sharing one transition and
ordinal but differing in any other field are equivocation and are refused; an
ordinal that regresses or repeats an existing body is likewise refused. The
observation carries no mutable status and no resolution field.

Observation time comes only from a freshly reauthenticated ADR-0012 qualified
time hull. A local clock never records when finality stopped.

## Governed recovery decision

`GovernedRecoveryDecisionV1` is the only thing that can change a blocked
transition's disposition. It binds:

- contract, profile, and trust-root identities;
- service instance, environment, mission, authority, and target;
- `event_digest` and `pending_record_id`;
- the exact `blocked_observation_id` **and** the complete observation binding it
  claims to answer: `unresolved_phase`, `unresolved_phase_record_id`,
  `blocked_operation`, `blocked_reason_code`, and `attempt_ordinal`;
- `disposition`;
- `recovery_policy_id` and `recovery_principal_id`;
- one 256-bit nonce;
- the qualified time bundle, hull, policy, and evidence; and
- `decision_id`, derived from the complete decision semantics.

Restating the complete observation binding inside the signed decision is
deliberate. A decision that carried only an opaque `observation_id` could be
signed against a summary the signer never saw. Restating the binding means the
signature covers the exact claim being authorized, and a decision cannot be
moved onto a different block, a different phase, or a different reason.

The decision is signed with the dedicated domain
`etzio.blocked-finality.governed-recovery.signature.v1\x00`, distinct from
every integrity, adapter, and head-authority domain, so no other signed
artifact can be replayed into a recovery authorization.

### Role separation

`BlockedFinalityRecoveryProfileV1` copies the enrolled
`ModeledIntegrityAuthorityBindingV1` and adds the recovery key and principal.
V1 requires that the recovery key differ from both the decision and checkpoint
keys, **and** that the recovery principal differ from both the decision and
checkpoint principals.

Requiring both is the point. A separate key held by the same principal is key
rotation, not separation of duty; the party that signs integrity decisions must
not also be able to authorize its own recovery from a block those decisions
caused. The recovery key must also be present in the enrolled trust store and
carry the recovery role there, so a profile cannot introduce an authority the
enrollment never admitted.

### Admissible dispositions

Exactly two, and both are closed:

**`retry_authorized`.** The transition may be re-attempted from its exact
retained phase. The barrier remains held. Nothing is deleted, rewritten, or
finalized, and no checkpoint is minted. The decision must name the current
unresolved phase and its exact record identity; a decision naming a stale phase
is refused, because the lineage it authorized retrying no longer exists.

**`instance_sealed`.** The service instance is terminally sealed. The barrier
is never released, no further pending transition may open, and no lifecycle
command may succeed on this database. The complete retained history remains
readable for audit and migration.

Sealing is the honest terminal outcome. When finality genuinely cannot advance,
the alternatives are to fabricate a checkpoint or to keep an unbounded queue of
failing retries. V1 does neither: it fences the instance off, records exactly
why, and leaves every retained byte intact and inspectable. A sealed instance is
migrated by standing up a new one, not by rewriting this one.

`instance_sealed` is terminal in the strong sense. After a seal, no further
observation and no further decision — including another seal — is admissible
for that instance. Re-sealing would imply the seal was a status that could be
revisited.

There is deliberately no `force_finalize`, `discard_transition`,
`rewind_phase`, or `release_barrier` disposition. Each of those would require
deleting or contradicting an immutable record, and each is listed among the
rejected alternatives below.

## Resolution results and barrier interaction

`BlockedFinalityResolutionV1` is the sealed result of applying an authenticated
decision to an authenticated observation. It retains the exact observation,
decision, signed bytes, and provider-neutral evidence, and exposes:

- `disposition`;
- `resume_phase`, which is the exact retained phase for `retry_authorized` and
  `None` for `instance_sealed`;
- `barrier_released`, which is **always** `False`; and
- `instance_sealed`, which is `True` only for the sealing disposition.

`barrier_released` exists as an explicit retained field precisely so that the
invariant is visible and testable rather than implicit in the absence of code.
There is no code path in the contract that sets it `True`, and a known-bad
asserts that no admissible disposition produces a released barrier.

This is the contract's central safety property. Under ADR-0011 the barrier is
enforced both by `_unresolved_integrity_digest_locked` and by the
`integrity_pending_reject_open_transition` and
`events_reject_while_integrity_pending` triggers, and the next instance-global
sequence is derived from `count(*)` over `integrity_finalizations`. A
disposition that released the barrier without a finalization row would leave
the sequence counter and the retained lineage permanently disagreeing.

## Deterministic repository-owned harness

`create_repository_owned_blocked_finality_fixture_v1` deterministically derives
role-separated fixture keys, the enrolled authority binding, the recovery
profile, an ordered observation roster, one qualification vector, an
adapter-implementation label, and a content-derived corpus-manifest identity
from a bounded seed. It reuses the ADR-0012 time fixture, so every observation
and decision is timed by a genuinely qualified hull rather than a constant.

`qualify_repository_blocked_finality_v1` executes a fixed case roster covering
observation retention and byte-stable retry, refusal of an observation naming
the finalized phase, refusal of ordinal equivocation, authorized retry,
refusal of a decision moved to another observation, refusal of a decision
signed by the integrity-decision and head-checkpoint principals, sealing, and
refusal of every further action after a seal.

The manifest binds every deterministic input that can affect a case, so
changing an observation, ordinal, reason, phase, key, principal, or case roster
changes the manifest identity.

## Claim boundary and deferred integration

This contract and harness establish only that:

- a blocked finality attempt has an exact, closed, content-addressed
  representation naming its transition, phase, operation, reason, and ordinal;
- observation time comes from an authenticated qualified hull;
- a disposition change requires an exact signed decision from a principal and
  key separated from both integrity-decision and head-checkpoint authority;
- the signed decision covers the complete observation binding, not an opaque
  identity;
- exactly two dispositions are admissible, neither of which finalizes, deletes,
  rewrites, or releases the barrier; and
- a sealed instance admits no further observation or decision.

They do not establish:

- durable persistence, since no SQLite table, schema version, migration, or
  store method changes in this tranche;
- crash-recovery behaviour of the retained blocked record, which belongs to the
  storage tranche;
- independently administered or externally custodied recovery authority, since
  the fixture keys are repository-owned;
- operator identity, authorization workflow, dual control, or audit delivery;
- that a sealed instance's history has been migrated or preserved elsewhere; or
- execution, independent verification, a finding, or live-target authority.

Integrating the durable record requires its own tranche, and the retained bytes
make its cost explicit. Adding an append-only blocked table requires new DDL in
`_integrity_schema_sql`, new entries in `_validate_schema`'s `required_objects`
(the table plus its append-only triggers), a recomputed
`_SQLITE_SCHEMA_CONTRACT_SHA256`, and a `user_version` 3 migration from the
exact version-2 layout, because `_validate_schema` compares object sets for
equality and therefore fails closed on extra objects. That tranche must also:

- add the recovery key and principal to the enrolled authority binding, which
  changes `ModeledIntegrityAuthorityBindingV1` and its `binding_id`;
- charge the new record's bytes in `_logical_evidence_storage_used_locked`; and
- widen `_INTEGRITY_FINALITY_CAPACITY_RESERVE_BYTES_V1`, since the current
  80 MiB reserve is exactly four 16 MiB phase records plus 16 MiB of transition
  evidence and is taken once, before the pending row is inserted.

It must preserve empty-history activation, event-plus-pending atomicity, all
four immutable phases, the database-global barrier, byte-identical
at-least-once retry, provider calls outside SQLite transactions, exact global
and mission continuity, generic pending-replay refusal, and store-domain error
classification. In particular, the durable write path must not be funnelled
through `_call_modeled_integrity_adapter` or `_advance_finality`, or a failure
to persist the blocked record would itself be reclassified as an adapter
contract failure.

## Consequences

- "Stuck" becomes a typed, reasoned, content-addressed state instead of the
  absence of a finalization row.
- Recovery becomes an authorized act with a retained signature and an exact
  scope, rather than an operational intervention outside the contract.
- Separation of duty is enforced by both key and principal, so the authority
  that caused a block cannot authorize its own escape from it.
- A genuinely unrecoverable instance has an honest terminal outcome that never
  fabricates finality.
- Strict all-or-nothing sealing prefers fail-closed auditability over
  availability. A future partial-quarantine or per-mission fencing policy
  requires a new explicit contract version.

## Rejected alternatives

### Record blocked state as a mutable status column

Every integrity table is append-only by trigger, and ADR-0011 already rejected
"one mutable pending row". A mutable status is exactly the surface an operator
under pressure would edit. Append-only observations with strictly increasing
ordinals retain the whole history of what was tried.

### Let repeated blocking auto-escalate to a terminal state

Time and repetition are not authority. An adapter that is misconfigured for an
hour and one that is permanently broken produce the same sequence of blocks;
only an external decision can tell them apart.

### Offer a `force_finalize` disposition

Finality means a checkpoint exists and its lineage validates. A disposition
that declares finality without one would make every downstream continuity
check, including the instance-global sequence derived from
`count(*)` over `integrity_finalizations`, disagree with the retained lineage.

### Offer a `discard_transition` disposition that deletes the pending rows

The local event is already durable, and ADR-0011 forbids deleting or rewriting
it because an adapter is unavailable. Deletion would also break the foreign-key
chain from anchor statement through finalization.

### Release the barrier on seal to keep the database usable

The barrier is what prevents a later event from extending a head that was never
finalized. Releasing it on seal would let new work build on an unfinalized
history, which is the exact failure the barrier exists to prevent. A sealed
instance is intentionally unusable for new work.

### Sign the decision over only the observation identity

An opaque identity lets a signer authorize a summary it never saw. Restating
the complete observation binding makes the signature cover the exact phase,
operation, reason, and ordinal being authorized.

### Reuse the integrity-decision key for recovery, or a new key under the same principal

A separate key under the same principal is rotation, not separation of duty.
The party whose decisions produced a block must not be able to authorize
recovery from it.

### Persist the blocked record inside the existing finality tranche

The storage change requires a schema version bump, an enrollment shape change,
capacity-reserve rework, and its own crash-recovery known-bads. Proving the
acceptance contract first, as ADR-0012 and ADR-0013 did, keeps qualification
separate from authority and keeps each tranche dependency-complete.
