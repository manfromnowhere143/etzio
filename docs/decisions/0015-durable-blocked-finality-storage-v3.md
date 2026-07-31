# ADR-0015: Schema-version-3 durable blocked-finality storage

- Status: accepted
- Date: 2026-07-31
- Owner: Daniel Wahnich

## Context

ADR-0014 specifies the durable blocked-finality observation, the role-separated
governed recovery decision, and the exactly two admissible dispositions. It
proves the acceptance contract deterministically and networklessly, but it
persists nothing: no SQLite table, schema version, migration, or store method
changes there. A blocked attempt therefore still leaves no durable trace, and
the recovery authority has nowhere to be enrolled.

This decision adds the storage layer. It is deliberately layout-only: it does
not change when a block is produced, does not make the recovery path consume a
decision, and does not alter the four immutable finality phases or the
database-global barrier.

## Decision

Schema version 3 adds three append-only integrity relations and one migration.
The Etzio SQLite `application_id` remains `0x45545A31`.

### The recovery authority is a separate relation

The obvious move — adding a recovery key and principal to
`ModeledIntegrityAuthorityBindingV1` — is rejected. That record's
`binding_id` is derived from its complete canonical body, so extending it
would change every existing binding identity, invalidate the retained
`store_profile.authority_binding_wire` of any enrolled database, and force
every binding known-bad to be rewritten. The authority binding is also
conceptually finished: it pins who signs integrity decisions and head
checkpoints, and ADR-0014 requires the recovery authority to be separate from
exactly those two.

V1 therefore enrolls `BlockedFinalityRecoveryProfileV1` in its own singleton
`integrity_recovery_profile` relation. The profile already copies the enrolled
authority binding and enforces separation of duty by key and principal, so the
two records stay cross-checked without either one containing the other.

### Exact relations

`integrity_recovery_profile` is a singleton holding the exact canonical profile
wire and its derived `recovery_profile_id`. It admits one insert and refuses
update and delete.

`integrity_blocked_observations` is keyed by `(event_digest, attempt_ordinal)`
with a `UNIQUE` `observation_id` and the exact canonical record BLOB. Ordinals
are per transition, so the primary key expresses the append-only ordinal
sequence directly. Update and delete are refused by trigger.

`integrity_recovery_decisions` is keyed by `decision_id`, carries the exact
signed-decision BLOB, the `disposition`, and a `blocked_observation_id`
foreign key into `integrity_blocked_observations`. Update and delete are
refused by trigger.

There is no seal table. A sealed instance is exactly the existence of a row in
`integrity_recovery_decisions` whose `disposition` is `instance_sealed`.
Deriving the seal rather than duplicating it removes the possibility of the
two disagreeing.

### SQL-level invariants

Four triggers enforce ADR-0014's semantics in the database, not only in
Python, so a caller that bypasses the store API still fails closed:

- `integrity_blocked_reject_finalized` refuses an observation whose
  `event_digest` already has a row in `integrity_finalizations`. A finalized
  transition is resolved and cannot be blocked.
- `integrity_blocked_reject_after_seal` and
  `integrity_recovery_reject_after_seal` refuse any new observation or decision
  once an `instance_sealed` decision exists. Sealing is terminal.
- `integrity_recovery_require_latest_observation` refuses a decision whose
  `blocked_observation_id` is not the highest-ordinal retained observation for
  that transition.

Every relation is append-only by `BEFORE UPDATE`/`BEFORE DELETE` `RAISE(ABORT)`
triggers, matching every existing integrity relation.

Critically, none of these relations participate in the barrier. The
unresolved-transition query joins `integrity_pending_transitions` against
`integrity_finalizations` only, and the instance-global sequence remains
`count(*)` over `integrity_finalizations`. Retaining a blocked observation or a
recovery decision therefore cannot release the barrier or advance the sequence,
which is the central ADR-0014 safety property expressed in storage terms.

### Migration

`_SQLITE_SCHEMA_VERSION` becomes 3. The exact version-2 contract digest is
retained as `_SQLITE_LEGACY_INTEGRITY_V2_SCHEMA_CONTRACT_SHA256`, and
`_migrate_integrity_v2_to_blocked_v3` verifies it before adding the new objects
inside one `BEGIN IMMEDIATE` script, revalidating, and committing. A version-1
vault migrates directly to the complete version-3 layout, since the added
relations are empty in both cases and no integrity finality is assigned.

The migration adds relations only. It backfills nothing: an existing unresolved
transition gains no retroactive blocked observation, because no retained byte
records why any earlier attempt failed. Inventing one would be a false record.

### Capacity

`_logical_evidence_storage_used_locked` charges the new relations' record and
wire bytes. `_INTEGRITY_FINALITY_CAPACITY_RESERVE_BYTES_V1` widens from four
phase records plus transition evidence to additionally cover one blocked
observation and one recovery decision, because the reserve is taken once before
the pending row is inserted and is never re-taken.

### Store-domain error classification

The durable write path is deliberately not routed through
`_call_modeled_integrity_adapter` or `_advance_finality`. Both funnels convert
an unexpected exception into `IntegrityFinalityBlockedError`, so persisting a
blocked observation through them would reclassify a SQLite failure as a
deterministic trust failure — recording that finality is blocked *because
recording that finality is blocked* failed. `StoreBusyError`,
`StoreCapacityError`, `StoreOperationalError`, and `EventStoreCorruptionError`
keep their exact domains.

## Claim boundary

This establishes only the durable layout, its migration, its append-only and
terminality enforcement, its capacity accounting, and its store-error
classification. It does not establish:

- lifecycle integration, since no recovery path yet produces an observation or
  consumes a decision;
- independently custodied operator authority, dual control, or audit delivery,
  since the enrolled recovery key remains repository-owned;
- power-fault or production-storage qualification beyond the documented SQLite
  rollback-journal assumptions; or
- execution, independent verification, a finding, or live-target authority.

Lifecycle integration is the next tranche: producing an observation at the
exact point a deterministic block is classified, consuming an authorized retry
to resume from the retained phase, and refusing every consequential command on
a sealed instance.

## Rejected alternatives

### Extend the modeled authority binding

Rejected above: it changes every `binding_id`, invalidates retained enrollment
wire, and conflates the authority that causes a block with the authority that
recovers from it.

### Add a mutable `blocked` column to `integrity_pending_transitions`

Every integrity relation is append-only by trigger, and ADR-0011 already
rejected a mutable pending row. A column would also lose the attempt history.

### Record a seal row in `integrity_finalizations` to clear the barrier

This is the failure the barrier exists to prevent. A finalization row releases
the barrier and increments the instance-global sequence derived from
`count(*)`, so a sealed instance would look finalized to every continuity
check.

### Backfill an observation for an existing unresolved transition

No retained byte records why an earlier attempt failed. A synthesized reason
would be indistinguishable from an observed one.
