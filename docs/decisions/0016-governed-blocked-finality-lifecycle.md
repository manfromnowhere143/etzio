# ADR-0016: Governed blocked-finality lifecycle integration

- Status: accepted
- Date: 2026-07-31
- Owner: Daniel Wahnich

## Context

ADR-0014 specified the durable blocked-finality observation and the governed
recovery decision. ADR-0015 persisted both under schema version 3. Neither
changed behaviour: no recovery path produced an observation or consumed a
decision, so a deterministic block still left no durable trace and could be
retried without bound.

Two properties were therefore still missing. A blocked attempt was not
recorded, so nothing could be audited after the fact. And nothing bounded
retries, so an adapter that refuses deterministically would be re-attempted
forever by every `load`, `recover`, and `append`.

## Decision

`ModeledIntegrityFinalizingEventStoreV1` accepts an optional
`GovernedBlockedFinalityBindingV1` holding the enrolled recovery profile and a
qualified-time source. The integration is opt-in: an unconfigured facade keeps
its exact historical behaviour, and a class-level default keeps deliberate
`__init__` bypasses ungoverned.

### A block becomes durable, outside the classifier

`_advance_finality` now wraps the original classifier, which is unchanged and
renamed `_classified_advance_finality`:

```text
_advance_finality
  → refuse if sealed
  → require recovery authorization
  → try: _classified_advance_finality
    except IntegrityFinalityBlockedError as blocked:
        retain observation      # outside the classifier
        raise
```

Retention deliberately runs in the outer handler. Both
`_call_modeled_integrity_adapter` and `_classified_advance_finality` convert
unexpected exceptions into `IntegrityFinalityBlockedError`, so persisting from
inside either would record that finality is blocked *because recording that
finality is blocked* failed. A store failure during retention keeps its own
domain and propagates.

The observation's phase, phase record identity, and operation are derived from
the retained lineage, not from caller input. A reason code outside the closed
taxonomy is retained as `modeled_integrity_adapter_contract_failure` rather
than widening the taxonomy with provider-controlled text.

Observation time comes from the binding's qualified-time source, which must
return a sealed ADR-0012 bundle. A local clock never records when finality
stopped.

### Recovery is authorized, not inferred

Once an observation is retained for a transition, `_advance_finality` requires
a retained governed decision answering the exact latest observation, with
disposition `retry_authorized`. Otherwise it raises
`IntegrityRecoveryNotAuthorizedError`.

This is the bound on retries. Elapsed time and repetition are not authority: an
adapter misconfigured for an hour and one permanently broken produce the same
sequence of blocks, and only an external decision distinguishes them.

An authorized retry does not promise success. If the adapter still refuses, the
retry blocks again and is retained under the next ordinal, so the attempt
history accumulates rather than being overwritten.

### Sealing is terminal for every consequential command

`load`, `recover_pending_transition`, `_advance_finality`, and therefore
`append` all refuse with `IntegrityInstanceSealedError` once a sealing decision
is retained. A sealing decision never authorizes a retry.

Sealing fences off new work; it never destroys retained evidence. The blocked
observations, the decision, the event, and every immutable phase remain
readable for audit and migration.

## Claim boundary

This establishes that a deterministic block is durably recorded, that recovery
after a block requires an authorized decision, and that a seal is terminal for
consequential commands. It does not establish:

- independently custodied operator authority, dual control, or audit delivery,
  since the enrolled recovery key remains repository-owned;
- crash recovery of an interruption *during* observation or decision retention,
  which the storage relations make atomic per statement but which has no
  injected-interruption known-bad yet;
- migration of a sealed instance to a new one; or
- execution, independent verification, a finding, or live-target authority.

## Rejected alternatives

### Retain the observation inside the classifier

The classifier converts unexpected exceptions into a blocked error. A store
failure raised while persisting the block would be reclassified as a
deterministic adapter refusal, hiding database corruption behind a trust
failure.

### Let recovery proceed without authorization after a block

That is the unbounded-retry behaviour this decision exists to remove.

### Make the integration mandatory

Enrolled databases without a recovery profile would be unable to recover at
all. Opt-in keeps the historical path intact and lets the governed path be
adopted per instance.

### Derive the blocked operation from the exception text

Provider-controlled text is not a taxonomy. The operation is derived from the
retained lineage phase, which is exactly the operation the recovery path
attempts from that phase.
