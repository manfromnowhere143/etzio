# ADR-0017: Blocked-finality crash recovery and status inspection

- Status: accepted
- Date: 2026-07-31
- Owner: Daniel Wahnich

## Context

ADR-0016 made the blocked-finality contract live: a deterministic block is
retained durably, recovery past a block requires an authorized decision, and a
seal is terminal. Its claim boundary named the remaining gap explicitly —
interruption *during* observation or decision retention had no
injected-interruption known-bad. The relations are atomic per statement, but
atomicity is not the same as proved replay.

Two smaller gaps surfaced while designing those scenarios.

A caller that dies immediately after the observation commits never sees the
original `IntegrityFinalityBlockedError`. On restart it receives
`IntegrityRecoveryNotAuthorizedError` instead, which named no reason, no phase,
and no attempt. The operator learned that recovery was gated but not what
blocked it — the exact information the durable record exists to preserve.

There was also no way to read the retained blocked state at all. ADR-0011
anticipated this: "operational inspection may expose the explicit pending phase
through a separate non-consequential status interface."

## Decision

### Interruption is proved, not assumed

Thirteen known-bads cover interruption on both sides of both retention points,
plus reopening the database in a fresh process:

- death *before* observation retention leaves no row, and the next attempt is
  ordinal 1 rather than 2, because an unrecorded block did not happen;
- death *after* observation retention leaves exactly one row, and replay is
  gated by the authorization check rather than inserting a duplicate;
- repeated death after retention across successive authorized retries yields
  ordinals `[1, 2, 3]` with three distinct observation identities, never a
  reused or skipped ordinal;
- an interrupted observation leaves the unresolved-transition barrier held and
  `integrity_finalizations` empty;
- death after decision retention reconciles: resubmitting the exact same signed
  bytes leaves one row;
- death before decision retention leaves recovery unauthorized;
- death after a sealing decision keeps the instance sealed; and
- a reopened database sees exactly the retained observations, reason, and
  decision.

The injected failure is a caller-side `RuntimeError` subclass, deliberately
neither a store nor an adapter condition, so it cannot be mistaken for either
domain. A separate known-bad injects `StoreBusyError` during retention and
asserts it propagates as `StoreBusyError` — recording that finality is blocked
must never itself become a deterministic adapter refusal.

### The refusal carries the retained reason

`IntegrityRecoveryNotAuthorizedError` now states the attempt ordinal, the
unresolved phase, the refused operation, and the reason code drawn from the
retained observation. A caller that lost the original error still learns why it
is blocked, which is the whole point of retaining the record.

### Non-consequential status inspection

`blocked_finality_status()` returns the event digest, mission, unresolved
phase, attempt count, latest ordinal, latest operation and reason, latest
disposition, and seal state — or `None` when no governed binding is configured
or no transition is unresolved.

It cannot append, authorize, resolve, or return command success, and it never
projects the pending event as a finalized head. A known-bad asserts that
calling it retains nothing and finalizes nothing.

## Claim boundary

Logical crash recovery is claimed only under the documented SQLite
rollback-journal assumptions and deterministic injected failures. This is not
power-loss, device, or production-storage qualification, and it does not make
the enrolled recovery key independently custodied, prove dual control, or
provide audit delivery.

## Rejected alternatives

### Assume per-statement atomicity is sufficient

Atomicity prevents a partial row. It says nothing about whether the *next*
attempt duplicates an ordinal, skips one, or bypasses the authorization gate.
Those are the properties an operator depends on, and they needed proving.

### Let the unauthorized refusal stay opaque

A durable record that cannot be read by the caller it is meant to inform is
retention without purpose.

### Expose the retained state through the ordinary load path

Status inspection must never be able to return command success or project an
unfinalized event as a head. A separate non-consequential interface keeps that
impossible by construction.
