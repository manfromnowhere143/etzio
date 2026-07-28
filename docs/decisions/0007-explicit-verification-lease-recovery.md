# ADR-0007: Explicit modeled verification-lease recovery

- Status: accepted
- Date: 2026-07-28
- Owner: Daniel Wahnich

## Context

ADR-0006 made one admitted verifier receipt the canonical, single-use terminal
disposition of its lease, but every lease otherwise remained permanently active in
replay. Wall-clock passage did not produce an event, cancellation had no contract,
reassignment would have violated the reducer's lifetime candidate uniqueness rule, and a
verification-intent mission with candidates could not close. A crashed, unavailable, or
deliberately withdrawn modeled assignment could therefore make its mission immortal.

Deriving expiry from the machine reading a stream would make canonical replay depend on
the reader's clock. Allowing a second ordinary issuance would lose predecessor lineage
and permit two active verifiers. Separating active supersession from successor issuance
would create a partial state in which the predecessor was ended but the replacement was
not retained.

## Decision

Etzio adds three exact protocol-v1 events, taking the event registry from 15 to 18 while
retaining the existing nine semantic object kinds:

| Event | Unit | Exact payload |
|---|---|---|
| `verification_lease_expired` | ETZIO | `verification_lease_id` |
| `verification_lease_cancelled` | AQUILA | `verification_lease_id`, `reason_code` |
| `verification_lease_reassigned` | AQUILA | predecessor ID, successor lease, reason code, verifier trust snapshot and ID |

Expiry is an explicit retained observation relative to the event's caller-supplied
`decision_time`. The reducer accepts it only for the candidate's active lineage tip when
`decision_time >= expires_at`. Replay never changes state merely because time passed.

Cancellation is accepted only for the active lineage tip before its deadline. Protocol
v1 admits exactly one closed reason, `operator_cancelled`. This is a modeled fixture
control assertion at the trusted command/store boundary; the AQUILA label and event do
not cryptographically prove which human or external control principal requested it. An
at-or-after-deadline cancellation is rejected so cancellation cannot disguise expiry.

Reassignment is the only way to issue a successor for an assigned candidate. Its
predecessor must be that candidate's latest lineage tip and must be active, explicitly
expired, or explicitly cancelled. The event:

- atomically supersedes an active predecessor and issues its successor;
- preserves an already expired or cancelled predecessor's original disposition;
- derives one exact reason from retained state:
  `active_lease_superseded`, `expired_lease_recovery`, or
  `cancelled_lease_recovery`;
- copies the predecessor's mission, authority, target, candidate, producer, PoC,
  supporting-evidence, environment, and effect-oracle identities exactly;
- assigns a different verifier identity, under a newly retained issuance trust
  snapshot;
- derives a fresh nonce from the current canonical event head;
- clips the successor deadline to the original admission and grant deadline; and
- counts every successor against the original grant's total verification-lease ceiling.

This surface is reassignment, not renewal. A successor with the predecessor's verifier
identity is rejected even when it uses another key. A successor requires its own typed
artifact-resolution event. A predecessor's historical resolution remains visible but
cannot resolve or admit a receipt for the successor.

The reducer reconstructs one lineage tip per candidate and one disjoint disposition per
lease:

- active;
- expired;
- cancelled;
- superseded; or
- consumed by an admitted receipt.

Only the active latest lease may receive a first artifact resolution or a first receipt.
Once expiry, cancellation, reassignment, or receipt admission wins the canonical append,
a later receipt cannot resurrect the predecessor even if its signed completion time
preceded the recovery event.

Terminal recovery reuses `mission_closed`, which is already a terminal store event. Its
exact three-field payload remains unchanged, while `status` becomes a closed
discriminator:

- new writers use `completed` only for a mission without verification intent;
- `receipt_coverage_complete` applies to verification intent when every retained
  candidate has one admitted receipt and no lease is active; and
- `receipt_coverage_incomplete` applies when no lease is active and at least one
  candidate is uncovered.

Replay exposes an exhaustive, disjoint candidate partition: active, receipt-covered,
never assigned, latest lease expired, or latest lease cancelled. Never-assigned
candidates remain explicitly uncovered and may close only as
`receipt_coverage_incomplete`; otherwise a mission with no eligible verifier could never
terminate. A verification-intent mission with zero candidates is vacuously
`receipt_coverage_complete`. Superseded ancestors never count as a candidate's final
coverage state.

For reader compatibility, replay additionally accepts the exact pre-recovery
verification-intent closure labeled `completed` only when it has zero candidates and no
lease, recovery, resolution, or receipt events. The retained bytes and status are
preserved. Current canonical command writers never emit that alias, and nonempty
verification streams cannot use it.

Every recovery command searches retained history before terminal and head checks. An exact retry
after a commit, later head advancement, or mission closure returns the original event.
A changed time, reason, verifier, key, trust snapshot, or effective successor lease is a
deterministic conflict. Compare-and-append serializes receipt, expiry, cancellation,
reassignment, and closure races: one event wins one head, and a loser cannot silently
rebase a consequential decision.

## Consequences

- Canonical replay can distinguish an active assignment, admitted receipt, explicit
  expiry, explicit cancellation, and atomic supersession.
- A crash after expiry or cancellation leaves a valid terminal lineage tip that can be
  reassigned or closed. A crash after reassignment cannot leave a superseded predecessor
  without its retained successor.
- Plain second issuance, lineage branching, duplicate dispositions, binding
  substitution, same-verifier renewal, budget reset, and deadline extension fail closed.
- Verification-intent closure reports receipt coverage, not execution success, claim
  truth, or finding status.
- Existing pre-release protocol-v1 zero-candidate verification closures remain replayable
  through the narrow reader-only alias. The newly accepted event variants, closure
  statuses, and near-neighbor refusal are guarded by runtime/schema parity and known-bad
  mutations.

## Claim boundary and residual risks

These events govern repository-owned deterministic modeled fixtures only. They do not
dispatch work, terminate a process, establish that a verifier became unavailable, prove
execution, evaluate a claim, mint a finding, authorize a live target, or authorize
disclosure.

`decision_time` remains caller supplied. An expiry event proves only that the canonical
modeled command accepted that value against the retained deadline; it is not trusted
clock evidence. The AQUILA unit and `operator_cancelled` reason are not a signature by an
external control principal. Verifier trust freshness is not externally proved.

Event heads remain externally unauthenticated. The filesystem CAS and SQLite event store
still lack one atomic retention transaction, and the documented same-user SQLite
pathname race remains. Structured independently produced execution evidence and the
Linux/KVM isolation proof remain future gates.

The next dependency-complete gate is trusted time, revocation freshness, and externally
authenticated event-head anchoring.

## Rejected alternatives

### Infer expiry while replaying

The same retained bytes would project differently at different wall-clock times.
Canonical state changes require an event.

### Permit another `verification_lease_issued` event

Ordinary issuance has no predecessor field. It cannot prove supersession, prevent
branching, or retain a candidate's recovery lineage.

### Append supersession and successor issuance separately

A crash between events would strand the candidate in a partially replaced state. One
reassignment event retains both facts atomically.

### Treat cancellation at or after the deadline as equivalent to expiry

That would replace a mechanically checkable deadline outcome with a differently authored
reason. The caller must retain explicit expiry first.

### Require every candidate to receive a lease before closure

No-verifier missions would remain immortal. Never-assigned candidates are instead
retained as an explicit uncovered partition and force incomplete receipt coverage.

### Call receipt coverage `completed`

An admitted receipt may be negative, invalid, inconclusive, or otherwise unsupported,
and coverage says nothing about execution truth. Verification closure therefore uses
receipt-coverage statuses rather than scientific or finding claims.
