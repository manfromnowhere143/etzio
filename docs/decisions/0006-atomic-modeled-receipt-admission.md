# ADR-0006: Atomic modeled-receipt admission and single-use lease consumption

- Status: accepted
- Date: 2026-07-28
- Owner: Daniel Wahnich
- Superseded in part: split-store output-retention and canonical retry caveats by
  [ADR-0010](0010-transactional-evidence-vault.md)

## Context

ADR-0005 retained the exact target and typed verification inputs resolved for one
verification lease. The modeled verifier receipt was still only a standalone proposal:
its signed body did not bind the retained resolution identity, no separately produced
outputs existed, and no canonical event could both admit the receipt and consume its
lease. A caller-selected resolution or expected verdict therefore could not become
consequential evidence.

Appending receipt admission and lease consumption as separate events would create a
recoverable partial state. A mutable consumed-leases table would duplicate canonical
authority outside the append-only mission stream. Neither design can make the current
single-event SQLite append boundary atomic.

## Decision

Etzio amends the unreleased protocol-v1 `verifier_receipt` body. There is no legacy
fallback. The verifier's one Ed25519 attestation now covers:

- the canonical `verification_artifact_resolution` identity;
- the lease's exact mission, authority, target, candidate, producer, verifier, key, PoC,
  supporting-evidence, environment-specification, and effect-oracle identities;
- four distinct typed-output digest/size pairs for execution, effect, measured
  environment, and termination;
- the modeled evidence tier, verdict, observations, and completion time.

The four output roles use the existing typed-CAS identity domain with code-owned types:

| Receipt role | Required artifact type |
|---|---|
| Execution output | `modeled_execution_output` |
| Effect output | `modeled_effect_output` |
| Measured-environment output | `modeled_measured_environment_output` |
| Termination output | `modeled_termination_output` |

Output identities must be unique by role and disjoint from every predeclared verification
input. Each signed size is a strict positive integer bounded at 64 MiB, their aggregate is
at most 64 MiB, and the retained resolution bytes plus output bytes must fit the authority
grant's one signed `max_bytes` ceiling. Etzio reads outputs in fixed execution, effect,
measured-environment, termination order and requires the resulting byte lengths to equal
the signed sizes. It derives each retained digest, type, and size binding from the bytes,
signed descriptor, and code-owned role map.

Protocol v1 retains nine semantic object kinds and adds the fifteenth exact event,
`verifier_receipt_admitted`. The event is authored by ETZIO and is an
`awaiting_verification` self-loop. Its exact payload retains:

- adjudication profile `modeled_fixture_receipt_admission_v1`;
- the complete decision-time verifier trust and revocation snapshot and its content
  identity;
- the exact, singly attested verifier-receipt envelope; and
- the four code-derived typed-output bindings.

That one append-only event is both the modeled-receipt admission and the single-use lease
consumption fact. No separate consumption event or mutable consumption authority exists.
Every authenticated allowed verdict, including negative, inconclusive, and invalid
outcomes, consumes the lease and remains equally visible. Admission authenticates and
retains a verifier's modeled statement; it does not accept the underlying claim as true or
create a finding.

The command derives the authority grant, target, candidate, lease, and unique resolution
from replayed canonical history. It accepts no caller-supplied lease, resolution,
consumption set, or expected verdict. Authentication, trust, revocation, binding, time,
and verdict checks precede CAS reads. A positive first admission revalidates the target,
resolved inputs, and four outputs before compare-and-append.

The reducer repeats every consequential signed, historical, lifecycle, and budget
invariant while the store holds its `BEGIN IMMEDIATE` writer transaction. It reconstructs
the decision trust store from the retained snapshot, reauthenticates the signed receipt,
cross-checks all historical bindings and signed sizes, enforces the signed byte ceiling,
and rejects duplicate receipt identities or a second admission for one lease. Pure
reduction cannot prove a mutable CAS read, so generic event append rejects
receipt-admission events. A dedicated store append path repeats target, resolved-input,
and output CAS validation from the locked retained history, requires its derived bindings
to equal the exact event, and only then inserts the event. This closes command bypass
through the ordinary append surface.

An exact retry searches the complete retained history before head comparison or CAS
access. It succeeds only when the complete canonical event context is identical and
returns the original event without requiring current CAS availability. A different
receipt or context for an already consumed lease is a deterministic conflict. Concurrent
submissions can encounter SQLite `BUSY` or `LOCKED`; the command makes exactly one append
retry and then reconciles retained history. If an identical submission commits during that
bounded window, both callers return the same retained event. Persistent contention remains
a retryable `StoreBusyError`, not corruption. Once a competing commit is visible, a
conflicting receipt is refused and different leases submitted from one shared head preserve
ordinary stale-head semantics.

## Consequences

- Canonical replay can prove which authenticated modeled statement was admitted, under
  which decision trust view, and which lease was consumed.
- Resolution substitution and output-role substitution change signed content and fail
  closed.
- Output-size substitution changes signed content; direct event bindings must equal those
  signed values, and the dedicated append path must independently derive the same lengths
  from current CAS bytes.
- Crash recovery cannot append a duplicate after a durable commit, even if the CAS later
  becomes unavailable or unrelated events advance the stream.
- Protocol-v1 receipts created before this amendment are incompatible. This pre-release
  convergence is permitted by ADR-0001 and is guarded by schema and runtime known-bads.
- Historical admission and current byte availability are intentionally different
  questions. Exact admission replay is CAS-free; a new first admission is CAS-aware.

## Claim boundary and residual risks

The four output artifacts are closed typed byte roles. Etzio does not yet parse a
structured execution record, correlate them through an independently measured run
identity, prove their provenance, or establish that the stated execution, environment,
effect, or termination occurred. One verifier signature authenticates the grouped
statement; it does not make the statement true.

The verifier remains a modeled identity. Separate labels and keys do not prove separate
principals, processes, hosts, or isolation boundaries. The receipt event does not mint a
finding, close a mission, authorize exploit execution, or authorize a live target.

The filesystem CAS and SQLite event store do not share one transaction. The dedicated
append repeats CAS checks while holding the SQLite writer transaction, but bytes can still
disappear after validation and before or after the event commit. The event retains their
historical signed identities and sizes, not current availability. Decision time and trust
snapshot freshness are not externally proved. Lease expiry, cancellation, supersession,
reassignment, and terminal recovery remain undefined. Event heads remain externally
unauthenticated, and the documented same-user SQLite pathname race remains.

The next dependency-complete gate is explicit lease recovery semantics. Trusted time,
revocation freshness, externally authenticated head anchoring, atomic filesystem-CAS/SQLite
retention, and closure of the same-user pathname race follow before a finding pipeline or
proof-plane execution can be accepted.

## Rejected alternatives

### Append separate receipt and consumption events

A crash between events would retain either an unconsumed admitted receipt or a consumed
lease without its adjudication. The current store can make exactly one event append
atomic.

### Track consumption in a mutable side table

Canonical state must remain reconstructible from append-only events. A side table would
introduce a second, rewritable authority and ambiguous recovery order.

### Let the caller supply the resolution, lease, or expected verdict

Those values are the subject of adjudication. The kernel must derive them from retained
history and authenticated receipt bytes.

### Accept legacy receipts without the new signed bindings

Unsigned context cannot become consequential safely. A compatibility fallback would
preserve the exact substitution flaw this decision closes.

### Treat `confirmed` as a finding

Authentication and atomic retention do not establish provenance, independent execution,
isolation, or scientific truth. Finding admission remains blocked.

### Require current CAS availability for exact retry

A committed adjudication is historical canonical state. Making its recovery depend on a
mutable filesystem would turn byte deletion into duplicate or ambiguous adjudication
behavior.
