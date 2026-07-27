# ADR-0004: Kernel-issued, authority-bound verification leases

- Status: accepted
- Date: 2026-07-27
- Owner: Daniel Wahnich

## Context

ADR-0003 closed the semantic wire contract for the existing modeled verification lease,
but any caller could still construct that lease outside canonical mission history. The
fixture runner also closed a completed scan immediately, leaving no nonterminal state from
which the kernel could authorize independent verification. A valid lease object therefore
did not prove that:

- the mission had admitted `modeled_fixture_verification` for the exact target;
- the referenced candidate existed in the retained event stream;
- AQUILA admitted and issued an assignment to an eligible verifier distinct from the
  candidate producer;
- issuance time and expiry remained inside the admitted grant; or
- the verifier trust and revocation snapshot used at issuance was retained for replay.

Adding receipt acceptance before closing these conditions would let a correctly signed
statement enter through a caller-defined authority boundary.

## Decision

Etzio protocol v1 adds `verification_lease_issued` as the thirteenth exact event variant.
The event is authored by AQUILA and contains:

- one canonical `VerificationLeaseV1`;
- the complete verifier trust and revocation snapshot used for assignment; and
- the content-derived identifier of that snapshot.

The kernel issues the lease only from a lifecycle-validated retained mission projection.
Issuance requires the exact authority admission and target, an admitted grant permitting
`modeled_fixture_verification`, a retained candidate from the completed scan, an eligible
non-revoked modeled-fixture verifier key, and a verifier identity different from the
candidate producer. The lease binds the candidate, producer, target, authority, PoC,
evidence, environment, effect oracle, verifier, key, issue time, and bounded expiry.
The lease also content-binds the exact `issuance_trust_snapshot_id`. Replay revalidates
those bindings and the retained trust snapshot before reconstructing the state.

A fixture mission opened with verification intent does not close at `scan_completed`.
After issuance it enters the nonterminal `awaiting_verification` phase. A mission without
verification intent preserves the existing terminal closure path. A repeated request for
the same candidate may return the already retained lease only when the request is
semantically identical; substitution or conflicting reissuance is rejected.

This decision authorizes no verifier or exploit execution. It adds no receipt acceptance,
lease consumption, adjudication, finding, external effect, or live-target capability.

## Consequences

- A modeled verification assignment is now kernel-issued, authority-bound, durable, and
  replayable instead of caller-asserted.
- The verifier trust snapshot becomes canonical mission evidence for issuance, while its
  real-time freshness remains unproved.
- `awaiting_verification` is deliberately nonterminal so the later receipt gate can append
  without reopening a closed stream.
- The semantic event registry and installed schema have thirteen exact event branches.
- Candidate generation and lease issuance still do not establish that referenced digests
  exist, that any effect occurred, or that a finding is valid.

## Residual risks and next gate

The next dependency-complete gate is typed CAS resolution for every receipt reference.
After that, Etzio still must atomically accept a signed receipt and consume its lease,
retain canonical adjudication, establish trusted time and revocation freshness, externally
anchor event heads, and prove verifier process, principal, and isolation separation.

Until those gates close, `awaiting_verification` records an authorized modeled assignment
only. It is not a finding-admission state.

This tranche admits one lifetime lease per candidate and intentionally defines no lease
expiry, cancellation, supersession, reassignment, or terminal recovery event. Those
transitions must be designed with atomic receipt admission; an expired or unavailable
assignment cannot be silently replaced.

## Rejected alternatives

### Let callers mint leases and submit them with receipts

That would make a syntactically valid object stand in for kernel authority and retained
mission state.

### Store only the verifier snapshot identifier

An identifier without the exact snapshot bytes cannot reconstruct which keys, roles, and
revocations the kernel evaluated.

### Close the scan and later reopen it for verification

Reopening would violate the terminal append invariant and make stream closure conditional
on out-of-band state.

### Accept the receipt in the same tranche

Receipt acceptance depends on typed CAS resolution, atomic single-use consumption, and
canonical adjudication. Bundling those unproved dependencies would weaken the gate rather
than complete it.
