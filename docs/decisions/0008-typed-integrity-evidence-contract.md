# ADR-0008: Typed integrity-evidence contract before external authority

- Status: accepted
- Date: 2026-07-28
- Owner: Daniel Wahnich

## Context

Etzio's lifecycle events are canonical, hash-linked, and replay checked, but every
consequential command still receives a caller-selected scalar `decision_time`. Authority
and verifier trust snapshots have content identities but no externally authenticated
version, expiry, or proof that they were latest. The legacy `SignedCheckpoint` table
accepts opaque signature bytes and lives in the same SQLite database as the event history.
A coherent database rollback can therefore remove events and checkpoints together.

Three superficially attractive changes would not close that gap:

- signing a local timestamp would authenticate the signer, not prove trustworthy UTC;
- signing a local trust snapshot would not prove that it is the current revocation state;
  and
- verifying a checkpoint signature stored in the same rollbackable database would not
  establish external durability or latest-head knowledge.

The next runtime gate also needs crash and retry semantics. A command cannot report
success merely because its event committed locally if the resulting head never reached an
external anchor. Per-mission anchoring alone is insufficient because restoring an older
database could delete an entire mission and its discovery record.

## Decision

Etzio introduces a provider-neutral, cryptographically authenticated contract before
qualifying or selecting external services. Protocol v1 grows from nine to eleven exact
semantic object kinds while retaining its eighteen event variants:

- `integrity_decision`; and
- `head_checkpoint`.

Both kinds require exactly one canonical Ed25519 attestation. They use distinct signature
domains, exact noninterchangeable roles, content-derived key IDs, canonical Base64, and
prime-subgroup public-key validation. A decision authority and checkpoint authority must
be different principals, not merely different keys.

This ADR supersedes ADR-0003 only where that record reserved and rejected the
`head_checkpoint` name. The old `kernel.store.SignedCheckpoint` remains opaque legacy data
and is not promoted, migrated, or counted as authenticated evidence.

### Pre-transition integrity decision

`IntegrityDecisionV1` binds:

- service instance, environment, mission, authority, and target;
- the exact immediately previous instance-global checkpoint sequence, semantic identity,
  signed-attestation identity, signer principal, and historical trust snapshot;
- the exact previous event sequence and digest;
- event kind, a code-checked complete proposed-event digest, and a transition-intent
  identity;
- a 256-bit request nonce;
- a conservative trusted-time interval and exact time-policy identity;
- at least two typed time-evidence references with distinct `source_id` labels;
- complete namespace-sorted revocation views with root version, metadata version,
  snapshot identity, typed provider evidence, and a half-open validity interval; and
- the exact integrity-decision policy identity.

The proposed event uses the interval's upper bound as its scalar protocol-v1
`decision_time`. Binding validation compares the complete canonical event identity,
mission, authority, target, kind, sequence, predecessor, and time. An arbitrary intent
digest cannot authorize a different event.

Time is never treated as an asserted exact point. A capability-extending transition is
valid only when its entire uncertainty interval lies inside every relevant half-open
validity window. A pre-deadline decision requires the upper bound before the deadline; an
expiry decision requires the lower bound at or after it. An interval crossing a boundary
fails closed.

Revocation continuity rejects namespace removal, root or metadata rollback,
same-version/different-snapshot mutation, and trusted-time regression. It also requires an
adapter-verified external floor for every represented namespace. Every floor binds the
service instance, environment, and exact decision policy so a valid older floor from
another deployment or policy cannot weaken rollback detection. The retained prior
decision must be the exact signed decision referenced by the immediately previous
instance-global checkpoint; a mission-local or older decision is not an acceptable
monotonicity baseline. Every new decision also signs the exact instance-global checkpoint
and attestation provenance it extends, preventing a caller from pairing it with an older
locally valid checkpoint, substituting a different trusted co-signature over the same
checkpoint body, or skipping a newer revocation state. An external revocation floor below
the retained local predecessor is rollback even when the current decision advances beyond
both. These floor values are typed boundary objects; direct construction validates their
shape but is not proof that an adapter or independent service authenticated them.

### Post-transition head checkpoint

`HeadCheckpointV1` binds:

- the service instance and environment;
- one monotonically advancing instance-global sequence and predecessor with exact
  signed-attestation, signer-principal, and trust-snapshot provenance;
- one mission-local event sequence and mission-checkpoint predecessor with the same exact
  provenance;
- exact mission, authority, target, and event digest;
- the exact signed integrity-decision attestation identity, signer principal, semantic
  identity, and historical trust-snapshot identity;
- a conservative checkpoint-time interval and typed time-evidence quorum;
- an exact anchor policy; and
- at least two typed anchor-receipt references with distinct `source_id` labels.

External anchor receipts register a separately derived `anchor_statement_id`. That
statement commits to every head, predecessor, policy, and time field before receipt bytes
exist, including the signed-decision provenance. The final checkpoint identity additionally
commits to the receipt references. This avoids an impossible cycle in which a receipt
would need to contain the final object ID that itself contains the receipt digest, while
preventing a later valid signature over the same decision body from rewriting who
authorized the transition.

Continuity validation requires an adapter-verified external instance catalog floor. The
catalog carries both the latest instance-global checkpoint and the selected mission's
latest checkpoint, including each exact signed-checkpoint attestation, signer principal,
and trust-snapshot identity. A witness ahead of local storage is classified as local
rollback; a local proposal that does not extend the exact witnessed heads is a branch.
An exact floor equal to the authenticated current checkpoint is accepted for idempotent
post-anchor reconciliation, while mixed global/mission provenance is rejected.
Domain-separated global and per-mission genesis identities close substitution between
those chains. A mission projection cannot be ahead of the global projection, and two
different checkpoints cannot occupy the same global instance sequence. For an older
mission head, ancestry and catalog co-residency remain facts that a qualified external
catalog adapter must verify from retained consistency evidence; this provider-neutral
contract does not interpret an opaque catalog proof, and direct floor construction does
not establish that fact.

The checkpoint interval must conservatively follow the decision interval, and each
successor decision's complete interval must conservatively follow its retained checkpoint
predecessor. The decision and checkpoint attestations are verified before
attacker-controlled semantic bodies are interpreted by the consequential authentication
path. Every consequential continuity validator cryptographically reauthenticates its input
wrappers against their exact historical trust stores; direct construction of an
`Authenticated*` dataclass cannot bypass signature verification because public
construction is refused and consequential validators also require the
authentication-boundary seal. Subclasses and malformed nested signed objects are rejected;
the exact constructed trust store and caller policy are copied; and reauthentication
rebuilds a fresh immutable result from the newly verified wire. Later composition reads
only that snapshot, so a stateful caller object cannot substitute unsigned semantics after
the authentication check. Decision predecessor sequences reserve one representable
signed-int64 successor for the proposed event and resulting checkpoint. Those validators
reapply the caller's exact decision, time, and anchor policy identities, required
revocation namespaces, and uncertainty ceilings to current and historical inputs rather
than trusting eligibility checked by an earlier caller. Both event and checkpoint
lineages must extend the same mission predecessor digest and exact predecessor attestation
provenance. When global and mission projections name the same semantic checkpoint, they
must name one identical attestation, principal, and trust snapshot. A mission-local
successor cannot rebind the mission's authority or target.

### Typed provider evidence

Evidence references have a closed kind:

- `trusted_time`;
- `revocation_metadata`;
- `head_anchor_receipt`; or
- `external_floor`.

Source labels and content IDs provide deterministic bindings; they do not prove that two
labels represent independent operators. Qualified adapters must authenticate the
underlying bytes, enforce provider identities and policy, retain complete validation
material, and reject replay, downgrade, equivocation, and stale evidence.

### Dependency direction

No new runtime dependency is accepted in this contract tranche.

- Revocation metadata should use the official
  [TUF client workflow](https://theupdateframework.readthedocs.io/en/latest/api/tuf.ngclient.updater.html),
  but Etzio must first supply conservative trusted time and an external rollback floor;
  a rollbackable local TUF cache is insufficient.
- RFC 3161/CMS and PKIX should not be implemented by Etzio. `pyHanko` is a conditional
  adapter candidate, subject to pinned CPython 3.11/3.14 conformance, dependency, malicious
  vector, and independent-oracle review.
- Head receipts should follow the final [RFC 9942 COSE Receipts](https://www.rfc-editor.org/rfc/rfc9942.html)
  profile and [RFC 9943 SCITT architecture](https://www.rfc-editor.org/rfc/rfc9943.html),
  with RFC 9162-style inclusion and consistency evidence where applicable. No available
  Python SCITT package is yet accepted as Etzio's canonical authority.
- NTS can authenticate a time server and exchange but cannot prove that a server reports
  truthful time. RFC 3161 quorums and a qualified rough-time adapter remain candidates;
  an Internet-Draft is not described as an RFC.

Every accepted dependency closure must be hash locked, SBOM-visible, tested on both
declared Python runtimes, and differentially checked against an independent implementation.

## Consequences

- Protocol-v1 framing, installed schema, typed dispatch, and repository policy now close
  eleven semantic kinds, distinguish required from optional attestations, and constrain
  time, revocation, and anchor evidence kinds at their exact nested schema locations.
- Known-bads cover signature forgery, signature-domain substitution, small-order keys,
  missing context, bool/int aliasing, nonce and proposed-event substitution, interval
  straddling, evidence-type confusion, revocation rollback/equivocation, rotated-key
  same-principal reuse, direct-wrapper forgery, cross-scope floor replay, alternate trusted
  attestation substitution, checkpoint/event predecessor splicing,
  older-global-baseline substitution, historical checkpoint re-signing, mixed
  global/mission provenance, mission authority/target rebinding, successor-time regression,
  stateful wrapper substitution after authentication, stale external revocation floors,
  post-authentication policy weakening, bounded iterable and pre-encode text exhaustion,
  terminal predecessor sequence exhaustion, checkpoint branch/gap/substitution,
  receipt-hash cycles, and local history below an external floor.
- The contracts can be used by independently administered adapters without changing
  existing event bytes or the eighteen event variants.
- Existing historical streams remain replayable. They are not silently promoted to
  trusted-time or externally anchored history.

## Claim boundary and remaining gate

This tranche implements and tests the contract only. It does not connect to a real TSA,
TUF repository, SCITT service, transparency log, monitor, or separately administered
key. It does not persist authenticated checkpoints, query an external latest-head catalog,
or make any lifecycle command require these objects. Current command
`decision_time` values and trust snapshots therefore remain modeled and caller supplied.

Repository-owned fixture signers and floor objects prove parsing, cryptography, interval
arithmetic, exact binding, scoped anti-rollback comparisons, and rollback logic. They do
not prove trustworthy UTC, current real revocation state, independent administration,
external retention, catalog ancestry/co-residency, non-equivocation, legal target
permission, execution, scientific truth, or a finding.

The next implementation slice is one anchor-final receipt-admission command vertical:

1. qualify concrete time, revocation, and anchor adapters;
2. derive and authenticate the exact proposed event;
3. commit the event locally as pending anchoring;
4. register the pre-receipt anchor statement externally;
5. verify and retain receipts plus external latest-head floors;
6. report success only after anchor finality; and
7. recover idempotently after a crash or timeout without holding a SQLite writer
   transaction across a network call.

No later append may proceed from an unanchored head. Timeout or unavailable evidence means
pending or blocked, never approval.

## Rejected alternatives

### Upgrade the existing SQLite checkpoint row

The legacy row has no exact sequence, predecessor, policy, revocation, interval, or
cryptographic trust semantics and shares the event database's rollback fate.

### Treat NTP or local wall time as trusted evidence

Local and network clocks can step, lie, or be replayed. Consequential boundary decisions
need authenticated retained evidence and interval semantics.

### Accept one valid inclusion proof

Inclusion alone does not establish consistency, latest state, or absence of split views.
The architecture requires external floors and independently operated evidence sources.

### Anchor only each mission

That cannot detect deletion of an entire mission. The instance-global chain and external
catalog are required.

### Return success immediately after the local commit

A crash or remote timeout could leave an unanchored event that later work incorrectly
treats as authoritative. Command completion must include verified anchor finality.
