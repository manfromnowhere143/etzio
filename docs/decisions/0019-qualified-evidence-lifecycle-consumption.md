# ADR-0019: Qualified evidence lifecycle consumption

- Status: accepted
- Date: 2026-07-31
- Owner: Daniel Wahnich

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

## Implementation sequence

Each step is its own dependency-complete tranche with `make verify` green on
both runtimes and CI reproduction:

1. **Schema-v4 enrollment.** Add `acceptance_mode` and the qualified-profile
   wires, the 3→4 migration, empty-history qualified enrollment, capacity
   accounting, and known-bads. Nothing consumes the mode yet — this mirrors
   ADR-0015 preceding ADR-0016.
2. **Anchor-phase consumption.** `CheckpointCandidateRecordV1` in qualified
   mode uses `accept_qualified_anchor_evidence_v1`.
3. **Revocation-phase consumption.** `PendingIntegrityTransitionV1` in
   qualified mode uses `accept_qualified_revocation_evidence_v1`, resolving the
   snapshot-identity coupling and the source rename.
4. **Head-floor-phase consumption.** `FinalizedIntegrityTransitionV1` in
   qualified mode uses `accept_qualified_head_floor_evidence_v1`.
5. **Qualified-path crash recovery.** Injected-interruption known-bads across
   the qualified finality vertical, plus a complete qualified-mode receipt
   vertical mirroring the modeled one.

## Claim boundary

This is a design record. It changes no code, schema, or test. When implemented,
it establishes that the modeled finality lifecycle can consume authenticated
signed fixture evidence under a permanently enrolled qualified profile. It does
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
