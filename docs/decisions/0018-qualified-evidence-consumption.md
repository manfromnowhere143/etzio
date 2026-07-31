# ADR-0018: Qualified signed evidence consumption

- Status: accepted
- Date: 2026-07-31
- Owner: Daniel Wahnich

## Context

ADR-0012 and ADR-0013 built networkless harnesses that authenticate signed
repository-owned fixture packages, recompute RFC 9162 inclusion and consistency
proofs, and map the result to the provider-neutral types the integrity contract
already understands: `RevocationFloorV1`, `HeadCheckpointFloorV1`, and
`EvidenceReferenceV1`. Both explicitly deferred consumption:

> The current `PendingIntegrityTransitionV1` path remains fixture-specific and
> does not consume `QualifiedIntegrityInputsV1`.

The modeled finality service (ADR-0011) still produces and validates *unsigned*
provider evidence. Every phase funnels through `_modeled_provider_content`,
which is `canonical_dumps` of a five-field code-derived dict with no signature,
and `_require_exact_modeled_provider_claims`, which requires the retained BLOB
bytes to equal that exact code-derived content.

A seam audit established the important fact: **the two subsystems already agree
on types.** `QualifiedIntegrityInputsV1.external_floors` is
`tuple[RevocationFloorV1, ...]`; `QualifiedHeadAuthorityInputsV1.external_floor`
is a `HeadCheckpointFloorV1`; both carry the same `ProviderEvidenceBlobV1` and
`EvidenceReferenceV1` the lifecycle consumes. The gap is not type adaptation.
It is exactly one thing: the acceptance gate demands byte-equality against
unsigned code-derived content, while a qualified BLOB carries
`signed.to_canonical_bytes()`.

Consuming qualified evidence therefore means adding a second acceptance mode,
not rewriting the provider-neutral shapes.

## Decision

Consumption proceeds in the same order ADR-0012 used for qualification:
specify the acceptance boundary and prove it networklessly first, then wire it
into the record identity and storage in a separate tranche.

### Two acceptance modes, profile-selected

Provider evidence is accepted under exactly one of two modes, chosen by the
enrolled store profile, never by the caller per event:

- `modeled_unsigned_code_derived` — the exact ADR-0011 behaviour, unchanged.
  Retained BLOB bytes must equal `_modeled_provider_content(...)`.
- `qualified_signed_fixture` — the retained BLOB bytes are the exact signed
  fixture package, and acceptance freshly reauthenticates the qualified bundle
  the evidence came from before comparing anything.

The two modes are mutually exclusive by construction: a signed package can never
equal the unsigned code-derived content, and the unsigned content carries no
signature to reauthenticate. Neither mode can silently satisfy the other's gate.

### Acceptance freshly reauthenticates, from the bundles

The `qualified_signed_fixture` mode does not trust a sealed
`QualifiedHeadAuthorityInputsV1` or `QualifiedIntegrityInputsV1` object. It
re-runs the reauthentication over the retained request and signed-package bytes
— for the anchor phase, `reauthenticate_anchor_bundle_v1` — and derives the
accepted `anchor_statement_id`, the accepted `anchor_evidence` references, and
the accepted signed BLOBs from that fresh result. A cached sealed object cannot
substitute for reauthentication, exactly as at every other qualification
boundary.

The evidence a checkpoint claims must then match the freshly derived result
exactly: the same `anchor_statement_id`, the same sorted references, and BLOBs
whose bytes are the exact retained signed packages. A BLOB carrying unsigned
modeled content is refused, because its bytes are not the signed package.

### This tranche: the anchor phase acceptance primitive

The seam audit identified the anchor-receipt → checkpoint phase as the smallest
dependency-complete cut: one validator, a `source_id` vocabulary
(`fixture.anchor.a`/`.b`) already shared between the modeled service and the
head-authority harness, and no revocation-snapshot or genesis-identity coupling.

This tranche implements `accept_qualified_anchor_evidence_v1` in
`etzio/kernel/qualified_evidence_v1.py`: given the head-authority and time
profiles, the retained time and anchor bundles, and the anchor statement and
evidence a checkpoint claims, it freshly reauthenticates and returns a sealed
`QualifiedAnchorEvidenceAcceptanceV1` or refuses. It changes no protocol kind,
store profile, record identity, lifecycle command, or the existing unsigned
validator.

### Deferred: record identity and storage

Wiring the `qualified_signed_fixture` mode into
`CheckpointCandidateRecordV1.__post_init__` changes the record body, its
`record_id`, and its SQLite retention, and requires a store profile that
selects the mode at enrollment. That is a schema-touching tranche with its own
crash-recovery known-bads, and it must preserve every ADR-0012 integration
requirement: empty-history activation, exact profile/root/policy/request and
signed-package retention, event-plus-pending atomicity, all four immutable
phases, the database-global barrier, byte-identical at-least-once retry,
provider calls outside SQLite transactions, exact global and mission
continuity, generic pending-replay refusal, and store-domain error
classification.

### Also this tranche: the revocation phase acceptance primitive

`accept_qualified_revocation_evidence_v1` extends the same discipline to a
decision's time and revocation inputs. It re-runs
`map_qualified_integrity_inputs_v1`, which reauthenticates every time and
revocation bundle from retained bytes, and accepts a decision's claimed time
hull, policy, time evidence, revocation views, and external floors only when
they equal the freshly derived mapping exactly, with BLOBs that are the exact
signed packages.

The acceptance primitive is networkless and touches neither the modeled service
nor record identity, so the two Side-A couplings the audit flagged — the
`RevocationFloorV1.snapshot_id == metadata.evidence_id` identity and the
`fixture.revocation-metadata` vs `fixture.revocation` source rename — are
deferred to the storage-wiring tranche that reconciles the modeled service, not
to acceptance. The head-floor phase, with its genesis-identity provenance, is
the remaining acceptance primitive.

## Claim boundary

This establishes only that a checkpoint's claimed anchor statement and evidence
can be accepted from a freshly reauthenticated qualified signed bundle, and
that a forged, scope-mismatched, or unsigned-content claim is refused. It does
not establish lifecycle consumption, a store profile selecting the mode,
independently administered provider authority, or any external observation. The
qualified fixtures remain repository-owned; distinct labels and keys prove no
independent operators.

## Rejected alternatives

### Widen the existing gate to accept both content shapes

A single gate that accepts either the unsigned content or a signed package
would let a caller choose which discipline applies per event. The mode must be
fixed by the enrolled profile, and the two gates must stay mutually exclusive.

### Trust the sealed qualified-inputs object

A sealed object proves it was constructed privately once. It does not prove the
retained request and package bytes still reauthenticate. Acceptance
reauthenticates from the bundles, consistent with every other boundary.

### Do all four phases at once

Each phase has distinct coupling. Proving the anchor phase first isolates the
one gate that changes and keeps the revocation and floor couplings out of the
first proof.

### Rewire the record before proving acceptance

Changing `CheckpointCandidateRecordV1` identity and storage before the
acceptance logic is proved would blur a schema migration with the acceptance
contract, exactly the mistake ADR-0012 avoided by specifying qualification
before ADR-0015 persisted it.
