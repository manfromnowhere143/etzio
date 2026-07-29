# ADR-0005: Typed, replayable verification-artifact resolution

- Status: accepted
- Date: 2026-07-27
- Owner: Daniel Wahnich
- Superseded in part: split-store retention and retry caveats by
  [ADR-0010](0010-transactional-evidence-vault.md)

## Context

ADR-0004 made a modeled verification assignment authority-bound and replayable, but its
PoC, supporting-evidence, environment, and effect-oracle fields were still bare SHA-256
references. The standalone receipt primitive accepted a caller-supplied set of digests as
proof that those references were retained. That set could not prove that bytes existed,
that each digest was interpreted under the intended role, that target files still matched
the retained snapshot, or that resolution happened in canonical mission history.

Using one untyped digest namespace for different verification roles would also permit type
confusion: identical bytes could be presented as a PoC, an environment description, or an
oracle specification without changing their identity. Resolving references only while
validating a later receipt would leave the exact pre-receipt input boundary absent from
replay.

## Decision

Etzio protocol v1 introduces a closed typed-CAS namespace for the four modeled
verification-input roles:

| Lease role | Required artifact type |
|---|---|
| PoC input | `modeled_poc_input` |
| Supporting-evidence input | `modeled_supporting_evidence_input` |
| Environment specification | `modeled_environment_spec` |
| Effect-oracle specification | `modeled_effect_oracle_spec` |

Typed identities are:

```text
sha256("etzio:evidence:typed:v1\0" || exact_type || "\0" || raw_bytes)
```

The existing untyped evidence namespace remains unchanged for repository-fixture target
files and prior protocol vectors. Generic and typed identities do not cross-resolve.
Artifact types are selected by kernel code from the retained lease field; callers cannot
choose a role, type, digest, size, or membership assertion during resolution.

Protocol v1 also adds the ninth semantic object,
`verification_artifact_resolution`, and the fourteenth exact event,
`verification_artifacts_resolved`. The ETZIO event records one canonical resolution for
one retained verification lease and leaves the mission in `awaiting_verification`. It
binds:

- the retained mission, authority, target snapshot, candidate, and verification lease;
- each target file's path, generic CAS identity, and exact size in snapshot order;
- the PoC, supporting evidence, environment, and oracle typed identities, types, and
  sizes; and
- the fixed resolution profile and decision time.

The resolution command derives all bindings from replayed state, checks the immutable
repository-fixture manifest, reads and rehashes every target and typed artifact, applies
per-item and aggregate byte ceilings, and compare-appends the event. The retained target
bytes plus all typed verification inputs share the grant's one signed `max_bytes` ceiling;
the command never resets that budget per role or action. Exact retries may return the
already retained resolution only after current CAS-aware revalidation.
Deterministic reducer replay establishes historical event consistency but does not claim
that an external filesystem still retains the bytes.

This decision removes caller-supplied digest membership as evidence authority. A modeled
receipt proposal must bind to the supplied exact resolution and re-read the CAS before it
can produce a positive modeled proposal. The receipt does not yet sign that resolution
identity, and no event in this tranche accepts the proposal.

## Consequences

- The same bytes under different modeled verification roles have distinct content
  identities.
- Every lease reference is resolved under a code-owned expected type, and every target file
  is rechecked against the retained snapshot and fixture manifest.
- Canonical history can reconstruct exactly which input bytes were resolved for a lease and
  when.
- One mission can retain resolution records for distinct leases without introducing a
  misleading mission-global “awaiting receipt” phase.
- The semantic registry now contains nine exact object bodies and fourteen exact event
  variants.
- Previously constructed modeled leases that used legacy untyped verification-input
  digests are incompatible with this resolution path.

## Claim boundary and residual risks

A resolution proves byte identity, assigned input role, and canonical historical linkage
at the resolution decision time. It does not prove provenance, truth, completeness,
exploitability, effect, execution, termination, environment measurement, verifier
independence, isolation, current retention, or finding validity.

The four lease artifacts are predeclared modeled inputs. In particular,
`effect_oracle_id` denotes a retained oracle specification, not evidence that an oracle
ran. A future execution receipt must introduce separately produced, content-bound
execution, effect, measured-environment, and termination outputs.

The filesystem CAS and SQLite event store do not share one atomic transaction. A crash can
therefore leave retained bytes without an event, and a later same-identity filesystem actor
can remove bytes after a valid event. Current availability requires CAS-aware
revalidation. The documented same-user filesystem race, untrusted clock, absent external
event-head anchor, and absent verifier isolation remain blockers.

The next dependency-complete gate is atomic receipt acceptance and single-use lease
consumption with complete canonical adjudication evidence. That gate must also define
lease expiry, cancellation, supersession, reassignment, and terminal recovery. Until then,
no receipt is accepted and no finding can be minted.

## Rejected alternatives

### Trust a caller-supplied set of retained digests

A set proves neither bytes nor types and lets the caller assert the condition under
evaluation.

### Infer artifact type from an untyped digest

Digest syntax contains no role information. An external type map would recreate mutable
membership authority and permit cross-role confusion.

### Record one event per artifact

Partial resolution events would create ambiguous intermediate states and make retries,
expiry, and aggregate-budget enforcement harder to reason about. One per-lease record is
the smallest replayable boundary.

### Treat the resolution event as proof of current CAS availability

The reducer is pure and must not depend on mutable filesystem state. Historical linkage
and current availability are intentionally separate checks.

### Accept a verifier receipt in the same tranche

Resolution is a dependency of receipt admission, not a substitute for atomic single-use
consumption, independent execution evidence, and adjudication.
