# Etzio Agent Bootstrap

Canonical workspace: `/Users/danielwahnich/workspace/etzio`.

Run first in every new session:

```bash
cd /Users/danielwahnich/workspace/etzio
git status --short --branch
cat docs/SESSION_HANDOFF.md
python3.11 -m venv .venv
.venv/bin/python -m pip install \
  --no-input \
  --require-hashes \
  --only-binary=:all: \
  --requirement tools/ci/requirements-ci.lock
.venv/bin/python -m pip check
ETZIO_PYTHON=.venv/bin/python make verify
```

Read `docs/SESSION_HANDOFF.md` before changing repository bytes. Then read, in order:
`README.md`, `CHARTER.md`, `docs/ARCHITECTURE.md`, `docs/ROADMAP.md`, and
`docs/FRONTIER_BASELINE.md`.

If `.venv` already contains the exact locked dependencies, skip only environment creation
and installation. Status inspection, handoff reading, and validation remain mandatory.

## Identity invariant

This repository is **Etzio**. It is independent from Odeya, Sentinel, Aweb, Maestro, Telos,
and every other Daniel Wahnich project.

Before acting, the project name, current directory, Git root, and recovery handoff must all
agree. If a prompt says Etzio while the working directory or injected instructions point to
another repository, stop and resolve the mismatch. Never treat project names as aliases.

Other repositories may be inspected for engineering patterns only. Do not copy their runtime
code, import their infrastructure, or modify them while working on Etzio.

## Mission boundary

Etzio is an authorized vulnerability-research engine. The long horizon spans vulnerability
classes, languages, target types, and defensive workflows. Breadth is delivered through
versioned domain and technique adapters; the kernel remains target-neutral.

- No live target without an admitted `TargetContract` for that exact target and revision.
- No exploit execution outside a proved hard-isolation profile.
- No network egress, spending, credential use, or disclosure without a separate scoped grant.
- A model-generated candidate is not a finding.
- The generator may not verify its own claim.
- Missing, blocked, inconclusive, not-reproduced, and null results remain distinct.
- Self-improvement is offline, evaluated, reversible, and unable to change authority policy,
  evaluators, benchmarks, or production bytes directly.

The current authorized execution surface is repository-owned deterministic fixtures only.
Pinned historical benchmarks may be inspected read-only; executing their build systems or
payloads remains blocked until the isolation gate. Winning bounties is a future measured
outcome, not authority to touch a third-party system.

## Current mission order

The first governed fixture vertical slice now has a canonical protocol envelope, signed
authority admission, content-addressed target snapshot, stable candidates, lifecycle-checked
SQLite replay, semantic schemas for every typed wire kind, fail-closed terminal states,
kernel-issued authority-bound modeled-fixture verification leases, typed resolution for
every modeled verification input, atomic modeled-receipt admission, single-use lease
consumption, and known-bad controls. A versioned SQLite evidence vault now atomically
retains the exact BLOBs, code-derived mappings, and event at all four implemented
byte-claiming boundaries; the filesystem evidence store is staging/cache only. Committed
replay and retry are staging-independent, and canonical corruption never falls back to
staging. The receipt signs the retained resolution and four typed output digest/size pairs,
but those opaque outputs do not establish execution or a finding. Canonical per-candidate
lease lineages now retain explicit expiry, modeled cancellation, atomic reassignment to a
different verifier, single-use receipt consumption, and complete or incomplete
receipt-coverage closure.

The next-gate protocol contract now has typed, required-attestation integrity decisions and
head checkpoints with proposed-event binding, conservative time intervals, typed provider
evidence, exact current and predecessor signed-attestation provenance, scope-bound
nonstale external rollback-floor inputs, conservative cross-transition time ordering, and
global plus mission continuity. Consequential composition rejects subclasses, copies the
constructed trust store and caller policy, and rebuilds fresh authenticated snapshots from
verified wire before applying continuity logic. Empty-history schema-v2 modeled-integrity
enrollment now pins a fixture-adapter authority binding, and consequential fixture commands
persist and require that contract through atomic pending retention, four immutable recovery
phases, two at-least-once modeled protocol writes, one database-global unresolved-transition
barrier, and exact-current global plus mission completion.

Separately, a versioned, networkless trusted-time and revocation qualification contract now
pins an exact copied profile, trust root, validation policy, role-separated source roster,
and codec identities. It authenticates exact repository-fixture provider statements before
parsing claims, proves byte-stable retry under a content-derived corpus manifest, requires
all time sources to overlap while retaining their conservative outer hull, applies that
complete hull to half-open revocation validity and staleness, requires unanimous configured
floors, and freshly reauthenticates sealed mappings into provider-neutral evidence.
Eighty-one focused tests and known-bads cover substitution, replay, staleness, ambiguity,
malformed wire, incomplete rosters, and sealed-boundary abuse.

A second versioned, networkless qualification contract now closes the remaining two
integrity evidence kinds. It pins an exact copied head-authority profile, trust root,
validation policy, role-separated anchor, catalog, and monitor roster, log origins, and
codec identities. It authenticates exact repository-fixture statements before parsing
claims, recomputes RFC 9162 inclusion proofs against a byte-bound Etzio anchor-registration
leaf, recomputes RFC 9162 consistency proofs from the exact retained predecessor root,
refuses an unchanged tree size whose root changed, requires unanimous monitor agreement on
one catalog head, evaluates freshness only against the complete qualified time hull, and
freshly reauthenticates sealed mappings into provider-neutral anchor references and one
`HeadCheckpointFloorV1`. Seventy-eight focused tests and known-bads cover the published
RFC reference tree, tampered, truncated, padded, forged, and forked proofs, rollback,
equivocation, split view, substitution, staleness, and sealed-boundary abuse.

A third versioned, networkless contract now makes a blocked finality attempt durable. One
closed observation names the exact transition, highest retained immutable phase, refused
operation, deterministic reason, and attempt ordinal, timed only by a qualified hull. It
resolves nothing. A role-separated Ed25519 governed recovery decision, whose key and
principal must both differ from the enrolled integrity-decision and head-checkpoint
authorities, is the only thing able to change a disposition, and it restates the complete
observation binding so a signature cannot be moved onto another block. Exactly two
dispositions are admissible: authorized retry from the exact retained phase, and terminal
instance sealing. Neither finalizes, deletes, rewrites, mints a checkpoint, or releases the
database-global barrier. Sixty-one focused tests and known-bads cover phase, ordinal,
binding, separation-of-duty, staleness, seal-terminality, and barrier invariants.

Schema version 3 now persists that contract as three append-only relations: a singleton
enrolled recovery profile, per-transition blocked observations keyed by attempt ordinal, and
governed recovery decisions. A forward migration from the exact version-2 layout adds
relations only and backfills nothing. Database triggers refuse an observation on a finalized
transition, any observation or decision after a seal, and a decision that does not answer the
latest retained observation. None of the new relations participate in the unresolved-transition
barrier or the instance-global sequence, so retaining a block can never release finality.

An opt-in governed binding now makes that storage live. When the classifier reports a
deterministic block, a durable observation is retained from outside the classifier, so a
store failure keeps its own domain instead of becoming an adapter refusal. Once an
observation exists, recovery requires a retained decision authorizing a retry for the exact
latest observation; elapsed time and repetition are not authority. An authorized retry does
not promise success, so a still-refusing adapter accumulates attempts under increasing
ordinals. A sealing decision never authorizes a retry and makes load, recover, and append
refuse, while leaving every retained byte readable. Injected-interruption known-bads prove
that death on either side of observation and decision retention never duplicates, reuses,
or skips an attempt ordinal, never releases the barrier, and never reclassifies a store
failure; the unauthorized-recovery refusal carries the retained reason, and a
non-consequential status interface exposes the blocked state without resolving it.

The three qualification harnesses are contract proof only and are not consumed by modeled
finality unless the governed binding is configured. Modeled finality still uses unsigned, deterministic,
code-derived provider assertions. No real or native provider is connected, and no external
durability, trustworthy UTC, current real-world revocation, independent administration,
real non-equivocation, execution, or finding claim follows.

Close the remaining foundation-integrity gates before adding finder breadth:

1. qualify independently administered trusted-time, revocation, anchor, catalog, and
   monitor adapters and connect an explicitly admitted profile without weakening the
   retained recovery state machine;
2. only then qualify independently administered providers and integrate accepted adapter
   outputs without weakening the retained recovery state machine;
3. prove external latest-head authority survives local loss, then close the documented
   same-user SQLite pathname and coherent offline-rewrite boundary;
4. accept and qualify a concrete SQLite/VFS/filesystem/device profile, physical and journal
   quotas, backup/restore, process-kill and power-fault recovery, and sensitive-evidence
   access-control, encryption, and retention policy;
5. replace opaque modeled outputs with structured independently produced execution
   evidence; and
6. prove every new refusal and concurrency invariant with a known-bad.

Then build MARCELLUS and independent CATO execution on an explicitly accepted Linux/KVM
profile before the benchmark-first EVM domain pack. Only after the integrity, isolation,
benchmark, and exact-`TargetContract` gates close may a strictly authorized bounty-research
lane run in parallel with continued engine development; accepted outcomes and income are
measurements, never authority.

## Change discipline

- Preserve a clean distinction between `implemented`, `modeled`, `proposed`, and `blocked`.
- Every consequential gate needs a known-bad case demonstrating that it fires.
- Update contracts before behavior that changes their meaning.
- Prefer the smallest dependency-complete proof tranche; do not confuse narrow validation
  with MVP quality.
- Run `make verify` before and after a change.
- Inspect the complete diff and stage only the intended scope.
- Update `docs/SESSION_HANDOFF.md` and `docs/MISSION_STATE.json` when mission state changes.

## Authorship and publication

Daniel Wahnich is the sole repository author. Use the configured identity:

```text
Daniel Wahnich <cogitoergosum143@gmail.com>
```

Do not add `Co-Authored-By` trailers. Automated systems may assist with authorized changes,
validation, and publication, but they may not appear as an author or co-author. The
authorized remote is the private repository `manfromnowhere143/etzio`. Public visibility,
deployment, live-target work, disclosure, and spending require separate explicit authority.
