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

Close foundation integrity before adding finder breadth:

1. align runtime objects with the versioned wire contracts;
2. admit authorization before mission opening;
3. route the real read-only analyzer through AQUILA and the kernel;
4. make candidate and event identities stable and content-bound;
5. add durable deterministic replay and fail-closed interruption semantics;
6. validate verifier evidence inside the kernel;
7. prove each invariant with a known-bad test.

Only then build MARCELLUS and independent CATO execution on Linux/KVM.

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
