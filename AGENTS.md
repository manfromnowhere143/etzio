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
kernel-issued authority-bound modeled-fixture verification leases, and known-bad controls.
It remains a narrow candidate-and-assignment proof, not a finding pipeline.

Close the remaining foundation-integrity gates before adding finder breadth:

1. resolve referenced receipt evidence from retained CAS bytes with exact expected types;
2. atomically consume each lease with its accepted signed receipt and retain canonical
   adjudication;
3. establish a trusted clock boundary and externally anchor event heads; and
4. prove every new refusal and concurrency invariant with a known-bad.

Then build MARCELLUS and independent CATO execution on an explicitly accepted Linux/KVM
profile before the benchmark-first EVM domain pack.

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
