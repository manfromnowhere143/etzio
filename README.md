# Etzio

**An evidence-native operating system for authorized vulnerability research.**

Etzio is being designed to turn an exact, authorized target into a governed and
replayable research chain:

```text
authority → surface → hypotheses → candidates → exploit proof
          → independent reproduction → adjudication → disclosure draft → learning
```

The long-range mission spans vulnerability classes, languages, target categories, and
defensive workflows. Blockchain and smart-contract benchmarks are the first economic and
technical wedge, not the architectural boundary. Target-specific knowledge belongs in
versioned domain and technique packs; scientific and policy authority remains in the kernel.

> **Current status — architecture foundation, 2026-07-27.**
> The repository contains a deterministic demonstration loop, typed skeleton ports, a small
> Python AST analyzer, modeled benchmark fixtures, schemas, tests, and repository-policy CI.
> It does **not** yet contain a durable replayable kernel, enforceable authorization
> admission, hard-isolated exploit execution, independent verifier infrastructure, a live
> target adapter, or a learning system. No production-readiness or state-of-the-art claim is
> made.

## The thesis

A vulnerability is a scientific claim. A candidate says that a specific input against a
specific revision causes a security-relevant effect. A finding is warranted only when a
separate verifier reproduces that effect from retained bytes inside a clean environment.

Etzio therefore optimizes for an auditable chain of evidence, not the volume of model prose
or scanner alerts:

1. authorization is admitted before any target action;
2. generators cannot confirm their own candidates;
3. evidence is content-addressed and replayable;
4. null, blocked, failed, and inconclusive outcomes remain visible;
5. egress, spending, credentials, live actions, and disclosure are separate authorities;
6. learning is offline, evaluated, reversible, and unable to rewrite its own authority.

## System map

| Plane | Unit | Responsibility | Current repository status |
|---|---|---|---|
| Control | **ETZIO** | lifecycle kernel, event ledger, next legal action | modeled in memory; integrity work is next |
| Governance | **AQUILA** | authority, scope, budgets, egress, kill switch | deterministic stub; not a security boundary |
| Recon | **SCIPIO** | attack-surface and dependency mapping | modeled port plus narrow Python AST mapper |
| Strategy | **FABIUS** | ranked, falsifiable hypotheses | deterministic stub |
| Investigation | **VELITES** | decomposed static and dynamic probes | stub plus six-rule Python AST analyzer |
| Proof | **MARCELLUS** | exploit/PoC construction | pass-through stub; no isolation |
| Verification | **CATO** | clean independent reproduction and verdict | in-process modeled gate; not independent |
| Adjudication | **CAMILLUS** | deduplication, severity, ranking | deterministic stub |
| Disclosure | **FABRICIUS** | evidence-bound report drafting | deterministic stub; no submission |
| Learning | **MINERVA** | evaluated cross-mission strategy promotion | count-only stub |

See [Architecture](docs/ARCHITECTURE.md) for the target design and the exact implemented
boundary.

## What the present evidence establishes

The current suite passes a tiny, synthetic corpus:

- 29 tests: 15 original behavior regressions and 14 repository-policy known-bads;
- a modeled CATO corpus with TP=3, FP=0, TN=4, FN=1;
- seven planted instances across six Python AST rule classes;
- zero alerts on one clean fixture;
- one intentional fixture-only alert surface in the package scan.

These numbers establish deterministic behavior on those fixtures only. Four benign corpus
cases are far too few to support a real false-positive claim: observing 0/4 false positives
still permits a large one-sided 95% upper bound. The scanner also has parse-error and
coverage limitations documented in [Architecture](docs/ARCHITECTURE.md).

## Reproduce locally

The canonical interpreter is CPython 3.11.15. CI additionally checks CPython 3.14.2.

```bash
git clone git@github.com:manfromnowhere143/etzio.git
cd etzio
python3.11 -m venv .venv
.venv/bin/python -m pip install \
  --no-input \
  --require-hashes \
  --only-binary=:all: \
  --requirement tools/ci/requirements-ci.lock
.venv/bin/python -m pip check
PATH="$PWD/.venv/bin:$PATH" make verify
```

The demos operate on local fixtures only:

```bash
.venv/bin/python -m etzio.cli
.venv/bin/python -m etzio.harness.fpr
.venv/bin/python -m etzio.scan
```

Do not point the current scan command at private or third-party source merely because it
accepts a path. The command is not yet routed through admitted authority or the kernel.

## Build order

The next mission is **foundation integrity before capability breadth**:

1. one versioned runtime/wire contract;
2. authorization admission before mission opening;
3. stable content-bound identities;
4. immutable canonical full-SHA events with durable replay;
5. kernel-validated independent-verifier receipts;
6. known-bad evidence for every invariant.

Only after that slice passes do MARCELLUS and CATO move into genuinely separate Linux/KVM
isolation. Domain packs, finder swarms, broader benchmarks, and progressively authorized
live research follow measured gates. See the [Roadmap](docs/ROADMAP.md).

## Authorized use

Etzio is for locally owned fixtures, historical benchmarks, and targets covered by an exact
bug-bounty scope or written permission. Repository access is not target authorization.
Exploit execution, network egress, spending, credentials, disclosure, and publication each
require their own scoped grant. See [Security](SECURITY.md).

## Project record

- [Session handoff](docs/SESSION_HANDOFF.md) — canonical recovery entrypoint
- [Machine-readable mission state](docs/MISSION_STATE.json)
- [Charter](CHARTER.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Roadmap](docs/ROADMAP.md)
- [2026 frontier baseline](docs/FRONTIER_BASELINE.md)
- [Architecture decisions](docs/decisions/README.md)
- [Contributing](CONTRIBUTING.md)

Etzio is private and solely authored by [Daniel Wahnich](AUTHORS.md).
