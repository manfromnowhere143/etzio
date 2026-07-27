# Etzio Session Handoff

Status: **canonical recovery entrypoint**. Updated 2026-07-27, Asia/Jerusalem.

This file describes Etzio only. It is not authority to access a live target, execute an
exploit, spend money, use credentials, submit a report, or publish the repository. Revalidate
every statement from checked-out bytes and retained evidence.

## Mandatory recovery

```bash
cd /Users/danielwahnich/workspace/etzio
test "$(basename "$(git rev-parse --show-toplevel)")" = "etzio"
git status --short --branch
git log --oneline -6
git remote -v
sed -n '1,320p' docs/SESSION_HANDOFF.md
python3.11 -m venv .venv
.venv/bin/python -m pip install \
  --no-input \
  --require-hashes \
  --only-binary=:all: \
  --requirement tools/ci/requirements-ci.lock
.venv/bin/python -m pip check
ETZIO_PYTHON=.venv/bin/python make verify
```

If `.venv` already contains the exact locked dependencies, skip only environment creation
and installation. Always inspect status and read this handoff. Then read
[README](../README.md), [Charter](../CHARTER.md), [Architecture](ARCHITECTURE.md),
[Roadmap](ROADMAP.md), [Frontier baseline](FRONTIER_BASELINE.md), and
[ADR-0001](decisions/0001-foundation-integrity-before-breadth.md).

Precedence: checked-out Git bytes → reproducible retained evidence → this handoff → chat
memory. A green repository check validates only what it names.

## Project identity

- Workspace: `/Users/danielwahnich/workspace/etzio`
- Engine: **Etzio**
- Canonical branch: `main`
- Foundation predecessor: `542122752701c62a776cba6cc4c712dc86c11041`
- Foundation predecessor tree: `ac1cd687052d004b5668aec142faa2adc791623b`
- Active foundation branch while this packet was written: `agent/repository-foundation`
- Canonical remote: private `https://github.com/manfromnowhere143/etzio`
- Verified default branch: `main`
- Sole author: `Daniel Wahnich <cogitoergosum143@gmail.com>`

The remote was created and its private visibility and default branch were verified on
2026-07-27. Resolve current visibility, checks, and protections from GitHub before relying
on this record. Do not add co-author trailers or automated author commits.

Etzio is independent from Odeya, Sentinel, Aweb, Maestro, Telos, Inbar, and every other
project. A prompt naming Etzio plus a different injected working directory is an identity
mismatch, not permission to work in the other repository.

## Founder intent

Etzio is not a scanner, toy, or one-domain bounty script. It is intended to become an
enterprise-grade operating system for authorized vulnerability research across languages,
vulnerability classes, target categories, and defensive workflows.

The engine should:

- run progressively authorized missions while its capability grows;
- learn transferable strategy from findings, nulls, failures, cost, and reviewer outcomes;
- use bounty acceptance and economic value as one hard external signal;
- preserve scientific, legal, and policy authority outside model workers;
- expand through versioned domain and technique packs without fragmenting the kernel.

Blockchain, Solidity, EVM, and eventually L1/client research are the first benchmark and
economic wedge. They are not the ceiling.

## Mission thesis

A vulnerability is a falsifiable claim: a specific input against a specific target revision
causes a security-relevant effect. A candidate is not a finding. A finding exists only after
a separately identified verifier reproduces the effect from retained bytes in a clean,
authorized environment and the kernel validates the receipt.

The architectural moat is the chain:

```text
exact authority
  → reproducible target
  → falsifiable hypothesis
  → content-bound candidate
  → isolated exploit artifact
  → independent reproduction
  → kernel adjudication
  → evidence-bound disclosure draft
  → governed offline learning
```

## Current implementation truth

The repository currently has:

- dataclass contracts and three JSON Schemas;
- an in-memory mission state and hash-linked event demonstration;
- deterministic skeletons for the ten named units;
- a modeled target and eight-case CATO fixture corpus;
- a standard-library Python AST mapper and six-rule scanner;
- 15 original behavior tests;
- professional repository-policy and CI work on the active branch.

The active repository-foundation branch currently defines 29 tests: 15 original behavior
regressions and 14 repository-policy known-bads. Local CPython 3.11.15 validation, source
and wheel builds, an out-of-checkout wheel smoke test, actionlint, and shellcheck pass.

It does not have:

- one aligned versioned runtime/wire protocol;
- validated, signed, expiring, or revocable authority;
- a durable immutable ledger, pure reducer, replay, or resume;
- a real worker protocol or scheduler;
- stable content-bound candidate identity;
- isolated MARCELLUS construction;
- separately isolated CATO verification;
- kernel-authenticated evidence receipts;
- a real report package, external effect gateway, cockpit, or learning system;
- a live-target adapter or authority for a live mission.

The current code is safer mainly because it has no live adapters, not because the intended
boundaries are enforced.

## Reproduced evidence

Before this tranche, the original repository was independently reproduced under CPython
3.14.2 and CPython 3.11.15:

- 15 tests passed and Ruff was clean under the then-configured rules;
- the demo emitted one modeled finding, two nulls, 16 events, and an intact predecessor
  chain;
- the CATO fixture corpus produced TP=3, FP=0, TN=4, FN=1;
- the vulnerable Python fixture produced seven instances across six rule classes;
- the clean fixture produced zero alerts;
- the package scan produced only intentional-fixture alerts.

These results are synthetic and narrow. They do not establish real-world precision,
authorization enforcement, independent verification, event integrity, isolation, or
superiority. In particular, 0 false positives among four benign cases has a very wide
confidence interval.

## Architecture audit findings

The 2026-07-27 audit reproduced the following blockers:

1. The lifecycle demo and real Python scanner are disconnected. `etzio.scan` accepts a local
   path without AQUILA, `TargetContract`, lifecycle state, or events.
2. `TargetContract` is self-asserted and accepts invalid kinds, blank references, negative
   budgets, and missing expiry/revocation evidence. `mission_opened` precedes admission.
3. CATO directly invokes caller-supplied target behavior in the host process and does not
   independently check `poc_execution` authority.
4. The kernel trusts a caller-supplied verdict. A forged verifier can confirm mismatched or
   false candidates because receipt fields are not validated.
5. `Event.payload` is mutable, the ledger is in-memory, semantic bytes are noncanonical,
   digests are truncated, appends remain possible after closure, and there is no durable
   load/replay/anchor protocol.
6. Runtime `TargetContract` and `Finding` objects do not validate against their checked-in
   schemas.
7. Verification and finding minting execute while lifecycle state is still `construct`;
   `verify` and `adjudicate` are advanced afterward.
8. Scope refusal emits an event and raises but does not persist a `blocked` projection.
9. “Reproduced from bytes” and the environment digest are modeled labels, not retained
   isolated-execution evidence.
10. Budget, wall-clock, egress, credential, spending, disclosure, and kill controls are not
    implemented boundaries.
11. The FPR corpus has only four benign cases; empty metric denominators report misleading
    perfect values; an always-negative verifier passes the `FP == 0` command-line bar.
12. The scanner skips syntax failures in its finding path, lacks interprocedural and alias
    reasoning, may print secret literals, and uses traversal-position candidate IDs.
13. MINERVA returns only counts and prose; there is no evaluated promotion loop.

These findings are why [ADR-0001](decisions/0001-foundation-integrity-before-breadth.md)
places integrity before language or finder expansion.

## Frontier conclusion

Open Kritt demonstrates the commercial value of focused domain workflows, repeat runs,
compiling PoCs, post-validation, and ranking. EVMbench and SCONE-bench demonstrate rapid
progress on executable smart-contract tasks. ReEVMBench demonstrates contamination,
stability, scaffold, and real-incident gaps. BountyBench and CVE-Bench show the importance
and difficulty of broader real systems. Codex Security, Big Sleep, and AIxCC show that deep
context, validation, patching, and expert-guided workflows can produce real defensive value.

Etzio’s legitimate differentiator is the intended combination of exact authority, durable
mission replay, independent proof, domain depth, and governed learning. None is accepted
until Etzio retains its own evidence.

## Current mission order

### Mission A — repository foundation

Finish and integrate:

- exact interpreter and hash-locked dependencies;
- SHA-pinned least-privilege GitHub Actions;
- provenance and repository-policy known-bads;
- honest README, architecture, roadmap, security policy, frontier baseline, and ADR;
- private remote, required checks, and protected `main`.

### Mission B — foundation integrity

Implement the smallest real vertical slice:

1. one versioned runtime/wire protocol;
2. contract admission before mission creation;
3. one real read-only fixture scan through AQUILA and the kernel;
4. canonical full-SHA identities;
5. deeply immutable persisted events;
6. pure deterministic reducer and resume;
7. kernel validation of independent-verifier receipts;
8. known-bad tests for every invariant.

### Mission C — independent proof plane

On a separately authorized Linux/KVM host, build isolated MARCELLUS and CATO workers with
default-deny egress, no ambient credentials, resource ceilings, expiring leases, complete
receipts, and a tested kill path.

### Mission D — blockchain benchmark wedge

Run pinned historical EVMbench, SCONE-bench, and contamination-controlled real-incident
subsets. Measure recall, precision, FPR, FDR, exploit/patch success, stability, cost, and
time. Preserve all excluded, invalid, crashed, timed-out, and negative cases.

### Mission E — progressive authorized research and learning

Admit a specific program contract only after isolation and benchmark gates. Keep every
external effect human-controlled. Promote MINERVA strategy versions offline through frozen
holdouts, regressions, signatures, and rollback.

## Authority state

Authorized in this tranche:

- modify and validate the Etzio repository;
- study public frontier systems and private estate patterns read-only;
- create `manfromnowhere143/etzio` as a private GitHub repository;
- push Daniel-authored Etzio changes and configure repository checks.

Not authorized:

- public visibility;
- deployment;
- live-target interaction;
- exploit execution outside repository-owned deterministic fixtures;
- credential use for a research target;
- spending;
- disclosure, submission, publication, or external messaging.

GitHub credentials used solely to publish the authorized private repository are repository
operations, not mission credentials.

## Continuation standard

Before handoff:

1. inspect the complete diff and all untracked paths;
2. reproduce the declared checks from the hash-locked environment;
3. retain exact test, benchmark, commit, tree, workflow, and remote state;
4. stage only the declared tranche;
5. commit as Daniel without co-author trailers;
6. push through a pull request and verify required checks;
7. update this file and `MISSION_STATE.json`;
8. leave unsupported claims, open risks, and unimplemented components explicit.

Never infer completion from confident prose. Recover from bytes, evidence, and authority.
