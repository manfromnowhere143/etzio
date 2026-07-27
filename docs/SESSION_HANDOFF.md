# Etzio Session Handoff

Status: **canonical recovery entrypoint**. Updated 2026-07-27, Asia/Jerusalem.

This file describes Etzio only. It is not authority to access a live target, execute an
exploit, use research credentials, spend, disclose, publish, deploy, or change repository
visibility. Revalidate every statement from checked-out bytes and retained evidence.

## Mandatory recovery

```bash
cd /Users/danielwahnich/workspace/etzio
test "$(basename "$(git rev-parse --show-toplevel)")" = "etzio"
git status --short --branch
git log --oneline -6
git remote -v
sed -n '1,360p' docs/SESSION_HANDOFF.md
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
and installation. Status, handoff reading, and validation remain mandatory. Then read
[README](../README.md), [Charter](../CHARTER.md), [Architecture](ARCHITECTURE.md),
[Roadmap](ROADMAP.md), [Frontier baseline](FRONTIER_BASELINE.md), [ADR-0001](decisions/0001-foundation-integrity-before-breadth.md),
and [ADR-0002](decisions/0002-canonical-governed-fixture-boundary.md).

Precedence: checked-out Git bytes → reproducible retained evidence → this handoff → chat
memory. A green check validates only what it names.

## Repository identity

- Workspace: `/Users/danielwahnich/workspace/etzio`
- Engine: **Etzio**
- Canonical branch: `main`
- Current foundation-integrity branch: `agent/foundation-integrity-v1`
- Branch base: `745e860f9db25691b285834853fe23aa2ec73840`
- Branch-base tree: `42d8401e90900cfdf5e81ba415fdc44d9c51a98f`
- Canonical remote: private `https://github.com/manfromnowhere143/etzio`
- Sole author: `Daniel Wahnich <cogitoergosum143@gmail.com>`

Resolve the current branch head, pull request, workflow state, visibility, and default branch
from Git and GitHub. Do not infer them from this dated packet.

The private remote and `main` default branch were verified on 2026-07-27. Read-only Actions
permissions, SHA-pinned actions, squash-only merging, and automatic branch deletion were
configured. GitHub branch protection/rulesets were unavailable for this private repository
on the current account plan; never change visibility to obtain them.

Etzio is independent from Odeya, Sentinel, Aweb, Maestro, Telos, Inbar, and every other
project. A prompt naming Etzio while the injected working directory names another project
is an identity mismatch that must be resolved before acting.

## Founder intent

Etzio is intended to become an enterprise-grade operating system for authorized
vulnerability research—not a scanner, toy, or single bounty script.

The engine should:

- span vulnerability classes, languages, target categories, and defensive workflows;
- run progressively authorized missions while capability grows;
- treat accepted bounty outcomes as one external economic signal, never as authority;
- preserve findings, contradictions, nulls, failures, cost, and reviewer outcomes;
- keep scientific and policy authority outside generative workers; and
- expand through versioned domain and technique packs without fragmenting the kernel.

Blockchain, Solidity, EVM, and later L1/client research are the first benchmark and economic
wedge. They are not the ceiling.

## Mission thesis

A candidate is a falsifiable claim about exact target bytes. It becomes a finding only
after a separately authorized verifier reproduces a material effect from retained artifacts
inside an independently controlled environment and the kernel accepts the complete receipt.

```text
exact authority
  → immutable target
  → falsifiable hypothesis
  → content-bound candidate
  → isolated exploit artifact
  → independent reproduction
  → kernel adjudication
  → evidence-bound disclosure draft
  → governed offline learning
```

## Current implementation truth

### Implemented for the repository-fixture scan

- common protocol-v1 envelopes and strict canonical JSON;
- Unicode 17.0.0 NFC, signed 64-bit integers, and fixed resource ceilings;
- full domain-separated SHA-256 object and event identities;
- Ed25519 signed authority grants and self-verifying admission records;
- prime-subgroup trust-key validation for configured and embedded snapshots;
- exact clean/vulnerable fixture manifests and content-addressed evidence;
- bounded analysis leases and stable candidate/claim identities;
- byte-bound Python AST analysis with no production filesystem walker;
- lifecycle-validated append-only SQLite storage and deterministic replay;
- fail-closed refusal, cancellation, failure, timeout, budget, completion, and closure;
- recoverable deterministic fixture scans without duplicate outputs; and
- a supported fixture-only CLI that emits candidates and never findings.

### Implemented as modeled contract primitives only

- distinct verification leases;
- verifier trust snapshots and revocations;
- canonical one-attestation signed verifier receipts;
- exact receipt/lease/digest/time/verdict bindings and resource ceilings.

Receipt validation authenticates a configured modeled statement. It does not establish
kernel issuance, CAS evidence, atomic single use, actual independence, isolation, or a
finding.

### Retained behavior models

The original in-memory `MasterLoop`, ten unit stubs, `BenchmarkTarget`, and eight-case
verdict/FPR corpus remain regression models. Their findings, verifier labels, environment
digests, and event chain are not evidence of the protocol-v1 architecture.

## Reproduced local evidence

On the current candidate bytes, `make verify` passed under both CPython 3.11.15 and
CPython 3.14.2:

- 290 tests passed;
- Ruff was clean;
- all four JSON Schemas and repository policy passed;
- the governed vulnerable fixture closed with seven candidates and no finding;
- the governed clean fixture closed with zero candidates; and
- both modeled regression demonstrations retained their historical outputs.

The hash-locked environments passed `pip check`. This evidence remains fixture-scoped and
must be reproduced by GitHub Actions for the pushed commit.

## Closed adversarial findings in this tranche

Known-bads now cover:

- cross-runtime Unicode identity divergence;
- duplicate/noncanonical/oversized protocol values;
- forged, revoked, wrong-role, wrong-issuer, expired, and wrong-target authority;
- small-order Ed25519 keys in configured and embedded trust snapshots;
- target artifact, size, path, mode, symlink, and manifest substitution;
- analysis/verification lease object-kind confusion;
- hard-linked event-store aliasing, event fork, gap, mutation, illegal transition, wrong
  unit, and post-terminal append;
- action substitution and byte/time/output budget overflow before persistence;
- candidate mission/authority/lease/source substitution;
- receipt signature, verifier, lease, verdict, time, and digest substitution;
- oversized receipt/trust/revocation/evidence collections;
- crash-after-append replay without duplicate candidates;
- late recovery before lease issuance and completed-scan closure after grant/trust
  changes; and
- the former arbitrary local-path CLI escape hatch.

## Open foundation-integrity blockers

1. `protocol.v1.schema.json` validates framing, not semantic per-kind bodies.
2. Verification leases are not issued by the kernel under an admitted
   `modeled_fixture_verification` grant.
3. Receipt digest membership does not resolve and type-check retained CAS bytes.
4. Receipt acceptance and lease consumption are not one atomic durable transaction.
5. Complete receipt adjudication is not part of canonical mission history.
6. Authority/verifier clock and revocation snapshot freshness are not externally proved.
7. SQLite event heads are not externally authenticated or anchored.
8. SQLite retains a documented same-user pathname race.
9. Separate verifier labels and keys do not prove separate principals, processes, or
   isolation.
10. MARCELLUS/CATO Linux/KVM execution, live adapters, learning, cockpit, and domain packs
    are not implemented.

These blockers prevent a finding pipeline and all live-target work.

## Current mission order

### Mission 1 — close finding-admission integrity

Implement semantic schemas, kernel-issued verification leases, typed CAS resolution,
atomic receipt acceptance/single-use consumption, canonical adjudication history, trusted
time, and authenticated external head anchoring. Add concurrency and substitution
known-bads.

### Mission 2 — independent proof plane

On a separately authorized Linux/KVM host, prove MARCELLUS/CATO separation with immutable
inputs, default-deny egress, no ambient credentials, resource ceilings, expiring leases,
complete receipts, and an out-of-band kill path.

### Mission 3 — blockchain benchmark wedge

Run pinned, licensed, contamination-controlled historical EVM/Solidity benchmarks. Retain
eligibility, exclusions, all negative/error outcomes, repeated-run stability, precision,
recall, FPR/FDR, exploit and patch success, compute, time, and reviewer burden.

### Mission 4 — progressive authorized research and learning

Admit one exact program only after the integrity, isolation, and benchmark gates. Keep
external effects human-authorized. Promote MINERVA strategy versions offline through frozen
holdouts, regressions, signatures, and rollback.

## Authority state

Authorized:

- modify, validate, commit, and push this Etzio repository;
- use repository-owned deterministic fixtures;
- inspect public research and other estate repositories read-only for patterns;
- operate the private `manfromnowhere143/etzio` GitHub repository.

Not authorized:

- public visibility or deployment;
- live-target interaction;
- execution of unknown or third-party exploit/build material;
- research credentials or sensitive target data;
- spending;
- disclosure, submission, publication, or external messaging.

GitHub credentials used only for the authorized private repository are repository
operations, not research-target credentials.

## Handoff standard

Before handing off:

1. inspect all modified and untracked paths;
2. reproduce the suite from the hash-locked environment on both declared runtimes;
3. validate schemas, package build, wheel install, shell/workflow checks, and Git diff;
4. stage only the declared tranche;
5. commit as Daniel without co-author trailers;
6. push to the private remote and inspect GitHub Actions;
7. update this file and `MISSION_STATE.json`; and
8. report exact residuals without promoting modeled behavior to implemented status.
