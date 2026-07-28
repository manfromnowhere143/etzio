# Etzio Session Handoff

Status: **canonical recovery entrypoint**. Updated 2026-07-28, Asia/Jerusalem.

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
[ADR-0002](decisions/0002-canonical-governed-fixture-boundary.md),
[ADR-0003](decisions/0003-semantic-wire-schema-and-typed-kind-closure.md), and
[ADR-0004](decisions/0004-kernel-issued-verification-leases.md), and
[ADR-0005](decisions/0005-typed-verification-artifact-resolution.md), and
[ADR-0006](decisions/0006-atomic-modeled-receipt-admission.md).

Precedence: checked-out Git bytes → reproducible retained evidence → this handoff → chat
memory. A green check validates only what it names.

## Repository identity

- Workspace: `/Users/danielwahnich/workspace/etzio`
- Engine: **Etzio**
- Canonical branch: `main`
- Current foundation-integrity branch: `agent/atomic-receipt-adjudication-v1`
- Stacked on: `agent/typed-cas-receipt-evidence-v1`
- Branch base: `1e0c8ad271f19acfd862cc3dba3bd9502bed638b`
- Branch-base tree: `4782fec37a6384298ef188f92dd6e4e4801b4816`
- Canonical remote: private `https://github.com/manfromnowhere143/etzio`
- Sole author: `Daniel Wahnich <cogitoergosum143@gmail.com>`

Resolve the current branch head, pull request, workflow state, visibility, and default branch
from Git and GitHub. Do not infer them from this dated packet.

The private remote and `main` default branch were verified on 2026-07-28. Read-only Actions
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
- installed semantic wire schemas and typed dispatch for every supported object kind;
- exact closed-field schema/runtime parity for all nine semantic bodies and all fifteen
  event kind, unit, and payload forms;
- Unicode 17.0.0 NFC, signed 64-bit integers, and fixed resource ceilings;
- full domain-separated SHA-256 object and event identities;
- Ed25519 signed authority grants and self-verifying admission records;
- prime-subgroup trust-key validation for configured and embedded snapshots;
- exact clean/vulnerable fixture manifests and content-addressed evidence;
- bounded analysis leases and stable candidate/claim identities;
- byte-bound Python AST analysis with no production filesystem walker;
- lifecycle-validated append-only SQLite storage and deterministic replay;
- kernel-issued verification leases under the exact admitted
  `modeled_fixture_verification` grant;
- complete verifier trust and revocation evidence retained with each issuance;
- replay-checked authority, target, candidate, producer, verifier, key,
  `issuance_trust_snapshot_id`, time, and expiry bindings;
- type-domain-separated CAS identities for each modeled PoC, supporting-evidence,
  environment, and effect-oracle specification input;
- code-owned role-to-type resolution for every target and verification-input byte under a
  fixed aggregate bound shared with the grant's one signed `max_bytes` ceiling;
- one canonical `verification_artifacts_resolved` event per lease with replay, retry,
  crash-recovery, and concurrent-writer controls;
- type-domain-separated identities for modeled execution, effect, measured-environment,
  and termination outputs;
- a canonical signed receipt binding the retained resolution plus each output's exact
  digest and positive bounded size;
- authentication-first receipt checks under a retained decision trust/revocation snapshot,
  followed by fixed-order target, input, and output CAS revalidation;
- one `verifier_receipt_admitted` event that atomically retains the complete modeled
  decision and records single-use lease consumption;
- a dedicated receipt-admission store path that repeats current-CAS validation from locked
  retained history before insertion, while generic append rejects the reserved event;
- CAS-free exact committed retry, crash recovery, one bounded SQLite-contention retry,
  same-receipt reconciliation when an identical commit becomes visible, retryable
  `StoreBusyError` on persistent `BUSY` or `LOCKED`, conflicting-receipt refusal, and
  distinct-lease stale-head semantics;
- nonterminal `awaiting_verification` lifecycle state for verification-intent missions;
- fail-closed refusal, cancellation, failure, timeout, budget, completion, and closure;
- recoverable deterministic fixture scans without duplicate outputs; and
- a supported fixture-only CLI that emits candidates and never findings.

### Implemented for modeled receipt admission

- canonical one-attestation signed verifier receipts;
- exact receipt/lease/resolution/output-digest/output-size/time/verdict bindings and
  resource ceilings;
- distinct issuance- and proposal-time trust snapshot identities in modeled receipt
  proposals; and
- matching typed-resolution and current-CAS revalidation before a positive standalone
  modeled proposal or first canonical admission.

Lease issuance records an authorized modeled assignment, and resolution records exact
predeclared input bytes and roles. Receipt admission authenticates and atomically retains a
configured modeled statement while consuming its lease. Its four output artifacts are
opaque typed bytes grouped by one signature. This does not establish that an execution
occurred, that one run produced the outputs, that their contents are true, or that the
verifier was independent or isolated. It does not mint a finding.

### Retained behavior models

The original in-memory `MasterLoop`, ten unit stubs, `BenchmarkTarget`, and eight-case
verdict/FPR corpus remain regression models. Their findings, verifier labels, environment
digests, and event chain are not evidence of the protocol-v1 architecture.

## Reproduced local evidence

On the current candidate bytes, `make verify` passed under both CPython 3.11.15 and
CPython 3.14.2:

- 463 tests passed;
- Ruff was clean;
- the installed semantic protocol schema, three explicitly modeled legacy schemas, and
  repository policy passed;
- the built wheel loaded and metaschema-checked the canonical protocol schema outside the
  checkout;
- the governed vulnerable fixture closed with seven candidates and no finding;
- the governed clean fixture closed with zero candidates; and
- both modeled regression demonstrations retained their historical outputs.

The hash-locked environments passed `pip check`. This evidence remains fixture-scoped and
must be reproduced by GitHub Actions for the pushed commit.

## Closed adversarial findings in this tranche

Known-bads now cover:

- cross-runtime Unicode identity divergence;
- duplicate/noncanonical/oversized protocol values;
- arbitrary semantic bodies, missing/unknown per-kind fields, forbidden or multiple
  attestations, schema/runtime dispatch drift, and malformed identifier anchors;
- root/body field removal, body reopening, case-reference substitution, and attestation
  policy weakening against the repository schema gate;
- Python/ECMA-262 edge-whitespace divergence and portable U+001C–U+001F, U+0085, and U+FEFF
  behavior;
- the untyped `head_checkpoint` name and literal `"."` relative paths;
- malformed signed-grant Base64 before authority admission;
- semantically invalid signed-grant wire production/parsing without changing
  authentication-first admission refusal precedence;
- schema-valid/runtime-invalid ordering, field-keyed target/trust uniqueness, time,
  derived-identity, nested-binding, and canonical-wire controls;
- forged, revoked, wrong-role, wrong-issuer, expired, and wrong-target authority;
- small-order Ed25519 keys in configured and embedded trust snapshots;
- target artifact, size, path, mode, symlink, and manifest substitution;
- analysis/verification lease object-kind confusion;
- hard-linked event-store aliasing, event fork, gap, mutation, illegal transition, wrong
  unit, and post-terminal append;
- action substitution and byte/time/output budget overflow before persistence;
- candidate mission/authority/lease/source substitution;
- receipt signature, verifier, lease, resolution, verdict, time, output digest, and signed
  output-size substitution;
- verification issuance without the exact admitted action, against an unknown or substituted
  candidate, under a malformed/substituted trust snapshot, to the candidate producer, or
  to an unknown, revoked, or wrong-role verifier key;
- verification lease target, authority, time, expiry, event-unit, and conflicting
  reissuance substitution;
- issuance-trust identity substitution, decision-trust separation, and post-commit
  different-candidate interleaving;
- oversized receipt/trust/revocation/evidence collections;
- unknown or substituted artifact types, generic/typed digest confusion, missing or
  corrupted typed inputs, target-resolution mismatch, cross-role aliasing, and aggregate
  resolved-byte overflow;
- oversized write rejection before digest work, manifest-sized target reads, native atomic
  no-clobber publication, paused-publisher convergence, directory durability, unsupported
  publication primitives, and preservation of preexisting names;
- reuse of one signed byte ceiling as multiple action budgets;
- forged, partial, reordered, stale, expired, or conflicting per-lease resolution events;
- exact resolution retry, crash-after-append recovery, concurrent convergence, and
  post-event CAS disappearance;
- caller-selected unsigned resolution contexts promoted beyond non-authoritative proposal
  status, noncausal resolution/receipt times, and consequential receipt refusals that would
  otherwise reach CAS reads;
- missing, empty, corrupt, wrong-type, swapped, colliding, individually oversized,
  aggregate-oversized, or signed-size-mismatched modeled output artifacts;
- unattested, multiply attested, malformed, forged, revoked, wrong-role, or substituted
  receipt-admission decision evidence;
- receipt reuse, lease double consumption, exact committed retry after CAS loss and head
  advancement, identical and conflicting submission races, and distinct-lease stale-head
  races;
- bounded SQLite writer contention, identical-commit reconciliation after one retry, and
  retryable `StoreBusyError` exhaustion without a corruption classification;
- generic and direct-internal append bypass, receipt-event/evidence-store pairing mismatch,
  wrong-kind dedicated append, direct undersized-output event injection, and rollback with
  unchanged history on dedicated CAS validation failure;
- crash-after-append replay without duplicate candidates;
- late recovery before lease issuance and completed-scan closure after grant/trust
  changes; and
- the former arbitrary local-path CLI escape hatch.

## Open foundation-integrity blockers

1. Issued leases have no canonical expiry, cancellation, supersession, reassignment, or
   terminal recovery event.
2. Authority/verifier clock and revocation snapshot freshness are not externally proved.
3. SQLite event heads are not externally authenticated or anchored.
4. The filesystem CAS and SQLite event commit do not share one transaction; bytes can
   disappear after the dedicated append validates them.
5. SQLite retains a documented same-user pathname race.
6. Modeled output artifacts are opaque signed descriptors, not structured evidence tied to
   an independently measured execution identity.
7. Separate verifier labels and keys do not prove separate principals, processes, or
   isolation.
8. MARCELLUS/CATO Linux/KVM execution, live adapters, learning, cockpit, and domain packs
   are not implemented.

These blockers prevent a finding pipeline and all live-target work.

## Current mission order

### Mission 1 — close finding-admission integrity

Next, define canonical lease expiry, cancellation, supersession, reassignment, and terminal
recovery. Then close trusted time, revocation freshness, and authenticated external head
anchoring with concurrency and substitution known-bads. Atomic filesystem-CAS/SQLite
retention and closure of the same-user pathname race also remain mandatory before a finding
pipeline can be accepted.

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
