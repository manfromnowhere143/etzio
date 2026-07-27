# Etzio Roadmap

Status: 2026-07-27. Etzio is built through dependency-complete proofs. A phase advances only
when its acceptance evidence is retained; a green structural check does not waive a
scientific or authority gate.

## Governing scorecard

No single metric governs vulnerability research. Every benchmark tranche reports:

- recall over eligible ground-truth vulnerabilities;
- precision and false-discovery rate over adjudicated candidates;
- false-positive rate over labeled benign cases;
- exploit and patch success where the task supports them;
- coverage failures, invalid tasks, crashes, and nondeterminism;
- best-of-*k* and pass@*k* separately from single-run performance;
- wall time, model/tool cost, compute cost, and human review time;
- duplicate rate and accepted economic value for authorized bounty missions.

Empty denominators are `undefined`, never perfect scores. Confidence intervals accompany
rates, and target-, harness-, model-, and date-specific results are never generalized
silently.

## Phase 0 — modeled foundation

Status: **implemented narrowly; not accepted as the target architecture**.

The repository has a state-machine demonstration, in-memory event chain, ten typed unit
stubs, a tiny labeled verdict corpus, and a six-rule Python AST analyzer. The original 15
tests pass. This phase established vocabulary and exposed the real trust-boundary work.

## Phase 0A — professional repository foundation

Status: **in progress on `agent/repository-foundation`**.

- exact CPython patch and hash-locked validation dependencies;
- SHA-pinned, least-privilege CI with retained logs;
- repository policy known-bads;
- sole-author provenance enforcement;
- canonical bootstrap, handoff, architecture decisions, and evidence-bounded documentation;
- private `manfromnowhere143/etzio` remote and protected `main`.

Acceptance: the declared Python matrix reproduces all checks from a clean locked
environment, the private remote is verified, and required GitHub checks pass.

## Phase 0B — foundation integrity

Status: **next implementation mission**.

Deliver one real read-only fixture scan through a truthful control path:

1. freeze one versioned runtime/wire protocol;
2. validate and admit an exact benchmark authority before `mission_opened`;
3. issue a scoped scan lease through AQUILA;
4. bind target, candidate, artifact, and event identities to canonical full-SHA bytes;
5. persist deeply immutable events with compare-and-append and terminal closure;
6. rebuild state through a pure reducer and resume after interruption;
7. validate verifier receipts in the kernel rather than trusting a Python object;
8. retain denial, timeout, cancellation, crash, invalid, and non-reproduction distinctly.

Acceptance includes known-bads for malformed/blank/expired/wrong-target authority, mutation,
reordering, truncation, forked heads, append-after-close, unstable IDs, self-verification,
mismatched candidates, forged receipts, and missing evidence.

## Phase 1 — independent proof plane

Status: **proposed; blocked on Linux/KVM execution infrastructure**.

- package immutable target, toolchain, PoC, and oracle bytes;
- build MARCELLUS and CATO as separate worker identities;
- evaluate Firecracker, gVisor, and Kata against Etzio’s syscall, performance, tenancy, and
  evidence requirements;
- default-deny egress, remove ambient credentials, enforce ceilings and expiring leases;
- produce complete signed execution receipts;
- demonstrate out-of-band termination and cleanup under known-bad workloads.

Acceptance: CATO independently reproduces a planted exploit and rejects substituted,
producer-forged, non-impactful, nondeterministic, escaped, timed-out, and policy-denied
cases. Host and guest compromise assumptions are explicit.

## Phase 2 — benchmark-first blockchain wedge

Status: **proposed**.

Use pinned historical tasks only:

- EVM/Solidity surface and build adapter;
- versioned smart-contract hypothesis and oracle pack;
- EVMbench Detect, Patch, and Exploit subsets;
- SCONE-bench and a contamination-controlled real-incident holdout;
- negative contracts and semantics-preserving patch tests;
- report generation from retained evidence only.

Acceptance: end-to-end admitted target → candidate → isolated proof → verdict → finding/null
→ disclosure draft, with reproducible scorecards and no hidden task exclusions.

## Phase 3 — research depth and swarm

Status: **proposed**.

- SCIPIO attack-surface graph and change-aware incremental analysis;
- FABIUS information-gain and domain-conditioned hypothesis ranking;
- diverse, leased VELITES workers with controlled ablations;
- CAMILLUS root-cause deduplication, severity calibration, and review queues;
- experiment registry for prompts, models, tools, pack versions, and budgets.

Parallelism is earned only when it improves confirmed findings per unit cost without
degrading precision, isolation, or reproducibility.

## Phase 4 — progressively authorized missions

Status: **not authorized**.

Progression is per target and reversible:

1. local historical benchmark;
2. read-only source under exact permission;
3. passive or program-approved analysis;
4. isolated dynamic proof against a local replica;
5. narrowly approved live interaction;
6. human-reviewed disclosure draft;
7. one-time human-authorized submission.

Each program’s current scope, automation rules, exclusions, rate limits, safe harbor, target
revision, disclosure channel, and reward policy are captured in the admitted authority.
Bounty revenue, duplicate rate, triage acceptance, time-to-confirm, and reviewer burden are
measured without sacrificing negative-result visibility.

## Phase 5 — governed learning and category expansion

Status: **proposed**.

MINERVA creates candidate strategy versions from mission evidence. Promotion requires
frozen training/evaluation splits, contamination checks, shadow runs, regression suites,
cost and stability measurements, human review, signed release, and rollback.

Category expansion then proceeds through domain packs: blockchain clients, web and APIs,
cloud/IAM, native memory safety, mobile, supply chain, configuration, protocol and
distributed-systems logic. Each pack brings its own authority vocabulary, environment,
oracles, threat model, negative fixtures, and benchmark evidence.

## Deliberate exclusions

- No live target is inferred from a repository URL or bounty listing.
- No exploit execution occurs on the macOS host or in an ordinary developer container.
- No model, worker, or verifier approves its own consequential effect.
- No self-modification path edits policy, evaluators, labels, or production bytes.
- No result is called state of the art without a dated comparator and retained run evidence.
