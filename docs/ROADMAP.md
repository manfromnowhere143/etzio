# Etzio Roadmap

Status: **architecture foundation**, updated 2026-07-27.

The roadmap advances by retained evidence, not calendar dates. A phase may start only when
its predecessor’s named acceptance conditions are reproduced.

## Phase 0 — repository foundation

Status: **implemented**.

Evidence in the private repository:

- sole-author provenance policy;
- exact CPython patch matrix and hash-locked dependencies;
- least-privilege GitHub Actions pinned to immutable commit SHAs;
- repository-policy known-bads and retained CI logs;
- private remote, charter, security policy, architecture, frontier baseline, handoff, and
  machine-readable mission state.

Operational limitation: GitHub branch protection and repository rulesets were unavailable
for this private repository on the current account plan when checked on 2026-07-27. CI and
review discipline therefore remain procedural controls; public visibility is not an
acceptable workaround.

## Phase 1 — foundation integrity

Status: **running**.

### 1A. Governed candidate-generation slice

Status: **implemented for repository fixtures**.

- common protocol-v1 envelope and canonical JSON;
- full content-bound identities;
- signed, expiring, revocable authority admission before mission opening;
- prime-subgroup Ed25519 trust-key validation;
- private content-addressed target evidence;
- exact manifest-backed clean and vulnerable fixtures;
- bounded analysis leases;
- stable, source-minimized static candidates;
- lifecycle-validated compare-and-append SQLite events;
- deterministic replay, interruption recovery, and distinct terminal states;
- supported CLI with no arbitrary target path; and
- known-bads for cryptographic, protocol, authority, evidence, lifecycle, budget,
  filesystem, and replay failures.

This slice emits candidates only.

### 1B. Finding-admission integrity

Status: **running**.

Implemented in this phase:

- installed semantic per-kind wire schemas for all nine typed objects and all fourteen event
  variants;
- runtime/schema dispatch parity plus schema-expressible and runtime-only known-bads; and
- fail-closed rejection of untyped reserved kinds, malformed signed-grant encoding, and
  `"."` relative paths;
- kernel-issued verification leases under the exact admitted
  `modeled_fixture_verification` grant;
- retained verifier trust and revocation evidence with exact candidate, producer, target,
  authority, verifier, key, issuance-trust identity, time, and expiry bindings; and
- a replayable nonterminal `awaiting_verification` state with substitution and conflicting
  reissuance known-bads;
- type-domain-separated CAS identities for the PoC, supporting-evidence, environment, and
  effect-oracle specification roles;
- canonical per-lease resolution of every target and verification-input byte with exact
  role, type, size, order, time, and retained-state bindings; and
- replay, current-CAS revalidation, aggregate-bound, substitution, crash, retry, and
  concurrent-writer known-bads for the resolution boundary.

Remaining required:

1. canonical retention of receipt decision inputs, signed receipt, and adjudication;
2. atomic receipt acceptance and single-use lease consumption under concurrent writers;
3. separately content-bound execution, effect, measured-environment, and termination
   outputs;
4. explicit lease expiry, cancellation, supersession, and terminal recovery semantics;
5. trusted time and revocation freshness;
6. authenticated, externally anchored event heads; and
7. known-bads for every new refusal, substitution, replay, and concurrency condition.

Acceptance: an authority-bound modeled verification assignment and every predeclared input
can be resolved and retained today. A modeled receipt can produce only a standalone
proposal after matching that resolution and revalidating CAS bytes; no receipt or
finding-admission claim is accepted until the remaining conditions above are retained and
replayable.

## Phase 2 — independent proof plane

Status: **blocked on an explicitly authorized Linux/KVM environment and Phase 1B**.

Build separately identified MARCELLUS and CATO workers:

- immutable, measured images and exact toolchains;
- read-only target and artifact inputs;
- no ambient host credentials;
- default-deny egress with separately granted destinations;
- ephemeral writable layers;
- CPU, memory, process, storage, and wall-clock ceilings;
- syscall/device restrictions;
- expiring one-purpose leases;
- complete stdout, stderr, effect, environment, and termination receipts;
- out-of-band cancellation and kill; and
- adversarial escape, confusion, stale-lease, replay, and teardown tests.

Acceptance is evidence that builder and verifier differ by principal, key, process, and
isolation boundary—not merely by label.

## Phase 3 — benchmark-first blockchain wedge

Status: **proposed**.

Build the first domain pack around pinned historical Solidity/EVM tasks and later
blockchain-client cases. Candidate benchmark sources include EVMbench, SCONE-bench,
ReEVMBench, and carefully licensed historical incident subsets.

The benchmark manifest must retain:

- exact upstream revision, license/terms, acquisition digest, and build environment;
- contamination and prior-exposure annotations;
- labeled positive, negative, invalid, excluded, and unsupported cases;
- deterministic effect oracles independent of generated prose;
- repeated-run stability;
- tool/model/configuration version;
- compute, time, and failure accounting; and
- all raw candidate, PoC, verifier, and adjudication receipts.

Primary measures:

- eligibility and coverage;
- precision, recall, false-positive rate, and false-discovery rate;
- exploit reproduction and patch success where applicable;
- duplicate and invalid-result rates;
- run-to-run stability;
- time, compute, and reviewer burden; and
- category-level failure analysis.

No benchmark result is generalized beyond its named corpus, comparator, configuration, and
date.

## Phase 4 — progressive authorized research

Status: **proposed**.

Progression is target-specific and reversible:

1. local historical benchmark;
2. read-only source under exact permission;
3. passive or program-approved analysis;
4. isolated dynamic proof against a local replica;
5. narrowly approved live interaction;
6. human-reviewed disclosure draft; and
7. one-time human-authorized submission.

Every program snapshot records current scope, assets, exclusions, automation rules, rate
limits, safe harbor, revision, disclosure channel, and reward policy. Bounty acceptance and
economic value are measured outcomes, never authority.

## Phase 5 — governed learning and category expansion

Status: **proposed**.

MINERVA may propose strategy versions from findings, contradictions, nulls, failures, costs,
and reviewer outcomes. Promotion requires frozen train/evaluation partitions, contamination
checks, shadow runs, positive and negative regressions, stability/cost analysis, human
review, signature, rollout limits, and rollback.

Learning cannot directly edit authority policy, evaluators, benchmark labels, production
bytes, or its own promotion gate.

Category expansion then proceeds through versioned domain packs: blockchain clients, web
and APIs, cloud/IAM, native memory safety, mobile, supply chain, configuration, and protocol
or distributed-systems logic.

## Deliberate exclusions

- No live target is inferred from a URL, repository, credential, or bounty listing.
- No exploit execution occurs on the macOS host or in an ordinary developer container.
- No generator or verifier approves its own consequential effect.
- No timeout, missing review, or retry exhaustion implies approval.
- No self-modification path controls policy, evaluators, labels, or production.
- No result is described as safe, autonomous, solved, production-ready, or state of the art
  without a named benchmark, comparator, scope, date, and retained evidence.
