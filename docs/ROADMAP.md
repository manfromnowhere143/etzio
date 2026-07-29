# Etzio Roadmap

Status: **architecture foundation**, updated 2026-07-29.

The roadmap advances by retained evidence, not calendar dates. A phase may start only when
its predecessor’s named acceptance conditions are reproduced.

## Phase 0 — repository foundation

Status: **implemented**.

Evidence in the private repository:

- sole-author provenance policy;
- exact CPython patch matrix and hash-locked dependencies;
- isolated and repository-context agreement on the runtime-reported SQLite version and
  source ID in retained verification output;
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
- bounded private content-addressed staging/cache plus canonical transactional target
  retention in the SQLite evidence vault;
- exact manifest-backed clean and vulnerable fixtures;
- bounded analysis leases;
- stable, source-minimized static candidates;
- lifecycle-validated compare-and-append SQLite events under one matrix-wide
  rollback-journal `DELETE`/`EXTRA` policy;
- deterministic replay, interruption recovery, and distinct terminal states;
- supported CLI with no arbitrary target path; and
- known-bads for cryptographic, protocol, authority, evidence, lifecycle, budget,
  filesystem, and replay failures.

This slice emits candidates only.

### 1B. Finding-admission integrity

Status: **running**.

Implemented in this phase:

- pre-open refusal of persistent WAL state, exact upstream WAL-fix classification,
  explicit SQLite 3.37 minimum/major-version admission, and known-bads proving fixed and
  affected accessors cannot choose different journal policies;
- fail-closed authentication of the exact journal, synchronization, foreign-key,
  trusted-schema, CHECK-enforcement, read-isolation, and writable-schema settings on
  cached replay and every writer boundary;
- exact SQLite `application_id = 0x45545A31` (ASCII `ETZ1`) and `user_version = 2`,
  strict append-only evidence, event-role, integrity-phase, and integrity-evidence tables,
  full schema-shape validation, an exact version-1-to-version-2 legacy-layout migration,
  and explicit refusal to promote any nonempty legacy history into integrity finality;
- one canonical evidence vault transaction that derives artifact manifests in code and
  commits exact immutable BLOBs, complete role mappings, and the event together for
  `authority_admitted`, `mission_opened`, `verification_artifacts_resolved`, and
  `verifier_receipt_admitted`;
- staging-independent committed replay and exact retry, canonical-vault-first reuse, and
  fail-closed corruption handling that never substitutes otherwise-valid staging bytes;
- fixed authority, target, resolution, output, and aggregate grant bounds plus a default
  1 GiB configurable per-opening logical evidence ceiling covering unique vault BLOBs and
  modeled-integrity profile, phase-record, and provider-evidence bytes, with conservative
  finality reservation and without treating physical deduplication as a mission budget
  discount;
- installed semantic per-kind wire schemas for all eleven typed objects and all eighteen event
  variants;
- runtime/schema dispatch parity plus schema-expressible and runtime-only known-bads; and
- fail-closed rejection of arbitrary semantic bodies, missing required attestations,
  malformed signed-grant encoding, and `"."` relative paths;
- kernel-issued verification leases under the exact admitted
  `modeled_fixture_verification` grant;
- retained verifier trust and revocation evidence with exact candidate, producer, target,
  authority, verifier, key, issuance-trust identity, time, and expiry bindings; and
- a replayable nonterminal `awaiting_verification` state with substitution and conflicting
  reissuance known-bads;
- type-domain-separated content identities for the PoC, supporting-evidence, environment, and
  effect-oracle specification roles;
- canonical per-lease resolution of every target and verification-input byte with exact
  role, type, size, order, time, and retained-state bindings; and
- vault-first/staging-on-absence resolution, aggregate-bound, substitution, injected
  caller-failure, retry, and concurrent-writer known-bads for the resolution boundary;
- signed receipt binding of the exact retained resolution plus four distinct execution,
  effect, measured-environment, and termination output digest/size pairs;
- fixed-order vault-first resolution of every output during canonical admission under a
  code-owned type and the authority grant's one non-resetting byte ceiling;
- one canonical receipt-admission event retaining the exact signed receipt, decision trust
  snapshot, adjudication profile, and derived output bindings;
- atomic single-use lease consumption, staging-independent committed retry, deterministic
  conflicting receipt refusal after a competing commit is visible, and bounded one-retry
  reconciliation of identical submissions under SQLite contention;
- retryable `StoreBusyError` classification for SQLite `BUSY` or `LOCKED`, without
  reclassifying bounded-contention exhaustion as corruption; and
- reducer, schema, repository-policy, signature, revocation, substitution, byte-budget,
  staging-loss, direct-append, injected caller-failure, retry, and concurrency known-bads
  for modeled-receipt admission;
- explicit ETZIO lease-expiry and AQUILA modeled-cancellation events with closed reasons
  and no implicit wall-clock replay transition;
- one nonbranching candidate lease lineage with atomic supersession/reassignment to a
  different verifier, immutable work bindings, retained successor-issuance trust evidence,
  and non-resetting authority deadlines and lease-count ceilings;
- active-only artifact resolution and receipt admission, with predecessor resurrection
  rejected after expiry, cancellation, reassignment, or consumption; and
- exact `receipt_coverage_complete` or `receipt_coverage_incomplete` terminal recovery with
  active, covered, never-assigned, latest-expired, and latest-cancelled candidate
  partitions;
- required-attestation `integrity_decision` and `head_checkpoint` contracts with exact
  proposed-event binding, conservative time intervals, typed provider evidence,
  versioned revocation views, exact signed-decision and checkpoint-predecessor provenance,
  distinct decision/checkpoint principals, pre-receipt anchor statements, conservative
  cross-transition temporal ordering, and global plus mission continuity; and
- adapter-facing external revocation and instance-catalog floors with rollback,
  scope/provenance replay, equivocation, branch, gap, evidence-confusion,
  event/checkpoint-lineage splice, stale-floor, mixed-projection, and historical
  attestation-substitution known-bads;
- one empty-history-only modeled-integrity profile that atomically retains each event with
  its signed decision dossier, permanently binds the exact fixture adapter/version,
  service scope, policy, complete trust snapshot, and distinct decision/checkpoint
  identities, globally serializes one unresolved transition across missions, and makes
  every modeled facade append wait for an exact current global and mission checkpoint;
- four immutable local recovery phases—pending event, byte-exact anchor statement, signed
  checkpoint candidate, and external-floor finalization—with provider calls outside
  SQLite transactions and exact retry reconciliation after every retained phase;
- two modeled protocol-write calls, plus process-local `prime_catalog` rehydration that is
  neither a durable phase nor a third protocol write; and
- deterministic repository-owned time, revocation, anchor, catalog, and monitor adapters
  demonstrating crash recovery and two-stage semantic idempotence with canonical unsigned
  code-derived provider assertions, without claiming external authentication, time,
  durability, independence, or production authority;
- a separate versioned, networkless trusted-time and revocation qualification contract with
  an exact copied profile, trust root, validation policy, role-separated all-required
  source roster, provider-policy and codec binding, and authentication of exact signed
  repository-fixture statement bytes before claim parsing;
- deterministic same-request byte stability and a content-derived corpus manifest; common
  overlap across all required time sources while retaining their conservative outer hull;
  complete-hull half-open revocation validity and bounded-staleness checks; unanimous
  metadata and configured floor witnesses; and fresh sealed mapping to exact
  provider-neutral evidence BLOBs, references, views, and floors; and
- eighty-one focused contract tests and known-bads spanning trust/profile/policy/source
  substitution, cross-request replay, malformed or noncanonical wire, incomplete or
  reordered rosters, disjoint or over-wide intervals, future/stale/expired revocation
  state, floor disagreement and rollback, mapping confusion, deterministic retry, corpus
  substitution, and sealed-boundary abuse.

Current canonical command writers use receipt-coverage status for every verification-intent
closure. Replay also accepts the exact pre-recovery zero-candidate `completed` shape as a
reader-only legacy alias; it is vacuous coverage compatibility, not a finding or execution
claim.

Remaining required:

1. extend the networkless qualification harness to anchor, catalog, and monitor adapters,
   and add durable blocked-finality disposition and governed recovery before connecting any
   external provider;
2. only then qualify independently administered providers and integrate accepted adapter
   outputs without weakening the retained finality state machine;
3. prove external latest-head authority survives local loss, then close the documented
   same-user SQLite pathname and coherent offline-rewrite boundary;
4. accept and qualify a concrete SQLite/VFS/filesystem/device profile, physical and journal
   quotas, backup/restore, process-kill and power-fault recovery, and sensitive-evidence
   access-control, encryption, and retention policy;
5. structured independently produced execution evidence with a common measured run
   identity; and
6. known-bads for every new refusal, substitution, replay, and concurrency condition.

Current retained boundary: an authority-bound modeled verification assignment, every
predeclared input, and one authenticated modeled receipt can be resolved and retained today.
All four implemented byte-claiming boundaries commit exact BLOBs, code-derived mappings,
and their event together; committed replay and retry no longer depend on filesystem
staging. Receipt admission and lease consumption are one event. Explicit expiry, modeled
cancellation, atomic reassignment, and exact receipt-coverage closure can recover the
mission without rewriting its history. This authenticates and retains modeled statements
and lifecycle decisions. On a separately enrolled empty store, the modeled facade also
persists and recovers exact decision, anchor, checkpoint, and current-floor lineages for
every event before command success. A later mission begins at its own mission genesis while
extending the latest instance-global checkpoint, and subsequent events extend both exact
predecessors. Generic raw replay refuses while any transition is unresolved. Its
providers remain deterministic fixtures and their modeled-finality assertions are unsigned
and not independently authenticated. The separate signed trusted-time/revocation
qualification harness is not consumed by this lifecycle path. It proves only deterministic
repository-fixture conformance under its exact profile, not truthful UTC, current external
revocation, native-provider correctness, independent administration, external durability,
execution, authority, or a finding.

## Phase 2 — independent proof plane

Status: **blocked on an explicitly authorized Linux/KVM environment and Phase 1B**.

Build separately identified MARCELLUS and CATO workers:

- immutable, measured images and exact dependency closure and toolchains;
- an accepted host firmware, microcode, SMT, KSM, VFS, and device policy;
- one unique unprivileged host identity per worker, least-privilege `/dev/kvm` access,
  cgroup-v2 ceilings, seccomp/jailer confinement, and no shared writable paths;
- read-only target and artifact inputs;
- no ambient host credentials;
- default-deny DNS and egress with separately granted destinations;
- ephemeral writable layers;
- CPU, memory, process, storage, and wall-clock ceilings;
- syscall/device restrictions plus bounded guest-controlled serial, log, and artifact
  channels;
- expiring one-purpose leases;
- complete stdout, stderr, effect, environment, and termination receipts;
- an explicit trust split among worker, target, dependency mirror, model gateway,
  controller, evidence receiver, and grader;
- one-way bounded evidence export, with grader secrets unavailable to the worker;
- tamper-evident trajectory and network telemetry retained outside the guest;
- out-of-band cancellation, synchronous kill, and incident-response recovery; and
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
