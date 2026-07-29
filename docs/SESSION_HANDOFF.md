# Etzio Session Handoff

Status: **canonical recovery entrypoint**. Updated 2026-07-29, Asia/Jerusalem.

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

If `.venv` already contains the exact locked dependencies, skip only environment creation
and installation. Status, handoff reading, and validation remain mandatory. Then read
[README](../README.md), [Charter](../CHARTER.md), [Architecture](ARCHITECTURE.md),
[Roadmap](ROADMAP.md), [Frontier baseline](FRONTIER_BASELINE.md), [ADR-0001](decisions/0001-foundation-integrity-before-breadth.md),
[ADR-0002](decisions/0002-canonical-governed-fixture-boundary.md),
[ADR-0003](decisions/0003-semantic-wire-schema-and-typed-kind-closure.md), and
[ADR-0004](decisions/0004-kernel-issued-verification-leases.md), and
[ADR-0005](decisions/0005-typed-verification-artifact-resolution.md), and
[ADR-0006](decisions/0006-atomic-modeled-receipt-admission.md), and
[ADR-0007](decisions/0007-explicit-verification-lease-recovery.md), and
[ADR-0008](decisions/0008-typed-integrity-evidence-contract.md), and
[ADR-0009](decisions/0009-uniform-sqlite-rollback-journal-safety.md), and
[ADR-0010](decisions/0010-transactional-evidence-vault.md), and
[ADR-0011](decisions/0011-crash-safe-modeled-integrity-finality.md), and
[ADR-0012](decisions/0012-networkless-time-revocation-adapter-qualification.md).

Precedence: checked-out Git bytes → reproducible retained evidence → this handoff → chat
memory. A green check validates only what it names.

## Repository identity

- Workspace: `/Users/danielwahnich/workspace/etzio`
- Engine: **Etzio**
- Canonical branch: `main`
- Current foundation-integrity branch:
  `agent/time-revocation-adapter-qualification-v1`
- Stacked on: `agent/integrity-finality-enforcement-v1`
- Branch base: `d88aa73a3186c380f42181293ceef3e16a53b0e3`
- Branch-base tree: `e5576962cd2fff0976f0b806169ef87eacf50950`
- Canonical remote: private `https://github.com/manfromnowhere143/etzio`
- Sole author: `Daniel Wahnich <cogitoergosum143@gmail.com>`

Resolve the current branch head, pull request, workflow state, visibility, and default branch
from Git and GitHub. Do not infer them from this dated packet.

The private remote and `main` default branch were verified on 2026-07-29. Read-only Actions
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
- expand through versioned domain and technique packs without fragmenting the kernel; and
- after the integrity, isolation, benchmark, and exact-target authority gates close, run a
  strictly authorized bounty-research lane in parallel with continued engine development,
  measuring accepted outcomes and income without treating either as authority.

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
- exact closed-field schema/runtime parity for all eleven semantic bodies and all eighteen
  event kind, unit, and payload forms;
- Unicode 17.0.0 NFC, signed 64-bit integers, and fixed resource ceilings;
- full domain-separated SHA-256 object and event identities;
- Ed25519 signed authority grants and self-verifying admission records;
- prime-subgroup trust-key validation for configured and embedded snapshots;
- exact clean/vulnerable fixture manifests and a bounded private content-addressed
  filesystem staging/cache surface;
- bounded analysis leases and stable candidate/claim identities;
- byte-bound Python AST analysis with no production filesystem walker;
- lifecycle-validated append-only SQLite storage and deterministic replay;
- one uniform rollback-journal `DELETE`/`EXTRA` policy across the declared SQLite matrix,
  with a pre-open persistent-WAL refusal and explicit offline-migration boundary; no WAL
  conversion tool is implemented;
- exact WAL-reset-fix classification, SQLite 3.37 minimum and major-version admission, and
  loaded-version/fix diagnostics;
- retained runtime-reported SQLite version/source identity with isolated versus
  repository-import-context agreement;
- one SQLite schema with exact `application_id = 0x45545A31` (ASCII `ETZ1`) and
  `user_version = 2`, exact object, strict-table, foreign-key, index, and trigger
  validation, transactional initialization, and an exact version-1 transactional-vault
  migration into a permanent legacy profile without assigning integrity finality;
- explicit refusal of malformed, unknown, or nonempty pre-vault event state without
  changing its application/schema identity; no pre-vault backfill tool is implemented;
- a canonical append-only SQLite evidence vault retaining deduplicated exact BLOBs and
  complete code-derived event-role mappings;
- immutable first-origin event provenance for each unique BLOB plus a covering
  artifact-identity, size, and event reverse index;
- one `BEGIN IMMEDIATE` commit of exact evidence BLOBs, mappings, and event for each
  `authority_admitted`, `mission_opened`, `verification_artifacts_resolved`, and
  `verifier_receipt_admitted` boundary, with generic append refusing all four kinds;
- canonical-vault-first artifact reuse, exact committed replay/retry without filesystem
  staging, and corruption refusal that never falls back to otherwise-valid staging bytes;
- exact batch reads bounded to 515 selectors or requests and 1 GiB of selected unique
  identities; identity resolution follows immutable first-origin events, selector loads
  follow exact event owners, each distinct required mission is reduced once, one shared
  rehash set reads and hashes each distinct BLOB encountered across the complete histories
  at most once, and only requested bytes remain in the response cache;
- fixed 16 MiB authority-evidence and existing target/resolution/output/grant bounds, plus
  a default 1 GiB configurable per-opening logical evidence-storage ceiling. The ceiling
  charges distinct vault BLOB bytes, deduplicated integrity-provider BLOB bytes, canonical
  pending/anchor/candidate/finalization record bytes, and modeled profile, policy, and
  fixture-adapter authority-binding bytes. Enrollment and each pending append additionally
  preflight 80 MiB of worst-case finality headroom; that reserve is neither retained data
  nor a bound on SQLite pages, journals, backups, or device use;
- kernel-issued verification leases under the exact admitted
  `modeled_fixture_verification` grant;
- complete verifier trust and revocation evidence retained with each issuance;
- replay-checked authority, target, candidate, producer, verifier, key,
  `issuance_trust_snapshot_id`, time, and expiry bindings;
- type-domain-separated content identities for each modeled PoC, supporting-evidence,
  environment, and effect-oracle specification input;
- code-owned role-to-type resolution for every target and verification-input byte under a
  fixed aggregate bound shared with the grant's one signed `max_bytes` ceiling;
- one canonical `verification_artifacts_resolved` event per lease with replay, retry,
  injected post-commit caller-failure recovery, and concurrent-writer controls;
- type-domain-separated identities for modeled execution, effect, measured-environment,
  and termination outputs;
- a canonical signed receipt binding the retained resolution plus each output's exact
  digest and positive bounded size;
- authentication-first receipt checks under a retained decision trust/revocation snapshot,
  followed by fixed-order vault-first target, input, and output resolution;
- one `verifier_receipt_admitted` event that atomically retains the complete modeled
  decision and records single-use lease consumption;
- a dedicated receipt-admission store path that repeats exact manifest and byte validation
  from locked retained history before insertion, while generic append rejects the
  protected event;
- staging-independent exact committed retry, injected post-commit caller-failure recovery,
  one bounded
  SQLite-contention retry, same-receipt reconciliation when an identical commit becomes
  visible, retryable
  `StoreBusyError` on persistent `BUSY` or `LOCKED`, conflicting-receipt refusal, and
  distinct-lease stale-head semantics;
- explicit ETZIO lease expiry and pre-deadline AQUILA modeled cancellation;
- canonical nonbranching per-candidate lease lineages with atomic reassignment to a
  different verifier, immutable work bindings, retained successor-issuance trust evidence,
  and original authority deadlines and lease-count ceilings;
- active-only resolution and receipt admission with expired, cancelled, superseded, and
  consumed predecessors unable to resurrect;
- exact terminal `receipt_coverage_complete` or `receipt_coverage_incomplete` status from
  exhaustive active, covered, never-assigned, latest-expired, and latest-cancelled
  candidate partitions;
- reader-only replay compatibility for the exact zero-candidate pre-recovery
  verification-intent `completed` closure, without rewriting retained bytes;
- nonterminal `awaiting_verification` lifecycle state for verification-intent missions;
- fail-closed refusal, cancellation, failure, timeout, budget, completion, and closure;
- recoverable deterministic fixture scans without duplicate outputs; and
- a supported fixture-only CLI that emits candidates and never findings.

### Implemented integrity-evidence contract

- one required-attestation `IntegrityDecisionV1` binding exact service, environment,
  mission, authority, target, exact prior instance-global checkpoint semantic and signed
  attestation/principal/trust provenance, mission event head, complete proposed event,
  transition intent, 256-bit nonce, decision/time policy, conservative time interval,
  typed time evidence, and versioned revocation views;
- one required-attestation `HeadCheckpointV1` binding instance-global and mission-local
  predecessors plus their exact attestation/principal/trust provenance, exact event plus
  signed-decision attestation/principal/trust provenance, conservative checkpoint time,
  pre-receipt anchor statement, anchor policy, and typed anchor-receipt references with
  distinct `source_id` labels, without treating those labels as proof of independent
  operators;
- distinct signature domains, exact noninterchangeable roles, and decision/checkpoint
  separation by principal as well as key;
- typed external revocation floors bound to service, environment, and decision policy;
  instance-catalog floors retain exact signed-checkpoint/principal/trust provenance for
  both heads, with namespace removal, cross-scope replay, rollback, same-version mutation,
  equivocation, whole-history deletion, branch, and gap refusal;
- exact linkage from revocation continuity to the immediately previous instance-global
  checkpoint decision, signed linkage from every decision to that exact checkpoint, and
  signed linkage from successor checkpoints to both exact predecessor attestations;
  identical global/mission predecessor identities cannot carry mixed provenance, and
  mission-local successors cannot rebind authority or target;
- mission projections cannot exceed the global sequence or conflict with another
  checkpoint at the same global position; older mission ancestry/co-residency remains an
  explicit external-catalog adapter obligation, not a property of direct floor
  construction;
- conservative temporal ordering from predecessor checkpoint through successor decision
  and resulting checkpoint, plus refusal of external revocation floors behind retained
  local history;
- cryptographic reauthentication of every consequential validator input against its exact
  historical trust store, refused public construction of authenticated-result wrappers,
  authentication-boundary seals, exact-type refusal, fresh verified signed snapshots,
  copied constructed trust stores and caller policies, and reapplication of policy
  identities, namespace requirements, and uncertainty ceilings at composition boundaries;
- predecessor sequences that reserve one representable signed-int64 successor, preventing
  a decision from proposing an impossible event or checkpoint position;
- authentication-before-semantic-interpretation on consequential signed-wire paths;
- installed schema, semantic dispatch, repository-policy parity, and known-bads for both
  new protocol kinds; and
- an explicit dependency decision: official TUF direction, conditional RFC 3161 adapter
  qualification, and no accepted canonical Python SCITT verifier yet.

The contract remains provider-neutral. A separate modeled fixture profile now persists and
requires it, as described below. No real time, revocation, anchor, transparency, catalog,
or monitoring service is connected, and directly constructed floor objects do not prove
external authentication.

### Implemented modeled integrity finality and recovery

- schema version 2 retains an immutable legacy or
  `modeled_integrity_fixture_v1` profile; only an entirely empty history can enter the
  modeled profile, while an exact nonempty version-1 vault migrates only to legacy;
- enrollment permanently retains the exact modeled fixture-adapter profile/version,
  service instance, environment, validation policy, complete trust snapshot and identity,
  and distinct decision/checkpoint key and principal identities; every pending decision
  and checkpoint candidate is cross-checked against that binding;
- every modeled event atomically commits with one exact reauthenticated signed
  pending-decision/trust dossier and complete canonical code-derived provider assertions
  before the event can exist;
- one unresolved transition is serialized across the database, so another mission or
  append path cannot bypass finality; a later mission's event zero extends the latest
  finalized instance-global checkpoint while beginning from its own mission genesis, and
  later events extend both exact predecessors;
- anchor statement, signed checkpoint candidate, and external-floor finalization are
  immutable append-only records with exact predecessor identities and evidence coverage;
- exact anchor registration-request bytes and the exact signed checkpoint candidate are
  retained before their respective modeled protocol-write calls, giving at-least-once
  byte-identical recovery under deterministic idempotency keys;
- process-local `prime_catalog` rehydrates the deterministic service's in-memory
  compare-and-set view from retained predecessor lineages; it is neither durable nor a
  third protocol write;
- provider calls occur outside SQLite transactions; generic raw
  `SQLiteEventStore.load()` refuses while any transition is unresolved, explicit
  integrity-inspection APIs alone can read that lineage, and facade load recovers it
  before exposing lifecycle history or a replay shortcut;
- command success requires an exact code-derived current-floor assertion naming the exact
  checkpoint as both instance-global and mission head;
- fully revalidated modeled-lineage replay is cached only under mutation-sensitive SQLite
  signals, the exact schema fingerprint, and exact `journal_mode`, `synchronous`,
  `foreign_keys`, `trusted_schema`, `ignore_check_constraints`, `read_uncommitted`, and
  `writable_schema` settings; drift fails closed on cached replay and every writer
  boundary, while raw same-connection, other-connection, and schema-cookie tampering
  invalidates or fails the cache; and
- the complete fourteen-event repository-fixture receipt vertical retains a contiguous
  finalized lineage from `authority_admitted` through
  `verifier_receipt_admitted`, including recovery after interruption immediately after
  checkpoint publication.

The service implementations are repository-owned deterministic fixtures. Profile-bound
keys fixed at enrollment authenticate decisions and checkpoints only; provider-evidence
BLOBs are unsigned, canonical, code-derived assertions checked for exact source, kind,
claim, and reference equality. Separate labels, evidence, and logical stages do not prove
trustworthy UTC, external durability, independent operators, current real revocation, or
production non-equivocation. A typed blocked classification is per recovery attempt and is
not durably retained; the last immutable local phase remains pending. The ordinary fixture
CLI remains on the legacy profile.

### Implemented networkless trusted-time and revocation qualification

- [ADR-0012](decisions/0012-networkless-time-revocation-adapter-qualification.md)
  and `etzio/kernel/integrity_adapters_v1.py` define a separate version-1,
  repository-owned, networkless qualification boundary; it does not add a protocol-v1
  object kind, store profile, lifecycle command, provider call, or finality phase;
- one copied `IntegrityAdapterTrustProfileV1` content-binds the exact service,
  environment, validation policy, trust root, fixed source roster, source roles and
  namespaces, distinct fixture keys and principals, provider-policy identities, codec
  profiles, and revocation-staleness ceiling;
- source-specific time and revocation requests bind the exact profile/root, scope, event,
  transition, policy, 256-bit nonce, and time imprint or qualified-time bundle; distinct
  Ed25519 signature domains separate trusted-time, revocation-metadata, and
  revocation-floor fixture packages;
- package authentication resolves the source exclusively from the retained profile,
  verifies the exact signed statement bytes before parsing provider-controlled claims,
  and maps the complete canonical signed package—not a normalized claim—to one typed
  `ProviderEvidenceBlobV1`;
- every configured time source is required. Its closed interval must share a common
  overlap with every other source, while the result retains the conservative outer hull;
  each source and the hull must remain within the purpose-specific policy ceiling;
- each required revocation namespace uses exactly one metadata source and at least two
  fixed floor witnesses. The complete closed time hull must fit inside the metadata's
  half-open validity window, publication age must remain within the exact staleness
  ceiling, predecessor root/version/snapshot rollback or equal-version mutation is
  refused, and every floor witness must agree with metadata exactly;
- authenticated packages, qualified time, qualified revocation, provider-neutral mapped
  inputs, and the qualification report are privately constructed sealed exact types.
  Consequential mapping freshly reauthenticates retained request and package bytes and
  requires exact BLOB/reference and namespace coverage;
- the content-addressed corpus manifest binds the adapter implementation, profile, vector,
  ordered cases, exact ordered time intervals, and exact ordered revocation adapter
  states. The deterministic harness proves byte-identical retry, time and revocation
  qualification, cross-request replay refusal, and exact provider-neutral mapping; and
- 81 focused adversarial tests additionally prove canonical parsing, trust/profile/role/
  scope/policy/claim substitution refusal, hostile duplicate mappings, exact source
  rosters, interval boundaries, full-hull freshness, rollback/equivocation, namespace
  swapping, corpus reconfiguration, evidence closure, no ambient clock/network
  dependency, and direct or dataclass-copy seal bypass refusal.

This establishes deterministic authentication and semantic qualification of
repository-owned signed fixture packages under the exact retained fixture profile only.
Distinct fixture labels, principals, and keys do not prove independent operators,
administration, clocks, storage, or legal authority. No RFC 3161, TUF, PKIX, COSE,
SCITT, Rekor, or provider-native parser/client is qualified; no trustworthy UTC, current
real-world revocation, external availability/durability/non-equivocation, lifecycle
finality, execution, finding, or live-target authority follows. The existing modeled
finality facade still consumes its separate unsigned code-derived fixture assertions.

### Implemented for modeled verification admission and recovery

- canonical one-attestation signed verifier receipts;
- exact receipt/lease/resolution/output-digest/output-size/time/verdict bindings and
  resource ceilings;
- distinct issuance- and proposal-time trust snapshot identities in modeled receipt
  proposals; and
- matching typed-resolution and exact current-staging validation before a positive
  standalone modeled proposal, plus vault-first exact-byte validation before first
  canonical admission.

Lease issuance records an authorized modeled assignment, and resolution records exact
predeclared input bytes and roles. Receipt admission authenticates and atomically retains a
configured modeled statement while consuming its lease. Its four output artifacts are
opaque typed bytes grouped by one signature. This does not establish that an execution
occurred, that one run produced the outputs, that their contents are true, or that the
verifier was independent or isolated. It does not mint a finding.

Recovery retains modeled lifecycle decisions only. Caller-supplied event time is not
trusted-clock evidence, and AQUILA plus `operator_cancelled` does not cryptographically
authenticate an external control principal. Receipt-coverage closure is not a verdict or
finding claim.

### Retained behavior models

The original in-memory `MasterLoop`, ten unit stubs, `BenchmarkTarget`, and eight-case
verdict/FPR corpus remain regression models. Their findings, verifier labels, environment
digests, and event chain are not evidence of the protocol-v1 architecture.

## Current adapter-qualification local release evidence

On the hardened trusted-time/revocation qualification candidate, the canonical release
command passed under both declared local runtimes:

- 910 tests passed;
- the focused adapter-qualification file passed all 81 tests;
- the deterministic qualification report retained all ten ordered cases;
- CPython 3.11.15 loaded SQLite 3.53.1 and used `DELETE`/`EXTRA`;
- CPython 3.14.2 loaded SQLite 3.51.2 and used `DELETE`/`EXTRA`;
- both runtimes retained their complete `sqlite_source_id()` values and proved isolated
  versus repository-import-context agreement;
- both hash-locked environments passed `pip check`;
- exact schema, semantic dispatch, repository policy, Ruff, fixture runs, and
  retained-evidence checks passed; and
- `git diff --check` passed.

The CPython 3.11 test suite completed in 474.94 seconds and the CPython 3.14 suite
completed in 484.35 seconds. Each complete release entrypoint also ran the modeled
demonstrations and the governed vulnerable and clean fixture scans. The working-tree
status was unchanged by validation.

The retained SQLite source identities were:

- CPython 3.11.15 / SQLite 3.53.1:
  `2026-05-05 10:34:17 c88b22011a54b4f6fbd149e9f8e4de77658ce58143a1af0e3785e4e6475127e9`;
- CPython 3.14.2 / SQLite 3.51.2:
  `2026-01-09 17:27:48 b270f8339eb13b504d0b2ba154ebca966b7dde08e40c3ed7d559749818cb2075`.

This is local release evidence only until the exact committed bytes are reproduced by
private GitHub Actions. The current implementation commit, workflow run, draft pull
request, and GitGuardian result must be resolved from Git and GitHub after publication;
none is claimed here yet.

The evidence scope is repository-owned deterministic fixtures. It validates the
contract/harness boundary described above, not a real provider, native provider format,
truthful clock, current external revocation state, lifecycle integration, execution,
finding, or live-target authority.

## Current integrity-finality release evidence

On the final audited integrity-finality release candidate, the complete release command
passed under both declared local runtimes:

- the prior integrity-finality suite reported 829 passing tests;
- CPython 3.11.15 / SQLite 3.53.1 / `DELETE`/`EXTRA`;
- CPython 3.14.2 / SQLite 3.51.2 / `DELETE`/`EXTRA`;
- exact schema, semantic dispatch, repository policy, Ruff, fixture runs, and
  retained-evidence checks on both local hash-locked environments; and
- full local release entrypoints completed without changing repository state.

The CPython 3.11 suite completed in 486.56 seconds and the CPython 3.14 suite in 507.92
seconds. Both hash-locked environments passed `pip check`. Private GitHub Actions run
[`30474966878`](https://github.com/manfromnowhere143/etzio/actions/runs/30474966878)
reproduced repository policy, both declared runtime suites, package build,
outside-checkout wheel smoke, clean-tree proof, and retained foundation evidence on exact
release-candidate commit
[`82f8ceca3eb0a32cdc67421f70ab45e845a90bdc`](https://github.com/manfromnowhere143/etzio/commit/82f8ceca3eb0a32cdc67421f70ab45e845a90bdc);
GitGuardian also passed. Draft
[#11](https://github.com/manfromnowhere143/etzio/pull/11) is stacked on the transactional
evidence-vault branch. This evidence-only handoff update follows the validated candidate.

Earlier run
[`30472204976`](https://github.com/manfromnowhere143/etzio/actions/runs/30472204976)
was cancelled by the obsolete 12-minute foundation-job ceiling after both declared
runtime suites reached 78 percent. Run
[`30473383200`](https://github.com/manfromnowhere143/etzio/actions/runs/30473383200)
then failed closed before test execution because the retained count of 828 lagged the new
timeout-regression known-bad's 829 collected tests. Neither run is release evidence. The
foundation job now has a bounded 30-minute budget protected by repository policy and that
known-bad.

## Documentation and frontier reconciliation

A complete 2026-07-29 repository-documentation audit reconciled the README, every
diagrammatic block, Architecture, Roadmap, frontier baseline, ADR-0011, repository
instructions, this handoff, and machine-readable mission state against the retained
implementation:

- the visual model now distinguishes the supported CLI legacy profile, the explicit
  fixture-only verification-intent path, the optional modeled-finality facade, legacy
  behavior models, and blocked target roles;
- Architecture and ADR-0011 retain the canonical four-transaction recovery order and the
  database-global unresolved-transition barrier without collapsing external calls into
  SQLite transactions;
- worker receipts flow back through ETZIO admission, CAMILLUS receives only
  kernel-accepted evidence, and MINERVA evaluates retained positive and negative outcomes
  offline;
- adapter claims are scoped to the concrete repository-owned fixture implementation,
  RFC 3161 EKU wording is exact, and durable blocked-finality recovery remains explicit;
- `AGENTS.md`, the README, and the Roadmap at that revision named the same networkless
  trusted-time and revocation conformance harness as the next proof tranche; and
- the [frontier baseline](FRONTIER_BASELINE.md) incorporates primary 2026 evidence on
  capability-ladder, exploit-generation, long-horizon discovery, multi-host, and
  evaluator-containment benchmarks while preserving every harness, population, budget,
  information-regime, and vendor/private-evaluation caveat.

This reconciliation changes documentation, not capability or authority. In particular, no
benchmark corpus was downloaded or executed, no external provider was connected, and no
live-target, exploit-execution, credential, egress, spending, disclosure, or publication
grant was created.

Documentation-release evidence is separate from implementation evidence. On exact
documentation-reconciliation commit
[`a0f43a4267e65251afd2a7a32012f5c8ea31dfea`](https://github.com/manfromnowhere143/etzio/commit/a0f43a4267e65251afd2a7a32012f5c8ea31dfea),
the complete local release command passed all 829 tests under CPython 3.11.15 in 467.49
seconds and CPython 3.14.2 in 480.81 seconds. Repository policy, mission-state JSON,
relative Markdown links, and both README Mermaid diagrams also passed their exact
validation or render checks. Private GitHub Actions run
[`30480296580`](https://github.com/manfromnowhere143/etzio/actions/runs/30480296580)
then reproduced repository policy, both declared runtime suites, package build,
outside-checkout wheel smoke, clean-tree proof, and retained foundation evidence on that
same commit; GitGuardian also passed. This validates the documentation reconciliation
only, adds no capability or authority, and does not supersede implementation evidence
commit `82f8ceca3eb0a32cdc67421f70ab45e845a90bdc`. This evidence-only handoff and
mission-state update follows the validated documentation commit.

## Inherited transactional-vault evidence

On transactional-vault implementation commit
`612953648eff751a49054e8a700005216ddf7fb6`, the complete release command passed under
both declared runtimes:

- the inherited suite reported 730 passing tests;
- CPython 3.11.15 loaded SQLite 3.53.1 and used `DELETE`/`EXTRA`;
- CPython 3.14.2 loaded SQLite 3.51.2 and used `DELETE`/`EXTRA`;
- each verification log retained `sqlite_source_id()` and proved that the isolated and
  repository import contexts reported the same identity;
- Ruff was clean;
- the installed semantic protocol schema, three explicitly modeled legacy schemas, and
  repository policy passed;
- the built wheel loaded and metaschema-checked the canonical protocol schema outside the
  checkout;
- the governed vulnerable fixture closed with seven candidates and no finding;
- the governed clean fixture closed with zero candidates; and
- both modeled regression demonstrations retained their historical outputs.

Both hash-locked environments passed `pip check`. GitHub Actions run
[`30450447700`](https://github.com/manfromnowhere143/etzio/actions/runs/30450447700)
reproduced repository policy plus both declared runtime suites, package build,
outside-checkout wheel smoke, clean-tree proof, and retained foundation evidence on that
exact implementation commit; GitGuardian also passed. Draft
[#10](https://github.com/manfromnowhere143/etzio/pull/10) is stacked on the SQLite
journal-safety branch. This evidence-only handoff update follows the validated
implementation commit.

Inherited foundation evidence is separate. GitHub Actions run
[`30438318919`](https://github.com/manfromnowhere143/etzio/actions/runs/30438318919)
reproduced repository policy plus both declared runtime suites, package build,
outside-checkout wheel smoke, and clean-tree proof on the exact SQLite journal-safety
implementation commit `4dfbcc319a63a14a3a223b80b1740fbd05fc676e`; GitGuardian also
passed. That run predates the transactional vault and validates no vault claim. All
evidence remains fixture-scoped.

## Closed adversarial findings in this tranche

Known-bads now cover:

- adapter profile/root/policy/service/environment/source/role/namespace/key/principal/
  codec substitution; revoked, unknown, wrong-role, and invalid-signature fixture keys;
  noncanonical or malformed signed framing; nonce, imprint, purpose, event, transition,
  request, time-bundle, scope, and authenticated-claim replay or substitution; missing,
  extra, duplicate, reordered, hostile-mapping, or reconfigured source/corpus inputs;
  reversed, individually oversized, disjoint, point-overlap, exact-limit, and
  outer-hull-overlimit trusted-time intervals; future-valid, boundary-straddling,
  expired, frozen, stale, root/version rollback, skipped-root, same-version mutation,
  metadata/floor disagreement, namespace swapping, and incomplete revocation coverage;
  missing, extra, changed, corrupt, or mismapped signed provider BLOBs/references;
  nondeterministic exact retry, corpus-manifest substitution, ambient clock/network use,
  and direct, subclass, or dataclass-copy construction of every sealed qualification
  result;
- malformed, wrong-source, wrong-kind, wrong-phase, or substituted modeled provider claims
  and references, including arbitrary unsigned floor and anchor-receipt payloads;
- fixture-adapter profile/version, validation-policy, trust-snapshot, service-scope,
  key/principal, and replacement-service authority-binding substitution;
- generic raw replay while pending, cross-mission append bypass, later-mission global
  continuity, exact predecessor recovery, and self-predecessor exclusion;
- low-quota enrollment and pending-transition refusal before mutation, including the exact
  modeled profile bytes and 80 MiB worst-case finality reserve;
- interruption before and after every immutable recovery phase, lost anchor/publication
  responses, exact finalization retry after caller-response loss, and concurrent recovery
  through independent SQLite connections; and
- typed pending, typed blocked, and preserved SQLite busy/capacity/operational/corruption
  classifications without reclassifying store failures as adapter failures;
- cached replay, pending append, and finalization refusal after drift in any of the seven
  authenticated SQLite security settings, with zero partial write or finalization;
- oversized direct anchor time-evidence tuples rejected by count before any entry is
  inspected;
- cross-runtime Unicode identity divergence;
- duplicate/noncanonical/oversized protocol values;
- arbitrary semantic bodies, missing/unknown per-kind fields, forbidden or multiple
  attestations, schema/runtime dispatch drift, and malformed identifier anchors;
- root/body field removal, body reopening, case-reference substitution, and attestation
  policy weakening against the repository schema gate;
- Python/ECMA-262 edge-whitespace divergence and portable U+001C–U+001F, U+0085, and U+FEFF
  behavior;
- arbitrary, unattested, multiply attested, forged, wrong-role, or signature-domain-
  substituted integrity decisions and head checkpoints;
- nonce, policy, proposed-event, prior-head, mission, authority, target, instance,
  environment, time, and transition substitution;
- time intervals that regress, exceed policy, reverse, or straddle not-before, expiry, or
  deadline boundaries;
- unsorted, duplicate-source, duplicate-evidence, wrong-kind, or undersized time,
  revocation, anchor, and external-floor evidence quorums;
- revocation namespace removal, root/version rollback, same-version mutation, external
  equivocation, cross-service/environment/policy floor replay, unbounded floor sets, and
  local state below an external floor;
- rotated-key same-principal reuse, decision/checkpoint event substitution, checkpoint
  time preceding decision time, alternate trusted decision/checkpoint attestation
  substitution, direct authenticated-wrapper forgery, event/checkpoint predecessor splice,
  older-global-baseline substitution, historical checkpoint re-signing, mixed
  global/mission provenance, mission authority/target rebinding, successor-time regression,
  stateful wrapper-subclass substitution after authentication, stale external revocation
  floors, post-authentication policy weakening, bounded hostile iterables and pre-encode
  oversized text, terminal predecessor sequence exhaustion, global/mission branch or gap,
  exact-current reconciliation, whole-history rollback, and receipt/checkpoint hash cycles;
- weakened integrity nonce, nested evidence, revocation, body-reference, attestation, and
  dispatch schema contracts;
- the literal `"."` relative path;
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
- exact resolution retry, injected post-append caller-failure recovery, concurrent
  convergence, and post-event staging disappearance;
- caller-selected unsigned resolution contexts promoted beyond non-authoritative proposal
  status, noncausal resolution/receipt times, and consequential receipt refusals that would
  otherwise reach evidence reads;
- missing, empty, corrupt, wrong-type, swapped, colliding, individually oversized,
  aggregate-oversized, or signed-size-mismatched modeled output artifacts;
- unattested, multiply attested, malformed, forged, revoked, wrong-role, or substituted
  receipt-admission decision evidence;
- receipt reuse, lease double consumption, exact committed retry after staging loss and head
  advancement, identical and conflicting submission races, and distinct-lease stale-head
  races;
- expiry before the retained boundary, cancellation disguised as expiry, unknown or
  inactive disposition, duplicate/conflicting disposition, and post-resolution recovery;
- plain second issuance, branching or older-predecessor reassignment, same-verifier
  renewal, immutable-binding substitution, deadline/budget reset, and reason/state
  mismatch;
- predecessor resolution or receipt reuse after reassignment, receipt-versus-recovery
  commit ordering, identical/conflicting concurrent reassignment, and active-lease
  closure;
- complete, incomplete, never-assigned, latest-expired, latest-cancelled, and zero-candidate
  receipt-coverage partitions;
- bounded SQLite writer contention, identical-commit reconciliation after one retry, and
  retryable `StoreBusyError` exhaustion without a corruption classification;
- SQLite `BUSY`/`LOCKED`, `FULL`/`TOOBIG`/`NOMEM`, explicit corruption, and other
  operational result-code classification, production capacity propagation, and locked
  receipt revalidation preserving the exact store-failure class;
- exact SQLite WAL-reset fix/backport boundaries, unsupported pre-3.37 and future-major
  releases, matrix-wide fixed/affected rollback-policy agreement, and preexisting WAL
  header refusal before ordinary startup;
- removal of the SQLite source probe, repository-root `sqlite3` shadowing, and isolated
  versus repository-context SQLite identity disagreement;
- generic and direct-internal append bypass, receipt-event/evidence-store pairing mismatch,
  wrong-kind dedicated append, direct undersized-output event injection, and rollback with
  unchanged history on dedicated evidence validation failure;
- generic or raw-SQL insertion of any protected byte-claiming event without its exact
  mappings, mutable or late vault-role rows, and a transaction-sabotaging staging-store
  subclass;
- failed, quota-exceeding, or stale protected appends leaving any event, mapping, or orphan
  BLOB; cross-mission BLOB deduplication losing logical role records; and malformed
  pre-vault schema promotion;
- lower-ceiling reopen, ETZ1 schema drift, oversized retained authority metadata, and a
  missing canonical BLOB escaping their exact capacity or corruption classes;
- 515 ordered duplicate requests, 256 distinct target identities with one event-owner
  reduction, one rehash for each of 257 complete-history BLOBs, and requested-only response
  caching;
- authority, target, typed-input, and typed-output replay or retry after staging deletion,
  wrong-role canonical reuse, canonical corruption hidden by valid staging, and offline
  vault corruption surviving reopen;
- injected post-append caller-failure replay without duplicate candidates;
- late recovery before lease issuance and completed-scan closure after grant/trust
  changes; and
- the former arbitrary local-path CLI escape hatch.

## Open foundation-integrity blockers

1. The separate networkless harness authenticates and semantically qualifies signed
   repository-owned time/revocation packages, but modeled commands still consume their
   own code-derived assertions. No provider-native adapter or independently administered
   source proves trustworthy clock or current revocation freshness; the ordinary fixture
   CLI remains on the legacy profile.
2. Modeled commands persist and require exact-current checkpoint lineages, but no qualified
   externally authenticated and durable anchor/catalog/witness survives local database
   loss or proves non-equivocation.
3. Typed blocked results are attempt-local; no durable blocked disposition, reason, or
   governed recovery decision exists beyond the unresolved immutable phase.
4. SQLite retains a documented same-user pathname race, and a coherent offline rewrite
   remains undetectable without an authenticated external latest-head catalog.
5. Production storage still needs an accepted SQLite/VFS/filesystem/device profile,
   physical and journal quotas, backup/restore, process-kill and power-fault qualification,
   and sensitive-evidence access-control, encryption, and retention policy.
6. Modeled output artifacts are opaque signed descriptors, not structured evidence tied to
   an independently measured execution identity.
7. Separate verifier labels and keys do not prove separate principals, processes, or
   isolation.
8. MARCELLUS/CATO Linux/KVM execution, live adapters, learning, cockpit, and domain packs
   are not implemented.

These blockers prevent a finding pipeline and all live-target work.

## Current mission order

### Mission 1 — close finding-admission integrity

**Exact next-session pickup:** extend the completed versioned, networkless
trusted-time/revocation qualification boundary to authenticated anchor-registration
receipts, external head-catalog floors, and monitor-witness evidence. Specify and prove a
durable blocked-finality disposition, exact reason, policy-authorized recovery decision,
and recovery replay contract in the same dependency-complete tranche. Keep acquisition
repository-owned and deterministic; add known-bads for registration replay, inclusion and
consistency proof substitution, catalog rollback/equivocation/local-loss recovery,
witness disagreement, blocked-state mutation, and unauthorized recovery. Do not connect
a real provider, alter the retained lifecycle state machine, add finder breadth, or add
execution capability.

Concrete continuation map:

1. begin from ADR-0012, `etzio/kernel/integrity_adapters_v1.py`, and
   `tests/test_integrity_adapter_qualification_v1.py`; preserve authentication before
   claim parsing, complete fixed source sets, exact raw-package retention, private sealed
   results, content-bound corpus inputs, and fresh reauthentication before mapping;
2. specify the anchor/catalog/monitor request, trust, signed-package, conservative
   consistency/floor, evidence-mapping, and report contracts in a new decision before
   changing lifecycle behavior;
3. keep `RepositoryOwnedDeterministicModeledIntegrityServiceV1`,
   `PendingIntegrityTransitionV1`, and the SQLite finality records unchanged while proving
   the new networkless adapter boundary; their current validators intentionally accept
   only the enrolled modeled-fixture claim shape;
4. separately specify durable blocked-finality state, admissible terminal/retry
   dispositions, policy authority, atomic persistence point, crash recovery, and
   database-global barrier interaction; and
5. only after both deterministic proof sets pass, design an empty-history admitted
   lifecycle profile that retains exact provider roots, policies, packages, and durable
   blocked recovery without weakening the four immutable phases, byte-identical
   at-least-once writes, global/mission continuity, or store-error classifications.

Only after that networkless proof passes, qualify and connect independently administered
trusted-time, revocation, anchor, catalog, and monitor adapters inside the retained state
machine. Preserve exact
fixture-proved pending retention, byte-identical at-least-once retries, global/mission
continuity, raw pending-replay refusal, and store-error classifications while replacing
code-derived provider assertions with authenticated external evidence. Add a durable
blocked disposition and governed recovery decision, then prove that external head
authority survives local database loss. Closure of the same-user SQLite pathname,
coherent offline-rewrite, and qualified physical-storage boundaries remains mandatory
before a finding pipeline can be accepted.

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
