# Etzio Session Handoff

Status: **canonical recovery entrypoint**. Updated 2026-08-01, Asia/Jerusalem.

This file describes Etzio only. The repository is public (source visibility, not an
open-source license; `LICENSE.md` remains proprietary). This file is not authority to access
a live target, execute an exploit, use research credentials, spend, disclose, publish
results, or deploy. Revalidate every statement from checked-out bytes and retained evidence.

**Standards.** Read [`docs/PRESENTATION.md`](PRESENTATION.md) before writing any prose: lead
with status, keep `implemented`/`modeled`/`proposed`/`blocked` exact, a candidate is not a
finding, exact nouns over adjectives, every gate names a known-bad, and never overclaim.
Engineering discipline: contract or ADR before behavior; adversarial known-bad for every
consequential gate; `make verify` green on **both** declared runtimes (CPython 3.11.15 and
3.14.2) before a tranche is done; smallest dependency-complete proof tranche. Git: Daniel is
the **sole author** — never add `Co-Authored-By` or any AI/Claude attribution to commits, PR
bodies, or code; merge the linear stack to `main` by **fast-forward, not squash**;
auto-delete merged branches; record CI and GitGuardian evidence honestly and never claim a
CI run passed when it did not.

**Founder intent (not derivable from the repo).** Bounty/audit income is a real survival
priority for the founder, not a hobby. The foundation is deep and world-class; the *finder*
is deliberately tiny (six rule classes, two fixtures, zero findings). Foundation progress
does not by itself move toward income — say so honestly. The faster honest path to money is a
real EVM/Solidity finder plus human-in-the-loop audit-contest work, but that consciously
reverses ADR-0001 (foundation before breadth) and needs an explicit founder decision. Give
real odds, never hope.

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
[ADR-0012](decisions/0012-networkless-time-revocation-adapter-qualification.md), and
[ADR-0013](decisions/0013-networkless-head-authority-adapter-qualification.md), and
[ADR-0014](decisions/0014-durable-blocked-finality-and-governed-recovery.md), and
[ADR-0015](decisions/0015-durable-blocked-finality-storage-v3.md), and
[ADR-0016](decisions/0016-governed-blocked-finality-lifecycle.md), and
[ADR-0017](decisions/0017-blocked-finality-crash-recovery.md), and
[ADR-0018](decisions/0018-qualified-evidence-consumption.md), and
[ADR-0019](decisions/0019-qualified-evidence-lifecycle-consumption.md).

Precedence: checked-out Git bytes → reproducible retained evidence → this handoff → chat
memory. A green check validates only what it names.

## Repository identity

- Workspace: `/Users/danielwahnich/workspace/etzio`
- Engine: **Etzio**
- Canonical branch: `main`
- Current foundation-integrity branch: `agent/qualified-anchor-consumption-v1`, stacked on `main` (all prior tranches consolidated on `main` by fast-forward).
- The repository is **public** as of 2026-08-01 (founder-authorized; source visibility, not
  an open-source license). Public repositories run GitHub Actions free and unmetered.
- **CI note for a future session:** on 2026-08-01 the account's Actions were billing-blocked
  by heavy same-day usage; runs failed at startup even after going public. The schema-v4 and
  presentation tranches are green on both local runtimes (`1158` tests) but their CI
  reproduction was **deferred** — `current_evidence.validation_status` reads
  `local_release_suites_pending_github_reproduction`. Do not read that as a failure; re-run
  CI once billing clears and update the evidence to reflect the reproduced commit.
- Every tranche stack has been merged into `main` by fast-forward, not squash. Each stack was
  strictly linear and `main` was a pure ancestor, so fast-forwarding preserved every
  authorship. Squashing would have collapsed each tranche and, because each branch still
  contained its predecessors' commits, produced replay conflicts against an already-squashed
  `main`. PR #3 is labelled closed rather than merged for that reason; its head commit
  `fbfa6ed` is an ancestor of `main` and a comment on the PR records this.
- `main` was verified green after the merge: 1083 tests under CPython 3.11.15.
- Canonical remote: private `https://github.com/manfromnowhere143/etzio`
- Sole author: `Daniel Wahnich <cogitoergosum143@gmail.com>`

Resolve the current branch head, pull request, workflow state, visibility, and default branch
from Git and GitHub. Do not infer them from this dated packet.

The repository is **public** as of 2026-08-01 (source visibility, not an open-source
license; see LICENSE.md). Public visibility was explicitly authorized by the founder; every
other grant — deployment, live-target, credential, spend, disclosure, submission — remains
unheld. Public repositories run GitHub Actions free and unmetered. The presentation standard
is now recorded in [`docs/PRESENTATION.md`](PRESENTATION.md); the README, charter, and this
handoff follow it.

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

### Implemented networkless anchor, catalog, and monitor qualification

- [ADR-0013](decisions/0013-networkless-head-authority-adapter-qualification.md)
  and `etzio/kernel/head_authority_adapters_v1.py` define a separate version-1,
  repository-owned, networkless head-authority qualification boundary; it does not add a
  protocol-v1 object kind, store profile, lifecycle command, provider call, or finality
  phase;
- one copied `HeadAuthorityTrustProfileV1` content-binds the exact service, environment,
  validation policy, trust root, fixed source roster, roles, log origins, distinct fixture
  keys and principals, provider-policy identities, codec profiles, and head-staleness
  ceiling. The roster requires at least two anchor sources over distinct log origins,
  exactly one catalog source, and at least two monitor sources witnessing the catalog's
  exact log origin;
- three distinct Ed25519 signature domains separate anchor-receipt, catalog, and monitor
  fixture packages, and all three differ from every ADR-0012 domain, so no time or
  revocation package can authenticate into a head-authority role;
- package authentication resolves the source exclusively from the retained profile,
  verifies the exact signed statement bytes before parsing provider-controlled claims, and
  maps the complete canonical signed package to one typed `ProviderEvidenceBlobV1`;
- the registered object is one closed canonical `AnchorRegistrationLeafV1` binding contract
  version, service, environment, mission, instance sequence, anchor policy, and anchor
  statement. The qualifier recomputes its RFC 9162 leaf hash from the request and refuses
  any authenticated receipt claiming a different leaf, so a receipt for another statement,
  mission, sequence, or policy cannot satisfy the request even when its own proof is
  internally valid;
- `verify_merkle_inclusion_v1` implements RFC 9162 section 2.1.3.2 and
  `verify_merkle_consistency_v1` implements section 2.1.4.2 over SHA-256 with the
  domain-separated `0x00` leaf and `0x01` node prefixes. Both recompute the claimed roots
  and refuse proofs that are shorter or longer than the tree geometry requires;
- every anchor source must carry a verifying inclusion proof to its own claimed root, must
  not regress below its retained tree size, and must agree exactly on the anchor statement.
  Anchor sources are deliberately not required to agree on tree size or root, because each
  is an independent log;
- the catalog head must carry a verifying consistency proof from the exact retained
  predecessor size and root; an unchanged tree size must retain its exact root and carry an
  empty proof; and the instance-global and mission heads may not regress;
- every monitor must name the exact catalog source and agree exactly on log origin, tree
  size, and root hash. Unanimity is required, so a single disagreeing witness refuses the
  bundle instead of being outvoted;
- anchor, catalog, and monitor freshness are evaluated only against the complete freshly
  reauthenticated ADR-0012 qualified time hull under the exact retained staleness ceiling;
- authenticated packages, qualified anchor and catalog bundles, provider-neutral mapped
  inputs, and the qualification report are privately constructed sealed exact types.
  Consequential mapping freshly reauthenticates retained request and package bytes and
  requires exact BLOB/reference coverage across the anchor references and head floor;
- the sealed catalog bundle constructs one `HeadCheckpointFloorV1`, whose own constructor
  reapplies the ADR-0008 genesis, attestation-provenance, and mission-not-ahead rules, so a
  qualified bundle can never produce a floor the integrity contract would reject;
- the content-addressed corpus manifest binds the adapter implementation, profile, vector,
  ordered cases, each anchor adapter's source, log origin, and ordered leaf digests, the
  catalog adapter's ordered leaf digests and head projection, each monitor's source and
  witnessed leaves, and the retained catalog prefix and root. The deterministic harness
  builds real Merkle trees and computes genuine proofs, so no case can pass by agreeing
  with a precomputed constant; and
- 78 focused adversarial tests additionally prove the published RFC 6962/9162 reference
  tree heads for sizes zero through eight, all 36 reference inclusion proofs and all 36
  reference consistency proofs, leaf/node domain separation, tampered, truncated, padded,
  substituted, forked, and unbounded proof refusal, roster and log-origin requirements,
  cross-request replay, foreign-leaf and foreign-statement receipts, forged proofs,
  asserted roots without proofs, tree and head rollback, equal-size equivocation, monitor
  split view and witness substitution, half-open freshness at both boundaries, exact
  evidence coverage, corpus and adapter substitution, no ambient clock or network
  dependency, and direct construction of every sealed result.

This establishes deterministic authentication and semantic qualification of
repository-owned signed fixture packages under the exact retained head-authority profile
only. Distinct fixture labels, principals, keys, and log origins do not prove independent
operators, administration, storage, or observers. No RFC 9162, RFC 9942, RFC 9943, SCITT,
Rekor, or provider-native parser/client is qualified; no trustworthy UTC, real publication
time, external availability/durability, real-world non-equivocation, survival of local
database loss, lifecycle finality, execution, finding, or live-target authority follows.
The existing modeled finality facade still consumes its separate unsigned code-derived
fixture assertions.

### Implemented durable blocked-finality and governed-recovery contract

- [ADR-0014](decisions/0014-durable-blocked-finality-and-governed-recovery.md) and
  `etzio/kernel/blocked_finality_v1.py` define a separate version-1, repository-owned,
  networkless contract; it changes no SQLite schema, store method, lifecycle command,
  provider call, or finality phase;
- one closed canonical `BlockedFinalityObservationV1` names the exact service instance,
  environment, mission, authority, target, event, mission and instance-global sequences,
  pending record, highest retained immutable phase and its exact record identity, refused
  operation, deterministic reason code, and attempt ordinal;
- `unresolved_phase` admits exactly `local_pending`, `anchor_statement_ready`, and
  `checkpoint_candidate_retained`. The fourth lineage phase `finalized` is deliberately
  inadmissible, because a finalized transition is resolved;
- `blocked_reason_code` is a closed set taken from the reason codes the implemented
  recovery path actually produces, and a known-bad asserts each one still appears in
  `etzio/kernel/integrity_transition.py`. Retryable uncertainty and every
  `EventStoreError` classification keep their existing domains and produce no observation;
- observations carry no resolution, status, or disposition field, are timed only by a
  freshly qualified ADR-0012 time hull, and are append-only under strictly increasing
  attempt ordinals. An exact duplicate reconciles, a gap-filling lower ordinal is a
  regression, and one ordinal carrying two different bodies is equivocation;
- `BlockedFinalityRecoveryProfileV1` copies the enrolled
  `ModeledIntegrityAuthorityBindingV1` and adds a recovery key and principal that must
  both differ from the decision and checkpoint authorities. A distinct key under the same
  principal is refused as rotation rather than separation of duty;
- the recovery authority is deliberately outside the enrolled integrity trust store, whose
  `INTEGRITY_ROLES_V1` admits exactly the decision and checkpoint roles; a recovery key
  that is also an enrolled integrity key is refused;
- `GovernedRecoveryDecisionV1` is signed under the dedicated domain
  `etzio.blocked-finality.governed-recovery.signature.v1`, distinct from every integrity,
  adapter, and head-authority domain, and restates the complete observation binding so a
  signature cannot be moved onto another block, phase, operation, reason, or attempt;
- exactly two dispositions are admissible. `retry_authorized` resumes from the exact
  retained phase and holds the barrier; `instance_sealed` is terminal, holds the barrier,
  offers no resume phase, and admits no further observation or decision. There is no
  `force_finalize`, `discard_transition`, `rewind_phase`, or `release_barrier`;
- `BlockedFinalityResolutionV1` retains `barrier_released` as an explicit always-false
  field so the central safety invariant is testable rather than implicit, and a decision
  answering a stale phase or a non-latest observation is refused; and
- 61 focused adversarial tests cover the blockable phase set, observation identity binding,
  operation and reason taxonomies, ordinal reconciliation, regression, and equivocation,
  cross-transition contamination, separation of duty by key and by principal, rotation
  refusal, signature-domain separation, invalid signatures, foreign scopes, stale phases,
  seal terminality, barrier invariants, manifest substitution, and absence of any ambient
  clock or network dependency.

This establishes the acceptance contract. Its storage follows below.

### Implemented schema-version-3 blocked-finality storage

- [ADR-0015](decisions/0015-durable-blocked-finality-storage-v3.md) raises
  `user_version` to 3 while the exact `application_id` stays `0x45545A31`;
- three append-only relations are added: singleton `integrity_recovery_profile`,
  `integrity_blocked_observations` keyed by `(event_digest, attempt_ordinal)` with a
  unique `observation_id`, and `integrity_recovery_decisions` keyed by `decision_id` with
  a unique `blocked_observation_id`. All three refuse update and delete by trigger;
- the recovery authority is enrolled as its own record rather than by extending
  `ModeledIntegrityAuthorityBindingV1`, so no existing `binding_id`, retained enrollment
  wire, or binding known-bad changes;
- there is no seal relation. A sealed instance is exactly the existence of a decision row
  whose `disposition` is `instance_sealed`, so the two cannot disagree;
- database triggers refuse an observation on a finalized transition, any observation or
  decision once a seal exists, and a decision whose `blocked_observation_id` is not the
  highest-ordinal retained observation for that transition;
- none of the new relations participate in the unresolved-transition barrier or the
  instance-global sequence. The barrier still joins `integrity_pending_transitions`
  against `integrity_finalizations` only, and the sequence remains `count(*)` over
  `integrity_finalizations`, so retaining a block cannot release finality;
- `_migrate_integrity_v2_to_blocked_v3` verifies the exact retained version-2 contract
  digest before adding the new objects in one `BEGIN IMMEDIATE` script, revalidates, and
  commits; a drifted version-2 layout fails closed. The migration adds relations only and
  backfills nothing, because no retained byte records why an earlier attempt failed;
- `_logical_evidence_storage_used_locked` charges the new record and wire bytes, and
  `_INTEGRITY_FINALITY_CAPACITY_RESERVE_BYTES_V1` widens to six record ceilings plus
  transition evidence because the reserve is taken once before the pending row is
  inserted; and
- the durable write path is deliberately outside `_call_modeled_integrity_adapter` and
  `_advance_finality`. Both funnels convert an unexpected exception into
  `IntegrityFinalityBlockedError`, so routing persistence through them would record that
  finality is blocked because recording that finality is blocked failed. `StoreBusyError`,
  `StoreCapacityError`, `StoreOperationalError`, and `EventStoreCorruptionError` keep
  their exact domains.

### Implemented governed blocked-finality lifecycle

- [ADR-0016](decisions/0016-governed-blocked-finality-lifecycle.md) adds an opt-in
  `GovernedBlockedFinalityBindingV1` holding the enrolled recovery profile and a
  qualified-time source; an unconfigured facade keeps its exact historical behaviour and a
  class-level default keeps deliberate `__init__` bypasses ungoverned;
- `_advance_finality` now wraps the unchanged classifier, renamed
  `_classified_advance_finality`. A durable observation is retained in the outer handler,
  so a store failure during retention keeps its own domain rather than being reclassified
  as a deterministic adapter refusal;
- the observation's phase, phase record identity, and operation are derived from the
  retained lineage, never from caller input, and a reason code outside the closed taxonomy
  is retained as `modeled_integrity_adapter_contract_failure` rather than widening the
  taxonomy with provider-controlled text;
- once an observation exists, recovery requires a retained governed decision answering the
  exact latest observation with disposition `retry_authorized`, or
  `IntegrityRecoveryNotAuthorizedError` is raised. This is the bound on retries: elapsed
  time and repetition are not authority;
- an authorized retry does not promise success. A still-refusing adapter blocks again and
  is retained under the next ordinal, so the attempt history accumulates; and
- a sealing decision never authorizes a retry, and `load`, `recover_pending_transition`,
  and `append` all raise `IntegrityInstanceSealedError`. Sealing fences off new work and
  never destroys retained evidence.

### Implemented blocked-finality crash recovery and status inspection

- [ADR-0017](decisions/0017-blocked-finality-crash-recovery.md) proves interruption on both
  sides of both retention points with a caller-side failure that is deliberately neither a
  store nor an adapter condition;
- death before observation retention leaves no row and the next attempt is ordinal 1, not
  2, because an unrecorded block did not happen;
- death after observation retention leaves exactly one row and replay is gated by the
  authorization check rather than duplicating it;
- repeated death across successive authorized retries yields ordinals `[1, 2, 3]` with
  three distinct observation identities, never reusing or skipping one;
- an interrupted observation leaves the barrier held and `integrity_finalizations` empty;
- death after decision retention reconciles on identical signed bytes, death before it
  leaves recovery unauthorized, and death after a sealing decision keeps the instance
  sealed;
- a reopened database sees exactly the retained observations, reason, and decision;
- an injected `StoreBusyError` during retention propagates as `StoreBusyError`, so
  recording that finality is blocked never becomes a deterministic adapter refusal;
- `IntegrityRecoveryNotAuthorizedError` now carries the retained attempt ordinal,
  unresolved phase, refused operation, and reason code, so a caller that lost the original
  error still learns why it is blocked; and
- `blocked_finality_status()` is a non-consequential inspection interface that cannot
  append, authorize, resolve, or return command success, proved by a known-bad asserting it
  retains and finalizes nothing.

Logical crash recovery is claimed only under the documented SQLite rollback-journal
assumptions and deterministic injected failures. It is not power-loss, device, or
production-storage qualification. The enrolled recovery key is repository-owned and proves
no independently custodied operator authority, dual control, audit delivery, or migration
of a sealed instance.

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

## Current schema-v4 qualified-acceptance enrollment

[ADR-0019](decisions/0019-qualified-evidence-lifecycle-consumption.md) step 1 is
implemented. SQLite `user_version` is now 4. A new append-only singleton
`integrity_acceptance_profile` table pins the qualified time-adapter and head-authority
trust profiles under a `qualified_signed_fixture` acceptance mode; absence of a row is the
`modeled_unsigned_code_derived` default. A `user_version` 3-to-4 migration adds the table
only and backfills nothing. `enroll_qualified_acceptance` is empty-history only, requires an
enrolled modeled profile, is idempotent and permanent, charges its bytes to logical storage,
and preserves store-domain error classification; four SQL triggers enforce immutability,
the modeled-profile requirement, and the empty-history requirement as defense in depth.
`resolve_acceptance_mode` and `load_qualified_acceptance_profiles` read it back. Nothing
consumes the mode yet, mirroring ADR-0015 before ADR-0016. Fifteen known-bads plus the
updated store-schema suite cover the migration, drift refusal, no-backfill, enrollment
exactness, requirements, immutability, forged-mode refusal, and capacity.

## Current qualified-consumption design record

[ADR-0019](decisions/0019-qualified-evidence-lifecycle-consumption.md) is a documentation
design record. It changes no code, schema, or test; the retained full-suite count is
unchanged. Local repository policy, mission-state JSON, and relative Markdown links passed;
the dual-runtime suite is unchanged and reproduced by CI. This adds no capability or
authority and does not supersede implementation evidence.

## Current schema-v4 qualified-acceptance enrollment release evidence

On the schema-version-4 qualified-acceptance enrollment candidate, the canonical release
command passed under both declared local runtimes:

- 1165 tests passed;
- the focused enrollment file passed all 15 tests, including the version-3-to-4 forward
  migration, drifted-layout refusal, no-backfill, empty-history and modeled-profile
  requirements, replacement refusal, immutability, forged-mode refusal, and capacity;
- the updated store-schema suite passed all 51 tests across the v1, v2, and v3 migration
  paths through v4;
- CPython 3.11.15 and 3.14.2 both loaded `application_id` `ETZ1` at `user_version` 4;
- the three inherited qualified-evidence acceptance files passed all 47 tests (16 anchor,
  17 revocation, 14 head-floor);
- the inherited focused crash-recovery file passed all 13 tests, covering interruption on both sides
  of both retention points, ordinal integrity across repeated interrupted retries, barrier
  retention, store-domain preservation, reopened-database replay, and non-consequential
  status inspection;
- the inherited focused lifecycle file passed all 11 tests, covering durable observation of a
  deterministic block, unclassifiable-reason fallback, the authorized-retry gate,
  accumulating attempt ordinals, seal terminality across load, recover, and append, and
  the ungoverned default;
- the inherited focused storage file passed all 23 tests, including the exact version-2 forward
  migration, drifted-layout refusal, append-only and terminality triggers, and the proof
  that retaining a block leaves the unresolved-transition barrier held;
- the inherited focused blocked-finality contract file passed all 61 tests and the
  deterministic report retained all eight ordered cases;
- the inherited focused head-authority qualification file passed all 78 tests;
- the deterministic head-authority report retained all nine ordered cases;
- the Merkle core reproduced the published RFC 6962/9162 reference tree heads for sizes
  zero through eight and verified all 36 reference inclusion proofs and all 36 reference
  consistency proofs;
- the inherited focused adapter-qualification file passed all 81 tests;
- the inherited deterministic qualification report retained all ten ordered cases;
- CPython 3.11.15 loaded SQLite 3.53.1 and used `DELETE`/`EXTRA`;
- CPython 3.14.2 loaded SQLite 3.51.2 and used `DELETE`/`EXTRA`;
- both runtimes retained their complete `sqlite_source_id()` values and proved isolated
  versus repository-import-context agreement;
- both hash-locked environments passed `pip check`;
- exact schema, semantic dispatch, repository policy, Ruff, fixture runs, and
  retained-evidence checks passed; and
- `git diff --check` passed.

The CPython 3.11 test suite completed in 492.90 seconds and the CPython 3.14 suite
completed in 502.67 seconds; the complete release entrypoints took 495 and 506 seconds. The
fail-closed retained-evidence gate correctly refused an earlier run whose collected count
(1158) led the not-yet-updated retained count (1143); the count was reconciled before this
validated run.
Each complete release entrypoint also ran the modeled demonstrations and the governed
vulnerable and clean fixture scans. The working-tree status was unchanged by validation.

The retained SQLite source identities were:

- CPython 3.11.15 / SQLite 3.53.1:
  `2026-05-05 10:34:17 c88b22011a54b4f6fbd149e9f8e4de77658ce58143a1af0e3785e4e6475127e9`;
- CPython 3.14.2 / SQLite 3.51.2:
  `2026-01-09 17:27:48 b270f8339eb13b504d0b2ba154ebca966b7dde08e40c3ed7d559749818cb2075`.

Private GitHub Actions run
[`30621809292`](https://github.com/manfromnowhere143/etzio/actions/runs/30621809292)
reproduced repository policy, both declared runtime suites, package build,
outside-checkout wheel smoke, clean-tree proof, and retained foundation evidence on exact
implementation commit
[`7882a8cd447d8a9364725298a0dd853bbe3b5942`](https://github.com/manfromnowhere143/etzio/commit/7882a8cd447d8a9364725298a0dd853bbe3b5942);
GitGuardian also passed. The 3.11.15 foundation job took 14 minutes 55 seconds and the
3.14.2 job took 15 minutes 2 seconds, both inside the 30-minute release budget. Pull
request [#18](https://github.com/manfromnowhere143/etzio/pull/18) targets `main`. This
evidence-only handoff and mission-state update follows the validated implementation commit.

The inherited governed-lifecycle tranche was reproduced by private run
[`30614243915`](https://github.com/manfromnowhere143/etzio/actions/runs/30614243915) on
implementation commit
[`092a89989ddf2b0e231bae91406bcde89f1c9f9d`](https://github.com/manfromnowhere143/etzio/commit/092a89989ddf2b0e231bae91406bcde89f1c9f9d);
GitGuardian also passed. The 3.11.15 foundation job took 14 minutes 42 seconds and the
3.14.2 job took 15 minutes 34 seconds, both inside the 30-minute release budget. Draft
[#16](https://github.com/manfromnowhere143/etzio/pull/16) is stacked on the
blocked-finality storage branch. This evidence-only handoff and mission-state update
follows the validated implementation commit.

The inherited storage tranche was reproduced by private run
[`30597483642`](https://github.com/manfromnowhere143/etzio/actions/runs/30597483642) on
implementation commit
[`80d6a0ea363b65cc47f0a01c8b6b9a3eb4d1df1a`](https://github.com/manfromnowhere143/etzio/commit/80d6a0ea363b65cc47f0a01c8b6b9a3eb4d1df1a);
GitGuardian also passed. The 3.11.15 foundation job took 13 minutes 49 seconds and the
3.14.2 job took 14 minutes 59 seconds, both inside the 30-minute release budget. Draft
[#15](https://github.com/manfromnowhere143/etzio/pull/15) is stacked on the
blocked-finality contract branch. This evidence-only handoff and mission-state update
follows the validated implementation commit.

The inherited blocked-finality contract tranche was reproduced by private run
[`30592555479`](https://github.com/manfromnowhere143/etzio/actions/runs/30592555479) on
implementation commit
[`a7bde73a1a79bc874d8c0f15db0780a58e24d056`](https://github.com/manfromnowhere143/etzio/commit/a7bde73a1a79bc874d8c0f15db0780a58e24d056),
with draft [#14](https://github.com/manfromnowhere143/etzio/pull/14) stacked on the
head-authority qualification branch; GitGuardian also passed.

The inherited head-authority tranche was reproduced by private run
[`30588650930`](https://github.com/manfromnowhere143/etzio/actions/runs/30588650930) on
implementation commit
[`377ed659da407dc87e4d3ae20cc00792914b5b44`](https://github.com/manfromnowhere143/etzio/commit/377ed659da407dc87e4d3ae20cc00792914b5b44),
with draft [#13](https://github.com/manfromnowhere143/etzio/pull/13) stacked on the
time-revocation qualification branch; GitGuardian also passed.

The inherited trusted-time/revocation tranche was reproduced by private run
[`30491151887`](https://github.com/manfromnowhere143/etzio/actions/runs/30491151887) on
implementation commit
[`3c7a30038de17a673674c81a36a3a3197f1d64e2`](https://github.com/manfromnowhere143/etzio/commit/3c7a30038de17a673674c81a36a3a3197f1d64e2),
with draft [#12](https://github.com/manfromnowhere143/etzio/pull/12) stacked on the
integrity-finality branch.

The evidence scope is repository-owned deterministic fixtures. It validates the
contract/harness boundary described above, not a real provider, native provider format,
truthful clock, real publication time, current external revocation state, independent
observers, external durability, real-world non-equivocation, survival of local database
loss, lifecycle integration, execution, finding, or live-target authority.

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

- blocked observations naming the resolved finalized phase or an unknown phase; observation
  identity substitution across ordinal, operation, reason, phase, phase record, pending
  record, and event; unsupported operations and reason codes; resolution, status, or
  disposition fields on an observation; a mission head above the global head; nonpositive
  attempt ordinals; exact-duplicate reconciliation, gap-filling ordinal regression,
  same-ordinal equivocation, and cross-transition contamination; substituted authority
  binding identity; a recovery key or principal equal to the decision or checkpoint
  authority; a rotated key under the same principal; a recovery key smuggled into the
  enrolled trust store; a wrong recovery role or small-order key; decision identity
  substitution across disposition, ordinal, phase, and reason; unsupported dispositions;
  undomained and invalid signatures; foreign profile scope; foreign algorithm; a signer
  answering another principal's decision; decisions for a non-latest or foreign
  observation; decisions answering a stale phase; every action after a seal; empty retained
  history; direct construction of every sealed result; corpus-manifest, reason, and phase
  substitution; a recovery signer that is not the retained key; and absence of any ambient
  clock or network dependency;
- head-authority profile/root/policy/service/environment/source/role/log-origin/key/
  principal/codec substitution; rosters missing a required anchor, catalog, or monitor;
  anchor sources sharing one log origin; monitors witnessing a foreign log origin or
  source; the published RFC 6962/9162 reference tree heads for sizes zero through eight;
  all 36 reference inclusion proofs and all 36 reference consistency proofs; leaf versus
  node domain separation; tampered, truncated, padded, substituted-leaf, out-of-range,
  forked, and unbounded proofs; asserted roots carried without a verifying proof; anchor
  and catalog tree rollback; equal-size root change; monitor split view; foreign-leaf and
  foreign-statement receipts; cross-request replay; resigned request, log-origin, statement,
  and claim substitution; invalid signatures; revoked fixture keys; signature-domain
  substitution across roles; half-open head freshness at both boundaries; instance-global
  and mission head regression; a mission head above the global head; exact evidence
  coverage; corpus-manifest, adapter-order, and retained-root substitution; absence of any
  ambient clock or network dependency; and direct construction of every sealed
  head-authority result;
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
3. The durable blocked disposition, exact reason, and governed recovery decision are now
   specified, deterministically proved, and persisted under schema version 3. No recovery
   path yet produces an observation or consumes a decision, so typed blocked results
   remain attempt-local in the live lifecycle.
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

**Exact next-session pickup:** ADR-0018 began qualified signed evidence consumption. A
seam audit established that the qualification harnesses already produce the exact
provider-neutral types the lifecycle consumes (`RevocationFloorV1`, `HeadCheckpointFloorV1`,
`EvidenceReferenceV1`); the only gap is that the modeled gate demands byte-equality against
unsigned code-derived content while a qualified BLOB carries the signed package. This
tranche specified two profile-selected acceptance modes and implemented the networkless
anchor-phase acceptance primitive in `etzio/kernel/qualified_evidence_v1.py`.

The acceptance-primitive layer is complete (anchor, revocation, head-floor).
[ADR-0019](decisions/0019-qualified-evidence-lifecycle-consumption.md) now specifies the
full lifecycle-consumption architecture: a schema-version-4 profile-selected acceptance
mode that pins the qualified adapter roots at enrollment, a modeled service that produces
signed-package evidence in qualified mode, and record validators that re-derive the
qualification requests from retained scope (each `request_id` is `content_id` over that
scope) and reauthenticate from the retained signed packages. The design resolves the
Side-A revocation `snapshot_id == metadata.evidence_id` coupling and the
`fixture.revocation-metadata` source rename, and sequences the work into five
dependency-complete tranches: (1) schema-v4 enrollment; (2) anchor-phase consumption;
(3) revocation-phase consumption; (4) head-floor-phase consumption; (5) qualified-path
crash recovery. Step 1 is the exact next pickup.
That is schema-touching: it changes the record bodies and `record_id`s, needs a store
profile that selects the mode at enrollment, must preserve every ADR-0012 integration
requirement plus its own crash-recovery known-bads, and is where the Side-A revocation
`snapshot_id == metadata.evidence_id` coupling and the `fixture.revocation-metadata` vs
`fixture.revocation` source rename are resolved. A real provider still requires its own
admitted grant.

The superseded storage scoping note follows for provenance only. The retained bytes make the
cost explicit: `_validate_schema` compares object sets for equality and therefore fails
closed on extra objects, so a new append-only blocked table needs new DDL in
`_integrity_schema_sql`, new `required_objects` entries for the table and its append-only
triggers, a recomputed `_SQLITE_SCHEMA_CONTRACT_SHA256`, and a `user_version` 3 migration
from the exact version-2 layout. The same tranche must add the recovery key and principal
to `ModeledIntegrityAuthorityBindingV1`, which changes its `binding_id`; charge the new
record's bytes in `_logical_evidence_storage_used_locked`; and widen
`_INTEGRITY_FINALITY_CAPACITY_RESERVE_BYTES_V1`, since the current 80 MiB reserve is
exactly four 16 MiB phase records plus 16 MiB of transition evidence and is taken once
before the pending row is inserted. The durable write path must not be funnelled through
`_call_modeled_integrity_adapter` or `_advance_finality`, or a failure to persist the
blocked record would be reclassified as an adapter contract failure. Add known-bads for
blocked-state mutation, unauthorized recovery, duplicate or conflicting disposition, and
recovery replay after interruption at every immutable phase. Do not connect a real
provider, alter the retained lifecycle state machine, add finder breadth, or add execution
capability.

Concrete continuation map:

1. begin from ADR-0014, `etzio/kernel/blocked_finality_v1.py`, and
   `tests/test_blocked_finality_qualification_v1.py`; preserve the append-only observation,
   the inadmissible finalized phase, the closed reason and operation taxonomies, separation
   of duty by key and principal, the restated observation binding, the two admissible
   dispositions, and the always-false `barrier_released` invariant;
2. specify the storage layout, migration, enrolled recovery authority, capacity
   accounting, and crash-recovery contract in a new decision before changing lifecycle
   behavior;
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

Only after the durable blocked-state persistence passes, qualify and connect independently
administered trusted-time, revocation, anchor, catalog, and monitor adapters inside the
retained state machine. Preserve exact
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
