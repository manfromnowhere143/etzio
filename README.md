# Etzio

Etzio is an evidence-native engine for authorized vulnerability research. Its design
connects exact permission and target bytes to a falsifiable candidate, independent reproduction and
kernel adjudication. The long-term objective is a research and remediation system whose
results can be replayed, challenged and corrected from retained evidence.

The kernel is target-neutral. Versioned domain and technique packs supply language,
analysis, execution and oracle knowledge. Solidity/EVM research is the first planned
benchmark domain; the mission extends to native code, web services, protocols, cloud,
mobile and supply chains.

**Current capability: a governed fixture kernel.** The supported analyzer has six Python
rule classes over two repository-owned fixtures. It produces `7` planted candidates on
the vulnerable fixture and `0` on the clean fixture. Modeled verification receipts and
signed fixture-provider packages exercise admission and recovery; independently produced
execution evidence, qualified native providers and a finding pipeline remain blocked.

A separate supervised bounty workflow proceeds alongside the kernel. Its source
reviews and owned toolchain preparation are retained below. It permits clearly
labeled self-reproduction under exact scope and isolation; no eligible report,
accepted bounty or payment has been established.

Start with the [engineering review guide](docs/REVIEW_GUIDE.md) for the claim-to-code/test
map and open risks, [architecture](docs/ARCHITECTURE.md) for the contracts, and the
[handoff](docs/SESSION_HANDOFF.md) for the exact release and continuation state. Public
source visibility is governed by [LICENSE.md](LICENSE.md).

## The system in one view

Authority → immutable target → falsifiable hypothesis → content-bound candidate → isolated
exploit artifact → independent reproduction → kernel adjudication → evidence-bound
disclosure → governed offline learning.

```text
authority → immutable target → leased observations → candidates
                                                    ├─ current retained boundary
                                                    └╌→ exploit proof → independent reproduction
                                                        → adjudication → disclosure draft → learning
```

This is the intended operating chain, not a runtime screenshot. Everything left of the
boundary is implemented on repository fixtures; everything right of it is a design target
gated behind isolation, benchmark, and exact-authority acceptance. The mission spans
vulnerability classes, languages, and target categories; blockchain, Solidity, and EVM
research are the first benchmark and economic wedge. Domain
knowledge belongs in versioned packs; policy and scientific authority stay in the kernel.
The implemented observations come from fixed AST rules. Hypothesis ranking remains a
planned research-worker capability.

## Why Etzio

A candidate identifies a falsifiable observation against specific bytes. A production kernel finding requires
a separately authorized verifier to reproduce a security-relevant effect from retained artifacts in an independently controlled
environment, followed by kernel adjudication.

That yields six production kernel operating laws:

1. authority is admitted before a mission opens;
2. workers propose; the kernel alone changes canonical state;
3. a generator cannot verify its own candidate;
4. evidence and identities are content-bound and replayable;
5. refusals, nulls, failures, timeouts, and inconclusive results remain visible; and
6. credentials, egress, spending, live actions, disclosure, and publication are separate
   grants.

## Current release and evidence

The preceding verified release is [`b010c08`](https://github.com/manfromnowhere143/etzio/commit/b010c0850c97a2280b452f64ab2dee0edc08a25e)
([PR 71](https://github.com/manfromnowhere143/etzio/pull/71), October 25, 2026):
`2971` tests passed on CPython `3.11.15` and `3.14.2`, locally and in
[Linux CI](https://github.com/manfromnowhere143/etzio/actions/runs/40181735173).
Both package builds and installed-wheel checks passed. These results cover repository
behavior under the recorded environments; discovery quality requires a separate benchmark.

The October 24 [process-death controls](docs/evidence/store-process-death-2026-10-24.json)
add `18` real `SIGKILL` cases around canonical evidence and qualified finality
commits, including spilled rollback pages. They check exact cold state and repeat
outcomes without changing the runtime. Process death does not qualify power loss
or production storage. The [mission review](docs/MISSION_REVIEW_2026-10-24.md)
sets out the remaining operational chain to a measured, authorized bounty lane.

The released [evidence-close repair](docs/evidence/evidence-close-ownership-2026-10-21.json)
prevents cleanup from retrying an ambiguous close and closing an unrelated reused descriptor.
Its `18` new controls fail on the predecessor and pass after correction on both runtimes;
all `97` focused evidence tests pass. Existing evidence and retries remain intact.
The retained [recovery composition controls](docs/evidence/qualified-governed-recovery-2026-10-21.json)
add eleven signed-fixture schedules for cold restart and concurrently changed authority.
All `67` focused tests pass per runtime; deliberately removing authorization gates fails
the eight corresponding refusal controls. The existing runtime passes without a repair.

The October 25 [owned collector-death controls](docs/OWNED_COLLECTOR_DEATH_PREFLIGHT.md)
measure real collector SIGKILL, watchdog cleanup and a deliberately withheld
watchdog. The negative control refuses primary acceptance and uses separately
bounded cleanup. All four attempts are retained and their cloud resources deleted.
This remains preparation for an execution profile; no target or finding is admitted.

The October 25 [resource and peer controls](docs/OWNED_RESOURCE_PREFLIGHT.md)
measure cgroup OOM and task ceilings, then bidirectional file/API/signal denial,
input immutability and abstract-socket namespace separation between two owned
workers. All attempts and cleanup evidence are retained. The
[containment packet](docs/CONTAINMENT_REVIEW_2026-10-25.md) now follows the
[solo supervised workflow](docs/decisions/0026-solo-supervised-bounty-workflow.md):
the assistant may assess an exact measured profile without recruiting an outside
reviewer. This changes an internal workflow prerequisite, not a target's permission.

The latest private Aave source review closes `5` hypotheses without an eligible
report. It binds `21` source/support files, `6` published audits and an official
proposal report. An owned integer model passed `422619` finite checks and rejected
`3` deliberately wrong variants; these are neither EVM runs nor independent proof.
Known issues, contrary evidence and deployment limits remain retained privately.

[Owned compiler preparation](docs/SUPERVISED_TOOLCHAIN_PREPARATION.md) pins official
Foundry `1.8.6` and Solidity `0.8.38` binaries. Two fixed guest images, one intended
to pass and one intended to fail, match across `2` builds and `8` artifact pairs.
An earlier assembler failure is retained. The compiler and guest images have
not been executed; this is preparation for the next isolated calibration.

The full collection is `2971` tests; resolve exact full-suite, package and CI results from
the [release handoff](docs/SESSION_HANDOFF.md). Earlier byte-admission, cleanup, accounting
and protocol corrections remain in the retained release history.

## Progress through 2026-10-25

| Workstream | Retained progress | Remaining boundary |
|---|---|---|
| Governed fixture kernel | Signed admission, immutable inputs, candidate and lease lineages, transactional evidence vault, deterministic replay and schema-v4 qualified fixture enrollment | Six Python rule classes and two owned scan fixtures; no independently verified security effect |
| Integrity and recovery | Four immutable finality phases, authenticated signed-fixture packages, governed retry/seal decisions and interruption controls | Actual independent provider administration and external latest-head recovery are unqualified |
| Native evidence preparation | Offline timestamp/CRL validation, conditional elapsed-time bounds, trusted-list and checkpoint inspection, source-provenance reconciliation | Documentary and offline observations do not admit a live provider; both FreeTSA acquisition attempts are spent |
| Host preparation | Benign KVM, owned guest, collector-death, resource-exhaustion and cross-worker controls measured; disposable resources deleted | No target profile, protected storage or power-fault qualification |
| Repository reliability | Cleanup and coherent-read repairs, exact evidence-byte admission, interrupted setup cleanup, ambiguous close ownership, qualified recovery and real canonical process-death controls | `2971` tests in the current collection; release checks establish repository behavior only |
| Research and comparison | Targeted primary-source reviews through October 24; verifier acceptance, model-specific skill evaluation and explicit proof scope refine the retained comparison | Experiment order selected; `18` registration inputs remain unbound; no comparator has run |
| Supervised bounty research | CoW, GHO and Aave source dispositions retained; latest Aave batch has `5` hypotheses and no eligible report; ADR-0026 permits labeled self-reproduction | Exact eligible target applicability and accepted isolation precede proof work; no confirmed finding or payment |
| Supervised toolchain | Publisher digests checked; `2` fixed owned compiler fixtures built identically twice | Guest execution and positive/failing result calibration have not run; no general target runner is admitted |
| Operating dependencies | Eight organizations previously contacted for catalog or monitor roles; October 24 readback records one decline already acknowledged by the operator | No commitment in seven reread provider/customer conversations; other threads and channels unobserved |
| Upstream engineering | [Source review contributed to Tessera issue 1098](https://github.com/transparency-dev/tessera/issues/1098#issuecomment-6320024671), with producer error cleanup and worker completion controls | No native reproduction, upstream fix or maintainer acceptance established |
| Customer discovery | Two new inquiries proposing a small paid design pilot on synthetic evidence, with current capability limits stated | No customer engagement, delivery commitment or payment established |

The [engineering review record](docs/evidence/reviewer-readiness-2026-10-16.json)
retains the preceding presentation review. The latest
[mission review](docs/MISSION_REVIEW_2026-10-24.md) assesses discovery claims, verifier
acceptance, proof scope and the dependency-complete path to bounty work. Private source captures, correspondence and
recovery copies are excluded from the published repository; their paths are continuity
locators, not downloadable evidence in a fresh clone. Model-access onboarding is separate
from provider admission, target permission and execution qualification.

This progress map shows the production engine's accepted dependency order, not an operating
pipeline. Solid edges connect the implemented fixture foundation; dashed edges require new
acceptance evidence. Preparation is complete only for its named, bounded scope.

The parallel supervised report workflow follows
[ADR-0025](docs/decisions/0025-parallel-supervised-bounty-research.md) and
[ADR-0026](docs/decisions/0026-solo-supervised-bounty-workflow.md). It requires exact
program and target scope, accepted containment and bounded actions. The assistant
may develop and repeat proofs with self-reproduction stated explicitly, without
an outside reviewer or completed production-provider qualification. Independent
assessment is only claimed after it occurs. This workflow cannot issue a production
kernel finding, and report submission retains separate authority.

```mermaid
---
config:
  theme: base
  fontFamily: Arial
  themeVariables:
    fontFamily: 'Arial'
    fontSize: '15px'
    primaryColor: '#edf4fb'
    primaryTextColor: '#18344d'
    primaryBorderColor: '#6b8ba8'
    lineColor: '#62788d'
    clusterBkg: '#f8fafc'
    clusterBorder: '#c5d1dd'
    edgeLabelBackground: '#ffffff'
  flowchart:
    curve: linear
    nodeSpacing: 28
    rankSpacing: 48
    padding: 16
    wrappingWidth: 260
    subGraphTitleMargin:
      top: 12
      bottom: 20
---
flowchart TB
    accTitle: Production engine — retained foundation and open gates
    accDescr: The fixture foundation is implemented. Native integrity, external recovery, protected storage and independent execution are blocked. Evaluation and bounty outcomes remain proposed; dashed arrows indicate dependencies, not execution.
    subgraph FOUNDATION["01 · Fixture foundation"]
        K["<b>Fixture kernel</b><br/>Authority · candidates · evidence vault<br/>IMPLEMENTED ON FIXTURES"]
        F["<b>Integrity and recovery</b><br/>Signed qualification · finality · retry / seal<br/>IMPLEMENTED ON FIXTURES"]
        P["<b>Qualification preparation</b><br/>Native-format inspection · KVM preflight<br/>Research · source review · operator inquiries"]
        K --> F
    end
    subgraph NATIVE["02 · Production gates"]
        N["<b>Native integrity · BLOCKED</b><br/>Independent operating commitments"]
        R["<b>Latest-head recovery · BLOCKED</b><br/>Effective writer fencing"]
        S["<b>Protected storage · BLOCKED</b><br/>Device · quotas · backup · fault recovery"]
        X["<b>Independent execution · BLOCKED</b><br/>MARCELLUS / CATO<br/>Explicitly admitted isolation"]
        N -.-> R -.-> S -.-> X
    end
    subgraph EVALUATION["03 · Proposed evaluation"]
        B["<b>Admitted EVM benchmark</b><br/>Exact targets · frozen protocol"]
        E["<b>Controlled comparison · NOT RUN</b><br/>Static / fuzzing / model / hybrid"]
        A["<b>Separate feature experiments</b><br/>Semantic guidance · scheduling<br/>Evidence reuse"]
        U["<b>Authorized bounty lane · FUTURE</b><br/>Independent findings<br/>Accepted outcomes"]
        B -.-> E -.-> U
        E -.-> A
    end
    F -.-> N
    P -. "preparation is not admission" .-> N
    X -.-> B

    classDef core fill:#18344d,stroke:#18344d,color:#ffffff,stroke-width:2px;
    classDef retained fill:#eaf5f0,stroke:#468570,color:#173e32,stroke-width:1.5px;
    classDef fixture fill:#edf4fb,stroke:#6b8ba8,color:#18344d,stroke-width:1.5px;
    classDef qualified fill:#fff5e3,stroke:#af8137,color:#624719,stroke-width:1.5px;
    classDef planned fill:#f4f3f8,stroke:#8a829e,color:#48415a,stroke-width:1.5px,stroke-dasharray:5 4;
    classDef blocked fill:#fff0ef,stroke:#ad6461,color:#713735,stroke-width:1.5px;
    class K,F retained;
    class P fixture;
    class N,R,S,X blocked;
    class B,E,A,U planned;
    style FOUNDATION fill:#f8fafc,stroke:#c5d1dd,color:#304b63,stroke-width:1px
    style NATIVE fill:#f8fafc,stroke:#c5d1dd,color:#304b63,stroke-width:1px
    style EVALUATION fill:#f8fafc,stroke:#c5d1dd,color:#304b63,stroke-width:1px
```

The supervised workflow has its own current boundary. Building an image does not
establish execution or vulnerability impact. The detailed
[supervised evidence path](docs/ARCHITECTURE.md#supervised-evidence-path) separates
self-reproduction, report preparation and actual program assessment.

```mermaid
---
config:
  theme: base
  fontFamily: Arial
  themeVariables:
    fontFamily: 'Arial'
    fontSize: '15px'
    primaryColor: '#edf4fb'
    primaryTextColor: '#18344d'
    primaryBorderColor: '#6b8ba8'
    lineColor: '#62788d'
    clusterBkg: '#f8fafc'
    clusterBorder: '#c5d1dd'
    edgeLabelBackground: '#ffffff'
  flowchart:
    curve: linear
    nodeSpacing: 28
    rankSpacing: 48
    padding: 16
    wrappingWidth: 260
    subGraphTitleMargin:
      top: 12
      bottom: 20
---
flowchart TB
    accTitle: Supervised research — evidence retained and the next experiment
    accDescr: Source review retains no eligible report. Two owned compiler images have matching rebuilds but have not run. Isolated calibration must precede an exact scoped proof. Neither proof nor payment is established.
    subgraph RETAINED["Retained evidence"]
        SR["<b>Source review</b><br/>Hypotheses and contrary evidence<br/>No eligible report"]
        BI["<b>Owned compiler fixtures</b><br/>Two images · matching rebuilds<br/>BUILT · NOT EXECUTED"]
    end
    subgraph NEXT["Next · not run"]
        CAL["<b>Isolated compiler calibration</b><br/>Expected pass and failure<br/>Measured execution and cleanup"]
        NX["<b>Exact scoped proof</b><br/>Eligible target · accepted isolation<br/>Self-reproduction stated explicitly"]
    end
    BI -. "execute owned calibration" .-> CAL
    SR -. "eligibility evidence" .-> NX
    CAL -. "accepted measured result" .-> NX

    classDef core fill:#18344d,stroke:#18344d,color:#ffffff,stroke-width:2px;
    classDef retained fill:#eaf5f0,stroke:#468570,color:#173e32,stroke-width:1.5px;
    classDef fixture fill:#edf4fb,stroke:#6b8ba8,color:#18344d,stroke-width:1.5px;
    classDef qualified fill:#fff5e3,stroke:#af8137,color:#624719,stroke-width:1.5px;
    classDef planned fill:#f4f3f8,stroke:#8a829e,color:#48415a,stroke-width:1.5px,stroke-dasharray:5 4;
    classDef blocked fill:#fff0ef,stroke:#ad6461,color:#713735,stroke-width:1.5px;
    class SR retained;
    class BI fixture;
    class CAL,NX planned;
    style RETAINED fill:#f8fafc,stroke:#c5d1dd,color:#304b63,stroke-width:1px
    style NEXT fill:#f8fafc,stroke:#c5d1dd,color:#304b63,stroke-width:1px
```

### Progress through 2026-10-15

The [October 15 snapshot](docs/evidence/documentation-handoff-2026-10-15.json) retains the
preceding `2617`-test baseline, research reviews and provider readback. The current table
above incorporates the October 16, 18 and 21 repairs and bounded follow-through without changing gate
order or promoting source hypotheses into findings.

## Current-state guide

- **Today:** the supported fixture CLI reaches stable candidates and `mission_closed` on
  the permanent SQLite legacy profile. Separate kernel APIs retain modeled verification
  lifecycle statements; an optional empty-store facade exercises modeled finality.
- **Signed-fixture qualification:** three separate deterministic, networkless harnesses prove
  exact request/profile/root/policy authentication, complete-roster conservative time
  fusion, full-hull revocation validity/freshness/floor checks, RFC 9162 inclusion and
  consistency verification, unanimous monitor agreement on one catalog head, and sealed
  mapping for repository-owned signed fixtures. An explicitly enrolled qualified mode now
  consumes their signed packages at all four finality phases and reconstructs them on replay.
- **Governed blocked finality:** a refused finality attempt is now a durable, reasoned,
  content-addressed observation introduced in schema version 3 and retained in current schema version 4. Recovery past a
  block requires a signed decision from a principal and key separated from both the
  integrity-decision and head-checkpoint authorities. Exactly two dispositions exist —
  authorized retry and terminal instance sealing — and neither finalizes, deletes,
  rewrites, mints a checkpoint, or releases the database-global barrier.
- **Modeled evidence:** receipt outputs and integrity-provider assertions are authenticated
  or code-derived fixture statements. Unsigned modeled mode and qualified signed-fixture
  mode remain distinct enrollments. Signatures authenticate fixture producers; they do not
  turn their statements into external observations. Neither path establishes execution,
  trustworthy UTC, current real
  revocation, independent administration, external durability, or a finding.
- **Blocked production target system:** exploit construction, hard isolation, independent
  reproduction, adjudication, governed disclosure, evaluated promotion, live targets, and
  production external finality remain unavailable.

The optional [native-time qualification profile](docs/decisions/0020-offline-native-time-qualification.md)
now validates repository-owned RFC 3161/5816 bytes with pinned pyHanko and retains an
OpenSSL comparison. It checks exact request binding, certificate/CRL evidence and the full
time-uncertainty interval. Its offline observation has no kernel authority; no external
provider is connected.

A separate [RSA chain profile](docs/decisions/0021-offline-rsa-timestamp-chains.md) now
covers an intermediate CA, both revocation roles and a closed issuer qualified statement.
Its [19-case OpenSSL comparison and provider research](tools/native-time-rsa/README.md)
are retained, with `241` new tests. The statement does not establish legal
qualification, and no native provider is admitted.

A separate [public-material replay](docs/PUBLISHED_TSA_MATERIAL.md) now retains a published
historical signer chain and both CRLs, with `44` diagnostic controls and a local nine-case
OpenSSL path comparison. It does not establish the current service signer or admit a time source.

The [elapsed-time contract](docs/decisions/0022-native-time-consumption-bounds.md) now
propagates native timestamp issuance intervals to receipt and use under explicit clock
error assumptions. Its offline evaluator refuses delays and complete intervals crossing
an evaluation window. Real clock qualification and the actual consequential use point
remain prerequisites to integration.

## Implemented vertical slice

The supported `etzio` command can analyze only the two repository-owned manifest fixtures
and closes each completed scan:

```text
manifest fixture → content-addressed target snapshot
  → ephemeral operator key + target-bound signed fixture grant
  → self-verifying authority admission
  → bounded analysis lease
  → byte-bound Python AST observations
  → stable candidate envelopes
  → deterministic replay from append-only lifecycle-validated events
  → SQLite schema-v4 store with legacy profile → mission_closed
```

This supported CLI path has no integrity-finality lineage.

An explicit fixture-only kernel path may instead admit both `static_analysis` and
`modeled_fixture_verification`, retain a completed scan with candidates, issue an AQUILA
verification lease, resolve its predeclared inputs under code-owned artifact types, retain
one canonical ETZIO resolution event, and admit one signed modeled receipt. A single
`verifier_receipt_admitted` event retains the decision trust snapshot and four code-derived
typed output bindings while consuming the lease. A canonical lease lineage can also retain
explicit expiry, pre-deadline modeled cancellation, or atomic reassignment to a different
verifier, then close with exact complete or incomplete receipt coverage. This is
authenticated statement and lifecycle-decision retention—not PoC, oracle, or verifier
execution and not finding adjudication.

When that repository-fixture flow is attached to the exact
`ModeledIntegrityFinalizingEventStoreV1` facade on an empty store using the
repository-supplied qualified deterministic fixture service, each event first commits with
its complete signed decision dossier, then advances through retained anchor statement,
signed checkpoint candidate, and exact-current external-floor records. Recovery repeats
only the same byte-bound anchor registration and checkpoint publication. The ordinary
fixture CLI remains on the legacy profile; this concrete modeled-finality composition is a
deterministic qualification surface, not production external authority.

The supported CLI, explicit fixture kernel path, and repository-supplied deterministic
finality composition have no arbitrary target-path option and do not execute a PoC, use the
network, access credentials, spend, disclose, publish, or mint a finding. The service-port
interfaces do not mechanically prohibit egress or credentials in an arbitrary replacement;
structural conformance alone does not admit one.

The protocol-v1 foundation includes:

- canonical JSON with duplicate-key rejection, Unicode 17.0.0 NFC, signed 64-bit integers,
  fixed resource ceilings, and full domain-separated SHA-256 identities;
- an installed Draft 2020-12 semantic wire schema with exact branches for all eleven typed
  object kinds and all eighteen event payload variants;
- Ed25519 authority and modeled-receipt attestations, including prime-subgroup public-key
  validation before a key can enter a trust snapshot;
- required-attestation contracts for pre-transition integrity decisions and
  post-transition head checkpoints, with proposed-event binding, conservative time
  intervals and ordering, context-typed provider evidence, exact current and predecessor
  signed-attestation provenance, scope-bound nonstale revocation/head floors, and distinct
  principals;
- a separate V1 trusted-time and revocation adapter conformance contract and deterministic
  networkless qualification harness with an exact copied validation policy, complete trust
  root, fixed source/key/principal/role roster, role-separated Ed25519 fixture signatures,
  authentication-before-claim parsing, nonce-bound requests, all-source common-overlap and
  conservative-outer-hull time fusion, full-hull revocation validity/freshness plus
  metadata-and-floor agreement, freshly reauthenticated sealed mappings, exact signed-BLOB
  coverage, and substitution, replay, staleness, ambiguity, roster, and mutation
  known-bads;
- an irreversible schema-v2 modeled-integrity profile for an empty history, with atomic
  event-plus-pending retention, four append-only recovery phases, byte-exact two-stage
  idempotency, one instance-global pending barrier, and exact current global/mission floor
  finalization before the fixture facade returns; the default modeled profile uses unsigned
  assertions, while schema-v4 qualified enrollment requires signed packages and cold
  reconstruction under exact copied roots, scope and policy;
- exact-type composition boundaries that copy trust and policy inputs and rebuild fresh
  authenticated snapshots from verified wire before continuity logic runs;
- exact fixture manifests, a bounded private filesystem staging/cache store, and a
  canonical SQLite evidence vault retaining exact immutable BLOBs;
- immutable target, authority, lease, candidate, receipt, and event objects;
- kernel-issued verification-lease events binding retained authority, target, candidate,
  modeled-fixture grant evidence, and the exact issuance-trust snapshot identity;
- type-domain-separated verification-input identities plus one replayable resolution event
  that binds every target, PoC, supporting-evidence, environment, and oracle-specification
  byte to the retained lease;
- a signed receipt binding that exact resolution plus execution, effect,
  measured-environment, and termination output digest/size pairs under four separate
  code-owned artifact types;
- one atomic receipt-admission event that retains the complete decision trust view,
  preserves every allowed verdict, and derives single-use lease consumption through
  replay;
- explicit lease expiry, modeled cancellation, atomic nonbranching reassignment, and
  terminal receipt-coverage events with exhaustive candidate partitions;
- atomic event, role-mapping, and BLOB retention for `authority_admitted`,
  `mission_opened`, `verification_artifacts_resolved`, and
  `verifier_receipt_admitted`, with code-derived manifests, staging-independent committed
  replay/retry, and fail-closed corruption handling;
- a strict Etzio-identified and versioned SQLite schema with explicit refusal of nonempty
  pre-vault state, bounded direct BLOB ingestion, and a configurable per-opening logical
  evidence-storage ceiling that defaults to 1 GiB and charges distinct vault BLOBs,
  integrity-provider BLOBs, canonical integrity-phase records, and modeled profile,
  policy, and fixture-adapter authority-binding bytes; enrollment and each pending append
  additionally preflight 80 MiB of worst-case finality headroom;
- uniform compare-and-append SQLite `DELETE`/`EXTRA` storage across every declared runtime,
  with pre-open WAL-header refusal, loaded-version/fix diagnostics, and fail-closed
  authentication of journal mode, synchronization, foreign keys, trusted schema, CHECK
  enforcement, read isolation, and writable-schema state on cached replay and every writer
  boundary; and
- known-bad tests for signature, scope, identity, lifecycle, budget, corruption, replay,
  and filesystem-boundary failures.

Here, **atomic retention** means same-transaction SQLite behavior exercised by repository
tests under the documented runtime and storage assumptions. It is not a claim of
protection against coherent same-user offline rewrite, unqualified VFS/device behavior, or
power loss.

CPython 3.11.15/SQLite 3.53.1 and CPython 3.14.2/SQLite 3.51.2 both use the
same rollback-journal policy. Canonical verification records the runtime-reported SQLite
version and source ID and rejects a different SQLite identity under the repository import
context. This is dependency evidence, not binary provenance or a general storage-safety
claim.

## System map

This full composition shows authority, candidate admission, modeled verification, signed
qualification and both storage profiles. All run within one trusted host process. The
supported CLI uses the legacy profile; finality is available only through explicit APIs on
an enrolled empty store. VELITES supplies the bounded AST analysis. The same diagram is
retained in [Architecture](docs/ARCHITECTURE.md#qualified-fixture-composition).

The [diagram history](docs/DIAGRAM_HISTORY.md) traces the October 15 rewrite and October 16
move that reduced the earlier README detail. This October 25 restoration brings the current
composition back to the front page and applies one visual language across all ten diagrams.

```mermaid
---
config:
  theme: base
  fontFamily: Arial
  themeVariables:
    fontFamily: 'Arial'
    fontSize: '15px'
    primaryColor: '#edf4fb'
    primaryTextColor: '#18344d'
    primaryBorderColor: '#6b8ba8'
    lineColor: '#62788d'
    clusterBkg: '#f8fafc'
    clusterBorder: '#c5d1dd'
    edgeLabelBackground: '#ffffff'
  flowchart:
    curve: linear
    nodeSpacing: 28
    rankSpacing: 48
    padding: 16
    wrappingWidth: 260
    subGraphTitleMargin:
      top: 12
      bottom: 20
---
flowchart TB
    accTitle: Implemented fixture composition — authority, candidates, qualification and storage
    accDescr: All components share one trusted host. Authority and immutable inputs feed candidate admission and optional modeled verification. Signed-fixture qualification feeds only qualified finality enrollment. Legacy and enrolled SQLite profiles remain distinct; no execution or finding is established.
    subgraph AUTH["01 · Authority and control"]
        direction LR
        AQ["<b>AQUILA</b><br/>Fixture authority<br/>Budgets · leases"]
        S[("<b>Filesystem staging / cache</b><br/>Bounded pre-ingestion bytes")]
        K["<b>ETZIO kernel</b><br/>Fixture protocol<br/>Lifecycle · replay"]
    end

    subgraph SCAN["02 · Candidate path"]
        direction LR
        V["<b>VELITES</b><br/>Narrow AST observations"]
        KC["<b>Candidate admission</b><br/>Construct · validate · retain"]
        C["<b>Stable candidates</b><br/>Not findings"]
    end

    subgraph OPTIONAL["03 · APIs and storage"]
        direction LR
        VR["<b>Verification-intent APIs</b><br/>Modeled lease · resolution · recovery<br/>Signed opaque receipts · no execution"]
        DBL[("<b>SQLite v4 · legacy profile</b><br/>Supported CLI<br/>Ordinary kernel store")]
        IF["<b>Fixture-finality facade</b><br/>Mode selected at enrollment"]
        DBM[("<b>SQLite v4 · enrolled profile</b><br/>Fixture integrity<br/>Permanent after enrollment")]
    end

    subgraph QUAL["04 · Fixture qualification"]
        direction LR
        AP["<b>Exact adapter profile</b><br/>Trust root · validation / provider policies<br/>Fixed all-source roster"]
        SP["<b>Role-separated signed packages</b><br/>Ed25519 · nonce-bound requests<br/>Authenticate before claim parsing"]
        TH["<b>All-source time</b><br/>Common overlap<br/>Conservative outer hull"]
        RF["<b>Full-hull revocation</b><br/>Validity · staleness<br/>Metadata and floors"]
        HH["<b>Head authority</b><br/>RFC 9162 inclusion + consistency<br/>Unanimous catalog monitors"]
        SM["<b>Sealed provider-neutral mapping</b><br/>Fresh reauthentication · exact BLOBs<br/>Qualified lifecycle input"]
    end

    AQ --> K
    S -->|"first canonical ingestion"| K
    K -->|"analysis lease + immutable bytes"| V
    V -->|"typed observations"| KC --> C
    K -->|"explicit command · action admitted<br/>before mission opening"| VR
    C -->|"exact retained candidate input"| VR
    VR -->|"canonical events + evidence"| DBL
    K <--> DBL
    K -->|"optional empty-store facade"| IF
    IF <--> DBM
    AP --> SP
    SP --> TH
    SP --> RF
    SP --> HH
    TH -->|"complete time hull"| RF
    TH -->|"complete time hull"| HH
    TH --> SM
    RF --> SM
    HH --> SM
    SM -->|"qualified enrollment only"| IF

    classDef core fill:#18344d,stroke:#18344d,color:#ffffff,stroke-width:2px;
    classDef retained fill:#eaf5f0,stroke:#468570,color:#173e32,stroke-width:1.5px;
    classDef fixture fill:#edf4fb,stroke:#6b8ba8,color:#18344d,stroke-width:1.5px;
    classDef qualified fill:#fff5e3,stroke:#af8137,color:#624719,stroke-width:1.5px;
    classDef planned fill:#f4f3f8,stroke:#8a829e,color:#48415a,stroke-width:1.5px,stroke-dasharray:5 4;
    classDef blocked fill:#fff0ef,stroke:#ad6461,color:#713735,stroke-width:1.5px;
    class K core;
    class AQ,V,KC,C,DBL retained;
    class S,VR,IF,DBM fixture;
    class AP,SP,TH,RF,HH,SM qualified;
    style AUTH fill:#f8fafc,stroke:#c5d1dd,color:#304b63,stroke-width:1px
    style SCAN fill:#f8fafc,stroke:#c5d1dd,color:#304b63,stroke-width:1px
    style OPTIONAL fill:#f8fafc,stroke:#c5d1dd,color:#304b63,stroke-width:1px
    style QUAL fill:#f8fafc,stroke:#c5d1dd,color:#304b63,stroke-width:1px
```

The CLI closes a scan with candidates. The explicit verification-intent APIs retain leases,
resolved bytes and signed modeled receipts. Neither path executes a proof artifact or
creates a finding. The enrolled facade adds integrity finality; its provider inputs remain
repository-owned fixtures. Labels carry these distinctions independently of color.

The optional integrity facade retains four immutable local phases. Its enrolled mode selects
unsigned modeled assertions or qualified signed-fixture packages. Both remain local fixture
sources. A future independently administered adapter set must satisfy the same state machine
and prove external authority at each trust, write and read boundary:

```mermaid
---
config:
  theme: base
  fontFamily: Arial
  themeVariables:
    fontFamily: 'Arial'
    fontSize: '15px'
    primaryColor: '#edf4fb'
    primaryTextColor: '#18344d'
    primaryBorderColor: '#6b8ba8'
    lineColor: '#62788d'
    clusterBkg: '#f8fafc'
    clusterBorder: '#c5d1dd'
    edgeLabelBackground: '#ffffff'
  flowchart:
    curve: linear
    nodeSpacing: 28
    rankSpacing: 48
    padding: 16
    wrappingWidth: 260
    subGraphTitleMargin:
      top: 12
      bottom: 20
---
flowchart TB
    accTitle: Fixture finality — four immutable phases and one global barrier
    accDescr: A proposed event and signed decision precede atomic pending retention. Process-local catalog rehydration is not a durable protocol write. Anchor and checkpoint bytes are retained before byte-identical retries. Only verified finalization releases the database-global barrier.
    subgraph ADMISSION["Admission · exact prior state"]
        E["<b>Proposed event</b><br/>Prior global + mission heads"]
        D["<b>Signed integrity decision</b><br/>Enrolled profile · authenticated dossier"]
        E --> D
    end
    subgraph RETENTION["Four immutable phases"]
        P1["<b>01 · Pending event</b><br/>Atomic event + dossier<br/>Required evidence"]
        RH["<b>Catalog rehydration</b><br/>Process-local · not durable<br/>Not a protocol write"]
        P2["<b>02 · Retained anchor statement</b><br/>Then byte-identical registration retry"]
        P3["<b>03 · Signed checkpoint candidate</b><br/>Then byte-identical publication retry"]
        P4["<b>04 · Retained finalization</b><br/>Exact current global + mission floor"]
        P1 --> RH --> P2 --> P3 --> P4
    end
    B["<b>Database-global barrier</b><br/>Blocks later appends and generic replay<br/>Held from phase 01 until verified phase 04"]
    OK["<b>Fixture facade returns success</b><br/>No execution or finding claim"]
    D --> P1
    P1 -. "establishes" .-> B
    P4 -. "verified completion releases" .-> B
    P4 --> OK

    classDef core fill:#18344d,stroke:#18344d,color:#ffffff,stroke-width:2px;
    classDef retained fill:#eaf5f0,stroke:#468570,color:#173e32,stroke-width:1.5px;
    classDef fixture fill:#edf4fb,stroke:#6b8ba8,color:#18344d,stroke-width:1.5px;
    classDef qualified fill:#fff5e3,stroke:#af8137,color:#624719,stroke-width:1.5px;
    classDef planned fill:#f4f3f8,stroke:#8a829e,color:#48415a,stroke-width:1.5px,stroke-dasharray:5 4;
    classDef blocked fill:#fff0ef,stroke:#ad6461,color:#713735,stroke-width:1.5px;
    class E,RH fixture;
    class D qualified;
    class P1,P2,P3,P4,OK retained;
    class B core;
    style ADMISSION fill:#f8fafc,stroke:#c5d1dd,color:#304b63,stroke-width:1px
    style RETENTION fill:#f8fafc,stroke:#c5d1dd,color:#304b63,stroke-width:1px
```

The following companion diagram shows the implemented opt-in recovery contract within
the fixture lifecycle. Its relations were introduced in schema v3 and remain in the
current schema-v4 store. Neither a recovery decision nor elapsed time releases finality.

```mermaid
---
config:
  theme: base
  fontFamily: Arial
  themeVariables:
    fontFamily: 'Arial'
    fontSize: '15px'
    primaryColor: '#edf4fb'
    primaryTextColor: '#18344d'
    primaryBorderColor: '#6b8ba8'
    lineColor: '#62788d'
    clusterBkg: '#f8fafc'
    clusterBorder: '#c5d1dd'
    edgeLabelBackground: '#ffffff'
  flowchart:
    curve: linear
    nodeSpacing: 28
    rankSpacing: 48
    padding: 16
    wrappingWidth: 260
    subGraphTitleMargin:
      top: 12
      bottom: 20
---
flowchart TB
    accTitle: Blocked finality — retained observation and governed disposition
    accDescr: A deterministic refusal retains the exact phase, operation, reason and attempt ordinal. A decision from a separated key and principal must bind the latest observation. Retry returns to that phase; sealing is terminal. Neither disposition releases the unresolved-transition barrier.
    subgraph OBSERVATION["01 · Retain the block"]
        PH["<b>Exact highest retained phase</b><br/>Pending · anchor · checkpoint candidate"]
        REF["<b>Deterministic finality refusal</b>"]
        OBS["<b>Durable blocked observation</b><br/>Phase · operation · reason · attempt ordinal"]
        PH --> REF --> OBS
    end
    subgraph GOVERNANCE["02 · Governed disposition"]
        DEC{"<b>Signed decision</b><br/>Different key AND principal<br/>Latest observation binding"}
        RETRY["<b>Authorized retry</b><br/>Resume the exact retained phase"]
        SEAL["<b>Terminal instance seal</b><br/>Load / recover / append refuse<br/>Retained bytes remain readable"]
        DEC -->|"retry"| RETRY
        DEC -->|"seal"| SEAL
    end
    BAR["<b>Barrier remains</b><br/>Only normal verified finalization releases it"]
    OBS --> DEC
    RETRY --> PH
    OBS -.-> BAR
    RETRY -.-> BAR
    SEAL -.-> BAR

    classDef core fill:#18344d,stroke:#18344d,color:#ffffff,stroke-width:2px;
    classDef retained fill:#eaf5f0,stroke:#468570,color:#173e32,stroke-width:1.5px;
    classDef fixture fill:#edf4fb,stroke:#6b8ba8,color:#18344d,stroke-width:1.5px;
    classDef qualified fill:#fff5e3,stroke:#af8137,color:#624719,stroke-width:1.5px;
    classDef planned fill:#f4f3f8,stroke:#8a829e,color:#48415a,stroke-width:1.5px,stroke-dasharray:5 4;
    classDef blocked fill:#fff0ef,stroke:#ad6461,color:#713735,stroke-width:1.5px;
    class PH,OBS,RETRY retained;
    class DEC qualified;
    class REF,SEAL blocked;
    class BAR core;
    style OBSERVATION fill:#f8fafc,stroke:#c5d1dd,color:#304b63,stroke-width:1px
    style GOVERNANCE fill:#f8fafc,stroke:#c5d1dd,color:#304b63,stroke-width:1px
```

From phase 1 until phase 4, one unresolved transition blocks later appends and generic raw
replay across all missions; facade recovery revalidates and resumes the same retained
bytes. A blocked finality attempt is now a durable, reasoned, content-addressed
observation, and recovery past a block requires a role-separated signed decision — retry or
terminal seal — that never finalizes, rewrites, or releases the barrier. See the canonical
[integrity-evidence architecture](docs/ARCHITECTURE.md#integrity-evidence-contract),
[ADR-0011](docs/decisions/0011-crash-safe-modeled-integrity-finality.md#four-immutable-local-phases),
and [ADR-0014 through ADR-0017](docs/decisions/README.md). In qualified mode, a separate
reconstructor derives time, revocation, anchor and catalog requests from canonical records,
checks their signed packages and log proofs, and compares the complete evidence closure.
Transient bundles are optional; if supplied, they must freshly authenticate and agree,
including on retry. The service does not choose the store's mode. See
[ADR-0019](docs/decisions/0019-qualified-evidence-lifecycle-consumption.md).

| Plane | Unit | Responsibility | Repository status |
|---|---|---|---|
| Control | **ETZIO** | protocol, lifecycle, event ledger, replay | fixture scan, modeled-verification lifecycle, and optional modeled-finality facade implemented |
| Governance | **AQUILA** | authority, scope, budgets, leases | fixture authority plus modeled-verification issuance, cancellation, and reassignment implemented |
| Recon | **SCIPIO** | target and attack-surface mapping | legacy behavior stub only; target role absent |
| Strategy | **FABIUS** | ranked falsifiable hypotheses | legacy fixed-hypothesis stub only; target role absent |
| Investigation | **VELITES** | leased probes and candidates | implemented narrow byte-bound Python AST slice |
| Proof | **MARCELLUS** | isolated exploit construction | legacy in-memory pass-through only; isolated construction absent |
| Verification | **CATO** | independent reproduction and verdict | legacy toy host-process call only; ETZIO modeled-receipt admission exists, but independent execution is absent |
| Adjudication | **CAMILLUS** | evidence completeness, dedup, severity | legacy in-memory sorting only; protocol finding authority absent |
| Disclosure | **FABRICIUS** | evidence-bound report draft | legacy in-memory renderer only; governed disclosure absent |
| Learning | **MINERVA** | evaluated offline strategy promotion | legacy count-only behavior; evaluation and promotion absent |

The original in-process behavior model remains available as `python -m etzio.cli`, but its
toy findings and verifier labels are not security evidence.

## Retained evidence

Release-specific numbers below retain their historical scope. The current collection
target and completed local/CI validation are recorded separately in the
[handoff](docs/SESSION_HANDOFF.md). None is a capability claim: the suite runs against
repository-owned deterministic fixtures.

| Retained | Value |
|---|---|
| Engine baseline `cd5c6ad` ([PR 59](https://github.com/manfromnowhere143/etzio/pull/59)) | `2629` passing tests per runtime locally and in exact-head Linux CI on CPython 3.11.15 and 3.14.2 |
| Historical published-material full-suite release | `1794` passing tests on CPython 3.11.15 and 3.14.2 in Linux CI; retains that release's scope |
| Rollback-journal policy | `DELETE` / `EXTRA` on both runtimes, exact `sqlite_source_id()` retained |
| SQLite identity | `application_id` `0x45545A31` (ASCII `ETZ1`), `user_version` `4` |
| Accepted decisions | `24` architecture decision records, each with a known-bad where it names a gate |
| Merkle core | reproduces the published RFC 6962/9162 reference tree for sizes `0`–`8`, and all `36` reference inclusion plus `36` reference consistency proofs |
| Merkle append frontier | compared with the full-tree implementation across `512` tree sizes |
| Qualified-evidence acceptance | `47` known-bads across the anchor, revocation, and head-floor phases; unsigned content is refused in signed mode |
| Governed fixture scans | vulnerable fixture closes with `7` candidates, clean fixture with `0`, neither mints a finding |

The Merkle verifiers are validated against the published RFC reference vectors rather than
against Etzio's own prover, because a broken verifier and a broken prover agree with each
other. A green check is evidence about this repository snapshot; it is never a security,
provider, or finding claim.

## Reproduce

The canonical interpreter is CPython 3.11.15; CI also reproduces the suite on CPython
3.14.2. Validation dependencies are exact and hash-locked.

```bash
git clone https://github.com/manfromnowhere143/etzio.git
cd etzio
python3.11 -m venv .venv
.venv/bin/python -m pip install \
  --no-input \
  --require-hashes \
  --only-binary=:all: \
  --requirement tools/ci/requirements-ci.lock
.venv/bin/python -m pip check
.venv/bin/python -m pip install --no-input --no-deps --no-build-isolation .
ETZIO_PYTHON=.venv/bin/python make verify
```

Record `git rev-parse HEAD` with the validation output. The package-install step creates
the `etzio` console command using the already locked build/runtime dependencies. A passing
suite validates this checkout under the recorded runtime; it does not establish a finding.

Run the governed fixtures:

```bash
.venv/bin/etzio --fixture vulnerable
.venv/bin/etzio --fixture clean
```

For local integrations, `etzio --fixture vulnerable --format json` emits the
[versioned fixture report](docs/FIXTURE_SCAN_REPORT_V1.md). Exit `0` means completed
static analysis, including scans with candidates; incomplete or refused analysis
exits `3`, and operational errors exit `2`. Empty candidate output is not a finding
or proof of safety. The [interface and paid pilot assessment](docs/ENGINE_INTERFACES_AND_VALUE.md)
sets out the consumer requirements for a future SDK, API and MCP adapter.

To retain replay state, provide a new path or an existing owner-controlled directory whose
mode is already `0700`:

```bash
mkdir -m 700 .etzio-state
.venv/bin/etzio --fixture vulnerable --state-dir .etzio-state
```

Existing persistent-WAL databases and nonempty pre-vault event databases are refused.
Neither conversion tool exists yet. Use a fresh state path and preserve the refused
database plus journal bytes unchanged until an explicit stop-the-world migration is
implemented and qualified.

Exact supported version-1, version-2 and version-3 schema layouts migrate transactionally
to version `4`, adding the required relations without relabeling retained events as
finalized. A version-1 transactional-vault database retains the legacy profile. Existing
enrollment is preserved; only an entirely empty legacy profile can newly enroll in
fixture-integrity finality.

## Open gates and next mission

The production mission qualifies the external integrity boundary. The fixture foundation includes the typed
integrity-evidence contract, crash-safe modeled finality across four immutable phases, three
networkless qualification harnesses, durable governed blocked-finality — specified,
persisted, wired into the lifecycle, and crash-recovered — and a schema-version-4 store that
pins the qualified adapter roots. The qualified fixture service now completes the same
four-phase lifecycle with signed provider packages, exact profile alignment and
reconstruction from retained bytes. Release
validation of this tranche is recorded in the handoff; these are still repository fixtures.

Its immediate dependency is an accountable catalog operator, independent application
monitors and the complete native administration/custody dossier. Existing inquiries and
follow-ups are already sent. Additional fixture parsers, cloud credits or model-access
approval cannot supply those commitments. See the
[operating decision](docs/CATALOG_RECOVERY_DECISION.md).

What remains before a production kernel finding pipeline can exist:

1. qualify independently administered trusted-time, revocation, anchor, catalog, and monitor
   providers, and prove external latest-head authority survives local database loss;
2. close the documented same-user SQLite pathname and coherent offline-rewrite boundary, and
   accept a concrete VFS, device, quota, backup, process-kill, and power-fault storage
   profile with sensitive-evidence access control, encryption, and retention;
3. replace opaque modeled outputs with structured, independently produced execution evidence;
   and
4. prove MARCELLUS/CATO separation on an explicitly accepted Linux/KVM profile.

Only then does the benchmark-first EVM pack run, and only after the integrity, isolation,
benchmark, and exact-`TargetContract` gates close may production kernel bounty execution
begin. The separately supervised workflow proceeds alongside this work under ADR-0025
and ADR-0026, with exact scope, accepted containment and labeled self-reproduction.
Accepted outcomes and income are measurements, never authority. Autonomy over a live target
expands after one full chain of custody survives independent reproduction, isolation, and
adjudication — not before.

After qualification, the first decisive discovery evidence is the selected
**static-analysis / fuzzing / model-only / hybrid comparison**, under matched information
and complete cost accounting. Freeze the baseline before testing semantic guidance,
scheduling and evidence reuse separately. Exact targets, profiles, numerical budgets and
the other registration inputs still need to be bound. This order is an accepted direction,
not a completed preregistration or a comparative result. See the
[experiment contract](docs/FRONTIER_BASELINE.md#controlled-comparison-and-separate-ablations).

## Project record

- [Engineering review guide](docs/REVIEW_GUIDE.md)
- [Session handoff](docs/SESSION_HANDOFF.md)
- [Machine-readable mission state](docs/MISSION_STATE.json)
- [Charter](CHARTER.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Roadmap](docs/ROADMAP.md)
- [2026 frontier baseline](docs/FRONTIER_BASELINE.md)
- [Provider and host qualification next steps](docs/QUALIFICATION_NEXT_STEPS.md)
- [Protocol-v1 semantic wire schema](etzio/schemas/protocol.v1.schema.json)
- [Architecture decisions (26 records)](docs/decisions/README.md)
- [Presentation standard](docs/PRESENTATION.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Citation](CITATION.cff)

Etzio is a public, solely authored research repository by
[Daniel Wahnich](AUTHORS.md). Public visibility and bounded cloud qualification preparation
are authorized. Production deployment, live-target work, disclosure and submission remain
separate, unheld grants; cloud preparation admits none of them. It is independent from
Odeya, Sentinel, Aweb, Maestro, Telos, Inbar, and every other
project in the estate — it may study reusable engineering patterns, never their runtime code,
stores, identities, or authority.
