# Etzio

**An evidence-native engine for authorized vulnerability research: a candidate becomes a
finding only when a separately authorized verifier reproduces a material effect from
retained bytes and the kernel accepts the receipt — proof by reproduction, not by
confidence.**

> **Honest status — 2026-10-16. Phase: foundation integrity. This is the courtroom, not
> yet the detective.**
>
> Etzio has built a tested evidence and adjudication kernel. It has *not* built
> the part that finds vulnerabilities. The entire detection surface today is **six Python
> rule classes over two repository fixtures** — `7` planted candidates on the vulnerable
> fixture, `0` on the clean one, and **never a finding**. The kernel authenticates and
> retains modeled statements; independent proof of a real security effect remains blocked.
>
> The engine execution surface remains repository-owned deterministic fixtures. Separately,
> public-source research and operator-authorized, bounded Google Cloud host preflight prepare
> the next gates; no native provider, exploit execution, benchmark corpus, live target or
> disclosure is admitted. No trustworthy UTC, current real-world revocation, external durability,
> non-equivocation, independent verification, finding, live-target authority, or superiority
> claim follows from anything in this repository.
>
> What *is* implemented, end to end on those fixtures: a canonical protocol-v1 envelope with
> semantic wire schemas; Ed25519-signed authority admission; content-addressed immutable
> targets; a bounded, byte-bound Python analyzer under a lease; lifecycle-checked append-only
> SQLite with deterministic replay; a transactional evidence vault; kernel-issued modeled
> verification leases, typed input resolution, and single-use signed-receipt admission;
> crash-safe modeled integrity finality across four immutable phases behind one
> database-global barrier; three networkless qualification harnesses (trusted-time and
> revocation; RFC 9162 anchor, catalog, and monitor head-authority; and a qualified-evidence
> acceptance layer); durable governed blocked-finality — specified, persisted, wired into the
> lifecycle, and crash-recovered; and a schema-version-4 store that pins the qualified
> adapter roots. The opt-in qualified fixture service now carries signed provider packages
> through the complete lifecycle and reconstructs them from retained bytes on cold replay.
> Merkle verification uses the published **RFC 6962/9162 reference vectors**; append-frontier
> recovery is also compared with the full-tree implementation across `512` tree sizes.
> The preceding engine release, [PR 57](https://github.com/manfromnowhere143/etzio/pull/57)
> at `285fdb6`, passed `2617` tests on both declared Python runtimes locally and in exact-head
> Linux CI. This includes the protocol validation optimization; it measures fixture
> behavior, not vulnerability-discovery quality. The October 16 evidence-input repair adds
> `12` controls, for a collection target of `2629`. Resolve its full validation and
> publication from the current [handoff](docs/SESSION_HANDOFF.md).

> The [decision index](docs/decisions/README.md) contains `24` architecture decisions
> defining the contracts and their refusal cases.
>
> Winning bounties is a future measured outcome, never present authority. See
> [Open gates and next mission](#open-gates-and-next-mission).

The [October 15 frontier review](docs/FRONTIER_BASELINE.md#competitive-review-and-experiment-order-2026-10-15)
connects current research to a controlled comparison and separate feature experiments.
The [October 12 mission assessment](docs/MISSION_REVIEW_2026-10-12.md) retains the
provider-feasibility decision. Competitive discovery, independent external reproduction
and income remain undemonstrated.

## Evidence-input repair and research, 2026-10-16

Generic evidence inputs now require exact built-in bytes before caller behavior, hashing
or filesystem work. A reproduced subclass defect could publish 64 bytes under an 8-byte
limit before refusing the write; another could redirect the digest input. The repair
refuses both before work and preserves ordinary-byte identities. All `63` focused evidence
tests pass on both runtimes; the [repair record](docs/evidence/evidence-byte-admission-2026-10-16.json)
identifies the separate full-release validation. This is a local engine correction.

Three [new primary-paper reviews](docs/FRONTIER_BASELINE.md#evidence-reuse-and-oracle-quality-2026-10-16)
add proposed controls for source-linked reasoning, target-identity sensitivity and
intended-behavior oracles. The additional CoW fee/fill source analysis remains conditional,
with degenerate-order semantics unresolved and no confirmed finding. Six provider threads
were checked again October 16: no new human reply or operating commitment. The dependency
diagram below and selected comparison order remain current; the October 15 table records
the preceding progress snapshot.

## Progress through 2026-10-15

| Workstream | Retained progress | Remaining boundary |
|---|---|---|
| Governed fixture kernel | Signed admission, immutable inputs, candidate and lease lineages, transactional evidence vault, deterministic replay and schema-v4 qualified fixture enrollment | Six Python rule classes and two owned scan fixtures; no independently verified security effect |
| Integrity and recovery | Four immutable finality phases, authenticated signed-fixture packages, governed retry/seal decisions and interruption controls | Actual independent provider administration and external latest-head recovery are unqualified |
| Native evidence preparation | Offline timestamp/CRL validation, conditional elapsed-time bounds, trusted-list and checkpoint inspection, source-provenance reconciliation | Documentary and offline observations do not admit a live provider; both FreeTSA acquisition attempts are spent |
| Host preparation | Bounded Google Cloud KVM preflight completed and disposable resources cleaned up | No accepted worker isolation, protected storage or power-fault profile |
| Repository reliability | Cleanup and coherent-read repairs, honest unresolved-result accounting, owned-document checks and equivalent ASCII validation | `2617` passing engine-release tests establish repository behavior only |
| Research and comparison | Two October 15 primary-source review packets; four-arm comparison and separate semantic-guidance, scheduling and evidence-reuse designs retained | Experiment order selected; `18` registration inputs remain unbound; no comparator has run |
| Bounty preparation | CoW source/deployment-record reconciliation and a finite source review with contrary evidence against four suspected weaknesses | Exact deployed state, scope, independent reproduction and program eligibility remain unresolved; no confirmed finding or payment |
| Operating dependencies | Three approved pilot follow-ups sent; six existing threads checked on October 15 | No human reply or catalog/monitor operating commitment in that readback |

The [progress evidence record](docs/evidence/documentation-handoff-2026-10-15.json)
links these claims to their retained records. Private source captures, correspondence and
recovery copies are excluded from the published repository; their paths are continuity
locators, not downloadable evidence in a fresh clone. Model-access onboarding is separate
from provider admission, target permission and execution qualification.

This progress map shows the accepted dependency order, not an operating pipeline. Solid
edges connect the implemented fixture foundation; dashed edges require new acceptance
evidence. Preparation is complete only for its named, bounded scope.

```mermaid
flowchart TB
    K["IMPLEMENTED ON FIXTURES<br/>authority · candidates · evidence vault"]
    F["IMPLEMENTED ON FIXTURES<br/>signed qualification · finality · recovery"]
    P["PREPARATION RETAINED<br/>native-format inspection · KVM preflight<br/>research · source review · operator inquiries"]
    N["BLOCKED: native integrity roster<br/>independent operating commitments missing"]
    R["BLOCKED: external latest-head recovery<br/>effective writer fencing"]
    S["BLOCKED: protected storage<br/>device · quotas · backup · fault recovery"]
    X["BLOCKED: independent execution<br/>MARCELLUS / CATO · admitted isolation"]
    B["PROPOSED: admitted EVM benchmark<br/>exact targets · frozen comparison protocol"]
    E["NOT RUN: static / fuzzing / model / hybrid"]
    A["PROPOSED: separate feature experiments<br/>semantic guidance · scheduling · evidence reuse"]
    U["FUTURE: authorized bounty lane<br/>independent findings · accepted outcomes"]
    K --> F
    F -.-> N
    P -. "preparation is not admission" .-> N
    N -.-> R -.-> S -.-> X -.-> B -.-> E -.-> U
    E -.-> A
    classDef done fill:#d8f3dc,stroke:#2d6a4f,color:#081c15;
    classDef prep fill:#e7f5ff,stroke:#1971c2,color:#061b2c;
    classDef blocked fill:#ffe3e3,stroke:#c92a2a,color:#3b0a0a;
    class K,F done;
    class P,B,E,A,U prep;
    class N,R,S,X blocked;
```

## The system in one view

Authority → immutable target → falsifiable hypothesis → content-bound candidate → isolated
exploit artifact → independent reproduction → kernel adjudication → evidence-bound
disclosure → governed offline learning. **Nothing jumps the chain.**

```text
authority → immutable target → hypotheses → candidates
                                             ├─ current retained boundary
                                             └╌→ exploit proof → independent reproduction
                                                 → adjudication → disclosure draft → learning
```

This is the intended operating chain, not a runtime screenshot. Everything left of the
boundary is implemented on repository fixtures; everything right of it is a design target
gated behind isolation, benchmark, and exact-authority acceptance. The mission spans
vulnerability classes, languages, and target categories; blockchain, Solidity, and EVM
research are the first benchmark and economic wedge — not the architectural ceiling. Domain
knowledge belongs in versioned packs; policy and scientific authority stay in the kernel.

## Why Etzio

A vulnerability is a falsifiable claim, not an alert. A candidate identifies a specific
observation against specific bytes. A finding requires a separately authorized verifier to
reproduce a security-relevant effect from retained artifacts in an independently controlled
environment, followed by kernel adjudication.

That yields six operating laws:

1. authority is admitted before a mission opens;
2. workers propose; the kernel alone changes canonical state;
3. a generator cannot verify its own candidate;
4. evidence and identities are content-bound and replayable;
5. refusals, nulls, failures, timeouts, and inconclusive results remain visible; and
6. credentials, egress, spending, live actions, disclosure, and publication are separate
   grants.

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
  content-addressed observation persisted under SQLite schema version 3. Recovery past a
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
- **Blocked target system:** exploit construction, hard isolation, independent
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

This compact diagram shows retained repository-fixture paths only. Green nodes and solid
arrows are implemented; an `optional` edge is implemented but is not used by the supported
CLI. Blue is the empty-store fixture-finality surface. Amber is signed-fixture adapter
qualification, consumed only under explicit qualified enrollment. Its signed packages are
reconstructed at store admission and replay. Legacy behavior-only
stubs and blocked target roles are intentionally excluded here and named precisely in the
status table below. The complete target-state authority topology is in
[Architecture](docs/ARCHITECTURE.md#target-system); labels, rather than color alone, carry
status.

```mermaid
flowchart TB
    subgraph AUTH["Authority and control"]
        direction LR
        AQ["AQUILA<br/>implemented fixture authority · budgets · leases"]
        S[("Filesystem staging/cache<br/>bounded pre-ingestion bytes")]
        K["ETZIO kernel<br/>implemented fixture protocol · lifecycle · replay"]
    end

    subgraph SCAN["Supported candidate path"]
        direction LR
        V["VELITES<br/>implemented narrow AST observations"]
        KC["ETZIO candidate admission<br/>construct · validate · retain"]
        C["Stable candidates<br/>implemented · not findings"]
    end

    subgraph OPTIONAL["Optional implemented paths and storage"]
        direction LR
        VR["ETZIO verification-intent path<br/>modeled lease · resolution · recovery<br/>signed opaque receipt admission · no execution"]
        DBL[("SQLite schema v4 · legacy profile<br/>supported CLI + ordinary kernel store")]
        IF["Fixture-integrity finality facade<br/>mode selected at enrollment"]
        DBM[("SQLite schema v4 · fixture-integrity profile<br/>permanent after enrollment")]
    end

    subgraph QUAL["Signed-fixture qualification"]
        direction LR
        AP["Exact adapter profile<br/>trust root · validation/provider policies<br/>fixed all-source roster"]
        SP["Role-separated signed fixture packages<br/>Ed25519 · exact nonce-bound requests<br/>authenticate before claim parsing"]
        TH["All-source time qualification<br/>common overlap · conservative outer hull"]
        RF["Full-hull revocation qualification<br/>validity · staleness · metadata/floors"]
        HH["Head-authority qualification<br/>RFC 9162 inclusion + consistency<br/>unanimous catalog monitors"]
        SM["Sealed provider-neutral mapping<br/>fresh reauthentication · exact BLOB coverage<br/>qualified lifecycle input"]
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

    classDef implemented fill:#d8f3dc,stroke:#2d6a4f,color:#081c15;
    classDef fixture fill:#e7f5ff,stroke:#1971c2,color:#061b2c;
    classDef qualification fill:#fff3bf,stroke:#e67700,color:#3d2100;
    class AQ,K,S,DBL,V,KC,C,VR implemented;
    class IF,DBM fixture;
    class AP,SP,TH,RF,HH,SM qualification;
    style AUTH fill:#f8f9fa,stroke:#adb5bd,color:#212529
    style SCAN fill:#f8f9fa,stroke:#adb5bd,color:#212529
    style OPTIONAL fill:#f8f9fa,stroke:#adb5bd,color:#212529
    style QUAL fill:#fff9db,stroke:#f59f00,color:#3d2100
```

The optional integrity facade retains four immutable local phases. Its enrolled mode selects
unsigned modeled assertions or qualified signed-fixture packages. Both remain local fixture
sources. A future independently administered adapter set must satisfy the same state machine
and prove external authority at each trust, write and read boundary:

```mermaid
flowchart TB
    E["Proposed event<br/>exact prior global + mission heads"]
    D["Signed integrity decision<br/>enrolled profile · authenticated dossier"]
    P1["1 · Pending event<br/>atomic event + dossier + required evidence"]
    RH["Process-local catalog rehydration<br/>not durable · not a protocol write"]
    P2["2 · Retained anchor statement<br/>then byte-identical registration retry"]
    P3["3 · Retained signed checkpoint candidate<br/>then byte-identical publication retry"]
    P4["4 · Retained finalization<br/>exact current global + mission floor"]
    OK["Fixture facade returns success<br/>no execution or finding claim"]
    B["One database-global barrier<br/>blocks later appends and generic replay<br/>from phase 1 until verified phase 4"]
    E --> D --> P1 --> RH --> P2 --> P3 --> P4 --> OK
    P1 -. "establishes" .-> B
    P4 -. "only verified completion releases" .-> B
    classDef retained fill:#d8f3dc,stroke:#2d6a4f,color:#081c15;
    classDef boundary fill:#e7f5ff,stroke:#1971c2,color:#061b2c;
    class E,D,P1,P2,P3,P4,OK retained;
    class RH,B boundary;
```

The following companion diagram shows the implemented opt-in recovery contract within
the fixture lifecycle. Its relations were introduced in schema v3 and remain in the
current schema-v4 store. Neither a recovery decision nor elapsed time releases finality.

```mermaid
flowchart TB
    PH["Exact highest retained phase<br/>pending · anchor · checkpoint candidate"]
    REF["Deterministic finality refusal"]
    OBS["Durable blocked observation<br/>phase · operation · reason · attempt ordinal"]
    DEC["Signed governed decision<br/>different key AND principal<br/>bound to the latest observation"]
    RETRY["Authorized retry<br/>resume the exact retained phase"]
    SEAL["Terminal instance seal<br/>load / recover / append refuse<br/>retained bytes remain readable"]
    BAR["Unresolved-transition barrier remains<br/>only normal verified finalization releases it"]
    PH --> REF --> OBS --> DEC
    DEC -->|"retry disposition"| RETRY
    RETRY --> PH
    DEC -->|"seal disposition"| SEAL
    OBS -.-> BAR
    RETRY -.-> BAR
    SEAL -.-> BAR
    classDef retained fill:#d8f3dc,stroke:#2d6a4f,color:#081c15;
    classDef blocked fill:#ffe3e3,stroke:#c92a2a,color:#3b0a0a;
    class PH,OBS,DEC,RETRY retained;
    class REF,SEAL,BAR blocked;
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
| Latest engine release, `285fdb6` ([PR 57](https://github.com/manfromnowhere143/etzio/pull/57)) | `2617` passing tests per runtime locally and in exact-head Linux CI on CPython 3.11.15 and 3.14.2 |
| Historical published-material full-suite release | `1794` passing tests on CPython 3.11.15 and 3.14.2 in Linux CI; retains that release's scope |
| Rollback-journal policy | `DELETE` / `EXTRA` on both runtimes, exact `sqlite_source_id()` retained |
| SQLite identity | `application_id` `0x45545A31` (ASCII `ETZ1`), `user_version` `4` |
| Accepted decisions | `24` architecture decision records, each with a known-bad where it names a gate |
| Merkle core | reproduces the published RFC 6962/9162 reference tree for sizes `0`–`8`, and all `36` reference inclusion plus `36` reference consistency proofs |
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
git clone git@github.com:manfromnowhere143/etzio.git
cd etzio
python3.11 -m venv .venv
.venv/bin/python -m pip install \
  --no-input \
  --require-hashes \
  --only-binary=:all: \
  --requirement tools/ci/requirements-ci.lock
.venv/bin/python -m pip check
ETZIO_PYTHON=.venv/bin/python make verify
```

Run the governed fixtures:

```bash
.venv/bin/etzio --fixture vulnerable
.venv/bin/etzio --fixture clean
```

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

An exact `user_version = 1` transactional-vault database is the narrow exception: opening
it atomically installs the version-2 integrity tables under the permanent legacy profile
without relabeling any retained event as finalized. Only an entirely empty legacy profile
can enroll in modeled integrity finality.

## Open gates and next mission

The next mission is not more detector breadth. The evidence foundation is deep: the typed
integrity-evidence contract, crash-safe modeled finality across four immutable phases, three
networkless qualification harnesses, durable governed blocked-finality — specified,
persisted, wired into the lifecycle, and crash-recovered — and a schema-version-4 store that
pins the qualified adapter roots. The qualified fixture service now completes the same
four-phase lifecycle with signed provider packages, exact profile alignment and
reconstruction from retained bytes. Release
validation of this tranche is recorded in the handoff; these are still repository fixtures.

The immediate dependency is an accountable catalog operator, independent application
monitors and the complete native administration/custody dossier. Existing inquiries and
follow-ups are already sent. Additional fixture parsers, cloud credits or model-access
approval cannot supply those commitments. See the
[operating decision](docs/CATALOG_RECOVERY_DECISION.md).

What remains before a finding pipeline can exist:

1. qualify independently administered trusted-time, revocation, anchor, catalog, and monitor
   providers, and prove external latest-head authority survives local database loss;
2. close the documented same-user SQLite pathname and coherent offline-rewrite boundary, and
   accept a concrete VFS, device, quota, backup, process-kill, and power-fault storage
   profile with sensitive-evidence access control, encryption, and retention;
3. replace opaque modeled outputs with structured, independently produced execution evidence;
   and
4. prove MARCELLUS/CATO separation on an explicitly accepted Linux/KVM profile.

Only then does the benchmark-first EVM pack run, and only after the integrity, isolation,
benchmark, and exact-`TargetContract` gates close may a strictly authorized bounty-research
lane run in parallel with continued engine development. Accepted outcomes and income are
measurements, never authority. Autonomy over a live target expands after one full chain of
custody survives independent reproduction, isolation, and adjudication — not before.

After qualification, the first decisive discovery evidence is the selected
**static-analysis / fuzzing / model-only / hybrid comparison**, under matched information
and complete cost accounting. Freeze the baseline before testing semantic guidance,
scheduling and evidence reuse separately. Exact targets, profiles, numerical budgets and
the other registration inputs still need to be bound. This order is an accepted direction,
not a completed preregistration or a comparative result. See the
[experiment contract](docs/FRONTIER_BASELINE.md#controlled-comparison-and-separate-ablations).

## Project record

- [Session handoff](docs/SESSION_HANDOFF.md)
- [Machine-readable mission state](docs/MISSION_STATE.json)
- [Charter](CHARTER.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Roadmap](docs/ROADMAP.md)
- [2026 frontier baseline](docs/FRONTIER_BASELINE.md)
- [Provider and host qualification next steps](docs/QUALIFICATION_NEXT_STEPS.md)
- [Protocol-v1 semantic wire schema](etzio/schemas/protocol.v1.schema.json)
- [Architecture decisions (ADR-0001 through ADR-0022)](docs/decisions/README.md)
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
