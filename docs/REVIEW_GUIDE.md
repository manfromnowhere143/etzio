# Engineering review guide

Status: review entrypoint, 2026-10-16. The implemented code baseline is
[`cd5c6ad`](https://github.com/manfromnowhere143/etzio/commit/cd5c6ada82b349f3272b0fe010c2878bada6d74c)
([PR 59](https://github.com/manfromnowhere143/etzio/pull/59)). This guide maps claims to
implementation and refusal evidence. It is a scoped review aid, not an exhaustive security
audit, independent assessment or comparative performance result.

## Read in this order

1. [Charter](../CHARTER.md): mission, authority and claim boundaries.
2. [README](../README.md): current capability, operating chain and retained progress.
3. [Architecture](ARCHITECTURE.md): wire, state, custody, recovery and trust contracts.
4. The code/test map below, then the relevant [decision record](decisions/README.md).
5. [Frontier baseline](FRONTIER_BASELINE.md#controlled-comparison-and-separate-ablations):
   the proposed comparison and its unbound registration inputs.
6. [Handoff](SESSION_HANDOFF.md) and [mission state](MISSION_STATE.json): exact continuation
   and release evidence, including private locators unavailable in a fresh clone.

## What exists at this revision

The supported fixture CLI admits exact authority and target bytes, runs a bounded Python
AST analyzer, retains stable candidates and closes the mission. Separate APIs retain
verification leases, resolved bytes and caller-supplied signed modeled receipts. An
explicitly enrolled facade exercises four-phase integrity finality, qualified signed
fixture packages and governed blocked recovery. Schema version `4` contains these distinct
profiles; the CLI uses the legacy profile.

These paths execute in a trusted Python process on the host. Module names, worker roles
and distinct signing keys do not provide OS isolation or independent administration.
The generator/verifier execution boundary, native provider roster, protected storage and
finding adjudication are acceptance targets. Inspect [the target topology](ARCHITECTURE.md#target-system)
separately from [the implemented composition](ARCHITECTURE.md#qualified-fixture-composition).

## Claim-to-code and refusal map

These are entrypoints into the review, not exhaustive lists of all supporting tests.

| Claim or boundary | Implementation to inspect | Refusal or preservation evidence |
|---|---|---|
| Canonical wire and semantic dispatch | [protocol](../etzio/protocol/v1.py), [semantic registry](../etzio/protocol/semantic_v1.py) | [wire controls](../tests/test_protocol_v1.py), [schema parity](../tests/test_protocol_schema_v1.py) |
| Authority before mission opening; exact fixture scope | [authority](../etzio/authority.py), [fixture scan](../etzio/kernel/fixture_scan.py), [CLI](../etzio/scan.py) | [grant controls](../tests/test_authority_v1.py), [fixture lifecycle](../tests/test_fixture_scan_v1.py), [CLI controls](../tests/test_scan_cli.py) |
| Immutable byte identity and bounded staging | [evidence store](../etzio/evidence.py) | [filesystem/identity controls](../tests/test_evidence_v1.py), [subclass refusal before work](../tests/test_evidence_input_boundary.py) |
| Atomic event, role and BLOB retention; replay after staging loss | [vault manifests](../etzio/kernel/evidence_vault.py), [SQLite store](../etzio/kernel/store.py), [reducer](../etzio/kernel/reducer.py) | [protected appends, rollback and corruption](../tests/test_transactional_evidence_vault_v1.py), [coherent reads](../tests/test_store_read_snapshot.py) |
| Exact lease/input/receipt binding and single consumption | [lease issuance](../etzio/kernel/verification_lease.py), [resolution](../etzio/kernel/artifact_resolution.py), [receipt admission](../etzio/kernel/receipt_admission.py) | [lease controls](../tests/test_kernel_verification_lease_v1.py), [resolution controls](../tests/test_kernel_verification_artifacts_v1.py), [receipt races and substitution](../tests/test_kernel_receipt_admission_v1.py) |
| Four-phase finality, exact retry and global barrier | [transition coordinator](../etzio/kernel/integrity_transition.py), [store](../etzio/kernel/store.py) | [recovery matrix](../tests/test_integrity_recovery_matrix_v1.py), [adversarial transitions](../tests/test_integrity_transition_adversarial_v1.py) |
| Qualified fixture reconstruction from canonical bytes | [reconstruction](../etzio/kernel/qualified_lifecycle_v1.py), [fixture service](../etzio/kernel/qualified_fixture_service_v1.py) | [cold replay](../tests/test_qualified_cold_replay_v1.py), [finalization wiring](../tests/test_qualified_finalization_record_wiring_v1.py) |
| Role-separated retry/seal decisions; no barrier release by disposition | [blocked-finality contract](../etzio/kernel/blocked_finality_v1.py), [transition coordinator](../etzio/kernel/integrity_transition.py) | [governed composition](../tests/test_blocked_finality_composition_v1.py), [interrupted observation/decision retention](../tests/test_blocked_finality_crash_recovery_v1.py) |
| Missing outcomes and zero denominators remain explicit | [modeled FPR harness](../etzio/harness/fpr.py) | [empty, unresolved and invalid verdict controls](../tests/test_fpr_accounting.py) |

The four protected byte-claiming events are `authority_admitted`, `mission_opened`,
`verification_artifacts_resolved` and `verifier_receipt_admitted`. Trace each through its
dedicated store method, locked history validation, derived role manifest, transaction and
replay. Generic append must refuse them. A valid descriptor alone is insufficient when
the corresponding canonical BLOB or mapping is absent or corrupt.

## Questions the design must survive

| Review question | Present evidence or remaining obligation |
|---|---|
| Can committed replay depend on mutable staging or silently repair canonical corruption? | Owned tests cover staging deletion and fail-closed canonical corruption. Staging is a pre-ingestion cache. |
| Can a retry alter retained bytes, consume a lease twice or release an unresolved transition? | Canonical identities, append serialization and recovery controls govern these paths. Review concurrent receipt, phase and governed-disposition tests together. |
| Do authentication and distinct keys establish truthful time or independent verification? | No. Fixture signatures authenticate fixture statements. Native administration, freshness and separate execution still require evidence. |
| Can a same-user process replace the database or coherently rewrite its history? | The pathname and coherent-rewrite boundary remains open. An external latest-head authority and protected storage profile are required. |
| Is the storage profile qualified against power loss, physical/journal exhaustion and recovery from independent backups? | No accepted production profile exists. Local transaction and injected-interruption results have narrower scope. |
| Is the implemented detector competitive? | Unknown. Six rules and two fixtures cannot establish comparative discovery quality. S/F/M/H remains unrun. |
| Does the code structure make critical invariants easy to preserve? | Storage and finality modules concentrate schema, custody, capacity, replay and recovery responsibilities. Review cross-boundary changes together; any decomposition must preserve atomicity and refusal behavior. This review makes no runtime refactor. |

## Reproduce and inspect the evidence

Use the [README commands](../README.md#reproduce) in a fresh environment and record the
checked-out commit. The supported validation matrix is CPython `3.11.15` and `3.14.2`.
The exact lock includes the build and optional qualification dependencies; install the
local package before invoking its console command.

The cited engine release passed `2629` tests per runtime locally and in
[exact-commit Linux CI](https://github.com/manfromnowhere143/etzio/actions/runs/38873128704).
Package contents and installed-wheel behavior were checked separately. Repository policy
also checks sole-author history, immutable Action revisions, read-only workflow permissions
and owned-document paths. These checks do not certify all code, detect all broken external
links or validate every prose claim.

The [review record](evidence/reviewer-readiness-2026-10-16.json) separates the validated
engine baseline from this documentation release, records review coverage and points to
the fresh-install and diagram evidence. Private correspondence, raw captures and recovery
archives are not shipped in the repository. Same-host restore checks establish recoverable
copies of the retained material, not independently administered durability.

## What would establish frontier performance

The accepted order is native integrity qualification, external latest-head recovery and
fencing, protected storage, independent execution, benchmark/exact-target admission, then
the controlled static-analysis, fuzzing, model-only and hybrid comparison. Semantic
guidance, scheduling and evidence reuse follow as separate experiments. All `18`
registration inputs remain unbound.

Compare verified outcomes, false positives, coverage, cost and reviewer burden under fixed
information and resource conditions. Preserve null and inconclusive results, family-level
holdouts, contamination uncertainty and intended-behavior controls. The
[dated primary-source review](FRONTIER_BASELINE.md#evidence-reuse-and-oracle-quality-2026-10-16)
informs these hypotheses. It does not establish superiority over another system or imply
endorsement by an external engineering team.
