# Security and authorized-use policy

Etzio is a private architecture foundation for authorized vulnerability research. It is not
currently approved for live targets or untrusted exploit execution.

## Current security boundary

The only supported research bytes are the repository-owned clean or vulnerable Python
fixture. The `etzio --fixture ...` command admits a signed, expiring fixture grant; resolves
an exact manifest-backed content-addressed snapshot; emits stable candidate observations;
and persists a lifecycle-checked hash chain plus protected exact evidence in a private
SQLite vault. The supported command has no arbitrary target-path argument. An explicit
fixture-only kernel path can retain a completed candidate scan for modeled verification
assignment; it does not execute the assignment.

Those controls prove only the bounded fixture slice:

- the local operator trust snapshot and decision clock are supplied by the invoking
  process; the admission record cannot prove their freshness or the legal validity of
  third-party permission;
- the filesystem content store checks byte identity and private file modes but is bounded
  staging/cache, not canonical retention or a production access-control service. Its
  no-clobber write path requires Darwin
  `renameatx_np(RENAME_EXCL)` or Linux libc `renameat2(RENAME_NOREPLACE)` on a supporting
  filesystem and fails closed when that primitive is unavailable;
- the strict, application-identified, versioned SQLite store is the canonical append-only
  evidence vault. For `authority_admitted`, `mission_opened`,
  `verification_artifacts_resolved`, and `verifier_receipt_admitted`, one transaction
  commits exact immutable BLOBs, complete code-derived event-role mappings, and the event,
  or none. The vault is not externally anchored and retains a documented same-user
  pathname and coherent offline-rewrite boundary;
- authority evidence has a fixed 16 MiB ceiling; existing target, resolution, output, and
  signed grant bounds remain logical even when BLOBs deduplicate; and each store opening
  enforces a configured unique logical-BLOB ceiling that defaults to 1 GiB but is not
  persisted authority. SQLite pages, rollback journals, backups, and device capacity
  require separate operational quotas. Production use also requires an accepted
  SQLite/VFS/filesystem/device profile, backup/restore and process-kill/power-fault
  qualification, plus access-control, encryption, and retention policy for sensitive
  evidence;
- static observations are candidates only; this path creates no PoC or finding;
- a verification-intent fixture mission can retain an AQUILA-issued lease under the exact
  admitted `modeled_fixture_verification` grant, together with the verifier trust and
  revocation snapshot used for assignment; the lease content-binds that issuance snapshot
  identity;
- canonical modeled lifecycle decisions now retain lease expiry, pre-deadline AQUILA
  cancellation, nonbranching supersession through atomic reassignment to a different
  verifier, and complete or incomplete receipt-coverage closure. Caller-supplied event
  time remains untrusted-clock input, and the modeled cancellation label does not
  authenticate an external control principal;
- ETZIO can resolve every target file and predeclared PoC, supporting-evidence,
  environment, and oracle-specification input under an exact code-owned content type,
  retain one canonical resolution plus its exact BLOBs and roles for the lease, and remain
  in nonterminal `awaiting_verification`; this establishes byte identity, assigned role,
  and canonical retention, not provenance, truth, execution, or effect;
- a signed modeled-fixture receipt now binds that exact resolution plus distinct execution,
  effect, measured-environment, and termination output digest/size pairs. Before first
  admission, the supported kernel command revalidates the target, every resolved input,
  and each nonempty output vault-first, using exact filesystem staging only for genuinely
  new identities, under its code-owned type and the grant's one signed byte ceiling;
- one `verifier_receipt_admitted` event retains the exact signed receipt, decision-time
  trust and revocation snapshot, derived output bindings, and exact output BLOBs. The same
  append atomically records single-use lease consumption. Exact recovery of that committed
  historical decision is independent of filesystem staging;
- receipt admission authenticates and preserves a modeled verifier statement, including
  negative, inconclusive, and invalid outcomes. Opaque typed output bytes do not prove
  their semantics, provenance, common-run coherence, execution, effect, measured
  environment, termination, verifier independence, or finding validity;
- store-backed replay verifies signed descriptors, exact code-derived mappings, sizes,
  types, and rehashed canonical BLOBs. Generic event append rejects all four
  byte-claiming event kinds; dedicated paths derive and retain their exact manifests from
  locked history while holding the SQLite writer transaction. Untrusted code must not
  receive that privileged store surface. The ordinary filesystem-staging/SQLite retention
  split is closed for those protected events, but a coherent offline rewrite remains
  undetectable until ETZIO has an authenticated external event-head anchor. Trust-view
  freshness and decision time are likewise not externally proved. SQLite `BUSY` or
  `LOCKED` outcomes are retryable `StoreBusyError` conditions, not corruption: receipt
  admission makes exactly one command-level retry and reconciles retained history, then
  propagates persistent contention for an operator-controlled retry; and
- the separate `etzio.cli` foundation model executes only its deterministic in-process
  toy target. Its modeled verdicts are not vulnerability evidence.

Do not run generated payloads, unknown repositories, historical benchmark build systems,
or third-party exploit material with the current engine.

## Research categories and current authority

The current executable research surface is repository-owned fixtures only. Public research
and pinned historical benchmarks whose terms permit local analysis may be inspected
read-only; their build systems and payloads must not be executed with the current engine.
Locally owned test systems are a future gated category, not part of the supported target
surface. Any such system—and, later, any external target—requires an exact admitted target
contract, the applicable integrity and isolation gates, and separately scoped grants.

## Separate authorities

The following require explicit, scoped approval and must fail closed independently:

1. read-only access to target bytes;
2. network recon or dynamic target interaction;
3. exploit or model-generated code execution;
4. credential or sensitive-data access;
5. paid compute or other spending;
6. disclosure drafting;
7. submission, publication, or any external write.

A bug-bounty program is not blanket authorization. Its current rules, assets, exclusions,
rate limits, automation policy, safe harbor, and disclosure channel must be captured for the
specific mission.

## Required execution posture

Before executable research is enabled, MARCELLUS and CATO must run in separate,
independently identified workers under a proved Linux isolation profile. The profile must
provide default-deny egress, no ambient host credentials, read-only immutable inputs,
resource ceilings, expiring leases, complete receipts, and a tested kill path. A container
label alone is not evidence of isolation.

## Sensitive material

Never commit credentials, private target source, undisclosed findings, exploit payloads,
raw model reasoning, mission ledgers, or unrestricted sensitive prompts. Content-addressed
staging and canonical vault evidence still require access control and retention policy.

## Reporting an Etzio issue

Coordinate privately with Daniel Wahnich. `research@danielwahnich.dev` is the provisional
project address and must be operationally verified before it is relied upon as the only
reporting channel. Do not create a public issue or external disclosure from repository
bytes.
