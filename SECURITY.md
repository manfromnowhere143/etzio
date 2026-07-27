# Security and authorized-use policy

Etzio is a private architecture foundation for authorized vulnerability research. It is not
currently approved for live targets or untrusted exploit execution.

## Current security boundary

The only supported executable research path is the repository-owned clean or vulnerable
Python fixture selected by `etzio --fixture ...`. That path admits a signed, expiring
fixture grant; resolves an exact manifest-backed content-addressed snapshot; emits stable
candidate observations; and persists a lifecycle-checked hash chain in a private SQLite
store. The supported command has no arbitrary target-path argument.

Those controls prove only the bounded fixture slice:

- the local operator trust snapshot and decision clock are supplied by the invoking
  process; the admission record cannot prove their freshness or the legal validity of
  third-party permission;
- the content store checks byte identity and private file modes but is not a production
  access-control or retention service;
- the SQLite stream is durable and append-only through Etzio's API, but it is not
  externally anchored and retains a documented same-user pathname race;
- static observations are candidates only; this path creates no PoC or finding;
- verifier leases and signed modeled-fixture receipts are contract primitives, not a
  kernel-integrated acceptance path: authoritative lease issuance, CAS-byte resolution,
  atomic lease consumption, and independent execution remain open; and
- the separate `etzio.cli` foundation model executes only its deterministic in-process
  toy target. Its modeled verdicts are not vulnerability evidence.

Do not run generated payloads, unknown repositories, historical benchmark build systems,
or third-party exploit material with the current engine.

## Allowed research

- repository-owned fixtures;
- locally owned test systems;
- pinned historical benchmarks whose terms permit local analysis;
- later, an exact target and revision covered by a kernel-admitted bounty scope or written
  permission.

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
evidence still requires access control and retention policy.

## Reporting an Etzio issue

Coordinate privately with Daniel Wahnich. `research@danielwahnich.dev` is the provisional
project address and must be operationally verified before it is relied upon as the only
reporting channel. Do not create a public issue or external disclosure from repository
bytes.
