# Security and authorized-use policy

Etzio is a private architecture foundation for authorized vulnerability research. It is not
currently approved for live targets or untrusted exploit execution.

## Current security boundary

The current permitted execution surface is repository-owned deterministic fixtures. Pinned
historical benchmarks may be inspected read-only, but their build systems or payloads may
not be executed until the isolation gate is accepted:

- the demonstration verifier runs caller-supplied target behavior in the host process;
- the standalone Python scan path is not admitted through `TargetContract`, AQUILA, or the
  lifecycle kernel;
- authorization records are not yet signed, validated, expired, or revoked;
- budgets, egress, credentials, and disclosure controls are not yet enforcement boundaries;
- the event ledger is in-memory and is not a durable tamper-evident audit record.

These are tracked architecture blockers, not operational safeguards. Do not run generated
payloads, unknown repositories, or third-party exploit material with the current engine.

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
