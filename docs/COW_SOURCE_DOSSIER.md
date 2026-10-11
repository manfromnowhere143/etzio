# CoW contracts: source dossier and unresolved deployment identity

Status: **documentary preparation; campaign refused**, 2026-10-11. No contract was built,
executed or queried on a chain. No vulnerability, accepted finding or payment is claimed.
This continues the [paid-findings decision](PAID_FINDINGS_DECISION_2026-10-11.md) within
public-source inspection authority.

The advertised source boundary is recoverable, but its historical deployment records do
not match the current brief's addresses. Resolve that discrepancy before investing in a
campaign. It does not prove that the deployed source is different or that the program is
invalid. It disproves the assumption that this commit's deployment records alone establish
the current target identity.

## Retained result

The [scope](https://immunefi.com/bug-bounty/cowprotocol/scope/) and
[resources](https://immunefi.com/bug-bounty/cowprotocol/resources/) point to contracts
commit `6ebbd810ff2da635fb6f88e9a15fde196f8c852a`, dated 2021-04-29. All `12` listed Solidity
files, their `19`-file source import closure and `33` parsed import edges were retained.
The `33` pinned files also include license/build inputs and ten mainnet/xDai deployment
records. Every retained file's size and Git blob identity matched the non-truncated tree;
SHA-256 identities are separately recorded. No upstream installer or build command ran.

The [machine-readable dossier](evidence/cow-source-dossier-2026-10-11.json) contains exact
paths, URLs, retrieval times, digests, import edges, deployment comparison and review limits.
Raw captures and the one-off documentary check script remain private under
`artifacts/checkpoints/2026-10-11-decision-packet/cow/`. They are ignored local evidence,
not part of a fresh clone. Retrieval clocks are host observations, not qualified UTC.

| Documentary check | Observed result |
| --- | --- |
| Unchanged pinned files and recorded import closure | Pass |
| Append a byte to one retained source in memory | Identity mismatch; refused |
| Remove the imported vault-relayer file in memory | Missing retained file; refused |
| Substitute another source under a listed path in memory | Identity mismatch; refused |
| Compare the four unique advertised addresses with pinned deployment records and `networks.json` | Zero matches; source-to-deployment identity remains unresolved |

These controls check this documentary comparison. They are not a Solidity parser,
independent execution, a new kernel admission mechanism or a security audit. A publisher's
Git tree and its raw files are one source, not independently administered witnesses.

## Why the deployment boundary remains open

The current resources page lists the following four addresses on Ethereum and Gnosis:

```text
0x9008d19f58aabd9ed0d60971565aa8510560ab41
0x9e7ae8bdba9aa346739792d219a808884996db67
0xc92e8bdf79f0507f65a392b0ab4667716bfe0110
0x2c4c28ddbdac9c5e7055b4c863b72ea0149d8afe
```

In contrast, the pinned commit's
[network manifest](https://github.com/cowprotocol/contracts/blob/6ebbd810ff2da635fb6f88e9a15fde196f8c852a/networks.json)
and deployment JSON identify these historical addresses on both chains:

| Recorded role | Historical address |
| --- | --- |
| Settlement | `0x3328f5f2cEcAF00a2443082B657CedEAf70bfAEf` |
| Authentication proxy | `0xbbfB9a525ACdd2aB3A5Eb5fc9Ab8CF53b881000e` |
| Authentication implementation | `0xFeDbc87123caF3925145e1bD1Be844c03b36722f` |
| Allowance manager in `networks.json` | `0x7D8E28184408Bc4790E79Fd08ED67f7eBaCBEbcc` |

An address difference can reflect later deployment of the same source. No such equivalence
has been established here. No current chain height, runtime code, implementation/admin
slot, constructor input, immutable value or state snapshot was independently retained.
Explorer links are leads, not bytecode evidence. Current upstream main was pinned separately
at `c07a93e3596194c5e3cf331c755a3f9f0e4a17d8`; it is not silently substituted for the brief's
commit.

## Build and dependency evidence

The pinned `hardhat.config.ts` specifies Solidity `0.7.6`, optimizer enabled with
`1,000,000` runs, plus test compilers `0.5.17` and `0.4.11`. Deployment metadata reports
`0.7.6+commit.7338295f` for settlement/implementation, but `0.7.1+commit.f4a555be` with
`2,000` optimizer runs for the proxy. Those are retained publisher claims, not reproduced
builds. The config loads environment variables and registers tasks; reading it did not
execute them.

The retained `package.json` is `@gnosis.pm/gp-v2-contracts` `0.0.1-alpha.17`; its SPDX
license and source headers identify LGPL-3.0-or-later. `yarn.lock` is retained. Compiler
binaries, package archive bytes, task closure, builder image and complete proxy dependency
closure remain unqualified. A lockfile alone cannot establish an offline reproducible
build. Full third-party source is not copied into Etzio's published tree.

The source closure includes `GPv2VaultRelayer.sol`, although that file is not one of the
12 explicitly linked source assets. It also includes vendored interfaces and arithmetic,
initialization and reentrancy helpers. The brief distinguishes CoW modifications or use
from original vendor defects. Source reachability does not extend the program's scope;
resolve the relayer and vendor boundary before admitting an impact hypothesis.

## Finite invariant to investigate after admission

Selected hypothesis family: **a non-partially-fillable order must not cause repeated input
collection for the same order identity in one settlement**. This follows the public
impact category; it is not evidence of a flaw. The relevant pinned source is:

| Source and reviewed lines | Documentary observation |
| --- | --- |
| `GPv2Settlement.sol`, 75–140 and 274–426 | `settle` checks solver authority and reentrancy, computes trade executions before input transfers; the trade loop updates the shared fill mapping and enforces a fill bound. |
| `mixins/GPv2Signing.sol`, 109–160 | Recovery constructs order identity from the domain-bound order digest, recovered owner and expiry. |
| `GPv2AllowListAuthentication.sol`, 1–111 | Manager/owner checks and the solver allowlist define actor privileges. |

For a later experiment, fix positive sell/buy amounts, token behavior, signature scheme,
owner, authorized solver, receiver, prices, fees and initial balances. Derive one order UID
independently. Compare one valid fill, two distinct valid orders and a duplicate UID in the
same batch. The duplicate case should revert atomically, with no persistent debit or fill
mutation. Fee accounting must be checked separately from the order's fill units. Treat
nonstandard token behavior, zero-amount orders, other signature schemes and cross-transaction
variants as separate declared strata, not hidden changes to this first test.

An independent verifier must reproduce the balance/state effect from exact retained inputs.
A transaction success flag or model assertion is insufficient. Clean, deliberately broken
owned controls and a fixed version must establish that the effect oracle can distinguish
the intended property. These are proposed tests; none ran against CoW. Existing source
checks are contrary evidence to a naive duplicate-fill hypothesis, not proof that every
interaction or arithmetic edge is safe.

## Audit and duplicate boundary

The [pinned current audit index](https://github.com/cowprotocol/contracts/tree/c07a93e3596194c5e3cf331c755a3f9f0e4a17d8/audits)
contains `GnosisProtocolV2May2021.pdf` and `[Cowswap_10122021]SCAudit_Report_2.pdf`.
Their Git blob identities and sizes are retained from the tree. PDF contents were not
reviewed in this tranche, and audit names do not prove which source revision was audited.
The advertised historical tree has no audit directory.

A single public issues page retained 100 records, including 27 issues and 73 pull requests.
Only issue titles/state were inspected; pagination, discussions, code changes and reported
security issues remain incomplete. No public or private duplicate clearance follows.
Audit revision/finding reconciliation is a prerequisite to the proposed experiment.

## Decision and next bounded work

Source acquisition and one source-level predicate are now reviewable. Campaign readiness
is refused because deployment equivalence, reproducible build, audit/duplicate review and
Etzio's foundation/execution/target gates remain open. CoW stays first for **documentary
preparation**, not automatically first for a funded campaign.

Next authorized work is a bounded public documentary reconciliation: read the two indexed
audits, retain their audited revisions/findings, and compare publisher/explorer source and
deployment records with the advertised commit. Preserve the mismatch if no exact mapping
can be established. Do not choose a convenient current revision, invoke RPC, build contracts
or contact the program under this dossier. Re-rank against Immutable if documentary mapping
cannot be closed within one proposed engineer-day; that is a future effort cap, not time
already spent or a claim that another program will be easier.

No additional permission is needed for that public-document work. Native-provider admission,
the pending FreeTSA request, any earlier human-assisted roadmap exception, target execution
and submission remain separate decisions under the current mission contracts.
