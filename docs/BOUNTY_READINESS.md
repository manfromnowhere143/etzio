# Bounty readiness and candidate selection

Status: **proposed selection; execution blocked**. Public briefs inspected 2026-10-09.
No target is admitted, no external code was executed, and no finding or income exists.
This is a dated research decision, not a replacement for a program's current terms or an
Etzio `TargetContract`. The engine remains limited to repository-owned fixtures.

The operator requested continued foundation work with paid research as soon as the engine
is ready. Preserve ADR-0001's ordering. Public scope research can proceed now; a campaign
depends on the integrity, Linux/KVM isolation, independent execution, benchmark and exact
target gates. Continuous operation also requires a qualified scheduler, bounded resources,
scope refresh and stop conditions. None is established by an open chat session.

## Proposed order

Selection favors a reproducible code boundary, eligible impact, known-issue visibility,
permitted methods and affordable setup. The order below is an engineering judgment, not
a measured probability of finding a bug. Headline caps are not expected revenue.

| Candidate | Public evidence and fit | Missing before admission |
| --- | --- | --- |
| **CoW Protocol contracts: first dossier** | The [resources brief](https://immunefi.com/bug-bounty/cowprotocol/resources/) names commit `6ebbd810ff2da635fb6f88e9a15fde196f8c852a` and deployed contract addresses. This is a concrete source-to-deployment boundary for the first EVM lane. | Independently resolve source and deployed bytes; pin compiler, dependencies and state; review audits and known issues; reproduce permitted impacts under isolation. |
| **Immutable bridge on Immunefi: second dossier** | The [scope](https://immunefi.com/bug-bounty/immutable/scope/) lists Ethereum/L2 bridge and adapter proxies and implementations, plus a child-token template. Suitable later for cross-chain state invariants. | Resolve both chains, proxy implementation revisions, message/state assumptions and local reproduction cost. Do not infer authority over every Immutable component. |
| **Immutable on Bugcrowd: incomplete brief** | The [official trust page](https://www.immutable.com/trust) links this separately from Immunefi. The [public engagement](https://bugcrowd.com/engagements/immutable) describes funds/wallet authorization, unauthorized transactions, tenant boundaries and privileged systems as impact areas. | Complete asset list, exclusions, testing methods, automation limits, reward schedule and account eligibility remain unverified. Do not transfer Immunefi's scope or rewards to this program. |
| **Aave: reserve** | The [program brief](https://immunefi.com/bug-bounty/aave/information/) describes a broad mature contract surface and governance-mediated payouts. | Resolve source/reward discrepancies, isolate one component and assess audit/duplicate burden. Payment timing makes this unsuitable as an assumed immediate cash source. |

## First proposed dossier: CoW contracts

The [scope brief](https://immunefi.com/bug-bounty/cowprotocol/scope/) lists signing,
authentication, settlement, order, trade and transfer components. Its eligible impacts
include unauthorized orders/solver changes, invalid trade conditions and duplicate token
collection. Known audit findings and previously reported issues are excluded. Solver price
choices, certain solver theft scenarios, migration methods and gas improvements are also
excluded. Convert each included impact and exclusion into a reviewable predicate before
generating candidates; a suspicious code pattern alone is insufficient.

The [information brief](https://immunefi.com/bug-bounty/cowprotocol/information/) requires a
PoC and KYC for payment, prohibits mainnet/public-testnet testing and significant automated
service traffic, and offers a local-fork route. The smart-contract critical cap is
`$1,000,000`; web rewards have different limits. The brief was last updated 2026-09-24.
No payout probability follows from those values.

Proposed dossier contents:

1. Retain the current information, scope and resources versions with retrieval identity;
   reconcile differences, and recheck them before both execution and submission.
2. Resolve the brief's commit, exact eligible contract paths, deployed bytecode and chain
   state without executing the target's build system. A listed revision is documentary
   evidence until this mapping is independently checked.
3. Retain audit/issue exclusions and impact predicates. Keep unknown private duplicates
   explicit; public deduplication cannot establish uniqueness.
4. Describe one finite, local experiment on order authorization and settlement accounting.
   Specify actors, initial balances, allowed transitions and observable effects. This is a
   hypothesis family, not a claim that CoW has a vulnerability.
5. Admit an exact `TargetContract` only when the execution and authority gates close.
   Separate generation from CATO reproduction; retain failing and fixed/control cases,
   environment identity, traces, resource use and null/refusal outcomes.

The current parser did not expose every dynamically rendered asset URL. The dossier must
resolve the complete source-path and deployed-address mapping; this document is not an
allowlist. No target checkout, build, deployment, transaction or service scan was performed.

## Other programs and unresolved evidence

Immutable's [Immunefi information brief](https://immunefi.com/bug-bounty/immutable/information/)
requires PoCs and KYC, uses local forks instead of deployed mainnet/public-testnet tests,
and prohibits high-traffic automation. Its critical smart-contract range is
`$50,000–$1,000,000`, subject to funds-at-risk and other conditions. The displayed update
date is 2026-01-29, while the scope includes a later 2026-02-06 entry; do not treat the
header date as a complete scope revision identity.

For Bugcrowd Immutable, the unauthenticated engagement HTML was readable, but the linked
brief-version document returned HTTP `404`. This is incomplete retrieval, not proof that
the program is unavailable. No login, account setting, research credential or submission
was used. The [Bugcrowd standard terms](https://www.bugcrowd.com/resources/levelup/standard-disclosure-terms/)
defer to each program's brief; account ownership does not establish target scope or a cash
reward. Private invitations and account-specific eligibility were not inspected.

[Aave's security page](https://aave.com/security) advertises a core-program maximum of
`$5,000,000`, while the opened [Immunefi brief](https://immunefi.com/bug-bounty/aave/information/)
shows `$1,000,000`. Retain this discrepancy instead of selecting the larger number. The
brief also describes governance payouts near month-end and only after fixes. A proposed
program restructure is not proof of operative terms or immediate liquidity.

## Campaign acceptance and economic evidence

Foundation release tests measure Etzio's contracts, not bug-finding ability. Before a paid
campaign, measure the EVM pack against pinned historical vulnerabilities and clean controls
under the accepted isolation profile. Track reproducible detection, false positives,
coverage gaps, verifier disagreement and reviewer effort. Keep held-out targets separate
from development fixtures and retain all attempted cases.

For each future campaign, the unit of work is one admitted target revision and one bounded
hypothesis batch. Retain wall time, compute cost, human review time, candidate count,
independently reproduced eligible reports, duplicates, rejection reasons, severity changes,
accepted awards, settlement date and actual net receipts. A submission, accepted report,
award promise and received payment are distinct events. No expected-value estimate is
defensible before enough comparable outcomes exist; early uncertainty must remain explicit.

Stop on scope/version changes, uncertain ownership, isolation failure, unauthorized egress,
unexpected sensitive data, exhausted budgets or an unreviewable effect. Refresh the contract
before restarting. Submission and disclosure remain separate scoped actions. Sustained
operation must preserve these conditions, not weaken them to increase report volume.

## Next dependency-complete work

Finish the native-provider acquisition dossier and admission experiments specified in
ADR-0020/0021; preserve lifecycle replay and governed recovery. Prove external latest-head
recovery after local loss, qualify storage and evidence protection, and replace modeled
outputs with independent execution evidence. Then qualify MARCELLUS/CATO on Linux/KVM and
the first EVM benchmark pack. Keep this shortlist current during that work, with CoW as the
first proposed target dossier. None of these steps guarantees a bounty or a payment date.
