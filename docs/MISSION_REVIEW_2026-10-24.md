# Etzio mission review, 2026-10-24

Status: scoped review and proposed execution plan. No new target or execution authority.

## Verdict

Etzio has a substantial governed fixture kernel. It does not yet have evidence
supporting a state-of-the-art vulnerability-discovery claim. The six-rule Python
analyzer, seven planted candidates and one clean fixture establish a small owned
test surface. They do not measure discovery on unfamiliar code, independent
execution, false-positive rates, exploitable effects or bounty income. The
inherited release passes `2711` tests, but test count measures neither competitive
research quality nor commercial yield.

The architecture's strongest thesis is the path from exact authorized bytes to
independently checked effects and retained decisions, including explicit unknowns
and recoverable interruption. That is a useful research hypothesis. Other systems
already combine models, tools, reproduction and remediation; the mere presence
of those components is not differentiation. Etzio must demonstrate more distinct
confirmed causes per complete cost and reviewer effort under matched conditions.

The immediate failure is an incomplete operational chain. Native provider
administration, external recovery, protected storage, independent MARCELLUS/CATO
execution and the registered EVM comparison are still open. All `18` comparison
registration inputs remain unbound. Adding more proposed adapters, reviews or
languages cannot substitute for closing those dependencies. Income is a desired
outcome, not evidence that the chain already works.

This review covers the current recovery records, architecture, roadmap, frontier
baseline, qualification and bounty dossiers, and targeted code and test paths.
It is not an exhaustive line-by-line audit or an independent reproduction of the
papers below. Existing gate order and authority remain in force.

## What the current frontier changes

| Primary source and review scope | Result and limit | Consequence for Etzio |
|---|---|---|
| [VerifierBench v1, October 19](https://arxiv.org/html/2610.28679v1): selected construction, validation and results sections | `222` tasks and `4993` cases include valid alternatives, ordinary mistakes and attacks. The study identifies vacuous rejection and verifier-construction failures; these are general task verifiers, not independent security-effect oracles. | Validate CATO's oracle with legitimate alternatives as well as known-bads. Keep missing or timed-out verification in the denominator with its own status. Replay, repeatability, provenance and mutation checks precede scoring. |
| [Demystifying Agent Skills for Smart Contract Auditing v1, September 24](https://arxiv.org/html/2609.29454v1): selected methods, results and limitations | `83` skills and `7` configurations are evaluated on annotation and audit tasks. Some configurations improve; others regress. Historical award credit is not money earned by the evaluated agent. Most configurations have limited repeated-run evidence. | Freeze skills with their model and harness. Compare against no-skill and matched-budget controls on a disjoint holdout. Charge invocation and verification costs; preserve regressions. Do not install a large skill library and call it an improvement. |
| [ReEVMBench v1, March 11](https://arxiv.org/html/2603.10795v1): abstract, selected results and limitations | The selected agents achieved no profitable end-to-end replay across `110` agent-incident pairs on `22` incidents. Older models, selected historical incidents, grading choices and infrastructure failures limit generalization. | Separate source detection, runtime reproduction and forbidden economic effect. Report task and cause denominators, failures and full attempted cost. This result is not a ceiling on October models. |
| [Anthropic formal verification, October 22](https://www.anthropic.com/research/formal-verification): article methods and stated limits | The vendor describes machine-checked proofs over `239` entrypoints in `123` libraries under a specific static, single-threaded RISC-V Linux/musl model. Specification adequacy, unverified entrypoints and production equivalence remain separate. | A useful future proof names the exact invariant, executable correspondence, semantics and checker. First identify a consequential narrow kernel property; do not infer whole-system security from a theorem about a surrogate. |
| [Anthropic attack surface reduction, October 20](https://www.anthropic.com/research/attack-surface-reduction): article and limits | The vendor reports unnecessary exposed behavior across `25` projects. Unnecessary surface is not automatically an exploitable vulnerability or a payable finding. | Retain a later defensive reduction lane with legitimate-use and regression controls. It does not replace the first admitted EVM comparison. |

These observations refine the existing proposed experiments. They do not add an
unregistered experimental arm, change an evaluator after seeing results or justify
a new runtime dependency. After the first frozen static/fuzzer/model/hybrid
comparison, evaluate semantic guidance, scheduling and evidence reuse separately.
Learned changes remain offline, reversible and unable to change authority or
their own evaluation standard.

Proof tooling is a candidate investment, not the next implementation commitment.
Before choosing it, identify a property whose proof would close an actual open
boundary, its correspondence to deployed code, and a counterexample that the
checker rejects. A separate formal model that assumes atomic storage cannot
qualify the filesystem providing that atomicity.

## Bounties: measure the path to cash

There is real evidence of large awards. [XBOW's October 13 account](https://xbow.com/blog/xbow-built-a-chrome-full-chain-exploit)
reports a `$250,000` Google award and roughly `$40,000` compute for a six-day exploit
chain. It also describes earlier preparation, a previous duplicate and human
researcher intervention. That is a useful example of a complete research workflow,
not a six-day start-from-zero income guarantee or a net-profit calculation.

[Kritt's documentation](https://docs.kritt.ai/getting-started/welcome) attributes
over `$1.5 million` to its team's internal workflow; the
[Blockian platform profile](https://immunefi.com/profile/Blockian/) displays over
`$1.1 million` in earnings across a longer history. These are different populations
and attribution claims. They must not be summed, treated as an experiment on an
open-source release or converted into Etzio's expected revenue.

CoW remains the first prepared contract-program dossier; broadening the prospect
list is not the immediate constraint. The retained 19-file source closure matches
a historical publisher record. It does not bind current deployed runtime and
state, or settle the old advertised revision's relationship to later fixes.
Four earlier hypotheses have contrary source evidence. Fee/fill and degenerate
order obligations remain questions, not discoveries.

The [current CoW rules](https://immunefi.com/bug-bounty/cowprotocol/information/)
require a PoC and demonstrated impact, impose eligibility and identity conditions,
and prohibit contract testing on mainnet or public testnets. Current and former
paid contributors, including listed auditor/service-provider relationships, are
excluded. A proposed commercial engagement must therefore be evaluated separately
from eligibility for this bounty. Program ceilings are not expected rewards;
the program decides acceptance and payment. The source review grants no permission
to execute a fork or submit a report.

The bounty funnel must retain these distinct states: hypothesis; source-supported
candidate; independently reproduced effect; exact-scope eligible report; submitted
report; accepted distinct cause; award; settled payment. Retain duplicates,
rejections, unresolved cases and every attempt's compute and human cost. The
current record establishes no confirmed finding, submitted bounty or settled cash.

## Dependency-complete execution order

| Work package | Required exit evidence | Current action and stopping rule |
|---|---|---|
| Independent native integrity | Named catalog and monitor operators, accepted duties and costs, exact admitted profiles, provider-native known-bads and retained administration evidence | Seek a real operating commitment through the existing operator process. A fresh readback finds one declined prospect, already acknowledged by Daniel, and no commitment in seven reread provider/customer conversations. No new message was sent. Preserve unanswered threads; do not restart the survey or send automatic reminders. |
| External latest-head recovery | Recovery after complete local loss, correct global and mission floors, stale-client fencing and negative controls | Implement against the actual admitted provider arrangement. Mock success or another local signature cannot close this gate. |
| Protected storage and isolation | Accepted SQLite/VFS/filesystem/device profile, quotas, backup/restore, process and power-fault evidence, sensitive-data policy; accepted Linux/KVM containment with measured denial tests | This tranche adds real process-death controls on owned fixture writes. Continue with the concrete qualification profile when its authority and operating evidence exist. Cloud KVM preflight remains preparation. |
| MARCELLUS and independent CATO | Structured retained execution, environment, effect and termination evidence; independent producer; patched and legitimate-use controls | Complete the smallest end-to-end fixture task on the accepted profile. Opaque modeled outputs are insufficient. |
| Registered EVM comparison | Bind all `18` inputs; exact admitted corpus; disjoint pilot/holdout; matched budgets; static, fuzzer, model and hybrid results | Run the frozen comparison before claiming superiority or adding finder breadth. Record nulls, failures, duplicates and reviewer effort. |
| One exact bounty task | Current target/source/state identity, program eligibility, exact TargetContract, independently reproduced in-scope effect | Use the prepared CoW dossier if its unresolved conditions close; otherwise record why it is unsuitable before selecting a substitute. Disclosure and submission require their separate scoped authority. |
| Continued engine improvement | Retained accepted causes and complete cost, prospective holdout gains without safety regressions | Run the authorized bounty lane alongside engine work only after the gates close. Revert changes that do not improve the registered objective. |

Assign a concrete owner, artifact and acceptance criterion to each open dependency
when its operating arrangement is available. Do not give a bounty date without
that arrangement. A declining provider changes the dependency status; it does not
justify weakening independent administration. If the critical path remains blocked,
the operator decision is which real arrangement to obtain, fund or reject. Repeated
status documents and speculative provider code are not closure.

Each engineering continuation should close a retained obligation, repair a
demonstrated defect or produce a bounded negative result that changes a decision.
Review new papers when they can change that next experiment; no fresh broad survey
is a prerequisite for the next implementation. Preserve the long-term breadth in
versioned adapters while concentrating the next runnable slice on the EVM wedge.

## Work completed in this continuation

The [process-death contract](STORE_PROCESS_DEATH.md) specifies real `SIGKILL`
before and after canonical commit at four evidence admissions and four qualified
finality phases, plus a cache-spill pair. Cold replay compares the full logical
database, preserves the global barrier, distinguishes stale-head refusal from
idempotent phase retry, and checks committed evidence without staging. It adds
no runtime behavior or production qualification. Results and limits are in the
[evidence record](evidence/store-process-death-2026-10-24.json).

Private research captures are tool-extracted text with their own retained hashes,
not original publisher HTTP bytes. The research ledger records review depth and
separates public sources from private correspondence. Full release results belong
to the exact candidate checkpoint identified in the handoff. No third-party
payload was run, provider admitted, bounty submitted or payment collected here.
