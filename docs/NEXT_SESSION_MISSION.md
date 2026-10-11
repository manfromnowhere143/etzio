# Next-session mission: evidence, frontier review, and first paid research

Status: operator-requested continuation brief, 2026-10-11. This is a research and execution
plan, not a provider admission, target grant, or finding. Start with
[SESSION_HANDOFF](SESSION_HANDOFF.md) and [MISSION_STATE](MISSION_STATE.json).
The latest dated recovery section governs current status; older sections retain history.

## Founder objective and engineering verdict

Build an enterprise-grade, target-neutral engine for authorized vulnerability discovery,
independent reproduction, remediation and governed learning. Paid findings are an urgent
economic objective. Bugcrowd is one possible channel; EVM is the first proposed domain,
not a permanent limit. Consider source, native code, protocols, web/API, cloud, mobile,
smart contracts, supply chain and defensive assurance through versioned adapters.

The present evidence supports an extensively tested foundation and a fixture-only
detector. It does not demonstrate competitive discovery, a production execution service,
an accepted finding or income. Treat outperforming leading systems as an experimental
objective with named comparators and budgets. Do not promise superiority or millions in
revenue. Study what leading teams have disclosed; do not claim knowledge of their private
plans or extrapolate vendor results to Etzio.

The next session must independently challenge the roadmap, identify the shortest credible
route to a first authorized, independently reproduced, eligible finding, and continue
dependency-complete engineering. Preserve the long-horizon system while reducing the first
campaign to one well-understood target boundary. Measure progress by closed dependencies
and external evidence, not added abstractions, test counts or paper lists.

## First-session sequence

1. Verify cwd, Git root, remote, branch, clean/dirty state and current release. Read the
   actual `AGENTS.md`, current handoff and machine state. Preserve uncommitted work and
   inspect any unfinished validation before resuming it.
2. Complete the mandatory locked-environment bootstrap and unchanged `make verify`.
   Read README, CHARTER, ARCHITECTURE, ROADMAP and FRONTIER_BASELINE in that order,
   then this brief, PRESENTATION, QUALIFICATION_NEXT_STEPS and BOUNTY_READINESS.
   Review ADR-0001 and ADRs 0019–0024 before changing the current boundary.
3. Map the whole repository, then trace the consequential paths against contracts,
   schemas, tests and retained release evidence. Keep a coverage record of files read
   and unresolved questions; do not describe a search or sampled review as a full audit.
4. Conduct a bounded, fresh primary-source research pass. Extend and challenge the
   [dated seed ledger](evidence/next-session-research-seeds-2026-10-11.json), including
   arXiv full texts, official specifications, released code and current program briefs.
   Produce a decision, rather than postponing engineering for an unbounded survey.
5. Write one reviewable next-step packet: architectural verdict; updated dependency graph;
   ranked revenue-path comparison; one chosen near-term milestone; falsifying experiment;
   required authority/resources; and explicit acceptance/refusal criteria. Separate
   engineering effort estimates from external waiting and uncertain payout timing.
6. Continue the highest-value authorized tranche. A pending acquisition decision blocks
   that acquisition only. Public-document research, exact program dossiers, experiment
   design, and dependency-complete offline work can continue without repeated permission.
   Request only genuinely missing, action-specific inputs after preparing the concrete
   decision. No hardware specification or new cloud login is presently needed for planning.

Repository review map:

| Surface | Read together | Question the review must answer |
| --- | --- | --- |
| Identity, scope and wire | `authority.py`, `crypto_v1.py`, `mission_v1.py`, `protocol/`, `schemas/` | Can any alternate entrypoint, type, replay or serialization bypass authority or identity binding? |
| Canonical state and recovery | `kernel/store.py`, events, reducer, evidence vault, integrity transition, blocked finality and qualified lifecycle | Do atomic retention, cold reconstruction, current-head checks and governed recovery compose under failure? |
| Candidate and verifier boundary | `analysis/`, fixture scan, leases, artifact resolution, receipt admission and recovery | Which artifacts are observed, which are modeled, and who independently establishes the effect? |
| External-material qualification | `qualification/`, `scripts/`, ADRs 0020–0024 and `tools/native-time*/` | Are exact bytes, trust assumptions, acquisition budgets and compatibility refusals preserved end to end? |
| Release and validation | `tests/`, fixtures, lockfiles, `scripts/ci/`, workflows and policy validator | Which claims have independent controls, and which pass only self-generated fixtures? |
| Proposed product surface | Charter, architecture, roadmap and all decision records | What is implemented, what is absent, and what is necessary for the first measured domain? |

Paths in the first four rows are relative to `etzio/` except explicitly named
`scripts/`, `tools/` and documents. This is an orientation map, not a review-completion claim.

## Research questions and required output

For every consequential recommendation retain: exact source URL; title and authors or
publisher; publication and revision dates; version/commit/dataset manifest; retrieval date;
review depth; license/access constraints; the specific supporting claim; contradictory
evidence; and a proposed Etzio experiment. Preserve exact source bytes privately with
size/digest where possible. Retrieval failure remains missing evidence. An arXiv submission
is a preprint unless a separate publication is verified; a vendor report is a vendor report.
A recent date alone does not make a method better. Recheck corrections and newer versions.

| Use case | Compare | Evidence needed before adoption |
| --- | --- | --- |
| Native provider authority | RFC 3161 paths, Roughtime, revocation metadata, transparency/catalog/witness arrangements | Exact applicable wire versions, trust bootstrap, independent administration, full time hull, freshness, native refusals and cold replay |
| Storage and isolation | Concrete SQLite/VFS/device profile; supported Linux/KVM/VMM configurations | Failure model, physical/journal quotas, restore and stale-head controls; denied egress, credential separation, measured independent verification and kill authority |
| Discovery | Static/dataflow analysis, symbolic/concolic methods, coverage-guided and property fuzzing, semantic/model-guided search, patch/variant analysis | Domain-specific threat model, affordable baselines, realistic clean controls, independently reproduced effects, ablations and total cost |
| Verification and repair | Effect/invariant oracles, differential replay, executable security probes, vulnerable/fixed comparisons | Oracle ownership outside generator control, preserved legitimate behavior, grader abuse controls and repeatable receipts |
| Knowledge and learning | Source-bound reusable evidence, retrieval/context tools, search scheduling, offline strategy promotion | Reduced repeated analysis without laundering hypotheses into facts; held-out gains, provenance, full auxiliary cost and rollback |
| Economic application | Public bounties, audit contests, customer-authorized code review, defensive remediation/assurance | Actual eligibility, delivery obligations, review effort, unique accepted results, costs and cash timing; none is an established Etzio product |

Read the existing frontier comparison before adding another system. Refresh Google
DeepMind/CodeMender/Big Sleep, other major security agents, AIxCC/ATLANTIS and accessible
independent systems from primary reports and artifacts. Compare available methods and
reproducible protocols; inaccessible models and private evaluations are not usable local
baselines. Do not assume that more agents, more tokens or more complex mathematics improves
results. State the hypothesis, the alternative, and the experiment that could reject it.

New seed observations inspected on 2026-10-11:

- [AVRI, arXiv 2610.11602v1](https://arxiv.org/abs/2610.11602v1), submitted
  2026-10-08, studies repeated analysis and full-run cost. Its initial `200` traces cover
  only `10` tasks reused across configurations; harness entrypoints are supplied, and its
  crash criterion is not a bounty finding. Selected full-text methods and limitations were
  inspected. Proposed lesson: evaluate reusable source evidence and include auxiliary costs;
  independently reproduce before adopting claimed savings.
- [MobileCybench, arXiv 2609.23980v1](https://arxiv.org/abs/2609.23980v1), submitted
  2026-09-21, proposes executable security-property probes. Only its abstract and version
  metadata were reviewed here. Investigate whether the oracle design transfers to Etzio's
  proof workers; no Android adapter or generality claim follows.
- [CyberChainBench, arXiv 2606.26216v1](https://arxiv.org/abs/2606.26216v1), submitted
  2026-06-24, adds historical chain-state evaluation. Selected full-text methods and
  limitations were inspected: contamination remains possible, patch coverage is restricted,
  and multi-transaction behavior is largely absent. Its simulated economic effects are
  not collected bounties. Investigate reproducible state capture and independent oracles.
- [ReEVMBench v1](https://arxiv.org/abs/2603.10795v1), 2026-03-11, is a required
  counterpoint to contest-based EVM results: scaffold, information regime and incident
  selection matter. Refresh the full paper and code; the current seed capture is an abstract.
- [ATLANTIS v1](https://arxiv.org/abs/2509.14589v1), submitted 2025-09-18, and
  [OSS-CRS v2](https://arxiv.org/abs/2603.08566v2), revised 2026-03-25, are leads for
  hybrid analysis and operationally reusable research systems. Abstracts/version histories
  were checked; implementation, licensing and resource demands still need review.
- [Google's cyber model page](https://deepmind.google/models/gemini/cyber/) currently
  describes Gemini 4 Argon and restricted Fairwind rollout. It is a mutable vendor page
  without a publication date established here. Preserve the retrieved snapshot, verify
  actual access and evaluation protocols, and do not reuse July model comparisons as current.
- [Bugcrowd AI documentation](https://docs.bugcrowd.com/researchers/onboarding/ai-privacy-security/)
  principally describes Bugcrowd's own AI features and data controls. It is not a target
  allowlist or a blanket permission for researcher automation. Recheck the actual researcher
  rules and exact engagement brief before relying on a broader interpretation.

The seed ledger is intentionally small and explicitly records review depth. It does not
constitute a completed frontier survey or independent reproduction. Existing EVMbench,
SCONE-bench, BountyBench, CVE-Bench, ExploitBench and other leads remain in FRONTIER_BASELINE.
Do not run downloaded build systems, benchmark payloads or installers before the relevant
execution and dataset gates. Public source inspection is a different action.

## Faster route to income: decision required, no silent shortcut

The current order remains native provider admission and lifecycle, external latest-head
recovery, qualified storage, independent isolated execution, measured domain discovery, and
exact target admission. The historical handoff's suggestion that human-assisted contests
might be faster is an unmeasured option, not an approved reversal of ADR-0001.

Evaluate at least these paths on a common dependency/cost basis:

| Path | Work available now | Decision before execution or a paid commitment |
| --- | --- | --- |
| Narrow EVM bounty through Etzio | Refresh CoW and Immutable dossiers, known issues, scope mapping and finite invariant hypotheses; plan benchmark baselines | Close applicable engine gates and admit exact target/revision, allowed methods and finite resources |
| Human-assisted audit contest | Research active rules, accessible code, scoring, duplicates, verification and deadlines; compare required capability | If this would precede or bypass current foundation ordering, propose an explicit scoped ADR/mission change for operator acceptance first |
| Customer-authorized review or remediation | Compare deliverables, qualified tools, confidential-data handling and likely reviewer work using public material | A real customer engagement, exact authorization, data policy and delivery terms; no assumed client or authority to solicit one |
| Enterprise evidence/verification product | Identify a narrow buyer problem and measurable evidence quality using owned fixtures | Validate demand and production requirements; a credible product hypothesis is not present revenue |

No platform is mandatory. The founder reports a Bugcrowd account; account access, invitations,
eligibility and payment setup have not been verified. Do not request credentials for public
research or infer account-specific access from that report. CoW is the existing proposed
first dossier, not a frozen investment decision or an admitted target.

The next packet must rank these paths by time and dependencies to the first independently
reproducible result, total expected effort, setup cost, review burden, duplicate/ineligible
risk, payment conditions and reusable engine value. Separate known facts, assumptions and
unknowns. Use scenario ranges when justified; do not invent success probabilities or a
cash date. Public bounty caps and simulated exploit profits are not forecasts.

Keep two workstreams active in the plan: closing the foundation critical path, and preparing
one commercial/benchmark dossier from public evidence. This means concurrent project
priorities, not permission to spawn agents or run targets. Defer broad adapters and optional
abstractions until a measured need justifies them. Any proposed scope reduction must identify
which claims are deferred and preserve the controls required by the remaining claims.

## Mathematical and experimental discipline

Use the applicable mathematics for each claim. Retain the assumptions, failure model and
units beside the result. Required areas include conservative interval propagation and
half-open freshness; cryptographic domain separation and trust roots; state-machine and
crash/concurrency reasoning; domain-specific safety/accounting invariants; and statistically
valid comparisons. Formal proofs, fuzzing, signatures and model agreement establish
different properties; none substitutes for independent empirical effects.

Freeze eligible task IDs, licenses, versions, images, information/hints, tools, models,
prompts, oracles, seeds and budgets before a reported experiment. Compare simple static,
model-only and hybrid baselines under matched constraints. Separate Detect, Exploit and
Patch outcomes. Use held-out targets, patched/clean/near-miss controls and grader adversaries.
Withhold labels and reference solutions from workers. Record contamination uncertainty;
a time split alone does not prove absence of training leakage.

Report all attempted tasks and exclusions, independent reproduction, precision/recall,
false-positive and false-discovery rates where labels permit them, unsupported cases,
timeouts, disagreement, review time, compute and total cost. Zero denominators are undefined.
Cluster uncertainty by independent target/root cause; repeated seeds are not new independent
targets. Do not infer recall on live programs with unknown ground truth. Predeclare stopping
rules and account for adaptive selection and multiple comparisons. An honest null result
can reject a design and save money.

For economics, separately retain: candidate, independently reproduced effect, eligible
report, submitted report, duplicate/rejection, accepted finding, award, settled payment and
net cash after costs. The first useful commercial milestone is one authorized independently
reproduced eligible report; acceptance and payment require external outcomes. Until these
exist, competitive advantage and bounty income remain unproven.

For standards, refresh the existing crosswalk and retain exact version, date, applicable
clause, implementation mapping, test/evidence and gaps. Follow current primary specifications,
errata and deprecations. Do not claim blanket compliance, legal qualification, or a universal
2026 technique set. A standard belongs in the plan only when it governs an actual use case.

## Concrete pending experiment and preservation rules

The released diagnostics are advisory observations outside canonical custody. They do not
retroactively diagnose the first FreeTSA failure. The next proposed one-request capture is
fully described in [FREETSA_DIAGNOSTIC_PROPOSAL](FREETSA_DIAGNOSTIC_PROPOSAL.md), with exact
plan/runtime/request/assumptions in its linked JSON. The 2026-10-11 handoff request is not
acceptance of that experiment.

Before an explicitly accepted follow-up, verify the exact proposal, environment, runtime,
input manifest and original spent journal. Only then create the new journal and invoke the
prepared command once. Retain advisory CLI output separately; inspect cold state afterward.
Never reset, copy, replace or retry a spent journal to obtain a new attempt. A failed or
missing response remains indeterminate. Any response is untrusted material for offline
inspection, not automatically provider or clock authority.

Passive Roughtime reviews already exist in
`artifacts/checkpoints/2026-10-10-https-capture/roughtime-research/` and
`artifacts/checkpoints/2026-10-10-capture-diagnostics/roughtime-readonly/`.
They distinguish RFC 10049 version contexts, trust-key requirements and raw/parsed byte
binding; no upstream code was built or executed and no upstream vulnerability was proved.
Use these retained observations before repeating research. Compare provider options by
compatibility and independent trust evidence, not by sunk implementation effort.

Temporary cloud probes were cleaned up according to retained readbacks. Existing bounded
benign Google Cloud qualification authority persists; production storage, hard isolation
and target execution remain unqualified. Revalidate cloud identity/state if a new authorized
experiment requires it; preserve unrelated workloads and retain cleanup/cost evidence.
The old login transcript is not a current credential check. Do not provision a 24/7 worker
from this handoff or imply that work continues after the session closes.

## Completion record for the next tranche

Before reporting completion, retain the chosen hypothesis, contracts, exact code/data
identities, positive and known-bad results, unresolved assumptions, full diff and validation.
Run required `make verify` before and after changes, preserve all negative results, and
complete both declared-runtime release checks. Follow the existing sole-human-author,
exact-head CI/package and linear fast-forward publication process. Update handoff and
machine state without rewriting historical observations.

Each checkpoint must answer: what is now proved; what remains modeled or blocked; which
dependency was removed; what is the next falsifying experiment; what can proceed without
Daniel; and what exact decision, if any, is still his. Stop the current tranche at a
recoverable boundary when asked for a handoff. Do not replace the mission with perpetual
research or represent prepared work as an operating bounty engine.
