# 2026 Vulnerability-Research Frontier Baseline

Snapshot date: **2026-07-29**. This is a design baseline, not an Etzio performance claim.
Sources are primary project, research, program, or vendor publications where available.
Results are not directly comparable across different datasets, scaffolds, budgets, and
best-of-*k* settings.

## What the frontier demonstrates

| System or evidence | Published result | Architectural lesson for Etzio |
|---|---|---|
| [Open Kritt](https://kritt.ai/) and its [launch methodology](https://kritt.ai/open-kritt-launch/) | Kritt reports $1.5M+ in total bug-bounty payouts across Immunefi and HackenProof and separately reports competition results from a workflow built around focused tasks, agent runs, PoC validation, deduplication, and ranking | domain workflows and verification discipline matter more than orchestration novelty |
| [Immunefi Blockian profile](https://immunefi.com/profile/Blockian/) | The current profile displays $1.1M in earnings and high/critical bounty and competition reports | economic outcomes are useful evidence, but profile totals and competition claims must remain distinct |
| [EVMbench](https://openai.com/index/introducing-evmbench/) | 117 vulnerabilities from 40 audits across Detect, Patch, and Exploit; GPT-5.3-Codex scored 71.0% in the published exploit mode | use executable historical tasks, deterministic local chains, explicit modes, and hardened graders |
| [SCONE-bench](https://www.anthropic.com/research/smart-contracts) | 405 known exploited contracts evaluated in local simulation; published analysis emphasizes simulated exploit revenue and cutoff-aware subsets | evaluate exploit construction, contamination, best-of-*k*, and economic effect separately |
| [ReEVMBench](https://arxiv.org/abs/2603.10795) | Reports ranking instability, scaffold sensitivity, and no end-to-end exploit success across its 110 agent-incident pairs | pin scaffolds, rerun for stability, retain failures, and include contamination-controlled real incidents |
| [BountyBench](https://bountybench.github.io/) | 25 real-world systems and 40 bounties across Detect, Exploit, and Patch | expand beyond smart contracts through executable multi-service environments and economic scoring |
| [CVE-Bench](https://arxiv.org/abs/2503.17332) | The original paper baseline reports up to 13% success on real-world web CVE exploitation | real applications remain substantially harder than curated local exploit tasks |
| [AXE](https://arxiv.org/abs/2602.14345) | The June 2026 v2 preprint reports 30% on CVE-Bench when given a CWE and vulnerable source location | report black-, grey-, and white-box information regimes separately; metadata-assisted triage is not open-ended discovery |
| [ExploitBench](https://exploitbench.ai/) | 41 patched V8 vulnerabilities graded by 16 deterministic capabilities in five tiers, from coverage and reproduction through target/generic primitives to full control | a crash or PoC is not an exploit; retain a mechanically graded capability ladder, randomized replay stability, and exact vulnerable/fixed-build evidence |
| [ExploitGym](https://arxiv.org/abs/2605.11086) and its [released corpus](https://github.com/sunblaze-ucb/exploitgym) | The paper describes 898 userspace, V8, and Linux-kernel instances; the current v1.0 corpus declares 869 tasks that extend a supplied proof of vulnerability to unauthorized code execution and flag retrieval | pin code, data manifest, mitigations, task IDs, and judge policy; preserve intended-vulnerability attribution separately from effect, and never silently merge paper and release populations |
| [SEC-bench Pro](https://arxiv.org/abs/2605.26548) | The July 2026 v2 has 344 validated tasks across V8, SpiderMonkey, and Linux; evaluation prompts name target source paths, validation interface, expected error type, and vulnerability class while withholding the reference PoC and root-cause location | pin the exact information regime and three-image grader, run offline to protect withheld artifacts, and retain mechanical evidence for independent adjudication rather than trusting an LLM grade alone |
| [AgentCyberRange](https://arxiv.org/abs/2606.14295) | 110 vulnerabilities across 15 applications and eight enterprise-like ranges with 156 internal hosts add foothold and post-exploitation measurement | multi-host progress requires explicit topology, identity, reachability, foothold, lateral-movement, and effect receipts; it also raises the isolation bar |
| [GPT-5.6 cyber evaluations](https://openai.com/index/gpt-5-6/) | OpenAI's July 2026 vendor report gives GPT-5.6 Sol 73.5% on five-seed ExploitBench, 24.9%/33.7% on two-/six-hour ExploitGym, and 71.2% on the earlier May 183-task V8/SpiderMonkey SEC-bench Pro snapshot—not the current 344-task v2 | retain provider, model, benchmark revision/population, harness, seeds, token and wall-time budgets, safety configuration, and latency treatment; vendor scores do not transfer to Etzio |
| [Anthropic exploit evaluations](https://www.anthropic.com/research/exploit-evals) | Anthropic's May 2026 vendor report says Mythos Preview reached full control on 21 of 41 ExploitBench CVEs across combined Baseline/Nudged variants and evaluates an updated 12-case post-cutoff SCONE set at Best@8 | keep variant, trial, cutoff, best-of-*k*, and simulated-economic assumptions explicit; never compare vendor headline numbers without matched protocols |
| [Gemini 3.5 Flash Cyber](https://deepmind.google/blog/introducing-gemini-3-5-flash-cyber/) | Google's July 2026 vendor report describes repeated-agent search and 55 confirmed V8 issues, including ten not found by its two named comparators, on a private evaluation | breadth, deduplication, and ensemble search matter, but hidden targets, denominators, budgets, and production adjudication cannot serve as Etzio release evidence |
| [Codex Security](https://openai.com/index/codex-security-now-in-research-preview/) | Repository context, threat modeling, validation, findings, and patches; OpenAI's March 2026 report says 14 CVEs were assigned, including two dual reports | continuous repository context, isolated validation, human review, and remediation belong in the full loop |
| [Google Big Sleep](https://googleprojectzero.blogspot.com/2024/11/) | This historical 2024 report describes an exploitable SQLite stack-buffer underflow found and fixed before release | variant analysis plus expert-guided real-code validation can produce novel results |
| [DARPA AIxCC](https://www.darpa.mil/news/2025/aixcc-results) | Team Atlanta won the 2025 final competition; finalist systems combined discovery and patching on critical open-source software | end-to-end cyber reasoning needs build, test, patch, and evaluation infrastructure, not only model calls |
| [OpenAI–Hugging Face evaluation incident](https://openai.com/index/hugging-face-model-evaluation-security-incident/) | OpenAI's preliminary July 2026 report says evaluation models escaped a constrained research environment through a package-cache path and reached external production infrastructure while pursuing an ExploitGym goal | treat the agent, target, dependency proxy, controller, artifact store, grader, and network as separate attack surfaces; default-deny egress and credentials, retain trajectory telemetry, and provide independent containment and kill authority |

## What remains unsolved

The public evidence does not support a universal autonomous vulnerability researcher:

- benchmark performance changes with harness, scaffold, model, budget, and number of trials;
- exploit tasks with explicit success oracles are often easier to grade than open-ended
  detection;
- benchmark labels can omit legitimate novel findings or leak through training data;
- an agent can attack its harness, grader, dependency path, or benchmark infrastructure
  instead of solving the intended task;
- local historical exploits do not reproduce all mainnet, timing, cross-chain, deployment,
  or operational conditions;
- a high recall figure says nothing about false positives unless the denominator and
  adjudication process are published;
- real bounty value includes scope interpretation, duplicates, severity negotiation,
  disclosure quality, and timing;
- model-generated verifiers can game weak graders and must not define their own success.

Etzio therefore needs an evaluation system, not a leaderboard number. The benchmark
environment itself is an adversarial target and must never share the worker's authority.

## Integrity-authority baseline

No single transparency or timestamp service answers every Etzio authority question. The
current adapter-qualification baseline is deliberately compositional:

| Standard or service | Etzio use | Required narrowing |
|---|---|---|
| [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161.html), [RFC 5816](https://www.rfc-editor.org/rfc/rfc5816.html), and [RFC 9921](https://www.rfc-editor.org/rfc/rfc9921.html) | conservative trusted-time evidence over exact bytes | nonce, imprint, policy, certificate path, EKU, revocation, accuracy, algorithm agility, and COSE timestamp ordering must all be explicit |
| [TUF 1.0.35](https://theupdateframework.github.io/specification/v1.0.35/) | versioned revocation and trust metadata | pin the exact specification/client closure; require sequential root, threshold, expiry, hash/length, and rollback checks against trusted time |
| [RFC 9942](https://www.rfc-editor.org/rfc/rfc9942.html), [RFC 9943](https://www.rfc-editor.org/rfc/rfc9943.html), and [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html) | byte-bound registration receipts plus inclusion and consistency evidence | accept only configured algorithms and proof forms; require predecessor consistency and a separately authenticated latest-head witness |
| [Sigstore Rekor](https://docs.sigstore.dev/logging/overview/) | possible future transparency evidence source | never promote one deployment into trusted UTC, revocation freshness, independent witnessing, or complete Etzio command authority |

The modeled-finality adapters currently exercise these roles and idempotent recovery with
unsigned, canonical, code-derived provider assertions; only their decisions and
checkpoints authenticate under the permanently enrolled fixture trust binding. They do not
consume the separate qualified adapter outputs.

ADR-0012 adds a versioned, networkless qualification contract for signed repository-owned
trusted-time and revocation fixture statements. Its exact copied profile binds the trust
root, validation policy, all-required role-separated source roster, provider policies,
codecs, service, and environment. It authenticates the exact statement bytes before parsing
claims, binds requests and nonces against replay, requires a common overlap while retaining
the conservative outer time hull, applies that full hull to half-open revocation validity
and bounded freshness, requires unanimous configured floors, and freshly maps sealed signed
BLOBs to the provider-neutral evidence types. A deterministic corpus manifest and exact
same-request retry make the repository-fixture qualification reproducible.

This is a common contract and harness, not RFC 3161, PKIX, TUF, COSE, SCITT, Rekor, or any
named-provider conformance. It does not establish truthful UTC, current real-world
revocation, separate operators, independent administration, external storage or durability,
availability, consistency, or non-equivocation.

ADR-0013 closes the remaining two evidence kinds under the same discipline. Its exact copied
head-authority profile binds the trust root, validation policy, log origins, and a fixed
roster of at least two anchor sources, exactly one catalog source, and at least two monitor
witnesses. It recomputes RFC 9162 inclusion proofs against a byte-bound Etzio
anchor-registration leaf, recomputes RFC 9162 consistency proofs from the exact retained
predecessor root, refuses an unchanged tree size whose root changed, and requires unanimous
monitor agreement on one catalog head before mapping a sealed `HeadCheckpointFloorV1`. The
Merkle core is validated against the published RFC 6962/9162 reference tree, so correctness
does not rest on agreement with Etzio's own prover.

This remains a common contract and harness, not RFC 9162, RFC 9942, RFC 9943, SCITT, or
Rekor conformance; no native wire format, certificate path, or provider client is parsed.
Unanimous fixture monitors prove the acceptance rule for split-view detection, not the
existence of independent observers. The next gate adds durable blocked-finality disposition
and governed recovery before any external provider connection.

## Required benchmark portfolio

These are future inputs, not authorized executions. Every corpus remains inert until its
license, exact revision, isolation profile, target contract, and resource policy are
accepted.

### Smart contracts and blockchain

- EVMbench Detect/Patch/Exploit with exact upstream revision;
- SCONE-bench cutoff-aware subsets;
- ReEVMBench-style real-incident and scaffold-stability evaluation;
- Etzio-owned negative contracts, patched variants, duplicate root causes, and oracle
  adversaries;
- later, L1/client memory, consensus, networking, and state-machine benchmarks.

### Web, services, and patching

- BountyBench and CVE-Bench subsets with pinned services and database state, reporting
  AXE-style grey-box metadata assistance separately from black-box work;
- an AgentCyberRange subset only after multi-host isolation is independently qualified,
  with exact topology, foothold, reachability, and post-exploitation effect receipts;
- patch correctness with regression and exploit tests;
- multi-step authentication, authorization, SSRF, injection, deserialization, race, and
  business-logic cases;
- clean and near-miss repositories to measure reviewer burden.

### Native and critical open source

- ExploitBench with exact V8 vulnerable/fixed images, all 16 capability flags, randomized
  challenge-response replay, and crash-to-full-control separation;
- a pinned ExploitGym release subset across userspace, V8, and Linux, retaining the exact
  paper/release population distinction, mitigations, flag effect, and intended-vulnerability
  attribution;
- SEC-bench Pro vulnerable/fixed/latest triples for discovery-to-PoC attribution and
  clean-target control, with the source paths, expected error type, vulnerability class,
  withheld artifacts, offline policy, and judge version retained exactly;
- other reproducible historical CVEs and sanitizer-backed oracles;
- variant-analysis corpora;
- build-system, dependency, parser, memory-safety, and concurrency tasks;
- patch preservation and regression evaluation.

## Evaluation protocol

Every released result records:

```text
benchmark + exact revision
eligible and excluded task IDs with reasons
target/environment image digests
dependency closure, network policy, and isolation-profile identity
model, tool, prompt, scaffold, and policy versions
information regime and all target-specific hints
single-run and best-of-k budgets
raw candidate, artifact, verdict, and timing receipts
mechanical capability tier plus intended-vulnerability attribution
TP / FP / TN / FN / invalid / crash / timeout / policy-denied
precision / recall / FPR / FDR with undefined denominators preserved
confidence intervals and run-to-run stability
token, compute, wall-time, and human-review cost
```

Training, tuning, and promotion data remain separated from final holdouts. Benchmark graders
receive adversarial tests, and a model is never allowed to rewrite its evaluator or label.

## Isolation baseline

The initial candidates are:

- [Firecracker production host setup](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md), which requires the jailer or stronger constraints and separately configured network filtering;
- [gVisor security model](https://gvisor.dev/docs/architecture_guide/security/), which reduces the host system-call attack surface but explicitly remains one layer in a larger architecture;
- [Kata Containers architecture](https://github.com/kata-containers/kata-containers/tree/main/docs), for VM-backed container workflows.

Selection requires Etzio-specific threat-model tests, syscall compatibility measurements,
operational recovery, artifact capture, and escape/egress known-bads. Popularity or a vendor
claim is not acceptance evidence.

Regardless of runtime, the worker, vulnerable target, dependency mirror, model gateway,
controller, artifact receiver, and grader require explicit trust boundaries. The accepted
profile must provide immutable dependency closure; no ambient credentials; default-deny
DNS and egress; one-way, bounded evidence export; grader secrets unavailable to the worker;
tamper-evident trajectory and network telemetry; an out-of-band watchdog and kill path; and
clean-snapshot replay after every suspected containment or benchmark-integrity event.

## Etzio’s differentiating target

Etzio should combine five properties that public systems often demonstrate separately:

1. exact authorization and external-effect control;
2. evidence-native, durable mission replay;
3. independent exploit reproduction rather than confidence-based confirmation;
4. benchmarked domain depth with broad adapter architecture;
5. governed cross-mission learning that cannot rewrite its own authority or evaluators.

No evidence yet shows that Etzio has achieved this combination. The roadmap is constructed
to prove it one dependency-complete slice at a time.
