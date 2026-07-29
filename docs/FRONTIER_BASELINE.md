# 2026 Vulnerability-Research Frontier Baseline

Snapshot date: **2026-07-29**. This is a design baseline, not an Etzio performance claim.
Sources are primary project, research, program, or vendor publications where available.
Results are not directly comparable across different datasets, scaffolds, budgets, and
best-of-*k* settings.

## What the frontier demonstrates

| System or evidence | Published result | Architectural lesson for Etzio |
|---|---|---|
| [Open Kritt](https://kritt.ai/open-kritt-launch/) | Kritt reports $1.5M+ in blockchain bounty and competition payouts from a workflow built around focused tasks, agent runs, PoC validation, deduplication, and ranking | domain workflows and verification discipline matter more than orchestration novelty |
| [Immunefi Blockian profile](https://immunefi.com/profile/Blockian/) | The current profile displays $1.1M in earnings and high/critical bounty and competition reports | economic outcomes are useful evidence, but profile totals and competition claims must remain distinct |
| [EVMbench](https://openai.com/index/introducing-evmbench/) | 117 vulnerabilities from 40 audits across Detect, Patch, and Exploit; GPT-5.3-Codex scored 71.0% in the published exploit mode | use executable historical tasks, deterministic local chains, explicit modes, and hardened graders |
| [SCONE-bench](https://www.anthropic.com/research/smart-contracts) | 405 known exploited contracts evaluated in local simulation; published analysis emphasizes simulated exploit revenue and cutoff-aware subsets | evaluate exploit construction, contamination, best-of-*k*, and economic effect separately |
| [ReEVMBench](https://arxiv.org/abs/2603.10795) | Reports ranking instability, scaffold sensitivity, and no end-to-end exploit success across its 110 agent-incident pairs | pin scaffolds, rerun for stability, retain failures, and include contamination-controlled real incidents |
| [BountyBench](https://bountybench.github.io/) | 25 real-world systems and 40 bounties across Detect, Exploit, and Patch | expand beyond smart contracts through executable multi-service environments and economic scoring |
| [CVE-Bench](https://arxiv.org/abs/2503.17332) | The paper reports up to 13% success on real-world web CVE exploitation | real applications remain substantially harder than curated local exploit tasks |
| [Codex Security](https://openai.com/index/codex-security-now-in-research-preview/) | Repository context, threat modeling, validation, findings, and patches; the predecessor Aardvark reported 92% recall on its golden repositories and ten CVEs | continuous repository context, isolated validation, human review, and remediation belong in the full loop |
| [Google Big Sleep](https://googleprojectzero.blogspot.com/2024/11/) | Publicly reported an exploitable SQLite stack-buffer underflow found and fixed before release | variant analysis plus expert-guided real-code validation can produce novel results |
| [DARPA AIxCC](https://www.darpa.mil/news/2025/aixcc-results) | Team Atlanta won the 2025 final competition; finalist systems combined discovery and patching on critical open-source software | end-to-end cyber reasoning needs build, test, patch, and evaluation infrastructure, not only model calls |

## What remains unsolved

The public evidence does not support a universal autonomous vulnerability researcher:

- benchmark performance changes with harness, scaffold, model, budget, and number of trials;
- exploit tasks with explicit success oracles are often easier to grade than open-ended
  detection;
- benchmark labels can omit legitimate novel findings or leak through training data;
- local historical exploits do not reproduce all mainnet, timing, cross-chain, deployment,
  or operational conditions;
- a high recall figure says nothing about false positives unless the denominator and
  adjudication process are published;
- real bounty value includes scope interpretation, duplicates, severity negotiation,
  disclosure quality, and timing;
- model-generated verifiers can game weak graders and must not define their own success.

Etzio therefore needs an evaluation system, not a leaderboard number.

## Integrity-authority baseline

No single transparency or timestamp service answers every Etzio authority question. The
current adapter-qualification baseline is deliberately compositional:

| Standard or service | Etzio use | Required narrowing |
|---|---|---|
| [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161.html), [RFC 5816](https://www.rfc-editor.org/rfc/rfc5816.html), and [RFC 9921](https://www.rfc-editor.org/rfc/rfc9921.html) | conservative trusted-time evidence over exact bytes | nonce, imprint, policy, certificate path, EKU, revocation, accuracy, algorithm agility, and COSE timestamp ordering must all be explicit |
| [TUF 1.0.35](https://theupdateframework.github.io/specification/v1.0.35/) | versioned revocation and trust metadata | pin the exact specification/client closure; require sequential root, threshold, expiry, hash/length, and rollback checks against trusted time |
| [RFC 9942](https://www.rfc-editor.org/rfc/rfc9942.html), [RFC 9943](https://www.rfc-editor.org/rfc/rfc9943.html), and [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html) | byte-bound registration receipts plus inclusion and consistency evidence | accept only configured algorithms and proof forms; require predecessor consistency and a separately authenticated latest-head witness |
| [Sigstore Rekor](https://docs.sigstore.dev/logging/overview/) | possible future transparency evidence source | never promote one deployment into trusted UTC, revocation freshness, independent witnessing, or complete Etzio command authority |

The current repository-owned adapters model these roles and idempotent recovery only. They
do not qualify any external provider or prove separate operators, clocks, storage, or
administration. Their provider-evidence BLOBs are unsigned, canonical, code-derived
fixture assertions; only the decisions and checkpoints are cryptographically
authenticated under the permanently enrolled fixture trust binding.

## Required benchmark portfolio

### Smart contracts and blockchain

- EVMbench Detect/Patch/Exploit with exact upstream revision;
- SCONE-bench cutoff-aware subsets;
- ReEVMBench-style real-incident and scaffold-stability evaluation;
- Etzio-owned negative contracts, patched variants, duplicate root causes, and oracle
  adversaries;
- later, L1/client memory, consensus, networking, and state-machine benchmarks.

### Web, services, and patching

- BountyBench and CVE-Bench subsets with pinned services and database state;
- patch correctness with regression and exploit tests;
- multi-step authentication, authorization, SSRF, injection, deserialization, race, and
  business-logic cases;
- clean and near-miss repositories to measure reviewer burden.

### Native and critical open source

- reproducible historical CVEs and sanitizer-backed oracles;
- variant-analysis corpora;
- build-system, dependency, parser, memory-safety, and concurrency tasks;
- patch preservation and regression evaluation.

## Evaluation protocol

Every released result records:

```text
benchmark + exact revision
eligible and excluded task IDs with reasons
target/environment image digests
model, tool, prompt, scaffold, and policy versions
single-run and best-of-k budgets
raw candidate, artifact, verdict, and timing receipts
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

## Etzio’s differentiating target

Etzio should combine five properties that public systems often demonstrate separately:

1. exact authorization and external-effect control;
2. evidence-native, durable mission replay;
3. independent exploit reproduction rather than confidence-based confirmation;
4. benchmarked domain depth with broad adapter architecture;
5. governed cross-mission learning that cannot rewrite its own authority or evaluators.

No evidence yet shows that Etzio has achieved this combination. The roadmap is constructed
to prove it one dependency-complete slice at a time.
