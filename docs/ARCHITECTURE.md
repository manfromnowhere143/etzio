# Etzio Architecture

Status: **architecture foundation**, 2026-07-27. This document separates the implemented
repository from the intended system. “Target” marks a design obligation, not shipped code.

## Architectural verdict

Etzio’s intended shape is sound: a small deterministic control kernel surrounded by
replaceable research workers, with policy authority and independent scientific verification
kept outside the generative swarm. That is the right foundation for broad vulnerability
research.

The current implementation does not yet realize that shape. It contains two disconnected
demonstrations:

1. a governed-looking, in-memory lifecycle using mostly deterministic stubs; and
2. a real but narrow Python AST scan command that accepts a local path and bypasses the
   lifecycle, authority, event, and verification layers.

The first engineering mission is to make one small path truthful end to end before adding
languages, agents, or live adapters.

## Target system

```text
                          human / program authority
                                      │
                         signed, exact grants and policy
                                      ▼
┌───────────────────────────────────────────────────────────────────────────┐
│ AQUILA · policy plane                                                    │
│ contract admission · scope · budgets · leases · egress · kill · approval │
└──────────────────────────────┬────────────────────────────────────────────┘
                               │ admitted commands
                               ▼
┌───────────────────────────────────────────────────────────────────────────┐
│ ETZIO · deterministic control plane                                      │
│ protocol registry · lifecycle reducer · append-only ledger · scheduler   │
│ idempotency · recovery · evidence graph · next legal action               │
└──────────────┬───────────────────────────────┬────────────────────────────┘
               │ leased work                   │ validated receipts
               ▼                               ▼
┌──────────────────────────────┐     ┌──────────────────────────────────────┐
│ research plane              │     │ independent proof plane              │
│ SCIPIO → FABIUS → VELITES   │     │ MARCELLUS builder → CATO verifier   │
│ domain + technique packs    │     │ separate identities and isolation   │
└──────────────┬───────────────┘     └──────────────────┬───────────────────┘
               └──────────────────────┬─────────────────┘
                                      ▼
                         CAMILLUS → FABRICIUS
                         adjudication   draft
                                      │
                                      ▼
                       MINERVA offline promotion loop
```

Workers propose observations and receipts. They do not mutate canonical state or grant
authority. The kernel validates commands against the protocol, current state, exact lease,
authority snapshot, evidence digests, and producer identity before appending an event.

## Planes and responsibilities

### ETZIO — control plane

Target: a deterministic command handler and pure reducer. It owns protocol versions,
mission state, legal transitions, idempotency, artifact references, and the next legal
action. It must recover the same state from retained events without conversational memory.

Current: `MasterLoop` directly calls in-process Python objects and mutates `MissionState`.
There is no command protocol, loader, reducer, durable store, resume, or closed-ledger
enforcement.

### AQUILA — policy plane

Target: validate and admit a versioned authority envelope before mission creation. Every
lease binds actor, target revision, allowed operation, resource ceiling, expiry, and
revocation state. Egress, credentials, spending, live interaction, disclosure, and
publication remain separate capabilities.

Current: `TargetContract` is a caller-created dataclass. It accepts blank references,
arbitrary authorization kinds, negative budgets, and unvalidated scope. `Aquila.permit`
performs simple membership checks. The loop emits `mission_opened` and
`scope_authorized` without an admission proof.

### SCIPIO — surface plane

Target: emit a versioned attack-surface graph with exact target revision, source provenance,
entrypoints, trust boundaries, dependencies, build context, and parse/coverage failures.

Current: the demo returns three hard-coded entrypoints. The standalone Python mapper walks
files with `ast`, records functions and imports, and reports parse errors.

### FABIUS — strategy plane

Target: rank falsifiable hypotheses using domain-pack knowledge, target evidence, expected
information gain, cost, and risk. Rankings remain reproducible and benchmarkable.

Current: three hard-coded hypotheses.

### VELITES — investigation plane

Target: run small leased probes through versioned technique packs. Static and dynamic
workers return typed observations and candidates; they never issue findings.

Current: the demo emits two fixed candidates and one null. The standalone analyzer has six
syntactic Python rule classes covering seven planted instances. It has no interprocedural
taint, alias analysis, dependency reasoning, or proof construction. Syntax errors are
skipped by the finding path, candidate IDs depend on traversal position, and snippets may
expose literal source values.

### MARCELLUS — construction plane

Target: construct minimal exploit proofs inside an isolated worker, returning immutable
artifact and execution receipts. Builder identity is cryptographically and operationally
separate from CATO.

Current: returns an existing in-memory `PoCArtifact` unchanged.

### CATO — independent proof plane

Target: rehydrate exact artifact bytes in a fresh environment, execute under a separate
identity and policy, observe a machine-checkable effect, challenge the result, and return a
signed verdict receipt. CATO may reject; only the kernel may mint a finding.

Current: directly invokes `target.run(payload)` in the caller’s process. It trusts
caller-supplied verifier fields and does not enforce a `poc_execution` grant itself.
`reproduced_from_bytes` and the environment digest are modeled labels, not proof of separate
execution.

### CAMILLUS — adjudication plane

Target: validate evidence completeness, deduplicate by root cause, calculate severity with a
versioned rubric, rank review queues, and preserve conflicting interpretations.

Current: deterministic ordering only.

### FABRICIUS — disclosure plane

Target: render a report solely from retained evidence and a program-specific template.
Submission is a separate one-time human-authorized external effect.

Current: deterministic report prose in memory; no external write.

### MINERVA — learning plane

Target: derive lessons from findings, nulls, failures, costs, and reviewer outcomes. A
candidate strategy version passes shadow and holdout evaluation before human promotion.
Training data, benchmark labels, evaluators, policy, and production code are protected from
direct self-modification.

Current: returns counts and a fixed note.

## One versioned protocol

The intended canonical envelope is:

```text
ProtocolEnvelope
  protocol_version
  object_kind
  object_version
  object_id              # full SHA-256 of canonical semantic bytes
  mission_id
  target_revision
  authority_snapshot_id
  producer_identity
  created_at
  body
```

Python runtime objects, JSON wire objects, stored events, tests, and schemas must serialize
to this contract without special cases. Unknown versions fail closed. Canonicalization must
reject non-finite numbers, implicit string coercion, duplicate keys, and unrecognized
security-relevant fields.

Current dataclasses do not satisfy the checked-in JSON Schemas: `TargetContract` and
`Finding` have different shapes, and tuples do not validate as JSON arrays without explicit
serialization. Alignment is a blocking task.

## Authority lifecycle

```text
untrusted contract
      │ validate syntax, semantics, issuer, signature, time, revocation, target digest
      ▼
admitted authority snapshot
      │ authorize mission creation
      ▼
mission_opened
      │ derive scoped, expiring work leases
      ▼
worker receipts
      │ validate identity + lease + evidence + current state
      ▼
canonical events
```

A refusal appends a distinct terminal-visible event and projects the mission to `blocked`.
Timeout, cancellation, crash, budget exhaustion, revocation, policy denial, and scientific
non-reproduction are distinct outcomes.

## Event and replay model

Target events use canonical JSON bytes and full SHA-256 digests. Event payloads are deeply
immutable values. Each event commits to:

- stream and sequence;
- protocol and event version;
- mission and target revision;
- command and idempotency key;
- actor and authority snapshot;
- complete state-relevant payload;
- prior event digest;
- deterministic event digest.

The durable store performs compare-and-append against the expected head, fsyncs before
acknowledgment, refuses appends after terminal closure, and exposes an anchored head. A pure
reducer reconstructs state and rejects gaps, forks, malformed events, illegal transitions,
or incompatible versions. Runtime timestamps and diagnostics may be recorded, but cannot
make semantic replay nondeterministic.

Current `EventLedger` is a mutable in-memory list. Its frozen `Event` contains a mutable
dictionary; events can be changed after append, appends remain possible after closure, only
the predecessor linkage is checked, digests are truncated to 96 bits, and `default=str`
hides noncanonical values. This is not a durable audit ledger.

## Finding admission

A kernel-minted finding must establish all of the following:

1. the candidate ID is content-bound and matches the verdict;
2. the candidate producer differs from the admitted verifier identity;
3. the authority snapshot permits the exact target revision and action;
4. the PoC bytes and environment specification match their full digests;
5. the isolated execution receipt is authentic, complete, and within lease;
6. the observed effect satisfies a versioned oracle independent of the producer’s claim;
7. the verdict is `confirmed`;
8. every referenced artifact is retained and traversable.

The current kernel checks only a producer/verifier identity string inequality before calling
the verifier and trusts the returned object. A forged verifier can therefore mint a finding.

## Isolation model

The proof plane requires at least two separately identified workers:

- **builder**: receives candidate evidence and creates an exploit artifact;
- **verifier**: receives immutable target and artifact bytes, not builder state, and
  independently executes the oracle.

The initial production candidate is a Linux/KVM microVM profile, with gVisor or Kata
evaluated where their syscall and operational trade-offs fit. Required controls include:
default-deny egress, no ambient credentials, immutable base image, measured environment,
read-only inputs, ephemeral writable layer, cgroup/resource ceilings, seccomp/device
restrictions, expiring leases, complete stdout/stderr/effect receipts, and a tested
out-of-band kill path.

No such execution tier exists in this repository.

## Domain and technique packs

Breadth is an adapter problem, not a kernel fork:

```text
domain pack
  target/revision resolver
  authority vocabulary
  surface schema
  hypothesis library
  build and execution profile
  effect oracles
  severity/disclosure rules
  benchmark suite

technique pack
  tool declaration
  accepted input protocol
  output/receipt protocol
  capability and resource requirements
  negative fixtures
  versioned evaluator
```

The first wedge is benchmark-first EVM, Solidity, and blockchain-client research because
the ecosystem provides concrete exploits, high-value outcomes, and emerging public
benchmarks. Python analysis remains a small technique fixture, not the product boundary.

## Threat model

Etzio assumes hostile target bytes, malicious build systems, prompt injection in all
research inputs, deceptive tool output, compromised or mistaken model workers, forged
receipts, verifier gaming, artifact substitution, dependency compromise, event tampering,
credential theft, resource exhaustion, and an operator making an accidental scope mistake.

No single model, worker, signature, consensus, or green CI job is scientific or policy
authority. Security depends on independently enforced boundaries and replayable evidence.

## Current evidence and its limits

| Evidence | Observed result | Valid claim |
|---|---:|---|
| Original behavior suite | 15 passing tests | modeled paths remain deterministic |
| CATO fixture corpus | TP=3, FP=0, TN=4, FN=1 | behavior on eight labeled fixtures only |
| Python vulnerable fixture | 7 planted instances found | six narrow syntactic rule classes |
| Python clean fixture | 0 alerts | one clean fixture only |
| Package scan | intentional fixture alerts only | no non-fixture alert under current rules |

The evidence does not establish authorization enforcement, isolation, independent
verification, event durability, real-world precision, broad recall, or superiority.

## Blocking acceptance criteria

Before capability breadth:

- runtime values validate against one immutable protocol;
- malformed, expired, revoked, blank, over-budget, and wrong-target authority is refused
  before `mission_opened`;
- the real read-only scan path runs only through an admitted lease and kernel;
- IDs are stable across ordering, process, and machine;
- immutable events persist and deterministically replay;
- denial, crash, cancellation, timeout, and revocation project distinctly;
- the kernel rejects forged, mismatched, self-produced, or incomplete verifier receipts;
- every invariant has a known-bad fixture.

Before live or executable research:

- MARCELLUS and CATO run in separate proved isolation;
- a pinned historical benchmark traverses the complete chain from admitted bytes to report;
- positive and negative holdouts measure precision, recall, stability, time, and cost;
- the exact external program contract is current and human accepted;
- external effects remain separately approved and audited.
