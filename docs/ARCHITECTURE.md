# Etzio Architecture

Status: proposed foundation, 2026-07-25. Components are design targets unless explicitly
marked implemented. The kernel skeleton in `etzio/` is implemented at skeleton grade (a
runnable state machine + master loop + engine ports); the ten units are ports with stub
bodies until each is closed by a real vertical slice.

## Verdict

Etzio is an **evidence-native vulnerability-research operating system**: a deterministic,
replayable kernel (ETZIO) surrounded by replaceable intelligence units (the roster). The
kernel never depends on an agent remembering the mission. It owns state, authority, budget,
the finding ledger, and the *next legal action*. Units propose; the kernel decides what is
legal; CATO decides what is true.

```
                         ┌─────────────────────────────────────────────┐
                         │  ETZIO  ·  deterministic kernel + master loop │
                         │  event ledger · state machine · authority     │
                         │  budget · idempotency · next legal action     │
                         └───────────────┬─────────────────────────────┘
        proposes (never confirms)        │  derives next legal action
   ┌───────────────┬───────────────┬─────┴──────┬───────────────┬──────────────┐
   ▼               ▼               ▼            ▼               ▼              ▼
 SCIPIO   →     FABIUS    →     VELITES   →  MARCELLUS  →     CATO    →    CAMILLUS
 recon /       threat model    finder      exploit /       INDEPENDENT   dedup /
 surface map   hypotheses      swarm       PoC build       verify+judge  rank / triage
                                                               │
                                                               ▼
                                                          FABRICIUS  →  disclosure
   AQUILA  (scope · egress · budget · kill-switch)  spans every stage
   MINERVA (grounded learning · memory · transfer)  observes every stage, promotes offline only
```

## Architectural invariants

1. Canonical state is an **append-only event ledger**; everything else (dashboards, indexes,
   caches) is a projection and never the only copy of truth.
2. **One writer per stage.** Parallelism is for decomposable investigation (VELITES), never
   for competing mutations of the same finding.
3. **The generator never supplies the terminal verdict for its own finding** (law 2).
4. Every consequential transition names its unit, the authority it acted under, its inputs,
   and the evidence it produced.
5. **A missing authorization fails closed.** Timeout and retry exhaustion are not findings.
6. **Artifact integrity and exploit validity are separate.** A correct PoC hash proves
   identity; only independent reproduction proves the bug.
7. Every finding is bounded by its `TargetContract`'s declared scope.

## The units (planes)

### ETZIO — kernel & master loop
Deterministic transition system. Validates the target contract, opens a mission, builds the
work graph, assigns leases, enforces budget and authorization, appends events, survives
interruption, and derives the next legal action. Units cannot write the ledger directly;
they submit proposals through typed commands.

Commands: `open_mission`, `authorize_scope`, `record_recon`, `record_hypotheses`,
`lease_investigation`, `record_candidate`, `build_poc`, `request_verification`,
`adjudicate_finding`, `triage`, `request_disclosure`, `record_null`, `close_mission`.

### SCIPIO — recon & attack-surface mapping
Maps the target: repository/protocol structure, entrypoints, trust boundaries, dependency
graph, and previously disclosed issues. Output is a structured attack surface, not prose.

### FABIUS — threat modeling & hypothesis generation
From the surface, predicts likely bug classes and emits a **ranked hypothesis list** (an
attack graph). Each hypothesis is a falsifiable statement with a suggested probe. This is
where domain expertise concentrates (e.g. for L1/DeFi: reentrancy, oracle manipulation,
signature replay, integer/precision, access control, consensus edge cases).

### VELITES — the finder swarm
The open-kritt insight, disciplined: decompose research into **small, well-defined tasks**
and run them in parallel across investigation agents (static reasoning + dynamic probing).
Each agent is blind to the others and returns candidates against a fixed schema. VELITES
*proposes*; it never confirms.

### MARCELLUS — exploit / PoC construction
Takes a promising candidate and builds a **compiling, reproducing proof-of-concept** inside
a hard-isolated sandbox (default-deny egress, no ambient credentials, scoped lease). A
candidate without a constructed PoC never reaches CATO as a finding — it stays a candidate
or becomes a null.

### CATO — independent verification & adjudication
A *different execution identity and isolation boundary* from whatever produced the PoC.
Re-runs the exploit from bytes in a clean environment; applies the evidence ladder
(schema/integrity → clean re-execution → adversarial critique, preferably a different model
family). Emits one verdict: `confirmed`, `not_reproduced`, `out_of_scope`, or `inconclusive`.
CATO is the only unit that can turn a candidate into a finding.

### CAMILLUS — dedup, ranking, triage
Normalizes confirmed findings to one schema, deduplicates across the swarm (same root cause,
different surface), and ranks by severity × exploitability × payout class. Produces the
ordered queue a human reviews.

### FABRICIUS — disclosure & report generation
Generates a bounty-grade report from the finding's retained evidence: summary, impact,
reproduction steps, PoC, suggested fix, and the program's required format. Disclosure itself
is a separate human-authorized effect (law 5) — FABRICIUS drafts; it does not submit.

### AQUILA — governance, authority, scope, safety
Spans every stage. Enforces the `TargetContract` (in-scope only), owns egress control and
budget, and holds the kill-switch. Any unit acting outside scope is refused at the kernel.

### MINERVA — grounded learning & memory
Observes every mission and records what worked: which hypotheses paid off on which target
class, which probes were dead ends, false-positive patterns CATO caught. Promotes strategy
changes **offline only**, through shadow evaluation against pinned targets and negative
fixtures. There is no direct production self-modification path.

## Mission lifecycle

```
open → authorize → recon → threat_model → investigate → construct → verify
     → adjudicate → triage → disclose(request) → learn → close
                 ↘ blocked / null are terminal-visible at any stage ↗
```

`null` and `blocked` are retained outcomes, not failures to hide. Interruptions resume from
persisted events with a generated handoff — never from conversational memory.

## Core objects

```
TargetContract      program, in-scope assets, permitted actions, disclosure channel, budget
Mission             one authorized hunt against one target revision
AttackSurface       entrypoints, trust boundaries, dependency graph  (SCIPIO)
Hypothesis          falsifiable bug-class claim + suggested probe + rank  (FABIUS)
InvestigationTask   one small, well-defined unit of the swarm's work  (VELITES)
Candidate           a proposed vulnerability, pre-verification  (VELITES / MARCELLUS)
PoCArtifact         content-addressed, reproducing proof; env digest  (MARCELLUS)
Verdict             confirmed | not_reproduced | out_of_scope | inconclusive  (CATO)
Finding             a CATO-confirmed candidate + all its evidence edges
NullResult          a retained "nothing here under hypothesis H"
Report              disclosure-grade package  (FABRICIUS)
AuthorityGrant      a scoped, expiring permission  (AQUILA)
StrategyLesson      a promoted-offline learning  (MINERVA)
```

Every `Finding` must be traversable to its target revision, triggering input, PoC artifact,
environment digest, verifier identity, and scope boundary. No traversal, no finding.

## Recommended implementation shape

Modular monolith (the kernel) plus isolated workers (the units), mirroring the discipline
that works elsewhere in the estate but sharing none of its code.

```
etzio/
  kernel/        state machine, event ledger, master loop, commands
  engines/       the ten units as typed ports + (initially) stub bodies
  contracts.py   TargetContract, Candidate, Verdict, Finding, NullResult
schemas/         JSON Schemas for the wire objects (finding, verdict, target-contract)
tests/           first-slice admission tests (the architecture must prove itself)
```

Leading reversible candidates (not frozen): Python runtime; content-addressed object store
for PoC artifacts; microVM/gVisor/Kata isolation for exploit execution; a durable queue for
the swarm; OpenTelemetry tracing `mission → stage → task → run`. Add nothing heavier until a
measured bottleneck or a security need demands it.

## First vertical slice (the architecture must prove itself before scale)

The slice is complete when Etzio can, against **one authorized benchmark target with a known
planted bug**:

- validate a `TargetContract` and refuse an out-of-scope action;
- open a mission and build a work graph under a budget;
- run SCIPIO → FABIUS → VELITES to produce at least one candidate;
- have MARCELLUS construct a reproducing PoC in isolation;
- have **CATO independently reproduce it** and emit `confirmed`;
- have CATO **reject a planted false-positive** as `not_reproduced`;
- record a `NullResult` for a hypothesis that found nothing;
- survive interruption and resume from the ledger;
- have FABRICIUS render a disclosure-grade report from retained evidence only.

Passing that slice tests the architecture. Adding more finder agents before it passes adds
complexity without establishing reliability — and reliability (a low false-positive rate) is
the entire product.
