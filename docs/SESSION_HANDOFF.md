# Etzio Session Handoff

Status: **canonical recovery entrypoint** for the Etzio engine. Last updated 2026-07-25,
Asia/Jerusalem. This is a handoff contract — not a confirmed vulnerability, not authority to
touch a live target, not permission to push a remote, and not proof of real-world detection
quality. Read this file before changing repository bytes.

Then read, in order: [README](../README.md) → [Charter](../CHARTER.md) →
[Architecture](ARCHITECTURE.md) → [Roadmap](ROADMAP.md). Revalidate every claim below from
repository bytes and the test suite. A chat summary, a model assertion, or a green check does
not authorize a later action.

**Precedence when records differ:** exact checked-out Git bytes → the test suite result →
this handoff → dated chat. A newer document does not silently overrule a committed decision.

---

## Mission soul

Etzio is an **autonomous vulnerability-research engine** for *authorized* security work
(bug-bounty scope, written permission, responsible disclosure, local benchmarks). Named for
the assassin — patient, precise, one clean strike.

The one idea that organizes everything: **a vulnerability is a scientific claim.** "This input
triggers this exploit" is a falsifiable hypothesis; a bounty submission is a published claim
with evidence. So Etzio is not a smarter scanner — it is a disciplined *evidence machine* that
generates candidates cheaply and spends its real effort **killing the false ones and proving
the true ones with a reproduced exploit.** Precision is the product.

Origin (2026-07-25): built after studying Kritt / "Blockian" (open-kritt), a team that earned
**$1.5M+ in bug-bounty payouts in blockchain L1 client code** (the Immunefi ecosystem) — not a
competition prize (that framing was conflated; DARPA AIxCC was won by Team Atlanta). The lesson
that shaped Etzio: the moat is the **target class + verification discipline**, not the
orchestrator. open-kritt's own shape is modest — decompose → parallel sandboxed agents →
compile a PoC → post-script verify → dedup/rank.

Long vision: a self-improving engine that finds real, exploitable bugs at a false-positive
rate low enough that a human reviewer and a bounty triage team trust its output. Immediate
mission: prove the architecture one measured vertical slice at a time before any live target.

Etzio learns the *patterns* of Odeya (its evidence-native kernel) and Maestro (its disciplined
master loop). **It imports none of their code and shares none of their infrastructure.** That
separation is a law, not a preference.

## Non-negotiable engineering laws

1. **Authorization before action.** Every hunt carries a `TargetContract`. Anything not in
   scope is out of scope by default; missing authorization fails closed. AQUILA enforces this
   at the kernel and holds the kill-switch.
2. **The generator never confirms its own claim.** The unit that proposes a candidate is never
   the unit that verifies it. CATO verifies in a separate identity and isolation boundary.
3. **Evidence before claim.** No finding exists without a reproduced PoC — a real artifact
   re-executed from bytes, never a model's self-reported confidence.
4. **Nulls and failures are first-class.** "No bug," "blocked," "not reproduced," and
   "inconclusive" are retained results with equal standing to a finding.
5. **Every external effect is separately governed.** Egress, paid compute, live-target actions,
   and disclosure each need an exact scoped grant. Exploit code runs only in hard isolation.
6. **Claims stay bounded.** Never write "state of the art," "solved," "production-ready," or
   "beats X" without a named scope, benchmark, date, and retained evidence. Measured numbers
   below are about *modeled benchmarks*, not the real world.
7. **Every gate has a known-bad proof that it fires.** A passing test on real intent, not
   passing prose. The false-positive corpus and the planted-FP fixture exist for this reason.
8. **Start with the smallest dependency-complete slice.** Add agents/complexity only when a
   measured bottleneck demands it.

## Current repository recovery identity

- Canonical workspace: `/Users/danielwahnich/workspace/etzio`
- Branch: `master`
- Predecessor `HEAD` this handoff descends from:
  `277a79994ad0305ce4e1873d4bf58cad4c1def0b` (tree `cb09a528fed8dfb3fcacc6c3aa4f91d450fa2ab8`)
- Canonical remote: **none** (local-only by decision)
- Remote creation, push, publication, deployment authority: **not granted**

This committed file cannot contain the hash of the commit that contains it. The active branch
`HEAD` is the subject to resolve; never copy a hash from chat. Run first:

```bash
cd /Users/danielwahnich/workspace/etzio
git status --short --branch
git log --oneline -6
git remote -v            # expected: empty
python3 -m pytest -q     # expected: all green
ruff check etzio tests   # expected: All checks passed!
```

## What each tranche established (with exact reproduce commands)

All numbers are for **modeled/benchmark targets** and prove *architecture and gate logic*, not
real-world detection quality. Three commits:

**1 · Foundation — `5c36904`**
Runnable ETZIO kernel: append-only hash-chained event ledger, mission state machine, master
loop enforcing the laws in code. Ten-unit roster (ETZIO, SCIPIO, FABIUS, VELITES, MARCELLUS,
CATO, CAMILLUS, FABRICIUS, AQUILA, MINERVA) as typed ports with deterministic stub bodies.
- Reproduce: `python3 -m etzio.cli` → 1 confirmed finding, 1 rejected planted false positive,
  2 first-class nulls, ledger chain intact, out-of-scope fails closed.

**2 · CATO gate + false-positive harness — `09965f9`**
CATO is a two-part gate: a candidate becomes a finding only if re-execution both matches the
producer's claim AND produces a materially impactful effect. Labeled benchmark corpus + FPR
harness scoring CATO against hidden ground truth.
- Reproduce: `python3 -m etzio.harness.fpr` → on the corpus: **precision 1.000, FPR 0.000,
  recall 0.750** (the broken-PoC case is an honest miss, never a false alarm). Bar: FP == 0.

**3 · SCIPIO + VELITES real static analysis — `277a799`**
Real `ast`-based Python analyzer (no dependencies). SCIPIO maps attack surface (files,
entrypoints, imports); VELITES detects seven vulnerability classes (code/command injection,
unsafe deserialization, SQL injection, weak crypto, hardcoded secrets) at exact file:line.
- Reproduce: `python3 -m etzio.scan` (7/7 planted bugs), `python3 -m etzio.scan etzio/fixtures_code/clean_app.py`
  (0 findings), `python3 -m etzio.scan --self` (only the intentional fixture; 0 in real source).
- A static hit is an **execution-pending candidate** with no PoC → CATO returns `inconclusive`.
  It is never auto-confirmed. A test pins exactly this.

State of the suite at `277a799`: **15 tests green, ruff clean, zero warnings.**

## Current hard boundary

- **No live target.** Only local benchmark/fixture targets until Phase 2 passes on a real
  benchmark with a known bug (see Roadmap).
- **No PoC *execution* yet.** MARCELLUS builds and CATO reproduces PoCs only in hard isolation
  (microVM/gVisor/Kata) — which needs **Linux + KVM**. This machine is macOS (XNU); the real
  execution tier does not exist here. Do not run untrusted exploit code on the host.
- **No remote, no disclosure, no spend.** Disclosure is a separate human-authorized effect.

## Two genuine blockers (credentials do not fix either)

1. **A Linux+KVM host** for real exploit isolation. An OS fact, not a permission.
2. **A real authorized program** (e.g. an Immunefi researcher identity + accepted scope). A
   human/legal enrolment step, not a key that can be handed over.

## Next mission, in dependency order

1. **MARCELLUS + real CATO execution** — build a compiling PoC in isolation and reproduce it
   from bytes. *Requires the Linux/KVM host.* This is the "analyze → prove" crossing.
2. **FABIUS real hypothesis library** (macOS-ok) — a domain library for the target class
   (default: blockchain/DeFi — reentrancy, oracle manipulation, signature replay, precision,
   access control), ranking hypotheses against the SCIPIO surface.
3. **SCIPIO Solidity surface-mapper** (macOS-ok) — extend recon to Solidity, the high-payout
   domain, if the target-class decision confirms blockchain.
4. **CAMILLUS dedup/rank + FABRICIUS disclosure draft** on real candidates.
5. **MINERVA grounded learning** — record which hypotheses pay off per target class; offline
   promotion only, no production self-modification.

The governing metric throughout: **false-positive rate on a benchmark.** No slice ships
without an FPR number. Miss before you cry wolf.

## Open decisions (Daniel's call)

- **Target class** — proceeding on default **benchmark-first, aimed at blockchain/Immunefi**
  (biggest payouts, hardest domain). Redirect to web/SaaS or OSS reshapes SCIPIO + FABIUS.
- **Remote repo** — stay local (current) or create a **private** GitHub repo (then SHA-pin CI
  before push, per estate standard).
- **Linux host** — cloud VM (needs cloud creds + a few $/day) vs. wait, gating mission item 1.

## Definition of a proper continuation handoff

Before ending a future session:

1. inspect the complete diff; stage only the declared scope;
2. run `ruff check etzio tests && python3 -m pytest -q` — both must pass before and after;
3. create a scoped local commit with an intentional message (no Co-Authored-By trailer;
   Daniel's authorship alone);
4. record branch, commit, tree, checks, open blockers, and absence of remote authority;
5. **update this file and `docs/MISSION_STATE.json`** when mission state or decisions change;
6. leave every unsupported claim and incomplete item explicit — bounded, dated, scoped.

The standard is not that the next session feels confident. The standard is that it can recover
identity, reproduce every number, see every boundary, and know the next safe action without
trusting the previous session's memory.
