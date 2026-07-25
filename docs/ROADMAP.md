# Etzio Roadmap — build while running

The strategy is not "build the whole engine, then hunt." It is "build the smallest honest
slice, run it against a benchmark, measure the false-positive rate, then widen." Every stage
below ends with a *measured* number, not a feeling.

## The one metric that governs everything

**False-positive rate (FPR)** — the fraction of candidates CATO confirms that a human then
rejects. A vuln engine with high recall and high FPR is worthless: it drowns the reviewer and
burns bounty-program goodwill. Etzio optimizes precision first, recall second. No slice ships
without an FPR number on a benchmark.

## Phase 0 — Foundation (this repository, now)
- Charter, architecture, roster, laws. **Done.**
- Core contracts + JSON schemas (`TargetContract`, `Candidate`, `Verdict`, `Finding`). **Done (skeleton).**
- Runnable kernel skeleton: event ledger, state machine, master loop, engine ports. **Done (skeleton).**
- First-slice admission test that runs the chain end-to-end on a *fake* target. **Done (skeleton).**

## Phase 1 — The verification gate first (CATO before VELITES)
Counter-intuitive and correct: build the *judge* before the *finders*. If CATO can't
reproduce a PoC in clean isolation and reject a planted false positive, no amount of finding
matters.
- Real isolation tier (microVM/gVisor/Kata) with default-deny egress.
- CATO re-executes a supplied PoC from bytes; emits `confirmed` / `not_reproduced`.
- Negative-fixture suite: planted false positives CATO **must** reject. This is the FPR harness.

## Phase 2 — One benchmark target, full chain
- Pick a target class (decision pending — see below) and one benchmark with a *known* bug.
- SCIPIO maps it; FABIUS emits ranked hypotheses; a single VELITES agent finds the candidate;
  MARCELLUS builds the PoC; CATO confirms; FABRICIUS drafts the report.
- Ship the first-slice admission criteria from `ARCHITECTURE.md`. Record FPR on the negatives.

## Phase 3 — The swarm (VELITES scale) + CAMILLUS
- Decompose into parallel investigation tasks; run the swarm; CAMILLUS dedups + ranks.
- Measure: candidates/hour, confirmed/candidates, FPR. Widen only if FPR stays low.

## Phase 4 — MINERVA (learning) + real programs
- Grounded learning: which hypotheses pay off on which target class; offline promotion only.
- Move from benchmarks to a real authorized program, human-in-the-loop on every submission.

## Open decisions (Daniel's call)

1. **Target class.** Blockchain/Immunefi (where the $1.5M actually came from — biggest
   payouts, hardest domain), web/SaaS (easy start, small payouts), OSS responsible
   disclosure (track record, little money), or benchmark-only first. The answer reshapes
   SCIPIO and FABIUS most. My recommendation: **benchmark-first, aimed at blockchain**, so
   FABIUS's hypothesis library is built for the high-payout domain from day one.
2. **Isolation vendor** for Phase 1 (gVisor vs Kata vs Firecracker microVM).
3. **Whether to commit this foundation now** or iterate the docs first.

## What we will not do
- No live target before Phase 2's benchmark passes.
- No disclosure without human authorization.
- No coupling to Odeya or Aweb code.
- No FPR-free slice shipped as "working."
