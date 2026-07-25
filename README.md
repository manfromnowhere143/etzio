# Etzio

**Etzio is an autonomous vulnerability-research engine.** It turns an *authorized* target
into a governed, replayable chain: target → hypothesis → exploit → **independent
verification** → a disclosure-grade finding.

> **Status — 2026-07-25: foundation only.** This repository contains the architecture,
> the operating laws, the core contracts, and a runnable kernel skeleton. No live
> targets, no results, and no autonomous discovery capability are claimed yet. Real
> capability is built one verified vertical slice at a time. Nothing jumps the chain.

Etzio is named for the assassin — patient, precise, one clean strike. Its sub-engines
carry the names of Rome's warriors and censors. Each owns one stage of the hunt.

## The one idea

**A vulnerability is a scientific claim.** "This input triggers this exploit" is a
falsifiable hypothesis. A bounty submission is a *published claim with evidence*.
So the engine that finds bugs well is not a smarter scanner — it is a disciplined
**evidence machine**: it generates candidates cheaply, then spends its real effort
*killing the false ones* and *proving the true ones* with a reproducing exploit.

That discipline is the whole moat. The orchestration is a few days of work; the
verification gate is the thing worth building well.

## The chain

```
Target contract  →  Recon  →  Threat model  →  Investigation swarm  →  Exploit / PoC
                                                                            │
        Finding  ←  Disclosure  ←  Triage / rank  ←  Independent verify  ←──┘
```

The unit that *finds* a candidate is never the unit that *confirms* it. A finding is
not real until an independent verifier reproduces the exploit in clean isolation.

## The roster

| Unit | Role | Namesake |
|---|---|---|
| **ETZIO** | Motherboard: kernel, master loop, mission state, authority, budget, next legal action | Ezio — the assassin |
| **SCIPIO** | Recon & attack-surface mapping (repo/protocol map, entrypoints, dependency graph) | Scipio Africanus — the strategist who studied Hannibal |
| **FABIUS** | Threat modeling & hypothesis generation (bug-class prediction, ranked attack graph) | Fabius Maximus — the anticipator |
| **VELITES** | The finder swarm: decomposed, parallel investigation agents (static + dynamic) | Velites — the skirmishers who probe the line |
| **MARCELLUS** | Exploit / PoC construction in hard isolation (a *compiling, reproducing* proof) | Marcellus — the Sword of Rome, breaker of walls |
| **CATO** | Independent verification & adjudication (re-run the PoC; kill false positives; verdict) | Cato the Censor — the incorruptible |
| **CAMILLUS** | Dedup, ranking, triage (one finding schema, severity, cross-swarm dedup) | Camillus — the reformer who reordered Rome |
| **FABRICIUS** | Disclosure & report generation (bounty-grade, responsible packaging) | Fabricius — the envoy who could not be bribed |
| **AQUILA** | Governance: scope & authority enforcement, egress control, budget, kill-switch | Aquila — the legion's sacred standard |
| **MINERVA** | Grounded learning & memory (what worked, transfer across targets; no self-modify) | Minerva — wisdom and strategy |

## The laws

1. **Authorization before action.** Etzio touches a target only under an explicit,
   in-scope authorization (bug-bounty scope or written permission). Out of scope fails closed.
2. **Generator never confirms itself.** The unit that proposes a finding never issues its
   terminal verdict. Verification is a separate identity and isolation boundary.
3. **Evidence before claim.** No finding exists without a reproducing artifact — a PoC that
   an independent verifier re-runs from bytes, not a model asserting confidence.
4. **Nulls are first-class.** "No bug found," "blocked," "could not reproduce," and
   "inconclusive" are real, retained results — never silently dropped.
5. **Every external effect is governed.** Disclosure, network egress, paid compute, and any
   action against a live target require exact scoped authority and a kill-switch.

## Independence

Etzio is independent from Odeya and from Aweb/Maestro in runtime, storage, namespace, and
control. It *learns their patterns* — Odeya's evidence-native kernel, Maestro's disciplined
master loop — and **imports none of their code.** That separation is a law, not a preference.

## Read next

- **[Session handoff](docs/SESSION_HANDOFF.md) — the canonical recovery entrypoint. A new
  session reads this FIRST.** Machine state: [docs/MISSION_STATE.json](docs/MISSION_STATE.json).
- [Charter](CHARTER.md) — the operating laws in full
- [Architecture](docs/ARCHITECTURE.md) — planes, the roster, the pipeline, isolation tiers
- [Roadmap](docs/ROADMAP.md) — build-while-running, slice by slice
