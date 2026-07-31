# Etzio presentation standard

Status: standard, 2026-08-01.

Etzio should read like a record a hostile reviewer can audit. The engine's whole thesis is
that a claim is worth nothing until it is reproduced from retained bytes; the writing must
hold itself to the same bar. Presentation is not decoration here — it is part of the
evidence.

## Rules

1. Lead with status before interpretation. The first thing a reader meets is what is *not*
   established, not what is impressive.
2. Keep `implemented`, `modeled`, `proposed`, and `blocked` exactly distinct, and never
   collapse `missing`, `blocked`, `inconclusive`, `not_reproduced`, or `null` into success,
   zero, or silence.
3. A candidate is not a finding. A digest proves byte identity, not authorship, chronology,
   independence, truth, or a security effect. A green check is evidence about this
   repository snapshot, never a finding, provider, or superiority claim.
4. Prefer exact nouns over promotional adjectives. State a limit with a mechanism, not a
   soft qualifier.
5. Put the boundary, the comparator, and the known-bad next to the claim they govern.
6. Every consequential gate names a known-bad that proves it refuses. A happy-path
   demonstration is not evidence that a gate exists.
7. Quote numbers exactly, with denominators attached, as backticked literals — `1158`
   tests, `7` candidates, `36` reference proofs — never a rounded or marketing figure.
8. Use Mermaid diagrams only to clarify a mechanism, gate, or boundary, and keep them small
   enough to render on a phone. Label every architecture diagram as intended structure, not
   a runtime screenshot.
9. Reproduce sections carry literal, copy-pasteable commands and a plain statement that a
   passing suite validates repository bytes, not truth.
10. Corrections and retractions stay visible in the document they correct. Nulls receive the
    same structure as wins.

## The words we do not use

"State of the art", "safe", "solved", "autonomous", "production-ready", "revolutionary",
"seamless", and "powerful" require a named benchmark, comparator, scope, date, and retained
evidence, or they do not appear. There are no badges, no emoji, no feature-bullet spam, and
no hype opener. The structure is bespoke to the engine's epistemics, not a generic
README skeleton.

## Voice

The voice is direct, calm, and confident about the design while relentlessly honest about
the status. It is impersonal by default — the subject is Etzio, the kernel, a candidate, an
event — and it varies sentence length on purpose: a long, exact enumeration followed by a
short verdict. Confidence and humility are not in tension here; the confidence is in the
discipline, and the humility is about the result.

- "A candidate is a falsifiable claim about exact target bytes."
- "The generator cannot verify its own claim."
- "Nothing jumps the chain."
- "This is the courtroom, not yet the detective."
- "Winning bounties is a future measured outcome, never present authority."

Do not decorate the work. Let the receipts carry the weight.
