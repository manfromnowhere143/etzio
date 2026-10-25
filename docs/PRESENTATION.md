# Etzio presentation standard

Status: standard, revised 2026-10-25.

Etzio should read like an engineering record an external team can inspect and reproduce.
Writing connects each claim to its mechanism, retained evidence and remaining assumptions.
The mission, current implementation and next experiment should be clear without requiring
the reader to reconstruct session history.

## Rules

1. Lead with the stable purpose and a concise statement of current capability. Put dated
   progress below that introduction. Identify implemented behavior and open gates before
   interpreting significance; preserve substantive explanations when reorganizing them.
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
8. Give each Mermaid diagram a clear purpose: architecture, mechanism, gate sequence or
   trust boundary. Preserve the full README architecture and its substantive relationships;
   an overview may supplement it but must not silently replace or move it. Explain any
   proposed removal or restructuring before editing. Use consistent typography, restrained
   semantic colors, labeled subsystem groups and deliberate routing. Label current fixture
   paths and proposed target structure explicitly; roles, boxes and keys do not imply
   separate processes. Status must remain legible without color. Add accessible titles and
   descriptions. Render and visually inspect every changed diagram before release, using
   GitHub-compatible Mermaid without external icons, fonts or layout plugins.
9. Reproduce sections carry literal, copy-pasteable commands and a plain statement that a
   passing suite validates repository bytes, not truth.
10. Corrections and retractions stay visible in the document they correct. Nulls receive the
    same structure as wins. Label historical snapshots and preserve their evidence links;
    keep one current continuation point and one unambiguous current code baseline.

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
- "The current fixture paths run within one trusted host process."
- "Independent execution remains an open acceptance gate."
- "Winning bounties is a future measured outcome, never present authority."

Do not decorate the work. Let the receipts carry the weight.
