# Diagram history and restoration

Reviewed 2026-10-25. This is a documentation correction; it changes no runtime,
authority, provider, isolation profile or research outcome.

The richer README diagrams did exist. Their later simplification is visible in Git:

| Revision | What changed | Retained evidence |
|---|---|---|
| [August 1 · `caa2ddd`](https://github.com/manfromnowhere143/etzio/commit/caa2ddd44d4570a3f4c54ac62d15f80532ea67d4) | The README contained two detailed diagrams, with four and three subsystem groups respectively. | Historical README Mermaid source. Some labels describe older implementation states and must not be restored verbatim. |
| [October 15 · `00083c2`](https://github.com/manfromnowhere143/etzio/commit/00083c29614c142d2d13c0ded6a307a03dfa564b) | Two large diagrams became four: a gate map, detailed composition, shorter finality flow and separate recovery flow. The large finality diagram lost its qualification groups; related concepts remained in the composition and prose. | [Documentation handoff](evidence/documentation-handoff-2026-10-15.json) records a documentation projection, not a runtime change. It does not establish a specific instruction to simplify the diagrams. |
| [October 16 · `827f570`](https://github.com/manfromnowhere143/etzio/commit/827f5707ef9a3372d6cbfb9c3dcd48871b4caf4e) | The detailed README composition was replaced by a compact overview. The full composition moved to Architecture. | The moved Mermaid source is identical after excluding the two new accessibility metadata lines. The [review record](evidence/reviewer-readiness-2026-10-16.json) explicitly records “Compact README diagram with detailed composition preserved in Architecture.” Presentation rule 8 then favored a compact overview linking to detail. |

The recorded rationale was readability and reviewer orientation. The visible front page
nevertheless lost architectural depth. Git identifies the commits and content changes;
the configured human authorship does not identify which assistant session proposed them
or establish the operator's approval of that presentation choice.

## October 25 correction

At the operator's direction, the README again includes the full **current** fixture
composition: authority, candidate admission, modeled verification, both storage profiles
and signed-fixture qualification. Its source matches the detailed Architecture diagram.
The separate finality and recovery diagrams retain their mechanisms and limits.

All `10` Mermaid blocks across README, Architecture, Frontier Baseline and Catalog Recovery
receive a shared visual language: consistent typography, labeled subsystem boundaries,
restrained colors, explicit statuses and accessible titles/descriptions. The meaning of
each relationship remains in the source and surrounding prose. Group boundaries denote
responsibilities or workflow stages; they do not claim process or administrator isolation.
Proposed experiment flows remain proposed even where a solid arrow expresses their order.

Nisayon was inspected read-only at public revision
[`9bc2afa`](https://github.com/manfromnowhere143/nisayon/tree/9bc2afa18cb88069825af137b2782de7e84ebe59).
Its three README diagrams use ordinary Mermaid, with grouping and concise labels providing
most of the hierarchy. No special renderer or custom theme was present in those sources.
This comparison informed presentation only; no sibling files, refs or runtime were changed.

The [presentation standard](PRESENTATION.md) now explicitly preserves substantive README
diagram detail and requires explaining future removals or restructuring before editing.
The design uses supported flowcharts, frontmatter configuration and inline styles, without
remote assets or optional layout engines. A rendered diagram is presentation evidence,
not evidence of an operating system, a discovered vulnerability or a bounty.
