# Etzio mission assessment and next decision

Status: evidence review and completed provider-feasibility research, 2026-10-12.
Baseline: `0c060602dc2cbcb3e5025802b926065bb80f3cd3`, published in
[PR #46](https://github.com/manfromnowhere143/etzio/pull/46).
No native profile, roadmap exception, target, execution or disclosure is admitted here.

The subsequent [catalog operating decision](CATALOG_RECOVERY_DECISION.md) completes the
bounded feasibility continuation below. It specifies the recovery cut, writer fencing,
data custody and concrete operator inquiry. No complete roster or operator commitment was
found in the reviewed record; native integration awaits that operating decision.

## Engineering verdict

Etzio has a substantial, tested foundation for authorization, evidence retention and
fixture recovery. It has not demonstrated competitive vulnerability discovery or economic
value. Calling the system state of the art would currently exceed the evidence. Its
architecture supports the enterprise mission; its present execution surface cannot deliver
that mission yet.

| Question | Demonstrated | Missing measure |
| --- | --- | --- |
| Does the foundation enforce useful invariants? | Published release: `2504` tests pass on both supported runtimes locally and in exact-head CI; packaged replay is retained. The latest repair closes an observed pre-commit recovery defect. | Independent security audit; actual provider, device and operational behavior. Test count is not reliability or discovery performance. |
| Can the engine discover useful vulnerabilities? | Six Python rule classes, `7` planted candidates on one vulnerable fixture and `0` on one clean fixture. | Real-target coverage, unique validated causes, false reports and matched-budget comparators. These are unmeasured, not zero-valued scores. |
| Can CATO independently establish an effect? | Signed modeled receipts and typed byte bindings; the old CATO demo calls an owned model in the host process. | Separately administered, isolated execution and an independent effect oracle. Neither identity labels nor receipt signatures supply this. |
| Is there external acceptance or income? | No retained accepted external finding or settled payment. | Exact eligibility, independent reproduction, external triage and actual receipts. LinkedIn connections establish none of these. |

The review checked release identities, all `43` files in the prior release index, the
fixture CLI and analyzer, modeled verification declarations, head-provider roster and
freshness logic, and the governing contracts. It is a sampled review, not a complete
repository audit. [The evidence ledger](evidence/mission-assessment-2026-10-12.json)
records coverage and source identities. The unchanged baseline is revalidated separately
from the eventual documentation release.

Keep the target-neutral kernel, independent verification requirement and versioned domain
packs. EVM remains the first proposed domain, with native code, web/API, cloud, mobile,
protocols and supply-chain assurance still part of the long horizon. Do not add breadth,
agent roles or an optimizer without a measured dependency. The important gap is now between
internal conformance and externally useful execution, not between the current test count
and a larger one.

## Research that changes the next evaluation

[ReproBench v1](https://arxiv.org/html/2609.34450v1), He et al., 2026-09-28,
reports simulation substitution in `204/450` IoT reproduction runs. Its `8/150` near-full
trigger results are CVE–model pairs under best-of-three scoring, not `8/450` independent
discoveries. The scorer is an LLM; the study uses one harness and describes several tools
as “latest,” limiting exact replay. This is a preprint, not an Etzio result. Require
target provenance through acquisition, build and observed execution. An owned
reimplementation must never substitute for the admitted target when reporting success.
Keep preparation cost in the denominator. Review covered methods, results and limitations;
the benchmark was not executed.

[VLoc Bench v1](https://arxiv.org/html/2609.15939v1), Priyanshu et al., 2026-09-14,
separates repository-scale localization from behavior after remediation across `500` tasks.
Its patch-derived file labels are a proxy: a fixed recorded defect does not make an entire
repository clean. Phase B also credits no-submission outcomes, including exhausted runs,
as true negatives. Etzio should retain explicit clean judgments, unfinished work, refusals
and unsupported findings separately. Use localization as an intermediate measure, not a
finding oracle. This preprint's methods, results and limitations were reviewed; its
released code and task data were not audited or run.

[Anthropic's OSS Scanner announcement](https://www.anthropic.com/research/launching-opt-in-vuln-finding-service-for-open-source),
2026-10-08, describes free opt-in scanning and a reviewed subset of generated reports.
That is competitive pressure on generic scanning, not proof that Etzio cannot compete.
The product hypothesis to test remains lower independent-review effort and useful repairs
from replayable evidence. Customer demand remains unmeasured.

Before a later comparison, freeze exact tasks, information, model/tool versions, budgets
and independent oracles. Count target-level root causes, retain every attempt and its full
cost, and test preserved legitimate behavior alongside security effects. Split development
and held-out targets before tuning. The earlier
[effect-evidence experiment](EFFECT_EVIDENCE_EXPERIMENT.md) already establishes why a single
disappearing effect cannot prove a complete repair; repeating it would add no capability.

## Completed continuation: can public witnesses close the native gate?

The finite question was whether published operator evidence identifies a ready complete
roster for Etzio's next native lifecycle. **It does not.** This is a documented integration
gap, not a vulnerability in the services or proof that a suitable provider cannot exist.
Only public documents and repository metadata were fetched; no checkpoint was submitted,
log registered, provider enrolled or operator contacted.

The [Witness Network directory](https://witness-network.org/witness-tables/) currently has
no production entries and lists four staging operators. That fact is limited to this
directory: stable services exist elsewhere. The operators' own statements matter more than
a service label:

| Candidate | Published operating boundary | Etzio disposition |
| --- | --- | --- |
| [Geomys Navigli](https://geomys.org/witness/navigli) | Development Sunlight, staging, non-paging monitoring; shares a machine with its production CT logs. | Documentary candidate for bounded interoperability; production custody and recovery not established. |
| [Mullvad Stagemole](https://witness.stagemole.eu/about) | Test service explicitly permits state rollback. | Cannot assume retained history survives operator rollback. |
| [Google TrustFabric](https://transparency.dev/witnesses/) | Dev may reset or rotate without notice; staging uses regional Spanner and non-paging monitoring. | Separate dev/staging terms; Google Cloud availability does not establish independence from Etzio's own possible cloud dependencies. |
| [IPng](https://ipng.ch/s/ct/#witness) | Testing/staging witnesses; production under construction; best-effort operations. | Future candidate; advertised support horizon is not completed production qualification. |

Sigsum's `sigsum-generic-2025-1` is a concrete stable-service lead: two log keys and three
witness keys with a `2-of-3` rule. The pinned builtin directory at
`c924c03da54eabb6e5add0b9ee3d63183b3dfc41` contains this generic policy and three test policies.
Its publisher explicitly records that the three witness companies share a parent in the
[named-policy explanation](https://www.glasklarteknik.se/post/named-policies-for-sigsum/).
This establishes a disclosed dependency, not shared administrator credentials or collusion.
It is insufficient evidence for Etzio to assume independently controlled failure domains.
Etzio's all-required roster is unchanged; importing the `2-of-3` rule is not authorized.

An offline comparison using the existing key inspector confirms that all `3/3` published
witness vkeys encode the keys in the pinned policy. The compared documents are retained;
Glasklar and Tillitis also match exact repository revisions. This resolves a documentary
key-mapping question only. No current signature or external administration was verified.

[Glasklar's operating document](https://git.glasklar.is/glasklar/services/witnessing/-/blob/e5528ff896c31100887337f423ba7fd615f1d926/witness.glasklar.is/about.md)
identifies funding by Mullvad and its own staff access.
[Mullvad's stable witness](https://witness.mullvad.net/about) describes hardware key custody
and operator onboarding; [Tillitis](https://github.com/tillitis/tillitis.se-tillitis-witness-1/blob/b85b49ee0a1df4ec375a7f2898e8bc631c6fd818/about.md)
describes TKey custody and Amagicom funding. These are operator declarations, not independent
audits. The [policy-maintenance procedure](https://git.glasklar.is/sigsum/project/documentation/-/blob/main/policy-maintenance.md)
explicitly leaves revocation and obsolete-policy communication outside its scope.

## Exact obligations before integration

| Etzio obligation | Evidence available | Still required |
| --- | --- | --- |
| Two distinct anchors | [Seasalp](https://git.glasklar.is/glasklar/services/sigsum-logs/-/blob/main/instances/seasalp.md) and [Ginkgo](https://ginkgo.tlog.mullvad.net/about) publish identities and operating documents; both advertise `288` entries/day per domain suffix. | Exact accepted leaf semantics, submission authority, complete inclusion/consistency evidence, custody and capacity at Etzio's event rate. Shared dependencies remain explicit. |
| One catalog plus at least two required monitors | Native checkpoint/cosignature formats and operator descriptions. | A named catalog operator and exact Etzio global/mission-head projection; all required monitors must cover that catalog. No such complete deployed roster is retained. |
| Fresh latest head after local loss | Append-only witnessing is a useful building block. | Independent bootstrap custody and fresh, scope-bound recovery. A recently cosigned unchanged tree or a valid historical proof cannot alone establish the latest Etzio head. |
| Time and revocation | Offline native inspections and conditional elapsed-time mathematics. | Complete admitted time and revocation sources, qualified consumption bounds, current floors and rotation/revocation behavior. Ordinary NTP configuration is not a measured UTC error bound. |

**Chosen next milestone:** resolve the catalog operator, complete source roster and custody
obligations before writing another native adapter. Prepare one exact deployment/administration
dossier with responsible operators, signing and recovery access, shared ownership/hosting/
software/clock dependencies, key rotation, data retention, scope, rate limits and costs.
No production deployment is selected by this review. An outreach or deployment request
must name the concrete operator, origin/key, actions and resources; there is no generic
permission question to answer here.

First carry the complete admitted native dossier through all four lifecycle phases,
including cold replay and refusal controls, without releasing the governed barrier on
failure. The subsequent local-loss experiment remains
`H0 → H1 → loss of local DB/cache/staging → recovery`: require `H1` or a retained block.
Reject coherent `H0` restore, stale cosignatures, missing required monitor, conflicting
head, revoked key and changed clock epoch. A public-key match, staging availability or
successful TSA response cannot pass these criteria.

Bound the next feasibility pass to one proposed engineer-day on these named missing
obligations. If no viable complete roster emerges, return a concrete architecture/scope
decision with alternatives and residual risks. Do not indefinitely substitute optional
codecs or fixture demonstrations for the external dependency. This is an effort stop rule,
not a promise that an operator will respond or that native qualification takes one day.

## Paid work and the preserved mission

| Route | Decision today | What changes the decision |
| --- | --- | --- |
| Customer-paid reproduction/remediation | Conditional fastest path to contracted value; no buyer, price or accountable external reviewer is retained. | A written paid deliverable, exact scope, reviewer and accepted isolated environment. An early lane still needs a scoped roadmap exception. |
| Selective audit engagement | Conditional opportunity; no invitation or operative engagement supplied. | Verified access and exact terms, followed by the same authority, containment and reproduction obligations. |
| Etzio EVM bounty campaign | First prepared public dossier remains CoW; execution blocked. | Foundation, isolation and benchmark gates plus exact deployed source/state and target admission. |
| Enterprise product | Preserve the evidence/reproduction/repair thesis. | Measured reviewer savings, accepted repairs, integration needs and purchasing evidence. |

The refreshed [CoW information brief](https://immunefi.com/bug-bounty/cowprotocol/information/)
still requires impact evidence, a reproducer/failing case and KYC. Contract testing is
restricted to local forks; eligibility and payout are not automatic. Public documentation
does not admit a campaign. The completed [source dossier](COW_SOURCE_DOSSIER.md) remains
useful, but source/deployment provenance, private-duplicate uncertainty and the engine gates
remain unresolved. There is no defensible bounty date or expected revenue yet.

```text
complete admitted native lifecycle → external latest-head recovery
  → qualified protected storage → isolated independent execution
  → matched EVM evaluation → exact target admission
  → independently reproduced eligible report → approved submission
  → external acceptance → settled payment
```

Public-source research and preparation proceed alongside this chain. A separately approved
human-assisted engagement could accelerate learning and income while preserving the
enterprise path, but this assessment does not enact that exception. No concrete engagement
was present in the reviewed record. The prepared FreeTSA diagnostic remains unaccepted;
its original spent journal is preserved and no new journal or dispatch was created.
