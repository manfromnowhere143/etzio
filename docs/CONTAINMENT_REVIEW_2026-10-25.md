# Containment review packet

Status: **review preparation; independent reviewer and execution unassigned**.
Date: 2026-10-25. No target-execution acceptance is recorded here.

## Review scope and evidence

Review the fixed owned Linux/KVM preparation experiments as a potential basis
for one supervised local reproduction under [ADR-0025](decisions/0025-parallel-supervised-bounty-research.md).
This packet does not admit the production MARCELLUS/CATO profile.

| Experiment | Current evidence | Meaning |
| --- | --- | --- |
| Fixed guest readiness, wrong output, CPU spin and output limit | [Owned Firecracker preflight](OWNED_FIRECRACKER_PREFLIGHT.md) | Real owned guests under the pinned jailer and VMM |
| Real collector SIGKILL and withheld-watchdog control | [Collector-death preflight](OWNED_COLLECTOR_DEATH_PREFLIGHT.md) | Primary cleanup and calibrated outer cleanup measured separately |
| Memory and task exhaustion | [Resource preflight](OWNED_RESOURCE_PREFLIGHT.md) | Four owned controls passed, exact OOM attribution and process cleanup retained |
| File, signal and abstract-socket separation | [Cross-worker contract](OWNED_CROSS_WORKER_PREFLIGHT.md) | Bidirectional owned controls passed; exact observations and all cleanup retained |

Resolve exact candidate, full-suite and publication identities from
`artifacts/checkpoints/2026-10-25-resource-containment/release-validation.json`
when that record exists. Private provisioning records, immutable source copies,
build products, source ledgers, serial observations and all failed attempts are
under `artifacts/resource-containment-20261025/`. Controllers are spent one-attempt
records, not a reusable dispatch command. Preserve the earlier frozen releases.

The new memory fixtures reproduce across three builds and a final-generator
readback. Portable controls exercise false outcomes; they do not substitute for
the host observations. Review both the acceptance predicates and collection
mechanism, including what could prevent a failing value from being retained.

## Independent reproduction obligations

The reviewer must identify the actual person or independently operated verifier,
its administration and the separate execution environment. Another model's
agreement, a second role label or re-reading this session's output is insufficient.
Record the reviewed commit, exact input hashes, allowed actions, hard limits,
fixture effects, contrary controls, cleanup results, objections and disposition.

Before a separate run, prepare a new exact resource manifest on the reviewer's
authorized disposable environment. Verify host/image/KVM and pinned artifacts,
remove staging egress, attach no service account, preserve unrelated workloads,
and retain all resource identities and deletion evidence. Never rerun a spent
controller or reuse a former attempt's completion record as new evidence.

Review these limits explicitly:

- Root observation and watchdogs in these experiments share one administration.
  They are not independent CATO execution or protection from a malicious host.
- Memory and task effects have bounded observations on the selected profile;
  they do not qualify physical storage quotas, power loss or production recovery.
- Host probes joining a VMM namespace do not inherit its seccomp filter. Their
  actual filter state, credentials and namespace bindings must be retained.
- Abstract Unix socket separation is one network namespace measurement. It does
  not establish TCP/IP reachability or absence of a VMM/KVM/kernel escape.
- Source visibility, an owned-fixture pass and a public reward ceiling do not
  authorize a target, demonstrate a new vulnerability or establish payment.

## Exact target follow-through

After review and explicit profile acceptance, retain a separate reproduction
contract naming one candidate, exact eligible target/revision, current program
terms, actor, allowed local actions, input bytes, effect oracle, negative controls,
resource limits and cleanup. Pin compiler/dependency identities before executing
any target build system. Bind a separate verifier and its execution to the same
inputs. Submission and disclosure retain their separate scoped authorization.

The retained CoW source reviews currently have **no demonstrated report candidate**.
Their source revision is `6ebbd810ff2da635fb6f88e9a15fde196f8c852a`; current deployed
byte/compiler identity, personal eligibility and duplicate clearance remain
unverified. The zero-quantity fee behavior is an official known issue and cannot
be recycled as a new finding. Preserve these dispositions and the other session's
separate Immutable work. Do not invent a candidate to fill a reproduction form.

Reviewer identity, independent execution, accepted disposition, exact target
admission, report submission, accepted bounty and payment are all pending or absent.
