# Owned resource-exhaustion experiment

Status: **four owned host controls passed; no target profile admitted**, 2026-10-25.

The second disposable-host attempt passed all four effects and cleanup controls.
The first attempt stopped at an invalid combination of `dmesg` options; retain it
as a failure. The corrected host reproduced that CLI error before guest startup
and successfully read the kernel log with `--raw` alone. Both attempts' twelve
cloud resource identities are verified absent. Exact observations and controllers
are retained privately at `artifacts/resource-containment-20261025/`.

The small allocation completed with a `141344768`-byte observed cgroup peak and
no OOM. The large allocation reached `268435456` bytes and produced exactly one
local OOM kill, attributed by the kernel to the bound VMM and cgroup. The VMM
exited with SIGKILL and its helper exited before supervisor cleanup. The host
task controls observed five tasks in the positive case and sixteen in the
negative case; the latter returned Linux `EAGAIN` after fifteen children, with
one task-limit event and no OOM. All owned userspace processes were reaped.

This finite experiment extends the owned Firecracker and collector-death controls.
It uses the existing disposable Linux/KVM preparation grant. It admits no target
or arbitrary-code execution profile. Sources, fixture bytes, image, budgets and
one-attempt resource identities must be retained before dispatch.

## Memory controls

Two new fixed assembly init programs use a separately checked `512` MiB, one-vCPU
guest configuration. Both announce readiness, wait five seconds for host binding,
then map and write one byte per `4096`-byte page. The positive program touches
`64` MiB and announces completion; the negative program attempts `384` MiB.
Each VMM has a fresh `256` MiB memory cgroup, zero swap, `32` tasks and the existing
`20000/100000` CPU quota. The earlier `128` MiB runtime barrier remains unchanged.

Before pressure, bind the VMM and its kernel helper with pidfds and start times;
check every VMM thread's identity, credentials, seccomp and NoNewPrivs; retain
exact cgroup membership, limits and event baselines. Readiness must precede the
pressure result. The positive control requires its completion marker, a live VMM
and no OOM events. It is then deliberately stopped.

The negative control requires local `max`, `oom` and `oom_kill` event increases,
the exact VMM's SIGKILL termination before supervisor cleanup, helper exit and
an empty cgroup. A retained new kernel OOM summary must name `CONSTRAINT_MEMCG`,
that exact cgroup and that VMM PID. Unknown victims, missing records, log rollover,
unexpected host pressure, deadlines or fallback cleanup refuse acceptance.
Observed peak memory must remain within the separately stated `384` MiB outer
ceiling; a configured limit alone is not a physical peak measurement.

The previous proposal's unchanged host `oom_kill` counter requirement was wrong:
Linux 6.1 [increments that counter](https://github.com/torvalds/linux/blob/v6.1/mm/oom_kill.c)
for a memcg victim too. Require a delta of one for the single expected victim,
zero in the positive control, and the scoped kernel summary. This correction
does not relax attribution to the exact worker and cgroup. Counter and log
semantics are reviewed against the pinned kernel source, not inferred from a
process exit code.

## Host task controls

Guest forks do not exercise the host task controller. A separate fixed owned
Python helper therefore runs under a distinct unprivileged UID, NoNewPrivs, zero
effective capabilities and a new network namespace in a fresh host cgroup.
Its limits are `128` MiB, zero swap, `16` tasks and `20000/100000` CPU quota.
The helper's process limit is explicitly `1024`, above the cgroup ceiling.
It executes no target code and is not a Firecracker escape test.

The positive helper creates four waiting children. The negative helper makes at
most `32` fork attempts and must receive `EAGAIN` after exactly `15` children.
Require the corresponding `pids.events` increase, observed task count of `16`,
unchanged memory OOM counters, and an exact process roster independently read
from the host. A reported error without those observations is insufficient.
Bind every process with pidfd/start-time and reap every owned process after stop.

## Bounds and continuation

Every case has a held-cgroup watchdog with a `45`-second deadline and collector
pipe-EOF cleanup. The supervisor retains separate observation and cleanup bounds;
the disposable VM retains its fifteen-minute DELETE deadline. Temporary staging
egress and the public IP must be removed before release. No service account,
guest network or research credential is supplied. A failed attempt is retained
and cleaned up; it is never silently redispatched.

Portable positive and known-bad controls validate the outcome predicates; actual
host observations are required for effects. Same-host root observation is not
independent CATO administration. Cross-worker/input controls, independent review,
explicit profile acceptance and an exact target contract remain subsequent work.

The [summary](evidence/owned-resource-preflight-2026-10-25.json) and
[exact observation](evidence/owned-resource-observation-2026-10-25.json)
retain source hashes, event counters, process identity and cleanup. Eighty new
portable resource controls and thirty-seven peer controls pass on both supported
runtimes; the combined focused total with the prior preflights is 240.
