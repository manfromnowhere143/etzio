# Owned input and cross-worker experiment

Status: **owned bidirectional checks passed; no target profile admitted**, 2026-10-25.

Run this only after the resource experiment's actual host observations and complete
cleanup are retained. It uses two concurrent fixed owned readiness guests on a
fresh disposable host, unique UIDs, distinct cgroups and distinct jailer-created
mount, PID and network namespaces. Retain the same pinned image, kernel, VMM,
jailer, source bytes, fixed guest fixtures, budgets and egress-removal evidence.
No target or arbitrary build input is admitted.

The exact readiness fixture is the resource experiment's `memory-low` program:
one vCPU, `512` MiB configured guest memory, `64` MiB touched, then waiting. Each
VMM retains its `256` MiB/zero-swap/32-task/20-percent CPU cgroup. A separate
`128` MiB/zero-swap/eight-task/20-percent CPU cgroup holds six fixed host helpers:
two listeners, two DAC/signal probes and two namespace/input probes. All six
must remain bound and alive at the final observation, including both listeners;
otherwise an apparent network refusal cannot pass. Record and reap each helper.

## Effect contract

Bind both workers and their kernel helpers by pidfd/start time. Observe every VMM
thread's credentials, seccomp and NoNewPrivs. Distinct namespace identities must
be observed, not inferred from separate configuration names. Both guests must
remain alive through the peer probes, and both must subsequently be killed and
reaped with empty cgroups and observed helper exit.

Use fixed owned probes with positive controls in both directions:

1. An actor can read its own canary and contact its own API. It cannot read the
   peer's private canary or connect to the peer API under the actor's UID. The
   root collector deliberately supplies directory descriptors for both run
   directories, bypassing unrelated ancestor permissions. This stronger owned
   challenge tests the run-directory and socket access controls separately from
   path absence in a chroot. These descriptors are never supplied to a guest.
2. An actor in its jail's mount/root context can read the exact kernel and initrd
   but cannot open either for writing, truncate them, change permissions, unlink
   them or replace them by rename. Rehash the inputs before and after each probe;
   retain actual errno results and a positive writable scratch control. Test both
   the file and its containing directory. A read-only file alone does not stop
   replacement in a writable directory.
3. Signal-zero probes from the actor's UID must succeed against its own process
   and refuse the bound peer process with `EPERM`. Observe the peer still alive
   through its pidfd after the probe. A PID-namespace `ESRCH` result is a separate
   visibility measurement, not evidence that host-namespace signaling is denied.
4. Host and peer abstract Unix socket listeners have positive connection controls
   from their own network contexts. Connections to those exact names from the
   actor's distinct network context must fail with Linux `ECONNREFUSED`; a
   connection to its own listener must succeed. Inspect exact namespace,
   interface and route state. A nonexistent listener cannot calibrate isolation.
   This measures the abstract Unix socket namespace, not TCP/IP reachability.
   Keep loopback down; supply no external address, DNS operation, service
   credential or guest NIC.

The probes are closed owned programs. A host probe that enters a VMM namespace
does not inherit that VMM's seccomp filter, and is not a guest exploit. Record its
actual credentials, capabilities, NoNewPrivs, namespace and filter state. These
measurements establish only the exercised file, credential and namespace layers.
They do not establish absence of a Firecracker, KVM or kernel vulnerability.

## Refusal, cleanup and independent review

Every expected denial needs a working positive control, exact resource binding
and a known-bad predicate control. Missing peer identity, ambiguous errno, missing
baseline, changed input hash, successful peer access, an unrelated process, extra
interface, output overflow or deadline is a refused experiment. Cleanup cannot
turn a failed effect into a pass. Preserve the full failed attempt before fixing
the collector or redispatching.

Use held-cgroup watchdogs, bounded probe lifetimes/output and the independent
fifteen-minute VM DELETE deadline. Verify all owned cloud resource identities
absent. Retain the final source/payload hashes, observations, local tests and exact
candidate validation for review.

Under [ADR-0026](decisions/0026-solo-supervised-bounty-workflow.md), the assistant
may assess the combined containment evidence for an exact supervised profile
without recruiting an outside reviewer. Retain the accepted bounds, objections
and disposition before binding an exact target/revision and its program rules.
Same-assistant repeats remain self-reproduction. A claim of independent review
still needs an actual separate reviewer and execution identity. This experiment's
results alone authorize no target execution.

## Retained result

The first cross-worker host attempt passed all six helper controls in both
worker directions. Own canary/API access and signal-zero succeeded. Peer canary
and API access returned Linux EACCES; peer signal-zero returned EPERM. Each
kernel/initrd write, truncate, chmod, unlink and replacement attempt was refused,
and the before, helper-read and after hashes agreed. Writable scratch controls
succeeded. Own abstract-socket connections succeeded while peer and host names
returned ECONNREFUSED. Both listeners were still alive at final observation.

All six helpers and both VMMs were bound and alive through the effects, then
reaped with SIGKILL; both kernel helpers exited and every cgroup emptied. All six
cloud resource identities are verified absent. Across the resource and peer
experiments, all three attempts' eighteen resource identities are absent.

The [summary](evidence/owned-cross-worker-preflight-2026-10-25.json) and
[exact observation](evidence/owned-cross-worker-observation-2026-10-25.json)
retain the bounded result. The probe process has seccomp mode zero and the VMM
threads mode two; the result is explicitly limited to the measured layers.
The [Linux namespace contract](https://www.man7.org/linux/man-pages/man7/network_namespaces.7.html)
describes the abstract-socket separation exercised here.
