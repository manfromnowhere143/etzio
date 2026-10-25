# Owned collector-death experiment

Status: **three owned controls passed; no execution profile admitted**, 2026-10-25.

This extends the [owned guest preflight](OWNED_FIRECRACKER_PREFLIGHT.md)
under the existing bounded cloud-preparation grant. It executes only the exact
previously pinned ready fixture on the same Debian 6.1/Firecracker 1.17.0 profile.
It admits no target, arbitrary-code runner or production kernel evidence.

## Three controls

1. The normal ready fixture retains its marker, thread-filter and explicit-stop
   checks.
2. A separate outer observer kills the actual collector with SIGKILL after
   receiving a bounded readiness record. The watchdog must observe EOF on its
   control pipe, kill the worker cgroup and report emptiness. The outer observer
   must reap both the collector and worker with SIGKILL and the watchdog with
   exit zero, and observe the bound cgroup empty within five seconds of injection.
3. A separate owned calibration withholds the watchdog. The primary criterion
   must refuse. The worker must remain present through the five-second primary
   window; the observer then kills the cgroup and reaps the worker before the
   ten-second outer deadline. Fallback cleanup never satisfies the primary test.

Each case has a new UID, jail, network namespace and cgroup. The readiness wire
has a closed field set, rejects duplicate keys and binds collector/worker/watchdog
process identities, cgroup device/inode, thread observations and complete bounded
guest output. Only exact CRLF readiness and the existing filter requirements may
produce readiness. The observer opens pidfds, rechecks process start times and
cgroup membership, and refuses mismatches before injection. The watchdog pipe is
created inside the collector after it starts; the observer checks that it holds
no descriptor for that pipe. Neither worker nor watchdog inherits its write end.

The observer is a Linux child subreaper. After collector death, it independently
observes process termination rather than trusting a collector exit assertion.
The watchdog and observer hold directory descriptors to the exact cgroup; their
kill/read operations do not re-resolve a caller-selected pathname. The observer
keeps a ten-second monotonic deadline after injection, even for the negative
control. Readiness itself is bounded to thirty seconds. Setup failure, incomplete
readiness or cleanup failure is retained as a failed experiment. The cloud VM
still has its independent fifteen-minute DELETE deadline.

The implementation follows the documented Linux
[subreaper](https://man7.org/linux/man-pages/man2/PR_SET_CHILD_SUBREAPER.2const.html),
[cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html) and Python
[pidfd](https://docs.python.org/3.11/library/os.html#os.pidfd_open) interfaces.
Time measurements use one host monotonic clock; they establish no trusted UTC.

The first two attempts refused membership before injection. The second retained
two process IDs after guest start. Linux 6.1's
[KVM worker implementation](https://github.com/torvalds/linux/blob/v6.1/virt/kvm/kvm_main.c)
attaches its NX large-page recovery kernel thread to the VM's cgroup; the
[MMU lifecycle](https://github.com/torvalds/linux/blob/v6.1/arch/x86/kvm/mmu/mmu.c)
starts it at VM initialization and stops it at destruction. The revised owned
profile requires exactly the bound VMM plus one such helper, observed with the
kernel-thread flag, parent PID 2, root credentials and its exact full comm bound
to the VMM's host PID. The third attempt retained that full name and refused an
incorrect assumption that the kernel-thread name was truncated to fifteen bytes.
A matching name alone is insufficient. Unknown or additional userspace processes
still refuse. The observer binds the helper's pidfd and start time and requires
its actual exit as well as empty cgroup membership; it does not claim to reap a
kernel thread owned by kthreadd. This is a host observation under trusted host
root, not separate administration or proof against a compromised kernel.

Readiness also requires the successful jailer launcher to have been reaped.
All fresh cgroup and helper observations are retained before their gates, so a
failure cannot discard the evidence needed to diagnose it.

## Dispatch and claim limits

Before a single cloud attempt, retain the exact sources, finite cases, artifact
pins, existing image identity, resource names and budget; pass portable positive
and refusal controls; verify predecessor resources absent. Preserve temporary
artifact-staging egress removal, no service account, no guest network and all
previous limits. Do not repeat a spent attempt or overwrite its evidence.

Portable tests establish parser and decision behavior only. Actual host records
are required for any process-death claim. All observers share one operator and
host root: process separation is not independent CATO administration. Memory and
task exhaustion, input mutation, cross-worker access, escape resistance, storage
durability and independent reproduction remain separate obligations.

## Retained result

The fourth attempt passed the normal, collector-death and withheld-watchdog
controls. The primary watchdog case completed in 0.132149 seconds. The withheld
case correctly refused primary acceptance, then completed outer cleanup in
5.062013 seconds from injection. Both workers were reaped with SIGKILL; the
kernel helpers exited and both cgroups emptied. All four attempts’ 24 resource
identities are verified absent. The three failed attempts remain failed.

The [summary](evidence/owned-collector-death-preflight-2026-10-25.json) and
[exact observation](evidence/owned-collector-death-observation-2026-10-25.json)
retain source identities, intervals and refusal outcomes. Eighty-seven new portable
controls pass on both supported runtimes; together with the earlier guest
preflight controls, the focused total is 123. These tests do not run a VM.
