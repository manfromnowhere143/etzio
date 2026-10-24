# Owned KVM instruction preflight

Status: **seven benign controls passed; both disposable attempts cleaned up**,
2026-10-24. This advances the October 9 empty-VM observation to actual, fixed
instruction execution. It admits no target or production isolation profile.

The [retained result](evidence/benign-kvm-preflight-2026-10-24.json) binds the exact
[collector](../scripts/collect_benign_kvm_preflight.py), raw guest observation,
resource configuration and cleanup evidence. The collector accepts no target path,
guest image or instruction input. Run it only as root on an explicitly scoped,
disposable Linux x86-64 host; never on the operator workstation or an unrelated VM.
It is not called by `make verify` and has no cloud provisioning interface.

## Experiment and measured outcomes

The host was an `n2-standard-4` with nested virtualization, image
`ubuntu-2404-noble-amd64-v20261021` (image ID `4996011480491275419`), Ubuntu 24.04.5,
kernel `7.0.0-1014-gcp` and KVM API 12. The 64 KiB guest has no operating system,
network or filesystem device. The observer interprets one byte-output port and
refuses other device effects. Exact fixed instruction bytes are in the collector.

| Control | Retained effect |
| --- | --- |
| Emit 42 and halt, UID 65532 | I/O exit, byte 42, halt; worker exit 0 |
| Same program, UID 65533 | Same effect; worker exit 0 |
| Emit 43 instead | Wrong output rejected |
| Store to writable guest RAM | Bytes at address 4096 become `3412` |
| Same store to read-only guest RAM | MMIO write request refused without emulation; bytes remain `0000` |
| Infinite owned instruction loop | External observer kills and reaps worker after its 0.3 s ready interval |
| Same loop, supervisor killed | Parent-death signal kills worker; both processes reaped |

Every worker observed only loopback in its new network namespace, `ENETUNREACH`
for the numeric metadata and documentation addresses, `EACCES` on an owned
protected canary, zero effective capabilities and `NoNewPrivs=1`. The controller
could read the canary. These observations measure specific denials, not complete
filesystem or credential confinement. `Seccomp=0` is retained explicitly.

Post-kill reaping took approximately 7.7 ms and 6.2 ms in the two termination
cases. Those are single observed monotonic intervals, not latency guarantees.
Distinct UIDs and separate processes do not establish independent administration
or CATO verification. One collector produced and interpreted all seven cases.

The first attempt raised Python `OverflowError` while passing `0xFFFBD000` to
`KVM_SET_TSS_ADDR`, before any guest instructions ran. Its failed evidence remains
intact. The retry used `0x100000`, outside guest RAM and within the signed integer
argument range. Both attempts used separate resource names; the retry started
only after the first attempt's cleanup was verified.

## Resource and evidence boundaries

Each VM had a dedicated VPC/subnet with deny-all egress, no external IP, service
account or OAuth scopes, one visible thread per core, shielded boot, a 10 GB
auto-delete disk and a 15-minute DELETE deadline. The controller used serial
output, not guest SSH. Nonce-bound chunk counts, byte length and SHA-256 were
checked before accepting the observation. VM, disk, firewall, subnet and VPC
absence were checked by exact-name control-plane queries after each attempt.
No unrelated workload was changed.

At the captured public compute rate, the two requested 15-minute lifetimes total
about USD 0.097118 before disk, taxes, account pricing or termination delay. This
is an estimate, not an invoice or an enforced account spending cap. Controller,
cloud and guest timestamps are observations, not qualified trusted time.

The Linux [KVM API](https://docs.kernel.org/virt/kvm/api.html) and pinned
[generic](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/kvm.h) and
[x86](https://github.com/torvalds/linux/blob/v6.12/arch/x86/include/uapi/asm/kvm.h)
ABI definitions informed the probe. Cloud configuration follows the documented
[nested-virtualization](https://docs.cloud.google.com/compute/docs/instances/nested-virtualization/overview)
and [runtime-limit](https://docs.cloud.google.com/compute/docs/instances/limit-vm-runtime)
interfaces. Raw control records and source captures remain private and indexed.

## Next containment evidence

Use a separately reviewed production VMM/jailer profile for arbitrary code, with
immutable inputs, controlled output, syscall/device restrictions, cgroup ceilings,
credential and mount confinement, teardown under interruption, and an external
termination path. Exercise those boundaries with owned adversarial controls before
acceptance. This small instruction probe is not that runner. Kernel-escape
resistance, physical-host policy, resource exhaustion, cross-worker state,
independent verification, storage power faults and target execution remain open.

Supervised bounty work follows [ADR-0025](decisions/0025-parallel-supervised-bounty-research.md).
Source review can proceed while that accepted execution environment is completed.
