# Owned Firecracker guest preflight

Status: **four owned controls passed; no execution profile admitted**, 2026-10-24. This is a separate
continuation of the [fixed-instruction KVM probe](BENIGN_KVM_PREFLIGHT.md), under
the existing benign cloud-preparation grant. It admits no target or arbitrary-code
execution profile.

## Experiment contract

Use the non-debug, static x86-64 Firecracker and jailer release `v1.17.0`, source
commit `95f868c8e345b1cc8faccd1a3c910b4989dc3f58`. Pin the archive and each selected
binary before execution. The release tag is unsigned; public HTTPS delivery,
publisher checksums and matching byte identities are not independent supply-chain
attestation.

The pinned release's [kernel support policy](https://github.com/firecracker-microvm/firecracker/blob/95f868c8e345b1cc8faccd1a3c910b4989dc3f58/docs/kernel-policy.md)
lists host kernels 5.10, 6.1 and 6.18. The previous probe's 7.0 host is not assumed
to qualify. This experiment selects the exact Debian 12 image
`debian-12-bookworm-v20261023` and requires a 6.1 host kernel. The guest kernel is
the vendor's public CI `vmlinux-6.18.54`, pinned by byte count and SHA-256. Its
separately published config lists initrd, ELF, KVM guest and serial-console support;
that publication does not prove the config was used to build the binary.

The [owned fixture builder](../scripts/build_owned_firecracker_initrd.py) assembles
four fixed programs and creates minimal initramfs archives containing `/init` and
`/dev/console`. It executes no guest. There is no downloaded root filesystem,
shell, package manager, network interface or caller-supplied target in the guest.
The programs write LF-terminated markers; this pinned guest console emits CRLF.
The collector requires a complete exact CRLF line at a line boundary, rejecting
partial markers, wrong markers and embedded or suffixed lookalikes.

| Fixture | Required observation |
| --- | --- |
| Ready marker then wait | Exact marker from the guest; observer terminates the cgroup |
| Wrong marker then wait | Distinct wrong marker; expected marker absent |
| Ready marker then spin | Guest runs until the external observer kills its cgroup |
| Repeated marker | Output limit triggers termination; overflow remains explicit |

The [collector](../scripts/collect_owned_firecracker_preflight.py) accepts only
these four pinned images. Run it only as root on the exact disposable host after
the artifact and network checks. It is excluded from ordinary repository tests
and has no target-loading or cloud-provisioning interface.

## Host controls and resource limits

Each case uses a fresh UID, PID namespace, mount namespace, empty network
namespace, jail and cgroup. The collector requires exact configured limits:
256 MiB memory, zero swap, 32 tasks, and `cpu.max = 20000 100000`. The guest uses
one vCPU and 128 MiB memory. It verifies actual cgroup membership, reduced
credentials and every observed thread's seccomp/NoNewPrivs state after VM start.
Pre-start API-thread filtering alone does not satisfy this check.

The pinned release sends `InstanceStart`'s response before installing the VMM
thread's filter. The collector therefore issues `GET /machine-config` after
start and verifies the exact requested machine settings before observing threads.
That synchronous VMM request is handled by the runtime event loop, entered after
filter installation. This ordering follows the pinned
[API adapter](https://github.com/firecracker-microvm/firecracker/blob/95f868c8e345b1cc8faccd1a3c910b4989dc3f58/src/firecracker/src/api_server_adapter.rs)
and [request controller](https://github.com/firecracker-microvm/firecracker/blob/95f868c8e345b1cc8faccd1a3c910b4989dc3f58/src/vmm/src/rpc_interface.rs).
Every observed thread must still have `Seccomp: 2` and `NoNewPrivs: 1`. The
snapshot is retained even when that check refuses; no sleep or filter exception
substitutes for the runtime response and actual thread observations.

The host observer bounds output and terminates through `cgroup.kill`. A separate
local watchdog also kills that cgroup after 45 seconds or closure of its control
pipe. The collector requires worker membership before termination, observes SIGKILL
reaping, bounds its output drain and records cgroup emptiness. Distinct UIDs
and a watchdog process do not establish independent CATO administration.

One exact disposable VM is allowed per attempt, with a 10 GiB auto-delete disk
and a 15-minute DELETE deadline. It has no service account, OAuth scopes or
added ingress rule. Artifact staging temporarily permits public HTTPS. Before
executing the collector, the controller removes the temporary public address and
HTTPS rule, verifies their absence and the egress-deny rule, and releases the
exact attempt nonce. Each worker has an empty network namespace and the guest
has no network device. This two-phase preparation is distinct from allowing
research-target egress.

Serial observations are nonce-bound, chunk-counted and size/digest-checked. Every
attempt retains its exact sources, plan, cloud operations, serial output and
cleanup checks. A failed attempt remains failed. Retry uses a new record and
resource identity only after the predecessor's resources are verified absent.

## Retained result

The sixth bounded attempt passed all four controls. Each case retained three
threads with seccomp filtering and NoNewPrivs, then worker SIGKILL reaping and an
empty cgroup. The output case crossed the 65,536-byte observation limit. All six
attempts' VM, boot disk, temporary HTTPS rule, deny rule, subnet and network are
verified absent. The five failed attempts remain failures, with their setup and
observation corrections recorded in the
[summary](evidence/owned-firecracker-preflight-2026-10-24.json).

The exact [guest observation](evidence/owned-firecracker-guest-observation-2026-10-24.json)
binds the collector and artifact digests. Three complete outputs fit within their
retained prefixes and can be rehashed. The overflow case retains a count, digest,
prefix and suffix; its complete output is not retained. Thirty-six portable
checks cover host/artifact refusals, API completion/refusal, restrictive umask,
runtime response validation and exact console framing on both supported runtimes.

Next, measure actual collector death, resource exhaustion, input mutation and
cross-worker access controls on this same pinned profile. Then require independent
review of those results and an exact scoped reproduction contract. These four
guest cases alone do not close those obligations.

## Claim boundary

Configured limits are not resource-exhaustion evidence. These four controls do
not establish memory/pids exhaustion handling, cross-worker confidentiality,
immutable-input resistance, kill behavior after actual controller death,
physical-host isolation, microcode policy, kernel-escape resistance, storage
durability or independent verification. Optional snapshots, vsock, network and
target builds are not exercised. A successful run cannot admit an arbitrary-code
runner or create a security finding.

Continue [supervised source review](decisions/0025-parallel-supervised-bounty-research.md)
alongside the remaining containment controls. Exact target/revision, program
scope, accepted containment and independent reproduction remain necessary before
a bounty reproduction is admitted.
