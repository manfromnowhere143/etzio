# Supervised compiler preparation

Status: **two owned guest images built; compiler and guest execution not performed**.
Date: 2026-10-25. This is preparation under [ADR-0026](decisions/0026-solo-supervised-bounty-workflow.md),
not a general target runner or a vulnerability result.

Official release metadata pins Foundry
[`v1.8.6`](https://github.com/foundry-rs/foundry/releases/tag/v1.8.6) and Solidity
[`v0.8.38`](https://github.com/argotorg/solidity/releases/tag/v0.8.38). The downloaded
Foundry Alpine x86-64 archive and static Solidity compiler match the byte counts
and SHA-256 digests in their publisher release metadata. The extracted `forge`
and compiler ELF headers identify Linux x86-64 binaries with no interpreter segment.
These are byte and format observations, not independent supply-chain attestation.

A private prototype builder creates two fixed initramfs images. Each contains the
pinned tools, an owned assembly init, an offline compiler configuration and one
owned Solidity arithmetic test. One assertion is intended to pass; the other is
deliberately false. The init checks the expected child exit status and then waits
for external cleanup. No downloaded binary, Solidity build or guest has executed.
The only executed build tool was the local assembler on owned assembly.

An initial build failed because a memory comparison lacked an operand-size suffix.
Its source and assembler error are retained. The corrected builder uses an explicit
32-bit comparison. Two corrected builds match all `8` source/object/ELF/initramfs
artifact pairs and their manifests. Each resulting image is `138912256` bytes.
This checks deterministic construction; it does not validate the guest init,
compiler behavior, failing-test detection or containment during execution.

The public [byte summary](evidence/supervised-toolchain-preparation-2026-10-25.json)
contains the artifact identities and limitations. The complete release metadata,
downloaded tools, prototype, failed attempt and rebuilds remain privately at
`artifacts/supervised-evm-preparation-20261025/`. They are not installed or included
in Etzio packages, and this document offers no supported runner command.

The next experiment must retain one exact disposable host/profile, resource and
time limits, immutable inputs, denied execution egress and credentials, bounded
serial output and cleanup. It must observe the intended pass and intended failure
as different outcomes before a target-specific proof is attempted. A positive
compiler run alone is insufficient. No new cloud resources, target executions,
report candidates, submissions or payments occurred during this preparation.
