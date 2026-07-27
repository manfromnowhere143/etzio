# ADR-0001: Foundation integrity before capability breadth

- Status: accepted
- Date: 2026-07-27
- Owner: Daniel Wahnich

## Context

The first Etzio tranche established a useful vocabulary and deterministic fixtures, but the
audit found that its claimed trust boundaries are not yet enforced. The lifecycle demo and
the real Python scan are disconnected; contracts and schemas diverge; authorization is
self-asserted; events are mutable and in-memory; and the kernel trusts caller-supplied
verdicts. Adding Solidity, finder agents, or live adapters would multiply behavior on top of
an unauditable foundation.

## Decision

Etzio will close one read-only, fixture-only vertical path before adding capability breadth:

- one immutable versioned protocol shared by runtime, wire, schema, storage, and tests;
- authority admission before mission creation;
- the real analyzer invoked only through a kernel-issued lease;
- full-SHA content-bound identities;
- durable immutable events and deterministic replay;
- kernel validation of independent-verifier receipts;
- a known-bad fixture for every consequential invariant.

Linux/KVM isolation follows this integrity slice. The benchmark-first blockchain domain pack
follows the independent proof plane.

## Consequences

- Finder breadth and live research are intentionally delayed.
- Existing data structures may change incompatibly while the repository remains pre-release.
- The current demo’s green tests remain regression evidence, not architecture acceptance.
- Every later domain pack can depend on one stable authority, event, identity, and receipt
  protocol.

## Rejected alternatives

### Build Solidity and FABIUS first

This creates more candidates without a trustworthy path to authorize, persist, reproduce,
or adjudicate them.

### Build host-process PoC execution on macOS

This would turn untrusted generated code into a host risk and still would not establish the
intended isolation boundary.

### Treat signatures or multi-model agreement as verification

Identity and consensus do not establish that a security effect occurred. Etzio requires
independent execution evidence and a versioned effect oracle.
