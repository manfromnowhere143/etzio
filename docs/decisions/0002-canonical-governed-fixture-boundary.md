# ADR-0002: Canonical governed fixture boundary

- Status: accepted
- Date: 2026-07-27
- Owner: Daniel Wahnich

## Context

ADR-0001 required one truthful vertical slice before capability breadth. The predecessor
repository had a path-taking scanner disconnected from self-asserted authority, mutable
in-memory events, traversal-position candidate IDs, and an in-process verifier model.

Implementation and adversarial review also exposed two protocol hazards:

- Unicode normalization differed across the supported Python runtimes; and
- the generic Ed25519 backend accepted a known small-order public-key/signature pair.

A green happy path could not close either risk.

## Decision

Etzio protocol v1 adopts:

- one canonical `EnvelopeV1` for authority, admission, target, analysis lease,
  verification lease, candidate, receipt, and event framing; `head_checkpoint` remains a
  framing-level reserved kind, while current checkpoint storage is explicitly opaque;
- Unicode 17.0.0 NFC through an exact runtime dependency;
- signed 64-bit integers, no floats, duplicate-key rejection, canonical UTF-8, fixed
  structural ceilings, and full domain-separated SHA-256 identities;
- Ed25519 attestations with canonical signature encoding;
- libsodium prime-subgroup point validation before a public key enters configured or
  embedded authority/verifier trust snapshots;
- immutable manifest-backed target snapshots and content-addressed evidence;
- a fixture-only analysis command with no arbitrary path-taking production API;
- lifecycle validation inside the SQLite compare-and-append transaction; and
- explicit candidate-only output.

The checked-in protocol JSON Schema is a framing schema. Semantic body validation remains
in typed Python parsers until per-kind schemas and parity fixtures are implemented.

Modeled verifier receipts receive a distinct `verification_lease` kind and canonical signed
wire, but they do not enter finding admission until the kernel issues the lease, resolves
all referenced CAS bytes, and atomically commits receipt acceptance with lease consumption.

## Consequences

- CPython 3.11 and 3.14 derive identical protocol identities for the declared Unicode
  corpus.
- Trust provisioning fails closed for malformed, noncanonical, or small-order Ed25519
  points.
- The supported command cannot be redirected to an unknown local repository.
- A valid event hash is insufficient; typed payload and lifecycle semantics are replayed
  before append and on load.
- Existing prototype schemas and in-memory model objects remain non-authoritative and are
  documented as such.
- PyNaCl/libsodium becomes a pinned runtime dependency in addition to `cryptography`.

## Residual risks

- clock and revocation freshness are supplied by the invoking service;
- SQLite has a documented same-user pathname race and no external head anchor;
- the protocol schema does not yet validate per-kind body semantics;
- verifier leases are not kernel-issued or authority-bound;
- receipt evidence membership does not yet resolve and type-check CAS bytes;
- lease consumption is not atomic; and
- verifier labels and keys do not prove process, principal, or isolation independence.

These remain blocking conditions, not deferred implementation details that may be treated
as satisfied.

## Rejected alternatives

### Use the Python standard library Unicode database

Supported Python patch lines ship different Unicode databases, which can produce different
normalization and content identities.

### Treat successful Ed25519 object construction as public-key validation

The pinned backend accepted the reproduced small-order identity encoding. Trust keys require
explicit canonical main-subgroup validation.

### Preserve the arbitrary filesystem scan as a convenience

That would keep an authority and evidence bypass in the supported product surface. Tests
may traverse repository bytes; production analysis receives admitted immutable bytes only.

### Call a signed modeled receipt a finding

A signature authenticates a statement. It does not prove kernel authority, retained
evidence, independent execution, or the claimed security effect.
