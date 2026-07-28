# Etzio

**An evidence-native operating system for authorized vulnerability research.**

Etzio is designed to turn an exact authorized target into a governed, replayable research
chain:

```text
authority → immutable target → hypotheses → candidates → exploit proof
          → independent reproduction → adjudication → disclosure draft → learning
```

The mission spans vulnerability classes, languages, and target categories. Blockchain,
Solidity, EVM, and later L1/client research are the first benchmark and economic wedge—not
the architectural ceiling. Domain knowledge belongs in versioned packs; policy and
scientific authority remain in the kernel.

> **Status — architecture foundation, 2026-07-28.**
> One repository-fixture candidate-generation path is implemented end to end. It admits a
> signed authority record, resolves immutable content-addressed bytes, executes a narrow
> Python analyzer under a bounded lease, and commits lifecycle-checked events to SQLite. A
> verification-intent mission can also retain a kernel-issued, authority-bound
> modeled-fixture verification lease for a retained candidate, resolve every target and
> predeclared verification-input byte under an exact CAS type, and atomically admit one
> authenticated modeled receipt while consuming its lease. The receipt signs the retained
> resolution and four exact typed output digest/size pairs. The mission remains in
> `awaiting_verification`. Etzio does not construct or execute exploits, establish that
> those opaque outputs came from an execution, adjudicate a finding, access a live target,
> or learn. No production-readiness or superiority claim is made.

## Why Etzio

A vulnerability is a falsifiable claim, not an alert. A candidate identifies a specific
observation against specific bytes. A finding requires a separately authorized verifier to
reproduce a security-relevant effect from retained artifacts in an independently controlled
environment, followed by kernel adjudication.

That yields six operating laws:

1. authority is admitted before a mission opens;
2. workers propose; the kernel alone changes canonical state;
3. a generator cannot verify its own candidate;
4. evidence and identities are content-bound and replayable;
5. refusals, nulls, failures, timeouts, and inconclusive results remain visible; and
6. credentials, egress, spending, live actions, disclosure, and publication are separate
   grants.

## Implemented vertical slice

The supported `etzio` command can analyze only the two repository-owned manifest fixtures
and closes each completed scan:

```text
manifest fixture → content-addressed target snapshot
  → ephemeral operator key + target-bound signed fixture grant
  → self-verifying authority admission
  → bounded analysis lease
  → byte-bound Python AST observations
  → stable candidate envelopes
  → append-only lifecycle-validated SQLite events
  → deterministic replay
  → terminal closure
```

An explicit fixture-only kernel path may instead admit both `static_analysis` and
`modeled_fixture_verification`, retain a completed scan with candidates, issue an AQUILA
verification lease, resolve its predeclared inputs under code-owned artifact types, retain
one canonical ETZIO resolution event, and admit one signed modeled receipt. A single
`verifier_receipt_admitted` event retains the decision trust snapshot and four code-derived
typed output bindings while consuming the lease. This is authenticated statement
retention—not PoC, oracle, or verifier execution and not finding adjudication.

The command has no arbitrary target-path option. It emits candidates only; neither fixture
path can mint a finding, execute a PoC, use the network, access credentials, spend,
disclose, or publish.

The protocol-v1 foundation includes:

- canonical JSON with duplicate-key rejection, Unicode 17.0.0 NFC, signed 64-bit integers,
  fixed resource ceilings, and full domain-separated SHA-256 identities;
- an installed Draft 2020-12 semantic wire schema with exact branches for all nine typed
  object kinds and all fifteen event payload variants;
- Ed25519 authority and modeled-receipt attestations, including prime-subgroup public-key
  validation before a key can enter a trust snapshot;
- exact fixture manifests and a private content-addressed evidence store;
- immutable target, authority, lease, candidate, receipt, and event objects;
- kernel-issued verification-lease events binding retained authority, target, candidate,
  modeled-fixture grant evidence, and the exact issuance-trust snapshot identity;
- type-domain-separated verification-input identities plus one replayable resolution event
  that binds every target, PoC, supporting-evidence, environment, and oracle-specification
  byte to the retained lease;
- a signed receipt binding that exact resolution plus execution, effect,
  measured-environment, and termination output digest/size pairs under four separate
  code-owned CAS types;
- one atomic receipt-admission event that retains the complete decision trust view,
  preserves every allowed verdict, and derives single-use lease consumption through
  replay;
- compare-and-append SQLite storage with replay-time lifecycle validation; and
- known-bad tests for signature, scope, identity, lifecycle, budget, corruption, replay,
  and filesystem-boundary failures.

## System map

| Plane | Unit | Responsibility | Repository status |
|---|---|---|---|
| Control | **ETZIO** | protocol, lifecycle, event ledger, replay | implemented for the fixture scan |
| Governance | **AQUILA** | authority, scope, budgets, leases | fixture analysis and modeled-verification lease issuance implemented |
| Recon | **SCIPIO** | target and attack-surface mapping | modeled |
| Strategy | **FABIUS** | ranked falsifiable hypotheses | modeled |
| Investigation | **VELITES** | leased probes and candidates | narrow byte-bound Python AST slice |
| Proof | **MARCELLUS** | isolated exploit construction | modeled; isolation absent |
| Verification | **CATO** | independent reproduction and verdict | CATO behavior modeled; ETZIO receipt admission implemented; execution and independence absent |
| Adjudication | **CAMILLUS** | evidence completeness, dedup, severity | modeled |
| Disclosure | **FABRICIUS** | evidence-bound report draft | modeled; no external write |
| Learning | **MINERVA** | evaluated offline strategy promotion | modeled |

The original in-process behavior model remains available as `python -m etzio.cli`, but its
toy findings and verifier labels are not security evidence.

## Reproduce

The canonical interpreter is CPython 3.11.15; CI also reproduces the suite on CPython
3.14.2. Validation dependencies are exact and hash-locked.

```bash
git clone git@github.com:manfromnowhere143/etzio.git
cd etzio
python3.11 -m venv .venv
.venv/bin/python -m pip install \
  --no-input \
  --require-hashes \
  --only-binary=:all: \
  --requirement tools/ci/requirements-ci.lock
.venv/bin/python -m pip check
ETZIO_PYTHON=.venv/bin/python make verify
```

Run the governed fixtures:

```bash
.venv/bin/etzio --fixture vulnerable
.venv/bin/etzio --fixture clean
```

To retain replay state, provide a new path or an existing owner-controlled directory whose
mode is already `0700`:

```bash
mkdir -m 700 .etzio-state
.venv/bin/etzio --fixture vulnerable --state-dir .etzio-state
```

## Open gates and next mission

The next mission is not more detector breadth. Kernel-issued modeled-fixture assignments,
typed input resolutions, and atomic modeled-receipt admission are retained; completing the
foundation-integrity boundary still requires:

1. close lease expiry, cancellation, supersession, reassignment, and terminal recovery;
2. establish a trusted clock, revocation freshness, and external event-head anchoring;
3. close the filesystem-CAS/SQLite atomic-retention gap and the documented same-user SQLite
   pathname race;
4. replace opaque modeled outputs with structured, independently produced execution
   evidence; and
5. prove MARCELLUS/CATO separation on an explicitly accepted Linux/KVM profile.

Only then should Etzio run the benchmark-first EVM pack. Live bounty work remains a later,
target-specific authorization stage.

## Project record

- [Session handoff](docs/SESSION_HANDOFF.md)
- [Machine-readable mission state](docs/MISSION_STATE.json)
- [Charter](CHARTER.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Roadmap](docs/ROADMAP.md)
- [2026 frontier baseline](docs/FRONTIER_BASELINE.md)
- [Protocol-v1 semantic wire schema](etzio/schemas/protocol.v1.schema.json)
- [Architecture decisions](docs/decisions/README.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

Etzio is private and solely authored by [Daniel Wahnich](AUTHORS.md).
