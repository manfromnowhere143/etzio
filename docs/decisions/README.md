# Architecture decision records

Etzio records changes to load-bearing invariants and major dependencies as immutable,
numbered ADRs. A later ADR supersedes an earlier decision; history is not rewritten.

- [ADR-0001: Foundation integrity before capability breadth](0001-foundation-integrity-before-breadth.md)
- [ADR-0002: Canonical governed fixture boundary](0002-canonical-governed-fixture-boundary.md)
- [ADR-0003: Semantic wire schema and typed-kind closure](0003-semantic-wire-schema-and-typed-kind-closure.md)
- [ADR-0004: Kernel-issued, authority-bound verification leases](0004-kernel-issued-verification-leases.md)
- [ADR-0005: Typed, replayable verification-artifact resolution](0005-typed-verification-artifact-resolution.md)
- [ADR-0006: Atomic modeled-receipt admission and single-use lease consumption](0006-atomic-modeled-receipt-admission.md)
- [ADR-0007: Explicit modeled verification-lease recovery](0007-explicit-verification-lease-recovery.md)
- [ADR-0008: Typed integrity-evidence contract before external authority](0008-typed-integrity-evidence-contract.md)
- [ADR-0009: Uniform SQLite rollback-journal safety](0009-uniform-sqlite-rollback-journal-safety.md)
- [ADR-0010: Transactional canonical evidence vault](0010-transactional-evidence-vault.md)
- [ADR-0011: Crash-safe modeled integrity finality](0011-crash-safe-modeled-integrity-finality.md)
- [ADR-0012: Networkless trusted-time and revocation adapter qualification](0012-networkless-time-revocation-adapter-qualification.md)
- [ADR-0013: Networkless anchor, catalog, and monitor adapter qualification](0013-networkless-head-authority-adapter-qualification.md)
- [ADR-0014: Durable blocked-finality disposition and governed recovery](0014-durable-blocked-finality-and-governed-recovery.md)
- [ADR-0015: Schema-version-3 durable blocked-finality storage](0015-durable-blocked-finality-storage-v3.md)
- [ADR-0016: Governed blocked-finality lifecycle integration](0016-governed-blocked-finality-lifecycle.md)
- [ADR-0017: Blocked-finality crash recovery and status inspection](0017-blocked-finality-crash-recovery.md)
- [ADR-0018: Qualified signed evidence consumption](0018-qualified-evidence-consumption.md)
- [ADR-0019: Qualified evidence lifecycle consumption](0019-qualified-evidence-lifecycle-consumption.md)
- [ADR-0020: Offline RFC 3161 timestamp qualification](0020-offline-native-time-qualification.md)
- [ADR-0021: Offline RSA timestamp chains and provider selection evidence](0021-offline-rsa-timestamp-chains.md)
- [ADR-0022: Native timestamp acquisition and consumption bounds](0022-native-time-consumption-bounds.md)
- [ADR-0023: Offline single-request acquisition custody](0023-offline-acquisition-custody.md)

ADR-0010 supersedes only the split filesystem/SQLite retention caveats and deferred work
recorded in ADR-0005, ADR-0006, ADR-0007, and ADR-0009. Their protocol, lifecycle,
authentication, and rollback-journal decisions remain current.

ADR-0011 operationalizes ADR-0008 only for an empty-history schema-version-2
repository-owned deterministic fixture profile. It does not qualify or connect an
external authority and does not supersede ADR-0008's external-provider gate.

ADR-0012 specifies the repository-owned Ed25519 fixture authentication contract and
deterministic qualification harness for trusted-time and revocation adapters. It does not
connect or qualify a native provider, alter lifecycle finality, or qualify anchor, catalog,
or monitor authority.

ADR-0013 extends that boundary to the remaining two integrity evidence kinds. It adds
RFC 9162 inclusion and consistency verification, byte-bound anchor registration leaves,
and unanimous monitor agreement over one catalog head, mapping sealed results to the
existing `head_anchor_receipt` references and `HeadCheckpointFloorV1` values. It does not
connect or qualify a native provider, prove independent operators or external durability,
alter lifecycle finality, or add durable blocked-finality recovery.

ADR-0014 specifies the durable blocked-finality observation, the role-separated signed
governed recovery decision, and the exactly two admissible dispositions. It changes no
SQLite schema, store method, or lifecycle command; persistence, crash recovery, and the
enrolled recovery authority remain a separate storage tranche.

ADR-0015 persists the ADR-0014 contract as three append-only schema-version-3 relations
with a forward migration from the exact version-2 layout. It is layout-only: no recovery
path yet produces an observation or consumes a decision, and no relation participates in
the database-global barrier.

ADR-0016 makes the persisted contract live: an opt-in governed binding retains a durable
observation when a deterministic block is classified, requires an authorized retry before
recovery may advance, and refuses every consequential command on a sealed instance.

ADR-0017 proves injected-interruption recovery on both sides of observation and decision
retention, makes the unauthorized-recovery refusal carry the retained reason, and adds a
non-consequential status interface.

ADR-0018 begins qualified signed evidence consumption. It specifies the two profile-selected
acceptance modes and implements the complete acceptance-primitive layer — anchor,
revocation, and head-floor — which freshly reauthenticates a qualified bundle and accepts a
checkpoint's, decision's, or finalization's claimed evidence only as the exact signed
packages. They change no record identity, store profile, or lifecycle command; the one
remaining step is the schema-touching storage-wiring tranche.

ADR-0019 wires the ADR-0018 acceptance primitives into the four-phase fixture finality
lifecycle. Schema-version-4 enrollment pins the qualified adapter roots; store admission,
retry and cold replay reconstruct requests and reauthenticate retained signed packages.
The qualified fixture service, complete receipt vertical and governed interruption
recovery are implemented; externally administered providers remain a separate gate.

ADR-0020 qualifies a bounded native RFC 3161/5816 offline observation profile using pinned
pyHanko CMS/PKIX validation and a retained OpenSSL comparison. It introduces no provider
acquisition or lifecycle authority; independent administration and fresh external evidence
remain required.

ADR-0021 adds a separate finite RSA chain observation profile, both revocation roles,
closed qualified-statement parsing, documentary provider selection evidence and a retained
whole-chain OpenSSL comparison. It admits no external provider or legal qualification.

ADR-0022 composes both native validators with an exact elapsed-time trace and conditional
clock-error model. It propagates issuance uncertainty to receipt and consumption, then
checks the whole consumption interval against a half-open evaluation window. It adds no
clock qualification, provider acquisition, kernel authority or lifecycle behavior.

ADR-0023 implements a separate offline acquisition journal over repository-owned fixtures.
It retains exact request bytes, commits a non-resetting attempt debit and preserves opaque
or indeterminate capture through interrupted execution. It provides no transport, grant
admission, native provider authority, cross-copy budget or qualified storage profile.
