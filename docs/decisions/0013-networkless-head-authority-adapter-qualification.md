# ADR-0013: Networkless anchor, catalog, and monitor adapter qualification

- Status: accepted
- Date: 2026-07-31
- Owner: Daniel Wahnich

## Context

ADR-0008 defines four provider-neutral integrity evidence kinds:
`trusted_time`, `revocation_metadata`, `head_anchor_receipt`, and
`external_floor`. ADR-0012 closed the first two behind a deterministic,
networkless qualification boundary: exact copied trust profile, fixed source
roster, role-separated Ed25519 fixture signatures, authentication before claim
parsing, conservative interval fusion, and sealed provider-neutral mapping.

The remaining two kinds are still unqualified. Today:

- `HeadCheckpointV1.anchor_evidence` requires at least two
  `head_anchor_receipt` references bound to an exact `anchor_statement_id`,
  but nothing authenticates a receipt, proves that the exact anchor statement
  was registered, or proves that the registering log is append-only;
- `HeadCheckpointFloorV1` carries at least two `external_floor` references and
  exact global plus mission checkpoint provenance, but direct construction
  validates shape only. It does not authenticate a catalog, prove that the
  catalog did not roll back or fork, or prove that any independent observer
  saw the same head; and
- `RepositoryOwnedDeterministicModeledIntegrityServiceV1` consumes unsigned,
  canonical, code-derived assertions for the anchor, catalog, and monitor
  roles.

Two open foundation-integrity blockers depend on exactly this gap: no
externally authenticated head authority survives local database loss, and a
coherent offline rewrite of the local database remains undetectable. Both are
head-authority questions, not time or revocation questions.

Connecting a real transparency service before closing this boundary would let
a caller-supplied `source_id` label and an unverified digest appear to be
external head authority. Implementing a native RFC 9162, RFC 9942, or Rekor
client inside the lifecycle kernel would instead combine proof mathematics,
network behavior, provider selection, and authority policy before a common
acceptance boundary was proved.

The next dependency-complete tranche is therefore the direct ADR-0012
extension: a deterministic, networkless contract and qualification harness for
repository-owned anchor, catalog, and monitor fixture adapters. It closes the
two remaining evidence kinds against the same acceptance discipline.

## Decision

Etzio implements the V1 contract in
`etzio/kernel/head_authority_adapters_v1.py`. It reuses the ADR-0012 shape
exactly: closed canonical records, a fixed source roster, role-separated
Ed25519 fixture signatures, authentication before claim parsing, sealed
results, fresh reauthentication before mapping, and a kernel-owned
deterministic harness bound by a content-addressed corpus manifest.

V1 is intentionally strict:

- `adapter_profile` is exactly
  `repository_owned_networkless_head_authority_v1`;
- `contract_version` is exactly `1` wherever the implemented record carries
  that field;
- every required source is present; callers cannot select a quorum subset;
- the profile binds the complete validation policy, trust store, source
  roster, codec profile, provider policy, service, environment, log origin,
  and head-staleness ceiling;
- no operating-system trust store, wall clock, network response, cache,
  credential, or environment variable contributes authority;
- a provider claim is parsed only after the exact signed statement bytes
  authenticate;
- head freshness is evaluated against a freshly reauthenticated ADR-0012
  qualified time hull, never against local time; and
- provider-neutral mappings are derived only from freshly reauthenticated
  sealed bundles whose exact signed bytes cover every evidence reference.

This module adds no protocol-v1 object kind, store profile, schema version,
lifecycle command, provider call, or finality phase.

## Merkle proof core

Anchor and catalog qualification require append-only log mathematics, not a
digest comparison. V1 implements the RFC 9162 (Certificate Transparency
version 2) hash and proof algorithms over SHA-256, which RFC 9162 inherits
from RFC 6962.

Domain-separated hashing prevents the classic second-preimage confusion
between a leaf and an internal node:

```text
MTH({})      = SHA-256()
leaf_hash(d) = SHA-256(0x00 || d)
node_hash(l, r) = SHA-256(0x01 || l || r)
```

`verify_merkle_inclusion_v1` implements RFC 9162 section 2.1.3.2. Given a leaf
hash, a leaf index, a tree size, an ordered proof, and a claimed root, it
recomputes the root and requires exact equality. It refuses an index at or
above the tree size, an empty tree, and any proof whose length is not exactly
the length the tree geometry requires. A proof that is too short or too long
for its `(leaf_index, tree_size)` pair is refused before hashing, so a caller
cannot pad or truncate a proof into agreement.

`verify_merkle_consistency_v1` implements RFC 9162 section 2.1.4.2. Given a
retained first size and first root, a second size and second root, and an
ordered proof, it recomputes both roots from the proof and requires both to
match exactly. It requires `0 < first_size <= second_size`. Equal sizes
require an empty proof and identical roots, which is the exact rule that turns
a same-size root change into a refusal rather than an update.

Both verifiers are pure functions over bounded immutable inputs. They consume
no clock, network, randomness, or ambient state, and they never accept a
"trust the claimed root" shortcut.

Proof node counts and tree sizes are bounded. `MAX_HEAD_PROOF_NODES_V1` is 64,
which admits any tree size representable in the signed 64-bit domain the
protocol already uses, while refusing an unbounded hostile proof.

## Exact roles, codecs, and signature domains

Three new roles complete the four ADR-0008 evidence kinds:

| Role | Evidence kind | Codec profile |
|---|---|---|
| `head_anchor` | `head_anchor_receipt` | `etzio.fixture.signed-anchor-receipt.v1` |
| `head_catalog` | `external_floor` | `etzio.fixture.signed-head-catalog.v1` |
| `head_monitor` | `external_floor` | `etzio.fixture.signed-head-monitor.v1` |

Each role has a distinct Ed25519 signature domain:

```text
etzio.integrity-adapter.head-anchor.signature.v1\x00
etzio.integrity-adapter.head-catalog.signature.v1\x00
etzio.integrity-adapter.head-monitor.signature.v1\x00
```

These domains are also distinct from every ADR-0012 domain, so no time or
revocation package can be replayed into a head-authority role and no
head-authority package can be replayed into a time or revocation role.

`HeadAuthoritySourceBindingV1` has the exact fields `source_id`, `role`,
`log_origin`, `key_id`, `principal_id`, `provider_policy_id`, and
`codec_profile`. Anchor and catalog sources each carry their own log origin.
A monitor carries the log origin it witnesses. A source label never selects
trust implicitly.

`HeadAuthorityTrustProfileV1` has the exact fields `adapter_profile`,
`contract_version`, `service_instance_id`, `environment_id`,
`validation_policy`, `validation_policy_id`, `trust_store`, `trust_root_id`,
`source_bindings`, and `max_head_staleness_seconds`. The canonically sorted
fixed roster requires:

- unique source IDs, key IDs, and principal IDs;
- a trust store containing exactly the roster's keys;
- at least two `head_anchor` sources, each with a distinct log origin;
- exactly one `head_catalog` source; and
- at least two `head_monitor` sources whose log origin equals the catalog's.

At least two anchor logs mean the loss or defection of one log cannot silently
erase the registration record. Exactly one catalog defines the head under
adjudication; the monitors are what make its statement checkable. Distinct
labels, principals, and keys prove logical and cryptographic separation in the
fixture. They do not prove different operators, infrastructure, clocks,
storage, legal entities, or administration.

## Byte-bound anchor registration

The registered object is not a label or a bare digest. It is one closed
canonical record, `AnchorRegistrationLeafV1`, with the exact fields
`contract_version`, `service_instance_id`, `environment_id`, `mission_id`,
`instance_sequence`, `anchor_policy_id`, and `anchor_statement_id`.

The leaf that must appear in the log is exactly
`leaf_hash(canonical_bytes(AnchorRegistrationLeafV1))`. The qualifier
recomputes that leaf hash from the request and refuses any authenticated
receipt whose claimed `leaf_hash` differs. A receipt proving inclusion of some
other statement, another mission, another instance sequence, or another anchor
policy therefore cannot satisfy this request, even when its own inclusion
proof is internally valid.

`HeadAnchorRequestV1` binds contract, profile, trust-root, service,
environment, mission, authority, target, event digest, and transition intent;
the exact source; the anchor policy, instance sequence, and
`anchor_statement_id`; the derived `anchor_leaf_hash`; the exact qualified
time-bundle identity, outer hull, and time-evidence references; the retained
`prior_tree_size` for that source's log; one 256-bit nonce; and a `request_id`
derived from the complete request semantics.

`qualify_anchor_bundle_v1` freshly reauthenticates the ADR-0012 time bundle,
then requires the exact fixed anchor-source roster. For each source it
authenticates the package and requires:

- exact log origin agreement with the retained source binding;
- `leaf_hash` equal to the request-derived anchor leaf hash;
- `0 <= leaf_index < tree_size`;
- a valid RFC 9162 inclusion proof from that leaf to the claimed root;
- `tree_size >= prior_tree_size` for that source, and an equal size retaining
  the exact retained root; and
- `registered_at <= T_L` and `T_U - registered_at <=
  max_head_staleness_seconds` against the complete qualified hull.

Every source must agree exactly on `anchor_statement_id`. Sources are not
required to agree on tree size or root hash: each anchor source is an
independent log with its own geometry, and requiring agreement there would
model one log wearing several labels.

## Catalog head authority and monitor non-equivocation

`HeadCatalogRequestV1` binds the same scope plus the exact retained
predecessor: `prior_tree_size`, `prior_log_root_hash`,
`prior_instance_sequence`, `prior_checkpoint_id`, `prior_mission_event_seq`,
and `prior_mission_checkpoint_id`.

The authenticated catalog claim carries `log_origin`, `tree_size`,
`log_root_hash`, `consistency_proof`, `published_at`, and the complete head
projection: `instance_sequence`, `checkpoint_id`, `checkpoint_attestation_id`,
`checkpoint_principal_id`, `checkpoint_trust_snapshot_id`, `mission_id`,
`mission_event_seq`, `mission_checkpoint_id`,
`mission_checkpoint_attestation_id`, `mission_checkpoint_principal_id`, and
`mission_checkpoint_trust_snapshot_id`.

`qualify_head_catalog_bundle_v1` freshly reauthenticates the time bundle, then
requires exactly one authenticated catalog package and the complete fixed
monitor roster. Accepted qualification requires all of:

```text
tree_size >= prior_tree_size
tree_size == prior_tree_size  implies  log_root_hash == prior_log_root_hash
                                 and   consistency_proof is empty
tree_size >  prior_tree_size  implies  a valid RFC 9162 consistency proof
                                       from (prior_tree_size, prior_log_root_hash)
                                       to   (tree_size, log_root_hash)
published_at <= T_L
T_U - published_at <= max_head_staleness_seconds
instance_sequence >= prior_instance_sequence
mission_event_seq >= prior_mission_event_seq
```

The consistency requirement is what makes a rollback or a fork mechanically
detectable rather than a matter of trust. A catalog that deletes or rewrites
history cannot produce a proof from the retained predecessor root to its new
root.

Every monitor must then agree with the catalog exactly on `log_origin`,
`tree_size`, and `log_root_hash`, and must name the exact catalog source it
witnesses. Its `observed_at` must satisfy the same half-open freshness rule.
Unanimity is required; a single disagreeing monitor refuses the bundle instead
of being outvoted.

This is the split-view check. A catalog that shows one root to Etzio and a
different root to the monitors cannot produce a unanimously cosigned bundle.
Within the deterministic fixture this proves the acceptance rule, not the
existence of independent observers.

The sealed `QualifiedHeadCatalogBundleV1` maps the catalog claim to one
`HeadCheckpointFloorV1` whose `evidence` is the canonically sorted union of
the catalog and monitor evidence references. The floor's own constructor then
reapplies the ADR-0008 genesis, provenance, and mission-not-ahead rules, so a
qualified bundle can never produce a floor that the integrity contract would
reject.

## Provider-neutral mapping and evidence coverage

`map_qualified_head_authority_inputs_v1` freshly reauthenticates the time
bundle, the anchor bundle, and the catalog bundle before constructing a sealed
`QualifiedHeadAuthorityInputsV1` containing:

- `anchor_policy_id`, `anchor_statement_id`, and the canonically sorted
  `head_anchor_receipt` references;
- one `HeadCheckpointFloorV1`; and
- the exact signed evidence BLOBs.

The set of mapped evidence references must equal the set of retained BLOB
references exactly, without duplicates, omissions, or unreferenced extras.
Aggregate retained evidence remains bounded. Directly constructed
`EvidenceReferenceV1` or `HeadCheckpointFloorV1` values remain shape-only and
cannot produce this sealed mapping.

Every consequential qualifier returns a privately sealed exact type. Public
construction, subclasses, changed retained packages, changed derived bodies,
incomplete source mappings, and post-qualification mutation fail closed
through `HeadAuthorityAdapterError` reason codes.

## Deterministic repository-owned harness

`create_repository_owned_head_authority_fixture_v1` deterministically derives
role-separated fixture keys, the exact trust profile and source roster, two
anchor adapters over distinct fixture logs, one catalog adapter, two monitor
adapters, one `HeadAuthorityQualificationVectorV1`, an adapter-implementation
label, and a content-derived corpus-manifest identity from a bounded seed.

The fixture builds real Merkle trees. Each anchor adapter holds an ordered
tuple of leaves whose registered entry is the exact
`AnchorRegistrationLeafV1` bytes, and computes genuine RFC 9162 inclusion
proofs. The catalog adapter holds an ordered leaf tuple and computes a genuine
consistency proof from the retained predecessor size. No proof in the harness
is a precomputed constant, so a broken verifier cannot pass by agreeing with a
broken prover on a fixed value.

`RepositoryOwnedDeterministicHeadAuthorityFixtureV1` requires the anchor,
catalog, and monitor adapters in the exact source-roster order. Reordered,
duplicated, missing, or extra adapters are refused. Every adapter must retain
the exact fixture profile.

The adapters implement the narrow `HeadAnchorAdapterV1`,
`HeadCatalogAdapterV1`, and `HeadMonitorAdapterV1` acquisition protocols.
Their `acquire` methods are pure fixture operations: no socket, credential,
ambient clock, provider discovery, or third-party service is available.

`qualify_repository_head_authority_adapters_v1` executes a fixed case roster:

- exact-retry byte stability and qualification for anchor registration;
- refusal of an anchor package replayed under another request;
- refusal of an anchor receipt proving a different registration leaf;
- exact-retry byte stability and qualification for the catalog head;
- refusal of a catalog head that regresses below the retained tree size;
- refusal of a monitor that cosigns a different root; and
- complete provider-neutral mapping.

The manifest is recomputed from every deterministic input that can affect a
case, including the adapter implementation label, ordered case IDs, profile
and vector identities, each anchor adapter's source, log origin, and ordered
leaf digests, the catalog adapter's ordered leaf digests and head projection,
and each monitor's source and witnessed root. Changing any of them changes the
manifest identity. A case omission, reordering, unexpected disposition,
nondeterministic same-request package, or mapping failure rejects the run
instead of producing a passing report.

`HeadAuthorityQualificationReportV1` is privately sealed. It binds
deterministic fixture labels and results; it is not an attestation about
deployed code bytes, a native provider, or an operational service.

## Claim boundary and deferred integration

This contract and harness establish only that:

- repository-owned Ed25519 fixture statements authenticate under the exact
  retained fixture roots;
- statements bind exact requests, scopes, roles, profiles, policies, and log
  origins;
- an anchor receipt proves RFC 9162 inclusion of the exact byte-bound Etzio
  registration leaf in its own claimed log;
- a catalog head proves RFC 9162 consistency with the exact retained
  predecessor root, and equal sizes cannot change roots;
- unanimous monitor witnesses agree exactly on the catalog's log origin, tree
  size, and root hash; and
- sealed results map reproducibly to the existing provider-neutral
  `head_anchor_receipt` references and `HeadCheckpointFloorV1` values while
  retaining the exact signed BLOBs.

They do not establish:

- truthful UTC, a production trusted clock, or real publication time;
- legal, operational, or independently administered provider authority;
- separate operators, infrastructure, clocks, administration, or storage;
- external durability, availability, or survival of local database loss;
- real-world non-equivocation, since the fixture monitors are repository-owned
  and a real split view requires genuinely independent observers;
- native RFC 9162, RFC 9942, RFC 9943, SCITT, or Rekor conformance, since no
  native wire format, certificate path, or provider client is parsed;
- safe provider networking, credential custody, privacy, spending, retention,
  disclosure, or incident response;
- lifecycle finality, durable blocked-finality adjudication, or governed
  recovery;
- closure of the same-user pathname, coherent offline rewrite, storage,
  backup, process-kill, power-fault, encryption, or evidence-retention
  boundaries; or
- execution, independent verification, a finding, live-target authority, or
  bounty readiness.

The current `PendingIntegrityTransitionV1` path remains fixture-specific and
does not consume `QualifiedHeadAuthorityInputsV1`. Its validators
intentionally accept only the enrolled modeled-fixture claim shape.
Integrating qualified head authority requires a later admitted profile and
storage/lifecycle tranche that preserves empty-history activation, exact
profile and package retention, event-plus-pending atomicity, all four
immutable recovery phases, the database-global unresolved-transition barrier,
byte-identical at-least-once retry, provider calls outside SQLite
transactions, exact global and mission continuity, generic pending-replay
refusal, and store-domain error classification.

Durable blocked-finality disposition and governed recovery remain a separate
gate with their own decision record, as does connection of any independently
administered provider.

## Consequences

- All four ADR-0008 integrity evidence kinds now have a deterministic,
  networkless acceptance boundary.
- Head authority is decided by recomputed Merkle proofs, not by a claimed
  root, a source label, or a digest comparison.
- Rollback and fork of a catalog log become mechanically detectable.
- Non-equivocation has an implemented acceptance rule that is ready for
  genuinely independent witnesses, without claiming to have them.
- Strict all-source semantics prefer fail-closed auditability over
  availability. A future threshold or Byzantine witness policy requires a new
  explicit contract version.
- Native provider parsing and acquisition remain deferred adapters outside
  this lifecycle tranche.

## Rejected alternatives

### Compare claimed root hashes instead of verifying proofs

A claimed root is provider-controlled. Without recomputing the root from the
leaf and proof, a log can assert any history. Inclusion and consistency
verification is the only part that makes the claim falsifiable.

### Accept an anchor receipt bound only to `anchor_statement_id`

A digest field inside a claim is provider-controlled text. Deriving the leaf
hash from an Etzio-owned closed canonical record, and requiring the claim to
match it exactly, is what makes the registration byte-bound.

### Treat monitor disagreement as a majority vote

A split view is exactly the case where a minority is right. V1 requires
unanimity and refuses. Threshold behavior requires a new contract with
explicit Byzantine assumptions and a defined honest-witness bound.

### Let a catalog skip the consistency proof on its first observation

The retained predecessor is what makes rollback detectable. V1 requires a
positive retained tree size and root before qualification, so the genesis case
belongs to the later lifecycle-integration tranche that defines how a head
authority is first admitted.

### Use local wall time or arrival time as head freshness

Both are observations outside qualified evidence. V1 evaluates freshness only
against the ADR-0012 conservative time hull.

### Reuse the ADR-0012 module and signature domains

Sharing a role namespace would let a time or revocation package authenticate
into a head-authority role. Distinct modules, profiles, codecs, and signature
domains keep the two boundaries independently versionable.

### Integrate directly into pending finality

The existing pending-transition validator is deliberately fixture-specific.
Changing lifecycle consumption before separately proving retention, recovery,
retry, and continuity would blur qualification with authority.
