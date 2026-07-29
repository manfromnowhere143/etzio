# ADR-0012: Networkless trusted-time and revocation adapter qualification

- Status: accepted
- Date: 2026-07-29
- Owner: Daniel Wahnich

## Context

ADR-0008 defines provider-neutral `IntegrityDecisionV1` and
`HeadCheckpointV1` contracts. They retain conservative time intervals, typed
provider-evidence references, versioned revocation views, external rollback
floors, and exact policy identities. ADR-0011 exercises those contracts through
one repository-owned deterministic finality service.

That service deliberately stops before provider qualification:

- `EvidenceReferenceV1` binds an evidence kind, source label, and byte digest,
  but does not authenticate the bytes or the represented source;
- `ProviderEvidenceBlobV1` proves exact byte identity, not signature validity,
  truthful time, current revocation state, or provider independence;
- direct `RevocationViewV1` and `RevocationFloorV1` construction validates
  provider-neutral shape only; and
- the current pending-transition path accepts only exact code-derived fixture
  assertions.

Connecting a provider before closing this boundary would let
caller-controlled labels and bytes appear authoritative. Implementing a native
RFC 3161, PKIX, TUF, or provider client inside the lifecycle kernel would
instead combine parsing, network behavior, provider selection, and authority
policy before a common acceptance boundary was proved.

The next dependency-complete tranche is therefore a deterministic,
networkless contract and qualification harness for repository-owned
trusted-time and revocation fixture adapters. It proves authentication,
request binding, conservative fusion, freshness, rollback checks, and exact
mapping to the existing ADR-0008 provider-neutral values. It does not change
lifecycle finality or connect a real provider.

## Decision

Etzio implements the V1 contract in
`etzio/kernel/integrity_adapters_v1.py`. The contract has closed canonical
records, a fixed source roster, role-separated Ed25519 fixture signatures,
sealed authenticated results, fresh reauthentication, and a kernel-owned
deterministic harness.

V1 is intentionally strict:

- `adapter_profile` is exactly
  `repository_owned_networkless_time_revocation_v1`;
- `contract_version` is exactly `1` wherever the implemented record carries
  that field;
- every required source is present; callers cannot select a quorum subset;
- the profile binds the complete validation policy, trust store, source
  roster, codec profile, provider policy, service, and environment;
- no operating-system trust store, wall clock, network response, cache,
  credential, or environment variable contributes authority;
- a provider claim is parsed only after the exact signed statement bytes
  authenticate;
- trusted-time qualification retains the conservative outer hull of all
  accepted intervals;
- revocation qualification uses that complete hull for validity and freshness,
  and requires exact metadata-plus-floor agreement; and
- provider-neutral mappings are derived only from freshly reauthenticated,
  sealed bundles whose exact signed bytes cover every evidence reference.

The implementation uses Etzio canonical JSON with exact field sets and
content-derived identities. It does not invent a generic `record_kind` or
`record_version` envelope and does not add a protocol-v1 semantic wire kind.
The V1 signed fixture codec is not a generic provider package format.

## Exact trust profile

### `TrustedAdapterKeyV1` and `IntegrityAdapterTrustStoreV1`

`TrustedAdapterKeyV1` has the exact constructor fields:

- `source_id`;
- `principal_id`;
- `role`; and
- `public_key_bytes`.

The role is one of `trusted_time`, `revocation_metadata`, or
`revocation_floor`. The public key must be a valid prime-subgroup Ed25519 key.
`key_id` is derived from the exact key bytes. Including `source_id`,
`principal_id`, and `role` prevents one admitted fixture key from silently
changing logical identity or evidence role.

`IntegrityAdapterTrustStoreV1` has the exact inputs `keys` and
`revoked_key_ids`. It copies and canonically sorts the bounded key mapping,
copies the bounded revoked-key set, and derives `root_id` from the complete
canonical body. It admits no ambient key lookup or replacement root.

### `AdapterSourceBindingV1`

One source binding has the exact fields:

- `source_id`;
- `role`;
- `namespace`;
- `key_id`;
- `principal_id`;
- `provider_policy_id`; and
- `codec_profile`.

Trusted-time sources require `namespace=None`. Revocation sources require one
namespace. The codec profile is fixed by role:

- `etzio.fixture.signed-time.v1`;
- `etzio.fixture.signed-revocation-metadata.v1`; or
- `etzio.fixture.signed-revocation-floor.v1`.

A source label never selects trust implicitly. Source, role, namespace, key,
principal, provider policy, and codec must all match the retained profile.

### `IntegrityAdapterTrustProfileV1`

The trust profile has the exact fields:

- `adapter_profile`;
- `contract_version`;
- `service_instance_id`;
- `environment_id`;
- `validation_policy`;
- `validation_policy_id`;
- `trust_store`;
- `trust_root_id`;
- `source_bindings`; and
- `max_revocation_staleness_seconds`.

`validation_policy` is an exact copied `IntegrityValidationPolicyV1`;
`validation_policy_id` must match its canonical body. `trust_root_id` must
match the exact copied `trust_store`. `profile_id` is derived from the complete
canonical profile body.

The canonically sorted fixed roster requires:

- unique source IDs, key IDs, and principal IDs;
- a trust store containing exactly the roster's keys;
- at least two trusted-time sources;
- exactly one revocation-metadata source for every policy-required namespace;
- at least two revocation-floor sources for every required namespace; and
- no revocation namespace outside or missing from the policy.

Distinct labels, principals, and keys prove logical and cryptographic
separation in the fixture. They do not prove different operators,
infrastructure, clocks, storage, legal entities, or administration.

The profile has no independent time-hull field. The purpose-selected limits
come from the copied validation policy:
`max_decision_uncertainty_seconds` or
`max_checkpoint_uncertainty_seconds`.

## Exact requests and signed fixture evidence

### `TrustedTimeRequestV1`

One source-specific time request binds:

- contract, profile, and trust-root identities;
- service instance and environment;
- mission, authority, target, event, and transition intent;
- exact source;
- purpose, restricted to `decision` or `checkpoint`;
- the corresponding validation-policy time-policy identity;
- one content identity for the message imprint;
- one 256-bit request nonce; and
- a `request_id` derived from the complete request semantics.

All required time sources receive source-specific requests with one shared
bundle context. Retry reuses the same request. A changed source, nonce,
imprint, purpose, event, transition, scope, profile, root, or policy produces a
different request.

### `RevocationRequestV1`

One source-specific revocation request binds:

- contract, profile, trust-root, service, and environment;
- mission, authority, target, event, and transition intent inherited from a
  sealed decision-time bundle;
- source, role, namespace, and decision-policy identity;
- the exact qualified time-bundle identity, outer interval, and time-evidence
  references;
- retained predecessor root version, metadata version, and snapshot identity;
- one 256-bit request nonce; and
- a `request_id` derived from the complete request semantics.

The request does not contain a caller-proposed current revocation state. The
authenticated provider claims supply the candidate current state, and the
qualifier compares every required source before accepting it.

### `ProviderEvidenceStatementV1` and `SignedProviderEvidenceV1`

`ProviderEvidenceStatementV1` is the signed inner statement. It binds
`contract_version`, `profile_id`, `trust_root_id`, service, environment,
source, role, `provider_policy_id`, `request_id`, and one closed claim object.

`SignedProviderEvidenceV1` is the bounded outer wrapper. Its exact fields are:

- `evidence_role`;
- `key_id`;
- `statement_bytes`;
- `signature_bytes`; and
- `algorithm`, which is exactly `ed25519`.

The three roles use distinct signature domains. A role's signature covers its
domain followed by the exact canonical `statement_bytes`.

Authentication is deliberately ordered:

1. copy and reconstruct the profile, request, and bounded outer wrapper;
2. resolve the exact source binding and source-bound key from the copied
   profile;
3. reject role, key, revocation, or algorithm mismatches;
4. verify the Ed25519 signature over the still-opaque statement bytes;
5. only then parse the canonical `ProviderEvidenceStatementV1`;
6. require exact profile, root, service, environment, source, role,
   provider-policy, and request binding; and
7. validate the exact role-specific claim fields.

`authenticate_provider_evidence_v1` is the public authentication entrypoint.
It returns a sealed `AuthenticatedProviderEvidencePackageV1` containing the
reconstructed request, exact `SignedProviderEvidenceV1`, parsed statement,
copied source binding, exact claim, and one `ProviderEvidenceBlobV1`.
Construction is private and exact subclasses are not accepted at
consequential entrypoints.

The evidence BLOB contains the complete canonical bytes of
`SignedProviderEvidenceV1`, including the exact signed statement and
signature. Its reference is derived from those bytes. A cached parsed claim or
caller-created evidence reference cannot replace reauthentication.

This is an Ed25519 repository-fixture transport. It contains no native
certificate chain, timestamp token, TUF metadata closure, transparency proof,
or provider response. No native RFC 3161, PKIX, TUF, COSE, SCITT, Rekor, or
named-provider conformance follows.

## Conservative trusted-time qualification

`qualify_time_bundle_v1` requires an exact request and signed-evidence mapping
whose keys equal the complete fixed trusted-time roster. It authenticates
every source and requires all requests to share the same profile, root, scope,
mission, authority, target, event, transition, purpose, time policy, imprint,
and nonce.

For authenticated source intervals `[L_i, U_i]`, V1 requires:

```text
L_i <= U_i
max(L_i) <= min(U_i)
U_i - L_i <= purpose_max_uncertainty
max(U_i) - min(L_i) <= purpose_max_uncertainty
```

The second condition requires a nonempty common overlap. The accepted
interval remains the conservative outer hull:

```text
time_lower_bound = min(L_i)
time_upper_bound = max(U_i)
```

The purpose-selected maximum is
`validation_policy.max_decision_uncertainty_seconds` for `decision` and
`validation_policy.max_checkpoint_uncertainty_seconds` for `checkpoint`.
Using the intersection would erase authenticated disagreement and claim more
precision than all retained evidence supports.

The sealed `QualifiedTimeBundleV1` retains the reconstructed requests, exact
signed evidence, authenticated packages, outer hull, context, and exact
evidence BLOBs. `reauthenticate_time_bundle_v1` rebuilds it from retained
requests and signed evidence and compares the complete derived body.

Nonce and exact request binding prevent an old signed statement from
satisfying a new request. They do not prove that the fixture intervals are
truthful UTC. Local wall time, file timestamps, package arrival time, or test
execution time never narrow the interval.

## Revocation validity, freshness, and floors

`qualify_revocation_bundle_v1` first freshly reauthenticates the exact
decision-time bundle. For one required namespace it then requires the exact
fixed request and signed-evidence mappings: one metadata source and every
configured floor source.

Every source request must bind the same predecessor. The authenticated metadata
claim and all authenticated floor claims must agree exactly on:

- root version;
- metadata version;
- snapshot identity;
- `valid_from`;
- `valid_until`; and
- `published_at`.

For qualified time hull `[T_L, T_U]`, accepted validity and freshness require:

```text
valid_from <= T_L
T_U < valid_until
published_at <= T_L
T_U - published_at <= max_revocation_staleness_seconds
```

The half-open validity rule rejects a hull touching `valid_until`. A
future-published or stale state cannot be repaired with arrival time or the
local wall clock.

Relative to the request-bound predecessor, V1 also requires:

- current root version is not lower;
- when the predecessor root version is positive, a root update does not skip
  more than one version;
- current metadata version is not lower; and
- equal metadata versions retain the same root version and snapshot identity.

The sealed `QualifiedRevocationBundleV1` maps the metadata package to one
`RevocationViewV1` and the complete floor-package set to one
`RevocationFloorV1`. It retains every request, exact signed package,
authenticated package, state field, and evidence BLOB.
`reauthenticate_revocation_bundle_v1` reconstructs the result and compares the
complete derived body.

`ExpectedRevocationStateV1` is only the deterministic fixture's expected
current state plus retained predecessor. It is not a provider-neutral
production record and does not cross the authentication boundary by itself.

## Provider-neutral mapping and evidence coverage

`map_qualified_integrity_inputs_v1` requires the complete required namespace
set. It freshly reauthenticates the time bundle and every namespace's
revocation bundle before constructing a sealed `QualifiedIntegrityInputsV1`.
Each mapping key must equal its sealed bundle's namespace; exchanging two
otherwise valid namespace bundles is refused rather than normalized by the
bundle contents.

The mapping contains:

- the qualified time bounds, time policy, and time references;
- namespace-complete `RevocationViewV1` values;
- namespace-complete `RevocationFloorV1` values; and
- the exact signed evidence BLOBs.

The set of mapped evidence references must equal the set of retained BLOB
references exactly, without duplicates, omissions, or unreferenced extras.
Aggregate retained evidence remains bounded. Directly constructed
`EvidenceReferenceV1`, `RevocationViewV1`, or `RevocationFloorV1` values remain
shape-only and cannot produce this sealed mapping.

Every consequential qualifier returns a privately sealed exact type. Public
construction, subclasses, changed retained packages, changed derived bodies,
incomplete source mappings, and post-qualification mutation fail closed
through `IntegrityAdapterError` reason codes.

## Deterministic repository-owned harness

`create_repository_owned_adapter_fixture_v1` deterministically derives from a
bounded seed:

- role-separated fixture keys and signers;
- the exact trust profile and source roster;
- two fixed trusted-time adapters;
- one metadata and two floor adapters per requested namespace;
- one `IntegrityAdapterQualificationVectorV1`;
- an adapter-implementation label; and
- a content-derived corpus-manifest identity.

`RepositoryOwnedDeterministicAdapterFixtureV1` requires the time-adapter and
revocation-adapter tuples in the exact source-roster order. Reordered,
duplicated, missing, or extra adapters are refused. Every adapter must retain
the exact fixture profile, and every revocation adapter's namespace and full
`ExpectedRevocationStateV1` body must equal the vector's expectation for that
namespace.

The adapters implement the narrow `TrustedTimeAdapterV1` and
`RevocationAdapterV1` acquisition protocols. Their `acquire` methods are pure
fixture operations: no socket, credential, ambient clock, provider discovery,
or third-party service is available.

`qualify_repository_time_revocation_adapters_v1` executes a fixed case roster:

- exact-retry byte stability and qualification for decision time;
- exact-retry byte stability and qualification for checkpoint time;
- refusal of a decision-time package replayed under another request;
- exact-retry byte stability and qualification for each revocation namespace;
  and
- complete provider-neutral mapping.

The manifest is recomputed from every deterministic input that can affect a
case:

- `adapter_implementation_id`;
- the exact ordered case IDs;
- `profile_id` and `vector_id`;
- the ordered trusted-time adapter inputs, including each `source_id`,
  `time_lower_bound`, and `time_upper_bound`; and
- the ordered revocation adapter inputs, including each `role`, `source_id`,
  and complete expected state body.

Changing an interval, role, source, state, adapter order, implementation label,
profile, vector, or case roster therefore changes the manifest identity.
A case omission, reordering, unexpected disposition, nondeterministic
same-request package, wrong expected state, or mapping failure rejects the run
instead of producing a passing report.

`IntegrityAdapterQualificationReportV1` is privately sealed and contains
exactly:

- `contract_version`;
- `adapter_implementation_id`;
- `profile_id`;
- `vector_id`;
- `corpus_manifest_id`;
- the ordered `IntegrityAdapterQualificationCaseV1` tuple; and
- `overall_disposition`.

Each case records its ID, expected and observed disposition, reason code, and
result identity. The report binds deterministic fixture labels and results; it
is not an attestation about deployed code bytes, a native provider, or an
operational service.

The broader conformance tests exercise known-bads at the contract boundaries,
including profile and root substitution, confused source/key/principal/role
bindings, noncanonical records, signed framing and claim substitution,
cross-request replay, wrong roles or keys, invalid signatures, malformed or
reversed time claims, incomplete source rosters, disjoint intervals,
source-width and outer-hull overflow, mixed request contexts, direct sealed
construction, noncanonical or duplicate fixture-adapter tuples,
source-mapping key substitution, namespace-key/bundle substitution, manifest
input substitution, exact retry, and absence of clock or network dependence.
Every new consequential refusal requires its own deterministic known-bad.

## Claim boundary and deferred integration

This contract and harness establish only that:

- repository-owned Ed25519 fixture statements authenticate under the exact
  retained fixture roots;
- statements bind exact requests, scopes, roles, profiles, and policies;
- fixture time intervals fuse conservatively;
- fixture revocation claims satisfy the implemented validity, freshness,
  agreement, and predecessor rules; and
- sealed results map reproducibly to existing provider-neutral values while
  retaining the exact signed BLOBs.

They do not establish:

- truthful UTC or a production trusted clock;
- current real-world revocation state;
- legal, operational, or independently administered provider authority;
- separate operators, infrastructure, clocks, administration, or storage;
- external durability, availability, consistency, or non-equivocation;
- native timestamp, PKI, update-framework, or transparency-log conformance;
- safe provider networking, credential custody, privacy, spending, retention,
  disclosure, or incident response;
- anchor registration, checkpoint publication, head-catalog, or monitor
  authority;
- lifecycle finality, durable blocked-finality adjudication, or recovery;
- external latest-head survival after local loss;
- closure of same-user pathname, coherent offline rewrite, storage, backup,
  process-kill, power-fault, encryption, or evidence-retention boundaries; or
- execution, independent verification, a finding, live-target authority, or
  bounty readiness.

The current `PendingIntegrityTransitionV1` path remains fixture-specific and
does not consume `QualifiedIntegrityInputsV1`. Integrating qualified adapter
results requires a later admitted profile and storage/lifecycle tranche. That
tranche must preserve:

- empty-history activation or an equally strong non-backfill rule;
- exact profile, root, policy, request, and signed-package retention;
- event-plus-pending atomicity;
- all immutable local recovery phases;
- the database-global unresolved-transition barrier;
- byte-identical at-least-once retry;
- provider calls outside SQLite transactions;
- exact global and mission continuity;
- generic pending-replay refusal; and
- store-domain error classification.

The qualification report must never be reinterpreted as time, revocation,
provider evidence, lifecycle authority, or external-provider approval.
Anchor, catalog, monitor, durable blocked recovery, native-provider
qualification, and provider connection remain separate gates.

## Consequences

- Fixture trust roots, policies, source rosters, and codecs have exact
  content-derived identities before provider-like bytes can influence
  ADR-0008 values.
- Source labels alone are not an authentication boundary.
- Time precision cannot improve by discarding an authenticated required
  source.
- Revocation freshness depends on the complete qualified time hull and exact
  metadata-plus-floor agreement.
- Strict all-source semantics prefer fail-closed auditability over
  availability. A future threshold policy requires a new explicit contract
  with Byzantine and subset-selection semantics.
- Native provider parsing and acquisition remain deferred adapters outside
  this lifecycle tranche.

## Rejected alternatives

### Treat source labels and content digests as authentication

A digest establishes byte identity. It does not establish who produced the
bytes, which root and policy admitted them, whether they answer this request,
or whether their claims are fresh.

### Parse claims before signature verification

Provider-controlled semantics must not influence trust lookup, interval
fusion, freshness, version, or floor logic before the exact signed statement
authenticates.

### Fuse time by interval intersection

Intersection would erase authenticated disagreement and understate
uncertainty. V1 requires overlap for consistency but retains the outer hull.

### Accept any policy-sized source subset

A caller could omit a dissenting source and select the result. V1 requires the
entire fixed roster. Threshold behavior requires a new contract version.

### Use local wall time or arrival time as freshness

Both are observations outside qualified evidence. They cannot narrow a
provider interval or make revocation metadata current.

### Treat the fixture codec as native-provider conformance

The fixture codec proves Etzio's common authentication and qualification
boundary. Native formats require their own exact parsers, roots, policies,
proof closure, deterministic corpus, and independent qualification.

### Integrate directly into pending finality

The existing pending-transition validator is deliberately fixture-specific.
Changing lifecycle consumption before separately proving retention, recovery,
retry, and continuity would blur qualification with authority.
