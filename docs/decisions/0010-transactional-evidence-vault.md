# ADR-0010: Transactional canonical evidence vault

- Status: accepted
- Date: 2026-07-29
- Owner: Daniel Wahnich

## Context

Before this decision, Etzio published evidence bytes to a private filesystem
content-addressed store before appending the event that claimed those bytes were
available. Receipt admission repeated current-CAS validation while holding the SQLite
writer transaction, but the filesystem bytes and canonical event did not share one
commit. An interrupted writer or same-user filesystem action could therefore leave either
unreferenced staging bytes or a retained event whose referenced bytes were no longer
available.

Four canonical event kinds make an actual byte-availability claim:

| Event kind | Bytes required and atomically mapped at this boundary |
|---|---|
| `authority_admitted` | authority evidence under the generic evidence digest |
| `mission_opened` | every target-snapshot source file under its generic digest |
| `verification_artifacts_resolved` | exact target dependencies and typed PoC, supporting-evidence, environment, and effect-oracle inputs |
| `verifier_receipt_admitted` | four typed execution, effect, measured-environment, and termination outputs |

The resolution event remaps its target dependencies from the already canonical
`mission_opened` target; only its typed verification inputs can be first-seen bytes at
that boundary.

Verification-lease issuance and reassignment intentionally declare unresolved future
inputs. Candidate and parse events refer to target bytes already retained at mission
opening. Treating either category as a new byte-ingestion boundary would change protocol
meaning rather than close the storage gap.

## Decision

The SQLite event database becomes the canonical immutable evidence vault for every byte
claimed by those four events. `FileEvidenceStore` remains the bounded, private staging and
cache surface used before first canonical ingestion. Filesystem availability after commit
is no longer a replay invariant.

The store adds two strict append-only relations:

- a deduplicated artifact relation uniquely keyed by exact identity scheme, exact
  typed-artifact discriminator when applicable, and digest, retaining the byte-checked
  size and exact BLOB; and
- an event-artifact relation binding one event digest to a code-owned role, ordinal,
  optional locator, exact identity scheme, type, digest, and size.

Each first-seen BLOB also retains the exact event digest that introduced it. That
`origin_event_digest` is immutable when later events or missions reuse the physical row,
must identify an event that maps the same exact identity and size, and has a deferred
foreign key to canonical event history. A covering reverse index over artifact identity,
size, and event digest supports that provenance check without scanning every role mapping.
The identity plus size is also a candidate key for exact mapping foreign keys; size is a
checked dependent attribute, not an independent deduplication identity.

Generic target and authority evidence retain the existing
`etzio:evidence:v1` digest domain. Typed verification inputs and outputs retain the
existing `etzio:evidence:typed:v1` domain plus their exact closed artifact type. Semantic
labels never choose the hash function, and a caller cannot supply a manifest, role, type,
membership assertion, or ordering decision independently of the canonical event. Sizes
carried by authority, target, resolution, or receipt semantics are always checked against
the exact retained bytes before they enter a vault mapping.

One protected append executes the following under a single `BEGIN IMMEDIATE` transaction:

1. decode and reduce the complete retained mission stream;
2. compare the expected head and validate the proposed lifecycle transition;
3. derive the exact required artifact set from canonical event and retained-history bytes;
4. resolve already-canonical dependencies from the SQLite vault and new dependencies from
   the staging CAS;
5. bound, read, rehash, type-check, size-check, and byte-compare every artifact;
6. insert new immutable BLOBs or prove an existing identity retains the same exact bytes;
7. insert the exact event-artifact mappings;
8. insert the canonical event last; and
9. compare the persisted mapping set to the code-derived set before commit.

The event mapping uses a deferred foreign key so mappings can precede their event inside
the transaction. Database triggers provide defense-in-depth: protected events require a
coarse kind-appropriate mapping shape, and artifact and mapping rows reject update and
delete. Code remains responsible for cryptographic validation and exact dynamic manifest
equality because SQLite row triggers cannot parse or authenticate canonical protocol
BLOBs.

Generic append rejects all four protected kinds. The first three use one dedicated
evidence-retaining append; receipt admission keeps its separately authenticated dedicated
path and then enters the same vault primitive. Internal append helpers enforce the same
pairing so an alternate public call path cannot omit retention.

The pure `validate_verifier_receipt` API remains a non-authoritative proposal check over
the filesystem evidence view supplied by its caller. Canonical
`admit_modeled_fixture_verifier_receipt` revalidates under the locked writer transaction
through a vault-first overlay and consults staging only for genuinely first-seen output
identities. Only that canonical admission path enters this decision's atomic-retention
boundary.

Every mission load and locked replay checks exact mapping completeness, rejects missing or
extra rows, verifies stored types and sizes, and rehashes each unique retained BLOB under
its declared digest domain. Committed exact retries reconstruct historical state from the
vault without requiring mutable staging bytes. Vault corruption never falls back to the
filesystem CAS.

Vault reads have exact bounded batch forms in addition to scalar compatibility wrappers.
A batch accepts at most 515 exact selectors or role-derived resolution requests and at
most 1 GiB of selected unique response identities. Identity resolution follows immutable
first-origin events; selector loads follow their exact event owners. Each distinct
required mission is reduced once, and one shared rehash set ensures that each distinct
BLOB encountered across those complete histories is read and hashed at most once for the
batch. Only requested identities are retained in the response cache. Production target,
verification-input, and receipt-output paths use the batch forms; the scalar methods
remain single-request wrappers.

The selected-response ceiling is not a claim that integrity-validation I/O is limited to
the returned bytes. Validating a required mission deliberately verifies all protected
manifests and distinct BLOBs in that complete retained history. The configured vault
ceiling and protocol event bounds constrain that work independently.

The storage schema has an Etzio application identifier and explicit user version. A
recognized empty unversioned layout may be initialized atomically. Malformed, unknown, or
nonempty pre-vault state is not silently promoted. A nonempty legacy event database
requires an explicit stop-the-world migration that reconstructs every protected manifest,
imports and rehashes every referenced byte, proves complete event coverage, and only then
changes the schema version. This tranche supplies refusal, not that migration.

All existing protocol bounds remain cumulative even when physical BLOB rows deduplicate:

- authority evidence has a new fixed 16 MiB ingestion ceiling;
- target snapshots remain at most 256 files and 64 MiB total;
- one artifact resolution remains at most 128 MiB total, including at most 64 MiB of typed
  inputs and the authority grant's tighter signed `max_bytes`;
- receipt output remains exactly four positive artifacts and at most 64 MiB total; and
- resolution plus output bytes remain under the grant's one non-resetting byte ceiling.

Each store opening enforces an exact configured positive signed-int64 logical unique-BLOB
ceiling, defaulting to 1 GiB. The ceiling sums each distinct
identity-scheme/type/digest row once and is operational configuration, not canonical
authority or persisted policy; a later opening can supply a different ceiling.
Deduplication never reduces a mission's logical signed byte use. SQLite pages,
rollback-journal headroom, backups, and device capacity require separate operational
quotas.

The first implementation uses bounded direct BLOB insertion. It does not use writable
incremental-BLOB handles: writable handles can mutate a BLOB without firing ordinary
`UPDATE` triggers, so introducing them would invalidate the stated append-only defense.
Any later streaming ingestion requires a separately reviewed unpublished/sealed state
machine and must not expose a writable handle to canonical bytes.

## Consequences

- Under SQLite's documented rollback-journal, VFS, filesystem, and durability assumptions,
  crash recovery observes the complete event, exact mappings, and newly claimed bytes, or
  their pre-transaction state. The repository controls exercise exception rollback and
  post-commit recovery; they are not a power-cut qualification.
- Staging deletion after a successful commit cannot erase the canonical evidence required
  for deterministic replay or exact retry.
- Reused canonical artifact identities share one SQLite row while every event retains its
  complete logical role and ordering record. Equal raw bytes in generic versus typed, or
  in two different typed, digest domains intentionally remain separate identities.
- A missing artifact, digest/type substitution, byte collision, partial mapping, orphan
  canonical BLOB, stale-head loser, or quota failure cannot produce a protected event.
- Backups and recovery procedures must copy the whole SQLite database, including evidence
  BLOBs and mappings. The event database is no longer metadata-only and inherits the
  confidentiality requirements of retained fixture and modeled evidence bytes.
- The canonical event and semantic wire formats do not change; this is a versioned storage
  contract.

## Claim boundary and residual risks

This decision closes the ordinary filesystem-CAS/SQLite event-retention split for the four
implemented byte-claiming boundaries. It does not prove the truth, provenance,
independence, execution, effect, termination, environment measurement, or finding status
of any retained byte.

SQLite rollback journaling still relies on the admitted SQLite library, VFS, filesystem,
kernel, device, locking, flush, and power-loss assumptions. The documented Python
SQLite pathname race remains: a hostile process under the same OS user can replace or
rewrite database, journal, schema, or trigger state. Closing that boundary requires an
isolated service identity and protected descriptor-based or equivalent storage adapter.
Externally authenticated latest heads remain necessary to detect coherent offline
rewrites.

The vault does not establish trusted time, revocation freshness, external head finality,
verifier isolation, live-target authority, egress authority, spending authority,
disclosure authority, or structured independently produced execution evidence. Opaque
modeled receipt outputs remain opaque modeled statements.

## Implementation references

The storage contract is grounded in the current primary SQLite and CPython documentation:

- [SQLite atomic commit](https://www.sqlite.org/atomiccommit.html) for rollback-journal
  transaction and recovery assumptions;
- [SQLite `synchronous` and application pragmas](https://www.sqlite.org/pragma.html) for
  `EXTRA`, `application_id`, `user_version`, and `trusted_schema`;
- [SQLite strict tables](https://www.sqlite.org/stricttables.html) for rigid storage types
  and integrity checking;
- [SQLite deferred foreign keys](https://www.sqlite.org/foreignkeys.html#fk_deferred) for
  mapping-before-event insertion with commit-time closure;
- [SQLite trigger semantics](https://www.sqlite.org/lang_createtrigger.html) for the
  row-level defense-in-depth boundary; and
- [CPython `sqlite3.Blob`](https://docs.python.org/3/library/sqlite3.html#sqlite3.Blob) for
  incremental BLOB handle behavior and the explicit `readonly` control.

## Rejected alternatives

### Keep repeated filesystem reads inside the SQLite writer transaction

Holding the writer lock narrows a race but cannot make a filesystem unlink and SQLite
commit one atomic state transition. A valid read can still be followed by byte loss.

### Retain only resolution and receipt artifacts

That would close the newest modeled-verification gap while leaving authority evidence and
mission target opening under the same split-store failure. It would not support a claim
that Etzio's implemented byte-claiming boundaries are closed.

### Embed evidence bytes in canonical event payloads

This would change protocol identities, duplicate shared bytes, inflate replay objects, and
mix semantic history with storage representation. Exact immutable event-to-BLOB mappings
preserve both boundaries.

### Let callers provide artifact manifests

The manifest is the condition under evaluation. Caller-selected roles, types, order, or
membership would recreate the substitution authority removed by ADR-0005 and ADR-0006.

### Auto-backfill legacy events from current filesystem state

Later filesystem availability cannot prove that bytes were atomically retained with an
earlier event. Silent backfill would relabel historical event-only state as a guarantee it
never had.

### Use writable incremental-BLOB I/O as an implementation detail

Writable BLOB handles bypass ordinary row-update triggers. Without a separate sealing
protocol, that optimization would make the immutable-vault claim false.
