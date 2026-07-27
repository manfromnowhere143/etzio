# ADR-0003: Semantic wire schema and typed-kind closure

- Status: accepted
- Date: 2026-07-27
- Owner: Daniel Wahnich

## Context

Protocol v1 had one strict canonical envelope and typed Python parsers, but its checked-in
JSON Schema validated only the six framing fields. It accepted arbitrary bodies,
attestations on kinds that forbid them, and an `event` with no lifecycle-recognized shape.
The runtime allowlist also admitted the name `head_checkpoint` even though checkpoint
storage is an opaque, unauthenticated record with no protocol-v1 body or parser.

The schema existed only in the source distribution. Installed wheels therefore could not
load the contract they were expected to emit or consume. Repository policy checked only
that each schema was valid against its metaschema; it did not detect dispatch drift.

The parity audit also found two runtime gaps:

- a signed authority-grant object checked signature length but not canonical Base64; and
- the target, candidate, and event path validators accepted the literal `"."`.

The adversarial portability pass found that bare `\S` has different edge-whitespace
semantics in Python and ECMA-262 regex engines. U+001C through U+001F, U+0085, and U+FEFF
could therefore make schema acceptance depend on the validator implementation. It also
found that whole-object `uniqueItems` cannot express uniqueness keyed by fields such as
target `relative_path` or trust-key `key_id`.

## Decision

Etzio protocol v1 now has:

- exactly eight supported object kinds, each with a typed runtime parser and an exact
  semantic schema branch;
- a fail-closed semantic dispatcher shared by parity fixtures;
- exact signed and unsigned authority-grant and verifier-receipt wire forms;
- twelve exact event kind, unit, and payload branches derived against exported immutable
  runtime contract maps;
- one immutable per-kind body-field registry used by typed parsers and checked against
  closed schema bodies by repository policy;
- one canonical Draft 2020-12 schema installed as `etzio.schemas` package data and loaded
  with duplicate-key rejection;
- repository-policy checks for exact envelope, body, attestation, kind, branch, event-unit,
  and payload-field parity;
- canonical Base64 validation at signed authority-grant construction;
- semantic grant validation before a signed authority carrier can emit or publicly parse
  protocol wire;
- an explicit, cross-validator edge-whitespace pattern aligned with the protocol runtime;
  and
- rejection of `"."` at every implemented relative-path boundary.

`head_checkpoint` remains a reserved future name but is no longer a supported generic
protocol-v1 object kind. A future authenticated checkpoint must introduce an exact typed
contract and a new compatible protocol decision before the name can be admitted. This
supersedes ADR-0002 only where it described `head_checkpoint` as framing-supported.

The three original `finding`, `target-contract`, and `verdict` schemas remain repository
behavior models. They are explicitly marked modeled and non-authoritative and are not
installed as protocol package data.

## Schema authority boundary

The semantic schema is a structural preflight guard. It proves exact fields, constants,
enums, scalar bounds, array cardinality and uniqueness, attestation shape, per-kind
dispatch, and event kind/unit/payload shape for a parsed JSON instance.

Typed runtime parsers remain authoritative for:

- canonical UTF-8 bytes, duplicate keys, numeric spelling, Unicode 17.0.0 NFC, size,
  nesting, and global node ceilings;
- content-derived object, claim, trust, evidence, key, and event identities;
- lexical ordering, field-keyed uniqueness, aggregate limits, and time relations;
- canonical cryptographic decoding, Ed25519 subgroup and signature verification, and key
  bindings;
- cross-object equality, authority, retained CAS membership and type, event lifecycle,
  budget, replay, and concurrency rules.

Draft 2020-12 defines integer mathematically, so a parsed host-language `1.0` can validate
as an integer even though Etzio's canonical wire parser rejects every floating-point token.
Its regex guidance follows ECMA-262, so Etzio does not delegate edge-whitespace meaning to
`\s` or `\S`; the schema spells out the runtime's supported trim set and retains divergent
code-point controls.

Parity evidence therefore has two named classes: schema-expressible agreement and
schema-valid/runtime-invalid controls. It does not claim raw-wire equivalence.

## Consequences

- Every runtime-produced semantic object and all twelve event variants are checked against
  the installed schema and round-trip through the typed dispatcher.
- Missing and unknown fields, kind/body confusion, forbidden attestations, malformed
  cryptographic encodings, arbitrary event bodies, trailing-newline identifiers, and the
  untyped checkpoint name have retained known-bads.
- Repository-policy mutations prove that root/body field removal, body reopening, case-ref
  substitution, and attestation-policy weakening are rejected.
- Portable edge-whitespace and schema-valid/runtime-invalid field-keyed uniqueness controls
  are retained for target paths and authority trust keys.
- Wheels and source distributions contain the same single canonical protocol schema, and
  CI loads and metaschema-checks it outside the checkout.
- Phase 1B remains running. Semantic structural parity does not issue verification leases,
  resolve receipt evidence, consume leases atomically, establish trusted time, anchor event
  heads, prove verifier independence, or mint a finding.

## Rejected alternatives

### Keep a permissive fallback body for reserved or future kinds

That would preserve the exact type-confusion gap this gate is intended to close. Unknown
and untyped kinds are denied until their typed contract exists.

### Duplicate the schema at a repository path and inside the package

Two editable copies create contract drift. The installed package resource is the canonical
copy; repository validation and tests load that same file.

### Treat JSON Schema as cryptographic or lifecycle authority

Document-schema validation cannot recompute content identities, authenticate signatures,
resolve evidence, or adjudicate a sequence of events. Those invariants stay in typed
runtime and kernel gates with separate known-bads.
