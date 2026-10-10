# ADR-0023: Offline single-request acquisition custody

Status: implemented qualification experiment, subject to the release evidence in the handoff.
Scope: repository-owned fixtures; no transport, native provider, clock or kernel authority.

## Problem and boundary

The next provider-discovery experiment needs exact request retention and a non-resetting
attempt budget. A network timeout cannot establish that the server did nothing. A local
commit and a remote request also cannot be made one atomic transaction by this client.
The finite experiment therefore sacrifices availability: once an attempt is committed,
recovery never returns it to the prepared state, even when no request was actually sent.

This tranche implements an offline journal, not an acquisition client or a grant checker.
Scope and terms references are byte-bound documentary inputs, not accepted agreements or
authority admissions. A successful debit is not permission to contact its endpoint. No
network library, transport callback, timestamp parser or conversion to kernel evidence is
provided. Only repository-owned request/response fixtures exercise the mechanism.

## Contract

One newly and exclusively created private database retains one canonical intent and the
exact bounded request BLOB. The intent binds service, endpoint, scope reference, terms
reference, request hash/size and response ceiling. Its identity is domain-separated from
all kernel wire kinds. Creation never adopts, resets or repairs an existing file.

Three append-only singleton relations retain intent, attempt debit and optional terminal
capture. Foreign keys, parent checks and insert/update/delete guards enforce their ordering.
Insert guards also reject INSERT OR REPLACE, independently of recursive-trigger settings.
An exact schema, application ID and version distinguish this journal from the kernel evidence vault. Every
operation opens an existing database without implicit creation, validates the supported
SQLite policy, uses DELETE/EXTRA, checks the schema and freshly reconstructs every byte
binding in one transaction. No caller-created snapshot is accepted as input authority.

The observable states are `prepared`, `attempt_indeterminate`, `response_captured` and
`capture_indeterminate`. A response capture is untrusted opaque data, never a timestamp
validation result. Terminal capture is immutable; exact capture retry is retention-only
and returns no new attempt. Conflicting captures refuse. Invalid capture input leaves the
already consumed attempt intact. Missing outcomes remain visible after a process dies.

`debit()` commits the only attempt row before returning a fresh attempt identifier. A
second invocation always refuses, including after a retained terminal outcome. Readback
exposes the existing attempt identity but never reissues a successful debit. Commit or
storage exceptions propagate as storage failures; they are not adapter refusals or
successful captures. A lost commit acknowledgement must be resolved by inspection; it
cannot justify a resend. A future transport must begin only after successful commit
return and must have its own admitted grant and containment profile.

Request bytes are limited to 16 KiB, intent/outcome records to 8 KiB each and retained
response bytes to the declared ceiling, at most 64 KiB. Oversized stored fields refuse
before their BLOBs are fetched. These are logical limits, not qualified physical/journal
quotas. All times, freshness, entropy, HTTP semantics, parser containment and transport
resource enforcement remain outside this journal.

## Conditional safety argument and required counterexamples

Within one unchanged database under the declared SQLite atomicity assumptions, the
attempt relation has cardinality at most one. Every successful `debit()` requires a new
insert and acknowledged commit. Therefore at most one call can return a fresh debit.
There is no retry or recovery transition that deletes it. This establishes a local
at-most-once handoff opportunity, not exactly-once remote execution or delivery.

Controls must cover concurrent debit calls, death before and after debit commit, lost
commit acknowledgement, cold replay without original input files, retained input/output
substitution, missing or foreign schema, raw ordering violations, immutable-row changes,
oversized/noncanonical records, pre-existing WAL, wrong application/version identities,
changed connection settings and exact-versus-conflicting terminal retries.

Process interruption is not a power-fault test. Database copies, coherent offline rewrite,
same-user pathname races, rollback to an old database, directory/device durability,
independent administration and grant reuse across databases are not qualified here. A
production grant registry must prevent a copied/new database from creating another budget.
These are acceptance dependencies before this mechanism can govern production authority.
A separately scoped finite discovery experiment must explicitly declare and accept its
narrower storage assumptions; a passing fixture experiment cannot waive them.

## Primary research basis

Reviewed 2026-10-10 against the primary publications below. RFC 9110 is the June 2022
published standard; the two engineering articles are explanatory sources, not a
certification or versioned storage qualification.

- [RFC 9110, section 9.2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.2.2),
  June 2022: automatic retry restrictions when a request is not known to be idempotent.
- [SQLite atomic commit](https://sqlite.org/atomiccommit.html): transaction guarantees
  depend on the specified storage assumptions; an acknowledged local commit does not
  acknowledge a remote operation.
- [Amazon Builders' Library: Making retries safe with idempotent APIs](https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/):
  caller identifiers and retained intent are necessary for explicit retry semantics.
  Etzio does not assume that an RFC 3161 server implements such an idempotency service.

The state machine and proof above are Etzio's design, not claims that those sources
certify this implementation. This contract does not alter existing native codecs,
provider admission, lifecycle recovery, the kernel store schema or the mission gate order.
