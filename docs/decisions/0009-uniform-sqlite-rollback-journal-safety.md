# ADR-0009: Uniform SQLite rollback-journal safety

- Status: accepted
- Date: 2026-07-29
- Owner: Daniel Wahnich

## Context

Etzio's event store selected SQLite WAL mode unconditionally. The declared runtime matrix
currently embeds two different SQLite releases:

- CPython 3.11.15 loads SQLite 3.53.1; and
- CPython 3.14.2 loads SQLite 3.51.2.

SQLite disclosed the [WAL-reset bug](https://www.sqlite.org/wal.html#the_wal_reset_bug)
on 2026-03-03. It can corrupt a WAL database when at least two connections in separate
threads or processes overlap a write with checkpoint/reset activity. SQLite identifies
3.7.0 through 3.51.2 as affected, fixes the race in 3.51.3 and later, and provides explicit
backports in 3.44.6 and 3.50.7.

Etzio intentionally supports concurrent connections and tests competing writers. Its
`BEGIN IMMEDIATE` transactions serialize writers, but they do not remove SQLite's separate
checkpointer race. The repository's small stress tests also cannot prove absence of a race
that SQLite required instrumented test hooks to reproduce. A green suite on SQLite 3.51.2
was therefore not evidence that WAL was safe.

Journal mode is persistent database state but cached independently by each connection. A
per-process version gate is insufficient: a fixed-runtime accessor can change a shared
database to WAL while an affected accessor continues to believe its cached mode is
rollback. The affected connection can then enter WAL on its next transaction before a
later diagnostic check observes the change.

## Decision

Every Etzio accessor in the declared runtime matrix uses rollback-journal `DELETE` mode
with `synchronous=EXTRA`, including accessors whose own loaded SQLite release contains the
upstream WAL fix. Etzio will not re-enable WAL until every supported accessor is qualified
on a fixed release under a later decision.

Before schema creation or canonical event operations, the store selects this one uniform
policy and inspects the already-open database descriptor. Persistent WAL header state is
refused before SQLite opens the path; migration requires a separately controlled,
stop-the-world operation using a fixed SQLite release. The constructor then requires
DELETE mode rather than converting another live mode in place. If SQLite refuses the
journal mode or synchronous level, store construction fails closed. Diagnostics expose
the loaded SQLite version, whether that library contains the WAL-reset fix, and the
connection's journal and synchronous settings. SQLite before 3.37.0, which introduced the
STRICT tables Etzio requires, and unknown SQLite major versions fail closed.

Fix classification remains exact for retained dependency evidence: 3.51.3 and later on
the supported 3.x major line contain the fix, as do the bounded 3.44.6-or-later-before-3.45
and 3.50.7-or-later-before-3.51 maintenance lines. For example, 3.45.0 is not inferred safe
merely because its version sorts above 3.44.6. Classification does not change journal
policy while an affected runtime remains supported.

The canonical verification entrypoint records both `sqlite3.sqlite_version` and
`sqlite_source_id()` in retained CI output. Python-runtime pinning alone is insufficient
because the embedded SQLite build is a separate security-relevant dependency. These are
runtime-reported identity values, not an authenticated or allowlisted binary-provenance
claim.

Rollback journaling uses `synchronous=EXTRA`, which adds the directory sync needed after
journal unlink beyond `FULL` rollback behavior. It preserves SQLite atomic
transactions and Etzio's compare-and-append semantics at a performance and concurrency
cost. Event protocol bytes and reducer semantics do not vary by journal policy.

## Consequences

- CPython 3.11.15/SQLite 3.53.1 and CPython 3.14.2/SQLite 3.51.2 both use DELETE/EXTRA.
- Supported Etzio processes do not select incompatible persistent journal modes merely
  because their embedded SQLite versions differ.
- WAL performance and reader/writer concurrency are deliberately unavailable until the
  complete accessor matrix is fixed and separately requalified.
- Boundary tests retain the exact upstream fixed versions, reject an unknown future major,
  and prove fixed and affected releases receive the same rollback policy.
- A preexisting WAL database cannot be converted implicitly during ordinary Etzio startup.

## Claim boundary

This decision closes Etzio-created WAL exposure to the disclosed WAL-reset race under the
declared runtime matrix. It does not prove the absence of other SQLite, filesystem, kernel,
device, or power-loss failures.

It does not close the documented same-user pathname replacement race. A process with the
same filesystem authority can still rename, unlink, replace, or overwrite SQLite state and
its journal files or use another SQLite connection to change persistent journal state
after Etzio's admission check. Closure still requires a dedicated service identity,
protected local mount, and accepted deployment profile.

Diagnostics report the connection's observed settings; they are not a continuous
cross-process journal-mode monitor. A hostile same-user connection can race any
application-level check. Etzio therefore does not claim rollback policy alone closes that
authority boundary.

It also does not make event heads externally durable, close the filesystem-CAS/SQLite
atomic-retention gap, or establish trusted time, revocation freshness, anchoring, or a
finding.

## Rejected alternatives

### Keep WAL because the race is rare

The failure mode is canonical-state corruption, and Etzio exactly permits the multi-
connection conditions named by SQLite. Low observed frequency is not an integrity proof.

### Treat `BEGIN IMMEDIATE` or disabled automatic checkpoints as a fix

SQLite's bug involves separate connections and WAL checkpoint/reset state. Application
writer serialization and checkpoint scheduling do not establish that the vulnerable code
path is unreachable.

### Gate WAL independently in each process

Journal mode is shared persistent state while connections cache their current mode. A
fixed process could therefore expose an affected process using the same database. Safety
policy must be uniform across the supported accessor matrix.

### Drop CPython 3.14 validation silently

That would remove cross-runtime evidence and conceal the embedded dependency difference.
The uniform rollback policy preserves the declared matrix while making the embedded
dependency difference explicit.

### Accept any version numerically above a backport

The upstream fixes name exact maintenance lines. Treating unrelated 3.45 through 3.49
releases as fixed would recreate the vulnerable configuration through an invalid version
ordering assumption.
