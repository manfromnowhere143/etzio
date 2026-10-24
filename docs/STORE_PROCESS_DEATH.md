# Canonical store process-death controls

Status: test contract, 2026-10-24. This extends the owned fixture evidence for the
existing store contract; it changes no authority, schema or runtime behavior.

The experiment uses one authentic fixture dossier for three database copies:
the retained prefix, an uninterrupted completion, and a writer killed with
`SIGKILL`. Every handle is closed before copying. The child reconstructs the
operation from exact canonical event and phase bytes. It arms the kill point only
after opening the store and requires an active transaction with new writes.

Two boundaries are measured: immediately before calling SQLite `COMMIT`, and
immediately after that call returns but before the store returns to its caller.
The latter is a lost acknowledgement. Neither is an interruption inside SQLite's
commit implementation. The child exits by signal, so Python exception handlers,
context-manager cleanup and connection destructors cannot repair the state.

The matrix covers the four protected evidence admissions (`authority_admitted`,
`mission_opened`, `verification_artifacts_resolved`, `verifier_receipt_admitted`)
and four qualified signed-fixture finality phases (pending, anchor statement,
checkpoint candidate, finalization). Cold reopening must validate the database
and recover exactly the prefix or completed logical database, respectively.
The oracle compares the complete SQL dump, including canonical BLOBs, mappings,
enrollments, events and phase records; row counts alone are insufficient.
Two repeated operations must converge to the uninterrupted state without duplicate
rows. Qualified phase APIs reconcile exact retries. Low-level evidence append APIs
retain their existing stale-head refusal after commit; the test must verify that
refusal and reconcile the exact canonical event through cold replay. Committed
evidence replay must also work after deleting its temporary staging directory.
An unresolved finality phase must continue to block ordinary
reads in both its own mission and another mission. Only completed finalization
may release that barrier.

An additional authority-admission pair uses a larger inert authority document
and an explicitly reduced SQLite page cache. The precommit child must leave a
rollback journal with a valid header and must have changed the main database
file. This distinguishes exercised rollback of spilled pages from simply losing
an in-memory transaction. The cache override belongs only to the test profile;
it is not a production recommendation.

The uninterrupted branch is an acceptance control. A reversed pre/post commit
oracle must fail the matrix as a private calibration. Retain runtime identities,
commands and outcomes with the release evidence. Run on both declared CPython
runtimes locally and in the existing Linux CI matrix.

Limits: this does not qualify power-loss behavior, filesystem or device flush
semantics, every possible process-kill timing, quotas, concurrent writers,
backup/restore, encryption, same-user pathname attacks or coherent offline
rewrite resistance. It does not establish external durability, independently
administered providers, trustworthy UTC, exploit execution or a finding. Those
gates remain in [qualification next steps](QUALIFICATION_NEXT_STEPS.md).

The experiment follows SQLite's documented [rollback-journal locking and
recovery](https://sqlite.org/lockingv3.html) and
[cache spill behavior](https://sqlite.org/pragma.html#pragma_cache_spill), checked
2026-10-24. It complements SQLite's own extensive fault testing; it does not
replace qualification of Etzio's exact deployed storage profile.
