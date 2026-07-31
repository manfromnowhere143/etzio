"""Schema-version-4 qualified acceptance profile enrollment and its known-bads."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from test_integrity_store_v2 import (
    _downgrade_exact_empty_integrity_schema_to_v3,
    _enroll,
    _policy,
    _refusal_event,
    _state_path,
)

from etzio.kernel.events_v1 import GENESIS_DIGEST
from etzio.kernel.head_authority_adapters_v1 import (
    create_repository_owned_head_authority_fixture_v1,
)
from etzio.kernel.integrity_adapters_v1 import (
    create_repository_owned_adapter_fixture_v1,
)
from etzio.kernel.store import (
    EventStoreCorruptionError,
    EventStoreError,
    IntegrityTransitionConflictError,
    SQLiteEventStore,
)

_APPLICATION_ID = 0x45545A31
_MODE_MODELED = "modeled_unsigned_code_derived"
_MODE_QUALIFIED = "qualified_signed_fixture"


def _time_profile(seed: bytes = b"acceptance-enrollment-time"):
    return create_repository_owned_adapter_fixture_v1(seed=seed).profile


def _head_profile(seed: bytes = b"acceptance-enrollment-head"):
    return create_repository_owned_head_authority_fixture_v1(seed=seed).profile


def _modeled_store(tmp_path: Path):
    path = _state_path(tmp_path)
    store = SQLiteEventStore(path)
    _enroll(store, _policy())
    return store, path


def _enroll_qualified(store):
    return store.enroll_qualified_acceptance(
        qualified_time_profile=_time_profile(),
        qualified_head_profile=_head_profile(),
    )


# ---------------------------------------------------------------------------
# Schema identity and migration
# ---------------------------------------------------------------------------


def test_fresh_store_is_schema_version_four_with_the_acceptance_table(
    tmp_path: Path,
) -> None:
    path = _state_path(tmp_path)
    with SQLiteEventStore(path):
        pass
    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA application_id").fetchone() == (_APPLICATION_ID,)
        assert connection.execute("PRAGMA user_version").fetchone() == (4,)
        assert connection.execute(
            "SELECT 1 FROM sqlite_schema WHERE name = 'integrity_acceptance_profile'"
        ).fetchone() is not None
    finally:
        connection.close()


def test_exact_version_three_layout_migrates_forward(tmp_path: Path) -> None:
    path = _state_path(tmp_path)
    with SQLiteEventStore(path):
        pass
    _downgrade_exact_empty_integrity_schema_to_v3(path)
    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA user_version").fetchone() == (3,)
    finally:
        connection.close()
    with SQLiteEventStore(path):
        pass
    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA user_version").fetchone() == (4,)
        assert connection.execute(
            "SELECT count(*) FROM integrity_acceptance_profile"
        ).fetchone() == (0,)
    finally:
        connection.close()


def test_a_drifted_version_three_layout_refuses_to_migrate(tmp_path: Path) -> None:
    path = _state_path(tmp_path)
    with SQLiteEventStore(path):
        pass
    _downgrade_exact_empty_integrity_schema_to_v3(path)
    connection = sqlite3.connect(path, isolation_level=None)
    try:
        connection.execute("CREATE TABLE unexpected_object (id INTEGER PRIMARY KEY)")
    finally:
        connection.close()
    with pytest.raises(EventStoreCorruptionError):
        SQLiteEventStore(path)


def test_migration_backfills_no_acceptance_profile(tmp_path: Path) -> None:
    store, path = _modeled_store(tmp_path)
    _enroll_qualified(store)
    store.close()
    _downgrade_exact_empty_integrity_schema_to_v3(path)
    with SQLiteEventStore(path) as migrated:
        assert migrated.resolve_acceptance_mode() == _MODE_MODELED
        assert migrated.load_qualified_acceptance_profiles() is None


# ---------------------------------------------------------------------------
# Enrollment
# ---------------------------------------------------------------------------


def test_default_mode_is_modeled_unsigned(tmp_path: Path) -> None:
    store, _ = _modeled_store(tmp_path)
    with store:
        assert store.resolve_acceptance_mode() == _MODE_MODELED
        assert store.load_qualified_acceptance_profiles() is None


def test_qualified_enrollment_is_exact_and_idempotent(tmp_path: Path) -> None:
    store, _ = _modeled_store(tmp_path)
    with store:
        assert _enroll_qualified(store) == _MODE_QUALIFIED
        assert store.resolve_acceptance_mode() == _MODE_QUALIFIED
        assert _enroll_qualified(store) == _MODE_QUALIFIED


def test_qualified_profiles_reload_exactly(tmp_path: Path) -> None:
    store, _ = _modeled_store(tmp_path)
    with store:
        _enroll_qualified(store)
        loaded = store.load_qualified_acceptance_profiles()
        assert loaded is not None
        assert loaded[0].profile_id == _time_profile().profile_id
        assert loaded[1].profile_id == _head_profile().profile_id


def test_qualified_enrollment_survives_reopen(tmp_path: Path) -> None:
    store, path = _modeled_store(tmp_path)
    _enroll_qualified(store)
    store.close()
    with SQLiteEventStore(path) as reopened:
        assert reopened.resolve_acceptance_mode() == _MODE_QUALIFIED
        assert reopened.load_qualified_acceptance_profiles() is not None


def test_enrollment_refuses_a_replacement_profile(tmp_path: Path) -> None:
    store, _ = _modeled_store(tmp_path)
    with store:
        _enroll_qualified(store)
        with pytest.raises(IntegrityTransitionConflictError):
            store.enroll_qualified_acceptance(
                qualified_time_profile=_time_profile(seed=b"a-different-time-corpus"),
                qualified_head_profile=_head_profile(),
            )


def test_enrollment_requires_a_modeled_profile(tmp_path: Path) -> None:
    path = _state_path(tmp_path)
    with SQLiteEventStore(path) as store:
        # A legacy store has no modeled profile; the SQL trigger fires.
        with pytest.raises(EventStoreError):
            _enroll_qualified(store)


def test_enrollment_requires_empty_history(tmp_path: Path) -> None:
    path = _state_path(tmp_path)
    with SQLiteEventStore(path) as store:
        service = _enroll(store, _policy())
        event = _refusal_event("acceptance-nonempty")
        pending = service.prepare_pending_transition(
            event, previous_global=None, previous_mission=None
        )
        store.append_pending_integrity_event(
            event, expected_head=GENESIS_DIGEST, pending=pending
        )
        with pytest.raises(EventStoreError):
            _enroll_qualified(store)


def test_enrollment_rejects_wrong_profile_types(tmp_path: Path) -> None:
    store, _ = _modeled_store(tmp_path)
    with store:
        with pytest.raises(EventStoreError):
            store.enroll_qualified_acceptance(
                qualified_time_profile=object(),
                qualified_head_profile=_head_profile(),
            )
        with pytest.raises(EventStoreError):
            store.enroll_qualified_acceptance(
                qualified_time_profile=_time_profile(),
                qualified_head_profile=object(),
            )


# ---------------------------------------------------------------------------
# The acceptance profile is immutable
# ---------------------------------------------------------------------------


def test_the_acceptance_profile_is_append_only(tmp_path: Path) -> None:
    store, path = _modeled_store(tmp_path)
    _enroll_qualified(store)
    store.close()
    connection = sqlite3.connect(path, isolation_level=None)
    try:
        with pytest.raises(sqlite3.DatabaseError):
            connection.execute(
                "UPDATE integrity_acceptance_profile SET acceptance_mode = ?",
                (_MODE_MODELED,),
            )
        with pytest.raises(sqlite3.DatabaseError):
            connection.execute("DELETE FROM integrity_acceptance_profile")
    finally:
        connection.close()


def test_raw_sql_cannot_forge_an_unknown_acceptance_mode(tmp_path: Path) -> None:
    store, path = _modeled_store(tmp_path)
    store.close()
    connection = sqlite3.connect(path, isolation_level=None)
    try:
        with pytest.raises(sqlite3.DatabaseError):
            connection.execute(
                "INSERT INTO integrity_acceptance_profile "
                "(singleton, acceptance_mode, qualified_time_profile_id, "
                "qualified_time_profile_wire, qualified_head_profile_id, "
                "qualified_head_profile_wire) VALUES (1, 'force_qualified', ?, ?, ?, ?)",
                (
                    "sha256:" + "0" * 64,
                    b"x",
                    "sha256:" + "0" * 64,
                    b"y",
                ),
            )
    finally:
        connection.close()


# ---------------------------------------------------------------------------
# Capacity
# ---------------------------------------------------------------------------


def test_qualified_profiles_are_charged_to_logical_storage(tmp_path: Path) -> None:
    store, _ = _modeled_store(tmp_path)
    with store:
        before = store._logical_evidence_storage_used_locked()  # noqa: SLF001
        _enroll_qualified(store)
        after = store._logical_evidence_storage_used_locked()  # noqa: SLF001
        assert after > before
