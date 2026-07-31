"""Injected-interruption recovery across blocked-observation and decision retention."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from test_blocked_finality_lifecycle_v1 import (
    _block_once,
    _BlockingService,
    _governed,
    _time_source,
)
from test_blocked_finality_storage_v3 import _recovery_profile, _sign
from test_integrity_store_v2 import (
    _ENVIRONMENT_ID,
    _SERVICE_INSTANCE_ID,
    _policy,
    _refusal_event,
    _service,
    _state_path,
)

from etzio.kernel.blocked_finality_v1 import (
    INSTANCE_SEALED_DISPOSITION_V1,
    RETRY_AUTHORIZED_DISPOSITION_V1,
)
from etzio.kernel.integrity_transition import (
    GovernedBlockedFinalityBindingV1,
    IntegrityFinalityBlockedError,
    IntegrityInstanceSealedError,
    IntegrityRecoveryNotAuthorizedError,
    ModeledIntegrityFinalizingEventStoreV1,
)
from etzio.kernel.store import SQLiteEventStore


class _InjectedCallerFailure(RuntimeError):
    """A caller-side death that is not a store or adapter condition."""


def _crash_before(store: SQLiteEventStore, method: str) -> None:
    """Die before the retention transaction opens."""

    def _die(*_args: object, **_kwargs: object) -> object:
        raise _InjectedCallerFailure(f"caller died before {method} committed")

    setattr(store, method, _die)


def _crash_after(store: SQLiteEventStore, method: str) -> None:
    """Commit exactly once, then lose the caller before it observes the result."""

    real = getattr(store, method)

    def _die(*args: object, **kwargs: object) -> object:
        real(*args, **kwargs)
        raise _InjectedCallerFailure(f"caller died after {method} committed")

    setattr(store, method, _die)


def _restore(store: SQLiteEventStore, method: str) -> None:
    if method in store.__dict__:
        del store.__dict__[method]


def _db_path(tmp_path: Path, name: str = "state") -> Path:
    """Resolve the database `_state_path` already created, without recreating it."""

    return tmp_path / name / "events.sqlite3"


def _rows(path: Path, table: str) -> int:
    connection = sqlite3.connect(path)
    try:
        return connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
    finally:
        connection.close()


# ---------------------------------------------------------------------------
# Interruption around observation retention
# ---------------------------------------------------------------------------


def test_death_before_observation_retention_leaves_no_partial_state(
    tmp_path: Path,
) -> None:
    store, facade, service, _, _ = _governed(tmp_path)
    with store:
        path = _db_path(tmp_path)
        _crash_before(store, "retain_blocked_finality_observation")
        event = _refusal_event("crash-before")
        with pytest.raises(_InjectedCallerFailure):
            facade.append(event, expected_head=event.prev_digest)
        assert _rows(path, "integrity_blocked_observations") == 0
        # The block itself is unrecorded, so the next attempt is ordinal 1, not 2.
        _restore(store, "retain_blocked_finality_observation")
        with pytest.raises(IntegrityFinalityBlockedError):
            facade.recover_pending_transition()
        observations = store.load_blocked_finality_observations(event.event_digest)
        assert [entry.attempt_ordinal for entry in observations] == [1]


def test_death_after_observation_retention_replays_without_duplicates(
    tmp_path: Path,
) -> None:
    store, facade, service, _, _ = _governed(tmp_path)
    with store:
        path = _db_path(tmp_path)
        _crash_after(store, "retain_blocked_finality_observation")
        event = _refusal_event("crash-after")
        with pytest.raises(_InjectedCallerFailure):
            facade.append(event, expected_head=event.prev_digest)
        assert _rows(path, "integrity_blocked_observations") == 1
        _restore(store, "retain_blocked_finality_observation")
        # Exactly one observation exists, so replay is gated rather than duplicating it.
        with pytest.raises(IntegrityRecoveryNotAuthorizedError):
            facade.recover_pending_transition()
        assert _rows(path, "integrity_blocked_observations") == 1
        observations = store.load_blocked_finality_observations(event.event_digest)
        assert [entry.attempt_ordinal for entry in observations] == [1]


def test_repeated_death_after_retention_never_reuses_an_ordinal(
    tmp_path: Path,
) -> None:
    store, facade, service, profile, signer = _governed(tmp_path)
    with store:
        path = _db_path(tmp_path)
        event = _block_once(facade, service, tmp_path)
        for expected in (2, 3):
            observation = store.load_blocked_finality_observations(
                event.event_digest
            )[-1]
            store.retain_governed_recovery_decision(
                _sign(profile, signer, observation, RETRY_AUTHORIZED_DISPOSITION_V1)
            )
            _crash_after(store, "retain_blocked_finality_observation")
            with pytest.raises(_InjectedCallerFailure):
                facade.recover_pending_transition()
            _restore(store, "retain_blocked_finality_observation")
            assert _rows(path, "integrity_blocked_observations") == expected
        observations = store.load_blocked_finality_observations(event.event_digest)
        assert [entry.attempt_ordinal for entry in observations] == [1, 2, 3]
        assert len({entry.observation_id for entry in observations}) == 3


def test_an_interrupted_observation_never_releases_the_barrier(
    tmp_path: Path,
) -> None:
    store, facade, service, _, _ = _governed(tmp_path)
    with store:
        path = _db_path(tmp_path)
        _crash_after(store, "retain_blocked_finality_observation")
        event = _refusal_event("crash-barrier")
        with pytest.raises(_InjectedCallerFailure):
            facade.append(event, expected_head=event.prev_digest)
        assert _rows(path, "integrity_finalizations") == 0
        connection = sqlite3.connect(path)
        try:
            unresolved = connection.execute(
                """
                SELECT count(*)
                FROM integrity_pending_transitions AS pending
                LEFT JOIN integrity_finalizations AS finalized
                  ON finalized.event_digest = pending.event_digest
                WHERE finalized.event_digest IS NULL
                """
            ).fetchone()[0]
        finally:
            connection.close()
        assert unresolved == 1


# ---------------------------------------------------------------------------
# A store failure during retention is never reclassified
# ---------------------------------------------------------------------------


def test_a_store_failure_during_retention_keeps_its_own_domain(
    tmp_path: Path,
) -> None:
    """Recording that finality is blocked must not itself become an adapter refusal."""

    from etzio.kernel.store import StoreBusyError

    store, facade, service, _, _ = _governed(tmp_path)
    with store:
        def _busy(*_args: object, **_kwargs: object) -> object:
            raise StoreBusyError("simulated retained-state contention")

        store.retain_blocked_finality_observation = _busy  # type: ignore[method-assign]
        event = _refusal_event("crash-store-domain")
        with pytest.raises(StoreBusyError):
            facade.append(event, expected_head=event.prev_digest)


# ---------------------------------------------------------------------------
# Interruption around governed-decision retention
# ---------------------------------------------------------------------------


def test_death_after_decision_retention_reconciles_exactly(tmp_path: Path) -> None:
    store, facade, service, profile, signer = _governed(tmp_path)
    with store:
        path = _db_path(tmp_path)
        event = _block_once(facade, service, tmp_path)
        observation = store.load_blocked_finality_observations(event.event_digest)[0]
        signed = _sign(profile, signer, observation, RETRY_AUTHORIZED_DISPOSITION_V1)
        _crash_after(store, "retain_governed_recovery_decision")
        with pytest.raises(_InjectedCallerFailure):
            store.retain_governed_recovery_decision(signed)
        _restore(store, "retain_governed_recovery_decision")
        assert _rows(path, "integrity_recovery_decisions") == 1
        # The exact same signed bytes reconcile instead of inserting a second row.
        store.retain_governed_recovery_decision(signed)
        assert _rows(path, "integrity_recovery_decisions") == 1


def test_death_before_decision_retention_leaves_recovery_unauthorized(
    tmp_path: Path,
) -> None:
    store, facade, service, profile, signer = _governed(tmp_path)
    with store:
        path = _db_path(tmp_path)
        event = _block_once(facade, service, tmp_path)
        observation = store.load_blocked_finality_observations(event.event_digest)[0]
        signed = _sign(profile, signer, observation, RETRY_AUTHORIZED_DISPOSITION_V1)
        _crash_before(store, "retain_governed_recovery_decision")
        with pytest.raises(_InjectedCallerFailure):
            store.retain_governed_recovery_decision(signed)
        _restore(store, "retain_governed_recovery_decision")
        assert _rows(path, "integrity_recovery_decisions") == 0
        with pytest.raises(IntegrityRecoveryNotAuthorizedError):
            facade.recover_pending_transition()


def test_death_after_sealing_keeps_the_instance_sealed(tmp_path: Path) -> None:
    store, facade, service, profile, signer = _governed(tmp_path)
    with store:
        event = _block_once(facade, service, tmp_path)
        observation = store.load_blocked_finality_observations(event.event_digest)[0]
        signed = _sign(profile, signer, observation, INSTANCE_SEALED_DISPOSITION_V1)
        _crash_after(store, "retain_governed_recovery_decision")
        with pytest.raises(_InjectedCallerFailure):
            store.retain_governed_recovery_decision(signed)
        _restore(store, "retain_governed_recovery_decision")
        assert store.instance_is_sealed() is True
        with pytest.raises(IntegrityInstanceSealedError):
            facade.recover_pending_transition()


def test_the_retained_state_survives_reopening_the_database(tmp_path: Path) -> None:
    """A fresh process sees exactly the retained observations and decision."""

    store, facade, service, profile, signer = _governed(tmp_path)
    path = _db_path(tmp_path)
    with store:
        event = _block_once(facade, service, tmp_path)
        observation = store.load_blocked_finality_observations(event.event_digest)[0]
        store.retain_governed_recovery_decision(
            _sign(profile, signer, observation, RETRY_AUTHORIZED_DISPOSITION_V1)
        )
    with SQLiteEventStore(path) as reopened:
        observations = reopened.load_blocked_finality_observations(event.event_digest)
        assert [entry.attempt_ordinal for entry in observations] == [1]
        assert observations[0].observation_id == observation.observation_id
        assert observations[0].blocked_reason_code == "modeled_anchor_equivocation"
        signed = reopened.load_governed_recovery_decision(observation.observation_id)
        assert signed is not None
        assert reopened.instance_is_sealed() is False


# ---------------------------------------------------------------------------
# Non-consequential status inspection
# ---------------------------------------------------------------------------


def test_status_reports_the_retained_block_without_resolving_it(
    tmp_path: Path,
) -> None:
    store, facade, service, profile, signer = _governed(tmp_path)
    with store:
        path = _db_path(tmp_path)
        event = _block_once(facade, service, tmp_path)
        status = facade.blocked_finality_status()
        assert status is not None
        assert status["event_digest"] == event.event_digest
        assert status["attempt_count"] == 1
        assert status["latest_attempt_ordinal"] == 1
        assert status["latest_blocked_reason_code"] == "modeled_anchor_equivocation"
        assert status["latest_disposition"] is None
        assert status["instance_sealed"] is False
        assert status["unresolved_phase"] == "local_pending"
        # Inspection resolves nothing and retains nothing.
        assert _rows(path, "integrity_finalizations") == 0
        assert _rows(path, "integrity_recovery_decisions") == 0
        assert _rows(path, "integrity_blocked_observations") == 1


def test_status_reports_a_retained_disposition(tmp_path: Path) -> None:
    store, facade, service, profile, signer = _governed(tmp_path)
    with store:
        event = _block_once(facade, service, tmp_path)
        observation = store.load_blocked_finality_observations(event.event_digest)[0]
        store.retain_governed_recovery_decision(
            _sign(profile, signer, observation, INSTANCE_SEALED_DISPOSITION_V1)
        )
        status = facade.blocked_finality_status()
        assert status is not None
        assert status["latest_disposition"] == INSTANCE_SEALED_DISPOSITION_V1
        assert status["instance_sealed"] is True


def test_status_is_none_without_a_governed_binding_or_a_pending_transition(
    tmp_path: Path,
) -> None:
    path = _state_path(tmp_path)
    store = SQLiteEventStore(path)
    policy = _policy()
    inner = _service(policy)
    ungoverned = ModeledIntegrityFinalizingEventStoreV1(store, inner)
    with store:
        assert ungoverned.blocked_finality_status() is None

    other = _state_path(tmp_path, "second")
    second = SQLiteEventStore(other)
    inner2 = _service(_policy())
    profile, _ = _recovery_profile(
        _SERVICE_INSTANCE_ID,
        _ENVIRONMENT_ID,
        inner2.authority_binding,
    )
    governed = ModeledIntegrityFinalizingEventStoreV1(
        second,
        _BlockingService(inner2, "none"),
        blocked_finality=GovernedBlockedFinalityBindingV1(
            profile=profile,
            time_source=_time_source(),
        ),
    )
    with second:
        assert governed.blocked_finality_status() is None


def test_unauthorized_recovery_reports_the_retained_reason(tmp_path: Path) -> None:
    """A caller that lost the original error still learns why it is blocked."""

    store, facade, service, _, _ = _governed(tmp_path)
    with store:
        _block_once(facade, service, tmp_path)
        with pytest.raises(IntegrityRecoveryNotAuthorizedError) as exc:
            facade.recover_pending_transition()
        message = str(exc.value)
        assert "attempt 1" in message
        assert "local_pending" in message
        assert "modeled_anchor_equivocation" in message
