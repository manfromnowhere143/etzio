"""Schema-version-3 durable blocked-finality storage and its known-bads."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from test_integrity_store_v2 import (
    _ENVIRONMENT_ID,
    _SERVICE_INSTANCE_ID,
    _append_pending,
    _digest,
    _downgrade_exact_empty_integrity_schema_to_v2,
    _enroll,
    _policy,
    _refusal_event,
    _state_path,
)

from etzio.kernel.blocked_finality_v1 import (
    BLOCKED_FINALITY_CONTRACT_VERSION_V1,
    BLOCKED_FINALITY_RECOVERY_ROLE_V1,
    INSTANCE_SEALED_DISPOSITION_V1,
    LOCAL_PENDING_PHASE_V1,
    RETRY_AUTHORIZED_DISPOSITION_V1,
    BlockedFinalityObservationV1,
    BlockedFinalityRecoveryProfileV1,
    GovernedRecoveryDecisionV1,
    RecoveryDecisionSignerV1,
    TrustedRecoveryKeyV1,
    create_repository_owned_blocked_finality_fixture_v1,
    fixture_time_bundle_v1,
)
from etzio.kernel.store import (
    EventStoreCorruptionError,
    EventStoreError,
    IntegrityTransitionConflictError,
    SQLiteEventStore,
)

_APPLICATION_ID = 0x45545A31


def _fixture():
    return create_repository_owned_blocked_finality_fixture_v1(seed=b"storage-v3-corpus")


def _recovery_profile(store_service_instance: str, environment: str, binding):
    """Build a recovery profile bound to a live enrolled authority binding."""

    signer = RecoveryDecisionSignerV1.from_seed(
        principal_id="fixture.integrity-recovery.principal",
        seed=b"storage-v3-recovery",
    )
    profile = BlockedFinalityRecoveryProfileV1(
        profile="repository_owned_networkless_blocked_finality_v1",
        contract_version=BLOCKED_FINALITY_CONTRACT_VERSION_V1,
        service_instance_id=store_service_instance,
        environment_id=environment,
        authority_binding=binding,
        authority_binding_id=binding.binding_id,
        recovery_key=TrustedRecoveryKeyV1(
            principal_id=signer.principal_id,
            role=BLOCKED_FINALITY_RECOVERY_ROLE_V1,
            public_key_bytes=signer.public_key_bytes,
        ),
        recovery_policy_id=_digest("storage-v3-recovery-policy"),
    )
    return profile, signer


def _live_blocked_store(tmp_path: Path):
    """Enroll modeled integrity, open a pending transition, and enroll recovery."""

    path = _state_path(tmp_path)
    store = SQLiteEventStore(path)
    policy = _policy()
    service = _enroll(store, policy)
    event = _refusal_event("storage-v3")
    _append_pending(store, event, service)
    profile, signer = _recovery_profile(
        _SERVICE_INSTANCE_ID,
        _ENVIRONMENT_ID,
        service.authority_binding,
    )
    store.enroll_blocked_finality_recovery(profile)
    return store, path, event, profile, signer


def _observation(profile, event_digest: str, ordinal: int = 1):
    fixture = _fixture()
    bundle = fixture_time_bundle_v1(fixture)
    return BlockedFinalityObservationV1.record(
        profile=profile,
        mission_id=fixture.vector.mission_id,
        authority_id=fixture.vector.authority_id,
        target_id=fixture.vector.target_id,
        event_digest=event_digest,
        event_seq=0,
        instance_sequence=0,
        pending_record_id=_digest("storage-v3-pending-record"),
        unresolved_phase=LOCAL_PENDING_PHASE_V1,
        unresolved_phase_record_id=_digest("storage-v3-phase-record"),
        blocked_operation="prepare_anchor_statement",
        blocked_reason_code="modeled_anchor_equivocation",
        attempt_ordinal=ordinal,
        time_bundle=bundle,
    )


def _sign(profile, signer, observation, disposition):
    fixture = _fixture()
    return signer.sign(
        GovernedRecoveryDecisionV1.issue(
            profile=profile,
            observation=observation,
            disposition=disposition,
            time_bundle=fixture_time_bundle_v1(fixture),
            request_nonce=fixture.vector.request_nonce,
        )
    )


# ---------------------------------------------------------------------------
# Schema identity and migration
# ---------------------------------------------------------------------------


def test_fresh_store_creates_the_complete_version_three_layout(tmp_path: Path) -> None:
    path = _state_path(tmp_path)
    with SQLiteEventStore(path):
        pass
    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA application_id").fetchone() == (_APPLICATION_ID,)
        assert connection.execute("PRAGMA user_version").fetchone() == (4,)
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table'"
            ).fetchall()
        }
        assert {
            "integrity_blocked_observations",
            "integrity_recovery_decisions",
            "integrity_recovery_profile",
        } <= tables
    finally:
        connection.close()


def test_exact_version_two_layout_migrates_forward(tmp_path: Path) -> None:
    path = _state_path(tmp_path)
    with SQLiteEventStore(path):
        pass
    _downgrade_exact_empty_integrity_schema_to_v2(path)
    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA user_version").fetchone() == (2,)
    finally:
        connection.close()
    with SQLiteEventStore(path):
        pass
    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA user_version").fetchone() == (4,)
        assert connection.execute(
            "SELECT count(*) FROM integrity_blocked_observations"
        ).fetchone() == (0,)
    finally:
        connection.close()


def test_a_drifted_version_two_layout_refuses_to_migrate(tmp_path: Path) -> None:
    path = _state_path(tmp_path)
    with SQLiteEventStore(path):
        pass
    _downgrade_exact_empty_integrity_schema_to_v2(path)
    connection = sqlite3.connect(path, isolation_level=None)
    try:
        connection.execute("CREATE TABLE unexpected_object (id INTEGER PRIMARY KEY)")
    finally:
        connection.close()
    with pytest.raises(EventStoreCorruptionError):
        SQLiteEventStore(path)


def test_migration_backfills_no_blocked_observation(tmp_path: Path) -> None:
    """No retained byte records why an earlier attempt failed, so none is invented."""

    store, path, event, _, _ = _live_blocked_store(tmp_path)
    store.close()
    _downgrade_exact_empty_integrity_schema_to_v2(path)
    with SQLiteEventStore(path) as migrated:
        assert migrated.load_blocked_finality_observations(event.event_digest) == ()
        assert migrated.instance_is_sealed() is False


# ---------------------------------------------------------------------------
# Recovery-profile enrollment
# ---------------------------------------------------------------------------


def test_recovery_enrollment_is_exact_and_idempotent(tmp_path: Path) -> None:
    store, _, _, profile, _ = _live_blocked_store(tmp_path)
    with store:
        assert store.enroll_blocked_finality_recovery(profile) == profile.profile_id


def test_recovery_enrollment_refuses_a_replacement_profile(tmp_path: Path) -> None:
    store, _, _, profile, _ = _live_blocked_store(tmp_path)
    with store:
        other, _ = _recovery_profile(
            profile.service_instance_id,
            profile.environment_id,
            profile.authority_binding,
        )
        replacement = BlockedFinalityRecoveryProfileV1(
            profile=other.profile,
            contract_version=other.contract_version,
            service_instance_id=other.service_instance_id,
            environment_id=other.environment_id,
            authority_binding=other.authority_binding,
            authority_binding_id=other.authority_binding_id,
            recovery_key=other.recovery_key,
            recovery_policy_id=_digest("a-different-recovery-policy"),
        )
        with pytest.raises(IntegrityTransitionConflictError):
            store.enroll_blocked_finality_recovery(replacement)


def test_blocked_observation_requires_an_enrolled_recovery_profile(
    tmp_path: Path,
) -> None:
    path = _state_path(tmp_path)
    with SQLiteEventStore(path) as store:
        policy = _policy()
        service = _enroll(store, policy)
        event = _refusal_event("storage-v3-unenrolled")
        _append_pending(store, event, service)
        profile, _ = _recovery_profile(
            _SERVICE_INSTANCE_ID,
            _ENVIRONMENT_ID,
            service.authority_binding,
        )
        with pytest.raises(EventStoreError):
            store.retain_blocked_finality_observation(
                _observation(profile, event.event_digest)
            )


def test_the_retained_recovery_profile_is_immutable(tmp_path: Path) -> None:
    store, path, _, _, _ = _live_blocked_store(tmp_path)
    store.close()
    connection = sqlite3.connect(path, isolation_level=None)
    try:
        with pytest.raises(sqlite3.DatabaseError):
            connection.execute(
                "UPDATE integrity_recovery_profile SET recovery_profile_id = ?",
                (_digest("forged"),),
            )
        with pytest.raises(sqlite3.DatabaseError):
            connection.execute("DELETE FROM integrity_recovery_profile")
    finally:
        connection.close()


# ---------------------------------------------------------------------------
# Durable observations
# ---------------------------------------------------------------------------


def test_blocked_observation_is_retained_and_reloads_exactly(tmp_path: Path) -> None:
    store, _, event, profile, _ = _live_blocked_store(tmp_path)
    with store:
        observation = _observation(profile, event.event_digest)
        retained = store.retain_blocked_finality_observation(observation)
        assert retained.to_body() == observation.to_body()
        reloaded = store.load_blocked_finality_observations(event.event_digest)
        assert len(reloaded) == 1
        assert reloaded[0].observation_id == observation.observation_id


def test_exact_duplicate_observation_reconciles(tmp_path: Path) -> None:
    store, _, event, profile, _ = _live_blocked_store(tmp_path)
    with store:
        observation = _observation(profile, event.event_digest)
        store.retain_blocked_finality_observation(observation)
        store.retain_blocked_finality_observation(observation)
        assert len(store.load_blocked_finality_observations(event.event_digest)) == 1


def test_one_ordinal_cannot_carry_two_bodies(tmp_path: Path) -> None:
    store, _, event, profile, _ = _live_blocked_store(tmp_path)
    with store:
        store.retain_blocked_finality_observation(
            _observation(profile, event.event_digest)
        )
        fixture = _fixture()
        conflicting = BlockedFinalityObservationV1.record(
            profile=profile,
            mission_id=fixture.vector.mission_id,
            authority_id=fixture.vector.authority_id,
            target_id=fixture.vector.target_id,
            event_digest=event.event_digest,
            event_seq=0,
            instance_sequence=0,
            pending_record_id=_digest("storage-v3-pending-record"),
            unresolved_phase=LOCAL_PENDING_PHASE_V1,
            unresolved_phase_record_id=_digest("storage-v3-phase-record"),
            blocked_operation="publish_checkpoint",
            blocked_reason_code="modeled_anchor_equivocation",
            attempt_ordinal=1,
            time_bundle=fixture_time_bundle_v1(fixture),
        )
        with pytest.raises(IntegrityTransitionConflictError):
            store.retain_blocked_finality_observation(conflicting)


def test_a_blocked_attempt_ordinal_cannot_regress(tmp_path: Path) -> None:
    store, _, event, profile, _ = _live_blocked_store(tmp_path)
    with store:
        store.retain_blocked_finality_observation(
            _observation(profile, event.event_digest, ordinal=3)
        )
        with pytest.raises(IntegrityTransitionConflictError):
            store.retain_blocked_finality_observation(
                _observation(profile, event.event_digest, ordinal=2)
            )


def test_blocked_observations_are_append_only(tmp_path: Path) -> None:
    store, path, event, profile, _ = _live_blocked_store(tmp_path)
    with store:
        store.retain_blocked_finality_observation(
            _observation(profile, event.event_digest)
        )
    connection = sqlite3.connect(path, isolation_level=None)
    try:
        with pytest.raises(sqlite3.DatabaseError):
            connection.execute(
                "UPDATE integrity_blocked_observations SET attempt_ordinal = 9"
            )
        with pytest.raises(sqlite3.DatabaseError):
            connection.execute("DELETE FROM integrity_blocked_observations")
    finally:
        connection.close()


# ---------------------------------------------------------------------------
# The barrier is never released
# ---------------------------------------------------------------------------


def test_retaining_a_block_never_releases_the_barrier(tmp_path: Path) -> None:
    store, path, event, profile, signer = _live_blocked_store(tmp_path)
    with store:
        observation = _observation(profile, event.event_digest)
        store.retain_blocked_finality_observation(observation)
        store.retain_governed_recovery_decision(
            _sign(profile, signer, observation, RETRY_AUTHORIZED_DISPOSITION_V1)
        )
    connection = sqlite3.connect(path)
    try:
        # The barrier joins pending against finalizations only; the blocked relations
        # cannot satisfy it and cannot advance the instance-global sequence.
        unresolved = connection.execute(
            """
            SELECT count(*)
            FROM integrity_pending_transitions AS pending
            LEFT JOIN integrity_finalizations AS finalized
              ON finalized.event_digest = pending.event_digest
            WHERE finalized.event_digest IS NULL
            """
        ).fetchone()[0]
        assert unresolved == 1
        assert connection.execute(
            "SELECT count(*) FROM integrity_finalizations"
        ).fetchone() == (0,)
    finally:
        connection.close()


def test_generic_replay_still_refuses_while_blocked(tmp_path: Path) -> None:
    from etzio.kernel.store import PendingIntegrityTransitionError

    store, _, event, profile, _ = _live_blocked_store(tmp_path)
    with store:
        store.retain_blocked_finality_observation(
            _observation(profile, event.event_digest)
        )
        with pytest.raises(PendingIntegrityTransitionError):
            store.load(event.mission_id)


# ---------------------------------------------------------------------------
# Governed recovery decisions and seal terminality
# ---------------------------------------------------------------------------


def test_recovery_decision_is_retained_and_idempotent(tmp_path: Path) -> None:
    store, _, event, profile, signer = _live_blocked_store(tmp_path)
    with store:
        observation = _observation(profile, event.event_digest)
        store.retain_blocked_finality_observation(observation)
        signed = _sign(profile, signer, observation, RETRY_AUTHORIZED_DISPOSITION_V1)
        first = store.retain_governed_recovery_decision(signed)
        assert store.retain_governed_recovery_decision(signed) == first


def test_recovery_decision_must_answer_the_latest_observation(tmp_path: Path) -> None:
    store, _, event, profile, signer = _live_blocked_store(tmp_path)
    with store:
        stale = _observation(profile, event.event_digest, ordinal=1)
        store.retain_blocked_finality_observation(stale)
        store.retain_blocked_finality_observation(
            _observation(profile, event.event_digest, ordinal=2)
        )
        with pytest.raises(EventStoreError):
            store.retain_governed_recovery_decision(
                _sign(profile, signer, stale, RETRY_AUTHORIZED_DISPOSITION_V1)
            )


def test_a_forged_recovery_decision_is_refused(tmp_path: Path) -> None:
    from dataclasses import replace

    store, _, event, profile, signer = _live_blocked_store(tmp_path)
    with store:
        observation = _observation(profile, event.event_digest)
        store.retain_blocked_finality_observation(observation)
        signed = _sign(profile, signer, observation, RETRY_AUTHORIZED_DISPOSITION_V1)
        with pytest.raises(ValueError):
            store.retain_governed_recovery_decision(
                replace(signed, signature_bytes=bytes(64))
            )


def test_sealing_is_terminal_for_observations_and_decisions(tmp_path: Path) -> None:
    store, _, event, profile, signer = _live_blocked_store(tmp_path)
    with store:
        observation = _observation(profile, event.event_digest)
        store.retain_blocked_finality_observation(observation)
        store.retain_governed_recovery_decision(
            _sign(profile, signer, observation, INSTANCE_SEALED_DISPOSITION_V1)
        )
        assert store.instance_is_sealed() is True
        with pytest.raises(EventStoreError):
            store.retain_blocked_finality_observation(
                _observation(profile, event.event_digest, ordinal=2)
            )


def test_recovery_decisions_are_append_only(tmp_path: Path) -> None:
    store, path, event, profile, signer = _live_blocked_store(tmp_path)
    with store:
        observation = _observation(profile, event.event_digest)
        store.retain_blocked_finality_observation(observation)
        store.retain_governed_recovery_decision(
            _sign(profile, signer, observation, RETRY_AUTHORIZED_DISPOSITION_V1)
        )
    connection = sqlite3.connect(path, isolation_level=None)
    try:
        with pytest.raises(sqlite3.DatabaseError):
            connection.execute(
                "UPDATE integrity_recovery_decisions SET disposition = 'instance_sealed'"
            )
        with pytest.raises(sqlite3.DatabaseError):
            connection.execute("DELETE FROM integrity_recovery_decisions")
    finally:
        connection.close()


def test_raw_sql_cannot_forge_an_unknown_disposition(tmp_path: Path) -> None:
    store, path, event, profile, _ = _live_blocked_store(tmp_path)
    with store:
        store.retain_blocked_finality_observation(
            _observation(profile, event.event_digest)
        )
    connection = sqlite3.connect(path, isolation_level=None)
    try:
        with pytest.raises(sqlite3.DatabaseError):
            connection.execute(
                "INSERT INTO integrity_recovery_decisions "
                "(decision_id, event_digest, blocked_observation_id, disposition, record) "
                "VALUES (?, ?, ?, 'force_finalize', ?)",
                (
                    _digest("forged-decision"),
                    event.event_digest,
                    _digest("forged-observation"),
                    b"x",
                ),
            )
    finally:
        connection.close()


# ---------------------------------------------------------------------------
# Capacity accounting
# ---------------------------------------------------------------------------


def test_blocked_records_are_charged_to_logical_storage(tmp_path: Path) -> None:
    store, _, event, profile, _ = _live_blocked_store(tmp_path)
    with store:
        before = store._logical_evidence_storage_used_locked()  # noqa: SLF001
        store.retain_blocked_finality_observation(
            _observation(profile, event.event_digest)
        )
        after = store._logical_evidence_storage_used_locked()  # noqa: SLF001
        assert after > before


def test_the_finality_reserve_covers_the_new_records() -> None:
    from etzio.kernel.store import (
        _INTEGRITY_FINALITY_CAPACITY_RESERVE_BYTES_V1,
        _MAX_INTEGRITY_RECORD_BYTES_V1,
        _MAX_INTEGRITY_TRANSITION_EVIDENCE_BYTES_V1,
    )

    assert _INTEGRITY_FINALITY_CAPACITY_RESERVE_BYTES_V1 == (
        (6 * _MAX_INTEGRITY_RECORD_BYTES_V1)
        + _MAX_INTEGRITY_TRANSITION_EVIDENCE_BYTES_V1
    )
