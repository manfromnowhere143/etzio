"""Adversarial storage tests for schema-v2 modeled-integrity finality."""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest

from etzio.integrity_v1 import IntegrityValidationPolicyV1
from etzio.kernel.events_v1 import GENESIS_DIGEST, EventV1
from etzio.kernel.integrity_transition import (
    FinalizedIntegrityTransitionV1,
    PendingIntegrityTransitionV1,
    RepositoryOwnedDeterministicModeledIntegrityServiceV1,
)
from etzio.kernel.store import (
    EventStoreCorruptionError,
    EventStoreError,
    EvidenceVaultCapacityError,
    IntegrityFinalityRequiredError,
    PendingIntegrityTransitionError,
    SQLiteEventStore,
)
from etzio.protocol import canonical_dumps, content_id

_APPLICATION_ID = 0x45545A31
_SCHEMA_VERSION = 2
_LEGACY_PROFILE = "legacy_fixture_v1"
_INTEGRITY_PROFILE = "modeled_integrity_fixture_v1"
_SERVICE_INSTANCE_ID = "Etzio.fixture-instance"
_ENVIRONMENT_ID = "fixture.control-plane"


def _digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("ascii")).hexdigest()


def _state_path(tmp_path: Path, name: str = "state") -> Path:
    parent = tmp_path / name
    parent.mkdir(mode=0o700)
    return parent / "events.sqlite3"


def _policy(
    *,
    anchor_policy_id: str | None = None,
) -> IntegrityValidationPolicyV1:
    return IntegrityValidationPolicyV1(
        decision_policy_id=_digest("decision-policy"),
        decision_time_policy_id=_digest("decision-time-policy"),
        checkpoint_time_policy_id=_digest("checkpoint-time-policy"),
        anchor_policy_id=anchor_policy_id or _digest("anchor-policy"),
        required_revocation_namespaces=frozenset(
            {"authority", "verifier"}
        ),
        max_decision_uncertainty_seconds=0,
        max_checkpoint_uncertainty_seconds=0,
    )


def _refusal_event(
    mission_label: str,
    *,
    decision_time: int = 2_000_000_000,
) -> EventV1:
    return EventV1.create(
        mission_id=_digest(mission_label),
        seq=0,
        kind="mission_admission_refused",
        unit="AQUILA",
        authority_id=_digest(f"{mission_label}-authority"),
        target_id=_digest(f"{mission_label}-target"),
        decision_time=decision_time,
        payload={
            "reason_code": "authority_expired",
            "stage": "admission",
        },
        prev_digest=GENESIS_DIGEST,
    )


def _raw_insert_event(
    connection: sqlite3.Connection,
    event: EventV1,
) -> None:
    connection.execute(
        """
        INSERT INTO events (
            mission_id,
            seq,
            digest,
            prev_digest,
            kind,
            canonical
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            event.mission_id,
            event.seq,
            event.event_digest,
            event.prev_digest,
            event.kind,
            sqlite3.Binary(event.to_canonical_bytes()),
        ),
    )


def _raw_insert_pending_dossier(
    connection: sqlite3.Connection,
    pending: PendingIntegrityTransitionV1,
) -> None:
    connection.execute(
        """
        INSERT INTO integrity_pending_transitions (
            event_digest,
            mission_id,
            event_seq,
            instance_sequence,
            record_id,
            record
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            pending.event_digest,
            pending.mission_id,
            pending.event_seq,
            pending.instance_sequence,
            pending.record_id,
            sqlite3.Binary(pending.to_canonical_bytes()),
        ),
    )
    for slot, blob in enumerate(pending.provider_evidence):
        connection.execute(
            """
            INSERT OR IGNORE INTO integrity_evidence_artifacts (
                evidence_id,
                byte_size,
                content
            ) VALUES (?, ?, ?)
            """,
            (
                blob.evidence_id,
                len(blob.content),
                sqlite3.Binary(blob.content),
            ),
        )
        connection.execute(
            """
            INSERT INTO integrity_transition_evidence (
                event_digest,
                phase,
                slot,
                evidence_kind,
                source_id,
                evidence_id
            ) VALUES (?, 'pending', ?, ?, ?, ?)
            """,
            (
                pending.event_digest,
                slot,
                blob.evidence_kind,
                blob.source_id,
                blob.evidence_id,
            ),
        )


def _raw_insert_orphan_integrity_evidence(
    connection: sqlite3.Connection,
    *,
    label: str,
) -> None:
    content = f"orphan:{label}".encode("ascii")
    evidence_id = (
        "sha256:" + hashlib.sha256(content).hexdigest()
    )
    connection.execute(
        """
        INSERT INTO integrity_evidence_artifacts (
            evidence_id,
            byte_size,
            content
        ) VALUES (?, ?, ?)
        """,
        (
            evidence_id,
            len(content),
            sqlite3.Binary(content),
        ),
    )


def _raw_insert_orphan_integrity_anchor(
    connection: sqlite3.Connection,
    *,
    label: str,
) -> None:
    connection.execute(
        """
        INSERT INTO integrity_anchor_statements (
            event_digest,
            record_id,
            anchor_statement_id,
            record
        ) VALUES (?, ?, ?, ?)
        """,
        (
            _digest(f"{label}-event"),
            _digest(f"{label}-record"),
            _digest(f"{label}-statement"),
            sqlite3.Binary(b"{}"),
        ),
    )


def _raw_insert_orphan_integrity_mapping(
    connection: sqlite3.Connection,
    *,
    label: str,
) -> None:
    connection.execute(
        """
        INSERT INTO integrity_transition_evidence (
            event_digest,
            phase,
            slot,
            evidence_kind,
            source_id,
            evidence_id
        ) VALUES (?, 'pending', 0, 'trusted_time', ?, ?)
        """,
        (
            _digest(f"{label}-event"),
            f"fixture.{label}",
            _digest(f"{label}-evidence"),
        ),
    )


def _profile_row(
    store: SQLiteEventStore,
) -> tuple[object, ...]:
    row = store._connection.execute(  # noqa: SLF001 - adversarial SQL boundary
        """
        SELECT
            profile,
            service_instance_id,
            environment_id,
            validation_policy_id,
            validation_policy_wire,
            authority_binding_id,
            authority_binding_wire
        FROM store_profile
        WHERE singleton = 1
        """
    ).fetchone()
    assert row is not None
    return row


def _assert_integrity_validation_cache_is_current(
    store: SQLiteEventStore,
) -> None:
    cache = store._integrity_validation_cache  # noqa: SLF001
    assert cache is not None
    assert cache == (  # noqa: SLF001
        store._integrity_validation_cache_key_locked()
    )


def _service(
    validation_policy: IntegrityValidationPolicyV1,
) -> RepositoryOwnedDeterministicModeledIntegrityServiceV1:
    return RepositoryOwnedDeterministicModeledIntegrityServiceV1.deterministic(
        seed=b"integrity-store-v2",
        service_instance_id=_SERVICE_INSTANCE_ID,
        environment_id=_ENVIRONMENT_ID,
        validation_policy=validation_policy,
    )


def _enroll(
    store: SQLiteEventStore,
    validation_policy: IntegrityValidationPolicyV1,
    *,
    service: RepositoryOwnedDeterministicModeledIntegrityServiceV1
    | None = None,
    service_instance_id: str = _SERVICE_INSTANCE_ID,
    environment_id: str = _ENVIRONMENT_ID,
) -> RepositoryOwnedDeterministicModeledIntegrityServiceV1:
    resolved_service = service or _service(validation_policy)
    store.enroll_modeled_integrity(
        service_instance_id=service_instance_id,
        environment_id=environment_id,
        validation_policy=validation_policy,
        authority_binding=resolved_service.authority_binding,
    )
    return resolved_service


def _append_pending(
    store: SQLiteEventStore,
    event: EventV1,
    service: RepositoryOwnedDeterministicModeledIntegrityServiceV1,
    *,
    previous_global=None,
    previous_mission=None,
):
    pending = service.prepare_pending_transition(
        event,
        previous_global=previous_global,
        previous_mission=previous_mission,
    )
    retained = store.append_pending_integrity_event(
        event,
        expected_head=GENESIS_DIGEST,
        pending=pending,
    )
    assert retained == event
    return pending


def _finalize_one_transition(
    store: SQLiteEventStore,
    event: EventV1,
    service: RepositoryOwnedDeterministicModeledIntegrityServiceV1,
    *,
    previous_global=None,
    previous_mission=None,
):
    pending = _append_pending(
        store,
        event,
        service,
        previous_global=previous_global,
        previous_mission=previous_mission,
    )
    anchor = service.prepare_anchor_statement(pending)
    assert store.retain_integrity_anchor_statement(anchor) == anchor
    receipts = service.register_anchor_statement(anchor)
    candidate = service.prepare_checkpoint_candidate(
        pending,
        anchor,
        anchor_receipts=receipts,
    )
    assert store.retain_integrity_checkpoint_candidate(candidate) == candidate
    service.publish_checkpoint(candidate)
    floor, floor_evidence = service.observe_current_floor(
        pending,
        candidate,
    )
    finalization = FinalizedIntegrityTransitionV1(
        pending_record_id=pending.record_id,
        checkpoint_candidate_record_id=candidate.record_id,
        event_digest=event.event_digest,
        external_head_floor=floor,
        provider_evidence=floor_evidence,
    )
    assert store.finalize_integrity_transition(finalization) == finalization
    return store.load_integrity_lineage(event.event_digest)


_V2_ONLY_TRIGGERS = (
    "events_reject_while_integrity_pending",
    "events_require_integrity_pending",
    "integrity_anchor_reject_delete",
    "integrity_anchor_reject_update",
    "integrity_checkpoint_reject_delete",
    "integrity_checkpoint_reject_update",
    "integrity_evidence_reject_delete",
    "integrity_evidence_reject_update",
    "integrity_finalization_reject_delete",
    "integrity_finalization_reject_update",
    "integrity_pending_reject_delete",
    "integrity_pending_reject_open_transition",
    "integrity_pending_reject_update",
    "integrity_pending_require_next_global",
    "integrity_pending_require_profile",
    "integrity_transition_evidence_reject_delete",
    "integrity_transition_evidence_reject_update",
    "store_profile_reject_delete",
    "store_profile_validate_update",
)
_V2_ONLY_INDEXES = (
    "integrity_finalized_mission_head",
    "integrity_transition_evidence_identity",
)
_V2_ONLY_TABLES_IN_DROP_ORDER = (
    "integrity_transition_evidence",
    "integrity_finalizations",
    "integrity_checkpoint_candidates",
    "integrity_anchor_statements",
    "integrity_pending_transitions",
    "integrity_evidence_artifacts",
    "store_profile",
)


def _downgrade_exact_empty_integrity_schema_to_v1(path: Path) -> None:
    connection = sqlite3.connect(path, isolation_level=None)
    try:
        for name in _V2_ONLY_TRIGGERS:
            connection.execute(f'DROP TRIGGER "{name}"')
        for name in _V2_ONLY_INDEXES:
            connection.execute(f'DROP INDEX "{name}"')
        for name in _V2_ONLY_TABLES_IN_DROP_ORDER:
            connection.execute(f'DROP TABLE "{name}"')
        connection.execute("PRAGMA user_version = 1")
        assert connection.execute("PRAGMA application_id").fetchone() == (
            _APPLICATION_ID,
        )
    finally:
        connection.close()


def _schema_inventory(
    path: Path,
) -> tuple[tuple[str, str, str], ...]:
    connection = sqlite3.connect(path, isolation_level=None)
    try:
        return tuple(
            connection.execute(
                """
                SELECT type, name, sql
                FROM sqlite_schema
                WHERE name NOT LIKE 'sqlite_%'
                ORDER BY type ASC, name ASC
                """
            ).fetchall()
        )
    finally:
        connection.close()


def test_fresh_store_defaults_to_schema_v2_legacy_profile(
    tmp_path: Path,
) -> None:
    path = _state_path(tmp_path)
    with SQLiteEventStore(path) as store:
        assert store._connection.execute(  # noqa: SLF001
            "PRAGMA application_id"
        ).fetchone() == (_APPLICATION_ID,)
        assert store._connection.execute(  # noqa: SLF001
            "PRAGMA user_version"
        ).fetchone() == (_SCHEMA_VERSION,)
        assert _profile_row(store) == (
            _LEGACY_PROFILE,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        retained_tables = {
            row[0]
            for row in store._connection.execute(  # noqa: SLF001
                """
                SELECT name
                FROM sqlite_schema
                WHERE type = 'table'
                """
            )
        }
        assert {
            "store_profile",
            "integrity_evidence_artifacts",
            "integrity_pending_transitions",
            "integrity_anchor_statements",
            "integrity_checkpoint_candidates",
            "integrity_finalizations",
            "integrity_transition_evidence",
        } <= retained_tables

    with SQLiteEventStore(path) as reopened:
        assert _profile_row(reopened)[0] == _LEGACY_PROFILE


def test_empty_store_integrity_enrollment_is_exact_and_idempotent(
    tmp_path: Path,
) -> None:
    path = _state_path(tmp_path)
    policy = _policy()
    expected_wire = canonical_dumps(policy.to_body())
    expected_id = content_id(
        "integrity_validation_policy",
        policy.to_body(),
    )
    service = _service(policy)
    binding_wire = service.authority_binding.to_canonical_bytes()
    with SQLiteEventStore(path) as store:
        _enroll(store, policy, service=service)
        expected = (
            _INTEGRITY_PROFILE,
            _SERVICE_INSTANCE_ID,
            _ENVIRONMENT_ID,
            expected_id,
            expected_wire,
            service.authority_binding.binding_id,
            binding_wire,
        )
        assert _profile_row(store) == expected

        _enroll(store, policy, service=service)
        assert _profile_row(store) == expected

        with pytest.raises(EventStoreError, match="conflicts"):
            store.enroll_modeled_integrity(
                service_instance_id="Etzio.other-instance",
                environment_id=_ENVIRONMENT_ID,
                validation_policy=policy,
                authority_binding=service.authority_binding,
            )
        with pytest.raises(EventStoreError, match="conflicts"):
            other_policy = _policy(
                anchor_policy_id=_digest("other-anchor-policy")
            )
            store.enroll_modeled_integrity(
                service_instance_id=_SERVICE_INSTANCE_ID,
                environment_id=_ENVIRONMENT_ID,
                validation_policy=other_policy,
                authority_binding=service.authority_binding,
            )
        assert _profile_row(store) == expected


def test_integrity_enrollment_rejects_replacement_adapter_authority(
    tmp_path: Path,
) -> None:
    path = _state_path(tmp_path)
    policy = _policy()
    admitted = _service(policy)
    replacement = (
        RepositoryOwnedDeterministicModeledIntegrityServiceV1.deterministic(
            seed=b"integrity-store-v2-replacement-authority",
            service_instance_id=_SERVICE_INSTANCE_ID,
            environment_id=_ENVIRONMENT_ID,
            validation_policy=policy,
        )
    )
    assert (
        admitted.authority_binding.binding_id
        != replacement.authority_binding.binding_id
    )
    event = _refusal_event("replacement-adapter-authority")

    with SQLiteEventStore(path) as store:
        _enroll(store, policy, service=admitted)
        retained = _profile_row(store)
        with pytest.raises(EventStoreError, match="conflicts"):
            _enroll(store, policy, service=replacement)
        assert _profile_row(store) == retained
        with pytest.raises(
            EventStoreError,
            match="enrolled store profile",
        ):
            _append_pending(store, event, replacement)

        pending = _append_pending(store, event, admitted)
        anchor = admitted.prepare_anchor_statement(pending)
        assert store.retain_integrity_anchor_statement(anchor) == anchor
        receipts = admitted.register_anchor_statement(anchor)
        replacement_candidate = (
            replacement.prepare_checkpoint_candidate(
                pending,
                anchor,
                anchor_receipts=receipts,
            )
        )
        with pytest.raises(
            EventStoreError,
            match="authority binding",
        ):
            store.retain_integrity_checkpoint_candidate(
                replacement_candidate
            )
        lineage = store.load_integrity_lineage(event.event_digest)
        assert lineage is not None
        assert lineage.checkpoint_candidate is None

    with SQLiteEventStore(path) as reopened:
        with pytest.raises(EventStoreError, match="conflicts"):
            _enroll(reopened, policy, service=replacement)
        _enroll(reopened, policy, service=admitted)


def test_integrity_enrollment_preflights_profile_and_finality_capacity(
    tmp_path: Path,
) -> None:
    path = _state_path(tmp_path)
    policy = _policy()
    with SQLiteEventStore(path, max_vault_bytes=1) as store:
        retained = _profile_row(store)
        with pytest.raises(
            EvidenceVaultCapacityError,
            match="enrollment",
        ):
            _enroll(store, policy)
        assert _profile_row(store) == retained
        assert store._connection.execute(  # noqa: SLF001
            "SELECT count(*) FROM events"
        ).fetchone() == (0,)

    with SQLiteEventStore(path, max_vault_bytes=1) as reopened:
        assert _profile_row(reopened) == retained


@pytest.mark.parametrize(
    ("service_instance_id", "environment_id"),
    (
        ("E", _ENVIRONMENT_ID),
        ("Étzio.fixture", _ENVIRONMENT_ID),
        (_SERVICE_INSTANCE_ID, "f"),
        (_SERVICE_INSTANCE_ID, "fixture.环境"),
    ),
)
def test_integrity_enrollment_rejects_noncanonical_scope(
    tmp_path: Path,
    service_instance_id: str,
    environment_id: str,
) -> None:
    path = _state_path(
        tmp_path,
        hashlib.sha256(
            f"{service_instance_id}:{environment_id}".encode()
        ).hexdigest(),
    )
    policy = _policy()
    service = _service(policy)
    with SQLiteEventStore(path) as store:
        retained = _profile_row(store)
        with pytest.raises(
            EventStoreError,
            match="canonical ASCII",
        ):
            store.enroll_modeled_integrity(
                service_instance_id=service_instance_id,
                environment_id=environment_id,
                validation_policy=policy,
                authority_binding=service.authority_binding,
            )
        assert _profile_row(store) == retained


def test_store_profile_sql_rejects_noncanonical_scope(
    tmp_path: Path,
) -> None:
    path = _state_path(tmp_path)
    policy = _policy()
    service = _service(policy)
    policy_wire = canonical_dumps(policy.to_body())
    policy_id = content_id(
        "integrity_validation_policy",
        policy.to_body(),
    )
    binding_wire = service.authority_binding.to_canonical_bytes()
    with SQLiteEventStore(path) as store:
        with pytest.raises(sqlite3.IntegrityError, match="CHECK"):
            store._connection.execute(  # noqa: SLF001
                """
                UPDATE store_profile
                SET
                    profile = ?,
                    service_instance_id = 'E',
                    environment_id = ?,
                    validation_policy_id = ?,
                    validation_policy_wire = ?,
                    authority_binding_id = ?,
                    authority_binding_wire = ?
                WHERE singleton = 1
                """,
                (
                    _INTEGRITY_PROFILE,
                    _ENVIRONMENT_ID,
                    policy_id,
                    sqlite3.Binary(policy_wire),
                    service.authority_binding.binding_id,
                    sqlite3.Binary(binding_wire),
                ),
            )
        assert _profile_row(store)[0] == _LEGACY_PROFILE


def test_store_profile_reload_rejects_bypassed_noncanonical_scope(
    tmp_path: Path,
) -> None:
    path = _state_path(tmp_path)
    policy = _policy()
    service = _service(policy)
    policy_wire = canonical_dumps(policy.to_body())
    binding_wire = service.authority_binding.to_canonical_bytes()
    with SQLiteEventStore(path) as store:
        connection = store._connection  # noqa: SLF001
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute(
            """
            UPDATE store_profile
            SET
                profile = ?,
                service_instance_id = 'E',
                environment_id = ?,
                validation_policy_id = ?,
                validation_policy_wire = ?,
                authority_binding_id = ?,
                authority_binding_wire = ?
            WHERE singleton = 1
            """,
            (
                _INTEGRITY_PROFILE,
                _ENVIRONMENT_ID,
                content_id(
                    "integrity_validation_policy",
                    policy.to_body(),
                ),
                sqlite3.Binary(policy_wire),
                service.authority_binding.binding_id,
                sqlite3.Binary(binding_wire),
            ),
        )
        connection.execute("PRAGMA ignore_check_constraints = OFF")

        with pytest.raises(
            EventStoreCorruptionError,
            match="profile is malformed",
        ):
            store.load_unresolved_integrity_transition()


def test_nonempty_legacy_store_cannot_enroll(tmp_path: Path) -> None:
    path = _state_path(tmp_path)
    event = _refusal_event("legacy-nonempty")
    policy = _policy()
    service = _service(policy)
    with SQLiteEventStore(path) as store:
        assert store.append(event, expected_head=GENESIS_DIGEST) == event
        with pytest.raises(
            EventStoreError,
            match="nonempty legacy history",
        ):
            store.enroll_modeled_integrity(
                service_instance_id=_SERVICE_INSTANCE_ID,
                environment_id=_ENVIRONMENT_ID,
                validation_policy=policy,
                authority_binding=service.authority_binding,
            )
        assert _profile_row(store) == (
            _LEGACY_PROFILE,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        assert store.load(event.mission_id) == (event,)


def test_exact_v1_migration_preserves_nonempty_history_as_legacy(
    tmp_path: Path,
) -> None:
    path = _state_path(tmp_path)
    event = _refusal_event("migrated-v1")
    policy = _policy()
    service = _service(policy)
    with SQLiteEventStore(path) as store:
        assert store.append(event, expected_head=GENESIS_DIGEST) == event
    _downgrade_exact_empty_integrity_schema_to_v1(path)

    with SQLiteEventStore(path) as migrated:
        assert migrated._connection.execute(  # noqa: SLF001
            "PRAGMA user_version"
        ).fetchone() == (_SCHEMA_VERSION,)
        assert migrated.load(event.mission_id) == (event,)
        assert _profile_row(migrated) == (
            _LEGACY_PROFILE,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        assert migrated.load_unresolved_integrity_transition() is None
        with pytest.raises(
            EventStoreError,
            match="nonempty legacy history",
        ):
            migrated.enroll_modeled_integrity(
                service_instance_id=_SERVICE_INSTANCE_ID,
                environment_id=_ENVIRONMENT_ID,
                validation_policy=policy,
                authority_binding=service.authority_binding,
            )


def test_exact_empty_v1_vault_migrates_then_enrolls_modeled_authority(
    tmp_path: Path,
) -> None:
    path = _state_path(tmp_path)
    policy = _policy()
    service = _service(policy)
    with SQLiteEventStore(path):
        pass
    _downgrade_exact_empty_integrity_schema_to_v1(path)

    with SQLiteEventStore(path) as migrated:
        assert migrated._connection.execute(  # noqa: SLF001
            "PRAGMA application_id"
        ).fetchone() == (_APPLICATION_ID,)
        assert migrated._connection.execute(  # noqa: SLF001
            "PRAGMA user_version"
        ).fetchone() == (_SCHEMA_VERSION,)
        assert _profile_row(migrated) == (
            _LEGACY_PROFILE,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        _enroll(migrated, policy, service=service)
        assert _profile_row(migrated)[0] == _INTEGRITY_PROFILE

    with SQLiteEventStore(path) as reopened:
        _enroll(reopened, policy, service=service)
        assert _profile_row(reopened)[0] == _INTEGRITY_PROFILE


def test_failed_v1_to_v2_migration_rolls_back_every_schema_byte(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _state_path(tmp_path)
    with SQLiteEventStore(path):
        pass
    _downgrade_exact_empty_integrity_schema_to_v1(path)
    before = _schema_inventory(path)

    def fail_after_transactional_schema_creation(
        _store: SQLiteEventStore,
    ) -> None:
        raise RuntimeError("injected migration validation failure")

    with monkeypatch.context() as patch:
        patch.setattr(
            SQLiteEventStore,
            "_validate_schema",
            fail_after_transactional_schema_creation,
        )
        with pytest.raises(
            RuntimeError,
            match="injected migration validation failure",
        ):
            SQLiteEventStore(path)

    connection = sqlite3.connect(path, isolation_level=None)
    try:
        assert connection.execute(
            "PRAGMA application_id"
        ).fetchone() == (_APPLICATION_ID,)
        assert connection.execute("PRAGMA user_version").fetchone() == (1,)
        assert connection.execute("PRAGMA integrity_check").fetchone() == (
            "ok",
        )
        assert connection.execute(
            "PRAGMA foreign_key_check"
        ).fetchall() == []
        assert connection.execute(
            """
            SELECT 1
            FROM sqlite_schema
            WHERE name = 'store_profile'
            """
        ).fetchone() is None
    finally:
        connection.close()
    assert _schema_inventory(path) == before

    with SQLiteEventStore(path) as migrated:
        assert migrated._connection.execute(  # noqa: SLF001
            "PRAGMA user_version"
        ).fetchone() == (_SCHEMA_VERSION,)
        assert _profile_row(migrated)[0] == _LEGACY_PROFILE


def test_enrolled_store_refuses_base_and_raw_event_append(
    tmp_path: Path,
) -> None:
    path = _state_path(tmp_path)
    event = _refusal_event("enrolled-refusal")
    policy = _policy()
    with SQLiteEventStore(path) as store:
        _enroll(store, policy)
        with pytest.raises(IntegrityFinalityRequiredError):
            store.append(event, expected_head=GENESIS_DIGEST)
        with pytest.raises(
            sqlite3.IntegrityError,
            match="omitted its pending transition",
        ):
            _raw_insert_event(store._connection, event)  # noqa: SLF001
        assert store.load(event.mission_id) == ()


def test_integrity_schema_tamper_is_detected_on_reopen(
    tmp_path: Path,
) -> None:
    path = _state_path(tmp_path)
    with SQLiteEventStore(path):
        pass
    connection = sqlite3.connect(path, isolation_level=None)
    try:
        connection.execute("DROP TRIGGER integrity_pending_reject_update")
    finally:
        connection.close()

    with pytest.raises(
        EventStoreCorruptionError,
        match="schema objects differ",
    ):
        SQLiteEventStore(path)


def test_integrity_profile_records_and_evidence_are_sql_append_only(
    tmp_path: Path,
) -> None:
    path = _state_path(tmp_path)
    policy = _policy()
    service = _service(policy)
    event = _refusal_event("append-only")
    with SQLiteEventStore(path) as store:
        _enroll(store, policy, service=service)
        lineage = _finalize_one_transition(
            store,
            event,
            service,
        )
        assert lineage is not None and lineage.finalization is not None

        connection = store._connection  # noqa: SLF001
        record_tables = (
            "integrity_pending_transitions",
            "integrity_anchor_statements",
            "integrity_checkpoint_candidates",
            "integrity_finalizations",
        )
        for table in record_tables:
            with pytest.raises(sqlite3.IntegrityError, match="append-only"):
                connection.execute(
                    f'UPDATE "{table}" SET record = record'
                )
            with pytest.raises(sqlite3.IntegrityError, match="append-only"):
                connection.execute(f'DELETE FROM "{table}"')

        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                """
                UPDATE integrity_evidence_artifacts
                SET content = content
                """
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "DELETE FROM integrity_evidence_artifacts"
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                """
                UPDATE integrity_transition_evidence
                SET source_id = source_id
                """
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "DELETE FROM integrity_transition_evidence"
            )
        with pytest.raises(sqlite3.IntegrityError, match="forbidden"):
            connection.execute(
                "UPDATE store_profile SET profile = profile"
            )
        with pytest.raises(sqlite3.IntegrityError, match="permanent"):
            connection.execute("DELETE FROM store_profile")

        replayed = store.load_integrity_lineage(event.event_digest)
        assert replayed == lineage


def test_unresolved_pending_blocks_cross_mission_base_and_raw_append(
    tmp_path: Path,
) -> None:
    path = _state_path(tmp_path)
    policy = _policy()
    service = _service(policy)
    first = _refusal_event("pending-first")
    second = _refusal_event(
        "pending-second",
        decision_time=first.decision_time + 1,
    )
    with SQLiteEventStore(path) as store:
        _enroll(store, policy, service=service)
        pending = _append_pending(store, first, service)
        unresolved = store.load_unresolved_integrity_transition()
        assert unresolved is not None
        assert unresolved.pending.record_id == pending.record_id

        with pytest.raises(PendingIntegrityTransitionError):
            store.append_pending_integrity_event(
                second,
                expected_head=GENESIS_DIGEST,
                pending=service.prepare_pending_transition(
                    second,
                    previous_global=None,
                    previous_mission=None,
                ),
            )
        with pytest.raises(
            sqlite3.IntegrityError,
            match="instance-global integrity transition is pending",
        ):
            _raw_insert_event(store._connection, second)  # noqa: SLF001

        with pytest.raises(
            PendingIntegrityTransitionError,
            match="generic mission replay",
        ):
            store.load(first.mission_id)
        with pytest.raises(
            PendingIntegrityTransitionError,
            match="generic mission replay",
        ):
            store.load(second.mission_id)
        assert store.load_integrity_event(first.event_digest) == first
        assert store.load_integrity_event(second.event_digest) is None


def test_authenticated_replay_rejects_raw_pending_from_another_scope(
    tmp_path: Path,
) -> None:
    path = _state_path(tmp_path)
    policy = _policy()
    event = _refusal_event("raw-wrong-scope")
    wrong_scope_service = (
        RepositoryOwnedDeterministicModeledIntegrityServiceV1.deterministic(
            seed=b"integrity-store-v2-wrong-scope",
            service_instance_id="Etzio.wrong-instance",
            environment_id="fixture.wrong-control-plane",
            validation_policy=policy,
        )
    )
    wrong_scope_pending = wrong_scope_service.prepare_pending_transition(
        event,
        previous_global=None,
        previous_mission=None,
    )

    with SQLiteEventStore(path) as store:
        _enroll(store, policy)
        connection = store._connection  # noqa: SLF001
        connection.execute("BEGIN IMMEDIATE")
        _raw_insert_pending_dossier(connection, wrong_scope_pending)
        _raw_insert_event(connection, event)
        connection.execute("COMMIT")

        with pytest.raises(
            EventStoreCorruptionError,
            match="authority binding|authenticated replay",
        ):
            store.load(event.mission_id)

    with pytest.raises(
        EventStoreCorruptionError,
        match="authority binding|authenticated replay",
    ):
        SQLiteEventStore(path)


def test_all_integrity_phases_reconcile_exact_retries_after_finality(
    tmp_path: Path,
) -> None:
    path = _state_path(tmp_path)
    policy = _policy()
    service = _service(policy)
    event = _refusal_event("phase-exact-retry")
    with SQLiteEventStore(path) as store:
        _enroll(store, policy, service=service)
        _assert_integrity_validation_cache_is_current(store)
        pending = _append_pending(store, event, service)
        _assert_integrity_validation_cache_is_current(store)

        assert (
            store.append_pending_integrity_event(
                event,
                expected_head=GENESIS_DIGEST,
                pending=pending,
            )
            == event
        )

        anchor = service.prepare_anchor_statement(pending)
        assert store.retain_integrity_anchor_statement(anchor) == anchor
        _assert_integrity_validation_cache_is_current(store)
        receipts = service.register_anchor_statement(anchor)
        candidate = service.prepare_checkpoint_candidate(
            pending,
            anchor,
            anchor_receipts=receipts,
        )
        assert (
            store.retain_integrity_checkpoint_candidate(candidate)
            == candidate
        )
        _assert_integrity_validation_cache_is_current(store)
        service.publish_checkpoint(candidate)
        floor, floor_evidence = service.observe_current_floor(
            pending,
            candidate,
        )
        finalization = FinalizedIntegrityTransitionV1(
            pending_record_id=pending.record_id,
            checkpoint_candidate_record_id=candidate.record_id,
            event_digest=event.event_digest,
            external_head_floor=floor,
            provider_evidence=floor_evidence,
        )
        assert (
            store.finalize_integrity_transition(finalization)
            == finalization
        )
        _assert_integrity_validation_cache_is_current(store)

        assert (
            store.append_pending_integrity_event(
                event,
                expected_head=GENESIS_DIGEST,
                pending=pending,
            )
            == event
        )
        assert store.retain_integrity_anchor_statement(anchor) == anchor
        assert (
            store.retain_integrity_checkpoint_candidate(candidate)
            == candidate
        )
        assert (
            store.finalize_integrity_transition(finalization)
            == finalization
        )
        assert store.load_integrity_lineage(event.event_digest).finalization == (
            finalization
        )
        for table in (
            "events",
            "integrity_pending_transitions",
            "integrity_anchor_statements",
            "integrity_checkpoint_candidates",
            "integrity_finalizations",
        ):
            assert store._connection.execute(  # noqa: SLF001
                f'SELECT count(*) FROM "{table}"'
            ).fetchone() == (1,)


def test_integrity_head_and_predecessor_reads_are_cross_mission_exact(
    tmp_path: Path,
) -> None:
    path = _state_path(tmp_path)
    policy = _policy()
    service = _service(policy)
    first = _refusal_event("latest-finalized-first-mission")
    second = _refusal_event(
        "latest-finalized-second-mission",
        decision_time=first.decision_time + 1,
    )
    with SQLiteEventStore(path) as store:
        _enroll(store, policy, service=service)
        first_lineage = _finalize_one_transition(
            store,
            first,
            service,
        )
        assert first_lineage is not None
        assert first_lineage.finalization is not None
        assert store.load_integrity_predecessor_lineages(
            first.event_digest
        ) == (None, None)

        second_lineage = _finalize_one_transition(
            store,
            second,
            service,
            previous_global=first_lineage,
            previous_mission=None,
        )
        assert second_lineage is not None
        assert second_lineage.finalization is not None

        latest_global, first_mission = (
            store.load_latest_finalized_integrity_lineages(
                first.mission_id
            )
        )
        assert latest_global == second_lineage
        assert first_mission == first_lineage

        latest_global, second_mission = (
            store.load_latest_finalized_integrity_lineages(
                second.mission_id
            )
        )
        assert latest_global == second_lineage
        assert second_mission == second_lineage
        assert store.load_integrity_predecessor_lineages(
            second.event_digest
        ) == (first_lineage, None)


def test_cached_validation_invalidates_on_same_connection_dml(
    tmp_path: Path,
) -> None:
    path = _state_path(tmp_path)
    with SQLiteEventStore(path) as store:
        _enroll(store, _policy())
        primed = store._integrity_validation_cache  # noqa: SLF001
        assert primed is not None

        _raw_insert_orphan_integrity_evidence(
            store._connection,  # noqa: SLF001
            label="same-connection",
        )
        assert store._connection.total_changes > (  # noqa: SLF001
            primed.total_changes
        )
        with pytest.raises(
            EventStoreCorruptionError,
            match="orphan provider evidence",
        ):
            store.load_unresolved_integrity_transition()


def test_cached_validation_invalidates_on_other_connection_commit(
    tmp_path: Path,
) -> None:
    path = _state_path(tmp_path)
    with SQLiteEventStore(path) as store:
        _enroll(store, _policy())
        primed = store._integrity_validation_cache  # noqa: SLF001
        assert primed is not None

        other = sqlite3.connect(path, isolation_level=None)
        try:
            _raw_insert_orphan_integrity_evidence(
                other,
                label="other-connection",
            )
        finally:
            other.close()

        changed = store._integrity_validation_cache_key_locked()  # noqa: SLF001
        assert changed.data_version != primed.data_version
        with pytest.raises(
            EventStoreCorruptionError,
            match="orphan provider evidence",
        ):
            store.load_unresolved_integrity_transition()


def test_cached_validation_hashes_schema_even_if_cookie_is_reset(
    tmp_path: Path,
) -> None:
    path = _state_path(tmp_path)
    with SQLiteEventStore(path) as store:
        _enroll(store, _policy())
        primed = store._integrity_validation_cache  # noqa: SLF001
        assert primed is not None

        store._connection.execute(  # noqa: SLF001
            "DROP TRIGGER integrity_pending_reject_update"
        )
        store._connection.execute(  # noqa: SLF001
            f"PRAGMA schema_version = {primed.schema_version}"
        )
        forged = store._integrity_validation_cache_key_locked()  # noqa: SLF001
        assert forged == primed

        with pytest.raises(
            EventStoreCorruptionError,
            match="schema definitions differ",
        ):
            store.load_unresolved_integrity_transition()


def test_cached_validation_rejects_same_connection_schema_identity_change(
    tmp_path: Path,
) -> None:
    path = _state_path(tmp_path)
    with SQLiteEventStore(path) as store:
        _enroll(store, _policy())
        _assert_integrity_validation_cache_is_current(store)

        store._connection.execute(  # noqa: SLF001
            "PRAGMA user_version = 1"
        )
        with pytest.raises(
            EventStoreCorruptionError,
            match="schema identity",
        ):
            store.load_unresolved_integrity_transition()


def test_cached_validation_rejects_other_connection_schema_identity_change(
    tmp_path: Path,
) -> None:
    path = _state_path(tmp_path)
    with SQLiteEventStore(path) as store:
        _enroll(store, _policy())
        _assert_integrity_validation_cache_is_current(store)

        other = sqlite3.connect(path, isolation_level=None)
        try:
            other.execute("PRAGMA application_id = 0")
        finally:
            other.close()

        with pytest.raises(
            EventStoreCorruptionError,
            match="schema identity",
        ):
            store.load_unresolved_integrity_transition()


@pytest.mark.parametrize(
    ("pragma_name", "drift_value", "restore_value", "observed_value"),
    (
        ("journal_mode", "OFF", "DELETE", "off"),
        ("synchronous", "OFF", "EXTRA", 0),
        ("foreign_keys", "OFF", "ON", 0),
        ("trusted_schema", "ON", "OFF", 1),
        ("ignore_check_constraints", "ON", "OFF", 1),
        ("read_uncommitted", "ON", "OFF", 1),
        ("writable_schema", "ON", "OFF", 1),
    ),
)
def test_cached_validation_rejects_connection_security_pragma_drift(
    tmp_path: Path,
    pragma_name: str,
    drift_value: str,
    restore_value: str,
    observed_value: object,
) -> None:
    path = _state_path(tmp_path, f"cached-{pragma_name}")
    with SQLiteEventStore(path) as store:
        _enroll(store, _policy())
        _assert_integrity_validation_cache_is_current(store)

        try:
            store._connection.execute(  # noqa: SLF001
                f"PRAGMA {pragma_name} = {drift_value}"
            )
            assert store._connection.execute(  # noqa: SLF001
                f"PRAGMA {pragma_name}"
            ).fetchone() == (observed_value,)
            with pytest.raises(
                EventStoreCorruptionError,
                match="security settings",
            ) as refused:
                store.load_unresolved_integrity_transition()
            assert type(refused.value) is EventStoreCorruptionError
            assert store._integrity_validation_cache is None  # noqa: SLF001
        finally:
            store._connection.execute(  # noqa: SLF001
                f"PRAGMA {pragma_name} = {restore_value}"
            )

        assert store.load_unresolved_integrity_transition() is None
        _assert_integrity_validation_cache_is_current(store)


@pytest.mark.parametrize(
    ("pragma_name", "drift_value", "restore_value"),
    (
        ("journal_mode", "OFF", "DELETE"),
        ("synchronous", "OFF", "EXTRA"),
        ("foreign_keys", "OFF", "ON"),
        ("trusted_schema", "ON", "OFF"),
        ("ignore_check_constraints", "ON", "OFF"),
        ("read_uncommitted", "ON", "OFF"),
        ("writable_schema", "ON", "OFF"),
    ),
)
def test_pending_append_rejects_connection_security_pragma_drift(
    tmp_path: Path,
    pragma_name: str,
    drift_value: str,
    restore_value: str,
) -> None:
    path = _state_path(tmp_path, f"append-{pragma_name}")
    policy = _policy()
    service = _service(policy)
    event = _refusal_event(f"append-{pragma_name}")
    pending = service.prepare_pending_transition(
        event,
        previous_global=None,
        previous_mission=None,
    )
    with SQLiteEventStore(path) as store:
        _enroll(store, policy, service=service)

        try:
            store._connection.execute(  # noqa: SLF001
                f"PRAGMA {pragma_name} = {drift_value}"
            )
            with pytest.raises(
                EventStoreCorruptionError,
                match="security settings",
            ) as refused:
                store.append_pending_integrity_event(
                    event,
                    expected_head=GENESIS_DIGEST,
                    pending=pending,
                )
            assert type(refused.value) is EventStoreCorruptionError
        finally:
            store._connection.execute(  # noqa: SLF001
                f"PRAGMA {pragma_name} = {restore_value}"
            )

        assert store._connection.execute(  # noqa: SLF001
            "SELECT count(*) FROM events"
        ).fetchone() == (0,)
        assert store._connection.execute(  # noqa: SLF001
            "SELECT count(*) FROM integrity_pending_transitions"
        ).fetchone() == (0,)


@pytest.mark.parametrize(
    ("pragma_name", "drift_value", "restore_value"),
    (
        ("journal_mode", "OFF", "DELETE"),
        ("synchronous", "OFF", "EXTRA"),
        ("foreign_keys", "OFF", "ON"),
        ("trusted_schema", "ON", "OFF"),
        ("ignore_check_constraints", "ON", "OFF"),
        ("read_uncommitted", "ON", "OFF"),
        ("writable_schema", "ON", "OFF"),
    ),
)
def test_finalization_rejects_connection_security_pragma_drift(
    tmp_path: Path,
    pragma_name: str,
    drift_value: str,
    restore_value: str,
) -> None:
    path = _state_path(tmp_path, f"finalize-{pragma_name}")
    policy = _policy()
    service = _service(policy)
    event = _refusal_event(f"finalize-{pragma_name}")
    with SQLiteEventStore(path) as store:
        _enroll(store, policy, service=service)
        pending = _append_pending(store, event, service)
        anchor = service.prepare_anchor_statement(pending)
        assert store.retain_integrity_anchor_statement(anchor) == anchor
        receipts = service.register_anchor_statement(anchor)
        candidate = service.prepare_checkpoint_candidate(
            pending,
            anchor,
            anchor_receipts=receipts,
        )
        assert (
            store.retain_integrity_checkpoint_candidate(candidate)
            == candidate
        )
        service.publish_checkpoint(candidate)
        floor, floor_evidence = service.observe_current_floor(
            pending,
            candidate,
        )
        finalization = FinalizedIntegrityTransitionV1(
            pending_record_id=pending.record_id,
            checkpoint_candidate_record_id=candidate.record_id,
            event_digest=event.event_digest,
            external_head_floor=floor,
            provider_evidence=floor_evidence,
        )

        try:
            store._connection.execute(  # noqa: SLF001
                f"PRAGMA {pragma_name} = {drift_value}"
            )
            with pytest.raises(
                EventStoreCorruptionError,
                match="security settings",
            ) as refused:
                store.finalize_integrity_transition(finalization)
            assert type(refused.value) is EventStoreCorruptionError
        finally:
            store._connection.execute(  # noqa: SLF001
                f"PRAGMA {pragma_name} = {restore_value}"
            )

        assert store._connection.execute(  # noqa: SLF001
            "SELECT count(*) FROM integrity_finalizations"
        ).fetchone() == (0,)
        unresolved = store.load_unresolved_integrity_transition()
        assert unresolved is not None
        assert unresolved.finalization is None


@pytest.mark.parametrize(
    "inject",
    (
        _raw_insert_orphan_integrity_anchor,
        _raw_insert_orphan_integrity_mapping,
    ),
)
def test_uncached_replay_rejects_other_connection_phase_orphans(
    tmp_path: Path,
    inject,
) -> None:
    path = _state_path(tmp_path)
    with SQLiteEventStore(path) as store:
        _enroll(store, _policy())
        _assert_integrity_validation_cache_is_current(store)

        other = sqlite3.connect(path, isolation_level=None)
        try:
            assert other.execute("PRAGMA foreign_keys").fetchone() == (0,)
            inject(other, label="other-connection-orphan")
        finally:
            other.close()

        with pytest.raises(
            EventStoreCorruptionError,
            match="foreign-key violation",
        ):
            store.load_unresolved_integrity_transition()


def test_owned_phase_cache_rejects_raw_finalized_prefix_rewrite(
    tmp_path: Path,
) -> None:
    path = _state_path(tmp_path)
    policy = _policy()
    service = _service(policy)
    event = _refusal_event("raw-finalized-prefix-rewrite")
    wrong_scope_service = (
        RepositoryOwnedDeterministicModeledIntegrityServiceV1.deterministic(
            seed=b"integrity-store-v2-forged-prefix",
            service_instance_id="Etzio.forged-instance",
            environment_id="fixture.forged-control-plane",
            validation_policy=policy,
        )
    )
    wrong_pending = wrong_scope_service.prepare_pending_transition(
        event,
        previous_global=None,
        previous_mission=None,
    )

    with SQLiteEventStore(path) as store:
        _enroll(store, policy, service=service)
        lineage = _finalize_one_transition(store, event, service)
        assert lineage is not None
        assert lineage.finalization is not None
        assert lineage.pending.record_id != wrong_pending.record_id
        _assert_integrity_validation_cache_is_current(store)
        primed = store._integrity_validation_cache  # noqa: SLF001
        assert primed is not None

        connection = store._connection  # noqa: SLF001
        trigger_row = connection.execute(
            """
            SELECT sql
            FROM sqlite_schema
            WHERE
                type = 'trigger'
                AND name = 'integrity_pending_reject_update'
            """
        ).fetchone()
        assert trigger_row is not None
        trigger_sql = trigger_row[0]
        assert type(trigger_sql) is str
        schema_contract_before = (  # noqa: SLF001
            store._schema_contract_locked()[1]
        )

        connection.execute(
            "DROP TRIGGER integrity_pending_reject_update"
        )
        connection.execute(
            """
            UPDATE integrity_pending_transitions
            SET record_id = ?, record = ?
            WHERE event_digest = ?
            """,
            (
                wrong_pending.record_id,
                sqlite3.Binary(wrong_pending.to_canonical_bytes()),
                event.event_digest,
            ),
        )
        connection.execute(trigger_sql)
        connection.execute(
            f"PRAGMA schema_version = {primed.schema_version}"
        )

        forged = store._integrity_validation_cache_key_locked()  # noqa: SLF001
        assert forged.schema_version == primed.schema_version
        assert forged.data_version == primed.data_version
        assert forged.total_changes > primed.total_changes
        assert store._schema_contract_locked()[1] == (  # noqa: SLF001
            schema_contract_before
        )

        with pytest.raises(EventStoreCorruptionError):
            store.load_integrity_lineage(event.event_digest)
        assert store._integrity_validation_cache is None  # noqa: SLF001


def test_second_connection_cannot_cross_global_pending_transition(
    tmp_path: Path,
) -> None:
    path = _state_path(tmp_path)
    policy = _policy()
    service = _service(policy)
    first = _refusal_event("two-connection-first")
    second = _refusal_event(
        "two-connection-second",
        decision_time=first.decision_time + 1,
    )
    with SQLiteEventStore(path) as first_store:
        _enroll(first_store, policy, service=service)
        with SQLiteEventStore(path) as second_store:
            _append_pending(first_store, first, service)

            with pytest.raises(
                PendingIntegrityTransitionError,
                match="instance-global",
            ):
                second_store.append_pending_integrity_event(
                    second,
                    expected_head=GENESIS_DIGEST,
                    pending=service.prepare_pending_transition(
                        second,
                        previous_global=None,
                        previous_mission=None,
                    ),
                )

            with pytest.raises(
                PendingIntegrityTransitionError,
                match="generic mission replay",
            ):
                first_store.load(first.mission_id)
            with pytest.raises(
                PendingIntegrityTransitionError,
                match="generic mission replay",
            ):
                first_store.load(second.mission_id)
            assert (
                first_store.load_integrity_event(first.event_digest)
                == first
            )
            assert (
                first_store.load_integrity_event(second.event_digest)
                is None
            )
            assert first_store._connection.execute(  # noqa: SLF001
                "SELECT count(*) FROM events"
            ).fetchone() == (1,)
            assert first_store._connection.execute(  # noqa: SLF001
                "SELECT count(*) FROM integrity_pending_transitions"
            ).fetchone() == (1,)
