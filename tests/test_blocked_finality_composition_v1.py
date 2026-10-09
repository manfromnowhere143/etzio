"""Recovery authorization is enforced across admission, replay, and phase progress."""

from __future__ import annotations

import sqlite3
from dataclasses import replace

import pytest
from test_blocked_finality_lifecycle_v1 import _governed, _refusal_event, _sign

from etzio.kernel.blocked_finality_v1 import (
    INSTANCE_SEALED_DISPOSITION_V1,
    RETRY_AUTHORIZED_DISPOSITION_V1,
    BlockedFinalityError,
    GovernedRecoveryDecisionV1,
)
from etzio.kernel.integrity_transition import (
    FinalizedIntegrityTransitionV1,
    IntegrityFinalityBlockedError,
    IntegrityRecoveryNotAuthorizedError,
)
from etzio.kernel.store import EventStoreCorruptionError, EventStoreError, SQLiteEventStore
from etzio.protocol import canonical_dumps, content_id, strict_loads


def _block(facade):
    event = _refusal_event("composition-review")
    with pytest.raises(IntegrityFinalityBlockedError):
        facade.append(event, expected_head=event.prev_digest)
    return event


def _changed_decision(signed, signer, field, value):
    body = strict_loads(signed.decision_bytes)
    body[field] = value
    del body["decision_id"]
    body["decision_id"] = content_id("blocked_finality_recovery_decision", body)
    return signer.sign(GovernedRecoveryDecisionV1.from_canonical_bytes(canonical_dumps(body)))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        (name, content_id("review_foreign_scope", {"field": name}))
        for name in (
            "mission_id", "authority_id", "target_id", "pending_record_id",
            "unresolved_phase_record_id", "event_digest",
        )
    ] + [
        ("unresolved_phase", "anchor_statement_ready"),
        ("blocked_operation", "publish_checkpoint"),
        ("blocked_reason_code", "modeled_integrity_adapter_contract_failure"),
        ("attempt_ordinal", 2),
    ],
)
def test_signed_decision_must_restate_every_observation_field(tmp_path, field, value):
    store, facade, _, profile, signer = _governed(tmp_path)
    with store:
        event = _block(facade)
        observation = store.load_blocked_finality_observations(event.event_digest)[-1]
        signed = _sign(profile, signer, observation, RETRY_AUTHORIZED_DISPOSITION_V1)
        changed = _changed_decision(signed, signer, field, value)
        with pytest.raises((BlockedFinalityError, EventStoreError)):
            store.retain_governed_recovery_decision(changed)
        assert store.load_governed_recovery_decision(observation.observation_id) is None
        with pytest.raises(IntegrityRecoveryNotAuthorizedError):
            facade.recover_pending_transition()
        assert store.load_integrity_finalization(event.event_digest) is None


@pytest.mark.parametrize(
    ("operation", "phase"),
    [
        ("prime_catalog", "local_pending"),
        ("prepare_anchor_statement", "local_pending"),
        ("register_anchor_statement", "anchor_statement_ready"),
        ("prepare_checkpoint_candidate", "anchor_statement_ready"),
        ("publish_checkpoint", "checkpoint_candidate_retained"),
        ("observe_current_floor", "checkpoint_candidate_retained"),
    ],
)
def test_block_records_actual_operation_and_highest_durable_phase(tmp_path, operation, phase):
    store, facade, service, _, _ = _governed(tmp_path, failing="none")

    def refuse(*_args, **_kwargs):
        error = IntegrityFinalityBlockedError(
            "modeled_integrity_adapter_contract_failure", "fixture refusal")
        # The provider cannot choose the kernel call site by adding an exception field.
        error.blocked_operation = "propose_transition"
        raise error

    setattr(service, operation, refuse)
    with store:
        event = _block(facade)
        lineage = store.load_unresolved_integrity_transition()
        observation = store.load_blocked_finality_observations(event.event_digest)[-1]
        assert lineage.phase == phase
        assert observation.unresolved_phase == phase
        assert observation.blocked_operation == (
            "recover_lineage" if operation == "prime_catalog" else operation
        )
        assert store.load_integrity_finalization(event.event_digest) is None


@pytest.mark.parametrize("damage", ["binding", "signature", "index"])
@pytest.mark.parametrize("reopen", [False, True])
def test_raw_retained_recovery_corruption_is_rejected(tmp_path, damage, reopen):
    store, facade, _, profile, signer = _governed(tmp_path)
    event = _block(facade)
    observation = store.load_blocked_finality_observations(event.event_digest)[-1]
    signed = _sign(profile, signer, observation, RETRY_AUTHORIZED_DISPOSITION_V1)
    if damage == "binding":
        signed = _changed_decision(
            signed, signer, "blocked_reason_code", "modeled_integrity_adapter_contract_failure")
    elif damage == "signature":
        signed = replace(signed, signature_bytes=bytes(64))
    decision = GovernedRecoveryDecisionV1.from_canonical_bytes(signed.decision_bytes)
    path = tmp_path / "state" / "events.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute(
            "INSERT INTO integrity_recovery_decisions "
            "(decision_id, event_digest, blocked_observation_id, disposition, record) "
            "VALUES (?, ?, ?, ?, ?)",
            (decision.decision_id, event.event_digest, observation.observation_id,
             "instance_sealed" if damage == "index" else decision.disposition,
             signed.to_canonical_bytes()),
        )
    try:
        with pytest.raises(EventStoreCorruptionError):
            if reopen:
                with SQLiteEventStore(path):
                    pass
            else:
                facade.recover_pending_transition()
    finally:
        store.close()


@pytest.mark.parametrize("retention", ["retain_integrity_anchor_statement", "retain_integrity_checkpoint_candidate"])
def test_interrupted_authorized_progress_requires_a_current_phase_decision(tmp_path, retention):
    store, facade, service, profile, signer = _governed(tmp_path)
    with store:
        event = _block(facade)
        observation = store.load_blocked_finality_observations(event.event_digest)[-1]
        store.retain_governed_recovery_decision(
            _sign(profile, signer, observation, RETRY_AUTHORIZED_DISPOSITION_V1))
        service._failing = "none"
        original = getattr(store, retention)

        def die_after(*args, **kwargs):
            original(*args, **kwargs)
            raise KeyboardInterrupt("injected death after phase commit")

        setattr(store, retention, die_after)
        with pytest.raises(KeyboardInterrupt):
            facade.recover_pending_transition()
        delattr(store, retention)
        with pytest.raises(IntegrityFinalityBlockedError) as error:
            facade.recover_pending_transition()
        assert error.value.reason_code == "modeled_integrity_recovery_phase_changed"
        observations = store.load_blocked_finality_observations(event.event_digest)
        assert [entry.attempt_ordinal for entry in observations] == [1, 2]
        current = observations[-1]
        assert current.unresolved_phase == store.load_unresolved_integrity_transition().phase
        with pytest.raises(IntegrityRecoveryNotAuthorizedError):
            facade.recover_pending_transition()
        store.retain_governed_recovery_decision(
            _sign(profile, signer, current, RETRY_AUTHORIZED_DISPOSITION_V1))
        assert facade.recover_pending_transition() is not None
        assert store.load_integrity_finalization(event.event_digest) is not None
    with SQLiteEventStore(tmp_path / "state" / "events.sqlite3") as reopened:
        assert reopened.load_governed_recovery_decision(observation.observation_id) is not None
        assert reopened.load_integrity_finalization(event.event_digest) is not None


@pytest.mark.parametrize("phase", ["anchor", "checkpoint", "finalization"])
@pytest.mark.parametrize("disposition", [None, INSTANCE_SEALED_DISPOSITION_V1, RETRY_AUTHORIZED_DISPOSITION_V1])
def test_direct_store_phase_writes_require_governed_retry(tmp_path, phase, disposition):
    store, facade, service, profile, signer = _governed(tmp_path, failing="none")
    operation = {
        "anchor": "prepare_anchor_statement",
        "checkpoint": "prepare_checkpoint_candidate",
        "finalization": "observe_current_floor",
    }[phase]

    def refuse(*_args, **_kwargs):
        raise IntegrityFinalityBlockedError("modeled_integrity_adapter_contract_failure", "fixture refusal")

    setattr(service, operation, refuse)
    with store:
        event = _block(facade)
        lineage = store.load_unresolved_integrity_transition()
        observation = store.load_blocked_finality_observations(event.event_digest)[-1]
        if disposition is not None:
            store.retain_governed_recovery_decision(_sign(profile, signer, observation, disposition))
        inner = service._inner
        if phase == "anchor":
            record = inner.prepare_anchor_statement(lineage.pending)
            retain = store.retain_integrity_anchor_statement
        elif phase == "checkpoint":
            receipts = inner.register_anchor_statement(lineage.anchor_statement)
            record = inner.prepare_checkpoint_candidate(
                lineage.pending, lineage.anchor_statement, anchor_receipts=receipts)
            retain = store.retain_integrity_checkpoint_candidate
        else:
            floor, evidence = inner.observe_current_floor(lineage.pending, lineage.checkpoint_candidate)
            record = FinalizedIntegrityTransitionV1(
                pending_record_id=lineage.pending.record_id,
                checkpoint_candidate_record_id=lineage.checkpoint_candidate.record_id,
                event_digest=event.event_digest, external_head_floor=floor, provider_evidence=evidence,
            )
            retain = store.finalize_integrity_transition
        if disposition == RETRY_AUTHORIZED_DISPOSITION_V1:
            assert retain(record) == record
        else:
            with pytest.raises(EventStoreError):
                retain(record)
            assert store.load_unresolved_integrity_transition().phase == lineage.phase


def test_store_refuses_a_stale_observation_after_authorized_phase_progress(tmp_path):
    from etzio.kernel.blocked_finality_v1 import BlockedFinalityObservationV1

    store, facade, service, profile, signer = _governed(tmp_path)
    with store:
        event = _block(facade)
        observation = store.load_blocked_finality_observations(event.event_digest)[-1]
        store.retain_governed_recovery_decision(
            _sign(profile, signer, observation, RETRY_AUTHORIZED_DISPOSITION_V1))
        lineage = store.load_unresolved_integrity_transition()
        store.retain_integrity_anchor_statement(service._inner.prepare_anchor_statement(lineage.pending))
        body = observation.to_body()
        body["attempt_ordinal"] = 2
        del body["observation_id"]
        body["observation_id"] = content_id("blocked_finality_observation", body)
        stale = BlockedFinalityObservationV1.from_canonical_bytes(canonical_dumps(body))
        with pytest.raises(EventStoreError, match="highest durable phase"):
            store.retain_blocked_finality_observation(stale)
        assert len(store.load_blocked_finality_observations(event.event_digest)) == 1


@pytest.mark.parametrize("damage", ["scope", "index"])
def test_reopen_refuses_observation_scope_or_index_corruption(tmp_path, damage):
    from etzio.kernel.blocked_finality_v1 import BlockedFinalityObservationV1

    store, facade, _, _, _ = _governed(tmp_path)
    event = _block(facade)
    observation = store.load_blocked_finality_observations(event.event_digest)[-1]
    store.close()
    body = observation.to_body()
    body["attempt_ordinal"] = 2
    if damage == "scope":
        body["authority_id"] = content_id("review_foreign_authority", {})
    del body["observation_id"]
    body["observation_id"] = content_id("blocked_finality_observation", body)
    changed = BlockedFinalityObservationV1.from_canonical_bytes(canonical_dumps(body))
    path = tmp_path / "state" / "events.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute(
            "INSERT INTO integrity_blocked_observations "
            "(event_digest, attempt_ordinal, observation_id, unresolved_phase, record) VALUES (?, ?, ?, ?, ?)",
            (event.event_digest, 3 if damage == "index" else 2, changed.observation_id,
             changed.unresolved_phase, changed.to_canonical_bytes()),
        )
    with pytest.raises(EventStoreCorruptionError):
        with SQLiteEventStore(path):
            pass


@pytest.mark.parametrize("field", ["service_instance_id", "environment_id"])
def test_recovery_profile_cannot_name_another_enrolled_scope(tmp_path, field):
    store, _, _, profile, _ = _governed(tmp_path)
    with store:
        foreign = replace(profile, **{field: "Etzio.foreign-scope"})
        with pytest.raises(EventStoreError, match="enrolled integrity authority"):
            store.enroll_blocked_finality_recovery(foreign)
        assert store.enroll_blocked_finality_recovery(profile) == profile.profile_id
