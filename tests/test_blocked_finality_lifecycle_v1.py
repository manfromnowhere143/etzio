"""Governed blocked-finality lifecycle integration and its known-bads."""

from __future__ import annotations

from pathlib import Path

import pytest
from test_blocked_finality_storage_v3 import _fixture, _recovery_profile, _sign
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
    fixture_time_bundle_v1,
)
from etzio.kernel.integrity_transition import (
    GovernedBlockedFinalityBindingV1,
    IntegrityFinalityBlockedError,
    IntegrityInstanceSealedError,
    IntegrityRecoveryNotAuthorizedError,
    ModeledIntegrityFinalizingEventStoreV1,
)
from etzio.kernel.store import SQLiteEventStore


class _BlockingService:
    """Wrap the deterministic service so one named phase call refuses."""

    def __init__(self, inner: object, failing: str) -> None:
        self._inner = inner
        self._failing = failing
        self.calls = 0

    def __getattr__(self, name: str) -> object:
        return getattr(self._inner, name)

    def prepare_anchor_statement(self, pending: object) -> object:
        if self._failing == "prepare_anchor_statement":
            self.calls += 1
            raise IntegrityFinalityBlockedError(
                "modeled_anchor_equivocation",
                "the fixture anchor adapter refuses deterministically",
            )
        return self._inner.prepare_anchor_statement(pending)


def _time_source():
    fixture = _fixture()
    return lambda: fixture_time_bundle_v1(fixture)


def _governed(tmp_path: Path, *, failing: str = "prepare_anchor_statement"):
    path = _state_path(tmp_path)
    store = SQLiteEventStore(path)
    policy = _policy()
    inner = _service(policy)
    profile, signer = _recovery_profile(
        _SERVICE_INSTANCE_ID,
        _ENVIRONMENT_ID,
        inner.authority_binding,
    )
    binding = GovernedBlockedFinalityBindingV1(
        profile=profile,
        time_source=_time_source(),
    )
    service = _BlockingService(inner, failing)
    facade = ModeledIntegrityFinalizingEventStoreV1(
        store,
        service,
        blocked_finality=binding,
    )
    return store, facade, service, profile, signer


def _block_once(facade, service, tmp_path: Path):
    event = _refusal_event("governed-lifecycle")
    with pytest.raises(IntegrityFinalityBlockedError):
        facade.append(event, expected_head=event.prev_digest)
    return event


# ---------------------------------------------------------------------------
# A block becomes durable
# ---------------------------------------------------------------------------


def test_a_deterministic_block_is_durably_observed(tmp_path: Path) -> None:
    store, facade, service, _, _ = _governed(tmp_path)
    with store:
        event = _block_once(facade, service, tmp_path)
        observations = store.load_blocked_finality_observations(event.event_digest)
        assert len(observations) == 1
        observed = observations[0]
        assert observed.attempt_ordinal == 1
        assert observed.unresolved_phase == "local_pending"
        assert observed.blocked_operation == "prepare_anchor_statement"
        assert observed.blocked_reason_code == "modeled_anchor_equivocation"
        assert observed.event_digest == event.event_digest


def test_the_durable_block_never_releases_the_barrier(tmp_path: Path) -> None:
    from etzio.kernel.store import PendingIntegrityTransitionError

    store, facade, service, _, _ = _governed(tmp_path)
    with store:
        event = _block_once(facade, service, tmp_path)
        # The event is durable, finality is not reached, and the barrier still holds.
        with pytest.raises(PendingIntegrityTransitionError):
            store.load(event.mission_id)


def test_an_unclassifiable_refusal_is_retained_as_a_contract_failure(
    tmp_path: Path,
) -> None:
    store = SQLiteEventStore(_state_path(tmp_path))
    policy = _policy()
    inner = _service(policy)
    profile, _ = _recovery_profile(
        _SERVICE_INSTANCE_ID,
        _ENVIRONMENT_ID,
        inner.authority_binding,
    )

    class _OddlyBlocking(_BlockingService):
        def prepare_anchor_statement(self, pending: object) -> object:
            raise IntegrityFinalityBlockedError(
                "a_reason_the_contract_does_not_admit",
                "an unclassifiable deterministic refusal",
            )

    facade = ModeledIntegrityFinalizingEventStoreV1(
        store,
        _OddlyBlocking(inner, "prepare_anchor_statement"),
        blocked_finality=GovernedBlockedFinalityBindingV1(
            profile=profile,
            time_source=_time_source(),
        ),
    )
    with store:
        event = _refusal_event("governed-unclassifiable")
        with pytest.raises(IntegrityFinalityBlockedError):
            facade.append(event, expected_head=event.prev_digest)
        observed = store.load_blocked_finality_observations(event.event_digest)[0]
        assert observed.blocked_reason_code == "modeled_integrity_adapter_contract_failure"


# ---------------------------------------------------------------------------
# Recovery is authorized, not inferred
# ---------------------------------------------------------------------------


def test_recovery_after_a_block_requires_an_authorized_retry(tmp_path: Path) -> None:
    store, facade, service, _, _ = _governed(tmp_path)
    with store:
        _block_once(facade, service, tmp_path)
        with pytest.raises(IntegrityRecoveryNotAuthorizedError):
            facade.recover_pending_transition()


def test_an_authorized_retry_lets_recovery_proceed(tmp_path: Path) -> None:
    store, facade, service, profile, signer = _governed(tmp_path)
    with store:
        event = _block_once(facade, service, tmp_path)
        observation = store.load_blocked_finality_observations(event.event_digest)[0]
        store.retain_governed_recovery_decision(
            _sign(profile, signer, observation, RETRY_AUTHORIZED_DISPOSITION_V1)
        )
        # The adapter still refuses, so the retry blocks again rather than succeeding,
        # and the second attempt is retained under the next ordinal.
        with pytest.raises(IntegrityFinalityBlockedError):
            facade.recover_pending_transition()
        observations = store.load_blocked_finality_observations(event.event_digest)
        assert [entry.attempt_ordinal for entry in observations] == [1, 2]


def test_a_sealing_decision_does_not_authorize_a_retry(tmp_path: Path) -> None:
    store, facade, service, profile, signer = _governed(tmp_path)
    with store:
        event = _block_once(facade, service, tmp_path)
        observation = store.load_blocked_finality_observations(event.event_digest)[0]
        store.retain_governed_recovery_decision(
            _sign(profile, signer, observation, INSTANCE_SEALED_DISPOSITION_V1)
        )
        with pytest.raises(IntegrityInstanceSealedError):
            facade.recover_pending_transition()


# ---------------------------------------------------------------------------
# Sealing is terminal for every consequential command
# ---------------------------------------------------------------------------


def test_a_sealed_instance_refuses_load_recover_and_append(tmp_path: Path) -> None:
    store, facade, service, profile, signer = _governed(tmp_path)
    with store:
        event = _block_once(facade, service, tmp_path)
        observation = store.load_blocked_finality_observations(event.event_digest)[0]
        store.retain_governed_recovery_decision(
            _sign(profile, signer, observation, INSTANCE_SEALED_DISPOSITION_V1)
        )
        assert store.instance_is_sealed() is True
        with pytest.raises(IntegrityInstanceSealedError):
            facade.load(event.mission_id)
        with pytest.raises(IntegrityInstanceSealedError):
            facade.recover_pending_transition()
        with pytest.raises(IntegrityInstanceSealedError):
            facade.append(
                _refusal_event("governed-after-seal"),
                expected_head=event.prev_digest,
            )


def test_a_sealed_instance_still_exposes_its_retained_history(tmp_path: Path) -> None:
    """Sealing fences off new work; it never destroys retained evidence."""

    store, facade, service, profile, signer = _governed(tmp_path)
    with store:
        event = _block_once(facade, service, tmp_path)
        observation = store.load_blocked_finality_observations(event.event_digest)[0]
        store.retain_governed_recovery_decision(
            _sign(profile, signer, observation, INSTANCE_SEALED_DISPOSITION_V1)
        )
        retained = store.load_blocked_finality_observations(event.event_digest)
        assert len(retained) == 1
        assert retained[0].observation_id == observation.observation_id


# ---------------------------------------------------------------------------
# The integration stays opt-in
# ---------------------------------------------------------------------------


def test_an_unconfigured_facade_retains_no_observation(tmp_path: Path) -> None:
    store = SQLiteEventStore(_state_path(tmp_path))
    policy = _policy()
    facade = ModeledIntegrityFinalizingEventStoreV1(
        store,
        _BlockingService(_service(policy), "prepare_anchor_statement"),
    )
    with store:
        event = _refusal_event("ungoverned")
        with pytest.raises(IntegrityFinalityBlockedError):
            facade.append(event, expected_head=event.prev_digest)
        assert store.load_blocked_finality_observations(event.event_digest) == ()
        # Without the governed binding, recovery keeps its historical retry behaviour.
        with pytest.raises(IntegrityFinalityBlockedError):
            facade.recover_pending_transition()


def test_the_binding_requires_an_exact_profile_and_time_source() -> None:
    from etzio.protocol import ProtocolError

    with pytest.raises(ProtocolError):
        GovernedBlockedFinalityBindingV1(profile=object(), time_source=_time_source())
    fixture = _fixture()
    with pytest.raises(ProtocolError):
        GovernedBlockedFinalityBindingV1(profile=fixture.profile, time_source=object())


def test_the_binding_refuses_a_time_source_that_is_not_a_sealed_bundle() -> None:
    from etzio.protocol import ProtocolError

    fixture = _fixture()
    binding = GovernedBlockedFinalityBindingV1(
        profile=fixture.profile,
        time_source=lambda: object(),
    )
    with pytest.raises(ProtocolError):
        binding.qualified_time()
