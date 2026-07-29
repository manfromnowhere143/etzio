"""Crash and concurrency proofs for the modeled integrity-finality facade."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

from etzio.integrity_v1 import IntegrityValidationPolicyV1
from etzio.kernel.events_v1 import GENESIS_DIGEST, EventV1
from etzio.kernel.integrity_transition import (
    AnchorStatementRecordV1,
    FinalizedIntegrityTransitionV1,
    IntegrityFinalityBlockedError,
    IntegrityFinalityPendingError,
    ModeledIntegrityFinalizingEventStoreV1,
    PendingIntegrityTransitionV1,
    ProviderEvidenceBlobV1,
    RepositoryOwnedDeterministicModeledIntegrityServiceV1,
)
from etzio.kernel.store import PendingIntegrityTransitionError, SQLiteEventStore
from etzio.protocol import content_id

_SERVICE_INSTANCE_ID = "Etzio.integrity-recovery-matrix"
_ENVIRONMENT_ID = "fixture.integrity-recovery-matrix"
_SEED = b"etzio-integrity-recovery-matrix-v1"


def _digest(label: str) -> str:
    return content_id(
        "integrity_recovery_matrix_test",
        {"label": label},
    )


def _policy() -> IntegrityValidationPolicyV1:
    return IntegrityValidationPolicyV1(
        decision_policy_id=_digest("decision-policy"),
        decision_time_policy_id=_digest("decision-time-policy"),
        checkpoint_time_policy_id=_digest("checkpoint-time-policy"),
        anchor_policy_id=_digest("anchor-policy"),
        required_revocation_namespaces=frozenset({"authority", "verifier"}),
        max_decision_uncertainty_seconds=0,
        max_checkpoint_uncertainty_seconds=0,
    )


def _service() -> RepositoryOwnedDeterministicModeledIntegrityServiceV1:
    return RepositoryOwnedDeterministicModeledIntegrityServiceV1.deterministic(
        seed=_SEED,
        service_instance_id=_SERVICE_INSTANCE_ID,
        environment_id=_ENVIRONMENT_ID,
        validation_policy=_policy(),
    )


def _event(label: str) -> EventV1:
    return EventV1.create(
        mission_id=_digest(f"{label}-mission"),
        seq=0,
        kind="mission_admission_refused",
        unit="AQUILA",
        authority_id=_digest(f"{label}-authority"),
        target_id=_digest(f"{label}-target"),
        decision_time=2_000_000_000,
        payload={
            "reason_code": "authority_expired",
            "stage": "admission",
        },
        prev_digest=GENESIS_DIGEST,
    )


def _state_path(tmp_path: Path, label: str) -> Path:
    parent = tmp_path / label
    parent.mkdir(mode=0o700)
    return parent / "events.sqlite3"


class _ServiceProxy:
    def __init__(
        self,
        delegate: RepositoryOwnedDeterministicModeledIntegrityServiceV1,
    ) -> None:
        self._delegate = delegate

    def __getattr__(self, name: str) -> object:
        return getattr(self._delegate, name)


class _LostAnchorResponseService(_ServiceProxy):
    """Perform exact modeled registration, then lose its first response."""

    def __init__(
        self,
        delegate: RepositoryOwnedDeterministicModeledIntegrityServiceV1,
    ) -> None:
        super().__init__(delegate)
        self.anchor_statement_id: str | None = None
        self.registration_request: bytes | None = None
        self.receipts: tuple[ProviderEvidenceBlobV1, ...] | None = None
        self._response_lost = False

    def register_anchor_statement(
        self,
        anchor: AnchorStatementRecordV1,
    ) -> tuple[ProviderEvidenceBlobV1, ...]:
        receipts = self._delegate.register_anchor_statement(anchor)
        self.anchor_statement_id = anchor.anchor_statement_id
        self.registration_request = anchor.registration_request
        self.receipts = receipts
        if not self._response_lost:
            self._response_lost = True
            raise TimeoutError("modeled anchor response was lost after registration")
        return receipts


class _BeforeAnchorTimeoutService(_ServiceProxy):
    """Leave only the atomic event-plus-pending phase committed."""

    def __init__(
        self,
        delegate: RepositoryOwnedDeterministicModeledIntegrityServiceV1,
    ) -> None:
        super().__init__(delegate)
        self._timed_out = False

    def prepare_anchor_statement(
        self,
        pending: PendingIntegrityTransitionV1,
    ) -> AnchorStatementRecordV1:
        if not self._timed_out:
            self._timed_out = True
            raise TimeoutError("modeled anchor preparation timed out")
        return self._delegate.prepare_anchor_statement(pending)


class _PostCommitFinalizationFailureStore:
    """Lose the caller response only after exact finalization committed."""

    def __init__(self, delegate: SQLiteEventStore) -> None:
        self._delegate = delegate
        self.calls = 0

    def __getattr__(self, name: str) -> object:
        return getattr(self._delegate, name)

    def finalize_integrity_transition(
        self,
        record: FinalizedIntegrityTransitionV1,
    ) -> FinalizedIntegrityTransitionV1:
        retained = self._delegate.finalize_integrity_transition(record)
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("finalization committed before caller response was lost")
        return retained


class _SynchronizedRecoveryStore:
    """Ensure both independent workers read the same pending lineage."""

    def __init__(self, delegate: SQLiteEventStore, barrier: Barrier) -> None:
        self._delegate = delegate
        self._barrier = barrier

    def __getattr__(self, name: str) -> object:
        return getattr(self._delegate, name)

    def load_unresolved_integrity_transition(self) -> object | None:
        lineage = self._delegate.load_unresolved_integrity_transition()
        self._barrier.wait(timeout=15)
        return lineage


def test_lost_anchor_response_recovers_after_reopen_with_exact_bytes(
    tmp_path: Path,
) -> None:
    state_path = _state_path(tmp_path, "lost-anchor-response")
    event = _event("lost-anchor-response")
    first_service = _service()
    interrupted = _LostAnchorResponseService(first_service)

    with SQLiteEventStore(state_path) as store:
        facade = ModeledIntegrityFinalizingEventStoreV1(store, interrupted)
        with pytest.raises(IntegrityFinalityPendingError) as lost:
            facade.append(event, expected_head=GENESIS_DIGEST)
        assert lost.value.reason_code == "modeled_integrity_adapter_response_uncertain"
        assert isinstance(lost.value.__cause__, TimeoutError)

        unresolved = store.load_unresolved_integrity_transition()
        assert unresolved is not None
        assert unresolved.phase == "anchor_statement_ready"
        assert unresolved.anchor_statement is not None
        retained_anchor = unresolved.anchor_statement
        assert interrupted.anchor_statement_id == retained_anchor.anchor_statement_id
        assert interrupted.registration_request == retained_anchor.registration_request
        assert interrupted.receipts is not None
        assert first_service.register_anchor_statement(retained_anchor) == interrupted.receipts
        with pytest.raises(PendingIntegrityTransitionError):
            store.load(event.mission_id)
        assert store.load_integrity_event(event.event_digest) == event

    exact_receipts = interrupted.receipts
    assert exact_receipts is not None
    with SQLiteEventStore(state_path) as reopened:
        recovered = ModeledIntegrityFinalizingEventStoreV1(reopened, _service())
        assert recovered.load(event.mission_id) == (event,)
        lineage = reopened.load_integrity_lineage(event.event_digest)
        assert lineage is not None
        assert lineage.phase == "finalized"
        assert lineage.anchor_statement == retained_anchor
        assert lineage.checkpoint_candidate is not None
        assert lineage.checkpoint_candidate.provider_evidence == exact_receipts
        assert reopened.load_unresolved_integrity_transition() is None


def test_post_commit_finalization_failure_has_exact_fresh_facade_retry(
    tmp_path: Path,
) -> None:
    state_path = _state_path(tmp_path, "post-commit-finalization")
    event = _event("post-commit-finalization")

    with SQLiteEventStore(state_path) as store:
        interrupted_store = _PostCommitFinalizationFailureStore(store)
        facade = ModeledIntegrityFinalizingEventStoreV1(
            interrupted_store,
            _service(),
        )
        with pytest.raises(
            (IntegrityFinalityPendingError, IntegrityFinalityBlockedError),
        ) as lost_response:
            facade.append(event, expected_head=GENESIS_DIGEST)
        assert isinstance(lost_response.value.__cause__, RuntimeError)
        assert str(lost_response.value.__cause__) == ("finalization committed before caller response was lost")
        assert interrupted_store.calls == 1
        committed = store.load_integrity_lineage(event.event_digest)
        assert committed is not None
        assert committed.phase == "finalized"
        assert committed.finalization is not None
        exact_finalization = committed.finalization
        assert store.load(event.mission_id) == (event,)

    with SQLiteEventStore(state_path) as reopened:
        retry = ModeledIntegrityFinalizingEventStoreV1(reopened, _service())
        assert retry.append(event, expected_head=GENESIS_DIGEST) == event
        assert retry.require_finalized(event.event_digest) == exact_finalization
        assert reopened.load(event.mission_id) == (event,)
        assert reopened.load_unresolved_integrity_transition() is None


def test_independent_facades_converge_on_one_exact_pending_recovery(
    tmp_path: Path,
) -> None:
    state_path = _state_path(tmp_path, "concurrent-recovery")
    event = _event("concurrent-recovery")

    with SQLiteEventStore(state_path) as store:
        interrupted = ModeledIntegrityFinalizingEventStoreV1(
            store,
            _BeforeAnchorTimeoutService(_service()),
        )
        with pytest.raises(IntegrityFinalityPendingError):
            interrupted.append(event, expected_head=GENESIS_DIGEST)
        pending = store.load_unresolved_integrity_transition()
        assert pending is not None
        assert pending.phase == "local_pending"
        with pytest.raises(PendingIntegrityTransitionError):
            store.load(event.mission_id)

    start_recovery = Barrier(2)

    def recover_in_independent_connection() -> tuple[bytes, str]:
        with SQLiteEventStore(state_path) as store:
            synchronized = _SynchronizedRecoveryStore(store, start_recovery)
            facade = ModeledIntegrityFinalizingEventStoreV1(
                synchronized,
                _service(),
            )
            finalization = facade.recover_pending_transition()
            assert finalization is not None
            lineage = store.load_integrity_lineage(event.event_digest)
            assert lineage is not None
            assert lineage.phase == "finalized"
            return finalization.to_canonical_bytes(), lineage.lineage_id

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(recover_in_independent_connection) for _ in range(2)]
        outcomes = tuple(future.result(timeout=45) for future in futures)

    assert outcomes[0] == outcomes[1]
    with SQLiteEventStore(state_path) as reopened:
        facade = ModeledIntegrityFinalizingEventStoreV1(reopened, _service())
        assert facade.load(event.mission_id) == (event,)
        lineage = reopened.load_integrity_lineage(event.event_digest)
        assert lineage is not None
        assert lineage.phase == "finalized"
        assert lineage.finalization is not None
        assert lineage.finalization.to_canonical_bytes() == outcomes[0][0]
        assert lineage.lineage_id == outcomes[0][1]
        assert reopened.load_unresolved_integrity_transition() is None
