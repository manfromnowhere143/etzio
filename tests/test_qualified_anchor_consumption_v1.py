"""Store-layer consumption of qualified signed anchor evidence (ADR-0019 step 2)."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from test_integrity_store_v2 import _enroll, _policy, _state_path

from etzio.kernel.head_authority_adapters_v1 import (
    HeadAnchorRequestV1,
    create_repository_owned_head_authority_fixture_v1,
    qualify_anchor_bundle_v1,
)
from etzio.kernel.integrity_adapters_v1 import (
    TrustedTimeRequestV1,
    qualify_time_bundle_v1,
)
from etzio.kernel.store import (
    EventStoreError,
    IntegrityFinalityRequiredError,
    SQLiteEventStore,
)
from etzio.protocol import content_id


def _head_fixture(seed: bytes = b"anchor-consumption-corpus-v1"):
    return create_repository_owned_head_authority_fixture_v1(seed=seed)


def _time_bundle(hfx):
    tfx = hfx.time_fixture
    tv = tfx.vector
    requests = {
        a.source_id: TrustedTimeRequestV1.issue(
            profile=tfx.profile,
            source_id=a.source_id,
            purpose="checkpoint",
            mission_id=tv.mission_id,
            authority_id=tv.authority_id,
            target_id=tv.target_id,
            event_digest=tv.event_digest,
            transition_intent_id=tv.transition_intent_id,
            imprint_id=content_id(
                "head_authority_repository_fixture",
                {"label": "head-authority-imprint", "value": "checkpoint"},
            ),
            request_nonce=tv.request_nonce,
        )
        for a in tfx.time_adapters
    }
    return qualify_time_bundle_v1(
        profile=tfx.profile,
        requests=requests,
        signed_evidence={a.source_id: a.acquire(requests[a.source_id]) for a in tfx.time_adapters},
    )


def _anchor_bundle(hfx, time_bundle):
    v = hfx.vector
    requests = {
        a.source_id: HeadAnchorRequestV1.issue(
            profile=hfx.profile,
            source_id=a.source_id,
            mission_id=v.mission_id,
            authority_id=v.authority_id,
            target_id=v.target_id,
            event_digest=v.event_digest,
            transition_intent_id=v.transition_intent_id,
            anchor_statement_id=v.anchor_statement_id,
            instance_sequence=v.expected_head.instance_sequence,
            time_bundle=time_bundle,
            prior_tree_size=hfx.anchor_prior_tree_size,
            request_nonce=v.request_nonce,
        )
        for a in hfx.anchor_adapters
    }
    return qualify_anchor_bundle_v1(
        profile=hfx.profile,
        time_profile=hfx.time_fixture.profile,
        time_bundle=time_bundle,
        requests=requests,
        signed_evidence={a.source_id: a.acquire(requests[a.source_id]) for a in hfx.anchor_adapters},
    )


def _modeled_store(tmp_path: Path):
    path = _state_path(tmp_path)
    store = SQLiteEventStore(path)
    _enroll(store, _policy())
    return store


def _qualified_store(tmp_path: Path, hfx):
    store = _modeled_store(tmp_path)
    store.enroll_qualified_acceptance(
        qualified_time_profile=hfx.time_fixture.profile,
        qualified_head_profile=hfx.profile,
    )
    return store


def _verify(store, hfx, time_bundle, anchor_bundle, **overrides):
    kwargs = {
        "anchor_bundle": anchor_bundle,
        "time_bundle": time_bundle,
        "claimed_anchor_statement_id": anchor_bundle.anchor_statement_id,
        "claimed_anchor_evidence": anchor_bundle.evidence,
        "claimed_evidence_blobs": anchor_bundle.evidence_blobs,
    }
    kwargs.update(overrides)
    return store.verify_qualified_anchor_evidence(**kwargs)


# ---------------------------------------------------------------------------
# The enrolled store roots drive acceptance
# ---------------------------------------------------------------------------


def test_the_enrolled_store_consumes_qualified_anchor_evidence(tmp_path: Path) -> None:
    hfx = _head_fixture()
    tb = _time_bundle(hfx)
    ab = _anchor_bundle(hfx, tb)
    with _qualified_store(tmp_path, hfx) as store:
        acceptance = _verify(store, hfx, tb, ab)
        assert acceptance.mode == "qualified_signed_fixture"
        assert acceptance.anchor_statement_id == ab.anchor_statement_id
        assert len(acceptance.evidence_blobs) == 2


def test_consumption_uses_the_reloaded_enrolled_roots(tmp_path: Path) -> None:
    """The store reloads its enrolled profiles from bytes; a fresh reopen still consumes."""

    hfx = _head_fixture()
    tb = _time_bundle(hfx)
    ab = _anchor_bundle(hfx, tb)
    store = _qualified_store(tmp_path, hfx)
    path = Path(store._connection.execute("PRAGMA database_list").fetchone()[2])  # noqa: SLF001
    store.close()
    with SQLiteEventStore(path) as reopened:
        acceptance = _verify(reopened, hfx, tb, ab)
        assert acceptance.mode == "qualified_signed_fixture"


# ---------------------------------------------------------------------------
# A store without a qualified profile never falls back to the unsigned gate
# ---------------------------------------------------------------------------


def test_a_modeled_only_store_refuses_consumption(tmp_path: Path) -> None:
    hfx = _head_fixture()
    tb = _time_bundle(hfx)
    ab = _anchor_bundle(hfx, tb)
    with _modeled_store(tmp_path) as store:
        with pytest.raises(IntegrityFinalityRequiredError):
            _verify(store, hfx, tb, ab)


def test_a_legacy_store_refuses_consumption(tmp_path: Path) -> None:
    hfx = _head_fixture()
    tb = _time_bundle(hfx)
    ab = _anchor_bundle(hfx, tb)
    with SQLiteEventStore(_state_path(tmp_path)) as store:
        with pytest.raises(EventStoreError):
            _verify(store, hfx, tb, ab)


# ---------------------------------------------------------------------------
# The enrolled roots must actually authenticate the bundle
# ---------------------------------------------------------------------------


def test_a_bundle_from_foreign_roots_fails_under_enrolled_roots(tmp_path: Path) -> None:
    hfx = _head_fixture()
    other = _head_fixture(seed=b"a-different-anchor-corpus")
    other_tb = _time_bundle(other)
    other_ab = _anchor_bundle(other, other_tb)
    # Store enrolls hfx roots; the bundle is from `other` roots — reauthentication fails.
    with _qualified_store(tmp_path, hfx) as store:
        with pytest.raises(ValueError) as exc:
            _verify(store, hfx, other_tb, other_ab)
        assert getattr(exc.value, "reason_code", "") != ""


def test_a_tampered_claim_is_refused(tmp_path: Path) -> None:
    hfx = _head_fixture()
    tb = _time_bundle(hfx)
    ab = _anchor_bundle(hfx, tb)
    with _qualified_store(tmp_path, hfx) as store:
        forged = (
            ab.evidence[0],
            replace(ab.evidence[1], evidence_id="sha256:" + "0" * 64),
        )
        with pytest.raises(ValueError) as exc:
            _verify(store, hfx, tb, ab, claimed_anchor_evidence=forged)
        assert getattr(exc.value, "reason_code", "") != ""


def test_unsigned_content_blobs_are_refused_by_the_store(tmp_path: Path) -> None:
    from etzio.kernel.integrity_transition import ProviderEvidenceBlobV1
    from etzio.protocol import canonical_dumps

    hfx = _head_fixture()
    tb = _time_bundle(hfx)
    ab = _anchor_bundle(hfx, tb)
    unsigned = tuple(
        ProviderEvidenceBlobV1.from_content(
            evidence_kind=blob.evidence_kind,
            source_id=blob.source_id,
            content=canonical_dumps(
                {
                    "claim": {"source_id": blob.source_id},
                    "evidence_kind": blob.evidence_kind,
                    "qualification": "repository_owned_deterministic_fixture_only",
                    "source_id": blob.source_id,
                    "trust_boundary": "not_trustworthy_utc_external_durability_or_independence",
                }
            ),
        )
        for blob in ab.evidence_blobs
    )
    with _qualified_store(tmp_path, hfx) as store:
        with pytest.raises(ValueError) as exc:
            _verify(store, hfx, tb, ab, claimed_evidence_blobs=unsigned)
        assert getattr(exc.value, "reason_code", "") != ""
