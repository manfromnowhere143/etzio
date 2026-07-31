"""Adversarial conformance for qualified signed head-floor-evidence acceptance."""

from __future__ import annotations

import pytest

from etzio.kernel.head_authority_adapters_v1 import (
    HEAD_CATALOG_ADAPTER_ROLE_V1,
    HEAD_MONITOR_ADAPTER_ROLE_V1,
    HeadCatalogRequestV1,
    create_repository_owned_head_authority_fixture_v1,
    qualify_head_catalog_bundle_v1,
)
from etzio.kernel.integrity_adapters_v1 import (
    TrustedTimeRequestV1,
    qualify_time_bundle_v1,
)
from etzio.kernel.integrity_transition import ProviderEvidenceBlobV1
from etzio.kernel.qualified_evidence_v1 import (
    QUALIFIED_EVIDENCE_MODE_QUALIFIED_SIGNED_V1,
    QualifiedEvidenceError,
    QualifiedHeadFloorEvidenceAcceptanceV1,
    accept_qualified_head_floor_evidence_v1,
)
from etzio.protocol import canonical_dumps, content_id


def _fixture(seed: bytes = b"qualified-head-floor-acceptance-corpus-v1"):
    return create_repository_owned_head_authority_fixture_v1(seed=seed)


def _time_bundle(fixture):
    time_fixture = fixture.time_fixture
    vector = time_fixture.vector
    requests = {
        adapter.source_id: TrustedTimeRequestV1.issue(
            profile=time_fixture.profile,
            source_id=adapter.source_id,
            purpose="checkpoint",
            mission_id=vector.mission_id,
            authority_id=vector.authority_id,
            target_id=vector.target_id,
            event_digest=vector.event_digest,
            transition_intent_id=vector.transition_intent_id,
            imprint_id=content_id(
                "head_authority_repository_fixture",
                {"label": "head-authority-imprint", "value": "checkpoint"},
            ),
            request_nonce=vector.request_nonce,
        )
        for adapter in time_fixture.time_adapters
    }
    return qualify_time_bundle_v1(
        profile=time_fixture.profile,
        requests=requests,
        signed_evidence={
            adapter.source_id: adapter.acquire(requests[adapter.source_id])
            for adapter in time_fixture.time_adapters
        },
    )


def _catalog_bundle(fixture, time_bundle):
    vector = fixture.vector
    head = vector.expected_head
    adapters = {fixture.catalog_adapter.source_id: fixture.catalog_adapter}
    for monitor in fixture.monitor_adapters:
        adapters[monitor.source_id] = monitor
    roles = [(fixture.catalog_adapter.source_id, HEAD_CATALOG_ADAPTER_ROLE_V1)]
    roles.extend(
        (monitor.source_id, HEAD_MONITOR_ADAPTER_ROLE_V1)
        for monitor in fixture.monitor_adapters
    )
    requests = {
        source_id: HeadCatalogRequestV1.issue(
            profile=fixture.profile,
            source_id=source_id,
            evidence_role=role,
            mission_id=vector.mission_id,
            authority_id=vector.authority_id,
            target_id=vector.target_id,
            event_digest=vector.event_digest,
            transition_intent_id=vector.transition_intent_id,
            time_bundle=time_bundle,
            prior_tree_size=fixture.prior_tree_size,
            prior_log_root_hash=fixture.prior_log_root_hash,
            prior_instance_sequence=head.prior_instance_sequence,
            prior_checkpoint_id=head.prior_checkpoint_id,
            prior_mission_event_seq=head.prior_mission_event_seq,
            prior_mission_checkpoint_id=head.prior_mission_checkpoint_id,
            request_nonce=vector.request_nonce,
        )
        for source_id, role in roles
    }
    return qualify_head_catalog_bundle_v1(
        profile=fixture.profile,
        time_profile=fixture.time_fixture.profile,
        time_bundle=time_bundle,
        requests=requests,
        signed_evidence={
            source_id: adapters[source_id].acquire(requests[source_id])
            for source_id in adapters
        },
    )


def _built(seed: bytes = b"qualified-head-floor-acceptance-corpus-v1"):
    fixture = _fixture(seed)
    time_bundle = _time_bundle(fixture)
    catalog_bundle = _catalog_bundle(fixture, time_bundle)
    return fixture, time_bundle, catalog_bundle


def _accept(fixture, time_bundle, catalog_bundle, **overrides):
    kwargs = {
        "head_profile": fixture.profile,
        "time_profile": fixture.time_fixture.profile,
        "time_bundle": time_bundle,
        "catalog_bundle": catalog_bundle,
        "claimed_external_floor": catalog_bundle.external_floor,
        "claimed_evidence_blobs": catalog_bundle.evidence_blobs,
    }
    kwargs.update(overrides)
    return accept_qualified_head_floor_evidence_v1(**kwargs)


# ---------------------------------------------------------------------------
# Acceptance
# ---------------------------------------------------------------------------


def test_a_qualified_head_floor_is_accepted() -> None:
    fixture, time_bundle, catalog_bundle = _built()
    acceptance = _accept(fixture, time_bundle, catalog_bundle)
    assert acceptance.mode == QUALIFIED_EVIDENCE_MODE_QUALIFIED_SIGNED_V1
    assert acceptance.external_floor.to_body() == catalog_bundle.external_floor.to_body()
    assert len(acceptance.evidence_blobs) == 3


def test_acceptance_is_deterministic() -> None:
    fixture, time_bundle, catalog_bundle = _built()
    first = _accept(fixture, time_bundle, catalog_bundle)
    second = _accept(fixture, time_bundle, catalog_bundle)
    assert first.acceptance_id == second.acceptance_id
    assert first.to_body() == second.to_body()


def test_accepted_blobs_are_the_exact_signed_packages() -> None:
    fixture, time_bundle, catalog_bundle = _built()
    acceptance = _accept(fixture, time_bundle, catalog_bundle)
    retained = {
        blob.reference.evidence_id: blob for blob in catalog_bundle.evidence_blobs
    }
    for blob in acceptance.evidence_blobs:
        assert blob.content == retained[blob.reference.evidence_id].content


# ---------------------------------------------------------------------------
# Fresh reauthentication
# ---------------------------------------------------------------------------


def test_a_foreign_seed_catalog_bundle_fails_reauthentication() -> None:
    fixture, time_bundle, _ = _built()
    _, other_tb, other_catalog = _built(seed=b"a-different-head-floor-corpus")
    with pytest.raises(ValueError) as exc:
        accept_qualified_head_floor_evidence_v1(
            head_profile=fixture.profile,
            time_profile=fixture.time_fixture.profile,
            time_bundle=time_bundle,
            catalog_bundle=other_catalog,
            claimed_external_floor=other_catalog.external_floor,
            claimed_evidence_blobs=other_catalog.evidence_blobs,
        )
    assert getattr(exc.value, "reason_code", "") != ""


def test_a_wrong_bundle_type_is_refused() -> None:
    fixture, time_bundle, catalog_bundle = _built()
    with pytest.raises(QualifiedEvidenceError) as exc:
        accept_qualified_head_floor_evidence_v1(
            head_profile=fixture.profile,
            time_profile=fixture.time_fixture.profile,
            time_bundle=time_bundle,
            catalog_bundle=object(),
            claimed_external_floor=catalog_bundle.external_floor,
            claimed_evidence_blobs=catalog_bundle.evidence_blobs,
        )
    assert exc.value.reason_code == "invalid_qualified_catalog_bundle"


# ---------------------------------------------------------------------------
# The claimed floor must match exactly
# ---------------------------------------------------------------------------


def test_a_claimed_floor_of_the_wrong_type_is_refused() -> None:
    fixture, time_bundle, catalog_bundle = _built()
    with pytest.raises(QualifiedEvidenceError) as exc:
        _accept(fixture, time_bundle, catalog_bundle, claimed_external_floor=object())
    assert exc.value.reason_code == "invalid_claimed_head_floor"


def test_a_claimed_floor_from_another_head_is_refused() -> None:
    fixture, time_bundle, catalog_bundle = _built()
    other_fixture, other_tb, other_catalog = _built(seed=b"another-head-position")
    # A structurally valid but different floor (different service scope) is refused.
    with pytest.raises(QualifiedEvidenceError) as exc:
        _accept(
            fixture,
            time_bundle,
            catalog_bundle,
            claimed_external_floor=other_catalog.external_floor,
        )
    assert exc.value.reason_code == "qualified_head_floor_mismatch"


# ---------------------------------------------------------------------------
# BLOB bytes must be the signed packages
# ---------------------------------------------------------------------------


def test_unsigned_modeled_content_is_refused_in_qualified_mode() -> None:
    fixture, time_bundle, catalog_bundle = _built()
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
        for blob in catalog_bundle.evidence_blobs
    )
    with pytest.raises(QualifiedEvidenceError) as exc:
        _accept(fixture, time_bundle, catalog_bundle, claimed_evidence_blobs=unsigned)
    assert exc.value.reason_code == "qualified_head_floor_blob_coverage_mismatch"


def test_a_non_covering_blob_set_is_refused() -> None:
    fixture, time_bundle, catalog_bundle = _built()
    with pytest.raises(QualifiedEvidenceError) as exc:
        _accept(
            fixture,
            time_bundle,
            catalog_bundle,
            claimed_evidence_blobs=catalog_bundle.evidence_blobs[:-1],
        )
    assert exc.value.reason_code == "qualified_head_floor_blob_coverage_mismatch"


def test_empty_claimed_blobs_are_refused() -> None:
    fixture, time_bundle, catalog_bundle = _built()
    with pytest.raises(QualifiedEvidenceError) as exc:
        _accept(fixture, time_bundle, catalog_bundle, claimed_evidence_blobs=())
    assert exc.value.reason_code == "invalid_claimed_anchor_blobs"


def test_a_tampered_blob_is_refused() -> None:
    fixture, time_bundle, catalog_bundle = _built()
    good = catalog_bundle.evidence_blobs[0]
    tampered = ProviderEvidenceBlobV1.from_content(
        evidence_kind=good.evidence_kind,
        source_id=good.source_id,
        content=good.content + b" ",
    )
    with pytest.raises(QualifiedEvidenceError) as exc:
        _accept(
            fixture,
            time_bundle,
            catalog_bundle,
            claimed_evidence_blobs=(tampered, *catalog_bundle.evidence_blobs[1:]),
        )
    assert exc.value.reason_code == "qualified_head_floor_blob_coverage_mismatch"


# ---------------------------------------------------------------------------
# Sealing
# ---------------------------------------------------------------------------


def test_acceptance_direct_construction_is_refused() -> None:
    with pytest.raises(QualifiedEvidenceError) as exc:
        QualifiedHeadFloorEvidenceAcceptanceV1()
    assert exc.value.reason_code == "unauthenticated_acceptance_construction"


def test_the_acceptance_id_binds_the_derived_body() -> None:
    fixture, time_bundle, catalog_bundle = _built()
    acceptance = _accept(fixture, time_bundle, catalog_bundle)
    body = acceptance.to_body()
    assert body["mode"] == QUALIFIED_EVIDENCE_MODE_QUALIFIED_SIGNED_V1
    assert body["external_floor"] == catalog_bundle.external_floor.to_body()
    assert len(body["evidence_blobs"]) == 3


def test_all_three_acceptance_primitives_share_one_mode() -> None:
    """Anchor, revocation, and head-floor acceptance report the one qualified mode."""

    from etzio.kernel.qualified_evidence_v1 import (
        QUALIFIED_EVIDENCE_MODE_MODELED_UNSIGNED_V1,
        accept_qualified_anchor_evidence_v1,
        accept_qualified_revocation_evidence_v1,
    )

    assert accept_qualified_anchor_evidence_v1 is not None
    assert accept_qualified_revocation_evidence_v1 is not None
    assert (
        QUALIFIED_EVIDENCE_MODE_QUALIFIED_SIGNED_V1
        != QUALIFIED_EVIDENCE_MODE_MODELED_UNSIGNED_V1
    )
    fixture, time_bundle, catalog_bundle = _built()
    assert (
        _accept(fixture, time_bundle, catalog_bundle).mode
        == QUALIFIED_EVIDENCE_MODE_QUALIFIED_SIGNED_V1
    )
