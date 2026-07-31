"""Adversarial conformance for qualified signed revocation-evidence acceptance."""

from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from etzio.kernel.integrity_adapters_v1 import (
    RevocationRequestV1,
    TrustedTimeRequestV1,
    create_repository_owned_adapter_fixture_v1,
    map_qualified_integrity_inputs_v1,
    qualify_revocation_bundle_v1,
    qualify_time_bundle_v1,
)
from etzio.kernel.integrity_transition import ProviderEvidenceBlobV1
from etzio.kernel.qualified_evidence_v1 import (
    QUALIFIED_EVIDENCE_MODE_QUALIFIED_SIGNED_V1,
    QualifiedEvidenceError,
    QualifiedRevocationEvidenceAcceptanceV1,
    accept_qualified_revocation_evidence_v1,
)
from etzio.protocol import canonical_dumps


def _digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def _nonce(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _fixture(seed: bytes = b"qualified-revocation-acceptance-corpus-v1"):
    return create_repository_owned_adapter_fixture_v1(seed=seed)


def _time_bundle(fixture):
    vector = fixture.vector
    requests = {
        adapter.source_id: TrustedTimeRequestV1.issue(
            profile=fixture.profile,
            source_id=adapter.source_id,
            purpose="decision",
            mission_id=vector.mission_id,
            authority_id=vector.authority_id,
            target_id=vector.target_id,
            event_digest=vector.event_digest,
            transition_intent_id=vector.transition_intent_id,
            imprint_id=_digest("decision-imprint"),
            request_nonce=vector.request_nonce,
        )
        for adapter in fixture.time_adapters
    }
    return qualify_time_bundle_v1(
        profile=fixture.profile,
        requests=requests,
        signed_evidence={
            adapter.source_id: adapter.acquire(requests[adapter.source_id])
            for adapter in fixture.time_adapters
        },
    )


def _revocation_bundles(fixture, time_bundle):
    namespaces = sorted(fixture.profile.validation_policy.required_revocation_namespaces)
    bundles = {}
    for namespace in namespaces:
        state = next(
            s for s in fixture.vector.expected_revocation if s.namespace == namespace
        )
        adapters = [a for a in fixture.revocation_adapters if a.namespace == namespace]
        requests = {
            adapter.source_id: RevocationRequestV1.issue(
                profile=fixture.profile,
                source_id=adapter.source_id,
                evidence_role=adapter.role,
                namespace=namespace,
                time_bundle=time_bundle,
                prior_root_version=state.prior_root_version,
                prior_version=state.prior_version,
                prior_snapshot_id=state.prior_snapshot_id,
                request_nonce=_nonce(f"revocation-{namespace}"),
            )
            for adapter in adapters
        }
        bundles[namespace] = qualify_revocation_bundle_v1(
            profile=fixture.profile,
            namespace=namespace,
            time_bundle=time_bundle,
            requests={
                adapter.source_id: requests[adapter.source_id] for adapter in adapters
            },
            signed_evidence={
                adapter.source_id: adapter.acquire(requests[adapter.source_id])
                for adapter in adapters
            },
        )
    return bundles


def _inputs(fixture, time_bundle, bundles):
    return map_qualified_integrity_inputs_v1(
        profile=fixture.profile,
        time_bundle=time_bundle,
        revocation_bundles=bundles,
    )


def _accept(fixture, time_bundle, bundles, inputs, **overrides):
    kwargs = {
        "profile": fixture.profile,
        "time_bundle": time_bundle,
        "revocation_bundles": bundles,
        "claimed_time_lower_bound": inputs.time_lower_bound,
        "claimed_time_upper_bound": inputs.time_upper_bound,
        "claimed_time_policy_id": inputs.time_policy_id,
        "claimed_time_evidence": inputs.time_evidence,
        "claimed_revocation_views": inputs.revocation_views,
        "claimed_external_floors": inputs.external_floors,
        "claimed_evidence_blobs": inputs.evidence_blobs,
    }
    kwargs.update(overrides)
    return accept_qualified_revocation_evidence_v1(**kwargs)


def _built(seed: bytes = b"qualified-revocation-acceptance-corpus-v1"):
    fixture = _fixture(seed)
    time_bundle = _time_bundle(fixture)
    bundles = _revocation_bundles(fixture, time_bundle)
    inputs = _inputs(fixture, time_bundle, bundles)
    return fixture, time_bundle, bundles, inputs


# ---------------------------------------------------------------------------
# Acceptance of a genuine qualified mapping
# ---------------------------------------------------------------------------


def test_a_qualified_revocation_mapping_is_accepted() -> None:
    fixture, time_bundle, bundles, inputs = _built()
    acceptance = _accept(fixture, time_bundle, bundles, inputs)
    assert acceptance.mode == QUALIFIED_EVIDENCE_MODE_QUALIFIED_SIGNED_V1
    assert acceptance.revocation_views == inputs.revocation_views
    assert acceptance.external_floors == inputs.external_floors
    assert acceptance.time_evidence == inputs.time_evidence
    assert len(acceptance.revocation_views) == 2
    assert len(acceptance.evidence_blobs) == len(inputs.evidence_blobs)


def test_acceptance_is_deterministic() -> None:
    fixture, time_bundle, bundles, inputs = _built()
    first = _accept(fixture, time_bundle, bundles, inputs)
    second = _accept(fixture, time_bundle, bundles, inputs)
    assert first.acceptance_id == second.acceptance_id
    assert first.to_body() == second.to_body()


def test_accepted_blobs_are_the_exact_signed_packages() -> None:
    fixture, time_bundle, bundles, inputs = _built()
    acceptance = _accept(fixture, time_bundle, bundles, inputs)
    retained = {blob.reference.evidence_id: blob for blob in inputs.evidence_blobs}
    for blob in acceptance.evidence_blobs:
        assert blob.content == retained[blob.reference.evidence_id].content


# ---------------------------------------------------------------------------
# Fresh reauthentication, not sealed-object trust
# ---------------------------------------------------------------------------


def test_a_foreign_seed_mapping_fails_reauthentication() -> None:
    fixture, time_bundle, bundles, inputs = _built()
    _, other_tb, other_bundles, other_inputs = _built(seed=b"a-different-revocation-corpus")
    with pytest.raises(ValueError) as exc:
        accept_qualified_revocation_evidence_v1(
            profile=fixture.profile,
            time_bundle=time_bundle,
            revocation_bundles=other_bundles,
            claimed_time_lower_bound=other_inputs.time_lower_bound,
            claimed_time_upper_bound=other_inputs.time_upper_bound,
            claimed_time_policy_id=other_inputs.time_policy_id,
            claimed_time_evidence=other_inputs.time_evidence,
            claimed_revocation_views=other_inputs.revocation_views,
            claimed_external_floors=other_inputs.external_floors,
            claimed_evidence_blobs=other_inputs.evidence_blobs,
        )
    assert getattr(exc.value, "reason_code", "") != ""


# ---------------------------------------------------------------------------
# The claim must match the freshly derived mapping exactly
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("field", ["lower", "upper", "policy"])
def test_a_claimed_time_hull_or_policy_mismatch_is_refused(field: str) -> None:
    fixture, time_bundle, bundles, inputs = _built()
    overrides = {}
    if field == "lower":
        overrides["claimed_time_lower_bound"] = inputs.time_lower_bound - 1
    elif field == "upper":
        overrides["claimed_time_upper_bound"] = inputs.time_upper_bound + 1
    else:
        overrides["claimed_time_policy_id"] = _digest("a-foreign-time-policy")
    with pytest.raises(QualifiedEvidenceError) as exc:
        _accept(fixture, time_bundle, bundles, inputs, **overrides)
    assert exc.value.reason_code == "qualified_time_binding_mismatch"


def test_a_claimed_time_evidence_mismatch_is_refused() -> None:
    fixture, time_bundle, bundles, inputs = _built()
    forged = (
        replace(inputs.time_evidence[0], evidence_id=_digest("forged-time-ref")),
        *inputs.time_evidence[1:],
    )
    with pytest.raises(QualifiedEvidenceError) as exc:
        _accept(fixture, time_bundle, bundles, inputs, claimed_time_evidence=forged)
    assert exc.value.reason_code == "qualified_time_evidence_mismatch"


def test_a_claimed_revocation_view_mismatch_is_refused() -> None:
    fixture, time_bundle, bundles, inputs = _built()
    forged = (
        replace(inputs.revocation_views[0], version=inputs.revocation_views[0].version + 1),
        *inputs.revocation_views[1:],
    )
    with pytest.raises(QualifiedEvidenceError) as exc:
        _accept(fixture, time_bundle, bundles, inputs, claimed_revocation_views=forged)
    assert exc.value.reason_code == "qualified_revocation_view_mismatch"


def test_a_claimed_revocation_floor_mismatch_is_refused() -> None:
    fixture, time_bundle, bundles, inputs = _built()
    forged = (
        replace(inputs.external_floors[0], version=inputs.external_floors[0].version + 1),
        *inputs.external_floors[1:],
    )
    with pytest.raises(QualifiedEvidenceError) as exc:
        _accept(fixture, time_bundle, bundles, inputs, claimed_external_floors=forged)
    assert exc.value.reason_code == "qualified_revocation_floor_mismatch"


def test_reordered_views_are_refused() -> None:
    fixture, time_bundle, bundles, inputs = _built()
    reordered = tuple(reversed(inputs.revocation_views))
    with pytest.raises(QualifiedEvidenceError) as exc:
        _accept(fixture, time_bundle, bundles, inputs, claimed_revocation_views=reordered)
    assert exc.value.reason_code == "qualified_revocation_view_mismatch"


# ---------------------------------------------------------------------------
# BLOB bytes must be the signed packages
# ---------------------------------------------------------------------------


def test_unsigned_modeled_content_is_refused_in_qualified_mode() -> None:
    fixture, time_bundle, bundles, inputs = _built()
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
        for blob in inputs.evidence_blobs
    )
    with pytest.raises(QualifiedEvidenceError) as exc:
        _accept(fixture, time_bundle, bundles, inputs, claimed_evidence_blobs=unsigned)
    assert exc.value.reason_code == "qualified_revocation_blob_coverage_mismatch"


def test_a_non_covering_blob_set_is_refused() -> None:
    fixture, time_bundle, bundles, inputs = _built()
    with pytest.raises(QualifiedEvidenceError) as exc:
        _accept(
            fixture,
            time_bundle,
            bundles,
            inputs,
            claimed_evidence_blobs=inputs.evidence_blobs[:-1],
        )
    assert exc.value.reason_code == "qualified_revocation_blob_coverage_mismatch"


def test_empty_claimed_views_are_refused() -> None:
    fixture, time_bundle, bundles, inputs = _built()
    with pytest.raises(QualifiedEvidenceError) as exc:
        _accept(fixture, time_bundle, bundles, inputs, claimed_revocation_views=())
    assert exc.value.reason_code == "invalid_claimed_revocation_views"


def test_empty_claimed_floors_are_refused() -> None:
    fixture, time_bundle, bundles, inputs = _built()
    with pytest.raises(QualifiedEvidenceError) as exc:
        _accept(fixture, time_bundle, bundles, inputs, claimed_external_floors=())
    assert exc.value.reason_code == "invalid_claimed_revocation_floors"


# ---------------------------------------------------------------------------
# Sealing
# ---------------------------------------------------------------------------


def test_acceptance_direct_construction_is_refused() -> None:
    with pytest.raises(QualifiedEvidenceError) as exc:
        QualifiedRevocationEvidenceAcceptanceV1()
    assert exc.value.reason_code == "unauthenticated_acceptance_construction"


def test_the_acceptance_id_binds_the_derived_body() -> None:
    fixture, time_bundle, bundles, inputs = _built()
    acceptance = _accept(fixture, time_bundle, bundles, inputs)
    body = acceptance.to_body()
    assert body["mode"] == QUALIFIED_EVIDENCE_MODE_QUALIFIED_SIGNED_V1
    assert len(body["revocation_views"]) == 2
    assert len(body["external_floors"]) == 2
    assert body["time_lower_bound"] == inputs.time_lower_bound
