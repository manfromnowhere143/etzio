"""Time reauthentication after canonical serialization requires neither adapters nor transient bundles."""

from dataclasses import fields, replace

import pytest
from test_qualified_anchor_consumption_v1 import _head_fixture
from test_qualified_pending_record_wiring_v1 import (
    _coherent_qualified_pending,
    _decision_time_bundle,
    _profile_aligned_service,
)

from etzio.integrity_v1 import IntegrityDecisionV1
from etzio.kernel.integrity_adapters_v1 import (
    IntegrityAdapterError,
    RepositoryOwnedDeterministicTrustedTimeAdapterV1,
    SignedProviderEvidenceV1,
)
from etzio.kernel.integrity_transition import PendingIntegrityTransitionV1, ProviderEvidenceBlobV1
from etzio.kernel.qualified_lifecycle_v1 import reconstruct_decision_time_v1


def _fixture_pending():
    fixture = _head_fixture()
    service = _profile_aligned_service(fixture)
    _, pending = _coherent_qualified_pending(service, fixture)
    return fixture, service, pending


def _replace_time_blobs(service, pending, blobs):
    values = {field.name: getattr(pending.decision, field.name) for field in fields(pending.decision)
              if field.name != "decision_id"}
    values["time_evidence"] = tuple(blob.reference for blob in blobs)
    decision = IntegrityDecisionV1.issue(**values)
    old = {reference.evidence_id for reference in pending.decision.time_evidence}
    retained = tuple(blob for blob in pending.provider_evidence if blob.evidence_id not in old)
    return replace(pending, signed_decision=service._decision_signer.sign_decision(decision),
                   provider_evidence=tuple(sorted((*retained, *blobs),
                       key=lambda blob: (blob.evidence_kind, blob.source_id, blob.evidence_id))), time_bundle=None)


def test_cold_time_reconstruction_uses_only_canonical_records(monkeypatch):
    fixture, _, original = _fixture_pending()
    wire = original.to_canonical_bytes()
    pending = PendingIntegrityTransitionV1.from_canonical_bytes(wire)
    assert pending.time_bundle is None

    def forbidden(*args, **kwargs):
        raise AssertionError("reconstruction must not acquire provider evidence")

    monkeypatch.setattr(RepositoryOwnedDeterministicTrustedTimeAdapterV1, "acquire", forbidden)
    reconstructed = reconstruct_decision_time_v1(profile=fixture.time_fixture.profile, pending=pending)
    assert reconstructed.bundle_id == original.time_bundle.bundle_id
    assert reconstructed.evidence_blobs == original.time_bundle.evidence_blobs
    assert pending.to_canonical_bytes() == wire


def test_cold_time_reconstruction_rejects_a_forged_provider_signature():
    fixture, service, pending = _fixture_pending()
    blobs = list(pending.time_bundle.evidence_blobs)
    signed = SignedProviderEvidenceV1.from_canonical_bytes(blobs[0].content)
    forged = replace(signed, signature_bytes=bytes(64))
    blobs[0] = ProviderEvidenceBlobV1.from_content(
        evidence_kind=blobs[0].evidence_kind, source_id=blobs[0].source_id, content=forged.to_canonical_bytes(),
    )
    changed = _replace_time_blobs(service, pending, tuple(blobs))
    with pytest.raises(IntegrityAdapterError, match="signature"):
        reconstruct_decision_time_v1(profile=fixture.time_fixture.profile, pending=changed)


def test_cold_time_reconstruction_rejects_valid_signatures_for_another_request():
    fixture, service, pending = _fixture_pending()
    foreign = _decision_time_bundle(fixture)
    changed = _replace_time_blobs(service, pending, foreign.evidence_blobs)
    with pytest.raises(IntegrityAdapterError):
        reconstruct_decision_time_v1(profile=fixture.time_fixture.profile, pending=changed)


def test_reconstruction_does_not_take_scope_from_a_transient_bundle():
    fixture, _, pending = _fixture_pending()
    contradictory = replace(pending, time_bundle=_decision_time_bundle(fixture))
    fresh = reconstruct_decision_time_v1(profile=fixture.time_fixture.profile, pending=contradictory)
    assert fresh.bundle_id == pending.time_bundle.bundle_id
    assert fresh.bundle_id != contradictory.time_bundle.bundle_id
