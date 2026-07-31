"""Adversarial conformance for qualified signed anchor-evidence acceptance."""

from __future__ import annotations

from dataclasses import replace

import pytest

from etzio.integrity_v1 import HEAD_ANCHOR_RECEIPT_EVIDENCE_KIND
from etzio.kernel.head_authority_adapters_v1 import (
    HeadAnchorRequestV1,
    create_repository_owned_head_authority_fixture_v1,
    qualify_anchor_bundle_v1,
)
from etzio.kernel.integrity_adapters_v1 import (
    TrustedTimeRequestV1,
    qualify_time_bundle_v1,
)
from etzio.kernel.integrity_transition import ProviderEvidenceBlobV1
from etzio.kernel.qualified_evidence_v1 import (
    QUALIFIED_EVIDENCE_MODE_MODELED_UNSIGNED_V1,
    QUALIFIED_EVIDENCE_MODE_QUALIFIED_SIGNED_V1,
    QUALIFIED_EVIDENCE_MODES_V1,
    QualifiedAnchorEvidenceAcceptanceV1,
    QualifiedEvidenceError,
    accept_qualified_anchor_evidence_v1,
)
from etzio.protocol import canonical_dumps, content_id


def _fixture(seed: bytes = b"qualified-evidence-acceptance-corpus-v1"):
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


def _anchor_bundle(fixture, time_bundle):
    vector = fixture.vector
    requests = {
        adapter.source_id: HeadAnchorRequestV1.issue(
            profile=fixture.profile,
            source_id=adapter.source_id,
            mission_id=vector.mission_id,
            authority_id=vector.authority_id,
            target_id=vector.target_id,
            event_digest=vector.event_digest,
            transition_intent_id=vector.transition_intent_id,
            anchor_statement_id=vector.anchor_statement_id,
            instance_sequence=vector.expected_head.instance_sequence,
            time_bundle=time_bundle,
            prior_tree_size=fixture.anchor_prior_tree_size,
            request_nonce=vector.request_nonce,
        )
        for adapter in fixture.anchor_adapters
    }
    signed = {
        adapter.source_id: adapter.acquire(requests[adapter.source_id])
        for adapter in fixture.anchor_adapters
    }
    return qualify_anchor_bundle_v1(
        profile=fixture.profile,
        time_profile=fixture.time_fixture.profile,
        time_bundle=time_bundle,
        requests=requests,
        signed_evidence=signed,
    )


def _accept(fixture, time_bundle, anchor_bundle, **overrides):
    kwargs = {
        "head_profile": fixture.profile,
        "time_profile": fixture.time_fixture.profile,
        "time_bundle": time_bundle,
        "anchor_bundle": anchor_bundle,
        "claimed_anchor_statement_id": anchor_bundle.anchor_statement_id,
        "claimed_anchor_evidence": anchor_bundle.evidence,
        "claimed_evidence_blobs": anchor_bundle.evidence_blobs,
    }
    kwargs.update(overrides)
    return accept_qualified_anchor_evidence_v1(**kwargs)


def _digest(label: str) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# The two modes are distinct and mutually exclusive
# ---------------------------------------------------------------------------


def test_the_two_acceptance_modes_are_exactly_defined() -> None:
    assert QUALIFIED_EVIDENCE_MODES_V1 == frozenset(
        {
            QUALIFIED_EVIDENCE_MODE_MODELED_UNSIGNED_V1,
            QUALIFIED_EVIDENCE_MODE_QUALIFIED_SIGNED_V1,
        }
    )
    assert (
        QUALIFIED_EVIDENCE_MODE_MODELED_UNSIGNED_V1
        != QUALIFIED_EVIDENCE_MODE_QUALIFIED_SIGNED_V1
    )


# ---------------------------------------------------------------------------
# Acceptance of a genuine qualified bundle
# ---------------------------------------------------------------------------


def test_a_qualified_anchor_bundle_is_accepted() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    anchor = _anchor_bundle(fixture, bundle)
    acceptance = _accept(fixture, bundle, anchor)
    assert acceptance.mode == QUALIFIED_EVIDENCE_MODE_QUALIFIED_SIGNED_V1
    assert acceptance.anchor_statement_id == anchor.anchor_statement_id
    assert acceptance.anchor_evidence == anchor.evidence
    assert len(acceptance.evidence_blobs) == 2
    assert all(
        blob.evidence_kind == HEAD_ANCHOR_RECEIPT_EVIDENCE_KIND
        for blob in acceptance.evidence_blobs
    )


def test_acceptance_is_deterministic() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    anchor = _anchor_bundle(fixture, bundle)
    first = _accept(fixture, bundle, anchor)
    second = _accept(fixture, bundle, anchor)
    assert first.acceptance_id == second.acceptance_id
    assert first.to_body() == second.to_body()


def test_accepted_blobs_are_the_exact_signed_packages() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    anchor = _anchor_bundle(fixture, bundle)
    acceptance = _accept(fixture, bundle, anchor)
    retained = {blob.reference.evidence_id: blob for blob in anchor.evidence_blobs}
    for blob in acceptance.evidence_blobs:
        assert blob.content == retained[blob.reference.evidence_id].content


# ---------------------------------------------------------------------------
# Fresh reauthentication, not sealed-object trust
# ---------------------------------------------------------------------------


def test_a_forged_anchor_bundle_fails_reauthentication() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    # Swap in a bundle from a different seed; its retained packages will not
    # reauthenticate under this fixture's profile.
    other_fixture = _fixture(seed=b"a-different-qualified-corpus")
    other_bundle = _time_bundle(other_fixture)
    other_anchor = _anchor_bundle(other_fixture, other_bundle)
    with pytest.raises(ValueError) as exc:
        accept_qualified_anchor_evidence_v1(
            head_profile=fixture.profile,
            time_profile=fixture.time_fixture.profile,
            time_bundle=bundle,
            anchor_bundle=other_anchor,
            claimed_anchor_statement_id=other_anchor.anchor_statement_id,
            claimed_anchor_evidence=other_anchor.evidence,
            claimed_evidence_blobs=other_anchor.evidence_blobs,
        )
    assert getattr(exc.value, "reason_code", "") != ""


def test_a_sealed_bundle_of_the_wrong_type_is_refused() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    anchor = _anchor_bundle(fixture, bundle)
    with pytest.raises(QualifiedEvidenceError) as exc:
        accept_qualified_anchor_evidence_v1(
            head_profile=fixture.profile,
            time_profile=fixture.time_fixture.profile,
            time_bundle=bundle,
            anchor_bundle=object(),
            claimed_anchor_statement_id=anchor.anchor_statement_id,
            claimed_anchor_evidence=anchor.evidence,
            claimed_evidence_blobs=anchor.evidence_blobs,
        )
    assert exc.value.reason_code == "invalid_qualified_anchor_bundle"


# ---------------------------------------------------------------------------
# The claim must match the freshly derived result exactly
# ---------------------------------------------------------------------------


def test_a_claimed_foreign_anchor_statement_is_refused() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    anchor = _anchor_bundle(fixture, bundle)
    with pytest.raises(QualifiedEvidenceError) as exc:
        _accept(
            fixture,
            bundle,
            anchor,
            claimed_anchor_statement_id=_digest("a-foreign-statement"),
        )
    assert exc.value.reason_code == "qualified_anchor_statement_mismatch"


def test_claimed_references_that_do_not_match_are_refused() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    anchor = _anchor_bundle(fixture, bundle)
    forged = (
        anchor.evidence[0],
        replace(anchor.evidence[1], evidence_id=_digest("forged-reference")),
    )
    with pytest.raises(QualifiedEvidenceError) as exc:
        _accept(fixture, bundle, anchor, claimed_anchor_evidence=forged)
    assert exc.value.reason_code == "qualified_anchor_evidence_mismatch"


def test_claimed_references_below_quorum_are_refused() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    anchor = _anchor_bundle(fixture, bundle)
    with pytest.raises(QualifiedEvidenceError) as exc:
        _accept(fixture, bundle, anchor, claimed_anchor_evidence=(anchor.evidence[0],))
    assert exc.value.reason_code == "invalid_claimed_anchor_evidence"


def test_claimed_references_of_the_wrong_kind_are_refused() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    anchor = _anchor_bundle(fixture, bundle)
    wrong_kind = tuple(
        replace(reference, evidence_kind="external_floor")
        for reference in anchor.evidence
    )
    with pytest.raises(QualifiedEvidenceError) as exc:
        _accept(fixture, bundle, anchor, claimed_anchor_evidence=wrong_kind)
    assert exc.value.reason_code == "invalid_claimed_anchor_evidence"


# ---------------------------------------------------------------------------
# The BLOB bytes must be the signed packages, never unsigned modeled content
# ---------------------------------------------------------------------------


def test_unsigned_modeled_content_is_refused_in_qualified_mode() -> None:
    """The key mutual-exclusion property: qualified mode rejects unsigned content."""

    fixture = _fixture()
    bundle = _time_bundle(fixture)
    anchor = _anchor_bundle(fixture, bundle)
    # Rebuild each anchor blob with unsigned code-derived content of the ADR-0011
    # shape.  It hashes to a different identity, so coverage fails.
    unsigned = tuple(
        ProviderEvidenceBlobV1.from_content(
            evidence_kind=HEAD_ANCHOR_RECEIPT_EVIDENCE_KIND,
            source_id=blob.source_id,
            content=canonical_dumps(
                {
                    "claim": {"anchor_statement_id": anchor.anchor_statement_id},
                    "evidence_kind": HEAD_ANCHOR_RECEIPT_EVIDENCE_KIND,
                    "qualification": "repository_owned_deterministic_fixture_only",
                    "source_id": blob.source_id,
                    "trust_boundary": "not_trustworthy_utc_external_durability_or_independence",
                }
            ),
        )
        for blob in anchor.evidence_blobs
    )
    with pytest.raises(QualifiedEvidenceError) as exc:
        _accept(fixture, bundle, anchor, claimed_evidence_blobs=unsigned)
    assert exc.value.reason_code == "qualified_anchor_blob_coverage_mismatch"


def test_claimed_blobs_that_do_not_cover_the_retained_set_are_refused() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    anchor = _anchor_bundle(fixture, bundle)
    with pytest.raises(QualifiedEvidenceError) as exc:
        _accept(
            fixture,
            bundle,
            anchor,
            claimed_evidence_blobs=(anchor.evidence_blobs[0],),
        )
    assert exc.value.reason_code == "qualified_anchor_blob_coverage_mismatch"


def test_empty_claimed_blobs_are_refused() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    anchor = _anchor_bundle(fixture, bundle)
    with pytest.raises(QualifiedEvidenceError) as exc:
        _accept(fixture, bundle, anchor, claimed_evidence_blobs=())
    assert exc.value.reason_code == "invalid_claimed_anchor_blobs"


def test_a_claimed_blob_with_tampered_content_is_refused() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    anchor = _anchor_bundle(fixture, bundle)
    # A blob whose identity matches a retained one but whose bytes differ cannot be
    # constructed (the digest is content-bound), so use a foreign in-set identity: a
    # blob with a valid but unrelated signed-shaped payload under a retained source.
    good = anchor.evidence_blobs[0]
    tampered = ProviderEvidenceBlobV1.from_content(
        evidence_kind=good.evidence_kind,
        source_id=good.source_id,
        content=good.content + b" ",
    )
    with pytest.raises(QualifiedEvidenceError) as exc:
        _accept(
            fixture,
            bundle,
            anchor,
            claimed_evidence_blobs=(tampered, anchor.evidence_blobs[1]),
        )
    assert exc.value.reason_code == "qualified_anchor_blob_coverage_mismatch"


# ---------------------------------------------------------------------------
# Sealing
# ---------------------------------------------------------------------------


def test_acceptance_direct_construction_is_refused() -> None:
    with pytest.raises(QualifiedEvidenceError) as exc:
        QualifiedAnchorEvidenceAcceptanceV1()
    assert exc.value.reason_code == "unauthenticated_acceptance_construction"


def test_the_acceptance_id_binds_the_derived_body() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    anchor = _anchor_bundle(fixture, bundle)
    acceptance = _accept(fixture, bundle, anchor)
    body = acceptance.to_body()
    assert body["mode"] == QUALIFIED_EVIDENCE_MODE_QUALIFIED_SIGNED_V1
    assert body["anchor_statement_id"] == anchor.anchor_statement_id
    assert len(body["anchor_evidence"]) == 2
    assert len(body["evidence_blobs"]) == 2
