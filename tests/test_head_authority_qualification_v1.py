"""Adversarial conformance for the networkless head-authority qualification contract."""

from __future__ import annotations

import hashlib
import socket
import time
from dataclasses import replace

import pytest

from etzio.integrity_v1 import (
    EXTERNAL_FLOOR_EVIDENCE_KIND,
    HEAD_ANCHOR_RECEIPT_EVIDENCE_KIND,
    EvidenceReferenceV1,
    IntegrityValidationPolicyV1,
)
from etzio.kernel.head_authority_adapters_v1 import (
    HEAD_ANCHOR_ADAPTER_ROLE_V1,
    HEAD_AUTHORITY_CONTRACT_VERSION_V1,
    HEAD_CATALOG_ADAPTER_ROLE_V1,
    HEAD_MONITOR_ADAPTER_ROLE_V1,
    REPOSITORY_OWNED_HEAD_AUTHORITY_PROFILE_V1,
    AnchorRegistrationLeafV1,
    AuthenticatedHeadEvidencePackageV1,
    HeadAnchorRequestV1,
    HeadAuthorityAdapterError,
    HeadAuthorityQualificationReportV1,
    HeadAuthoritySourceBindingV1,
    HeadAuthorityTrustProfileV1,
    HeadAuthorityTrustStoreV1,
    HeadCatalogRequestV1,
    HeadEvidenceSignerV1,
    HeadProviderStatementV1,
    QualifiedAnchorBundleV1,
    QualifiedHeadAuthorityInputsV1,
    QualifiedHeadCatalogBundleV1,
    RepositoryOwnedDeterministicHeadAuthorityFixtureV1,
    RepositoryOwnedDeterministicHeadMonitorAdapterV1,
    SignedHeadEvidenceV1,
    TrustedHeadAuthorityKeyV1,
    authenticate_head_evidence_v1,
    create_repository_owned_head_authority_fixture_v1,
    map_qualified_head_authority_inputs_v1,
    merkle_consistency_proof_v1,
    merkle_inclusion_proof_v1,
    merkle_leaf_hash_v1,
    merkle_root_v1,
    qualify_anchor_bundle_v1,
    qualify_head_catalog_bundle_v1,
    qualify_repository_head_authority_adapters_v1,
    reauthenticate_anchor_bundle_v1,
    reauthenticate_head_catalog_bundle_v1,
    verify_merkle_consistency_v1,
    verify_merkle_inclusion_v1,
)
from etzio.kernel.integrity_adapters_v1 import (
    QualifiedTimeBundleV1,
    TrustedTimeRequestV1,
    qualify_time_bundle_v1,
)
from etzio.protocol import content_id

SEED = b"etzio-head-authority-known-bad-corpus-v1"

# RFC 6962 / RFC 9162 reference test-tree entries and their published tree heads.
_RFC_ENTRIES = (
    b"",
    bytes.fromhex("00"),
    bytes.fromhex("10"),
    bytes.fromhex("2021"),
    bytes.fromhex("3031"),
    bytes.fromhex("40414243"),
    bytes.fromhex("5051525354555657"),
    bytes.fromhex("606162636465666768696a6b6c6d6e6f"),
)
_RFC_ROOTS = (
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
)


def _rfc_leaves() -> tuple[bytes, ...]:
    return tuple(hashlib.sha256(b"\x00" + entry).digest() for entry in _RFC_ENTRIES)


def _digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def _fixture() -> RepositoryOwnedDeterministicHeadAuthorityFixtureV1:
    return create_repository_owned_head_authority_fixture_v1(seed=SEED)


def _time_bundle(
    fixture: RepositoryOwnedDeterministicHeadAuthorityFixtureV1,
) -> QualifiedTimeBundleV1:
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


def _anchor_requests(
    fixture: RepositoryOwnedDeterministicHeadAuthorityFixtureV1,
    bundle: QualifiedTimeBundleV1,
    *,
    anchor_statement_id: str | None = None,
    prior_tree_size: int | None = None,
) -> dict[str, HeadAnchorRequestV1]:
    vector = fixture.vector
    return {
        adapter.source_id: HeadAnchorRequestV1.issue(
            profile=fixture.profile,
            source_id=adapter.source_id,
            mission_id=vector.mission_id,
            authority_id=vector.authority_id,
            target_id=vector.target_id,
            event_digest=vector.event_digest,
            transition_intent_id=vector.transition_intent_id,
            anchor_statement_id=anchor_statement_id or vector.anchor_statement_id,
            instance_sequence=vector.expected_head.instance_sequence,
            time_bundle=bundle,
            prior_tree_size=(
                fixture.anchor_prior_tree_size if prior_tree_size is None else prior_tree_size
            ),
            request_nonce=vector.request_nonce,
        )
        for adapter in fixture.anchor_adapters
    }


def _anchor_inputs(
    fixture: RepositoryOwnedDeterministicHeadAuthorityFixtureV1,
    bundle: QualifiedTimeBundleV1,
) -> tuple[dict[str, HeadAnchorRequestV1], dict[str, SignedHeadEvidenceV1]]:
    requests = _anchor_requests(fixture, bundle)
    signed = {
        adapter.source_id: adapter.acquire(requests[adapter.source_id])
        for adapter in fixture.anchor_adapters
    }
    return requests, signed


def _catalog_sources(
    fixture: RepositoryOwnedDeterministicHeadAuthorityFixtureV1,
) -> dict[str, object]:
    adapters: dict[str, object] = {
        fixture.catalog_adapter.source_id: fixture.catalog_adapter
    }
    for adapter in fixture.monitor_adapters:
        adapters[adapter.source_id] = adapter
    return adapters


def _catalog_requests(
    fixture: RepositoryOwnedDeterministicHeadAuthorityFixtureV1,
    bundle: QualifiedTimeBundleV1,
    *,
    prior_tree_size: int | None = None,
) -> dict[str, HeadCatalogRequestV1]:
    vector = fixture.vector
    head = vector.expected_head
    roles = [(fixture.catalog_adapter.source_id, HEAD_CATALOG_ADAPTER_ROLE_V1)]
    roles.extend(
        (adapter.source_id, HEAD_MONITOR_ADAPTER_ROLE_V1)
        for adapter in fixture.monitor_adapters
    )
    return {
        source_id: HeadCatalogRequestV1.issue(
            profile=fixture.profile,
            source_id=source_id,
            evidence_role=role,
            mission_id=vector.mission_id,
            authority_id=vector.authority_id,
            target_id=vector.target_id,
            event_digest=vector.event_digest,
            transition_intent_id=vector.transition_intent_id,
            time_bundle=bundle,
            prior_tree_size=(
                fixture.prior_tree_size if prior_tree_size is None else prior_tree_size
            ),
            prior_log_root_hash=fixture.prior_log_root_hash,
            prior_instance_sequence=head.prior_instance_sequence,
            prior_checkpoint_id=head.prior_checkpoint_id,
            prior_mission_event_seq=head.prior_mission_event_seq,
            prior_mission_checkpoint_id=head.prior_mission_checkpoint_id,
            request_nonce=vector.request_nonce,
        )
        for source_id, role in roles
    }


def _catalog_inputs(
    fixture: RepositoryOwnedDeterministicHeadAuthorityFixtureV1,
    bundle: QualifiedTimeBundleV1,
) -> tuple[dict[str, HeadCatalogRequestV1], dict[str, SignedHeadEvidenceV1]]:
    requests = _catalog_requests(fixture, bundle)
    adapters = _catalog_sources(fixture)
    signed = {
        source_id: adapter.acquire(requests[source_id])  # type: ignore[union-attr]
        for source_id, adapter in adapters.items()
    }
    return requests, signed


def _resign(
    signer: HeadEvidenceSignerV1,
    statement: HeadProviderStatementV1,
    **claim_overrides: object,
) -> SignedHeadEvidenceV1:
    claim = dict(statement.claim)
    claim.update(claim_overrides)
    return signer.sign(replace(statement, claim=claim))


def _anchor_signer(
    fixture: RepositoryOwnedDeterministicHeadAuthorityFixtureV1,
    source_id: str,
) -> HeadEvidenceSignerV1:
    return next(
        adapter.signer
        for adapter in fixture.anchor_adapters
        if adapter.source_id == source_id
    )


# ---------------------------------------------------------------------------
# RFC 9162 Merkle core
# ---------------------------------------------------------------------------


def test_merkle_roots_match_the_published_rfc_reference_tree() -> None:
    leaves = _rfc_leaves()
    for size, expected in enumerate(_RFC_ROOTS):
        assert merkle_root_v1(leaves[:size]).hex() == expected


def test_merkle_inclusion_proofs_verify_for_every_reference_leaf() -> None:
    leaves = _rfc_leaves()
    checked = 0
    for size in range(1, len(leaves) + 1):
        root = merkle_root_v1(leaves[:size])
        for index in range(size):
            verify_merkle_inclusion_v1(
                leaf_hash=leaves[index],
                leaf_index=index,
                tree_size=size,
                proof=merkle_inclusion_proof_v1(leaves[:size], index),
                root_hash=root,
            )
            checked += 1
    assert checked == 36


def test_merkle_consistency_proofs_verify_for_every_reference_prefix() -> None:
    leaves = _rfc_leaves()
    checked = 0
    for size in range(1, len(leaves) + 1):
        for prefix in range(1, size + 1):
            verify_merkle_consistency_v1(
                first_size=prefix,
                first_root=merkle_root_v1(leaves[:prefix]),
                second_size=size,
                second_root=merkle_root_v1(leaves[:size]),
                proof=merkle_consistency_proof_v1(leaves[:size], prefix),
            )
            checked += 1
    assert checked == 36


def test_leaf_and_node_hashing_are_domain_separated() -> None:
    payload = b"etzio"
    assert merkle_leaf_hash_v1(payload) == hashlib.sha256(b"\x00" + payload).digest()
    assert merkle_leaf_hash_v1(payload) != hashlib.sha256(b"\x01" + payload).digest()
    assert merkle_leaf_hash_v1(payload) != hashlib.sha256(payload).digest()


def test_inclusion_proof_rejects_a_tampered_node() -> None:
    leaves = _rfc_leaves()
    proof = list(merkle_inclusion_proof_v1(leaves[:8], 3))
    proof[0] = hashlib.sha256(b"tampered").digest()
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        verify_merkle_inclusion_v1(
            leaf_hash=leaves[3],
            leaf_index=3,
            tree_size=8,
            proof=tuple(proof),
            root_hash=merkle_root_v1(leaves[:8]),
        )
    assert exc.value.reason_code == "head_inclusion_proof_invalid"


@pytest.mark.parametrize("delta", [-1, 1])
def test_inclusion_proof_rejects_truncated_and_padded_proofs(delta: int) -> None:
    leaves = _rfc_leaves()
    proof = list(merkle_inclusion_proof_v1(leaves[:8], 3))
    if delta < 0:
        proof = proof[:-1]
    else:
        proof.append(hashlib.sha256(b"extra").digest())
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        verify_merkle_inclusion_v1(
            leaf_hash=leaves[3],
            leaf_index=3,
            tree_size=8,
            proof=tuple(proof),
            root_hash=merkle_root_v1(leaves[:8]),
        )
    assert exc.value.reason_code == "head_inclusion_proof_invalid"


def test_inclusion_proof_rejects_an_out_of_range_leaf_index() -> None:
    leaves = _rfc_leaves()
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        verify_merkle_inclusion_v1(
            leaf_hash=leaves[0],
            leaf_index=8,
            tree_size=8,
            proof=(),
            root_hash=merkle_root_v1(leaves[:8]),
        )
    assert exc.value.reason_code == "head_inclusion_proof_invalid"


def test_inclusion_proof_rejects_a_substituted_leaf() -> None:
    leaves = _rfc_leaves()
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        verify_merkle_inclusion_v1(
            leaf_hash=leaves[4],
            leaf_index=3,
            tree_size=8,
            proof=merkle_inclusion_proof_v1(leaves[:8], 3),
            root_hash=merkle_root_v1(leaves[:8]),
        )
    assert exc.value.reason_code == "head_inclusion_proof_invalid"


def test_consistency_proof_refuses_a_shrinking_tree() -> None:
    leaves = _rfc_leaves()
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        verify_merkle_consistency_v1(
            first_size=6,
            first_root=merkle_root_v1(leaves[:6]),
            second_size=4,
            second_root=merkle_root_v1(leaves[:4]),
            proof=(),
        )
    assert exc.value.reason_code == "head_catalog_tree_rollback"


def test_consistency_proof_refuses_an_equal_size_root_change() -> None:
    leaves = _rfc_leaves()
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        verify_merkle_consistency_v1(
            first_size=5,
            first_root=merkle_root_v1(leaves[:5]),
            second_size=5,
            second_root=merkle_root_v1(leaves[:4]),
            proof=(),
        )
    assert exc.value.reason_code == "head_catalog_equivocation"


def test_consistency_proof_refuses_a_missing_proof_for_a_grown_tree() -> None:
    leaves = _rfc_leaves()
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        verify_merkle_consistency_v1(
            first_size=3,
            first_root=merkle_root_v1(leaves[:3]),
            second_size=8,
            second_root=merkle_root_v1(leaves[:8]),
            proof=(),
        )
    assert exc.value.reason_code == "head_consistency_proof_invalid"


def test_consistency_proof_refuses_a_forked_history() -> None:
    leaves = _rfc_leaves()
    forked = (*leaves[:3], hashlib.sha256(b"\x00forked").digest(), *leaves[4:8])
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        verify_merkle_consistency_v1(
            first_size=5,
            first_root=merkle_root_v1(leaves[:5]),
            second_size=8,
            second_root=merkle_root_v1(forked),
            proof=merkle_consistency_proof_v1(forked, 5),
        )
    assert exc.value.reason_code == "head_consistency_proof_invalid"


def test_consistency_proof_refuses_a_tampered_node() -> None:
    leaves = _rfc_leaves()
    proof = list(merkle_consistency_proof_v1(leaves[:8], 3))
    proof[-1] = hashlib.sha256(b"tampered").digest()
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        verify_merkle_consistency_v1(
            first_size=3,
            first_root=merkle_root_v1(leaves[:3]),
            second_size=8,
            second_root=merkle_root_v1(leaves[:8]),
            proof=tuple(proof),
        )
    assert exc.value.reason_code == "head_consistency_proof_invalid"


def test_merkle_verifiers_reject_unbounded_proofs() -> None:
    leaves = _rfc_leaves()
    oversized = tuple(hashlib.sha256(bytes([index])).digest() for index in range(65))
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        verify_merkle_inclusion_v1(
            leaf_hash=leaves[0],
            leaf_index=0,
            tree_size=8,
            proof=oversized,
            root_hash=merkle_root_v1(leaves[:8]),
        )
    assert exc.value.reason_code == "invalid_head_proof"


# ---------------------------------------------------------------------------
# Trust profile
# ---------------------------------------------------------------------------


def test_profile_is_deterministic_canonical_and_deeply_snapshotted() -> None:
    fixture = _fixture()
    profile = fixture.profile
    assert profile.adapter_profile == REPOSITORY_OWNED_HEAD_AUTHORITY_PROFILE_V1
    assert profile.contract_version == HEAD_AUTHORITY_CONTRACT_VERSION_V1
    rebuilt = HeadAuthorityTrustProfileV1.from_canonical_bytes(profile.to_canonical_bytes())
    assert rebuilt.profile_id == profile.profile_id
    assert rebuilt.to_body() == profile.to_body()
    assert profile.sources_for(HEAD_ANCHOR_ADAPTER_ROLE_V1) == (
        "fixture.anchor.a",
        "fixture.anchor.b",
    )
    assert profile.catalog_binding.source_id == "fixture.catalog"
    assert profile.sources_for(HEAD_MONITOR_ADAPTER_ROLE_V1) == (
        "fixture.monitor.a",
        "fixture.monitor.b",
    )


def test_profile_rejects_policy_and_trust_root_substitution() -> None:
    profile = _fixture().profile
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        replace(profile, validation_policy_id=_digest("other-policy"))
    assert exc.value.reason_code == "head_policy_binding_mismatch"
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        replace(profile, trust_root_id=_digest("other-root"))
    assert exc.value.reason_code == "head_trust_root_binding_mismatch"


def test_profile_requires_two_anchor_sources_with_distinct_log_origins() -> None:
    profile = _fixture().profile
    without_anchor = tuple(
        binding for binding in profile.source_bindings if binding.source_id != "fixture.anchor.b"
    )
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        replace(
            profile,
            source_bindings=without_anchor,
            trust_store=HeadAuthorityTrustStoreV1.from_keys(
                profile.trust_store.keys[binding.key_id] for binding in without_anchor
            ),
            trust_root_id=HeadAuthorityTrustStoreV1.from_keys(
                profile.trust_store.keys[binding.key_id] for binding in without_anchor
            ).root_id,
        )
    assert exc.value.reason_code == "invalid_head_source_roster"

    shared_origin = tuple(
        replace(binding, log_origin="fixture.anchor-log.a")
        if binding.role == HEAD_ANCHOR_ADAPTER_ROLE_V1
        else binding
        for binding in profile.source_bindings
    )
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        replace(profile, source_bindings=shared_origin)
    assert exc.value.reason_code == "head_source_independence_confusion"


def test_profile_requires_exactly_one_catalog_and_two_monitors() -> None:
    profile = _fixture().profile
    without_monitor = tuple(
        binding
        for binding in profile.source_bindings
        if binding.source_id != "fixture.monitor.b"
    )
    store = HeadAuthorityTrustStoreV1.from_keys(
        profile.trust_store.keys[binding.key_id] for binding in without_monitor
    )
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        replace(
            profile,
            source_bindings=without_monitor,
            trust_store=store,
            trust_root_id=store.root_id,
        )
    assert exc.value.reason_code == "invalid_head_source_roster"


def test_profile_requires_monitors_to_witness_the_catalog_log_origin() -> None:
    profile = _fixture().profile
    drifted = tuple(
        replace(binding, log_origin="fixture.other-log")
        if binding.source_id == "fixture.monitor.b"
        else binding
        for binding in profile.source_bindings
    )
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        replace(profile, source_bindings=drifted)
    assert exc.value.reason_code == "head_monitor_origin_mismatch"


def test_profile_rejects_source_key_principal_and_role_confusion() -> None:
    profile = _fixture().profile
    anchor = profile.binding_for(role=HEAD_ANCHOR_ADAPTER_ROLE_V1, source_id="fixture.anchor.a")
    other = profile.binding_for(role=HEAD_ANCHOR_ADAPTER_ROLE_V1, source_id="fixture.anchor.b")
    confused = tuple(
        replace(binding, key_id=other.key_id) if binding.source_id == anchor.source_id else binding
        for binding in profile.source_bindings
    )
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        replace(profile, source_bindings=confused)
    assert exc.value.reason_code == "head_source_independence_confusion"


def test_source_binding_rejects_a_codec_that_does_not_match_its_role() -> None:
    binding = _fixture().profile.catalog_binding
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        replace(binding, codec_profile="etzio.fixture.signed-anchor-receipt.v1")
    assert exc.value.reason_code == "invalid_head_codec_profile"


def test_profile_rejects_noncanonical_and_unknown_wire_fields() -> None:
    profile = _fixture().profile
    body = profile.to_body()
    body["unexpected"] = True
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        HeadAuthorityTrustProfileV1.from_canonical_bytes(
            __import__("json").dumps(body, sort_keys=True, separators=(",", ":")).encode()
        )
    assert exc.value.reason_code == "invalid_head_trust_profile"


def test_profile_rejects_a_foreign_contract_version() -> None:
    profile = _fixture().profile
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        replace(profile, contract_version=2)
    assert exc.value.reason_code == "invalid_head_profile_version"


def test_trust_key_requires_a_prime_subgroup_ed25519_key() -> None:
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        TrustedHeadAuthorityKeyV1(
            source_id="fixture.anchor.a",
            principal_id="fixture.anchor.a.principal",
            role=HEAD_ANCHOR_ADAPTER_ROLE_V1,
            public_key_bytes=bytes(32),
        )
    assert exc.value.reason_code == "invalid_head_public_key"


def test_binding_for_refuses_an_unknown_source_or_role() -> None:
    profile = _fixture().profile
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        profile.binding_for(role=HEAD_ANCHOR_ADAPTER_ROLE_V1, source_id="fixture.catalog")
    assert exc.value.reason_code == "head_source_mismatch"


# ---------------------------------------------------------------------------
# Byte-bound anchor registration leaf
# ---------------------------------------------------------------------------


def test_anchor_leaf_hash_is_the_domain_separated_hash_of_exact_record_bytes() -> None:
    leaf = AnchorRegistrationLeafV1(
        contract_version=HEAD_AUTHORITY_CONTRACT_VERSION_V1,
        service_instance_id="Etzio.head-authority-qualification-fixture",
        environment_id="fixture.networkless-control-plane",
        mission_id=_digest("mission"),
        instance_sequence=7,
        anchor_policy_id=_digest("anchor-policy"),
        anchor_statement_id=_digest("anchor-statement"),
    )
    assert leaf.leaf_hash == merkle_leaf_hash_v1(leaf.to_canonical_bytes())
    assert AnchorRegistrationLeafV1.from_canonical_bytes(
        leaf.to_canonical_bytes()
    ).to_body() == leaf.to_body()


def test_anchor_request_refuses_a_leaf_hash_that_is_not_its_own_record() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    request = _anchor_requests(fixture, bundle)["fixture.anchor.a"]
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        replace(request, anchor_leaf_hash=_digest("foreign-leaf"))
    assert exc.value.reason_code == "head_anchor_leaf_mismatch"


def test_anchor_request_identity_binds_its_complete_semantics() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    request = _anchor_requests(fixture, bundle)["fixture.anchor.a"]
    assert HeadAnchorRequestV1.from_canonical_bytes(
        request.to_canonical_bytes()
    ).request_id == request.request_id
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        replace(request, prior_tree_size=request.prior_tree_size + 1)
    assert exc.value.reason_code == "head_anchor_request_id_mismatch"


def test_catalog_request_identity_binds_its_complete_semantics() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    request = _catalog_requests(fixture, bundle)["fixture.catalog"]
    assert HeadCatalogRequestV1.from_canonical_bytes(
        request.to_canonical_bytes()
    ).request_id == request.request_id
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        replace(request, prior_instance_sequence=request.prior_instance_sequence + 1)
    assert exc.value.reason_code == "head_catalog_request_id_mismatch"


def test_catalog_request_refuses_a_mission_head_ahead_of_the_global_head() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    vector = fixture.vector
    head = vector.expected_head
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        HeadCatalogRequestV1.issue(
            profile=fixture.profile,
            source_id="fixture.catalog",
            evidence_role=HEAD_CATALOG_ADAPTER_ROLE_V1,
            mission_id=vector.mission_id,
            authority_id=vector.authority_id,
            target_id=vector.target_id,
            event_digest=vector.event_digest,
            transition_intent_id=vector.transition_intent_id,
            time_bundle=bundle,
            prior_tree_size=fixture.prior_tree_size,
            prior_log_root_hash=fixture.prior_log_root_hash,
            prior_instance_sequence=2,
            prior_checkpoint_id=head.prior_checkpoint_id,
            prior_mission_event_seq=5,
            prior_mission_checkpoint_id=head.prior_mission_checkpoint_id,
            request_nonce=vector.request_nonce,
        )
    assert exc.value.reason_code == "invalid_head_request"


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


def test_authentication_is_exact_retry_stable_and_retains_signed_wire() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    requests, signed = _anchor_inputs(fixture, bundle)
    package = authenticate_head_evidence_v1(
        profile=fixture.profile,
        request=requests["fixture.anchor.a"],
        signed_evidence=signed["fixture.anchor.a"],
    )
    assert package.provider_evidence.evidence_kind == HEAD_ANCHOR_RECEIPT_EVIDENCE_KIND
    assert package.provider_evidence.content == signed["fixture.anchor.a"].to_canonical_bytes()
    again = authenticate_head_evidence_v1(
        profile=fixture.profile,
        request=requests["fixture.anchor.a"],
        signed_evidence=signed["fixture.anchor.a"],
    )
    assert again.provider_evidence.evidence_id == package.provider_evidence.evidence_id


def test_authentication_rejects_cross_request_replay() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    requests, signed = _anchor_inputs(fixture, bundle)
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        authenticate_head_evidence_v1(
            profile=fixture.profile,
            request=requests["fixture.anchor.a"],
            signed_evidence=signed["fixture.anchor.b"],
        )
    assert exc.value.reason_code == "head_source_mismatch"


def test_authentication_rejects_a_resigned_foreign_request_binding() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    requests, signed = _anchor_inputs(fixture, bundle)
    package = authenticate_head_evidence_v1(
        profile=fixture.profile,
        request=requests["fixture.anchor.a"],
        signed_evidence=signed["fixture.anchor.a"],
    )
    forged = _anchor_signer(fixture, "fixture.anchor.a").sign(
        replace(package.statement, request_id=_digest("another-request"))
    )
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        authenticate_head_evidence_v1(
            profile=fixture.profile,
            request=requests["fixture.anchor.a"],
            signed_evidence=forged,
        )
    assert exc.value.reason_code == "head_request_mismatch"


def test_authentication_rejects_a_claimed_foreign_log_origin() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    requests, signed = _anchor_inputs(fixture, bundle)
    package = authenticate_head_evidence_v1(
        profile=fixture.profile,
        request=requests["fixture.anchor.a"],
        signed_evidence=signed["fixture.anchor.a"],
    )
    forged = _resign(
        _anchor_signer(fixture, "fixture.anchor.a"),
        package.statement,
        log_origin="fixture.anchor-log.b",
    )
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        authenticate_head_evidence_v1(
            profile=fixture.profile,
            request=requests["fixture.anchor.a"],
            signed_evidence=forged,
        )
    assert exc.value.reason_code == "head_log_origin_mismatch"


def test_authentication_rejects_a_receipt_for_another_anchor_statement() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    requests, signed = _anchor_inputs(fixture, bundle)
    package = authenticate_head_evidence_v1(
        profile=fixture.profile,
        request=requests["fixture.anchor.a"],
        signed_evidence=signed["fixture.anchor.a"],
    )
    forged = _resign(
        _anchor_signer(fixture, "fixture.anchor.a"),
        package.statement,
        anchor_statement_id=_digest("foreign-statement"),
    )
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        authenticate_head_evidence_v1(
            profile=fixture.profile,
            request=requests["fixture.anchor.a"],
            signed_evidence=forged,
        )
    assert exc.value.reason_code == "head_anchor_statement_mismatch"


def test_authentication_rejects_a_receipt_for_another_registration_leaf() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    requests, signed = _anchor_inputs(fixture, bundle)
    package = authenticate_head_evidence_v1(
        profile=fixture.profile,
        request=requests["fixture.anchor.a"],
        signed_evidence=signed["fixture.anchor.a"],
    )
    forged = _resign(
        _anchor_signer(fixture, "fixture.anchor.a"),
        package.statement,
        leaf_hash=_digest("foreign-leaf"),
    )
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        authenticate_head_evidence_v1(
            profile=fixture.profile,
            request=requests["fixture.anchor.a"],
            signed_evidence=forged,
        )
    assert exc.value.reason_code == "head_anchor_leaf_mismatch"


def test_authentication_rejects_an_invalid_signature() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    requests, signed = _anchor_inputs(fixture, bundle)
    package = signed["fixture.anchor.a"]
    broken = replace(package, signature_bytes=bytes(64))
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        authenticate_head_evidence_v1(
            profile=fixture.profile,
            request=requests["fixture.anchor.a"],
            signed_evidence=broken,
        )
    assert exc.value.reason_code == "head_signature_invalid"


def test_authentication_rejects_a_signature_domain_substitution() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    requests, signed = _anchor_inputs(fixture, bundle)
    package = authenticate_head_evidence_v1(
        profile=fixture.profile,
        request=requests["fixture.anchor.a"],
        signed_evidence=signed["fixture.anchor.a"],
    )
    signer = _anchor_signer(fixture, "fixture.anchor.a")
    cross_domain = HeadEvidenceSignerV1(
        source_id=signer.source_id,
        principal_id=signer.principal_id,
        role=HEAD_CATALOG_ADAPTER_ROLE_V1,
        private_key_bytes=signer.private_key_bytes,
    ).sign(replace(package.statement, evidence_role=HEAD_CATALOG_ADAPTER_ROLE_V1))
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        authenticate_head_evidence_v1(
            profile=fixture.profile,
            request=requests["fixture.anchor.a"],
            signed_evidence=cross_domain,
        )
    assert exc.value.reason_code == "head_role_mismatch"


def test_authentication_rejects_a_revoked_fixture_key() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    requests, signed = _anchor_inputs(fixture, bundle)
    profile = fixture.profile
    revoked_store = HeadAuthorityTrustStoreV1(
        keys=dict(profile.trust_store.keys),
        revoked_key_ids=frozenset(
            {
                profile.binding_for(
                    role=HEAD_ANCHOR_ADAPTER_ROLE_V1,
                    source_id="fixture.anchor.a",
                ).key_id
            }
        ),
    )
    revoked_profile = replace(
        profile,
        trust_store=revoked_store,
        trust_root_id=revoked_store.root_id,
    )
    vector = fixture.vector
    reissued = HeadAnchorRequestV1.issue(
        profile=revoked_profile,
        source_id="fixture.anchor.a",
        mission_id=vector.mission_id,
        authority_id=vector.authority_id,
        target_id=vector.target_id,
        event_digest=vector.event_digest,
        transition_intent_id=vector.transition_intent_id,
        anchor_statement_id=vector.anchor_statement_id,
        instance_sequence=vector.expected_head.instance_sequence,
        time_bundle=bundle,
        prior_tree_size=fixture.anchor_prior_tree_size,
        request_nonce=vector.request_nonce,
    )
    package = replace(
        signed["fixture.anchor.a"],
        statement_bytes=_anchor_signer(fixture, "fixture.anchor.a")
        .sign(
            replace(
                authenticate_head_evidence_v1(
                    profile=fixture.profile,
                    request=requests["fixture.anchor.a"],
                    signed_evidence=signed["fixture.anchor.a"],
                ).statement,
                profile_id=revoked_profile.profile_id,
                trust_root_id=revoked_profile.trust_root_id,
                request_id=reissued.request_id,
            )
        )
        .statement_bytes,
    )
    resigned = _anchor_signer(fixture, "fixture.anchor.a").sign(
        HeadProviderStatementV1.from_canonical_bytes(package.statement_bytes)
    )
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        authenticate_head_evidence_v1(
            profile=revoked_profile,
            request=reissued,
            signed_evidence=resigned,
        )
    assert exc.value.reason_code == "revoked_head_key"


def test_signed_evidence_rejects_noncanonical_or_malformed_wire() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    _, signed = _anchor_inputs(fixture, bundle)
    body = signed["fixture.anchor.a"].to_body()
    body["algorithm"] = "ed448"
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        SignedHeadEvidenceV1.from_canonical_bytes(
            __import__("json").dumps(body, sort_keys=True, separators=(",", ":")).encode()
        )
    assert exc.value.reason_code == "unsupported_head_algorithm"


def test_authenticated_package_direct_construction_is_refused() -> None:
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        AuthenticatedHeadEvidencePackageV1()
    assert exc.value.reason_code == "unauthenticated_head_result_construction"


# ---------------------------------------------------------------------------
# Anchor qualification
# ---------------------------------------------------------------------------


def test_anchor_qualification_is_deterministic_and_reauthenticates_exact_bytes() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    requests, signed = _anchor_inputs(fixture, bundle)
    qualified = qualify_anchor_bundle_v1(
        profile=fixture.profile,
        time_profile=fixture.time_fixture.profile,
        time_bundle=bundle,
        requests=requests,
        signed_evidence=signed,
    )
    assert qualified.anchor_statement_id == fixture.vector.anchor_statement_id
    assert len(qualified.evidence) == 2
    assert all(
        reference.evidence_kind == HEAD_ANCHOR_RECEIPT_EVIDENCE_KIND
        for reference in qualified.evidence
    )
    fresh = reauthenticate_anchor_bundle_v1(
        profile=fixture.profile,
        time_profile=fixture.time_fixture.profile,
        time_bundle=bundle,
        bundle=qualified,
    )
    assert fresh.to_body() == qualified.to_body()


def test_anchor_qualification_requires_the_exact_source_roster() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    requests, signed = _anchor_inputs(fixture, bundle)
    partial = {"fixture.anchor.a": signed["fixture.anchor.a"]}
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        qualify_anchor_bundle_v1(
            profile=fixture.profile,
            time_profile=fixture.time_fixture.profile,
            time_bundle=bundle,
            requests=requests,
            signed_evidence=partial,
        )
    assert exc.value.reason_code == "head_source_set_mismatch"


def test_anchor_qualification_rejects_an_unbound_time_hull() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    other = _time_bundle(create_repository_owned_head_authority_fixture_v1(seed=b"other-seed"))
    requests, signed = _anchor_inputs(fixture, bundle)
    with pytest.raises(ValueError) as exc:
        qualify_anchor_bundle_v1(
            profile=fixture.profile,
            time_profile=fixture.time_fixture.profile,
            time_bundle=other,
            requests=requests,
            signed_evidence=signed,
        )
    assert exc.value.reason_code in {
        "head_time_bundle_mismatch",
        "provider_root_mismatch",
        "provider_profile_mismatch",
    }


def test_anchor_qualification_rejects_a_forged_inclusion_proof() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    requests, signed = _anchor_inputs(fixture, bundle)
    package = authenticate_head_evidence_v1(
        profile=fixture.profile,
        request=requests["fixture.anchor.a"],
        signed_evidence=signed["fixture.anchor.a"],
    )
    forged = dict(signed)
    forged["fixture.anchor.a"] = _resign(
        _anchor_signer(fixture, "fixture.anchor.a"),
        package.statement,
        inclusion_proof=[_digest("forged-node")],
    )
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        qualify_anchor_bundle_v1(
            profile=fixture.profile,
            time_profile=fixture.time_fixture.profile,
            time_bundle=bundle,
            requests=requests,
            signed_evidence=forged,
        )
    assert exc.value.reason_code == "head_inclusion_proof_invalid"


def test_anchor_qualification_rejects_a_claimed_root_without_a_proof() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    requests, signed = _anchor_inputs(fixture, bundle)
    package = authenticate_head_evidence_v1(
        profile=fixture.profile,
        request=requests["fixture.anchor.a"],
        signed_evidence=signed["fixture.anchor.a"],
    )
    forged = dict(signed)
    forged["fixture.anchor.a"] = _resign(
        _anchor_signer(fixture, "fixture.anchor.a"),
        package.statement,
        log_root_hash=_digest("asserted-root"),
    )
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        qualify_anchor_bundle_v1(
            profile=fixture.profile,
            time_profile=fixture.time_fixture.profile,
            time_bundle=bundle,
            requests=requests,
            signed_evidence=forged,
        )
    assert exc.value.reason_code == "head_inclusion_proof_invalid"


def test_anchor_qualification_rejects_a_tree_size_below_the_retained_predecessor() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    requests = _anchor_requests(fixture, bundle, prior_tree_size=99)
    signed = {
        adapter.source_id: adapter.acquire(requests[adapter.source_id])
        for adapter in fixture.anchor_adapters
    }
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        qualify_anchor_bundle_v1(
            profile=fixture.profile,
            time_profile=fixture.time_fixture.profile,
            time_bundle=bundle,
            requests=requests,
            signed_evidence=signed,
        )
    assert exc.value.reason_code == "head_anchor_tree_rollback"


@pytest.mark.parametrize(
    ("offset", "expected"),
    [
        (60, "head_publication_not_established"),
        (-10_000, "head_evidence_stale"),
    ],
)
def test_anchor_qualification_enforces_half_open_freshness(
    offset: int,
    expected: str,
) -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    requests, signed = _anchor_inputs(fixture, bundle)
    package = authenticate_head_evidence_v1(
        profile=fixture.profile,
        request=requests["fixture.anchor.a"],
        signed_evidence=signed["fixture.anchor.a"],
    )
    forged = dict(signed)
    forged["fixture.anchor.a"] = _resign(
        _anchor_signer(fixture, "fixture.anchor.a"),
        package.statement,
        registered_at=fixture.vector.expected_epoch_second + offset,
    )
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        qualify_anchor_bundle_v1(
            profile=fixture.profile,
            time_profile=fixture.time_fixture.profile,
            time_bundle=bundle,
            requests=requests,
            signed_evidence=forged,
        )
    assert exc.value.reason_code == expected


def test_qualified_anchor_direct_construction_is_refused() -> None:
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        QualifiedAnchorBundleV1()
    assert exc.value.reason_code == "unauthenticated_head_result_construction"


# ---------------------------------------------------------------------------
# Catalog and monitor qualification
# ---------------------------------------------------------------------------


def test_catalog_qualification_produces_an_admissible_external_head_floor() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    requests, signed = _catalog_inputs(fixture, bundle)
    qualified = qualify_head_catalog_bundle_v1(
        profile=fixture.profile,
        time_profile=fixture.time_fixture.profile,
        time_bundle=bundle,
        requests=requests,
        signed_evidence=signed,
    )
    floor = qualified.external_floor
    assert floor.instance_sequence == fixture.vector.expected_head.instance_sequence
    assert floor.mission_event_seq == fixture.vector.expected_head.mission_event_seq
    assert len(floor.evidence) == 3
    assert all(
        reference.evidence_kind == EXTERNAL_FLOOR_EVIDENCE_KIND
        for reference in floor.evidence
    )
    fresh = reauthenticate_head_catalog_bundle_v1(
        profile=fixture.profile,
        time_profile=fixture.time_fixture.profile,
        time_bundle=bundle,
        bundle=qualified,
    )
    assert fresh.to_body() == qualified.to_body()


def test_catalog_qualification_requires_every_monitor() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    requests, signed = _catalog_inputs(fixture, bundle)
    reduced = {
        source_id: package
        for source_id, package in signed.items()
        if source_id != "fixture.monitor.b"
    }
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        qualify_head_catalog_bundle_v1(
            profile=fixture.profile,
            time_profile=fixture.time_fixture.profile,
            time_bundle=bundle,
            requests=requests,
            signed_evidence=reduced,
        )
    assert exc.value.reason_code == "head_source_set_mismatch"


def test_catalog_qualification_rejects_a_forged_consistency_proof() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    requests, signed = _catalog_inputs(fixture, bundle)
    package = authenticate_head_evidence_v1(
        profile=fixture.profile,
        request=requests["fixture.catalog"],
        signed_evidence=signed["fixture.catalog"],
    )
    forged = dict(signed)
    forged["fixture.catalog"] = _resign(
        fixture.catalog_adapter.signer,
        package.statement,
        consistency_proof=[_digest("forged-node")],
    )
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        qualify_head_catalog_bundle_v1(
            profile=fixture.profile,
            time_profile=fixture.time_fixture.profile,
            time_bundle=bundle,
            requests=requests,
            signed_evidence=forged,
        )
    assert exc.value.reason_code == "head_consistency_proof_invalid"


def test_catalog_qualification_rejects_an_equal_size_root_change() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    requests = _catalog_requests(
        fixture,
        bundle,
        prior_tree_size=len(fixture.catalog_adapter.leaf_hashes),
    )
    adapters = _catalog_sources(fixture)
    signed = {
        source_id: adapter.acquire(requests[source_id])  # type: ignore[union-attr]
        for source_id, adapter in adapters.items()
    }
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        qualify_head_catalog_bundle_v1(
            profile=fixture.profile,
            time_profile=fixture.time_fixture.profile,
            time_bundle=bundle,
            requests=requests,
            signed_evidence=signed,
        )
    assert exc.value.reason_code == "head_catalog_equivocation"


def test_catalog_qualification_rejects_a_monitor_split_view() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    requests, signed = _catalog_inputs(fixture, bundle)
    monitor = fixture.monitor_adapters[0]
    split = RepositoryOwnedDeterministicHeadMonitorAdapterV1(
        profile=monitor.profile,
        binding=monitor.binding,
        signer=monitor.signer,
        leaf_hashes=(*fixture.catalog_adapter.leaf_hashes, hashlib.sha256(b"split").digest()),
        witnessed_source_id=monitor.witnessed_source_id,
        observed_at=monitor.observed_at,
    )
    forged = dict(signed)
    forged[monitor.source_id] = split.acquire(requests[monitor.source_id])
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        qualify_head_catalog_bundle_v1(
            profile=fixture.profile,
            time_profile=fixture.time_fixture.profile,
            time_bundle=bundle,
            requests=requests,
            signed_evidence=forged,
        )
    assert exc.value.reason_code == "head_catalog_equivocation"


def test_catalog_qualification_rejects_a_monitor_witnessing_another_source() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    requests, signed = _catalog_inputs(fixture, bundle)
    monitor = fixture.monitor_adapters[0]
    package = authenticate_head_evidence_v1(
        profile=fixture.profile,
        request=requests[monitor.source_id],
        signed_evidence=signed[monitor.source_id],
    )
    forged = dict(signed)
    forged[monitor.source_id] = _resign(
        monitor.signer,
        package.statement,
        witnessed_source_id="fixture.monitor.b",
    )
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        qualify_head_catalog_bundle_v1(
            profile=fixture.profile,
            time_profile=fixture.time_fixture.profile,
            time_bundle=bundle,
            requests=requests,
            signed_evidence=forged,
        )
    assert exc.value.reason_code == "head_monitor_witness_mismatch"


def test_catalog_qualification_rejects_a_regressing_instance_head() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    requests, signed = _catalog_inputs(fixture, bundle)
    package = authenticate_head_evidence_v1(
        profile=fixture.profile,
        request=requests["fixture.catalog"],
        signed_evidence=signed["fixture.catalog"],
    )
    forged = dict(signed)
    forged["fixture.catalog"] = _resign(
        fixture.catalog_adapter.signer,
        package.statement,
        instance_sequence=1,
        mission_event_seq=1,
    )
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        qualify_head_catalog_bundle_v1(
            profile=fixture.profile,
            time_profile=fixture.time_fixture.profile,
            time_bundle=bundle,
            requests=requests,
            signed_evidence=forged,
        )
    assert exc.value.reason_code == "head_catalog_head_rollback"


def test_catalog_qualification_rejects_a_mission_head_above_the_global_head() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    requests, signed = _catalog_inputs(fixture, bundle)
    package = authenticate_head_evidence_v1(
        profile=fixture.profile,
        request=requests["fixture.catalog"],
        signed_evidence=signed["fixture.catalog"],
    )
    forged = dict(signed)
    forged["fixture.catalog"] = _resign(
        fixture.catalog_adapter.signer,
        package.statement,
        mission_event_seq=9,
    )
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        qualify_head_catalog_bundle_v1(
            profile=fixture.profile,
            time_profile=fixture.time_fixture.profile,
            time_bundle=bundle,
            requests=requests,
            signed_evidence=forged,
        )
    assert exc.value.reason_code == "head_catalog_floor_invalid"


def test_catalog_qualification_rejects_a_stale_publication() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    requests, signed = _catalog_inputs(fixture, bundle)
    package = authenticate_head_evidence_v1(
        profile=fixture.profile,
        request=requests["fixture.catalog"],
        signed_evidence=signed["fixture.catalog"],
    )
    forged = dict(signed)
    forged["fixture.catalog"] = _resign(
        fixture.catalog_adapter.signer,
        package.statement,
        published_at=fixture.vector.expected_epoch_second - 10_000,
    )
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        qualify_head_catalog_bundle_v1(
            profile=fixture.profile,
            time_profile=fixture.time_fixture.profile,
            time_bundle=bundle,
            requests=requests,
            signed_evidence=forged,
        )
    assert exc.value.reason_code == "head_evidence_stale"


def test_catalog_qualification_rejects_a_catalog_package_in_a_monitor_slot() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    requests, signed = _catalog_inputs(fixture, bundle)
    forged = dict(signed)
    forged["fixture.monitor.a"] = signed["fixture.catalog"]
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        qualify_head_catalog_bundle_v1(
            profile=fixture.profile,
            time_profile=fixture.time_fixture.profile,
            time_bundle=bundle,
            requests=requests,
            signed_evidence=forged,
        )
    assert exc.value.reason_code in {"head_role_mismatch", "head_source_mismatch"}


def test_qualified_catalog_direct_construction_is_refused() -> None:
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        QualifiedHeadCatalogBundleV1()
    assert exc.value.reason_code == "unauthenticated_head_result_construction"


# ---------------------------------------------------------------------------
# Provider-neutral mapping
# ---------------------------------------------------------------------------


def test_mapping_covers_every_retained_signed_blob_exactly() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    anchor_requests, anchor_signed = _anchor_inputs(fixture, bundle)
    catalog_requests, catalog_signed = _catalog_inputs(fixture, bundle)
    anchor_bundle = qualify_anchor_bundle_v1(
        profile=fixture.profile,
        time_profile=fixture.time_fixture.profile,
        time_bundle=bundle,
        requests=anchor_requests,
        signed_evidence=anchor_signed,
    )
    catalog_bundle = qualify_head_catalog_bundle_v1(
        profile=fixture.profile,
        time_profile=fixture.time_fixture.profile,
        time_bundle=bundle,
        requests=catalog_requests,
        signed_evidence=catalog_signed,
    )
    mapping = map_qualified_head_authority_inputs_v1(
        profile=fixture.profile,
        time_profile=fixture.time_fixture.profile,
        time_bundle=bundle,
        anchor_bundle=anchor_bundle,
        catalog_bundle=catalog_bundle,
    )
    retained = {(blob.source_id, blob.evidence_id) for blob in mapping.evidence_blobs}
    mapped = {
        (reference.source_id, reference.evidence_id)
        for reference in mapping.anchor_evidence
    } | {
        (reference.source_id, reference.evidence_id)
        for reference in mapping.external_floor.evidence
    }
    assert mapped == retained
    assert len(mapping.evidence_blobs) == 5
    assert mapping.anchor_statement_id == fixture.vector.anchor_statement_id
    assert mapping.anchor_policy_id == fixture.profile.validation_policy.anchor_policy_id


def test_mapping_refuses_a_directly_constructed_evidence_reference() -> None:
    reference = EvidenceReferenceV1(
        evidence_kind=HEAD_ANCHOR_RECEIPT_EVIDENCE_KIND,
        source_id="fixture.anchor.a",
        evidence_id=_digest("claimed"),
    )
    assert reference.evidence_kind == HEAD_ANCHOR_RECEIPT_EVIDENCE_KIND
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        QualifiedHeadAuthorityInputsV1()
    assert exc.value.reason_code == "unauthenticated_head_result_construction"


def test_mapping_refuses_bundles_from_different_time_hulls() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    anchor_requests, anchor_signed = _anchor_inputs(fixture, bundle)
    catalog_requests, catalog_signed = _catalog_inputs(fixture, bundle)
    anchor_bundle = qualify_anchor_bundle_v1(
        profile=fixture.profile,
        time_profile=fixture.time_fixture.profile,
        time_bundle=bundle,
        requests=anchor_requests,
        signed_evidence=anchor_signed,
    )
    catalog_bundle = qualify_head_catalog_bundle_v1(
        profile=fixture.profile,
        time_profile=fixture.time_fixture.profile,
        time_bundle=bundle,
        requests=catalog_requests,
        signed_evidence=catalog_signed,
    )
    other = _time_bundle(create_repository_owned_head_authority_fixture_v1(seed=b"other-seed"))
    with pytest.raises(ValueError):
        map_qualified_head_authority_inputs_v1(
            profile=fixture.profile,
            time_profile=fixture.time_fixture.profile,
            time_bundle=other,
            anchor_bundle=anchor_bundle,
            catalog_bundle=catalog_bundle,
        )


# ---------------------------------------------------------------------------
# Deterministic harness
# ---------------------------------------------------------------------------


def test_repository_harness_qualifies_every_ordered_case() -> None:
    report = qualify_repository_head_authority_adapters_v1(_fixture())
    assert report.passed
    assert report.overall_disposition == "qualified"
    assert len(report.cases) == 9
    assert [case.case_id for case in report.cases] == [
        "anchor_registration_qualifies",
        "anchor_exact_retry_is_byte_stable",
        "anchor_cross_request_replay_refused",
        "anchor_foreign_statement_receipt_refused",
        "catalog_head_qualifies",
        "catalog_exact_retry_is_byte_stable",
        "catalog_tree_rollback_refused",
        "monitor_split_view_refused",
        "provider_neutral_mapping_complete",
    ]
    assert [case.observed_disposition for case in report.cases] == [
        "qualified",
        "qualified",
        "refused",
        "refused",
        "qualified",
        "qualified",
        "refused",
        "refused",
        "qualified",
    ]


def test_repository_harness_is_byte_identical_across_runs() -> None:
    first = qualify_repository_head_authority_adapters_v1(_fixture())
    second = qualify_repository_head_authority_adapters_v1(_fixture())
    assert first.report_id == second.report_id
    assert first.to_body() == second.to_body()


def test_corpus_manifest_binds_every_outcome_affecting_input() -> None:
    fixture = _fixture()
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        replace(fixture, prior_tree_size=3)
    assert exc.value.reason_code == "invalid_head_qualification_fixture"
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        replace(fixture, corpus_manifest_id=_digest("substituted-manifest"))
    assert exc.value.reason_code == "head_qualification_manifest_mismatch"


def test_fixture_refuses_reordered_or_duplicated_adapters() -> None:
    fixture = _fixture()
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        replace(fixture, anchor_adapters=tuple(reversed(fixture.anchor_adapters)))
    assert exc.value.reason_code == "invalid_head_fixture_adapter"
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        replace(
            fixture,
            monitor_adapters=(fixture.monitor_adapters[0], fixture.monitor_adapters[0]),
        )
    assert exc.value.reason_code == "invalid_head_fixture_adapter"


def test_fixture_refuses_a_retained_root_that_is_not_its_own_prefix() -> None:
    fixture = _fixture()
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        replace(fixture, prior_log_root_hash=_digest("unrelated-root"))
    assert exc.value.reason_code == "invalid_head_qualification_fixture"


def test_qualification_report_direct_construction_is_refused() -> None:
    with pytest.raises(HeadAuthorityAdapterError) as exc:
        HeadAuthorityQualificationReportV1()
    assert exc.value.reason_code == "unauthenticated_head_result_construction"


def test_harness_has_no_clock_or_network_dependency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _no_clock(*_args: object, **_kwargs: object) -> float:
        raise AssertionError("head-authority qualification must not read an ambient clock")

    def _no_socket(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("head-authority qualification must not open a socket")

    monkeypatch.setattr(time, "time", _no_clock)
    monkeypatch.setattr(time, "time_ns", _no_clock)
    monkeypatch.setattr(socket, "socket", _no_socket)
    monkeypatch.setattr(socket, "create_connection", _no_socket)
    report = qualify_repository_head_authority_adapters_v1(_fixture())
    assert report.passed


def test_fixture_builds_genuine_merkle_trees_not_constant_proofs() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    requests, signed = _anchor_inputs(fixture, bundle)
    package = authenticate_head_evidence_v1(
        profile=fixture.profile,
        request=requests["fixture.anchor.a"],
        signed_evidence=signed["fixture.anchor.a"],
    )
    claim = package.claim
    adapter = fixture.anchor_adapters[0]
    leaves = (
        *adapter.prefix_leaf_hashes,
        merkle_leaf_hash_v1(
            AnchorRegistrationLeafV1(
                contract_version=HEAD_AUTHORITY_CONTRACT_VERSION_V1,
                service_instance_id=fixture.profile.service_instance_id,
                environment_id=fixture.profile.environment_id,
                mission_id=fixture.vector.mission_id,
                instance_sequence=fixture.vector.expected_head.instance_sequence,
                anchor_policy_id=fixture.profile.validation_policy.anchor_policy_id,
                anchor_statement_id=fixture.vector.anchor_statement_id,
            ).to_canonical_bytes()
        ),
        *adapter.suffix_leaf_hashes,
    )
    assert claim["tree_size"] == len(leaves)
    assert claim["leaf_index"] == len(adapter.prefix_leaf_hashes)
    assert claim["log_root_hash"] == "sha256:" + merkle_root_v1(leaves).hex()
    assert len(claim["inclusion_proof"]) == 2


def test_two_anchor_logs_have_independent_roots() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    requests, signed = _anchor_inputs(fixture, bundle)
    qualified = qualify_anchor_bundle_v1(
        profile=fixture.profile,
        time_profile=fixture.time_fixture.profile,
        time_bundle=bundle,
        requests=requests,
        signed_evidence=signed,
    )
    roots = dict(qualified.log_roots)
    assert set(roots) == {"fixture.anchor-log.a", "fixture.anchor-log.b"}
    assert len(set(roots.values())) == 2


def test_validation_policy_anchor_identity_flows_into_every_request() -> None:
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    policy = fixture.profile.validation_policy
    assert isinstance(policy, IntegrityValidationPolicyV1)
    for request in _anchor_requests(fixture, bundle).values():
        assert request.anchor_policy_id == policy.anchor_policy_id


def test_source_binding_evidence_kinds_close_the_remaining_integrity_kinds() -> None:
    profile = _fixture().profile
    kinds = {binding.role: binding.evidence_kind for binding in profile.source_bindings}
    assert kinds[HEAD_ANCHOR_ADAPTER_ROLE_V1] == HEAD_ANCHOR_RECEIPT_EVIDENCE_KIND
    assert kinds[HEAD_CATALOG_ADAPTER_ROLE_V1] == EXTERNAL_FLOOR_EVIDENCE_KIND
    assert kinds[HEAD_MONITOR_ADAPTER_ROLE_V1] == EXTERNAL_FLOOR_EVIDENCE_KIND


def test_head_source_bindings_are_canonically_ordered() -> None:
    profile = _fixture().profile
    observed = tuple(
        (binding.role, binding.source_id) for binding in profile.source_bindings
    )
    assert observed == tuple(sorted(observed))


def test_fixture_source_binding_lookup_is_role_scoped() -> None:
    profile = _fixture().profile
    binding = profile.binding_for(
        role=HEAD_MONITOR_ADAPTER_ROLE_V1,
        source_id="fixture.monitor.a",
    )
    assert isinstance(binding, HeadAuthoritySourceBindingV1)
    assert binding.log_origin == profile.catalog_binding.log_origin
