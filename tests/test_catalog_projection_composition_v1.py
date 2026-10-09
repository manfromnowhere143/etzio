"""A catalog signer cannot substitute checkpoint projections under an unchanged witnessed root."""

from dataclasses import replace

import pytest
from test_head_authority_qualification_v1 import _catalog_inputs, _catalog_sources, _fixture, _time_bundle

from etzio.kernel.head_authority_adapters_v1 import (
    HeadAuthorityAdapterError,
    HeadProviderStatementV1,
    catalog_projection_leaf_bytes_v1,
    merkle_inclusion_proof_v1,
    merkle_leaf_hash_v1,
    merkle_root_v1,
    qualify_head_catalog_bundle_v1,
)
from etzio.protocol import content_id, thaw_json


@pytest.mark.parametrize(
    "field",
    [
        "instance_sequence",
        "checkpoint_id",
        "checkpoint_attestation_id",
        "checkpoint_principal_id",
        "checkpoint_trust_snapshot_id",
        "mission_event_seq",
        "mission_checkpoint_id",
        "mission_checkpoint_attestation_id",
        "mission_checkpoint_principal_id",
        "mission_checkpoint_trust_snapshot_id",
    ],
)
def test_resigned_projection_must_belong_to_the_witnessed_tree(field):
    fixture = _fixture()
    time = _time_bundle(fixture)
    requests, signed = _catalog_inputs(fixture, time)
    original = qualify_head_catalog_bundle_v1(
        profile=fixture.profile,
        time_profile=fixture.time_fixture.profile,
        time_bundle=time,
        requests=requests,
        signed_evidence=signed,
    )
    source = fixture.catalog_adapter.source_id
    statement = HeadProviderStatementV1.from_canonical_bytes(signed[source].statement_bytes)
    claim = thaw_json(statement.claim)
    if field in {"instance_sequence", "mission_event_seq"}:
        claim[field] += 1
    elif "principal" in field:
        claim[field] = "fixture.other-checkpoint-principal"
    else:
        claim[field] = content_id("foreign_catalog_projection", {"field": field})
    signed[source] = fixture.catalog_adapter.signer.sign(replace(statement, claim=claim))
    assert claim["log_root_hash"] == original.log_root_hash
    assert claim["tree_size"] == original.tree_size
    with pytest.raises(HeadAuthorityAdapterError, match="projection|inclusion"):
        qualify_head_catalog_bundle_v1(
            profile=fixture.profile,
            time_profile=fixture.time_fixture.profile,
            time_bundle=time,
            requests=requests,
            signed_evidence=signed,
        )


@pytest.mark.parametrize("kind", ["global", "mission"])
def test_same_checkpoint_sequence_cannot_replace_the_retained_identity(kind):
    fixture = _fixture()
    time = _time_bundle(fixture)
    requests, _ = _catalog_inputs(fixture, time)
    expected = fixture.vector.expected_head
    changes = (
        {
            "prior_instance_sequence": expected.instance_sequence,
            "prior_checkpoint_id": content_id("foreign_predecessor", {}),
        }
        if kind == "global"
        else {
            "prior_mission_event_seq": expected.mission_event_seq,
            "prior_mission_checkpoint_id": content_id("foreign_predecessor", {}),
        }
    )
    changed = {}
    for source, request in requests.items():
        body = request.to_body()
        del body["request_id"]
        body.update(changes)
        changed[source] = replace(request, **changes, request_id=content_id("head_catalog_adapter_request", body))
    signed = {source: adapter.acquire(changed[source]) for source, adapter in _catalog_sources(fixture).items()}
    with pytest.raises(HeadAuthorityAdapterError, match="checkpoint|head") as error:
        qualify_head_catalog_bundle_v1(
            profile=fixture.profile,
            time_profile=fixture.time_fixture.profile,
            time_bundle=time,
            requests=changed,
            signed_evidence=signed,
        )
    assert error.value.reason_code == "head_catalog_checkpoint_equivocation"


@pytest.mark.parametrize("damage", ["missing", "empty", "truncated", "padded", "tampered", "reversed"])
def test_signed_projection_proof_damage_is_refused(damage):
    fixture = _fixture()
    time = _time_bundle(fixture)
    requests, signed = _catalog_inputs(fixture, time)
    source = fixture.catalog_adapter.source_id
    statement = HeadProviderStatementV1.from_canonical_bytes(signed[source].statement_bytes)
    claim = thaw_json(statement.claim)
    proof = claim["projection_inclusion_proof"]
    if damage == "missing":
        del claim["projection_inclusion_proof"]
    elif damage == "empty":
        claim["projection_inclusion_proof"] = []
    elif damage == "truncated":
        claim["projection_inclusion_proof"] = proof[:-1]
    elif damage == "padded":
        claim["projection_inclusion_proof"] = [*proof, proof[0]]
    elif damage == "tampered":
        claim["projection_inclusion_proof"] = [content_id("tampered_node", {}), *proof[1:]]
    else:
        claim["projection_inclusion_proof"] = list(reversed(proof))
    signed[source] = fixture.catalog_adapter.signer.sign(replace(statement, claim=claim))
    with pytest.raises(HeadAuthorityAdapterError):
        qualify_head_catalog_bundle_v1(
            profile=fixture.profile,
            time_profile=fixture.time_fixture.profile,
            time_bundle=time,
            requests=requests,
            signed_evidence=signed,
        )


def _requests_with_predecessor(requests, *, leaves, size, head=None):
    changes = {"prior_tree_size": size, "prior_log_root_hash": "sha256:" + merkle_root_v1(leaves[:size]).hex()}
    if head is not None:
        changes.update(
            prior_instance_sequence=head.instance_sequence,
            prior_checkpoint_id=head.checkpoint_id,
            prior_mission_event_seq=head.mission_event_seq,
            prior_mission_checkpoint_id=head.mission_checkpoint_id,
        )
    changed = {}
    for source, request in requests.items():
        body = request.to_body()
        del body["request_id"]
        body.update(changes)
        changed[source] = replace(request, **changes, request_id=content_id("head_catalog_adapter_request", body))
    return changed


def _packages_with_leaves(fixture, requests, leaves, *, head=None):
    adapters = _catalog_sources(fixture)
    catalog = fixture.catalog_adapter.source_id
    adapters[catalog] = replace(adapters[catalog], head=head or fixture.vector.expected_head)
    return {
        source: replace(adapter, leaf_hashes=leaves).acquire(requests[source]) for source, adapter in adapters.items()
    }


def test_a_valid_inclusion_proof_for_a_non_last_projection_is_refused():
    fixture = _fixture()
    time = _time_bundle(fixture)
    requests, _ = _catalog_inputs(fixture, time)
    original = fixture.catalog_adapter.leaf_hashes
    leaves = (original[-1], *original[:-1])
    requests = _requests_with_predecessor(requests, leaves=leaves, size=1)
    signed = _packages_with_leaves(fixture, requests, leaves)
    source = fixture.catalog_adapter.source_id
    statement = HeadProviderStatementV1.from_canonical_bytes(signed[source].statement_bytes)
    claim = thaw_json(statement.claim)
    claim["projection_inclusion_proof"] = ["sha256:" + node.hex() for node in merkle_inclusion_proof_v1(leaves, 0)]
    signed[source] = fixture.catalog_adapter.signer.sign(replace(statement, claim=claim))
    with pytest.raises(HeadAuthorityAdapterError, match="inclusion"):
        qualify_head_catalog_bundle_v1(
            profile=fixture.profile,
            time_profile=fixture.time_fixture.profile,
            time_bundle=time,
            requests=requests,
            signed_evidence=signed,
        )


def test_catalog_projection_can_advance_with_a_real_append_proof():
    fixture = _fixture()
    time = _time_bundle(fixture)
    requests, _ = _catalog_inputs(fixture, time)
    previous = fixture.vector.expected_head
    head = replace(
        previous,
        instance_sequence=previous.instance_sequence + 1,
        checkpoint_id=content_id("successor_global", {}),
        mission_event_seq=previous.mission_event_seq + 1,
        mission_checkpoint_id=content_id("successor_mission", {}),
    )
    original = fixture.catalog_adapter.leaf_hashes
    leaves = (
        *original,
        merkle_leaf_hash_v1(
            catalog_projection_leaf_bytes_v1(profile=fixture.profile, mission_id=fixture.vector.mission_id, head=head)
        ),
    )
    requests = _requests_with_predecessor(requests, leaves=original, size=len(original), head=previous)
    signed = _packages_with_leaves(fixture, requests, leaves, head=head)
    result = qualify_head_catalog_bundle_v1(
        profile=fixture.profile,
        time_profile=fixture.time_fixture.profile,
        time_bundle=time,
        requests=requests,
        signed_evidence=signed,
    )
    assert result.tree_size == len(original) + 1
    assert result.external_floor.checkpoint_id == head.checkpoint_id
    assert result.external_floor.mission_checkpoint_id == head.mission_checkpoint_id


def test_exact_current_projection_reconciles_without_tree_growth():
    fixture = _fixture()
    time = _time_bundle(fixture)
    requests, _ = _catalog_inputs(fixture, time)
    leaves = fixture.catalog_adapter.leaf_hashes
    requests = _requests_with_predecessor(requests, leaves=leaves, size=len(leaves), head=fixture.vector.expected_head)
    first = _packages_with_leaves(fixture, requests, leaves)
    assert first == _packages_with_leaves(fixture, requests, leaves)
    result = qualify_head_catalog_bundle_v1(
        profile=fixture.profile,
        time_profile=fixture.time_fixture.profile,
        time_bundle=time,
        requests=requests,
        signed_evidence=first,
    )
    assert result.tree_size == len(leaves)
    assert result.log_root_hash == "sha256:" + merkle_root_v1(leaves).hex()


def test_legacy_catalog_codec_is_refused():
    with pytest.raises(HeadAuthorityAdapterError):
        replace(_fixture().profile.catalog_binding, codec_profile="etzio.fixture.signed-head-catalog.v1")


def test_a_witnessed_leaf_for_another_exact_profile_is_refused():
    fixture = _fixture()
    time = _time_bundle(fixture)
    requests, _ = _catalog_inputs(fixture, time)
    foreign = replace(fixture.profile, max_head_staleness_seconds=fixture.profile.max_head_staleness_seconds + 1)
    leaf = merkle_leaf_hash_v1(
        catalog_projection_leaf_bytes_v1(
            profile=foreign,
            mission_id=fixture.vector.mission_id,
            head=fixture.vector.expected_head,
        )
    )
    leaves = (*fixture.catalog_adapter.leaf_hashes[:-1], leaf)
    signed = _packages_with_leaves(fixture, requests, leaves)
    with pytest.raises(HeadAuthorityAdapterError, match="inclusion"):
        qualify_head_catalog_bundle_v1(
            profile=fixture.profile,
            time_profile=fixture.time_fixture.profile,
            time_bundle=time,
            requests=requests,
            signed_evidence=signed,
        )
