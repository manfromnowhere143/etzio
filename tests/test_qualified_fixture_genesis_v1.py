"""Qualified genesis observations require exact genesis identities and absent provenance."""

from dataclasses import replace

import pytest
from test_catalog_projection_composition_v1 import _packages_with_leaves, _requests_with_predecessor
from test_head_authority_qualification_v1 import _catalog_inputs, _fixture, _time_bundle

from etzio.integrity_v1 import head_checkpoint_genesis_id, mission_checkpoint_genesis_id
from etzio.kernel.head_authority_adapters_v1 import (
    HeadAuthorityAdapterError,
    catalog_projection_leaf_bytes_v1,
    merkle_leaf_hash_v1,
    qualify_head_catalog_bundle_v1,
)
from etzio.protocol import content_id


def _genesis_head(fixture, *, global_genesis=True):
    profile = fixture.profile
    changes = dict(
        prior_mission_event_seq=-1,
        mission_event_seq=-1,
        prior_mission_checkpoint_id=mission_checkpoint_genesis_id(
            service_instance_id=profile.service_instance_id,
            environment_id=profile.environment_id,
            mission_id=fixture.vector.mission_id,
        ),
        mission_checkpoint_attestation_id=None,
        mission_checkpoint_principal_id=None,
        mission_checkpoint_trust_snapshot_id=None,
    )
    changes["mission_checkpoint_id"] = changes["prior_mission_checkpoint_id"]
    if global_genesis:
        changes.update(
            prior_instance_sequence=-1,
            instance_sequence=-1,
            prior_checkpoint_id=head_checkpoint_genesis_id(
                service_instance_id=profile.service_instance_id,
                environment_id=profile.environment_id,
            ),
            checkpoint_attestation_id=None,
            checkpoint_principal_id=None,
            checkpoint_trust_snapshot_id=None,
        )
        changes["checkpoint_id"] = changes["prior_checkpoint_id"]
    return replace(fixture.vector.expected_head, **changes)


def _qualify_genesis(fixture, head, *, request_head=None):
    time = _time_bundle(fixture)
    requests, _ = _catalog_inputs(fixture, time)
    leaves = (
        *fixture.catalog_adapter.leaf_hashes[:-1],
        merkle_leaf_hash_v1(
            catalog_projection_leaf_bytes_v1(profile=fixture.profile, mission_id=fixture.vector.mission_id, head=head)
        ),
    )
    requests = _requests_with_predecessor(
        requests, leaves=leaves, size=fixture.prior_tree_size, head=request_head or head
    )
    signed = _packages_with_leaves(fixture, requests, leaves, head=head)
    return qualify_head_catalog_bundle_v1(
        profile=fixture.profile,
        time_profile=fixture.time_fixture.profile,
        time_bundle=time,
        requests=requests,
        signed_evidence=signed,
    )


@pytest.mark.parametrize("global_genesis", [False, True])
def test_signed_genesis_projection_qualifies_with_exact_identity(global_genesis):
    fixture = _fixture()
    head = _genesis_head(fixture, global_genesis=global_genesis)
    bundle = _qualify_genesis(fixture, head)
    assert bundle.external_floor.mission_event_seq == -1
    assert bundle.external_floor.mission_checkpoint_id == head.mission_checkpoint_id
    assert bundle.external_floor.instance_sequence == head.instance_sequence


@pytest.mark.parametrize(
    "field",
    [
        "checkpoint_attestation_id",
        "checkpoint_principal_id",
        "checkpoint_trust_snapshot_id",
        "mission_checkpoint_attestation_id",
        "mission_checkpoint_principal_id",
        "mission_checkpoint_trust_snapshot_id",
    ],
)
def test_signed_genesis_cannot_claim_checkpoint_attestation_provenance(field):
    fixture = _fixture()
    value = "fixture.invented-principal" if "principal" in field else content_id("invented_provenance", {})
    head = replace(_genesis_head(fixture), **{field: value})
    with pytest.raises(HeadAuthorityAdapterError, match="admissible external head floor"):
        _qualify_genesis(fixture, head)


@pytest.mark.parametrize("field", ["checkpoint_id", "mission_checkpoint_id"])
def test_a_signed_genesis_cannot_replace_its_domain_separated_identity(field):
    fixture = _fixture()
    original = _genesis_head(fixture)
    head = replace(original, **{field: content_id("invented_genesis", {"field": field})})
    with pytest.raises(HeadAuthorityAdapterError):
        _qualify_genesis(fixture, head, request_head=original)


@pytest.mark.parametrize("sequence", [-2, False])
def test_genesis_does_not_admit_other_negative_or_boolean_sequences(sequence):
    with pytest.raises(HeadAuthorityAdapterError):
        replace(_genesis_head(_fixture()), instance_sequence=sequence)
