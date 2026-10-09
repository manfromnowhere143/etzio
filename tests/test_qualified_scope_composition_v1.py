"""Valid provider signatures must still bind the exact consuming transition."""

from dataclasses import fields, replace

import pytest
from test_head_authority_qualification_v1 import (
    _anchor_requests,
    _catalog_requests,
    _catalog_sources,
    _fixture,
    _time_bundle,
)
from test_integrity_adapter_qualification_v1 import _fixture_time_bundle, _revocation_inputs

from etzio.kernel.head_authority_adapters_v1 import (
    HeadAuthorityAdapterError,
    qualify_anchor_bundle_v1,
    qualify_head_catalog_bundle_v1,
)
from etzio.kernel.integrity_adapters_v1 import IntegrityAdapterError, qualify_revocation_bundle_v1
from etzio.kernel.qualified_evidence_v1 import qualified_decision_time_imprint_v1
from etzio.protocol import content_id


@pytest.mark.parametrize(
    "field",
    [
        None,
        "mission_id",
        "authority_id",
        "target_id",
        "event_digest",
        "transition_intent_id",
        "request_nonce",
        "imprint_id",
    ],
)
def test_pending_consumes_only_its_own_signed_scope(tmp_path, field):
    from test_qualified_pending_record_wiring_v1 import (
        _aligned_qualified_store,
        _coherent_qualified_pending,
        _revocation_bundles,
    )

    from etzio.integrity_v1 import IntegrityDecisionV1
    from etzio.kernel.integrity_adapters_v1 import (
        TrustedTimeRequestV1,
        map_qualified_integrity_inputs_v1,
        qualify_time_bundle_v1,
    )
    from etzio.kernel.store import EventStoreError

    fixture = _fixture()
    store, service = _aligned_qualified_store(tmp_path, fixture)
    with store:
        event, pending = _coherent_qualified_pending(service, fixture)
        decision = pending.decision
        scope = {
            name: getattr(decision, name)
            for name in ("mission_id", "authority_id", "target_id", "transition_intent_id", "request_nonce")
        }
        scope["event_digest"] = event.event_digest
        scope["imprint_id"] = qualified_decision_time_imprint_v1(decision)
        if field is not None:
            scope[field] = "f" * 64 if field == "request_nonce" else content_id("scope_probe", {"field": field})
        tfx = fixture.time_fixture
        requests = {
            adapter.source_id: TrustedTimeRequestV1.issue(
                profile=tfx.profile, source_id=adapter.source_id, purpose="decision", **scope
            )
            for adapter in tfx.time_adapters
        }
        bundle = qualify_time_bundle_v1(
            profile=tfx.profile,
            requests=requests,
            signed_evidence={
                adapter.source_id: adapter.acquire(requests[adapter.source_id]) for adapter in tfx.time_adapters
            },
        )
        revocation = _revocation_bundles(fixture, bundle)
        mapped = map_qualified_integrity_inputs_v1(
            profile=tfx.profile, time_bundle=bundle, revocation_bundles=revocation
        )
        values = {
            entry.name: getattr(decision, entry.name) for entry in fields(decision) if entry.name != "decision_id"
        }
        values.update(time_evidence=mapped.time_evidence, revocation_views=mapped.revocation_views)
        rebound = IntegrityDecisionV1.issue(**values)
        old_ids = {blob.evidence_id for blob in pending.time_bundle.evidence_blobs}
        for old in pending.revocation_bundles.values():
            old_ids.update(blob.evidence_id for blob in old.evidence_blobs)
        remaining = tuple(blob for blob in pending.provider_evidence if blob.evidence_id not in old_ids)
        rebound_pending = replace(
            pending,
            signed_decision=service._decision_signer.sign_decision(rebound),
            revocation_floors=mapped.external_floors,
            time_bundle=bundle,
            revocation_bundles=revocation,
            provider_evidence=tuple(
                sorted(
                    (*remaining, *mapped.evidence_blobs),
                    key=lambda blob: (blob.evidence_kind, blob.source_id, blob.evidence_id),
                )
            ),
        )
        if field is None:
            assert (
                store.append_pending_integrity_event(event, expected_head=event.prev_digest, pending=rebound_pending)
                == event
            )
        else:
            with pytest.raises(EventStoreError, match="scope|imprint"):
                store.append_pending_integrity_event(event, expected_head=event.prev_digest, pending=rebound_pending)
            assert store.load_integrity_lineage(event.event_digest) is None


def _changed_request(request, field, domain):
    value = content_id("scope_probe", {"field": field})
    body = request.to_body()
    del body["request_id"]
    body[field] = value
    return replace(request, **{field: value, "request_id": content_id(domain, body)})


@pytest.mark.parametrize("field", ["mission_id", "authority_id", "target_id", "event_digest", "transition_intent_id"])
def test_revocation_scope_must_match_authenticated_time(field):
    fixture = _fixture().time_fixture
    bundle = _fixture_time_bundle(fixture)
    requests, _ = _revocation_inputs(fixture=fixture, time_bundle=bundle, namespace="authority")
    requests = {
        source: _changed_request(request, field, "revocation_adapter_request") for source, request in requests.items()
    }
    signed = {
        adapter.source_id: adapter.acquire(requests[adapter.source_id])
        for adapter in fixture.revocation_adapters
        if adapter.namespace == "authority"
    }
    with pytest.raises(IntegrityAdapterError, match="scope|time bundle"):
        qualify_revocation_bundle_v1(
            profile=fixture.profile,
            namespace="authority",
            time_bundle=bundle,
            requests=requests,
            signed_evidence=signed,
        )


@pytest.mark.parametrize("kind", ["anchor", "catalog"])
@pytest.mark.parametrize("field", ["authority_id", "target_id", "event_digest", "transition_intent_id"])
def test_head_scope_must_match_authenticated_time(kind, field):
    fixture = _fixture()
    bundle = _time_bundle(fixture)
    if kind == "anchor":
        requests = _anchor_requests(fixture, bundle)
        adapters = {adapter.source_id: adapter for adapter in fixture.anchor_adapters}
        qualify = qualify_anchor_bundle_v1
    else:
        requests = _catalog_requests(fixture, bundle)
        adapters = _catalog_sources(fixture)
        qualify = qualify_head_catalog_bundle_v1
    requests = {
        source: _changed_request(request, field, f"head_{kind}_adapter_request") for source, request in requests.items()
    }
    signed = {source: adapter.acquire(requests[source]) for source, adapter in adapters.items()}
    with pytest.raises(HeadAuthorityAdapterError, match="scope|time hull"):
        qualify(
            profile=fixture.profile,
            time_profile=fixture.time_fixture.profile,
            time_bundle=bundle,
            requests=requests,
            signed_evidence=signed,
        )


@pytest.mark.parametrize("kind", ["anchor", "catalog"])
@pytest.mark.parametrize("field", ["service_instance_id", "environment_id"])
def test_head_and_time_profiles_must_name_the_same_scope(kind, field):
    from etzio.kernel.integrity_adapters_v1 import TrustedTimeRequestV1, qualify_time_bundle_v1

    fixture = _fixture()
    tfx = fixture.time_fixture
    profile = replace(tfx.profile, **{field: "Etzio.foreign-scope"})
    adapters = tuple(replace(adapter, profile=profile) for adapter in tfx.time_adapters)
    vector = tfx.vector
    requests = {
        adapter.source_id: TrustedTimeRequestV1.issue(
            profile=profile,
            source_id=adapter.source_id,
            purpose="checkpoint",
            mission_id=vector.mission_id,
            authority_id=vector.authority_id,
            target_id=vector.target_id,
            event_digest=vector.event_digest,
            transition_intent_id=vector.transition_intent_id,
            imprint_id=content_id("scope_probe", {}),
            request_nonce=vector.request_nonce,
        )
        for adapter in adapters
    }
    time = qualify_time_bundle_v1(
        profile=profile,
        requests=requests,
        signed_evidence={adapter.source_id: adapter.acquire(requests[adapter.source_id]) for adapter in adapters},
    )
    if kind == "anchor":
        requests = _anchor_requests(fixture, time)
        sources = {adapter.source_id: adapter for adapter in fixture.anchor_adapters}
        qualify = qualify_anchor_bundle_v1
    else:
        requests = _catalog_requests(fixture, time)
        sources = _catalog_sources(fixture)
        qualify = qualify_head_catalog_bundle_v1
    with pytest.raises(HeadAuthorityAdapterError, match="time hull"):
        qualify(
            profile=fixture.profile,
            time_profile=profile,
            time_bundle=time,
            requests=requests,
            signed_evidence={source: adapter.acquire(requests[source]) for source, adapter in sources.items()},
        )
