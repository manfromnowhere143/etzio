"""Provider forgery remains detectable after coherent local indexes and hashes are rewritten."""

import sqlite3
from dataclasses import fields, replace

import pytest
from test_qualified_anchor_consumption_v1 import _head_fixture
from test_qualified_fixture_lifecycle_v1 import _enroll_store, _event, _service

from etzio.integrity_v1 import HeadCheckpointV1, IntegrityDecisionV1, signed_head_checkpoint_attestation_id
from etzio.kernel.head_authority_adapters_v1 import HeadProviderStatementV1, SignedHeadEvidenceV1
from etzio.kernel.integrity_adapters_v1 import ProviderEvidenceStatementV1, SignedProviderEvidenceV1
from etzio.kernel.integrity_transition import (
    INTEGRITY_ACCEPTANCE_MODE_QUALIFIED_SIGNED_V1,
    FinalizedIntegrityTransitionV1,
    ProviderEvidenceBlobV1,
)
from etzio.kernel.store import EventStoreCorruptionError, EventStoreError, SQLiteEventStore
from etzio.protocol import canonical_dumps, content_id


def _values(value, excluded):
    return {field.name: getattr(value, field.name) for field in fields(value) if field.name != excluded}


def _change_provider(record, fixture, source, damage):
    old = next(blob for blob in record.provider_evidence if blob.source_id == source)
    time_adapters = (*fixture.time_fixture.time_adapters, *fixture.time_fixture.revocation_adapters)
    adapters = (*time_adapters, *fixture.anchor_adapters, fixture.catalog_adapter, *fixture.monitor_adapters)
    adapter = next(adapter for adapter in adapters if adapter.source_id == source)
    if adapter in time_adapters:
        signed = SignedProviderEvidenceV1.from_canonical_bytes(old.content)
        statement = ProviderEvidenceStatementV1.from_canonical_bytes(signed.statement_bytes)
    else:
        signed = SignedHeadEvidenceV1.from_canonical_bytes(old.content)
        statement = HeadProviderStatementV1.from_canonical_bytes(signed.statement_bytes)
    if damage == "signature":
        changed = replace(signed, signature_bytes=bytes(64))
    else:
        changed = adapter.signer.sign(replace(statement, request_id=content_id("foreign_qualified_request", {})))
    new = ProviderEvidenceBlobV1.from_content(evidence_kind=old.evidence_kind, source_id=source,
                                             content=changed.to_canonical_bytes())
    blobs = tuple(new if blob == old else blob for blob in record.provider_evidence)
    blobs = tuple(sorted(blobs, key=lambda blob: (blob.evidence_kind, blob.source_id, blob.evidence_id)))
    return old.reference, new.reference, blobs


def _forge(record, fixture, service, phase, source, damage):
    old, new, blobs = _change_provider(record, fixture, source, damage)

    def refs(values):
        return tuple(new if reference == old else reference for reference in values)

    if phase == "pending":
        views = tuple(replace(view, evidence=new) if view.evidence == old else view
                      for view in record.decision.revocation_views)
        values = _values(record.decision, "decision_id")
        values.update(time_evidence=refs(record.decision.time_evidence), revocation_views=views)
        decision = IntegrityDecisionV1.issue(**values)
        return replace(record, signed_decision=service._core._decision_signer.sign_decision(decision),
            revocation_floors=tuple(replace(floor, evidence=refs(floor.evidence)) for floor
                                     in record.revocation_floors),
            prior_head_floor=replace(record.prior_head_floor, evidence=refs(record.prior_head_floor.evidence)),
            provider_evidence=blobs, time_bundle=None, revocation_bundles=None)
    if phase == "anchor_statement":
        body = record.registration_body
        body["time_evidence"] = [reference.to_body() for reference in refs(record.time_evidence)]
        return replace(record, time_evidence=refs(record.time_evidence), provider_evidence=blobs,
            registration_request=canonical_dumps(body), anchor_statement_id=content_id("head_anchor_statement", body))
    if phase == "checkpoint_candidate":
        values = _values(record.checkpoint, "checkpoint_id")
        values.pop("anchor_statement_id")
        values["anchor_evidence"] = refs(record.checkpoint.anchor_evidence)
        checkpoint = HeadCheckpointV1.issue(**values)
        return replace(record, signed_checkpoint=service._core._checkpoint_signer.sign_checkpoint(checkpoint),
                        provider_evidence=blobs, anchor_bundle=None, time_bundle=None)
    return replace(record, external_head_floor=replace(record.external_head_floor,
        evidence=refs(record.external_head_floor.evidence)), provider_evidence=blobs,
        catalog_bundle=None, time_bundle=None)


def _prepare_phase(store, service, event, phase):
    pending = service.prepare_pending_transition(event, previous_global=None, previous_mission=None)
    if phase == "pending":
        return pending
    store.append_pending_integrity_event(event, expected_head=event.prev_digest, pending=pending)
    anchor = service.prepare_anchor_statement(pending)
    if phase == "anchor_statement":
        return anchor
    store.retain_integrity_anchor_statement(anchor)
    candidate = service.prepare_checkpoint_candidate(pending, anchor,
        anchor_receipts=service.register_anchor_statement(anchor, pending=pending))
    if phase == "checkpoint_candidate":
        return candidate
    store.retain_integrity_checkpoint_candidate(candidate)
    service.publish_checkpoint(candidate)
    floor, blobs = service.observe_current_floor(pending, candidate)
    return FinalizedIntegrityTransitionV1(pending_record_id=pending.record_id,
        checkpoint_candidate_record_id=candidate.record_id, event_digest=event.event_digest,
        external_head_floor=floor, provider_evidence=blobs,
        acceptance_mode=INTEGRITY_ACCEPTANCE_MODE_QUALIFIED_SIGNED_V1)


def _retain(store, event, phase, record):
    if phase == "pending":
        return store.append_pending_integrity_event(event, expected_head=event.prev_digest, pending=record)
    return getattr(store, {
        "anchor_statement": "retain_integrity_anchor_statement",
        "checkpoint_candidate": "retain_integrity_checkpoint_candidate",
        "finalization": "finalize_integrity_transition",
    }[phase])(record)


def _rewrite_phase(path, phase, record):
    """Simulate coherent offline tampering, restoring every schema trigger exactly."""
    tables = {"pending": "integrity_pending_transitions", "anchor_statement": "integrity_anchor_statements",
              "checkpoint_candidate": "integrity_checkpoint_candidates", "finalization": "integrity_finalizations"}
    with sqlite3.connect(path) as connection:
        triggers = connection.execute("SELECT name, sql FROM sqlite_schema WHERE type = 'trigger'").fetchall()
        for name, _ in triggers:
            connection.execute('DROP TRIGGER "' + name.replace('"', '""') + '"')
        values = {"record_id": record.record_id, "record": record.to_canonical_bytes()}
        if phase == "anchor_statement":
            values["anchor_statement_id"] = record.anchor_statement_id
        if phase == "checkpoint_candidate":
            values.update(checkpoint_id=record.checkpoint.checkpoint_id,
                          checkpoint_attestation_id=signed_head_checkpoint_attestation_id(record.signed_checkpoint))
        assignments = ', '.join(name + ' = ?' for name in values)
        connection.execute(f"UPDATE {tables[phase]} SET {assignments} WHERE event_digest = ?",
                           (*values.values(), record.event_digest))
        connection.execute("DELETE FROM integrity_transition_evidence WHERE event_digest = ? AND phase = ?",
                           (record.event_digest, phase))
        for slot, blob in enumerate(record.provider_evidence):
            connection.execute("INSERT OR IGNORE INTO integrity_evidence_artifacts VALUES (?, ?, ?)",
                               (blob.evidence_id, len(blob.content), blob.content))
            connection.execute("INSERT INTO integrity_transition_evidence VALUES (?, ?, ?, ?, ?, ?)",
                               (record.event_digest, phase, slot, blob.evidence_kind, blob.source_id, blob.evidence_id))
        connection.execute("DELETE FROM integrity_evidence_artifacts WHERE evidence_id NOT IN "
                           "(SELECT evidence_id FROM integrity_transition_evidence)")
        for _, sql in triggers:
            connection.execute(sql)
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


@pytest.mark.parametrize("damage", ["signature", "signed_foreign_request"])
@pytest.mark.parametrize("phase,kind", [
    ("pending", "time"), ("pending", "revocation"), ("pending", "catalog"),
    ("anchor_statement", "time"), ("checkpoint_candidate", "anchor"), ("finalization", "catalog"),
])
def test_forged_provider_is_rejected_at_admission_and_after_coherent_rewrite(tmp_path, phase, kind, damage):
    fixture = _head_fixture()
    service = _service(fixture)
    event = _event(fixture)
    sources = {"time": fixture.time_fixture.time_adapters[0].source_id,
               "revocation": fixture.time_fixture.revocation_adapters[0].source_id,
               "catalog": fixture.catalog_adapter.source_id, "anchor": fixture.anchor_adapters[0].source_id}
    path = tmp_path / "forged.sqlite3"
    with SQLiteEventStore(path) as store:
        _enroll_store(store, service)
        record = _prepare_phase(store, service, event, phase)
        forged = _forge(record, fixture, service, phase, sources[kind], damage)
        with pytest.raises(EventStoreError, match="qualified lifecycle evidence failed reauthentication"):
            _retain(store, event, phase, forged)
        _retain(store, event, phase, record)
    _rewrite_phase(path, phase, forged)
    with pytest.raises(EventStoreCorruptionError, match="qualified lifecycle evidence failed reauthentication"):
        SQLiteEventStore(path)


@pytest.mark.parametrize("profile_kind", ["time", "head"])
@pytest.mark.parametrize("field", ["service_instance_id", "environment_id", "validation_policy"])
def test_enrollment_and_cold_replay_bind_profiles_to_kernel_scope(tmp_path, profile_kind, field):
    fixture = _head_fixture()
    service = _service(fixture)
    profile = service.time_profile if profile_kind == "time" else service.head_profile
    if field == "validation_policy":
        policy = replace(profile.validation_policy, max_decision_uncertainty_seconds=123)
        changed = replace(profile, validation_policy=policy,
                          validation_policy_id=content_id("integrity_validation_policy", policy.to_body()))
    else:
        changed = replace(profile, **{field: "fixture.foreign-scope"})
    path = tmp_path / "profile.sqlite3"
    with SQLiteEventStore(path) as store:
        store.enroll_modeled_integrity(service_instance_id=service.service_instance_id,
            environment_id=service.environment_id, validation_policy=service.validation_policy,
            authority_binding=service.authority_binding)
        with pytest.raises(EventStoreError, match="scope or validation policy"):
            store.enroll_qualified_acceptance(
                qualified_time_profile=changed if profile_kind == "time" else service.time_profile,
                qualified_head_profile=changed if profile_kind == "head" else service.head_profile)
        assert store.load_qualified_acceptance_profiles() is None
        _enroll_store(store, service)
    with sqlite3.connect(path) as connection:
        triggers = connection.execute("SELECT name, sql FROM sqlite_schema "
            "WHERE type = 'trigger' AND tbl_name = 'integrity_acceptance_profile'").fetchall()
        for name, _ in triggers:
            connection.execute('DROP TRIGGER "' + name + '"')
        connection.execute(f"UPDATE integrity_acceptance_profile SET qualified_{profile_kind}_profile_id = ?, "
            f"qualified_{profile_kind}_profile_wire = ?", (changed.profile_id, changed.to_canonical_bytes()))
        for _, sql in triggers:
            connection.execute(sql)
    with pytest.raises(EventStoreCorruptionError, match="scope or validation policy"):
        SQLiteEventStore(path)


def test_legacy_anchor_bytes_are_preserved_and_redundant_mode_refuses():
    from etzio.kernel.integrity_transition import AnchorStatementRecordV1, IntegrityTransitionError

    fixture = _head_fixture()
    service = _service(fixture)._core
    pending = service.prepare_pending_transition(_event(fixture), previous_global=None, previous_mission=None)
    anchor = service.prepare_anchor_statement(pending)
    assert "acceptance_mode" not in anchor.to_body()
    assert AnchorStatementRecordV1.from_canonical_bytes(anchor.to_canonical_bytes()) == anchor
    body = {**anchor.to_body(), "acceptance_mode": anchor.acceptance_mode}
    with pytest.raises(IntegrityTransitionError, match="explicit mode"):
        AnchorStatementRecordV1.from_canonical_bytes(canonical_dumps(body))


@pytest.mark.parametrize("phase,field", [
    ("pending", "time_bundle"), ("pending", "revocation_bundles"),
    ("checkpoint_candidate", "time_bundle"), ("checkpoint_candidate", "anchor_bundle"),
    ("finalization", "time_bundle"), ("finalization", "catalog_bundle"),
])
def test_optional_bundle_conflicts_are_refused_on_fresh_admission_and_retry(tmp_path, phase, field):
    from test_qualified_anchor_consumption_v1 import _anchor_bundle, _time_bundle
    from test_qualified_head_floor_acceptance_v1 import _built
    from test_qualified_pending_record_wiring_v1 import _decision_time_bundle, _revocation_bundles

    fixture = _head_fixture()
    service = _service(fixture)
    event = _event(fixture)
    with SQLiteEventStore(tmp_path / "transient.sqlite3") as store:
        _enroll_store(store, service)
        record = _prepare_phase(store, service, event, phase)
        time = _decision_time_bundle(fixture) if phase == "pending" else _time_bundle(fixture)
        supplied = {"time_bundle": time, "revocation_bundles": lambda: _revocation_bundles(fixture, time),
                    "anchor_bundle": lambda: _anchor_bundle(fixture, time),
                    "catalog_bundle": lambda: _built()[2]}[field]
        if callable(supplied):
            supplied = supplied()
        changed = replace(record, **{field: supplied})
        assert changed.to_canonical_bytes() == record.to_canonical_bytes()
        with pytest.raises(EventStoreError, match="reauthentication"):
            _retain(store, event, phase, changed)
        cold = type(record).from_canonical_bytes(record.to_canonical_bytes())
        _retain(store, event, phase, cold)
        with pytest.raises(EventStoreError, match="reauthentication"):
            _retain(store, event, phase, changed)
        _retain(store, event, phase, cold)


def test_valid_anchor_inclusion_in_a_disconnected_log_does_not_establish_append(tmp_path):
    from etzio.kernel.head_authority_adapters_v1 import merkle_leaf_hash_v1, merkle_root_v1

    fixture = _head_fixture()
    service = _service(fixture)
    event = _event(fixture)
    path = tmp_path / "disconnected.sqlite3"
    with SQLiteEventStore(path) as store:
        _enroll_store(store, service)
        record = _prepare_phase(store, service, event, "checkpoint_candidate")
        adapter = fixture.anchor_adapters[0]
        old = next(blob for blob in record.provider_evidence if blob.source_id == adapter.source_id)
        signed = SignedHeadEvidenceV1.from_canonical_bytes(old.content)
        statement = HeadProviderStatementV1.from_canonical_bytes(signed.statement_bytes)
        claim = dict(statement.claim)
        junk = merkle_leaf_hash_v1(b"different log genesis")
        root = merkle_root_v1((junk, bytes.fromhex(claim["leaf_hash"][7:])))
        claim.update(log_root_hash="sha256:" + root.hex(), inclusion_proof=["sha256:" + junk.hex()])
        changed = adapter.signer.sign(replace(statement, claim=claim))
        new = ProviderEvidenceBlobV1.from_content(evidence_kind=old.evidence_kind, source_id=old.source_id,
                                                content=changed.to_canonical_bytes())
        values = _values(record.checkpoint, "checkpoint_id")
        values.pop("anchor_statement_id")
        values["anchor_evidence"] = tuple(new.reference if ref == old.reference else ref
                                          for ref in record.checkpoint.anchor_evidence)
        checkpoint = HeadCheckpointV1.issue(**values)
        forged = replace(record, signed_checkpoint=service._core._checkpoint_signer.sign_checkpoint(checkpoint),
            provider_evidence=tuple(new if blob == old else blob for blob in record.provider_evidence),
            anchor_bundle=None, time_bundle=None)
        with pytest.raises(EventStoreError, match="qualified_anchor_append_mismatch"):
            _retain(store, event, "checkpoint_candidate", forged)
        _retain(store, event, "checkpoint_candidate", record)
    _rewrite_phase(path, "checkpoint_candidate", forged)
    with pytest.raises(EventStoreCorruptionError, match="qualified_anchor_append_mismatch"):
        SQLiteEventStore(path)


def test_valid_catalog_consistency_cannot_insert_an_extra_lifecycle_leaf(tmp_path):
    from etzio.kernel.head_authority_adapters_v1 import (
        catalog_projection_leaf_bytes_v1,
        merkle_consistency_proof_v1,
        merkle_inclusion_proof_v1,
        merkle_leaf_hash_v1,
        merkle_root_v1,
    )
    from etzio.kernel.qualified_lifecycle_v1 import qualified_log_genesis_leaf_v1

    fixture = _head_fixture()
    service = _service(fixture)
    event = _event(fixture)
    path = tmp_path / "extra-leaf.sqlite3"
    with SQLiteEventStore(path) as store:
        _enroll_store(store, service)
        record = _prepare_phase(store, service, event, "pending")
        catalog = fixture.catalog_adapter
        leaves = (
            merkle_leaf_hash_v1(qualified_log_genesis_leaf_v1(fixture.profile, catalog.source_id)),
            merkle_leaf_hash_v1(b"extra lifecycle leaf"),
            merkle_leaf_hash_v1(catalog_projection_leaf_bytes_v1(profile=fixture.profile,
                mission_id=event.mission_id, head=record.prior_head_floor)),
        )
        changed = []
        for adapter in (catalog, *fixture.monitor_adapters):
            old = next(blob for blob in record.provider_evidence if blob.source_id == adapter.source_id)
            signed = SignedHeadEvidenceV1.from_canonical_bytes(old.content)
            statement = HeadProviderStatementV1.from_canonical_bytes(signed.statement_bytes)
            claim = dict(statement.claim)
            claim.update(tree_size=3, log_root_hash="sha256:" + merkle_root_v1(leaves).hex())
            if adapter is catalog:
                claim.update(consistency_proof=["sha256:" + node.hex()
                    for node in merkle_consistency_proof_v1(leaves, 1)],
                    projection_inclusion_proof=["sha256:" + node.hex()
                    for node in merkle_inclusion_proof_v1(leaves, 2)])
            signed = adapter.signer.sign(replace(statement, claim=claim))
            changed.append(ProviderEvidenceBlobV1.from_content(evidence_kind=old.evidence_kind,
                source_id=old.source_id, content=signed.to_canonical_bytes()))
        changed.sort(key=lambda blob: (blob.evidence_kind, blob.source_id, blob.evidence_id))
        sources = {blob.source_id for blob in changed}
        blobs = [blob for blob in record.provider_evidence if blob.source_id not in sources] + changed
        blobs.sort(key=lambda blob: (blob.evidence_kind, blob.source_id, blob.evidence_id))
        forged = replace(record, prior_head_floor=replace(record.prior_head_floor,
            evidence=tuple(blob.reference for blob in changed)), provider_evidence=tuple(blobs),
            time_bundle=None, revocation_bundles=None)
        with pytest.raises(EventStoreError, match="qualified_catalog_append_mismatch"):
            _retain(store, event, "pending", forged)
        _retain(store, event, "pending", record)
    _rewrite_phase(path, "pending", forged)
    with pytest.raises(EventStoreCorruptionError, match="qualified_catalog_append_mismatch"):
        SQLiteEventStore(path)


@pytest.mark.parametrize("qualified_store", [False, True])
def test_anchor_mode_must_match_its_enrolled_store(tmp_path, qualified_store):
    fixture = _head_fixture()
    service = _service(fixture)
    event = _event(fixture)
    with SQLiteEventStore(tmp_path / "mode.sqlite3") as store:
        store.enroll_modeled_integrity(service_instance_id=service.service_instance_id,
            environment_id=service.environment_id, validation_policy=service.validation_policy,
            authority_binding=service.authority_binding)
        if qualified_store:
            _enroll_store(store, service)
        owner = service if qualified_store else service._core
        pending = owner.prepare_pending_transition(event, previous_global=None, previous_mission=None)
        store.append_pending_integrity_event(event, expected_head=event.prev_digest, pending=pending)
        foreign_mode_service = service._core if qualified_store else service
        anchor = foreign_mode_service.prepare_anchor_statement(pending)
        with pytest.raises(EventStoreError, match="acceptance mode"):
            store.retain_integrity_anchor_statement(anchor)
        assert store.load_integrity_lineage(event.event_digest).anchor_statement is None
