"""Semantic schema/runtime parity and explicit boundary evidence for protocol v1."""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from jsonschema import Draft202012Validator

from etzio.analysis import StaticFinding
from etzio.authority import (
    AuthorityAdmissionV1,
    AuthorityGrantV1,
    AuthoritySigner,
    TrustedAuthorityKey,
    TrustStore,
)
from etzio.evidence import EvidenceError, SnapshotFileV1, TargetSnapshotV1
from etzio.kernel.events_v1 import (
    EVENT_PAYLOAD_FIELDS_BY_KIND_V1,
    EVENT_UNIT_BY_KIND_V1,
    GENESIS_DIGEST,
    EventV1,
)
from etzio.mission_v1 import AnalysisLeaseV1, StaticCandidateV1
from etzio.protocol import (
    RESERVED_OBJECT_KINDS,
    SEMANTIC_BODY_FIELDS_BY_KIND_V1,
    SUPPORTED_OBJECT_KINDS,
    EnvelopeV1,
    ProtocolError,
    SemanticProtocolError,
    canonical_dumps,
    content_id,
    parse_semantic_bytes,
    parse_semantic_envelope,
    thaw_json,
)
from etzio.schemas import protocol_v1_schema
from etzio.verification import (
    MODELED_FIXTURE_TIER,
    VERIFIER_ROLE,
    TrustedVerifierKey,
    VerificationLeaseV1,
    VerifierReceiptV1,
    VerifierSigner,
    VerifierTrustStore,
    derive_verification_lease_nonce,
)

NOW = 1_750_000_000


def _digest(character: str) -> str:
    return "sha256:" + (character * 64)


@dataclass(frozen=True)
class GoldenGraph:
    envelopes: dict[str, EnvelopeV1]
    events: dict[str, EventV1]


def _golden_graph() -> GoldenGraph:
    snapshot = TargetSnapshotV1.create(
        "repository_fixture",
        (
            SnapshotFileV1("fixture/clean.py", _digest("a"), 64),
            SnapshotFileV1("fixture/vulnerable.py", _digest("b"), 128),
        ),
    )
    authority_signer = AuthoritySigner.generate()
    grant = AuthorityGrantV1.issue(
        issuer="operator:daniel",
        subject="benchmark:semantic-schema",
        target_snapshot_id=snapshot.object_id,
        assets=("fixture://clean.py", "fixture://vulnerable.py"),
        permitted_actions=("modeled_fixture_verification", "static_analysis"),
        evidence_digest=_digest("c"),
        issued_at=NOW - 10,
        not_before=NOW,
        expires_at=NOW + 600,
        max_bytes=1_000_000,
        max_candidates=100,
        max_wallclock_seconds=60,
    )
    signed_grant = authority_signer.sign(grant)
    trust_store = TrustStore.from_keys(
        (
            TrustedAuthorityKey(
                public_key_bytes=authority_signer.public_key_bytes,
                roles=frozenset({"operator"}),
                issuers=frozenset({"operator:daniel"}),
            ),
        )
    )
    admission = AuthorityAdmissionV1.issue(
        grant=grant,
        signed_grant=signed_grant,
        signer_key_id=authority_signer.key_id,
        trust_store=trust_store,
        decision_time=NOW,
        required_actions=("static_analysis",),
        target_snapshot_id=snapshot.object_id,
    )
    mission_id = _digest("d")
    analysis_lease = AnalysisLeaseV1.issue(
        mission_id=mission_id,
        authority_id=grant.grant_id,
        target_snapshot_id=snapshot.object_id,
        issued_at=NOW,
        expires_at=NOW + 60,
        max_bytes=1_000_000,
        max_candidates=100,
        max_wallclock_seconds=60,
        lease_nonce="1" * 32,
    )
    candidate = StaticCandidateV1.from_finding(
        StaticFinding(
            rule_id="PY-CMD-INJECTION",
            severity="high",
            message="schema fixture",
            file="fixture/vulnerable.py",
            line=7,
            column=4,
            symbol="os.system",
            snippet="excluded",
        ),
        mission_id=mission_id,
        authority_id=grant.grant_id,
        analysis_lease_id=analysis_lease.lease_id,
        target_snapshot_id=snapshot.object_id,
        source_artifact_digest=_digest("b"),
    )
    verifier_signer = VerifierSigner.generate()
    verifier_trust_store = VerifierTrustStore.from_keys(
        (
            TrustedVerifierKey(
                verifier_id="CATO",
                public_key_bytes=verifier_signer.public_key_bytes,
                roles=frozenset({VERIFIER_ROLE}),
            ),
        )
    )
    verification_nonce = derive_verification_lease_nonce(
        prior_event_digest=GENESIS_DIGEST,
        mission_id=mission_id,
        authority_id=grant.grant_id,
        target_snapshot_id=snapshot.object_id,
        candidate_id=candidate.candidate_id,
        candidate_producer_id="VELITES",
        poc_artifact_digest=_digest("3"),
        evidence_artifact_digests=(_digest("4"), _digest("5")),
        environment_digest=_digest("6"),
        effect_oracle_id=_digest("7"),
        verifier_id="CATO",
        verifier_key_id=verifier_signer.key_id,
        issued_at=NOW,
        expires_at=NOW + 60,
        issuance_trust_snapshot_id=verifier_trust_store.snapshot_id,
    )
    verification_lease = VerificationLeaseV1.issue(
        lease_nonce=verification_nonce,
        mission_id=mission_id,
        authority_id=grant.grant_id,
        target_snapshot_id=snapshot.object_id,
        candidate_id=candidate.candidate_id,
        candidate_producer_id="VELITES",
        poc_artifact_digest=_digest("3"),
        evidence_artifact_digests=(_digest("4"), _digest("5")),
        environment_digest=_digest("6"),
        effect_oracle_id=_digest("7"),
        verifier_id="CATO",
        verifier_key_id=verifier_signer.key_id,
        issuance_trust_snapshot_id=verifier_trust_store.snapshot_id,
        issued_at=NOW,
        expires_at=NOW + 60,
    )
    receipt = VerifierReceiptV1.for_lease(
        verification_lease,
        evidence_tier=MODELED_FIXTURE_TIER,
        verdict="confirmed",
        effect_observed=True,
        oracle_satisfied=True,
        completed_at=NOW + 10,
    )
    signed_receipt = verifier_signer.sign(receipt)

    payloads: dict[str, dict[str, object]] = {
        "authority_admitted": {
            "admission": admission.to_envelope().to_dict(),
            "grant": grant.to_envelope().to_dict(),
            "key_id": authority_signer.key_id,
            "signature_b64": signed_grant.signature_b64,
        },
        "mission_admission_refused": {
            "reason_code": "authority_expired",
            "stage": "admission",
        },
        "mission_opened": {"target_snapshot": snapshot.to_envelope().to_dict()},
        "analysis_lease_issued": {"lease": analysis_lease.to_envelope().to_dict()},
        "verification_lease_issued": {
            "lease": verification_lease.to_envelope().to_dict(),
            "verifier_trust_snapshot": verifier_trust_store.to_snapshot_body(),
            "verifier_trust_snapshot_id": verifier_trust_store.snapshot_id,
        },
        "candidate_recorded": {"candidate": candidate.to_envelope().to_dict()},
        "parse_failed": {
            "analysis_lease_id": analysis_lease.lease_id,
            "parse_failure": {
                "column": 2,
                "line": 4,
                "reason_code": "syntax_error",
                "relative_path": "fixture/broken.py",
            },
            "source_artifact_digest": _digest("b"),
        },
        "scan_completed": {
            "analyzer_version": "python_ast.v1",
            "bytes_scanned": 192,
            "candidate_count": 1,
            "file_count": 2,
            "parse_failure_count": 0,
        },
        "mission_closed": {
            "candidate_count": 1,
            "parse_failure_count": 0,
            "status": "completed",
        },
        "scan_failed": {"reason_code": "fixture_failure"},
        "scan_timed_out": {"reason_code": "fixture_timeout"},
        "scan_cancelled": {"reason_code": "fixture_cancelled"},
        "budget_exhausted": {"reason_code": "fixture_budget"},
    }
    events = {
        kind: EventV1.create(
            mission_id=mission_id,
            seq=0,
            kind=kind,
            unit=EVENT_UNIT_BY_KIND_V1[kind],
            authority_id=grant.grant_id,
            target_id=snapshot.object_id,
            decision_time=NOW,
            payload=payload,
            prev_digest=GENESIS_DIGEST,
        )
        for kind, payload in payloads.items()
    }
    envelopes = {
        "authority_grant_unsigned": grant.to_envelope(),
        "authority_grant_signed": signed_grant.to_envelope(),
        "authority_admission": admission.to_envelope(),
        "target_snapshot": snapshot.to_envelope(),
        "analysis_lease": analysis_lease.to_envelope(),
        "candidate": candidate.to_envelope(),
        "verification_lease": verification_lease.to_envelope(),
        "verifier_receipt_unsigned": receipt.to_envelope(),
        "verifier_receipt_signed": signed_receipt.to_envelope(),
        "event": events["analysis_lease_issued"].to_envelope(),
    }
    return GoldenGraph(envelopes=envelopes, events=events)


@pytest.fixture(scope="module")
def golden() -> GoldenGraph:
    return _golden_graph()


@pytest.fixture(scope="module")
def validator() -> Draft202012Validator:
    schema = protocol_v1_schema()
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _assert_schema_rejects(
    validator: Draft202012Validator,
    instance: object,
    label: str,
) -> None:
    assert list(validator.iter_errors(instance)), f"schema unexpectedly accepted {label}"


def test_every_runtime_produced_semantic_wire_validates_and_dispatches(
    golden: GoldenGraph,
    validator: Draft202012Validator,
) -> None:
    assert {envelope.object_kind for envelope in golden.envelopes.values()} == SUPPORTED_OBJECT_KINDS
    for label, envelope in golden.envelopes.items():
        validator.validate(envelope.to_dict())
        assert parse_semantic_envelope(envelope) is not None, label
        assert parse_semantic_bytes(envelope.to_bytes()) is not None, label


def test_all_event_kind_unit_payload_variants_validate_and_round_trip(
    golden: GoldenGraph,
    validator: Draft202012Validator,
) -> None:
    assert set(golden.events) == set(EVENT_UNIT_BY_KIND_V1)
    for kind, event in golden.events.items():
        validator.validate(event.to_envelope().to_dict())
        assert EventV1.from_canonical_bytes(event.to_canonical_bytes()) == event, kind
        assert parse_semantic_bytes(event.to_canonical_bytes()) == event, kind


def test_schema_branch_metadata_has_exact_runtime_parity() -> None:
    schema = protocol_v1_schema()
    assert frozenset(SEMANTIC_BODY_FIELDS_BY_KIND_V1) == SUPPORTED_OBJECT_KINDS
    case_refs = {
        branch["$ref"]
        for branch in schema["oneOf"]
    }
    assert case_refs == {
        f"#/$defs/{kind}_case"
        for kind in SUPPORTED_OBJECT_KINDS
    }
    assert frozenset(schema["properties"]["object_kind"]["enum"]) == SUPPORTED_OBJECT_KINDS
    assert RESERVED_OBJECT_KINDS == frozenset({"head_checkpoint"})
    assert RESERVED_OBJECT_KINDS.isdisjoint(SUPPORTED_OBJECT_KINDS)

    variants = schema["$defs"]["event_variants"]["oneOf"]
    schema_units: dict[str, str] = {}
    schema_payload_fields: dict[str, frozenset[str]] = {}
    for variant in variants:
        properties = variant["properties"]
        kind = properties["kind"]["const"]
        schema_units[kind] = properties["unit"]["const"]
        payload_name = properties["payload"]["$ref"].removeprefix("#/$defs/")
        schema_payload_fields[kind] = frozenset(
            schema["$defs"][payload_name]["required"]
        )
    assert schema_units == dict(EVENT_UNIT_BY_KIND_V1)
    assert schema_payload_fields == dict(EVENT_PAYLOAD_FIELDS_BY_KIND_V1)
    for kind, expected_fields in SEMANTIC_BODY_FIELDS_BY_KIND_V1.items():
        body_name = "event_body_common" if kind == "event" else f"{kind}_body"
        body_schema = schema["$defs"][body_name]
        assert body_schema["additionalProperties"] is False
        assert frozenset(body_schema["required"]) == expected_fields
        assert frozenset(body_schema["properties"]) == expected_fields


def test_every_kind_rejects_missing_and_unknown_body_fields(
    golden: GoldenGraph,
    validator: Draft202012Validator,
) -> None:
    representatives: dict[str, EnvelopeV1] = {}
    for envelope in golden.envelopes.values():
        representatives.setdefault(envelope.object_kind, envelope)

    for kind, envelope in representatives.items():
        body = thaw_json(envelope.body)
        assert type(body) is dict
        for field in tuple(body):
            missing_body = dict(body)
            missing_body.pop(field)
            missing = EnvelopeV1.create(
                kind,
                missing_body,
                attestations=envelope.attestations,
            )
            _assert_schema_rejects(
                validator,
                missing.to_dict(),
                f"{kind} missing {field}",
            )
            with pytest.raises(SemanticProtocolError):
                parse_semantic_envelope(missing)

        extra_body = {**body, "unexpected": True}
        extra = EnvelopeV1.create(
            kind,
            extra_body,
            attestations=envelope.attestations,
        )
        _assert_schema_rejects(validator, extra.to_dict(), f"{kind} unknown field")
        with pytest.raises(SemanticProtocolError):
            parse_semantic_envelope(extra)


def test_root_envelope_fields_are_exact_and_fail_closed(
    golden: GoldenGraph,
    validator: Draft202012Validator,
) -> None:
    wire = golden.envelopes["analysis_lease"].to_dict()
    for field in tuple(wire):
        missing = dict(wire)
        missing.pop(field)
        _assert_schema_rejects(validator, missing, f"root missing {field}")
        with pytest.raises(ProtocolError):
            parse_semantic_bytes(canonical_dumps(missing))

    unknown = {**wire, "unexpected": True}
    _assert_schema_rejects(validator, unknown, "root unknown field")
    with pytest.raises(ProtocolError):
        parse_semantic_bytes(canonical_dumps(unknown))


def test_attestation_cardinality_and_shape_are_fail_closed(
    golden: GoldenGraph,
    validator: Draft202012Validator,
) -> None:
    valid_attestation = thaw_json(
        golden.envelopes["authority_grant_signed"].attestations[0]
    )
    assert type(valid_attestation) is dict

    for label in (
        "authority_admission",
        "target_snapshot",
        "analysis_lease",
        "candidate",
        "verification_lease",
        "event",
    ):
        source = golden.envelopes[label]
        attested = EnvelopeV1.create(
            source.object_kind,
            source.body,
            attestations=[valid_attestation],
        )
        _assert_schema_rejects(validator, attested.to_dict(), f"{label} attestation")
        with pytest.raises(SemanticProtocolError):
            parse_semantic_envelope(attested)

    for label in ("authority_grant_unsigned", "verifier_receipt_unsigned"):
        source = golden.envelopes[label]
        doubled = EnvelopeV1.create(
            source.object_kind,
            source.body,
            attestations=[valid_attestation, valid_attestation],
        )
        _assert_schema_rejects(validator, doubled.to_dict(), f"{label} double attestation")
        with pytest.raises(SemanticProtocolError):
            parse_semantic_envelope(doubled)

    grant = golden.envelopes["authority_grant_unsigned"]
    malformed_attestations: list[tuple[str, dict[str, object]]] = []
    for field in tuple(valid_attestation):
        missing = dict(valid_attestation)
        missing.pop(field)
        malformed_attestations.append((f"missing {field}", missing))
    malformed_attestations.extend(
        [
            ("unknown field", {**valid_attestation, "unexpected": True}),
            ("wrong algorithm", {**valid_attestation, "algorithm": "rsa"}),
            (
                "malformed key",
                {**valid_attestation, "key_id": "ed25519:sha256:" + ("g" * 64)},
            ),
            ("malformed signature", {**valid_attestation, "signature_b64": "!" * 88}),
        ]
    )
    for label, attestation in malformed_attestations:
        malformed = EnvelopeV1.create(
            "authority_grant",
            grant.body,
            attestations=[attestation],
        )
        _assert_schema_rejects(
            validator,
            malformed.to_dict(),
            f"authority attestation {label}",
        )
        with pytest.raises(SemanticProtocolError):
            parse_semantic_envelope(malformed)


def test_nonblank_edge_whitespace_is_ecmascript_portable_and_runtime_aligned(
    golden: GoldenGraph,
    validator: Draft202012Validator,
) -> None:
    edge_class = (
        r"\u0009-\u000d\u001c-\u0020\u0085\u00a0\u1680"
        r"\u2000-\u200a\u2028-\u2029\u202f\u205f\u3000"
    )
    pattern = protocol_v1_schema()["$defs"]["canonical_nonblank_string"]["pattern"]
    assert pattern == rf"^[^{edge_class}](?:[\s\S]*[^{edge_class}])?(?![\s\S])"

    grant = golden.envelopes["authority_grant_unsigned"]
    for codepoint in (*range(0x1C, 0x20), 0x85):
        whitespace = chr(codepoint)
        assert whitespace.strip() == ""
        body = thaw_json(grant.body)
        assert type(body) is dict
        body["issuer"] = whitespace
        mutated = EnvelopeV1.create("authority_grant", body)
        _assert_schema_rejects(
            validator,
            mutated.to_dict(),
            f"issuer U+{codepoint:04X}",
        )
        with pytest.raises(SemanticProtocolError):
            parse_semantic_envelope(mutated)

    byte_order_mark = "\ufeff"
    assert byte_order_mark.strip() == byte_order_mark
    body = thaw_json(grant.body)
    assert type(body) is dict
    body["issuer"] = byte_order_mark
    accepted = EnvelopeV1.create("authority_grant", body)
    validator.validate(accepted.to_dict())
    assert parse_semantic_envelope(accepted) is not None


def test_field_keyed_uniqueness_is_explicitly_runtime_only(
    golden: GoldenGraph,
    validator: Draft202012Validator,
) -> None:
    runtime_invariants = protocol_v1_schema()["x-etzio-runtime-only-invariants"]
    assert any("field-keyed uniqueness" in item for item in runtime_invariants)

    snapshot_body = thaw_json(golden.envelopes["target_snapshot"].body)
    assert type(snapshot_body) is dict
    duplicate_path = {
        **snapshot_body["files"][0],
        "artifact_digest": _digest("e"),
    }
    snapshot_body["files"].insert(1, duplicate_path)
    duplicate_snapshot = EnvelopeV1.create("target_snapshot", snapshot_body)
    validator.validate(duplicate_snapshot.to_dict())
    with pytest.raises(SemanticProtocolError, match="paths must be unique"):
        parse_semantic_envelope(duplicate_snapshot)

    admission_body = thaw_json(golden.envelopes["authority_admission"].body)
    assert type(admission_body) is dict
    trust_snapshot = admission_body["trust_snapshot"]
    duplicate_key = {
        **trust_snapshot["keys"][0],
        "roles": ["observer"],
    }
    trust_snapshot["keys"].append(duplicate_key)
    admission_body["trust_snapshot_id"] = content_id(
        "authority_trust_snapshot",
        trust_snapshot,
    )
    duplicate_trust_key = EnvelopeV1.create(
        "authority_admission",
        admission_body,
    )
    validator.validate(duplicate_trust_key.to_dict())
    with pytest.raises(SemanticProtocolError, match="keys are noncanonical"):
        parse_semantic_envelope(duplicate_trust_key)


def test_relative_dot_path_is_rejected_by_schema_and_all_runtime_boundaries(
    golden: GoldenGraph,
    validator: Draft202012Validator,
) -> None:
    with pytest.raises(EvidenceError):
        SnapshotFileV1(".", _digest("a"), 1)

    snapshot = golden.envelopes["target_snapshot"]
    body = thaw_json(snapshot.body)
    assert type(body) is dict
    body["files"][0]["relative_path"] = "."
    mutated = EnvelopeV1.create("target_snapshot", body)
    _assert_schema_rejects(validator, mutated.to_dict(), "dot target path")
    with pytest.raises(SemanticProtocolError):
        parse_semantic_envelope(mutated)

    candidate = golden.envelopes["candidate"]
    candidate_body = thaw_json(candidate.body)
    assert type(candidate_body) is dict
    candidate_body["relative_path"] = "."
    mutated_candidate = EnvelopeV1.create("candidate", candidate_body)
    _assert_schema_rejects(validator, mutated_candidate.to_dict(), "dot candidate path")
    with pytest.raises(SemanticProtocolError):
        parse_semantic_envelope(mutated_candidate)

    event = golden.events["parse_failed"]
    event_body = thaw_json(event.to_envelope().body)
    assert type(event_body) is dict
    event_body["payload"]["parse_failure"]["relative_path"] = "."
    mutated_event = EnvelopeV1.create("event", event_body)
    _assert_schema_rejects(validator, mutated_event.to_dict(), "dot event path")
    with pytest.raises(SemanticProtocolError):
        parse_semantic_envelope(mutated_event)


def test_schema_rejects_former_framing_only_bypasses(
    golden: GoldenGraph,
    validator: Draft202012Validator,
) -> None:
    arbitrary_event = EnvelopeV1.create("event", {"anything": 1})
    _assert_schema_rejects(validator, arbitrary_event.to_dict(), "arbitrary event body")
    with pytest.raises(SemanticProtocolError):
        parse_semantic_envelope(arbitrary_event)

    trailing_lf = golden.envelopes["analysis_lease"].to_dict()
    trailing_lf["object_id"] += "\n"
    _assert_schema_rejects(validator, trailing_lf, "digest with trailing LF")

    with pytest.raises(ProtocolError, match="unsupported"):
        EnvelopeV1.create("head_checkpoint", {"anything": 1})


def test_schema_valid_runtime_invalid_cases_are_explicitly_retained(
    golden: GoldenGraph,
    validator: Draft202012Validator,
) -> None:
    runtime_only: list[tuple[str, EnvelopeV1]] = []

    grant_body = thaw_json(golden.envelopes["authority_grant_unsigned"].body)
    assert type(grant_body) is dict
    grant_body["assets"].reverse()
    runtime_only.append(
        ("lexical asset order", EnvelopeV1.create("authority_grant", grant_body))
    )

    snapshot_body = thaw_json(golden.envelopes["target_snapshot"].body)
    assert type(snapshot_body) is dict
    snapshot_body["files"].reverse()
    runtime_only.append(
        ("lexical snapshot order", EnvelopeV1.create("target_snapshot", snapshot_body))
    )

    analysis_body = thaw_json(golden.envelopes["analysis_lease"].body)
    assert type(analysis_body) is dict
    analysis_body["expires_at"] = analysis_body["issued_at"]
    runtime_only.append(
        ("analysis time relation", EnvelopeV1.create("analysis_lease", analysis_body))
    )

    candidate_body = thaw_json(golden.envelopes["candidate"].body)
    assert type(candidate_body) is dict
    candidate_body["claim_id"] = _digest("f")
    runtime_only.append(
        ("derived claim identity", EnvelopeV1.create("candidate", candidate_body))
    )

    verification_body = thaw_json(golden.envelopes["verification_lease"].body)
    assert type(verification_body) is dict
    verification_body["evidence_artifact_digests"].reverse()
    runtime_only.append(
        (
            "lexical evidence order",
            EnvelopeV1.create("verification_lease", verification_body),
        )
    )

    event_body = thaw_json(golden.events["analysis_lease_issued"].to_envelope().body)
    assert type(event_body) is dict
    event_body["mission_id"] = _digest("e")
    runtime_only.append(
        ("nested event identity binding", EnvelopeV1.create("event", event_body))
    )

    for label, envelope in runtime_only:
        validator.validate(envelope.to_dict())
        with pytest.raises(SemanticProtocolError) as caught:
            parse_semantic_envelope(envelope)
        assert caught.value.code == "invalid_semantic_object", label


def test_schema_cannot_replace_canonical_wire_or_content_identity_checks(
    golden: GoldenGraph,
    validator: Draft202012Validator,
) -> None:
    tampered_id = golden.envelopes["analysis_lease"].to_dict()
    tampered_id["object_id"] = _digest("f")
    validator.validate(tampered_id)
    with pytest.raises(ProtocolError, match="does not match"):
        parse_semantic_bytes(canonical_dumps(tampered_id))

    mathematical_integer = golden.envelopes["analysis_lease"].to_dict()
    mathematical_integer["body"]["issued_at"] = float(
        mathematical_integer["body"]["issued_at"]
    )
    validator.validate(mathematical_integer)
    with pytest.raises(ProtocolError, match="unsupported JSON value"):
        canonical_dumps(mathematical_integer)
