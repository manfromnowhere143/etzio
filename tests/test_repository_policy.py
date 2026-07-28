"""Known-bad controls for repository provenance and workflow policy."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

import scripts.validate_repository as repository_policy
from etzio.schemas import protocol_v1_schema
from scripts.validate_repository import (
    action_ref_issues,
    author_record_issues,
    decode_schema_document,
    mission_state_issues,
    protocol_schema_contract_issues,
    required_path_issues,
    workflow_permission_issues,
    workflow_syntax_issues,
)


def test_mutable_action_tag_is_rejected():
    issues = action_ref_issues("steps:\n  - uses: actions/checkout@v7\n", "known-bad.yml")
    assert issues
    assert "not pinned" in issues[0]


def test_missing_required_schema_is_rejected(tmp_path: Path):
    required = ("etzio/schemas/protocol.v1.schema.json",)
    assert required_path_issues(tmp_path, required) == [
        "missing required repository file: etzio/schemas/protocol.v1.schema.json"
    ]


def test_protocol_schema_contract_rejects_missing_object_branch():
    schema = deepcopy(protocol_v1_schema())
    schema["oneOf"].pop()

    issues = protocol_schema_contract_issues(schema)

    assert any("dispatch branches" in issue for issue in issues)


def test_protocol_schema_contract_accepts_the_canonical_resource():
    assert protocol_schema_contract_issues(protocol_v1_schema()) == []


def test_protocol_policy_freezes_runtime_resolution_registries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        repository_policy,
        "RESOLUTION_PROFILE_V1",
        "caller_selected_profile",
    )
    monkeypatch.setattr(
        repository_policy,
        "RESOLUTION_BODY_FIELDS_V1",
        frozenset({"mission_id"}),
    )
    monkeypatch.setattr(
        repository_policy,
        "VERIFICATION_ARTIFACT_BINDING_FIELDS_V1",
        frozenset({"artifact_digest"}),
    )
    monkeypatch.setattr(
        repository_policy,
        "TARGET_ARTIFACT_BINDING_FIELDS_V1",
        frozenset({"artifact_digest", "relative_path"}),
    )
    monkeypatch.setattr(
        repository_policy,
        "VERIFICATION_ARTIFACT_TYPES_V1",
        frozenset({"modeled_poc_input"}),
    )

    issues = protocol_schema_contract_issues(protocol_v1_schema())

    assert any("runtime resolution profile" in issue for issue in issues)
    assert any("runtime resolution body fields" in issue for issue in issues)
    assert any(
        "runtime verification artifact binding fields" in issue
        for issue in issues
    )
    assert any(
        "runtime target artifact binding fields" in issue for issue in issues
    )
    assert any(
        "runtime verification artifact type registry" in issue
        for issue in issues
    )


def test_protocol_policy_freezes_runtime_receipt_admission_contracts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body_fields = dict(repository_policy.SEMANTIC_BODY_FIELDS_BY_KIND_V1)
    body_fields["verifier_receipt"] = frozenset({"lease_id"})
    monkeypatch.setattr(
        repository_policy,
        "SEMANTIC_BODY_FIELDS_BY_KIND_V1",
        body_fields,
    )

    event_units = dict(repository_policy.EVENT_UNIT_BY_KIND_V1)
    event_units["verifier_receipt_admitted"] = "AQUILA"
    monkeypatch.setattr(
        repository_policy,
        "EVENT_UNIT_BY_KIND_V1",
        event_units,
    )
    monkeypatch.setattr(
        repository_policy,
        "RECEIPT_ADMISSION_PROFILE_V1",
        "changed_receipt_admission_profile",
    )

    payload_fields = dict(repository_policy.EVENT_PAYLOAD_FIELDS_BY_KIND_V1)
    payload_fields["verifier_receipt_admitted"] = frozenset({"receipt"})
    monkeypatch.setattr(
        repository_policy,
        "EVENT_PAYLOAD_FIELDS_BY_KIND_V1",
        payload_fields,
    )

    nested_fields = dict(
        repository_policy.EVENT_NESTED_ENVELOPE_KIND_BY_FIELD_V1
    )
    nested_fields["verifier_receipt_admitted"] = {
        "receipt": "verification_lease"
    }
    monkeypatch.setattr(
        repository_policy,
        "EVENT_NESTED_ENVELOPE_KIND_BY_FIELD_V1",
        nested_fields,
    )

    issues = protocol_schema_contract_issues(protocol_v1_schema())

    assert any("runtime verifier receipt body fields" in issue for issue in issues)
    assert any("receipt admission event unit" in issue for issue in issues)
    assert any("receipt admission profile" in issue for issue in issues)
    assert any("receipt admission payload fields" in issue for issue in issues)
    assert any(
        "receipt admission nested envelope map" in issue for issue in issues
    )


def test_protocol_policy_freezes_exact_v1_object_and_event_counts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        repository_policy,
        "SUPPORTED_OBJECT_KINDS",
        frozenset(set(repository_policy.SUPPORTED_OBJECT_KINDS) - {"candidate"}),
    )
    monkeypatch.setattr(
        repository_policy,
        "EVENT_UNIT_BY_KIND_V1",
        {
            key: value
            for key, value in repository_policy.EVENT_UNIT_BY_KIND_V1.items()
            if key != "candidate_recorded"
        },
    )

    issues = protocol_schema_contract_issues(protocol_v1_schema())

    assert any("semantic object-kind count" in issue for issue in issues)
    assert any("event-kind count" in issue for issue in issues)


def test_protocol_policy_freezes_runtime_verification_recovery_contracts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_units = dict(repository_policy.EVENT_UNIT_BY_KIND_V1)
    event_units["verification_lease_expired"] = "AQUILA"
    monkeypatch.setattr(
        repository_policy,
        "EVENT_UNIT_BY_KIND_V1",
        event_units,
    )
    payload_fields = dict(
        repository_policy.EVENT_PAYLOAD_FIELDS_BY_KIND_V1
    )
    payload_fields["verification_lease_cancelled"] = frozenset(
        {"verification_lease_id"}
    )
    monkeypatch.setattr(
        repository_policy,
        "EVENT_PAYLOAD_FIELDS_BY_KIND_V1",
        payload_fields,
    )
    nested = dict(
        repository_policy.EVENT_NESTED_ENVELOPE_KIND_BY_FIELD_V1
    )
    nested["verification_lease_reassigned"] = {
        "lease": "analysis_lease"
    }
    monkeypatch.setattr(
        repository_policy,
        "EVENT_NESTED_ENVELOPE_KIND_BY_FIELD_V1",
        nested,
    )
    monkeypatch.setattr(
        repository_policy,
        "VERIFICATION_LEASE_CANCELLATION_REASON_V1",
        "verifier_unavailable",
    )
    monkeypatch.setattr(
        repository_policy,
        "VERIFICATION_LEASE_REASSIGNMENT_REASONS_V1",
        frozenset({"active_lease_superseded"}),
    )
    monkeypatch.setattr(
        repository_policy,
        "MISSION_CLOSED_STATUSES_V1",
        frozenset({"completed"}),
    )

    issues = protocol_schema_contract_issues(protocol_v1_schema())

    assert any("recovery event units" in issue for issue in issues)
    assert any("recovery payload fields" in issue for issue in issues)
    assert any("recovery nested envelopes" in issue for issue in issues)
    assert any("runtime verification cancellation reason" in issue for issue in issues)
    assert any("runtime verification reassignment reasons" in issue for issue in issues)
    assert any("runtime mission closure statuses" in issue for issue in issues)


def test_protocol_policy_rejects_recovery_reason_reference_and_status_drift():
    schema = deepcopy(protocol_v1_schema())
    definitions = schema["$defs"]
    definitions["event_payload_verification_lease_cancelled"][
        "properties"
    ]["reason_code"] = {"const": "verifier_unavailable"}
    reassigned = definitions[
        "event_payload_verification_lease_reassigned"
    ]["properties"]
    reassigned["reason_code"]["enum"] = ["active_lease_superseded"]
    reassigned["predecessor_verification_lease_id"] = {
        "$ref": "#/$defs/canonical_nonblank_string"
    }
    reassigned["verifier_trust_snapshot"] = {
        "$ref": "#/$defs/sha256_id"
    }
    definitions["event_payload_mission_closed"]["properties"]["status"][
        "enum"
    ] = ["completed"]

    issues = protocol_schema_contract_issues(schema)

    assert any("cancellation reason" in issue for issue in issues)
    assert any("reassignment reasons" in issue for issue in issues)
    assert any("predecessor reference" in issue for issue in issues)
    assert any("reassignment trust reference" in issue for issue in issues)
    assert any("mission closure statuses" in issue for issue in issues)


def test_protocol_schema_contract_rejects_resolution_contract_drift():
    schema = deepcopy(protocol_v1_schema())
    definitions = schema["$defs"]
    definitions["verification_artifact_type"]["enum"].append("caller_defined")
    definitions["verification_artifact_binding"]["required"].remove("size")
    definitions["verification_artifact_binding"]["properties"]["size"][
        "minimum"
    ] = 0
    definitions["verification_target_artifact_binding"]["properties"][
        "artifact_type"
    ] = {"type": "string"}
    definitions["modeled_poc_artifact_binding"]["allOf"][1]["properties"][
        "artifact_type"
    ] = {"const": "modeled_environment_spec"}
    definitions["modeled_termination_output_artifact_binding"]["allOf"][1][
        "properties"
    ]["artifact_type"] = {"const": "modeled_execution_output"}
    resolution = definitions["verification_artifact_resolution_body"]
    resolution["properties"]["resolution_profile"] = {"type": "string"}
    resolution["properties"]["evidence_artifacts"]["maxItems"] = 257

    issues = protocol_schema_contract_issues(schema)

    assert any("artifact type registry drifted" in issue for issue in issues)
    assert any("artifact binding required fields" in issue for issue in issues)
    assert any("artifact size contract drifted" in issue for issue in issues)
    assert any(
        "target artifact artifact_type contract" in issue for issue in issues
    )
    assert any("modeled poc artifact binding role contract" in issue for issue in issues)
    assert any(
        "modeled termination output artifact binding role contract" in issue
        for issue in issues
    )
    assert any("resolution resolution_profile contract" in issue for issue in issues)
    assert any("resolution evidence_artifacts contract" in issue for issue in issues)


def test_protocol_schema_contract_rejects_receipt_admission_contract_drift():
    schema = deepcopy(protocol_v1_schema())
    definitions = schema["$defs"]
    receipt = definitions["verifier_receipt_body"]
    receipt["required"].remove("artifact_resolution_id")
    receipt["properties"]["execution_output_digest"] = {"type": "string"}
    for field in (
        "effect_output_size",
        "execution_output_size",
        "measured_environment_output_size",
        "termination_output_size",
    ):
        receipt["properties"][field] = {
            "type": "integer",
            "minimum": 0,
            "maximum": 67_108_865,
        }

    payload = definitions["event_payload_verifier_receipt_admitted"]
    payload["required"].remove("termination_output_artifact")
    payload["properties"]["adjudication_profile"] = {"type": "string"}
    payload["properties"]["decision_trust_snapshot"] = {"type": "object"}
    payload["properties"]["effect_output_artifact"] = {
        "$ref": "#/$defs/modeled_execution_output_artifact_binding"
    }

    signed_receipt = definitions["signed_verifier_receipt_envelope"]
    constraints = signed_receipt["allOf"][1]["properties"]
    constraints["object_kind"]["const"] = "verification_lease"
    constraints["body"]["$ref"] = "#/$defs/verification_lease_body"
    constraints["attestations"]["$ref"] = "#/$defs/no_attestations"

    issues = protocol_schema_contract_issues(schema)

    assert any("verifier receipt body required fields" in issue for issue in issues)
    assert any(
        "verifier receipt execution_output_digest contract" in issue
        for issue in issues
    )
    for field in (
        "effect_output_size",
        "execution_output_size",
        "measured_environment_output_size",
        "termination_output_size",
    ):
        assert any(
            f"verifier receipt {field} contract" in issue
            for issue in issues
        )
    assert any(
        "receipt admission event payload required fields" in issue
        for issue in issues
    )
    assert any(
        "receipt admission adjudication_profile contract" in issue
        for issue in issues
    )
    assert any(
        "receipt admission decision_trust_snapshot contract" in issue
        for issue in issues
    )
    assert any(
        "receipt admission effect_output_artifact contract" in issue
        for issue in issues
    )
    assert any(
        "verifier_receipt_admitted.receipt" in issue
        and "discriminator" in issue
        for issue in issues
    )
    assert any(
        "verifier_receipt_admitted.receipt" in issue
        and "body reference" in issue
        for issue in issues
    )
    assert any(
        "verifier_receipt_admitted.receipt" in issue
        and "one Ed25519 attestation" in issue
        for issue in issues
    )


def test_protocol_schema_contract_rejects_root_field_and_version_drift():
    schema = deepcopy(protocol_v1_schema())
    schema["required"].remove("body")
    schema["properties"]["unexpected"] = {"type": "boolean"}
    schema["properties"]["object_version"]["const"] = 2

    issues = protocol_schema_contract_issues(schema)

    assert any("envelope required fields" in issue for issue in issues)
    assert any("envelope declared fields" in issue for issue in issues)
    assert any("object_version contract" in issue for issue in issues)


def test_protocol_schema_contract_rejects_nonfirst_body_field_drift():
    schema = deepcopy(protocol_v1_schema())
    schema["$defs"]["candidate_body"]["required"].remove("symbol")

    issues = protocol_schema_contract_issues(schema)

    assert any("candidate body required fields" in issue for issue in issues)


def test_protocol_schema_contract_rejects_open_or_extra_body_fields():
    schema = deepcopy(protocol_v1_schema())
    candidate = schema["$defs"]["candidate_body"]
    candidate["additionalProperties"] = True
    candidate["properties"]["ambient_credentials"] = {"type": "boolean"}

    issues = protocol_schema_contract_issues(schema)

    assert any("candidate body must reject unknown" in issue for issue in issues)
    assert any("candidate body declared fields" in issue for issue in issues)


def test_protocol_schema_contract_rejects_case_reference_drift():
    schema = deepcopy(protocol_v1_schema())
    schema["$defs"]["candidate_case"]["properties"]["body"]["$ref"] = (
        "#/$defs/analysis_lease_body"
    )

    issues = protocol_schema_contract_issues(schema)

    assert any("candidate case body reference" in issue for issue in issues)


def test_protocol_schema_contract_rejects_event_common_body_weakening():
    schema = deepcopy(protocol_v1_schema())
    event = schema["$defs"]["event_body_common"]
    event["required"].remove("payload")
    event["additionalProperties"] = True

    issues = protocol_schema_contract_issues(schema)

    assert any("event body required fields" in issue for issue in issues)
    assert any("event body must reject unknown" in issue for issue in issues)


def test_protocol_schema_contract_rejects_event_common_enum_drift():
    schema = deepcopy(protocol_v1_schema())
    event_properties = schema["$defs"]["event_body_common"]["properties"]
    event_properties["kind"]["enum"].append("untyped_event")
    event_properties["unit"]["enum"].append("UNTRUSTED")

    issues = protocol_schema_contract_issues(schema)

    assert any("event common kind enum" in issue for issue in issues)
    assert any("event common unit enum" in issue for issue in issues)


def test_protocol_schema_contract_rejects_inline_nested_event_envelope_drift():
    schema = deepcopy(protocol_v1_schema())
    variants = schema["$defs"]["event_variants"]["oneOf"]
    verification_lease_issued = next(
        branch
        for branch in variants
        if branch["properties"]["kind"]["const"] == "verification_lease_issued"
    )
    payload_name = verification_lease_issued["properties"]["payload"][
        "$ref"
    ].removeprefix("#/$defs/")
    nested = schema["$defs"][payload_name]["properties"]["lease"]
    constraints = nested["allOf"][1]["properties"]
    constraints["object_kind"]["const"] = "analysis_lease"
    constraints["body"]["$ref"] = "#/$defs/analysis_lease_body"
    constraints["attestations"]["$ref"] = "#/$defs/one_ed25519_attestation"

    issues = protocol_schema_contract_issues(schema)

    assert any(
        "verification_lease_issued.lease" in issue and "discriminator" in issue
        for issue in issues
    )
    assert any(
        "verification_lease_issued.lease" in issue and "body reference" in issue
        for issue in issues
    )
    assert any(
        "verification_lease_issued.lease" in issue and "unattested" in issue
        for issue in issues
    )


def test_protocol_schema_contract_rejects_resolution_event_envelope_drift():
    schema = deepcopy(protocol_v1_schema())
    variants = schema["$defs"]["event_variants"]["oneOf"]
    resolved = next(
        branch
        for branch in variants
        if branch["properties"]["kind"]["const"]
        == "verification_artifacts_resolved"
    )
    payload_name = resolved["properties"]["payload"]["$ref"].removeprefix(
        "#/$defs/"
    )
    nested = schema["$defs"][payload_name]["properties"]["resolution"]
    constraints = nested["allOf"][1]["properties"]
    constraints["object_kind"]["const"] = "verification_lease"
    constraints["body"]["$ref"] = "#/$defs/verification_lease_body"
    constraints["attestations"]["$ref"] = "#/$defs/one_ed25519_attestation"

    issues = protocol_schema_contract_issues(schema)

    assert any(
        "verification_artifacts_resolved.resolution" in issue
        and "discriminator" in issue
        for issue in issues
    )
    assert any(
        "verification_artifacts_resolved.resolution" in issue
        and "body reference" in issue
        for issue in issues
    )
    assert any(
        "verification_artifacts_resolved.resolution" in issue
        and "unattested" in issue
        for issue in issues
    )


def test_protocol_schema_contract_rejects_verifier_trust_contract_drift():
    schema = deepcopy(protocol_v1_schema())
    snapshot = schema["$defs"]["verifier_trust_snapshot"]
    snapshot["required"].remove("revoked_lease_ids")
    snapshot["additionalProperties"] = True
    key = schema["$defs"]["verifier_trust_key"]
    key["required"].remove("verifier_id")

    issues = protocol_schema_contract_issues(schema)

    assert any(
        "verifier trust snapshot required fields" in issue
        for issue in issues
    )
    assert any(
        "verifier trust snapshot must reject unknown" in issue
        for issue in issues
    )
    assert any(
        "verifier trust key required fields" in issue
        for issue in issues
    )


def test_protocol_schema_contract_rejects_verifier_trust_reference_drift():
    schema = deepcopy(protocol_v1_schema())
    payload = schema["$defs"]["event_payload_verification_lease_issued"]
    payload["properties"]["verifier_trust_snapshot"] = {"type": "object"}
    payload["properties"]["verifier_trust_snapshot_id"] = {"type": "string"}

    issues = protocol_schema_contract_issues(schema)

    assert any("event trust snapshot reference" in issue for issue in issues)
    assert any(
        "event trust snapshot ID reference" in issue for issue in issues
    )


def test_protocol_schema_contract_rejects_direct_ref_to_signed_nested_envelope():
    schema = deepcopy(protocol_v1_schema())
    variants = schema["$defs"]["event_variants"]["oneOf"]
    authority_admitted = next(
        branch
        for branch in variants
        if branch["properties"]["kind"]["const"] == "authority_admitted"
    )
    payload_name = authority_admitted["properties"]["payload"]["$ref"].removeprefix(
        "#/$defs/"
    )
    schema["$defs"][payload_name]["properties"]["grant"] = {
        "$ref": "#/$defs/signed_authority_grant_envelope"
    }

    issues = protocol_schema_contract_issues(schema)

    assert any(
        "authority_admitted.grant" in issue and "unattested" in issue
        for issue in issues
    )


def test_protocol_schema_contract_rejects_attestation_policy_drift():
    schema = deepcopy(protocol_v1_schema())
    schema["$defs"]["candidate_case"]["properties"]["attestations"] = {
        "$ref": "#/$defs/one_ed25519_attestation"
    }
    schema["$defs"]["authority_grant_case"]["properties"]["attestations"][
        "oneOf"
    ].pop()
    schema["$defs"]["one_ed25519_attestation"]["maxItems"] = 2

    issues = protocol_schema_contract_issues(schema)

    assert any("candidate must remain unattested" in issue for issue in issues)
    assert any("authority_grant attestation policy" in issue for issue in issues)
    assert any("one-attestation contract" in issue for issue in issues)


def test_protocol_schema_contract_rejects_attestation_shape_weakening():
    schema = deepcopy(protocol_v1_schema())
    attestation = schema["$defs"]["ed25519_attestation"]
    attestation["required"].remove("signature_b64")
    attestation["additionalProperties"] = True

    issues = protocol_schema_contract_issues(schema)

    assert any("attestation required fields" in issue for issue in issues)
    assert any("attestation must reject unknown" in issue for issue in issues)


def test_protocol_schema_contract_rejects_event_unit_and_payload_drift():
    schema = deepcopy(protocol_v1_schema())
    variant = schema["$defs"]["event_variants"]["oneOf"][0]
    variant["properties"]["unit"]["const"] = "ETZIO"
    payload_name = variant["properties"]["payload"]["$ref"].removeprefix("#/$defs/")
    schema["$defs"][payload_name]["required"].append("unexpected")
    schema["$defs"][payload_name]["additionalProperties"] = True

    issues = protocol_schema_contract_issues(schema)

    assert any("event units" in issue for issue in issues)
    assert any("event payload fields" in issue for issue in issues)
    assert any("event payload must reject unknown" in issue for issue in issues)


def test_schema_decoder_rejects_duplicate_object_keys():
    with pytest.raises(ValueError, match="duplicate"):
        decode_schema_document('{"type":"object","type":"array"}')


def test_exact_action_commit_and_local_action_are_accepted():
    text = (
        "steps:\n"
        "  - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0\n"
        "  - uses: ./actions/local\n"
    )
    assert action_ref_issues(text) == []


def test_flow_style_mutable_action_tag_is_rejected():
    text = "steps: [{ uses: actions/checkout@v7 }]\n"
    assert action_ref_issues(text, "known-bad.yaml")


def test_spaced_policy_keys_cannot_bypass_checks():
    text = (
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  test:\n"
        "    permissions : write-all\n"
        "    steps:\n"
        "      - uses : actions/checkout@v7\n"
    )
    assert action_ref_issues(text, "known-bad.yaml")
    assert workflow_permission_issues(text, "known-bad.yaml")
    assert workflow_syntax_issues(text, "known-bad.yaml")


def test_quoted_policy_keys_are_rejected():
    text = (
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  test:\n"
        '    "permissions": write-all\n'
        "    steps:\n"
        '      - "uses": actions/checkout@v7\n'
    )
    issues = workflow_syntax_issues(text, "known-bad.yaml")
    assert len(issues) == 2
    assert all("quoted YAML keys" in issue for issue in issues)


def test_escaped_quoted_action_key_is_rejected():
    text = (
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        '      - "u\\u0073es": actions/checkout@v7\n'
    )
    issues = workflow_syntax_issues(text, "known-bad.yaml")
    assert len(issues) == 1
    assert "quoted YAML keys" in issues[0]


def test_complex_action_key_is_rejected():
    text = (
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - ? uses\n"
        "        : actions/checkout@v7\n"
    )
    issues = workflow_syntax_issues(text, "known-bad.yaml")
    assert len(issues) == 2
    assert all("complex YAML keys" in issue for issue in issues)


def test_coauthor_and_wrong_author_are_rejected():
    records = [
        ("Someone Else", "other@example.com", "change"),
        (
            "Daniel Wahnich",
            "cogitoergosum143@gmail.com",
            "change\n\nCo-Authored-By: Bot <bot@example.com>",
        ),
    ]
    issues = author_record_issues(records)
    assert any("unexpected commit author" in issue for issue in issues)
    assert any("Co-Authored-By" in issue for issue in issues)


def test_write_permissions_are_rejected_even_with_read_only_contents():
    text = (
        "permissions:\n"
        "  contents: read\n"
        "  pull-requests: write\n"
        "jobs:\n"
        "  test:\n"
        "    permissions: write-all\n"
    )
    issues = workflow_permission_issues(text, "known-bad.yaml")
    assert len(issues) == 2
    assert all("write" in issue for issue in issues)


def test_explicit_read_only_permissions_are_accepted():
    text = "permissions:\n  contents: read\njobs:\n  test:\n    runs-on: ubuntu-24.04\n"
    assert workflow_permission_issues(text) == []


def test_escaped_quoted_write_permission_is_rejected():
    text = (
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  test:\n"
        "    permissions:\n"
        '      contents: "wri\\u0074e"\n'
    )
    issues = workflow_permission_issues(text, "known-bad.yaml")
    assert len(issues) == 1
    assert "unsupported contents permission" in issues[0]


def test_yaml_alias_cannot_hide_write_permission():
    text = (
        "env:\n"
        "  LEVEL: &level write\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  test:\n"
        "    permissions:\n"
        "      contents: *level\n"
    )
    issues = workflow_syntax_issues(text, "known-bad.yaml")
    assert len(issues) == 2
    assert all("anchors and aliases" in issue for issue in issues)


def test_wrong_project_state_is_rejected():
    issues = mission_state_issues(
        {
            "schema_version": "etzio.mission_state.v1",
            "engine": "AnotherProject",
            "canonical_branch": "master",
        }
    )
    assert len(issues) == 3
