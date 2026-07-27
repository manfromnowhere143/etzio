"""Fail-closed repository policy checks for the Etzio foundation.

This validator concerns repository bytes and provenance. It does not establish detection
quality, sandbox safety, authorization validity, or readiness for a live target.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

from jsonschema.exceptions import SchemaError
from jsonschema.validators import validator_for

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from etzio.evidence import VERIFICATION_ARTIFACT_TYPES_V1  # noqa: E402
from etzio.kernel.events_v1 import (  # noqa: E402
    EVENT_NESTED_ENVELOPE_KIND_BY_FIELD_V1,
    EVENT_PAYLOAD_FIELDS_BY_KIND_V1,
    EVENT_UNIT_BY_KIND_V1,
)
from etzio.protocol import (  # noqa: E402
    ENVELOPE_FIELDS_V1,
    OPTIONALLY_ATTESTED_OBJECT_KINDS_V1,
    SEMANTIC_BODY_FIELDS_BY_KIND_V1,
    SUPPORTED_OBJECT_KINDS,
)
from etzio.verification import (  # noqa: E402
    VERIFIER_TRUST_KEY_FIELDS_V1,
    VERIFIER_TRUST_SNAPSHOT_FIELDS_V1,
)
from etzio.verification_artifacts import (  # noqa: E402
    RESOLUTION_BODY_FIELDS_V1,
    RESOLUTION_PROFILE_V1,
    TARGET_ARTIFACT_BINDING_FIELDS_V1,
    TARGET_ARTIFACT_TYPE_V1,
    VERIFICATION_ARTIFACT_BINDING_FIELDS_V1,
)

EXPECTED_AUTHOR = ("Daniel Wahnich", "cogitoergosum143@gmail.com")
ACTION_REF = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
MARKDOWN_LINK = re.compile(r"!?\[[^\]]*]\(([^)]+)\)")
REQUIRED_PATHS = (
    "AGENTS.md",
    "AUTHORS.md",
    "CHARTER.md",
    "CONTRIBUTING.md",
    "LICENSE.md",
    "MANIFEST.in",
    "README.md",
    "SECURITY.md",
    "docs/ARCHITECTURE.md",
    "docs/FRONTIER_BASELINE.md",
    "docs/MISSION_STATE.json",
    "docs/ROADMAP.md",
    "docs/SESSION_HANDOFF.md",
    "docs/decisions/0001-foundation-integrity-before-breadth.md",
    "docs/decisions/0002-canonical-governed-fixture-boundary.md",
    "docs/decisions/0003-semantic-wire-schema-and-typed-kind-closure.md",
    "docs/decisions/0004-kernel-issued-verification-leases.md",
    "docs/decisions/README.md",
    "schemas/finding.schema.json",
    "etzio/schemas/__init__.py",
    "etzio/schemas/protocol.v1.schema.json",
    "schemas/target-contract.schema.json",
    "schemas/verdict.schema.json",
    ".github/CODEOWNERS",
    ".github/workflows/ci.yml",
    "tools/ci/requirements-ci.in",
    "tools/ci/requirements-ci.lock",
)
PROTOCOL_SCHEMA_PATH = ROOT / "etzio/schemas/protocol.v1.schema.json"
LEGACY_SCHEMA_PATHS = frozenset(
    {
        ROOT / "schemas/finding.schema.json",
        ROOT / "schemas/target-contract.schema.json",
        ROOT / "schemas/verdict.schema.json",
    }
)
EXPECTED_SEMANTIC_OBJECT_KIND_COUNT_V1 = 9
EXPECTED_EVENT_KIND_COUNT_V1 = 14
EXPECTED_RESOLUTION_PROFILE_V1 = "modeled_fixture_typed_cas_v1"
EXPECTED_VERIFICATION_ARTIFACT_TYPES_V1 = frozenset(
    {
        "modeled_effect_oracle_spec",
        "modeled_environment_spec",
        "modeled_poc_input",
        "modeled_supporting_evidence_input",
        "repository_fixture_source",
    }
)
EXPECTED_VERIFICATION_ARTIFACT_BINDING_FIELDS_V1 = frozenset(
    {"artifact_digest", "artifact_type", "size"}
)
EXPECTED_TARGET_ARTIFACT_BINDING_FIELDS_V1 = frozenset(
    {"artifact_digest", "artifact_type", "relative_path", "size"}
)
EXPECTED_RESOLUTION_BODY_FIELDS_V1 = frozenset(
    {
        "authority_id",
        "candidate_id",
        "effect_oracle_artifact",
        "environment_artifact",
        "evidence_artifacts",
        "mission_id",
        "poc_artifact",
        "resolution_profile",
        "resolved_at",
        "target_artifacts",
        "target_snapshot_id",
        "verification_lease_id",
    }
)


def required_path_issues(root: Path, required: tuple[str, ...] = REQUIRED_PATHS) -> list[str]:
    return [
        f"missing required repository file: {relative}"
        for relative in required
        if not (root / relative).is_file()
    ]


def _workflow_structure_lines(text: str) -> list[tuple[int, str]]:
    """Return YAML structure lines while excluding literal/folded block-scalar bodies."""
    structural: list[tuple[int, str]] = []
    block_scalar_indent: int | None = None
    for number, line in enumerate(text.splitlines(), 1):
        indent = len(line) - len(line.lstrip())
        if block_scalar_indent is not None:
            if not line.strip() or indent > block_scalar_indent:
                continue
            block_scalar_indent = None
        code = line.split("#", 1)[0].rstrip()
        if not code.strip():
            continue
        structural.append((number, code))
        if re.match(r"^\s*[A-Za-z0-9_-]+\s*:\s*[>|][+-]?\s*$", code):
            block_scalar_indent = indent
    return structural


def action_ref_issues(text: str, source: str = "workflow") -> list[str]:
    issues: list[str] = []
    for number, code in _workflow_structure_lines(text):
        matches = re.finditer(r"(?:^|[\s{,\[])uses\s*:\s*([^\s,}\]]+)", code)
        for match in matches:
            reference = match.group(1)
            if reference.startswith("./"):
                continue
            if not ACTION_REF.fullmatch(reference):
                issues.append(
                    f"{source}:{number}: action is not pinned to a 40-character commit SHA: {reference}"
                )
    return issues


def workflow_syntax_issues(text: str, source: str = "workflow") -> list[str]:
    """Restrict workflows to the block-style YAML subset the policy parser can resolve."""
    issues: list[str] = []
    for number, code in _workflow_structure_lines(text):
        if re.search(r"(?:^|\s)[&*][A-Za-z0-9_-]+", code):
            issues.append(f"{source}:{number}: YAML anchors and aliases are not permitted")
        if re.search(r"(^|\s)<<\s*:", code):
            issues.append(f"{source}:{number}: YAML merge keys are not permitted")
        quoted_key = re.search(r'"(?:\\.|[^"\\])*"\s*:', code) or re.search(
            r"'(?:''|[^'])*'\s*:",
            code,
        )
        if quoted_key:
            issues.append(f"{source}:{number}: quoted YAML keys are not permitted")
        if re.search(r"\b[A-Za-z0-9_-]+\s+:", code):
            issues.append(f"{source}:{number}: whitespace before a YAML key colon is not permitted")
        without_expressions = re.sub(r"\$\{\{.*?\}\}", "", code)
        if any(character in without_expressions for character in "{}[]"):
            issues.append(f"{source}:{number}: YAML flow collections are not permitted")
        if re.search(r"(?:^|\s)![!<A-Za-z]", code):
            issues.append(f"{source}:{number}: explicit YAML tags are not permitted")
        if re.search(r"\b(?:uses|permissions)\s*:\s*[>|]", code):
            issues.append(f"{source}:{number}: policy keys may not use block scalar values")
        if re.match(r"^\s*(?:-\s*)?[?:]\s", code):
            issues.append(f"{source}:{number}: explicit complex YAML keys are not permitted")
    return issues


def workflow_permission_issues(text: str, source: str = "workflow") -> list[str]:
    """Require a read-only workflow token and reject write elevation at any scope."""
    issues: list[str] = []
    lines = _workflow_structure_lines(text)
    top_level_contents: str | None = None
    saw_top_level_permissions = False

    for index, (number, line) in enumerate(lines):
        header = re.match(
            r"^(?P<indent>\s*)permissions\s*:\s*(?P<value>[^#]*?)\s*(?:#.*)?$",
            line,
        )
        if not header:
            continue
        indent = len(header.group("indent"))
        value = header.group("value").strip()
        if indent == 0:
            saw_top_level_permissions = True
        if value:
            if value != "read-all":
                issues.append(f"{source}:{number}: unsupported permissions value: {value}")
            if indent == 0:
                issues.append(f"{source}:{number}: top-level permissions must use an explicit map")
            continue

        for child_number, child in lines[index + 1 :]:
            child_indent = len(child) - len(child.lstrip())
            if child_indent <= indent:
                break
            entry = re.match(r"^\s*([a-zA-Z0-9_-]+)\s*:\s*([^#\s]+)", child)
            if not entry:
                continue
            permission, level = entry.groups()
            if level not in {"none", "read"}:
                issues.append(f"{source}:{child_number}: unsupported {permission} permission: {level}")
            if indent == 0 and permission == "contents":
                top_level_contents = level

    if not saw_top_level_permissions:
        issues.append(f"{source}: missing explicit top-level permissions")
    elif top_level_contents != "read":
        issues.append(f"{source}: top-level contents permission must be read")
    return issues


def author_record_issues(records: list[tuple[str, str, str]]) -> list[str]:
    issues: list[str] = []
    for name, email, body in records:
        if (name, email) != EXPECTED_AUTHOR:
            issues.append(f"unexpected commit author: {name} <{email}>")
        if re.search(r"(?im)^co-authored-by\s*:", body):
            issues.append("commit contains a Co-Authored-By trailer")
    return issues


def mission_state_issues(state: object) -> list[str]:
    if not isinstance(state, dict):
        return ["docs/MISSION_STATE.json must contain a JSON object"]
    issues: list[str] = []
    if state.get("schema_version") != "etzio.mission_state.v2":
        issues.append("docs/MISSION_STATE.json must use etzio.mission_state.v2")
    if state.get("engine") != "Etzio":
        issues.append("docs/MISSION_STATE.json does not identify Etzio")
    if state.get("canonical_branch") != "main":
        issues.append("docs/MISSION_STATE.json must identify main as the canonical branch")
    return issues


def _git_author_records() -> list[tuple[str, str, str]]:
    raw = subprocess.check_output(
        ["git", "log", "--format=%an%x00%ae%x00%B%x1e"],
        cwd=ROOT,
    ).decode("utf-8")
    records: list[tuple[str, str, str]] = []
    for record in raw.split("\x1e"):
        record = record.strip()
        if not record:
            continue
        fields = record.split("\x00", 2)
        if len(fields) != 3:
            records.append(("<malformed>", "<malformed>", record))
        else:
            records.append((fields[0], fields[1], fields[2]))
    return records


def _unique_schema_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate schema object key {key!r}")
        result[key] = value
    return result


def decode_schema_document(text: str) -> object:
    """Decode one schema document without silently overwriting duplicate keys."""

    return json.loads(text, object_pairs_hook=_unique_schema_object)


def _exact_object_contract_issues(
    value: object,
    expected_fields: frozenset[str],
    label: str,
) -> list[str]:
    """Require a closed JSON object whose declared and required fields are identical."""

    if type(value) is not dict:
        return [f"{label} must be an object schema"]
    issues: list[str] = []
    if value.get("type") != "object":
        issues.append(f"{label} must declare object type")
    if value.get("additionalProperties") is not False:
        issues.append(f"{label} must reject unknown fields")

    required = value.get("required")
    if (
        type(required) is not list
        or any(type(field) is not str for field in required)
        or len(required) != len(expected_fields)
        or frozenset(required) != expected_fields
    ):
        issues.append(f"{label} required fields differ from the runtime contract")

    properties = value.get("properties")
    if type(properties) is not dict or frozenset(properties) != expected_fields:
        issues.append(f"{label} declared fields differ from the runtime contract")
    return issues


def _resolve_direct_local_ref(
    value: object,
    definitions: dict[str, object],
) -> object:
    """Resolve an exact local-definition reference, retaining fail-closed structure."""

    seen: set[str] = set()
    while type(value) is dict and frozenset(value) == frozenset({"$ref"}):
        reference = value.get("$ref")
        if type(reference) is not str or not reference.startswith("#/$defs/"):
            return None
        name = reference.removeprefix("#/$defs/")
        if not name or "/" in name or name in seen:
            return None
        seen.add(name)
        value = definitions.get(name)
    return value


def _nested_event_envelope_contract_issues(
    value: object,
    definitions: dict[str, object],
    expected_kind: str,
    label: str,
) -> list[str]:
    """Require an unsigned, exactly typed envelope in a retained event payload."""

    resolved = _resolve_direct_local_ref(value, definitions)
    if type(resolved) is not dict:
        return [f"{label} must contain a typed nested envelope contract"]

    branches = resolved.get("allOf")
    if type(branches) is not list or len(branches) != 2:
        return [f"{label} nested envelope composition drifted"]

    frame_ref = {"$ref": "#/$defs/envelope_frame"}
    frame_count = sum(branch == frame_ref for branch in branches)
    contract_branches = [branch for branch in branches if branch != frame_ref]
    if frame_count != 1 or len(contract_branches) != 1:
        return [f"{label} nested envelope frame drifted"]

    contract = _resolve_direct_local_ref(contract_branches[0], definitions)
    if (
        type(contract) is not dict
        or frozenset(contract) != frozenset({"properties"})
        or type(contract.get("properties")) is not dict
    ):
        return [f"{label} nested envelope constraints drifted"]

    properties = contract["properties"]
    expected_fields = frozenset({"object_kind", "body", "attestations"})
    issues: list[str] = []
    if frozenset(properties) != expected_fields:
        issues.append(f"{label} nested envelope constraint fields drifted")
    if properties.get("object_kind") != {"const": expected_kind}:
        issues.append(f"{label} nested envelope discriminator drifted")
    if properties.get("body") != {"$ref": f"#/$defs/{expected_kind}_body"}:
        issues.append(f"{label} nested envelope body reference drifted")
    if properties.get("attestations") != {"$ref": "#/$defs/no_attestations"}:
        issues.append(f"{label} nested envelope must remain unattested")
    return issues


def _verification_artifact_schema_contract_issues(
    definitions: dict[str, object],
) -> list[str]:
    """Freeze the structural side of the typed-CAS resolution record."""

    issues: list[str] = []
    artifact_type = definitions.get("verification_artifact_type")
    if type(artifact_type) is not dict:
        issues.append("protocol-v1 verification artifact type registry is malformed")
    else:
        raw_types = artifact_type.get("enum")
        if (
            artifact_type.get("type") != "string"
            or type(raw_types) is not list
            or any(type(value) is not str for value in raw_types)
            or len(raw_types) != len(EXPECTED_VERIFICATION_ARTIFACT_TYPES_V1)
            or frozenset(raw_types) != EXPECTED_VERIFICATION_ARTIFACT_TYPES_V1
        ):
            issues.append(
                "protocol-v1 verification artifact type registry drifted"
            )

    artifact_binding = definitions.get("verification_artifact_binding")
    issues.extend(
        _exact_object_contract_issues(
            artifact_binding,
            EXPECTED_VERIFICATION_ARTIFACT_BINDING_FIELDS_V1,
            "protocol-v1 verification artifact binding",
        )
    )
    if type(artifact_binding) is dict and type(
        artifact_binding.get("properties")
    ) is dict:
        properties = artifact_binding["properties"]
        if properties.get("artifact_digest") != {"$ref": "#/$defs/sha256_id"}:
            issues.append(
                "protocol-v1 verification artifact digest reference drifted"
            )
        if properties.get("artifact_type") != {
            "$ref": "#/$defs/verification_artifact_type"
        }:
            issues.append(
                "protocol-v1 verification artifact type reference drifted"
            )
        if properties.get("size") != {
            "type": "integer",
            "minimum": 1,
            "maximum": 67108864,
        }:
            issues.append("protocol-v1 verification artifact size contract drifted")

    target_binding = definitions.get("verification_target_artifact_binding")
    issues.extend(
        _exact_object_contract_issues(
            target_binding,
            EXPECTED_TARGET_ARTIFACT_BINDING_FIELDS_V1,
            "protocol-v1 verification target artifact binding",
        )
    )
    if type(target_binding) is dict and type(
        target_binding.get("properties")
    ) is dict:
        properties = target_binding["properties"]
        expected_target_properties = {
            "artifact_digest": {"$ref": "#/$defs/sha256_id"},
            "artifact_type": {"const": "repository_fixture_source"},
            "relative_path": {"$ref": "#/$defs/snapshot_relative_path"},
            "size": {
                "type": "integer",
                "minimum": 0,
                "maximum": 67108864,
            },
        }
        for field, expected in expected_target_properties.items():
            if properties.get(field) != expected:
                issues.append(
                    "protocol-v1 verification target artifact "
                    f"{field} contract drifted"
                )

    role_bindings = {
        "modeled_effect_oracle_artifact_binding": "modeled_effect_oracle_spec",
        "modeled_environment_artifact_binding": "modeled_environment_spec",
        "modeled_poc_artifact_binding": "modeled_poc_input",
        "modeled_supporting_evidence_artifact_binding": (
            "modeled_supporting_evidence_input"
        ),
    }
    for name, expected_type in role_bindings.items():
        value = definitions.get(name)
        expected = [
            {"$ref": "#/$defs/verification_artifact_binding"},
            {"properties": {"artifact_type": {"const": expected_type}}},
        ]
        if type(value) is not dict or value.get("allOf") != expected:
            issues.append(
                f"protocol-v1 {name.replace('_', ' ')} role contract drifted"
            )

    resolution = definitions.get("verification_artifact_resolution_body")
    issues.extend(
        _exact_object_contract_issues(
            resolution,
            EXPECTED_RESOLUTION_BODY_FIELDS_V1,
            "protocol-v1 verification artifact resolution body",
        )
    )
    if type(resolution) is not dict or type(resolution.get("properties")) is not dict:
        return issues
    properties = resolution["properties"]
    exact_properties = {
        "authority_id": {"$ref": "#/$defs/sha256_id"},
        "candidate_id": {"$ref": "#/$defs/sha256_id"},
        "effect_oracle_artifact": {
            "$ref": "#/$defs/modeled_effect_oracle_artifact_binding"
        },
        "environment_artifact": {
            "$ref": "#/$defs/modeled_environment_artifact_binding"
        },
        "mission_id": {"$ref": "#/$defs/sha256_id"},
        "poc_artifact": {"$ref": "#/$defs/modeled_poc_artifact_binding"},
        "resolution_profile": {"const": EXPECTED_RESOLUTION_PROFILE_V1},
        "resolved_at": {"$ref": "#/$defs/epoch_second"},
        "target_snapshot_id": {"$ref": "#/$defs/sha256_id"},
        "verification_lease_id": {"$ref": "#/$defs/sha256_id"},
    }
    for field, expected in exact_properties.items():
        if properties.get(field) != expected:
            issues.append(
                "protocol-v1 verification artifact resolution "
                f"{field} contract drifted"
            )
    expected_arrays = {
        "evidence_artifacts": (
            "#/$defs/modeled_supporting_evidence_artifact_binding",
            256,
        ),
        "target_artifacts": (
            "#/$defs/verification_target_artifact_binding",
            256,
        ),
    }
    for field, (item_ref, maximum) in expected_arrays.items():
        if properties.get(field) != {
            "type": "array",
            "minItems": 1,
            "maxItems": maximum,
            "uniqueItems": True,
            "items": {"$ref": item_ref},
        }:
            issues.append(
                "protocol-v1 verification artifact resolution "
                f"{field} contract drifted"
            )
    return issues


def protocol_schema_contract_issues(schema: object) -> list[str]:
    """Check load-bearing schema/runtime structure for exact parity."""

    if type(schema) is not dict:
        return ["protocol-v1 schema must contain a JSON object"]
    issues: list[str] = []
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        issues.append("protocol-v1 schema must declare Draft 2020-12")
    if schema.get("$id") != "https://etzio.local/schemas/protocol.v1.schema.json":
        issues.append("protocol-v1 schema has an unexpected canonical ID")
    if schema.get("x-etzio-schema-role") != "semantic_wire_shape_guard":
        issues.append("protocol-v1 schema must declare the semantic wire-shape role")
    if frozenset(SEMANTIC_BODY_FIELDS_BY_KIND_V1) != SUPPORTED_OBJECT_KINDS:
        issues.append("protocol-v1 runtime body registry differs from its kind allowlist")
    if len(SUPPORTED_OBJECT_KINDS) != EXPECTED_SEMANTIC_OBJECT_KIND_COUNT_V1:
        issues.append("protocol-v1 runtime semantic object-kind count drifted")
    if len(EVENT_UNIT_BY_KIND_V1) != EXPECTED_EVENT_KIND_COUNT_V1:
        issues.append("protocol-v1 runtime event-kind count drifted")
    if RESOLUTION_PROFILE_V1 != EXPECTED_RESOLUTION_PROFILE_V1:
        issues.append("protocol-v1 runtime resolution profile drifted")
    if RESOLUTION_BODY_FIELDS_V1 != EXPECTED_RESOLUTION_BODY_FIELDS_V1:
        issues.append("protocol-v1 runtime resolution body fields drifted")
    if (
        VERIFICATION_ARTIFACT_BINDING_FIELDS_V1
        != EXPECTED_VERIFICATION_ARTIFACT_BINDING_FIELDS_V1
    ):
        issues.append("protocol-v1 runtime verification artifact binding fields drifted")
    if (
        TARGET_ARTIFACT_BINDING_FIELDS_V1
        != EXPECTED_TARGET_ARTIFACT_BINDING_FIELDS_V1
    ):
        issues.append("protocol-v1 runtime target artifact binding fields drifted")
    if (
        frozenset((*VERIFICATION_ARTIFACT_TYPES_V1, TARGET_ARTIFACT_TYPE_V1))
        != EXPECTED_VERIFICATION_ARTIFACT_TYPES_V1
    ):
        issues.append("protocol-v1 runtime verification artifact type registry drifted")

    issues.extend(
        _exact_object_contract_issues(
            schema,
            ENVELOPE_FIELDS_V1,
            "protocol-v1 envelope",
        )
    )

    root_properties = schema.get("properties")
    if type(root_properties) is dict:
        if root_properties.get("protocol_version") != {"type": "integer", "const": 1}:
            issues.append("protocol-v1 envelope protocol_version contract drifted")
        if root_properties.get("object_version") != {"type": "integer", "const": 1}:
            issues.append("protocol-v1 envelope object_version contract drifted")
        if root_properties.get("object_id") != {"$ref": "#/$defs/sha256_id"}:
            issues.append("protocol-v1 envelope object_id contract drifted")
        if root_properties.get("body") != {"type": "object"}:
            issues.append("protocol-v1 envelope body contract drifted")
        root_attestations = root_properties.get("attestations")
        if (
            type(root_attestations) is not dict
            or root_attestations.get("type") != "array"
            or root_attestations.get("minItems", 0) != 0
            or root_attestations.get("maxItems") != 1
            or root_attestations.get("items")
            != {"$ref": "#/$defs/ed25519_attestation"}
        ):
            issues.append("protocol-v1 envelope attestation frame drifted")

    try:
        raw_schema_kinds = schema["properties"]["object_kind"]["enum"]
        schema_kinds = frozenset(raw_schema_kinds)
    except (KeyError, TypeError):
        raw_schema_kinds = []
        schema_kinds = frozenset()
        issues.append("protocol-v1 schema is missing its object-kind enum")
    if (
        len(raw_schema_kinds) != len(SUPPORTED_OBJECT_KINDS)
        or schema_kinds != SUPPORTED_OBJECT_KINDS
    ):
        issues.append("protocol-v1 schema object kinds differ from the runtime allowlist")

    expected_case_refs = frozenset(
        f"#/$defs/{kind}_case"
        for kind in SUPPORTED_OBJECT_KINDS
    )
    try:
        raw_case_refs = [branch["$ref"] for branch in schema["oneOf"]]
        case_refs = frozenset(raw_case_refs)
    except (KeyError, TypeError):
        raw_case_refs = []
        case_refs = frozenset()
        issues.append("protocol-v1 schema is missing its per-kind dispatch branches")
    if len(raw_case_refs) != len(expected_case_refs) or case_refs != expected_case_refs:
        issues.append("protocol-v1 schema dispatch branches differ from the runtime allowlist")

    definitions = schema.get("$defs")
    if type(definitions) is not dict:
        issues.append("protocol-v1 schema is missing its definitions")
        return issues
    issues.extend(_verification_artifact_schema_contract_issues(definitions))

    frame = definitions.get("envelope_frame")
    issues.extend(
        _exact_object_contract_issues(
            frame,
            ENVELOPE_FIELDS_V1,
            "protocol-v1 nested envelope frame",
        )
    )
    if type(frame) is dict and type(frame.get("properties")) is dict:
        frame_properties = frame["properties"]
        if frame_properties.get("protocol_version") != {"type": "integer", "const": 1}:
            issues.append("protocol-v1 nested frame protocol_version contract drifted")
        if frame_properties.get("object_version") != {"type": "integer", "const": 1}:
            issues.append("protocol-v1 nested frame object_version contract drifted")
        if frame_properties.get("object_id") != {"$ref": "#/$defs/sha256_id"}:
            issues.append("protocol-v1 nested frame object_id contract drifted")
        if frame_properties.get("body") != {"type": "object"}:
            issues.append("protocol-v1 nested frame body contract drifted")
        try:
            frame_kinds = frame_properties["object_kind"]["enum"]
        except (KeyError, TypeError):
            frame_kinds = []
        if (
            len(frame_kinds) != len(SUPPORTED_OBJECT_KINDS)
            or frozenset(frame_kinds) != SUPPORTED_OBJECT_KINDS
        ):
            issues.append("protocol-v1 nested frame object kinds differ from runtime")
        frame_attestations = frame_properties.get("attestations")
        if (
            type(frame_attestations) is not dict
            or frame_attestations.get("type") != "array"
            or frame_attestations.get("minItems", 0) != 0
            or frame_attestations.get("maxItems") != 1
            or frame_attestations.get("items")
            != {"$ref": "#/$defs/ed25519_attestation"}
        ):
            issues.append("protocol-v1 nested frame attestation contract drifted")

    for kind, expected_fields in SEMANTIC_BODY_FIELDS_BY_KIND_V1.items():
        body_name = "event_body_common" if kind == "event" else f"{kind}_body"
        issues.extend(
            _exact_object_contract_issues(
                definitions.get(body_name),
                expected_fields,
                f"protocol-v1 {kind} body",
            )
        )

        case = definitions.get(f"{kind}_case")
        if type(case) is not dict or type(case.get("properties")) is not dict:
            issues.append(f"protocol-v1 {kind} case is malformed")
            continue
        case_properties = case["properties"]
        if frozenset(case_properties) != frozenset(
            {"object_kind", "body", "attestations"}
        ):
            issues.append(f"protocol-v1 {kind} case fields drifted")
        if case_properties.get("object_kind") != {"const": kind}:
            issues.append(f"protocol-v1 {kind} case discriminator drifted")
        if case_properties.get("body") != {"$ref": f"#/$defs/{kind}_body"}:
            issues.append(f"protocol-v1 {kind} case body reference drifted")

        attestation_contract = case_properties.get("attestations")
        if kind in OPTIONALLY_ATTESTED_OBJECT_KINDS_V1:
            try:
                attestation_refs = [
                    branch["$ref"] for branch in attestation_contract["oneOf"]
                ]
            except (KeyError, TypeError):
                attestation_refs = []
            expected_attestation_refs = frozenset(
                {
                    "#/$defs/no_attestations",
                    "#/$defs/one_ed25519_attestation",
                }
            )
            if (
                len(attestation_refs) != len(expected_attestation_refs)
                or frozenset(attestation_refs) != expected_attestation_refs
            ):
                issues.append(f"protocol-v1 {kind} attestation policy drifted")
        elif attestation_contract != {"$ref": "#/$defs/no_attestations"}:
            issues.append(f"protocol-v1 {kind} must remain unattested")

    issues.extend(
        _exact_object_contract_issues(
            definitions.get("verifier_trust_key"),
            VERIFIER_TRUST_KEY_FIELDS_V1,
            "protocol-v1 verifier trust key",
        )
    )
    issues.extend(
        _exact_object_contract_issues(
            definitions.get("verifier_trust_snapshot"),
            VERIFIER_TRUST_SNAPSHOT_FIELDS_V1,
            "protocol-v1 verifier trust snapshot",
        )
    )
    verification_event_payload = definitions.get(
        "event_payload_verification_lease_issued"
    )
    verification_event_properties = (
        verification_event_payload.get("properties")
        if type(verification_event_payload) is dict
        else None
    )
    if type(verification_event_properties) is not dict:
        issues.append(
            "protocol-v1 verification lease event properties are malformed"
        )
    else:
        if verification_event_properties.get(
            "verifier_trust_snapshot"
        ) != {"$ref": "#/$defs/verifier_trust_snapshot"}:
            issues.append(
                "protocol-v1 verification lease event trust snapshot "
                "reference drifted"
            )
        if verification_event_properties.get(
            "verifier_trust_snapshot_id"
        ) != {"$ref": "#/$defs/sha256_id"}:
            issues.append(
                "protocol-v1 verification lease event trust snapshot ID "
                "reference drifted"
            )

    event_body_common = definitions.get("event_body_common")
    event_body_common_properties = (
        event_body_common.get("properties")
        if type(event_body_common) is dict
        else None
    )
    if type(event_body_common_properties) is not dict:
        issues.append("protocol-v1 event common body properties are malformed")
    else:
        event_kind_contract = event_body_common_properties.get("kind")
        raw_event_kinds = (
            event_kind_contract.get("enum")
            if type(event_kind_contract) is dict
            else None
        )
        if (
            type(raw_event_kinds) is not list
            or any(type(kind) is not str for kind in raw_event_kinds)
            or len(raw_event_kinds) != len(EVENT_UNIT_BY_KIND_V1)
            or frozenset(raw_event_kinds) != frozenset(EVENT_UNIT_BY_KIND_V1)
        ):
            issues.append(
                "protocol-v1 event common kind enum differs from the runtime contract"
            )

        expected_event_units = frozenset(EVENT_UNIT_BY_KIND_V1.values())
        event_unit_contract = event_body_common_properties.get("unit")
        raw_event_units = (
            event_unit_contract.get("enum")
            if type(event_unit_contract) is dict
            else None
        )
        if (
            type(raw_event_units) is not list
            or any(type(unit) is not str for unit in raw_event_units)
            or len(raw_event_units) != len(expected_event_units)
            or frozenset(raw_event_units) != expected_event_units
        ):
            issues.append(
                "protocol-v1 event common unit enum differs from the runtime contract"
            )

    event_body = definitions.get("event_body")
    try:
        event_body_refs = [branch["$ref"] for branch in event_body["allOf"]]
    except (KeyError, TypeError):
        event_body_refs = []
    expected_event_body_refs = frozenset(
        {"#/$defs/event_body_common", "#/$defs/event_variants"}
    )
    if (
        len(event_body_refs) != len(expected_event_body_refs)
        or frozenset(event_body_refs) != expected_event_body_refs
    ):
        issues.append("protocol-v1 event body composition drifted")

    issues.extend(
        _exact_object_contract_issues(
            definitions.get("ed25519_attestation"),
            frozenset({"algorithm", "key_id", "signature_b64"}),
            "protocol-v1 Ed25519 attestation",
        )
    )
    ed25519_attestation = definitions.get("ed25519_attestation")
    if type(ed25519_attestation) is dict and type(
        ed25519_attestation.get("properties")
    ) is dict:
        attestation_properties = ed25519_attestation["properties"]
        if attestation_properties.get("algorithm") != {"const": "ed25519"}:
            issues.append("protocol-v1 attestation algorithm contract drifted")
        if attestation_properties.get("key_id") != {
            "$ref": "#/$defs/ed25519_key_id"
        }:
            issues.append("protocol-v1 attestation key contract drifted")
        if attestation_properties.get("signature_b64") != {
            "$ref": "#/$defs/ed25519_signature_b64"
        }:
            issues.append("protocol-v1 attestation signature contract drifted")

    no_attestations = definitions.get("no_attestations")
    if (
        type(no_attestations) is not dict
        or no_attestations.get("type") != "array"
        or no_attestations.get("minItems", 0) != 0
        or no_attestations.get("maxItems") != 0
    ):
        issues.append("protocol-v1 no-attestation contract drifted")
    one_attestation = definitions.get("one_ed25519_attestation")
    if (
        type(one_attestation) is not dict
        or one_attestation.get("type") != "array"
        or one_attestation.get("minItems") != 1
        or one_attestation.get("maxItems") != 1
        or one_attestation.get("items")
        != {"$ref": "#/$defs/ed25519_attestation"}
    ):
        issues.append("protocol-v1 one-attestation contract drifted")

    schema_units: dict[str, str] = {}
    schema_payload_fields: dict[str, frozenset[str]] = {}
    try:
        for variant in definitions["event_variants"]["oneOf"]:
            properties = variant["properties"]
            kind = properties["kind"]["const"]
            if kind in schema_units:
                issues.append(f"protocol-v1 schema repeats event branch {kind!r}")
                continue
            schema_units[kind] = properties["unit"]["const"]
            payload_name = properties["payload"]["$ref"].removeprefix("#/$defs/")
            payload_schema = definitions[payload_name]
            schema_payload_fields[kind] = frozenset(payload_schema["required"])
            issues.extend(
                _exact_object_contract_issues(
                    payload_schema,
                    EVENT_PAYLOAD_FIELDS_BY_KIND_V1[kind],
                    f"protocol-v1 {kind} event payload",
                )
            )
            payload_properties = payload_schema.get("properties")
            for field, expected_kind in EVENT_NESTED_ENVELOPE_KIND_BY_FIELD_V1.get(
                kind,
                {},
            ).items():
                nested_schema = (
                    payload_properties.get(field)
                    if type(payload_properties) is dict
                    else None
                )
                issues.extend(
                    _nested_event_envelope_contract_issues(
                        nested_schema,
                        definitions,
                        expected_kind,
                        f"protocol-v1 {kind}.{field}",
                    )
                )
    except (AttributeError, KeyError, TypeError):
        issues.append("protocol-v1 schema has malformed event dispatch metadata")
    if schema_units != dict(EVENT_UNIT_BY_KIND_V1):
        issues.append("protocol-v1 schema event units differ from the runtime contract")
    if schema_payload_fields != dict(EVENT_PAYLOAD_FIELDS_BY_KIND_V1):
        issues.append("protocol-v1 schema event payload fields differ from the runtime contract")
    return issues


def _schema_paths() -> tuple[Path, ...]:
    return tuple(sorted((ROOT / "schemas").glob("*.json"))) + (PROTOCOL_SCHEMA_PATH,)


def _schema_issues() -> list[str]:
    issues: list[str] = []
    for path in _schema_paths():
        try:
            schema = decode_schema_document(path.read_text(encoding="utf-8"))
            validator_for(schema).check_schema(schema)
            if path == PROTOCOL_SCHEMA_PATH:
                issues.extend(
                    f"{path.relative_to(ROOT)}: {issue}"
                    for issue in protocol_schema_contract_issues(schema)
                )
            elif (
                path in LEGACY_SCHEMA_PATHS
                and (
                    type(schema) is not dict
                    or schema.get("x-etzio-status") != "modeled_non_authoritative"
                )
            ):
                issues.append(
                    f"{path.relative_to(ROOT)}: legacy schema must remain explicitly "
                    "modeled and non-authoritative"
                )
        except (OSError, json.JSONDecodeError, SchemaError, TypeError, ValueError) as exc:
            issues.append(f"{path.relative_to(ROOT)}: invalid schema: {exc}")
    return issues


def _markdown_link_issues() -> list[str]:
    issues: list[str] = []
    for path in sorted(ROOT.rglob("*.md")):
        if any(part.startswith(".") and part != ".github" for part in path.relative_to(ROOT).parts):
            continue
        text = path.read_text(encoding="utf-8")
        for raw_target in MARKDOWN_LINK.findall(text):
            target = raw_target.strip().strip("<>")
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            target = target.split("#", 1)[0]
            if not target:
                continue
            resolved = (path.parent / target).resolve()
            if not resolved.exists():
                issues.append(f"{path.relative_to(ROOT)}: missing linked path: {raw_target}")
    return issues


def _tracked_artifact_issues() -> list[str]:
    tracked = subprocess.check_output(["git", "ls-files"], cwd=ROOT, text=True).splitlines()
    forbidden = (
        ".env",
        ".coverage",
        ".pytest_cache/",
        ".ruff_cache/",
        "__pycache__/",
        "artifacts/",
        "ledgers/",
    )
    return [
        f"tracked runtime or secret artifact: {path}"
        for path in tracked
        if any(item in path for item in forbidden)
    ]


def validate() -> list[str]:
    issues = required_path_issues(ROOT)

    python_version = (ROOT / ".python-version").read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"3\.\d+\.\d+", python_version):
        issues.append(".python-version must pin an exact CPython patch release")

    try:
        state = json.loads((ROOT / "docs/MISSION_STATE.json").read_text(encoding="utf-8"))
        issues.extend(mission_state_issues(state))
    except (OSError, json.JSONDecodeError) as exc:
        issues.append(f"docs/MISSION_STATE.json is invalid: {exc}")

    workflows = sorted(
        path
        for path in (ROOT / ".github/workflows").iterdir()
        if path.is_file() and path.suffix in {".yml", ".yaml"}
    )
    for workflow in workflows:
        text = workflow.read_text(encoding="utf-8")
        issues.extend(workflow_syntax_issues(text, str(workflow.relative_to(ROOT))))
        issues.extend(action_ref_issues(text, str(workflow.relative_to(ROOT))))
        issues.extend(workflow_permission_issues(text, str(workflow.relative_to(ROOT))))

    issues.extend(author_record_issues(_git_author_records()))
    issues.extend(_schema_issues())
    issues.extend(_markdown_link_issues())
    issues.extend(_tracked_artifact_issues())
    return issues


def main() -> int:
    issues = validate()
    if issues:
        print("Etzio repository policy: FAIL")
        for issue in issues:
            print(f"- {issue}")
        return 1
    schema_count = len(_schema_paths())
    workflow_count = len(
        [
            path
            for path in (ROOT / ".github/workflows").iterdir()
            if path.is_file() and path.suffix in {".yml", ".yaml"}
        ]
    )
    print(
        "Etzio repository policy: PASS "
        f"({schema_count} schemas, {workflow_count} workflow, sole-author history, "
        "immutable action refs, read-only workflow permissions)"
    )
    print("Boundary: repository policy only; no live-target, isolation, or detection-quality claim.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
