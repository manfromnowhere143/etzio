"""Fail-closed repository policy checks for the Etzio foundation.

This validator concerns repository bytes and provenance. It does not establish detection
quality, sandbox safety, authorization validity, or readiness for a live target.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

from jsonschema.exceptions import SchemaError
from jsonschema.validators import validator_for

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from etzio.evidence import VERIFICATION_ARTIFACT_TYPES_V1  # noqa: E402
from etzio.integrity_v1 import INTEGRITY_EVIDENCE_KINDS_V1  # noqa: E402
from etzio.kernel.events_v1 import (  # noqa: E402
    EVENT_NESTED_ENVELOPE_KIND_BY_FIELD_V1,
    EVENT_PAYLOAD_FIELDS_BY_KIND_V1,
    EVENT_UNIT_BY_KIND_V1,
    MISSION_CLOSED_STATUSES_V1,
    RECEIPT_ADMISSION_PROFILE_V1,
    VERIFICATION_LEASE_CANCELLATION_REASON_V1,
    VERIFICATION_LEASE_REASSIGNMENT_REASONS_V1,
)
from etzio.protocol import (  # noqa: E402
    ENVELOPE_FIELDS_V1,
    OPTIONALLY_ATTESTED_OBJECT_KINDS_V1,
    REQUIRED_ATTESTED_OBJECT_KINDS_V1,
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
    "Makefile",
    "MANIFEST.in",
    "pyproject.toml",
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
    "docs/decisions/0005-typed-verification-artifact-resolution.md",
    "docs/decisions/0006-atomic-modeled-receipt-admission.md",
    "docs/decisions/0007-explicit-verification-lease-recovery.md",
    "docs/decisions/0008-typed-integrity-evidence-contract.md",
    "docs/decisions/README.md",
    "schemas/finding.schema.json",
    "etzio/schemas/__init__.py",
    "etzio/schemas/protocol.v1.schema.json",
    "schemas/target-contract.schema.json",
    "schemas/verdict.schema.json",
    ".github/CODEOWNERS",
    ".github/workflows/ci.yml",
    "scripts/ci/verify.sh",
    "tests/conftest.py",
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
EXPECTED_SEMANTIC_OBJECT_KIND_COUNT_V1 = 11
EXPECTED_EVENT_KIND_COUNT_V1 = 18
EXPECTED_REQUIRED_ATTESTED_OBJECT_KINDS_V1 = frozenset({"head_checkpoint", "integrity_decision"})
EXPECTED_INTEGRITY_EVIDENCE_REFERENCE_FIELDS_V1 = frozenset({"evidence_id", "evidence_kind", "source_id"})
EXPECTED_FOUNDATION_PYTHON_MATRIX = ("3.11.15", "3.14.2")
EXPECTED_TOP_LEVEL_WORKFLOW_ENV = (
    'PYTHONDONTWRITEBYTECODE: "1"',
    'PIP_DISABLE_PIP_VERSION_CHECK: "1"',
)
EXPECTED_CI_WORKFLOW_NORMALIZED_SHA256 = "eb6a884715e6af4e2c14dab5f01868ebf11b9f8b27b289ae1ffa272e7c1e3396"
EXPECTED_MAKEFILE_NORMALIZED_SHA256 = "490e139bf70b5f3c4c658dce69d3a9ee587a3db1352ba00b4223b7248516de61"
EXPECTED_PYTEST_INI_OPTIONS = {
    "testpaths": ["tests"],
    "addopts": ["--strict-config", "--strict-markers"],
}
EXPECTED_RUFF_CONFIGURATION = {
    "line-length": 120,
    "target-version": "py311",
    "lint": {
        "select": ["E", "F", "I", "UP", "B"],
        "ignore": ["UP042"],
    },
}
ALTERNATE_TOOL_CONFIG_NAMES = {
    "pytest": ("pytest.ini", ".pytest.ini", "tox.ini", "setup.cfg"),
    "Ruff": ("ruff.toml", ".ruff.toml"),
}
EXPECTED_MAKEFILE_LINES = (
    ".PHONY: demo model-demo test lint policy verify all",
    "ETZIO_PYTHON ?= python3",
    "demo:",
    "\t$(ETZIO_PYTHON) -m etzio.scan --fixture vulnerable",
    "model-demo:",
    "\t$(ETZIO_PYTHON) -m etzio.cli",
    "test:",
    "\t$(ETZIO_PYTHON) -m pytest -q",
    "lint:",
    "\t$(ETZIO_PYTHON) -m ruff check etzio tests scripts",
    "policy:",
    "\t$(ETZIO_PYTHON) scripts/validate_repository.py",
    "verify:",
    "\tbash scripts/ci/verify.sh",
    "all: verify",
)
EXPECTED_FOUNDATION_VERIFY_BODY = (
    "mkdir -p artifacts/ci",
    ("bash scripts/ci/verify.sh 2>&1 | tee artifacts/ci/foundation-${{ matrix.python-version }}.log"),
)
EXPECTED_VERIFICATION_SCRIPT_LINES = (
    "#!/usr/bin/env bash",
    "set -euo pipefail",
    'etzio_python="${ETZIO_PYTHON:-python3}"',
    ("unset BASH_ENV ENV PYTHONHOME PYTHONOPTIMIZE PYTHONPATH PYTEST_ADDOPTS PYTEST_PLUGINS"),
    "export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1",
    "export PYTHONNOUSERSITE=1",
    'etzio_python_version="$(',
    ('"${etzio_python}" -I -c \'import sys; print("%s:%s.%s.%s" % (sys.implementation.name, *sys.version_info[:3]))\''),
    ')"',
    ('if [[ "${etzio_python_version}" != "cpython:3.11.15" && "${etzio_python_version}" != "cpython:3.14.2" ]]; then'),
    (
        "printf 'Etzio verification requires CPython 3.11.15 or 3.14.2; "
        'got %s\\n\' "${etzio_python_version:-no implementation/version}" >&2'
    ),
    "exit 2",
    "fi",
    '"${etzio_python}" scripts/validate_repository.py',
    ('"${etzio_python}" -m ruff check --config pyproject.toml etzio tests scripts'),
    ('"${etzio_python}" -m pytest -q -c pyproject.toml --verify-mission-evidence tests'),
    '"${etzio_python}" -m etzio.cli',
    '"${etzio_python}" -m etzio.harness.fpr',
    '"${etzio_python}" -m etzio.scan --fixture vulnerable',
    '"${etzio_python}" -m etzio.scan --fixture clean',
)
EXPECTED_INTEGRITY_REVOCATION_VIEW_FIELDS_V1 = frozenset(
    {
        "evidence",
        "namespace",
        "root_version",
        "snapshot_id",
        "valid_from",
        "valid_until",
        "version",
    }
)
EXPECTED_INTEGRITY_DECISION_PROPERTY_REFS_V1 = {
    "authority_id": "#/$defs/sha256_id",
    "decision_policy_id": "#/$defs/sha256_id",
    "environment_id": "#/$defs/canonical_identity",
    "mission_id": "#/$defs/sha256_id",
    "prior_event_digest": "#/$defs/sha256_id",
    "prior_global_checkpoint_attestation_id": "#/$defs/nullable_sha256_id",
    "prior_global_checkpoint_id": "#/$defs/sha256_id",
    "prior_global_checkpoint_principal_id": ("#/$defs/nullable_canonical_identity"),
    "prior_global_checkpoint_trust_snapshot_id": ("#/$defs/nullable_sha256_id"),
    "proposed_event_digest": "#/$defs/sha256_id",
    "request_nonce": "#/$defs/integrity_nonce_256_hex",
    "revocation_views": "#/$defs/integrity_revocation_views",
    "service_instance_id": "#/$defs/canonical_identity",
    "target_id": "#/$defs/sha256_id",
    "time_evidence": "#/$defs/trusted_time_evidence_quorum",
    "time_lower_bound": "#/$defs/epoch_second",
    "time_policy_id": "#/$defs/sha256_id",
    "time_upper_bound": "#/$defs/epoch_second",
    "transition_intent_id": "#/$defs/sha256_id",
}
EXPECTED_HEAD_CHECKPOINT_PROPERTY_REFS_V1 = {
    "anchor_evidence": "#/$defs/head_anchor_receipt_evidence_quorum",
    "anchor_policy_id": "#/$defs/sha256_id",
    "anchor_statement_id": "#/$defs/sha256_id",
    "authority_id": "#/$defs/sha256_id",
    "environment_id": "#/$defs/canonical_identity",
    "event_digest": "#/$defs/sha256_id",
    "event_seq": "#/$defs/epoch_second",
    "instance_sequence": "#/$defs/epoch_second",
    "integrity_decision_attestation_id": "#/$defs/sha256_id",
    "integrity_decision_id": "#/$defs/sha256_id",
    "integrity_decision_principal_id": "#/$defs/canonical_identity",
    "integrity_decision_trust_snapshot_id": "#/$defs/sha256_id",
    "mission_id": "#/$defs/sha256_id",
    "previous_checkpoint_attestation_id": "#/$defs/nullable_sha256_id",
    "previous_checkpoint_id": "#/$defs/sha256_id",
    "previous_checkpoint_principal_id": ("#/$defs/nullable_canonical_identity"),
    "previous_checkpoint_trust_snapshot_id": ("#/$defs/nullable_sha256_id"),
    "previous_mission_checkpoint_attestation_id": ("#/$defs/nullable_sha256_id"),
    "previous_mission_checkpoint_id": "#/$defs/sha256_id",
    "previous_mission_checkpoint_principal_id": ("#/$defs/nullable_canonical_identity"),
    "previous_mission_checkpoint_trust_snapshot_id": ("#/$defs/nullable_sha256_id"),
    "service_instance_id": "#/$defs/canonical_identity",
    "target_id": "#/$defs/sha256_id",
    "time_evidence": "#/$defs/trusted_time_evidence_quorum",
    "time_lower_bound": "#/$defs/epoch_second",
    "time_policy_id": "#/$defs/sha256_id",
    "time_upper_bound": "#/$defs/epoch_second",
}
EXPECTED_RESOLUTION_PROFILE_V1 = "modeled_fixture_typed_cas_v1"
EXPECTED_RECEIPT_ADJUDICATION_PROFILE_V1 = "modeled_fixture_receipt_admission_v1"
EXPECTED_VERIFICATION_RECOVERY_EVENT_UNITS_V1 = {
    "verification_lease_cancelled": "AQUILA",
    "verification_lease_expired": "ETZIO",
    "verification_lease_reassigned": "AQUILA",
}
EXPECTED_VERIFICATION_RECOVERY_PAYLOAD_FIELDS_V1 = {
    "verification_lease_cancelled": frozenset({"reason_code", "verification_lease_id"}),
    "verification_lease_expired": frozenset({"verification_lease_id"}),
    "verification_lease_reassigned": frozenset(
        {
            "lease",
            "predecessor_verification_lease_id",
            "reason_code",
            "verifier_trust_snapshot",
            "verifier_trust_snapshot_id",
        }
    ),
}
EXPECTED_VERIFICATION_RECOVERY_NESTED_ENVELOPES_V1 = {"verification_lease_reassigned": {"lease": "verification_lease"}}
EXPECTED_VERIFICATION_LEASE_CANCELLATION_REASON_V1 = "operator_cancelled"
EXPECTED_VERIFICATION_LEASE_REASSIGNMENT_REASONS_V1 = frozenset(
    {
        "active_lease_superseded",
        "cancelled_lease_recovery",
        "expired_lease_recovery",
    }
)
EXPECTED_MISSION_CLOSED_STATUSES_V1 = frozenset(
    {
        "completed",
        "receipt_coverage_complete",
        "receipt_coverage_incomplete",
    }
)
EXPECTED_VERIFICATION_ARTIFACT_TYPES_V1 = frozenset(
    {
        "modeled_effect_oracle_spec",
        "modeled_effect_output",
        "modeled_environment_spec",
        "modeled_execution_output",
        "modeled_measured_environment_output",
        "modeled_poc_input",
        "modeled_supporting_evidence_input",
        "modeled_termination_output",
        "repository_fixture_source",
    }
)
EXPECTED_VERIFICATION_ARTIFACT_BINDING_FIELDS_V1 = frozenset({"artifact_digest", "artifact_type", "size"})
EXPECTED_TARGET_ARTIFACT_BINDING_FIELDS_V1 = frozenset({"artifact_digest", "artifact_type", "relative_path", "size"})
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
EXPECTED_VERIFIER_RECEIPT_BODY_FIELDS_V1 = frozenset(
    {
        "artifact_resolution_id",
        "authority_id",
        "candidate_id",
        "candidate_producer_id",
        "completed_at",
        "effect_observed",
        "effect_oracle_id",
        "effect_output_digest",
        "effect_output_size",
        "environment_digest",
        "evidence_artifact_digests",
        "evidence_tier",
        "execution_output_digest",
        "execution_output_size",
        "lease_id",
        "measured_environment_output_digest",
        "measured_environment_output_size",
        "mission_id",
        "oracle_satisfied",
        "poc_artifact_digest",
        "target_snapshot_id",
        "termination_output_digest",
        "termination_output_size",
        "verdict",
        "verifier_id",
        "verifier_key_id",
    }
)
EXPECTED_RECEIPT_ADMISSION_PAYLOAD_FIELDS_V1 = frozenset(
    {
        "adjudication_profile",
        "decision_trust_snapshot",
        "decision_trust_snapshot_id",
        "effect_output_artifact",
        "execution_output_artifact",
        "measured_environment_output_artifact",
        "receipt",
        "termination_output_artifact",
    }
)


def required_path_issues(root: Path, required: tuple[str, ...] = REQUIRED_PATHS) -> list[str]:
    return [f"missing required repository file: {relative}" for relative in required if not (root / relative).is_file()]


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
                issues.append(f"{source}:{number}: action is not pinned to a 40-character commit SHA: {reference}")
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


def verification_entrypoint_issues(text: str) -> list[str]:
    observed = tuple(line.strip() for line in text.splitlines() if line.strip())
    if observed != EXPECTED_VERIFICATION_SCRIPT_LINES:
        return ["scripts/ci/verify.sh must retain the exact fail-closed verification command sequence"]
    return []


def pyproject_configuration_issues(
    text: str,
    root: Path = ROOT,
    source: str = "pyproject.toml",
) -> list[str]:
    """Reject project-tool configuration surfaces that can bypass verification."""

    issues: list[str] = []
    try:
        document = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, TypeError) as exc:
        return [f"{source}: invalid TOML: {exc}"]

    tool_configuration = document.get("tool")
    if not isinstance(tool_configuration, dict):
        return [f"{source}: missing exact pytest and Ruff tool configuration"]

    pytest_configuration = tool_configuration.get("pytest")
    pytest_options = pytest_configuration.get("ini_options") if isinstance(pytest_configuration, dict) else None
    if pytest_options != EXPECTED_PYTEST_INI_OPTIONS:
        issues.append(f"{source}: pytest ini options must retain the exact fail-closed contract")

    ruff_configuration = tool_configuration.get("ruff")
    if ruff_configuration != EXPECTED_RUFF_CONFIGURATION:
        issues.append(f"{source}: Ruff options must retain the exact fail-closed contract")

    for tool, names in ALTERNATE_TOOL_CONFIG_NAMES.items():
        for name in names:
            if (root / name).is_file():
                issues.append(f"{name}: alternate root {tool} configuration is forbidden")
    return issues


def makefile_issues(text: str, source: str = "Makefile") -> list[str]:
    """Freeze the exact local verification delegation and supporting targets."""

    normalized_digest = hashlib.sha256(_lf_normalized_text(text).encode("utf-8")).hexdigest()
    observed_lines = tuple(line.rstrip() for line in text.splitlines() if line.strip())
    if normalized_digest != EXPECTED_MAKEFILE_NORMALIZED_SHA256 or observed_lines != EXPECTED_MAKEFILE_LINES:
        return [f"{source}: Makefile must retain the exact fail-closed verification contract"]
    return []


def _workflow_mapping_block(
    lines: list[tuple[int, str]],
    *,
    header: str,
    indent: int,
) -> list[tuple[int, str]] | None:
    expected = (" " * indent) + header
    matches = [index for index, (_, code) in enumerate(lines) if code == expected]
    if len(matches) != 1:
        return None
    start = matches[0]
    end = len(lines)
    for index in range(start + 1, len(lines)):
        code = lines[index][1]
        if len(code) - len(code.lstrip()) <= indent:
            end = index
            break
    return lines[start:end]


def _yaml_scalar(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _lf_normalized_text(text: str) -> str:
    """Normalize line-ending encoding while retaining every other repository byte."""

    return text.replace("\r\n", "\n").replace("\r", "\n")


def _normalized_workflow_contract_text(text: str) -> str:
    """Retain every workflow byte except the platform-specific line ending."""

    return _lf_normalized_text(text)


def foundation_workflow_issues(
    text: str,
    source: str = ".github/workflows/ci.yml",
) -> list[str]:
    """Freeze the exact dual-runtime foundation gate and its fail-closed entrypoint."""

    issues: list[str] = []
    normalized_digest = hashlib.sha256(_normalized_workflow_contract_text(text).encode("utf-8")).hexdigest()
    if normalized_digest != EXPECTED_CI_WORKFLOW_NORMALIZED_SHA256:
        issues.append(f"{source}: load-bearing CI workflow contract drifted")

    lines = _workflow_structure_lines(text)
    workflow_env = _workflow_mapping_block(lines, header="env:", indent=0)
    workflow_env_entries = (
        []
        if workflow_env is None
        else [code.strip() for _, code in workflow_env[1:] if len(code) - len(code.lstrip()) == 2]
    )
    if tuple(workflow_env_entries) != EXPECTED_TOP_LEVEL_WORKFLOW_ENV:
        issues.append(f"{source}: top-level workflow environment must remain exact")

    jobs = _workflow_mapping_block(lines, header="jobs:", indent=0)
    foundation = (
        None
        if jobs is None
        else _workflow_mapping_block(
            jobs,
            header="foundation:",
            indent=2,
        )
    )
    strategy = (
        None
        if foundation is None
        else _workflow_mapping_block(
            foundation,
            header="strategy:",
            indent=4,
        )
    )
    matrix = (
        None
        if strategy is None
        else _workflow_mapping_block(
            strategy,
            header="matrix:",
            indent=6,
        )
    )
    python_versions = (
        None
        if matrix is None
        else _workflow_mapping_block(
            matrix,
            header="python-version:",
            indent=8,
        )
    )
    matrix_keys = (
        [] if matrix is None else [code.strip() for _, code in matrix[1:] if len(code) - len(code.lstrip()) == 8]
    )
    versions = (
        ()
        if python_versions is None
        else tuple(
            _yaml_scalar(code.strip()[2:])
            for _, code in python_versions[1:]
            if len(code) - len(code.lstrip()) == 10 and code.strip().startswith("- ")
        )
    )
    if matrix_keys != ["python-version:"] or versions != EXPECTED_FOUNDATION_PYTHON_MATRIX:
        issues.append(f"{source}: foundation Python matrix must be exactly 3.11.15 and 3.14.2")

    defaults = _workflow_mapping_block(lines, header="defaults:", indent=0)
    default_keys = (
        [] if defaults is None else [code.strip() for _, code in defaults[1:] if len(code) - len(code.lstrip()) == 2]
    )
    run_defaults = (
        None
        if defaults is None
        else _workflow_mapping_block(
            defaults,
            header="run:",
            indent=2,
        )
    )
    run_shells = (
        []
        if run_defaults is None
        else [code.strip() for _, code in run_defaults[1:] if len(code) - len(code.lstrip()) == 4]
    )
    if default_keys != ["run:"] or run_shells != ["shell: bash"]:
        issues.append(f"{source}: workflow run shell must remain bash")

    step_headers = (
        []
        if foundation is None
        else [
            (number, code) for number, code in foundation if code.strip() == "- name: Reproduce the foundation checks"
        ]
    )
    body: tuple[str, ...] | None = None
    if len(step_headers) == 1:
        step_header_number = step_headers[0][0]
        step_header_index = next(index for index, (number, _) in enumerate(foundation) if number == step_header_number)
        step_structure: list[str] = []
        for _, code in foundation[step_header_index + 1 :]:
            indent = len(code) - len(code.lstrip())
            if indent <= 6:
                break
            if indent == 8:
                step_structure.append(code.strip())
        raw_lines = text.splitlines()
        step_line = step_header_number - 1
        step_indent = len(raw_lines[step_line]) - len(raw_lines[step_line].lstrip())
        step_end = len(raw_lines)
        for index in range(step_line + 1, len(raw_lines)):
            raw = raw_lines[index]
            if not raw.strip():
                continue
            indent = len(raw) - len(raw.lstrip())
            if indent <= step_indent:
                step_end = index
                break
        run_headers = (
            [index for index in range(step_line + 1, step_end) if raw_lines[index].strip() == "run: |"]
            if step_structure == ["run: |"]
            else []
        )
        if len(run_headers) == 1:
            run_line = run_headers[0]
            run_indent = len(raw_lines[run_line]) - len(raw_lines[run_line].lstrip())
            body_lines: list[str] = []
            for raw in raw_lines[run_line + 1 : step_end]:
                if not raw.strip():
                    continue
                indent = len(raw) - len(raw.lstrip())
                if indent <= run_indent:
                    break
                body_lines.append(raw.strip())
            body = tuple(body_lines)
    if body != EXPECTED_FOUNDATION_VERIFY_BODY:
        issues.append(f"{source}: foundation job must invoke the exact fail-closed verification entrypoint")
    if foundation is not None and any(code.strip() == "defaults:" for _, code in foundation[1:]):
        issues.append(f"{source}: foundation job may not override the fail-closed run shell")
    if foundation is not None and any(
        len(code) - len(code.lstrip()) == 4 and code.strip().split(":", 1)[0] in {"continue-on-error", "if"}
        for _, code in foundation[1:]
    ):
        issues.append(f"{source}: foundation job may not bypass verification failure")
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


def _predecessor_provenance_conditional(
    *,
    sequence_field: str,
    genesis_sequence: int,
    attestation_field: str,
    principal_field: str,
    trust_snapshot_field: str,
) -> dict[str, object]:
    """Return the exact null-at-genesis/non-null-after-genesis schema contract."""

    return {
        "if": {
            "properties": {
                sequence_field: {
                    "const": genesis_sequence,
                }
            },
            "required": [sequence_field],
        },
        "then": {
            "properties": {
                attestation_field: {"type": "null"},
                principal_field: {"type": "null"},
                trust_snapshot_field: {"type": "null"},
            }
        },
        "else": {
            "properties": {
                attestation_field: {"$ref": "#/$defs/sha256_id"},
                principal_field: {"$ref": "#/$defs/canonical_identity"},
                trust_snapshot_field: {"$ref": "#/$defs/sha256_id"},
            }
        },
    }


def _integrity_schema_contract_issues(
    definitions: dict[str, object],
) -> list[str]:
    """Freeze the structural side of the integrity evidence boundary."""

    issues: list[str] = []
    nullable_contracts = {
        "nullable_sha256_id": "#/$defs/sha256_id",
        "nullable_canonical_identity": "#/$defs/canonical_identity",
    }
    for name, reference in nullable_contracts.items():
        if definitions.get(name) != {
            "oneOf": [
                {"$ref": reference},
                {"type": "null"},
            ]
        }:
            issues.append(f"protocol-v1 {name} contract drifted")

    evidence_reference = definitions.get("integrity_evidence_reference")
    issues.extend(
        _exact_object_contract_issues(
            evidence_reference,
            EXPECTED_INTEGRITY_EVIDENCE_REFERENCE_FIELDS_V1,
            "protocol-v1 integrity evidence reference",
        )
    )
    evidence_properties = (
        evidence_reference.get("properties")
        if type(evidence_reference) is dict and type(evidence_reference.get("properties")) is dict
        else {}
    )
    if evidence_properties.get("evidence_id") != {"$ref": "#/$defs/sha256_id"}:
        issues.append("protocol-v1 integrity evidence ID reference drifted")
    if evidence_properties.get("source_id") != {"$ref": "#/$defs/canonical_identity"}:
        issues.append("protocol-v1 integrity evidence source reference drifted")
    evidence_kind = evidence_properties.get("evidence_kind")
    raw_evidence_kinds = evidence_kind.get("enum") if type(evidence_kind) is dict else None
    if (
        type(raw_evidence_kinds) is not list
        or len(raw_evidence_kinds) != len(INTEGRITY_EVIDENCE_KINDS_V1)
        or frozenset(raw_evidence_kinds) != INTEGRITY_EVIDENCE_KINDS_V1
    ):
        issues.append("protocol-v1 integrity evidence-kind registry drifted")

    quorum = definitions.get("integrity_evidence_quorum")
    if (
        type(quorum) is not dict
        or quorum.get("type") != "array"
        or quorum.get("minItems") != 2
        or quorum.get("maxItems") != 16
        or quorum.get("uniqueItems") is not True
        or quorum.get("items") != {"$ref": "#/$defs/integrity_evidence_reference"}
    ):
        issues.append("protocol-v1 integrity evidence quorum drifted")

    typed_reference_kinds = {
        "trusted_time_evidence_reference": "trusted_time",
        "revocation_metadata_evidence_reference": "revocation_metadata",
        "head_anchor_receipt_evidence_reference": "head_anchor_receipt",
    }
    for name, evidence_kind_value in typed_reference_kinds.items():
        if definitions.get(name) != {
            "allOf": [
                {"$ref": "#/$defs/integrity_evidence_reference"},
                {"properties": {"evidence_kind": {"const": evidence_kind_value}}},
            ]
        }:
            issues.append(f"protocol-v1 typed evidence reference {name} drifted")

    typed_quorums = {
        "trusted_time_evidence_quorum": ("#/$defs/trusted_time_evidence_reference"),
        "head_anchor_receipt_evidence_quorum": ("#/$defs/head_anchor_receipt_evidence_reference"),
    }
    for name, item_reference in typed_quorums.items():
        if definitions.get(name) != {
            "type": "array",
            "minItems": 2,
            "maxItems": 16,
            "uniqueItems": True,
            "items": {"$ref": item_reference},
        }:
            issues.append(f"protocol-v1 typed evidence quorum {name} drifted")

    revocation_view = definitions.get("integrity_revocation_view")
    issues.extend(
        _exact_object_contract_issues(
            revocation_view,
            EXPECTED_INTEGRITY_REVOCATION_VIEW_FIELDS_V1,
            "protocol-v1 integrity revocation view",
        )
    )
    revocation_properties = (
        revocation_view.get("properties")
        if type(revocation_view) is dict and type(revocation_view.get("properties")) is dict
        else {}
    )
    expected_revocation_refs = {
        "evidence": "#/$defs/revocation_metadata_evidence_reference",
        "namespace": "#/$defs/canonical_identity",
        "root_version": "#/$defs/positive_int64",
        "snapshot_id": "#/$defs/sha256_id",
        "valid_from": "#/$defs/epoch_second",
        "valid_until": "#/$defs/epoch_second",
        "version": "#/$defs/positive_int64",
    }
    for field, reference in expected_revocation_refs.items():
        if revocation_properties.get(field) != {"$ref": reference}:
            issues.append(f"protocol-v1 integrity revocation {field} reference drifted")

    revocation_views = definitions.get("integrity_revocation_views")
    if (
        type(revocation_views) is not dict
        or revocation_views.get("type") != "array"
        or revocation_views.get("minItems") != 1
        or revocation_views.get("maxItems") != 16
        or revocation_views.get("uniqueItems") is not True
        or revocation_views.get("items") != {"$ref": "#/$defs/integrity_revocation_view"}
    ):
        issues.append("protocol-v1 integrity revocation-view array drifted")

    nonce = definitions.get("integrity_nonce_256_hex")
    if nonce != {
        "type": "string",
        "minLength": 64,
        "maxLength": 64,
        "pattern": r"^[0-9a-f]{64}(?![\s\S])",
    }:
        issues.append("protocol-v1 integrity nonce contract drifted")

    decision = definitions.get("integrity_decision_body")
    decision_properties = (
        decision.get("properties") if type(decision) is dict and type(decision.get("properties")) is dict else {}
    )
    for field, reference in EXPECTED_INTEGRITY_DECISION_PROPERTY_REFS_V1.items():
        if decision_properties.get(field) != {"$ref": reference}:
            issues.append(f"protocol-v1 integrity decision {field} reference drifted")
    if decision_properties.get("event_kind") != {
        "type": "string",
        "minLength": 1,
        "maxLength": 1_000_000,
        "pattern": r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*(?![\s\S])",
    }:
        issues.append("protocol-v1 integrity event-kind contract drifted")
    if decision_properties.get("prior_event_seq") != {
        "type": "integer",
        "minimum": -1,
        "maximum": 9_223_372_036_854_775_806,
    }:
        issues.append("protocol-v1 integrity prior-event sequence drifted")
    if decision_properties.get("prior_global_checkpoint_sequence") != {
        "type": "integer",
        "minimum": -1,
        "maximum": 9_223_372_036_854_775_806,
    }:
        issues.append("protocol-v1 integrity prior-global-checkpoint sequence drifted")
    expected_decision_provenance = _predecessor_provenance_conditional(
        sequence_field="prior_global_checkpoint_sequence",
        genesis_sequence=-1,
        attestation_field="prior_global_checkpoint_attestation_id",
        principal_field="prior_global_checkpoint_principal_id",
        trust_snapshot_field=("prior_global_checkpoint_trust_snapshot_id"),
    )
    if type(decision) is not dict or decision.get("allOf") != [expected_decision_provenance]:
        issues.append("protocol-v1 integrity decision predecessor-provenance conditional drifted")

    checkpoint = definitions.get("head_checkpoint_body")
    checkpoint_properties = (
        checkpoint.get("properties") if type(checkpoint) is dict and type(checkpoint.get("properties")) is dict else {}
    )
    for field, reference in EXPECTED_HEAD_CHECKPOINT_PROPERTY_REFS_V1.items():
        if checkpoint_properties.get(field) != {"$ref": reference}:
            issues.append(f"protocol-v1 head checkpoint {field} reference drifted")
    expected_global_provenance = _predecessor_provenance_conditional(
        sequence_field="instance_sequence",
        genesis_sequence=0,
        attestation_field="previous_checkpoint_attestation_id",
        principal_field="previous_checkpoint_principal_id",
        trust_snapshot_field="previous_checkpoint_trust_snapshot_id",
    )
    expected_mission_provenance = _predecessor_provenance_conditional(
        sequence_field="event_seq",
        genesis_sequence=0,
        attestation_field=("previous_mission_checkpoint_attestation_id"),
        principal_field="previous_mission_checkpoint_principal_id",
        trust_snapshot_field=("previous_mission_checkpoint_trust_snapshot_id"),
    )
    if type(checkpoint) is not dict or checkpoint.get("allOf") != [
        expected_global_provenance,
        expected_mission_provenance,
    ]:
        observed_conditionals = (
            checkpoint.get("allOf") if type(checkpoint) is dict and type(checkpoint.get("allOf")) is list else []
        )
        if len(observed_conditionals) < 1 or observed_conditionals[0] != expected_global_provenance:
            issues.append("protocol-v1 head checkpoint global-predecessor provenance conditional drifted")
        if len(observed_conditionals) < 2 or observed_conditionals[1] != expected_mission_provenance:
            issues.append("protocol-v1 head checkpoint mission-predecessor provenance conditional drifted")
        if len(observed_conditionals) > 2:
            issues.append("protocol-v1 head checkpoint predecessor-provenance conditional registry drifted")
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
    *,
    expected_attestations_ref: str = "#/$defs/no_attestations",
) -> list[str]:
    """Require an exactly typed envelope with the named attestation contract."""

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
    if properties.get("attestations") != {"$ref": expected_attestations_ref}:
        if expected_attestations_ref == "#/$defs/one_ed25519_attestation":
            issues.append(f"{label} nested envelope must require one Ed25519 attestation")
        else:
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
            issues.append("protocol-v1 verification artifact type registry drifted")

    artifact_binding = definitions.get("verification_artifact_binding")
    issues.extend(
        _exact_object_contract_issues(
            artifact_binding,
            EXPECTED_VERIFICATION_ARTIFACT_BINDING_FIELDS_V1,
            "protocol-v1 verification artifact binding",
        )
    )
    if type(artifact_binding) is dict and type(artifact_binding.get("properties")) is dict:
        properties = artifact_binding["properties"]
        if properties.get("artifact_digest") != {"$ref": "#/$defs/sha256_id"}:
            issues.append("protocol-v1 verification artifact digest reference drifted")
        if properties.get("artifact_type") != {"$ref": "#/$defs/verification_artifact_type"}:
            issues.append("protocol-v1 verification artifact type reference drifted")
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
    if type(target_binding) is dict and type(target_binding.get("properties")) is dict:
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
                issues.append(f"protocol-v1 verification target artifact {field} contract drifted")

    role_bindings = {
        "modeled_effect_oracle_artifact_binding": "modeled_effect_oracle_spec",
        "modeled_effect_output_artifact_binding": "modeled_effect_output",
        "modeled_environment_artifact_binding": "modeled_environment_spec",
        "modeled_execution_output_artifact_binding": ("modeled_execution_output"),
        "modeled_measured_environment_output_artifact_binding": ("modeled_measured_environment_output"),
        "modeled_poc_artifact_binding": "modeled_poc_input",
        "modeled_supporting_evidence_artifact_binding": ("modeled_supporting_evidence_input"),
        "modeled_termination_output_artifact_binding": ("modeled_termination_output"),
    }
    for name, expected_type in role_bindings.items():
        value = definitions.get(name)
        expected = [
            {"$ref": "#/$defs/verification_artifact_binding"},
            {"properties": {"artifact_type": {"const": expected_type}}},
        ]
        if type(value) is not dict or value.get("allOf") != expected:
            issues.append(f"protocol-v1 {name.replace('_', ' ')} role contract drifted")

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
        "effect_oracle_artifact": {"$ref": "#/$defs/modeled_effect_oracle_artifact_binding"},
        "environment_artifact": {"$ref": "#/$defs/modeled_environment_artifact_binding"},
        "mission_id": {"$ref": "#/$defs/sha256_id"},
        "poc_artifact": {"$ref": "#/$defs/modeled_poc_artifact_binding"},
        "resolution_profile": {"const": EXPECTED_RESOLUTION_PROFILE_V1},
        "resolved_at": {"$ref": "#/$defs/epoch_second"},
        "target_snapshot_id": {"$ref": "#/$defs/sha256_id"},
        "verification_lease_id": {"$ref": "#/$defs/sha256_id"},
    }
    for field, expected in exact_properties.items():
        if properties.get(field) != expected:
            issues.append(f"protocol-v1 verification artifact resolution {field} contract drifted")
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
            issues.append(f"protocol-v1 verification artifact resolution {field} contract drifted")
    return issues


def _receipt_admission_schema_contract_issues(
    definitions: dict[str, object],
) -> list[str]:
    """Freeze the signed modeled-receipt admission wire boundary."""

    issues: list[str] = []
    receipt = definitions.get("verifier_receipt_body")
    issues.extend(
        _exact_object_contract_issues(
            receipt,
            EXPECTED_VERIFIER_RECEIPT_BODY_FIELDS_V1,
            "protocol-v1 verifier receipt body",
        )
    )
    receipt_properties = receipt.get("properties") if type(receipt) is dict else None
    if type(receipt_properties) is dict:
        for field in (
            "artifact_resolution_id",
            "effect_output_digest",
            "execution_output_digest",
            "measured_environment_output_digest",
            "termination_output_digest",
        ):
            if receipt_properties.get(field) != {"$ref": "#/$defs/sha256_id"}:
                issues.append(f"protocol-v1 verifier receipt {field} contract drifted")
        expected_output_size = {
            "type": "integer",
            "minimum": 1,
            "maximum": 67_108_864,
        }
        for field in (
            "effect_output_size",
            "execution_output_size",
            "measured_environment_output_size",
            "termination_output_size",
        ):
            if receipt_properties.get(field) != expected_output_size:
                issues.append(f"protocol-v1 verifier receipt {field} contract drifted")

    payload = definitions.get("event_payload_verifier_receipt_admitted")
    issues.extend(
        _exact_object_contract_issues(
            payload,
            EXPECTED_RECEIPT_ADMISSION_PAYLOAD_FIELDS_V1,
            "protocol-v1 verifier receipt admission event payload",
        )
    )
    payload_properties = payload.get("properties") if type(payload) is dict else None
    if type(payload_properties) is not dict:
        return issues

    expected_properties = {
        "adjudication_profile": {"const": EXPECTED_RECEIPT_ADJUDICATION_PROFILE_V1},
        "decision_trust_snapshot": {"$ref": "#/$defs/verifier_trust_snapshot"},
        "decision_trust_snapshot_id": {"$ref": "#/$defs/sha256_id"},
        "effect_output_artifact": {"$ref": "#/$defs/modeled_effect_output_artifact_binding"},
        "execution_output_artifact": {"$ref": "#/$defs/modeled_execution_output_artifact_binding"},
        "measured_environment_output_artifact": {
            "$ref": ("#/$defs/modeled_measured_environment_output_artifact_binding")
        },
        "termination_output_artifact": {"$ref": "#/$defs/modeled_termination_output_artifact_binding"},
    }
    for field, expected in expected_properties.items():
        if payload_properties.get(field) != expected:
            issues.append(f"protocol-v1 verifier receipt admission {field} contract drifted")
    issues.extend(
        _nested_event_envelope_contract_issues(
            payload_properties.get("receipt"),
            definitions,
            "verifier_receipt",
            "protocol-v1 verifier_receipt_admitted.receipt",
            expected_attestations_ref=("#/$defs/one_ed25519_attestation"),
        )
    )
    return issues


def _verification_recovery_schema_contract_issues(
    definitions: object,
) -> list[str]:
    """Freeze the closed recovery reasons, references, and terminal statuses."""

    if type(definitions) is not dict:
        return ["protocol-v1 verification recovery definitions are missing"]
    issues: list[str] = []
    cancelled = definitions.get("event_payload_verification_lease_cancelled")
    expired = definitions.get("event_payload_verification_lease_expired")
    reassigned = definitions.get("event_payload_verification_lease_reassigned")
    mission_closed = definitions.get("event_payload_mission_closed")
    cancelled_properties = cancelled.get("properties") if type(cancelled) is dict else None
    expired_properties = expired.get("properties") if type(expired) is dict else None
    reassigned_properties = reassigned.get("properties") if type(reassigned) is dict else None
    mission_closed_properties = mission_closed.get("properties") if type(mission_closed) is dict else None
    if type(cancelled_properties) is not dict:
        issues.append("protocol-v1 verification lease cancellation properties drifted")
    else:
        if cancelled_properties.get("reason_code") != {"const": EXPECTED_VERIFICATION_LEASE_CANCELLATION_REASON_V1}:
            issues.append("protocol-v1 verification lease cancellation reason drifted")
        if cancelled_properties.get("verification_lease_id") != {"$ref": "#/$defs/sha256_id"}:
            issues.append("protocol-v1 verification lease cancellation ID reference drifted")
    if type(expired_properties) is not dict or expired_properties.get("verification_lease_id") != {
        "$ref": "#/$defs/sha256_id"
    }:
        issues.append("protocol-v1 verification lease expiry ID reference drifted")
    if type(reassigned_properties) is not dict:
        issues.append("protocol-v1 verification lease reassignment properties drifted")
    else:
        reason_contract = reassigned_properties.get("reason_code")
        raw_reasons = reason_contract.get("enum") if type(reason_contract) is dict else None
        if (
            type(raw_reasons) is not list
            or len(raw_reasons) != len(EXPECTED_VERIFICATION_LEASE_REASSIGNMENT_REASONS_V1)
            or frozenset(raw_reasons) != EXPECTED_VERIFICATION_LEASE_REASSIGNMENT_REASONS_V1
        ):
            issues.append("protocol-v1 verification lease reassignment reasons drifted")
        if reassigned_properties.get("predecessor_verification_lease_id") != {"$ref": "#/$defs/sha256_id"}:
            issues.append("protocol-v1 verification lease predecessor reference drifted")
        if reassigned_properties.get("verifier_trust_snapshot") != {"$ref": "#/$defs/verifier_trust_snapshot"}:
            issues.append("protocol-v1 verification lease reassignment trust reference drifted")
        if reassigned_properties.get("verifier_trust_snapshot_id") != {"$ref": "#/$defs/sha256_id"}:
            issues.append("protocol-v1 verification lease reassignment trust ID reference drifted")
    status_contract = mission_closed_properties.get("status") if type(mission_closed_properties) is dict else None
    raw_statuses = status_contract.get("enum") if type(status_contract) is dict else None
    if (
        type(raw_statuses) is not list
        or len(raw_statuses) != len(EXPECTED_MISSION_CLOSED_STATUSES_V1)
        or frozenset(raw_statuses) != EXPECTED_MISSION_CLOSED_STATUSES_V1
    ):
        issues.append("protocol-v1 mission closure statuses drifted")
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
    if REQUIRED_ATTESTED_OBJECT_KINDS_V1 != EXPECTED_REQUIRED_ATTESTED_OBJECT_KINDS_V1:
        issues.append("protocol-v1 required-attestation registry drifted")
    if REQUIRED_ATTESTED_OBJECT_KINDS_V1 & OPTIONALLY_ATTESTED_OBJECT_KINDS_V1:
        issues.append("protocol-v1 attestation registries overlap")
    if not (REQUIRED_ATTESTED_OBJECT_KINDS_V1 | OPTIONALLY_ATTESTED_OBJECT_KINDS_V1).issubset(SUPPORTED_OBJECT_KINDS):
        issues.append("protocol-v1 attestation registry names an unsupported kind")
    if len(EVENT_UNIT_BY_KIND_V1) != EXPECTED_EVENT_KIND_COUNT_V1:
        issues.append("protocol-v1 runtime event-kind count drifted")
    if {
        kind: EVENT_UNIT_BY_KIND_V1.get(kind) for kind in EXPECTED_VERIFICATION_RECOVERY_EVENT_UNITS_V1
    } != EXPECTED_VERIFICATION_RECOVERY_EVENT_UNITS_V1:
        issues.append("protocol-v1 runtime verification recovery event units drifted")
    if {
        kind: EVENT_PAYLOAD_FIELDS_BY_KIND_V1.get(kind) for kind in EXPECTED_VERIFICATION_RECOVERY_PAYLOAD_FIELDS_V1
    } != EXPECTED_VERIFICATION_RECOVERY_PAYLOAD_FIELDS_V1:
        issues.append("protocol-v1 runtime verification recovery payload fields drifted")
    if {
        kind: EVENT_NESTED_ENVELOPE_KIND_BY_FIELD_V1.get(kind)
        for kind in EXPECTED_VERIFICATION_RECOVERY_NESTED_ENVELOPES_V1
    } != EXPECTED_VERIFICATION_RECOVERY_NESTED_ENVELOPES_V1:
        issues.append("protocol-v1 runtime verification recovery nested envelopes drifted")
    if VERIFICATION_LEASE_CANCELLATION_REASON_V1 != EXPECTED_VERIFICATION_LEASE_CANCELLATION_REASON_V1:
        issues.append("protocol-v1 runtime verification cancellation reason drifted")
    if VERIFICATION_LEASE_REASSIGNMENT_REASONS_V1 != EXPECTED_VERIFICATION_LEASE_REASSIGNMENT_REASONS_V1:
        issues.append("protocol-v1 runtime verification reassignment reasons drifted")
    if MISSION_CLOSED_STATUSES_V1 != EXPECTED_MISSION_CLOSED_STATUSES_V1:
        issues.append("protocol-v1 runtime mission closure statuses drifted")
    if RESOLUTION_PROFILE_V1 != EXPECTED_RESOLUTION_PROFILE_V1:
        issues.append("protocol-v1 runtime resolution profile drifted")
    if RESOLUTION_BODY_FIELDS_V1 != EXPECTED_RESOLUTION_BODY_FIELDS_V1:
        issues.append("protocol-v1 runtime resolution body fields drifted")
    if SEMANTIC_BODY_FIELDS_BY_KIND_V1.get("verifier_receipt") != EXPECTED_VERIFIER_RECEIPT_BODY_FIELDS_V1:
        issues.append("protocol-v1 runtime verifier receipt body fields drifted")
    if EVENT_UNIT_BY_KIND_V1.get("verifier_receipt_admitted") != "ETZIO":
        issues.append("protocol-v1 runtime receipt admission event unit drifted")
    if RECEIPT_ADMISSION_PROFILE_V1 != EXPECTED_RECEIPT_ADJUDICATION_PROFILE_V1:
        issues.append("protocol-v1 runtime receipt admission profile drifted")
    if EVENT_PAYLOAD_FIELDS_BY_KIND_V1.get("verifier_receipt_admitted") != EXPECTED_RECEIPT_ADMISSION_PAYLOAD_FIELDS_V1:
        issues.append("protocol-v1 runtime receipt admission payload fields drifted")
    if EVENT_NESTED_ENVELOPE_KIND_BY_FIELD_V1.get("verifier_receipt_admitted") != {"receipt": "verifier_receipt"}:
        issues.append("protocol-v1 runtime receipt admission nested envelope map drifted")
    if VERIFICATION_ARTIFACT_BINDING_FIELDS_V1 != EXPECTED_VERIFICATION_ARTIFACT_BINDING_FIELDS_V1:
        issues.append("protocol-v1 runtime verification artifact binding fields drifted")
    if TARGET_ARTIFACT_BINDING_FIELDS_V1 != EXPECTED_TARGET_ARTIFACT_BINDING_FIELDS_V1:
        issues.append("protocol-v1 runtime target artifact binding fields drifted")
    if frozenset((*VERIFICATION_ARTIFACT_TYPES_V1, TARGET_ARTIFACT_TYPE_V1)) != EXPECTED_VERIFICATION_ARTIFACT_TYPES_V1:
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
            or root_attestations.get("items") != {"$ref": "#/$defs/ed25519_attestation"}
        ):
            issues.append("protocol-v1 envelope attestation frame drifted")

    try:
        raw_schema_kinds = schema["properties"]["object_kind"]["enum"]
        schema_kinds = frozenset(raw_schema_kinds)
    except (KeyError, TypeError):
        raw_schema_kinds = []
        schema_kinds = frozenset()
        issues.append("protocol-v1 schema is missing its object-kind enum")
    if len(raw_schema_kinds) != len(SUPPORTED_OBJECT_KINDS) or schema_kinds != SUPPORTED_OBJECT_KINDS:
        issues.append("protocol-v1 schema object kinds differ from the runtime allowlist")

    expected_case_refs = frozenset(f"#/$defs/{kind}_case" for kind in SUPPORTED_OBJECT_KINDS)
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
    issues.extend(_integrity_schema_contract_issues(definitions))
    issues.extend(_verification_artifact_schema_contract_issues(definitions))
    issues.extend(_receipt_admission_schema_contract_issues(definitions))
    issues.extend(_verification_recovery_schema_contract_issues(definitions))

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
        if len(frame_kinds) != len(SUPPORTED_OBJECT_KINDS) or frozenset(frame_kinds) != SUPPORTED_OBJECT_KINDS:
            issues.append("protocol-v1 nested frame object kinds differ from runtime")
        frame_attestations = frame_properties.get("attestations")
        if (
            type(frame_attestations) is not dict
            or frame_attestations.get("type") != "array"
            or frame_attestations.get("minItems", 0) != 0
            or frame_attestations.get("maxItems") != 1
            or frame_attestations.get("items") != {"$ref": "#/$defs/ed25519_attestation"}
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
        if frozenset(case_properties) != frozenset({"object_kind", "body", "attestations"}):
            issues.append(f"protocol-v1 {kind} case fields drifted")
        if case_properties.get("object_kind") != {"const": kind}:
            issues.append(f"protocol-v1 {kind} case discriminator drifted")
        if case_properties.get("body") != {"$ref": f"#/$defs/{kind}_body"}:
            issues.append(f"protocol-v1 {kind} case body reference drifted")

        attestation_contract = case_properties.get("attestations")
        if kind in REQUIRED_ATTESTED_OBJECT_KINDS_V1:
            if attestation_contract != {"$ref": "#/$defs/one_ed25519_attestation"}:
                issues.append(f"protocol-v1 {kind} must require one Ed25519 attestation")
        elif kind in OPTIONALLY_ATTESTED_OBJECT_KINDS_V1:
            try:
                attestation_refs = [branch["$ref"] for branch in attestation_contract["oneOf"]]
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
    verification_event_payload = definitions.get("event_payload_verification_lease_issued")
    verification_event_properties = (
        verification_event_payload.get("properties") if type(verification_event_payload) is dict else None
    )
    if type(verification_event_properties) is not dict:
        issues.append("protocol-v1 verification lease event properties are malformed")
    else:
        if verification_event_properties.get("verifier_trust_snapshot") != {"$ref": "#/$defs/verifier_trust_snapshot"}:
            issues.append("protocol-v1 verification lease event trust snapshot reference drifted")
        if verification_event_properties.get("verifier_trust_snapshot_id") != {"$ref": "#/$defs/sha256_id"}:
            issues.append("protocol-v1 verification lease event trust snapshot ID reference drifted")

    event_body_common = definitions.get("event_body_common")
    event_body_common_properties = event_body_common.get("properties") if type(event_body_common) is dict else None
    if type(event_body_common_properties) is not dict:
        issues.append("protocol-v1 event common body properties are malformed")
    else:
        event_kind_contract = event_body_common_properties.get("kind")
        raw_event_kinds = event_kind_contract.get("enum") if type(event_kind_contract) is dict else None
        if (
            type(raw_event_kinds) is not list
            or any(type(kind) is not str for kind in raw_event_kinds)
            or len(raw_event_kinds) != len(EVENT_UNIT_BY_KIND_V1)
            or frozenset(raw_event_kinds) != frozenset(EVENT_UNIT_BY_KIND_V1)
        ):
            issues.append("protocol-v1 event common kind enum differs from the runtime contract")

        expected_event_units = frozenset(EVENT_UNIT_BY_KIND_V1.values())
        event_unit_contract = event_body_common_properties.get("unit")
        raw_event_units = event_unit_contract.get("enum") if type(event_unit_contract) is dict else None
        if (
            type(raw_event_units) is not list
            or any(type(unit) is not str for unit in raw_event_units)
            or len(raw_event_units) != len(expected_event_units)
            or frozenset(raw_event_units) != expected_event_units
        ):
            issues.append("protocol-v1 event common unit enum differs from the runtime contract")

    event_body = definitions.get("event_body")
    try:
        event_body_refs = [branch["$ref"] for branch in event_body["allOf"]]
    except (KeyError, TypeError):
        event_body_refs = []
    expected_event_body_refs = frozenset({"#/$defs/event_body_common", "#/$defs/event_variants"})
    if len(event_body_refs) != len(expected_event_body_refs) or frozenset(event_body_refs) != expected_event_body_refs:
        issues.append("protocol-v1 event body composition drifted")

    issues.extend(
        _exact_object_contract_issues(
            definitions.get("ed25519_attestation"),
            frozenset({"algorithm", "key_id", "signature_b64"}),
            "protocol-v1 Ed25519 attestation",
        )
    )
    ed25519_attestation = definitions.get("ed25519_attestation")
    if type(ed25519_attestation) is dict and type(ed25519_attestation.get("properties")) is dict:
        attestation_properties = ed25519_attestation["properties"]
        if attestation_properties.get("algorithm") != {"const": "ed25519"}:
            issues.append("protocol-v1 attestation algorithm contract drifted")
        if attestation_properties.get("key_id") != {"$ref": "#/$defs/ed25519_key_id"}:
            issues.append("protocol-v1 attestation key contract drifted")
        if attestation_properties.get("signature_b64") != {"$ref": "#/$defs/ed25519_signature_b64"}:
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
        or one_attestation.get("items") != {"$ref": "#/$defs/ed25519_attestation"}
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
                nested_schema = payload_properties.get(field) if type(payload_properties) is dict else None
                issues.extend(
                    _nested_event_envelope_contract_issues(
                        nested_schema,
                        definitions,
                        expected_kind,
                        f"protocol-v1 {kind}.{field}",
                        expected_attestations_ref=(
                            "#/$defs/one_ed25519_attestation"
                            if (kind == "verifier_receipt_admitted" and field == "receipt")
                            else "#/$defs/no_attestations"
                        ),
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
                issues.extend(f"{path.relative_to(ROOT)}: {issue}" for issue in protocol_schema_contract_issues(schema))
            elif path in LEGACY_SCHEMA_PATHS and (
                type(schema) is not dict or schema.get("x-etzio-status") != "modeled_non_authoritative"
            ):
                issues.append(
                    f"{path.relative_to(ROOT)}: legacy schema must remain explicitly modeled and non-authoritative"
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
        f"tracked runtime or secret artifact: {path}" for path in tracked if any(item in path for item in forbidden)
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

    issues.extend(verification_entrypoint_issues((ROOT / "scripts/ci/verify.sh").read_text(encoding="utf-8")))
    issues.extend(makefile_issues((ROOT / "Makefile").read_text(encoding="utf-8")))
    issues.extend(
        pyproject_configuration_issues(
            (ROOT / "pyproject.toml").read_text(encoding="utf-8"),
            ROOT,
        )
    )

    workflows = sorted(
        path for path in (ROOT / ".github/workflows").iterdir() if path.is_file() and path.suffix in {".yml", ".yaml"}
    )
    for workflow in workflows:
        text = workflow.read_text(encoding="utf-8")
        issues.extend(workflow_syntax_issues(text, str(workflow.relative_to(ROOT))))
        issues.extend(action_ref_issues(text, str(workflow.relative_to(ROOT))))
        issues.extend(workflow_permission_issues(text, str(workflow.relative_to(ROOT))))
        if workflow == ROOT / ".github/workflows/ci.yml":
            issues.extend(
                foundation_workflow_issues(
                    text,
                    str(workflow.relative_to(ROOT)),
                )
            )

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
        [path for path in (ROOT / ".github/workflows").iterdir() if path.is_file() and path.suffix in {".yml", ".yaml"}]
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
