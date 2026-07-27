"""Fail-closed repository policy checks for the Etzio foundation.

This validator concerns repository bytes and provenance. It does not establish detection
quality, sandbox safety, authorization validity, or readiness for a live target.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from jsonschema.exceptions import SchemaError
from jsonschema.validators import validator_for

ROOT = Path(__file__).resolve().parents[1]
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
    "docs/decisions/README.md",
    "schemas/finding.schema.json",
    "schemas/target-contract.schema.json",
    "schemas/verdict.schema.json",
    ".github/CODEOWNERS",
    ".github/workflows/ci.yml",
    "tools/ci/requirements-ci.in",
    "tools/ci/requirements-ci.lock",
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


def _schema_issues() -> list[str]:
    issues: list[str] = []
    for path in sorted((ROOT / "schemas").glob("*.json")):
        try:
            schema = json.loads(path.read_text(encoding="utf-8"))
            validator_for(schema).check_schema(schema)
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
    schema_count = len(list((ROOT / "schemas").glob("*.json")))
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
