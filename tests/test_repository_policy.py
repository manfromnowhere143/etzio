"""Known-bad controls for repository provenance and workflow policy."""

from __future__ import annotations

from pathlib import Path

from scripts.validate_repository import (
    action_ref_issues,
    author_record_issues,
    mission_state_issues,
    required_path_issues,
    workflow_permission_issues,
    workflow_syntax_issues,
)


def test_mutable_action_tag_is_rejected():
    issues = action_ref_issues("steps:\n  - uses: actions/checkout@v7\n", "known-bad.yml")
    assert issues
    assert "not pinned" in issues[0]


def test_missing_required_schema_is_rejected(tmp_path: Path):
    required = ("schemas/protocol.v1.schema.json",)
    assert required_path_issues(tmp_path, required) == [
        "missing required repository file: schemas/protocol.v1.schema.json"
    ]


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
