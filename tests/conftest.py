"""Full-suite evidence checks used by the canonical verification command."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_HANDOFF_TEST_COUNT = re.compile(
    r"^- (?P<count>[0-9]+) tests passed;$",
    re.MULTILINE,
)


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("etzio")
    group.addoption(
        "--verify-mission-evidence",
        action="store_true",
        default=False,
        help="fail collection when retained full-suite counts differ",
    )


def pytest_collection_finish(session: pytest.Session) -> None:
    if not session.config.getoption("--verify-mission-evidence"):
        return

    mission_state = json.loads(
        (_REPOSITORY_ROOT / "docs" / "MISSION_STATE.json").read_text(
            encoding="utf-8"
        )
    )
    retained_count = mission_state.get("current_evidence", {}).get(
        "test_count"
    )
    handoff = (
        _REPOSITORY_ROOT / "docs" / "SESSION_HANDOFF.md"
    ).read_text(encoding="utf-8")
    handoff_counts = {
        int(match.group("count"))
        for match in _HANDOFF_TEST_COUNT.finditer(handoff)
    }
    collected_count = len(session.items)
    if (
        type(retained_count) is not int
        or retained_count != collected_count
        or handoff_counts != {collected_count}
    ):
        raise pytest.UsageError(
            "retained verification evidence drifted: "
            f"collected={collected_count}, "
            f"mission_state={retained_count!r}, "
            f"handoff={sorted(handoff_counts)}"
        )
