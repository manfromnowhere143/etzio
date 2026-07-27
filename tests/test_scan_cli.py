"""Supported command-line boundary for the governed repository fixtures."""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from etzio.scan import main


def test_cli_has_no_arbitrary_target_path_escape_hatch(capsys) -> None:
    with pytest.raises(SystemExit) as caught:
        main(["/tmp/unadmitted-target"])

    assert caught.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err


def test_cli_runs_clean_fixture_through_private_durable_state(
    tmp_path: Path,
    capsys,
) -> None:
    state_dir = tmp_path / "state"

    assert main(["--fixture", "clean", "--state-dir", str(state_dir)]) == 0

    output = capsys.readouterr().out
    assert "terminal phase   : closed" in output
    assert "VELITES candidates: 0" in output
    assert stat.S_IMODE(state_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE((state_dir / "events.sqlite3").stat().st_mode) == 0o600


def test_cli_refuses_existing_nonprivate_state_directory_without_changing_its_mode(
    tmp_path: Path,
    capsys,
) -> None:
    state_dir = tmp_path / "shared"
    state_dir.mkdir(mode=0o755)
    state_dir.chmod(0o755)

    assert main(["--fixture", "clean", "--state-dir", str(state_dir)]) == 2

    assert "must already have mode 0700" in capsys.readouterr().err
    assert stat.S_IMODE(state_dir.stat().st_mode) == 0o755
