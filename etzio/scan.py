"""Run Etzio's governed protocol-v1 scan on an immutable repository fixture.

This command deliberately has no target-path argument. It creates an ephemeral local
operator key for one repository-owned benchmark mission, admits that signed grant, retains
exact fixture bytes, executes VELITES static analysis through the durable kernel, and
replays the resulting event stream before reporting candidates. A candidate is not a
finding.
"""

from __future__ import annotations

import argparse
import os
import secrets
import stat
import sys
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path

from .authority import (
    AuthorityGrantV1,
    AuthoritySigner,
    TrustedAuthorityKey,
    TrustStore,
)
from .evidence import (
    FileEvidenceStore,
    TargetSnapshotV1,
    read_etzio_fixture,
    retain_snapshot,
)
from .kernel.fixture_scan import run_fixture_scan
from .kernel.reducer import MissionProjection, ProjectionPhase, reduce_events
from .kernel.store import SQLiteEventStore
from .mission_v1 import StaticCandidateV1
from .protocol import EnvelopeV1, canonical_dumps, content_id, thaw_json

_FIXTURES = {
    "clean": "clean_app.py",
    "vulnerable": "vulnerable_app.py",
}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m etzio.scan",
        description="Run the authority-gated Etzio scan on one repository-owned fixture.",
    )
    parser.add_argument(
        "--fixture",
        choices=tuple(sorted(_FIXTURES)),
        default="vulnerable",
        help="closed-manifest fixture to analyze (default: vulnerable)",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="report format (default: text); JSON uses etzio.fixture_scan_report.v1",
    )
    parser.add_argument(
        "--state-dir",
        type=Path,
        help="private mode-0700 state directory; default is ephemeral",
    )
    return parser


def _prepare_state_dir(path: Path) -> Path:
    if path.exists():
        if path.is_symlink() or not path.is_dir():
            raise ValueError("state directory must be a non-symlink directory")
        metadata = path.stat(follow_symlinks=False)
        if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
            raise ValueError("state directory must be owned by the current service user")
        if stat.S_IMODE(metadata.st_mode) != 0o700:
            raise ValueError("existing state directory must already have mode 0700")
    else:
        path.mkdir(mode=0o700, parents=False)
    return path


def _execute(
    fixture_name: str,
    state_dir: Path,
) -> tuple[MissionProjection, TargetSnapshotV1, str]:
    now = int(time.time())
    evidence_store = FileEvidenceStore(state_dir / "evidence")
    relative_path, fixture_bytes = read_etzio_fixture(fixture_name, maximum=64 * 1024)
    snapshot = retain_snapshot(
        "repository_fixture",
        {relative_path: fixture_bytes},
        evidence_store,
    )
    authority_evidence = evidence_store.put(
        canonical_dumps(
            {
                "fixture": fixture_name,
                "kind": "ephemeral_repository_benchmark_authority",
            }
        )
    )
    signer = AuthoritySigner.generate()
    grant = AuthorityGrantV1.issue(
        issuer="operator:daniel",
        subject="benchmark:etzio-python-fixture-v1",
        target_snapshot_id=snapshot.object_id,
        assets=(f"fixture://{relative_path}",),
        permitted_actions=("static_analysis",),
        evidence_digest=authority_evidence.digest,
        issued_at=now,
        not_before=now,
        expires_at=now + 300,
        max_bytes=len(fixture_bytes),
        max_candidates=100,
        max_wallclock_seconds=60,
    )
    signed = signer.sign(grant)
    trust_store = TrustStore.from_keys(
        (
            TrustedAuthorityKey(
                signer.public_key_bytes,
                frozenset({"operator"}),
                frozenset({"operator:daniel"}),
            ),
        )
    )
    mission_id = content_id(
        "mission",
        {
            "nonce": secrets.token_hex(16),
            "target_snapshot_id": snapshot.object_id,
        },
    )
    with SQLiteEventStore(state_dir / "events.sqlite3") as event_store:
        projection = run_fixture_scan(
            mission_id=mission_id,
            snapshot=snapshot,
            signed_authority=signed,
            trust_store=trust_store,
            evidence_store=evidence_store,
            event_store=event_store,
            decision_time=now,
        )
        replayed = event_store.load(mission_id)
    if replayed != projection.events:
        raise RuntimeError("durable replay differs from the mission projection")
    return reduce_events(replayed), snapshot, relative_path


def _scan_status(projection: MissionProjection) -> tuple[str, str | None]:
    """Keep lifecycle closure separate from complete static analysis."""

    if projection.phase is ProjectionPhase.CLOSED:
        if projection.parse_failures:
            return "incomplete", "parse_failures"
        if (
            projection.scan_summary is not None
            and projection.terminal_event is not None
            and projection.terminal_event.payload["status"] == "completed"
        ):
            return "completed", None
    if projection.phase in {
        ProjectionPhase.REFUSED,
        ProjectionPhase.FAILED,
        ProjectionPhase.CANCELLED,
        ProjectionPhase.TIMED_OUT,
        ProjectionPhase.BUDGET_EXHAUSTED,
    }:
        terminal = projection.terminal_event
        if terminal is None:
            raise RuntimeError("terminal fixture result has no retained terminal event")
        return projection.phase.value, terminal.payload["reason_code"]
    return "incomplete", "static_scan_not_closed"


def _candidates(projection: MissionProjection) -> tuple[StaticCandidateV1, ...]:
    return tuple(
        StaticCandidateV1.from_envelope(
            EnvelopeV1.from_bytes(canonical_dumps(thaw_json(event.payload)["candidate"]))
        )
        for event in projection.candidate_events
    )


def _json_report(
    projection: MissionProjection,
    snapshot: TargetSnapshotV1,
    relative_path: str,
    *,
    ephemeral: bool,
) -> dict[str, object]:
    """Present the supported static fixture command; this is not an admission API."""

    status, reason = _scan_status(projection)
    return {
        "schema_version": "etzio.fixture_scan_report.v1",
        "scope": "repository_fixture",
        "claim_level": "static_candidates",
        "verification_status": "not_performed",
        "mission_id": projection.mission_id,
        "authority_id": projection.authority_id,
        "target_snapshot_id": snapshot.object_id,
        "event_head": projection.events[-1].event_digest,
        "event_count": len(projection.events),
        "fixture": relative_path,
        "phase": projection.phase.value,
        "status": status,
        "reason_code": reason,
        "state_retention": "ephemeral" if ephemeral else "operator_path",
        "candidate_count": len(projection.candidate_events),
        "candidates": [
            {
                "candidate_id": candidate.candidate_id,
                "claim_id": candidate.claim_id,
                "source_artifact_digest": candidate.source_artifact_digest,
                "relative_path": candidate.relative_path,
                "line": candidate.line,
                "column": candidate.column,
                "rule_id": candidate.rule_id,
                "severity": candidate.severity,
            }
            for candidate in _candidates(projection)
        ],
        "parse_failure_count": len(projection.parse_failures),
        "parse_failures": [thaw_json(event.payload)["parse_failure"] for event in projection.parse_failures],
    }


def _render(
    projection: MissionProjection,
    snapshot: TargetSnapshotV1,
    relative_path: str,
    *,
    ephemeral: bool,
) -> None:
    print("=" * 78)
    print("ETZIO governed fixture scan · protocol v1")
    print("=" * 78)
    print(f"mission          : {projection.mission_id}")
    print(f"target snapshot  : {snapshot.object_id}")
    print(f"fixture          : {relative_path}")
    print(f"terminal phase   : {projection.phase.value}")
    status, reason = _scan_status(projection)
    print(f"scan status      : {status}")
    if reason is not None:
        print(f"reason           : {reason}")
    print(f"parse failures   : {len(projection.parse_failures)}")
    print(f"durable events   : {len(projection.events)}")
    print(f"state retention  : {'ephemeral demo directory' if ephemeral else 'operator path'}")
    print("-" * 78)
    print(f"VELITES candidates: {len(projection.candidate_events)}")
    for candidate in _candidates(projection):
        print(
            f"  {candidate.candidate_id}  [{candidate.severity}] "
            f"{candidate.rule_id} at {candidate.relative_path}:"
            f"{candidate.line}:{candidate.column}"
        )
    print("-" * 78)
    print("state: candidates only — no PoC, independent reproduction, or finding was created")
    print("=" * 78)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    fixture_name = _FIXTURES[args.fixture]
    ephemeral = args.state_dir is None
    try:
        with ExitStack() as cleanup:
            if ephemeral:
                temporary = cleanup.enter_context(tempfile.TemporaryDirectory(prefix="etzio-fixture-"))
                state_dir = Path(temporary)
                os.chmod(state_dir, 0o700)
            else:
                state_dir = _prepare_state_dir(args.state_dir)
            projection, snapshot, relative_path = _execute(fixture_name, state_dir)
        # Finish ephemeral cleanup before emitting a report. Both retention modes
        # use the same outcome policy and operational-error channel.
        if args.format == "json":
            report = _json_report(projection, snapshot, relative_path, ephemeral=ephemeral)
            print(canonical_dumps(report).decode("utf-8"))
        else:
            _render(projection, snapshot, relative_path, ephemeral=ephemeral)
        return 0 if _scan_status(projection)[0] == "completed" else 3
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"error: governed fixture mission failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
