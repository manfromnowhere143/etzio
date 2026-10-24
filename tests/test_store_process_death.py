"""Real process death at canonical commit boundaries; see STORE_PROCESS_DEATH.md."""

from __future__ import annotations

import json
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from test_qualified_anchor_consumption_v1 import _head_fixture
from test_qualified_cold_replay_v1 import _prepare_phase, _retain
from test_qualified_fixture_lifecycle_v1 import _enroll_store, _event, _service
from test_transactional_evidence_vault_v1 import (
    _append_protected_prefix,
    _build_harness,
)
from test_transactional_evidence_vault_v1 import (
    _event as _vault_event,
)

from etzio.evidence import FileEvidenceStore
from etzio.kernel.events_v1 import EventV1
from etzio.kernel.evidence_vault import PROTECTED_EVIDENCE_EVENT_KINDS_V1
from etzio.kernel.integrity_transition import (
    AnchorStatementRecordV1,
    CheckpointCandidateRecordV1,
    FinalizedIntegrityTransitionV1,
    PendingIntegrityTransitionV1,
)
from etzio.kernel.store import PendingIntegrityTransitionError, SQLiteEventStore, StaleHeadError
from etzio.protocol import content_id

_ROOT = Path(__file__).resolve().parents[1]
_PHASE_TYPES = {
    "pending": PendingIntegrityTransitionV1,
    "anchor_statement": AnchorStatementRecordV1,
    "checkpoint_candidate": CheckpointCandidateRecordV1,
    "finalization": FinalizedIntegrityTransitionV1,
}
_CASES = [*sorted(PROTECTED_EVIDENCE_EVENT_KINDS_V1), *_PHASE_TYPES]
_JOURNAL_MAGIC = "d9d505f920a163d7"


def _operation(store, plan):
    event = EventV1.from_canonical_bytes(plan["event"].encode())
    if plan["case"] in _PHASE_TYPES:
        record = _PHASE_TYPES[plan["case"]].from_canonical_bytes(plan["record"].encode())
        _retain(store, event, plan["case"], record)
        return "retained"
    append = (store.append_receipt_admission if event.kind == "verifier_receipt_admitted"
              else store.append_evidence_event)
    try:
        append(event, expected_head=event.prev_digest,
               evidence_store=FileEvidenceStore(plan["staging"]))
    except StaleHeadError:
        # These low-level evidence appends deliberately refuse duplicate writes.
        # Reconciliation requires the exact retained event, never a guessed success.
        assert store.load(event.mission_id)[-1].to_canonical_bytes() == event.to_canonical_bytes()
        return "exact_retained_stale_head"
    return "retained"


def _child_main():
    """Only the subprocess uses this connection class; no runtime kill hooks."""
    plan_path, database, point = sys.argv[1:]
    plan = json.loads(Path(plan_path).read_text())
    original_connect = sqlite3.connect

    class KillConnection(sqlite3.Connection):
        armed = False
        initial_changes = 0

        def execute(self, sql, parameters=()):
            if (sql == "COMMIT" and self.armed and point != "none"
                    and self.total_changes > self.initial_changes):
                assert self.in_transaction
                assert self.total_changes > self.initial_changes
                if point == "after":
                    super().execute(sql, parameters)
                journal = Path(database + "-journal")
                header = journal.read_bytes()[:8].hex() if journal.exists() else None
                print(json.dumps({"point": point, "in_transaction": self.in_transaction,
                                  "journal_header": header}), flush=True)
                os.kill(os.getpid(), signal.SIGKILL)
                raise AssertionError("SIGKILL returned")
            return super().execute(sql, parameters)

    def connect(*args, **kwargs):
        return original_connect(*args, **kwargs, factory=KillConnection)

    sqlite3.connect = connect
    with SQLiteEventStore(database) as store:
        if plan["spill"]:
            store._connection.execute("PRAGMA cache_size=1")
            store._connection.execute("PRAGMA cache_spill=1")
            assert store._connection.execute("PRAGMA cache_size").fetchone()[0] == 1
            assert store._connection.execute("PRAGMA cache_spill").fetchone()[0] == 1
        store._connection.initial_changes = store._connection.total_changes
        store._connection.armed = True
        outcome = _operation(store, plan)
    print(json.dumps({"returned": outcome}), flush=True)


def _run_child(plan_path, database, point):
    code = ("import sys; sys.path.insert(0, 'tests'); "
            "from test_store_process_death import _child_main; _child_main()")
    result = subprocess.run([sys.executable, "-c", code, str(plan_path), str(database), point],
                            cwd=_ROOT, capture_output=True, text=True, timeout=60, check=False)
    assert result.stderr == "", result.stderr
    if point == "none":
        assert result.returncode == 0, result.stdout
        marker = json.loads(result.stdout)
        assert marker["returned"] in ("retained", "exact_retained_stale_head")
        return marker
    assert result.returncode == -signal.SIGKILL, result.stdout
    marker = json.loads(result.stdout)
    assert marker["point"] == point
    assert marker["in_transaction"] is (point == "before")
    return marker


def _prepare(tmp_path, case, spill):
    database = tmp_path / "prefix.sqlite3"
    plan = {"case": case, "spill": spill}
    if case in _PHASE_TYPES:
        fixture = _head_fixture()
        service, event = _service(fixture), _event(fixture)
        with SQLiteEventStore(database) as store:
            _enroll_store(store, service)
            record = _prepare_phase(store, service, event, case)
        plan["record"] = record.to_canonical_bytes().decode()
    else:
        harness = _build_harness(tmp_path / "dossier",
                                 authority_marker="inert:" + "x" * 262144 if spill else "process_death")
        event = _vault_event(harness, case)
        with SQLiteEventStore(database) as store:
            _append_protected_prefix(store, harness.events, stop_before=event,
                                     evidence_store=harness.evidence_store)
        plan["staging"] = str(harness.evidence_store.root)
    plan["event"] = event.to_canonical_bytes().decode()
    plan_path = tmp_path / "operation.json"
    plan_path.write_text(json.dumps(plan))
    return database, plan_path, plan, event


def _cold_snapshot(database, event, qualified):
    with SQLiteEventStore(database) as store:
        if qualified:
            unresolved = store.load_unresolved_integrity_transition()
            if unresolved is not None:
                assert unresolved.pending.event_digest == event.event_digest
                assert store.load_integrity_lineage(event.event_digest).finalization is None
                other_mission = content_id("mission", {"fixture": "process-death-other-mission"})
                assert other_mission != event.mission_id
                for mission in (event.mission_id, other_mission):
                    with pytest.raises(PendingIntegrityTransitionError):
                        store.load(mission)
            else:
                events = store.load(event.mission_id)
                assert events in ((), (event,))
                if events:
                    assert store.load_integrity_lineage(event.event_digest).finalization is not None
        else:
            store.load(event.mission_id)
        assert store._connection.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
        assert store._connection.execute("PRAGMA foreign_key_check").fetchall() == []
        return tuple(store._connection.iterdump())


def _exercise(tmp_path, case, point, *, spill=False):
    prefix, plan_path, plan, event = _prepare(tmp_path, case, spill)
    qualified = case in _PHASE_TYPES
    before = _cold_snapshot(prefix, event, qualified)
    complete, killed = tmp_path / "complete.sqlite3", tmp_path / "killed.sqlite3"
    shutil.copy2(prefix, complete)
    shutil.copy2(prefix, killed)
    original_file = killed.read_bytes()
    assert _run_child(plan_path, complete, "none") == {"returned": "retained"}
    committed = _cold_snapshot(complete, event, qualified)
    assert committed != before
    marker = _run_child(plan_path, killed, point)
    if spill and point == "before":
        assert marker["journal_header"] == _JOURNAL_MAGIC
        assert killed.read_bytes() != original_file
    if point == "after":
        assert marker["journal_header"] is None  # admitted DELETE journal profile
    assert _cold_snapshot(killed, event, qualified) == (before if point == "before" else committed)
    if not qualified and point == "after":
        shutil.rmtree(plan["staging"])
    for attempt in range(2):
        expected = ("retained" if qualified or (point == "before" and attempt == 0)
                    else "exact_retained_stale_head")
        assert _run_child(plan_path, killed, "none") == {"returned": expected}
        assert _cold_snapshot(killed, event, qualified) == committed


@pytest.mark.parametrize("case", _CASES)
@pytest.mark.parametrize("point", ["before", "after"])
def test_process_death_recovers_exact_state_and_repeat_outcome(tmp_path, case, point):
    _exercise(tmp_path, case, point)


@pytest.mark.parametrize("point", ["before", "after"])
def test_process_death_with_spilled_pages_recovers_exact_state(tmp_path, point):
    _exercise(tmp_path, "authority_admitted", point, spill=True)
