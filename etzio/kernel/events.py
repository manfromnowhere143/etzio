"""Append-only event ledger. Canonical state is the event stream; everything else is a
projection. Replaying the ledger reconstructs the mission exactly — no conversational memory."""

from __future__ import annotations

import json
import time
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from typing import Any

from ..contracts import digest


@dataclass(frozen=True)
class Event:
    seq: int
    mission_id: str
    kind: str                 # e.g. "mission_opened", "candidate_recorded", "verdict_recorded", "null_recorded"
    unit: str                 # which unit's action produced this event ("ETZIO" for kernel events)
    payload: dict[str, Any]
    ts_monotonic: float
    prev_digest: str          # hash chain: each event commits to the prior one

    @property
    def event_digest(self) -> str:
        body = {k: v for k, v in asdict(self).items() if k != "event_digest"}
        return digest(body)


class EventLedger:
    """In-memory + JSONL-persistable append-only log with a hash chain. One writer: the kernel."""

    def __init__(self) -> None:
        self._events: list[Event] = []

    def append(self, mission_id: str, kind: str, unit: str, payload: dict[str, Any]) -> Event:
        prev = self._events[-1].event_digest if self._events else "sha256:genesis"
        ev = Event(
            seq=len(self._events),
            mission_id=mission_id,
            kind=kind,
            unit=unit,
            payload=payload,
            ts_monotonic=time.monotonic(),
            prev_digest=prev,
        )
        self._events.append(ev)
        return ev

    def __iter__(self) -> Iterable[Event]:
        return iter(self._events)

    def __len__(self) -> int:
        return len(self._events)

    def of_kind(self, kind: str) -> list[Event]:
        return [e for e in self._events if e.kind == kind]

    def verify_chain(self) -> bool:
        """A tamper check: every event must commit to its predecessor's digest."""
        prev = "sha256:genesis"
        for e in self._events:
            if e.prev_digest != prev:
                return False
            prev = e.event_digest
        return True

    def to_jsonl(self) -> str:
        return "\n".join(json.dumps(asdict(e), default=str) for e in self._events)
