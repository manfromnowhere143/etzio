"""The mission state machine. A pure map of legal transitions — the kernel derives the next
legal action from state alone, never from an agent's memory. Illegal jumps are impossible."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..contracts import Stage

# Legal forward transitions. BLOCKED and CLOSED are reachable from most stages (fail-closed),
# handled explicitly by the loop rather than enumerated for every source here.
_TRANSITIONS: dict[Stage, tuple[Stage, ...]] = {
    Stage.OPEN: (Stage.AUTHORIZED, Stage.BLOCKED),
    Stage.AUTHORIZED: (Stage.RECON, Stage.BLOCKED),
    Stage.RECON: (Stage.THREAT_MODEL, Stage.BLOCKED),
    Stage.THREAT_MODEL: (Stage.INVESTIGATE, Stage.BLOCKED),
    Stage.INVESTIGATE: (Stage.CONSTRUCT, Stage.LEARN, Stage.BLOCKED),   # LEARN if all hypotheses null
    Stage.CONSTRUCT: (Stage.VERIFY, Stage.LEARN, Stage.BLOCKED),
    Stage.VERIFY: (Stage.ADJUDICATE, Stage.BLOCKED),
    Stage.ADJUDICATE: (Stage.TRIAGE, Stage.LEARN, Stage.BLOCKED),
    Stage.TRIAGE: (Stage.DISCLOSE, Stage.LEARN, Stage.BLOCKED),
    Stage.DISCLOSE: (Stage.LEARN, Stage.BLOCKED),
    Stage.LEARN: (Stage.CLOSED,),
    Stage.BLOCKED: (Stage.CLOSED,),
    Stage.CLOSED: (),
}


def legal_next(stage: Stage) -> tuple[Stage, ...]:
    return _TRANSITIONS.get(stage, ())


def is_legal(src: Stage, dst: Stage) -> bool:
    return dst in legal_next(src)


@dataclass
class MissionState:
    """A projection rebuilt from the ledger. Holds only what the loop needs to pick the next action."""
    mission_id: str
    stage: Stage = Stage.OPEN
    findings: list = field(default_factory=list)
    nulls: list = field(default_factory=list)
    blocked_reason: str | None = None

    def advance(self, dst: Stage) -> None:
        if not is_legal(self.stage, dst):
            raise ValueError(f"illegal transition {self.stage} -> {dst}")
        self.stage = dst

    def block(self, reason: str) -> None:
        self.blocked_reason = reason
        self.stage = Stage.BLOCKED
