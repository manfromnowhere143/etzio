"""ETZIO kernel: the deterministic, replayable core. Units propose; the kernel decides
what is legal and appends the truth. Nothing else writes the ledger."""

from .events import Event, EventLedger
from .loop import GeneratorIsVerifierError, MasterLoop, ScopeError
from .state import MissionState, Stage, legal_next

__all__ = [
    "Event",
    "EventLedger",
    "Stage",
    "legal_next",
    "MissionState",
    "MasterLoop",
    "ScopeError",
    "GeneratorIsVerifierError",
]
