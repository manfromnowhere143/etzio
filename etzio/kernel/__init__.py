"""ETZIO foundation kernel.

The current objects demonstrate deterministic stage wiring in memory. Durable replay,
admitted authority, and authenticated receipts remain blocking work.
"""

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
