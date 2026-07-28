"""Etzio kernel surfaces.

The names exported here are the original in-memory behavior model. The governed
protocol-v1 fixture path lives in ``fixture_scan``, ``verification_lease``, ``events_v1``,
``artifact_resolution``, ``receipt_admission``, ``reducer``, and ``store``; it is
intentionally imported explicitly so modeled and durable objects cannot be confused.
Receipt admission remains modeled-fixture scoped and does not mint a finding.
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
