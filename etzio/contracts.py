"""Core wire objects for Etzio. Plain dataclasses so the kernel stays dependency-free.

These mirror the JSON Schemas under schemas/. A vulnerability is a scientific claim, so
the object graph is: hypothesis -> candidate -> PoC -> verdict -> finding | null.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


def digest(obj) -> str:
    """Content address: stable sha256 over the canonical JSON form."""
    payload = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]


class Stage(str, Enum):
    OPEN = "open"
    AUTHORIZED = "authorized"
    RECON = "recon"
    THREAT_MODEL = "threat_model"
    INVESTIGATE = "investigate"
    CONSTRUCT = "construct"
    VERIFY = "verify"
    ADJUDICATE = "adjudicate"
    TRIAGE = "triage"
    DISCLOSE = "disclose"
    LEARN = "learn"
    CLOSED = "closed"
    BLOCKED = "blocked"


class VerdictKind(str, Enum):
    CONFIRMED = "confirmed"
    NOT_REPRODUCED = "not_reproduced"
    OUT_OF_SCOPE = "out_of_scope"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class TargetContract:
    program: str
    authorization_kind: str          # bug_bounty_scope | written_permission | benchmark | responsible_disclosure
    authorization_reference: str
    in_scope: tuple[str, ...]
    permitted_actions: tuple[str, ...]
    disclosure_channel: str
    max_usd: float
    out_of_scope: tuple[str, ...] = ()
    max_wallclock_minutes: Optional[float] = None

    def allows(self, action: str) -> bool:
        return action in self.permitted_actions

    def covers(self, asset: str) -> bool:
        if asset in self.out_of_scope:
            return False
        return asset in self.in_scope


@dataclass(frozen=True)
class Hypothesis:
    id: str
    bug_class: str
    statement: str        # a falsifiable claim
    probe: str            # how VELITES should test it
    rank: float           # FABIUS's priority, 0..1


@dataclass(frozen=True)
class PoCArtifact:
    """A reproducing proof. `payload` is what gets replayed against the target; `claimed_effect`
    is what the producer asserts it causes. CATO re-runs it and compares — it does not trust the claim."""
    payload: str
    claimed_effect: str

    @property
    def artifact_digest(self) -> str:
        return digest(asdict(self))


@dataclass(frozen=True)
class Candidate:
    id: str
    hypothesis_id: str
    producer: str          # the unit identity that produced it (VELITES/MARCELLUS). NEVER the verifier.
    target_asset: str
    poc: Optional[PoCArtifact]
    note: str = ""


@dataclass(frozen=True)
class Verdict:
    candidate_id: str
    verdict: VerdictKind
    verifier_identity: str
    reproduced_from_bytes: bool
    environment_digest: str
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class Finding:
    id: str
    mission_id: str
    target_revision: str
    hypothesis_id: str
    triggering_input: str
    poc_artifact_digest: str
    environment_digest: str
    verifier_identity: str
    severity_level: str
    exploitability: str
    in_scope: bool
    verdict: str = "confirmed"


@dataclass(frozen=True)
class NullResult:
    """First-class: 'nothing here under hypothesis H'. Retained, never dropped to look productive."""
    mission_id: str
    hypothesis_id: str
    reason: str
