"""Governed protocol-v1 objects for Etzio's repository-fixture scan.

This tranche authorizes deterministic static analysis of already retained, repository-owned
fixture bytes only. It creates candidates, never findings, and provides no target-network,
credential, exploit-execution, or disclosure capability.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from .analysis import PYTHON_SAST_VERSION, StaticFinding
from .protocol import EnvelopeV1, ProtocolError, content_id, thaw_json

_FULL_SHA = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
_NONCE = re.compile(r"^[0-9a-f]{32}$", re.ASCII)
_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
_LEASE_FIELDS = frozenset(
    {
        "action",
        "authority_id",
        "expires_at",
        "issued_at",
        "lease_nonce",
        "max_bytes",
        "max_candidates",
        "max_wallclock_seconds",
        "mission_id",
        "target_snapshot_id",
        "worker_identity",
    }
)
_CANDIDATE_FIELDS = frozenset(
    {
        "analysis_lease_id",
        "analyzer_version",
        "authority_id",
        "claim_id",
        "column",
        "line",
        "mission_id",
        "producer_identity",
        "relative_path",
        "rule_id",
        "severity",
        "source_artifact_digest",
        "symbol",
        "target_snapshot_id",
    }
)


class MissionProtocolError(ProtocolError):
    """A fixture-mission object violates the frozen protocol-v1 semantics."""


def _require_digest(value: object, field: str) -> str:
    if type(value) is not str or _FULL_SHA.fullmatch(value) is None:
        raise MissionProtocolError(f"{field} must be a full sha256 identifier")
    return value


def _require_text(value: object, field: str) -> str:
    if type(value) is not str or not value or value.strip() != value:
        raise MissionProtocolError(f"{field} must be a nonblank canonical string")
    return value


def _require_nonnegative_int(value: object, field: str) -> int:
    if type(value) is not int or value < 0:
        raise MissionProtocolError(f"{field} must be a nonnegative integer")
    return value


def _require_relative_path(value: object) -> str:
    path_text = _require_text(value, "relative_path")
    path = PurePosixPath(path_text)
    if (
        path.is_absolute()
        or path.as_posix() != path_text
        or "." in path.parts
        or ".." in path.parts
        or "\\" in path_text
        or "\x00" in path_text
    ):
        raise MissionProtocolError("relative_path must be normalized and relative")
    return path_text


@dataclass(frozen=True, slots=True)
class AnalysisLeaseV1:
    """A content-bound, expiring capability for one VELITES static-analysis worker."""

    lease_id: str
    mission_id: str
    authority_id: str
    target_snapshot_id: str
    worker_identity: str
    action: str
    issued_at: int
    expires_at: int
    max_bytes: int
    max_candidates: int
    max_wallclock_seconds: int
    lease_nonce: str

    def __post_init__(self) -> None:
        _require_digest(self.lease_id, "lease_id")
        _validate_lease_body(self._body())
        if self.to_envelope().object_id != self.lease_id:
            raise MissionProtocolError("lease_id does not match the canonical lease body")

    @classmethod
    def issue(
        cls,
        *,
        mission_id: str,
        authority_id: str,
        target_snapshot_id: str,
        issued_at: int,
        expires_at: int,
        max_bytes: int,
        max_candidates: int,
        max_wallclock_seconds: int,
        lease_nonce: str,
    ) -> AnalysisLeaseV1:
        values = {
            "action": "static_analysis",
            "authority_id": authority_id,
            "expires_at": expires_at,
            "issued_at": issued_at,
            "lease_nonce": lease_nonce,
            "max_bytes": max_bytes,
            "max_candidates": max_candidates,
            "max_wallclock_seconds": max_wallclock_seconds,
            "mission_id": mission_id,
            "target_snapshot_id": target_snapshot_id,
            "worker_identity": "VELITES",
        }
        _validate_lease_body(values)
        envelope = EnvelopeV1.create("analysis_lease", values)
        return cls(lease_id=envelope.object_id, **values)

    @classmethod
    def from_envelope(cls, envelope: EnvelopeV1) -> AnalysisLeaseV1:
        if envelope.object_kind != "analysis_lease" or envelope.attestations:
            raise MissionProtocolError("expected an unattested analysis_lease envelope")
        body = thaw_json(envelope.body)
        if type(body) is not dict or set(body) != _LEASE_FIELDS:
            raise MissionProtocolError("analysis lease has missing or unknown fields")
        _validate_lease_body(body)
        return cls(lease_id=envelope.object_id, **body)

    def _body(self) -> dict[str, object]:
        return {
            "action": self.action,
            "authority_id": self.authority_id,
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "lease_nonce": self.lease_nonce,
            "max_bytes": self.max_bytes,
            "max_candidates": self.max_candidates,
            "max_wallclock_seconds": self.max_wallclock_seconds,
            "mission_id": self.mission_id,
            "target_snapshot_id": self.target_snapshot_id,
            "worker_identity": self.worker_identity,
        }

    def to_envelope(self) -> EnvelopeV1:
        return EnvelopeV1.create("analysis_lease", self._body())


def _validate_lease_body(body: dict[str, object]) -> None:
    if set(body) != _LEASE_FIELDS:
        raise MissionProtocolError("analysis lease has missing or unknown fields")
    _require_digest(body["mission_id"], "mission_id")
    _require_digest(body["authority_id"], "authority_id")
    _require_digest(body["target_snapshot_id"], "target_snapshot_id")
    if body["worker_identity"] != "VELITES" or body["action"] != "static_analysis":
        raise MissionProtocolError("foundation analysis leases are VELITES static_analysis only")
    issued_at = _require_nonnegative_int(body["issued_at"], "issued_at")
    expires_at = _require_nonnegative_int(body["expires_at"], "expires_at")
    if issued_at >= expires_at:
        raise MissionProtocolError("analysis lease must have a nonempty half-open validity window")
    for field in ("max_bytes", "max_candidates", "max_wallclock_seconds"):
        if _require_nonnegative_int(body[field], field) == 0:
            raise MissionProtocolError(f"{field} must be positive for an issued analysis lease")
    nonce = body["lease_nonce"]
    if type(nonce) is not str or _NONCE.fullmatch(nonce) is None:
        raise MissionProtocolError("lease_nonce must contain exactly 128 bits of lowercase hex")


@dataclass(frozen=True, slots=True)
class StaticCandidateV1:
    """A byte-bound VELITES observation. It is not a verified vulnerability finding."""

    candidate_id: str
    claim_id: str
    mission_id: str
    authority_id: str
    analysis_lease_id: str
    target_snapshot_id: str
    source_artifact_digest: str
    relative_path: str
    analyzer_version: str
    rule_id: str
    severity: str
    line: int
    column: int
    symbol: str
    producer_identity: str

    def __post_init__(self) -> None:
        _require_digest(self.candidate_id, "candidate_id")
        _validate_candidate_body(self._body())
        expected_claim = _claim_id(self._body())
        if self.claim_id != expected_claim:
            raise MissionProtocolError("claim_id does not match the static claim")
        if self.to_envelope().object_id != self.candidate_id:
            raise MissionProtocolError("candidate_id does not match the canonical candidate body")

    @classmethod
    def from_finding(
        cls,
        finding: StaticFinding,
        *,
        mission_id: str,
        authority_id: str,
        analysis_lease_id: str,
        target_snapshot_id: str,
        source_artifact_digest: str,
    ) -> StaticCandidateV1:
        values = {
            "analysis_lease_id": analysis_lease_id,
            "analyzer_version": PYTHON_SAST_VERSION,
            "authority_id": authority_id,
            "column": finding.column,
            "line": finding.line,
            "mission_id": mission_id,
            "producer_identity": "VELITES",
            "relative_path": finding.file,
            "rule_id": finding.rule_id,
            "severity": finding.severity,
            "source_artifact_digest": source_artifact_digest,
            "symbol": finding.symbol,
            "target_snapshot_id": target_snapshot_id,
        }
        values["claim_id"] = _claim_id(values)
        _validate_candidate_body(values)
        envelope = EnvelopeV1.create("candidate", values)
        return cls(candidate_id=envelope.object_id, **values)

    @classmethod
    def from_envelope(cls, envelope: EnvelopeV1) -> StaticCandidateV1:
        if envelope.object_kind != "candidate" or envelope.attestations:
            raise MissionProtocolError("expected an unattested candidate envelope")
        body = thaw_json(envelope.body)
        if type(body) is not dict or set(body) != _CANDIDATE_FIELDS:
            raise MissionProtocolError("candidate has missing or unknown fields")
        _validate_candidate_body(body)
        return cls(candidate_id=envelope.object_id, **body)

    def _body(self) -> dict[str, object]:
        return {
            "analysis_lease_id": self.analysis_lease_id,
            "analyzer_version": self.analyzer_version,
            "authority_id": self.authority_id,
            "claim_id": self.claim_id,
            "column": self.column,
            "line": self.line,
            "mission_id": self.mission_id,
            "producer_identity": self.producer_identity,
            "relative_path": self.relative_path,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "source_artifact_digest": self.source_artifact_digest,
            "symbol": self.symbol,
            "target_snapshot_id": self.target_snapshot_id,
        }

    def to_envelope(self) -> EnvelopeV1:
        return EnvelopeV1.create("candidate", self._body())


def _claim_id(body: dict[str, object]) -> str:
    return content_id(
        "static_claim",
        {
            "analyzer_version": body["analyzer_version"],
            "column": body["column"],
            "line": body["line"],
            "relative_path": body["relative_path"],
            "rule_id": body["rule_id"],
            "source_artifact_digest": body["source_artifact_digest"],
            "symbol": body["symbol"],
            "target_snapshot_id": body["target_snapshot_id"],
        },
    )


def _validate_candidate_body(body: dict[str, object]) -> None:
    if set(body) != _CANDIDATE_FIELDS:
        raise MissionProtocolError("candidate has missing or unknown fields")
    for field in (
        "analysis_lease_id",
        "authority_id",
        "claim_id",
        "mission_id",
        "source_artifact_digest",
        "target_snapshot_id",
    ):
        _require_digest(body[field], field)
    if body["producer_identity"] != "VELITES":
        raise MissionProtocolError("static candidate producer must be VELITES")
    if body["analyzer_version"] != PYTHON_SAST_VERSION:
        raise MissionProtocolError("unsupported Python analyzer version")
    _require_relative_path(body["relative_path"])
    _require_text(body["rule_id"], "rule_id")
    _require_text(body["symbol"], "symbol")
    if body["severity"] not in _SEVERITIES:
        raise MissionProtocolError("unsupported candidate severity")
    if _require_nonnegative_int(body["line"], "line") == 0:
        raise MissionProtocolError("candidate line must be positive")
    _require_nonnegative_int(body["column"], "column")
