"""Canonical, content-bound events for Etzio protocol v1.

Every retained event is the common :class:`~etzio.protocol.EnvelopeV1` with
``object_kind == "event"``.  The event body contains the mission-local chain fields; the
envelope ``object_id`` is therefore also the event digest.  Payload bytes are retained
separately inside the Python value so caller-owned mappings cannot mutate an event after
construction.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Any, Final

from ..protocol import (
    EnvelopeV1,
    ProtocolError,
    canonical_dumps,
    freeze_json,
    strict_loads,
    thaw_json,
)

PROTOCOL_VERSION: Final = 1
EVENT_VERSION: Final = 1

# SHA-256("etzio.event.v1.genesis").  This fixed, domain-specific sentinel represents the
# predecessor of sequence zero; it is not an externally anchored checkpoint.
GENESIS_DIGEST: Final = "sha256:d97322dec35e47b77b1045b723936e345978b2223804c19f62ac6150cb377a23"

_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)
_KEY_ID_RE = re.compile(r"ed25519:sha256:[0-9a-f]{64}\Z", re.ASCII)
_BODY_KEYS = frozenset(
    {
        "authority_id",
        "decision_time",
        "kind",
        "mission_id",
        "payload",
        "prev_digest",
        "seq",
        "target_id",
        "unit",
    }
)
_EVENT_UNITS: Final = {
    "authority_admitted": "AQUILA",
    "mission_admission_refused": "AQUILA",
    "mission_opened": "ETZIO",
    "analysis_lease_issued": "AQUILA",
    "candidate_recorded": "VELITES",
    "parse_failed": "VELITES",
    "scan_completed": "VELITES",
    "mission_closed": "ETZIO",
    "scan_failed": "ETZIO",
    "scan_timed_out": "ETZIO",
    "scan_cancelled": "AQUILA",
    "budget_exhausted": "AQUILA",
}
_PAYLOAD_KEYS: Final = {
    "authority_admitted": frozenset({"admission", "grant", "key_id", "signature_b64"}),
    "mission_admission_refused": frozenset({"reason_code", "stage"}),
    "mission_opened": frozenset({"target_snapshot"}),
    "analysis_lease_issued": frozenset({"lease"}),
    "candidate_recorded": frozenset({"candidate"}),
    "parse_failed": frozenset(
        {"analysis_lease_id", "parse_failure", "source_artifact_digest"}
    ),
    "scan_completed": frozenset(
        {
            "analyzer_version",
            "bytes_scanned",
            "candidate_count",
            "file_count",
            "parse_failure_count",
        }
    ),
    "mission_closed": frozenset({"candidate_count", "parse_failure_count", "status"}),
    "scan_failed": frozenset({"reason_code"}),
    "scan_timed_out": frozenset({"reason_code"}),
    "scan_cancelled": frozenset({"reason_code"}),
    "budget_exhausted": frozenset({"reason_code"}),
}
_PARSE_FAILURE_KEYS: Final = frozenset(
    {"column", "line", "reason_code", "relative_path"}
)


class EventIntegrityError(ProtocolError):
    """Raised when an event violates the canonical wire or semantic contract."""


def _require_nonempty_text(name: str, value: object) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise EventIntegrityError(f"{name} must be non-empty text without edge whitespace")
    return value


def _require_digest(name: str, value: object) -> str:
    if type(value) is not str or _DIGEST_RE.fullmatch(value) is None:
        raise EventIntegrityError(f"{name} must be a full lowercase sha256 digest")
    return value


def _require_nonnegative_int(name: str, value: object) -> int:
    if type(value) is not int or value < 0:
        raise EventIntegrityError(f"{name} must be a non-negative integer")
    return value


def _require_exact_keys(
    name: str,
    value: object,
    expected: frozenset[str],
) -> dict[str, Any]:
    if type(value) is not dict:
        raise EventIntegrityError(f"{name} must be a JSON object")
    keys = set(value)
    if keys != expected:
        missing = sorted(expected - keys)
        extra = sorted(keys - expected)
        raise EventIntegrityError(
            f"{name} keys differ: missing={missing}, extra={extra}"
        )
    return value


def _require_nested_envelope(
    payload: dict[str, Any],
    field: str,
    expected_kind: str,
) -> EnvelopeV1:
    value = payload[field]
    if type(value) is not dict:
        raise EventIntegrityError(f"{field} must be a protocol envelope object")
    try:
        envelope = EnvelopeV1.from_bytes(canonical_dumps(value))
    except ProtocolError as exc:
        raise EventIntegrityError(f"{field} is not a valid canonical envelope: {exc}") from exc
    if envelope.object_kind != expected_kind:
        raise EventIntegrityError(
            f"{field} must contain a {expected_kind} envelope"
        )
    if envelope.attestations:
        raise EventIntegrityError(f"{field} envelope must not contain attestations")
    return envelope


def _require_relative_path(value: object) -> str:
    text = _require_nonempty_text("relative_path", value)
    path = PurePosixPath(text)
    if (
        path.is_absolute()
        or path.as_posix() != text
        or "." in path.parts
        or ".." in path.parts
        or "\\" in text
        or "\x00" in text
    ):
        raise EventIntegrityError("relative_path must be normalized and relative")
    return text


def _validate_payload(
    *,
    kind: str,
    unit: str,
    mission_id: str,
    authority_id: str,
    target_id: str,
    decision_time: int,
    payload: dict[str, Any],
) -> None:
    expected_unit = _EVENT_UNITS.get(kind)
    if expected_unit is None:
        raise EventIntegrityError(f"unsupported event kind: {kind!r}")
    if unit != expected_unit:
        raise EventIntegrityError(f"{kind} events must be authored by {expected_unit}")
    _require_exact_keys(f"{kind} payload", payload, _PAYLOAD_KEYS[kind])

    if kind == "authority_admitted":
        from ..authority import (
            AuthorityAdmissionV1,
            AuthorityError,
            AuthorityGrantV1,
            SignedAuthorityGrantV1,
        )

        admission_envelope = _require_nested_envelope(
            payload, "admission", "authority_admission"
        )
        grant_envelope = _require_nested_envelope(
            payload, "grant", "authority_grant"
        )
        try:
            admission = AuthorityAdmissionV1.from_envelope(admission_envelope)
            grant = AuthorityGrantV1.from_envelope(grant_envelope)
            embedded_signed_grant = SignedAuthorityGrantV1.from_bytes(
                admission.signed_grant_bytes
            )
        except AuthorityError as exc:
            raise EventIntegrityError(
                f"authority_admitted contains invalid authority evidence: {exc}"
            ) from exc
        if grant.grant_id != authority_id:
            raise EventIntegrityError(
                "authority grant object_id does not match event authority_id"
            )
        if (
            admission.authority_id != authority_id
            or admission.target_snapshot_id != target_id
            or admission.decision_time != decision_time
            or "static_analysis" not in admission.required_actions
            or "static_analysis" not in grant.permitted_actions
        ):
            raise EventIntegrityError(
                "authority admission does not authorize this event and target"
            )
        if (
            grant.target_snapshot_id != target_id
            or admission.grant_expires_at != grant.expires_at
        ):
            raise EventIntegrityError(
                "authority grant does not match the admission and event target"
            )
        key_id = _require_nonempty_text("key_id", payload["key_id"])
        if _KEY_ID_RE.fullmatch(key_id) is None:
            raise EventIntegrityError("key_id must identify an Ed25519 public key")
        signature_b64 = _require_nonempty_text(
            "signature_b64", payload["signature_b64"]
        )
        try:
            signature = base64.b64decode(signature_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise EventIntegrityError("signature_b64 must be canonical base64") from exc
        if (
            len(signature) != 64
            or base64.b64encode(signature).decode("ascii") != signature_b64
        ):
            raise EventIntegrityError(
                "signature_b64 must encode one canonical Ed25519 signature"
            )
        if (
            admission.signer_key_id != key_id
            or embedded_signed_grant.key_id != key_id
            or embedded_signed_grant.signature_b64 != signature_b64
            or embedded_signed_grant.envelope_bytes != grant_envelope.to_bytes()
        ):
            raise EventIntegrityError(
                "authority event fields do not match the self-verifying admission"
            )
        return

    if kind == "mission_admission_refused":
        _require_nonempty_text("reason_code", payload["reason_code"])
        if payload["stage"] not in {"admission", "preflight"}:
            raise EventIntegrityError(
                "mission admission refusal stage must be admission or preflight"
            )
        return

    if kind == "mission_opened":
        from ..evidence import EvidenceError, TargetSnapshotV1

        snapshot = _require_nested_envelope(
            payload, "target_snapshot", "target_snapshot"
        )
        try:
            TargetSnapshotV1.from_envelope(snapshot)
        except EvidenceError as exc:
            raise EventIntegrityError(
                f"mission_opened contains an invalid target snapshot: {exc}"
            ) from exc
        if snapshot.object_id != target_id:
            raise EventIntegrityError(
                "target snapshot object_id does not match event target_id"
            )
        return

    if kind == "analysis_lease_issued":
        from ..mission_v1 import AnalysisLeaseV1, MissionProtocolError

        lease_envelope = _require_nested_envelope(
            payload, "lease", "analysis_lease"
        )
        try:
            lease = AnalysisLeaseV1.from_envelope(lease_envelope)
        except MissionProtocolError as exc:
            raise EventIntegrityError(
                f"analysis_lease_issued contains an invalid lease: {exc}"
            ) from exc
        if (
            lease.mission_id != mission_id
            or lease.authority_id != authority_id
            or lease.target_snapshot_id != target_id
        ):
            raise EventIntegrityError(
                "analysis lease does not match the event identities"
            )
        if (
            lease.expires_at
            > lease.issued_at + lease.max_wallclock_seconds
        ):
            raise EventIntegrityError(
                "analysis lease expiry exceeds its wallclock ceiling"
            )
        return

    if kind == "candidate_recorded":
        from ..mission_v1 import MissionProtocolError, StaticCandidateV1

        candidate_envelope = _require_nested_envelope(
            payload, "candidate", "candidate"
        )
        try:
            candidate = StaticCandidateV1.from_envelope(candidate_envelope)
        except MissionProtocolError as exc:
            raise EventIntegrityError(
                f"candidate_recorded contains an invalid candidate: {exc}"
            ) from exc
        if (
            candidate.mission_id != mission_id
            or candidate.authority_id != authority_id
            or candidate.target_snapshot_id != target_id
        ):
            raise EventIntegrityError(
                "candidate does not match the event identities"
            )
        return

    if kind == "parse_failed":
        _require_digest("analysis_lease_id", payload["analysis_lease_id"])
        _require_digest(
            "source_artifact_digest", payload["source_artifact_digest"]
        )
        failure = _require_exact_keys(
            "parse_failure", payload["parse_failure"], _PARSE_FAILURE_KEYS
        )
        _require_nonnegative_int("parse_failure.line", failure["line"])
        _require_nonnegative_int("parse_failure.column", failure["column"])
        _require_nonempty_text("parse_failure.reason_code", failure["reason_code"])
        _require_relative_path(failure["relative_path"])
        return

    if kind == "scan_completed":
        _require_nonempty_text("analyzer_version", payload["analyzer_version"])
        for field in (
            "bytes_scanned",
            "candidate_count",
            "file_count",
            "parse_failure_count",
        ):
            _require_nonnegative_int(field, payload[field])
        return

    if kind == "mission_closed":
        _require_nonnegative_int("candidate_count", payload["candidate_count"])
        _require_nonnegative_int(
            "parse_failure_count", payload["parse_failure_count"]
        )
        if payload["status"] != "completed":
            raise EventIntegrityError("mission_closed status must be completed")
        return

    # The remaining supported kinds are terminal interruption events.
    _require_nonempty_text("reason_code", payload["reason_code"])


@dataclass(frozen=True, slots=True)
class EventV1:
    """One immutable event in a mission-local hash chain.

    ``event_digest`` is retained as the compatibility spelling used by the store and
    mission runner.  It is exactly the common envelope's ``object_id``; ``object_id`` is
    also exposed as a read-only property.
    """

    protocol_version: int
    event_version: int
    mission_id: str
    seq: int
    kind: str
    unit: str
    authority_id: str
    target_id: str
    decision_time: int
    payload_bytes: bytes
    prev_digest: str
    event_digest: str

    def __post_init__(self) -> None:
        if type(self.protocol_version) is not int or self.protocol_version != PROTOCOL_VERSION:
            raise EventIntegrityError(
                f"unsupported protocol_version: {self.protocol_version!r}"
            )
        if type(self.event_version) is not int or self.event_version != EVENT_VERSION:
            raise EventIntegrityError(
                f"unsupported event_version: {self.event_version!r}"
            )
        _require_digest("mission_id", self.mission_id)
        _require_nonnegative_int("seq", self.seq)
        _require_nonempty_text("kind", self.kind)
        _require_nonempty_text("unit", self.unit)
        _require_digest("authority_id", self.authority_id)
        _require_digest("target_id", self.target_id)
        _require_nonnegative_int("decision_time", self.decision_time)
        if type(self.payload_bytes) is not bytes:
            raise EventIntegrityError("payload_bytes must be immutable bytes")
        _require_digest("prev_digest", self.prev_digest)
        _require_digest("event_digest", self.event_digest)

        try:
            payload = strict_loads(self.payload_bytes)
            if type(payload) is not dict:
                raise EventIntegrityError("event payload must be a JSON object")
            if canonical_dumps(payload) != self.payload_bytes:
                raise EventIntegrityError("payload bytes are not canonical")
            _validate_payload(
                kind=self.kind,
                unit=self.unit,
                mission_id=self.mission_id,
                authority_id=self.authority_id,
                target_id=self.target_id,
                decision_time=self.decision_time,
                payload=payload,
            )
            expected = EnvelopeV1.create("event", self._body(payload))
        except EventIntegrityError:
            raise
        except ProtocolError as exc:
            raise EventIntegrityError(f"event body violates protocol v1: {exc}") from exc
        if self.event_digest != expected.object_id:
            raise EventIntegrityError(
                "event digest does not match the common envelope object_id"
            )

    @classmethod
    def create(
        cls,
        *,
        mission_id: str,
        seq: int,
        kind: str,
        unit: str,
        authority_id: str,
        target_id: str,
        decision_time: int,
        payload: Mapping[str, Any],
        prev_digest: str,
    ) -> EventV1:
        """Create an event without retaining references to the caller's object graph."""

        if not isinstance(payload, Mapping):
            raise EventIntegrityError("payload must be a JSON object")
        try:
            payload_bytes = canonical_dumps(thaw_json(freeze_json(payload)))
            normalized_payload = strict_loads(payload_bytes)
            if type(normalized_payload) is not dict:
                raise EventIntegrityError("event payload must be a JSON object")
            body = {
                "authority_id": authority_id,
                "decision_time": decision_time,
                "kind": kind,
                "mission_id": mission_id,
                "payload": normalized_payload,
                "prev_digest": prev_digest,
                "seq": seq,
                "target_id": target_id,
                "unit": unit,
            }
            envelope = EnvelopeV1.create("event", body)
        except EventIntegrityError:
            raise
        except ProtocolError as exc:
            raise EventIntegrityError(f"event cannot be represented by protocol v1: {exc}") from exc
        return cls(
            protocol_version=envelope.protocol_version,
            event_version=envelope.object_version,
            mission_id=mission_id,
            seq=seq,
            kind=kind,
            unit=unit,
            authority_id=authority_id,
            target_id=target_id,
            decision_time=decision_time,
            payload_bytes=payload_bytes,
            prev_digest=prev_digest,
            event_digest=envelope.object_id,
        )

    @property
    def object_id(self) -> str:
        """Return the common-envelope identity (the same value as ``event_digest``)."""

        return self.event_digest

    @property
    def payload(self) -> MappingProxyType:
        """Return a fresh, recursively immutable view of the retained payload bytes."""

        payload = freeze_json(strict_loads(self.payload_bytes))
        if type(payload) is not MappingProxyType:  # guarded by construction
            raise EventIntegrityError("event payload must be a JSON object")
        return payload

    def _body(self, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        if payload is None:
            loaded = strict_loads(self.payload_bytes)
            if type(loaded) is not dict:
                raise EventIntegrityError("event payload must be a JSON object")
            payload = loaded
        return {
            "authority_id": self.authority_id,
            "decision_time": self.decision_time,
            "kind": self.kind,
            "mission_id": self.mission_id,
            "payload": payload,
            "prev_digest": self.prev_digest,
            "seq": self.seq,
            "target_id": self.target_id,
            "unit": self.unit,
        }

    def to_envelope(self) -> EnvelopeV1:
        """Return the validated common protocol envelope for this event."""

        envelope = EnvelopeV1.create("event", self._body())
        if envelope.object_id != self.event_digest:
            raise EventIntegrityError(
                "event digest does not match the common envelope object_id"
            )
        return envelope

    def to_wire(self) -> MappingProxyType:
        """Return a deeply immutable common-envelope wire record."""

        wire = freeze_json(self.to_envelope().to_dict())
        if type(wire) is not MappingProxyType:  # guaranteed by EnvelopeV1
            raise EventIntegrityError("event envelope must be a JSON object")
        return wire

    def to_canonical_bytes(self) -> bytes:
        """Serialize the complete common envelope."""

        return self.to_envelope().to_bytes()

    def verify(self) -> None:
        """Re-run all canonical, payload, unit, binding, and identity checks."""

        type(self)(
            protocol_version=self.protocol_version,
            event_version=self.event_version,
            mission_id=self.mission_id,
            seq=self.seq,
            kind=self.kind,
            unit=self.unit,
            authority_id=self.authority_id,
            target_id=self.target_id,
            decision_time=self.decision_time,
            payload_bytes=self.payload_bytes,
            prev_digest=self.prev_digest,
            event_digest=self.event_digest,
        )

    @classmethod
    def from_canonical_bytes(cls, raw: bytes) -> EventV1:
        """Decode an event through the one common envelope parser."""

        if type(raw) is not bytes:
            raise EventIntegrityError("canonical event representation must be bytes")
        try:
            envelope = EnvelopeV1.from_bytes(raw)
        except ProtocolError as exc:
            raise EventIntegrityError(f"invalid event envelope: {exc}", code=exc.code) from exc
        if envelope.object_kind != "event":
            raise EventIntegrityError("protocol envelope is not an event")
        if envelope.attestations:
            raise EventIntegrityError("event envelopes must not contain attestations")
        body = thaw_json(envelope.body)
        if type(body) is not dict or set(body) != _BODY_KEYS:
            actual = set(body) if type(body) is dict else set()
            missing = sorted(_BODY_KEYS - actual)
            extra = sorted(actual - _BODY_KEYS)
            raise EventIntegrityError(
                f"event body keys differ: missing={missing}, extra={extra}"
            )
        payload = body["payload"]
        if type(payload) is not dict:
            raise EventIntegrityError("event payload must be a JSON object")
        return cls(
            protocol_version=envelope.protocol_version,
            event_version=envelope.object_version,
            mission_id=body["mission_id"],
            seq=body["seq"],
            kind=body["kind"],
            unit=body["unit"],
            authority_id=body["authority_id"],
            target_id=body["target_id"],
            decision_time=body["decision_time"],
            payload_bytes=canonical_dumps(payload),
            prev_digest=body["prev_digest"],
            event_digest=envelope.object_id,
        )
