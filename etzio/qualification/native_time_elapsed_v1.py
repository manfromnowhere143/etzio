"""Conditional offline issuance-to-use bounds. No clock or kernel authority.

ADR-0022 specifies the causal and clock assumptions. Native bytes are freshly
validated by the unchanged codecs; caller-constructed observations are never inputs.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, fields

from etzio.kernel.integrity_adapters_v1 import TrustedTimeRequestV1
from etzio.protocol import ProtocolError, canonical_dumps, content_id, strict_loads
from etzio.qualification import rfc3161_rsa_chain_v1 as rsa
from etzio.qualification import rfc3161_v1 as direct

_BILLION = 1_000_000_000
_MAX_COUNTER = (1 << 63) - 1
_MAX_UTC_US = 253370764800000000  # 9999-01-01, matching the native codecs' limit.
_MAX_RECORD_BYTES = 8192
_ID = re.compile(r"sha256:[0-9a-f]{64}", re.ASCII)
_SHA = re.compile(r"[0-9a-f]{64}", re.ASCII)
_SEMANTICS = "suspend_inclusive_continuous_posix_window_v1"


class ElapsedTimeError(ValueError):
    """Deterministic conditional-evaluation refusal, not an adapter outage."""

    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise ElapsedTimeError(reason)


def _integer(value, lower: int, upper: int, reason: str) -> None:
    _require(type(value) is int and lower <= value <= upper, reason)


def _identity(value, reason: str, pattern=_ID) -> None:
    length = 71 if pattern is _ID else 64
    _require(type(value) is str and len(value) == length and pattern.fullmatch(value) is not None, reason)


def _body(record, schema: str) -> dict:
    return {"schema": schema, **asdict(record)}


def _decode(wire: bytes, cls, schema: str) -> dict:
    _require(type(wire) is bytes and 0 < len(wire) <= _MAX_RECORD_BYTES, "record_size")
    try:
        body = strict_loads(wire)
        _require(type(body) is dict, "record_shape")
        _require(set(body) == {"schema", *(f.name for f in fields(cls))}, "record_shape")
        _require(body["schema"] == schema and canonical_dumps(body) == wire, "record_encoding")
    except ProtocolError as exc:
        raise ElapsedTimeError("record_encoding") from exc
    return {k: v for k, v in body.items() if k != "schema"}


@dataclass(frozen=True, slots=True)
class ElapsedTimePolicyV1:
    """Declared clock assumptions and ceilings, never clock admission evidence."""

    clock_profile_id: str
    max_rate_error_ppb: int
    sample_error_ns: int
    max_acquisition_ns: int
    max_total_ns: int
    max_width_us: int
    clock_semantics: str = _SEMANTICS

    def __post_init__(self) -> None:
        _identity(self.clock_profile_id, "clock_profile")
        _integer(self.max_rate_error_ppb, 0, 100_000_000, "rate_bound")
        _integer(self.sample_error_ns, 0, _BILLION, "sample_error")
        _integer(self.max_acquisition_ns, 1, 30 * _BILLION, "acquisition_ceiling")
        _integer(self.max_total_ns, self.max_acquisition_ns, 60 * _BILLION, "total_ceiling")
        _integer(self.max_width_us, 1, 180_000_000, "width_ceiling")
        _require(type(self.clock_semantics) is str and self.clock_semantics == _SEMANTICS, "clock_semantics")

    def to_canonical_bytes(self) -> bytes:
        return canonical_dumps(_body(self, "etzio.native-time.elapsed-policy.v1"))

    @classmethod
    def from_canonical_bytes(cls, wire: bytes) -> ElapsedTimePolicyV1:
        return cls(**_decode(wire, cls, "etzio.native-time.elapsed-policy.v1"))

    @property
    def policy_id(self) -> str:
        return content_id("native_time_elapsed_policy_v1", _body(self, "etzio.native-time.elapsed-policy.v1"))


@dataclass(frozen=True, slots=True)
class ElapsedSampleV1:
    clock_profile_id: str
    epoch_id: str
    counter_ns: int

    def __post_init__(self) -> None:
        _identity(self.clock_profile_id, "clock_profile")
        _identity(self.epoch_id, "clock_epoch")
        _integer(self.counter_ns, 0, _MAX_COUNTER, "counter_bounds")


@dataclass(frozen=True, slots=True)
class NativeTimeTraceV1:
    policy_id: str
    attempt_id: str
    request_sha256: str
    response_sha256: str
    before_disclosure: ElapsedSampleV1
    response_complete: ElapsedSampleV1
    consumed: ElapsedSampleV1

    def __post_init__(self) -> None:
        _identity(self.policy_id, "policy_binding")
        _identity(self.attempt_id, "attempt_binding")
        _identity(self.request_sha256, "request_digest", _SHA)
        _identity(self.response_sha256, "response_digest", _SHA)
        samples = (self.before_disclosure, self.response_complete, self.consumed)
        for sample in samples:
            _require(type(sample) is ElapsedSampleV1, "sample_type")
            # Recheck even exact dataclasses: frozen instances can be bypassed.
            ElapsedSampleV1(sample.clock_profile_id, sample.epoch_id, sample.counter_ns)
        _require(len({s.clock_profile_id for s in samples}) == 1, "mixed_clock_profiles")
        _require(len({s.epoch_id for s in samples}) == 1, "mixed_clock_epochs")
        _require(samples[0].counter_ns <= samples[1].counter_ns <= samples[2].counter_ns, "counter_regression")

    def to_canonical_bytes(self) -> bytes:
        return canonical_dumps(_body(self, "etzio.native-time.elapsed-trace.v1"))

    @classmethod
    def from_canonical_bytes(cls, wire: bytes) -> NativeTimeTraceV1:
        body = _decode(wire, cls, "etzio.native-time.elapsed-trace.v1")
        for name in ("before_disclosure", "response_complete", "consumed"):
            sample = body[name]
            _require(type(sample) is dict and set(sample) == {f.name for f in fields(ElapsedSampleV1)}, "record_shape")
            body[name] = ElapsedSampleV1(**sample)
        return cls(**body)


def _snapshot(policy, trace):
    _require(type(policy) is ElapsedTimePolicyV1 and type(trace) is NativeTimeTraceV1, "input_type")
    try:
        policy = ElapsedTimePolicyV1(**{f.name: getattr(policy, f.name) for f in fields(policy)})
        # Validate nested exact types BEFORE asdict can erase subclass identity.
        trace = NativeTimeTraceV1(**{f.name: getattr(trace, f.name) for f in fields(trace)})
    except AttributeError as exc:
        raise ElapsedTimeError("record_shape") from exc
    trace = NativeTimeTraceV1.from_canonical_bytes(trace.to_canonical_bytes())
    _require(trace.policy_id == policy.policy_id, "policy_binding")
    _require(trace.before_disclosure.clock_profile_id == policy.clock_profile_id, "clock_profile_binding")
    return policy, trace


def _ceil_ratio(numerator: int, denominator: int) -> int:
    return -(-numerator // denominator)


def _elapsed_upper(delta: int, policy: ElapsedTimePolicyV1, unit_ns: int = 1) -> int:
    return _ceil_ratio(
        (delta + 2 * policy.sample_error_ns) * _BILLION,
        (_BILLION - policy.max_rate_error_ppb) * unit_ns,
    )


def _elapsed_lower_us(delta: int, policy: ElapsedTimePolicyV1) -> int:
    return max(0, delta - 2 * policy.sample_error_ns) * _BILLION // ((_BILLION + policy.max_rate_error_ppb) * 1000)


def _project(lower: int, upper: int, policy: ElapsedTimePolicyV1, trace: NativeTimeTraceV1):
    s, r, c = (sample.counter_ns for sample in (trace.before_disclosure, trace.response_complete, trace.consumed))
    receipt = (lower, upper + _elapsed_upper(r - s, policy, 1000))
    use = (lower + _elapsed_lower_us(c - r, policy), upper + _elapsed_upper(c - s, policy, 1000))
    _require(0 <= use[0] <= use[1] < _MAX_UTC_US, "projected_time_bounds")
    _require(use[1] - use[0] <= policy.max_width_us, "projected_width")
    return receipt, use


@dataclass(frozen=True, slots=True)
class NativeTimeElapsedObservationV1:
    """Public conditional evidence; deliberately not a sealed authority value."""

    native_observation: direct.Rfc3161OfflineObservationV1 | rsa.Rfc3161RsaChainObservationV1
    policy_bytes: bytes
    trace_bytes: bytes
    evaluation_window_us: tuple[int, int]
    receipt_interval_us: tuple[int, int]
    consumption_interval_us: tuple[int, int]

    def to_body(self) -> dict:
        lower, upper = self.consumption_interval_us
        return {
            "schema": "etzio.native-time.elapsed-observation.v1",
            "status": "conditional_offline_observation",
            "kernel_authority": False,
            "clock_qualified": False,
            "challenge_freshness_established": False,
            "revocation_at_consumption_checked": False,
            "native_observation_id": self.native_observation.observation_id,
            "artifacts": {
                name: {"sha256": hashlib.sha256(getattr(self, name)).hexdigest(), "size": len(getattr(self, name))}
                for name in ("policy_bytes", "trace_bytes")
            },
            "evaluation_window_us": list(self.evaluation_window_us),
            "receipt_interval_us": list(self.receipt_interval_us),
            "consumption_interval_us": list(self.consumption_interval_us),
            "consumption_interval_seconds": [lower // 1_000_000, _ceil_ratio(upper, 1_000_000)],
        }

    @property
    def observation_id(self) -> str:
        return content_id("native_time_elapsed_observation_v1", self.to_body())


async def evaluate_native_time_elapsed_v1(
    *,
    native_profile: direct.Rfc3161OfflineProfileV1 | rsa.Rfc3161RsaChainProfileV1,
    request: TrustedTimeRequestV1,
    response_der: bytes,
    crls: tuple[bytes, ...],
    policy: ElapsedTimePolicyV1,
    trace: NativeTimeTraceV1,
    evaluation_window_us: tuple[int, int],
) -> NativeTimeElapsedObservationV1:
    """Revalidate bytes and apply a conditional time-of-use gate without I/O.

    The evaluation window is caller policy, not a grant. Live clock qualification,
    freshness, causality, revocation-at-use and enrollment remain separate gates.
    """
    policy, trace = _snapshot(policy, trace)
    _require(type(evaluation_window_us) is tuple and len(evaluation_window_us) == 2, "window_shape")
    for value in evaluation_window_us:
        _integer(value, 0, _MAX_UTC_US, "window_bounds")
    _require(evaluation_window_us[0] < evaluation_window_us[1], "window_bounds")
    _require(type(crls) is tuple, "crl_roles")
    _require(type(response_der) is bytes and 0 < len(response_der) <= direct.MAX_RESPONSE_BYTES_V1, "response_size")
    if type(native_profile) is direct.Rfc3161OfflineProfileV1:
        codec = direct
        _require(len(crls) == 1, "crl_roles")
    elif type(native_profile) is rsa.Rfc3161RsaChainProfileV1:
        codec = rsa
        _require(len(crls) == 2, "crl_roles")
    else:
        raise ElapsedTimeError("native_profile_type")
    for crl in crls:
        _require(type(crl) is bytes and 0 < len(crl) <= direct.MAX_CRL_BYTES_V1, "crl_size")
    try:
        profile, request = codec._snapshot_inputs(native_profile, request)
    except AttributeError as exc:
        raise ElapsedTimeError("record_shape") from exc
    query = codec._request_der(profile, request)
    _require(hashlib.sha256(query).hexdigest() == trace.request_sha256, "request_binding")
    _require(hashlib.sha256(response_der).hexdigest() == trace.response_sha256, "response_binding")
    s, r, c = (sample.counter_ns for sample in (trace.before_disclosure, trace.response_complete, trace.consumed))
    _require(_elapsed_upper(r - s, policy) <= policy.max_acquisition_ns, "acquisition_delay")
    _require(_elapsed_upper(c - s, policy) <= policy.max_total_ns, "consumption_delay")
    # Everything used after the await is a copied record or exact immutable bytes.
    if codec is direct:
        native = await direct.validate_rfc3161_offline_v1(
            profile=profile, request=request, response_der=response_der, crl_der=crls[0]
        )
    else:
        native = await rsa.validate_rfc3161_rsa_chain_offline_v1(
            profile=profile, request=request, response_der=response_der, root_crl_der=crls[0], issuer_crl_der=crls[1]
        )
    receipt, use = _project(native.lower_microseconds, native.upper_microseconds, policy, trace)
    _require(evaluation_window_us[0] <= use[0] and use[1] < evaluation_window_us[1], "consumption_window")
    return NativeTimeElapsedObservationV1(
        native, policy.to_canonical_bytes(), trace.to_canonical_bytes(), evaluation_window_us, receipt, use
    )
