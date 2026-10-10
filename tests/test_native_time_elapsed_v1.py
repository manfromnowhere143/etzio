"""Conditional timing proof, independent rational timelines and native composition."""

from __future__ import annotations

import asyncio
import hashlib
import itertools
import json
import socket
import time
from dataclasses import replace
from fractions import Fraction

import pytest
from native_time_fixtures import context as direct_context
from native_time_fixtures import fixture as direct_fixture
from native_time_rsa_fixtures import context as rsa_context
from native_time_rsa_fixtures import fixture as rsa_fixture

from etzio.protocol import canonical_dumps, content_id
from etzio.qualification import native_time_elapsed_v1 as elapsed
from etzio.qualification import rfc3161_rsa_chain_v1 as rsa
from etzio.qualification import rfc3161_v1 as direct

G = 1791547200 * 1_000_000
CLOCK = content_id("elapsed_fixture", {"clock": 1})
EPOCH = content_id("elapsed_fixture", {"epoch": 1})
ATTEMPT = content_id("elapsed_fixture", {"attempt": 1})


def policy(**changes):
    return replace(elapsed.ElapsedTimePolicyV1(CLOCK, 0, 0, 30_000_000_000, 60_000_000_000, 60_000_000), **changes)


def sample(counter, **changes):
    return replace(elapsed.ElapsedSampleV1(CLOCK, EPOCH, counter), **changes)


def trace(p, query=b"query", response=b"response", *, s=1_000_000_000, r=3_000_000_000, c=6_000_000_000):
    return elapsed.NativeTimeTraceV1(
        p.policy_id,
        ATTEMPT,
        hashlib.sha256(query).hexdigest(),
        hashlib.sha256(response).hexdigest(),
        sample(s),
        sample(r),
        sample(c),
    )


@pytest.fixture(scope="module", params=["direct", "rsa"])
def inputs(request):
    if request.param == "direct":
        fixture, context = direct_fixture(), direct_context()
        crls = (fixture.crl(),)
        query = direct.build_rfc3161_request_v1(profile=fixture.profile, request=context)
    else:
        fixture, context = rsa_fixture(), rsa_context()
        crls = (fixture.crl("root"), fixture.crl("issuer"))
        query = rsa.build_rfc3161_rsa_chain_request_v1(profile=fixture.profile, request=context)
    response = fixture.response()
    p = policy()
    return dict(
        native_profile=fixture.profile,
        request=context,
        response_der=response,
        crls=crls,
        policy=p,
        trace=trace(p, query, response),
        evaluation_window_us=(G - 10_000_000, G + 70_000_000),
    )


def evaluate(inputs, **changes):
    return asyncio.run(elapsed.evaluate_native_time_elapsed_v1(**(inputs | changes)))


def refused(inputs, reason, **changes):
    with pytest.raises(elapsed.ElapsedTimeError) as exc:
        evaluate(inputs, **changes)
    assert exc.value.reason_code == reason


def test_both_native_profiles_reauthenticate_and_replay_exact_retained_bytes(inputs, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("network or ambient clock accessed")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(time, "time", forbidden)
    monkeypatch.setattr(time, "monotonic_ns", forbidden)
    monkeypatch.setattr(time, "clock_gettime_ns", forbidden)
    first = evaluate(inputs)
    replay = evaluate(
        inputs,
        policy=elapsed.ElapsedTimePolicyV1.from_canonical_bytes(first.policy_bytes),
        trace=elapsed.NativeTimeTraceV1.from_canonical_bytes(first.trace_bytes),
    )
    assert first == replay
    assert first.observation_id == replay.observation_id
    assert first.receipt_interval_us == (G - 1_000_000, G + 3_000_000)
    assert first.consumption_interval_us == (G + 2_000_000, G + 6_000_000)
    assert first.to_body()["consumption_interval_seconds"] == [1791547202, 1791547206]
    for name in (
        "kernel_authority",
        "clock_qualified",
        "challenge_freshness_established",
        "revocation_at_consumption_checked",
    ):
        assert first.to_body()[name] is False
    assert first.native_observation.response_der == inputs["response_der"]


@pytest.mark.parametrize("offset", [-1, 0, 1])
def test_complete_hull_at_half_open_expiry(inputs, offset):
    # The signed issuance center is within every window; only the whole use hull decides.
    window = (G - 10_000_000, G + 6_000_000 + offset)
    if offset > 0:
        assert evaluate(inputs, evaluation_window_us=window).consumption_interval_us[1] < window[1]
    else:
        refused(inputs, "consumption_window", evaluation_window_us=window)


@pytest.mark.parametrize("offset", [-1, 0, 1])
def test_closed_lower_endpoint(inputs, offset):
    window = (G + 2_000_000 + offset, G + 70_000_000)
    if offset <= 0:
        evaluate(inputs, evaluation_window_us=window)
    else:
        refused(inputs, "consumption_window", evaluation_window_us=window)


@pytest.mark.parametrize(
    ("r", "c", "reason"),
    [
        (31_000_000_001, 31_000_000_001, "acquisition_delay"),
        (3_000_000_000, 61_000_000_001, "consumption_delay"),
    ],
)
def test_delay_limits_include_post_receipt_pause(inputs, r, c, reason):
    t = replace(inputs["trace"], response_complete=sample(r), consumed=sample(c))
    refused(inputs, reason, trace=t)


def test_exact_delay_ceilings_and_conservative_rate_correction(inputs):
    t = replace(inputs["trace"], response_complete=sample(31_000_000_000), consumed=sample(61_000_000_000))
    evaluate(inputs, trace=t)
    p = policy(max_rate_error_ppb=1)
    refused(inputs, "acquisition_delay", policy=p, trace=replace(t, policy_id=p.policy_id))
    p = policy(sample_error_ns=1)
    refused(inputs, "acquisition_delay", policy=p, trace=replace(t, policy_id=p.policy_id))


def test_width_after_outward_rounding(inputs):
    p = policy(max_width_us=4_000_000)
    evaluate(inputs, policy=p, trace=replace(inputs["trace"], policy_id=p.policy_id))
    p = replace(p, sample_error_ns=1)
    refused(inputs, "projected_width", policy=p, trace=replace(inputs["trace"], policy_id=p.policy_id))


@pytest.mark.parametrize("field", ["request_sha256", "response_sha256", "policy_id"])
def test_transcript_and_policy_substitution(inputs, field):
    new = ("sha256:" if field == "policy_id" else "") + "0" * 64
    refused(
        inputs,
        {"request_sha256": "request_binding", "response_sha256": "response_binding", "policy_id": "policy_binding"}[
            field
        ],
        trace=replace(inputs["trace"], **{field: new}),
    )


def test_native_signature_is_rechecked_even_after_trace_digest_is_recomputed(inputs):
    response = inputs["response_der"][:-1] + bytes([inputs["response_der"][-1] ^ 1])
    t = replace(inputs["trace"], response_sha256=hashlib.sha256(response).hexdigest())
    with pytest.raises(direct.NativeTimeError) as exc:
        evaluate(inputs, response_der=response, trace=t)
    assert exc.value.reason_code == "signature_or_path"


def test_foreign_native_request_refused(inputs):
    builder = direct_context if type(inputs["native_profile"]) is direct.Rfc3161OfflineProfileV1 else rsa_context
    refused(inputs, "request_binding", request=builder(request_nonce="ab" * 32))


@pytest.mark.parametrize("crls", [[], (), (b"x", b"y", b"z")])
def test_no_missing_extra_or_mutable_crl_roster(inputs, crls):
    refused(inputs, "crl_roles", crls=crls)


@pytest.mark.parametrize("response", [bytearray(b"x"), b"", b"x" * (65536 + 1)])
def test_response_bounds_before_parsing(inputs, response):
    refused(inputs, "response_size", response_der=response)


@pytest.mark.parametrize("window", [[], (G,), (G, G, G), (True, G), (G, G), (-1, G), (G, 2**63)])
def test_malformed_window(inputs, window):
    refused(
        inputs,
        "window_shape" if type(window) is not tuple or len(window) != 2 else "window_bounds",
        evaluation_window_us=window,
    )


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("max_rate_error_ppb", True, "rate_bound"),
        ("max_rate_error_ppb", -1, "rate_bound"),
        ("max_rate_error_ppb", 100_000_001, "rate_bound"),
        ("sample_error_ns", -1, "sample_error"),
        ("sample_error_ns", 1_000_000_001, "sample_error"),
        ("sample_error_ns", 0.0, "sample_error"),
        ("max_acquisition_ns", 0, "acquisition_ceiling"),
        ("max_acquisition_ns", 30_000_000_001, "acquisition_ceiling"),
        ("max_total_ns", 1, "total_ceiling"),
        ("max_total_ns", 60_000_000_001, "total_ceiling"),
        ("max_width_us", 0, "width_ceiling"),
        ("max_width_us", 180_000_001, "width_ceiling"),
        ("clock_profile_id", "CLOCK_BOOTTIME", "clock_profile"),
        ("clock_semantics", "CLOCK_MONOTONIC", "clock_semantics"),
        ("clock_semantics", "leap_smear", "clock_semantics"),
    ],
)
def test_clock_assumption_domain(field, value, reason):
    with pytest.raises(elapsed.ElapsedTimeError) as exc:
        policy(**{field: value})
    assert exc.value.reason_code == reason


@pytest.mark.parametrize("counter", [-1, 2**63, True, 0.1, None])
def test_counter_domain(counter):
    with pytest.raises(elapsed.ElapsedTimeError, match="counter_bounds"):
        sample(counter)


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"epoch_id": content_id("elapsed_fixture", {"epoch": 2})}, "mixed_clock_epochs"),
        ({"clock_profile_id": content_id("elapsed_fixture", {"clock": 2})}, "mixed_clock_profiles"),
        ({"counter_ns": 0}, "counter_regression"),
    ],
)
def test_reboot_profile_change_or_counter_reset(changes, reason):
    t = trace(policy())
    with pytest.raises(elapsed.ElapsedTimeError, match=reason):
        replace(t, consumed=replace(t.consumed, **changes))


def test_internally_consistent_foreign_clock_still_refuses_policy(inputs):
    foreign = content_id("elapsed_fixture", {"clock": "foreign"})
    t = inputs["trace"]
    changes = {
        name: replace(getattr(t, name), clock_profile_id=foreign)
        for name in ("before_disclosure", "response_complete", "consumed")
    }
    refused(inputs, "clock_profile_binding", trace=replace(t, **changes))


@pytest.mark.parametrize("field", ["policy", "trace", "sample", "native_profile"])
def test_subclass_cannot_change_interpretation(inputs, field):
    if field == "sample":
        t = replace(inputs["trace"])
        cls = type("ForeignSample", (elapsed.ElapsedSampleV1,), {})
        object.__setattr__(t, "consumed", cls(CLOCK, EPOCH, 6_000_000_000))
        refused(inputs, "sample_type", trace=t)
        return
    value = inputs[field]
    cls = type("ForeignRecord", (type(value),), {})
    from dataclasses import fields

    changed = cls(**{f.name: getattr(value, f.name) for f in fields(value)})
    refused(inputs, "native_profile_type" if field == "native_profile" else "input_type", **{field: changed})


def test_frozen_constructor_bypass_is_revalidated(inputs):
    t = replace(inputs["trace"], consumed=replace(inputs["trace"].consumed))
    object.__setattr__(t.consumed, "counter_ns", True)
    refused(inputs, "counter_bounds", trace=t)


def test_caller_mutation_across_await_cannot_change_retained_inputs(inputs, monkeypatch):
    p = replace(inputs["policy"])
    t = replace(inputs["trace"], consumed=replace(inputs["trace"].consumed))
    prof = replace(inputs["native_profile"])
    name = (
        "validate_rfc3161_offline_v1"
        if type(prof) is direct.Rfc3161OfflineProfileV1
        else "validate_rfc3161_rsa_chain_offline_v1"
    )
    module = direct if type(prof) is direct.Rfc3161OfflineProfileV1 else rsa
    original = getattr(module, name)
    expected = evaluate(inputs)

    async def mutate(**kwargs):
        object.__setattr__(p, "sample_error_ns", 999999999)
        object.__setattr__(t.consumed, "counter_ns", 999999999999)
        object.__setattr__(prof, "root_certificate_der", b"foreign")
        return await original(**kwargs)

    monkeypatch.setattr(module, name, mutate)
    assert evaluate(inputs, policy=p, trace=t, native_profile=prof) == expected


@pytest.mark.parametrize("kind", ["policy", "trace"])
@pytest.mark.parametrize("mutation", ["extra", "missing", "duplicate", "space", "oversize", "schema", "nested"])
def test_closed_bounded_canonical_records(kind, mutation):
    record = policy() if kind == "policy" else trace(policy())
    wire = record.to_canonical_bytes()
    body = json.loads(wire)
    if mutation == "extra":
        body["kernel_authority"] = True
    elif mutation == "missing":
        del body[next(k for k in body if k != "schema")]
    elif mutation == "schema":
        body["schema"] += ".foreign"
    elif mutation == "nested":
        body["clock_profile_id" if kind == "policy" else "consumed"] = {"bad": True}
    else:
        wire = {"duplicate": b'{"schema":"duplicate",' + wire[1:], "space": b" " + wire, "oversize": b"x" * 8193}[
            mutation
        ]
    if mutation in {"extra", "missing", "schema", "nested"}:
        wire = canonical_dumps(body)
    expected = {
        "extra": "record_shape",
        "missing": "record_shape",
        "duplicate": "record_encoding",
        "space": "record_encoding",
        "oversize": "record_size",
        "schema": "record_encoding",
        "nested": "clock_profile" if kind == "policy" else "record_shape",
    }[mutation]
    with pytest.raises(elapsed.ElapsedTimeError) as exc:
        type(record).from_canonical_bytes(wire)
    assert exc.value.reason_code == expected


def test_rounding_matches_fraction_reference_and_maximum_counter_origin():
    for drift, error, acquisition, wait in itertools.product(
        (0, 1, 100_000, 100_000_000), (0, 1, 999), (0, 1, 999, 1000, 1001), (0, 1, 1999)
    ):
        p = policy(max_rate_error_ppb=drift, sample_error_ns=error)
        origin = 2**63 - 1 - acquisition - wait
        t = trace(p, s=origin, r=origin + acquisition, c=origin + acquisition + wait)
        receipt, use = elapsed._project(G - 1, G + 1, p, t)
        rate = Fraction(drift, 10**9)
        lo = Fraction(max(0, wait - 2 * error), 1000) / (1 + rate)
        hi = Fraction(acquisition + wait + 2 * error, 1000) / (1 - rate)
        assert use == (G - 1 + lo.__floor__(), G + 1 + hi.__ceil__())
        receipt_hi = Fraction(acquisition + 2 * error, 1000) / (1 - rate)
        assert receipt == (G - 1, G + 1 + receipt_hi.__ceil__())


def test_bounds_contain_physical_timelines_with_asymmetry_and_changing_rate():
    # Construct counter readings from physical timelines, rather than invert the formula.
    # Rates change at receipt; endpoint reading errors are independent.
    p = policy(max_rate_error_ppb=100_000_000, sample_error_ns=5)
    cases = 0
    for acquisition, wait, rate_a, rate_b, errors in itertools.product(
        (100, 10_000, 2_000_000_000),
        (0, 10_000, 3_000_000_000),
        (Fraction(9, 10), Fraction(1), Fraction(11, 10)),
        (Fraction(9, 10), Fraction(1), Fraction(11, 10)),
        itertools.product((-5, 0, 5), repeat=3),
    ):
        s = 100 + errors[0]
        r = 100 + int(acquisition * rate_a) + errors[1]
        c = 100 + int(acquisition * rate_a + wait * rate_b) + errors[2]
        if c < r:  # The contract deliberately refuses regressing observed readings.
            continue
        t = trace(p, s=s, r=r, c=c)
        for issuance in (0, acquisition // 2, acquisition):
            # Source center at real issuance, +/- 1 us of explicit accuracy.
            center = G + Fraction(issuance, 1000)
            lower, upper = (center - 1).__floor__(), (center + 1).__ceil__()
            receipt, use = elapsed._project(lower, upper, p, t)
            actual_receipt = G + Fraction(acquisition, 1000)
            actual_use = G + Fraction(acquisition + wait, 1000)
            assert receipt[0] <= actual_receipt <= receipt[1]
            assert use[0] <= actual_use <= use[1]
            cases += 1
    assert cases == 5832


def test_no_half_round_trip_or_frozen_issuance_shortcut():
    p = policy()
    t = trace(p, s=0, r=10_000_000_000, c=20_000_000_000)
    receipt, use = elapsed._project(G - 1_000_000, G + 1_000_000, p, t)
    assert receipt == (G - 1_000_000, G + 11_000_000)
    assert use == (G + 9_000_000, G + 21_000_000)
    # All network delay can follow issuance; RTT/2 would exclude this valid endpoint.
    assert receipt[1] > G + 1_000_000 + 5_000_000


def test_projected_epoch_overflow_refused():
    with pytest.raises(elapsed.ElapsedTimeError, match="projected_time_bounds"):
        elapsed._project(elapsed._MAX_UTC_US - 2, elapsed._MAX_UTC_US - 1, policy(), trace(policy()))


@pytest.mark.parametrize("field", ["policy", "trace", "native_profile"])
def test_uninitialized_exact_records_refuse(inputs, field):
    refused(inputs, "record_shape", **{field: object.__new__(type(inputs[field]))})


@pytest.mark.parametrize("crl", [b"", bytearray(b"x"), b"x" * (262144 + 1)])
def test_crl_size_and_immutability_before_parsing(inputs, crl):
    refused(inputs, "crl_size", crls=(crl,) + inputs["crls"][1:])


def test_consumption_trace_and_window_change_identity(inputs):
    original = evaluate(inputs)
    t = replace(inputs["trace"], consumed=sample(6_000_000_001))
    later = evaluate(inputs, trace=t)
    assert later.observation_id != original.observation_id
    assert later.consumption_interval_us[1] == original.consumption_interval_us[1] + 1
    another = replace(inputs["trace"], attempt_id=content_id("elapsed_fixture", {"attempt": 2}))
    assert evaluate(inputs, trace=another).observation_id != original.observation_id
    window_change = evaluate(inputs, evaluation_window_us=(G - 9_000_000, G + 70_000_000))
    assert window_change.observation_id != original.observation_id


def test_operational_error_and_cancellation_keep_their_domain(inputs, monkeypatch):
    module, name = (
        (direct, "validate_rfc3161_offline_v1")
        if type(inputs["native_profile"]) is direct.Rfc3161OfflineProfileV1
        else (rsa, "validate_rfc3161_rsa_chain_offline_v1")
    )
    for error in (OSError("fixture storage error"), asyncio.CancelledError()):

        async def fail(error=error, **kwargs):
            raise error

        monkeypatch.setattr(module, name, fail)
        with pytest.raises(type(error)) as exc:
            evaluate(inputs)
        assert exc.value is error
