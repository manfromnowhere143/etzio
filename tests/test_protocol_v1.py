"""Golden vectors and known-bad controls for the Etzio protocol-v1 boundary."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import unicodedata2
from jsonschema import Draft202012Validator

from etzio.protocol import (
    MAX_CONTAINER_ITEMS,
    MAX_INTEGER,
    MAX_NESTING_DEPTH,
    MIN_INTEGER,
    UNICODE_VERSION,
    EnvelopeV1,
    ProtocolError,
    canonical_dumps,
    content_id,
    freeze_json,
    strict_loads,
    thaw_json,
)
from etzio.protocol.v1 import SUPPORTED_OBJECT_KINDS


def test_canonical_bytes_and_content_id_are_order_stable():
    left = {"zebra": [3, {"inner_key": "café"}], "alpha": True}
    right = {"alpha": True, "zebra": [3, {"inner_key": "café"}]}

    expected_bytes = b'{"alpha":true,"zebra":[3,{"inner_key":"caf\xc3\xa9"}]}'
    assert canonical_dumps(left) == expected_bytes
    assert canonical_dumps(right) == expected_bytes
    assert content_id("candidate", left) == content_id("candidate", right)
    assert content_id("candidate", left) == ("sha256:f37dd7c41aaabd2d790624aad9f7f597fe5fa41713b9d4b77cb600d5479bb6b9")
    assert content_id("event", left) != content_id("candidate", left)


@pytest.mark.parametrize(
    "wire",
    [
        '{"key":1,"key":2}',
        '{"outer":{"key":1,"key":2}}',
    ],
)
def test_duplicate_keys_are_rejected(wire: str):
    with pytest.raises(ProtocolError, match="duplicate"):
        strict_loads(wire)


@pytest.mark.parametrize("wire", ["1.0", "1e3", "NaN", "Infinity", "-Infinity"])
def test_floating_point_wire_values_are_rejected(wire: str):
    with pytest.raises(ProtocolError):
        strict_loads(wire)


@pytest.mark.parametrize("value", [1.0, float("nan"), float("inf")])
def test_floating_point_runtime_values_are_rejected(value: float):
    with pytest.raises(ProtocolError):
        canonical_dumps({"value": value})


@pytest.mark.parametrize(
    "value",
    [
        {"bad-key": 1},
        {"Upper": 1},
        {"_private": 1},
        {"trailing_": 1},
        {"naïve": 1},
    ],
)
def test_object_keys_must_be_ascii_snake_case(value: dict[str, int]):
    with pytest.raises(ProtocolError, match="ASCII snake_case"):
        canonical_dumps(value)


@pytest.mark.parametrize(
    "value",
    [
        {"value": "e\u0301"},
        {"e\u0301": "value"},
        {"value": "\ud800"},
        {"value": "\udfff"},
    ],
)
def test_strings_must_be_nfc_unicode_scalars(value: dict[str, str]):
    with pytest.raises(ProtocolError):
        canonical_dumps(value)


def test_strict_loads_rejects_escaped_surrogates_and_non_nfc():
    with pytest.raises(ProtocolError, match="surrogate"):
        strict_loads(r'{"value":"\ud800"}')
    with pytest.raises(ProtocolError, match="NFC"):
        strict_loads('{"value":"e\\u0301"}')


def test_protocol_uses_one_pinned_unicode_database_across_python_versions():
    assert UNICODE_VERSION == "17.0.0"
    assert unicodedata2.unidata_version == UNICODE_VERSION
    newly_assigned_combining_mark = "a\U00010d69\u0323"
    with pytest.raises(ProtocolError, match="NFC"):
        canonical_dumps({"value": newly_assigned_combining_mark})


def test_freeze_and_thaw_are_deep_and_do_not_alias_source():
    source = {"outer": [{"count": 1}]}
    frozen = freeze_json(source)
    source["outer"][0]["count"] = 99

    assert frozen["outer"][0]["count"] == 1
    with pytest.raises(TypeError):
        frozen["new_key"] = "forbidden"
    with pytest.raises(TypeError):
        frozen["outer"][0]["count"] = 2

    thawed = thaw_json(frozen)
    thawed["outer"][0]["count"] = 7
    assert frozen["outer"][0]["count"] == 1


def test_envelope_round_trip_is_canonical_and_deeply_immutable():
    envelope = EnvelopeV1.create(
        "candidate",
        {"candidate_id": "C-1", "evidence": [{"digest": "sha256:abc"}]},
    )

    restored = EnvelopeV1.from_bytes(envelope.to_bytes())
    assert restored == envelope
    assert restored.object_id == content_id("candidate", restored.body)
    assert restored.to_bytes() == envelope.to_bytes()
    with pytest.raises(TypeError):
        restored.body["candidate_id"] = "forged"
    with pytest.raises(TypeError):
        restored.body["evidence"][0]["digest"] = "forged"


def test_attestations_do_not_change_semantic_object_id():
    plain = EnvelopeV1.create("authority_grant", {"grant_id": "G-1"})
    attested = EnvelopeV1.create(
        "authority_grant",
        {"grant_id": "G-1"},
        attestations=[{"key_id": "operator-1", "signature": "example"}],
    )

    assert attested.object_id == plain.object_id
    assert attested.to_bytes() != plain.to_bytes()


def _mutated_envelope(**updates: object) -> bytes:
    value = EnvelopeV1.create("event", {"event_type": "mission_opened"}).to_dict()
    value.update(updates)
    return canonical_dumps(value)


@pytest.mark.parametrize(
    ("update", "message"),
    [
        ({"protocol_version": 2}, "protocol version"),
        ({"object_version": 2}, "object version"),
        ({"object_kind": "future_kind"}, "object kind"),
        ({"object_id": "sha256:" + ("0" * 64)}, "does not match"),
    ],
)
def test_unknown_versions_kinds_and_tampered_ids_are_rejected(
    update: dict[str, object],
    message: str,
):
    with pytest.raises(ProtocolError, match=message) as raised:
        EnvelopeV1.from_bytes(_mutated_envelope(**update))
    if "object_id" in update:
        assert raised.value.code == "object_id_mismatch"


def test_unknown_and_missing_envelope_fields_are_rejected():
    value = EnvelopeV1.create("event", {"event_type": "mission_opened"}).to_dict()
    value["unexpected"] = True
    with pytest.raises(ProtocolError, match="unknown envelope fields"):
        EnvelopeV1.from_bytes(canonical_dumps(value))
    del value["unexpected"]
    del value["attestations"]
    with pytest.raises(ProtocolError, match="missing envelope fields"):
        EnvelopeV1.from_bytes(canonical_dumps(value))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda raw: b" " + raw,
        lambda raw: raw.replace(b'"count":0', b'"count":-0'),
        lambda raw: raw.replace(b'"candidate_id"', b'"candidate_\\u0069d"'),
    ],
)
def test_envelope_parser_rejects_noncanonical_wire_spellings(mutate):
    raw = EnvelopeV1.create("candidate", {"candidate_id": "C-1", "count": 0}).to_bytes()
    with pytest.raises(ProtocolError, match="not canonical"):
        EnvelopeV1.from_bytes(mutate(raw))


def test_schema_is_valid_and_accepts_canonical_envelope():
    schema_path = Path(__file__).parents[1] / "schemas" / "protocol.v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)

    envelope = EnvelopeV1.create("target_snapshot", {"revision": "abc123"})
    Draft202012Validator(schema).validate(envelope.to_dict())


def test_schema_and_runtime_object_kind_allowlists_have_exact_parity():
    schema_path = Path(__file__).parents[1] / "schemas" / "protocol.v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    schema_kinds = frozenset(schema["properties"]["object_kind"]["enum"])

    assert schema_kinds == SUPPORTED_OBJECT_KINDS
    assert EnvelopeV1.create("verification_lease", {"purpose": "modeled_fixture_verification"})
    with pytest.raises(ProtocolError, match="unsupported"):
        EnvelopeV1.create("verification_leases", {"purpose": "modeled_fixture_verification"})


def test_non_json_values_and_non_utf8_wire_are_rejected():
    for value in ({1, 2}, b"bytes", object()):
        with pytest.raises(ProtocolError):
            canonical_dumps({"value": value})
    with pytest.raises(ProtocolError, match="UTF-8"):
        strict_loads(b'{"value":"\xff"}')


def test_integer_domain_is_explicit_and_independent_of_interpreter_digit_settings():
    assert canonical_dumps({"maximum": MAX_INTEGER, "minimum": MIN_INTEGER})
    for value in (MAX_INTEGER + 1, MIN_INTEGER - 1):
        with pytest.raises(ProtocolError, match="64-bit"):
            canonical_dumps({"value": value})
        with pytest.raises(ProtocolError, match="64-bit"):
            strict_loads(str(value))
    with pytest.raises(ProtocolError, match="64-bit"):
        strict_loads("1" * 1000)


def test_container_and_nesting_limits_fail_before_protocol_use():
    with pytest.raises(ProtocolError, match="item-count"):
        canonical_dumps({"items": [None] * (MAX_CONTAINER_ITEMS + 1)})

    nested: object = None
    for _ in range(MAX_NESTING_DEPTH + 1):
        nested = [nested]
    with pytest.raises(ProtocolError, match="nesting"):
        canonical_dumps(nested)


def test_envelope_attestation_count_is_bounded():
    with pytest.raises(ProtocolError, match="attestation-count"):
        EnvelopeV1.create(
            "candidate",
            {"candidate_id": "C-1"},
            attestations=[{"key_id": f"K-{index}"} for index in range(17)],
        )
