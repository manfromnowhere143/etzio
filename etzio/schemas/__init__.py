"""Installed, single-source schema resources for Etzio protocol objects."""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Any

PROTOCOL_V1_SCHEMA_RESOURCE = "protocol.v1.schema.json"


class SchemaResourceError(ValueError):
    """A packaged schema resource is missing, ambiguous, or malformed."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SchemaResourceError(f"duplicate schema object key {key!r}")
        result[key] = value
    return result


def protocol_v1_schema_text() -> str:
    """Return the exact installed Draft 2020-12 protocol-v1 schema text."""

    return (
        files(__package__)
        .joinpath(PROTOCOL_V1_SCHEMA_RESOURCE)
        .read_text(encoding="utf-8")
    )


def protocol_v1_schema() -> dict[str, Any]:
    """Load the installed protocol-v1 schema while rejecting duplicate keys."""

    try:
        value = json.loads(protocol_v1_schema_text(), object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SchemaResourceError("protocol-v1 schema resource is invalid") from exc
    if type(value) is not dict:
        raise SchemaResourceError("protocol-v1 schema resource must contain an object")
    return value


__all__ = [
    "PROTOCOL_V1_SCHEMA_RESOURCE",
    "SchemaResourceError",
    "protocol_v1_schema",
    "protocol_v1_schema_text",
]
