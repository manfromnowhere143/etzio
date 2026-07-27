"""Etzio protocol-v1 canonical values and envelopes.

The protocol deliberately accepts a smaller value space than Python's JSON encoder:
only null, booleans, integers, NFC strings, arrays, and ASCII-snake-case-keyed objects.
"""

from .v1 import (
    MAX_CONTAINER_ITEMS,
    MAX_INTEGER,
    MAX_NESTING_DEPTH,
    MAX_WIRE_BYTES,
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

__all__ = [
    "EnvelopeV1",
    "MAX_CONTAINER_ITEMS",
    "MAX_INTEGER",
    "MAX_NESTING_DEPTH",
    "MAX_WIRE_BYTES",
    "MIN_INTEGER",
    "ProtocolError",
    "UNICODE_VERSION",
    "canonical_dumps",
    "content_id",
    "freeze_json",
    "strict_loads",
    "thaw_json",
]
