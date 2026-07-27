"""Etzio protocol-v1 canonical values and envelopes.

The protocol deliberately accepts a smaller value space than Python's JSON encoder:
only null, booleans, integers, NFC strings, arrays, and ASCII-snake-case-keyed objects.
"""

from .semantic_v1 import SemanticProtocolError, parse_semantic_bytes, parse_semantic_envelope
from .v1 import (
    ENVELOPE_FIELDS_V1,
    MAX_CONTAINER_ITEMS,
    MAX_INTEGER,
    MAX_NESTING_DEPTH,
    MAX_WIRE_BYTES,
    MIN_INTEGER,
    OPTIONALLY_ATTESTED_OBJECT_KINDS_V1,
    RESERVED_OBJECT_KINDS,
    SEMANTIC_BODY_FIELDS_BY_KIND_V1,
    SEMANTIC_OBJECT_KINDS,
    SUPPORTED_OBJECT_KINDS,
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
    "ENVELOPE_FIELDS_V1",
    "MAX_CONTAINER_ITEMS",
    "MAX_INTEGER",
    "MAX_NESTING_DEPTH",
    "MAX_WIRE_BYTES",
    "MIN_INTEGER",
    "OPTIONALLY_ATTESTED_OBJECT_KINDS_V1",
    "ProtocolError",
    "RESERVED_OBJECT_KINDS",
    "SEMANTIC_BODY_FIELDS_BY_KIND_V1",
    "SEMANTIC_OBJECT_KINDS",
    "SUPPORTED_OBJECT_KINDS",
    "SemanticProtocolError",
    "UNICODE_VERSION",
    "canonical_dumps",
    "content_id",
    "freeze_json",
    "parse_semantic_bytes",
    "parse_semantic_envelope",
    "strict_loads",
    "thaw_json",
]
