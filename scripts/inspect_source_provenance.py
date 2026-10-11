"""Compare retained source bytes without executing them or conferring authority.

See docs/SOURCE_PROVENANCE_INSPECTION.md. This deliberately does not use protocol
JSON normalization: source text is opaque and Unicode normalization changes bytes.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import sys
from pathlib import Path

SCHEMA = "etzio.source-provenance-inspection.v1"
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
MAX_SOURCE_BYTES = 256 * 1024
MAX_SOURCES = 128
MAX_DEPTH = 32
MAX_NODES = 100_000


class InspectionError(ValueError):
    """A malformed or inconsistent documentary input, not a target verdict."""


def require(condition, reason):
    if not condition:
        raise InspectionError(reason)


def sha(wire):
    return hashlib.sha256(wire).hexdigest()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def _unsupported_number(_):
    raise InspectionError("unsupported_json_number")


def _json(wire, maximum):
    require(type(wire) is bytes and 0 < len(wire) <= maximum, "json_size")
    try:
        value = json.loads(wire.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_float=_unsupported_number, parse_constant=_unsupported_number)
        pending = [(value, 0)]
        nodes = 0
        while pending:
            item, depth = pending.pop()
            nodes += 1
            require(nodes <= MAX_NODES, "json_nodes")
            require(depth <= MAX_DEPTH, "json_depth")
            if type(item) is dict:
                pending.extend((entry, depth + 1) for pair in item.items() for entry in pair)
            elif type(item) is list:
                pending.extend((entry, depth + 1) for entry in item)
            elif type(item) is str:
                item.encode("utf-8")  # Refuse lone surrogates; preserve valid code points.
        return value
    except InspectionError:
        raise
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise InspectionError("invalid_json") from exc


def _shape(value, keys, reason):
    require(type(value) is dict and set(value) == set(keys), reason)


def _path(value):
    require(type(value) is str and 0 < len(value) <= 512, "source_path")
    require(re.fullmatch(r"[A-Za-z0-9_@.+/-]+", value, re.ASCII) is not None, "source_path")
    require(all(part not in {"", ".", ".."} for part in value.split("/")), "source_path")
    return value


def _bound_bytes(record, maximum, *, source=False):
    keys = {"size_bytes", "sha256", "bytes_base64"} | ({"path"} if source else set())
    _shape(record, keys, "artifact_shape")
    size, digest, encoded = (record[name] for name in ("size_bytes", "sha256", "bytes_base64"))
    require(type(size) is int and 0 <= size <= maximum, "artifact_size")
    require(type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest, re.ASCII) is not None,
            "artifact_digest")
    require(type(encoded) is str and len(encoded) == 4 * ((size + 2) // 3), "base64_size")
    try:
        wire = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise InspectionError("base64_encoding") from exc
    require(base64.b64encode(wire).decode("ascii") == encoded, "base64_encoding")
    require(len(wire) == size and sha(wire) == digest, "artifact_binding")
    return wire


def _side(value):
    require(type(value) is dict, "side_shape")
    kind, label = value.get("kind"), value.get("label")
    require(type(label) is str and re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", label, re.ASCII) is not None,
            "side_label")
    sources = {}
    identity = {"label": label, "kind": kind}
    if kind == "source_bundle":
        _shape(value, {"kind", "label", "sources"}, "side_shape")
        records = value["sources"]
        require(type(records) is list and len(records) <= MAX_SOURCES, "source_count")
        for record in records:
            wire = _bound_bytes(record, MAX_SOURCE_BYTES, source=True)
            path = _path(record["path"])
            require(path not in sources, "duplicate_source_path")
            sources[path] = wire
    elif kind == "hardhat_deployment":
        _shape(value, {"kind", "label", "document"}, "side_shape")
        wire = _bound_bytes(value["document"], MAX_ARTIFACT_BYTES)
        identity["document_sha256"] = sha(wire)
        document = _json(wire, MAX_ARTIFACT_BYTES)
        require(type(document) is dict and type(document.get("metadata")) is str, "metadata_string")
        metadata = _json(document["metadata"].encode("utf-8"), MAX_ARTIFACT_BYTES)
        require(type(metadata) is dict and type(metadata.get("sources")) is dict, "metadata_sources")
        require(len(metadata["sources"]) <= MAX_SOURCES, "source_count")
        for path, record in metadata["sources"].items():
            path = _path(path)
            require(type(record) is dict, "metadata_source_shape")
            if "content" not in record:
                sources[path] = None  # A URL or asserted digest is not literal source bytes.
            else:
                require(type(record["content"]) is str, "literal_source_type")
                wire = record["content"].encode("utf-8")
                require(len(wire) <= MAX_SOURCE_BYTES, "source_size")
                sources[path] = wire
    else:
        raise InspectionError("source_kind")
    identity["available_source_paths"] = sorted(p for p, wire in sources.items() if wire is not None)
    identity["unavailable_source_paths"] = sorted(p for p, wire in sources.items() if wire is None)
    return identity, sources


def _availability(sources, path):
    if path not in sources:
        return {"state": "absent"}
    wire = sources[path]
    if wire is None:
        return {"state": "literal_content_unavailable"}
    return {"state": "available", "size_bytes": len(wire), "sha256": sha(wire)}


def inspect_source_provenance(wire: bytes) -> dict:
    body = _json(wire, MAX_MANIFEST_BYTES)
    _shape(body, {"schema", "scope", "left", "right"}, "manifest_shape")
    require(body["schema"] == SCHEMA, "manifest_schema")
    scope = body["scope"]
    require(type(scope) is list and 0 < len(scope) <= MAX_SOURCES, "scope_size")
    scope = [_path(path) for path in scope]
    require(len(set(scope)) == len(scope), "duplicate_scope_path")
    left_identity, left = _side(body["left"])
    right_identity, right = _side(body["right"])
    rows, counts = [], dict.fromkeys(("equal", "different", "unknown"), 0)
    for path in sorted(scope):
        a, b = _availability(left, path), _availability(right, path)
        state = "unknown"
        if a["state"] == b["state"] == "available":
            state = "equal" if left[path] == right[path] else "different"
        counts[state] += 1
        rows.append({"path": path, "state": state, "left": a, "right": b})
    return {
        "schema": "etzio.source-provenance-observation.v1",
        "status": "documentary_observation",
        "manifest_sha256": sha(wire),
        "kernel_authority": False,
        "bytecode_reproduced": False,
        "chain_state_verified": False,
        "audit_coverage_established": False,
        "metadata_keccak_validated": False,
        "inputs": {"left": left_identity, "right": right_identity},
        "scope": sorted(scope),
        "counts": counts,
        "all_requested_sources_equal": counts["equal"] == len(scope),
        "sources": rows,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args(argv)
    try:
        with args.manifest.open("rb") as source:
            report = inspect_source_provenance(source.read(MAX_MANIFEST_BYTES + 1))
    except (InspectionError, OSError) as exc:
        print(f"source provenance inspection refused: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
