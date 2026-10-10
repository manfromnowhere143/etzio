"""Recover exactly one bounded collector record from a noisy serial capture."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path

BEGIN = b"ETZIO_CLOCK_BEGIN_V1"
END = b"ETZIO_CLOCK_END_V1"
MAX_CAPTURE = 262144


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def finite_float(token):
    value = float(token)
    if not math.isfinite(value):
        raise ValueError("nonfinite JSON number")
    return value


def extract(capture: bytes, collector: bytes) -> dict:
    if type(capture) is not bytes or not 0 < len(capture) <= MAX_CAPTURE:
        raise ValueError("capture size")
    lines = capture.splitlines()
    starts = [i for i, line in enumerate(lines) if line.strip() == BEGIN]
    ends = [i for i, line in enumerate(lines) if line.strip() == END]
    if len(starts) != 1 or len(ends) != 1 or starts[0] >= ends[0]:
        raise ValueError("ambiguous or truncated frame")
    candidates = [line for line in lines[starts[0] + 1 : ends[0]] if line.lstrip().startswith(b"{")]
    if len(candidates) != 1 or len(candidates[0]) > 131072:
        raise ValueError("ambiguous or missing JSON record")
    # Collector resolution observations contain finite floats; this is not protocol JSON.
    body = json.loads(
        candidates[0], object_pairs_hook=unique_object, parse_float=finite_float, parse_constant=finite_float
    )
    if type(body) is not dict or body.get("schema") != "etzio.clock-preflight.observation.v1":
        raise ValueError("collector schema")
    if body.get("collector_sha256") != hashlib.sha256(collector).hexdigest():
        raise ValueError("collector source mismatch")
    if type(body.get("samples")) is not list or len(body["samples"]) != 200:
        raise ValueError("incomplete sample roster")
    return {
        "schema": "etzio.clock-capture-extraction.v1",
        "capture_sha256": hashlib.sha256(capture).hexdigest(),
        "record_sha256": hashlib.sha256(candidates[0]).hexdigest(),
        "record": body,
        "interleaved_lines": ends[0] - starts[0] - 2,
        "boundary": "Exact JSON record recovered; source correspondence is not attestation or clock qualification.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("collector", type=Path)
    args = parser.parse_args()
    with args.capture.open("rb") as source:
        capture = source.read(MAX_CAPTURE + 1)
    print(json.dumps(extract(capture, args.collector.read_bytes()), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
