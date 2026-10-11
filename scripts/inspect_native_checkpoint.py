"""Finite offline C2SP checkpoint signature inspection; no trust or head admission."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from etzio.crypto_v1 import is_valid_ed25519_public_key

MAX_NOTE = 128 * 1024
MAX_SIGNATURES = 32
MAX_SIGNATURE_VALUE = 8192
MAX_VKEY = 512
MAX_KEYS = 16
MAX_NAME = 255
MAX_UINT64 = 2**64 - 1


class CheckpointInspectionError(ValueError):
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise CheckpointInspectionError(reason)


def utf8(value: str, maximum: int, reason: str) -> bytes:
    require(type(value) is str and 0 < len(value) <= maximum, reason)
    try:
        result = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise CheckpointInspectionError(reason) from exc
    require(len(result) <= maximum, reason)
    return result


def name(value: str) -> bytes:
    encoded = utf8(value, MAX_NAME, "name")
    require(not any(c.isspace() or c == "+" or ord(c) < 32 for c in value), "name")
    return encoded


def decoded(value: str, maximum: int) -> bytes:
    require(len(value) <= 4 * ((maximum + 2) // 3), "base64_bound")
    try:
        result = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise CheckpointInspectionError("base64") from exc
    require(len(result) <= maximum, "base64_bound")
    require(base64.b64encode(result).decode("ascii") == value, "base64_canonical")
    return result


def verifier(value: str, kind: int) -> dict:
    wire = utf8(value, MAX_VKEY, "verifier_bound")
    parts = value.split("+", 2)
    require(len(parts) == 3 and re.fullmatch(r"[0-9a-f]{8}", parts[1]) is not None, "verifier_format")
    key_name, key_id, encoded = parts
    name_wire = name(key_name)
    material = decoded(encoded, 33)
    require(len(material) == 33 and material[0] == kind, "verifier_type")
    require(hashlib.sha256(name_wire + b"\n" + material).digest()[:4].hex() == key_id, "verifier_id")
    require(is_valid_ed25519_public_key(material[1:]), "verifier_point")
    return {"name": key_name, "id": key_id, "type": kind, "key": material[1:], "wire": wire}


def inspect_checkpoint(
    wire: bytes, *, expected_origin: str, log_vkey: str, witness_vkeys: tuple[str, ...] = ()
) -> dict:
    require(type(wire) is bytes and 0 < len(wire) <= MAX_NOTE, "note_bound")
    name(expected_origin)
    require(type(witness_vkeys) is tuple and len(witness_vkeys) < MAX_KEYS, "roster_bound")
    keys = [verifier(log_vkey, 1)] + [verifier(value, 4) for value in witness_vkeys]
    require(len({key["name"] for key in keys}) == len(keys), "roster_name_reuse")
    require(len({key["key"] for key in keys}) == len(keys), "roster_key_reuse")
    try:
        text = wire.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise CheckpointInspectionError("note_utf8") from exc
    require(not any(ord(c) < 32 and c != "\n" for c in text), "note_control")
    require(wire.endswith(b"\n") and wire.count(b"\n\n") == 1, "note_framing")
    body_prefix, signatures = wire.split(b"\n\n")
    body = body_prefix + b"\n"
    # Count before splitting or decoding each signature value.
    require(0 < signatures.count(b"\n") <= MAX_SIGNATURES, "signature_count")
    configured = {(key["name"], key["id"]): key for key in keys}
    seen: set[tuple[str, str]] = set()
    verified: dict[tuple[str, str], int | None] = {}
    ignored = 0
    for line in signatures[:-1].decode("utf-8").split("\n"):
        parts = line.split(" ")
        require(len(parts) == 3 and parts[0] == "—", "signature_framing")
        name(parts[1])
        value = decoded(parts[2], MAX_SIGNATURE_VALUE)
        require(len(value) >= 4, "signature_value")
        identity = (parts[1], value[:4].hex())
        require(identity not in seen, "signature_duplicate")
        seen.add(identity)
        key = configured.get(identity)
        if key is None:
            ignored += 1
            continue
        timestamp = None
        message = body
        payload = value[4:]
        require(len(payload) == (64 if key["type"] == 1 else 72), "signature_length")
        if key["type"] == 4:
            timestamp = int.from_bytes(payload[:8], "big")
            message = b"cosignature/v1\ntime " + str(timestamp).encode("ascii") + b"\n" + body
            payload = payload[8:]
        try:
            Ed25519PublicKey.from_public_bytes(key["key"]).verify(payload, message)
        except InvalidSignature as exc:
            raise CheckpointInspectionError("signature_invalid") from exc
        verified[identity] = timestamp
    require(len(verified) == len(keys), "required_signature_missing")

    # Checkpoint interpretation follows authentication of all required exact-body signatures.
    fields = body[:-1].decode("utf-8").split("\n")
    require(len(fields) == 3 and all(fields), "checkpoint_structure")
    origin, size_text, root_text = fields
    name(origin)
    require(origin == expected_origin, "origin_mismatch")
    require(re.fullmatch(r"0|[1-9][0-9]{0,19}", size_text) is not None, "tree_size")
    tree_size = int(size_text)
    require(tree_size <= MAX_UINT64, "tree_size")
    root = decoded(root_text, 32)
    require(len(root) == 32, "root_size")
    require(tree_size != 0 or root == hashlib.sha256(b"").digest(), "empty_tree_root")
    return {
        "schema": "etzio.offline-native-checkpoint-inspection.v1",
        "input_sha256": hashlib.sha256(wire).hexdigest(),
        "input_size_bytes": len(wire),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "expected_origin": expected_origin,
        "origin": origin,
        "tree_size": tree_size,
        "root_sha256_hex": root.hex(),
        "required_signatures": [
            {
                "name": key["name"], "key_id": key["id"], "signature_type": key["type"],
                "verifier_sha256": hashlib.sha256(key["wire"]).hexdigest(),
                "public_key_sha256": hashlib.sha256(key["key"]).hexdigest(),
                "signature_valid": True, "timestamp_claim": verified[(key["name"], key["id"])],
            }
            for key in keys
        ],
        "ignored_signature_count": ignored,
        "provider_admitted": False,
        "independent_administration_established": False,
        "clock_qualified": False,
        "inclusion_checked": False,
        "consistency_checked": False,
        "latest_head_authority": False,
        "kernel_authority": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("note", type=Path)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--log-vkey", required=True)
    parser.add_argument("--witness-vkey", action="append", default=[])
    args = parser.parse_args(argv)
    try:
        with args.note.open("rb") as stream:
            wire = stream.read(MAX_NOTE + 1)
        report = inspect_checkpoint(
            wire, expected_origin=args.origin, log_vkey=args.log_vkey, witness_vkeys=tuple(args.witness_vkey)
        )
    except (OSError, CheckpointInspectionError) as exc:
        print(f"checkpoint inspection refused: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
