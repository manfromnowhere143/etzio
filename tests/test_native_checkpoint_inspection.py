"""Owned checkpoint controls; fixture signing is independent of inspector encoding."""

import base64
import hashlib
import json
import socket
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import inspect_native_checkpoint as inspect

ORIGIN = "owned.example/log"
ROOT = hashlib.sha256(b"owned root").digest()


def b64(wire):
    return base64.b64encode(wire).decode("ascii")


def key(label, kind, *, seed=None, raw=None):
    private = Ed25519PrivateKey.from_private_bytes(hashlib.sha256((seed or label).encode()).digest())
    public = raw if raw is not None else private.public_key().public_bytes_raw()
    material = bytes([kind]) + public
    identity = hashlib.sha256(label.encode() + b"\n" + material).digest()[:4]
    return label, kind, private, identity, label + "+" + identity.hex() + "+" + b64(material)


LOG = key("owned-log", 1)
WITNESS = key("owned-witness", 4)


def body(*, origin=ORIGIN, size="1", root=ROOT):
    return f"{origin}\n{size}\n{b64(root)}\n".encode()


def line(signer, content, *, timestamp=7, domain=b"cosignature/v1\ntime "):
    label, kind, private, identity, _ = signer
    if kind == 4:
        signature = timestamp.to_bytes(8, "big") + private.sign(domain + str(timestamp).encode() + b"\n" + content)
    else:
        signature = private.sign(content)
    return f"— {label} {b64(identity + signature)}\n".encode()


def note(content=None, signers=(LOG, WITNESS), *, timestamp=7):
    content = body() if content is None else content
    return content + b"\n" + b"".join(line(signer, content, timestamp=timestamp) for signer in signers)


def check(wire=None, *, origin=ORIGIN, log=LOG, witnesses=(WITNESS,)):
    return inspect.inspect_checkpoint(
        note() if wire is None else wire, expected_origin=origin,
        log_vkey=log[4], witness_vkeys=tuple(witness[4] for witness in witnesses),
    )


def refuses(wire, reason, **kwargs):
    with pytest.raises(inspect.CheckpointInspectionError) as error:
        check(wire, **kwargs)
    assert error.value.reason_code == reason


def unknown(label="unknown", identity=b"\x00" * 4, payload=b""):
    return f"— {label} {b64(identity + payload)}\n".encode()


def test_exact_replay_offline_and_no_authority(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("inspection attempted an external operation")
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    result = check()
    assert result == check()
    assert result["input_sha256"] == hashlib.sha256(note()).hexdigest()
    assert result["body_sha256"] == hashlib.sha256(body()).hexdigest()
    assert result["tree_size"] == 1
    assert result["root_sha256_hex"] == ROOT.hex()
    assert [row["timestamp_claim"] for row in result["required_signatures"]] == [None, 7]
    assert result["required_signatures"][1]["verifier_sha256"] == hashlib.sha256(WITNESS[4].encode()).hexdigest()
    assert all(result[flag] is False for flag in (
        "provider_admitted", "independent_administration_established", "clock_qualified",
        "inclusion_checked", "consistency_checked", "latest_head_authority", "kernel_authority",
    ))


@pytest.mark.parametrize("timestamp", [0, 1, 2**64 - 1])
def test_historical_and_extreme_timestamps_are_claims_only(timestamp):
    result = check(note(timestamp=timestamp))
    assert result["required_signatures"][1]["timestamp_claim"] == timestamp
    assert result["clock_qualified"] is False
    assert result["latest_head_authority"] is False


def test_validly_signed_conflicting_roots_do_not_establish_consistency():
    first, second = check(), check(note(body(root=b"x" * 32)))
    assert first["tree_size"] == second["tree_size"]
    assert first["root_sha256_hex"] != second["root_sha256_hex"]
    assert first["consistency_checked"] is second["consistency_checked"] is False


@pytest.mark.parametrize("which", [0, 1])
def test_changed_signature(which):
    lines = note().splitlines(keepends=True)
    prefix, encoded = lines[4 + which].rsplit(b" ", 1)
    value = base64.b64decode(encoded)
    lines[4 + which] = prefix + b" " + b64(value[:-1] + bytes([value[-1] ^ 1])).encode() + b"\n"
    refuses(b"".join(lines), "signature_invalid")


def test_body_authentication_precedes_interpretation():
    refuses(note().replace(b"\n1\n", b"\nnot-a-size\n"), "signature_invalid")


def test_changed_timestamp():
    signed_line = line(WITNESS, body())
    value = base64.b64decode(signed_line.split(b" ")[2])
    changed = unknown(WITNESS[0], value[:4], b"\x00" * 8 + value[12:])
    refuses(body() + b"\n" + line(LOG, body()) + changed, "signature_invalid")


@pytest.mark.parametrize("domain", [b"", b"cosignature/v2\ntime ", b"cosignature/v1\ntime 0"])
def test_wrong_cosignature_domain(domain):
    refuses(body() + b"\n" + line(LOG, body()) + line(WITNESS, body(), domain=domain), "signature_invalid")


def test_expected_origin_is_exact():
    refuses(note(), "origin_mismatch", origin="Owned.example/log")


def test_wrong_pin_does_not_satisfy_required_roster():
    refuses(note(), "required_signature_missing", log=key(LOG[0], 1, seed="different"))


@pytest.mark.parametrize("signers", [(LOG,), (WITNESS,)])
def test_missing_required_signature(signers):
    refuses(note(signers=signers), "required_signature_missing")


@pytest.mark.parametrize("label,identity", [(LOG[0], b"\x00" * 4), ("different", LOG[3]), ("different", b"\x00" * 4)])
def test_unknown_tuples_ignored_and_never_replace_required(label, identity):
    extra = unknown(label, identity)
    assert check(note() + extra)["ignored_signature_count"] == 1
    refuses(note(signers=(WITNESS,)) + extra, "required_signature_missing")


def test_matching_tuple_forgery_has_no_unknown_fallback():
    forged = unknown(LOG[0], LOG[3], key("attacker", 1)[2].sign(body()))
    refuses(body() + b"\n" + forged + line(WITNESS, body()) + unknown(), "signature_invalid")


@pytest.mark.parametrize("extra", [line(LOG, body()), line(WITNESS, body()), unknown() + unknown()])
def test_duplicate_signature_tuples(extra):
    refuses(note() + extra, "signature_duplicate")


def test_duplicate_roster_names():
    refuses(note(), "roster_name_reuse", witnesses=(WITNESS, WITNESS))


@pytest.mark.parametrize("witnesses", [
    (WITNESS, key("renamed", 4, seed=WITNESS[0])), (key("different-role", 4, seed=LOG[0]),),
])
def test_reused_roster_public_keys(witnesses):
    refuses(note(), "roster_key_reuse", witnesses=witnesses)


@pytest.mark.parametrize("kind", [0, 2, 4, 6, 255])
def test_wrong_log_algorithm(kind):
    refuses(note(), "verifier_type", log=key("wrong-type", kind))


@pytest.mark.parametrize("kind", [0, 1, 2, 6, 255])
def test_wrong_witness_algorithm(kind):
    refuses(note(), "verifier_type", witnesses=(key("wrong-type", kind),))


@pytest.mark.parametrize("raw", [b"\x00" * 32, b"\x01" + b"\x00" * 31, b"\xff" * 32])
def test_degenerate_public_key(raw):
    refuses(note(), "verifier_point", log=key("bad-point", 1, raw=raw))


@pytest.mark.parametrize("replacement,reason", [
    ("owned-log+00000000+" + LOG[4].split("+", 2)[2], "verifier_id"),
    (LOG[4].replace(LOG[3].hex(), LOG[3].hex().upper()), "verifier_format"),
    (LOG[4] + "=", "base64_bound"), ("x" * 513, "verifier_bound"),
    ("é" * 257, "verifier_bound"), ("x" * 512, "verifier_format"),
    ("\ud800", "verifier_bound"), ("", "verifier_bound"), (None, "verifier_bound"),
])
def test_verifier_wire_refusals(replacement, reason):
    refuses(note(), reason, log=(*LOG[:4], replacement))


@pytest.mark.parametrize("wire,reason", [
    (b"", "note_bound"), (bytearray(note()), "note_bound"), (b"x" * (128 * 1024 + 1), "note_bound"),
    (note() + b"\xff", "note_utf8"), (note().replace(b"\n", b"\r\n"), "note_control"),
    (note().replace(b"owned-log", b"owned\tlog"), "note_control"),
    (note()[:-1], "note_framing"), (note() + b"\n", "note_framing"),
    (note().replace(b"\n\n", b"\n"), "note_framing"),
    (note().replace("—".encode(), b"-"), "signature_framing"),
    (note().replace(b"owned-log ", b"owned-log  "), "signature_framing"),
    (note().replace(b"owned-log ", "owned\u00a0log ".encode()), "name"),
    (note() + b"\xe2\x80\xa8", "note_framing"),
    (body() + b"\n", "signature_count"),
])
def test_note_framing_and_type(wire, reason):
    refuses(wire, reason)


@pytest.mark.parametrize("origin", ["has space", "has+plus", "a\u2028b", "\ud800", "", "x" * 256, "é" * 128])
def test_invalid_expected_origin(origin):
    refuses(note(), "name", origin=origin)


def test_maximum_utf8_name_and_no_normalization():
    origin = "é" * 127 + "x"
    assert check(note(body(origin=origin)), origin=origin)["origin"] == origin
    refuses(note(body(origin="é")), "origin_mismatch", origin="e\u0301")


@pytest.mark.parametrize("content,reason", [
    (body() + b"extension\n", "checkpoint_structure"),
    (b"one\ntwo\n", "checkpoint_structure"), (body(origin="has space"), "name"),
    (body(size="01"), "tree_size"), (body(size="-1"), "tree_size"),
    (body(size="+1"), "tree_size"), (body(size="1.0"), "tree_size"),
    (body(size="１"), "tree_size"), (body(size="1" * 10000), "tree_size"),
    (body(size=str(2**64)), "tree_size"), (body(root=b"x" * 31), "root_size"),
    (body(root=b"x" * 33), "base64_bound"), (body(size="0"), "empty_tree_root"),
])
def test_authenticated_checkpoint_field_refusals(content, reason):
    refuses(note(content), reason)


@pytest.mark.parametrize("size,root", [("0", hashlib.sha256(b"").digest()), (str(2**64 - 1), ROOT)])
def test_unsigned_size_boundaries(size, root):
    assert check(note(body(size=size, root=root)))["tree_size"] == int(size)


def test_noncanonical_root_pad_bits():
    encoded = b64(ROOT)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    alias = encoded[:-2] + alphabet[alphabet.index(encoded[-2]) + 1] + "="
    assert base64.b64decode(alias) == ROOT
    refuses(note(body().replace(encoded.encode(), alias.encode())), "base64_canonical")


@pytest.mark.parametrize("value,reason", [("!!!!", "base64"), ("é", "base64"), ("AAA=", "signature_value"),
                                         ("AAAAAB==", "base64_canonical")])
def test_signature_base64(value, reason):
    refuses(note() + f"— unknown {value}\n".encode(), reason)


@pytest.mark.parametrize("signer,length", [(LOG, 63), (LOG, 65), (WITNESS, 71), (WITNESS, 73)])
def test_known_signature_lengths(signer, length):
    other = WITNESS if signer == LOG else LOG
    refuses(body() + b"\n" + line(other, body()) + unknown(signer[0], signer[3], b"x" * length), "signature_length")


def test_decoded_signature_value_limit():
    assert check(note() + unknown(payload=b"x" * 8188))["ignored_signature_count"] == 1
    refuses(note() + unknown(payload=b"x" * 8189), "base64_bound")


def test_signature_line_count_limit():
    wire = note() + b"".join(unknown(f"unknown-{i}") for i in range(30))
    assert check(wire)["ignored_signature_count"] == 30
    refuses(wire + unknown("one-too-many"), "signature_count")


def test_complete_roster_limit():
    witnesses = tuple(key(f"witness-{i}", 4) for i in range(15))
    assert len(check(note(signers=(LOG, *witnesses)), witnesses=witnesses)["required_signatures"]) == 16
    refuses(note(), "roster_bound", witnesses=(*witnesses, key("too-many", 4)))


def test_mutable_roster_refused():
    with pytest.raises(inspect.CheckpointInspectionError, match="roster_bound"):
        inspect.inspect_checkpoint(note(), expected_origin=ORIGIN, log_vkey=LOG[4], witness_vkeys=[WITNESS[4]])


def test_log_only_is_explicitly_supported():
    assert len(check(note(signers=(LOG,)), witnesses=())["required_signatures"]) == 1


def test_note_limit_checked_before_decode(monkeypatch):
    monkeypatch.setattr(inspect, "MAX_NOTE", len(note()))
    assert check()["input_size_bytes"] == len(note())
    monkeypatch.setattr(inspect, "MAX_NOTE", len(note()) - 1)
    refuses(note(), "note_bound")


def test_actual_note_ceiling_accepts_exact_limit():
    prefix = note() + b"".join(unknown(f"large-{i}", payload=b"x" * 8188) for i in range(11))
    for name_length in range(1, 5):
        remaining = inspect.MAX_NOTE - len(prefix) - len(unknown("z" * name_length))
        if remaining % 4 == 0:
            payload = b"x" * (remaining // 4 * 3)
            wire = prefix + unknown("z" * name_length, payload=payload)
            assert len(wire) == inspect.MAX_NOTE
            assert check(wire)["ignored_signature_count"] == 12
            refuses(wire + b"x", "note_bound")
            return
    pytest.fail("could not construct exact bound fixture")


def test_signature_name_utf8_limit():
    assert check(note() + unknown("é" * 127 + "x"))["ignored_signature_count"] == 1
    refuses(note() + unknown("é" * 128), "name")


def test_signature_order_is_bound_but_not_authority():
    changed = body() + b"\n" + line(WITNESS, body()) + line(LOG, body())
    first, second = check(), check(changed)
    assert first["required_signatures"] == second["required_signatures"]
    assert first["input_sha256"] != second["input_sha256"]


def test_cli_success_and_refusal(tmp_path, capsys):
    path = tmp_path / "owned.note"
    path.write_bytes(note())
    argv = [str(path), "--origin", ORIGIN, "--log-vkey", LOG[4], "--witness-vkey", WITNESS[4]]
    assert inspect.main(argv) == 0
    output = capsys.readouterr()
    assert json.loads(output.out) == check()
    path.write_bytes(b"x" * (inspect.MAX_NOTE + 1))
    assert inspect.main(argv) == 2
    output = capsys.readouterr()
    assert not output.out and "note_bound" in output.err
    path.unlink()
    assert inspect.main(argv) == 2
    assert not capsys.readouterr().out


def test_direct_script_entry(tmp_path):
    path = tmp_path / "owned.note"
    path.write_bytes(note())
    result = subprocess.run([
        sys.executable, "scripts/inspect_native_checkpoint.py", str(path), "--origin", ORIGIN,
        "--log-vkey", LOG[4], "--witness-vkey", WITNESS[4],
    ], capture_output=True, check=True)
    assert json.loads(result.stdout) == check()
