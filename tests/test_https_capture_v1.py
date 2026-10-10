"""ADR-0024: owned loopback TLS, bounded processes, byte custody and HTTP refusals."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from etzio.protocol import canonical_dumps, strict_loads
from etzio.qualification import acquisition_custody_v1 as custody
from etzio.qualification import https_capture_v1 as capture

REQUEST = b"owned synthetic timestamp request fixture"
BODY = b"opaque timestamp fixture\x00\xff"
REF = "sha256:" + "a" * 64
HEAD = b"HTTP/1.1 200 OK\r\nContent-Type: application/timestamp-reply\r\n"
REPLY = HEAD + b"Content-Length: " + str(len(BODY)).encode() + b"\r\n\r\n" + BODY


@pytest.fixture(scope="module")
def tls_material(tmp_path_factory):
    directory = tmp_path_factory.mktemp("capture-tls")
    key = ec.derive_private_key(9024, ec.SECP256R1())  # Public fixture key, no authority.
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture.invalid")])
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(9024).not_valid_before(datetime(2020, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2100, 1, 1, tzinfo=UTC))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("fixture.invalid")]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM)
    (directory / "cert.pem").write_bytes(pem)
    (directory / "key.pem").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
    ))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(directory / "cert.pem", directory / "key.pem")
    context.set_alpn_protocols(["http/1.1"])
    return pem, context


@contextmanager
def _server(tls_material, reply=REPLY, *, mode="normal"):
    _, context = tls_material
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    listener.settimeout(0.05)
    stop = threading.Event()
    record = {"connections": 0, "requests": [], "alpn": []}

    def serve():
        while not stop.is_set():
            try:
                raw, _ = listener.accept()
            except TimeoutError:
                continue
            record["connections"] += 1
            raw.settimeout(2)
            try:
                with context.wrap_socket(raw, server_side=True) as stream:
                    record["alpn"].append(stream.selected_alpn_protocol())
                    wire = b""
                    while b"\r\n\r\n" not in wire:
                        chunk = stream.recv(4096)
                        if not chunk:
                            raise ConnectionError("fixture client closed before headers")
                        wire += chunk
                        assert len(wire) <= 20000
                    head, body = wire.split(b"\r\n\r\n", 1)
                    size = int(next(
                        row.split(b":", 1)[1] for row in head.split(b"\r\n") if row.startswith(b"Content-Length:")
                    ))
                    while len(body) < size:
                        chunk = stream.recv(4096)
                        if not chunk:
                            raise ConnectionError("fixture client closed before body")
                        body += chunk
                    record["requests"].append(head + b"\r\n\r\n" + body)
                    if mode == "stall":
                        stop.wait(2)
                    elif mode == "trickle":
                        for byte in reply:
                            if stop.wait(0.03):
                                break
                            stream.sendall(bytes([byte]))
                    else:
                        stream.sendall(reply)
                    if mode != "ragged":
                        stream.unwrap().close()
            except (OSError, ssl.SSLError):
                raw.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1], record
    finally:
        stop.set()
        thread.join(3)
        listener.close()
        assert not thread.is_alive()


def _plan(ca, port=443, **changes):
    fields = dict(
        surface="repository_fixture", service_id="fixture.tsa", endpoint=f"https://fixture.invalid:{port}/tsr",
        ipv4="127.0.0.1", terms_reference_id=REF, assumptions_reference_id=REF,
        response_limit_bytes=65536, timeout_ms=5000,
    )
    fields.update(changes)
    return capture.plan_wire(request=REQUEST, ca_pem=ca, **fields)


def _journal(tmp_path, plan, *, request=REQUEST, **changes):
    value = strict_loads(plan)
    fields = dict(
        service_id=value["service_id"], endpoint=value["endpoint"], request=request,
        scope_reference_id=capture.plan_id(plan), terms_reference_id=value["terms_reference_id"],
        response_limit_bytes=value["response_limit_bytes"],
    )
    fields.update(changes)
    return custody.AcquisitionJournal.create(tmp_path / "capture.sqlite3", custody.intent_wire(**fields), request)


def _acquire(journal, plan, ca):
    return capture.capture_once(journal, plan, ca, acknowledged_plan_id=capture.plan_id(plan))


def test_real_tls_exact_request_cold_custody_and_no_second_dispatch(tmp_path, tls_material):
    ca, _ = tls_material
    with _server(tls_material) as (port, record):
        plan = _plan(ca, port)
        journal = _journal(tmp_path, plan)
        state = _acquire(journal, plan, ca)
        assert state.status == "response_captured" and state.response_wire == REPLY
        assert capture.timestamp_body(state.response_wire) == BODY
        assert record["connections"] == 1 and record["alpn"] == ["http/1.1"]
        assert record["requests"] == [
            f"POST /tsr HTTP/1.1\r\nHost: fixture.invalid:{port}\r\n".encode()
            + b"Content-Type: application/timestamp-query\r\nAccept: application/timestamp-reply\r\n"
            + b"Accept-Encoding: identity\r\nConnection: close\r\nContent-Length: "
            + str(len(REQUEST)).encode() + b"\r\n\r\n" + REQUEST
        ]
        with pytest.raises(custody.CustodyError, match="attempt_already_spent"):
            _acquire(custody.AcquisitionJournal(journal.path), plan, ca)
        assert record["connections"] == 1
    assert custody.AcquisitionJournal(journal.path).inspect() == state


@pytest.mark.parametrize("partial", [b"", b"POST /tsr HTTP/1.1\r\nContent-Length: 4\r\n\r\nab"])
def test_owned_server_recovers_after_client_disconnect(tmp_path, tls_material, partial):
    ca, _ = tls_material
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=ca.decode())
    with _server(tls_material) as (port, record):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw:
            raw.settimeout(2)
            raw.connect(("127.0.0.1", port))
            with context.wrap_socket(raw, server_hostname="fixture.invalid") as stream:
                stream.sendall(partial)
        plan = _plan(ca, port)
        assert _acquire(_journal(tmp_path, plan), plan, ca).status == "response_captured"
        assert record["connections"] == 2 and len(record["requests"]) == 1


@pytest.mark.parametrize("reply,reason", [
    (b"HTTP/1.1 302 Found\r\nLocation: https://elsewhere.invalid/\r\n\r\nx", "http_status"),
    (b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic\r\n\r\nx", "http_status"),
    (REPLY.replace(b"application/timestamp-reply", b"text/html"), "http_media_type"),
    (b"not HTTP", "http_header_size"),
])
def test_invalid_http_retained_before_interpretation_without_followup(tmp_path, tls_material, reply, reason):
    ca, _ = tls_material
    with _server(tls_material, reply) as (port, record):
        plan = _plan(ca, port)
        journal = _journal(tmp_path, plan)
        state = _acquire(journal, plan, ca)
        assert state.status == "response_captured" and state.response_wire == reply
        with pytest.raises(capture.CaptureError, match=reason):
            capture.timestamp_body(state.response_wire)
        assert record["connections"] == 1 and len(record["requests"]) == 1
        assert journal.inspect() == state


@pytest.mark.parametrize("mode,reason", [("stall", "timeout"), ("trickle", "timeout"), ("ragged", "transport_error")])
def test_timeout_trickle_and_truncated_tls_never_rearm(tmp_path, tls_material, mode, reason):
    ca, _ = tls_material
    with _server(tls_material, mode=mode) as (port, record):
        plan = _plan(ca, port, timeout_ms=650)
        journal = _journal(tmp_path, plan)
        start = time.monotonic()
        state = _acquire(journal, plan, ca)
        assert time.monotonic() - start < 3
        assert state.status == "capture_indeterminate"
        assert strict_loads(state.outcome_wire)["reason"] == reason
        assert state.response_wire == b""
        with pytest.raises(custody.CustodyError, match="attempt_already_spent"):
            _acquire(journal, plan, ca)
        assert record["connections"] == 1


@pytest.mark.parametrize("length,kind", [(65536, "response_captured"), (65537, "capture_indeterminate")])
def test_raw_response_cap_includes_headers(tmp_path, tls_material, length, kind):
    ca, _ = tls_material
    reply = HEAD + b"\r\n" + b"x" * (length - len(HEAD) - 2)
    with _server(tls_material, reply) as (port, _):
        plan = _plan(ca, port)
        state = _acquire(_journal(tmp_path, plan), plan, ca)
    assert state.status == kind
    if kind == "response_captured":
        assert state.response_wire == reply
    else:
        assert strict_loads(state.outcome_wire)["reason"] == "body_limit"


def test_tls_hostname_mismatch_sends_no_http(tmp_path, tls_material):
    ca, _ = tls_material
    with _server(tls_material) as (port, record):
        plan = _plan(ca, port, endpoint=f"https://wrong.invalid:{port}/tsr")
        state = _acquire(_journal(tmp_path, plan), plan, ca)
        assert state.status == "capture_indeterminate" and record["requests"] == []
        assert strict_loads(state.outcome_wire)["reason"] == "transport_error"


def test_untrusted_tls_root_sends_no_http(tmp_path, tls_material):
    key = ec.derive_private_key(9025, ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "different fixture root")])
    ca = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(9025).not_valid_before(datetime(2020, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2100, 1, 1, tzinfo=UTC))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)
    )
    with _server(tls_material) as (port, record):
        plan = _plan(ca, port)
        state = _acquire(_journal(tmp_path, plan), plan, ca)
        assert strict_loads(state.outcome_wire)["reason"] == "transport_error"
        assert record["requests"] == []


def test_competing_controllers_dispatch_only_once(tmp_path, tls_material, monkeypatch):
    ca, _ = tls_material
    original = custody.AcquisitionJournal.debit
    barrier = threading.Barrier(2)

    def debit(self):
        barrier.wait(timeout=3)
        return original(self)

    monkeypatch.setattr(custody.AcquisitionJournal, "debit", debit)
    with _server(tls_material) as (port, record):
        plan = _plan(ca, port)
        journal = _journal(tmp_path, plan)

        def attempt():
            try:
                return _acquire(custody.AcquisitionJournal(journal.path), plan, ca).status
            except (custody.CustodyError, sqlite3.OperationalError) as error:
                return str(error)

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: attempt(), range(2)))
        assert results.count("response_captured") == 1
        assert record["connections"] == 1 and len(record["requests"]) == 1


def test_lost_capture_acknowledgement_preserves_cold_response(tmp_path, tls_material, monkeypatch):
    ca, _ = tls_material
    plan = _plan(ca)
    journal = _journal(tmp_path, plan)
    monkeypatch.setattr(capture, "_supervise", lambda *a: capture._decode_worker_result(b"R" + REPLY, 65536))
    original = custody.AcquisitionJournal.retain_response

    def lost(self, raw):
        original(self, raw)
        raise sqlite3.OperationalError("capture acknowledgement lost")

    monkeypatch.setattr(custody.AcquisitionJournal, "retain_response", lost)
    with pytest.raises(sqlite3.OperationalError, match="acknowledgement lost"):
        _acquire(journal, plan, ca)
    state = custody.AcquisitionJournal(journal.path).inspect()
    assert state.status == "response_captured" and state.response_wire == REPLY
    with pytest.raises(custody.CustodyError, match="attempt_already_spent"):
        _acquire(journal, plan, ca)


def test_no_ambient_proxy_ca_keylog_or_dns(tmp_path, tls_material, monkeypatch):
    ca, _ = tls_material
    for name, value in {
        "HTTPS_PROXY": "http://127.0.0.1:1", "ALL_PROXY": "http://127.0.0.1:1",
        "SSL_CERT_FILE": str(tmp_path / "missing"), "SSLKEYLOGFILE": str(tmp_path / "keylog"),
        "PYTHONPATH": str(tmp_path), "GOOGLE_APPLICATION_CREDENTIALS": "fixture-no-real-credential",
    }.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: pytest.fail("controller DNS"))
    original = capture.subprocess.Popen
    observed = []

    def spawn(*args, **kwargs):
        observed.append(kwargs)
        return original(*args, **kwargs)

    monkeypatch.setattr(capture.subprocess, "Popen", spawn)
    with _server(tls_material) as (port, _):
        plan = _plan(ca, port)
        assert _acquire(_journal(tmp_path, plan), plan, ca).status == "response_captured"
    assert observed[0]["env"] == {"LANG": "C", "OPENSSL_CONF": os.devnull}
    assert observed[0]["close_fds"] and observed[0]["start_new_session"]
    assert not (tmp_path / "keylog").exists()
    # The real request used fixture.invalid (never publicly resolvable), pinned to loopback.


@pytest.mark.parametrize("ack", [None, "", REF, 1])
def test_unacknowledged_plan_cannot_debit_or_spawn(tmp_path, tls_material, monkeypatch, ack):
    ca, _ = tls_material
    plan = _plan(ca)
    journal = _journal(tmp_path, plan)
    monkeypatch.setattr(capture, "_supervise", lambda *a: pytest.fail("collector invoked"))
    with pytest.raises(capture.CaptureError, match="plan_not_acknowledged"):
        capture.capture_once(journal, plan, ca, acknowledged_plan_id=ack)
    assert journal.inspect().status == "prepared"


@pytest.mark.parametrize("changes", [
    {"request": b"changed"}, {"service_id": "other.tsa"}, {"endpoint": "https://other.invalid/tsr"},
    {"scope_reference_id": REF}, {"terms_reference_id": "sha256:" + "b" * 64}, {"response_limit_bytes": 8},
])
def test_journal_binding_refuses_before_debit(tmp_path, tls_material, changes):
    ca, _ = tls_material
    plan = _plan(ca)
    journal = _journal(tmp_path, plan, **changes)
    with pytest.raises(capture.CaptureError, match="binding"):
        _acquire(journal, plan, ca)
    assert journal.inspect().status == "prepared"


@pytest.mark.parametrize("kind", ["runtime", "ca", "ca_encoding"])
def test_runtime_and_ca_refuse_before_debit(tmp_path, tls_material, kind):
    ca, _ = tls_material
    if kind == "ca_encoding":
        ca = b"not a certificate"
    plan = _plan(ca)
    if kind == "runtime":
        value = strict_loads(plan)
        value["runtime_id"] = REF
        plan = canonical_dumps(value)
    journal = _journal(tmp_path, plan)
    if kind == "ca":
        ca += b"\n"
    with pytest.raises(capture.CaptureError, match=kind):
        _acquire(journal, plan, ca)
    assert journal.inspect().status == "prepared"


@pytest.mark.parametrize("changes,reason", [
    ({"surface": "production"}, "plan_surface"),
    ({"ipv4": "127.0.0.2"}, "fixture_address"),
    ({"ipv4": "::1"}, "plan_address"),
    ({"ipv4": 2130706433}, "plan_address"),
    ({"surface": "external_discovery", "ipv4": "127.0.0.1"}, "external_address"),
    ({"surface": "external_discovery", "ipv4": "169.254.169.254"}, "external_address"),
    ({"surface": "external_discovery", "ipv4": "224.1.2.3"}, "external_address"),
    ({"endpoint": "https://fixture.invalid:65536/tsr"}, "plan_endpoint"),
    ({"endpoint": "https://u:p@fixture.invalid/tsr"}, "plan_endpoint"),
    ({"endpoint": "https://fixture.invalid/tsr?query=yes"}, "plan_endpoint"),
    ({"endpoint": "https://fixture.invalid/tsr#fragment"}, "plan_endpoint"),
    ({"endpoint": "https://fixture.invalid/%0d%0a"}, "plan_endpoint"),
    ({"endpoint": "http://fixture.invalid/tsr"}, "plan_endpoint"),
    ({"timeout_ms": True}, "plan_limit"), ({"timeout_ms": 30001}, "plan_limit"),
    ({"response_limit_bytes": 65537}, "plan_limit"), ({"request_size": 0}, "plan_limit"),
    ({"terms_reference_id": "unbound"}, "plan_reference"), ({"ca_sha256": "bad"}, "plan_digest"),
    ({"service_id": "x"}, "plan_service"),
])
def test_closed_plan_controls(tls_material, changes, reason):
    value = strict_loads(_plan(tls_material[0]))
    value.update(changes)
    with pytest.raises(capture.CaptureError, match=reason):
        capture.plan_id(canonical_dumps(value))


@pytest.mark.parametrize("kind", ["extra", "missing", "noncanonical", "duplicate", "oversize", "schema"])
def test_plan_wire_shape(tls_material, kind):
    wire = _plan(tls_material[0])
    value = strict_loads(wire)
    if kind == "extra":
        value["extra"] = True
    elif kind == "missing":
        del value["surface"]
    elif kind == "schema":
        value["schema"] += ".unknown"
    wire = canonical_dumps(value)
    if kind == "noncanonical":
        wire += b"\n"
    elif kind == "duplicate":
        wire = b'{"surface":"repository_fixture",' + wire[1:]
    elif kind == "oversize":
        wire += b" " * capture.MAX_PLAN
    with pytest.raises(capture.CaptureError):
        capture.plan_id(wire)


def test_lost_debit_acknowledgement_never_spawns(tmp_path, tls_material, monkeypatch):
    ca, _ = tls_material
    plan = _plan(ca)
    journal = _journal(tmp_path, plan)
    original = custody.AcquisitionJournal.debit

    def lost(self):
        original(self)
        raise sqlite3.OperationalError("lost commit acknowledgement")

    monkeypatch.setattr(custody.AcquisitionJournal, "debit", lost)
    monkeypatch.setattr(capture, "_supervise", lambda *a: pytest.fail("collector invoked"))
    with pytest.raises(sqlite3.OperationalError, match="lost commit"):
        _acquire(journal, plan, ca)
    assert journal.inspect().status == "attempt_indeterminate"


def test_capture_store_failure_keeps_domain_and_spent_state(tmp_path, tls_material, monkeypatch):
    ca, _ = tls_material
    plan = _plan(ca)
    journal = _journal(tmp_path, plan)
    monkeypatch.setattr(capture, "_supervise", lambda *a: capture._decode_worker_result(b"R" + REPLY, 65536))

    def failed(*args):
        raise sqlite3.OperationalError("retention failed")

    monkeypatch.setattr(custody.AcquisitionJournal, "retain_response", failed)
    with pytest.raises(sqlite3.OperationalError, match="retention failed"):
        _acquire(journal, plan, ca)
    assert journal.inspect().status == "attempt_indeterminate"


def test_operator_interrupt_is_retained_but_reraised(tmp_path, tls_material, monkeypatch):
    ca, _ = tls_material
    plan = _plan(ca)
    journal = _journal(tmp_path, plan)

    def interrupted(*args):
        raise KeyboardInterrupt

    monkeypatch.setattr(capture, "_supervise", interrupted)
    with pytest.raises(KeyboardInterrupt):
        _acquire(journal, plan, ca)
    assert strict_loads(journal.inspect().outcome_wire)["reason"] == "operator_stop"


@pytest.mark.parametrize("program,reason", [
    ("import time; time.sleep(10)", "timeout"),
    ("import os,time; os.close(0); os.close(1); os.close(2); time.sleep(10)", "timeout"),
    ("import sys; sys.stdout.buffer.write(b'R'+b'x'*10000)", "body_limit"),
    ("import sys; sys.stderr.buffer.write(b'x'*10000)", "transport_error"),
    ("import sys; sys.stdout.buffer.write(b'Rreply'); sys.exit(2)", "transport_error"),
    ("import sys; sys.stdout.buffer.write(b'unknown')", "transport_error"),
    ("import sys; sys.stdout.buffer.write(b'T')", "transport_error"),
    ("import sys; sys.stdout.buffer.write(b'B')", "transport_error"),
])
def test_parent_watchdog_pipe_bounds_and_protocol(tmp_path, monkeypatch, program, reason):
    worker = tmp_path / "worker.py"
    worker.write_text(program)
    monkeypatch.setattr(capture, "WORKER", worker)
    original = capture.subprocess.Popen
    children = []

    def spawn(*args, **kwargs):
        child = original(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(capture.subprocess, "Popen", spawn)
    start = time.monotonic()
    result = capture._supervise(b"x" * 500000, 128, 400)
    assert result.reason == reason and result.response == b""
    assert time.monotonic() - start < 3
    assert children and children[0].poll() is not None
    with pytest.raises(ProcessLookupError):
        os.kill(children[0].pid, 0)


@pytest.mark.parametrize("wire,expected", [
    (REPLY, BODY), (HEAD + b"\r\n" + BODY, BODY),
    (HEAD + b"Transfer-Encoding: chunked\r\n\r\n2\r\nab\r\n1\r\nc\r\n0\r\n\r\n", b"abc"),
    (REPLY.replace(b"HTTP/1.1", b"HTTP/1.0"), BODY),
])
def test_offline_http_positive_framing(wire, expected):
    assert capture.timestamp_body(wire) == expected


@pytest.mark.parametrize("wire,reason", [
    (HEAD + b"Content-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\nx", "http_ambiguous_length"),
    (HEAD + b"Content-Length: 1\r\ncontent-length: 1\r\n\r\nx", "http_duplicate_header"),
    (HEAD + b"Content-Length : 1\r\n\r\nx", "http_header"),
    (HEAD + b" folded\r\n\r\nx", "http_header"),
    (HEAD + b"X: a\nb\r\n\r\nx", "http_header"),
    (HEAD + b"Content-Encoding: gzip\r\n\r\nx", "http_content_coding"),
    (HEAD + b"Transfer-Encoding: gzip, chunked\r\n\r\nx", "http_transfer_coding"),
    (b"HTTP/1.0 200 OK\r\nContent-Type: application/timestamp-reply\r\n"
     b"Transfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n", "http_transfer_version"),
    (HEAD + b"Content-Length: 01\r\n\r\nx", "http_content_length"),
    (HEAD + b"Content-Length: 3\r\n\r\nxy", "http_body_length"),
    (HEAD + b"Content-Length: 1\r\n\r\nxy", "http_body_length"),
    (HEAD + b"Content-Length: 0\r\n\r\n", "http_empty_body"),
    (HEAD + b"Transfer-Encoding: chunked\r\n\r\n1;foo=bar\r\nx\r\n0\r\n\r\n", "http_chunk_size"),
    (HEAD + b"Transfer-Encoding: chunked\r\n\r\nFFFFFFFF\r\nx", "http_chunk_body"),
    (HEAD + b"Transfer-Encoding: chunked\r\n\r\n1\r\nxX\n0\r\n\r\n", "http_chunk_body"),
    (HEAD + b"Transfer-Encoding: chunked\r\n\r\n0\r\nX: a\r\n\r\n", "http_trailer_or_extra"),
    (HEAD + b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\nextra", "http_trailer_or_extra"),
    (HEAD + b"Transfer-Encoding: chunked\r\n\r\n" + b"1\r\nx\r\n" * 257 + b"0\r\n\r\n", "http_chunk_count"),
    (HEAD + b"X: " + b"x" * 8192 + b"\r\n\r\nx", "http_header_size"),
    (HEAD + b"".join(f"X-{i}: a\r\n".encode() for i in range(64)) + b"\r\nx", "http_header_count"),
    (b"HTTP/1.1 100 Continue\r\n\r\n" + REPLY, "http_status"),
])
def test_offline_http_refusals(wire, reason):
    with pytest.raises(capture.CaptureError, match=reason):
        capture.timestamp_body(wire)


def test_runtime_identity_changes_when_worker_changes(tmp_path, monkeypatch):
    before = capture.runtime_identity()
    worker = tmp_path / "changed.py"
    worker.write_bytes(capture.WORKER.read_bytes() + b"\n# changed\n")
    monkeypatch.setattr(capture, "WORKER", worker)
    assert capture.runtime_identity() != before


def test_parent_timeout_stops_descendant_holding_output_pipe(tmp_path, monkeypatch):
    marker = tmp_path / "descendant_ticks"
    worker = tmp_path / "descendant_worker.py"
    worker.write_text(
        "import os,time\n"
        "if os.fork():\n    os._exit(0)\n"
        f"with open({str(marker)!r}, 'ab', buffering=0) as output:\n"
        "    for _ in range(100):\n        output.write(b'x')\n        time.sleep(0.02)\n"
    )
    monkeypatch.setattr(capture, "WORKER", worker)
    result = capture._supervise(b"{}", 128, 500)
    assert result.reason == "timeout" and result.response == b""
    assert result.observation.category == "watchdog_timeout"
    captured = marker.read_bytes()
    assert captured
    time.sleep(0.1)
    assert marker.read_bytes() == captured


def test_collector_resource_limits_refuse_file_and_linux_memory_growth(tmp_path):
    code = """
import json, resource, runpy, sys
namespace = runpy.run_path(sys.argv[1])
def probe(packet):
    result = {'cpu': list(resource.getrlimit(resource.RLIMIT_CPU)),
              'core': list(resource.getrlimit(resource.RLIMIT_CORE))}
    try:
        with open(sys.argv[2], 'wb') as stream:
            stream.write(b'x')
            stream.flush()
    except OSError:
        result['file_refused'] = True
    if sys.platform.startswith('linux'):
        try:
            excess = bytearray(600 * 1024 * 1024)
        except MemoryError:
            result['memory_refused'] = True
    return b'R' + json.dumps(result).encode()
namespace['main'].__globals__['collect'] = probe
raise SystemExit(namespace['main']())
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", code, str(capture.WORKER), str(tmp_path / "bounded-file")],
        input=b"{}", capture_output=True, timeout=10, check=False,
    )
    assert result.returncode == 0, result.stderr
    observed = json.loads(result.stdout[1:])
    assert observed["cpu"] == [5, 5] and observed["core"] == [0, 0] and observed["file_refused"]
    if sys.platform.startswith("linux"):
        assert observed["memory_refused"]


def test_start_failure_spends_attempt_and_retains_transport_failure(tmp_path, tls_material, monkeypatch):
    ca, _ = tls_material
    plan = _plan(ca)
    journal = _journal(tmp_path, plan)

    def refused(*a, **k):
        raise OSError("owned fixture start refusal")

    monkeypatch.setattr(capture.subprocess, "Popen", refused)
    result = capture.capture_observed(journal, plan, ca, acknowledged_plan_id=capture.plan_id(plan))
    state = result.state
    assert result.observation == capture.TransportObservation("controller", "launch", "spawn_error")
    assert strict_loads(state.outcome_wire)["reason"] == "transport_error"
    with pytest.raises(custody.CustodyError, match="attempt_already_spent"):
        _acquire(journal, plan, ca)


def _cli(*args):
    return subprocess.run(
        [sys.executable, str(Path(__file__).resolve().parents[1] / "scripts/capture_timestamp_once.py"), *args],
        capture_output=True, text=True, timeout=10, check=False,
    )


def test_cli_missing_ack_cannot_consume_budget(tmp_path, tls_material):
    plan = _plan(tls_material[0])
    journal = _journal(tmp_path, plan)
    result = _cli("--capture", "--journal", str(journal.path))
    assert result.returncode == 2 and "capture requires" in result.stderr
    assert journal.inspect().status == "prepared"


def test_cli_capture_and_networkless_export(tmp_path, tls_material):
    ca, _ = tls_material
    with _server(tls_material) as (port, record):
        plan = _plan(ca, port)
        journal = _journal(tmp_path, plan)
        (tmp_path / "plan.json").write_bytes(plan)
        (tmp_path / "ca.pem").write_bytes(ca)
        result = _cli(
            "--capture", "--journal", str(journal.path), "--plan", str(tmp_path / "plan.json"),
            "--ca", str(tmp_path / "ca.pem"), "--acknowledged-plan-id", capture.plan_id(plan),
        )
        assert result.returncode == 0, result.stderr
        report = json.loads(result.stdout)
        assert report["status"] == "response_captured" and record["connections"] == 1
        assert report["opaque_timestamp_body"] == {"size": len(BODY), "sha256": hashlib.sha256(BODY).hexdigest()}
    output = tmp_path / "body.der"
    result = _cli("--inspect", "--journal", str(journal.path), "--body-output", str(output))
    assert result.returncode == 0, result.stderr
    assert output.read_bytes() == BODY and output.stat().st_mode & 0o777 == 0o600
    retry = _cli("--inspect", "--journal", str(journal.path), "--body-output", str(output))
    assert retry.returncode != 0 and output.read_bytes() == BODY


def test_cli_http_refusal_preserves_raw_and_does_not_export(tmp_path, tls_material):
    plan = _plan(tls_material[0])
    journal = _journal(tmp_path, plan)
    journal.debit()
    journal.retain_response(b"unsupported HTTP fixture")
    result = _cli("--inspect", "--journal", str(journal.path))
    assert result.returncode == 0 and json.loads(result.stdout)["http_refusal"] == "http_header_size"
    output = tmp_path / "absent.der"
    result = _cli("--inspect", "--journal", str(journal.path), "--body-output", str(output))
    assert result.returncode != 0 and not output.exists()
    assert journal.inspect().response_wire == b"unsupported HTTP fixture"


def test_retained_external_proposal_is_byte_bound_and_unaccepted():
    import certifi
    from asn1crypto import tsp

    record = json.loads((Path(__file__).resolve().parents[1]
                         / "docs/evidence/freetsa-discovery-proposal-2026-10-10.json").read_text())
    plan = base64.b64decode(record["plan_wire_base64"], validate=True)
    request = base64.b64decode(record["request_der_base64"], validate=True)
    assumptions = base64.b64decode(record["assumptions_wire_base64"], validate=True)
    assert capture.plan_id(plan) == record["plan_id"] and canonical_dumps(record["plan"]) == plan
    assert canonical_dumps(record["assumptions"]) == assumptions
    assert "sha256:" + hashlib.sha256(assumptions).hexdigest() == record["plan"]["assumptions_reference_id"]
    assert "sha256:" + hashlib.sha256(canonical_dumps(record["runtime_binding_material"])).hexdigest() == (
        record["plan"]["runtime_id"]
    )
    assert hashlib.sha256(request).hexdigest() == record["request_sha256"] == record["plan"]["request_sha256"]
    assert len(request) == record["request_size"] == record["plan"]["request_size"]
    assert hashlib.sha256(Path(certifi.where()).read_bytes()).hexdigest() == record["plan"]["ca_sha256"]
    query = tsp.TimeStampReq.load(request, strict=True)
    assert query.dump() == request and query["cert_req"].native is True
    assert query["req_policy"].native is None
    assert query["nonce"].native == int(record["nonce_hex"], 16)
    assert query["message_imprint"]["hashed_message"].native == hashlib.sha256(record["statement"].encode()).digest()
    assert record["status"] == "proposed_not_accepted" and record["timestamp_protocol_requests"] == 0


@pytest.mark.parametrize("mode,reply,limit,category,received", [
    ("ragged", REPLY, 65536, "tls_eof", len(REPLY)),
    ("normal", b"", 65536, "empty_response", 0),
    ("normal", REPLY, 1, "body_limit", 2),
])
def test_real_failure_diagnostics_preserve_indeterminate_custody(
    tmp_path, tls_material, mode, reply, limit, category, received,
):
    ca, _ = tls_material
    with _server(tls_material, reply=reply, mode=mode) as (port, record):
        plan = _plan(ca, port, response_limit_bytes=limit)
        journal = _journal(tmp_path, plan)
        result = capture.capture_observed(journal, plan, ca, acknowledged_plan_id=capture.plan_id(plan))
        assert result.state.status == "capture_indeterminate" and result.state.response_wire == b""
        assert result.observation == capture.TransportObservation("collector", "response_read", category, received)
        assert result.state == journal.inspect()
        assert result.diagnostic()["attempt_id"] == result.state.attempt_id
        assert result.diagnostic()["plan_id"] == capture.plan_id(plan)
        assert record["connections"] == 1 and len(record["requests"]) == 1
        with pytest.raises(custody.CustodyError, match="attempt_already_spent"):
            capture.capture_observed(journal, plan, ca, acknowledged_plan_id=capture.plan_id(plan))
        assert record["connections"] == 1


def test_real_tls_certificate_failure_is_sanitized_and_bound(tmp_path, tls_material):
    ca, _ = tls_material
    with _server(tls_material) as (port, record):
        plan = _plan(ca, port, endpoint=f"https://wrong.invalid:{port}/tsr")
        journal = _journal(tmp_path, plan)
        result = capture.capture_observed(journal, plan, ca, acknowledged_plan_id=capture.plan_id(plan))
        assert result.state.status == "capture_indeterminate" and record["requests"] == []
        observation = result.observation
        assert (observation.source, observation.phase, observation.category) == (
            "collector", "tls_handshake", "tls_verification",
        )
        assert observation.received_bytes == 0 and 1 <= observation.tls_verify_code <= 0x7FFFFFFF
        diagnostic = json.dumps(result.diagnostic())
        assert "wrong.invalid" not in diagnostic and "certificate verify failed" not in diagnostic.lower()
        assert result.diagnostic()["intent_id"] == result.state.intent_id
        assert result.diagnostic()["authority"] == "advisory_local_observation_only"


def test_real_refused_connection_reports_no_response_bytes(tmp_path, tls_material):
    ca, _ = tls_material
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserved:
        reserved.bind(("127.0.0.1", 0))
        port = reserved.getsockname()[1]
    # macOS can silently drop SYNs to a bound, non-listening socket. Close it first.
    plan = _plan(ca, port)
    journal = _journal(tmp_path, plan)
    result = capture.capture_observed(journal, plan, ca, acknowledged_plan_id=capture.plan_id(plan))
    assert result.observation == capture.TransportObservation("collector", "connect", "connection_refused", 0)
    assert strict_loads(result.state.outcome_wire)["reason"] == "transport_error"


def _diagnostic_frame(phase, category, received=0, code=0xFFFFFFFF):
    return b"D1" + bytes((phase, category)) + received.to_bytes(4, "big") + code.to_bytes(4, "big")


@pytest.mark.parametrize("wire", [
    b"E", b"T", b"B", b"D2" + bytes(10), b"D1", b"R",
    _diagnostic_frame(4, 2)[:-1], _diagnostic_frame(4, 2) + b"x",
    _diagnostic_frame(255, 2), _diagnostic_frame(4, 255),
    _diagnostic_frame(4, 1), _diagnostic_frame(2, 1, 1),
    _diagnostic_frame(2, 1, code=0), _diagnostic_frame(2, 1, code=0x80000000),
    _diagnostic_frame(4, 2, code=62), _diagnostic_frame(4, 2, 130),
    _diagnostic_frame(4, 9, 128), _diagnostic_frame(4, 9, 0),
    _diagnostic_frame(4, 2, 129), _diagnostic_frame(4, 8, 1),
    _diagnostic_frame(0, 0), _diagnostic_frame(3, 4), _diagnostic_frame(4, 7),
])
def test_malformed_diagnostics_cannot_become_a_worker_observation(wire):
    result = capture._decode_worker_result(wire, 128)
    assert result.reason == "transport_error" and result.response == b""
    assert result.observation == capture.TransportObservation("controller", "supervision", "worker_protocol")


def test_diagnostic_framing_does_not_increase_a_tiny_response_budget():
    result = capture._decode_worker_result(b"Rxx", 1)
    assert result.reason == "body_limit" and result.response == b""
    assert result.observation.category == "stdout_limit"
    assert capture._decode_worker_result(_diagnostic_frame(2, 1, code=62), 1).observation.tls_verify_code == 62


@pytest.mark.parametrize("phase,error,category,received", [
    (0, ValueError("fixture private detail"), "input_error", 0),
    (1, ConnectionRefusedError("fixture private detail"), "connection_refused", 0),
    (1, TimeoutError("fixture private detail"), "timeout", 0),
    (2, ssl.SSLEOFError("fixture private detail"), "tls_eof", 0),
    (2, ssl.SSLError("fixture private detail"), "tls_error", 0),
    (3, BrokenPipeError("fixture private detail"), "os_error", 0),
    (3, TimeoutError("fixture private detail"), "timeout", 0),
    (4, ConnectionResetError("fixture private detail"), "connection_reset", 2),
    (4, ssl.SSLEOFError("fixture private detail"), "tls_eof", 2),
    (4, TimeoutError("fixture private detail"), "timeout", 2),
])
def test_worker_observes_faults_without_exposing_exception_text(monkeypatch, phase, error, category, received):
    from etzio.qualification import https_capture_worker_v1 as worker

    class Endpoint:
        reads = 0

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def settimeout(self, value):
            pass

        def connect(self, address):
            if phase == 1:
                raise error

        def sendall(self, data):
            if phase == 3:
                raise error

        def recv(self, size):
            self.reads += 1
            if self.reads == 1:
                return b"ab"
            raise error

    endpoint = Endpoint()

    class Context:
        def load_verify_locations(self, **kwargs):
            if phase == 0:
                raise error

        def set_alpn_protocols(self, value):
            pass

        def wrap_socket(self, raw, **kwargs):
            assert kwargs["suppress_ragged_eofs"] is False
            if phase == 2:
                raise error
            return endpoint

    monkeypatch.setattr(worker.socket, "socket", lambda *a: endpoint)
    monkeypatch.setattr(worker.ssl, "SSLContext", lambda *a: Context())
    wire = worker.collect({
        "timeout_ms": 1000, "response_limit_bytes": 128, "ca_pem": "fixture", "ipv4": "127.0.0.1",
        "hostname": "fixture.invalid", "port": 1, "http_request_base64": base64.b64encode(REQUEST).decode(),
    })
    assert len(wire) == 12 and b"fixture private detail" not in wire
    result = capture._decode_worker_result(wire, 128)
    assert result.observation == capture.TransportObservation("collector", worker.PHASES[phase], category, received)
    assert result.reason == ("timeout" if category == "timeout" else "transport_error")


@pytest.mark.parametrize("program,category", [
    ("import sys; sys.stdout.buffer.write(b'Rabc'); sys.stderr.write('private detail')", "worker_stderr"),
    ("import sys; sys.stdout.buffer.write(b'Rabc'); sys.exit(2)", "worker_exit"),
    ("import sys; sys.stdout.buffer.write(b'unknown')", "worker_protocol"),
    ("import sys; sys.stderr.buffer.write(b'x'*9000)", "stderr_limit"),
])
def test_parent_refusals_do_not_claim_a_collector_phase(tmp_path, monkeypatch, program, category):
    worker = tmp_path / "refused_worker.py"
    worker.write_text(program)
    monkeypatch.setattr(capture, "WORKER", worker)
    result = capture._supervise(b"{}", 128, 2000)
    assert result.reason == "transport_error" and result.response == b""
    assert result.observation == capture.TransportObservation("controller", "supervision", category)


def test_cli_prints_failure_observation_but_cold_inspection_does_not_invent_it(tmp_path, tls_material):
    ca, _ = tls_material
    with _server(tls_material, mode="ragged") as (port, record):
        plan = _plan(ca, port)
        journal = _journal(tmp_path, plan)
        (tmp_path / "plan.json").write_bytes(plan)
        (tmp_path / "ca.pem").write_bytes(ca)
        result = _cli(
            "--capture", "--journal", str(journal.path), "--plan", str(tmp_path / "plan.json"),
            "--ca", str(tmp_path / "ca.pem"), "--acknowledged-plan-id", capture.plan_id(plan),
        )
        assert result.returncode == 0, result.stderr
        report = json.loads(result.stdout)
        assert report["status"] == "capture_indeterminate"
        assert report["transport_observation"]["category"] == "tls_eof"
        assert report["transport_observation"]["attempt_id"] == report["attempt_id"]
        assert "opaque_timestamp_body" not in report and record["connections"] == 1
    cold = _cli("--inspect", "--journal", str(journal.path))
    assert cold.returncode == 0
    assert "transport_observation" not in json.loads(cold.stdout)
