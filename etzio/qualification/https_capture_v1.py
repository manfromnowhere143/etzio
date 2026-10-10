"""Opt-in bounded HTTPS material discovery; no engine or provider authority.

ADR-0024 requires separate operator acceptance of an exact plan and assumptions.
An acknowledgement digest is a substitution guard, not an authority signature.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import selectors
import signal
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

from etzio.protocol import ProtocolError, canonical_dumps, strict_loads
from etzio.qualification.acquisition_custody_v1 import AcquisitionJournal, CustodySnapshot

MAX_CA = 524288
MAX_PLAN = 8192
MAX_WIRE = 65536
MAX_STDERR = 2048
WORKER = Path(__file__).with_name("https_capture_worker_v1.py")
_SHA = re.compile(r"[0-9a-f]{64}")
_ID = re.compile(r"sha256:[0-9a-f]{64}")
_FIELDS = frozenset({
    "schema", "surface", "service_id", "endpoint", "ipv4", "request_sha256", "request_size",
    "terms_reference_id", "assumptions_reference_id", "ca_sha256", "runtime_id",
    "response_limit_bytes", "timeout_ms",
})


class CaptureError(ValueError):
    """Deterministic preflight or offline HTTP refusal; not a storage exception."""


def _require(condition, reason):
    if not condition:
        raise CaptureError(reason)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def plan_id(wire: bytes) -> str:
    _plan(wire)
    return "sha256:" + _sha(wire)


def runtime_identity() -> str:
    """Finite runtime binding; not complete binary/library or host provenance."""
    value = {
        "python": sys.version,
        "openssl": ssl.OPENSSL_VERSION,
        "executable_sha256": _sha(Path(sys.executable).resolve().read_bytes()),
        "worker_sha256": _sha(WORKER.read_bytes()),
        "controller_sha256": _sha(Path(__file__).read_bytes()),
    }
    return "sha256:" + _sha(canonical_dumps(value))


def _plan(wire):
    _require(type(wire) is bytes and 0 < len(wire) <= MAX_PLAN, "plan_size")
    try:
        value = strict_loads(wire)
    except ProtocolError as error:
        raise CaptureError("plan_encoding") from error
    _require(type(value) is dict and set(value) == _FIELDS, "plan_shape")
    _require(canonical_dumps(value) == wire and value["schema"] == "etzio.https-capture.plan.v1", "plan_encoding")
    for key in ("terms_reference_id", "assumptions_reference_id", "runtime_id"):
        _require(type(value[key]) is str and _ID.fullmatch(value[key]), "plan_reference")
    for key in ("request_sha256", "ca_sha256"):
        _require(type(value[key]) is str and _SHA.fullmatch(value[key]), "plan_digest")
    for key, ceiling in (("request_size", 16384), ("response_limit_bytes", MAX_WIRE), ("timeout_ms", 30000)):
        _require(type(value[key]) is int and 1 <= value[key] <= ceiling, "plan_limit")
    _require(
        type(value["service_id"]) is str
        and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]{1,127}", value["service_id"]), "plan_service",
    )
    endpoint = value["endpoint"]
    _require(type(endpoint) is str and len(endpoint) <= 512, "plan_endpoint")
    match = re.fullmatch(r"https://([a-z0-9]+(?:[.-][a-z0-9]+)*)(?::([1-9][0-9]{0,4}))?(/[A-Za-z0-9/_.-]*)", endpoint)
    _require(match is not None, "plan_endpoint")
    port = int(match[2] or 443)
    _require(port <= 65535, "plan_endpoint")
    try:
        address = ipaddress.IPv4Address(value["ipv4"])
    except (ipaddress.AddressValueError, TypeError) as error:
        raise CaptureError("plan_address") from error
    _require(type(value["ipv4"]) is str and str(address) == value["ipv4"], "plan_address")
    if value["surface"] == "repository_fixture":
        _require(str(address) == "127.0.0.1", "fixture_address")
    else:
        _require(value["surface"] == "external_discovery", "plan_surface")
        _require(address.is_global and not address.is_multicast and not address.is_reserved, "external_address")
        _require(port == 443, "external_port")
    return value


def plan_wire(*, request: bytes, ca_pem: bytes, **fields) -> bytes:
    """Prepare exact bytes offline. This function cannot accept or authorize them."""
    _require(type(request) is bytes and 0 < len(request) <= 16384, "request_size")
    _require(type(ca_pem) is bytes and 0 < len(ca_pem) <= MAX_CA, "ca_size")
    wire = canonical_dumps({
        "schema": "etzio.https-capture.plan.v1", "runtime_id": runtime_identity(),
        "request_sha256": _sha(request), "request_size": len(request), "ca_sha256": _sha(ca_pem), **fields,
    })
    _plan(wire)
    return wire


def _preflight(journal, wire, ca, acknowledged_plan_id):
    _require(type(journal) is AcquisitionJournal, "journal_type")
    value = _plan(wire)
    identity = plan_id(wire)
    _require(type(acknowledged_plan_id) is str and acknowledged_plan_id == identity, "plan_not_acknowledged")
    _require(value["runtime_id"] == runtime_identity(), "runtime_binding")
    _require(type(ca) is bytes and 0 < len(ca) <= MAX_CA and _sha(ca) == value["ca_sha256"], "ca_binding")
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=ca.decode("ascii"))
    except (UnicodeError, ssl.SSLError) as error:
        raise CaptureError("ca_encoding") from error
    state = journal.inspect()
    intent = strict_loads(state.intent_wire)
    _require(intent["scope_reference_id"] == identity, "scope_binding")
    for key in (
        "service_id", "endpoint", "request_sha256", "request_size", "terms_reference_id", "response_limit_bytes",
    ):
        _require(intent[key] == value[key], "intent_binding")
    parsed = urlsplit(value["endpoint"])
    request = (
        f"POST {parsed.path} HTTP/1.1\r\nHost: {parsed.netloc}\r\n"
        "Content-Type: application/timestamp-query\r\nAccept: application/timestamp-reply\r\n"
        "Accept-Encoding: identity\r\nConnection: close\r\n"
        f"Content-Length: {len(state.request_wire)}\r\n\r\n"
    ).encode("ascii") + state.request_wire
    packet = json.dumps({
        "hostname": parsed.hostname, "port": parsed.port or 443, "ipv4": value["ipv4"],
        "http_request_base64": base64.b64encode(request).decode("ascii"), "ca_pem": ca.decode("ascii"),
        "response_limit_bytes": value["response_limit_bytes"], "timeout_ms": value["timeout_ms"],
    }, separators=(",", ":")).encode("ascii")
    _require(len(packet) <= 1048576, "packet_size")
    return value, packet


def _kill_and_reap(process):
    # Do not signal a numeric process group after reaping and releasing its PID.
    # The supervisor does not poll/reap while inherited pipes might remain open.
    if process.returncode is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=2)


def _supervise(packet: bytes, cap: int, timeout_ms: int) -> tuple[str, bytes]:
    """Bound pipes and elapsed acquisition time; cleanup errors propagate separately."""
    deadline = time.monotonic() + timeout_ms / 1000
    output = bytearray()
    errors = bytearray()
    with tempfile.TemporaryDirectory(prefix="etzio-capture-") as directory:
        try:
            process = subprocess.Popen(
                [str(Path(sys.executable).resolve()), "-I", str(WORKER.resolve())],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=directory, env={"LANG": "C", "OPENSSL_CONF": os.devnull},
                start_new_session=True, close_fds=True,
            )
        except OSError:
            return "transport_error", b""
        try:
            with selectors.DefaultSelector() as selector:
                for stream, event, role in (
                    (process.stdin, selectors.EVENT_WRITE, "input"),
                    (process.stdout, selectors.EVENT_READ, "output"),
                    (process.stderr, selectors.EVENT_READ, "error"),
                ):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, event, role)
                offset = 0
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return "timeout", b""
                    for key, _ in selector.select(min(remaining, 0.05)):
                        stream = key.fileobj
                        if key.data == "input":
                            try:
                                offset += os.write(stream.fileno(), packet[offset:offset + 8192])
                            except BrokenPipeError:
                                offset = len(packet)
                            if offset == len(packet):
                                selector.unregister(stream)
                                stream.close()
                        else:
                            target, limit = (output, cap + 1) if key.data == "output" else (errors, MAX_STDERR)
                            chunk = os.read(stream.fileno(), min(8192, limit + 1 - len(target)))
                            if not chunk:
                                selector.unregister(stream)
                                stream.close()
                            else:
                                target.extend(chunk)
                                if len(target) > limit:
                                    return ("body_limit" if key.data == "output" else "transport_error"), b""
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return "timeout", b""
            try:
                process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                return "timeout", b""
            if process.returncode != 0 or errors:
                return "transport_error", b""
            result = bytes(output)
            if result.startswith(b"R") and len(result) > 1:
                return "response", result[1:]
            return {b"T": "timeout", b"B": "body_limit"}.get(result, "transport_error"), b""
        finally:
            _kill_and_reap(process)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()


def capture_once(
    journal: AcquisitionJournal, wire: bytes, ca_pem: bytes, *, acknowledged_plan_id: str,
) -> CustodySnapshot:
    """Dispatch only after separate operator acceptance; digest equality is not authority."""
    value, packet = _preflight(journal, wire, ca_pem, acknowledged_plan_id)
    journal.debit()  # A failed/lost acknowledgement must never reach the collector.
    try:
        reason, response = _supervise(packet, value["response_limit_bytes"], value["timeout_ms"])
    except KeyboardInterrupt:
        journal.retain_indeterminate("operator_stop")
        raise
    # Deliberately outside the transport exception domain. A store failure stays a store failure.
    if reason == "response":
        return journal.retain_response(response)
    return journal.retain_indeterminate(reason)


def timestamp_body(wire: bytes) -> bytes:
    """Offline finite HTTP decoder only. No ASN.1, CMS, timestamp or UTC acceptance."""
    _require(type(wire) is bytes and 0 < len(wire) <= MAX_WIRE, "http_size")
    boundary = wire.find(b"\r\n\r\n")
    _require(0 <= boundary <= 8192 - 4, "http_header_size")
    lines = wire[:boundary].split(b"\r\n")
    _require(re.fullmatch(rb"HTTP/1\.[01] 200 [\x20-\x7e]*", lines[0]), "http_status")
    _require(len(lines) <= 65, "http_header_count")
    headers = {}
    for line in lines[1:]:
        match = re.fullmatch(rb"([!#$%&'*+.^_`|~0-9A-Za-z-]+):([\t\x20-\x7e]*)", line)
        _require(match is not None, "http_header")
        name = match[1].lower()
        _require(name not in headers, "http_duplicate_header")
        headers[name] = match[2].strip(b" \t").lower()
    _require(headers.get(b"content-type") == b"application/timestamp-reply", "http_media_type")
    _require(headers.get(b"content-encoding", b"identity") == b"identity", "http_content_coding")
    body = wire[boundary + 4:]
    length, transfer = headers.get(b"content-length"), headers.get(b"transfer-encoding")
    _require(not (length is not None and transfer is not None), "http_ambiguous_length")
    if transfer is not None:
        _require(transfer == b"chunked", "http_transfer_coding")
        _require(lines[0].startswith(b"HTTP/1.1 "), "http_transfer_version")
        decoded = bytearray()
        position = 0
        for _ in range(257):
            end = body.find(b"\r\n", position)
            _require(end >= 0 and re.fullmatch(rb"[0-9A-Fa-f]{1,8}", body[position:end]), "http_chunk_size")
            size = int(body[position:end], 16)
            position = end + 2
            if size == 0:
                _require(body[position:] == b"\r\n", "http_trailer_or_extra")
                body = bytes(decoded)
                break
            _require(size <= MAX_WIRE and body[position + size:position + size + 2] == b"\r\n", "http_chunk_body")
            decoded.extend(body[position:position + size])
            position += size + 2
        else:
            raise CaptureError("http_chunk_count")
    elif length is not None:
        _require(re.fullmatch(rb"(?:0|[1-9][0-9]{0,4})", length), "http_content_length")
        _require(int(length) == len(body), "http_body_length")
    _require(body, "http_empty_body")
    return body
