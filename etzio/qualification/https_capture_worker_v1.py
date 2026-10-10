"""Private ADR-0024 collector, with bounded advisory failure observations.

No journal, provider validation, DNS, HTTP parsing, redirects or retries here.
Invoked by https_capture_v1 under Python isolated mode, never by the engine.
"""

from __future__ import annotations

import base64
import json
import resource
import socket
import ssl
import sys
import time

MAX_PACKET = 1048576
DIAGNOSTIC_SIZE = 12
PHASES = ("configuration", "connect", "tls_handshake", "request_write", "response_read")
CATEGORIES = (
    "timeout", "tls_verification", "tls_eof", "tls_error", "connection_refused",
    "connection_reset", "os_error", "input_error", "empty_response", "body_limit",
)
NO_VERIFY_CODE = 0xFFFFFFFF


def _failure(phase, category, received, verify_code=None):
    code = verify_code if type(verify_code) is int and 1 <= verify_code <= 0x7FFFFFFF else NO_VERIFY_CODE
    return b"D1" + bytes((phase, category)) + received.to_bytes(4, "big") + code.to_bytes(4, "big")


def collect(packet: dict) -> bytes:
    phase, received = 0, 0
    try:
        deadline = time.monotonic() + packet["timeout_ms"] / 1000
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.hostname_checks_common_name = False
        context.load_verify_locations(cadata=packet["ca_pem"])
        context.set_alpn_protocols(["http/1.1"])
        cap = packet["response_limit_bytes"]

        def remaining():
            value = deadline - time.monotonic()
            if value <= 0:
                raise TimeoutError
            return value

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw:
            phase = 1
            raw.settimeout(remaining())
            raw.connect((packet["ipv4"], packet["port"]))
            phase = 2
            raw.settimeout(remaining())
            with context.wrap_socket(raw, server_hostname=packet["hostname"], suppress_ragged_eofs=False) as stream:
                phase = 3
                stream.settimeout(remaining())
                stream.sendall(base64.b64decode(packet["http_request_base64"], validate=True))
                phase = 4
                wire = bytearray()
                while True:
                    stream.settimeout(remaining())
                    chunk = stream.recv(min(8192, cap + 1 - len(wire)))
                    if not chunk:
                        return b"R" + wire if wire else _failure(phase, 8, 0)
                    wire.extend(chunk)
                    received = len(wire)
                    if received > cap:
                        return _failure(phase, 9, received)
    except TimeoutError:
        return _failure(phase, 0, received)
    except ssl.SSLCertVerificationError as error:
        return _failure(phase, 1, received, getattr(error, "verify_code", None))
    except ssl.SSLEOFError:
        return _failure(phase, 2, received)
    except ssl.SSLError:
        return _failure(phase, 3, received)
    except ConnectionRefusedError:
        return _failure(phase, 4, received)
    except ConnectionResetError:
        return _failure(phase, 5, received)
    except OSError:
        return _failure(phase, 6, received)
    except (ValueError, KeyError, TypeError):
        return _failure(phase, 7, received)


def main() -> int:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
    if sys.platform.startswith("linux"):
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    try:
        raw = sys.stdin.buffer.read(MAX_PACKET + 1)
        if len(raw) > MAX_PACKET:
            return 2
        result = collect(json.loads(raw))
    except (ValueError, KeyError, TypeError):
        result = _failure(0, 7, 0)
    sys.stdout.buffer.write(result)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
