"""Private ADR-0024 collector. Trusted parent supplies a bounded, approved packet.

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


def collect(packet: dict) -> bytes:
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
        raw.settimeout(remaining())
        # AF_INET plus a validated numeric IPv4 avoids the resolver and fallback.
        raw.connect((packet["ipv4"], packet["port"]))
        raw.settimeout(remaining())
        with context.wrap_socket(raw, server_hostname=packet["hostname"], suppress_ragged_eofs=False) as stream:
            stream.settimeout(remaining())
            stream.sendall(base64.b64decode(packet["http_request_base64"], validate=True))
            wire = bytearray()
            while True:
                stream.settimeout(remaining())
                chunk = stream.recv(min(8192, cap + 1 - len(wire)))
                if not chunk:
                    return b"R" + wire if wire else b"E"
                wire.extend(chunk)
                if len(wire) > cap:
                    return b"B"


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
    except TimeoutError:
        result = b"T"
    except (OSError, ValueError, KeyError, TypeError):
        result = b"E"
    sys.stdout.buffer.write(result)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
