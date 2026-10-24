"""Portable refusal checks; these do not execute a VMM, guest, or cloud command."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import socketserver
import stat
import tempfile
import threading
from pathlib import Path

import pytest


@pytest.fixture
def collector(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    path = Path(__file__).resolve().parents[1] / "scripts/collect_owned_firecracker_preflight.py"
    spec = importlib.util.spec_from_file_location("owned_firecracker_preflight_control", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(module.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(module.platform, "release", lambda: "6.1.0-owned-control")
    monkeypatch.setattr(module.os, "getuid", lambda: 0)
    monkeypatch.setattr(module, "ROOT", tmp_path)

    def native_call_forbidden(*_args, **_kwargs):
        raise AssertionError("refusal must precede native library initialization")

    monkeypatch.setattr(module.ctypes, "CDLL", native_call_forbidden)
    return module


@pytest.mark.parametrize("field,value", [("system", "Darwin"), ("machine", "aarch64"), ("getuid", 501)])
def test_unsupported_host_refused_before_native_calls(collector, monkeypatch, field, value):
    owner = collector.os if field == "getuid" else collector.platform
    monkeypatch.setattr(owner, field, lambda: value)
    with pytest.raises(RuntimeError, match="requires the specified disposable"):
        collector.collect()


@pytest.mark.parametrize("release", ["7.0.0-owned-control", "6.18.0-owned-control", "6.10.0-owned-control"])
def test_unselected_kernel_refused_before_native_calls(collector, monkeypatch, release):
    monkeypatch.setattr(collector.platform, "release", lambda: release)
    with pytest.raises(RuntimeError, match="outside the selected 6.1 profile"):
        collector.collect()


@pytest.mark.parametrize("kind", ["missing", "altered", "symlink", "directory"])
def test_invalid_pinned_artifact_refused_before_native_calls(collector, tmp_path, kind):
    path = tmp_path / "firecracker"
    if kind == "altered":
        path.write_bytes(b"not the pinned release")
    elif kind == "symlink":
        other = tmp_path / "replacement"
        other.write_bytes(b"untrusted replacement")
        path.symlink_to(other)
    elif kind == "directory":
        path.mkdir()
    with pytest.raises(RuntimeError, match="artifact pin mismatch: firecracker"):
        collector.collect()


def test_matching_fixture_pins_reach_native_boundary_without_running_it(collector, monkeypatch, tmp_path):
    # Positive calibration for the pin refusal, using explicit test-only bytes.
    # The native boundary remains a trap; no real profile is admitted.
    payload = b"owned unit-test bytes, not an executable"
    (tmp_path / "owned-control").write_bytes(payload)
    monkeypatch.setattr(collector, "PINS", {"owned-control": hashlib.sha256(payload).hexdigest()})
    with pytest.raises(AssertionError, match="refusal must precede native"):
        collector.collect()


@pytest.mark.parametrize("mode", ["target", "../ready"])
def test_unlisted_guest_mode_refused_before_creating_resources(collector, mode):
    with pytest.raises(ValueError, match="closed owned fixture set"):
        collector.collect_case(mode, 1)


@pytest.mark.parametrize("status,body", [(204, b""), (503, b"owned refusal"), (200, b"x" * 4097)])
def test_local_api_completion_and_refusal_close_the_connection(collector, status, body):
    observed = {}

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.request.settimeout(3)
            observed["request"] = self.rfile.readline()
            headers = {}
            while (line := self.rfile.readline()) != b"\r\n":
                key, value = line.split(b":", 1)
                headers[key.lower()] = value.strip()
            observed["body"] = json.loads(self.rfile.read(int(headers[b"content-length"])))
            self.wfile.write(f"HTTP/1.1 {status} Owned control\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body)
            self.wfile.flush()
            observed["closed"] = self.rfile.read(1) == b""

    # Keep the socket name within macOS's sockaddr_un path-length limit.
    with tempfile.TemporaryDirectory(prefix="etzio-api-", dir="/tmp") as directory:
        path = Path(directory) / "api.sock"
        with socketserver.UnixStreamServer(str(path), Handler) as server:
            server.timeout = 3
            thread = threading.Thread(target=server.handle_request, daemon=True)
            thread.start()
            try:
                if status == 204:
                    collector.put(path, "/machine-config", {"vcpu_count": 1})
                else:
                    with pytest.raises(RuntimeError, match="API /machine-config"):
                        collector.put(path, "/machine-config", {"vcpu_count": 1})
            finally:
                thread.join(timeout=4)
            assert not thread.is_alive()
    assert observed == {
        "request": b"PUT /machine-config HTTP/1.1\r\n",
        "body": {"vcpu_count": 1},
        "closed": True,
    }


@pytest.mark.parametrize("mask", [0o022, 0o077])
def test_owned_inputs_remain_readable_after_restrictive_bootstrap_umask(collector, tmp_path, mask):
    (tmp_path / "vmlinux").write_bytes(b"owned kernel placeholder")
    (tmp_path / "ready.cpio").write_bytes(b"owned initrd placeholder")
    jail = tmp_path / "jail"
    jail.mkdir()
    previous = os.umask(mask)
    try:
        collector.prepare_inputs(jail, "ready")
    finally:
        os.umask(previous)
    inputs = jail / "inputs"
    try:
        assert stat.S_IMODE(inputs.stat().st_mode) == 0o555
        assert stat.S_IMODE((inputs / "kernel").stat().st_mode) == 0o444
        assert stat.S_IMODE((inputs / "initrd").stat().st_mode) == 0o444
        assert (inputs / "kernel").read_bytes() == b"owned kernel placeholder"
        assert (inputs / "initrd").read_bytes() == b"owned initrd placeholder"
    finally:
        inputs.chmod(0o700)


@pytest.mark.parametrize(
    "status,body,accepted",
    [
        (200, b'{"vcpu_count":1,"mem_size_mib":128,"smt":false,"track_dirty_pages":false}', True),
        (503, b"owned refusal", False),
        (200, b"x" * 4097, False),
        (200, b"{", False),
        (200, b"null", False),
        (200, b'{"vcpu_count":1,"mem_size_mib":256,"smt":false}', False),
        (200, b'{"vcpu_count":true,"mem_size_mib":128,"smt":false}', False),
        (200, b'{"vcpu_count":1,"mem_size_mib":128}', False),
    ],
)
def test_runtime_barrier_requires_exact_machine_config_and_closes(collector, status, body, accepted):
    observed = {}

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.request.settimeout(3)
            observed["request"] = self.rfile.readline()
            while self.rfile.readline() != b"\r\n":
                pass
            self.wfile.write(f"HTTP/1.1 {status} Owned control\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body)
            self.wfile.flush()
            observed["closed"] = self.rfile.read(1) == b""

    with tempfile.TemporaryDirectory(prefix="etzio-api-", dir="/tmp") as directory:
        path = Path(directory) / "api.sock"
        with socketserver.UnixStreamServer(str(path), Handler) as server:
            server.timeout = 3
            thread = threading.Thread(target=server.handle_request, daemon=True)
            thread.start()
            try:
                if accepted:
                    assert collector.runtime_barrier(path) == json.loads(body)
                else:
                    with pytest.raises((RuntimeError, json.JSONDecodeError)):
                        collector.runtime_barrier(path)
            finally:
                thread.join(timeout=4)
            assert not thread.is_alive()
    assert observed == {"request": b"GET /machine-config HTTP/1.1\r\n", "closed": True}


@pytest.mark.parametrize(
    "wire,marker_name,expected",
    [
        (b"ETZIO_OWNED_READY_V1\r\n", "READY", True),
        (b"logger\nETZIO_OWNED_READY_V1\r\n", "READY", True),
        (b"ETZIO_OWNED_WRONG_V1\r\n", "READY", False),
        (b"ETZIO_OWNED_READY_V1\r", "READY", False),
        (b"ETZIO_OWNED_READY_V1\n", "READY", False),
        (b"prefixETZIO_OWNED_READY_V1\r\n", "READY", False),
        (b"ETZIO_OWNED_READY_V1suffix\r\n", "READY", False),
        (b"ETZIO_OWNED_READY_V1\r\r\n", "READY", False),
        (b"ETZIO_OWNED_WRONG_V1\r\n", "WRONG", True),
        (b"ETZIO_OWNED_READY_V1\r\n", "WRONG", False),
    ],
)
def test_guest_console_marker_requires_complete_exact_line(collector, wire, marker_name, expected):
    assert collector.marker_observed(wire, getattr(collector, marker_name)) is expected
