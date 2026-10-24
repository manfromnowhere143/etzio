"""Closed benign Linux/x86 KVM preflight; never an untrusted-workload runner.

Only the fixed instruction fixtures below can execute. No guest OS, target,
network device, filesystem device, or caller-supplied instructions are accepted.
Observations do not admit an isolation profile or independent verifier.
"""

from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import json
import mmap
import os
import platform
import resource
import select
import signal
import socket
import struct
import tempfile
import time
from pathlib import Path

PROGRAMS = {
    "emit": bytes.fromhex("b02ae6e9f4"),  # mov al,42; out 0xe9,al; hlt
    "wrong_emit": bytes.fromhex("b02be6e9f4"),
    "store": bytes.fromhex("b83412a30010f4"),  # store 0x1234 at address 4096
    "spin": bytes.fromhex("ebfe"),  # bounded by the external process observer
}
LIBC = None


def checked(result: int, label: str) -> None:
    if result != 0:
        raise OSError(ctypes.get_errno(), label)


def emit(fd: int, value: dict) -> None:
    wire = json.dumps(value, sort_keys=True).encode() + b"\n"
    if len(wire) > 3500:
        raise RuntimeError("observation exceeds pipe atomic-write bound")
    if os.write(fd, wire) != len(wire):
        raise RuntimeError("incomplete observation")


def restrict_worker(uid: int, parent: int, canary: str) -> dict:
    # Never attempt a connection unless a fresh empty network namespace exists.
    checked(LIBC.unshare(0x40000000), "unshare(CLONE_NEWNET)")
    os.setgroups([])
    os.setgid(uid)
    os.setuid(uid)
    checked(LIBC.prctl(38, 1, 0, 0, 0), "PR_SET_NO_NEW_PRIVS")
    # Linux clears PDEATHSIG on credential changes: set it after dropping UID.
    checked(LIBC.prctl(1, signal.SIGKILL, 0, 0, 0), "PR_SET_PDEATHSIG")
    if os.getppid() != parent:
        os._exit(91)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2, 256 * 1024**2))
    resource.setrlimit(resource.RLIMIT_CPU, (8, 8))
    interfaces = [name for _, name in socket.if_nameindex()]
    if interfaces != ["lo"]:
        raise RuntimeError("unexpected worker network interface")
    denied = {}
    for address in ("169.254.169.254", "192.0.2.1"):
        with socket.socket() as connection:
            connection.settimeout(0.2)
            try:
                connection.connect((address, 80))
            except OSError as exc:
                denied[address] = exc.errno
            else:
                raise RuntimeError("unexpected network connection")
        if denied[address] != errno.ENETUNREACH:
            raise RuntimeError("network denial was not ENETUNREACH")
    try:
        Path(canary).read_bytes()
    except PermissionError as exc:
        canary_errno = exc.errno
    else:
        raise RuntimeError("protected canary was readable")
    status = Path("/proc/self/status").read_text()
    selected = {
        line.split(":", 1)[0]: line.split(":", 1)[1].strip()
        for line in status.splitlines()
        if line.startswith(("Uid:", "Gid:", "CapEff:", "NoNewPrivs:", "Seccomp:"))
    }
    return {
        "uid": os.getuid(),
        "gid": os.getgid(),
        "interfaces": interfaces,
        "network_errno": denied,
        "protected_canary_errno": canary_errno,
        "status": selected,
        "network_namespace": os.readlink("/proc/self/ns/net"),
    }


def worker(fd: int, mode: str, readonly: bool, uid: int, canary: str) -> None:
    parent = os.getppid()
    handles = []
    mappings = []
    try:
        kvm = os.open("/dev/kvm", os.O_RDWR | os.O_CLOEXEC)
        handles.append(kvm)
        version = fcntl.ioctl(kvm, 0xAE00, 0)
        if version != 12:
            raise RuntimeError("unsupported KVM API")
        vm = fcntl.ioctl(kvm, 0xAE01, 0)
        handles.append(vm)
        fcntl.ioctl(vm, 0xAE47, 0x100000)  # KVM_SET_TSS_ADDR, x86 ABI
        memory = mmap.mmap(-1, 65536, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS)
        mappings.append(memory)
        memory[: len(PROGRAMS[mode])] = PROGRAMS[mode]
        address = ctypes.addressof(ctypes.c_char.from_buffer(memory))
        region = struct.pack("<IIQQQ", 0, 2 if readonly else 0, 0, 65536, address)
        fcntl.ioctl(vm, 0x4020AE46, region)
        vcpu = fcntl.ioctl(vm, 0xAE41, 0)
        handles.append(vcpu)
        run_size = fcntl.ioctl(kvm, 0xAE04, 0)
        if not 4096 <= run_size <= 1024 * 1024:
            raise RuntimeError("unexpected KVM run mapping size")
        run = mmap.mmap(vcpu, run_size, flags=mmap.MAP_SHARED, prot=mmap.PROT_READ | mmap.PROT_WRITE)
        mappings.append(run)
        special = bytearray(312)
        fcntl.ioctl(vcpu, 0x8138AE83, special, True)
        struct.pack_into("<Q", special, 0, 0)  # CS base
        struct.pack_into("<H", special, 12, 0)  # CS selector
        fcntl.ioctl(vcpu, 0x4138AE84, special)
        fcntl.ioctl(vcpu, 0x4090AE82, struct.pack("<18Q", *([0] * 17), 2))
        restriction = restrict_worker(uid, parent, canary)
        emit(
            fd,
            {
                "kind": "ready",
                "pid": os.getpid(),
                "parent": parent,
                "mode": mode,
                "readonly": readonly,
                "kvm_api": version,
                "program_sha256": hashlib.sha256(PROGRAMS[mode]).hexdigest(),
                "restrictions": restriction,
            },
        )
        exits = []
        output = []
        for _ in range(8):
            fcntl.ioctl(vcpu, 0xAE80, 0)
            reason = struct.unpack_from("<I", run, 8)[0]
            exits.append(reason)
            if reason == 2:
                direction, size, port, count, offset = struct.unpack_from("<BBHIQ", run, 32)
                if (direction, size, port, count) != (1, 1, 0xE9, 1):
                    raise RuntimeError("unexpected I/O request")
                if offset < 48 or offset + size > run_size:
                    raise RuntimeError("invalid I/O offset")
                output.append(run[offset])
            elif reason in (5, 6):
                observation = {
                    "kind": "effect",
                    "exits": exits,
                    "output": output,
                    "memory_4096_hex": memory[4096:4098].hex(),
                }
                if reason == 6:
                    phys, data, size, writing = struct.unpack_from("<Q8sIB", run, 32)
                    observation["mmio"] = {
                        "address": phys,
                        "data_hex": data[:size].hex(),
                        "size": size,
                        "is_write": writing,
                    }
                emit(fd, observation)
                return
            else:
                raise RuntimeError(f"unexpected KVM exit {reason}")
        raise RuntimeError("exit count exceeded")
    finally:
        for mapping in reversed(mappings):
            mapping.close()
        for handle in reversed(handles):
            os.close(handle)


def case(mode: str, readonly: bool, uid: int, canary: str, parent_death: bool = False) -> dict:
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            if parent_death:
                worker_pid = os.fork()
                if worker_pid:
                    os.close(write_fd)
                    os.waitpid(worker_pid, 0)
                    os._exit(0)
            worker(write_fd, mode, readonly, uid, canary)
        except BaseException as exc:
            emit(write_fd, {"kind": "error", "type": type(exc).__name__, "message": str(exc)[:400]})
            os._exit(1)
        os._exit(0)
    os.close(write_fd)
    start = time.monotonic()
    ready_at = None
    killed_at = None
    worker_pid = None
    messages = []
    buffered = b""
    reaped = {}
    eof = False
    try:
        while time.monotonic() - start < 12:
            now = time.monotonic()
            if mode == "spin" and ready_at is not None and killed_at is None and now - ready_at >= 0.3:
                os.kill(pid, signal.SIGKILL)
                killed_at = time.monotonic()
            if not eof and select.select([read_fd], [], [], 0.05)[0]:
                data = os.read(read_fd, 4096)
                if not data:
                    eof = True
                buffered += data
                if len(buffered) > 8192:
                    raise RuntimeError("bounded pipe output exceeded")
                while b"\n" in buffered:
                    line, buffered = buffered.split(b"\n", 1)
                    message = json.loads(line)
                    messages.append(message)
                    if message.get("kind") == "ready":
                        ready_at = time.monotonic()
                        worker_pid = message["pid"]
            for candidate in {pid, worker_pid} - {None}:
                if candidate not in reaped:
                    try:
                        found, status = os.waitpid(candidate, os.WNOHANG)
                    except ChildProcessError:
                        continue
                    if found:
                        reaped[candidate] = os.waitstatus_to_exitcode(status)
            if eof and pid in reaped and (not parent_death or worker_pid in reaped):
                break
        else:
            raise RuntimeError("observer deadline exceeded")
        if buffered:
            raise RuntimeError("truncated observation")
        if any(m.get("kind") == "error" for m in messages):
            raise RuntimeError(str(messages))
        ready = [m for m in messages if m.get("kind") == "ready"]
        effects = [m for m in messages if m.get("kind") == "effect"]
        if len(ready) != 1:
            raise RuntimeError("missing or repeated ready observation")
        if mode == "spin":
            passed = killed_at is not None and not effects and all(v == -signal.SIGKILL for v in reaped.values())
            decision = "worker_killed_after_parent_death" if parent_death else "worker_killed_by_external_observer"
        else:
            if len(effects) != 1 or reaped[pid] != 0:
                raise RuntimeError("missing effect or failed worker")
            effect = effects[0]
            if mode in ("emit", "wrong_emit"):
                accepted_effect = effect["exits"] == [2, 5] and effect["output"] == [42]
                passed = accepted_effect if mode == "emit" else not accepted_effect and effect["output"] == [43]
                decision = "effect_accepted" if accepted_effect else "wrong_effect_rejected"
            elif readonly:
                passed = (
                    effect["exits"] == [6]
                    and effect["memory_4096_hex"] == "0000"
                    and effect.get("mmio") == {"address": 4096, "data_hex": "3412", "size": 2, "is_write": 1}
                )
                decision = "write_request_refused_without_emulation"
            else:
                passed = effect["exits"] == [5] and effect["memory_4096_hex"] == "3412"
                decision = "writable_memory_positive_control"
        return {
            "mode": mode,
            "readonly": readonly,
            "uid": uid,
            "parent_death": parent_death,
            "passed": bool(passed),
            "decision": decision,
            "messages": messages,
            "reaped_exit_codes": list(reaped.values()),
            "elapsed_seconds": time.monotonic() - start,
            "post_kill_reap_seconds": None if killed_at is None else time.monotonic() - killed_at,
        }
    finally:
        os.close(read_fd)
        for candidate in {pid, worker_pid} - {None}:
            if candidate not in reaped:
                try:
                    os.kill(candidate, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    os.waitpid(candidate, 0)
                except ChildProcessError:
                    pass


def collect() -> dict:
    if platform.system() != "Linux" or platform.machine() != "x86_64" or os.getuid() != 0:
        raise RuntimeError("requires disposable Linux x86_64 root collector")
    global LIBC
    LIBC = ctypes.CDLL(None, use_errno=True)
    LIBC.prctl.restype = ctypes.c_int
    LIBC.unshare.argtypes = [ctypes.c_int]
    LIBC.unshare.restype = ctypes.c_int
    checked(LIBC.prctl(36, 1, 0, 0, 0), "PR_SET_CHILD_SUBREAPER")
    result = {
        "schema": "etzio.benign-kvm-preflight.observation.v1",
        "boundary": "owned fixed instructions; not an admitted isolation or verifier profile",
        "collector_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "kernel": platform.uname()._replace(node="omitted")._asdict(),
        "os_release": Path("/etc/os-release").read_text(),
        "cases": [],
    }
    with tempfile.TemporaryDirectory(prefix="etzio-owned-kvm-") as directory:
        canary = Path(directory) / "protected-canary"
        canary.write_bytes(b"etzio-owned-benign-canary\n")
        canary.chmod(0o600)
        result["controller_canary_read_positive_control"] = canary.read_bytes() == b"etzio-owned-benign-canary\n"
        for mode, readonly, uid, parent_death in [
            ("emit", False, 65532, False),
            ("emit", False, 65533, False),
            ("wrong_emit", False, 65532, False),
            ("store", False, 65532, False),
            ("store", True, 65532, False),
            ("spin", False, 65532, False),
            ("spin", False, 65532, True),
        ]:
            result["cases"].append(case(mode, readonly, uid, str(canary), parent_death))
    result["all_controls_passed"] = all(c["passed"] for c in result["cases"])
    return result


if __name__ == "__main__":
    observation = collect()
    print(json.dumps(observation, sort_keys=True), flush=True)
    raise SystemExit(0 if observation["all_controls_passed"] else 1)
