"""Portable owned-process/protocol controls; no guest, cloud or target runs."""

import base64
import copy
import importlib.util
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest


@pytest.fixture
def observer(monkeypatch):
    scripts = Path(__file__).resolve().parents[1] / "scripts"
    monkeypatch.syspath_prepend(str(scripts))
    spec = importlib.util.spec_from_file_location("owned_death_control", scripts / "observe_owned_collector_death.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ready(ordinal=5):
    status = {
        "Seccomp": "2",
        "NoNewPrivs": "1",
        "CapEff": "0000000000000000",
        "Uid": " ".join([str(65000 + ordinal)] * 4),
        "Gid": " ".join([str(65000 + ordinal)] * 4),
    }
    return {
        "schema": "etzio.owned-collector-ready.v1",
        "ordinal": ordinal,
        "launcher_exit_code": 0,
        "collector": {"pid": 100, "parent": 99, "start_ticks": 20},
        "worker": {"pid": 101, "parent": 100, "start_ticks": 21},
        "watchdog": {"pid": 102, "parent": 100, "start_ticks": 21} if ordinal == 5 else None,
        "cgroup": {"device": 25, "inode": 1234},
        "watch_pipe": "pipe:[4567]" if ordinal == 5 else None,
        "threads": {str(x): dict(status) for x in (101, 103, 104)},
        "output_b64": base64.b64encode(b"boot\r\nETZIO_OWNED_READY_V1\r\n").decode(),
    }


@pytest.mark.parametrize("ordinal", [5, 6])
def test_closed_ready_positive(observer, ordinal):
    value = ready(ordinal)
    assert observer.decode_ready(json.dumps(value).encode(), ordinal, 100, 99) == value


@pytest.mark.parametrize(
    "case",
    [
        "extra",
        "missing",
        "schema",
        "ordinal_bool",
        "ordinal_swap",
        "identity_extra",
        "pid_bool",
        "parent",
        "collector_pid",
        "alias",
        "observer_alias",
        "device_bool",
        "inode_zero",
        "pipe",
        "thread_count",
        "filter",
        "capability",
        "uid",
        "gid",
        "thread_id",
        "partial",
        "wrong",
        "output_size",
    ],
)
def test_ready_substitutions_refused(observer, case):
    value = ready()
    if case == "extra":
        value["extra"] = 1
    elif case == "missing":
        del value["threads"]
    elif case == "schema":
        value["schema"] = "future"
    elif case == "ordinal_bool":
        value["ordinal"] = True
    elif case == "ordinal_swap":
        value["ordinal"] = 6
    elif case == "identity_extra":
        value["worker"]["extra"] = 1
    elif case == "pid_bool":
        value["worker"]["pid"] = True
    elif case == "parent":
        value["worker"]["parent"] = 99
    elif case == "collector_pid":
        value["collector"]["pid"] = 90
    elif case == "alias":
        value["watchdog"]["pid"] = 101
    elif case == "observer_alias":
        value["worker"]["pid"] = 99
    elif case == "device_bool":
        value["cgroup"]["device"] = True
    elif case == "inode_zero":
        value["cgroup"]["inode"] = 0
    elif case == "pipe":
        value["watch_pipe"] = "not a pipe"
    elif case == "thread_count":
        del value["threads"]["104"]
    elif case == "filter":
        value["threads"]["101"]["Seccomp"] = "0"
    elif case == "capability":
        value["threads"]["101"]["CapEff"] = "0000000000000001"
    elif case == "uid":
        value["threads"]["101"]["Uid"] = "0 0 0 0"
    elif case == "gid":
        value["threads"]["101"]["Gid"] = "0 0 0 0"
    elif case == "thread_id":
        value["threads"]["bad"] = value["threads"].pop("101")
    elif case == "partial":
        value["output_b64"] = base64.b64encode(b"ETZIO_OWNED_READY_V1").decode()
    elif case == "wrong":
        value["output_b64"] = base64.b64encode(b"ETZIO_OWNED_WRONG_V1\r\n").decode()
    elif case == "output_size":
        value["output_b64"] = base64.b64encode(b"x" * 4097).decode()
    with pytest.raises(ValueError):
        observer.decode_ready(json.dumps(value).encode(), 5, 100, 99)


@pytest.mark.parametrize("wire", [b"", b"{}" * 9000, b"{", b"null", b'{"ordinal":5,"ordinal":5}'])
def test_ready_wire_refused(observer, wire):
    with pytest.raises(ValueError):
        observer.decode_ready(wire, 5, 100, 99)


@pytest.mark.parametrize("field", ["watchdog", "watch_pipe"])
def test_withheld_case_rejects_watchdog(observer, field):
    value = ready(6)
    value[field] = ready()[field]
    with pytest.raises(ValueError, match="withheld"):
        observer.decode_ready(json.dumps(value).encode(), 6, 100, 99)


def accepted():
    return {
        "fallback_used": False,
        "injected_ns": 10,
        "primary_observed_ns": 100,
        "primary_reaped": {"collector": -9, "worker": -9, "watchdog": 0},
        "primary_empty": True,
        "kernel_helper_exited": True,
        "watchdog": {"reason": "collector_pipe_closed", "empty": True, "observed_ns": 20, "completed_ns": 90},
    }


def test_primary_accepts_complete_observation(observer):
    assert observer.primary_accepts(accepted())


@pytest.mark.parametrize(
    "case",
    [
        "fallback",
        "missing",
        "late",
        "backwards",
        "empty",
        "collector_exit",
        "worker_exit",
        "watch_exit",
        "reason",
        "watch_empty",
        "watch_missing",
        "watch_extra",
        "watch_before",
        "watch_after",
        "watch_bool",
    ],
)
def test_primary_never_promotes_incomplete_or_fallback(observer, case):
    r = accepted()
    if case == "fallback":
        r["fallback_used"] = True
    elif case == "missing":
        del r["primary_reaped"]["worker"]
    elif case == "late":
        r["primary_observed_ns"] = observer.PRIMARY_NS + 11
    elif case == "backwards":
        r["primary_observed_ns"] = 9
    elif case == "empty":
        r["primary_empty"] = False
    elif case == "collector_exit":
        r["primary_reaped"]["collector"] = 0
    elif case == "worker_exit":
        r["primary_reaped"]["worker"] = 0
    elif case == "watch_exit":
        r["primary_reaped"]["watchdog"] = -9
    elif case == "reason":
        r["watchdog"]["reason"] = "explicit_stop"
    elif case == "watch_empty":
        r["watchdog"]["empty"] = False
    elif case == "watch_missing":
        del r["watchdog"]
    elif case == "watch_extra":
        r["watchdog"]["extra"] = 1
    elif case == "watch_before":
        r["watchdog"]["observed_ns"] = 9
    elif case == "watch_after":
        r["watchdog"]["completed_ns"] = 101
    elif case == "watch_bool":
        r["watchdog"]["observed_ns"] = True
    assert not observer.primary_accepts(r)


def test_read_pipe_bounds_and_timeout(observer):
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, b"{}")
        with pytest.raises(TimeoutError):
            observer.read_ready(read_fd, time.monotonic() + 0.02)
        os.write(write_fd, b"owned")
        os.close(write_fd)
        write_fd = None
        assert observer.read_ready(read_fd, time.monotonic() + 1) == b"owned"
    finally:
        os.close(read_fd)
        if write_fd is not None:
            os.close(write_fd)


def test_actual_owned_process_death_closes_pipe(observer):
    # A real SIGKILL of a harmless owned Python child. The observer closes its
    # writer first: EOF proves no accidental parent copy remains. No VM is run.
    read_fd, write_fd = os.pipe()
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"], pass_fds=(write_fd,))
    os.close(write_fd)
    try:
        with pytest.raises(TimeoutError):
            observer.read_ready(read_fd, time.monotonic() + 0.02)
        child.send_signal(signal.SIGKILL)
        assert child.wait(timeout=2) == -signal.SIGKILL
        assert observer.read_ready(read_fd, time.monotonic() + 1) == b""
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=2)
        os.close(read_fd)


@pytest.mark.parametrize("ordinal", [True, 4, 7, "5"])
def test_bad_case_cannot_start_process(observer, monkeypatch, ordinal):
    def forbidden(*args, **kwargs):
        raise AssertionError("process creation forbidden")

    monkeypatch.setattr(observer.subprocess, "Popen", forbidden)
    with pytest.raises(ValueError, match="closed"):
        observer.observe_case(ordinal)


@pytest.mark.parametrize("role", ["collector", "worker"])
def test_binding_refuses_changed_process_before_use(observer, monkeypatch, role):
    identity = ready()[role]
    read_fd, write_fd = os.pipe()
    os.close(write_fd)
    changed = copy.deepcopy(identity)
    changed["start_ticks"] += 1
    monkeypatch.setattr(observer.os, "pidfd_open", lambda _pid: read_fd, raising=False)
    monkeypatch.setattr(observer.guest, "process_identity", lambda _pid: changed)
    with pytest.raises(ValueError, match="changed/exited"):
        observer.bind_process(identity)
    with pytest.raises(OSError):
        os.fstat(read_fd)


def test_boolean_exit_status_is_not_success(observer):
    value = accepted()
    value["primary_reaped"]["watchdog"] = False
    assert not observer.primary_accepts(value)


@pytest.mark.parametrize(
    "mode,ordinal,fd",
    [
        ("spin", 5, 4),
        ("ready", 1, 4),
        ("ready", 5.0, 4),
        ("ready", 5, True),
        ("ready", 6, 2),
    ],
)
def test_crash_hook_refuses_nonclosed_case_before_resources(observer, mode, ordinal, fd):
    with pytest.raises(ValueError, match="closed owned collector-death"):
        observer.guest.collect_case(mode, ordinal, crash_probe_fd=fd)


@pytest.mark.parametrize("fault", ["inode", "device", "missing", "extra", "limit"])
def test_cgroup_rebinding_and_membership_refused(observer, monkeypatch, tmp_path, fault):
    value = ready()
    cg = tmp_path / "owned"
    cg.mkdir()
    st = cg.stat()
    value["cgroup"] = {"device": st.st_dev, "inode": st.st_ino}
    (cg / "cgroup.procs").write_text("101\n102\n")
    (cg / "cgroup.events").write_text("populated 1\n")
    for key, limit in observer.guest.LIMITS.items():
        (cg / key).write_text(limit)
    if fault in ("inode", "device"):
        value["cgroup"][fault] += 1
    elif fault == "missing":
        (cg / "cgroup.procs").write_text("")
    elif fault == "extra":
        (cg / "cgroup.procs").write_text("101\n102\n999\n")
    else:
        (cg / "pids.max").write_text("max")
    fd = os.open(cg, os.O_RDONLY)
    monkeypatch.setattr(observer, "kernel_helper_snapshot", lambda _pid: helper())
    evidence = {}
    try:
        with pytest.raises(ValueError, match="cgroup"):
            observer.fresh_binding(value, fd, 5, evidence)
        assert evidence["members"] == (cg / "cgroup.procs").read_text()
        assert evidence["limits"] == {key: (cg / key).read_text() for key in observer.guest.LIMITS}
    finally:
        os.close(fd)


def test_oversized_ready_pipe_refused(observer):
    read_fd, write_fd = os.pipe()
    child = subprocess.Popen(
        [sys.executable, "-c", "import os,sys; os.write(int(sys.argv[1]), b'x'*20000)", str(write_fd)],
        pass_fds=(write_fd,),
    )
    os.close(write_fd)
    try:
        with pytest.raises(ValueError, match="size"):
            observer.read_ready(read_fd, time.monotonic() + 2)
    finally:
        child.kill()
        child.wait(timeout=2)
        os.close(read_fd)


@pytest.mark.parametrize("code", [0, 1])
def test_actual_launcher_reaping_and_failure(observer, code):
    child = subprocess.Popen([sys.executable, "-c", "import sys;sys.exit(int(sys.argv[1]))", str(code)])
    if code == 0:
        assert observer.guest.reap_launcher(child) == 0
    else:
        with pytest.raises(RuntimeError, match="launcher"):
            observer.guest.reap_launcher(child)
    with pytest.raises(ChildProcessError):
        os.waitpid(child.pid, os.WNOHANG)


@pytest.mark.parametrize("code", [False, 1, None])
def test_bad_launcher_completion_refused(observer, code):
    value = ready()
    value["launcher_exit_code"] = code
    with pytest.raises(ValueError, match="launcher"):
        observer.decode_ready(json.dumps(value).encode(), 5, 100, 99)


def helper():
    return {
        "identity": {"pid": 102, "parent": 2, "start_ticks": 40},
        "comm": "kvm-nx-lpage-recovery-101",
        "flags": 0x00200000,
        "status": {"Uid": "0 0 0 0", "Gid": "0 0 0 0"},
    }


def test_kernel_helper_positive(observer):
    observer.validate_kernel_helper(helper(), 101)


@pytest.mark.parametrize("fault", ["userspace", "name", "parent", "uid", "gid", "bool_flags", "wrong_vm"])
def test_kernel_helper_cannot_be_replaced_by_named_userspace_process(observer, fault):
    value = helper()
    if fault == "userspace":
        value["flags"] = 0
    elif fault == "name":
        value["comm"] = "other-kthread"
    elif fault == "parent":
        value["identity"]["parent"] = 100
    elif fault == "uid":
        value["status"]["Uid"] = "65005 65005 65005 65005"
    elif fault == "gid":
        value["status"]["Gid"] = "65005 65005 65005 65005"
    elif fault == "wrong_vm":
        value["comm"] = "kvm-nx-lpage-recovery-999"
    else:
        value["flags"] = True
    with pytest.raises(ValueError, match="helper"):
        observer.validate_kernel_helper(value, 101)


def test_empty_group_does_not_replace_kernel_helper_exit(observer):
    value = accepted()
    value["kernel_helper_exited"] = False
    assert not observer.primary_accepts(value)


@pytest.mark.parametrize("fault", [None, "mnt", "net", "pid", "pipe"])
def test_fresh_namespace_and_observer_pipe_checks(observer, monkeypatch, tmp_path, fault):
    value = ready()
    cg = tmp_path / "owned"
    cg.mkdir()
    st = cg.stat()
    value["cgroup"] = {"device": st.st_dev, "inode": st.st_ino}
    (cg / "cgroup.procs").write_text("101\n102\n")
    (cg / "cgroup.events").write_text("populated 1\n")
    for key, limit in observer.guest.LIMITS.items():
        (cg / key).write_text(limit)
    monkeypatch.setattr(observer, "kernel_helper_snapshot", lambda _pid: helper())
    monkeypatch.setattr(observer.guest, "read_status", lambda tid: value["threads"][tid])

    def entries(path):
        if str(path) == "/proc/101/task":
            return iter(Path(tid) for tid in value["threads"])
        assert str(path) == "/proc/self/fd"
        return iter([Path("/proc/self/fd/99")])

    def link(path):
        text = str(path)
        if text == "/proc/self/fd/99":
            return value["watch_pipe"] if fault == "pipe" else "pipe:[9876]"
        ns = text.rsplit("/", 1)[1]
        return "host" if "/self/" in text or fault == ns else "worker"

    monkeypatch.setattr(Path, "iterdir", entries)
    monkeypatch.setattr(observer.os, "readlink", link)
    evidence = {}
    fd = os.open(cg, os.O_RDONLY)
    try:
        if fault is None:
            assert observer.fresh_binding(value, fd, 5, evidence) == value["threads"]
        else:
            with pytest.raises(ValueError, match="namespace shared|holds watchdog pipe"):
                observer.fresh_binding(value, fd, 5, evidence)
        assert evidence["threads"] == value["threads"]
    finally:
        os.close(fd)
