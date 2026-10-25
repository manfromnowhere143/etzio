"""Portable outcome controls; no guest, task pressure or cloud execution."""

import copy
import importlib.util
import json
import subprocess
from pathlib import Path

import pytest


@pytest.fixture
def observer(monkeypatch):
    scripts = Path(__file__).resolve().parents[1] / "scripts"
    monkeypatch.syspath_prepend(str(scripts))
    spec = importlib.util.spec_from_file_location(
        "owned_resource_control", scripts / "observe_owned_resource_containment.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def memory_record(observer, high=True):
    before = {
        "limits": dict(observer.MEMORY_LIMITS),
        "memory": {"max": 0, "oom": 0, "oom_kill": 0},
        "peak": 90000000,
        "host_available_kib": 4000000,
        "host_oom_kill": 3,
    }
    after = copy.deepcopy(before)
    after.update(peak=268435456, host_oom_kill=4 if high else 3)
    if high:
        after["memory"].update(max=20, oom=1, oom_kill=1)
    return {
        "mode": "memory-high" if high else "memory-low",
        "before": before,
        "after": after,
        "cgroup_path": "/etzio-resource/resource-12",
        "worker_pid": 101,
        "uid": 65012,
        "kernel_delta": (
            "oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),"
            "oom_memcg=/etzio-resource/resource-12,task_memcg=/etzio-resource/resource-12,"
            "task=firecracker,pid=101,uid=65012\n"
        )
        if high
        else "",
        "fallback": False,
        "ready": True,
        "done": not high,
        "alive_at_result": not high,
        "natural_exit": -9,
        "natural_empty": True,
        "natural_helper_exit": True,
    }


@pytest.mark.parametrize("high", [True, False])
def test_memory_calibration(observer, high):
    assert observer.memory_accepts(memory_record(observer, high))


@pytest.mark.parametrize(
    "field,value",
    [
        ("fallback", True),
        ("ready", False),
        ("done", True),
        ("natural_exit", 0),
        ("natural_exit", None),
        ("natural_empty", False),
        ("natural_helper_exit", False),
        ("worker_pid", 102),
        ("uid", 65013),
        ("cgroup_path", "/other"),
        ("kernel_delta", ""),
    ],
)
def test_memory_missing_or_substituted_effect_refused(observer, field, value):
    record = memory_record(observer)
    record[field] = value
    assert not observer.memory_accepts(record)


@pytest.mark.parametrize(
    "old,new",
    [
        ("CONSTRAINT_MEMCG", "CONSTRAINT_NONE"),
        ("task_memcg=/etzio-resource/resource-12", "task_memcg=/other"),
        ("pid=101", "pid=1010"),
        ("uid=65012", "uid=0"),
        ("oom_memcg=", "global_oom,oom_memcg="),
    ],
)
def test_wrong_kernel_oom_attribution_refused(observer, old, new):
    record = memory_record(observer)
    record["kernel_delta"] = record["kernel_delta"].replace(old, new)
    assert not observer.memory_accepts(record)


def test_two_victims_cannot_be_hidden_by_expected_summary(observer):
    record = memory_record(observer)
    record["kernel_delta"] *= 2
    assert not observer.memory_accepts(record)


@pytest.mark.parametrize(
    "field,value",
    [("peak", 402653185), ("peak", 0), ("host_available_kib", 500000), ("host_oom_kill", 3), ("host_oom_kill", 5)],
)
def test_memory_outer_bounds_and_system_counter(observer, field, value):
    record = memory_record(observer)
    record["after"][field] = value
    assert not observer.memory_accepts(record)


@pytest.mark.parametrize("field,value", [("max", 0), ("oom", 0), ("oom_kill", 0), ("oom_kill", 2)])
def test_memory_event_attribution_required(observer, field, value):
    record = memory_record(observer)
    record["after"]["memory"][field] = value
    assert not observer.memory_accepts(record)


@pytest.mark.parametrize("field,value", [("done", False), ("alive_at_result", False), ("fallback", True)])
def test_memory_positive_requires_live_completion(observer, field, value):
    record = memory_record(observer, False)
    record[field] = value
    assert not observer.memory_accepts(record)


def tasks_record(observer, high=True):
    children = list(range(102, 117 if high else 106))
    before = {
        "limits": dict(observer.TASK_LIMITS),
        "memory": {"oom": 0, "oom_kill": 0},
        "pids": {"max": 0},
        "host_oom_kill": 3,
    }
    after = copy.deepcopy(before)
    after.update(pids={"max": int(high)}, pids_current=len(children) + 1)
    return {
        "mode": "tasks-high" if high else "tasks-low",
        "worker_pid": 101,
        "before": before,
        "after": after,
        "report": {"children": children, "errno": 11 if high else 0, "nproc": [1024, 1024]},
        "host_children": list(children),
        "roster": [101, *children],
        "identities_bound": True,
        "fallback": False,
    }


@pytest.mark.parametrize("high", [True, False])
def test_task_calibration(observer, high):
    assert observer.tasks_accepts(tasks_record(observer, high))


@pytest.mark.parametrize(
    "field,value",
    [("roster", [101]), ("host_children", []), ("identities_bound", False), ("fallback", True), ("worker_pid", 117)],
)
def test_task_report_requires_host_identity_and_roster(observer, field, value):
    record = tasks_record(observer)
    record[field] = value
    assert not observer.tasks_accepts(record)


@pytest.mark.parametrize(
    "field,value",
    [
        ("errno", 12),
        ("errno", 0),
        ("errno", True),
        ("nproc", [16, 16]),
        ("children", list(range(101, 116))),
        ("children", [102] * 15),
    ],
)
def test_task_error_cannot_be_rlimit_memory_or_duplicated_children(observer, field, value):
    record = tasks_record(observer)
    record["report"][field] = value
    assert not observer.tasks_accepts(record)


@pytest.mark.parametrize(
    "field,value",
    [
        ("pids", {"max": 0}),
        ("pids", {"max": 2}),
        ("pids_current", 15),
        ("host_oom_kill", 4),
        ("memory", {"oom": 1, "oom_kill": 0}),
    ],
)
def test_task_limit_attribution_required(observer, field, value):
    record = tasks_record(observer)
    record["after"][field] = value
    assert not observer.tasks_accepts(record)


@pytest.mark.parametrize("mode", ["memory-low", "tasks-high"])
@pytest.mark.parametrize("phase", ["before", "after"])
def test_limits_cannot_drift(observer, mode, phase):
    record = memory_record(observer, False) if mode == "memory-low" else tasks_record(observer)
    record[phase]["limits"]["memory.max"] = "max"
    assert not (observer.memory_accepts(record) if mode == "memory-low" else observer.tasks_accepts(record))


@pytest.mark.parametrize("before,after", [(b"prior\n", b"next\n"), (b"prior\n", b"prior\n" + b"x" * 32769)])
def test_kernel_log_rollover_and_overflow_refuse(observer, before, after):
    with pytest.raises(ValueError, match="kernel"):
        observer.log_delta(before, after)


def test_kernel_delta_preserves_only_new_bytes(observer):
    assert observer.log_delta(b"prior\n", b"prior\nnew\n") == "new\n"


def test_prior_dmesg_option_failure_is_calibrated_before_positive_read(observer, monkeypatch):
    calls = []

    def command(argv, **_kwargs):
        calls.append(argv)
        if "--notime" in argv:
            return subprocess.CompletedProcess(argv, 1, b"", b"dmesg: mutually exclusive arguments: --notime --raw\n")
        return subprocess.CompletedProcess(argv, 0, b"<6>[0.001] owned kernel record\n", b"")

    monkeypatch.setattr(observer.subprocess, "run", command)
    value = observer.kernel_log_calibration()
    assert value["old_command_exit"] == 1 and value["readable_bytes"] > 0
    assert calls == [["dmesg", "--raw", "--notime"], ["dmesg", "--raw"]]


@pytest.mark.parametrize(
    "code,stdout,stderr", [(1, b"", b"permission denied"), (0, b"x" * 262145, b""), (0, b"data", b"warning")]
)
def test_kernel_log_error_or_truncation_cannot_be_empty_success(observer, monkeypatch, code, stdout, stderr):
    monkeypatch.setattr(
        observer.subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(args[0], code, stdout, stderr)
    )
    with pytest.raises((RuntimeError, ValueError), match="kernel log"):
        observer.kernel_log()


@pytest.mark.parametrize("text", ["oom 1\noom 2\n", "oom -1\n", "oom true\n", "oom 1 2\n"])
def test_ambiguous_counter_refused(observer, text):
    with pytest.raises(ValueError):
        observer.counters(text)


@pytest.mark.parametrize("mode", ["target", "../memory-low", True, None])
def test_unknown_modes_refused_before_resources(observer, mode):
    with pytest.raises(ValueError, match="closed owned"):
        observer.Case(mode)


@pytest.mark.parametrize(
    "field,value", [("system", "Darwin"), ("machine", "aarch64"), ("release", "6.10.0"), ("getuid", 501)]
)
def test_host_guard_precedes_native_calls(observer, monkeypatch, field, value):
    monkeypatch.setattr(observer.platform, "system", lambda: "Linux")
    monkeypatch.setattr(observer.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(observer.platform, "release", lambda: "6.1.0")
    monkeypatch.setattr(observer.os, "getuid", lambda: 0)
    monkeypatch.setattr(observer.os if field == "getuid" else observer.platform, field, lambda: value)
    monkeypatch.setattr(observer.guest, "set_subreaper", lambda: pytest.fail("native call before refusal"))
    with pytest.raises(RuntimeError):
        observer.collect()


@pytest.mark.parametrize("kind", ["missing", "altered", "symlink", "directory"])
def test_resource_pin_guard_precedes_native_calls(observer, monkeypatch, tmp_path, kind):
    monkeypatch.setattr(observer.platform, "system", lambda: "Linux")
    monkeypatch.setattr(observer.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(observer.platform, "release", lambda: "6.1.0")
    monkeypatch.setattr(observer.os, "getuid", lambda: 0)
    monkeypatch.setattr(observer, "ROOT", tmp_path)
    monkeypatch.setattr(observer.guest, "set_subreaper", lambda: pytest.fail("native call before pin refusal"))
    path = tmp_path / "firecracker"
    if kind == "altered":
        path.write_bytes(b"owned wrong bytes")
    elif kind == "symlink":
        (tmp_path / "other").write_bytes(b"owned bytes")
        path.symlink_to(tmp_path / "other")
    elif kind == "directory":
        path.mkdir()
    with pytest.raises(RuntimeError, match="artifact pin mismatch"):
        observer.collect()


@pytest.mark.parametrize(
    "config",
    [
        {"vcpu_count": 1, "mem_size_mib": 128, "smt": False},
        {"vcpu_count": True, "mem_size_mib": 512, "smt": False},
        {"vcpu_count": 1, "mem_size_mib": 512, "smt": 0},
        {"vcpu_count": 1, "mem_size_mib": 512, "smt": False},
    ],
)
def test_separate_memory_profile_does_not_relax_old_barrier(observer, monkeypatch, config):
    class Connection:
        status = 200

        def __init__(self, _path):
            self.closed = False

        def request(self, *_args):
            pass

        def getresponse(self):
            return self

        def read(self, _count):
            return json.dumps(config).encode()

        def close(self):
            self.closed = True

    monkeypatch.setattr(observer.guest, "LocalAPI", Connection)
    if (
        config == {"vcpu_count": 1, "mem_size_mib": 512, "smt": False}
        and type(config["vcpu_count"]) is int
        and type(config["smt"]) is bool
    ):
        assert observer.runtime_barrier("owned") == config
        with pytest.raises(RuntimeError, match="configuration"):
            observer.guest.runtime_barrier("owned")
    else:
        with pytest.raises(ValueError, match="configuration"):
            observer.runtime_barrier("owned")
