"""Finite owned resource controls on the selected disposable host; no target input."""

import base64
import ctypes
import hashlib
import json
import os
import platform
import re
import resource
import select
import signal
import subprocess
import sys
import time
from contextlib import closing
from pathlib import Path

import collect_owned_firecracker_preflight as guest
import observe_owned_collector_death as death

ROOT = guest.ROOT
CGROOT = Path("/sys/fs/cgroup/etzio-resource")
PINS = {k: guest.PINS[k] for k in ("firecracker", "jailer", "vmlinux")} | {
    "memory-low.cpio": "eea36941182a37d2a069744f04003ccd08b59a05abb54a9abe222de54792ab1f",
    "memory-high.cpio": "6c45eef6f09be0abb52fd049958453512c920bf7bd59a9a8c88f1cf127c3e6b6",
}
READY = b"ETZIO_MEMORY_READY_V1\r\n"
DONE = b"ETZIO_MEMORY_DONE_V1\r\n"
MEMORY_LIMITS = dict(guest.LIMITS)
TASK_LIMITS = MEMORY_LIMITS | {"memory.max": "134217728", "pids.max": "16"}
CASES = {"memory-low": 11, "memory-high": 12, "tasks-low": 13, "tasks-high": 14}
LINUX_EAGAIN = 11  # The observed host is Linux, including when predicates run on macOS.


def counters(text):
    result = {}
    for line in text.splitlines():
        key, value = line.split()
        if key in result or not value.isascii() or not value.isdecimal():
            raise ValueError("invalid counter observation")
        result[key] = int(value)
    return result


def runtime_barrier(path):
    with closing(guest.LocalAPI(path)) as conn:
        conn.request("GET", "/machine-config")
        response = conn.getresponse()
        wire = response.read(4097)
        if response.status != 200 or len(wire) > 4096:
            raise ValueError("memory runtime barrier response")
        config = json.loads(wire, object_pairs_hook=death.closed_object)
        expected = {"vcpu_count": 1, "mem_size_mib": 512, "smt": False}
        if type(config) is not dict or any(
            type(config.get(k)) is not type(v) or config[k] != v for k, v in expected.items()
        ):
            raise ValueError("memory runtime barrier configuration")
        return config


def oom_summary(delta, cgroup, pid, uid):
    summaries = [line.split("oom-kill:", 1)[1] for line in delta.splitlines() if "oom-kill:" in line]
    if len(summaries) != 1:
        raise ValueError("missing or additional OOM victim")
    fields = dict(item.split("=", 1) for item in summaries[0].split(",") if "=" in item)
    expected = {
        "constraint": "CONSTRAINT_MEMCG",
        "oom_memcg": cgroup,
        "task_memcg": cgroup,
        "pid": str(pid),
        "uid": str(uid),
    }
    if any(fields.get(k) != v for k, v in expected.items()) or ",global_oom" in summaries[0]:
        raise ValueError("OOM victim/cgroup attribution")
    return fields


def memory_accepts(record):
    try:
        high = record["mode"] == "memory-high"
        if record["mode"] not in ("memory-low", "memory-high"):
            return False
        before, after = record["before"], record["after"]
        if before["limits"] != MEMORY_LIMITS or after["limits"] != MEMORY_LIMITS:
            return False
        if not 0 < after["peak"] <= 384 * 1024**2 or after["peak"] < before["peak"]:
            return False
        if min(before["host_available_kib"], after["host_available_kib"]) < 1024**2:
            return False
        events = {k: after["memory"][k] - before["memory"][k] for k in before["memory"]}
        if any(v < 0 for v in events.values()) or any(before["memory"][k] for k in ("oom", "oom_kill")):
            return False
        if after["host_oom_kill"] - before["host_oom_kill"] != int(high):
            return False
        if record["fallback"] is not False or record["ready"] is not True:
            return False
        if high:
            oom_summary(record["kernel_delta"], record["cgroup_path"], record["worker_pid"], record["uid"])
            return (
                events["max"] > 0
                and events["oom"] > 0
                and events["oom_kill"] == 1
                and record["natural_exit"] == -signal.SIGKILL
                and record["natural_empty"] is True
                and record["natural_helper_exit"] is True
                and record["done"] is False
            )
        return (
            events["oom"] == events["oom_kill"] == 0
            and "oom-kill:" not in record["kernel_delta"]
            and record["done"] is True
            and record["alive_at_result"] is True
        )
    except (KeyError, TypeError, ValueError):
        return False


def tasks_accepts(record):
    try:
        high = record["mode"] == "tasks-high"
        if record["mode"] not in ("tasks-low", "tasks-high"):
            return False
        report, before, after = record["report"], record["before"], record["after"]
        count = 15 if high else 4
        children = report["children"]
        roster = record["roster"]
        if (
            type(children) is not list
            or len(children) != count
            or len(set(children)) != count
            or any(type(x) is not int or x <= 0 for x in children)
        ):
            return False
        if (
            type(report["errno"]) is not int
            or report["errno"] != (LINUX_EAGAIN if high else 0)
            or report["nproc"] != [1024, 1024]
        ):
            return False
        if set(children + [record["worker_pid"]]) != set(roster) or len(roster) != count + 1:
            return False
        if sorted(record["host_children"]) != sorted(children) or after["pids_current"] != count + 1:
            return False
        if before["limits"] != TASK_LIMITS or after["limits"] != TASK_LIMITS:
            return False
        if after["pids"]["max"] - before["pids"]["max"] != int(high):
            return False
        if any(after["memory"][k] != before["memory"][k] for k in ("oom", "oom_kill")):
            return False
        if after["host_oom_kill"] != before["host_oom_kill"]:
            return False
        return record["fallback"] is False and record["identities_bound"] is True
    except (KeyError, TypeError, ValueError):
        return False


def snapshot(fd, limits):
    meminfo = Path("/proc/meminfo").read_text()
    available = re.search(r"^MemAvailable:\s+(\d+) kB$", meminfo, re.M)
    if available is None:
        raise ValueError("missing host memory observation")
    return {
        "limits": {key: death.cg_read(fd, key).strip() for key in limits},
        "memory": counters(death.cg_read(fd, "memory.events.local")),
        "peak": int(death.cg_read(fd, "memory.peak")),
        "current": int(death.cg_read(fd, "memory.current")),
        "pids": counters(death.cg_read(fd, "pids.events")),
        "pids_current": int(death.cg_read(fd, "pids.current")),
        "cpu": counters(death.cg_read(fd, "cpu.stat")),
        "host_oom_kill": counters(Path("/proc/vmstat").read_text())["oom_kill"],
        "host_available_kib": int(available[1]),
    }


def kernel_log():
    result = subprocess.run(["dmesg", "--raw"], capture_output=True, timeout=3)
    if result.returncode:
        raise RuntimeError(f"kernel log read failed: {result.returncode}: {result.stderr[:400]!r}")
    if len(result.stdout) > 262144 or result.stderr:
        raise ValueError("kernel log bound")
    return result.stdout


def kernel_log_calibration():
    # Retain the actual old CLI failure before a guest is started. util-linux
    # v2.38.1 marks -r and -t mutually exclusive; this is not a kernel refusal.
    bad = subprocess.run(
        ["dmesg", "--raw", "--notime"],
        capture_output=True,
        timeout=3,
        env={"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
    )
    if bad.returncode != 1 or len(bad.stderr) > 4096 or b"mutually exclusive" not in bad.stderr:
        raise ValueError("old kernel-log CLI failure calibration")
    good = kernel_log()
    return {
        "old_command_exit": bad.returncode,
        "old_command_stderr": bad.stderr.decode(),
        "readable_bytes": len(good),
        "readable_sha256": hashlib.sha256(good).hexdigest(),
    }


def log_delta(before, after):
    if not after.startswith(before):
        raise ValueError("kernel log rollover/substitution")
    delta = after[len(before) :]
    if len(delta) > 32768:
        raise ValueError("kernel delta bound")
    return delta.decode()


def watchdog(cgfd, readfd, path):
    reason = "deadline"
    if select.select([readfd], [], [], 45)[0]:
        reason = "collector_pipe_closed" if os.read(readfd, 1) == b"" else "explicit_stop"
    observed = time.monotonic_ns()
    death.cg_kill(cgfd)
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline and not death.cg_empty(cgfd):
        time.sleep(0.01)
    path.write_text(
        json.dumps(
            {
                "reason": reason,
                "empty": death.cg_empty(cgfd),
                "observed_ns": observed,
                "completed_ns": time.monotonic_ns(),
            }
        )
    )


def task_setup(fd, uid):
    member = os.open("cgroup.procs", os.O_WRONLY, dir_fd=fd)
    os.write(member, str(os.getpid()).encode())
    os.close(member)
    os.close(fd)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.unshare(0x40000000) or libc.prctl(38, 1, 0, 0, 0):
        raise OSError(ctypes.get_errno(), "owned task namespace/NoNewPrivs")
    resource.setrlimit(resource.RLIMIT_NPROC, (1024, 1024))
    os.setgroups([])
    os.setgid(uid)
    os.setuid(uid)


def task_worker(mode):
    if mode not in ("tasks-low", "tasks-high") or os.getuid() != 65000 + CASES[mode]:
        raise ValueError("closed owned task helper identity")
    status = guest.read_status(os.getpid())
    if status["CapEff"] != "0000000000000000" or status["NoNewPrivs"] != "1":
        raise ValueError("owned task helper privilege")
    children, error = [], 0
    for _ in range(32 if mode == "tasks-high" else 4):
        try:
            pid = os.fork()
        except OSError as exc:
            error = exc.errno
            break
        if pid == 0:
            os.close(1)
            os.close(2)
            while True:
                signal.pause()
        children.append(pid)
    print(
        json.dumps({"children": children, "errno": error, "nproc": resource.getrlimit(resource.RLIMIT_NPROC)}),
        flush=True,
    )
    while True:
        signal.pause()


class Case:
    def __init__(self, mode):
        if type(mode) is not str or mode not in CASES:
            raise ValueError("closed owned resource case")
        self.mode, self.ordinal = mode, CASES[mode]
        self.uid = 65000 + self.ordinal
        self.name = "resource-" + str(self.ordinal)
        self.cg = CGROOT / self.name
        self.limits = MEMORY_LIMITS if mode.startswith("memory-") else TASK_LIMITS
        self.fd = self.writefd = None
        self.watcher = self.proc = None
        self.netns = None
        self.bindings, self.identities, self.reaped = {}, {}, {}
        self.output = b""
        self.result = {
            "mode": mode,
            "uid": self.uid,
            "passed": False,
            "fallback": False,
            "cgroup_path": "/etzio-resource/" + self.name,
        }

    def setup(self):
        self.cg.mkdir()
        self.fd = os.open(self.cg, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for key, value in self.limits.items():
            (self.cg / key).write_text(value)
        self.result["initial"] = snapshot(self.fd, self.limits)
        if self.result["initial"]["limits"] != self.limits or not death.cg_empty(self.fd):
            raise ValueError("initial resource group")
        readfd, self.writefd = os.pipe()
        try:
            self.watcher = subprocess.Popen(
                [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--watch",
                    str(self.fd),
                    str(readfd),
                    str(ROOT / (self.name + "-watch.json")),
                ],
                pass_fds=(self.fd, readfd),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        finally:
            os.close(readfd)

    def bind(self, pid, role):
        identity = guest.process_identity(pid)
        self.bindings[role] = death.bind_process(identity)
        self.identities[role] = identity
        self.result["identities"] = self.identities

    def read_output(self):
        if select.select([self.proc.stdout], [], [], 0.02)[0]:
            self.output += os.read(self.proc.stdout.fileno(), 4096)
            if len(self.output) > 65536:
                raise ValueError("owned output bound")

    def memory(self):
        jail = ROOT / "jails/firecracker" / self.name / "root"
        jail.mkdir(parents=True, mode=0o555)
        guest.prepare_inputs(jail, self.mode)
        (jail / "run").mkdir(mode=0o700)
        os.chown(jail / "run", self.uid, self.uid)
        self.netns = "etzio-" + self.name
        guest.command("ip", "netns", "add", self.netns)
        links = json.loads(guest.command("ip", "-n", self.netns, "-j", "link", "show"))
        if [x["ifname"] for x in links] != ["lo"]:
            raise ValueError("owned network interface roster")
        self.proc = subprocess.Popen(
            [
                str(ROOT / "jailer"),
                "--id",
                self.name,
                "--exec-file",
                str(ROOT / "firecracker"),
                "--uid",
                str(self.uid),
                "--gid",
                str(self.uid),
                "--chroot-base-dir",
                str(ROOT / "jails"),
                "--cgroup-version",
                "2",
                "--parent-cgroup",
                "etzio-resource/" + self.name,
                "--netns",
                "/var/run/netns/" + self.netns,
                "--new-pid-ns",
                "--resource-limit",
                "fsize=1048576",
                "--resource-limit",
                "no-file=128",
                "--",
                "--api-sock",
                "/run/api.sock",
            ],
            env={},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        api, deadline = jail / "run/api.sock", time.monotonic() + 8
        while not api.exists() and time.monotonic() < deadline:
            self.read_output()
        if not api.exists():
            raise ValueError("owned memory API readiness")
        members = death.cg_read(self.fd, "cgroup.procs").split()
        if len(members) != 1:
            raise ValueError("preboot cgroup membership")
        pid = int(members[0])
        self.result["worker_pid"] = pid
        self.result["launcher_exit"] = guest.reap_launcher(self.proc)
        self.bind(pid, "worker")
        self.result["namespaces"] = {}
        for ns in ("mnt", "net", "pid"):
            value = os.readlink(f"/proc/{pid}/ns/{ns}")
            self.result["namespaces"][ns] = value
            if value == os.readlink(f"/proc/self/ns/{ns}"):
                raise ValueError("worker shares host namespace")
        guest.put(api, "/machine-config", {"vcpu_count": 1, "mem_size_mib": 512, "smt": False})
        guest.put(
            api,
            "/boot-source",
            {
                "kernel_image_path": "/inputs/kernel",
                "initrd_path": "/inputs/initrd",
                "boot_args": "console=ttyS0 reboot=k panic=1 nomodule loglevel=1 init=/init",
            },
        )
        guest.put(api, "/actions", {"action_type": "InstanceStart"})
        self.result["machine_config"] = runtime_barrier(api)
        self.result["threads"] = {p.name: guest.read_status(p.name) for p in Path(f"/proc/{pid}/task").iterdir()}
        death.validate_threads(self.result["threads"], self.ordinal)
        members = [int(x) for x in death.cg_read(self.fd, "cgroup.procs").split()]
        if len(members) != 2 or pid not in members:
            raise ValueError("running VMM/helper membership")
        helper = next(x for x in members if x != pid)
        self.result["helper"] = death.kernel_helper_snapshot(helper)
        death.validate_kernel_helper(self.result["helper"], pid)
        self.bind(helper, "helper")
        for member in members:
            if Path(f"/proc/{member}/cgroup").read_text().strip() != "0::" + self.result["cgroup_path"]:
                raise ValueError("cgroup path attribution")
        deadline = time.monotonic() + 12
        while not guest.marker_observed(self.output, READY) and time.monotonic() < deadline:
            self.read_output()
        self.result["ready"] = guest.marker_observed(self.output, READY)
        if not self.result["ready"] or guest.marker_observed(self.output, DONE):
            raise ValueError("memory pressure readiness window")
        before_log = kernel_log()
        self.result["kernel_before"] = {"bytes": len(before_log), "sha256": hashlib.sha256(before_log).hexdigest()}
        self.result["before"] = snapshot(self.fd, self.limits)
        if select.select([self.bindings["worker"]], [], [], 0)[0]:
            raise ValueError("worker exited before pressure baseline")
        deadline = time.monotonic() + 18
        while time.monotonic() < deadline:
            self.read_output()
            self.result["done"] = guest.marker_observed(self.output, DONE)
            if self.mode == "memory-low" and self.result["done"]:
                self.result["alive_at_result"] = not bool(select.select([self.bindings["worker"]], [], [], 0)[0])
                break
            if self.mode == "memory-high" and select.select([self.bindings["worker"]], [], [], 0)[0]:
                death.reap(pid, self.reaped, "worker")
                if death.cg_empty(self.fd) and select.select([self.bindings["helper"]], [], [], 0)[0]:
                    self.result.update(
                        natural_exit=self.reaped.get("worker"), natural_empty=True, natural_helper_exit=True
                    )
                    break
        else:
            self.result["fallback"] = True
            raise TimeoutError("memory result deadline")
        self.result["after"] = snapshot(self.fd, self.limits)
        self.result["kernel_delta"] = log_delta(before_log, kernel_log())
        self.result["effect_accepted"] = memory_accepts(self.result)

    def tasks(self):
        self.result["before"] = snapshot(self.fd, self.limits)
        self.proc = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "--tasks", self.mode],
            preexec_fn=lambda: task_setup(self.fd, self.uid),
            pass_fds=(self.fd,),
            env={},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        pid = self.proc.pid
        self.result["worker_pid"] = pid
        deadline = time.monotonic() + 8
        while b"\n" not in self.output and time.monotonic() < deadline:
            self.read_output()
        if len(self.output) > 4096 or not self.output.endswith(b"\n") or self.output.count(b"\n") != 1:
            raise ValueError("owned task report framing")
        report = json.loads(self.output, object_pairs_hook=death.closed_object)
        if type(report) is not dict or set(report) != {"children", "errno", "nproc"}:
            raise ValueError("owned task report fields")
        self.result["report"] = report
        roster = [int(x) for x in death.cg_read(self.fd, "cgroup.procs").split()]
        self.result["roster"] = roster
        self.result["host_children"] = [int(x) for x in Path(f"/proc/{pid}/task/{pid}/children").read_text().split()]
        self.result["processes"] = {}
        network = os.readlink(f"/proc/{pid}/ns/net")
        if network == os.readlink("/proc/self/ns/net"):
            raise ValueError("task helper shares host network")
        for member in roster:
            self.bind(member, "worker" if member == pid else str(member))
            status = guest.read_status(member)
            self.result["processes"][str(member)] = status
            if (
                status["Uid"].split() != [str(self.uid)] * 4
                or status["Gid"].split() != [str(self.uid)] * 4
                or status["CapEff"] != "0000000000000000"
                or status["NoNewPrivs"] != "1"
                or os.readlink(f"/proc/{member}/ns/net") != network
            ):
                raise ValueError("task process credentials/namespace")
            if member != pid and self.identities[str(member)]["parent"] != pid:
                raise ValueError("task child ancestry")
        self.result["identities_bound"] = True
        self.result["after"] = snapshot(self.fd, self.limits)
        self.result["effect_accepted"] = tasks_accepts(self.result)

    def cleanup(self):
        if self.fd is None:
            return
        started = time.monotonic()
        death.cg_kill(self.fd)
        if self.writefd is not None:
            try:
                os.write(self.writefd, b"s")
            finally:
                os.close(self.writefd)
        if self.proc:
            # Popen owns the direct task parent or the already reaped jailer.
            code = self.proc.wait(timeout=3)
            if self.mode.startswith("tasks-"):
                self.reaped["worker"] = code
            self.proc.stdout.close()
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            for role, identity in self.identities.items():
                if role != "helper":
                    death.reap(identity["pid"], self.reaped, role)
            required = set(self.identities) - {"helper"}
            if required <= set(self.reaped) and death.cg_empty(self.fd):
                break
            time.sleep(0.01)
        self.result["cleanup"] = {
            "empty": death.cg_empty(self.fd),
            "reaped": self.reaped,
            "seconds": time.monotonic() - started,
        }
        helper_exit = "helper" not in self.bindings or bool(select.select([self.bindings["helper"]], [], [], 0)[0])
        if self.watcher:
            self.result["watcher_exit"] = self.watcher.wait(timeout=5)
            self.result["watchdog"] = json.loads((ROOT / (self.name + "-watch.json")).read_text())
        self.result["passed"] = (
            self.result.get("effect_accepted") is True
            and self.result["cleanup"]["empty"]
            and set(self.reaped) == set(self.identities) - {"helper"}
            and all(x == -signal.SIGKILL for x in self.reaped.values())
            and helper_exit
            and self.result.get("watcher_exit") == 0
            and self.result["watchdog"]["reason"] == "explicit_stop"
            and self.result["watchdog"]["empty"] is True
        )
        for fd in self.bindings.values():
            os.close(fd)
        os.close(self.fd)
        if self.netns:
            guest.command("ip", "netns", "delete", self.netns)
        self.cg.rmdir()

    def run(self):
        try:
            self.setup()
            self.memory() if self.mode.startswith("memory-") else self.tasks()
        except BaseException as exc:
            self.result["error"] = {"type": type(exc).__name__, "message": str(exc)[:600]}
        finally:
            try:
                self.cleanup()
            except BaseException as exc:
                self.result["passed"] = False
                self.result["cleanup_error"] = {"type": type(exc).__name__, "message": str(exc)[:600]}
            self.result["output_b64"] = base64.b64encode(self.output[:65536]).decode()
            if "error" in self.result:
                self.result["passed"] = False
        return self.result


def require_host():
    if platform.system() != "Linux" or platform.machine() != "x86_64" or os.getuid() != 0:
        raise RuntimeError("requires the specified disposable Linux x86_64 root host")
    if not platform.release().startswith("6.1."):
        raise RuntimeError("host kernel is outside the selected 6.1 profile")
    for name, digest in PINS.items():
        path = ROOT / name
        if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise RuntimeError("artifact pin mismatch: " + name)
    guest.set_subreaper()


def collect():
    require_host()
    kernel_capability = kernel_log_calibration()
    base = Path("/sys/fs/cgroup")
    (base / "cgroup.subtree_control").write_text("+cpu +memory +pids")
    CGROOT.mkdir()
    (CGROOT / "cgroup.subtree_control").write_text("+cpu +memory +pids")
    result = {
        "schema": "etzio.owned-resource.observation.v1",
        "kernel": platform.release(),
        "kernel_log_capability": kernel_capability,
        "pins": PINS,
        "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "dependency_sha256": {
            "collect_owned_firecracker_preflight.py": hashlib.sha256(Path(guest.__file__).read_bytes()).hexdigest(),
            "observe_owned_collector_death.py": hashlib.sha256(Path(death.__file__).read_bytes()).hexdigest(),
        },
        "cases": [],
        "claim": "Owned resource controls only; not an accepted target profile or independent reproduction.",
    }
    for mode in CASES:
        case = Case(mode).run()
        result["cases"].append(case)
        if not case["passed"]:
            break
    try:
        CGROOT.rmdir()
    except OSError as exc:
        result["cleanup_error"] = str(exc)[:600]
    result["all_controls_passed"] = (
        len(result["cases"]) == 4 and all(x["passed"] for x in result["cases"]) and "cleanup_error" not in result
    )
    return result


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "--watch":
        watchdog(int(sys.argv[2]), int(sys.argv[3]), Path(sys.argv[4]))
    elif len(sys.argv) == 3 and sys.argv[1] == "--tasks":
        task_worker(sys.argv[2])
    elif len(sys.argv) == 1:
        try:
            result = collect()
        except BaseException as exc:
            result = {"all_controls_passed": False, "error": {"type": type(exc).__name__, "message": str(exc)[:600]}}
        print(json.dumps(result, sort_keys=True), flush=True)
    else:
        raise SystemExit("closed owned resource observer")
