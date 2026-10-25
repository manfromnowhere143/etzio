"""Closed disposable-host observation. Only the four owned initrd fixtures run.

This is not an admitted target runner. Invoke only after staged artifact identity,
cloud egress removal and exact disposable host identity have been checked.
"""

import base64
import ctypes
import hashlib
import http.client
import json
import os
import platform
import select
import shutil
import signal
import socket
import subprocess
import time
from contextlib import closing
from pathlib import Path

ROOT = Path("/opt/etzio-owned")
CGROOT = Path("/sys/fs/cgroup/etzio-owned")
PINS = {
    "firecracker": "99ad0f5cd0514a88aad0e9ae8cfdb3cc3b4ab9d190e1194602406c786b5de7a5",
    "jailer": "65ef226e96f0ceda55ba643f445801ef2cc0ea667ef67cad8ac4f406c9c8434f",
    "vmlinux": "da5e0041fb31fcc7337026da9e2b64fb7694b4eed760cc9b5e8fe54e52fa8188",
    "ready.cpio": "0ebe96565bc13874d342a711e239579cabce9e83bd9942ea50e9809b0a22b556",
    "wrong.cpio": "1f05fb9e7a9ba0ca3466b554fed114fa8294aefdca372d0124c1affd436ccb13",
    "spin.cpio": "b9f97806803bdd9e7b0d8f6a61d0edefcd1c9e75f48d1e3d832e110215cc0673",
    "output.cpio": "a2c7993868ac3cdb07356c2b676122909d1e3bd4e3e7755c7b7e0267bbb93dd3",
}
LIMITS = {"memory.max": "268435456", "memory.swap.max": "0", "pids.max": "32", "cpu.max": "20000 100000"}
# The pinned guest console emits CRLF for the fixture's LF write.
READY = b"ETZIO_OWNED_READY_V1\r\n"
WRONG = b"ETZIO_OWNED_WRONG_V1\r\n"


def marker_observed(output, marker):
    return output.startswith(marker) or b"\n" + marker in output


def command(*args):
    r = subprocess.run(args, check=True, capture_output=True, timeout=15)
    if len(r.stdout) + len(r.stderr) > 65536:
        raise RuntimeError("command output exceeds bound")
    return r.stdout.decode()


def read_status(pid):
    return {
        line.split(":", 1)[0]: line.split(":", 1)[1].strip()
        for line in Path(f"/proc/{pid}/status").read_text().splitlines()
        if line.startswith(("Name:", "Uid:", "Gid:", "CapEff:", "NoNewPrivs:", "Seccomp:", "NSpid:"))
    }


class LocalAPI(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=2)
        self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(2)
        self.sock.connect(self.path)


def put(path, endpoint, data):
    with closing(LocalAPI(path)) as conn:
        conn.request("PUT", endpoint, json.dumps(data), {"Content-Type": "application/json"})
        response = conn.getresponse()
        wire = response.read(4097)
        if response.status != 204 or len(wire) > 4096:
            raise RuntimeError(f"API {endpoint}: {response.status} {wire[:500]!r}")


def runtime_barrier(path):
    # InstanceStart's response precedes installation of the VMM thread filter
    # in the pinned release. A runtime VMM request is processed only afterwards.
    with closing(LocalAPI(path)) as conn:
        conn.request("GET", "/machine-config")
        response = conn.getresponse()
        wire = response.read(4097)
        if response.status != 200 or len(wire) > 4096:
            raise RuntimeError("runtime barrier response status/size")
        config = json.loads(wire)
        expected = {"vcpu_count": 1, "mem_size_mib": 128, "smt": False}
        if type(config) is not dict or any(
            type(config.get(k)) is not type(v) or config.get(k) != v for k, v in expected.items()
        ):
            raise RuntimeError("runtime barrier machine configuration mismatch")
        return config


def kill_group(cg):
    (cg / "cgroup.kill").write_text("1")
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if "populated 0" in (cg / "cgroup.events").read_text():
            return True
        time.sleep(0.01)
    return False


def prepare_inputs(jail, mode):
    inputs = jail / "inputs"
    inputs.mkdir(mode=0o700)
    for src, dst in [("vmlinux", "kernel"), (mode + ".cpio", "initrd")]:
        shutil.copyfile(ROOT / src, inputs / dst)
        (inputs / dst).chmod(0o444)
    # Publish the complete inputs with exact traversal permission after copying.
    # mkdir's mode alone is filtered by the restrictive startup umask.
    inputs.chmod(0o555)


def process_identity(pid):
    # comm may contain spaces and parentheses; fields after its final ')' start
    # at stat field 3. starttime is field 22, not a wall-clock timestamp.
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return {"pid": pid, "parent": int(fields[1]), "start_ticks": int(fields[19])}


def reap_launcher(proc):
    code = proc.wait(timeout=2)
    if code != 0:
        raise RuntimeError("owned jailer launcher did not exit successfully")
    return code


def hold_for_crash_probe(fd, ordinal, pid, watcher, cg, write_fd, result, output):
    if not result["passed"] or len(output) > 4096:
        raise RuntimeError("owned crash readiness prerequisite failed")
    st = cg.stat()
    ready = {
        "schema": "etzio.owned-collector-ready.v1",
        "ordinal": ordinal,
        "launcher_exit_code": result["launcher_exit_code"],
        "collector": process_identity(os.getpid()),
        "worker": process_identity(pid),
        "watchdog": process_identity(watcher.pid) if watcher else None,
        "cgroup": {"device": st.st_dev, "inode": st.st_ino},
        "watch_pipe": os.readlink(f"/proc/self/fd/{write_fd}") if write_fd is not None else None,
        "threads": result["poststart_threads"],
        "output_b64": base64.b64encode(output).decode(),
    }
    wire = json.dumps(ready, sort_keys=True).encode()
    if len(wire) > 16384:
        raise RuntimeError("owned crash readiness size")
    view = memoryview(wire)
    while view:
        view = view[os.write(fd, view):]
    os.close(fd)
    while True:
        signal.pause()


def collect_case(mode, ordinal, *, crash_probe_fd=None):
    if mode not in ("ready", "wrong", "spin", "output"):
        raise ValueError("closed owned fixture set")
    if crash_probe_fd is not None and (
        mode != "ready" or type(ordinal) is not int or ordinal not in (5, 6)
        or type(crash_probe_fd) is not int or crash_probe_fd < 3
    ):
        raise ValueError("closed owned collector-death probe")
    uid = 65000 + ordinal
    name = "owned-" + str(ordinal)
    cg = CGROOT / name
    cg.mkdir()
    for key, value in LIMITS.items():
        (cg / key).write_text(value)
    observed_limits = {key: (cg / key).read_text().strip() for key in LIMITS}
    if observed_limits != LIMITS or (cg / "cgroup.procs").read_text().strip():
        raise RuntimeError("missing/incorrect cgroup limits or preexisting processes")
    jail = ROOT / "jails" / "firecracker" / name / "root"
    jail.mkdir(parents=True, mode=0o555)
    prepare_inputs(jail, mode)
    (jail / "run").mkdir(mode=0o700)
    os.chown(jail / "run", uid, uid)
    netns = "etzio-" + name
    command("ip", "netns", "add", netns)
    links = json.loads(command("ip", "-n", netns, "-j", "link", "show"))
    if [x["ifname"] for x in links] != ["lo"]:
        raise RuntimeError("network namespace contains non-loopback interface")
    # Separate root watchdog: it closes the cgroup on collector death or 45s,
    # and has no model or target input. This is not separate administration.
    # Ordinal 6 is a deliberately withheld watchdog, reachable only through the
    # separate bounded owned crash observer. Ordinary controls always have one.
    watcher = None
    write_fd = None
    watch_source = """import os,select,sys,time,pathlib,json
cg=int(sys.argv[1]); fd=int(sys.argv[2]); out=pathlib.Path(sys.argv[3])
def empty():
 f=os.open('cgroup.events',os.O_RDONLY,dir_fd=cg)
 try:return b'populated 0' in os.read(f,4096)
 finally:os.close(f)
reason='deadline'
if select.select([fd],[],[],45)[0]:
 reason='collector_pipe_closed' if os.read(fd,1)==b'' else 'explicit_stop'
observed=time.monotonic_ns()
os.close(fd); k=os.open('cgroup.kill',os.O_WRONLY,dir_fd=cg)
try:os.write(k,b'1')
finally:os.close(k)
end=time.monotonic()+3
while time.monotonic()<end and not empty():time.sleep(.01)
out.write_text(json.dumps({'reason':reason,'empty':empty(),
 'observed_ns':observed,'completed_ns':time.monotonic_ns()}))
"""
    if not (crash_probe_fd is not None and ordinal == 6):
        read_fd, write_fd = os.pipe()
        cg_fd = os.open(cg, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            watcher = subprocess.Popen(
                ["python3", "-c", watch_source, str(cg_fd), str(read_fd), str(ROOT / (name + "-watch.json"))],
                pass_fds=(read_fd, cg_fd),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        finally:
            os.close(read_fd)
            os.close(cg_fd)
    proc = None
    pid = None
    output = b""
    result = {"mode": mode, "uid": uid, "limits": observed_limits, "passed": False}
    started = time.monotonic()
    try:
        proc = subprocess.Popen(
            [
                str(ROOT / "jailer"),
                "--id",
                name,
                "--exec-file",
                str(ROOT / "firecracker"),
                "--uid",
                str(uid),
                "--gid",
                str(uid),
                "--chroot-base-dir",
                str(ROOT / "jails"),
                "--cgroup-version",
                "2",
                "--parent-cgroup",
                "etzio-owned/" + name,
                "--netns",
                "/var/run/netns/" + netns,
                "--new-pid-ns",
                "--resource-limit",
                "fsize=1048576",
                "--resource-limit",
                "no-file=128",
                "--",
                "--api-sock",
                "/run/api.sock",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env={},
        )
        api = jail / "run/api.sock"
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and not api.exists():
            if select.select([proc.stdout], [], [], 0.05)[0]:
                output += os.read(proc.stdout.fileno(), 4096)
                if len(output) > 65536:
                    raise RuntimeError("prestart output overflow")
        if not api.exists():
            raise RuntimeError("API socket not ready")
        members = (cg / "cgroup.procs").read_text().split()
        if len(members) != 1:
            raise RuntimeError("unexpected cgroup membership")
        pid = int(members[0])
        status = read_status(pid)
        if status["Uid"].split() != [str(uid)] * 4 or status["CapEff"] != "0000000000000000":
            raise RuntimeError("worker credentials do not match")
        if status.get("NSpid", "").split()[-1:] != ["1"]:
            raise RuntimeError("worker is not init of its PID namespace")
        mountns = os.readlink(f"/proc/{pid}/ns/mnt")
        networkns = os.readlink(f"/proc/{pid}/ns/net")
        if mountns == os.readlink("/proc/self/ns/mnt") or networkns == os.readlink("/proc/self/ns/net"):
            raise RuntimeError("worker shares host mount/network namespace")
        result["prestart_status"] = status
        result["namespace"] = {"mount": mountns, "network": networkns}
        put(api, "/machine-config", {"vcpu_count": 1, "mem_size_mib": 128, "smt": False})
        put(
            api,
            "/boot-source",
            {
                "kernel_image_path": "/inputs/kernel",
                "initrd_path": "/inputs/initrd",
                "boot_args": "console=ttyS0 reboot=k panic=1 nomodule loglevel=1 init=/init",
            },
        )
        put(api, "/actions", {"action_type": "InstanceStart"})
        result["runtime_machine_config"] = runtime_barrier(api)
        threads = {p.name: read_status(p.name) for p in Path(f"/proc/{pid}/task").iterdir()}
        result["poststart_threads"] = threads
        if len(threads) < 3 or any(s.get("Seccomp") != "2" or s.get("NoNewPrivs") != "1" for s in threads.values()):
            raise RuntimeError("poststart thread filter/NoNewPrivs mismatch")
        ready_at = None
        overflow = False
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if select.select([proc.stdout], [], [], 0.05)[0]:
                data = os.read(proc.stdout.fileno(), 4096)
                if not data:
                    break
                output += data
                if len(output) > 65536:
                    overflow = True
                    break
                if ready_at is None and (marker_observed(output, READY) or marker_observed(output, WRONG)):
                    ready_at = time.monotonic()
            if mode != "output" and ready_at is not None and time.monotonic() - ready_at > 0.6:
                break
        if str(pid) not in (cg / "cgroup.procs").read_text().split():
            raise RuntimeError("worker exited before the external termination control")
        if mode != "output" and ready_at is None:
            raise RuntimeError("no complete owned marker before the observation deadline")
        if mode != "output" and time.monotonic() - ready_at < 0.6:
            raise RuntimeError("worker did not survive the required observation interval")
        result["worker_present_before_kill"] = True
        result["cpu_stat_before_kill"] = (cg / "cpu.stat").read_text()
        result["memory_events"] = (cg / "memory.events").read_text()
        result["pids_events"] = (cg / "pids.events").read_text()
        expected = WRONG if mode == "wrong" else READY
        if mode == "output":
            result["passed"] = marker_observed(output, expected) and overflow
            result["decision"] = "output_limit_termination" if result["passed"] else "output_control_failed"
        elif mode == "wrong":
            result["passed"] = marker_observed(output, WRONG) and not marker_observed(output, READY)
            result["decision"] = "wrong_marker_rejected" if result["passed"] else "wrong_marker_control_failed"
        else:
            result["passed"] = marker_observed(output, READY) and not marker_observed(output, WRONG) and not overflow
            result["decision"] = "owned_marker_observed_then_stopped"
        result["output_limit_exceeded"] = overflow
        if crash_probe_fd is not None:
            # --new-pid-ns leaves an exited launcher as our direct child. Reap
            # it before publishing readiness, so collector death cannot pass
            # an unaccounted zombie launcher to the outer subreaper.
            result["launcher_exit_code"] = reap_launcher(proc)
            hold_for_crash_probe(crash_probe_fd, ordinal, pid, watcher, cg, write_fd, result, output)
    except BaseException as exc:
        result["error"] = {"type": type(exc).__name__, "message": str(exc)[:600]}
    finally:
        kill_started = time.monotonic()
        empty = kill_group(cg)
        if watcher:
            os.write(write_fd, b"s")
            os.close(write_fd)
            watcher.wait(timeout=5)
            result["watchdog"] = json.loads((ROOT / (name + "-watch.json")).read_text())
        else:
            result["watchdog"] = {"reason": "withheld", "empty": False}
        if proc:
            proc.wait(timeout=3)
            if proc.stdout:
                remaining = 8192
                eof = False
                drain_deadline = time.monotonic() + 0.5
                while remaining and time.monotonic() < drain_deadline:
                    if not select.select([proc.stdout], [], [], 0.02)[0]:
                        continue
                    remainder = os.read(proc.stdout.fileno(), min(4096, remaining))
                    if not remainder:
                        eof = True
                        break
                    output += remainder
                    remaining -= len(remainder)
                result["postkill_output_incomplete"] = not eof
                proc.stdout.close()
        result["worker_reaped_exit_code"] = None
        if pid:
            reap_deadline = time.monotonic() + 3
            while time.monotonic() < reap_deadline:
                try:
                    found, status = os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    break
                if found:
                    result["worker_reaped_exit_code"] = os.waitstatus_to_exitcode(status)
                    break
                time.sleep(0.01)
        result["cgroup_empty_after_kill"] = empty
        result["post_kill_seconds"] = time.monotonic() - kill_started
        result["elapsed_seconds"] = time.monotonic() - started
        result["output_bytes_observed"] = len(output)
        result["output_sha256"] = hashlib.sha256(output).hexdigest()
        result["output_prefix_b64"] = base64.b64encode(output[:4096]).decode()
        result["output_suffix_b64"] = base64.b64encode(output[-1024:]).decode()
        result["passed"] = (
            result["passed"]
            and empty
            and result["watchdog"]["empty"]
            and result["worker_reaped_exit_code"] == -signal.SIGKILL
            and (mode == "output" or not result.get("postkill_output_incomplete", True))
        )
        command("ip", "netns", "delete", netns)
        cg.rmdir()
    return result


def require_host():
    if platform.system() != "Linux" or platform.machine() != "x86_64" or os.getuid() != 0:
        raise RuntimeError("requires the specified disposable Linux x86_64 root host")
    if not platform.release().startswith("6.1."):
        raise RuntimeError("host kernel is outside the selected 6.1 profile")
    for name, digest in PINS.items():
        path = ROOT / name
        if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise RuntimeError("artifact pin mismatch: " + name)
    set_subreaper()


def set_subreaper():
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "subreaper")


def prepare_cgroups():
    cgbase = Path("/sys/fs/cgroup")
    if not {"cpu", "memory", "pids"} <= set((cgbase / "cgroup.controllers").read_text().split()):
        raise RuntimeError("required cgroup controllers missing")
    (cgbase / "cgroup.subtree_control").write_text("+cpu +memory +pids")
    CGROOT.mkdir()
    (CGROOT / "cgroup.subtree_control").write_text("+cpu +memory +pids")


def collect():
    require_host()
    prepare_cgroups()
    result = {
        "schema": "etzio.owned-firecracker.observation.v1",
        "kernel": platform.release(),
        "collector_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "os_release": Path("/etc/os-release").read_text(),
        "pins": PINS,
        "cases": [],
        "limit": "Owned controls only; not target execution or a complete isolation qualification.",
    }
    try:
        for ordinal, mode in enumerate(("ready", "wrong", "spin", "output"), 1):
            case = collect_case(mode, ordinal)
            result["cases"].append(case)
            if not case["passed"]:
                break
    finally:
        CGROOT.rmdir()
    result["all_controls_passed"] = len(result["cases"]) == 4 and all(c["passed"] for c in result["cases"])
    return result


if __name__ == "__main__":
    try:
        result = collect()
    except BaseException as exc:
        result = {
            "all_controls_passed": False,
            "collector_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "error": {"type": type(exc).__name__, "message": str(exc)[:1000]},
        }
    print(json.dumps(result, sort_keys=True), flush=True)
