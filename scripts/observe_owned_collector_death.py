"""Finite owned collector-death controls; no target or provisioning interface."""

import base64
import hashlib
import json
import os
import re
import select
import signal
import subprocess
import sys
import time
from pathlib import Path

import collect_owned_firecracker_preflight as guest

READY_LIMIT = 16384
PRIMARY_NS = 5_000_000_000
OUTER_NS = 10_000_000_000


def closed_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def decode_ready(wire, ordinal, collector_pid, observer_pid):
    if type(wire) is not bytes or not 0 < len(wire) <= READY_LIMIT:
        raise ValueError("readiness size")
    value = json.loads(wire, object_pairs_hook=closed_object)
    fields = {
        "schema",
        "ordinal",
        "collector",
        "worker",
        "watchdog",
        "cgroup",
        "watch_pipe",
        "threads",
        "output_b64",
        "launcher_exit_code",
    }
    if type(value) is not dict or set(value) != fields:
        raise ValueError("readiness fields")
    if value["schema"] != "etzio.owned-collector-ready.v1" or type(value["ordinal"]) is not int:
        raise ValueError("readiness schema/ordinal")
    if ordinal not in (5, 6) or value["ordinal"] != ordinal:
        raise ValueError("readiness case")
    if type(value["launcher_exit_code"]) is not int or value["launcher_exit_code"] != 0:
        raise ValueError("launcher completion")
    roles = ("collector", "worker", "watchdog") if ordinal == 5 else ("collector", "worker")
    pids = []
    for role in roles:
        identity = value[role]
        if type(identity) is not dict or set(identity) != {"pid", "parent", "start_ticks"}:
            raise ValueError("process identity fields")
        if any(type(x) is not int or x <= 0 for x in identity.values()):
            raise ValueError("process identity values")
        if identity["parent"] != (observer_pid if role == "collector" else collector_pid):
            raise ValueError("process ancestry")
        pids.append(identity["pid"])
    if value["collector"]["pid"] != collector_pid or len(set(pids + [observer_pid])) != len(pids) + 1:
        raise ValueError("process alias/substitution")
    if ordinal == 6 and (value["watchdog"] is not None or value["watch_pipe"] is not None):
        raise ValueError("withheld watchdog present")
    if ordinal == 5 and (
        type(value["watch_pipe"]) is not str or not re.fullmatch(r"pipe:\[[0-9]+\]", value["watch_pipe"])
    ):
        raise ValueError("watch pipe identity")
    cg = value["cgroup"]
    if type(cg) is not dict or set(cg) != {"device", "inode"}:
        raise ValueError("cgroup fields")
    if any(type(x) is not int or x <= 0 for x in cg.values()):
        raise ValueError("cgroup identity")
    output = base64.b64decode(value["output_b64"], validate=True)
    if not 0 < len(output) <= 4096 or not guest.marker_observed(output, guest.READY):
        raise ValueError("owned marker missing")
    if guest.marker_observed(output, guest.WRONG):
        raise ValueError("wrong owned marker")
    validate_threads(value["threads"], ordinal)
    return value


def validate_threads(threads, ordinal):
    if type(threads) is not dict or not 3 <= len(threads) <= 32:
        raise ValueError("thread roster")
    for tid, status in threads.items():
        if type(tid) is not str or not tid.isascii() or not tid.isdecimal():
            raise ValueError("thread id")
        if type(status) is not dict or any(
            status.get(k) != v for k, v in {"Seccomp": "2", "NoNewPrivs": "1", "CapEff": "0000000000000000"}.items()
        ):
            raise ValueError("thread filter/credentials")
        for field in ("Uid", "Gid"):
            if type(status.get(field)) is not str or status[field].split() != [str(65000 + ordinal)] * 4:
                raise ValueError("thread uid/gid")


def read_ready(fd, deadline):
    wire = b""
    while time.monotonic() < deadline:
        if not select.select([fd], [], [], min(0.05, max(0, deadline - time.monotonic())))[0]:
            continue
        part = os.read(fd, min(4096, READY_LIMIT + 1 - len(wire)))
        if not part:
            return wire
        wire += part
        if len(wire) > READY_LIMIT:
            raise ValueError("readiness size")
    raise TimeoutError("readiness deadline")


def cg_read(fd, name):
    child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
    try:
        data = os.read(child, 4097)
        if len(data) > 4096:
            raise ValueError("cgroup observation size")
        return data.decode()
    finally:
        os.close(child)


def cg_empty(fd):
    return "populated 0" in cg_read(fd, "cgroup.events").splitlines() and not cg_read(fd, "cgroup.procs").strip()


def cg_kill(fd):
    child = os.open("cgroup.kill", os.O_WRONLY | os.O_NOFOLLOW, dir_fd=fd)
    try:
        os.write(child, b"1")
    finally:
        os.close(child)


def bind_process(identity):
    fd = os.pidfd_open(identity["pid"])
    try:
        if guest.process_identity(identity["pid"]) != identity or select.select([fd], [], [], 0)[0]:
            raise ValueError("process identity changed/exited")
        return fd
    except BaseException:
        os.close(fd)
        raise


def kernel_helper_snapshot(pid):
    stat = Path(f"/proc/{pid}/stat").read_text()
    comm, suffix = stat.split("(", 1)[1].rsplit(")", 1)
    fields = suffix.split()
    return {
        "identity": {"pid": pid, "parent": int(fields[1]), "start_ticks": int(fields[19])},
        "comm": comm,
        "flags": int(fields[6]),
        "status": guest.read_status(pid),
    }


def validate_kernel_helper(snapshot, worker_pid):
    identity = snapshot["identity"]
    if (
        snapshot["comm"] != f"kvm-nx-lpage-recovery-{worker_pid}"
        or type(snapshot["flags"]) is not int
        or not snapshot["flags"] & 0x00200000
        or identity["parent"] != 2
    ):
        raise ValueError("unqualified cgroup helper")
    for field in ("Uid", "Gid"):
        if snapshot["status"].get(field, "").split() != ["0"] * 4:
            raise ValueError("kernel helper credentials")


def fresh_binding(ready, cgfd, ordinal, evidence=None):
    st = os.fstat(cgfd)
    snapshot = evidence if evidence is not None else {}
    snapshot["cgroup"] = {"device": st.st_dev, "inode": st.st_ino}
    snapshot["members"] = cg_read(cgfd, "cgroup.procs")
    snapshot["events"] = cg_read(cgfd, "cgroup.events")
    snapshot["limits"] = {k: cg_read(cgfd, k).strip() for k in guest.LIMITS}
    if ready["cgroup"] != {"device": st.st_dev, "inode": st.st_ino}:
        raise ValueError("cgroup substitution")
    members = snapshot["members"].split()
    worker = str(ready["worker"]["pid"])
    if len(members) != 2 or len(set(members)) != 2 or worker not in members:
        raise ValueError("worker cgroup membership")
    extra = next(x for x in members if x != worker)
    if not extra.isascii() or not extra.isdecimal() or int(extra) <= 0:
        raise ValueError("cgroup helper PID")
    snapshot["kernel_helper"] = kernel_helper_snapshot(int(extra))
    validate_kernel_helper(snapshot["kernel_helper"], ready["worker"]["pid"])
    if snapshot["limits"] != guest.LIMITS:
        raise ValueError("cgroup limits changed")
    pid = ready["worker"]["pid"]
    threads = {p.name: guest.read_status(p.name) for p in Path(f"/proc/{pid}/task").iterdir()}
    snapshot["threads"] = threads
    validate_threads(threads, ordinal)
    for ns in ("mnt", "net", "pid"):
        if os.readlink(f"/proc/{pid}/ns/{ns}") == os.readlink(f"/proc/self/ns/{ns}"):
            raise ValueError("worker namespace shared")
    pipe = ready["watch_pipe"]
    for p in Path("/proc/self/fd").iterdir():
        try:
            if pipe is not None and os.readlink(p) == pipe:
                raise ValueError("observer holds watchdog pipe")
        except FileNotFoundError:
            continue
    return threads


def reap(pid, results, role):
    if role in results:
        return
    try:
        found, status = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        return
    if found:
        results[role] = os.waitstatus_to_exitcode(status)


def primary_accepts(record):
    # Fallback can never repair missing primary evidence.
    watch = record.get("watchdog")
    injected = record.get("injected_ns")
    observed = record.get("primary_observed_ns")
    reaped = record.get("primary_reaped")
    return (
        record.get("fallback_used") is False
        and type(injected) is int
        and type(observed) is int
        and 0 <= observed - injected <= PRIMARY_NS
        and type(reaped) is dict
        and reaped == {"collector": -9, "worker": -9, "watchdog": 0}
        and all(type(code) is int for code in reaped.values())
        and record.get("primary_empty") is True
        and record.get("kernel_helper_exited") is True
        and type(watch) is dict
        and set(watch) == {"reason", "empty", "observed_ns", "completed_ns"}
        and watch["reason"] == "collector_pipe_closed"
        and watch["empty"] is True
        and type(watch["observed_ns"]) is int
        and type(watch["completed_ns"]) is int
        and injected <= watch["observed_ns"] <= watch["completed_ns"] <= observed
    )


def clean_adopted_children():
    # This process owns only this experiment. Never enumerate host-wide PIDs.
    children = Path(f"/proc/self/task/{os.getpid()}/children").read_text().split()
    result = {}
    for text in children:
        pid = int(text)
        fd = os.pidfd_open(pid)
        try:
            if guest.process_identity(pid)["parent"] != os.getpid():
                raise ValueError("cleanup child ancestry changed")
            signal.pidfd_send_signal(fd, signal.SIGKILL)
            if not select.select([fd], [], [], 2)[0]:
                raise TimeoutError("cleanup child deadline")
            found, status = os.waitpid(pid, os.WNOHANG)
            if found != pid:
                raise RuntimeError("cleanup child not reaped")
            result[text] = os.waitstatus_to_exitcode(status)
        finally:
            os.close(fd)
    return result


def observe_case(ordinal):
    if type(ordinal) is not int or ordinal not in (5, 6):
        raise ValueError("closed owned collector-death case")
    read_fd, write_fd = os.pipe()
    cg = guest.CGROOT / f"owned-{ordinal}"
    cgfd = None
    proc = None
    fds = {}
    helper_fd = None
    result = {"ordinal": ordinal, "passed": False, "fallback_used": False}
    try:
        proc = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "--collector", str(ordinal), str(write_fd)],
            pass_fds=(write_fd,),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        os.close(write_fd)
        write_fd = None
        collector_identity = guest.process_identity(proc.pid)
        fds["collector"] = bind_process(collector_identity)
        wire = read_ready(read_fd, time.monotonic() + 30)
        result["readiness_wire_b64"] = base64.b64encode(wire).decode()
        ready = decode_ready(wire, ordinal, proc.pid, os.getpid())
        result["readiness"] = ready
        if ready["collector"] != collector_identity:
            raise ValueError("collector readiness substitution")
        cgfd = os.open(cg, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for role in ("worker", "watchdog"):
            if ready[role] is not None:
                fds[role] = bind_process(ready[role])
        result["fresh_binding"] = {}
        result["fresh_threads"] = fresh_binding(ready, cgfd, ordinal, result["fresh_binding"])
        helper = result["fresh_binding"]["kernel_helper"]["identity"]
        helper_fd = bind_process(helper)
        for role in fds:
            if select.select([fds[role]], [], [], 0)[0] or guest.process_identity(ready[role]["pid"]) != ready[role]:
                raise ValueError("process changed before injection")
        if select.select([helper_fd], [], [], 0)[0] or guest.process_identity(helper["pid"]) != helper:
            raise ValueError("kernel helper changed before injection")
        start = time.monotonic_ns()
        result["injected_ns"] = start
        signal.pidfd_send_signal(fds["collector"], signal.SIGKILL)
        reaped = {}
        watch_path = guest.ROOT / f"owned-{ordinal}-watch.json"
        while time.monotonic_ns() - start < PRIMARY_NS:
            for role in fds:
                reap(ready[role]["pid"], reaped, role)
            if set(reaped) == set(fds) and cg_empty(cgfd) and select.select([helper_fd], [], [], 0)[0]:
                break
            time.sleep(0.01)
        result["primary_observed_ns"] = time.monotonic_ns()
        result["primary_reaped"] = dict(reaped)
        result["primary_empty"] = cg_empty(cgfd)
        result["kernel_helper_exited"] = bool(select.select([helper_fd], [], [], 0)[0])
        if "watchdog" in reaped and watch_path.exists():
            with watch_path.open("rb") as stream:
                watch_wire = stream.read(4097)
            if len(watch_wire) > 4096:
                raise ValueError("watchdog observation size")
            result["watchdog"] = json.loads(watch_wire, object_pairs_hook=closed_object)
        result["primary_accepted"] = primary_accepts(result)
        if not result["primary_accepted"]:
            result["worker_present_at_refusal"] = (
                set(cg_read(cgfd, "cgroup.procs").split()) == {str(ready["worker"]["pid"]), str(helper["pid"])}
                and not select.select([fds["worker"]], [], [], 0)[0]
            )
            result["fallback_used"] = True
            cg_kill(cgfd)
        while time.monotonic_ns() - start < OUTER_NS:
            for role in fds:
                reap(ready[role]["pid"], reaped, role)
            if set(reaped) == set(fds) and cg_empty(cgfd) and select.select([helper_fd], [], [], 0)[0]:
                break
            time.sleep(0.01)
        result["completed_ns"] = time.monotonic_ns()
        result["final_reaped"] = reaped
        result["final_empty"] = cg_empty(cgfd)
        result["final_kernel_helper_exited"] = bool(select.select([helper_fd], [], [], 0)[0])
        bounded = (
            result["completed_ns"] - start <= OUTER_NS
            and result["final_empty"]
            and result["final_kernel_helper_exited"]
        )
        result["passed"] = bounded and (
            result["primary_accepted"]
            if ordinal == 5
            else (
                not result["primary_accepted"]
                and result["fallback_used"]
                and result["worker_present_at_refusal"]
                and reaped == {"collector": -9, "worker": -9}
            )
        )
    except BaseException as exc:
        result["error"] = {"type": type(exc).__name__, "message": str(exc)[:600]}
    finally:
        os.close(read_fd)
        if write_fd is not None:
            os.close(write_fd)
        try:
            if proc:
                if "collector" in fds and not select.select([fds["collector"]], [], [], 0)[0]:
                    signal.pidfd_send_signal(fds["collector"], signal.SIGKILL)
                # waitpid may already have reaped this Popen child in the observation.
                if result.get("final_reaped", {}).get("collector") is not None:
                    proc.returncode = result["final_reaped"]["collector"]
                proc.wait(timeout=3)
            if cgfd is None and cg.exists():
                cgfd = os.open(cg, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            if cgfd is not None and not cg_empty(cgfd):
                result["emergency_cleanup_used"] = True
                result["passed"] = False
                cg_kill(cgfd)
            result["remaining_children_cleanup"] = clean_adopted_children()
            if result["remaining_children_cleanup"]:
                result["passed"] = False
            if cgfd is not None:
                if not cg_empty(cgfd):
                    raise RuntimeError("residual cgroup members")
                cg.rmdir()
            guest.command("ip", "netns", "delete", f"etzio-owned-{ordinal}")
            result["cleanup_complete"] = True
        except BaseException as exc:
            result["passed"] = False
            result["cleanup_error"] = {"type": type(exc).__name__, "message": str(exc)[:600]}
        finally:
            for fd in fds.values():
                os.close(fd)
            if cgfd is not None:
                os.close(cgfd)
            if helper_fd is not None:
                os.close(helper_fd)
    return result


def collect():
    guest.require_host()
    guest.prepare_cgroups()
    result = {
        "schema": "etzio.owned-collector-death.observation.v1",
        "collector_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "guest_collector_sha256": hashlib.sha256(Path(guest.__file__).read_bytes()).hexdigest(),
        "kernel": guest.platform.release(),
        "pins": guest.PINS,
        "cases": [],
        "primary_bound_ns": PRIMARY_NS,
        "outer_bound_ns": OUTER_NS,
        "claim": "Owned preparation only; no target or independent administration.",
    }
    try:
        normal = guest.collect_case("ready", 1)
        normal["passed"] = normal["passed"] and normal["watchdog"]["reason"] == "explicit_stop"
        result["normal_control"] = normal
        if normal["passed"]:
            for ordinal in (5, 6):
                result["cases"].append(observe_case(ordinal))
                if not result["cases"][-1]["passed"]:
                    break
    except BaseException as exc:
        result["error"] = {"type": type(exc).__name__, "message": str(exc)[:600]}
    finally:
        try:
            guest.CGROOT.rmdir()
        except BaseException as exc:
            result["cleanup_error"] = {"type": type(exc).__name__, "message": str(exc)[:600]}
    result["all_controls_passed"] = (
        not result.get("error")
        and not result.get("cleanup_error")
        and result.get("normal_control", {}).get("passed") is True
        and len(result["cases"]) == 2
        and all(x["passed"] for x in result["cases"])
    )
    return result


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--collector":
        guest.require_host()
        guest.collect_case("ready", int(sys.argv[2]), crash_probe_fd=int(sys.argv[3]))
    elif len(sys.argv) == 1:
        try:
            observation = collect()
        except BaseException as exc:
            observation = {
                "collector_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "all_controls_passed": False,
                "error": {"type": type(exc).__name__, "message": str(exc)[:600]},
            }
        print(json.dumps(observation, sort_keys=True), flush=True)
    else:
        raise SystemExit("closed owned experiment arguments")
