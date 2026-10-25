"""Closed owned peer controls; namespace probes do not inherit VMM seccomp."""

import ctypes
import hashlib
import json
import os
import select
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import observe_owned_resource_containment as resources

guest, death, ROOT = resources.guest, resources.death, resources.ROOT
SIDES = {"a": 21, "b": 22}
PROBE_LIMITS = {"memory.max": "134217728", "memory.swap.max": "0", "pids.max": "8", "cpu.max": "20000 100000"}
PROBE_CG = resources.CGROOT / "peer-probes"
CONFIG = ROOT / "peer-config.json"


class PeerVM(resources.Case):
    def __init__(self, side):
        if type(side) is not str or side not in SIDES:
            raise ValueError("closed owned peer identity")
        super().__init__("memory-low")
        self.ordinal = SIDES[side]
        self.uid = 65000 + self.ordinal
        self.name = "resource-" + str(self.ordinal)
        self.cg = resources.CGROOT / self.name
        self.result.update(uid=self.uid, cgroup_path="/etzio-resource/" + self.name, side=side)

    @property
    def jail(self):
        return ROOT / "jails/firecracker" / self.name / "root"


def denied(operation):
    try:
        value = operation()
        if isinstance(value, int) and value >= 0:
            os.close(value)
        return 0
    except OSError as exc:
        return exc.errno


def connect_abstract(name):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        sock.connect(b"\0etzio-owned-peer-" + name.encode() + b"-v1")


def abstract_result(name):
    try:
        connect_abstract(name)
        return 0
    except OSError as exc:
        return exc.errno


def read_canary(fd):
    child = os.open("canary", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
    try:
        return os.read(child, 129).decode()
    finally:
        os.close(child)


def api_control(fd):
    return resources.runtime_barrier(Path(f"/proc/self/fd/{fd}/api.sock"))


def drop(uid):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0):
        raise OSError(ctypes.get_errno(), "peer probe NoNewPrivs")
    os.setgroups([])
    os.setgid(uid)
    os.setuid(uid)


def enter_namespace(fd, kind):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.setns(fd, kind):
        raise OSError(ctypes.get_errno(), "owned namespace join")
    os.close(fd)


def input_probe():
    scratch = Path("/run/probe-scratch")
    scratch.write_bytes(b"owned writable control\n")
    result = {"scratch": scratch.read_bytes() == b"owned writable control\n", "denials": {}, "hashes": {}}
    for name in ("kernel", "initrd"):
        path = Path("/inputs") / name
        data = path.read_bytes()
        if len(data) > 32 * 1024**2:
            raise ValueError("owned input read bound")
        result["hashes"][name] = hashlib.sha256(data).hexdigest()
        result["denials"][name] = {
            "write": denied(lambda p=path: os.open(p, os.O_WRONLY)),
            "truncate": denied(lambda p=path: os.open(p, os.O_WRONLY | os.O_TRUNC)),
            "chmod": denied(lambda p=path: os.chmod(p, 0o600)),
            "unlink": denied(lambda p=path: os.unlink(p)),
            "replace": denied(lambda p=path: os.rename(scratch, p)),
        }
    result["create_input"] = denied(lambda: os.open("/inputs/new", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
    return result


def helper(role, side):
    if role not in ("serve", "dac", "namespace") or side not in SIDES or os.getuid() != 0:
        raise ValueError("closed owned peer helper")
    config = json.loads(CONFIG.read_text(), object_pairs_hook=death.closed_object)
    own, peer = config[side], config["b" if side == "a" else "a"]
    if own["uid"] != 65000 + SIDES[side] or guest.process_identity(own["identity"]["pid"]) != own["identity"]:
        raise ValueError("owned peer identity changed")
    if guest.process_identity(peer["identity"]["pid"]) != peer["identity"]:
        raise ValueError("other peer identity changed")
    pid = own["identity"]["pid"]
    if role == "dac":
        ownfd = os.open(Path(own["jail"]) / "run", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        peerfd = os.open(Path(peer["jail"]) / "run", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        drop(own["uid"])
        own_canary = read_canary(ownfd)
        try:
            read_canary(peerfd)
            peer_read = 0
        except OSError as exc:
            peer_read = exc.errno
        own_api = api_control(ownfd)
        try:
            api_control(peerfd)
            peer_api = 0
        except OSError as exc:
            peer_api = exc.errno
        os.kill(pid, 0)
        try:
            os.kill(peer["identity"]["pid"], 0)
            peer_signal = 0
        except OSError as exc:
            peer_signal = exc.errno
        result = {
            "own_canary": own_canary,
            "peer_read_errno": peer_read,
            "own_api": own_api,
            "own_signal": True,
            "peer_signal_errno": peer_signal,
            "peer_api_errno": peer_api,
        }
        os.close(ownfd)
        os.close(peerfd)
    else:
        network = os.open(f"/proc/{pid}/ns/net", os.O_RDONLY)
        if role == "namespace":
            mount = os.open(f"/proc/{pid}/ns/mnt", os.O_RDONLY)
            jailfd = os.open(own["jail"], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            enter_namespace(mount, 0x00020000)
            os.fchdir(jailfd)
            os.chroot(".")
            os.chdir("/")
            os.close(jailfd)
        enter_namespace(network, 0x40000000)
        drop(own["uid"])
        if role == "serve":
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(b"\0etzio-owned-peer-" + side.encode() + b"-v1")
            server.listen(4)
            connect_abstract(side)
            result = {"listener_positive": True}
        else:
            result = input_probe()
            result["network"] = {name: abstract_result(name) for name in (side, "b" if side == "a" else "a", "host")}
    print(json.dumps(result, sort_keys=True), flush=True)
    while True:
        signal.pause()


def dac_accepts(report, side):
    expected = {"vcpu_count": 1, "mem_size_mib": 512, "smt": False}
    try:
        return (
            report["own_canary"] == "owned-peer-" + side + "\n"
            and report["peer_read_errno"] == 13
            and report["peer_api_errno"] == 13
            and report["own_signal"] is True
            and type(report["peer_signal_errno"]) is int
            and report["peer_signal_errno"] == 1
            and all(
                type(report["own_api"].get(k)) is type(v) and report["own_api"][k] == v for k, v in expected.items()
            )
        )
    except (KeyError, TypeError):
        return False


def namespace_accepts(report, side, before, after):
    try:
        expected = {"write": 13, "truncate": 13, "chmod": 1, "unlink": 13, "replace": 13}
        if any(type(value) is not int for operations in report["denials"].values() for value in operations.values()):
            return False
        if any(type(value) is not int for value in report["network"].values()):
            return False
        return (
            report["scratch"] is True
            and report["hashes"] == before == after
            and report["denials"] == {"kernel": expected, "initrd": expected}
            and report["create_input"] == 13
            and report["network"] == {side: 0, "b" if side == "a" else "a": 111, "host": 111}
        )
    except (KeyError, TypeError):
        return False


def input_hashes(vm):
    return {name: hashlib.sha256((vm.jail / "inputs" / name).read_bytes()).hexdigest() for name in ("kernel", "initrd")}


class Probes:
    def __init__(self):
        self.fd = self.writefd = None
        self.watcher = None
        self.children = []
        self.records = []
        self.bindings = []

    def setup(self):
        PROBE_CG.mkdir()
        self.fd = os.open(PROBE_CG, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for key, value in PROBE_LIMITS.items():
            (PROBE_CG / key).write_text(value)
        if {k: death.cg_read(self.fd, k).strip() for k in PROBE_LIMITS} != PROBE_LIMITS:
            raise ValueError("peer probe limits")
        readfd, self.writefd = os.pipe()
        try:
            self.watcher = subprocess.Popen(
                [
                    sys.executable,
                    str(Path(resources.__file__).resolve()),
                    "--watch",
                    str(self.fd),
                    str(readfd),
                    str(ROOT / "peer-watch.json"),
                ],
                pass_fds=(self.fd, readfd),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        finally:
            os.close(readfd)

    def start(self, role, side, vm):
        def attach():
            fd = os.open("cgroup.procs", os.O_WRONLY, dir_fd=self.fd)
            os.write(fd, str(os.getpid()).encode())
            os.close(fd)
            os.close(self.fd)

        proc = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "--helper", role, side],
            preexec_fn=attach,
            pass_fds=(self.fd,),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env={},
        )
        self.children.append(proc)
        record = {"role": role, "side": side, "pid": proc.pid, "passed": False}
        self.records.append(record)
        wire, deadline = b"", time.monotonic() + 4
        while b"\n" not in wire and time.monotonic() < deadline:
            if select.select([proc.stdout], [], [], 0.02)[0]:
                wire += os.read(proc.stdout.fileno(), 4096)
                if len(wire) > 16384:
                    raise ValueError("peer probe output bound")
        record["output"] = wire.decode(errors="replace")
        if not wire.endswith(b"\n") or wire.count(b"\n") != 1:
            raise ValueError("peer probe framing/deadline")
        record["report"] = json.loads(wire, object_pairs_hook=death.closed_object)
        identity = guest.process_identity(proc.pid)
        fd = death.bind_process(identity)
        try:
            if identity["parent"] != os.getpid():
                raise ValueError("peer helper ancestry")
            status = guest.read_status(proc.pid)
            record.update(identity=identity, status=status)
            if (
                status["Uid"].split() != [str(vm.uid)] * 4
                or status["Gid"].split() != [str(vm.uid)] * 4
                or status["CapEff"] != "0000000000000000"
                or status["NoNewPrivs"] != "1"
                or status["Seccomp"] != "0"
            ):
                raise ValueError("peer probe credentials or unexpected filter")
            record["namespaces"] = {ns: os.readlink(f"/proc/{proc.pid}/ns/{ns}") for ns in ("mnt", "net", "pid")}
            for ns in ("mnt", "net", "pid"):
                target = (
                    vm.result["namespaces"][ns]
                    if (ns == "net" and role != "dac") or (ns == "mnt" and role == "namespace")
                    else os.readlink(f"/proc/self/ns/{ns}")
                )
                if record["namespaces"][ns] != target:
                    raise ValueError("peer probe namespace binding")
            if role == "namespace":
                actual, expected = Path(f"/proc/{proc.pid}/root").stat(), vm.jail.stat()
                record["root_inode"] = [actual.st_dev, actual.st_ino]
                if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
                    raise ValueError("peer probe root binding")
            if Path(f"/proc/{proc.pid}/cgroup").read_text().strip() != "0::/etzio-resource/peer-probes":
                raise ValueError("peer probe cgroup binding")
            if select.select([fd], [], [], 0)[0]:
                raise ValueError("peer probe exited before binding")
        except BaseException:
            os.close(fd)
            raise
        self.bindings.append(fd)
        return record

    def final_binding(self):
        roster = [int(x) for x in death.cg_read(self.fd, "cgroup.procs").split()]
        if len(roster) != 6 or set(roster) != {p.pid for p in self.children}:
            raise ValueError("peer helper final roster")
        if len(self.bindings) != 6 or any(select.select([fd], [], [], 0)[0] for fd in self.bindings):
            raise ValueError("peer helper/listener died before final observation")
        observed = resources.snapshot(self.fd, PROBE_LIMITS)
        if observed["limits"] != PROBE_LIMITS or observed["pids_current"] != 6:
            raise ValueError("peer helper final limits/count")
        return {"roster": roster, "all_bound_helpers_alive": True, "snapshot": observed}

    def cleanup(self):
        if self.fd is None:
            return {"passed": False, "reason": "not prepared"}
        death.cg_kill(self.fd)
        os.write(self.writefd, b"s")
        os.close(self.writefd)
        codes = {str(p.pid): p.wait(timeout=3) for p in self.children}
        for proc in self.children:
            proc.stdout.close()
        for fd in self.bindings:
            os.close(fd)
        watcher_exit = self.watcher.wait(timeout=5)
        watch = json.loads((ROOT / "peer-watch.json").read_text())
        empty = death.cg_empty(self.fd)
        final = resources.snapshot(self.fd, PROBE_LIMITS)
        os.close(self.fd)
        PROBE_CG.rmdir()
        return {
            "passed": empty
            and all(x == -9 for x in codes.values())
            and watcher_exit == 0
            and watch["reason"] == "explicit_stop"
            and watch["empty"] is True
            and final["memory"]["oom"] == final["memory"]["oom_kill"] == 0,
            "empty": empty,
            "reaped": codes,
            "watchdog": watch,
            "final": final,
        }


def collect():
    resources.require_host()
    result = {
        "schema": "etzio.owned-cross-worker.observation.v1",
        "all_controls_passed": False,
        "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "dependency_sha256": {
            Path(m.__file__).name: hashlib.sha256(Path(m.__file__).read_bytes()).hexdigest()
            for m in (resources, guest, death)
        },
        "claim": "Owned file, UID and abstract-socket namespace controls; no guest-escape or CATO claim.",
    }
    (Path("/sys/fs/cgroup") / "cgroup.subtree_control").write_text("+cpu +memory +pids")
    resources.CGROOT.mkdir()
    (resources.CGROOT / "cgroup.subtree_control").write_text("+cpu +memory +pids")
    peers, probes, host = {}, Probes(), None
    result["peers"], result["probes"] = {}, probes.records
    try:
        for side in SIDES:
            vm = PeerVM(side)
            peers[side] = vm
            result["peers"][side] = vm.result
            vm.setup()
            vm.memory()
            if not vm.result.get("effect_accepted"):
                raise ValueError("peer readiness prerequisite")
            canary = vm.jail / "run/canary"
            canary.write_text("owned-peer-" + side + "\n")
            canary.chmod(0o600)
            os.chown(canary, vm.uid, vm.uid)
        for ns in ("mnt", "net", "pid"):
            if peers["a"].result["namespaces"][ns] == peers["b"].result["namespaces"][ns]:
                raise ValueError("peer namespace alias")
        config = {
            side: {"uid": vm.uid, "jail": str(vm.jail), "identity": vm.identities["worker"]}
            for side, vm in peers.items()
        }
        CONFIG.write_text(json.dumps(config))
        CONFIG.chmod(0o444)
        probes.setup()
        host = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        host.bind(b"\0etzio-owned-peer-host-v1")
        host.listen(4)
        connect_abstract("host")
        result["host_listener_positive"] = True
        for side, vm in peers.items():
            record = probes.start("serve", side, vm)
            record["passed"] = record["report"] == {"listener_positive": True}
            if not record["passed"]:
                raise ValueError("peer listener calibration")
        for side, vm in peers.items():
            record = probes.start("dac", side, vm)
            record["passed"] = dac_accepts(record["report"], side)
            if not record["passed"]:
                raise ValueError("peer DAC/signal control")
            before = input_hashes(vm)
            record = probes.start("namespace", side, vm)
            after = input_hashes(vm)
            record.update(input_before=before, input_after=after)
            record["passed"] = namespace_accepts(record["report"], side, before, after)
            if not record["passed"]:
                raise ValueError("peer input/network control")
        result["helpers_final"] = probes.final_binding()
        for vm in peers.values():
            vm.result["alive_after_peer_probes"] = not bool(select.select([vm.bindings["worker"]], [], [], 0)[0])
            vm.result["network_links_after"] = json.loads(guest.command("ip", "-n", vm.netns, "-j", "link", "show"))
            vm.result["network_routes_after"] = json.loads(guest.command("ip", "-n", vm.netns, "-j", "route", "show"))
            if not vm.result["alive_after_peer_probes"] or vm.result["network_routes_after"]:
                raise ValueError("peer lifetime/network drift")
            links = vm.result["network_links_after"]
            if len(links) != 1 or links[0]["ifname"] != "lo" or "UP" in links[0]["flags"]:
                raise ValueError("peer network interfaces changed")
    except BaseException as exc:
        result["error"] = {"type": type(exc).__name__, "message": str(exc)[:600]}
    finally:
        if host:
            host.close()
        try:
            result["probe_cleanup"] = probes.cleanup()
        except BaseException as exc:
            result["probe_cleanup"] = {"passed": False, "error": str(exc)[:600]}
        for vm in peers.values():
            try:
                vm.cleanup()
            except BaseException as exc:
                vm.result.update(passed=False, cleanup_error=str(exc)[:600])
        try:
            resources.CGROOT.rmdir()
        except OSError as exc:
            result["cleanup_error"] = str(exc)[:600]
    result["all_controls_passed"] = (
        "error" not in result
        and "cleanup_error" not in result
        and len(probes.records) == 6
        and all(r["passed"] for r in probes.records)
        and len(peers) == 2
        and all(vm.result["passed"] for vm in peers.values())
        and result["probe_cleanup"]["passed"]
    )
    return result


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--helper":
        helper(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 1:
        try:
            result = collect()
        except BaseException as exc:
            result = {"all_controls_passed": False, "error": {"type": type(exc).__name__, "message": str(exc)[:600]}}
        print(json.dumps(result, sort_keys=True), flush=True)
    else:
        raise SystemExit("closed owned peer observer")
