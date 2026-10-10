"""Benign Linux clock-device observations; no clock, UTC or isolation qualification."""

from __future__ import annotations

import glob
import hashlib
import json
import os
import platform
import subprocess
import time
from pathlib import Path


def read(path: str):
    try:
        with open(path, encoding="utf-8") as source:
            return source.read(8192).strip()
    except OSError as exc:
        return {"unavailable": type(exc).__name__, "errno": exc.errno}


def collect() -> dict:
    if platform.system() != "Linux":
        raise RuntimeError("Linux observation only")
    result = {
        "schema": "etzio.clock-preflight.observation.v1",
        "boundary": "finite benign observations; no drift/error bound, UTC, suspend or migration qualification",
        "collector_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "kernel": platform.uname()._replace(node="omitted")._asdict(),
        "os_release": read("/etc/os-release"),
        "boot_id": read("/proc/sys/kernel/random/boot_id"),
        "clocksource": read("/sys/devices/system/clocksource/clocksource0/current_clocksource"),
        "available_clocksources": read("/sys/devices/system/clocksource/clocksource0/available_clocksource"),
        "cpu_vulnerabilities": {
            Path(p).name: read(p) for p in sorted(glob.glob("/sys/devices/system/cpu/vulnerabilities/*"))[:32]
        },
        "ptp_devices": [],
        "unavailable_clocks": {},
    }
    try:
        proc = subprocess.run(["modprobe", "ptp_kvm"], capture_output=True, text=True, timeout=5, check=False)
        result["ptp_module_load"] = {"exit_code": proc.returncode, "stderr": proc.stderr[:1024]}
    except (OSError, subprocess.TimeoutExpired) as exc:
        result["ptp_module_load"] = {"unavailable": type(exc).__name__}
    names = ("CLOCK_BOOTTIME", "CLOCK_MONOTONIC", "CLOCK_MONOTONIC_RAW", "CLOCK_REALTIME", "CLOCK_TAI")
    clocks = {name: getattr(time, name) for name in names if hasattr(time, name)}
    descriptors = []
    try:
        for path in sorted(glob.glob("/dev/ptp[0-9]*"))[:8]:
            entry = {"device": path, "clock_name": read("/sys/class/ptp/" + Path(path).name + "/clock_name")}
            result["ptp_devices"].append(entry)
            try:
                descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
                descriptors.append(descriptor)
                # Linux dynamic clock descriptor ABI: CLOCKFD = 3.
                clocks[path] = ((~descriptor) << 3) | 3
            except OSError as exc:
                entry["unavailable"] = {"type": type(exc).__name__, "errno": exc.errno}
        result["reported_resolution_seconds"] = {}
        for name, clock in tuple(clocks.items()):
            try:
                time.clock_gettime_ns(clock)
                result["reported_resolution_seconds"][name] = time.clock_getres(clock)
            except OSError as exc:
                result["unavailable_clocks"][name] = {"type": type(exc).__name__, "errno": exc.errno}
                del clocks[name]
        if "CLOCK_BOOTTIME" not in clocks:
            raise RuntimeError("CLOCK_BOOTTIME required for observation brackets")

        def sample():
            readings = {}
            for name, clock in clocks.items():
                before = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
                value = time.clock_gettime_ns(clock)
                after = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
                readings[name] = [before, value, after]
            return readings

        result["bracket_order"] = ["boottime_before_ns", "clock_value_ns", "boottime_after_ns"]
        result["samples"] = []
        for _ in range(200):
            result["samples"].append(sample())
            time.sleep(0.01)
        result["ordinary_wait"] = {"requested_seconds": 2, "before": sample()}
        time.sleep(2)
        result["ordinary_wait"]["after"] = sample()
        result["final_boot_id"] = read("/proc/sys/kernel/random/boot_id")
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
    return result


if __name__ == "__main__":
    print(json.dumps(collect(), sort_keys=True))
