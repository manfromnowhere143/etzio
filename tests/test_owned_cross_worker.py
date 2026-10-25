"""Portable peer outcome controls; no native namespaces or guest execution."""

import copy
import importlib.util
from pathlib import Path

import pytest


@pytest.fixture
def observer(monkeypatch):
    scripts = Path(__file__).resolve().parents[1] / "scripts"
    monkeypatch.syspath_prepend(str(scripts))
    spec = importlib.util.spec_from_file_location("owned_peer_controls", scripts / "observe_owned_cross_worker.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def dac_record(side="a"):
    return {
        "own_canary": "owned-peer-" + side + "\n",
        "peer_read_errno": 13,
        "peer_api_errno": 13,
        "own_api": {"vcpu_count": 1, "mem_size_mib": 512, "smt": False},
        "own_signal": True,
        "peer_signal_errno": 1,
    }


def namespace_record(side="a"):
    return {
        "scratch": True,
        "hashes": {"kernel": "owned-kernel", "initrd": "owned-initrd"},
        "denials": {
            n: {"write": 13, "truncate": 13, "chmod": 1, "unlink": 13, "replace": 13} for n in ("kernel", "initrd")
        },
        "create_input": 13,
        "network": {side: 0, "b" if side == "a" else "a": 111, "host": 111},
    }


@pytest.mark.parametrize("side", ["a", "b"])
def test_peer_calibration(observer, side):
    assert observer.dac_accepts(dac_record(side), side)
    record = namespace_record(side)
    assert observer.namespace_accepts(record, side, record["hashes"], record["hashes"])
    vm = observer.PeerVM(side)
    assert vm.uid == 65000 + observer.SIDES[side]
    assert vm.result["uid"] == vm.uid and vm.result["cgroup_path"].endswith(vm.name)
    assert vm.mode == "memory-low" and vm.limits == observer.resources.MEMORY_LIMITS


@pytest.mark.parametrize("side", ["target", "../a", True, None])
def test_unlisted_peer_refused_without_resources(observer, side):
    with pytest.raises(ValueError, match="closed owned peer"):
        observer.PeerVM(side)


@pytest.mark.parametrize(
    "field,value",
    [
        ("own_canary", "owned-peer-b\n"),
        ("peer_read_errno", 0),
        ("peer_read_errno", 2),
        ("peer_api_errno", 0),
        ("peer_api_errno", 111),
        ("own_signal", False),
        ("peer_signal_errno", 0),
        ("peer_signal_errno", 3),
        ("peer_signal_errno", True),
        ("own_api", {"vcpu_count": True, "mem_size_mib": 512, "smt": False}),
    ],
)
def test_peer_access_or_missing_positive_cannot_pass(observer, field, value):
    record = dac_record()
    record[field] = value
    assert not observer.dac_accepts(record, "a")


@pytest.mark.parametrize("name", ["kernel", "initrd"])
@pytest.mark.parametrize("operation", ["write", "truncate", "chmod", "unlink", "replace"])
def test_each_input_mutation_must_refuse(observer, name, operation):
    record = namespace_record()
    record["denials"][name][operation] = 0
    assert not observer.namespace_accepts(record, "a", record["hashes"], record["hashes"])


@pytest.mark.parametrize("field,value", [("scratch", False), ("create_input", 0), ("create_input", 2)])
def test_directory_and_positive_control_required(observer, field, value):
    record = namespace_record()
    record[field] = value
    assert not observer.namespace_accepts(record, "a", record["hashes"], record["hashes"])


@pytest.mark.parametrize("name", ["a", "b", "host"])
def test_each_listener_requires_exact_positive_or_negative(observer, name):
    record = namespace_record()
    record["network"][name] = 111 if name == "a" else 0
    assert not observer.namespace_accepts(record, "a", record["hashes"], record["hashes"])


@pytest.mark.parametrize("which", ["before", "after", "helper"])
def test_changed_or_misreported_input_hash_refused(observer, which):
    record = namespace_record()
    before, after = copy.deepcopy(record["hashes"]), copy.deepcopy(record["hashes"])
    {"before": before, "after": after, "helper": record["hashes"]}[which]["kernel"] = "changed"
    assert not observer.namespace_accepts(record, "a", before, after)


def test_boolean_errno_is_not_an_observation(observer):
    record = namespace_record()
    record["denials"]["kernel"]["chmod"] = True
    assert not observer.namespace_accepts(record, "a", record["hashes"], record["hashes"])


def test_final_binding_rejects_dead_listener_even_with_matching_roster(observer, monkeypatch):
    probe = observer.Probes()
    probe.fd = 100
    probe.bindings = list(range(20, 26))
    probe.children = [type("Child", (), {"pid": pid})() for pid in range(10, 16)]
    monkeypatch.setattr(observer.death, "cg_read", lambda *_args: "10 11 12 13 14 15")
    monkeypatch.setattr(observer.select, "select", lambda fds, *_args: ([fds[0]] if fds[0] == 20 else [], [], []))
    with pytest.raises(ValueError, match="listener died"):
        probe.final_binding()
