"""Acquired setup resources remain owned until a successful handoff to the writer."""
from __future__ import annotations

import errno
import os
import stat

import pytest

from etzio.evidence import FileEvidenceStore


@pytest.mark.parametrize("failure", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("entrypoint", ["generic", "typed"])
@pytest.mark.parametrize("site", ["shard_mode", "shard_validation", "root_sync", "temporary_mode"])
def test_setup_interruption_releases_resources_and_allows_retry(tmp_path, monkeypatch, failure, entrypoint, site):
    store = FileEvidenceStore(tmp_path / "evidence")
    prior = store.put(b"retained before interruption")
    before = {p.relative_to(store.root): p.read_bytes() for p in store.root.rglob("*") if p.is_file()}
    payload = b"new owned evidence after interruption"
    sentinel = failure("owned setup interruption")
    opened = []
    injected = []
    real_open, real_fstat, real_close = os.open, os.fstat, os.close
    real_fchmod, real_fsync = os.fchmod, os.fsync
    real_validate = FileEvidenceStore._validate_private_directory
    root_identity = (store.root.stat().st_dev, store.root.stat().st_ino)

    def put():
        if entrypoint == "generic":
            return store.put(payload)
        return store.put_typed(payload, artifact_type="modeled_poc_input")

    def tracked_open(*args, **kwargs):
        descriptor = real_open(*args, **kwargs)
        opened.append(descriptor)
        return descriptor

    def interrupt():
        injected.append(site)
        raise sentinel

    def interrupted_mode(descriptor, mode):
        real_fchmod(descriptor, mode)
        metadata = real_fstat(descriptor)
        if site == "shard_mode" and stat.S_ISDIR(metadata.st_mode):
            interrupt()
        if site == "temporary_mode" and stat.S_ISREG(metadata.st_mode):
            interrupt()

    def interrupted_validation(cls, metadata, label):
        real_validate(metadata, label)
        if site == "shard_validation" and label == "evidence shard":
            interrupt()

    def interrupted_sync(descriptor):
        real_fsync(descriptor)
        metadata = real_fstat(descriptor)
        if site == "root_sync" and (metadata.st_dev, metadata.st_ino) == root_identity:
            interrupt()

    with monkeypatch.context() as patch:
        patch.setattr(os, "open", tracked_open)
        patch.setattr(os, "fchmod", interrupted_mode)
        patch.setattr(os, "fsync", interrupted_sync)
        patch.setattr(FileEvidenceStore, "_validate_private_directory", classmethod(interrupted_validation))
        try:
            with pytest.raises(failure) as caught:
                put()
            assert caught.value is sentinel
            assert injected == [site]
            assert len(opened) == (3 if site == "temporary_mode" else 2)
            leaks = []
            for descriptor in set(opened):
                try:
                    real_fstat(descriptor)
                except OSError as exc:
                    assert exc.errno == errno.EBADF
                else:
                    leaks.append(descriptor)
            assert leaks == []
        finally:
            # Clean even on the broken predecessor so the control cannot leak into pytest.
            for descriptor in set(opened):
                try:
                    real_fstat(descriptor)
                except OSError as exc:
                    assert exc.errno == errno.EBADF
                else:
                    real_close(descriptor)

    assert list(store.root.rglob(".incoming-*")) == []
    assert {p.relative_to(store.root): p.read_bytes() for p in store.root.rglob("*") if p.is_file()} == before
    assert store.get(prior.digest) == b"retained before interruption"
    receipt = put()
    assert receipt == put()
    if entrypoint == "generic":
        assert store.get(receipt.digest) == payload
    else:
        assert store.get_typed(receipt.digest, expected_type="modeled_poc_input") == payload
    assert store.get(prior.digest) == b"retained before interruption"
