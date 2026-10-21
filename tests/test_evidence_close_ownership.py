"""An ambiguous close must never close a newly reused descriptor number."""
from __future__ import annotations

import errno
import os
import stat

import pytest

from etzio.evidence import FileEvidenceStore


@pytest.mark.parametrize("failure", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("entrypoint", ["generic", "typed"])
@pytest.mark.parametrize("close_state", ["not_released", "released", "reused"])
def test_temporary_close_is_attempted_once(tmp_path, monkeypatch, failure, entrypoint, close_state):
    store = FileEvidenceStore(tmp_path / "evidence")
    prior = store.put(b"retained evidence")
    before = {p.relative_to(store.root): p.read_bytes() for p in store.root.rglob("*") if p.is_file()}
    unrelated = tmp_path / "unrelated"
    unrelated.write_bytes(b"unrelated owned descriptor")
    payload = b"new evidence at the close boundary"
    sentinel = failure("owned ambiguous close")
    real_close, real_open, real_fstat = os.close, os.open, os.fstat
    closing = []
    attempts = []
    replacement = []

    def put():
        if entrypoint == "generic":
            return store.put(payload)
        return store.put_typed(payload, artifact_type="modeled_poc_input")

    def interrupted_close(descriptor):
        if closing:
            if descriptor == closing[0]:
                attempts.append(descriptor)
            return real_close(descriptor)
        if not stat.S_ISREG(real_fstat(descriptor).st_mode):
            return real_close(descriptor)
        closing.append(descriptor)
        attempts.append(descriptor)
        if close_state != "not_released":
            real_close(descriptor)
        if close_state == "reused":
            replacement.append(real_open(unrelated, os.O_RDONLY))
            assert replacement[0] == descriptor
        raise sentinel

    try:
        with monkeypatch.context() as patch:
            patch.setattr(os, "close", interrupted_close)
            with pytest.raises(failure) as caught:
                put()
            assert caught.value is sentinel
        assert len(attempts) == 1
        if close_state == "reused":
            metadata = real_fstat(closing[0])
            assert (metadata.st_dev, metadata.st_ino) == (unrelated.stat().st_dev, unrelated.stat().st_ino)
            assert os.read(replacement[0], 64) == b"unrelated owned descriptor"
        elif close_state == "not_released":
            # The failure did not release the resource; blindly retrying is still unsafe.
            assert real_fstat(closing[0]).st_nlink == 0
        else:
            with pytest.raises(OSError) as closed:
                real_fstat(closing[0])
            assert closed.value.errno == errno.EBADF
        assert list(store.root.rglob(".incoming-*")) == []
        assert {p.relative_to(store.root): p.read_bytes() for p in store.root.rglob("*") if p.is_file()} == before
    finally:
        # Clean any deliberately retained descriptor, including on a failing predecessor.
        for descriptor in set(closing + replacement):
            try:
                real_fstat(descriptor)
            except OSError as exc:
                assert exc.errno == errno.EBADF
            else:
                real_close(descriptor)

    assert store.get(prior.digest) == b"retained evidence"
    receipt = put()
    assert receipt == put()
    if entrypoint == "generic":
        assert store.get(receipt.digest) == payload
    else:
        assert store.get_typed(receipt.digest, expected_type="modeled_poc_input") == payload
    assert store.get(prior.digest) == b"retained evidence"
