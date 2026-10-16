"""Untrusted Python behavior cannot enter byte-identity or staging work."""
from __future__ import annotations

import pytest

import etzio.evidence as evidence
from etzio.evidence import EvidenceError, FileEvidenceStore


@pytest.mark.parametrize('behavior', ['plain', 'underreported_length', 'redirected_concat'])
@pytest.mark.parametrize('entrypoint', ['generic_digest', 'typed_digest', 'generic_put', 'typed_put'])
def test_evidence_rejects_bytes_subclasses_before_behavior_or_work(tmp_path, monkeypatch, behavior, entrypoint):
    observed = []

    class PlainBytes(bytes):
        def __bytes__(self):
            observed.append('coercion')
            raise AssertionError('subclass must not be coerced')

    class UnderreportedBytes(PlainBytes):
        def __len__(self):
            observed.append('length')
            return 1

    class RedirectedBytes(PlainBytes):
        def __radd__(self, other):
            observed.append('concatenation')
            return b'redirected-owned-input'

    payload_type = {'plain': PlainBytes, 'underreported_length': UnderreportedBytes,
                    'redirected_concat': RedirectedBytes}[behavior]
    payload = payload_type(b'x' * 64)
    store = FileEvidenceStore(tmp_path / 'evidence', max_artifact_bytes=8)
    # A pre-existing artifact must survive every refusal unchanged.
    prior = store.put(b'prior')
    before = {p.relative_to(store.root): p.read_bytes() for p in store.root.rglob('*') if p.is_file()}

    def forbidden(*args, **kwargs):
        raise AssertionError('invalid input reached hashing or filesystem work')

    with monkeypatch.context() as patch:
        patch.setattr(evidence.hashlib, 'sha256', forbidden)
        patch.setattr(FileEvidenceStore, '_open_root', forbidden)
        with pytest.raises(EvidenceError, match='immutable bytes'):
            if entrypoint == 'generic_digest':
                evidence.evidence_digest(payload)
            elif entrypoint == 'typed_digest':
                evidence.typed_evidence_digest(payload, artifact_type='modeled_poc_input')
            elif entrypoint == 'generic_put':
                store.put(payload)
            else:
                store.put_typed(payload, artifact_type='modeled_poc_input')
    assert observed == []
    assert {p.relative_to(store.root): p.read_bytes() for p in store.root.rglob('*') if p.is_file()} == before
    assert store.get(prior.digest) == b'prior'
