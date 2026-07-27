"""Known-good and known-bad evidence-store controls for protocol v1."""

from __future__ import annotations

import os

import pytest

from etzio.evidence import (
    ArtifactReceipt,
    EvidenceError,
    FileEvidenceStore,
    SnapshotFileV1,
    TargetSnapshotV1,
    evidence_digest,
    read_etzio_fixture,
    read_repository_fixture,
    retain_snapshot,
    validate_etzio_fixture_snapshot,
)


def test_evidence_round_trip_is_content_addressed_and_private(tmp_path):
    store = FileEvidenceStore(tmp_path / "evidence")
    first = store.put(b"exact bytes")
    second = store.put(b"exact bytes")

    assert first == second
    assert first.digest == evidence_digest(b"exact bytes")
    assert store.get(first.digest) == b"exact bytes"
    assert (store.root.stat().st_mode & 0o777) == 0o700
    assert (store._path_for(first.digest).stat().st_mode & 0o777) == 0o600


def test_tampered_artifact_is_rejected(tmp_path):
    store = FileEvidenceStore(tmp_path / "evidence")
    receipt = store.put(b"retained")
    path = store._path_for(receipt.digest)
    path.write_bytes(b"tampered")
    os.chmod(path, 0o600)

    with pytest.raises(EvidenceError, match="digest mismatch"):
        store.get(receipt.digest)


def test_persisted_bytes_are_rehashed_before_put_succeeds(tmp_path, monkeypatch):
    store = FileEvidenceStore(tmp_path / "evidence")
    real_write = os.write

    def corrupting_write(descriptor, data):
        return real_write(descriptor, b"\x00" * len(data))

    monkeypatch.setattr(os, "write", corrupting_write)

    with pytest.raises(EvidenceError, match="post-write verification"):
        store.put(b"retained")


def test_broad_artifact_permissions_are_rejected(tmp_path):
    store = FileEvidenceStore(tmp_path / "evidence")
    receipt = store.put(b"retained")
    os.chmod(store._path_for(receipt.digest), 0o644)

    with pytest.raises(EvidenceError, match="permissions"):
        store.get(receipt.digest)


@pytest.mark.parametrize(
    "digest",
    (
        "../../escape",
        "sha256:xyz",
        "sha256:" + ("a" * 63),
        "SHA256:" + ("a" * 64),
    ),
)
def test_invalid_digest_cannot_address_the_store(tmp_path, digest):
    store = FileEvidenceStore(tmp_path / "evidence")
    with pytest.raises(EvidenceError, match="digest"):
        store.get(digest)


def test_artifact_limit_fails_closed(tmp_path):
    store = FileEvidenceStore(tmp_path / "evidence", max_artifact_bytes=4)
    with pytest.raises(EvidenceError, match="exceeds"):
        store.put(b"12345")


@pytest.mark.parametrize("bad_size", (True, 1.5, -1))
def test_receipt_and_snapshot_sizes_require_exact_nonnegative_integers(bad_size):
    with pytest.raises(EvidenceError, match="size"):
        ArtifactReceipt(evidence_digest(b"a"), bad_size)
    with pytest.raises(EvidenceError, match="size"):
        SnapshotFileV1("a.py", evidence_digest(b"a"), bad_size)


@pytest.mark.parametrize("bad_limit", (True, 1.5, 0, -1))
def test_store_and_fixture_limits_require_exact_positive_integers(tmp_path, bad_limit):
    with pytest.raises(EvidenceError, match="positive"):
        FileEvidenceStore(tmp_path / f"evidence-{bad_limit}", max_artifact_bytes=bad_limit)
    fixture_root = tmp_path / "fixtures"
    fixture_root.mkdir(exist_ok=True)
    fixture = fixture_root / "a.py"
    fixture.write_bytes(b"a")
    with pytest.raises(EvidenceError, match="positive"):
        read_repository_fixture(fixture, fixture_root, maximum=bad_limit)


def test_snapshot_identity_is_order_independent(tmp_path):
    store = FileEvidenceStore(tmp_path / "evidence")
    first = retain_snapshot("repository_fixture", {"b.py": b"b", "a.py": b"a"}, store)
    second = retain_snapshot("repository_fixture", {"a.py": b"a", "b.py": b"b"}, store)

    assert first.object_id == second.object_id
    assert [item.relative_path for item in first.files] == ["a.py", "b.py"]
    assert first.artifacts_by_path()["a.py"] == evidence_digest(b"a")
    assert TargetSnapshotV1.from_envelope(first.to_envelope()) == first


def test_duplicate_or_escaping_snapshot_paths_are_rejected():
    entry = SnapshotFileV1("a.py", evidence_digest(b"a"), 1)
    with pytest.raises(EvidenceError, match="unique"):
        TargetSnapshotV1.create("repository_fixture", (entry, entry))
    with pytest.raises(EvidenceError, match="relative"):
        SnapshotFileV1("../a.py", evidence_digest(b"a"), 1)
    with pytest.raises(EvidenceError, match="normalized"):
        SnapshotFileV1("nested//a.py", evidence_digest(b"a"), 1)


def test_snapshot_direct_construction_cannot_forge_identity_or_mutability(tmp_path):
    store = FileEvidenceStore(tmp_path / "evidence")
    snapshot = retain_snapshot("repository_fixture", {"a.py": b"a"}, store)

    with pytest.raises(EvidenceError, match="object ID"):
        TargetSnapshotV1(snapshot.source, snapshot.files, "sha256:" + ("0" * 64))
    with pytest.raises(EvidenceError, match="tuple"):
        TargetSnapshotV1(snapshot.source, list(snapshot.files), snapshot.object_id)  # type: ignore[arg-type]


def test_snapshot_source_file_count_and_aggregate_bytes_are_bounded(tmp_path):
    store = FileEvidenceStore(tmp_path / "evidence")
    with pytest.raises(EvidenceError, match="repository_fixture"):
        retain_snapshot("caller_supplied_root", {"a.py": b"a"}, store)
    with pytest.raises(EvidenceError, match="file limit"):
        retain_snapshot(
            "repository_fixture",
            {"a.py": b"a", "b.py": b"b"},
            store,
            max_files=1,
        )
    with pytest.raises(EvidenceError, match="byte limit"):
        retain_snapshot(
            "repository_fixture",
            {"a.py": b"aa", "b.py": b"bb"},
            store,
            max_total_bytes=3,
        )
    with pytest.raises(EvidenceError, match="immutable bytes"):
        retain_snapshot(
            "repository_fixture",
            {"a.py": bytearray(b"a")},  # type: ignore[dict-item]
            store,
        )
    with pytest.raises(EvidenceError, match="hard ceiling"):
        retain_snapshot(
            "repository_fixture",
            {"a.py": b"a"},
            store,
            max_files=257,
        )
    small_store = FileEvidenceStore(tmp_path / "small-evidence", max_artifact_bytes=1)
    with pytest.raises(EvidenceError, match="artifact limit"):
        retain_snapshot("repository_fixture", {"late.py": b"too large"}, small_store)
    assert list((tmp_path / "small-evidence").rglob("*")) == []


def test_fixture_reader_refuses_outside_and_symlink(tmp_path):
    fixture_root = tmp_path / "fixtures"
    fixture_root.mkdir()
    fixture = fixture_root / "case.py"
    fixture.write_bytes(b"print('fixture')")
    outside = tmp_path / "outside.py"
    outside.write_bytes(b"print('outside')")
    symlink = fixture_root / "link.py"
    symlink.symlink_to(fixture)

    relative, data = read_repository_fixture(fixture, fixture_root, maximum=1024)
    assert relative == "case.py"
    assert data == b"print('fixture')"
    with pytest.raises(EvidenceError, match="outside"):
        read_repository_fixture(outside, fixture_root, maximum=1024)
    with pytest.raises(EvidenceError, match="symlink"):
        read_repository_fixture(symlink, fixture_root, maximum=1024)


def test_etzio_fixture_reader_uses_a_closed_repository_manifest():
    relative, data = read_etzio_fixture("clean_app.py", maximum=64 * 1024)
    assert relative == "clean_app.py"
    assert b"CLEAN benchmark fixture" in data
    with pytest.raises(EvidenceError, match="manifest"):
        read_etzio_fixture("../../etc/hosts", maximum=64 * 1024)


def test_only_manifested_snapshot_bytes_are_admissible(tmp_path):
    store = FileEvidenceStore(tmp_path / "evidence")
    relative, data = read_etzio_fixture("clean_app.py", maximum=64 * 1024)
    valid = retain_snapshot("repository_fixture", {relative: data}, store)
    validate_etzio_fixture_snapshot(valid, store)

    unmanifested = retain_snapshot(
        "repository_fixture",
        {"caller_supplied.py": b"print('not manifested')"},
        store,
    )
    with pytest.raises(EvidenceError, match="manifest"):
        validate_etzio_fixture_snapshot(unmanifested, store)
