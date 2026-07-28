"""Known-good and known-bad evidence-store controls for protocol v1."""

from __future__ import annotations

import os
import stat
from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest

import etzio.evidence as evidence
from etzio.evidence import (
    VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1,
    VERIFICATION_ARTIFACT_TYPES_V1,
    VERIFICATION_INPUT_ARTIFACT_TYPE_BY_ROLE_V1,
    VERIFICATION_OUTPUT_ARTIFACT_TYPE_BY_ROLE_V1,
    ArtifactReceipt,
    EvidenceError,
    FileEvidenceStore,
    SnapshotFileV1,
    TargetSnapshotV1,
    TypedArtifactReceipt,
    evidence_digest,
    read_etzio_fixture,
    read_repository_fixture,
    retain_snapshot,
    typed_evidence_digest,
    validate_etzio_fixture_snapshot,
)


def test_typed_artifact_registry_and_digest_vectors_are_exact_and_immutable():
    expected_inputs = {
        "effect_oracle": "modeled_effect_oracle_spec",
        "environment": "modeled_environment_spec",
        "evidence": "modeled_supporting_evidence_input",
        "poc": "modeled_poc_input",
    }
    expected_outputs = {
        "effect_output": "modeled_effect_output",
        "execution_output": "modeled_execution_output",
        "measured_environment_output": "modeled_measured_environment_output",
        "termination_output": "modeled_termination_output",
    }
    assert dict(VERIFICATION_INPUT_ARTIFACT_TYPE_BY_ROLE_V1) == expected_inputs
    assert dict(VERIFICATION_OUTPUT_ARTIFACT_TYPE_BY_ROLE_V1) == expected_outputs
    assert dict(VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1) == {
        **expected_inputs,
        **expected_outputs,
    }
    assert VERIFICATION_ARTIFACT_TYPES_V1 == frozenset(VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1.values())
    with pytest.raises(TypeError):
        VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["poc"] = "changed"  # type: ignore[index]
    with pytest.raises(TypeError):
        VERIFICATION_OUTPUT_ARTIFACT_TYPE_BY_ROLE_V1["effect_output"] = "changed"  # type: ignore[index]

    assert evidence_digest(b"exact bytes") == (
        "sha256:0c3353c8b645c751e1919e28cd21b20c6fd9ff6dddae6ab42741e1eab66c804a"
    )
    assert typed_evidence_digest(
        b"exact typed bytes",
        artifact_type="modeled_poc_input",
    ) == ("sha256:35da3fb47a4e38d1a017c243fe0eb7e3ca612361174a79a6437a01750f5204c4")


def test_typed_evidence_round_trip_is_role_bound_and_private(tmp_path):
    store = FileEvidenceStore(tmp_path / "evidence")
    payload = b"repository-owned modeled input"
    receipt = store.put_typed(
        payload,
        artifact_type="modeled_poc_input",
    )
    repeated = store.put_typed(
        payload,
        artifact_type="modeled_poc_input",
    )

    assert (
        receipt
        == repeated
        == TypedArtifactReceipt(
            digest=typed_evidence_digest(
                payload,
                artifact_type="modeled_poc_input",
            ),
            size=len(payload),
            artifact_type="modeled_poc_input",
        )
    )
    assert (
        store.get_typed(
            receipt.digest,
            expected_type="modeled_poc_input",
        )
        == payload
    )
    assert (store._path_for(receipt.digest).stat().st_mode & 0o777) == 0o600
    assert store._path_for(receipt.digest).stat().st_nlink == 1


def test_generic_and_typed_digest_domains_cannot_be_confused(tmp_path):
    store = FileEvidenceStore(tmp_path / "evidence")
    payload = b"same exact bytes"
    generic = store.put(payload)
    poc = store.put_typed(payload, artifact_type="modeled_poc_input")
    environment = store.put_typed(
        payload,
        artifact_type="modeled_environment_spec",
    )

    assert len({generic.digest, poc.digest, environment.digest}) == 3
    with pytest.raises(EvidenceError, match="digest"):
        store.get(poc.digest)
    with pytest.raises(EvidenceError, match="digest"):
        store.get_typed(
            generic.digest,
            expected_type="modeled_poc_input",
        )
    with pytest.raises(EvidenceError, match="type mismatch"):
        store.get_typed(
            poc.digest,
            expected_type="modeled_environment_spec",
        )


@pytest.mark.parametrize(
    "artifact_type",
    (
        "",
        "MODELED_POC_INPUT",
        "modeled_poc_input\x00modeled_environment_spec",
        "modeled_poc_input ",
        "unknown",
        True,
        None,
    ),
)
def test_typed_evidence_rejects_every_non_allowlisted_type(
    tmp_path,
    artifact_type,
):
    store = FileEvidenceStore(tmp_path / "evidence")
    with pytest.raises(EvidenceError, match="unknown"):
        typed_evidence_digest(b"bytes", artifact_type=artifact_type)
    with pytest.raises(EvidenceError, match="unknown"):
        store.put_typed(b"bytes", artifact_type=artifact_type)
    with pytest.raises(EvidenceError, match="unknown"):
        store.get_typed(
            "sha256:" + ("0" * 64),
            expected_type=artifact_type,
        )


@pytest.mark.parametrize("payload", ("text", bytearray(b"bytes"), memoryview(b"bytes")))
def test_typed_evidence_accepts_only_immutable_exact_bytes(tmp_path, payload):
    store = FileEvidenceStore(tmp_path / "evidence")
    with pytest.raises(EvidenceError, match="immutable bytes"):
        typed_evidence_digest(payload, artifact_type="modeled_poc_input")
    with pytest.raises(EvidenceError, match="immutable bytes"):
        store.put_typed(payload, artifact_type="modeled_poc_input")


def test_typed_store_rejects_empty_inputs_while_legacy_store_preserves_them(
    tmp_path,
):
    legacy_store = FileEvidenceStore(tmp_path / "legacy")
    legacy_receipt = legacy_store.put(b"")
    assert legacy_receipt.size == 0
    assert legacy_store.get(legacy_receipt.digest) == b""

    typed_store = FileEvidenceStore(tmp_path / "typed")
    artifact_type = VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["poc"]
    empty_typed_digest = typed_evidence_digest(
        b"",
        artifact_type=artifact_type,
    )
    with pytest.raises(EvidenceError, match="nonempty"):
        typed_store.put_typed(b"", artifact_type=artifact_type)

    empty_typed_path = typed_store._path_for(empty_typed_digest)
    empty_typed_path.parent.mkdir(mode=0o700)
    empty_typed_path.write_bytes(b"")
    os.chmod(empty_typed_path, 0o600)
    with pytest.raises(EvidenceError, match="nonempty"):
        typed_store.get_typed(
            empty_typed_digest,
            expected_type=artifact_type,
        )


def test_typed_receipt_requires_exact_fields():
    valid_digest = typed_evidence_digest(
        b"bytes",
        artifact_type="modeled_poc_input",
    )
    with pytest.raises(EvidenceError, match="typed evidence digest"):
        TypedArtifactReceipt(
            digest="not-a-digest",
            size=5,
            artifact_type="modeled_poc_input",
        )
    with pytest.raises(EvidenceError, match="size"):
        TypedArtifactReceipt(
            digest=valid_digest,
            size=True,
            artifact_type="modeled_poc_input",
        )
    with pytest.raises(EvidenceError, match="positive"):
        TypedArtifactReceipt(
            digest=valid_digest,
            size=0,
            artifact_type="modeled_poc_input",
        )
    with pytest.raises(EvidenceError, match="unknown"):
        TypedArtifactReceipt(
            digest=valid_digest,
            size=5,
            artifact_type="unknown",
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


def test_existing_root_and_shard_permissions_are_not_silently_changed(tmp_path):
    broad_root = tmp_path / "broad-root"
    broad_root.mkdir(mode=0o700)
    os.chmod(broad_root, 0o755)
    with pytest.raises(EvidenceError, match="0700"):
        FileEvidenceStore(broad_root)
    assert (broad_root.stat().st_mode & 0o777) == 0o755

    store = FileEvidenceStore(tmp_path / "evidence")
    digest = typed_evidence_digest(
        b"typed",
        artifact_type="modeled_poc_input",
    )
    shard = store._path_for(digest).parent
    shard.mkdir(mode=0o700)
    os.chmod(shard, 0o755)
    with pytest.raises(EvidenceError, match="0700"):
        store.put_typed(
            b"typed",
            artifact_type="modeled_poc_input",
        )
    assert (shard.stat().st_mode & 0o777) == 0o755


def test_directory_and_artifact_owner_mismatches_are_rejected(tmp_path, monkeypatch):
    if not hasattr(os, "geteuid"):
        pytest.skip("effective-user ownership checks require a POSIX platform")

    directory = tmp_path / "directory"
    directory.mkdir(mode=0o700)
    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"bytes")
    os.chmod(artifact, 0o600)
    actual_uid = directory.stat().st_uid
    monkeypatch.setattr(os, "geteuid", lambda: actual_uid + 1)

    with pytest.raises(EvidenceError, match="owned by the effective user"):
        FileEvidenceStore._validate_private_directory(
            directory.stat(),
            "evidence root",
        )
    with pytest.raises(EvidenceError, match="owned by the effective user"):
        FileEvidenceStore._validate_private_artifact(artifact.stat())


def test_symlink_root_shard_and_artifact_are_rejected(tmp_path):
    external_root = tmp_path / "external-root"
    external_root.mkdir(mode=0o700)
    symlink_root = tmp_path / "symlink-root"
    symlink_root.symlink_to(external_root, target_is_directory=True)
    with pytest.raises(EvidenceError, match="symlink"):
        FileEvidenceStore(symlink_root)

    store = FileEvidenceStore(tmp_path / "evidence")
    payload = b"typed artifact"
    digest = typed_evidence_digest(
        payload,
        artifact_type="modeled_poc_input",
    )
    artifact_path = store._path_for(digest)
    external_shard = tmp_path / "external-shard"
    external_shard.mkdir(mode=0o700)
    artifact_path.parent.symlink_to(
        external_shard,
        target_is_directory=True,
    )
    with pytest.raises(EvidenceError, match="shard"):
        store.put_typed(
            payload,
            artifact_type="modeled_poc_input",
        )
    assert list(external_shard.iterdir()) == []

    artifact_path.parent.unlink()
    receipt = store.put_typed(
        payload,
        artifact_type="modeled_poc_input",
    )
    stored_path = store._path_for(receipt.digest)
    outside = tmp_path / "outside"
    outside.write_bytes(payload)
    os.chmod(outside, 0o600)
    stored_path.unlink()
    stored_path.symlink_to(outside)
    with pytest.raises(EvidenceError, match="securely open"):
        store.get_typed(
            receipt.digest,
            expected_type="modeled_poc_input",
        )


def test_nonregular_artifact_is_rejected(tmp_path):
    store = FileEvidenceStore(tmp_path / "evidence")
    artifact_type = VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["poc"]
    digest = typed_evidence_digest(b"typed artifact", artifact_type=artifact_type)
    artifact_path = store._path_for(digest)
    artifact_path.parent.mkdir(mode=0o700)
    artifact_path.mkdir(mode=0o700)

    with pytest.raises(EvidenceError, match="not a regular file"):
        store.get_typed(digest, expected_type=artifact_type)


def test_hardlinked_artifacts_are_rejected_on_get_and_put(tmp_path):
    store = FileEvidenceStore(tmp_path / "evidence")
    payload = b"typed artifact"
    receipt = store.put_typed(
        payload,
        artifact_type="modeled_poc_input",
    )
    alias = tmp_path / "artifact-alias"
    os.link(store._path_for(receipt.digest), alias)

    with pytest.raises(EvidenceError, match="hard-linked"):
        store.get_typed(
            receipt.digest,
            expected_type="modeled_poc_input",
        )
    with pytest.raises(EvidenceError, match="hard-linked"):
        store.put_typed(
            payload,
            artifact_type="modeled_poc_input",
        )


def test_typed_artifact_missing_tampering_and_broad_mode_fail_closed(tmp_path):
    store = FileEvidenceStore(tmp_path / "evidence")
    missing = typed_evidence_digest(
        b"missing",
        artifact_type="modeled_poc_input",
    )
    with pytest.raises(EvidenceError, match="not found"):
        store.get_typed(
            missing,
            expected_type="modeled_poc_input",
        )

    tampered = store.put_typed(
        b"retained",
        artifact_type="modeled_poc_input",
    )
    tampered_path = store._path_for(tampered.digest)
    tampered_path.write_bytes(b"tampered")
    os.chmod(tampered_path, 0o600)
    with pytest.raises(EvidenceError, match="digest"):
        store.get_typed(
            tampered.digest,
            expected_type="modeled_poc_input",
        )

    broad = store.put_typed(
        b"private",
        artifact_type="modeled_environment_spec",
    )
    os.chmod(store._path_for(broad.digest), 0o640)
    with pytest.raises(EvidenceError, match="0600"):
        store.get_typed(
            broad.digest,
            expected_type="modeled_environment_spec",
        )


def test_concurrent_identical_typed_puts_converge_without_temporary_aliases(
    tmp_path,
):
    store = FileEvidenceStore(tmp_path / "evidence")

    def put_once(payload):
        return store.put_typed(
            payload,
            artifact_type="modeled_supporting_evidence_input",
        )

    for wave in range(4):
        payload = f"one immutable modeled input {wave}".encode()

        with ThreadPoolExecutor(max_workers=8) as executor:
            receipts = tuple(executor.map(put_once, (payload,) * 32))

        assert len(set(receipts)) == 1
        receipt = receipts[0]
        assert (
            store.get_typed(
                receipt.digest,
                expected_type="modeled_supporting_evidence_input",
            )
            == payload
        )
        artifact_path = store._path_for(receipt.digest)
        assert artifact_path.stat().st_nlink == 1
        assert not tuple(artifact_path.parent.glob(".incoming-*"))


def test_paused_winning_publisher_does_not_block_identical_convergence(
    tmp_path,
    monkeypatch,
):
    store = FileEvidenceStore(tmp_path / "evidence")
    payload = b"one immutable input across a paused publication"
    published = Event()
    release_winner = Event()
    concurrent_directory_synced = Event()
    original_rename = evidence._rename_noreplace
    original_fsync = evidence.os.fsync

    def rename_then_pause(
        directory_descriptor: int,
        source_name: str,
        target_name: str,
    ) -> None:
        original_rename(
            directory_descriptor,
            source_name,
            target_name,
        )
        published.set()
        if not release_winner.wait(timeout=5):
            raise AssertionError("test did not release the winning publisher")

    monkeypatch.setattr(evidence, "_rename_noreplace", rename_then_pause)

    def record_fsync(descriptor: int) -> None:
        original_fsync(descriptor)
        if (
            published.is_set()
            and not release_winner.is_set()
            and stat.S_ISDIR(os.fstat(descriptor).st_mode)
        ):
            concurrent_directory_synced.set()

    monkeypatch.setattr(evidence.os, "fsync", record_fsync)

    def put_once():
        return store.put_typed(
            payload,
            artifact_type=VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["evidence"],
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        winner = executor.submit(put_once)
        assert published.wait(timeout=5)
        concurrent = executor.submit(put_once)
        concurrent_receipt = concurrent.result(timeout=2)
        assert concurrent_directory_synced.is_set()
        release_winner.set()
        winning_receipt = winner.result(timeout=5)

    assert winning_receipt == concurrent_receipt
    artifact_path = store._path_for(winning_receipt.digest)
    assert artifact_path.stat().st_nlink == 1
    assert not tuple(artifact_path.parent.glob(".incoming-*"))


def test_no_clobber_publication_never_replaces_an_existing_name(tmp_path):
    store = FileEvidenceStore(tmp_path / "evidence")
    payload = b"expected immutable typed bytes"
    artifact_type = VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["poc"]
    digest = typed_evidence_digest(payload, artifact_type=artifact_type)
    artifact_path = store._path_for(digest)
    artifact_path.parent.mkdir(mode=0o700)
    substituted = b"preexisting substituted bytes"
    artifact_path.write_bytes(substituted)
    os.chmod(artifact_path, 0o600)

    with pytest.raises(EvidenceError, match="fails digest verification"):
        store.put_typed(payload, artifact_type=artifact_type)

    assert artifact_path.read_bytes() == substituted
    assert not tuple(artifact_path.parent.glob(".incoming-*"))


def test_store_fails_closed_without_a_native_exclusive_rename(
    tmp_path,
    monkeypatch,
):
    store = FileEvidenceStore(tmp_path / "evidence")
    monkeypatch.setattr(evidence, "_EXCLUSIVE_RENAME", None)

    with pytest.raises(EvidenceError, match="unsupported"):
        store.put_typed(
            b"typed bytes",
            artifact_type=VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["poc"],
        )

    assert not tuple((tmp_path / "evidence").rglob(".incoming-*"))


def test_generic_and_typed_reads_apply_exact_caller_bounds(tmp_path):
    store = FileEvidenceStore(tmp_path / "evidence", max_artifact_bytes=8)
    generic = store.put(b"12345678")
    typed = store.put_typed(
        b"abcdefgh",
        artifact_type="modeled_effect_oracle_spec",
    )

    assert store.get(generic.digest, maximum=8) == b"12345678"
    assert (
        store.get_typed(
            typed.digest,
            expected_type="modeled_effect_oracle_spec",
            maximum=8,
        )
        == b"abcdefgh"
    )
    with pytest.raises(EvidenceError, match="exceeds"):
        store.get(generic.digest, maximum=7)
    with pytest.raises(EvidenceError, match="exceeds"):
        store.get_typed(
            typed.digest,
            expected_type="modeled_effect_oracle_spec",
            maximum=7,
        )
    with pytest.raises(EvidenceError, match="exceeds"):
        store.put_typed(
            b"123456789",
            artifact_type="modeled_effect_oracle_spec",
        )
    for invalid in (True, -1, 1.5, "8"):
        with pytest.raises(EvidenceError, match="nonnegative integer"):
            store.get(generic.digest, maximum=invalid)


def test_oversized_puts_are_rejected_before_digest_work(
    tmp_path,
    monkeypatch,
):
    store = FileEvidenceStore(tmp_path / "evidence", max_artifact_bytes=4)

    def digest_must_not_run(*_args, **_kwargs):
        raise AssertionError("oversized input reached digest computation")

    monkeypatch.setattr(evidence, "evidence_digest", digest_must_not_run)
    with pytest.raises(EvidenceError, match="exceeds"):
        store.put(b"12345")

    monkeypatch.setattr(
        evidence,
        "typed_evidence_digest",
        digest_must_not_run,
    )
    with pytest.raises(EvidenceError, match="exceeds"):
        store.put_typed(
            b"12345",
            artifact_type=VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["poc"],
        )


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


def test_fixture_manifest_validation_bounds_reads_to_the_expected_size(
    tmp_path,
):
    store = FileEvidenceStore(
        tmp_path / "evidence",
        max_artifact_bytes=1024 * 1024,
    )
    relative, data = read_etzio_fixture("clean_app.py", maximum=64 * 1024)
    snapshot = retain_snapshot(
        "repository_fixture",
        {relative: data},
        store,
    )
    artifact_path = store._path_for(snapshot.files[0].artifact_digest)
    artifact_path.write_bytes(b"x" * (snapshot.files[0].size + 1))
    os.chmod(artifact_path, 0o600)

    with pytest.raises(EvidenceError, match="exceeds configured limit"):
        validate_etzio_fixture_snapshot(snapshot, store)
