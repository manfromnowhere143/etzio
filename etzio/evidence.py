"""Content-addressed evidence storage and target snapshots for protocol v1.

This module retains repository-owned fixture bytes only. A digest establishes byte identity,
not truth, authorization, isolation, or exploitability.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType

import unicodedata2 as unicodedata

from .protocol import SEMANTIC_BODY_FIELDS_BY_KIND_V1, EnvelopeV1, content_id, thaw_json

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_EVIDENCE_DOMAIN = b"etzio:evidence:v1\x00"
DEFAULT_MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_SNAPSHOT_BYTES_HARD_CEILING = 64 * 1024 * 1024
MAX_SNAPSHOT_FILES_HARD_CEILING = 256
DEFAULT_MAX_SNAPSHOT_BYTES = MAX_SNAPSHOT_BYTES_HARD_CEILING
DEFAULT_MAX_SNAPSHOT_FILES = MAX_SNAPSHOT_FILES_HARD_CEILING
_REPOSITORY_FIXTURE_SOURCE = "repository_fixture"
_ETZIO_FIXTURE_MANIFEST = MappingProxyType(
    {
        "clean_app.py": (
            754,
            "sha256:1f0d6b7b2a30b9a62a1940f199c4b48909c1a84b8992dced5fe78861dc19e84d",
        ),
        "vulnerable_app.py": (
            964,
            "sha256:e2cc0adcb1773cb51e19be3efa68b5e544252a5c8417a83f1c0a3f4c0524ed33",
        ),
    }
)


class EvidenceError(ValueError):
    """Evidence bytes or their storage violate the protocol-v1 contract."""


def evidence_digest(data: bytes) -> str:
    if not isinstance(data, bytes):
        raise EvidenceError("evidence must be bytes")
    return f"sha256:{hashlib.sha256(_EVIDENCE_DOMAIN + data).hexdigest()}"


@dataclass(frozen=True, slots=True)
class ArtifactReceipt:
    digest: str
    size: int

    def __post_init__(self) -> None:
        if type(self.digest) is not str or not _DIGEST_RE.fullmatch(self.digest):
            raise EvidenceError("invalid evidence digest")
        if type(self.size) is not int or self.size < 0:
            raise EvidenceError("artifact size must be nonnegative")


class FileEvidenceStore:
    """Private local CAS with exclusive creation, fsync, and rehash-on-read.

    The store is locally durable against ordinary process interruption. It does not defend
    against an operator who controls the filesystem and process identity.
    """

    def __init__(self, root: str | Path, *, max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES) -> None:
        self.root = Path(root)
        if type(max_artifact_bytes) is not int or max_artifact_bytes <= 0:
            raise EvidenceError("max_artifact_bytes must be positive")
        self.max_artifact_bytes = max_artifact_bytes
        if self.root.is_symlink():
            raise EvidenceError("evidence root may not be a symlink")
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not self.root.is_dir():
            raise EvidenceError("evidence root is not a directory")
        os.chmod(self.root, 0o700)

    def _path_for(self, digest: str) -> Path:
        if not _DIGEST_RE.fullmatch(digest):
            raise EvidenceError("invalid evidence digest")
        hexadecimal = digest.removeprefix("sha256:")
        return self.root / hexadecimal[:2] / hexadecimal[2:]

    @staticmethod
    def _read_exact(path: Path, maximum: int) -> bytes:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise EvidenceError(f"cannot open evidence artifact: {exc}") from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise EvidenceError("evidence artifact is not a regular file")
            if stat.S_IMODE(metadata.st_mode) & 0o077:
                raise EvidenceError("evidence artifact permissions are too broad")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > maximum:
                    raise EvidenceError("evidence artifact exceeds configured limit")
            return b"".join(chunks)
        finally:
            os.close(descriptor)

    def put(self, data: bytes) -> ArtifactReceipt:
        if not isinstance(data, bytes):
            raise EvidenceError("evidence must be bytes")
        if len(data) > self.max_artifact_bytes:
            raise EvidenceError("evidence artifact exceeds configured limit")
        digest = evidence_digest(data)
        target = self._path_for(digest)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(target.parent, 0o700)

        if target.exists():
            existing = self._read_exact(target, self.max_artifact_bytes)
            if evidence_digest(existing) != digest:
                raise EvidenceError("existing evidence artifact fails digest verification")
            return ArtifactReceipt(digest, len(existing))

        descriptor, temporary_name = tempfile.mkstemp(prefix=".incoming-", dir=target.parent)
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            view = memoryview(data)
            written = 0
            while written < len(view):
                written += os.write(descriptor, view[written:])
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            try:
                os.link(temporary, target)
            except FileExistsError as exc:
                existing = self._read_exact(target, self.max_artifact_bytes)
                if evidence_digest(existing) != digest:
                    raise EvidenceError(
                        "concurrent evidence artifact fails digest verification"
                    ) from exc
            directory = os.open(target.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            persisted = self._read_exact(target, self.max_artifact_bytes)
            if len(persisted) != len(data) or evidence_digest(persisted) != digest:
                raise EvidenceError(
                    "persisted evidence artifact fails post-write verification"
                )
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            temporary.unlink(missing_ok=True)
        return ArtifactReceipt(digest, len(data))

    def get(self, digest: str) -> bytes:
        path = self._path_for(digest)
        data = self._read_exact(path, self.max_artifact_bytes)
        if evidence_digest(data) != digest:
            raise EvidenceError("evidence artifact digest mismatch")
        return data


def _validate_relative_path(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise EvidenceError("snapshot path must be a nonempty string")
    if unicodedata.normalize("NFC", value) != value:
        raise EvidenceError("snapshot path must be NFC-normalized")
    path = PurePosixPath(value)
    if value == "." or path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise EvidenceError("snapshot path must be normalized and relative")
    if path.as_posix() != value:
        raise EvidenceError("snapshot path must be normalized and relative")
    if "\\" in value or "\x00" in value:
        raise EvidenceError("snapshot path contains a forbidden character")
    return value


@dataclass(frozen=True, slots=True)
class SnapshotFileV1:
    relative_path: str
    artifact_digest: str
    size: int

    def __post_init__(self) -> None:
        _validate_relative_path(self.relative_path)
        if type(self.artifact_digest) is not str or not _DIGEST_RE.fullmatch(
            self.artifact_digest
        ):
            raise EvidenceError("invalid snapshot artifact digest")
        if type(self.size) is not int or self.size < 0:
            raise EvidenceError("snapshot file size must be nonnegative")

    def to_dict(self) -> dict[str, object]:
        return {
            "artifact_digest": self.artifact_digest,
            "relative_path": self.relative_path,
            "size": self.size,
        }


@dataclass(frozen=True, slots=True)
class TargetSnapshotV1:
    source: str
    files: tuple[SnapshotFileV1, ...]
    object_id: str

    def __post_init__(self) -> None:
        if self.source != _REPOSITORY_FIXTURE_SOURCE:
            raise EvidenceError("protocol-v1 snapshots must use the repository_fixture source")
        if not isinstance(self.files, tuple) or not self.files:
            raise EvidenceError("target snapshot files must be a nonempty tuple")
        if any(not isinstance(item, SnapshotFileV1) for item in self.files):
            raise EvidenceError("target snapshot contains an invalid file entry")
        if len(self.files) > MAX_SNAPSHOT_FILES_HARD_CEILING:
            raise EvidenceError("target snapshot exceeds the hard file-count ceiling")
        if sum(item.size for item in self.files) > MAX_SNAPSHOT_BYTES_HARD_CEILING:
            raise EvidenceError("target snapshot exceeds the hard aggregate-byte ceiling")
        paths = [item.relative_path for item in self.files]
        if paths != sorted(paths):
            raise EvidenceError("target snapshot files must use canonical path order")
        if len(paths) != len(set(paths)):
            raise EvidenceError("target snapshot paths must be unique")
        body = self.to_body_dict()
        if self.object_id != content_id("target_snapshot", body):
            raise EvidenceError("target snapshot object ID does not match its content")

    @classmethod
    def create(cls, source: str, files: tuple[SnapshotFileV1, ...]) -> TargetSnapshotV1:
        if source != _REPOSITORY_FIXTURE_SOURCE:
            raise EvidenceError("protocol-v1 snapshots must use the repository_fixture source")
        if not files:
            raise EvidenceError("target snapshot must contain at least one file")
        ordered = tuple(sorted(files, key=lambda item: item.relative_path))
        paths = [item.relative_path for item in ordered]
        if len(paths) != len(set(paths)):
            raise EvidenceError("target snapshot paths must be unique")
        body = {"files": [item.to_dict() for item in ordered], "source": source}
        return cls(source=source, files=ordered, object_id=content_id("target_snapshot", body))

    def to_body_dict(self) -> dict[str, object]:
        """Return the semantic body used for the target-snapshot envelope identity."""
        return {
            "files": [item.to_dict() for item in self.files],
            "source": self.source,
        }

    def to_record_dict(self) -> dict[str, object]:
        """Return a display/storage record including the derived object identifier."""
        return {
            "files": [item.to_dict() for item in self.files],
            "object_id": self.object_id,
            "source": self.source,
        }

    def to_envelope(self) -> EnvelopeV1:
        envelope = EnvelopeV1.create("target_snapshot", self.to_body_dict())
        if envelope.object_id != self.object_id:
            raise EvidenceError("target snapshot object ID does not match its envelope")
        return envelope

    @classmethod
    def from_envelope(cls, envelope: EnvelopeV1) -> TargetSnapshotV1:
        if envelope.object_kind != "target_snapshot" or envelope.attestations:
            raise EvidenceError("expected an unattested target_snapshot envelope")
        body = thaw_json(envelope.body)
        if (
            type(body) is not dict
            or set(body) != SEMANTIC_BODY_FIELDS_BY_KIND_V1["target_snapshot"]
        ):
            raise EvidenceError("target snapshot envelope has missing or unknown fields")
        raw_files = body["files"]
        if type(raw_files) is not list:
            raise EvidenceError("target snapshot files must be an array")
        entries: list[SnapshotFileV1] = []
        for raw_file in raw_files:
            if type(raw_file) is not dict or set(raw_file) != {
                "artifact_digest",
                "relative_path",
                "size",
            }:
                raise EvidenceError("target snapshot contains an invalid file entry")
            entries.append(SnapshotFileV1(**raw_file))
        return cls(source=body["source"], files=tuple(entries), object_id=envelope.object_id)

    def artifacts_by_path(self) -> Mapping[str, str]:
        return MappingProxyType({item.relative_path: item.artifact_digest for item in self.files})


def retain_snapshot(
    source: str,
    files: Mapping[str, bytes],
    evidence_store: FileEvidenceStore,
    *,
    max_files: int = DEFAULT_MAX_SNAPSHOT_FILES,
    max_total_bytes: int = DEFAULT_MAX_SNAPSHOT_BYTES,
) -> TargetSnapshotV1:
    """Retain an explicit byte mapping and return a content-bound target snapshot."""
    if source != _REPOSITORY_FIXTURE_SOURCE:
        raise EvidenceError("protocol-v1 snapshots must use the repository_fixture source")
    if type(max_files) is not int or max_files <= 0:
        raise EvidenceError("snapshot file limit must be a positive integer")
    if type(max_total_bytes) is not int or max_total_bytes <= 0:
        raise EvidenceError("snapshot byte limit must be a positive integer")
    if max_files > MAX_SNAPSHOT_FILES_HARD_CEILING:
        raise EvidenceError("snapshot file limit exceeds the hard ceiling")
    if max_total_bytes > MAX_SNAPSHOT_BYTES_HARD_CEILING:
        raise EvidenceError("snapshot byte limit exceeds the hard ceiling")
    if not files:
        raise EvidenceError("target snapshot must contain at least one file")
    if len(files) > max_files:
        raise EvidenceError("target snapshot exceeds the configured file limit")
    validated: list[tuple[str, bytes]] = []
    total_bytes = 0
    for relative_path, data in files.items():
        normalized = _validate_relative_path(relative_path)
        if type(data) is not bytes:
            raise EvidenceError("snapshot file content must be immutable bytes")
        if len(data) > evidence_store.max_artifact_bytes:
            raise EvidenceError("snapshot file exceeds the evidence-store artifact limit")
        total_bytes += len(data)
        if total_bytes > max_total_bytes:
            raise EvidenceError("target snapshot exceeds the configured byte limit")
        validated.append((normalized, data))

    entries: list[SnapshotFileV1] = []
    for normalized, data in validated:
        receipt = evidence_store.put(data)
        entries.append(SnapshotFileV1(normalized, receipt.digest, receipt.size))
    return TargetSnapshotV1.create(source, tuple(entries))


def read_etzio_fixture(filename: str, *, maximum: int) -> tuple[str, bytes]:
    """Read one immutable-manifest Etzio fixture from the installed package tree."""
    manifest_entry = _ETZIO_FIXTURE_MANIFEST.get(filename)
    if manifest_entry is None:
        raise EvidenceError("fixture is not present in the Etzio repository-owned manifest")
    root = Path(__file__).with_name("fixtures_code")
    relative, data = read_repository_fixture(root / filename, root, maximum=maximum)
    expected_size, expected_digest = manifest_entry
    if len(data) != expected_size or evidence_digest(data) != expected_digest:
        raise EvidenceError("Etzio fixture bytes do not match the immutable manifest")
    return relative, data


def validate_etzio_fixture_snapshot(
    snapshot: TargetSnapshotV1,
    evidence_store: FileEvidenceStore,
) -> None:
    """Require every target entry to match the immutable repository fixture manifest."""
    if not isinstance(snapshot, TargetSnapshotV1):
        raise EvidenceError("fixture snapshot must be a TargetSnapshotV1")
    for snapshot_file in snapshot.files:
        manifest_entry = _ETZIO_FIXTURE_MANIFEST.get(snapshot_file.relative_path)
        if manifest_entry is None:
            raise EvidenceError("snapshot path is not present in the Etzio fixture manifest")
        expected_size, expected_digest = manifest_entry
        if (
            snapshot_file.size != expected_size
            or snapshot_file.artifact_digest != expected_digest
        ):
            raise EvidenceError("snapshot metadata does not match the Etzio fixture manifest")
        data = evidence_store.get(snapshot_file.artifact_digest)
        if len(data) != expected_size or evidence_digest(data) != expected_digest:
            raise EvidenceError("snapshot bytes do not match the Etzio fixture manifest")


def read_repository_fixture(path: str | Path, fixture_root: str | Path, *, maximum: int) -> tuple[str, bytes]:
    """Read one repository-owned fixture without following a fixture-file symlink."""
    if type(maximum) is not int or maximum <= 0:
        raise EvidenceError("fixture byte limit must be positive")
    candidate = Path(path)
    root = Path(fixture_root).resolve(strict=True)
    if not root.is_dir():
        raise EvidenceError("fixture root is not a directory")
    if candidate.is_symlink():
        raise EvidenceError("fixture path may not be a symlink")
    resolved = candidate.resolve(strict=True)
    try:
        relative = resolved.relative_to(root)
    except ValueError as exc:
        raise EvidenceError("fixture path is outside the repository fixture root") from exc
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(resolved, flags)
    except OSError as exc:
        raise EvidenceError(f"cannot open fixture: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise EvidenceError("fixture path is not a regular file")
        if metadata.st_size > maximum:
            raise EvidenceError("fixture exceeds configured byte limit")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise EvidenceError("fixture exceeds configured byte limit")
        data = b"".join(chunks)
    finally:
        os.close(descriptor)
    return relative.as_posix(), data
