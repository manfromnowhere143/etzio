"""Content-addressed evidence storage and target snapshots for protocol v1.

This module retains repository-owned fixture bytes only. A digest establishes byte identity,
not truth, authorization, isolation, or exploitability.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import os
import re
import secrets
import stat
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Final

import unicodedata2 as unicodedata

from .protocol import SEMANTIC_BODY_FIELDS_BY_KIND_V1, EnvelopeV1, content_id, thaw_json

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_EVIDENCE_DOMAIN = b"etzio:evidence:v1\x00"
_TYPED_EVIDENCE_DOMAIN = b"etzio:evidence:typed:v1\x00"
DEFAULT_MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_AUTHORITY_EVIDENCE_BYTES_V1: Final[int] = DEFAULT_MAX_ARTIFACT_BYTES
MAX_SNAPSHOT_BYTES_HARD_CEILING = 64 * 1024 * 1024
MAX_SNAPSHOT_FILES_HARD_CEILING = 256
DEFAULT_MAX_SNAPSHOT_BYTES = MAX_SNAPSHOT_BYTES_HARD_CEILING
DEFAULT_MAX_SNAPSHOT_FILES = MAX_SNAPSHOT_FILES_HARD_CEILING
VERIFICATION_INPUT_ARTIFACT_TYPE_BY_ROLE_V1: Final = MappingProxyType(
    {
        "effect_oracle": "modeled_effect_oracle_spec",
        "environment": "modeled_environment_spec",
        "evidence": "modeled_supporting_evidence_input",
        "poc": "modeled_poc_input",
    }
)
VERIFICATION_OUTPUT_ARTIFACT_TYPE_BY_ROLE_V1: Final = MappingProxyType(
    {
        "effect_output": "modeled_effect_output",
        "execution_output": "modeled_execution_output",
        "measured_environment_output": "modeled_measured_environment_output",
        "termination_output": "modeled_termination_output",
    }
)
VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1: Final = MappingProxyType(
    {
        **VERIFICATION_INPUT_ARTIFACT_TYPE_BY_ROLE_V1,
        **VERIFICATION_OUTPUT_ARTIFACT_TYPE_BY_ROLE_V1,
    }
)
VERIFICATION_ARTIFACT_TYPES_V1: Final = frozenset(VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1.values())
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


def _exclusive_rename_function() -> tuple[object, int] | None:
    """Return the native dirfd-relative no-clobber rename and platform flag."""

    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        function = getattr(libc, "renameatx_np", None)
        flag = 0x00000004  # RENAME_EXCL from Darwin sys/stdio.h.
    elif sys.platform.startswith("linux"):
        function = getattr(libc, "renameat2", None)
        flag = 0x00000001  # RENAME_NOREPLACE from Linux stdio/renameat2.
    else:
        return None
    if function is None:
        return None
    function.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    function.restype = ctypes.c_int
    return function, flag


_EXCLUSIVE_RENAME = _exclusive_rename_function()


def _rename_noreplace(
    directory_descriptor: int,
    source_name: str,
    target_name: str,
) -> None:
    """Atomically publish one name without overwriting an existing artifact."""

    if _EXCLUSIVE_RENAME is None:
        raise EvidenceError("atomic no-clobber evidence publication is unsupported on this platform")
    function, flag = _EXCLUSIVE_RENAME
    ctypes.set_errno(0)
    result = function(
        directory_descriptor,
        os.fsencode(source_name),
        directory_descriptor,
        os.fsencode(target_name),
        flag,
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise FileExistsError(
            error_number,
            os.strerror(error_number),
            target_name,
        )
    raise EvidenceError("atomic no-clobber evidence publication failed") from OSError(
        error_number, os.strerror(error_number)
    )


def evidence_digest(data: bytes) -> str:
    if not isinstance(data, bytes):
        raise EvidenceError("evidence must be bytes")
    return f"sha256:{hashlib.sha256(_EVIDENCE_DOMAIN + data).hexdigest()}"


def _validate_verification_artifact_type(value: object) -> str:
    if type(value) is not str or value not in VERIFICATION_ARTIFACT_TYPES_V1:
        raise EvidenceError("unknown verification artifact type")
    return value


def typed_evidence_digest(data: bytes, *, artifact_type: str) -> str:
    """Return a type-domain-separated digest for one modeled verification artifact."""

    if type(data) is not bytes:
        raise EvidenceError("typed evidence must be immutable bytes")
    validated_type = _validate_verification_artifact_type(artifact_type)
    digest = hashlib.sha256(_TYPED_EVIDENCE_DOMAIN + validated_type.encode("ascii") + b"\x00" + data).hexdigest()
    return f"sha256:{digest}"


@dataclass(frozen=True, slots=True)
class ArtifactReceipt:
    digest: str
    size: int

    def __post_init__(self) -> None:
        if type(self.digest) is not str or not _DIGEST_RE.fullmatch(self.digest):
            raise EvidenceError("invalid evidence digest")
        if type(self.size) is not int or self.size < 0:
            raise EvidenceError("artifact size must be nonnegative")


@dataclass(frozen=True, slots=True)
class TypedArtifactReceipt:
    """A retained byte count and identity bound to one closed artifact type."""

    digest: str
    size: int
    artifact_type: str

    def __post_init__(self) -> None:
        if type(self.digest) is not str or not _DIGEST_RE.fullmatch(self.digest):
            raise EvidenceError("invalid typed evidence digest")
        if type(self.size) is not int or self.size <= 0:
            raise EvidenceError("typed artifact size must be positive")
        _validate_verification_artifact_type(self.artifact_type)


class FileEvidenceStore:
    """Private local CAS with exclusive creation, fsync, and rehash-on-read.

    The store is locally durable against ordinary process interruption. It does not defend
    against an operator who controls the filesystem and process identity.
    """

    def __init__(
        self,
        root: str | Path,
        *,
        max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
    ) -> None:
        self.root = Path(root)
        if type(max_artifact_bytes) is not int or max_artifact_bytes <= 0:
            raise EvidenceError("max_artifact_bytes must be positive")
        self.max_artifact_bytes = max_artifact_bytes
        if self.root.is_symlink():
            raise EvidenceError("evidence root may not be a symlink")
        created = False
        try:
            self.root.mkdir(mode=0o700, parents=True, exist_ok=False)
            created = True
        except FileExistsError:
            pass
        descriptor = self._open_root()
        try:
            if created:
                os.fchmod(descriptor, 0o700)
            self._validate_private_directory(
                os.fstat(descriptor),
                "evidence root",
            )
        finally:
            os.close(descriptor)

    def _path_for(self, digest: str) -> Path:
        if type(digest) is not str or not _DIGEST_RE.fullmatch(digest):
            raise EvidenceError("invalid evidence digest")
        hexadecimal = digest.removeprefix("sha256:")
        return self.root / hexadecimal[:2] / hexadecimal[2:]

    @staticmethod
    def _directory_open_flags() -> int:
        return os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)

    @staticmethod
    def _artifact_open_flags() -> int:
        return os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)

    @staticmethod
    def _validate_owner(metadata: os.stat_result, label: str) -> None:
        if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
            raise EvidenceError(f"{label} must be owned by the effective user")

    @classmethod
    def _validate_private_directory(
        cls,
        metadata: os.stat_result,
        label: str,
    ) -> None:
        if not stat.S_ISDIR(metadata.st_mode):
            raise EvidenceError(f"{label} is not a directory")
        cls._validate_owner(metadata, label)
        if stat.S_IMODE(metadata.st_mode) != 0o700:
            raise EvidenceError(f"{label} permissions must be exactly 0700")

    @classmethod
    def _validate_private_artifact(
        cls,
        metadata: os.stat_result,
    ) -> None:
        if not stat.S_ISREG(metadata.st_mode):
            raise EvidenceError("evidence artifact is not a regular file")
        cls._validate_owner(metadata, "evidence artifact")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise EvidenceError("evidence artifact permissions must be exactly 0600")
        if metadata.st_nlink != 1:
            raise EvidenceError("evidence artifact may not be hard-linked")

    def _open_root(self) -> int:
        try:
            return os.open(self.root, self._directory_open_flags())
        except OSError as exc:
            raise EvidenceError("cannot securely open evidence root") from exc

    def _open_shard(
        self,
        root_descriptor: int,
        shard_name: str,
        *,
        create: bool,
    ) -> int:
        created = False
        if create:
            try:
                os.mkdir(
                    shard_name,
                    mode=0o700,
                    dir_fd=root_descriptor,
                )
                created = True
            except FileExistsError:
                pass
            except OSError as exc:
                raise EvidenceError("cannot create evidence shard") from exc
        try:
            descriptor = os.open(
                shard_name,
                self._directory_open_flags(),
                dir_fd=root_descriptor,
            )
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise EvidenceError("cannot securely open evidence shard") from exc
        try:
            if created:
                os.fchmod(descriptor, 0o700)
            self._validate_private_directory(
                os.fstat(descriptor),
                "evidence shard",
            )
            if created:
                os.fsync(root_descriptor)
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    @staticmethod
    def _stable_artifact_metadata(
        metadata: os.stat_result,
    ) -> tuple[int, int, int, int, int, int, int, int]:
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_uid,
            metadata.st_nlink,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )

    @classmethod
    def _read_descriptor_exact(
        cls,
        descriptor: int,
        maximum: int,
    ) -> bytes:
        before = os.fstat(descriptor)
        cls._validate_private_artifact(before)
        if before.st_size > maximum:
            raise EvidenceError("evidence artifact exceeds configured limit")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, maximum + 1 - total),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise EvidenceError("evidence artifact exceeds configured limit")
        after = os.fstat(descriptor)
        cls._validate_private_artifact(after)
        if cls._stable_artifact_metadata(before) != (cls._stable_artifact_metadata(after)):
            raise EvidenceError("evidence artifact changed while being read")
        return b"".join(chunks)

    @classmethod
    def _read_from_shard(
        cls,
        shard_descriptor: int,
        artifact_name: str,
        maximum: int,
    ) -> bytes:
        try:
            descriptor = os.open(
                artifact_name,
                cls._artifact_open_flags(),
                dir_fd=shard_descriptor,
            )
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise EvidenceError("cannot securely open evidence artifact") from exc
        try:
            return cls._read_descriptor_exact(descriptor, maximum)
        finally:
            os.close(descriptor)

    @classmethod
    def _read_existing_for_put(
        cls,
        shard_descriptor: int,
        artifact_name: str,
        maximum: int,
    ) -> bytes:
        """Read an existing target after an atomic no-clobber publication."""

        return cls._read_from_shard(
            shard_descriptor,
            artifact_name,
            maximum,
        )

    def _effective_maximum(self, maximum: int | None) -> int:
        if maximum is None:
            return self.max_artifact_bytes
        if type(maximum) is not int or maximum < 0:
            raise EvidenceError("artifact read maximum must be a nonnegative integer")
        return min(maximum, self.max_artifact_bytes)

    @staticmethod
    def _digest_names(digest: str) -> tuple[str, str]:
        if type(digest) is not str or not _DIGEST_RE.fullmatch(digest):
            raise EvidenceError("invalid evidence digest")
        hexadecimal = digest.removeprefix("sha256:")
        return hexadecimal[:2], hexadecimal[2:]

    def _read_digest(self, digest: str, maximum: int) -> bytes:
        shard_name, artifact_name = self._digest_names(digest)
        root_descriptor = self._open_root()
        try:
            self._validate_private_directory(
                os.fstat(root_descriptor),
                "evidence root",
            )
            shard_descriptor = self._open_shard(
                root_descriptor,
                shard_name,
                create=False,
            )
            try:
                return self._read_from_shard(
                    shard_descriptor,
                    artifact_name,
                    maximum,
                )
            finally:
                os.close(shard_descriptor)
        except FileNotFoundError as exc:
            raise EvidenceError("cannot open evidence artifact: not found") from exc
        finally:
            os.close(root_descriptor)

    @staticmethod
    def _temporary_name() -> str:
        return f".incoming-{secrets.token_hex(16)}"

    def _create_temporary(
        self,
        shard_descriptor: int,
    ) -> tuple[int, str]:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        for _ in range(16):
            temporary_name = self._temporary_name()
            try:
                descriptor = os.open(
                    temporary_name,
                    flags,
                    0o600,
                    dir_fd=shard_descriptor,
                )
            except FileExistsError:
                continue
            except OSError as exc:
                raise EvidenceError("cannot create temporary evidence artifact") from exc
            try:
                os.fchmod(descriptor, 0o600)
            except Exception:
                os.close(descriptor)
                try:
                    os.unlink(temporary_name, dir_fd=shard_descriptor)
                except FileNotFoundError:
                    pass
                raise
            return descriptor, temporary_name
        raise EvidenceError("cannot allocate a unique temporary evidence artifact")

    def _put_exact(
        self,
        data: bytes,
        *,
        digest: str,
        digest_for_data: Callable[[bytes], str],
    ) -> None:
        if len(data) > self.max_artifact_bytes:
            raise EvidenceError("evidence artifact exceeds configured limit")
        shard_name, artifact_name = self._digest_names(digest)
        root_descriptor = self._open_root()
        try:
            self._validate_private_directory(
                os.fstat(root_descriptor),
                "evidence root",
            )
            shard_descriptor = self._open_shard(
                root_descriptor,
                shard_name,
                create=True,
            )
            try:
                try:
                    existing = self._read_existing_for_put(
                        shard_descriptor,
                        artifact_name,
                        self.max_artifact_bytes,
                    )
                except FileNotFoundError:
                    existing = None
                if existing is not None:
                    if digest_for_data(existing) != digest:
                        raise EvidenceError("existing evidence artifact fails digest verification")
                    os.fsync(shard_descriptor)
                    return

                descriptor, temporary_name = self._create_temporary(shard_descriptor)
                temporary_exists = True
                try:
                    view = memoryview(data)
                    written = 0
                    while written < len(view):
                        count = os.write(descriptor, view[written:])
                        if count <= 0:
                            raise EvidenceError("evidence artifact write made no progress")
                        written += count
                    os.fsync(descriptor)
                    os.close(descriptor)
                    descriptor = -1
                    try:
                        _rename_noreplace(
                            shard_descriptor,
                            temporary_name,
                            artifact_name,
                        )
                    except FileExistsError as exc:
                        existing = self._read_existing_for_put(
                            shard_descriptor,
                            artifact_name,
                            self.max_artifact_bytes,
                        )
                        if digest_for_data(existing) != digest:
                            raise EvidenceError("concurrent evidence artifact fails digest verification") from exc
                    else:
                        temporary_exists = False
                    os.fsync(shard_descriptor)
                    persisted = self._read_from_shard(
                        shard_descriptor,
                        artifact_name,
                        self.max_artifact_bytes,
                    )
                    if len(persisted) != len(data) or digest_for_data(persisted) != digest:
                        raise EvidenceError("persisted evidence artifact fails post-write verification")
                finally:
                    if descriptor >= 0:
                        os.close(descriptor)
                    if temporary_exists:
                        try:
                            os.unlink(
                                temporary_name,
                                dir_fd=shard_descriptor,
                            )
                        except FileNotFoundError:
                            pass
            finally:
                os.close(shard_descriptor)
        finally:
            os.close(root_descriptor)

    def put(self, data: bytes) -> ArtifactReceipt:
        if not isinstance(data, bytes):
            raise EvidenceError("evidence must be bytes")
        if len(data) > self.max_artifact_bytes:
            raise EvidenceError("evidence artifact exceeds configured limit")
        digest = evidence_digest(data)
        self._put_exact(
            data,
            digest=digest,
            digest_for_data=evidence_digest,
        )
        return ArtifactReceipt(digest, len(data))

    def put_typed(
        self,
        data: bytes,
        *,
        artifact_type: str,
    ) -> TypedArtifactReceipt:
        if type(data) is not bytes:
            raise EvidenceError("typed evidence must be immutable bytes")
        if not data:
            raise EvidenceError("typed evidence must be nonempty")
        if len(data) > self.max_artifact_bytes:
            raise EvidenceError("evidence artifact exceeds configured limit")
        validated_type = _validate_verification_artifact_type(artifact_type)
        digest = typed_evidence_digest(
            data,
            artifact_type=validated_type,
        )
        self._put_exact(
            data,
            digest=digest,
            digest_for_data=lambda retained: typed_evidence_digest(
                retained,
                artifact_type=validated_type,
            ),
        )
        return TypedArtifactReceipt(
            digest=digest,
            size=len(data),
            artifact_type=validated_type,
        )

    def get(
        self,
        digest: str,
        *,
        maximum: int | None = None,
    ) -> bytes:
        data = self._read_digest(digest, self._effective_maximum(maximum))
        if evidence_digest(data) != digest:
            raise EvidenceError("evidence artifact digest mismatch")
        return data

    def get_typed(
        self,
        digest: str,
        *,
        expected_type: str,
        maximum: int | None = None,
    ) -> bytes:
        validated_type = _validate_verification_artifact_type(expected_type)
        data = self._read_digest(digest, self._effective_maximum(maximum))
        if not data:
            raise EvidenceError("typed evidence must be nonempty")
        if (
            typed_evidence_digest(
                data,
                artifact_type=validated_type,
            )
            != digest
        ):
            raise EvidenceError("evidence artifact digest or type mismatch")
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
        if type(self.artifact_digest) is not str or not _DIGEST_RE.fullmatch(self.artifact_digest):
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
        if type(body) is not dict or set(body) != SEMANTIC_BODY_FIELDS_BY_KIND_V1["target_snapshot"]:
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
    source_bytes: dict[str, bytes] = {}
    for snapshot_file in snapshot.files:
        manifest_entry = _ETZIO_FIXTURE_MANIFEST.get(snapshot_file.relative_path)
        if manifest_entry is None:
            raise EvidenceError("snapshot path is not present in the Etzio fixture manifest")
        expected_size, expected_digest = manifest_entry
        if snapshot_file.size != expected_size or snapshot_file.artifact_digest != expected_digest:
            raise EvidenceError("snapshot metadata does not match the Etzio fixture manifest")
        source_bytes[snapshot_file.relative_path] = evidence_store.get(
            snapshot_file.artifact_digest,
            maximum=expected_size,
        )
    validate_etzio_fixture_snapshot_bytes(snapshot, source_bytes)


def validate_etzio_fixture_snapshot_bytes(
    snapshot: TargetSnapshotV1,
    source_bytes: Mapping[str, bytes],
) -> None:
    """Validate an exact path-to-bytes view against the immutable fixture manifest."""

    if not isinstance(snapshot, TargetSnapshotV1):
        raise EvidenceError("fixture snapshot must be a TargetSnapshotV1")
    if not isinstance(source_bytes, Mapping):
        raise EvidenceError("fixture source bytes must be a path-to-bytes mapping")
    expected_paths = tuple(value.relative_path for value in snapshot.files)
    try:
        supplied_paths = tuple(sorted(source_bytes))
    except TypeError as exc:
        raise EvidenceError("fixture source-byte paths must be text") from exc
    if any(type(value) is not str for value in supplied_paths):
        raise EvidenceError("fixture source-byte paths must be text")
    if supplied_paths != expected_paths:
        raise EvidenceError("fixture source-byte paths differ from the target snapshot")
    for snapshot_file in snapshot.files:
        manifest_entry = _ETZIO_FIXTURE_MANIFEST.get(snapshot_file.relative_path)
        if manifest_entry is None:
            raise EvidenceError("snapshot path is not present in the Etzio fixture manifest")
        expected_size, expected_digest = manifest_entry
        if snapshot_file.size != expected_size or snapshot_file.artifact_digest != expected_digest:
            raise EvidenceError("snapshot metadata does not match the Etzio fixture manifest")
        data = source_bytes[snapshot_file.relative_path]
        if type(data) is not bytes:
            raise EvidenceError("fixture source bytes must be immutable bytes")
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
