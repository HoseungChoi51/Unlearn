"""Immutable regular-payload snapshot for a development runtime projection.

The named development runtime remains mutable by another process with the
same UID.  This module closes that *payload* race without launching anything:
it pins the materialized root, validates its complete descriptor-relative
projection, copies every authenticated regular file into a Linux memfd, and
applies the write/grow/shrink/further-seal locks.

The result is deliberately narrower than a launchable root filesystem.
Directories and symbolic links are immutable records, memfd inode modes are
not protected by the content seals, and no namespace, dynamic-runtime closure,
systemd, Bubblewrap, supervisor, candidate, or scored-evaluation handoff is
performed here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import fcntl
from hashlib import sha256
import os
from pathlib import Path, PurePosixPath
import resource
import stat
import threading
from typing import Final

from . import development_runtime_materializer as _materializer
from . import static_slice as _static
from .development_runtime_bundle import (
    canonical_development_runtime_json_bytes,
)
from .development_runtime_materializer import (
    DevelopmentRuntimeMaterializationError,
    DevelopmentRuntimeMaterializationEvidence,
    DevelopmentRuntimeMaterializedDirectory,
    DevelopmentRuntimeMaterializedEntry,
    validate_development_runtime_materialization_binding,
)


DEVELOPMENT_RUNTIME_FD_SNAPSHOT_SCHEMA_VERSION: Final[str] = "1.0.0"
DEVELOPMENT_RUNTIME_FD_SNAPSHOT_VERSION: Final[str] = "1.0.0"
DEVELOPMENT_RUNTIME_FD_SNAPSHOT_KIND: Final[str] = (
    "cbds-development-runtime-fd-snapshot"
)
DEVELOPMENT_RUNTIME_FD_SNAPSHOT_ALGORITHM: Final[str] = (
    "pinned-projection-sealed-regular-memfd-v1"
)
FD_SNAPSHOT_RESERVE: Final[int] = 32
_HASH_CHUNK_BYTES: Final[int] = 1024 * 1024


class DevelopmentRuntimeFdSnapshotError(ValueError):
    """Raised when an immutable runtime-payload snapshot cannot be proven."""


def _lower_sha256(value: object, *, what: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise DevelopmentRuntimeFdSnapshotError(
            f"{what} must be lowercase SHA-256"
        )
    return value


def _plain_nonnegative_int(value: object, *, what: str) -> int:
    if type(value) is not int or value < 0:
        raise DevelopmentRuntimeFdSnapshotError(
            f"{what} must be a nonnegative plain integer"
        )
    return value


def _seal_masks() -> tuple[int, int]:
    values: dict[str, int] = {}
    for name in (
        "F_SEAL_SEAL",
        "F_SEAL_SHRINK",
        "F_SEAL_GROW",
        "F_SEAL_WRITE",
    ):
        value = getattr(fcntl, name, None)
        if type(value) is not int or value < 0:
            raise DevelopmentRuntimeFdSnapshotError(
                f"required Linux memfd primitive {name} is unavailable"
            )
        values[name] = value
    content = (
        values["F_SEAL_SHRINK"]
        | values["F_SEAL_GROW"]
        | values["F_SEAL_WRITE"]
    )
    return content, content | values["F_SEAL_SEAL"]


def _required_seals() -> tuple[int, int]:
    for name in ("F_ADD_SEALS", "F_GET_SEALS"):
        value = getattr(fcntl, name, None)
        if type(value) is not int or value < 0:
            raise DevelopmentRuntimeFdSnapshotError(
                f"required Linux memfd primitive {name} is unavailable"
            )
    return _seal_masks()


def _memfd_flags() -> int:
    creator = getattr(os, "memfd_create", None)
    cloexec = getattr(os, "MFD_CLOEXEC", None)
    allow_sealing = getattr(os, "MFD_ALLOW_SEALING", None)
    if (
        not callable(creator)
        or type(cloexec) is not int
        or cloexec <= 0
        or type(allow_sealing) is not int
        or allow_sealing <= 0
    ):
        raise DevelopmentRuntimeFdSnapshotError(
            "required Linux memfd_create sealing primitives are unavailable"
        )
    return cloexec | allow_sealing


def _hash_descriptor(descriptor: int, size: int) -> str:
    digest = sha256()
    offset = 0
    while offset < size:
        block = os.pread(
            descriptor,
            min(_HASH_CHUNK_BYTES, size - offset),
            offset,
        )
        if not block:
            raise DevelopmentRuntimeFdSnapshotError(
                "descriptor ended before its authenticated size"
            )
        digest.update(block)
        offset += len(block)
    if os.pread(descriptor, 1, size):
        raise DevelopmentRuntimeFdSnapshotError(
            "descriptor grew beyond its authenticated size"
        )
    return digest.hexdigest()


def _slot_id(destination_path: str, content_sha256: str) -> str:
    digest = sha256(
        b"cbds.development-runtime-fd-slot.v1\0"
        + canonical_development_runtime_json_bytes(
            {
                "destination_path": destination_path,
                "content_sha256": content_sha256,
            }
        )
    ).hexdigest()
    return "slot-" + digest[:24]


@dataclass(frozen=True, slots=True)
class DevelopmentRuntimeFdSlot:
    """Serializable identity for one privately owned sealed memfd."""

    slot_id: str
    destination_path: str
    materialized_mode: int
    size: int
    content_sha256: str
    required_content_seals: int

    def __post_init__(self) -> None:
        if (
            type(self.slot_id) is not str
            or len(self.slot_id) != 29
            or not self.slot_id.startswith("slot-")
            or any(character not in "0123456789abcdef" for character in self.slot_id[5:])
        ):
            raise DevelopmentRuntimeFdSnapshotError("slot_id is invalid")
        try:
            normalized = _materializer._absolute_runtime_path(
                self.destination_path
            )
        except (DevelopmentRuntimeMaterializationError, TypeError, ValueError) as exc:
            raise DevelopmentRuntimeFdSnapshotError(
                "slot destination path is invalid"
            ) from exc
        if normalized != self.destination_path:
            raise DevelopmentRuntimeFdSnapshotError(
                "slot destination path is not canonical"
            )
        if (
            type(self.materialized_mode) is not int
            or self.materialized_mode < 0
            or self.materialized_mode > 0o555
            or self.materialized_mode & ~0o555
        ):
            raise DevelopmentRuntimeFdSnapshotError(
                "slot materialized mode is invalid"
            )
        _plain_nonnegative_int(self.size, what="slot size")
        _lower_sha256(self.content_sha256, what="slot content_sha256")
        _plain_nonnegative_int(
            self.required_content_seals,
            what="slot required_content_seals",
        )
        _unused_content, required = _seal_masks()
        if self.required_content_seals != required:
            raise DevelopmentRuntimeFdSnapshotError(
                "slot carries an unexpected content-seal mask"
            )
        if self.slot_id != _slot_id(
            self.destination_path,
            self.content_sha256,
        ):
            raise DevelopmentRuntimeFdSnapshotError(
                "slot_id does not bind its destination and content"
            )

    def to_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "slot_id": self.slot_id,
            "destination_path": self.destination_path,
            "materialized_mode": self.materialized_mode,
            "size": self.size,
            "content_sha256": self.content_sha256,
            "required_content_seals": self.required_content_seals,
        }


def _snapshot_index_sha256(
    slots: tuple[DevelopmentRuntimeFdSlot, ...],
) -> str:
    return sha256(
        canonical_development_runtime_json_bytes(
            [slot.to_record() for slot in slots]
        )
    ).hexdigest()


def _snapshot_record_unchecked(
    snapshot: "DevelopmentRuntimeFdSnapshot",
    *,
    include_self_digest: bool,
) -> dict[str, object]:
    record: dict[str, object] = {
        "schema_version": snapshot.schema_version,
        "snapshot_version": snapshot.snapshot_version,
        "kind": snapshot.kind,
        "algorithm": snapshot.algorithm,
        "source_manifest_sha256": snapshot.source_manifest_sha256,
        "source_evidence_sha256": snapshot.source_evidence_sha256,
        "source_projection_sha256": snapshot.source_projection_sha256,
        "directories": [item.to_record() for item in snapshot.directories],
        "entries": [item.to_record() for item in snapshot.entries],
        "regular_slots": [item.to_record() for item in snapshot.regular_slots],
        "directory_count": snapshot.directory_count,
        "entry_count": snapshot.entry_count,
        "regular_file_count": snapshot.regular_file_count,
        "symlink_count": snapshot.symlink_count,
        "regular_payload_bytes": snapshot.regular_payload_bytes,
        "snapshot_index_sha256": snapshot.snapshot_index_sha256,
        "source_materialization_binding_verified": (
            snapshot.source_materialization_binding_verified
        ),
        "descriptor_relative_projection_verified": (
            snapshot.descriptor_relative_projection_verified
        ),
        "sealed_regular_payloads_verified": (
            snapshot.sealed_regular_payloads_verified
        ),
        "same_uid_snapshot_payload_mutation_resistant": (
            snapshot.same_uid_snapshot_payload_mutation_resistant
        ),
        "independent_read_descriptor_available": (
            snapshot.independent_read_descriptor_available
        ),
        "symlink_projection_recorded": snapshot.symlink_projection_recorded,
        "memfd_mode_immutable": snapshot.memfd_mode_immutable,
        "same_uid_materialized_tree_mutation_resistant": (
            snapshot.same_uid_materialized_tree_mutation_resistant
        ),
        "runtime_data_and_dlopen_closure_verified": (
            snapshot.runtime_data_and_dlopen_closure_verified
        ),
        "namespace_runtime_closure_verified": (
            snapshot.namespace_runtime_closure_verified
        ),
        "fd_bound_launch_handoff": snapshot.fd_bound_launch_handoff,
        "launch_eligible": snapshot.launch_eligible,
        "candidate_execution_authorized": (
            snapshot.candidate_execution_authorized
        ),
        "scored_evaluation_eligible": snapshot.scored_evaluation_eligible,
        "claim_pipeline_eligible": snapshot.claim_pipeline_eligible,
    }
    if include_self_digest:
        record["snapshot_sha256"] = snapshot.snapshot_sha256
    return record


def _compute_snapshot_sha256(snapshot: "DevelopmentRuntimeFdSnapshot") -> str:
    return sha256(
        canonical_development_runtime_json_bytes(
            _snapshot_record_unchecked(snapshot, include_self_digest=False)
        )
    ).hexdigest()


def _validate_snapshot_metadata(snapshot: "DevelopmentRuntimeFdSnapshot") -> None:
    exact: dict[str, object] = {
        "schema_version": DEVELOPMENT_RUNTIME_FD_SNAPSHOT_SCHEMA_VERSION,
        "snapshot_version": DEVELOPMENT_RUNTIME_FD_SNAPSHOT_VERSION,
        "kind": DEVELOPMENT_RUNTIME_FD_SNAPSHOT_KIND,
        "algorithm": DEVELOPMENT_RUNTIME_FD_SNAPSHOT_ALGORITHM,
        "source_materialization_binding_verified": True,
        "descriptor_relative_projection_verified": True,
        "sealed_regular_payloads_verified": True,
        "same_uid_snapshot_payload_mutation_resistant": True,
        "independent_read_descriptor_available": True,
        "symlink_projection_recorded": True,
        "memfd_mode_immutable": False,
        "same_uid_materialized_tree_mutation_resistant": False,
        "runtime_data_and_dlopen_closure_verified": False,
        "namespace_runtime_closure_verified": False,
        "fd_bound_launch_handoff": False,
        "launch_eligible": False,
        "candidate_execution_authorized": False,
        "scored_evaluation_eligible": False,
        "claim_pipeline_eligible": False,
    }
    for name, expected in exact.items():
        actual = getattr(snapshot, name)
        if type(actual) is not type(expected) or actual != expected:
            raise DevelopmentRuntimeFdSnapshotError(
                f"snapshot field {name!r} is invalid"
            )
    for name in (
        "source_manifest_sha256",
        "source_evidence_sha256",
        "source_projection_sha256",
        "snapshot_index_sha256",
        "snapshot_sha256",
    ):
        _lower_sha256(getattr(snapshot, name), what=name)
    if type(snapshot.directories) is not tuple or any(
        type(item) is not DevelopmentRuntimeMaterializedDirectory
        for item in snapshot.directories
    ):
        raise DevelopmentRuntimeFdSnapshotError(
            "snapshot directories must be an exact tuple"
        )
    if type(snapshot.entries) is not tuple or any(
        type(item) is not DevelopmentRuntimeMaterializedEntry
        for item in snapshot.entries
    ):
        raise DevelopmentRuntimeFdSnapshotError(
            "snapshot entries must be an exact tuple"
        )
    if type(snapshot.regular_slots) is not tuple or any(
        type(item) is not DevelopmentRuntimeFdSlot
        for item in snapshot.regular_slots
    ):
        raise DevelopmentRuntimeFdSnapshotError(
            "snapshot regular_slots must be an exact tuple"
        )
    for item in snapshot.directories:
        item.__post_init__()
    for item in snapshot.entries:
        item.__post_init__()
    for item in snapshot.regular_slots:
        item.__post_init__()
    directory_paths = tuple(item.destination_path for item in snapshot.directories)
    entry_paths = tuple(item.destination_path for item in snapshot.entries)
    slot_paths = tuple(item.destination_path for item in snapshot.regular_slots)
    regular_entries = tuple(
        item for item in snapshot.entries if item.kind == "regular"
    )
    if directory_paths != tuple(sorted(set(directory_paths), key=str.encode)):
        raise DevelopmentRuntimeFdSnapshotError(
            "snapshot directory paths are not uniquely sorted"
        )
    if entry_paths != tuple(sorted(set(entry_paths), key=str.encode)):
        raise DevelopmentRuntimeFdSnapshotError(
            "snapshot entry paths are not uniquely sorted"
        )
    if slot_paths != tuple(item.destination_path for item in regular_entries):
        raise DevelopmentRuntimeFdSnapshotError(
            "snapshot slots do not match regular-entry order"
        )
    if len({item.slot_id for item in snapshot.regular_slots}) != len(
        snapshot.regular_slots
    ):
        raise DevelopmentRuntimeFdSnapshotError("snapshot slot IDs are duplicated")
    for entry, slot in zip(regular_entries, snapshot.regular_slots, strict=True):
        if (
            entry.destination_path != slot.destination_path
            or entry.mode != slot.materialized_mode
            or entry.size != slot.size
            or entry.content_sha256 != slot.content_sha256
        ):
            raise DevelopmentRuntimeFdSnapshotError(
                "snapshot slot metadata differs from its regular entry"
            )
    counts = {
        "directory_count": len(snapshot.directories),
        "entry_count": len(snapshot.entries),
        "regular_file_count": len(regular_entries),
        "symlink_count": sum(item.kind == "symlink" for item in snapshot.entries),
        "regular_payload_bytes": sum(item.size for item in regular_entries),
    }
    for name, expected in counts.items():
        actual = getattr(snapshot, name)
        if type(actual) is not int or actual != expected:
            raise DevelopmentRuntimeFdSnapshotError(
                f"snapshot count {name!r} is invalid"
            )
    if snapshot.regular_file_count < 1:
        raise DevelopmentRuntimeFdSnapshotError(
            "snapshot must contain at least one regular payload"
        )
    expected_projection = _materializer._projection_sha256(
        snapshot.directories,
        snapshot.entries,
    )
    if snapshot.source_projection_sha256 != expected_projection:
        raise DevelopmentRuntimeFdSnapshotError(
            "snapshot source projection digest is invalid"
        )
    if snapshot.snapshot_index_sha256 != _snapshot_index_sha256(
        snapshot.regular_slots
    ):
        raise DevelopmentRuntimeFdSnapshotError(
            "snapshot regular index digest is invalid"
        )
    if snapshot.snapshot_sha256 != _compute_snapshot_sha256(snapshot):
        raise DevelopmentRuntimeFdSnapshotError(
            "snapshot self-digest is invalid"
        )


def _verify_owned_descriptor(
    descriptor: int,
    slot: DevelopmentRuntimeFdSlot,
) -> os.stat_result:
    if type(descriptor) is not int or descriptor < 0:
        raise DevelopmentRuntimeFdSnapshotError(
            "snapshot owns an invalid descriptor"
        )
    metadata = os.fstat(descriptor)
    _content, required = _required_seals()
    seals = fcntl.fcntl(descriptor, getattr(fcntl, "F_GET_SEALS"))
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size != slot.size
        or type(seals) is not int
        or seals != required
        or os.get_inheritable(descriptor)
        or _hash_descriptor(descriptor, slot.size) != slot.content_sha256
    ):
        raise DevelopmentRuntimeFdSnapshotError(
            "owned memfd differs from its authenticated slot"
        )
    return metadata


@dataclass(frozen=True, slots=True)
class DevelopmentRuntimeFdSnapshot:
    """Opaque owner of sealed runtime regular-file payload descriptors."""

    source_manifest_sha256: str
    source_evidence_sha256: str
    source_projection_sha256: str
    directories: tuple[DevelopmentRuntimeMaterializedDirectory, ...]
    entries: tuple[DevelopmentRuntimeMaterializedEntry, ...]
    regular_slots: tuple[DevelopmentRuntimeFdSlot, ...]
    directory_count: int
    entry_count: int
    regular_file_count: int
    symlink_count: int
    regular_payload_bytes: int
    snapshot_index_sha256: str
    snapshot_sha256: str
    schema_version: str = DEVELOPMENT_RUNTIME_FD_SNAPSHOT_SCHEMA_VERSION
    snapshot_version: str = DEVELOPMENT_RUNTIME_FD_SNAPSHOT_VERSION
    kind: str = DEVELOPMENT_RUNTIME_FD_SNAPSHOT_KIND
    algorithm: str = DEVELOPMENT_RUNTIME_FD_SNAPSHOT_ALGORITHM
    source_materialization_binding_verified: bool = True
    descriptor_relative_projection_verified: bool = True
    sealed_regular_payloads_verified: bool = True
    same_uid_snapshot_payload_mutation_resistant: bool = True
    independent_read_descriptor_available: bool = True
    symlink_projection_recorded: bool = True
    memfd_mode_immutable: bool = False
    same_uid_materialized_tree_mutation_resistant: bool = False
    runtime_data_and_dlopen_closure_verified: bool = False
    namespace_runtime_closure_verified: bool = False
    fd_bound_launch_handoff: bool = False
    launch_eligible: bool = False
    candidate_execution_authorized: bool = False
    scored_evaluation_eligible: bool = False
    claim_pipeline_eligible: bool = False
    _owned_descriptors: tuple[int, ...] = field(
        default=(), repr=False, compare=False
    )
    _closed: bool = field(default=False, repr=False, compare=False)
    _lifecycle_lock: object = field(
        default_factory=threading.RLock,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        _validate_snapshot_metadata(self)
        if type(self._closed) is not bool or self._closed:
            raise DevelopmentRuntimeFdSnapshotError(
                "new snapshot must own open descriptors"
            )
        if (
            type(self._owned_descriptors) is not tuple
            or len(self._owned_descriptors) != len(self.regular_slots)
            or any(type(item) is not int for item in self._owned_descriptors)
            or len(set(self._owned_descriptors)) != len(self._owned_descriptors)
        ):
            raise DevelopmentRuntimeFdSnapshotError(
                "snapshot descriptor ownership table is invalid"
            )
        for descriptor, slot in zip(
            self._owned_descriptors,
            self.regular_slots,
            strict=True,
        ):
            _verify_owned_descriptor(descriptor, slot)

    @property
    def closed(self) -> bool:
        lock = self._lifecycle_lock
        if not hasattr(lock, "__enter__"):
            raise DevelopmentRuntimeFdSnapshotError(
                "snapshot lifecycle lock is invalid"
            )
        with lock:  # type: ignore[attr-defined]
            return self._closed

    def to_record(self) -> dict[str, object]:
        """Return descriptor-free evidence; raw FD numbers never serialize."""

        _validate_snapshot_metadata(self)
        return _snapshot_record_unchecked(self, include_self_digest=True)

    def regular_entry(
        self,
        destination_path: str,
    ) -> DevelopmentRuntimeMaterializedEntry:
        """Rebind one regular path to the immutable descriptor-free inventory."""

        if type(destination_path) is not str:
            raise DevelopmentRuntimeFdSnapshotError(
                "destination_path must be an exact string"
            )
        for entry in self.entries:
            if entry.destination_path == destination_path:
                if entry.kind != "regular":
                    break
                entry.__post_init__()
                return entry
        raise KeyError(destination_path)

    def duplicate_regular_fd(self, destination_path: str) -> int:
        """Return a caller-owned, independent-offset read-only descriptor.

        ``dup`` is intentionally insufficient because it shares one open-file
        description and therefore one offset.  Reopening the sealed memfd via
        procfs yields a distinct read cursor.  The reopened descriptor is
        fully rebound to the authenticated slot before it is returned.
        """

        if type(destination_path) is not str:
            raise DevelopmentRuntimeFdSnapshotError(
                "destination_path must be an exact string"
            )
        lock = self._lifecycle_lock
        if not hasattr(lock, "__enter__"):
            raise DevelopmentRuntimeFdSnapshotError(
                "snapshot lifecycle lock is invalid"
            )
        with lock:  # type: ignore[attr-defined]
            if self._closed:
                raise DevelopmentRuntimeFdSnapshotError(
                    "snapshot is already closed"
                )
            try:
                index = tuple(
                    item.destination_path for item in self.regular_slots
                ).index(destination_path)
            except ValueError as exc:
                raise DevelopmentRuntimeFdSnapshotError(
                    "destination_path is not a regular snapshot entry"
                ) from exc
            base_descriptor = self._owned_descriptors[index]
            base_metadata = _verify_owned_descriptor(
                base_descriptor,
                self.regular_slots[index],
            )
            cloexec = getattr(os, "O_CLOEXEC", None)
            if type(cloexec) is not int or cloexec <= 0:
                raise DevelopmentRuntimeFdSnapshotError(
                    "O_CLOEXEC is unavailable"
                )
            reopened: int | None = None
            try:
                reopened = os.open(
                    f"/proc/self/fd/{base_descriptor}",
                    os.O_RDONLY | cloexec,
                )
                reopened_metadata = _verify_owned_descriptor(
                    reopened,
                    self.regular_slots[index],
                )
                access_mode = fcntl.fcntl(reopened, fcntl.F_GETFL) & os.O_ACCMODE
                if (
                    reopened_metadata.st_dev != base_metadata.st_dev
                    or reopened_metadata.st_ino != base_metadata.st_ino
                    or access_mode != os.O_RDONLY
                    or os.lseek(reopened, 0, os.SEEK_CUR) != 0
                ):
                    raise DevelopmentRuntimeFdSnapshotError(
                        "independent read descriptor differs from its sealed memfd"
                    )
                result = reopened
                reopened = None
                return result
            except DevelopmentRuntimeFdSnapshotError:
                raise
            except (OSError, TypeError, ValueError) as exc:
                raise DevelopmentRuntimeFdSnapshotError(
                    "cannot create an independent sealed-payload descriptor"
                ) from exc
            finally:
                if reopened is not None:
                    os.close(reopened)

    def close(self) -> None:
        """Release every owned descriptor exactly once; repeated close is safe."""

        lock = self._lifecycle_lock
        if not hasattr(lock, "__enter__"):
            return
        with lock:  # type: ignore[attr-defined]
            if self._closed:
                return
            owned = self._owned_descriptors
            # Relinquish ownership before close so a repeated cleanup cannot
            # close a newly reused integer descriptor.
            object.__setattr__(self, "_owned_descriptors", ())
            object.__setattr__(self, "_closed", True)
        for descriptor in owned:
            try:
                os.close(descriptor)
            except OSError:
                pass

    def __enter__(self) -> "DevelopmentRuntimeFdSnapshot":
        if self.closed:
            raise DevelopmentRuntimeFdSnapshotError(
                "snapshot is already closed"
            )
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()

    def __copy__(self) -> "DevelopmentRuntimeFdSnapshot":
        raise DevelopmentRuntimeFdSnapshotError(
            "snapshot descriptor ownership cannot be copied"
        )

    def __deepcopy__(self, _memo: object) -> "DevelopmentRuntimeFdSnapshot":
        raise DevelopmentRuntimeFdSnapshotError(
            "snapshot descriptor ownership cannot be copied"
        )

    def __del__(self) -> None:  # pragma: no cover - best-effort finalizer
        try:
            self.close()
        except BaseException:
            pass


def _preflight_descriptor_budget(regular_count: int) -> None:
    if type(regular_count) is not int or regular_count < 1:
        raise DevelopmentRuntimeFdSnapshotError(
            "runtime snapshot requires at least one regular entry"
        )
    _memfd_flags()
    _required_seals()
    try:
        soft_limit, _hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
        with os.scandir("/proc/self/fd") as iterator:
            current_count = sum(1 for _item in iterator)
    except (OSError, ValueError) as exc:
        raise DevelopmentRuntimeFdSnapshotError(
            "cannot establish the descriptor budget"
        ) from exc
    if soft_limit != resource.RLIM_INFINITY and (
        type(soft_limit) is not int
        or current_count + regular_count + FD_SNAPSHOT_RESERVE > soft_limit
    ):
        raise DevelopmentRuntimeFdSnapshotError(
            "runtime snapshot would exceed the descriptor budget"
        )


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise DevelopmentRuntimeFdSnapshotError(
                "memfd write made no progress"
            )
        offset += written


def _capture_regular_memfd(
    root_descriptor: int,
    entry: DevelopmentRuntimeMaterializedEntry,
) -> int:
    if entry.kind != "regular" or entry.content_sha256 is None:
        raise DevelopmentRuntimeFdSnapshotError(
            "only regular entries can be captured into memfds"
        )
    relative = PurePosixPath(entry.destination_path.lstrip("/"))
    parent_descriptor: int | None = None
    source_descriptor: int | None = None
    memfd_descriptor: int | None = None
    try:
        parent_descriptor = _static._open_relative_directory(
            root_descriptor,
            relative.parent,
        )
        _static._assert_relative_directory_reachable(
            root_descriptor,
            parent_descriptor,
            relative.parent,
        )
        source_descriptor = os.open(
            relative.name,
            _static._regular_open_flags(),
            dir_fd=parent_descriptor,
        )
        before = os.fstat(source_descriptor)
        named_before = os.stat(
            relative.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        identity = _materializer._source_metadata_identity(before)
        if (
            not stat.S_ISREG(before.st_mode)
            or identity != _materializer._source_metadata_identity(named_before)
            or stat.S_IMODE(before.st_mode) != entry.mode
            or before.st_nlink != entry.link_count
            or before.st_size != entry.size
        ):
            raise DevelopmentRuntimeFdSnapshotError(
                "materialized regular changed before memfd capture"
            )
        memfd_descriptor = os.memfd_create(
            "cbds-" + _slot_id(entry.destination_path, entry.content_sha256),
            _memfd_flags(),
        )
        if os.get_inheritable(memfd_descriptor):
            raise DevelopmentRuntimeFdSnapshotError(
                "new memfd is unexpectedly inheritable"
            )
        digest = sha256()
        offset = 0
        while offset < entry.size:
            block = os.pread(
                source_descriptor,
                min(_HASH_CHUNK_BYTES, entry.size - offset),
                offset,
            )
            if not block:
                raise DevelopmentRuntimeFdSnapshotError(
                    "materialized regular ended during memfd capture"
                )
            digest.update(block)
            _write_all(memfd_descriptor, block)
            offset += len(block)
        if os.pread(source_descriptor, 1, entry.size):
            raise DevelopmentRuntimeFdSnapshotError(
                "materialized regular grew during memfd capture"
            )
        after = os.fstat(source_descriptor)
        named_after = os.stat(
            relative.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        _static._assert_relative_directory_reachable(
            root_descriptor,
            parent_descriptor,
            relative.parent,
        )
        if (
            _materializer._source_metadata_identity(after) != identity
            or _materializer._source_metadata_identity(named_after) != identity
            or digest.hexdigest() != entry.content_sha256
        ):
            raise DevelopmentRuntimeFdSnapshotError(
                "materialized regular changed during memfd capture"
            )
        os.fchmod(memfd_descriptor, entry.mode)
        metadata = os.fstat(memfd_descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != entry.mode
            or metadata.st_size != entry.size
            or _hash_descriptor(memfd_descriptor, entry.size)
            != entry.content_sha256
        ):
            raise DevelopmentRuntimeFdSnapshotError(
                "captured memfd differs before sealing"
            )
        content_seals, required_seals = _required_seals()
        add_seals = getattr(fcntl, "F_ADD_SEALS")
        get_seals = getattr(fcntl, "F_GET_SEALS")
        if fcntl.fcntl(memfd_descriptor, get_seals) != 0:
            raise DevelopmentRuntimeFdSnapshotError(
                "new memfd unexpectedly carries seals"
            )
        fcntl.fcntl(memfd_descriptor, add_seals, content_seals)
        if fcntl.fcntl(memfd_descriptor, get_seals) != content_seals:
            raise DevelopmentRuntimeFdSnapshotError(
                "memfd content seals did not apply exactly"
            )
        seal_seal = getattr(fcntl, "F_SEAL_SEAL")
        fcntl.fcntl(memfd_descriptor, add_seals, seal_seal)
        if fcntl.fcntl(memfd_descriptor, get_seals) != required_seals:
            raise DevelopmentRuntimeFdSnapshotError(
                "memfd final seal did not apply exactly"
            )
        result = memfd_descriptor
        memfd_descriptor = None
        return result
    except DevelopmentRuntimeFdSnapshotError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise DevelopmentRuntimeFdSnapshotError(
            f"cannot capture sealed runtime payload: {entry.destination_path}"
        ) from exc
    finally:
        for descriptor in (
            memfd_descriptor,
            source_descriptor,
            parent_descriptor,
        ):
            if descriptor is not None:
                os.close(descriptor)


def _scan_bound_projection(
    root_descriptor: int,
    expected_entries: tuple[object, ...],
    expected_directories: tuple[str, ...],
    evidence: DevelopmentRuntimeMaterializationEvidence,
) -> tuple[object, ...]:
    try:
        observations, directories, entries = _materializer._scan_destination_once(
            root_descriptor,
            expected_entries,  # type: ignore[arg-type]
            expected_directories,
        )
    except (DevelopmentRuntimeMaterializationError, OSError, TypeError, ValueError) as exc:
        raise DevelopmentRuntimeFdSnapshotError(
            "materialized runtime projection failed descriptor-relative scan"
        ) from exc
    if (
        directories != evidence.directories
        or entries != evidence.entries
        or _materializer._scan_sha256(observations)
        not in {evidence.first_scan_sha256, evidence.second_scan_sha256}
    ):
        raise DevelopmentRuntimeFdSnapshotError(
            "pinned runtime projection differs from materialization evidence"
        )
    return observations


def _construct_snapshot(
    evidence: DevelopmentRuntimeMaterializationEvidence,
    descriptors: tuple[int, ...],
) -> DevelopmentRuntimeFdSnapshot:
    regular_entries = tuple(
        item for item in evidence.entries if item.kind == "regular"
    )
    _content, required = _required_seals()
    slots = tuple(
        DevelopmentRuntimeFdSlot(
            slot_id=_slot_id(item.destination_path, item.content_sha256),  # type: ignore[arg-type]
            destination_path=item.destination_path,
            materialized_mode=item.mode,
            size=item.size,
            content_sha256=item.content_sha256,  # type: ignore[arg-type]
            required_content_seals=required,
        )
        for item in regular_entries
    )
    counts = {
        "directory_count": evidence.directory_count,
        "entry_count": evidence.entry_count,
        "regular_file_count": evidence.regular_file_count,
        "symlink_count": evidence.symlink_count,
        "regular_payload_bytes": evidence.regular_payload_bytes,
    }
    fields: dict[str, object] = {
        "source_manifest_sha256": evidence.source_manifest_sha256,
        "source_evidence_sha256": evidence.evidence_sha256,
        "source_projection_sha256": evidence.projection_sha256,
        "directories": evidence.directories,
        "entries": evidence.entries,
        "regular_slots": slots,
        **counts,
        "snapshot_index_sha256": _snapshot_index_sha256(slots),
    }
    record: dict[str, object] = {
        "schema_version": DEVELOPMENT_RUNTIME_FD_SNAPSHOT_SCHEMA_VERSION,
        "snapshot_version": DEVELOPMENT_RUNTIME_FD_SNAPSHOT_VERSION,
        "kind": DEVELOPMENT_RUNTIME_FD_SNAPSHOT_KIND,
        "algorithm": DEVELOPMENT_RUNTIME_FD_SNAPSHOT_ALGORITHM,
        "source_manifest_sha256": evidence.source_manifest_sha256,
        "source_evidence_sha256": evidence.evidence_sha256,
        "source_projection_sha256": evidence.projection_sha256,
        "directories": [item.to_record() for item in evidence.directories],
        "entries": [item.to_record() for item in evidence.entries],
        "regular_slots": [item.to_record() for item in slots],
        **counts,
        "snapshot_index_sha256": fields["snapshot_index_sha256"],
        "source_materialization_binding_verified": True,
        "descriptor_relative_projection_verified": True,
        "sealed_regular_payloads_verified": True,
        "same_uid_snapshot_payload_mutation_resistant": True,
        "independent_read_descriptor_available": True,
        "symlink_projection_recorded": True,
        "memfd_mode_immutable": False,
        "same_uid_materialized_tree_mutation_resistant": False,
        "runtime_data_and_dlopen_closure_verified": False,
        "namespace_runtime_closure_verified": False,
        "fd_bound_launch_handoff": False,
        "launch_eligible": False,
        "candidate_execution_authorized": False,
        "scored_evaluation_eligible": False,
        "claim_pipeline_eligible": False,
    }
    digest = sha256(canonical_development_runtime_json_bytes(record)).hexdigest()
    return DevelopmentRuntimeFdSnapshot(
        snapshot_sha256=digest,
        _owned_descriptors=descriptors,
        **fields,  # type: ignore[arg-type]
    )


def snapshot_development_runtime_for_launch(
    manifest: object,
    evidence: DevelopmentRuntimeMaterializationEvidence,
    *,
    expected_manifest_sha256: str,
) -> DevelopmentRuntimeFdSnapshot:
    """Capture authenticated regular payloads without authorizing a launch."""

    expected_digest = _lower_sha256(
        expected_manifest_sha256,
        what="expected_manifest_sha256",
    )
    if type(evidence) is not DevelopmentRuntimeMaterializationEvidence:
        raise DevelopmentRuntimeFdSnapshotError(
            "evidence must be exact materialization evidence"
        )
    try:
        validate_development_runtime_materialization_binding(
            evidence,
            manifest,
            expected_manifest_sha256=expected_digest,
        )
        shell = _materializer._preflight_runtime_manifest_shell(
            manifest,
            expected_manifest_sha256=expected_digest,
        )
        _materializer._preflight_materializer_manifest_bounds(shell)
        frozen_manifest = _materializer._strict_plain_json_copy(manifest)
        expected_entries, expected_directories = (
            _materializer._expected_projection(frozen_manifest)
        )
    except (
        DevelopmentRuntimeMaterializationError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        raise DevelopmentRuntimeFdSnapshotError(
            "runtime manifest and materialization evidence failed binding"
        ) from exc
    regular_entries = tuple(
        item for item in evidence.entries if item.kind == "regular"
    )
    _preflight_descriptor_budget(len(regular_entries))
    root_descriptor: int | None = None
    captured: list[int] = []
    try:
        root_descriptor, _metadata = _static._open_absolute_directory_no_follow(
            Path(evidence.destination_root)
        )
        _materializer._assert_named_destination(
            Path(evidence.destination_root),
            root_descriptor,
        )
        first = _scan_bound_projection(
            root_descriptor,
            expected_entries,
            expected_directories,
            evidence,
        )
        for entry in regular_entries:
            captured.append(_capture_regular_memfd(root_descriptor, entry))
        second = _scan_bound_projection(
            root_descriptor,
            expected_entries,
            expected_directories,
            evidence,
        )
        _materializer._assert_named_destination(
            Path(evidence.destination_root),
            root_descriptor,
        )
        if first != second:
            raise DevelopmentRuntimeFdSnapshotError(
                "pinned runtime projection changed during memfd capture"
            )
        snapshot = _construct_snapshot(evidence, tuple(captured))
        captured.clear()
        return snapshot
    except DevelopmentRuntimeFdSnapshotError:
        raise
    except (
        DevelopmentRuntimeMaterializationError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        raise DevelopmentRuntimeFdSnapshotError(
            "runtime fd snapshot failed closed"
        ) from exc
    finally:
        if root_descriptor is not None:
            os.close(root_descriptor)
        while captured:
            descriptor = captured.pop()
            try:
                os.close(descriptor)
            except OSError:
                pass


def verify_development_runtime_fd_snapshot_structure(snapshot: object) -> bool:
    """Validate descriptor-free metadata; closed snapshots remain auditable."""

    if type(snapshot) is not DevelopmentRuntimeFdSnapshot:
        return False
    try:
        _validate_snapshot_metadata(snapshot)
    except (
        AttributeError,
        DevelopmentRuntimeFdSnapshotError,
        DevelopmentRuntimeMaterializationError,
        OSError,
        TypeError,
        ValueError,
    ):
        return False
    return True


__all__ = [
    "DEVELOPMENT_RUNTIME_FD_SNAPSHOT_ALGORITHM",
    "DEVELOPMENT_RUNTIME_FD_SNAPSHOT_KIND",
    "DEVELOPMENT_RUNTIME_FD_SNAPSHOT_SCHEMA_VERSION",
    "DEVELOPMENT_RUNTIME_FD_SNAPSHOT_VERSION",
    "DevelopmentRuntimeFdSlot",
    "DevelopmentRuntimeFdSnapshot",
    "DevelopmentRuntimeFdSnapshotError",
    "snapshot_development_runtime_for_launch",
    "verify_development_runtime_fd_snapshot_structure",
]
