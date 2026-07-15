"""Safely materialize, but never launch, a development runtime source manifest.

The source-manifest builder deliberately stops before copying any bytes.  This
module implements the next, still non-executing, boundary: it replays an exact
``DevelopmentRuntimeBundleManifest``, copies its authenticated regular files
and symbolic links into a newly-created root, and returns immutable evidence
of a final named double scan.

Nothing in this module authorizes a candidate process.  In particular, an ELF
link closure is not a complete runtime closure: locale data, dynamically
loaded modules, utility policy, and the execution supervisor remain outside
this boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import os
from pathlib import Path, PurePosixPath
import stat
from typing import Final, Literal, TypeAlias

from . import static_slice as _static
from .development_runtime_bundle import (
    DEFAULT_MAXIMUM_FILE_BYTES,
    DEFAULT_MAXIMUM_TOTAL_REGULAR_PAYLOAD_BYTES,
    DEVELOPMENT_RUNTIME_BUNDLE_KIND,
    DEVELOPMENT_RUNTIME_BUNDLE_SCHEMA_VERSION,
    DEVELOPMENT_RUNTIME_BUNDLE_VERSION,
    MAXIMUM_ALLOWED_SOURCE_ROOTS,
    MAXIMUM_LIBRARY_LOOKUP_CANDIDATES,
    MAXIMUM_LIBRARY_SEARCH_DIRECTORIES,
    MAXIMUM_MANIFEST_ENTRIES,
    DevelopmentRuntimeBundleError,
    canonical_development_runtime_json_bytes,
    validate_development_runtime_bundle_manifest,
)


DEVELOPMENT_RUNTIME_MATERIALIZATION_SCHEMA_VERSION: Final[str] = "1.0.0"
DEVELOPMENT_RUNTIME_MATERIALIZER_VERSION: Final[str] = "1.0.0"
DEVELOPMENT_RUNTIME_MATERIALIZATION_KIND: Final[str] = (
    "cbds-development-runtime-materialization-evidence"
)
DEVELOPMENT_RUNTIME_MATERIALIZATION_ALGORITHM: Final[str] = (
    "descriptor-relative-nofollow-source-replay-double-scan-v1"
)
MATERIALIZED_DIRECTORY_MODE: Final[int] = 0o555
MAXIMUM_MATERIALIZED_DIRECTORIES: Final[int] = 16_384
MAXIMUM_MATERIALIZED_DEPTH: Final[int] = 64
MAXIMUM_MATERIALIZED_PATH_BYTES: Final[int] = 4096
MAXIMUM_MATERIALIZED_COMPONENT_BYTES: Final[int] = 255
MAXIMUM_SYMLINK_TARGET_BYTES: Final[int] = 4096
MAXIMUM_STRICT_JSON_NODES: Final[int] = 1_000_000
MAXIMUM_STRICT_JSON_DEPTH: Final[int] = 16
MAXIMUM_STRICT_JSON_STRING_BYTES: Final[int] = 64 * 1024

_RUNTIME_MANIFEST_TOP_LEVEL_KEYS: Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "builder_version",
        "kind",
        "allowed_source_roots",
        "library_search_directories",
        "maximum_file_bytes",
        "maximum_total_regular_payload_bytes",
        "maximum_manifest_entries",
        "explicit_executables",
        "entries",
        "closure",
        "library_resolution",
        "runtime_bundle_materialized",
        "launch_eligible",
        "candidate_execution_authorized",
        "claim_pipeline_eligible",
        "scored_evaluation_eligible",
        "manifest_sha256",
    }
)
_RUNTIME_CLOSURE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "algorithm",
        "elf_pt_interp_dt_needed_verified",
        "runtime_data_and_dlopen_closure_verified",
        "entry_count",
        "regular_file_count",
        "symlink_count",
        "regular_payload_bytes",
    }
)
_RUNTIME_LIBRARY_RESOLUTION_KEYS: Final[frozenset[str]] = frozenset(
    {
        "algorithm",
        "search_precedence_and_negative_lookups_verified",
        "resolution_count",
        "negative_lookup_count",
        "lookup_candidate_count",
        "resolutions",
    }
)
_RUNTIME_EXPLICIT_KEYS: Final[frozenset[str]] = frozenset(
    {"name", "source_path", "resolved_path", "expected_sha256"}
)
_RUNTIME_ENTRY_COMMON_KEYS: Final[frozenset[str]] = frozenset(
    {
        "source_path",
        "destination_path",
        "kind",
        "mode",
        "uid",
        "gid",
        "size",
        "roles",
    }
)
_RUNTIME_ELF_KEYS: Final[frozenset[str]] = frozenset(
    {
        "class_bits",
        "byte_order",
        "machine",
        "object_type",
        "pt_interp",
        "dt_needed",
    }
)
_RUNTIME_RESOLUTION_KEYS: Final[frozenset[str]] = frozenset(
    {
        "requester_path",
        "needed_index",
        "needed_name",
        "searches",
        "selected_source_path",
        "selected_resolved_path",
    }
)
_RUNTIME_SEARCH_KEYS: Final[frozenset[str]] = frozenset(
    {"search_directory_index", "directory", "candidate_path", "outcome"}
)

_EntryKind: TypeAlias = Literal["regular", "symlink"]


class DevelopmentRuntimeMaterializationError(ValueError):
    """Raised when materialization cannot establish every safety boundary."""


def _is_plain_int(value: object) -> bool:
    return type(value) is int


def _sha256_text(value: object, *, what: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise DevelopmentRuntimeMaterializationError(
            f"{what} must be lowercase SHA-256"
        )
    return value


def _absolute_runtime_path(value: object, *, allow_root: bool = False) -> str:
    if type(value) is not str:
        raise DevelopmentRuntimeMaterializationError(
            "materialized path must be a string"
        )
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise DevelopmentRuntimeMaterializationError(
            "materialized path is not strict UTF-8 text"
        ) from exc
    path = PurePosixPath(value)
    if (
        not value
        or not value.startswith("/")
        or value.startswith("//")
        or any(character in value for character in ("\x00", "\r", "\n"))
        or str(path) != value
        or "." in path.parts
        or ".." in path.parts
        or (value == "/" and not allow_root)
    ):
        raise DevelopmentRuntimeMaterializationError(
            "materialized path must be normalized and absolute"
        )
    if len(encoded) > MAXIMUM_MATERIALIZED_PATH_BYTES:
        raise DevelopmentRuntimeMaterializationError(
            "materialized path exceeds its byte limit"
        )
    for component in path.parts[1:]:
        if len(component.encode("utf-8")) > MAXIMUM_MATERIALIZED_COMPONENT_BYTES:
            raise DevelopmentRuntimeMaterializationError(
                "materialized path component exceeds its byte limit"
            )
    if len(path.parts) - 1 > MAXIMUM_MATERIALIZED_DEPTH:
        raise DevelopmentRuntimeMaterializationError(
            "materialized path exceeds its depth limit"
        )
    return value


@dataclass(frozen=True, slots=True)
class DevelopmentRuntimeMaterializedDirectory:
    """One observed real directory in the materialized projection."""

    destination_path: str
    mode: int
    link_count: int

    def __post_init__(self) -> None:
        _absolute_runtime_path(self.destination_path, allow_root=True)
        if not _is_plain_int(self.mode) or self.mode != MATERIALIZED_DIRECTORY_MODE:
            raise DevelopmentRuntimeMaterializationError(
                "materialized directories must have mode 0555"
            )
        if not _is_plain_int(self.link_count) or self.link_count < 1:
            raise DevelopmentRuntimeMaterializationError(
                "materialized directory link_count is invalid"
            )

    def to_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "destination_path": self.destination_path,
            "kind": "directory",
            "mode": self.mode,
            "link_count": self.link_count,
        }


@dataclass(frozen=True, slots=True)
class DevelopmentRuntimeMaterializedEntry:
    """One content-bound regular file or no-follow symbolic link."""

    destination_path: str
    kind: _EntryKind
    mode: int
    size: int
    link_count: int
    content_sha256: str | None
    symlink_target: str | None

    def __post_init__(self) -> None:
        _absolute_runtime_path(self.destination_path)
        if type(self.kind) is not str or self.kind not in {"regular", "symlink"}:
            raise DevelopmentRuntimeMaterializationError(
                "materialized entry kind is invalid"
            )
        if (
            not _is_plain_int(self.mode)
            or self.mode < 0
            or self.mode > 0o7777
            or not _is_plain_int(self.size)
            or self.size < 0
            or not _is_plain_int(self.link_count)
            or self.link_count != 1
        ):
            raise DevelopmentRuntimeMaterializationError(
                "materialized entry metadata is invalid"
            )
        if self.kind == "regular":
            _sha256_text(self.content_sha256, what="regular content_sha256")
            if self.mode & ~0o555:
                raise DevelopmentRuntimeMaterializationError(
                    "materialized regular files must carry no write or privilege bits"
                )
            if self.symlink_target is not None:
                raise DevelopmentRuntimeMaterializationError(
                    "regular materialized entry carries a symlink target"
                )
        else:
            if self.content_sha256 is not None:
                raise DevelopmentRuntimeMaterializationError(
                    "symbolic materialized entry carries a content digest"
                )
            _validate_symlink_target(
                self.destination_path,
                self.symlink_target,
            )

    def to_record(self) -> dict[str, object]:
        self.__post_init__()
        record: dict[str, object] = {
            "destination_path": self.destination_path,
            "kind": self.kind,
            "mode": self.mode,
            "size": self.size,
            "link_count": self.link_count,
        }
        if self.kind == "regular":
            record["content_sha256"] = self.content_sha256
        else:
            record["symlink_target"] = self.symlink_target
        return record


def _projection_record(
    directories: tuple[DevelopmentRuntimeMaterializedDirectory, ...],
    entries: tuple[DevelopmentRuntimeMaterializedEntry, ...],
) -> dict[str, object]:
    return {
        "directories": [item.to_record() for item in directories],
        "entries": [item.to_record() for item in entries],
    }


def _projection_sha256(
    directories: tuple[DevelopmentRuntimeMaterializedDirectory, ...],
    entries: tuple[DevelopmentRuntimeMaterializedEntry, ...],
) -> str:
    return sha256(
        canonical_development_runtime_json_bytes(
            _projection_record(directories, entries)
        )
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class DevelopmentRuntimeMaterializationEvidence:
    """Immutable, non-authorizing evidence of one materialization boundary."""

    source_manifest_sha256: str
    destination_root: str
    directories: tuple[DevelopmentRuntimeMaterializedDirectory, ...]
    entries: tuple[DevelopmentRuntimeMaterializedEntry, ...]
    directory_count: int
    entry_count: int
    regular_file_count: int
    symlink_count: int
    regular_payload_bytes: int
    projection_sha256: str
    first_scan_sha256: str
    second_scan_sha256: str
    evidence_sha256: str
    schema_version: str = DEVELOPMENT_RUNTIME_MATERIALIZATION_SCHEMA_VERSION
    materializer_version: str = DEVELOPMENT_RUNTIME_MATERIALIZER_VERSION
    kind: str = DEVELOPMENT_RUNTIME_MATERIALIZATION_KIND
    algorithm: str = DEVELOPMENT_RUNTIME_MATERIALIZATION_ALGORITHM
    source_replay_verified_before_materialization: bool = True
    source_replay_verified_after_materialization: bool = True
    final_named_destination_verified: bool = True
    final_double_scan_verified: bool = True
    runtime_bundle_materialized: bool = True
    same_uid_mutation_resistant: bool = False
    fd_bound_launch_handoff: bool = False
    launch_eligible: bool = False
    candidate_execution_authorized: bool = False
    claim_pipeline_eligible: bool = False
    scored_evaluation_eligible: bool = False

    def __post_init__(self) -> None:
        exact = {
            "schema_version": DEVELOPMENT_RUNTIME_MATERIALIZATION_SCHEMA_VERSION,
            "materializer_version": DEVELOPMENT_RUNTIME_MATERIALIZER_VERSION,
            "kind": DEVELOPMENT_RUNTIME_MATERIALIZATION_KIND,
            "algorithm": DEVELOPMENT_RUNTIME_MATERIALIZATION_ALGORITHM,
            "source_replay_verified_before_materialization": True,
            "source_replay_verified_after_materialization": True,
            "final_named_destination_verified": True,
            "final_double_scan_verified": True,
            "runtime_bundle_materialized": True,
            "same_uid_mutation_resistant": False,
            "fd_bound_launch_handoff": False,
            "launch_eligible": False,
            "candidate_execution_authorized": False,
            "claim_pipeline_eligible": False,
            "scored_evaluation_eligible": False,
        }
        for field, expected in exact.items():
            actual = getattr(self, field)
            if type(actual) is not type(expected) or actual != expected:
                raise DevelopmentRuntimeMaterializationError(
                    f"materialization evidence field {field!r} is invalid"
                )
        _sha256_text(self.source_manifest_sha256, what="source_manifest_sha256")
        _absolute_destination_root(self.destination_root)
        if type(self.directories) is not tuple or any(
            type(item) is not DevelopmentRuntimeMaterializedDirectory
            for item in self.directories
        ):
            raise DevelopmentRuntimeMaterializationError(
                "materialization evidence directories must be an exact tuple"
            )
        if type(self.entries) is not tuple or any(
            type(item) is not DevelopmentRuntimeMaterializedEntry
            for item in self.entries
        ):
            raise DevelopmentRuntimeMaterializationError(
                "materialization evidence entries must be an exact tuple"
            )
        for item in self.directories:
            item.__post_init__()
        for item in self.entries:
            item.__post_init__()
        directory_paths = tuple(item.destination_path for item in self.directories)
        entry_paths = tuple(item.destination_path for item in self.entries)
        if directory_paths != tuple(sorted(set(directory_paths), key=str.encode)):
            raise DevelopmentRuntimeMaterializationError(
                "materialization evidence directories are not uniquely sorted"
            )
        if entry_paths != tuple(sorted(set(entry_paths), key=str.encode)):
            raise DevelopmentRuntimeMaterializationError(
                "materialization evidence entries are not uniquely sorted"
            )
        if set(directory_paths) & set(entry_paths):
            raise DevelopmentRuntimeMaterializationError(
                "materialization evidence paths conflict"
            )
        if not self.directories or self.directories[0].destination_path != "/":
            raise DevelopmentRuntimeMaterializationError(
                "materialization evidence must contain the root directory"
            )
        if not self.entries:
            raise DevelopmentRuntimeMaterializationError(
                "materialization evidence must contain at least one runtime entry"
            )
        if (
            len(self.directories) > MAXIMUM_MATERIALIZED_DIRECTORIES
            or len(self.entries) > MAXIMUM_MANIFEST_ENTRIES
        ):
            raise DevelopmentRuntimeMaterializationError(
                "materialization evidence exceeds entry bounds"
            )
        directory_set = set(directory_paths)
        leaf_set = set(entry_paths)
        for path in (*directory_paths[1:], *entry_paths):
            parent = str(PurePosixPath(path).parent)
            if parent not in directory_set:
                raise DevelopmentRuntimeMaterializationError(
                    "materialization evidence omits a parent directory"
                )
            if any(
                str(ancestor) in leaf_set
                for ancestor in tuple(PurePosixPath(path).parents)[:-1]
            ):
                raise DevelopmentRuntimeMaterializationError(
                    "materialization evidence places a path below a leaf"
                )
        used_directories = {"/"}
        for path in entry_paths:
            used_directories.update(
                str(parent) for parent in PurePosixPath(path).parents
            )
        if directory_set != used_directories:
            raise DevelopmentRuntimeMaterializationError(
                "materialization evidence contains an unused directory"
            )
        counts = {
            "directory_count": len(self.directories),
            "entry_count": len(self.entries),
            "regular_file_count": sum(
                item.kind == "regular" for item in self.entries
            ),
            "symlink_count": sum(item.kind == "symlink" for item in self.entries),
            "regular_payload_bytes": sum(
                item.size for item in self.entries if item.kind == "regular"
            ),
        }
        for field, expected in counts.items():
            if not _is_plain_int(getattr(self, field)) or getattr(self, field) != expected:
                raise DevelopmentRuntimeMaterializationError(
                    f"materialization evidence count {field!r} is invalid"
                )
        if self.regular_payload_bytes > DEFAULT_MAXIMUM_TOTAL_REGULAR_PAYLOAD_BYTES:
            raise DevelopmentRuntimeMaterializationError(
                "materialization evidence exceeds its payload bound"
            )
        expected_projection = _projection_sha256(self.directories, self.entries)
        if self.projection_sha256 != expected_projection:
            raise DevelopmentRuntimeMaterializationError(
                "materialization projection digest is invalid"
            )
        _sha256_text(self.first_scan_sha256, what="first_scan_sha256")
        _sha256_text(self.second_scan_sha256, what="second_scan_sha256")
        if self.first_scan_sha256 != self.second_scan_sha256:
            raise DevelopmentRuntimeMaterializationError(
                "final materialization scans do not agree"
            )
        _sha256_text(self.evidence_sha256, what="evidence_sha256")
        if self.evidence_sha256 != _compute_evidence_sha256(self):
            raise DevelopmentRuntimeMaterializationError(
                "materialization evidence self-digest is invalid"
            )

    def to_record(self, *, include_self_digest: bool = True) -> dict[str, object]:
        self.__post_init__()
        return _evidence_record_unchecked(
            self, include_self_digest=include_self_digest
        )


def _evidence_record_unchecked(
    evidence: DevelopmentRuntimeMaterializationEvidence,
    *,
    include_self_digest: bool,
) -> dict[str, object]:
    record: dict[str, object] = {
            "schema_version": evidence.schema_version,
            "materializer_version": evidence.materializer_version,
            "kind": evidence.kind,
            "algorithm": evidence.algorithm,
            "source_manifest_sha256": evidence.source_manifest_sha256,
            "destination_root": evidence.destination_root,
            **_projection_record(evidence.directories, evidence.entries),
            "directory_count": evidence.directory_count,
            "entry_count": evidence.entry_count,
            "regular_file_count": evidence.regular_file_count,
            "symlink_count": evidence.symlink_count,
            "regular_payload_bytes": evidence.regular_payload_bytes,
            "projection_sha256": evidence.projection_sha256,
            "first_scan_sha256": evidence.first_scan_sha256,
            "second_scan_sha256": evidence.second_scan_sha256,
            "source_replay_verified_before_materialization": (
                evidence.source_replay_verified_before_materialization
            ),
            "source_replay_verified_after_materialization": (
                evidence.source_replay_verified_after_materialization
            ),
            "final_named_destination_verified": (
                evidence.final_named_destination_verified
            ),
            "final_double_scan_verified": evidence.final_double_scan_verified,
            "runtime_bundle_materialized": evidence.runtime_bundle_materialized,
            "same_uid_mutation_resistant": evidence.same_uid_mutation_resistant,
            "fd_bound_launch_handoff": evidence.fd_bound_launch_handoff,
            "launch_eligible": evidence.launch_eligible,
            "candidate_execution_authorized": evidence.candidate_execution_authorized,
            "claim_pipeline_eligible": evidence.claim_pipeline_eligible,
            "scored_evaluation_eligible": evidence.scored_evaluation_eligible,
    }
    if include_self_digest:
        record["evidence_sha256"] = evidence.evidence_sha256
    return record


def _compute_evidence_sha256(
    evidence: DevelopmentRuntimeMaterializationEvidence,
) -> str:
    return sha256(
        canonical_development_runtime_json_bytes(
            _evidence_record_unchecked(evidence, include_self_digest=False)
        )
    ).hexdigest()


def verify_development_runtime_materialization_evidence_structure(
    evidence: object,
) -> bool:
    """Validate only the frozen record structure, never the live filesystem."""

    if type(evidence) is not DevelopmentRuntimeMaterializationEvidence:
        return False
    try:
        evidence.__post_init__()
    except (
        AttributeError,
        DevelopmentRuntimeMaterializationError,
        TypeError,
        ValueError,
    ):
        return False
    return True


@dataclass(frozen=True, slots=True)
class _ExpectedEntry:
    source_path: str
    destination_path: str
    kind: _EntryKind
    mode: int
    uid: int
    gid: int
    size: int
    sha256: str | None
    target: str | None


@dataclass(frozen=True, slots=True)
class _ScanObservation:
    path: str
    kind: str
    mode: int
    uid: int
    gid: int
    size: int
    link_count: int
    device: int
    inode: int
    mtime_ns: int
    ctime_ns: int
    content_sha256: str | None = None
    symlink_target: str | None = None

    def to_record(self) -> dict[str, object]:
        return {
            "path": self.path,
            "kind": self.kind,
            "mode": self.mode,
            "uid": self.uid,
            "gid": self.gid,
            "size": self.size,
            "link_count": self.link_count,
            "device": self.device,
            "inode": self.inode,
            "mtime_ns": self.mtime_ns,
            "ctime_ns": self.ctime_ns,
            "content_sha256": self.content_sha256,
            "symlink_target": self.symlink_target,
        }


def _preflight_runtime_manifest_shell(
    value: object,
    *,
    expected_manifest_sha256: str,
) -> dict[str, object]:
    """Reject malformed or unbounded manifest containers before deep cloning."""

    if type(value) is not dict:
        raise DevelopmentRuntimeMaterializationError(
            "runtime manifest must be an exact dictionary"
        )
    if (
        len(value) != len(_RUNTIME_MANIFEST_TOP_LEVEL_KEYS)
        or set(value) != _RUNTIME_MANIFEST_TOP_LEVEL_KEYS
    ):
        raise DevelopmentRuntimeMaterializationError(
            "runtime manifest top-level shell is invalid"
        )
    exact = {
        "schema_version": DEVELOPMENT_RUNTIME_BUNDLE_SCHEMA_VERSION,
        "builder_version": DEVELOPMENT_RUNTIME_BUNDLE_VERSION,
        "kind": DEVELOPMENT_RUNTIME_BUNDLE_KIND,
        "runtime_bundle_materialized": False,
        "launch_eligible": False,
        "candidate_execution_authorized": False,
        "claim_pipeline_eligible": False,
        "scored_evaluation_eligible": False,
    }
    for field, expected in exact.items():
        actual = value.get(field)
        if type(actual) is not type(expected) or actual != expected:
            raise DevelopmentRuntimeMaterializationError(
                f"runtime manifest schema shell field {field!r} is invalid"
            )
    digest = _sha256_text(value.get("manifest_sha256"), what="manifest_sha256")
    if digest != expected_manifest_sha256:
        raise DevelopmentRuntimeMaterializationError(
            "runtime manifest does not match the trusted expected digest"
        )

    bounded_arrays = (
        ("allowed_source_roots", MAXIMUM_ALLOWED_SOURCE_ROOTS, False),
        (
            "library_search_directories",
            MAXIMUM_LIBRARY_SEARCH_DIRECTORIES,
            True,
        ),
        ("explicit_executables", MAXIMUM_MANIFEST_ENTRIES, False),
        ("entries", MAXIMUM_MANIFEST_ENTRIES, False),
    )
    for field, maximum, may_be_empty in bounded_arrays:
        selected = value.get(field)
        if (
            type(selected) is not list
            or (not may_be_empty and not selected)
            or len(selected) > maximum
        ):
            raise DevelopmentRuntimeMaterializationError(
                f"runtime manifest shell array {field!r} is invalid"
            )
    if any(type(item) is not str for item in value["allowed_source_roots"]):
        raise DevelopmentRuntimeMaterializationError(
            "runtime manifest source-root shell is invalid"
        )
    if any(type(item) is not str for item in value["library_search_directories"]):
        raise DevelopmentRuntimeMaterializationError(
            "runtime manifest search-directory shell is invalid"
        )
    for item in value["explicit_executables"]:
        if type(item) is not dict or set(item) != _RUNTIME_EXPLICIT_KEYS:
            raise DevelopmentRuntimeMaterializationError(
                "runtime manifest executable shell is invalid"
            )
    needed_count = 0
    for item in value["entries"]:
        if type(item) is not dict:
            raise DevelopmentRuntimeMaterializationError(
                "runtime manifest entry shell is invalid"
            )
        kind = item.get("kind")
        expected_entry_keys = _RUNTIME_ENTRY_COMMON_KEYS | (
            {"sha256", "elf"} if kind == "regular" else {"target"}
        )
        if kind not in {"regular", "symlink"} or set(item) != expected_entry_keys:
            raise DevelopmentRuntimeMaterializationError(
                "runtime manifest entry shell is invalid"
            )
        if kind == "regular":
            elf = item.get("elf")
            if type(elf) is not dict or set(elf) != _RUNTIME_ELF_KEYS:
                raise DevelopmentRuntimeMaterializationError(
                    "runtime manifest ELF shell is invalid"
                )
            needed = elf.get("dt_needed")
            if (
                type(needed) is not list
                or len(needed) > MAXIMUM_LIBRARY_LOOKUP_CANDIDATES - needed_count
            ):
                raise DevelopmentRuntimeMaterializationError(
                    "runtime manifest DT_NEEDED shell exceeds its aggregate bound"
                )
            needed_count += len(needed)

    closure = value.get("closure")
    resolution = value.get("library_resolution")
    if (
        type(closure) is not dict
        or set(closure) != _RUNTIME_CLOSURE_KEYS
        or type(resolution) is not dict
        or set(resolution) != _RUNTIME_LIBRARY_RESOLUTION_KEYS
    ):
        raise DevelopmentRuntimeMaterializationError(
            "runtime manifest nested schema shell is invalid"
        )
    resolutions = resolution.get("resolutions")
    if (
        type(resolutions) is not list
        or len(resolutions) > MAXIMUM_LIBRARY_LOOKUP_CANDIDATES
    ):
        raise DevelopmentRuntimeMaterializationError(
            "runtime manifest resolution shell exceeds its bound"
        )
    lookup_candidates = 0
    for row in resolutions:
        if (
            type(row) is not dict
            or set(row) != _RUNTIME_RESOLUTION_KEYS
            or type(row.get("searches")) is not list
        ):
            raise DevelopmentRuntimeMaterializationError(
                "runtime manifest resolution shell is invalid"
            )
        searches = row["searches"]
        if len(searches) > MAXIMUM_LIBRARY_SEARCH_DIRECTORIES:
            raise DevelopmentRuntimeMaterializationError(
                "runtime manifest resolution search shell exceeds its bound"
            )
        if len(searches) > MAXIMUM_LIBRARY_LOOKUP_CANDIDATES - lookup_candidates:
            raise DevelopmentRuntimeMaterializationError(
                "runtime manifest lookup shell exceeds its aggregate bound"
            )
        lookup_candidates += len(searches)
        if any(
            type(item) is not dict or set(item) != _RUNTIME_SEARCH_KEYS
            for item in searches
        ):
            raise DevelopmentRuntimeMaterializationError(
                "runtime manifest search-observation shell is invalid"
            )
    return value


def _strict_plain_json_copy(value: object) -> dict[str, object]:
    """Reject active/subclassed containers before trusted validation."""

    nodes = 0

    def copy(item: object, depth: int) -> object:
        nonlocal nodes
        nodes += 1
        if nodes > MAXIMUM_STRICT_JSON_NODES or depth > MAXIMUM_STRICT_JSON_DEPTH:
            raise DevelopmentRuntimeMaterializationError(
                "runtime manifest exceeds strict JSON bounds"
            )
        if type(item) is dict:
            result: dict[str, object] = {}
            for key, nested in item.items():  # type: ignore[union-attr]
                if type(key) is not str:
                    raise DevelopmentRuntimeMaterializationError(
                        "runtime manifest keys must be exact strings"
                    )
                try:
                    key_bytes = key.encode("utf-8", errors="strict")
                except UnicodeEncodeError as exc:
                    raise DevelopmentRuntimeMaterializationError(
                        "runtime manifest key is not strict UTF-8"
                    ) from exc
                if len(key_bytes) > MAXIMUM_STRICT_JSON_STRING_BYTES:
                    raise DevelopmentRuntimeMaterializationError(
                        "runtime manifest key exceeds its byte limit"
                    )
                result[key] = copy(nested, depth + 1)
            return result
        if type(item) is list:
            return [copy(nested, depth + 1) for nested in item]  # type: ignore[union-attr]
        if type(item) is str:
            try:
                item_bytes = item.encode("utf-8", errors="strict")
            except UnicodeEncodeError as exc:
                raise DevelopmentRuntimeMaterializationError(
                    "runtime manifest string is not strict UTF-8"
                ) from exc
            if len(item_bytes) > MAXIMUM_STRICT_JSON_STRING_BYTES:
                raise DevelopmentRuntimeMaterializationError(
                    "runtime manifest string exceeds its byte limit"
                )
            return item
        if type(item) in {int, bool} or item is None:
            return item
        raise DevelopmentRuntimeMaterializationError(
            "runtime manifest must contain only exact JSON values"
        )

    if type(value) is not dict:
        raise DevelopmentRuntimeMaterializationError(
            "runtime manifest must be an exact dictionary"
        )
    copied = copy(value, 0)
    if type(copied) is not dict:  # pragma: no cover - guarded above
        raise DevelopmentRuntimeMaterializationError("runtime manifest is invalid")
    return copied


def _preflight_materializer_manifest_bounds(manifest: dict[str, object]) -> None:
    """Reject oversized declared work before source replay can read payloads."""

    ceilings = (
        (
            "maximum_file_bytes",
            DEFAULT_MAXIMUM_FILE_BYTES,
        ),
        (
            "maximum_total_regular_payload_bytes",
            DEFAULT_MAXIMUM_TOTAL_REGULAR_PAYLOAD_BYTES,
        ),
        ("maximum_manifest_entries", MAXIMUM_MANIFEST_ENTRIES),
    )
    for field, maximum in ceilings:
        value = manifest.get(field)
        if not _is_plain_int(value) or value <= 0 or value > maximum:
            raise DevelopmentRuntimeMaterializationError(
                f"runtime manifest {field} exceeds the materializer hard bound"
            )
    raw_entries = manifest.get("entries")
    if (
        type(raw_entries) is not list
        or len(raw_entries) > MAXIMUM_MANIFEST_ENTRIES
    ):
        raise DevelopmentRuntimeMaterializationError(
            "runtime manifest entries exceed the materializer hard bound"
        )
    regular_total = 0
    for raw in raw_entries:
        if type(raw) is not dict:
            raise DevelopmentRuntimeMaterializationError(
                "runtime manifest entry is not an exact object"
            )
        size = raw.get("size")
        kind = raw.get("kind")
        if not _is_plain_int(size) or size < 0:
            raise DevelopmentRuntimeMaterializationError(
                "runtime manifest entry size is invalid"
            )
        if kind == "regular":
            if size > DEFAULT_MAXIMUM_FILE_BYTES:
                raise DevelopmentRuntimeMaterializationError(
                    "runtime manifest regular entry exceeds the file hard bound"
                )
            if size > DEFAULT_MAXIMUM_TOTAL_REGULAR_PAYLOAD_BYTES - regular_total:
                raise DevelopmentRuntimeMaterializationError(
                    "runtime manifest regular entries exceed the payload hard bound"
                )
            regular_total += size
        elif kind != "symlink":
            raise DevelopmentRuntimeMaterializationError(
                "runtime manifest entry kind is outside the materializer boundary"
            )


def _expected_projection(
    manifest: dict[str, object],
) -> tuple[tuple[_ExpectedEntry, ...], tuple[str, ...]]:
    raw_entries = manifest["entries"]
    if type(raw_entries) is not list:
        raise DevelopmentRuntimeMaterializationError(
            "validated manifest entries changed type"
        )
    if len(raw_entries) > MAXIMUM_MANIFEST_ENTRIES:
        raise DevelopmentRuntimeMaterializationError(
            "runtime materialization exceeds its entry bound"
        )
    entries: list[_ExpectedEntry] = []
    directories: set[str] = {"/"}
    total = 0
    paths: set[str] = set()
    for raw in raw_entries:
        if type(raw) is not dict:
            raise DevelopmentRuntimeMaterializationError(
                "validated runtime entry changed type"
            )
        source = _absolute_runtime_path(raw["source_path"])
        destination = _absolute_runtime_path(raw["destination_path"])
        if source != destination:
            raise DevelopmentRuntimeMaterializationError(
                "runtime source and destination paths differ"
            )
        kind = raw["kind"]
        if type(kind) is not str or kind not in {"regular", "symlink"}:
            raise DevelopmentRuntimeMaterializationError(
                "runtime entry kind is invalid"
            )
        mode = raw["mode"]
        uid = raw["uid"]
        gid = raw["gid"]
        size = raw["size"]
        if any(
            not _is_plain_int(value) or value < 0
            for value in (mode, uid, gid, size)
        ) or mode > 0o7777:
            raise DevelopmentRuntimeMaterializationError(
                "runtime entry metadata is invalid"
            )
        digest: str | None = None
        target: str | None = None
        if kind == "regular":
            digest = _sha256_text(raw["sha256"], what="runtime entry sha256")
            if size > DEFAULT_MAXIMUM_FILE_BYTES:
                raise DevelopmentRuntimeMaterializationError(
                    "regular runtime entry exceeds materializer file bound"
                )
            if size > DEFAULT_MAXIMUM_TOTAL_REGULAR_PAYLOAD_BYTES - total:
                raise DevelopmentRuntimeMaterializationError(
                    "runtime projection exceeds materializer payload bound"
                )
            total += size
        else:
            target = _validate_symlink_target(destination, raw["target"])
        if destination in paths:
            raise DevelopmentRuntimeMaterializationError(
                "runtime destination paths are duplicated"
            )
        paths.add(destination)
        pure = PurePosixPath(destination)
        for index in range(1, len(pure.parts) - 1):
            directories.add("/" + "/".join(pure.parts[1 : index + 1]))
        entries.append(
            _ExpectedEntry(
                source_path=source,
                destination_path=destination,
                kind=kind,  # type: ignore[arg-type]
                mode=mode,
                uid=uid,
                gid=gid,
                size=size,
                sha256=digest,
                target=target,
            )
        )
    if len(directories) > MAXIMUM_MATERIALIZED_DIRECTORIES:
        raise DevelopmentRuntimeMaterializationError(
            "runtime projection exceeds its directory bound"
        )
    if paths & directories:
        raise DevelopmentRuntimeMaterializationError(
            "runtime entry conflicts with a required directory"
        )
    ordered_entries = tuple(
        sorted(entries, key=lambda item: item.destination_path.encode("utf-8"))
    )
    ordered_directories = tuple(sorted(directories, key=str.encode))
    return ordered_entries, ordered_directories


def _validate_symlink_target(destination_path: str, value: object) -> str:
    if (
        type(value) is not str
        or not value
        or any(character in value for character in ("\x00", "\r", "\n"))
    ):
        raise DevelopmentRuntimeMaterializationError(
            "runtime symbolic-link target is invalid"
        )
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise DevelopmentRuntimeMaterializationError(
            "runtime symbolic-link target is not strict UTF-8 text"
        ) from exc
    if len(encoded) > MAXIMUM_SYMLINK_TARGET_BYTES:
        raise DevelopmentRuntimeMaterializationError(
            "runtime symbolic-link target exceeds its byte limit"
        )
    # Treat absolute targets as paths inside the future virtual root.  For a
    # relative target, reject lexical traversal above that virtual root.  The
    # materializer itself never follows either form.
    depth = 0 if value.startswith("/") else len(PurePosixPath(destination_path).parent.parts) - 1
    for part in PurePosixPath(value).parts:
        if part in {"/", "."}:
            continue
        if part == "..":
            if depth == 0:
                raise DevelopmentRuntimeMaterializationError(
                    "runtime symbolic-link target escapes the virtual root"
                )
            depth -= 1
        else:
            depth += 1
    return value


def _absolute_destination_root(value: object) -> str:
    if type(value) is not str:
        raise DevelopmentRuntimeMaterializationError(
            "destination root must be an exact string"
        )
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise DevelopmentRuntimeMaterializationError(
            "destination root is not strict UTF-8 text"
        ) from exc
    path = Path(value)
    if (
        not path.is_absolute()
        or path == Path("/")
        or value.startswith("//")
        or os.path.abspath(value) != value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or len(encoded) > MAXIMUM_MATERIALIZED_PATH_BYTES
        or len(path.parts) - 1 > MAXIMUM_MATERIALIZED_DEPTH
    ):
        raise DevelopmentRuntimeMaterializationError(
            "destination root must be a normalized non-root absolute path"
        )
    for component in path.parts[1:]:
        if len(component.encode("utf-8", errors="strict")) > (
            MAXIMUM_MATERIALIZED_COMPONENT_BYTES
        ):
            raise DevelopmentRuntimeMaterializationError(
                "destination root component exceeds its byte limit"
            )
    return value


def _destination_path(value: str | os.PathLike[str]) -> tuple[Path, str]:
    try:
        raw = os.fspath(value)
        if type(raw) is not str:
            raise TypeError("destination path must decode to str")
        normalized = os.path.abspath(raw)
    except (TypeError, ValueError, OSError) as exc:
        raise DevelopmentRuntimeMaterializationError(
            "destination path is invalid"
        ) from exc
    _absolute_destination_root(normalized)
    return Path(normalized), normalized


def _directory_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory:
        raise DevelopmentRuntimeMaterializationError(
            "descriptor-relative no-follow directories are unavailable"
        )
    return os.O_RDONLY | os.O_CLOEXEC | nofollow | directory


def _open_absolute_directory_allow_root(path: Path) -> tuple[int, os.stat_result]:
    if path == Path("/"):
        descriptor = os.open("/", _directory_flags())
        return descriptor, os.fstat(descriptor)
    return _static._open_absolute_directory_no_follow(path)


def _create_new_destination(path: Path) -> int:
    parent_descriptor: int | None = None
    root_descriptor: int | None = None
    created = False
    try:
        parent_descriptor, _ = _open_absolute_directory_allow_root(path.parent)
        try:
            os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise DevelopmentRuntimeMaterializationError(
                "destination path already exists"
            )
        os.mkdir(path.name, 0o700, dir_fd=parent_descriptor)
        created = True
        root_descriptor = os.open(path.name, _directory_flags(), dir_fd=parent_descriptor)
        named = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        opened = os.fstat(root_descriptor)
        if (
            not stat.S_ISDIR(named.st_mode)
            or not _static._same_inode(named, opened)
            or stat.S_IMODE(opened.st_mode) != 0o700
        ):
            raise DevelopmentRuntimeMaterializationError(
                "new destination changed while being created"
            )
        result = root_descriptor
        root_descriptor = None
        return result
    except DevelopmentRuntimeMaterializationError:
        raise
    except OSError as exc:
        raise DevelopmentRuntimeMaterializationError(
            f"cannot create a new no-follow destination: {type(exc).__name__}"
        ) from exc
    finally:
        if parent_descriptor is not None:
            os.close(parent_descriptor)
        if root_descriptor is not None:
            os.close(root_descriptor)
        if created and root_descriptor is None:
            # No path-based recursive cleanup is attempted.  A failed, empty
            # destination remains unusable because future calls require a new
            # path; this avoids deleting through an adversarial replacement.
            pass


def _assert_named_destination(path: Path, root_descriptor: int) -> None:
    reopened: int | None = None
    try:
        reopened, _ = _static._open_absolute_directory_no_follow(path)
        if not _static._same_inode(os.fstat(reopened), os.fstat(root_descriptor)):
            raise DevelopmentRuntimeMaterializationError(
                "destination is no longer named by its requested path"
            )
    except DevelopmentRuntimeMaterializationError:
        raise
    except OSError as exc:
        raise DevelopmentRuntimeMaterializationError(
            "destination path changed during materialization"
        ) from exc
    finally:
        if reopened is not None:
            os.close(reopened)


def _source_metadata_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _open_source_parent(path: str) -> tuple[int, Path]:
    parent_path = Path(str(PurePosixPath(path).parent))
    descriptor, _ = _open_absolute_directory_allow_root(parent_path)
    return descriptor, parent_path


def _assert_source_parent_named(parent_path: Path, descriptor: int) -> None:
    reopened: int | None = None
    try:
        reopened, _ = _open_absolute_directory_allow_root(parent_path)
        if not _static._same_inode(os.fstat(reopened), os.fstat(descriptor)):
            raise DevelopmentRuntimeMaterializationError(
                "runtime source parent changed during materialization"
            )
    finally:
        if reopened is not None:
            os.close(reopened)


def _observe_source_symlink(expected: _ExpectedEntry) -> str:
    parent, parent_path = _open_source_parent(expected.source_path)
    name = PurePosixPath(expected.source_path).name
    try:
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        target = os.readlink(name, dir_fd=parent)
        after = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (
            not stat.S_ISLNK(before.st_mode)
            or _source_metadata_identity(before) != _source_metadata_identity(after)
            or stat.S_IMODE(before.st_mode) != expected.mode
            or before.st_uid != expected.uid
            or before.st_gid != expected.gid
            or before.st_size != expected.size
            or target != expected.target
        ):
            raise DevelopmentRuntimeMaterializationError(
                f"runtime source symlink changed: {expected.source_path}"
            )
        _assert_source_parent_named(parent_path, parent)
        return target
    except DevelopmentRuntimeMaterializationError:
        raise
    except OSError as exc:
        raise DevelopmentRuntimeMaterializationError(
            f"cannot replay runtime source symlink: {expected.source_path}"
        ) from exc
    finally:
        os.close(parent)


def _stage_name(path: str) -> str:
    return ".cbds-runtime-stage-" + sha256(path.encode("utf-8")).hexdigest()


def _materialized_regular_mode(source_mode: int) -> int:
    """Strip write and privilege bits from a copied runtime regular file."""

    if not _is_plain_int(source_mode) or source_mode < 0 or source_mode > 0o7777:
        raise DevelopmentRuntimeMaterializationError("runtime source mode is invalid")
    return source_mode & 0o555


def _publish_regular_from_source(
    root_descriptor: int,
    expected: _ExpectedEntry,
) -> None:
    relative = PurePosixPath(expected.destination_path.lstrip("/"))
    parent_descriptor: int | None = None
    source_parent: int | None = None
    source_descriptor: int | None = None
    stage_descriptor: int | None = None
    stage_exists = False
    published = False
    stage_metadata: os.stat_result | None = None
    stage_name = _stage_name(expected.destination_path)
    try:
        parent_descriptor = _static._open_relative_directory(
            root_descriptor, relative.parent
        )
        _static._assert_relative_directory_reachable(
            root_descriptor, parent_descriptor, relative.parent
        )
        source_parent, source_parent_path = _open_source_parent(expected.source_path)
        source_name = PurePosixPath(expected.source_path).name
        source_descriptor = os.open(
            source_name,
            _static._regular_open_flags(),
            dir_fd=source_parent,
        )
        source_before = os.fstat(source_descriptor)
        source_named = os.stat(
            source_name, dir_fd=source_parent, follow_symlinks=False
        )
        if (
            not stat.S_ISREG(source_before.st_mode)
            or _source_metadata_identity(source_before)
            != _source_metadata_identity(source_named)
            or stat.S_IMODE(source_before.st_mode) != expected.mode
            or source_before.st_uid != expected.uid
            or source_before.st_gid != expected.gid
            or source_before.st_size != expected.size
        ):
            raise DevelopmentRuntimeMaterializationError(
                f"runtime source regular changed: {expected.source_path}"
            )
        stage_descriptor = os.open(
            stage_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=root_descriptor,
        )
        stage_exists = True
        digest = sha256()
        copied = 0
        while copied < expected.size:
            chunk = os.read(source_descriptor, min(1024 * 1024, expected.size - copied))
            if not chunk:
                raise DevelopmentRuntimeMaterializationError(
                    f"runtime source ended early: {expected.source_path}"
                )
            digest.update(chunk)
            offset = 0
            while offset < len(chunk):
                written = os.write(stage_descriptor, chunk[offset:])
                if written <= 0:
                    raise DevelopmentRuntimeMaterializationError(
                        "runtime destination write made no progress"
                    )
                offset += written
            copied += len(chunk)
        if os.read(source_descriptor, 1):
            raise DevelopmentRuntimeMaterializationError(
                f"runtime source grew while copying: {expected.source_path}"
            )
        if copied != expected.size or digest.hexdigest() != expected.sha256:
            raise DevelopmentRuntimeMaterializationError(
                f"runtime source digest mismatch: {expected.source_path}"
            )
        source_after = os.fstat(source_descriptor)
        source_named_after = os.stat(
            source_name, dir_fd=source_parent, follow_symlinks=False
        )
        if (
            _source_metadata_identity(source_after)
            != _source_metadata_identity(source_before)
            or _source_metadata_identity(source_named_after)
            != _source_metadata_identity(source_before)
        ):
            raise DevelopmentRuntimeMaterializationError(
                f"runtime source changed while copying: {expected.source_path}"
            )
        _assert_source_parent_named(source_parent_path, source_parent)
        materialized_mode = _materialized_regular_mode(expected.mode)
        os.fchmod(stage_descriptor, materialized_mode)
        stage_metadata = os.fstat(stage_descriptor)
        named_stage = os.stat(
            stage_name, dir_fd=root_descriptor, follow_symlinks=False
        )
        if (
            not stat.S_ISREG(stage_metadata.st_mode)
            or not _static._same_inode(stage_metadata, named_stage)
            or stat.S_IMODE(stage_metadata.st_mode) != materialized_mode
            or stage_metadata.st_size != expected.size
        ):
            raise DevelopmentRuntimeMaterializationError(
                "staged runtime regular file changed"
            )
        _static._assert_relative_directory_reachable(
            root_descriptor, parent_descriptor, relative.parent
        )
        os.link(
            stage_name,
            relative.name,
            src_dir_fd=root_descriptor,
            dst_dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        published = True
        named = os.stat(relative.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if not _static._same_inode(stage_metadata, named):
            raise DevelopmentRuntimeMaterializationError(
                "published runtime regular file changed"
            )
        _static._assert_relative_directory_reachable(
            root_descriptor, parent_descriptor, relative.parent
        )
        os.unlink(stage_name, dir_fd=root_descriptor)
        stage_exists = False
        final = os.fstat(stage_descriptor)
        named = os.stat(relative.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            final.st_nlink != 1
            or _source_metadata_identity(final) != _source_metadata_identity(named)
        ):
            raise DevelopmentRuntimeMaterializationError(
                "published runtime regular file is not stable"
            )
    except DevelopmentRuntimeMaterializationError:
        raise
    except OSError as exc:
        raise DevelopmentRuntimeMaterializationError(
            f"cannot copy runtime regular file: {expected.destination_path}"
        ) from exc
    finally:
        if published and stage_metadata is not None and parent_descriptor is not None:
            # Published files are deliberately retained on failure.  Deleting
            # through a potentially raced name is less safe than leaving the
            # entire newly-created destination unusable for a future call.
            pass
        if stage_exists:
            try:
                os.unlink(stage_name, dir_fd=root_descriptor)
            except OSError:
                pass
        for descriptor in (stage_descriptor, source_descriptor, source_parent, parent_descriptor):
            if descriptor is not None:
                os.close(descriptor)


def _publish_symlink(root_descriptor: int, expected: _ExpectedEntry) -> None:
    target = _observe_source_symlink(expected)
    relative = PurePosixPath(expected.destination_path.lstrip("/"))
    try:
        _static._create_relative_symlink(root_descriptor, relative, target)
    except OSError as exc:
        raise DevelopmentRuntimeMaterializationError(
            f"cannot copy runtime symbolic link: {expected.destination_path}"
        ) from exc


def _seal_materialized_directories(
    root_descriptor: int,
    expected_directories: tuple[str, ...],
) -> None:
    """Remove directory write bits only after the full projection is installed."""

    for path in sorted(
        (item for item in expected_directories if item != "/"),
        key=lambda item: (-len(PurePosixPath(item).parts), item.encode("utf-8")),
    ):
        relative = PurePosixPath(path.lstrip("/"))
        descriptor: int | None = None
        try:
            descriptor = _static._open_relative_directory(root_descriptor, relative)
            _static._assert_relative_directory_reachable(
                root_descriptor, descriptor, relative
            )
            os.fchmod(descriptor, MATERIALIZED_DIRECTORY_MODE)
            if stat.S_IMODE(os.fstat(descriptor).st_mode) != MATERIALIZED_DIRECTORY_MODE:
                raise DevelopmentRuntimeMaterializationError(
                    "materialized directory mode did not seal"
                )
        finally:
            if descriptor is not None:
                os.close(descriptor)
    os.fchmod(root_descriptor, MATERIALIZED_DIRECTORY_MODE)


def _observation(
    path: str,
    kind: str,
    metadata: os.stat_result,
    *,
    digest: str | None = None,
    target: str | None = None,
) -> _ScanObservation:
    return _ScanObservation(
        path=path,
        kind=kind,
        mode=stat.S_IMODE(metadata.st_mode),
        uid=metadata.st_uid,
        gid=metadata.st_gid,
        size=metadata.st_size,
        link_count=metadata.st_nlink,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mtime_ns=metadata.st_mtime_ns,
        ctime_ns=metadata.st_ctime_ns,
        content_sha256=digest,
        symlink_target=target,
    )


def _read_destination_regular(
    directory_descriptor: int,
    name: str,
    before: os.stat_result,
    *,
    maximum_bytes: int,
) -> str:
    descriptor: int | None = None
    try:
        descriptor = os.open(name, _static._regular_open_flags(), dir_fd=directory_descriptor)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _source_metadata_identity(opened) != _source_metadata_identity(before)
            or opened.st_size > maximum_bytes
        ):
            raise DevelopmentRuntimeMaterializationError(
                "materialized regular changed before its scan"
            )
        digest = sha256()
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise DevelopmentRuntimeMaterializationError(
                    "materialized regular ended during its scan"
                )
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise DevelopmentRuntimeMaterializationError(
                "materialized regular grew during its scan"
            )
        after_fd = os.fstat(descriptor)
        after_name = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        if (
            _source_metadata_identity(after_fd) != _source_metadata_identity(before)
            or _source_metadata_identity(after_name) != _source_metadata_identity(before)
        ):
            raise DevelopmentRuntimeMaterializationError(
                "materialized regular changed during its scan"
            )
        return digest.hexdigest()
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _scan_destination_once(
    root_descriptor: int,
    expected_entries: tuple[_ExpectedEntry, ...],
    expected_directories: tuple[str, ...],
) -> tuple[
    tuple[_ScanObservation, ...],
    tuple[DevelopmentRuntimeMaterializedDirectory, ...],
    tuple[DevelopmentRuntimeMaterializedEntry, ...],
]:
    entry_by_path = {item.destination_path: item for item in expected_entries}
    directory_paths = set(expected_directories)
    expected_paths = directory_paths | set(entry_by_path)
    observations: list[_ScanObservation] = []
    directories: list[DevelopmentRuntimeMaterializedDirectory] = []
    entries: list[DevelopmentRuntimeMaterializedEntry] = []
    observed_paths: set[str] = set()
    root_before = os.fstat(root_descriptor)
    if (
        not stat.S_ISDIR(root_before.st_mode)
        or stat.S_IMODE(root_before.st_mode) != MATERIALIZED_DIRECTORY_MODE
    ):
        raise DevelopmentRuntimeMaterializationError(
            "materialized destination root is not a mode-0555 directory"
        )
    observations.append(_observation("/", "directory", root_before))
    directories.append(
        DevelopmentRuntimeMaterializedDirectory(
            destination_path="/",
            mode=MATERIALIZED_DIRECTORY_MODE,
            link_count=root_before.st_nlink,
        )
    )
    observed_paths.add("/")
    stack: list[tuple[PurePosixPath, tuple[int, ...] | None]] = [
        (PurePosixPath(), None)
    ]
    maximum_nodes = len(expected_paths)
    while stack:
        relative_parent, discovered_identity = stack.pop()
        directory_descriptor: int | None = None
        try:
            if relative_parent == PurePosixPath():
                directory_descriptor = os.dup(root_descriptor)
            else:
                directory_descriptor = _static._open_relative_directory(
                    root_descriptor, relative_parent
                )
                _static._assert_relative_directory_reachable(
                    root_descriptor, directory_descriptor, relative_parent
                )
            before_directory = os.fstat(directory_descriptor)
            if (
                discovered_identity is not None
                and _source_metadata_identity(before_directory)
                != discovered_identity
            ):
                raise DevelopmentRuntimeMaterializationError(
                    "materialized directory changed before traversal"
                )
            child_directories: list[
                tuple[PurePosixPath, tuple[int, ...]]
            ] = []
            with os.scandir(directory_descriptor) as iterator:
                names = [item.name for item in iterator]
            if len(observed_paths) + len(names) > maximum_nodes:
                raise DevelopmentRuntimeMaterializationError(
                    "materialized destination contains extra paths"
                )
            names.sort(key=os.fsencode)
            for name in names:
                relative = relative_parent / name
                path = "/" + relative.as_posix()
                if path not in expected_paths or path in observed_paths:
                    raise DevelopmentRuntimeMaterializationError(
                        "materialized destination path projection differs"
                    )
                metadata = os.stat(
                    name, dir_fd=directory_descriptor, follow_symlinks=False
                )
                observed_paths.add(path)
                if stat.S_ISDIR(metadata.st_mode):
                    if path not in directory_paths:
                        raise DevelopmentRuntimeMaterializationError(
                            "unexpected materialized directory"
                        )
                    child: int | None = None
                    try:
                        child = os.open(
                            name, _directory_flags(), dir_fd=directory_descriptor
                        )
                        opened = os.fstat(child)
                        if (
                            _source_metadata_identity(opened)
                            != _source_metadata_identity(metadata)
                            or stat.S_IMODE(metadata.st_mode)
                            != MATERIALIZED_DIRECTORY_MODE
                        ):
                            raise DevelopmentRuntimeMaterializationError(
                                "materialized directory changed during scan"
                            )
                    finally:
                        if child is not None:
                            os.close(child)
                    observations.append(_observation(path, "directory", metadata))
                    directories.append(
                        DevelopmentRuntimeMaterializedDirectory(
                            destination_path=path,
                            mode=MATERIALIZED_DIRECTORY_MODE,
                            link_count=metadata.st_nlink,
                        )
                    )
                    child_directories.append(
                        (relative, _source_metadata_identity(metadata))
                    )
                    continue
                expected = entry_by_path.get(path)
                if expected is None:
                    raise DevelopmentRuntimeMaterializationError(
                        "materialized leaf is not declared"
                    )
                if stat.S_ISREG(metadata.st_mode):
                    if expected.kind != "regular" or metadata.st_nlink != 1:
                        raise DevelopmentRuntimeMaterializationError(
                            "materialized regular kind or link count differs"
                        )
                    digest = _read_destination_regular(
                        directory_descriptor,
                        name,
                        metadata,
                        maximum_bytes=expected.size,
                    )
                    if (
                        stat.S_IMODE(metadata.st_mode)
                        != _materialized_regular_mode(expected.mode)
                        or metadata.st_size != expected.size
                        or digest != expected.sha256
                    ):
                        raise DevelopmentRuntimeMaterializationError(
                            "materialized regular differs from source manifest"
                        )
                    observations.append(
                        _observation(path, "regular", metadata, digest=digest)
                    )
                    entries.append(
                        DevelopmentRuntimeMaterializedEntry(
                            destination_path=path,
                            kind="regular",
                            mode=stat.S_IMODE(metadata.st_mode),
                            size=metadata.st_size,
                            link_count=metadata.st_nlink,
                            content_sha256=digest,
                            symlink_target=None,
                        )
                    )
                elif stat.S_ISLNK(metadata.st_mode):
                    target = os.readlink(name, dir_fd=directory_descriptor)
                    after = os.stat(
                        name, dir_fd=directory_descriptor, follow_symlinks=False
                    )
                    if (
                        expected.kind != "symlink"
                        or _source_metadata_identity(metadata)
                        != _source_metadata_identity(after)
                        or stat.S_IMODE(metadata.st_mode) != expected.mode
                        or metadata.st_size != expected.size
                        or metadata.st_nlink != 1
                        or target != expected.target
                    ):
                        raise DevelopmentRuntimeMaterializationError(
                            "materialized symbolic link differs from source manifest"
                        )
                    observations.append(
                        _observation(path, "symlink", metadata, target=target)
                    )
                    entries.append(
                        DevelopmentRuntimeMaterializedEntry(
                            destination_path=path,
                            kind="symlink",
                            mode=stat.S_IMODE(metadata.st_mode),
                            size=metadata.st_size,
                            link_count=metadata.st_nlink,
                            content_sha256=None,
                            symlink_target=target,
                        )
                    )
                else:
                    raise DevelopmentRuntimeMaterializationError(
                        "materialized destination contains a special file"
                    )
            after_directory = os.fstat(directory_descriptor)
            if _source_metadata_identity(after_directory) != _source_metadata_identity(
                before_directory
            ):
                raise DevelopmentRuntimeMaterializationError(
                    "materialized directory changed while scanning"
                )
            stack.extend(reversed(child_directories))
        finally:
            if directory_descriptor is not None:
                os.close(directory_descriptor)
    if observed_paths != expected_paths:
        raise DevelopmentRuntimeMaterializationError(
            "materialized destination is missing declared paths"
        )
    ordered_observations = tuple(sorted(observations, key=lambda item: item.path.encode("utf-8")))
    ordered_directories = tuple(
        sorted(directories, key=lambda item: item.destination_path.encode("utf-8"))
    )
    ordered_entries = tuple(
        sorted(entries, key=lambda item: item.destination_path.encode("utf-8"))
    )
    return ordered_observations, ordered_directories, ordered_entries


def _scan_sha256(observations: tuple[_ScanObservation, ...]) -> str:
    return sha256(
        canonical_development_runtime_json_bytes(
            [item.to_record() for item in observations]
        )
    ).hexdigest()


def _construct_evidence(
    *,
    source_manifest_sha256: str,
    destination_root: str,
    directories: tuple[DevelopmentRuntimeMaterializedDirectory, ...],
    entries: tuple[DevelopmentRuntimeMaterializedEntry, ...],
    first_scan_sha256: str,
    second_scan_sha256: str,
) -> DevelopmentRuntimeMaterializationEvidence:
    counts = {
        "directory_count": len(directories),
        "entry_count": len(entries),
        "regular_file_count": sum(item.kind == "regular" for item in entries),
        "symlink_count": sum(item.kind == "symlink" for item in entries),
        "regular_payload_bytes": sum(
            item.size for item in entries if item.kind == "regular"
        ),
    }
    # Compute the digest from the exact public record without weakening the
    # dataclass invariant with an optional or placeholder self-digest.
    record: dict[str, object] = {
        "schema_version": DEVELOPMENT_RUNTIME_MATERIALIZATION_SCHEMA_VERSION,
        "materializer_version": DEVELOPMENT_RUNTIME_MATERIALIZER_VERSION,
        "kind": DEVELOPMENT_RUNTIME_MATERIALIZATION_KIND,
        "algorithm": DEVELOPMENT_RUNTIME_MATERIALIZATION_ALGORITHM,
        "source_manifest_sha256": source_manifest_sha256,
        "destination_root": destination_root,
        **_projection_record(directories, entries),
        **counts,
        "projection_sha256": _projection_sha256(directories, entries),
        "first_scan_sha256": first_scan_sha256,
        "second_scan_sha256": second_scan_sha256,
        "source_replay_verified_before_materialization": True,
        "source_replay_verified_after_materialization": True,
        "final_named_destination_verified": True,
        "final_double_scan_verified": True,
        "runtime_bundle_materialized": True,
        "same_uid_mutation_resistant": False,
        "fd_bound_launch_handoff": False,
        "launch_eligible": False,
        "candidate_execution_authorized": False,
        "claim_pipeline_eligible": False,
        "scored_evaluation_eligible": False,
    }
    digest = sha256(canonical_development_runtime_json_bytes(record)).hexdigest()
    return DevelopmentRuntimeMaterializationEvidence(
        source_manifest_sha256=source_manifest_sha256,
        destination_root=destination_root,
        directories=directories,
        entries=entries,
        projection_sha256=record["projection_sha256"],  # type: ignore[arg-type]
        first_scan_sha256=first_scan_sha256,
        second_scan_sha256=second_scan_sha256,
        evidence_sha256=digest,
        **counts,
    )


def materialize_development_runtime_bundle(
    manifest: object,
    destination: str | os.PathLike[str],
    *,
    expected_manifest_sha256: str,
) -> DevelopmentRuntimeMaterializationEvidence:
    """Copy one authenticated source manifest into a new nonlaunching root.

    ``expected_manifest_sha256`` is a trusted campaign input rather than a
    digest learned from ``manifest``.  ``destination`` must not exist.  Its
    parent must already be a real path reachable without following symbolic
    links.  Failure may leave a partial newly-created destination; such a path
    is intentionally not reused or recursively cleaned through potentially
    raced names.
    """

    expected_manifest_digest = _sha256_text(
        expected_manifest_sha256, what="expected_manifest_sha256"
    )
    shell = _preflight_runtime_manifest_shell(
        manifest,
        expected_manifest_sha256=expected_manifest_digest,
    )
    _preflight_materializer_manifest_bounds(shell)
    frozen_manifest = _strict_plain_json_copy(manifest)
    destination_path, destination_text = _destination_path(destination)
    try:
        validate_development_runtime_bundle_manifest(frozen_manifest)
    except (DevelopmentRuntimeBundleError, OSError, TypeError, ValueError) as exc:
        raise DevelopmentRuntimeMaterializationError(
            "runtime source manifest failed pre-materialization replay"
        ) from exc
    expected_entries, expected_directories = _expected_projection(frozen_manifest)
    reserved = {"/" + _stage_name(item.destination_path) for item in expected_entries}
    if reserved & (
        set(expected_directories)
        | {item.destination_path for item in expected_entries}
    ):
        raise DevelopmentRuntimeMaterializationError(
            "runtime projection collides with materializer staging names"
        )

    root_descriptor: int | None = None
    try:
        root_descriptor = _create_new_destination(destination_path)
        for path in sorted(
            (item for item in expected_directories if item != "/"),
            key=lambda item: (len(PurePosixPath(item).parts), item.encode("utf-8")),
        ):
            _static._ensure_relative_directory(
                root_descriptor, PurePosixPath(path.lstrip("/"))
            )
        for expected in expected_entries:
            if expected.kind == "regular":
                _publish_regular_from_source(root_descriptor, expected)
            else:
                _publish_symlink(root_descriptor, expected)
        _seal_materialized_directories(root_descriptor, expected_directories)

        try:
            validate_development_runtime_bundle_manifest(frozen_manifest)
        except (DevelopmentRuntimeBundleError, OSError, TypeError, ValueError) as exc:
            raise DevelopmentRuntimeMaterializationError(
                "runtime source manifest failed post-materialization replay"
            ) from exc

        _assert_named_destination(destination_path, root_descriptor)
        first, directories, entries = _scan_destination_once(
            root_descriptor, expected_entries, expected_directories
        )
        second, second_directories, second_entries = _scan_destination_once(
            root_descriptor, expected_entries, expected_directories
        )
        _assert_named_destination(destination_path, root_descriptor)
        if (
            first != second
            or directories != second_directories
            or entries != second_entries
        ):
            raise DevelopmentRuntimeMaterializationError(
                "materialized destination changed across its final double scan"
            )
        first_sha = _scan_sha256(first)
        second_sha = _scan_sha256(second)
        if first_sha != second_sha:
            raise DevelopmentRuntimeMaterializationError(
                "materialized destination scan digests disagree"
            )
        source_digest = frozen_manifest.get("manifest_sha256")
        _sha256_text(source_digest, what="source manifest digest")
        return _construct_evidence(
            source_manifest_sha256=source_digest,
            destination_root=destination_text,
            directories=directories,
            entries=entries,
            first_scan_sha256=first_sha,
            second_scan_sha256=second_sha,
        )
    except DevelopmentRuntimeMaterializationError:
        raise
    except (OSError, TypeError, ValueError, UnicodeError) as exc:
        raise DevelopmentRuntimeMaterializationError(
            f"runtime materialization failed closed: {type(exc).__name__}"
        ) from exc
    finally:
        if root_descriptor is not None:
            os.close(root_descriptor)


def validate_development_runtime_materialization_binding(
    evidence: DevelopmentRuntimeMaterializationEvidence,
    manifest: object,
    *,
    expected_manifest_sha256: str,
) -> None:
    """Rebind structural evidence to current trusted sources and destination.

    This is a point-in-time validation only.  It deliberately does not claim a
    same-UID mutation-resistant or fd-bound launch handoff; both flags remain
    false in the evidence and a future launcher must close that race.
    """

    if type(evidence) is not DevelopmentRuntimeMaterializationEvidence:
        raise DevelopmentRuntimeMaterializationError(
            "evidence must be exact materialization evidence"
        )
    evidence.__post_init__()
    expected_digest = _sha256_text(
        expected_manifest_sha256, what="expected_manifest_sha256"
    )
    if evidence.source_manifest_sha256 != expected_digest:
        raise DevelopmentRuntimeMaterializationError(
            "evidence source digest differs from the trusted manifest digest"
        )
    shell = _preflight_runtime_manifest_shell(
        manifest,
        expected_manifest_sha256=expected_digest,
    )
    _preflight_materializer_manifest_bounds(shell)
    frozen_manifest = _strict_plain_json_copy(manifest)
    try:
        validate_development_runtime_bundle_manifest(frozen_manifest)
    except (DevelopmentRuntimeBundleError, OSError, TypeError, ValueError) as exc:
        raise DevelopmentRuntimeMaterializationError(
            "runtime source manifest failed binding replay"
        ) from exc
    expected_entries, expected_directories = _expected_projection(frozen_manifest)
    destination_path, destination_text = _destination_path(evidence.destination_root)
    if destination_text != evidence.destination_root:
        raise DevelopmentRuntimeMaterializationError(
            "evidence destination root is not canonical"
        )
    root_descriptor: int | None = None
    try:
        root_descriptor, _ = _static._open_absolute_directory_no_follow(
            destination_path
        )
        _assert_named_destination(destination_path, root_descriptor)
        first, directories, entries = _scan_destination_once(
            root_descriptor, expected_entries, expected_directories
        )
        second, second_directories, second_entries = _scan_destination_once(
            root_descriptor, expected_entries, expected_directories
        )
        _assert_named_destination(destination_path, root_descriptor)
        if (
            first != second
            or directories != second_directories
            or entries != second_entries
        ):
            raise DevelopmentRuntimeMaterializationError(
                "materialized destination changed during binding replay"
            )
        rebound = _construct_evidence(
            source_manifest_sha256=expected_digest,
            destination_root=destination_text,
            directories=directories,
            entries=entries,
            first_scan_sha256=_scan_sha256(first),
            second_scan_sha256=_scan_sha256(second),
        )
        if rebound.to_record() != evidence.to_record():
            raise DevelopmentRuntimeMaterializationError(
                "materialization evidence differs from the current bound root"
            )
    except DevelopmentRuntimeMaterializationError:
        raise
    except (OSError, TypeError, ValueError, UnicodeError) as exc:
        raise DevelopmentRuntimeMaterializationError(
            f"runtime materialization binding failed: {type(exc).__name__}"
        ) from exc
    finally:
        if root_descriptor is not None:
            os.close(root_descriptor)


def verify_development_runtime_materialization_binding(
    evidence: object,
    manifest: object,
    *,
    expected_manifest_sha256: str,
) -> bool:
    """Return whether live source/root rebinding succeeds at this instant."""

    try:
        validate_development_runtime_materialization_binding(
            evidence,  # type: ignore[arg-type]
            manifest,
            expected_manifest_sha256=expected_manifest_sha256,
        )
    except (
        AttributeError,
        DevelopmentRuntimeMaterializationError,
        OSError,
        TypeError,
        ValueError,
    ):
        return False
    return True


__all__ = [
    "DEVELOPMENT_RUNTIME_MATERIALIZATION_ALGORITHM",
    "DEVELOPMENT_RUNTIME_MATERIALIZATION_KIND",
    "DEVELOPMENT_RUNTIME_MATERIALIZATION_SCHEMA_VERSION",
    "DEVELOPMENT_RUNTIME_MATERIALIZER_VERSION",
    "DevelopmentRuntimeMaterializationError",
    "DevelopmentRuntimeMaterializationEvidence",
    "DevelopmentRuntimeMaterializedDirectory",
    "DevelopmentRuntimeMaterializedEntry",
    "materialize_development_runtime_bundle",
    "validate_development_runtime_materialization_binding",
    "verify_development_runtime_materialization_binding",
    "verify_development_runtime_materialization_evidence_structure",
]
