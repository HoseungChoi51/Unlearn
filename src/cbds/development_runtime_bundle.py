"""Content-addressed source manifest for a minimal development runtime.

This module does not copy files, construct a root filesystem, or execute a
program.  It inspects caller-named ELF executables through descriptor-relative,
no-follow reads rooted at pinned directory descriptors, resolves their
``PT_INTERP`` and ``DT_NEEDED`` closure through caller-pinned search
directories, and records every regular file, symbolic link, ordered search,
and negative lookup needed to reproduce that closure.

The resulting document is deliberately *not* launch authorization.  Dynamic
loading, locale data, shell modules, and utility policy enforcement are wider
than the ELF link closure described here.  Those boundaries must be supplied
and verified separately before any candidate execution path can exist.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import stat
import struct
from typing import Final


DEVELOPMENT_RUNTIME_BUNDLE_SCHEMA_VERSION: Final[str] = "2.0.0"
DEVELOPMENT_RUNTIME_BUNDLE_VERSION: Final[str] = "2.0.0"
DEVELOPMENT_RUNTIME_BUNDLE_KIND: Final[str] = (
    "cbds-development-runtime-source-manifest"
)
ELF_CLOSURE_ALGORITHM: Final[str] = "elf-pt-interp-dt-needed-v2"
LIBRARY_RESOLUTION_ALGORITHM: Final[str] = (
    "ordered-pinned-directory-fd-negative-lookup-v1"
)
DEFAULT_MAXIMUM_FILE_BYTES: Final[int] = 512 * 1024 * 1024
DEFAULT_MAXIMUM_TOTAL_REGULAR_PAYLOAD_BYTES: Final[int] = 512 * 1024 * 1024
MAXIMUM_MANIFEST_ENTRIES: Final[int] = 4096
MAXIMUM_ALLOWED_SOURCE_ROOTS: Final[int] = 64
MAXIMUM_LIBRARY_SEARCH_DIRECTORIES: Final[int] = 256
MAXIMUM_LIBRARY_LOOKUP_CANDIDATES: Final[int] = 65_536
MAXIMUM_SYMLINK_EXPANSIONS: Final[int] = 40
MAXIMUM_PINNED_DIRECTORIES: Final[int] = 8_192
PINNED_DIRECTORY_FD_RESERVE: Final[int] = 32

_WRITE_RELEVANT_XATTRS: Final[frozenset[str]] = frozenset(
    {
        "security.capability",
        "system.nfs4_acl",
        "system.posix_acl_access",
        "system.posix_acl_default",
        "system.richacl",
    }
)

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}")
_NAME_RE: Final[re.Pattern[str]] = re.compile(r"[a-z0-9][a-z0-9._+-]{0,127}")
_ELF_MAGIC: Final[bytes] = b"\x7fELF"
_PT_LOAD: Final[int] = 1
_PT_DYNAMIC: Final[int] = 2
_PT_INTERP: Final[int] = 3
_DT_NULL: Final[int] = 0
_DT_NEEDED: Final[int] = 1
_DT_STRTAB: Final[int] = 5
_DT_STRSZ: Final[int] = 10
_DT_RPATH: Final[int] = 15
_DT_RUNPATH: Final[int] = 29


class DevelopmentRuntimeBundleError(ValueError):
    """Raised when a runtime source or manifest fails closed validation."""


@dataclass(frozen=True, slots=True)
class DevelopmentRuntimeExecutable:
    """One explicitly requested ELF executable and its expected content."""

    name: str
    source_path: str
    expected_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or _NAME_RE.fullmatch(self.name) is None:
            raise ValueError("name must be a normalized runtime executable label")
        _validate_absolute_path(self.source_path, what="source_path")
        if (
            not isinstance(self.expected_sha256, str)
            or _SHA256_RE.fullmatch(self.expected_sha256) is None
        ):
            raise ValueError("expected_sha256 must be lowercase SHA-256")

    def to_record(self, *, resolved_path: str) -> dict[str, str]:
        return {
            "name": self.name,
            "source_path": self.source_path,
            "resolved_path": resolved_path,
            "expected_sha256": self.expected_sha256,
        }


@dataclass(frozen=True, slots=True)
class _ElfMetadata:
    elf_class: int
    byte_order: str
    machine: int
    object_type: int
    pt_interp: str | None
    dt_needed: tuple[str, ...]

    def to_record(self) -> dict[str, object]:
        return {
            "class_bits": self.elf_class,
            "byte_order": self.byte_order,
            "machine": self.machine,
            "object_type": self.object_type,
            "pt_interp": self.pt_interp,
            "dt_needed": list(self.dt_needed),
        }


@dataclass(frozen=True, slots=True)
class _ObservedRegular:
    path: str
    mode: int
    uid: int
    gid: int
    size: int
    sha256: str
    payload: bytes


@dataclass(frozen=True, slots=True)
class _ObservedSymlink:
    path: str
    mode: int
    uid: int
    gid: int
    size: int
    target: str


@dataclass(frozen=True, slots=True)
class _PinnedDirectory:
    path: str
    descriptor: int
    identity: tuple[int, ...]


def canonical_development_runtime_json_bytes(value: object) -> bytes:
    """Return the canonical JSON representation used for manifest identity."""

    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise DevelopmentRuntimeBundleError("value is not canonical JSON") from exc


def compute_development_runtime_bundle_sha256(
    manifest: Mapping[str, object],
) -> str:
    """Hash a manifest after excluding its self-referential digest."""

    if not isinstance(manifest, Mapping):
        raise TypeError("manifest must be a mapping")
    payload = dict(manifest)
    payload.pop("manifest_sha256", None)
    return sha256(canonical_development_runtime_json_bytes(payload)).hexdigest()


def verify_development_runtime_bundle_sha256(
    manifest: Mapping[str, object],
) -> bool:
    """Return whether ``manifest`` carries a valid canonical self-digest."""

    if not isinstance(manifest, Mapping):
        return False
    digest = manifest.get("manifest_sha256")
    if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
        return False
    try:
        return digest == compute_development_runtime_bundle_sha256(manifest)
    except (DevelopmentRuntimeBundleError, TypeError):
        return False


def build_development_runtime_bundle_manifest(
    executables: Iterable[DevelopmentRuntimeExecutable],
    *,
    allowed_source_roots: Iterable[str],
    library_search_directories: Iterable[str],
    maximum_file_bytes: int = DEFAULT_MAXIMUM_FILE_BYTES,
    maximum_total_regular_payload_bytes: int = (
        DEFAULT_MAXIMUM_TOTAL_REGULAR_PAYLOAD_BYTES
    ),
    maximum_manifest_entries: int = MAXIMUM_MANIFEST_ENTRIES,
) -> dict[str, object]:
    """Inspect and describe a deterministic ELF dependency closure.

    No executable is invoked.  The library resolver searches the supplied
    directories in their declared order.  ELF ``RPATH`` and ``RUNPATH`` are
    rejected rather than approximated, and ``DT_NEEDED`` values containing a
    slash are rejected.  This makes the implemented closure exact for the
    explicitly supported resolution model.
    """

    maximum_file_bytes = _positive_limit(
        maximum_file_bytes,
        what="maximum_file_bytes",
        upper=2**63 - 1,
    )
    maximum_total_regular_payload_bytes = _positive_limit(
        maximum_total_regular_payload_bytes,
        what="maximum_total_regular_payload_bytes",
        upper=2**63 - 1,
    )
    maximum_manifest_entries = _positive_limit(
        maximum_manifest_entries,
        what="maximum_manifest_entries",
        upper=MAXIMUM_MANIFEST_ENTRIES,
    )
    selected = _normalize_executables(
        executables,
        maximum_count=maximum_manifest_entries,
    )
    roots = _normalize_roots(allowed_source_roots)
    search_directories = _normalize_search_directories(
        library_search_directories, roots
    )
    observer = _SourceObserver(
        roots=roots,
        maximum_file_bytes=maximum_file_bytes,
        maximum_total_regular_payload_bytes=maximum_total_regular_payload_bytes,
        maximum_entries=maximum_manifest_entries,
    )
    try:
        observer.pin_search_directories(search_directories)
        return _assemble_development_runtime_bundle_manifest(
            selected=selected,
            roots=roots,
            search_directories=search_directories,
            maximum_file_bytes=maximum_file_bytes,
            maximum_total_regular_payload_bytes=(
                maximum_total_regular_payload_bytes
            ),
            maximum_manifest_entries=maximum_manifest_entries,
            observer=observer,
        )
    finally:
        observer.close()


def _assemble_development_runtime_bundle_manifest(
    *,
    selected: tuple[DevelopmentRuntimeExecutable, ...],
    roots: tuple[str, ...],
    search_directories: tuple[str, ...],
    maximum_file_bytes: int,
    maximum_total_regular_payload_bytes: int,
    maximum_manifest_entries: int,
    observer: "_SourceObserver",
) -> dict[str, object]:
    roles: dict[str, set[str]] = {}
    symlinks: dict[str, _ObservedSymlink] = {}
    regulars: dict[str, _ObservedRegular] = {}
    elf_by_path: dict[str, _ElfMetadata] = {}
    library_resolutions: list[dict[str, object]] = []
    parsed_paths: set[str] = set()
    queued_roles: set[tuple[str, str]] = set()
    queue: deque[tuple[str, str]] = deque()

    def enqueue(path: str, role: str) -> None:
        pair = (path, role)
        if pair not in queued_roles:
            queued_roles.add(pair)
            queue.append(pair)

    explicit_records: list[dict[str, str]] = []
    resolved_explicit_paths: set[str] = set()
    explicit_resolution: dict[str, str] = {}
    for item in selected:
        chain, final = observer.resolve_regular(item.source_path)
        _merge_chain(
            chain,
            final,
            "explicit_executable",
            symlinks,
            regulars,
            roles,
            maximum_entries=maximum_manifest_entries,
        )
        if not final.mode & 0o111:
            raise DevelopmentRuntimeBundleError(
                f"explicit executable lacks an execute bit: {item.source_path}"
            )
        if final.sha256 != item.expected_sha256:
            raise DevelopmentRuntimeBundleError(
                f"explicit executable digest mismatch: {item.source_path}"
            )
        if final.path in resolved_explicit_paths:
            raise DevelopmentRuntimeBundleError(
                "explicit executable destinations must resolve uniquely"
            )
        resolved_explicit_paths.add(final.path)
        explicit_resolution[item.source_path] = final.path
        enqueue(final.path, "explicit_executable")

    architecture: tuple[int, str, int] | None = None
    while queue:
        path, role = queue.popleft()
        roles.setdefault(path, set()).add(role)
        if path in parsed_paths:
            continue
        parsed_paths.add(path)
        observed = regulars[path]
        metadata = _parse_elf(observed.payload, path=path)
        elf_by_path[path] = metadata
        current_architecture = (
            metadata.elf_class,
            metadata.byte_order,
            metadata.machine,
        )
        if architecture is None:
            architecture = current_architecture
        elif current_architecture != architecture:
            raise DevelopmentRuntimeBundleError(
                f"ELF architecture mismatch in closure: {path}"
            )
        if metadata.pt_interp is not None:
            chain, final = observer.resolve_regular(metadata.pt_interp)
            if not final.mode & 0o111:
                raise DevelopmentRuntimeBundleError(
                    f"ELF interpreter lacks an execute bit: {metadata.pt_interp}"
                )
            _merge_chain(
                chain,
                final,
                "elf_interpreter",
                symlinks,
                regulars,
                roles,
                maximum_entries=maximum_manifest_entries,
            )
            enqueue(final.path, "elf_interpreter")
        for needed_index, needed in enumerate(metadata.dt_needed):
            dependency_path, searches = observer.find_library(
                needed,
                search_directories=search_directories,
            )
            chain, final = observer.resolve_regular(dependency_path)
            _merge_chain(
                chain,
                final,
                "shared_library",
                symlinks,
                regulars,
                roles,
                maximum_entries=maximum_manifest_entries,
            )
            library_resolutions.append(
                {
                    "requester_path": path,
                    "needed_index": needed_index,
                    "needed_name": needed,
                    "searches": list(searches),
                    "selected_source_path": dependency_path,
                    "selected_resolved_path": final.path,
                }
            )
            enqueue(final.path, "shared_library")
        if len(symlinks) + len(regulars) > maximum_manifest_entries:
            raise DevelopmentRuntimeBundleError("ELF closure exceeds entry limit")

    for item in selected:
        resolved = explicit_resolution[item.source_path]
        explicit_records.append(item.to_record(resolved_path=resolved))

    observer.revalidate()
    if observer.total_regular_payload_bytes != sum(
        regular.size for regular in regulars.values()
    ):
        raise DevelopmentRuntimeBundleError(
            "runtime regular-payload accounting is inconsistent"
        )
    entries: list[dict[str, object]] = []
    for path, link in symlinks.items():
        entries.append(
            {
                "source_path": path,
                "destination_path": path,
                "kind": "symlink",
                "mode": link.mode,
                "uid": link.uid,
                "gid": link.gid,
                "size": link.size,
                "target": link.target,
                "roles": sorted(roles.get(path, set())),
            }
        )
    for path, regular in regulars.items():
        entries.append(
            {
                "source_path": path,
                "destination_path": path,
                "kind": "regular",
                "mode": regular.mode,
                "uid": regular.uid,
                "gid": regular.gid,
                "size": regular.size,
                "sha256": regular.sha256,
                "roles": sorted(roles.get(path, set())),
                "elf": elf_by_path[path].to_record(),
            }
        )
    entries.sort(key=lambda entry: str(entry["destination_path"]).encode("utf-8"))
    destinations = [str(entry["destination_path"]) for entry in entries]
    if len(destinations) != len(set(destinations)):
        raise DevelopmentRuntimeBundleError("runtime closure has duplicate destinations")

    library_resolutions.sort(
        key=lambda record: (
            str(record["requester_path"]).encode("utf-8"),
            int(record["needed_index"]),
        )
    )
    negative_lookup_count = sum(
        1
        for resolution in library_resolutions
        for search in resolution["searches"]  # type: ignore[union-attr]
        if isinstance(search, Mapping) and search.get("outcome") == "missing"
    )
    lookup_candidate_count = sum(
        len(resolution["searches"])  # type: ignore[arg-type]
        for resolution in library_resolutions
    )

    manifest: dict[str, object] = {
        "schema_version": DEVELOPMENT_RUNTIME_BUNDLE_SCHEMA_VERSION,
        "builder_version": DEVELOPMENT_RUNTIME_BUNDLE_VERSION,
        "kind": DEVELOPMENT_RUNTIME_BUNDLE_KIND,
        "allowed_source_roots": list(roots),
        "library_search_directories": list(search_directories),
        "maximum_file_bytes": maximum_file_bytes,
        "maximum_total_regular_payload_bytes": (
            maximum_total_regular_payload_bytes
        ),
        "maximum_manifest_entries": maximum_manifest_entries,
        "explicit_executables": explicit_records,
        "entries": entries,
        "closure": {
            "algorithm": ELF_CLOSURE_ALGORITHM,
            "elf_pt_interp_dt_needed_verified": True,
            "runtime_data_and_dlopen_closure_verified": False,
            "entry_count": len(entries),
            "regular_file_count": len(regulars),
            "symlink_count": len(symlinks),
            "regular_payload_bytes": observer.total_regular_payload_bytes,
        },
        "library_resolution": {
            "algorithm": LIBRARY_RESOLUTION_ALGORITHM,
            "search_precedence_and_negative_lookups_verified": True,
            "resolution_count": len(library_resolutions),
            "negative_lookup_count": negative_lookup_count,
            "lookup_candidate_count": lookup_candidate_count,
            "resolutions": library_resolutions,
        },
        "runtime_bundle_materialized": False,
        "launch_eligible": False,
        "candidate_execution_authorized": False,
        "claim_pipeline_eligible": False,
        "scored_evaluation_eligible": False,
    }
    manifest["manifest_sha256"] = compute_development_runtime_bundle_sha256(manifest)
    return manifest


def validate_development_runtime_bundle_manifest(
    manifest: Mapping[str, object],
) -> None:
    """Strictly validate and fully reproduce a manifest from current sources.

    Validation is intentionally stronger than checking recorded hashes.  It
    reconstructs the complete supported ELF closure from the explicit roots,
    reopening every symbolic link and regular file with the same fail-closed
    stability checks, and requires byte-for-byte canonical manifest equality.
    """

    if not isinstance(manifest, Mapping):
        raise DevelopmentRuntimeBundleError("manifest must be an object")
    expected_top = {
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
    if set(manifest) != expected_top:
        raise DevelopmentRuntimeBundleError("manifest top-level shape is invalid")
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
    for name, value in exact.items():
        if manifest.get(name) != value:
            raise DevelopmentRuntimeBundleError(f"manifest field {name!r} is invalid")
    if not verify_development_runtime_bundle_sha256(manifest):
        raise DevelopmentRuntimeBundleError("manifest self-digest is invalid")

    roots = _string_list(
        manifest.get("allowed_source_roots"),
        "allowed_source_roots",
        maximum_count=MAXIMUM_ALLOWED_SOURCE_ROOTS,
    )
    search = _string_list(
        manifest.get("library_search_directories"),
        "library_search_directories",
        maximum_count=MAXIMUM_LIBRARY_SEARCH_DIRECTORIES,
    )
    maximum = _positive_limit(
        manifest.get("maximum_file_bytes"),
        what="maximum_file_bytes",
        upper=2**63 - 1,
    )
    maximum_total = _positive_limit(
        manifest.get("maximum_total_regular_payload_bytes"),
        what="maximum_total_regular_payload_bytes",
        upper=2**63 - 1,
    )
    maximum_entries = _positive_limit(
        manifest.get("maximum_manifest_entries"),
        what="maximum_manifest_entries",
        upper=MAXIMUM_MANIFEST_ENTRIES,
    )
    explicit_raw = manifest.get("explicit_executables")
    if (
        not isinstance(explicit_raw, list)
        or not explicit_raw
        or len(explicit_raw) > maximum_entries
    ):
        raise DevelopmentRuntimeBundleError("explicit_executables is invalid")
    explicit: list[DevelopmentRuntimeExecutable] = []
    for record in explicit_raw:
        if not isinstance(record, Mapping) or set(record) != {
            "name",
            "source_path",
            "resolved_path",
            "expected_sha256",
        }:
            raise DevelopmentRuntimeBundleError(
                "explicit executable record shape is invalid"
            )
        resolved = record.get("resolved_path")
        _validate_absolute_path(resolved, what="resolved_path")
        explicit.append(
            DevelopmentRuntimeExecutable(
                name=record.get("name"),  # type: ignore[arg-type]
                source_path=record.get("source_path"),  # type: ignore[arg-type]
                expected_sha256=record.get("expected_sha256"),  # type: ignore[arg-type]
            )
        )
    entries = manifest.get("entries")
    _validate_declared_entries(entries, maximum_entries=maximum_entries)
    _validate_declared_closure(
        manifest.get("closure"),
        entries,
        maximum_total_regular_payload_bytes=maximum_total,
    )
    _validate_declared_library_resolution(
        manifest.get("library_resolution"),
        search_directories=search,
        entries=entries,
    )

    rebuilt = build_development_runtime_bundle_manifest(
        explicit,
        allowed_source_roots=roots,
        library_search_directories=search,
        maximum_file_bytes=maximum,
        maximum_total_regular_payload_bytes=maximum_total,
        maximum_manifest_entries=maximum_entries,
    )
    rebuilt_bytes = canonical_development_runtime_json_bytes(rebuilt)
    declared_bytes = canonical_development_runtime_json_bytes(dict(manifest))
    if rebuilt_bytes != declared_bytes:
        raise DevelopmentRuntimeBundleError(
            "manifest does not reproduce from current source closure"
        )


def verify_development_runtime_bundle_manifest(
    manifest: Mapping[str, object],
) -> bool:
    """Return whether strict source-replaying validation succeeds."""

    try:
        validate_development_runtime_bundle_manifest(manifest)
    except (DevelopmentRuntimeBundleError, OSError, TypeError, ValueError):
        return False
    return True


def _normalize_executables(
    values: Iterable[DevelopmentRuntimeExecutable],
    *,
    maximum_count: int,
) -> tuple[DevelopmentRuntimeExecutable, ...]:
    if isinstance(values, (str, bytes, Mapping)):
        raise DevelopmentRuntimeBundleError("executables must be an iterable of records")
    try:
        iterator = iter(values)
    except TypeError as exc:
        raise DevelopmentRuntimeBundleError("executables must be iterable") from exc
    selected: list[DevelopmentRuntimeExecutable] = []
    names: set[str] = set()
    sources: set[str] = set()
    for index, item in enumerate(iterator):
        if index >= maximum_count:
            raise DevelopmentRuntimeBundleError(
                "executables exceeds maximum_manifest_entries"
            )
        if not isinstance(item, DevelopmentRuntimeExecutable):
            raise DevelopmentRuntimeBundleError(
                "executables must contain DevelopmentRuntimeExecutable records"
            )
        if item.name in names:
            raise DevelopmentRuntimeBundleError("executable names must be unique")
        if item.source_path in sources:
            raise DevelopmentRuntimeBundleError("explicit destinations must be unique")
        names.add(item.name)
        sources.add(item.source_path)
        selected.append(item)
    if not selected:
        raise DevelopmentRuntimeBundleError(
            "at least one DevelopmentRuntimeExecutable is required"
        )
    return tuple(sorted(selected, key=lambda item: item.source_path.encode("utf-8")))


def _normalize_roots(values: Iterable[str]) -> tuple[str, ...]:
    roots = _materialize_strings(
        values,
        "allowed_source_roots",
        maximum_count=MAXIMUM_ALLOWED_SOURCE_ROOTS,
    )
    if not roots:
        raise DevelopmentRuntimeBundleError("at least one allowed source root is required")
    normalized = tuple(sorted(roots, key=str.encode))
    for root in normalized:
        _validate_absolute_path(root, what="allowed source root")
    return normalized


def _normalize_search_directories(
    values: Iterable[str], roots: tuple[str, ...]
) -> tuple[str, ...]:
    directories = _materialize_strings(
        values,
        "library_search_directories",
        maximum_count=MAXIMUM_LIBRARY_SEARCH_DIRECTORIES,
    )
    for directory in directories:
        _validate_absolute_path(directory, what="library search directory")
        _require_allowed(directory, roots)
    return tuple(directories)


def _materialize_strings(
    values: Iterable[str],
    what: str,
    *,
    maximum_count: int,
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes, Mapping)):
        raise DevelopmentRuntimeBundleError(f"{what} must be an iterable of strings")
    try:
        iterator = iter(values)
    except TypeError as exc:
        raise DevelopmentRuntimeBundleError(f"{what} must be iterable") from exc
    result: list[str] = []
    seen: set[str] = set()
    for index, value in enumerate(iterator):
        if index >= maximum_count:
            raise DevelopmentRuntimeBundleError(
                f"{what} exceeds its maximum count of {maximum_count}"
            )
        if not isinstance(value, str):
            raise DevelopmentRuntimeBundleError(f"{what} must contain only strings")
        if value in seen:
            raise DevelopmentRuntimeBundleError(f"{what} must not contain duplicates")
        seen.add(value)
        result.append(value)
    return tuple(result)


def _positive_limit(value: object, *, what: str, upper: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value <= 0
        or value > upper
    ):
        raise DevelopmentRuntimeBundleError(
            f"{what} must be a positive integer no greater than {upper}"
        )
    return value


def _string_list(
    value: object,
    what: str,
    *,
    maximum_count: int,
) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or len(value) > maximum_count
        or any(not isinstance(item, str) for item in value)
    ):
        raise DevelopmentRuntimeBundleError(f"{what} must be a string array")
    return tuple(value)


def _validate_absolute_path(value: object, *, what: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or not value.startswith("/")
        or value.startswith("//")
        or any(character in value for character in ("\x00", "\r", "\n"))
        or str(PurePosixPath(value)) != value
        or "." in PurePosixPath(value).parts
        or ".." in PurePosixPath(value).parts
        or value == "/"
    ):
        raise DevelopmentRuntimeBundleError(f"{what} must be a normalized absolute path")


def _require_allowed(path: str, roots: tuple[str, ...]) -> None:
    if not any(path == root or path.startswith(root + "/") for root in roots):
        raise DevelopmentRuntimeBundleError(f"source path is outside allowed roots: {path}")


def _require_traversable(path: str, roots: tuple[str, ...]) -> None:
    """Permit an allowed path or a real ancestor needed to reach one."""

    if not any(
        path == root
        or path.startswith(root + "/")
        or root.startswith(path.rstrip("/") + "/")
        for root in roots
    ):
        raise DevelopmentRuntimeBundleError(f"source path is outside allowed roots: {path}")


def _metadata_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _directory_identity(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid)


def _pinned_directory_budget(*, maximum_entries: int, root_count: int) -> int:
    """Return a declared-work and RLIMIT_NOFILE bounded descriptor budget."""

    declared = min(
        MAXIMUM_PINNED_DIRECTORIES,
        max(16, maximum_entries * 4, root_count * 4),
    )
    try:
        soft_limit, _hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
    except (OSError, ValueError) as exc:
        raise DevelopmentRuntimeBundleError(
            "cannot establish a pinned-directory descriptor budget"
        ) from exc
    try:
        with os.scandir("/proc/self/fd") as iterator:
            open_descriptor_count = sum(1 for _entry in iterator)
    except OSError as exc:
        raise DevelopmentRuntimeBundleError(
            "cannot account for open descriptors before source inspection"
        ) from exc
    if soft_limit == resource.RLIM_INFINITY:
        available = MAXIMUM_PINNED_DIRECTORIES
    else:
        available = (
            int(soft_limit)
            - open_descriptor_count
            - PINNED_DIRECTORY_FD_RESERVE
        )
    if available < 1:
        raise DevelopmentRuntimeBundleError(
            "RLIMIT_NOFILE leaves no pinned-directory descriptor budget"
        )
    return min(declared, available)


class _SourceObserver:
    def __init__(
        self,
        *,
        roots: tuple[str, ...],
        maximum_file_bytes: int,
        maximum_total_regular_payload_bytes: int,
        maximum_entries: int,
    ) -> None:
        if (
            not getattr(os, "O_PATH", 0)
            or not getattr(os, "O_NOFOLLOW", 0)
            or not getattr(os, "O_DIRECTORY", 0)
        ):
            raise DevelopmentRuntimeBundleError(
                "descriptor-relative no-follow traversal is unavailable"
            )
        self.roots = roots
        self.maximum_file_bytes = maximum_file_bytes
        self.maximum_total_regular_payload_bytes = (
            maximum_total_regular_payload_bytes
        )
        self.maximum_entries = maximum_entries
        self.maximum_pinned_directories = _pinned_directory_budget(
            maximum_entries=maximum_entries,
            root_count=len(roots),
        )
        self._directories: dict[str, _PinnedDirectory] = {}
        self._root_alias_targets: dict[str, str] = {}
        self._search_directory_pins: dict[str, _PinnedDirectory] = {}
        self._symlinks: dict[str, _ObservedSymlink] = {}
        self._regulars: dict[str, _ObservedRegular] = {}
        self._negative_lookups: set[tuple[str, str]] = set()
        self._lookup_candidate_count = 0
        self._total_regular_payload_bytes = 0
        self._closed = False
        try:
            self._pin_initial_root()
            for root in roots:
                self._pin_declared_root(root)
        except Exception:
            self.close()
            raise

    @property
    def total_regular_payload_bytes(self) -> int:
        return self._total_regular_payload_bytes

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for pinned in sorted(
            self._directories.values(),
            key=lambda item: item.path.count("/"),
            reverse=True,
        ):
            try:
                os.close(pinned.descriptor)
            except OSError:
                pass
        self._directories.clear()

    def _pin_initial_root(self) -> None:
        flags = self._directory_open_flags()
        descriptor: int | None = None
        try:
            descriptor = os.open("/", flags)
            metadata = os.fstat(descriptor)
        except OSError as exc:
            if descriptor is not None:
                os.close(descriptor)
            raise DevelopmentRuntimeBundleError(
                "cannot pin the filesystem root directory"
            ) from exc
        if not stat.S_ISDIR(metadata.st_mode):
            os.close(descriptor)
            raise DevelopmentRuntimeBundleError("filesystem root is not a directory")
        self._directories["/"] = _PinnedDirectory(
            path="/",
            descriptor=descriptor,
            identity=_directory_identity(metadata),
        )

    def _require_pinned_directory_capacity(self, path: str) -> None:
        if path in self._directories:
            return
        if len(self._directories) >= self.maximum_pinned_directories:
            raise DevelopmentRuntimeBundleError(
                "runtime source exceeds the pinned-directory descriptor limit"
            )

    @staticmethod
    def _directory_open_flags() -> int:
        return (
            os.O_PATH
            | os.O_DIRECTORY
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0)
        )

    def _pin_absolute_directory(self, path: str) -> _PinnedDirectory:
        _validate_absolute_path(path, what="runtime source directory")
        existing = self._directories.get(path)
        if existing is not None:
            return existing
        current = self._directories["/"]
        current_path = ""
        for component in PurePosixPath(path).parts[1:]:
            current_path += "/" + component
            _require_traversable(current_path, self.roots)
            existing = self._directories.get(current_path)
            if existing is not None:
                current = existing
                continue
            self._require_pinned_directory_capacity(current_path)
            descriptor: int | None = None
            try:
                descriptor = os.open(
                    component,
                    self._directory_open_flags(),
                    dir_fd=current.descriptor,
                )
                metadata = os.fstat(descriptor)
            except OSError as exc:
                if descriptor is not None:
                    os.close(descriptor)
                raise DevelopmentRuntimeBundleError(
                    f"runtime source directory is unavailable or symbolic: {current_path}"
                ) from exc
            if not stat.S_ISDIR(metadata.st_mode):
                os.close(descriptor)
                raise DevelopmentRuntimeBundleError(
                    f"runtime source path is not a directory: {current_path}"
                )
            current = _PinnedDirectory(
                path=current_path,
                descriptor=descriptor,
                identity=_directory_identity(metadata),
            )
            self._directories[current_path] = current
        return current

    def _pin_declared_root(self, path: str) -> None:
        """Pin a real root or authenticate one symlink alias into another root.

        Usr-merged systems commonly expose ``/lib`` and ``/lib64`` as symbolic
        aliases into ``/usr``.  The alias itself is retained as a manifest
        entry, and its resolved directory must fall below another explicitly
        declared root.  No arbitrary ancestor symlink is accepted.
        """

        try:
            self._pin_absolute_directory(path)
            return
        except DevelopmentRuntimeBundleError as directory_error:
            pure = PurePosixPath(path)
            parent_path = str(pure.parent)
            parent = (
                self._directories["/"]
                if parent_path == "/"
                else self._pin_absolute_directory(parent_path)
            )
            observed = self._observe_symlink_at(
                parent=parent,
                name=pure.name,
                path=path,
            )
            if observed is None:
                raise directory_error
            combined = (
                observed.target
                if observed.target.startswith("/")
                else parent.path.rstrip("/") + "/" + observed.target
            )
            normalized = os.path.normpath(combined)
            _validate_absolute_path(normalized, what="resolved allowed source root")
            _require_allowed(normalized, self.roots)
            if normalized == path:
                raise DevelopmentRuntimeBundleError(
                    f"allowed source root alias loops to itself: {path}"
                )
            self._pin_absolute_directory(normalized)
            self._root_alias_targets[path] = normalized

    def _resolve_declared_alias_path(self, path: str) -> str:
        aliases = [
            alias
            for alias in self._root_alias_targets
            if path == alias or path.startswith(alias + "/")
        ]
        if not aliases:
            return path
        alias = max(aliases, key=lambda item: (len(item), item.encode("utf-8")))
        target = self._root_alias_targets[alias]
        suffix = PurePosixPath(path).relative_to(PurePosixPath(alias))
        translated = target
        if suffix.parts:
            translated = target.rstrip("/") + "/" + suffix.as_posix()
        _validate_absolute_path(translated, what="resolved library search directory")
        _require_allowed(translated, self.roots)
        return translated

    def pin_search_directories(self, directories: tuple[str, ...]) -> None:
        for directory in directories:
            _require_allowed(directory, self.roots)
            translated = self._resolve_declared_alias_path(directory)
            self._search_directory_pins[directory] = self._pin_absolute_directory(
                translated
            )

    def _select_root(self, path: str) -> str:
        candidates = [
            root
            for root in self.roots
            if path == root or path.startswith(root + "/")
        ]
        if not candidates:
            raise DevelopmentRuntimeBundleError(
                f"source path is outside allowed roots: {path}"
            )
        pinned = [candidate for candidate in candidates if candidate in self._directories]
        if not pinned:
            # Start at the pinned filesystem root so a declared symlink alias
            # (for example /lib64 -> usr/lib64) is observed rather than
            # followed by pathname resolution.
            return "/"
        return max(pinned, key=lambda value: (len(value), value.encode("utf-8")))

    def _pin_child_directory(
        self,
        *,
        parent: _PinnedDirectory,
        name: str,
        path: str,
    ) -> _PinnedDirectory:
        existing = self._directories.get(path)
        if existing is not None:
            return existing
        self._require_pinned_directory_capacity(path)
        descriptor = os.open(
            name,
            self._directory_open_flags(),
            dir_fd=parent.descriptor,
        )
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                raise DevelopmentRuntimeBundleError(
                    f"non-directory path component in runtime source: {path}"
                )
            pinned = _PinnedDirectory(
                path=path,
                descriptor=descriptor,
                identity=_directory_identity(metadata),
            )
            self._directories[path] = pinned
            return pinned
        except Exception:
            os.close(descriptor)
            raise

    def resolve_regular(
        self, source_path: str
    ) -> tuple[tuple[_ObservedSymlink, ...], _ObservedRegular]:
        _validate_absolute_path(source_path, what="source path")
        _require_allowed(source_path, self.roots)
        active_path = source_path
        chain: list[_ObservedSymlink] = []
        visited: set[str] = set()
        expansions = 0
        while True:
            root = self._select_root(active_path)
            current = self._directories[root]
            relative = PurePosixPath(active_path).relative_to(PurePosixPath(root))
            remaining = list(relative.parts)
            if not remaining:
                raise DevelopmentRuntimeBundleError(
                    "runtime source resolved to a directory"
                )
            while remaining:
                component = remaining.pop(0)
                candidate = (
                    current.path.rstrip("/") + "/" + component
                    if current.path != "/"
                    else "/" + component
                )
                if remaining:
                    try:
                        current = self._pin_child_directory(
                            parent=current,
                            name=component,
                            path=candidate,
                        )
                        continue
                    except OSError as open_error:
                        observed_link = self._observe_symlink_at(
                            parent=current,
                            name=component,
                            path=candidate,
                        )
                        if observed_link is None:
                            raise DevelopmentRuntimeBundleError(
                                "non-directory path component in runtime source: "
                                + candidate
                            ) from open_error
                else:
                    try:
                        return tuple(chain), self._observe_regular_at(
                            parent=current,
                            name=component,
                            path=candidate,
                        )
                    except OSError as open_error:
                        observed_link = self._observe_symlink_at(
                            parent=current,
                            name=component,
                            path=candidate,
                        )
                        if observed_link is None:
                            raise DevelopmentRuntimeBundleError(
                                f"runtime source is not a regular file: {candidate}"
                            ) from open_error

                expansions += 1
                if (
                    expansions > MAXIMUM_SYMLINK_EXPANSIONS
                    or candidate in visited
                ):
                    raise DevelopmentRuntimeBundleError(
                        f"symbolic-link loop or depth limit: {candidate}"
                    )
                visited.add(candidate)
                chain.append(observed_link)
                suffix = remaining
                if observed_link.target.startswith("/"):
                    combined = observed_link.target
                else:
                    combined = (
                        current.path.rstrip("/") + "/" + observed_link.target
                    )
                if suffix:
                    combined = combined.rstrip("/") + "/" + "/".join(suffix)
                normalized = os.path.normpath(combined)
                _validate_absolute_path(
                    normalized,
                    what="resolved symbolic-link path",
                )
                _require_allowed(normalized, self.roots)
                active_path = normalized
                break

    def _observe_symlink_at(
        self,
        *,
        parent: _PinnedDirectory,
        name: str,
        path: str,
    ) -> _ObservedSymlink | None:
        try:
            before = os.stat(name, dir_fd=parent.descriptor, follow_symlinks=False)
        except OSError as exc:
            raise DevelopmentRuntimeBundleError(
                f"runtime source path is missing or inaccessible: {path}"
            ) from exc
        if not stat.S_ISLNK(before.st_mode):
            return None
        _require_allowed(path, self.roots)
        try:
            target = os.readlink(name, dir_fd=parent.descriptor)
            after = os.stat(name, dir_fd=parent.descriptor, follow_symlinks=False)
        except OSError as exc:
            raise DevelopmentRuntimeBundleError(
                f"symbolic link changed while reading: {path}"
            ) from exc
        if _metadata_identity(before) != _metadata_identity(after):
            raise DevelopmentRuntimeBundleError(
                f"symbolic link changed while reading: {path}"
            )
        if not target or "\x00" in target or "\r" in target or "\n" in target:
            raise DevelopmentRuntimeBundleError(
                f"symbolic link target is invalid: {path}"
            )
        observed = _ObservedSymlink(
            path=path,
            mode=stat.S_IMODE(before.st_mode),
            uid=before.st_uid,
            gid=before.st_gid,
            size=before.st_size,
            target=target,
        )
        previous = self._symlinks.get(path)
        if previous is None:
            if path in self._regulars:
                raise DevelopmentRuntimeBundleError(
                    f"conflicting regular and symbolic runtime source: {path}"
                )
            self._reserve_observed_entry(path)
            self._symlinks[path] = observed
        elif previous != observed:
            raise DevelopmentRuntimeBundleError(
                f"symbolic link observation is inconsistent: {path}"
            )
        return observed

    def _observe_regular_at(
        self,
        *,
        parent: _PinnedDirectory,
        name: str,
        path: str,
    ) -> _ObservedRegular:
        flags = (
            os.O_RDONLY
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        descriptor = os.open(name, flags, dir_fd=parent.descriptor)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise DevelopmentRuntimeBundleError(
                    f"runtime source is not a regular file: {path}"
                )
            return self._observe_open_regular(path, descriptor, before)
        finally:
            os.close(descriptor)

    def _observe_open_regular(
        self,
        path: str,
        descriptor: int,
        before: os.stat_result,
    ) -> _ObservedRegular:
        mode = stat.S_IMODE(before.st_mode)
        if mode & (stat.S_ISUID | stat.S_ISGID):
            raise DevelopmentRuntimeBundleError(
                f"setuid or setgid runtime source is forbidden: {path}"
            )
        if _writable_by_caller(before):
            raise DevelopmentRuntimeBundleError(
                f"runtime executable or library is writable by the builder: {path}"
            )
        _require_unambiguous_nonwritable_access(path, descriptor)
        if before.st_size < 0 or before.st_size > self.maximum_file_bytes:
            raise DevelopmentRuntimeBundleError(
                f"runtime source exceeds maximum_file_bytes: {path}"
            )
        previous = self._regulars.get(path)
        if previous is None:
            if path in self._symlinks:
                raise DevelopmentRuntimeBundleError(
                    f"conflicting symbolic and regular runtime source: {path}"
                )
            self._reserve_observed_entry(path)
            if (
                before.st_size
                > self.maximum_total_regular_payload_bytes
                - self._total_regular_payload_bytes
            ):
                raise DevelopmentRuntimeBundleError(
                    "runtime closure exceeds "
                    "maximum_total_regular_payload_bytes"
                )
        chunks: list[bytes] = []
        remaining = self.maximum_file_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after_fd = os.fstat(descriptor)
        if (
            len(payload) > self.maximum_file_bytes
            or len(payload) != before.st_size
            or _metadata_identity(after_fd) != _metadata_identity(before)
        ):
            raise DevelopmentRuntimeBundleError(
                f"runtime source changed while reading: {path}"
            )
        observed = _ObservedRegular(
            path=path,
            mode=mode,
            uid=before.st_uid,
            gid=before.st_gid,
            size=len(payload),
            sha256=sha256(payload).hexdigest(),
            payload=payload,
        )
        if previous is None:
            self._regulars[path] = observed
            self._total_regular_payload_bytes += observed.size
        elif previous != observed:
            raise DevelopmentRuntimeBundleError(
                f"runtime source observation is inconsistent: {path}"
            )
        return observed

    def _reserve_observed_entry(self, path: str) -> None:
        if path in self._symlinks or path in self._regulars:
            return
        if len(self._symlinks) + len(self._regulars) >= self.maximum_entries:
            raise DevelopmentRuntimeBundleError("ELF closure exceeds entry limit")

    def find_library(
        self,
        name: str,
        *,
        search_directories: tuple[str, ...],
    ) -> tuple[str, tuple[dict[str, object], ...]]:
        _validate_library_name(name)
        searches: list[dict[str, object]] = []
        for index, directory in enumerate(search_directories):
            self._lookup_candidate_count += 1
            if self._lookup_candidate_count > MAXIMUM_LIBRARY_LOOKUP_CANDIDATES:
                raise DevelopmentRuntimeBundleError(
                    "library resolution exceeds lookup-candidate limit"
                )
            pinned = self._search_directory_pins.get(directory)
            if pinned is None:
                raise DevelopmentRuntimeBundleError(
                    f"library search directory was not pinned: {directory}"
                )
            candidate = directory.rstrip("/") + "/" + name
            try:
                probe = os.open(
                    name,
                    os.O_PATH | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=pinned.descriptor,
                )
            except FileNotFoundError:
                self._negative_lookups.add((directory, name))
                searches.append(
                    {
                        "search_directory_index": index,
                        "directory": directory,
                        "candidate_path": candidate,
                        "outcome": "missing",
                    }
                )
                continue
            except OSError as exc:
                raise DevelopmentRuntimeBundleError(
                    f"cannot inspect DT_NEEDED candidate: {candidate}"
                ) from exc
            else:
                os.close(probe)
            searches.append(
                {
                    "search_directory_index": index,
                    "directory": directory,
                    "candidate_path": candidate,
                    "outcome": "selected",
                }
            )
            return candidate, tuple(searches)
        raise DevelopmentRuntimeBundleError(
            f"unresolved DT_NEEDED dependency: {name}"
        )

    def revalidate(self) -> None:
        self._revalidate_named_directories()
        for path, expected in self._symlinks.items():
            parent_path = str(PurePosixPath(path).parent)
            parent = self._directories.get(parent_path)
            if parent is None:
                raise DevelopmentRuntimeBundleError(
                    f"runtime symbolic-link parent was not pinned: {path}"
                )
            name = PurePosixPath(path).name
            try:
                current = os.stat(
                    name,
                    dir_fd=parent.descriptor,
                    follow_symlinks=False,
                )
                target = os.readlink(name, dir_fd=parent.descriptor)
                again = os.stat(
                    name,
                    dir_fd=parent.descriptor,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise DevelopmentRuntimeBundleError(
                    f"runtime symbolic link disappeared: {path}"
                ) from exc
            if (
                not stat.S_ISLNK(current.st_mode)
                or _metadata_identity(current) != _metadata_identity(again)
                or stat.S_IMODE(current.st_mode) != expected.mode
                or current.st_uid != expected.uid
                or current.st_gid != expected.gid
                or current.st_size != expected.size
                or target != expected.target
            ):
                raise DevelopmentRuntimeBundleError(
                    f"runtime symbolic link changed: {path}"
                )
        for directory, name in sorted(self._negative_lookups):
            pinned = self._search_directory_pins[directory]
            try:
                probe = os.open(
                    name,
                    os.O_PATH | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=pinned.descriptor,
                )
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise DevelopmentRuntimeBundleError(
                    "library negative lookup became inaccessible: "
                    f"{directory}/{name}"
                ) from exc
            else:
                os.close(probe)
            raise DevelopmentRuntimeBundleError(
                "library search precedence changed after a negative lookup: "
                f"{directory}/{name}"
            )
        for path, expected in tuple(self._regulars.items()):
            current = self.resolve_regular(path)[1]
            if current != expected:
                raise DevelopmentRuntimeBundleError(
                    f"runtime regular file changed: {path}"
                )
        # Re-establish that every pinned descriptor is still named by its
        # declared absolute path after symlink, lookup, and regular-file replay.
        self._revalidate_named_directories()

    def _revalidate_named_directories(self) -> None:
        for path, expected in tuple(self._directories.items()):
            descriptor: int | None = None
            try:
                descriptor = self._reopen_absolute_directory(path)
                current = os.fstat(descriptor)
            except OSError as exc:
                raise DevelopmentRuntimeBundleError(
                    f"runtime source directory disappeared: {path}"
                ) from exc
            finally:
                if descriptor is not None:
                    os.close(descriptor)
            if (
                not stat.S_ISDIR(current.st_mode)
                or _directory_identity(current) != expected.identity
            ):
                raise DevelopmentRuntimeBundleError(
                    f"runtime source directory changed: {path}"
                )

    def _reopen_absolute_directory(self, path: str) -> int:
        descriptor = os.open("/", self._directory_open_flags())
        if path == "/":
            return descriptor
        try:
            for component in PurePosixPath(path).parts[1:]:
                next_descriptor = os.open(
                    component,
                    self._directory_open_flags(),
                    dir_fd=descriptor,
                )
                os.close(descriptor)
                descriptor = next_descriptor
            return descriptor
        except Exception:
            os.close(descriptor)
            raise


def _writable_by_caller(metadata: os.stat_result) -> bool:
    mode = stat.S_IMODE(metadata.st_mode)
    uid = os.geteuid()
    groups = {os.getegid(), *os.getgroups()}
    if metadata.st_uid == uid and mode & stat.S_IWUSR:
        return True
    if metadata.st_gid in groups and mode & stat.S_IWGRP:
        return True
    return bool(mode & stat.S_IWOTH)


def _require_unambiguous_nonwritable_access(path: str, descriptor: int) -> None:
    """Reject ACL/file-capability ambiguity and effective write access.

    Mode bits alone do not describe POSIX ACL grants, and a privileged builder
    can have write access even when every write bit is clear.  Both situations
    invalidate the source-stability premise, so inspection fails closed.
    """

    try:
        attributes = os.listxattr(descriptor)
    except (AttributeError, OSError, TypeError) as exc:
        raise DevelopmentRuntimeBundleError(
            f"cannot establish runtime source access metadata: {path}"
        ) from exc
    if any(
        type(name) is not str
        or name in _WRITE_RELEVANT_XATTRS
        or name.startswith("system.posix_acl_")
        for name in attributes
    ):
        raise DevelopmentRuntimeBundleError(
            f"runtime source has ambiguous ACL or capability metadata: {path}"
        )
    descriptor_path = f"/proc/self/fd/{descriptor}"
    try:
        effectively_writable = os.access(
            descriptor_path,
            os.W_OK,
            effective_ids=True,
        )
    except (NotImplementedError, OSError, TypeError, ValueError) as exc:
        raise DevelopmentRuntimeBundleError(
            f"cannot establish effective runtime source access: {path}"
        ) from exc
    if effectively_writable:
        raise DevelopmentRuntimeBundleError(
            f"runtime source has effective write access for the builder: {path}"
        )


def _merge_chain(
    chain: tuple[_ObservedSymlink, ...],
    regular: _ObservedRegular,
    role: str,
    symlinks: dict[str, _ObservedSymlink],
    regulars: dict[str, _ObservedRegular],
    roles: dict[str, set[str]],
    *,
    maximum_entries: int,
) -> None:
    for link in chain:
        if (
            link.path not in symlinks
            and link.path not in regulars
            and len(symlinks) + len(regulars) >= maximum_entries
        ):
            raise DevelopmentRuntimeBundleError("ELF closure exceeds entry limit")
        existing = symlinks.setdefault(link.path, link)
        if existing != link or link.path in regulars:
            raise DevelopmentRuntimeBundleError(
                f"duplicate or conflicting runtime destination: {link.path}"
            )
        roles.setdefault(link.path, set()).add(role)
    if (
        regular.path not in symlinks
        and regular.path not in regulars
        and len(symlinks) + len(regulars) >= maximum_entries
    ):
        raise DevelopmentRuntimeBundleError("ELF closure exceeds entry limit")
    existing_regular = regulars.setdefault(regular.path, regular)
    if existing_regular != regular or regular.path in symlinks:
        raise DevelopmentRuntimeBundleError(
            f"duplicate or conflicting runtime destination: {regular.path}"
        )
    roles.setdefault(regular.path, set()).add(role)


def _validate_library_name(name: str) -> None:
    if (
        not isinstance(name, str)
        or not name
        or "/" in name
        or "\x00" in name
        or "\r" in name
        or "\n" in name
        or name in {".", ".."}
    ):
        raise DevelopmentRuntimeBundleError(f"unsupported DT_NEEDED name: {name!r}")


def _parse_elf(payload: bytes, *, path: str) -> _ElfMetadata:
    if len(payload) < 16 or payload[:4] != _ELF_MAGIC:
        raise DevelopmentRuntimeBundleError(f"runtime closure member is not ELF: {path}")
    elf_class_byte = payload[4]
    data_byte = payload[5]
    if (
        elf_class_byte not in (1, 2)
        or data_byte not in (1, 2)
        or payload[6] != 1
    ):
        raise DevelopmentRuntimeBundleError(f"unsupported ELF identity: {path}")
    elf_class = 32 if elf_class_byte == 1 else 64
    byte_order = "little" if data_byte == 1 else "big"
    endian = "<" if data_byte == 1 else ">"
    header_format = endian + ("HHIIIIIHHHHHH" if elf_class == 32 else "HHIQQQIHHHHHH")
    header_size = struct.calcsize(header_format)
    if len(payload) < 16 + header_size:
        raise DevelopmentRuntimeBundleError(f"truncated ELF header: {path}")
    header = struct.unpack_from(header_format, payload, 16)
    object_type = int(header[0])
    machine = int(header[1])
    object_version = int(header[2])
    program_offset = int(header[4])
    elf_header_size = int(header[7])
    program_entry_size = int(header[8])
    program_count = int(header[9])
    if (
        object_type not in (2, 3)
        or machine <= 0
        or object_version != 1
        or elf_header_size != 16 + header_size
    ):
        raise DevelopmentRuntimeBundleError(f"unsupported ELF object type: {path}")
    program_format = endian + ("IIIIIIII" if elf_class == 32 else "IIQQQQQQ")
    expected_program_size = struct.calcsize(program_format)
    if program_entry_size < expected_program_size or program_count > 65535:
        raise DevelopmentRuntimeBundleError(f"invalid ELF program table: {path}")
    _require_range(payload, program_offset, program_entry_size * program_count, path)
    loads: list[tuple[int, int, int, int]] = []
    dynamic: tuple[int, int] | None = None
    interpreter: str | None = None
    for index in range(program_count):
        offset = program_offset + index * program_entry_size
        fields = struct.unpack_from(program_format, payload, offset)
        if elf_class == 32:
            p_type, p_offset, p_vaddr, _p_paddr, p_filesz, _p_memsz, _flags, _align = fields
        else:
            p_type, _flags, p_offset, p_vaddr, _p_paddr, p_filesz, _p_memsz, _align = fields
        p_type = int(p_type)
        p_offset = int(p_offset)
        p_vaddr = int(p_vaddr)
        p_filesz = int(p_filesz)
        _require_range(payload, p_offset, p_filesz, path)
        if p_type == _PT_LOAD:
            loads.append((p_vaddr, p_offset, p_filesz, p_vaddr + p_filesz))
        elif p_type == _PT_DYNAMIC:
            if dynamic is not None:
                raise DevelopmentRuntimeBundleError(f"multiple PT_DYNAMIC segments: {path}")
            dynamic = (p_offset, p_filesz)
        elif p_type == _PT_INTERP:
            if interpreter is not None or p_filesz < 2:
                raise DevelopmentRuntimeBundleError(f"invalid PT_INTERP segment: {path}")
            raw = payload[p_offset : p_offset + p_filesz]
            if not raw.endswith(b"\x00") or b"\x00" in raw[:-1]:
                raise DevelopmentRuntimeBundleError(f"invalid PT_INTERP string: {path}")
            try:
                interpreter = raw[:-1].decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise DevelopmentRuntimeBundleError(
                    f"PT_INTERP path is not UTF-8: {path}"
                ) from exc
            _validate_absolute_path(interpreter, what="PT_INTERP path")

    if not loads:
        raise DevelopmentRuntimeBundleError(f"ELF has no PT_LOAD segment: {path}")

    needed_offsets: list[int] = []
    string_vaddr: int | None = None
    string_size: int | None = None
    if dynamic is not None:
        dynamic_offset, dynamic_size = dynamic
        dynamic_format = endian + ("iI" if elf_class == 32 else "qQ")
        dynamic_entry_size = struct.calcsize(dynamic_format)
        if dynamic_size % dynamic_entry_size != 0:
            raise DevelopmentRuntimeBundleError(f"misaligned PT_DYNAMIC segment: {path}")
        terminated = False
        for offset in range(
            dynamic_offset,
            dynamic_offset + dynamic_size,
            dynamic_entry_size,
        ):
            tag, value = struct.unpack_from(dynamic_format, payload, offset)
            tag = int(tag)
            value = int(value)
            if tag == _DT_NULL:
                terminated = True
                break
            if tag == _DT_NEEDED:
                needed_offsets.append(value)
                if len(needed_offsets) > MAXIMUM_LIBRARY_LOOKUP_CANDIDATES:
                    raise DevelopmentRuntimeBundleError(
                        f"ELF has too many DT_NEEDED entries: {path}"
                    )
            elif tag == _DT_STRTAB:
                if string_vaddr is not None and string_vaddr != value:
                    raise DevelopmentRuntimeBundleError(f"multiple DT_STRTAB values: {path}")
                string_vaddr = value
            elif tag == _DT_STRSZ:
                if string_size is not None and string_size != value:
                    raise DevelopmentRuntimeBundleError(f"multiple DT_STRSZ values: {path}")
                string_size = value
            elif tag in (_DT_RPATH, _DT_RUNPATH):
                raise DevelopmentRuntimeBundleError(
                    f"ELF RPATH/RUNPATH is unsupported by pinned resolver: {path}"
                )
        if not terminated:
            raise DevelopmentRuntimeBundleError(f"unterminated PT_DYNAMIC segment: {path}")

    needed: list[str] = []
    if needed_offsets:
        if string_vaddr is None or string_size is None or string_size <= 0:
            raise DevelopmentRuntimeBundleError(f"DT_NEEDED lacks string table: {path}")
        string_offset = _virtual_to_file_offset(
            string_vaddr,
            string_size,
            loads=loads,
            path=path,
        )
        string_table = payload[string_offset : string_offset + string_size]
        for offset in needed_offsets:
            if offset < 0 or offset >= len(string_table):
                raise DevelopmentRuntimeBundleError(f"DT_NEEDED offset is invalid: {path}")
            end = string_table.find(b"\x00", offset)
            if end < 0:
                raise DevelopmentRuntimeBundleError(f"unterminated DT_NEEDED string: {path}")
            try:
                name = string_table[offset:end].decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise DevelopmentRuntimeBundleError(
                    f"DT_NEEDED name is not UTF-8: {path}"
                ) from exc
            if not name or "/" in name:
                raise DevelopmentRuntimeBundleError(f"unsupported DT_NEEDED name: {name!r}")
            needed.append(name)
    return _ElfMetadata(
        elf_class=elf_class,
        byte_order=byte_order,
        machine=machine,
        object_type=object_type,
        pt_interp=interpreter,
        dt_needed=tuple(needed),
    )


def _require_range(payload: bytes, offset: int, size: int, path: str) -> None:
    if offset < 0 or size < 0 or offset > len(payload) or size > len(payload) - offset:
        raise DevelopmentRuntimeBundleError(f"ELF range is outside file: {path}")


def _virtual_to_file_offset(
    address: int,
    size: int,
    *,
    loads: list[tuple[int, int, int, int]],
    path: str,
) -> int:
    candidates: list[int] = []
    for virtual, file_offset, file_size, virtual_end in loads:
        if virtual <= address and address <= virtual_end:
            delta = address - virtual
            if delta <= file_size and size <= file_size - delta:
                candidates.append(file_offset + delta)
    if len(candidates) != 1:
        raise DevelopmentRuntimeBundleError(
            f"DT_STRTAB does not map uniquely into PT_LOAD: {path}"
        )
    return candidates[0]


def _validate_declared_entries(
    value: object,
    *,
    maximum_entries: int,
) -> None:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > maximum_entries
    ):
        raise DevelopmentRuntimeBundleError("entries must be a nonempty array")
    destinations: list[str] = []
    previous: bytes | None = None
    for entry in value:
        if not isinstance(entry, Mapping):
            raise DevelopmentRuntimeBundleError("runtime entry must be an object")
        kind = entry.get("kind")
        common = {
            "source_path",
            "destination_path",
            "kind",
            "mode",
            "uid",
            "gid",
            "size",
            "roles",
        }
        expected = common | ({"target"} if kind == "symlink" else {"sha256", "elf"})
        if kind not in {"regular", "symlink"} or set(entry) != expected:
            raise DevelopmentRuntimeBundleError("runtime entry shape is invalid")
        source = entry.get("source_path")
        destination = entry.get("destination_path")
        _validate_absolute_path(source, what="entry source_path")
        _validate_absolute_path(destination, what="entry destination_path")
        if source != destination:
            raise DevelopmentRuntimeBundleError("source and destination paths must match")
        destinations.append(destination)  # type: ignore[arg-type]
        encoded = destination.encode("utf-8")  # type: ignore[union-attr]
        if previous is not None and encoded <= previous:
            raise DevelopmentRuntimeBundleError("runtime entries are not uniquely sorted")
        previous = encoded
        for field in ("mode", "uid", "gid", "size"):
            item = entry.get(field)
            if isinstance(item, bool) or not isinstance(item, int) or item < 0:
                raise DevelopmentRuntimeBundleError(f"runtime entry {field} is invalid")
        roles = entry.get("roles")
        if (
            not isinstance(roles, list)
            or not roles
            or any(
                role
                not in {
                    "explicit_executable",
                    "elf_interpreter",
                    "shared_library",
                }
                for role in roles
            )
            or roles != sorted(set(roles))
        ):
            raise DevelopmentRuntimeBundleError("runtime entry roles are invalid")
        if kind == "regular":
            digest = entry.get("sha256")
            if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
                raise DevelopmentRuntimeBundleError("regular entry digest is invalid")
            _validate_declared_elf(entry.get("elf"))
        else:
            target = entry.get("target")
            if (
                not isinstance(target, str)
                or not target
                or any(character in target for character in ("\x00", "\r", "\n"))
            ):
                raise DevelopmentRuntimeBundleError("symlink target is invalid")
    if len(destinations) != len(set(destinations)):
        raise DevelopmentRuntimeBundleError("runtime destinations are duplicated")


def _validate_declared_elf(value: object) -> None:
    if not isinstance(value, Mapping) or set(value) != {
        "class_bits",
        "byte_order",
        "machine",
        "object_type",
        "pt_interp",
        "dt_needed",
    }:
        raise DevelopmentRuntimeBundleError("ELF metadata shape is invalid")
    if value.get("class_bits") not in {32, 64} or value.get("byte_order") not in {
        "little",
        "big",
    }:
        raise DevelopmentRuntimeBundleError("ELF identity metadata is invalid")
    for field in ("machine", "object_type"):
        item = value.get(field)
        if isinstance(item, bool) or not isinstance(item, int) or item <= 0:
            raise DevelopmentRuntimeBundleError("ELF numeric metadata is invalid")
    interpreter = value.get("pt_interp")
    if interpreter is not None:
        _validate_absolute_path(interpreter, what="ELF pt_interp")
    needed = value.get("dt_needed")
    if (
        not isinstance(needed, list)
        or len(needed) > MAXIMUM_LIBRARY_LOOKUP_CANDIDATES
        or any(not isinstance(item, str) or not item or "/" in item for item in needed)
    ):
        raise DevelopmentRuntimeBundleError("ELF dt_needed metadata is invalid")


def _validate_declared_closure(
    value: object,
    entries: object,
    *,
    maximum_total_regular_payload_bytes: int,
) -> None:
    if not isinstance(value, Mapping) or set(value) != {
        "algorithm",
        "elf_pt_interp_dt_needed_verified",
        "runtime_data_and_dlopen_closure_verified",
        "entry_count",
        "regular_file_count",
        "symlink_count",
        "regular_payload_bytes",
    }:
        raise DevelopmentRuntimeBundleError("closure record shape is invalid")
    if (
        value.get("algorithm") != ELF_CLOSURE_ALGORITHM
        or value.get("elf_pt_interp_dt_needed_verified") is not True
        or value.get("runtime_data_and_dlopen_closure_verified") is not False
        or not isinstance(entries, list)
    ):
        raise DevelopmentRuntimeBundleError("closure declaration is invalid")
    regular = sum(
        1 for entry in entries if isinstance(entry, Mapping) and entry.get("kind") == "regular"
    )
    symbolic = sum(
        1 for entry in entries if isinstance(entry, Mapping) and entry.get("kind") == "symlink"
    )
    counts = {
        "entry_count": len(entries),
        "regular_file_count": regular,
        "symlink_count": symbolic,
        "regular_payload_bytes": sum(
            int(entry["size"])
            for entry in entries
            if isinstance(entry, Mapping) and entry.get("kind") == "regular"
        ),
    }
    for name, expected in counts.items():
        if value.get(name) != expected:
            raise DevelopmentRuntimeBundleError("closure counts are invalid")
    if counts["regular_payload_bytes"] > maximum_total_regular_payload_bytes:
        raise DevelopmentRuntimeBundleError(
            "closure regular payload exceeds declared aggregate limit"
        )


def _validate_declared_library_resolution(
    value: object,
    *,
    search_directories: tuple[str, ...],
    entries: object,
) -> None:
    if not isinstance(value, Mapping) or set(value) != {
        "algorithm",
        "search_precedence_and_negative_lookups_verified",
        "resolution_count",
        "negative_lookup_count",
        "lookup_candidate_count",
        "resolutions",
    }:
        raise DevelopmentRuntimeBundleError(
            "library_resolution record shape is invalid"
        )
    resolutions = value.get("resolutions")
    if (
        value.get("algorithm") != LIBRARY_RESOLUTION_ALGORITHM
        or value.get("search_precedence_and_negative_lookups_verified") is not True
        or not isinstance(resolutions, list)
    ):
        raise DevelopmentRuntimeBundleError(
            "library_resolution declaration is invalid"
        )
    if not isinstance(entries, list):
        raise DevelopmentRuntimeBundleError("library_resolution entries are invalid")
    entry_paths = {
        entry.get("destination_path")
        for entry in entries
        if isinstance(entry, Mapping)
    }
    symbolic_entry_paths = {
        entry.get("destination_path")
        for entry in entries
        if isinstance(entry, Mapping) and entry.get("kind") == "symlink"
    }
    previous: tuple[bytes, int] | None = None
    negative_count = 0
    candidate_count = 0
    for resolution in resolutions:
        if not isinstance(resolution, Mapping) or set(resolution) != {
            "requester_path",
            "needed_index",
            "needed_name",
            "searches",
            "selected_source_path",
            "selected_resolved_path",
        }:
            raise DevelopmentRuntimeBundleError(
                "library resolution entry shape is invalid"
            )
        requester = resolution.get("requester_path")
        selected_source = resolution.get("selected_source_path")
        selected_resolved = resolution.get("selected_resolved_path")
        _validate_absolute_path(requester, what="library requester_path")
        _validate_absolute_path(
            selected_source,
            what="selected library source_path",
        )
        _validate_absolute_path(
            selected_resolved,
            what="selected library resolved_path",
        )
        if (
            requester not in entry_paths
            or selected_resolved not in entry_paths
            or not (
                selected_source in entry_paths
                or any(
                    isinstance(symbolic, str)
                    and isinstance(selected_source, str)
                    and selected_source.startswith(symbolic + "/")
                    for symbolic in symbolic_entry_paths
                )
            )
        ):
            raise DevelopmentRuntimeBundleError(
                "library resolution paths do not bind to runtime entries"
            )
        needed_index = resolution.get("needed_index")
        if (
            isinstance(needed_index, bool)
            or not isinstance(needed_index, int)
            or needed_index < 0
        ):
            raise DevelopmentRuntimeBundleError(
                "library resolution needed_index is invalid"
            )
        needed_name = resolution.get("needed_name")
        _validate_library_name(needed_name)  # type: ignore[arg-type]
        order_key = (requester.encode("utf-8"), needed_index)  # type: ignore[union-attr]
        if previous is not None and order_key <= previous:
            raise DevelopmentRuntimeBundleError(
                "library resolutions are not uniquely sorted"
            )
        previous = order_key
        searches = resolution.get("searches")
        if not isinstance(searches, list) or not searches:
            raise DevelopmentRuntimeBundleError(
                "library resolution searches are invalid"
            )
        if len(searches) > len(search_directories):
            raise DevelopmentRuntimeBundleError(
                "library resolution searches exceed declared precedence"
            )
        for index, search in enumerate(searches):
            if candidate_count >= MAXIMUM_LIBRARY_LOOKUP_CANDIDATES:
                raise DevelopmentRuntimeBundleError(
                    "library resolution exceeds lookup-candidate limit"
                )
            if not isinstance(search, Mapping) or set(search) != {
                "search_directory_index",
                "directory",
                "candidate_path",
                "outcome",
            }:
                raise DevelopmentRuntimeBundleError(
                    "library search observation shape is invalid"
                )
            directory = search_directories[index]
            expected_candidate = (
                directory.rstrip("/") + "/" + needed_name  # type: ignore[operator]
            )
            expected_outcome = "selected" if index == len(searches) - 1 else "missing"
            if (
                search.get("search_directory_index") != index
                or search.get("directory") != directory
                or search.get("candidate_path") != expected_candidate
                or search.get("outcome") != expected_outcome
            ):
                raise DevelopmentRuntimeBundleError(
                    "library search precedence observation is invalid"
                )
            candidate_count += 1
            if expected_outcome == "missing":
                negative_count += 1
        if searches[-1].get("candidate_path") != selected_source:
            raise DevelopmentRuntimeBundleError(
                "selected library does not match final search observation"
            )
    counts = {
        "resolution_count": len(resolutions),
        "negative_lookup_count": negative_count,
        "lookup_candidate_count": candidate_count,
    }
    for name, expected in counts.items():
        if value.get(name) != expected:
            raise DevelopmentRuntimeBundleError(
                "library_resolution counts are invalid"
            )


__all__ = [
    "DEFAULT_MAXIMUM_FILE_BYTES",
    "DEFAULT_MAXIMUM_TOTAL_REGULAR_PAYLOAD_BYTES",
    "DEVELOPMENT_RUNTIME_BUNDLE_KIND",
    "DEVELOPMENT_RUNTIME_BUNDLE_SCHEMA_VERSION",
    "DEVELOPMENT_RUNTIME_BUNDLE_VERSION",
    "ELF_CLOSURE_ALGORITHM",
    "LIBRARY_RESOLUTION_ALGORITHM",
    "MAXIMUM_ALLOWED_SOURCE_ROOTS",
    "MAXIMUM_LIBRARY_LOOKUP_CANDIDATES",
    "MAXIMUM_LIBRARY_SEARCH_DIRECTORIES",
    "MAXIMUM_MANIFEST_ENTRIES",
    "MAXIMUM_PINNED_DIRECTORIES",
    "DevelopmentRuntimeBundleError",
    "DevelopmentRuntimeExecutable",
    "build_development_runtime_bundle_manifest",
    "canonical_development_runtime_json_bytes",
    "compute_development_runtime_bundle_sha256",
    "validate_development_runtime_bundle_manifest",
    "verify_development_runtime_bundle_manifest",
    "verify_development_runtime_bundle_sha256",
]
