"""Fail-closed verification for generated benchmark artifact directories.

The preparation manifest is content-addressed, but a hash stored beside the
content it protects is not an authenticity mechanism.  This module therefore
checks three complementary properties:

* exact manifest, sidecar, file-size, file-hash, and record-count consistency;
* equivalence to the versioned deterministic generator declared by the
  manifest; and
* optional caller-provided manifest or dataset digests as external trust
  anchors.

Successful summaries contain only aggregate metadata and digests.  Benchmark
records, prompts, fixture seeds, and other sealed content are never returned.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
import errno
from hashlib import sha256
from itertools import zip_longest
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any, Final, cast

from .benchmark import (
    BENCHMARK_GENERATOR_VERSION,
    BENCHMARK_SCHEMA_VERSION,
    DETERMINISTIC_SAMPLER,
    SPLIT_NAMES,
    SUITE_NAMES,
    BenchmarkConfig,
    BenchmarkValidationError,
    SemanticSpec,
    canonical_json,
    generate_benchmark,
    validate_specs,
)


_MANIFEST_NAME: Final[str] = "manifest.json"
_SIDECAR_NAME: Final[str] = "manifest.sha256"
_HASH_SCOPE: Final[str] = "canonical_json_excluding_dataset_hash_fields"
_SHA256_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
_MANIFEST_KEYS: Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "generator",
        "config",
        "total_records",
        "files",
        "dataset_hash_scope",
        "dataset_sha256",
    }
)
_GENERATOR_KEYS: Final[frozenset[str]] = frozenset(
    {"name", "version", "deterministic_sampler"}
)
_FILE_KEYS: Final[frozenset[str]] = frozenset(
    {"path", "records", "bytes", "sha256", "suite", "split"}
)
_CONFIG_KEYS: Final[frozenset[str]] = frozenset(
    {"seed", "fixture_count", "family_size", "static", "interactive"}
)
_SPLIT_KEYS: Final[frozenset[str]] = frozenset(SPLIT_NAMES)
_DEFAULT_MAX_MANIFEST_BYTES: Final[int] = 1024 * 1024
_DEFAULT_MAX_INVENTORY_ENTRIES: Final[int] = 100_000
_DEFAULT_MAX_TOTAL_RECORDS: Final[int] = 100_000
_DEFAULT_MAX_TOTAL_JSONL_BYTES: Final[int] = 256 * 1024 * 1024
_DEFAULT_MAX_TOTAL_FIXTURES: Final[int] = 1_000_000


class BenchmarkArtifactValidationError(ValueError):
    """Raised when any artifact invariant fails.

    ``issues`` is stable machine-readable detail for callers that need to log
    individual findings.  It intentionally contains no benchmark prompts or
    record payloads.
    """

    def __init__(self, issues: str | Iterable[str]) -> None:
        if isinstance(issues, str):
            normalized = (issues,)
        else:
            normalized = tuple(str(issue) for issue in issues)
        if not normalized:
            normalized = ("benchmark artifact validation failed",)
        self.issues = normalized
        super().__init__(
            "benchmark artifact validation failed:\n- "
            + "\n- ".join(normalized)
        )


@dataclass(frozen=True, slots=True)
class _FileDeclaration:
    path: str
    suite: str
    split: str
    records: int
    bytes: int
    sha256: str


@dataclass(frozen=True, slots=True)
class _ArtifactRoot:
    path: Path
    descriptor: int
    snapshot: tuple[int, int, int, int, int, int, int]
    manifest_snapshot: tuple[int, int, int, int, int, int, int] | None


def _snapshot(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _descriptor_flags(*, directory: bool = False) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:  # pragma: no cover - Linux evaluation requirement
        raise BenchmarkArtifactValidationError(
            "platform does not support no-follow artifact opens"
        )
    flags = os.O_RDONLY | os.O_CLOEXEC | nofollow
    if directory:
        directory_flag = getattr(os, "O_DIRECTORY", None)
        if directory_flag is None:  # pragma: no cover - Linux requirement
            raise BenchmarkArtifactValidationError(
                "platform does not support directory-descriptor artifact opens"
            )
        flags |= directory_flag
    else:
        flags |= getattr(os, "O_NONBLOCK", 0)
    return flags


@contextmanager
def _open_artifact_root(source: str | os.PathLike[str]) -> Iterable[_ArtifactRoot]:
    path = Path(source)
    try:
        source_metadata = path.lstat()
    except OSError as error:
        raise BenchmarkArtifactValidationError(
            f"cannot inspect benchmark artifact source: {type(error).__name__}"
        ) from error
    if stat.S_ISLNK(source_metadata.st_mode):
        raise BenchmarkArtifactValidationError(
            "benchmark artifact source must not be a symlink"
        )
    manifest_snapshot = None
    if stat.S_ISDIR(source_metadata.st_mode):
        root_path = path
        root_metadata = source_metadata
    elif stat.S_ISREG(source_metadata.st_mode) and path.name == _MANIFEST_NAME:
        manifest_snapshot = _snapshot(source_metadata)
        root_path = path.parent
        try:
            root_metadata = root_path.lstat()
        except OSError as error:
            raise BenchmarkArtifactValidationError(
                f"cannot inspect benchmark artifact root: {type(error).__name__}"
            ) from error
        if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
            raise BenchmarkArtifactValidationError(
                "artifact root must be a real directory, not a symlink"
            )
    else:
        raise BenchmarkArtifactValidationError(
            "benchmark artifact source must be a directory or manifest.json"
        )

    try:
        descriptor = os.open(root_path, _descriptor_flags(directory=True))
    except OSError as error:
        raise BenchmarkArtifactValidationError(
            f"cannot open benchmark artifact root: {type(error).__name__}"
        ) from error
    try:
        opened_metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened_metadata.st_mode)
            or _snapshot(opened_metadata) != _snapshot(root_metadata)
        ):
            raise BenchmarkArtifactValidationError(
                "benchmark artifact root changed before validation"
            )
        yield _ArtifactRoot(
            root_path,
            descriptor,
            _snapshot(opened_metadata),
            manifest_snapshot,
        )
    finally:
        os.close(descriptor)


def _safe_parts(relative_path: str) -> tuple[str, ...]:
    safe = _safe_relative_artifact_path(relative_path)
    if safe is None:
        raise BenchmarkArtifactValidationError(
            "artifact path is not a canonical safe relative path"
        )
    return PurePosixPath(safe).parts


def _open_relative_regular_fd(
    root_descriptor: int,
    relative_path: str,
    *,
    label: str,
) -> tuple[int, int]:
    """Open a regular member without following any path component.

    Returns the file descriptor and its containing-directory descriptor.  The
    caller owns both descriptors.  Keeping the parent open permits a final
    name-to-inode check after the read.
    """

    current = os.dup(root_descriptor)
    try:
        parts = _safe_parts(relative_path)
        for part in parts[:-1]:
            try:
                child = os.open(
                    part,
                    _descriptor_flags(directory=True),
                    dir_fd=current,
                )
            except OSError as error:
                raise BenchmarkArtifactValidationError(
                    f"cannot open directory component for {label}: "
                    f"{type(error).__name__}"
                ) from error
            os.close(current)
            current = child
        try:
            descriptor = os.open(
                parts[-1],
                _descriptor_flags(),
                dir_fd=current,
            )
        except OSError as error:
            if error.errno == errno.ELOOP:
                raise BenchmarkArtifactValidationError(
                    f"{label} must not be a symlink"
                ) from error
            raise BenchmarkArtifactValidationError(
                f"cannot open {label}: {type(error).__name__}"
            ) from error
        return descriptor, current
    except BaseException:
        os.close(current)
        raise


def _read_relative_regular(
    root_descriptor: int,
    relative_path: str,
    *,
    label: str,
    maximum_bytes: int | None = None,
    expected_snapshot: tuple[int, int, int, int, int, int, int] | None = None,
) -> tuple[bytes, tuple[int, int, int, int, int, int, int]]:
    descriptor, parent_descriptor = _open_relative_regular_fd(
        root_descriptor, relative_path, label=label
    )
    try:
        before = os.fstat(descriptor)
        before_snapshot = _snapshot(before)
        if not stat.S_ISREG(before.st_mode):
            raise BenchmarkArtifactValidationError(f"{label} must be a regular file")
        if expected_snapshot is not None and before_snapshot != expected_snapshot:
            raise BenchmarkArtifactValidationError(f"{label} changed before validation")
        if maximum_bytes is not None and before.st_size > maximum_bytes:
            raise BenchmarkArtifactValidationError(
                f"{label} exceeds the {maximum_bytes}-byte validation limit"
            )
        payload = bytearray()
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise BenchmarkArtifactValidationError(
                    f"{label} ended before its snapshotted size"
                )
            payload.extend(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise BenchmarkArtifactValidationError(
                f"{label} grew beyond its snapshotted size"
            )
        after = os.fstat(descriptor)
        try:
            named = os.stat(
                PurePosixPath(relative_path).name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            raise BenchmarkArtifactValidationError(
                f"{label} changed during validation: {type(error).__name__}"
            ) from error
        if _snapshot(after) != before_snapshot or _snapshot(named) != before_snapshot:
            raise BenchmarkArtifactValidationError(
                f"{label} changed during validation"
            )
        return bytes(payload), before_snapshot
    finally:
        os.close(descriptor)
        os.close(parent_descriptor)


def _stat_relative_regular(
    root_descriptor: int,
    relative_path: str,
    *,
    label: str,
) -> tuple[int, int, int, int, int, int, int]:
    descriptor, parent_descriptor = _open_relative_regular_fd(
        root_descriptor, relative_path, label=label
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise BenchmarkArtifactValidationError(f"{label} must be regular")
        return _snapshot(metadata)
    finally:
        os.close(descriptor)
        os.close(parent_descriptor)


def compute_manifest_sidecar(manifest_bytes: bytes) -> bytes:
    """Return the exact GNU-style SHA-256 sidecar for ``manifest.json``."""

    if not isinstance(manifest_bytes, bytes):
        raise TypeError("manifest_bytes must be bytes")
    digest = sha256(manifest_bytes).hexdigest()
    return f"{digest}  {_MANIFEST_NAME}\n".encode("ascii")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BenchmarkArtifactValidationError(
                f"{_MANIFEST_NAME}: duplicate object key {key!r}"
            )
        result[key] = value
    return result


def _reject_non_json_number(value: str) -> None:
    raise BenchmarkArtifactValidationError(
        f"{_MANIFEST_NAME}: non-finite JSON number {value!r} is forbidden"
    )


def _load_manifest_bytes(
    root: _ArtifactRoot, *, maximum_bytes: int
) -> tuple[bytes, dict[str, object], tuple[int, int, int, int, int, int, int]]:
    payload, snapshot = _read_relative_regular(
        root.descriptor,
        _MANIFEST_NAME,
        label=_MANIFEST_NAME,
        maximum_bytes=maximum_bytes,
        expected_snapshot=root.manifest_snapshot,
    )
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise BenchmarkArtifactValidationError(
            f"{_MANIFEST_NAME} is not valid UTF-8"
        ) from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_json_number,
        )
    except BenchmarkArtifactValidationError:
        raise
    except json.JSONDecodeError as error:
        raise BenchmarkArtifactValidationError(
            f"invalid JSON in {_MANIFEST_NAME}: line {error.lineno}, "
            f"column {error.colno}: {error.msg}"
        ) from error
    except (ValueError, RecursionError) as error:
        raise BenchmarkArtifactValidationError(
            f"invalid JSON value in {_MANIFEST_NAME}: {error}"
        ) from error
    if not isinstance(value, dict):
        raise BenchmarkArtifactValidationError(
            f"{_MANIFEST_NAME} must contain one JSON object"
        )
    return payload, cast(dict[str, object], value), snapshot


def load_benchmark_manifest(
    source: str | os.PathLike[str],
    *,
    max_manifest_bytes: int = _DEFAULT_MAX_MANIFEST_BYTES,
) -> dict[str, object]:
    """Strictly load ``manifest.json`` from an artifact directory or path.

    This function rejects duplicate keys, non-finite numbers, symlinks, and
    oversized manifests.  Use :func:`validate_benchmark_artifacts` to validate
    the manifest semantics and the full directory.
    """

    if (
        isinstance(max_manifest_bytes, bool)
        or not isinstance(max_manifest_bytes, int)
        or max_manifest_bytes <= 0
    ):
        raise ValueError("max_manifest_bytes must be a positive integer")
    with _open_artifact_root(source) as root:
        _, manifest, _ = _load_manifest_bytes(
            root, maximum_bytes=max_manifest_bytes
        )
        return manifest


def _exact_keys(
    value: Mapping[str, object], expected: frozenset[str], label: str, issues: list[str]
) -> None:
    missing = expected.difference(value)
    extra = set(value).difference(expected)
    if missing:
        issues.append(f"{label} is missing keys {sorted(missing)!r}")
    if extra:
        issues.append(f"{label} has unknown keys {sorted(extra)!r}")


def _is_nonnegative_integer(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value >= 0


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256_PATTERN.fullmatch(value) is not None


def _expected_relative_path(suite: str, split: str) -> str:
    return f"{suite}/{split}.jsonl"


def _safe_relative_artifact_path(value: object) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    if "\\" in value or "\x00" in value:
        return None
    parsed = PurePosixPath(value)
    if parsed.is_absolute() or parsed.as_posix() != value:
        return None
    if any(part in {"", ".", ".."} for part in parsed.parts):
        return None
    return value


def _parse_manifest(
    manifest: Mapping[str, object],
) -> tuple[BenchmarkConfig, tuple[_FileDeclaration, ...], list[str]]:
    issues: list[str] = []
    _exact_keys(manifest, _MANIFEST_KEYS, "manifest", issues)

    if manifest.get("schema_version") != BENCHMARK_SCHEMA_VERSION:
        issues.append(
            "unsupported schema_version; expected "
            f"{BENCHMARK_SCHEMA_VERSION!r}"
        )
    if manifest.get("dataset_hash_scope") != _HASH_SCOPE:
        issues.append(f"dataset_hash_scope must equal {_HASH_SCOPE!r}")
    if not _is_sha256(manifest.get("dataset_sha256")):
        issues.append("dataset_sha256 must be a lowercase SHA-256 digest")

    generator = manifest.get("generator")
    if not isinstance(generator, Mapping):
        issues.append("generator must be an object")
    else:
        _exact_keys(generator, _GENERATOR_KEYS, "generator", issues)
        expected_generator = {
            "name": "cbds.benchmark",
            "version": BENCHMARK_GENERATOR_VERSION,
            "deterministic_sampler": DETERMINISTIC_SAMPLER,
        }
        for key, expected in expected_generator.items():
            if generator.get(key) != expected:
                issues.append(f"generator.{key} must equal {expected!r}")

    config_value = manifest.get("config")
    config: BenchmarkConfig | None = None
    if not isinstance(config_value, Mapping):
        issues.append("config must be an object")
    else:
        _exact_keys(config_value, _CONFIG_KEYS, "config", issues)
        for suite in SUITE_NAMES:
            split_counts = config_value.get(suite)
            if isinstance(split_counts, Mapping):
                _exact_keys(
                    split_counts,
                    _SPLIT_KEYS,
                    f"config.{suite}",
                    issues,
                )
        try:
            config = BenchmarkConfig.from_mapping(
                cast(Mapping[str, object], config_value)
            )
        except (TypeError, ValueError) as error:
            issues.append(f"invalid benchmark config: {error}")

    total_records = manifest.get("total_records")
    if not _is_nonnegative_integer(total_records):
        issues.append("total_records must be a non-negative integer")

    declarations: list[_FileDeclaration] = []
    files = manifest.get("files")
    if not isinstance(files, list):
        issues.append("files must be an array")
        files = []
    for index, raw in enumerate(files):
        label = f"files[{index}]"
        if not isinstance(raw, Mapping):
            issues.append(f"{label} must be an object")
            continue
        _exact_keys(raw, _FILE_KEYS, label, issues)
        path = _safe_relative_artifact_path(raw.get("path"))
        suite = raw.get("suite")
        split = raw.get("split")
        records = raw.get("records")
        byte_count = raw.get("bytes")
        digest = raw.get("sha256")
        valid = True
        if path is None:
            issues.append(f"{label}.path must be a canonical safe relative path")
            valid = False
        if suite not in SUITE_NAMES:
            issues.append(f"{label}.suite is unknown")
            valid = False
        if split not in SPLIT_NAMES:
            issues.append(f"{label}.split is unknown")
            valid = False
        if not _is_nonnegative_integer(records):
            issues.append(f"{label}.records must be a non-negative integer")
            valid = False
        if not _is_nonnegative_integer(byte_count):
            issues.append(f"{label}.bytes must be a non-negative integer")
            valid = False
        if not _is_sha256(digest):
            issues.append(f"{label}.sha256 must be a lowercase SHA-256 digest")
            valid = False
        if valid:
            assert path is not None
            assert isinstance(suite, str)
            assert isinstance(split, str)
            assert isinstance(records, int)
            assert isinstance(byte_count, int)
            assert isinstance(digest, str)
            expected_path = _expected_relative_path(suite, split)
            if path != expected_path:
                issues.append(
                    f"{label}.path must equal {expected_path!r} for its suite/split"
                )
            declarations.append(
                _FileDeclaration(
                    path=path,
                    suite=suite,
                    split=split,
                    records=records,
                    bytes=byte_count,
                    sha256=digest,
                )
            )

    paths = [declaration.path for declaration in declarations]
    pairs = [(declaration.suite, declaration.split) for declaration in declarations]
    duplicate_paths = sorted(
        path for path, count in Counter(paths).items() if count > 1
    )
    duplicate_pairs = sorted(
        pair for pair, count in Counter(pairs).items() if count > 1
    )
    if duplicate_paths:
        issues.append(f"duplicate declared file paths {duplicate_paths!r}")
    if duplicate_pairs:
        issues.append(f"duplicate suite/split declarations {duplicate_pairs!r}")
    expected_pairs = {
        (suite, split) for suite in SUITE_NAMES for split in SPLIT_NAMES
    }
    actual_pairs = set(pairs)
    if actual_pairs != expected_pairs:
        missing = sorted(expected_pairs.difference(actual_pairs))
        extra = sorted(actual_pairs.difference(expected_pairs))
        if missing:
            issues.append(f"manifest is missing suite/split declarations {missing!r}")
        if extra:
            issues.append(f"manifest has unexpected suite/split declarations {extra!r}")

    if config is not None:
        expected_counts = {
            (suite, split): getattr(getattr(config, suite), split)
            for suite in SUITE_NAMES
            for split in SPLIT_NAMES
        }
        for declaration in declarations:
            expected = expected_counts[(declaration.suite, declaration.split)]
            if declaration.records != expected:
                issues.append(
                    f"declared record count for {declaration.suite}/"
                    f"{declaration.split} must equal config count {expected}"
                )
        expected_total = sum(expected_counts.values())
        if total_records != expected_total:
            issues.append(
                f"total_records must equal config total {expected_total}"
            )
    if _is_nonnegative_integer(total_records):
        declared_total = sum(declaration.records for declaration in declarations)
        if total_records != declared_total:
            issues.append(
                f"total_records does not equal declared file total {declared_total}"
            )

    if config is None:
        # The caller cannot safely inspect file declarations without a valid
        # config, so use a placeholder only to satisfy the return type.  The
        # accumulated issue is raised before this value can be used.
        config = BenchmarkConfig()
    return config, tuple(declarations), issues


def _inventory_directory(
    root_descriptor: int, *, maximum_entries: int
) -> tuple[set[str], set[str], list[str]]:
    files: set[str] = set()
    directories: set[str] = set()
    issues: list[str] = []
    seen = 0
    stack: list[tuple[int, PurePosixPath]] = [
        (os.dup(root_descriptor), PurePosixPath("."))
    ]
    while stack:
        directory_descriptor, relative_directory = stack.pop()
        entries: list[str] = []
        try:
            with os.scandir(directory_descriptor) as iterator:
                for entry in iterator:
                    seen += 1
                    if seen > maximum_entries:
                        issues.append(
                            f"artifact inventory exceeds {maximum_entries} entries"
                        )
                        os.close(directory_descriptor)
                        for pending_descriptor, _ in stack:
                            os.close(pending_descriptor)
                        return files, directories, issues
                    entries.append(entry.name)
        except OSError as error:
            issues.append(
                "cannot inventory artifact directory: "
                f"{type(error).__name__}"
            )
            os.close(directory_descriptor)
            continue
        entries.sort(key=os.fsencode)
        child_directories: list[tuple[int, PurePosixPath]] = []
        for name in entries:
            relative = (
                PurePosixPath(name)
                if relative_directory == PurePosixPath(".")
                else relative_directory / name
            )
            rendered = relative.as_posix()
            try:
                metadata = os.stat(
                    name,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
                if stat.S_ISLNK(metadata.st_mode):
                    issues.append(f"artifact path {rendered!r} must not be a symlink")
                elif stat.S_ISDIR(metadata.st_mode):
                    directories.add(rendered)
                    child = os.open(
                        name,
                        _descriptor_flags(directory=True),
                        dir_fd=directory_descriptor,
                    )
                    if _snapshot(os.fstat(child)) != _snapshot(metadata):
                        os.close(child)
                        issues.append(
                            f"artifact path {rendered!r} changed during inventory"
                        )
                    else:
                        child_directories.append((child, relative))
                elif stat.S_ISREG(metadata.st_mode):
                    files.add(rendered)
                else:
                    issues.append(
                        f"artifact path {rendered!r} must be a regular file or directory"
                    )
            except OSError as error:
                issues.append(
                    f"cannot inspect artifact path {rendered!r}: "
                    f"{type(error).__name__}"
                )
        os.close(directory_descriptor)
        stack.extend(reversed(child_directories))
    return files, directories, issues


def _canonical_jsonl_issue(
    payload: bytes, specs: Sequence[SemanticSpec], relative_path: str
) -> str | None:
    """Return one payload-free canonicalization finding, if any."""

    sentinel = object()
    disk_lines = payload.splitlines(keepends=True)
    for line_number, pair in enumerate(
        zip_longest(disk_lines, specs, fillvalue=sentinel), start=1
    ):
        line, spec = pair
        if line is sentinel or spec is sentinel:
            return (
                f"{relative_path}: JSONL line count differs from typed "
                "record count"
            )
        assert isinstance(line, bytes)
        assert isinstance(spec, SemanticSpec)
        expected = (canonical_json(spec.to_record()) + "\n").encode("utf-8")
        if line != expected:
            return (
                f"{relative_path}:{line_number}: record is not exact "
                "canonical JSONL"
            )
    return None


def _load_jsonl_bytes(payload: bytes, relative_path: str) -> tuple[SemanticSpec, ...]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("JSONL is not valid UTF-8") from error
    specs: list[SemanticSpec] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, Mapping):
            raise ValueError(
                f"{relative_path}:{line_number}: record must be an object"
            )
        specs.append(SemanticSpec.from_record(value))
    return tuple(specs)


def _validate_expected_digest(
    value: str | None, label: str
) -> str | None:
    if value is None:
        return None
    if not _is_sha256(value):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _validate_benchmark_artifacts_opened(
    root: _ArtifactRoot,
    *,
    expected_dataset_sha256: str | None = None,
    expected_manifest_sha256: str | None = None,
    reject_extra_files: bool = True,
    max_manifest_bytes: int = _DEFAULT_MAX_MANIFEST_BYTES,
    max_inventory_entries: int = _DEFAULT_MAX_INVENTORY_ENTRIES,
    max_total_records: int = _DEFAULT_MAX_TOTAL_RECORDS,
    max_total_jsonl_bytes: int = _DEFAULT_MAX_TOTAL_JSONL_BYTES,
    max_total_fixtures: int = _DEFAULT_MAX_TOTAL_FIXTURES,
) -> dict[str, object]:
    """Validate a complete generated benchmark artifact directory.

    Validation is fail-closed and non-mutating.  The manifest must declare one
    canonical JSONL file for every suite/split pair.  Every record is loaded as
    a typed :class:`~cbds.benchmark.SemanticSpec`, globally validated, and
    compared to the deterministic generator output.  Symlinks and special
    files are always rejected.  Undeclared regular files/directories are
    rejected by default and may only be tolerated explicitly.

    ``expected_dataset_sha256`` and ``expected_manifest_sha256`` are optional
    external trust anchors.  The returned mapping is JSON serializable and
    intentionally excludes all benchmark content.  Resource ceilings are
    checked against both declarations and actual file sizes before record
    parsing or deterministic regeneration; callers must opt in explicitly to
    bundles larger than the conservative defaults.
    """

    expected_dataset_sha256 = _validate_expected_digest(
        expected_dataset_sha256, "expected_dataset_sha256"
    )
    expected_manifest_sha256 = _validate_expected_digest(
        expected_manifest_sha256, "expected_manifest_sha256"
    )
    for value, label in (
        (max_manifest_bytes, "max_manifest_bytes"),
        (max_inventory_entries, "max_inventory_entries"),
        (max_total_records, "max_total_records"),
        (max_total_jsonl_bytes, "max_total_jsonl_bytes"),
        (max_total_fixtures, "max_total_fixtures"),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"{label} must be a positive integer")
    if not isinstance(reject_extra_files, bool):
        raise TypeError("reject_extra_files must be a boolean")

    manifest_bytes, manifest, manifest_snapshot = _load_manifest_bytes(
        root, maximum_bytes=max_manifest_bytes
    )
    read_snapshots = {_MANIFEST_NAME: manifest_snapshot}

    config, declarations, manifest_issues = _parse_manifest(manifest)
    declared_total_records = manifest.get("total_records")
    if (
        _is_nonnegative_integer(declared_total_records)
        and cast(int, declared_total_records) > max_total_records
    ):
        manifest_issues.append(
            f"total_records exceeds validation ceiling {max_total_records}"
        )
    if _is_nonnegative_integer(declared_total_records):
        declared_total_fixtures = (
            cast(int, declared_total_records) * config.fixture_count
        )
        if declared_total_fixtures > max_total_fixtures:
            manifest_issues.append(
                "total generated fixtures exceed validation ceiling "
                f"{max_total_fixtures}"
            )
    declared_total_bytes = sum(
        declaration.bytes for declaration in declarations
    )
    if declared_total_bytes > max_total_jsonl_bytes:
        manifest_issues.append(
            "declared JSONL bytes exceed validation ceiling "
            f"{max_total_jsonl_bytes}"
        )
    issues = list(manifest_issues)

    try:
        canonical_manifest = (canonical_json(manifest) + "\n").encode("utf-8")
    except (TypeError, ValueError, RecursionError) as error:
        canonical_manifest = b""
        issues.append(f"manifest cannot be canonicalized: {error}")
    if canonical_manifest != manifest_bytes:
        issues.append("manifest.json is not exact canonical JSON with one final newline")

    manifest_digest = sha256(manifest_bytes).hexdigest()
    if expected_manifest_sha256 is not None and (
        manifest_digest != expected_manifest_sha256
    ):
        issues.append("manifest digest does not match expected_manifest_sha256")
    declared_dataset_digest = manifest.get("dataset_sha256")
    if expected_dataset_sha256 is not None and (
        declared_dataset_digest != expected_dataset_sha256
    ):
        issues.append("dataset digest does not match expected_dataset_sha256")

    core = {
        key: value
        for key, value in manifest.items()
        if key not in {"dataset_hash_scope", "dataset_sha256"}
    }
    try:
        computed_dataset_digest = sha256(
            canonical_json(core).encode("utf-8")
        ).hexdigest()
    except (TypeError, ValueError, RecursionError) as error:
        computed_dataset_digest = ""
        issues.append(f"cannot compute dataset digest: {error}")
    if declared_dataset_digest != computed_dataset_digest:
        issues.append("dataset_sha256 does not match canonical manifest core")

    try:
        sidecar_bytes, sidecar_snapshot = _read_relative_regular(
            root.descriptor,
            _SIDECAR_NAME,
            label=_SIDECAR_NAME,
            maximum_bytes=256,
        )
    except BenchmarkArtifactValidationError as error:
        issues.extend(error.issues)
    else:
        read_snapshots[_SIDECAR_NAME] = sidecar_snapshot
        if sidecar_bytes != compute_manifest_sidecar(manifest_bytes):
            issues.append(
                "manifest.sha256 does not match the exact manifest.json bytes"
            )

    files, directories, inventory_issues = _inventory_directory(
        root.descriptor, maximum_entries=max_inventory_entries
    )
    issues.extend(inventory_issues)
    expected_files = {
        _MANIFEST_NAME,
        _SIDECAR_NAME,
        *(declaration.path for declaration in declarations),
    }
    expected_directories = {
        PurePosixPath(declaration.path).parent.as_posix()
        for declaration in declarations
    }
    missing_files = sorted(expected_files.difference(files))
    if missing_files:
        issues.append(f"artifact directory is missing files {missing_files!r}")
    if reject_extra_files:
        extra_files = sorted(files.difference(expected_files))
        extra_directories = sorted(directories.difference(expected_directories))
        if extra_files:
            issues.append(f"artifact directory has undeclared files {extra_files!r}")
        if extra_directories:
            issues.append(
                f"artifact directory has undeclared directories {extra_directories!r}"
            )

    # Invalid manifest structure may include unsafe or ambiguous declarations.
    # Report all manifest/inventory findings, but never dereference such paths.
    if manifest_issues:
        raise BenchmarkArtifactValidationError(issues)

    # Preflight all declared files before hashing or parsing any of them.  This
    # keeps a small declaration from smuggling a very large file past the
    # manifest-level resource ceilings.
    preflight_metadata: dict[str, tuple[int, int, int, int, int, int, int]] = {}
    actual_total_bytes = 0
    for declaration in declarations:
        try:
            snapshot = _stat_relative_regular(
                root.descriptor,
                declaration.path,
                label=f"declared file {declaration.path}",
            )
        except BenchmarkArtifactValidationError as error:
            issues.extend(error.issues)
            continue
        preflight_metadata[declaration.path] = snapshot
        actual_total_bytes += snapshot[4]
    if actual_total_bytes > max_total_jsonl_bytes:
        issues.append(
            f"actual JSONL bytes exceed validation ceiling {max_total_jsonl_bytes}"
        )
    if len(preflight_metadata) != len(declarations) or (
        actual_total_bytes > max_total_jsonl_bytes
    ):
        raise BenchmarkArtifactValidationError(issues)

    all_specs: list[SemanticSpec] = []
    specs_by_pair: dict[tuple[str, str], tuple[SemanticSpec, ...]] = {}
    verified_files: list[dict[str, object]] = []
    for declaration in declarations:
        try:
            payload, snapshot = _read_relative_regular(
                root.descriptor,
                declaration.path,
                label=f"declared file {declaration.path}",
                maximum_bytes=max_total_jsonl_bytes,
                expected_snapshot=preflight_metadata[declaration.path],
            )
        except BenchmarkArtifactValidationError as error:
            issues.extend(error.issues)
            continue
        read_snapshots[declaration.path] = snapshot
        actual_bytes = len(payload)
        actual_digest = sha256(payload).hexdigest()
        if actual_bytes != declaration.bytes:
            issues.append(
                f"byte count mismatch for {declaration.path}: expected "
                f"{declaration.bytes}, found {actual_bytes}"
            )
        if actual_digest != declaration.sha256:
            issues.append(f"SHA-256 mismatch for {declaration.path}")

        try:
            specs = _load_jsonl_bytes(payload, declaration.path)
        except (
            OSError,
            UnicodeError,
            TypeError,
            ValueError,
            RecursionError,
        ) as error:
            issues.append(
                f"typed JSONL load failed for {declaration.path}: "
                f"{type(error).__name__}"
            )
            continue
        if len(specs) != declaration.records:
            issues.append(
                f"record count mismatch for {declaration.path}: expected "
                f"{declaration.records}, found {len(specs)}"
            )
        wrong_metadata = sum(
            spec.suite != declaration.suite or spec.split != declaration.split
            for spec in specs
        )
        if wrong_metadata:
            issues.append(
                f"{declaration.path} contains {wrong_metadata} record(s) with "
                "incorrect suite/split metadata"
            )
        canonical_issue = _canonical_jsonl_issue(
            payload, specs, declaration.path
        )
        if canonical_issue is not None:
            issues.append(canonical_issue)
        specs_by_pair[(declaration.suite, declaration.split)] = specs
        all_specs.extend(specs)
        verified_files.append(
            {
                "path": declaration.path,
                "suite": declaration.suite,
                "split": declaration.split,
                "records": len(specs),
                "bytes": actual_bytes,
                "sha256": actual_digest,
            }
        )

    try:
        validate_specs(all_specs, config=config)
    except BenchmarkValidationError as error:
        # ``validate_specs`` findings can include opaque spec, graph, family,
        # or signature identifiers.  Those are useful inside the generator's
        # own tests but must not cross a sealed-artifact validation boundary.
        issues.append(
            "typed benchmark invariant validation failed with "
            f"{len(error.issues)} finding(s)"
        )

    # The declared generator is current and deterministic, so a well-formed
    # but rehashed semantic mutation is still invalid preparation output.
    expected_specs = generate_benchmark(config)
    expected_by_pair = {
        (suite, split): tuple(
            spec
            for spec in expected_specs
            if spec.suite == suite and spec.split == split
        )
        for suite in SUITE_NAMES
        for split in SPLIT_NAMES
    }
    for pair, expected in expected_by_pair.items():
        actual = specs_by_pair.get(pair)
        if actual != expected:
            issues.append(
                "typed records differ from deterministic generator output for "
                f"{pair[0]}/{pair[1]}"
            )

    for relative_path, expected_snapshot in read_snapshots.items():
        try:
            current_snapshot = _stat_relative_regular(
                root.descriptor,
                relative_path,
                label=relative_path,
            )
        except BenchmarkArtifactValidationError as error:
            issues.extend(error.issues)
        else:
            if current_snapshot != expected_snapshot:
                issues.append(f"{relative_path} changed during artifact validation")

    try:
        descriptor_snapshot = _snapshot(os.fstat(root.descriptor))
        named_snapshot = _snapshot(root.path.lstat())
    except OSError as error:
        issues.append(
            "artifact root changed during validation: "
            f"{type(error).__name__}"
        )
    else:
        if descriptor_snapshot != root.snapshot or named_snapshot != root.snapshot:
            issues.append("artifact root changed during validation")

    if issues:
        raise BenchmarkArtifactValidationError(issues)

    verified_files.sort(key=lambda item: cast(str, item["path"]))
    return {
        "valid": True,
        "schema_version": manifest["schema_version"],
        "generator_version": BENCHMARK_GENERATOR_VERSION,
        "dataset_sha256": declared_dataset_digest,
        "manifest_sha256": manifest_digest,
        "file_count": len(verified_files),
        "total_records": sum(cast(int, item["records"]) for item in verified_files),
        "total_bytes": sum(cast(int, item["bytes"]) for item in verified_files),
        "files": verified_files,
    }


def validate_benchmark_artifacts(
    source: str | os.PathLike[str],
    *,
    expected_dataset_sha256: str | None = None,
    expected_manifest_sha256: str | None = None,
    reject_extra_files: bool = True,
    max_manifest_bytes: int = _DEFAULT_MAX_MANIFEST_BYTES,
    max_inventory_entries: int = _DEFAULT_MAX_INVENTORY_ENTRIES,
    max_total_records: int = _DEFAULT_MAX_TOTAL_RECORDS,
    max_total_jsonl_bytes: int = _DEFAULT_MAX_TOTAL_JSONL_BYTES,
    max_total_fixtures: int = _DEFAULT_MAX_TOTAL_FIXTURES,
) -> dict[str, object]:
    """Validate a complete benchmark through a pinned root descriptor.

    Every path component is opened relative to the pinned artifact root with
    no-follow semantics. Each regular member is read once, checked for stable
    metadata and name-to-inode identity, and rechecked before success.
    """

    for value, label in (
        (max_manifest_bytes, "max_manifest_bytes"),
        (max_inventory_entries, "max_inventory_entries"),
        (max_total_records, "max_total_records"),
        (max_total_jsonl_bytes, "max_total_jsonl_bytes"),
        (max_total_fixtures, "max_total_fixtures"),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"{label} must be a positive integer")
    if not isinstance(reject_extra_files, bool):
        raise TypeError("reject_extra_files must be a boolean")
    with _open_artifact_root(source) as root:
        return _validate_benchmark_artifacts_opened(
            root,
            expected_dataset_sha256=expected_dataset_sha256,
            expected_manifest_sha256=expected_manifest_sha256,
            reject_extra_files=reject_extra_files,
            max_manifest_bytes=max_manifest_bytes,
            max_inventory_entries=max_inventory_entries,
            max_total_records=max_total_records,
            max_total_jsonl_bytes=max_total_jsonl_bytes,
            max_total_fixtures=max_total_fixtures,
        )


__all__ = [
    "BenchmarkArtifactValidationError",
    "compute_manifest_sidecar",
    "load_benchmark_manifest",
    "validate_benchmark_artifacts",
]
