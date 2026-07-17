"""A real, execution-grounded static terminal benchmark vertical slice.

This module owns fixtures and post-execution verification only.  It never
executes candidate programs.  A separate, container-isolated harness may
materialize one fixture, run a candidate in that workspace, and then pass the
returned :class:`FixtureInstance` to :meth:`StaticSliceSuite.verify`.

The task is intentionally small but exercises several terminal-programming
failure modes: recursive file discovery, JSONL filtering, strict JSON types,
deduplication, bytewise sorting, quoting hostile path names, symlink handling,
and deterministic permission handling.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import stat
from typing import Final, Literal, TypeAlias


TASK_ID: Final[str] = "static.active-labels-jsonl"
TASK_VERSION: Final[str] = "1.1.0"
FIXTURE_SCHEMA_VERSION: Final[str] = "1.0.0"
CONTRACT_VERSION: Final[str] = "1.1.0"
REFERENCE_SEMANTICS_VERSION: Final[str] = "active-true-string-label-c-sort-v1"
OUTPUT_RELATIVE_PATH: Final[str] = "output.txt"
MAX_OUTPUT_BYTES: Final[int] = 16 * 1024
MAX_TREE_ENTRY_BYTES: Final[int] = 1024 * 1024
MAX_TREE_ENTRIES: Final[int] = 4_096
MAX_TREE_DEPTH: Final[int] = 64
MAX_TREE_TOTAL_BYTES: Final[int] = 16 * 1024 * 1024

TASK_PROMPT: Final[str] = """\
Write a Bash program that operates only in the current workspace.

Recursively inspect `input/` without following symbolic links. Consider only
regular files whose basename ends exactly in `.jsonl` and whose Unix mode has
at least one read bit from `0444`. Each nonempty line in those files is a JSON
value. From JSON objects where `active` is the JSON boolean `true` and `label`
is a JSON string, collect the label. Ignore all other values and records.

Write the distinct labels to `output.txt`, one UTF-8 label per line, sorted by
their exact UTF-8 bytes as under `LC_ALL=C`. A nonempty output must end in one
newline; if there are no labels, create an empty `output.txt`. When your
program exits, every path, file kind, Unix permission mode, size, content,
modification time, hard-link count, and symbolic-link target under `input/`
must match its initial state. When your program exits, no path other than the
original `input/` tree and `output.txt` may remain. For `output.txt`, do not
use a symlink or hard link.
"""

REQUIRED_EDGE_CASES: Final[frozenset[str]] = frozenset(
    {
        "unicode",
        "spaces",
        "leading_dash",
        "glob_characters",
        "empty_input",
        "duplicate_records",
        "symlink_decoy",
        "permission_decoy",
        "ordering_variation",
    }
)

EntryKind: TypeAlias = Literal["directory", "file", "symlink", "other"]


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _digest(value: object) -> str:
    return sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _contract_commitment() -> dict[str, object]:
    """Return every evaluator constant that changes task meaning or acceptance."""

    return {
        "contract_version": CONTRACT_VERSION,
        "task_id": TASK_ID,
        "task_version": TASK_VERSION,
        "task_prompt_sha256": sha256(TASK_PROMPT.encode("utf-8")).hexdigest(),
        "output_relative_path": OUTPUT_RELATIVE_PATH,
        "max_output_bytes": MAX_OUTPUT_BYTES,
        "max_tree_entry_bytes": MAX_TREE_ENTRY_BYTES,
        "max_tree_entries": MAX_TREE_ENTRIES,
        "max_tree_depth": MAX_TREE_DEPTH,
        "max_tree_total_bytes": MAX_TREE_TOTAL_BYTES,
        "required_edge_cases": sorted(REQUIRED_EDGE_CASES),
        "reference_semantics_version": REFERENCE_SEMANTICS_VERSION,
    }


def _seed_order(values: Iterable[object], *, seed: int, context: str) -> list[object]:
    """Order values using only specified SHA-256 operations.

    This avoids relying on the implementation details of ``random.Random``.
    The original position is included so duplicate records remain stable.
    """

    indexed = list(enumerate(values))
    indexed.sort(
        key=lambda pair: sha256(
            f"{TASK_VERSION}\0{seed}\0{context}\0{pair[0]}".encode("utf-8")
        ).digest()
    )
    return [value for _, value in indexed]


def _jsonl(records: Iterable[object], *, seed: int, context: str) -> bytes:
    ordered = _seed_order(records, seed=seed, context=context)
    if not ordered:
        return b""
    return (
        "\n".join(_canonical_json(record) for record in ordered) + "\n"
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class FixtureDescriptor:
    """Public-development fixture identity, withheld only from candidate input."""

    fixture_id: str
    fixture_sha256: str
    task_id: str = TASK_ID
    task_version: str = TASK_VERSION
    schema_version: str = FIXTURE_SCHEMA_VERSION

    def to_record(self) -> dict[str, str]:
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "task_version": self.task_version,
            "fixture_id": self.fixture_id,
            "fixture_sha256": self.fixture_sha256,
        }


@dataclass(frozen=True, slots=True)
class VerificationFailure:
    """One machine-readable failure from a fixture verification."""

    code: str
    path: str | None = None
    detail: str | None = None

    def to_record(self) -> dict[str, str]:
        record = {"code": self.code}
        if self.path is not None:
            record["path"] = self.path
        if self.detail is not None:
            record["detail"] = self.detail
        return record


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Complete verifier result; ``passed`` is true only with no failures."""

    fixture_id: str
    passed: bool
    failures: tuple[VerificationFailure, ...]
    expected_label_count: int
    observed_label_count: int | None
    output_sha256: str | None

    def to_record(self) -> dict[str, object]:
        return {
            "fixture_id": self.fixture_id,
            "passed": self.passed,
            "failures": [failure.to_record() for failure in self.failures],
            "expected_label_count": self.expected_label_count,
            "observed_label_count": self.observed_label_count,
            "output_sha256": self.output_sha256,
        }


@dataclass(frozen=True, slots=True)
class _FileDefinition:
    path: str
    content: bytes
    mode: int = 0o644

    def commitment(self) -> dict[str, object]:
        return {
            "kind": "file",
            "path": self.path,
            "mode": self.mode,
            "size": len(self.content),
            "sha256": sha256(self.content).hexdigest(),
        }


@dataclass(frozen=True, slots=True)
class _SymlinkDefinition:
    path: str
    target: str

    def commitment(self) -> dict[str, object]:
        return {"kind": "symlink", "path": self.path, "target": self.target}


_DefinitionEntry: TypeAlias = _FileDefinition | _SymlinkDefinition


@dataclass(frozen=True, slots=True)
class _FixtureDefinition:
    name: str
    cases: frozenset[str]
    entries: tuple[_DefinitionEntry, ...]

    def commitment(self, *, seed: int) -> dict[str, object]:
        entries = sorted(
            (entry.commitment() for entry in self.entries),
            key=lambda item: str(item["path"]).encode("utf-8"),
        )
        return {
            "schema_version": FIXTURE_SCHEMA_VERSION,
            "task_id": TASK_ID,
            "task_version": TASK_VERSION,
            "contract_sha256": _digest(_contract_commitment()),
            "seed": seed,
            "fixture_name": self.name,
            "cases": sorted(self.cases),
            "entries": entries,
        }


@dataclass(frozen=True, slots=True)
class _TreeEntry:
    path: str
    kind: EntryKind
    mode: int
    size: int
    mtime_ns: int
    link_count: int
    device: int
    inode: int
    content_sha256: str | None = None
    symlink_target: str | None = None


@dataclass(slots=True)
class _PinnedRegular:
    """Trusted descriptor retained when pathname reads are not effective."""

    path: str
    descriptor: int

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1

    def __del__(self) -> None:  # pragma: no cover - interpreter cleanup timing
        try:
            self.close()
        except OSError:
            pass


@dataclass(frozen=True, slots=True)
class FixtureInstance:
    """Trusted handle tying one materialized workspace to its baseline.

    Baseline state and reference output are intentionally absent from the
    representation and from :class:`FixtureDescriptor`.  The instance belongs
    to the trusted evaluator and must not be passed to a candidate program.
    """

    descriptor: FixtureDescriptor
    workspace: Path
    _baseline: tuple[_TreeEntry, ...] = field(repr=False)
    _expected_output: bytes = field(repr=False)
    _suite_commitment: str = field(repr=False)
    _pinned_regulars: tuple[_PinnedRegular, ...] = field(repr=False)


class StaticSliceError(ValueError):
    """Base error for invalid fixture use or fixture state."""


class MaterializationError(StaticSliceError):
    """Raised when a fixture cannot safely be materialized."""


class FixtureVerificationError(StaticSliceError):
    """Raised for evaluator misuse, rather than a candidate failure."""


def _validate_relative_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise MaterializationError(f"unsafe fixture path: {value!r}")
    if path.parts[0] != "input":
        raise MaterializationError(f"fixture path must be below input/: {value!r}")
    return path


def _validate_symlink_target(value: str) -> PurePosixPath:
    target = PurePosixPath(value)
    if (
        not value
        or target.is_absolute()
        or ".." in target.parts
        or "." in target.parts
    ):
        raise MaterializationError(f"unsafe fixture symlink target: {value!r}")
    return target


def _definitions(seed: int) -> tuple[_FixtureDefinition, ...]:
    """Build deterministic definitions; case annotations never enter descriptors."""

    basic = _FixtureDefinition(
        name="basic-types-and-duplicates",
        cases=frozenset(
            {"leading_dash", "duplicate_records", "ordering_variation"}
        ),
        entries=(
            _FileDefinition(
                "input/basic.jsonl",
                _jsonl(
                    (
                        {"active": True, "label": "zeta"},
                        {"active": True, "label": "alpha"},
                        {"active": True, "label": "alpha"},
                        {"active": False, "label": "ignored"},
                        {"active": True, "label": "-leading"},
                        {"active": 1, "label": "integer-is-not-true"},
                        {"active": True, "label": 17},
                    ),
                    seed=seed,
                    context="basic",
                ),
            ),
        ),
    )

    hostile_paths = _FixtureDefinition(
        name="hostile-paths",
        cases=frozenset(
            {
                "spaces",
                "leading_dash",
                "glob_characters",
                "duplicate_records",
                "ordering_variation",
            }
        ),
        entries=(
            _FileDefinition(
                "input/with spaces/records one.jsonl",
                _jsonl(
                    (
                        {"active": True, "label": "two words"},
                        {"active": True, "label": "[literal]*?"},
                    ),
                    seed=seed,
                    context="hostile-spaces",
                ),
            ),
            _FileDefinition(
                "input/-leading name.jsonl",
                _jsonl(
                    (
                        {"active": True, "label": "-option"},
                        {"active": True, "label": "two words"},
                    ),
                    seed=seed,
                    context="hostile-leading",
                ),
            ),
            _FileDefinition(
                "input/literal[glob]*?.jsonl",
                _jsonl(
                    ({"active": True, "label": "asterisk*question?"},),
                    seed=seed,
                    context="hostile-glob",
                ),
            ),
        ),
    )

    unicode_values = _FixtureDefinition(
        name="unicode-byte-order",
        cases=frozenset({"unicode", "ordering_variation"}),
        entries=(
            _FileDefinition(
                "input/자료/유니코드.jsonl",
                _jsonl(
                    (
                        {"active": True, "label": "東京"},
                        {"active": True, "label": "éclair"},
                        {"active": True, "label": "Ångström"},
                        {"active": True, "label": "Zebra"},
                        {"active": True, "label": "e\u0301clair"},
                        {"active": True, "label": "🙂 emoji"},
                    ),
                    seed=seed,
                    context="unicode",
                ),
            ),
        ),
    )

    empty = _FixtureDefinition(
        name="empty-and-nonmatching",
        cases=frozenset({"empty_input"}),
        entries=(
            _FileDefinition("input/empty.jsonl", b""),
            _FileDefinition(
                "input/no matches.jsonl",
                _jsonl(
                    (
                        {"active": False, "label": "inactive"},
                        {"active": "true", "label": "wrong-active-type"},
                        {"active": True, "label": None},
                        {"label": "missing-active"},
                        ["not", "an", "object"],
                        None,
                    ),
                    seed=seed,
                    context="empty-nonmatching",
                ),
            ),
            _FileDefinition(
                "input/not-jsonl.txt",
                b'{"active":true,"label":"wrong-extension"}\n',
            ),
        ),
    )

    symlinks = _FixtureDefinition(
        name="symlink-decoys",
        cases=frozenset({"symlink_decoy"}),
        entries=(
            _FileDefinition(
                "input/real/accepted.jsonl",
                _jsonl(
                    ({"active": True, "label": "accepted-real-file"},),
                    seed=seed,
                    context="symlink-real",
                ),
            ),
            _FileDefinition(
                "input/decoys/payload.data",
                b'{"active":true,"label":"must-not-follow-symlink"}\n',
            ),
            _SymlinkDefinition("input/linked.jsonl", "decoys/payload.data"),
            _SymlinkDefinition("input/broken.jsonl", "does-not-exist.jsonl"),
        ),
    )

    permissions = _FixtureDefinition(
        name="permission-decoys",
        cases=frozenset({"permission_decoy"}),
        entries=(
            _FileDefinition(
                "input/readable.jsonl",
                _jsonl(
                    ({"active": True, "label": "readable-record"},),
                    seed=seed,
                    context="permission-readable",
                ),
            ),
            _FileDefinition(
                "input/locked.jsonl",
                b'{"active":true,"label":"must-not-read-mode-000"}\n',
                mode=0o000,
            ),
            _FileDefinition(
                "input/executable-only.jsonl",
                b'{"active":true,"label":"must-not-read-mode-111"}\n',
                mode=0o111,
            ),
        ),
    )

    nested = _FixtureDefinition(
        name="nested-cross-file-dedup",
        cases=frozenset({"duplicate_records", "ordering_variation"}),
        entries=(
            _FileDefinition(
                "input/a/third.jsonl",
                _jsonl(
                    (
                        {"active": True, "label": "2"},
                        {"active": True, "label": "shared"},
                    ),
                    seed=seed,
                    context="nested-third",
                ),
            ),
            _FileDefinition(
                "input/b/deeper/first.jsonl",
                _jsonl(
                    (
                        {"active": True, "label": "10"},
                        {"active": True, "label": "A"},
                    ),
                    seed=seed,
                    context="nested-first",
                ),
            ),
            _FileDefinition(
                "input/b/second.jsonl",
                _jsonl(
                    (
                        {"active": True, "label": "shared"},
                        {"active": True, "label": "a"},
                    ),
                    seed=seed,
                    context="nested-second",
                ),
            ),
        ),
    )

    empty_label = _FixtureDefinition(
        name="empty-string-label",
        cases=frozenset({"empty_input", "ordering_variation"}),
        entries=(
            _FileDefinition(
                "input/empty-label.jsonl",
                _jsonl(
                    (
                        {"active": True, "label": "visible"},
                        {"active": True, "label": ""},
                        {"active": True, "label": "visible"},
                    ),
                    seed=seed,
                    context="empty-label",
                ),
            ),
        ),
    )

    return (
        basic,
        hostile_paths,
        unicode_values,
        empty,
        symlinks,
        permissions,
        nested,
        empty_label,
    )


def _filesystem_snapshot(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _stable_content_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int]:
    """Identity fields unaffected by the verifier's temporary chmod."""

    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _directory_open_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None:  # pragma: no cover - Linux requirement
        raise OSError("no-follow directory descriptors are unavailable")
    return os.O_RDONLY | os.O_CLOEXEC | nofollow | directory


def _regular_open_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:  # pragma: no cover - Linux requirement
        raise OSError("no-follow regular-file descriptors are unavailable")
    return os.O_RDONLY | os.O_CLOEXEC | nofollow | getattr(os, "O_NONBLOCK", 0)


def _open_absolute_directory_no_follow(path: Path) -> tuple[int, os.stat_result]:
    absolute = Path(os.path.abspath(path))
    if not absolute.is_absolute() or absolute == Path("/"):
        raise OSError("workspace must be a non-root absolute directory")
    current = os.open("/", _directory_open_flags())
    try:
        for part in absolute.parts[1:]:
            child = os.open(part, _directory_open_flags(), dir_fd=current)
            os.close(current)
            current = child
        metadata = os.fstat(current)
        if not stat.S_ISDIR(metadata.st_mode):
            raise OSError("workspace is not a directory")
        return current, metadata
    except BaseException:
        os.close(current)
        raise


def _open_or_create_workspace_no_follow(
    destination: Path,
) -> tuple[int, os.stat_result]:
    """Create/open a workspace through pinned, no-follow directory FDs."""

    absolute = Path(os.path.abspath(destination))
    if not absolute.is_absolute() or absolute == Path("/"):
        raise OSError("workspace must be a non-root absolute directory")
    current = os.open("/", _directory_open_flags())
    try:
        for part in absolute.parts[1:]:
            created = False
            try:
                child = os.open(part, _directory_open_flags(), dir_fd=current)
            except FileNotFoundError:
                os.mkdir(part, mode=0o755, dir_fd=current)
                created = True
                child = os.open(part, _directory_open_flags(), dir_fd=current)
            try:
                if created:
                    os.fchmod(child, 0o755)
                named = os.stat(part, dir_fd=current, follow_symlinks=False)
                if not _same_inode(named, os.fstat(child)):
                    raise OSError("workspace component changed while opening")
            except BaseException:
                os.close(child)
                raise
            os.close(current)
            current = child
        with os.scandir(current) as iterator:
            if next(iterator, None) is not None:
                raise OSError("workspace must be empty")
        metadata = os.fstat(current)
        if not stat.S_ISDIR(metadata.st_mode):
            raise OSError("workspace must be a real directory")
        return current, metadata
    except BaseException:
        os.close(current)
        raise


def _open_relative_directory(
    root_descriptor: int, relative: PurePosixPath
) -> int:
    """Open a relative directory without following any path component."""

    current = os.dup(root_descriptor)
    try:
        for part in relative.parts:
            child = os.open(part, _directory_open_flags(), dir_fd=current)
            try:
                named = os.stat(part, dir_fd=current, follow_symlinks=False)
                if _filesystem_snapshot(named) != _filesystem_snapshot(
                    os.fstat(child)
                ):
                    raise OSError("directory component changed while opening")
            except BaseException:
                os.close(child)
                raise
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def _assert_relative_directory_reachable(
    root_descriptor: int,
    directory_descriptor: int,
    relative: PurePosixPath,
) -> None:
    """Require an opened directory to remain named below the pinned root."""

    named = _open_relative_directory(root_descriptor, relative)
    try:
        opened_metadata = os.fstat(directory_descriptor)
        named_metadata = os.fstat(named)
        if (
            opened_metadata.st_dev != named_metadata.st_dev
            or opened_metadata.st_ino != named_metadata.st_ino
            or not stat.S_ISDIR(opened_metadata.st_mode)
        ):
            raise OSError("directory is no longer reachable below workspace")
    finally:
        os.close(named)


def _ensure_relative_directory(
    root_descriptor: int, relative: PurePosixPath
) -> None:
    """Create a reachable mode-0755 tree below a pinned workspace root."""

    current = os.dup(root_descriptor)
    current_relative = PurePosixPath()
    try:
        for part in relative.parts:
            _assert_relative_directory_reachable(
                root_descriptor, current, current_relative
            )
            created = False
            try:
                child = os.open(part, _directory_open_flags(), dir_fd=current)
            except FileNotFoundError:
                os.mkdir(part, mode=0o755, dir_fd=current)
                created = True
                child = os.open(part, _directory_open_flags(), dir_fd=current)
            child_relative = current_relative / part
            try:
                if created:
                    os.fchmod(child, 0o755)
                named = os.stat(part, dir_fd=current, follow_symlinks=False)
                if _filesystem_snapshot(named) != _filesystem_snapshot(
                    os.fstat(child)
                ):
                    raise OSError("directory changed while creating fixture")
                _assert_relative_directory_reachable(
                    root_descriptor, child, child_relative
                )
            except BaseException:
                if created:
                    try:
                        current_named = os.stat(
                            part, dir_fd=current, follow_symlinks=False
                        )
                        if (
                            current_named.st_dev == os.fstat(child).st_dev
                            and current_named.st_ino == os.fstat(child).st_ino
                        ):
                            os.rmdir(part, dir_fd=current)
                    except OSError:
                        pass
                os.close(child)
                raise
            os.close(current)
            current = child
            current_relative = child_relative
    finally:
        os.close(current)


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and stat.S_IFMT(left.st_mode) == stat.S_IFMT(right.st_mode)
    )


def _regular_is_effectively_readable(metadata: os.stat_result) -> bool:
    """Return the current process's Unix-mode read decision for one inode.

    Permission classes are exclusive: when the EUID owns a file, group and
    other bits do not supplement a missing owner-read bit.  Likewise, a group
    match selects only the group class.  Linux root may read a regular file
    regardless of its read bits.
    """

    effective_uid = os.geteuid()
    if effective_uid == 0:
        return True
    mode = stat.S_IMODE(metadata.st_mode)
    if metadata.st_uid == effective_uid:
        return bool(mode & stat.S_IRUSR)
    effective_groups = set(os.getgroups())
    effective_groups.add(os.getegid())
    if metadata.st_gid in effective_groups:
        return bool(mode & stat.S_IRGRP)
    return bool(mode & stat.S_IROTH)


def _write_relative_file(
    root_descriptor: int,
    relative: PurePosixPath,
    payload: bytes,
    mode: int,
) -> _PinnedRegular | None:
    """Stage bytes at the root, then publish only to a reachable parent."""

    parent = _open_relative_directory(root_descriptor, relative.parent)
    stage_name = ".cbds-stage-" + sha256(
        relative.as_posix().encode("utf-8")
    ).hexdigest()
    descriptor: int | None = None
    stage_exists = False
    published = False
    opened_metadata: os.stat_result | None = None
    try:
        _assert_relative_directory_reachable(
            root_descriptor, parent, relative.parent
        )
        nofollow = getattr(os, "O_NOFOLLOW", None)
        if nofollow is None:  # pragma: no cover - Linux requirement
            raise OSError("no-follow file creation is unavailable")
        descriptor = os.open(
            stage_name,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | nofollow,
            0o600,
            dir_fd=root_descriptor,
        )
        stage_exists = True
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("fixture write made no progress")
            offset += written
        os.fchmod(descriptor, mode)
        opened_metadata = os.fstat(descriptor)
        stage_metadata = os.stat(
            stage_name, dir_fd=root_descriptor, follow_symlinks=False
        )
        if (
            not stat.S_ISREG(opened_metadata.st_mode)
            or not _same_inode(opened_metadata, stage_metadata)
        ):
            raise OSError("staged fixture file changed while writing")

        _assert_relative_directory_reachable(
            root_descriptor, parent, relative.parent
        )
        os.link(
            stage_name,
            relative.name,
            src_dir_fd=root_descriptor,
            dst_dir_fd=parent,
            follow_symlinks=False,
        )
        published = True
        try:
            _assert_relative_directory_reachable(
                root_descriptor, parent, relative.parent
            )
        except BaseException:
            named = os.stat(
                relative.name, dir_fd=parent, follow_symlinks=False
            )
            if _same_inode(opened_metadata, named):
                os.unlink(relative.name, dir_fd=parent)
                published = False
            raise
        named = os.stat(relative.name, dir_fd=parent, follow_symlinks=False)
        if not _same_inode(opened_metadata, named):
            raise OSError("published fixture file changed")
        os.unlink(stage_name, dir_fd=root_descriptor)
        stage_exists = False
        final_metadata = os.fstat(descriptor)
        named = os.stat(relative.name, dir_fd=parent, follow_symlinks=False)
        if (
            final_metadata.st_nlink != 1
            or _filesystem_snapshot(final_metadata)
            != _filesystem_snapshot(named)
        ):
            raise OSError("published fixture file is not stable")
        if not _regular_is_effectively_readable(final_metadata):
            return _PinnedRegular(relative.as_posix(), os.dup(descriptor))
        return None
    except BaseException:
        if published and opened_metadata is not None:
            try:
                named = os.stat(
                    relative.name, dir_fd=parent, follow_symlinks=False
                )
                if _same_inode(opened_metadata, named):
                    os.unlink(relative.name, dir_fd=parent)
            except OSError:
                pass
        if stage_exists:
            try:
                os.unlink(stage_name, dir_fd=root_descriptor)
            except OSError:
                pass
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def _create_relative_symlink(
    root_descriptor: int, relative: PurePosixPath, target: str
) -> None:
    """Create a symlink only while its pinned parent remains reachable."""

    parent = _open_relative_directory(root_descriptor, relative.parent)
    created_metadata: os.stat_result | None = None
    try:
        _assert_relative_directory_reachable(
            root_descriptor, parent, relative.parent
        )
        os.symlink(target, relative.name, dir_fd=parent)
        created_metadata = os.stat(
            relative.name, dir_fd=parent, follow_symlinks=False
        )
        if (
            not stat.S_ISLNK(created_metadata.st_mode)
            or os.readlink(relative.name, dir_fd=parent) != target
        ):
            raise OSError("fixture symlink changed while creating")
        _assert_relative_directory_reachable(
            root_descriptor, parent, relative.parent
        )
    except BaseException:
        if created_metadata is not None:
            try:
                named = os.stat(
                    relative.name, dir_fd=parent, follow_symlinks=False
                )
                if _same_inode(created_metadata, named):
                    os.unlink(relative.name, dir_fd=parent)
            except OSError:
                pass
        raise
    finally:
        os.close(parent)


def _close_pinned_regulars(pinned: Iterable[_PinnedRegular]) -> None:
    for item in pinned:
        try:
            item.close()
        except OSError:
            pass


def _read_exact_fd(descriptor: int, advertised_size: int, maximum: int) -> bytes | None:
    if advertised_size > maximum:
        return None
    payload = bytearray()
    remaining = advertised_size
    while remaining:
        chunk = os.read(descriptor, min(64 * 1024, remaining))
        if not chunk:
            raise OSError("regular file ended before its snapshotted size")
        payload.extend(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise OSError("regular file grew beyond its snapshotted size")
    return bytes(payload)


def _read_regular_entry(
    directory_descriptor: int,
    name: str,
    metadata: os.stat_result,
    *,
    maximum_bytes: int,
) -> bytes | None:
    """Read the exact snapshotted inode without following a replacement path."""

    descriptor: int | None = None
    try:
        descriptor = os.open(
            name,
            _regular_open_flags(),
            dir_fd=directory_descriptor,
        )
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _filesystem_snapshot(opened) != _filesystem_snapshot(metadata)
        ):
            raise OSError("regular entry changed before read")
        payload = _read_exact_fd(descriptor, metadata.st_size, maximum_bytes)
        if _filesystem_snapshot(os.fstat(descriptor)) != _filesystem_snapshot(
            metadata
        ):
            raise OSError("regular entry changed during read")
        named = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if _filesystem_snapshot(named) != _filesystem_snapshot(metadata):
            raise OSError("regular entry name changed during read")
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return payload


def _read_exact_pinned(
    descriptor: int, advertised_size: int, maximum: int
) -> bytes | None:
    if advertised_size > maximum:
        return None
    payload = bytearray()
    offset = 0
    while offset < advertised_size:
        chunk = os.pread(
            descriptor,
            min(64 * 1024, advertised_size - offset),
            offset,
        )
        if not chunk:
            raise OSError("pinned regular file ended before its snapshotted size")
        payload.extend(chunk)
        offset += len(chunk)
    if os.pread(descriptor, 1, advertised_size):
        raise OSError("pinned regular file grew beyond its snapshotted size")
    return bytes(payload)


def _read_pinned_regular(
    pinned: _PinnedRegular,
    metadata: os.stat_result,
    *,
    maximum_bytes: int,
) -> bytes | None:
    """Read a retained fixture inode without chmod or pathname traversal."""

    if pinned.descriptor < 0:
        raise OSError("pinned fixture descriptor is closed")
    before = os.fstat(pinned.descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or _filesystem_snapshot(before) != _filesystem_snapshot(metadata)
    ):
        raise OSError("pinned fixture inode no longer matches its path")
    payload = _read_exact_pinned(
        pinned.descriptor,
        metadata.st_size,
        maximum_bytes,
    )
    if _filesystem_snapshot(os.fstat(pinned.descriptor)) != _filesystem_snapshot(
        metadata
    ):
        raise OSError("pinned fixture changed during read")
    return payload


def _hash_regular_entry(
    directory_descriptor: int,
    name: str,
    metadata: os.stat_result,
    pinned: _PinnedRegular | None = None,
) -> str | None:
    if _regular_is_effectively_readable(metadata):
        payload = _read_regular_entry(
            directory_descriptor,
            name,
            metadata,
            maximum_bytes=MAX_TREE_ENTRY_BYTES,
        )
    elif pinned is not None:
        payload = _read_pinned_regular(
            pinned,
            metadata,
            maximum_bytes=MAX_TREE_ENTRY_BYTES,
        )
    else:
        return None
    return None if payload is None else sha256(payload).hexdigest()


def _scan_tree_descriptor(
    root_descriptor: int,
    *,
    exclude_top_level: frozenset[str] = frozenset(),
    pinned_regulars: Mapping[str, _PinnedRegular] | None = None,
) -> tuple[tuple[_TreeEntry, ...], tuple[str, ...]]:
    entries: list[_TreeEntry] = []
    errors: list[str] = []
    entry_count = 0
    total_regular_bytes = 0
    entry_limit_reported = False
    total_bytes_limit_reported = False
    stack: list[tuple[int, PurePosixPath]] = [
        (os.dup(root_descriptor), PurePosixPath())
    ]

    while stack and not entry_limit_reported:
        directory_descriptor, relative_directory = stack.pop()
        directory_before = os.fstat(directory_descriptor)
        children: list[str] = []
        try:
            with os.scandir(directory_descriptor) as iterator:
                for child in iterator:
                    entry_count += 1
                    if entry_count > MAX_TREE_ENTRIES:
                        errors.append(
                            f"tree entry limit exceeded ({MAX_TREE_ENTRIES})"
                        )
                        entry_limit_reported = True
                        break
                    children.append(child.name)
        except OSError as exc:
            display = relative_directory.as_posix() or "."
            errors.append(f"{display}: {type(exc).__name__}")
            os.close(directory_descriptor)
            continue
        if entry_limit_reported:
            os.close(directory_descriptor)
            for pending_descriptor, _ in stack:
                os.close(pending_descriptor)
            stack.clear()
            break
        children.sort(key=os.fsencode)
        child_directories: list[tuple[int, PurePosixPath]] = []
        for name in children:
            relative = relative_directory / name
            relative_text = relative.as_posix()
            if len(relative.parts) == 1 and name in exclude_top_level:
                continue
            try:
                metadata = os.stat(
                    name,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
                mode = stat.S_IMODE(metadata.st_mode)
                common = {
                    "path": relative_text,
                    "mode": mode,
                    "size": metadata.st_size,
                    "mtime_ns": metadata.st_mtime_ns,
                    "link_count": metadata.st_nlink,
                    "device": metadata.st_dev,
                    "inode": metadata.st_ino,
                }
                if stat.S_ISLNK(metadata.st_mode):
                    target = os.readlink(name, dir_fd=directory_descriptor)
                    if _filesystem_snapshot(
                        os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
                    ) != _filesystem_snapshot(metadata):
                        raise OSError("symlink changed during read")
                    entries.append(
                        _TreeEntry(kind="symlink", symlink_target=target, **common)
                    )
                elif stat.S_ISDIR(metadata.st_mode):
                    entries.append(_TreeEntry(kind="directory", **common))
                    if len(relative.parts) >= MAX_TREE_DEPTH:
                        errors.append(
                            f"tree depth limit exceeded ({MAX_TREE_DEPTH})"
                        )
                    else:
                        child = os.open(
                            name,
                            _directory_open_flags(),
                            dir_fd=directory_descriptor,
                        )
                        if _filesystem_snapshot(os.fstat(child)) != _filesystem_snapshot(
                            metadata
                        ):
                            os.close(child)
                            raise OSError("directory changed before traversal")
                        child_directories.append((child, relative))
                elif stat.S_ISREG(metadata.st_mode):
                    total_regular_bytes += metadata.st_size
                    may_hash = total_regular_bytes <= MAX_TREE_TOTAL_BYTES
                    if not may_hash and not total_bytes_limit_reported:
                        errors.append(
                            "tree regular-file byte limit exceeded "
                            f"({MAX_TREE_TOTAL_BYTES})"
                        )
                        total_bytes_limit_reported = True
                    entries.append(
                        _TreeEntry(
                            kind="file",
                            content_sha256=(
                                _hash_regular_entry(
                                    directory_descriptor,
                                    name,
                                    metadata,
                                    None
                                    if pinned_regulars is None
                                    else pinned_regulars.get(relative_text),
                                )
                                if may_hash
                                else None
                            ),
                            **common,
                        )
                    )
                else:
                    entries.append(_TreeEntry(kind="other", **common))
            except OSError as exc:
                errors.append(f"{relative_text}: {type(exc).__name__}")
        if _filesystem_snapshot(os.fstat(directory_descriptor)) != _filesystem_snapshot(
            directory_before
        ):
            display = relative_directory.as_posix() or "."
            errors.append(f"{display}: directory_changed_during_scan")
        os.close(directory_descriptor)
        stack.extend(reversed(child_directories))
    entries.sort(key=lambda entry: entry.path.encode("utf-8"))
    return tuple(entries), tuple(errors)


def _scan_tree(
    workspace: Path, *, exclude_top_level: frozenset[str] = frozenset()
) -> tuple[tuple[_TreeEntry, ...], tuple[str, ...]]:
    try:
        descriptor, _ = _open_absolute_directory_no_follow(workspace)
    except OSError as exc:
        return (), (f".: {type(exc).__name__}",)
    try:
        return _scan_tree_descriptor(
            descriptor, exclude_top_level=exclude_top_level
        )
    finally:
        os.close(descriptor)


def _reference_output_descriptor(
    root_descriptor: int,
    *,
    pinned_regulars: Mapping[str, _PinnedRegular] | None = None,
) -> bytes:
    """Build the trusted answer below an already pinned workspace root."""

    labels: set[bytes] = set()
    try:
        input_descriptor = os.open(
            "input", _directory_open_flags(), dir_fd=root_descriptor
        )
    except OSError as exc:
        raise MaterializationError(
            "fixture did not materialize a stable real input directory"
        ) from exc
    stack: list[tuple[int, PurePosixPath]] = [
        (input_descriptor, PurePosixPath("input"))
    ]
    try:
        while stack:
            directory_descriptor, relative_directory = stack.pop()
            children: list[str] = []
            child_directories: list[tuple[int, PurePosixPath]] = []
            try:
                with os.scandir(directory_descriptor) as iterator:
                    children = sorted(
                        (child.name for child in iterator), key=os.fsencode
                    )
                for name in children:
                    relative = relative_directory / name
                    metadata = os.stat(
                        name,
                        dir_fd=directory_descriptor,
                        follow_symlinks=False,
                    )
                    if stat.S_ISLNK(metadata.st_mode):
                        continue
                    if stat.S_ISDIR(metadata.st_mode):
                        child_descriptor = os.open(
                            name,
                            _directory_open_flags(),
                            dir_fd=directory_descriptor,
                        )
                        if _filesystem_snapshot(
                            os.fstat(child_descriptor)
                        ) != _filesystem_snapshot(metadata):
                            os.close(child_descriptor)
                            raise OSError("reference directory changed")
                        child_directories.append((child_descriptor, relative))
                        continue
                    if not stat.S_ISREG(metadata.st_mode):
                        continue
                    mode = stat.S_IMODE(metadata.st_mode)
                    if not name.endswith(".jsonl") or not mode & 0o444:
                        continue
                    if _regular_is_effectively_readable(metadata):
                        payload = _read_regular_entry(
                            directory_descriptor,
                            name,
                            metadata,
                            maximum_bytes=MAX_TREE_ENTRY_BYTES,
                        )
                    else:
                        pinned = (
                            None
                            if pinned_regulars is None
                            else pinned_regulars.get(relative.as_posix())
                        )
                        if pinned is None:
                            raise OSError(
                                "trusted fixture lacks its retained read descriptor"
                            )
                        payload = _read_pinned_regular(
                            pinned,
                            metadata,
                            maximum_bytes=MAX_TREE_ENTRY_BYTES,
                        )
                    if payload is None:
                        raise MaterializationError("trusted fixture file is oversized")
                    for line_number, raw_line in enumerate(
                        payload.splitlines(), start=1
                    ):
                        if not raw_line:
                            continue
                        try:
                            value = json.loads(raw_line)
                        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                            raise MaterializationError(
                                "invalid JSONL fixture at "
                                f"{relative.as_posix()}:{line_number}"
                            ) from exc
                        if (
                            not isinstance(value, Mapping)
                            or value.get("active") is not True
                        ):
                            continue
                        label = value.get("label")
                        if not isinstance(label, str):
                            continue
                        if "\n" in label or "\r" in label or "\0" in label:
                            raise MaterializationError(
                                "fixture label violates line protocol"
                            )
                        labels.add(label.encode("utf-8"))
            finally:
                os.close(directory_descriptor)
            stack.extend(reversed(child_directories))
    except OSError as exc:
        for descriptor, _ in stack:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise MaterializationError(
            f"cannot read trusted fixture: {type(exc).__name__}"
        ) from exc
    ordered = sorted(labels)
    return b"" if not ordered else b"\n".join(ordered) + b"\n"


def _reference_output(workspace: Path) -> bytes:
    """Build the trusted answer from a no-follow workspace descriptor."""

    try:
        root_descriptor, _ = _open_absolute_directory_no_follow(workspace)
    except OSError as exc:
        raise MaterializationError(
            "fixture did not materialize a stable real input directory"
        ) from exc
    try:
        return _reference_output_descriptor(root_descriptor)
    finally:
        os.close(root_descriptor)


def _validate_materialized_projection(
    definition: _FixtureDefinition, observed: tuple[_TreeEntry, ...]
) -> None:
    """Bind the materialized tree back to the committed fixture definition."""

    expected_directories: set[str] = {"input"}
    expected_entries: dict[str, _DefinitionEntry] = {}
    for entry in definition.entries:
        relative = _validate_relative_path(entry.path)
        expected_entries[relative.as_posix()] = entry
        for parent in relative.parents:
            if parent != PurePosixPath("."):
                expected_directories.add(parent.as_posix())
    expected_paths = expected_directories | set(expected_entries)
    observed_by_path = {entry.path: entry for entry in observed}
    if set(observed_by_path) != expected_paths:
        raise MaterializationError("materialized fixture path projection disagrees")
    for path in expected_directories:
        actual = observed_by_path[path]
        if actual.kind != "directory" or actual.mode != 0o755:
            raise MaterializationError("materialized fixture directory disagrees")
    for path, expected in expected_entries.items():
        actual = observed_by_path[path]
        if isinstance(expected, _FileDefinition):
            if (
                actual.kind != "file"
                or actual.mode != expected.mode
                or actual.size != len(expected.content)
                or actual.link_count != 1
                or actual.content_sha256 != sha256(expected.content).hexdigest()
            ):
                raise MaterializationError("materialized fixture file disagrees")
        elif (
            actual.kind != "symlink"
            or actual.symlink_target != expected.target
        ):
            raise MaterializationError("materialized fixture symlink disagrees")


class StaticSliceSuite:
    """Deterministic fixture suite and trusted post-execution verifier."""

    def __init__(self, seed: int = 20260714) -> None:
        if isinstance(seed, bool) or not isinstance(seed, int):
            raise ValueError("seed must be an integer")
        self.seed = seed
        definitions = _definitions(seed)
        records: list[tuple[FixtureDescriptor, _FixtureDefinition]] = []
        for definition in definitions:
            commitment = _digest(definition.commitment(seed=seed))
            descriptor = FixtureDescriptor(
                fixture_id=f"fx-{commitment[:20]}",
                fixture_sha256=commitment,
            )
            records.append((descriptor, definition))
        self._records = tuple(records)
        self._by_id = {
            descriptor.fixture_id: (descriptor, item)
            for descriptor, item in records
        }
        self._suite_commitment = _digest(
            {
                "schema_version": FIXTURE_SCHEMA_VERSION,
                "task_id": TASK_ID,
                "task_version": TASK_VERSION,
                "contract": _contract_commitment(),
                "seed": seed,
                "fixtures": [
                    descriptor.to_record() for descriptor, _ in self._records
                ],
            }
        )

    @property
    def descriptors(self) -> tuple[FixtureDescriptor, ...]:
        """Return opaque descriptors, without paths, records, tags, or answers."""

        return tuple(descriptor for descriptor, _ in self._records)

    @property
    def suite_sha256(self) -> str:
        return self._suite_commitment

    @property
    def contract_sha256(self) -> str:
        """Commit to the prompt, output boundary, and reference semantics."""

        return _digest(_contract_commitment())

    @property
    def coverage_tags(self) -> frozenset[str]:
        """Aggregate audit coverage without disclosing fixture-to-case mapping."""

        return frozenset(
            case for _, definition in self._records for case in definition.cases
        )

    def _resolve(
        self, descriptor: FixtureDescriptor | str
    ) -> tuple[FixtureDescriptor, _FixtureDefinition]:
        fixture_id = (
            descriptor.fixture_id
            if isinstance(descriptor, FixtureDescriptor)
            else descriptor
        )
        if not isinstance(fixture_id, str) or fixture_id not in self._by_id:
            raise MaterializationError(f"unknown fixture id: {fixture_id!r}")
        expected_descriptor, definition = self._by_id[fixture_id]
        if isinstance(descriptor, FixtureDescriptor) and descriptor != expected_descriptor:
            raise MaterializationError("fixture descriptor commitment does not match suite")
        return expected_descriptor, definition

    def materialize(
        self, descriptor: FixtureDescriptor | str, workspace: str | Path
    ) -> FixtureInstance:
        """Materialize one fixture into a new or existing empty directory."""

        expected_descriptor, definition = self._resolve(descriptor)
        destination = Path(os.path.abspath(workspace))
        root_descriptor: int | None = None
        pinned_regulars: list[_PinnedRegular] = []
        try:
            root_descriptor, _ = _open_or_create_workspace_no_follow(destination)
            directories: set[PurePosixPath] = {PurePosixPath("input")}
            for entry in definition.entries:
                relative = _validate_relative_path(entry.path)
                for parent in relative.parents:
                    if parent != PurePosixPath("."):
                        directories.add(parent)
            for relative in sorted(
                directories,
                key=lambda item: (len(item.parts), item.as_posix().encode()),
            ):
                _ensure_relative_directory(root_descriptor, relative)

            for entry in definition.entries:
                if isinstance(entry, _FileDefinition):
                    pinned = _write_relative_file(
                        root_descriptor,
                        _validate_relative_path(entry.path),
                        entry.content,
                        entry.mode,
                    )
                    if pinned is not None:
                        pinned_regulars.append(pinned)
            for entry in definition.entries:
                if isinstance(entry, _SymlinkDefinition):
                    _create_relative_symlink(
                        root_descriptor,
                        _validate_relative_path(entry.path),
                        _validate_symlink_target(entry.target).as_posix(),
                    )

            pinned_by_path = {item.path: item for item in pinned_regulars}
            baseline, errors = _scan_tree_descriptor(
                root_descriptor, pinned_regulars=pinned_by_path
            )
            if errors:
                raise MaterializationError(
                    "cannot snapshot materialized fixture: " + "; ".join(errors)
                )
            _validate_materialized_projection(definition, baseline)
            expected_output = _reference_output_descriptor(
                root_descriptor,
                pinned_regulars=pinned_by_path,
            )
            if len(expected_output) > MAX_OUTPUT_BYTES:
                raise MaterializationError("trusted fixture exceeds output byte limit")
            reopened, reopened_metadata = _open_absolute_directory_no_follow(
                destination
            )
            try:
                if _filesystem_snapshot(reopened_metadata) != _filesystem_snapshot(
                    os.fstat(root_descriptor)
                ):
                    raise OSError("workspace changed during materialization")
            finally:
                os.close(reopened)
        except MaterializationError:
            _close_pinned_regulars(pinned_regulars)
            raise
        except (OSError, ValueError) as exc:
            _close_pinned_regulars(pinned_regulars)
            raise MaterializationError(
                f"cannot materialize workspace: {type(exc).__name__}: {exc}"
            ) from exc
        finally:
            if root_descriptor is not None:
                os.close(root_descriptor)
        return FixtureInstance(
            descriptor=expected_descriptor,
            workspace=destination,
            _baseline=baseline,
            _expected_output=expected_output,
            _suite_commitment=self._suite_commitment,
            _pinned_regulars=tuple(pinned_regulars),
        )

    def trusted_reference_output(self, instance: FixtureInstance) -> bytes:
        """Return the answer for trusted harness/audit code, never candidates."""

        self._validate_instance(instance)
        return instance._expected_output

    def _validate_instance(self, instance: FixtureInstance) -> None:
        if not isinstance(instance, FixtureInstance):
            raise FixtureVerificationError("instance must be a FixtureInstance")
        if instance._suite_commitment != self._suite_commitment:
            raise FixtureVerificationError("fixture instance belongs to another suite")
        expected, _ = self._resolve(instance.descriptor)
        if expected != instance.descriptor:
            raise FixtureVerificationError("fixture instance descriptor is invalid")

    def verify(self, instance: FixtureInstance) -> VerificationResult:
        """Verify output properties and the complete non-output tree state.

        This method is read-only. Retained close-on-exec descriptors provide
        non-mutating evidence for deliberately unreadable fixture decoys. It
        does not invoke a shell, subprocess, candidate, or container runtime.
        """

        self._validate_instance(instance)
        failures: list[VerificationFailure] = []
        try:
            root_descriptor, root_metadata = _open_absolute_directory_no_follow(
                instance.workspace
            )
        except OSError as exc:
            failures.append(
                VerificationFailure(
                    "workspace_unavailable", detail=type(exc).__name__
                )
            )
            return self._result(instance, failures, None, None)
        try:
            return self._verify_opened(instance, root_descriptor, root_metadata)
        finally:
            os.close(root_descriptor)

    def _verify_opened(
        self,
        instance: FixtureInstance,
        root_descriptor: int,
        root_metadata: os.stat_result,
    ) -> VerificationResult:
        failures: list[VerificationFailure] = []
        pinned_by_path = {
            item.path: item for item in instance._pinned_regulars
        }
        current, scan_errors = _scan_tree_descriptor(
            root_descriptor,
            exclude_top_level=frozenset({OUTPUT_RELATIVE_PATH}),
            pinned_regulars=pinned_by_path,
        )
        for detail in scan_errors:
            failures.append(VerificationFailure("tree_scan_error", detail=detail))

        baseline_by_path = {entry.path: entry for entry in instance._baseline}
        current_by_path = {entry.path: entry for entry in current}
        for path in sorted(
            baseline_by_path.keys() - current_by_path.keys(), key=str.encode
        ):
            failures.append(VerificationFailure("missing_input_path", path=path))
        for path in sorted(
            current_by_path.keys() - baseline_by_path.keys(), key=str.encode
        ):
            failures.append(VerificationFailure("unexpected_path", path=path))
        for path in sorted(
            baseline_by_path.keys() & current_by_path.keys(), key=str.encode
        ):
            if baseline_by_path[path] != current_by_path[path]:
                failures.append(VerificationFailure("input_entry_changed", path=path))

        try:
            output_metadata = os.stat(
                OUTPUT_RELATIVE_PATH,
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            failures.append(
                VerificationFailure("output_missing", path=OUTPUT_RELATIVE_PATH)
            )
            return self._result(instance, failures, None, None)
        except OSError as exc:
            failures.append(
                VerificationFailure(
                    "output_stat_error",
                    path=OUTPUT_RELATIVE_PATH,
                    detail=type(exc).__name__,
                )
            )
            return self._result(instance, failures, None, None)

        if not stat.S_ISREG(output_metadata.st_mode):
            failures.append(
                VerificationFailure("output_not_regular", path=OUTPUT_RELATIVE_PATH)
            )
            return self._result(instance, failures, None, None)
        if output_metadata.st_nlink != 1:
            failures.append(
                VerificationFailure("output_hardlinked", path=OUTPUT_RELATIVE_PATH)
            )
        if output_metadata.st_size > MAX_OUTPUT_BYTES:
            failures.append(
                VerificationFailure(
                    "output_too_large",
                    path=OUTPUT_RELATIVE_PATH,
                    detail=f"{output_metadata.st_size}>{MAX_OUTPUT_BYTES}",
                )
            )
            return self._result(instance, failures, None, None)

        try:
            payload = _read_regular_entry(
                root_descriptor,
                OUTPUT_RELATIVE_PATH,
                output_metadata,
                maximum_bytes=MAX_OUTPUT_BYTES,
            )
            if payload is None:  # guarded by the explicit size check above
                raise OSError("output exceeds its read limit")
            output_snapshot = _filesystem_snapshot(
                os.stat(
                    OUTPUT_RELATIVE_PATH,
                    dir_fd=root_descriptor,
                    follow_symlinks=False,
                )
            )
        except OSError as exc:
            failures.append(
                VerificationFailure(
                    "output_read_error",
                    path=OUTPUT_RELATIVE_PATH,
                    detail=type(exc).__name__,
                )
            )
            return self._result(instance, failures, None, None)

        final_current, final_scan_errors = _scan_tree_descriptor(
            root_descriptor,
            exclude_top_level=frozenset({OUTPUT_RELATIVE_PATH}),
            pinned_regulars=pinned_by_path,
        )
        for detail in final_scan_errors:
            failures.append(VerificationFailure("tree_scan_error", detail=detail))
        if final_current != current:
            failures.append(
                VerificationFailure(
                    "tree_scan_error", detail="tree_changed_during_verification"
                )
            )
        try:
            current_output = os.stat(
                OUTPUT_RELATIVE_PATH,
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
            reopened_descriptor, reopened_metadata = (
                _open_absolute_directory_no_follow(instance.workspace)
            )
        except OSError as exc:
            failures.append(
                VerificationFailure(
                    "tree_scan_error",
                    detail=f"workspace_changed:{type(exc).__name__}",
                )
            )
        else:
            try:
                if (
                    _filesystem_snapshot(current_output) != output_snapshot
                    or _filesystem_snapshot(os.fstat(root_descriptor))
                    != _filesystem_snapshot(root_metadata)
                    or _filesystem_snapshot(reopened_metadata)
                    != _filesystem_snapshot(root_metadata)
                ):
                    failures.append(
                        VerificationFailure(
                            "tree_scan_error",
                            detail="workspace_or_output_changed_during_verification",
                        )
                    )
            finally:
                os.close(reopened_descriptor)

        output_hash = sha256(payload).hexdigest()
        observed_labels: list[bytes] | None = None
        try:
            payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            failures.append(VerificationFailure("output_not_utf8"))
        else:
            framing_valid = True
            if b"\0" in payload:
                failures.append(VerificationFailure("output_contains_nul"))
                framing_valid = False
            if b"\r" in payload:
                failures.append(VerificationFailure("output_contains_cr"))
                framing_valid = False
            if payload and not payload.endswith(b"\n"):
                failures.append(VerificationFailure("output_missing_final_newline"))
                framing_valid = False
            if framing_valid:
                observed_labels = [] if not payload else payload[:-1].split(b"\n")
                if observed_labels != sorted(observed_labels):
                    failures.append(VerificationFailure("output_not_c_sorted"))
                if len(observed_labels) != len(set(observed_labels)):
                    failures.append(VerificationFailure("output_not_unique"))

        if payload != instance._expected_output:
            failures.append(VerificationFailure("output_labels_mismatch"))
        return self._result(instance, failures, observed_labels, output_hash)

    @staticmethod
    def _result(
        instance: FixtureInstance,
        failures: list[VerificationFailure],
        observed_labels: list[bytes] | None,
        output_hash: str | None,
    ) -> VerificationResult:
        return VerificationResult(
            fixture_id=instance.descriptor.fixture_id,
            passed=not failures,
            failures=tuple(failures),
            expected_label_count=(
                0
                if not instance._expected_output
                else len(instance._expected_output[:-1].split(b"\n"))
            ),
            observed_label_count=(
                None if observed_labels is None else len(observed_labels)
            ),
            output_sha256=output_hash,
        )


__all__ = [
    "CONTRACT_VERSION",
    "FIXTURE_SCHEMA_VERSION",
    "MAX_OUTPUT_BYTES",
    "MAX_TREE_DEPTH",
    "MAX_TREE_ENTRY_BYTES",
    "MAX_TREE_ENTRIES",
    "MAX_TREE_TOTAL_BYTES",
    "OUTPUT_RELATIVE_PATH",
    "REFERENCE_SEMANTICS_VERSION",
    "REQUIRED_EDGE_CASES",
    "TASK_ID",
    "TASK_PROMPT",
    "TASK_VERSION",
    "FixtureDescriptor",
    "FixtureInstance",
    "FixtureVerificationError",
    "MaterializationError",
    "StaticSliceError",
    "StaticSliceSuite",
    "VerificationFailure",
    "VerificationResult",
]
