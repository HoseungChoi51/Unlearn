"""Descriptor-relative workspace materialization for executable fixtures.

This module is deliberately a safety facade, not an executor or a verifier.  It
materializes trusted fixture inputs, binds their exact initial filesystem state,
and offers stable read-only scans before or after some *separate* harness has
operated on the workspace.  It never starts a process and it contains no claim
or execution-authorization decision.

The low-level filesystem operations are the already mutation-tested primitives
from :mod:`cbds.static_slice`: every path component is opened without following
symlinks, files are staged and linked through pinned directory descriptors, and
mode-unreadable fixture files retain close-on-exec read descriptors.  This
facade adds a generic, frozen definition model and an explicitly owned handle.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import threading
from typing import Final, Literal, TypeAlias

from . import static_slice as _static


WORKSPACE_SCHEMA_VERSION: Final[str] = "1.0.0"
INPUT_ROOT: Final[str] = "input"
INITIAL_OUTPUT_POLICY: Final[str] = "all-paths-outside-input-absent"
MAX_PATH_UTF8_BYTES: Final[int] = 4_096
MAX_PATH_COMPONENT_UTF8_BYTES: Final[int] = 255
MAX_FILE_BYTES: Final[int] = _static.MAX_TREE_ENTRY_BYTES
MAX_TOTAL_BYTES: Final[int] = _static.MAX_TREE_TOTAL_BYTES
MAX_ENTRIES: Final[int] = _static.MAX_TREE_ENTRIES
MAX_DEPTH: Final[int] = _static.MAX_TREE_DEPTH

_IDENTIFIER_RE: Final[re.Pattern[str]] = re.compile(
    r"[a-z0-9][a-z0-9._-]{2,127}\Z"
)
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_RESERVED_STAGE_PREFIX: Final[str] = ".cbds-stage-"

EntryKind: TypeAlias = Literal["directory", "file", "symlink", "other"]
ScanScope: TypeAlias = Literal["inputs", "outputs"]


class ExecutableWorkspaceError(ValueError):
    """Base error for workspace definitions, materialization, and scans."""


class WorkspaceDefinitionError(ExecutableWorkspaceError):
    """Raised when a fixture definition is unsafe or outside fixed bounds."""


class WorkspaceMaterializationError(ExecutableWorkspaceError):
    """Raised when inputs cannot be safely materialized and bound."""


class WorkspaceScanError(ExecutableWorkspaceError):
    """Raised when a read-only scan cannot establish one stable tree state."""


class WorkspaceClosedError(WorkspaceScanError):
    """Raised when a scan is attempted after its descriptor handle was closed."""


class WorkspaceOutputPolicyError(ExecutableWorkspaceError):
    """Raised when a stable output scan violates its declared exact policy."""


class WorkspaceOutputReadError(WorkspaceScanError):
    """Raised when bounded output bytes cannot be safely released to a verifier."""


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(value: object) -> str:
    return sha256(_canonical_json_bytes(value)).hexdigest()


def _validate_identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        raise WorkspaceDefinitionError(f"{label} must be a canonical identifier")
    return value


def _validate_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise WorkspaceDefinitionError(f"{label} must be a lowercase SHA-256")
    return value


def _validate_mode(value: object, label: str, *, optional: bool = False) -> int | None:
    if value is None and optional:
        return None
    if type(value) is not int or not 0 <= value <= 0o777:
        raise WorkspaceDefinitionError(
            f"{label} must contain only Unix permission bits 0000..0777"
        )
    return value


def _validate_nonnegative_int(
    value: object, label: str, *, maximum: int
) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise WorkspaceDefinitionError(f"{label} must be between 0 and {maximum}")
    return value


def _validate_relative_path(value: object, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value:
        raise WorkspaceDefinitionError(f"{label} must be a nonempty string")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise WorkspaceDefinitionError(f"{label} contains a control character")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise WorkspaceDefinitionError(f"{label} is not valid Unicode text") from exc
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or value.startswith("//")
        or path.as_posix() != value
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise WorkspaceDefinitionError(f"{label} must be a canonical safe relative path")
    if len(encoded) > MAX_PATH_UTF8_BYTES:
        raise WorkspaceDefinitionError(f"{label} exceeds the UTF-8 path limit")
    if len(path.parts) > MAX_DEPTH:
        raise WorkspaceDefinitionError(f"{label} exceeds the path-depth limit")
    for part in path.parts:
        if len(part.encode("utf-8")) > MAX_PATH_COMPONENT_UTF8_BYTES:
            raise WorkspaceDefinitionError(f"{label} has an oversized path component")
        if part.startswith(_RESERVED_STAGE_PREFIX):
            raise WorkspaceDefinitionError(f"{label} uses a reserved staging prefix")
    return path


def _validate_input_path(value: object, label: str) -> PurePosixPath:
    path = _validate_relative_path(value, label)
    if len(path.parts) < 2 or path.parts[0] != INPUT_ROOT:
        raise WorkspaceDefinitionError(f"{label} must be strictly below input/")
    return path


def _validate_output_path(value: object, label: str) -> PurePosixPath:
    path = _validate_relative_path(value, label)
    if path.parts[0] == INPUT_ROOT:
        raise WorkspaceDefinitionError(f"{label} must be outside input/")
    return path


def _validate_symlink_target(value: object, label: str) -> PurePosixPath:
    # A target is interpreted relative to the link's parent.  Forbidding every
    # ``..`` component makes it impossible for a fixture link to escape that
    # already descriptor-pinned subtree.
    return _validate_relative_path(value, label)


@dataclass(frozen=True, slots=True)
class InputFile:
    """One immutable regular-file input to materialize below ``input/``."""

    path: str
    content: bytes = field(repr=False)
    mode: int = 0o644

    def __post_init__(self) -> None:
        _validate_input_path(self.path, "InputFile.path")
        if type(self.content) is not bytes:
            raise WorkspaceDefinitionError("InputFile.content must be immutable bytes")
        if len(self.content) > MAX_FILE_BYTES:
            raise WorkspaceDefinitionError("InputFile.content exceeds the per-file limit")
        _validate_mode(self.mode, "InputFile.mode")

    def to_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "kind": "file",
            "path": self.path,
            "mode": self.mode,
            "size": len(self.content),
            "sha256": sha256(self.content).hexdigest(),
        }


@dataclass(frozen=True, slots=True)
class InputSymlink:
    """One non-escaping symbolic-link input below ``input/``."""

    path: str
    target: str

    def __post_init__(self) -> None:
        _validate_input_path(self.path, "InputSymlink.path")
        _validate_symlink_target(self.target, "InputSymlink.target")

    def to_record(self) -> dict[str, object]:
        self.__post_init__()
        return {"kind": "symlink", "path": self.path, "target": self.target}


@dataclass(frozen=True, slots=True)
class ExpectedFile:
    """Public output safety boundary, intentionally containing no answer."""

    path: str
    maximum_bytes: int = MAX_FILE_BYTES
    mode: int | None = None

    def __post_init__(self) -> None:
        _validate_output_path(self.path, "ExpectedFile.path")
        _validate_nonnegative_int(
            self.maximum_bytes,
            "ExpectedFile.maximum_bytes",
            maximum=MAX_FILE_BYTES,
        )
        _validate_mode(self.mode, "ExpectedFile.mode", optional=True)

    def to_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "path": self.path,
            "maximum_bytes": self.maximum_bytes,
            "mode": self.mode,
            "required_kind": "regular",
            "required_link_count": 1,
        }


InputEntry: TypeAlias = InputFile | InputSymlink


def _ancestors(path: PurePosixPath) -> tuple[PurePosixPath, ...]:
    return tuple(parent for parent in path.parents if parent != PurePosixPath("."))


@dataclass(frozen=True, slots=True)
class FixtureDefinition:
    """Frozen trusted inputs plus answer-free expected-file boundaries."""

    fixture_id: str
    inputs: tuple[InputEntry, ...]
    expected_files: tuple[ExpectedFile, ...]
    schema_version: str = WORKSPACE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _validate_identifier(self.fixture_id, "FixtureDefinition.fixture_id")
        if self.schema_version != WORKSPACE_SCHEMA_VERSION:
            raise WorkspaceDefinitionError(
                f"FixtureDefinition.schema_version must equal {WORKSPACE_SCHEMA_VERSION!r}"
            )
        if type(self.inputs) is not tuple or any(
            type(item) not in {InputFile, InputSymlink} for item in self.inputs
        ):
            raise WorkspaceDefinitionError(
                "FixtureDefinition.inputs must be a tuple of InputFile/InputSymlink"
            )
        if type(self.expected_files) is not tuple or any(
            type(item) is not ExpectedFile for item in self.expected_files
        ):
            raise WorkspaceDefinitionError(
                "FixtureDefinition.expected_files must be a tuple of ExpectedFile"
            )

        for item in self.inputs:
            item.__post_init__()
        for item in self.expected_files:
            item.__post_init__()

        input_paths = [_validate_input_path(item.path, "fixture input path") for item in self.inputs]
        output_paths = [
            _validate_output_path(item.path, "fixture expected path")
            for item in self.expected_files
        ]
        all_paths = input_paths + output_paths
        path_texts = [item.as_posix() for item in all_paths]
        if len(path_texts) != len(set(path_texts)):
            raise WorkspaceDefinitionError("fixture paths contain a duplicate")
        leaf_paths = set(all_paths)
        for path in all_paths:
            if any(parent in leaf_paths for parent in _ancestors(path)):
                raise WorkspaceDefinitionError(
                    "fixture paths contain a file/symlink ancestor conflict"
                )

        directories: set[PurePosixPath] = {PurePosixPath(INPUT_ROOT)}
        for path in all_paths:
            directories.update(_ancestors(path))
        # Include future expected files in the ceiling: a safe materialization
        # must remain scannable after every declared output has been created.
        projected_entries = len(directories) + len(self.inputs) + len(self.expected_files)
        if projected_entries > MAX_ENTRIES:
            raise WorkspaceDefinitionError("fixture exceeds the workspace entry limit")
        input_bytes = sum(
            len(item.content) for item in self.inputs if isinstance(item, InputFile)
        )
        output_bytes = sum(item.maximum_bytes for item in self.expected_files)
        if input_bytes + output_bytes > MAX_TOTAL_BYTES:
            raise WorkspaceDefinitionError("fixture exceeds the workspace byte limit")

    def commitment_record(self) -> dict[str, object]:
        self.__post_init__()
        inputs = sorted(
            (item.to_record() for item in self.inputs),
            key=lambda item: str(item["path"]).encode("utf-8"),
        )
        expected = sorted(
            (item.to_record() for item in self.expected_files),
            key=lambda item: str(item["path"]).encode("utf-8"),
        )
        return {
            "schema_version": self.schema_version,
            "record_type": "cbds.executable-fixture-definition",
            "fixture_id": self.fixture_id,
            "input_root": INPUT_ROOT,
            "initial_output_policy": INITIAL_OUTPUT_POLICY,
            "inputs": inputs,
            "expected_files": expected,
            "limits": {
                "maximum_depth": MAX_DEPTH,
                "maximum_entries": MAX_ENTRIES,
                "maximum_file_bytes": MAX_FILE_BYTES,
                "maximum_total_bytes": MAX_TOTAL_BYTES,
            },
        }

    @property
    def fixture_sha256(self) -> str:
        return _digest(self.commitment_record())


@dataclass(frozen=True, slots=True)
class WorkspaceEntry:
    """One no-follow filesystem observation from a stable scan."""

    path: str
    kind: EntryKind
    mode: int
    size: int
    mtime_ns: int
    link_count: int
    content_sha256: str | None = None
    symlink_target: str | None = None

    def __post_init__(self) -> None:
        _validate_relative_path(self.path, "WorkspaceEntry.path")
        if self.kind not in {"directory", "file", "symlink", "other"}:
            raise WorkspaceDefinitionError("WorkspaceEntry.kind is invalid")
        _validate_mode(self.mode, "WorkspaceEntry.mode")
        for label, value in (
            ("WorkspaceEntry.size", self.size),
            ("WorkspaceEntry.mtime_ns", self.mtime_ns),
            ("WorkspaceEntry.link_count", self.link_count),
        ):
            if type(value) is not int or value < 0:
                raise WorkspaceDefinitionError(f"{label} must be a nonnegative integer")
        if self.content_sha256 is not None:
            _validate_sha256(self.content_sha256, "WorkspaceEntry.content_sha256")
        if self.kind == "symlink":
            if not isinstance(self.symlink_target, str):
                raise WorkspaceDefinitionError("symlink entry requires its literal target")
            if self.content_sha256 is not None:
                raise WorkspaceDefinitionError("symlink entry cannot have a content hash")
        elif self.symlink_target is not None:
            raise WorkspaceDefinitionError("non-symlink entry cannot have a symlink target")
        if self.kind != "file" and self.content_sha256 is not None:
            raise WorkspaceDefinitionError("only regular files may have content hashes")

    def to_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "path": self.path,
            "kind": self.kind,
            "mode": self.mode,
            "size": self.size,
            "mtime_ns": self.mtime_ns,
            "link_count": self.link_count,
            "content_sha256": self.content_sha256,
            "symlink_target": self.symlink_target,
        }


def _entries_digest(scope: str, entries: Iterable[WorkspaceEntry]) -> str:
    return _digest(
        {
            "contract": "cbds.executable-workspace-scan",
            "version": WORKSPACE_SCHEMA_VERSION,
            "scope": scope,
            "entries": [item.to_record() for item in entries],
        }
    )


@dataclass(frozen=True, slots=True)
class WorkspaceBaseline:
    """Content-addressed initial tree state bound to one materialization."""

    fixture_id: str
    fixture_sha256: str
    workspace_identity_sha256: str
    input_entries: tuple[WorkspaceEntry, ...]
    output_scaffold_entries: tuple[WorkspaceEntry, ...]
    input_tree_sha256: str
    output_scaffold_sha256: str
    baseline_sha256: str
    schema_version: str = WORKSPACE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _validate_identifier(self.fixture_id, "WorkspaceBaseline.fixture_id")
        if self.schema_version != WORKSPACE_SCHEMA_VERSION:
            raise WorkspaceDefinitionError("WorkspaceBaseline.schema_version is invalid")
        for label, value in (
            ("fixture_sha256", self.fixture_sha256),
            ("workspace_identity_sha256", self.workspace_identity_sha256),
            ("input_tree_sha256", self.input_tree_sha256),
            ("output_scaffold_sha256", self.output_scaffold_sha256),
            ("baseline_sha256", self.baseline_sha256),
        ):
            _validate_sha256(value, f"WorkspaceBaseline.{label}")
        if type(self.input_entries) is not tuple or not all(
            type(item) is WorkspaceEntry for item in self.input_entries
        ):
            raise WorkspaceDefinitionError("WorkspaceBaseline.input_entries is invalid")
        if type(self.output_scaffold_entries) is not tuple or not all(
            type(item) is WorkspaceEntry for item in self.output_scaffold_entries
        ):
            raise WorkspaceDefinitionError(
                "WorkspaceBaseline.output_scaffold_entries is invalid"
            )
        if self.output_scaffold_entries:
            raise WorkspaceDefinitionError(
                "WorkspaceBaseline requires every initial output path to be absent"
            )
        for item in (*self.input_entries, *self.output_scaffold_entries):
            item.__post_init__()
        if self.input_tree_sha256 != _entries_digest("inputs", self.input_entries):
            raise WorkspaceDefinitionError("WorkspaceBaseline input hash differs")
        if self.output_scaffold_sha256 != _entries_digest(
            "outputs", self.output_scaffold_entries
        ):
            raise WorkspaceDefinitionError("WorkspaceBaseline scaffold hash differs")
        if self.baseline_sha256 != _digest(self._core_record()):
            raise WorkspaceDefinitionError("WorkspaceBaseline content address differs")

    def _core_record(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "record_type": "cbds.executable-workspace-baseline",
            "fixture_id": self.fixture_id,
            "fixture_sha256": self.fixture_sha256,
            "initial_output_policy": INITIAL_OUTPUT_POLICY,
            "workspace_identity_sha256": self.workspace_identity_sha256,
            "input_tree_sha256": self.input_tree_sha256,
            "output_scaffold_sha256": self.output_scaffold_sha256,
            "input_entries": [item.to_record() for item in self.input_entries],
            "output_scaffold_entries": [
                item.to_record() for item in self.output_scaffold_entries
            ],
        }

    def to_record(self) -> dict[str, object]:
        self.__post_init__()
        return {**self._core_record(), "baseline_sha256": self.baseline_sha256}


@dataclass(frozen=True, slots=True)
class WorkspaceScan:
    """A stable read-only scan bound to a workspace baseline."""

    scope: ScanScope
    entries: tuple[WorkspaceEntry, ...]
    tree_sha256: str
    baseline_sha256: str
    schema_version: str = WORKSPACE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != WORKSPACE_SCHEMA_VERSION:
            raise WorkspaceDefinitionError("WorkspaceScan.schema_version is invalid")
        if self.scope not in {"inputs", "outputs"}:
            raise WorkspaceDefinitionError("WorkspaceScan.scope is invalid")
        if type(self.entries) is not tuple or not all(
            type(item) is WorkspaceEntry for item in self.entries
        ):
            raise WorkspaceDefinitionError("WorkspaceScan.entries is invalid")
        for item in self.entries:
            item.__post_init__()
        if (
            tuple(sorted(self.entries, key=lambda item: item.path.encode("utf-8")))
            != self.entries
        ):
            raise WorkspaceDefinitionError("WorkspaceScan.entries are not in canonical order")
        _validate_sha256(self.tree_sha256, "WorkspaceScan.tree_sha256")
        _validate_sha256(self.baseline_sha256, "WorkspaceScan.baseline_sha256")
        if self.tree_sha256 != _entries_digest(self.scope, self.entries):
            raise WorkspaceDefinitionError("WorkspaceScan tree hash differs")

    def to_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "schema_version": self.schema_version,
            "record_type": "cbds.executable-workspace-scan",
            "scope": self.scope,
            "baseline_sha256": self.baseline_sha256,
            "tree_sha256": self.tree_sha256,
            "entries": [item.to_record() for item in self.entries],
        }


def validate_expected_output_policy(
    definition: FixtureDefinition, scan: WorkspaceScan
) -> tuple[WorkspaceEntry, ...]:
    """Validate one stable output scan against an exact answer-free policy.

    The only permitted output paths are the declared regular files and the
    directories strictly required to contain them.  This validator never opens
    a path: it consumes the no-follow observations already bound by
    :class:`WorkspaceScan`.  It therefore cannot authorize execution or attest
    functional correctness; it only enforces the public filesystem boundary.
    """

    if type(definition) is not FixtureDefinition:
        raise WorkspaceOutputPolicyError(
            "output policy definition must be a FixtureDefinition"
        )
    if type(scan) is not WorkspaceScan:
        raise WorkspaceOutputPolicyError(
            "output policy requires a stable outputs WorkspaceScan"
        )
    try:
        definition.__post_init__()
        scan.__post_init__()
    except WorkspaceDefinitionError as exc:
        raise WorkspaceOutputPolicyError(
            "output policy inputs failed closed-contract revalidation"
        ) from exc
    if scan.scope != "outputs":
        raise WorkspaceOutputPolicyError(
            "output policy requires a stable outputs WorkspaceScan"
        )

    expected_by_path = {item.path: item for item in definition.expected_files}
    required_directories: set[str] = set()
    for path_text in expected_by_path:
        path = _validate_output_path(path_text, "fixture expected path")
        required_directories.update(
            parent.as_posix() for parent in _ancestors(path)
        )
    permitted_paths = set(expected_by_path) | required_directories

    observed: dict[str, WorkspaceEntry] = {}
    for entry in scan.entries:
        if entry.path in observed:
            raise WorkspaceOutputPolicyError(
                "output scan contains a duplicate path observation"
            )
        observed[entry.path] = entry
    observed_paths = set(observed)
    missing = sorted(
        permitted_paths - observed_paths, key=lambda item: item.encode("utf-8")
    )
    extra = sorted(
        observed_paths - permitted_paths, key=lambda item: item.encode("utf-8")
    )
    if missing or extra:
        details: list[str] = []
        if missing:
            details.append("missing=" + ",".join(missing))
        if extra:
            details.append("extra=" + ",".join(extra))
        raise WorkspaceOutputPolicyError(
            "output paths differ from exact policy: " + "; ".join(details)
        )

    for path in required_directories:
        if observed[path].kind != "directory" or observed[path].mode != 0o755:
            raise WorkspaceOutputPolicyError(
                f"expected output ancestor is not a real mode-0755 directory: {path}"
            )

    validated: list[WorkspaceEntry] = []
    for path, expected in sorted(
        expected_by_path.items(), key=lambda item: item[0].encode("utf-8")
    ):
        entry = observed[path]
        if entry.kind != "file" or entry.symlink_target is not None:
            raise WorkspaceOutputPolicyError(
                f"expected output is not a no-follow regular file: {path}"
            )
        if entry.link_count != 1:
            raise WorkspaceOutputPolicyError(
                f"expected output does not have link count one: {path}"
            )
        if entry.size > expected.maximum_bytes:
            raise WorkspaceOutputPolicyError(
                f"expected output exceeds its per-file byte limit: {path}"
            )
        if expected.mode is not None and entry.mode != expected.mode:
            raise WorkspaceOutputPolicyError(
                f"expected output mode differs from policy: {path}"
            )
        if entry.content_sha256 is None:
            raise WorkspaceOutputPolicyError(
                f"expected output lacks a stable content digest: {path}"
            )
        validated.append(entry)
    return tuple(validated)


def _workspace_entry(item: _static._TreeEntry, *, prefix: str = "") -> WorkspaceEntry:
    path = item.path if not prefix else f"{prefix}/{item.path}"
    return WorkspaceEntry(
        path=path,
        kind=item.kind,
        mode=item.mode,
        size=item.size,
        mtime_ns=item.mtime_ns,
        link_count=item.link_count,
        content_sha256=item.content_sha256,
        symlink_target=item.symlink_target,
    )


def _directory_entry(path: str, metadata: os.stat_result) -> WorkspaceEntry:
    if not stat.S_ISDIR(metadata.st_mode):
        raise WorkspaceScanError(f"{path} is no longer a real directory")
    return WorkspaceEntry(
        path=path,
        kind="directory",
        mode=stat.S_IMODE(metadata.st_mode),
        size=metadata.st_size,
        mtime_ns=metadata.st_mtime_ns,
        link_count=metadata.st_nlink,
    )


def _regular_metadata_matches_entry(
    metadata: os.stat_result, entry: WorkspaceEntry
) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and stat.S_IMODE(metadata.st_mode) == entry.mode
        and metadata.st_size == entry.size
        and metadata.st_mtime_ns == entry.mtime_ns
        and metadata.st_nlink == entry.link_count
    )


def _read_output_descriptor(
    descriptor: int, advertised_size: int, maximum_bytes: int
) -> bytes:
    """Read exactly one already-open output inode within its declared bound."""

    payload = _static._read_exact_fd(
        descriptor, advertised_size, maximum_bytes
    )
    if payload is None:
        raise OSError("output exceeds its declared byte limit")
    return payload


def _workspace_identity(metadata: os.stat_result) -> str:
    return _digest(
        {
            "contract": "cbds.executable-workspace-inode",
            "version": WORKSPACE_SCHEMA_VERSION,
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "file_type": stat.S_IFMT(metadata.st_mode),
        }
    )


def _make_baseline(
    definition: FixtureDefinition,
    workspace_metadata: os.stat_result,
    entries: tuple[WorkspaceEntry, ...],
) -> WorkspaceBaseline:
    inputs = tuple(
        item
        for item in entries
        if item.path == INPUT_ROOT or item.path.startswith(INPUT_ROOT + "/")
    )
    scaffold = tuple(item for item in entries if item not in inputs)
    input_hash = _entries_digest("inputs", inputs)
    scaffold_hash = _entries_digest("outputs", scaffold)
    core = {
        "schema_version": WORKSPACE_SCHEMA_VERSION,
        "record_type": "cbds.executable-workspace-baseline",
        "fixture_id": definition.fixture_id,
        "fixture_sha256": definition.fixture_sha256,
        "initial_output_policy": INITIAL_OUTPUT_POLICY,
        "workspace_identity_sha256": _workspace_identity(workspace_metadata),
        "input_tree_sha256": input_hash,
        "output_scaffold_sha256": scaffold_hash,
        "input_entries": [item.to_record() for item in inputs],
        "output_scaffold_entries": [item.to_record() for item in scaffold],
    }
    return WorkspaceBaseline(
        fixture_id=definition.fixture_id,
        fixture_sha256=definition.fixture_sha256,
        workspace_identity_sha256=core["workspace_identity_sha256"],
        input_entries=inputs,
        output_scaffold_entries=scaffold,
        input_tree_sha256=input_hash,
        output_scaffold_sha256=scaffold_hash,
        baseline_sha256=_digest(core),
    )


def _expected_projection(definition: FixtureDefinition) -> tuple[set[str], dict[str, InputEntry]]:
    """Return the exact initial projection, before any candidate behavior.

    Expected output files and their ancestors are intentionally absent.  A
    candidate that needs a nested output directory must create it itself; that
    behavior is visible in the later output scan.
    """

    directories: set[PurePosixPath] = {PurePosixPath(INPUT_ROOT)}
    leaves: dict[str, InputEntry] = {}
    for item in definition.inputs:
        path = _validate_input_path(item.path, "fixture input path")
        leaves[path.as_posix()] = item
        directories.update(_ancestors(path))
    return {item.as_posix() for item in directories}, leaves


def _validate_materialized_projection(
    definition: FixtureDefinition, entries: tuple[WorkspaceEntry, ...]
) -> None:
    directories, leaves = _expected_projection(definition)
    observed = {item.path: item for item in entries}
    if set(observed) != directories | set(leaves):
        raise WorkspaceMaterializationError(
            "materialized workspace path projection differs from its definition"
        )
    for path in directories:
        entry = observed[path]
        if entry.kind != "directory" or entry.mode != 0o755:
            raise WorkspaceMaterializationError(
                "materialized workspace directory projection differs"
            )
    for path, expected in leaves.items():
        entry = observed[path]
        if isinstance(expected, InputFile):
            if (
                entry.kind != "file"
                or entry.mode != expected.mode
                or entry.size != len(expected.content)
                or entry.link_count != 1
                or entry.content_sha256 != sha256(expected.content).hexdigest()
            ):
                raise WorkspaceMaterializationError(
                    "materialized regular input differs from its definition"
                )
        elif (
            entry.kind != "symlink" or entry.symlink_target != expected.target
        ):
            raise WorkspaceMaterializationError(
                "materialized symlink input differs from its definition"
            )


def _scan_materialized_projection_once(
    root_descriptor: int,
    pinned_by_path: Mapping[str, _static._PinnedRegular],
) -> tuple[WorkspaceEntry, ...]:
    scanned, errors = _static._scan_tree_descriptor(
        root_descriptor, pinned_regulars=pinned_by_path
    )
    if errors:
        raise WorkspaceMaterializationError(
            "cannot bind materialized workspace: " + "; ".join(errors)
        )
    return tuple(_workspace_entry(item) for item in scanned)


def _assert_named_materialization_workspace(
    destination: Path, root_descriptor: int
) -> os.stat_result:
    try:
        reopened, reopened_metadata = _static._open_absolute_directory_no_follow(
            destination
        )
    except OSError as exc:
        raise WorkspaceMaterializationError(
            "workspace path is unavailable at materialization boundary: "
            f"{type(exc).__name__}"
        ) from exc
    try:
        current_metadata = os.fstat(root_descriptor)
        if not _static._same_inode(current_metadata, reopened_metadata):
            raise WorkspaceMaterializationError(
                "workspace path changed during materialization"
            )
        return current_metadata
    finally:
        os.close(reopened)


def _assert_final_materialization_boundary(
    destination: Path,
    root_descriptor: int,
    pinned_by_path: Mapping[str, _static._PinnedRegular],
    baseline_entries: tuple[WorkspaceEntry, ...],
) -> None:
    """Linearize return against a final named-workspace double scan."""

    _assert_named_materialization_workspace(destination, root_descriptor)
    before = _static._filesystem_snapshot(os.fstat(root_descriptor))
    first = _scan_materialized_projection_once(root_descriptor, pinned_by_path)
    second = _scan_materialized_projection_once(root_descriptor, pinned_by_path)
    after = _static._filesystem_snapshot(os.fstat(root_descriptor))
    _assert_named_materialization_workspace(destination, root_descriptor)
    if first != second or before != after:
        raise WorkspaceMaterializationError(
            "workspace changed during final materialization double scan"
        )
    if first != baseline_entries:
        raise WorkspaceMaterializationError(
            "workspace differs from its baseline at the final named boundary"
        )


class WorkspaceHandle:
    """Owned descriptor handle for stable read-only input and output scans."""

    __slots__ = (
        "_baseline",
        "_expected_files",
        "_lock",
        "_pinned_regulars",
        "_root_descriptor",
        "_workspace",
    )

    def __init__(
        self,
        *,
        workspace: Path,
        root_descriptor: int,
        baseline: WorkspaceBaseline,
        expected_files: tuple[ExpectedFile, ...],
        pinned_regulars: tuple[_static._PinnedRegular, ...],
    ) -> None:
        self._workspace = workspace
        self._root_descriptor = root_descriptor
        self._baseline = baseline
        self._expected_files = expected_files
        self._pinned_regulars = pinned_regulars
        self._lock = threading.RLock()

    @property
    def workspace(self) -> Path:
        return self._workspace

    @property
    def baseline(self) -> WorkspaceBaseline:
        return self._baseline

    @property
    def expected_files(self) -> tuple[ExpectedFile, ...]:
        return tuple(self._expected_files)

    @property
    def closed(self) -> bool:
        return self._root_descriptor < 0

    def _require_open(self) -> int:
        if self._root_descriptor < 0:
            raise WorkspaceClosedError("workspace handle is closed")
        return self._root_descriptor

    def _assert_named_workspace(self, descriptor: int) -> None:
        try:
            reopened, metadata = _static._open_absolute_directory_no_follow(
                self._workspace
            )
        except OSError as exc:
            raise WorkspaceScanError(
                f"workspace path is unavailable: {type(exc).__name__}"
            ) from exc
        try:
            opened = os.fstat(descriptor)
            if not _static._same_inode(opened, metadata):
                raise WorkspaceScanError(
                    "workspace path no longer names the pinned workspace"
                )
        finally:
            os.close(reopened)

    @staticmethod
    def _raise_scan_errors(errors: tuple[str, ...]) -> None:
        if errors:
            raise WorkspaceScanError("workspace scan failed: " + "; ".join(errors))

    def _scan_inputs_once(self, descriptor: int) -> tuple[WorkspaceEntry, ...]:
        try:
            input_descriptor = _static._open_relative_directory(
                descriptor, PurePosixPath(INPUT_ROOT)
            )
        except OSError as exc:
            raise WorkspaceScanError(
                f"input tree is unavailable: {type(exc).__name__}"
            ) from exc
        try:
            input_before = os.fstat(input_descriptor)
            pinned = {
                item.path.removeprefix(INPUT_ROOT + "/"): item
                for item in self._pinned_regulars
                if item.path.startswith(INPUT_ROOT + "/")
            }
            scanned, errors = _static._scan_tree_descriptor(
                input_descriptor, pinned_regulars=pinned
            )
            self._raise_scan_errors(errors)
            _static._assert_relative_directory_reachable(
                descriptor, input_descriptor, PurePosixPath(INPUT_ROOT)
            )
            if _static._filesystem_snapshot(os.fstat(input_descriptor)) != _static._filesystem_snapshot(
                input_before
            ):
                raise WorkspaceScanError("input directory changed during scan")
            entries = (_directory_entry(INPUT_ROOT, input_before),) + tuple(
                _workspace_entry(item, prefix=INPUT_ROOT) for item in scanned
            )
            return tuple(sorted(entries, key=lambda item: item.path.encode("utf-8")))
        finally:
            os.close(input_descriptor)

    def _scan_outputs_once(self, descriptor: int) -> tuple[WorkspaceEntry, ...]:
        scanned, errors = _static._scan_tree_descriptor(
            descriptor, exclude_top_level=frozenset({INPUT_ROOT})
        )
        self._raise_scan_errors(errors)
        return tuple(_workspace_entry(item) for item in scanned)

    def _stable_scan(self, scope: ScanScope) -> WorkspaceScan:
        with self._lock:
            descriptor = self._require_open()
            self._assert_named_workspace(descriptor)
            before = _static._filesystem_snapshot(os.fstat(descriptor))
            scan_once = (
                self._scan_inputs_once if scope == "inputs" else self._scan_outputs_once
            )
            first = scan_once(descriptor)
            second = scan_once(descriptor)
            after = _static._filesystem_snapshot(os.fstat(descriptor))
            self._assert_named_workspace(descriptor)
            if first != second or before != after:
                raise WorkspaceScanError("workspace changed during stable scan")
            return WorkspaceScan(
                scope=scope,
                entries=first,
                tree_sha256=_entries_digest(scope, first),
                baseline_sha256=self._baseline.baseline_sha256,
            )

    def scan_inputs(self) -> WorkspaceScan:
        """Return one stable no-follow snapshot of ``input/`` and descendants."""

        return self._stable_scan("inputs")

    def scan_outputs(self) -> WorkspaceScan:
        """Return one stable no-follow snapshot of everything outside ``input/``."""

        return self._stable_scan("outputs")

    def read_output_bytes(self, scan: WorkspaceScan, path: str) -> bytes:
        """Release one declared, bounded output file to a separate verifier.

        ``scan`` must still be the exact current output-tree observation from
        this handle.  The path is opened below the pinned workspace descriptor
        without following any component, and the whole output scan is
        re-established after the byte read.  This method performs no semantic
        comparison and never executes candidate or verifier code.
        """

        with self._lock:
            descriptor = self._require_open()
            if type(scan) is not WorkspaceScan:
                raise WorkspaceOutputReadError(
                    "output egress requires an outputs WorkspaceScan"
                )
            try:
                scan.__post_init__()
            except WorkspaceDefinitionError as exc:
                raise WorkspaceOutputReadError(
                    "output egress scan failed closed-contract revalidation"
                ) from exc
            if scan.scope != "outputs":
                raise WorkspaceOutputReadError(
                    "output egress requires an outputs WorkspaceScan"
                )
            if scan.baseline_sha256 != self._baseline.baseline_sha256:
                raise WorkspaceOutputReadError(
                    "output scan is not bound to this workspace baseline"
                )
            try:
                relative = _validate_output_path(path, "output egress path")
            except WorkspaceDefinitionError as exc:
                raise WorkspaceOutputReadError(
                    "output egress path is not a canonical safe output path"
                ) from exc
            expected = next(
                (item for item in self._expected_files if item.path == path),
                None,
            )
            if expected is None:
                raise WorkspaceOutputReadError(
                    "output egress path is not declared by the fixture"
                )

            try:
                current_before = self._stable_scan("outputs")
            except WorkspaceScanError as exc:
                raise WorkspaceOutputReadError(
                    "cannot establish the current output scan before egress"
                ) from exc
            if current_before != scan:
                raise WorkspaceOutputReadError(
                    "supplied output scan is stale or does not match this workspace"
                )
            matching = tuple(item for item in scan.entries if item.path == path)
            if len(matching) != 1:
                raise WorkspaceOutputReadError(
                    "declared output path is absent or duplicated in the scan"
                )
            entry = matching[0]
            if entry.kind != "file" or entry.symlink_target is not None:
                raise WorkspaceOutputReadError(
                    "declared output path is not a no-follow regular file"
                )
            if entry.link_count != 1:
                raise WorkspaceOutputReadError(
                    "declared output does not have link count one"
                )
            if entry.size > expected.maximum_bytes:
                raise WorkspaceOutputReadError(
                    "declared output exceeds its per-file byte limit"
                )
            if expected.mode is not None and entry.mode != expected.mode:
                raise WorkspaceOutputReadError(
                    "declared output mode differs from its fixture policy"
                )
            if entry.content_sha256 is None:
                raise WorkspaceOutputReadError(
                    "declared output scan lacks a stable content digest"
                )

            parent_descriptor: int | None = None
            output_descriptor: int | None = None
            try:
                self._assert_named_workspace(descriptor)
                parent_descriptor = _static._open_relative_directory(
                    descriptor, relative.parent
                )
                _static._assert_relative_directory_reachable(
                    descriptor, parent_descriptor, relative.parent
                )
                named_before = os.stat(
                    relative.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                output_descriptor = os.open(
                    relative.name,
                    _static._regular_open_flags(),
                    dir_fd=parent_descriptor,
                )
                opened_before = os.fstat(output_descriptor)
                if (
                    _static._filesystem_snapshot(opened_before)
                    != _static._filesystem_snapshot(named_before)
                    or not _regular_metadata_matches_entry(opened_before, entry)
                ):
                    raise WorkspaceOutputReadError(
                        "declared output changed between its scan and open"
                    )

                payload = _read_output_descriptor(
                    output_descriptor, entry.size, expected.maximum_bytes
                )
                opened_after = os.fstat(output_descriptor)
                named_after = os.stat(
                    relative.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                if (
                    _static._filesystem_snapshot(opened_after)
                    != _static._filesystem_snapshot(opened_before)
                    or _static._filesystem_snapshot(named_after)
                    != _static._filesystem_snapshot(opened_after)
                    or not _regular_metadata_matches_entry(opened_after, entry)
                ):
                    raise WorkspaceOutputReadError(
                        "declared output changed while its bytes were read"
                    )
                if len(payload) != entry.size:
                    raise WorkspaceOutputReadError(
                        "declared output byte count differs from its scan"
                    )
                if sha256(payload).hexdigest() != entry.content_sha256:
                    raise WorkspaceOutputReadError(
                        "declared output digest differs from its scan"
                    )
                _static._assert_relative_directory_reachable(
                    descriptor, parent_descriptor, relative.parent
                )
                self._assert_named_workspace(descriptor)
            except WorkspaceOutputReadError:
                raise
            except (OSError, WorkspaceScanError) as exc:
                raise WorkspaceOutputReadError(
                    f"cannot safely read declared output: {type(exc).__name__}"
                ) from exc
            finally:
                if output_descriptor is not None:
                    os.close(output_descriptor)
                if parent_descriptor is not None:
                    os.close(parent_descriptor)

            try:
                current_after = self._stable_scan("outputs")
            except WorkspaceScanError as exc:
                raise WorkspaceOutputReadError(
                    "cannot re-establish the output scan after egress"
                ) from exc
            if current_after != scan:
                raise WorkspaceOutputReadError(
                    "output tree changed while verifier bytes were released"
                )
            return payload

    def duplicate_launch_directory(self) -> int:
        """Return one close-on-exec duplicate of the pinned workspace directory.

        This is a transport primitive for a separately reviewed namespace
        controller.  It does not make the workspace executable or authorize a
        candidate.  The caller owns the returned descriptor and must close it.
        Revalidating the named workspace on both sides of ``dup`` prevents a
        caller from silently converting a stale handle into a launch path.
        """

        duplicate: int | None = None
        with self._lock:
            descriptor = self._require_open()
            self._assert_named_workspace(descriptor)
            try:
                duplicate = os.dup(descriptor)
                os.set_inheritable(duplicate, False)
                source_metadata = os.fstat(descriptor)
                duplicate_metadata = os.fstat(duplicate)
                access_mode = fcntl.fcntl(duplicate, fcntl.F_GETFL) & os.O_ACCMODE
                if (
                    not _static._same_inode(source_metadata, duplicate_metadata)
                    or not stat.S_ISDIR(duplicate_metadata.st_mode)
                    or access_mode != os.O_RDONLY
                    or os.get_inheritable(duplicate)
                ):
                    raise WorkspaceScanError(
                        "workspace launch descriptor is not an exact read-only duplicate"
                    )
                self._assert_named_workspace(descriptor)
                result = duplicate
                duplicate = None
                return result
            except WorkspaceScanError:
                raise
            except (OSError, TypeError, ValueError) as exc:
                raise WorkspaceScanError(
                    "workspace launch descriptor could not be duplicated"
                ) from exc
            finally:
                if duplicate is not None:
                    os.close(duplicate)

    def close(self) -> None:
        """Close every retained descriptor; repeated calls are harmless."""

        with self._lock:
            if self._root_descriptor < 0:
                return
            _static._close_pinned_regulars(self._pinned_regulars)
            os.close(self._root_descriptor)
            self._root_descriptor = -1

    def __enter__(self) -> WorkspaceHandle:
        with self._lock:
            self._require_open()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def __del__(self) -> None:  # pragma: no cover - interpreter cleanup timing
        try:
            self.close()
        except (OSError, AttributeError):
            pass


def materialize_fixture(
    definition: FixtureDefinition, workspace: str | os.PathLike[str]
) -> WorkspaceHandle:
    """Materialize a validated fixture into one empty no-follow workspace.

    No expected answer is accepted or derived here, and no candidate program or
    other executable is started.  The returned handle owns the pinned workspace
    and unreadable-file descriptors until explicitly closed.
    """

    if type(definition) is not FixtureDefinition:
        raise WorkspaceDefinitionError("definition must be a FixtureDefinition")
    definition.__post_init__()
    try:
        destination = Path(os.path.abspath(os.fspath(workspace)))
    except (TypeError, ValueError, OSError) as exc:
        raise WorkspaceMaterializationError("workspace path is invalid") from exc

    root_descriptor: int | None = None
    pinned_regulars: list[_static._PinnedRegular] = []
    try:
        root_descriptor, _ = _static._open_or_create_workspace_no_follow(destination)
        directories, _ = _expected_projection(definition)
        for relative_text in sorted(
            directories,
            key=lambda value: (len(PurePosixPath(value).parts), value.encode("utf-8")),
        ):
            _static._ensure_relative_directory(
                root_descriptor, PurePosixPath(relative_text)
            )

        for item in definition.inputs:
            if isinstance(item, InputFile):
                pinned = _static._write_relative_file(
                    root_descriptor,
                    _validate_input_path(item.path, "InputFile.path"),
                    item.content,
                    item.mode,
                )
                if pinned is not None:
                    pinned_regulars.append(pinned)
        for item in definition.inputs:
            if isinstance(item, InputSymlink):
                _static._create_relative_symlink(
                    root_descriptor,
                    _validate_input_path(item.path, "InputSymlink.path"),
                    _validate_symlink_target(
                        item.target, "InputSymlink.target"
                    ).as_posix(),
                )

        pinned_by_path: Mapping[str, _static._PinnedRegular] = {
            item.path: item for item in pinned_regulars
        }
        entries = _scan_materialized_projection_once(
            root_descriptor, pinned_by_path
        )
        _validate_materialized_projection(definition, entries)

        current_metadata = _assert_named_materialization_workspace(
            destination, root_descriptor
        )
        baseline = _make_baseline(definition, current_metadata, entries)
        _assert_final_materialization_boundary(
            destination,
            root_descriptor,
            pinned_by_path,
            entries,
        )
        handle = WorkspaceHandle(
            workspace=destination,
            root_descriptor=root_descriptor,
            baseline=baseline,
            expected_files=definition.expected_files,
            pinned_regulars=tuple(pinned_regulars),
        )
        root_descriptor = None
        pinned_regulars = []
        return handle
    except WorkspaceMaterializationError:
        raise
    except (OSError, ValueError) as exc:
        raise WorkspaceMaterializationError(
            f"cannot materialize workspace: {type(exc).__name__}: {exc}"
        ) from exc
    finally:
        _static._close_pinned_regulars(pinned_regulars)
        if root_descriptor is not None:
            os.close(root_descriptor)


__all__ = [
    "INPUT_ROOT",
    "INITIAL_OUTPUT_POLICY",
    "MAX_DEPTH",
    "MAX_ENTRIES",
    "MAX_FILE_BYTES",
    "MAX_PATH_COMPONENT_UTF8_BYTES",
    "MAX_PATH_UTF8_BYTES",
    "MAX_TOTAL_BYTES",
    "WORKSPACE_SCHEMA_VERSION",
    "ExecutableWorkspaceError",
    "ExpectedFile",
    "FixtureDefinition",
    "InputFile",
    "InputSymlink",
    "WorkspaceBaseline",
    "WorkspaceClosedError",
    "WorkspaceDefinitionError",
    "WorkspaceEntry",
    "WorkspaceHandle",
    "WorkspaceMaterializationError",
    "WorkspaceOutputPolicyError",
    "WorkspaceOutputReadError",
    "WorkspaceScan",
    "WorkspaceScanError",
    "materialize_fixture",
    "validate_expected_output_policy",
]
