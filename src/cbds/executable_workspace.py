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
MAX_INPUT_MTIME_SECONDS: Final[int] = 4_102_444_800

_IDENTIFIER_RE: Final[re.Pattern[str]] = re.compile(
    r"[a-z0-9][a-z0-9._-]{2,127}\Z"
)
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_RESERVED_STAGE_PREFIX: Final[str] = ".cbds-stage-"

EntryKind: TypeAlias = Literal["directory", "file", "symlink", "other"]
ScanScope: TypeAlias = Literal["inputs", "outputs"]
_InputObjectIdentity: TypeAlias = tuple[str, str, int, int]


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
    mtime_seconds: int | None = None

    def __post_init__(self) -> None:
        _validate_input_path(self.path, "InputFile.path")
        if type(self.content) is not bytes:
            raise WorkspaceDefinitionError("InputFile.content must be immutable bytes")
        if len(self.content) > MAX_FILE_BYTES:
            raise WorkspaceDefinitionError("InputFile.content exceeds the per-file limit")
        _validate_mode(self.mode, "InputFile.mode")
        if self.mtime_seconds is not None:
            _validate_nonnegative_int(
                self.mtime_seconds,
                "InputFile.mtime_seconds",
                maximum=MAX_INPUT_MTIME_SECONDS,
            )

    def to_record(self) -> dict[str, object]:
        self.__post_init__()
        record: dict[str, object] = {
            "kind": "file",
            "path": self.path,
            "mode": self.mode,
            "size": len(self.content),
            "sha256": sha256(self.content).hexdigest(),
        }
        if self.mtime_seconds is not None:
            record["mtime_seconds"] = self.mtime_seconds
        return record


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
class InputHardlink:
    """One regular-file input name sharing an inode with an InputFile."""

    path: str
    target: str

    def __post_init__(self) -> None:
        path = _validate_input_path(self.path, "InputHardlink.path")
        target = _validate_input_path(self.target, "InputHardlink.target")
        if path == target:
            raise WorkspaceDefinitionError(
                "InputHardlink.path must differ from its target"
            )

    def to_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "kind": "hardlink",
            "path": self.path,
            "target": self.target,
        }


@dataclass(frozen=True, slots=True)
class ExpectedFile:
    """Public output safety boundary, intentionally containing no answer."""

    path: str
    maximum_bytes: int = MAX_FILE_BYTES
    mode: int | None = None
    required_link_count: int | None = 1

    def __post_init__(self) -> None:
        _validate_output_path(self.path, "ExpectedFile.path")
        _validate_nonnegative_int(
            self.maximum_bytes,
            "ExpectedFile.maximum_bytes",
            maximum=MAX_FILE_BYTES,
        )
        _validate_mode(self.mode, "ExpectedFile.mode", optional=True)
        if self.required_link_count is not None:
            _validate_nonnegative_int(
                self.required_link_count,
                "ExpectedFile.required_link_count",
                maximum=MAX_ENTRIES,
            )
            if self.required_link_count < 1:
                raise WorkspaceDefinitionError(
                    "ExpectedFile.required_link_count must be positive or None"
                )

    def to_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "path": self.path,
            "maximum_bytes": self.maximum_bytes,
            "mode": self.mode,
            "required_kind": "regular",
            "required_link_count": self.required_link_count,
        }


@dataclass(frozen=True, slots=True)
class ExpectedSymlink:
    """One answer-free no-follow symbolic-link output boundary."""

    path: str
    maximum_target_utf8_bytes: int = MAX_PATH_UTF8_BYTES

    def __post_init__(self) -> None:
        _validate_output_path(self.path, "ExpectedSymlink.path")
        _validate_nonnegative_int(
            self.maximum_target_utf8_bytes,
            "ExpectedSymlink.maximum_target_utf8_bytes",
            maximum=MAX_PATH_UTF8_BYTES,
        )
        if self.maximum_target_utf8_bytes < 1:
            raise WorkspaceDefinitionError(
                "ExpectedSymlink.maximum_target_utf8_bytes must be positive"
            )

    def to_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "path": self.path,
            "maximum_target_utf8_bytes": self.maximum_target_utf8_bytes,
            "required_kind": "symlink",
            "required_link_count": 1,
            "target_policy": "canonical-safe-relative-no-parent-v1",
        }


InputEntry: TypeAlias = InputFile | InputSymlink | InputHardlink


def _ancestors(path: PurePosixPath) -> tuple[PurePosixPath, ...]:
    return tuple(parent for parent in path.parents if parent != PurePosixPath("."))


@dataclass(frozen=True, slots=True)
class FixtureDefinition:
    """Frozen trusted inputs plus answer-free expected-file boundaries."""

    fixture_id: str
    inputs: tuple[InputEntry, ...]
    expected_files: tuple[ExpectedFile, ...]
    schema_version: str = WORKSPACE_SCHEMA_VERSION
    expected_symlinks: tuple[ExpectedSymlink, ...] = ()

    def __post_init__(self) -> None:
        _validate_identifier(self.fixture_id, "FixtureDefinition.fixture_id")
        if self.schema_version != WORKSPACE_SCHEMA_VERSION:
            raise WorkspaceDefinitionError(
                f"FixtureDefinition.schema_version must equal {WORKSPACE_SCHEMA_VERSION!r}"
            )
        if type(self.inputs) is not tuple or any(
            type(item) not in {InputFile, InputSymlink, InputHardlink}
            for item in self.inputs
        ):
            raise WorkspaceDefinitionError(
                "FixtureDefinition.inputs must be a tuple of "
                "InputFile/InputSymlink/InputHardlink"
            )
        if type(self.expected_files) is not tuple or any(
            type(item) is not ExpectedFile for item in self.expected_files
        ):
            raise WorkspaceDefinitionError(
                "FixtureDefinition.expected_files must be a tuple of ExpectedFile"
            )
        if type(self.expected_symlinks) is not tuple or any(
            type(item) is not ExpectedSymlink for item in self.expected_symlinks
        ):
            raise WorkspaceDefinitionError(
                "FixtureDefinition.expected_symlinks must be a tuple of "
                "ExpectedSymlink"
            )

        for item in self.inputs:
            item.__post_init__()
        for item in self.expected_files:
            item.__post_init__()
        for item in self.expected_symlinks:
            item.__post_init__()

        input_paths = [_validate_input_path(item.path, "fixture input path") for item in self.inputs]
        output_paths = [
            _validate_output_path(item.path, "fixture expected path")
            for item in (*self.expected_files, *self.expected_symlinks)
        ]
        all_paths = input_paths + output_paths
        path_texts = [item.as_posix() for item in all_paths]
        if len(path_texts) != len(set(path_texts)):
            raise WorkspaceDefinitionError("fixture paths contain a duplicate")
        input_files = {
            item.path: item
            for item in self.inputs
            if type(item) is InputFile
        }
        for item in self.inputs:
            if type(item) is InputHardlink and item.target not in input_files:
                raise WorkspaceDefinitionError(
                    "fixture hardlink target must name an exact InputFile"
                )
        hardlink_members: dict[str, list[str]] = {
            path: [path] for path in input_files
        }
        for item in self.inputs:
            if type(item) is InputHardlink:
                hardlink_members[item.target].append(item.path)
        for target, members in hardlink_members.items():
            if len(members) > 1 and target != min(
                members,
                key=lambda value: value.encode("utf-8"),
            ):
                raise WorkspaceDefinitionError(
                    "fixture hardlink target must be the byte-smallest "
                    "path in its group"
                )
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
        projected_entries = (
            len(directories)
            + len(self.inputs)
            + len(self.expected_files)
            + len(self.expected_symlinks)
        )
        if projected_entries > MAX_ENTRIES:
            raise WorkspaceDefinitionError("fixture exceeds the workspace entry limit")
        input_bytes = sum(
            len(item.content)
            if type(item) is InputFile
            else (
                len(input_files[item.target].content)
                if type(item) is InputHardlink
                else 0
            )
            for item in self.inputs
        )
        output_bytes = sum(item.maximum_bytes for item in self.expected_files)
        output_bytes += sum(
            item.maximum_target_utf8_bytes
            for item in self.expected_symlinks
        )
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
        record: dict[str, object] = {
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
        # The optional additive boundary is omitted for all legacy fixtures so
        # every previously frozen fixture record and digest remains exact.
        if self.expected_symlinks:
            record["expected_symlinks"] = [
                item.to_record()
                for item in sorted(
                    self.expected_symlinks,
                    key=lambda item: item.path.encode("utf-8"),
                )
            ]
        return record

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
    hardlink_group_sha256: str | None = None

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
        if self.hardlink_group_sha256 is not None:
            _validate_sha256(
                self.hardlink_group_sha256,
                "WorkspaceEntry.hardlink_group_sha256",
            )
        if self.kind == "symlink":
            if not isinstance(self.symlink_target, str):
                raise WorkspaceDefinitionError("symlink entry requires its literal target")
            if self.content_sha256 is not None:
                raise WorkspaceDefinitionError("symlink entry cannot have a content hash")
        elif self.symlink_target is not None:
            raise WorkspaceDefinitionError("non-symlink entry cannot have a symlink target")
        if self.kind != "file" and self.content_sha256 is not None:
            raise WorkspaceDefinitionError("only regular files may have content hashes")
        if self.kind != "file" and self.hardlink_group_sha256 is not None:
            raise WorkspaceDefinitionError(
                "only regular files may have a hardlink group"
            )
        if self.kind == "file":
            if self.link_count < 1:
                raise WorkspaceDefinitionError(
                    "a named regular file must have a positive link count"
                )
            # Legacy v1 records could observe a multiply linked file without
            # carrying a topology identity.  Newly produced scans always add
            # the identity; accepting its historical absence keeps record
            # revalidation backward compatible.
            if (
                self.hardlink_group_sha256 is not None
                and self.link_count < 2
            ):
                raise WorkspaceDefinitionError(
                    "regular-file hardlink identity and link count disagree"
                )

    def to_record(self) -> dict[str, object]:
        self.__post_init__()
        record: dict[str, object] = {
            "path": self.path,
            "kind": self.kind,
            "mode": self.mode,
            "size": self.size,
            "mtime_ns": self.mtime_ns,
            "link_count": self.link_count,
            "content_sha256": self.content_sha256,
            "symlink_target": self.symlink_target,
        }
        # Omitting the additive field for link-count-one files preserves the
        # exact serialized records and hashes of every existing fixture.
        if self.hardlink_group_sha256 is not None:
            record["hardlink_group_sha256"] = self.hardlink_group_sha256
        return record


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

    The only permitted output paths are the declared regular files, exact
    symbolic links, and the directories strictly required to contain them.
    This validator never opens a path: it consumes the no-follow observations
    already bound by :class:`WorkspaceScan`.  It therefore cannot authorize
    execution or attest functional correctness; it only enforces the public
    filesystem boundary.
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
    expected_symlinks_by_path = {
        item.path: item for item in definition.expected_symlinks
    }
    required_directories: set[str] = set()
    for path_text in (*expected_by_path, *expected_symlinks_by_path):
        path = _validate_output_path(path_text, "fixture expected path")
        required_directories.update(
            parent.as_posix() for parent in _ancestors(path)
        )
    permitted_paths = (
        set(expected_by_path)
        | set(expected_symlinks_by_path)
        | required_directories
    )

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
        if (
            expected.required_link_count is not None
            and entry.link_count != expected.required_link_count
        ):
            requirement = (
                "link count one"
                if expected.required_link_count == 1
                else f"required link count {expected.required_link_count}"
            )
            raise WorkspaceOutputPolicyError(
                f"expected output does not have {requirement}: {path}"
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
    for path, expected in sorted(
        expected_symlinks_by_path.items(),
        key=lambda item: item[0].encode("utf-8"),
    ):
        entry = observed[path]
        target = entry.symlink_target
        try:
            if target is None:
                raise WorkspaceDefinitionError(
                    "expected symlink lacks a literal target"
                )
            target_path = _validate_symlink_target(
                target,
                "expected output symlink target",
            )
            del target_path
            target_size = len(target.encode("utf-8", errors="strict"))
        except (WorkspaceDefinitionError, UnicodeEncodeError) as exc:
            raise WorkspaceOutputPolicyError(
                f"expected output symlink target is unsafe: {path}"
            ) from exc
        if (
            entry.kind != "symlink"
            or entry.link_count != 1
            or entry.content_sha256 is not None
            or entry.hardlink_group_sha256 is not None
            or target_size > expected.maximum_target_utf8_bytes
            or entry.size != target_size
        ):
            raise WorkspaceOutputPolicyError(
                f"expected output is not a bounded no-follow symlink: {path}"
            )
        validated.append(entry)
    return tuple(sorted(validated, key=lambda item: item.path.encode("utf-8")))


def compute_workspace_hardlink_group_sha256(
    paths: tuple[str, ...],
    link_count: int,
) -> str:
    """Return the portable identity of one visible hardlink path group."""

    if (
        type(paths) is not tuple
        or not paths
        or any(type(path) is not str for path in paths)
    ):
        raise WorkspaceDefinitionError(
            "hardlink group paths must be a nonempty exact tuple of strings"
        )
    for path in paths:
        _validate_relative_path(path, "hardlink group path")
    expected_order = tuple(
        sorted(paths, key=lambda value: value.encode("utf-8"))
    )
    if paths != expected_order or len(paths) != len(set(paths)):
        raise WorkspaceDefinitionError(
            "hardlink group paths must be unique and byte-sorted"
        )
    if (
        type(link_count) is not int
        or link_count < len(paths)
        or link_count < 2
    ):
        raise WorkspaceDefinitionError(
            "hardlink group must have an observed count of at least two "
            "covering every visible name"
        )
    return _digest(
        {
            "contract": "cbds.executable-workspace-hardlink-group",
            "version": WORKSPACE_SCHEMA_VERSION,
            "visible_members": list(paths),
            "observed_link_count": link_count,
        }
    )


def _workspace_entry(
    item: _static._TreeEntry,
    *,
    prefix: str = "",
    hardlink_group_sha256: str | None = None,
) -> WorkspaceEntry:
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
        hardlink_group_sha256=hardlink_group_sha256,
    )


def _workspace_entries(
    items: tuple[_static._TreeEntry, ...],
    *,
    prefix: str = "",
) -> tuple[WorkspaceEntry, ...]:
    visible_paths: dict[tuple[int, int], list[str]] = {}
    for item in items:
        if item.kind != "file" or item.link_count <= 1:
            continue
        path = item.path if not prefix else f"{prefix}/{item.path}"
        visible_paths.setdefault((item.device, item.inode), []).append(path)

    group_digests: dict[tuple[int, int], str] = {}
    for identity, paths in visible_paths.items():
        members = tuple(sorted(paths, key=lambda value: value.encode("utf-8")))
        link_counts = {
            item.link_count
            for item in items
            if (item.device, item.inode) == identity
        }
        if len(link_counts) != 1:
            raise WorkspaceScanError(
                "one hardlink group has inconsistent link counts"
            )
        group_digests[identity] = compute_workspace_hardlink_group_sha256(
            members, next(iter(link_counts))
        )

    return tuple(
        _workspace_entry(
            item,
            prefix=prefix,
            hardlink_group_sha256=group_digests.get(
                (item.device, item.inode)
            ),
        )
        for item in items
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


def _symlink_metadata_matches_entry(
    metadata: os.stat_result, entry: WorkspaceEntry
) -> bool:
    return (
        stat.S_ISLNK(metadata.st_mode)
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


def _input_hardlink_projection(
    definition: FixtureDefinition,
) -> tuple[
    dict[str, InputFile],
    dict[str, str],
    dict[str, tuple[str, ...]],
]:
    files = {
        item.path: item
        for item in definition.inputs
        if type(item) is InputFile
    }
    target_by_path = {path: path for path in files}
    for item in definition.inputs:
        if type(item) is InputHardlink:
            target_by_path[item.path] = item.target
    members: dict[str, list[str]] = {path: [path] for path in files}
    for path, target in target_by_path.items():
        if path != target:
            members[target].append(path)
    return (
        files,
        target_by_path,
        {
            target: tuple(
                sorted(paths, key=lambda value: value.encode("utf-8"))
            )
            for target, paths in members.items()
        },
    )


def _validate_materialized_projection(
    definition: FixtureDefinition, entries: tuple[WorkspaceEntry, ...]
) -> None:
    directories, leaves = _expected_projection(definition)
    files, target_by_path, members_by_target = _input_hardlink_projection(
        definition
    )
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
        if type(expected) in {InputFile, InputHardlink}:
            target = target_by_path[path]
            source = files[target]
            members = members_by_target[target]
            link_count = len(members)
            group_sha256 = (
                compute_workspace_hardlink_group_sha256(
                    members, link_count
                )
                if link_count > 1
                else None
            )
            if (
                entry.kind != "file"
                or entry.mode != source.mode
                or entry.size != len(source.content)
                or entry.link_count != link_count
                or entry.content_sha256 != sha256(source.content).hexdigest()
                or entry.hardlink_group_sha256 != group_sha256
                or (
                    source.mtime_seconds is not None
                    and entry.mtime_ns
                    != source.mtime_seconds * 1_000_000_000
                )
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
    return _workspace_entries(scanned)


def _scan_input_tree_once(
    root_descriptor: int,
    pinned_regulars: tuple[_static._PinnedRegular, ...],
) -> tuple[os.stat_result, tuple[_static._TreeEntry, ...]]:
    """Return one reachable no-follow input scan retaining local object IDs."""

    try:
        input_descriptor = _static._open_relative_directory(
            root_descriptor, PurePosixPath(INPUT_ROOT)
        )
    except OSError as exc:
        raise WorkspaceScanError(
            f"input tree is unavailable: {type(exc).__name__}"
        ) from exc
    try:
        input_before = os.fstat(input_descriptor)
        pinned = {
            item.path.removeprefix(INPUT_ROOT + "/"): item
            for item in pinned_regulars
            if item.path.startswith(INPUT_ROOT + "/")
        }
        scanned, errors = _static._scan_tree_descriptor(
            input_descriptor, pinned_regulars=pinned
        )
        if errors:
            raise WorkspaceScanError(
                "workspace scan failed: " + "; ".join(errors)
            )
        _static._assert_relative_directory_reachable(
            root_descriptor, input_descriptor, PurePosixPath(INPUT_ROOT)
        )
        if (
            _static._filesystem_snapshot(os.fstat(input_descriptor))
            != _static._filesystem_snapshot(input_before)
        ):
            raise WorkspaceScanError("input directory changed during scan")
        return input_before, scanned
    finally:
        os.close(input_descriptor)


def _input_object_identities(
    root_metadata: os.stat_result,
    scanned: tuple[_static._TreeEntry, ...],
) -> tuple[_InputObjectIdentity, ...]:
    """Project process-local input object identities without serializing them."""

    values: list[_InputObjectIdentity] = [
        (
            INPUT_ROOT,
            "directory",
            root_metadata.st_dev,
            root_metadata.st_ino,
        )
    ]
    values.extend(
        (
            f"{INPUT_ROOT}/{item.path}",
            item.kind,
            item.device,
            item.inode,
        )
        for item in scanned
    )
    return tuple(
        sorted(values, key=lambda item: item[0].encode("utf-8"))
    )


def _stable_input_object_identities(
    root_descriptor: int,
    pinned_regulars: tuple[_static._PinnedRegular, ...],
) -> tuple[_InputObjectIdentity, ...]:
    """Observe one stable process-local input identity projection."""

    before = _static._filesystem_snapshot(os.fstat(root_descriptor))
    first_root, first_scan = _scan_input_tree_once(
        root_descriptor, pinned_regulars
    )
    second_root, second_scan = _scan_input_tree_once(
        root_descriptor, pinned_regulars
    )
    after = _static._filesystem_snapshot(os.fstat(root_descriptor))
    first = _input_object_identities(first_root, first_scan)
    second = _input_object_identities(second_root, second_scan)
    if (
        first_scan != second_scan
        or _static._filesystem_snapshot(first_root)
        != _static._filesystem_snapshot(second_root)
        or first != second
        or before != after
    ):
        raise WorkspaceScanError(
            "input object identities changed during stable scan"
        )
    return first


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
        "_expected_symlinks",
        "_input_object_identities",
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
        expected_symlinks: tuple[ExpectedSymlink, ...],
        input_object_identities: tuple[_InputObjectIdentity, ...],
        pinned_regulars: tuple[_static._PinnedRegular, ...],
    ) -> None:
        self._workspace = workspace
        self._root_descriptor = root_descriptor
        self._baseline = baseline
        self._expected_files = expected_files
        self._expected_symlinks = expected_symlinks
        self._input_object_identities = input_object_identities
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
    def expected_symlinks(self) -> tuple[ExpectedSymlink, ...]:
        return tuple(self._expected_symlinks)

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
        input_metadata, scanned = _scan_input_tree_once(
            descriptor, self._pinned_regulars
        )
        entries = (_directory_entry(INPUT_ROOT, input_metadata),) + tuple(
            _workspace_entries(scanned, prefix=INPUT_ROOT)
        )
        return tuple(
            sorted(entries, key=lambda item: item.path.encode("utf-8"))
        )

    def _scan_outputs_once(self, descriptor: int) -> tuple[WorkspaceEntry, ...]:
        scanned, errors = _static._scan_tree_descriptor(
            descriptor, exclude_top_level=frozenset({INPUT_ROOT})
        )
        self._raise_scan_errors(errors)
        return _workspace_entries(scanned)

    def _stable_scan(self, scope: ScanScope) -> WorkspaceScan:
        with self._lock:
            descriptor = self._require_open()
            self._assert_named_workspace(descriptor)
            before = _static._filesystem_snapshot(os.fstat(descriptor))
            scan_once = (
                self._scan_inputs_once if scope == "inputs" else self._scan_outputs_once
            )
            try:
                first = scan_once(descriptor)
                second = scan_once(descriptor)
            except (WorkspaceDefinitionError, UnicodeEncodeError) as exc:
                raise WorkspaceScanError(
                    "workspace scan contains an unrepresentable entry"
                ) from exc
            after = _static._filesystem_snapshot(os.fstat(descriptor))
            self._assert_named_workspace(descriptor)
            if first != second or before != after:
                raise WorkspaceScanError("workspace changed during stable scan")
            try:
                tree_sha256 = _entries_digest(scope, first)
                return WorkspaceScan(
                    scope=scope,
                    entries=first,
                    tree_sha256=tree_sha256,
                    baseline_sha256=self._baseline.baseline_sha256,
                )
            except (WorkspaceDefinitionError, UnicodeEncodeError) as exc:
                raise WorkspaceScanError(
                    "workspace scan contains an unrepresentable entry"
                ) from exc

    def scan_inputs(self) -> WorkspaceScan:
        """Return one stable no-follow snapshot of ``input/`` and descendants."""

        return self._stable_scan("inputs")

    def scan_outputs(self) -> WorkspaceScan:
        """Return one stable no-follow snapshot of everything outside ``input/``."""

        return self._stable_scan("outputs")

    def validate_input_object_identities(self, scan: WorkspaceScan) -> None:
        """Require input names to retain their materialized filesystem objects.

        Portable baseline records intentionally omit host-specific device and
        inode numbers.  A topology-sensitive verifier can call this trusted,
        process-local check to reject replacement by a fresh but otherwise
        byte/metadata-identical inode.  The check is bracketed by portable
        stable scans; like all workspace reads, it still relies on the trusted
        harness to establish global quiescence.
        """

        with self._lock:
            if (
                type(scan) is not WorkspaceScan
                or scan.scope != "inputs"
                or scan.baseline_sha256
                != self._baseline.baseline_sha256
            ):
                raise WorkspaceScanError(
                    "input identity check requires this handle's input scan"
                )
            before = self._stable_scan("inputs")
            if before != scan:
                raise WorkspaceScanError(
                    "input scan is stale before object-identity validation"
                )
            descriptor = self._require_open()
            observed = _stable_input_object_identities(
                descriptor, self._pinned_regulars
            )
            after = self._stable_scan("inputs")
            if (
                before != after
                or observed != self._input_object_identities
            ):
                raise WorkspaceScanError(
                    "an input path no longer names its materialized object"
                )

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
            if (
                expected.required_link_count is not None
                and entry.link_count != expected.required_link_count
            ):
                requirement = (
                    "link count one"
                    if expected.required_link_count == 1
                    else f"required link count {expected.required_link_count}"
                )
                raise WorkspaceOutputReadError(
                    f"declared output does not have {requirement}"
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

    def read_output_symlink_target(
        self,
        scan: WorkspaceScan,
        path: str,
    ) -> str:
        """Release one declared literal symlink target without following it."""

        with self._lock:
            descriptor = self._require_open()
            if type(scan) is not WorkspaceScan:
                raise WorkspaceOutputReadError(
                    "symlink egress requires an outputs WorkspaceScan"
                )
            try:
                scan.__post_init__()
            except WorkspaceDefinitionError as exc:
                raise WorkspaceOutputReadError(
                    "symlink egress scan failed closed-contract revalidation"
                ) from exc
            if scan.scope != "outputs":
                raise WorkspaceOutputReadError(
                    "symlink egress requires an outputs WorkspaceScan"
                )
            if scan.baseline_sha256 != self._baseline.baseline_sha256:
                raise WorkspaceOutputReadError(
                    "output scan is not bound to this workspace baseline"
                )
            try:
                relative = _validate_output_path(path, "symlink egress path")
            except WorkspaceDefinitionError as exc:
                raise WorkspaceOutputReadError(
                    "symlink egress path is not a canonical safe output path"
                ) from exc
            expected = next(
                (item for item in self._expected_symlinks if item.path == path),
                None,
            )
            if expected is None:
                raise WorkspaceOutputReadError(
                    "symlink egress path is not declared by the fixture"
                )

            try:
                current_before = self._stable_scan("outputs")
            except WorkspaceScanError as exc:
                raise WorkspaceOutputReadError(
                    "cannot establish the current output scan before symlink egress"
                ) from exc
            if current_before != scan:
                raise WorkspaceOutputReadError(
                    "supplied output scan is stale or does not match this workspace"
                )
            matching = tuple(item for item in scan.entries if item.path == path)
            if len(matching) != 1:
                raise WorkspaceOutputReadError(
                    "declared symlink path is absent or duplicated in the scan"
                )
            entry = matching[0]
            target = entry.symlink_target
            try:
                if (
                    entry.kind != "symlink"
                    or target is None
                    or entry.link_count != 1
                    or entry.content_sha256 is not None
                    or entry.hardlink_group_sha256 is not None
                ):
                    raise WorkspaceDefinitionError(
                        "declared output is not a no-follow symlink"
                    )
                _validate_symlink_target(target, "symlink egress target")
                target_size = len(target.encode("utf-8", errors="strict"))
            except (WorkspaceDefinitionError, UnicodeEncodeError) as exc:
                raise WorkspaceOutputReadError(
                    "declared output is not a bounded safe symlink"
                ) from exc
            if (
                target_size > expected.maximum_target_utf8_bytes
                or entry.size != target_size
            ):
                raise WorkspaceOutputReadError(
                    "declared symlink target exceeds its fixture policy"
                )

            parent_descriptor: int | None = None
            try:
                self._assert_named_workspace(descriptor)
                parent_descriptor = _static._open_relative_directory(
                    descriptor,
                    relative.parent,
                )
                _static._assert_relative_directory_reachable(
                    descriptor,
                    parent_descriptor,
                    relative.parent,
                )
                named_before = os.stat(
                    relative.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                if not _symlink_metadata_matches_entry(named_before, entry):
                    raise WorkspaceOutputReadError(
                        "declared symlink changed between its scan and read"
                    )
                observed_target = os.readlink(
                    relative.name,
                    dir_fd=parent_descriptor,
                )
                named_after = os.stat(
                    relative.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                if (
                    _static._filesystem_snapshot(named_after)
                    != _static._filesystem_snapshot(named_before)
                    or not _symlink_metadata_matches_entry(named_after, entry)
                    or observed_target != target
                ):
                    raise WorkspaceOutputReadError(
                        "declared symlink changed while its target was read"
                    )
                try:
                    _validate_symlink_target(
                        observed_target,
                        "observed symlink target",
                    )
                    observed_size = len(
                        observed_target.encode("utf-8", errors="strict")
                    )
                except (WorkspaceDefinitionError, UnicodeEncodeError) as exc:
                    raise WorkspaceOutputReadError(
                        "observed symlink target is unsafe"
                    ) from exc
                if (
                    observed_size != entry.size
                    or observed_size > expected.maximum_target_utf8_bytes
                ):
                    raise WorkspaceOutputReadError(
                        "observed symlink target differs from its scan policy"
                    )
                _static._assert_relative_directory_reachable(
                    descriptor,
                    parent_descriptor,
                    relative.parent,
                )
                self._assert_named_workspace(descriptor)
            except WorkspaceOutputReadError:
                raise
            except (OSError, WorkspaceScanError) as exc:
                raise WorkspaceOutputReadError(
                    f"cannot safely read declared symlink: {type(exc).__name__}"
                ) from exc
            finally:
                if parent_descriptor is not None:
                    os.close(parent_descriptor)

            try:
                current_after = self._stable_scan("outputs")
            except WorkspaceScanError as exc:
                raise WorkspaceOutputReadError(
                    "cannot re-establish the output scan after symlink egress"
                ) from exc
            if current_after != scan:
                raise WorkspaceOutputReadError(
                    "output tree changed while symlink target was released"
                )
            return target

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


def _create_input_hardlink(
    root_descriptor: int,
    source: PurePosixPath,
    destination: PurePosixPath,
) -> None:
    """Link one trusted input file through two reachable pinned parents."""

    source_parent: int | None = None
    destination_parent: int | None = None
    created = False
    source_before: os.stat_result | None = None
    try:
        source_parent = _static._open_relative_directory(
            root_descriptor, source.parent
        )
        destination_parent = _static._open_relative_directory(
            root_descriptor, destination.parent
        )
        _static._assert_relative_directory_reachable(
            root_descriptor, source_parent, source.parent
        )
        _static._assert_relative_directory_reachable(
            root_descriptor, destination_parent, destination.parent
        )
        source_before = os.stat(
            source.name,
            dir_fd=source_parent,
            follow_symlinks=False,
        )
        if not stat.S_ISREG(source_before.st_mode):
            raise OSError("fixture hardlink source is not a regular file")
        os.link(
            source.name,
            destination.name,
            src_dir_fd=source_parent,
            dst_dir_fd=destination_parent,
            follow_symlinks=False,
        )
        created = True
        source_after = os.stat(
            source.name,
            dir_fd=source_parent,
            follow_symlinks=False,
        )
        destination_after = os.stat(
            destination.name,
            dir_fd=destination_parent,
            follow_symlinks=False,
        )
        if (
            not _static._same_inode(source_before, source_after)
            or not _static._same_inode(source_after, destination_after)
            or source_after.st_nlink != source_before.st_nlink + 1
            or _static._filesystem_snapshot(source_after)
            != _static._filesystem_snapshot(destination_after)
        ):
            raise OSError("fixture hardlink publication is not stable")
        _static._assert_relative_directory_reachable(
            root_descriptor, source_parent, source.parent
        )
        _static._assert_relative_directory_reachable(
            root_descriptor, destination_parent, destination.parent
        )
    except BaseException:
        if (
            created
            and source_before is not None
            and destination_parent is not None
        ):
            try:
                named = os.stat(
                    destination.name,
                    dir_fd=destination_parent,
                    follow_symlinks=False,
                )
                # The workspace is private until materialization returns.  As
                # with the existing staging primitive, POSIX still has no
                # atomic conditional unlink-by-inode operation.
                if _static._same_inode(source_before, named):
                    os.unlink(destination.name, dir_fd=destination_parent)
            except OSError:
                pass
        raise
    finally:
        if source_parent is not None:
            os.close(source_parent)
        if destination_parent is not None:
            os.close(destination_parent)


def _set_input_file_mtime(
    root_descriptor: int,
    path: PurePosixPath,
    mtime_seconds: int,
) -> None:
    """Set one committed fixture mtime through a pinned no-follow parent."""

    _validate_nonnegative_int(
        mtime_seconds,
        "InputFile.mtime_seconds",
        maximum=MAX_INPUT_MTIME_SECONDS,
    )
    parent_descriptor: int | None = None
    try:
        parent_descriptor = _static._open_relative_directory(
            root_descriptor,
            path.parent,
        )
        _static._assert_relative_directory_reachable(
            root_descriptor,
            parent_descriptor,
            path.parent,
        )
        before = os.stat(
            path.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if not stat.S_ISREG(before.st_mode):
            raise OSError("fixture mtime target is not a regular file")
        value_ns = mtime_seconds * 1_000_000_000
        os.utime(
            path.name,
            ns=(value_ns, value_ns),
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        after = os.stat(
            path.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not _static._same_inode(before, after)
            or not stat.S_ISREG(after.st_mode)
            or stat.S_IMODE(before.st_mode) != stat.S_IMODE(after.st_mode)
            or before.st_size != after.st_size
            or before.st_nlink != after.st_nlink
            or after.st_mtime_ns != value_ns
        ):
            raise OSError("fixture mtime publication is not stable")
        _static._assert_relative_directory_reachable(
            root_descriptor,
            parent_descriptor,
            path.parent,
        )
    finally:
        if parent_descriptor is not None:
            os.close(parent_descriptor)


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
                if item.mtime_seconds is not None:
                    _set_input_file_mtime(
                        root_descriptor,
                        _validate_input_path(item.path, "InputFile.path"),
                        item.mtime_seconds,
                    )
        pinned_by_path = {item.path: item for item in pinned_regulars}
        for item in definition.inputs:
            if type(item) is InputHardlink:
                _create_input_hardlink(
                    root_descriptor,
                    _validate_input_path(
                        item.target, "InputHardlink.target"
                    ),
                    _validate_input_path(item.path, "InputHardlink.path"),
                )
                target_pinned = pinned_by_path.get(item.target)
                if target_pinned is not None:
                    duplicate: int | None = None
                    try:
                        duplicate = os.dup(target_pinned.descriptor)
                        os.set_inheritable(duplicate, False)
                        alias_pinned = _static._PinnedRegular(
                            item.path, duplicate
                        )
                        duplicate = None
                        pinned_regulars.append(alias_pinned)
                        pinned_by_path[item.path] = alias_pinned
                    finally:
                        if duplicate is not None:
                            os.close(duplicate)
        for item in definition.inputs:
            if isinstance(item, InputSymlink):
                _static._create_relative_symlink(
                    root_descriptor,
                    _validate_input_path(item.path, "InputSymlink.path"),
                    _validate_symlink_target(
                        item.target, "InputSymlink.target"
                    ).as_posix(),
                )

        pinned_by_path_view: Mapping[str, _static._PinnedRegular] = {
            item.path: item for item in pinned_regulars
        }
        entries = _scan_materialized_projection_once(
            root_descriptor, pinned_by_path_view
        )
        _validate_materialized_projection(definition, entries)

        current_metadata = _assert_named_materialization_workspace(
            destination, root_descriptor
        )
        baseline = _make_baseline(definition, current_metadata, entries)
        _assert_final_materialization_boundary(
            destination,
            root_descriptor,
            pinned_by_path_view,
            entries,
        )
        input_object_identities = _stable_input_object_identities(
            root_descriptor, tuple(pinned_regulars)
        )
        handle = WorkspaceHandle(
            workspace=destination,
            root_descriptor=root_descriptor,
            baseline=baseline,
            expected_files=definition.expected_files,
            expected_symlinks=definition.expected_symlinks,
            input_object_identities=input_object_identities,
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
    "MAX_INPUT_MTIME_SECONDS",
    "MAX_PATH_COMPONENT_UTF8_BYTES",
    "MAX_PATH_UTF8_BYTES",
    "MAX_TOTAL_BYTES",
    "WORKSPACE_SCHEMA_VERSION",
    "ExecutableWorkspaceError",
    "ExpectedFile",
    "ExpectedSymlink",
    "FixtureDefinition",
    "InputFile",
    "InputHardlink",
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
    "compute_workspace_hardlink_group_sha256",
    "materialize_fixture",
    "validate_expected_output_policy",
]
