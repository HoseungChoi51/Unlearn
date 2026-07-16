"""Strict parser for the reviewed Bash canary's workspace archive.

``CBDSWSN1`` is an observation format, not an execution or scoring boundary.
The native development supervisor emits one bounded, little-endian archive
after every descendant has been reaped.  The archive contains the workspace
root and every path *outside* the top-level ``input`` subtree.  Fixture inputs
are deliberately excluded: some reviewed inputs are mode 000, and reopening
them from PID1 would be neither reliable nor necessary.  This module accepts
only that canonical output-side tree encoding and hashes every payload.  Its
audit projection is **digest-only and raw-payload-byte-free**, not
answer-confidential: it still exposes paths, modes, sizes, and payload digests,
which can confirm or leak expected outputs.  Neither the raw archive nor its
audit projection may cross or be reused as a sealed-evaluation boundary.  The
module never executes a program, invokes an oracle, or grants experimental
authority.

The archive deliberately carries only the metadata needed by this canary:
kind, permission/special bits, path, and complete regular-file or symlink
payload bytes.  It does not carry timestamps, ownership, inode identity, or
link counts.  The optional :func:`compare_development_candidate_workspace_snapshot_to_handle`
therefore compares the complete archive-representable *output* projection of a
stable ``WorkspaceHandle`` scan.  It separately records the stable input-tree
digest but explicitly says that the input projection was not compared.  Its
evidence also records every omitted metadata field.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from hashlib import sha256
import json
import os
from pathlib import PurePosixPath
import stat
import struct
from typing import Final

from .development_candidate_protocol import (
    DEVELOPMENT_CANDIDATE_MAXIMUM_WORKSPACE_SNAPSHOT_BYTES,
)
from .executable_workspace import (
    MAX_DEPTH as WORKSPACE_MAX_DEPTH,
    MAX_ENTRIES as WORKSPACE_MAX_ENTRIES,
    MAX_FILE_BYTES as WORKSPACE_MAX_FILE_BYTES,
    MAX_PATH_COMPONENT_UTF8_BYTES as WORKSPACE_MAX_PATH_COMPONENT_UTF8_BYTES,
    MAX_PATH_UTF8_BYTES as WORKSPACE_MAX_PATH_UTF8_BYTES,
    MAX_TOTAL_BYTES as WORKSPACE_MAX_TOTAL_BYTES,
    WorkspaceEntry,
    WorkspaceHandle,
    WorkspaceScan,
)


DEVELOPMENT_CANDIDATE_WORKSPACE_SNAPSHOT_MAGIC: Final[bytes] = b"CBDSWSN1"
DEVELOPMENT_CANDIDATE_WORKSPACE_SNAPSHOT_VERSION: Final[int] = 1
DEVELOPMENT_CANDIDATE_WORKSPACE_SNAPSHOT_HEADER_BYTES: Final[int] = 16
DEVELOPMENT_CANDIDATE_WORKSPACE_SNAPSHOT_ENTRY_HEADER_BYTES: Final[int] = 20
DEVELOPMENT_CANDIDATE_WORKSPACE_SNAPSHOT_SCHEMA_VERSION: Final[str] = "1.0.0"
DEVELOPMENT_CANDIDATE_WORKSPACE_SNAPSHOT_RECORD_TYPE: Final[str] = (
    "cbds.development-candidate-workspace-snapshot"
)
DEVELOPMENT_CANDIDATE_WORKSPACE_COMPARISON_RECORD_TYPE: Final[str] = (
    "cbds.development-candidate-workspace-comparison"
)
DEVELOPMENT_CANDIDATE_WORKSPACE_OUTPUT_PROJECTION_SCOPE: Final[str] = (
    "workspace-root-and-all-paths-outside-top-level-input"
)

DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_ARCHIVE_BYTES: Final[int] = (
    DEVELOPMENT_CANDIDATE_MAXIMUM_WORKSPACE_SNAPSHOT_BYTES
)
DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_ENTRIES: Final[int] = (
    WORKSPACE_MAX_ENTRIES
)
DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_DEPTH: Final[int] = WORKSPACE_MAX_DEPTH
DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_PATH_BYTES: Final[int] = (
    WORKSPACE_MAX_PATH_UTF8_BYTES
)
DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_COMPONENT_BYTES: Final[int] = (
    WORKSPACE_MAX_PATH_COMPONENT_UTF8_BYTES
)
DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_REGULAR_BYTES: Final[int] = (
    WORKSPACE_MAX_FILE_BYTES
)
DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_TOTAL_PAYLOAD_BYTES: Final[int] = (
    WORKSPACE_MAX_TOTAL_BYTES
)
DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_SYMLINK_TARGET_BYTES: Final[int] = (
    WORKSPACE_MAX_PATH_UTF8_BYTES
)

_HEADER: Final[struct.Struct] = struct.Struct("<8sII")
_ENTRY_HEADER: Final[struct.Struct] = struct.Struct("<B3sIIQ")
_EMPTY_SHA256: Final[str] = sha256(b"").hexdigest()
_RESERVED_STAGE_PREFIX: Final[str] = ".cbds-stage-"
_SHA256_HEX_BYTES: Final[int] = 64


class DevelopmentCandidateWorkspaceSnapshotError(ValueError):
    """Raised when a workspace archive or comparison fails closed."""


class DevelopmentCandidateWorkspaceEntryType(IntEnum):
    """The complete entry-kind vocabulary of ``CBDSWSN1``."""

    DIRECTORY = 1
    REGULAR = 2
    SYMLINK = 3


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _exact_sha256(value: object, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != _SHA256_HEX_BYTES
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise DevelopmentCandidateWorkspaceSnapshotError(
            f"{label} must be one lowercase SHA-256"
        )
    return value


def _decode_utf8(raw: bytes, label: str) -> str:
    if b"\0" in raw:
        raise DevelopmentCandidateWorkspaceSnapshotError(
            f"{label} contains a NUL byte"
        )
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise DevelopmentCandidateWorkspaceSnapshotError(
            f"{label} is not strict UTF-8"
        ) from exc


def _validate_relative_components(
    text: str,
    raw: bytes,
    label: str,
    *,
    maximum_bytes: int,
    allow_empty_root: bool,
) -> tuple[bytes, ...]:
    if type(text) is not str or type(raw) is not bytes:
        raise DevelopmentCandidateWorkspaceSnapshotError(
            f"{label} has an active or noncanonical type"
        )
    try:
        if text.encode("utf-8", errors="strict") != raw:
            raise DevelopmentCandidateWorkspaceSnapshotError(
                f"{label} does not round-trip through UTF-8"
            )
    except UnicodeEncodeError as exc:
        raise DevelopmentCandidateWorkspaceSnapshotError(
            f"{label} is not encodable as strict UTF-8"
        ) from exc
    if len(raw) > maximum_bytes:
        raise DevelopmentCandidateWorkspaceSnapshotError(
            f"{label} exceeds its byte limit"
        )
    if not raw:
        if allow_empty_root:
            return ()
        raise DevelopmentCandidateWorkspaceSnapshotError(
            f"{label} must not be empty"
        )
    if raw.startswith(b"/") or raw.endswith(b"/") or b"//" in raw:
        raise DevelopmentCandidateWorkspaceSnapshotError(
            f"{label} is not a canonical relative path"
        )
    if any(ord(character) < 32 or ord(character) == 127 for character in text):
        raise DevelopmentCandidateWorkspaceSnapshotError(
            f"{label} contains a control character"
        )
    components = tuple(raw.split(b"/"))
    if len(components) > DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_DEPTH:
        raise DevelopmentCandidateWorkspaceSnapshotError(
            f"{label} exceeds the depth limit"
        )
    for component in components:
        if component in {b"", b".", b".."}:
            raise DevelopmentCandidateWorkspaceSnapshotError(
                f"{label} contains an empty, dot, or dot-dot component"
            )
        if len(component) > DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_COMPONENT_BYTES:
            raise DevelopmentCandidateWorkspaceSnapshotError(
                f"{label} contains an oversized component"
            )
        try:
            component_text = component.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:  # guarded by whole-string decoding
            raise DevelopmentCandidateWorkspaceSnapshotError(
                f"{label} contains an invalid UTF-8 component"
            ) from exc
        if component_text.startswith(_RESERVED_STAGE_PREFIX):
            raise DevelopmentCandidateWorkspaceSnapshotError(
                f"{label} uses a reserved workspace staging prefix"
            )
    # PurePosixPath is not the parser: this is a redundant canonicality check
    # which fails closed if its normalization semantics ever surprise us.
    if PurePosixPath(text).as_posix() != text:
        raise DevelopmentCandidateWorkspaceSnapshotError(
            f"{label} is not a canonical POSIX relative path"
        )
    return components


def _path_components(path: str) -> tuple[bytes, ...]:
    raw = path.encode("utf-8", errors="strict")
    return _validate_relative_components(
        path,
        raw,
        "workspace entry path",
        maximum_bytes=DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_PATH_BYTES,
        allow_empty_root=True,
    )


def _validate_mode(entry_type: DevelopmentCandidateWorkspaceEntryType, mode: object) -> int:
    if type(mode) is not int or not 0 <= mode <= 0o7777:
        raise DevelopmentCandidateWorkspaceSnapshotError(
            "workspace entry mode must contain only permission and special bits"
        )
    # On the Linux host targeted by this development canary, lstat(2) exposes
    # mode 0777 for symbolic links.  Accepting another value would create an
    # unrepresentable archive state rather than portable symlink metadata.
    if entry_type is DevelopmentCandidateWorkspaceEntryType.SYMLINK and mode != 0o777:
        raise DevelopmentCandidateWorkspaceSnapshotError(
            "workspace symlink mode must be exactly 0777"
        )
    return mode


def _decode_symlink_target(payload: bytes) -> str:
    if len(payload) > DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_SYMLINK_TARGET_BYTES:
        raise DevelopmentCandidateWorkspaceSnapshotError(
            "workspace symlink target exceeds its byte limit"
        )
    text = _decode_utf8(payload, "workspace symlink target")
    _validate_relative_components(
        text,
        payload,
        "workspace symlink target",
        maximum_bytes=DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_SYMLINK_TARGET_BYTES,
        allow_empty_root=False,
    )
    return text


@dataclass(frozen=True, slots=True)
class DevelopmentCandidateWorkspaceEntry:
    """One immutable, fully bounded archive entry."""

    entry_type: DevelopmentCandidateWorkspaceEntryType
    path: str
    mode: int
    payload: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.entry_type) is not DevelopmentCandidateWorkspaceEntryType:
            raise DevelopmentCandidateWorkspaceSnapshotError(
                "workspace entry type must be an exact enum member"
            )
        _path_components(self.path)
        _validate_mode(self.entry_type, self.mode)
        if type(self.payload) is not bytes:
            raise DevelopmentCandidateWorkspaceSnapshotError(
                "workspace entry payload must be immutable bytes"
            )
        if self.entry_type is DevelopmentCandidateWorkspaceEntryType.DIRECTORY:
            if self.payload:
                raise DevelopmentCandidateWorkspaceSnapshotError(
                    "workspace directory payload must be empty"
                )
        elif self.entry_type is DevelopmentCandidateWorkspaceEntryType.REGULAR:
            if len(self.payload) > DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_REGULAR_BYTES:
                raise DevelopmentCandidateWorkspaceSnapshotError(
                    "workspace regular payload exceeds its per-file limit"
                )
        else:
            _decode_symlink_target(self.payload)

    @property
    def kind(self) -> str:
        return {
            DevelopmentCandidateWorkspaceEntryType.DIRECTORY: "directory",
            DevelopmentCandidateWorkspaceEntryType.REGULAR: "file",
            DevelopmentCandidateWorkspaceEntryType.SYMLINK: "symlink",
        }[self.entry_type]

    @property
    def payload_bytes(self) -> int:
        return len(self.payload)

    @property
    def payload_sha256(self) -> str:
        return sha256(self.payload).hexdigest()

    @property
    def content_sha256(self) -> str | None:
        if self.entry_type is DevelopmentCandidateWorkspaceEntryType.REGULAR:
            return self.payload_sha256
        return None

    @property
    def symlink_target(self) -> str | None:
        if self.entry_type is DevelopmentCandidateWorkspaceEntryType.SYMLINK:
            return _decode_symlink_target(self.payload)
        return None

    def to_answer_free_record(self) -> dict[str, object]:
        """Return metadata and payload identity, never payload bytes."""

        self.__post_init__()
        return {
            "entry_type": self.kind,
            "entry_type_code": int(self.entry_type),
            "path": self.path,
            "mode": self.mode,
            "payload_bytes": self.payload_bytes,
            "payload_sha256": self.payload_sha256,
        }


def _parent_path(path: str) -> str:
    if "/" not in path:
        return ""
    return path.rsplit("/", 1)[0]


def _basename_bytes(path: str) -> bytes:
    return path.rsplit("/", 1)[-1].encode("utf-8", errors="strict")


def _canonical_preorder(
    entries: tuple[DevelopmentCandidateWorkspaceEntry, ...],
) -> tuple[DevelopmentCandidateWorkspaceEntry, ...]:
    children: dict[str, list[DevelopmentCandidateWorkspaceEntry]] = {}
    for entry in entries[1:]:
        children.setdefault(_parent_path(entry.path), []).append(entry)
    for siblings in children.values():
        siblings.sort(key=lambda item: _basename_bytes(item.path))

    ordered: list[DevelopmentCandidateWorkspaceEntry] = []

    def visit(entry: DevelopmentCandidateWorkspaceEntry) -> None:
        ordered.append(entry)
        if entry.entry_type is DevelopmentCandidateWorkspaceEntryType.DIRECTORY:
            for child in children.get(entry.path, ()):
                visit(child)

    visit(entries[0])
    return tuple(ordered)


def _validate_entry_sequence(
    entries: object,
) -> tuple[DevelopmentCandidateWorkspaceEntry, ...]:
    if type(entries) is not tuple or not all(
        type(entry) is DevelopmentCandidateWorkspaceEntry for entry in entries
    ):
        raise DevelopmentCandidateWorkspaceSnapshotError(
            "workspace snapshot entries must be an exact immutable tuple"
        )
    if not 1 <= len(entries) <= DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_ENTRIES:
        raise DevelopmentCandidateWorkspaceSnapshotError(
            "workspace snapshot entry count is outside its fixed bounds"
        )
    for entry in entries:
        entry.__post_init__()
    root = entries[0]
    if (
        root.path != ""
        or root.entry_type is not DevelopmentCandidateWorkspaceEntryType.DIRECTORY
    ):
        raise DevelopmentCandidateWorkspaceSnapshotError(
            "workspace snapshot requires exactly one leading directory root"
        )
    by_path: dict[str, DevelopmentCandidateWorkspaceEntry] = {}
    total_payload = 0
    for index, entry in enumerate(entries):
        if entry.path in by_path:
            raise DevelopmentCandidateWorkspaceSnapshotError(
                "workspace snapshot contains a duplicate path"
            )
        if index > 0 and entry.path == "":
            raise DevelopmentCandidateWorkspaceSnapshotError(
                "workspace snapshot contains more than one root"
            )
        by_path[entry.path] = entry
        total_payload += entry.payload_bytes
        if total_payload > DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_TOTAL_PAYLOAD_BYTES:
            raise DevelopmentCandidateWorkspaceSnapshotError(
                "workspace snapshot exceeds the cumulative payload limit"
            )
    for entry in entries[1:]:
        if _path_components(entry.path)[0] == b"input":
            raise DevelopmentCandidateWorkspaceSnapshotError(
                "workspace snapshot must exclude the top-level input subtree"
            )
        parent = by_path.get(_parent_path(entry.path))
        if parent is None:
            raise DevelopmentCandidateWorkspaceSnapshotError(
                "workspace snapshot omits an explicit parent directory"
            )
        if parent.entry_type is not DevelopmentCandidateWorkspaceEntryType.DIRECTORY:
            raise DevelopmentCandidateWorkspaceSnapshotError(
                "workspace snapshot places an entry below a nondirectory ancestor"
            )
    canonical = _canonical_preorder(entries)
    if len(canonical) != len(entries) or canonical != entries:
        raise DevelopmentCandidateWorkspaceSnapshotError(
            "workspace snapshot is not canonical bytewise preorder"
        )
    return entries


def _encode_entries(
    entries: tuple[DevelopmentCandidateWorkspaceEntry, ...],
) -> bytes:
    _validate_entry_sequence(entries)
    encoded = bytearray(
        _HEADER.pack(
            DEVELOPMENT_CANDIDATE_WORKSPACE_SNAPSHOT_MAGIC,
            DEVELOPMENT_CANDIDATE_WORKSPACE_SNAPSHOT_VERSION,
            len(entries),
        )
    )
    for entry in entries:
        path = entry.path.encode("utf-8", errors="strict")
        encoded.extend(
            _ENTRY_HEADER.pack(
                int(entry.entry_type),
                b"\0\0\0",
                entry.mode,
                len(path),
                len(entry.payload),
            )
        )
        encoded.extend(path)
        encoded.extend(entry.payload)
    if len(encoded) > DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_ARCHIVE_BYTES:
        raise DevelopmentCandidateWorkspaceSnapshotError(
            "workspace snapshot exceeds the archive byte limit"
        )
    return bytes(encoded)


@dataclass(frozen=True, slots=True)
class DevelopmentCandidateWorkspaceSnapshot:
    """Canonical output bytes plus a raw-byte-free, nonconfidential projection."""

    entries: tuple[DevelopmentCandidateWorkspaceEntry, ...]
    schema_version: str = DEVELOPMENT_CANDIDATE_WORKSPACE_SNAPSHOT_SCHEMA_VERSION
    candidate_execution_authorized: bool = False
    scored_evaluation_eligible: bool = False
    model_selection_eligible: bool = False
    claim_pipeline_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not str
            or self.schema_version
            != DEVELOPMENT_CANDIDATE_WORKSPACE_SNAPSHOT_SCHEMA_VERSION
            or self.candidate_execution_authorized is not False
            or self.scored_evaluation_eligible is not False
            or self.model_selection_eligible is not False
            or self.claim_pipeline_eligible is not False
            or self.claim_authorized is not False
        ):
            raise DevelopmentCandidateWorkspaceSnapshotError(
                "workspace snapshot metadata or authority boundary is invalid"
            )
        _encode_entries(_validate_entry_sequence(self.entries))

    @property
    def archive_bytes(self) -> int:
        return len(_encode_entries(self.entries))

    @property
    def archive_sha256(self) -> str:
        return sha256(_encode_entries(self.entries)).hexdigest()

    @property
    def entry_count(self) -> int:
        return len(self.entries)

    @property
    def total_payload_bytes(self) -> int:
        return sum(entry.payload_bytes for entry in self.entries)

    def _answer_free_core_record(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "record_type": DEVELOPMENT_CANDIDATE_WORKSPACE_SNAPSHOT_RECORD_TYPE,
            "archive_scope": DEVELOPMENT_CANDIDATE_WORKSPACE_OUTPUT_PROJECTION_SCOPE,
            "wire_magic": DEVELOPMENT_CANDIDATE_WORKSPACE_SNAPSHOT_MAGIC.decode(
                "ascii"
            ),
            "wire_version": DEVELOPMENT_CANDIDATE_WORKSPACE_SNAPSHOT_VERSION,
            "archive_bytes": self.archive_bytes,
            "archive_sha256": self.archive_sha256,
            "entry_count": self.entry_count,
            "total_payload_bytes": self.total_payload_bytes,
            "raw_payload_bytes_included": False,
            "payload_digests_included": True,
            "paths_modes_and_sizes_included": True,
            "answer_confidentiality_established": False,
            "sealed_boundary_reuse_eligible": False,
            "limits": {
                "maximum_archive_bytes": (
                    DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_ARCHIVE_BYTES
                ),
                "maximum_entries": DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_ENTRIES,
                "maximum_depth": DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_DEPTH,
                "maximum_path_bytes": (
                    DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_PATH_BYTES
                ),
                "maximum_component_bytes": (
                    DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_COMPONENT_BYTES
                ),
                "maximum_regular_bytes": (
                    DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_REGULAR_BYTES
                ),
                "maximum_total_payload_bytes": (
                    DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_TOTAL_PAYLOAD_BYTES
                ),
                "maximum_symlink_target_bytes": (
                    DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_SYMLINK_TARGET_BYTES
                ),
            },
            "entries": [entry.to_answer_free_record() for entry in self.entries],
            "candidate_execution_authorized": self.candidate_execution_authorized,
            "scored_evaluation_eligible": self.scored_evaluation_eligible,
            "model_selection_eligible": self.model_selection_eligible,
            "claim_pipeline_eligible": self.claim_pipeline_eligible,
            "claim_authorized": self.claim_authorized,
        }

    @property
    def answer_free_record_sha256(self) -> str:
        """Hash legacy-named metadata that is raw-byte-free, not answer-safe."""

        self.__post_init__()
        return sha256(_canonical_json_bytes(self._answer_free_core_record())).hexdigest()

    def to_answer_free_record(self) -> dict[str, object]:
        """Return legacy-named digest metadata, never an answer-safe record."""

        self.__post_init__()
        core = self._answer_free_core_record()
        return {**core, "answer_free_record_sha256": self.answer_free_record_sha256}

    def canonical_answer_free_record_bytes(self) -> bytes:
        return _canonical_json_bytes(self.to_answer_free_record())


def parse_development_candidate_workspace_snapshot(
    archive: bytes,
) -> DevelopmentCandidateWorkspaceSnapshot:
    """Parse exactly one complete, canonical ``CBDSWSN1`` archive.

    Partial cap-plus-one output, trailing bytes, noncanonical ordering, unsafe
    names, and every unsupported filesystem state fail closed.  ``bytes`` is
    required exactly so a mutable producer cannot alter the archive while it
    is being validated.
    """

    if type(archive) is not bytes:
        raise DevelopmentCandidateWorkspaceSnapshotError(
            "workspace snapshot archive must be immutable bytes"
        )
    if not (
        DEVELOPMENT_CANDIDATE_WORKSPACE_SNAPSHOT_HEADER_BYTES
        <= len(archive)
        <= DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_ARCHIVE_BYTES
    ):
        raise DevelopmentCandidateWorkspaceSnapshotError(
            "workspace snapshot archive length is outside its fixed bounds"
        )
    magic, version, entry_count = _HEADER.unpack_from(archive, 0)
    if magic != DEVELOPMENT_CANDIDATE_WORKSPACE_SNAPSHOT_MAGIC:
        raise DevelopmentCandidateWorkspaceSnapshotError(
            "workspace snapshot magic is invalid"
        )
    if version != DEVELOPMENT_CANDIDATE_WORKSPACE_SNAPSHOT_VERSION:
        raise DevelopmentCandidateWorkspaceSnapshotError(
            "workspace snapshot version is invalid"
        )
    if not 1 <= entry_count <= DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_ENTRIES:
        raise DevelopmentCandidateWorkspaceSnapshotError(
            "workspace snapshot header entry count is outside its fixed bounds"
        )

    offset = DEVELOPMENT_CANDIDATE_WORKSPACE_SNAPSHOT_HEADER_BYTES
    entries: list[DevelopmentCandidateWorkspaceEntry] = []
    total_payload = 0
    for _ in range(entry_count):
        if len(archive) - offset < DEVELOPMENT_CANDIDATE_WORKSPACE_SNAPSHOT_ENTRY_HEADER_BYTES:
            raise DevelopmentCandidateWorkspaceSnapshotError(
                "workspace snapshot is truncated in an entry header"
            )
        kind_code, reserved, mode, path_bytes, payload_bytes = _ENTRY_HEADER.unpack_from(
            archive, offset
        )
        offset += DEVELOPMENT_CANDIDATE_WORKSPACE_SNAPSHOT_ENTRY_HEADER_BYTES
        if reserved != b"\0\0\0":
            raise DevelopmentCandidateWorkspaceSnapshotError(
                "workspace snapshot entry reserved bytes are nonzero"
            )
        try:
            entry_type = DevelopmentCandidateWorkspaceEntryType(kind_code)
        except ValueError as exc:
            raise DevelopmentCandidateWorkspaceSnapshotError(
                "workspace snapshot entry type is unknown"
            ) from exc
        if path_bytes > DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_PATH_BYTES:
            raise DevelopmentCandidateWorkspaceSnapshotError(
                "workspace snapshot path exceeds its byte limit"
            )
        if entry_type is DevelopmentCandidateWorkspaceEntryType.DIRECTORY:
            maximum_payload = 0
        elif entry_type is DevelopmentCandidateWorkspaceEntryType.REGULAR:
            maximum_payload = DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_REGULAR_BYTES
        else:
            maximum_payload = (
                DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_SYMLINK_TARGET_BYTES
            )
        if payload_bytes > maximum_payload:
            raise DevelopmentCandidateWorkspaceSnapshotError(
                "workspace snapshot entry payload exceeds its kind-specific limit"
            )
        total_payload += payload_bytes
        if total_payload > DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_TOTAL_PAYLOAD_BYTES:
            raise DevelopmentCandidateWorkspaceSnapshotError(
                "workspace snapshot exceeds its cumulative payload limit"
            )
        remaining = len(archive) - offset
        required = path_bytes + payload_bytes
        if required > remaining:
            raise DevelopmentCandidateWorkspaceSnapshotError(
                "workspace snapshot is truncated in an entry body"
            )
        path_raw = archive[offset : offset + path_bytes]
        offset += path_bytes
        payload = archive[offset : offset + payload_bytes]
        offset += payload_bytes
        path = _decode_utf8(path_raw, "workspace entry path")
        entries.append(
            DevelopmentCandidateWorkspaceEntry(
                entry_type=entry_type,
                path=path,
                mode=mode,
                payload=payload,
            )
        )
    if offset != len(archive):
        raise DevelopmentCandidateWorkspaceSnapshotError(
            "workspace snapshot contains trailing bytes"
        )
    snapshot = DevelopmentCandidateWorkspaceSnapshot(entries=tuple(entries))
    # Re-encoding is an independent canonicality and integer-layout check.
    if _encode_entries(snapshot.entries) != archive:
        raise DevelopmentCandidateWorkspaceSnapshotError(
            "workspace snapshot differs from its canonical encoding"
        )
    return snapshot


def canonical_development_candidate_workspace_snapshot_record_bytes(
    snapshot: DevelopmentCandidateWorkspaceSnapshot,
) -> bytes:
    """Encode digest metadata which must never be treated as sealed-safe."""

    if type(snapshot) is not DevelopmentCandidateWorkspaceSnapshot:
        raise DevelopmentCandidateWorkspaceSnapshotError(
            "snapshot must be an exact DevelopmentCandidateWorkspaceSnapshot"
        )
    return snapshot.canonical_answer_free_record_bytes()


def _root_signature(metadata: os.stat_result) -> tuple[int, ...]:
    if not stat.S_ISDIR(metadata.st_mode):
        raise DevelopmentCandidateWorkspaceSnapshotError(
            "workspace launch descriptor no longer names a directory"
        )
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _scan_workspace_twice(
    handle: WorkspaceHandle,
) -> tuple[WorkspaceScan, WorkspaceScan, int]:
    descriptor = -1
    try:
        descriptor = handle.duplicate_launch_directory()
        root_before = _root_signature(os.fstat(descriptor))
        inputs = handle.scan_inputs()
        outputs = handle.scan_outputs()
        second_inputs = handle.scan_inputs()
        second_outputs = handle.scan_outputs()
        root_after_metadata = os.fstat(descriptor)
        root_after = _root_signature(root_after_metadata)
        if (
            inputs != second_inputs
            or outputs != second_outputs
            or root_before != root_after
            or inputs.baseline_sha256 != outputs.baseline_sha256
        ):
            raise DevelopmentCandidateWorkspaceSnapshotError(
                "workspace changed across the comparison double scan"
            )
        return inputs, outputs, stat.S_IMODE(root_after_metadata.st_mode)
    except DevelopmentCandidateWorkspaceSnapshotError:
        raise
    except (AttributeError, OSError, TypeError, ValueError) as exc:
        raise DevelopmentCandidateWorkspaceSnapshotError(
            "workspace handle could not produce a stable comparison scan"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _comparison_core_record(
    *,
    snapshot: DevelopmentCandidateWorkspaceSnapshot,
    inputs: WorkspaceScan,
    outputs: WorkspaceScan,
) -> dict[str, object]:
    return {
        "schema_version": DEVELOPMENT_CANDIDATE_WORKSPACE_SNAPSHOT_SCHEMA_VERSION,
        "record_type": DEVELOPMENT_CANDIDATE_WORKSPACE_COMPARISON_RECORD_TYPE,
        "archive_scope": DEVELOPMENT_CANDIDATE_WORKSPACE_OUTPUT_PROJECTION_SCOPE,
        "snapshot_archive_sha256": snapshot.archive_sha256,
        "snapshot_answer_free_record_sha256": snapshot.answer_free_record_sha256,
        "workspace_baseline_sha256": inputs.baseline_sha256,
        "input_tree_sha256": inputs.tree_sha256,
        "output_tree_sha256": outputs.tree_sha256,
        "entry_count": snapshot.entry_count,
        "raw_snapshot_payload_bytes_included": False,
        "snapshot_payload_digests_included": True,
        "answer_confidentiality_established": False,
        "sealed_boundary_reuse_eligible": False,
        "output_projection_matched": True,
        "output_kind_compared": True,
        "output_mode_compared": True,
        "output_regular_size_compared": True,
        "output_regular_content_sha256_compared": True,
        "output_symlink_target_bytes_compared": True,
        "stable_input_tree_observed": True,
        "input_projection_compared": False,
        "mtime_ns_compared": False,
        "ownership_compared": False,
        "inode_identity_compared": False,
        "link_count_compared": False,
        "candidate_execution_authorized": False,
        "scored_evaluation_eligible": False,
        "model_selection_eligible": False,
        "claim_pipeline_eligible": False,
        "claim_authorized": False,
    }


@dataclass(frozen=True, slots=True)
class DevelopmentCandidateWorkspaceComparison:
    """Nonauthorizing equality evidence for the output-side projection."""

    snapshot_archive_sha256: str
    snapshot_answer_free_record_sha256: str
    workspace_baseline_sha256: str
    input_tree_sha256: str
    output_tree_sha256: str
    entry_count: int
    comparison_sha256: str
    output_projection_matched: bool = True
    output_kind_compared: bool = True
    output_mode_compared: bool = True
    output_regular_size_compared: bool = True
    output_regular_content_sha256_compared: bool = True
    output_symlink_target_bytes_compared: bool = True
    stable_input_tree_observed: bool = True
    input_projection_compared: bool = False
    mtime_ns_compared: bool = False
    ownership_compared: bool = False
    inode_identity_compared: bool = False
    link_count_compared: bool = False
    candidate_execution_authorized: bool = False
    scored_evaluation_eligible: bool = False
    model_selection_eligible: bool = False
    claim_pipeline_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        for label in (
            "snapshot_archive_sha256",
            "snapshot_answer_free_record_sha256",
            "workspace_baseline_sha256",
            "input_tree_sha256",
            "output_tree_sha256",
            "comparison_sha256",
        ):
            _exact_sha256(getattr(self, label), label)
        if type(self.entry_count) is not int or not (
            1 <= self.entry_count <= DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_ENTRIES
        ):
            raise DevelopmentCandidateWorkspaceSnapshotError(
                "workspace comparison entry count is invalid"
            )
        if (
            self.output_projection_matched is not True
            or self.output_kind_compared is not True
            or self.output_mode_compared is not True
            or self.output_regular_size_compared is not True
            or self.output_regular_content_sha256_compared is not True
            or self.output_symlink_target_bytes_compared is not True
            or self.stable_input_tree_observed is not True
            or self.input_projection_compared is not False
            or self.mtime_ns_compared is not False
            or self.ownership_compared is not False
            or self.inode_identity_compared is not False
            or self.link_count_compared is not False
            or self.candidate_execution_authorized is not False
            or self.scored_evaluation_eligible is not False
            or self.model_selection_eligible is not False
            or self.claim_pipeline_eligible is not False
            or self.claim_authorized is not False
        ):
            raise DevelopmentCandidateWorkspaceSnapshotError(
                "workspace comparison scope or authority boundary is invalid"
            )
        core = self._core_record()
        if self.comparison_sha256 != sha256(_canonical_json_bytes(core)).hexdigest():
            raise DevelopmentCandidateWorkspaceSnapshotError(
                "workspace comparison digest differs from its record"
            )

    def _core_record(self) -> dict[str, object]:
        return {
            "schema_version": DEVELOPMENT_CANDIDATE_WORKSPACE_SNAPSHOT_SCHEMA_VERSION,
            "record_type": DEVELOPMENT_CANDIDATE_WORKSPACE_COMPARISON_RECORD_TYPE,
            "archive_scope": DEVELOPMENT_CANDIDATE_WORKSPACE_OUTPUT_PROJECTION_SCOPE,
            "snapshot_archive_sha256": self.snapshot_archive_sha256,
            "snapshot_answer_free_record_sha256": (
                self.snapshot_answer_free_record_sha256
            ),
            "workspace_baseline_sha256": self.workspace_baseline_sha256,
            "input_tree_sha256": self.input_tree_sha256,
            "output_tree_sha256": self.output_tree_sha256,
            "entry_count": self.entry_count,
            "raw_snapshot_payload_bytes_included": False,
            "snapshot_payload_digests_included": True,
            "answer_confidentiality_established": False,
            "sealed_boundary_reuse_eligible": False,
            "output_projection_matched": self.output_projection_matched,
            "output_kind_compared": self.output_kind_compared,
            "output_mode_compared": self.output_mode_compared,
            "output_regular_size_compared": self.output_regular_size_compared,
            "output_regular_content_sha256_compared": (
                self.output_regular_content_sha256_compared
            ),
            "output_symlink_target_bytes_compared": (
                self.output_symlink_target_bytes_compared
            ),
            "stable_input_tree_observed": self.stable_input_tree_observed,
            "input_projection_compared": self.input_projection_compared,
            "mtime_ns_compared": self.mtime_ns_compared,
            "ownership_compared": self.ownership_compared,
            "inode_identity_compared": self.inode_identity_compared,
            "link_count_compared": self.link_count_compared,
            "candidate_execution_authorized": self.candidate_execution_authorized,
            "scored_evaluation_eligible": self.scored_evaluation_eligible,
            "model_selection_eligible": self.model_selection_eligible,
            "claim_pipeline_eligible": self.claim_pipeline_eligible,
            "claim_authorized": self.claim_authorized,
        }

    def to_record(self) -> dict[str, object]:
        self.__post_init__()
        return {**self._core_record(), "comparison_sha256": self.comparison_sha256}


def compare_development_candidate_workspace_snapshot_to_handle(
    snapshot: DevelopmentCandidateWorkspaceSnapshot,
    handle: WorkspaceHandle,
) -> DevelopmentCandidateWorkspaceComparison:
    """Compare every output-side archive field to two stable handle scans.

    The input scan is made stable and its digest is recorded, but inputs are
    intentionally absent from ``CBDSWSN1`` and are not compared.  Success
    proves only equality of the output-side local observation.  Timestamps,
    ownership, inode identity, and link counts are also absent and explicitly
    false in the returned comparison scope.  The result grants no execution,
    scoring, model-selection, or claim authority.
    """

    if type(snapshot) is not DevelopmentCandidateWorkspaceSnapshot:
        raise DevelopmentCandidateWorkspaceSnapshotError(
            "snapshot must be an exact DevelopmentCandidateWorkspaceSnapshot"
        )
    if type(handle) is not WorkspaceHandle:
        raise DevelopmentCandidateWorkspaceSnapshotError(
            "handle must be an exact WorkspaceHandle"
        )
    snapshot.__post_init__()
    inputs, outputs, root_mode = _scan_workspace_twice(handle)
    observed = {entry.path: entry for entry in snapshot.entries}
    scanned_entries = outputs.entries
    expected_paths = {"", *(entry.path for entry in scanned_entries)}
    if set(observed) != expected_paths:
        raise DevelopmentCandidateWorkspaceSnapshotError(
            "workspace snapshot path set differs from stable handle scans"
        )
    root = observed[""]
    if (
        root.entry_type is not DevelopmentCandidateWorkspaceEntryType.DIRECTORY
        or root.mode != root_mode
        or root.payload
    ):
        raise DevelopmentCandidateWorkspaceSnapshotError(
            "workspace snapshot root differs from the stable handle"
        )
    kind_map = {
        "directory": DevelopmentCandidateWorkspaceEntryType.DIRECTORY,
        "file": DevelopmentCandidateWorkspaceEntryType.REGULAR,
        "symlink": DevelopmentCandidateWorkspaceEntryType.SYMLINK,
    }
    for scanned in scanned_entries:
        if type(scanned) is not WorkspaceEntry:
            raise DevelopmentCandidateWorkspaceSnapshotError(
                "workspace scan contains an active entry type"
            )
        archive_entry = observed[scanned.path]
        expected_type = kind_map.get(scanned.kind)
        if expected_type is None or archive_entry.entry_type is not expected_type:
            raise DevelopmentCandidateWorkspaceSnapshotError(
                "workspace snapshot kind differs from the stable handle scan"
            )
        if archive_entry.mode != scanned.mode:
            raise DevelopmentCandidateWorkspaceSnapshotError(
                "workspace snapshot mode differs from the stable handle scan"
            )
        if expected_type is DevelopmentCandidateWorkspaceEntryType.DIRECTORY:
            if archive_entry.payload:
                raise DevelopmentCandidateWorkspaceSnapshotError(
                    "workspace directory archive payload is nonempty"
                )
        elif expected_type is DevelopmentCandidateWorkspaceEntryType.REGULAR:
            if (
                scanned.content_sha256 is None
                or archive_entry.payload_bytes != scanned.size
                or archive_entry.content_sha256 != scanned.content_sha256
            ):
                raise DevelopmentCandidateWorkspaceSnapshotError(
                    "workspace regular content differs from the stable handle scan"
                )
        else:
            if (
                type(scanned.symlink_target) is not str
                or archive_entry.payload
                != scanned.symlink_target.encode("utf-8", errors="strict")
            ):
                raise DevelopmentCandidateWorkspaceSnapshotError(
                    "workspace symlink target differs from the stable handle scan"
                )
    core = _comparison_core_record(
        snapshot=snapshot,
        inputs=inputs,
        outputs=outputs,
    )
    return DevelopmentCandidateWorkspaceComparison(
        snapshot_archive_sha256=snapshot.archive_sha256,
        snapshot_answer_free_record_sha256=snapshot.answer_free_record_sha256,
        workspace_baseline_sha256=inputs.baseline_sha256,
        input_tree_sha256=inputs.tree_sha256,
        output_tree_sha256=outputs.tree_sha256,
        entry_count=snapshot.entry_count,
        comparison_sha256=sha256(_canonical_json_bytes(core)).hexdigest(),
    )


__all__ = [
    "DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_ARCHIVE_BYTES",
    "DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_COMPONENT_BYTES",
    "DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_DEPTH",
    "DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_ENTRIES",
    "DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_PATH_BYTES",
    "DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_REGULAR_BYTES",
    "DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_SYMLINK_TARGET_BYTES",
    "DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_TOTAL_PAYLOAD_BYTES",
    "DEVELOPMENT_CANDIDATE_WORKSPACE_SNAPSHOT_ENTRY_HEADER_BYTES",
    "DEVELOPMENT_CANDIDATE_WORKSPACE_SNAPSHOT_HEADER_BYTES",
    "DEVELOPMENT_CANDIDATE_WORKSPACE_SNAPSHOT_MAGIC",
    "DEVELOPMENT_CANDIDATE_WORKSPACE_SNAPSHOT_RECORD_TYPE",
    "DEVELOPMENT_CANDIDATE_WORKSPACE_OUTPUT_PROJECTION_SCOPE",
    "DEVELOPMENT_CANDIDATE_WORKSPACE_SNAPSHOT_SCHEMA_VERSION",
    "DEVELOPMENT_CANDIDATE_WORKSPACE_SNAPSHOT_VERSION",
    "DevelopmentCandidateWorkspaceComparison",
    "DevelopmentCandidateWorkspaceEntry",
    "DevelopmentCandidateWorkspaceEntryType",
    "DevelopmentCandidateWorkspaceSnapshot",
    "DevelopmentCandidateWorkspaceSnapshotError",
    "canonical_development_candidate_workspace_snapshot_record_bytes",
    "compare_development_candidate_workspace_snapshot_to_handle",
    "parse_development_candidate_workspace_snapshot",
]
