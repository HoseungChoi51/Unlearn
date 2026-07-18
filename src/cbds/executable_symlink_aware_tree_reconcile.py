"""Semantic core for the ``symlink-aware-tree-reconcile`` method-development family.

This module is the first implementation increment of the sixteenth and final
public family, whose reviewed contract is
``SYMLINK_TREE_RECONCILE_DESIGN.md`` (accepted by rolling review ``infra-016c``).
It implements only the family-local, filesystem-independent *primary* semantic
path:

- the four desired-state decoders (JSONL, CSV, NUL records, and a
  directory-blueprint decoder over an in-memory no-follow entry list);
- the immutable leaf model, exact-match equality, and the one-hop map-based
  safe-link alias rule;
- the union leaf/ancestor-compatibility invariant;
- the five reconciliation policies and their final-tree/decision derivation;
- the byte-exact ``operations.tsv`` serializer.

It deliberately publishes **no** identities: no task contract, normalized
graph, ``domain_sha256`` commitment, registry, catalog, coverage promotion,
oracle, or workspace binding lives here yet.  The independent reference engine,
custom bundle/oracle/verifier, on-disk fixture construction, task declarations,
and the Bash feasibility canary are subsequent reviewed increments (design
publication-sequence step 2 continued).

This is public, unsealed, unscored, nonauthorizing method-development
infrastructure.  Nothing here runs candidate code, selects a model, or
authorizes a research claim.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
import io
import json
from pathlib import PurePosixPath
import re
from typing import Final, Literal, TypeAlias


SYMLINK_TREE_RECONCILE_FAMILY_ID: Final[str] = "symlink-aware-tree-reconcile"
SYMLINK_TREE_RECONCILE_GENERATOR_VERSION: Final[str] = "1.0.0"

# --- Frozen axes (retained from the coverage-v8 planned record) -------------

DesiredStateFormat: TypeAlias = Literal[
    "jsonl",
    "csv",
    "nul-records",
    "directory-blueprint",
]
ReconciliationPolicy: TypeAlias = Literal[
    "create-missing",
    "replace-mismatch",
    "remove-extra",
    "preserve-safe-links",
    "strict-exact-state",
]

DESIRED_STATE_FORMATS: Final[tuple[DesiredStateFormat, ...]] = (
    "jsonl",
    "csv",
    "nul-records",
    "directory-blueprint",
)
RECONCILIATION_POLICIES: Final[tuple[ReconciliationPolicy, ...]] = (
    "create-missing",
    "replace-mismatch",
    "remove-extra",
    "preserve-safe-links",
    "strict-exact-state",
)

# The tool tuple corrected by review infra-016b (cmp -> sha256sum); every
# member is present in the frozen FROZEN_BASH_NATIVE_EXECUTABLES policy, so the
# family stays a strict subset without widening the sealed instrument.  Recorded
# here for reference only; no coverage identity is frozen by this module.
SYMLINK_TREE_RECONCILE_ALLOWED_TOOLS: Final[tuple[str, ...]] = (
    "awk",
    "chmod",
    "cp",
    "find",
    "jq",
    "ln",
    "mkdir",
    "mv",
    "sha256sum",
    "sort",
    "stat",
)

# --- Resource bounds (design "Resource bounds") -----------------------------

MAX_ACTUAL_LEAVES: Final[int] = 96
MAX_DESIRED_LEAVES: Final[int] = 96
MAX_PAYLOAD_FILES: Final[int] = 64
MAX_PATH_UTF8_BYTES: Final[int] = 512
MAX_PATH_COMPONENT_UTF8_BYTES: Final[int] = 128
MAX_PATH_COMPONENTS: Final[int] = 12
MAX_FILE_BYTES: Final[int] = 16 * 1024
MAX_TOTAL_PAYLOAD_BYTES: Final[int] = 1024 * 1024
MAX_FINAL_LEAVES: Final[int] = 192
MAX_FINAL_FILE_BYTES: Final[int] = 1024 * 1024
MAX_OPERATIONS_TSV_BYTES: Final[int] = 256 * 1024
MAX_OUTPUT_TREE_BYTES: Final[int] = 2 * 1024 * 1024
MAX_TARGET_UTF8_BYTES: Final[int] = 512
MAX_TARGET_COMPONENT_UTF8_BYTES: Final[int] = 128
MAX_TARGET_COMPONENTS: Final[int] = 12
MAX_PAYLOAD_ID_BYTES: Final[int] = 64
MAX_DESIRED_STATE_BYTES: Final[int] = 1024 * 1024

_MODE_RE: Final[re.Pattern[str]] = re.compile(r"[0-7]{4}")
_PAYLOAD_ID_RE: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_RECORD_HEADER: Final[str] = "kind,mode,path,value"
_OPERATIONS_HEADER: Final[str] = "path\tdecision\tactual_kind\tdesired_kind\tfinal_kind"

LeafKind: TypeAlias = Literal["absent", "file", "symlink"]
Decision: TypeAlias = Literal[
    "keep",
    "create",
    "replace",
    "remove",
    "preserve-safe-link",
    "defer-missing",
    "defer-mismatch",
    "retain-extra",
]


class SymlinkTreeReconcileError(ValueError):
    """Raised when a codec, state, policy, or serialization fails closed."""


# --- Immutable leaf model ---------------------------------------------------


@dataclass(frozen=True, slots=True)
class FileLeaf:
    """A regular-file leaf: an owner-visible permission mode and exact bytes."""

    mode: int
    content: bytes

    def __post_init__(self) -> None:
        if type(self.mode) is not int or not (0 <= self.mode <= 0o777):
            raise SymlinkTreeReconcileError("file leaf mode is out of range")
        if type(self.content) is not bytes:
            raise SymlinkTreeReconcileError("file leaf content is not bytes")
        if len(self.content) > MAX_FILE_BYTES:
            raise SymlinkTreeReconcileError("file leaf exceeds its byte bound")
        if self.content and not (self.mode & 0o400):
            raise SymlinkTreeReconcileError(
                "a non-empty file leaf must be owner-readable"
            )


@dataclass(frozen=True, slots=True)
class SymlinkLeaf:
    """A symbolic-link leaf: an observed literal, never-followed target."""

    target: str

    def __post_init__(self) -> None:
        _validate_symlink_target(self.target)


Leaf: TypeAlias = FileLeaf | SymlinkLeaf
LeafMap: TypeAlias = dict[str, Leaf]


def _leaf_kind(leaf: Leaf | None) -> LeafKind:
    if leaf is None:
        return "absent"
    if type(leaf) is FileLeaf:
        return "file"
    if type(leaf) is SymlinkLeaf:
        return "symlink"
    raise SymlinkTreeReconcileError("value is not a leaf")


def leaves_match(left: Leaf, right: Leaf) -> bool:
    """Exact semantic equality (design "Logical tree model")."""

    if type(left) is FileLeaf and type(right) is FileLeaf:
        return left.mode == right.mode and left.content == right.content
    if type(left) is SymlinkLeaf and type(right) is SymlinkLeaf:
        return left.target == right.target
    return False


# --- Path, target, mode, and payload-id validation --------------------------


def _forbidden_char(value: str) -> bool:
    return any(
        ord(character) < 32
        or ord(character) == 127
        or character in {",", '"', "\\"}
        for character in value
    )


def _validate_relative_path(
    value: object,
    *,
    max_bytes: int,
    max_component_bytes: int,
    max_components: int,
    label: str,
) -> str:
    if type(value) is not str or not value:
        raise SymlinkTreeReconcileError(f"{label} is empty or non-text")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise SymlinkTreeReconcileError(f"{label} is not strict UTF-8") from exc
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or not path.parts
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
        or _forbidden_char(value)
        or len(encoded) > max_bytes
        or len(path.parts) > max_components
        or any(
            len(part.encode("utf-8")) > max_component_bytes
            for part in path.parts
        )
    ):
        raise SymlinkTreeReconcileError(
            f"{label} is not a canonical safe relative path"
        )
    return value


def _validate_leaf_path(value: object) -> str:
    return _validate_relative_path(
        value,
        max_bytes=MAX_PATH_UTF8_BYTES,
        max_component_bytes=MAX_PATH_COMPONENT_UTF8_BYTES,
        max_components=MAX_PATH_COMPONENTS,
        label="leaf path",
    )


def _validate_symlink_target(value: object) -> str:
    target = _validate_relative_path(
        value,
        max_bytes=MAX_TARGET_UTF8_BYTES,
        max_component_bytes=MAX_TARGET_COMPONENT_UTF8_BYTES,
        max_components=MAX_TARGET_COMPONENTS,
        label="symlink target",
    )
    if any(part == ".." for part in PurePosixPath(target).parts):
        raise SymlinkTreeReconcileError("symlink target has a parent component")
    return target


def _validate_mode(value: object) -> int:
    if type(value) is not str or _MODE_RE.fullmatch(value) is None:
        raise SymlinkTreeReconcileError("file mode is not a four-digit octal string")
    parsed = int(value, 8)
    if parsed > 0o777:
        raise SymlinkTreeReconcileError("file mode exceeds 0777")
    return parsed


def _validate_payload_id(value: object) -> str:
    if (
        type(value) is not str
        or _PAYLOAD_ID_RE.fullmatch(value) is None
        or len(value.encode("utf-8")) > MAX_PAYLOAD_ID_BYTES
    ):
        raise SymlinkTreeReconcileError("payload id is not canonical")
    return value


# --- Ancestor / antichain checks --------------------------------------------


def _components(path: str) -> tuple[str, ...]:
    return PurePosixPath(path).parts


def _assert_antichain(paths: tuple[str, ...], label: str) -> None:
    present = set(paths)
    for path in present:
        parts = _components(path)
        for index in range(1, len(parts)):
            ancestor = "/".join(parts[:index])
            if ancestor in present:
                raise SymlinkTreeReconcileError(
                    f"{label} has a leaf/ancestor conflict"
                )


# --- Desired-state records --------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Record:
    """One decoded four-field desired-state record before payload resolution."""

    kind: str
    mode_field: str | None
    path: str
    value: str


def _record_from_fields(
    kind: object, mode_field: object, path: object, value: object
) -> _Record:
    if kind == "file":
        if type(mode_field) is not str:
            raise SymlinkTreeReconcileError("file record requires an octal mode")
        _validate_mode(mode_field)
        _validate_payload_id(value)
        return _Record("file", mode_field, _validate_leaf_path(path), value)  # type: ignore[arg-type]
    if kind == "symlink":
        if mode_field is not None:
            raise SymlinkTreeReconcileError("symlink record must have a null mode")
        _validate_symlink_target(value)
        return _Record("symlink", None, _validate_leaf_path(path), value)  # type: ignore[arg-type]
    raise SymlinkTreeReconcileError("record kind is not file or symlink")


def _records_to_leaf_map(
    records: tuple[_Record, ...], payloads: dict[str, bytes]
) -> LeafMap:
    """Collapse exact duplicates, reject conflicts, resolve payloads."""

    by_path: dict[str, _Record] = {}
    for record in records:
        existing = by_path.get(record.path)
        if existing is None:
            by_path[record.path] = record
        elif existing != record:
            raise SymlinkTreeReconcileError(
                "two records for one path disagree"
            )
    if len(by_path) > MAX_DESIRED_LEAVES:
        raise SymlinkTreeReconcileError("desired leaves exceed their bound")
    leaves: LeafMap = {}
    for path, record in by_path.items():
        if record.kind == "file":
            content = payloads.get(record.value)
            if content is None:
                raise SymlinkTreeReconcileError(
                    "record references a missing payload"
                )
            leaves[path] = FileLeaf(_validate_mode(record.mode_field), content)
        else:
            leaves[path] = SymlinkLeaf(record.value)
    _assert_antichain(tuple(leaves), "desired state")
    return leaves


def _validate_payload_store(payloads: object) -> dict[str, bytes]:
    if type(payloads) is not dict:
        raise SymlinkTreeReconcileError("payload store is not a mapping")
    if len(payloads) > MAX_PAYLOAD_FILES:
        raise SymlinkTreeReconcileError("payload files exceed their bound")
    total = 0
    validated: dict[str, bytes] = {}
    for payload_id, content in payloads.items():
        _validate_payload_id(payload_id)
        if type(content) is not bytes or len(content) > MAX_FILE_BYTES:
            raise SymlinkTreeReconcileError("payload content violates its bound")
        total += len(content)
        validated[payload_id] = content
    if total > MAX_TOTAL_PAYLOAD_BYTES:
        raise SymlinkTreeReconcileError("total payload bytes exceed their bound")
    return validated


# --- Format decoders --------------------------------------------------------


def _strict_json_object(line: str) -> dict[str, object]:
    def hook(pairs: list[tuple[str, object]]) -> dict[str, object]:
        keys = [key for key, _value in pairs]
        if len(keys) != len(set(keys)):
            raise SymlinkTreeReconcileError("JSON object has duplicate members")
        return dict(pairs)

    try:
        value = json.loads(
            line,
            object_pairs_hook=hook,
            parse_constant=lambda token: (_ for _ in ()).throw(
                SymlinkTreeReconcileError(
                    f"JSON extension token is forbidden: {token}"
                )
            ),
            parse_float=lambda token: (_ for _ in ()).throw(
                SymlinkTreeReconcileError("JSON float is forbidden")
            ),
        )
    except SymlinkTreeReconcileError:
        raise
    except (json.JSONDecodeError, UnicodeError, RecursionError, ValueError) as exc:
        raise SymlinkTreeReconcileError("JSON record is malformed") from exc
    if type(value) is not dict:
        raise SymlinkTreeReconcileError("JSON record is not an exact object")
    return value


def _decode_jsonl(payload: bytes, payloads: dict[str, bytes]) -> LeafMap:
    if type(payload) is not bytes or len(payload) > MAX_DESIRED_STATE_BYTES:
        raise SymlinkTreeReconcileError("JSONL exceeds its byte bound")
    if payload == b"":
        return {}
    if not payload.endswith(b"\n") or b"\r" in payload:
        raise SymlinkTreeReconcileError("JSONL framing is invalid")
    try:
        lines = payload[:-1].decode("utf-8", "strict").split("\n")
    except UnicodeDecodeError as exc:
        raise SymlinkTreeReconcileError("JSONL is not strict UTF-8") from exc
    if any(not line for line in lines):
        raise SymlinkTreeReconcileError("JSONL has a blank row")
    records: list[_Record] = []
    for line in lines:
        obj = _strict_json_object(line)
        if set(obj) != {"kind", "mode", "path", "value"}:
            raise SymlinkTreeReconcileError("JSONL object members differ")
        records.append(
            _record_from_fields(obj["kind"], obj["mode"], obj["path"], obj["value"])
        )
    return _records_to_leaf_map(tuple(records), payloads)


def _decode_csv(payload: bytes, payloads: dict[str, bytes]) -> LeafMap:
    if type(payload) is not bytes or len(payload) > MAX_DESIRED_STATE_BYTES:
        raise SymlinkTreeReconcileError("CSV exceeds its byte bound")
    if not payload.endswith(b"\n") or b"\r" in payload or b"\0" in payload:
        raise SymlinkTreeReconcileError("CSV framing is invalid")
    if b'"' in payload:
        raise SymlinkTreeReconcileError("CSV quoting is not accepted")
    try:
        text = payload.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise SymlinkTreeReconcileError("CSV is not strict UTF-8") from exc
    rows = list(csv.reader(io.StringIO(text, newline=""), strict=True))
    if not rows or rows[0] != ["kind", "mode", "path", "value"]:
        raise SymlinkTreeReconcileError("CSV header is invalid")
    records: list[_Record] = []
    for row in rows[1:]:
        if len(row) != 4:
            raise SymlinkTreeReconcileError("CSV row width is invalid")
        kind, mode_field, path, value = row
        mode: str | None = mode_field if kind == "file" else None
        if kind == "symlink" and mode_field != "":
            raise SymlinkTreeReconcileError("symlink CSV row must have an empty mode")
        records.append(_record_from_fields(kind, mode, path, value))
    return _records_to_leaf_map(tuple(records), payloads)


def _decode_nul_records(payload: bytes, payloads: dict[str, bytes]) -> LeafMap:
    if type(payload) is not bytes or len(payload) > MAX_DESIRED_STATE_BYTES:
        raise SymlinkTreeReconcileError("NUL records exceed their byte bound")
    if payload == b"":
        return {}
    if not payload.endswith(b"\0"):
        raise SymlinkTreeReconcileError("NUL records are unterminated")
    fields = payload[:-1].split(b"\0")
    if len(fields) % 4:
        raise SymlinkTreeReconcileError("NUL record framing is invalid")
    records: list[_Record] = []
    for offset in range(0, len(fields), 4):
        try:
            kind = fields[offset].decode("utf-8", "strict")
            mode_field = fields[offset + 1].decode("utf-8", "strict")
            path = fields[offset + 2].decode("utf-8", "strict")
            value = fields[offset + 3].decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise SymlinkTreeReconcileError("NUL records are not strict UTF-8") from exc
        mode: str | None
        if kind == "file":
            mode = mode_field
        elif kind == "symlink":
            if mode_field != "":
                raise SymlinkTreeReconcileError(
                    "symlink NUL record must have an empty mode"
                )
            mode = None
        else:
            raise SymlinkTreeReconcileError("NUL record kind is invalid")
        records.append(_record_from_fields(kind, mode, path, value))
    return _records_to_leaf_map(tuple(records), payloads)


@dataclass(frozen=True, slots=True)
class BlueprintEntry:
    """One no-follow observation of ``input/desired-blueprint/`` (or actual/)."""

    path: str
    kind: LeafKind
    mode: int | None = None
    content: bytes | None = None
    target: str | None = None

    def __post_init__(self) -> None:
        _validate_leaf_path(self.path)
        if self.kind == "file":
            if type(self.mode) is not int or self.content is None or self.target is not None:
                raise SymlinkTreeReconcileError("file blueprint entry is malformed")
        elif self.kind == "symlink":
            if self.target is None or self.mode is not None or self.content is not None:
                raise SymlinkTreeReconcileError("symlink blueprint entry is malformed")
        else:
            raise SymlinkTreeReconcileError("blueprint entry kind must be file or symlink")


def _entries_to_leaf_map(entries: tuple[BlueprintEntry, ...], label: str) -> LeafMap:
    if type(entries) is not tuple:
        raise SymlinkTreeReconcileError("blueprint entries must be a tuple")
    leaves: LeafMap = {}
    for entry in entries:
        if type(entry) is not BlueprintEntry:
            raise SymlinkTreeReconcileError("blueprint entry has wrong type")
        entry.__post_init__()
        if entry.path in leaves:
            raise SymlinkTreeReconcileError("blueprint has a duplicate path")
        if entry.kind == "file":
            leaves[entry.path] = FileLeaf(entry.mode, entry.content)  # type: ignore[arg-type]
        else:
            leaves[entry.path] = SymlinkLeaf(entry.target)  # type: ignore[arg-type]
    _assert_antichain(tuple(leaves), label)
    return leaves


def decode_desired_state(
    desired_format: DesiredStateFormat,
    *,
    payload_bytes: bytes | None = None,
    payloads: dict[str, bytes] | None = None,
    blueprint_entries: tuple[BlueprintEntry, ...] | None = None,
) -> LeafMap:
    """Decode any of the four desired-state formats to the one leaf map."""

    if desired_format == "directory-blueprint":
        if blueprint_entries is None:
            blueprint_entries = ()
        leaves = _entries_to_leaf_map(blueprint_entries, "desired blueprint")
        if len(leaves) > MAX_DESIRED_LEAVES:
            raise SymlinkTreeReconcileError("desired leaves exceed their bound")
        return leaves
    if desired_format not in ("jsonl", "csv", "nul-records"):
        raise SymlinkTreeReconcileError("desired-state format is unknown")
    if payload_bytes is None:
        payload_bytes = b""
    resolved = _validate_payload_store({} if payloads is None else payloads)
    if desired_format == "jsonl":
        return _decode_jsonl(payload_bytes, resolved)
    if desired_format == "csv":
        return _decode_csv(payload_bytes, resolved)
    return _decode_nul_records(payload_bytes, resolved)


def decode_actual_state(entries: tuple[BlueprintEntry, ...]) -> LeafMap:
    """Decode the no-follow actual leaf state (absent root == empty)."""

    leaves = _entries_to_leaf_map(entries, "actual state")
    if len(leaves) > MAX_ACTUAL_LEAVES:
        raise SymlinkTreeReconcileError("actual leaves exceed their bound")
    return leaves


# --- Safe-link alias (design "Safe-link alias", 6 conditions) ---------------


def is_safe_link_alias(path: str, actual: LeafMap, desired: LeafMap) -> bool:
    actual_leaf = actual.get(path)
    desired_leaf = desired.get(path)
    # An actual symlink standing at a desired regular-file path.
    if type(actual_leaf) is not SymlinkLeaf or type(desired_leaf) is not FileLeaf:
        return False
    target = actual_leaf.target
    # (2) canonical, relative, no parent component -- guaranteed by validation.
    try:
        _validate_symlink_target(target)
    except SymlinkTreeReconcileError:
        return False
    # (3) resolve one hop lexically from P's parent; Q must be in-tree and != P.
    resolved = (PurePosixPath(path).parent / target).as_posix()
    if resolved == path or resolved not in desired:
        return False
    q_desired = desired[resolved]
    # (4) desired Q is a regular file, not a symlink.
    if type(q_desired) is not FileLeaf:
        return False
    # (5) desired files P and Q have identical bytes and modes.
    if not leaves_match(desired_leaf, q_desired):
        return False
    # (6) the actual entry at Q is a regular file or absent -- never a symlink.
    q_actual = actual.get(resolved)
    if type(q_actual) is SymlinkLeaf:
        return False
    return True


# --- Reconciliation policies (design action table) --------------------------

Condition: TypeAlias = Literal["exact", "M", "X", "E", "A"]
Action: TypeAlias = Literal["keep", "create", "replace", "remove", "retain", "defer", "preserve"]

_ACTION_TABLE: Final[dict[str, dict[str, str]]] = {
    "create-missing": {"M": "create", "X": "defer", "E": "retain", "A": "defer"},
    "replace-mismatch": {"M": "defer", "X": "replace", "E": "retain", "A": "replace"},
    "remove-extra": {"M": "defer", "X": "defer", "E": "remove", "A": "defer"},
    "preserve-safe-links": {"M": "create", "X": "replace", "E": "remove", "A": "preserve"},
    "strict-exact-state": {"M": "create", "X": "replace", "E": "remove", "A": "replace"},
}

_DECISION_STRINGS: Final[dict[tuple[str, str], Decision]] = {
    ("exact", "keep"): "keep",
    ("M", "create"): "create",
    ("M", "defer"): "defer-missing",
    ("X", "replace"): "replace",
    ("X", "defer"): "defer-mismatch",
    ("E", "retain"): "retain-extra",
    ("E", "remove"): "remove",
    ("A", "preserve"): "preserve-safe-link",
    ("A", "replace"): "replace",
    ("A", "defer"): "defer-mismatch",
}


def _classify(path: str, actual: LeafMap, desired: LeafMap) -> Condition:
    actual_leaf = actual.get(path)
    desired_leaf = desired.get(path)
    if actual_leaf is not None and desired_leaf is not None:
        if leaves_match(actual_leaf, desired_leaf):
            return "exact"
        if is_safe_link_alias(path, actual, desired):
            return "A"
        return "X"
    if desired_leaf is not None:
        return "M"
    return "E"


@dataclass(frozen=True, slots=True)
class DecisionRow:
    path: str
    decision: Decision
    actual_kind: LeafKind
    desired_kind: LeafKind
    final_kind: LeafKind


@dataclass(frozen=True, slots=True)
class ReconciledState:
    final: tuple[tuple[str, Leaf], ...]
    rows: tuple[DecisionRow, ...]

    def final_map(self) -> LeafMap:
        return dict(self.final)


def reconcile(
    policy: ReconciliationPolicy, actual: LeafMap, desired: LeafMap
) -> ReconciledState:
    """Derive the final leaf map and one decision row per union path."""

    if policy not in RECONCILIATION_POLICIES:
        raise SymlinkTreeReconcileError("reconciliation policy is unknown")
    union_paths = tuple(sorted(set(actual) | set(desired), key=lambda p: p.encode("utf-8")))
    _assert_antichain(union_paths, "actual/desired union")
    table = _ACTION_TABLE[policy]
    final: dict[str, Leaf] = {}
    rows: list[DecisionRow] = []
    for path in union_paths:
        actual_leaf = actual.get(path)
        desired_leaf = desired.get(path)
        condition = _classify(path, actual, desired)
        action = "keep" if condition == "exact" else table[condition]
        decision = _DECISION_STRINGS[(condition, action)]
        if action in ("keep", "retain", "preserve"):
            final_leaf: Leaf | None = actual_leaf
        elif action in ("create", "replace"):
            final_leaf = desired_leaf
        elif action == "remove":
            final_leaf = None
        elif action == "defer":
            final_leaf = None if condition == "M" else actual_leaf
        else:  # pragma: no cover - table is exhaustive
            raise SymlinkTreeReconcileError("unreachable action")
        if final_leaf is not None:
            final[path] = final_leaf
        rows.append(
            DecisionRow(
                path=path,
                decision=decision,
                actual_kind=_leaf_kind(actual_leaf),
                desired_kind=_leaf_kind(desired_leaf),
                final_kind=_leaf_kind(final_leaf),
            )
        )
    if len(final) > MAX_FINAL_LEAVES:
        raise SymlinkTreeReconcileError("final leaves exceed their bound")
    final_file_bytes = sum(
        len(leaf.content) for leaf in final.values() if type(leaf) is FileLeaf
    )
    if final_file_bytes > MAX_FINAL_FILE_BYTES:
        raise SymlinkTreeReconcileError("final file bytes exceed their bound")
    ordered_final = tuple(
        (path, final[path])
        for path in sorted(final, key=lambda p: p.encode("utf-8"))
    )
    return ReconciledState(final=ordered_final, rows=tuple(rows))


# --- Canonical decision-log serialization -----------------------------------


def _forbidden_tsv_field(value: str) -> bool:
    return any(character in {"\t", "\r", "\n", "\0"} for character in value)


def serialize_operations_tsv(rows: tuple[DecisionRow, ...]) -> bytes:
    """Serialize the byte-exact ``operations.tsv`` (design "Canonical decision log")."""

    seen: set[str] = set()
    ordered = sorted(rows, key=lambda row: row.path.encode("utf-8"))
    lines = [_OPERATIONS_HEADER]
    for row in ordered:
        if row.path in seen:
            raise SymlinkTreeReconcileError("operations log has a duplicate path")
        seen.add(row.path)
        if _forbidden_tsv_field(row.path):
            raise SymlinkTreeReconcileError("operations log path holds a delimiter")
        if row.decision not in {value for value in _DECISION_STRINGS.values()}:
            raise SymlinkTreeReconcileError("operations log decision is invalid")
        for kind in (row.actual_kind, row.desired_kind, row.final_kind):
            if kind not in {"absent", "file", "symlink"}:
                raise SymlinkTreeReconcileError("operations log kind is invalid")
        lines.append(
            "\t".join(
                (row.path, row.decision, row.actual_kind, row.desired_kind, row.final_kind)
            )
        )
    rendered = ("\n".join(lines) + "\n").encode("utf-8")
    if len(rendered) > MAX_OPERATIONS_TSV_BYTES:
        raise SymlinkTreeReconcileError("operations log exceeds its byte bound")
    return rendered


__all__ = [
    "SYMLINK_TREE_RECONCILE_FAMILY_ID",
    "SYMLINK_TREE_RECONCILE_ALLOWED_TOOLS",
    "DESIRED_STATE_FORMATS",
    "RECONCILIATION_POLICIES",
    "SymlinkTreeReconcileError",
    "FileLeaf",
    "SymlinkLeaf",
    "BlueprintEntry",
    "DecisionRow",
    "ReconciledState",
    "leaves_match",
    "is_safe_link_alias",
    "decode_desired_state",
    "decode_actual_state",
    "reconcile",
    "serialize_operations_tsv",
]
