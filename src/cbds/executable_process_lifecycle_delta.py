"""Executable-static deltas over bounded synthetic process snapshots.

The family compares ordinary files under ``input/process-lifecycle``.  It
does not inspect live process state or perform process actions.  A canonical
PID entry is classified as absent, unknown, or valid.  Unknown on either
endpoint suppresses that PID, preventing malformed or unreadable evidence
from being mislabeled as a start or exit.

Stable identity is ``(boot_id, pid, start_ticks)``.  Reuse of one PID is an
old-instance exit followed by a new-instance start.  CPU is a synthetic
point-in-time ``cpu_milli_percent`` observation, not cumulative CPU time.

This is public, unsealed, nonauthorizing method-development infrastructure.
The workspace verifier observes only final JSONL and preserved inputs under
trusted quiescence; it cannot prove read/tool history, process history,
atomicity, candidate exit status, transient state, or global quiescence.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from hashlib import sha256
import json
import os
from pathlib import PurePosixPath
import re
from typing import Final, Literal, TypeAlias
import unicodedata

from .benchmark import NormalizedSemanticGraph, OperatorNode
from .executable_fixture_bundle import (
    EXECUTABLE_FIXTURE_BINDING_VERSION,
    EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION,
    compute_bound_fixture_sha256,
    compute_fixture_definition_semantic_sha256,
)
from .executable_fixture_profiles import (
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
    ExecutableFixtureProfile,
)
from .executable_static_types import (
    EXECUTABLE_STATIC_CONTRACT_VERSION,
    EXECUTABLE_STATIC_FAMILY_VERSION,
    EXECUTABLE_STATIC_SCHEMA_VERSION,
    METHOD_DEVELOPMENT_SPLIT,
    OpaqueFixtureDescriptor,
    domain_sha256,
    task_id_from_contract,
)
from .executable_workspace import (
    MAX_TOTAL_BYTES,
    ExecutableWorkspaceError,
    ExpectedFile,
    FixtureDefinition,
    InputFile,
    InputHardlink,
    InputSymlink,
    WorkspaceHandle,
    materialize_fixture,
    validate_expected_output_policy,
)


PROCESS_LIFECYCLE_DELTA_FAMILY_ID: Final[str] = "process-lifecycle-delta"
PROCESS_LIFECYCLE_DELTA_FILESYSTEM_IDENTITY: Final[str] = (
    "paired-process-state-snapshots"
)
PROCESS_LIFECYCLE_DELTA_OUTPUT_IDENTITY: Final[str] = (
    "pid-lifecycle-transition-report"
)
PROCESS_LIFECYCLE_DELTA_GENERATOR_VERSION: Final[str] = "1.0.0"
PROCESS_LIFECYCLE_DELTA_VERIFIER_IDENTITY: Final[str] = (
    "verify-process-lifecycle-delta-v1"
)
PROCESS_LIFECYCLE_DELTA_SOURCE_ROOT: Final[str] = "input/process-lifecycle"
PROCESS_LIFECYCLE_DELTA_PAIR_INPUT: Final[str] = (
    "input/process-lifecycle/pair.json"
)
PROCESS_LIFECYCLE_DELTA_OUTPUT: Final[str] = "output/transitions.jsonl"
PROCESS_LIFECYCLE_DELTA_OUTPUT_MODE: Final[int] = 0o644
PROCESS_LIFECYCLE_DELTA_OUTPUT_MAXIMUM_BYTES: Final[int] = 1024 * 1024
PROCESS_LIFECYCLE_DELTA_PROVED_MAXIMUM_TOTAL_OUTPUT_BYTES: Final[int] = (
    PROCESS_LIFECYCLE_DELTA_OUTPUT_MAXIMUM_BYTES
)
PROCESS_LIFECYCLE_DELTA_PROOF_CHANGED_OUTPUT_BYTES: Final[int] = 855_808
PROCESS_LIFECYCLE_DELTA_PROOF_DISJOINT_OUTPUT_BYTES: Final[int] = 864_704
PROCESS_LIFECYCLE_DELTA_PAIR_MAXIMUM_BYTES: Final[int] = 4 * 1024
PROCESS_LIFECYCLE_DELTA_STATUS_MAXIMUM_BYTES: Final[int] = 4 * 1024
PROCESS_LIFECYCLE_DELTA_SIDECAR_MAXIMUM_BYTES: Final[int] = 4 * 1024
PROCESS_LIFECYCLE_DELTA_INPUT_MAXIMUM_BYTES: Final[int] = 8 * 1024 * 1024
PROCESS_LIFECYCLE_DELTA_MAXIMUM_PROCESSES: Final[int] = 64
PROCESS_LIFECYCLE_DELTA_MAXIMUM_UNION_PROCESSES: Final[int] = 128
PROCESS_LIFECYCLE_DELTA_MAXIMUM_PID: Final[int] = 4_194_304
PROCESS_LIFECYCLE_DELTA_MAXIMUM_INTEGER: Final[int] = 9_007_199_254_740_991
PROCESS_LIFECYCLE_DELTA_MAXIMUM_UID: Final[int] = 4_294_967_295
PROCESS_LIFECYCLE_DELTA_MAXIMUM_CPU_MILLI_PERCENT: Final[int] = 100_000
PROCESS_LIFECYCLE_DELTA_COMM_MAXIMUM_UTF8_BYTES: Final[int] = 64
PROCESS_LIFECYCLE_DELTA_SIDECAR_ITEM_MAXIMUM_UTF8_BYTES: Final[int] = 128
PROCESS_LIFECYCLE_DELTA_SIDECAR_TOTAL_MAXIMUM_UTF8_BYTES: Final[int] = 512
PROCESS_LIFECYCLE_DELTA_MAXIMUM_ARRAY_ITEMS: Final[int] = 32
PROCESS_LIFECYCLE_DELTA_JSON_MAXIMUM_DEPTH: Final[int] = 8
PROCESS_LIFECYCLE_DELTA_JSON_MAXIMUM_NODES: Final[int] = 4_096
PROCESS_LIFECYCLE_DELTA_JSON_MAXIMUM_OBJECT_MEMBERS: Final[int] = 32
PROCESS_LIFECYCLE_DELTA_ALLOWED_TOOLS: Final[tuple[str, ...]] = (
    "awk",
    "comm",
    "jq",
    "mkdir",
    "sort",
)

PROCESS_LIFECYCLE_DELTA_FINAL_OUTPUT_OBSERVED: Final[bool] = True
PROCESS_LIFECYCLE_DELTA_INPUT_PRESERVATION_OBSERVED: Final[bool] = True
PROCESS_LIFECYCLE_DELTA_ATOMICITY_OBSERVED: Final[bool] = False
PROCESS_LIFECYCLE_DELTA_TOOL_HISTORY_OBSERVED: Final[bool] = False
PROCESS_LIFECYCLE_DELTA_READ_SCOPE_OBSERVED: Final[bool] = False
PROCESS_LIFECYCLE_DELTA_CANDIDATE_EXIT_STATUS_OBSERVED: Final[bool] = False
PROCESS_LIFECYCLE_DELTA_TRANSIENT_STATE_OBSERVED: Final[bool] = False
PROCESS_LIFECYCLE_DELTA_LIVE_PROC_OBSERVED: Final[bool] = False
PROCESS_LIFECYCLE_DELTA_PROCESS_ACTIONS_OBSERVED: Final[bool] = False
PROCESS_LIFECYCLE_DELTA_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE: Final[
    bool
] = True
PROCESS_LIFECYCLE_DELTA_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE: Final[
    bool
] = False

SnapshotPair: TypeAlias = Literal[
    "status-only",
    "status-and-cmdline",
    "status-and-cgroups",
    "complete-synthetic-proc",
]
SelectionPolicy: TypeAlias = Literal[
    "all-changes",
    "starts-only",
    "exits-only",
    "state-changes",
    "resource-threshold-crossings",
]
Transition: TypeAlias = Literal["started", "exited", "changed"]
ProcessState: TypeAlias = Literal["R", "S", "D", "Z", "T", "I"]
CrossingDirection: TypeAlias = Literal["upward", "downward"]

PROCESS_LIFECYCLE_DELTA_SNAPSHOT_PAIRS: Final[tuple[SnapshotPair, ...]] = (
    "status-only",
    "status-and-cmdline",
    "status-and-cgroups",
    "complete-synthetic-proc",
)
PROCESS_LIFECYCLE_DELTA_SELECTION_POLICIES: Final[
    tuple[SelectionPolicy, ...]
] = (
    "all-changes",
    "starts-only",
    "exits-only",
    "state-changes",
    "resource-threshold-crossings",
)
PROCESS_LIFECYCLE_DELTA_STATES: Final[tuple[ProcessState, ...]] = (
    "R",
    "S",
    "D",
    "Z",
    "T",
    "I",
)

_TASK_ID_RE: Final[re.Pattern[str]] = re.compile(r"mds-[0-9a-f]{24}\Z")
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_PID_RE: Final[re.Pattern[str]] = re.compile(r"[1-9][0-9]*\Z")
_BOOT_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
_PAIR_KEYS: Final[frozenset[str]] = frozenset(
    {"schema_version", "before", "after", "thresholds"}
)
_ENDPOINT_KEYS: Final[frozenset[str]] = frozenset(
    {"boot_id", "snapshot_ticks"}
)
_THRESHOLD_KEYS: Final[frozenset[str]] = frozenset(
    {"rss_kib", "cpu_milli_percent"}
)
_STATUS_KEYS: Final[frozenset[str]] = frozenset(
    {
        "comm",
        "cpu_milli_percent",
        "pid",
        "ppid",
        "rss_kib",
        "start_ticks",
        "state",
        "uid",
    }
)
_CROSSING_KEYS: Final[frozenset[str]] = _THRESHOLD_KEYS
_EVENT_KEYS: Final[frozenset[str]] = frozenset(
    {
        "boot_id",
        "pid",
        "start_ticks",
        "event",
        "before",
        "after",
        "changed_fields",
        "threshold_crossings",
    }
)
_CHANGED_FIELD_ORDER: Final[tuple[str, ...]] = (
    "ppid",
    "uid",
    "state",
    "rss_kib",
    "cpu_milli_percent",
    "comm",
    "argv",
    "cgroups",
)
_TRANSITION_RANK: Final[dict[str, int]] = {
    "exited": 0,
    "started": 1,
    "changed": 2,
}


class ProcessLifecycleDeltaError(ValueError):
    """Raised when the closed process-lifecycle contract is violated."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def _closed_text(
    value: object,
    allowed: tuple[str, ...],
    field_name: str,
) -> str:
    if type(value) is not str or value not in allowed:
        raise ProcessLifecycleDeltaError(
            f"{field_name} is outside its closed set"
        )
    return value


def _bounded_int(
    value: object,
    field_name: str,
    *,
    minimum: int = 0,
    maximum: int = PROCESS_LIFECYCLE_DELTA_MAXIMUM_INTEGER,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ProcessLifecycleDeltaError(
            f"{field_name} must be an exact bounded integer"
        )
    return value


def _validate_scalar_text(
    value: object,
    field_name: str,
    *,
    minimum_bytes: int,
    maximum_bytes: int,
    forbidden_categories: frozenset[str],
    forbidden_characters: frozenset[str] = frozenset(),
) -> str:
    if type(value) is not str:
        raise ProcessLifecycleDeltaError(f"{field_name} must be exact text")
    if any(
        unicodedata.category(character) in forbidden_categories
        or character in forbidden_characters
        for character in value
    ):
        raise ProcessLifecycleDeltaError(
            f"{field_name} contains a forbidden character"
        )
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ProcessLifecycleDeltaError(
            f"{field_name} is not scalar Unicode"
        ) from exc
    if not minimum_bytes <= len(encoded) <= maximum_bytes:
        raise ProcessLifecycleDeltaError(
            f"{field_name} exceeds its UTF-8 byte bounds"
        )
    return value


def _validate_comm(value: object, field_name: str = "comm") -> str:
    return _validate_scalar_text(
        value,
        field_name,
        minimum_bytes=1,
        maximum_bytes=PROCESS_LIFECYCLE_DELTA_COMM_MAXIMUM_UTF8_BYTES,
        forbidden_categories=frozenset({"Cc", "Cf"}),
    )


def _require_exact_keys(
    value: object,
    keys: frozenset[str],
    field_name: str,
) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise ProcessLifecycleDeltaError(
            f"{field_name} must be an exact closed object"
        )
    return value


def _prebound_json_text(text: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > PROCESS_LIFECYCLE_DELTA_JSON_MAXIMUM_DEPTH:
                raise ProcessLifecycleDeltaError(
                    "JSON exceeds its nesting-depth bound"
                )
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise ProcessLifecycleDeltaError(
                    "JSON delimiters are unbalanced"
                )
    if in_string or escaped or depth != 0:
        raise ProcessLifecycleDeltaError("JSON framing is incomplete")


def _bounded_json_int(token: str) -> int:
    # Bound the lexical token before conversion.  This avoids depending on
    # CPython's process-global decimal-digit limit for attacker-sized input.
    if (
        type(token) is not str
        or re.fullmatch(r"(?:0|[1-9][0-9]{0,15})", token) is None
    ):
        raise ProcessLifecycleDeltaError(
            "JSON integer is not a canonical bounded nonnegative decimal"
        )
    value = int(token, 10)
    if value > PROCESS_LIFECYCLE_DELTA_MAXIMUM_INTEGER:
        raise ProcessLifecycleDeltaError("JSON integer exceeds safe bounds")
    return value


def _reject_float(token: str) -> object:
    raise ProcessLifecycleDeltaError(
        f"JSON floating-point token is forbidden: {token[:16]}"
    )


def _reject_constant(token: str) -> object:
    raise ProcessLifecycleDeltaError(
        f"JSON nonfinite token is forbidden: {token}"
    )


def _reject_duplicate_object(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    if len(pairs) > PROCESS_LIFECYCLE_DELTA_JSON_MAXIMUM_OBJECT_MEMBERS:
        raise ProcessLifecycleDeltaError(
            "JSON object exceeds its member bound"
        )
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ProcessLifecycleDeltaError(
                "JSON object contains a duplicate key"
            )
        result[key] = value
    return result


def _validate_json_tree(root: object) -> None:
    stack: list[tuple[object, int]] = [(root, 1)]
    count = 0
    while stack:
        value, depth = stack.pop()
        count += 1
        if (
            count > PROCESS_LIFECYCLE_DELTA_JSON_MAXIMUM_NODES
            or depth > PROCESS_LIFECYCLE_DELTA_JSON_MAXIMUM_DEPTH
        ):
            raise ProcessLifecycleDeltaError(
                "JSON tree exceeds its node/depth bound"
            )
        if type(value) is dict:
            if (
                len(value)
                > PROCESS_LIFECYCLE_DELTA_JSON_MAXIMUM_OBJECT_MEMBERS
            ):
                raise ProcessLifecycleDeltaError(
                    "JSON object exceeds its member bound"
                )
            stack.extend((item, depth + 1) for item in value.values())
        elif type(value) is list:
            if len(value) > PROCESS_LIFECYCLE_DELTA_MAXIMUM_ARRAY_ITEMS:
                raise ProcessLifecycleDeltaError(
                    "JSON array exceeds its item bound"
                )
            stack.extend((item, depth + 1) for item in value)
        elif type(value) is str:
            try:
                value.encode("utf-8", errors="strict")
            except UnicodeEncodeError as exc:
                raise ProcessLifecycleDeltaError(
                    "JSON string is not scalar Unicode"
                ) from exc
        elif value is None or type(value) in {bool, int}:
            continue
        else:
            raise ProcessLifecycleDeltaError(
                "JSON contains an unsupported scalar"
            )


def _decode_json_strict(payload: bytes, maximum_bytes: int) -> object:
    if (
        type(payload) is not bytes
        or not payload
        or len(payload) > maximum_bytes
    ):
        raise ProcessLifecycleDeltaError("JSON payload violates its byte bound")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ProcessLifecycleDeltaError(
            "JSON payload is not strict UTF-8"
        ) from exc
    if text.startswith("\ufeff") or "\x00" in text:
        raise ProcessLifecycleDeltaError("JSON BOM or NUL is forbidden")
    _prebound_json_text(text)
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_object,
            parse_int=_bounded_json_int,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except ProcessLifecycleDeltaError:
        raise
    except (json.JSONDecodeError, RecursionError, TypeError, ValueError) as exc:
        raise ProcessLifecycleDeltaError(
            "JSON payload is outside the strict grammar"
        ) from exc
    _validate_json_tree(value)
    return value


def _canonical_json(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8", errors="strict")
            + b"\n"
        )
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ProcessLifecycleDeltaError(
            "value cannot be encoded as canonical JSON"
        ) from exc


def _decode_canonical_json(payload: bytes, maximum_bytes: int) -> object:
    value = _decode_json_strict(payload, maximum_bytes)
    if _canonical_json(value) != payload:
        raise ProcessLifecycleDeltaError(
            "source is not canonical JSON plus one LF"
        )
    return value


@dataclass(frozen=True, slots=True)
class ProcessLifecycleDeltaParameters:
    snapshot_pair: SnapshotPair
    selection_policy: SelectionPolicy

    def __post_init__(self) -> None:
        if type(self) is not ProcessLifecycleDeltaParameters:
            raise ProcessLifecycleDeltaError("parameters have wrong exact type")
        _closed_text(
            self.snapshot_pair,
            PROCESS_LIFECYCLE_DELTA_SNAPSHOT_PAIRS,
            "snapshot_pair",
        )
        _closed_text(
            self.selection_policy,
            PROCESS_LIFECYCLE_DELTA_SELECTION_POLICIES,
            "selection_policy",
        )

    def to_record(self) -> dict[str, str]:
        self.__post_init__()
        return {
            "parameter_type": PROCESS_LIFECYCLE_DELTA_FAMILY_ID,
            "snapshot_pair": self.snapshot_pair,
            "selection_policy": self.selection_policy,
        }


@dataclass(frozen=True, slots=True)
class ProcessPairMetadata:
    boot_id: str
    before_snapshot_ticks: int
    after_snapshot_ticks: int
    rss_threshold_kib: int
    cpu_threshold_milli_percent: int

    def __post_init__(self) -> None:
        if (
            type(self) is not ProcessPairMetadata
            or type(self.boot_id) is not str
            or _BOOT_ID_RE.fullmatch(self.boot_id) is None
        ):
            raise ProcessLifecycleDeltaError("pair metadata has invalid boot ID")
        _bounded_int(
            self.before_snapshot_ticks,
            "before snapshot_ticks",
            minimum=1,
        )
        _bounded_int(
            self.after_snapshot_ticks,
            "after snapshot_ticks",
            minimum=1,
        )
        _bounded_int(self.rss_threshold_kib, "rss threshold", minimum=1)
        _bounded_int(
            self.cpu_threshold_milli_percent,
            "CPU threshold",
            minimum=1,
            maximum=PROCESS_LIFECYCLE_DELTA_MAXIMUM_CPU_MILLI_PERCENT,
        )
        if self.before_snapshot_ticks >= self.after_snapshot_ticks:
            raise ProcessLifecycleDeltaError(
                "snapshot ticks are not strictly increasing"
            )

    def to_value(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "schema_version": 1,
            "before": {
                "boot_id": self.boot_id,
                "snapshot_ticks": self.before_snapshot_ticks,
            },
            "after": {
                "boot_id": self.boot_id,
                "snapshot_ticks": self.after_snapshot_ticks,
            },
            "thresholds": {
                "rss_kib": self.rss_threshold_kib,
                "cpu_milli_percent": self.cpu_threshold_milli_percent,
            },
        }


@dataclass(frozen=True, slots=True)
class ProcessProjection:
    snapshot_pair: SnapshotPair
    comm: str
    cpu_milli_percent: int
    pid: int
    ppid: int
    rss_kib: int
    start_ticks: int
    state: ProcessState
    uid: int
    argv: tuple[str, ...] | None = None
    cgroups: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        if type(self) is not ProcessProjection:
            raise ProcessLifecycleDeltaError(
                "projection has wrong exact type"
            )
        _closed_text(
            self.snapshot_pair,
            PROCESS_LIFECYCLE_DELTA_SNAPSHOT_PAIRS,
            "projection snapshot_pair",
        )
        _validate_comm(self.comm)
        _bounded_int(
            self.cpu_milli_percent,
            "cpu_milli_percent",
            maximum=PROCESS_LIFECYCLE_DELTA_MAXIMUM_CPU_MILLI_PERCENT,
        )
        _bounded_int(
            self.pid,
            "pid",
            minimum=1,
            maximum=PROCESS_LIFECYCLE_DELTA_MAXIMUM_PID,
        )
        _bounded_int(
            self.ppid,
            "ppid",
            maximum=PROCESS_LIFECYCLE_DELTA_MAXIMUM_PID,
        )
        _bounded_int(self.rss_kib, "rss_kib")
        _bounded_int(self.start_ticks, "start_ticks", minimum=1)
        _closed_text(self.state, PROCESS_LIFECYCLE_DELTA_STATES, "state")
        _bounded_int(
            self.uid,
            "uid",
            maximum=PROCESS_LIFECYCLE_DELTA_MAXIMUM_UID,
        )
        needs_argv = self.snapshot_pair in {
            "status-and-cmdline",
            "complete-synthetic-proc",
        }
        needs_cgroups = self.snapshot_pair in {
            "status-and-cgroups",
            "complete-synthetic-proc",
        }
        if needs_argv != (self.argv is not None):
            raise ProcessLifecycleDeltaError(
                "projection argv presence differs from snapshot axis"
            )
        if needs_cgroups != (self.cgroups is not None):
            raise ProcessLifecycleDeltaError(
                "projection cgroups presence differs from snapshot axis"
            )
        if self.argv is not None:
            _validate_argv_tuple(self.argv)
        if self.cgroups is not None:
            _validate_cgroups_tuple(self.cgroups)

    def to_value(self) -> dict[str, object]:
        self.__post_init__()
        value: dict[str, object] = {
            "comm": self.comm,
            "cpu_milli_percent": self.cpu_milli_percent,
            "pid": self.pid,
            "ppid": self.ppid,
            "rss_kib": self.rss_kib,
            "start_ticks": self.start_ticks,
            "state": self.state,
            "uid": self.uid,
        }
        if self.argv is not None:
            value["argv"] = list(self.argv)
        if self.cgroups is not None:
            value["cgroups"] = list(self.cgroups)
        return value


def _validate_argv_tuple(value: object) -> tuple[str, ...]:
    if (
        type(value) is not tuple
        or len(value) > PROCESS_LIFECYCLE_DELTA_MAXIMUM_ARRAY_ITEMS
        or any(type(item) is not str for item in value)
    ):
        raise ProcessLifecycleDeltaError("argv must be an exact bounded tuple")
    total = 0
    for item in value:
        _validate_scalar_text(
            item,
            "argv item",
            minimum_bytes=0,
            maximum_bytes=(
                PROCESS_LIFECYCLE_DELTA_SIDECAR_ITEM_MAXIMUM_UTF8_BYTES
            ),
            forbidden_categories=frozenset(),
            forbidden_characters=frozenset({"\x00"}),
        )
        total += len(item.encode("utf-8"))
    if total > PROCESS_LIFECYCLE_DELTA_SIDECAR_TOTAL_MAXIMUM_UTF8_BYTES:
        raise ProcessLifecycleDeltaError("argv exceeds aggregate byte bound")
    return value


def _validate_cgroups_tuple(value: object) -> tuple[str, ...]:
    if (
        type(value) is not tuple
        or len(value) > PROCESS_LIFECYCLE_DELTA_MAXIMUM_ARRAY_ITEMS
        or any(type(item) is not str for item in value)
    ):
        raise ProcessLifecycleDeltaError(
            "cgroups must be an exact bounded tuple"
        )
    total = 0
    for item in value:
        _validate_scalar_text(
            item,
            "cgroup path",
            minimum_bytes=1,
            maximum_bytes=(
                PROCESS_LIFECYCLE_DELTA_SIDECAR_ITEM_MAXIMUM_UTF8_BYTES
            ),
            forbidden_categories=frozenset({"Cf"}),
            forbidden_characters=frozenset({"\x00", "\r", "\n"}),
        )
        if not item.startswith("/"):
            raise ProcessLifecycleDeltaError(
                "cgroup membership path must be absolute text"
            )
        total += len(item.encode("utf-8"))
    if (
        total > PROCESS_LIFECYCLE_DELTA_SIDECAR_TOTAL_MAXIMUM_UTF8_BYTES
        or len(value) != len(set(value))
        or value
        != tuple(sorted(value, key=lambda item: item.encode("utf-8")))
    ):
        raise ProcessLifecycleDeltaError(
            "cgroups are not a bounded raw-UTF8 ordered set"
        )
    return value


@dataclass(frozen=True, slots=True)
class ThresholdCrossings:
    rss_kib: CrossingDirection | None
    cpu_milli_percent: CrossingDirection | None

    def __post_init__(self) -> None:
        if type(self) is not ThresholdCrossings:
            raise ProcessLifecycleDeltaError(
                "threshold crossings have wrong exact type"
            )
        for value in (self.rss_kib, self.cpu_milli_percent):
            if value is not None and (
                type(value) is not str
                or value not in {"upward", "downward"}
            ):
                raise ProcessLifecycleDeltaError(
                    "threshold crossing direction is invalid"
                )

    def to_value(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "cpu_milli_percent": self.cpu_milli_percent,
            "rss_kib": self.rss_kib,
        }

    @property
    def any(self) -> bool:
        self.__post_init__()
        return self.rss_kib is not None or self.cpu_milli_percent is not None


def _projection_changed_fields(
    before: ProcessProjection,
    after: ProcessProjection,
) -> tuple[str, ...]:
    old = before.to_value()
    new = after.to_value()
    return tuple(
        field_name
        for field_name in _CHANGED_FIELD_ORDER
        if field_name in old and old[field_name] != new[field_name]
    )


def _projection_crossings(
    before: ProcessProjection,
    after: ProcessProjection,
    pair: ProcessPairMetadata,
) -> ThresholdCrossings:
    def direction(old: int, new: int, threshold: int) -> CrossingDirection | None:
        if old < threshold <= new:
            return "upward"
        if new < threshold <= old:
            return "downward"
        return None

    return ThresholdCrossings(
        direction(before.rss_kib, after.rss_kib, pair.rss_threshold_kib),
        direction(
            before.cpu_milli_percent,
            after.cpu_milli_percent,
            pair.cpu_threshold_milli_percent,
        ),
    )


@dataclass(frozen=True, slots=True)
class ProcessLifecycleEvent:
    boot_id: str
    pid: int
    start_ticks: int
    event: Transition
    before: ProcessProjection | None
    after: ProcessProjection | None
    changed_fields: tuple[str, ...]
    threshold_crossings: ThresholdCrossings

    def __post_init__(self) -> None:
        if (
            type(self) is not ProcessLifecycleEvent
            or type(self.boot_id) is not str
            or _BOOT_ID_RE.fullmatch(self.boot_id) is None
            or type(self.threshold_crossings) is not ThresholdCrossings
        ):
            raise ProcessLifecycleDeltaError(
                "event has invalid exact owned types"
            )
        _bounded_int(
            self.pid,
            "event pid",
            minimum=1,
            maximum=PROCESS_LIFECYCLE_DELTA_MAXIMUM_PID,
        )
        _bounded_int(self.start_ticks, "event start_ticks", minimum=1)
        _closed_text(self.event, ("started", "exited", "changed"), "event")
        self.threshold_crossings.__post_init__()
        if (
            self.before is not None
            and type(self.before) is not ProcessProjection
        ) or (
            self.after is not None
            and type(self.after) is not ProcessProjection
        ):
            raise ProcessLifecycleDeltaError(
                "event projection has wrong exact type"
            )
        for projection in (self.before, self.after):
            if projection is not None:
                projection.__post_init__()
                if (
                    projection.pid != self.pid
                    or projection.start_ticks != self.start_ticks
                ):
                    raise ProcessLifecycleDeltaError(
                        "event redundant identity is inconsistent"
                    )
        if (
            type(self.changed_fields) is not tuple
            or any(type(item) is not str for item in self.changed_fields)
        ):
            raise ProcessLifecycleDeltaError(
                "changed_fields has wrong exact type"
            )
        null_crossings = ThresholdCrossings(None, None)
        if self.event == "started":
            if (
                self.before is not None
                or self.after is None
                or self.changed_fields
                or self.threshold_crossings != null_crossings
            ):
                raise ProcessLifecycleDeltaError(
                    "started event fields are inconsistent"
                )
        elif self.event == "exited":
            if (
                self.before is None
                or self.after is not None
                or self.changed_fields
                or self.threshold_crossings != null_crossings
            ):
                raise ProcessLifecycleDeltaError(
                    "exited event fields are inconsistent"
                )
        elif (
            self.before is None
            or self.after is None
            or self.before.snapshot_pair != self.after.snapshot_pair
            or not self.changed_fields
            or self.changed_fields
            != _projection_changed_fields(self.before, self.after)
        ):
            raise ProcessLifecycleDeltaError(
                "changed event does not contain its full projection delta"
            )

    def to_value(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "boot_id": self.boot_id,
            "pid": self.pid,
            "start_ticks": self.start_ticks,
            "event": self.event,
            "before": None if self.before is None else self.before.to_value(),
            "after": None if self.after is None else self.after.to_value(),
            "changed_fields": list(self.changed_fields),
            "threshold_crossings": self.threshold_crossings.to_value(),
        }


def _event_selected(
    event: ProcessLifecycleEvent,
    policy: SelectionPolicy,
) -> bool:
    if policy == "all-changes":
        return True
    if policy == "starts-only":
        return event.event == "started"
    if policy == "exits-only":
        return event.event == "exited"
    if policy == "state-changes":
        return event.event == "changed" and "state" in event.changed_fields
    if policy == "resource-threshold-crossings":
        return event.event == "changed" and event.threshold_crossings.any
    raise ProcessLifecycleDeltaError("selection policy is unsupported")


@dataclass(frozen=True, slots=True)
class ProcessLifecycleDeltaState:
    snapshot_pair: SnapshotPair
    selection_policy: SelectionPolicy
    pair: ProcessPairMetadata
    before_valid_count: int
    after_valid_count: int
    unknown_pids: tuple[int, ...]
    events: tuple[ProcessLifecycleEvent, ...]
    content: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self) is not ProcessLifecycleDeltaState
            or type(self.pair) is not ProcessPairMetadata
        ):
            raise ProcessLifecycleDeltaError(
                "state has wrong exact owned type"
            )
        self.pair.__post_init__()
        _closed_text(
            self.snapshot_pair,
            PROCESS_LIFECYCLE_DELTA_SNAPSHOT_PAIRS,
            "state snapshot_pair",
        )
        _closed_text(
            self.selection_policy,
            PROCESS_LIFECYCLE_DELTA_SELECTION_POLICIES,
            "state selection_policy",
        )
        _bounded_int(
            self.before_valid_count,
            "before valid count",
            maximum=PROCESS_LIFECYCLE_DELTA_MAXIMUM_PROCESSES,
        )
        _bounded_int(
            self.after_valid_count,
            "after valid count",
            maximum=PROCESS_LIFECYCLE_DELTA_MAXIMUM_PROCESSES,
        )
        if (
            type(self.unknown_pids) is not tuple
            or any(type(item) is not int for item in self.unknown_pids)
            or self.unknown_pids != tuple(sorted(set(self.unknown_pids)))
            or len(self.unknown_pids)
            > PROCESS_LIFECYCLE_DELTA_MAXIMUM_UNION_PROCESSES
            or type(self.events) is not tuple
            or any(type(item) is not ProcessLifecycleEvent for item in self.events)
            or len(self.events) > 2 * PROCESS_LIFECYCLE_DELTA_MAXIMUM_PROCESSES
            or type(self.content) is not bytes
            or len(self.content) > PROCESS_LIFECYCLE_DELTA_OUTPUT_MAXIMUM_BYTES
        ):
            raise ProcessLifecycleDeltaError(
                "state collections violate exact bounds"
            )
        for pid in self.unknown_pids:
            _bounded_int(
                pid,
                "unknown pid",
                minimum=1,
                maximum=PROCESS_LIFECYCLE_DELTA_MAXIMUM_PID,
            )
        expected_order = tuple(
            sorted(
                self.events,
                key=lambda item: (
                    item.pid,
                    _TRANSITION_RANK[item.event],
                    item.start_ticks,
                ),
            )
        )
        if expected_order != self.events:
            raise ProcessLifecycleDeltaError(
                "events are not in numeric PID/event/generation order"
            )
        identities: set[tuple[str, int, int, str]] = set()
        for event in self.events:
            event.__post_init__()
            identity = (
                event.boot_id,
                event.pid,
                event.start_ticks,
                event.event,
            )
            if (
                identity in identities
                or event.boot_id != self.pair.boot_id
                or event.pid in self.unknown_pids
                or not _event_selected(event, self.selection_policy)
            ):
                raise ProcessLifecycleDeltaError(
                    "event is duplicate, suppressed, or outside its policy"
                )
            identities.add(identity)
            if (
                event.event == "changed"
                and event.before is not None
                and event.after is not None
                and event.threshold_crossings
                != _projection_crossings(
                    event.before, event.after, self.pair
                )
            ):
                raise ProcessLifecycleDeltaError(
                    "changed event crossings differ from pair thresholds"
                )
            if event.before is not None and (
                event.before.start_ticks > self.pair.before_snapshot_ticks
            ):
                raise ProcessLifecycleDeltaError(
                    "before projection begins after before endpoint"
                )
            if event.after is not None and (
                event.after.start_ticks > self.pair.after_snapshot_ticks
            ):
                raise ProcessLifecycleDeltaError(
                    "after projection begins after after endpoint"
                )
            if event.event == "started" and (
                event.start_ticks <= self.pair.before_snapshot_ticks
                or event.start_ticks > self.pair.after_snapshot_ticks
            ):
                raise ProcessLifecycleDeltaError(
                    "started event is outside the observation interval"
                )
        by_pid: dict[int, list[ProcessLifecycleEvent]] = {}
        for event in self.events:
            by_pid.setdefault(event.pid, []).append(event)
        for rows in by_pid.values():
            if len(rows) > 2 or (
                len(rows) == 2
                and tuple(item.event for item in rows)
                != ("exited", "started")
            ):
                raise ProcessLifecycleDeltaError(
                    "one PID has an impossible selected event combination"
                )
        if self.content != b"".join(
            _canonical_json(event.to_value()) for event in self.events
        ):
            raise ProcessLifecycleDeltaError(
                "state content is not canonical ordered JSONL"
            )

    @property
    def commitment_sha256(self) -> str:
        self.__post_init__()
        return domain_sha256(
            "cbds.process-lifecycle-delta.state.v1",
            self.commitment_record(include_digest=False),
        )

    def commitment_record(
        self,
        *,
        include_digest: bool = True,
    ) -> dict[str, object]:
        self.__post_init__() if include_digest else None
        record: dict[str, object] = {
            "snapshot_pair": self.snapshot_pair,
            "selection_policy": self.selection_policy,
            "pair": self.pair.to_value(),
            "before_valid_count": self.before_valid_count,
            "after_valid_count": self.after_valid_count,
            "unknown_pids": list(self.unknown_pids),
            "events": [event.to_value() for event in self.events],
            "content_sha256": sha256(self.content).hexdigest(),
            "content_bytes": len(self.content),
        }
        if include_digest:
            record["state_sha256"] = domain_sha256(
                "cbds.process-lifecycle-delta.state.v1", record
            )
        return record


def _task_contract(
    parameters: ProcessLifecycleDeltaParameters,
) -> tuple[str, NormalizedSemanticGraph]:
    prompt = f"""Write one Bash program that operates only in the current workspace.

Compare the immutable synthetic snapshots below
`input/process-lifecycle/before/` and
`input/process-lifecycle/after/` using metadata from
`input/process-lifecycle/pair.json`.  Do not inspect live `/proc`, `/sys`,
cgroups, clocks, or host processes, and do not start, signal, wait for, poll,
or otherwise act on a process.

Use snapshot projection `{parameters.snapshot_pair}` and selection policy
`{parameters.selection_policy}`.  The authenticated family domain contains
no hardlinks.  Treat a source tree containing any authenticated hardlink as
out of domain.  Every consulted document must be a no-follow independent
regular file whose owner-read bit 0400 is set; a symlink or unreadable file
is not consulted.

Every consulted JSON document is at most 4096 bytes and is canonical JSON:
strict
UTF-8 with no BOM or NUL, lexicographically sorted object keys, compact `,`
and `:` separators, direct non-ASCII UTF-8 with mandatory JSON string
escapes, and exactly one trailing LF with no other surrounding whitespace.
Reject duplicate keys, floats, exponents, negative or nonfinite numbers.
Integers use `0` or `[1-9][0-9]{{0,15}}` and are at most
9007199254740991.  JSON is limited to depth 8 and 4096 total nodes, with
32 members per object and 32 items per array.  The authenticated input files
together are at most 8388608 bytes.

Discover only direct canonical PID names `[1-9][0-9]*` in 1..4194304,
numerically, with at most 64 names per endpoint and
128 in the endpoint union.  Ignore noncanonical names such as zero,
leading-zero, signed,
whitespace-padded, or over-bound forms.  A canonical PID is absent, unknown,
or valid.  Missing, wrong-kind, symlinked, owner-unreadable, malformed, or
inconsistent required records make that PID unknown.  Unknown on either
endpoint suppresses the PID; it never means absence or an empty sidecar.

`pair.json` has exactly `schema_version`, `before`, `after`, and `thresholds`;
schema_version is integer 1.  Each endpoint has exactly `boot_id` and
`snapshot_ticks`.  Boot IDs are the same lowercase canonical UUID.
Snapshot ticks are in 1..9007199254740991 and before is strictly less than
after.  Thresholds have exactly `rss_kib` in 1..9007199254740991 and
`cpu_milli_percent` in 1..100000.

Every valid `status.json` has exactly `comm`, `cpu_milli_percent`, `pid`,
`ppid`, `rss_kib`, `start_ticks`, `state`, and `uid`.  PID is in
1..4194304 and equals the directory name; ppid is in 0..4194304; uid is in
0..4294967295; rss_kib is in 0..9007199254740991; cpu_milli_percent is in
0..100000; start_ticks is in 1..9007199254740991 and no later than that
endpoint tick; state is exactly one of `R,S,D,Z,T,I`.  Comm is scalar Unicode
of 1..64 UTF-8 bytes and contains no Unicode Cc or Cf character.

`status-and-cmdline` additionally requires `cmdline.json` and exposes
`argv`; `status-and-cgroups` requires `cgroups.json` and exposes `cgroups`;
`complete-synthetic-proc` requires both; `status-only` consults neither.
Argv has at most 32 scalar-Unicode strings, each 0..128 UTF-8 bytes and at
most 512 bytes in aggregate.  NUL is forbidden; order, duplicates, controls,
and empty strings are semantic.  Cgroups has at most 32 unique absolute
strings, each 1..128 UTF-8 bytes and at most 512 bytes in aggregate, in
strict raw-UTF-8 byte order.  Cgroup paths forbid NUL, CR, LF, and Unicode
Cf but otherwise preserve text exactly.  A malformed required sidecar makes
the PID unknown; an unrequired sidecar is ignored.

Identity is `(boot_id,pid,start_ticks)`.  After-only observations and new PID
generations start only when
`before.snapshot_ticks < start_ticks <= after.snapshot_ticks`; otherwise
suppress the PID.  A valid before-only instance exits.  PID reuse emits the
old exit then the new start.  Same-instance mutable fields use fixed order
`ppid,uid,state,rss_kib,cpu_milli_percent,comm,argv,cgroups`.
Threshold crossing is upward for before<T and after>=T, downward for
before>=T and after<T, otherwise null.  CPU is a point observation, not a
cumulative counter.

After deriving complete aggregate rows, apply `{parameters.selection_policy}`:
all rows; started only; exited only; changed rows containing state; or changed
rows crossing RSS or CPU.  Selected rows still expose the complete projection,
all changed fields, and both crossing results.

Create only real mode-0755 `output/` and independent, one-link mode-0644
`output/transitions.jsonl`, at most 1048576 bytes.  Each nonblank physical
line is one strict UTF-8 JSON object with exactly `boot_id`, `pid`,
`start_ticks`, `event`, `before`, `after`, `changed_fields`, and
`threshold_crossings`; output object key order and whitespace need not be
canonical, but duplicate keys, CR, floats, negative numbers, and invalid
UTF-8 are forbidden.  The crossing object has exactly `rss_kib` and
`cpu_milli_percent`, each null, `upward`, or `downward`.

A started row has null before, one full after projection, no changed fields,
and null crossings.  An exited row is the converse.  A changed row has both
full same-identity projections, every and only changed mutable field in the
fixed order, and both exact crossing results.  Redundant row
boot_id/pid/start_ticks must equal its projection identity.  Sort rows by
numeric PID, event rank exited/started/changed, then numeric start_ticks; one
PID has at most an exited-then-started pair.  Empty results are a zero-byte
file; nonempty output has no blank lines and ends in exactly one LF.  Preserve
all inputs.

The final-state verifier cannot prove process or read history, tool use,
candidate exit status, atomicity, transient state, or global quiescence.
Use only Bash built-ins plus `awk`, `comm`, `jq`, `mkdir`, and `sort`.
"""
    graph = NormalizedSemanticGraph(
        nodes=(
            OperatorNode(
                "parse_pair_metadata",
                ("path:input/process-lifecycle/pair.json",),
            ),
            OperatorNode(
                "classify_snapshot_observations",
                (
                    f"projection:{parameters.snapshot_pair}",
                    "states:absent-unknown-valid",
                    "no-follow",
                ),
            ),
            OperatorNode(
                "join_process_instances",
                ("identity:boot-pid-start", "pid-reuse:exit-then-start"),
            ),
            OperatorNode(
                "derive_aggregate_deltas",
                (
                    "full-changed-fields",
                    "rss-cpu-threshold-crossings",
                ),
            ),
            OperatorNode(
                "filter_selection_policy",
                (f"policy:{parameters.selection_policy}",),
            ),
            OperatorNode(
                "emit_transition_jsonl",
                (
                    "path:output/transitions.jsonl",
                    "order:numeric-pid-event-generation",
                ),
            ),
        ),
        dependencies=((0, 1), (1, 2), (2, 3), (3, 4), (4, 5)),
    )
    return prompt, graph


def _validate_graph(graph: object) -> NormalizedSemanticGraph:
    if type(graph) is not NormalizedSemanticGraph:
        raise ProcessLifecycleDeltaError("graph has wrong exact type")
    if (
        type(graph.nodes) is not tuple
        or not graph.nodes
        or any(type(node) is not OperatorNode for node in graph.nodes)
        or type(graph.dependencies) is not tuple
    ):
        raise ProcessLifecycleDeltaError(
            "graph collections have wrong exact types"
        )
    for node in graph.nodes:
        if (
            type(node.name) is not str
            or type(node.parameters) is not tuple
            or any(type(item) is not str for item in node.parameters)
        ):
            raise ProcessLifecycleDeltaError(
                "graph operator has noncanonical scalar types"
            )
    if any(
        type(edge) is not tuple
        or len(edge) != 2
        or any(type(index) is not int for index in edge)
        for edge in graph.dependencies
    ):
        raise ProcessLifecycleDeltaError(
            "graph dependencies have wrong exact types"
        )
    rebuilt = NormalizedSemanticGraph(
        tuple(OperatorNode(node.name, node.parameters) for node in graph.nodes),
        graph.dependencies,
    )
    if rebuilt != graph:
        raise ProcessLifecycleDeltaError("graph is noncanonical")
    return graph


def process_lifecycle_delta_task_semantic_core(
    parameters: ProcessLifecycleDeltaParameters,
    prompt: str,
    graph: NormalizedSemanticGraph,
) -> dict[str, object]:
    if type(parameters) is not ProcessLifecycleDeltaParameters:
        raise ProcessLifecycleDeltaError("parameters have wrong exact type")
    parameters.__post_init__()
    expected_prompt, expected_graph = _task_contract(parameters)
    if (
        type(prompt) is not str
        or prompt != expected_prompt
        or _validate_graph(graph) != expected_graph
    ):
        raise ProcessLifecycleDeltaError("task prompt or graph differs")
    return {
        "schema_version": EXECUTABLE_STATIC_SCHEMA_VERSION,
        "contract_version": EXECUTABLE_STATIC_CONTRACT_VERSION,
        "split_role": METHOD_DEVELOPMENT_SPLIT,
        "family_id": PROCESS_LIFECYCLE_DELTA_FAMILY_ID,
        "family_version": EXECUTABLE_STATIC_FAMILY_VERSION,
        "generator_version": PROCESS_LIFECYCLE_DELTA_GENERATOR_VERSION,
        "parameters": parameters.to_record(),
        "prompt": prompt,
        "graph": graph.to_record(),
        "graph_sha256": graph.hash,
        "filesystem_identity": PROCESS_LIFECYCLE_DELTA_FILESYSTEM_IDENTITY,
        "output_identity": PROCESS_LIFECYCLE_DELTA_OUTPUT_IDENTITY,
        "allowed_tools": list(PROCESS_LIFECYCLE_DELTA_ALLOWED_TOOLS),
        "public": True,
        "sealed": False,
        "candidate_execution_authorized": False,
        "model_selection_eligible": False,
        "claim_authorized": False,
    }


def compute_process_lifecycle_delta_task_sha256(
    parameters: ProcessLifecycleDeltaParameters,
    prompt: str,
    graph: NormalizedSemanticGraph,
) -> str:
    return domain_sha256(
        "cbds.executable-static.task-contract.v1",
        process_lifecycle_delta_task_semantic_core(
            parameters, prompt, graph
        ),
    )


@dataclass(frozen=True, slots=True)
class ProcessLifecycleDeltaTask:
    task_id: str
    parameters: ProcessLifecycleDeltaParameters
    prompt: str
    graph: NormalizedSemanticGraph
    fixtures: tuple[OpaqueFixtureDescriptor, ...]
    task_contract_sha256: str
    family_id: str = PROCESS_LIFECYCLE_DELTA_FAMILY_ID
    family_version: str = EXECUTABLE_STATIC_FAMILY_VERSION
    filesystem_identity: str = PROCESS_LIFECYCLE_DELTA_FILESYSTEM_IDENTITY
    output_identity: str = PROCESS_LIFECYCLE_DELTA_OUTPUT_IDENTITY
    allowed_tools: tuple[str, ...] = PROCESS_LIFECYCLE_DELTA_ALLOWED_TOOLS
    split_role: str = METHOD_DEVELOPMENT_SPLIT
    public: bool = True
    sealed: bool = False
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        if (
            type(self) is not ProcessLifecycleDeltaTask
            or type(self.parameters) is not ProcessLifecycleDeltaParameters
            or type(self.family_id) is not str
            or self.family_id != PROCESS_LIFECYCLE_DELTA_FAMILY_ID
            or type(self.family_version) is not str
            or self.family_version != EXECUTABLE_STATIC_FAMILY_VERSION
            or type(self.filesystem_identity) is not str
            or self.filesystem_identity
            != PROCESS_LIFECYCLE_DELTA_FILESYSTEM_IDENTITY
            or type(self.output_identity) is not str
            or self.output_identity != PROCESS_LIFECYCLE_DELTA_OUTPUT_IDENTITY
            or type(self.allowed_tools) is not tuple
            or any(type(item) is not str for item in self.allowed_tools)
            or self.allowed_tools != PROCESS_LIFECYCLE_DELTA_ALLOWED_TOOLS
            or type(self.split_role) is not str
            or self.split_role != METHOD_DEVELOPMENT_SPLIT
            or self.public is not True
            or self.sealed is not False
            or self.candidate_execution_authorized is not False
            or self.model_selection_eligible is not False
            or self.claim_authorized is not False
        ):
            raise ProcessLifecycleDeltaError("task metadata is invalid")
        expected = compute_process_lifecycle_delta_task_sha256(
            self.parameters, self.prompt, self.graph
        )
        if (
            type(self.task_id) is not str
            or _TASK_ID_RE.fullmatch(self.task_id) is None
            or not _is_sha256(self.task_contract_sha256)
            or self.task_contract_sha256 != expected
            or self.task_id != task_id_from_contract(expected)
            or type(self.fixtures) is not tuple
            or len(self.fixtures) != len(PUBLIC_DEVELOPMENT_FIXTURE_PROFILES)
            or any(
                type(item) is not OpaqueFixtureDescriptor
                for item in self.fixtures
            )
        ):
            raise ProcessLifecycleDeltaError("task identity is invalid")
        for descriptor in self.fixtures:
            descriptor.__post_init__()
        if (
            len({item.fixture_id for item in self.fixtures})
            != len(self.fixtures)
            or any(
                item.task_contract_sha256 != expected
                for item in self.fixtures
            )
        ):
            raise ProcessLifecycleDeltaError(
                "task fixture descriptor binding is invalid"
            )

    @property
    def graph_sha256(self) -> str:
        self.__post_init__()
        return self.graph.hash

    def to_public_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            **process_lifecycle_delta_task_semantic_core(
                self.parameters, self.prompt, self.graph
            ),
            "task_id": self.task_id,
            "task_contract_sha256": self.task_contract_sha256,
            "fixtures": [
                descriptor.to_public_record()
                for descriptor in self.fixtures
            ],
        }


def _bootstrap_descriptors(
    task_contract_sha256: str,
) -> tuple[OpaqueFixtureDescriptor, ...]:
    return tuple(
        OpaqueFixtureDescriptor(
            f"fx-{digest[:24]}",
            digest,
            task_contract_sha256,
        )
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        for digest in (
            domain_sha256(
                "cbds.executable-static.fixture.v1",
                {
                    "task_contract_sha256": task_contract_sha256,
                    "profile_sha256": profile.profile_sha256,
                },
            ),
        )
    )


def _bootstrap_task(
    parameters: ProcessLifecycleDeltaParameters,
) -> ProcessLifecycleDeltaTask:
    prompt, graph = _task_contract(parameters)
    digest = compute_process_lifecycle_delta_task_sha256(
        parameters, prompt, graph
    )
    return ProcessLifecycleDeltaTask(
        task_id_from_contract(digest),
        parameters,
        prompt,
        graph,
        _bootstrap_descriptors(digest),
        digest,
    )


def _parse_pair_payload(payload: bytes) -> ProcessPairMetadata:
    value = _require_exact_keys(
        _decode_canonical_json(
            payload, PROCESS_LIFECYCLE_DELTA_PAIR_MAXIMUM_BYTES
        ),
        _PAIR_KEYS,
        "pair metadata",
    )
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ProcessLifecycleDeltaError(
            "pair schema_version must be exact integer one"
        )
    before = _require_exact_keys(
        value["before"], _ENDPOINT_KEYS, "before endpoint"
    )
    after = _require_exact_keys(
        value["after"], _ENDPOINT_KEYS, "after endpoint"
    )
    thresholds = _require_exact_keys(
        value["thresholds"], _THRESHOLD_KEYS, "thresholds"
    )
    before_boot = before["boot_id"]
    after_boot = after["boot_id"]
    if (
        type(before_boot) is not str
        or type(after_boot) is not str
        or _BOOT_ID_RE.fullmatch(before_boot) is None
        or before_boot != after_boot
    ):
        raise ProcessLifecycleDeltaError(
            "pair boot IDs must be equal lowercase canonical UUIDs"
        )
    return ProcessPairMetadata(
        before_boot,
        _bounded_int(
            before["snapshot_ticks"],
            "before snapshot_ticks",
            minimum=1,
        ),
        _bounded_int(
            after["snapshot_ticks"],
            "after snapshot_ticks",
            minimum=1,
        ),
        _bounded_int(thresholds["rss_kib"], "rss threshold", minimum=1),
        _bounded_int(
            thresholds["cpu_milli_percent"],
            "CPU threshold",
            minimum=1,
            maximum=PROCESS_LIFECYCLE_DELTA_MAXIMUM_CPU_MILLI_PERCENT,
        ),
    )


def _parse_status_payload(
    payload: bytes,
    *,
    expected_pid: int,
    endpoint_ticks: int,
) -> dict[str, object]:
    value = _require_exact_keys(
        _decode_canonical_json(
            payload, PROCESS_LIFECYCLE_DELTA_STATUS_MAXIMUM_BYTES
        ),
        _STATUS_KEYS,
        "status record",
    )
    pid = _bounded_int(
        value["pid"],
        "status pid",
        minimum=1,
        maximum=PROCESS_LIFECYCLE_DELTA_MAXIMUM_PID,
    )
    if pid != expected_pid:
        raise ProcessLifecycleDeltaError(
            "status pid differs from canonical directory"
        )
    start_ticks = _bounded_int(
        value["start_ticks"], "start_ticks", minimum=1
    )
    if start_ticks > endpoint_ticks:
        raise ProcessLifecycleDeltaError(
            "status start_ticks is after endpoint snapshot"
        )
    return {
        "comm": _validate_comm(value["comm"]),
        "cpu_milli_percent": _bounded_int(
            value["cpu_milli_percent"],
            "cpu_milli_percent",
            maximum=PROCESS_LIFECYCLE_DELTA_MAXIMUM_CPU_MILLI_PERCENT,
        ),
        "pid": pid,
        "ppid": _bounded_int(
            value["ppid"],
            "ppid",
            maximum=PROCESS_LIFECYCLE_DELTA_MAXIMUM_PID,
        ),
        "rss_kib": _bounded_int(value["rss_kib"], "rss_kib"),
        "start_ticks": start_ticks,
        "state": _closed_text(
            value["state"], PROCESS_LIFECYCLE_DELTA_STATES, "state"
        ),
        "uid": _bounded_int(
            value["uid"],
            "uid",
            maximum=PROCESS_LIFECYCLE_DELTA_MAXIMUM_UID,
        ),
    }


def _parse_argv_payload(payload: bytes) -> tuple[str, ...]:
    value = _decode_canonical_json(
        payload, PROCESS_LIFECYCLE_DELTA_SIDECAR_MAXIMUM_BYTES
    )
    if type(value) is not list:
        raise ProcessLifecycleDeltaError("cmdline sidecar must be an array")
    result = tuple(value)
    return _validate_argv_tuple(result)


def _parse_cgroups_payload(payload: bytes) -> tuple[str, ...]:
    value = _decode_canonical_json(
        payload, PROCESS_LIFECYCLE_DELTA_SIDECAR_MAXIMUM_BYTES
    )
    if type(value) is not list:
        raise ProcessLifecycleDeltaError("cgroups sidecar must be an array")
    result = tuple(value)
    return _validate_cgroups_tuple(result)


def _canonical_pid(value: str) -> int | None:
    if type(value) is not str or _PID_RE.fullmatch(value) is None:
        return None
    # Length is checked before integer conversion, avoiding attacker-sized
    # decimal conversion and any shell-style octal ambiguity.
    if len(value) > len(str(PROCESS_LIFECYCLE_DELTA_MAXIMUM_PID)):
        return None
    parsed = int(value, 10)
    if not 1 <= parsed <= PROCESS_LIFECYCLE_DELTA_MAXIMUM_PID:
        return None
    return parsed


def _definition_index(
    definition: FixtureDefinition,
) -> dict[str, InputFile | InputHardlink | InputSymlink]:
    return {item.path: item for item in definition.inputs}


def _consulted_file(
    definition: FixtureDefinition,
    index: dict[str, InputFile | InputHardlink | InputSymlink],
    path: str,
) -> InputFile:
    item = index.get(path)
    if type(item) is not InputFile or item.mode & 0o400 == 0:
        raise ProcessLifecycleDeltaError(
            "consulted source is not an owner-readable independent file"
        )
    if any(
        type(candidate) is InputHardlink and candidate.target == path
        for candidate in definition.inputs
    ):
        raise ProcessLifecycleDeltaError(
            "consulted source has an authenticated hardlink alias"
        )
    return item


def _discover_endpoint_pids(
    definition: FixtureDefinition,
    side: Literal["before", "after"],
) -> tuple[int, ...]:
    prefix = ("input", "process-lifecycle", side)
    pids: set[int] = set()
    for item in definition.inputs:
        parts = PurePosixPath(item.path).parts
        if len(parts) < 4 or parts[:3] != prefix:
            continue
        pid = _canonical_pid(parts[3])
        if pid is not None:
            pids.add(pid)
    if len(pids) > PROCESS_LIFECYCLE_DELTA_MAXIMUM_PROCESSES:
        raise ProcessLifecycleDeltaError(
            "endpoint exceeds canonical PID basename bound"
        )
    return tuple(sorted(pids))


def _classify_pid_observation(
    definition: FixtureDefinition,
    index: dict[str, InputFile | InputHardlink | InputSymlink],
    parameters: ProcessLifecycleDeltaParameters,
    pair: ProcessPairMetadata,
    side: Literal["before", "after"],
    pid: int,
) -> ProcessProjection:
    root = f"{PROCESS_LIFECYCLE_DELTA_SOURCE_ROOT}/{side}/{pid}"
    if root in index:
        raise ProcessLifecycleDeltaError(
            "canonical PID basename is not a real directory"
        )
    status_file = _consulted_file(definition, index, f"{root}/status.json")
    endpoint_ticks = (
        pair.before_snapshot_ticks
        if side == "before"
        else pair.after_snapshot_ticks
    )
    status = _parse_status_payload(
        status_file.content,
        expected_pid=pid,
        endpoint_ticks=endpoint_ticks,
    )
    argv: tuple[str, ...] | None = None
    cgroups: tuple[str, ...] | None = None
    if parameters.snapshot_pair in {
        "status-and-cmdline",
        "complete-synthetic-proc",
    }:
        argv_file = _consulted_file(
            definition, index, f"{root}/cmdline.json"
        )
        argv = _parse_argv_payload(argv_file.content)
    if parameters.snapshot_pair in {
        "status-and-cgroups",
        "complete-synthetic-proc",
    }:
        cgroups_file = _consulted_file(
            definition, index, f"{root}/cgroups.json"
        )
        cgroups = _parse_cgroups_payload(cgroups_file.content)
    return ProcessProjection(
        parameters.snapshot_pair,
        status["comm"],  # type: ignore[arg-type]
        status["cpu_milli_percent"],  # type: ignore[arg-type]
        status["pid"],  # type: ignore[arg-type]
        status["ppid"],  # type: ignore[arg-type]
        status["rss_kib"],  # type: ignore[arg-type]
        status["start_ticks"],  # type: ignore[arg-type]
        status["state"],  # type: ignore[arg-type]
        status["uid"],  # type: ignore[arg-type]
        argv,
        cgroups,
    )


@dataclass(frozen=True, slots=True)
class _EndpointClassification:
    present_pids: tuple[int, ...]
    valid: tuple[ProcessProjection, ...]
    unknown_pids: tuple[int, ...]

    def __post_init__(self) -> None:
        if (
            type(self) is not _EndpointClassification
            or type(self.present_pids) is not tuple
            or type(self.valid) is not tuple
            or type(self.unknown_pids) is not tuple
            or any(type(item) is not int for item in self.present_pids)
            or any(type(item) is not ProcessProjection for item in self.valid)
            or any(type(item) is not int for item in self.unknown_pids)
        ):
            raise ProcessLifecycleDeltaError(
                "endpoint classification has wrong exact types"
            )
        if (
            self.present_pids != tuple(sorted(set(self.present_pids)))
            or self.unknown_pids != tuple(sorted(set(self.unknown_pids)))
            or tuple(item.pid for item in self.valid)
            != tuple(sorted({item.pid for item in self.valid}))
            or set(self.unknown_pids) & {item.pid for item in self.valid}
            or set(self.present_pids)
            != set(self.unknown_pids) | {item.pid for item in self.valid}
        ):
            raise ProcessLifecycleDeltaError(
                "endpoint classification is not a canonical partition"
            )


def _classify_endpoint_primary(
    definition: FixtureDefinition,
    parameters: ProcessLifecycleDeltaParameters,
    pair: ProcessPairMetadata,
    side: Literal["before", "after"],
) -> _EndpointClassification:
    index = _definition_index(definition)
    pids = _discover_endpoint_pids(definition, side)
    valid: list[ProcessProjection] = []
    unknown: list[int] = []
    for pid in pids:
        try:
            valid.append(
                _classify_pid_observation(
                    definition, index, parameters, pair, side, pid
                )
            )
        except ProcessLifecycleDeltaError:
            unknown.append(pid)
    return _EndpointClassification(pids, tuple(valid), tuple(unknown))


def _reference_exact_object(
    value: object,
    keys: frozenset[str],
    field_name: str,
) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise ProcessLifecycleDeltaError(
            f"reference {field_name} is not an exact closed object"
        )
    return value


def _reference_integer(
    value: object,
    field_name: str,
    *,
    minimum: int = 0,
    maximum: int = PROCESS_LIFECYCLE_DELTA_MAXIMUM_INTEGER,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ProcessLifecycleDeltaError(
            f"reference {field_name} is not an exact bounded integer"
        )
    return value


def _reference_parse_pair_payload(payload: bytes) -> ProcessPairMetadata:
    root = _reference_exact_object(
        _decode_canonical_json(
            payload, PROCESS_LIFECYCLE_DELTA_PAIR_MAXIMUM_BYTES
        ),
        _PAIR_KEYS,
        "pair metadata",
    )
    if type(root["schema_version"]) is not int or root["schema_version"] != 1:
        raise ProcessLifecycleDeltaError(
            "reference pair schema_version is not integer one"
        )
    before = _reference_exact_object(
        root["before"], _ENDPOINT_KEYS, "before endpoint"
    )
    after = _reference_exact_object(
        root["after"], _ENDPOINT_KEYS, "after endpoint"
    )
    thresholds = _reference_exact_object(
        root["thresholds"], _THRESHOLD_KEYS, "thresholds"
    )
    before_boot = before["boot_id"]
    after_boot = after["boot_id"]
    if (
        type(before_boot) is not str
        or type(after_boot) is not str
        or re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{4}-[0-9a-f]{12}",
            before_boot,
        )
        is None
        or before_boot != after_boot
    ):
        raise ProcessLifecycleDeltaError(
            "reference pair boot IDs are not equal canonical UUIDs"
        )
    return ProcessPairMetadata(
        before_boot,
        _reference_integer(
            before["snapshot_ticks"],
            "before snapshot_ticks",
            minimum=1,
        ),
        _reference_integer(
            after["snapshot_ticks"],
            "after snapshot_ticks",
            minimum=1,
        ),
        _reference_integer(
            thresholds["rss_kib"],
            "RSS threshold",
            minimum=1,
        ),
        _reference_integer(
            thresholds["cpu_milli_percent"],
            "CPU threshold",
            minimum=1,
            maximum=PROCESS_LIFECYCLE_DELTA_MAXIMUM_CPU_MILLI_PERCENT,
        ),
    )


def _reference_parse_status_payload(
    payload: bytes,
    *,
    expected_pid: int,
    endpoint_ticks: int,
) -> dict[str, object]:
    root = _reference_exact_object(
        _decode_canonical_json(
            payload, PROCESS_LIFECYCLE_DELTA_STATUS_MAXIMUM_BYTES
        ),
        _STATUS_KEYS,
        "status record",
    )
    pid = _reference_integer(
        root["pid"],
        "status pid",
        minimum=1,
        maximum=PROCESS_LIFECYCLE_DELTA_MAXIMUM_PID,
    )
    start_ticks = _reference_integer(
        root["start_ticks"],
        "start_ticks",
        minimum=1,
    )
    comm = root["comm"]
    if type(comm) is not str or any(
        unicodedata.category(character) in {"Cc", "Cf"}
        for character in comm
    ):
        raise ProcessLifecycleDeltaError(
            "reference comm is not permitted scalar text"
        )
    try:
        comm_bytes = comm.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ProcessLifecycleDeltaError(
            "reference comm is not scalar Unicode"
        ) from exc
    if not 1 <= len(comm_bytes) <= PROCESS_LIFECYCLE_DELTA_COMM_MAXIMUM_UTF8_BYTES:
        raise ProcessLifecycleDeltaError(
            "reference comm exceeds its byte bound"
        )
    state = root["state"]
    if type(state) is not str or state not in PROCESS_LIFECYCLE_DELTA_STATES:
        raise ProcessLifecycleDeltaError(
            "reference process state is outside its closed set"
        )
    if pid != expected_pid or start_ticks > endpoint_ticks:
        raise ProcessLifecycleDeltaError(
            "reference status identity or time is inconsistent"
        )
    return {
        "comm": comm,
        "cpu_milli_percent": _reference_integer(
            root["cpu_milli_percent"],
            "cpu_milli_percent",
            maximum=PROCESS_LIFECYCLE_DELTA_MAXIMUM_CPU_MILLI_PERCENT,
        ),
        "pid": pid,
        "ppid": _reference_integer(
            root["ppid"],
            "ppid",
            maximum=PROCESS_LIFECYCLE_DELTA_MAXIMUM_PID,
        ),
        "rss_kib": _reference_integer(root["rss_kib"], "rss_kib"),
        "start_ticks": start_ticks,
        "state": state,
        "uid": _reference_integer(
            root["uid"],
            "uid",
            maximum=PROCESS_LIFECYCLE_DELTA_MAXIMUM_UID,
        ),
    }


def _reference_parse_argv_payload(payload: bytes) -> tuple[str, ...]:
    value = _decode_canonical_json(
        payload, PROCESS_LIFECYCLE_DELTA_SIDECAR_MAXIMUM_BYTES
    )
    if (
        type(value) is not list
        or len(value) > PROCESS_LIFECYCLE_DELTA_MAXIMUM_ARRAY_ITEMS
    ):
        raise ProcessLifecycleDeltaError(
            "reference argv is not a bounded array"
        )
    result: list[str] = []
    total = 0
    for item in value:
        if type(item) is not str or "\x00" in item:
            raise ProcessLifecycleDeltaError(
                "reference argv item is not permitted text"
            )
        try:
            encoded = item.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise ProcessLifecycleDeltaError(
                "reference argv item is not scalar Unicode"
            ) from exc
        if len(encoded) > PROCESS_LIFECYCLE_DELTA_SIDECAR_ITEM_MAXIMUM_UTF8_BYTES:
            raise ProcessLifecycleDeltaError(
                "reference argv item exceeds its byte bound"
            )
        total += len(encoded)
        result.append(item)
    if total > PROCESS_LIFECYCLE_DELTA_SIDECAR_TOTAL_MAXIMUM_UTF8_BYTES:
        raise ProcessLifecycleDeltaError(
            "reference argv exceeds its aggregate byte bound"
        )
    return tuple(result)


def _reference_parse_cgroups_payload(payload: bytes) -> tuple[str, ...]:
    value = _decode_canonical_json(
        payload, PROCESS_LIFECYCLE_DELTA_SIDECAR_MAXIMUM_BYTES
    )
    if (
        type(value) is not list
        or len(value) > PROCESS_LIFECYCLE_DELTA_MAXIMUM_ARRAY_ITEMS
    ):
        raise ProcessLifecycleDeltaError(
            "reference cgroups is not a bounded array"
        )
    result: list[str] = []
    total = 0
    for item in value:
        if (
            type(item) is not str
            or not item.startswith("/")
            or any(
                character in {"\x00", "\r", "\n"}
                or unicodedata.category(character) == "Cf"
                for character in item
            )
        ):
            raise ProcessLifecycleDeltaError(
                "reference cgroup path is not permitted absolute text"
            )
        try:
            encoded = item.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise ProcessLifecycleDeltaError(
                "reference cgroup path is not scalar Unicode"
            ) from exc
        if not (
            1
            <= len(encoded)
            <= PROCESS_LIFECYCLE_DELTA_SIDECAR_ITEM_MAXIMUM_UTF8_BYTES
        ):
            raise ProcessLifecycleDeltaError(
                "reference cgroup path exceeds its byte bound"
            )
        total += len(encoded)
        result.append(item)
    selected = tuple(result)
    if (
        total > PROCESS_LIFECYCLE_DELTA_SIDECAR_TOTAL_MAXIMUM_UTF8_BYTES
        or len(selected) != len(set(selected))
        or selected
        != tuple(sorted(selected, key=lambda item: item.encode("utf-8")))
    ):
        raise ProcessLifecycleDeltaError(
            "reference cgroups is not a unique raw-UTF8 ordered set"
        )
    return selected


def _reference_canonical_pid(value: object) -> int | None:
    if (
        type(value) is not str
        or len(value) > len(str(PROCESS_LIFECYCLE_DELTA_MAXIMUM_PID))
        or re.fullmatch(r"[1-9][0-9]*", value) is None
    ):
        return None
    parsed = int(value, 10)
    return (
        parsed
        if 1 <= parsed <= PROCESS_LIFECYCLE_DELTA_MAXIMUM_PID
        else None
    )


def _reference_discover_endpoint_pids(
    definition: FixtureDefinition,
    side: Literal["before", "after"],
) -> tuple[int, ...]:
    prefix = ("input", "process-lifecycle", side)
    numeric_names: set[int] = set()
    for entry in tuple(reversed(definition.inputs)):
        pieces = entry.path.split("/")
        if len(pieces) < 4 or tuple(pieces[:3]) != prefix:
            continue
        parsed = _reference_canonical_pid(pieces[3])
        if parsed is not None:
            numeric_names.add(parsed)
    if len(numeric_names) > PROCESS_LIFECYCLE_DELTA_MAXIMUM_PROCESSES:
        raise ProcessLifecycleDeltaError(
            "reference endpoint exceeds PID basename bound"
        )
    return tuple(sorted(numeric_names))


def _classify_endpoint_reference(
    definition: FixtureDefinition,
    parameters: ProcessLifecycleDeltaParameters,
    pair: ProcessPairMetadata,
    side: Literal["before", "after"],
) -> _EndpointClassification:
    # Independent rescan: do not call the primary discovery or classifier.
    numeric_names = _reference_discover_endpoint_pids(definition, side)
    by_path = {entry.path: entry for entry in definition.inputs}
    valid: list[ProcessProjection] = []
    unknown: list[int] = []
    for pid in numeric_names:
        base = f"{PROCESS_LIFECYCLE_DELTA_SOURCE_ROOT}/{side}/{pid}"
        try:
            if base in by_path:
                raise ProcessLifecycleDeltaError(
                    "reference PID entry has wrong kind"
                )
            status_entry = by_path.get(f"{base}/status.json")
            if (
                type(status_entry) is not InputFile
                or status_entry.mode & 0o400 == 0
                or any(
                    type(alias) is InputHardlink
                    and alias.target == status_entry.path
                    for alias in definition.inputs
                )
            ):
                raise ProcessLifecycleDeltaError(
                    "reference status is unavailable"
                )
            endpoint_ticks = (
                pair.before_snapshot_ticks
                if side == "before"
                else pair.after_snapshot_ticks
            )
            raw = _reference_parse_status_payload(
                status_entry.content,
                expected_pid=pid,
                endpoint_ticks=endpoint_ticks,
            )
            argv: tuple[str, ...] | None = None
            cgroups: tuple[str, ...] | None = None
            if parameters.snapshot_pair in {
                "status-and-cmdline",
                "complete-synthetic-proc",
            }:
                argv_entry = by_path.get(f"{base}/cmdline.json")
                if (
                    type(argv_entry) is not InputFile
                    or argv_entry.mode & 0o400 == 0
                    or any(
                        type(alias) is InputHardlink
                        and alias.target == argv_entry.path
                        for alias in definition.inputs
                    )
                ):
                    raise ProcessLifecycleDeltaError(
                        "reference argv is unavailable"
                    )
                argv = _reference_parse_argv_payload(argv_entry.content)
            if parameters.snapshot_pair in {
                "status-and-cgroups",
                "complete-synthetic-proc",
            }:
                cgroups_entry = by_path.get(f"{base}/cgroups.json")
                if (
                    type(cgroups_entry) is not InputFile
                    or cgroups_entry.mode & 0o400 == 0
                    or any(
                        type(alias) is InputHardlink
                        and alias.target == cgroups_entry.path
                        for alias in definition.inputs
                    )
                ):
                    raise ProcessLifecycleDeltaError(
                        "reference cgroups are unavailable"
                    )
                cgroups = _reference_parse_cgroups_payload(
                    cgroups_entry.content
                )
            valid.append(
                ProcessProjection(
                    parameters.snapshot_pair,
                    raw["comm"],  # type: ignore[arg-type]
                    raw["cpu_milli_percent"],  # type: ignore[arg-type]
                    raw["pid"],  # type: ignore[arg-type]
                    raw["ppid"],  # type: ignore[arg-type]
                    raw["rss_kib"],  # type: ignore[arg-type]
                    raw["start_ticks"],  # type: ignore[arg-type]
                    raw["state"],  # type: ignore[arg-type]
                    raw["uid"],  # type: ignore[arg-type]
                    argv,
                    cgroups,
                )
            )
        except ProcessLifecycleDeltaError:
            unknown.append(pid)
    return _EndpointClassification(
        numeric_names,
        tuple(valid),
        tuple(unknown),
    )


def _pair_input_file(definition: FixtureDefinition) -> InputFile:
    index = _definition_index(definition)
    return _consulted_file(
        definition, index, PROCESS_LIFECYCLE_DELTA_PAIR_INPUT
    )


def _load_pair_primary(definition: FixtureDefinition) -> ProcessPairMetadata:
    return _parse_pair_payload(_pair_input_file(definition).content)


def _load_pair_reference(definition: FixtureDefinition) -> ProcessPairMetadata:
    matches = tuple(
        entry
        for entry in reversed(definition.inputs)
        if entry.path == PROCESS_LIFECYCLE_DELTA_PAIR_INPUT
    )
    if len(matches) != 1 or type(matches[0]) is not InputFile:
        raise ProcessLifecycleDeltaError(
            "reference pair metadata is not one regular file"
        )
    selected = matches[0]
    if selected.mode & 0o400 == 0 or any(
        type(alias) is InputHardlink and alias.target == selected.path
        for alias in definition.inputs
    ):
        raise ProcessLifecycleDeltaError(
            "reference pair metadata is unavailable"
        )
    return _reference_parse_pair_payload(selected.content)


def _primary_changed_fields(
    before: ProcessProjection,
    after: ProcessProjection,
) -> tuple[str, ...]:
    old = before.to_value()
    new = after.to_value()
    changed: list[str] = []
    for field_name in _CHANGED_FIELD_ORDER:
        if field_name in old and old[field_name] != new[field_name]:
            changed.append(field_name)
    return tuple(changed)


def _reference_changed_fields(
    before: ProcessProjection,
    after: ProcessProjection,
) -> tuple[str, ...]:
    pairs = (
        ("ppid", before.ppid, after.ppid),
        ("uid", before.uid, after.uid),
        ("state", before.state, after.state),
        ("rss_kib", before.rss_kib, after.rss_kib),
        (
            "cpu_milli_percent",
            before.cpu_milli_percent,
            after.cpu_milli_percent,
        ),
        ("comm", before.comm, after.comm),
    )
    result = [name for name, old, new in pairs if old != new]
    if before.argv is not None and before.argv != after.argv:
        result.append("argv")
    if before.cgroups is not None and before.cgroups != after.cgroups:
        result.append("cgroups")
    return tuple(result)


def _primary_crossings(
    before: ProcessProjection,
    after: ProcessProjection,
    pair: ProcessPairMetadata,
) -> ThresholdCrossings:
    return _projection_crossings(before, after, pair)


def _reference_crossings(
    before: ProcessProjection,
    after: ProcessProjection,
    pair: ProcessPairMetadata,
) -> ThresholdCrossings:
    rss: CrossingDirection | None = None
    cpu: CrossingDirection | None = None
    if (
        before.rss_kib < pair.rss_threshold_kib
        and after.rss_kib >= pair.rss_threshold_kib
    ):
        rss = "upward"
    elif (
        before.rss_kib >= pair.rss_threshold_kib
        and after.rss_kib < pair.rss_threshold_kib
    ):
        rss = "downward"
    if (
        before.cpu_milli_percent < pair.cpu_threshold_milli_percent
        and after.cpu_milli_percent >= pair.cpu_threshold_milli_percent
    ):
        cpu = "upward"
    elif (
        before.cpu_milli_percent >= pair.cpu_threshold_milli_percent
        and after.cpu_milli_percent < pair.cpu_threshold_milli_percent
    ):
        cpu = "downward"
    return ThresholdCrossings(rss, cpu)


def _reference_make_event(
    pair: ProcessPairMetadata,
    event_name: Transition,
    before: ProcessProjection | None,
    after: ProcessProjection | None,
    changed_fields: tuple[str, ...] = (),
    crossings: ThresholdCrossings | None = None,
) -> ProcessLifecycleEvent:
    projection = before if before is not None else after
    if projection is None:
        raise ProcessLifecycleDeltaError(
            "reference event has no process projection"
        )
    event = object.__new__(ProcessLifecycleEvent)
    values: dict[str, object] = {
        "boot_id": pair.boot_id,
        "pid": projection.pid,
        "start_ticks": projection.start_ticks,
        "event": event_name,
        "before": before,
        "after": after,
        "changed_fields": changed_fields,
        "threshold_crossings": (
            ThresholdCrossings(None, None)
            if crossings is None
            else crossings
        ),
    }
    for name, value in values.items():
        object.__setattr__(event, name, value)
    return event


def _reference_event_selected(
    event: ProcessLifecycleEvent,
    policy: SelectionPolicy,
) -> bool:
    if policy == "all-changes":
        return True
    if policy == "starts-only":
        return event.event == "started"
    if policy == "exits-only":
        return event.event == "exited"
    if policy == "state-changes":
        return event.event == "changed" and "state" in event.changed_fields
    if policy == "resource-threshold-crossings":
        return event.event == "changed" and (
            event.threshold_crossings.rss_kib is not None
            or event.threshold_crossings.cpu_milli_percent is not None
        )
    raise ProcessLifecycleDeltaError(
        "reference selection policy is unsupported"
    )


def _reference_projection_value(
    projection: ProcessProjection,
) -> dict[str, object]:
    value: dict[str, object] = {
        "comm": projection.comm,
        "cpu_milli_percent": projection.cpu_milli_percent,
        "pid": projection.pid,
        "ppid": projection.ppid,
        "rss_kib": projection.rss_kib,
        "start_ticks": projection.start_ticks,
        "state": projection.state,
        "uid": projection.uid,
    }
    if projection.argv is not None:
        value["argv"] = list(projection.argv)
    if projection.cgroups is not None:
        value["cgroups"] = list(projection.cgroups)
    return value


def _reference_event_value(
    event: ProcessLifecycleEvent,
) -> dict[str, object]:
    return {
        "boot_id": event.boot_id,
        "pid": event.pid,
        "start_ticks": event.start_ticks,
        "event": event.event,
        "before": (
            None
            if event.before is None
            else _reference_projection_value(event.before)
        ),
        "after": (
            None
            if event.after is None
            else _reference_projection_value(event.after)
        ),
        "changed_fields": list(event.changed_fields),
        "threshold_crossings": {
            "cpu_milli_percent": (
                event.threshold_crossings.cpu_milli_percent
            ),
            "rss_kib": event.threshold_crossings.rss_kib,
        },
    }


def _started_event(
    pair: ProcessPairMetadata,
    after: ProcessProjection,
) -> ProcessLifecycleEvent:
    return ProcessLifecycleEvent(
        pair.boot_id,
        after.pid,
        after.start_ticks,
        "started",
        None,
        after,
        (),
        ThresholdCrossings(None, None),
    )


def _exited_event(
    pair: ProcessPairMetadata,
    before: ProcessProjection,
) -> ProcessLifecycleEvent:
    return ProcessLifecycleEvent(
        pair.boot_id,
        before.pid,
        before.start_ticks,
        "exited",
        before,
        None,
        (),
        ThresholdCrossings(None, None),
    )


def _changed_event(
    pair: ProcessPairMetadata,
    before: ProcessProjection,
    after: ProcessProjection,
    changed_fields: tuple[str, ...],
    crossings: ThresholdCrossings,
) -> ProcessLifecycleEvent:
    return ProcessLifecycleEvent(
        pair.boot_id,
        before.pid,
        before.start_ticks,
        "changed",
        before,
        after,
        changed_fields,
        crossings,
    )


def _temporally_suppressed_pids(
    before: dict[int, ProcessProjection],
    after: dict[int, ProcessProjection],
    pair: ProcessPairMetadata,
) -> set[int]:
    suppressed: set[int] = set()
    for pid, observed_after in after.items():
        observed_before = before.get(pid)
        if (
            observed_before is None
            or observed_before.start_ticks != observed_after.start_ticks
        ) and observed_after.start_ticks <= pair.before_snapshot_ticks:
            suppressed.add(pid)
    return suppressed


def _derive_primary_events(
    pair: ProcessPairMetadata,
    before_classification: _EndpointClassification,
    after_classification: _EndpointClassification,
    parameters: ProcessLifecycleDeltaParameters,
) -> tuple[int, int, tuple[int, ...], tuple[ProcessLifecycleEvent, ...]]:
    before = {item.pid: item for item in before_classification.valid}
    after = {item.pid: item for item in after_classification.valid}
    unknown = set(before_classification.unknown_pids)
    unknown.update(after_classification.unknown_pids)
    unknown.update(_temporally_suppressed_pids(before, after, pair))
    for pid in unknown:
        before.pop(pid, None)
        after.pop(pid, None)

    events: list[ProcessLifecycleEvent] = []
    for pid in sorted(set(before) | set(after)):
        old = before.get(pid)
        new = after.get(pid)
        if old is None and new is not None:
            events.append(_started_event(pair, new))
        elif old is not None and new is None:
            events.append(_exited_event(pair, old))
        elif old is not None and new is not None:
            if old.start_ticks != new.start_ticks:
                events.extend(
                    (_exited_event(pair, old), _started_event(pair, new))
                )
            else:
                fields = _primary_changed_fields(old, new)
                if fields:
                    events.append(
                        _changed_event(
                            pair,
                            old,
                            new,
                            fields,
                            _primary_crossings(old, new, pair),
                        )
                    )
    selected = tuple(
        event
        for event in events
        if _event_selected(event, parameters.selection_policy)
    )
    return len(before), len(after), tuple(sorted(unknown)), selected


def _derive_reference_events(
    pair: ProcessPairMetadata,
    before_classification: _EndpointClassification,
    after_classification: _EndpointClassification,
    parameters: ProcessLifecycleDeltaParameters,
) -> tuple[int, int, tuple[int, ...], tuple[ProcessLifecycleEvent, ...]]:
    before_rows = list(before_classification.valid)
    after_rows = list(after_classification.valid)
    unknown = set(before_classification.unknown_pids) | set(
        after_classification.unknown_pids
    )
    before_by_pid = {row.pid: row for row in before_rows}
    after_by_pid = {row.pid: row for row in after_rows}
    for row in after_rows:
        old = before_by_pid.get(row.pid)
        if (
            old is None or old.start_ticks != row.start_ticks
        ) and row.start_ticks <= pair.before_snapshot_ticks:
            unknown.add(row.pid)
    before_rows = [row for row in before_rows if row.pid not in unknown]
    after_rows = [row for row in after_rows if row.pid not in unknown]

    output: list[ProcessLifecycleEvent] = []
    left = 0
    right = 0
    while left < len(before_rows) or right < len(after_rows):
        old = before_rows[left] if left < len(before_rows) else None
        new = after_rows[right] if right < len(after_rows) else None
        if new is None or (old is not None and old.pid < new.pid):
            candidates = [
                _reference_make_event(
                    pair,
                    "exited",
                    old,  # type: ignore[arg-type]
                    None,
                )
            ]
            left += 1
        elif old is None or new.pid < old.pid:
            candidates = [
                _reference_make_event(pair, "started", None, new)
            ]
            right += 1
        else:
            candidates = []
            if old.start_ticks != new.start_ticks:
                candidates.extend(
                    (
                        _reference_make_event(
                            pair, "exited", old, None
                        ),
                        _reference_make_event(
                            pair, "started", None, new
                        ),
                    )
                )
            else:
                differences = _reference_changed_fields(old, new)
                if differences:
                    candidates.append(
                        _reference_make_event(
                            pair,
                            "changed",
                            old,
                            new,
                            differences,
                            _reference_crossings(old, new, pair),
                        )
                    )
            left += 1
            right += 1
        output.extend(
            candidate
            for candidate in candidates
            if _reference_event_selected(
                candidate, parameters.selection_policy
            )
        )
    return (
        len(before_rows),
        len(after_rows),
        tuple(sorted(unknown)),
        tuple(output),
    )


def _build_state(
    pair: ProcessPairMetadata,
    parameters: ProcessLifecycleDeltaParameters,
    result: tuple[
        int,
        int,
        tuple[int, ...],
        tuple[ProcessLifecycleEvent, ...],
    ],
) -> ProcessLifecycleDeltaState:
    before_count, after_count, unknown, events = result
    content = b"".join(_canonical_json(event.to_value()) for event in events)
    return ProcessLifecycleDeltaState(
        parameters.snapshot_pair,
        parameters.selection_policy,
        pair,
        before_count,
        after_count,
        unknown,
        events,
        content,
    )


def _reference_validate_definition(
    definition: object,
) -> FixtureDefinition:
    if type(definition) is not FixtureDefinition:
        raise ProcessLifecycleDeltaError(
            "reference fixture definition has wrong exact type"
        )
    if (
        type(definition.fixture_id) is not str
        or type(definition.schema_version) is not str
        or type(definition.inputs) is not tuple
        or type(definition.expected_files) is not tuple
        or type(definition.expected_symlinks) is not tuple
    ):
        raise ProcessLifecycleDeltaError(
            "reference fixture definition fields have wrong exact types"
        )
    for item in definition.inputs:
        if type(item) is InputFile:
            if (
                type(item.path) is not str
                or type(item.content) is not bytes
                or type(item.mode) is not int
                or (
                    item.mtime_seconds is not None
                    and type(item.mtime_seconds) is not int
                )
            ):
                raise ProcessLifecycleDeltaError(
                    "reference input file fields have wrong exact types"
                )
        elif type(item) is InputSymlink:
            if type(item.path) is not str or type(item.target) is not str:
                raise ProcessLifecycleDeltaError(
                    "reference input symlink fields have wrong exact types"
                )
        elif type(item) is InputHardlink:
            raise ProcessLifecycleDeltaError(
                "authenticated hardlinks are outside the reference domain"
            )
        else:
            raise ProcessLifecycleDeltaError(
                "reference fixture contains an unsupported input type"
            )
    for expected in definition.expected_files:
        if (
            type(expected) is not ExpectedFile
            or type(expected.path) is not str
            or type(expected.maximum_bytes) is not int
            or (
                expected.mode is not None
                and type(expected.mode) is not int
            )
            or (
                expected.required_link_count is not None
                and type(expected.required_link_count) is not int
            )
        ):
            raise ProcessLifecycleDeltaError(
                "reference expected output fields have wrong exact types"
            )
    try:
        rebuilt = FixtureDefinition(
            definition.fixture_id,
            definition.inputs,
            definition.expected_files,
            definition.schema_version,
            definition.expected_symlinks,
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise ProcessLifecycleDeltaError(
            "reference fixture definition reconstruction failed"
        ) from exc
    expected_output = (
        ExpectedFile(
            PROCESS_LIFECYCLE_DELTA_OUTPUT,
            PROCESS_LIFECYCLE_DELTA_OUTPUT_MAXIMUM_BYTES,
            PROCESS_LIFECYCLE_DELTA_OUTPUT_MODE,
        ),
    )
    if (
        rebuilt != definition
        or definition.expected_symlinks
        or (
            definition.expected_files
            and definition.expected_files != expected_output
        )
    ):
        raise ProcessLifecycleDeltaError(
            "reference fixture output policy is outside the family domain"
        )
    source_prefix = PROCESS_LIFECYCLE_DELTA_SOURCE_ROOT + "/"
    if any(
        not item.path.startswith(source_prefix)
        for item in definition.inputs
    ):
        raise ProcessLifecycleDeltaError(
            "reference fixture input escapes the semantic source root"
        )
    if (
        sum(
            len(item.content)
            for item in definition.inputs
            if type(item) is InputFile
        )
        > PROCESS_LIFECYCLE_DELTA_INPUT_MAXIMUM_BYTES
    ):
        raise ProcessLifecycleDeltaError(
            "reference fixture exceeds its input-byte bound"
        )
    if any(
        item.path
        in {
            PROCESS_LIFECYCLE_DELTA_SOURCE_ROOT,
            f"{PROCESS_LIFECYCLE_DELTA_SOURCE_ROOT}/before",
            f"{PROCESS_LIFECYCLE_DELTA_SOURCE_ROOT}/after",
        }
        for item in definition.inputs
    ):
        raise ProcessLifecycleDeltaError(
            "reference source or endpoint root is not a real directory"
        )
    endpoint_pids: dict[str, tuple[int, ...]] = {}
    for side in ("before", "after"):
        prefix = f"{PROCESS_LIFECYCLE_DELTA_SOURCE_ROOT}/{side}/"
        if not any(
            item.path.startswith(prefix) for item in definition.inputs
        ):
            raise ProcessLifecycleDeltaError(
                f"reference {side} endpoint lacks a descendant"
            )
        endpoint_pids[side] = _reference_discover_endpoint_pids(
            definition, side  # type: ignore[arg-type]
        )
    if (
        len(set(endpoint_pids["before"]) | set(endpoint_pids["after"]))
        > PROCESS_LIFECYCLE_DELTA_MAXIMUM_UNION_PROCESSES
    ):
        raise ProcessLifecycleDeltaError(
            "reference fixture PID union exceeds its bound"
        )
    return definition


def _reference_build_state(
    pair: ProcessPairMetadata,
    parameters: ProcessLifecycleDeltaParameters,
    result: tuple[
        int,
        int,
        tuple[int, ...],
        tuple[ProcessLifecycleEvent, ...],
    ],
) -> ProcessLifecycleDeltaState:
    before_count, after_count, unknown, events = result
    expected_order = tuple(
        sorted(
            events,
            key=lambda item: (
                item.pid,
                _TRANSITION_RANK[item.event],
                item.start_ticks,
            ),
        )
    )
    identities = {
        (item.boot_id, item.pid, item.start_ticks, item.event)
        for item in events
    }
    if (
        before_count < 0
        or after_count < 0
        or before_count > PROCESS_LIFECYCLE_DELTA_MAXIMUM_PROCESSES
        or after_count > PROCESS_LIFECYCLE_DELTA_MAXIMUM_PROCESSES
        or unknown != tuple(sorted(set(unknown)))
        or len(unknown) > PROCESS_LIFECYCLE_DELTA_MAXIMUM_UNION_PROCESSES
        or events != expected_order
        or len(identities) != len(events)
        or len(events) > 2 * PROCESS_LIFECYCLE_DELTA_MAXIMUM_PROCESSES
    ):
        raise ProcessLifecycleDeltaError(
            "reference state assembly violates its collection bounds"
        )
    content = b"".join(
        _canonical_json(_reference_event_value(event))
        for event in events
    )
    if len(content) > PROCESS_LIFECYCLE_DELTA_OUTPUT_MAXIMUM_BYTES:
        raise ProcessLifecycleDeltaError(
            "reference state exceeds its output-byte bound"
        )
    state = object.__new__(ProcessLifecycleDeltaState)
    values: dict[str, object] = {
        "snapshot_pair": parameters.snapshot_pair,
        "selection_policy": parameters.selection_policy,
        "pair": pair,
        "before_valid_count": before_count,
        "after_valid_count": after_count,
        "unknown_pids": unknown,
        "events": events,
        "content": content,
    }
    for name, value in values.items():
        object.__setattr__(state, name, value)
    return state


def derive_process_lifecycle_delta_state(
    definition: FixtureDefinition,
    parameters: ProcessLifecycleDeltaParameters,
) -> ProcessLifecycleDeltaState:
    """Derive lifecycle events through indexed endpoint maps."""

    _revalidate_definition(definition)
    if type(parameters) is not ProcessLifecycleDeltaParameters:
        raise ProcessLifecycleDeltaError("parameters have wrong exact type")
    parameters.__post_init__()
    pair = _load_pair_primary(definition)
    before = _classify_endpoint_primary(
        definition, parameters, pair, "before"
    )
    after = _classify_endpoint_primary(
        definition, parameters, pair, "after"
    )
    if (
        len(set(before.present_pids) | set(after.present_pids))
        > PROCESS_LIFECYCLE_DELTA_MAXIMUM_UNION_PROCESSES
    ):
        raise ProcessLifecycleDeltaError("snapshot union exceeds PID bound")
    return _build_state(
        pair,
        parameters,
        _derive_primary_events(pair, before, after, parameters),
    )


def reference_process_lifecycle_delta_state(
    definition: FixtureDefinition,
    parameters: ProcessLifecycleDeltaParameters,
) -> ProcessLifecycleDeltaState:
    """Derive lifecycle events through an independent raw-entry rescan."""

    _reference_validate_definition(definition)
    if type(parameters) is not ProcessLifecycleDeltaParameters:
        raise ProcessLifecycleDeltaError("parameters have wrong exact type")
    parameters.__post_init__()
    pair = _load_pair_reference(definition)
    before = _classify_endpoint_reference(
        definition, parameters, pair, "before"
    )
    after = _classify_endpoint_reference(
        definition, parameters, pair, "after"
    )
    if (
        len(set(before.present_pids) | set(after.present_pids))
        > PROCESS_LIFECYCLE_DELTA_MAXIMUM_UNION_PROCESSES
    ):
        raise ProcessLifecycleDeltaError(
            "reference snapshot union exceeds PID bound"
        )
    return _reference_build_state(
        pair,
        parameters,
        _derive_reference_events(pair, before, after, parameters),
    )


def _projection_from_value(
    value: object,
    snapshot_pair: SnapshotPair,
    field_name: str,
) -> ProcessProjection:
    keys = set(_STATUS_KEYS)
    if snapshot_pair in {
        "status-and-cmdline",
        "complete-synthetic-proc",
    }:
        keys.add("argv")
    if snapshot_pair in {
        "status-and-cgroups",
        "complete-synthetic-proc",
    }:
        keys.add("cgroups")
    projection = _require_exact_keys(value, frozenset(keys), field_name)
    argv: tuple[str, ...] | None = None
    cgroups: tuple[str, ...] | None = None
    if "argv" in projection:
        raw_argv = projection["argv"]
        if type(raw_argv) is not list:
            raise ProcessLifecycleDeltaError(
                f"{field_name}.argv must be an exact array"
            )
        argv = _validate_argv_tuple(tuple(raw_argv))
    if "cgroups" in projection:
        raw_cgroups = projection["cgroups"]
        if type(raw_cgroups) is not list:
            raise ProcessLifecycleDeltaError(
                f"{field_name}.cgroups must be an exact array"
            )
        cgroups = _validate_cgroups_tuple(tuple(raw_cgroups))
    return ProcessProjection(
        snapshot_pair,
        _validate_comm(projection["comm"], f"{field_name}.comm"),
        _bounded_int(
            projection["cpu_milli_percent"],
            f"{field_name}.cpu_milli_percent",
            maximum=PROCESS_LIFECYCLE_DELTA_MAXIMUM_CPU_MILLI_PERCENT,
        ),
        _bounded_int(
            projection["pid"],
            f"{field_name}.pid",
            minimum=1,
            maximum=PROCESS_LIFECYCLE_DELTA_MAXIMUM_PID,
        ),
        _bounded_int(
            projection["ppid"],
            f"{field_name}.ppid",
            maximum=PROCESS_LIFECYCLE_DELTA_MAXIMUM_PID,
        ),
        _bounded_int(projection["rss_kib"], f"{field_name}.rss_kib"),
        _bounded_int(
            projection["start_ticks"],
            f"{field_name}.start_ticks",
            minimum=1,
        ),
        _closed_text(
            projection["state"],
            PROCESS_LIFECYCLE_DELTA_STATES,
            f"{field_name}.state",
        ),
        _bounded_int(
            projection["uid"],
            f"{field_name}.uid",
            maximum=PROCESS_LIFECYCLE_DELTA_MAXIMUM_UID,
        ),
        argv,
        cgroups,
    )


def _crossings_from_value(value: object) -> ThresholdCrossings:
    crossings = _require_exact_keys(
        value, _CROSSING_KEYS, "threshold_crossings"
    )
    for field_name in ("rss_kib", "cpu_milli_percent"):
        direction = crossings[field_name]
        if direction is not None and (
            type(direction) is not str
            or direction not in {"upward", "downward"}
        ):
            raise ProcessLifecycleDeltaError(
                f"{field_name} crossing direction is invalid"
            )
    return ThresholdCrossings(
        crossings["rss_kib"],  # type: ignore[arg-type]
        crossings["cpu_milli_percent"],  # type: ignore[arg-type]
    )


def _event_from_value(
    value: object,
    parameters: ProcessLifecycleDeltaParameters,
    pair: ProcessPairMetadata,
) -> ProcessLifecycleEvent:
    row = _require_exact_keys(value, _EVENT_KEYS, "transition row")
    boot_id = row["boot_id"]
    if type(boot_id) is not str or boot_id != pair.boot_id:
        raise ProcessLifecycleDeltaError(
            "transition boot_id differs from pair metadata"
        )
    event_name = _closed_text(
        row["event"], ("started", "exited", "changed"), "event"
    )
    before = (
        None
        if row["before"] is None
        else _projection_from_value(
            row["before"], parameters.snapshot_pair, "before"
        )
    )
    after = (
        None
        if row["after"] is None
        else _projection_from_value(
            row["after"], parameters.snapshot_pair, "after"
        )
    )
    changed = row["changed_fields"]
    if (
        type(changed) is not list
        or any(type(item) is not str for item in changed)
    ):
        raise ProcessLifecycleDeltaError(
            "changed_fields must be an exact string array"
        )
    event = ProcessLifecycleEvent(
        boot_id,
        _bounded_int(
            row["pid"],
            "row pid",
            minimum=1,
            maximum=PROCESS_LIFECYCLE_DELTA_MAXIMUM_PID,
        ),
        _bounded_int(row["start_ticks"], "row start_ticks", minimum=1),
        event_name,  # type: ignore[arg-type]
        before,
        after,
        tuple(changed),
        _crossings_from_value(row["threshold_crossings"]),
    )
    if not _event_selected(event, parameters.selection_policy):
        raise ProcessLifecycleDeltaError(
            "transition row is outside selected policy"
        )
    if event.event == "started":
        if (
            event.start_ticks <= pair.before_snapshot_ticks
            or event.start_ticks > pair.after_snapshot_ticks
        ):
            raise ProcessLifecycleDeltaError(
                "started row is outside snapshot interval"
            )
    if event.before is not None and (
        event.before.start_ticks > pair.before_snapshot_ticks
    ):
        raise ProcessLifecycleDeltaError(
            "before projection begins after before endpoint"
        )
    if event.after is not None and (
        event.after.start_ticks > pair.after_snapshot_ticks
    ):
        raise ProcessLifecycleDeltaError(
            "after projection begins after after endpoint"
        )
    if (
        event.event == "changed"
        and event.before is not None
        and event.after is not None
        and event.threshold_crossings
        != _projection_crossings(event.before, event.after, pair)
    ):
        raise ProcessLifecycleDeltaError(
            "transition row has fabricated or incomplete crossings"
        )
    return event


def parse_process_lifecycle_delta_output(
    payload: bytes,
    parameters: ProcessLifecycleDeltaParameters,
    pair: ProcessPairMetadata,
) -> bytes:
    """Validate semantic JSONL and return canonical ordered JSONL bytes."""

    if type(parameters) is not ProcessLifecycleDeltaParameters:
        raise ProcessLifecycleDeltaError("parameters have wrong exact type")
    if type(pair) is not ProcessPairMetadata:
        raise ProcessLifecycleDeltaError("pair has wrong exact type")
    parameters.__post_init__()
    pair.__post_init__()
    if (
        type(payload) is not bytes
        or len(payload) > PROCESS_LIFECYCLE_DELTA_OUTPUT_MAXIMUM_BYTES
    ):
        raise ProcessLifecycleDeltaError(
            "transition output violates its byte bound"
        )
    if not payload:
        return b""
    if (
        not payload.endswith(b"\n")
        or payload.endswith(b"\n\n")
        or b"\r" in payload
    ):
        raise ProcessLifecycleDeltaError(
            "transition output violates strict JSONL framing"
        )
    physical_rows = payload[:-1].split(b"\n")
    if not physical_rows or any(not row for row in physical_rows):
        raise ProcessLifecycleDeltaError(
            "transition output contains a blank row"
        )
    events = tuple(
        _event_from_value(
            _decode_json_strict(
                row, PROCESS_LIFECYCLE_DELTA_OUTPUT_MAXIMUM_BYTES
            ),
            parameters,
            pair,
        )
        for row in physical_rows
    )
    expected_order = tuple(
        sorted(
            events,
            key=lambda item: (
                item.pid,
                _TRANSITION_RANK[item.event],
                item.start_ticks,
            ),
        )
    )
    identities = {
        (event.boot_id, event.pid, event.start_ticks, event.event)
        for event in events
    }
    if expected_order != events or len(identities) != len(events):
        raise ProcessLifecycleDeltaError(
            "transition rows are unordered or duplicated"
        )
    by_pid: dict[int, list[ProcessLifecycleEvent]] = {}
    for event in events:
        by_pid.setdefault(event.pid, []).append(event)
    if any(
        len(rows) > 2
        or (
            len(rows) == 2
            and tuple(item.event for item in rows)
            != ("exited", "started")
        )
        for rows in by_pid.values()
    ):
        raise ProcessLifecycleDeltaError(
            "transition rows contain an impossible PID event combination"
        )
    return b"".join(_canonical_json(event.to_value()) for event in events)


def _expected_files() -> tuple[ExpectedFile, ...]:
    return (
        ExpectedFile(
            PROCESS_LIFECYCLE_DELTA_OUTPUT,
            PROCESS_LIFECYCLE_DELTA_OUTPUT_MAXIMUM_BYTES,
            PROCESS_LIFECYCLE_DELTA_OUTPUT_MODE,
        ),
    )


def _revalidate_definition(definition: object) -> FixtureDefinition:
    if type(definition) is not FixtureDefinition:
        raise ProcessLifecycleDeltaError(
            "fixture definition has wrong exact type"
        )
    if (
        type(definition.fixture_id) is not str
        or type(definition.schema_version) is not str
        or type(definition.inputs) is not tuple
        or type(definition.expected_files) is not tuple
        or type(definition.expected_symlinks) is not tuple
    ):
        raise ProcessLifecycleDeltaError(
            "fixture definition fields have wrong exact types"
        )
    for item in definition.inputs:
        if type(item) is InputFile:
            if (
                type(item.path) is not str
                or type(item.content) is not bytes
                or type(item.mode) is not int
                or (
                    item.mtime_seconds is not None
                    and type(item.mtime_seconds) is not int
                )
            ):
                raise ProcessLifecycleDeltaError(
                    "input file fields have wrong exact types"
                )
        elif type(item) is InputSymlink:
            if type(item.path) is not str or type(item.target) is not str:
                raise ProcessLifecycleDeltaError(
                    "input symlink fields have wrong exact types"
                )
        elif type(item) is InputHardlink:
            raise ProcessLifecycleDeltaError(
                "authenticated hardlinks are outside the family domain"
            )
        else:
            raise ProcessLifecycleDeltaError(
                "fixture contains unsupported input type"
            )
    for expected in definition.expected_files:
        if (
            type(expected) is not ExpectedFile
            or type(expected.path) is not str
            or type(expected.maximum_bytes) is not int
            or (
                expected.mode is not None and type(expected.mode) is not int
            )
            or (
                expected.required_link_count is not None
                and type(expected.required_link_count) is not int
            )
        ):
            raise ProcessLifecycleDeltaError(
                "expected output fields have wrong exact types"
            )
    try:
        rebuilt = FixtureDefinition(
            definition.fixture_id,
            definition.inputs,
            definition.expected_files,
            definition.schema_version,
            definition.expected_symlinks,
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise ProcessLifecycleDeltaError(
            "fixture definition reconstruction failed"
        ) from exc
    if (
        rebuilt != definition
        or definition.expected_symlinks
        or (
            definition.expected_files
            and definition.expected_files != _expected_files()
        )
    ):
        raise ProcessLifecycleDeltaError(
            "fixture output policy is outside the family domain"
        )
    root_prefix = PROCESS_LIFECYCLE_DELTA_SOURCE_ROOT + "/"
    if any(
        not item.path.startswith(root_prefix)
        for item in definition.inputs
    ):
        raise ProcessLifecycleDeltaError(
            "fixture input escapes the sole semantic source root"
        )
    if sum(
        len(item.content)
        for item in definition.inputs
        if type(item) is InputFile
    ) > PROCESS_LIFECYCLE_DELTA_INPUT_MAXIMUM_BYTES:
        raise ProcessLifecycleDeltaError(
            "fixture exceeds authenticated input-byte bound"
        )
    if any(
        item.path
        in {
            PROCESS_LIFECYCLE_DELTA_SOURCE_ROOT,
            f"{PROCESS_LIFECYCLE_DELTA_SOURCE_ROOT}/before",
            f"{PROCESS_LIFECYCLE_DELTA_SOURCE_ROOT}/after",
        }
        for item in definition.inputs
    ):
        raise ProcessLifecycleDeltaError(
            "source or endpoint root is not a real directory"
        )
    for side in ("before", "after"):
        prefix = f"{PROCESS_LIFECYCLE_DELTA_SOURCE_ROOT}/{side}/"
        if not any(item.path.startswith(prefix) for item in definition.inputs):
            raise ProcessLifecycleDeltaError(
                f"{side} endpoint root lacks an authenticated descendant"
            )
        _discover_endpoint_pids(definition, side)
    if (
        len(
            set(_discover_endpoint_pids(definition, "before"))
            | set(_discover_endpoint_pids(definition, "after"))
        )
        > PROCESS_LIFECYCLE_DELTA_MAXIMUM_UNION_PROCESSES
    ):
        raise ProcessLifecycleDeltaError("fixture PID union exceeds bound")
    _pair_input_file(definition)
    return definition


def _status_value(
    pid: int,
    start_ticks: int,
    *,
    comm: str,
    state: ProcessState = "S",
    ppid: int = 1,
    uid: int = 1000,
    rss_kib: int = 2048,
    cpu_milli_percent: int = 12500,
) -> dict[str, object]:
    value = {
        "comm": comm,
        "cpu_milli_percent": cpu_milli_percent,
        "pid": pid,
        "ppid": ppid,
        "rss_kib": rss_kib,
        "start_ticks": start_ticks,
        "state": state,
        "uid": uid,
    }
    _parse_status_payload(
        _canonical_json(value),
        expected_pid=pid,
        endpoint_ticks=PROCESS_LIFECYCLE_DELTA_MAXIMUM_INTEGER,
    )
    return value


def _append_valid_process(
    inputs: list[InputFile | InputHardlink | InputSymlink],
    side: Literal["before", "after"],
    status: dict[str, object],
    *,
    argv: tuple[str, ...],
    cgroups: tuple[str, ...],
    status_mode: int = 0o600,
    argv_mode: int = 0o600,
    cgroups_mode: int = 0o600,
) -> None:
    pid = status["pid"]
    if type(pid) is not int:
        raise ProcessLifecycleDeltaError("fixture status pid is invalid")
    root = f"{PROCESS_LIFECYCLE_DELTA_SOURCE_ROOT}/{side}/{pid}"
    sorted_cgroups = tuple(
        sorted(set(cgroups), key=lambda item: item.encode("utf-8"))
    )
    inputs.extend(
        (
            InputFile(
                f"{root}/status.json",
                _canonical_json(status),
                status_mode,
                3_000 + pid,
            ),
            InputFile(
                f"{root}/cmdline.json",
                _canonical_json(list(argv)),
                argv_mode,
                4_000 + pid,
            ),
            InputFile(
                f"{root}/cgroups.json",
                _canonical_json(list(sorted_cgroups)),
                cgroups_mode,
                5_000 + pid,
            ),
        )
    )


def _profile_literals(
    profile: ExecutableFixtureProfile,
) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
    if profile.profile_id == "spaces-unicode":
        return (
            "shell worker 雪",
            ("bash", "-c", "echo café", "", "echo café", 'quote"\\'),
            ("/user slice/雪", "/work/café"),
        )
    if profile.profile_id == "leading-dashes-globs":
        return (
            "-worker[*]?",
            ("--", "-n", "*.txt", "file?[x]", "--literal"),
            ("/-slice/[*]?", "/jobs/*/literal"),
        )
    if profile.profile_id == "empty-duplicates":
        return (
            "duplicate worker",
            ("", "same", "same", ""),
            ("/empty-test", "/same"),
        )
    if profile.profile_id == "symlinks-ordering":
        return (
            "ordered worker",
            ("bash", "numeric", "2", "10", "100"),
            ("/order/10", "/order/100", "/order/2"),
        )
    if profile.profile_id == "partial-permissions":
        return (
            "bounded worker",
            ("bash", "-eu", "bounded"),
            ("/limits/max", "/limits/min"),
        )
    raise ProcessLifecycleDeltaError(
        "fixture profile is outside the closed set"
    )


def _fixture_inputs(
    profile: ExecutableFixtureProfile,
) -> tuple[InputFile | InputHardlink | InputSymlink, ...]:
    if type(profile) is not ExecutableFixtureProfile:
        raise ProcessLifecycleDeltaError(
            "fixture profile has wrong exact type"
        )
    profile.__post_init__()
    comm, argv, cgroups = _profile_literals(profile)
    boot_id = "01234567-89ab-cdef-0123-456789abcdef"
    pair = ProcessPairMetadata(boot_id, 1_000, 2_000, 4_096, 50_000)
    inputs: list[InputFile | InputHardlink | InputSymlink] = [
        InputFile(
            PROCESS_LIFECYCLE_DELTA_PAIR_INPUT,
            _canonical_json(pair.to_value()),
            0o600,
            2_900,
        )
    ]

    # Exit anchor.
    _append_valid_process(
        inputs,
        "before",
        _status_value(2, 100, comm=f"{comm} exit"),
        argv=(*argv, "exit"),
        cgroups=(*cgroups, "/events/exit"),
    )
    # Strict-interval start anchor.
    _append_valid_process(
        inputs,
        "after",
        _status_value(3, 1_500, comm=f"{comm} start", state="R"),
        argv=(*argv, "start"),
        cgroups=(*cgroups, "/events/start"),
    )
    # Same-instance state change.
    _append_valid_process(
        inputs,
        "before",
        _status_value(4, 200, comm=f"{comm} state", state="S"),
        argv=(*argv, "state-before"),
        cgroups=(*cgroups, "/events/state-before"),
    )
    _append_valid_process(
        inputs,
        "after",
        _status_value(
            4,
            200,
            comm=f"{comm} state changed",
            state="R",
            uid=1001,
        ),
        argv=(*argv, "state-after"),
        cgroups=(*cgroups, "/events/state-after"),
    )
    # Simultaneous RSS-up and CPU-down boundary crossing.
    _append_valid_process(
        inputs,
        "before",
        _status_value(
            5,
            300,
            comm=f"{comm} resource",
            rss_kib=4_095,
            cpu_milli_percent=50_000,
        ),
        argv=(*argv, "resource-before"),
        cgroups=(*cgroups, "/events/resource-before"),
    )
    _append_valid_process(
        inputs,
        "after",
        _status_value(
            5,
            300,
            comm=f"{comm} resource",
            rss_kib=4_096,
            cpu_milli_percent=49_999,
        ),
        argv=(*argv, "resource-after"),
        cgroups=(*cgroups, "/events/resource-after"),
    )
    # Completely unchanged anchor.
    _append_valid_process(
        inputs,
        "before",
        _status_value(6, 400, comm=f"{comm} unchanged"),
        argv=argv,
        cgroups=cgroups,
    )
    _append_valid_process(
        inputs,
        "after",
        _status_value(6, 400, comm=f"{comm} unchanged"),
        argv=argv,
        cgroups=cgroups,
    )
    # PID reuse: exit old generation, then start new generation.
    _append_valid_process(
        inputs,
        "before",
        _status_value(7, 500, comm=f"{comm} generation old"),
        argv=(*argv, "old"),
        cgroups=(*cgroups, "/generation/old"),
    )
    _append_valid_process(
        inputs,
        "after",
        _status_value(7, 1_700, comm=f"{comm} generation new"),
        argv=(*argv, "new"),
        cgroups=(*cgroups, "/generation/new"),
    )
    # Status-only change not selected by the narrow policies.
    _append_valid_process(
        inputs,
        "before",
        _status_value(8, 600, comm=f"{comm} common before"),
        argv=(*argv, "common"),
        cgroups=(*cgroups, "/common"),
    )
    _append_valid_process(
        inputs,
        "after",
        _status_value(8, 600, comm=f"{comm} common after"),
        argv=(*argv, "common"),
        cgroups=(*cgroups, "/common"),
    )
    # Sidecar-only change makes all four projection modes behavioral.
    _append_valid_process(
        inputs,
        "before",
        _status_value(9, 700, comm=f"{comm} sidecar"),
        argv=(*argv, "sidecar-before"),
        cgroups=(*cgroups, "/sidecar/before"),
    )
    _append_valid_process(
        inputs,
        "after",
        _status_value(9, 700, comm=f"{comm} sidecar"),
        argv=(*argv, "sidecar-after"),
        cgroups=(*cgroups, "/sidecar/after"),
    )

    # UNKNOWN paired with a valid after observation.  Its exact failure mode
    # varies by profile, but it must never become a start.
    unknown_root = f"{PROCESS_LIFECYCLE_DELTA_SOURCE_ROOT}/before/10"
    if profile.profile_id == "spaces-unicode":
        inputs.append(
            InputFile(
                f"{unknown_root}/cmdline.json",
                _canonical_json(["status intentionally missing"]),
                0o600,
                6_010,
            )
        )
    elif profile.profile_id == "leading-dashes-globs":
        inputs.append(
            InputFile(
                f"{unknown_root}/status.json",
                b'{"pid":10,"state":"S"}\n',
                0o600,
                6_010,
            )
        )
    elif profile.profile_id == "empty-duplicates":
        inputs.append(
            InputFile(
                f"{unknown_root}/status.json",
                b'{"comm":"x","comm":"y","cpu_milli_percent":0,'
                b'"pid":10,"ppid":1,"rss_kib":0,"start_ticks":1,'
                b'"state":"S","uid":0}\n',
                0o600,
                6_010,
            )
        )
    elif profile.profile_id == "symlinks-ordering":
        inputs.extend(
            (
                InputFile(
                    f"{unknown_root}/status-target.json",
                    _canonical_json(
                        _status_value(10, 800, comm="symlink target")
                    ),
                    0o600,
                    6_010,
                ),
                InputSymlink(
                    f"{unknown_root}/status.json",
                    "status-target.json",
                ),
            )
        )
    elif profile.profile_id == "partial-permissions":
        inputs.append(
            InputFile(
                f"{unknown_root}/status.json",
                _canonical_json(
                    _status_value(10, 800, comm="unreadable status")
                ),
                0o000,
                6_010,
            )
        )
    else:
        raise ProcessLifecycleDeltaError(
            "fixture profile is outside the closed set"
        )
    _append_valid_process(
        inputs,
        "after",
        _status_value(10, 1_800, comm=f"{comm} suppressed"),
        argv=(*argv, "suppressed"),
        cgroups=(*cgroups, "/suppressed"),
    )

    # Authenticated noncanonical distractors never alias a canonical PID.
    for name in ("0", "00", "07", "+7", "-7", " 7 ", "4194305"):
        inputs.append(
            InputFile(
                f"{PROCESS_LIFECYCLE_DELTA_SOURCE_ROOT}/before/"
                f"{name}/ignored.json",
                b"not semantic\n",
                0o400,
                7_000 + len(inputs),
            )
        )

    if profile.profile_id == "empty-duplicates":
        # Valid empty arrays remain observations, while a duplicate cgroup
        # record on PID 12 is UNKNOWN in cgroup projections.
        _append_valid_process(
            inputs,
            "before",
            _status_value(11, 800, comm="empty arrays"),
            argv=(),
            cgroups=(),
        )
        _append_valid_process(
            inputs,
            "after",
            _status_value(11, 800, comm="empty arrays"),
            argv=(),
            cgroups=(),
        )
        root = f"{PROCESS_LIFECYCLE_DELTA_SOURCE_ROOT}/before/12"
        inputs.extend(
            (
                InputFile(
                    f"{root}/status.json",
                    _canonical_json(
                        _status_value(12, 810, comm="duplicate cgroup")
                    ),
                    0o600,
                    7_112,
                ),
                InputFile(
                    f"{root}/cmdline.json",
                    _canonical_json(["same", "same", ""]),
                    0o600,
                    7_212,
                ),
                InputFile(
                    f"{root}/cgroups.json",
                    _canonical_json(["/dup", "/dup"]),
                    0o600,
                    7_312,
                ),
            )
        )
        # FixtureDefinition materializes directories implicitly.  This
        # authenticated marker therefore represents an otherwise empty
        # non-PID directory that discovery must ignore.
        inputs.append(
            InputFile(
                f"{PROCESS_LIFECYCLE_DELTA_SOURCE_ROOT}/before/"
                "empty-ignored-directory/.authenticated-marker",
                b"",
                0o400,
                7_400,
            )
        )
        # Two different PIDs deliberately have equal same-endpoint mutable
        # projections.  Identity, not projection equality, keeps both exits.
        for pid in (13, 14):
            _append_valid_process(
                inputs,
                "before",
                _status_value(
                    pid,
                    820,
                    comm="duplicate mutable projection",
                    ppid=7,
                    uid=77,
                    rss_kib=777,
                    cpu_milli_percent=7_777,
                ),
                argv=("", "same", "same"),
                cgroups=("/duplicate/projection",),
            )
        # Equality at both thresholds is not a crossing.  A comm change makes
        # the null crossing observable in all-changes output.
        _append_valid_process(
            inputs,
            "before",
            _status_value(
                15,
                830,
                comm="equal threshold before",
                rss_kib=4_096,
                cpu_milli_percent=50_000,
            ),
            argv=("equal-threshold",),
            cgroups=("/threshold/equal",),
        )
        _append_valid_process(
            inputs,
            "after",
            _status_value(
                15,
                830,
                comm="equal threshold after",
                rss_kib=4_096,
                cpu_milli_percent=50_000,
            ),
            argv=("equal-threshold",),
            cgroups=("/threshold/equal",),
        )
    elif profile.profile_id == "symlinks-ordering":
        # A real PID 100 exit makes lexical 2,10,100 directory ordering
        # observably wrong.  PID 10 remains UNKNOWN because its status is a
        # symlink, while PID 100 must survive as the numeric tail event.
        _append_valid_process(
            inputs,
            "before",
            _status_value(100, 900, comm="numeric ordering tail"),
            argv=("bash", "numeric-tail", "100"),
            cgroups=("/order/numeric-tail",),
        )
        # A PID-directory symlink is UNKNOWN, and a nonconsulted symlink is
        # merely a preserved distractor.
        inputs.extend(
            (
                InputFile(
                    f"{PROCESS_LIFECYCLE_DELTA_SOURCE_ROOT}/before/"
                    "decoy-dir/keep",
                    b"do not follow\n",
                    0o400,
                    7_111,
                ),
                InputSymlink(
                    f"{PROCESS_LIFECYCLE_DELTA_SOURCE_ROOT}/before/11",
                    "decoy-dir",
                ),
                InputSymlink(
                    f"{PROCESS_LIFECYCLE_DELTA_SOURCE_ROOT}/after/"
                    "6/nonconsulted-link",
                    "status.json",
                ),
            )
        )
        inputs.reverse()
    elif profile.profile_id == "partial-permissions":
        # Old after-only generation, future status, PID mismatch, over-bound
        # status, and mode-unreadable required sidecars remain UNKNOWN or
        # temporally suppressed.
        for side, comm_suffix in (
            ("before", "before"),
            ("after", "after"),
        ):
            _append_valid_process(
                inputs,
                side,  # type: ignore[arg-type]
                _status_value(
                    1,
                    1,
                    comm=f"minimum numeric {comm_suffix}",
                    ppid=0,
                    uid=0,
                    rss_kib=0,
                    cpu_milli_percent=0,
                ),
                argv=("numeric-minimum",),
                cgroups=("/numeric/minimum",),
            )
            _append_valid_process(
                inputs,
                side,  # type: ignore[arg-type]
                _status_value(
                    PROCESS_LIFECYCLE_DELTA_MAXIMUM_PID,
                    1_000,
                    comm=f"maximum numeric {comm_suffix}",
                    ppid=PROCESS_LIFECYCLE_DELTA_MAXIMUM_PID,
                    uid=PROCESS_LIFECYCLE_DELTA_MAXIMUM_UID,
                    rss_kib=PROCESS_LIFECYCLE_DELTA_MAXIMUM_INTEGER,
                    cpu_milli_percent=(
                        PROCESS_LIFECYCLE_DELTA_MAXIMUM_CPU_MILLI_PERCENT
                    ),
                ),
                argv=("numeric-maximum",),
                cgroups=("/numeric/maximum",),
            )
            _append_valid_process(
                inputs,
                side,  # type: ignore[arg-type]
                _status_value(
                    31,
                    950,
                    comm=f"equal thresholds {comm_suffix}",
                    rss_kib=4_096,
                    cpu_milli_percent=50_000,
                ),
                argv=("equal-thresholds",),
                cgroups=("/threshold/equal-equal",),
            )
        _append_valid_process(
            inputs,
            "after",
            _status_value(20, 1_000, comm="old after-only"),
            argv=("old",),
            cgroups=("/old",),
        )
        future_root = (
            f"{PROCESS_LIFECYCLE_DELTA_SOURCE_ROOT}/after/21"
        )
        inputs.append(
            InputFile(
                f"{future_root}/status.json",
                _canonical_json(
                    _status_value(21, 2_001, comm="future")
                ),
                0o600,
                7_121,
            )
        )
        mismatch_root = (
            f"{PROCESS_LIFECYCLE_DELTA_SOURCE_ROOT}/after/22"
        )
        inputs.append(
            InputFile(
                f"{mismatch_root}/status.json",
                _canonical_json(
                    _status_value(23, 1_900, comm="mismatch")
                ),
                0o600,
                7_122,
            )
        )
        _append_valid_process(
            inputs,
            "before",
            _status_value(24, 900, comm="sidecar permission"),
            argv=("unreadable",),
            cgroups=("/readable",),
            argv_mode=0o000,
        )
        _append_valid_process(
            inputs,
            "after",
            _status_value(24, 900, comm="sidecar permission"),
            argv=("readable",),
            cgroups=("/readable",),
        )
        huge_root = f"{PROCESS_LIFECYCLE_DELTA_SOURCE_ROOT}/before/25"
        inputs.append(
            InputFile(
                f"{huge_root}/status.json",
                b"x" * (PROCESS_LIFECYCLE_DELTA_STATUS_MAXIMUM_BYTES + 1),
                0o600,
                7_125,
            )
        )
    # Ensure endpoint directories exist even in hand-derived empty variants.
    inputs.extend(
        (
            InputFile(
                f"{PROCESS_LIFECYCLE_DELTA_SOURCE_ROOT}/before/"
                "distractors/keep",
                b"before root anchor\n",
                0o400,
                8_001,
            ),
            InputFile(
                f"{PROCESS_LIFECYCLE_DELTA_SOURCE_ROOT}/after/"
                "distractors/keep",
                b"after root anchor\n",
                0o400,
                8_002,
            ),
        )
    )
    return tuple(inputs)


def _oracle_sha256(
    state: ProcessLifecycleDeltaState,
    parameters: ProcessLifecycleDeltaParameters,
) -> str:
    state.__post_init__()
    parameters.__post_init__()
    if (
        state.snapshot_pair != parameters.snapshot_pair
        or state.selection_policy != parameters.selection_policy
    ):
        raise ProcessLifecycleDeltaError(
            "oracle state differs from task parameters"
        )
    return domain_sha256(
        "cbds.executable-fixture.trusted-oracle.v1",
        {
            "schema_version": EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION,
            "semantic_verifier_identity": (
                PROCESS_LIFECYCLE_DELTA_VERIFIER_IDENTITY
            ),
            "parameters": parameters.to_record(),
            "state": state.commitment_record(),
        },
    )


@dataclass(frozen=True, slots=True)
class ProcessLifecycleDeltaOracle:
    state: ProcessLifecycleDeltaState = field(repr=False)
    snapshot_pair: SnapshotPair
    selection_policy: SelectionPolicy
    oracle_sha256: str
    semantic_verifier_identity: str = (
        PROCESS_LIFECYCLE_DELTA_VERIFIER_IDENTITY
    )
    schema_version: str = EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            type(self) is not ProcessLifecycleDeltaOracle
            or type(self.state) is not ProcessLifecycleDeltaState
        ):
            raise ProcessLifecycleDeltaError(
                "oracle or state has wrong exact type"
            )
        parameters = ProcessLifecycleDeltaParameters(
            self.snapshot_pair, self.selection_policy
        )
        self.state.__post_init__()
        if (
            type(self.semantic_verifier_identity) is not str
            or self.semantic_verifier_identity
            != PROCESS_LIFECYCLE_DELTA_VERIFIER_IDENTITY
            or type(self.schema_version) is not str
            or self.schema_version != EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION
            or self.state.snapshot_pair != self.snapshot_pair
            or self.state.selection_policy != self.selection_policy
            or not _is_sha256(self.oracle_sha256)
            or self.oracle_sha256 != _oracle_sha256(
                self.state, parameters
            )
        ):
            raise ProcessLifecycleDeltaError("oracle identity is invalid")

    def commitment_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "schema_version": self.schema_version,
            "record_type": "cbds.executable-fixture-trusted-oracle",
            "semantic_verifier_identity": self.semantic_verifier_identity,
            "snapshot_pair": self.snapshot_pair,
            "selection_policy": self.selection_policy,
            "state": self.state.commitment_record(),
            "oracle_sha256": self.oracle_sha256,
        }


@dataclass(frozen=True, slots=True)
class ProcessLifecycleDeltaFixtureBundle:
    task_contract_sha256: str
    profile_sha256: str
    definition: FixtureDefinition = field(repr=False)
    fixture_definition_sha256: str
    oracle: ProcessLifecycleDeltaOracle = field(repr=False)
    descriptor: OpaqueFixtureDescriptor
    schema_version: str = EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_process_lifecycle_delta_fixture_bundle(self)

    def commitment_record(self) -> dict[str, object]:
        validate_process_lifecycle_delta_fixture_bundle(self)
        return {
            "schema_version": self.schema_version,
            "record_type": "cbds.executable-fixture-private-binding",
            "binding_version": EXECUTABLE_FIXTURE_BINDING_VERSION,
            "task_contract_sha256": self.task_contract_sha256,
            "profile_sha256": self.profile_sha256,
            "fixture_definition_sha256": self.fixture_definition_sha256,
            "oracle": self.oracle.commitment_record(),
            "descriptor": self.descriptor.to_public_record(),
            "candidate_execution_authorized": False,
            "model_selection_eligible": False,
            "claim_authorized": False,
        }


def validate_process_lifecycle_delta_fixture_bundle(
    bundle: ProcessLifecycleDeltaFixtureBundle,
) -> None:
    if type(bundle) is not ProcessLifecycleDeltaFixtureBundle:
        raise ProcessLifecycleDeltaError("bundle has wrong exact type")
    if (
        type(bundle.schema_version) is not str
        or bundle.schema_version != EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION
        or not _is_sha256(bundle.task_contract_sha256)
        or not _is_sha256(bundle.profile_sha256)
        or not _is_sha256(bundle.fixture_definition_sha256)
        or bundle.candidate_execution_authorized is not False
        or bundle.model_selection_eligible is not False
        or bundle.claim_authorized is not False
    ):
        raise ProcessLifecycleDeltaError("bundle metadata is invalid")
    definition = _revalidate_definition(bundle.definition)
    definition_sha256 = compute_fixture_definition_semantic_sha256(
        definition
    )
    if definition_sha256 != bundle.fixture_definition_sha256:
        raise ProcessLifecycleDeltaError(
            "fixture definition digest differs"
        )
    if type(bundle.oracle) is not ProcessLifecycleDeltaOracle:
        raise ProcessLifecycleDeltaError("oracle has wrong exact type")
    bundle.oracle.__post_init__()
    parameters = ProcessLifecycleDeltaParameters(
        bundle.oracle.snapshot_pair,
        bundle.oracle.selection_policy,
    )
    primary = derive_process_lifecycle_delta_state(definition, parameters)
    reference = reference_process_lifecycle_delta_state(
        definition, parameters
    )
    if (
        primary != reference
        or primary != bundle.oracle.state
        or definition.expected_files != _expected_files()
    ):
        raise ProcessLifecycleDeltaError(
            "fixture output policy or oracle differs"
        )
    if type(bundle.descriptor) is not OpaqueFixtureDescriptor:
        raise ProcessLifecycleDeltaError(
            "descriptor has wrong exact type"
        )
    bundle.descriptor.__post_init__()
    fixture_sha256 = compute_bound_fixture_sha256(
        task_contract_sha256=bundle.task_contract_sha256,
        profile_sha256=bundle.profile_sha256,
        fixture_definition_sha256=definition_sha256,
        oracle_sha256=bundle.oracle.oracle_sha256,
    )
    if (
        bundle.descriptor.fixture_sha256 != fixture_sha256
        or bundle.descriptor.fixture_id != f"fx-{fixture_sha256[:24]}"
        or bundle.descriptor.task_contract_sha256
        != bundle.task_contract_sha256
    ):
        raise ProcessLifecycleDeltaError(
            "descriptor binding differs"
        )


def verify_process_lifecycle_delta_fixture_bundle(bundle: object) -> bool:
    try:
        validate_process_lifecycle_delta_fixture_bundle(
            bundle  # type: ignore[arg-type]
        )
    except (
        AttributeError,
        ProcessLifecycleDeltaError,
        TypeError,
        ValueError,
    ):
        return False
    return True


def _validate_task_profile(
    task: object,
    profile: object,
) -> tuple[ProcessLifecycleDeltaTask, ExecutableFixtureProfile]:
    if type(task) is not ProcessLifecycleDeltaTask:
        raise ProcessLifecycleDeltaError("task has wrong exact type")
    if type(profile) is not ExecutableFixtureProfile:
        raise ProcessLifecycleDeltaError("profile has wrong exact type")
    try:
        task.__post_init__()
        rebuilt = ExecutableFixtureProfile(
            profile.profile_id,
            profile.cases,
            profile.profile_sha256,
            profile.profile_version,
            profile.public_method_development,
            profile.sealed,
            profile.candidate_execution_authorized,
            profile.model_selection_eligible,
            profile.claim_authorized,
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise ProcessLifecycleDeltaError(
            "task/profile reconstruction failed"
        ) from exc
    if rebuilt not in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
        raise ProcessLifecycleDeltaError(
            "profile is outside public method development"
        )
    return task, profile


def _construct_process_lifecycle_delta_fixture_bundle(
    task: ProcessLifecycleDeltaTask,
    profile: ExecutableFixtureProfile,
) -> ProcessLifecycleDeltaFixtureBundle:
    task, profile = _validate_task_profile(task, profile)
    inputs = _fixture_inputs(profile)
    provisional = FixtureDefinition(
        f"fixture.{task.task_id}.{profile.profile_id}",
        inputs,
        (),
    )
    primary = derive_process_lifecycle_delta_state(
        provisional, task.parameters
    )
    reference = reference_process_lifecycle_delta_state(
        provisional, task.parameters
    )
    if primary != reference:
        raise ProcessLifecycleDeltaError(
            "independent lifecycle derivations disagree"
        )
    definition = FixtureDefinition(
        provisional.fixture_id,
        inputs,
        _expected_files(),
    )
    if (
        derive_process_lifecycle_delta_state(
            definition, task.parameters
        )
        != primary
        or reference_process_lifecycle_delta_state(
            definition, task.parameters
        )
        != reference
    ):
        raise ProcessLifecycleDeltaError(
            "final output policy changed lifecycle semantics"
        )
    oracle = ProcessLifecycleDeltaOracle(
        primary,
        task.parameters.snapshot_pair,
        task.parameters.selection_policy,
        _oracle_sha256(primary, task.parameters),
    )
    definition_sha256 = compute_fixture_definition_semantic_sha256(
        definition
    )
    fixture_sha256 = compute_bound_fixture_sha256(
        task_contract_sha256=task.task_contract_sha256,
        profile_sha256=profile.profile_sha256,
        fixture_definition_sha256=definition_sha256,
        oracle_sha256=oracle.oracle_sha256,
    )
    return ProcessLifecycleDeltaFixtureBundle(
        task.task_contract_sha256,
        profile.profile_sha256,
        definition,
        definition_sha256,
        oracle,
        OpaqueFixtureDescriptor(
            f"fx-{fixture_sha256[:24]}",
            fixture_sha256,
            task.task_contract_sha256,
        ),
    )


def build_process_lifecycle_delta_fixture_bundle(
    task: ProcessLifecycleDeltaTask,
    profile: ExecutableFixtureProfile,
) -> ProcessLifecycleDeltaFixtureBundle:
    selected_task, selected_profile = _validate_task_profile(task, profile)
    bundle = _construct_process_lifecycle_delta_fixture_bundle(
        selected_task, selected_profile
    )
    index = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES.index(selected_profile)
    if selected_task.fixtures[index] != bundle.descriptor:
        raise ProcessLifecycleDeltaError(
            "task descriptor differs from reconstructed fixture"
        )
    return bundle


def validate_process_lifecycle_delta_fixture_for_task_profile(
    task: ProcessLifecycleDeltaTask,
    profile: ExecutableFixtureProfile,
    bundle: ProcessLifecycleDeltaFixtureBundle,
) -> None:
    selected_task, selected_profile = _validate_task_profile(task, profile)
    validate_process_lifecycle_delta_fixture_bundle(bundle)
    expected = _construct_process_lifecycle_delta_fixture_bundle(
        selected_task, selected_profile
    )
    if expected != bundle:
        raise ProcessLifecycleDeltaError(
            "bundle differs from deterministic reconstruction"
        )
    index = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES.index(selected_profile)
    if selected_task.fixtures[index] != bundle.descriptor:
        raise ProcessLifecycleDeltaError(
            "public descriptor differs from private binding"
        )


def verify_process_lifecycle_delta_fixture_for_task_profile(
    task: object,
    profile: object,
    bundle: object,
) -> bool:
    try:
        validate_process_lifecycle_delta_fixture_for_task_profile(
            task,  # type: ignore[arg-type]
            profile,  # type: ignore[arg-type]
            bundle,  # type: ignore[arg-type]
        )
    except (
        AttributeError,
        ProcessLifecycleDeltaError,
        TypeError,
        ValueError,
    ):
        return False
    return True


def _source_commitment(
    definition: FixtureDefinition,
) -> str:
    records: list[dict[str, object]] = []
    for item in sorted(
        definition.inputs, key=lambda entry: entry.path.encode("utf-8")
    ):
        if type(item) is InputFile:
            records.append(
                {
                    "kind": "file",
                    "path": item.path,
                    "mode": item.mode,
                    "mtime": item.mtime_seconds,
                    "bytes": len(item.content),
                    "sha256": sha256(item.content).hexdigest(),
                }
            )
        elif type(item) is InputSymlink:
            records.append(
                {
                    "kind": "symlink",
                    "path": item.path,
                    "target": item.target,
                }
            )
        else:
            records.append(
                {
                    "kind": "hardlink",
                    "path": item.path,
                    "target": item.target,
                }
            )
    return domain_sha256(
        "cbds.process-lifecycle-delta.source-tree.v1", records
    )


def _behavioral_outcome_sha256(
    state: ProcessLifecycleDeltaState,
) -> str:
    if (
        type(state) is not ProcessLifecycleDeltaState
        or type(state.content) is not bytes
        or len(state.content) > PROCESS_LIFECYCLE_DELTA_OUTPUT_MAXIMUM_BYTES
    ):
        raise ProcessLifecycleDeltaError(
            "behavioral outcome is not bounded canonical output"
        )
    return domain_sha256(
        "cbds.process-lifecycle-delta.behavioral-outcome.v2",
        {
            "content_sha256": sha256(state.content).hexdigest(),
            "content_bytes": len(state.content),
        },
    )


def _discrimination_signature(
    bundle: ProcessLifecycleDeltaFixtureBundle,
) -> tuple[str, str]:
    return (
        _source_commitment(bundle.definition),
        _behavioral_outcome_sha256(bundle.oracle.state),
    )


def compute_process_lifecycle_delta_discrimination_sha256(
    tasks: tuple[ProcessLifecycleDeltaTask, ...],
) -> str:
    expected = tuple(
        (snapshot_pair, policy)
        for snapshot_pair in PROCESS_LIFECYCLE_DELTA_SNAPSHOT_PAIRS
        for policy in PROCESS_LIFECYCLE_DELTA_SELECTION_POLICIES
    )
    if (
        type(tasks) is not tuple
        or len(tasks) != 20
        or any(type(task) is not ProcessLifecycleDeltaTask for task in tasks)
        or tuple(
            (
                task.parameters.snapshot_pair,
                task.parameters.selection_policy,
            )
            for task in tasks
        )
        != expected
    ):
        raise ProcessLifecycleDeltaError(
            "discrimination requires canonical 20-cell task order"
        )
    profile_signatures = tuple(
        (
            profile,
            tuple(
                _discrimination_signature(
                    _construct_process_lifecycle_delta_fixture_bundle(
                        task, profile
                    )
                )
                for task in tasks
            ),
        )
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
    )
    if any(
        len(set(signatures)) != 20
        for _, signatures in profile_signatures
    ):
        raise ProcessLifecycleDeltaError(
            "task grid is not 20/20 discriminable in every profile"
        )
    return domain_sha256(
        "cbds.process-lifecycle-delta.discrimination-evidence.v2",
        {
            "family_id": PROCESS_LIFECYCLE_DELTA_FAMILY_ID,
            "profile_count": len(profile_signatures),
            "profiles": [
                {
                    "profile_sha256": profile.profile_sha256,
                    "signature_count": len(signatures),
                    "outcomes": [
                        {
                            "source_sha256": source,
                            "output_sha256": output,
                        }
                        for source, output in signatures
                    ],
                }
                for profile, signatures in profile_signatures
            ],
        },
    )


def build_process_lifecycle_delta_tasks() -> tuple[
    ProcessLifecycleDeltaTask, ...
]:
    tasks: list[ProcessLifecycleDeltaTask] = []
    signatures: list[list[tuple[str, str]]] = [
        [] for _ in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
    ]
    for snapshot_pair in PROCESS_LIFECYCLE_DELTA_SNAPSHOT_PAIRS:
        for policy in PROCESS_LIFECYCLE_DELTA_SELECTION_POLICIES:
            bootstrap = _bootstrap_task(
                ProcessLifecycleDeltaParameters(snapshot_pair, policy)
            )
            bundles = tuple(
                _construct_process_lifecycle_delta_fixture_bundle(
                    bootstrap, profile
                )
                for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
            )
            task = replace(
                bootstrap,
                fixtures=tuple(bundle.descriptor for bundle in bundles),
            )
            task.__post_init__()
            tasks.append(task)
            for index, bundle in enumerate(bundles):
                if not bundle.oracle.state.content:
                    raise ProcessLifecycleDeltaError(
                        "task cell has an empty profile outcome"
                    )
                signatures[index].append(
                    _discrimination_signature(bundle)
                )
    selected = tuple(tasks)
    if (
        len(selected) != 20
        or len({task.task_id for task in selected}) != 20
        or len({task.task_contract_sha256 for task in selected}) != 20
        or len({task.graph_sha256 for task in selected}) != 20
        or any(len(set(profile)) != 20 for profile in signatures)
    ):
        raise ProcessLifecycleDeltaError(
            "task grid is not 20/20 discriminable in every profile"
        )
    return selected


def compute_process_lifecycle_delta_proved_output_bound() -> int:
    """Mechanically bound worst-case escaping-heavy transition JSONL."""

    # argv and cgroup strings admit non-NUL C0 controls.  Canonical JSON
    # renders each such one-byte input scalar as a six-byte ``\u00xx``
    # escape, which is stricter than quote/backslash doubling.
    before_argv = tuple(["\x01" * 128] * 4 + [""] * 28)
    after_argv = tuple(["\x02" * 128] * 4 + [""] * 28)
    before_cgroups = tuple(
        sorted(
            (
                "/" + chr(1 + index) + "\x01" * 126
                for index in range(4)
            ),
            key=lambda item: item.encode("utf-8"),
        )
    )
    after_markers = ("\x05", "\x06", "\x07", "\x0b")
    after_cgroups = tuple(
        sorted(
            (
                "/" + marker + "\x02" * 126
                for marker in after_markers
            ),
            key=lambda item: item.encode("utf-8"),
        )
    )
    pair = ProcessPairMetadata(
        "ffffffff-ffff-ffff-ffff-ffffffffffff",
        PROCESS_LIFECYCLE_DELTA_MAXIMUM_INTEGER - 2,
        PROCESS_LIFECYCLE_DELTA_MAXIMUM_INTEGER,
        PROCESS_LIFECYCLE_DELTA_MAXIMUM_INTEGER,
        PROCESS_LIFECYCLE_DELTA_MAXIMUM_CPU_MILLI_PERCENT,
    )
    before = ProcessProjection(
        "complete-synthetic-proc",
        "\\" * PROCESS_LIFECYCLE_DELTA_COMM_MAXIMUM_UTF8_BYTES,
        PROCESS_LIFECYCLE_DELTA_MAXIMUM_CPU_MILLI_PERCENT,
        PROCESS_LIFECYCLE_DELTA_MAXIMUM_PID,
        PROCESS_LIFECYCLE_DELTA_MAXIMUM_PID,
        PROCESS_LIFECYCLE_DELTA_MAXIMUM_INTEGER,
        PROCESS_LIFECYCLE_DELTA_MAXIMUM_INTEGER - 2,
        "S",
        PROCESS_LIFECYCLE_DELTA_MAXIMUM_UID,
        before_argv,
        before_cgroups,
    )
    after_same = ProcessProjection(
        "complete-synthetic-proc",
        '"' * PROCESS_LIFECYCLE_DELTA_COMM_MAXIMUM_UTF8_BYTES,
        PROCESS_LIFECYCLE_DELTA_MAXIMUM_CPU_MILLI_PERCENT - 1,
        PROCESS_LIFECYCLE_DELTA_MAXIMUM_PID,
        PROCESS_LIFECYCLE_DELTA_MAXIMUM_PID - 1,
        PROCESS_LIFECYCLE_DELTA_MAXIMUM_INTEGER - 1,
        PROCESS_LIFECYCLE_DELTA_MAXIMUM_INTEGER - 2,
        "R",
        PROCESS_LIFECYCLE_DELTA_MAXIMUM_UID - 1,
        after_argv,
        after_cgroups,
    )
    after_started = replace(
        after_same,
        cpu_milli_percent=(
            PROCESS_LIFECYCLE_DELTA_MAXIMUM_CPU_MILLI_PERCENT
        ),
        start_ticks=PROCESS_LIFECYCLE_DELTA_MAXIMUM_INTEGER - 1,
    )
    changed = _changed_event(
        pair,
        before,
        after_same,
        _projection_changed_fields(before, after_same),
        _projection_crossings(before, after_same, pair),
    )
    started = _started_event(pair, after_started)
    exited = _exited_event(pair, before)
    maximum_changed_total = (
        len(_canonical_json(changed.to_value()))
        * PROCESS_LIFECYCLE_DELTA_MAXIMUM_PROCESSES
    )
    maximum_disjoint_total = (
        len(_canonical_json(started.to_value()))
        + len(_canonical_json(exited.to_value()))
    ) * PROCESS_LIFECYCLE_DELTA_MAXIMUM_PROCESSES
    if (
        maximum_changed_total
        != PROCESS_LIFECYCLE_DELTA_PROOF_CHANGED_OUTPUT_BYTES
        or maximum_disjoint_total
        != PROCESS_LIFECYCLE_DELTA_PROOF_DISJOINT_OUTPUT_BYTES
        or max(maximum_changed_total, maximum_disjoint_total)
        > PROCESS_LIFECYCLE_DELTA_OUTPUT_MAXIMUM_BYTES
        or PROCESS_LIFECYCLE_DELTA_PROVED_MAXIMUM_TOTAL_OUTPUT_BYTES
        > MAX_TOTAL_BYTES
    ):
        raise ProcessLifecycleDeltaError(
            "mechanical output proof exceeds declared ceiling"
        )
    return PROCESS_LIFECYCLE_DELTA_PROVED_MAXIMUM_TOTAL_OUTPUT_BYTES


def materialize_process_lifecycle_delta_fixture(
    task: ProcessLifecycleDeltaTask,
    profile: ExecutableFixtureProfile,
    bundle: ProcessLifecycleDeltaFixtureBundle,
    workspace: str | os.PathLike[str],
) -> WorkspaceHandle:
    validate_process_lifecycle_delta_fixture_for_task_profile(
        task, profile, bundle
    )
    return materialize_fixture(bundle.definition, workspace)


def verify_process_lifecycle_delta_workspace(
    task: ProcessLifecycleDeltaTask,
    profile: ExecutableFixtureProfile,
    bundle: ProcessLifecycleDeltaFixtureBundle,
    handle: WorkspaceHandle,
) -> bool:
    """Verify exact final JSONL and preserved authenticated inputs."""

    if type(handle) is not WorkspaceHandle:
        return False
    try:
        validate_process_lifecycle_delta_fixture_for_task_profile(
            task, profile, bundle
        )
        baseline = handle.baseline
        if (
            baseline.fixture_id != bundle.definition.fixture_id
            or baseline.fixture_sha256
            != bundle.definition.fixture_sha256
            or handle.expected_files != bundle.definition.expected_files
            or handle.expected_symlinks
            or baseline.output_scaffold_entries
        ):
            return False
        primary = derive_process_lifecycle_delta_state(
            bundle.definition, task.parameters
        )
        reference = reference_process_lifecycle_delta_state(
            bundle.definition, task.parameters
        )
        if primary != reference or primary != bundle.oracle.state:
            return False

        input_scan = handle.scan_inputs()
        if (
            input_scan.scope != "inputs"
            or input_scan.baseline_sha256 != baseline.baseline_sha256
            or input_scan.entries != baseline.input_entries
        ):
            return False
        handle.validate_input_object_identities(input_scan)

        output_scan = handle.scan_outputs()
        output_entries = validate_expected_output_policy(
            bundle.definition, output_scan
        )
        if (
            len(output_entries) != 1
            or output_entries[0].path != PROCESS_LIFECYCLE_DELTA_OUTPUT
            or output_entries[0].mode
            != PROCESS_LIFECYCLE_DELTA_OUTPUT_MODE
            or output_entries[0].link_count != 1
            or output_entries[0].hardlink_group_sha256 is not None
        ):
            return False
        observed = handle.read_output_bytes(
            output_scan, PROCESS_LIFECYCLE_DELTA_OUTPUT
        )
        if (
            parse_process_lifecycle_delta_output(
                observed, task.parameters, primary.pair
            )
            != primary.content
        ):
            return False

        final_input_scan = handle.scan_inputs()
        handle.validate_input_object_identities(final_input_scan)
        final_output_scan = handle.scan_outputs()
        return (
            final_input_scan == input_scan
            and final_input_scan.entries == baseline.input_entries
            and final_output_scan == output_scan
        )
    except (
        ExecutableWorkspaceError,
        ProcessLifecycleDeltaError,
        OSError,
        TypeError,
        ValueError,
    ):
        return False


__all__ = [
    "PROCESS_LIFECYCLE_DELTA_ALLOWED_TOOLS",
    "PROCESS_LIFECYCLE_DELTA_ATOMICITY_OBSERVED",
    "PROCESS_LIFECYCLE_DELTA_CANDIDATE_EXIT_STATUS_OBSERVED",
    "PROCESS_LIFECYCLE_DELTA_COMM_MAXIMUM_UTF8_BYTES",
    "PROCESS_LIFECYCLE_DELTA_FAMILY_ID",
    "PROCESS_LIFECYCLE_DELTA_FILESYSTEM_IDENTITY",
    "PROCESS_LIFECYCLE_DELTA_FINAL_OUTPUT_OBSERVED",
    "PROCESS_LIFECYCLE_DELTA_GENERATOR_VERSION",
    "PROCESS_LIFECYCLE_DELTA_INPUT_MAXIMUM_BYTES",
    "PROCESS_LIFECYCLE_DELTA_INPUT_PRESERVATION_OBSERVED",
    "PROCESS_LIFECYCLE_DELTA_JSON_MAXIMUM_DEPTH",
    "PROCESS_LIFECYCLE_DELTA_LIVE_PROC_OBSERVED",
    "PROCESS_LIFECYCLE_DELTA_MAXIMUM_ARRAY_ITEMS",
    "PROCESS_LIFECYCLE_DELTA_MAXIMUM_CPU_MILLI_PERCENT",
    "PROCESS_LIFECYCLE_DELTA_MAXIMUM_INTEGER",
    "PROCESS_LIFECYCLE_DELTA_MAXIMUM_PID",
    "PROCESS_LIFECYCLE_DELTA_MAXIMUM_PROCESSES",
    "PROCESS_LIFECYCLE_DELTA_MAXIMUM_UNION_PROCESSES",
    "PROCESS_LIFECYCLE_DELTA_MAXIMUM_UID",
    "PROCESS_LIFECYCLE_DELTA_OUTPUT",
    "PROCESS_LIFECYCLE_DELTA_OUTPUT_IDENTITY",
    "PROCESS_LIFECYCLE_DELTA_OUTPUT_MAXIMUM_BYTES",
    "PROCESS_LIFECYCLE_DELTA_PAIR_INPUT",
    "PROCESS_LIFECYCLE_DELTA_PAIR_MAXIMUM_BYTES",
    "PROCESS_LIFECYCLE_DELTA_PROCESS_ACTIONS_OBSERVED",
    "PROCESS_LIFECYCLE_DELTA_PROOF_CHANGED_OUTPUT_BYTES",
    "PROCESS_LIFECYCLE_DELTA_PROOF_DISJOINT_OUTPUT_BYTES",
    "PROCESS_LIFECYCLE_DELTA_PROVED_MAXIMUM_TOTAL_OUTPUT_BYTES",
    "PROCESS_LIFECYCLE_DELTA_READ_SCOPE_OBSERVED",
    "PROCESS_LIFECYCLE_DELTA_SELECTION_POLICIES",
    "PROCESS_LIFECYCLE_DELTA_SIDECAR_ITEM_MAXIMUM_UTF8_BYTES",
    "PROCESS_LIFECYCLE_DELTA_SIDECAR_MAXIMUM_BYTES",
    "PROCESS_LIFECYCLE_DELTA_SIDECAR_TOTAL_MAXIMUM_UTF8_BYTES",
    "PROCESS_LIFECYCLE_DELTA_SNAPSHOT_PAIRS",
    "PROCESS_LIFECYCLE_DELTA_SOURCE_ROOT",
    "PROCESS_LIFECYCLE_DELTA_STATUS_MAXIMUM_BYTES",
    "PROCESS_LIFECYCLE_DELTA_TOOL_HISTORY_OBSERVED",
    "PROCESS_LIFECYCLE_DELTA_TRANSIENT_STATE_OBSERVED",
    "PROCESS_LIFECYCLE_DELTA_VERIFIER_IDENTITY",
    "PROCESS_LIFECYCLE_DELTA_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE",
    "PROCESS_LIFECYCLE_DELTA_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE",
    "ProcessLifecycleDeltaError",
    "ProcessLifecycleDeltaFixtureBundle",
    "ProcessLifecycleDeltaOracle",
    "ProcessLifecycleDeltaParameters",
    "ProcessLifecycleDeltaState",
    "ProcessLifecycleDeltaTask",
    "ProcessLifecycleEvent",
    "ProcessPairMetadata",
    "ProcessProjection",
    "ThresholdCrossings",
    "build_process_lifecycle_delta_fixture_bundle",
    "build_process_lifecycle_delta_tasks",
    "compute_process_lifecycle_delta_discrimination_sha256",
    "compute_process_lifecycle_delta_proved_output_bound",
    "compute_process_lifecycle_delta_task_sha256",
    "derive_process_lifecycle_delta_state",
    "materialize_process_lifecycle_delta_fixture",
    "parse_process_lifecycle_delta_output",
    "process_lifecycle_delta_task_semantic_core",
    "reference_process_lifecycle_delta_state",
    "validate_process_lifecycle_delta_fixture_bundle",
    "validate_process_lifecycle_delta_fixture_for_task_profile",
    "verify_process_lifecycle_delta_fixture_bundle",
    "verify_process_lifecycle_delta_fixture_for_task_profile",
    "verify_process_lifecycle_delta_workspace",
]
