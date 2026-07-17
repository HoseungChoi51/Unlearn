"""Executable-static checksum classification and declarative repair plans.

The family reads one of four strict checksum-manifest encodings, classifies
each declaration against a no-follow asset leaf, and emits a batch-aware JSONL
plan under one of five policies.  Manifest multiplicity is semantic: exact
duplicates and same-path/different-digest records are retained.  Physical
manifest order is not semantic; output rows are ordered by raw UTF-8 path
bytes and then the declared digest.

This module never executes candidate code and never applies a repair.  Its
workspace verifier observes only a bounded final plan plus preserved inputs
under trusted quiescence.  A plan cannot prove that a repair, quarantine,
atomic publication, declared tool, read scope, or exit behavior occurred.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field, replace
from hashlib import sha256
import io
import json
import os
from pathlib import PurePosixPath
import re
from typing import Final, Literal, TypeAlias

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
    MAX_PATH_COMPONENT_UTF8_BYTES,
    MAX_PATH_UTF8_BYTES,
    ExecutableWorkspaceError,
    ExpectedFile,
    FixtureDefinition,
    InputFile,
    InputSymlink,
    WorkspaceHandle,
    materialize_fixture,
    validate_expected_output_policy,
)


CHECKSUM_REPAIR_PLAN_FAMILY_ID: Final[str] = "checksum-repair-plan"
CHECKSUM_REPAIR_PLAN_FILESYSTEM_IDENTITY: Final[str] = (
    "damaged-checksum-assets"
)
CHECKSUM_REPAIR_PLAN_OUTPUT_IDENTITY: Final[str] = (
    "ordered-checksum-repair-plan"
)
CHECKSUM_REPAIR_PLAN_GENERATOR_VERSION: Final[str] = "1.0.0"
CHECKSUM_REPAIR_PLAN_VERIFIER_IDENTITY: Final[str] = (
    "verify-checksum-repair-plan-v1"
)
CHECKSUM_REPAIR_PLAN_MANIFEST: Final[str] = "input/manifest.data"
CHECKSUM_REPAIR_PLAN_ASSET_ROOT: Final[PurePosixPath] = PurePosixPath(
    "input/assets"
)
CHECKSUM_REPAIR_PLAN_OUTPUT: Final[str] = "output/repair-plan.jsonl"
CHECKSUM_REPAIR_PLAN_OUTPUT_MODE: Final[int] = 0o644
CHECKSUM_REPAIR_PLAN_MANIFEST_MAXIMUM_BYTES: Final[int] = 64 * 1024
CHECKSUM_REPAIR_PLAN_MAXIMUM_RECORDS: Final[int] = 128
CHECKSUM_REPAIR_PLAN_ASSET_MAXIMUM_BYTES: Final[int] = 16 * 1024
CHECKSUM_REPAIR_PLAN_OUTPUT_MAXIMUM_BYTES: Final[int] = 256 * 1024
CHECKSUM_REPAIR_PLAN_ALLOWED_TOOLS: Final[tuple[str, ...]] = (
    "awk",
    "jq",
    "mkdir",
    "sha256sum",
    "sort",
)

# Honest observation and fixture-coverage boundaries.
CHECKSUM_REPAIR_PLAN_FINAL_PLAN_OBSERVED: Final[bool] = True
CHECKSUM_REPAIR_PLAN_INPUT_PRESERVATION_OBSERVED: Final[bool] = True
CHECKSUM_REPAIR_PLAN_REPAIR_EXECUTION_OBSERVED: Final[bool] = False
CHECKSUM_REPAIR_PLAN_QUARANTINE_EXECUTION_OBSERVED: Final[bool] = False
CHECKSUM_REPAIR_PLAN_ATOMICITY_OBSERVED: Final[bool] = False
CHECKSUM_REPAIR_PLAN_TOOL_HISTORY_OBSERVED: Final[bool] = False
CHECKSUM_REPAIR_PLAN_READ_SCOPE_OBSERVED: Final[bool] = False
CHECKSUM_REPAIR_PLAN_CANDIDATE_EXIT_STATUS_OBSERVED: Final[bool] = False
CHECKSUM_REPAIR_PLAN_DIRECTORY_PERMISSION_ERRORS_COVERED: Final[bool] = False
CHECKSUM_REPAIR_PLAN_SPECIAL_FILE_KINDS_COVERED: Final[bool] = False
CHECKSUM_REPAIR_PLAN_ANCESTOR_SYMLINKS_COVERED: Final[bool] = False
CHECKSUM_REPAIR_PLAN_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE: Final[
    bool
] = True
CHECKSUM_REPAIR_PLAN_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE: Final[
    bool
] = False

ManifestLayout: TypeAlias = Literal[
    "sha256sum-text", "jsonl", "csv", "nul-pairs"
]
RepairPolicy: TypeAlias = Literal[
    "report-only",
    "replace-digest",
    "drop-missing",
    "quarantine-mismatch",
    "strict-reject",
]
RepairStatus: TypeAlias = Literal[
    "ok",
    "checksum-mismatch",
    "missing",
    "symlink",
    "directory",
    "unreadable",
]
RepairAction: TypeAlias = Literal[
    "report",
    "keep",
    "replace-digest",
    "drop-record",
    "quarantine-asset",
    "unresolved",
    "reject-batch",
]
PlanState: TypeAlias = Literal[
    "clean", "reported", "planned", "partial", "rejected"
]

CHECKSUM_REPAIR_PLAN_MANIFEST_LAYOUTS: Final[tuple[ManifestLayout, ...]] = (
    "sha256sum-text",
    "jsonl",
    "csv",
    "nul-pairs",
)
CHECKSUM_REPAIR_PLAN_REPAIR_POLICIES: Final[tuple[RepairPolicy, ...]] = (
    "report-only",
    "replace-digest",
    "drop-missing",
    "quarantine-mismatch",
    "strict-reject",
)
CHECKSUM_REPAIR_PLAN_STATUSES: Final[tuple[RepairStatus, ...]] = (
    "ok",
    "checksum-mismatch",
    "missing",
    "symlink",
    "directory",
    "unreadable",
)
CHECKSUM_REPAIR_PLAN_ACTIONS: Final[tuple[RepairAction, ...]] = (
    "report",
    "keep",
    "replace-digest",
    "drop-record",
    "quarantine-asset",
    "unresolved",
    "reject-batch",
)
CHECKSUM_REPAIR_PLAN_STATES: Final[tuple[PlanState, ...]] = (
    "clean",
    "reported",
    "planned",
    "partial",
    "rejected",
)

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_TASK_ID_RE: Final[re.Pattern[str]] = re.compile(r"mds-[0-9a-f]{24}\Z")
_HEADER_KEYS: Final[frozenset[str]] = frozenset(
    {
        "record",
        "policy",
        "state",
        "entry_count",
        "issue_count",
        "action_count",
        "unresolved_count",
    }
)
_ENTRY_KEYS: Final[frozenset[str]] = frozenset(
    {
        "record",
        "path",
        "status",
        "action",
        "declared_sha256",
        "actual_sha256",
        "action_argument",
    }
)
_MUTATING_ACTIONS: Final[frozenset[str]] = frozenset(
    {"replace-digest", "drop-record", "quarantine-asset"}
)


class ChecksumRepairPlanError(ValueError):
    """Raised when a task, fixture, plan, or final state fails closed."""


def _raw(value: str) -> bytes:
    return value.encode("utf-8")


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def _closed_text(
    value: object, allowed: tuple[str, ...], field_name: str
) -> str:
    if type(value) is not str or value not in allowed:
        raise ChecksumRepairPlanError(
            f"{field_name} is outside the closed family contract"
        )
    return value


def _validate_relative_asset_path(value: object) -> str:
    if type(value) is not str or not value:
        raise ChecksumRepairPlanError("asset path is empty or non-text")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ChecksumRepairPlanError("asset path is not strict UTF-8") from exc
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or not path.parts
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or len(encoded) > MAX_PATH_UTF8_BYTES
        or any(
            len(part.encode("utf-8")) > MAX_PATH_COMPONENT_UTF8_BYTES
            for part in path.parts
        )
    ):
        raise ChecksumRepairPlanError(
            "asset path is not a canonical safe relative path"
        )
    return value


@dataclass(frozen=True, slots=True)
class ChecksumRepairPlanParameters:
    manifest_layout: ManifestLayout
    repair_policy: RepairPolicy

    def __post_init__(self) -> None:
        if type(self) is not ChecksumRepairPlanParameters:
            raise ChecksumRepairPlanError("parameters have wrong exact type")
        _closed_text(
            self.manifest_layout,
            CHECKSUM_REPAIR_PLAN_MANIFEST_LAYOUTS,
            "manifest_layout",
        )
        _closed_text(
            self.repair_policy,
            CHECKSUM_REPAIR_PLAN_REPAIR_POLICIES,
            "repair_policy",
        )

    def to_record(self) -> dict[str, str]:
        self.__post_init__()
        return {
            "parameter_type": CHECKSUM_REPAIR_PLAN_FAMILY_ID,
            "manifest_layout": self.manifest_layout,
            "repair_policy": self.repair_policy,
        }


_LAYOUT_TEXT: Final[dict[ManifestLayout, str]] = {
    "sha256sum-text": (
        "strict UTF-8 records `SHA256`, exactly two ASCII spaces, `PATH`, "
        "and LF; the restricted form has no GNU escape marker, binary marker, "
        "blank row, CR, or missing final LF"
    ),
    "jsonl": (
        "strict UTF-8 JSON Lines objects with exactly string members `path` "
        "and `sha256`, no duplicate keys or blank rows, and an LF after every row"
    ),
    "csv": (
        "strict UTF-8 RFC 4180 CSV with exact header `path,sha256`, exactly "
        "two fields per data record, and CRLF after every record"
    ),
    "nul-pairs": (
        "an exact nonempty sequence of UTF-8 `PATH`, NUL, ASCII `SHA256`, "
        "NUL pairs with no partial or trailing field"
    ),
}

_POLICY_TEXT: Final[dict[RepairPolicy, str]] = {
    "report-only": (
        "assign action `report` to every entry and make no repair proposal"
    ),
    "replace-digest": (
        "keep `ok`; for `checksum-mismatch`, propose `replace-digest` with "
        "the actual digest; mark every other issue `unresolved`"
    ),
    "drop-missing": (
        "keep `ok`; for `missing`, propose `drop-record`; mark every other "
        "issue `unresolved`"
    ),
    "quarantine-mismatch": (
        "keep `ok`; for `checksum-mismatch`, propose `quarantine-asset` with "
        "logical destination `quarantine/PATH`; mark every other issue `unresolved`"
    ),
    "strict-reject": (
        "if any entry is not `ok`, assign `reject-batch` to every entry and "
        "reject the whole plan; otherwise keep every entry"
    ),
}


def _task_contract(
    parameters: ChecksumRepairPlanParameters,
) -> tuple[str, NormalizedSemanticGraph]:
    prompt = f"""Write one Bash program that operates only in the current workspace.

Read `input/manifest.data` as {_LAYOUT_TEXT[parameters.manifest_layout]}.
Every manifest is well formed, nonempty, at most 65536 bytes and 128 physical
records.  SHA256 is exactly 64 lowercase hexadecimal characters.  PATH is a
nonempty canonical strict-UTF-8 relative POSIX path below `input/assets/`: it
has no absolute, empty, dot, dot-dot, backslash, ASCII-control, or DEL
component, is at most 4096 UTF-8 bytes, and each component is at most 255.
Retain record multiplicity, including exact duplicates and same-path records
with different digests.  Physical manifest order is nonsemantic.

Inspect each named leaf without following symbolic links or resolving through
a symbolic-link ancestor.  Scored fixtures contain no named path below a
symbolic-link ancestor and no special file kinds.  Classify it as `missing`,
`symlink`, `directory`, or `unreadable`; otherwise SHA-256 its readable regular
bytes and classify it `ok` or `checksum-mismatch`.  Readability means at least
one of mode bits 0444 is set.  Scored regular targets with any read bit also
have owner-read set, and unreadable targets have no read bit.  Supply the
actual lowercase digest only for `ok` and `checksum-mismatch`; otherwise use
JSON null.

For policy `{parameters.repair_policy}`, {_POLICY_TEXT[parameters.repair_policy]}.
Only `replace-digest`, `drop-record`, and `quarantine-asset` count as repair
actions.  Only `unresolved` counts as unresolved.  If issue count is zero,
state is `clean`; otherwise report-only is `reported`, strict-reject is
`rejected`, and a targeted policy is `planned` exactly when unresolved count
is zero and `partial` otherwise.

Sort entries by raw PATH UTF-8 bytes under `LC_ALL=C`, then by declared digest
ASCII bytes, retaining ties.  Write strict-UTF-8 `output/repair-plan.jsonl`
with LF after every JSON object.  Its first object has exactly members:
`record`=`plan`, `policy`, `state`, `entry_count`, `issue_count`,
`action_count`, and `unresolved_count`.  Then write one object per entry with
exactly members: `record`=`entry`, `path`, `status`, `action`,
`declared_sha256`, `actual_sha256`, and `action_argument`.  The argument is
the actual digest only for `replace-digest`, `quarantine/PATH` only for
`quarantine-asset`, and JSON null otherwise.

This is only a declarative plan.  Preserve every input path, kind, byte,
permission mode, modification time, link count, and symlink target.  Do not
rewrite the manifest, apply a repair, or create a quarantine tree.  Leave only
the required real mode-0755 `output/` and an independent mode-0644,
link-count-one report.  The final-state check does not prove repair,
quarantine, atomicity, tool, read-scope, exit-status, transient-state, or
global-quiescence history.  Use only Bash built-ins plus `awk`, `jq`, `mkdir`,
`sha256sum`, and `sort`.
"""
    graph = NormalizedSemanticGraph(
        nodes=(
            OperatorNode(
                "parse_checksum_repair_manifest",
                (
                    f"layout:{parameters.manifest_layout}",
                    "path:input/manifest.data",
                    "multiplicity:retain",
                ),
            ),
            OperatorNode(
                "classify_checksum_assets",
                (
                    "root:input/assets",
                    "no-follow:true",
                    "digest:sha256",
                ),
            ),
            OperatorNode(
                "select_checksum_repair_actions",
                (
                    f"policy:{parameters.repair_policy}",
                    "strict-scope:whole-batch",
                ),
            ),
            OperatorNode(
                "sort_repair_plan_entries",
                ("primary:path-raw-utf8", "secondary:declared-digest"),
            ),
            OperatorNode(
                "emit_checksum_repair_plan",
                (
                    "path:output/repair-plan.jsonl",
                    "format:strict-jsonl",
                ),
            ),
        ),
        dependencies=((0, 1), (1, 2), (2, 3), (3, 4)),
    )
    return prompt, graph


def _validate_graph(graph: object) -> NormalizedSemanticGraph:
    if type(graph) is not NormalizedSemanticGraph:
        raise ChecksumRepairPlanError("graph has wrong exact type")
    try:
        rebuilt = NormalizedSemanticGraph(
            nodes=tuple(
                OperatorNode(node.name, node.parameters)
                for node in graph.nodes
                if type(node) is OperatorNode
            ),
            dependencies=graph.dependencies,
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise ChecksumRepairPlanError("graph reconstruction failed") from exc
    if rebuilt != graph or len(rebuilt.nodes) != len(graph.nodes):
        raise ChecksumRepairPlanError("graph is noncanonical")
    return graph


def checksum_repair_plan_task_semantic_core(
    parameters: ChecksumRepairPlanParameters,
    prompt: str,
    graph: NormalizedSemanticGraph,
) -> dict[str, object]:
    if type(parameters) is not ChecksumRepairPlanParameters:
        raise ChecksumRepairPlanError("parameters have wrong exact type")
    parameters.__post_init__()
    expected_prompt, expected_graph = _task_contract(parameters)
    if (
        type(prompt) is not str
        or prompt != expected_prompt
        or _validate_graph(graph) != expected_graph
    ):
        raise ChecksumRepairPlanError("prompt or graph differs")
    return {
        "schema_version": EXECUTABLE_STATIC_SCHEMA_VERSION,
        "contract_version": EXECUTABLE_STATIC_CONTRACT_VERSION,
        "split_role": METHOD_DEVELOPMENT_SPLIT,
        "family_id": CHECKSUM_REPAIR_PLAN_FAMILY_ID,
        "family_version": EXECUTABLE_STATIC_FAMILY_VERSION,
        "generator_version": CHECKSUM_REPAIR_PLAN_GENERATOR_VERSION,
        "parameters": parameters.to_record(),
        "prompt": prompt,
        "graph": graph.to_record(),
        "graph_sha256": graph.hash,
        "filesystem_identity": CHECKSUM_REPAIR_PLAN_FILESYSTEM_IDENTITY,
        "output_identity": CHECKSUM_REPAIR_PLAN_OUTPUT_IDENTITY,
        "allowed_tools": list(CHECKSUM_REPAIR_PLAN_ALLOWED_TOOLS),
        "public": True,
        "sealed": False,
        "candidate_execution_authorized": False,
        "model_selection_eligible": False,
        "claim_authorized": False,
    }


def compute_checksum_repair_plan_task_sha256(
    parameters: ChecksumRepairPlanParameters,
    prompt: str,
    graph: NormalizedSemanticGraph,
) -> str:
    return domain_sha256(
        "cbds.executable-static.task-contract.v1",
        checksum_repair_plan_task_semantic_core(parameters, prompt, graph),
    )


@dataclass(frozen=True, slots=True)
class ChecksumRepairPlanTask:
    task_id: str
    parameters: ChecksumRepairPlanParameters
    prompt: str
    graph: NormalizedSemanticGraph
    fixtures: tuple[OpaqueFixtureDescriptor, ...]
    task_contract_sha256: str
    family_id: str = CHECKSUM_REPAIR_PLAN_FAMILY_ID
    family_version: str = EXECUTABLE_STATIC_FAMILY_VERSION
    filesystem_identity: str = CHECKSUM_REPAIR_PLAN_FILESYSTEM_IDENTITY
    output_identity: str = CHECKSUM_REPAIR_PLAN_OUTPUT_IDENTITY
    allowed_tools: tuple[str, ...] = CHECKSUM_REPAIR_PLAN_ALLOWED_TOOLS
    split_role: str = METHOD_DEVELOPMENT_SPLIT
    public: bool = True
    sealed: bool = False
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        if (
            type(self) is not ChecksumRepairPlanTask
            or type(self.parameters) is not ChecksumRepairPlanParameters
            or self.family_id != CHECKSUM_REPAIR_PLAN_FAMILY_ID
            or self.family_version != EXECUTABLE_STATIC_FAMILY_VERSION
            or self.filesystem_identity
            != CHECKSUM_REPAIR_PLAN_FILESYSTEM_IDENTITY
            or self.output_identity != CHECKSUM_REPAIR_PLAN_OUTPUT_IDENTITY
            or self.allowed_tools != CHECKSUM_REPAIR_PLAN_ALLOWED_TOOLS
            or self.split_role != METHOD_DEVELOPMENT_SPLIT
            or self.public is not True
            or self.sealed is not False
            or self.candidate_execution_authorized is not False
            or self.model_selection_eligible is not False
            or self.claim_authorized is not False
        ):
            raise ChecksumRepairPlanError("task metadata is invalid")
        expected = compute_checksum_repair_plan_task_sha256(
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
            or any(type(item) is not OpaqueFixtureDescriptor for item in self.fixtures)
        ):
            raise ChecksumRepairPlanError("task identity is invalid")
        for descriptor in self.fixtures:
            descriptor.__post_init__()
        if (
            len({item.fixture_id for item in self.fixtures}) != len(self.fixtures)
            or any(
                item.task_contract_sha256 != expected for item in self.fixtures
            )
        ):
            raise ChecksumRepairPlanError("task descriptor binding is invalid")

    @property
    def graph_sha256(self) -> str:
        self.__post_init__()
        return self.graph.hash

    def to_public_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            **checksum_repair_plan_task_semantic_core(
                self.parameters, self.prompt, self.graph
            ),
            "task_id": self.task_id,
            "task_contract_sha256": self.task_contract_sha256,
            "fixtures": [item.to_public_record() for item in self.fixtures],
        }


def _bootstrap_descriptors(
    task_contract_sha256: str,
) -> tuple[OpaqueFixtureDescriptor, ...]:
    values: list[OpaqueFixtureDescriptor] = []
    for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
        digest = domain_sha256(
            "cbds.executable-static.fixture.v1",
            {
                "task_contract_sha256": task_contract_sha256,
                "profile_sha256": profile.profile_sha256,
            },
        )
        values.append(
            OpaqueFixtureDescriptor(
                f"fx-{digest[:24]}", digest, task_contract_sha256
            )
        )
    return tuple(values)


def _bootstrap_task(
    parameters: ChecksumRepairPlanParameters,
) -> ChecksumRepairPlanTask:
    prompt, graph = _task_contract(parameters)
    digest = compute_checksum_repair_plan_task_sha256(
        parameters, prompt, graph
    )
    return ChecksumRepairPlanTask(
        task_id_from_contract(digest),
        parameters,
        prompt,
        graph,
        _bootstrap_descriptors(digest),
        digest,
    )


def _strict_json_object(line: str) -> dict[str, object]:
    def hook(pairs: list[tuple[str, object]]) -> dict[str, object]:
        keys = [key for key, _value in pairs]
        if len(keys) != len(set(keys)):
            raise ChecksumRepairPlanError("JSON object has duplicate keys")
        return dict(pairs)

    try:
        value = json.loads(
            line,
            object_pairs_hook=hook,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ChecksumRepairPlanError(
                    f"JSON extension token is forbidden: {token}"
                )
            ),
        )
    except ChecksumRepairPlanError:
        raise
    except (
        json.JSONDecodeError,
        UnicodeError,
        RecursionError,
        ValueError,
    ) as exc:
        raise ChecksumRepairPlanError("JSON record is malformed") from exc
    if type(value) is not dict:
        raise ChecksumRepairPlanError("JSON record is not an exact object")
    return value


def _validate_manifest_record(
    path: object, digest: object
) -> tuple[str, str]:
    selected_path = _validate_relative_asset_path(path)
    if not _is_sha256(digest):
        raise ChecksumRepairPlanError(
            "declared digest is not lowercase SHA-256"
        )
    return selected_path, digest


def _validate_manifest_result(
    payload: bytes, records: list[tuple[str, str]]
) -> tuple[tuple[str, str], ...]:
    if (
        type(payload) is not bytes
        or not payload
        or len(payload) > CHECKSUM_REPAIR_PLAN_MANIFEST_MAXIMUM_BYTES
        or not records
        or len(records) > CHECKSUM_REPAIR_PLAN_MAXIMUM_RECORDS
    ):
        raise ChecksumRepairPlanError("manifest violates its closed bounds")
    return tuple(records)


def _parse_manifest_primary(
    payload: bytes, layout: ManifestLayout
) -> tuple[tuple[str, str], ...]:
    if (
        type(payload) is not bytes
        or not payload
        or len(payload) > CHECKSUM_REPAIR_PLAN_MANIFEST_MAXIMUM_BYTES
    ):
        raise ChecksumRepairPlanError("manifest violates its byte bound")
    records: list[tuple[str, str]] = []
    if layout == "sha256sum-text":
        if not payload.endswith(b"\n") or b"\r" in payload:
            raise ChecksumRepairPlanError("sha256sum text framing is invalid")
        lines = payload[:-1].split(b"\n")
        if any(not line for line in lines):
            raise ChecksumRepairPlanError("sha256sum text has a blank row")
        for line in lines:
            if len(line) < 67 or line[64:66] != b"  ":
                raise ChecksumRepairPlanError(
                    "sha256sum text separator is invalid"
                )
            try:
                digest = line[:64].decode("ascii", "strict")
                path = line[66:].decode("utf-8", "strict")
            except UnicodeError as exc:
                raise ChecksumRepairPlanError(
                    "sha256sum text encoding is invalid"
                ) from exc
            records.append(_validate_manifest_record(path, digest))
    elif layout == "jsonl":
        if not payload.endswith(b"\n") or b"\r" in payload:
            raise ChecksumRepairPlanError("JSONL framing is invalid")
        try:
            lines = payload[:-1].decode("utf-8", "strict").split("\n")
        except UnicodeDecodeError as exc:
            raise ChecksumRepairPlanError("JSONL is not strict UTF-8") from exc
        if any(not line for line in lines):
            raise ChecksumRepairPlanError("JSONL has a blank row")
        for line in lines:
            value = _strict_json_object(line)
            if set(value) != {"path", "sha256"}:
                raise ChecksumRepairPlanError("JSONL keys differ")
            records.append(
                _validate_manifest_record(value["path"], value["sha256"])
            )
    elif layout == "csv":
        if (
            not payload.endswith(b"\r\n")
            or any(
                payload[index] == 10
                and (index == 0 or payload[index - 1] != 13)
                for index in range(len(payload))
            )
            or any(
                payload[index] == 13
                and (
                    index + 1 == len(payload)
                    or payload[index + 1] != 10
                )
                for index in range(len(payload))
            )
        ):
            raise ChecksumRepairPlanError("CSV line endings are invalid")
        try:
            text = payload.decode("utf-8", "strict")
            rows = list(
                csv.reader(io.StringIO(text, newline=""), strict=True)
            )
        except (UnicodeDecodeError, csv.Error) as exc:
            raise ChecksumRepairPlanError("CSV syntax is invalid") from exc
        if (
            not rows
            or rows[0] != ["path", "sha256"]
            or len(rows) < 2
            or len(rows) > CHECKSUM_REPAIR_PLAN_MAXIMUM_RECORDS
        ):
            raise ChecksumRepairPlanError("CSV header or body is invalid")
        for row in rows[1:]:
            if len(row) != 2:
                raise ChecksumRepairPlanError("CSV row width is invalid")
            records.append(_validate_manifest_record(row[0], row[1]))
    elif layout == "nul-pairs":
        if payload[-1:] != b"\0":
            raise ChecksumRepairPlanError("NUL manifest is unterminated")
        fields = payload[:-1].split(b"\0")
        if not fields or len(fields) % 2 or any(not field for field in fields):
            raise ChecksumRepairPlanError("NUL pair framing is invalid")
        for offset in range(0, len(fields), 2):
            try:
                path = fields[offset].decode("utf-8", "strict")
                digest = fields[offset + 1].decode("ascii", "strict")
            except UnicodeError as exc:
                raise ChecksumRepairPlanError(
                    "NUL manifest encoding is invalid"
                ) from exc
            records.append(_validate_manifest_record(path, digest))
    else:
        raise ChecksumRepairPlanError("manifest layout is invalid")
    return _validate_manifest_result(payload, records)


def _parse_csv_record_reference(record: str) -> tuple[str, ...]:
    fields: list[str] = []
    cursor = 0
    while True:
        if cursor < len(record) and record[cursor] == '"':
            cursor += 1
            value: list[str] = []
            while True:
                if cursor >= len(record):
                    raise ChecksumRepairPlanError(
                        "reference CSV quote is unterminated"
                    )
                character = record[cursor]
                if character != '"':
                    value.append(character)
                    cursor += 1
                    continue
                if cursor + 1 < len(record) and record[cursor + 1] == '"':
                    value.append('"')
                    cursor += 2
                    continue
                cursor += 1
                break
            if cursor < len(record) and record[cursor] != ",":
                raise ChecksumRepairPlanError(
                    "reference CSV has data after a quote"
                )
            fields.append("".join(value))
        else:
            start = cursor
            while cursor < len(record) and record[cursor] != ",":
                if record[cursor] == '"':
                    raise ChecksumRepairPlanError(
                        "reference CSV has quote in an unquoted field"
                    )
                cursor += 1
            fields.append(record[start:cursor])
        if cursor == len(record):
            break
        cursor += 1
        if cursor == len(record):
            fields.append("")
            break
    return tuple(fields)


def _parse_manifest_reference(
    payload: bytes, layout: ManifestLayout
) -> tuple[tuple[str, str], ...]:
    """Separately structured framing/parser implementation for oracle agreement."""

    if (
        type(payload) is not bytes
        or not 0 < len(payload)
        <= CHECKSUM_REPAIR_PLAN_MANIFEST_MAXIMUM_BYTES
    ):
        raise ChecksumRepairPlanError("reference manifest bound differs")
    records: list[tuple[str, str]] = []
    if layout == "sha256sum-text":
        cursor = 0
        while cursor < len(payload):
            marker = payload.find(b"\n", cursor)
            if marker < 0:
                raise ChecksumRepairPlanError(
                    "reference sha row is unterminated"
                )
            line = payload[cursor:marker]
            cursor = marker + 1
            if (
                len(line) < 67
                or line[64:66] != b"  "
                or b"\r" in line
            ):
                raise ChecksumRepairPlanError(
                    "reference sha separator differs"
                )
            try:
                digest = line[:64].decode("ascii", "strict")
                path = line[66:].decode("utf-8", "strict")
            except UnicodeError as exc:
                raise ChecksumRepairPlanError(
                    "reference sha encoding differs"
                ) from exc
            records.append(_validate_manifest_record(path, digest))
    elif layout == "jsonl":
        if not payload.endswith(b"\n") or b"\r" in payload:
            raise ChecksumRepairPlanError("reference JSONL framing differs")
        cursor = 0
        while cursor < len(payload):
            marker = payload.find(b"\n", cursor)
            if marker < 0 or marker == cursor:
                raise ChecksumRepairPlanError("reference JSONL row differs")
            try:
                line = payload[cursor:marker].decode("utf-8", "strict")
            except UnicodeDecodeError as exc:
                raise ChecksumRepairPlanError(
                    "reference JSONL encoding differs"
                ) from exc
            cursor = marker + 1
            value = _strict_json_object(line)
            if frozenset(value) != frozenset({"path", "sha256"}):
                raise ChecksumRepairPlanError("reference JSONL keys differ")
            records.append(
                _validate_manifest_record(value["path"], value["sha256"])
            )
    elif layout == "csv":
        if not payload.endswith(b"\r\n"):
            raise ChecksumRepairPlanError("reference CSV terminator differs")
        try:
            text = payload.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise ChecksumRepairPlanError(
                "reference CSV encoding differs"
            ) from exc
        rows = text[:-2].split("\r\n")
        if (
            not rows
            or rows[0] != "path,sha256"
            or len(rows) < 2
            or len(rows) > CHECKSUM_REPAIR_PLAN_MAXIMUM_RECORDS
            or any("\r" in row or "\n" in row for row in rows)
        ):
            raise ChecksumRepairPlanError("reference CSV framing differs")
        for row in rows[1:]:
            fields = _parse_csv_record_reference(row)
            if len(fields) != 2:
                raise ChecksumRepairPlanError(
                    "reference CSV width differs"
                )
            records.append(_validate_manifest_record(*fields))
    elif layout == "nul-pairs":
        cursor = 0
        fields: list[bytes] = []
        while cursor < len(payload):
            marker = payload.find(b"\0", cursor)
            if marker < 0 or marker == cursor:
                raise ChecksumRepairPlanError(
                    "reference NUL framing differs"
                )
            fields.append(payload[cursor:marker])
            cursor = marker + 1
        if not fields or len(fields) % 2:
            raise ChecksumRepairPlanError("reference NUL parity differs")
        for offset in range(0, len(fields), 2):
            try:
                path = fields[offset].decode("utf-8", "strict")
                digest = fields[offset + 1].decode("ascii", "strict")
            except UnicodeError as exc:
                raise ChecksumRepairPlanError(
                    "reference NUL encoding differs"
                ) from exc
            records.append(_validate_manifest_record(path, digest))
    else:
        raise ChecksumRepairPlanError("reference layout is invalid")
    return _validate_manifest_result(payload, records)


def parse_checksum_repair_plan_manifest(
    payload: bytes, layout: ManifestLayout
) -> tuple[tuple[str, str], ...]:
    _closed_text(
        layout, CHECKSUM_REPAIR_PLAN_MANIFEST_LAYOUTS, "manifest_layout"
    )
    primary = _parse_manifest_primary(payload, layout)
    reference = _parse_manifest_reference(payload, layout)
    if primary != reference:
        raise ChecksumRepairPlanError("manifest parsers disagree")
    return primary


def _encode_manifest(
    records: tuple[tuple[str, str], ...], layout: ManifestLayout
) -> bytes:
    if not records:
        raise ChecksumRepairPlanError("fixture records are empty")
    if layout == "sha256sum-text":
        return b"".join(
            digest.encode("ascii")
            + b"  "
            + path.encode("utf-8")
            + b"\n"
            for path, digest in records
        )
    if layout == "jsonl":
        return b"".join(
            (
                json.dumps(
                    {"path": path, "sha256": digest},
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            for path, digest in records
        )
    if layout == "csv":
        stream = io.StringIO(newline="")
        writer = csv.writer(stream, lineterminator="\r\n")
        writer.writerow(("path", "sha256"))
        writer.writerows(records)
        return stream.getvalue().encode("utf-8")
    if layout == "nul-pairs":
        result = bytearray()
        for path, digest in records:
            result.extend(path.encode("utf-8"))
            result.append(0)
            result.extend(digest.encode("ascii"))
            result.append(0)
        return bytes(result)
    raise ChecksumRepairPlanError("fixture layout is invalid")


def _declared_mismatch(content: bytes, label: str) -> str:
    digest = sha256(b"declared-mismatch\0" + label.encode("utf-8")).hexdigest()
    if digest == sha256(content).hexdigest():
        raise ChecksumRepairPlanError("fixture mismatch unexpectedly collided")
    return digest


def _profile_inputs_and_records(
    profile: ExecutableFixtureProfile,
) -> tuple[
    tuple[InputFile | InputSymlink, ...],
    tuple[tuple[str, str], ...],
]:
    profile_id = profile.profile_id
    inputs: list[InputFile | InputSymlink] = []
    records: list[tuple[str, str]] = []

    def add_file(
        relative: str,
        content: bytes,
        mode: int,
        *,
        declared: str = "actual",
        mtime: int = 1_000,
    ) -> None:
        inputs.append(
            InputFile(
                (CHECKSUM_REPAIR_PLAN_ASSET_ROOT / relative).as_posix(),
                content,
                mode,
                mtime,
            )
        )
        digest = (
            sha256(content).hexdigest()
            if declared == "actual"
            else _declared_mismatch(content, relative)
        )
        records.append((relative, digest))

    if profile_id == "spaces-unicode":
        add_file(
            "space dir/café 雪.txt",
            "snow 雪\n".encode("utf-8"),
            0o640,
            mtime=1_011,
        )
        quoted = b"quoted actual bytes\x00\n"
        add_file(
            'quoted,"asset".bin',
            quoted,
            0o600,
            declared="mismatch",
            mtime=1_012,
        )
        # Same path with a different declaration is intentionally retained.
        records.append(
            ('quoted,"asset".bin', sha256(quoted).hexdigest())
        )
        add_file(
            "nested/über ok.txt",
            b"nested ok\n",
            0o444,
            mtime=1_013,
        )
        inputs.append(
            InputFile("input/outside/space distractor.txt", b"ignore\n", 0o644)
        )
    elif profile_id == "leading-dashes-globs":
        add_file(
            "-[draft]*?.txt",
            b"literal leading and glob bytes\n",
            0o400,
            mtime=1_021,
        )
        records.append(
            (
                "-missing[?]*.bin",
                sha256(b"declared missing").hexdigest(),
            )
        )
        add_file(
            "literal?/star*.dat",
            b"literal glob path\n",
            0o604,
            mtime=1_022,
        )
        inputs.append(
            InputSymlink(
                "input/assets/-unlisted[*]?",
                "-[draft]*?.txt",
            )
        )
    elif profile_id == "empty-duplicates":
        add_file("empty.bin", b"", 0o400, mtime=1_031)
        records.append(records[0])
        duplicate = b"same duplicate bytes\x00\xff\n"
        add_file(
            "duplicates/one.bin", duplicate, 0o440, mtime=1_032
        )
        add_file(
            "duplicates/two.bin", duplicate, 0o644, mtime=1_033
        )
        inputs.append(
            InputFile("input/assets/unlisted-empty.bin", b"", 0o400, 1_034)
        )
    elif profile_id == "symlinks-ordering":
        add_file(
            "z-last/report.txt", b"zulu\n", 0o644, mtime=1_041
        )
        add_file(
            "a-first/report.txt",
            b"alpha\n",
            0o600,
            declared="mismatch",
            mtime=1_042,
        )
        inputs.extend(
            (
                InputSymlink(
                    "input/assets/link-to-z", "z-last/report.txt"
                ),
                InputSymlink(
                    "input/assets/dangling-link", "missing-target"
                ),
                InputFile(
                    "input/assets/directory/inside.txt",
                    b"directory witness\n",
                    0o640,
                    1_043,
                ),
            )
        )
        records.extend(
            (
                ("link-to-z", sha256(b"symlink declaration").hexdigest()),
                (
                    "dangling-link",
                    sha256(b"dangling declaration").hexdigest(),
                ),
                ("directory", sha256(b"directory declaration").hexdigest()),
            )
        )
        records.reverse()
        inputs.reverse()
    elif profile_id == "partial-permissions":
        add_file(
            "readable/ok.txt", b"readable\n", 0o400, mtime=1_051
        )
        add_file(
            "mismatch.bin",
            b"mismatch actual\n",
            0o600,
            declared="mismatch",
            mtime=1_052,
        )
        add_file(
            "unreadable.bin",
            b"unreadable secret\n",
            0o000,
            mtime=1_053,
        )
        records.append(
            ("missing.bin", sha256(b"permission missing").hexdigest())
        )
        inputs.append(
            InputSymlink(
                "input/assets/unlisted-link", "readable/ok.txt"
            )
        )
    else:
        raise ChecksumRepairPlanError("fixture profile is invalid")
    return tuple(inputs), tuple(records)


def _fixture_inputs(
    profile: ExecutableFixtureProfile, layout: ManifestLayout
) -> tuple[InputFile | InputSymlink, ...]:
    assets, records = _profile_inputs_and_records(profile)
    manifest = InputFile(
        CHECKSUM_REPAIR_PLAN_MANIFEST,
        _encode_manifest(records, layout),
        0o400 if profile.profile_id == "partial-permissions" else 0o600,
        900,
    )
    if profile.profile_id == "symlinks-ordering":
        return (*assets, manifest)
    return (manifest, *assets)


def _revalidate_definition(definition: object) -> FixtureDefinition:
    if type(definition) is not FixtureDefinition:
        raise ChecksumRepairPlanError("definition has wrong exact type")
    try:
        rebuilt = FixtureDefinition(
            definition.fixture_id,
            definition.inputs,
            definition.expected_files,
            definition.schema_version,
            definition.expected_symlinks,
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise ChecksumRepairPlanError(
            "definition reconstruction failed"
        ) from exc
    if (
        rebuilt != definition
        or definition.expected_symlinks
        or any(
            type(item) not in {InputFile, InputSymlink}
            for item in definition.inputs
        )
    ):
        raise ChecksumRepairPlanError("definition is outside family domain")
    return definition


def _definition_manifest(
    definition: FixtureDefinition,
) -> InputFile:
    matches = tuple(
        item
        for item in definition.inputs
        if type(item) is InputFile
        and item.path == CHECKSUM_REPAIR_PLAN_MANIFEST
    )
    if len(matches) != 1:
        raise ChecksumRepairPlanError("fixture must have one exact manifest")
    return matches[0]


def _asset_maps_primary(
    definition: FixtureDefinition,
) -> tuple[dict[str, InputFile | InputSymlink], frozenset[str]]:
    prefix = CHECKSUM_REPAIR_PLAN_ASSET_ROOT.as_posix() + "/"
    entries: dict[str, InputFile | InputSymlink] = {}
    directories: set[str] = set()
    for item in definition.inputs:
        if not item.path.startswith(prefix):
            continue
        relative = item.path[len(prefix) :]
        _validate_relative_asset_path(relative)
        entries[relative] = item
        path = PurePosixPath(relative)
        directories.update(
            parent.as_posix()
            for parent in path.parents
            if parent != PurePosixPath(".")
        )
    return entries, frozenset(directories)


def _reject_symlink_ancestors(
    records: tuple[tuple[str, str], ...],
    entries: dict[str, InputFile | InputSymlink],
) -> None:
    links = {
        PurePosixPath(path)
        for path, item in entries.items()
        if type(item) is InputSymlink
    }
    for path, _digest in records:
        candidate = PurePosixPath(path)
        if any(parent in links for parent in candidate.parents):
            raise ChecksumRepairPlanError(
                "fixture contains a named symlink ancestor"
            )


def _classify_primary(
    path: str,
    declared: str,
    entries: dict[str, InputFile | InputSymlink],
    directories: frozenset[str],
) -> tuple[RepairStatus, str | None]:
    item = entries.get(path)
    if type(item) is InputSymlink:
        return "symlink", None
    if item is None and path in directories:
        return "directory", None
    if item is None:
        return "missing", None
    if type(item) is not InputFile:
        raise ChecksumRepairPlanError("asset kind is outside family domain")
    if len(item.content) > CHECKSUM_REPAIR_PLAN_ASSET_MAXIMUM_BYTES:
        raise ChecksumRepairPlanError("named asset exceeds its byte bound")
    if item.mode & 0o444 and not item.mode & 0o400:
        raise ChecksumRepairPlanError(
            "fixture has an ambiguous non-owner-readable asset"
        )
    if item.mode & 0o444 == 0:
        return "unreadable", None
    actual = sha256(item.content).hexdigest()
    return (
        ("ok" if actual == declared else "checksum-mismatch"),
        actual,
    )


@dataclass(frozen=True, slots=True)
class ChecksumRepairPlanEntry:
    path: str
    status: RepairStatus
    action: RepairAction
    declared_sha256: str
    actual_sha256: str | None
    action_argument: str | None

    def __post_init__(self) -> None:
        if type(self) is not ChecksumRepairPlanEntry:
            raise ChecksumRepairPlanError("entry has wrong exact type")
        _validate_relative_asset_path(self.path)
        _closed_text(self.status, CHECKSUM_REPAIR_PLAN_STATUSES, "status")
        _closed_text(self.action, CHECKSUM_REPAIR_PLAN_ACTIONS, "action")
        if not _is_sha256(self.declared_sha256):
            raise ChecksumRepairPlanError("entry declared digest is invalid")
        if self.actual_sha256 is not None and not _is_sha256(
            self.actual_sha256
        ):
            raise ChecksumRepairPlanError("entry actual digest is invalid")
        if self.status in {"ok", "checksum-mismatch"}:
            if self.actual_sha256 is None:
                raise ChecksumRepairPlanError(
                    "hashed status requires an actual digest"
                )
            if (
                self.status == "ok"
                and self.actual_sha256 != self.declared_sha256
            ):
                raise ChecksumRepairPlanError(
                    "ok status has different declared and actual digests"
                )
            if (
                self.status == "checksum-mismatch"
                and self.actual_sha256 == self.declared_sha256
            ):
                raise ChecksumRepairPlanError(
                    "mismatch status has equal declared and actual digests"
                )
        elif self.actual_sha256 is not None:
            raise ChecksumRepairPlanError(
                "unhashed status cannot carry an actual digest"
            )
        if self.action == "replace-digest":
            if self.action_argument != self.actual_sha256:
                raise ChecksumRepairPlanError(
                    "replacement argument differs from actual digest"
                )
        elif self.action == "quarantine-asset":
            if self.action_argument != f"quarantine/{self.path}":
                raise ChecksumRepairPlanError(
                    "quarantine argument differs from its path"
                )
        elif self.action_argument is not None:
            raise ChecksumRepairPlanError(
                "nonargument action carries an argument"
            )

    def to_json_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "record": "entry",
            "path": self.path,
            "status": self.status,
            "action": self.action,
            "declared_sha256": self.declared_sha256,
            "actual_sha256": self.actual_sha256,
            "action_argument": self.action_argument,
        }

    def commitment_record(self) -> dict[str, object]:
        return self.to_json_record()


def _entry_order(entry: ChecksumRepairPlanEntry) -> tuple[bytes, bytes]:
    return _raw(entry.path), entry.declared_sha256.encode("ascii")


def _action_for(
    status: RepairStatus,
    path: str,
    actual: str | None,
    policy: RepairPolicy,
    strict_rejected: bool,
) -> tuple[RepairAction, str | None]:
    if policy == "report-only":
        return "report", None
    if policy == "strict-reject":
        return ("reject-batch", None) if strict_rejected else ("keep", None)
    if status == "ok":
        return "keep", None
    if policy == "replace-digest" and status == "checksum-mismatch":
        if actual is None:
            raise ChecksumRepairPlanError(
                "replacement status has no actual digest"
            )
        return "replace-digest", actual
    if policy == "drop-missing" and status == "missing":
        return "drop-record", None
    if (
        policy == "quarantine-mismatch"
        and status == "checksum-mismatch"
    ):
        return "quarantine-asset", f"quarantine/{path}"
    return "unresolved", None


def _derive_plan_state(
    entries: tuple[ChecksumRepairPlanEntry, ...],
    policy: RepairPolicy,
) -> PlanState:
    issues = sum(entry.status != "ok" for entry in entries)
    unresolved = sum(entry.action == "unresolved" for entry in entries)
    if issues == 0:
        return "clean"
    if policy == "report-only":
        return "reported"
    if policy == "strict-reject":
        return "rejected"
    return "planned" if unresolved == 0 else "partial"


def _json_line(value: dict[str, object]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _render_plan(
    entries: tuple[ChecksumRepairPlanEntry, ...],
    policy: RepairPolicy,
    state: PlanState,
) -> bytes:
    issue_count = sum(entry.status != "ok" for entry in entries)
    action_count = sum(
        entry.action in _MUTATING_ACTIONS for entry in entries
    )
    unresolved_count = sum(
        entry.action == "unresolved" for entry in entries
    )
    header = {
        "record": "plan",
        "policy": policy,
        "state": state,
        "entry_count": len(entries),
        "issue_count": issue_count,
        "action_count": action_count,
        "unresolved_count": unresolved_count,
    }
    return b"".join(
        (_json_line(header),)
        + tuple(_json_line(entry.to_json_record()) for entry in entries)
    )


@dataclass(frozen=True, slots=True)
class ChecksumRepairPlanState:
    policy: RepairPolicy
    state: PlanState
    entries: tuple[ChecksumRepairPlanEntry, ...]
    report: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if type(self) is not ChecksumRepairPlanState:
            raise ChecksumRepairPlanError("state has wrong exact type")
        _closed_text(
            self.policy, CHECKSUM_REPAIR_PLAN_REPAIR_POLICIES, "policy"
        )
        _closed_text(self.state, CHECKSUM_REPAIR_PLAN_STATES, "state")
        if (
            type(self.entries) is not tuple
            or not self.entries
            or any(
                type(entry) is not ChecksumRepairPlanEntry
                for entry in self.entries
            )
            or tuple(sorted(self.entries, key=_entry_order)) != self.entries
        ):
            raise ChecksumRepairPlanError("state entries are noncanonical")
        for entry in self.entries:
            entry.__post_init__()
        strict_rejected = (
            self.policy == "strict-reject"
            and any(entry.status != "ok" for entry in self.entries)
        )
        for entry in self.entries:
            expected_action, expected_argument = _action_for(
                entry.status,
                entry.path,
                entry.actual_sha256,
                self.policy,
                strict_rejected,
            )
            if (
                entry.action != expected_action
                or entry.action_argument != expected_argument
            ):
                raise ChecksumRepairPlanError(
                    "state entry action differs from policy"
                )
        if self.state != _derive_plan_state(self.entries, self.policy):
            raise ChecksumRepairPlanError("plan state differs from entries")
        expected_report = _render_plan(self.entries, self.policy, self.state)
        if (
            type(self.report) is not bytes
            or self.report != expected_report
            or len(self.report) > CHECKSUM_REPAIR_PLAN_OUTPUT_MAXIMUM_BYTES
        ):
            raise ChecksumRepairPlanError("report bytes differ or exceed bound")

    def header_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "record": "plan",
            "policy": self.policy,
            "state": self.state,
            "entry_count": len(self.entries),
            "issue_count": sum(
                entry.status != "ok" for entry in self.entries
            ),
            "action_count": sum(
                entry.action in _MUTATING_ACTIONS for entry in self.entries
            ),
            "unresolved_count": sum(
                entry.action == "unresolved" for entry in self.entries
            ),
        }

    def commitment_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "header": self.header_record(),
            "entries": [entry.commitment_record() for entry in self.entries],
            "report_size": len(self.report),
            "report_sha256": sha256(self.report).hexdigest(),
        }


def _records_primary(
    definition: FixtureDefinition,
    parameters: ChecksumRepairPlanParameters,
) -> tuple[tuple[str, str, RepairStatus, str | None], ...]:
    selected = _revalidate_definition(definition)
    manifest = _definition_manifest(selected)
    records = _parse_manifest_primary(
        manifest.content, parameters.manifest_layout
    )
    reference_records = _parse_manifest_reference(
        manifest.content, parameters.manifest_layout
    )
    if records != reference_records:
        raise ChecksumRepairPlanError("manifest parsers disagree in fixture")
    entries, directories = _asset_maps_primary(selected)
    _reject_symlink_ancestors(records, entries)
    classified = [
        (
            path,
            declared,
            *_classify_primary(path, declared, entries, directories),
        )
        for path, declared in records
    ]
    classified.sort(key=lambda row: (_raw(row[0]), row[1].encode("ascii")))
    return tuple(classified)


def derive_checksum_repair_plan_state(
    definition: FixtureDefinition,
    parameters: ChecksumRepairPlanParameters,
) -> ChecksumRepairPlanState:
    """Primary dictionary-based semantic implementation."""

    if type(parameters) is not ChecksumRepairPlanParameters:
        raise ChecksumRepairPlanError("primary parameters are invalid")
    parameters.__post_init__()
    classified = _records_primary(definition, parameters)
    strict_rejected = (
        parameters.repair_policy == "strict-reject"
        and any(row[2] != "ok" for row in classified)
    )
    entries = tuple(
        ChecksumRepairPlanEntry(
            path,
            status,
            action,
            declared,
            actual,
            argument,
        )
        for path, declared, status, actual in classified
        for action, argument in (
            _action_for(
                status,
                path,
                actual,
                parameters.repair_policy,
                strict_rejected,
            ),
        )
    )
    state = _derive_plan_state(entries, parameters.repair_policy)
    return ChecksumRepairPlanState(
        parameters.repair_policy,
        state,
        entries,
        _render_plan(entries, parameters.repair_policy, state),
    )


def _classify_reference(
    path: str,
    declared: str,
    file_values: list[tuple[str, bytes, int]],
    link_paths: frozenset[str],
    directory_paths: frozenset[str],
) -> tuple[RepairStatus, str | None]:
    if path in link_paths:
        return "symlink", None
    matching = [value for value in file_values if value[0] == path]
    if not matching:
        return ("directory", None) if path in directory_paths else (
            "missing",
            None,
        )
    if len(matching) != 1:
        raise ChecksumRepairPlanError("reference asset path is duplicated")
    _relative, content, mode = matching[0]
    if len(content) > CHECKSUM_REPAIR_PLAN_ASSET_MAXIMUM_BYTES:
        raise ChecksumRepairPlanError("reference asset exceeds bound")
    if mode & 0o444 and not mode & 0o400:
        raise ChecksumRepairPlanError(
            "reference sees ambiguous read permissions"
        )
    if mode & 0o444 == 0:
        return "unreadable", None
    actual = sha256(content).hexdigest()
    if actual == declared:
        return "ok", actual
    return "checksum-mismatch", actual


def _reference_action(
    status: RepairStatus,
    path: str,
    actual: str | None,
    policy: RepairPolicy,
    rejected: bool,
) -> tuple[RepairAction, str | None]:
    if policy == "strict-reject":
        return ("reject-batch", None) if rejected else ("keep", None)
    if policy == "report-only":
        return "report", None
    if status == "ok":
        return "keep", None
    if status == "checksum-mismatch":
        if policy == "replace-digest":
            if actual is None:
                raise ChecksumRepairPlanError(
                    "reference replacement lacks digest"
                )
            return "replace-digest", actual
        if policy == "quarantine-mismatch":
            return "quarantine-asset", "quarantine/" + path
    if status == "missing" and policy == "drop-missing":
        return "drop-record", None
    return "unresolved", None


def reference_checksum_repair_plan_state(
    definition: FixtureDefinition,
    parameters: ChecksumRepairPlanParameters,
) -> ChecksumRepairPlanState:
    """Reference list/state-machine semantic implementation."""

    if type(parameters) is not ChecksumRepairPlanParameters:
        raise ChecksumRepairPlanError("reference parameters are invalid")
    parameters.__post_init__()
    selected = _revalidate_definition(definition)
    manifest = _definition_manifest(selected)
    records = _parse_manifest_reference(
        manifest.content, parameters.manifest_layout
    )
    prefix = CHECKSUM_REPAIR_PLAN_ASSET_ROOT.as_posix() + "/"
    file_values: list[tuple[str, bytes, int]] = []
    link_paths: set[str] = set()
    directories: set[str] = set()
    for item in selected.inputs:
        if not item.path.startswith(prefix):
            continue
        relative = item.path[len(prefix) :]
        _validate_relative_asset_path(relative)
        if type(item) is InputFile:
            file_values.append((relative, item.content, item.mode))
        elif type(item) is InputSymlink:
            link_paths.add(relative)
        path = PurePosixPath(relative)
        for parent in path.parents:
            if parent != PurePosixPath("."):
                directories.add(parent.as_posix())
    _reject_symlink_ancestors(
        records,
        {
            relative: item
            for item in selected.inputs
            if item.path.startswith(prefix)
            for relative in (item.path[len(prefix) :],)
        },
    )
    classified = [
        (
            path,
            declared,
            *_classify_reference(
                path,
                declared,
                file_values,
                frozenset(link_paths),
                frozenset(directories),
            ),
        )
        for path, declared in records
    ]
    classified.sort(key=lambda row: (_raw(row[0]), row[1].encode("ascii")))
    rejected = (
        parameters.repair_policy == "strict-reject"
        and any(row[2] != "ok" for row in classified)
    )
    entries: list[ChecksumRepairPlanEntry] = []
    for path, declared, status, actual in classified:
        action, argument = _reference_action(
            status,
            path,
            actual,
            parameters.repair_policy,
            rejected,
        )
        entries.append(
            ChecksumRepairPlanEntry(
                path,
                status,
                action,
                declared,
                actual,
                argument,
            )
        )
    selected_entries = tuple(entries)
    state = _derive_plan_state(selected_entries, parameters.repair_policy)
    return ChecksumRepairPlanState(
        parameters.repair_policy,
        state,
        selected_entries,
        _render_plan(
            selected_entries, parameters.repair_policy, state
        ),
    )


def _normalize_output_object(value: dict[str, object]) -> bytes:
    return _json_line(value)


def parse_checksum_repair_plan_output(payload: bytes) -> bytes:
    """Validate candidate JSONL semantics and return canonical equivalent bytes."""

    if (
        type(payload) is not bytes
        or not payload
        or len(payload) > CHECKSUM_REPAIR_PLAN_OUTPUT_MAXIMUM_BYTES
        or not payload.endswith(b"\n")
        or b"\r" in payload
    ):
        raise ChecksumRepairPlanError("candidate plan framing is invalid")
    try:
        lines = payload[:-1].decode("utf-8", "strict").split("\n")
    except UnicodeDecodeError as exc:
        raise ChecksumRepairPlanError(
            "candidate plan is not strict UTF-8"
        ) from exc
    if len(lines) < 2 or any(not line for line in lines):
        raise ChecksumRepairPlanError("candidate plan row count is invalid")
    header = _strict_json_object(lines[0])
    if set(header) != _HEADER_KEYS or header.get("record") != "plan":
        raise ChecksumRepairPlanError("candidate plan header schema differs")
    policy = _closed_text(
        header.get("policy"),
        CHECKSUM_REPAIR_PLAN_REPAIR_POLICIES,
        "output policy",
    )
    state = _closed_text(
        header.get("state"), CHECKSUM_REPAIR_PLAN_STATES, "output state"
    )
    for key in (
        "entry_count",
        "issue_count",
        "action_count",
        "unresolved_count",
    ):
        value = header.get(key)
        if type(value) is not int or value < 0:
            raise ChecksumRepairPlanError(
                "candidate plan count is not a nonnegative integer"
            )
    entries: list[ChecksumRepairPlanEntry] = []
    for line in lines[1:]:
        value = _strict_json_object(line)
        if set(value) != _ENTRY_KEYS or value.get("record") != "entry":
            raise ChecksumRepairPlanError(
                "candidate plan entry schema differs"
            )
        path = _validate_relative_asset_path(value.get("path"))
        status = _closed_text(
            value.get("status"), CHECKSUM_REPAIR_PLAN_STATUSES, "output status"
        )
        action = _closed_text(
            value.get("action"), CHECKSUM_REPAIR_PLAN_ACTIONS, "output action"
        )
        declared = value.get("declared_sha256")
        actual = value.get("actual_sha256")
        argument = value.get("action_argument")
        if not _is_sha256(declared):
            raise ChecksumRepairPlanError(
                "candidate declared digest is invalid"
            )
        if actual is not None and not _is_sha256(actual):
            raise ChecksumRepairPlanError(
                "candidate actual digest is invalid"
            )
        if argument is not None and type(argument) is not str:
            raise ChecksumRepairPlanError(
                "candidate action argument has wrong type"
            )
        entries.append(
            ChecksumRepairPlanEntry(
                path,
                status,  # type: ignore[arg-type]
                action,  # type: ignore[arg-type]
                declared,
                actual,
                argument,
            )
        )
    selected = tuple(entries)
    if (
        not selected
        or len(selected) > CHECKSUM_REPAIR_PLAN_MAXIMUM_RECORDS
        or tuple(sorted(selected, key=_entry_order)) != selected
    ):
        raise ChecksumRepairPlanError("candidate entries are not ordered")
    by_path: dict[str, list[ChecksumRepairPlanEntry]] = {}
    for entry in selected:
        by_path.setdefault(entry.path, []).append(entry)
    for same_path in by_path.values():
        hashed = [
            entry
            for entry in same_path
            if entry.status in {"ok", "checksum-mismatch"}
        ]
        if hashed:
            if (
                len(hashed) != len(same_path)
                or len(
                    {
                        entry.actual_sha256
                        for entry in hashed
                    }
                )
                != 1
            ):
                raise ChecksumRepairPlanError(
                    "candidate classifications disagree for one asset path"
                )
        elif len({entry.status for entry in same_path}) != 1:
            raise ChecksumRepairPlanError(
                "candidate nonregular classifications disagree for one path"
            )
    issues = sum(entry.status != "ok" for entry in selected)
    rejected = policy == "strict-reject" and issues > 0
    for entry in selected:
        expected_action, expected_argument = _action_for(
            entry.status,
            entry.path,
            entry.actual_sha256,
            policy,  # type: ignore[arg-type]
            rejected,
        )
        if (
            entry.action != expected_action
            or entry.action_argument != expected_argument
        ):
            raise ChecksumRepairPlanError(
                "candidate action differs from policy"
            )
    expected_state = _derive_plan_state(
        selected, policy  # type: ignore[arg-type]
    )
    action_count = sum(
        entry.action in _MUTATING_ACTIONS for entry in selected
    )
    unresolved_count = sum(
        entry.action == "unresolved" for entry in selected
    )
    if (
        state != expected_state
        or header["entry_count"] != len(selected)
        or header["issue_count"] != issues
        or header["action_count"] != action_count
        or header["unresolved_count"] != unresolved_count
    ):
        raise ChecksumRepairPlanError(
            "candidate header differs from entry semantics"
        )
    canonical_header = {
        "record": "plan",
        "policy": policy,
        "state": state,
        "entry_count": len(selected),
        "issue_count": issues,
        "action_count": action_count,
        "unresolved_count": unresolved_count,
    }
    return b"".join(
        (_normalize_output_object(canonical_header),)
        + tuple(
            _normalize_output_object(entry.to_json_record())
            for entry in selected
        )
    )


def _expected_files() -> tuple[ExpectedFile, ...]:
    return (
        ExpectedFile(
            CHECKSUM_REPAIR_PLAN_OUTPUT,
            CHECKSUM_REPAIR_PLAN_OUTPUT_MAXIMUM_BYTES,
            CHECKSUM_REPAIR_PLAN_OUTPUT_MODE,
        ),
    )


def _oracle_sha256(
    state: ChecksumRepairPlanState,
    parameters: ChecksumRepairPlanParameters,
) -> str:
    state.__post_init__()
    parameters.__post_init__()
    if state.policy != parameters.repair_policy:
        raise ChecksumRepairPlanError("oracle policy differs from parameters")
    return domain_sha256(
        "cbds.executable-fixture.trusted-oracle.v1",
        {
            "schema_version": EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION,
            "semantic_verifier_identity": (
                CHECKSUM_REPAIR_PLAN_VERIFIER_IDENTITY
            ),
            "parameters": parameters.to_record(),
            "state": state.commitment_record(),
        },
    )


@dataclass(frozen=True, slots=True)
class ChecksumRepairPlanOracle:
    state: ChecksumRepairPlanState = field(repr=False)
    manifest_layout: ManifestLayout
    repair_policy: RepairPolicy
    oracle_sha256: str
    semantic_verifier_identity: str = CHECKSUM_REPAIR_PLAN_VERIFIER_IDENTITY
    schema_version: str = EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        parameters = ChecksumRepairPlanParameters(
            self.manifest_layout, self.repair_policy
        )
        self.state.__post_init__()
        if (
            type(self) is not ChecksumRepairPlanOracle
            or self.semantic_verifier_identity
            != CHECKSUM_REPAIR_PLAN_VERIFIER_IDENTITY
            or self.schema_version != EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION
            or self.state.policy != self.repair_policy
            or not _is_sha256(self.oracle_sha256)
            or self.oracle_sha256 != _oracle_sha256(self.state, parameters)
        ):
            raise ChecksumRepairPlanError("oracle identity is invalid")

    def commitment_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "schema_version": self.schema_version,
            "record_type": "cbds.executable-fixture-trusted-oracle",
            "semantic_verifier_identity": self.semantic_verifier_identity,
            "manifest_layout": self.manifest_layout,
            "repair_policy": self.repair_policy,
            "state": self.state.commitment_record(),
            "oracle_sha256": self.oracle_sha256,
        }


@dataclass(frozen=True, slots=True)
class ChecksumRepairPlanFixtureBundle:
    task_contract_sha256: str
    profile_sha256: str
    definition: FixtureDefinition = field(repr=False)
    fixture_definition_sha256: str
    oracle: ChecksumRepairPlanOracle = field(repr=False)
    descriptor: OpaqueFixtureDescriptor
    schema_version: str = EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_checksum_repair_plan_fixture_bundle(self)

    def commitment_record(self) -> dict[str, object]:
        validate_checksum_repair_plan_fixture_bundle(self)
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


def validate_checksum_repair_plan_fixture_bundle(
    bundle: ChecksumRepairPlanFixtureBundle,
) -> None:
    if type(bundle) is not ChecksumRepairPlanFixtureBundle:
        raise ChecksumRepairPlanError("bundle has wrong exact type")
    if (
        bundle.schema_version != EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION
        or not _is_sha256(bundle.task_contract_sha256)
        or not _is_sha256(bundle.profile_sha256)
        or not _is_sha256(bundle.fixture_definition_sha256)
        or bundle.candidate_execution_authorized is not False
        or bundle.model_selection_eligible is not False
        or bundle.claim_authorized is not False
    ):
        raise ChecksumRepairPlanError("bundle metadata is invalid")
    definition = _revalidate_definition(bundle.definition)
    definition_sha256 = compute_fixture_definition_semantic_sha256(
        definition
    )
    if definition_sha256 != bundle.fixture_definition_sha256:
        raise ChecksumRepairPlanError("definition digest differs")
    if type(bundle.oracle) is not ChecksumRepairPlanOracle:
        raise ChecksumRepairPlanError("oracle has wrong exact type")
    bundle.oracle.__post_init__()
    if definition.expected_files != _expected_files():
        raise ChecksumRepairPlanError("output policy differs")
    parameters = ChecksumRepairPlanParameters(
        bundle.oracle.manifest_layout,
        bundle.oracle.repair_policy,
    )
    primary = derive_checksum_repair_plan_state(definition, parameters)
    reference = reference_checksum_repair_plan_state(definition, parameters)
    if primary != reference or primary != bundle.oracle.state:
        raise ChecksumRepairPlanError(
            "oracle state differs from independently derived fixture state"
        )
    if type(bundle.descriptor) is not OpaqueFixtureDescriptor:
        raise ChecksumRepairPlanError("descriptor has wrong exact type")
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
        raise ChecksumRepairPlanError("descriptor binding differs")


def verify_checksum_repair_plan_fixture_bundle(bundle: object) -> bool:
    try:
        validate_checksum_repair_plan_fixture_bundle(
            bundle  # type: ignore[arg-type]
        )
    except (ChecksumRepairPlanError, TypeError, ValueError):
        return False
    return True


def _validate_task_profile(
    task: object, profile: object
) -> tuple[ChecksumRepairPlanTask, ExecutableFixtureProfile]:
    if type(task) is not ChecksumRepairPlanTask:
        raise ChecksumRepairPlanError("task has wrong exact type")
    if type(profile) is not ExecutableFixtureProfile:
        raise ChecksumRepairPlanError("profile has wrong exact type")
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
        raise ChecksumRepairPlanError(
            "task/profile reconstruction failed"
        ) from exc
    if rebuilt not in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
        raise ChecksumRepairPlanError(
            "profile is outside public development"
        )
    return task, profile


def _construct_checksum_repair_plan_fixture_bundle(
    task: ChecksumRepairPlanTask,
    profile: ExecutableFixtureProfile,
) -> ChecksumRepairPlanFixtureBundle:
    task, profile = _validate_task_profile(task, profile)
    inputs = _fixture_inputs(profile, task.parameters.manifest_layout)
    provisional = FixtureDefinition(
        f"fixture.{task.task_id}.{profile.profile_id}",
        inputs,
        (),
    )
    primary = derive_checksum_repair_plan_state(
        provisional, task.parameters
    )
    reference = reference_checksum_repair_plan_state(
        provisional, task.parameters
    )
    if primary != reference:
        raise ChecksumRepairPlanError(
            "independent plan engines disagree"
        )
    definition = FixtureDefinition(
        provisional.fixture_id,
        inputs,
        _expected_files(),
    )
    if (
        derive_checksum_repair_plan_state(definition, task.parameters)
        != primary
        or reference_checksum_repair_plan_state(
            definition, task.parameters
        )
        != reference
    ):
        raise ChecksumRepairPlanError(
            "final output policy changed semantics"
        )
    oracle = ChecksumRepairPlanOracle(
        primary,
        task.parameters.manifest_layout,
        task.parameters.repair_policy,
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
    return ChecksumRepairPlanFixtureBundle(
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


def build_checksum_repair_plan_fixture_bundle(
    task: ChecksumRepairPlanTask,
    profile: ExecutableFixtureProfile,
) -> ChecksumRepairPlanFixtureBundle:
    selected_task, selected_profile = _validate_task_profile(task, profile)
    bundle = _construct_checksum_repair_plan_fixture_bundle(
        selected_task, selected_profile
    )
    index = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES.index(selected_profile)
    if selected_task.fixtures[index] != bundle.descriptor:
        raise ChecksumRepairPlanError(
            "task descriptor differs from fixture"
        )
    return bundle


def validate_checksum_repair_plan_fixture_for_task_profile(
    task: ChecksumRepairPlanTask,
    profile: ExecutableFixtureProfile,
    bundle: ChecksumRepairPlanFixtureBundle,
) -> None:
    task, profile = _validate_task_profile(task, profile)
    validate_checksum_repair_plan_fixture_bundle(bundle)
    expected = _construct_checksum_repair_plan_fixture_bundle(task, profile)
    if expected != bundle:
        raise ChecksumRepairPlanError(
            "bundle differs from deterministic reconstruction"
        )
    index = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES.index(profile)
    if task.fixtures[index] != bundle.descriptor:
        raise ChecksumRepairPlanError("public descriptor differs")


def verify_checksum_repair_plan_fixture_for_task_profile(
    task: object, profile: object, bundle: object
) -> bool:
    try:
        validate_checksum_repair_plan_fixture_for_task_profile(
            task,  # type: ignore[arg-type]
            profile,  # type: ignore[arg-type]
            bundle,  # type: ignore[arg-type]
        )
    except (ChecksumRepairPlanError, TypeError, ValueError):
        return False
    return True


def _discrimination_signature(
    bundle: ChecksumRepairPlanFixtureBundle,
) -> tuple[str, str, str, tuple[str, ...]]:
    manifest = _definition_manifest(bundle.definition)
    state = bundle.oracle.state
    return (
        bundle.oracle.manifest_layout,
        sha256(manifest.content).hexdigest(),
        state.state,
        tuple(entry.action for entry in state.entries),
    )


def compute_checksum_repair_plan_discrimination_sha256(
    tasks: tuple[ChecksumRepairPlanTask, ...],
) -> str:
    expected = tuple(
        (layout, policy)
        for layout in CHECKSUM_REPAIR_PLAN_MANIFEST_LAYOUTS
        for policy in CHECKSUM_REPAIR_PLAN_REPAIR_POLICIES
    )
    if (
        type(tasks) is not tuple
        or len(tasks) != 20
        or any(type(task) is not ChecksumRepairPlanTask for task in tasks)
        or tuple(
            (
                task.parameters.manifest_layout,
                task.parameters.repair_policy,
            )
            for task in tasks
        )
        != expected
    ):
        raise ChecksumRepairPlanError(
            "discrimination requires canonical task order"
        )
    profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
    signatures: list[tuple[str, str, str, tuple[str, ...]]] = []
    records: list[dict[str, object]] = []
    for task in tasks:
        bundle = _construct_checksum_repair_plan_fixture_bundle(task, profile)
        signature = _discrimination_signature(bundle)
        signatures.append(signature)
        records.append(
            {
                "task_id": task.task_id,
                "manifest_layout": task.parameters.manifest_layout,
                "repair_policy": task.parameters.repair_policy,
                "manifest_sha256": signature[1],
                "plan_state": signature[2],
                "actions": list(signature[3]),
                "fixture_sha256": bundle.descriptor.fixture_sha256,
            }
        )
    if len(set(signatures)) != 20:
        raise ChecksumRepairPlanError(
            "grid is not behaviorally discriminable"
        )
    return domain_sha256(
        "cbds.executable-static.checksum-repair-plan."
        "discrimination-evidence.v1",
        {
            "family_id": CHECKSUM_REPAIR_PLAN_FAMILY_ID,
            "profile_sha256": profile.profile_sha256,
            "signature_count": len(records),
            "signatures": records,
        },
    )


def build_checksum_repair_plan_tasks() -> tuple[
    ChecksumRepairPlanTask, ...
]:
    tasks: list[ChecksumRepairPlanTask] = []
    signatures: list[tuple[str, str, str, tuple[str, ...]]] = []
    for layout in CHECKSUM_REPAIR_PLAN_MANIFEST_LAYOUTS:
        for policy in CHECKSUM_REPAIR_PLAN_REPAIR_POLICIES:
            bootstrap = _bootstrap_task(
                ChecksumRepairPlanParameters(layout, policy)
            )
            bundles = tuple(
                _construct_checksum_repair_plan_fixture_bundle(
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
            signatures.append(_discrimination_signature(bundles[0]))
    selected = tuple(tasks)
    if (
        len(selected) != 20
        or len({task.task_id for task in selected}) != 20
        or len({task.task_contract_sha256 for task in selected}) != 20
        or len({task.graph_sha256 for task in selected}) != 20
        or len(set(signatures)) != 20
    ):
        raise ChecksumRepairPlanError(
            "task grid is not 20 discriminable cells"
        )
    return selected


def materialize_checksum_repair_plan_fixture(
    task: ChecksumRepairPlanTask,
    profile: ExecutableFixtureProfile,
    bundle: ChecksumRepairPlanFixtureBundle,
    workspace: str | os.PathLike[str],
) -> WorkspaceHandle:
    validate_checksum_repair_plan_fixture_for_task_profile(
        task, profile, bundle
    )
    return materialize_fixture(bundle.definition, workspace)


def verify_checksum_repair_plan_workspace(
    task: ChecksumRepairPlanTask,
    profile: ExecutableFixtureProfile,
    bundle: ChecksumRepairPlanFixtureBundle,
    handle: WorkspaceHandle,
) -> bool:
    """Verify a semantically exact plan and preserved quiescent input tree."""

    if type(handle) is not WorkspaceHandle:
        return False
    try:
        validate_checksum_repair_plan_fixture_for_task_profile(
            task, profile, bundle
        )
        baseline = handle.baseline
        if (
            baseline.fixture_id != bundle.definition.fixture_id
            or baseline.fixture_sha256 != bundle.definition.fixture_sha256
            or handle.expected_files != bundle.definition.expected_files
            or handle.expected_symlinks
            or baseline.output_scaffold_entries
        ):
            return False
        primary = derive_checksum_repair_plan_state(
            bundle.definition, task.parameters
        )
        reference = reference_checksum_repair_plan_state(
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
            or output_entries[0].path != CHECKSUM_REPAIR_PLAN_OUTPUT
            or output_entries[0].mode != CHECKSUM_REPAIR_PLAN_OUTPUT_MODE
            or output_entries[0].link_count != 1
            or output_entries[0].hardlink_group_sha256 is not None
        ):
            return False
        observed = handle.read_output_bytes(
            output_scan, CHECKSUM_REPAIR_PLAN_OUTPUT
        )
        if parse_checksum_repair_plan_output(observed) != primary.report:
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
        ChecksumRepairPlanError,
        ExecutableWorkspaceError,
        OSError,
        TypeError,
        ValueError,
    ):
        return False


__all__ = [
    "CHECKSUM_REPAIR_PLAN_ACTIONS",
    "CHECKSUM_REPAIR_PLAN_ALLOWED_TOOLS",
    "CHECKSUM_REPAIR_PLAN_ANCESTOR_SYMLINKS_COVERED",
    "CHECKSUM_REPAIR_PLAN_ASSET_MAXIMUM_BYTES",
    "CHECKSUM_REPAIR_PLAN_ASSET_ROOT",
    "CHECKSUM_REPAIR_PLAN_ATOMICITY_OBSERVED",
    "CHECKSUM_REPAIR_PLAN_CANDIDATE_EXIT_STATUS_OBSERVED",
    "CHECKSUM_REPAIR_PLAN_DIRECTORY_PERMISSION_ERRORS_COVERED",
    "CHECKSUM_REPAIR_PLAN_FAMILY_ID",
    "CHECKSUM_REPAIR_PLAN_FILESYSTEM_IDENTITY",
    "CHECKSUM_REPAIR_PLAN_FINAL_PLAN_OBSERVED",
    "CHECKSUM_REPAIR_PLAN_GENERATOR_VERSION",
    "CHECKSUM_REPAIR_PLAN_INPUT_PRESERVATION_OBSERVED",
    "CHECKSUM_REPAIR_PLAN_MANIFEST",
    "CHECKSUM_REPAIR_PLAN_MANIFEST_LAYOUTS",
    "CHECKSUM_REPAIR_PLAN_MANIFEST_MAXIMUM_BYTES",
    "CHECKSUM_REPAIR_PLAN_MAXIMUM_RECORDS",
    "CHECKSUM_REPAIR_PLAN_OUTPUT",
    "CHECKSUM_REPAIR_PLAN_OUTPUT_IDENTITY",
    "CHECKSUM_REPAIR_PLAN_OUTPUT_MAXIMUM_BYTES",
    "CHECKSUM_REPAIR_PLAN_OUTPUT_MODE",
    "CHECKSUM_REPAIR_PLAN_QUARANTINE_EXECUTION_OBSERVED",
    "CHECKSUM_REPAIR_PLAN_READ_SCOPE_OBSERVED",
    "CHECKSUM_REPAIR_PLAN_REPAIR_EXECUTION_OBSERVED",
    "CHECKSUM_REPAIR_PLAN_REPAIR_POLICIES",
    "CHECKSUM_REPAIR_PLAN_SPECIAL_FILE_KINDS_COVERED",
    "CHECKSUM_REPAIR_PLAN_STATUSES",
    "CHECKSUM_REPAIR_PLAN_STATES",
    "CHECKSUM_REPAIR_PLAN_TOOL_HISTORY_OBSERVED",
    "CHECKSUM_REPAIR_PLAN_VERIFIER_IDENTITY",
    "CHECKSUM_REPAIR_PLAN_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE",
    "CHECKSUM_REPAIR_PLAN_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE",
    "ChecksumRepairPlanEntry",
    "ChecksumRepairPlanError",
    "ChecksumRepairPlanFixtureBundle",
    "ChecksumRepairPlanOracle",
    "ChecksumRepairPlanParameters",
    "ChecksumRepairPlanState",
    "ChecksumRepairPlanTask",
    "build_checksum_repair_plan_fixture_bundle",
    "build_checksum_repair_plan_tasks",
    "checksum_repair_plan_task_semantic_core",
    "compute_checksum_repair_plan_discrimination_sha256",
    "compute_checksum_repair_plan_task_sha256",
    "derive_checksum_repair_plan_state",
    "materialize_checksum_repair_plan_fixture",
    "parse_checksum_repair_plan_manifest",
    "parse_checksum_repair_plan_output",
    "reference_checksum_repair_plan_state",
    "validate_checksum_repair_plan_fixture_bundle",
    "validate_checksum_repair_plan_fixture_for_task_profile",
    "verify_checksum_repair_plan_fixture_bundle",
    "verify_checksum_repair_plan_fixture_for_task_profile",
    "verify_checksum_repair_plan_workspace",
]
