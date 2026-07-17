"""Executable-static planning over bounded dependency graphs.

The family decodes one of four closed graph encodings, validates declared
nodes and prerequisite-to-dependent edges, and emits one deterministic
topological execution plan or one exact cycle report.  The trusted primary
path uses incremental Kahn state; the reference path independently rescans
predecessors and derives graph reachability.

This is public method-development infrastructure.  It does not execute a
candidate, authorize scored evaluation, expose sealed data, or support a
model-quality claim.  The workspace verifier establishes only the final
bounded output tree and preservation of pinned inputs under trusted
quiescence.  Allowing ``python3`` is a task-level tool list, not syscall,
module-import, or read-scope confinement.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field, replace
from hashlib import sha256
import io
import json
import os
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
    InputSymlink,
    WorkspaceHandle,
    materialize_fixture,
    validate_expected_output_policy,
)


DEPENDENCY_DAG_EXECUTION_PLAN_FAMILY_ID: Final[str] = (
    "dependency-dag-execution-plan"
)
DEPENDENCY_DAG_EXECUTION_PLAN_FILESYSTEM_IDENTITY: Final[str] = (
    "dependency-graph-documents"
)
DEPENDENCY_DAG_EXECUTION_PLAN_OUTPUT_IDENTITY: Final[str] = (
    "validated-topological-execution-plan"
)
DEPENDENCY_DAG_EXECUTION_PLAN_GENERATOR_VERSION: Final[str] = "1.0.0"
DEPENDENCY_DAG_EXECUTION_PLAN_VERIFIER_IDENTITY: Final[str] = (
    "verify-dependency-dag-execution-plan-v1"
)
DEPENDENCY_DAG_EXECUTION_PLAN_INPUT: Final[str] = "input/graph.data"
DEPENDENCY_DAG_EXECUTION_PLAN_OUTPUT: Final[str] = (
    "output/execution-plan.json"
)
DEPENDENCY_DAG_EXECUTION_PLAN_OUTPUT_MODE: Final[int] = 0o644
DEPENDENCY_DAG_EXECUTION_PLAN_SOURCE_MAXIMUM_BYTES: Final[int] = 128 * 1024
DEPENDENCY_DAG_EXECUTION_PLAN_MAXIMUM_NODES: Final[int] = 64
DEPENDENCY_DAG_EXECUTION_PLAN_MAXIMUM_PHYSICAL_DEPENDENCIES: Final[int] = 512
DEPENDENCY_DAG_EXECUTION_PLAN_MAXIMUM_EDGES: Final[int] = 256
DEPENDENCY_DAG_EXECUTION_PLAN_JSON_MAXIMUM_DEPTH: Final[int] = 8
DEPENDENCY_DAG_EXECUTION_PLAN_JSON_MAXIMUM_NODES: Final[int] = 4_096
DEPENDENCY_DAG_EXECUTION_PLAN_JSON_MAXIMUM_OBJECT_MEMBERS: Final[int] = 128
DEPENDENCY_DAG_EXECUTION_PLAN_NODE_ID_MAXIMUM_UTF8_BYTES: Final[int] = 128
DEPENDENCY_DAG_EXECUTION_PLAN_PRIORITY_MAXIMUM: Final[int] = 1_000_000
DEPENDENCY_DAG_EXECUTION_PLAN_OUTPUT_MAXIMUM_BYTES: Final[int] = 64 * 1024
DEPENDENCY_DAG_EXECUTION_PLAN_PROVED_MAXIMUM_TOTAL_OUTPUT_BYTES: Final[int] = (
    DEPENDENCY_DAG_EXECUTION_PLAN_OUTPUT_MAXIMUM_BYTES
)
DEPENDENCY_DAG_EXECUTION_PLAN_ALLOWED_TOOLS: Final[tuple[str, ...]] = (
    "mkdir",
    "python3",
)

# Honest final-state observation boundaries.
DEPENDENCY_DAG_EXECUTION_PLAN_FINAL_OUTPUT_OBSERVED: Final[bool] = True
DEPENDENCY_DAG_EXECUTION_PLAN_INPUT_PRESERVATION_OBSERVED: Final[bool] = True
DEPENDENCY_DAG_EXECUTION_PLAN_ATOMICITY_OBSERVED: Final[bool] = False
DEPENDENCY_DAG_EXECUTION_PLAN_TOOL_HISTORY_OBSERVED: Final[bool] = False
DEPENDENCY_DAG_EXECUTION_PLAN_READ_SCOPE_OBSERVED: Final[bool] = False
DEPENDENCY_DAG_EXECUTION_PLAN_CANDIDATE_EXIT_STATUS_OBSERVED: Final[
    bool
] = False
DEPENDENCY_DAG_EXECUTION_PLAN_TRANSIENT_STATE_OBSERVED: Final[bool] = False
DEPENDENCY_DAG_EXECUTION_PLAN_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE: Final[
    bool
] = True
DEPENDENCY_DAG_EXECUTION_PLAN_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE: Final[
    bool
] = False

GraphEncoding: TypeAlias = Literal[
    "json-adjacency",
    "json-edge-list",
    "csv-edges",
    "line-oriented-dependencies",
]
TieBreakPolicy: TypeAlias = Literal[
    "utf8-smallest",
    "declared-priority",
    "shortest-depth",
    "largest-fanout",
    "stable-input-order",
]
PlanStatus: TypeAlias = Literal["valid", "cycle"]

DEPENDENCY_DAG_EXECUTION_PLAN_GRAPH_ENCODINGS: Final[
    tuple[GraphEncoding, ...]
] = (
    "json-adjacency",
    "json-edge-list",
    "csv-edges",
    "line-oriented-dependencies",
)
DEPENDENCY_DAG_EXECUTION_PLAN_TIE_BREAK_POLICIES: Final[
    tuple[TieBreakPolicy, ...]
] = (
    "utf8-smallest",
    "declared-priority",
    "shortest-depth",
    "largest-fanout",
    "stable-input-order",
)

_TASK_ID_RE: Final[re.Pattern[str]] = re.compile(r"mds-[0-9a-f]{24}\Z")
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_CANONICAL_DECIMAL_RE: Final[re.Pattern[str]] = re.compile(
    r"-?(?:0|[1-9][0-9]{0,6})\Z"
)
_ADJACENCY_TOP_KEYS: Final[frozenset[str]] = frozenset({"nodes"})
_ADJACENCY_NODE_KEYS: Final[frozenset[str]] = frozenset(
    {"id", "priority", "depends_on"}
)
_EDGE_LIST_TOP_KEYS: Final[frozenset[str]] = frozenset({"nodes", "edges"})
_EDGE_LIST_NODE_KEYS: Final[frozenset[str]] = frozenset({"id", "priority"})
_EDGE_KEYS: Final[frozenset[str]] = frozenset(
    {"dependent", "prerequisite"}
)
_OUTPUT_KEYS: Final[frozenset[str]] = frozenset(
    {
        "graph_encoding",
        "tie_break_policy",
        "status",
        "node_count",
        "edge_count",
        "plan",
        "blocked_nodes",
        "cyclic_nodes",
    }
)


class DependencyDagExecutionPlanError(ValueError):
    """Raised when a dependency-plan contract is violated."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def _closed_text(
    value: object,
    allowed: tuple[str, ...],
    field_name: str,
) -> str:
    if type(value) is not str or value not in allowed:
        raise DependencyDagExecutionPlanError(
            f"{field_name} is outside its closed set"
        )
    return value


def _validate_node_id(value: object, field_name: str) -> str:
    if type(value) is not str or not value:
        raise DependencyDagExecutionPlanError(
            f"{field_name} must be a nonempty exact string"
        )
    if any(
        unicodedata.category(character) in {"Cc", "Cf"}
        for character in value
    ):
        raise DependencyDagExecutionPlanError(
            f"{field_name} contains a control or format character"
        )
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise DependencyDagExecutionPlanError(
            f"{field_name} is not strict UTF-8 text"
        ) from exc
    if (
        not encoded
        or len(encoded)
        > DEPENDENCY_DAG_EXECUTION_PLAN_NODE_ID_MAXIMUM_UTF8_BYTES
    ):
        raise DependencyDagExecutionPlanError(
            f"{field_name} exceeds its UTF-8 bound"
        )
    return value


def _validate_priority(value: object, field_name: str) -> int:
    if (
        type(value) is not int
        or abs(value) > DEPENDENCY_DAG_EXECUTION_PLAN_PRIORITY_MAXIMUM
    ):
        raise DependencyDagExecutionPlanError(
            f"{field_name} must be an exact bounded integer"
        )
    return value


def _parse_priority_text(value: object, field_name: str) -> int:
    if (
        type(value) is not str
        or value == "-0"
        or _CANONICAL_DECIMAL_RE.fullmatch(value) is None
    ):
        raise DependencyDagExecutionPlanError(
            f"{field_name} must be a canonical bounded decimal"
        )
    parsed = int(value)
    return _validate_priority(parsed, field_name)


def _require_exact_keys(
    value: object,
    keys: frozenset[str],
    field_name: str,
) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise DependencyDagExecutionPlanError(
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
            if depth > DEPENDENCY_DAG_EXECUTION_PLAN_JSON_MAXIMUM_DEPTH:
                raise DependencyDagExecutionPlanError(
                    "JSON exceeds its nesting-depth bound"
                )
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise DependencyDagExecutionPlanError(
                    "JSON delimiters are unbalanced"
                )
    if in_string or escaped or depth != 0:
        raise DependencyDagExecutionPlanError(
            "JSON lexical framing is incomplete"
        )


def _bounded_json_int(token: str) -> int:
    if (
        token == "-0"
        or _CANONICAL_DECIMAL_RE.fullmatch(token) is None
    ):
        raise DependencyDagExecutionPlanError(
            "JSON integer is not a canonical bounded decimal"
        )
    return _validate_priority(int(token), "JSON integer")


def _reject_float(token: str) -> object:
    raise DependencyDagExecutionPlanError(
        f"JSON floating-point token is forbidden: {token[:16]}"
    )


def _reject_constant(token: str) -> object:
    raise DependencyDagExecutionPlanError(
        f"JSON nonfinite token is forbidden: {token}"
    )


def _reject_duplicate_object(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    if (
        len(pairs)
        > DEPENDENCY_DAG_EXECUTION_PLAN_JSON_MAXIMUM_OBJECT_MEMBERS
    ):
        raise DependencyDagExecutionPlanError(
            "JSON object exceeds its member bound"
        )
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DependencyDagExecutionPlanError(
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
            count > DEPENDENCY_DAG_EXECUTION_PLAN_JSON_MAXIMUM_NODES
            or depth > DEPENDENCY_DAG_EXECUTION_PLAN_JSON_MAXIMUM_DEPTH
        ):
            raise DependencyDagExecutionPlanError(
                "JSON tree exceeds its node or depth bound"
            )
        if type(value) is dict:
            if (
                len(value)
                > DEPENDENCY_DAG_EXECUTION_PLAN_JSON_MAXIMUM_OBJECT_MEMBERS
            ):
                raise DependencyDagExecutionPlanError(
                    "JSON object exceeds its member bound"
                )
            for key, item in value.items():
                if type(key) is not str:
                    raise DependencyDagExecutionPlanError(
                        "JSON object key is not an exact string"
                    )
                stack.append((item, depth + 1))
        elif type(value) is list:
            if len(value) > DEPENDENCY_DAG_EXECUTION_PLAN_JSON_MAXIMUM_NODES:
                raise DependencyDagExecutionPlanError(
                    "JSON array exceeds its element bound"
                )
            stack.extend((item, depth + 1) for item in value)
        elif type(value) is str:
            try:
                value.encode("utf-8", errors="strict")
            except UnicodeEncodeError as exc:
                raise DependencyDagExecutionPlanError(
                    "JSON string is not strict UTF-8"
                ) from exc
        elif value is None or type(value) in {bool, int}:
            continue
        else:
            raise DependencyDagExecutionPlanError(
                "JSON contains an unsupported scalar type"
            )


def _decode_json_strict(payload: bytes) -> object:
    if type(payload) is not bytes or not payload:
        raise DependencyDagExecutionPlanError(
            "JSON payload must be nonempty immutable bytes"
        )
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise DependencyDagExecutionPlanError(
            "JSON payload is not strict UTF-8"
        ) from exc
    if text.startswith("\ufeff"):
        raise DependencyDagExecutionPlanError("JSON BOM is forbidden")
    _prebound_json_text(text)
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_object,
            parse_int=_bounded_json_int,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except DependencyDagExecutionPlanError:
        raise
    except (
        json.JSONDecodeError,
        RecursionError,
        TypeError,
        ValueError,
    ) as exc:
        raise DependencyDagExecutionPlanError(
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
        raise DependencyDagExecutionPlanError(
            "value cannot be encoded as canonical JSON"
        ) from exc


@dataclass(frozen=True, slots=True)
class DependencyDagExecutionPlanParameters:
    graph_encoding: GraphEncoding
    tie_break_policy: TieBreakPolicy

    def __post_init__(self) -> None:
        if type(self) is not DependencyDagExecutionPlanParameters:
            raise DependencyDagExecutionPlanError(
                "parameters have wrong exact type"
            )
        _closed_text(
            self.graph_encoding,
            DEPENDENCY_DAG_EXECUTION_PLAN_GRAPH_ENCODINGS,
            "graph_encoding",
        )
        _closed_text(
            self.tie_break_policy,
            DEPENDENCY_DAG_EXECUTION_PLAN_TIE_BREAK_POLICIES,
            "tie_break_policy",
        )

    def to_record(self) -> dict[str, str]:
        self.__post_init__()
        return {
            "parameter_type": DEPENDENCY_DAG_EXECUTION_PLAN_FAMILY_ID,
            "graph_encoding": self.graph_encoding,
            "tie_break_policy": self.tie_break_policy,
        }


def _task_contract(
    parameters: DependencyDagExecutionPlanParameters,
) -> tuple[str, NormalizedSemanticGraph]:
    prompt = f"""Write one Bash program that operates only in the current workspace.

Read only `input/graph.data` as `{parameters.graph_encoding}`.  The source is
strict UTF-8 and bounded to 131072 bytes, one to 64 declared nodes, 512
physical dependency references, 256 distinct edges, JSON depth 8 and 4096
JSON nodes.  Node IDs are nonempty, contain no Unicode control or format
characters, and are at most 128 UTF-8 bytes.  Priorities are exact integers
from -1000000 through 1000000.  Duplicate node declarations and unknown
endpoints are invalid.  An edge is prerequisite -> dependent; duplicate
edges are idempotent and count once.

`json-adjacency` is one LF-terminated closed object with only `nodes`; each
node is exactly `id`, `priority`, and `depends_on`.  `json-edge-list` is one
LF-terminated closed object with exact `nodes` and `edges`; a node is exactly
`id` and `priority`, and an edge is exactly `dependent` and `prerequisite`.
`csv-edges` is strict RFC 4180 with CRLF records and exact header
`record,node,priority,dependency`; a node row is
`node,<id>,<priority>,`, an edge row is `edge,<dependent>,,<prerequisite>`,
rows may interleave, and node-row order declares.  `line-oriented-dependencies`
has LF-terminated rows `<priority><TAB><node-id>` followed by zero or more
`<TAB><prerequisite>` fields.  JSON node-array, CSV node-row, and line-row
order is declaration order.

Use Kahn topological planning with `{parameters.tie_break_policy}` among ready
nodes.  `utf8-smallest` chooses the smallest raw UTF-8 ID.
`declared-priority` chooses larger numeric priority, then raw UTF-8 ID.
`shortest-depth` uses depth zero for roots and one plus the longest
prerequisite depth otherwise, choosing smaller depth then raw UTF-8 ID.
`largest-fanout` chooses more distinct direct dependents, then raw UTF-8 ID.
`stable-input-order` chooses smaller node declaration index.  If acyclic,
emit status `valid`, the complete plan, and empty cycle arrays.  If cyclic,
discard every partial plan, emit status `cycle`, raw-UTF8-sorted
`blocked_nodes` equal to the final Kahn residual (including downstream
blocked nodes), and raw-UTF8-sorted `cyclic_nodes` containing exactly nodes
in a nontrivial strongly connected component or with a self-loop.

Create only a real mode-0755 `output/` directory and independent mode-0644
`output/execution-plan.json`.  The JSON object has exactly
`graph_encoding`, `tie_break_policy`, `status`, `node_count`, `edge_count`,
`plan`, `blocked_nodes`, and `cyclic_nodes`; edge_count counts distinct
edges.  JSON key order and insignificant whitespace are not semantic.
Preserve every input path, kind, byte, mode, mtime, link count and symlink
target.

The final-state verifier cannot prove tool use, Python module or syscall
confinement, read scope, exit status, atomicity, transient state or global
quiescence.  Use only Bash built-ins plus `mkdir` and `python3`.
"""
    graph = NormalizedSemanticGraph(
        nodes=(
            OperatorNode(
                "parse_dependency_graph",
                (
                    f"encoding:{parameters.graph_encoding}",
                    "path:input/graph.data",
                    "nodes:64",
                    "edges:256",
                ),
            ),
            OperatorNode(
                "validate_graph_contract",
                ("endpoint-closure", "duplicate-edges:idempotent"),
            ),
            OperatorNode(
                "derive_graph_metrics",
                ("depth:longest-prerequisite", "fanout:distinct-direct"),
            ),
            OperatorNode(
                "run_kahn_planner",
                (f"tie-break:{parameters.tie_break_policy}",),
            ),
            OperatorNode(
                "classify_cycle_residual",
                ("blocked:kahn-residual", "cyclic:scc-or-self-loop"),
            ),
            OperatorNode(
                "emit_execution_plan",
                (
                    "path:output/execution-plan.json",
                    "file-mode:0644",
                    "directory-mode:0755",
                ),
            ),
        ),
        dependencies=((0, 1), (1, 2), (2, 3), (3, 4), (4, 5)),
    )
    return prompt, graph


def _validate_graph_contract(
    graph: object,
) -> NormalizedSemanticGraph:
    if type(graph) is not NormalizedSemanticGraph:
        raise DependencyDagExecutionPlanError("graph has wrong exact type")
    if (
        type(graph.nodes) is not tuple
        or not graph.nodes
        or any(type(node) is not OperatorNode for node in graph.nodes)
        or type(graph.dependencies) is not tuple
    ):
        raise DependencyDagExecutionPlanError(
            "graph collections have wrong exact types"
        )
    for node in graph.nodes:
        if (
            type(node.name) is not str
            or not node.name
            or type(node.parameters) is not tuple
            or any(
                type(parameter) is not str
                for parameter in node.parameters
            )
        ):
            raise DependencyDagExecutionPlanError(
                "graph operator has noncanonical scalar types"
            )
    if any(
        type(edge) is not tuple
        or len(edge) != 2
        or any(type(index) is not int for index in edge)
        for edge in graph.dependencies
    ):
        raise DependencyDagExecutionPlanError(
            "graph dependencies have wrong exact types"
        )
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
        raise DependencyDagExecutionPlanError(
            "graph reconstruction failed"
        ) from exc
    if rebuilt != graph or len(rebuilt.nodes) != len(graph.nodes):
        raise DependencyDagExecutionPlanError("graph is noncanonical")
    return graph


def dependency_dag_execution_plan_task_semantic_core(
    parameters: DependencyDagExecutionPlanParameters,
    prompt: str,
    graph: NormalizedSemanticGraph,
) -> dict[str, object]:
    if type(parameters) is not DependencyDagExecutionPlanParameters:
        raise DependencyDagExecutionPlanError(
            "parameters have wrong exact type"
        )
    parameters.__post_init__()
    expected_prompt, expected_graph = _task_contract(parameters)
    if (
        type(prompt) is not str
        or prompt != expected_prompt
        or _validate_graph_contract(graph) != expected_graph
    ):
        raise DependencyDagExecutionPlanError("prompt or graph differs")
    return {
        "schema_version": EXECUTABLE_STATIC_SCHEMA_VERSION,
        "contract_version": EXECUTABLE_STATIC_CONTRACT_VERSION,
        "split_role": METHOD_DEVELOPMENT_SPLIT,
        "family_id": DEPENDENCY_DAG_EXECUTION_PLAN_FAMILY_ID,
        "family_version": EXECUTABLE_STATIC_FAMILY_VERSION,
        "generator_version": DEPENDENCY_DAG_EXECUTION_PLAN_GENERATOR_VERSION,
        "parameters": parameters.to_record(),
        "prompt": prompt,
        "graph": graph.to_record(),
        "graph_sha256": graph.hash,
        "filesystem_identity": (
            DEPENDENCY_DAG_EXECUTION_PLAN_FILESYSTEM_IDENTITY
        ),
        "output_identity": DEPENDENCY_DAG_EXECUTION_PLAN_OUTPUT_IDENTITY,
        "allowed_tools": list(DEPENDENCY_DAG_EXECUTION_PLAN_ALLOWED_TOOLS),
        "public": True,
        "sealed": False,
        "candidate_execution_authorized": False,
        "model_selection_eligible": False,
        "claim_authorized": False,
    }


def compute_dependency_dag_execution_plan_task_sha256(
    parameters: DependencyDagExecutionPlanParameters,
    prompt: str,
    graph: NormalizedSemanticGraph,
) -> str:
    return domain_sha256(
        "cbds.executable-static.task-contract.v1",
        dependency_dag_execution_plan_task_semantic_core(
            parameters, prompt, graph
        ),
    )


@dataclass(frozen=True, slots=True)
class DependencyDagExecutionPlanTask:
    task_id: str
    parameters: DependencyDagExecutionPlanParameters
    prompt: str
    graph: NormalizedSemanticGraph
    fixtures: tuple[OpaqueFixtureDescriptor, ...]
    task_contract_sha256: str
    family_id: str = DEPENDENCY_DAG_EXECUTION_PLAN_FAMILY_ID
    family_version: str = EXECUTABLE_STATIC_FAMILY_VERSION
    filesystem_identity: str = (
        DEPENDENCY_DAG_EXECUTION_PLAN_FILESYSTEM_IDENTITY
    )
    output_identity: str = DEPENDENCY_DAG_EXECUTION_PLAN_OUTPUT_IDENTITY
    allowed_tools: tuple[str, ...] = (
        DEPENDENCY_DAG_EXECUTION_PLAN_ALLOWED_TOOLS
    )
    split_role: str = METHOD_DEVELOPMENT_SPLIT
    public: bool = True
    sealed: bool = False
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        if (
            type(self) is not DependencyDagExecutionPlanTask
            or type(self.parameters) is not DependencyDagExecutionPlanParameters
            or type(self.family_id) is not str
            or self.family_id != DEPENDENCY_DAG_EXECUTION_PLAN_FAMILY_ID
            or type(self.family_version) is not str
            or self.family_version != EXECUTABLE_STATIC_FAMILY_VERSION
            or type(self.filesystem_identity) is not str
            or self.filesystem_identity
            != DEPENDENCY_DAG_EXECUTION_PLAN_FILESYSTEM_IDENTITY
            or type(self.output_identity) is not str
            or self.output_identity
            != DEPENDENCY_DAG_EXECUTION_PLAN_OUTPUT_IDENTITY
            or type(self.allowed_tools) is not tuple
            or any(type(item) is not str for item in self.allowed_tools)
            or self.allowed_tools
            != DEPENDENCY_DAG_EXECUTION_PLAN_ALLOWED_TOOLS
            or type(self.split_role) is not str
            or self.split_role != METHOD_DEVELOPMENT_SPLIT
            or self.public is not True
            or self.sealed is not False
            or self.candidate_execution_authorized is not False
            or self.model_selection_eligible is not False
            or self.claim_authorized is not False
        ):
            raise DependencyDagExecutionPlanError(
                "task metadata is invalid"
            )
        expected = compute_dependency_dag_execution_plan_task_sha256(
            self.parameters, self.prompt, self.graph
        )
        if (
            type(self.task_id) is not str
            or _TASK_ID_RE.fullmatch(self.task_id) is None
            or not _is_sha256(self.task_contract_sha256)
            or self.task_contract_sha256 != expected
            or self.task_id != task_id_from_contract(expected)
            or type(self.fixtures) is not tuple
            or len(self.fixtures)
            != len(PUBLIC_DEVELOPMENT_FIXTURE_PROFILES)
            or any(
                type(item) is not OpaqueFixtureDescriptor
                for item in self.fixtures
            )
        ):
            raise DependencyDagExecutionPlanError(
                "task identity is invalid"
            )
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
            raise DependencyDagExecutionPlanError(
                "task descriptor binding is invalid"
            )

    @property
    def graph_sha256(self) -> str:
        self.__post_init__()
        return self.graph.hash

    def to_public_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            **dependency_dag_execution_plan_task_semantic_core(
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
            f"fx-{digest[:24]}", digest, task_contract_sha256
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
    parameters: DependencyDagExecutionPlanParameters,
) -> DependencyDagExecutionPlanTask:
    prompt, graph = _task_contract(parameters)
    digest = compute_dependency_dag_execution_plan_task_sha256(
        parameters, prompt, graph
    )
    return DependencyDagExecutionPlanTask(
        task_id_from_contract(digest),
        parameters,
        prompt,
        graph,
        _bootstrap_descriptors(digest),
        digest,
    )


@dataclass(frozen=True, slots=True)
class DependencyDagNode:
    node_id: str
    priority: int
    declaration_index: int
    prerequisites: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            type(self) is not DependencyDagNode
            or type(self.node_id) is not str
            or type(self.priority) is not int
            or type(self.declaration_index) is not int
            or self.declaration_index < 0
            or self.declaration_index
            >= DEPENDENCY_DAG_EXECUTION_PLAN_MAXIMUM_NODES
            or type(self.prerequisites) is not tuple
            or any(type(item) is not str for item in self.prerequisites)
        ):
            raise DependencyDagExecutionPlanError(
                "dependency node metadata is invalid"
            )
        _validate_node_id(self.node_id, "node_id")
        _validate_priority(self.priority, "priority")
        for prerequisite in self.prerequisites:
            _validate_node_id(prerequisite, "prerequisite")
        if (
            tuple(
                sorted(
                    set(self.prerequisites),
                    key=lambda item: item.encode("utf-8"),
                )
            )
            != self.prerequisites
        ):
            raise DependencyDagExecutionPlanError(
                "node prerequisites are not unique raw-UTF8 order"
            )


@dataclass(frozen=True, slots=True)
class DependencyDag:
    nodes: tuple[DependencyDagNode, ...]

    def __post_init__(self) -> None:
        if (
            type(self) is not DependencyDag
            or type(self.nodes) is not tuple
            or not self.nodes
            or len(self.nodes) > DEPENDENCY_DAG_EXECUTION_PLAN_MAXIMUM_NODES
            or any(type(node) is not DependencyDagNode for node in self.nodes)
        ):
            raise DependencyDagExecutionPlanError(
                "dependency graph node collection is invalid"
            )
        identifiers: list[str] = []
        for index, node in enumerate(self.nodes):
            node.__post_init__()
            if node.declaration_index != index:
                raise DependencyDagExecutionPlanError(
                    "node declaration indexes are nonconsecutive"
                )
            identifiers.append(node.node_id)
        if len(identifiers) != len(set(identifiers)):
            raise DependencyDagExecutionPlanError(
                "dependency graph contains duplicate nodes"
            )
        identifier_set = set(identifiers)
        if any(
            prerequisite not in identifier_set
            for node in self.nodes
            for prerequisite in node.prerequisites
        ):
            raise DependencyDagExecutionPlanError(
                "dependency graph references an unknown endpoint"
            )
        if self.edge_count > DEPENDENCY_DAG_EXECUTION_PLAN_MAXIMUM_EDGES:
            raise DependencyDagExecutionPlanError(
                "dependency graph exceeds its distinct-edge bound"
            )

    @property
    def edge_count(self) -> int:
        return sum(len(node.prerequisites) for node in self.nodes)

    def commitment_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "nodes": [
                {
                    "id": node.node_id,
                    "priority": node.priority,
                    "declaration_index": node.declaration_index,
                    "prerequisites": list(node.prerequisites),
                }
                for node in self.nodes
            ],
            "node_count": len(self.nodes),
            "edge_count": self.edge_count,
        }


def _build_dependency_graph(
    declarations: list[tuple[str, int]],
    physical_edges: list[tuple[str, str]],
) -> DependencyDag:
    if (
        type(declarations) is not list
        or not declarations
        or len(declarations) > DEPENDENCY_DAG_EXECUTION_PLAN_MAXIMUM_NODES
        or any(
            type(item) is not tuple
            or len(item) != 2
            or type(item[0]) is not str
            or type(item[1]) is not int
            for item in declarations
        )
        or type(physical_edges) is not list
        or len(physical_edges)
        > DEPENDENCY_DAG_EXECUTION_PLAN_MAXIMUM_PHYSICAL_DEPENDENCIES
        or any(
            type(item) is not tuple
            or len(item) != 2
            or any(type(part) is not str for part in item)
            for item in physical_edges
        )
    ):
        raise DependencyDagExecutionPlanError(
            "parsed graph declarations violate structural bounds"
        )
    identifiers: list[str] = []
    priorities: list[int] = []
    for node_id, priority in declarations:
        identifiers.append(_validate_node_id(node_id, "node id"))
        priorities.append(_validate_priority(priority, "node priority"))
    if len(identifiers) != len(set(identifiers)):
        raise DependencyDagExecutionPlanError(
            "node declarations are duplicated"
        )
    identifier_set = set(identifiers)
    unique_edges: set[tuple[str, str]] = set()
    for dependent, prerequisite in physical_edges:
        _validate_node_id(dependent, "edge dependent")
        _validate_node_id(prerequisite, "edge prerequisite")
        if dependent not in identifier_set or prerequisite not in identifier_set:
            raise DependencyDagExecutionPlanError(
                "edge references an unknown endpoint"
            )
        unique_edges.add((dependent, prerequisite))
    if len(unique_edges) > DEPENDENCY_DAG_EXECUTION_PLAN_MAXIMUM_EDGES:
        raise DependencyDagExecutionPlanError(
            "graph exceeds its distinct-edge bound"
        )
    prerequisites_by_node: dict[str, list[str]] = {
        node_id: [] for node_id in identifiers
    }
    for dependent, prerequisite in unique_edges:
        prerequisites_by_node[dependent].append(prerequisite)
    nodes = tuple(
        DependencyDagNode(
            node_id,
            priorities[index],
            index,
            tuple(
                sorted(
                    prerequisites_by_node[node_id],
                    key=lambda item: item.encode("utf-8"),
                )
            ),
        )
        for index, node_id in enumerate(identifiers)
    )
    return DependencyDag(nodes)


def _parse_json_adjacency(payload: bytes) -> DependencyDag:
    root = _require_exact_keys(
        _decode_json_strict(payload), _ADJACENCY_TOP_KEYS, "adjacency source"
    )
    raw_nodes = root["nodes"]
    if (
        type(raw_nodes) is not list
        or not raw_nodes
        or len(raw_nodes) > DEPENDENCY_DAG_EXECUTION_PLAN_MAXIMUM_NODES
    ):
        raise DependencyDagExecutionPlanError(
            "adjacency nodes must be a nonempty bounded array"
        )
    declarations: list[tuple[str, int]] = []
    edges: list[tuple[str, str]] = []
    for raw_node in raw_nodes:
        node = _require_exact_keys(
            raw_node, _ADJACENCY_NODE_KEYS, "adjacency node"
        )
        node_id = _validate_node_id(node["id"], "node id")
        priority = _validate_priority(node["priority"], "node priority")
        raw_dependencies = node["depends_on"]
        if type(raw_dependencies) is not list:
            raise DependencyDagExecutionPlanError(
                "depends_on must be an exact array"
            )
        declarations.append((node_id, priority))
        for prerequisite in raw_dependencies:
            edges.append(
                (
                    node_id,
                    _validate_node_id(prerequisite, "depends_on item"),
                )
            )
            if (
                len(edges)
                > DEPENDENCY_DAG_EXECUTION_PLAN_MAXIMUM_PHYSICAL_DEPENDENCIES
            ):
                raise DependencyDagExecutionPlanError(
                    "adjacency source exceeds its physical dependency bound"
                )
    return _build_dependency_graph(declarations, edges)


def _parse_json_edge_list(payload: bytes) -> DependencyDag:
    root = _require_exact_keys(
        _decode_json_strict(payload), _EDGE_LIST_TOP_KEYS, "edge-list source"
    )
    raw_nodes = root["nodes"]
    raw_edges = root["edges"]
    if (
        type(raw_nodes) is not list
        or not raw_nodes
        or len(raw_nodes) > DEPENDENCY_DAG_EXECUTION_PLAN_MAXIMUM_NODES
        or type(raw_edges) is not list
        or len(raw_edges)
        > DEPENDENCY_DAG_EXECUTION_PLAN_MAXIMUM_PHYSICAL_DEPENDENCIES
    ):
        raise DependencyDagExecutionPlanError(
            "edge-list arrays violate their cardinality bounds"
        )
    declarations: list[tuple[str, int]] = []
    for raw_node in raw_nodes:
        node = _require_exact_keys(
            raw_node, _EDGE_LIST_NODE_KEYS, "edge-list node"
        )
        declarations.append(
            (
                _validate_node_id(node["id"], "node id"),
                _validate_priority(node["priority"], "node priority"),
            )
        )
    edges: list[tuple[str, str]] = []
    for raw_edge in raw_edges:
        edge = _require_exact_keys(raw_edge, _EDGE_KEYS, "edge-list edge")
        edges.append(
            (
                _validate_node_id(edge["dependent"], "edge dependent"),
                _validate_node_id(
                    edge["prerequisite"], "edge prerequisite"
                ),
            )
        )
    return _build_dependency_graph(declarations, edges)


def _validate_rfc4180_lexical(text: str) -> None:
    """Reject quote placement that ``csv.reader(strict=True)`` still accepts."""

    index = 0
    in_quotes = False
    after_quote = False
    at_field_start = True
    while index < len(text):
        character = text[index]
        if in_quotes:
            if character == '"':
                if index + 1 < len(text) and text[index + 1] == '"':
                    index += 2
                    continue
                in_quotes = False
                after_quote = True
            index += 1
            continue
        if after_quote:
            if character == ",":
                after_quote = False
                at_field_start = True
                index += 1
                continue
            if text.startswith("\r\n", index):
                after_quote = False
                at_field_start = True
                index += 2
                continue
            raise DependencyDagExecutionPlanError(
                "CSV contains characters after a closing quote"
            )
        if character == '"':
            if not at_field_start:
                raise DependencyDagExecutionPlanError(
                    "CSV contains an unescaped quote in an unquoted field"
                )
            in_quotes = True
            at_field_start = False
            index += 1
            continue
        if character == ",":
            at_field_start = True
            index += 1
            continue
        if text.startswith("\r\n", index):
            at_field_start = True
            index += 2
            continue
        if character in {"\r", "\n"}:
            raise DependencyDagExecutionPlanError(
                "CSV contains a bare record delimiter byte"
            )
        at_field_start = False
        index += 1
    if in_quotes or after_quote or not at_field_start:
        # A valid source is already required to end in CRLF.  Reaching this
        # branch therefore identifies incomplete quote/framing state rather
        # than rejecting an ordinary final nonempty field.
        raise DependencyDagExecutionPlanError(
            "CSV quote or record framing is incomplete"
        )


def _parse_csv_edges(payload: bytes) -> DependencyDag:
    try:
        text = payload.decode("utf-8", errors="strict")
    except (AttributeError, UnicodeDecodeError) as exc:
        raise DependencyDagExecutionPlanError(
            "CSV source is not immutable strict UTF-8 bytes"
        ) from exc
    if (
        type(payload) is not bytes
        or not payload
        or not payload.endswith(b"\r\n")
        or b"\r" in payload.replace(b"\r\n", b"")
        or b"\n" in payload.replace(b"\r\n", b"")
        or text.startswith("\ufeff")
    ):
        raise DependencyDagExecutionPlanError(
            "CSV source violates strict CRLF framing"
        )
    _validate_rfc4180_lexical(text)
    try:
        rows = list(
            csv.reader(
                io.StringIO(text, newline=""),
                dialect="excel",
                strict=True,
            )
        )
    except (csv.Error, UnicodeError) as exc:
        raise DependencyDagExecutionPlanError(
            "CSV source violates strict RFC 4180 parsing"
        ) from exc
    if not rows or rows[0] != [
        "record",
        "node",
        "priority",
        "dependency",
    ]:
        raise DependencyDagExecutionPlanError(
            "CSV source has the wrong exact header"
        )
    declarations: list[tuple[str, int]] = []
    edges: list[tuple[str, str]] = []
    for row in rows[1:]:
        if len(row) != 4:
            raise DependencyDagExecutionPlanError(
                "CSV record must have exactly four fields"
            )
        record, node_id, priority, dependency = row
        if record == "node":
            if dependency != "":
                raise DependencyDagExecutionPlanError(
                    "CSV node record dependency field must be empty"
                )
            declarations.append(
                (
                    _validate_node_id(node_id, "CSV node"),
                    _parse_priority_text(priority, "CSV priority"),
                )
            )
            if (
                len(declarations)
                > DEPENDENCY_DAG_EXECUTION_PLAN_MAXIMUM_NODES
            ):
                raise DependencyDagExecutionPlanError(
                    "CSV exceeds its node declaration bound"
                )
        elif record == "edge":
            if priority != "":
                raise DependencyDagExecutionPlanError(
                    "CSV edge record priority field must be empty"
                )
            edges.append(
                (
                    _validate_node_id(node_id, "CSV edge dependent"),
                    _validate_node_id(
                        dependency, "CSV edge prerequisite"
                    ),
                )
            )
            if (
                len(edges)
                > DEPENDENCY_DAG_EXECUTION_PLAN_MAXIMUM_PHYSICAL_DEPENDENCIES
            ):
                raise DependencyDagExecutionPlanError(
                    "CSV exceeds its physical dependency bound"
                )
        else:
            raise DependencyDagExecutionPlanError(
                "CSV record discriminator is outside its closed set"
            )
    return _build_dependency_graph(declarations, edges)


def _parse_line_dependencies(payload: bytes) -> DependencyDag:
    try:
        text = payload.decode("utf-8", errors="strict")
    except (AttributeError, UnicodeDecodeError) as exc:
        raise DependencyDagExecutionPlanError(
            "line source is not immutable strict UTF-8 bytes"
        ) from exc
    if (
        type(payload) is not bytes
        or not payload
        or not payload.endswith(b"\n")
        or b"\r" in payload
        or text.startswith("\ufeff")
    ):
        raise DependencyDagExecutionPlanError(
            "line source violates exact LF framing"
        )
    lines = text[:-1].split("\n")
    if (
        not lines
        or len(lines) > DEPENDENCY_DAG_EXECUTION_PLAN_MAXIMUM_NODES
        or any(not line for line in lines)
    ):
        raise DependencyDagExecutionPlanError(
            "line source has invalid physical rows"
        )
    declarations: list[tuple[str, int]] = []
    edges: list[tuple[str, str]] = []
    for line in lines:
        fields = line.split("\t")
        if len(fields) < 2:
            raise DependencyDagExecutionPlanError(
                "line record requires priority and node ID"
            )
        priority = _parse_priority_text(fields[0], "line priority")
        node_id = _validate_node_id(fields[1], "line node")
        declarations.append((node_id, priority))
        for prerequisite in fields[2:]:
            edges.append(
                (
                    node_id,
                    _validate_node_id(
                        prerequisite, "line prerequisite"
                    ),
                )
            )
            if (
                len(edges)
                > DEPENDENCY_DAG_EXECUTION_PLAN_MAXIMUM_PHYSICAL_DEPENDENCIES
            ):
                raise DependencyDagExecutionPlanError(
                    "line source exceeds its physical dependency bound"
                )
    return _build_dependency_graph(declarations, edges)


def parse_dependency_dag_execution_plan_source(
    payload: bytes,
    graph_encoding: GraphEncoding,
) -> DependencyDag:
    """Decode one bounded graph source into its canonical logical graph."""

    encoding = _closed_text(
        graph_encoding,
        DEPENDENCY_DAG_EXECUTION_PLAN_GRAPH_ENCODINGS,
        "graph_encoding",
    )
    if (
        type(payload) is not bytes
        or not payload
        or len(payload) > DEPENDENCY_DAG_EXECUTION_PLAN_SOURCE_MAXIMUM_BYTES
    ):
        raise DependencyDagExecutionPlanError(
            "graph source violates its byte bound"
        )
    if encoding == "json-adjacency":
        if (
            not payload.endswith(b"\n")
            or payload.endswith(b"\r\n")
            or payload.endswith(b"\n\n")
        ):
            raise DependencyDagExecutionPlanError(
                "JSON adjacency requires one LF terminator"
            )
        return _parse_json_adjacency(payload[:-1])
    if encoding == "json-edge-list":
        if (
            not payload.endswith(b"\n")
            or payload.endswith(b"\r\n")
            or payload.endswith(b"\n\n")
        ):
            raise DependencyDagExecutionPlanError(
                "JSON edge list requires one LF terminator"
            )
        return _parse_json_edge_list(payload[:-1])
    if encoding == "csv-edges":
        return _parse_csv_edges(payload)
    if encoding == "line-oriented-dependencies":
        return _parse_line_dependencies(payload)
    raise DependencyDagExecutionPlanError(
        "graph encoding is unsupported"
    )


def _source_payload(definition: FixtureDefinition) -> bytes:
    matches = tuple(
        item
        for item in definition.inputs
        if type(item) is InputFile
        and item.path == DEPENDENCY_DAG_EXECUTION_PLAN_INPUT
    )
    if len(matches) != 1:
        raise DependencyDagExecutionPlanError(
            "fixture must contain one exact graph source"
        )
    return matches[0].content


def _raw_order(values: set[str] | tuple[str, ...] | list[str]) -> tuple[str, ...]:
    return tuple(sorted(values, key=lambda item: item.encode("utf-8")))


def _graph_maps(
    graph: DependencyDag,
) -> tuple[
    dict[str, DependencyDagNode],
    dict[str, set[str]],
    dict[str, set[str]],
]:
    graph.__post_init__()
    nodes = {node.node_id: node for node in graph.nodes}
    prerequisites = {
        node.node_id: set(node.prerequisites) for node in graph.nodes
    }
    dependents = {node.node_id: set() for node in graph.nodes}
    for dependent, required in prerequisites.items():
        for prerequisite in required:
            dependents[prerequisite].add(dependent)
    return nodes, prerequisites, dependents


def _selection_key(
    node_id: str,
    policy: TieBreakPolicy,
    nodes: dict[str, DependencyDagNode],
    dependents: dict[str, set[str]],
    depths: dict[str, int],
) -> tuple[object, ...]:
    raw = node_id.encode("utf-8")
    if policy == "utf8-smallest":
        return (raw,)
    if policy == "declared-priority":
        return (-nodes[node_id].priority, raw)
    if policy == "shortest-depth":
        if node_id not in depths:
            raise DependencyDagExecutionPlanError(
                "ready node lacks a derived prerequisite depth"
            )
        return (depths[node_id], raw)
    if policy == "largest-fanout":
        return (-len(dependents[node_id]), raw)
    if policy == "stable-input-order":
        return (nodes[node_id].declaration_index, raw)
    raise DependencyDagExecutionPlanError(
        "tie-break policy is unsupported"
    )


def _cyclic_nodes_by_return_reachability(
    residual: set[str],
    dependents: dict[str, set[str]],
) -> tuple[str, ...]:
    cyclic: set[str] = set()
    for origin in residual:
        frontier = list(dependents[origin] & residual)
        seen: set[str] = set()
        while frontier:
            candidate = frontier.pop()
            if candidate == origin:
                cyclic.add(origin)
                break
            if candidate in seen:
                continue
            seen.add(candidate)
            frontier.extend(dependents[candidate] & residual)
    return _raw_order(cyclic)


def _derive_primary_plan(
    graph: DependencyDag,
    policy: TieBreakPolicy,
) -> tuple[PlanStatus, tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    nodes, prerequisites, dependents = _graph_maps(graph)
    indegrees = {
        node_id: len(required)
        for node_id, required in prerequisites.items()
    }
    ready = {
        node_id for node_id, indegree in indegrees.items() if indegree == 0
    }
    depths = {node_id: 0 for node_id in ready}
    ordered: list[str] = []
    while ready:
        selected = min(
            ready,
            key=lambda node_id: _selection_key(
                node_id, policy, nodes, dependents, depths
            ),
        )
        ready.remove(selected)
        ordered.append(selected)
        for dependent in dependents[selected]:
            depths[dependent] = max(
                depths.get(dependent, 0), depths[selected] + 1
            )
            indegrees[dependent] -= 1
            if indegrees[dependent] == 0:
                ready.add(dependent)
    if len(ordered) == len(nodes):
        return "valid", tuple(ordered), (), ()
    residual = set(nodes) - set(ordered)
    return (
        "cycle",
        (),
        _raw_order(residual),
        _cyclic_nodes_by_return_reachability(residual, dependents),
    )


def _reference_kahn_residual(
    prerequisites: dict[str, set[str]],
) -> set[str]:
    remaining = set(prerequisites)
    while True:
        removable = {
            node_id
            for node_id in remaining
            if not (prerequisites[node_id] & remaining)
        }
        if not removable:
            return remaining
        remaining -= removable


def _reference_cyclic_nodes(
    residual: set[str],
    prerequisites: dict[str, set[str]],
) -> tuple[str, ...]:
    # Independent transitive closure over prerequisite direction.  A node is
    # cyclic exactly when it can reach itself by at least one residual edge.
    reachability = {
        node_id: set(prerequisites[node_id] & residual)
        for node_id in residual
    }
    for intermediate in tuple(residual):
        for source in tuple(residual):
            if intermediate in reachability[source]:
                reachability[source].update(reachability[intermediate])
    return _raw_order(
        {
            node_id
            for node_id in residual
            if node_id in reachability[node_id]
        }
    )


def _reference_depths(
    identifiers: tuple[str, ...],
    prerequisites: dict[str, set[str]],
) -> dict[str, int]:
    cache: dict[str, int] = {}

    def visit(node_id: str, active: set[str]) -> int:
        if node_id in cache:
            return cache[node_id]
        if node_id in active:
            raise DependencyDagExecutionPlanError(
                "reference depth encountered a cycle"
            )
        required = prerequisites[node_id]
        value = (
            0
            if not required
            else 1
            + max(
                visit(prerequisite, active | {node_id})
                for prerequisite in required
            )
        )
        cache[node_id] = value
        return value

    for identifier in identifiers:
        visit(identifier, set())
    return cache


def _reference_selection_key(
    node_id: str,
    policy: TieBreakPolicy,
    nodes: dict[str, DependencyDagNode],
    dependents: dict[str, set[str]],
    depths: dict[str, int],
) -> tuple[object, ...]:
    """Independent reference ordering implementation."""

    raw = node_id.encode("utf-8")
    if policy == "utf8-smallest":
        return (raw,)
    if policy == "declared-priority":
        return (0 - nodes[node_id].priority, raw)
    if policy == "shortest-depth":
        if node_id not in depths:
            raise DependencyDagExecutionPlanError(
                "reference ready node lacks a depth"
            )
        return (depths[node_id], raw)
    if policy == "largest-fanout":
        return (0 - len(dependents[node_id]), raw)
    if policy == "stable-input-order":
        return (nodes[node_id].declaration_index, raw)
    raise DependencyDagExecutionPlanError(
        "reference tie-break policy is unsupported"
    )


def _derive_reference_plan(
    graph: DependencyDag,
    policy: TieBreakPolicy,
) -> tuple[PlanStatus, tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    # Reconstruct every relationship directly rather than borrowing the
    # primary planner's map or selection-key helpers.  Both paths share only
    # the already validated immutable logical graph boundary.
    graph.__post_init__()
    nodes = {node.node_id: node for node in graph.nodes}
    prerequisites = {
        node.node_id: {item for item in node.prerequisites}
        for node in graph.nodes
    }
    dependents: dict[str, set[str]] = {
        node.node_id: set() for node in graph.nodes
    }
    for node in graph.nodes:
        for prerequisite in node.prerequisites:
            dependents[prerequisite].add(node.node_id)
    residual = _reference_kahn_residual(prerequisites)
    if residual:
        return (
            "cycle",
            (),
            _raw_order(residual),
            _reference_cyclic_nodes(residual, prerequisites),
        )
    identifiers = tuple(node.node_id for node in graph.nodes)
    depths = _reference_depths(identifiers, prerequisites)
    completed: set[str] = set()
    ordered: list[str] = []
    while len(completed) < len(identifiers):
        candidates = [
            node_id
            for node_id in identifiers
            if node_id not in completed
            and prerequisites[node_id] <= completed
        ]
        if not candidates:
            raise DependencyDagExecutionPlanError(
                "reference planner stalled on an acyclic graph"
            )
        selected = min(
            candidates,
            key=lambda node_id: _reference_selection_key(
                node_id, policy, nodes, dependents, depths
            ),
        )
        completed.add(selected)
        ordered.append(selected)
    return "valid", tuple(ordered), (), ()


@dataclass(frozen=True, slots=True)
class DependencyDagExecutionPlanState:
    graph_encoding: GraphEncoding
    tie_break_policy: TieBreakPolicy
    status: PlanStatus
    node_count: int
    edge_count: int
    plan: tuple[str, ...]
    blocked_nodes: tuple[str, ...]
    cyclic_nodes: tuple[str, ...]
    content: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if type(self) is not DependencyDagExecutionPlanState:
            raise DependencyDagExecutionPlanError(
                "state has wrong exact type"
            )
        _closed_text(
            self.graph_encoding,
            DEPENDENCY_DAG_EXECUTION_PLAN_GRAPH_ENCODINGS,
            "state graph_encoding",
        )
        _closed_text(
            self.tie_break_policy,
            DEPENDENCY_DAG_EXECUTION_PLAN_TIE_BREAK_POLICIES,
            "state tie_break_policy",
        )
        if type(self.status) is not str or self.status not in {"valid", "cycle"}:
            raise DependencyDagExecutionPlanError(
                "state status is outside its closed set"
            )
        if (
            type(self.node_count) is not int
            or not 1 <= self.node_count
            <= DEPENDENCY_DAG_EXECUTION_PLAN_MAXIMUM_NODES
            or type(self.edge_count) is not int
            or not 0 <= self.edge_count
            <= DEPENDENCY_DAG_EXECUTION_PLAN_MAXIMUM_EDGES
            or type(self.plan) is not tuple
            or type(self.blocked_nodes) is not tuple
            or type(self.cyclic_nodes) is not tuple
            or any(
                len(sequence) > self.node_count
                for sequence in (
                    self.plan,
                    self.blocked_nodes,
                    self.cyclic_nodes,
                )
            )
            or any(
                type(item) is not str
                for sequence in (
                    self.plan,
                    self.blocked_nodes,
                    self.cyclic_nodes,
                )
                for item in sequence
            )
            or type(self.content) is not bytes
            or not self.content
            or len(self.content)
            > DEPENDENCY_DAG_EXECUTION_PLAN_OUTPUT_MAXIMUM_BYTES
        ):
            raise DependencyDagExecutionPlanError(
                "state fields violate type or cardinality bounds"
            )
        for sequence in (self.plan, self.blocked_nodes, self.cyclic_nodes):
            for node_id in sequence:
                _validate_node_id(node_id, "state node ID")
            if len(sequence) != len(set(sequence)):
                raise DependencyDagExecutionPlanError(
                    "state node arrays contain duplicates"
                )
        if self.status == "valid":
            if (
                len(self.plan) != self.node_count
                or self.blocked_nodes
                or self.cyclic_nodes
            ):
                raise DependencyDagExecutionPlanError(
                    "valid state has incomplete or cyclic arrays"
                )
        elif (
            self.plan
            or not self.blocked_nodes
            or not self.cyclic_nodes
            or not set(self.cyclic_nodes) <= set(self.blocked_nodes)
            or self.blocked_nodes != _raw_order(self.blocked_nodes)
            or self.cyclic_nodes != _raw_order(self.cyclic_nodes)
        ):
            raise DependencyDagExecutionPlanError(
                "cycle state has invalid plan or residual arrays"
            )
        if self.content != _canonical_json(self.to_value()):
            raise DependencyDagExecutionPlanError(
                "state content is noncanonical"
            )

    def to_value(self) -> dict[str, object]:
        return {
            "graph_encoding": self.graph_encoding,
            "tie_break_policy": self.tie_break_policy,
            "status": self.status,
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "plan": list(self.plan),
            "blocked_nodes": list(self.blocked_nodes),
            "cyclic_nodes": list(self.cyclic_nodes),
        }

    @property
    def commitment_sha256(self) -> str:
        self.__post_init__()
        return domain_sha256(
            "cbds.dependency-dag-execution-plan.state.v1",
            {
                **self.to_value(),
                "content_sha256": sha256(self.content).hexdigest(),
                "content_bytes": len(self.content),
            },
        )

    def commitment_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            **self.to_value(),
            "content_sha256": sha256(self.content).hexdigest(),
            "content_bytes": len(self.content),
            "state_sha256": self.commitment_sha256,
        }


def _build_state(
    graph: DependencyDag,
    parameters: DependencyDagExecutionPlanParameters,
    *,
    reference: bool,
) -> DependencyDagExecutionPlanState:
    result = (
        _derive_reference_plan(graph, parameters.tie_break_policy)
        if reference
        else _derive_primary_plan(graph, parameters.tie_break_policy)
    )
    status, plan, blocked, cyclic = result
    value = {
        "graph_encoding": parameters.graph_encoding,
        "tie_break_policy": parameters.tie_break_policy,
        "status": status,
        "node_count": len(graph.nodes),
        "edge_count": graph.edge_count,
        "plan": list(plan),
        "blocked_nodes": list(blocked),
        "cyclic_nodes": list(cyclic),
    }
    return DependencyDagExecutionPlanState(
        parameters.graph_encoding,
        parameters.tie_break_policy,
        status,
        len(graph.nodes),
        graph.edge_count,
        plan,
        blocked,
        cyclic,
        _canonical_json(value),
    )


def _revalidate_definition(definition: object) -> FixtureDefinition:
    if type(definition) is not FixtureDefinition:
        raise DependencyDagExecutionPlanError(
            "definition has wrong exact type"
        )
    if (
        type(definition.fixture_id) is not str
        or type(definition.schema_version) is not str
        or type(definition.inputs) is not tuple
        or type(definition.expected_files) is not tuple
        or type(definition.expected_symlinks) is not tuple
    ):
        raise DependencyDagExecutionPlanError(
            "definition fields have wrong exact types"
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
                raise DependencyDagExecutionPlanError(
                    "input file fields have wrong exact types"
                )
        elif type(item) is InputSymlink:
            if (
                type(item.path) is not str
                or type(item.target) is not str
            ):
                raise DependencyDagExecutionPlanError(
                    "input symlink fields have wrong exact types"
                )
        else:
            raise DependencyDagExecutionPlanError(
                "definition contains an unsupported input type"
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
            raise DependencyDagExecutionPlanError(
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
        raise DependencyDagExecutionPlanError(
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
        raise DependencyDagExecutionPlanError(
            "definition is outside the family domain"
        )
    _source_payload(definition)
    return definition


def derive_dependency_dag_execution_plan_state(
    definition: FixtureDefinition,
    parameters: DependencyDagExecutionPlanParameters,
) -> DependencyDagExecutionPlanState:
    """Derive trusted output with incremental Kahn bookkeeping."""

    _revalidate_definition(definition)
    if type(parameters) is not DependencyDagExecutionPlanParameters:
        raise DependencyDagExecutionPlanError(
            "parameters have wrong exact type"
        )
    parameters.__post_init__()
    graph = parse_dependency_dag_execution_plan_source(
        _source_payload(definition), parameters.graph_encoding
    )
    return _build_state(graph, parameters, reference=False)


def reference_dependency_dag_execution_plan_state(
    definition: FixtureDefinition,
    parameters: DependencyDagExecutionPlanParameters,
) -> DependencyDagExecutionPlanState:
    """Derive trusted output with rescans and independent reachability."""

    _revalidate_definition(definition)
    if type(parameters) is not DependencyDagExecutionPlanParameters:
        raise DependencyDagExecutionPlanError(
            "parameters have wrong exact type"
        )
    parameters.__post_init__()
    graph = parse_dependency_dag_execution_plan_source(
        _source_payload(definition), parameters.graph_encoding
    )
    return _build_state(graph, parameters, reference=True)


def _validate_output_value(value: object) -> dict[str, object]:
    output = _require_exact_keys(value, _OUTPUT_KEYS, "execution-plan output")
    _closed_text(
        output["graph_encoding"],
        DEPENDENCY_DAG_EXECUTION_PLAN_GRAPH_ENCODINGS,
        "output graph_encoding",
    )
    _closed_text(
        output["tie_break_policy"],
        DEPENDENCY_DAG_EXECUTION_PLAN_TIE_BREAK_POLICIES,
        "output tie_break_policy",
    )
    status = output["status"]
    if type(status) is not str or status not in {"valid", "cycle"}:
        raise DependencyDagExecutionPlanError(
            "output status is outside its closed set"
        )
    node_count = output["node_count"]
    edge_count = output["edge_count"]
    if (
        type(node_count) is not int
        or not 1 <= node_count <= DEPENDENCY_DAG_EXECUTION_PLAN_MAXIMUM_NODES
        or type(edge_count) is not int
        or not 0 <= edge_count <= DEPENDENCY_DAG_EXECUTION_PLAN_MAXIMUM_EDGES
    ):
        raise DependencyDagExecutionPlanError(
            "output counts violate their exact bounds"
        )
    sequences: list[list[str]] = []
    for field_name in ("plan", "blocked_nodes", "cyclic_nodes"):
        raw = output[field_name]
        if (
            type(raw) is not list
            or len(raw) > node_count
            or any(type(item) is not str for item in raw)
        ):
            raise DependencyDagExecutionPlanError(
                f"output {field_name} is not a bounded exact string array"
            )
        for item in raw:
            _validate_node_id(item, f"output {field_name} item")
        if len(raw) != len(set(raw)):
            raise DependencyDagExecutionPlanError(
                f"output {field_name} contains duplicates"
            )
        sequences.append(raw)
    plan, blocked, cyclic = sequences
    if status == "valid":
        if len(plan) != node_count or blocked or cyclic:
            raise DependencyDagExecutionPlanError(
                "valid output has incomplete or cyclic arrays"
            )
    elif (
        plan
        or not blocked
        or not cyclic
        or not set(cyclic) <= set(blocked)
        or tuple(blocked) != _raw_order(blocked)
        or tuple(cyclic) != _raw_order(cyclic)
    ):
        raise DependencyDagExecutionPlanError(
            "cycle output has invalid plan or residual arrays"
        )
    return output


def parse_dependency_dag_execution_plan_output(payload: bytes) -> bytes:
    """Validate closed semantic output and return canonical JSON bytes."""

    if (
        type(payload) is not bytes
        or not payload
        or len(payload) > DEPENDENCY_DAG_EXECUTION_PLAN_OUTPUT_MAXIMUM_BYTES
    ):
        raise DependencyDagExecutionPlanError(
            "execution-plan output violates its byte bound"
        )
    value = _decode_json_strict(payload)
    _validate_output_value(value)
    return _canonical_json(value)


_PhysicalNode: TypeAlias = tuple[str, int, tuple[str, ...]]


def _profile_graph(
    profile: ExecutableFixtureProfile,
) -> tuple[_PhysicalNode, ...]:
    if type(profile) is not ExecutableFixtureProfile:
        raise DependencyDagExecutionPlanError(
            "profile has wrong exact type"
        )
    profile_id = profile.profile_id
    if profile_id == "spaces-unicode":
        nodes = (
            ("z stable", 0, ()),
            ("f fanout 雪", 10, ()),
            ("p priority", 100, ()),
            ("a root", -10, ()),
            ('-child "quoted" \\ literal', 50, ("a root",)),
            ("fan child café", 0, ("f fanout 雪",)),
            ("fan child beta", 0, ("f fanout 雪",)),
            ("fan child gamma", 0, ("f fanout 雪",)),
            ("z child", 0, ("z stable",)),
        )
    elif profile_id == "leading-dashes-globs":
        nodes = (
            ("z-stable[*]?", 0, ()),
            ("f-fanout?", 10, ()),
            ("p-priority", 100, ()),
            ("-a-root", -10, ()),
            ("--child[*]?", 50, ("-a-root",)),
            ("fan-*", 0, ("f-fanout?",)),
            ("fan-?", 0, ("f-fanout?",)),
            ("fan-[x]", 0, ("f-fanout?",)),
            ("z-*", 0, ("z-stable[*]?",)),
        )
    elif profile_id == "empty-duplicates":
        nodes = (
            ("z-isolated", 0, ()),
            ("a-source", 2, ()),
            ("b-dependent", 1, ("a-source", "a-source")),
            (
                "c-merge",
                3,
                ("a-source", "b-dependent", "b-dependent"),
            ),
            ("empty-dependency-list", -1, ()),
        )
    elif profile_id == "symlinks-ordering":
        nodes = (
            ("z-declared-first", 0, ()),
            ("m-wide", 20, ()),
            ("y-priority", 1_000_000, ()),
            ("a-byte-first", -1_000_000, ()),
            ("-ready-after-a", 30, ("a-byte-first",)),
            ("wide-3", 0, ("m-wide",)),
            ("wide-1", 0, ("m-wide",)),
            ("wide-2", 0, ("m-wide",)),
            ("stable-child", 0, ("z-declared-first",)),
        )
    elif profile_id == "partial-permissions":
        nodes = (
            ("free-root", 1_000_000, ()),
            ("free-child", -1_000_000, ("free-root",)),
            ("cycle-a", 3, ("cycle-b",)),
            ("cycle-b", 2, ("cycle-a", "cycle-a")),
            ("downstream blocked", 1, ("cycle-a",)),
            ("self-loop", 0, ("self-loop",)),
        )
    else:
        raise DependencyDagExecutionPlanError(
            "fixture profile is outside the closed set"
        )
    for node_id, priority, prerequisites in nodes:
        _validate_node_id(node_id, "fixture node")
        _validate_priority(priority, "fixture priority")
        for prerequisite in prerequisites:
            _validate_node_id(prerequisite, "fixture prerequisite")
    return nodes


def _encode_graph(
    nodes: tuple[_PhysicalNode, ...],
    encoding: GraphEncoding,
) -> bytes:
    declarations = [(node_id, priority) for node_id, priority, _ in nodes]
    edges = [
        (node_id, prerequisite)
        for node_id, _priority, prerequisites in nodes
        for prerequisite in prerequisites
    ]
    _build_dependency_graph(declarations, edges)
    if encoding == "json-adjacency":
        payload = _canonical_json(
            {
                "nodes": [
                    {
                        "id": node_id,
                        "priority": priority,
                        "depends_on": list(prerequisites),
                    }
                    for node_id, priority, prerequisites in nodes
                ]
            }
        )
    elif encoding == "json-edge-list":
        payload = _canonical_json(
            {
                "nodes": [
                    {"id": node_id, "priority": priority}
                    for node_id, priority, _prerequisites in nodes
                ],
                "edges": [
                    {
                        "dependent": dependent,
                        "prerequisite": prerequisite,
                    }
                    for dependent, prerequisite in edges
                ],
            }
        )
    elif encoding == "csv-edges":
        stream = io.StringIO(newline="")
        writer = csv.writer(
            stream,
            dialect="excel",
            lineterminator="\r\n",
        )
        writer.writerow(("record", "node", "priority", "dependency"))
        # Dependency rows intentionally interleave node declarations.  Full
        # endpoint closure is checked only after the complete source is read.
        for node_id, priority, prerequisites in nodes:
            writer.writerow(("node", node_id, str(priority), ""))
            for prerequisite in prerequisites:
                writer.writerow(("edge", node_id, "", prerequisite))
        payload = stream.getvalue().encode("utf-8")
    elif encoding == "line-oriented-dependencies":
        payload = "".join(
            "\t".join((str(priority), node_id, *prerequisites)) + "\n"
            for node_id, priority, prerequisites in nodes
        ).encode("utf-8")
    else:
        raise DependencyDagExecutionPlanError(
            "fixture encoding is unsupported"
        )
    parsed = parse_dependency_dag_execution_plan_source(payload, encoding)
    expected = _build_dependency_graph(declarations, edges)
    if parsed != expected:
        raise DependencyDagExecutionPlanError(
            "fixture encoding changed logical graph semantics"
        )
    return payload


def _fixture_inputs(
    profile: ExecutableFixtureProfile,
    parameters: DependencyDagExecutionPlanParameters,
) -> tuple[InputFile | InputSymlink, ...]:
    nodes = _profile_graph(profile)
    source_mode = (
        0o400 if profile.profile_id == "partial-permissions" else 0o600
    )
    inputs: list[InputFile | InputSymlink] = [
        InputFile(
            DEPENDENCY_DAG_EXECUTION_PLAN_INPUT,
            _encode_graph(nodes, parameters.graph_encoding),
            source_mode,
            2_200,
        )
    ]
    if profile.profile_id == "spaces-unicode":
        inputs.append(
            InputFile(
                "input/distractors/space café.graph",
                b"ignore snow\n",
                0o444,
                2_201,
            )
        )
    elif profile.profile_id == "leading-dashes-globs":
        inputs.append(
            InputFile(
                "input/-distractor[*]?.graph",
                b"ignore literal globs\n",
                0o400,
                2_202,
            )
        )
    elif profile.profile_id == "empty-duplicates":
        inputs.append(
            InputFile(
                "input/distractors/empty",
                b"",
                0o444,
                2_203,
            )
        )
    elif profile.profile_id == "symlinks-ordering":
        inputs.extend(
            (
                InputFile(
                    "input/distractors/target",
                    b"do not follow\n",
                    0o444,
                    2_204,
                ),
                InputSymlink(
                    "input/distractors/link",
                    "target",
                ),
            )
        )
        inputs.reverse()
    elif profile.profile_id == "partial-permissions":
        inputs.append(
            InputFile(
                "input/distractors/unreadable",
                b"preserve without reading\n",
                0o000,
                2_205,
            )
        )
    else:
        raise DependencyDagExecutionPlanError(
            "fixture profile is outside the closed set"
        )
    return tuple(inputs)


def _expected_files() -> tuple[ExpectedFile, ...]:
    return (
        ExpectedFile(
            DEPENDENCY_DAG_EXECUTION_PLAN_OUTPUT,
            DEPENDENCY_DAG_EXECUTION_PLAN_OUTPUT_MAXIMUM_BYTES,
            DEPENDENCY_DAG_EXECUTION_PLAN_OUTPUT_MODE,
        ),
    )


def _oracle_sha256(
    state: DependencyDagExecutionPlanState,
    parameters: DependencyDagExecutionPlanParameters,
) -> str:
    state.__post_init__()
    parameters.__post_init__()
    if (
        state.graph_encoding != parameters.graph_encoding
        or state.tie_break_policy != parameters.tie_break_policy
    ):
        raise DependencyDagExecutionPlanError(
            "oracle state differs from parameters"
        )
    return domain_sha256(
        "cbds.executable-fixture.trusted-oracle.v1",
        {
            "schema_version": EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION,
            "semantic_verifier_identity": (
                DEPENDENCY_DAG_EXECUTION_PLAN_VERIFIER_IDENTITY
            ),
            "parameters": parameters.to_record(),
            "state": state.commitment_record(),
        },
    )


@dataclass(frozen=True, slots=True)
class DependencyDagExecutionPlanOracle:
    state: DependencyDagExecutionPlanState = field(repr=False)
    graph_encoding: GraphEncoding
    tie_break_policy: TieBreakPolicy
    oracle_sha256: str
    semantic_verifier_identity: str = (
        DEPENDENCY_DAG_EXECUTION_PLAN_VERIFIER_IDENTITY
    )
    schema_version: str = EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            type(self) is not DependencyDagExecutionPlanOracle
            or type(self.state) is not DependencyDagExecutionPlanState
        ):
            raise DependencyDagExecutionPlanError(
                "oracle or owned state has wrong exact type"
            )
        parameters = DependencyDagExecutionPlanParameters(
            self.graph_encoding, self.tie_break_policy
        )
        self.state.__post_init__()
        if (
            type(self.semantic_verifier_identity) is not str
            or self.semantic_verifier_identity
            != DEPENDENCY_DAG_EXECUTION_PLAN_VERIFIER_IDENTITY
            or type(self.schema_version) is not str
            or self.schema_version != EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION
            or self.state.graph_encoding != self.graph_encoding
            or self.state.tie_break_policy != self.tie_break_policy
            or not _is_sha256(self.oracle_sha256)
            or self.oracle_sha256 != _oracle_sha256(
                self.state, parameters
            )
        ):
            raise DependencyDagExecutionPlanError(
                "oracle identity is invalid"
            )

    def commitment_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "schema_version": self.schema_version,
            "record_type": "cbds.executable-fixture-trusted-oracle",
            "semantic_verifier_identity": self.semantic_verifier_identity,
            "graph_encoding": self.graph_encoding,
            "tie_break_policy": self.tie_break_policy,
            "state": self.state.commitment_record(),
            "oracle_sha256": self.oracle_sha256,
        }


@dataclass(frozen=True, slots=True)
class DependencyDagExecutionPlanFixtureBundle:
    task_contract_sha256: str
    profile_sha256: str
    definition: FixtureDefinition = field(repr=False)
    fixture_definition_sha256: str
    oracle: DependencyDagExecutionPlanOracle = field(repr=False)
    descriptor: OpaqueFixtureDescriptor
    schema_version: str = EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_dependency_dag_execution_plan_fixture_bundle(self)

    def commitment_record(self) -> dict[str, object]:
        validate_dependency_dag_execution_plan_fixture_bundle(self)
        return {
            "schema_version": self.schema_version,
            "record_type": "cbds.executable-fixture-private-binding",
            "binding_version": EXECUTABLE_FIXTURE_BINDING_VERSION,
            "task_contract_sha256": self.task_contract_sha256,
            "profile_sha256": self.profile_sha256,
            "fixture_definition_sha256": (
                self.fixture_definition_sha256
            ),
            "oracle": self.oracle.commitment_record(),
            "descriptor": self.descriptor.to_public_record(),
            "candidate_execution_authorized": False,
            "model_selection_eligible": False,
            "claim_authorized": False,
        }


def validate_dependency_dag_execution_plan_fixture_bundle(
    bundle: DependencyDagExecutionPlanFixtureBundle,
) -> None:
    if type(bundle) is not DependencyDagExecutionPlanFixtureBundle:
        raise DependencyDagExecutionPlanError(
            "bundle has wrong exact type"
        )
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
        raise DependencyDagExecutionPlanError(
            "bundle metadata is invalid"
        )
    definition = _revalidate_definition(bundle.definition)
    definition_sha256 = compute_fixture_definition_semantic_sha256(
        definition
    )
    if definition_sha256 != bundle.fixture_definition_sha256:
        raise DependencyDagExecutionPlanError(
            "fixture definition digest differs"
        )
    if type(bundle.oracle) is not DependencyDagExecutionPlanOracle:
        raise DependencyDagExecutionPlanError(
            "oracle has wrong exact type"
        )
    bundle.oracle.__post_init__()
    parameters = DependencyDagExecutionPlanParameters(
        bundle.oracle.graph_encoding,
        bundle.oracle.tie_break_policy,
    )
    primary = derive_dependency_dag_execution_plan_state(
        definition, parameters
    )
    reference = reference_dependency_dag_execution_plan_state(
        definition, parameters
    )
    if (
        primary != reference
        or primary != bundle.oracle.state
        or definition.expected_files != _expected_files()
    ):
        raise DependencyDagExecutionPlanError(
            "fixture output policy or oracle differs"
        )
    if type(bundle.descriptor) is not OpaqueFixtureDescriptor:
        raise DependencyDagExecutionPlanError(
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
        raise DependencyDagExecutionPlanError(
            "descriptor binding differs"
        )


def verify_dependency_dag_execution_plan_fixture_bundle(
    bundle: object,
) -> bool:
    try:
        validate_dependency_dag_execution_plan_fixture_bundle(
            bundle  # type: ignore[arg-type]
        )
    except (
        AttributeError,
        DependencyDagExecutionPlanError,
        TypeError,
        ValueError,
    ):
        return False
    return True


def _validate_task_profile(
    task: object,
    profile: object,
) -> tuple[DependencyDagExecutionPlanTask, ExecutableFixtureProfile]:
    if type(task) is not DependencyDagExecutionPlanTask:
        raise DependencyDagExecutionPlanError(
            "task has wrong exact type"
        )
    if type(profile) is not ExecutableFixtureProfile:
        raise DependencyDagExecutionPlanError(
            "profile has wrong exact type"
        )
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
        raise DependencyDagExecutionPlanError(
            "task/profile reconstruction failed"
        ) from exc
    if rebuilt not in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
        raise DependencyDagExecutionPlanError(
            "profile is outside public method development"
        )
    return task, profile


def _construct_dependency_dag_execution_plan_fixture_bundle(
    task: DependencyDagExecutionPlanTask,
    profile: ExecutableFixtureProfile,
) -> DependencyDagExecutionPlanFixtureBundle:
    task, profile = _validate_task_profile(task, profile)
    inputs = _fixture_inputs(profile, task.parameters)
    provisional = FixtureDefinition(
        f"fixture.{task.task_id}.{profile.profile_id}",
        inputs,
        (),
    )
    primary = derive_dependency_dag_execution_plan_state(
        provisional, task.parameters
    )
    reference = reference_dependency_dag_execution_plan_state(
        provisional, task.parameters
    )
    if primary != reference:
        raise DependencyDagExecutionPlanError(
            "independent dependency planners disagree"
        )
    definition = FixtureDefinition(
        provisional.fixture_id,
        inputs,
        _expected_files(),
    )
    if (
        derive_dependency_dag_execution_plan_state(
            definition, task.parameters
        )
        != primary
        or reference_dependency_dag_execution_plan_state(
            definition, task.parameters
        )
        != reference
    ):
        raise DependencyDagExecutionPlanError(
            "final output policy changed semantics"
        )
    oracle = DependencyDagExecutionPlanOracle(
        primary,
        task.parameters.graph_encoding,
        task.parameters.tie_break_policy,
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
    return DependencyDagExecutionPlanFixtureBundle(
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


def build_dependency_dag_execution_plan_fixture_bundle(
    task: DependencyDagExecutionPlanTask,
    profile: ExecutableFixtureProfile,
) -> DependencyDagExecutionPlanFixtureBundle:
    selected_task, selected_profile = _validate_task_profile(task, profile)
    bundle = _construct_dependency_dag_execution_plan_fixture_bundle(
        selected_task, selected_profile
    )
    index = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES.index(selected_profile)
    if selected_task.fixtures[index] != bundle.descriptor:
        raise DependencyDagExecutionPlanError(
            "task descriptor differs from reconstructed fixture"
        )
    return bundle


def validate_dependency_dag_execution_plan_fixture_for_task_profile(
    task: DependencyDagExecutionPlanTask,
    profile: ExecutableFixtureProfile,
    bundle: DependencyDagExecutionPlanFixtureBundle,
) -> None:
    selected_task, selected_profile = _validate_task_profile(task, profile)
    validate_dependency_dag_execution_plan_fixture_bundle(bundle)
    expected = _construct_dependency_dag_execution_plan_fixture_bundle(
        selected_task, selected_profile
    )
    if expected != bundle:
        raise DependencyDagExecutionPlanError(
            "bundle differs from deterministic reconstruction"
        )
    index = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES.index(selected_profile)
    if selected_task.fixtures[index] != bundle.descriptor:
        raise DependencyDagExecutionPlanError(
            "public descriptor differs from private binding"
        )


def verify_dependency_dag_execution_plan_fixture_for_task_profile(
    task: object,
    profile: object,
    bundle: object,
) -> bool:
    try:
        validate_dependency_dag_execution_plan_fixture_for_task_profile(
            task,  # type: ignore[arg-type]
            profile,  # type: ignore[arg-type]
            bundle,  # type: ignore[arg-type]
        )
    except (
        AttributeError,
        DependencyDagExecutionPlanError,
        TypeError,
        ValueError,
    ):
        return False
    return True


def _discrimination_signature(
    bundle: DependencyDagExecutionPlanFixtureBundle,
) -> tuple[str, str]:
    return (
        sha256(_source_payload(bundle.definition)).hexdigest(),
        _outcome_sha256(bundle.oracle.state),
    )


def _outcome_sha256(state: DependencyDagExecutionPlanState) -> str:
    """Commit only to behavior, excluding echoed task-axis labels."""

    if type(state) is not DependencyDagExecutionPlanState:
        raise DependencyDagExecutionPlanError(
            "discrimination outcome has wrong exact type"
        )
    state.__post_init__()
    return domain_sha256(
        "cbds.executable-static.dependency-dag-execution-plan."
        "behavioral-outcome.v1",
        {
            "status": state.status,
            "node_count": state.node_count,
            "edge_count": state.edge_count,
            "plan": list(state.plan),
            "blocked_nodes": list(state.blocked_nodes),
            "cyclic_nodes": list(state.cyclic_nodes),
        },
    )


def compute_dependency_dag_execution_plan_discrimination_sha256(
    tasks: tuple[DependencyDagExecutionPlanTask, ...],
) -> str:
    expected = tuple(
        (encoding, policy)
        for encoding in DEPENDENCY_DAG_EXECUTION_PLAN_GRAPH_ENCODINGS
        for policy in DEPENDENCY_DAG_EXECUTION_PLAN_TIE_BREAK_POLICIES
    )
    if (
        type(tasks) is not tuple
        or len(tasks) != 20
        or any(
            type(task) is not DependencyDagExecutionPlanTask
            for task in tasks
        )
        or tuple(
            (
                task.parameters.graph_encoding,
                task.parameters.tie_break_policy,
            )
            for task in tasks
        )
        != expected
    ):
        raise DependencyDagExecutionPlanError(
            "discrimination requires canonical 20-cell task order"
        )
    profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
    signatures = tuple(
        _discrimination_signature(
            _construct_dependency_dag_execution_plan_fixture_bundle(
                task, profile
            )
        )
        for task in tasks
    )
    if len(set(signatures)) != len(signatures):
        raise DependencyDagExecutionPlanError(
            "task grid is not behaviorally discriminable"
        )
    # Axis names, prompts, graph labels, and task IDs are deliberately absent.
    return domain_sha256(
        "cbds.executable-static.dependency-dag-execution-plan."
        "discrimination-evidence.v1",
        {
            "family_id": DEPENDENCY_DAG_EXECUTION_PLAN_FAMILY_ID,
            "profile_sha256": profile.profile_sha256,
            "signature_count": len(signatures),
            "outcomes": [
                {
                    "source_sha256": source_sha256,
                    "output_sha256": output_sha256,
                }
                for source_sha256, output_sha256 in signatures
            ],
        },
    )


def build_dependency_dag_execution_plan_tasks() -> tuple[
    DependencyDagExecutionPlanTask, ...
]:
    tasks: list[DependencyDagExecutionPlanTask] = []
    signatures: list[tuple[str, str]] = []
    for encoding in DEPENDENCY_DAG_EXECUTION_PLAN_GRAPH_ENCODINGS:
        for policy in DEPENDENCY_DAG_EXECUTION_PLAN_TIE_BREAK_POLICIES:
            bootstrap = _bootstrap_task(
                DependencyDagExecutionPlanParameters(encoding, policy)
            )
            bundles = tuple(
                _construct_dependency_dag_execution_plan_fixture_bundle(
                    bootstrap, profile
                )
                for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
            )
            task = replace(
                bootstrap,
                fixtures=tuple(
                    bundle.descriptor for bundle in bundles
                ),
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
        raise DependencyDagExecutionPlanError(
            "task grid is not 20 discriminable cells"
        )
    return selected


def compute_dependency_dag_execution_plan_proved_output_bound() -> int:
    """Reconstruct a conservative bound for the one output file."""

    identifier = "\\" * (
        DEPENDENCY_DAG_EXECUTION_PLAN_NODE_ID_MAXIMUM_UTF8_BYTES
    )
    maximum_ids = [
        f"{index:02d}"
        + identifier[
            2:DEPENDENCY_DAG_EXECUTION_PLAN_NODE_ID_MAXIMUM_UTF8_BYTES
        ]
        for index in range(DEPENDENCY_DAG_EXECUTION_PLAN_MAXIMUM_NODES)
    ]
    valid = {
        "graph_encoding": "line-oriented-dependencies",
        "tie_break_policy": "stable-input-order",
        "status": "valid",
        "node_count": DEPENDENCY_DAG_EXECUTION_PLAN_MAXIMUM_NODES,
        "edge_count": DEPENDENCY_DAG_EXECUTION_PLAN_MAXIMUM_EDGES,
        "plan": maximum_ids,
        "blocked_nodes": [],
        "cyclic_nodes": [],
    }
    cycle = {
        **valid,
        "status": "cycle",
        "plan": [],
        "blocked_nodes": maximum_ids,
        "cyclic_nodes": maximum_ids,
    }
    if (
        max(len(_canonical_json(valid)), len(_canonical_json(cycle)))
        > DEPENDENCY_DAG_EXECUTION_PLAN_OUTPUT_MAXIMUM_BYTES
        or DEPENDENCY_DAG_EXECUTION_PLAN_PROVED_MAXIMUM_TOTAL_OUTPUT_BYTES
        > MAX_TOTAL_BYTES
    ):
        raise DependencyDagExecutionPlanError(
            "output bound proof exceeds a declared ceiling"
        )
    return DEPENDENCY_DAG_EXECUTION_PLAN_PROVED_MAXIMUM_TOTAL_OUTPUT_BYTES


def materialize_dependency_dag_execution_plan_fixture(
    task: DependencyDagExecutionPlanTask,
    profile: ExecutableFixtureProfile,
    bundle: DependencyDagExecutionPlanFixtureBundle,
    workspace: str | os.PathLike[str],
) -> WorkspaceHandle:
    validate_dependency_dag_execution_plan_fixture_for_task_profile(
        task, profile, bundle
    )
    return materialize_fixture(bundle.definition, workspace)


def verify_dependency_dag_execution_plan_workspace(
    task: DependencyDagExecutionPlanTask,
    profile: ExecutableFixtureProfile,
    bundle: DependencyDagExecutionPlanFixtureBundle,
    handle: WorkspaceHandle,
) -> bool:
    """Verify the exact semantic output tree and pinned input state."""

    if type(handle) is not WorkspaceHandle:
        return False
    try:
        validate_dependency_dag_execution_plan_fixture_for_task_profile(
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
        primary = derive_dependency_dag_execution_plan_state(
            bundle.definition, task.parameters
        )
        reference = reference_dependency_dag_execution_plan_state(
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
            or output_entries[0].path
            != DEPENDENCY_DAG_EXECUTION_PLAN_OUTPUT
            or output_entries[0].mode
            != DEPENDENCY_DAG_EXECUTION_PLAN_OUTPUT_MODE
            or output_entries[0].link_count != 1
            or output_entries[0].hardlink_group_sha256 is not None
        ):
            return False
        observed = handle.read_output_bytes(
            output_scan, DEPENDENCY_DAG_EXECUTION_PLAN_OUTPUT
        )
        if (
            parse_dependency_dag_execution_plan_output(observed)
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
        DependencyDagExecutionPlanError,
        OSError,
        TypeError,
        ValueError,
    ):
        return False


__all__ = [
    "DEPENDENCY_DAG_EXECUTION_PLAN_ALLOWED_TOOLS",
    "DEPENDENCY_DAG_EXECUTION_PLAN_ATOMICITY_OBSERVED",
    "DEPENDENCY_DAG_EXECUTION_PLAN_CANDIDATE_EXIT_STATUS_OBSERVED",
    "DEPENDENCY_DAG_EXECUTION_PLAN_FAMILY_ID",
    "DEPENDENCY_DAG_EXECUTION_PLAN_FILESYSTEM_IDENTITY",
    "DEPENDENCY_DAG_EXECUTION_PLAN_FINAL_OUTPUT_OBSERVED",
    "DEPENDENCY_DAG_EXECUTION_PLAN_GENERATOR_VERSION",
    "DEPENDENCY_DAG_EXECUTION_PLAN_GRAPH_ENCODINGS",
    "DEPENDENCY_DAG_EXECUTION_PLAN_INPUT",
    "DEPENDENCY_DAG_EXECUTION_PLAN_INPUT_PRESERVATION_OBSERVED",
    "DEPENDENCY_DAG_EXECUTION_PLAN_JSON_MAXIMUM_DEPTH",
    "DEPENDENCY_DAG_EXECUTION_PLAN_JSON_MAXIMUM_NODES",
    "DEPENDENCY_DAG_EXECUTION_PLAN_MAXIMUM_EDGES",
    "DEPENDENCY_DAG_EXECUTION_PLAN_MAXIMUM_NODES",
    "DEPENDENCY_DAG_EXECUTION_PLAN_MAXIMUM_PHYSICAL_DEPENDENCIES",
    "DEPENDENCY_DAG_EXECUTION_PLAN_NODE_ID_MAXIMUM_UTF8_BYTES",
    "DEPENDENCY_DAG_EXECUTION_PLAN_OUTPUT",
    "DEPENDENCY_DAG_EXECUTION_PLAN_OUTPUT_IDENTITY",
    "DEPENDENCY_DAG_EXECUTION_PLAN_OUTPUT_MAXIMUM_BYTES",
    "DEPENDENCY_DAG_EXECUTION_PLAN_OUTPUT_MODE",
    "DEPENDENCY_DAG_EXECUTION_PLAN_PRIORITY_MAXIMUM",
    "DEPENDENCY_DAG_EXECUTION_PLAN_PROVED_MAXIMUM_TOTAL_OUTPUT_BYTES",
    "DEPENDENCY_DAG_EXECUTION_PLAN_READ_SCOPE_OBSERVED",
    "DEPENDENCY_DAG_EXECUTION_PLAN_SOURCE_MAXIMUM_BYTES",
    "DEPENDENCY_DAG_EXECUTION_PLAN_TIE_BREAK_POLICIES",
    "DEPENDENCY_DAG_EXECUTION_PLAN_TOOL_HISTORY_OBSERVED",
    "DEPENDENCY_DAG_EXECUTION_PLAN_TRANSIENT_STATE_OBSERVED",
    "DEPENDENCY_DAG_EXECUTION_PLAN_VERIFIER_IDENTITY",
    "DEPENDENCY_DAG_EXECUTION_PLAN_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE",
    "DEPENDENCY_DAG_EXECUTION_PLAN_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE",
    "DependencyDag",
    "DependencyDagExecutionPlanError",
    "DependencyDagExecutionPlanFixtureBundle",
    "DependencyDagExecutionPlanOracle",
    "DependencyDagExecutionPlanParameters",
    "DependencyDagExecutionPlanState",
    "DependencyDagExecutionPlanTask",
    "DependencyDagNode",
    "GraphEncoding",
    "TieBreakPolicy",
    "build_dependency_dag_execution_plan_fixture_bundle",
    "build_dependency_dag_execution_plan_tasks",
    "compute_dependency_dag_execution_plan_discrimination_sha256",
    "compute_dependency_dag_execution_plan_proved_output_bound",
    "compute_dependency_dag_execution_plan_task_sha256",
    "dependency_dag_execution_plan_task_semantic_core",
    "derive_dependency_dag_execution_plan_state",
    "materialize_dependency_dag_execution_plan_fixture",
    "parse_dependency_dag_execution_plan_output",
    "parse_dependency_dag_execution_plan_source",
    "reference_dependency_dag_execution_plan_state",
    "validate_dependency_dag_execution_plan_fixture_bundle",
    "validate_dependency_dag_execution_plan_fixture_for_task_profile",
    "verify_dependency_dag_execution_plan_fixture_bundle",
    "verify_dependency_dag_execution_plan_fixture_for_task_profile",
    "verify_dependency_dag_execution_plan_workspace",
]
