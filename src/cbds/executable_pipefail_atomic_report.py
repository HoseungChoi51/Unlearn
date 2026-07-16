"""Public method-development family for atomic pipeline status reports.

The family exercises complete-stream pipeline processing, ordered per-stage
status capture, first/last failure selection, deterministic aggregation, and
failure-dependent atomic publication contracts.  Logical stage status is
fixture data: every stage consumes its complete stream before returning that
configured status, avoiding SIGPIPE and scheduler races in the specification.

Two separately structured trusted implementations parse the immutable fixture
records and derive the answer.  They must agree before a fixture is admitted or
an output is accepted.  This family is local to this module: it runs no
subprocess, grants no candidate-execution or scoring authority, and does not
widen a frozen registry or invocation contract.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import json
import os
from pathlib import PurePosixPath
import re
import unicodedata
from typing import Final, Literal, TypeAlias

from .benchmark import NormalizedSemanticGraph, OperatorNode
from .executable_fixture_bundle import (
    EXECUTABLE_FIXTURE_BINDING_VERSION,
    EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION,
    OracleOutputRecord,
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
    ExecutableWorkspaceError,
    ExpectedFile,
    FixtureDefinition,
    InputFile,
    InputSymlink,
    WorkspaceHandle,
    materialize_fixture,
    validate_expected_output_policy,
)


PIPEFAIL_ATOMIC_REPORT_FAMILY_ID: Final[str] = "pipefail-atomic-report"
PIPEFAIL_ATOMIC_REPORT_FILESYSTEM_IDENTITY: Final[str] = (
    "pipeline-record-streams"
)
PIPEFAIL_ATOMIC_REPORT_OUTPUT_IDENTITY: Final[str] = (
    "atomic-pipeline-status-json"
)
PIPEFAIL_ATOMIC_REPORT_GENERATOR_VERSION: Final[str] = "1.0.0"
PIPEFAIL_ATOMIC_REPORT_VERIFIER_IDENTITY: Final[str] = (
    "verify-pipefail-atomic-report-v1"
)
PIPEFAIL_ATOMIC_REPORT_ROOT: Final[PurePosixPath] = PurePosixPath(
    "input/pipeline"
)
PIPEFAIL_ATOMIC_REPORT_DATA_ROOT: Final[PurePosixPath] = PurePosixPath(
    "input/pipeline/data"
)
PIPEFAIL_ATOMIC_REPORT_SOURCES: Final[str] = "input/pipeline/sources.tsv"
PIPEFAIL_ATOMIC_REPORT_STATUSES: Final[str] = "input/pipeline/status.tsv"
PIPEFAIL_ATOMIC_REPORT_PRIOR: Final[str] = "input/pipeline/prior-report.json"
PIPEFAIL_ATOMIC_REPORT_OUTPUT: Final[str] = "output/report.json"
PIPEFAIL_ATOMIC_REPORT_OUTPUT_MODE: Final[int] = 0o644
PIPEFAIL_ATOMIC_REPORT_OUTPUT_MAXIMUM_BYTES: Final[int] = 64 * 1024
PIPEFAIL_ATOMIC_REPORT_ALLOWED_TOOLS: Final[tuple[str, ...]] = (
    "awk",
    "grep",
    "mkdir",
    "mv",
    "sed",
    "sort",
)

# Honest final-state observability boundaries.  Exact input/output scans can
# establish the resulting tree, but cannot attest how a candidate got there.
PIPEFAIL_ATOMIC_REPORT_SYMLINK_DISTRACTORS_COVERED: Final[bool] = True
PIPEFAIL_ATOMIC_REPORT_DIRECTORY_PERMISSION_ERRORS_COVERED: Final[bool] = False
PIPEFAIL_ATOMIC_REPORT_EFFECTIVE_ACCESS_FAILURES_COVERED: Final[bool] = False
PIPEFAIL_ATOMIC_REPORT_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE: Final[
    bool
] = True
PIPEFAIL_ATOMIC_REPORT_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE: Final[
    bool
] = False
PIPEFAIL_ATOMIC_REPORT_ATOMIC_PUBLICATION_HISTORY_OBSERVED: Final[bool] = False
PIPEFAIL_ATOMIC_REPORT_PIPELINE_STATUS_HISTORY_OBSERVED: Final[bool] = False
PIPEFAIL_ATOMIC_REPORT_TOOL_HISTORY_OBSERVED: Final[bool] = False
# Direct aliases make the two specific unobservable mechanisms explicit to
# callers without implying that a final-state scan can attest their history.
PIPEFAIL_ATOMIC_REPORT_ATOMIC_PUBLICATION_OBSERVED: Final[bool] = False
PIPEFAIL_ATOMIC_REPORT_PIPESTATUS_HISTORY_OBSERVED: Final[bool] = False
PIPEFAIL_ATOMIC_REPORT_PIPELINE_TOPOLOGY_HISTORY_OBSERVED: Final[bool] = False

PipelineShape: TypeAlias = Literal[
    "linear-two-stage",
    "linear-four-stage",
    "fan-in-merge",
    "tee-and-reduce",
]
FailureCommitPolicy: TypeAlias = Literal[
    "commit-success-only",
    "write-status-always",
    "rollback-on-any-failure",
    "preserve-first-failure",
    "preserve-last-failure",
]

PIPEFAIL_ATOMIC_REPORT_PIPELINE_SHAPES: Final[tuple[PipelineShape, ...]] = (
    "linear-two-stage",
    "linear-four-stage",
    "fan-in-merge",
    "tee-and-reduce",
)
PIPEFAIL_ATOMIC_REPORT_FAILURE_COMMIT_POLICIES: Final[
    tuple[FailureCommitPolicy, ...]
] = (
    "commit-success-only",
    "write-status-always",
    "rollback-on-any-failure",
    "preserve-first-failure",
    "preserve-last-failure",
)

_STAGES: Final[dict[PipelineShape, tuple[str, ...]]] = {
    "linear-two-stage": ("select-enabled", "reduce"),
    "linear-four-stage": (
        "select-enabled",
        "normalize-key",
        "select-positive",
        "reduce",
    ),
    "fan-in-merge": (
        "left-select",
        "left-project",
        "right-select",
        "right-project",
        "merge-sort",
        "reduce",
    ),
    "tee-and-reduce": (
        "select-enabled",
        "normalize-key",
        "tee",
        "audit",
        "reduce",
    ),
}
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_TASK_ID_RE: Final[re.Pattern[str]] = re.compile(r"mds-[0-9a-f]{24}\Z")
_CANONICAL_INTEGER_RE: Final[re.Pattern[bytes]] = re.compile(
    rb"(?:0|-[1-9][0-9]{0,6}|[1-9][0-9]{0,6})\Z"
)
_CANONICAL_STATUS_RE: Final[re.Pattern[bytes]] = re.compile(
    rb"(?:0|[1-9][0-9]{0,2})\Z"
)
_MINIMUM_VALUE: Final[int] = -1_000_000
_MAXIMUM_VALUE: Final[int] = 1_000_000
_PRIOR_JSON_MAXIMUM_DEPTH: Final[int] = 64
_PRIOR_JSON_MAXIMUM_NODES: Final[int] = 4_096


class PipefailAtomicReportError(ValueError):
    """Raised when a task, fixture, or semantic report fails closed."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def _closed_text(value: object, allowed: tuple[str, ...], field_name: str) -> str:
    if type(value) is not str or value not in allowed:
        raise PipefailAtomicReportError(
            f"{field_name} is outside the closed family contract"
        )
    return value


@dataclass(frozen=True, slots=True)
class PipefailAtomicReportParameters:
    """One cell in the four-shape by five-publication-policy grid."""

    pipeline_shape: PipelineShape
    failure_commit_policy: FailureCommitPolicy

    def __post_init__(self) -> None:
        _closed_text(
            self.pipeline_shape,
            PIPEFAIL_ATOMIC_REPORT_PIPELINE_SHAPES,
            "pipeline_shape",
        )
        _closed_text(
            self.failure_commit_policy,
            PIPEFAIL_ATOMIC_REPORT_FAILURE_COMMIT_POLICIES,
            "failure_commit_policy",
        )

    def to_record(self) -> dict[str, str]:
        self.__post_init__()
        return {
            "parameter_type": PIPEFAIL_ATOMIC_REPORT_FAMILY_ID,
            "pipeline_shape": self.pipeline_shape,
            "failure_commit_policy": self.failure_commit_policy,
        }


_SHAPE_TEXT: Final[dict[PipelineShape, str]] = {
    "linear-two-stage": (
        "Read every listed `main` source exactly once.  The aggregate result is "
        "independent of source-manifest enumeration order.  The "
        "`select-enabled` stage keeps enabled=`yes` rows.  The `reduce` stage "
        "groups the surviving case-sensitive keys and computes count and sum."
    ),
    "linear-four-stage": (
        "Read every listed `main` source exactly once; source-manifest "
        "enumeration order does not affect the aggregate result.  "
        "`select-enabled` keeps enabled=`yes`; `normalize-key` maps only ASCII "
        "A through Z in each key to lowercase; `select-positive` keeps values "
        "strictly greater than zero; and `reduce` groups keys into count/sum."
    ),
    "fan-in-merge": (
        "Process every listed `left` and `right` source exactly once.  Source-"
        "manifest enumeration order does not affect the aggregate result.  "
        "Each branch select stage "
        "keeps enabled=`yes` rows.  "
        "Each project stage maps only ASCII A through Z in every key to "
        "lowercase; `left-project` preserves values and `right-project` "
        "negates values.  All other key bytes, including non-ASCII UTF-8, "
        "survive unchanged.  "
        "`merge-sort` concatenates both projected streams and sorts records by "
        "raw key bytes; `reduce` groups keys into count/sum."
    ),
    "tee-and-reduce": (
        "Read every listed `main` source exactly once; source-manifest "
        "enumeration order does not affect the aggregate result.  "
        "`select-enabled` keeps enabled=`yes`; `normalize-key` maps only ASCII "
        "A through Z in each key to lowercase; the logical `tee` fans the "
        "complete immutable record stream to `audit` and `reduce` without the "
        "external tee utility.  Audit reports global record count and value "
        "sum, while reduce groups keys into count/sum."
    ),
}

_POLICY_TEXT: Final[dict[FailureCommitPolicy, str]] = {
    "commit-success-only": (
        "On any nonzero status, leave no output path and no `output/` directory."
    ),
    "write-status-always": (
        "On any nonzero status, publish a status report with decision `status`, "
        "the full ordered pipeline vector, null selected_failure and audit, "
        "and an empty result."
    ),
    "rollback-on-any-failure": (
        "On any nonzero status, publish the exact bytes of "
        "`input/pipeline/prior-report.json`."
    ),
    "preserve-first-failure": (
        "On any nonzero status, publish the status report and select the "
        "earliest nonzero stage in canonical stage order."
    ),
    "preserve-last-failure": (
        "On any nonzero status, publish the status report and select the latest "
        "nonzero stage in canonical stage order."
    ),
}


def _task_contract(
    parameters: PipefailAtomicReportParameters,
) -> tuple[str, NormalizedSemanticGraph]:
    stages = _STAGES[parameters.pipeline_shape]
    prompt = f"""Write one Bash program that operates only in the current workspace.

Read `input/pipeline/sources.tsv`.  It is strict LF-terminated UTF-8 TSV with
ROLE and a literal relative path under `input/pipeline/data/`; ROLE is `main`,
`left`, or `right`.  Paths are unique, canonical, and name regular owner-readable
files.  The linear and tee shapes contain one or more `main` rows and no other
role; fan-in contains one or more each of `left` and `right` and no `main`.
Process every listed source exactly once.  Manifest rows may occur in any
order, and the aggregate result must not depend on their physical row order.
Do not follow or read unlisted symbolic links or files.

Every data source is either empty or strict LF-terminated UTF-8 TSV.  A row has
exactly ENABLED, KEY, VALUE, MESSAGE.  ENABLED is `yes` or `no`; KEY and MESSAGE
are nonempty strict UTF-8.  KEY contains no Unicode control character, double
quote, or backslash.  MESSAGE excludes NUL, tab, and LF but may contain other
Unicode control characters.  VALUE is canonical decimal in
[-1000000,1000000].  No quoting or escaping is interpreted.

{_SHAPE_TEXT[parameters.pipeline_shape]}

Read `input/pipeline/status.tsv`, which contains each canonical logical stage
exactly once as STAGE and a canonical decimal status from 0 through 125 in
arbitrary row order.  Canonical stage order is {', '.join(stages)}.  Every
logical stage must consume and emit its complete specified stream before it
returns its configured status; do not make data semantics depend on a
short-circuited pipe or SIGPIPE timing.  Capture and report every status in
canonical order.

When every status is zero, every policy publishes one compact canonical UTF-8
JSON object plus LF to `output/report.json`: sorted object keys, literal Unicode,
version 1, this shape, decision `success`, the full ordered pipeline array,
selected_failure null, the byte-sorted result array, and audit null except for
the tee shape.  Result entries contain key, count, and mathematical sum.
{_POLICY_TEXT[parameters.failure_commit_policy]}
The configured logical-stage codes are report data, not the Bash program's
final status.  After completely handling those codes and applying the selected
commit policy, exit with status 0.

For every published report, including byte-exact rollback output, create a
sibling temporary regular file, set mode 0644, and atomically rename it to
`output/report.json`; remove every temporary path.  Leave a real mode-0755
`output/`, a mode-0644 independent
regular report with link count one when a report is required, and no other
non-input path.  Preserve every input path, kind, mode, byte, modification time,
hard-link count, and symlink target.  Use only Bash built-ins plus `awk`, `grep`,
`mkdir`, `mv`, `sed`, and `sort`.
"""
    nodes: list[OperatorNode] = [
        OperatorNode(
            "parse_pipeline_source_manifest",
            ("path:input/pipeline/sources.tsv", "source-order:nonsemantic"),
        ),
        OperatorNode(
            "execute_complete_logical_pipeline",
            (f"shape:{parameters.pipeline_shape}", f"stages:{','.join(stages)}"),
        ),
        OperatorNode(
            "capture_full_pipeline_status",
            ("path:input/pipeline/status.tsv", "range:0..125"),
        ),
        OperatorNode(
            "apply_failure_commit_policy",
            (
                f"policy:{parameters.failure_commit_policy}",
                "candidate-exit:0-after-policy",
            ),
        ),
        OperatorNode(
            "publish_atomic_status_json",
            ("path:output/report.json", "mode:0644", "rename:sibling"),
        ),
    ]
    graph = NormalizedSemanticGraph(
        nodes=tuple(nodes),
        dependencies=((0, 1), (1, 2), (2, 3), (3, 4)),
    )
    return prompt, graph


def _validate_graph(graph: object) -> NormalizedSemanticGraph:
    if type(graph) is not NormalizedSemanticGraph:
        raise PipefailAtomicReportError("graph must have the exact graph type")
    if type(graph.nodes) is not tuple or not graph.nodes:
        raise PipefailAtomicReportError("graph nodes must be a nonempty tuple")
    if type(graph.dependencies) is not tuple:
        raise PipefailAtomicReportError("graph dependencies must be a tuple")
    for node in graph.nodes:
        if (
            type(node) is not OperatorNode
            or type(node.name) is not str
            or not node.name
            or "\0" in node.name
            or type(node.parameters) is not tuple
            or any(type(value) is not str for value in node.parameters)
        ):
            raise PipefailAtomicReportError("graph contains a noncanonical node")
    for edge in graph.dependencies:
        if (
            type(edge) is not tuple
            or len(edge) != 2
            or any(type(index) is not int for index in edge)
        ):
            raise PipefailAtomicReportError("graph contains a noncanonical edge")
        source, target = edge
        if source < 0 or source >= target or target >= len(graph.nodes):
            raise PipefailAtomicReportError("graph edge violates canonical order")
    try:
        rebuilt = NormalizedSemanticGraph(
            nodes=tuple(
                OperatorNode(node.name, node.parameters) for node in graph.nodes
            ),
            dependencies=graph.dependencies,
        )
    except (TypeError, ValueError) as exc:
        raise PipefailAtomicReportError("graph reconstruction failed") from exc
    if rebuilt != graph:
        raise PipefailAtomicReportError("graph changed during reconstruction")
    return graph


def pipefail_atomic_report_task_semantic_core(
    parameters: PipefailAtomicReportParameters,
    prompt: str,
    graph: NormalizedSemanticGraph,
) -> dict[str, object]:
    if type(parameters) is not PipefailAtomicReportParameters:
        raise PipefailAtomicReportError("parameters have the wrong exact type")
    parameters.__post_init__()
    if type(prompt) is not str or not prompt.strip() or "\0" in prompt:
        raise PipefailAtomicReportError("prompt must be exact nonempty text")
    _validate_graph(graph)
    expected_prompt, expected_graph = _task_contract(parameters)
    if prompt != expected_prompt or graph != expected_graph:
        raise PipefailAtomicReportError("prompt or graph differs from contract")
    return {
        "schema_version": EXECUTABLE_STATIC_SCHEMA_VERSION,
        "contract_version": EXECUTABLE_STATIC_CONTRACT_VERSION,
        "split_role": METHOD_DEVELOPMENT_SPLIT,
        "family_id": PIPEFAIL_ATOMIC_REPORT_FAMILY_ID,
        "family_version": EXECUTABLE_STATIC_FAMILY_VERSION,
        "parameters": parameters.to_record(),
        "prompt": prompt,
        "graph": graph.to_record(),
        "graph_sha256": graph.hash,
        "filesystem_identity": PIPEFAIL_ATOMIC_REPORT_FILESYSTEM_IDENTITY,
        "output_identity": PIPEFAIL_ATOMIC_REPORT_OUTPUT_IDENTITY,
        "allowed_tools": list(PIPEFAIL_ATOMIC_REPORT_ALLOWED_TOOLS),
        "public": True,
        "sealed": False,
        "candidate_execution_authorized": False,
        "model_selection_eligible": False,
        "claim_authorized": False,
    }


def compute_pipefail_atomic_report_task_sha256(
    parameters: PipefailAtomicReportParameters,
    prompt: str,
    graph: NormalizedSemanticGraph,
) -> str:
    return domain_sha256(
        "cbds.executable-static.task-contract.v1",
        pipefail_atomic_report_task_semantic_core(parameters, prompt, graph),
    )


@dataclass(frozen=True, slots=True)
class PipefailAtomicReportTask:
    task_id: str
    parameters: PipefailAtomicReportParameters
    prompt: str
    graph: NormalizedSemanticGraph
    fixtures: tuple[OpaqueFixtureDescriptor, ...]
    task_contract_sha256: str
    family_id: str = PIPEFAIL_ATOMIC_REPORT_FAMILY_ID
    family_version: str = EXECUTABLE_STATIC_FAMILY_VERSION
    filesystem_identity: str = PIPEFAIL_ATOMIC_REPORT_FILESYSTEM_IDENTITY
    output_identity: str = PIPEFAIL_ATOMIC_REPORT_OUTPUT_IDENTITY
    allowed_tools: tuple[str, ...] = PIPEFAIL_ATOMIC_REPORT_ALLOWED_TOOLS
    split_role: str = METHOD_DEVELOPMENT_SPLIT
    public: bool = True
    sealed: bool = False
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.parameters) is not PipefailAtomicReportParameters
            or type(self.family_id) is not str
            or self.family_id != PIPEFAIL_ATOMIC_REPORT_FAMILY_ID
            or type(self.family_version) is not str
            or self.family_version != EXECUTABLE_STATIC_FAMILY_VERSION
            or type(self.filesystem_identity) is not str
            or self.filesystem_identity != PIPEFAIL_ATOMIC_REPORT_FILESYSTEM_IDENTITY
            or type(self.output_identity) is not str
            or self.output_identity != PIPEFAIL_ATOMIC_REPORT_OUTPUT_IDENTITY
            or type(self.allowed_tools) is not tuple
            or self.allowed_tools != PIPEFAIL_ATOMIC_REPORT_ALLOWED_TOOLS
            or any(type(tool) is not str for tool in self.allowed_tools)
            or type(self.split_role) is not str
            or self.split_role != METHOD_DEVELOPMENT_SPLIT
            or self.public is not True
            or self.sealed is not False
            or self.candidate_execution_authorized is not False
            or self.model_selection_eligible is not False
            or self.claim_authorized is not False
        ):
            raise PipefailAtomicReportError("task metadata is invalid")
        expected = compute_pipefail_atomic_report_task_sha256(
            self.parameters, self.prompt, self.graph
        )
        if (
            type(self.task_id) is not str
            or _TASK_ID_RE.fullmatch(self.task_id) is None
            or not _is_sha256(self.task_contract_sha256)
            or self.task_contract_sha256 != expected
            or self.task_id != task_id_from_contract(expected)
        ):
            raise PipefailAtomicReportError("task identity is invalid")
        if (
            type(self.fixtures) is not tuple
            or len(self.fixtures) != len(PUBLIC_DEVELOPMENT_FIXTURE_PROFILES)
            or any(type(item) is not OpaqueFixtureDescriptor for item in self.fixtures)
        ):
            raise PipefailAtomicReportError("task fixture descriptors are invalid")
        for descriptor in self.fixtures:
            descriptor.__post_init__()
        if (
            len({item.fixture_id for item in self.fixtures}) != 5
            or any(item.task_contract_sha256 != expected for item in self.fixtures)
        ):
            raise PipefailAtomicReportError("task descriptor binding is invalid")

    @property
    def graph_sha256(self) -> str:
        self.__post_init__()
        return self.graph.hash

    def to_public_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            **pipefail_atomic_report_task_semantic_core(
                self.parameters, self.prompt, self.graph
            ),
            "task_id": self.task_id,
            "task_contract_sha256": self.task_contract_sha256,
            "fixtures": [item.to_public_record() for item in self.fixtures],
        }


def _bootstrap_descriptors(
    task_contract_sha256: str,
) -> tuple[OpaqueFixtureDescriptor, ...]:
    result: list[OpaqueFixtureDescriptor] = []
    for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
        digest = domain_sha256(
            "cbds.executable-static.fixture.v1",
            {
                "task_contract_sha256": task_contract_sha256,
                "profile_sha256": profile.profile_sha256,
            },
        )
        result.append(
            OpaqueFixtureDescriptor(
                fixture_id=f"fx-{digest[:24]}",
                fixture_sha256=digest,
                task_contract_sha256=task_contract_sha256,
            )
        )
    return tuple(result)


def _bootstrap_task(
    parameters: PipefailAtomicReportParameters,
) -> PipefailAtomicReportTask:
    prompt, graph = _task_contract(parameters)
    digest = compute_pipefail_atomic_report_task_sha256(parameters, prompt, graph)
    return PipefailAtomicReportTask(
        task_id=task_id_from_contract(digest),
        parameters=parameters,
        prompt=prompt,
        graph=graph,
        fixtures=_bootstrap_descriptors(digest),
        task_contract_sha256=digest,
    )


def build_pipefail_atomic_report_tasks() -> tuple[PipefailAtomicReportTask, ...]:
    """Build the deterministic 20-task family in frozen axis order."""

    tasks: list[PipefailAtomicReportTask] = []
    for pipeline_shape in PIPEFAIL_ATOMIC_REPORT_PIPELINE_SHAPES:
        for policy in PIPEFAIL_ATOMIC_REPORT_FAILURE_COMMIT_POLICIES:
            bootstrap = _bootstrap_task(
                PipefailAtomicReportParameters(pipeline_shape, policy)
            )
            descriptors = tuple(
                _construct_pipefail_atomic_report_fixture_bundle(
                    bootstrap, profile
                ).descriptor
                for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
            )
            tasks.append(replace(bootstrap, fixtures=descriptors))
    selected = tuple(tasks)
    if (
        len(selected) != 20
        or len({task.task_id for task in selected}) != 20
        or len({task.task_contract_sha256 for task in selected}) != 20
        or len({task.graph_sha256 for task in selected}) != 20
    ):
        raise PipefailAtomicReportError("task grid is not exactly 20 unique tasks")
    return selected


def _data_row(enabled: str, key: str, value: int, message: str) -> bytes:
    return (
        enabled.encode("ascii")
        + b"\t"
        + key.encode("utf-8")
        + b"\t"
        + str(value).encode("ascii")
        + b"\t"
        + message.encode("utf-8")
        + b"\n"
    )


def _profile_sources(
    profile_id: str,
    shape: PipelineShape,
) -> tuple[tuple[str, InputFile], ...]:
    """Return role/source pairs; source order is intentionally not semantic."""

    if profile_id == "spaces-unicode":
        if shape == "fan-in-merge":
            return (
                (
                    "left",
                    InputFile(
                        "input/pipeline/data/gauche café.tsv",
                        _data_row("yes", "alpha", 5, "départ")
                        + _data_row("yes", "Upper", 9, "normalize")
                        + _data_row("yes", "βeta", 7, "preserve Unicode")
                        + _data_row("no", "bravo", 100, "disabled"),
                    ),
                ),
                (
                    "left",
                    InputFile(
                        "input/pipeline/data/gauche second.tsv",
                        _data_row("yes", "SecondLeft", 1, "second source"),
                        0o400,
                    ),
                ),
                (
                    "right",
                    InputFile(
                        "input/pipeline/data/droite 雪.tsv",
                        _data_row("yes", "alpha", 2, "retour")
                        + _data_row("yes", "zeta", -3, "negative")
                        + _data_row("yes", "two words", 4, "spaced key"),
                    ),
                ),
                (
                    "right",
                    InputFile(
                        "input/pipeline/data/droite second.tsv",
                        _data_row("yes", "RightUpper", 6, "normalize right")
                        + _data_row("no", "right-disabled", 100, "disabled"),
                    ),
                ),
            )
        return (
            (
                "main",
                InputFile(
                    "input/pipeline/data/main café 雪.tsv",
                    _data_row("yes", "Alpha team", 2, "démarrage")
                    + _data_row("yes", "βeta", 3, "雪")
                    + _data_row("no", "ignored", 90, "désactivé")
                    + _data_row("yes", "ALPHA team", -1, "retour"),
                ),
            ),
            (
                "main",
                InputFile(
                    "input/pipeline/data/second source.tsv",
                    _data_row("yes", "SecondMain", 4, "second source")
                    + _data_row("yes", "ZeroCase", 0, "zero boundary"),
                    0o400,
                ),
            ),
        )
    if profile_id == "leading-dashes-globs":
        if shape == "fan-in-merge":
            return (
                (
                    "right",
                    InputFile(
                        "input/pipeline/data/-right[?]*.tsv",
                        _data_row("yes", "literal", 8, "right")
                        + _data_row("yes", "dash", -2, "right"),
                    ),
                ),
                (
                    "left",
                    InputFile(
                        "input/pipeline/data/-left[*]?.tsv",
                        _data_row("yes", "literal", 10, "left")
                        + _data_row("no", "dash", 100, "disabled"),
                    ),
                ),
            )
        content = (
            _data_row("yes", "-[Key]*?", 0, "zero boundary")
            + _data_row("yes", "plain", -4, "nonpositive")
            + _data_row("no", "plain", 20, "disabled")
            if shape == "linear-four-stage"
            else _data_row("yes", "-[Key]*?", 8, "literal glob")
            + _data_row("yes", "plain", 4, "second")
            + _data_row("no", "plain", 20, "disabled")
        )
        return (
            (
                "main",
                InputFile(
                    "input/pipeline/data/-[main]*?.tsv",
                    content,
                ),
            ),
        )
    if profile_id == "empty-duplicates":
        if shape == "fan-in-merge":
            return (
                ("left", InputFile("input/pipeline/data/a-empty.tsv", b"")),
                (
                    "left",
                    InputFile(
                        "input/pipeline/data/b-left.tsv",
                        _data_row("yes", "repeat", 5, "same") * 2
                        + _data_row("no", "repeat", 90, "disabled"),
                    ),
                ),
                (
                    "right",
                    InputFile(
                        "input/pipeline/data/c-right.tsv",
                        _data_row("yes", "repeat", 10, "cancel")
                        + _data_row("yes", "other", -2, "negated"),
                    ),
                ),
            )
        return (
            ("main", InputFile("input/pipeline/data/a-empty.tsv", b"")),
            (
                "main",
                InputFile(
                    "input/pipeline/data/b-duplicates.tsv",
                    _data_row("yes", "repeat", 5, "same") * 2
                    + _data_row("yes", "cancel", 4, "positive")
                    + _data_row("yes", "cancel", -4, "negative")
                    + _data_row("no", "repeat", 99, "disabled"),
                ),
            ),
        )
    if profile_id == "symlinks-ordering":
        if shape == "fan-in-merge":
            return (
                (
                    "right",
                    InputFile(
                        "input/pipeline/data/z-right.tsv",
                        _data_row("yes", "same", 6, "right")
                        + _data_row("yes", "omega", 1, "right"),
                    ),
                ),
                (
                    "left",
                    InputFile(
                        "input/pipeline/data/a-left.tsv",
                        _data_row("yes", "same", 9, "left")
                        + _data_row("yes", "alpha", 2, "left"),
                    ),
                ),
            )
        return (
            (
                "main",
                InputFile(
                    "input/pipeline/data/z-last.tsv",
                    _data_row("yes", "Zeta", 9, "last")
                    + _data_row("yes", "same", -2, "last"),
                ),
            ),
            (
                "main",
                InputFile(
                    "input/pipeline/data/a-first.tsv",
                    _data_row("yes", "Alpha", 1, "first")
                    + _data_row("yes", "same", 3, "first"),
                ),
            ),
        )
    if profile_id == "partial-permissions":
        if shape == "fan-in-merge":
            return (
                (
                    "left",
                    InputFile(
                        "input/pipeline/data/group-selected.tsv",
                        _data_row("yes", "alpha", 7, "left"),
                        0o400,
                    ),
                ),
                (
                    "right",
                    InputFile(
                        "input/pipeline/data/owner-selected.tsv",
                        _data_row("yes", "alpha", 3, "right"),
                        0o600,
                    ),
                ),
            )
        return (
            (
                "main",
                InputFile(
                    "input/pipeline/data/selected-0400.tsv",
                    _data_row("yes", "ModeKey", 7, "owner read"),
                    0o400,
                ),
            ),
            (
                "main",
                InputFile(
                    "input/pipeline/data/selected-0600.tsv",
                    _data_row("yes", "modekey", 2, "owner write"),
                    0o600,
                ),
            ),
        )
    raise PipefailAtomicReportError("unsupported fixture profile")


def _configured_statuses(profile_id: str, shape: PipelineShape) -> tuple[int, ...]:
    stages = _STAGES[shape]
    result = [0] * len(stages)
    if profile_id in {"spaces-unicode", "leading-dashes-globs", "empty-duplicates"}:
        return tuple(result)
    if profile_id == "symlinks-ordering":
        indices = {0, len(stages) - 1}
        indices.update(range(2, len(stages) - 1, 2))
        for index in indices:
            result[index] = 109 - index * 7
        return tuple(result)
    if profile_id == "partial-permissions":
        indices = set(range(1, len(stages), 2))
        if len(stages) == 2:
            indices = {0, 1}
        for index in indices:
            result[index] = 71 + index * 5
        return tuple(result)
    raise PipefailAtomicReportError("unsupported fixture profile")


def _canonical_json_line(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8", errors="strict")
            + b"\n"
        )
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise PipefailAtomicReportError("JSON value is not canonicalizable") from exc


def _validate_prior_json_resources(value: object) -> None:
    """Bound a decoded prior report without recursive Python traversal."""

    stack: list[tuple[object, int]] = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > _PRIOR_JSON_MAXIMUM_NODES:
            raise PipefailAtomicReportError("prior report JSON has too many values")
        if depth > _PRIOR_JSON_MAXIMUM_DEPTH:
            raise PipefailAtomicReportError("prior report JSON is too deeply nested")
        if type(current) is dict:
            if any(type(key) is not str for key in current):
                raise PipefailAtomicReportError("prior report JSON key is invalid")
            stack.extend((item, depth + 1) for item in current.values())
        elif type(current) is list:
            stack.extend((item, depth + 1) for item in current)
        elif type(current) not in {str, int, float, bool, type(None)}:
            raise PipefailAtomicReportError("prior report JSON value is invalid")


def _fixture_inputs(
    profile: ExecutableFixtureProfile,
    shape: PipelineShape,
) -> tuple[InputFile | InputSymlink, ...]:
    pairs = _profile_sources(profile.profile_id, shape)
    manifest_pairs = list(pairs)
    # The symlink-ordering source declarations are already deliberately in
    # reverse byte order; the leading-dash declarations need an explicit flip.
    if profile.profile_id == "leading-dashes-globs":
        manifest_pairs.reverse()
    sources = b"".join(
        role.encode("ascii")
        + b"\t"
        + PurePosixPath(item.path).relative_to(
            PIPEFAIL_ATOMIC_REPORT_DATA_ROOT
        ).as_posix().encode("utf-8")
        + b"\n"
        for role, item in manifest_pairs
    )
    stages = _STAGES[shape]
    statuses = _configured_statuses(profile.profile_id, shape)
    status_pairs = list(zip(stages, statuses, strict=True))
    if profile.profile_id == "symlinks-ordering":
        status_pairs.reverse()
    elif profile.profile_id == "leading-dashes-globs":
        status_pairs = status_pairs[1:] + status_pairs[:1]
    status_bytes = b"".join(
        stage.encode("ascii") + b"\t" + str(code).encode("ascii") + b"\n"
        for stage, code in status_pairs
    )
    prior = _canonical_json_line(
        {
            "decision": "prior",
            "profile": profile.profile_id,
            "shape": shape,
            "version": 0,
        }
    )
    inputs: list[InputFile | InputSymlink] = [
        InputFile(PIPEFAIL_ATOMIC_REPORT_SOURCES, sources),
        InputFile(PIPEFAIL_ATOMIC_REPORT_STATUSES, status_bytes),
        InputFile(PIPEFAIL_ATOMIC_REPORT_PRIOR, prior),
    ]
    inputs.extend(item for _role, item in pairs)
    if profile.profile_id == "leading-dashes-globs":
        inputs.extend(
            (
                InputFile(
                    "input/pipeline/data/-unlisted[*]?.tsv",
                    _data_row("yes", "unlisted-decoy", 999, "must ignore"),
                ),
                InputSymlink(
                    "input/pipeline/data/-unlisted-link?.tsv",
                    "-unlisted[*]?.tsv",
                ),
            )
        )
    if profile.profile_id == "symlinks-ordering":
        inputs.extend(
            (
                InputFile(
                    "input/pipeline/data/unlisted-real.tsv",
                    _data_row("yes", "decoy", 999, "unlisted"),
                ),
                InputSymlink(
                    "input/pipeline/data/00-unlisted-link.tsv",
                    "unlisted-real.tsv",
                ),
                InputSymlink(
                    "input/pipeline/data/nested/unlisted-link.tsv",
                    "missing.tsv",
                ),
            )
        )
    if profile.profile_id == "partial-permissions":
        inputs.extend(
            (
                InputFile(
                    "input/pipeline/data/unlisted-000.tsv",
                    _data_row("yes", "hidden", 999, "must not read"),
                    0o000,
                ),
                InputSymlink(
                    "input/pipeline/data/unlisted-permission-link.tsv",
                    "unlisted-000.tsv",
                ),
            )
        )
    return tuple(inputs)


def _revalidate_definition(definition: object) -> FixtureDefinition:
    if type(definition) is not FixtureDefinition:
        raise PipefailAtomicReportError("definition has the wrong exact type")
    if (
        type(definition.fixture_id) is not str
        or type(definition.inputs) is not tuple
        or type(definition.expected_files) is not tuple
        or type(definition.schema_version) is not str
    ):
        raise PipefailAtomicReportError("definition nested types are invalid")
    for item in definition.inputs:
        if type(item) is InputFile:
            if (
                type(item.path) is not str
                or type(item.content) is not bytes
                or type(item.mode) is not int
            ):
                raise PipefailAtomicReportError("input file nested types are invalid")
        elif type(item) is InputSymlink:
            if type(item.path) is not str or type(item.target) is not str:
                raise PipefailAtomicReportError("symlink nested types are invalid")
        else:
            raise PipefailAtomicReportError("definition input type is invalid")
    for expected in definition.expected_files:
        if (
            type(expected) is not ExpectedFile
            or type(expected.path) is not str
            or type(expected.maximum_bytes) is not int
            or (expected.mode is not None and type(expected.mode) is not int)
        ):
            raise PipefailAtomicReportError("expected-file nested types are invalid")
    try:
        rebuilt = FixtureDefinition(
            fixture_id=definition.fixture_id,
            inputs=definition.inputs,
            expected_files=definition.expected_files,
            schema_version=definition.schema_version,
        )
    except (TypeError, ValueError) as exc:
        raise PipefailAtomicReportError("definition reconstruction failed") from exc
    if rebuilt != definition:
        raise PipefailAtomicReportError("definition changed on reconstruction")
    return definition


def _exact_input_map(
    definition: FixtureDefinition,
) -> dict[str, InputFile | InputSymlink]:
    result: dict[str, InputFile | InputSymlink] = {}
    for item in definition.inputs:
        if not item.path.startswith("input/pipeline/"):
            raise PipefailAtomicReportError("fixture input is outside pipeline root")
        if item.path in result:
            raise PipefailAtomicReportError("fixture input path is duplicated")
        result[item.path] = item
    for path in (
        PIPEFAIL_ATOMIC_REPORT_SOURCES,
        PIPEFAIL_ATOMIC_REPORT_STATUSES,
        PIPEFAIL_ATOMIC_REPORT_PRIOR,
    ):
        item = result.get(path)
        if type(item) is not InputFile or item.mode != 0o644:
            raise PipefailAtomicReportError("required metadata input is not exact")
    for path in result:
        if path in {
            PIPEFAIL_ATOMIC_REPORT_SOURCES,
            PIPEFAIL_ATOMIC_REPORT_STATUSES,
            PIPEFAIL_ATOMIC_REPORT_PRIOR,
        }:
            continue
        parsed = PurePosixPath(path)
        if (
            len(parsed.parts) <= len(PIPEFAIL_ATOMIC_REPORT_DATA_ROOT.parts)
            or parsed.parts[: len(PIPEFAIL_ATOMIC_REPORT_DATA_ROOT.parts)]
            != PIPEFAIL_ATOMIC_REPORT_DATA_ROOT.parts
        ):
            raise PipefailAtomicReportError("non-metadata input is outside data root")
    return result


def _strict_lines(content: bytes, label: str, *, allow_empty: bool) -> tuple[bytes, ...]:
    if type(content) is not bytes:
        raise PipefailAtomicReportError(f"{label} bytes have the wrong exact type")
    if not content:
        if allow_empty:
            return ()
        raise PipefailAtomicReportError(f"{label} must not be empty")
    if not content.endswith(b"\n"):
        raise PipefailAtomicReportError(f"{label} is not LF terminated")
    rows = tuple(content[:-1].split(b"\n"))
    if any(row == b"" for row in rows):
        raise PipefailAtomicReportError(f"{label} contains an empty physical row")
    return rows


def _decode_strict_field(raw: bytes, label: str) -> str:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise PipefailAtomicReportError(f"{label} is not strict UTF-8") from exc
    if not text:
        raise PipefailAtomicReportError(f"{label} is empty")
    return text


def _valid_key_field(raw: bytes) -> str:
    text = _decode_strict_field(raw, "record key")
    if (
        '"' in text
        or "\\" in text
        or any(unicodedata.category(character) == "Cc" for character in text)
    ):
        raise PipefailAtomicReportError("record key contains a forbidden character")
    return text


def _valid_message_field(raw: bytes) -> str:
    text = _decode_strict_field(raw, "record message")
    if "\0" in text or "\t" in text or "\n" in text:
        raise PipefailAtomicReportError("record message contains a framing character")
    return text


def _primary_parse_sources(
    inputs: dict[str, InputFile | InputSymlink],
    shape: PipelineShape,
) -> dict[str, tuple[InputFile, ...]]:
    manifest = inputs[PIPEFAIL_ATOMIC_REPORT_SOURCES]
    if type(manifest) is not InputFile:
        raise PipefailAtomicReportError("sources manifest is not a regular file")
    collected: dict[str, list[InputFile]] = {"main": [], "left": [], "right": []}
    seen: set[str] = set()
    for row in _strict_lines(manifest.content, "sources manifest", allow_empty=False):
        fields = row.split(b"\t")
        if len(fields) != 2:
            raise PipefailAtomicReportError("sources manifest row is not two-field TSV")
        try:
            role = fields[0].decode("ascii", errors="strict")
            relative = fields[1].decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise PipefailAtomicReportError("sources manifest encoding is invalid") from exc
        if role not in collected or not relative or relative in seen:
            raise PipefailAtomicReportError("sources role or uniqueness is invalid")
        path = PurePosixPath(relative)
        if (
            path.is_absolute()
            or path.as_posix() != relative
            or any(part in {"", ".", ".."} for part in path.parts)
            or any(
                unicodedata.category(character) == "Cc"
                for character in relative
            )
        ):
            raise PipefailAtomicReportError("source path is not canonical and safe")
        full = (PIPEFAIL_ATOMIC_REPORT_DATA_ROOT / path).as_posix()
        item = inputs.get(full)
        if type(item) is not InputFile or item.mode & 0o400 == 0:
            raise PipefailAtomicReportError("listed source is not owner-readable regular data")
        seen.add(relative)
        collected[role].append(item)
    if shape == "fan-in-merge":
        if collected["main"] or not collected["left"] or not collected["right"]:
            raise PipefailAtomicReportError("fan-in source roles are invalid")
    elif not collected["main"] or collected["left"] or collected["right"]:
        raise PipefailAtomicReportError("linear source roles are invalid")
    return {role: tuple(items) for role, items in collected.items()}


def _primary_parse_rows(files: tuple[InputFile, ...]) -> tuple[tuple[bool, bytes, int], ...]:
    records: list[tuple[bool, bytes, int]] = []
    for item in files:
        for physical in _strict_lines(item.content, "pipeline data", allow_empty=True):
            fields = physical.split(b"\t")
            if len(fields) != 4 or fields[0] not in {b"yes", b"no"}:
                raise PipefailAtomicReportError("pipeline row shape is invalid")
            _valid_key_field(fields[1])
            _valid_message_field(fields[3])
            if _CANONICAL_INTEGER_RE.fullmatch(fields[2]) is None:
                raise PipefailAtomicReportError("pipeline integer is noncanonical")
            value = int(fields[2].decode("ascii"))
            if not _MINIMUM_VALUE <= value <= _MAXIMUM_VALUE:
                raise PipefailAtomicReportError("pipeline integer is out of range")
            records.append((fields[0] == b"yes", fields[1], value))
    return tuple(records)


def _primary_parse_statuses(
    inputs: dict[str, InputFile | InputSymlink],
    shape: PipelineShape,
) -> tuple[int, ...]:
    status_file = inputs[PIPEFAIL_ATOMIC_REPORT_STATUSES]
    if type(status_file) is not InputFile:
        raise PipefailAtomicReportError("status input is not a regular file")
    observed: dict[str, int] = {}
    allowed = _STAGES[shape]
    for row in _strict_lines(status_file.content, "status input", allow_empty=False):
        fields = row.split(b"\t")
        if len(fields) != 2:
            raise PipefailAtomicReportError("status row is not two-field TSV")
        try:
            stage = fields[0].decode("ascii", errors="strict")
        except UnicodeDecodeError as exc:
            raise PipefailAtomicReportError("status stage is not ASCII") from exc
        if (
            stage not in allowed
            or stage in observed
            or _CANONICAL_STATUS_RE.fullmatch(fields[1]) is None
        ):
            raise PipefailAtomicReportError("status stage or code is invalid")
        code = int(fields[1].decode("ascii"))
        if code > 125:
            raise PipefailAtomicReportError("status code exceeds 125")
        observed[stage] = code
    if set(observed) != set(allowed):
        raise PipefailAtomicReportError("status vector is incomplete")
    return tuple(observed[stage] for stage in allowed)


def _primary_prior_bytes(inputs: dict[str, InputFile | InputSymlink]) -> bytes:
    prior = inputs[PIPEFAIL_ATOMIC_REPORT_PRIOR]
    if type(prior) is not InputFile:
        raise PipefailAtomicReportError("prior report is not a regular file")
    raw = prior.content
    if (
        not raw
        or len(raw) > PIPEFAIL_ATOMIC_REPORT_OUTPUT_MAXIMUM_BYTES
        or not raw.endswith(b"\n")
        or raw.count(b"\n") != 1
    ):
        raise PipefailAtomicReportError("prior report is not one JSON line")
    try:
        value = json.loads(
            raw[:-1].decode("utf-8", errors="strict"),
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"nonfinite {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise PipefailAtomicReportError("prior report JSON is invalid") from exc
    _validate_prior_json_resources(value)
    if type(value) is not dict or _canonical_json_line(value) != raw:
        raise PipefailAtomicReportError("prior report is not canonical JSON")
    return raw


def _ascii_lower(raw: bytes) -> bytes:
    return bytes(byte + 32 if 65 <= byte <= 90 else byte for byte in raw)


def _result_records(records: tuple[tuple[bytes, int], ...]) -> list[dict[str, object]]:
    totals: dict[bytes, list[int]] = {}
    for key, value in records:
        slot = totals.setdefault(key, [0, 0])
        slot[0] += 1
        slot[1] += value
    return [
        {"key": key.decode("utf-8"), "count": count, "sum": total}
        for key, (count, total) in sorted(totals.items(), key=lambda item: item[0])
    ]


def _primary_success(
    sources: dict[str, tuple[InputFile, ...]],
    shape: PipelineShape,
) -> tuple[list[dict[str, object]], dict[str, int] | None]:
    if shape == "fan-in-merge":
        left = _primary_parse_rows(sources["left"])
        right = _primary_parse_rows(sources["right"])
        projected = tuple(
            (_ascii_lower(key), value)
            for enabled, key, value in left
            if enabled
        ) + tuple(
            (_ascii_lower(key), -value)
            for enabled, key, value in right
            if enabled
        )
        return _result_records(tuple(sorted(projected, key=lambda item: item[0]))), None
    rows = _primary_parse_rows(sources["main"])
    selected = tuple((key, value) for enabled, key, value in rows if enabled)
    if shape == "linear-two-stage":
        return _result_records(selected), None
    normalized = tuple((_ascii_lower(key), value) for key, value in selected)
    if shape == "linear-four-stage":
        return _result_records(tuple(item for item in normalized if item[1] > 0)), None
    if shape == "tee-and-reduce":
        audit = {
            "count": len(normalized),
            "sum": sum(value for _key, value in normalized),
        }
        return _result_records(normalized), audit
    raise PipefailAtomicReportError("unsupported pipeline shape")


def _primary_payload(
    definition: FixtureDefinition,
    parameters: PipefailAtomicReportParameters,
) -> bytes | None:
    selected = _revalidate_definition(definition)
    if type(parameters) is not PipefailAtomicReportParameters:
        raise PipefailAtomicReportError("parameters have the wrong exact type")
    parameters.__post_init__()
    inputs = _exact_input_map(selected)
    sources = _primary_parse_sources(inputs, parameters.pipeline_shape)
    # Validate every selected data row even on configured failure.
    for role in ("main", "left", "right"):
        _primary_parse_rows(sources[role])
    statuses = _primary_parse_statuses(inputs, parameters.pipeline_shape)
    prior = _primary_prior_bytes(inputs)
    stages = _STAGES[parameters.pipeline_shape]
    failed = tuple(index for index, code in enumerate(statuses) if code != 0)
    if not failed:
        result, audit = _primary_success(sources, parameters.pipeline_shape)
        payload: bytes | None = _canonical_json_line(
            {
                "version": 1,
                "shape": parameters.pipeline_shape,
                "decision": "success",
                "pipeline": [
                    {"stage": stage, "status": code}
                    for stage, code in zip(stages, statuses, strict=True)
                ],
                "selected_failure": None,
                "result": result,
                "audit": audit,
            }
        )
    elif parameters.failure_commit_policy == "commit-success-only":
        payload = None
    elif parameters.failure_commit_policy == "rollback-on-any-failure":
        payload = prior
    else:
        selected_failure: dict[str, object] | None = None
        if parameters.failure_commit_policy == "preserve-first-failure":
            index = failed[0]
            selected_failure = {"stage": stages[index], "code": statuses[index]}
        elif parameters.failure_commit_policy == "preserve-last-failure":
            index = failed[-1]
            selected_failure = {"stage": stages[index], "code": statuses[index]}
        payload = _canonical_json_line(
            {
                "version": 1,
                "shape": parameters.pipeline_shape,
                "decision": "status",
                "pipeline": [
                    {"stage": stage, "status": code}
                    for stage, code in zip(stages, statuses, strict=True)
                ],
                "selected_failure": selected_failure,
                "result": [],
                "audit": None,
            }
        )
    expected = (
        ()
        if payload is None
        else (
            ExpectedFile(
                PIPEFAIL_ATOMIC_REPORT_OUTPUT,
                maximum_bytes=PIPEFAIL_ATOMIC_REPORT_OUTPUT_MAXIMUM_BYTES,
                mode=PIPEFAIL_ATOMIC_REPORT_OUTPUT_MODE,
            ),
        )
    )
    if selected.expected_files != expected:
        raise PipefailAtomicReportError("output policy does not match semantics")
    if payload is not None and len(payload) > PIPEFAIL_ATOMIC_REPORT_OUTPUT_MAXIMUM_BYTES:
        raise PipefailAtomicReportError("derived report exceeds the output ceiling")
    return payload


def derive_pipefail_atomic_report_output(
    definition: FixtureDefinition,
    parameters: PipefailAtomicReportParameters,
) -> bytes | None:
    """Primary trusted implementation; ``None`` means exact output absence."""

    return _primary_payload(definition, parameters)


def reference_pipefail_atomic_report_output(
    definition: FixtureDefinition,
    parameters: PipefailAtomicReportParameters,
) -> bytes | None:
    """Separately structured trusted parser and semantic implementation."""

    checked = _revalidate_definition(definition)
    if type(parameters) is not PipefailAtomicReportParameters:
        raise PipefailAtomicReportError("parameters have the wrong exact type")
    parameters.__post_init__()
    # Rebuild the input inventory independently of the primary semantic map.
    files: dict[str, InputFile | InputSymlink] = {}
    for entry in checked.inputs:
        if entry.path in files or not entry.path.startswith("input/pipeline/"):
            raise PipefailAtomicReportError("reference input inventory is invalid")
        files[entry.path] = entry
    metadata_paths = {
        PIPEFAIL_ATOMIC_REPORT_SOURCES,
        PIPEFAIL_ATOMIC_REPORT_STATUSES,
        PIPEFAIL_ATOMIC_REPORT_PRIOR,
    }
    for metadata_path in metadata_paths:
        metadata_entry = files.get(metadata_path)
        if type(metadata_entry) is not InputFile or metadata_entry.mode != 0o644:
            raise PipefailAtomicReportError("reference metadata input is not exact")
    data_prefix = PIPEFAIL_ATOMIC_REPORT_DATA_ROOT.parts
    for input_path in files:
        if input_path in metadata_paths:
            continue
        parsed_input_path = PurePosixPath(input_path)
        if (
            len(parsed_input_path.parts) <= len(data_prefix)
            or parsed_input_path.parts[: len(data_prefix)] != data_prefix
        ):
            raise PipefailAtomicReportError("reference input is outside data root")
    manifest_item = files[PIPEFAIL_ATOMIC_REPORT_SOURCES]
    status_item = files[PIPEFAIL_ATOMIC_REPORT_STATUSES]
    prior_item = files[PIPEFAIL_ATOMIC_REPORT_PRIOR]
    if not all(type(item) is InputFile for item in (manifest_item, status_item, prior_item)):
        raise PipefailAtomicReportError("reference metadata type check failed")

    # Reference manifest parser uses a cursor rather than the primary line helper.
    manifest: list[tuple[str, str]] = []
    cursor = 0
    manifest_bytes = manifest_item.content
    while cursor < len(manifest_bytes):
        newline = manifest_bytes.find(b"\n", cursor)
        if newline < 0 or newline == cursor:
            raise PipefailAtomicReportError("reference manifest is not strict LF TSV")
        physical = manifest_bytes[cursor:newline]
        cursor = newline + 1
        tab = physical.find(b"\t")
        if tab <= 0 or physical.find(b"\t", tab + 1) >= 0:
            raise PipefailAtomicReportError("reference manifest field count is invalid")
        try:
            role = physical[:tab].decode("ascii", "strict")
            relative = physical[tab + 1 :].decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise PipefailAtomicReportError("reference manifest encoding is invalid") from exc
        if role not in {"main", "left", "right"}:
            raise PipefailAtomicReportError("reference manifest role is invalid")
        relative_path = PurePosixPath(relative)
        if (
            not relative
            or relative_path.is_absolute()
            or relative_path.as_posix() != relative
            or any(part in {"", ".", ".."} for part in relative_path.parts)
            or any(
                unicodedata.category(character) == "Cc"
                for character in relative
            )
        ):
            raise PipefailAtomicReportError("reference manifest path is invalid")
        manifest.append((role, relative))
    if not manifest_bytes or cursor != len(manifest_bytes):
        raise PipefailAtomicReportError("reference manifest is empty or truncated")
    if len({relative for _role, relative in manifest}) != len(manifest):
        raise PipefailAtomicReportError("reference manifest paths repeat")
    role_paths = {
        role: [relative for item_role, relative in manifest if item_role == role]
        for role in ("main", "left", "right")
    }
    if parameters.pipeline_shape == "fan-in-merge":
        roles_ok = not role_paths["main"] and bool(role_paths["left"]) and bool(role_paths["right"])
    else:
        roles_ok = bool(role_paths["main"]) and not role_paths["left"] and not role_paths["right"]
    if not roles_ok:
        raise PipefailAtomicReportError("reference source roles do not match shape")

    streams: dict[str, list[tuple[bool, bytes, int]]] = {
        "main": [],
        "left": [],
        "right": [],
    }
    for role in ("main", "left", "right"):
        for relative in role_paths[role]:
            full = f"{PIPEFAIL_ATOMIC_REPORT_DATA_ROOT.as_posix()}/{relative}"
            source = files.get(full)
            if type(source) is not InputFile or source.mode & 0o400 == 0:
                raise PipefailAtomicReportError("reference source is not owner-readable regular data")
            data = source.content
            position = 0
            while position < len(data):
                newline = data.find(b"\n", position)
                if newline < 0 or newline == position:
                    raise PipefailAtomicReportError("reference data is not strict LF TSV")
                parts = data[position:newline].split(b"\t", 4)
                position = newline + 1
                if len(parts) != 4 or parts[0] not in {b"yes", b"no"}:
                    raise PipefailAtomicReportError("reference data row shape is invalid")
                try:
                    key_text = parts[1].decode("utf-8", "strict")
                    message_text = parts[3].decode("utf-8", "strict")
                    integer = int(parts[2].decode("ascii", "strict"))
                except (UnicodeDecodeError, ValueError) as exc:
                    raise PipefailAtomicReportError("reference data field is invalid") from exc
                if (
                    not key_text
                    or not message_text
                    or any(
                        unicodedata.category(character) == "Cc"
                        for character in key_text
                    )
                    or '"' in key_text
                    or "\\" in key_text
                    or "\0" in message_text
                    or "\t" in message_text
                    or "\n" in message_text
                    or str(integer).encode("ascii") != parts[2]
                    or len(parts[2].lstrip(b"-")) > 7
                    or not _MINIMUM_VALUE <= integer <= _MAXIMUM_VALUE
                ):
                    raise PipefailAtomicReportError("reference data field contract failed")
                streams[role].append((parts[0] == b"yes", parts[1], integer))
            if position != len(data):
                raise PipefailAtomicReportError("reference data cursor did not terminate")

    stages = _STAGES[parameters.pipeline_shape]
    stage_codes: dict[str, int] = {}
    position = 0
    status_bytes = status_item.content
    while position < len(status_bytes):
        newline = status_bytes.find(b"\n", position)
        if newline < 0 or newline == position:
            raise PipefailAtomicReportError("reference status is not strict LF TSV")
        physical = status_bytes[position:newline]
        position = newline + 1
        parts = physical.split(b"\t")
        if len(parts) != 2:
            raise PipefailAtomicReportError("reference status field count is invalid")
        try:
            stage = parts[0].decode("ascii", "strict")
            code = int(parts[1].decode("ascii", "strict"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise PipefailAtomicReportError("reference status field is invalid") from exc
        if (
            stage not in stages
            or stage in stage_codes
            or str(code).encode("ascii") != parts[1]
            or not 0 <= code <= 125
        ):
            raise PipefailAtomicReportError("reference status contract failed")
        stage_codes[stage] = code
    if not status_bytes or position != len(status_bytes) or set(stage_codes) != set(stages):
        raise PipefailAtomicReportError("reference status vector is incomplete")
    ordered_codes = [stage_codes[stage] for stage in stages]

    prior_raw = prior_item.content
    if (
        not prior_raw
        or len(prior_raw) > PIPEFAIL_ATOMIC_REPORT_OUTPUT_MAXIMUM_BYTES
        or not prior_raw.endswith(b"\n")
        or prior_raw.count(b"\n") != 1
    ):
        raise PipefailAtomicReportError("reference prior report line is invalid")
    try:
        prior_value = json.JSONDecoder(
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"nonfinite {token}")
            )
        ).decode(prior_raw[:-1].decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise PipefailAtomicReportError("reference prior JSON is invalid") from exc
    _validate_prior_json_resources(prior_value)
    try:
        reference_prior = (
            json.dumps(
                prior_value,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8", "strict")
            + b"\n"
        )
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise PipefailAtomicReportError("reference prior JSON cannot canonicalize") from exc
    if type(prior_value) is not dict or reference_prior != prior_raw:
        raise PipefailAtomicReportError("reference prior JSON is not canonical")

    failures = [index for index, code in enumerate(ordered_codes) if code]
    result_rows: list[tuple[bytes, int]] = []
    audit_value: dict[str, int] | None = None
    if not failures:
        if parameters.pipeline_shape == "linear-two-stage":
            result_rows = [(key, value) for enabled, key, value in streams["main"] if enabled]
        elif parameters.pipeline_shape == "linear-four-stage":
            result_rows = [
                (
                    bytes(
                        byte + 32 if 65 <= byte <= 90 else byte
                        for byte in key
                    ),
                    value,
                )
                for enabled, key, value in streams["main"]
                if enabled and value > 0
            ]
        elif parameters.pipeline_shape == "fan-in-merge":
            result_rows = [
                (
                    bytes(
                        byte + 32 if 65 <= byte <= 90 else byte
                        for byte in key
                    ),
                    value,
                )
                for enabled, key, value in streams["left"]
                if enabled
            ] + [
                (
                    bytes(
                        byte + 32 if 65 <= byte <= 90 else byte
                        for byte in key
                    ),
                    -value,
                )
                for enabled, key, value in streams["right"]
                if enabled
            ]
            result_rows.sort(key=lambda item: item[0])
        elif parameters.pipeline_shape == "tee-and-reduce":
            result_rows = [
                (
                    bytes(
                        byte + 32 if 65 <= byte <= 90 else byte
                        for byte in key
                    ),
                    value,
                )
                for enabled, key, value in streams["main"]
                if enabled
            ]
            audit_value = {
                "count": len(result_rows),
                "sum": sum(value for _key, value in result_rows),
            }
        totals: dict[bytes, list[int]] = {}
        for key, value in result_rows:
            pair = totals.setdefault(key, [0, 0])
            pair[0] += 1
            pair[1] += value
        result_value = [
            {"count": pair[0], "key": key.decode("utf-8"), "sum": pair[1]}
            for key, pair in sorted(totals.items(), key=lambda item: item[0])
        ]
        success_record = {
                "audit": audit_value,
                "decision": "success",
                "pipeline": [
                    {"stage": stage, "status": stage_codes[stage]}
                    for stage in stages
                ],
                "result": result_value,
                "selected_failure": None,
                "shape": parameters.pipeline_shape,
                "version": 1,
            }
        answer: bytes | None = (
            json.dumps(
                success_record,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8", "strict")
            + b"\n"
        )
    elif parameters.failure_commit_policy == "commit-success-only":
        answer = None
    elif parameters.failure_commit_policy == "rollback-on-any-failure":
        answer = prior_raw
    else:
        chosen: dict[str, object] | None = None
        if parameters.failure_commit_policy == "preserve-first-failure":
            chosen_index = failures[0]
            chosen = {"code": ordered_codes[chosen_index], "stage": stages[chosen_index]}
        elif parameters.failure_commit_policy == "preserve-last-failure":
            chosen_index = failures[-1]
            chosen = {"code": ordered_codes[chosen_index], "stage": stages[chosen_index]}
        failure_record = {
                "audit": None,
                "decision": "status",
                "pipeline": [
                    {"stage": stage, "status": stage_codes[stage]}
                    for stage in stages
                ],
                "result": [],
                "selected_failure": chosen,
                "shape": parameters.pipeline_shape,
                "version": 1,
            }
        answer = (
            json.dumps(
                failure_record,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8", "strict")
            + b"\n"
        )
    expected = () if answer is None else (
        ExpectedFile(
            PIPEFAIL_ATOMIC_REPORT_OUTPUT,
            maximum_bytes=PIPEFAIL_ATOMIC_REPORT_OUTPUT_MAXIMUM_BYTES,
            mode=PIPEFAIL_ATOMIC_REPORT_OUTPUT_MODE,
        ),
    )
    if checked.expected_files != expected:
        raise PipefailAtomicReportError("reference output policy differs from semantics")
    if answer is not None and len(answer) > PIPEFAIL_ATOMIC_REPORT_OUTPUT_MAXIMUM_BYTES:
        raise PipefailAtomicReportError("reference report exceeds ceiling")
    return answer


def verify_pipefail_atomic_report_output(
    definition: FixtureDefinition,
    parameters: PipefailAtomicReportParameters,
    candidate_output: bytes | None,
) -> bool:
    """Verify exact bytes or exact absence, requiring both oracles to agree."""

    if candidate_output is not None and type(candidate_output) is not bytes:
        return False
    try:
        primary = derive_pipefail_atomic_report_output(definition, parameters)
        reference = reference_pipefail_atomic_report_output(definition, parameters)
    except (PipefailAtomicReportError, TypeError, ValueError):
        return False
    return primary == reference == candidate_output


def _compute_oracle_sha256(outputs: tuple[OracleOutputRecord, ...]) -> str:
    if type(outputs) is not tuple or len(outputs) > 1:
        raise PipefailAtomicReportError("oracle output tuple is invalid")
    if outputs:
        output = outputs[0]
        if type(output) is not OracleOutputRecord:
            raise PipefailAtomicReportError("oracle output has the wrong exact type")
        output.__post_init__()
        if (
            output.path != PIPEFAIL_ATOMIC_REPORT_OUTPUT
            or output.mode != PIPEFAIL_ATOMIC_REPORT_OUTPUT_MODE
            or len(output.content) > PIPEFAIL_ATOMIC_REPORT_OUTPUT_MAXIMUM_BYTES
        ):
            raise PipefailAtomicReportError("oracle output contract is invalid")
    return domain_sha256(
        "cbds.executable-fixture.trusted-oracle.v1",
        {
            "schema_version": EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION,
            "semantic_verifier_identity": PIPEFAIL_ATOMIC_REPORT_VERIFIER_IDENTITY,
            "outputs": [output.commitment_record() for output in outputs],
        },
    )


@dataclass(frozen=True, slots=True)
class PipefailAtomicReportOracle:
    outputs: tuple[OracleOutputRecord, ...]
    oracle_sha256: str
    semantic_verifier_identity: str = PIPEFAIL_ATOMIC_REPORT_VERIFIER_IDENTITY
    schema_version: str = EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            type(self.outputs) is not tuple
            or type(self.semantic_verifier_identity) is not str
            or self.semantic_verifier_identity != PIPEFAIL_ATOMIC_REPORT_VERIFIER_IDENTITY
            or type(self.schema_version) is not str
            or self.schema_version != EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION
            or not _is_sha256(self.oracle_sha256)
            or self.oracle_sha256 != _compute_oracle_sha256(self.outputs)
        ):
            raise PipefailAtomicReportError("oracle identity is invalid")

    def commitment_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "schema_version": self.schema_version,
            "record_type": "cbds.executable-fixture-trusted-oracle",
            "semantic_verifier_identity": self.semantic_verifier_identity,
            "outputs": [item.commitment_record() for item in self.outputs],
            "oracle_sha256": self.oracle_sha256,
        }


@dataclass(frozen=True, slots=True)
class PipefailAtomicReportFixtureBundle:
    task_contract_sha256: str
    profile_sha256: str
    definition: FixtureDefinition = field(repr=False)
    fixture_definition_sha256: str
    oracle: PipefailAtomicReportOracle = field(repr=False)
    descriptor: OpaqueFixtureDescriptor
    schema_version: str = EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_pipefail_atomic_report_fixture_bundle(self)

    def to_opaque_descriptor(self) -> OpaqueFixtureDescriptor:
        validate_pipefail_atomic_report_fixture_bundle(self)
        return self.descriptor

    def commitment_record(self) -> dict[str, object]:
        validate_pipefail_atomic_report_fixture_bundle(self)
        return {
            "schema_version": self.schema_version,
            "record_type": "cbds.executable-fixture-private-binding",
            "binding_version": EXECUTABLE_FIXTURE_BINDING_VERSION,
            "task_contract_sha256": self.task_contract_sha256,
            "profile_sha256": self.profile_sha256,
            "fixture_definition_sha256": self.fixture_definition_sha256,
            "oracle": self.oracle.commitment_record(),
            "descriptor": self.descriptor.to_public_record(),
            "candidate_execution_authorized": self.candidate_execution_authorized,
            "model_selection_eligible": self.model_selection_eligible,
            "claim_authorized": self.claim_authorized,
        }


def validate_pipefail_atomic_report_fixture_bundle(
    bundle: PipefailAtomicReportFixtureBundle,
) -> None:
    """Validate structural binding; task/profile authenticity is separate."""

    if type(bundle) is not PipefailAtomicReportFixtureBundle:
        raise PipefailAtomicReportError("bundle has the wrong exact type")
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
        raise PipefailAtomicReportError("bundle metadata is invalid")
    definition = _revalidate_definition(bundle.definition)
    if bundle.fixture_definition_sha256 != compute_fixture_definition_semantic_sha256(definition):
        raise PipefailAtomicReportError("definition digest is invalid")
    if type(bundle.oracle) is not PipefailAtomicReportOracle:
        raise PipefailAtomicReportError("oracle has the wrong exact type")
    bundle.oracle.__post_init__()
    expected = () if not bundle.oracle.outputs else (
        ExpectedFile(
            PIPEFAIL_ATOMIC_REPORT_OUTPUT,
            maximum_bytes=PIPEFAIL_ATOMIC_REPORT_OUTPUT_MAXIMUM_BYTES,
            mode=PIPEFAIL_ATOMIC_REPORT_OUTPUT_MODE,
        ),
    )
    if definition.expected_files != expected:
        raise PipefailAtomicReportError("definition output policy does not bind oracle")
    if type(bundle.descriptor) is not OpaqueFixtureDescriptor:
        raise PipefailAtomicReportError("descriptor has the wrong exact type")
    bundle.descriptor.__post_init__()
    fixture_sha256 = compute_bound_fixture_sha256(
        task_contract_sha256=bundle.task_contract_sha256,
        profile_sha256=bundle.profile_sha256,
        fixture_definition_sha256=bundle.fixture_definition_sha256,
        oracle_sha256=bundle.oracle.oracle_sha256,
    )
    if (
        bundle.descriptor.fixture_sha256 != fixture_sha256
        or bundle.descriptor.fixture_id != f"fx-{fixture_sha256[:24]}"
        or bundle.descriptor.task_contract_sha256 != bundle.task_contract_sha256
    ):
        raise PipefailAtomicReportError("descriptor binding is invalid")


def verify_pipefail_atomic_report_fixture_bundle(bundle: object) -> bool:
    try:
        validate_pipefail_atomic_report_fixture_bundle(bundle)  # type: ignore[arg-type]
    except (PipefailAtomicReportError, TypeError, ValueError):
        return False
    return True


def _validate_task_profile(
    task: object,
    profile: object,
) -> tuple[PipefailAtomicReportTask, ExecutableFixtureProfile]:
    if type(task) is not PipefailAtomicReportTask:
        raise PipefailAtomicReportError("task has the wrong exact type")
    if type(profile) is not ExecutableFixtureProfile:
        raise PipefailAtomicReportError("profile has the wrong exact type")
    if (
        type(profile.profile_id) is not str
        or type(profile.cases) is not tuple
        or any(type(case) is not str for case in profile.cases)
        or type(profile.profile_sha256) is not str
        or type(profile.profile_version) is not str
    ):
        raise PipefailAtomicReportError("profile nested types are invalid")
    try:
        task.__post_init__()
        PipefailAtomicReportParameters(
            task.parameters.pipeline_shape,
            task.parameters.failure_commit_policy,
        )
        rebuilt_profile = ExecutableFixtureProfile(
            profile_id=profile.profile_id,
            cases=profile.cases,
            profile_sha256=profile.profile_sha256,
            profile_version=profile.profile_version,
            public_method_development=profile.public_method_development,
            sealed=profile.sealed,
            candidate_execution_authorized=profile.candidate_execution_authorized,
            model_selection_eligible=profile.model_selection_eligible,
            claim_authorized=profile.claim_authorized,
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise PipefailAtomicReportError("task/profile revalidation failed") from exc
    if rebuilt_profile not in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
        raise PipefailAtomicReportError("profile is not public method-development data")
    return task, profile


def _construct_pipefail_atomic_report_fixture_bundle(
    task: PipefailAtomicReportTask,
    profile: ExecutableFixtureProfile,
) -> PipefailAtomicReportFixtureBundle:
    selected_task, selected_profile = _validate_task_profile(task, profile)
    inputs = _fixture_inputs(selected_profile, selected_task.parameters.pipeline_shape)
    statuses = _configured_statuses(
        selected_profile.profile_id, selected_task.parameters.pipeline_shape
    )
    has_failure = any(statuses)
    should_publish = not (
        has_failure
        and selected_task.parameters.failure_commit_policy == "commit-success-only"
    )
    expected = () if not should_publish else (
        ExpectedFile(
            PIPEFAIL_ATOMIC_REPORT_OUTPUT,
            maximum_bytes=PIPEFAIL_ATOMIC_REPORT_OUTPUT_MAXIMUM_BYTES,
            mode=PIPEFAIL_ATOMIC_REPORT_OUTPUT_MODE,
        ),
    )
    definition = FixtureDefinition(
        fixture_id=f"fixture.{selected_task.task_id}.{selected_profile.profile_id}",
        inputs=inputs,
        expected_files=expected,
    )
    primary = derive_pipefail_atomic_report_output(definition, selected_task.parameters)
    reference = reference_pipefail_atomic_report_output(definition, selected_task.parameters)
    if primary != reference:
        raise PipefailAtomicReportError("independent production oracles disagree")
    outputs = () if primary is None else (
        OracleOutputRecord(
            PIPEFAIL_ATOMIC_REPORT_OUTPUT,
            primary,
            PIPEFAIL_ATOMIC_REPORT_OUTPUT_MODE,
        ),
    )
    oracle = PipefailAtomicReportOracle(outputs, _compute_oracle_sha256(outputs))
    definition_sha256 = compute_fixture_definition_semantic_sha256(definition)
    fixture_sha256 = compute_bound_fixture_sha256(
        task_contract_sha256=selected_task.task_contract_sha256,
        profile_sha256=selected_profile.profile_sha256,
        fixture_definition_sha256=definition_sha256,
        oracle_sha256=oracle.oracle_sha256,
    )
    return PipefailAtomicReportFixtureBundle(
        task_contract_sha256=selected_task.task_contract_sha256,
        profile_sha256=selected_profile.profile_sha256,
        definition=definition,
        fixture_definition_sha256=definition_sha256,
        oracle=oracle,
        descriptor=OpaqueFixtureDescriptor(
            fixture_id=f"fx-{fixture_sha256[:24]}",
            fixture_sha256=fixture_sha256,
            task_contract_sha256=selected_task.task_contract_sha256,
        ),
    )


def build_pipefail_atomic_report_fixture_bundle(
    task: PipefailAtomicReportTask,
    profile: ExecutableFixtureProfile,
) -> PipefailAtomicReportFixtureBundle:
    selected_task, selected_profile = _validate_task_profile(task, profile)
    bundle = _construct_pipefail_atomic_report_fixture_bundle(
        selected_task, selected_profile
    )
    index = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES.index(selected_profile)
    if selected_task.fixtures[index] != bundle.descriptor:
        raise PipefailAtomicReportError(
            "generated descriptor differs from task profile binding"
        )
    return bundle


def validate_pipefail_atomic_report_fixture_for_task_profile(
    task: PipefailAtomicReportTask,
    profile: ExecutableFixtureProfile,
    bundle: PipefailAtomicReportFixtureBundle,
) -> None:
    selected_task, selected_profile = _validate_task_profile(task, profile)
    validate_pipefail_atomic_report_fixture_bundle(bundle)
    expected = build_pipefail_atomic_report_fixture_bundle(
        selected_task, selected_profile
    )
    if bundle != expected:
        raise PipefailAtomicReportError("bundle differs from reconstruction")
    index = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES.index(selected_profile)
    if selected_task.fixtures[index] != expected.descriptor:
        raise PipefailAtomicReportError("task descriptor differs from fixture")


def verify_pipefail_atomic_report_fixture_for_task_profile(
    task: object,
    profile: object,
    bundle: object,
) -> bool:
    try:
        validate_pipefail_atomic_report_fixture_for_task_profile(
            task,  # type: ignore[arg-type]
            profile,  # type: ignore[arg-type]
            bundle,  # type: ignore[arg-type]
        )
    except (PipefailAtomicReportError, TypeError, ValueError):
        return False
    return True


def materialize_pipefail_atomic_report_fixture(
    task: PipefailAtomicReportTask,
    profile: ExecutableFixtureProfile,
    bundle: PipefailAtomicReportFixtureBundle,
    workspace: str | os.PathLike[str],
) -> WorkspaceHandle:
    validate_pipefail_atomic_report_fixture_for_task_profile(task, profile, bundle)
    return materialize_fixture(bundle.definition, workspace)


def verify_pipefail_atomic_report_workspace(
    task: PipefailAtomicReportTask,
    profile: ExecutableFixtureProfile,
    bundle: PipefailAtomicReportFixtureBundle,
    handle: WorkspaceHandle,
) -> bool:
    """Verify an exact quiescent final state without executing a candidate.

    A trusted harness must stop all candidate processes and other writers before
    entry and hold the workspace quiescent through return.  Stable scans do not
    prove global quiescence, transient sibling staging, use of ``mv``, or actual
    PIPESTATUS/tool history; those are intentionally honest mechanism limits.
    """

    if type(handle) is not WorkspaceHandle:
        return False
    try:
        validate_pipefail_atomic_report_fixture_for_task_profile(task, profile, bundle)
        baseline = handle.baseline
        if (
            baseline.fixture_id != bundle.definition.fixture_id
            or baseline.fixture_sha256 != bundle.definition.fixture_sha256
            or handle.expected_files != bundle.definition.expected_files
            or baseline.output_scaffold_entries
        ):
            return False
        input_scan = handle.scan_inputs()
        if (
            input_scan.scope != "inputs"
            or input_scan.baseline_sha256 != baseline.baseline_sha256
            or input_scan.entries != baseline.input_entries
            or input_scan.tree_sha256 != baseline.input_tree_sha256
        ):
            return False
        output_scan = handle.scan_outputs()
        output_entries = validate_expected_output_policy(bundle.definition, output_scan)
        primary = derive_pipefail_atomic_report_output(
            bundle.definition, task.parameters
        )
        reference = reference_pipefail_atomic_report_output(
            bundle.definition, task.parameters
        )
        if primary != reference:
            return False
        if primary is None:
            if output_entries or bundle.oracle.outputs:
                return False
        else:
            if (
                len(output_entries) != 1
                or output_entries[0].path != PIPEFAIL_ATOMIC_REPORT_OUTPUT
                or output_entries[0].mode != PIPEFAIL_ATOMIC_REPORT_OUTPUT_MODE
                or len(bundle.oracle.outputs) != 1
            ):
                return False
            payload = handle.read_output_bytes(
                output_scan, PIPEFAIL_ATOMIC_REPORT_OUTPUT
            )
            if (
                payload != primary
                or payload != bundle.oracle.outputs[0].content
                or bundle.oracle.outputs[0].mode != PIPEFAIL_ATOMIC_REPORT_OUTPUT_MODE
            ):
                return False
        final_input_scan = handle.scan_inputs()
        final_output_scan = handle.scan_outputs()
        return (
            final_input_scan == input_scan
            and final_output_scan == output_scan
            and final_input_scan.entries == baseline.input_entries
            and final_input_scan.tree_sha256 == baseline.input_tree_sha256
        )
    except (
        ExecutableWorkspaceError,
        PipefailAtomicReportError,
        OSError,
        TypeError,
        ValueError,
    ):
        return False


__all__ = [
    "PIPEFAIL_ATOMIC_REPORT_ALLOWED_TOOLS",
    "PIPEFAIL_ATOMIC_REPORT_ATOMIC_PUBLICATION_OBSERVED",
    "PIPEFAIL_ATOMIC_REPORT_ATOMIC_PUBLICATION_HISTORY_OBSERVED",
    "PIPEFAIL_ATOMIC_REPORT_DIRECTORY_PERMISSION_ERRORS_COVERED",
    "PIPEFAIL_ATOMIC_REPORT_EFFECTIVE_ACCESS_FAILURES_COVERED",
    "PIPEFAIL_ATOMIC_REPORT_FAILURE_COMMIT_POLICIES",
    "PIPEFAIL_ATOMIC_REPORT_FAMILY_ID",
    "PIPEFAIL_ATOMIC_REPORT_GENERATOR_VERSION",
    "PIPEFAIL_ATOMIC_REPORT_OUTPUT",
    "PIPEFAIL_ATOMIC_REPORT_OUTPUT_MAXIMUM_BYTES",
    "PIPEFAIL_ATOMIC_REPORT_PIPELINE_SHAPES",
    "PIPEFAIL_ATOMIC_REPORT_PIPELINE_STATUS_HISTORY_OBSERVED",
    "PIPEFAIL_ATOMIC_REPORT_PIPELINE_TOPOLOGY_HISTORY_OBSERVED",
    "PIPEFAIL_ATOMIC_REPORT_PIPESTATUS_HISTORY_OBSERVED",
    "PIPEFAIL_ATOMIC_REPORT_SYMLINK_DISTRACTORS_COVERED",
    "PIPEFAIL_ATOMIC_REPORT_TOOL_HISTORY_OBSERVED",
    "PIPEFAIL_ATOMIC_REPORT_VERIFIER_IDENTITY",
    "PIPEFAIL_ATOMIC_REPORT_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE",
    "PIPEFAIL_ATOMIC_REPORT_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE",
    "PipefailAtomicReportError",
    "PipefailAtomicReportFixtureBundle",
    "PipefailAtomicReportOracle",
    "PipefailAtomicReportParameters",
    "PipefailAtomicReportTask",
    "build_pipefail_atomic_report_fixture_bundle",
    "build_pipefail_atomic_report_tasks",
    "compute_pipefail_atomic_report_task_sha256",
    "derive_pipefail_atomic_report_output",
    "materialize_pipefail_atomic_report_fixture",
    "pipefail_atomic_report_task_semantic_core",
    "reference_pipefail_atomic_report_output",
    "validate_pipefail_atomic_report_fixture_bundle",
    "validate_pipefail_atomic_report_fixture_for_task_profile",
    "verify_pipefail_atomic_report_fixture_bundle",
    "verify_pipefail_atomic_report_fixture_for_task_profile",
    "verify_pipefail_atomic_report_output",
    "verify_pipefail_atomic_report_workspace",
]
