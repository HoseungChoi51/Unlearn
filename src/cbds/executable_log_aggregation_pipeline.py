"""Additive public method-development family for static log pipelines.

The family exercises recursive file selection, strict byte-level TSV parsing,
extended-regular-expression filtering, malformed-row policies, grouped integer
aggregation, and deterministic byte ordering.  It is intentionally absent
from the first two frozen shared registries; a later additive catalog admits
it through its exact family-local task and bundle types.

All fixture inputs and oracle values are immutable typed records.  The module
never runs candidate code.  Its materialization facade delegates exclusively
to :mod:`cbds.executable_workspace`, whose implementation uses descriptor-
relative, no-follow primitives.  Oracle construction and output verification
require agreement between two independent production implementations below.
Nothing here authorizes candidate execution, model selection, sealed scoring,
or a research claim.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import os
from pathlib import PurePosixPath
import re
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


LOG_AGGREGATION_FAMILY_ID: Final[str] = "regex-log-group-aggregation"
LOG_AGGREGATION_FILESYSTEM_IDENTITY: Final[str] = "recursive-tsv-log-tree-v1"
LOG_AGGREGATION_OUTPUT_IDENTITY: Final[str] = "byte-sorted-group-count-sum-v1"
LOG_AGGREGATION_GENERATOR_VERSION: Final[str] = "1.1.0"
LOG_AGGREGATION_VERIFIER_IDENTITY: Final[str] = (
    "verify-regex-log-group-aggregation-v1"
)
LOG_AGGREGATION_ROOT: Final[PurePosixPath] = PurePosixPath("input/logs")
LOG_AGGREGATION_OUTPUT: Final[str] = "output/summary.tsv"
LOG_AGGREGATION_OUTPUT_MODE: Final[int] = 0o644
LOG_AGGREGATION_OUTPUT_MAXIMUM_BYTES: Final[int] = 64 * 1024
LOG_AGGREGATION_ALLOWED_TOOLS: Final[tuple[str, ...]] = (
    "awk",
    "chmod",
    "find",
    "grep",
    "mkdir",
    "sort",
)

# Honest fixture-coverage boundaries.  FixtureDefinition has file/symlink
# leaves but no explicit directory modes, and no effective-access simulation.
LOG_AGGREGATION_MALFORMED_BYTES_COVERED: Final[bool] = True
LOG_AGGREGATION_UNTERMINATED_ROWS_COVERED: Final[bool] = True
LOG_AGGREGATION_SYMLINKS_COVERED: Final[bool] = True
LOG_AGGREGATION_MODE_UNREADABLE_LEAVES_COVERED: Final[bool] = True
LOG_AGGREGATION_DIRECTORY_PERMISSION_ERRORS_COVERED: Final[bool] = False
LOG_AGGREGATION_EFFECTIVE_ACCESS_FAILURES_COVERED: Final[bool] = False
LOG_AGGREGATION_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE: Final[bool] = True
LOG_AGGREGATION_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE: Final[bool] = False

SeverityEre: TypeAlias = Literal[
    "^ERROR$",
    "^(WARN|ERROR)$",
    "^[A-Z]{4}$",
    "^(INFO|WARN|ERROR)$",
]
MalformedPolicy: TypeAlias = Literal[
    "skip-row",
    "stop-file",
    "reject-file",
    "reject-all",
    "count-malformed",
]

LOG_AGGREGATION_SEVERITY_ERES: Final[tuple[SeverityEre, ...]] = (
    "^ERROR$",
    "^(WARN|ERROR)$",
    "^[A-Z]{4}$",
    "^(INFO|WARN|ERROR)$",
)
LOG_AGGREGATION_MALFORMED_POLICIES: Final[tuple[MalformedPolicy, ...]] = (
    "skip-row",
    "stop-file",
    "reject-file",
    "reject-all",
    "count-malformed",
)

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_TASK_ID_RE: Final[re.Pattern[str]] = re.compile(r"mds-[0-9a-f]{24}\Z")
_CANONICAL_INTEGER_RE: Final[re.Pattern[bytes]] = re.compile(
    rb"(?:0|-[1-9][0-9]{0,6}|[1-9][0-9]{0,6})\Z"
)
_REFERENCE_SEVERITY_RE: Final[re.Pattern[bytes]] = re.compile(rb"[A-Z]{4,8}\Z")
_MINIMUM_VALUE: Final[int] = -1_000_000
_MAXIMUM_VALUE: Final[int] = 1_000_000
_MALFORMED_GROUP: Final[bytes] = b"!malformed"


class LogAggregationPipelineError(ValueError):
    """Raised when a staged task or fixture fails closed validation."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def _closed_text(value: object, allowed: tuple[str, ...], field_name: str) -> str:
    if type(value) is not str or value not in allowed:
        raise LogAggregationPipelineError(
            f"{field_name} is outside the closed family contract"
        )
    return value


@dataclass(frozen=True, slots=True)
class LogAggregationParameters:
    """One cell in the four-ERE by five-error-policy task grid."""

    severity_ere: SeverityEre
    malformed_policy: MalformedPolicy

    def __post_init__(self) -> None:
        _closed_text(
            self.severity_ere,
            LOG_AGGREGATION_SEVERITY_ERES,
            "severity_ere",
        )
        _closed_text(
            self.malformed_policy,
            LOG_AGGREGATION_MALFORMED_POLICIES,
            "malformed_policy",
        )

    def to_record(self) -> dict[str, str]:
        self.__post_init__()
        return {
            "parameter_type": LOG_AGGREGATION_FAMILY_ID,
            "severity_ere": self.severity_ere,
            "malformed_policy": self.malformed_policy,
        }


_POLICY_TEXT: Final[dict[MalformedPolicy, str]] = {
    "skip-row": "ignore each malformed physical row and continue its file",
    "stop-file": (
        "at the first malformed physical row in each file, ignore that row "
        "and every later row in that file"
    ),
    "reject-file": (
        "if a file contains any malformed physical row, discard every row "
        "from that file"
    ),
    "reject-all": (
        "if any selected file contains a malformed physical row, emit a "
        "zero-byte output for the whole task"
    ),
    "count-malformed": (
        "ignore malformed row fields but add one count (and value zero) to "
        "the reserved output group !malformed for each malformed physical row"
    ),
}


def _task_contract(
    parameters: LogAggregationParameters,
) -> tuple[str, NormalizedSemanticGraph]:
    prompt = f"""Write one Bash program that operates only in the current workspace.

Recursively inspect regular files strictly below `input/logs/` whose basename
ends exactly in `.log`.  Never follow symbolic links.  A regular file is
mode-readable exactly when at least one 0444 permission bit is set; effective
user access does not change this definition.  Because every fixture leaf is
owned by the execution UID, a mode-0040 or mode-0004 file is not directly
kernel-readable by that owner.  For a selected regular file whose original
mode has at least one 0444 bit, you may temporarily add owner-read permission
only long enough to read it, but you must restore its exact original mode
before the program completes.  Never add a read bit to a file whose original
mode has no 0444 bit.  Process selected files in raw UTF-8 path-byte order,
although a correct result must not depend on filesystem enumeration order.

A valid physical row must end in LF and contain exactly four tab-separated byte
fields: SEVERITY, GROUP, VALUE, MESSAGE.  SEVERITY is 4 through 8 ASCII uppercase
letters.  GROUP and MESSAGE are nonempty valid UTF-8 without NUL; GROUP must not
start with `!`.  VALUE is canonical decimal `0`, `-[1-9][0-9]*`, or
`[1-9][0-9]*`, lies in [-1000000,1000000], and contains at most seven digits.
No quoting or escaping is interpreted.  A final nonempty fragment without LF,
invalid UTF-8, an extra/missing tab, or any field violation is malformed.

Keep valid rows whose SEVERITY fully matches the byte-oriented POSIX extended
regular expression `{parameters.severity_ere}`.  For malformed input,
{_POLICY_TEXT[parameters.malformed_policy]}.  For every retained GROUP, emit its
exact UTF-8 bytes, a tab, the base-10 retained-row count, a tab, the mathematical
sum of VALUE, and LF.  Sort output rows by raw GROUP bytes under `LC_ALL=C`.
Do not emit groups with zero retained rows.  An empty result is a zero-byte file.

Preserve every input path, kind, permission mode, byte, modification time,
hard-link count, and symlink target.  Leave only a real mode-0755 `output/`
directory and an independent mode-0644 regular `output/summary.tsv` with link
count one.  Use only Bash built-ins plus `awk`, `chmod`, `find`, `grep`,
`mkdir`, and `sort`.
"""
    graph = NormalizedSemanticGraph(
        nodes=(
            OperatorNode(
                "discover_readable_log_files",
                (
                    "root:input/logs",
                    "suffix:.log",
                    "follow_symlinks:false",
                    "mode-read:0444-any",
                    "temporary-owner-read:restore-exact-mode",
                ),
            ),
            OperatorNode(
                "parse_strict_tsv_log_rows",
                ("fields:4", "terminator:LF", "encoding:utf8", "value:canonical"),
            ),
            OperatorNode(
                "apply_malformed_row_policy",
                (f"policy:{parameters.malformed_policy}",),
            ),
            OperatorNode(
                "filter_severity_ere",
                (f"ere:{parameters.severity_ere}", "match:full-byte-field"),
            ),
            OperatorNode(
                "aggregate_group_count_sum",
                ("key:group-bytes", "measures:count,value-sum"),
            ),
            OperatorNode(
                "emit_sorted_tsv_summary",
                ("path:output/summary.tsv", "sort:raw-group-bytes", "mode:0644"),
            ),
        ),
        dependencies=((0, 1), (1, 2), (2, 3), (3, 4), (4, 5)),
    )
    return prompt, graph


def _validate_graph(graph: object) -> NormalizedSemanticGraph:
    if type(graph) is not NormalizedSemanticGraph:
        raise LogAggregationPipelineError("graph must have the exact graph type")
    if type(graph.nodes) is not tuple or not graph.nodes:
        raise LogAggregationPipelineError("graph nodes must be a nonempty tuple")
    if type(graph.dependencies) is not tuple:
        raise LogAggregationPipelineError("graph dependencies must be a tuple")
    for node in graph.nodes:
        if (
            type(node) is not OperatorNode
            or type(node.name) is not str
            or not node.name
            or "\0" in node.name
            or type(node.parameters) is not tuple
            or any(type(value) is not str for value in node.parameters)
        ):
            raise LogAggregationPipelineError("graph contains a noncanonical node")
    for edge in graph.dependencies:
        if (
            type(edge) is not tuple
            or len(edge) != 2
            or any(type(index) is not int for index in edge)
        ):
            raise LogAggregationPipelineError("graph contains a noncanonical edge")
        source, target = edge
        if source < 0 or source >= target or target >= len(graph.nodes):
            raise LogAggregationPipelineError("graph edge violates canonical order")
    try:
        rebuilt = NormalizedSemanticGraph(
            nodes=tuple(
                OperatorNode(node.name, node.parameters) for node in graph.nodes
            ),
            dependencies=graph.dependencies,
        )
    except (TypeError, ValueError) as exc:
        raise LogAggregationPipelineError("graph reconstruction failed") from exc
    if rebuilt != graph:
        raise LogAggregationPipelineError("graph changed during reconstruction")
    return graph


def log_aggregation_task_semantic_core(
    parameters: LogAggregationParameters,
    prompt: str,
    graph: NormalizedSemanticGraph,
) -> dict[str, object]:
    if type(parameters) is not LogAggregationParameters:
        raise LogAggregationPipelineError("parameters have the wrong exact type")
    parameters.__post_init__()
    if type(prompt) is not str or not prompt.strip() or "\0" in prompt:
        raise LogAggregationPipelineError("prompt must be exact nonempty text")
    _validate_graph(graph)
    expected_prompt, expected_graph = _task_contract(parameters)
    if prompt != expected_prompt or graph != expected_graph:
        raise LogAggregationPipelineError("prompt or graph differs from contract")
    return {
        "schema_version": EXECUTABLE_STATIC_SCHEMA_VERSION,
        "contract_version": EXECUTABLE_STATIC_CONTRACT_VERSION,
        "split_role": METHOD_DEVELOPMENT_SPLIT,
        "family_id": LOG_AGGREGATION_FAMILY_ID,
        "family_version": EXECUTABLE_STATIC_FAMILY_VERSION,
        "parameters": parameters.to_record(),
        "prompt": prompt,
        "graph": graph.to_record(),
        "graph_sha256": graph.hash,
        "filesystem_identity": LOG_AGGREGATION_FILESYSTEM_IDENTITY,
        "output_identity": LOG_AGGREGATION_OUTPUT_IDENTITY,
        "allowed_tools": list(LOG_AGGREGATION_ALLOWED_TOOLS),
        "public": True,
        "sealed": False,
        "candidate_execution_authorized": False,
        "model_selection_eligible": False,
        "claim_authorized": False,
    }


def compute_log_aggregation_task_sha256(
    parameters: LogAggregationParameters,
    prompt: str,
    graph: NormalizedSemanticGraph,
) -> str:
    return domain_sha256(
        "cbds.executable-static.task-contract.v1",
        log_aggregation_task_semantic_core(parameters, prompt, graph),
    )


@dataclass(frozen=True, slots=True)
class LogAggregationTask:
    task_id: str
    parameters: LogAggregationParameters
    prompt: str
    graph: NormalizedSemanticGraph
    fixtures: tuple[OpaqueFixtureDescriptor, ...]
    task_contract_sha256: str
    family_id: str = LOG_AGGREGATION_FAMILY_ID
    family_version: str = EXECUTABLE_STATIC_FAMILY_VERSION
    filesystem_identity: str = LOG_AGGREGATION_FILESYSTEM_IDENTITY
    output_identity: str = LOG_AGGREGATION_OUTPUT_IDENTITY
    allowed_tools: tuple[str, ...] = LOG_AGGREGATION_ALLOWED_TOOLS
    split_role: str = METHOD_DEVELOPMENT_SPLIT
    public: bool = True
    sealed: bool = False
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.parameters) is not LogAggregationParameters
            or type(self.family_id) is not str
            or self.family_id != LOG_AGGREGATION_FAMILY_ID
            or type(self.family_version) is not str
            or self.family_version != EXECUTABLE_STATIC_FAMILY_VERSION
            or type(self.filesystem_identity) is not str
            or self.filesystem_identity != LOG_AGGREGATION_FILESYSTEM_IDENTITY
            or type(self.output_identity) is not str
            or self.output_identity != LOG_AGGREGATION_OUTPUT_IDENTITY
            or type(self.allowed_tools) is not tuple
            or self.allowed_tools != LOG_AGGREGATION_ALLOWED_TOOLS
            or any(type(tool) is not str for tool in self.allowed_tools)
            or type(self.split_role) is not str
            or self.split_role != METHOD_DEVELOPMENT_SPLIT
            or self.public is not True
            or self.sealed is not False
            or self.candidate_execution_authorized is not False
            or self.model_selection_eligible is not False
            or self.claim_authorized is not False
        ):
            raise LogAggregationPipelineError("task metadata is invalid")
        expected = compute_log_aggregation_task_sha256(
            self.parameters, self.prompt, self.graph
        )
        if (
            type(self.task_id) is not str
            or _TASK_ID_RE.fullmatch(self.task_id) is None
            or not _is_sha256(self.task_contract_sha256)
            or self.task_contract_sha256 != expected
            or self.task_id != task_id_from_contract(expected)
        ):
            raise LogAggregationPipelineError("task identity is invalid")
        if (
            type(self.fixtures) is not tuple
            or len(self.fixtures) != len(PUBLIC_DEVELOPMENT_FIXTURE_PROFILES)
            or any(type(item) is not OpaqueFixtureDescriptor for item in self.fixtures)
        ):
            raise LogAggregationPipelineError("task fixture descriptors are invalid")
        for descriptor in self.fixtures:
            descriptor.__post_init__()
        if (
            len({item.fixture_id for item in self.fixtures}) != 5
            or any(item.task_contract_sha256 != expected for item in self.fixtures)
        ):
            raise LogAggregationPipelineError("task descriptor binding is invalid")

    @property
    def graph_sha256(self) -> str:
        self.__post_init__()
        return self.graph.hash

    def to_public_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            **log_aggregation_task_semantic_core(
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


def _bootstrap_task(parameters: LogAggregationParameters) -> LogAggregationTask:
    prompt, graph = _task_contract(parameters)
    digest = compute_log_aggregation_task_sha256(parameters, prompt, graph)
    return LogAggregationTask(
        task_id=task_id_from_contract(digest),
        parameters=parameters,
        prompt=prompt,
        graph=graph,
        fixtures=_bootstrap_descriptors(digest),
        task_contract_sha256=digest,
    )


def build_log_aggregation_tasks() -> tuple[LogAggregationTask, ...]:
    """Build the deterministic staged 20-task family."""

    tasks: list[LogAggregationTask] = []
    for severity_ere in LOG_AGGREGATION_SEVERITY_ERES:
        for malformed_policy in LOG_AGGREGATION_MALFORMED_POLICIES:
            bootstrap = _bootstrap_task(
                LogAggregationParameters(severity_ere, malformed_policy)
            )
            descriptors = tuple(
                _construct_log_aggregation_fixture_bundle(
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
        raise LogAggregationPipelineError("task grid is not exactly 20 unique tasks")
    return selected


def _row(severity: str, group: str, value: int, message: str) -> bytes:
    return (
        severity.encode("ascii")
        + b"\t"
        + group.encode("utf-8")
        + b"\t"
        + str(value).encode("ascii")
        + b"\t"
        + message.encode("utf-8")
        + b"\n"
    )


def _fixture_inputs(
    profile: ExecutableFixtureProfile,
) -> tuple[InputFile | InputSymlink, ...]:
    """Return explicit deterministic bytes for one public edge-case profile."""

    if profile.profile_id == "spaces-unicode":
        return (
            InputFile(
                "input/logs/service café/main log.log",
                _row("INFO", "alpha team", 2, "démarrage")
                + _row("ERROR", "alpha team", 3, "échec")
                + b"WARN\tbroken\n"
                + _row("WARN", "βeta", -2, "après erreur")
                + _row("DEBUG", "βeta", 4, "trace 雪"),
                0o640,
            ),
            InputFile(
                "input/logs/雪 audit.log",
                _row("WARN", "alpha team", 5, "attention")
                + _row("ERROR", "βeta", 7, "雪")
                + b"INFO\tbad-utf8\t1\t\xff\n"
                + b"ERROR\t\t1\tempty group\n"
                + b"ERROR\t!reserved\t1\treserved group\n"
                + b"ERROR\tnul\0group\t1\tNUL group\n"
                + b"ERROR\tbad-group-utf8-\xff\t1\tinvalid group\n"
                + b"ERROR\tmessage-nul\t1\tbad\0message\n",
                0o604,
            ),
            InputFile("input/logs/not selected.txt", b"ERROR\tx\t9\tno\n", 0o644),
            InputFile(
                "input/outside/out-of-root.log",
                _row("ERROR", "outside", 999, "must be ignored"),
                0o644,
            ),
            InputSymlink("input/logs/service café/link log.log", "main log.log"),
        )
    if profile.profile_id == "leading-dashes-globs":
        return (
            InputFile(
                "input/logs/-[prod]*?.log",
                _row("ERROR", "-[group]*?", 8, "literal glob")
                + _row("INFO", "after?", 4, "clean info"),
                0o644,
            ),
            InputFile(
                "input/logs/-nested[?]/-audit*.log",
                _row("WARN", "-[group]*?", 2, "dash")
                + _row("ABCD", "after?", -3, "four letters")
                + _row("XERROR", "near-match", 6, "not ERROR"),
                0o440,
            ),
            InputFile(
                "input/logs/-ignore[?].LOG",
                _row("ERROR", "x", 9, "case")
                + b"INFO\t-[group]*?\t01\tnoncanonical\n"
                + b"ERROR\textra-tab\t1\ttoo\tmany\n",
            ),
            InputSymlink("input/logs/-link*.log", "-[prod]*?.log"),
        )
    if profile.profile_id == "empty-duplicates":
        duplicate = _row("ERROR", "repeat", 5, "same")
        return (
            InputFile("input/logs/empty.log", b"", 0o644),
            InputFile(
                "input/logs/duplicates.log",
                duplicate
                + duplicate
                + _row("WARN", "repeat", -1, "different")
                + b"ERROR\trepeat\t5\n"
                + _row("INFO", "tail", 0, "after malformed"),
                0o644,
            ),
            InputFile(
                "input/logs/clean.log",
                _row("ABCD", "repeat", 1, "four")
                + _row("INFO", "tail", 2, "clean"),
                0o444,
            ),
        )
    if profile.profile_id == "symlinks-ordering":
        entries: list[InputFile | InputSymlink] = [
            InputFile(
                "input/logs/z-last.log",
                _row("ERROR", "zeta", 9, "last")
                + b"WARN\tzeta\t2\tunterminated",
                0o644,
            ),
            InputFile(
                "input/logs/a-first.log",
                _row("WARN", "alpha", 1, "first")
                + _row("INFO", "zeta", -4, "second"),
                0o644,
            ),
            InputFile(
                "input/logs/m-middle.log",
                _row("ABCD", "alpha", 6, "middle")
                + b"ERROR\tbad\t1000001\trange\n"
                + _row("ERROR", "omega", 3, "after"),
                0o644,
            ),
            InputSymlink("input/logs/00-duplicate.log", "z-last.log"),
            InputSymlink("input/logs/nested/link.log", "local.log"),
            InputFile(
                "input/logs/nested/local.log",
                _row("INFO", "omega", 2, "real target"),
                0o640,
            ),
        ]
        entries.reverse()
        return tuple(entries)
    if profile.profile_id == "partial-permissions":
        return (
            InputFile(
                "input/logs/group-readable.log",
                _row("ERROR", "visible", 4, "group read")
                + _row("WARN", "visible", 3, "group warning"),
                0o040,
            ),
            InputFile(
                "input/logs/other-readable.log",
                _row("INFO", "other", 2, "other read")
                + _row("ABCD", "visible", -1, "four"),
                0o004,
            ),
            InputFile(
                "input/logs/owner-readable.log",
                _row("ERROR", "other", 5, "owner read"),
                0o400,
            ),
            InputFile(
                "input/logs/permission-denied.log",
                b"not\tvalid\n"
                + b"WARN\tbroken\t+2\tnoncanonical\n"
                + _row("ERROR", "hidden", 99, "unreadable"),
                0o000,
            ),
            InputFile(
                "input/logs/executable-unreadable.log",
                _row("ERROR", "hidden", 88, "execute only"),
                0o111,
            ),
            InputSymlink("input/logs/permission-link.log", "owner-readable.log"),
        )
    raise LogAggregationPipelineError("unsupported fixture profile")


def _revalidate_definition(definition: object) -> FixtureDefinition:
    if type(definition) is not FixtureDefinition:
        raise LogAggregationPipelineError("definition has the wrong exact type")
    if (
        type(definition.fixture_id) is not str
        or type(definition.inputs) is not tuple
        or type(definition.expected_files) is not tuple
        or type(definition.schema_version) is not str
    ):
        raise LogAggregationPipelineError("definition nested types are invalid")
    for item in definition.inputs:
        if type(item) is InputFile:
            if (
                type(item.path) is not str
                or type(item.content) is not bytes
                or type(item.mode) is not int
            ):
                raise LogAggregationPipelineError("input file nested types are invalid")
        elif type(item) is InputSymlink:
            if type(item.path) is not str or type(item.target) is not str:
                raise LogAggregationPipelineError("symlink nested types are invalid")
        else:
            raise LogAggregationPipelineError("definition input type is invalid")
    for expected in definition.expected_files:
        if (
            type(expected) is not ExpectedFile
            or type(expected.path) is not str
            or type(expected.maximum_bytes) is not int
            or (expected.mode is not None and type(expected.mode) is not int)
        ):
            raise LogAggregationPipelineError("expected-file nested types are invalid")
    try:
        rebuilt = FixtureDefinition(
            fixture_id=definition.fixture_id,
            inputs=definition.inputs,
            expected_files=definition.expected_files,
            schema_version=definition.schema_version,
        )
    except (TypeError, ValueError) as exc:
        raise LogAggregationPipelineError("definition reconstruction failed") from exc
    if rebuilt != definition:
        raise LogAggregationPipelineError("definition changed on reconstruction")
    return definition


def _trusted_selected_files(definition: FixtureDefinition) -> tuple[InputFile, ...]:
    files: list[InputFile] = []
    for item in definition.inputs:
        if type(item) is not InputFile or item.mode & 0o444 == 0:
            continue
        path = PurePosixPath(item.path)
        if (
            len(path.parts) >= 3
            and path.parts[:2] == LOG_AGGREGATION_ROOT.parts
            and path.name.endswith(".log")
        ):
            files.append(item)
    return tuple(sorted(files, key=lambda item: item.path.encode("utf-8")))


def _trusted_parse_file(
    content: bytes,
) -> tuple[tuple[bytes, bytes, int] | None, ...]:
    chunks = content.split(b"\n")
    terminated_count = len(chunks) - 1
    rows: list[tuple[bytes, bytes, int] | None] = []
    for index in range(terminated_count):
        physical = chunks[index]
        fields = physical.split(b"\t")
        if len(fields) != 4:
            rows.append(None)
            continue
        severity, group, value_bytes, message = fields
        valid = (
            4 <= len(severity) <= 8
            and all(65 <= byte <= 90 for byte in severity)
            and bool(group)
            and not group.startswith(b"!")
            and b"\0" not in group
            and bool(message)
            and b"\0" not in message
            and _CANONICAL_INTEGER_RE.fullmatch(value_bytes) is not None
        )
        if valid:
            try:
                group.decode("utf-8", errors="strict")
                message.decode("utf-8", errors="strict")
                value = int(value_bytes.decode("ascii"))
            except (UnicodeDecodeError, ValueError):
                valid = False
            else:
                valid = _MINIMUM_VALUE <= value <= _MAXIMUM_VALUE
        if not valid:
            rows.append(None)
        else:
            rows.append((severity, group, value))
    if chunks[-1]:
        rows.append(None)
    return tuple(rows)


def _trusted_severity_matches(severity: bytes, expression: SeverityEre) -> bool:
    if expression == "^ERROR$":
        return severity == b"ERROR"
    if expression == "^(WARN|ERROR)$":
        return severity in {b"WARN", b"ERROR"}
    if expression == "^[A-Z]{4}$":
        return len(severity) == 4 and all(65 <= byte <= 90 for byte in severity)
    if expression == "^(INFO|WARN|ERROR)$":
        return severity in {b"INFO", b"WARN", b"ERROR"}
    raise LogAggregationPipelineError("unsupported severity ERE")


def _encode_aggregates(aggregates: dict[bytes, tuple[int, int]]) -> bytes:
    return b"".join(
        group
        + b"\t"
        + str(count).encode("ascii")
        + b"\t"
        + str(total).encode("ascii")
        + b"\n"
        for group, (count, total) in sorted(aggregates.items())
        if count > 0
    )


def derive_log_aggregation_output(
    definition: FixtureDefinition,
    parameters: LogAggregationParameters,
) -> bytes:
    """Primary trusted implementation over immutable fixture records."""

    selected = _revalidate_definition(definition)
    if type(parameters) is not LogAggregationParameters:
        raise LogAggregationPipelineError("parameters have the wrong exact type")
    parameters.__post_init__()
    aggregates: dict[bytes, tuple[int, int]] = {}
    for item in _trusted_selected_files(selected):
        parsed = _trusted_parse_file(item.content)
        malformed_count = sum(row is None for row in parsed)
        if parameters.malformed_policy == "reject-all" and malformed_count:
            return b""
        if parameters.malformed_policy == "reject-file" and malformed_count:
            continue
        for row in parsed:
            if row is None:
                if parameters.malformed_policy == "stop-file":
                    break
                if parameters.malformed_policy == "count-malformed":
                    count, total = aggregates.get(_MALFORMED_GROUP, (0, 0))
                    aggregates[_MALFORMED_GROUP] = (count + 1, total)
                continue
            severity, group, value = row
            if _trusted_severity_matches(severity, parameters.severity_ere):
                count, total = aggregates.get(group, (0, 0))
                aggregates[group] = (count + 1, total + value)
    return _encode_aggregates(aggregates)


def reference_log_aggregation_output(
    definition: FixtureDefinition,
    parameters: LogAggregationParameters,
) -> bytes:
    """Independent production reference implementation.

    This deliberately does not call the primary file selector, row parser,
    severity predicate, policy loop, or encoder.  It uses a compiled regular
    expression and a separately structured two-phase representation.
    """

    selected = _revalidate_definition(definition)
    if type(parameters) is not LogAggregationParameters:
        raise LogAggregationPipelineError("parameters have the wrong exact type")
    parameters.__post_init__()
    severity_filter = re.compile(parameters.severity_ere.encode("ascii"))
    streams: list[list[tuple[bytes, bytes, int] | object]] = []
    malformed = object()
    candidates = [
        item
        for item in selected.inputs
        if type(item) is InputFile
        and (item.mode & 0o444) != 0
        and item.path.startswith("input/logs/")
        and PurePosixPath(item.path).name[-4:] == ".log"
    ]
    candidates.sort(key=lambda item: list(item.path.encode("utf-8")))
    for item in candidates:
        stream: list[tuple[bytes, bytes, int] | object] = []
        cursor = 0
        while cursor < len(item.content):
            newline = item.content.find(b"\n", cursor)
            if newline < 0:
                stream.append(malformed)
                cursor = len(item.content)
                continue
            physical = item.content[cursor:newline]
            cursor = newline + 1
            pieces = physical.split(b"\t", 4)
            accepted: tuple[bytes, bytes, int] | None = None
            if len(pieces) == 4:
                severity, group, number, message = pieces
                try:
                    group_text = group.decode("utf-8", "strict")
                    message_text = message.decode("utf-8", "strict")
                    integer = int(number)
                except (UnicodeDecodeError, ValueError):
                    pass
                else:
                    number_is_canonical = str(integer).encode("ascii") == number
                    if (
                        _REFERENCE_SEVERITY_RE.fullmatch(severity) is not None
                        and group_text != ""
                        and not group_text.startswith("!")
                        and "\0" not in group_text
                        and message_text != ""
                        and "\0" not in message_text
                        and number_is_canonical
                        and len(number.lstrip(b"-")) <= 7
                        and _MINIMUM_VALUE <= integer <= _MAXIMUM_VALUE
                    ):
                        accepted = (severity, group, integer)
            stream.append(accepted if accepted is not None else malformed)
        streams.append(stream)

    if parameters.malformed_policy == "reject-all" and any(
        malformed in stream for stream in streams
    ):
        return bytes()
    totals: dict[bytes, list[int]] = {}
    for stream in streams:
        if parameters.malformed_policy == "reject-file" and malformed in stream:
            continue
        for value in stream:
            if value is malformed:
                if parameters.malformed_policy == "stop-file":
                    break
                if parameters.malformed_policy == "count-malformed":
                    slot = totals.setdefault(_MALFORMED_GROUP, [0, 0])
                    slot[0] += 1
                continue
            severity, group, integer = value
            if severity_filter.fullmatch(severity) is not None:
                slot = totals.setdefault(group, [0, 0])
                slot[0] += 1
                slot[1] += integer
    output = bytearray()
    for group in sorted(totals, key=lambda key: tuple(key)):
        count, total = totals[group]
        if count:
            output.extend(group)
            output.extend(b"\t")
            output.extend(format(count, "d").encode("ascii"))
            output.extend(b"\t")
            output.extend(format(total, "d").encode("ascii"))
            output.extend(b"\n")
    return bytes(output)


def verify_log_aggregation_output(
    definition: FixtureDefinition,
    parameters: LogAggregationParameters,
    candidate_output: bytes,
) -> bool:
    """Verify supplied bytes only, requiring independent oracle agreement."""

    if type(candidate_output) is not bytes:
        return False
    try:
        primary = derive_log_aggregation_output(definition, parameters)
        reference = reference_log_aggregation_output(definition, parameters)
    except (LogAggregationPipelineError, TypeError, ValueError):
        return False
    return primary == reference == candidate_output


def _compute_oracle_sha256(outputs: tuple[OracleOutputRecord, ...]) -> str:
    if (
        type(outputs) is not tuple
        or len(outputs) != 1
        or type(outputs[0]) is not OracleOutputRecord
    ):
        raise LogAggregationPipelineError("oracle output tuple is invalid")
    output = outputs[0]
    output.__post_init__()
    if (
        output.path != LOG_AGGREGATION_OUTPUT
        or output.mode != LOG_AGGREGATION_OUTPUT_MODE
        or len(output.content) > LOG_AGGREGATION_OUTPUT_MAXIMUM_BYTES
    ):
        raise LogAggregationPipelineError("oracle output contract is invalid")
    return domain_sha256(
        "cbds.executable-fixture.trusted-oracle.v1",
        {
            "schema_version": EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION,
            "semantic_verifier_identity": LOG_AGGREGATION_VERIFIER_IDENTITY,
            "outputs": [output.commitment_record()],
        },
    )


@dataclass(frozen=True, slots=True)
class LogAggregationOracle:
    outputs: tuple[OracleOutputRecord, ...]
    oracle_sha256: str
    semantic_verifier_identity: str = LOG_AGGREGATION_VERIFIER_IDENTITY
    schema_version: str = EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            type(self.semantic_verifier_identity) is not str
            or self.semantic_verifier_identity != LOG_AGGREGATION_VERIFIER_IDENTITY
            or type(self.schema_version) is not str
            or self.schema_version != EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION
            or not _is_sha256(self.oracle_sha256)
            or self.oracle_sha256 != _compute_oracle_sha256(self.outputs)
        ):
            raise LogAggregationPipelineError("oracle identity is invalid")

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
class LogAggregationFixtureBundle:
    task_contract_sha256: str
    profile_sha256: str
    definition: FixtureDefinition = field(repr=False)
    fixture_definition_sha256: str
    oracle: LogAggregationOracle = field(repr=False)
    descriptor: OpaqueFixtureDescriptor
    schema_version: str = EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_log_aggregation_fixture_bundle(self)

    def to_opaque_descriptor(self) -> OpaqueFixtureDescriptor:
        validate_log_aggregation_fixture_bundle(self)
        return self.descriptor

    def commitment_record(self) -> dict[str, object]:
        validate_log_aggregation_fixture_bundle(self)
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


def validate_log_aggregation_fixture_bundle(
    bundle: LogAggregationFixtureBundle,
) -> None:
    """Validate structural self-consistency, not task/profile authenticity."""

    if type(bundle) is not LogAggregationFixtureBundle:
        raise LogAggregationPipelineError("bundle has the wrong exact type")
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
        raise LogAggregationPipelineError("bundle metadata is invalid")
    definition = _revalidate_definition(bundle.definition)
    definition_sha256 = compute_fixture_definition_semantic_sha256(definition)
    if bundle.fixture_definition_sha256 != definition_sha256:
        raise LogAggregationPipelineError("definition digest is invalid")
    if type(bundle.oracle) is not LogAggregationOracle:
        raise LogAggregationPipelineError("oracle has the wrong exact type")
    bundle.oracle.__post_init__()
    output = bundle.oracle.outputs[0]
    if definition.expected_files != (
        ExpectedFile(
            LOG_AGGREGATION_OUTPUT,
            maximum_bytes=LOG_AGGREGATION_OUTPUT_MAXIMUM_BYTES,
            mode=LOG_AGGREGATION_OUTPUT_MODE,
        ),
    ):
        raise LogAggregationPipelineError("output policy does not bind oracle")
    if type(bundle.descriptor) is not OpaqueFixtureDescriptor:
        raise LogAggregationPipelineError("descriptor has the wrong exact type")
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
        or bundle.descriptor.task_contract_sha256 != bundle.task_contract_sha256
    ):
        raise LogAggregationPipelineError("descriptor binding is invalid")


def verify_log_aggregation_fixture_bundle(bundle: object) -> bool:
    try:
        validate_log_aggregation_fixture_bundle(bundle)  # type: ignore[arg-type]
    except (LogAggregationPipelineError, TypeError, ValueError):
        return False
    return True


def _validate_task_profile(
    task: object,
    profile: object,
) -> tuple[LogAggregationTask, ExecutableFixtureProfile]:
    if type(task) is not LogAggregationTask:
        raise LogAggregationPipelineError("task has the wrong exact type")
    if type(profile) is not ExecutableFixtureProfile:
        raise LogAggregationPipelineError("profile has the wrong exact type")
    if (
        type(profile.profile_id) is not str
        or type(profile.cases) is not tuple
        or any(type(case) is not str for case in profile.cases)
        or type(profile.profile_sha256) is not str
        or type(profile.profile_version) is not str
    ):
        raise LogAggregationPipelineError("profile nested types are invalid")
    try:
        task.__post_init__()
        LogAggregationParameters(
            task.parameters.severity_ere,
            task.parameters.malformed_policy,
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
        raise LogAggregationPipelineError("task/profile revalidation failed") from exc
    if rebuilt_profile not in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
        raise LogAggregationPipelineError("profile is not public development data")
    return task, profile


def _construct_log_aggregation_fixture_bundle(
    task: LogAggregationTask,
    profile: ExecutableFixtureProfile,
) -> LogAggregationFixtureBundle:
    """Construct a fixture while bootstrapping its public task descriptors."""

    selected_task, selected_profile = _validate_task_profile(task, profile)
    inputs = _fixture_inputs(selected_profile)
    provisional = FixtureDefinition(
        fixture_id=f"fixture.{selected_task.task_id}.{selected_profile.profile_id}",
        inputs=inputs,
        expected_files=(
            ExpectedFile(
                LOG_AGGREGATION_OUTPUT,
                maximum_bytes=LOG_AGGREGATION_OUTPUT_MAXIMUM_BYTES,
                mode=LOG_AGGREGATION_OUTPUT_MODE,
            ),
        ),
    )
    primary = derive_log_aggregation_output(provisional, selected_task.parameters)
    reference = reference_log_aggregation_output(
        provisional, selected_task.parameters
    )
    if primary != reference:
        raise LogAggregationPipelineError(
            "independent production oracle implementations disagree"
        )
    definition = FixtureDefinition(
        fixture_id=provisional.fixture_id,
        inputs=inputs,
        expected_files=(
            ExpectedFile(
                LOG_AGGREGATION_OUTPUT,
                maximum_bytes=LOG_AGGREGATION_OUTPUT_MAXIMUM_BYTES,
                mode=LOG_AGGREGATION_OUTPUT_MODE,
            ),
        ),
    )
    outputs = (
        OracleOutputRecord(
            LOG_AGGREGATION_OUTPUT,
            primary,
            LOG_AGGREGATION_OUTPUT_MODE,
        ),
    )
    oracle = LogAggregationOracle(outputs, _compute_oracle_sha256(outputs))
    definition_sha256 = compute_fixture_definition_semantic_sha256(definition)
    fixture_sha256 = compute_bound_fixture_sha256(
        task_contract_sha256=selected_task.task_contract_sha256,
        profile_sha256=selected_profile.profile_sha256,
        fixture_definition_sha256=definition_sha256,
        oracle_sha256=oracle.oracle_sha256,
    )
    return LogAggregationFixtureBundle(
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


def build_log_aggregation_fixture_bundle(
    task: LogAggregationTask,
    profile: ExecutableFixtureProfile,
) -> LogAggregationFixtureBundle:
    """Build one fixture and require its selected public descriptor to agree."""

    selected_task, selected_profile = _validate_task_profile(task, profile)
    bundle = _construct_log_aggregation_fixture_bundle(
        selected_task, selected_profile
    )
    profile_index = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES.index(selected_profile)
    if selected_task.fixtures[profile_index] != bundle.descriptor:
        raise LogAggregationPipelineError(
            "generated descriptor differs from the task's selected profile"
        )
    return bundle


def validate_log_aggregation_fixture_for_task_profile(
    task: LogAggregationTask,
    profile: ExecutableFixtureProfile,
    bundle: LogAggregationFixtureBundle,
) -> None:
    """Authenticate a bundle by deterministic task/profile reconstruction."""

    selected_task, selected_profile = _validate_task_profile(task, profile)
    validate_log_aggregation_fixture_bundle(bundle)
    expected = build_log_aggregation_fixture_bundle(selected_task, selected_profile)
    if bundle != expected:
        raise LogAggregationPipelineError("bundle differs from reconstruction")
    profile_index = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES.index(selected_profile)
    if selected_task.fixtures[profile_index] != expected.descriptor:
        raise LogAggregationPipelineError("task descriptor differs from fixture")


def verify_log_aggregation_fixture_for_task_profile(
    task: object,
    profile: object,
    bundle: object,
) -> bool:
    try:
        validate_log_aggregation_fixture_for_task_profile(
            task,  # type: ignore[arg-type]
            profile,  # type: ignore[arg-type]
            bundle,  # type: ignore[arg-type]
        )
    except (LogAggregationPipelineError, TypeError, ValueError):
        return False
    return True


def materialize_log_aggregation_fixture(
    task: LogAggregationTask,
    profile: ExecutableFixtureProfile,
    bundle: LogAggregationFixtureBundle,
    workspace: str | os.PathLike[str],
) -> WorkspaceHandle:
    """Authenticate then use the shared descriptor-relative materializer."""

    validate_log_aggregation_fixture_for_task_profile(task, profile, bundle)
    return materialize_fixture(bundle.definition, workspace)


def verify_log_aggregation_workspace(
    task: LogAggregationTask,
    profile: ExecutableFixtureProfile,
    bundle: LogAggregationFixtureBundle,
    handle: WorkspaceHandle,
) -> bool:
    """Verify the complete post-run workspace without executing a candidate.

    Authentication binds the task, profile, definition, oracle, and public
    descriptor.  The pinned handle must name the same materialization and
    output policy.  Stable no-follow scans then require exact preservation of
    the initial input tree, including content, mode, mtime, link count, kind,
    and symlink target.  The shared output-policy validator rejects every
    extra/missing path, non-directory ancestor, symlink, hard link, wrong mode,
    and oversized file.  Output bytes leave the workspace only through the
    bounded descriptor-relative handle egress and must agree with both
    independent production implementations.

    A trusted harness must stop every candidate and other workspace writer
    before calling this function and keep the workspace quiescent through its
    return.  Repeated stable scans detect changes between observations; they do
    not prove global quiescence or exclude a mutation after the final scan.
    """

    if type(handle) is not WorkspaceHandle:
        return False
    try:
        validate_log_aggregation_fixture_for_task_profile(task, profile, bundle)
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
        output_entries = validate_expected_output_policy(
            bundle.definition, output_scan
        )
        if (
            len(output_entries) != 1
            or output_entries[0].path != LOG_AGGREGATION_OUTPUT
            or output_entries[0].mode != LOG_AGGREGATION_OUTPUT_MODE
        ):
            return False
        payload = handle.read_output_bytes(output_scan, LOG_AGGREGATION_OUTPUT)
        primary = derive_log_aggregation_output(
            bundle.definition, task.parameters
        )
        reference = reference_log_aggregation_output(
            bundle.definition, task.parameters
        )
        if (
            primary != reference
            or payload != primary
            or payload != bundle.oracle.outputs[0].content
            or bundle.oracle.outputs[0].mode != LOG_AGGREGATION_OUTPUT_MODE
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
        LogAggregationPipelineError,
        OSError,
        TypeError,
        ValueError,
    ):
        return False


__all__ = [
    "LOG_AGGREGATION_ALLOWED_TOOLS",
    "LOG_AGGREGATION_DIRECTORY_PERMISSION_ERRORS_COVERED",
    "LOG_AGGREGATION_EFFECTIVE_ACCESS_FAILURES_COVERED",
    "LOG_AGGREGATION_FAMILY_ID",
    "LOG_AGGREGATION_GENERATOR_VERSION",
    "LOG_AGGREGATION_MALFORMED_BYTES_COVERED",
    "LOG_AGGREGATION_MALFORMED_POLICIES",
    "LOG_AGGREGATION_MODE_UNREADABLE_LEAVES_COVERED",
    "LOG_AGGREGATION_OUTPUT",
    "LOG_AGGREGATION_OUTPUT_MAXIMUM_BYTES",
    "LOG_AGGREGATION_SEVERITY_ERES",
    "LOG_AGGREGATION_SYMLINKS_COVERED",
    "LOG_AGGREGATION_UNTERMINATED_ROWS_COVERED",
    "LOG_AGGREGATION_VERIFIER_IDENTITY",
    "LOG_AGGREGATION_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE",
    "LOG_AGGREGATION_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE",
    "LogAggregationFixtureBundle",
    "LogAggregationOracle",
    "LogAggregationParameters",
    "LogAggregationPipelineError",
    "LogAggregationTask",
    "build_log_aggregation_fixture_bundle",
    "build_log_aggregation_tasks",
    "compute_log_aggregation_task_sha256",
    "derive_log_aggregation_output",
    "log_aggregation_task_semantic_core",
    "materialize_log_aggregation_fixture",
    "reference_log_aggregation_output",
    "validate_log_aggregation_fixture_bundle",
    "validate_log_aggregation_fixture_for_task_profile",
    "verify_log_aggregation_fixture_bundle",
    "verify_log_aggregation_fixture_for_task_profile",
    "verify_log_aggregation_output",
    "verify_log_aggregation_workspace",
]
