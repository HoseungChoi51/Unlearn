"""Isolated public method-development family for compound path queries.

This module is intentionally additive.  The first two executable-static
registries and their closed shared type unions remain untouched while this
family is reviewed.  It nevertheless uses the same task, profile, workspace,
oracle, and opaque-fixture hash domains so a later registry integration can be
mechanical.

Both independently structured trusted implementations operate only on
immutable ``FixtureDefinition`` records and must agree.  The authenticated
workspace facade uses descriptor-relative materialization and bounded reads;
it does not invoke a shell, execute a candidate, or authorize execution,
model selection, or a research claim.
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


COMPOUND_PATH_QUERY_FAMILY_ID: Final[str] = "compound-path-query"
COMPOUND_PATH_QUERY_FILESYSTEM_IDENTITY: Final[str] = (
    "compound-query-tree-v1"
)
COMPOUND_PATH_QUERY_OUTPUT_IDENTITY: Final[str] = (
    "utf8-byte-sorted-compound-paths-v1"
)
COMPOUND_PATH_QUERY_GENERATOR_VERSION: Final[str] = "1.0.0"
COMPOUND_PATH_QUERY_VERIFIER_IDENTITY: Final[str] = (
    "verify-compound-path-query-v1"
)
COMPOUND_PATH_QUERY_ROOT: Final[PurePosixPath] = PurePosixPath("input/query")
COMPOUND_PATH_QUERY_OUTPUT: Final[str] = "output/matches.txt"
COMPOUND_PATH_QUERY_OUTPUT_MODE: Final[int] = 0o644
COMPOUND_PATH_DIRECTORY_PERMISSION_ERRORS_COVERED: Final[bool] = False
COMPOUND_PATH_QUERY_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE: Final[
    bool
] = True
COMPOUND_PATH_QUERY_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE: Final[bool] = False
COMPOUND_PATH_QUERY_ALLOWED_TOOLS: Final[tuple[str, ...]] = (
    "find",
    "mkdir",
    "sort",
)

NamePattern: TypeAlias = Literal[
    "*.txt",
    "report-*",
    "[a-z]*.log",
    "*.[0-9]",
]
CompoundExpression: TypeAlias = Literal[
    "readable-regular-and-name",
    "readable-regular-and-not-name",
    "readable-regular-and-name-or-symlink",
    "readable-regular-and-name-or-executable",
    "readable-regular-and-name-depth-at-most-three",
]

COMPOUND_PATH_NAME_PATTERNS: Final[tuple[NamePattern, ...]] = (
    "*.txt",
    "report-*",
    "[a-z]*.log",
    "*.[0-9]",
)
COMPOUND_PATH_EXPRESSIONS: Final[tuple[CompoundExpression, ...]] = (
    "readable-regular-and-name",
    "readable-regular-and-not-name",
    "readable-regular-and-name-or-symlink",
    "readable-regular-and-name-or-executable",
    "readable-regular-and-name-depth-at-most-three",
)

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_TASK_ID_RE: Final[re.Pattern[str]] = re.compile(r"mds-[0-9a-f]{24}\Z")
_READ_BITS: Final[int] = 0o444
_EXECUTE_BITS: Final[int] = 0o111
_REFERENCE_PATTERN_BYTES: Final[dict[str, bytes]] = {
    "*.txt": rb".*\.txt\Z",
    "report-*": rb"report-.*\Z",
    "[a-z]*.log": rb"[a-z].*\.log\Z",
    "*.[0-9]": rb".*\.[0-9]\Z",
}


class CompoundPathQueryError(ValueError):
    """Raised when a compound-path task or fixture fails closed validation."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def _require_closed_text(value: object, allowed: tuple[str, ...], field: str) -> str:
    if type(value) is not str or value not in allowed:
        raise CompoundPathQueryError(f"{field} is outside the closed contract")
    return value


@dataclass(frozen=True, slots=True)
class CompoundPathQueryParameters:
    """The four-by-five semantic parameter grid for this family."""

    name_pattern: NamePattern
    expression: CompoundExpression

    def __post_init__(self) -> None:
        _require_closed_text(
            self.name_pattern,
            COMPOUND_PATH_NAME_PATTERNS,
            "name_pattern",
        )
        _require_closed_text(
            self.expression,
            COMPOUND_PATH_EXPRESSIONS,
            "expression",
        )

    def to_record(self) -> dict[str, str]:
        self.__post_init__()
        return {
            "parameter_type": COMPOUND_PATH_QUERY_FAMILY_ID,
            "name_pattern": self.name_pattern,
            "expression": self.expression,
        }


_EXPRESSION_TEXT: Final[dict[CompoundExpression, str]] = {
    "readable-regular-and-name": (
        "a path matches exactly when it is a mode-readable regular file AND "
        "its basename matches the name pattern"
    ),
    "readable-regular-and-not-name": (
        "a path matches exactly when it is a mode-readable regular file AND "
        "its basename does NOT match the name pattern"
    ),
    "readable-regular-and-name-or-symlink": (
        "a path matches exactly when (it is a mode-readable regular file AND "
        "its basename matches the name pattern) OR it is a symbolic link"
    ),
    "readable-regular-and-name-or-executable": (
        "a path matches exactly when it is a mode-readable regular file AND "
        "(its basename matches the name pattern OR at least one execute bit "
        "is set)"
    ),
    "readable-regular-and-name-depth-at-most-three": (
        "a path matches exactly when it is a mode-readable regular file AND "
        "its basename matches the name pattern AND its relative path has at "
        "most three components"
    ),
}


def _task_contract(
    parameters: CompoundPathQueryParameters,
) -> tuple[str, NormalizedSemanticGraph]:
    prompt = f"""Write one Bash program that operates only in the current workspace.

Recursively inspect paths strictly below `input/query/` without following any
symbolic link.  Apply the basename pattern `{parameters.name_pattern}` with the
same byte-oriented `LC_ALL=C` wildcard semantics as GNU `find -name`: `*`
matches zero or more bytes, `?` matches one byte, and `[a-z]` and `[0-9]` are
the literal ASCII ranges shown.  A regular file is mode-readable exactly when
at least one of its 0444 permission bits is set; effective-user access does not
change this definition.  Relative-path depth is the number of components below
`input/query/`.  {_EXPRESSION_TEXT[parameters.expression].capitalize()}.

Emit the path of every match relative to `input/query/`, one path per physical
line, sorted by raw UTF-8 bytes under `LC_ALL=C`.  An empty result is a zero-byte
file; otherwise the final line ends in LF.  Preserve every path, file kind,
permission mode, byte, modification time, hard-link count, and symlink target
below `input/`.  Leave only a real mode-0755 `output/` directory and an
independent mode-0644 regular file `output/matches.txt` with link count one.
Use only Bash built-ins plus `find`, `mkdir`, and `sort`.
"""
    graph = NormalizedSemanticGraph(
        nodes=(
            OperatorNode(
                "discover_compound_query_paths",
                ("root:input/query", "follow_symlinks:false", "locale:C"),
            ),
            OperatorNode(
                "match_compound_query_basename",
                (f"pattern:{parameters.name_pattern}", "scope:basename"),
            ),
            OperatorNode(
                "classify_compound_query_entry",
                ("kind:lstat", "readable:mode-0444", "depth:relative-components"),
            ),
            OperatorNode(
                "evaluate_compound_query_expression",
                (f"expression:{parameters.expression}",),
            ),
            OperatorNode(
                "sort_compound_query_paths",
                ("key:utf8-bytes", "locale:C", "duplicates:preserve-path-identity"),
            ),
            OperatorNode(
                "emit_compound_query_lines",
                ("path:output/matches.txt", "file_mode:0644", "directory_mode:0755"),
            ),
        ),
        dependencies=((0, 1), (0, 2), (1, 3), (2, 3), (3, 4), (4, 5)),
    )
    return prompt, graph


def _validate_graph(graph: object) -> NormalizedSemanticGraph:
    if type(graph) is not NormalizedSemanticGraph:
        raise CompoundPathQueryError("graph must be an exact semantic graph")
    if type(graph.nodes) is not tuple or not graph.nodes:
        raise CompoundPathQueryError("graph nodes must be a nonempty exact tuple")
    if type(graph.dependencies) is not tuple:
        raise CompoundPathQueryError("graph dependencies must be an exact tuple")
    for node in graph.nodes:
        if (
            type(node) is not OperatorNode
            or type(node.name) is not str
            or not node.name
            or "\0" in node.name
            or type(node.parameters) is not tuple
            or any(type(value) is not str for value in node.parameters)
        ):
            raise CompoundPathQueryError("graph contains a noncanonical node")
    for edge in graph.dependencies:
        if (
            type(edge) is not tuple
            or len(edge) != 2
            or any(type(index) is not int for index in edge)
        ):
            raise CompoundPathQueryError("graph contains a noncanonical edge")
        source, target = edge
        if source < 0 or target >= len(graph.nodes) or source >= target:
            raise CompoundPathQueryError("graph edge is outside canonical order")
    # Reconstruct so a low-level mutation of a frozen graph is not trusted.
    try:
        reconstructed = NormalizedSemanticGraph(
            nodes=tuple(
                OperatorNode(node.name, node.parameters) for node in graph.nodes
            ),
            dependencies=graph.dependencies,
        )
    except (TypeError, ValueError) as exc:
        raise CompoundPathQueryError("graph reconstruction failed") from exc
    if reconstructed != graph:
        raise CompoundPathQueryError("graph reconstruction changed its content")
    return graph


def compound_path_query_task_semantic_core(
    parameters: CompoundPathQueryParameters,
    prompt: str,
    graph: NormalizedSemanticGraph,
) -> dict[str, object]:
    """Return the registry-compatible semantic task core for this family."""

    if type(parameters) is not CompoundPathQueryParameters:
        raise CompoundPathQueryError("parameters have the wrong exact type")
    parameters.__post_init__()
    if type(prompt) is not str or not prompt.strip() or "\0" in prompt:
        raise CompoundPathQueryError("prompt must be nonempty NUL-free exact text")
    _validate_graph(graph)
    expected_prompt, expected_graph = _task_contract(parameters)
    if prompt != expected_prompt or graph != expected_graph:
        raise CompoundPathQueryError("prompt or graph differs from the family contract")
    return {
        "schema_version": EXECUTABLE_STATIC_SCHEMA_VERSION,
        "contract_version": EXECUTABLE_STATIC_CONTRACT_VERSION,
        "split_role": METHOD_DEVELOPMENT_SPLIT,
        "family_id": COMPOUND_PATH_QUERY_FAMILY_ID,
        "family_version": EXECUTABLE_STATIC_FAMILY_VERSION,
        "parameters": parameters.to_record(),
        "prompt": prompt,
        "graph": graph.to_record(),
        "graph_sha256": graph.hash,
        "filesystem_identity": COMPOUND_PATH_QUERY_FILESYSTEM_IDENTITY,
        "output_identity": COMPOUND_PATH_QUERY_OUTPUT_IDENTITY,
        "allowed_tools": list(COMPOUND_PATH_QUERY_ALLOWED_TOOLS),
        "public": True,
        "sealed": False,
        "claim_authorized": False,
    }


def compute_compound_path_query_task_sha256(
    parameters: CompoundPathQueryParameters,
    prompt: str,
    graph: NormalizedSemanticGraph,
) -> str:
    return domain_sha256(
        "cbds.executable-static.task-contract.v1",
        compound_path_query_task_semantic_core(parameters, prompt, graph),
    )


@dataclass(frozen=True, slots=True)
class CompoundPathQueryTask:
    """Family-local exact task value pending shared-registry integration."""

    task_id: str
    parameters: CompoundPathQueryParameters
    prompt: str
    graph: NormalizedSemanticGraph
    fixtures: tuple[OpaqueFixtureDescriptor, ...]
    task_contract_sha256: str
    family_id: str = COMPOUND_PATH_QUERY_FAMILY_ID
    family_version: str = EXECUTABLE_STATIC_FAMILY_VERSION
    filesystem_identity: str = COMPOUND_PATH_QUERY_FILESYSTEM_IDENTITY
    output_identity: str = COMPOUND_PATH_QUERY_OUTPUT_IDENTITY
    allowed_tools: tuple[str, ...] = COMPOUND_PATH_QUERY_ALLOWED_TOOLS
    split_role: str = METHOD_DEVELOPMENT_SPLIT
    public: bool = True
    sealed: bool = False
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.family_id) is not str
            or self.family_id != COMPOUND_PATH_QUERY_FAMILY_ID
            or type(self.family_version) is not str
            or self.family_version != EXECUTABLE_STATIC_FAMILY_VERSION
            or type(self.filesystem_identity) is not str
            or self.filesystem_identity != COMPOUND_PATH_QUERY_FILESYSTEM_IDENTITY
            or type(self.output_identity) is not str
            or self.output_identity != COMPOUND_PATH_QUERY_OUTPUT_IDENTITY
            or type(self.allowed_tools) is not tuple
            or self.allowed_tools != COMPOUND_PATH_QUERY_ALLOWED_TOOLS
            or type(self.split_role) is not str
            or self.split_role != METHOD_DEVELOPMENT_SPLIT
            or self.public is not True
            or self.sealed is not False
            or self.candidate_execution_authorized is not False
            or self.model_selection_eligible is not False
            or self.claim_authorized is not False
        ):
            raise CompoundPathQueryError("task metadata or authority boundary is invalid")
        expected = compute_compound_path_query_task_sha256(
            self.parameters,
            self.prompt,
            self.graph,
        )
        if (
            not _is_sha256(self.task_contract_sha256)
            or self.task_contract_sha256 != expected
            or type(self.task_id) is not str
            or _TASK_ID_RE.fullmatch(self.task_id) is None
            or self.task_id != task_id_from_contract(expected)
        ):
            raise CompoundPathQueryError("task identity is not content derived")
        if (
            type(self.fixtures) is not tuple
            or len(self.fixtures) != len(PUBLIC_DEVELOPMENT_FIXTURE_PROFILES)
            or any(type(item) is not OpaqueFixtureDescriptor for item in self.fixtures)
        ):
            raise CompoundPathQueryError("task fixtures must be five exact descriptors")
        for descriptor in self.fixtures:
            descriptor.__post_init__()
        if (
            len({item.fixture_id for item in self.fixtures}) != 5
            or any(item.task_contract_sha256 != expected for item in self.fixtures)
        ):
            raise CompoundPathQueryError("task fixture descriptors are invalid")

    @property
    def graph_sha256(self) -> str:
        self.__post_init__()
        return self.graph.hash

    def to_public_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            **compound_path_query_task_semantic_core(
                self.parameters,
                self.prompt,
                self.graph,
            ),
            "task_id": self.task_id,
            "task_contract_sha256": self.task_contract_sha256,
            "fixtures": [item.to_public_record() for item in self.fixtures],
        }


def _bootstrap_descriptors(task_sha256: str) -> tuple[OpaqueFixtureDescriptor, ...]:
    descriptors: list[OpaqueFixtureDescriptor] = []
    for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
        digest = domain_sha256(
            "cbds.executable-static.fixture.v1",
            {
                "task_contract_sha256": task_sha256,
                "profile_sha256": profile.profile_sha256,
            },
        )
        descriptors.append(
            OpaqueFixtureDescriptor(
                fixture_id=f"fx-{digest[:24]}",
                fixture_sha256=digest,
                task_contract_sha256=task_sha256,
            )
        )
    return tuple(descriptors)


def _build_bootstrap_task(
    parameters: CompoundPathQueryParameters,
) -> CompoundPathQueryTask:
    prompt, graph = _task_contract(parameters)
    contract_sha256 = compute_compound_path_query_task_sha256(
        parameters,
        prompt,
        graph,
    )
    return CompoundPathQueryTask(
        task_id=task_id_from_contract(contract_sha256),
        parameters=parameters,
        prompt=prompt,
        graph=graph,
        fixtures=_bootstrap_descriptors(contract_sha256),
        task_contract_sha256=contract_sha256,
    )


def build_compound_path_query_tasks() -> tuple[CompoundPathQueryTask, ...]:
    """Build the deterministic four-pattern by five-expression task grid."""

    tasks: list[CompoundPathQueryTask] = []
    for name_pattern in COMPOUND_PATH_NAME_PATTERNS:
        for expression in COMPOUND_PATH_EXPRESSIONS:
            bootstrap = _build_bootstrap_task(
                CompoundPathQueryParameters(
                    name_pattern=name_pattern,
                    expression=expression,
                )
            )
            descriptors = tuple(
                build_compound_path_query_fixture_bundle(bootstrap, profile).descriptor
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
        raise CompoundPathQueryError("compound-path task grid is not 20 unique tasks")
    return selected


# The path roles are semantically parallel across profiles while their literal
# names and insertion order realize the five public edge-case commitments.
_PROFILE_PATHS: Final[dict[str, dict[str, str]]] = {
    "spaces-unicode": {
        "joint": "report-café snow.txt",
        "txt_only": "plain café.txt",
        "report_only": "report-雪-only.bin",
        "class_log": "dir space/alpha snow.log",
        "digit": "雪/data.7",
        "depth3_txt": "depth three/slot/plain snow.txt",
        "depth3_report": "depth three/slot/report-雪-three.bin",
        "depth3_log": "depth three/slot/alpha snow.log",
        "depth3_digit": "depth three/slot/value.5",
        "deep_txt": "deep space/é/x/deep snow.txt",
        "deep_report": "deep space/é/x/report-雪.bin",
        "deep_log": "deep space/é/x/alpha雪.log",
        "deep_digit": "deep space/é/x/value.3",
        "worker": "worker café.bin",
        "worker_other": "other worker 雪.bin",
        "plain": "notes 雪.md",
        "locked_txt": "locked space.txt",
        "locked_report": "report-locked 雪.bin",
        "locked_log": "locked space.log",
        "locked_digit": "locked.9",
        "link_one": "link café.txt",
        "link_two": "report-link 雪",
    },
    "leading-dashes-globs": {
        "joint": "report--dash[glob]*?.txt",
        "txt_only": "-plain[only]*?.txt",
        "report_only": "report--only[?].bin",
        "class_log": "-dir/alpha[glob]*?.log",
        "digit": "-dir/[x]/-data.7",
        "depth3_txt": "-three/[x]/-plain?.txt",
        "depth3_report": "-three/[x]/report-[?].bin",
        "depth3_log": "-three/[x]/alpha[*].log",
        "depth3_digit": "-three/[x]/-value.5",
        "deep_txt": "-deep/[a]/*/deep?.txt",
        "deep_report": "-deep/[a]/*/report-?*.bin",
        "deep_log": "-deep/[a]/*/alpha[?].log",
        "deep_digit": "-deep/[a]/*/-value.3",
        "worker": "-worker[run]*?.bin",
        "worker_other": "-other-worker[run]?.bin",
        "plain": "-[notes]*?.md",
        "locked_txt": "-locked[?].txt",
        "locked_report": "report-[locked]*?",
        "locked_log": "locked[?].log",
        "locked_digit": "-locked.9",
        "link_one": "-[link]*?.txt",
        "link_two": "report-[link]*?",
    },
    "empty-duplicates": {
        "joint": "one/report-repeat.txt",
        "txt_only": "one/repeat.txt",
        "report_only": "one/report-repeat.bin",
        "class_log": "two/alpha.log",
        "digit": "three/data.7",
        "depth3_txt": "three/a/repeat.txt",
        "depth3_report": "three/a/report-repeat.bin",
        "depth3_log": "three/a/alpha.log",
        "depth3_digit": "three/a/data.7",
        "deep_txt": "deep/x/y/repeat.txt",
        "deep_report": "deep/x/y/report-repeat.bin",
        "deep_log": "deep/x/y/alpha.log",
        "deep_digit": "deep/x/y/data.7",
        "worker": "worker.bin",
        "worker_other": "other-worker.bin",
        "plain": "notes.md",
        "locked_txt": "locked.txt",
        "locked_report": "report-locked.bin",
        "locked_log": "locked.log",
        "locked_digit": "locked.9",
        "link_one": "linked.txt",
        "link_two": "report-link",
    },
    "symlinks-ordering": {
        "joint": "z/report-zeta.txt",
        "txt_only": "c-plain.txt",
        "report_only": "report-c-only.bin",
        "class_log": "a/alpha.log",
        "digit": "m/data.7",
        "depth3_txt": "c/b/plain.txt",
        "depth3_report": "c/b/report-three.bin",
        "depth3_log": "c/b/alpha-three.log",
        "depth3_digit": "c/b/value.5",
        "deep_txt": "z/y/x/deep.txt",
        "deep_report": "a/z/y/report-deep.bin",
        "deep_log": "m/z/y/alpha-deep.log",
        "deep_digit": "b/z/y/value.3",
        "worker": "zz-worker.bin",
        "worker_other": "yy-other-worker.bin",
        "plain": "aa-notes.md",
        "locked_txt": "y-locked.txt",
        "locked_report": "report-a-locked.bin",
        "locked_log": "xlocked.log",
        "locked_digit": "wlocked.9",
        "link_one": "00-linked.txt",
        "link_two": "report-zz-link",
    },
    # FixtureDefinition represents file and symlink leaves, not explicit
    # directory modes.  This profile exercises mode-denied leaf predicates;
    # it does not claim directory permission-failure coverage.
    "partial-permissions": {
        "joint": "readable/report-anchor.txt",
        "txt_only": "group-readable.txt",
        "report_only": "report-other-readable.bin",
        "class_log": "partial/alpha.log",
        "digit": "partial/deeper/data.7",
        "depth3_txt": "three/a/plain.txt",
        "depth3_report": "three/a/report-three.bin",
        "depth3_log": "three/a/alpha-three.log",
        "depth3_digit": "three/a/value.5",
        "deep_txt": "partial/a/b/deep.txt",
        "deep_report": "partial/a/b/report-deep.bin",
        "deep_log": "partial/a/b/alpha-deep.log",
        "deep_digit": "partial/a/b/value.3",
        "worker": "partial-worker.bin",
        "worker_other": "other-worker.bin",
        "plain": "readable-notes.md",
        "locked_txt": "permission-denied.txt",
        "locked_report": "report-permission-denied.bin",
        "locked_log": "permission-denied.log",
        "locked_digit": "permission-denied.9",
        "link_one": "permission-link.txt",
        "link_two": "report-permission-link",
    },
}


def _fixture_inputs(
    profile: ExecutableFixtureProfile,
) -> tuple[InputFile | InputSymlink, ...]:
    paths = _PROFILE_PATHS.get(profile.profile_id)
    if paths is None:
        raise CompoundPathQueryError("fixture profile has no compound-path cases")

    def full(role: str) -> str:
        return (COMPOUND_PATH_QUERY_ROOT / paths[role]).as_posix()

    empty = profile.profile_id == "empty-duplicates"
    if empty:
        # Every entry below the queried root is deliberately mode-unreadable.
        # The duplicated basenames at shallow and deep paths still exercise
        # path identity, while the two symlinks and readable/executable decoys
        # live outside input/query and therefore cannot satisfy any of the five
        # expressions.  This gives every task in the grid a genuine zero-byte
        # empty-result oracle rather than merely placing empty content in files
        # whose content the query never consults.
        return (
            InputFile(full("joint"), b"", 0o000),
            InputFile(full("txt_only"), b"", 0o000),
            InputFile(full("report_only"), b"", 0o000),
            InputFile(full("class_log"), b"", 0o000),
            InputFile(full("digit"), b"", 0o000),
            InputFile(full("depth3_txt"), b"duplicate bytes\n", 0o000),
            InputFile(full("depth3_report"), b"duplicate bytes\n", 0o000),
            InputFile(full("depth3_log"), b"", 0o000),
            InputFile(full("depth3_digit"), b"", 0o000),
            InputFile(full("deep_txt"), b"duplicate bytes\n", 0o000),
            InputFile(full("deep_report"), b"duplicate bytes\n", 0o000),
            InputFile(full("deep_log"), b"", 0o000),
            InputFile(full("deep_digit"), b"", 0o000),
            InputFile(full("worker"), b"unreadable executable\n", 0o111),
            InputFile(full("worker_other"), b"unreadable executable\n", 0o011),
            InputFile(full("plain"), b"", 0o000),
            InputFile(full("locked_txt"), b"", 0o000),
            InputFile(full("locked_report"), b"", 0o000),
            InputFile(full("locked_log"), b"", 0o000),
            InputFile(full("locked_digit"), b"", 0o000),
            InputFile(
                (COMPOUND_PATH_QUERY_ROOT / "unreadable-executable.bin").as_posix(),
                b"unreadable executable decoy\n",
                0o111,
            ),
            InputFile("input/query/decoys/Alpha.log", b"", 0o000),
            InputFile("input/query/decoys/éclair.log", b"", 0o000),
            InputFile("input/outside/report-outside.txt", b"outside root\n", 0o644),
            InputFile("input/outside/worker.bin", b"outside executable\n", 0o555),
            InputSymlink("input/outside/linked.txt", "report-outside.txt"),
            InputSymlink("input/outside/report-link", "worker.bin"),
        )
    entries: list[InputFile | InputSymlink] = [
        InputFile(full("joint"), b"joint\n", 0o640),
        InputFile(full("txt_only"), b"group-readable txt\n", 0o040),
        InputFile(full("report_only"), b"other-readable report\n", 0o004),
        InputFile(full("class_log"), b"other-readable class\n", 0o004),
        InputFile(full("digit"), b"group-readable digit\n", 0o040),
        InputFile(full("depth3_txt"), b"other-readable depth three\n", 0o004),
        InputFile(full("depth3_report"), b"group-readable depth three\n", 0o040),
        InputFile(full("depth3_log"), b"group-readable depth three\n", 0o040),
        InputFile(full("depth3_digit"), b"other-readable depth three\n", 0o004),
        InputFile(full("deep_txt"), b"deep txt\n", 0o644),
        InputFile(full("deep_report"), b"deep report\n", 0o604),
        InputFile(full("deep_log"), b"deep log\n", 0o440),
        InputFile(full("deep_digit"), b"deep digit\n", 0o444),
        InputFile(full("worker"), b"group executable alternative\n", 0o050),
        InputFile(full("worker_other"), b"other executable alternative\n", 0o005),
        InputFile(full("plain"), b"plain readable\n", 0o600),
        InputFile(full("locked_txt"), b"must stay unreadable\n", 0o000),
        InputFile(full("locked_report"), b"must stay unreadable\n", 0o000),
        InputFile(full("locked_log"), b"must stay unreadable\n", 0o000),
        InputFile(full("locked_digit"), b"must stay unreadable\n", 0o000),
        # An executable but mode-unreadable file distinguishes
        # R AND (N OR X) from the incorrectly parenthesized (R AND N) OR X.
        InputFile(
            (COMPOUND_PATH_QUERY_ROOT / "unreadable-executable.bin").as_posix(),
            b"unreadable executable decoy\n",
            0o111,
        ),
        # Both are readable .log files but fail the literal ASCII [a-z]
        # first-byte range in the closed basename pattern.
        InputFile("input/query/decoys/Alpha.log", b"uppercase decoy\n", 0o644),
        InputFile("input/query/decoys/éclair.log", b"non-ASCII decoy\n", 0o644),
        InputFile("input/outside/report-outside.txt", b"outside root\n", 0o644),
        InputSymlink(full("link_one"), PurePosixPath(paths["joint"]).name),
        InputSymlink(full("link_two"), PurePosixPath(paths["worker"]).name),
    ]
    if profile.profile_id == "symlinks-ordering":
        entries.reverse()
    return tuple(entries)


def _matches_name_pattern(name: str, pattern: NamePattern) -> bool:
    """Implement only the four byte-oriented patterns in the closed grid."""

    if pattern == "*.txt":
        return name.endswith(".txt")
    if pattern == "report-*":
        return name.startswith("report-")
    if pattern == "[a-z]*.log":
        return len(name) >= 5 and "a" <= name[0] <= "z" and name.endswith(".log")
    if pattern == "*.[0-9]":
        return len(name) >= 2 and name[-2] == "." and "0" <= name[-1] <= "9"
    raise CompoundPathQueryError("unsupported name pattern")


def _relative_query_path(path: str) -> PurePosixPath | None:
    candidate = PurePosixPath(path)
    if candidate.parts[:2] != COMPOUND_PATH_QUERY_ROOT.parts or len(candidate.parts) < 3:
        return None
    return PurePosixPath(*candidate.parts[2:])


def _entry_matches(
    item: InputFile | InputSymlink,
    relative: PurePosixPath,
    parameters: CompoundPathQueryParameters,
) -> bool:
    name_matches = _matches_name_pattern(relative.name, parameters.name_pattern)
    is_regular = type(item) is InputFile
    is_symlink = type(item) is InputSymlink
    readable_regular = is_regular and bool(item.mode & _READ_BITS)
    executable = is_regular and bool(item.mode & _EXECUTE_BITS)
    if parameters.expression == "readable-regular-and-name":
        return readable_regular and name_matches
    if parameters.expression == "readable-regular-and-not-name":
        return readable_regular and not name_matches
    if parameters.expression == "readable-regular-and-name-or-symlink":
        return (readable_regular and name_matches) or is_symlink
    if parameters.expression == "readable-regular-and-name-or-executable":
        return readable_regular and (name_matches or executable)
    if parameters.expression == "readable-regular-and-name-depth-at-most-three":
        return readable_regular and name_matches and len(relative.parts) <= 3
    raise CompoundPathQueryError("unsupported compound expression")


def _revalidate_definition(definition: object) -> FixtureDefinition:
    if type(definition) is not FixtureDefinition:
        raise CompoundPathQueryError("definition must be an exact FixtureDefinition")
    if (
        type(definition.fixture_id) is not str
        or type(definition.schema_version) is not str
        or type(definition.inputs) is not tuple
        or type(definition.expected_files) is not tuple
    ):
        raise CompoundPathQueryError(
            "definition scalar and container fields must have exact types"
        )
    for item in definition.inputs:
        if type(item) is InputFile:
            if (
                type(item.path) is not str
                or type(item.content) is not bytes
                or type(item.mode) is not int
            ):
                raise CompoundPathQueryError(
                    "input-file fields must have exact immutable types"
                )
        elif type(item) is InputSymlink:
            if type(item.path) is not str or type(item.target) is not str:
                raise CompoundPathQueryError(
                    "input-symlink fields must have exact text types"
                )
        else:
            raise CompoundPathQueryError("definition contains an unsupported input type")
    for policy in definition.expected_files:
        if (
            type(policy) is not ExpectedFile
            or type(policy.path) is not str
            or type(policy.maximum_bytes) is not int
            or (policy.mode is not None and type(policy.mode) is not int)
        ):
            raise CompoundPathQueryError(
                "expected-file fields must have exact scalar types"
            )
    try:
        reconstructed = FixtureDefinition(
            fixture_id=definition.fixture_id,
            inputs=definition.inputs,
            expected_files=definition.expected_files,
            schema_version=definition.schema_version,
        )
    except (TypeError, ValueError) as exc:
        raise CompoundPathQueryError("fixture definition failed revalidation") from exc
    if reconstructed != definition:
        raise CompoundPathQueryError("fixture definition changed on reconstruction")
    return definition


def derive_compound_path_query_output(
    definition: FixtureDefinition,
    parameters: CompoundPathQueryParameters,
) -> bytes:
    """Primary trusted derivation over immutable fixture records."""

    selected_definition = _revalidate_definition(definition)
    if type(parameters) is not CompoundPathQueryParameters:
        raise CompoundPathQueryError("parameters have the wrong exact type")
    parameters.__post_init__()
    selected: list[str] = []
    for item in selected_definition.inputs:
        if type(item) not in {InputFile, InputSymlink}:
            raise CompoundPathQueryError("fixture contains a noncanonical input type")
        relative = _relative_query_path(item.path)
        if relative is None:
            continue
        if _entry_matches(item, relative, parameters):
            selected.append(relative.as_posix())
    selected.sort(key=lambda value: value.encode("utf-8"))
    return b"".join(value.encode("utf-8") + b"\n" for value in selected)


def reference_compound_path_query_output(
    definition: FixtureDefinition,
    parameters: CompoundPathQueryParameters,
) -> bytes:
    """Independently derive the answer with byte regexes and set algebra.

    This production reference deliberately does not call the primary path
    projection, wildcard matcher, entry predicate, or line encoder.  It first
    classifies every in-scope record into disjoint index sets, then evaluates
    the closed expression as set operations.  The only shared step is strict
    reconstruction of the immutable fixture and parameter values at the trust
    boundary.
    """

    selected_definition = _revalidate_definition(definition)
    if type(parameters) is not CompoundPathQueryParameters:
        raise CompoundPathQueryError("parameters have the wrong exact type")
    parameters.__post_init__()
    pattern_bytes = _REFERENCE_PATTERN_BYTES.get(parameters.name_pattern)
    if type(pattern_bytes) is not bytes:
        raise CompoundPathQueryError("reference pattern is outside the closed grid")
    try:
        name_expression = re.compile(pattern_bytes, flags=re.ASCII)
    except re.error as exc:
        raise CompoundPathQueryError("reference pattern failed to compile") from exc

    # (relative bytes, is regular, is symlink, mode, depth, name matches)
    records: list[tuple[bytes, bool, bool, int, int, bool]] = []
    for item in selected_definition.inputs:
        path_parts = item.path.split("/")
        if len(path_parts) < 3 or path_parts[:2] != ["input", "query"]:
            continue
        relative_parts = path_parts[2:]
        relative_bytes = "/".join(relative_parts).encode("utf-8", "strict")
        basename_bytes = relative_parts[-1].encode("utf-8", "strict")
        regular = type(item) is InputFile
        symlink = type(item) is InputSymlink
        mode = item.mode if regular else 0
        records.append(
            (
                relative_bytes,
                regular,
                symlink,
                mode,
                len(relative_parts),
                name_expression.fullmatch(basename_bytes) is not None,
            )
        )

    readable = {
        index
        for index, record in enumerate(records)
        if record[1] and record[3] & 0o444
    }
    symlinks = {
        index for index, record in enumerate(records) if record[2]
    }
    executable = {
        index
        for index, record in enumerate(records)
        if record[1] and record[3] & 0o111
    }
    named = {
        index for index, record in enumerate(records) if record[5]
    }
    shallow = {
        index for index, record in enumerate(records) if record[4] <= 3
    }
    universe = set(range(len(records)))

    if parameters.expression == "readable-regular-and-name":
        accepted = readable & named
    elif parameters.expression == "readable-regular-and-not-name":
        accepted = readable & (universe - named)
    elif parameters.expression == "readable-regular-and-name-or-symlink":
        accepted = (readable & named) | symlinks
    elif parameters.expression == "readable-regular-and-name-or-executable":
        accepted = readable & (named | executable)
    elif parameters.expression == "readable-regular-and-name-depth-at-most-three":
        accepted = readable & named & shallow
    else:
        raise CompoundPathQueryError("unsupported reference compound expression")

    output = bytearray()
    for relative_bytes in sorted(records[index][0] for index in accepted):
        output.extend(relative_bytes)
        output.append(0x0A)
    return bytes(output)


def verify_compound_path_query_output(
    definition: FixtureDefinition,
    parameters: CompoundPathQueryParameters,
    candidate_output: bytes,
) -> bool:
    """Verify bytes only, requiring both production derivations to agree."""

    if type(candidate_output) is not bytes:
        return False
    try:
        primary = derive_compound_path_query_output(definition, parameters)
        reference = reference_compound_path_query_output(definition, parameters)
    except (CompoundPathQueryError, TypeError, ValueError):
        return False
    return primary == reference == candidate_output


def _compute_oracle_sha256(outputs: tuple[OracleOutputRecord, ...]) -> str:
    if (
        type(outputs) is not tuple
        or len(outputs) != 1
        or type(outputs[0]) is not OracleOutputRecord
    ):
        raise CompoundPathQueryError("oracle must contain one exact output record")
    output = outputs[0]
    output.__post_init__()
    if (
        output.path != COMPOUND_PATH_QUERY_OUTPUT
        or output.mode != COMPOUND_PATH_QUERY_OUTPUT_MODE
    ):
        raise CompoundPathQueryError("oracle output path or mode is invalid")
    return domain_sha256(
        "cbds.executable-fixture.trusted-oracle.v1",
        {
            "schema_version": EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION,
            "semantic_verifier_identity": COMPOUND_PATH_QUERY_VERIFIER_IDENTITY,
            "outputs": [output.commitment_record()],
        },
    )


@dataclass(frozen=True, slots=True)
class CompoundPathQueryOracle:
    outputs: tuple[OracleOutputRecord, ...]
    oracle_sha256: str
    semantic_verifier_identity: str = COMPOUND_PATH_QUERY_VERIFIER_IDENTITY
    schema_version: str = EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            type(self.semantic_verifier_identity) is not str
            or self.semantic_verifier_identity != COMPOUND_PATH_QUERY_VERIFIER_IDENTITY
            or type(self.schema_version) is not str
            or self.schema_version != EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION
            or not _is_sha256(self.oracle_sha256)
            or self.oracle_sha256 != _compute_oracle_sha256(self.outputs)
        ):
            raise CompoundPathQueryError("trusted oracle identity is invalid")

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
class CompoundPathQueryFixtureBundle:
    task_contract_sha256: str
    profile_sha256: str
    definition: FixtureDefinition = field(repr=False)
    fixture_definition_sha256: str
    oracle: CompoundPathQueryOracle = field(repr=False)
    descriptor: OpaqueFixtureDescriptor
    schema_version: str = EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_compound_path_query_fixture_bundle(self)

    def to_opaque_descriptor(self) -> OpaqueFixtureDescriptor:
        validate_compound_path_query_fixture_bundle(self)
        return self.descriptor

    def commitment_record(self) -> dict[str, object]:
        validate_compound_path_query_fixture_bundle(self)
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


def validate_compound_path_query_fixture_bundle(
    bundle: CompoundPathQueryFixtureBundle,
) -> None:
    """Validate internal structure and hashes, not semantic oracle authority.

    A self-consistent bundle can be constructed around a different definition
    and oracle.  Use
    :func:`validate_compound_path_query_fixture_for_task_profile` whenever a
    trusted task/profile pair is available.
    """

    if type(bundle) is not CompoundPathQueryFixtureBundle:
        raise CompoundPathQueryError("bundle has the wrong exact type")
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
        raise CompoundPathQueryError("bundle metadata or authority boundary is invalid")
    definition = _revalidate_definition(bundle.definition)
    definition_sha256 = compute_fixture_definition_semantic_sha256(definition)
    if bundle.fixture_definition_sha256 != definition_sha256:
        raise CompoundPathQueryError("fixture definition digest is invalid")
    if type(bundle.oracle) is not CompoundPathQueryOracle:
        raise CompoundPathQueryError("oracle has the wrong exact type")
    bundle.oracle.__post_init__()
    output = bundle.oracle.outputs[0]
    if bundle.definition.expected_files != (
        ExpectedFile(
            COMPOUND_PATH_QUERY_OUTPUT,
            maximum_bytes=len(output.content),
            mode=COMPOUND_PATH_QUERY_OUTPUT_MODE,
        ),
    ):
        raise CompoundPathQueryError("output policy does not exactly bind the oracle")
    if type(bundle.descriptor) is not OpaqueFixtureDescriptor:
        raise CompoundPathQueryError("descriptor has the wrong exact type")
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
        raise CompoundPathQueryError("descriptor does not bind the fixture content")


def verify_compound_path_query_fixture_bundle(bundle: object) -> bool:
    """Check structural self-consistency only; this is not authentication."""

    try:
        validate_compound_path_query_fixture_bundle(bundle)  # type: ignore[arg-type]
    except (CompoundPathQueryError, TypeError, ValueError):
        return False
    return True


def _validate_task_profile(
    task: object,
    profile: object,
) -> tuple[CompoundPathQueryTask, ExecutableFixtureProfile]:
    if type(task) is not CompoundPathQueryTask:
        raise CompoundPathQueryError("task must be an exact compound-path task")
    if type(profile) is not ExecutableFixtureProfile:
        raise CompoundPathQueryError("profile must be an exact fixture profile")
    if (
        type(profile.profile_id) is not str
        or type(profile.cases) is not tuple
        or any(type(case) is not str for case in profile.cases)
        or type(profile.profile_sha256) is not str
        or type(profile.profile_version) is not str
    ):
        raise CompoundPathQueryError(
            "profile nested fields must have exact scalar and container types"
        )
    try:
        task.__post_init__()
        CompoundPathQueryParameters(
            name_pattern=task.parameters.name_pattern,
            expression=task.parameters.expression,
        )
        reconstructed_profile = ExecutableFixtureProfile(
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
        raise CompoundPathQueryError("task or profile failed revalidation") from exc
    if reconstructed_profile not in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
        raise CompoundPathQueryError("profile is not public method-development data")
    return task, profile


def build_compound_path_query_fixture_bundle(
    task: CompoundPathQueryTask,
    profile: ExecutableFixtureProfile,
) -> CompoundPathQueryFixtureBundle:
    """Build one deterministic, nonexecuting compound-path fixture binding."""

    selected_task, selected_profile = _validate_task_profile(task, profile)
    inputs = _fixture_inputs(selected_profile)
    provisional_definition = FixtureDefinition(
        fixture_id=f"fixture.{selected_task.task_id}.{selected_profile.profile_id}",
        inputs=inputs,
        expected_files=(
            ExpectedFile(
                COMPOUND_PATH_QUERY_OUTPUT,
                maximum_bytes=0,
                mode=COMPOUND_PATH_QUERY_OUTPUT_MODE,
            ),
        ),
    )
    primary = derive_compound_path_query_output(
        provisional_definition,
        selected_task.parameters,
    )
    reference = reference_compound_path_query_output(
        provisional_definition,
        selected_task.parameters,
    )
    if primary != reference:
        raise CompoundPathQueryError(
            "primary and reference implementations disagree"
        )
    expected = primary
    definition = FixtureDefinition(
        fixture_id=provisional_definition.fixture_id,
        inputs=inputs,
        expected_files=(
            ExpectedFile(
                COMPOUND_PATH_QUERY_OUTPUT,
                maximum_bytes=len(expected),
                mode=COMPOUND_PATH_QUERY_OUTPUT_MODE,
            ),
        ),
    )
    outputs = (
        OracleOutputRecord(
            COMPOUND_PATH_QUERY_OUTPUT,
            expected,
            COMPOUND_PATH_QUERY_OUTPUT_MODE,
        ),
    )
    oracle = CompoundPathQueryOracle(
        outputs=outputs,
        oracle_sha256=_compute_oracle_sha256(outputs),
    )
    definition_sha256 = compute_fixture_definition_semantic_sha256(definition)
    fixture_sha256 = compute_bound_fixture_sha256(
        task_contract_sha256=selected_task.task_contract_sha256,
        profile_sha256=selected_profile.profile_sha256,
        fixture_definition_sha256=definition_sha256,
        oracle_sha256=oracle.oracle_sha256,
    )
    return CompoundPathQueryFixtureBundle(
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


def validate_compound_path_query_fixture_for_task_profile(
    task: CompoundPathQueryTask,
    profile: ExecutableFixtureProfile,
    bundle: CompoundPathQueryFixtureBundle,
) -> None:
    """Authenticate one bundle against an exact trusted task/profile pair.

    Structural hash checks alone cannot establish that an oracle implements
    the intended task.  This boundary revalidates the task and profile,
    deterministically rebuilds the complete fixture and trusted Python oracle,
    compares every field, and checks the task's public descriptor at the
    profile's canonical position.
    """

    selected_task, selected_profile = _validate_task_profile(task, profile)
    validate_compound_path_query_fixture_bundle(bundle)
    expected = build_compound_path_query_fixture_bundle(
        selected_task,
        selected_profile,
    )
    if bundle != expected:
        raise CompoundPathQueryError(
            "bundle differs from deterministic task/profile reconstruction"
        )
    profile_index = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES.index(selected_profile)
    if selected_task.fixtures[profile_index] != expected.descriptor:
        raise CompoundPathQueryError(
            "task public descriptor differs from authenticated fixture"
        )


def verify_compound_path_query_fixture_for_task_profile(
    task: object,
    profile: object,
    bundle: object,
) -> bool:
    """Return whether deterministic task/profile authentication succeeds."""

    try:
        validate_compound_path_query_fixture_for_task_profile(
            task,  # type: ignore[arg-type]
            profile,  # type: ignore[arg-type]
            bundle,  # type: ignore[arg-type]
        )
    except (CompoundPathQueryError, TypeError, ValueError):
        return False
    return True


def materialize_compound_path_query_fixture(
    task: CompoundPathQueryTask,
    profile: ExecutableFixtureProfile,
    bundle: CompoundPathQueryFixtureBundle,
    workspace: str | os.PathLike[str],
) -> WorkspaceHandle:
    """Authenticate the family binding before safe materialization."""

    validate_compound_path_query_fixture_for_task_profile(task, profile, bundle)
    return materialize_fixture(bundle.definition, workspace)


def verify_compound_path_query_workspace(
    task: CompoundPathQueryTask,
    profile: ExecutableFixtureProfile,
    bundle: CompoundPathQueryFixtureBundle,
    handle: WorkspaceHandle,
) -> bool:
    """Verify one complete pinned workspace without executing a candidate.

    The task/profile reconstruction authenticates the fixture, oracle, and
    public descriptor.  The exact pinned handle must retain the corresponding
    baseline and output policy.  Descriptor-relative stable scans require the
    complete input tree to remain unchanged and reject every missing, extra,
    linked, oversized, or incorrectly moded output path.  Candidate bytes are
    released only through the handle's bounded no-follow egress and must agree
    with both independently structured production derivations and the bound
    oracle.  Final scans close changes observed during verification.

    A trusted harness must first stop and reap every candidate descendant and
    keep the workspace quiescent through this return.  Repeated scans cannot
    prove global quiescence or exclude a mutation after their last observation.
    """

    if type(handle) is not WorkspaceHandle:
        return False
    try:
        validate_compound_path_query_fixture_for_task_profile(
            task, profile, bundle
        )
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
            or output_entries[0].path != COMPOUND_PATH_QUERY_OUTPUT
            or output_entries[0].mode != COMPOUND_PATH_QUERY_OUTPUT_MODE
        ):
            return False
        payload = handle.read_output_bytes(
            output_scan, COMPOUND_PATH_QUERY_OUTPUT
        )
        primary = derive_compound_path_query_output(
            bundle.definition, task.parameters
        )
        reference = reference_compound_path_query_output(
            bundle.definition, task.parameters
        )
        if (
            primary != reference
            or payload != primary
            or payload != bundle.oracle.outputs[0].content
            or bundle.oracle.outputs[0].mode != COMPOUND_PATH_QUERY_OUTPUT_MODE
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
        CompoundPathQueryError,
        ExecutableWorkspaceError,
        OSError,
        TypeError,
        ValueError,
    ):
        return False


__all__ = [
    "COMPOUND_PATH_EXPRESSIONS",
    "COMPOUND_PATH_NAME_PATTERNS",
    "COMPOUND_PATH_QUERY_ALLOWED_TOOLS",
    "COMPOUND_PATH_DIRECTORY_PERMISSION_ERRORS_COVERED",
    "COMPOUND_PATH_QUERY_FAMILY_ID",
    "COMPOUND_PATH_QUERY_GENERATOR_VERSION",
    "COMPOUND_PATH_QUERY_OUTPUT",
    "COMPOUND_PATH_QUERY_VERIFIER_IDENTITY",
    "COMPOUND_PATH_QUERY_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE",
    "COMPOUND_PATH_QUERY_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE",
    "CompoundPathQueryError",
    "CompoundPathQueryFixtureBundle",
    "CompoundPathQueryOracle",
    "CompoundPathQueryParameters",
    "CompoundPathQueryTask",
    "build_compound_path_query_fixture_bundle",
    "build_compound_path_query_tasks",
    "compute_compound_path_query_task_sha256",
    "derive_compound_path_query_output",
    "materialize_compound_path_query_fixture",
    "reference_compound_path_query_output",
    "validate_compound_path_query_fixture_bundle",
    "validate_compound_path_query_fixture_for_task_profile",
    "verify_compound_path_query_fixture_bundle",
    "verify_compound_path_query_fixture_for_task_profile",
    "verify_compound_path_query_output",
    "verify_compound_path_query_workspace",
]
