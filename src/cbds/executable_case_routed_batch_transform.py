"""Public method-development family for case-routed batch transforms.

The family exercises manifest-driven loops, mutually exclusive routing
signals, byte-exact transforms, and batch-level fallback policies.  It is an
additive family-local contract: no frozen shared task or fixture union is
widened here.  Fixture construction and final-state verification require two
separately structured semantic implementations to agree.

This module never executes candidate code.  Materialization delegates to the
descriptor-relative shared workspace implementation.  Nothing here authorizes
candidate execution, model selection, sealed scoring, or a research claim.
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


CASE_ROUTED_BATCH_TRANSFORM_FAMILY_ID: Final[str] = (
    "case-routed-batch-transform"
)
CASE_ROUTED_BATCH_TRANSFORM_FILESYSTEM_IDENTITY: Final[str] = (
    "routed-text-batch"
)
CASE_ROUTED_BATCH_TRANSFORM_OUTPUT_IDENTITY: Final[str] = (
    "route-partitioned-transform-tree"
)
CASE_ROUTED_BATCH_TRANSFORM_GENERATOR_VERSION: Final[str] = "1.0.0"
CASE_ROUTED_BATCH_TRANSFORM_VERIFIER_IDENTITY: Final[str] = (
    "verify-case-routed-batch-transform-v1"
)
CASE_ROUTED_BATCH_TRANSFORM_MANIFEST: Final[str] = (
    "input/batch/manifest.tsv"
)
CASE_ROUTED_BATCH_TRANSFORM_PAYLOAD_ROOT: Final[PurePosixPath] = (
    PurePosixPath("input/batch/payloads")
)
CASE_ROUTED_BATCH_TRANSFORM_STATUS_OUTPUT: Final[str] = "output/status.tsv"
CASE_ROUTED_BATCH_TRANSFORM_ERRORS_OUTPUT: Final[str] = "output/errors.tsv"
CASE_ROUTED_BATCH_TRANSFORM_OUTPUT_MODE: Final[int] = 0o644
CASE_ROUTED_BATCH_TRANSFORM_OUTPUT_MAXIMUM_BYTES: Final[int] = 64 * 1024
CASE_ROUTED_BATCH_TRANSFORM_MANIFEST_MAXIMUM_BYTES: Final[int] = 64 * 1024
CASE_ROUTED_BATCH_TRANSFORM_PAYLOAD_MAXIMUM_BYTES: Final[int] = 16 * 1024
CASE_ROUTED_BATCH_TRANSFORM_MAXIMUM_PHYSICAL_ROWS: Final[int] = 256
CASE_ROUTED_BATCH_TRANSFORM_MAXIMUM_LOGICAL_RECORDS: Final[int] = 128
CASE_ROUTED_BATCH_TRANSFORM_ALLOWED_TOOLS: Final[tuple[str, ...]] = (
    "awk",
    "mkdir",
    "sed",
    "sort",
    "tr",
)

# Honest coverage and final-state observation boundaries.
CASE_ROUTED_BATCH_TRANSFORM_SYMLINK_DISTRACTORS_COVERED: Final[bool] = True
CASE_ROUTED_BATCH_TRANSFORM_MODE_UNREADABLE_UNLISTED_LEAVES_COVERED: Final[
    bool
] = True
CASE_ROUTED_BATCH_TRANSFORM_DIRECTORY_PERMISSION_ERRORS_COVERED: Final[
    bool
] = False
CASE_ROUTED_BATCH_TRANSFORM_EFFECTIVE_ACCESS_FAILURES_COVERED: Final[
    bool
] = False
CASE_ROUTED_BATCH_TRANSFORM_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE: Final[
    bool
] = True
CASE_ROUTED_BATCH_TRANSFORM_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE: Final[
    bool
] = False
CASE_ROUTED_BATCH_TRANSFORM_ROUTE_HISTORY_OBSERVED: Final[bool] = False
CASE_ROUTED_BATCH_TRANSFORM_TRANSFORM_HISTORY_OBSERVED: Final[bool] = False
CASE_ROUTED_BATCH_TRANSFORM_READ_SCOPE_OBSERVED: Final[bool] = False
CASE_ROUTED_BATCH_TRANSFORM_TOOL_HISTORY_OBSERVED: Final[bool] = False
CASE_ROUTED_BATCH_TRANSFORM_ATOMIC_PUBLICATION_HISTORY_OBSERVED: Final[
    bool
] = False
CASE_ROUTED_BATCH_TRANSFORM_CANDIDATE_EXIT_STATUS_OBSERVED: Final[bool] = False

RouteKey: TypeAlias = Literal[
    "suffix",
    "record-kind",
    "leading-byte",
    "declared-action",
]
FallbackPolicy: TypeAlias = Literal[
    "skip",
    "copy-verbatim",
    "reject-batch",
    "route-default",
    "emit-error-record",
]
RouteName: TypeAlias = Literal[
    "upper",
    "lower",
    "detab",
    "strip-cr",
    "verbatim",
    "default",
]

CASE_ROUTED_BATCH_TRANSFORM_ROUTE_KEYS: Final[tuple[RouteKey, ...]] = (
    "suffix",
    "record-kind",
    "leading-byte",
    "declared-action",
)
CASE_ROUTED_BATCH_TRANSFORM_FALLBACK_POLICIES: Final[
    tuple[FallbackPolicy, ...]
] = (
    "skip",
    "copy-verbatim",
    "reject-batch",
    "route-default",
    "emit-error-record",
)

_RECOGNIZED_ROUTES: Final[tuple[str, ...]] = (
    "upper",
    "lower",
    "detab",
    "strip-cr",
)
_SUFFIX_ROUTES: Final[tuple[tuple[str, str], ...]] = (
    (".upper", "upper"),
    (".lower", "lower"),
    (".tabs", "detab"),
    (".crlf", "strip-cr"),
)
_KIND_ROUTES: Final[tuple[tuple[str, str], ...]] = (
    ("uppercase-text", "upper"),
    ("lowercase-text", "lower"),
    ("tabbed-text", "detab"),
    ("crlf-text", "strip-cr"),
)
_LEADING_ROUTES: Final[tuple[tuple[int, str], ...]] = (
    (ord("U"), "upper"),
    (ord("L"), "lower"),
    (ord("T"), "detab"),
    (ord("C"), "strip-cr"),
)
_ACTION_ROUTES: Final[tuple[tuple[str, str], ...]] = (
    ("uppercase", "upper"),
    ("lowercase", "lower"),
    ("expand-tabs", "detab"),
    ("delete-cr", "strip-cr"),
)
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_TASK_ID_RE: Final[re.Pattern[str]] = re.compile(r"mds-[0-9a-f]{24}\Z")
_TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")
_ASCII_UPPER = bytes.maketrans(
    b"abcdefghijklmnopqrstuvwxyz", b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
)
_ASCII_LOWER = bytes.maketrans(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ", b"abcdefghijklmnopqrstuvwxyz"
)
_ASCII_ROT13 = bytes.maketrans(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    b"NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)


class CaseRoutedBatchTransformError(ValueError):
    """Raised when a task, fixture, or routed output fails closed."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def _closed_text(value: object, allowed: tuple[str, ...], label: str) -> str:
    if type(value) is not str or value not in allowed:
        raise CaseRoutedBatchTransformError(
            f"{label} is outside the closed family contract"
        )
    return value


@dataclass(frozen=True, slots=True)
class CaseRoutedBatchTransformParameters:
    """One cell in the four-route-key by five-fallback-policy grid."""

    route_key: RouteKey
    fallback_policy: FallbackPolicy

    def __post_init__(self) -> None:
        if type(self) is not CaseRoutedBatchTransformParameters:
            raise CaseRoutedBatchTransformError(
                "parameters have the wrong exact type"
            )
        _closed_text(
            self.route_key,
            CASE_ROUTED_BATCH_TRANSFORM_ROUTE_KEYS,
            "route_key",
        )
        _closed_text(
            self.fallback_policy,
            CASE_ROUTED_BATCH_TRANSFORM_FALLBACK_POLICIES,
            "fallback_policy",
        )

    def to_record(self) -> dict[str, str]:
        self.__post_init__()
        return {
            "parameter_type": CASE_ROUTED_BATCH_TRANSFORM_FAMILY_ID,
            "route_key": self.route_key,
            "fallback_policy": self.fallback_policy,
        }


_ROUTE_KEY_TEXT: Final[dict[RouteKey, str]] = {
    "suffix": (
        "Use only the SOURCE basename suffix: .upper maps to upper, .lower "
        "to lower, .tabs to detab, and .crlf to strip-cr. Matching is "
        "case-sensitive and requires the exact final suffix."
    ),
    "record-kind": (
        "Use only KIND: uppercase-text maps to upper, lowercase-text to "
        "lower, tabbed-text to detab, and crlf-text to strip-cr."
    ),
    "leading-byte": (
        "Use only the first raw payload byte: U maps to upper, L to lower, "
        "T to detab, and C to strip-cr. An empty payload is unmatched."
    ),
    "declared-action": (
        "Use only ACTION: uppercase maps to upper, lowercase to lower, "
        "expand-tabs to detab, and delete-cr to strip-cr."
    ),
}

_FALLBACK_TEXT: Final[dict[FallbackPolicy, str]] = {
    "skip": (
        "For each unmatched record, emit no payload and no error row; retain "
        "every matched payload."
    ),
    "copy-verbatim": (
        "For each unmatched record, copy its exact bytes to route verbatim; "
        "emit no error row."
    ),
    "reject-batch": (
        "If any logical record is unmatched, publish no payload at all, set "
        "state rejected, and emit one rejected error row per unmatched ID. "
        "If all records match, publish the matched payloads normally."
    ),
    "route-default": (
        "For each unmatched record, route it to default and apply ASCII "
        "ROT13; emit no error row."
    ),
    "emit-error-record": (
        "For each unmatched record, emit no payload and append one unmatched "
        "error row; retain every matched payload."
    ),
}


def _task_contract(
    parameters: CaseRoutedBatchTransformParameters,
) -> tuple[str, NormalizedSemanticGraph]:
    prompt = f"""Write one Bash program that operates only in the current workspace.

Read `input/batch/manifest.tsv` and only the regular payload files it lists.
Ignore every other input path.  The manifest is empty or strict UTF-8,
LF-terminated, headerless TSV with exactly ID, SOURCE, KIND, ACTION.  It is at
most 65536 bytes, 256 physical rows, and 128 logical records.  ID is nonempty,
at most 64 UTF-8 bytes, not `.` or `..`, and contains no slash, ASCII control,
or DEL.  SOURCE is a canonical UTF-8 path strictly below
`input/batch/payloads/`, without empty, `.` or `..` components.  SOURCE is at
most 4096 UTF-8 bytes, each component is at most 255 bytes, and it contains no
ASCII control or DEL.  KIND and ACTION match `[a-z][a-z0-9-]{{0,31}}`.  Exact duplicate complete rows denote one
logical record.  IDs never conflict.  Physical row order is nonsemantic.
Every listed source is a link-count-one, owner-readable regular file of at
most 16384 bytes.  A path may be listed under multiple IDs.  Payloads are
arbitrary raw bytes and may begin with NUL or invalid UTF-8.  Scored fixtures
satisfy this input domain.

This task routes by `{parameters.route_key}`.  {_ROUTE_KEY_TEXT[parameters.route_key]}
Do not consult the other routing signals.  The upper transform changes only
ASCII a-z to A-Z; lower changes only ASCII A-Z to a-z; detab replaces every
TAB byte with four spaces; strip-cr deletes every CR byte.  Preserve every
other byte.  The leading selector byte remains part of the transformed data.
Use `LC_ALL=C` with the pinned GNU awk, sed, and tr behavior.  For
leading-byte routing, test the streamed first byte through awk predicate/exit
status; do not store it with Bash `read` or command substitution, because NUL
must remain observable and Bash variables cannot preserve NUL.

This task uses fallback `{parameters.fallback_policy}`.  {_FALLBACK_TEXT[parameters.fallback_policy]}
Verbatim preserves every byte.  Default changes ASCII letters by ROT13 and
preserves every other byte.

Write exact mode-0644, link-count-one regular files.  Every payload path is
`output/routes/ROUTE/ID.out`.  Write `output/status.tsv` as one LF-terminated
row: `batch`, STATE (`complete` or `rejected`), logical count, matched count,
unmatched count, payload count, error count.  Write `output/errors.tsv` as a
zero-byte file or raw-ID-byte-sorted rows: `unmatched`, ID, route key for
emit-error-record; `rejected`, ID, route key for a rejected batch.  Fields are
tab separated and rows LF terminated.  Create only ancestors needed by these
files, all as real mode-0755 directories; do not leave empty route directories
or any extra non-input path.

Preserve every input path, kind, mode, byte, modification time, hard-link
count, and symlink target.  Use only Bash built-ins plus `awk`, `mkdir`, `sed`,
`sort`, and `tr`.
"""
    graph = NormalizedSemanticGraph(
        nodes=(
            OperatorNode(
                "parse_routed_batch_manifest",
                (
                    "path:input/batch/manifest.tsv",
                    "exact-duplicates:collapse",
                    "physical-row-order:nonsemantic",
                ),
            ),
            OperatorNode(
                "select_case_route",
                (f"route-key:{parameters.route_key}",),
            ),
            OperatorNode(
                "apply_route_transform_or_fallback",
                (
                    f"fallback-policy:{parameters.fallback_policy}",
                    "default-transform:ascii-rot13",
                ),
            ),
            OperatorNode(
                "publish_partitioned_tree_and_reports",
                (
                    "root:output/routes",
                    "status:output/status.tsv",
                    "errors:output/errors.tsv",
                    "file-mode:0644",
                ),
            ),
        ),
        dependencies=((0, 1), (1, 2), (2, 3)),
    )
    return prompt, graph


def _validate_graph(graph: object) -> NormalizedSemanticGraph:
    if type(graph) is not NormalizedSemanticGraph:
        raise CaseRoutedBatchTransformError("graph has the wrong exact type")
    if type(graph.nodes) is not tuple or not graph.nodes:
        raise CaseRoutedBatchTransformError("graph nodes are invalid")
    if type(graph.dependencies) is not tuple:
        raise CaseRoutedBatchTransformError("graph dependencies are invalid")
    for node in graph.nodes:
        if (
            type(node) is not OperatorNode
            or type(node.name) is not str
            or not node.name
            or "\0" in node.name
            or type(node.parameters) is not tuple
            or any(type(value) is not str for value in node.parameters)
        ):
            raise CaseRoutedBatchTransformError("graph node is noncanonical")
    for edge in graph.dependencies:
        if (
            type(edge) is not tuple
            or len(edge) != 2
            or any(type(index) is not int for index in edge)
        ):
            raise CaseRoutedBatchTransformError("graph edge is noncanonical")
        source, target = edge
        if source < 0 or source >= target or target >= len(graph.nodes):
            raise CaseRoutedBatchTransformError("graph edge order is invalid")
    rebuilt = NormalizedSemanticGraph(
        nodes=tuple(
            OperatorNode(node.name, node.parameters) for node in graph.nodes
        ),
        dependencies=graph.dependencies,
    )
    if rebuilt != graph:
        raise CaseRoutedBatchTransformError("graph reconstruction changed")
    return graph


def case_routed_batch_transform_task_semantic_core(
    parameters: CaseRoutedBatchTransformParameters,
    prompt: str,
    graph: NormalizedSemanticGraph,
) -> dict[str, object]:
    if type(parameters) is not CaseRoutedBatchTransformParameters:
        raise CaseRoutedBatchTransformError("parameters have the wrong type")
    parameters.__post_init__()
    if type(prompt) is not str or not prompt.strip() or "\0" in prompt:
        raise CaseRoutedBatchTransformError("prompt is invalid")
    _validate_graph(graph)
    expected_prompt, expected_graph = _task_contract(parameters)
    if prompt != expected_prompt or graph != expected_graph:
        raise CaseRoutedBatchTransformError("prompt or graph differs")
    return {
        "schema_version": EXECUTABLE_STATIC_SCHEMA_VERSION,
        "contract_version": EXECUTABLE_STATIC_CONTRACT_VERSION,
        "split_role": METHOD_DEVELOPMENT_SPLIT,
        "family_id": CASE_ROUTED_BATCH_TRANSFORM_FAMILY_ID,
        "family_version": EXECUTABLE_STATIC_FAMILY_VERSION,
        "parameters": parameters.to_record(),
        "prompt": prompt,
        "graph": graph.to_record(),
        "graph_sha256": graph.hash,
        "filesystem_identity": (
            CASE_ROUTED_BATCH_TRANSFORM_FILESYSTEM_IDENTITY
        ),
        "output_identity": CASE_ROUTED_BATCH_TRANSFORM_OUTPUT_IDENTITY,
        "allowed_tools": list(CASE_ROUTED_BATCH_TRANSFORM_ALLOWED_TOOLS),
        "public": True,
        "sealed": False,
        "candidate_execution_authorized": False,
        "model_selection_eligible": False,
        "claim_authorized": False,
    }


def compute_case_routed_batch_transform_task_sha256(
    parameters: CaseRoutedBatchTransformParameters,
    prompt: str,
    graph: NormalizedSemanticGraph,
) -> str:
    return domain_sha256(
        "cbds.executable-static.task-contract.v1",
        case_routed_batch_transform_task_semantic_core(
            parameters, prompt, graph
        ),
    )


@dataclass(frozen=True, slots=True)
class CaseRoutedBatchTransformTask:
    task_id: str
    parameters: CaseRoutedBatchTransformParameters
    prompt: str
    graph: NormalizedSemanticGraph
    fixtures: tuple[OpaqueFixtureDescriptor, ...]
    task_contract_sha256: str
    family_id: str = CASE_ROUTED_BATCH_TRANSFORM_FAMILY_ID
    family_version: str = EXECUTABLE_STATIC_FAMILY_VERSION
    filesystem_identity: str = CASE_ROUTED_BATCH_TRANSFORM_FILESYSTEM_IDENTITY
    output_identity: str = CASE_ROUTED_BATCH_TRANSFORM_OUTPUT_IDENTITY
    allowed_tools: tuple[str, ...] = CASE_ROUTED_BATCH_TRANSFORM_ALLOWED_TOOLS
    split_role: str = METHOD_DEVELOPMENT_SPLIT
    public: bool = True
    sealed: bool = False
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        if (
            type(self) is not CaseRoutedBatchTransformTask
            or type(self.parameters) is not CaseRoutedBatchTransformParameters
            or type(self.family_id) is not str
            or self.family_id != CASE_ROUTED_BATCH_TRANSFORM_FAMILY_ID
            or type(self.family_version) is not str
            or self.family_version != EXECUTABLE_STATIC_FAMILY_VERSION
            or type(self.filesystem_identity) is not str
            or self.filesystem_identity
            != CASE_ROUTED_BATCH_TRANSFORM_FILESYSTEM_IDENTITY
            or type(self.output_identity) is not str
            or self.output_identity != CASE_ROUTED_BATCH_TRANSFORM_OUTPUT_IDENTITY
            or type(self.allowed_tools) is not tuple
            or self.allowed_tools != CASE_ROUTED_BATCH_TRANSFORM_ALLOWED_TOOLS
            or any(type(tool) is not str for tool in self.allowed_tools)
            or type(self.split_role) is not str
            or self.split_role != METHOD_DEVELOPMENT_SPLIT
            or self.public is not True
            or self.sealed is not False
            or self.candidate_execution_authorized is not False
            or self.model_selection_eligible is not False
            or self.claim_authorized is not False
        ):
            raise CaseRoutedBatchTransformError("task metadata is invalid")
        expected = compute_case_routed_batch_transform_task_sha256(
            self.parameters, self.prompt, self.graph
        )
        if (
            type(self.task_id) is not str
            or _TASK_ID_RE.fullmatch(self.task_id) is None
            or not _is_sha256(self.task_contract_sha256)
            or self.task_contract_sha256 != expected
            or self.task_id != task_id_from_contract(expected)
        ):
            raise CaseRoutedBatchTransformError("task identity is invalid")
        if (
            type(self.fixtures) is not tuple
            or len(self.fixtures) != len(PUBLIC_DEVELOPMENT_FIXTURE_PROFILES)
            or any(
                type(item) is not OpaqueFixtureDescriptor
                for item in self.fixtures
            )
        ):
            raise CaseRoutedBatchTransformError("task descriptors are invalid")
        for descriptor in self.fixtures:
            descriptor.__post_init__()
        if (
            len({item.fixture_id for item in self.fixtures}) != 5
            or any(
                item.task_contract_sha256 != expected
                for item in self.fixtures
            )
        ):
            raise CaseRoutedBatchTransformError("descriptor binding is invalid")

    @property
    def graph_sha256(self) -> str:
        self.__post_init__()
        return self.graph.hash

    def to_public_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            **case_routed_batch_transform_task_semantic_core(
                self.parameters, self.prompt, self.graph
            ),
            "task_id": self.task_id,
            "task_contract_sha256": self.task_contract_sha256,
            "fixtures": [item.to_public_record() for item in self.fixtures],
        }


def _bootstrap_descriptors(
    task_contract_sha256: str,
) -> tuple[OpaqueFixtureDescriptor, ...]:
    return tuple(
        OpaqueFixtureDescriptor(
            fixture_id=f"fx-{digest[:24]}",
            fixture_sha256=digest,
            task_contract_sha256=task_contract_sha256,
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
    parameters: CaseRoutedBatchTransformParameters,
) -> CaseRoutedBatchTransformTask:
    prompt, graph = _task_contract(parameters)
    digest = compute_case_routed_batch_transform_task_sha256(
        parameters, prompt, graph
    )
    return CaseRoutedBatchTransformTask(
        task_id=task_id_from_contract(digest),
        parameters=parameters,
        prompt=prompt,
        graph=graph,
        fixtures=_bootstrap_descriptors(digest),
        task_contract_sha256=digest,
    )


@dataclass(frozen=True, slots=True)
class _ManifestRecord:
    record_id: str
    source: str
    kind: str
    action: str

    def row(self) -> bytes:
        return (
            f"{self.record_id}\t{self.source}\t{self.kind}\t{self.action}\n"
        ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class _SeedRecord:
    manifest: _ManifestRecord
    content: bytes
    mode: int = 0o400


def _mixed_payload(leading: bytes, marker: str) -> bytes:
    return (
        leading
        + b"|Ab-z\tfield\r\n"
        + marker.encode("utf-8")
        + b"|\x00\xff\xc3(\n"
    )


def _core_seed_records(
    identifiers: tuple[str, str, str, str],
    source_stems: tuple[str, str, str, str],
    *,
    modes: tuple[int, int, int, int] = (0o400, 0o440, 0o444, 0o600),
) -> tuple[_SeedRecord, ...]:
    suffixes = (".upper", ".lower", ".tabs", ".crlf")
    kinds = (
        "lowercase-text",
        "tabbed-text",
        "crlf-text",
        "uppercase-text",
    )
    leading = (b"T", b"C", b"U", b"L")
    actions = ("delete-cr", "uppercase", "lowercase", "expand-tabs")
    return tuple(
        _SeedRecord(
            _ManifestRecord(
                identifiers[index],
                (
                    CASE_ROUTED_BATCH_TRANSFORM_PAYLOAD_ROOT
                    / f"{source_stems[index]}{suffixes[index]}"
                ).as_posix(),
                kinds[index],
                actions[index],
            ),
            _mixed_payload(leading[index], f"core-{index}-café-雪"),
            modes[index],
        )
        for index in range(4)
    )


def _unmatched_seed(
    identifier: str,
    stem: str,
    *,
    content: bytes | None = None,
    mode: int = 0o400,
) -> _SeedRecord:
    return _SeedRecord(
        _ManifestRecord(
            identifier,
            (
                CASE_ROUTED_BATCH_TRANSFORM_PAYLOAD_ROOT / f"{stem}.bin"
            ).as_posix(),
            "opaque",
            "preserve",
        ),
        (
            _mixed_payload(b"\x00", "unmatched-Mixed-Az")
            if content is None
            else content
        ),
        mode,
    )


def _signal_isolation_seeds() -> tuple[_SeedRecord, ...]:
    root = CASE_ROUTED_BATCH_TRANSFORM_PAYLOAD_ROOT
    return (
        _SeedRecord(
            _ManifestRecord(
                "suffix-only",
                (root / "signal-suffix.upper").as_posix(),
                "opaque",
                "preserve",
            ),
            _mixed_payload(b"?", "suffix-only"),
        ),
        _SeedRecord(
            _ManifestRecord(
                "kind-only",
                (root / "signal-kind.bin").as_posix(),
                "uppercase-text",
                "preserve",
            ),
            _mixed_payload(b"?", "kind-only"),
        ),
        _SeedRecord(
            _ManifestRecord(
                "leading-only",
                (root / "signal-leading.bin").as_posix(),
                "opaque",
                "preserve",
            ),
            _mixed_payload(b"U", "leading-only"),
        ),
        _SeedRecord(
            _ManifestRecord(
                "action-only",
                (root / "signal-action.bin").as_posix(),
                "opaque",
                "uppercase",
            ),
            _mixed_payload(b"?", "action-only"),
        ),
    )


def _signal_exclusion_seeds() -> tuple[_SeedRecord, ...]:
    """Rows with exactly one unknown signal and three agreeing signals."""

    root = CASE_ROUTED_BATCH_TRANSFORM_PAYLOAD_ROOT
    return (
        _SeedRecord(
            _ManifestRecord(
                "suffix-missing",
                (root / "missing-suffix.bin").as_posix(),
                "uppercase-text",
                "uppercase",
            ),
            _mixed_payload(b"U", "suffix-missing"),
        ),
        _SeedRecord(
            _ManifestRecord(
                "kind-missing",
                (root / "missing-kind.upper").as_posix(),
                "opaque",
                "uppercase",
            ),
            _mixed_payload(b"U", "kind-missing"),
        ),
        _SeedRecord(
            _ManifestRecord(
                "leading-missing",
                (root / "missing-leading.upper").as_posix(),
                "uppercase-text",
                "uppercase",
            ),
            _mixed_payload(b"?", "leading-missing"),
        ),
        _SeedRecord(
            _ManifestRecord(
                "action-missing",
                (root / "missing-action.upper").as_posix(),
                "uppercase-text",
                "preserve",
            ),
            _mixed_payload(b"U", "action-missing"),
        ),
    )


def _leading_byte_canary_seeds() -> tuple[_SeedRecord, ...]:
    root = CASE_ROUTED_BATCH_TRANSFORM_PAYLOAD_ROOT
    values = (
        ("leading-nul-u", b"\x00UAb\n"),
        ("leading-bom-u", b"\xef\xbb\xbfUAb\n"),
        ("leading-lf-u", b"\nUAb\n"),
        ("leading-lower-u", b"uUAb\n"),
        ("leading-no-final-lf", b"UAb"),
    )
    return tuple(
        _SeedRecord(
            _ManifestRecord(
                identifier,
                (root / f"{identifier}.bin").as_posix(),
                "opaque",
                "preserve",
            ),
            content,
        )
        for identifier, content in values
    )


def _profile_seed_records(
    profile: ExecutableFixtureProfile,
) -> tuple[tuple[_SeedRecord, ...], tuple[_ManifestRecord, ...]]:
    profile_id = profile.profile_id
    if profile_id == "spaces-unicode":
        seeds = (
            *_core_seed_records(
                (
                    "alpha space",
                    "café-雪",
                    'quote"name',
                    "back\\slash",
                ),
                (
                    "alpha space",
                    "café 雪",
                    'quote"source',
                    "back\\source",
                ),
            ),
            _unmatched_seed("mystery space", "mystery café"),
        )
        return seeds, tuple(seed.manifest for seed in seeds)
    if profile_id == "leading-dashes-globs":
        seeds = (
            *_core_seed_records(
                ("-alpha", "[beta]*?", "gamma?", "delta[0]"),
                ("-alpha", "[beta]*?", "gamma?", "delta[0]"),
            ),
            *_signal_isolation_seeds(),
            *_signal_exclusion_seeds(),
            *_leading_byte_canary_seeds(),
            _unmatched_seed("-unmatched[*]?", "-unmatched[*]?"),
        )
        return seeds, tuple(seed.manifest for seed in seeds)
    if profile_id == "empty-duplicates":
        core = _core_seed_records(
            ("alpha", "beta", "gamma", "delta"),
            ("alpha", "beta", "gamma", "delta"),
        )
        duplicate_content = _mixed_payload(b"C", "duplicate-content")
        seeds = (
            core[0],
            replace(core[1], content=duplicate_content),
            replace(core[2], content=duplicate_content),
            core[3],
            _unmatched_seed("mixed-unmatched", "mixed-unmatched"),
            _unmatched_seed("empty", "empty", content=b""),
        )
        physical = (
            seeds[0].manifest,
            seeds[0].manifest,
            *(seed.manifest for seed in seeds[1:]),
            _ManifestRecord(
                "beta-alias",
                seeds[1].manifest.source,
                seeds[1].manifest.kind,
                seeds[1].manifest.action,
            ),
        )
        return seeds, tuple(physical)
    if profile_id == "symlinks-ordering":
        seeds = _core_seed_records(
            ("zulu", "alpha", "mike", "bravo"),
            ("zulu", "alpha", "mike", "bravo"),
        )
        # This is the all-recognized batch witness for reject-batch success.
        return seeds, tuple(seed.manifest for seed in reversed(seeds))
    if profile_id == "partial-permissions":
        seeds = (
            *_core_seed_records(
                ("alpha", "beta", "gamma", "delta"),
                ("alpha", "beta", "gamma", "delta"),
                modes=(0o400, 0o440, 0o444, 0o400),
            ),
            _unmatched_seed(
                "zz-late-unmatched",
                "zz-late-unmatched",
                mode=0o400,
            ),
        )
        # The unmatched row is physically last to expose partial publication.
        return seeds, tuple(seed.manifest for seed in seeds)
    raise CaseRoutedBatchTransformError("unsupported fixture profile")


def _fixture_inputs(
    profile: ExecutableFixtureProfile,
) -> tuple[InputFile | InputSymlink, ...]:
    seeds, physical_rows = _profile_seed_records(profile)
    manifest_mode = 0o400 if profile.profile_id == "partial-permissions" else 0o444
    values: list[InputFile | InputSymlink] = [
        InputFile(
            CASE_ROUTED_BATCH_TRANSFORM_MANIFEST,
            b"".join(record.row() for record in physical_rows),
            manifest_mode,
        )
    ]
    values.extend(
        InputFile(seed.manifest.source, seed.content, seed.mode) for seed in seeds
    )
    if profile.profile_id == "spaces-unicode":
        values.append(
            InputFile(
                "input/batch/unlisted snow 雪.txt",
                b"ignore\n",
                0o444,
            )
        )
    elif profile.profile_id == "leading-dashes-globs":
        values.append(
            InputFile("input/batch/-unlisted[*]?.txt", b"ignore\n", 0o400)
        )
    elif profile.profile_id == "empty-duplicates":
        values.append(InputFile("input/batch/unlisted-empty", b"", 0o400))
    elif profile.profile_id == "symlinks-ordering":
        first = PurePosixPath(seeds[0].manifest.source)
        values.extend(
            (
                InputSymlink(
                    "input/batch/payloads/listed-looking.upper",
                    first.name,
                ),
                InputSymlink(
                    "input/batch/payloads/dangling[*]?.bin",
                    "missing.bin",
                ),
            )
        )
        values.reverse()
    elif profile.profile_id == "partial-permissions":
        values.extend(
            (
                InputFile(
                    "input/batch/payloads/unlisted-denied.bin",
                    b"ignore\n",
                    0o000,
                ),
                InputSymlink(
                    "input/batch/payloads/unlisted-link.bin",
                    PurePosixPath(seeds[0].manifest.source).name,
                ),
            )
        )
    return tuple(values)


def _validate_identifier_text(value: str) -> None:
    if type(value) is not str or not value or value in {".", ".."}:
        raise CaseRoutedBatchTransformError("record ID is invalid")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise CaseRoutedBatchTransformError("record ID is invalid") from exc
    if (
        len(encoded) > 64
        or "/" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise CaseRoutedBatchTransformError("record ID is invalid")


def _validate_source_text(value: str) -> None:
    if type(value) is not str:
        raise CaseRoutedBatchTransformError("source path is invalid")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise CaseRoutedBatchTransformError("source path is invalid") from exc
    path = PurePosixPath(value)
    root = CASE_ROUTED_BATCH_TRANSFORM_PAYLOAD_ROOT
    if (
        path.is_absolute()
        or path.as_posix() != value
        or len(path.parts) <= len(root.parts)
        or path.parts[: len(root.parts)] != root.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or len(encoded) > 4_096
        or any(len(part.encode("utf-8")) > 255 for part in path.parts)
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise CaseRoutedBatchTransformError("source path is invalid")


def _input_file_map(definition: FixtureDefinition) -> dict[str, InputFile]:
    return {
        item.path: item
        for item in definition.inputs
        if type(item) is InputFile
    }


def _parse_manifest_primary(
    definition: FixtureDefinition,
) -> tuple[tuple[_ManifestRecord, InputFile], ...]:
    files = _input_file_map(definition)
    manifest = files.get(CASE_ROUTED_BATCH_TRANSFORM_MANIFEST)
    if manifest is None:
        raise CaseRoutedBatchTransformError("manifest is missing")
    raw = manifest.content
    if len(raw) > CASE_ROUTED_BATCH_TRANSFORM_MANIFEST_MAXIMUM_BYTES:
        raise CaseRoutedBatchTransformError("manifest exceeds its byte limit")
    if raw and not raw.endswith(b"\n"):
        raise CaseRoutedBatchTransformError("manifest is not LF terminated")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise CaseRoutedBatchTransformError("manifest is not UTF-8") from exc
    physical = [] if text == "" else text[:-1].split("\n")
    if len(physical) > CASE_ROUTED_BATCH_TRANSFORM_MAXIMUM_PHYSICAL_ROWS:
        raise CaseRoutedBatchTransformError("manifest has too many rows")
    logical: dict[str, _ManifestRecord] = {}
    for line in physical:
        fields = line.split("\t")
        if len(fields) != 4:
            raise CaseRoutedBatchTransformError("manifest row is malformed")
        record = _ManifestRecord(*fields)
        _validate_identifier_text(record.record_id)
        _validate_source_text(record.source)
        if (
            _TOKEN_RE.fullmatch(record.kind) is None
            or _TOKEN_RE.fullmatch(record.action) is None
        ):
            raise CaseRoutedBatchTransformError("manifest token is malformed")
        previous = logical.get(record.record_id)
        if previous is not None and previous != record:
            raise CaseRoutedBatchTransformError("record ID conflicts")
        logical[record.record_id] = record
    if len(logical) > CASE_ROUTED_BATCH_TRANSFORM_MAXIMUM_LOGICAL_RECORDS:
        raise CaseRoutedBatchTransformError("manifest has too many logical records")
    selected: list[tuple[_ManifestRecord, InputFile]] = []
    for record in sorted(logical.values(), key=lambda item: item.record_id.encode("utf-8")):
        source = files.get(record.source)
        if (
            source is None
            or type(source) is not InputFile
            or source.mode & 0o400 == 0
            or len(source.content)
            > CASE_ROUTED_BATCH_TRANSFORM_PAYLOAD_MAXIMUM_BYTES
        ):
            raise CaseRoutedBatchTransformError("listed source is outside the domain")
        selected.append((record, source))
    return tuple(selected)


def _primary_route(
    record: _ManifestRecord,
    content: bytes,
    route_key: RouteKey,
) -> str | None:
    if route_key == "suffix":
        basename = PurePosixPath(record.source).name
        for suffix, route in _SUFFIX_ROUTES:
            if basename.endswith(suffix):
                return route
        return None
    if route_key == "record-kind":
        return dict(_KIND_ROUTES).get(record.kind)
    if route_key == "leading-byte":
        return dict(_LEADING_ROUTES).get(content[0]) if content else None
    if route_key == "declared-action":
        return dict(_ACTION_ROUTES).get(record.action)
    raise CaseRoutedBatchTransformError("route key is invalid")


def _primary_transform(content: bytes, route: str) -> bytes:
    if route == "upper":
        return content.translate(_ASCII_UPPER)
    if route == "lower":
        return content.translate(_ASCII_LOWER)
    if route == "detab":
        return content.replace(b"\t", b"    ")
    if route == "strip-cr":
        return content.replace(b"\r", b"")
    if route == "verbatim":
        return content
    if route == "default":
        return content.translate(_ASCII_ROT13)
    raise CaseRoutedBatchTransformError("route transform is invalid")


def _payload_output_path(route: str, record_id: str) -> str:
    _validate_identifier_text(record_id)
    if route not in (*_RECOGNIZED_ROUTES, "verbatim", "default"):
        raise CaseRoutedBatchTransformError("payload route is invalid")
    return (PurePosixPath("output/routes") / route / f"{record_id}.out").as_posix()


def _status_bytes(
    state: str,
    logical: int,
    matched: int,
    unmatched: int,
    payloads: int,
    errors: int,
) -> bytes:
    if state not in {"complete", "rejected"}:
        raise CaseRoutedBatchTransformError("batch state is invalid")
    values = (logical, matched, unmatched, payloads, errors)
    if any(type(value) is not int or value < 0 for value in values):
        raise CaseRoutedBatchTransformError("batch count is invalid")
    return (
        f"batch\t{state}\t{logical}\t{matched}\t{unmatched}\t"
        f"{payloads}\t{errors}\n"
    ).encode("ascii")


def derive_case_routed_batch_transform_outputs(
    definition: FixtureDefinition,
    parameters: CaseRoutedBatchTransformParameters,
) -> tuple[OracleOutputRecord, ...]:
    """Primary dictionary/translation-table semantic implementation."""

    if type(definition) is not FixtureDefinition:
        raise CaseRoutedBatchTransformError("definition has the wrong type")
    if type(parameters) is not CaseRoutedBatchTransformParameters:
        raise CaseRoutedBatchTransformError("parameters have the wrong type")
    parameters.__post_init__()
    selected_definition = _revalidate_definition(definition)
    records = _parse_manifest_primary(selected_definition)
    matched: list[tuple[_ManifestRecord, InputFile, str]] = []
    unmatched: list[tuple[_ManifestRecord, InputFile]] = []
    for record, source in records:
        route = _primary_route(record, source.content, parameters.route_key)
        if route is None:
            unmatched.append((record, source))
        else:
            matched.append((record, source, route))

    payloads: list[OracleOutputRecord] = []
    errors = bytearray()
    rejected = (
        parameters.fallback_policy == "reject-batch" and bool(unmatched)
    )
    if not rejected:
        for record, source, route in matched:
            payloads.append(
                OracleOutputRecord(
                    _payload_output_path(route, record.record_id),
                    _primary_transform(source.content, route),
                    CASE_ROUTED_BATCH_TRANSFORM_OUTPUT_MODE,
                )
            )
        for record, source in unmatched:
            if parameters.fallback_policy == "copy-verbatim":
                payloads.append(
                    OracleOutputRecord(
                        _payload_output_path("verbatim", record.record_id),
                        _primary_transform(source.content, "verbatim"),
                        CASE_ROUTED_BATCH_TRANSFORM_OUTPUT_MODE,
                    )
                )
            elif parameters.fallback_policy == "route-default":
                payloads.append(
                    OracleOutputRecord(
                        _payload_output_path("default", record.record_id),
                        _primary_transform(source.content, "default"),
                        CASE_ROUTED_BATCH_TRANSFORM_OUTPUT_MODE,
                    )
                )
            elif parameters.fallback_policy == "emit-error-record":
                errors.extend(
                    f"unmatched\t{record.record_id}\t{parameters.route_key}\n".encode(
                        "utf-8"
                    )
                )
    else:
        for record, _source in unmatched:
            errors.extend(
                f"rejected\t{record.record_id}\t{parameters.route_key}\n".encode(
                    "utf-8"
                )
            )

    error_count = (
        len(unmatched)
        if rejected or parameters.fallback_policy == "emit-error-record"
        else 0
    )
    outputs = [
        OracleOutputRecord(
            CASE_ROUTED_BATCH_TRANSFORM_STATUS_OUTPUT,
            _status_bytes(
                "rejected" if rejected else "complete",
                len(records),
                len(matched),
                len(unmatched),
                len(payloads),
                error_count,
            ),
            CASE_ROUTED_BATCH_TRANSFORM_OUTPUT_MODE,
        ),
        OracleOutputRecord(
            CASE_ROUTED_BATCH_TRANSFORM_ERRORS_OUTPUT,
            bytes(errors),
            CASE_ROUTED_BATCH_TRANSFORM_OUTPUT_MODE,
        ),
        *payloads,
    ]
    outputs.sort(key=lambda output: output.path.encode("utf-8"))
    selected_outputs = tuple(outputs)
    if (
        selected_definition.expected_files
        and selected_definition.expected_files
        != _expected_output_policy(selected_outputs)
    ):
        raise CaseRoutedBatchTransformError(
            "primary output policy differs from derived outputs"
        )
    return selected_outputs


def _reference_validate_identifier(value: object) -> str:
    if type(value) is not str or not value or value in {".", ".."}:
        raise CaseRoutedBatchTransformError("reference ID failed")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise CaseRoutedBatchTransformError("reference ID failed") from exc
    if (
        len(encoded) > 64
        or "/" in value
        or any(ord(character) <= 31 or ord(character) == 127 for character in value)
    ):
        raise CaseRoutedBatchTransformError("reference ID failed")
    return value


def _reference_validate_source(value: object) -> str:
    if type(value) is not str:
        raise CaseRoutedBatchTransformError("reference source path failed")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise CaseRoutedBatchTransformError("reference source path failed") from exc
    components = value.split("/")
    if (
        len(encoded) > 4_096
        or components[:3] != ["input", "batch", "payloads"]
        or len(components) < 4
        or any(component in {"", ".", ".."} for component in components)
        or any(len(component.encode("utf-8")) > 255 for component in components)
        or any(ord(character) <= 31 or ord(character) == 127 for character in value)
    ):
        raise CaseRoutedBatchTransformError("reference source path failed")
    return value


def _reference_output_path(route: object, identifier: object) -> str:
    selected_id = _reference_validate_identifier(identifier)
    if type(route) is not str or route not in {
        "upper",
        "lower",
        "detab",
        "strip-cr",
        "verbatim",
        "default",
    }:
        raise CaseRoutedBatchTransformError("reference output route failed")
    return f"output/routes/{route}/{selected_id}.out"


def _reference_manifest_records(
    definition: FixtureDefinition,
) -> tuple[tuple[_ManifestRecord, bytes], ...]:
    """Independent parser used only by the reference semantic engine."""

    if type(definition) is not FixtureDefinition:
        raise CaseRoutedBatchTransformError("reference definition is invalid")
    manifest: InputFile | None = None
    source_values: dict[str, InputFile] = {}
    for value in definition.inputs:
        if type(value) is InputFile:
            source_values[value.path] = value
            if value.path == CASE_ROUTED_BATCH_TRANSFORM_MANIFEST:
                manifest = value
    if manifest is None:
        raise CaseRoutedBatchTransformError("reference manifest is missing")
    raw = manifest.content
    if (
        len(raw) > CASE_ROUTED_BATCH_TRANSFORM_MANIFEST_MAXIMUM_BYTES
        or (raw and raw[-1:] != b"\n")
    ):
        raise CaseRoutedBatchTransformError("reference manifest framing failed")
    try:
        decoded = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise CaseRoutedBatchTransformError(
            "reference manifest decoding failed"
        ) from exc
    rows = [] if decoded == "" else decoded[:-1].split("\n")
    if len(rows) > CASE_ROUTED_BATCH_TRANSFORM_MAXIMUM_PHYSICAL_ROWS:
        raise CaseRoutedBatchTransformError("reference physical row limit")
    by_id: dict[str, tuple[str, str, str]] = {}
    for row in rows:
        if row.count("\t") != 3:
            raise CaseRoutedBatchTransformError("reference row framing failed")
        identifier, source, kind, action = row.split("\t")
        _reference_validate_identifier(identifier)
        _reference_validate_source(source)
        if (
            _TOKEN_RE.fullmatch(kind) is None
            or _TOKEN_RE.fullmatch(action) is None
        ):
            raise CaseRoutedBatchTransformError("reference token failed")
        candidate = (source, kind, action)
        old = by_id.get(identifier)
        if old is not None and old != candidate:
            raise CaseRoutedBatchTransformError("reference ID conflict")
        by_id[identifier] = candidate
    if len(by_id) > CASE_ROUTED_BATCH_TRANSFORM_MAXIMUM_LOGICAL_RECORDS:
        raise CaseRoutedBatchTransformError("reference logical row limit")
    result: list[tuple[_ManifestRecord, bytes]] = []
    for identifier in sorted(by_id, key=lambda item: item.encode("utf-8")):
        source, kind, action = by_id[identifier]
        source_value = source_values.get(source)
        if (
            source_value is None
            or source_value.mode & 0o400 == 0
            or len(source_value.content)
            > CASE_ROUTED_BATCH_TRANSFORM_PAYLOAD_MAXIMUM_BYTES
        ):
            raise CaseRoutedBatchTransformError("reference source failed")
        result.append(
            (_ManifestRecord(identifier, source, kind, action), source_value.content)
        )
    return tuple(result)


def _reference_route(
    record: _ManifestRecord,
    content: bytes,
    route_key: RouteKey,
) -> str | None:
    if route_key == "suffix":
        name = record.source.rsplit("/", 1)[-1]
        if name.endswith(".upper"):
            return "upper"
        if name.endswith(".lower"):
            return "lower"
        if name.endswith(".tabs"):
            return "detab"
        if name.endswith(".crlf"):
            return "strip-cr"
        return None
    if route_key == "record-kind":
        if record.kind == "uppercase-text":
            return "upper"
        if record.kind == "lowercase-text":
            return "lower"
        if record.kind == "tabbed-text":
            return "detab"
        if record.kind == "crlf-text":
            return "strip-cr"
        return None
    if route_key == "leading-byte":
        if not content:
            return None
        first = content[0]
        if first == 85:
            return "upper"
        if first == 76:
            return "lower"
        if first == 84:
            return "detab"
        if first == 67:
            return "strip-cr"
        return None
    if route_key == "declared-action":
        if record.action == "uppercase":
            return "upper"
        if record.action == "lowercase":
            return "lower"
        if record.action == "expand-tabs":
            return "detab"
        if record.action == "delete-cr":
            return "strip-cr"
        return None
    raise CaseRoutedBatchTransformError("reference route key failed")


def _reference_transform(content: bytes, route: str) -> bytes:
    result = bytearray()
    for value in content:
        if route == "upper" and 97 <= value <= 122:
            result.append(value - 32)
        elif route == "lower" and 65 <= value <= 90:
            result.append(value + 32)
        elif route == "detab" and value == 9:
            result.extend(b"    ")
        elif route == "strip-cr" and value == 13:
            continue
        elif route == "default" and 65 <= value <= 90:
            result.append(((value - 65 + 13) % 26) + 65)
        elif route == "default" and 97 <= value <= 122:
            result.append(((value - 97 + 13) % 26) + 97)
        else:
            result.append(value)
    return bytes(result)


def reference_case_routed_batch_transform_outputs(
    definition: FixtureDefinition,
    parameters: CaseRoutedBatchTransformParameters,
) -> tuple[OracleOutputRecord, ...]:
    """Reference match/byte-loop semantic implementation."""

    if type(parameters) is not CaseRoutedBatchTransformParameters:
        raise CaseRoutedBatchTransformError("reference parameters are invalid")
    parameters.__post_init__()
    selected_definition = _revalidate_definition(definition)
    records = _reference_manifest_records(selected_definition)
    classified = [
        (record, content, _reference_route(record, content, parameters.route_key))
        for record, content in records
    ]
    matched_count = sum(route is not None for _record, _content, route in classified)
    unmatched_values = [
        (record, content)
        for record, content, route in classified
        if route is None
    ]
    reject = (
        parameters.fallback_policy == "reject-batch"
        and len(unmatched_values) != 0
    )
    result: list[OracleOutputRecord] = []
    error_rows: list[bytes] = []
    if reject:
        for record, _content in unmatched_values:
            error_rows.append(
                ("rejected\t" + record.record_id + "\t" + parameters.route_key + "\n").encode(
                    "utf-8"
                )
            )
    else:
        for record, content, route in classified:
            destination = route
            transformed: bytes | None = None
            if destination is not None:
                transformed = _reference_transform(content, destination)
            elif parameters.fallback_policy == "copy-verbatim":
                destination = "verbatim"
                transformed = bytes(content)
            elif parameters.fallback_policy == "route-default":
                destination = "default"
                transformed = _reference_transform(content, "default")
            elif parameters.fallback_policy == "emit-error-record":
                error_rows.append(
                    (
                        "unmatched\t"
                        + record.record_id
                        + "\t"
                        + parameters.route_key
                        + "\n"
                    ).encode("utf-8")
                )
            if destination is not None and transformed is not None:
                result.append(
                    OracleOutputRecord(
                        _reference_output_path(destination, record.record_id),
                        transformed,
                        CASE_ROUTED_BATCH_TRANSFORM_OUTPUT_MODE,
                    )
                )
    error_count = len(error_rows)
    status = (
        "batch\t"
        + ("rejected" if reject else "complete")
        + f"\t{len(records)}\t{matched_count}\t{len(unmatched_values)}"
        + f"\t{len(result)}\t{error_count}\n"
    ).encode("ascii")
    result.extend(
        (
            OracleOutputRecord(
                CASE_ROUTED_BATCH_TRANSFORM_STATUS_OUTPUT,
                status,
                CASE_ROUTED_BATCH_TRANSFORM_OUTPUT_MODE,
            ),
            OracleOutputRecord(
                CASE_ROUTED_BATCH_TRANSFORM_ERRORS_OUTPUT,
                b"".join(error_rows),
                CASE_ROUTED_BATCH_TRANSFORM_OUTPUT_MODE,
            ),
        )
    )
    result.sort(key=lambda output: output.path.encode("utf-8"))
    selected_outputs = tuple(result)
    if (
        selected_definition.expected_files
        and selected_definition.expected_files
        != _expected_output_policy(selected_outputs)
    ):
        raise CaseRoutedBatchTransformError(
            "reference output policy differs from derived outputs"
        )
    return selected_outputs


def verify_case_routed_batch_transform_outputs(
    definition: FixtureDefinition,
    parameters: CaseRoutedBatchTransformParameters,
    candidate_outputs: object,
) -> bool:
    """Verify exact supplied output records through independent agreement."""

    if (
        type(candidate_outputs) is not tuple
        or any(type(item) is not OracleOutputRecord for item in candidate_outputs)
    ):
        return False
    try:
        selected_definition = _revalidate_definition(definition)
        primary = derive_case_routed_batch_transform_outputs(
            selected_definition, parameters
        )
        reference = reference_case_routed_batch_transform_outputs(
            selected_definition, parameters
        )
    except (CaseRoutedBatchTransformError, TypeError, ValueError):
        return False
    return (
        selected_definition.expected_files == _expected_output_policy(primary)
        and primary == reference == candidate_outputs
    )


def _revalidate_definition(definition: object) -> FixtureDefinition:
    if type(definition) is not FixtureDefinition:
        raise CaseRoutedBatchTransformError("definition has the wrong exact type")
    try:
        inputs = tuple(
            InputFile(item.path, item.content, item.mode)
            if type(item) is InputFile
            else InputSymlink(item.path, item.target)
            if type(item) is InputSymlink
            else (_ for _ in ()).throw(
                CaseRoutedBatchTransformError("input has the wrong exact type")
            )
            for item in definition.inputs
        )
        expected = tuple(
            ExpectedFile(item.path, item.maximum_bytes, item.mode)
            for item in definition.expected_files
        )
        rebuilt = FixtureDefinition(
            definition.fixture_id,
            inputs,
            expected,
            definition.schema_version,
        )
    except (
        AttributeError,
        CaseRoutedBatchTransformError,
        TypeError,
        ValueError,
    ) as exc:
        raise CaseRoutedBatchTransformError(
            "definition reconstruction failed"
        ) from exc
    if rebuilt != definition:
        raise CaseRoutedBatchTransformError("definition differs on reconstruction")
    return definition


def _expected_output_policy(
    outputs: tuple[OracleOutputRecord, ...],
) -> tuple[ExpectedFile, ...]:
    return tuple(
        ExpectedFile(
            output.path,
            maximum_bytes=CASE_ROUTED_BATCH_TRANSFORM_OUTPUT_MAXIMUM_BYTES,
            mode=CASE_ROUTED_BATCH_TRANSFORM_OUTPUT_MODE,
        )
        for output in outputs
    )


def _compute_oracle_sha256(outputs: tuple[OracleOutputRecord, ...]) -> str:
    if (
        type(outputs) is not tuple
        or len(outputs) < 2
        or any(type(output) is not OracleOutputRecord for output in outputs)
    ):
        raise CaseRoutedBatchTransformError("oracle output tuple is invalid")
    for output in outputs:
        output.__post_init__()
        if (
            output.mode != CASE_ROUTED_BATCH_TRANSFORM_OUTPUT_MODE
            or len(output.content)
            > CASE_ROUTED_BATCH_TRANSFORM_OUTPUT_MAXIMUM_BYTES
        ):
            raise CaseRoutedBatchTransformError("oracle output is outside policy")
    if (
        tuple(output.path for output in outputs)
        != tuple(sorted((output.path for output in outputs), key=str.encode))
        or len({output.path for output in outputs}) != len(outputs)
        or {CASE_ROUTED_BATCH_TRANSFORM_STATUS_OUTPUT,
            CASE_ROUTED_BATCH_TRANSFORM_ERRORS_OUTPUT}
        - {output.path for output in outputs}
    ):
        raise CaseRoutedBatchTransformError("oracle output paths are invalid")
    return domain_sha256(
        "cbds.executable-fixture.trusted-oracle.v1",
        {
            "schema_version": EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION,
            "semantic_verifier_identity": (
                CASE_ROUTED_BATCH_TRANSFORM_VERIFIER_IDENTITY
            ),
            "outputs": [output.commitment_record() for output in outputs],
        },
    )


@dataclass(frozen=True, slots=True)
class CaseRoutedBatchTransformOracle:
    outputs: tuple[OracleOutputRecord, ...]
    oracle_sha256: str
    semantic_verifier_identity: str = (
        CASE_ROUTED_BATCH_TRANSFORM_VERIFIER_IDENTITY
    )
    schema_version: str = EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            type(self.semantic_verifier_identity) is not str
            or self.semantic_verifier_identity
            != CASE_ROUTED_BATCH_TRANSFORM_VERIFIER_IDENTITY
            or type(self.schema_version) is not str
            or self.schema_version != EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION
            or not _is_sha256(self.oracle_sha256)
            or self.oracle_sha256 != _compute_oracle_sha256(self.outputs)
        ):
            raise CaseRoutedBatchTransformError("oracle identity is invalid")

    def commitment_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "schema_version": self.schema_version,
            "record_type": "cbds.executable-fixture-trusted-oracle",
            "semantic_verifier_identity": self.semantic_verifier_identity,
            "outputs": [output.commitment_record() for output in self.outputs],
            "oracle_sha256": self.oracle_sha256,
        }


@dataclass(frozen=True, slots=True)
class CaseRoutedBatchTransformFixtureBundle:
    task_contract_sha256: str
    profile_sha256: str
    definition: FixtureDefinition = field(repr=False)
    fixture_definition_sha256: str
    oracle: CaseRoutedBatchTransformOracle = field(repr=False)
    descriptor: OpaqueFixtureDescriptor
    schema_version: str = EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_case_routed_batch_transform_fixture_bundle(self)

    def to_opaque_descriptor(self) -> OpaqueFixtureDescriptor:
        validate_case_routed_batch_transform_fixture_bundle(self)
        return self.descriptor

    def commitment_record(self) -> dict[str, object]:
        validate_case_routed_batch_transform_fixture_bundle(self)
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


def validate_case_routed_batch_transform_fixture_bundle(
    bundle: CaseRoutedBatchTransformFixtureBundle,
) -> None:
    if type(bundle) is not CaseRoutedBatchTransformFixtureBundle:
        raise CaseRoutedBatchTransformError("bundle has the wrong exact type")
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
        raise CaseRoutedBatchTransformError("bundle metadata is invalid")
    definition = _revalidate_definition(bundle.definition)
    definition_sha256 = compute_fixture_definition_semantic_sha256(definition)
    if bundle.fixture_definition_sha256 != definition_sha256:
        raise CaseRoutedBatchTransformError("definition digest is invalid")
    if type(bundle.oracle) is not CaseRoutedBatchTransformOracle:
        raise CaseRoutedBatchTransformError("oracle has the wrong exact type")
    bundle.oracle.__post_init__()
    if definition.expected_files != _expected_output_policy(bundle.oracle.outputs):
        raise CaseRoutedBatchTransformError("output policy does not bind oracle")
    if type(bundle.descriptor) is not OpaqueFixtureDescriptor:
        raise CaseRoutedBatchTransformError("descriptor has the wrong exact type")
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
        raise CaseRoutedBatchTransformError("descriptor binding is invalid")


def verify_case_routed_batch_transform_fixture_bundle(bundle: object) -> bool:
    try:
        validate_case_routed_batch_transform_fixture_bundle(  # type: ignore[arg-type]
            bundle
        )
    except (CaseRoutedBatchTransformError, TypeError, ValueError):
        return False
    return True


def _validate_task_profile(
    task: object,
    profile: object,
) -> tuple[CaseRoutedBatchTransformTask, ExecutableFixtureProfile]:
    if type(task) is not CaseRoutedBatchTransformTask:
        raise CaseRoutedBatchTransformError("task has the wrong exact type")
    if type(profile) is not ExecutableFixtureProfile:
        raise CaseRoutedBatchTransformError("profile has the wrong exact type")
    try:
        task.__post_init__()
        CaseRoutedBatchTransformParameters(
            task.parameters.route_key,
            task.parameters.fallback_policy,
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
        raise CaseRoutedBatchTransformError("task/profile revalidation failed") from exc
    if rebuilt_profile not in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
        raise CaseRoutedBatchTransformError("profile is not public development data")
    return task, profile


def _construct_case_routed_batch_transform_fixture_bundle(
    task: CaseRoutedBatchTransformTask,
    profile: ExecutableFixtureProfile,
) -> CaseRoutedBatchTransformFixtureBundle:
    selected_task, selected_profile = _validate_task_profile(task, profile)
    inputs = _fixture_inputs(selected_profile)
    provisional = FixtureDefinition(
        fixture_id=(
            f"fixture.{selected_task.task_id}.{selected_profile.profile_id}"
        ),
        inputs=inputs,
        expected_files=(),
    )
    primary = derive_case_routed_batch_transform_outputs(
        provisional, selected_task.parameters
    )
    reference = reference_case_routed_batch_transform_outputs(
        provisional, selected_task.parameters
    )
    if primary != reference:
        raise CaseRoutedBatchTransformError(
            "independent production oracle implementations disagree"
        )
    definition = FixtureDefinition(
        fixture_id=provisional.fixture_id,
        inputs=inputs,
        expected_files=_expected_output_policy(primary),
    )
    if (
        derive_case_routed_batch_transform_outputs(
            definition, selected_task.parameters
        )
        != primary
        or reference_case_routed_batch_transform_outputs(
            definition, selected_task.parameters
        )
        != reference
    ):
        raise CaseRoutedBatchTransformError("final output policy changed semantics")
    oracle = CaseRoutedBatchTransformOracle(
        primary, _compute_oracle_sha256(primary)
    )
    definition_sha256 = compute_fixture_definition_semantic_sha256(definition)
    fixture_sha256 = compute_bound_fixture_sha256(
        task_contract_sha256=selected_task.task_contract_sha256,
        profile_sha256=selected_profile.profile_sha256,
        fixture_definition_sha256=definition_sha256,
        oracle_sha256=oracle.oracle_sha256,
    )
    return CaseRoutedBatchTransformFixtureBundle(
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


def build_case_routed_batch_transform_fixture_bundle(
    task: CaseRoutedBatchTransformTask,
    profile: ExecutableFixtureProfile,
) -> CaseRoutedBatchTransformFixtureBundle:
    bundle = _construct_case_routed_batch_transform_fixture_bundle(task, profile)
    validate_case_routed_batch_transform_fixture_for_task_profile(
        task, profile, bundle
    )
    return bundle


def validate_case_routed_batch_transform_fixture_for_task_profile(
    task: CaseRoutedBatchTransformTask,
    profile: ExecutableFixtureProfile,
    bundle: CaseRoutedBatchTransformFixtureBundle,
) -> None:
    selected_task, selected_profile = _validate_task_profile(task, profile)
    validate_case_routed_batch_transform_fixture_bundle(bundle)
    if (
        bundle.task_contract_sha256 != selected_task.task_contract_sha256
        or bundle.profile_sha256 != selected_profile.profile_sha256
    ):
        raise CaseRoutedBatchTransformError("bundle task/profile binding is invalid")
    profile_index = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES.index(selected_profile)
    if selected_task.fixtures[profile_index] != bundle.descriptor:
        raise CaseRoutedBatchTransformError("public descriptor differs from bundle")
    rebuilt = _construct_case_routed_batch_transform_fixture_bundle(
        selected_task, selected_profile
    )
    if rebuilt != bundle:
        raise CaseRoutedBatchTransformError("bundle differs from generation")


def verify_case_routed_batch_transform_fixture_for_task_profile(
    task: object,
    profile: object,
    bundle: object,
) -> bool:
    try:
        validate_case_routed_batch_transform_fixture_for_task_profile(
            task,  # type: ignore[arg-type]
            profile,  # type: ignore[arg-type]
            bundle,  # type: ignore[arg-type]
        )
    except (CaseRoutedBatchTransformError, TypeError, ValueError):
        return False
    return True


def build_case_routed_batch_transform_tasks() -> tuple[
    CaseRoutedBatchTransformTask, ...
]:
    tasks: list[CaseRoutedBatchTransformTask] = []
    for route_key in CASE_ROUTED_BATCH_TRANSFORM_ROUTE_KEYS:
        for fallback_policy in CASE_ROUTED_BATCH_TRANSFORM_FALLBACK_POLICIES:
            bootstrap = _bootstrap_task(
                CaseRoutedBatchTransformParameters(route_key, fallback_policy)
            )
            descriptors = tuple(
                _construct_case_routed_batch_transform_fixture_bundle(
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
        raise CaseRoutedBatchTransformError("task grid is not 20 unique tasks")
    return selected


def materialize_case_routed_batch_transform_fixture(
    task: CaseRoutedBatchTransformTask,
    profile: ExecutableFixtureProfile,
    bundle: CaseRoutedBatchTransformFixtureBundle,
    workspace: str | os.PathLike[str],
) -> WorkspaceHandle:
    validate_case_routed_batch_transform_fixture_for_task_profile(
        task, profile, bundle
    )
    return materialize_fixture(bundle.definition, workspace)


def verify_case_routed_batch_transform_workspace(
    task: CaseRoutedBatchTransformTask,
    profile: ExecutableFixtureProfile,
    bundle: CaseRoutedBatchTransformFixtureBundle,
    handle: WorkspaceHandle,
) -> bool:
    """Verify authenticated final state without claiming execution history.

    Stable descriptor-relative scans bind the complete input and output trees.
    They do not prove routing, transform, tool, read, or publication history;
    candidate exit status; global quiescence; or immutability after the final
    scan.  A trusted harness must stop all writers before this call and keep
    the workspace quiescent through its return.
    """

    if type(handle) is not WorkspaceHandle:
        return False
    try:
        validate_case_routed_batch_transform_fixture_for_task_profile(
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
        if len(output_entries) != len(bundle.oracle.outputs):
            return False
        observed: list[OracleOutputRecord] = []
        for output in bundle.oracle.outputs:
            entry = next(
                (item for item in output_entries if item.path == output.path),
                None,
            )
            if (
                entry is None
                or entry.mode != CASE_ROUTED_BATCH_TRANSFORM_OUTPUT_MODE
            ):
                return False
            observed.append(
                OracleOutputRecord(
                    output.path,
                    handle.read_output_bytes(output_scan, output.path),
                    entry.mode,
                )
            )
        observed_tuple = tuple(observed)
        primary = derive_case_routed_batch_transform_outputs(
            bundle.definition, task.parameters
        )
        reference = reference_case_routed_batch_transform_outputs(
            bundle.definition, task.parameters
        )
        if not (
            primary
            == reference
            == bundle.oracle.outputs
            == observed_tuple
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
        CaseRoutedBatchTransformError,
        OSError,
        TypeError,
        ValueError,
    ):
        return False


__all__ = [
    "CASE_ROUTED_BATCH_TRANSFORM_ALLOWED_TOOLS",
    "CASE_ROUTED_BATCH_TRANSFORM_ATOMIC_PUBLICATION_HISTORY_OBSERVED",
    "CASE_ROUTED_BATCH_TRANSFORM_CANDIDATE_EXIT_STATUS_OBSERVED",
    "CASE_ROUTED_BATCH_TRANSFORM_DIRECTORY_PERMISSION_ERRORS_COVERED",
    "CASE_ROUTED_BATCH_TRANSFORM_EFFECTIVE_ACCESS_FAILURES_COVERED",
    "CASE_ROUTED_BATCH_TRANSFORM_ERRORS_OUTPUT",
    "CASE_ROUTED_BATCH_TRANSFORM_FALLBACK_POLICIES",
    "CASE_ROUTED_BATCH_TRANSFORM_FAMILY_ID",
    "CASE_ROUTED_BATCH_TRANSFORM_FILESYSTEM_IDENTITY",
    "CASE_ROUTED_BATCH_TRANSFORM_GENERATOR_VERSION",
    "CASE_ROUTED_BATCH_TRANSFORM_MANIFEST",
    "CASE_ROUTED_BATCH_TRANSFORM_MANIFEST_MAXIMUM_BYTES",
    "CASE_ROUTED_BATCH_TRANSFORM_MAXIMUM_LOGICAL_RECORDS",
    "CASE_ROUTED_BATCH_TRANSFORM_MAXIMUM_PHYSICAL_ROWS",
    "CASE_ROUTED_BATCH_TRANSFORM_MODE_UNREADABLE_UNLISTED_LEAVES_COVERED",
    "CASE_ROUTED_BATCH_TRANSFORM_OUTPUT_IDENTITY",
    "CASE_ROUTED_BATCH_TRANSFORM_OUTPUT_MAXIMUM_BYTES",
    "CASE_ROUTED_BATCH_TRANSFORM_OUTPUT_MODE",
    "CASE_ROUTED_BATCH_TRANSFORM_PAYLOAD_MAXIMUM_BYTES",
    "CASE_ROUTED_BATCH_TRANSFORM_PAYLOAD_ROOT",
    "CASE_ROUTED_BATCH_TRANSFORM_READ_SCOPE_OBSERVED",
    "CASE_ROUTED_BATCH_TRANSFORM_ROUTE_HISTORY_OBSERVED",
    "CASE_ROUTED_BATCH_TRANSFORM_ROUTE_KEYS",
    "CASE_ROUTED_BATCH_TRANSFORM_STATUS_OUTPUT",
    "CASE_ROUTED_BATCH_TRANSFORM_SYMLINK_DISTRACTORS_COVERED",
    "CASE_ROUTED_BATCH_TRANSFORM_TOOL_HISTORY_OBSERVED",
    "CASE_ROUTED_BATCH_TRANSFORM_TRANSFORM_HISTORY_OBSERVED",
    "CASE_ROUTED_BATCH_TRANSFORM_VERIFIER_IDENTITY",
    "CASE_ROUTED_BATCH_TRANSFORM_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE",
    "CASE_ROUTED_BATCH_TRANSFORM_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE",
    "CaseRoutedBatchTransformError",
    "CaseRoutedBatchTransformFixtureBundle",
    "CaseRoutedBatchTransformOracle",
    "CaseRoutedBatchTransformParameters",
    "CaseRoutedBatchTransformTask",
    "build_case_routed_batch_transform_fixture_bundle",
    "build_case_routed_batch_transform_tasks",
    "case_routed_batch_transform_task_semantic_core",
    "compute_case_routed_batch_transform_task_sha256",
    "derive_case_routed_batch_transform_outputs",
    "materialize_case_routed_batch_transform_fixture",
    "reference_case_routed_batch_transform_outputs",
    "validate_case_routed_batch_transform_fixture_bundle",
    "validate_case_routed_batch_transform_fixture_for_task_profile",
    "verify_case_routed_batch_transform_fixture_bundle",
    "verify_case_routed_batch_transform_fixture_for_task_profile",
    "verify_case_routed_batch_transform_outputs",
    "verify_case_routed_batch_transform_workspace",
]
