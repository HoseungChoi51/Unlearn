"""Typed contracts for the public executable-static development registry.

This module describes tasks and opaque fixture identities only.  It does not
materialize a filesystem, expose fixture cases, run candidate code, or
authorize an evaluation or research claim.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Final, Literal, TypeAlias

from .benchmark import NormalizedSemanticGraph, OperatorNode


EXECUTABLE_STATIC_SCHEMA_VERSION: Final[str] = "1.0.0"
EXECUTABLE_STATIC_CONTRACT_VERSION: Final[str] = "1.0.0"
EXECUTABLE_STATIC_REGISTRY_VERSION: Final[str] = "1.0.0"
EXECUTABLE_STATIC_FAMILY_VERSION: Final[str] = "1.0.0"
EXECUTABLE_STATIC_SUITE_ID: Final[str] = (
    "cbds.public-method-development.static.100-v1"
)
METHOD_DEVELOPMENT_SPLIT: Final[str] = "method_development"

FamilyId: TypeAlias = Literal[
    "active-jsonl-labels",
    "manifest-copy",
    "csv-group-totals",
    "checksum-manifest",
    "path-suffix-inventory",
    "line-transform-mirror",
    "mode-normalized-mirror",
    "jsonl-keyed-inner-join",
    "ustar-safe-extract",
    "proc-snapshot-report",
]
FilesystemIdentity: TypeAlias = Literal[
    "structured-records-tree-v1",
    "symlinked-copy-workspace-v1",
    "structured-csv-tree-v1",
    "permission-boundary-assets-v1",
    "nested-project-tree-v1",
    "mixed-byte-text-tree-v1",
    "mixed-mode-source-tree-v1",
    "paired-jsonl-records-v1",
    "ustar-archive-workspace-v1",
    "synthetic-proc-snapshot-v1",
]
OutputIdentity: TypeAlias = Literal[
    "utf8-byte-sorted-lines-v1",
    "exact-output-tree-v1",
    "rfc4180-group-totals-v1",
    "jsonl-checksum-status-v1",
    "utf8-byte-sorted-paths-v1",
    "exact-transformed-mirror-v1",
    "exact-mode-normalized-mirror-v1",
    "ordered-jsonl-inner-join-v1",
    "exact-safe-extraction-tree-v1",
    "pid-ordered-process-report-v1",
]

ActiveLabelKey: TypeAlias = Literal["label", "name", "tag", "title"]
ActivePredicate: TypeAlias = Literal[
    "active-true",
    "enabled-yes",
    "state-ready",
    "score-at-least-10",
    "deleted-false",
]
CopySelector: TypeAlias = Literal[
    "all-readable",
    "txt-suffix",
    "selected-true",
    "declared-sha256-matches",
]
CollisionPolicy: TypeAlias = Literal[
    "reject-collision",
    "first-record",
    "last-record",
    "identical-bytes-only",
    "utf8-smallest-source",
]
CsvLayout: TypeAlias = Literal[
    "category-amount-enabled",
    "enabled-category-amount",
    "amount-enabled-category",
    "category-enabled-amount",
]
CsvPredicate: TypeAlias = Literal[
    "all-valid",
    "enabled-yes",
    "positive-amount",
    "nonempty-category",
    "enabled-and-positive",
]
ChecksumLayout: TypeAlias = Literal[
    "json-object-lines",
    "json-array-lines",
    "rfc4180-csv",
    "nul-triplets",
]
ChecksumPolicy: TypeAlias = Literal[
    "digest-only",
    "mode-only",
    "digest-and-mode",
    "readable-digest-and-mode",
    "strict-kind-digest-and-mode",
]
PathSuffix: TypeAlias = Literal[".txt", ".jsonl", ".log", ".csv"]
PathDepth: TypeAlias = Literal[1, 2, 3, 4, "unbounded"]
LineTransform: TypeAlias = Literal[
    "identity",
    "ascii-lower",
    "ascii-upper",
    "tabs-to-four-spaces",
    "delete-carriage-returns",
]
ModeMirrorSelector: TypeAlias = Literal[
    "all-readable",
    "txt-suffix",
    "any-executable",
    "owner-writable",
]
ModeNormalization: TypeAlias = Literal[
    "fixed-0644",
    "fixed-0600",
    "fixed-0444",
    "preserve-exec",
    "fold-class-bits-to-owner",
]
JoinKey: TypeAlias = Literal["id", "key", "name", "slug"]
JoinDuplicatePolicy: TypeAlias = Literal[
    "cartesian",
    "first-left",
    "last-left",
    "first-right",
    "last-right",
]
UstarSelector: TypeAlias = Literal[
    "all-regular",
    "txt-suffix",
    "jsonl-suffix",
    "nonempty-regular",
]
UstarConflictPolicy: TypeAlias = Literal[
    "reject-duplicates",
    "first-entry",
    "last-entry",
    "identical-only",
    "smallest-sha256",
]
ProcSnapshotView: TypeAlias = Literal[
    "identity",
    "ownership",
    "memory",
    "command",
]
ProcSnapshotPredicate: TypeAlias = Literal[
    "all-valid",
    "running-only",
    "non-zombie",
    "uid-zero",
    "has-argv",
]


_FAMILY_IDS: Final[frozenset[str]] = frozenset(
    {
        "active-jsonl-labels",
        "manifest-copy",
        "csv-group-totals",
        "checksum-manifest",
        "path-suffix-inventory",
        "line-transform-mirror",
        "mode-normalized-mirror",
        "jsonl-keyed-inner-join",
        "ustar-safe-extract",
        "proc-snapshot-report",
    }
)
_FILESYSTEM_IDENTITIES: Final[frozenset[str]] = frozenset(
    {
        "structured-records-tree-v1",
        "symlinked-copy-workspace-v1",
        "structured-csv-tree-v1",
        "permission-boundary-assets-v1",
        "nested-project-tree-v1",
        "mixed-byte-text-tree-v1",
        "mixed-mode-source-tree-v1",
        "paired-jsonl-records-v1",
        "ustar-archive-workspace-v1",
        "synthetic-proc-snapshot-v1",
    }
)
_OUTPUT_IDENTITIES: Final[frozenset[str]] = frozenset(
    {
        "utf8-byte-sorted-lines-v1",
        "exact-output-tree-v1",
        "rfc4180-group-totals-v1",
        "jsonl-checksum-status-v1",
        "utf8-byte-sorted-paths-v1",
        "exact-transformed-mirror-v1",
        "exact-mode-normalized-mirror-v1",
        "ordered-jsonl-inner-join-v1",
        "exact-safe-extraction-tree-v1",
        "pid-ordered-process-report-v1",
    }
)
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_TASK_ID_RE: Final[re.Pattern[str]] = re.compile(r"mds-[0-9a-f]{24}\Z")
_FIXTURE_ID_RE: Final[re.Pattern[str]] = re.compile(r"fx-[0-9a-f]{24}\Z")
_TOOL_RE: Final[re.Pattern[str]] = re.compile(r"[a-z0-9][a-z0-9+._-]{0,63}\Z")


def canonical_json_bytes(value: object) -> bytes:
    """Encode a contract using the repository's strict canonical JSON form."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def domain_sha256(domain: str, value: object) -> str:
    """Hash a canonical value with an explicit, unambiguous domain prefix."""

    if not isinstance(domain, str) or not domain or "\0" in domain:
        raise ValueError("hash domain must be a nonempty NUL-free string")
    return sha256(domain.encode("ascii") + b"\0" + canonical_json_bytes(value)).hexdigest()


# These trusted profile contracts are deliberately absent from the public
# projection.  Their commitments are part of the registry identity, so they
# live in this dependency-free contract layer rather than in the builder.
_EXECUTABLE_STATIC_FIXTURE_PROFILE_CORES: Final[tuple[dict[str, object], ...]] = (
    {"profile_version": "1.0.0", "cases": ["spaces", "unicode"]},
    {"profile_version": "1.0.0", "cases": ["leading-dashes", "glob-characters"]},
    {"profile_version": "1.0.0", "cases": ["empty-input", "duplicate-records"]},
    {"profile_version": "1.0.0", "cases": ["symlinks", "ordering-variation"]},
    {"profile_version": "1.0.0", "cases": ["partial-failure", "permission-errors"]},
)
EXECUTABLE_STATIC_FIXTURE_PROFILE_SHA256: Final[tuple[str, ...]] = tuple(
    domain_sha256("cbds.executable-static.fixture-profile.v1", profile)
    for profile in _EXECUTABLE_STATIC_FIXTURE_PROFILE_CORES
)


def _require_member(value: object, allowed: frozenset[object], field: str) -> None:
    if type(value) not in {str, int}:
        raise ValueError(f"{field} is not a supported closed-contract value")
    try:
        accepted = value in allowed
    except TypeError:
        accepted = False
    if not accepted:
        raise ValueError(f"{field} is not a supported closed-contract value")


@dataclass(frozen=True, slots=True)
class ActiveJsonlLabelsParameters:
    label_key: ActiveLabelKey
    predicate: ActivePredicate

    def __post_init__(self) -> None:
        _require_member(self.label_key, frozenset({"label", "name", "tag", "title"}), "label_key")
        _require_member(
            self.predicate,
            frozenset(
                {
                    "active-true",
                    "enabled-yes",
                    "state-ready",
                    "score-at-least-10",
                    "deleted-false",
                }
            ),
            "predicate",
        )

    def to_record(self) -> dict[str, str]:
        return {"parameter_type": "active-jsonl-labels", "label_key": self.label_key, "predicate": self.predicate}


@dataclass(frozen=True, slots=True)
class ManifestCopyParameters:
    selector: CopySelector
    collision_policy: CollisionPolicy

    def __post_init__(self) -> None:
        _require_member(
            self.selector,
            frozenset({"all-readable", "txt-suffix", "selected-true", "declared-sha256-matches"}),
            "selector",
        )
        _require_member(
            self.collision_policy,
            frozenset(
                {
                    "reject-collision",
                    "first-record",
                    "last-record",
                    "identical-bytes-only",
                    "utf8-smallest-source",
                }
            ),
            "collision_policy",
        )

    def to_record(self) -> dict[str, str]:
        return {
            "parameter_type": "manifest-copy",
            "selector": self.selector,
            "collision_policy": self.collision_policy,
        }


@dataclass(frozen=True, slots=True)
class CsvGroupTotalsParameters:
    layout: CsvLayout
    predicate: CsvPredicate

    def __post_init__(self) -> None:
        _require_member(
            self.layout,
            frozenset(
                {
                    "category-amount-enabled",
                    "enabled-category-amount",
                    "amount-enabled-category",
                    "category-enabled-amount",
                }
            ),
            "layout",
        )
        _require_member(
            self.predicate,
            frozenset(
                {
                    "all-valid",
                    "enabled-yes",
                    "positive-amount",
                    "nonempty-category",
                    "enabled-and-positive",
                }
            ),
            "predicate",
        )

    def to_record(self) -> dict[str, str]:
        return {"parameter_type": "csv-group-totals", "layout": self.layout, "predicate": self.predicate}


@dataclass(frozen=True, slots=True)
class ChecksumManifestParameters:
    layout: ChecksumLayout
    policy: ChecksumPolicy

    def __post_init__(self) -> None:
        _require_member(
            self.layout,
            frozenset({"json-object-lines", "json-array-lines", "rfc4180-csv", "nul-triplets"}),
            "layout",
        )
        _require_member(
            self.policy,
            frozenset(
                {
                    "digest-only",
                    "mode-only",
                    "digest-and-mode",
                    "readable-digest-and-mode",
                    "strict-kind-digest-and-mode",
                }
            ),
            "policy",
        )

    def to_record(self) -> dict[str, str]:
        return {"parameter_type": "checksum-manifest", "layout": self.layout, "policy": self.policy}


@dataclass(frozen=True, slots=True)
class PathSuffixInventoryParameters:
    suffix: PathSuffix
    maximum_depth: PathDepth

    def __post_init__(self) -> None:
        _require_member(self.suffix, frozenset({".txt", ".jsonl", ".log", ".csv"}), "suffix")
        if isinstance(self.maximum_depth, bool):
            raise ValueError("maximum_depth is not a supported closed-contract value")
        _require_member(self.maximum_depth, frozenset({1, 2, 3, 4, "unbounded"}), "maximum_depth")

    def to_record(self) -> dict[str, str | int]:
        return {
            "parameter_type": "path-suffix-inventory",
            "suffix": self.suffix,
            "maximum_depth": self.maximum_depth,
        }


@dataclass(frozen=True, slots=True)
class LineTransformMirrorParameters:
    suffix: PathSuffix
    transform: LineTransform

    def __post_init__(self) -> None:
        _require_member(
            self.suffix,
            frozenset({".txt", ".jsonl", ".log", ".csv"}),
            "suffix",
        )
        _require_member(
            self.transform,
            frozenset(
                {
                    "identity",
                    "ascii-lower",
                    "ascii-upper",
                    "tabs-to-four-spaces",
                    "delete-carriage-returns",
                }
            ),
            "transform",
        )

    def to_record(self) -> dict[str, str]:
        return {
            "parameter_type": "line-transform-mirror",
            "suffix": self.suffix,
            "transform": self.transform,
        }


@dataclass(frozen=True, slots=True)
class ModeNormalizedMirrorParameters:
    selector: ModeMirrorSelector
    normalization: ModeNormalization

    def __post_init__(self) -> None:
        _require_member(
            self.selector,
            frozenset(
                {
                    "all-readable",
                    "txt-suffix",
                    "any-executable",
                    "owner-writable",
                }
            ),
            "selector",
        )
        _require_member(
            self.normalization,
            frozenset(
                {
                    "fixed-0644",
                    "fixed-0600",
                    "fixed-0444",
                    "preserve-exec",
                    "fold-class-bits-to-owner",
                }
            ),
            "normalization",
        )

    def to_record(self) -> dict[str, str]:
        return {
            "parameter_type": "mode-normalized-mirror",
            "selector": self.selector,
            "normalization": self.normalization,
        }


@dataclass(frozen=True, slots=True)
class JsonlKeyedInnerJoinParameters:
    key: JoinKey
    duplicate_policy: JoinDuplicatePolicy

    def __post_init__(self) -> None:
        _require_member(self.key, frozenset({"id", "key", "name", "slug"}), "key")
        _require_member(
            self.duplicate_policy,
            frozenset(
                {
                    "cartesian",
                    "first-left",
                    "last-left",
                    "first-right",
                    "last-right",
                }
            ),
            "duplicate_policy",
        )

    def to_record(self) -> dict[str, str]:
        return {
            "parameter_type": "jsonl-keyed-inner-join",
            "key": self.key,
            "duplicate_policy": self.duplicate_policy,
        }


@dataclass(frozen=True, slots=True)
class UstarSafeExtractParameters:
    selector: UstarSelector
    conflict_policy: UstarConflictPolicy

    def __post_init__(self) -> None:
        _require_member(
            self.selector,
            frozenset(
                {
                    "all-regular",
                    "txt-suffix",
                    "jsonl-suffix",
                    "nonempty-regular",
                }
            ),
            "selector",
        )
        _require_member(
            self.conflict_policy,
            frozenset(
                {
                    "reject-duplicates",
                    "first-entry",
                    "last-entry",
                    "identical-only",
                    "smallest-sha256",
                }
            ),
            "conflict_policy",
        )

    def to_record(self) -> dict[str, str]:
        return {
            "parameter_type": "ustar-safe-extract",
            "selector": self.selector,
            "conflict_policy": self.conflict_policy,
        }


@dataclass(frozen=True, slots=True)
class ProcSnapshotReportParameters:
    view: ProcSnapshotView
    predicate: ProcSnapshotPredicate

    def __post_init__(self) -> None:
        _require_member(
            self.view,
            frozenset({"identity", "ownership", "memory", "command"}),
            "view",
        )
        _require_member(
            self.predicate,
            frozenset(
                {
                    "all-valid",
                    "running-only",
                    "non-zombie",
                    "uid-zero",
                    "has-argv",
                }
            ),
            "predicate",
        )

    def to_record(self) -> dict[str, str]:
        return {
            "parameter_type": "proc-snapshot-report",
            "view": self.view,
            "predicate": self.predicate,
        }


TaskParameters: TypeAlias = (
    ActiveJsonlLabelsParameters
    | ManifestCopyParameters
    | CsvGroupTotalsParameters
    | ChecksumManifestParameters
    | PathSuffixInventoryParameters
    | LineTransformMirrorParameters
    | ModeNormalizedMirrorParameters
    | JsonlKeyedInnerJoinParameters
    | UstarSafeExtractParameters
    | ProcSnapshotReportParameters
)


_FAMILY_SCHEMAS: Final[
    tuple[tuple[str, type[object], str, str, tuple[str, ...]], ...]
] = (
    (
        "active-jsonl-labels",
        ActiveJsonlLabelsParameters,
        "structured-records-tree-v1",
        "utf8-byte-sorted-lines-v1",
        ("find", "jq", "mkdir", "sort"),
    ),
    (
        "manifest-copy",
        ManifestCopyParameters,
        "symlinked-copy-workspace-v1",
        "exact-output-tree-v1",
        ("cp", "jq", "mkdir", "sha256sum"),
    ),
    (
        "csv-group-totals",
        CsvGroupTotalsParameters,
        "structured-csv-tree-v1",
        "rfc4180-group-totals-v1",
        ("awk", "mkdir", "sort"),
    ),
    (
        "checksum-manifest",
        ChecksumManifestParameters,
        "permission-boundary-assets-v1",
        "jsonl-checksum-status-v1",
        ("awk", "jq", "mkdir", "sha256sum", "sort", "stat"),
    ),
    (
        "path-suffix-inventory",
        PathSuffixInventoryParameters,
        "nested-project-tree-v1",
        "utf8-byte-sorted-paths-v1",
        ("find", "mkdir", "sort"),
    ),
    (
        "line-transform-mirror",
        LineTransformMirrorParameters,
        "mixed-byte-text-tree-v1",
        "exact-transformed-mirror-v1",
        ("cp", "find", "mkdir", "sed", "tr"),
    ),
    (
        "mode-normalized-mirror",
        ModeNormalizedMirrorParameters,
        "mixed-mode-source-tree-v1",
        "exact-mode-normalized-mirror-v1",
        ("chmod", "cp", "find", "mkdir", "stat"),
    ),
    (
        "jsonl-keyed-inner-join",
        JsonlKeyedInnerJoinParameters,
        "paired-jsonl-records-v1",
        "ordered-jsonl-inner-join-v1",
        ("jq", "mkdir", "sort"),
    ),
    (
        "ustar-safe-extract",
        UstarSafeExtractParameters,
        "ustar-archive-workspace-v1",
        "exact-safe-extraction-tree-v1",
        ("mkdir", "od", "sha256sum", "tar"),
    ),
    (
        "proc-snapshot-report",
        ProcSnapshotReportParameters,
        "synthetic-proc-snapshot-v1",
        "pid-ordered-process-report-v1",
        ("awk", "jq", "mkdir", "sort"),
    ),
)


def parameter_record(value: TaskParameters) -> dict[str, str | int]:
    if type(value) not in {
        ActiveJsonlLabelsParameters,
        ManifestCopyParameters,
        CsvGroupTotalsParameters,
        ChecksumManifestParameters,
        PathSuffixInventoryParameters,
        LineTransformMirrorParameters,
        ModeNormalizedMirrorParameters,
        JsonlKeyedInnerJoinParameters,
        UstarSafeExtractParameters,
        ProcSnapshotReportParameters,
    }:
        raise TypeError("parameters must be one of the closed frozen parameter dataclasses")
    # Frozen dataclasses can still be mutated through low-level deserialization
    # or ``object.__setattr__``.  Re-run the closed-value checks at every trust
    # boundary instead of relying on construction-time validation alone.
    value.__post_init__()
    return value.to_record()


def _validate_graph_contract(graph: object) -> NormalizedSemanticGraph:
    if type(graph) is not NormalizedSemanticGraph:
        raise ValueError("graph must be an exact NormalizedSemanticGraph")
    if type(graph.nodes) is not tuple or not graph.nodes:
        raise ValueError("graph.nodes must be a nonempty exact tuple")
    if type(graph.dependencies) is not tuple:
        raise ValueError("graph.dependencies must be an exact tuple")
    for node in graph.nodes:
        if type(node) is not OperatorNode:
            raise ValueError("graph nodes must be exact OperatorNode values")
        if not isinstance(node.name, str) or not node.name or "\0" in node.name:
            raise ValueError("graph node names must be nonempty NUL-free strings")
        if type(node.parameters) is not tuple or any(
            type(parameter) is not str for parameter in node.parameters
        ):
            raise ValueError("graph node parameters must be an exact tuple of strings")
    size = len(graph.nodes)
    for edge in graph.dependencies:
        if (
            type(edge) is not tuple
            or len(edge) != 2
            or any(type(index) is not int for index in edge)
        ):
            raise ValueError("graph dependencies must be exact integer-pair tuples")
        source, target = edge
        if source < 0 or target >= size or source >= target:
            raise ValueError("graph dependency is outside canonical forward order")
    return graph


def _validate_family_schema(
    *,
    family_id: FamilyId,
    family_version: str,
    parameters: TaskParameters,
    filesystem_identity: FilesystemIdentity,
    output_identity: OutputIdentity,
    allowed_tools: tuple[str, ...],
) -> None:
    schema = next(
        schema for schema in _FAMILY_SCHEMAS if schema[0] == family_id
    )
    (
        _family_id,
        expected_parameters,
        expected_filesystem,
        expected_output,
        expected_tools,
    ) = schema
    if family_version != EXECUTABLE_STATIC_FAMILY_VERSION:
        raise ValueError("family_version is outside the closed family schema")
    if type(parameters) is not expected_parameters:
        raise ValueError("parameters do not match the closed family schema")
    if filesystem_identity != expected_filesystem:
        raise ValueError("filesystem_identity does not match the closed family schema")
    if output_identity != expected_output:
        raise ValueError("output_identity does not match the closed family schema")
    if allowed_tools != expected_tools:
        raise ValueError("allowed_tools do not match the closed family schema")


@dataclass(frozen=True, slots=True)
class OpaqueFixtureDescriptor:
    """Candidate-safe identity with no case, path, seed, or answer data."""

    fixture_id: str
    fixture_sha256: str
    task_contract_sha256: str
    schema_version: str = EXECUTABLE_STATIC_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not str
            or self.schema_version != EXECUTABLE_STATIC_SCHEMA_VERSION
        ):
            raise ValueError("fixture schema_version is unsupported")
        if (
            type(self.fixture_id) is not str
            or _FIXTURE_ID_RE.fullmatch(self.fixture_id) is None
        ):
            raise ValueError("fixture_id is not an opaque fixture identity")
        if (
            type(self.fixture_sha256) is not str
            or _SHA256_RE.fullmatch(self.fixture_sha256) is None
        ):
            raise ValueError("fixture_sha256 must be lowercase SHA-256")
        if self.fixture_id != f"fx-{self.fixture_sha256[:24]}":
            raise ValueError("fixture_id is not derived from fixture_sha256")
        if (
            type(self.task_contract_sha256) is not str
            or _SHA256_RE.fullmatch(self.task_contract_sha256) is None
        ):
            raise ValueError("task_contract_sha256 must be lowercase SHA-256")

    def to_public_record(self) -> dict[str, str]:
        self.__post_init__()
        return {
            "schema_version": self.schema_version,
            "fixture_id": self.fixture_id,
            "fixture_sha256": self.fixture_sha256,
            "task_contract_sha256": self.task_contract_sha256,
        }


def task_semantic_core(
    *,
    family_id: FamilyId,
    family_version: str,
    parameters: TaskParameters,
    prompt: str,
    graph: NormalizedSemanticGraph,
    filesystem_identity: FilesystemIdentity,
    output_identity: OutputIdentity,
    allowed_tools: tuple[str, ...],
) -> dict[str, object]:
    """Return every semantic field used for the task identity.

    No ordinal, random seed, task ID, or fixture identity is accepted here, so
    callers cannot make otherwise identical tasks unique with an ID salt.
    """

    if type(family_id) is not str:
        raise ValueError("family_id must be exact text")
    _require_member(family_id, _FAMILY_IDS, "family_id")
    if type(family_version) is not str or re.fullmatch(r"[1-9][0-9]*\.[0-9]+\.[0-9]+", family_version) is None:
        raise ValueError("family_version must be a positive semantic version")
    if type(prompt) is not str or not prompt.strip() or "\0" in prompt:
        raise ValueError("prompt must be nonempty NUL-free text")
    _validate_graph_contract(graph)
    if type(filesystem_identity) is not str or type(output_identity) is not str:
        raise ValueError("filesystem and output identities must be exact text")
    _require_member(filesystem_identity, _FILESYSTEM_IDENTITIES, "filesystem_identity")
    _require_member(output_identity, _OUTPUT_IDENTITIES, "output_identity")
    if (
        type(allowed_tools) is not tuple
        or not allowed_tools
        or tuple(sorted(set(allowed_tools))) != allowed_tools
        or any(type(tool) is not str or _TOOL_RE.fullmatch(tool) is None for tool in allowed_tools)
    ):
        raise ValueError("allowed_tools must be a nonempty sorted tuple of unique tool identities")
    _validate_family_schema(
        family_id=family_id,
        family_version=family_version,
        parameters=parameters,
        filesystem_identity=filesystem_identity,
        output_identity=output_identity,
        allowed_tools=allowed_tools,
    )
    return {
        "schema_version": EXECUTABLE_STATIC_SCHEMA_VERSION,
        "contract_version": EXECUTABLE_STATIC_CONTRACT_VERSION,
        "split_role": METHOD_DEVELOPMENT_SPLIT,
        "family_id": family_id,
        "family_version": family_version,
        "parameters": parameter_record(parameters),
        "prompt": prompt,
        "graph": graph.to_record(),
        "graph_sha256": graph.hash,
        "filesystem_identity": filesystem_identity,
        "output_identity": output_identity,
        "allowed_tools": list(allowed_tools),
        "public": True,
        "sealed": False,
        "claim_authorized": False,
    }


def compute_task_contract_sha256(
    *,
    family_id: FamilyId,
    family_version: str,
    parameters: TaskParameters,
    prompt: str,
    graph: NormalizedSemanticGraph,
    filesystem_identity: FilesystemIdentity,
    output_identity: OutputIdentity,
    allowed_tools: tuple[str, ...],
) -> str:
    return domain_sha256(
        "cbds.executable-static.task-contract.v1",
        task_semantic_core(
            family_id=family_id,
            family_version=family_version,
            parameters=parameters,
            prompt=prompt,
            graph=graph,
            filesystem_identity=filesystem_identity,
            output_identity=output_identity,
            allowed_tools=allowed_tools,
        ),
    )


def task_id_from_contract(contract_sha256: str) -> str:
    if (
        type(contract_sha256) is not str
        or _SHA256_RE.fullmatch(contract_sha256) is None
    ):
        raise ValueError("contract_sha256 must be lowercase SHA-256")
    return f"mds-{contract_sha256[:24]}"


@dataclass(frozen=True, slots=True)
class ExecutableStaticTask:
    task_id: str
    family_id: FamilyId
    family_version: str
    parameters: TaskParameters
    prompt: str
    graph: NormalizedSemanticGraph
    filesystem_identity: FilesystemIdentity
    output_identity: OutputIdentity
    allowed_tools: tuple[str, ...]
    fixtures: tuple[OpaqueFixtureDescriptor, ...]
    task_contract_sha256: str
    split_role: str = METHOD_DEVELOPMENT_SPLIT
    public: bool = True
    sealed: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        if type(self.split_role) is not str or self.split_role != METHOD_DEVELOPMENT_SPLIT:
            raise ValueError("tasks are restricted to public method development")
        if self.public is not True or self.sealed is not False or self.claim_authorized is not False:
            raise ValueError("task claim boundary is invalid")
        expected = compute_task_contract_sha256(
            family_id=self.family_id,
            family_version=self.family_version,
            parameters=self.parameters,
            prompt=self.prompt,
            graph=self.graph,
            filesystem_identity=self.filesystem_identity,
            output_identity=self.output_identity,
            allowed_tools=self.allowed_tools,
        )
        if (
            type(self.task_contract_sha256) is not str
            or _SHA256_RE.fullmatch(self.task_contract_sha256) is None
            or self.task_contract_sha256 != expected
        ):
            raise ValueError("task_contract_sha256 does not match semantic task content")
        if (
            type(self.task_id) is not str
            or _TASK_ID_RE.fullmatch(self.task_id) is None
            or self.task_id != task_id_from_contract(expected)
        ):
            raise ValueError("task_id is not derived from the semantic task contract")
        if type(self.fixtures) is not tuple or any(
            type(item) is not OpaqueFixtureDescriptor for item in self.fixtures
        ):
            raise ValueError("fixtures must be an exact tuple of opaque fixture descriptors")
        for item in self.fixtures:
            item.__post_init__()
        if len(self.fixtures) != 5 or len({item.fixture_id for item in self.fixtures}) != 5:
            raise ValueError("each task must have exactly five unique opaque fixtures")
        if any(item.task_contract_sha256 != expected for item in self.fixtures):
            raise ValueError("fixture descriptor is bound to a different task contract")

    @property
    def graph_sha256(self) -> str:
        return self.graph.hash

    def to_public_record(self) -> dict[str, object]:
        self.__post_init__()
        core = task_semantic_core(
            family_id=self.family_id,
            family_version=self.family_version,
            parameters=self.parameters,
            prompt=self.prompt,
            graph=self.graph,
            filesystem_identity=self.filesystem_identity,
            output_identity=self.output_identity,
            allowed_tools=self.allowed_tools,
        )
        return {
            **core,
            "task_id": self.task_id,
            "task_contract_sha256": self.task_contract_sha256,
            "fixtures": [item.to_public_record() for item in self.fixtures],
        }


def _validate_task_tuple(
    tasks: object,
) -> tuple[ExecutableStaticTask, ...]:
    if type(tasks) is not tuple or any(
        type(task) is not ExecutableStaticTask for task in tasks
    ):
        raise ValueError("tasks must be an exact tuple of ExecutableStaticTask values")
    for task in tasks:
        task.__post_init__()
    return tasks


def compute_executable_static_registry_sha256(
    tasks: tuple[ExecutableStaticTask, ...],
) -> str:
    """Compute the registry identity without depending on the builder module."""

    selected_tasks = _validate_task_tuple(tasks)
    family_ids = sorted({task.family_id for task in selected_tasks})
    family_records: list[dict[str, object]] = []
    for family_id in family_ids:
        selected = tuple(
            task for task in selected_tasks if task.family_id == family_id
        )
        family_records.append(
            {
                "family_id": family_id,
                "family_version": EXECUTABLE_STATIC_FAMILY_VERSION,
                "task_count": len(selected),
                "parameter_grid": [
                    parameter_record(task.parameters) for task in selected
                ],
                "task_contract_sha256": [
                    task.task_contract_sha256 for task in selected
                ],
            }
        )
    return domain_sha256(
        "cbds.executable-static.registry.v1",
        {
            "registry_version": EXECUTABLE_STATIC_REGISTRY_VERSION,
            "suite_id": EXECUTABLE_STATIC_SUITE_ID,
            "families": family_records,
            "fixture_profile_sha256": list(
                EXECUTABLE_STATIC_FIXTURE_PROFILE_SHA256
            ),
        },
    )


def compute_executable_static_suite_sha256(
    tasks: tuple[ExecutableStaticTask, ...], registry_sha256: str
) -> str:
    """Compute the suite identity without depending on the builder module."""

    selected_tasks = _validate_task_tuple(tasks)
    if type(registry_sha256) is not str or _SHA256_RE.fullmatch(registry_sha256) is None:
        raise ValueError("registry_sha256 must be lowercase SHA-256")
    return domain_sha256(
        "cbds.executable-static.suite.v1",
        {
            "suite_id": EXECUTABLE_STATIC_SUITE_ID,
            "registry_sha256": registry_sha256,
            "tasks": [task.to_public_record() for task in selected_tasks],
        },
    )


@dataclass(frozen=True, slots=True)
class ExecutableStaticRegistry:
    tasks: tuple[ExecutableStaticTask, ...]
    registry_sha256: str
    suite_sha256: str
    schema_version: str = EXECUTABLE_STATIC_SCHEMA_VERSION
    split_role: str = METHOD_DEVELOPMENT_SPLIT
    public: bool = True
    sealed: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        if type(self.schema_version) is not str or self.schema_version != EXECUTABLE_STATIC_SCHEMA_VERSION:
            raise ValueError("registry schema_version is unsupported")
        if type(self.split_role) is not str or self.split_role != METHOD_DEVELOPMENT_SPLIT:
            raise ValueError("registry split_role is invalid")
        if self.public is not True or self.sealed is not False or self.claim_authorized is not False:
            raise ValueError("registry claim boundary is invalid")
        _validate_task_tuple(self.tasks)
        if len(self.tasks) != 100:
            raise ValueError("bounded registry must contain exactly 100 tasks")
        if len({task.task_id for task in self.tasks}) != 100:
            raise ValueError("registry task IDs are not unique")
        if len({task.graph_sha256 for task in self.tasks}) != 100:
            raise ValueError("registry semantic graph hashes are not unique")
        if (
            type(self.registry_sha256) is not str
            or type(self.suite_sha256) is not str
            or _SHA256_RE.fullmatch(self.registry_sha256) is None
            or _SHA256_RE.fullmatch(self.suite_sha256) is None
        ):
            raise ValueError("registry identities must be lowercase SHA-256")
        expected_registry = compute_executable_static_registry_sha256(self.tasks)
        if self.registry_sha256 != expected_registry:
            raise ValueError("registry_sha256 does not match registry content")
        expected_suite = compute_executable_static_suite_sha256(
            self.tasks, expected_registry
        )
        if self.suite_sha256 != expected_suite:
            raise ValueError("suite_sha256 does not match suite content")

    def to_public_projection(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "schema_version": self.schema_version,
            "split_role": self.split_role,
            "public": self.public,
            "sealed": self.sealed,
            "claim_authorized": self.claim_authorized,
            "task_count": len(self.tasks),
            "fixtures_per_task": 5,
            "fixture_count": sum(len(task.fixtures) for task in self.tasks),
            "registry_sha256": self.registry_sha256,
            "suite_sha256": self.suite_sha256,
            "tasks": [task.to_public_record() for task in self.tasks],
        }


__all__ = [
    "ActiveLabelKey",
    "ActivePredicate",
    "ActiveJsonlLabelsParameters",
    "ChecksumLayout",
    "ChecksumManifestParameters",
    "ChecksumPolicy",
    "CollisionPolicy",
    "CopySelector",
    "CsvLayout",
    "CsvGroupTotalsParameters",
    "CsvPredicate",
    "EXECUTABLE_STATIC_CONTRACT_VERSION",
    "EXECUTABLE_STATIC_FAMILY_VERSION",
    "EXECUTABLE_STATIC_FIXTURE_PROFILE_SHA256",
    "EXECUTABLE_STATIC_REGISTRY_VERSION",
    "EXECUTABLE_STATIC_SCHEMA_VERSION",
    "EXECUTABLE_STATIC_SUITE_ID",
    "ExecutableStaticRegistry",
    "ExecutableStaticTask",
    "FamilyId",
    "FilesystemIdentity",
    "LineTransform",
    "LineTransformMirrorParameters",
    "JoinDuplicatePolicy",
    "JoinKey",
    "JsonlKeyedInnerJoinParameters",
    "ManifestCopyParameters",
    "METHOD_DEVELOPMENT_SPLIT",
    "ModeMirrorSelector",
    "ModeNormalization",
    "ModeNormalizedMirrorParameters",
    "OpaqueFixtureDescriptor",
    "OutputIdentity",
    "PathDepth",
    "PathSuffix",
    "PathSuffixInventoryParameters",
    "ProcSnapshotPredicate",
    "ProcSnapshotReportParameters",
    "ProcSnapshotView",
    "TaskParameters",
    "UstarConflictPolicy",
    "UstarSafeExtractParameters",
    "UstarSelector",
    "canonical_json_bytes",
    "compute_executable_static_registry_sha256",
    "compute_executable_static_suite_sha256",
    "compute_task_contract_sha256",
    "domain_sha256",
    "parameter_record",
    "task_id_from_contract",
    "task_semantic_core",
]
