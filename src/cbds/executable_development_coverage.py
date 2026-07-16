"""Content-addressed coverage lock for the 500-task development slice.

This module separates already integrated executable families from concrete
planned families.  It binds the former to the live task registries and gives
the latter distinct parameter grids and capability contracts.  The checked
record is public method-development metadata only: it is unsealed, unscored,
and grants no execution, model-selection, evaluation, or claim authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
from typing import Final

from .evaluation_specs import FROZEN_BASH_NATIVE_EXECUTABLES
from .manifests import ManifestValidationError, canonical_json_bytes


COVERAGE_SCHEMA_VERSION: Final[str] = "1.0.0"
COVERAGE_VERSION: Final[str] = "1.0.0"
COVERAGE_SUITE_ID: Final[str] = "cbds-executable-method-development-v1"
COVERAGE_CONFIG_RELATIVE_PATH: Final[str] = (
    "configs/executable-method-development-coverage-v1.json"
)
MAXIMUM_COVERAGE_CONFIG_BYTES: Final[int] = 256 * 1024
FAMILY_COUNT: Final[int] = 25
TASKS_PER_FAMILY: Final[int] = 20
TOTAL_TASK_COUNT: Final[int] = 500
INTEGRATED_FAMILY_COUNT: Final[int] = 15
INTEGRATED_TASK_COUNT: Final[int] = 300
PLANNED_FAMILY_COUNT: Final[int] = 10
PLANNED_TASK_COUNT: Final[int] = 200

CANONICAL_FAMILY_ORDER: Final[tuple[str, ...]] = (
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
    "compound-path-query",
    "regex-log-group-aggregation",
    "reproducible-ustar-pack",
    "pipefail-atomic-report",
    "bounded-retry-state-machine",
    "case-routed-batch-transform",
    "collision-safe-batch-rename",
    "hardlink-deduplicated-mirror",
    "compressed-archive-roundtrip-verify",
    "checksum-repair-plan",
    "jsonl-csv-enrichment-compose",
    "nested-json-schema-migration",
    "dependency-dag-execution-plan",
    "process-lifecycle-delta",
    "symlink-aware-tree-reconcile",
)

_FIRST_REGISTRY_SHA256: Final[str] = (
    "ada6043b345e48f69ad602581030aab1bafcb3ff9dc453f9d02342faaf6a7f9a"
)
_FIRST_SUITE_SHA256: Final[str] = (
    "eb64bb4cdb60ab8e0e228f688cf54810fae2ef56768e8b34ac039bdc1aec42ae"
)
_SECOND_REGISTRY_SHA256: Final[str] = (
    "27e4721036c4870fec463e880cb3a36fcd72ebe530368cb45179f600ee694ab4"
)
_SECOND_SUITE_SHA256: Final[str] = (
    "0020c1e5c7907d979d7fa97dead79f199fff59d97184c33fae81bc98df3ef8fb"
)
_THIRD_REGISTRY_SHA256: Final[str] = (
    "66a9ef43a6387f5f94f511aec3357f0e625427d161a0c6da0d9590a837761237"
)
_THIRD_SUITE_SHA256: Final[str] = (
    "3a578668805bbdfdfaf3400483640bb29504591604ed1c9c28cf8f9bb0362fb3"
)
_FOURTH_REGISTRY_SHA256: Final[str] = (
    "3dc5512139361a275afaf0b57b94528961615f9b4eee22ee6c333cc7d8bf4ea5"
)
_FOURTH_SUITE_SHA256: Final[str] = (
    "668ab9c942888d568c80aaa27bee340ad8a10faf3493a6983bf068d79b134651"
)
_FIFTH_REGISTRY_SHA256: Final[str] = (
    "d562d462814b7fc6413e0e085d16f66def28157c1a6361adf28cd3d42eb5f88c"
)
_FIFTH_SUITE_SHA256: Final[str] = (
    "27ea8064a72453a4e7a4bc52b125a924139088cd1c20d417a867aa9ddda96e00"
)
_SIXTH_REGISTRY_SHA256: Final[str] = (
    "14280b3cbc8a96c919a57a325b5795c381cba86b2a31934f7069821b7ff4e3c4"
)
_SIXTH_SUITE_SHA256: Final[str] = (
    "db6d00278664f5a72834ebf0297411564da8b98a75d08eb2c2e9cf706dc985b1"
)

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_ID_RE: Final[re.Pattern[str]] = re.compile(r"[a-z0-9][a-z0-9-]{2,95}\Z")
_AXIS_RE: Final[re.Pattern[str]] = re.compile(r"[a-z][a-z0-9_]{1,63}\Z")
_TOOL_RE: Final[re.Pattern[str]] = re.compile(r"[a-z0-9][a-z0-9._+-]{0,63}\Z")
_FAMILY_KEYS: Final[frozenset[str]] = frozenset(
    {
        "family_id",
        "lifecycle_state",
        "task_count",
        "parameter_axes",
        "solution_track",
        "allowed_tools",
        "filesystem_schema",
        "output_contract",
        "capability_tags",
        "integrated_task_set_sha256",
        "family_sha256",
    }
)
_AXIS_KEYS: Final[frozenset[str]] = frozenset({"axis_name", "values"})
_SOURCE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "tranche_id",
        "added_task_count",
        "cumulative_task_count",
        "registry_sha256",
        "cumulative_suite_sha256",
    }
)
_ROOT_KEYS: Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "coverage_version",
        "record_type",
        "suite_id",
        "family_count",
        "tasks_per_family",
        "total_task_count",
        "integrated_family_count",
        "integrated_task_count",
        "planned_family_count",
        "planned_task_count",
        "canonical_family_order",
        "source_registry_commitments",
        "families",
        "coverage_sha256",
        "public_method_development",
        "sealed",
        "scored",
        "candidate_execution_authorized",
        "scored_evaluation_authorized",
        "model_selection_eligible",
        "claim_authorized",
        "independent_human_review_attested",
    }
)


class ExecutableDevelopmentCoverageError(ValueError):
    """Raised when the development coverage lock is not exact."""


AxisValue = str | int


@dataclass(frozen=True, slots=True)
class CoverageParameterAxis:
    axis_name: str
    values: tuple[AxisValue, ...]

    def __post_init__(self) -> None:
        _validate_axis(self)

    def to_record(self) -> dict[str, object]:
        _validate_axis(self)
        return {"axis_name": self.axis_name, "values": list(self.values)}


@dataclass(frozen=True, slots=True)
class CoverageFamily:
    family_id: str
    lifecycle_state: str
    task_count: int
    parameter_axes: tuple[CoverageParameterAxis, CoverageParameterAxis]
    solution_track: str
    allowed_tools: tuple[str, ...]
    filesystem_schema: str
    output_contract: str
    capability_tags: tuple[str, ...]
    integrated_task_set_sha256: str | None
    family_sha256: str

    def __post_init__(self) -> None:
        _validate_family(self)

    def to_record(self) -> dict[str, object]:
        _validate_family(self)
        return _family_record(self)


@dataclass(frozen=True, slots=True)
class SourceRegistryCommitment:
    tranche_id: str
    added_task_count: int
    cumulative_task_count: int
    registry_sha256: str
    cumulative_suite_sha256: str

    def __post_init__(self) -> None:
        _validate_source(self)

    def to_record(self) -> dict[str, object]:
        _validate_source(self)
        return {
            "tranche_id": self.tranche_id,
            "added_task_count": self.added_task_count,
            "cumulative_task_count": self.cumulative_task_count,
            "registry_sha256": self.registry_sha256,
            "cumulative_suite_sha256": self.cumulative_suite_sha256,
        }


@dataclass(frozen=True, slots=True)
class ExecutableDevelopmentCoverage:
    families: tuple[CoverageFamily, ...]
    source_registry_commitments: tuple[SourceRegistryCommitment, ...]
    coverage_sha256: str
    schema_version: str = COVERAGE_SCHEMA_VERSION
    coverage_version: str = COVERAGE_VERSION
    suite_id: str = COVERAGE_SUITE_ID
    public_method_development: bool = True
    sealed: bool = False
    scored: bool = False
    candidate_execution_authorized: bool = False
    scored_evaluation_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False
    independent_human_review_attested: bool = False

    def __post_init__(self) -> None:
        validate_executable_development_coverage(self)

    def to_hash_only_record(self) -> dict[str, object]:
        validate_executable_development_coverage(self)
        return _coverage_record(self)


@dataclass(frozen=True, slots=True)
class _FamilySpec:
    family_id: str
    lifecycle_state: str
    parameter_axes: tuple[CoverageParameterAxis, CoverageParameterAxis]
    solution_track: str
    allowed_tools: tuple[str, ...]
    filesystem_schema: str
    output_contract: str
    capability_tags: tuple[str, ...]


def _axis(name: str, values: tuple[AxisValue, ...]) -> CoverageParameterAxis:
    # Static declarations are assembled before the validation helpers below
    # are defined.  Every declaration is validated when the public coverage
    # object is built; bypassing __init__ here avoids import-order side effects.
    axis = CoverageParameterAxis.__new__(CoverageParameterAxis)
    object.__setattr__(axis, "axis_name", name)
    object.__setattr__(axis, "values", values)
    return axis


def _spec(
    family_id: str,
    lifecycle_state: str,
    axis_one: CoverageParameterAxis,
    axis_two: CoverageParameterAxis,
    solution_track: str,
    allowed_tools: tuple[str, ...],
    filesystem_schema: str,
    output_contract: str,
    capability_tags: tuple[str, ...],
) -> _FamilySpec:
    return _FamilySpec(
        family_id,
        lifecycle_state,
        (axis_one, axis_two),
        solution_track,
        allowed_tools,
        filesystem_schema,
        output_contract,
        capability_tags,
    )


_FAMILY_SPECS: Final[tuple[_FamilySpec, ...]] = (
    _spec("active-jsonl-labels", "integrated", _axis("label_key", ("label", "name", "tag", "title")), _axis("predicate", ("active-true", "enabled-yes", "state-ready", "score-at-least-10", "deleted-false")), "bash-native", ("find", "jq", "mkdir", "sort"), "structured-records-tree-v1", "utf8-byte-sorted-lines-v1", ("json", "recursive-search", "text-deduplication", "utf8-sorting")),
    _spec("manifest-copy", "integrated", _axis("selector", ("all-readable", "txt-suffix", "selected-true", "declared-sha256-matches")), _axis("collision_policy", ("reject-collision", "first-record", "last-record", "identical-bytes-only", "utf8-smallest-source")), "bash-native", ("cp", "jq", "mkdir", "sha256sum"), "symlinked-copy-workspace-v1", "exact-output-tree-v1", ("checksum-selection", "collision-resolution", "filesystem-copy", "jsonl")),
    _spec("csv-group-totals", "integrated", _axis("layout", ("category-amount-enabled", "enabled-category-amount", "amount-enabled-category", "category-enabled-amount")), _axis("predicate", ("all-valid", "enabled-yes", "positive-amount", "nonempty-category", "enabled-and-positive")), "bash-native", ("awk", "mkdir", "sort"), "structured-csv-tree-v1", "rfc4180-group-totals-v1", ("aggregation", "csv", "numeric-processing", "structured-output")),
    _spec("checksum-manifest", "integrated", _axis("layout", ("json-object-lines", "json-array-lines", "rfc4180-csv", "nul-triplets")), _axis("policy", ("digest-only", "mode-only", "digest-and-mode", "readable-digest-and-mode", "strict-kind-digest-and-mode")), "bash-native", ("awk", "jq", "mkdir", "sha256sum", "sort", "stat"), "permission-boundary-assets-v1", "jsonl-checksum-status-v1", ("checksums", "file-modes", "manifest-parsing", "status-classification")),
    _spec("path-suffix-inventory", "integrated", _axis("suffix", (".txt", ".jsonl", ".log", ".csv")), _axis("maximum_depth", (1, 2, 3, 4, "unbounded")), "bash-native", ("find", "mkdir", "sort"), "nested-project-tree-v1", "utf8-byte-sorted-paths-v1", ("depth-bounds", "path-selection", "recursive-search", "utf8-sorting")),
    _spec("line-transform-mirror", "integrated", _axis("suffix", (".txt", ".jsonl", ".log", ".csv")), _axis("transform", ("identity", "ascii-upper", "ascii-lower", "tabs-to-four-spaces", "delete-carriage-returns")), "bash-native", ("cp", "find", "mkdir", "sed", "tr"), "mixed-byte-text-tree-v1", "exact-transformed-mirror-v1", ("byte-preservation", "recursive-search", "text-transformation", "tree-mirroring")),
    _spec("mode-normalized-mirror", "integrated", _axis("selector", ("all-readable", "txt-suffix", "any-executable", "owner-writable")), _axis("normalization", ("fixed-0644", "fixed-0600", "fixed-0444", "preserve-exec", "fold-class-bits-to-owner")), "bash-native", ("chmod", "cp", "find", "mkdir", "stat"), "mixed-mode-source-tree-v1", "exact-mode-normalized-mirror-v1", ("file-modes", "permission-normalization", "recursive-search", "tree-mirroring")),
    _spec("jsonl-keyed-inner-join", "integrated", _axis("key", ("id", "key", "name", "slug")), _axis("duplicate_policy", ("cartesian", "first-left", "last-left", "first-right", "last-right")), "bash-native", ("jq", "mkdir", "sort"), "paired-jsonl-records-v1", "ordered-jsonl-inner-join-v1", ("duplicate-resolution", "joins", "jsonl", "structured-output")),
    _spec("ustar-safe-extract", "integrated", _axis("selector", ("all-regular", "txt-suffix", "jsonl-suffix", "nonempty-regular")), _axis("conflict_policy", ("reject-duplicates", "first-entry", "last-entry", "identical-only", "smallest-sha256")), "bash-native", ("mkdir", "od", "sha256sum", "tar"), "ustar-archive-workspace-v1", "exact-safe-extraction-tree-v1", ("archive-extraction", "path-safety", "ustar", "verification")),
    _spec("proc-snapshot-report", "integrated", _axis("view", ("identity", "ownership", "memory", "command")), _axis("predicate", ("all-valid", "running-only", "non-zombie", "uid-zero", "has-argv")), "bash-native", ("awk", "jq", "mkdir", "sort"), "synthetic-proc-snapshot-v1", "pid-ordered-process-report-v1", ("process-state", "structured-output", "synthetic-proc", "unix-concepts")),
    _spec("compound-path-query", "integrated", _axis("name_pattern", ("*.txt", "report-*", "[a-z]*.log", "*.[0-9]")), _axis("expression", ("readable-regular-and-name", "readable-regular-and-not-name", "readable-regular-and-name-or-symlink", "readable-regular-and-name-or-executable", "readable-regular-and-name-depth-at-most-three")), "bash-native", ("find", "mkdir", "sort"), "compound-query-tree-v1", "utf8-byte-sorted-compound-paths-v1", ("boolean-expressions", "find-semantics", "path-selection", "symlinks")),
    _spec("regex-log-group-aggregation", "integrated", _axis("severity_ere", ("^ERROR$", "^(WARN|ERROR)$", "^[A-Z]{4}$", "^(INFO|WARN|ERROR)$")), _axis("malformed_policy", ("skip-row", "stop-file", "reject-file", "reject-all", "count-malformed")), "bash-native", ("awk", "chmod", "find", "grep", "mkdir", "sort"), "recursive-tsv-log-tree-v1", "byte-sorted-group-count-sum-v1", ("aggregation", "error-policy", "regex", "text-processing")),
    _spec("reproducible-ustar-pack", "integrated", _axis("selector", ("all-mode-readable", "txt-suffix-mode-readable", "nonempty-mode-readable", "executable-mode-readable")), _axis("archive_mode_policy", ("preserve-permission-bits", "fixed-0644", "fixed-0600", "normalize-preserve-exec", "fold-class-bits-to-owner")), "bash-native", ("chmod", "find", "mkdir", "sort", "stat", "tar"), "recursive-source-tree-v1", "reproducible-posix-ustar-v1", ("archive-creation", "deterministic-output", "file-modes", "recursive-search")),
    _spec("pipefail-atomic-report", "integrated", _axis("pipeline_shape", ("linear-two-stage", "linear-four-stage", "fan-in-merge", "tee-and-reduce")), _axis("failure_commit_policy", ("commit-success-only", "write-status-always", "rollback-on-any-failure", "preserve-first-failure", "preserve-last-failure")), "bash-native", ("awk", "grep", "mkdir", "mv", "sed", "sort"), "pipeline-record-streams", "atomic-pipeline-status-json", ("atomic-output", "error-handling", "pipeline-status", "text-processing")),
    _spec("bounded-retry-state-machine", "integrated", _axis("transition_model", ("linear", "branching", "cyclic-bounded", "compensating")), _axis("retry_policy", ("never", "fixed-two", "fixed-four", "until-terminal", "retry-transient-only")), "bash-native", ("awk", "mkdir", "sort"), "workflow-event-ledger", "terminal-state-and-attempt-report", ("control-flow", "error-handling", "loops", "state-machines")),
    _spec("case-routed-batch-transform", "planned", _axis("route_key", ("suffix", "record-kind", "leading-byte", "declared-action")), _axis("fallback_policy", ("skip", "copy-verbatim", "reject-batch", "route-default", "emit-error-record")), "bash-native", ("awk", "mkdir", "sed", "sort", "tr"), "routed-text-batch", "route-partitioned-transform-tree", ("branching", "control-flow", "loops", "text-transformation")),
    _spec("collision-safe-batch-rename", "planned", _axis("rename_rule", ("lowercase-basename", "numbered-prefix", "suffix-rewrite", "manifest-mapping")), _axis("collision_policy", ("reject-all", "skip-collisions", "stable-first", "stable-last", "identical-files-coalesce")), "bash-native", ("find", "mkdir", "mv", "sort", "stat"), "rename-candidate-tree", "atomic-renamed-tree-and-ledger", ("atomic-output", "collision-resolution", "filesystem-mutation", "rename")),
    _spec("hardlink-deduplicated-mirror", "planned", _axis("equivalence_key", ("sha256", "size-and-sha256", "mode-and-sha256", "declared-content-id")), _axis("link_policy", ("smallest-path-owner", "first-discovered-owner", "preserve-existing-groups", "regular-files-only", "reject-cross-mode-group")), "bash-native", ("cp", "find", "ln", "mkdir", "sha256sum", "sort", "stat"), "duplicate-content-source-tree", "hardlink-topology-preserving-mirror", ("content-deduplication", "filesystem-mutation", "hard-links", "tree-mirroring")),
    _spec("compressed-archive-roundtrip-verify", "planned", _axis("compression_format", ("gzip", "bzip2", "xz", "none")), _axis("verification_policy", ("archive-digest", "member-digests", "roundtrip-bytes", "roundtrip-bytes-and-modes", "strict-all")), "bash-native", ("bzip2", "gzip", "mkdir", "sha256sum", "sort", "tar", "xz"), "archive-roundtrip-source-tree", "compressed-archive-with-verification-report", ("archive-creation", "checksums", "compression", "roundtrip-verification")),
    _spec("checksum-repair-plan", "planned", _axis("manifest_layout", ("sha256sum-text", "jsonl", "csv", "nul-pairs")), _axis("repair_policy", ("report-only", "replace-digest", "drop-missing", "quarantine-mismatch", "strict-reject")), "bash-native", ("awk", "jq", "mkdir", "sha256sum", "sort"), "damaged-checksum-assets", "ordered-checksum-repair-plan", ("checksums", "error-classification", "repair-planning", "structured-output")),
    _spec("jsonl-csv-enrichment-compose", "planned", _axis("join_layout", ("jsonl-left-csv-right", "csv-left-jsonl-right", "jsonl-both-with-csv-output", "csv-both-with-jsonl-output")), _axis("missing_field_policy", ("drop-row", "empty-string", "null-value", "emit-reject-row", "reject-source-file")), "bash-native", ("awk", "jq", "mkdir", "sort"), "mixed-jsonl-csv-sources", "composed-enriched-jsonl", ("csv", "joins", "jsonl", "multi-stage-composition")),
    _spec("nested-json-schema-migration", "planned", _axis("input_shape", ("single-object", "object-array", "keyed-object-map", "jsonl-objects")), _axis("migration_policy", ("rename-fields", "normalize-types", "lift-nested-members", "drop-deprecated-members", "combined-version-upgrade")), "python-permitted", ("mkdir", "python3", "sort"), "versioned-nested-json-documents", "schema-migrated-json-document-set", ("json", "nested-structures", "python-permitted", "schema-migration")),
    _spec("dependency-dag-execution-plan", "planned", _axis("graph_encoding", ("json-adjacency", "json-edge-list", "csv-edges", "line-oriented-dependencies")), _axis("tie_break_policy", ("utf8-smallest", "declared-priority", "shortest-depth", "largest-fanout", "stable-input-order")), "python-permitted", ("mkdir", "python3"), "dependency-graph-documents", "validated-topological-execution-plan", ("algorithms", "cycle-detection", "graph-processing", "python-permitted")),
    _spec("process-lifecycle-delta", "planned", _axis("snapshot_pair", ("status-only", "status-and-cmdline", "status-and-cgroups", "complete-synthetic-proc")), _axis("selection_policy", ("all-changes", "starts-only", "exits-only", "state-changes", "resource-threshold-crossings")), "bash-native", ("awk", "comm", "jq", "mkdir", "sort"), "paired-process-state-snapshots", "pid-lifecycle-transition-report", ("process-state", "structured-output", "temporal-diff", "unix-concepts")),
    _spec("symlink-aware-tree-reconcile", "planned", _axis("desired_state_format", ("jsonl", "csv", "nul-records", "directory-blueprint")), _axis("reconciliation_policy", ("create-missing", "replace-mismatch", "remove-extra", "preserve-safe-links", "strict-exact-state")), "bash-native", ("chmod", "find", "ln", "mkdir", "mv", "sort", "stat"), "actual-and-desired-filesystem-trees", "reconciled-tree-and-operation-log", ("filesystem-mutation", "state-reconciliation", "symlinks", "tree-operations")),
)


def _unchecked_source(
    tranche_id: str,
    added_task_count: int,
    cumulative_task_count: int,
    registry_sha256: str,
    cumulative_suite_sha256: str,
) -> SourceRegistryCommitment:
    source = SourceRegistryCommitment.__new__(SourceRegistryCommitment)
    object.__setattr__(source, "tranche_id", tranche_id)
    object.__setattr__(source, "added_task_count", added_task_count)
    object.__setattr__(source, "cumulative_task_count", cumulative_task_count)
    object.__setattr__(source, "registry_sha256", registry_sha256)
    object.__setattr__(source, "cumulative_suite_sha256", cumulative_suite_sha256)
    return source


_EXPECTED_SOURCES: Final[tuple[SourceRegistryCommitment, ...]] = (
    _unchecked_source("first-tranche", 100, 100, _FIRST_REGISTRY_SHA256, _FIRST_SUITE_SHA256),
    _unchecked_source("second-tranche", 100, 200, _SECOND_REGISTRY_SHA256, _SECOND_SUITE_SHA256),
    _unchecked_source("third-tranche", 40, 240, _THIRD_REGISTRY_SHA256, _THIRD_SUITE_SHA256),
    _unchecked_source("fourth-tranche", 20, 260, _FOURTH_REGISTRY_SHA256, _FOURTH_SUITE_SHA256),
    _unchecked_source("fifth-tranche", 20, 280, _FIFTH_REGISTRY_SHA256, _FIFTH_SUITE_SHA256),
    _unchecked_source("sixth-tranche", 20, 300, _SIXTH_REGISTRY_SHA256, _SIXTH_SUITE_SHA256),
)


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def _domain_sha256(domain: str, value: object) -> str:
    try:
        payload = canonical_json_bytes(value)
    except (ManifestValidationError, RecursionError, UnicodeEncodeError) as exc:
        raise ExecutableDevelopmentCoverageError("value is not canonical JSON") from exc
    return sha256(domain.encode("ascii") + b"\0" + payload).hexdigest()


def _validate_axis(axis: CoverageParameterAxis) -> None:
    if type(axis) is not CoverageParameterAxis:
        raise ExecutableDevelopmentCoverageError("parameter axis must have its exact type")
    if type(axis.axis_name) is not str or _AXIS_RE.fullmatch(axis.axis_name) is None:
        raise ExecutableDevelopmentCoverageError("parameter axis name is invalid")
    if type(axis.values) is not tuple or len(axis.values) not in {4, 5}:
        raise ExecutableDevelopmentCoverageError("parameter axis must have exactly four or five values")
    for value in axis.values:
        if type(value) not in {str, int} or (type(value) is str and (not value or "\0" in value)):
            raise ExecutableDevelopmentCoverageError("parameter axis value has an invalid exact type")
    if len(set(axis.values)) != len(axis.values):
        raise ExecutableDevelopmentCoverageError("parameter axis values must be unique")


def _family_core_record(family: CoverageFamily) -> dict[str, object]:
    return {
        "family_id": family.family_id,
        "lifecycle_state": family.lifecycle_state,
        "task_count": family.task_count,
        "parameter_axes": [axis.to_record() for axis in family.parameter_axes],
        "solution_track": family.solution_track,
        "allowed_tools": list(family.allowed_tools),
        "filesystem_schema": family.filesystem_schema,
        "output_contract": family.output_contract,
        "capability_tags": list(family.capability_tags),
        "integrated_task_set_sha256": family.integrated_task_set_sha256,
    }


def _family_record(family: CoverageFamily) -> dict[str, object]:
    return {**_family_core_record(family), "family_sha256": family.family_sha256}


def _validate_family(family: CoverageFamily) -> None:
    if type(family) is not CoverageFamily:
        raise ExecutableDevelopmentCoverageError("coverage family must have its exact type")
    if type(family.family_id) is not str or _ID_RE.fullmatch(family.family_id) is None:
        raise ExecutableDevelopmentCoverageError("family identifier is invalid")
    if type(family.lifecycle_state) is not str or family.lifecycle_state not in {"integrated", "planned"}:
        raise ExecutableDevelopmentCoverageError("family lifecycle state is invalid")
    if type(family.task_count) is not int or family.task_count != TASKS_PER_FAMILY:
        raise ExecutableDevelopmentCoverageError("every family must contain exactly 20 tasks")
    if type(family.parameter_axes) is not tuple or len(family.parameter_axes) != 2 or any(type(axis) is not CoverageParameterAxis for axis in family.parameter_axes):
        raise ExecutableDevelopmentCoverageError("family must have two exact parameter axes")
    for axis in family.parameter_axes:
        _validate_axis(axis)
    if tuple(len(axis.values) for axis in family.parameter_axes) != (4, 5):
        raise ExecutableDevelopmentCoverageError("family parameter grid must be exactly 4 by 5")
    if family.parameter_axes[0].axis_name == family.parameter_axes[1].axis_name:
        raise ExecutableDevelopmentCoverageError("family parameter axis names must differ")
    if type(family.solution_track) is not str or family.solution_track not in {"bash-native", "python-permitted"}:
        raise ExecutableDevelopmentCoverageError("solution track is invalid")
    if type(family.allowed_tools) is not tuple or not family.allowed_tools or any(type(tool) is not str or _TOOL_RE.fullmatch(tool) is None for tool in family.allowed_tools) or tuple(sorted(set(family.allowed_tools))) != family.allowed_tools:
        raise ExecutableDevelopmentCoverageError("allowed tools must be a unique sorted exact tuple")
    if (family.solution_track == "python-permitted") != ("python3" in family.allowed_tools):
        raise ExecutableDevelopmentCoverageError("solution track and Python tool policy disagree")
    permitted_tools = set(FROZEN_BASH_NATIVE_EXECUTABLES)
    if family.solution_track == "python-permitted":
        permitted_tools.add("python3")
    if not set(family.allowed_tools).issubset(permitted_tools):
        raise ExecutableDevelopmentCoverageError(
            "allowed tools exceed the frozen evaluation tool policy"
        )
    for value, label in ((family.filesystem_schema, "filesystem schema"), (family.output_contract, "output contract")):
        if type(value) is not str or _ID_RE.fullmatch(value) is None:
            raise ExecutableDevelopmentCoverageError(f"{label} is invalid")
    if type(family.capability_tags) is not tuple or len(family.capability_tags) < 3 or any(type(tag) is not str or _ID_RE.fullmatch(tag) is None for tag in family.capability_tags) or tuple(sorted(set(family.capability_tags))) != family.capability_tags:
        raise ExecutableDevelopmentCoverageError("capability tags must be a unique sorted exact tuple")
    if family.lifecycle_state == "integrated":
        if not _is_sha256(family.integrated_task_set_sha256):
            raise ExecutableDevelopmentCoverageError("integrated family lacks a task-set identity")
    elif family.integrated_task_set_sha256 is not None:
        raise ExecutableDevelopmentCoverageError("planned family cannot claim an integrated task set")
    if not _is_sha256(family.family_sha256) or family.family_sha256 != _domain_sha256("cbds.executable-method-development-coverage.family.v1", _family_core_record(family)):
        raise ExecutableDevelopmentCoverageError("family digest is invalid")


def _validate_source(source: SourceRegistryCommitment) -> None:
    if type(source) is not SourceRegistryCommitment:
        raise ExecutableDevelopmentCoverageError("source commitment must have its exact type")
    if type(source.tranche_id) is not str or _ID_RE.fullmatch(source.tranche_id) is None:
        raise ExecutableDevelopmentCoverageError("source tranche identifier is invalid")
    if type(source.added_task_count) is not int or source.added_task_count <= 0 or type(source.cumulative_task_count) is not int or source.cumulative_task_count <= 0 or source.added_task_count > source.cumulative_task_count:
        raise ExecutableDevelopmentCoverageError("source task counts are invalid")
    if not _is_sha256(source.registry_sha256) or not _is_sha256(source.cumulative_suite_sha256):
        raise ExecutableDevelopmentCoverageError("source digest is invalid")


def _task_set_sha256(family_id: str, tasks: tuple[object, ...]) -> str:
    return _domain_sha256(
        "cbds.executable-method-development-coverage.integrated-task-set.v1",
        {
            "family_id": family_id,
            "task_count": len(tasks),
            "task_id": [getattr(task, "task_id") for task in tasks],
            "task_contract_sha256": [getattr(task, "task_contract_sha256") for task in tasks],
            "graph_sha256": [getattr(task, "graph_sha256") for task in tasks],
        },
    )


@lru_cache(maxsize=1)
def _live_integrated_evidence() -> tuple[tuple[SourceRegistryCommitment, ...], tuple[tuple[str, str], ...]]:
    from .executable_static_registry import build_public_method_development_registry
    from .executable_static_second_registry import build_second_tranche_task_registry
    from .executable_static_third_registry import build_third_tranche_task_registry
    from .executable_static_fourth_registry import build_fourth_tranche_task_registry
    from .executable_static_fifth_registry import build_fifth_tranche_task_registry
    from .executable_static_sixth_registry import build_sixth_tranche_task_registry

    first = build_public_method_development_registry()
    second = build_second_tranche_task_registry()
    third = build_third_tranche_task_registry()
    fourth = build_fourth_tranche_task_registry()
    fifth = build_fifth_tranche_task_registry()
    sixth = build_sixth_tranche_task_registry()
    sources = (
        SourceRegistryCommitment("first-tranche", len(first.tasks), len(first.tasks), first.registry_sha256, first.suite_sha256),
        SourceRegistryCommitment("second-tranche", len(second.added_tasks), 200, second.registry_sha256, second.cumulative_suite_sha256),
        SourceRegistryCommitment("third-tranche", len(third.added_tasks), 240, third.registry_sha256, third.cumulative_suite_sha256),
        SourceRegistryCommitment("fourth-tranche", len(fourth.added_tasks), 260, fourth.registry_sha256, fourth.cumulative_suite_sha256),
        SourceRegistryCommitment("fifth-tranche", len(fifth.added_tasks), 280, fifth.registry_sha256, fifth.cumulative_suite_sha256),
        SourceRegistryCommitment("sixth-tranche", len(sixth.added_tasks), 300, sixth.registry_sha256, sixth.cumulative_suite_sha256),
    )
    if sources != _EXPECTED_SOURCES:
        raise ExecutableDevelopmentCoverageError("live integrated registries differ from the coverage base")
    all_tasks = (
        *first.tasks,
        *second.added_tasks,
        *third.added_tasks,
        *fourth.added_tasks,
        *fifth.added_tasks,
        *sixth.added_tasks,
    )
    integrated_specs = _FAMILY_SPECS[:INTEGRATED_FAMILY_COUNT]
    evidence: list[tuple[str, str]] = []
    offset = 0
    for spec in integrated_specs:
        tasks = tuple(all_tasks[offset : offset + TASKS_PER_FAMILY])
        offset += TASKS_PER_FAMILY
        if len(tasks) != TASKS_PER_FAMILY or any(getattr(task, "family_id", None) != spec.family_id for task in tasks):
            raise ExecutableDevelopmentCoverageError("live family order or task count differs from the coverage lock")
        if {getattr(task, "filesystem_identity", None) for task in tasks} != {spec.filesystem_schema} or {getattr(task, "output_identity", None) for task in tasks} != {spec.output_contract} or {getattr(task, "allowed_tools", None) for task in tasks} != {spec.allowed_tools}:
            raise ExecutableDevelopmentCoverageError(f"live {spec.family_id} contract identity differs from the coverage lock")
        expected_parameters = tuple(
            (spec.family_id, first_value, second_value)
            for first_value in spec.parameter_axes[0].values
            for second_value in spec.parameter_axes[1].values
        )
        observed_parameters: list[tuple[object, object, object]] = []
        for task in tasks:
            record = task.parameters.to_record()
            if type(record) is not dict or set(record) != {"parameter_type", spec.parameter_axes[0].axis_name, spec.parameter_axes[1].axis_name}:
                raise ExecutableDevelopmentCoverageError(f"live {spec.family_id} parameter schema differs from the coverage lock")
            observed_parameters.append((record["parameter_type"], record[spec.parameter_axes[0].axis_name], record[spec.parameter_axes[1].axis_name]))
        if tuple(observed_parameters) != expected_parameters:
            raise ExecutableDevelopmentCoverageError(f"live {spec.family_id} parameter grid differs from the coverage lock")
        evidence.append((spec.family_id, _task_set_sha256(spec.family_id, tasks)))
    if offset != INTEGRATED_TASK_COUNT or len(all_tasks) != INTEGRATED_TASK_COUNT:
        raise ExecutableDevelopmentCoverageError(
            f"integrated task total differs from {INTEGRATED_TASK_COUNT}"
        )
    return sources, tuple(evidence)


def _make_family(spec: _FamilySpec, task_set_sha256: str | None) -> CoverageFamily:
    provisional = CoverageFamily.__new__(CoverageFamily)
    object.__setattr__(provisional, "family_id", spec.family_id)
    object.__setattr__(provisional, "lifecycle_state", spec.lifecycle_state)
    object.__setattr__(provisional, "task_count", TASKS_PER_FAMILY)
    object.__setattr__(provisional, "parameter_axes", spec.parameter_axes)
    object.__setattr__(provisional, "solution_track", spec.solution_track)
    object.__setattr__(provisional, "allowed_tools", spec.allowed_tools)
    object.__setattr__(provisional, "filesystem_schema", spec.filesystem_schema)
    object.__setattr__(provisional, "output_contract", spec.output_contract)
    object.__setattr__(provisional, "capability_tags", spec.capability_tags)
    object.__setattr__(provisional, "integrated_task_set_sha256", task_set_sha256)
    object.__setattr__(provisional, "family_sha256", "0" * 64)
    digest = _domain_sha256("cbds.executable-method-development-coverage.family.v1", _family_core_record(provisional))
    return CoverageFamily(
        family_id=spec.family_id,
        lifecycle_state=spec.lifecycle_state,
        task_count=TASKS_PER_FAMILY,
        parameter_axes=spec.parameter_axes,
        solution_track=spec.solution_track,
        allowed_tools=spec.allowed_tools,
        filesystem_schema=spec.filesystem_schema,
        output_contract=spec.output_contract,
        capability_tags=spec.capability_tags,
        integrated_task_set_sha256=task_set_sha256,
        family_sha256=digest,
    )


def _coverage_record(coverage: ExecutableDevelopmentCoverage) -> dict[str, object]:
    return {
        "schema_version": coverage.schema_version,
        "coverage_version": coverage.coverage_version,
        "record_type": "cbds.executable-method-development-coverage-hashes",
        "suite_id": coverage.suite_id,
        "family_count": FAMILY_COUNT,
        "tasks_per_family": TASKS_PER_FAMILY,
        "total_task_count": TOTAL_TASK_COUNT,
        "integrated_family_count": INTEGRATED_FAMILY_COUNT,
        "integrated_task_count": INTEGRATED_TASK_COUNT,
        "planned_family_count": PLANNED_FAMILY_COUNT,
        "planned_task_count": PLANNED_TASK_COUNT,
        "canonical_family_order": list(CANONICAL_FAMILY_ORDER),
        "source_registry_commitments": [source.to_record() for source in coverage.source_registry_commitments],
        "families": [family.to_record() for family in coverage.families],
        "coverage_sha256": coverage.coverage_sha256,
        "public_method_development": coverage.public_method_development,
        "sealed": coverage.sealed,
        "scored": coverage.scored,
        "candidate_execution_authorized": coverage.candidate_execution_authorized,
        "scored_evaluation_authorized": coverage.scored_evaluation_authorized,
        "model_selection_eligible": coverage.model_selection_eligible,
        "claim_authorized": coverage.claim_authorized,
        "independent_human_review_attested": coverage.independent_human_review_attested,
    }


def compute_executable_development_coverage_sha256(record: object) -> str:
    if type(record) is not dict:
        raise ExecutableDevelopmentCoverageError("coverage hash input must be an exact object")
    payload = dict(record)
    payload.pop("coverage_sha256", None)
    return _domain_sha256("cbds.executable-method-development-coverage.record.v1", payload)


def validate_executable_development_coverage(coverage: ExecutableDevelopmentCoverage) -> None:
    if type(coverage) is not ExecutableDevelopmentCoverage:
        raise ExecutableDevelopmentCoverageError("coverage must have its exact type")
    if type(coverage.schema_version) is not str or coverage.schema_version != COVERAGE_SCHEMA_VERSION or type(coverage.coverage_version) is not str or coverage.coverage_version != COVERAGE_VERSION or type(coverage.suite_id) is not str or coverage.suite_id != COVERAGE_SUITE_ID:
        raise ExecutableDevelopmentCoverageError("coverage version metadata is invalid")
    authority = (
        coverage.public_method_development,
        coverage.sealed,
        coverage.scored,
        coverage.candidate_execution_authorized,
        coverage.scored_evaluation_authorized,
        coverage.model_selection_eligible,
        coverage.claim_authorized,
        coverage.independent_human_review_attested,
    )
    if any(type(value) is not bool for value in authority) or authority != (True, False, False, False, False, False, False, False):
        raise ExecutableDevelopmentCoverageError("coverage authority boundary is invalid")
    if type(coverage.families) is not tuple or len(coverage.families) != FAMILY_COUNT or any(type(family) is not CoverageFamily for family in coverage.families):
        raise ExecutableDevelopmentCoverageError("coverage must contain exactly 25 exact families")
    if type(coverage.source_registry_commitments) is not tuple or coverage.source_registry_commitments != _EXPECTED_SOURCES or any(type(source) is not SourceRegistryCommitment for source in coverage.source_registry_commitments):
        raise ExecutableDevelopmentCoverageError("coverage source commitments are invalid")
    for family in coverage.families:
        _validate_family(family)
    if tuple(family.family_id for family in coverage.families) != CANONICAL_FAMILY_ORDER:
        raise ExecutableDevelopmentCoverageError("coverage family order is not canonical")
    observed_specs = tuple(
        _FamilySpec(family.family_id, family.lifecycle_state, family.parameter_axes, family.solution_track, family.allowed_tools, family.filesystem_schema, family.output_contract, family.capability_tags)
        for family in coverage.families
    )
    if observed_specs != _FAMILY_SPECS:
        raise ExecutableDevelopmentCoverageError("coverage family declarations differ from the central lock")
    if tuple(family.lifecycle_state for family in coverage.families) != ("integrated",) * INTEGRATED_FAMILY_COUNT + ("planned",) * PLANNED_FAMILY_COUNT:
        raise ExecutableDevelopmentCoverageError("coverage lifecycle partition is invalid")
    if sum(family.task_count for family in coverage.families) != TOTAL_TASK_COUNT:
        raise ExecutableDevelopmentCoverageError("coverage task total is not 500")
    structural_signatures = {
        (
            tuple((axis.axis_name, axis.values) for axis in family.parameter_axes),
            family.allowed_tools,
            family.filesystem_schema,
            family.output_contract,
            family.capability_tags,
        )
        for family in coverage.families
    }
    planned = coverage.families[INTEGRATED_FAMILY_COUNT:]
    if len({tuple(axis.axis_name for axis in family.parameter_axes) for family in coverage.families}) != FAMILY_COUNT or len({tuple(tuple(axis.values) for axis in family.parameter_axes) for family in coverage.families}) != FAMILY_COUNT or len({family.allowed_tools for family in planned}) != PLANNED_FAMILY_COUNT or len({family.filesystem_schema for family in coverage.families}) != FAMILY_COUNT or len({family.output_contract for family in coverage.families}) != FAMILY_COUNT or len({family.family_sha256 for family in coverage.families}) != FAMILY_COUNT or len(structural_signatures) != FAMILY_COUNT:
        raise ExecutableDevelopmentCoverageError("families are not structurally distinct")
    live_sources, live_task_sets = _live_integrated_evidence()
    if coverage.source_registry_commitments != live_sources or tuple((family.family_id, family.integrated_task_set_sha256) for family in coverage.families[:INTEGRATED_FAMILY_COUNT]) != live_task_sets:
        raise ExecutableDevelopmentCoverageError("integrated family identities differ from live registries")
    record = _coverage_record(coverage)
    if not _is_sha256(coverage.coverage_sha256) or coverage.coverage_sha256 != compute_executable_development_coverage_sha256(record):
        raise ExecutableDevelopmentCoverageError("coverage digest is invalid")


def build_executable_development_coverage() -> ExecutableDevelopmentCoverage:
    sources, live_task_sets = _live_integrated_evidence()
    task_sets = dict(live_task_sets)
    families = tuple(
        _make_family(spec, task_sets.get(spec.family_id))
        for spec in _FAMILY_SPECS
    )
    provisional = ExecutableDevelopmentCoverage.__new__(ExecutableDevelopmentCoverage)
    object.__setattr__(provisional, "families", families)
    object.__setattr__(provisional, "source_registry_commitments", sources)
    object.__setattr__(provisional, "coverage_sha256", "0" * 64)
    for name, value in (
        ("schema_version", COVERAGE_SCHEMA_VERSION),
        ("coverage_version", COVERAGE_VERSION),
        ("suite_id", COVERAGE_SUITE_ID),
        ("public_method_development", True),
        ("sealed", False),
        ("scored", False),
        ("candidate_execution_authorized", False),
        ("scored_evaluation_authorized", False),
        ("model_selection_eligible", False),
        ("claim_authorized", False),
        ("independent_human_review_attested", False),
    ):
        object.__setattr__(provisional, name, value)
    digest = compute_executable_development_coverage_sha256(_coverage_record(provisional))
    return ExecutableDevelopmentCoverage(families=families, source_registry_commitments=sources, coverage_sha256=digest)


def _exact_keys(value: object, expected: frozenset[str], label: str) -> dict[str, object]:
    if type(value) is not dict:
        raise ExecutableDevelopmentCoverageError(f"{label} must be an exact object")
    if set(value) != expected:
        raise ExecutableDevelopmentCoverageError(f"{label} has a noncanonical closed schema")
    return value


def _axis_from_record(value: object) -> CoverageParameterAxis:
    record = _exact_keys(value, _AXIS_KEYS, "parameter axis")
    values = record["values"]
    if type(values) is not list:
        raise ExecutableDevelopmentCoverageError("parameter axis values must be an exact array")
    return CoverageParameterAxis(axis_name=record["axis_name"], values=tuple(values))  # type: ignore[arg-type]


def _family_from_record(value: object) -> CoverageFamily:
    record = _exact_keys(value, _FAMILY_KEYS, "coverage family")
    axes = record["parameter_axes"]
    tools = record["allowed_tools"]
    tags = record["capability_tags"]
    if type(axes) is not list or type(tools) is not list or type(tags) is not list:
        raise ExecutableDevelopmentCoverageError("family arrays must have exact array types")
    return CoverageFamily(
        family_id=record["family_id"],  # type: ignore[arg-type]
        lifecycle_state=record["lifecycle_state"],  # type: ignore[arg-type]
        task_count=record["task_count"],  # type: ignore[arg-type]
        parameter_axes=tuple(_axis_from_record(axis) for axis in axes),  # type: ignore[arg-type]
        solution_track=record["solution_track"],  # type: ignore[arg-type]
        allowed_tools=tuple(tools),  # type: ignore[arg-type]
        filesystem_schema=record["filesystem_schema"],  # type: ignore[arg-type]
        output_contract=record["output_contract"],  # type: ignore[arg-type]
        capability_tags=tuple(tags),  # type: ignore[arg-type]
        integrated_task_set_sha256=record["integrated_task_set_sha256"],  # type: ignore[arg-type]
        family_sha256=record["family_sha256"],  # type: ignore[arg-type]
    )


def _source_from_record(value: object) -> SourceRegistryCommitment:
    record = _exact_keys(value, _SOURCE_KEYS, "source registry commitment")
    return SourceRegistryCommitment(
        tranche_id=record["tranche_id"],  # type: ignore[arg-type]
        added_task_count=record["added_task_count"],  # type: ignore[arg-type]
        cumulative_task_count=record["cumulative_task_count"],  # type: ignore[arg-type]
        registry_sha256=record["registry_sha256"],  # type: ignore[arg-type]
        cumulative_suite_sha256=record["cumulative_suite_sha256"],  # type: ignore[arg-type]
    )


def _coverage_from_record(value: object) -> ExecutableDevelopmentCoverage:
    record = _exact_keys(value, _ROOT_KEYS, "coverage record")
    exact_scalars = {
        "schema_version": COVERAGE_SCHEMA_VERSION,
        "coverage_version": COVERAGE_VERSION,
        "record_type": "cbds.executable-method-development-coverage-hashes",
        "suite_id": COVERAGE_SUITE_ID,
        "family_count": FAMILY_COUNT,
        "tasks_per_family": TASKS_PER_FAMILY,
        "total_task_count": TOTAL_TASK_COUNT,
        "integrated_family_count": INTEGRATED_FAMILY_COUNT,
        "integrated_task_count": INTEGRATED_TASK_COUNT,
        "planned_family_count": PLANNED_FAMILY_COUNT,
        "planned_task_count": PLANNED_TASK_COUNT,
        "public_method_development": True,
        "sealed": False,
        "scored": False,
        "candidate_execution_authorized": False,
        "scored_evaluation_authorized": False,
        "model_selection_eligible": False,
        "claim_authorized": False,
        "independent_human_review_attested": False,
    }
    for key, expected in exact_scalars.items():
        if type(record[key]) is not type(expected) or record[key] != expected:
            raise ExecutableDevelopmentCoverageError(f"coverage field {key!r} is invalid")
    order = record["canonical_family_order"]
    sources = record["source_registry_commitments"]
    families = record["families"]
    if type(order) is not list or any(type(item) is not str for item in order) or tuple(order) != CANONICAL_FAMILY_ORDER:
        raise ExecutableDevelopmentCoverageError("canonical family order is invalid")
    if type(sources) is not list or type(families) is not list:
        raise ExecutableDevelopmentCoverageError("coverage collections must be exact arrays")
    return ExecutableDevelopmentCoverage(
        families=tuple(_family_from_record(family) for family in families),
        source_registry_commitments=tuple(_source_from_record(source) for source in sources),
        coverage_sha256=record["coverage_sha256"],  # type: ignore[arg-type]
        schema_version=record["schema_version"],  # type: ignore[arg-type]
        coverage_version=record["coverage_version"],  # type: ignore[arg-type]
        suite_id=record["suite_id"],  # type: ignore[arg-type]
        public_method_development=record["public_method_development"],  # type: ignore[arg-type]
        sealed=record["sealed"],  # type: ignore[arg-type]
        scored=record["scored"],  # type: ignore[arg-type]
        candidate_execution_authorized=record["candidate_execution_authorized"],  # type: ignore[arg-type]
        scored_evaluation_authorized=record["scored_evaluation_authorized"],  # type: ignore[arg-type]
        model_selection_eligible=record["model_selection_eligible"],  # type: ignore[arg-type]
        claim_authorized=record["claim_authorized"],  # type: ignore[arg-type]
        independent_human_review_attested=record["independent_human_review_attested"],  # type: ignore[arg-type]
    )


def _fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_nlink, metadata.st_uid, metadata.st_gid, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)


def _directory_flags() -> int:
    directory = getattr(os, "O_DIRECTORY", None)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if directory is None or nofollow is None:
        raise ExecutableDevelopmentCoverageError("platform lacks no-follow directory opens")
    return os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | directory | nofollow


def _open_parent_directory(path: Path) -> tuple[int, str]:
    absolute = Path(os.path.abspath(os.fspath(path)))
    if not absolute.name or absolute.name in {".", ".."}:
        raise ExecutableDevelopmentCoverageError("coverage path has no canonical file name")
    descriptor = os.open("/", _directory_flags())
    try:
        for component in absolute.parent.parts[1:]:
            try:
                named_before = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
                child = os.open(component, _directory_flags(), dir_fd=descriptor)
                opened = os.fstat(child)
                named_after = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            except OSError as exc:
                raise ExecutableDevelopmentCoverageError(f"cannot open coverage path: {type(exc).__name__}") from exc
            if not stat.S_ISDIR(opened.st_mode) or _fingerprint(named_before) != _fingerprint(opened) or _fingerprint(named_after) != _fingerprint(opened):
                os.close(child)
                raise ExecutableDevelopmentCoverageError("coverage directory changed while opening")
            os.close(descriptor)
            descriptor = child
        return descriptor, absolute.name
    except BaseException:
        os.close(descriptor)
        raise


def _read_stable_regular(path: Path) -> bytes:
    parent, name = _open_parent_directory(path)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        os.close(parent)
        raise ExecutableDevelopmentCoverageError("platform lacks O_NOFOLLOW")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0) | nofollow
    try:
        try:
            named_before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            descriptor = os.open(name, flags, dir_fd=parent)
        except OSError as exc:
            raise ExecutableDevelopmentCoverageError(f"cannot open coverage config: {type(exc).__name__}") from exc
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or _fingerprint(named_before) != _fingerprint(before):
                raise ExecutableDevelopmentCoverageError("coverage config must be a stable regular file")
            if before.st_size > MAXIMUM_COVERAGE_CONFIG_BYTES:
                raise ExecutableDevelopmentCoverageError("coverage config exceeds its byte limit")
            payload = bytearray()
            remaining = before.st_size
            while remaining:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    raise ExecutableDevelopmentCoverageError("coverage config ended while being read")
                payload.extend(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise ExecutableDevelopmentCoverageError("coverage config grew while being read")
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        try:
            named_after = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except OSError as exc:
            raise ExecutableDevelopmentCoverageError("coverage config path changed while being read") from exc
        if _fingerprint(before) != _fingerprint(after) or _fingerprint(after) != _fingerprint(named_after):
            raise ExecutableDevelopmentCoverageError("coverage config changed while being read")
        return bytes(payload)
    finally:
        os.close(parent)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ExecutableDevelopmentCoverageError("coverage JSON contains a duplicate object key")
        result[key] = value
    return result


def load_executable_development_coverage(path: str | os.PathLike[str]) -> ExecutableDevelopmentCoverage:
    """Load the exact canonical checked projection without following links."""

    try:
        source = Path(os.fspath(path))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ExecutableDevelopmentCoverageError("coverage config path is invalid") from exc
    payload = _read_stable_regular(source)
    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda token: (_ for _ in ()).throw(ExecutableDevelopmentCoverageError(f"coverage JSON contains non-finite number {token}")),
        )
    except ExecutableDevelopmentCoverageError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ExecutableDevelopmentCoverageError("coverage config is not strict UTF-8 JSON") from exc
    try:
        canonical = canonical_json_bytes(value) + b"\n"
    except (ManifestValidationError, RecursionError, UnicodeEncodeError, ValueError) as exc:
        raise ExecutableDevelopmentCoverageError("coverage config is not canonical JSON") from exc
    if payload != canonical:
        raise ExecutableDevelopmentCoverageError("coverage config bytes are not exact canonical JSON plus LF")
    try:
        coverage = _coverage_from_record(value)
    except ExecutableDevelopmentCoverageError:
        raise
    except (AttributeError, RecursionError, TypeError, ValueError) as exc:
        raise ExecutableDevelopmentCoverageError(
            "coverage record reconstruction failed"
        ) from exc
    expected = build_executable_development_coverage().to_hash_only_record()
    try:
        records_match = canonical_json_bytes(value) == canonical_json_bytes(expected)
    except (ManifestValidationError, RecursionError, UnicodeEncodeError, ValueError) as exc:
        raise ExecutableDevelopmentCoverageError(
            "coverage projection comparison failed"
        ) from exc
    if not records_match:
        raise ExecutableDevelopmentCoverageError("checked coverage config differs from the central builder projection")
    return coverage


__all__ = [
    "CANONICAL_FAMILY_ORDER",
    "COVERAGE_CONFIG_RELATIVE_PATH",
    "COVERAGE_SCHEMA_VERSION",
    "COVERAGE_SUITE_ID",
    "COVERAGE_VERSION",
    "CoverageFamily",
    "CoverageParameterAxis",
    "ExecutableDevelopmentCoverage",
    "ExecutableDevelopmentCoverageError",
    "FAMILY_COUNT",
    "INTEGRATED_FAMILY_COUNT",
    "INTEGRATED_TASK_COUNT",
    "MAXIMUM_COVERAGE_CONFIG_BYTES",
    "PLANNED_FAMILY_COUNT",
    "PLANNED_TASK_COUNT",
    "SourceRegistryCommitment",
    "TASKS_PER_FAMILY",
    "TOTAL_TASK_COUNT",
    "build_executable_development_coverage",
    "compute_executable_development_coverage_sha256",
    "load_executable_development_coverage",
    "validate_executable_development_coverage",
]
