"""Executable-static two-source JSONL/CSV enrichment composition.

The family parses two bounded tabular sources, performs a left-preserving
cartesian enrichment join, and publishes one semantic JSONL result.  Two
layouts name an intermediate codec; that codec is part of the required
composition semantics, but the final-state verifier cannot establish that a
candidate physically materialized an intermediate file.

This is public method-development infrastructure.  It does not execute a
candidate, authorize scored evaluation, expose sealed data, or support a
model-quality claim.  The workspace verifier establishes only the final
bounded output and preservation of its pinned inputs under trusted quiescence.
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
    ExecutableWorkspaceError,
    ExpectedFile,
    FixtureDefinition,
    InputFile,
    InputSymlink,
    WorkspaceHandle,
    materialize_fixture,
    validate_expected_output_policy,
)


JSONL_CSV_ENRICHMENT_COMPOSE_FAMILY_ID: Final[str] = (
    "jsonl-csv-enrichment-compose"
)
JSONL_CSV_ENRICHMENT_COMPOSE_FILESYSTEM_IDENTITY: Final[str] = (
    "mixed-jsonl-csv-sources"
)
JSONL_CSV_ENRICHMENT_COMPOSE_OUTPUT_IDENTITY: Final[str] = (
    "composed-enriched-jsonl"
)
JSONL_CSV_ENRICHMENT_COMPOSE_GENERATOR_VERSION: Final[str] = "1.0.0"
JSONL_CSV_ENRICHMENT_COMPOSE_VERIFIER_IDENTITY: Final[str] = (
    "verify-jsonl-csv-enrichment-compose-v1"
)
JSONL_CSV_ENRICHMENT_COMPOSE_LEFT_INPUT: Final[str] = "input/left.data"
JSONL_CSV_ENRICHMENT_COMPOSE_RIGHT_INPUT: Final[str] = "input/right.data"
JSONL_CSV_ENRICHMENT_COMPOSE_OUTPUT: Final[str] = "output/enriched.jsonl"
JSONL_CSV_ENRICHMENT_COMPOSE_OUTPUT_MODE: Final[int] = 0o644
JSONL_CSV_ENRICHMENT_COMPOSE_SOURCE_MAXIMUM_BYTES: Final[int] = 64 * 1024
JSONL_CSV_ENRICHMENT_COMPOSE_MAXIMUM_PHYSICAL_RECORDS: Final[int] = 128
JSONL_CSV_ENRICHMENT_COMPOSE_FIELD_MAXIMUM_UTF8_BYTES: Final[int] = 128
JSONL_CSV_ENRICHMENT_COMPOSE_MAXIMUM_ENRICHED_ROWS: Final[int] = 1024
JSONL_CSV_ENRICHMENT_COMPOSE_OUTPUT_MAXIMUM_BYTES: Final[int] = 1024 * 1024
# Worst canonical rows under the scalar/cardinality bounds: header 173,
# 1,024 enriched rows of 835 bytes, 256 row rejects of 363 bytes, and two
# source rejects of 143 bytes.  Rejection policies are mutually exclusive, so
# summing all categories is deliberately conservative.
JSONL_CSV_ENRICHMENT_COMPOSE_PROVED_MAXIMUM_CANONICAL_OUTPUT_BYTES: Final[
    int
] = 948_427
JSONL_CSV_ENRICHMENT_COMPOSE_ALLOWED_TOOLS: Final[tuple[str, ...]] = (
    "awk",
    "jq",
    "mkdir",
    "sort",
)

# Honest final-state observation boundaries.
JSONL_CSV_ENRICHMENT_COMPOSE_FINAL_OUTPUT_OBSERVED: Final[bool] = True
JSONL_CSV_ENRICHMENT_COMPOSE_INPUT_PRESERVATION_OBSERVED: Final[bool] = True
JSONL_CSV_ENRICHMENT_COMPOSE_INTERMEDIATE_MATERIALIZATION_OBSERVED: Final[
    bool
] = False
JSONL_CSV_ENRICHMENT_COMPOSE_ATOMICITY_OBSERVED: Final[bool] = False
JSONL_CSV_ENRICHMENT_COMPOSE_TOOL_HISTORY_OBSERVED: Final[bool] = False
JSONL_CSV_ENRICHMENT_COMPOSE_READ_SCOPE_OBSERVED: Final[bool] = False
JSONL_CSV_ENRICHMENT_COMPOSE_CANDIDATE_EXIT_STATUS_OBSERVED: Final[
    bool
] = False
JSONL_CSV_ENRICHMENT_COMPOSE_TRANSIENT_STATE_OBSERVED: Final[bool] = False
JSONL_CSV_ENRICHMENT_COMPOSE_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE: Final[
    bool
] = True
JSONL_CSV_ENRICHMENT_COMPOSE_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE: Final[
    bool
] = False

JoinLayout: TypeAlias = Literal[
    "jsonl-left-csv-right",
    "csv-left-jsonl-right",
    "jsonl-both-with-csv-output",
    "csv-both-with-jsonl-output",
]
MissingFieldPolicy: TypeAlias = Literal[
    "drop-row",
    "empty-string",
    "null-value",
    "emit-reject-row",
    "reject-source-file",
]
SourceEncoding: TypeAlias = Literal["jsonl", "csv"]
IntermediateEncoding: TypeAlias = Literal["jsonl", "csv"]
Side: TypeAlias = Literal["left", "right"]

JSONL_CSV_ENRICHMENT_COMPOSE_JOIN_LAYOUTS: Final[tuple[JoinLayout, ...]] = (
    "jsonl-left-csv-right",
    "csv-left-jsonl-right",
    "jsonl-both-with-csv-output",
    "csv-both-with-jsonl-output",
)
JSONL_CSV_ENRICHMENT_COMPOSE_MISSING_FIELD_POLICIES: Final[
    tuple[MissingFieldPolicy, ...]
] = (
    "drop-row",
    "empty-string",
    "null-value",
    "emit-reject-row",
    "reject-source-file",
)

_LAYOUT_CODECS: Final[
    dict[JoinLayout, tuple[SourceEncoding, SourceEncoding, IntermediateEncoding]]
] = {
    "jsonl-left-csv-right": ("jsonl", "csv", "jsonl"),
    "csv-left-jsonl-right": ("csv", "jsonl", "jsonl"),
    "jsonl-both-with-csv-output": ("jsonl", "jsonl", "csv"),
    "csv-both-with-jsonl-output": ("csv", "csv", "jsonl"),
}
_TASK_ID_RE: Final[re.Pattern[str]] = re.compile(r"mds-[0-9a-f]{24}\Z")
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_HEADER_KEYS: Final[frozenset[str]] = frozenset(
    {
        "record",
        "join_layout",
        "missing_field_policy",
        "enriched_count",
        "reject_count",
        "source_reject_count",
    }
)
_ENRICHED_KEYS: Final[frozenset[str]] = frozenset(
    {"record", "id", "left", "right", "matched"}
)
_REJECT_KEYS: Final[frozenset[str]] = frozenset(
    {"record", "source", "source_index", "id", "missing_fields"}
)
_SOURCE_REJECT_KEYS: Final[frozenset[str]] = frozenset(
    {"record", "source", "reason", "affected_count", "missing_fields"}
)
_SOURCE_PATHS: Final[tuple[str, str]] = (
    JSONL_CSV_ENRICHMENT_COMPOSE_LEFT_INPUT,
    JSONL_CSV_ENRICHMENT_COMPOSE_RIGHT_INPUT,
)
_MISSING_NAMES: Final[tuple[str, str, str]] = ("id", "left", "right")


class JsonlCsvEnrichmentComposeError(ValueError):
    """Raised when a family contract, fixture, or output fails closed."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def _closed_text(
    value: object, allowed: tuple[str, ...], field_name: str
) -> str:
    if type(value) is not str or value not in allowed:
        raise JsonlCsvEnrichmentComposeError(
            f"{field_name} is outside the closed family contract"
        )
    return value


def _raw(value: str) -> bytes:
    return value.encode("utf-8")


def _nullable_order(value: str | None) -> tuple[int, bytes]:
    return (0, b"") if value is None else (1, _raw(value))


def _validate_field(
    value: object,
    name: str,
    *,
    identifier: bool = False,
) -> str:
    if type(value) is not str:
        raise JsonlCsvEnrichmentComposeError(f"{name} is not exact text")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise JsonlCsvEnrichmentComposeError(
            f"{name} is not strict UTF-8"
        ) from exc
    if (
        (identifier and not value)
        or len(encoded) > JSONL_CSV_ENRICHMENT_COMPOSE_FIELD_MAXIMUM_UTF8_BYTES
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise JsonlCsvEnrichmentComposeError(
            f"{name} violates the bounded scalar grammar"
        )
    return value


def _validate_missing_fields(
    values: object,
    *,
    allowed: frozenset[str],
) -> tuple[str, ...]:
    if (
        type(values) not in {tuple, list}
        or not values
        or any(type(item) is not str or item not in allowed for item in values)
    ):
        raise JsonlCsvEnrichmentComposeError("missing_fields is invalid")
    selected = tuple(values)
    if selected != tuple(sorted(set(selected), key=_raw)):
        raise JsonlCsvEnrichmentComposeError(
            "missing_fields is not unique byte ordered"
        )
    return selected


@dataclass(frozen=True, slots=True)
class JsonlCsvEnrichmentComposeParameters:
    join_layout: JoinLayout
    missing_field_policy: MissingFieldPolicy

    def __post_init__(self) -> None:
        if type(self) is not JsonlCsvEnrichmentComposeParameters:
            raise JsonlCsvEnrichmentComposeError(
                "parameters have wrong exact type"
            )
        _closed_text(
            self.join_layout,
            JSONL_CSV_ENRICHMENT_COMPOSE_JOIN_LAYOUTS,
            "join_layout",
        )
        _closed_text(
            self.missing_field_policy,
            JSONL_CSV_ENRICHMENT_COMPOSE_MISSING_FIELD_POLICIES,
            "missing_field_policy",
        )

    @property
    def codecs(
        self,
    ) -> tuple[SourceEncoding, SourceEncoding, IntermediateEncoding]:
        self.__post_init__()
        return _LAYOUT_CODECS[self.join_layout]

    def to_record(self) -> dict[str, str]:
        self.__post_init__()
        return {
            "parameter_type": JSONL_CSV_ENRICHMENT_COMPOSE_FAMILY_ID,
            "join_layout": self.join_layout,
            "missing_field_policy": self.missing_field_policy,
        }


_POLICY_TEXT: Final[dict[MissingFieldPolicy, str]] = {
    "drop-row": (
        "discard every source row missing a required member and discard each "
        "otherwise-valid left row with no matching right row"
    ),
    "empty-string": (
        "replace every missing source field with the empty string; a null join "
        "key never exists, and an unmatched left row receives empty `right`"
    ),
    "null-value": (
        "replace every missing source field with JSON null; null join keys never "
        "match, and an unmatched left row receives null `right`"
    ),
    "emit-reject-row": (
        "exclude each incomplete source row and emit one rejection for it; emit "
        "one join rejection for each otherwise-valid unmatched left row"
    ),
    "reject-source-file": (
        "reject each source containing an incomplete row; any otherwise-valid "
        "unmatched left row rejects the right source; discard all enrichments "
        "when either source is rejected and emit one source rejection per source"
    ),
}


def _task_contract(
    parameters: JsonlCsvEnrichmentComposeParameters,
) -> tuple[str, NormalizedSemanticGraph]:
    left_codec, right_codec, intermediate_codec = parameters.codecs
    prompt = f"""Write one Bash program that operates only in the current workspace.

Read `input/left.data` as strict {left_codec} records with logical fields
`id,left`, and `input/right.data` as strict {right_codec} records with logical
fields `id,right`.  JSONL is strict UTF-8, has one LF-terminated exact object
per physical record, contains no duplicate or extra member, and permits a
nonempty subset of its two named members; every present value is an exact
string.  CSV is strict UTF-8 RFC-4180-compatible two-column data with exact
header, CRLF after every physical record, no embedded CR or LF, and exactly two
fields; an empty CSV field denotes a missing field.  Quoted commas and doubled
quotes are data.  Each source is nonempty, at most 65536 bytes and at most 128
physical records, with the CSV header counting toward that limit.  Every
present id is nonempty.  Every present field is at most 128 UTF-8 bytes and
contains no ASCII control or DEL byte.  After applying the policy's source-row
preparation, counting every retained unmatched left row as one potential
enriched row, the logical join expands to at most 1024 rows.

Apply policy `{parameters.missing_field_policy}`: {_POLICY_TEXT[parameters.missing_field_policy]}.
Then left-preservingly join every retained left row to every retained right row
with the same exact nonnull string id.  Retain source multiplicity and the full
cartesian multiplicity of duplicate keys.  An unmatched retained left row is a
missing `right` governed by the same policy.  The logical join stage uses
strict {intermediate_codec} as its intermediate codec before final publication;
this is composition semantics, not permission to publish an intermediate.  A
missing id filled with empty string or null remains nonjoinable because join
eligibility is determined before representation filling.

Write only mode-0644 `output/enriched.jsonl`, strict UTF-8 with LF after every
object.  First emit exactly one `compose` header with members `record`,
`join_layout`, `missing_field_policy`, `enriched_count`, `reject_count`, and
`source_reject_count`.  An enriched row has exactly `record`=`enriched`, `id`,
`left`, `right`, and boolean `matched`.  A row rejection has exactly
`record`=`reject`, `source`, zero-based `source_index`, `id`, and
`missing_fields`.  A source rejection has exactly `record`=`source-reject`,
`source`, `reason`=`required-field-missing`, positive `affected_count`, and
`missing_fields`.  Missing-field arrays are nonempty, unique, and raw-UTF-8-byte
sorted.

After the header, emit enriched rows first, ordered by nullable id, left, and
right (null before text, text by raw UTF-8 bytes), then `matched` false before
true.  Emit row rejections next by source raw bytes, source index, nullable id,
and missing-field tuple.  Emit source rejections last by source raw bytes.
Retain byte-identical ties.

Preserve every input path, kind, byte, mode, mtime, link count, and symlink
target.  Leave only the required real mode-0755 `output/` and an independent
link-count-one output file.  The final-state check does not prove physical
intermediate materialization, atomicity, tool use, read scope, exit status,
transient state, or global quiescence.  Use only Bash built-ins plus `awk`,
`jq`, `mkdir`, and `sort`.
"""
    graph = NormalizedSemanticGraph(
        nodes=(
            OperatorNode(
                "parse_left_enrichment_source",
                (f"codec:{left_codec}", "schema:id-left", "path:input/left.data"),
            ),
            OperatorNode(
                "parse_right_enrichment_source",
                (f"codec:{right_codec}", "schema:id-right", "path:input/right.data"),
            ),
            OperatorNode(
                "apply_missing_field_policy",
                (f"policy:{parameters.missing_field_policy}", "scope:sources-and-unmatched"),
            ),
            OperatorNode(
                "left_cartesian_enrichment_join",
                ("key:id", "multiplicity:retain", "null-keys:never-match"),
            ),
            OperatorNode(
                "roundtrip_composition_stage",
                (f"codec:{intermediate_codec}", "physical-publication:not-required"),
            ),
            OperatorNode(
                "emit_composed_enriched_jsonl",
                ("path:output/enriched.jsonl", "order:raw-utf8"),
            ),
        ),
        dependencies=((0, 2), (1, 2), (2, 3), (3, 4), (4, 5)),
    )
    return prompt, graph


def _validate_graph(graph: object) -> NormalizedSemanticGraph:
    if type(graph) is not NormalizedSemanticGraph:
        raise JsonlCsvEnrichmentComposeError("graph has wrong exact type")
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
        raise JsonlCsvEnrichmentComposeError(
            "graph reconstruction failed"
        ) from exc
    if rebuilt != graph or len(rebuilt.nodes) != len(graph.nodes):
        raise JsonlCsvEnrichmentComposeError("graph is noncanonical")
    return graph


def jsonl_csv_enrichment_compose_task_semantic_core(
    parameters: JsonlCsvEnrichmentComposeParameters,
    prompt: str,
    graph: NormalizedSemanticGraph,
) -> dict[str, object]:
    if type(parameters) is not JsonlCsvEnrichmentComposeParameters:
        raise JsonlCsvEnrichmentComposeError("parameters have wrong type")
    parameters.__post_init__()
    expected_prompt, expected_graph = _task_contract(parameters)
    if (
        type(prompt) is not str
        or prompt != expected_prompt
        or _validate_graph(graph) != expected_graph
    ):
        raise JsonlCsvEnrichmentComposeError("prompt or graph differs")
    return {
        "schema_version": EXECUTABLE_STATIC_SCHEMA_VERSION,
        "contract_version": EXECUTABLE_STATIC_CONTRACT_VERSION,
        "split_role": METHOD_DEVELOPMENT_SPLIT,
        "family_id": JSONL_CSV_ENRICHMENT_COMPOSE_FAMILY_ID,
        "family_version": EXECUTABLE_STATIC_FAMILY_VERSION,
        "generator_version": JSONL_CSV_ENRICHMENT_COMPOSE_GENERATOR_VERSION,
        "parameters": parameters.to_record(),
        "prompt": prompt,
        "graph": graph.to_record(),
        "graph_sha256": graph.hash,
        "filesystem_identity": (
            JSONL_CSV_ENRICHMENT_COMPOSE_FILESYSTEM_IDENTITY
        ),
        "output_identity": JSONL_CSV_ENRICHMENT_COMPOSE_OUTPUT_IDENTITY,
        "allowed_tools": list(JSONL_CSV_ENRICHMENT_COMPOSE_ALLOWED_TOOLS),
        "public": True,
        "sealed": False,
        "candidate_execution_authorized": False,
        "model_selection_eligible": False,
        "claim_authorized": False,
    }


def compute_jsonl_csv_enrichment_compose_task_sha256(
    parameters: JsonlCsvEnrichmentComposeParameters,
    prompt: str,
    graph: NormalizedSemanticGraph,
) -> str:
    return domain_sha256(
        "cbds.executable-static.task-contract.v1",
        jsonl_csv_enrichment_compose_task_semantic_core(
            parameters, prompt, graph
        ),
    )


@dataclass(frozen=True, slots=True)
class JsonlCsvEnrichmentComposeTask:
    task_id: str
    parameters: JsonlCsvEnrichmentComposeParameters
    prompt: str
    graph: NormalizedSemanticGraph
    fixtures: tuple[OpaqueFixtureDescriptor, ...]
    task_contract_sha256: str
    family_id: str = JSONL_CSV_ENRICHMENT_COMPOSE_FAMILY_ID
    family_version: str = EXECUTABLE_STATIC_FAMILY_VERSION
    filesystem_identity: str = JSONL_CSV_ENRICHMENT_COMPOSE_FILESYSTEM_IDENTITY
    output_identity: str = JSONL_CSV_ENRICHMENT_COMPOSE_OUTPUT_IDENTITY
    allowed_tools: tuple[str, ...] = JSONL_CSV_ENRICHMENT_COMPOSE_ALLOWED_TOOLS
    split_role: str = METHOD_DEVELOPMENT_SPLIT
    public: bool = True
    sealed: bool = False
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        if (
            type(self) is not JsonlCsvEnrichmentComposeTask
            or type(self.parameters) is not JsonlCsvEnrichmentComposeParameters
            or self.family_id != JSONL_CSV_ENRICHMENT_COMPOSE_FAMILY_ID
            or self.family_version != EXECUTABLE_STATIC_FAMILY_VERSION
            or self.filesystem_identity
            != JSONL_CSV_ENRICHMENT_COMPOSE_FILESYSTEM_IDENTITY
            or self.output_identity
            != JSONL_CSV_ENRICHMENT_COMPOSE_OUTPUT_IDENTITY
            or self.allowed_tools
            != JSONL_CSV_ENRICHMENT_COMPOSE_ALLOWED_TOOLS
            or self.split_role != METHOD_DEVELOPMENT_SPLIT
            or self.public is not True
            or self.sealed is not False
            or self.candidate_execution_authorized is not False
            or self.model_selection_eligible is not False
            or self.claim_authorized is not False
        ):
            raise JsonlCsvEnrichmentComposeError("task metadata is invalid")
        expected = compute_jsonl_csv_enrichment_compose_task_sha256(
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
            raise JsonlCsvEnrichmentComposeError("task identity is invalid")
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
            raise JsonlCsvEnrichmentComposeError(
                "task descriptor binding is invalid"
            )

    @property
    def graph_sha256(self) -> str:
        self.__post_init__()
        return self.graph.hash

    def to_public_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            **jsonl_csv_enrichment_compose_task_semantic_core(
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
    parameters: JsonlCsvEnrichmentComposeParameters,
) -> JsonlCsvEnrichmentComposeTask:
    prompt, graph = _task_contract(parameters)
    digest = compute_jsonl_csv_enrichment_compose_task_sha256(
        parameters, prompt, graph
    )
    return JsonlCsvEnrichmentComposeTask(
        task_id_from_contract(digest),
        parameters,
        prompt,
        graph,
        _bootstrap_descriptors(digest),
        digest,
    )


@dataclass(frozen=True, slots=True)
class _SourceRow:
    source: str
    index: int
    identifier: str | None
    value: str | None

    def __post_init__(self) -> None:
        if (
            type(self) is not _SourceRow
            or self.source not in _SOURCE_PATHS
            or type(self.index) is not int
            or self.index < 0
        ):
            raise JsonlCsvEnrichmentComposeError("source row metadata invalid")
        if self.identifier is not None:
            _validate_field(self.identifier, "id", identifier=True)
        if self.value is not None:
            _validate_field(self.value, "source value")

    @property
    def side(self) -> Side:
        return (
            "left"
            if self.source == JSONL_CSV_ENRICHMENT_COMPOSE_LEFT_INPUT
            else "right"
        )

    @property
    def missing_fields(self) -> tuple[str, ...]:
        names = (
            ("id", self.side)
            if self.side == "left"
            else ("id", "right")
        )
        values = (self.identifier, self.value)
        return tuple(
            name for name, value in zip(names, values, strict=True)
            if value is None
        )


def _strict_json_object(text: str) -> dict[str, object]:
    def hook(pairs: list[tuple[str, object]]) -> dict[str, object]:
        keys = [key for key, _value in pairs]
        if len(keys) != len(set(keys)):
            raise JsonlCsvEnrichmentComposeError(
                "JSON object has duplicate keys"
            )
        return dict(pairs)

    try:
        value = json.loads(
            text,
            object_pairs_hook=hook,
            parse_constant=lambda token: (_ for _ in ()).throw(
                JsonlCsvEnrichmentComposeError(
                    f"JSON extension token is forbidden: {token}"
                )
            ),
        )
    except JsonlCsvEnrichmentComposeError:
        raise
    except (
        json.JSONDecodeError,
        UnicodeError,
        RecursionError,
        ValueError,
    ) as exc:
        raise JsonlCsvEnrichmentComposeError("JSON row is malformed") from exc
    if type(value) is not dict:
        raise JsonlCsvEnrichmentComposeError("JSON row is not an object")
    return value


def _validate_source_bounds(payload: bytes) -> None:
    if (
        type(payload) is not bytes
        or not payload
        or len(payload)
        > JSONL_CSV_ENRICHMENT_COMPOSE_SOURCE_MAXIMUM_BYTES
    ):
        raise JsonlCsvEnrichmentComposeError(
            "source violates its closed byte bound"
        )


def _parse_jsonl_primary(
    payload: bytes, side: Side
) -> tuple[_SourceRow, ...]:
    _validate_source_bounds(payload)
    if not payload.endswith(b"\n") or b"\r" in payload:
        raise JsonlCsvEnrichmentComposeError("JSONL framing is invalid")
    try:
        lines = payload[:-1].decode("utf-8", "strict").split("\n")
    except UnicodeDecodeError as exc:
        raise JsonlCsvEnrichmentComposeError(
            "JSONL is not strict UTF-8"
        ) from exc
    if (
        not lines
        or len(lines)
        > JSONL_CSV_ENRICHMENT_COMPOSE_MAXIMUM_PHYSICAL_RECORDS
        or any(not line for line in lines)
    ):
        raise JsonlCsvEnrichmentComposeError("JSONL row count is invalid")
    value_name = side
    allowed = {"id", value_name}
    rows: list[_SourceRow] = []
    source = (
        JSONL_CSV_ENRICHMENT_COMPOSE_LEFT_INPUT
        if side == "left"
        else JSONL_CSV_ENRICHMENT_COMPOSE_RIGHT_INPUT
    )
    for index, line in enumerate(lines):
        value = _strict_json_object(line)
        if not value or not set(value).issubset(allowed):
            raise JsonlCsvEnrichmentComposeError("JSONL keys are invalid")
        identifier = (
            _validate_field(value["id"], "id", identifier=True)
            if "id" in value
            else None
        )
        field_value = (
            _validate_field(value[value_name], value_name)
            if value_name in value
            else None
        )
        rows.append(_SourceRow(source, index, identifier, field_value))
    return tuple(rows)


def _parse_csv_record_reference(record: str) -> tuple[str, ...]:
    fields: list[str] = []
    cursor = 0
    while True:
        if cursor < len(record) and record[cursor] == '"':
            cursor += 1
            value: list[str] = []
            while True:
                if cursor >= len(record):
                    raise JsonlCsvEnrichmentComposeError(
                        "CSV quote is unterminated"
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
                raise JsonlCsvEnrichmentComposeError(
                    "CSV data follows a closing quote"
                )
            fields.append("".join(value))
        else:
            start = cursor
            while cursor < len(record) and record[cursor] != ",":
                if record[cursor] == '"':
                    raise JsonlCsvEnrichmentComposeError(
                        "CSV quote occurs in an unquoted field"
                    )
                cursor += 1
            fields.append(record[start:cursor])
        if cursor == len(record):
            return tuple(fields)
        cursor += 1
        if cursor == len(record):
            fields.append("")
            return tuple(fields)


def _validate_crlf_framing(payload: bytes) -> None:
    if not payload.endswith(b"\r\n"):
        raise JsonlCsvEnrichmentComposeError("CSV lacks final CRLF")
    for index, byte in enumerate(payload):
        if byte == 10 and (index == 0 or payload[index - 1] != 13):
            raise JsonlCsvEnrichmentComposeError("CSV has bare LF")
        if byte == 13 and (
            index + 1 == len(payload) or payload[index + 1] != 10
        ):
            raise JsonlCsvEnrichmentComposeError("CSV has bare CR")


def _csv_rows_to_sources(
    records: tuple[tuple[str, ...], ...],
    side: Side,
) -> tuple[_SourceRow, ...]:
    header = ("id", side)
    if (
        not records
        or records[0] != header
        or len(records) < 2
        or len(records)
        > JSONL_CSV_ENRICHMENT_COMPOSE_MAXIMUM_PHYSICAL_RECORDS
    ):
        raise JsonlCsvEnrichmentComposeError("CSV header/body is invalid")
    source = (
        JSONL_CSV_ENRICHMENT_COMPOSE_LEFT_INPUT
        if side == "left"
        else JSONL_CSV_ENRICHMENT_COMPOSE_RIGHT_INPUT
    )
    result: list[_SourceRow] = []
    for index, record in enumerate(records[1:]):
        if len(record) != 2:
            raise JsonlCsvEnrichmentComposeError("CSV row width is invalid")
        identifier = (
            _validate_field(record[0], "id", identifier=True)
            if record[0]
            else None
        )
        field_value = (
            _validate_field(record[1], side) if record[1] else None
        )
        result.append(_SourceRow(source, index, identifier, field_value))
    return tuple(result)


def _parse_csv_primary(
    payload: bytes, side: Side
) -> tuple[_SourceRow, ...]:
    _validate_source_bounds(payload)
    _validate_crlf_framing(payload)
    try:
        text = payload.decode("utf-8", "strict")
        parsed = tuple(
            tuple(row)
            for row in csv.reader(io.StringIO(text, newline=""), strict=True)
        )
    except (UnicodeDecodeError, csv.Error) as exc:
        raise JsonlCsvEnrichmentComposeError("CSV syntax is invalid") from exc
    if any("\r" in field or "\n" in field for row in parsed for field in row):
        raise JsonlCsvEnrichmentComposeError(
            "CSV embedded line breaks are forbidden"
        )
    return _csv_rows_to_sources(parsed, side)


def _parse_jsonl_reference(
    payload: bytes, side: Side
) -> tuple[_SourceRow, ...]:
    _validate_source_bounds(payload)
    if payload[-1:] != b"\n" or b"\r" in payload:
        raise JsonlCsvEnrichmentComposeError(
            "reference JSONL framing differs"
        )
    rows: list[_SourceRow] = []
    cursor = 0
    index = 0
    source = _SOURCE_PATHS[0 if side == "left" else 1]
    allowed = frozenset(("id", side))
    while cursor < len(payload):
        marker = payload.find(b"\n", cursor)
        if marker < 0 or marker == cursor:
            raise JsonlCsvEnrichmentComposeError(
                "reference JSONL row differs"
            )
        try:
            text = payload[cursor:marker].decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise JsonlCsvEnrichmentComposeError(
                "reference JSONL encoding differs"
            ) from exc
        cursor = marker + 1
        value = _strict_json_object(text)
        if not value or not frozenset(value).issubset(allowed):
            raise JsonlCsvEnrichmentComposeError(
                "reference JSONL keys differ"
            )
        identifier = (
            _validate_field(value["id"], "id", identifier=True)
            if "id" in value
            else None
        )
        field_value = (
            _validate_field(value[side], side)
            if side in value
            else None
        )
        rows.append(_SourceRow(source, index, identifier, field_value))
        index += 1
    if (
        not rows
        or len(rows)
        > JSONL_CSV_ENRICHMENT_COMPOSE_MAXIMUM_PHYSICAL_RECORDS
    ):
        raise JsonlCsvEnrichmentComposeError(
            "reference JSONL bound differs"
        )
    return tuple(rows)


def _parse_csv_reference(
    payload: bytes, side: Side
) -> tuple[_SourceRow, ...]:
    _validate_source_bounds(payload)
    _validate_crlf_framing(payload)
    try:
        text = payload.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise JsonlCsvEnrichmentComposeError(
            "reference CSV encoding differs"
        ) from exc
    physical = text[:-2].split("\r\n")
    if any("\r" in record or "\n" in record for record in physical):
        raise JsonlCsvEnrichmentComposeError(
            "reference CSV physical framing differs"
        )
    records = tuple(_parse_csv_record_reference(record) for record in physical)
    return _csv_rows_to_sources(records, side)


def parse_jsonl_csv_enrichment_source(
    payload: bytes,
    encoding: SourceEncoding,
    side: Side,
) -> tuple[_SourceRow, ...]:
    _closed_text(encoding, ("jsonl", "csv"), "source encoding")
    _closed_text(side, ("left", "right"), "source side")
    if encoding == "jsonl":
        primary = _parse_jsonl_primary(payload, side)
        reference = _parse_jsonl_reference(payload, side)
    else:
        primary = _parse_csv_primary(payload, side)
        reference = _parse_csv_reference(payload, side)
    if primary != reference:
        raise JsonlCsvEnrichmentComposeError("source parsers disagree")
    return primary


def _encode_source(
    rows: tuple[_SourceRow, ...],
    encoding: SourceEncoding,
    side: Side,
) -> bytes:
    if (
        not rows
        or any(row.side != side for row in rows)
        or tuple(row.index for row in rows) != tuple(range(len(rows)))
    ):
        raise JsonlCsvEnrichmentComposeError(
            "fixture source rows are noncanonical"
        )
    if encoding == "jsonl":
        values: list[bytes] = []
        for row in rows:
            record: dict[str, str] = {}
            if row.identifier is not None:
                record["id"] = row.identifier
            if row.value is not None:
                record[side] = row.value
            if not record:
                raise JsonlCsvEnrichmentComposeError(
                    "fixture JSON row cannot omit both fields"
                )
            values.append(
                (
                    json.dumps(
                        record,
                        ensure_ascii=False,
                        allow_nan=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n"
                ).encode("utf-8")
            )
        result = b"".join(values)
    elif encoding == "csv":
        stream = io.StringIO(newline="")
        writer = csv.writer(stream, lineterminator="\r\n")
        writer.writerow(("id", side))
        writer.writerows(
            (
                "" if row.identifier is None else row.identifier,
                "" if row.value is None else row.value,
            )
            for row in rows
        )
        result = stream.getvalue().encode("utf-8")
    else:
        raise JsonlCsvEnrichmentComposeError(
            "fixture source codec is invalid"
        )
    parse_jsonl_csv_enrichment_source(result, encoding, side)
    return result


def _profile_logical_rows(
    profile: ExecutableFixtureProfile,
) -> tuple[tuple[_SourceRow, ...], tuple[_SourceRow, ...]]:
    left_path, right_path = _SOURCE_PATHS
    profile_id = profile.profile_id
    if profile_id == "spaces-unicode":
        left_values = (
            ("café id", "snow 雪 value"),
            ('quoted,"id"', 'left, "quoted"'),
            ("orphan id", "space value"),
        )
        right_values = (
            ("café id", "right 雪"),
            ('quoted,"id"', 'first, "right"'),
            ('quoted,"id"', "second right"),
            ("unused id", None),
        )
    elif profile_id == "leading-dashes-globs":
        left_values = (
            ("-leading", "-left[*]?"),
            ("glob[*]?", "literal ?*[]"),
            (None, "missing id never joins"),
        )
        right_values = (
            ("-leading", "-right[*]?"),
            ("glob[*]?", None),
            (None, "missing right id"),
        )
    elif profile_id == "empty-duplicates":
        left_values = (
            ("duplicate", "same"),
            ("duplicate", "same"),
            ("payload-missing", None),
        )
        right_values = (
            ("duplicate", "same right"),
            ("duplicate", "same right"),
            ("payload-missing", "present right"),
        )
    elif profile_id == "symlinks-ordering":
        left_values = (
            ("z-last", "zulu"),
            ("a-first", "alpha"),
            ("middle", "middle left"),
        )
        right_values = (
            ("middle", "middle right"),
            ("a-first", "alpha right"),
            ("z-last", "z right two"),
            ("z-last", "z right one"),
        )
    elif profile_id == "partial-permissions":
        left_values = (
            ("readable", "left readable"),
            ("missing-right", "left unmatched"),
            ("missing-left-value", None),
        )
        right_values = (
            ("readable", "right readable"),
            ("missing-left-value", "right for missing left"),
            ("bad-right", None),
        )
    else:
        raise JsonlCsvEnrichmentComposeError("fixture profile is invalid")
    left = tuple(
        _SourceRow(left_path, index, identifier, value)
        for index, (identifier, value) in enumerate(left_values)
    )
    right = tuple(
        _SourceRow(right_path, index, identifier, value)
        for index, (identifier, value) in enumerate(right_values)
    )
    return left, right


def _fixture_inputs(
    profile: ExecutableFixtureProfile,
    parameters: JsonlCsvEnrichmentComposeParameters,
) -> tuple[InputFile | InputSymlink, ...]:
    left_rows, right_rows = _profile_logical_rows(profile)
    left_codec, right_codec, _intermediate = parameters.codecs
    left_mode = 0o400 if profile.profile_id == "partial-permissions" else 0o600
    inputs: list[InputFile | InputSymlink] = [
        InputFile(
            JSONL_CSV_ENRICHMENT_COMPOSE_LEFT_INPUT,
            _encode_source(left_rows, left_codec, "left"),
            left_mode,
            1_100,
        ),
        InputFile(
            JSONL_CSV_ENRICHMENT_COMPOSE_RIGHT_INPUT,
            _encode_source(right_rows, right_codec, "right"),
            0o640,
            1_101,
        ),
    ]
    if profile.profile_id == "spaces-unicode":
        inputs.append(
            InputFile(
                "input/distractors/space café.csv",
                b"id,left\r\nignored,ignored\r\n",
                0o444,
                1_102,
            )
        )
    elif profile.profile_id == "leading-dashes-globs":
        inputs.append(
            InputFile(
                "input/-distractor[*]?.jsonl",
                b'{"id":"ignored","left":"ignored"}\n',
                0o400,
                1_103,
            )
        )
    elif profile.profile_id == "empty-duplicates":
        inputs.append(
            InputFile("input/distractors/empty", b"", 0o444, 1_104)
        )
    elif profile.profile_id == "symlinks-ordering":
        inputs.extend(
            (
                InputFile(
                    "input/distractors/target",
                    b"do not follow\n",
                    0o444,
                    1_105,
                ),
                InputSymlink(
                    "input/distractors/link", "target"
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
                1_106,
            )
        )
    return tuple(inputs)


def _revalidate_definition(definition: object) -> FixtureDefinition:
    if type(definition) is not FixtureDefinition:
        raise JsonlCsvEnrichmentComposeError(
            "definition has wrong exact type"
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
        raise JsonlCsvEnrichmentComposeError(
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
        raise JsonlCsvEnrichmentComposeError(
            "definition is outside family domain"
        )
    return definition


def _source_input(
    definition: FixtureDefinition, path: str
) -> InputFile:
    matches = tuple(
        item
        for item in definition.inputs
        if type(item) is InputFile and item.path == path
    )
    if len(matches) != 1:
        raise JsonlCsvEnrichmentComposeError(
            f"fixture must have one exact {path}"
        )
    return matches[0]


@dataclass(frozen=True, slots=True)
class _PreparedRow:
    original: _SourceRow
    identifier: str | None
    value: str | None
    joinable: bool

    def __post_init__(self) -> None:
        if (
            type(self) is not _PreparedRow
            or type(self.original) is not _SourceRow
            or self.joinable is not (self.original.identifier is not None)
        ):
            raise JsonlCsvEnrichmentComposeError(
                "prepared row lost original key presence"
            )
        self.original.__post_init__()
        if self.identifier is not None:
            _validate_field(self.identifier, "prepared id")
        if self.value is not None:
            _validate_field(self.value, "prepared value")


@dataclass(frozen=True, slots=True)
class JsonlCsvEnrichedEntry:
    identifier: str | None
    left: str | None
    right: str | None
    matched: bool

    def __post_init__(self) -> None:
        if type(self) is not JsonlCsvEnrichedEntry:
            raise JsonlCsvEnrichmentComposeError(
                "enriched entry has wrong exact type"
            )
        if self.identifier is not None:
            _validate_field(self.identifier, "enriched id")
        if self.left is not None:
            _validate_field(self.left, "enriched left")
        if self.right is not None:
            _validate_field(self.right, "enriched right")
        if type(self.matched) is not bool:
            raise JsonlCsvEnrichmentComposeError(
                "matched is not an exact boolean"
            )
        if self.matched and not self.identifier:
            raise JsonlCsvEnrichmentComposeError(
                "matched row must have an originally valid nonempty id"
            )

    def to_json_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "record": "enriched",
            "id": self.identifier,
            "left": self.left,
            "right": self.right,
            "matched": self.matched,
        }


@dataclass(frozen=True, slots=True)
class JsonlCsvRejectEntry:
    source: str
    source_index: int
    identifier: str | None
    missing_fields: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            type(self) is not JsonlCsvRejectEntry
            or self.source not in (*_SOURCE_PATHS, "join")
            or type(self.source_index) is not int
            or not 0 <= self.source_index
            < JSONL_CSV_ENRICHMENT_COMPOSE_MAXIMUM_PHYSICAL_RECORDS
        ):
            raise JsonlCsvEnrichmentComposeError(
                "reject entry metadata is invalid"
            )
        if self.identifier is not None:
            _validate_field(self.identifier, "reject id", identifier=True)
        allowed = (
            frozenset({"right"})
            if self.source == "join"
            else frozenset(
                {"id", "left"}
                if self.source
                == JSONL_CSV_ENRICHMENT_COMPOSE_LEFT_INPUT
                else {"id", "right"}
            )
        )
        _validate_missing_fields(self.missing_fields, allowed=allowed)
        if self.source == "join" and self.identifier is None:
            raise JsonlCsvEnrichmentComposeError(
                "join rejection must retain a valid id"
            )

    def to_json_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "record": "reject",
            "source": self.source,
            "source_index": self.source_index,
            "id": self.identifier,
            "missing_fields": list(self.missing_fields),
        }


@dataclass(frozen=True, slots=True)
class JsonlCsvSourceRejectEntry:
    source: str
    affected_count: int
    missing_fields: tuple[str, ...]
    reason: str = "required-field-missing"

    def __post_init__(self) -> None:
        if (
            type(self) is not JsonlCsvSourceRejectEntry
            or self.source not in _SOURCE_PATHS
            or type(self.affected_count) is not int
            or self.affected_count <= 0
            or self.affected_count
            > (
                JSONL_CSV_ENRICHMENT_COMPOSE_MAXIMUM_ENRICHED_ROWS
                + JSONL_CSV_ENRICHMENT_COMPOSE_MAXIMUM_PHYSICAL_RECORDS
            )
            or self.reason != "required-field-missing"
        ):
            raise JsonlCsvEnrichmentComposeError(
                "source rejection metadata is invalid"
            )
        allowed = frozenset(
            {"id", "left"}
            if self.source == JSONL_CSV_ENRICHMENT_COMPOSE_LEFT_INPUT
            else {"id", "right"}
        )
        _validate_missing_fields(self.missing_fields, allowed=allowed)

    def to_json_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "record": "source-reject",
            "source": self.source,
            "reason": self.reason,
            "affected_count": self.affected_count,
            "missing_fields": list(self.missing_fields),
        }


def _enriched_order(
    entry: JsonlCsvEnrichedEntry,
) -> tuple[
    tuple[int, bytes],
    tuple[int, bytes],
    tuple[int, bytes],
    bool,
]:
    return (
        _nullable_order(entry.identifier),
        _nullable_order(entry.left),
        _nullable_order(entry.right),
        entry.matched,
    )


def _reject_order(
    entry: JsonlCsvRejectEntry,
) -> tuple[bytes, int, tuple[int, bytes], tuple[bytes, ...]]:
    return (
        _raw(entry.source),
        entry.source_index,
        _nullable_order(entry.identifier),
        tuple(_raw(value) for value in entry.missing_fields),
    )


def _source_reject_order(
    entry: JsonlCsvSourceRejectEntry,
) -> bytes:
    return _raw(entry.source)


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


def _render_output(
    parameters: JsonlCsvEnrichmentComposeParameters,
    enriched: tuple[JsonlCsvEnrichedEntry, ...],
    rejects: tuple[JsonlCsvRejectEntry, ...],
    source_rejects: tuple[JsonlCsvSourceRejectEntry, ...],
) -> bytes:
    header = {
        "record": "compose",
        "join_layout": parameters.join_layout,
        "missing_field_policy": parameters.missing_field_policy,
        "enriched_count": len(enriched),
        "reject_count": len(rejects),
        "source_reject_count": len(source_rejects),
    }
    return b"".join(
        (_json_line(header),)
        + tuple(_json_line(entry.to_json_record()) for entry in enriched)
        + tuple(_json_line(entry.to_json_record()) for entry in rejects)
        + tuple(
            _json_line(entry.to_json_record())
            for entry in source_rejects
        )
    )


@dataclass(frozen=True, slots=True)
class JsonlCsvEnrichmentComposeState:
    join_layout: JoinLayout
    missing_field_policy: MissingFieldPolicy
    enriched: tuple[JsonlCsvEnrichedEntry, ...]
    rejects: tuple[JsonlCsvRejectEntry, ...]
    source_rejects: tuple[JsonlCsvSourceRejectEntry, ...]
    output: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if type(self) is not JsonlCsvEnrichmentComposeState:
            raise JsonlCsvEnrichmentComposeError("state has wrong type")
        parameters = JsonlCsvEnrichmentComposeParameters(
            self.join_layout, self.missing_field_policy
        )
        if (
            type(self.enriched) is not tuple
            or type(self.rejects) is not tuple
            or type(self.source_rejects) is not tuple
            or any(
                type(item) is not JsonlCsvEnrichedEntry
                for item in self.enriched
            )
            or any(
                type(item) is not JsonlCsvRejectEntry
                for item in self.rejects
            )
            or any(
                type(item) is not JsonlCsvSourceRejectEntry
                for item in self.source_rejects
            )
        ):
            raise JsonlCsvEnrichmentComposeError(
                "state collections have wrong exact types"
            )
        if (
            len(self.enriched)
            > JSONL_CSV_ENRICHMENT_COMPOSE_MAXIMUM_ENRICHED_ROWS
            or len(self.rejects)
            > 2
            * JSONL_CSV_ENRICHMENT_COMPOSE_MAXIMUM_PHYSICAL_RECORDS
            or len(self.source_rejects) > 2
        ):
            raise JsonlCsvEnrichmentComposeError(
                "state exceeds closed cardinality bounds"
            )
        for item in (*self.enriched, *self.rejects, *self.source_rejects):
            item.__post_init__()
        if (
            tuple(sorted(self.enriched, key=_enriched_order))
            != self.enriched
            or tuple(sorted(self.rejects, key=_reject_order))
            != self.rejects
            or tuple(
                sorted(self.source_rejects, key=_source_reject_order)
            )
            != self.source_rejects
        ):
            raise JsonlCsvEnrichmentComposeError(
                "state entries are not canonical"
            )
        policy = self.missing_field_policy
        if policy in {"drop-row", "empty-string", "null-value"} and (
            self.rejects or self.source_rejects
        ):
            raise JsonlCsvEnrichmentComposeError(
                "nonreject policy carries rejection records"
            )
        if policy == "emit-reject-row" and self.source_rejects:
            raise JsonlCsvEnrichmentComposeError(
                "row-reject policy carries source rejection"
            )
        if policy == "reject-source-file" and self.rejects:
            raise JsonlCsvEnrichmentComposeError(
                "source-reject policy carries row rejection"
            )
        if self.source_rejects and self.enriched:
            raise JsonlCsvEnrichmentComposeError(
                "source rejection did not discard enrichments"
            )
        for entry in self.enriched:
            if (
                entry.identifier == ""
                and policy != "empty-string"
            ):
                raise JsonlCsvEnrichmentComposeError(
                    "empty id is only a missing-id representation"
                )
            if policy == "drop-row" and not entry.matched:
                raise JsonlCsvEnrichmentComposeError(
                    "drop policy retained unmatched row"
                )
            if policy == "empty-string":
                if (
                    entry.identifier is None
                    or entry.left is None
                    or entry.right is None
                    or (not entry.matched and entry.right != "")
                ):
                    raise JsonlCsvEnrichmentComposeError(
                        "empty policy representation differs"
                    )
            elif policy == "null-value":
                if not entry.matched and entry.right is not None:
                    raise JsonlCsvEnrichmentComposeError(
                        "null policy unmatched right differs"
                    )
            elif (
                entry.identifier is None
                or entry.left is None
                or entry.right is None
            ):
                raise JsonlCsvEnrichmentComposeError(
                    "nonfill policy carries null enriched field"
                )
        expected = _render_output(
            parameters, self.enriched, self.rejects, self.source_rejects
        )
        if (
            type(self.output) is not bytes
            or self.output != expected
            or not self.output
            or len(self.output)
            > JSONL_CSV_ENRICHMENT_COMPOSE_OUTPUT_MAXIMUM_BYTES
        ):
            raise JsonlCsvEnrichmentComposeError(
                "state output differs or exceeds bound"
            )

    def header_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "record": "compose",
            "join_layout": self.join_layout,
            "missing_field_policy": self.missing_field_policy,
            "enriched_count": len(self.enriched),
            "reject_count": len(self.rejects),
            "source_reject_count": len(self.source_rejects),
        }

    def commitment_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "header": self.header_record(),
            "enriched": [
                entry.to_json_record() for entry in self.enriched
            ],
            "rejects": [entry.to_json_record() for entry in self.rejects],
            "source_rejects": [
                entry.to_json_record() for entry in self.source_rejects
            ],
            "output_size": len(self.output),
            "output_sha256": sha256(self.output).hexdigest(),
        }


def _prepare_primary(
    row: _SourceRow,
    policy: MissingFieldPolicy,
) -> _PreparedRow | None:
    missing = row.missing_fields
    if missing and policy in {"drop-row", "emit-reject-row", "reject-source-file"}:
        return None
    if policy == "empty-string":
        return _PreparedRow(
            row,
            "" if row.identifier is None else row.identifier,
            "" if row.value is None else row.value,
            row.identifier is not None,
        )
    return _PreparedRow(
        row,
        row.identifier,
        row.value,
        row.identifier is not None,
    )


def _count_join_expansion(
    left: tuple[_PreparedRow, ...],
    right: tuple[_PreparedRow, ...],
) -> int:
    counts: dict[str, int] = {}
    for row in right:
        if row.joinable:
            if row.identifier is None:
                raise JsonlCsvEnrichmentComposeError(
                    "joinable right row lost id"
                )
            counts[row.identifier] = counts.get(row.identifier, 0) + 1
    total = 0
    for row in left:
        matches = (
            counts.get(row.identifier, 0)
            if row.joinable and row.identifier is not None
            else 0
        )
        total += max(1, matches)
    if total > JSONL_CSV_ENRICHMENT_COMPOSE_MAXIMUM_ENRICHED_ROWS:
        raise JsonlCsvEnrichmentComposeError(
            "logical join expansion exceeds closed output bound"
        )
    return total


def _intermediate_jsonl_roundtrip_primary(
    entries: list[JsonlCsvEnrichedEntry],
) -> list[JsonlCsvEnrichedEntry]:
    payload = b"".join(_json_line(entry.to_json_record()) for entry in entries)
    if not payload:
        return []
    lines = payload[:-1].decode("utf-8", "strict").split("\n")
    result: list[JsonlCsvEnrichedEntry] = []
    for line in lines:
        value = _strict_json_object(line)
        if set(value) != _ENRICHED_KEYS or value.get("record") != "enriched":
            raise JsonlCsvEnrichmentComposeError(
                "JSONL intermediate schema differs"
            )
        result.append(_enriched_from_object(value))
    return result


def _json_scalar_token(value: str | None) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    )


def _parse_json_scalar_token(token: str) -> str | None:
    try:
        value = json.loads(token)
    except (json.JSONDecodeError, UnicodeError, RecursionError, ValueError) as exc:
        raise JsonlCsvEnrichmentComposeError(
            "CSV intermediate scalar token is invalid"
        ) from exc
    if value is not None and type(value) is not str:
        raise JsonlCsvEnrichmentComposeError(
            "CSV intermediate scalar token has wrong type"
        )
    return value


def _intermediate_csv_roundtrip_primary(
    entries: list[JsonlCsvEnrichedEntry],
) -> list[JsonlCsvEnrichedEntry]:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\r\n")
    writer.writerow(("id_json", "left_json", "right_json", "matched"))
    for entry in entries:
        writer.writerow(
            (
                _json_scalar_token(entry.identifier),
                _json_scalar_token(entry.left),
                _json_scalar_token(entry.right),
                "true" if entry.matched else "false",
            )
        )
    payload = stream.getvalue().encode("utf-8")
    _validate_crlf_framing(payload)
    try:
        rows = tuple(
            tuple(row)
            for row in csv.reader(
                io.StringIO(payload.decode("utf-8"), newline=""),
                strict=True,
            )
        )
    except (UnicodeDecodeError, csv.Error) as exc:
        raise JsonlCsvEnrichmentComposeError(
            "CSV intermediate parse failed"
        ) from exc
    if not rows or rows[0] != (
        "id_json", "left_json", "right_json", "matched"
    ):
        raise JsonlCsvEnrichmentComposeError(
            "CSV intermediate header differs"
        )
    result: list[JsonlCsvEnrichedEntry] = []
    for row in rows[1:]:
        if len(row) != 4 or row[3] not in {"true", "false"}:
            raise JsonlCsvEnrichmentComposeError(
                "CSV intermediate row differs"
            )
        result.append(
            JsonlCsvEnrichedEntry(
                _parse_json_scalar_token(row[0]),
                _parse_json_scalar_token(row[1]),
                _parse_json_scalar_token(row[2]),
                row[3] == "true",
            )
        )
    return result


def _roundtrip_primary(
    entries: list[JsonlCsvEnrichedEntry],
    codec: IntermediateEncoding,
) -> list[JsonlCsvEnrichedEntry]:
    if codec == "jsonl":
        return _intermediate_jsonl_roundtrip_primary(entries)
    if codec == "csv":
        return _intermediate_csv_roundtrip_primary(entries)
    raise JsonlCsvEnrichmentComposeError("intermediate codec is invalid")


def _intermediate_roundtrip_reference(
    entries: list[JsonlCsvEnrichedEntry],
    codec: IntermediateEncoding,
) -> list[JsonlCsvEnrichedEntry]:
    """Separately framed lossless intermediate round trip."""

    if codec == "jsonl":
        payload = b"".join(
            (
                json.dumps(
                    entry.to_json_record(),
                    ensure_ascii=False,
                    allow_nan=False,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            for entry in entries
        )
        result: list[JsonlCsvEnrichedEntry] = []
        cursor = 0
        while cursor < len(payload):
            marker = payload.find(b"\n", cursor)
            if marker < 0:
                raise JsonlCsvEnrichmentComposeError(
                    "reference intermediate is unterminated"
                )
            value = _strict_json_object(
                payload[cursor:marker].decode("utf-8", "strict")
            )
            cursor = marker + 1
            if frozenset(value) != _ENRICHED_KEYS:
                raise JsonlCsvEnrichmentComposeError(
                    "reference intermediate keys differ"
                )
            result.append(_enriched_from_object(value))
        return result
    if codec == "csv":
        records: list[str] = [
            "id_json,left_json,right_json,matched"
        ]
        for entry in entries:
            fields = (
                _json_scalar_token(entry.identifier),
                _json_scalar_token(entry.left),
                _json_scalar_token(entry.right),
                "true" if entry.matched else "false",
            )
            encoded_fields: list[str] = []
            for field_value in fields:
                encoded_fields.append(
                    '"'
                    + field_value.replace('"', '""')
                    + '"'
                )
            records.append(",".join(encoded_fields))
        parsed = tuple(
            _parse_csv_record_reference(record) for record in records
        )
        if parsed[0] != (
            "id_json", "left_json", "right_json", "matched"
        ):
            raise JsonlCsvEnrichmentComposeError(
                "reference CSV intermediate header differs"
            )
        result = []
        for row in parsed[1:]:
            if len(row) != 4 or row[3] not in {"true", "false"}:
                raise JsonlCsvEnrichmentComposeError(
                    "reference CSV intermediate row differs"
                )
            result.append(
                JsonlCsvEnrichedEntry(
                    _parse_json_scalar_token(row[0]),
                    _parse_json_scalar_token(row[1]),
                    _parse_json_scalar_token(row[2]),
                    row[3] == "true",
                )
            )
        return result
    raise JsonlCsvEnrichmentComposeError(
        "reference intermediate codec is invalid"
    )


def _source_rows_primary(
    definition: FixtureDefinition,
    parameters: JsonlCsvEnrichmentComposeParameters,
) -> tuple[tuple[_SourceRow, ...], tuple[_SourceRow, ...]]:
    selected = _revalidate_definition(definition)
    left_file = _source_input(
        selected, JSONL_CSV_ENRICHMENT_COMPOSE_LEFT_INPUT
    )
    right_file = _source_input(
        selected, JSONL_CSV_ENRICHMENT_COMPOSE_RIGHT_INPUT
    )
    left_codec, right_codec, _intermediate = parameters.codecs
    left = parse_jsonl_csv_enrichment_source(
        left_file.content, left_codec, "left"
    )
    right = parse_jsonl_csv_enrichment_source(
        right_file.content, right_codec, "right"
    )
    return left, right


def _source_rows_reference(
    definition: FixtureDefinition,
    parameters: JsonlCsvEnrichmentComposeParameters,
) -> tuple[tuple[_SourceRow, ...], tuple[_SourceRow, ...]]:
    selected = _revalidate_definition(definition)
    left_payload = _source_input(
        selected, JSONL_CSV_ENRICHMENT_COMPOSE_LEFT_INPUT
    ).content
    right_payload = _source_input(
        selected, JSONL_CSV_ENRICHMENT_COMPOSE_RIGHT_INPUT
    ).content
    left_codec, right_codec, _intermediate = parameters.codecs
    left = (
        _parse_jsonl_reference(left_payload, "left")
        if left_codec == "jsonl"
        else _parse_csv_reference(left_payload, "left")
    )
    right = (
        _parse_jsonl_reference(right_payload, "right")
        if right_codec == "jsonl"
        else _parse_csv_reference(right_payload, "right")
    )
    return left, right


def _source_rejection_state_primary(
    left_rows: tuple[_SourceRow, ...],
    right_rows: tuple[_SourceRow, ...],
) -> tuple[
    tuple[_PreparedRow, ...],
    tuple[_PreparedRow, ...],
    tuple[JsonlCsvSourceRejectEntry, ...],
]:
    left = tuple(
        prepared
        for row in left_rows
        for prepared in (_prepare_primary(row, "reject-source-file"),)
        if prepared is not None
    )
    right = tuple(
        prepared
        for row in right_rows
        for prepared in (_prepare_primary(row, "reject-source-file"),)
        if prepared is not None
    )
    _count_join_expansion(left, right)
    affected: dict[str, list[tuple[str, ...]]] = {
        path: [] for path in _SOURCE_PATHS
    }
    for row in (*left_rows, *right_rows):
        if row.missing_fields:
            affected[row.source].append(row.missing_fields)
    right_ids = {
        row.identifier
        for row in right
        if row.joinable and row.identifier is not None
    }
    for row in left:
        if not row.joinable or row.identifier not in right_ids:
            affected[JSONL_CSV_ENRICHMENT_COMPOSE_RIGHT_INPUT].append(
                ("right",)
            )
    source_rejects = tuple(
        JsonlCsvSourceRejectEntry(
            source,
            len(events),
            tuple(
                sorted(
                    {name for event in events for name in event},
                    key=_raw,
                )
            ),
        )
        for source in _SOURCE_PATHS
        for events in (affected[source],)
        if events
    )
    return left, right, source_rejects


def derive_jsonl_csv_enrichment_compose_state(
    definition: FixtureDefinition,
    parameters: JsonlCsvEnrichmentComposeParameters,
) -> JsonlCsvEnrichmentComposeState:
    """Primary indexed join and policy implementation."""

    if type(parameters) is not JsonlCsvEnrichmentComposeParameters:
        raise JsonlCsvEnrichmentComposeError(
            "primary parameters have wrong type"
        )
    parameters.__post_init__()
    left_rows, right_rows = _source_rows_primary(definition, parameters)
    policy = parameters.missing_field_policy
    source_rejects: tuple[JsonlCsvSourceRejectEntry, ...] = ()
    rejects: list[JsonlCsvRejectEntry] = []
    if policy == "reject-source-file":
        left, right, source_rejects = _source_rejection_state_primary(
            left_rows, right_rows
        )
        if source_rejects:
            selected_sources = tuple(
                sorted(source_rejects, key=_source_reject_order)
            )
            output = _render_output(
                parameters, (), (), selected_sources
            )
            return JsonlCsvEnrichmentComposeState(
                parameters.join_layout,
                policy,
                (),
                (),
                selected_sources,
                output,
            )
    else:
        if policy == "emit-reject-row":
            for row in (*left_rows, *right_rows):
                if row.missing_fields:
                    rejects.append(
                        JsonlCsvRejectEntry(
                            row.source,
                            row.index,
                            row.identifier,
                            row.missing_fields,
                        )
                    )
        left = tuple(
            prepared
            for row in left_rows
            for prepared in (_prepare_primary(row, policy),)
            if prepared is not None
        )
        right = tuple(
            prepared
            for row in right_rows
            for prepared in (_prepare_primary(row, policy),)
            if prepared is not None
        )
        _count_join_expansion(left, right)

    right_by_id: dict[str, list[_PreparedRow]] = {}
    for row in right:
        if row.joinable:
            if row.identifier is None:
                raise JsonlCsvEnrichmentComposeError(
                    "primary joinable right lost id"
                )
            right_by_id.setdefault(row.identifier, []).append(row)
    enriched: list[JsonlCsvEnrichedEntry] = []
    for left_row in left:
        matches = (
            right_by_id.get(left_row.identifier, ())
            if left_row.joinable and left_row.identifier is not None
            else ()
        )
        if matches:
            for right_row in matches:
                enriched.append(
                    JsonlCsvEnrichedEntry(
                        left_row.identifier,
                        left_row.value,
                        right_row.value,
                        True,
                    )
                )
            continue
        if policy == "empty-string":
            enriched.append(
                JsonlCsvEnrichedEntry(
                    left_row.identifier,
                    left_row.value,
                    "",
                    False,
                )
            )
        elif policy == "null-value":
            enriched.append(
                JsonlCsvEnrichedEntry(
                    left_row.identifier,
                    left_row.value,
                    None,
                    False,
                )
            )
        elif policy == "emit-reject-row":
            rejects.append(
                JsonlCsvRejectEntry(
                    "join",
                    left_row.original.index,
                    left_row.identifier,
                    ("right",),
                )
            )
    _left_codec, _right_codec, intermediate = parameters.codecs
    enriched = _roundtrip_primary(enriched, intermediate)
    selected_enriched = tuple(sorted(enriched, key=_enriched_order))
    selected_rejects = tuple(sorted(rejects, key=_reject_order))
    output = _render_output(
        parameters, selected_enriched, selected_rejects, source_rejects
    )
    return JsonlCsvEnrichmentComposeState(
        parameters.join_layout,
        policy,
        selected_enriched,
        selected_rejects,
        source_rejects,
        output,
    )


def _prepare_reference(
    rows: tuple[_SourceRow, ...],
    policy: MissingFieldPolicy,
) -> list[_PreparedRow]:
    prepared: list[_PreparedRow] = []
    for row in rows:
        missing = row.missing_fields
        if missing and policy in {
            "drop-row", "emit-reject-row", "reject-source-file"
        }:
            continue
        identifier = row.identifier
        value = row.value
        if policy == "empty-string":
            if identifier is None:
                identifier = ""
            if value is None:
                value = ""
        prepared.append(
            _PreparedRow(
                row,
                identifier,
                value,
                row.identifier is not None,
            )
        )
    return prepared


def reference_jsonl_csv_enrichment_compose_state(
    definition: FixtureDefinition,
    parameters: JsonlCsvEnrichmentComposeParameters,
) -> JsonlCsvEnrichmentComposeState:
    """Reference nested-loop join and explicit policy state machine."""

    if type(parameters) is not JsonlCsvEnrichmentComposeParameters:
        raise JsonlCsvEnrichmentComposeError(
            "reference parameters have wrong type"
        )
    parameters.__post_init__()
    left_rows, right_rows = _source_rows_reference(definition, parameters)
    policy = parameters.missing_field_policy
    left = _prepare_reference(left_rows, policy)
    right = _prepare_reference(right_rows, policy)
    _count_join_expansion(tuple(left), tuple(right))
    source_rejects: list[JsonlCsvSourceRejectEntry] = []
    rejects: list[JsonlCsvRejectEntry] = []
    if policy == "reject-source-file":
        event_map: dict[str, list[tuple[str, ...]]] = {
            path: [] for path in _SOURCE_PATHS
        }
        for row in left_rows:
            if row.missing_fields:
                event_map[row.source].append(row.missing_fields)
        for row in right_rows:
            if row.missing_fields:
                event_map[row.source].append(row.missing_fields)
        for left_row in left:
            found = False
            if left_row.joinable:
                for right_row in right:
                    if (
                        right_row.joinable
                        and left_row.identifier == right_row.identifier
                    ):
                        found = True
                        break
            if not found:
                event_map[
                    JSONL_CSV_ENRICHMENT_COMPOSE_RIGHT_INPUT
                ].append(("right",))
        for source in _SOURCE_PATHS:
            events = event_map[source]
            if events:
                names: set[str] = set()
                for event in events:
                    names.update(event)
                source_rejects.append(
                    JsonlCsvSourceRejectEntry(
                        source,
                        len(events),
                        tuple(sorted(names, key=_raw)),
                    )
                )
        if source_rejects:
            selected_sources = tuple(
                sorted(source_rejects, key=_source_reject_order)
            )
            output = _render_output(
                parameters, (), (), selected_sources
            )
            return JsonlCsvEnrichmentComposeState(
                parameters.join_layout,
                policy,
                (),
                (),
                selected_sources,
                output,
            )
    if policy == "emit-reject-row":
        for row in left_rows:
            if row.missing_fields:
                rejects.append(
                    JsonlCsvRejectEntry(
                        row.source,
                        row.index,
                        row.identifier,
                        row.missing_fields,
                    )
                )
        for row in right_rows:
            if row.missing_fields:
                rejects.append(
                    JsonlCsvRejectEntry(
                        row.source,
                        row.index,
                        row.identifier,
                        row.missing_fields,
                    )
                )
    enriched: list[JsonlCsvEnrichedEntry] = []
    for left_row in left:
        matches: list[_PreparedRow] = []
        if left_row.joinable:
            for right_row in right:
                if (
                    right_row.joinable
                    and left_row.identifier == right_row.identifier
                ):
                    matches.append(right_row)
        if matches:
            for match in matches:
                enriched.append(
                    JsonlCsvEnrichedEntry(
                        left_row.identifier,
                        left_row.value,
                        match.value,
                        True,
                    )
                )
        elif policy == "empty-string":
            enriched.append(
                JsonlCsvEnrichedEntry(
                    left_row.identifier, left_row.value, "", False
                )
            )
        elif policy == "null-value":
            enriched.append(
                JsonlCsvEnrichedEntry(
                    left_row.identifier, left_row.value, None, False
                )
            )
        elif policy == "emit-reject-row":
            rejects.append(
                JsonlCsvRejectEntry(
                    "join",
                    left_row.original.index,
                    left_row.identifier,
                    ("right",),
                )
            )
    _left_codec, _right_codec, intermediate = parameters.codecs
    enriched = _intermediate_roundtrip_reference(enriched, intermediate)
    selected_enriched = tuple(sorted(enriched, key=_enriched_order))
    selected_rejects = tuple(sorted(rejects, key=_reject_order))
    selected_sources = tuple(
        sorted(source_rejects, key=_source_reject_order)
    )
    output = _render_output(
        parameters,
        selected_enriched,
        selected_rejects,
        selected_sources,
    )
    return JsonlCsvEnrichmentComposeState(
        parameters.join_layout,
        policy,
        selected_enriched,
        selected_rejects,
        selected_sources,
        output,
    )


def _nullable_output_text(value: object, name: str) -> str | None:
    if value is None:
        return None
    return _validate_field(value, name)


def _enriched_from_object(
    value: dict[str, object],
) -> JsonlCsvEnrichedEntry:
    if set(value) != _ENRICHED_KEYS or value.get("record") != "enriched":
        raise JsonlCsvEnrichmentComposeError(
            "enriched output schema differs"
        )
    matched = value.get("matched")
    if type(matched) is not bool:
        raise JsonlCsvEnrichmentComposeError(
            "enriched matched has wrong type"
        )
    return JsonlCsvEnrichedEntry(
        _nullable_output_text(value.get("id"), "output id"),
        _nullable_output_text(value.get("left"), "output left"),
        _nullable_output_text(value.get("right"), "output right"),
        matched,
    )


def _reject_from_object(value: dict[str, object]) -> JsonlCsvRejectEntry:
    if set(value) != _REJECT_KEYS or value.get("record") != "reject":
        raise JsonlCsvEnrichmentComposeError("reject output schema differs")
    source = value.get("source")
    index = value.get("source_index")
    missing = value.get("missing_fields")
    if (
        type(source) is not str
        or type(index) is not int
        or type(missing) is not list
    ):
        raise JsonlCsvEnrichmentComposeError(
            "reject output members have wrong types"
        )
    return JsonlCsvRejectEntry(
        source,
        index,
        _nullable_output_text(value.get("id"), "reject output id"),
        tuple(missing),
    )


def _source_reject_from_object(
    value: dict[str, object],
) -> JsonlCsvSourceRejectEntry:
    if (
        set(value) != _SOURCE_REJECT_KEYS
        or value.get("record") != "source-reject"
    ):
        raise JsonlCsvEnrichmentComposeError(
            "source-reject output schema differs"
        )
    source = value.get("source")
    affected = value.get("affected_count")
    missing = value.get("missing_fields")
    reason = value.get("reason")
    if (
        type(source) is not str
        or type(affected) is not int
        or type(missing) is not list
        or type(reason) is not str
    ):
        raise JsonlCsvEnrichmentComposeError(
            "source-reject members have wrong types"
        )
    return JsonlCsvSourceRejectEntry(
        source, affected, tuple(missing), reason
    )


def parse_jsonl_csv_enrichment_compose_output(payload: bytes) -> bytes:
    """Validate semantic JSONL output and return canonical equivalent bytes."""

    if (
        type(payload) is not bytes
        or not payload
        or len(payload)
        > JSONL_CSV_ENRICHMENT_COMPOSE_OUTPUT_MAXIMUM_BYTES
        or not payload.endswith(b"\n")
        or b"\r" in payload
    ):
        raise JsonlCsvEnrichmentComposeError(
            "candidate output framing is invalid"
        )
    try:
        lines = payload[:-1].decode("utf-8", "strict").split("\n")
    except UnicodeDecodeError as exc:
        raise JsonlCsvEnrichmentComposeError(
            "candidate output is not strict UTF-8"
        ) from exc
    if not lines or any(not line for line in lines):
        raise JsonlCsvEnrichmentComposeError(
            "candidate output row framing is invalid"
        )
    header = _strict_json_object(lines[0])
    if set(header) != _HEADER_KEYS or header.get("record") != "compose":
        raise JsonlCsvEnrichmentComposeError(
            "candidate output header schema differs"
        )
    join_layout = _closed_text(
        header.get("join_layout"),
        JSONL_CSV_ENRICHMENT_COMPOSE_JOIN_LAYOUTS,
        "output join_layout",
    )
    policy = _closed_text(
        header.get("missing_field_policy"),
        JSONL_CSV_ENRICHMENT_COMPOSE_MISSING_FIELD_POLICIES,
        "output missing_field_policy",
    )
    for name in ("enriched_count", "reject_count", "source_reject_count"):
        count = header.get(name)
        if type(count) is not int or count < 0:
            raise JsonlCsvEnrichmentComposeError(
                "candidate header count has wrong type or range"
            )
    enriched: list[JsonlCsvEnrichedEntry] = []
    rejects: list[JsonlCsvRejectEntry] = []
    source_rejects: list[JsonlCsvSourceRejectEntry] = []
    phase = 0
    for line in lines[1:]:
        value = _strict_json_object(line)
        record = value.get("record")
        if record == "enriched":
            if phase != 0:
                raise JsonlCsvEnrichmentComposeError(
                    "enriched output appears after a rejection"
                )
            enriched.append(_enriched_from_object(value))
        elif record == "reject":
            if phase > 1:
                raise JsonlCsvEnrichmentComposeError(
                    "row rejection appears after source rejection"
                )
            phase = 1
            rejects.append(_reject_from_object(value))
        elif record == "source-reject":
            phase = 2
            source_rejects.append(_source_reject_from_object(value))
        else:
            raise JsonlCsvEnrichmentComposeError(
                "candidate output record kind is invalid"
            )
    if (
        header["enriched_count"] != len(enriched)
        or header["reject_count"] != len(rejects)
        or header["source_reject_count"] != len(source_rejects)
    ):
        raise JsonlCsvEnrichmentComposeError(
            "candidate header counts differ from rows"
        )
    parameters = JsonlCsvEnrichmentComposeParameters(
        join_layout, policy  # type: ignore[arg-type]
    )
    selected_enriched = tuple(enriched)
    selected_rejects = tuple(rejects)
    selected_sources = tuple(source_rejects)
    canonical = _render_output(
        parameters,
        selected_enriched,
        selected_rejects,
        selected_sources,
    )
    state = JsonlCsvEnrichmentComposeState(
        parameters.join_layout,
        parameters.missing_field_policy,
        selected_enriched,
        selected_rejects,
        selected_sources,
        canonical,
    )
    state.__post_init__()
    return canonical


def _expected_files() -> tuple[ExpectedFile, ...]:
    return (
        ExpectedFile(
            JSONL_CSV_ENRICHMENT_COMPOSE_OUTPUT,
            JSONL_CSV_ENRICHMENT_COMPOSE_OUTPUT_MAXIMUM_BYTES,
            JSONL_CSV_ENRICHMENT_COMPOSE_OUTPUT_MODE,
        ),
    )


def _oracle_sha256(
    state: JsonlCsvEnrichmentComposeState,
    parameters: JsonlCsvEnrichmentComposeParameters,
) -> str:
    state.__post_init__()
    parameters.__post_init__()
    if (
        state.join_layout != parameters.join_layout
        or state.missing_field_policy != parameters.missing_field_policy
    ):
        raise JsonlCsvEnrichmentComposeError(
            "oracle state differs from parameters"
        )
    return domain_sha256(
        "cbds.executable-fixture.trusted-oracle.v1",
        {
            "schema_version": EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION,
            "semantic_verifier_identity": (
                JSONL_CSV_ENRICHMENT_COMPOSE_VERIFIER_IDENTITY
            ),
            "parameters": parameters.to_record(),
            "state": state.commitment_record(),
        },
    )


@dataclass(frozen=True, slots=True)
class JsonlCsvEnrichmentComposeOracle:
    state: JsonlCsvEnrichmentComposeState = field(repr=False)
    join_layout: JoinLayout
    missing_field_policy: MissingFieldPolicy
    oracle_sha256: str
    semantic_verifier_identity: str = (
        JSONL_CSV_ENRICHMENT_COMPOSE_VERIFIER_IDENTITY
    )
    schema_version: str = EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        parameters = JsonlCsvEnrichmentComposeParameters(
            self.join_layout, self.missing_field_policy
        )
        self.state.__post_init__()
        if (
            type(self) is not JsonlCsvEnrichmentComposeOracle
            or self.semantic_verifier_identity
            != JSONL_CSV_ENRICHMENT_COMPOSE_VERIFIER_IDENTITY
            or self.schema_version
            != EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION
            or self.state.join_layout != self.join_layout
            or self.state.missing_field_policy != self.missing_field_policy
            or not _is_sha256(self.oracle_sha256)
            or self.oracle_sha256 != _oracle_sha256(self.state, parameters)
        ):
            raise JsonlCsvEnrichmentComposeError(
                "oracle identity is invalid"
            )

    def commitment_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "schema_version": self.schema_version,
            "record_type": "cbds.executable-fixture-trusted-oracle",
            "semantic_verifier_identity": self.semantic_verifier_identity,
            "join_layout": self.join_layout,
            "missing_field_policy": self.missing_field_policy,
            "state": self.state.commitment_record(),
            "oracle_sha256": self.oracle_sha256,
        }


@dataclass(frozen=True, slots=True)
class JsonlCsvEnrichmentComposeFixtureBundle:
    task_contract_sha256: str
    profile_sha256: str
    definition: FixtureDefinition = field(repr=False)
    fixture_definition_sha256: str
    oracle: JsonlCsvEnrichmentComposeOracle = field(repr=False)
    descriptor: OpaqueFixtureDescriptor
    schema_version: str = EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_jsonl_csv_enrichment_compose_fixture_bundle(self)

    def commitment_record(self) -> dict[str, object]:
        validate_jsonl_csv_enrichment_compose_fixture_bundle(self)
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


def validate_jsonl_csv_enrichment_compose_fixture_bundle(
    bundle: JsonlCsvEnrichmentComposeFixtureBundle,
) -> None:
    if type(bundle) is not JsonlCsvEnrichmentComposeFixtureBundle:
        raise JsonlCsvEnrichmentComposeError(
            "bundle has wrong exact type"
        )
    if (
        bundle.schema_version != EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION
        or not _is_sha256(bundle.task_contract_sha256)
        or not _is_sha256(bundle.profile_sha256)
        or not _is_sha256(bundle.fixture_definition_sha256)
        or bundle.candidate_execution_authorized is not False
        or bundle.model_selection_eligible is not False
        or bundle.claim_authorized is not False
    ):
        raise JsonlCsvEnrichmentComposeError(
            "bundle metadata is invalid"
        )
    definition = _revalidate_definition(bundle.definition)
    definition_sha256 = compute_fixture_definition_semantic_sha256(
        definition
    )
    if definition_sha256 != bundle.fixture_definition_sha256:
        raise JsonlCsvEnrichmentComposeError(
            "fixture definition digest differs"
        )
    if type(bundle.oracle) is not JsonlCsvEnrichmentComposeOracle:
        raise JsonlCsvEnrichmentComposeError(
            "oracle has wrong exact type"
        )
    bundle.oracle.__post_init__()
    if definition.expected_files != _expected_files():
        raise JsonlCsvEnrichmentComposeError("output policy differs")
    parameters = JsonlCsvEnrichmentComposeParameters(
        bundle.oracle.join_layout,
        bundle.oracle.missing_field_policy,
    )
    primary = derive_jsonl_csv_enrichment_compose_state(
        definition, parameters
    )
    reference = reference_jsonl_csv_enrichment_compose_state(
        definition, parameters
    )
    if primary != reference or primary != bundle.oracle.state:
        raise JsonlCsvEnrichmentComposeError(
            "oracle differs from independent derivations"
        )
    if type(bundle.descriptor) is not OpaqueFixtureDescriptor:
        raise JsonlCsvEnrichmentComposeError(
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
        raise JsonlCsvEnrichmentComposeError(
            "descriptor binding differs"
        )


def verify_jsonl_csv_enrichment_compose_fixture_bundle(
    bundle: object,
) -> bool:
    try:
        validate_jsonl_csv_enrichment_compose_fixture_bundle(
            bundle  # type: ignore[arg-type]
        )
    except (
        AttributeError,
        JsonlCsvEnrichmentComposeError,
        TypeError,
        ValueError,
    ):
        return False
    return True


def _validate_task_profile(
    task: object,
    profile: object,
) -> tuple[JsonlCsvEnrichmentComposeTask, ExecutableFixtureProfile]:
    if type(task) is not JsonlCsvEnrichmentComposeTask:
        raise JsonlCsvEnrichmentComposeError("task has wrong exact type")
    if type(profile) is not ExecutableFixtureProfile:
        raise JsonlCsvEnrichmentComposeError(
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
        raise JsonlCsvEnrichmentComposeError(
            "task/profile reconstruction failed"
        ) from exc
    if rebuilt not in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
        raise JsonlCsvEnrichmentComposeError(
            "profile is outside public method development"
        )
    return task, profile


def _construct_jsonl_csv_enrichment_compose_fixture_bundle(
    task: JsonlCsvEnrichmentComposeTask,
    profile: ExecutableFixtureProfile,
) -> JsonlCsvEnrichmentComposeFixtureBundle:
    task, profile = _validate_task_profile(task, profile)
    inputs = _fixture_inputs(profile, task.parameters)
    provisional = FixtureDefinition(
        f"fixture.{task.task_id}.{profile.profile_id}",
        inputs,
        (),
    )
    primary = derive_jsonl_csv_enrichment_compose_state(
        provisional, task.parameters
    )
    reference = reference_jsonl_csv_enrichment_compose_state(
        provisional, task.parameters
    )
    if primary != reference:
        raise JsonlCsvEnrichmentComposeError(
            "independent composition engines disagree"
        )
    definition = FixtureDefinition(
        provisional.fixture_id,
        inputs,
        _expected_files(),
    )
    if (
        derive_jsonl_csv_enrichment_compose_state(
            definition, task.parameters
        )
        != primary
        or reference_jsonl_csv_enrichment_compose_state(
            definition, task.parameters
        )
        != reference
    ):
        raise JsonlCsvEnrichmentComposeError(
            "final output policy changed semantics"
        )
    oracle = JsonlCsvEnrichmentComposeOracle(
        primary,
        task.parameters.join_layout,
        task.parameters.missing_field_policy,
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
    return JsonlCsvEnrichmentComposeFixtureBundle(
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


def build_jsonl_csv_enrichment_compose_fixture_bundle(
    task: JsonlCsvEnrichmentComposeTask,
    profile: ExecutableFixtureProfile,
) -> JsonlCsvEnrichmentComposeFixtureBundle:
    selected_task, selected_profile = _validate_task_profile(task, profile)
    bundle = _construct_jsonl_csv_enrichment_compose_fixture_bundle(
        selected_task, selected_profile
    )
    index = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES.index(selected_profile)
    if selected_task.fixtures[index] != bundle.descriptor:
        raise JsonlCsvEnrichmentComposeError(
            "task descriptor differs from reconstructed fixture"
        )
    return bundle


def validate_jsonl_csv_enrichment_compose_fixture_for_task_profile(
    task: JsonlCsvEnrichmentComposeTask,
    profile: ExecutableFixtureProfile,
    bundle: JsonlCsvEnrichmentComposeFixtureBundle,
) -> None:
    selected_task, selected_profile = _validate_task_profile(task, profile)
    validate_jsonl_csv_enrichment_compose_fixture_bundle(bundle)
    expected = _construct_jsonl_csv_enrichment_compose_fixture_bundle(
        selected_task, selected_profile
    )
    if expected != bundle:
        raise JsonlCsvEnrichmentComposeError(
            "bundle differs from deterministic reconstruction"
        )
    index = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES.index(selected_profile)
    if selected_task.fixtures[index] != bundle.descriptor:
        raise JsonlCsvEnrichmentComposeError(
            "public descriptor differs from private binding"
        )


def verify_jsonl_csv_enrichment_compose_fixture_for_task_profile(
    task: object,
    profile: object,
    bundle: object,
) -> bool:
    try:
        validate_jsonl_csv_enrichment_compose_fixture_for_task_profile(
            task,  # type: ignore[arg-type]
            profile,  # type: ignore[arg-type]
            bundle,  # type: ignore[arg-type]
        )
    except (
        AttributeError,
        JsonlCsvEnrichmentComposeError,
        TypeError,
        ValueError,
    ):
        return False
    return True


def _discrimination_signature(
    bundle: JsonlCsvEnrichmentComposeFixtureBundle,
) -> tuple[str, str, str]:
    left = _source_input(
        bundle.definition, JSONL_CSV_ENRICHMENT_COMPOSE_LEFT_INPUT
    )
    right = _source_input(
        bundle.definition, JSONL_CSV_ENRICHMENT_COMPOSE_RIGHT_INPUT
    )
    state = bundle.oracle.state
    return (
        sha256(left.content).hexdigest(),
        sha256(right.content).hexdigest(),
        domain_sha256(
            "cbds.executable-static.jsonl-csv-enrichment-compose."
            "semantic-body.v1",
            {
                "enriched": [
                    item.to_json_record() for item in state.enriched
                ],
                "rejects": [
                    item.to_json_record() for item in state.rejects
                ],
                "source_rejects": [
                    item.to_json_record()
                    for item in state.source_rejects
                ],
            },
        ),
    )


def compute_jsonl_csv_enrichment_compose_discrimination_sha256(
    tasks: tuple[JsonlCsvEnrichmentComposeTask, ...],
) -> str:
    expected = tuple(
        (layout, policy)
        for layout in JSONL_CSV_ENRICHMENT_COMPOSE_JOIN_LAYOUTS
        for policy in JSONL_CSV_ENRICHMENT_COMPOSE_MISSING_FIELD_POLICIES
    )
    if (
        type(tasks) is not tuple
        or len(tasks) != 20
        or any(
            type(task) is not JsonlCsvEnrichmentComposeTask
            for task in tasks
        )
        or tuple(
            (
                task.parameters.join_layout,
                task.parameters.missing_field_policy,
            )
            for task in tasks
        )
        != expected
    ):
        raise JsonlCsvEnrichmentComposeError(
            "discrimination requires canonical 20-cell task order"
        )
    profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
    signatures: list[tuple[str, str, str]] = []
    records: list[dict[str, object]] = []
    for task in tasks:
        bundle = _construct_jsonl_csv_enrichment_compose_fixture_bundle(
            task, profile
        )
        signature = _discrimination_signature(bundle)
        signatures.append(signature)
        records.append(
            {
                "task_id": task.task_id,
                "join_layout": task.parameters.join_layout,
                "missing_field_policy": (
                    task.parameters.missing_field_policy
                ),
                "left_sha256": signature[0],
                "right_sha256": signature[1],
                "semantic_body_sha256": signature[2],
                "enriched_count": len(bundle.oracle.state.enriched),
                "reject_count": len(bundle.oracle.state.rejects),
                "source_reject_count": len(
                    bundle.oracle.state.source_rejects
                ),
                "output_sha256": sha256(
                    bundle.oracle.state.output
                ).hexdigest(),
                "fixture_sha256": bundle.descriptor.fixture_sha256,
            }
        )
    if len(set(signatures)) != 20:
        raise JsonlCsvEnrichmentComposeError(
            "task grid is not behaviorally discriminable"
        )
    return domain_sha256(
        "cbds.executable-static.jsonl-csv-enrichment-compose."
        "discrimination-evidence.v1",
        {
            "family_id": JSONL_CSV_ENRICHMENT_COMPOSE_FAMILY_ID,
            "profile_sha256": profile.profile_sha256,
            "signature_count": len(records),
            "signatures": records,
        },
    )


def build_jsonl_csv_enrichment_compose_tasks() -> tuple[
    JsonlCsvEnrichmentComposeTask, ...
]:
    tasks: list[JsonlCsvEnrichmentComposeTask] = []
    signatures: list[tuple[str, str, str]] = []
    for layout in JSONL_CSV_ENRICHMENT_COMPOSE_JOIN_LAYOUTS:
        for policy in JSONL_CSV_ENRICHMENT_COMPOSE_MISSING_FIELD_POLICIES:
            bootstrap = _bootstrap_task(
                JsonlCsvEnrichmentComposeParameters(layout, policy)
            )
            bundles = tuple(
                _construct_jsonl_csv_enrichment_compose_fixture_bundle(
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
        raise JsonlCsvEnrichmentComposeError(
            "task grid is not 20 discriminable cells"
        )
    return selected


def compute_jsonl_csv_enrichment_compose_proved_output_bound() -> int:
    """Reconstruct the conservative canonical-output size proof."""

    worst = "\\" * JSONL_CSV_ENRICHMENT_COMPOSE_FIELD_MAXIMUM_UTF8_BYTES
    header = _json_line(
        {
            "record": "compose",
            "join_layout": "jsonl-both-with-csv-output",
            "missing_field_policy": "reject-source-file",
            "enriched_count": (
                JSONL_CSV_ENRICHMENT_COMPOSE_MAXIMUM_ENRICHED_ROWS
            ),
            "reject_count": (
                2
                * JSONL_CSV_ENRICHMENT_COMPOSE_MAXIMUM_PHYSICAL_RECORDS
            ),
            "source_reject_count": 2,
        }
    )
    enriched = _json_line(
        JsonlCsvEnrichedEntry(
            worst, worst, worst, False
        ).to_json_record()
    )
    reject = _json_line(
        JsonlCsvRejectEntry(
            JSONL_CSV_ENRICHMENT_COMPOSE_RIGHT_INPUT,
            JSONL_CSV_ENRICHMENT_COMPOSE_MAXIMUM_PHYSICAL_RECORDS - 1,
            worst,
            ("id", "right"),
        ).to_json_record()
    )
    source_reject = _json_line(
        JsonlCsvSourceRejectEntry(
            JSONL_CSV_ENRICHMENT_COMPOSE_RIGHT_INPUT,
            (
                JSONL_CSV_ENRICHMENT_COMPOSE_MAXIMUM_ENRICHED_ROWS
                + JSONL_CSV_ENRICHMENT_COMPOSE_MAXIMUM_PHYSICAL_RECORDS
            ),
            ("id", "right"),
        ).to_json_record()
    )
    result = (
        len(header)
        + JSONL_CSV_ENRICHMENT_COMPOSE_MAXIMUM_ENRICHED_ROWS
        * len(enriched)
        + 2
        * JSONL_CSV_ENRICHMENT_COMPOSE_MAXIMUM_PHYSICAL_RECORDS
        * len(reject)
        + 2 * len(source_reject)
    )
    if (
        result
        != JSONL_CSV_ENRICHMENT_COMPOSE_PROVED_MAXIMUM_CANONICAL_OUTPUT_BYTES
        or result > JSONL_CSV_ENRICHMENT_COMPOSE_OUTPUT_MAXIMUM_BYTES
    ):
        raise JsonlCsvEnrichmentComposeError(
            "canonical output bound proof differs"
        )
    return result


def materialize_jsonl_csv_enrichment_compose_fixture(
    task: JsonlCsvEnrichmentComposeTask,
    profile: ExecutableFixtureProfile,
    bundle: JsonlCsvEnrichmentComposeFixtureBundle,
    workspace: str | os.PathLike[str],
) -> WorkspaceHandle:
    validate_jsonl_csv_enrichment_compose_fixture_for_task_profile(
        task, profile, bundle
    )
    return materialize_fixture(bundle.definition, workspace)


def verify_jsonl_csv_enrichment_compose_workspace(
    task: JsonlCsvEnrichmentComposeTask,
    profile: ExecutableFixtureProfile,
    bundle: JsonlCsvEnrichmentComposeFixtureBundle,
    handle: WorkspaceHandle,
) -> bool:
    """Verify exact semantic output and preserved pinned input state."""

    if type(handle) is not WorkspaceHandle:
        return False
    try:
        validate_jsonl_csv_enrichment_compose_fixture_for_task_profile(
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
        primary = derive_jsonl_csv_enrichment_compose_state(
            bundle.definition, task.parameters
        )
        reference = reference_jsonl_csv_enrichment_compose_state(
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
            != JSONL_CSV_ENRICHMENT_COMPOSE_OUTPUT
            or output_entries[0].mode
            != JSONL_CSV_ENRICHMENT_COMPOSE_OUTPUT_MODE
            or output_entries[0].link_count != 1
            or output_entries[0].hardlink_group_sha256 is not None
        ):
            return False
        observed = handle.read_output_bytes(
            output_scan, JSONL_CSV_ENRICHMENT_COMPOSE_OUTPUT
        )
        if (
            parse_jsonl_csv_enrichment_compose_output(observed)
            != primary.output
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
        JsonlCsvEnrichmentComposeError,
        ExecutableWorkspaceError,
        OSError,
        TypeError,
        ValueError,
    ):
        return False


__all__ = [
    "JSONL_CSV_ENRICHMENT_COMPOSE_ALLOWED_TOOLS",
    "JSONL_CSV_ENRICHMENT_COMPOSE_ATOMICITY_OBSERVED",
    "JSONL_CSV_ENRICHMENT_COMPOSE_CANDIDATE_EXIT_STATUS_OBSERVED",
    "JSONL_CSV_ENRICHMENT_COMPOSE_FAMILY_ID",
    "JSONL_CSV_ENRICHMENT_COMPOSE_FIELD_MAXIMUM_UTF8_BYTES",
    "JSONL_CSV_ENRICHMENT_COMPOSE_FILESYSTEM_IDENTITY",
    "JSONL_CSV_ENRICHMENT_COMPOSE_FINAL_OUTPUT_OBSERVED",
    "JSONL_CSV_ENRICHMENT_COMPOSE_GENERATOR_VERSION",
    "JSONL_CSV_ENRICHMENT_COMPOSE_INPUT_PRESERVATION_OBSERVED",
    "JSONL_CSV_ENRICHMENT_COMPOSE_INTERMEDIATE_MATERIALIZATION_OBSERVED",
    "JSONL_CSV_ENRICHMENT_COMPOSE_JOIN_LAYOUTS",
    "JSONL_CSV_ENRICHMENT_COMPOSE_LEFT_INPUT",
    "JSONL_CSV_ENRICHMENT_COMPOSE_MAXIMUM_ENRICHED_ROWS",
    "JSONL_CSV_ENRICHMENT_COMPOSE_MAXIMUM_PHYSICAL_RECORDS",
    "JSONL_CSV_ENRICHMENT_COMPOSE_MISSING_FIELD_POLICIES",
    "JSONL_CSV_ENRICHMENT_COMPOSE_OUTPUT",
    "JSONL_CSV_ENRICHMENT_COMPOSE_OUTPUT_IDENTITY",
    "JSONL_CSV_ENRICHMENT_COMPOSE_OUTPUT_MAXIMUM_BYTES",
    "JSONL_CSV_ENRICHMENT_COMPOSE_OUTPUT_MODE",
    "JSONL_CSV_ENRICHMENT_COMPOSE_PROVED_MAXIMUM_CANONICAL_OUTPUT_BYTES",
    "JSONL_CSV_ENRICHMENT_COMPOSE_READ_SCOPE_OBSERVED",
    "JSONL_CSV_ENRICHMENT_COMPOSE_RIGHT_INPUT",
    "JSONL_CSV_ENRICHMENT_COMPOSE_SOURCE_MAXIMUM_BYTES",
    "JSONL_CSV_ENRICHMENT_COMPOSE_TOOL_HISTORY_OBSERVED",
    "JSONL_CSV_ENRICHMENT_COMPOSE_TRANSIENT_STATE_OBSERVED",
    "JSONL_CSV_ENRICHMENT_COMPOSE_VERIFIER_IDENTITY",
    "JSONL_CSV_ENRICHMENT_COMPOSE_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE",
    "JSONL_CSV_ENRICHMENT_COMPOSE_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE",
    "JsonlCsvEnrichedEntry",
    "JsonlCsvEnrichmentComposeError",
    "JsonlCsvEnrichmentComposeFixtureBundle",
    "JsonlCsvEnrichmentComposeOracle",
    "JsonlCsvEnrichmentComposeParameters",
    "JsonlCsvEnrichmentComposeState",
    "JsonlCsvEnrichmentComposeTask",
    "JsonlCsvRejectEntry",
    "JsonlCsvSourceRejectEntry",
    "build_jsonl_csv_enrichment_compose_fixture_bundle",
    "build_jsonl_csv_enrichment_compose_tasks",
    "compute_jsonl_csv_enrichment_compose_discrimination_sha256",
    "compute_jsonl_csv_enrichment_compose_proved_output_bound",
    "compute_jsonl_csv_enrichment_compose_task_sha256",
    "derive_jsonl_csv_enrichment_compose_state",
    "jsonl_csv_enrichment_compose_task_semantic_core",
    "materialize_jsonl_csv_enrichment_compose_fixture",
    "parse_jsonl_csv_enrichment_compose_output",
    "parse_jsonl_csv_enrichment_source",
    "reference_jsonl_csv_enrichment_compose_state",
    "validate_jsonl_csv_enrichment_compose_fixture_bundle",
    "validate_jsonl_csv_enrichment_compose_fixture_for_task_profile",
    "verify_jsonl_csv_enrichment_compose_fixture_bundle",
    "verify_jsonl_csv_enrichment_compose_fixture_for_task_profile",
    "verify_jsonl_csv_enrichment_compose_workspace",
]
