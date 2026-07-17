"""Executable-static migration of bounded, nested JSON document sets.

The family decodes one of four closed source shapes, validates a strict v1
document schema, applies one of five exact migrations, and publishes a
numbered set of v2 JSON documents plus a manifest.  The trusted primary and
reference paths share Python's bounded JSON tokenization boundary but
independently construct migrated records.

This is public method-development infrastructure.  It does not execute a
candidate, authorize scored evaluation, expose sealed data, or support a
model-quality claim.  The workspace verifier establishes only the final
bounded output tree and preservation of pinned inputs under trusted
quiescence.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field, replace
from hashlib import sha256
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


NESTED_JSON_SCHEMA_MIGRATION_FAMILY_ID: Final[str] = (
    "nested-json-schema-migration"
)
NESTED_JSON_SCHEMA_MIGRATION_FILESYSTEM_IDENTITY: Final[str] = (
    "versioned-nested-json-documents"
)
NESTED_JSON_SCHEMA_MIGRATION_OUTPUT_IDENTITY: Final[str] = (
    "schema-migrated-json-document-set"
)
NESTED_JSON_SCHEMA_MIGRATION_GENERATOR_VERSION: Final[str] = "1.0.0"
NESTED_JSON_SCHEMA_MIGRATION_VERIFIER_IDENTITY: Final[str] = (
    "verify-nested-json-schema-migration-v1"
)
NESTED_JSON_SCHEMA_MIGRATION_INPUT: Final[str] = "input/documents.data"
NESTED_JSON_SCHEMA_MIGRATION_OUTPUT_MANIFEST: Final[str] = (
    "output/manifest.json"
)
NESTED_JSON_SCHEMA_MIGRATION_OUTPUT_DIRECTORY: Final[str] = (
    "output/documents"
)
NESTED_JSON_SCHEMA_MIGRATION_OUTPUT_MODE: Final[int] = 0o644
NESTED_JSON_SCHEMA_MIGRATION_SOURCE_MAXIMUM_BYTES: Final[int] = 128 * 1024
NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_DOCUMENTS: Final[int] = 32
NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_DEPTH: Final[int] = 8
NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_NODES: Final[int] = 4_096
NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_OBJECT_MEMBERS: Final[int] = 128
NESTED_JSON_SCHEMA_MIGRATION_SCALAR_MAXIMUM_UTF8_BYTES: Final[int] = 128
NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_TAGS: Final[int] = 16
NESTED_JSON_SCHEMA_MIGRATION_QUOTA_MAXIMUM: Final[int] = 1_000_000
NESTED_JSON_SCHEMA_MIGRATION_DOCUMENT_OUTPUT_MAXIMUM_BYTES: Final[int] = (
    8 * 1024
)
NESTED_JSON_SCHEMA_MIGRATION_MANIFEST_OUTPUT_MAXIMUM_BYTES: Final[int] = (
    32 * 1024
)
NESTED_JSON_SCHEMA_MIGRATION_PROVED_MAXIMUM_TOTAL_OUTPUT_BYTES: Final[int] = (
    NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_DOCUMENTS
    * NESTED_JSON_SCHEMA_MIGRATION_DOCUMENT_OUTPUT_MAXIMUM_BYTES
    + NESTED_JSON_SCHEMA_MIGRATION_MANIFEST_OUTPUT_MAXIMUM_BYTES
)
NESTED_JSON_SCHEMA_MIGRATION_ALLOWED_TOOLS: Final[tuple[str, ...]] = (
    "mkdir",
    "python3",
    "sort",
)

# Honest final-state observation boundaries.
NESTED_JSON_SCHEMA_MIGRATION_FINAL_OUTPUT_OBSERVED: Final[bool] = True
NESTED_JSON_SCHEMA_MIGRATION_INPUT_PRESERVATION_OBSERVED: Final[bool] = True
NESTED_JSON_SCHEMA_MIGRATION_ATOMICITY_OBSERVED: Final[bool] = False
NESTED_JSON_SCHEMA_MIGRATION_TOOL_HISTORY_OBSERVED: Final[bool] = False
NESTED_JSON_SCHEMA_MIGRATION_READ_SCOPE_OBSERVED: Final[bool] = False
NESTED_JSON_SCHEMA_MIGRATION_CANDIDATE_EXIT_STATUS_OBSERVED: Final[
    bool
] = False
NESTED_JSON_SCHEMA_MIGRATION_TRANSIENT_STATE_OBSERVED: Final[bool] = False
NESTED_JSON_SCHEMA_MIGRATION_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE: Final[
    bool
] = True
NESTED_JSON_SCHEMA_MIGRATION_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE: Final[
    bool
] = False

InputShape: TypeAlias = Literal[
    "single-object",
    "object-array",
    "keyed-object-map",
    "jsonl-objects",
]
MigrationPolicy: TypeAlias = Literal[
    "rename-fields",
    "normalize-types",
    "lift-nested-members",
    "drop-deprecated-members",
    "combined-version-upgrade",
]

NESTED_JSON_SCHEMA_MIGRATION_INPUT_SHAPES: Final[
    tuple[InputShape, ...]
] = (
    "single-object",
    "object-array",
    "keyed-object-map",
    "jsonl-objects",
)
NESTED_JSON_SCHEMA_MIGRATION_POLICIES: Final[
    tuple[MigrationPolicy, ...]
] = (
    "rename-fields",
    "normalize-types",
    "lift-nested-members",
    "drop-deprecated-members",
    "combined-version-upgrade",
)

_TASK_ID_RE: Final[re.Pattern[str]] = re.compile(r"mds-[0-9a-f]{24}\Z")
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_CANONICAL_DECIMAL_RE: Final[re.Pattern[str]] = re.compile(
    r"-?(?:0|[1-9][0-9]{0,6})\Z"
)
_V1_TOP_KEYS: Final[frozenset[str]] = frozenset(
    {"schema_version", "record_id", "profile", "tags", "deprecated"}
)
_V1_PROFILE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "display_name",
        "enabled",
        "limits",
        "contact",
        "deprecated_code",
    }
)
_LIMIT_KEYS: Final[frozenset[str]] = frozenset({"quota"})
_CONTACT_KEYS: Final[frozenset[str]] = frozenset({"email"})
_DEPRECATED_KEYS: Final[frozenset[str]] = frozenset({"note"})
_MANIFEST_KEYS: Final[frozenset[str]] = frozenset(
    {
        "input_shape",
        "migration_policy",
        "document_count",
        "entries",
    }
)
_MANIFEST_ENTRY_KEYS: Final[frozenset[str]] = frozenset(
    {"file", "source_index", "source_key"}
)


class NestedJsonSchemaMigrationError(ValueError):
    """Raised when a nested JSON migration contract is violated."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def _closed_text(
    value: object,
    allowed: tuple[str, ...],
    field_name: str,
) -> str:
    if type(value) is not str or value not in allowed:
        raise NestedJsonSchemaMigrationError(
            f"{field_name} is outside its closed set"
        )
    return value


def _validate_string(
    value: object,
    field_name: str,
    *,
    nonempty: bool = False,
) -> str:
    if type(value) is not str or (nonempty and not value):
        raise NestedJsonSchemaMigrationError(
            f"{field_name} must be an exact string"
        )
    if any(
        unicodedata.category(character) in {"Cc", "Cf"}
        for character in value
    ):
        raise NestedJsonSchemaMigrationError(
            f"{field_name} contains a control character"
        )
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise NestedJsonSchemaMigrationError(
            f"{field_name} is not strict UTF-8 text"
        ) from exc
    if len(encoded) > NESTED_JSON_SCHEMA_MIGRATION_SCALAR_MAXIMUM_UTF8_BYTES:
        raise NestedJsonSchemaMigrationError(
            f"{field_name} exceeds its UTF-8 bound"
        )
    return value


def _validate_enabled(value: object) -> bool | int | str:
    if type(value) is bool:
        return value
    if type(value) is int and value in {0, 1}:
        return value
    if type(value) is str and value in {
        "true",
        "false",
        "yes",
        "no",
        "1",
        "0",
    }:
        return value
    raise NestedJsonSchemaMigrationError(
        "profile.enabled is outside its closed representation set"
    )


def _validate_quota(value: object) -> int | str:
    if type(value) is int:
        if abs(value) <= NESTED_JSON_SCHEMA_MIGRATION_QUOTA_MAXIMUM:
            return value
    elif (
        type(value) is str
        and value != "-0"
        and _CANONICAL_DECIMAL_RE.fullmatch(value)
    ):
        parsed = int(value)
        if abs(parsed) <= NESTED_JSON_SCHEMA_MIGRATION_QUOTA_MAXIMUM:
            return value
    raise NestedJsonSchemaMigrationError(
        "profile.limits.quota is not a bounded exact integer or decimal"
    )


def _validate_tags(value: object) -> str | list[str]:
    if type(value) is str:
        return _validate_string(value, "tags")
    if (
        type(value) is not list
        or len(value) > NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_TAGS
    ):
        raise NestedJsonSchemaMigrationError(
            "tags must be one string or a bounded string array"
        )
    for item in value:
        _validate_string(item, "tags item")
    return value


def _require_exact_keys(
    value: object,
    required: frozenset[str],
    allowed: frozenset[str],
    field_name: str,
) -> dict[str, object]:
    if type(value) is not dict:
        raise NestedJsonSchemaMigrationError(
            f"{field_name} must be an exact object"
        )
    keys = set(value)
    if not required <= keys or not keys <= allowed:
        raise NestedJsonSchemaMigrationError(
            f"{field_name} has missing or extra members"
        )
    return value


def _validate_v1_document(value: object) -> dict[str, object]:
    document = _require_exact_keys(
        value,
        frozenset({"schema_version", "record_id", "profile"}),
        _V1_TOP_KEYS,
        "v1 document",
    )
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != 1
    ):
        raise NestedJsonSchemaMigrationError(
            "schema_version must be exact integer 1"
        )
    _validate_string(document["record_id"], "record_id", nonempty=True)
    profile = _require_exact_keys(
        document["profile"],
        frozenset({"display_name", "enabled"}),
        _V1_PROFILE_KEYS,
        "profile",
    )
    _validate_string(profile["display_name"], "profile.display_name")
    _validate_enabled(profile["enabled"])
    if "limits" in profile:
        limits = _require_exact_keys(
            profile["limits"],
            _LIMIT_KEYS,
            _LIMIT_KEYS,
            "profile.limits",
        )
        _validate_quota(limits["quota"])
    if "contact" in profile:
        contact = _require_exact_keys(
            profile["contact"],
            _CONTACT_KEYS,
            _CONTACT_KEYS,
            "profile.contact",
        )
        _validate_string(contact["email"], "profile.contact.email")
    if "deprecated_code" in profile:
        _validate_string(
            profile["deprecated_code"],
            "profile.deprecated_code",
        )
    if "tags" in document:
        _validate_tags(document["tags"])
    if "deprecated" in document:
        deprecated = _require_exact_keys(
            document["deprecated"],
            _DEPRECATED_KEYS,
            _DEPRECATED_KEYS,
            "deprecated",
        )
        _validate_string(deprecated["note"], "deprecated.note")
    return document


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
            if depth > NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_DEPTH:
                raise NestedJsonSchemaMigrationError(
                    "JSON exceeds the nesting-depth bound"
                )
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise NestedJsonSchemaMigrationError(
                    "JSON delimiters are unbalanced"
                )
    if in_string or escaped or depth != 0:
        raise NestedJsonSchemaMigrationError(
            "JSON lexical framing is incomplete"
        )


def _bounded_parse_int(token: str) -> int:
    if len(token.lstrip("-")) > 7:
        raise NestedJsonSchemaMigrationError(
            "JSON integer token exceeds its digit bound"
        )
    value = int(token)
    if abs(value) > NESTED_JSON_SCHEMA_MIGRATION_QUOTA_MAXIMUM:
        raise NestedJsonSchemaMigrationError(
            "JSON integer exceeds its magnitude bound"
        )
    return value


def _reject_float(token: str) -> object:
    raise NestedJsonSchemaMigrationError(
        f"JSON floating-point token is forbidden: {token[:16]}"
    )


def _reject_constant(token: str) -> object:
    raise NestedJsonSchemaMigrationError(
        f"JSON nonfinite token is forbidden: {token}"
    )


def _reject_duplicate_object(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    if len(pairs) > NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_OBJECT_MEMBERS:
        raise NestedJsonSchemaMigrationError(
            "JSON object exceeds its member bound"
        )
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise NestedJsonSchemaMigrationError(
                "JSON object contains a duplicate key"
            )
        result[key] = value
    return result


def _validate_json_tree(root: object) -> None:
    stack: list[tuple[object, int]] = [(root, 1)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if (
            nodes > NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_NODES
            or depth > NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_DEPTH
        ):
            raise NestedJsonSchemaMigrationError(
                "JSON tree exceeds its node or depth bound"
            )
        if type(value) is dict:
            if (
                len(value)
                > NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_OBJECT_MEMBERS
            ):
                raise NestedJsonSchemaMigrationError(
                    "JSON object exceeds its member bound"
                )
            for key, item in value.items():
                _validate_string(key, "JSON object key")
                stack.append((item, depth + 1))
        elif type(value) is list:
            if len(value) > NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_NODES:
                raise NestedJsonSchemaMigrationError(
                    "JSON array exceeds its element bound"
                )
            stack.extend((item, depth + 1) for item in value)
        elif type(value) is str:
            _validate_string(value, "JSON string")
        elif value is None or type(value) in {bool, int}:
            continue
        else:
            raise NestedJsonSchemaMigrationError(
                "JSON contains an unsupported scalar type"
            )


def _decode_json_strict(payload: bytes) -> object:
    if type(payload) is not bytes or not payload:
        raise NestedJsonSchemaMigrationError(
            "JSON payload must be nonempty immutable bytes"
        )
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise NestedJsonSchemaMigrationError(
            "JSON payload is not strict UTF-8"
        ) from exc
    if text.startswith("\ufeff"):
        raise NestedJsonSchemaMigrationError("JSON BOM is forbidden")
    _prebound_json_text(text)
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_object,
            parse_int=_bounded_parse_int,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except NestedJsonSchemaMigrationError:
        raise
    except (
        json.JSONDecodeError,
        RecursionError,
        TypeError,
        ValueError,
    ) as exc:
        raise NestedJsonSchemaMigrationError(
            "JSON payload is outside the strict grammar"
        ) from exc
    _validate_json_tree(value)
    return value


@dataclass(frozen=True, slots=True)
class NestedJsonSchemaMigrationParameters:
    input_shape: InputShape
    migration_policy: MigrationPolicy

    def __post_init__(self) -> None:
        if type(self) is not NestedJsonSchemaMigrationParameters:
            raise NestedJsonSchemaMigrationError(
                "parameters have wrong exact type"
            )
        _closed_text(
            self.input_shape,
            NESTED_JSON_SCHEMA_MIGRATION_INPUT_SHAPES,
            "input_shape",
        )
        _closed_text(
            self.migration_policy,
            NESTED_JSON_SCHEMA_MIGRATION_POLICIES,
            "migration_policy",
        )

    def to_record(self) -> dict[str, str]:
        self.__post_init__()
        return {
            "parameter_type": NESTED_JSON_SCHEMA_MIGRATION_FAMILY_ID,
            "input_shape": self.input_shape,
            "migration_policy": self.migration_policy,
        }


def _task_contract(
    parameters: NestedJsonSchemaMigrationParameters,
) -> tuple[str, NormalizedSemanticGraph]:
    prompt = f"""Write one Bash program that operates only in the current workspace.

Read only `input/documents.data` as `{parameters.input_shape}`.  The source is
strict UTF-8 JSON bounded to 131072 bytes, 32 logical documents, depth 8 and
4096 JSON nodes.  `single-object` is one full v1 object; `object-array` is an
array preserving source order; `keyed-object-map` is a map ordered by raw
UTF-8 key bytes whose key must equal the full value's `record_id`;
`jsonl-objects` is one exact object per LF-terminated nonempty line.

Every v1 document is closed: exact integer `schema_version`=1, nonempty string
`record_id`, and `profile` with string `display_name` plus `enabled`.
`profile` may also contain `limits` with `quota`, `contact` with string
`email`, and string `deprecated_code`.  A document may contain `tags` as one
string or a string array and `deprecated` with string `note`.  Strings are
strict UTF-8, control-free and at most 128 bytes.  `enabled` is an exact bool,
integer 0/1, or one of `true,false,yes,no,1,0`; `quota` is an exact bounded
integer or canonical decimal string.

Apply `{parameters.migration_policy}` and set every output `schema_version` to
2.  `rename-fields` renames top `record_id` to `id` and
`profile.display_name` to `profile.name`.  `normalize-types` converts enabled
to bool, quota to int and tags to an array.  `lift-nested-members` moves
`profile.contact.email` to top `email` and `profile.limits.quota` to top
`quota`, deleting the emptied containers.  `drop-deprecated-members` removes
top `deprecated` and `profile.deprecated_code` only.
`combined-version-upgrade` applies rename, normalize, lift, then drop.
Preserve every other allowed field exactly.

Create only real mode-0755 `output/` and `output/documents/`, mode-0644
`output/manifest.json`, and one independent mode-0644 numbered document per
logical input: `output/documents/000000.json`, then consecutive six-digit
names.  Array and JSONL retain source order; a map uses raw-UTF8 key order.
The manifest has exactly `input_shape`, `migration_policy`, `document_count`,
and ordered `entries`; each entry has `file`, zero-based `source_index`, and
`source_key` (the map key, otherwise null).  JSON key order and insignificant
whitespace are not semantic.  Preserve every input path, kind, byte, mode,
mtime, link count and symlink target.

The final-state verifier cannot prove tool use, read scope, exit status,
atomicity, transient state or global quiescence.  Use only Bash built-ins plus
`mkdir`, `python3`, and `sort`.
"""
    graph = NormalizedSemanticGraph(
        nodes=(
            OperatorNode(
                "parse_versioned_document_source",
                (
                    f"shape:{parameters.input_shape}",
                    "schema:v1-closed",
                    "path:input/documents.data",
                ),
            ),
            OperatorNode(
                "validate_nested_schema",
                ("depth:8", "nodes:4096", "documents:32"),
            ),
            OperatorNode(
                "apply_schema_migration",
                (
                    f"policy:{parameters.migration_policy}",
                    "target-version:2",
                ),
            ),
            OperatorNode(
                "order_migrated_documents",
                ("array-jsonl:source-order", "map:raw-utf8-key"),
            ),
            OperatorNode(
                "emit_numbered_document_set",
                ("directory:output/documents", "mode:0644"),
            ),
            OperatorNode(
                "emit_migration_manifest",
                ("path:output/manifest.json", "mode:0644"),
            ),
        ),
        dependencies=((0, 1), (1, 2), (2, 3), (3, 4), (3, 5)),
    )
    return prompt, graph


def _validate_graph(graph: object) -> NormalizedSemanticGraph:
    if type(graph) is not NormalizedSemanticGraph:
        raise NestedJsonSchemaMigrationError("graph has wrong exact type")
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
        raise NestedJsonSchemaMigrationError(
            "graph reconstruction failed"
        ) from exc
    if rebuilt != graph or len(rebuilt.nodes) != len(graph.nodes):
        raise NestedJsonSchemaMigrationError("graph is noncanonical")
    return graph


def nested_json_schema_migration_task_semantic_core(
    parameters: NestedJsonSchemaMigrationParameters,
    prompt: str,
    graph: NormalizedSemanticGraph,
) -> dict[str, object]:
    if type(parameters) is not NestedJsonSchemaMigrationParameters:
        raise NestedJsonSchemaMigrationError("parameters have wrong type")
    parameters.__post_init__()
    expected_prompt, expected_graph = _task_contract(parameters)
    if (
        type(prompt) is not str
        or prompt != expected_prompt
        or _validate_graph(graph) != expected_graph
    ):
        raise NestedJsonSchemaMigrationError("prompt or graph differs")
    return {
        "schema_version": EXECUTABLE_STATIC_SCHEMA_VERSION,
        "contract_version": EXECUTABLE_STATIC_CONTRACT_VERSION,
        "split_role": METHOD_DEVELOPMENT_SPLIT,
        "family_id": NESTED_JSON_SCHEMA_MIGRATION_FAMILY_ID,
        "family_version": EXECUTABLE_STATIC_FAMILY_VERSION,
        "generator_version": (
            NESTED_JSON_SCHEMA_MIGRATION_GENERATOR_VERSION
        ),
        "parameters": parameters.to_record(),
        "prompt": prompt,
        "graph": graph.to_record(),
        "graph_sha256": graph.hash,
        "filesystem_identity": (
            NESTED_JSON_SCHEMA_MIGRATION_FILESYSTEM_IDENTITY
        ),
        "output_identity": NESTED_JSON_SCHEMA_MIGRATION_OUTPUT_IDENTITY,
        "allowed_tools": list(NESTED_JSON_SCHEMA_MIGRATION_ALLOWED_TOOLS),
        "public": True,
        "sealed": False,
        "candidate_execution_authorized": False,
        "model_selection_eligible": False,
        "claim_authorized": False,
    }


def compute_nested_json_schema_migration_task_sha256(
    parameters: NestedJsonSchemaMigrationParameters,
    prompt: str,
    graph: NormalizedSemanticGraph,
) -> str:
    return domain_sha256(
        "cbds.executable-static.task-contract.v1",
        nested_json_schema_migration_task_semantic_core(
            parameters, prompt, graph
        ),
    )


@dataclass(frozen=True, slots=True)
class NestedJsonSchemaMigrationTask:
    task_id: str
    parameters: NestedJsonSchemaMigrationParameters
    prompt: str
    graph: NormalizedSemanticGraph
    fixtures: tuple[OpaqueFixtureDescriptor, ...]
    task_contract_sha256: str
    family_id: str = NESTED_JSON_SCHEMA_MIGRATION_FAMILY_ID
    family_version: str = EXECUTABLE_STATIC_FAMILY_VERSION
    filesystem_identity: str = (
        NESTED_JSON_SCHEMA_MIGRATION_FILESYSTEM_IDENTITY
    )
    output_identity: str = NESTED_JSON_SCHEMA_MIGRATION_OUTPUT_IDENTITY
    allowed_tools: tuple[str, ...] = (
        NESTED_JSON_SCHEMA_MIGRATION_ALLOWED_TOOLS
    )
    split_role: str = METHOD_DEVELOPMENT_SPLIT
    public: bool = True
    sealed: bool = False
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        if (
            type(self) is not NestedJsonSchemaMigrationTask
            or type(self.parameters)
            is not NestedJsonSchemaMigrationParameters
            or type(self.family_id) is not str
            or self.family_id != NESTED_JSON_SCHEMA_MIGRATION_FAMILY_ID
            or type(self.family_version) is not str
            or self.family_version != EXECUTABLE_STATIC_FAMILY_VERSION
            or type(self.filesystem_identity) is not str
            or self.filesystem_identity
            != NESTED_JSON_SCHEMA_MIGRATION_FILESYSTEM_IDENTITY
            or type(self.output_identity) is not str
            or self.output_identity
            != NESTED_JSON_SCHEMA_MIGRATION_OUTPUT_IDENTITY
            or type(self.allowed_tools) is not tuple
            or any(type(item) is not str for item in self.allowed_tools)
            or self.allowed_tools
            != NESTED_JSON_SCHEMA_MIGRATION_ALLOWED_TOOLS
            or type(self.split_role) is not str
            or self.split_role != METHOD_DEVELOPMENT_SPLIT
            or self.public is not True
            or self.sealed is not False
            or self.candidate_execution_authorized is not False
            or self.model_selection_eligible is not False
            or self.claim_authorized is not False
        ):
            raise NestedJsonSchemaMigrationError(
                "task metadata is invalid"
            )
        expected = compute_nested_json_schema_migration_task_sha256(
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
            raise NestedJsonSchemaMigrationError(
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
            raise NestedJsonSchemaMigrationError(
                "task descriptor binding is invalid"
            )

    @property
    def graph_sha256(self) -> str:
        self.__post_init__()
        return self.graph.hash

    def to_public_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            **nested_json_schema_migration_task_semantic_core(
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
    parameters: NestedJsonSchemaMigrationParameters,
) -> NestedJsonSchemaMigrationTask:
    prompt, graph = _task_contract(parameters)
    digest = compute_nested_json_schema_migration_task_sha256(
        parameters, prompt, graph
    )
    return NestedJsonSchemaMigrationTask(
        task_id_from_contract(digest),
        parameters,
        prompt,
        graph,
        _bootstrap_descriptors(digest),
        digest,
    )


@dataclass(frozen=True, slots=True)
class _ParsedDocument:
    source_index: int
    source_key: str | None
    value: dict[str, object] = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self) is not _ParsedDocument
            or type(self.source_index) is not int
            or self.source_index < 0
            or (
                self.source_key is not None
                and type(self.source_key) is not str
            )
        ):
            raise NestedJsonSchemaMigrationError(
                "parsed document metadata is invalid"
            )
        if self.source_key is not None:
            _validate_string(
                self.source_key, "source map key", nonempty=True
            )
        _validate_v1_document(self.value)


def _source_payload(definition: FixtureDefinition) -> bytes:
    matches = tuple(
        item
        for item in definition.inputs
        if type(item) is InputFile
        and item.path == NESTED_JSON_SCHEMA_MIGRATION_INPUT
    )
    if len(matches) != 1:
        raise NestedJsonSchemaMigrationError(
            "fixture must contain one exact documents source"
        )
    return matches[0].content


def _parse_source_value(
    payload: bytes,
    shape: InputShape,
) -> tuple[_ParsedDocument, ...]:
    if (
        type(payload) is not bytes
        or not payload
        or len(payload)
        > NESTED_JSON_SCHEMA_MIGRATION_SOURCE_MAXIMUM_BYTES
        or not payload.endswith(b"\n")
    ):
        raise NestedJsonSchemaMigrationError(
            "document source violates byte or LF framing bounds"
        )
    if shape == "jsonl-objects":
        lines = payload[:-1].split(b"\n")
        if (
            not lines
            or len(lines)
            > NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_DOCUMENTS
            or any(not line or b"\r" in line or b"\n" in line for line in lines)
        ):
            raise NestedJsonSchemaMigrationError(
                "JSONL source has invalid physical records"
            )
        records = tuple(
            _ParsedDocument(index, None, _validate_v1_document(
                _decode_json_strict(line)
            ))
            for index, line in enumerate(lines)
        )
        return records

    value = _decode_json_strict(payload[:-1])
    if shape == "single-object":
        values = (_validate_v1_document(value),)
        return (_ParsedDocument(0, None, values[0]),)
    if shape == "object-array":
        if (
            type(value) is not list
            or not value
            or len(value)
            > NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_DOCUMENTS
        ):
            raise NestedJsonSchemaMigrationError(
                "object-array source has invalid cardinality"
            )
        return tuple(
            _ParsedDocument(
                index, None, _validate_v1_document(document)
            )
            for index, document in enumerate(value)
        )
    if shape == "keyed-object-map":
        if (
            type(value) is not dict
            or not value
            or len(value)
            > NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_DOCUMENTS
        ):
            raise NestedJsonSchemaMigrationError(
                "keyed map source has invalid cardinality"
            )
        ordered = sorted(
            value.items(), key=lambda item: item[0].encode("utf-8")
        )
        result: list[_ParsedDocument] = []
        for index, (key, raw_document) in enumerate(ordered):
            _validate_string(key, "source map key", nonempty=True)
            document = _validate_v1_document(raw_document)
            if document["record_id"] != key:
                raise NestedJsonSchemaMigrationError(
                    "map key differs from the full value record_id"
                )
            result.append(_ParsedDocument(index, key, document))
        return tuple(result)
    raise NestedJsonSchemaMigrationError("input shape is unsupported")


def parse_nested_json_schema_migration_source(
    payload: bytes,
    input_shape: InputShape,
) -> tuple[dict[str, object], ...]:
    """Return independent copies of validated v1 logical documents."""

    _closed_text(
        input_shape,
        NESTED_JSON_SCHEMA_MIGRATION_INPUT_SHAPES,
        "input_shape",
    )
    return tuple(
        copy.deepcopy(item.value)
        for item in _parse_source_value(payload, input_shape)
    )


def _normalize_enabled(value: bool | int | str) -> bool:
    _validate_enabled(value)
    if type(value) is bool:
        return value
    if type(value) is int:
        return value == 1
    return value in {"true", "yes", "1"}


def _normalize_quota(value: int | str) -> int:
    _validate_quota(value)
    return value if type(value) is int else int(value)


def _rename_primary(document: dict[str, object]) -> None:
    document["id"] = document.pop("record_id")
    profile = document["profile"]
    if type(profile) is not dict:
        raise NestedJsonSchemaMigrationError("validated profile was lost")
    profile["name"] = profile.pop("display_name")


def _normalize_primary(document: dict[str, object]) -> None:
    profile = document["profile"]
    if type(profile) is not dict:
        raise NestedJsonSchemaMigrationError("validated profile was lost")
    profile["enabled"] = _normalize_enabled(profile["enabled"])
    limits = profile.get("limits")
    if limits is not None:
        if type(limits) is not dict:
            raise NestedJsonSchemaMigrationError(
                "validated limits object was lost"
            )
        limits["quota"] = _normalize_quota(limits["quota"])
    if "tags" in document:
        tags = document["tags"]
        if type(tags) is str:
            document["tags"] = [tags]
        elif type(tags) is list:
            document["tags"] = list(tags)
        else:
            raise NestedJsonSchemaMigrationError(
                "validated tags representation was lost"
            )


def _lift_primary(document: dict[str, object]) -> None:
    profile = document["profile"]
    if type(profile) is not dict:
        raise NestedJsonSchemaMigrationError("validated profile was lost")
    contact = profile.pop("contact", None)
    if contact is not None:
        if type(contact) is not dict:
            raise NestedJsonSchemaMigrationError(
                "validated contact object was lost"
            )
        document["email"] = contact["email"]
    limits = profile.pop("limits", None)
    if limits is not None:
        if type(limits) is not dict:
            raise NestedJsonSchemaMigrationError(
                "validated limits object was lost"
            )
        document["quota"] = limits["quota"]


def _drop_primary(document: dict[str, object]) -> None:
    document.pop("deprecated", None)
    profile = document["profile"]
    if type(profile) is not dict:
        raise NestedJsonSchemaMigrationError("validated profile was lost")
    profile.pop("deprecated_code", None)


def _migrate_document_primary(
    source: dict[str, object],
    policy: MigrationPolicy,
) -> dict[str, object]:
    _validate_v1_document(source)
    _closed_text(
        policy,
        NESTED_JSON_SCHEMA_MIGRATION_POLICIES,
        "migration_policy",
    )
    result = copy.deepcopy(source)
    result["schema_version"] = 2
    if policy in {"rename-fields", "combined-version-upgrade"}:
        _rename_primary(result)
    if policy in {"normalize-types", "combined-version-upgrade"}:
        _normalize_primary(result)
    if policy in {"lift-nested-members", "combined-version-upgrade"}:
        _lift_primary(result)
    if policy in {
        "drop-deprecated-members",
        "combined-version-upgrade",
    }:
        _drop_primary(result)
    _validate_v2_document(result)
    return result


def _migrate_document_reference(
    source: dict[str, object],
    policy: MigrationPolicy,
) -> dict[str, object]:
    """Construct v2 from v1 members without mutating a copied v1 object."""

    document = _validate_v1_document(source)
    _closed_text(
        policy,
        NESTED_JSON_SCHEMA_MIGRATION_POLICIES,
        "migration_policy",
    )
    rename = policy in {"rename-fields", "combined-version-upgrade"}
    normalize = policy in {"normalize-types", "combined-version-upgrade"}
    lift = policy in {"lift-nested-members", "combined-version-upgrade"}
    drop = policy in {
        "drop-deprecated-members",
        "combined-version-upgrade",
    }
    source_profile = document["profile"]
    if type(source_profile) is not dict:
        raise NestedJsonSchemaMigrationError("validated profile was lost")

    profile: dict[str, object] = {}
    profile["name" if rename else "display_name"] = copy.deepcopy(
        source_profile["display_name"]
    )
    enabled = source_profile["enabled"]
    profile["enabled"] = (
        _normalize_enabled(enabled)
        if normalize
        else copy.deepcopy(enabled)
    )

    limits = source_profile.get("limits")
    if limits is not None and not lift:
        if type(limits) is not dict:
            raise NestedJsonSchemaMigrationError(
                "validated limits object was lost"
            )
        quota = limits["quota"]
        profile["limits"] = {
            "quota": (
                _normalize_quota(quota)
                if normalize
                else copy.deepcopy(quota)
            )
        }
    contact = source_profile.get("contact")
    if contact is not None and not lift:
        if type(contact) is not dict:
            raise NestedJsonSchemaMigrationError(
                "validated contact object was lost"
            )
        profile["contact"] = {"email": copy.deepcopy(contact["email"])}
    if "deprecated_code" in source_profile and not drop:
        profile["deprecated_code"] = copy.deepcopy(
            source_profile["deprecated_code"]
        )

    result: dict[str, object] = {
        "schema_version": 2,
        "id" if rename else "record_id": copy.deepcopy(
            document["record_id"]
        ),
        "profile": profile,
    }
    if "tags" in document:
        tags = document["tags"]
        if normalize:
            if type(tags) is str:
                result["tags"] = [tags]
            elif type(tags) is list:
                result["tags"] = copy.deepcopy(tags)
            else:
                raise NestedJsonSchemaMigrationError(
                    "validated tags representation was lost"
                )
        else:
            result["tags"] = copy.deepcopy(tags)
    if "deprecated" in document and not drop:
        result["deprecated"] = copy.deepcopy(document["deprecated"])
    if lift and contact is not None:
        if type(contact) is not dict:
            raise NestedJsonSchemaMigrationError(
                "validated contact object was lost"
            )
        result["email"] = copy.deepcopy(contact["email"])
    if lift and limits is not None:
        if type(limits) is not dict:
            raise NestedJsonSchemaMigrationError(
                "validated limits object was lost"
            )
        quota = limits["quota"]
        result["quota"] = (
            _normalize_quota(quota)
            if normalize
            else copy.deepcopy(quota)
        )
    _validate_v2_document(result)
    return result


def _validate_v2_document(value: object) -> dict[str, object]:
    top_allowed = frozenset(
        {
            "schema_version",
            "record_id",
            "id",
            "profile",
            "tags",
            "deprecated",
            "email",
            "quota",
        }
    )
    document = _require_exact_keys(
        value,
        frozenset({"schema_version", "profile"}),
        top_allowed,
        "v2 document",
    )
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != 2
    ):
        raise NestedJsonSchemaMigrationError(
            "schema_version must be exact integer 2"
        )
    identity_fields = tuple(
        key for key in ("record_id", "id") if key in document
    )
    if len(identity_fields) != 1:
        raise NestedJsonSchemaMigrationError(
            "v2 document must have exactly one identity field"
        )
    _validate_string(
        document[identity_fields[0]],
        identity_fields[0],
        nonempty=True,
    )

    profile_allowed = frozenset(
        {
            "display_name",
            "name",
            "enabled",
            "limits",
            "contact",
            "deprecated_code",
        }
    )
    profile = _require_exact_keys(
        document["profile"],
        frozenset({"enabled"}),
        profile_allowed,
        "v2 profile",
    )
    name_fields = tuple(
        key for key in ("display_name", "name") if key in profile
    )
    if len(name_fields) != 1:
        raise NestedJsonSchemaMigrationError(
            "v2 profile must have exactly one name field"
        )
    _validate_string(profile[name_fields[0]], name_fields[0])
    _validate_enabled(profile["enabled"])
    if "limits" in profile:
        limits = _require_exact_keys(
            profile["limits"],
            _LIMIT_KEYS,
            _LIMIT_KEYS,
            "v2 profile.limits",
        )
        _validate_quota(limits["quota"])
    if "contact" in profile:
        contact = _require_exact_keys(
            profile["contact"],
            _CONTACT_KEYS,
            _CONTACT_KEYS,
            "v2 profile.contact",
        )
        _validate_string(contact["email"], "v2 profile.contact.email")
    if "deprecated_code" in profile:
        _validate_string(
            profile["deprecated_code"],
            "v2 profile.deprecated_code",
        )
    if "tags" in document:
        _validate_tags(document["tags"])
    if "deprecated" in document:
        deprecated = _require_exact_keys(
            document["deprecated"],
            _DEPRECATED_KEYS,
            _DEPRECATED_KEYS,
            "v2 deprecated",
        )
        _validate_string(deprecated["note"], "v2 deprecated.note")
    if "email" in document:
        _validate_string(document["email"], "v2 email")
    if "quota" in document:
        _validate_quota(document["quota"])
    return document


def _canonical_json(value: object) -> bytes:
    try:
        text = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        return text.encode("utf-8", errors="strict") + b"\n"
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise NestedJsonSchemaMigrationError(
            "value cannot be encoded as canonical JSON"
        ) from exc


def _numbered_relative_path(index: int) -> str:
    if (
        type(index) is not int
        or index < 0
        or index >= NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_DOCUMENTS
    ):
        raise NestedJsonSchemaMigrationError(
            "document index is outside its bound"
        )
    return f"documents/{index:06d}.json"


def _numbered_output_path(index: int) -> str:
    return f"output/{_numbered_relative_path(index)}"


@dataclass(frozen=True, slots=True)
class MigratedJsonDocument:
    source_index: int
    source_key: str | None
    file: str
    value: dict[str, object] = field(repr=False)
    content: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self) is not MigratedJsonDocument
            or type(self.source_index) is not int
            or self.source_index < 0
            or self.source_index
            >= NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_DOCUMENTS
            or type(self.file) is not str
            or self.file != _numbered_relative_path(self.source_index)
            or (
                self.source_key is not None
                and type(self.source_key) is not str
            )
            or type(self.content) is not bytes
            or len(self.content)
            > NESTED_JSON_SCHEMA_MIGRATION_DOCUMENT_OUTPUT_MAXIMUM_BYTES
        ):
            raise NestedJsonSchemaMigrationError(
                "migrated document metadata is invalid"
            )
        if self.source_key is not None:
            _validate_string(
                self.source_key, "source map key", nonempty=True
            )
        _validate_v2_document(self.value)
        if self.content != _canonical_json(self.value):
            raise NestedJsonSchemaMigrationError(
                "migrated document content is noncanonical"
            )

    def to_manifest_entry(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "file": self.file,
            "source_index": self.source_index,
            "source_key": self.source_key,
        }

    def to_commitment_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            **self.to_manifest_entry(),
            "content_sha256": sha256(self.content).hexdigest(),
            "content_bytes": len(self.content),
        }


@dataclass(frozen=True, slots=True)
class NestedJsonSchemaMigrationState:
    input_shape: InputShape
    migration_policy: MigrationPolicy
    documents: tuple[MigratedJsonDocument, ...]
    manifest: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if type(self) is not NestedJsonSchemaMigrationState:
            raise NestedJsonSchemaMigrationError("state has wrong exact type")
        _closed_text(
            self.input_shape,
            NESTED_JSON_SCHEMA_MIGRATION_INPUT_SHAPES,
            "input_shape",
        )
        _closed_text(
            self.migration_policy,
            NESTED_JSON_SCHEMA_MIGRATION_POLICIES,
            "migration_policy",
        )
        if (
            type(self.documents) is not tuple
            or not self.documents
            or len(self.documents)
            > NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_DOCUMENTS
            or any(
                type(item) is not MigratedJsonDocument
                for item in self.documents
            )
            or type(self.manifest) is not bytes
            or len(self.manifest)
            > NESTED_JSON_SCHEMA_MIGRATION_MANIFEST_OUTPUT_MAXIMUM_BYTES
        ):
            raise NestedJsonSchemaMigrationError(
                "state document collection is invalid"
            )
        for index, document in enumerate(self.documents):
            document.__post_init__()
            if document.source_index != index:
                raise NestedJsonSchemaMigrationError(
                    "state source indexes are nonconsecutive"
                )
        keys = tuple(item.source_key for item in self.documents)
        if self.input_shape == "keyed-object-map":
            if (
                any(key is None for key in keys)
                or tuple(
                    sorted(
                        keys,
                        key=lambda key: (
                            key.encode("utf-8")
                            if type(key) is str
                            else b""
                        ),
                    )
                )
                != keys
            ):
                raise NestedJsonSchemaMigrationError(
                    "map source keys are absent or misordered"
                )
        elif any(key is not None for key in keys):
            raise NestedJsonSchemaMigrationError(
                "non-map state contains source keys"
            )
        if self.manifest != _canonical_json(self.manifest_value()):
            raise NestedJsonSchemaMigrationError(
                "state manifest is noncanonical"
            )

    def manifest_value(self) -> dict[str, object]:
        return {
            "input_shape": self.input_shape,
            "migration_policy": self.migration_policy,
            "document_count": len(self.documents),
            "entries": [
                item.to_manifest_entry() for item in self.documents
            ],
        }

    @property
    def total_output_bytes(self) -> int:
        self.__post_init__()
        return len(self.manifest) + sum(
            len(item.content) for item in self.documents
        )

    @property
    def commitment_sha256(self) -> str:
        self.__post_init__()
        return domain_sha256(
            "cbds.nested-json-schema-migration.state.v1",
            {
                "input_shape": self.input_shape,
                "migration_policy": self.migration_policy,
                "manifest_sha256": sha256(self.manifest).hexdigest(),
                "manifest_bytes": len(self.manifest),
                "documents": [
                    item.to_commitment_record()
                    for item in self.documents
                ],
                "total_output_bytes": self.total_output_bytes,
            },
        )

    def commitment_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "input_shape": self.input_shape,
            "migration_policy": self.migration_policy,
            "documents": [
                item.to_commitment_record() for item in self.documents
            ],
            "manifest_sha256": sha256(self.manifest).hexdigest(),
            "manifest_bytes": len(self.manifest),
            "total_output_bytes": self.total_output_bytes,
            "state_sha256": self.commitment_sha256,
        }


def _build_state(
    parsed: tuple[_ParsedDocument, ...],
    parameters: NestedJsonSchemaMigrationParameters,
    *,
    reference: bool,
) -> NestedJsonSchemaMigrationState:
    migrate = (
        _migrate_document_reference
        if reference
        else _migrate_document_primary
    )
    documents = tuple(
        MigratedJsonDocument(
            source_index=item.source_index,
            source_key=item.source_key,
            file=_numbered_relative_path(item.source_index),
            value=migrate(item.value, parameters.migration_policy),
            content=_canonical_json(
                migrate(item.value, parameters.migration_policy)
            ),
        )
        for item in parsed
    )
    # The constructor above intentionally calls each pure derivation twice;
    # agreement of the value and canonical bytes is then enforced by the
    # frozen document type without retaining a mutable intermediate.
    manifest_value = {
        "input_shape": parameters.input_shape,
        "migration_policy": parameters.migration_policy,
        "document_count": len(documents),
        "entries": [
            item.to_manifest_entry() for item in documents
        ],
    }
    return NestedJsonSchemaMigrationState(
        parameters.input_shape,
        parameters.migration_policy,
        documents,
        _canonical_json(manifest_value),
    )


def derive_nested_json_schema_migration_state(
    definition: FixtureDefinition,
    parameters: NestedJsonSchemaMigrationParameters,
) -> NestedJsonSchemaMigrationState:
    """Derive the trusted output with the sequential mutation algorithm."""

    _revalidate_definition(definition)
    if type(parameters) is not NestedJsonSchemaMigrationParameters:
        raise NestedJsonSchemaMigrationError("parameters have wrong type")
    parameters.__post_init__()
    parsed = _parse_source_value(
        _source_payload(definition), parameters.input_shape
    )
    return _build_state(parsed, parameters, reference=False)


def reference_nested_json_schema_migration_state(
    definition: FixtureDefinition,
    parameters: NestedJsonSchemaMigrationParameters,
) -> NestedJsonSchemaMigrationState:
    """Derive the trusted output with independent member reconstruction."""

    _revalidate_definition(definition)
    if type(parameters) is not NestedJsonSchemaMigrationParameters:
        raise NestedJsonSchemaMigrationError("parameters have wrong type")
    parameters.__post_init__()
    parsed = _parse_source_value(
        _source_payload(definition), parameters.input_shape
    )
    return _build_state(parsed, parameters, reference=True)


def parse_nested_json_schema_migration_document_output(
    payload: bytes,
) -> bytes:
    """Validate one v2 document and return its canonical JSON rendering."""

    if (
        type(payload) is not bytes
        or not payload
        or len(payload)
        > NESTED_JSON_SCHEMA_MIGRATION_DOCUMENT_OUTPUT_MAXIMUM_BYTES
    ):
        raise NestedJsonSchemaMigrationError(
            "document output violates its byte bound"
        )
    value = _decode_json_strict(payload)
    _validate_v2_document(value)
    return _canonical_json(value)


def _validate_manifest_value(value: object) -> dict[str, object]:
    manifest = _require_exact_keys(
        value,
        _MANIFEST_KEYS,
        _MANIFEST_KEYS,
        "output manifest",
    )
    shape = _closed_text(
        manifest["input_shape"],
        NESTED_JSON_SCHEMA_MIGRATION_INPUT_SHAPES,
        "manifest input_shape",
    )
    _closed_text(
        manifest["migration_policy"],
        NESTED_JSON_SCHEMA_MIGRATION_POLICIES,
        "manifest migration_policy",
    )
    count = manifest["document_count"]
    entries = manifest["entries"]
    if (
        type(count) is not int
        or count < 1
        or count > NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_DOCUMENTS
        or type(entries) is not list
        or len(entries) != count
    ):
        raise NestedJsonSchemaMigrationError(
            "manifest count or entries are invalid"
        )
    source_keys: list[str] = []
    for index, raw_entry in enumerate(entries):
        entry = _require_exact_keys(
            raw_entry,
            _MANIFEST_ENTRY_KEYS,
            _MANIFEST_ENTRY_KEYS,
            "manifest entry",
        )
        if (
            type(entry["file"]) is not str
            or entry["file"] != _numbered_relative_path(index)
            or type(entry["source_index"]) is not int
            or entry["source_index"] != index
        ):
            raise NestedJsonSchemaMigrationError(
                "manifest entry path or order is invalid"
            )
        source_key = entry["source_key"]
        if shape == "keyed-object-map":
            source_keys.append(
                _validate_string(
                    source_key,
                    "manifest source_key",
                    nonempty=True,
                )
            )
        elif source_key is not None:
            raise NestedJsonSchemaMigrationError(
                "non-map manifest source_key must be null"
            )
    if shape == "keyed-object-map":
        if (
            len(set(source_keys)) != len(source_keys)
            or source_keys
            != sorted(source_keys, key=lambda key: key.encode("utf-8"))
        ):
            raise NestedJsonSchemaMigrationError(
                "manifest map source keys are duplicated or misordered"
            )
    return manifest


def parse_nested_json_schema_migration_manifest_output(
    payload: bytes,
) -> bytes:
    """Validate the closed manifest and return canonical JSON bytes."""

    if (
        type(payload) is not bytes
        or not payload
        or len(payload)
        > NESTED_JSON_SCHEMA_MIGRATION_MANIFEST_OUTPUT_MAXIMUM_BYTES
    ):
        raise NestedJsonSchemaMigrationError(
            "manifest output violates its byte bound"
        )
    value = _decode_json_strict(payload)
    _validate_manifest_value(value)
    return _canonical_json(value)


def _profile_documents(
    profile: ExecutableFixtureProfile,
) -> tuple[dict[str, object], ...]:
    profile_id = profile.profile_id
    if profile_id == "spaces-unicode":
        records = (
            (
                "café record",
                'Snow "雪" \\ User',
                "yes",
                "7",
                "café@example.test",
                "legacy café",
                "alpha tag",
                "old note",
            ),
            (
                "雪 record",
                "Space User",
                False,
                -3,
                "snow@example.test",
                "",
                ["β", "two words"],
                "",
            ),
            (
                "plain record",
                "",
                1,
                "0",
                "",
                "obsolete",
                [],
                "retain exactly",
            ),
        )
    elif profile_id == "leading-dashes-globs":
        records = (
            (
                "-draft[*]?",
                "-name ?*[]",
                "no",
                "-12",
                "-mail[*]?@example.test",
                "-legacy[*]?",
                "-tag[*]?",
                "-deprecated[*]?",
            ),
            (
                "glob[*]? literal",
                "literal [abc]",
                "1",
                42,
                "glob@example.test",
                "old?",
                ["*", "?", "[x]"],
                "literal glob",
            ),
            (
                "--",
                "-",
                0,
                "1",
                "--@example.test",
                "--",
                [],
                "--",
            ),
        )
    elif profile_id == "empty-duplicates":
        records = (
            (
                "duplicate-a",
                "",
                "false",
                "0",
                "",
                "",
                "",
                "",
            ),
            (
                "duplicate-b",
                "",
                "false",
                "0",
                "",
                "",
                "",
                "",
            ),
            (
                "empty-array",
                "",
                False,
                0,
                "",
                "",
                [],
                "",
            ),
        )
    elif profile_id == "symlinks-ordering":
        # Deliberately not raw-byte sorted; keyed-map encoding reverses it
        # once more, and parsing must establish the only semantic map order.
        records = (
            (
                "z-last",
                "Zulu",
                "true",
                "10",
                "z@example.test",
                "z-old",
                ["z", "last"],
                "z note",
            ),
            (
                "a-first",
                "Alpha",
                "0",
                2,
                "a@example.test",
                "a-old",
                "a",
                "a note",
            ),
            (
                "middle",
                "Middle",
                True,
                "-1",
                "m@example.test",
                "m-old",
                ["m", "middle"],
                "m note",
            ),
        )
    elif profile_id == "partial-permissions":
        records = (
            (
                "read-only",
                "Read Only",
                0,
                "-1000000",
                "readonly@example.test",
                "retire",
                ["one", "two"],
                "drop me",
            ),
            (
                "bounded",
                "Boundary",
                "true",
                1_000_000,
                "bound@example.test",
                "v1",
                "boundary",
                "top old",
            ),
            (
                "negative",
                "Negative",
                "no",
                -999_999,
                "",
                "",
                [],
                "",
            ),
        )
    else:
        raise NestedJsonSchemaMigrationError(
            "fixture profile is outside the closed set"
        )
    result = tuple(
        {
            "schema_version": 1,
            "record_id": record_id,
            "profile": {
                "display_name": display_name,
                "enabled": enabled,
                "limits": {"quota": quota},
                "contact": {"email": email},
                "deprecated_code": deprecated_code,
            },
            "tags": copy.deepcopy(tags),
            "deprecated": {"note": deprecated_note},
        }
        for (
            record_id,
            display_name,
            enabled,
            quota,
            email,
            deprecated_code,
            tags,
            deprecated_note,
        ) in records
    )
    for document in result:
        _validate_v1_document(document)
    return result


def _encode_source(
    documents: tuple[dict[str, object], ...],
    shape: InputShape,
) -> bytes:
    if not documents:
        raise NestedJsonSchemaMigrationError(
            "fixture document set cannot be empty"
        )
    for document in documents:
        _validate_v1_document(document)
    if shape == "single-object":
        result = _canonical_json(documents[0])
    elif shape == "object-array":
        result = _canonical_json(list(documents))
    elif shape == "keyed-object-map":
        # Insertion order is intentionally the reverse of fixture order.
        # JSON object order is not semantic; the source contract requires
        # the parser to establish raw UTF-8 key ordering itself.
        entries: list[bytes] = []
        seen_record_ids: set[str] = set()
        for document in reversed(documents):
            record_id = document["record_id"]
            if type(record_id) is not str:
                raise NestedJsonSchemaMigrationError(
                    "fixture record_id lost exact type"
                )
            if record_id in seen_record_ids:
                raise NestedJsonSchemaMigrationError(
                    "keyed-map fixture record_id is duplicated"
                )
            seen_record_ids.add(record_id)
            entries.append(
                _canonical_json(record_id)[:-1]
                + b":"
                + _canonical_json(document)[:-1]
            )
        result = b"{" + b",".join(entries) + b"}\n"
    elif shape == "jsonl-objects":
        result = b"".join(_canonical_json(item) for item in documents)
    else:
        raise NestedJsonSchemaMigrationError(
            "fixture shape is outside the closed set"
        )
    _parse_source_value(result, shape)
    return result


def _fixture_inputs(
    profile: ExecutableFixtureProfile,
    parameters: NestedJsonSchemaMigrationParameters,
) -> tuple[InputFile | InputSymlink, ...]:
    documents = _profile_documents(profile)
    source_mode = (
        0o400 if profile.profile_id == "partial-permissions" else 0o600
    )
    inputs: list[InputFile | InputSymlink] = [
        InputFile(
            NESTED_JSON_SCHEMA_MIGRATION_INPUT,
            _encode_source(documents, parameters.input_shape),
            source_mode,
            2_100,
        )
    ]
    if profile.profile_id == "spaces-unicode":
        inputs.append(
            InputFile(
                "input/distractors/space café.json",
                b'{"ignore":"snow \\u96ea"}\n',
                0o444,
                2_101,
            )
        )
    elif profile.profile_id == "leading-dashes-globs":
        inputs.append(
            InputFile(
                "input/-distractor[*]?.json",
                b'{"ignore":"literal"}\n',
                0o400,
                2_102,
            )
        )
    elif profile.profile_id == "empty-duplicates":
        inputs.append(
            InputFile(
                "input/distractors/empty",
                b"",
                0o444,
                2_103,
            )
        )
    elif profile.profile_id == "symlinks-ordering":
        inputs.extend(
            (
                InputFile(
                    "input/distractors/target",
                    b"do not follow\n",
                    0o444,
                    2_104,
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
                2_105,
            )
        )
    else:
        raise NestedJsonSchemaMigrationError(
            "fixture profile is outside the closed set"
        )
    return tuple(inputs)


def _revalidate_definition(definition: object) -> FixtureDefinition:
    if type(definition) is not FixtureDefinition:
        raise NestedJsonSchemaMigrationError(
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
        raise NestedJsonSchemaMigrationError(
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
        raise NestedJsonSchemaMigrationError(
            "definition is outside the family domain"
        )
    _source_payload(definition)
    return definition


def _expected_files(document_count: int) -> tuple[ExpectedFile, ...]:
    if (
        type(document_count) is not int
        or document_count < 1
        or document_count
        > NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_DOCUMENTS
    ):
        raise NestedJsonSchemaMigrationError(
            "expected document count is invalid"
        )
    return (
        ExpectedFile(
            NESTED_JSON_SCHEMA_MIGRATION_OUTPUT_MANIFEST,
            NESTED_JSON_SCHEMA_MIGRATION_MANIFEST_OUTPUT_MAXIMUM_BYTES,
            NESTED_JSON_SCHEMA_MIGRATION_OUTPUT_MODE,
        ),
        *(
            ExpectedFile(
                _numbered_output_path(index),
                NESTED_JSON_SCHEMA_MIGRATION_DOCUMENT_OUTPUT_MAXIMUM_BYTES,
                NESTED_JSON_SCHEMA_MIGRATION_OUTPUT_MODE,
            )
            for index in range(document_count)
        ),
    )


def _oracle_sha256(
    state: NestedJsonSchemaMigrationState,
    parameters: NestedJsonSchemaMigrationParameters,
) -> str:
    state.__post_init__()
    parameters.__post_init__()
    if (
        state.input_shape != parameters.input_shape
        or state.migration_policy != parameters.migration_policy
    ):
        raise NestedJsonSchemaMigrationError(
            "oracle state differs from parameters"
        )
    return domain_sha256(
        "cbds.executable-fixture.trusted-oracle.v1",
        {
            "schema_version": EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION,
            "semantic_verifier_identity": (
                NESTED_JSON_SCHEMA_MIGRATION_VERIFIER_IDENTITY
            ),
            "parameters": parameters.to_record(),
            "state": state.commitment_record(),
        },
    )


@dataclass(frozen=True, slots=True)
class NestedJsonSchemaMigrationOracle:
    state: NestedJsonSchemaMigrationState = field(repr=False)
    input_shape: InputShape
    migration_policy: MigrationPolicy
    oracle_sha256: str
    semantic_verifier_identity: str = (
        NESTED_JSON_SCHEMA_MIGRATION_VERIFIER_IDENTITY
    )
    schema_version: str = EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            type(self) is not NestedJsonSchemaMigrationOracle
            or type(self.state) is not NestedJsonSchemaMigrationState
        ):
            raise NestedJsonSchemaMigrationError(
                "oracle or owned state has wrong exact type"
            )
        parameters = NestedJsonSchemaMigrationParameters(
            self.input_shape, self.migration_policy
        )
        self.state.__post_init__()
        if (
            type(self.semantic_verifier_identity) is not str
            or self.semantic_verifier_identity
            != NESTED_JSON_SCHEMA_MIGRATION_VERIFIER_IDENTITY
            or type(self.schema_version) is not str
            or self.schema_version
            != EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION
            or self.state.input_shape != self.input_shape
            or self.state.migration_policy != self.migration_policy
            or not _is_sha256(self.oracle_sha256)
            or self.oracle_sha256 != _oracle_sha256(
                self.state, parameters
            )
        ):
            raise NestedJsonSchemaMigrationError(
                "oracle identity is invalid"
            )

    def commitment_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "schema_version": self.schema_version,
            "record_type": "cbds.executable-fixture-trusted-oracle",
            "semantic_verifier_identity": self.semantic_verifier_identity,
            "input_shape": self.input_shape,
            "migration_policy": self.migration_policy,
            "state": self.state.commitment_record(),
            "oracle_sha256": self.oracle_sha256,
        }


@dataclass(frozen=True, slots=True)
class NestedJsonSchemaMigrationFixtureBundle:
    task_contract_sha256: str
    profile_sha256: str
    definition: FixtureDefinition = field(repr=False)
    fixture_definition_sha256: str
    oracle: NestedJsonSchemaMigrationOracle = field(repr=False)
    descriptor: OpaqueFixtureDescriptor
    schema_version: str = EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_nested_json_schema_migration_fixture_bundle(self)

    def commitment_record(self) -> dict[str, object]:
        validate_nested_json_schema_migration_fixture_bundle(self)
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


def validate_nested_json_schema_migration_fixture_bundle(
    bundle: NestedJsonSchemaMigrationFixtureBundle,
) -> None:
    if type(bundle) is not NestedJsonSchemaMigrationFixtureBundle:
        raise NestedJsonSchemaMigrationError(
            "bundle has wrong exact type"
        )
    if (
        type(bundle.schema_version) is not str
        or bundle.schema_version
        != EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION
        or not _is_sha256(bundle.task_contract_sha256)
        or not _is_sha256(bundle.profile_sha256)
        or not _is_sha256(bundle.fixture_definition_sha256)
        or bundle.candidate_execution_authorized is not False
        or bundle.model_selection_eligible is not False
        or bundle.claim_authorized is not False
    ):
        raise NestedJsonSchemaMigrationError(
            "bundle metadata is invalid"
        )
    definition = _revalidate_definition(bundle.definition)
    definition_sha256 = compute_fixture_definition_semantic_sha256(
        definition
    )
    if definition_sha256 != bundle.fixture_definition_sha256:
        raise NestedJsonSchemaMigrationError(
            "fixture definition digest differs"
        )
    if type(bundle.oracle) is not NestedJsonSchemaMigrationOracle:
        raise NestedJsonSchemaMigrationError(
            "oracle has wrong exact type"
        )
    bundle.oracle.__post_init__()
    parameters = NestedJsonSchemaMigrationParameters(
        bundle.oracle.input_shape,
        bundle.oracle.migration_policy,
    )
    primary = derive_nested_json_schema_migration_state(
        definition, parameters
    )
    reference = reference_nested_json_schema_migration_state(
        definition, parameters
    )
    if (
        primary != reference
        or primary != bundle.oracle.state
        or definition.expected_files
        != _expected_files(len(primary.documents))
    ):
        raise NestedJsonSchemaMigrationError(
            "fixture output policy or oracle differs"
        )
    if type(bundle.descriptor) is not OpaqueFixtureDescriptor:
        raise NestedJsonSchemaMigrationError(
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
        raise NestedJsonSchemaMigrationError(
            "descriptor binding differs"
        )


def verify_nested_json_schema_migration_fixture_bundle(
    bundle: object,
) -> bool:
    try:
        validate_nested_json_schema_migration_fixture_bundle(
            bundle  # type: ignore[arg-type]
        )
    except (
        AttributeError,
        NestedJsonSchemaMigrationError,
        TypeError,
        ValueError,
    ):
        return False
    return True


def _validate_task_profile(
    task: object,
    profile: object,
) -> tuple[
    NestedJsonSchemaMigrationTask,
    ExecutableFixtureProfile,
]:
    if type(task) is not NestedJsonSchemaMigrationTask:
        raise NestedJsonSchemaMigrationError(
            "task has wrong exact type"
        )
    if type(profile) is not ExecutableFixtureProfile:
        raise NestedJsonSchemaMigrationError(
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
        raise NestedJsonSchemaMigrationError(
            "task/profile reconstruction failed"
        ) from exc
    if rebuilt not in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
        raise NestedJsonSchemaMigrationError(
            "profile is outside public method development"
        )
    return task, profile


def _construct_nested_json_schema_migration_fixture_bundle(
    task: NestedJsonSchemaMigrationTask,
    profile: ExecutableFixtureProfile,
) -> NestedJsonSchemaMigrationFixtureBundle:
    task, profile = _validate_task_profile(task, profile)
    inputs = _fixture_inputs(profile, task.parameters)
    provisional = FixtureDefinition(
        f"fixture.{task.task_id}.{profile.profile_id}",
        inputs,
        (),
    )
    primary = derive_nested_json_schema_migration_state(
        provisional, task.parameters
    )
    reference = reference_nested_json_schema_migration_state(
        provisional, task.parameters
    )
    if primary != reference:
        raise NestedJsonSchemaMigrationError(
            "independent migration engines disagree"
        )
    definition = FixtureDefinition(
        provisional.fixture_id,
        inputs,
        _expected_files(len(primary.documents)),
    )
    if (
        derive_nested_json_schema_migration_state(
            definition, task.parameters
        )
        != primary
        or reference_nested_json_schema_migration_state(
            definition, task.parameters
        )
        != reference
    ):
        raise NestedJsonSchemaMigrationError(
            "final output policy changed semantics"
        )
    oracle = NestedJsonSchemaMigrationOracle(
        primary,
        task.parameters.input_shape,
        task.parameters.migration_policy,
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
    return NestedJsonSchemaMigrationFixtureBundle(
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


def build_nested_json_schema_migration_fixture_bundle(
    task: NestedJsonSchemaMigrationTask,
    profile: ExecutableFixtureProfile,
) -> NestedJsonSchemaMigrationFixtureBundle:
    selected_task, selected_profile = _validate_task_profile(
        task, profile
    )
    bundle = _construct_nested_json_schema_migration_fixture_bundle(
        selected_task, selected_profile
    )
    index = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES.index(
        selected_profile
    )
    if selected_task.fixtures[index] != bundle.descriptor:
        raise NestedJsonSchemaMigrationError(
            "task descriptor differs from reconstructed fixture"
        )
    return bundle


def validate_nested_json_schema_migration_fixture_for_task_profile(
    task: NestedJsonSchemaMigrationTask,
    profile: ExecutableFixtureProfile,
    bundle: NestedJsonSchemaMigrationFixtureBundle,
) -> None:
    selected_task, selected_profile = _validate_task_profile(
        task, profile
    )
    validate_nested_json_schema_migration_fixture_bundle(bundle)
    expected = _construct_nested_json_schema_migration_fixture_bundle(
        selected_task, selected_profile
    )
    if expected != bundle:
        raise NestedJsonSchemaMigrationError(
            "bundle differs from deterministic reconstruction"
        )
    index = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES.index(
        selected_profile
    )
    if selected_task.fixtures[index] != bundle.descriptor:
        raise NestedJsonSchemaMigrationError(
            "public descriptor differs from private binding"
        )


def verify_nested_json_schema_migration_fixture_for_task_profile(
    task: object,
    profile: object,
    bundle: object,
) -> bool:
    try:
        validate_nested_json_schema_migration_fixture_for_task_profile(
            task,  # type: ignore[arg-type]
            profile,  # type: ignore[arg-type]
            bundle,  # type: ignore[arg-type]
        )
    except (
        AttributeError,
        NestedJsonSchemaMigrationError,
        TypeError,
        ValueError,
    ):
        return False
    return True


def _discrimination_signature(
    bundle: NestedJsonSchemaMigrationFixtureBundle,
) -> tuple[str, tuple[str, ...]]:
    source = _source_payload(bundle.definition)
    return (
        sha256(source).hexdigest(),
        tuple(
            sha256(item.content).hexdigest()
            for item in bundle.oracle.state.documents
        ),
    )


def compute_nested_json_schema_migration_discrimination_sha256(
    tasks: tuple[NestedJsonSchemaMigrationTask, ...],
) -> str:
    expected = tuple(
        (shape, policy)
        for shape in NESTED_JSON_SCHEMA_MIGRATION_INPUT_SHAPES
        for policy in NESTED_JSON_SCHEMA_MIGRATION_POLICIES
    )
    if (
        type(tasks) is not tuple
        or len(tasks) != 20
        or any(
            type(task) is not NestedJsonSchemaMigrationTask
            for task in tasks
        )
        or tuple(
            (
                task.parameters.input_shape,
                task.parameters.migration_policy,
            )
            for task in tasks
        )
        != expected
    ):
        raise NestedJsonSchemaMigrationError(
            "discrimination requires canonical 20-cell task order"
        )
    profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
    signatures = tuple(
        _discrimination_signature(
            _construct_nested_json_schema_migration_fixture_bundle(
                task, profile
            )
        )
        for task in tasks
    )
    if len(set(signatures)) != len(signatures):
        raise NestedJsonSchemaMigrationError(
            "task grid is not behaviorally discriminable"
        )
    # Deliberately exclude shape names, policy names, prompts, graph labels,
    # manifest bytes, and task IDs.  This evidence binds only source bytes and
    # ordered migrated document outcomes.
    return domain_sha256(
        "cbds.executable-static.nested-json-schema-migration."
        "discrimination-evidence.v1",
        {
            "family_id": NESTED_JSON_SCHEMA_MIGRATION_FAMILY_ID,
            "profile_sha256": profile.profile_sha256,
            "signature_count": len(signatures),
            "outcomes": [
                {
                    "source_sha256": source_sha256,
                    "document_sha256s": list(document_sha256s),
                }
                for source_sha256, document_sha256s in signatures
            ],
        },
    )


def build_nested_json_schema_migration_tasks() -> tuple[
    NestedJsonSchemaMigrationTask, ...
]:
    tasks: list[NestedJsonSchemaMigrationTask] = []
    signatures: list[tuple[str, tuple[str, ...]]] = []
    for shape in NESTED_JSON_SCHEMA_MIGRATION_INPUT_SHAPES:
        for policy in NESTED_JSON_SCHEMA_MIGRATION_POLICIES:
            bootstrap = _bootstrap_task(
                NestedJsonSchemaMigrationParameters(shape, policy)
            )
            bundles = tuple(
                _construct_nested_json_schema_migration_fixture_bundle(
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
        or len(
            {task.task_contract_sha256 for task in selected}
        )
        != 20
        or len({task.graph_sha256 for task in selected}) != 20
        or len(set(signatures)) != 20
    ):
        raise NestedJsonSchemaMigrationError(
            "task grid is not 20 discriminable cells"
        )
    return selected


def compute_nested_json_schema_migration_proved_output_bound() -> int:
    """Reconstruct the deliberately conservative output-bound proof.

    Every individual document is first checked with all optional members,
    maximum-length escape-heavy strings, and maximum tag cardinality under
    all five policies.  The manifest is checked at maximum document count.
    The declared aggregate then allocates the full per-file byte ceiling to
    every file; it is conservative rather than a claim of a tight maximum.
    """

    worst = "\\" * NESTED_JSON_SCHEMA_MIGRATION_SCALAR_MAXIMUM_UTF8_BYTES
    source: dict[str, object] = {
        "schema_version": 1,
        "record_id": worst,
        "profile": {
            "display_name": worst,
            "enabled": "false",
            "limits": {
                "quota": str(
                    NESTED_JSON_SCHEMA_MIGRATION_QUOTA_MAXIMUM
                )
            },
            "contact": {"email": worst},
            "deprecated_code": worst,
        },
        "tags": [
            worst
            for _ in range(
                NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_TAGS
            )
        ],
        "deprecated": {"note": worst},
    }
    for policy in NESTED_JSON_SCHEMA_MIGRATION_POLICIES:
        primary = _migrate_document_primary(source, policy)
        reference = _migrate_document_reference(source, policy)
        if (
            primary != reference
            or len(_canonical_json(primary))
            > NESTED_JSON_SCHEMA_MIGRATION_DOCUMENT_OUTPUT_MAXIMUM_BYTES
        ):
            raise NestedJsonSchemaMigrationError(
                "worst-case document exceeds its declared ceiling"
            )
    entries = [
        {
            "file": _numbered_relative_path(index),
            "source_index": index,
            "source_key": (
                f"{index:02d}"
                + "\\" * (
                    NESTED_JSON_SCHEMA_MIGRATION_SCALAR_MAXIMUM_UTF8_BYTES
                    - 2
                )
            ),
        }
        for index in range(
            NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_DOCUMENTS
        )
    ]
    manifest = {
        "input_shape": "keyed-object-map",
        "migration_policy": "combined-version-upgrade",
        "document_count": (
            NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_DOCUMENTS
        ),
        "entries": entries,
    }
    if (
        len(_canonical_json(manifest))
        > NESTED_JSON_SCHEMA_MIGRATION_MANIFEST_OUTPUT_MAXIMUM_BYTES
        or NESTED_JSON_SCHEMA_MIGRATION_PROVED_MAXIMUM_TOTAL_OUTPUT_BYTES
        > MAX_TOTAL_BYTES
    ):
        raise NestedJsonSchemaMigrationError(
            "manifest or aggregate output proof exceeds workspace bounds"
        )
    return NESTED_JSON_SCHEMA_MIGRATION_PROVED_MAXIMUM_TOTAL_OUTPUT_BYTES


def materialize_nested_json_schema_migration_fixture(
    task: NestedJsonSchemaMigrationTask,
    profile: ExecutableFixtureProfile,
    bundle: NestedJsonSchemaMigrationFixtureBundle,
    workspace: str | os.PathLike[str],
) -> WorkspaceHandle:
    validate_nested_json_schema_migration_fixture_for_task_profile(
        task, profile, bundle
    )
    return materialize_fixture(bundle.definition, workspace)


def verify_nested_json_schema_migration_workspace(
    task: NestedJsonSchemaMigrationTask,
    profile: ExecutableFixtureProfile,
    bundle: NestedJsonSchemaMigrationFixtureBundle,
    handle: WorkspaceHandle,
) -> bool:
    """Verify the exact semantic output tree and pinned input state."""

    if type(handle) is not WorkspaceHandle:
        return False
    try:
        validate_nested_json_schema_migration_fixture_for_task_profile(
            task, profile, bundle
        )
        baseline = handle.baseline
        if (
            baseline.fixture_id != bundle.definition.fixture_id
            or baseline.fixture_sha256
            != bundle.definition.fixture_sha256
            or handle.expected_files
            != bundle.definition.expected_files
            or handle.expected_symlinks
            or baseline.output_scaffold_entries
        ):
            return False
        primary = derive_nested_json_schema_migration_state(
            bundle.definition, task.parameters
        )
        reference = reference_nested_json_schema_migration_state(
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
        expected_paths = {
            item.path for item in bundle.definition.expected_files
        }
        if (
            len(output_entries) != len(expected_paths)
            or {item.path for item in output_entries} != expected_paths
            or any(
                item.mode
                != NESTED_JSON_SCHEMA_MIGRATION_OUTPUT_MODE
                or item.link_count != 1
                or item.hardlink_group_sha256 is not None
                for item in output_entries
            )
        ):
            return False

        observed_manifest = handle.read_output_bytes(
            output_scan,
            NESTED_JSON_SCHEMA_MIGRATION_OUTPUT_MANIFEST,
        )
        if (
            parse_nested_json_schema_migration_manifest_output(
                observed_manifest
            )
            != primary.manifest
        ):
            return False
        for document in primary.documents:
            observed = handle.read_output_bytes(
                output_scan,
                f"output/{document.file}",
            )
            if (
                parse_nested_json_schema_migration_document_output(
                    observed
                )
                != document.content
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
        NestedJsonSchemaMigrationError,
        OSError,
        TypeError,
        ValueError,
    ):
        return False


__all__ = [
    "MigratedJsonDocument",
    "NESTED_JSON_SCHEMA_MIGRATION_ALLOWED_TOOLS",
    "NESTED_JSON_SCHEMA_MIGRATION_ATOMICITY_OBSERVED",
    "NESTED_JSON_SCHEMA_MIGRATION_CANDIDATE_EXIT_STATUS_OBSERVED",
    "NESTED_JSON_SCHEMA_MIGRATION_DOCUMENT_OUTPUT_MAXIMUM_BYTES",
    "NESTED_JSON_SCHEMA_MIGRATION_FAMILY_ID",
    "NESTED_JSON_SCHEMA_MIGRATION_FILESYSTEM_IDENTITY",
    "NESTED_JSON_SCHEMA_MIGRATION_FINAL_OUTPUT_OBSERVED",
    "NESTED_JSON_SCHEMA_MIGRATION_GENERATOR_VERSION",
    "NESTED_JSON_SCHEMA_MIGRATION_INPUT",
    "NESTED_JSON_SCHEMA_MIGRATION_INPUT_PRESERVATION_OBSERVED",
    "NESTED_JSON_SCHEMA_MIGRATION_INPUT_SHAPES",
    "NESTED_JSON_SCHEMA_MIGRATION_MANIFEST_OUTPUT_MAXIMUM_BYTES",
    "NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_DEPTH",
    "NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_DOCUMENTS",
    "NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_NODES",
    "NESTED_JSON_SCHEMA_MIGRATION_OUTPUT_DIRECTORY",
    "NESTED_JSON_SCHEMA_MIGRATION_OUTPUT_IDENTITY",
    "NESTED_JSON_SCHEMA_MIGRATION_OUTPUT_MANIFEST",
    "NESTED_JSON_SCHEMA_MIGRATION_OUTPUT_MODE",
    "NESTED_JSON_SCHEMA_MIGRATION_POLICIES",
    "NESTED_JSON_SCHEMA_MIGRATION_PROVED_MAXIMUM_TOTAL_OUTPUT_BYTES",
    "NESTED_JSON_SCHEMA_MIGRATION_READ_SCOPE_OBSERVED",
    "NESTED_JSON_SCHEMA_MIGRATION_SCALAR_MAXIMUM_UTF8_BYTES",
    "NESTED_JSON_SCHEMA_MIGRATION_SOURCE_MAXIMUM_BYTES",
    "NESTED_JSON_SCHEMA_MIGRATION_TOOL_HISTORY_OBSERVED",
    "NESTED_JSON_SCHEMA_MIGRATION_TRANSIENT_STATE_OBSERVED",
    "NESTED_JSON_SCHEMA_MIGRATION_VERIFIER_IDENTITY",
    "NESTED_JSON_SCHEMA_MIGRATION_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE",
    "NESTED_JSON_SCHEMA_MIGRATION_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE",
    "NestedJsonSchemaMigrationError",
    "NestedJsonSchemaMigrationFixtureBundle",
    "NestedJsonSchemaMigrationOracle",
    "NestedJsonSchemaMigrationParameters",
    "NestedJsonSchemaMigrationState",
    "NestedJsonSchemaMigrationTask",
    "build_nested_json_schema_migration_fixture_bundle",
    "build_nested_json_schema_migration_tasks",
    "compute_nested_json_schema_migration_discrimination_sha256",
    "compute_nested_json_schema_migration_proved_output_bound",
    "compute_nested_json_schema_migration_task_sha256",
    "derive_nested_json_schema_migration_state",
    "materialize_nested_json_schema_migration_fixture",
    "nested_json_schema_migration_task_semantic_core",
    "parse_nested_json_schema_migration_document_output",
    "parse_nested_json_schema_migration_manifest_output",
    "parse_nested_json_schema_migration_source",
    "reference_nested_json_schema_migration_state",
    "validate_nested_json_schema_migration_fixture_bundle",
    "validate_nested_json_schema_migration_fixture_for_task_profile",
    "verify_nested_json_schema_migration_fixture_bundle",
    "verify_nested_json_schema_migration_fixture_for_task_profile",
    "verify_nested_json_schema_migration_workspace",
]
