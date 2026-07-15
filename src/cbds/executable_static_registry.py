"""Deterministic 100-task public method-development registry.

The bounded registry contains five semantic families with a four-by-five
parameter cross product.  It creates typed task contracts and opaque fixture
commitments only; fixture bytes, reference answers, and execution are outside
this module's scope.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from typing import Final, cast

from .benchmark import NormalizedSemanticGraph, OperatorNode
from .executable_static_types import (
    ActiveLabelKey,
    ActivePredicate,
    ActiveJsonlLabelsParameters,
    ChecksumLayout,
    ChecksumManifestParameters,
    ChecksumPolicy,
    CollisionPolicy,
    CopySelector,
    CsvLayout,
    CsvGroupTotalsParameters,
    CsvPredicate,
    EXECUTABLE_STATIC_FAMILY_VERSION,
    EXECUTABLE_STATIC_FIXTURE_PROFILE_SHA256,
    EXECUTABLE_STATIC_REGISTRY_VERSION,
    EXECUTABLE_STATIC_SUITE_ID,
    ExecutableStaticRegistry,
    ExecutableStaticTask,
    FamilyId,
    FilesystemIdentity,
    ManifestCopyParameters,
    OpaqueFixtureDescriptor,
    OutputIdentity,
    PathDepth,
    PathSuffix,
    PathSuffixInventoryParameters,
    TaskParameters,
    compute_executable_static_registry_sha256,
    compute_executable_static_suite_sha256,
    compute_task_contract_sha256,
    domain_sha256,
    task_id_from_contract,
)


REGISTRY_VERSION: Final[str] = EXECUTABLE_STATIC_REGISTRY_VERSION
SUITE_ID: Final[str] = EXECUTABLE_STATIC_SUITE_ID
FAMILY_VERSION: Final[str] = EXECUTABLE_STATIC_FAMILY_VERSION

ACTIVE_LABEL_KEYS: Final[tuple[ActiveLabelKey, ...]] = ("label", "name", "tag", "title")
ACTIVE_PREDICATES: Final[tuple[ActivePredicate, ...]] = (
    "active-true",
    "enabled-yes",
    "state-ready",
    "score-at-least-10",
    "deleted-false",
)
COPY_SELECTORS: Final[tuple[CopySelector, ...]] = (
    "all-readable",
    "txt-suffix",
    "selected-true",
    "declared-sha256-matches",
)
COLLISION_POLICIES: Final[tuple[CollisionPolicy, ...]] = (
    "reject-collision",
    "first-record",
    "last-record",
    "identical-bytes-only",
    "utf8-smallest-source",
)
CSV_LAYOUTS: Final[tuple[CsvLayout, ...]] = (
    "category-amount-enabled",
    "enabled-category-amount",
    "amount-enabled-category",
    "category-enabled-amount",
)
CSV_PREDICATES: Final[tuple[CsvPredicate, ...]] = (
    "all-valid",
    "enabled-yes",
    "positive-amount",
    "nonempty-category",
    "enabled-and-positive",
)
CHECKSUM_LAYOUTS: Final[tuple[ChecksumLayout, ...]] = (
    "json-object-lines",
    "json-array-lines",
    "rfc4180-csv",
    "nul-triplets",
)
CHECKSUM_POLICIES: Final[tuple[ChecksumPolicy, ...]] = (
    "digest-only",
    "mode-only",
    "digest-and-mode",
    "readable-digest-and-mode",
    "strict-kind-digest-and-mode",
)
PATH_SUFFIXES: Final[tuple[PathSuffix, ...]] = (".txt", ".jsonl", ".log", ".csv")
PATH_DEPTHS: Final[tuple[PathDepth, ...]] = (1, 2, 3, 4, "unbounded")


_FIXTURE_PROFILE_SHA256: Final[tuple[str, ...]] = (
    EXECUTABLE_STATIC_FIXTURE_PROFILE_SHA256
)


_ACTIVE_PREDICATE_TEXT: Final[dict[str, str]] = {
    "active-true": "the `active` member is exactly the JSON boolean true",
    "enabled-yes": "the `enabled` member is exactly the JSON string `yes`",
    "state-ready": "the `state` member is exactly the JSON string `ready`",
    "score-at-least-10": (
        "the `score` member is a finite JSON number other than a boolean and is at least 10"
    ),
    "deleted-false": "the `deleted` member is exactly the JSON boolean false",
}
_COPY_SELECTOR_TEXT: Final[dict[str, str]] = {
    "all-readable": "every otherwise eligible readable regular source",
    "txt-suffix": "only sources whose final basename ends exactly in `.txt`",
    "selected-true": "only records whose `selected` member is exactly the JSON boolean true",
    "declared-sha256-matches": (
        "only records whose lowercase `sha256` member equals the SHA-256 of the source bytes"
    ),
}
_COLLISION_TEXT: Final[dict[str, str]] = {
    "reject-collision": "emit no file for a destination named by more than one eligible record",
    "first-record": "use the first eligible record in manifest order",
    "last-record": "use the last eligible record in manifest order",
    "identical-bytes-only": (
        "emit the destination only when every eligible record for it resolves to identical bytes"
    ),
    "utf8-smallest-source": (
        "use the eligible source path with the lexicographically smallest UTF-8 byte sequence"
    ),
}
_CSV_HEADER: Final[dict[str, str]] = {
    "category-amount-enabled": "category,amount,enabled",
    "enabled-category-amount": "enabled,category,amount",
    "amount-enabled-category": "amount,enabled,category",
    "category-enabled-amount": "category,enabled,amount",
}
_CSV_PREDICATE_TEXT: Final[dict[str, str]] = {
    "all-valid": "include every otherwise valid data row",
    "enabled-yes": "include only rows whose enabled field is exactly `yes`",
    "positive-amount": "include only rows whose amount is greater than zero",
    "nonempty-category": "include only rows whose category is nonempty",
    "enabled-and-positive": (
        "include only rows whose enabled field is exactly `yes` and whose amount is greater than zero"
    ),
}
_CHECKSUM_LAYOUT_TEXT: Final[dict[str, str]] = {
    "json-object-lines": (
        "UTF-8 JSON Lines objects with exactly string members `path`, `sha256`, and `mode`"
    ),
    "json-array-lines": (
        "UTF-8 JSON Lines arrays of exactly three strings `[path, sha256, mode]`"
    ),
    "rfc4180-csv": (
        "UTF-8 RFC 4180 CSV with the exact header `path,sha256,mode`"
    ),
    "nul-triplets": (
        "a byte stream of repeated UTF-8 `path`, ASCII `sha256`, and ASCII `mode` fields, "
        "each terminated by NUL"
    ),
}
_CHECKSUM_POLICY_TEXT: Final[dict[str, str]] = {
    "digest-only": (
        "classify existing readable regular files only as `ok` or `checksum_mismatch`; "
        "classify every other target as `unavailable`"
    ),
    "mode-only": (
        "classify existing regular files only as `ok` or `mode_mismatch`, without reading bytes; "
        "classify every other target as `unavailable`"
    ),
    "digest-and-mode": (
        "classify readable regular files as `ok`, `checksum_mismatch`, `mode_mismatch`, or "
        "`checksum_and_mode_mismatch`; classify every other target as `unavailable`"
    ),
    "readable-digest-and-mode": (
        "first distinguish `missing`, `not_regular`, and `unreadable`, then apply the four "
        "digest-and-mode statuses"
    ),
    "strict-kind-digest-and-mode": (
        "first distinguish `missing`, `symlink`, `directory`, and `unreadable`, "
        "then apply the four digest-and-mode statuses"
    ),
}


def _chain(*nodes: OperatorNode) -> NormalizedSemanticGraph:
    return NormalizedSemanticGraph(
        nodes=tuple(nodes),
        dependencies=tuple((index, index + 1) for index in range(len(nodes) - 1)),
    )


def _common_final_state(output_description: str) -> str:
    return (
        f"{output_description} Preserve every path, file kind, permission mode, byte, "
        "modification time, hard-link count, and symlink target below `input/`. Do not "
        "leave any path outside the original `input/` tree and the required `output/` tree. "
        "`output/` must be a real mode-0755 directory; every output file must be an "
        "independent mode-0644 regular file with link count one."
    )


def _active_contract(parameters: ActiveJsonlLabelsParameters) -> tuple[str, NormalizedSemanticGraph]:
    prompt = f"""Write one Bash program that operates only in the current workspace.

Recursively inspect `input/records/` without following symbolic links. Consider only
readable regular files whose basename ends exactly in `.jsonl`. Treat every nonempty
line independently as UTF-8 JSON and ignore malformed JSON and non-object values.
Select an object only when {_ACTIVE_PREDICATE_TEXT[parameters.predicate]}. From each
selected object take its `{parameters.label_key}` member only when that member is a
JSON string containing no NUL, carriage return, or newline. Deduplicate the resulting
strings and sort them by their exact UTF-8 bytes under `LC_ALL=C`.

{_common_final_state("Write the strings to `output/labels.txt`, one per line, with a final LF when nonempty and zero bytes when empty.")}
Use only Bash built-ins plus `find`, `jq`, `mkdir`, and `sort`.
"""
    graph = _chain(
        OperatorNode("discover_files", ("root:input/records", "suffix:.jsonl", "no_follow:true")),
        OperatorNode("select_json", (f"label_key:{parameters.label_key}", f"predicate:{parameters.predicate}")),
        OperatorNode("deduplicate", ("key:utf8-string",)),
        OperatorNode("sort_records", ("order:utf8-bytes",)),
        OperatorNode("emit_lines", ("path:output/labels.txt", "framing:lf",)),
    )
    return prompt, graph


def _copy_contract(parameters: ManifestCopyParameters) -> tuple[str, NormalizedSemanticGraph]:
    prompt = f"""Write one Bash program that operates only in the current workspace.

Read nonempty UTF-8 JSON lines from `input/copy-map.jsonl`. Ignore malformed lines
and records whose `source` or `destination` member is not a safe relative POSIX path.
Resolve sources below `input/files/` and destinations below `output/` without following
symbolic links. Missing, non-regular, or mode-unreadable sources are ineligible. Select
{_COPY_SELECTOR_TEXT[parameters.selector]}. For each destination with multiple eligible
records, {_COLLISION_TEXT[parameters.collision_policy]}. Copy the selected source bytes
exactly, creating only necessary destination directories.

{_common_final_state("The final `output/` tree must contain exactly the selected destination files and their necessary parent directories.")}
Use only Bash built-ins plus `cp`, `jq`, `mkdir`, and `sha256sum`.
"""
    graph = _chain(
        OperatorNode("parse_copy_manifest", ("path:input/copy-map.jsonl", "format:jsonl",)),
        OperatorNode("qualify_copy_source", (f"selector:{parameters.selector}", "no_follow:true")),
        OperatorNode("resolve_destination_collision", (f"policy:{parameters.collision_policy}",)),
        OperatorNode("copy_selected_files", ("root:input/files", "destination:output", "bytes:exact")),
        OperatorNode("verify_output_tree_shape", ("extra_paths:forbidden",)),
    )
    return prompt, graph


def _csv_contract(parameters: CsvGroupTotalsParameters) -> tuple[str, NormalizedSemanticGraph]:
    header = _CSV_HEADER[parameters.layout]
    prompt = f"""Write one Bash program that operates only in the current workspace.

Recursively inspect `input/records/` without following symbolic links. Consider only
readable regular files whose basename ends exactly in `.csv`. Parse each as UTF-8 RFC
4180 CSV and skip the entire file if it is malformed or its first row is not exactly
`{header}`. Ignore data rows that do not have exactly three fields or whose amount is
not a base-10 integer matching `-?[0-9]+`. {_CSV_PREDICATE_TEXT[parameters.predicate]}.
Sum included amounts by the exact category string across all accepted files.

{_common_final_state("Write `output/totals.csv` as UTF-8 RFC 4180 CSV with LF endings, the header `category,total`, and one row per category sorted by the category's exact UTF-8 bytes.")}
Use only Bash built-ins plus `awk`, `mkdir`, and `sort`.
"""
    graph = _chain(
        OperatorNode("discover_files", ("root:input/records", "suffix:.csv", "no_follow:true")),
        OperatorNode("parse_csv", (f"layout:{parameters.layout}", "syntax:rfc4180",)),
        OperatorNode("filter_csv_rows", (f"predicate:{parameters.predicate}", "amount:base10-integer")),
        OperatorNode("aggregate_fields", ("group:category", "measure:amount", "operation:sum")),
        OperatorNode("sort_records", ("field:category", "order:utf8-bytes",)),
        OperatorNode("emit_csv", ("path:output/totals.csv", "line_ending:lf",)),
    )
    return prompt, graph


def _checksum_contract(parameters: ChecksumManifestParameters) -> tuple[str, NormalizedSemanticGraph]:
    prompt = f"""Write one Bash program that operates only in the current workspace.

Read `input/manifest.data` as {_CHECKSUM_LAYOUT_TEXT[parameters.layout]}. A valid path
is a safe relative POSIX path below `input/assets/`, a valid digest is exactly 64
lowercase hexadecimal characters, and a valid mode is exactly three octal digits.
Ignore malformed records and inspect targets without following symbolic links. For every valid record,
{_CHECKSUM_POLICY_TEXT[parameters.policy]}. Retain duplicate valid records as duplicate
report rows.

{_common_final_state("Write `output/report.jsonl`, sorted by path UTF-8 bytes with original manifest order as the tie breaker, as one JSON object per line containing exactly string members `path` and `status`.")}
Use only Bash built-ins plus `awk`, `jq`, `mkdir`, `sha256sum`, `sort`, and `stat`.
"""
    nodes = [
        OperatorNode("parse_checksum_manifest", (f"layout:{parameters.layout}", "path:input/manifest.data")),
        OperatorNode("inspect_manifest_path", (f"policy:{parameters.policy}", "no_follow:true")),
    ]
    if parameters.policy != "mode-only":
        nodes.append(OperatorNode("compute_checksum", ("algorithm:sha256",)))
    nodes.extend(
        (
            OperatorNode("classify_checksum_status", (f"policy:{parameters.policy}",)),
            OperatorNode("sort_records", ("primary:path-utf8", "tie:manifest-order")),
            OperatorNode("emit_jsonl", ("path:output/report.jsonl", "keys:path,status")),
        )
    )
    return prompt, _chain(*nodes)


def _path_contract(parameters: PathSuffixInventoryParameters) -> tuple[str, NormalizedSemanticGraph]:
    depth_text = (
        "at any depth"
        if parameters.maximum_depth == "unbounded"
        else f"at most {parameters.maximum_depth} path component(s) below `input/tree/`"
    )
    prompt = f"""Write one Bash program that operates only in the current workspace.

Recursively inspect `input/tree/` without following symbolic links. Select only
mode-readable regular files {depth_text} whose basename ends exactly in
`{parameters.suffix}`. Emit each selected path relative to `input/tree/`, without a
leading `./`. Sort paths by their exact UTF-8 bytes under `LC_ALL=C`; do not deduplicate
distinct directory entries.

{_common_final_state("Write the paths to `output/paths.txt`, one per line, with a final LF when nonempty and zero bytes when empty.")}
Use only Bash built-ins plus `find`, `mkdir`, and `sort`.
"""
    return prompt, _chain(
        OperatorNode("discover_files", ("root:input/tree", f"maximum_depth:{parameters.maximum_depth}", "no_follow:true")),
        OperatorNode("filter_suffix", (f"suffix:{parameters.suffix}", "kind:readable-regular")),
        OperatorNode("project_relative_path", ("base:input/tree", "prefix:none")),
        OperatorNode("sort_records", ("order:utf8-bytes",)),
        OperatorNode("emit_lines", ("path:output/paths.txt", "framing:lf",)),
    )


_ContractBuilder = Callable[[TaskParameters], tuple[str, NormalizedSemanticGraph]]


def _bootstrap_fixture_descriptors(
    task_contract_sha256: str,
) -> tuple[OpaqueFixtureDescriptor, ...]:
    """Create private construction-only descriptors for task validation.

    They are replaced by content-bound descriptors from the real generated
    fixture definitions and trusted oracles before a task leaves ``_make_task``.
    """

    records: list[OpaqueFixtureDescriptor] = []
    for profile_sha256 in _FIXTURE_PROFILE_SHA256:
        digest = domain_sha256(
            "cbds.executable-static.fixture.v1",
            {
                "task_contract_sha256": task_contract_sha256,
                "profile_sha256": profile_sha256,
            },
        )
        records.append(
            OpaqueFixtureDescriptor(
                fixture_id=f"fx-{digest[:24]}",
                fixture_sha256=digest,
                task_contract_sha256=task_contract_sha256,
            )
        )
    return tuple(records)


def _make_task(
    *,
    family_id: FamilyId,
    parameters: TaskParameters,
    contract_builder: _ContractBuilder,
    filesystem_identity: FilesystemIdentity,
    output_identity: OutputIdentity,
    allowed_tools: tuple[str, ...],
) -> ExecutableStaticTask:
    prompt, graph = contract_builder(parameters)
    contract_sha256 = compute_task_contract_sha256(
        family_id=family_id,
        family_version=FAMILY_VERSION,
        parameters=parameters,
        prompt=prompt,
        graph=graph,
        filesystem_identity=filesystem_identity,
        output_identity=output_identity,
        allowed_tools=allowed_tools,
    )
    bootstrap = ExecutableStaticTask(
        task_id=task_id_from_contract(contract_sha256),
        family_id=family_id,
        family_version=FAMILY_VERSION,
        parameters=parameters,
        prompt=prompt,
        graph=graph,
        filesystem_identity=filesystem_identity,
        output_identity=output_identity,
        allowed_tools=allowed_tools,
        fixtures=_bootstrap_fixture_descriptors(contract_sha256),
        task_contract_sha256=contract_sha256,
    )
    # Import lazily so the catalog can depend on the task contract types and
    # family generators without creating a module-import cycle.
    from .executable_fixture_catalog import (
        build_fixture_bundle_for_task_profile,
    )
    from .executable_fixture_profiles import (
        PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
    )

    descriptors = tuple(
        build_fixture_bundle_for_task_profile(bootstrap, profile).descriptor
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
    )
    return replace(bootstrap, fixtures=descriptors)


def _all_tasks() -> tuple[ExecutableStaticTask, ...]:
    tasks: list[ExecutableStaticTask] = []
    for label_key in ACTIVE_LABEL_KEYS:
        for predicate in ACTIVE_PREDICATES:
            parameters = ActiveJsonlLabelsParameters(
                label_key=label_key,
                predicate=predicate,
            )
            tasks.append(
                _make_task(
                    family_id="active-jsonl-labels",
                    parameters=parameters,
                    contract_builder=cast(_ContractBuilder, _active_contract),
                    filesystem_identity="structured-records-tree-v1",
                    output_identity="utf8-byte-sorted-lines-v1",
                    allowed_tools=("find", "jq", "mkdir", "sort"),
                )
            )
    for selector in COPY_SELECTORS:
        for collision_policy in COLLISION_POLICIES:
            parameters = ManifestCopyParameters(
                selector=selector,
                collision_policy=collision_policy,
            )
            tasks.append(
                _make_task(
                    family_id="manifest-copy",
                    parameters=parameters,
                    contract_builder=cast(_ContractBuilder, _copy_contract),
                    filesystem_identity="symlinked-copy-workspace-v1",
                    output_identity="exact-output-tree-v1",
                    allowed_tools=("cp", "jq", "mkdir", "sha256sum"),
                )
            )
    for layout in CSV_LAYOUTS:
        for predicate in CSV_PREDICATES:
            parameters = CsvGroupTotalsParameters(
                layout=layout, predicate=predicate
            )
            tasks.append(
                _make_task(
                    family_id="csv-group-totals",
                    parameters=parameters,
                    contract_builder=cast(_ContractBuilder, _csv_contract),
                    filesystem_identity="structured-csv-tree-v1",
                    output_identity="rfc4180-group-totals-v1",
                    allowed_tools=("awk", "mkdir", "sort"),
                )
            )
    for layout in CHECKSUM_LAYOUTS:
        for policy in CHECKSUM_POLICIES:
            parameters = ChecksumManifestParameters(
                layout=layout, policy=policy
            )
            tasks.append(
                _make_task(
                    family_id="checksum-manifest",
                    parameters=parameters,
                    contract_builder=cast(_ContractBuilder, _checksum_contract),
                    filesystem_identity="permission-boundary-assets-v1",
                    output_identity="jsonl-checksum-status-v1",
                    allowed_tools=("awk", "jq", "mkdir", "sha256sum", "sort", "stat"),
                )
            )
    for suffix in PATH_SUFFIXES:
        for maximum_depth in PATH_DEPTHS:
            parameters = PathSuffixInventoryParameters(
                suffix=suffix, maximum_depth=maximum_depth
            )
            tasks.append(
                _make_task(
                    family_id="path-suffix-inventory",
                    parameters=parameters,
                    contract_builder=cast(_ContractBuilder, _path_contract),
                    filesystem_identity="nested-project-tree-v1",
                    output_identity="utf8-byte-sorted-paths-v1",
                    allowed_tools=("find", "mkdir", "sort"),
                )
            )
    return tuple(tasks)


def compute_registry_sha256(tasks: tuple[ExecutableStaticTask, ...]) -> str:
    return compute_executable_static_registry_sha256(tasks)


def compute_suite_sha256(
    tasks: tuple[ExecutableStaticTask, ...], registry_sha256: str
) -> str:
    return compute_executable_static_suite_sha256(tasks, registry_sha256)


def build_public_method_development_registry() -> ExecutableStaticRegistry:
    """Return the deterministic nonsealed, nonclaiming 100-task registry."""

    tasks = _all_tasks()
    registry_sha256 = compute_registry_sha256(tasks)
    suite_sha256 = compute_suite_sha256(tasks, registry_sha256)
    return ExecutableStaticRegistry(
        tasks=tasks,
        registry_sha256=registry_sha256,
        suite_sha256=suite_sha256,
    )


__all__ = [
    "ACTIVE_LABEL_KEYS",
    "ACTIVE_PREDICATES",
    "CHECKSUM_LAYOUTS",
    "CHECKSUM_POLICIES",
    "COLLISION_POLICIES",
    "COPY_SELECTORS",
    "CSV_LAYOUTS",
    "CSV_PREDICATES",
    "FAMILY_VERSION",
    "PATH_DEPTHS",
    "PATH_SUFFIXES",
    "REGISTRY_VERSION",
    "SUITE_ID",
    "build_public_method_development_registry",
    "compute_registry_sha256",
    "compute_suite_sha256",
]
