"""Additive task builders for the second executable-static tranche.

The checked first-tranche registry is deliberately immutable.  This module
owns only new public method-development task contracts; it does not alter the
100 existing tasks. Five deterministic 20-task grids form one hash-bound
100-task addition; catalog construction and authority remain separate.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Final

from .benchmark import NormalizedSemanticGraph, OperatorNode
from .executable_static_types import (
    EXECUTABLE_STATIC_FAMILY_VERSION,
    EXECUTABLE_STATIC_FIXTURE_PROFILE_SHA256,
    ExecutableStaticTask,
    FamilyId,
    FilesystemIdentity,
    JoinDuplicatePolicy,
    JoinKey,
    JsonlKeyedInnerJoinParameters,
    LineTransform,
    LineTransformMirrorParameters,
    ModeMirrorSelector,
    ModeNormalization,
    ModeNormalizedMirrorParameters,
    OpaqueFixtureDescriptor,
    OutputIdentity,
    PathSuffix,
    ProcSnapshotPredicate,
    ProcSnapshotReportParameters,
    ProcSnapshotView,
    TaskParameters,
    UstarConflictPolicy,
    UstarSafeExtractParameters,
    UstarSelector,
    compute_task_contract_sha256,
    domain_sha256,
    task_id_from_contract,
)


LINE_TRANSFORM_SUFFIXES: Final[tuple[PathSuffix, ...]] = (
    ".txt",
    ".jsonl",
    ".log",
    ".csv",
)
LINE_TRANSFORMS: Final[tuple[LineTransform, ...]] = (
    "identity",
    "ascii-upper",
    "ascii-lower",
    "tabs-to-four-spaces",
    "delete-carriage-returns",
)
MODE_MIRROR_SELECTORS: Final[tuple[ModeMirrorSelector, ...]] = (
    "all-readable",
    "txt-suffix",
    "any-executable",
    "owner-writable",
)
MODE_NORMALIZATIONS: Final[tuple[ModeNormalization, ...]] = (
    "fixed-0644",
    "fixed-0600",
    "fixed-0444",
    "preserve-exec",
    "fold-class-bits-to-owner",
)
JOIN_KEYS: Final[tuple[JoinKey, ...]] = ("id", "key", "name", "slug")
JOIN_DUPLICATE_POLICIES: Final[tuple[JoinDuplicatePolicy, ...]] = (
    "cartesian",
    "first-left",
    "last-left",
    "first-right",
    "last-right",
)
USTAR_SELECTORS: Final[tuple[UstarSelector, ...]] = (
    "all-regular",
    "txt-suffix",
    "jsonl-suffix",
    "nonempty-regular",
)
USTAR_CONFLICT_POLICIES: Final[tuple[UstarConflictPolicy, ...]] = (
    "reject-duplicates",
    "first-entry",
    "last-entry",
    "identical-only",
    "smallest-sha256",
)
PROC_SNAPSHOT_VIEWS: Final[tuple[ProcSnapshotView, ...]] = (
    "identity",
    "ownership",
    "memory",
    "command",
)
PROC_SNAPSHOT_PREDICATES: Final[tuple[ProcSnapshotPredicate, ...]] = (
    "all-valid",
    "running-only",
    "non-zombie",
    "uid-zero",
    "has-argv",
)

SECOND_TRANCHE_REGISTRY_SCHEMA_VERSION: Final[str] = "1.0.0"
SECOND_TRANCHE_REGISTRY_VERSION: Final[str] = "1.0.0"
SECOND_TRANCHE_ADDED_TASK_COUNT: Final[int] = 100
SECOND_TRANCHE_CUMULATIVE_TASK_COUNT: Final[int] = 200
FROZEN_FIRST_REGISTRY_SHA256: Final[str] = (
    "ada6043b345e48f69ad602581030aab1bafcb3ff9dc453f9d02342faaf6a7f9a"
)
FROZEN_FIRST_SUITE_SHA256: Final[str] = (
    "eb64bb4cdb60ab8e0e228f688cf54810fae2ef56768e8b34ac039bdc1aec42ae"
)


def _is_exact_lower_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )

_TRANSFORM_TEXT: Final[dict[LineTransform, str]] = {
    "identity": "leave every byte unchanged",
    "ascii-upper": (
        "replace each ASCII byte `a` through `z` with the corresponding "
        "byte `A` through `Z` and leave every other byte unchanged"
    ),
    "ascii-lower": (
        "replace each ASCII byte `A` through `Z` with the corresponding "
        "byte `a` through `z` and leave every other byte unchanged"
    ),
    "tabs-to-four-spaces": (
        "replace every horizontal-tab byte (0x09) with exactly four ASCII "
        "space bytes and leave every other byte unchanged"
    ),
    "delete-carriage-returns": (
        "delete every carriage-return byte (0x0d) and leave every other "
        "byte unchanged"
    ),
}

_MODE_SELECTOR_TEXT: Final[dict[ModeMirrorSelector, str]] = {
    "all-readable": "every mode-readable regular file",
    "txt-suffix": (
        "every mode-readable regular file whose basename ends exactly in `.txt`"
    ),
    "any-executable": (
        "every mode-readable regular file with at least one execute bit set"
    ),
    "owner-writable": (
        "every mode-readable regular file whose owner-write bit is set"
    ),
}
_MODE_NORMALIZATION_TEXT: Final[dict[ModeNormalization, str]] = {
    "fixed-0644": "set every output file mode to 0644",
    "fixed-0600": "set every output file mode to 0600",
    "fixed-0444": "set every output file mode to 0444",
    "preserve-exec": (
        "set the output mode to 0755 when any source execute bit is set and "
        "to 0644 otherwise"
    ),
    "fold-class-bits-to-owner": (
        "OR the source owner, group, and other rwx triplets together, place "
        "that triplet in the output owner bits, and clear every group and "
        "other bit"
    ),
}
_JOIN_POLICY_TEXT: Final[dict[JoinDuplicatePolicy, str]] = {
    "cartesian": "retain every left/right pair for each shared key",
    "first-left": (
        "retain only the first valid left record for each key and pair it "
        "with every matching right record"
    ),
    "last-left": (
        "retain only the last valid left record for each key and pair it "
        "with every matching right record"
    ),
    "first-right": (
        "retain every left record and pair it only with the first valid "
        "right record for each key"
    ),
    "last-right": (
        "retain every left record and pair it only with the last valid right "
        "record for each key"
    ),
}
_USTAR_SELECTOR_TEXT: Final[dict[UstarSelector, str]] = {
    "all-regular": "every safe regular-file member",
    "txt-suffix": (
        "only safe regular-file members whose basename ends exactly in `.txt`"
    ),
    "jsonl-suffix": (
        "only safe regular-file members whose basename ends exactly in `.jsonl`"
    ),
    "nonempty-regular": "only safe regular-file members with nonzero size",
}
_USTAR_CONFLICT_TEXT: Final[dict[UstarConflictPolicy, str]] = {
    "reject-duplicates": "emit no file for a path named by multiple eligible members",
    "first-entry": "use the first eligible member in archive order",
    "last-entry": "use the last eligible member in archive order",
    "identical-only": (
        "emit the path only when every eligible member for it has identical bytes"
    ),
    "smallest-sha256": (
        "use the member with the lexicographically smallest lowercase SHA-256, "
        "breaking an equal-digest tie by earlier archive order"
    ),
}
_PROC_VIEW_TEXT: Final[dict[ProcSnapshotView, str]] = {
    "identity": (
        "emit exactly integer `pid` and `ppid` plus string `state`"
    ),
    "ownership": "emit exactly integer `pid` and `uid`",
    "memory": "emit exactly integer `pid` and `rss_kib`",
    "command": (
        "emit exactly integer `pid`, string `comm`, and array-of-string `argv`"
    ),
}
_PROC_PREDICATE_TEXT: Final[dict[ProcSnapshotPredicate, str]] = {
    "all-valid": "include every valid process snapshot",
    "running-only": "include only snapshots whose state is exactly `R`",
    "non-zombie": "include only snapshots whose state is not `Z`",
    "uid-zero": "include only snapshots whose uid is zero",
    "has-argv": "include only snapshots with at least one parsed argv element",
}


def _line_transform_contract(
    parameters: LineTransformMirrorParameters,
) -> tuple[str, NormalizedSemanticGraph]:
    prompt = f"""Write one Bash program that operates only in the current workspace.

Recursively inspect `input/text/` without following symbolic links. Select only
mode-readable regular files whose basename ends exactly in `{parameters.suffix}`.
For every selected file, mirror its path relative to `input/text/` beneath
`output/mirror/` and {_TRANSFORM_TEXT[parameters.transform]}. Empty files remain
valid selected files. Create only the necessary destination directories.

Preserve every path, file kind, permission mode, byte, modification time,
hard-link count, and symlink target below `input/`. The final `output/` tree must
contain exactly the selected transformed files and their necessary parent
directories. `output/`, `output/mirror/`, and every necessary output directory
must be real mode-0755 directories. Every output file must be an independent
mode-0644 regular file with link count one. Do not leave any other path.
Use only Bash built-ins plus `cp`, `find`, `mkdir`, `sed`, and `tr`.
"""
    graph = NormalizedSemanticGraph(
        nodes=(
            OperatorNode(
                "discover_transform_sources",
                (
                    "root:input/text",
                    f"suffix:{parameters.suffix}",
                    "kind:mode-readable-regular",
                    "no_follow:true",
                ),
            ),
            OperatorNode(
                "transform_file_bytes",
                (f"transform:{parameters.transform}", "locale:C"),
            ),
            OperatorNode(
                "project_mirror_path",
                ("source:input/text", "destination:output/mirror"),
            ),
            OperatorNode(
                "emit_transformed_mirror",
                ("file_mode:0644", "directory_mode:0755", "link_count:1"),
            ),
            OperatorNode(
                "verify_transformed_tree_shape",
                ("extra_paths:forbidden", "input_tree:preserved"),
            ),
        ),
        dependencies=((0, 1), (1, 2), (2, 3), (3, 4)),
    )
    return prompt, graph


def _mode_mirror_contract(
    parameters: ModeNormalizedMirrorParameters,
) -> tuple[str, NormalizedSemanticGraph]:
    prompt = f"""Write one Bash program that operates only in the current workspace.

Recursively inspect `input/assets/` without following symbolic links. Select
{_MODE_SELECTOR_TEXT[parameters.selector]}. Mirror every selected file's relative
path beneath `output/mirror/`, copying its bytes exactly, and
{_MODE_NORMALIZATION_TEXT[parameters.normalization]}. Create only necessary
destination directories.

Preserve the complete `input/` tree. The final `output/` tree must contain
exactly the selected independent regular files and their necessary parent
directories. Every output directory must have mode 0755 and every output file
must have link count one. Do not leave any other path. Use only Bash built-ins
plus `chmod`, `cp`, `find`, `mkdir`, and `stat`.
"""
    graph = NormalizedSemanticGraph(
        nodes=(
            OperatorNode(
                "discover_mode_sources",
                (
                    "root:input/assets",
                    f"selector:{parameters.selector}",
                    "no_follow:true",
                ),
            ),
            OperatorNode("copy_mode_selected_bytes", ("bytes:exact",)),
            OperatorNode(
                "normalize_output_mode",
                (f"normalization:{parameters.normalization}",),
            ),
            OperatorNode(
                "project_mode_mirror_path",
                ("source:input/assets", "destination:output/mirror"),
            ),
            OperatorNode(
                "verify_mode_mirror_tree",
                ("extra_paths:forbidden", "input_tree:preserved"),
            ),
        ),
        dependencies=((0, 1), (1, 2), (2, 3), (3, 4)),
    )
    return prompt, graph


def _join_contract(
    parameters: JsonlKeyedInnerJoinParameters,
) -> tuple[str, NormalizedSemanticGraph]:
    prompt = f"""Write one Bash program that operates only in the current workspace.

Read `input/left.jsonl` and `input/right.jsonl` as independent UTF-8 JSON Lines
streams. Ignore empty or malformed lines, non-object values, and objects whose
`{parameters.key}` member is not a string free of NUL, carriage return, and
newline. In this task's strict JSON dialect, duplicate object member names at
any nesting are malformed, and every number token must be a canonical decimal
integer from -9007199254740991 through 9007199254740991; fractions, exponents,
negative zero, NaN, and infinities are malformed. Record each accepted object's
zero-based order among accepted objects on its own side. Inner-join the two
sides by exact `{parameters.key}` string and
{_JOIN_POLICY_TEXT[parameters.duplicate_policy]}.

For every retained pair, emit one object containing exactly `key`, `left`, and
`right`, where `key` is the join string and `left` and `right` are the complete
source objects. Emit each row as one physical line of strict UTF-8 JSON.
Insignificant spaces or horizontal tabs, object-member order, and equivalent
string-escape spelling are not scored. Sort rows by key UTF-8 bytes, then
accepted-left order, then accepted-right order; retain otherwise duplicate
rows. Write them to `output/joined.jsonl` with a final LF when nonempty and
zero bytes when empty.

Preserve the complete `input/` tree. Leave only a real mode-0755 `output/`
directory and an independent mode-0644 `output/joined.jsonl` regular file with
link count one. Use only Bash built-ins plus `jq`, `mkdir`, and `sort`.
"""
    graph = NormalizedSemanticGraph(
        nodes=(
            OperatorNode(
                "parse_join_jsonl_sides",
                ("left:input/left.jsonl", "right:input/right.jsonl"),
            ),
            OperatorNode(
                "validate_join_key",
                (f"key:{parameters.key}", "type:string", "line_safe:true"),
            ),
            OperatorNode(
                "resolve_join_duplicates",
                (f"policy:{parameters.duplicate_policy}",),
            ),
            OperatorNode("inner_join_records", (f"key:{parameters.key}",)),
            OperatorNode(
                "sort_join_rows",
                ("primary:key-utf8", "tie:left-order,right-order"),
            ),
            OperatorNode(
                "emit_join_jsonl",
                ("path:output/joined.jsonl", "canonical_json:true"),
            ),
        ),
        dependencies=((0, 1), (1, 2), (2, 3), (3, 4), (4, 5)),
    )
    return prompt, graph


def _ustar_contract(
    parameters: UstarSafeExtractParameters,
) -> tuple[str, NormalizedSemanticGraph]:
    prompt = f"""Write one Bash program that operates only in the current workspace.

Read `input/archive.tar` as a POSIX ustar archive. Verify every 512-byte header
checksum and stop at the first invalid header or truncated member. A safe member
name is scalar UTF-8 and a canonical nonempty relative POSIX path with no
control character and no empty, `.`, or `..` component. Skip unsafe names,
symbolic links, hard links, devices, FIFOs, GNU extensions, and pax extensions
and continue with the next otherwise valid header; never extract them. From
valid typeflag `0` or NUL regular members, select
{_USTAR_SELECTOR_TEXT[parameters.selector]}. For multiple eligible members
naming the same path, {_USTAR_CONFLICT_TEXT[parameters.conflict_policy]}.

Write selected bytes below `output/extracted/` at their archive-relative paths.
The output tree must contain exactly those independent mode-0644 regular files
and necessary mode-0755 directories, with link count one and no other paths.
Preserve the complete `input/` tree. Use only Bash built-ins plus `mkdir`, `od`,
`sha256sum`, and `tar`.
"""
    graph = NormalizedSemanticGraph(
        nodes=(
            OperatorNode(
                "parse_posix_ustar",
                ("path:input/archive.tar", "header_checksum:required"),
            ),
            OperatorNode(
                "filter_safe_ustar_members",
                (f"selector:{parameters.selector}", "regular_only:true"),
            ),
            OperatorNode(
                "resolve_ustar_conflicts",
                (f"policy:{parameters.conflict_policy}",),
            ),
            OperatorNode(
                "extract_safe_regular_bytes",
                ("destination:output/extracted", "file_mode:0644"),
            ),
            OperatorNode(
                "verify_extracted_tree_shape",
                ("extra_paths:forbidden", "input_tree:preserved"),
            ),
        ),
        dependencies=((0, 1), (1, 2), (2, 3), (3, 4)),
    )
    return prompt, graph


def _proc_snapshot_contract(
    parameters: ProcSnapshotReportParameters,
) -> tuple[str, NormalizedSemanticGraph]:
    prompt = f"""Write one Bash program that operates only in the current workspace.

Inspect only the synthetic tree `input/proc-snapshot/`; never read live `/proc`.
Each candidate process is a directory whose basename is a canonical positive
decimal PID and may contain `status.json` and `cmdline.bin`. Accept it only when
`status.json` is a UTF-8 JSON object containing exactly nonnegative integer
`pid`, `ppid`, `uid`, and `rss_kib` no greater than 9007199254740991, a
one-character `state` in `R,S,D,Z,T,I`, and a string `comm` free of NUL,
carriage return, and newline; `pid` must equal the directory name. Duplicate
JSON members, noncanonical integers, fractions, exponents, NaN, and infinities
invalidate the status. `status.json` must be a mode-readable regular file, and
an unreadable, missing, or other-kind status rejects the snapshot. Never follow
symlinks. Parse a mode-readable regular `cmdline.bin` only when it is a sequence
of one or more nonempty UTF-8 arguments, each NUL-terminated; an unreadable,
missing, other-kind, or malformed cmdline instead gives that valid snapshot an
empty argv.
{_PROC_PREDICATE_TEXT[parameters.predicate].capitalize()}. For each included
snapshot, {_PROC_VIEW_TEXT[parameters.view]}.

Sort output rows by numeric PID and emit each as one physical line of strict
UTF-8 JSON. Insignificant spaces or horizontal tabs, object-member order, and
equivalent string-escape spelling are not scored. Write
`output/processes.jsonl` with a final LF when nonempty and zero bytes when
empty. Preserve the complete input tree. Leave
only a mode-0755 `output/` directory and an independent mode-0644 output file
with link count one. Use only Bash built-ins plus `awk`, `jq`, `mkdir`, and
`sort`.
"""
    graph = NormalizedSemanticGraph(
        nodes=(
            OperatorNode(
                "discover_synthetic_proc_entries",
                ("root:input/proc-snapshot", "live_proc:forbidden"),
            ),
            OperatorNode("parse_proc_status_and_cmdline", ("format:json+NUL",)),
            OperatorNode(
                "filter_proc_snapshot",
                (f"predicate:{parameters.predicate}",),
            ),
            OperatorNode(
                "project_proc_view",
                (f"view:{parameters.view}",),
            ),
            OperatorNode("sort_process_rows", ("key:pid", "order:numeric")),
            OperatorNode(
                "emit_process_jsonl",
                ("path:output/processes.jsonl", "canonical_json:true"),
            ),
        ),
        dependencies=((0, 1), (1, 2), (2, 3), (3, 4), (4, 5)),
    )
    return prompt, graph


def _bootstrap_fixture_descriptors(
    task_contract_sha256: str,
) -> tuple[OpaqueFixtureDescriptor, ...]:
    records: list[OpaqueFixtureDescriptor] = []
    for profile_sha256 in EXECUTABLE_STATIC_FIXTURE_PROFILE_SHA256:
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


def _build_task(
    *,
    family_id: FamilyId,
    parameters: TaskParameters,
    prompt: str,
    graph: NormalizedSemanticGraph,
    filesystem_identity: FilesystemIdentity,
    output_identity: OutputIdentity,
    allowed_tools: tuple[str, ...],
) -> ExecutableStaticTask:
    contract_sha256 = compute_task_contract_sha256(
        family_id=family_id,
        family_version=EXECUTABLE_STATIC_FAMILY_VERSION,
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
        family_version=EXECUTABLE_STATIC_FAMILY_VERSION,
        parameters=parameters,
        prompt=prompt,
        graph=graph,
        filesystem_identity=filesystem_identity,
        output_identity=output_identity,
        allowed_tools=allowed_tools,
        fixtures=_bootstrap_fixture_descriptors(contract_sha256),
        task_contract_sha256=contract_sha256,
    )

    # Lazy imports preserve the task-contract/catalog generator dependency
    # direction used by the frozen first registry.
    from .executable_fixture_catalog import build_fixture_bundle_for_task_profile
    from .executable_fixture_profiles import PUBLIC_DEVELOPMENT_FIXTURE_PROFILES

    descriptors = tuple(
        build_fixture_bundle_for_task_profile(bootstrap, profile).descriptor
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
    )
    return replace(bootstrap, fixtures=descriptors)


def build_line_transform_mirror_tasks() -> tuple[ExecutableStaticTask, ...]:
    """Build the deterministic 4-by-5 line-transform task grid."""

    tasks: list[ExecutableStaticTask] = []
    for suffix in LINE_TRANSFORM_SUFFIXES:
        for transform in LINE_TRANSFORMS:
            parameters = LineTransformMirrorParameters(
                suffix=suffix,
                transform=transform,
            )
            prompt, graph = _line_transform_contract(parameters)
            tasks.append(
                _build_task(
                    family_id="line-transform-mirror",
                    parameters=parameters,
                    prompt=prompt,
                    graph=graph,
                    filesystem_identity="mixed-byte-text-tree-v1",
                    output_identity="exact-transformed-mirror-v1",
                    allowed_tools=("cp", "find", "mkdir", "sed", "tr"),
                )
            )
    selected = tuple(tasks)
    if (
        len(selected) != 20
        or len({task.task_id for task in selected}) != 20
        or len({task.graph_sha256 for task in selected}) != 20
    ):
        raise ValueError("line-transform task grid is not exactly 20 unique tasks")
    return selected


def _require_unique_grid(
    tasks: list[ExecutableStaticTask],
    *,
    family_id: str,
) -> tuple[ExecutableStaticTask, ...]:
    selected = tuple(tasks)
    if (
        len(selected) != 20
        or len({task.task_id for task in selected}) != 20
        or len({task.graph_sha256 for task in selected}) != 20
        or {task.family_id for task in selected} != {family_id}
    ):
        raise ValueError(f"{family_id} grid is not exactly 20 unique tasks")
    return selected


def build_mode_normalized_mirror_tasks() -> tuple[ExecutableStaticTask, ...]:
    tasks: list[ExecutableStaticTask] = []
    for selector in MODE_MIRROR_SELECTORS:
        for normalization in MODE_NORMALIZATIONS:
            parameters = ModeNormalizedMirrorParameters(
                selector=selector,
                normalization=normalization,
            )
            prompt, graph = _mode_mirror_contract(parameters)
            tasks.append(
                _build_task(
                    family_id="mode-normalized-mirror",
                    parameters=parameters,
                    prompt=prompt,
                    graph=graph,
                    filesystem_identity="mixed-mode-source-tree-v1",
                    output_identity="exact-mode-normalized-mirror-v1",
                    allowed_tools=("chmod", "cp", "find", "mkdir", "stat"),
                )
            )
    return _require_unique_grid(tasks, family_id="mode-normalized-mirror")


def build_jsonl_keyed_inner_join_tasks() -> tuple[ExecutableStaticTask, ...]:
    tasks: list[ExecutableStaticTask] = []
    for key in JOIN_KEYS:
        for duplicate_policy in JOIN_DUPLICATE_POLICIES:
            parameters = JsonlKeyedInnerJoinParameters(
                key=key,
                duplicate_policy=duplicate_policy,
            )
            prompt, graph = _join_contract(parameters)
            tasks.append(
                _build_task(
                    family_id="jsonl-keyed-inner-join",
                    parameters=parameters,
                    prompt=prompt,
                    graph=graph,
                    filesystem_identity="paired-jsonl-records-v1",
                    output_identity="ordered-jsonl-inner-join-v1",
                    allowed_tools=("jq", "mkdir", "sort"),
                )
            )
    return _require_unique_grid(tasks, family_id="jsonl-keyed-inner-join")


def build_ustar_safe_extract_tasks() -> tuple[ExecutableStaticTask, ...]:
    tasks: list[ExecutableStaticTask] = []
    for selector in USTAR_SELECTORS:
        for conflict_policy in USTAR_CONFLICT_POLICIES:
            parameters = UstarSafeExtractParameters(
                selector=selector,
                conflict_policy=conflict_policy,
            )
            prompt, graph = _ustar_contract(parameters)
            tasks.append(
                _build_task(
                    family_id="ustar-safe-extract",
                    parameters=parameters,
                    prompt=prompt,
                    graph=graph,
                    filesystem_identity="ustar-archive-workspace-v1",
                    output_identity="exact-safe-extraction-tree-v1",
                    allowed_tools=("mkdir", "od", "sha256sum", "tar"),
                )
            )
    return _require_unique_grid(tasks, family_id="ustar-safe-extract")


def build_proc_snapshot_report_tasks() -> tuple[ExecutableStaticTask, ...]:
    tasks: list[ExecutableStaticTask] = []
    for view in PROC_SNAPSHOT_VIEWS:
        for predicate in PROC_SNAPSHOT_PREDICATES:
            parameters = ProcSnapshotReportParameters(
                view=view,
                predicate=predicate,
            )
            prompt, graph = _proc_snapshot_contract(parameters)
            tasks.append(
                _build_task(
                    family_id="proc-snapshot-report",
                    parameters=parameters,
                    prompt=prompt,
                    graph=graph,
                    filesystem_identity="synthetic-proc-snapshot-v1",
                    output_identity="pid-ordered-process-report-v1",
                    allowed_tools=("awk", "jq", "mkdir", "sort"),
                )
            )
    return _require_unique_grid(tasks, family_id="proc-snapshot-report")


def build_second_tranche_added_tasks() -> tuple[ExecutableStaticTask, ...]:
    """Build all 100 additive tasks in canonical family order."""

    tasks = (
        *build_line_transform_mirror_tasks(),
        *build_mode_normalized_mirror_tasks(),
        *build_jsonl_keyed_inner_join_tasks(),
        *build_ustar_safe_extract_tasks(),
        *build_proc_snapshot_report_tasks(),
    )
    if (
        len(tasks) != 100
        or len({task.task_id for task in tasks}) != 100
        or len({task.graph_sha256 for task in tasks}) != 100
    ):
        raise ValueError("second-tranche additive task set is not 100 unique tasks")
    return tasks


def _second_registry_payload(
    added_tasks: tuple[ExecutableStaticTask, ...],
) -> dict[str, object]:
    return {
        "schema_version": SECOND_TRANCHE_REGISTRY_SCHEMA_VERSION,
        "registry_version": SECOND_TRANCHE_REGISTRY_VERSION,
        "record_type": "cbds.executable-static-second-tranche-registry",
        "base_registry_sha256": FROZEN_FIRST_REGISTRY_SHA256,
        "base_suite_sha256": FROZEN_FIRST_SUITE_SHA256,
        "added_task_count": SECOND_TRANCHE_ADDED_TASK_COUNT,
        "cumulative_task_count": SECOND_TRANCHE_CUMULATIVE_TASK_COUNT,
        "fixture_profile_sha256": list(
            EXECUTABLE_STATIC_FIXTURE_PROFILE_SHA256
        ),
        "added_tasks": [task.to_public_record() for task in added_tasks],
        "public_method_development": True,
        "sealed": False,
        "candidate_execution_authorized": False,
        "model_selection_eligible": False,
        "claim_authorized": False,
    }


def compute_second_tranche_registry_sha256(
    added_tasks: tuple[ExecutableStaticTask, ...],
) -> str:
    _validate_second_tranche_added_tasks(added_tasks)
    return domain_sha256(
        "cbds.executable-static.second-tranche-registry.v1",
        _second_registry_payload(added_tasks),
    )


def compute_second_tranche_cumulative_suite_sha256(
    added_tasks: tuple[ExecutableStaticTask, ...],
    registry_sha256: str,
) -> str:
    _validate_second_tranche_added_tasks(added_tasks)
    if (
        not _is_exact_lower_sha256(registry_sha256)
    ):
        raise ValueError("second-tranche registry SHA-256 is invalid")
    expected_registry = compute_second_tranche_registry_sha256(added_tasks)
    if registry_sha256 != expected_registry:
        raise ValueError("second-tranche registry SHA-256 does not bind added tasks")
    return domain_sha256(
        "cbds.executable-static.second-tranche-cumulative-suite.v1",
        {
            "base_suite_sha256": FROZEN_FIRST_SUITE_SHA256,
            "added_registry_sha256": registry_sha256,
            "cumulative_task_count": SECOND_TRANCHE_CUMULATIVE_TASK_COUNT,
        },
    )


def _validate_second_tranche_added_tasks(
    added_tasks: tuple[ExecutableStaticTask, ...],
) -> None:
    if (
        type(added_tasks) is not tuple
        or len(added_tasks) != SECOND_TRANCHE_ADDED_TASK_COUNT
        or any(type(task) is not ExecutableStaticTask for task in added_tasks)
    ):
        raise ValueError("second tranche requires exactly 100 exact task values")
    for task in added_tasks:
        task.__post_init__()
    family_order = (
        "line-transform-mirror",
        "mode-normalized-mirror",
        "jsonl-keyed-inner-join",
        "ustar-safe-extract",
        "proc-snapshot-report",
    )
    observed = tuple(task.family_id for task in added_tasks)
    expected = tuple(family for family in family_order for _index in range(20))
    if observed != expected:
        raise ValueError("second-tranche task family order is not canonical")
    if (
        len({task.task_id for task in added_tasks}) != SECOND_TRANCHE_ADDED_TASK_COUNT
        or len({task.task_contract_sha256 for task in added_tasks})
        != SECOND_TRANCHE_ADDED_TASK_COUNT
        or len({task.graph_sha256 for task in added_tasks})
        != SECOND_TRANCHE_ADDED_TASK_COUNT
    ):
        raise ValueError("second-tranche task identities are not unique")


@dataclass(frozen=True, slots=True)
class SecondTrancheTaskRegistry:
    """Hash-bound 100-task addition to the immutable first registry."""

    added_tasks: tuple[ExecutableStaticTask, ...]
    registry_sha256: str
    cumulative_suite_sha256: str
    schema_version: str = SECOND_TRANCHE_REGISTRY_SCHEMA_VERSION
    registry_version: str = SECOND_TRANCHE_REGISTRY_VERSION
    base_registry_sha256: str = FROZEN_FIRST_REGISTRY_SHA256
    base_suite_sha256: str = FROZEN_FIRST_SUITE_SHA256
    public_method_development: bool = True
    sealed: bool = False
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_second_tranche_task_registry(self)

    def to_hash_only_record(self) -> dict[str, object]:
        validate_second_tranche_task_registry(self)
        return {
            "schema_version": self.schema_version,
            "registry_version": self.registry_version,
            "record_type": "cbds.executable-static-second-tranche-registry-hashes",
            "base_registry_sha256": self.base_registry_sha256,
            "base_suite_sha256": self.base_suite_sha256,
            "added_task_count": len(self.added_tasks),
            "cumulative_task_count": SECOND_TRANCHE_CUMULATIVE_TASK_COUNT,
            "family_task_counts": {
                family: sum(task.family_id == family for task in self.added_tasks)
                for family in (
                    "line-transform-mirror",
                    "mode-normalized-mirror",
                    "jsonl-keyed-inner-join",
                    "ustar-safe-extract",
                    "proc-snapshot-report",
                )
            },
            "task_contract_sha256": [
                task.task_contract_sha256 for task in self.added_tasks
            ],
            "graph_sha256": [task.graph_sha256 for task in self.added_tasks],
            "registry_sha256": self.registry_sha256,
            "cumulative_suite_sha256": self.cumulative_suite_sha256,
            "public_method_development": True,
            "sealed": False,
            "candidate_execution_authorized": False,
            "model_selection_eligible": False,
            "claim_authorized": False,
        }


def validate_second_tranche_task_registry(
    registry: SecondTrancheTaskRegistry,
) -> None:
    if type(registry) is not SecondTrancheTaskRegistry:
        raise ValueError("registry must be an exact SecondTrancheTaskRegistry")
    if (
        type(registry.schema_version) is not str
        or registry.schema_version != SECOND_TRANCHE_REGISTRY_SCHEMA_VERSION
        or type(registry.registry_version) is not str
        or registry.registry_version != SECOND_TRANCHE_REGISTRY_VERSION
        or not _is_exact_lower_sha256(registry.base_registry_sha256)
        or registry.base_registry_sha256 != FROZEN_FIRST_REGISTRY_SHA256
        or not _is_exact_lower_sha256(registry.base_suite_sha256)
        or registry.base_suite_sha256 != FROZEN_FIRST_SUITE_SHA256
        or not _is_exact_lower_sha256(registry.registry_sha256)
        or not _is_exact_lower_sha256(registry.cumulative_suite_sha256)
        or registry.public_method_development is not True
        or registry.sealed is not False
        or registry.candidate_execution_authorized is not False
        or registry.model_selection_eligible is not False
        or registry.claim_authorized is not False
    ):
        raise ValueError("second-tranche registry metadata is invalid")
    _validate_second_tranche_added_tasks(registry.added_tasks)
    expected_registry = compute_second_tranche_registry_sha256(
        registry.added_tasks
    )
    if registry.registry_sha256 != expected_registry:
        raise ValueError("second-tranche registry digest is invalid")
    expected_suite = compute_second_tranche_cumulative_suite_sha256(
        registry.added_tasks,
        expected_registry,
    )
    if registry.cumulative_suite_sha256 != expected_suite:
        raise ValueError("second-tranche cumulative suite digest is invalid")


def build_second_tranche_task_registry() -> SecondTrancheTaskRegistry:
    tasks = build_second_tranche_added_tasks()
    registry_sha256 = compute_second_tranche_registry_sha256(tasks)
    suite_sha256 = compute_second_tranche_cumulative_suite_sha256(
        tasks,
        registry_sha256,
    )
    return SecondTrancheTaskRegistry(
        added_tasks=tasks,
        registry_sha256=registry_sha256,
        cumulative_suite_sha256=suite_sha256,
    )


__all__ = [
    "JOIN_DUPLICATE_POLICIES",
    "JOIN_KEYS",
    "LINE_TRANSFORMS",
    "LINE_TRANSFORM_SUFFIXES",
    "MODE_MIRROR_SELECTORS",
    "MODE_NORMALIZATIONS",
    "PROC_SNAPSHOT_PREDICATES",
    "PROC_SNAPSHOT_VIEWS",
    "SECOND_TRANCHE_ADDED_TASK_COUNT",
    "SECOND_TRANCHE_CUMULATIVE_TASK_COUNT",
    "SECOND_TRANCHE_REGISTRY_SCHEMA_VERSION",
    "SECOND_TRANCHE_REGISTRY_VERSION",
    "SecondTrancheTaskRegistry",
    "USTAR_CONFLICT_POLICIES",
    "USTAR_SELECTORS",
    "build_jsonl_keyed_inner_join_tasks",
    "build_line_transform_mirror_tasks",
    "build_mode_normalized_mirror_tasks",
    "build_proc_snapshot_report_tasks",
    "build_second_tranche_added_tasks",
    "build_second_tranche_task_registry",
    "build_ustar_safe_extract_tasks",
    "compute_second_tranche_cumulative_suite_sha256",
    "compute_second_tranche_registry_sha256",
    "validate_second_tranche_task_registry",
]
