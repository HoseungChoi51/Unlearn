"""Executable-static family for content-aware hardlink-deduplicated mirrors.

The family mirrors every no-follow regular file below a source tree, but names
that are equivalent under a task-selected key must share one physical inode in
the output.  A separately selected representative supplies bytes, permission
bits, and modification time.  The private oracle commits both ordinary file
contents and the required hardlink topology.

This module does not execute candidate code.  Workspace verification assumes a
trusted harness has established quiescence and observes only the final state.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from hashlib import sha256
from itertools import groupby
import os
from pathlib import PurePosixPath
import re
from typing import Final, Literal, TypeAlias

from .benchmark import NormalizedSemanticGraph, OperatorNode
from .executable_fixture_bundle import (
    EXECUTABLE_FIXTURE_BINDING_VERSION,
    EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION,
    compute_bound_fixture_sha256,
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
    InputHardlink,
    InputSymlink,
    WorkspaceEntry,
    WorkspaceHandle,
    compute_workspace_hardlink_group_sha256,
    materialize_fixture,
    validate_expected_output_policy,
)


HARDLINK_DEDUPLICATED_MIRROR_FAMILY_ID: Final[str] = (
    "hardlink-deduplicated-mirror"
)
HARDLINK_DEDUPLICATED_MIRROR_FILESYSTEM_IDENTITY: Final[str] = (
    "duplicate-content-source-tree"
)
HARDLINK_DEDUPLICATED_MIRROR_OUTPUT_IDENTITY: Final[str] = (
    "hardlink-topology-preserving-mirror"
)
HARDLINK_DEDUPLICATED_MIRROR_GENERATOR_VERSION: Final[str] = "2.0.0"
HARDLINK_DEDUPLICATED_MIRROR_VERIFIER_IDENTITY: Final[str] = (
    "verify-hardlink-deduplicated-mirror-v2"
)
HARDLINK_DEDUPLICATED_MIRROR_SOURCE_ROOT: Final[PurePosixPath] = PurePosixPath(
    "input/source"
)
HARDLINK_DEDUPLICATED_MIRROR_MANIFEST: Final[str] = "input/metadata.nul"
HARDLINK_DEDUPLICATED_MIRROR_OUTPUT_ROOT: Final[PurePosixPath] = PurePosixPath(
    "output/tree"
)
HARDLINK_DEDUPLICATED_MIRROR_LEDGER_OUTPUT: Final[str] = "output/ledger.tsv"
HARDLINK_DEDUPLICATED_MIRROR_LEDGER_MODE: Final[int] = 0o644
HARDLINK_DEDUPLICATED_MIRROR_OUTPUT_MAXIMUM_BYTES: Final[int] = 1024 * 1024
HARDLINK_DEDUPLICATED_MIRROR_REPORT_MAXIMUM_BYTES: Final[int] = (
    HARDLINK_DEDUPLICATED_MIRROR_OUTPUT_MAXIMUM_BYTES
)
HARDLINK_DEDUPLICATED_MIRROR_FILE_MAXIMUM_BYTES: Final[int] = 16 * 1024
HARDLINK_DEDUPLICATED_MIRROR_MANIFEST_MAXIMUM_BYTES: Final[int] = 64 * 1024
HARDLINK_DEDUPLICATED_MIRROR_MAXIMUM_FILES: Final[int] = 128
HARDLINK_DEDUPLICATED_MIRROR_ALLOWED_TOOLS: Final[tuple[str, ...]] = (
    "cp",
    "find",
    "ln",
    "mkdir",
    "sha256sum",
    "sort",
    "stat",
)

# Honest observation boundaries.
HARDLINK_DEDUPLICATED_MIRROR_INPUT_HARDLINKS_COVERED: Final[bool] = True
HARDLINK_DEDUPLICATED_MIRROR_OUTPUT_HARDLINK_TOPOLOGY_OBSERVED: Final[bool] = True
HARDLINK_DEDUPLICATED_MIRROR_SOURCE_MTIME_COMMITTED: Final[bool] = True
HARDLINK_DEDUPLICATED_MIRROR_SYMLINK_DISTRACTORS_COVERED: Final[bool] = True
HARDLINK_DEDUPLICATED_MIRROR_DIRECTORY_PERMISSION_ERRORS_COVERED: Final[
    bool
] = False
HARDLINK_DEDUPLICATED_MIRROR_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE: Final[
    bool
] = True
HARDLINK_DEDUPLICATED_MIRROR_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE: Final[
    bool
] = False
HARDLINK_DEDUPLICATED_MIRROR_CREATION_HISTORY_OBSERVED: Final[bool] = False
HARDLINK_DEDUPLICATED_MIRROR_TOOL_HISTORY_OBSERVED: Final[bool] = False
HARDLINK_DEDUPLICATED_MIRROR_CANDIDATE_EXIT_STATUS_OBSERVED: Final[bool] = False

EquivalenceKey: TypeAlias = Literal[
    "sha256",
    "mode-and-sha256",
    "suffix-and-sha256",
    "declared-group-and-sha256",
]
OwnerPolicy: TypeAlias = Literal[
    "smallest-path",
    "largest-path",
    "oldest-mtime",
    "newest-mtime",
    "manifest-priority",
]

HARDLINK_DEDUPLICATED_MIRROR_EQUIVALENCE_KEYS: Final[
    tuple[EquivalenceKey, ...]
] = (
    "sha256",
    "mode-and-sha256",
    "suffix-and-sha256",
    "declared-group-and-sha256",
)
HARDLINK_DEDUPLICATED_MIRROR_OWNER_POLICIES: Final[tuple[OwnerPolicy, ...]] = (
    "smallest-path",
    "largest-path",
    "oldest-mtime",
    "newest-mtime",
    "manifest-priority",
)

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_TASK_ID_RE: Final[re.Pattern[str]] = re.compile(r"mds-[0-9a-f]{24}\Z")


class HardlinkDeduplicatedMirrorError(ValueError):
    """Raised when a task, fixture, oracle, or final state fails closed."""


def _raw(value: str) -> bytes:
    return value.encode("utf-8")


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def _closed_text(value: object, allowed: tuple[str, ...], label: str) -> str:
    if type(value) is not str or value not in allowed:
        raise HardlinkDeduplicatedMirrorError(
            f"{label} is outside the closed family contract"
        )
    return value


def _validate_relative_source(value: object) -> str:
    if type(value) is not str or not value:
        raise HardlinkDeduplicatedMirrorError("source path is invalid")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise HardlinkDeduplicatedMirrorError("source path is not UTF-8") from exc
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or len(encoded) > 4096
        or any(len(part.encode("utf-8")) > 255 for part in path.parts)
    ):
        raise HardlinkDeduplicatedMirrorError("source path is noncanonical")
    return value


def _validate_declared_group(value: object) -> str:
    if type(value) is not str or not value:
        raise HardlinkDeduplicatedMirrorError("declared group is empty")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise HardlinkDeduplicatedMirrorError(
            "declared group is not UTF-8"
        ) from exc
    if (
        len(encoded) > 128
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise HardlinkDeduplicatedMirrorError("declared group is invalid")
    return value


@dataclass(frozen=True, slots=True)
class HardlinkDeduplicatedMirrorParameters:
    """One cell in the four-key by five-owner-policy grid."""

    equivalence_key: EquivalenceKey
    owner_policy: OwnerPolicy

    def __post_init__(self) -> None:
        if type(self) is not HardlinkDeduplicatedMirrorParameters:
            raise HardlinkDeduplicatedMirrorError("parameters have wrong exact type")
        _closed_text(
            self.equivalence_key,
            HARDLINK_DEDUPLICATED_MIRROR_EQUIVALENCE_KEYS,
            "equivalence_key",
        )
        _closed_text(
            self.owner_policy,
            HARDLINK_DEDUPLICATED_MIRROR_OWNER_POLICIES,
            "owner_policy",
        )

    def to_record(self) -> dict[str, str]:
        self.__post_init__()
        return {
            "parameter_type": HARDLINK_DEDUPLICATED_MIRROR_FAMILY_ID,
            "equivalence_key": self.equivalence_key,
            "owner_policy": self.owner_policy,
        }


_KEY_TEXT: Final[dict[EquivalenceKey, str]] = {
    "sha256": "Group files with exactly the same SHA-256 of their bytes.",
    "mode-and-sha256": (
        "Group files only when both permission bits and byte SHA-256 match."
    ),
    "suffix-and-sha256": (
        "Group files only when their suffix and byte SHA-256 match. The suffix "
        "is the final basename substring beginning at its last ASCII dot when "
        "that dot is not the first character; no such dot means empty suffix. "
        "A trailing dot therefore has suffix '.', and comparison is case-sensitive."
    ),
    "declared-group-and-sha256": (
        "Group files only when metadata.nul declares the same group and their "
        "byte SHA-256 values match."
    ),
}
_OWNER_TEXT: Final[dict[OwnerPolicy, str]] = {
    "smallest-path": "Choose the raw-UTF-8-byte-smallest relative source path.",
    "largest-path": "Choose the raw-UTF-8-byte-largest relative source path.",
    "oldest-mtime": (
        "Choose the smallest committed filesystem modification time, breaking "
        "ties by raw-UTF-8-byte-smallest relative source path."
    ),
    "newest-mtime": (
        "Choose the largest committed filesystem modification time, breaking "
        "ties by raw-UTF-8-byte-smallest relative source path."
    ),
    "manifest-priority": (
        "Choose the smallest integer priority declared by metadata.nul."
    ),
}


def _task_contract(
    parameters: HardlinkDeduplicatedMirrorParameters,
) -> tuple[str, NormalizedSemanticGraph]:
    prompt = f"""Write one Bash program that operates only in the current workspace.

Recursively discover every exact no-follow regular-file name below input/source.
These and only these names are mirror candidates. Symbolic links are distractors
and must not be followed. Multiple candidate names may already share an inode;
each pathname remains a distinct candidate. There are at most 128 candidate
names, every candidate contains at most 16384 arbitrary bytes, and every source
path is canonical strict UTF-8 without ASCII control characters or DEL.

input/metadata.nul is at most 65536 bytes and is a sequence of exact NUL-
terminated triplets RELATIVE-PATH, DECLARED-GROUP, PRIORITY. RELATIVE-PATH is
relative to input/source. DECLARED-GROUP is nonempty strict UTF-8, at most 128
bytes, without ASCII controls or DEL. PRIORITY is canonical decimal 0 through
candidate-count-minus-one. There is exactly one row per candidate and priorities
are unique. Physical manifest row order is nonsemantic.

Use equivalence key {parameters.equivalence_key}. {_KEY_TEXT[parameters.equivalence_key]}
Byte identity includes empty data, NUL, invalid UTF-8, and final-newline
differences.

For every equivalence group use owner policy {parameters.owner_policy}.
{_OWNER_TEXT[parameters.owner_policy]} The chosen owner supplies the bytes,
permission bits, and exact modification time for every mirrored name in that
group. Preserve every relative pathname beneath output/tree. All output names
in a group must be physical hardlinks to one inode. A singleton has link count
one. Do not link output files to input files or to any path outside their output
equivalence group.

Write output/ledger.tsv as strict UTF-8 with LF endings. Its first row is:
mirror, candidate count, equivalence-group count, and saved-inode count. Then
write one row per source in raw relative-path UTF-8 byte order:
file, RELATIVE-PATH, OWNER, GROUP-SHA256, GROUP-SIZE.
Compute GROUP-SHA256 by feeding this exact byte stream to sha256sum:
the ASCII bytes cbds-hardlink-group-v2, one NUL byte, the equivalence-key text,
one NUL byte, then each group member's relative-path UTF-8 bytes followed by one
NUL byte, with members in raw UTF-8 byte order. Fields are tab separated. Create
only necessary real mode-0755 output directories. The ledger is a mode-0644,
link-count-one regular file.
Leave every input and all noncandidate leaves exactly unchanged and leave no
extra or staging path.

The scored check observes exact final bytes, permission bits, modification
times, input preservation, link counts, and visible hardlink topology. It does
not claim to observe creation history, tools, transient state, global
quiescence, or exit status. Use LC_ALL=C and only Bash built-ins plus cp, find,
ln, mkdir, sha256sum, sort, and stat.
"""
    graph = NormalizedSemanticGraph(
        nodes=(
            OperatorNode(
                "discover_regular_source_names",
                ("root:input/source", "no-follow", "inode-aliases:distinct-names"),
            ),
            OperatorNode(
                "parse_group_priority_manifest",
                ("path:input/metadata.nul", "encoding:nul-triplets"),
            ),
            OperatorNode(
                "partition_equivalence_groups",
                (f"key:{parameters.equivalence_key}", "bytes:sha256"),
            ),
            OperatorNode(
                "select_metadata_owner",
                (f"owner-policy:{parameters.owner_policy}",),
            ),
            OperatorNode(
                "publish_hardlink_mirror",
                (
                    "tree:output/tree",
                    "ledger:output/ledger.tsv",
                    "topology:one-inode-per-group",
                ),
            ),
        ),
        dependencies=((0, 1), (0, 2), (1, 2), (2, 3), (3, 4)),
    )
    return prompt, graph


def _validate_graph(graph: object) -> NormalizedSemanticGraph:
    if type(graph) is not NormalizedSemanticGraph:
        raise HardlinkDeduplicatedMirrorError("graph has wrong exact type")
    rebuilt = NormalizedSemanticGraph(
        nodes=tuple(
            OperatorNode(node.name, node.parameters)
            for node in graph.nodes
            if type(node) is OperatorNode
        ),
        dependencies=graph.dependencies,
    )
    if rebuilt != graph or len(rebuilt.nodes) != len(graph.nodes):
        raise HardlinkDeduplicatedMirrorError("graph is noncanonical")
    return graph


def hardlink_deduplicated_mirror_task_semantic_core(
    parameters: HardlinkDeduplicatedMirrorParameters,
    prompt: str,
    graph: NormalizedSemanticGraph,
) -> dict[str, object]:
    if type(parameters) is not HardlinkDeduplicatedMirrorParameters:
        raise HardlinkDeduplicatedMirrorError("parameters have wrong exact type")
    parameters.__post_init__()
    expected_prompt, expected_graph = _task_contract(parameters)
    if (
        type(prompt) is not str
        or prompt != expected_prompt
        or _validate_graph(graph) != expected_graph
    ):
        raise HardlinkDeduplicatedMirrorError("prompt or graph differs")
    return {
        "schema_version": EXECUTABLE_STATIC_SCHEMA_VERSION,
        "contract_version": EXECUTABLE_STATIC_CONTRACT_VERSION,
        "split_role": METHOD_DEVELOPMENT_SPLIT,
        "family_id": HARDLINK_DEDUPLICATED_MIRROR_FAMILY_ID,
        "family_version": EXECUTABLE_STATIC_FAMILY_VERSION,
        "generator_version": HARDLINK_DEDUPLICATED_MIRROR_GENERATOR_VERSION,
        "parameters": parameters.to_record(),
        "prompt": prompt,
        "graph": graph.to_record(),
        "graph_sha256": graph.hash,
        "filesystem_identity": HARDLINK_DEDUPLICATED_MIRROR_FILESYSTEM_IDENTITY,
        "output_identity": HARDLINK_DEDUPLICATED_MIRROR_OUTPUT_IDENTITY,
        "allowed_tools": list(HARDLINK_DEDUPLICATED_MIRROR_ALLOWED_TOOLS),
        "public": True,
        "sealed": False,
        "candidate_execution_authorized": False,
        "model_selection_eligible": False,
        "claim_authorized": False,
    }


def compute_hardlink_deduplicated_mirror_task_sha256(
    parameters: HardlinkDeduplicatedMirrorParameters,
    prompt: str,
    graph: NormalizedSemanticGraph,
) -> str:
    return domain_sha256(
        "cbds.executable-static.task-contract.v1",
        hardlink_deduplicated_mirror_task_semantic_core(
            parameters, prompt, graph
        ),
    )


@dataclass(frozen=True, slots=True)
class HardlinkDeduplicatedMirrorTask:
    task_id: str
    parameters: HardlinkDeduplicatedMirrorParameters
    prompt: str
    graph: NormalizedSemanticGraph
    fixtures: tuple[OpaqueFixtureDescriptor, ...]
    task_contract_sha256: str
    family_id: str = HARDLINK_DEDUPLICATED_MIRROR_FAMILY_ID
    family_version: str = EXECUTABLE_STATIC_FAMILY_VERSION
    filesystem_identity: str = HARDLINK_DEDUPLICATED_MIRROR_FILESYSTEM_IDENTITY
    output_identity: str = HARDLINK_DEDUPLICATED_MIRROR_OUTPUT_IDENTITY
    allowed_tools: tuple[str, ...] = HARDLINK_DEDUPLICATED_MIRROR_ALLOWED_TOOLS
    split_role: str = METHOD_DEVELOPMENT_SPLIT
    public: bool = True
    sealed: bool = False
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        if (
            type(self) is not HardlinkDeduplicatedMirrorTask
            or type(self.parameters) is not HardlinkDeduplicatedMirrorParameters
            or self.family_id != HARDLINK_DEDUPLICATED_MIRROR_FAMILY_ID
            or self.family_version != EXECUTABLE_STATIC_FAMILY_VERSION
            or self.filesystem_identity
            != HARDLINK_DEDUPLICATED_MIRROR_FILESYSTEM_IDENTITY
            or self.output_identity != HARDLINK_DEDUPLICATED_MIRROR_OUTPUT_IDENTITY
            or type(self.allowed_tools) is not tuple
            or self.allowed_tools != HARDLINK_DEDUPLICATED_MIRROR_ALLOWED_TOOLS
            or self.split_role != METHOD_DEVELOPMENT_SPLIT
            or self.public is not True
            or self.sealed is not False
            or self.candidate_execution_authorized is not False
            or self.model_selection_eligible is not False
            or self.claim_authorized is not False
        ):
            raise HardlinkDeduplicatedMirrorError("task metadata is invalid")
        expected = compute_hardlink_deduplicated_mirror_task_sha256(
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
            raise HardlinkDeduplicatedMirrorError("task identity is invalid")
        for descriptor in self.fixtures:
            descriptor.__post_init__()
        if (
            len({item.fixture_id for item in self.fixtures}) != len(self.fixtures)
            or any(
                item.task_contract_sha256 != expected for item in self.fixtures
            )
        ):
            raise HardlinkDeduplicatedMirrorError("descriptor binding is invalid")

    @property
    def graph_sha256(self) -> str:
        self.__post_init__()
        return self.graph.hash

    def to_public_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            **hardlink_deduplicated_mirror_task_semantic_core(
                self.parameters, self.prompt, self.graph
            ),
            "task_id": self.task_id,
            "task_contract_sha256": self.task_contract_sha256,
            "fixtures": [item.to_public_record() for item in self.fixtures],
        }


def _bootstrap_descriptors(
    task_contract_sha256: str,
) -> tuple[OpaqueFixtureDescriptor, ...]:
    values: list[OpaqueFixtureDescriptor] = []
    for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
        digest = domain_sha256(
            "cbds.executable-static.fixture.v1",
            {
                "task_contract_sha256": task_contract_sha256,
                "profile_sha256": profile.profile_sha256,
            },
        )
        values.append(
            OpaqueFixtureDescriptor(
                fixture_id=f"fx-{digest[:24]}",
                fixture_sha256=digest,
                task_contract_sha256=task_contract_sha256,
            )
        )
    return tuple(values)


def _bootstrap_task(
    parameters: HardlinkDeduplicatedMirrorParameters,
) -> HardlinkDeduplicatedMirrorTask:
    prompt, graph = _task_contract(parameters)
    digest = compute_hardlink_deduplicated_mirror_task_sha256(
        parameters, prompt, graph
    )
    return HardlinkDeduplicatedMirrorTask(
        task_id=task_id_from_contract(digest),
        parameters=parameters,
        prompt=prompt,
        graph=graph,
        fixtures=_bootstrap_descriptors(digest),
        task_contract_sha256=digest,
    )


@dataclass(frozen=True, slots=True)
class _FixtureSeed:
    relative: str
    content: bytes
    mode: int
    declared_group: str
    priority: int
    mtime_seconds: int
    hardlink_target: str = ""


def _base_seeds() -> tuple[_FixtureSeed, ...]:
    # K is a four-way partition probe: all / rows / columns / diagonals.
    partition = b"partition-probe\x00\n"
    owner = b"owner-probe\xff\n"
    return (
        _FixtureSeed("key/a.txt", partition, 0o600, "red", 5, 1_005),
        _FixtureSeed("key/b.log", partition, 0o600, "blue", 6, 1_006),
        _FixtureSeed("key/c.txt", partition, 0o644, "blue", 7, 1_007),
        _FixtureSeed("key/d.log", partition, 0o644, "red", 8, 1_008),
        # U makes all five owner policies select a different representative.
        _FixtureSeed("owner/a.dat", owner, 0o640, "owner", 4, 300),
        _FixtureSeed("owner/b.dat", owner, 0o640, "owner", 3, 100),
        _FixtureSeed("owner/c.dat", owner, 0o640, "owner", 0, 200),
        _FixtureSeed("owner/d.dat", owner, 0o640, "owner", 2, 500),
        _FixtureSeed("owner/e.dat", owner, 0o640, "owner", 1, 400),
        _FixtureSeed("links/base.bin", b"already-linked\n", 0o604, "links", 9, 700),
        _FixtureSeed(
            "links/copy.bin",
            b"already-linked\n",
            0o604,
            "links",
            10,
            700,
            "links/base.bin",
        ),
    )


def _profile_extra_seeds(profile_id: str) -> tuple[_FixtureSeed, ...]:
    if profile_id == "spaces-unicode":
        return (
            _FixtureSeed("odd/space name.δ", b"odd-pair\n", 0o640, "odd", 11, 811),
            _FixtureSeed("odd/écho.δ", b"odd-pair\n", 0o640, "odd", 12, 812),
        )
    if profile_id == "leading-dashes-globs":
        return (
            _FixtureSeed("odd/-dash.*", b"glob-pair\n", 0o644, "glob", 11, 821),
            _FixtureSeed("odd/[bracket].*", b"glob-pair\n", 0o644, "glob", 12, 822),
        )
    if profile_id == "empty-duplicates":
        return (
            _FixtureSeed("empty/first.bin", b"", 0o600, "empty", 11, 831),
            _FixtureSeed("empty/second.bin", b"", 0o600, "empty", 12, 832),
        )
    if profile_id == "symlinks-ordering":
        return (
            _FixtureSeed("order/z.bin", b"ordering\n", 0o644, "order", 11, 841),
            _FixtureSeed("order/a.bin", b"ordering\n", 0o644, "order", 12, 842),
        )
    if profile_id == "partial-permissions":
        return (
            _FixtureSeed("modes/read-only.bin", b"mode-pair\n", 0o400, "mode", 11, 851),
            _FixtureSeed("modes/private.bin", b"mode-pair\n", 0o600, "mode", 12, 852),
        )
    raise HardlinkDeduplicatedMirrorError("profile id is invalid")


def _manifest_bytes(
    seeds: tuple[_FixtureSeed, ...], *, reverse: bool
) -> bytes:
    selected = tuple(reversed(seeds)) if reverse else seeds
    payload = bytearray()
    for seed in selected:
        payload.extend(seed.relative.encode("utf-8"))
        payload.append(0)
        payload.extend(seed.declared_group.encode("utf-8"))
        payload.append(0)
        payload.extend(str(seed.priority).encode("ascii"))
        payload.append(0)
    return bytes(payload)


def _fixture_inputs(
    profile: ExecutableFixtureProfile,
) -> tuple[InputFile | InputHardlink | InputSymlink, ...]:
    seeds = _base_seeds() + _profile_extra_seeds(profile.profile_id)
    inputs: list[InputFile | InputHardlink | InputSymlink] = [
        InputFile(
            HARDLINK_DEDUPLICATED_MIRROR_MANIFEST,
            _manifest_bytes(
                seeds, reverse=profile.profile_id == "symlinks-ordering"
            ),
            0o600,
            900,
        )
    ]
    for seed in seeds:
        full_path = (
            HARDLINK_DEDUPLICATED_MIRROR_SOURCE_ROOT / seed.relative
        ).as_posix()
        if seed.hardlink_target:
            inputs.append(
                InputHardlink(
                    full_path,
                    (
                        HARDLINK_DEDUPLICATED_MIRROR_SOURCE_ROOT
                        / seed.hardlink_target
                    ).as_posix(),
                )
            )
        else:
            inputs.append(
                InputFile(
                    full_path,
                    seed.content,
                    seed.mode,
                    seed.mtime_seconds,
                )
            )
    if profile.profile_id == "symlinks-ordering":
        inputs.append(InputSymlink("input/source/link-to-key", "key/a.txt"))
    if profile.profile_id == "partial-permissions":
        inputs.append(
            InputFile("input/ignored/blocked.bin", b"do-not-read\n", 0o000, 860)
        )
    return tuple(inputs)


@dataclass(frozen=True, slots=True)
class _SourceRecord:
    relative: str
    content: bytes = field(repr=False)
    mode: int
    mtime_seconds: int
    declared_group: str
    priority: int


def _parse_manifest(content: bytes) -> dict[str, tuple[str, int]]:
    if type(content) is not bytes or len(content) > HARDLINK_DEDUPLICATED_MIRROR_MANIFEST_MAXIMUM_BYTES:
        raise HardlinkDeduplicatedMirrorError("manifest exceeds its byte bound")
    fields = content.split(b"\0")
    if not fields or fields[-1] != b"" or (len(fields) - 1) % 3:
        raise HardlinkDeduplicatedMirrorError(
            "manifest is not exact NUL-terminated triplets"
        )
    records: dict[str, tuple[str, int]] = {}
    priorities: set[int] = set()
    for offset in range(0, len(fields) - 1, 3):
        try:
            relative = fields[offset].decode("utf-8", errors="strict")
            group = fields[offset + 1].decode("utf-8", errors="strict")
            priority_text = fields[offset + 2].decode("ascii", errors="strict")
        except UnicodeError as exc:
            raise HardlinkDeduplicatedMirrorError(
                "manifest text is not canonical"
            ) from exc
        _validate_relative_source(relative)
        _validate_declared_group(group)
        if (
            not priority_text
            or (priority_text != "0" and priority_text.startswith("0"))
            or not priority_text.isascii()
            or not priority_text.isdecimal()
        ):
            raise HardlinkDeduplicatedMirrorError("manifest priority is invalid")
        priority = int(priority_text)
        if relative in records or priority in priorities:
            raise HardlinkDeduplicatedMirrorError(
                "manifest path or priority is duplicated"
            )
        records[relative] = (group, priority)
        priorities.add(priority)
    if priorities != set(range(len(records))):
        raise HardlinkDeduplicatedMirrorError(
            "manifest priorities must be the exact rank range"
        )
    return records


def _revalidate_definition(definition: object) -> FixtureDefinition:
    if type(definition) is not FixtureDefinition:
        raise HardlinkDeduplicatedMirrorError("definition has wrong exact type")
    try:
        rebuilt = FixtureDefinition(
            fixture_id=definition.fixture_id,
            inputs=definition.inputs,
            expected_files=definition.expected_files,
            schema_version=definition.schema_version,
            expected_symlinks=definition.expected_symlinks,
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise HardlinkDeduplicatedMirrorError(
            "definition revalidation failed"
        ) from exc
    if rebuilt != definition or definition.expected_symlinks:
        raise HardlinkDeduplicatedMirrorError("definition is noncanonical")
    return definition


def _definition_semantic_sha256(definition: FixtureDefinition) -> str:
    selected = _revalidate_definition(definition)
    record = selected.commitment_record()
    del record["fixture_id"]
    record["record_type"] = "cbds.executable-fixture-definition-semantics"
    return domain_sha256(
        "cbds.executable-fixture.definition-semantics.v1", record
    )


def _source_records(definition: FixtureDefinition) -> tuple[_SourceRecord, ...]:
    selected = _revalidate_definition(definition)
    manifest_items = [
        item
        for item in selected.inputs
        if type(item) is InputFile
        and item.path == HARDLINK_DEDUPLICATED_MIRROR_MANIFEST
    ]
    if len(manifest_items) != 1:
        raise HardlinkDeduplicatedMirrorError("fixture must contain one manifest")
    metadata = _parse_manifest(manifest_items[0].content)
    files = {
        item.path: item
        for item in selected.inputs
        if type(item) is InputFile
    }
    records: list[_SourceRecord] = []
    prefix = HARDLINK_DEDUPLICATED_MIRROR_SOURCE_ROOT.as_posix() + "/"
    for item in selected.inputs:
        if type(item) not in {InputFile, InputHardlink} or not item.path.startswith(
            prefix
        ):
            continue
        relative = item.path.removeprefix(prefix)
        if type(item) is InputFile:
            source = item
        else:
            source = files.get(item.target)
            if source is None:
                raise HardlinkDeduplicatedMirrorError(
                    "hardlink target is unavailable"
                )
        if source.mtime_seconds is None:
            raise HardlinkDeduplicatedMirrorError(
                "every source candidate must commit an exact mtime"
            )
        declared = metadata.get(relative)
        if declared is None:
            raise HardlinkDeduplicatedMirrorError(
                "manifest does not cover every candidate"
            )
        records.append(
            _SourceRecord(
                relative,
                source.content,
                source.mode,
                source.mtime_seconds,
                declared[0],
                declared[1],
            )
        )
    records.sort(key=lambda item: _raw(item.relative))
    if (
        not records
        or len(records) > HARDLINK_DEDUPLICATED_MIRROR_MAXIMUM_FILES
        or len({item.relative for item in records}) != len(records)
        or set(metadata) != {item.relative for item in records}
    ):
        raise HardlinkDeduplicatedMirrorError(
            "candidate set and manifest coverage differ"
        )
    return tuple(records)


def _suffix(relative: str) -> str:
    basename = PurePosixPath(relative).name
    offset = basename.rfind(".")
    return basename[offset:] if offset > 0 else ""


def _equivalence_value(
    item: _SourceRecord, key: EquivalenceKey
) -> tuple[object, ...]:
    digest = sha256(item.content).hexdigest()
    if key == "sha256":
        return ("sha256", digest)
    if key == "mode-and-sha256":
        return ("mode-and-sha256", item.mode, digest)
    if key == "suffix-and-sha256":
        return ("suffix-and-sha256", _suffix(item.relative), digest)
    if key == "declared-group-and-sha256":
        return ("declared-group-and-sha256", item.declared_group, digest)
    raise HardlinkDeduplicatedMirrorError("equivalence key is invalid")


def _group_sha256(
    parameters: HardlinkDeduplicatedMirrorParameters,
    members: tuple[_SourceRecord, ...],
) -> str:
    digest = sha256()
    digest.update(b"cbds-hardlink-group-v2\0")
    digest.update(parameters.equivalence_key.encode("ascii"))
    digest.update(b"\0")
    for item in members:
        digest.update(item.relative.encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def _choose_owner(
    members: tuple[_SourceRecord, ...], policy: OwnerPolicy
) -> _SourceRecord:
    if policy == "smallest-path":
        return min(members, key=lambda item: _raw(item.relative))
    if policy == "largest-path":
        return max(members, key=lambda item: _raw(item.relative))
    if policy == "oldest-mtime":
        return min(
            members, key=lambda item: (item.mtime_seconds, _raw(item.relative))
        )
    if policy == "newest-mtime":
        return min(
            members, key=lambda item: (-item.mtime_seconds, _raw(item.relative))
        )
    if policy == "manifest-priority":
        return min(members, key=lambda item: item.priority)
    raise HardlinkDeduplicatedMirrorError("owner policy is invalid")


@dataclass(frozen=True, slots=True)
class HardlinkDeduplicatedMirrorMember:
    source: str
    output_path: str
    representative: str
    semantic_group_sha256: str
    group_size: int
    output_hardlink_group_sha256: str | None

    def __post_init__(self) -> None:
        if type(self) is not HardlinkDeduplicatedMirrorMember:
            raise HardlinkDeduplicatedMirrorError("member has wrong exact type")
        _validate_relative_source(self.source)
        _validate_relative_source(self.representative)
        expected_output = (
            HARDLINK_DEDUPLICATED_MIRROR_OUTPUT_ROOT / self.source
        ).as_posix()
        if (
            type(self.output_path) is not str
            or self.output_path != expected_output
            or not _is_sha256(self.semantic_group_sha256)
            or type(self.group_size) is not int
            or self.group_size < 1
            or (
                self.output_hardlink_group_sha256 is not None
                and not _is_sha256(self.output_hardlink_group_sha256)
            )
            or (
                self.group_size == 1
                and self.output_hardlink_group_sha256 is not None
            )
            or (
                self.group_size > 1
                and self.output_hardlink_group_sha256 is None
            )
        ):
            raise HardlinkDeduplicatedMirrorError("member fields are invalid")

    def commitment_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "source": self.source,
            "output_path": self.output_path,
            "representative": self.representative,
            "semantic_group_sha256": self.semantic_group_sha256,
            "group_size": self.group_size,
            "output_hardlink_group_sha256": self.output_hardlink_group_sha256,
        }


@dataclass(frozen=True, slots=True)
class HardlinkDeduplicatedMirrorOutput:
    path: str
    content: bytes = field(repr=False)
    mode: int
    mtime_seconds: int | None
    required_link_count: int
    hardlink_group_sha256: str | None

    def __post_init__(self) -> None:
        if type(self) is not HardlinkDeduplicatedMirrorOutput:
            raise HardlinkDeduplicatedMirrorError("output has wrong exact type")
        try:
            ExpectedFile(
                self.path,
                max(len(self.content), 1),
                self.mode,
                None,
            )
        except (TypeError, ValueError) as exc:
            raise HardlinkDeduplicatedMirrorError("output is invalid") from exc
        if (
            type(self.content) is not bytes
            or type(self.required_link_count) is not int
            or self.required_link_count < 1
            or (
                self.mtime_seconds is not None
                and (
                    type(self.mtime_seconds) is not int
                    or self.mtime_seconds < 0
                )
            )
            or (
                self.hardlink_group_sha256 is not None
                and not _is_sha256(self.hardlink_group_sha256)
            )
            or (
                self.required_link_count == 1
                and self.hardlink_group_sha256 is not None
            )
            or (
                self.required_link_count > 1
                and self.hardlink_group_sha256 is None
            )
        ):
            raise HardlinkDeduplicatedMirrorError("output metadata is invalid")

    def commitment_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "path": self.path,
            "required_kind": "regular",
            "required_link_count": self.required_link_count,
            "mode": self.mode,
            "mtime_seconds": self.mtime_seconds,
            "size": len(self.content),
            "sha256": sha256(self.content).hexdigest(),
            "hardlink_group_sha256": self.hardlink_group_sha256,
        }


def _ledger(
    members: tuple[HardlinkDeduplicatedMirrorMember, ...]
) -> bytes:
    groups = len({item.semantic_group_sha256 for item in members})
    payload = bytearray(
        f"mirror\t{len(members)}\t{groups}\t{len(members) - groups}\n".encode(
            "ascii"
        )
    )
    for item in members:
        payload.extend(
            (
                "file\t"
                + item.source
                + "\t"
                + item.representative
                + "\t"
                + item.semantic_group_sha256
                + "\t"
                + str(item.group_size)
                + "\n"
            ).encode("utf-8")
        )
    return bytes(payload)


def _expected_output_policy(
    outputs: tuple[HardlinkDeduplicatedMirrorOutput, ...],
) -> tuple[ExpectedFile, ...]:
    return tuple(
        ExpectedFile(
            output.path,
            (
                HARDLINK_DEDUPLICATED_MIRROR_OUTPUT_MAXIMUM_BYTES
                if output.path == HARDLINK_DEDUPLICATED_MIRROR_LEDGER_OUTPUT
                else HARDLINK_DEDUPLICATED_MIRROR_FILE_MAXIMUM_BYTES
            ),
            (
                HARDLINK_DEDUPLICATED_MIRROR_LEDGER_MODE
                if output.path == HARDLINK_DEDUPLICATED_MIRROR_LEDGER_OUTPUT
                else None
            ),
            (
                1
                if output.path == HARDLINK_DEDUPLICATED_MIRROR_LEDGER_OUTPUT
                else None
            ),
        )
        for output in outputs
    )


def _assemble_state(
    groups: list[tuple[_SourceRecord, ...]],
    parameters: HardlinkDeduplicatedMirrorParameters,
) -> tuple[
    tuple[HardlinkDeduplicatedMirrorMember, ...],
    tuple[HardlinkDeduplicatedMirrorOutput, ...],
]:
    members: list[HardlinkDeduplicatedMirrorMember] = []
    outputs: list[HardlinkDeduplicatedMirrorOutput] = []
    for group in groups:
        ordered = tuple(sorted(group, key=lambda item: _raw(item.relative)))
        owner = _choose_owner(ordered, parameters.owner_policy)
        semantic_digest = _group_sha256(parameters, ordered)
        output_paths = tuple(
            (
                HARDLINK_DEDUPLICATED_MIRROR_OUTPUT_ROOT / item.relative
            ).as_posix()
            for item in ordered
        )
        topology_digest = (
            compute_workspace_hardlink_group_sha256(
                tuple(sorted(output_paths, key=_raw)),
                len(output_paths),
            )
            if len(output_paths) > 1
            else None
        )
        for item, output_path in zip(ordered, output_paths, strict=True):
            members.append(
                HardlinkDeduplicatedMirrorMember(
                    item.relative,
                    output_path,
                    owner.relative,
                    semantic_digest,
                    len(ordered),
                    topology_digest,
                )
            )
            outputs.append(
                HardlinkDeduplicatedMirrorOutput(
                    output_path,
                    owner.content,
                    owner.mode,
                    owner.mtime_seconds,
                    len(ordered),
                    topology_digest,
                )
            )
    members.sort(key=lambda item: _raw(item.source))
    ledger_content = _ledger(tuple(members))
    outputs.append(
        HardlinkDeduplicatedMirrorOutput(
            HARDLINK_DEDUPLICATED_MIRROR_LEDGER_OUTPUT,
            ledger_content,
            HARDLINK_DEDUPLICATED_MIRROR_LEDGER_MODE,
            None,
            1,
            None,
        )
    )
    outputs.sort(key=lambda item: _raw(item.path))
    return tuple(members), tuple(outputs)


def derive_hardlink_deduplicated_mirror_state(
    definition: FixtureDefinition,
    parameters: HardlinkDeduplicatedMirrorParameters,
) -> tuple[
    tuple[HardlinkDeduplicatedMirrorMember, ...],
    tuple[HardlinkDeduplicatedMirrorOutput, ...],
]:
    """Primary dictionary-partition semantic implementation."""

    if type(parameters) is not HardlinkDeduplicatedMirrorParameters:
        raise HardlinkDeduplicatedMirrorError("parameters are invalid")
    parameters.__post_init__()
    source = _source_records(definition)
    partitions: dict[tuple[object, ...], list[_SourceRecord]] = {}
    for item in source:
        partitions.setdefault(
            _equivalence_value(item, parameters.equivalence_key), []
        ).append(item)
    groups = [
        tuple(values)
        for _key, values in sorted(
            partitions.items(),
            key=lambda item: min(_raw(value.relative) for value in item[1]),
        )
    ]
    state = _assemble_state(groups, parameters)
    if definition.expected_files and definition.expected_files != _expected_output_policy(
        state[1]
    ):
        raise HardlinkDeduplicatedMirrorError("output policy differs from state")
    return state


def _reference_sources(
    definition: FixtureDefinition,
) -> tuple[_SourceRecord, ...]:
    """Independently parse candidates by indexed paths and a streaming manifest."""

    selected = _revalidate_definition(definition)
    manifest: InputFile | None = None
    originals: dict[str, tuple[bytes, int, int]] = {}
    aliases: dict[str, str] = {}
    prefix = HARDLINK_DEDUPLICATED_MIRROR_SOURCE_ROOT.as_posix() + "/"
    for value in selected.inputs:
        if type(value) is InputFile:
            if value.path == HARDLINK_DEDUPLICATED_MIRROR_MANIFEST:
                if manifest is not None:
                    raise HardlinkDeduplicatedMirrorError(
                        "reference saw duplicate manifest"
                    )
                manifest = value
            elif value.path.startswith(prefix):
                if value.mtime_seconds is None:
                    raise HardlinkDeduplicatedMirrorError(
                        "reference source lacks mtime"
                    )
                originals[value.path] = (
                    value.content,
                    value.mode,
                    value.mtime_seconds,
                )
        elif type(value) is InputHardlink and value.path.startswith(prefix):
            aliases[value.path] = value.target
    if manifest is None:
        raise HardlinkDeduplicatedMirrorError("reference manifest is absent")
    fields = manifest.content.split(b"\0")
    if not fields or fields[-1:] != [b""] or (len(fields) - 1) % 3:
        raise HardlinkDeduplicatedMirrorError("reference manifest framing differs")
    rows: list[tuple[str, str, int]] = []
    for index in range(0, len(fields) - 1, 3):
        try:
            path = fields[index].decode("utf-8", "strict")
            declared = fields[index + 1].decode("utf-8", "strict")
            priority_wire = fields[index + 2].decode("ascii", "strict")
        except UnicodeError as exc:
            raise HardlinkDeduplicatedMirrorError(
                "reference manifest decoding failed"
            ) from exc
        _validate_relative_source(path)
        _validate_declared_group(declared)
        if (
            not priority_wire
            or not priority_wire.isdecimal()
            or (priority_wire.startswith("0") and priority_wire != "0")
        ):
            raise HardlinkDeduplicatedMirrorError(
                "reference priority is invalid"
            )
        rows.append((path, declared, int(priority_wire)))
    if (
        len(rows) > HARDLINK_DEDUPLICATED_MIRROR_MAXIMUM_FILES
        or len({row[0] for row in rows}) != len(rows)
        or {row[2] for row in rows} != set(range(len(rows)))
    ):
        raise HardlinkDeduplicatedMirrorError("reference manifest set is invalid")
    result: list[_SourceRecord] = []
    for relative, declared, priority in rows:
        absolute = prefix + relative
        values = originals.get(absolute)
        if values is None and absolute in aliases:
            values = originals.get(aliases[absolute])
        if values is None:
            raise HardlinkDeduplicatedMirrorError(
                "reference manifest names a noncandidate"
            )
        result.append(
            _SourceRecord(
                relative,
                values[0],
                values[1],
                values[2],
                declared,
                priority,
            )
        )
    discovered = set(originals) | set(aliases)
    if {prefix + item.relative for item in result} != discovered:
        raise HardlinkDeduplicatedMirrorError(
            "reference candidate coverage differs"
        )
    return tuple(sorted(result, key=lambda item: _raw(item.relative)))


def _reference_sort_key(
    item: _SourceRecord, key: EquivalenceKey
) -> tuple[bytes, ...]:
    digest = sha256(item.content).hexdigest().encode("ascii")
    if key == "sha256":
        return (b"0", digest)
    if key == "mode-and-sha256":
        return (b"1", f"{item.mode:04o}".encode("ascii"), digest)
    if key == "suffix-and-sha256":
        name = item.relative.rsplit("/", 1)[-1]
        dot = name.rfind(".")
        suffix = name[dot:] if dot > 0 else ""
        return (b"2", suffix.encode("utf-8"), digest)
    if key == "declared-group-and-sha256":
        return (b"3", item.declared_group.encode("utf-8"), digest)
    raise HardlinkDeduplicatedMirrorError("reference equivalence key invalid")


def reference_hardlink_deduplicated_mirror_state(
    definition: FixtureDefinition,
    parameters: HardlinkDeduplicatedMirrorParameters,
) -> tuple[
    tuple[HardlinkDeduplicatedMirrorMember, ...],
    tuple[HardlinkDeduplicatedMirrorOutput, ...],
]:
    """Reference sorted-stream/groupby semantic implementation."""

    if type(parameters) is not HardlinkDeduplicatedMirrorParameters:
        raise HardlinkDeduplicatedMirrorError("reference parameters are invalid")
    parameters.__post_init__()
    ordered = sorted(
        _reference_sources(definition),
        key=lambda item: (
            _reference_sort_key(item, parameters.equivalence_key),
            _raw(item.relative),
        ),
    )
    groups = [
        tuple(values)
        for _key, values in groupby(
            ordered,
            key=lambda item: _reference_sort_key(
                item, parameters.equivalence_key
            ),
        )
    ]
    state = _assemble_state(groups, parameters)
    if definition.expected_files and definition.expected_files != _expected_output_policy(
        state[1]
    ):
        raise HardlinkDeduplicatedMirrorError(
            "reference output policy differs"
        )
    return state


def verify_hardlink_deduplicated_mirror_state(
    definition: FixtureDefinition,
    parameters: HardlinkDeduplicatedMirrorParameters,
    candidate_members: object,
    candidate_outputs: object,
) -> bool:
    if (
        type(candidate_members) is not tuple
        or any(
            type(item) is not HardlinkDeduplicatedMirrorMember
            for item in candidate_members
        )
        or type(candidate_outputs) is not tuple
        or any(
            type(item) is not HardlinkDeduplicatedMirrorOutput
            for item in candidate_outputs
        )
    ):
        return False
    try:
        primary = derive_hardlink_deduplicated_mirror_state(
            definition, parameters
        )
        reference = reference_hardlink_deduplicated_mirror_state(
            definition, parameters
        )
    except (HardlinkDeduplicatedMirrorError, TypeError, ValueError):
        return False
    return primary == reference == (candidate_members, candidate_outputs)


def _validate_oracle_contents(
    members: object,
    outputs: object,
) -> tuple[
    tuple[HardlinkDeduplicatedMirrorMember, ...],
    tuple[HardlinkDeduplicatedMirrorOutput, ...],
]:
    if (
        type(members) is not tuple
        or not members
        or any(
            type(item) is not HardlinkDeduplicatedMirrorMember
            for item in members
        )
        or tuple(sorted(members, key=lambda item: _raw(item.source))) != members
        or len({item.source for item in members}) != len(members)
        or type(outputs) is not tuple
        or not outputs
        or any(
            type(item) is not HardlinkDeduplicatedMirrorOutput
            for item in outputs
        )
        or tuple(sorted(outputs, key=lambda item: _raw(item.path))) != outputs
        or len({item.path for item in outputs}) != len(outputs)
    ):
        raise HardlinkDeduplicatedMirrorError("oracle values are noncanonical")
    for item in members:
        item.__post_init__()
    for item in outputs:
        item.__post_init__()
    by_path = {item.path: item for item in outputs}
    if (
        set(by_path)
        != {item.output_path for item in members}
        | {HARDLINK_DEDUPLICATED_MIRROR_LEDGER_OUTPUT}
        or by_path[HARDLINK_DEDUPLICATED_MIRROR_LEDGER_OUTPUT].content
        != _ledger(members)
        or by_path[
            HARDLINK_DEDUPLICATED_MIRROR_LEDGER_OUTPUT
        ].required_link_count
        != 1
    ):
        raise HardlinkDeduplicatedMirrorError("oracle output coverage differs")
    groups: dict[str, list[HardlinkDeduplicatedMirrorMember]] = {}
    for member in members:
        groups.setdefault(member.semantic_group_sha256, []).append(member)
    for values in groups.values():
        owners = {item.representative for item in values}
        if (
            len(values) != values[0].group_size
            or len(owners) != 1
            or next(iter(owners)) not in {item.source for item in values}
            or any(
                item.group_size != len(values)
                or item.output_hardlink_group_sha256
                != values[0].output_hardlink_group_sha256
                for item in values
            )
        ):
            raise HardlinkDeduplicatedMirrorError(
                "oracle group membership differs"
            )
        group_outputs = [by_path[item.output_path] for item in values]
        first = group_outputs[0]
        if any(
            (
                output.content,
                output.mode,
                output.mtime_seconds,
                output.required_link_count,
                output.hardlink_group_sha256,
            )
            != (
                first.content,
                first.mode,
                first.mtime_seconds,
                len(values),
                values[0].output_hardlink_group_sha256,
            )
            for output in group_outputs
        ):
            raise HardlinkDeduplicatedMirrorError(
                "oracle group outputs differ"
            )
    return members, outputs  # type: ignore[return-value]


def _compute_oracle_sha256(
    members: tuple[HardlinkDeduplicatedMirrorMember, ...],
    outputs: tuple[HardlinkDeduplicatedMirrorOutput, ...],
) -> str:
    selected_members, selected_outputs = _validate_oracle_contents(
        members, outputs
    )
    return domain_sha256(
        "cbds.executable-fixture.trusted-oracle.v1",
        {
            "schema_version": EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION,
            "semantic_verifier_identity": (
                HARDLINK_DEDUPLICATED_MIRROR_VERIFIER_IDENTITY
            ),
            "members": [
                item.commitment_record() for item in selected_members
            ],
            "outputs": [
                item.commitment_record() for item in selected_outputs
            ],
        },
    )


@dataclass(frozen=True, slots=True)
class HardlinkDeduplicatedMirrorOracle:
    """Private answer and physical-topology commitment for one fixture."""

    members: tuple[HardlinkDeduplicatedMirrorMember, ...]
    outputs: tuple[HardlinkDeduplicatedMirrorOutput, ...]
    oracle_sha256: str
    semantic_verifier_identity: str = (
        HARDLINK_DEDUPLICATED_MIRROR_VERIFIER_IDENTITY
    )
    schema_version: str = EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            type(self) is not HardlinkDeduplicatedMirrorOracle
            or self.semantic_verifier_identity
            != HARDLINK_DEDUPLICATED_MIRROR_VERIFIER_IDENTITY
            or self.schema_version != EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION
            or not _is_sha256(self.oracle_sha256)
            or self.oracle_sha256
            != _compute_oracle_sha256(self.members, self.outputs)
        ):
            raise HardlinkDeduplicatedMirrorError("oracle identity is invalid")

    def commitment_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "schema_version": self.schema_version,
            "record_type": "cbds.executable-fixture-trusted-oracle",
            "semantic_verifier_identity": self.semantic_verifier_identity,
            "members": [item.commitment_record() for item in self.members],
            "outputs": [item.commitment_record() for item in self.outputs],
            "oracle_sha256": self.oracle_sha256,
        }


@dataclass(frozen=True, slots=True)
class HardlinkDeduplicatedMirrorFixtureBundle:
    task_contract_sha256: str
    profile_sha256: str
    definition: FixtureDefinition = field(repr=False)
    fixture_definition_sha256: str
    oracle: HardlinkDeduplicatedMirrorOracle = field(repr=False)
    descriptor: OpaqueFixtureDescriptor
    schema_version: str = EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_hardlink_deduplicated_mirror_fixture_bundle(self)

    def to_opaque_descriptor(self) -> OpaqueFixtureDescriptor:
        validate_hardlink_deduplicated_mirror_fixture_bundle(self)
        return self.descriptor

    def commitment_record(self) -> dict[str, object]:
        validate_hardlink_deduplicated_mirror_fixture_bundle(self)
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


def validate_hardlink_deduplicated_mirror_fixture_bundle(
    bundle: HardlinkDeduplicatedMirrorFixtureBundle,
) -> None:
    if type(bundle) is not HardlinkDeduplicatedMirrorFixtureBundle:
        raise HardlinkDeduplicatedMirrorError("bundle has wrong exact type")
    if (
        bundle.schema_version != EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION
        or not _is_sha256(bundle.task_contract_sha256)
        or not _is_sha256(bundle.profile_sha256)
        or not _is_sha256(bundle.fixture_definition_sha256)
        or bundle.candidate_execution_authorized is not False
        or bundle.model_selection_eligible is not False
        or bundle.claim_authorized is not False
    ):
        raise HardlinkDeduplicatedMirrorError("bundle metadata is invalid")
    definition = _revalidate_definition(bundle.definition)
    definition_digest = _definition_semantic_sha256(definition)
    if bundle.fixture_definition_sha256 != definition_digest:
        raise HardlinkDeduplicatedMirrorError("definition digest is invalid")
    if type(bundle.oracle) is not HardlinkDeduplicatedMirrorOracle:
        raise HardlinkDeduplicatedMirrorError("oracle has wrong exact type")
    bundle.oracle.__post_init__()
    if definition.expected_files != _expected_output_policy(
        bundle.oracle.outputs
    ):
        raise HardlinkDeduplicatedMirrorError(
            "answer-free output policy does not bind oracle paths"
        )
    if type(bundle.descriptor) is not OpaqueFixtureDescriptor:
        raise HardlinkDeduplicatedMirrorError(
            "descriptor has wrong exact type"
        )
    bundle.descriptor.__post_init__()
    fixture_digest = compute_bound_fixture_sha256(
        task_contract_sha256=bundle.task_contract_sha256,
        profile_sha256=bundle.profile_sha256,
        fixture_definition_sha256=definition_digest,
        oracle_sha256=bundle.oracle.oracle_sha256,
    )
    if (
        bundle.descriptor.fixture_sha256 != fixture_digest
        or bundle.descriptor.fixture_id != f"fx-{fixture_digest[:24]}"
        or bundle.descriptor.task_contract_sha256
        != bundle.task_contract_sha256
    ):
        raise HardlinkDeduplicatedMirrorError("descriptor binding is invalid")


def verify_hardlink_deduplicated_mirror_fixture_bundle(
    bundle: object,
) -> bool:
    try:
        validate_hardlink_deduplicated_mirror_fixture_bundle(
            bundle  # type: ignore[arg-type]
        )
    except (HardlinkDeduplicatedMirrorError, TypeError, ValueError):
        return False
    return True


def _validate_task_profile(
    task: object, profile: object
) -> tuple[
    HardlinkDeduplicatedMirrorTask,
    ExecutableFixtureProfile,
]:
    if type(task) is not HardlinkDeduplicatedMirrorTask:
        raise HardlinkDeduplicatedMirrorError("task has wrong exact type")
    if type(profile) is not ExecutableFixtureProfile:
        raise HardlinkDeduplicatedMirrorError("profile has wrong exact type")
    try:
        task.__post_init__()
        rebuilt_parameters = HardlinkDeduplicatedMirrorParameters(
            task.parameters.equivalence_key,
            task.parameters.owner_policy,
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
        raise HardlinkDeduplicatedMirrorError(
            "task/profile revalidation failed"
        ) from exc
    if (
        rebuilt_parameters != task.parameters
        or rebuilt_profile not in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
    ):
        raise HardlinkDeduplicatedMirrorError(
            "task/profile is outside the closed set"
        )
    return task, profile


def _construct_hardlink_deduplicated_mirror_fixture_bundle(
    task: HardlinkDeduplicatedMirrorTask,
    profile: ExecutableFixtureProfile,
) -> HardlinkDeduplicatedMirrorFixtureBundle:
    selected_task, selected_profile = _validate_task_profile(task, profile)
    inputs = _fixture_inputs(selected_profile)
    provisional = FixtureDefinition(
        f"fixture.{selected_task.task_id}.{selected_profile.profile_id}",
        inputs,
        (),
    )
    primary = derive_hardlink_deduplicated_mirror_state(
        provisional, selected_task.parameters
    )
    reference = reference_hardlink_deduplicated_mirror_state(
        provisional, selected_task.parameters
    )
    if primary != reference:
        raise HardlinkDeduplicatedMirrorError(
            "independent state engines disagree"
        )
    definition = FixtureDefinition(
        provisional.fixture_id,
        inputs,
        _expected_output_policy(primary[1]),
    )
    if (
        derive_hardlink_deduplicated_mirror_state(
            definition, selected_task.parameters
        )
        != primary
        or reference_hardlink_deduplicated_mirror_state(
            definition, selected_task.parameters
        )
        != reference
    ):
        raise HardlinkDeduplicatedMirrorError(
            "final output policy changed semantics"
        )
    oracle = HardlinkDeduplicatedMirrorOracle(
        primary[0],
        primary[1],
        _compute_oracle_sha256(primary[0], primary[1]),
    )
    definition_digest = _definition_semantic_sha256(definition)
    fixture_digest = compute_bound_fixture_sha256(
        task_contract_sha256=selected_task.task_contract_sha256,
        profile_sha256=selected_profile.profile_sha256,
        fixture_definition_sha256=definition_digest,
        oracle_sha256=oracle.oracle_sha256,
    )
    return HardlinkDeduplicatedMirrorFixtureBundle(
        task_contract_sha256=selected_task.task_contract_sha256,
        profile_sha256=selected_profile.profile_sha256,
        definition=definition,
        fixture_definition_sha256=definition_digest,
        oracle=oracle,
        descriptor=OpaqueFixtureDescriptor(
            fixture_id=f"fx-{fixture_digest[:24]}",
            fixture_sha256=fixture_digest,
            task_contract_sha256=selected_task.task_contract_sha256,
        ),
    )


def build_hardlink_deduplicated_mirror_fixture_bundle(
    task: HardlinkDeduplicatedMirrorTask,
    profile: ExecutableFixtureProfile,
) -> HardlinkDeduplicatedMirrorFixtureBundle:
    bundle = _construct_hardlink_deduplicated_mirror_fixture_bundle(
        task, profile
    )
    validate_hardlink_deduplicated_mirror_fixture_for_task_profile(
        task, profile, bundle
    )
    return bundle


def validate_hardlink_deduplicated_mirror_fixture_for_task_profile(
    task: HardlinkDeduplicatedMirrorTask,
    profile: ExecutableFixtureProfile,
    bundle: HardlinkDeduplicatedMirrorFixtureBundle,
) -> None:
    selected_task, selected_profile = _validate_task_profile(task, profile)
    validate_hardlink_deduplicated_mirror_fixture_bundle(bundle)
    if (
        bundle.task_contract_sha256 != selected_task.task_contract_sha256
        or bundle.profile_sha256 != selected_profile.profile_sha256
    ):
        raise HardlinkDeduplicatedMirrorError("bundle binding differs")
    index = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES.index(selected_profile)
    if selected_task.fixtures[index] != bundle.descriptor:
        raise HardlinkDeduplicatedMirrorError("public descriptor differs")
    rebuilt = _construct_hardlink_deduplicated_mirror_fixture_bundle(
        selected_task, selected_profile
    )
    if rebuilt != bundle:
        raise HardlinkDeduplicatedMirrorError(
            "bundle differs from reconstruction"
        )


def verify_hardlink_deduplicated_mirror_fixture_for_task_profile(
    task: object, profile: object, bundle: object
) -> bool:
    try:
        validate_hardlink_deduplicated_mirror_fixture_for_task_profile(
            task,  # type: ignore[arg-type]
            profile,  # type: ignore[arg-type]
            bundle,  # type: ignore[arg-type]
        )
    except (HardlinkDeduplicatedMirrorError, TypeError, ValueError):
        return False
    return True


def _discrimination_signature(
    bundle: HardlinkDeduplicatedMirrorFixtureBundle,
) -> tuple[tuple[tuple[str, ...], ...], str]:
    key_groups: dict[str, list[str]] = {}
    owner_probe = ""
    for member in bundle.oracle.members:
        if member.source.startswith("key/"):
            key_groups.setdefault(
                member.semantic_group_sha256, []
            ).append(member.source)
        if member.source == "owner/a.dat":
            owner_probe = member.representative
    partition = tuple(
        sorted(
            (
                tuple(sorted(values, key=_raw))
                for values in key_groups.values()
            ),
            key=lambda values: tuple(_raw(value) for value in values),
        )
    )
    if len({value for group in partition for value in group}) != 4 or not owner_probe:
        raise HardlinkDeduplicatedMirrorError(
            "fixture lacks discrimination probes"
        )
    return partition, owner_probe


def compute_hardlink_deduplicated_mirror_discrimination_sha256(
    tasks: tuple[HardlinkDeduplicatedMirrorTask, ...],
) -> str:
    """Bind the fixture-oracle-derived signature for every grid cell.

    This is development evidence, not candidate execution evidence.  It
    rebuilds the first public fixture for each exact task and commits the
    resulting equivalence partition and selected owner.  A digest is returned
    only when the canonical 4-by-5 task order yields 20 distinct signatures.
    """

    expected_grid = tuple(
        (key, policy)
        for key in HARDLINK_DEDUPLICATED_MIRROR_EQUIVALENCE_KEYS
        for policy in HARDLINK_DEDUPLICATED_MIRROR_OWNER_POLICIES
    )
    if (
        type(tasks) is not tuple
        or len(tasks) != len(expected_grid)
        or any(type(task) is not HardlinkDeduplicatedMirrorTask for task in tasks)
        or tuple(
            (task.parameters.equivalence_key, task.parameters.owner_policy)
            for task in tasks
        )
        != expected_grid
    ):
        raise HardlinkDeduplicatedMirrorError(
            "discrimination evidence requires the canonical 20-task grid"
        )
    profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
    records: list[dict[str, object]] = []
    signatures: list[tuple[tuple[tuple[str, ...], ...], str]] = []
    for task in tasks:
        task.__post_init__()
        bundle = _construct_hardlink_deduplicated_mirror_fixture_bundle(
            task, profile
        )
        if bundle.descriptor != task.fixtures[0]:
            raise HardlinkDeduplicatedMirrorError(
                "discrimination fixture differs from its public descriptor"
            )
        partition, owner = _discrimination_signature(bundle)
        signatures.append((partition, owner))
        records.append(
            {
                "task_id": task.task_id,
                "equivalence_key": task.parameters.equivalence_key,
                "owner_policy": task.parameters.owner_policy,
                "key_probe_partition": [list(group) for group in partition],
                "owner_probe_representative": owner,
                "fixture_sha256": bundle.descriptor.fixture_sha256,
            }
        )
    if len(set(signatures)) != len(expected_grid):
        raise HardlinkDeduplicatedMirrorError(
            "hardlink grid signatures are not fully discriminable"
        )
    return domain_sha256(
        "cbds.executable-static.hardlink-deduplicated-mirror."
        "discrimination-evidence.v1",
        {
            "family_id": HARDLINK_DEDUPLICATED_MIRROR_FAMILY_ID,
            "profile_sha256": profile.profile_sha256,
            "signature_count": len(records),
            "signatures": records,
        },
    )


def build_hardlink_deduplicated_mirror_tasks() -> tuple[
    HardlinkDeduplicatedMirrorTask, ...
]:
    tasks: list[HardlinkDeduplicatedMirrorTask] = []
    signatures: list[tuple[tuple[tuple[str, ...], ...], str]] = []
    for key in HARDLINK_DEDUPLICATED_MIRROR_EQUIVALENCE_KEYS:
        for policy in HARDLINK_DEDUPLICATED_MIRROR_OWNER_POLICIES:
            bootstrap = _bootstrap_task(
                HardlinkDeduplicatedMirrorParameters(key, policy)
            )
            bundles = tuple(
                _construct_hardlink_deduplicated_mirror_fixture_bundle(
                    bootstrap, profile
                )
                for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
            )
            task = replace(
                bootstrap,
                fixtures=tuple(bundle.descriptor for bundle in bundles),
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
        raise HardlinkDeduplicatedMirrorError(
            "task grid is not 20 fully discriminable tasks"
        )
    return selected


def materialize_hardlink_deduplicated_mirror_fixture(
    task: HardlinkDeduplicatedMirrorTask,
    profile: ExecutableFixtureProfile,
    bundle: HardlinkDeduplicatedMirrorFixtureBundle,
    workspace: str | os.PathLike[str],
) -> WorkspaceHandle:
    validate_hardlink_deduplicated_mirror_fixture_for_task_profile(
        task, profile, bundle
    )
    return materialize_fixture(bundle.definition, workspace)


def verify_hardlink_deduplicated_mirror_workspace(
    task: HardlinkDeduplicatedMirrorTask,
    profile: ExecutableFixtureProfile,
    bundle: HardlinkDeduplicatedMirrorFixtureBundle,
    handle: WorkspaceHandle,
) -> bool:
    """Verify exact bytes, metadata, input preservation, and inode topology."""

    if type(handle) is not WorkspaceHandle:
        return False
    try:
        validate_hardlink_deduplicated_mirror_fixture_for_task_profile(
            task, profile, bundle
        )
        baseline = handle.baseline
        if (
            baseline.fixture_id != bundle.definition.fixture_id
            or baseline.fixture_sha256 != bundle.definition.fixture_sha256
            or handle.expected_files != bundle.definition.expected_files
            or handle.expected_symlinks
            or baseline.output_scaffold_entries
        ):
            return False
        primary = derive_hardlink_deduplicated_mirror_state(
            bundle.definition, task.parameters
        )
        reference = reference_hardlink_deduplicated_mirror_state(
            bundle.definition, task.parameters
        )
        if primary != reference != (
            bundle.oracle.members,
            bundle.oracle.outputs,
        ):
            return False
        if primary != (
            bundle.oracle.members,
            bundle.oracle.outputs,
        ):
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
        by_path = {item.path: item for item in output_entries}
        for expected in bundle.oracle.outputs:
            entry = by_path.get(expected.path)
            if (
                entry is None
                or entry.mode != expected.mode
                or entry.link_count != expected.required_link_count
                or entry.hardlink_group_sha256
                != expected.hardlink_group_sha256
                or (
                    expected.mtime_seconds is not None
                    and entry.mtime_ns
                    != expected.mtime_seconds * 1_000_000_000
                )
                or handle.read_output_bytes(output_scan, expected.path)
                != expected.content
            ):
                return False
        final_input_scan = handle.scan_inputs()
        handle.validate_input_object_identities(final_input_scan)
        final_output_scan = handle.scan_outputs()
        return (
            final_input_scan == input_scan
            and final_output_scan == output_scan
            and final_input_scan.entries == baseline.input_entries
        )
    except (
        ExecutableWorkspaceError,
        HardlinkDeduplicatedMirrorError,
        OSError,
        TypeError,
        ValueError,
    ):
        return False


__all__ = [
    "HARDLINK_DEDUPLICATED_MIRROR_ALLOWED_TOOLS",
    "HARDLINK_DEDUPLICATED_MIRROR_CANDIDATE_EXIT_STATUS_OBSERVED",
    "HARDLINK_DEDUPLICATED_MIRROR_CREATION_HISTORY_OBSERVED",
    "HARDLINK_DEDUPLICATED_MIRROR_DIRECTORY_PERMISSION_ERRORS_COVERED",
    "HARDLINK_DEDUPLICATED_MIRROR_EQUIVALENCE_KEYS",
    "HARDLINK_DEDUPLICATED_MIRROR_FAMILY_ID",
    "HARDLINK_DEDUPLICATED_MIRROR_FILE_MAXIMUM_BYTES",
    "HARDLINK_DEDUPLICATED_MIRROR_FILESYSTEM_IDENTITY",
    "HARDLINK_DEDUPLICATED_MIRROR_GENERATOR_VERSION",
    "HARDLINK_DEDUPLICATED_MIRROR_INPUT_HARDLINKS_COVERED",
    "HARDLINK_DEDUPLICATED_MIRROR_LEDGER_MODE",
    "HARDLINK_DEDUPLICATED_MIRROR_LEDGER_OUTPUT",
    "HARDLINK_DEDUPLICATED_MIRROR_MANIFEST",
    "HARDLINK_DEDUPLICATED_MIRROR_MANIFEST_MAXIMUM_BYTES",
    "HARDLINK_DEDUPLICATED_MIRROR_MAXIMUM_FILES",
    "HARDLINK_DEDUPLICATED_MIRROR_OUTPUT_HARDLINK_TOPOLOGY_OBSERVED",
    "HARDLINK_DEDUPLICATED_MIRROR_OUTPUT_IDENTITY",
    "HARDLINK_DEDUPLICATED_MIRROR_OUTPUT_MAXIMUM_BYTES",
    "HARDLINK_DEDUPLICATED_MIRROR_OUTPUT_ROOT",
    "HARDLINK_DEDUPLICATED_MIRROR_OWNER_POLICIES",
    "HARDLINK_DEDUPLICATED_MIRROR_REPORT_MAXIMUM_BYTES",
    "HARDLINK_DEDUPLICATED_MIRROR_SOURCE_MTIME_COMMITTED",
    "HARDLINK_DEDUPLICATED_MIRROR_SOURCE_ROOT",
    "HARDLINK_DEDUPLICATED_MIRROR_SYMLINK_DISTRACTORS_COVERED",
    "HARDLINK_DEDUPLICATED_MIRROR_TOOL_HISTORY_OBSERVED",
    "HARDLINK_DEDUPLICATED_MIRROR_VERIFIER_IDENTITY",
    "HARDLINK_DEDUPLICATED_MIRROR_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE",
    "HARDLINK_DEDUPLICATED_MIRROR_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE",
    "HardlinkDeduplicatedMirrorError",
    "HardlinkDeduplicatedMirrorFixtureBundle",
    "HardlinkDeduplicatedMirrorMember",
    "HardlinkDeduplicatedMirrorOracle",
    "HardlinkDeduplicatedMirrorOutput",
    "HardlinkDeduplicatedMirrorParameters",
    "HardlinkDeduplicatedMirrorTask",
    "build_hardlink_deduplicated_mirror_fixture_bundle",
    "build_hardlink_deduplicated_mirror_tasks",
    "compute_hardlink_deduplicated_mirror_discrimination_sha256",
    "compute_hardlink_deduplicated_mirror_task_sha256",
    "derive_hardlink_deduplicated_mirror_state",
    "hardlink_deduplicated_mirror_task_semantic_core",
    "materialize_hardlink_deduplicated_mirror_fixture",
    "reference_hardlink_deduplicated_mirror_state",
    "validate_hardlink_deduplicated_mirror_fixture_bundle",
    "validate_hardlink_deduplicated_mirror_fixture_for_task_profile",
    "verify_hardlink_deduplicated_mirror_fixture_bundle",
    "verify_hardlink_deduplicated_mirror_fixture_for_task_profile",
    "verify_hardlink_deduplicated_mirror_state",
    "verify_hardlink_deduplicated_mirror_workspace",
]
