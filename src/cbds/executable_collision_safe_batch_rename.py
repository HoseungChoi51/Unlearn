"""Public method-development family for collision-safe batch renames.

The family turns a recursively discovered candidate tree into a flat renamed
tree while making collision policy, source retention, and byte-identical
coalescing observable in the final filesystem state.  Two separately
structured semantic engines must agree on both the source-action plan and the
published outputs.

This module never executes candidate code.  Its workspace verifier requires a
trusted harness to establish quiescence, and it intentionally does not claim
to observe rename, staging, atomic-publication, tool, or crash history.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from itertools import groupby
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
    MAX_PATH_UTF8_BYTES,
    WorkspaceEntry,
    WorkspaceHandle,
    materialize_fixture,
    validate_expected_output_policy,
)


COLLISION_SAFE_BATCH_RENAME_FAMILY_ID: Final[str] = (
    "collision-safe-batch-rename"
)
COLLISION_SAFE_BATCH_RENAME_FILESYSTEM_IDENTITY: Final[str] = (
    "rename-candidate-tree"
)
COLLISION_SAFE_BATCH_RENAME_OUTPUT_IDENTITY: Final[str] = (
    "atomic-renamed-tree-and-ledger"
)
COLLISION_SAFE_BATCH_RENAME_GENERATOR_VERSION: Final[str] = "1.0.0"
COLLISION_SAFE_BATCH_RENAME_VERIFIER_IDENTITY: Final[str] = (
    "verify-collision-safe-batch-rename-v1"
)
COLLISION_SAFE_BATCH_RENAME_CANDIDATE_ROOT: Final[PurePosixPath] = (
    PurePosixPath("input/rename/candidates")
)
COLLISION_SAFE_BATCH_RENAME_MAPPING: Final[str] = (
    "input/rename/mapping.tsv"
)
COLLISION_SAFE_BATCH_RENAME_OUTPUT_ROOT: Final[PurePosixPath] = (
    PurePosixPath("output/tree")
)
COLLISION_SAFE_BATCH_RENAME_LEDGER_OUTPUT: Final[str] = "output/ledger.tsv"
COLLISION_SAFE_BATCH_RENAME_LEDGER_MODE: Final[int] = 0o644
COLLISION_SAFE_BATCH_RENAME_OUTPUT_MAXIMUM_BYTES: Final[int] = 1024 * 1024
COLLISION_SAFE_BATCH_RENAME_MAPPING_MAXIMUM_BYTES: Final[int] = 64 * 1024
COLLISION_SAFE_BATCH_RENAME_CANDIDATE_MAXIMUM_BYTES: Final[int] = 16 * 1024
COLLISION_SAFE_BATCH_RENAME_MAXIMUM_CANDIDATES: Final[int] = 128
COLLISION_SAFE_BATCH_RENAME_MAXIMUM_MAPPING_ROWS: Final[int] = 256
COLLISION_SAFE_BATCH_RENAME_ALLOWED_TOOLS: Final[tuple[str, ...]] = (
    "find",
    "mkdir",
    "mv",
    "sort",
    "stat",
)

# Honest fixture and observation boundaries.
COLLISION_SAFE_BATCH_RENAME_SYMLINK_DISTRACTORS_COVERED: Final[bool] = True
COLLISION_SAFE_BATCH_RENAME_MODE_UNREADABLE_UNLISTED_LEAVES_COVERED: Final[
    bool
] = True
COLLISION_SAFE_BATCH_RENAME_DIRECTORY_PERMISSION_ERRORS_COVERED: Final[
    bool
] = False
COLLISION_SAFE_BATCH_RENAME_EFFECTIVE_ACCESS_FAILURES_COVERED: Final[
    bool
] = False
COLLISION_SAFE_BATCH_RENAME_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE: Final[
    bool
] = True
COLLISION_SAFE_BATCH_RENAME_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE: Final[
    bool
] = False
COLLISION_SAFE_BATCH_RENAME_RENAME_HISTORY_OBSERVED: Final[bool] = False
COLLISION_SAFE_BATCH_RENAME_ATOMIC_PUBLICATION_HISTORY_OBSERVED: Final[
    bool
] = False
COLLISION_SAFE_BATCH_RENAME_CRASH_ATOMICITY_OBSERVED: Final[bool] = False
COLLISION_SAFE_BATCH_RENAME_INODE_IDENTITY_OBSERVED: Final[bool] = False
COLLISION_SAFE_BATCH_RENAME_COLLISION_DECISION_HISTORY_OBSERVED: Final[
    bool
] = False
COLLISION_SAFE_BATCH_RENAME_READ_SCOPE_OBSERVED: Final[bool] = False
COLLISION_SAFE_BATCH_RENAME_TOOL_HISTORY_OBSERVED: Final[bool] = False
COLLISION_SAFE_BATCH_RENAME_TRANSIENT_INPUT_PRESERVATION_OBSERVED: Final[
    bool
] = False
COLLISION_SAFE_BATCH_RENAME_CANDIDATE_EXIT_STATUS_OBSERVED: Final[bool] = False

RenameRule: TypeAlias = Literal[
    "lowercase-basename",
    "numbered-prefix",
    "suffix-rewrite",
    "manifest-mapping",
]
CollisionPolicy: TypeAlias = Literal[
    "reject-all",
    "skip-collisions",
    "stable-first",
    "stable-last",
    "identical-files-coalesce",
]
RenameOutcome: TypeAlias = Literal[
    "moved",
    "retained-rejected",
    "retained-collision",
    "retained-loser",
    "coalesced",
    "retained-nonidentical",
]

COLLISION_SAFE_BATCH_RENAME_RENAME_RULES: Final[tuple[RenameRule, ...]] = (
    "lowercase-basename",
    "numbered-prefix",
    "suffix-rewrite",
    "manifest-mapping",
)
COLLISION_SAFE_BATCH_RENAME_COLLISION_POLICIES: Final[
    tuple[CollisionPolicy, ...]
] = (
    "reject-all",
    "skip-collisions",
    "stable-first",
    "stable-last",
    "identical-files-coalesce",
)
_OUTCOMES: Final[tuple[RenameOutcome, ...]] = (
    "moved",
    "retained-rejected",
    "retained-collision",
    "retained-loser",
    "coalesced",
    "retained-nonidentical",
)
_REMOVED_OUTCOMES: Final[frozenset[str]] = frozenset({"moved", "coalesced"})
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_TASK_ID_RE: Final[re.Pattern[str]] = re.compile(r"mds-[0-9a-f]{24}\Z")


class CollisionSafeBatchRenameError(ValueError):
    """Raised when a rename task, fixture, plan, or output fails closed."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def _closed_text(
    value: object, allowed: tuple[str, ...], field_name: str
) -> str:
    if type(value) is not str or value not in allowed:
        raise CollisionSafeBatchRenameError(
            f"{field_name} is outside the closed family contract"
        )
    return value


def _raw_key(value: str) -> bytes:
    return value.encode("utf-8")


def _validate_basename(value: object, label: str = "destination") -> str:
    if type(value) is not str or not value or value in {".", ".."}:
        raise CollisionSafeBatchRenameError(f"{label} is not a safe basename")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise CollisionSafeBatchRenameError(
            f"{label} is not strict UTF-8"
        ) from exc
    if (
        len(encoded) > 255
        or "/" in value
        or value.startswith(".cbds-stage-")
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise CollisionSafeBatchRenameError(f"{label} is not a safe basename")
    return value


def _validate_relative_source(value: object) -> str:
    if type(value) is not str or not value:
        raise CollisionSafeBatchRenameError("mapping source is invalid")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise CollisionSafeBatchRenameError("mapping source is not UTF-8") from exc
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
        or len(
            (
                COLLISION_SAFE_BATCH_RENAME_CANDIDATE_ROOT.as_posix()
                + "/"
                + value
            ).encode("utf-8")
        )
        > MAX_PATH_UTF8_BYTES
        or any(len(part.encode("utf-8")) > 255 for part in path.parts)
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise CollisionSafeBatchRenameError("mapping source is noncanonical")
    return value


@dataclass(frozen=True, slots=True)
class CollisionSafeBatchRenameParameters:
    """One cell in the four-rule by five-collision-policy grid."""

    rename_rule: RenameRule
    collision_policy: CollisionPolicy

    def __post_init__(self) -> None:
        if type(self) is not CollisionSafeBatchRenameParameters:
            raise CollisionSafeBatchRenameError("parameters have wrong exact type")
        _closed_text(
            self.rename_rule,
            COLLISION_SAFE_BATCH_RENAME_RENAME_RULES,
            "rename_rule",
        )
        _closed_text(
            self.collision_policy,
            COLLISION_SAFE_BATCH_RENAME_COLLISION_POLICIES,
            "collision_policy",
        )

    def to_record(self) -> dict[str, str]:
        self.__post_init__()
        return {
            "parameter_type": COLLISION_SAFE_BATCH_RENAME_FAMILY_ID,
            "rename_rule": self.rename_rule,
            "collision_policy": self.collision_policy,
        }


_RULE_TEXT: Final[dict[RenameRule, str]] = {
    "lowercase-basename": (
        "Use the final source basename and map only ASCII A through Z to "
        "lowercase. Preserve every other character."
    ),
    "numbered-prefix": (
        "Within each original parent directory, sort candidate basenames by "
        "raw UTF-8 bytes and prefix the one-based rank as four decimal digits "
        "and a hyphen. Keep the original basename after the prefix."
    ),
    "suffix-rewrite": (
        "If the final basename's last dot is neither its first nor final "
        "character, replace that dot and following suffix with .ready. "
        "Otherwise append .ready."
    ),
    "manifest-mapping": (
        "Use only the destination basename assigned by mapping.tsv. Mapping "
        "physical order is nonsemantic."
    ),
}
_POLICY_TEXT: Final[dict[CollisionPolicy, str]] = {
    "reject-all": (
        "If any destination has multiple sources, reject the whole batch and "
        "retain every source. Otherwise move every singleton."
    ),
    "skip-collisions": (
        "Move singleton groups and retain every source in collision groups."
    ),
    "stable-first": (
        "For each collision group move its raw-source-byte-first member and "
        "retain every loser. Move singleton groups."
    ),
    "stable-last": (
        "For each collision group move its raw-source-byte-last member and "
        "retain every loser. Move singleton groups."
    ),
    "identical-files-coalesce": (
        "Move singleton groups. For a collision group whose files have exactly "
        "identical bytes, remove all members into one destination and use the "
        "raw-source-byte-first member as metadata representative. If any bytes "
        "differ, retain the whole group."
    ),
}


def _task_contract(
    parameters: CollisionSafeBatchRenameParameters,
) -> tuple[str, NormalizedSemanticGraph]:
    prompt = f"""Write one Bash program that operates only in the current workspace.

Recursively discover exact regular files below input/rename/candidates without
following symlinks. These and only these files are candidates. Candidate paths
are canonical strict UTF-8 without ASCII control characters or DEL, are link-count-one and
owner-readable, and contain at most 16384 arbitrary bytes. There are at most
128 candidates. Preserve every noncandidate input leaf exactly.

input/rename/mapping.tsv is strict UTF-8, empty or LF-terminated, headerless
SOURCE<TAB>DEST data of at most 65536 bytes and 256 physical rows. SOURCE is a
canonical path relative to input/rename/candidates and DEST is a safe basename:
nonempty, not dot or dot-dot, no slash, ASCII control character, DEL, or
reserved .cbds-stage- prefix, at most 255 UTF-8 bytes. The full candidate
source path is at most 4096 UTF-8 bytes. Exact duplicate rows collapse. After collapsing duplicates there is
exactly one row per candidate and no SOURCE conflict. Scored fixtures satisfy
this domain.

Apply rename rule {parameters.rename_rule}. {_RULE_TEXT[parameters.rename_rule]}
Scored fixtures guarantee that the selected rule's derived basename remains
within the same safe 255-byte destination domain.
All destinations are flattened beneath output/tree; original parent paths are
not reproduced. A collision group consists of every source with exactly the
same destination basename. Sort source paths relative to the candidate root by
raw UTF-8 bytes for every stable choice and report order.

Apply collision policy {parameters.collision_policy}. {_POLICY_TEXT[parameters.collision_policy]}
Byte identity includes empty data, NUL, invalid UTF-8, and final-newline
differences. Under identical-files-coalesce, move nonrepresentatives first and
the representative last so the representative supplies the final permission
mode and modification time. Every published file preserves representative
bytes, permission bits, and modification time and has link count one. Removed
sources must be absent. Retained sources must preserve exact metadata and
bytes. Leave every original input directory in place.

Write output/ledger.tsv in strict UTF-8 with LF endings. Its first row is:
batch, STATE, candidate count, collision-group count, destination count,
removed-source count, retained-source count. STATE is rejected only when
reject-all sees a collision; otherwise it is complete. Then write one row per
source in raw source-byte order:
file, OUTCOME, full SOURCE path, destination basename, REPRESENTATIVE full
source path or an empty field, and group size. Fields are tab separated.
OUTCOME is moved, retained-rejected, retained-collision, retained-loser,
coalesced, or retained-nonidentical. Moved/coalesced and retained-loser rows
name the selected representative; the other retained outcomes use an empty
representative. Omit output/tree entirely when no destination is published.
Create only necessary real mode-0755 output ancestors; ledger is a mode-0644,
link-count-one regular file. Leave no staging or extra final path.

The tree and ledger should be assembled together before final publication.
The scored final-state check does not claim to observe atomic, crash, staging,
rename, inode, read-scope, tool, or exit-status history. Use LC_ALL=C and only
Bash built-ins plus find, mkdir, mv, sort, and stat.
"""
    graph = NormalizedSemanticGraph(
        nodes=(
            OperatorNode(
                "discover_rename_candidates",
                (
                    "root:input/rename/candidates",
                    "regular-files:no-follow",
                ),
            ),
            OperatorNode(
                "derive_flat_destination",
                (f"rename-rule:{parameters.rename_rule}",),
            ),
            OperatorNode(
                "resolve_destination_collisions",
                (
                    f"collision-policy:{parameters.collision_policy}",
                    "stable-order:raw-utf8-source",
                ),
            ),
            OperatorNode(
                "publish_tree_and_ledger",
                (
                    "tree:output/tree",
                    "ledger:output/ledger.tsv",
                    "representative-metadata:preserve",
                ),
            ),
        ),
        dependencies=((0, 1), (1, 2), (2, 3)),
    )
    return prompt, graph


def _validate_graph(graph: object) -> NormalizedSemanticGraph:
    if type(graph) is not NormalizedSemanticGraph:
        raise CollisionSafeBatchRenameError("graph has wrong exact type")
    rebuilt = NormalizedSemanticGraph(
        nodes=tuple(
            OperatorNode(node.name, node.parameters)
            for node in graph.nodes
            if type(node) is OperatorNode
        ),
        dependencies=graph.dependencies,
    )
    if (
        rebuilt != graph
        or len(rebuilt.nodes) != len(graph.nodes)
        or any(
            type(node.name) is not str
            or type(node.parameters) is not tuple
            or any(type(value) is not str for value in node.parameters)
            for node in rebuilt.nodes
        )
    ):
        raise CollisionSafeBatchRenameError("graph is noncanonical")
    return graph


def collision_safe_batch_rename_task_semantic_core(
    parameters: CollisionSafeBatchRenameParameters,
    prompt: str,
    graph: NormalizedSemanticGraph,
) -> dict[str, object]:
    if type(parameters) is not CollisionSafeBatchRenameParameters:
        raise CollisionSafeBatchRenameError("parameters have wrong exact type")
    parameters.__post_init__()
    expected_prompt, expected_graph = _task_contract(parameters)
    if (
        type(prompt) is not str
        or prompt != expected_prompt
        or _validate_graph(graph) != expected_graph
    ):
        raise CollisionSafeBatchRenameError("prompt or graph differs")
    return {
        "schema_version": EXECUTABLE_STATIC_SCHEMA_VERSION,
        "contract_version": EXECUTABLE_STATIC_CONTRACT_VERSION,
        "split_role": METHOD_DEVELOPMENT_SPLIT,
        "family_id": COLLISION_SAFE_BATCH_RENAME_FAMILY_ID,
        "family_version": EXECUTABLE_STATIC_FAMILY_VERSION,
        "parameters": parameters.to_record(),
        "prompt": prompt,
        "graph": graph.to_record(),
        "graph_sha256": graph.hash,
        "filesystem_identity": COLLISION_SAFE_BATCH_RENAME_FILESYSTEM_IDENTITY,
        "output_identity": COLLISION_SAFE_BATCH_RENAME_OUTPUT_IDENTITY,
        "allowed_tools": list(COLLISION_SAFE_BATCH_RENAME_ALLOWED_TOOLS),
        "public": True,
        "sealed": False,
        "candidate_execution_authorized": False,
        "model_selection_eligible": False,
        "claim_authorized": False,
    }


def compute_collision_safe_batch_rename_task_sha256(
    parameters: CollisionSafeBatchRenameParameters,
    prompt: str,
    graph: NormalizedSemanticGraph,
) -> str:
    return domain_sha256(
        "cbds.executable-static.task-contract.v1",
        collision_safe_batch_rename_task_semantic_core(
            parameters, prompt, graph
        ),
    )


@dataclass(frozen=True, slots=True)
class CollisionSafeBatchRenameTask:
    task_id: str
    parameters: CollisionSafeBatchRenameParameters
    prompt: str
    graph: NormalizedSemanticGraph
    fixtures: tuple[OpaqueFixtureDescriptor, ...]
    task_contract_sha256: str
    family_id: str = COLLISION_SAFE_BATCH_RENAME_FAMILY_ID
    family_version: str = EXECUTABLE_STATIC_FAMILY_VERSION
    filesystem_identity: str = COLLISION_SAFE_BATCH_RENAME_FILESYSTEM_IDENTITY
    output_identity: str = COLLISION_SAFE_BATCH_RENAME_OUTPUT_IDENTITY
    allowed_tools: tuple[str, ...] = COLLISION_SAFE_BATCH_RENAME_ALLOWED_TOOLS
    split_role: str = METHOD_DEVELOPMENT_SPLIT
    public: bool = True
    sealed: bool = False
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        if (
            type(self) is not CollisionSafeBatchRenameTask
            or type(self.parameters) is not CollisionSafeBatchRenameParameters
            or type(self.family_id) is not str
            or self.family_id != COLLISION_SAFE_BATCH_RENAME_FAMILY_ID
            or type(self.family_version) is not str
            or self.family_version != EXECUTABLE_STATIC_FAMILY_VERSION
            or type(self.filesystem_identity) is not str
            or self.filesystem_identity
            != COLLISION_SAFE_BATCH_RENAME_FILESYSTEM_IDENTITY
            or type(self.output_identity) is not str
            or self.output_identity != COLLISION_SAFE_BATCH_RENAME_OUTPUT_IDENTITY
            or type(self.allowed_tools) is not tuple
            or self.allowed_tools != COLLISION_SAFE_BATCH_RENAME_ALLOWED_TOOLS
            or any(type(tool) is not str for tool in self.allowed_tools)
            or type(self.split_role) is not str
            or self.split_role != METHOD_DEVELOPMENT_SPLIT
            or self.public is not True
            or self.sealed is not False
            or self.candidate_execution_authorized is not False
            or self.model_selection_eligible is not False
            or self.claim_authorized is not False
        ):
            raise CollisionSafeBatchRenameError("task metadata is invalid")
        expected = compute_collision_safe_batch_rename_task_sha256(
            self.parameters, self.prompt, self.graph
        )
        if (
            type(self.task_id) is not str
            or _TASK_ID_RE.fullmatch(self.task_id) is None
            or not _is_sha256(self.task_contract_sha256)
            or self.task_contract_sha256 != expected
            or self.task_id != task_id_from_contract(expected)
        ):
            raise CollisionSafeBatchRenameError("task identity is invalid")
        if (
            type(self.fixtures) is not tuple
            or len(self.fixtures) != len(PUBLIC_DEVELOPMENT_FIXTURE_PROFILES)
            or any(type(item) is not OpaqueFixtureDescriptor for item in self.fixtures)
        ):
            raise CollisionSafeBatchRenameError("task descriptors are invalid")
        for descriptor in self.fixtures:
            descriptor.__post_init__()
        if (
            len({item.fixture_id for item in self.fixtures})
            != len(PUBLIC_DEVELOPMENT_FIXTURE_PROFILES)
            or any(
                item.task_contract_sha256 != expected for item in self.fixtures
            )
        ):
            raise CollisionSafeBatchRenameError("descriptor binding is invalid")

    @property
    def graph_sha256(self) -> str:
        self.__post_init__()
        return self.graph.hash

    def to_public_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            **collision_safe_batch_rename_task_semantic_core(
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


def _bootstrap_task(
    parameters: CollisionSafeBatchRenameParameters,
) -> CollisionSafeBatchRenameTask:
    prompt, graph = _task_contract(parameters)
    digest = compute_collision_safe_batch_rename_task_sha256(
        parameters, prompt, graph
    )
    return CollisionSafeBatchRenameTask(
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
    mapped: str


def _profile_seeds(
    profile: ExecutableFixtureProfile,
) -> tuple[_FixtureSeed, ...]:
    profile_id = profile.profile_id
    duplicate = b"same\x00binary\xff\nwithout-text-assumption\r\n"
    if profile_id == "spaces-unicode":
        return (
            _FixtureSeed("Alpha Space/ReadMe.TXT", b"FIRST readme\n", 0o400, "mapped readme.txt"),
            _FixtureSeed("beta café/readme.txt", b"second README\n", 0o640, "mapped readme.txt"),
            _FixtureSeed("dupe one/dupe.bin", duplicate, 0o400, "mapped dupe.bin"),
            _FixtureSeed("dupe two/dupe.bin", duplicate, 0o640, "mapped dupe.bin"),
            _FixtureSeed("conflict one/conflict.bin", b"first conflict\n", 0o440, "mapped conflict.bin"),
            _FixtureSeed("conflict two/conflict.bin", b"last conflict!\n", 0o600, "mapped conflict.bin"),
            _FixtureSeed("stem one/report.tmp", b"temporary report\n", 0o444, "mapped report.txt"),
            _FixtureSeed("stem two/report.log", b"different report\n", 0o500, "mapped report.txt"),
            _FixtureSeed("unique/雪", b"unique snow\x00\n", 0o400, "mapped 雪"),
        )
    if profile_id == "leading-dashes-globs":
        return (
            _FixtureSeed("-one/-same[*]?.BIN", b"dash first\n", 0o400, "-mapped[*]?.bin"),
            _FixtureSeed("[two]*?/-same[*]?.BIN", b"dash second\n", 0o440, "-mapped[*]?.bin"),
            _FixtureSeed("dupe[1]/[dupe]*?.dat", duplicate, 0o400, "[mapped]*?.dat"),
            _FixtureSeed("dupe[2]/[dupe]*?.dat", duplicate, 0o500, "[mapped]*?.dat"),
            _FixtureSeed("stem?one/report.tmp", b"glob temp\n", 0o600, "report[*]?"),
            _FixtureSeed("stem?two/report.log", b"glob log!\n", 0o640, "report[*]?"),
            _FixtureSeed("unique*/-literal", b"unique\n", 0o444, "-unique[*]?"),
        )
    if profile_id == "empty-duplicates":
        full_domain = bytes(range(256))
        return (
            _FixtureSeed("empty one/empty.bin", b"", 0o400, "empty.out"),
            _FixtureSeed("empty two/empty.bin", b"", 0o600, "empty.out"),
            _FixtureSeed("binary one/binary.bin", full_domain, 0o440, "binary.out"),
            _FixtureSeed("binary two/binary.bin", full_domain, 0o500, "binary.out"),
            _FixtureSeed("equal one/equal.bin", b"A\x00B", 0o400, "equal.out"),
            _FixtureSeed("equal two/equal.bin", b"A\x01B", 0o640, "equal.out"),
            _FixtureSeed("newline one/final.dat", b"line\n", 0o444, "newline.out"),
            _FixtureSeed("newline two/final.dat", b"lineX", 0o600, "newline.out"),
            _FixtureSeed("unique/no-suffix", b"only\n", 0o400, "only.out"),
        )
    if profile_id == "symlinks-ordering":
        return (
            _FixtureSeed("ordered/Z-last.TXT", b"zulu\n", 0o400, "mapped-z.txt"),
            _FixtureSeed("ordered/a-first.log", b"alpha\n", 0o440, "mapped-a.log"),
            _FixtureSeed("ordered/café.bin", b"caf\xc3\xa9\x00\n", 0o500, "mapped-cafe.bin"),
            _FixtureSeed("separate/雪-data", b"snow\n", 0o640, "mapped-snow"),
        )
    if profile_id == "partial-permissions":
        return (
            _FixtureSeed("early/a.txt", b"early\n", 0o400, "early.out"),
            _FixtureSeed("middle/b.log", b"middle\n", 0o440, "middle.out"),
            _FixtureSeed("case one/Mode.TXT", b"mode first\n", 0o500, "case.out"),
            _FixtureSeed("case two/mode.txt", b"mode second\n", 0o640, "case.out"),
            _FixtureSeed("yy-one/same.dat", duplicate, 0o400, "same.out"),
            _FixtureSeed("yy-two/same.dat", duplicate, 0o750, "same.out"),
            _FixtureSeed("zz-one/late.bin", b"late first\n", 0o440, "late.out"),
            _FixtureSeed("zz-two/late.bin", b"late second\n", 0o500, "late.out"),
        )
    raise CollisionSafeBatchRenameError("unsupported fixture profile")


def _mapping_row(seed: _FixtureSeed) -> bytes:
    return f"{seed.relative}\t{seed.mapped}\n".encode("utf-8")


def _fixture_inputs(
    profile: ExecutableFixtureProfile,
) -> tuple[InputFile | InputSymlink, ...]:
    seeds = _profile_seeds(profile)
    rows = [_mapping_row(seed) for seed in seeds]
    if profile.profile_id == "empty-duplicates":
        rows.insert(1, rows[0])
    if profile.profile_id == "symlinks-ordering":
        rows.reverse()
    mapping_mode = 0o400 if profile.profile_id == "partial-permissions" else 0o444
    values: list[InputFile | InputSymlink] = [
        InputFile(COLLISION_SAFE_BATCH_RENAME_MAPPING, b"".join(rows), mapping_mode)
    ]
    values.extend(
        InputFile(
            (COLLISION_SAFE_BATCH_RENAME_CANDIDATE_ROOT / seed.relative).as_posix(),
            seed.content,
            seed.mode,
        )
        for seed in seeds
    )
    if profile.profile_id == "spaces-unicode":
        values.append(InputFile("input/rename/unlisted snow 雪.txt", b"ignore\n", 0o444))
    elif profile.profile_id == "leading-dashes-globs":
        values.append(InputFile("input/rename/-unlisted[*]?.txt", b"ignore\n", 0o400))
    elif profile.profile_id == "empty-duplicates":
        values.append(InputFile("input/rename/unlisted-empty", b"", 0o400))
    elif profile.profile_id == "symlinks-ordering":
        values.extend(
            (
                InputSymlink(
                    "input/rename/candidates/ordered/link.TXT",
                    "Z-last.TXT",
                ),
                InputSymlink(
                    "input/rename/candidates/ordered/dangling[*]?",
                    "missing.bin",
                ),
            )
        )
        values.reverse()
    elif profile.profile_id == "partial-permissions":
        values.extend(
            (
                InputFile("input/rename/unlisted-denied.bin", b"ignore\n", 0o000),
                InputSymlink(
                    "input/rename/candidates/early/unlisted-link.txt",
                    "a.txt",
                ),
            )
        )
    return tuple(values)


@dataclass(frozen=True, slots=True)
class _Candidate:
    source: str
    relative: str
    content: bytes = field(repr=False)
    mode: int


def _revalidate_definition(definition: object) -> FixtureDefinition:
    if type(definition) is not FixtureDefinition:
        raise CollisionSafeBatchRenameError("definition has wrong exact type")
    try:
        inputs = tuple(
            InputFile(item.path, item.content, item.mode)
            if type(item) is InputFile
            else InputSymlink(item.path, item.target)
            if type(item) is InputSymlink
            else (_ for _ in ()).throw(
                CollisionSafeBatchRenameError("input has wrong exact type")
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
        CollisionSafeBatchRenameError,
        TypeError,
        ValueError,
    ) as exc:
        raise CollisionSafeBatchRenameError(
            "definition reconstruction failed"
        ) from exc
    if rebuilt != definition:
        raise CollisionSafeBatchRenameError("definition differs on reconstruction")
    return definition


def _parse_primary(
    definition: FixtureDefinition,
) -> tuple[tuple[_Candidate, ...], dict[str, str]]:
    selected = _revalidate_definition(definition)
    prefix = COLLISION_SAFE_BATCH_RENAME_CANDIDATE_ROOT.as_posix() + "/"
    candidates: list[_Candidate] = []
    mapping_file: InputFile | None = None
    for item in selected.inputs:
        if type(item) is InputFile and item.path == COLLISION_SAFE_BATCH_RENAME_MAPPING:
            mapping_file = item
        elif type(item) is InputFile and item.path.startswith(prefix):
            relative = item.path[len(prefix):]
            _validate_relative_source(relative)
            if (
                item.mode & 0o400 == 0
                or len(item.content)
                > COLLISION_SAFE_BATCH_RENAME_CANDIDATE_MAXIMUM_BYTES
            ):
                raise CollisionSafeBatchRenameError("candidate outside input domain")
            candidates.append(_Candidate(item.path, relative, item.content, item.mode))
    candidates.sort(key=lambda item: _raw_key(item.relative))
    if (
        mapping_file is None
        or len(candidates) > COLLISION_SAFE_BATCH_RENAME_MAXIMUM_CANDIDATES
    ):
        raise CollisionSafeBatchRenameError("candidate domain is invalid")
    raw = mapping_file.content
    if (
        len(raw) > COLLISION_SAFE_BATCH_RENAME_MAPPING_MAXIMUM_BYTES
        or (raw and not raw.endswith(b"\n"))
    ):
        raise CollisionSafeBatchRenameError("mapping framing is invalid")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise CollisionSafeBatchRenameError("mapping is not UTF-8") from exc
    rows = [] if not text else text[:-1].split("\n")
    if len(rows) > COLLISION_SAFE_BATCH_RENAME_MAXIMUM_MAPPING_ROWS:
        raise CollisionSafeBatchRenameError("mapping has too many rows")
    mapping: dict[str, str] = {}
    logical: set[tuple[str, str]] = set()
    for row in rows:
        fields = row.split("\t")
        if len(fields) != 2:
            raise CollisionSafeBatchRenameError("mapping row is malformed")
        source = _validate_relative_source(fields[0])
        destination = _validate_basename(fields[1])
        pair = (source, destination)
        if pair in logical:
            continue
        logical.add(pair)
        previous = mapping.get(source)
        if previous is not None and previous != destination:
            raise CollisionSafeBatchRenameError("mapping source conflicts")
        mapping[source] = destination
    if set(mapping) != {candidate.relative for candidate in candidates}:
        raise CollisionSafeBatchRenameError("mapping is not total and exact")
    return tuple(candidates), mapping


def _ascii_lower_primary(value: str) -> str:
    return "".join(
        chr(ord(character) + 32)
        if "A" <= character <= "Z"
        else character
        for character in value
    )


def _destinations_primary(
    candidates: tuple[_Candidate, ...],
    mapping: dict[str, str],
    rename_rule: RenameRule,
) -> dict[str, str]:
    result: dict[str, str] = {}
    ranks: dict[str, int] = {}
    if rename_rule == "numbered-prefix":
        by_parent: dict[str, list[str]] = {}
        for candidate in candidates:
            parent, _separator, basename = candidate.relative.rpartition("/")
            by_parent.setdefault(parent, []).append(basename)
        for parent, basenames in by_parent.items():
            for index, basename in enumerate(sorted(basenames, key=_raw_key), 1):
                ranks[f"{parent}\0{basename}"] = index
    for candidate in candidates:
        basename = candidate.relative.rsplit("/", 1)[-1]
        if rename_rule == "lowercase-basename":
            destination = _ascii_lower_primary(basename)
        elif rename_rule == "numbered-prefix":
            parent = candidate.relative.rpartition("/")[0]
            destination = (
                f"{ranks[f'{parent}{chr(0)}{basename}']:04d}-{basename}"
            )
        elif rename_rule == "suffix-rewrite":
            dot = basename.rfind(".")
            destination = (
                basename[:dot] + ".ready"
                if 0 < dot < len(basename) - 1
                else basename + ".ready"
            )
        elif rename_rule == "manifest-mapping":
            destination = mapping[candidate.relative]
        else:
            raise CollisionSafeBatchRenameError("unknown rename rule")
        result[candidate.source] = _validate_basename(destination)
    return result


@dataclass(frozen=True, slots=True)
class CollisionSafeBatchRenameAction:
    source: str
    destination: str
    output_path: str
    outcome: RenameOutcome
    representative: str
    group_size: int

    def __post_init__(self) -> None:
        if type(self) is not CollisionSafeBatchRenameAction:
            raise CollisionSafeBatchRenameError("action has wrong exact type")
        prefix = COLLISION_SAFE_BATCH_RENAME_CANDIDATE_ROOT.as_posix() + "/"
        if type(self.source) is not str or not self.source.startswith(prefix):
            raise CollisionSafeBatchRenameError("action source is invalid")
        _validate_relative_source(self.source[len(prefix):])
        _validate_basename(self.destination)
        expected_output = (
            COLLISION_SAFE_BATCH_RENAME_OUTPUT_ROOT / self.destination
        ).as_posix()
        if type(self.output_path) is not str or self.output_path != expected_output:
            raise CollisionSafeBatchRenameError("action output path is invalid")
        _closed_text(self.outcome, _OUTCOMES, "outcome")
        if (
            type(self.representative) is not str
            or (
                self.representative
                and not self.representative.startswith(prefix)
            )
            or type(self.group_size) is not int
            or not 1 <= self.group_size <= COLLISION_SAFE_BATCH_RENAME_MAXIMUM_CANDIDATES
        ):
            raise CollisionSafeBatchRenameError("action metadata is invalid")
        if self.representative:
            _validate_relative_source(self.representative[len(prefix):])
        representative_required = self.outcome in {
            "moved",
            "coalesced",
            "retained-loser",
        }
        if representative_required != bool(self.representative):
            raise CollisionSafeBatchRenameError(
                "action representative presence differs from outcome"
            )
        if self.outcome == "moved" and self.representative != self.source:
            raise CollisionSafeBatchRenameError(
                "moved action must name itself as representative"
            )
        if self.outcome in {"coalesced", "retained-loser"} and (
            self.representative == self.source or self.group_size < 2
        ):
            raise CollisionSafeBatchRenameError(
                "nonwinner action has invalid representative or group size"
            )

    def commitment_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "source": self.source,
            "destination": self.destination,
            "output_path": self.output_path,
            "outcome": self.outcome,
            "representative": self.representative,
            "group_size": self.group_size,
        }


def _primary_action(
    candidate: _Candidate,
    destination: str,
    outcome: RenameOutcome,
    representative: str,
    group_size: int,
) -> CollisionSafeBatchRenameAction:
    return CollisionSafeBatchRenameAction(
        source=candidate.source,
        destination=destination,
        output_path=(
            COLLISION_SAFE_BATCH_RENAME_OUTPUT_ROOT / destination
        ).as_posix(),
        outcome=outcome,
        representative=representative,
        group_size=group_size,
    )


def _serialize_primary(
    actions: tuple[CollisionSafeBatchRenameAction, ...],
    collision_groups: int,
    rejected: bool,
) -> bytes:
    destination_count = sum(action.outcome == "moved" for action in actions)
    removed = sum(action.outcome in _REMOVED_OUTCOMES for action in actions)
    rows = [
        (
            "batch\t"
            + ("rejected" if rejected else "complete")
            + f"\t{len(actions)}\t{collision_groups}\t{destination_count}"
            + f"\t{removed}\t{len(actions) - removed}\n"
        ).encode("ascii")
    ]
    for action in actions:
        rows.append(
            (
                f"file\t{action.outcome}\t{action.source}\t"
                f"{action.destination}\t{action.representative}\t"
                f"{action.group_size}\n"
            ).encode("utf-8")
        )
    return b"".join(rows)


def derive_collision_safe_batch_rename_state(
    definition: FixtureDefinition,
    parameters: CollisionSafeBatchRenameParameters,
) -> tuple[
    tuple[CollisionSafeBatchRenameAction, ...],
    tuple[OracleOutputRecord, ...],
]:
    """Primary dictionary/group semantic implementation."""

    if type(parameters) is not CollisionSafeBatchRenameParameters:
        raise CollisionSafeBatchRenameError("primary parameters are invalid")
    parameters.__post_init__()
    candidates, mapping = _parse_primary(definition)
    destination_by_source = _destinations_primary(
        candidates, mapping, parameters.rename_rule
    )
    by_destination: dict[str, list[_Candidate]] = {}
    for candidate in candidates:
        by_destination.setdefault(
            destination_by_source[candidate.source], []
        ).append(candidate)
    for group in by_destination.values():
        group.sort(key=lambda item: _raw_key(item.relative))
    collision_groups = sum(len(group) > 1 for group in by_destination.values())
    rejected = (
        parameters.collision_policy == "reject-all"
        and collision_groups > 0
    )
    actions: list[CollisionSafeBatchRenameAction] = []
    representatives: dict[str, _Candidate] = {}
    for destination in sorted(by_destination, key=_raw_key):
        group = by_destination[destination]
        size = len(group)
        if rejected:
            for candidate in group:
                actions.append(
                    _primary_action(
                        candidate, destination, "retained-rejected", "", size
                    )
                )
            continue
        if size == 1:
            representative = group[0]
            representatives[destination] = representative
            actions.append(
                _primary_action(
                    representative,
                    destination,
                    "moved",
                    representative.source,
                    1,
                )
            )
            continue
        if parameters.collision_policy == "skip-collisions":
            for candidate in group:
                actions.append(
                    _primary_action(
                        candidate, destination, "retained-collision", "", size
                    )
                )
        elif parameters.collision_policy in {"stable-first", "stable-last"}:
            winner = (
                group[0]
                if parameters.collision_policy == "stable-first"
                else group[-1]
            )
            representatives[destination] = winner
            for candidate in group:
                actions.append(
                    _primary_action(
                        candidate,
                        destination,
                        "moved" if candidate is winner else "retained-loser",
                        winner.source,
                        size,
                    )
                )
        elif parameters.collision_policy == "identical-files-coalesce":
            representative = group[0]
            if all(item.content == representative.content for item in group[1:]):
                representatives[destination] = representative
                for candidate in group:
                    actions.append(
                        _primary_action(
                            candidate,
                            destination,
                            "moved"
                            if candidate is representative
                            else "coalesced",
                            representative.source,
                            size,
                        )
                    )
            else:
                for candidate in group:
                    actions.append(
                        _primary_action(
                            candidate,
                            destination,
                            "retained-nonidentical",
                            "",
                            size,
                        )
                    )
        else:
            raise CollisionSafeBatchRenameError("primary policy is invalid")
    actions.sort(key=lambda action: _raw_key(action.source))
    selected_actions = tuple(actions)
    candidate_by_source = {candidate.source: candidate for candidate in candidates}
    outputs: list[OracleOutputRecord] = [
        OracleOutputRecord(
            COLLISION_SAFE_BATCH_RENAME_LEDGER_OUTPUT,
            _serialize_primary(selected_actions, collision_groups, rejected),
            COLLISION_SAFE_BATCH_RENAME_LEDGER_MODE,
        )
    ]
    for destination in sorted(representatives, key=_raw_key):
        representative = candidate_by_source[representatives[destination].source]
        outputs.append(
            OracleOutputRecord(
                (
                    COLLISION_SAFE_BATCH_RENAME_OUTPUT_ROOT / destination
                ).as_posix(),
                representative.content,
                representative.mode,
            )
        )
    outputs.sort(key=lambda output: _raw_key(output.path))
    selected_outputs = tuple(outputs)
    if (
        definition.expected_files
        and definition.expected_files != _expected_output_policy(selected_outputs)
    ):
        raise CollisionSafeBatchRenameError("primary output policy differs")
    return selected_actions, selected_outputs


def _reference_parse(
    definition: FixtureDefinition,
) -> tuple[list[tuple[str, str, bytes, int]], list[tuple[str, str]]]:
    """Independent tuple/list parser for the reference engine."""

    selected = _revalidate_definition(definition)
    prefix = "input/rename/candidates/"
    raw_mapping: bytes | None = None
    candidate_values: list[tuple[str, str, bytes, int]] = []
    for entry in selected.inputs:
        if type(entry) is not InputFile:
            continue
        if entry.path == "input/rename/mapping.tsv":
            raw_mapping = entry.content
        elif entry.path[: len(prefix)] == prefix:
            relative = entry.path[len(prefix):]
            _validate_relative_source(relative)
            if (
                entry.mode & 256 == 0
                or len(entry.content)
                > COLLISION_SAFE_BATCH_RENAME_CANDIDATE_MAXIMUM_BYTES
            ):
                raise CollisionSafeBatchRenameError("reference candidate invalid")
            candidate_values.append(
                (entry.path, relative, bytes(entry.content), entry.mode)
            )
    candidate_values = sorted(
        candidate_values, key=lambda value: value[1].encode("utf-8")
    )
    if (
        raw_mapping is None
        or len(candidate_values) > COLLISION_SAFE_BATCH_RENAME_MAXIMUM_CANDIDATES
        or len(raw_mapping) > COLLISION_SAFE_BATCH_RENAME_MAPPING_MAXIMUM_BYTES
        or (raw_mapping != b"" and raw_mapping[-1] != 10)
    ):
        raise CollisionSafeBatchRenameError("reference input framing invalid")
    try:
        mapping_text = raw_mapping.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise CollisionSafeBatchRenameError("reference mapping decode failed") from exc
    physical = [] if mapping_text == "" else mapping_text[:-1].split("\n")
    if len(physical) > COLLISION_SAFE_BATCH_RENAME_MAXIMUM_MAPPING_ROWS:
        raise CollisionSafeBatchRenameError("reference mapping row limit")
    logical: list[tuple[str, str]] = []
    for row in physical:
        if row.count("\t") != 1:
            raise CollisionSafeBatchRenameError("reference mapping row invalid")
        source, destination = row.split("\t")
        _validate_relative_source(source)
        _validate_basename(destination)
        pair = (source, destination)
        if pair not in logical:
            logical.append(pair)
    by_source: dict[str, str] = {}
    for source, destination in logical:
        previous = by_source.setdefault(source, destination)
        if previous != destination:
            raise CollisionSafeBatchRenameError("reference mapping conflict")
    if sorted(by_source, key=str.encode) != [
        value[1] for value in candidate_values
    ]:
        raise CollisionSafeBatchRenameError("reference mapping coverage differs")
    return candidate_values, sorted(logical, key=lambda value: value[0].encode("utf-8"))


def _reference_ascii_lower(value: str) -> str:
    result: list[str] = []
    for character in value:
        codepoint = ord(character)
        result.append(chr(codepoint + 32) if 65 <= codepoint <= 90 else character)
    return "".join(result)


def _reference_destinations(
    candidates: list[tuple[str, str, bytes, int]],
    mapping_rows: list[tuple[str, str]],
    rule: RenameRule,
) -> list[tuple[str, str, bytes, int, str]]:
    mapping = {source: destination for source, destination in mapping_rows}
    local_order: dict[tuple[str, str], int] = {}
    parents = sorted(
        {relative.rpartition("/")[0] for _source, relative, _content, _mode in candidates},
        key=str.encode,
    )
    for parent in parents:
        names = [
            relative.rpartition("/")[2]
            for _source, relative, _content, _mode in candidates
            if relative.rpartition("/")[0] == parent
        ]
        names.sort(key=str.encode)
        for position, name in enumerate(names, 1):
            local_order[(parent, name)] = position
    result: list[tuple[str, str, bytes, int, str]] = []
    for source, relative, content, mode in candidates:
        parent, _separator, basename = relative.rpartition("/")
        if rule == "lowercase-basename":
            destination = _reference_ascii_lower(basename)
        elif rule == "numbered-prefix":
            destination = "%04d-%s" % (local_order[(parent, basename)], basename)
        elif rule == "suffix-rewrite":
            last_dot = -1
            for position, character in enumerate(basename):
                if character == ".":
                    last_dot = position
            if last_dot > 0 and last_dot < len(basename) - 1:
                destination = basename[:last_dot] + ".ready"
            else:
                destination = basename + ".ready"
        elif rule == "manifest-mapping":
            destination = mapping[relative]
        else:
            raise CollisionSafeBatchRenameError("reference rule invalid")
        _validate_basename(destination)
        result.append((source, relative, content, mode, destination))
    return result


def _reference_ledger(
    actions: list[CollisionSafeBatchRenameAction],
    collisions: int,
    rejected: bool,
) -> bytes:
    moved_destinations = 0
    removed_sources = 0
    for action in actions:
        if action.outcome == "moved":
            moved_destinations += 1
        if action.outcome == "moved" or action.outcome == "coalesced":
            removed_sources += 1
    buffer = bytearray()
    buffer.extend(b"batch\t")
    buffer.extend(b"rejected" if rejected else b"complete")
    for number in (
        len(actions),
        collisions,
        moved_destinations,
        removed_sources,
        len(actions) - removed_sources,
    ):
        buffer.extend(b"\t")
        buffer.extend(str(number).encode("ascii"))
    buffer.extend(b"\n")
    for action in actions:
        fields = (
            "file",
            action.outcome,
            action.source,
            action.destination,
            action.representative,
            str(action.group_size),
        )
        buffer.extend("\t".join(fields).encode("utf-8"))
        buffer.extend(b"\n")
    return bytes(buffer)


def reference_collision_safe_batch_rename_state(
    definition: FixtureDefinition,
    parameters: CollisionSafeBatchRenameParameters,
) -> tuple[
    tuple[CollisionSafeBatchRenameAction, ...],
    tuple[OracleOutputRecord, ...],
]:
    """Reference sorted-stream/groupby semantic implementation."""

    if type(parameters) is not CollisionSafeBatchRenameParameters:
        raise CollisionSafeBatchRenameError("reference parameters are invalid")
    parameters.__post_init__()
    candidates, mapping_rows = _reference_parse(definition)
    classified = _reference_destinations(
        candidates, mapping_rows, parameters.rename_rule
    )
    ordered = sorted(
        classified,
        key=lambda item: (item[4].encode("utf-8"), item[1].encode("utf-8")),
    )
    grouped = [
        (destination, list(values))
        for destination, values in groupby(ordered, key=lambda item: item[4])
    ]
    collisions = sum(len(values) > 1 for _destination, values in grouped)
    rejected = parameters.collision_policy == "reject-all" and collisions != 0
    action_values: list[CollisionSafeBatchRenameAction] = []
    output_representatives: list[tuple[str, tuple[str, str, bytes, int, str]]] = []
    for destination, values in grouped:
        size = len(values)
        winner: tuple[str, str, bytes, int, str] | None = None
        outcomes: list[tuple[tuple[str, str, bytes, int, str], RenameOutcome, str]] = []
        if rejected:
            outcomes = [(value, "retained-rejected", "") for value in values]
        elif size == 1:
            winner = values[0]
            outcomes = [(winner, "moved", winner[0])]
        elif parameters.collision_policy == "skip-collisions":
            outcomes = [(value, "retained-collision", "") for value in values]
        elif parameters.collision_policy == "stable-first":
            winner = values[0]
            outcomes = [
                (
                    value,
                    "moved" if value[0] == winner[0] else "retained-loser",
                    winner[0],
                )
                for value in values
            ]
        elif parameters.collision_policy == "stable-last":
            winner = values[-1]
            outcomes = [
                (
                    value,
                    "moved" if value[0] == winner[0] else "retained-loser",
                    winner[0],
                )
                for value in values
            ]
        elif parameters.collision_policy == "identical-files-coalesce":
            first_bytes = values[0][2]
            identical = True
            for value in values[1:]:
                if len(value[2]) != len(first_bytes) or any(
                    left != right for left, right in zip(value[2], first_bytes)
                ):
                    identical = False
                    break
            if identical:
                winner = values[0]
                outcomes = [
                    (
                        value,
                        "moved" if value[0] == winner[0] else "coalesced",
                        winner[0],
                    )
                    for value in values
                ]
            else:
                outcomes = [
                    (value, "retained-nonidentical", "") for value in values
                ]
        else:
            raise CollisionSafeBatchRenameError("reference policy invalid")
        if winner is not None:
            output_representatives.append((destination, winner))
        for value, outcome, representative in outcomes:
            action_values.append(
                CollisionSafeBatchRenameAction(
                    source=value[0],
                    destination=destination,
                    output_path=(
                        COLLISION_SAFE_BATCH_RENAME_OUTPUT_ROOT / destination
                    ).as_posix(),
                    outcome=outcome,
                    representative=representative,
                    group_size=size,
                )
            )
    action_values.sort(key=lambda action: action.source.encode("utf-8"))
    outputs: list[OracleOutputRecord] = [
        OracleOutputRecord(
            COLLISION_SAFE_BATCH_RENAME_LEDGER_OUTPUT,
            _reference_ledger(action_values, collisions, rejected),
            COLLISION_SAFE_BATCH_RENAME_LEDGER_MODE,
        )
    ]
    for destination, value in sorted(
        output_representatives, key=lambda item: item[0].encode("utf-8")
    ):
        outputs.append(
            OracleOutputRecord(
                (
                    COLLISION_SAFE_BATCH_RENAME_OUTPUT_ROOT / destination
                ).as_posix(),
                value[2],
                value[3],
            )
        )
    outputs.sort(key=lambda output: output.path.encode("utf-8"))
    selected = (tuple(action_values), tuple(outputs))
    if (
        definition.expected_files
        and definition.expected_files != _expected_output_policy(selected[1])
    ):
        raise CollisionSafeBatchRenameError("reference output policy differs")
    return selected


def verify_collision_safe_batch_rename_state(
    definition: FixtureDefinition,
    parameters: CollisionSafeBatchRenameParameters,
    candidate_actions: object,
    candidate_outputs: object,
) -> bool:
    if (
        type(candidate_actions) is not tuple
        or any(
            type(action) is not CollisionSafeBatchRenameAction
            for action in candidate_actions
        )
        or type(candidate_outputs) is not tuple
        or any(type(output) is not OracleOutputRecord for output in candidate_outputs)
    ):
        return False
    try:
        primary = derive_collision_safe_batch_rename_state(definition, parameters)
        reference = reference_collision_safe_batch_rename_state(
            definition, parameters
        )
    except (CollisionSafeBatchRenameError, TypeError, ValueError):
        return False
    return primary == reference == (candidate_actions, candidate_outputs)


def _expected_output_policy(
    outputs: tuple[OracleOutputRecord, ...],
) -> tuple[ExpectedFile, ...]:
    return tuple(
        ExpectedFile(
            output.path,
            (
                COLLISION_SAFE_BATCH_RENAME_OUTPUT_MAXIMUM_BYTES
                if output.path == COLLISION_SAFE_BATCH_RENAME_LEDGER_OUTPUT
                else COLLISION_SAFE_BATCH_RENAME_CANDIDATE_MAXIMUM_BYTES
            ),
            output.mode,
        )
        for output in outputs
    )


def _compute_oracle_sha256(
    actions: tuple[CollisionSafeBatchRenameAction, ...],
    outputs: tuple[OracleOutputRecord, ...],
) -> str:
    if (
        type(actions) is not tuple
        or any(type(action) is not CollisionSafeBatchRenameAction for action in actions)
        or tuple(sorted(actions, key=lambda action: action.source.encode("utf-8")))
        != actions
        or len({action.source for action in actions}) != len(actions)
        or type(outputs) is not tuple
        or not outputs
        or any(type(output) is not OracleOutputRecord for output in outputs)
        or tuple(sorted(outputs, key=lambda output: output.path.encode("utf-8")))
        != outputs
        or len({output.path for output in outputs}) != len(outputs)
        or COLLISION_SAFE_BATCH_RENAME_LEDGER_OUTPUT
        not in {output.path for output in outputs}
    ):
        raise CollisionSafeBatchRenameError("oracle contents are noncanonical")
    for action in actions:
        action.__post_init__()
    for output in outputs:
        output.__post_init__()
        maximum = (
            COLLISION_SAFE_BATCH_RENAME_OUTPUT_MAXIMUM_BYTES
            if output.path == COLLISION_SAFE_BATCH_RENAME_LEDGER_OUTPUT
            else COLLISION_SAFE_BATCH_RENAME_CANDIDATE_MAXIMUM_BYTES
        )
        if len(output.content) > maximum:
            raise CollisionSafeBatchRenameError("oracle output exceeds bound")
    return domain_sha256(
        "cbds.executable-fixture.trusted-oracle.v1",
        {
            "schema_version": EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION,
            "semantic_verifier_identity": (
                COLLISION_SAFE_BATCH_RENAME_VERIFIER_IDENTITY
            ),
            "actions": [action.commitment_record() for action in actions],
            "outputs": [output.commitment_record() for output in outputs],
        },
    )


@dataclass(frozen=True, slots=True)
class CollisionSafeBatchRenameOracle:
    actions: tuple[CollisionSafeBatchRenameAction, ...]
    outputs: tuple[OracleOutputRecord, ...]
    oracle_sha256: str
    semantic_verifier_identity: str = (
        COLLISION_SAFE_BATCH_RENAME_VERIFIER_IDENTITY
    )
    schema_version: str = EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            type(self) is not CollisionSafeBatchRenameOracle
            or type(self.semantic_verifier_identity) is not str
            or self.semantic_verifier_identity
            != COLLISION_SAFE_BATCH_RENAME_VERIFIER_IDENTITY
            or type(self.schema_version) is not str
            or self.schema_version != EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION
            or not _is_sha256(self.oracle_sha256)
            or self.oracle_sha256
            != _compute_oracle_sha256(self.actions, self.outputs)
        ):
            raise CollisionSafeBatchRenameError("oracle identity is invalid")

    def commitment_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "schema_version": self.schema_version,
            "record_type": "cbds.executable-fixture-trusted-oracle",
            "semantic_verifier_identity": self.semantic_verifier_identity,
            "actions": [action.commitment_record() for action in self.actions],
            "outputs": [output.commitment_record() for output in self.outputs],
            "oracle_sha256": self.oracle_sha256,
        }


@dataclass(frozen=True, slots=True)
class CollisionSafeBatchRenameFixtureBundle:
    task_contract_sha256: str
    profile_sha256: str
    definition: FixtureDefinition = field(repr=False)
    fixture_definition_sha256: str
    oracle: CollisionSafeBatchRenameOracle = field(repr=False)
    descriptor: OpaqueFixtureDescriptor
    schema_version: str = EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_collision_safe_batch_rename_fixture_bundle(self)

    def to_opaque_descriptor(self) -> OpaqueFixtureDescriptor:
        validate_collision_safe_batch_rename_fixture_bundle(self)
        return self.descriptor

    def commitment_record(self) -> dict[str, object]:
        validate_collision_safe_batch_rename_fixture_bundle(self)
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


def validate_collision_safe_batch_rename_fixture_bundle(
    bundle: CollisionSafeBatchRenameFixtureBundle,
) -> None:
    if type(bundle) is not CollisionSafeBatchRenameFixtureBundle:
        raise CollisionSafeBatchRenameError("bundle has wrong exact type")
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
        raise CollisionSafeBatchRenameError("bundle metadata is invalid")
    definition = _revalidate_definition(bundle.definition)
    definition_sha256 = compute_fixture_definition_semantic_sha256(definition)
    if bundle.fixture_definition_sha256 != definition_sha256:
        raise CollisionSafeBatchRenameError("definition digest is invalid")
    if type(bundle.oracle) is not CollisionSafeBatchRenameOracle:
        raise CollisionSafeBatchRenameError("oracle has wrong exact type")
    bundle.oracle.__post_init__()
    if definition.expected_files != _expected_output_policy(bundle.oracle.outputs):
        raise CollisionSafeBatchRenameError("output policy does not bind oracle")
    if type(bundle.descriptor) is not OpaqueFixtureDescriptor:
        raise CollisionSafeBatchRenameError("descriptor has wrong exact type")
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
        raise CollisionSafeBatchRenameError("descriptor binding is invalid")


def verify_collision_safe_batch_rename_fixture_bundle(bundle: object) -> bool:
    try:
        validate_collision_safe_batch_rename_fixture_bundle(bundle)  # type: ignore[arg-type]
    except (CollisionSafeBatchRenameError, TypeError, ValueError):
        return False
    return True


def _validate_task_profile(
    task: object,
    profile: object,
) -> tuple[CollisionSafeBatchRenameTask, ExecutableFixtureProfile]:
    if type(task) is not CollisionSafeBatchRenameTask:
        raise CollisionSafeBatchRenameError("task has wrong exact type")
    if type(profile) is not ExecutableFixtureProfile:
        raise CollisionSafeBatchRenameError("profile has wrong exact type")
    try:
        task.__post_init__()
        CollisionSafeBatchRenameParameters(
            task.parameters.rename_rule,
            task.parameters.collision_policy,
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
        raise CollisionSafeBatchRenameError("task/profile revalidation failed") from exc
    if rebuilt_profile not in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
        raise CollisionSafeBatchRenameError("profile is not public development")
    return task, profile


def _construct_collision_safe_batch_rename_fixture_bundle(
    task: CollisionSafeBatchRenameTask,
    profile: ExecutableFixtureProfile,
) -> CollisionSafeBatchRenameFixtureBundle:
    selected_task, selected_profile = _validate_task_profile(task, profile)
    inputs = _fixture_inputs(selected_profile)
    provisional = FixtureDefinition(
        f"fixture.{selected_task.task_id}.{selected_profile.profile_id}",
        inputs,
        (),
    )
    primary = derive_collision_safe_batch_rename_state(
        provisional, selected_task.parameters
    )
    reference = reference_collision_safe_batch_rename_state(
        provisional, selected_task.parameters
    )
    if primary != reference:
        raise CollisionSafeBatchRenameError("independent state engines disagree")
    definition = FixtureDefinition(
        provisional.fixture_id,
        inputs,
        _expected_output_policy(primary[1]),
    )
    if (
        derive_collision_safe_batch_rename_state(
            definition, selected_task.parameters
        )
        != primary
        or reference_collision_safe_batch_rename_state(
            definition, selected_task.parameters
        )
        != reference
    ):
        raise CollisionSafeBatchRenameError("final output policy changed state")
    oracle = CollisionSafeBatchRenameOracle(
        primary[0],
        primary[1],
        _compute_oracle_sha256(primary[0], primary[1]),
    )
    definition_sha256 = compute_fixture_definition_semantic_sha256(definition)
    fixture_sha256 = compute_bound_fixture_sha256(
        task_contract_sha256=selected_task.task_contract_sha256,
        profile_sha256=selected_profile.profile_sha256,
        fixture_definition_sha256=definition_sha256,
        oracle_sha256=oracle.oracle_sha256,
    )
    return CollisionSafeBatchRenameFixtureBundle(
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


def build_collision_safe_batch_rename_fixture_bundle(
    task: CollisionSafeBatchRenameTask,
    profile: ExecutableFixtureProfile,
) -> CollisionSafeBatchRenameFixtureBundle:
    bundle = _construct_collision_safe_batch_rename_fixture_bundle(task, profile)
    validate_collision_safe_batch_rename_fixture_for_task_profile(
        task, profile, bundle
    )
    return bundle


def validate_collision_safe_batch_rename_fixture_for_task_profile(
    task: CollisionSafeBatchRenameTask,
    profile: ExecutableFixtureProfile,
    bundle: CollisionSafeBatchRenameFixtureBundle,
) -> None:
    selected_task, selected_profile = _validate_task_profile(task, profile)
    validate_collision_safe_batch_rename_fixture_bundle(bundle)
    if (
        bundle.task_contract_sha256 != selected_task.task_contract_sha256
        or bundle.profile_sha256 != selected_profile.profile_sha256
    ):
        raise CollisionSafeBatchRenameError("bundle binding differs")
    index = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES.index(selected_profile)
    if selected_task.fixtures[index] != bundle.descriptor:
        raise CollisionSafeBatchRenameError("public descriptor differs")
    rebuilt = _construct_collision_safe_batch_rename_fixture_bundle(
        selected_task, selected_profile
    )
    if rebuilt != bundle:
        raise CollisionSafeBatchRenameError("bundle differs from reconstruction")


def verify_collision_safe_batch_rename_fixture_for_task_profile(
    task: object,
    profile: object,
    bundle: object,
) -> bool:
    try:
        validate_collision_safe_batch_rename_fixture_for_task_profile(
            task,  # type: ignore[arg-type]
            profile,  # type: ignore[arg-type]
            bundle,  # type: ignore[arg-type]
        )
    except (CollisionSafeBatchRenameError, TypeError, ValueError):
        return False
    return True


def build_collision_safe_batch_rename_tasks() -> tuple[
    CollisionSafeBatchRenameTask, ...
]:
    tasks: list[CollisionSafeBatchRenameTask] = []
    for rename_rule in COLLISION_SAFE_BATCH_RENAME_RENAME_RULES:
        for collision_policy in COLLISION_SAFE_BATCH_RENAME_COLLISION_POLICIES:
            bootstrap = _bootstrap_task(
                CollisionSafeBatchRenameParameters(
                    rename_rule, collision_policy
                )
            )
            descriptors = tuple(
                _construct_collision_safe_batch_rename_fixture_bundle(
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
        raise CollisionSafeBatchRenameError("task grid is not 20 unique tasks")
    return selected


def materialize_collision_safe_batch_rename_fixture(
    task: CollisionSafeBatchRenameTask,
    profile: ExecutableFixtureProfile,
    bundle: CollisionSafeBatchRenameFixtureBundle,
    workspace: str | os.PathLike[str],
) -> WorkspaceHandle:
    validate_collision_safe_batch_rename_fixture_for_task_profile(
        task, profile, bundle
    )
    return materialize_fixture(bundle.definition, workspace)


def _input_state_matches_plan(
    input_scan_entries: tuple[WorkspaceEntry, ...],
    baseline_entries: tuple[WorkspaceEntry, ...],
    actions: tuple[CollisionSafeBatchRenameAction, ...],
) -> bool:
    removed = {
        action.source
        for action in actions
        if action.outcome in _REMOVED_OUTCOMES
    }
    baseline_by_path = {entry.path: entry for entry in baseline_entries}
    observed_by_path = {entry.path: entry for entry in input_scan_entries}
    if set(observed_by_path) != set(baseline_by_path) - removed:
        return False
    for path, expected in baseline_by_path.items():
        if path in removed:
            continue
        observed = observed_by_path[path]
        if expected.kind == "directory":
            if (
                observed.kind != "directory"
                or observed.mode != expected.mode
                or observed.link_count != expected.link_count
            ):
                return False
        elif observed != expected:
            return False
    return True


def verify_collision_safe_batch_rename_workspace(
    task: CollisionSafeBatchRenameTask,
    profile: ExecutableFixtureProfile,
    bundle: CollisionSafeBatchRenameFixtureBundle,
    handle: WorkspaceHandle,
) -> bool:
    """Verify the exact quiescent final state and representative metadata."""

    if type(handle) is not WorkspaceHandle:
        return False
    try:
        validate_collision_safe_batch_rename_fixture_for_task_profile(
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
        primary = derive_collision_safe_batch_rename_state(
            bundle.definition, task.parameters
        )
        reference = reference_collision_safe_batch_rename_state(
            bundle.definition, task.parameters
        )
        if not (
            primary
            == reference
            == (bundle.oracle.actions, bundle.oracle.outputs)
        ):
            return False
        input_scan = handle.scan_inputs()
        if (
            input_scan.scope != "inputs"
            or input_scan.baseline_sha256 != baseline.baseline_sha256
            or not _input_state_matches_plan(
                input_scan.entries,
                baseline.input_entries,
                bundle.oracle.actions,
            )
        ):
            return False
        output_scan = handle.scan_outputs()
        output_entries = validate_expected_output_policy(
            bundle.definition, output_scan
        )
        output_by_path = {entry.path: entry for entry in output_entries}
        observed_outputs: list[OracleOutputRecord] = []
        for expected in bundle.oracle.outputs:
            entry = output_by_path.get(expected.path)
            if entry is None:
                return False
            observed_outputs.append(
                OracleOutputRecord(
                    expected.path,
                    handle.read_output_bytes(output_scan, expected.path),
                    entry.mode,
                )
            )
        if tuple(observed_outputs) != bundle.oracle.outputs:
            return False
        baseline_by_path = {
            entry.path: entry for entry in baseline.input_entries
        }
        for action in bundle.oracle.actions:
            if action.outcome != "moved":
                continue
            source_entry = baseline_by_path.get(action.representative)
            output_entry = output_by_path.get(action.output_path)
            if (
                source_entry is None
                or output_entry is None
                or source_entry.kind != "file"
                or output_entry.size != source_entry.size
                or output_entry.mode != source_entry.mode
                or output_entry.mtime_ns != source_entry.mtime_ns
                or output_entry.link_count != 1
            ):
                return False
        final_input_scan = handle.scan_inputs()
        final_output_scan = handle.scan_outputs()
        return (
            final_input_scan == input_scan
            and final_output_scan == output_scan
            and _input_state_matches_plan(
                final_input_scan.entries,
                baseline.input_entries,
                bundle.oracle.actions,
            )
        )
    except (
        ExecutableWorkspaceError,
        CollisionSafeBatchRenameError,
        OSError,
        TypeError,
        ValueError,
    ):
        return False


__all__ = [
    "COLLISION_SAFE_BATCH_RENAME_ALLOWED_TOOLS",
    "COLLISION_SAFE_BATCH_RENAME_ATOMIC_PUBLICATION_HISTORY_OBSERVED",
    "COLLISION_SAFE_BATCH_RENAME_CANDIDATE_EXIT_STATUS_OBSERVED",
    "COLLISION_SAFE_BATCH_RENAME_CANDIDATE_MAXIMUM_BYTES",
    "COLLISION_SAFE_BATCH_RENAME_CANDIDATE_ROOT",
    "COLLISION_SAFE_BATCH_RENAME_COLLISION_DECISION_HISTORY_OBSERVED",
    "COLLISION_SAFE_BATCH_RENAME_COLLISION_POLICIES",
    "COLLISION_SAFE_BATCH_RENAME_CRASH_ATOMICITY_OBSERVED",
    "COLLISION_SAFE_BATCH_RENAME_DIRECTORY_PERMISSION_ERRORS_COVERED",
    "COLLISION_SAFE_BATCH_RENAME_EFFECTIVE_ACCESS_FAILURES_COVERED",
    "COLLISION_SAFE_BATCH_RENAME_FAMILY_ID",
    "COLLISION_SAFE_BATCH_RENAME_FILESYSTEM_IDENTITY",
    "COLLISION_SAFE_BATCH_RENAME_GENERATOR_VERSION",
    "COLLISION_SAFE_BATCH_RENAME_INODE_IDENTITY_OBSERVED",
    "COLLISION_SAFE_BATCH_RENAME_LEDGER_MODE",
    "COLLISION_SAFE_BATCH_RENAME_LEDGER_OUTPUT",
    "COLLISION_SAFE_BATCH_RENAME_MAPPING",
    "COLLISION_SAFE_BATCH_RENAME_MAPPING_MAXIMUM_BYTES",
    "COLLISION_SAFE_BATCH_RENAME_MAXIMUM_CANDIDATES",
    "COLLISION_SAFE_BATCH_RENAME_MAXIMUM_MAPPING_ROWS",
    "COLLISION_SAFE_BATCH_RENAME_MODE_UNREADABLE_UNLISTED_LEAVES_COVERED",
    "COLLISION_SAFE_BATCH_RENAME_OUTPUT_IDENTITY",
    "COLLISION_SAFE_BATCH_RENAME_OUTPUT_MAXIMUM_BYTES",
    "COLLISION_SAFE_BATCH_RENAME_OUTPUT_ROOT",
    "COLLISION_SAFE_BATCH_RENAME_READ_SCOPE_OBSERVED",
    "COLLISION_SAFE_BATCH_RENAME_RENAME_HISTORY_OBSERVED",
    "COLLISION_SAFE_BATCH_RENAME_RENAME_RULES",
    "COLLISION_SAFE_BATCH_RENAME_SYMLINK_DISTRACTORS_COVERED",
    "COLLISION_SAFE_BATCH_RENAME_TOOL_HISTORY_OBSERVED",
    "COLLISION_SAFE_BATCH_RENAME_TRANSIENT_INPUT_PRESERVATION_OBSERVED",
    "COLLISION_SAFE_BATCH_RENAME_VERIFIER_IDENTITY",
    "COLLISION_SAFE_BATCH_RENAME_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE",
    "COLLISION_SAFE_BATCH_RENAME_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE",
    "CollisionSafeBatchRenameAction",
    "CollisionSafeBatchRenameError",
    "CollisionSafeBatchRenameFixtureBundle",
    "CollisionSafeBatchRenameOracle",
    "CollisionSafeBatchRenameParameters",
    "CollisionSafeBatchRenameTask",
    "build_collision_safe_batch_rename_fixture_bundle",
    "build_collision_safe_batch_rename_tasks",
    "collision_safe_batch_rename_task_semantic_core",
    "compute_collision_safe_batch_rename_task_sha256",
    "derive_collision_safe_batch_rename_state",
    "materialize_collision_safe_batch_rename_fixture",
    "reference_collision_safe_batch_rename_state",
    "validate_collision_safe_batch_rename_fixture_bundle",
    "validate_collision_safe_batch_rename_fixture_for_task_profile",
    "verify_collision_safe_batch_rename_fixture_bundle",
    "verify_collision_safe_batch_rename_fixture_for_task_profile",
    "verify_collision_safe_batch_rename_state",
    "verify_collision_safe_batch_rename_workspace",
]
