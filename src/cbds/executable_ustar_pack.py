"""Additive public method-development family for reproducible ustar packing.

The family measures static Bash synthesis over recursive no-follow selection,
permission-bit reasoning, reproducible archive metadata, UTF-8 byte ordering,
and the POSIX ustar name/prefix boundary.  It remains family-local: no frozen
shared registry or invocation type is widened by this module.

All trusted computation operates on immutable ``FixtureDefinition`` records.
One oracle path uses Python's USTAR writer while a separately structured path
selects members and emits headers manually.  Candidate archives are checked
with a strict independent ustar parser, so semantically identical archives may
use a different valid amount of trailing zero-block padding.  This module does
not execute a subprocess, authorize candidate execution, select a model, or
support a research claim.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import io
import os
from pathlib import PurePosixPath
import re
import tarfile
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


USTAR_PACK_FAMILY_ID: Final[str] = "reproducible-ustar-pack"
USTAR_PACK_FILESYSTEM_IDENTITY: Final[str] = "recursive-source-tree-v1"
USTAR_PACK_OUTPUT_IDENTITY: Final[str] = "reproducible-posix-ustar-v1"
USTAR_PACK_GENERATOR_VERSION: Final[str] = "1.0.0"
USTAR_PACK_VERIFIER_IDENTITY: Final[str] = "verify-reproducible-ustar-pack-v1"
USTAR_PACK_ROOT: Final[PurePosixPath] = PurePosixPath("input/source")
USTAR_PACK_OUTPUT: Final[str] = "output/archive.tar"
USTAR_PACK_OUTPUT_MODE: Final[int] = 0o644
USTAR_PACK_OUTPUT_MAXIMUM_BYTES: Final[int] = 1024 * 1024
USTAR_PACK_ALLOWED_TOOLS: Final[tuple[str, ...]] = (
    "chmod",
    "find",
    "mkdir",
    "sort",
    "stat",
    "tar",
)

# FixtureDefinition cannot express directory modes, alternate credentials,
# supplementary groups, ACLs, or a live effective-access failure oracle.
USTAR_PACK_DIRECTORY_PERMISSION_ERRORS_COVERED: Final[bool] = False
USTAR_PACK_EFFECTIVE_ACCESS_FAILURES_COVERED: Final[bool] = False
USTAR_PACK_SYMLINKS_COVERED: Final[bool] = True
USTAR_PACK_MODE_UNREADABLE_LEAVES_COVERED: Final[bool] = True
USTAR_PACK_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE: Final[bool] = True
USTAR_PACK_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE: Final[bool] = False

ArchiveSelector: TypeAlias = Literal[
    "all-mode-readable",
    "txt-suffix-mode-readable",
    "nonempty-mode-readable",
    "executable-mode-readable",
]
ArchiveModePolicy: TypeAlias = Literal[
    "preserve-permission-bits",
    "fixed-0644",
    "fixed-0600",
    "normalize-preserve-exec",
    "fold-class-bits-to-owner",
]

USTAR_PACK_SELECTORS: Final[tuple[ArchiveSelector, ...]] = (
    "all-mode-readable",
    "txt-suffix-mode-readable",
    "nonempty-mode-readable",
    "executable-mode-readable",
)
USTAR_PACK_MODE_POLICIES: Final[tuple[ArchiveModePolicy, ...]] = (
    "preserve-permission-bits",
    "fixed-0644",
    "fixed-0600",
    "normalize-preserve-exec",
    "fold-class-bits-to-owner",
)

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_TASK_ID_RE: Final[re.Pattern[str]] = re.compile(r"mds-[0-9a-f]{24}\Z")
_BLOCK_SIZE: Final[int] = 512
_RECORD_SIZE: Final[int] = 20 * _BLOCK_SIZE
_READ_BITS: Final[int] = 0o444
_EXECUTE_BITS: Final[int] = 0o111


class UstarPackError(ValueError):
    """Raised when a ustar-pack task, fixture, or archive fails closed."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def _closed_text(value: object, allowed: tuple[str, ...], field: str) -> str:
    if type(value) is not str or value not in allowed:
        raise UstarPackError(f"{field} is outside the closed family contract")
    return value


@dataclass(frozen=True, slots=True)
class UstarPackParameters:
    """One cell in the four-selector by five-mode-policy task grid."""

    selector: ArchiveSelector
    archive_mode_policy: ArchiveModePolicy

    def __post_init__(self) -> None:
        _closed_text(self.selector, USTAR_PACK_SELECTORS, "selector")
        _closed_text(
            self.archive_mode_policy,
            USTAR_PACK_MODE_POLICIES,
            "archive_mode_policy",
        )

    def to_record(self) -> dict[str, str]:
        self.__post_init__()
        return {
            "parameter_type": USTAR_PACK_FAMILY_ID,
            "selector": self.selector,
            "archive_mode_policy": self.archive_mode_policy,
        }


_SELECTOR_TEXT: Final[dict[ArchiveSelector, str]] = {
    "all-mode-readable": "select every mode-readable regular file",
    "txt-suffix-mode-readable": (
        "select each mode-readable regular file whose basename ends exactly "
        "in the lowercase byte suffix `.txt`"
    ),
    "nonempty-mode-readable": (
        "select each mode-readable regular file whose byte length is nonzero"
    ),
    "executable-mode-readable": (
        "select each mode-readable regular file with at least one 0111 execute bit"
    ),
}
_MODE_POLICY_TEXT: Final[dict[ArchiveModePolicy, str]] = {
    "preserve-permission-bits": (
        "copy all nine original 0777 permission bits"
    ),
    "fixed-0644": "set every member mode to 0644",
    "fixed-0600": "set every member mode to 0600",
    "normalize-preserve-exec": (
        "set mode to 0755 when any original 0111 execute bit is set, and "
        "otherwise set mode to 0644"
    ),
    "fold-class-bits-to-owner": (
        "OR the owner, group, and other three-bit classes together, put that "
        "union in the owner class, and clear the group and other classes"
    ),
}


def _task_contract(
    parameters: UstarPackParameters,
) -> tuple[str, NormalizedSemanticGraph]:
    prompt = f"""Write one Bash program that operates only in the current workspace.

Recursively inspect entries strictly below `input/source/` without following
any symbolic link.  A regular file is mode-readable exactly when at least one
of its 0444 permission bits is set; effective-user access does not change this
definition.  {_SELECTOR_TEXT[parameters.selector].capitalize()}.  Archive each
selected file under its path relative to `input/source/`, and archive no
directory, symbolic-link, hard-link, device, or other member.  Sort members by
their relative-path raw UTF-8 bytes under `LC_ALL=C`.

Write `output/archive.tar` as a POSIX ustar archive.  Every member must be a
regular member with its exact selected path and input bytes.  Set uid, gid, and
mtime to decimal zero, leave uname and gname empty, and
{_MODE_POLICY_TEXT[parameters.archive_mode_policy]}.  Use only the standard
ustar name and prefix fields: do not emit PAX, GNU, long-name, sparse, or other
extension records.  End the archive with at least two 512-byte zero blocks;
additional whole trailing zero blocks are allowed.  For an empty selection,
emit a valid empty ustar archive rather than a zero-byte file.

Because every fixture leaf is owned by the execution UID, a mode-0040 or
mode-0004 input is not directly kernel-readable by that owner.  You may
temporarily add owner-read permission only to an originally mode-readable
selected file, but restore its exact original mode before completion.
Preserve every input path,
kind, permission mode, byte, modification time, hard-link count, and symlink
target.  Leave only a real mode-0755 `output/` directory and an independent
mode-0644 regular `output/archive.tar` with link count one.  Use only Bash
built-ins plus `chmod`, `find`, `mkdir`, `sort`, `stat`, and `tar`.
"""
    graph = NormalizedSemanticGraph(
        nodes=(
            OperatorNode(
                "discover_ustar_source_files",
                (
                    "root:input/source",
                    "follow_symlinks:false",
                    "kind:regular",
                    "mode-readable:0444-any",
                ),
            ),
            OperatorNode(
                "select_ustar_source_files",
                (f"selector:{parameters.selector}",),
            ),
            OperatorNode(
                "sort_ustar_member_paths",
                ("key:relative-utf8-bytes", "locale:C"),
            ),
            OperatorNode(
                "normalize_ustar_member_metadata",
                (
                    f"mode-policy:{parameters.archive_mode_policy}",
                    "uid:0",
                    "gid:0",
                    "mtime:0",
                    "names:empty",
                ),
            ),
            OperatorNode(
                "encode_posix_ustar_regular_members",
                ("format:ustar", "extensions:none", "member-kinds:regular-only"),
            ),
            OperatorNode(
                "emit_reproducible_ustar_archive",
                (
                    "path:output/archive.tar",
                    "mode:0644",
                    "terminator:two-or-more-zero-blocks",
                ),
            ),
        ),
        dependencies=((0, 1), (1, 2), (2, 3), (3, 4), (4, 5)),
    )
    return prompt, graph


def _validate_graph(graph: object) -> NormalizedSemanticGraph:
    if type(graph) is not NormalizedSemanticGraph:
        raise UstarPackError("graph must have the exact semantic-graph type")
    if type(graph.nodes) is not tuple or not graph.nodes:
        raise UstarPackError("graph nodes must be a nonempty exact tuple")
    if type(graph.dependencies) is not tuple:
        raise UstarPackError("graph dependencies must be an exact tuple")
    for node in graph.nodes:
        if (
            type(node) is not OperatorNode
            or type(node.name) is not str
            or not node.name
            or "\0" in node.name
            or type(node.parameters) is not tuple
            or any(type(value) is not str for value in node.parameters)
        ):
            raise UstarPackError("graph contains a noncanonical node")
    for edge in graph.dependencies:
        if (
            type(edge) is not tuple
            or len(edge) != 2
            or any(type(index) is not int for index in edge)
        ):
            raise UstarPackError("graph contains a noncanonical edge")
        source, target = edge
        if source < 0 or source >= target or target >= len(graph.nodes):
            raise UstarPackError("graph edge violates canonical order")
    try:
        rebuilt = NormalizedSemanticGraph(
            nodes=tuple(
                OperatorNode(node.name, node.parameters) for node in graph.nodes
            ),
            dependencies=graph.dependencies,
        )
    except (TypeError, ValueError) as exc:
        raise UstarPackError("graph reconstruction failed") from exc
    if rebuilt != graph:
        raise UstarPackError("graph changed during reconstruction")
    return graph


def ustar_pack_task_semantic_core(
    parameters: UstarPackParameters,
    prompt: str,
    graph: NormalizedSemanticGraph,
) -> dict[str, object]:
    if type(parameters) is not UstarPackParameters:
        raise UstarPackError("parameters have the wrong exact type")
    parameters.__post_init__()
    if type(prompt) is not str or not prompt.strip() or "\0" in prompt:
        raise UstarPackError("prompt must be exact nonempty text")
    _validate_graph(graph)
    expected_prompt, expected_graph = _task_contract(parameters)
    if prompt != expected_prompt or graph != expected_graph:
        raise UstarPackError("prompt or graph differs from the family contract")
    return {
        "schema_version": EXECUTABLE_STATIC_SCHEMA_VERSION,
        "contract_version": EXECUTABLE_STATIC_CONTRACT_VERSION,
        "split_role": METHOD_DEVELOPMENT_SPLIT,
        "family_id": USTAR_PACK_FAMILY_ID,
        "family_version": EXECUTABLE_STATIC_FAMILY_VERSION,
        "parameters": parameters.to_record(),
        "prompt": prompt,
        "graph": graph.to_record(),
        "graph_sha256": graph.hash,
        "filesystem_identity": USTAR_PACK_FILESYSTEM_IDENTITY,
        "output_identity": USTAR_PACK_OUTPUT_IDENTITY,
        "allowed_tools": list(USTAR_PACK_ALLOWED_TOOLS),
        "public": True,
        "sealed": False,
        "candidate_execution_authorized": False,
        "model_selection_eligible": False,
        "claim_authorized": False,
    }


def compute_ustar_pack_task_sha256(
    parameters: UstarPackParameters,
    prompt: str,
    graph: NormalizedSemanticGraph,
) -> str:
    return domain_sha256(
        "cbds.executable-static.task-contract.v1",
        ustar_pack_task_semantic_core(parameters, prompt, graph),
    )


@dataclass(frozen=True, slots=True)
class UstarPackTask:
    task_id: str
    parameters: UstarPackParameters
    prompt: str
    graph: NormalizedSemanticGraph
    fixtures: tuple[OpaqueFixtureDescriptor, ...]
    task_contract_sha256: str
    family_id: str = USTAR_PACK_FAMILY_ID
    family_version: str = EXECUTABLE_STATIC_FAMILY_VERSION
    filesystem_identity: str = USTAR_PACK_FILESYSTEM_IDENTITY
    output_identity: str = USTAR_PACK_OUTPUT_IDENTITY
    allowed_tools: tuple[str, ...] = USTAR_PACK_ALLOWED_TOOLS
    split_role: str = METHOD_DEVELOPMENT_SPLIT
    public: bool = True
    sealed: bool = False
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.parameters) is not UstarPackParameters
            or type(self.family_id) is not str
            or self.family_id != USTAR_PACK_FAMILY_ID
            or type(self.family_version) is not str
            or self.family_version != EXECUTABLE_STATIC_FAMILY_VERSION
            or type(self.filesystem_identity) is not str
            or self.filesystem_identity != USTAR_PACK_FILESYSTEM_IDENTITY
            or type(self.output_identity) is not str
            or self.output_identity != USTAR_PACK_OUTPUT_IDENTITY
            or type(self.allowed_tools) is not tuple
            or self.allowed_tools != USTAR_PACK_ALLOWED_TOOLS
            or any(type(tool) is not str for tool in self.allowed_tools)
            or type(self.split_role) is not str
            or self.split_role != METHOD_DEVELOPMENT_SPLIT
            or self.public is not True
            or self.sealed is not False
            or self.candidate_execution_authorized is not False
            or self.model_selection_eligible is not False
            or self.claim_authorized is not False
        ):
            raise UstarPackError("task metadata is invalid")
        expected = compute_ustar_pack_task_sha256(
            self.parameters, self.prompt, self.graph
        )
        if (
            type(self.task_id) is not str
            or _TASK_ID_RE.fullmatch(self.task_id) is None
            or not _is_sha256(self.task_contract_sha256)
            or self.task_contract_sha256 != expected
            or self.task_id != task_id_from_contract(expected)
        ):
            raise UstarPackError("task identity is invalid")
        if (
            type(self.fixtures) is not tuple
            or len(self.fixtures) != len(PUBLIC_DEVELOPMENT_FIXTURE_PROFILES)
            or any(
                type(item) is not OpaqueFixtureDescriptor for item in self.fixtures
            )
        ):
            raise UstarPackError("task fixture descriptors are invalid")
        for descriptor in self.fixtures:
            descriptor.__post_init__()
        if (
            len({item.fixture_id for item in self.fixtures}) != 5
            or any(
                item.task_contract_sha256 != expected for item in self.fixtures
            )
        ):
            raise UstarPackError("task descriptor binding is invalid")

    @property
    def graph_sha256(self) -> str:
        self.__post_init__()
        return self.graph.hash

    def to_public_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            **ustar_pack_task_semantic_core(
                self.parameters, self.prompt, self.graph
            ),
            "task_id": self.task_id,
            "task_contract_sha256": self.task_contract_sha256,
            "fixtures": [item.to_public_record() for item in self.fixtures],
        }


def _bootstrap_descriptors(
    task_contract_sha256: str,
) -> tuple[OpaqueFixtureDescriptor, ...]:
    descriptors: list[OpaqueFixtureDescriptor] = []
    for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
        digest = domain_sha256(
            "cbds.executable-static.fixture.v1",
            {
                "task_contract_sha256": task_contract_sha256,
                "profile_sha256": profile.profile_sha256,
            },
        )
        descriptors.append(
            OpaqueFixtureDescriptor(
                fixture_id=f"fx-{digest[:24]}",
                fixture_sha256=digest,
                task_contract_sha256=task_contract_sha256,
            )
        )
    return tuple(descriptors)


def _bootstrap_task(parameters: UstarPackParameters) -> UstarPackTask:
    prompt, graph = _task_contract(parameters)
    digest = compute_ustar_pack_task_sha256(parameters, prompt, graph)
    return UstarPackTask(
        task_id=task_id_from_contract(digest),
        parameters=parameters,
        prompt=prompt,
        graph=graph,
        fixtures=_bootstrap_descriptors(digest),
        task_contract_sha256=digest,
    )


def build_ustar_pack_tasks() -> tuple[UstarPackTask, ...]:
    """Build the deterministic family-local 20-task grid."""

    tasks: list[UstarPackTask] = []
    for selector in USTAR_PACK_SELECTORS:
        for archive_mode_policy in USTAR_PACK_MODE_POLICIES:
            bootstrap = _bootstrap_task(
                UstarPackParameters(selector, archive_mode_policy)
            )
            descriptors = tuple(
                _construct_ustar_pack_fixture_bundle(bootstrap, profile).descriptor
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
        raise UstarPackError("task grid is not exactly 20 unique tasks")
    return selected


_PREFIX_SPLIT_RELATIVE_PATH: Final[str] = (
    "portable-archive-prefix-with-enough-characters/"
    "second-prefix-segment-for-ustar-boundary/"
    "long-selected-executable.txt"
)


def _fixture_inputs(
    profile: ExecutableFixtureProfile,
) -> tuple[InputFile | InputSymlink, ...]:
    """Return explicit deterministic leaves for one public edge-case profile."""

    if profile.profile_id == "spaces-unicode":
        return (
            InputFile(
                "input/source/café notes.txt",
                "snow 雪 and café\n".encode("utf-8"),
                0o640,
            ),
            InputFile(
                "input/source/tools/run 雪.sh",
                b"#!/bin/sh\nprintf '%s\\n' snow\n",
                0o751,
            ),
            InputFile("input/source/empty record.txt", b"", 0o444),
            InputFile(
                f"input/source/{_PREFIX_SPLIT_RELATIVE_PATH}",
                b"ustar-prefix-boundary\n",
                0o700,
            ),
            InputFile("input/outside/not-a-member.txt", b"outside\n", 0o644),
            InputFile(
                "input/outside/executable-outside.sh",
                b"#!/bin/sh\nexit 0\n",
                0o755,
            ),
            InputSymlink("input/source/link to café.txt", "café notes.txt"),
        )
    if profile.profile_id == "leading-dashes-globs":
        return (
            InputFile(
                "input/source/-[draft]*?.txt",
                b"literal glob characters\n",
                0o604,
            ),
            InputFile(
                "input/source/-nested[?]/--run*.sh",
                b"#!/bin/sh\nexit 0\n",
                0o510,
            ),
            InputFile("input/source/-empty?.txt", b"", 0o440),
            InputFile("input/source/group-exec.txt", b"group exec\n", 0o070),
            InputFile("input/source/other-exec.txt", b"other exec\n", 0o007),
            InputFile("input/source/single-byte.bin", b"x", 0o644),
            InputFile(
                "input/source/contains.txt.backup",
                b"suffix must be terminal\n",
                0o644,
            ),
            InputFile("input/source/case.TXT", b"uppercase is not suffix\n", 0o644),
            InputSymlink("input/source/-link*.txt", "-[draft]*?.txt"),
        )
    if profile.profile_id == "empty-duplicates":
        duplicate = b"same bytes repeated across independent files\n"
        return (
            InputFile("input/source/empty.txt", b"", 0o000),
            InputFile("input/source/also-empty.bin", b"", 0o111),
            InputFile("input/source/copies/one.txt", duplicate, 0o000),
            InputFile("input/source/copies/two.data", duplicate, 0o111),
            InputFile("input/source/unreadable-executable.sh", b"hidden\n", 0o111),
            InputSymlink("input/source/copies/duplicate-link.txt", "one.txt"),
        )
    if profile.profile_id == "symlinks-ordering":
        entries: list[InputFile | InputSymlink] = [
            # Reversal below deliberately leaves every selector's source
            # enumeration out of UTF-8 byte order.  A candidate that omits
            # the required sort therefore fails this profile.
            InputFile("input/source/middle/empty.txt", b"", 0o444),
            InputFile("input/source/a-first.bin", b"a\n", 0o605),
            InputFile("input/source/middle/run.sh", b"run\n", 0o744),
            InputFile("input/source/z-last.txt", b"z\n", 0o644),
            InputFile("input/source/duplicate-a.bin", b"duplicate\n", 0o640),
            InputFile("input/source/duplicate-b.bin", b"duplicate\n", 0o604),
            InputSymlink("input/source/00-link.txt", "z-last.txt"),
            InputSymlink("input/source/middle/link-run", "run.sh"),
        ]
        entries.reverse()
        return tuple(entries)
    if profile.profile_id == "partial-permissions":
        return (
            InputFile("input/source/group-readable.txt", b"group\n", 0o040),
            InputFile("input/source/other-readable.bin", b"other\n", 0o004),
            InputFile("input/source/owner-readable.txt", b"owner\n", 0o400),
            InputFile("input/source/group-write.bin", b"group write\n", 0o060),
            InputFile("input/source/other-write.bin", b"other write\n", 0o006),
            InputFile("input/source/readable-executable.sh", b"execute\n", 0o055),
            InputFile("input/source/permission-denied.txt", b"hidden\n", 0o000),
            InputFile("input/source/execute-only.sh", b"hidden exec\n", 0o111),
            InputSymlink(
                "input/source/permission-link.txt", "owner-readable.txt"
            ),
        )
    raise UstarPackError("unsupported fixture profile")


def _revalidate_definition(definition: object) -> FixtureDefinition:
    if type(definition) is not FixtureDefinition:
        raise UstarPackError("definition has the wrong exact type")
    if (
        type(definition.fixture_id) is not str
        or type(definition.inputs) is not tuple
        or type(definition.expected_files) is not tuple
        or type(definition.schema_version) is not str
    ):
        raise UstarPackError("definition nested types are invalid")
    for item in definition.inputs:
        if type(item) is InputFile:
            if (
                type(item.path) is not str
                or type(item.content) is not bytes
                or type(item.mode) is not int
            ):
                raise UstarPackError("input-file nested types are invalid")
        elif type(item) is InputSymlink:
            if type(item.path) is not str or type(item.target) is not str:
                raise UstarPackError("input-symlink nested types are invalid")
        else:
            raise UstarPackError("definition input type is invalid")
    for expected in definition.expected_files:
        if (
            type(expected) is not ExpectedFile
            or type(expected.path) is not str
            or type(expected.maximum_bytes) is not int
            or (expected.mode is not None and type(expected.mode) is not int)
        ):
            raise UstarPackError("expected-file nested types are invalid")
    try:
        rebuilt = FixtureDefinition(
            fixture_id=definition.fixture_id,
            inputs=definition.inputs,
            expected_files=definition.expected_files,
            schema_version=definition.schema_version,
        )
    except (TypeError, ValueError) as exc:
        raise UstarPackError("definition reconstruction failed") from exc
    if rebuilt != definition:
        raise UstarPackError("definition changed during reconstruction")
    return definition


def _split_ustar_name(path: str) -> tuple[bytes, bytes]:
    """Validate a safe UTF-8 member path and return name, prefix bytes."""

    if type(path) is not str or not path or "\0" in path:
        raise UstarPackError("ustar member path must be nonempty NUL-free text")
    if any(ord(character) < 32 or ord(character) == 127 for character in path):
        raise UstarPackError("ustar member path contains a control character")
    try:
        encoded = path.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise UstarPackError("ustar member path is not valid UTF-8") from exc
    parsed = PurePosixPath(path)
    if (
        parsed.is_absolute()
        or parsed.as_posix() != path
        or not parsed.parts
        or any(part in {"", ".", ".."} for part in parsed.parts)
    ):
        raise UstarPackError("ustar member path is not canonical and relative")
    if len(encoded) <= 100:
        return encoded, b""
    slash_positions = [index for index, byte in enumerate(encoded) if byte == 47]
    # USTAR's canonical split used by the primary writer takes the earliest
    # slash whose suffix fits the 100-byte name field.
    for index in slash_positions:
        prefix = encoded[:index]
        name = encoded[index + 1 :]
        if prefix and name and len(prefix) <= 155 and len(name) <= 100:
            return name, prefix
    raise UstarPackError("member path cannot be represented in POSIX ustar")


@dataclass(frozen=True, slots=True)
class UstarPackMember:
    """One complete semantic regular-file member, before block encoding."""

    path: str
    content: bytes = field(repr=False)
    mode: int

    def __post_init__(self) -> None:
        _split_ustar_name(self.path)
        if type(self.content) is not bytes:
            raise UstarPackError("member content must be exact immutable bytes")
        if type(self.mode) is not int or not 0 <= self.mode <= 0o777:
            raise UstarPackError("member mode must contain only 0777 bits")


def _primary_selected(item: InputFile, selector: ArchiveSelector) -> bool:
    if item.mode & _READ_BITS == 0:
        return False
    relative = PurePosixPath(*PurePosixPath(item.path).parts[2:])
    if selector == "all-mode-readable":
        return True
    if selector == "txt-suffix-mode-readable":
        return relative.name.endswith(".txt")
    if selector == "nonempty-mode-readable":
        return len(item.content) != 0
    if selector == "executable-mode-readable":
        return item.mode & _EXECUTE_BITS != 0
    raise UstarPackError("unsupported selector")


def _primary_member_mode(mode: int, policy: ArchiveModePolicy) -> int:
    if policy == "preserve-permission-bits":
        return mode & 0o777
    if policy == "fixed-0644":
        return 0o644
    if policy == "fixed-0600":
        return 0o600
    if policy == "normalize-preserve-exec":
        return 0o755 if mode & _EXECUTE_BITS else 0o644
    if policy == "fold-class-bits-to-owner":
        class_union = ((mode >> 6) | (mode >> 3) | mode) & 0o7
        return class_union << 6
    raise UstarPackError("unsupported archive mode policy")


def derive_ustar_pack_members(
    definition: FixtureDefinition,
    parameters: UstarPackParameters,
) -> tuple[UstarPackMember, ...]:
    """Primary semantic derivation over exact immutable fixture leaves."""

    selected = _revalidate_definition(definition)
    if type(parameters) is not UstarPackParameters:
        raise UstarPackError("parameters have the wrong exact type")
    parameters.__post_init__()
    members: list[UstarPackMember] = []
    for item in selected.inputs:
        if type(item) is not InputFile:
            continue
        path = PurePosixPath(item.path)
        if len(path.parts) < 3 or path.parts[:2] != USTAR_PACK_ROOT.parts:
            continue
        if not _primary_selected(item, parameters.selector):
            continue
        relative = PurePosixPath(*path.parts[2:]).as_posix()
        members.append(
            UstarPackMember(
                relative,
                item.content,
                _primary_member_mode(item.mode, parameters.archive_mode_policy),
            )
        )
    members.sort(key=lambda member: member.path.encode("utf-8"))
    if len({member.path for member in members}) != len(members):
        raise UstarPackError("selected member paths are not unique")
    return tuple(members)


def reference_ustar_pack_members(
    definition: FixtureDefinition,
    parameters: UstarPackParameters,
) -> tuple[UstarPackMember, ...]:
    """Separately structured selection and mode-policy derivation."""

    selected = _revalidate_definition(definition)
    if type(parameters) is not UstarPackParameters:
        raise UstarPackError("parameters have the wrong exact type")
    parameters.__post_init__()
    staged: dict[bytes, UstarPackMember] = {}
    for leaf in selected.inputs:
        if type(leaf) is not InputFile:
            continue
        pieces = leaf.path.split("/")
        if len(pieces) < 3 or pieces[0] != "input" or pieces[1] != "source":
            continue
        relative = "/".join(pieces[2:])
        readable = bool(leaf.mode & 0o400 or leaf.mode & 0o040 or leaf.mode & 0o004)
        selector_match = {
            "all-mode-readable": True,
            "txt-suffix-mode-readable": pieces[-1].endswith(".txt"),
            "nonempty-mode-readable": bool(leaf.content),
            "executable-mode-readable": bool(
                leaf.mode & 0o100 or leaf.mode & 0o010 or leaf.mode & 0o001
            ),
        }[parameters.selector]
        if not readable or not selector_match:
            continue
        original = leaf.mode
        if parameters.archive_mode_policy == "preserve-permission-bits":
            archived_mode = original
        elif parameters.archive_mode_policy == "fixed-0644":
            archived_mode = 0o644
        elif parameters.archive_mode_policy == "fixed-0600":
            archived_mode = 0o600
        elif parameters.archive_mode_policy == "normalize-preserve-exec":
            archived_mode = 0o755 if original & 0o111 else 0o644
        elif parameters.archive_mode_policy == "fold-class-bits-to-owner":
            owner_union = 0
            for permission in (0o4, 0o2, 0o1):
                if any(
                    original & (permission << shift) for shift in (0, 3, 6)
                ):
                    owner_union |= permission
            archived_mode = owner_union << 6
        else:  # pragma: no cover - closed parameters make this unreachable
            raise UstarPackError("unsupported archive mode policy")
        member = UstarPackMember(relative, bytes(leaf.content), archived_mode)
        key = relative.encode("utf-8")
        if key in staged:
            raise UstarPackError("selected member byte paths collide")
        staged[key] = member
    return tuple(staged[key] for key in sorted(staged))


def derive_ustar_pack_output(
    definition: FixtureDefinition,
    parameters: UstarPackParameters,
) -> bytes:
    """Canonical archive producer using the standard-library USTAR writer."""

    members = derive_ustar_pack_members(definition, parameters)
    stream = io.BytesIO()
    try:
        with tarfile.open(
            fileobj=stream,
            mode="w",
            format=tarfile.USTAR_FORMAT,
            encoding="utf-8",
            errors="strict",
        ) as archive:
            for member in members:
                info = tarfile.TarInfo(member.path)
                info.size = len(member.content)
                info.mode = member.mode
                info.uid = 0
                info.gid = 0
                info.mtime = 0
                info.uname = ""
                info.gname = ""
                info.type = tarfile.REGTYPE
                info.linkname = ""
                info.devmajor = 0
                info.devminor = 0
                archive.addfile(info, io.BytesIO(member.content))
    except (OSError, tarfile.TarError, UnicodeError, ValueError) as exc:
        raise UstarPackError("standard-library ustar construction failed") from exc
    payload = stream.getvalue()
    if len(payload) > USTAR_PACK_OUTPUT_MAXIMUM_BYTES:
        raise UstarPackError("canonical archive exceeds the family output ceiling")
    return payload


def _manual_octal(value: int, width: int) -> bytes:
    if type(value) is not int or value < 0:
        raise UstarPackError("ustar numeric field value is invalid")
    digits = format(value, "o").encode("ascii")
    if len(digits) > width - 1:
        raise UstarPackError("ustar numeric field does not fit")
    return b"0" * (width - 1 - len(digits)) + digits + b"\0"


def _manual_ustar_header(member: UstarPackMember) -> bytes:
    member.__post_init__()
    name, prefix = _split_ustar_name(member.path)
    header = bytearray(_BLOCK_SIZE)
    header[0 : len(name)] = name
    header[100:108] = _manual_octal(member.mode, 8)
    header[108:116] = _manual_octal(0, 8)
    header[116:124] = _manual_octal(0, 8)
    header[124:136] = _manual_octal(len(member.content), 12)
    header[136:148] = _manual_octal(0, 12)
    header[148:156] = b" " * 8
    header[156:157] = b"0"
    # linkname remains 100 NUL bytes.
    header[257:263] = b"ustar\0"
    header[263:265] = b"00"
    # uname, gname, devmajor, and devminor remain NUL-filled.
    header[345 : 345 + len(prefix)] = prefix
    checksum = sum(header)
    checksum_digits = format(checksum, "06o").encode("ascii")
    if len(checksum_digits) != 6:
        raise UstarPackError("ustar checksum does not fit the POSIX field")
    header[148:156] = checksum_digits + b"\0 "
    return bytes(header)


def reference_ustar_pack_output(
    definition: FixtureDefinition,
    parameters: UstarPackParameters,
) -> bytes:
    """Independent canonical producer using a manual POSIX header encoder."""

    members = reference_ustar_pack_members(definition, parameters)
    output = bytearray()
    for member in members:
        output.extend(_manual_ustar_header(member))
        output.extend(member.content)
        output.extend(b"\0" * (-len(member.content) % _BLOCK_SIZE))
    output.extend(b"\0" * (2 * _BLOCK_SIZE))
    output.extend(b"\0" * (-len(output) % _RECORD_SIZE))
    payload = bytes(output)
    if len(payload) > USTAR_PACK_OUTPUT_MAXIMUM_BYTES:
        raise UstarPackError("manual archive exceeds the family output ceiling")
    return payload


def _nul_field(field: bytes, label: str) -> bytes:
    if type(field) is not bytes or not field:
        raise UstarPackError(f"{label} field is invalid")
    marker = field.find(b"\0")
    if marker < 0:
        return field
    if any(field[marker + 1 :]):
        raise UstarPackError(f"{label} field has nonzero bytes after NUL")
    return field[:marker]


def _parse_octal(field: bytes, label: str) -> int:
    if type(field) is not bytes or not field or field[0] & 0x80:
        raise UstarPackError(f"{label} uses an unsupported numeric encoding")
    stripped = field.strip(b" \0")
    if not stripped:
        return 0
    if any(byte < 48 or byte > 55 for byte in stripped):
        raise UstarPackError(f"{label} is not an ASCII octal field")
    # No embedded terminator or space may split the digits.
    first = field.find(stripped)
    if first < 0 or any(byte not in (0, 32) for byte in field[:first]):
        raise UstarPackError(f"{label} has invalid leading padding")
    if any(byte not in (0, 32) for byte in field[first + len(stripped) :]):
        raise UstarPackError(f"{label} has invalid trailing padding")
    return int(stripped, 8)


def _parse_ustar_members(payload: bytes) -> tuple[UstarPackMember, ...]:
    """Strict extension-free parser with flexible trailing zero-block count."""

    if (
        type(payload) is not bytes
        or len(payload) < 2 * _BLOCK_SIZE
        or len(payload) > USTAR_PACK_OUTPUT_MAXIMUM_BYTES
        or len(payload) % _BLOCK_SIZE != 0
    ):
        raise UstarPackError("candidate archive violates block or size bounds")
    members: list[UstarPackMember] = []
    cursor = 0
    zero_block = b"\0" * _BLOCK_SIZE
    while cursor < len(payload):
        header = payload[cursor : cursor + _BLOCK_SIZE]
        if header == zero_block:
            if len(payload) - cursor < 2 * _BLOCK_SIZE:
                raise UstarPackError("archive lacks two terminating zero blocks")
            if any(payload[cursor:]):
                raise UstarPackError("archive has data after its zero terminator")
            break
        if len(header) != _BLOCK_SIZE:
            raise UstarPackError("archive contains a partial header")
        stored_checksum = _parse_octal(header[148:156], "checksum")
        checksum_view = bytearray(header)
        checksum_view[148:156] = b" " * 8
        if stored_checksum != sum(checksum_view):
            raise UstarPackError("ustar header checksum is invalid")
        if header[257:263] != b"ustar\0" or header[263:265] != b"00":
            raise UstarPackError("archive member is not POSIX ustar")
        if header[156:157] not in {b"0", b"\0"}:
            raise UstarPackError("archive contains a non-regular member or extension")
        if any(header[157:257]):
            raise UstarPackError("regular member has a nonempty link name")
        if any(header[265:329]) or any(header[329:345]):
            raise UstarPackError("archive member uname, gname, or device fields differ")
        if any(header[500:512]):
            raise UstarPackError("archive member reserved header bytes are nonzero")
        name_bytes = _nul_field(header[0:100], "name")
        prefix_bytes = _nul_field(header[345:500], "prefix")
        if not name_bytes:
            raise UstarPackError("archive member has an empty name")
        raw_path = prefix_bytes + (b"/" if prefix_bytes else b"") + name_bytes
        try:
            path = raw_path.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise UstarPackError("archive member name is not valid UTF-8") from exc
        _split_ustar_name(path)
        mode = _parse_octal(header[100:108], "mode")
        uid = _parse_octal(header[108:116], "uid")
        gid = _parse_octal(header[116:124], "gid")
        size = _parse_octal(header[124:136], "size")
        mtime = _parse_octal(header[136:148], "mtime")
        if mode > 0o777 or uid != 0 or gid != 0 or mtime != 0:
            raise UstarPackError("archive member metadata is not normalized")
        content_start = cursor + _BLOCK_SIZE
        content_end = content_start + size
        padded_size = ((size + _BLOCK_SIZE - 1) // _BLOCK_SIZE) * _BLOCK_SIZE
        padded_end = content_start + padded_size
        if content_end > len(payload) or padded_end > len(payload):
            raise UstarPackError("archive member content is truncated")
        if any(payload[content_end:padded_end]):
            raise UstarPackError("archive member has nonzero data padding")
        members.append(UstarPackMember(path, payload[content_start:content_end], mode))
        cursor = padded_end
    else:
        raise UstarPackError("archive is missing its zero-block terminator")
    if len({member.path for member in members}) != len(members):
        raise UstarPackError("archive contains duplicate member paths")
    if tuple(member.path.encode("utf-8") for member in members) != tuple(
        sorted(member.path.encode("utf-8") for member in members)
    ):
        raise UstarPackError("archive members are not in UTF-8 byte order")
    return tuple(members)


def verify_ustar_pack_output(
    definition: FixtureDefinition,
    parameters: UstarPackParameters,
    candidate_output: bytes,
) -> bool:
    """Accept exactly the expected ustar semantics and valid zero padding."""

    if type(candidate_output) is not bytes:
        return False
    try:
        primary_members = derive_ustar_pack_members(definition, parameters)
        reference_members = reference_ustar_pack_members(definition, parameters)
        primary_archive = derive_ustar_pack_output(definition, parameters)
        reference_archive = reference_ustar_pack_output(definition, parameters)
        candidate_members = _parse_ustar_members(candidate_output)
        # Parsing both canonical values makes format drift fail closed even if
        # the two semantic member derivations continue to agree.
        parsed_primary = _parse_ustar_members(primary_archive)
        parsed_reference = _parse_ustar_members(reference_archive)
    except (OSError, tarfile.TarError, UstarPackError, TypeError, ValueError):
        return False
    return (
        primary_members
        == reference_members
        == parsed_primary
        == parsed_reference
        == candidate_members
        and primary_archive == reference_archive
    )


def _compute_oracle_sha256(outputs: tuple[OracleOutputRecord, ...]) -> str:
    if (
        type(outputs) is not tuple
        or len(outputs) != 1
        or type(outputs[0]) is not OracleOutputRecord
    ):
        raise UstarPackError("oracle output tuple is invalid")
    output = outputs[0]
    output.__post_init__()
    if (
        output.path != USTAR_PACK_OUTPUT
        or output.mode != USTAR_PACK_OUTPUT_MODE
        or len(output.content) > USTAR_PACK_OUTPUT_MAXIMUM_BYTES
    ):
        raise UstarPackError("oracle output contract is invalid")
    return domain_sha256(
        "cbds.executable-fixture.trusted-oracle.v1",
        {
            "schema_version": EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION,
            "semantic_verifier_identity": USTAR_PACK_VERIFIER_IDENTITY,
            "outputs": [output.commitment_record()],
        },
    )


@dataclass(frozen=True, slots=True)
class UstarPackOracle:
    outputs: tuple[OracleOutputRecord, ...]
    oracle_sha256: str
    semantic_verifier_identity: str = USTAR_PACK_VERIFIER_IDENTITY
    schema_version: str = EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            type(self.semantic_verifier_identity) is not str
            or self.semantic_verifier_identity != USTAR_PACK_VERIFIER_IDENTITY
            or type(self.schema_version) is not str
            or self.schema_version != EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION
            or not _is_sha256(self.oracle_sha256)
            or self.oracle_sha256 != _compute_oracle_sha256(self.outputs)
        ):
            raise UstarPackError("oracle identity is invalid")

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
class UstarPackFixtureBundle:
    task_contract_sha256: str
    profile_sha256: str
    definition: FixtureDefinition = field(repr=False)
    fixture_definition_sha256: str
    oracle: UstarPackOracle = field(repr=False)
    descriptor: OpaqueFixtureDescriptor
    schema_version: str = EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_ustar_pack_fixture_bundle(self)

    def to_opaque_descriptor(self) -> OpaqueFixtureDescriptor:
        validate_ustar_pack_fixture_bundle(self)
        return self.descriptor

    def commitment_record(self) -> dict[str, object]:
        validate_ustar_pack_fixture_bundle(self)
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


def validate_ustar_pack_fixture_bundle(bundle: UstarPackFixtureBundle) -> None:
    """Validate structural self-consistency, not task/profile authenticity."""

    if type(bundle) is not UstarPackFixtureBundle:
        raise UstarPackError("bundle has the wrong exact type")
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
        raise UstarPackError("bundle metadata is invalid")
    definition = _revalidate_definition(bundle.definition)
    definition_sha256 = compute_fixture_definition_semantic_sha256(definition)
    if bundle.fixture_definition_sha256 != definition_sha256:
        raise UstarPackError("definition digest is invalid")
    if type(bundle.oracle) is not UstarPackOracle:
        raise UstarPackError("oracle has the wrong exact type")
    bundle.oracle.__post_init__()
    if definition.expected_files != (
        ExpectedFile(
            USTAR_PACK_OUTPUT,
            maximum_bytes=USTAR_PACK_OUTPUT_MAXIMUM_BYTES,
            mode=USTAR_PACK_OUTPUT_MODE,
        ),
    ):
        raise UstarPackError("output policy does not bind the family ceiling")
    if type(bundle.descriptor) is not OpaqueFixtureDescriptor:
        raise UstarPackError("descriptor has the wrong exact type")
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
        raise UstarPackError("descriptor binding is invalid")


def verify_ustar_pack_fixture_bundle(bundle: object) -> bool:
    try:
        validate_ustar_pack_fixture_bundle(bundle)  # type: ignore[arg-type]
    except (UstarPackError, TypeError, ValueError):
        return False
    return True


def _validate_task_profile(
    task: object,
    profile: object,
) -> tuple[UstarPackTask, ExecutableFixtureProfile]:
    if type(task) is not UstarPackTask:
        raise UstarPackError("task has the wrong exact type")
    if type(profile) is not ExecutableFixtureProfile:
        raise UstarPackError("profile has the wrong exact type")
    if (
        type(profile.profile_id) is not str
        or type(profile.cases) is not tuple
        or any(type(case) is not str for case in profile.cases)
        or type(profile.profile_sha256) is not str
        or type(profile.profile_version) is not str
    ):
        raise UstarPackError("profile nested types are invalid")
    try:
        task.__post_init__()
        UstarPackParameters(
            task.parameters.selector,
            task.parameters.archive_mode_policy,
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
        raise UstarPackError("task/profile revalidation failed") from exc
    if rebuilt_profile not in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
        raise UstarPackError("profile is not public method-development data")
    return task, profile


def _construct_ustar_pack_fixture_bundle(
    task: UstarPackTask,
    profile: ExecutableFixtureProfile,
) -> UstarPackFixtureBundle:
    """Construct a fixture while bootstrapping task descriptors."""

    selected_task, selected_profile = _validate_task_profile(task, profile)
    inputs = _fixture_inputs(selected_profile)
    definition = FixtureDefinition(
        fixture_id=f"fixture.{selected_task.task_id}.{selected_profile.profile_id}",
        inputs=inputs,
        expected_files=(
            ExpectedFile(
                USTAR_PACK_OUTPUT,
                maximum_bytes=USTAR_PACK_OUTPUT_MAXIMUM_BYTES,
                mode=USTAR_PACK_OUTPUT_MODE,
            ),
        ),
    )
    primary = derive_ustar_pack_output(definition, selected_task.parameters)
    reference = reference_ustar_pack_output(definition, selected_task.parameters)
    if primary != reference:
        raise UstarPackError("independent canonical archive producers disagree")
    if not verify_ustar_pack_output(definition, selected_task.parameters, primary):
        raise UstarPackError("canonical archive fails semantic verification")
    outputs = (
        OracleOutputRecord(
            USTAR_PACK_OUTPUT,
            primary,
            USTAR_PACK_OUTPUT_MODE,
        ),
    )
    oracle = UstarPackOracle(outputs, _compute_oracle_sha256(outputs))
    definition_sha256 = compute_fixture_definition_semantic_sha256(definition)
    fixture_sha256 = compute_bound_fixture_sha256(
        task_contract_sha256=selected_task.task_contract_sha256,
        profile_sha256=selected_profile.profile_sha256,
        fixture_definition_sha256=definition_sha256,
        oracle_sha256=oracle.oracle_sha256,
    )
    return UstarPackFixtureBundle(
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


def build_ustar_pack_fixture_bundle(
    task: UstarPackTask,
    profile: ExecutableFixtureProfile,
) -> UstarPackFixtureBundle:
    """Build one fixture and require its task descriptor to agree."""

    selected_task, selected_profile = _validate_task_profile(task, profile)
    bundle = _construct_ustar_pack_fixture_bundle(selected_task, selected_profile)
    profile_index = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES.index(selected_profile)
    if selected_task.fixtures[profile_index] != bundle.descriptor:
        raise UstarPackError(
            "generated descriptor differs from the task's selected profile"
        )
    return bundle


def validate_ustar_pack_fixture_for_task_profile(
    task: UstarPackTask,
    profile: ExecutableFixtureProfile,
    bundle: UstarPackFixtureBundle,
) -> None:
    """Authenticate a bundle by deterministic task/profile reconstruction."""

    selected_task, selected_profile = _validate_task_profile(task, profile)
    validate_ustar_pack_fixture_bundle(bundle)
    expected = build_ustar_pack_fixture_bundle(selected_task, selected_profile)
    if bundle != expected:
        raise UstarPackError("bundle differs from deterministic reconstruction")
    profile_index = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES.index(selected_profile)
    if selected_task.fixtures[profile_index] != expected.descriptor:
        raise UstarPackError("task descriptor differs from fixture")


def verify_ustar_pack_fixture_for_task_profile(
    task: object,
    profile: object,
    bundle: object,
) -> bool:
    try:
        validate_ustar_pack_fixture_for_task_profile(
            task,  # type: ignore[arg-type]
            profile,  # type: ignore[arg-type]
            bundle,  # type: ignore[arg-type]
        )
    except (UstarPackError, TypeError, ValueError):
        return False
    return True


def materialize_ustar_pack_fixture(
    task: UstarPackTask,
    profile: ExecutableFixtureProfile,
    bundle: UstarPackFixtureBundle,
    workspace: str | os.PathLike[str],
) -> WorkspaceHandle:
    """Authenticate then use the shared descriptor-relative materializer."""

    validate_ustar_pack_fixture_for_task_profile(task, profile, bundle)
    return materialize_fixture(bundle.definition, workspace)


def verify_ustar_pack_workspace(
    task: UstarPackTask,
    profile: ExecutableFixtureProfile,
    bundle: UstarPackFixtureBundle,
    handle: WorkspaceHandle,
) -> bool:
    """Verify a quiescent complete workspace without executing a candidate.

    A trusted harness must stop all candidate processes and other writers
    before entry and retain quiescence through return.  Stable no-follow scans
    detect changes between observations but do not prove global quiescence or
    exclude a write after the final scan.  The candidate archive is released
    only through bounded descriptor-relative egress and is checked
    semantically, permitting only a different valid count of trailing zero
    blocks from the canonical oracle bytes.
    """

    if type(handle) is not WorkspaceHandle:
        return False
    try:
        validate_ustar_pack_fixture_for_task_profile(task, profile, bundle)
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
            or output_entries[0].path != USTAR_PACK_OUTPUT
            or output_entries[0].mode != USTAR_PACK_OUTPUT_MODE
        ):
            return False
        payload = handle.read_output_bytes(output_scan, USTAR_PACK_OUTPUT)
        primary = derive_ustar_pack_output(bundle.definition, task.parameters)
        reference = reference_ustar_pack_output(
            bundle.definition, task.parameters
        )
        if (
            primary != reference
            or primary != bundle.oracle.outputs[0].content
            or bundle.oracle.outputs[0].mode != USTAR_PACK_OUTPUT_MODE
            or not verify_ustar_pack_output(
                bundle.definition, task.parameters, payload
            )
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
        OSError,
        tarfile.TarError,
        UstarPackError,
        TypeError,
        ValueError,
    ):
        return False


__all__ = [
    "USTAR_PACK_ALLOWED_TOOLS",
    "USTAR_PACK_DIRECTORY_PERMISSION_ERRORS_COVERED",
    "USTAR_PACK_EFFECTIVE_ACCESS_FAILURES_COVERED",
    "USTAR_PACK_FAMILY_ID",
    "USTAR_PACK_GENERATOR_VERSION",
    "USTAR_PACK_MODE_POLICIES",
    "USTAR_PACK_MODE_UNREADABLE_LEAVES_COVERED",
    "USTAR_PACK_OUTPUT",
    "USTAR_PACK_OUTPUT_MAXIMUM_BYTES",
    "USTAR_PACK_SELECTORS",
    "USTAR_PACK_SYMLINKS_COVERED",
    "USTAR_PACK_VERIFIER_IDENTITY",
    "USTAR_PACK_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE",
    "USTAR_PACK_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE",
    "UstarPackError",
    "UstarPackFixtureBundle",
    "UstarPackMember",
    "UstarPackOracle",
    "UstarPackParameters",
    "UstarPackTask",
    "build_ustar_pack_fixture_bundle",
    "build_ustar_pack_tasks",
    "compute_ustar_pack_task_sha256",
    "derive_ustar_pack_members",
    "derive_ustar_pack_output",
    "materialize_ustar_pack_fixture",
    "reference_ustar_pack_members",
    "reference_ustar_pack_output",
    "ustar_pack_task_semantic_core",
    "validate_ustar_pack_fixture_bundle",
    "validate_ustar_pack_fixture_for_task_profile",
    "verify_ustar_pack_fixture_bundle",
    "verify_ustar_pack_fixture_for_task_profile",
    "verify_ustar_pack_output",
    "verify_ustar_pack_workspace",
]
