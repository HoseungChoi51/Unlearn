"""Executable-static compressed ustar roundtrip and evidence-report family.

Every task consumes an exact NUL-framed manifest of owner-readable source
names, creates one normalized POSIX-ustar archive in the selected outer
encoding, exposes the extracted regular-file tree, and emits one of five
closed evidence projections.  The trusted verifier checks the full archive
and roundtrip tree for every policy; the policy controls only the observable
``verification.tsv`` schema.

This module never executes candidate code.  Final-state evidence cannot prove
that a candidate actually performed a verification step, used a declared
tool, or had any particular transient history.
"""

from __future__ import annotations

import bz2
from dataclasses import dataclass, field, replace
import gzip
from hashlib import sha256
import lzma
import os
from pathlib import PurePosixPath
import re
from typing import Final, Literal, TypeAlias
import zlib

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
from .executable_ustar_pack import (
    USTAR_PACK_OUTPUT_MAXIMUM_BYTES,
    UstarPackMember,
    UstarPackParameters,
    derive_ustar_pack_members,
    derive_ustar_pack_output,
    reference_ustar_pack_members,
    reference_ustar_pack_output,
    verify_ustar_pack_output,
)
from .executable_workspace import (
    ExecutableWorkspaceError,
    ExpectedFile,
    FixtureDefinition,
    InputFile,
    InputHardlink,
    InputSymlink,
    WorkspaceHandle,
    materialize_fixture,
    validate_expected_output_policy,
)


COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_FAMILY_ID: Final[str] = (
    "compressed-archive-roundtrip-verify"
)
COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_FILESYSTEM_IDENTITY: Final[str] = (
    "archive-roundtrip-source-tree"
)
COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_OUTPUT_IDENTITY: Final[str] = (
    "compressed-archive-with-verification-report"
)
COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_GENERATOR_VERSION: Final[str] = "1.0.0"
COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_VERIFIER_IDENTITY: Final[str] = (
    "verify-compressed-archive-roundtrip-v1"
)
COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_SOURCE_ROOT: Final[PurePosixPath] = (
    PurePosixPath("input/source")
)
COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_MANIFEST: Final[str] = "input/members.nul"
COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_OUTPUT_ROOT: Final[PurePosixPath] = (
    PurePosixPath("output/roundtrip")
)
COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_REPORT: Final[str] = (
    "output/verification.tsv"
)
COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_OUTPUT_MODE: Final[int] = 0o644
COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_MAXIMUM_ARCHIVE_BYTES: Final[int] = (
    1024 * 1024
)
COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_MAXIMUM_REPORT_BYTES: Final[int] = (
    256 * 1024
)
COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_MAXIMUM_FILE_BYTES: Final[int] = 16 * 1024
COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_MAXIMUM_MANIFEST_BYTES: Final[int] = (
    64 * 1024
)
COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_MAXIMUM_MEMBERS: Final[int] = 64
COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_XZ_DECODER_MEMLIMIT_BYTES: Final[int] = (
    64 * 1024 * 1024
)
COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_ALLOWED_TOOLS: Final[tuple[str, ...]] = (
    "bzip2",
    "gzip",
    "mkdir",
    "sha256sum",
    "sort",
    "tar",
    "xz",
)

# Honest observation boundaries.
COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_FINAL_ARCHIVE_OBSERVED: Final[bool] = True
COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_FINAL_TREE_OBSERVED: Final[bool] = True
COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_INPUT_HARDLINKS_COVERED: Final[bool] = True
COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_SYMLINK_DISTRACTORS_COVERED: Final[bool] = (
    True
)
COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_VERIFICATION_HISTORY_OBSERVED: Final[
    bool
] = False
COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_TOOL_HISTORY_OBSERVED: Final[bool] = False
COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_CANDIDATE_EXIT_STATUS_OBSERVED: Final[
    bool
] = False
COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE: Final[
    bool
] = True
COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE: Final[
    bool
] = False

CompressionFormat: TypeAlias = Literal["gzip", "bzip2", "xz", "none"]
VerificationPolicy: TypeAlias = Literal[
    "archive-digest",
    "member-digests",
    "roundtrip-bytes",
    "roundtrip-bytes-and-modes",
    "strict-all",
]

COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_COMPRESSION_FORMATS: Final[
    tuple[CompressionFormat, ...]
] = ("gzip", "bzip2", "xz", "none")
COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_VERIFICATION_POLICIES: Final[
    tuple[VerificationPolicy, ...]
] = (
    "archive-digest",
    "member-digests",
    "roundtrip-bytes",
    "roundtrip-bytes-and-modes",
    "strict-all",
)
COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_ARCHIVE_PATHS: Final[
    dict[CompressionFormat, str]
] = {
    "gzip": "output/package.tar.gz",
    "bzip2": "output/package.tar.bz2",
    "xz": "output/package.tar.xz",
    "none": "output/package.tar",
}

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_TASK_ID_RE: Final[re.Pattern[str]] = re.compile(r"mds-[0-9a-f]{24}\Z")
_MODE_RE: Final[re.Pattern[str]] = re.compile(r"0[0-7]{3}\Z")
_GZIP_MAGIC: Final[bytes] = b"\x1f\x8b"
_BZIP2_MAGIC: Final[bytes] = b"BZh"
_XZ_MAGIC: Final[bytes] = b"\xfd7zXZ\x00"


class CompressedArchiveRoundtripVerifyError(ValueError):
    """Raised when a task, fixture, archive, or final state fails closed."""


def _raw(value: str) -> bytes:
    return value.encode("utf-8")


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def _closed_text(value: object, allowed: tuple[str, ...], label: str) -> str:
    if type(value) is not str or value not in allowed:
        raise CompressedArchiveRoundtripVerifyError(
            f"{label} is outside the closed family contract"
        )
    return value


def _validate_relative_member(value: object) -> str:
    if type(value) is not str or not value:
        raise CompressedArchiveRoundtripVerifyError("member path is invalid")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise CompressedArchiveRoundtripVerifyError(
            "member path is not UTF-8"
        ) from exc
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or len(encoded) > 255
        or any(len(part.encode("utf-8")) > 100 for part in path.parts)
    ):
        raise CompressedArchiveRoundtripVerifyError(
            "member path is not canonical and ustar-safe"
        )
    return value


@dataclass(frozen=True, slots=True)
class CompressedArchiveRoundtripVerifyParameters:
    compression_format: CompressionFormat
    verification_policy: VerificationPolicy

    def __post_init__(self) -> None:
        if type(self) is not CompressedArchiveRoundtripVerifyParameters:
            raise CompressedArchiveRoundtripVerifyError(
                "parameters have wrong exact type"
            )
        _closed_text(
            self.compression_format,
            COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_COMPRESSION_FORMATS,
            "compression_format",
        )
        _closed_text(
            self.verification_policy,
            COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_VERIFICATION_POLICIES,
            "verification_policy",
        )

    def to_record(self) -> dict[str, str]:
        self.__post_init__()
        return {
            "parameter_type": COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_FAMILY_ID,
            "compression_format": self.compression_format,
            "verification_policy": self.verification_policy,
        }


_FORMAT_TEXT: Final[dict[CompressionFormat, str]] = {
    "gzip": (
        "encode it as exactly one gzip member with mtime zero and no optional "
        "header fields"
    ),
    "bzip2": "encode it as exactly one bzip2 stream",
    "xz": "encode it as exactly one XZ stream with a CRC64 integrity check",
    "none": "leave it as the raw POSIX-ustar byte stream",
}
_POLICY_TEXT: Final[dict[VerificationPolicy, str]] = {
    "archive-digest": (
        "one archive row binding the format, output path, and actual archive digest"
    ),
    "member-digests": (
        "a member-count header and one path/digest row per archive member"
    ),
    "roundtrip-bytes": (
        "a member-count header and one path/source-digest/roundtrip-digest row"
    ),
    "roundtrip-bytes-and-modes": (
        "a member-count header and one path/mode/source-digest/"
        "roundtrip-digest row"
    ),
    "strict-all": (
        "one strict header binding format, path, actual archive digest, "
        "decompressed-ustar digest, and member count, followed by path/mode/"
        "source/member/roundtrip digest rows"
    ),
}


def _task_contract(
    parameters: CompressedArchiveRoundtripVerifyParameters,
) -> tuple[str, NormalizedSemanticGraph]:
    archive_path = COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_ARCHIVE_PATHS[
        parameters.compression_format
    ]
    prompt = f"""Write one Bash program that operates only in the current workspace.

`input/members.nul` is an exact sequence of NUL-terminated pairs
RELATIVE-PATH, MODE.  RELATIVE-PATH is a canonical strict-UTF-8 path below
`input/source/`, contains no ASCII control or DEL byte, and is representable
in POSIX ustar.  MODE is exactly four octal digits including a leading zero.
Rows are unique and physical row order is nonsemantic.  Every listed name is
an owner-readable no-follow regular file and its permission bits equal MODE.
Multiple listed names may already share an inode; each pathname is a distinct
member.  Unlisted regular files and symbolic links are distractors.

Sort listed paths by raw UTF-8 bytes under `LC_ALL=C`.  Create one POSIX-ustar
archive containing exactly one regular member per listed path, in that order,
with exact source bytes and MODE.  Store every listed hardlink name as a
regular member, not a hard-link record.  Set uid, gid, and mtime to decimal
zero, leave uname and gname empty, use no PAX, GNU, long-name, sparse, or other
extension, and use at least two terminating zero blocks.  Then
{_FORMAT_TEXT[parameters.compression_format]} and write the result to
`{archive_path}` as an independent mode-0644, link-count-one regular file.

Extract the archive into `output/roundtrip/`.  The final tree must contain
exactly the listed regular paths, each with its source bytes, declared MODE,
mtime zero, and link count one.  It must contain no archive hardlinks,
symbolic links, or extra paths.  All required output directories are real
mode-0755 directories.

Write mode-0644 `output/verification.tsv` as strict UTF-8 with LF endings and
raw-path-byte-sorted rows.  For policy `{parameters.verification_policy}`, emit
{_POLICY_TEXT[parameters.verification_policy]}.  Hex digests are lowercase
SHA-256.  The exact schemas are:

archive-digest:
archive<TAB>FORMAT<TAB>ARCHIVE-PATH<TAB>ARCHIVE-SHA256

member-digests:
members<TAB>COUNT
member<TAB>PATH<TAB>MEMBER-SHA256

roundtrip-bytes:
roundtrip-bytes<TAB>COUNT
file<TAB>PATH<TAB>SOURCE-SHA256<TAB>ROUNDTRIP-SHA256

roundtrip-bytes-and-modes:
roundtrip-bytes-and-modes<TAB>COUNT
file<TAB>PATH<TAB>MODE<TAB>SOURCE-SHA256<TAB>ROUNDTRIP-SHA256

strict-all:
strict<TAB>FORMAT<TAB>ARCHIVE-PATH<TAB>ARCHIVE-SHA256<TAB>USTAR-SHA256<TAB>COUNT
file<TAB>PATH<TAB>MODE<TAB>SOURCE-SHA256<TAB>MEMBER-SHA256<TAB>ROUNDTRIP-SHA256

Preserve every input path, kind, byte, permission mode, modification time,
link count, symlink target, and visible hardlink topology.  Leave no staging
or extra output path.  The scored check observes final archive semantics,
compression framing, the complete roundtrip tree, and the candidate-relative
report.  It does not prove verification history, tool history, transient
state, global quiescence, or exit status.  Use only Bash built-ins plus
`bzip2`, `gzip`, `mkdir`, `sha256sum`, `sort`, `tar`, and `xz`.
"""
    graph = NormalizedSemanticGraph(
        nodes=(
            OperatorNode(
                "parse_archive_member_manifest",
                ("path:input/members.nul", "framing:nul-pairs"),
            ),
            OperatorNode(
                "encode_normalized_posix_ustar",
                (
                    "members:listed-regular-names",
                    "order:raw-utf8",
                    "metadata:uid-gid-mtime-zero",
                ),
            ),
            OperatorNode(
                "encode_archive_stream",
                (f"format:{parameters.compression_format}",),
            ),
            OperatorNode(
                "materialize_roundtrip_tree",
                ("root:output/roundtrip", "regular-only", "mtime:zero"),
            ),
            OperatorNode(
                "emit_verification_projection",
                (
                    f"policy:{parameters.verification_policy}",
                    "path:output/verification.tsv",
                ),
            ),
        ),
        dependencies=((0, 1), (1, 2), (2, 3), (0, 4), (2, 4), (3, 4)),
    )
    return prompt, graph


def _validate_graph(graph: object) -> NormalizedSemanticGraph:
    if type(graph) is not NormalizedSemanticGraph:
        raise CompressedArchiveRoundtripVerifyError("graph has wrong exact type")
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
        raise CompressedArchiveRoundtripVerifyError(
            "graph reconstruction failed"
        ) from exc
    if rebuilt != graph or len(rebuilt.nodes) != len(graph.nodes):
        raise CompressedArchiveRoundtripVerifyError("graph is noncanonical")
    return graph


def compressed_archive_roundtrip_verify_task_semantic_core(
    parameters: CompressedArchiveRoundtripVerifyParameters,
    prompt: str,
    graph: NormalizedSemanticGraph,
) -> dict[str, object]:
    if type(parameters) is not CompressedArchiveRoundtripVerifyParameters:
        raise CompressedArchiveRoundtripVerifyError(
            "parameters have wrong exact type"
        )
    parameters.__post_init__()
    expected_prompt, expected_graph = _task_contract(parameters)
    if (
        type(prompt) is not str
        or prompt != expected_prompt
        or _validate_graph(graph) != expected_graph
    ):
        raise CompressedArchiveRoundtripVerifyError("prompt or graph differs")
    return {
        "schema_version": EXECUTABLE_STATIC_SCHEMA_VERSION,
        "contract_version": EXECUTABLE_STATIC_CONTRACT_VERSION,
        "split_role": METHOD_DEVELOPMENT_SPLIT,
        "family_id": COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_FAMILY_ID,
        "family_version": EXECUTABLE_STATIC_FAMILY_VERSION,
        "generator_version": COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_GENERATOR_VERSION,
        "parameters": parameters.to_record(),
        "prompt": prompt,
        "graph": graph.to_record(),
        "graph_sha256": graph.hash,
        "filesystem_identity": (
            COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_FILESYSTEM_IDENTITY
        ),
        "output_identity": COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_OUTPUT_IDENTITY,
        "allowed_tools": list(
            COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_ALLOWED_TOOLS
        ),
        "public": True,
        "sealed": False,
        "candidate_execution_authorized": False,
        "model_selection_eligible": False,
        "claim_authorized": False,
    }


def compute_compressed_archive_roundtrip_verify_task_sha256(
    parameters: CompressedArchiveRoundtripVerifyParameters,
    prompt: str,
    graph: NormalizedSemanticGraph,
) -> str:
    return domain_sha256(
        "cbds.executable-static.task-contract.v1",
        compressed_archive_roundtrip_verify_task_semantic_core(
            parameters, prompt, graph
        ),
    )


@dataclass(frozen=True, slots=True)
class CompressedArchiveRoundtripVerifyTask:
    task_id: str
    parameters: CompressedArchiveRoundtripVerifyParameters
    prompt: str
    graph: NormalizedSemanticGraph
    fixtures: tuple[OpaqueFixtureDescriptor, ...]
    task_contract_sha256: str
    family_id: str = COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_FAMILY_ID
    family_version: str = EXECUTABLE_STATIC_FAMILY_VERSION
    filesystem_identity: str = (
        COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_FILESYSTEM_IDENTITY
    )
    output_identity: str = COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_OUTPUT_IDENTITY
    allowed_tools: tuple[str, ...] = (
        COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_ALLOWED_TOOLS
    )
    split_role: str = METHOD_DEVELOPMENT_SPLIT
    public: bool = True
    sealed: bool = False
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        if (
            type(self) is not CompressedArchiveRoundtripVerifyTask
            or type(self.parameters)
            is not CompressedArchiveRoundtripVerifyParameters
            or self.family_id != COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_FAMILY_ID
            or self.family_version != EXECUTABLE_STATIC_FAMILY_VERSION
            or self.filesystem_identity
            != COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_FILESYSTEM_IDENTITY
            or self.output_identity
            != COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_OUTPUT_IDENTITY
            or type(self.allowed_tools) is not tuple
            or self.allowed_tools
            != COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_ALLOWED_TOOLS
            or self.split_role != METHOD_DEVELOPMENT_SPLIT
            or self.public is not True
            or self.sealed is not False
            or self.candidate_execution_authorized is not False
            or self.model_selection_eligible is not False
            or self.claim_authorized is not False
        ):
            raise CompressedArchiveRoundtripVerifyError(
                "task metadata is invalid"
            )
        expected = compute_compressed_archive_roundtrip_verify_task_sha256(
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
            raise CompressedArchiveRoundtripVerifyError(
                "task identity is invalid"
            )
        for descriptor in self.fixtures:
            descriptor.__post_init__()
        if (
            len({item.fixture_id for item in self.fixtures}) != len(self.fixtures)
            or any(
                item.task_contract_sha256 != expected for item in self.fixtures
            )
        ):
            raise CompressedArchiveRoundtripVerifyError(
                "task descriptor binding is invalid"
            )

    @property
    def graph_sha256(self) -> str:
        self.__post_init__()
        return self.graph.hash

    def to_public_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            **compressed_archive_roundtrip_verify_task_semantic_core(
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
                f"fx-{digest[:24]}",
                digest,
                task_contract_sha256,
            )
        )
    return tuple(values)


def _bootstrap_task(
    parameters: CompressedArchiveRoundtripVerifyParameters,
) -> CompressedArchiveRoundtripVerifyTask:
    prompt, graph = _task_contract(parameters)
    digest = compute_compressed_archive_roundtrip_verify_task_sha256(
        parameters, prompt, graph
    )
    return CompressedArchiveRoundtripVerifyTask(
        task_id_from_contract(digest),
        parameters,
        prompt,
        graph,
        _bootstrap_descriptors(digest),
        digest,
    )


@dataclass(frozen=True, slots=True)
class _FixtureSeed:
    relative: str
    content: bytes
    mode: int
    mtime_seconds: int
    listed: bool = True
    hardlink_target: str = ""


_LONG_MEMBER: Final[str] = (
    "portable-prefix-segment-with-many-characters/"
    "second-prefix-segment-for-ustar/"
    "unicode-café-雪-report.txt"
)


def _base_seeds() -> tuple[_FixtureSeed, ...]:
    return (
        _FixtureSeed("probe/plain.txt", b"plain\n", 0o640, 1_001),
        _FixtureSeed("probe/empty.bin", b"", 0o400, 1_002),
        _FixtureSeed(
            "probe/binary.dat", b"\x00\xffbinary\r\n", 0o604, 1_003
        ),
        _FixtureSeed("links/00-base.bin", b"hardlink bytes\n", 0o644, 1_004),
        _FixtureSeed(
            "links/alias.bin",
            b"hardlink bytes\n",
            0o644,
            1_004,
            True,
            "links/00-base.bin",
        ),
    )


def _profile_seeds(profile_id: str) -> tuple[_FixtureSeed, ...]:
    if profile_id == "spaces-unicode":
        return (
            _FixtureSeed("space dir/café 雪.txt", "snow 雪\n".encode(), 0o604, 1_011),
            _FixtureSeed(_LONG_MEMBER, b"ustar prefix field\n", 0o700, 1_012),
        )
    if profile_id == "leading-dashes-globs":
        return (
            _FixtureSeed("-[draft]*?.txt", b"a" * 511, 0o600, 1_021),
            _FixtureSeed("-nested[?]/--block*.bin", b"b" * 512, 0o640, 1_022),
            _FixtureSeed("-nested[?]/-tail?.bin", b"c" * 513, 0o604, 1_023),
        )
    if profile_id == "empty-duplicates":
        duplicate = b"duplicate payload\n"
        return (
            _FixtureSeed("duplicates/one.txt", duplicate, 0o600, 1_031),
            _FixtureSeed("duplicates/two.txt", duplicate, 0o644, 1_032),
            _FixtureSeed("duplicates/empty.txt", b"", 0o440, 1_033),
        )
    if profile_id == "symlinks-ordering":
        return (
            _FixtureSeed("z-last/report.txt", b"z\n", 0o644, 1_041),
            _FixtureSeed("a-first/report.txt", b"a\n", 0o600, 1_042),
            _FixtureSeed("middle/é.txt", b"middle\n", 0o640, 1_043),
        )
    if profile_id == "partial-permissions":
        return (
            _FixtureSeed("modes/owner-only.txt", b"owner\n", 0o400, 1_051),
            _FixtureSeed("modes/owner-group.txt", b"group\n", 0o440, 1_052),
            _FixtureSeed("modes/owner-other.txt", b"other\n", 0o404, 1_053),
            _FixtureSeed("ignored/group-only.txt", b"hidden\n", 0o040, 1_054, False),
            _FixtureSeed("ignored/other-only.txt", b"hidden\n", 0o004, 1_055, False),
            _FixtureSeed("ignored/no-access.txt", b"hidden\n", 0o000, 1_056, False),
            _FixtureSeed("ignored/execute-only.sh", b"hidden\n", 0o111, 1_057, False),
        )
    raise CompressedArchiveRoundtripVerifyError("profile id is invalid")


def _manifest_bytes(seeds: tuple[_FixtureSeed, ...], *, reverse: bool) -> bytes:
    listed = tuple(seed for seed in seeds if seed.listed)
    if reverse:
        listed = tuple(reversed(listed))
    payload = bytearray()
    for seed in listed:
        payload.extend(seed.relative.encode("utf-8"))
        payload.append(0)
        payload.extend(f"{seed.mode:04o}".encode("ascii"))
        payload.append(0)
    return bytes(payload)


def _fixture_inputs(
    profile: ExecutableFixtureProfile,
) -> tuple[InputFile | InputHardlink | InputSymlink, ...]:
    seeds = _base_seeds() + _profile_seeds(profile.profile_id)
    inputs: list[InputFile | InputHardlink | InputSymlink] = [
        InputFile(
            COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_MANIFEST,
            _manifest_bytes(
                seeds, reverse=profile.profile_id == "symlinks-ordering"
            ),
            0o600,
            900,
        )
    ]
    for seed in seeds:
        path = (
            COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_SOURCE_ROOT / seed.relative
        ).as_posix()
        if seed.hardlink_target:
            inputs.append(
                InputHardlink(
                    path,
                    (
                        COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_SOURCE_ROOT
                        / seed.hardlink_target
                    ).as_posix(),
                )
            )
        else:
            inputs.append(
                InputFile(path, seed.content, seed.mode, seed.mtime_seconds)
            )
    inputs.append(InputFile("input/outside/not-listed.bin", b"outside\n", 0o644, 800))
    inputs.append(InputSymlink("input/source/link-to-plain", "probe/plain.txt"))
    if profile.profile_id == "symlinks-ordering":
        inputs.append(InputSymlink("input/source/link-to-directory", "probe"))
        inputs.reverse()
    return tuple(inputs)


@dataclass(frozen=True, slots=True)
class ArchiveRoundtripSource:
    relative: str
    content: bytes = field(repr=False)
    mode: int

    def __post_init__(self) -> None:
        _validate_relative_member(self.relative)
        if (
            type(self.content) is not bytes
            or len(self.content)
            > COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_MAXIMUM_FILE_BYTES
            or type(self.mode) is not int
            or not 0 <= self.mode <= 0o777
            or self.mode & 0o400 == 0
        ):
            raise CompressedArchiveRoundtripVerifyError(
                "source record is invalid"
            )


def _parse_manifest(content: bytes) -> tuple[tuple[str, int], ...]:
    if (
        type(content) is not bytes
        or not content
        or len(content)
        > COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_MAXIMUM_MANIFEST_BYTES
    ):
        raise CompressedArchiveRoundtripVerifyError("manifest is invalid")
    fields = content.split(b"\0")
    if fields[-1:] != [b""] or (len(fields) - 1) % 2:
        raise CompressedArchiveRoundtripVerifyError(
            "manifest is not NUL-terminated pairs"
        )
    rows: list[tuple[str, int]] = []
    for offset in range(0, len(fields) - 1, 2):
        try:
            relative = fields[offset].decode("utf-8", "strict")
            mode_wire = fields[offset + 1].decode("ascii", "strict")
        except UnicodeError as exc:
            raise CompressedArchiveRoundtripVerifyError(
                "manifest encoding is invalid"
            ) from exc
        _validate_relative_member(relative)
        if _MODE_RE.fullmatch(mode_wire) is None:
            raise CompressedArchiveRoundtripVerifyError(
                "manifest mode is invalid"
            )
        rows.append((relative, int(mode_wire, 8)))
    if (
        not rows
        or len(rows) > COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_MAXIMUM_MEMBERS
        or len({row[0] for row in rows}) != len(rows)
    ):
        raise CompressedArchiveRoundtripVerifyError(
            "manifest member set is invalid"
        )
    return tuple(rows)


def _revalidate_definition(definition: object) -> FixtureDefinition:
    if type(definition) is not FixtureDefinition:
        raise CompressedArchiveRoundtripVerifyError(
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
        raise CompressedArchiveRoundtripVerifyError(
            "definition revalidation failed"
        ) from exc
    if rebuilt != definition or definition.expected_symlinks:
        raise CompressedArchiveRoundtripVerifyError(
            "definition is noncanonical"
        )
    return definition


def _source_records_primary(
    definition: FixtureDefinition,
) -> tuple[ArchiveRoundtripSource, ...]:
    selected = _revalidate_definition(definition)
    manifests = tuple(
        item
        for item in selected.inputs
        if type(item) is InputFile
        and item.path == COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_MANIFEST
    )
    if len(manifests) != 1:
        raise CompressedArchiveRoundtripVerifyError(
            "fixture must contain one manifest"
        )
    rows = _parse_manifest(manifests[0].content)
    files = {
        item.path: item for item in selected.inputs if type(item) is InputFile
    }
    aliases = {
        item.path: item.target
        for item in selected.inputs
        if type(item) is InputHardlink
    }
    prefix = COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_SOURCE_ROOT.as_posix() + "/"
    records: list[ArchiveRoundtripSource] = []
    for relative, declared_mode in rows:
        absolute = prefix + relative
        source = files.get(absolute)
        if source is None and absolute in aliases:
            source = files.get(aliases[absolute])
        if (
            source is None
            or source.mode != declared_mode
            or source.mode & 0o400 == 0
        ):
            raise CompressedArchiveRoundtripVerifyError(
                "manifest does not name an owner-readable matching file"
            )
        records.append(
            ArchiveRoundtripSource(relative, source.content, source.mode)
        )
    records.sort(key=lambda item: _raw(item.relative))
    return tuple(records)


def _source_records_reference(
    definition: FixtureDefinition,
) -> tuple[ArchiveRoundtripSource, ...]:
    selected = _revalidate_definition(definition)
    manifest: InputFile | None = None
    original: dict[str, tuple[bytes, int]] = {}
    alias: dict[str, str] = {}
    for item in selected.inputs:
        if type(item) is InputFile:
            if item.path == COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_MANIFEST:
                if manifest is not None:
                    raise CompressedArchiveRoundtripVerifyError(
                        "reference saw duplicate manifest"
                    )
                manifest = item
            else:
                original[item.path] = (item.content, item.mode)
        elif type(item) is InputHardlink:
            alias[item.path] = item.target
    if manifest is None:
        raise CompressedArchiveRoundtripVerifyError(
            "reference manifest is absent"
        )
    raw = manifest.content
    fields: list[bytes] = []
    cursor = 0
    while cursor < len(raw):
        marker = raw.find(b"\0", cursor)
        if marker < 0:
            raise CompressedArchiveRoundtripVerifyError(
                "reference manifest is unterminated"
            )
        fields.append(raw[cursor:marker])
        cursor = marker + 1
    if not fields or len(fields) % 2:
        raise CompressedArchiveRoundtripVerifyError(
            "reference manifest framing differs"
        )
    prefix = COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_SOURCE_ROOT.as_posix() + "/"
    records: dict[bytes, ArchiveRoundtripSource] = {}
    for index in range(0, len(fields), 2):
        try:
            relative = fields[index].decode("utf-8", "strict")
            mode_wire = fields[index + 1].decode("ascii", "strict")
        except UnicodeError as exc:
            raise CompressedArchiveRoundtripVerifyError(
                "reference manifest decoding failed"
            ) from exc
        _validate_relative_member(relative)
        if _MODE_RE.fullmatch(mode_wire) is None:
            raise CompressedArchiveRoundtripVerifyError(
                "reference mode differs"
            )
        absolute = prefix + relative
        values = original.get(absolute)
        if values is None and absolute in alias:
            values = original.get(alias[absolute])
        declared_mode = int(mode_wire, 8)
        if (
            values is None
            or values[1] != declared_mode
            or values[1] & 0o400 == 0
            or _raw(relative) in records
        ):
            raise CompressedArchiveRoundtripVerifyError(
                "reference source binding differs"
            )
        records[_raw(relative)] = ArchiveRoundtripSource(
            relative, values[0], values[1]
        )
    if (
        not records
        or len(records)
        > COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_MAXIMUM_MEMBERS
    ):
        raise CompressedArchiveRoundtripVerifyError(
            "reference member count differs"
        )
    return tuple(records[key] for key in sorted(records))


def _synthetic_ustar_definition(
    records: tuple[ArchiveRoundtripSource, ...],
) -> FixtureDefinition:
    return FixtureDefinition(
        "fixture.archive-roundtrip.synthetic",
        tuple(
            InputFile(
                (
                    COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_SOURCE_ROOT
                    / item.relative
                ).as_posix(),
                item.content,
                item.mode,
                0,
            )
            for item in records
        ),
        (
            ExpectedFile(
                "output/archive.tar",
                USTAR_PACK_OUTPUT_MAXIMUM_BYTES,
                0o644,
            ),
        ),
    )


def _ustar_parameters() -> UstarPackParameters:
    return UstarPackParameters(
        "all-mode-readable", "preserve-permission-bits"
    )


def _canonical_compress(raw_archive: bytes, format_name: CompressionFormat) -> bytes:
    if type(raw_archive) is not bytes:
        raise CompressedArchiveRoundtripVerifyError(
            "raw archive must be immutable bytes"
        )
    try:
        if format_name == "gzip":
            payload = gzip.compress(raw_archive, compresslevel=9, mtime=0)
            # CPython 3.11 may delegate ``mtime=0`` to zlib and copy zlib's
            # platform-specific OS byte into the otherwise canonical header;
            # 3.13+ guarantees 255.  The byte is descriptive only, so pin it
            # explicitly to keep fixture/oracle identities interpreter- and
            # platform-neutral across the supported Python matrix.
            if len(payload) < 10 or payload[:2] != _GZIP_MAGIC:
                raise CompressedArchiveRoundtripVerifyError(
                    "canonical gzip encoder returned an invalid header"
                )
            payload = payload[:9] + b"\xff" + payload[10:]
        elif format_name == "bzip2":
            payload = bz2.compress(raw_archive, compresslevel=9)
        elif format_name == "xz":
            payload = lzma.compress(
                raw_archive,
                format=lzma.FORMAT_XZ,
                check=lzma.CHECK_CRC64,
                # Preset 6 keeps the stream well below the explicit 64 MiB
                # decoder-memory ceiling while remaining the xz default.
                preset=6,
            )
        elif format_name == "none":
            payload = raw_archive
        else:
            raise CompressedArchiveRoundtripVerifyError(
                "compression format is invalid"
            )
    except (OSError, EOFError, lzma.LZMAError) as exc:
        raise CompressedArchiveRoundtripVerifyError(
            "canonical compression failed"
        ) from exc
    if len(payload) > COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_MAXIMUM_ARCHIVE_BYTES:
        raise CompressedArchiveRoundtripVerifyError(
            "canonical archive exceeds its bound"
        )
    return payload


def _bounded_buffered_decompressor(
    decompressor: object,
    payload: bytes,
) -> bytes:
    limit = USTAR_PACK_OUTPUT_MAXIMUM_BYTES
    try:
        output = bytearray(
            decompressor.decompress(payload, max_length=limit + 1)  # type: ignore[attr-defined]
        )
        while (
            len(output) <= limit
            and not decompressor.eof  # type: ignore[attr-defined]
            and not decompressor.needs_input  # type: ignore[attr-defined]
        ):
            chunk = decompressor.decompress(  # type: ignore[attr-defined]
                b"", max_length=limit + 1 - len(output)
            )
            if not chunk:
                break
            output.extend(chunk)
    except (EOFError, OSError, ValueError, lzma.LZMAError) as exc:
        raise CompressedArchiveRoundtripVerifyError(
            "compressed stream cannot be decoded"
        ) from exc
    if (
        len(output) > limit
        or not decompressor.eof  # type: ignore[attr-defined]
        or decompressor.unused_data  # type: ignore[attr-defined]
    ):
        raise CompressedArchiveRoundtripVerifyError(
            "compressed stream is truncated, concatenated, or oversized"
        )
    return bytes(output)


def decompress_compressed_archive_roundtrip_verify_output(
    payload: bytes,
    format_name: CompressionFormat,
) -> bytes:
    """Decode exactly one bounded outer stream into a raw ustar payload."""

    if (
        type(payload) is not bytes
        or not payload
        or len(payload)
        > COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_MAXIMUM_ARCHIVE_BYTES
    ):
        raise CompressedArchiveRoundtripVerifyError(
            "candidate archive violates its byte bound"
        )
    if format_name == "none":
        return payload
    if format_name == "gzip":
        if (
            len(payload) < 18
            or payload[:2] != _GZIP_MAGIC
            or payload[2] != 8
            or payload[3] != 0
            or payload[4:8] != b"\0\0\0\0"
        ):
            raise CompressedArchiveRoundtripVerifyError(
                "gzip header is outside the closed contract"
            )
        decoder = zlib.decompressobj(wbits=31)
        try:
            output = decoder.decompress(
                payload, USTAR_PACK_OUTPUT_MAXIMUM_BYTES + 1
            )
        except zlib.error as exc:
            raise CompressedArchiveRoundtripVerifyError(
                "gzip stream cannot be decoded"
            ) from exc
        if (
            len(output) > USTAR_PACK_OUTPUT_MAXIMUM_BYTES
            or not decoder.eof
            or decoder.unused_data
            or decoder.unconsumed_tail
        ):
            raise CompressedArchiveRoundtripVerifyError(
                "gzip stream is truncated, concatenated, or oversized"
            )
        return output
    if format_name == "bzip2":
        if (
            len(payload) < 10
            or payload[:3] != _BZIP2_MAGIC
            or payload[3:4] not in tuple(bytes((value,)) for value in range(49, 58))
        ):
            raise CompressedArchiveRoundtripVerifyError(
                "bzip2 header is outside the closed contract"
            )
        return _bounded_buffered_decompressor(
            bz2.BZ2Decompressor(), payload
        )
    if format_name == "xz":
        if len(payload) < 24 or payload[:6] != _XZ_MAGIC:
            raise CompressedArchiveRoundtripVerifyError(
                "xz header is outside the closed contract"
            )
        decoder = lzma.LZMADecompressor(
            format=lzma.FORMAT_XZ,
            memlimit=(
                COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_XZ_DECODER_MEMLIMIT_BYTES
            ),
        )
        output = _bounded_buffered_decompressor(decoder, payload)
        if decoder.check != lzma.CHECK_CRC64:
            raise CompressedArchiveRoundtripVerifyError(
                "xz stream does not use CRC64"
            )
        return output
    raise CompressedArchiveRoundtripVerifyError(
        "compression format is invalid"
    )


def _report(
    parameters: CompressedArchiveRoundtripVerifyParameters,
    records: tuple[ArchiveRoundtripSource, ...],
    archive: bytes,
    raw_archive: bytes,
) -> bytes:
    archive_path = COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_ARCHIVE_PATHS[
        parameters.compression_format
    ]
    count = len(records)
    archive_digest = sha256(archive).hexdigest()
    raw_digest = sha256(raw_archive).hexdigest()
    payload = bytearray()
    policy = parameters.verification_policy
    if policy == "archive-digest":
        payload.extend(
            (
                f"archive\t{parameters.compression_format}\t{archive_path}\t"
                f"{archive_digest}\n"
            ).encode("utf-8")
        )
    elif policy == "member-digests":
        payload.extend(f"members\t{count}\n".encode("ascii"))
        for item in records:
            digest = sha256(item.content).hexdigest()
            payload.extend(
                f"member\t{item.relative}\t{digest}\n".encode("utf-8")
            )
    elif policy == "roundtrip-bytes":
        payload.extend(f"roundtrip-bytes\t{count}\n".encode("ascii"))
        for item in records:
            digest = sha256(item.content).hexdigest()
            payload.extend(
                (
                    f"file\t{item.relative}\t{digest}\t{digest}\n"
                ).encode("utf-8")
            )
    elif policy == "roundtrip-bytes-and-modes":
        payload.extend(
            f"roundtrip-bytes-and-modes\t{count}\n".encode("ascii")
        )
        for item in records:
            digest = sha256(item.content).hexdigest()
            payload.extend(
                (
                    f"file\t{item.relative}\t{item.mode:04o}\t"
                    f"{digest}\t{digest}\n"
                ).encode("utf-8")
            )
    elif policy == "strict-all":
        payload.extend(
            (
                f"strict\t{parameters.compression_format}\t{archive_path}\t"
                f"{archive_digest}\t{raw_digest}\t{count}\n"
            ).encode("utf-8")
        )
        for item in records:
            digest = sha256(item.content).hexdigest()
            payload.extend(
                (
                    f"file\t{item.relative}\t{item.mode:04o}\t{digest}\t"
                    f"{digest}\t{digest}\n"
                ).encode("utf-8")
            )
    else:
        raise CompressedArchiveRoundtripVerifyError(
            "verification policy is invalid"
        )
    result = bytes(payload)
    if len(result) > COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_MAXIMUM_REPORT_BYTES:
        raise CompressedArchiveRoundtripVerifyError(
            "verification report exceeds its bound"
        )
    return result


@dataclass(frozen=True, slots=True)
class CompressedArchiveRoundtripVerifyState:
    records: tuple[ArchiveRoundtripSource, ...]
    members: tuple[UstarPackMember, ...]
    raw_archive: bytes = field(repr=False)
    archive: bytes = field(repr=False)
    report: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self) is not CompressedArchiveRoundtripVerifyState
            or type(self.records) is not tuple
            or not self.records
            or any(type(item) is not ArchiveRoundtripSource for item in self.records)
            or tuple(sorted(self.records, key=lambda item: _raw(item.relative)))
            != self.records
            or type(self.members) is not tuple
            or any(type(item) is not UstarPackMember for item in self.members)
            or type(self.raw_archive) is not bytes
            or type(self.archive) is not bytes
            or type(self.report) is not bytes
        ):
            raise CompressedArchiveRoundtripVerifyError("state is invalid")


def derive_compressed_archive_roundtrip_verify_state(
    definition: FixtureDefinition,
    parameters: CompressedArchiveRoundtripVerifyParameters,
) -> CompressedArchiveRoundtripVerifyState:
    if type(parameters) is not CompressedArchiveRoundtripVerifyParameters:
        raise CompressedArchiveRoundtripVerifyError(
            "parameters have wrong exact type"
        )
    parameters.__post_init__()
    records = _source_records_primary(definition)
    synthetic = _synthetic_ustar_definition(records)
    members = derive_ustar_pack_members(synthetic, _ustar_parameters())
    raw_archive = derive_ustar_pack_output(synthetic, _ustar_parameters())
    archive = _canonical_compress(raw_archive, parameters.compression_format)
    return CompressedArchiveRoundtripVerifyState(
        records,
        members,
        raw_archive,
        archive,
        _report(parameters, records, archive, raw_archive),
    )


def reference_compressed_archive_roundtrip_verify_state(
    definition: FixtureDefinition,
    parameters: CompressedArchiveRoundtripVerifyParameters,
) -> CompressedArchiveRoundtripVerifyState:
    if type(parameters) is not CompressedArchiveRoundtripVerifyParameters:
        raise CompressedArchiveRoundtripVerifyError(
            "reference parameters have wrong exact type"
        )
    parameters.__post_init__()
    records = _source_records_reference(definition)
    synthetic = _synthetic_ustar_definition(records)
    members = reference_ustar_pack_members(synthetic, _ustar_parameters())
    raw_archive = reference_ustar_pack_output(synthetic, _ustar_parameters())
    archive = _canonical_compress(raw_archive, parameters.compression_format)
    return CompressedArchiveRoundtripVerifyState(
        records,
        members,
        raw_archive,
        archive,
        _report(parameters, records, archive, raw_archive),
    )


def verify_compressed_archive_roundtrip_verify_archive(
    definition: FixtureDefinition,
    parameters: CompressedArchiveRoundtripVerifyParameters,
    candidate_archive: bytes,
) -> bool:
    if type(candidate_archive) is not bytes:
        return False
    try:
        primary = derive_compressed_archive_roundtrip_verify_state(
            definition, parameters
        )
        reference = reference_compressed_archive_roundtrip_verify_state(
            definition, parameters
        )
        raw = decompress_compressed_archive_roundtrip_verify_output(
            candidate_archive, parameters.compression_format
        )
        synthetic = _synthetic_ustar_definition(primary.records)
    except (
        CompressedArchiveRoundtripVerifyError,
        OSError,
        TypeError,
        ValueError,
    ):
        return False
    return (
        primary.records == reference.records
        and primary.members == reference.members
        and primary.raw_archive == reference.raw_archive
        and verify_ustar_pack_output(
            synthetic, _ustar_parameters(), raw
        )
    )


def derive_compressed_archive_roundtrip_verify_report(
    definition: FixtureDefinition,
    parameters: CompressedArchiveRoundtripVerifyParameters,
    candidate_archive: bytes,
) -> bytes:
    records = _source_records_primary(definition)
    raw = decompress_compressed_archive_roundtrip_verify_output(
        candidate_archive, parameters.compression_format
    )
    synthetic = _synthetic_ustar_definition(records)
    if not verify_ustar_pack_output(synthetic, _ustar_parameters(), raw):
        raise CompressedArchiveRoundtripVerifyError(
            "candidate archive semantics differ"
        )
    return _report(parameters, records, candidate_archive, raw)


def _expected_files(
    state: CompressedArchiveRoundtripVerifyState,
    parameters: CompressedArchiveRoundtripVerifyParameters,
) -> tuple[ExpectedFile, ...]:
    values = [
        ExpectedFile(
            COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_ARCHIVE_PATHS[
                parameters.compression_format
            ],
            COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_MAXIMUM_ARCHIVE_BYTES,
            COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_OUTPUT_MODE,
        ),
        ExpectedFile(
            COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_REPORT,
            COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_MAXIMUM_REPORT_BYTES,
            COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_OUTPUT_MODE,
        ),
    ]
    values.extend(
        ExpectedFile(
            (
                COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_OUTPUT_ROOT
                / item.relative
            ).as_posix(),
            COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_MAXIMUM_FILE_BYTES,
            item.mode,
        )
        for item in state.records
    )
    return tuple(sorted(values, key=lambda item: _raw(item.path)))


def _oracle_sha256(
    state: CompressedArchiveRoundtripVerifyState,
    parameters: CompressedArchiveRoundtripVerifyParameters,
) -> str:
    return domain_sha256(
        "cbds.executable-fixture.trusted-oracle.v1",
        {
            "schema_version": EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION,
            "semantic_verifier_identity": (
                COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_VERIFIER_IDENTITY
            ),
            "compression_format": parameters.compression_format,
            "verification_policy": parameters.verification_policy,
            "members": [
                {
                    "path": item.relative,
                    "mode": item.mode,
                    "size": len(item.content),
                    "sha256": sha256(item.content).hexdigest(),
                }
                for item in state.records
            ],
            "canonical_archive": OracleOutputRecord(
                COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_ARCHIVE_PATHS[
                    parameters.compression_format
                ],
                state.archive,
                COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_OUTPUT_MODE,
            ).commitment_record(),
            "canonical_report": OracleOutputRecord(
                COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_REPORT,
                state.report,
                COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_OUTPUT_MODE,
            ).commitment_record(),
        },
    )


@dataclass(frozen=True, slots=True)
class CompressedArchiveRoundtripVerifyOracle:
    state: CompressedArchiveRoundtripVerifyState = field(repr=False)
    compression_format: CompressionFormat
    verification_policy: VerificationPolicy
    oracle_sha256: str
    semantic_verifier_identity: str = (
        COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_VERIFIER_IDENTITY
    )
    schema_version: str = EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        parameters = CompressedArchiveRoundtripVerifyParameters(
            self.compression_format, self.verification_policy
        )
        self.state.__post_init__()
        if (
            type(self) is not CompressedArchiveRoundtripVerifyOracle
            or self.semantic_verifier_identity
            != COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_VERIFIER_IDENTITY
            or self.schema_version != EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION
            or not _is_sha256(self.oracle_sha256)
            or self.oracle_sha256 != _oracle_sha256(self.state, parameters)
        ):
            raise CompressedArchiveRoundtripVerifyError(
                "oracle identity is invalid"
            )

    def commitment_record(self) -> dict[str, object]:
        self.__post_init__()
        parameters = CompressedArchiveRoundtripVerifyParameters(
            self.compression_format, self.verification_policy
        )
        return {
            "schema_version": self.schema_version,
            "record_type": "cbds.executable-fixture-trusted-oracle",
            "semantic_verifier_identity": self.semantic_verifier_identity,
            "compression_format": self.compression_format,
            "verification_policy": self.verification_policy,
            "members": [
                {
                    "path": item.relative,
                    "mode": item.mode,
                    "size": len(item.content),
                    "sha256": sha256(item.content).hexdigest(),
                }
                for item in self.state.records
            ],
            "canonical_archive_sha256": sha256(self.state.archive).hexdigest(),
            "canonical_report_sha256": sha256(self.state.report).hexdigest(),
            "oracle_sha256": _oracle_sha256(self.state, parameters),
        }


@dataclass(frozen=True, slots=True)
class CompressedArchiveRoundtripVerifyFixtureBundle:
    task_contract_sha256: str
    profile_sha256: str
    definition: FixtureDefinition = field(repr=False)
    fixture_definition_sha256: str
    oracle: CompressedArchiveRoundtripVerifyOracle = field(repr=False)
    descriptor: OpaqueFixtureDescriptor
    schema_version: str = EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_compressed_archive_roundtrip_verify_fixture_bundle(self)

    def commitment_record(self) -> dict[str, object]:
        validate_compressed_archive_roundtrip_verify_fixture_bundle(self)
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


def validate_compressed_archive_roundtrip_verify_fixture_bundle(
    bundle: CompressedArchiveRoundtripVerifyFixtureBundle,
) -> None:
    if type(bundle) is not CompressedArchiveRoundtripVerifyFixtureBundle:
        raise CompressedArchiveRoundtripVerifyError(
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
        raise CompressedArchiveRoundtripVerifyError(
            "bundle metadata is invalid"
        )
    definition = _revalidate_definition(bundle.definition)
    definition_digest = compute_fixture_definition_semantic_sha256(definition)
    if definition_digest != bundle.fixture_definition_sha256:
        raise CompressedArchiveRoundtripVerifyError(
            "definition digest differs"
        )
    if type(bundle.oracle) is not CompressedArchiveRoundtripVerifyOracle:
        raise CompressedArchiveRoundtripVerifyError(
            "oracle has wrong exact type"
        )
    bundle.oracle.__post_init__()
    parameters = CompressedArchiveRoundtripVerifyParameters(
        bundle.oracle.compression_format, bundle.oracle.verification_policy
    )
    if definition.expected_files != _expected_files(
        bundle.oracle.state, parameters
    ):
        raise CompressedArchiveRoundtripVerifyError(
            "output policy differs from oracle state"
        )
    if type(bundle.descriptor) is not OpaqueFixtureDescriptor:
        raise CompressedArchiveRoundtripVerifyError(
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
        raise CompressedArchiveRoundtripVerifyError(
            "descriptor binding differs"
        )


def verify_compressed_archive_roundtrip_verify_fixture_bundle(
    bundle: object,
) -> bool:
    try:
        validate_compressed_archive_roundtrip_verify_fixture_bundle(
            bundle  # type: ignore[arg-type]
        )
    except (CompressedArchiveRoundtripVerifyError, TypeError, ValueError):
        return False
    return True


def _validate_task_profile(
    task: object, profile: object
) -> tuple[
    CompressedArchiveRoundtripVerifyTask,
    ExecutableFixtureProfile,
]:
    if type(task) is not CompressedArchiveRoundtripVerifyTask:
        raise CompressedArchiveRoundtripVerifyError(
            "task has wrong exact type"
        )
    if type(profile) is not ExecutableFixtureProfile:
        raise CompressedArchiveRoundtripVerifyError(
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
        raise CompressedArchiveRoundtripVerifyError(
            "task/profile reconstruction failed"
        ) from exc
    if rebuilt not in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
        raise CompressedArchiveRoundtripVerifyError(
            "profile is outside public development"
        )
    return task, profile


def _construct_compressed_archive_roundtrip_verify_fixture_bundle(
    task: CompressedArchiveRoundtripVerifyTask,
    profile: ExecutableFixtureProfile,
) -> CompressedArchiveRoundtripVerifyFixtureBundle:
    task, profile = _validate_task_profile(task, profile)
    inputs = _fixture_inputs(profile)
    provisional = FixtureDefinition(
        f"fixture.{task.task_id}.{profile.profile_id}", inputs, ()
    )
    primary = derive_compressed_archive_roundtrip_verify_state(
        provisional, task.parameters
    )
    reference = reference_compressed_archive_roundtrip_verify_state(
        provisional, task.parameters
    )
    if primary != reference:
        raise CompressedArchiveRoundtripVerifyError(
            "independent state engines disagree"
        )
    definition = FixtureDefinition(
        provisional.fixture_id,
        inputs,
        _expected_files(primary, task.parameters),
    )
    if (
        derive_compressed_archive_roundtrip_verify_state(
            definition, task.parameters
        )
        != primary
        or reference_compressed_archive_roundtrip_verify_state(
            definition, task.parameters
        )
        != reference
    ):
        raise CompressedArchiveRoundtripVerifyError(
            "final policy changed semantics"
        )
    oracle = CompressedArchiveRoundtripVerifyOracle(
        primary,
        task.parameters.compression_format,
        task.parameters.verification_policy,
        _oracle_sha256(primary, task.parameters),
    )
    definition_digest = compute_fixture_definition_semantic_sha256(definition)
    fixture_digest = compute_bound_fixture_sha256(
        task_contract_sha256=task.task_contract_sha256,
        profile_sha256=profile.profile_sha256,
        fixture_definition_sha256=definition_digest,
        oracle_sha256=oracle.oracle_sha256,
    )
    return CompressedArchiveRoundtripVerifyFixtureBundle(
        task.task_contract_sha256,
        profile.profile_sha256,
        definition,
        definition_digest,
        oracle,
        OpaqueFixtureDescriptor(
            f"fx-{fixture_digest[:24]}",
            fixture_digest,
            task.task_contract_sha256,
        ),
    )


def build_compressed_archive_roundtrip_verify_fixture_bundle(
    task: CompressedArchiveRoundtripVerifyTask,
    profile: ExecutableFixtureProfile,
) -> CompressedArchiveRoundtripVerifyFixtureBundle:
    selected_task, selected_profile = _validate_task_profile(task, profile)
    bundle = _construct_compressed_archive_roundtrip_verify_fixture_bundle(
        selected_task, selected_profile
    )
    index = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES.index(selected_profile)
    if selected_task.fixtures[index] != bundle.descriptor:
        raise CompressedArchiveRoundtripVerifyError(
            "task descriptor differs from fixture"
        )
    return bundle


def validate_compressed_archive_roundtrip_verify_fixture_for_task_profile(
    task: CompressedArchiveRoundtripVerifyTask,
    profile: ExecutableFixtureProfile,
    bundle: CompressedArchiveRoundtripVerifyFixtureBundle,
) -> None:
    task, profile = _validate_task_profile(task, profile)
    validate_compressed_archive_roundtrip_verify_fixture_bundle(bundle)
    expected = _construct_compressed_archive_roundtrip_verify_fixture_bundle(
        task, profile
    )
    if expected != bundle:
        raise CompressedArchiveRoundtripVerifyError(
            "bundle differs from deterministic reconstruction"
        )
    index = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES.index(profile)
    if task.fixtures[index] != bundle.descriptor:
        raise CompressedArchiveRoundtripVerifyError(
            "public descriptor differs"
        )


def verify_compressed_archive_roundtrip_verify_fixture_for_task_profile(
    task: object, profile: object, bundle: object
) -> bool:
    try:
        validate_compressed_archive_roundtrip_verify_fixture_for_task_profile(
            task,  # type: ignore[arg-type]
            profile,  # type: ignore[arg-type]
            bundle,  # type: ignore[arg-type]
        )
    except (CompressedArchiveRoundtripVerifyError, TypeError, ValueError):
        return False
    return True


def _discrimination_signature(
    bundle: CompressedArchiveRoundtripVerifyFixtureBundle,
) -> tuple[str, bytes, str]:
    state = bundle.oracle.state
    report_token = state.report.split(b"\t", 1)[0].decode("ascii")
    format_name = bundle.oracle.compression_format
    if format_name == "gzip":
        magic = state.archive[:2]
    elif format_name == "bzip2":
        magic = state.archive[:3]
    elif format_name == "xz":
        magic = state.archive[:6]
    else:
        magic = state.raw_archive[257:263]
    return (
        COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_ARCHIVE_PATHS[format_name],
        magic,
        report_token,
    )


def compute_compressed_archive_roundtrip_verify_discrimination_sha256(
    tasks: tuple[CompressedArchiveRoundtripVerifyTask, ...],
) -> str:
    expected = tuple(
        (format_name, policy)
        for format_name in COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_COMPRESSION_FORMATS
        for policy in COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_VERIFICATION_POLICIES
    )
    if (
        type(tasks) is not tuple
        or len(tasks) != 20
        or any(
            type(task) is not CompressedArchiveRoundtripVerifyTask
            for task in tasks
        )
        or tuple(
            (
                task.parameters.compression_format,
                task.parameters.verification_policy,
            )
            for task in tasks
        )
        != expected
    ):
        raise CompressedArchiveRoundtripVerifyError(
            "discrimination requires canonical task order"
        )
    profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
    records: list[dict[str, object]] = []
    signatures: list[tuple[str, bytes, str]] = []
    for task in tasks:
        bundle = _construct_compressed_archive_roundtrip_verify_fixture_bundle(
            task, profile
        )
        signature = _discrimination_signature(bundle)
        signatures.append(signature)
        records.append(
            {
                "task_id": task.task_id,
                "compression_format": task.parameters.compression_format,
                "verification_policy": task.parameters.verification_policy,
                "archive_path": signature[0],
                "archive_magic_hex": signature[1].hex(),
                "report_record_type": signature[2],
                "fixture_sha256": bundle.descriptor.fixture_sha256,
            }
        )
    if len(set(signatures)) != 20:
        raise CompressedArchiveRoundtripVerifyError(
            "grid is not behaviorally discriminable"
        )
    return domain_sha256(
        "cbds.executable-static.compressed-archive-roundtrip-verify."
        "discrimination-evidence.v1",
        {
            "family_id": COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_FAMILY_ID,
            "profile_sha256": profile.profile_sha256,
            "signature_count": len(records),
            "signatures": records,
        },
    )


def build_compressed_archive_roundtrip_verify_tasks() -> tuple[
    CompressedArchiveRoundtripVerifyTask, ...
]:
    tasks: list[CompressedArchiveRoundtripVerifyTask] = []
    signatures: list[tuple[str, bytes, str]] = []
    for format_name in COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_COMPRESSION_FORMATS:
        for policy in COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_VERIFICATION_POLICIES:
            bootstrap = _bootstrap_task(
                CompressedArchiveRoundtripVerifyParameters(
                    format_name, policy
                )
            )
            bundles = tuple(
                _construct_compressed_archive_roundtrip_verify_fixture_bundle(
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
        raise CompressedArchiveRoundtripVerifyError(
            "task grid is not 20 fully discriminable cells"
        )
    return selected


def materialize_compressed_archive_roundtrip_verify_fixture(
    task: CompressedArchiveRoundtripVerifyTask,
    profile: ExecutableFixtureProfile,
    bundle: CompressedArchiveRoundtripVerifyFixtureBundle,
    workspace: str | os.PathLike[str],
) -> WorkspaceHandle:
    validate_compressed_archive_roundtrip_verify_fixture_for_task_profile(
        task, profile, bundle
    )
    return materialize_fixture(bundle.definition, workspace)


def verify_compressed_archive_roundtrip_verify_workspace(
    task: CompressedArchiveRoundtripVerifyTask,
    profile: ExecutableFixtureProfile,
    bundle: CompressedArchiveRoundtripVerifyFixtureBundle,
    handle: WorkspaceHandle,
) -> bool:
    """Check the complete quiescent final archive, report, and roundtrip tree."""

    if type(handle) is not WorkspaceHandle:
        return False
    try:
        validate_compressed_archive_roundtrip_verify_fixture_for_task_profile(
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
        primary = derive_compressed_archive_roundtrip_verify_state(
            bundle.definition, task.parameters
        )
        reference = reference_compressed_archive_roundtrip_verify_state(
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
        by_path = {item.path: item for item in output_entries}
        archive_path = COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_ARCHIVE_PATHS[
            task.parameters.compression_format
        ]
        archive_entry = by_path.get(archive_path)
        report_entry = by_path.get(
            COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_REPORT
        )
        if (
            archive_entry is None
            or report_entry is None
            or archive_entry.mode
            != COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_OUTPUT_MODE
            or report_entry.mode
            != COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_OUTPUT_MODE
        ):
            return False
        archive = handle.read_output_bytes(output_scan, archive_path)
        if not verify_compressed_archive_roundtrip_verify_archive(
            bundle.definition, task.parameters, archive
        ):
            return False
        report = handle.read_output_bytes(
            output_scan, COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_REPORT
        )
        if report != derive_compressed_archive_roundtrip_verify_report(
            bundle.definition, task.parameters, archive
        ):
            return False
        for record in primary.records:
            path = (
                COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_OUTPUT_ROOT
                / record.relative
            ).as_posix()
            entry = by_path.get(path)
            if (
                entry is None
                or entry.mode != record.mode
                or entry.mtime_ns != 0
                or entry.link_count != 1
                or entry.hardlink_group_sha256 is not None
                or handle.read_output_bytes(output_scan, path)
                != record.content
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
        CompressedArchiveRoundtripVerifyError,
        ExecutableWorkspaceError,
        OSError,
        TypeError,
        ValueError,
    ):
        return False


__all__ = [
    "COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_ALLOWED_TOOLS",
    "COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_ARCHIVE_PATHS",
    "COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_CANDIDATE_EXIT_STATUS_OBSERVED",
    "COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_COMPRESSION_FORMATS",
    "COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_FAMILY_ID",
    "COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_FILESYSTEM_IDENTITY",
    "COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_FINAL_ARCHIVE_OBSERVED",
    "COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_FINAL_TREE_OBSERVED",
    "COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_GENERATOR_VERSION",
    "COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_INPUT_HARDLINKS_COVERED",
    "COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_MANIFEST",
    "COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_MAXIMUM_ARCHIVE_BYTES",
    "COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_MAXIMUM_FILE_BYTES",
    "COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_MAXIMUM_MEMBERS",
    "COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_MAXIMUM_REPORT_BYTES",
    "COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_OUTPUT_IDENTITY",
    "COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_OUTPUT_ROOT",
    "COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_REPORT",
    "COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_SOURCE_ROOT",
    "COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_SYMLINK_DISTRACTORS_COVERED",
    "COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_TOOL_HISTORY_OBSERVED",
    "COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_VERIFICATION_HISTORY_OBSERVED",
    "COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_VERIFICATION_POLICIES",
    "COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_VERIFIER_IDENTITY",
    "COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_XZ_DECODER_MEMLIMIT_BYTES",
    "COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE",
    "COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE",
    "ArchiveRoundtripSource",
    "CompressedArchiveRoundtripVerifyError",
    "CompressedArchiveRoundtripVerifyFixtureBundle",
    "CompressedArchiveRoundtripVerifyOracle",
    "CompressedArchiveRoundtripVerifyParameters",
    "CompressedArchiveRoundtripVerifyState",
    "CompressedArchiveRoundtripVerifyTask",
    "build_compressed_archive_roundtrip_verify_fixture_bundle",
    "build_compressed_archive_roundtrip_verify_tasks",
    "compute_compressed_archive_roundtrip_verify_discrimination_sha256",
    "compute_compressed_archive_roundtrip_verify_task_sha256",
    "compressed_archive_roundtrip_verify_task_semantic_core",
    "decompress_compressed_archive_roundtrip_verify_output",
    "derive_compressed_archive_roundtrip_verify_report",
    "derive_compressed_archive_roundtrip_verify_state",
    "materialize_compressed_archive_roundtrip_verify_fixture",
    "reference_compressed_archive_roundtrip_verify_state",
    "validate_compressed_archive_roundtrip_verify_fixture_bundle",
    "validate_compressed_archive_roundtrip_verify_fixture_for_task_profile",
    "verify_compressed_archive_roundtrip_verify_archive",
    "verify_compressed_archive_roundtrip_verify_fixture_bundle",
    "verify_compressed_archive_roundtrip_verify_fixture_for_task_profile",
    "verify_compressed_archive_roundtrip_verify_workspace",
]
