"""Deterministic POSIX-ustar fixtures for safe static extraction.

The archive is assembled and parsed in memory.  No tar implementation or
candidate program is invoked.  The trusted oracle accepts only checksum-valid
POSIX ustar headers, stops at the first invalid/truncated member, and projects
safe regular-file members through the task's selector and duplicate policy.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import PurePosixPath
from typing import Final

from .executable_fixture_bundle import (
    ExecutableFixtureBundle,
    OracleOutputRecord,
    build_executable_fixture_bundle,
    build_trusted_fixture_oracle,
)
from .executable_fixture_profiles import (
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
    ExecutableFixtureProfile,
)
from .executable_static_types import (
    ExecutableStaticTask,
    UstarSafeExtractParameters,
)
from .executable_workspace import (
    ExpectedFile,
    FixtureDefinition,
    InputFile,
    InputSymlink,
)


USTAR_FIXTURE_GENERATOR_VERSION: Final[str] = "1.0.0"
ARCHIVE_PATH: Final[str] = "input/archive.tar"
OUTPUT_ROOT: Final[PurePosixPath] = PurePosixPath("output/extracted")
OUTPUT_MODE: Final[int] = 0o644
_BLOCK_SIZE: Final[int] = 512
_USTAR_MAGIC: Final[bytes] = b"ustar\0"
_USTAR_VERSION: Final[bytes] = b"00"
_REGULAR_TYPEFLAGS: Final[frozenset[bytes]] = frozenset({b"\0", b"0"})


class ExecutableFixtureUstarError(ValueError):
    """Raised when a ustar fixture is outside its closed contract."""


@dataclass(frozen=True, slots=True)
class _Member:
    name: str
    content: bytes
    typeflag: bytes = b"0"
    linkname: str = ""
    mode: int = 0o644

    def __post_init__(self) -> None:
        if type(self.name) is not str or not self.name or "\0" in self.name:
            raise ExecutableFixtureUstarError("archive member name is invalid")
        if type(self.content) is not bytes:
            raise ExecutableFixtureUstarError("archive member content must be bytes")
        if type(self.typeflag) is not bytes or len(self.typeflag) != 1:
            raise ExecutableFixtureUstarError("archive typeflag must be one byte")
        if (
            type(self.linkname) is not str
            or "\0" in self.linkname
            or len(self.linkname.encode("utf-8")) > 100
        ):
            raise ExecutableFixtureUstarError("archive linkname is invalid")
        if type(self.mode) is not int or not 0 <= self.mode <= 0o7777:
            raise ExecutableFixtureUstarError("archive member mode is invalid")


@dataclass(frozen=True, slots=True)
class _ParsedMember:
    ordinal: int
    name: str
    content: bytes


def _validate_task_profile(
    task: object, profile: object
) -> tuple[
    ExecutableStaticTask,
    ExecutableFixtureProfile,
    UstarSafeExtractParameters,
]:
    if (
        type(task) is not ExecutableStaticTask
        or task.family_id != "ustar-safe-extract"
        or type(task.parameters) is not UstarSafeExtractParameters
    ):
        raise ExecutableFixtureUstarError(
            "task must be an exact ustar-safe-extract ExecutableStaticTask"
        )
    if type(profile) is not ExecutableFixtureProfile:
        raise ExecutableFixtureUstarError(
            "profile must be an exact ExecutableFixtureProfile"
        )
    try:
        parameters = UstarSafeExtractParameters(
            selector=task.parameters.selector,
            conflict_policy=task.parameters.conflict_policy,
        )
        task.__post_init__()
        reconstructed_profile = ExecutableFixtureProfile(
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
    except (TypeError, ValueError) as exc:
        raise ExecutableFixtureUstarError(
            "task or profile failed closed-contract revalidation"
        ) from exc
    if reconstructed_profile not in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
        raise ExecutableFixtureUstarError(
            "profile is not public method-development data"
        )
    return task, profile, parameters


def _octal_field(value: int, width: int) -> bytes:
    if type(value) is not int or value < 0:
        raise ExecutableFixtureUstarError("negative ustar numeric field")
    digits = f"{value:0{width - 1}o}".encode("ascii")
    if len(digits) != width - 1:
        raise ExecutableFixtureUstarError("ustar numeric field overflow")
    return digits + b"\0"


def _split_ustar_name(name: str) -> tuple[bytes, bytes]:
    try:
        encoded = name.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ExecutableFixtureUstarError("archive name is not UTF-8 encodable") from exc
    if len(encoded) <= 100:
        return encoded, b""
    slash_positions = [index for index, byte in enumerate(encoded) if byte == 47]
    for position in reversed(slash_positions):
        prefix = encoded[:position]
        leaf = encoded[position + 1 :]
        if prefix and leaf and len(prefix) <= 155 and len(leaf) <= 100:
            return leaf, prefix
    raise ExecutableFixtureUstarError("archive name does not fit POSIX ustar")


def _member_header(
    member: _Member,
    *,
    declared_size: int | None = None,
    magic: bytes = _USTAR_MAGIC,
) -> bytes:
    name, prefix = _split_ustar_name(member.name)
    size = len(member.content) if declared_size is None else declared_size
    if type(size) is not int or size < 0:
        raise ExecutableFixtureUstarError("declared member size is invalid")
    if type(magic) is not bytes or len(magic) != 6:
        raise ExecutableFixtureUstarError("ustar magic field must be six bytes")

    header = bytearray(_BLOCK_SIZE)
    header[0 : len(name)] = name
    header[100:108] = _octal_field(member.mode, 8)
    header[108:116] = _octal_field(1000, 8)
    header[116:124] = _octal_field(1000, 8)
    header[124:136] = _octal_field(size, 12)
    header[136:148] = _octal_field(1_700_000_000, 12)
    header[148:156] = b"        "
    header[156:157] = member.typeflag
    linkname = member.linkname.encode("utf-8")
    header[157 : 157 + len(linkname)] = linkname
    header[257:263] = magic
    header[263:265] = _USTAR_VERSION
    header[265:270] = b"cbds\0"
    header[297:302] = b"cbds\0"
    header[329:337] = _octal_field(0, 8)
    header[337:345] = _octal_field(0, 8)
    header[345 : 345 + len(prefix)] = prefix
    checksum = sum(header)
    encoded_checksum = f"{checksum:06o}\0 ".encode("ascii")
    if len(encoded_checksum) != 8:
        raise ExecutableFixtureUstarError("ustar checksum field overflow")
    header[148:156] = encoded_checksum
    return bytes(header)


def _encoded_member(member: _Member) -> bytes:
    padding = (-len(member.content)) % _BLOCK_SIZE
    return _member_header(member) + member.content + (b"\0" * padding)


def _encoded_invalid_utf8_name_member() -> bytes:
    """Return a checksum-valid regular header with a non-UTF-8 name."""

    encoded = bytearray(
        _encoded_member(_Member("unsafe/invalid-utf8.txt", b"must-not-extract"))
    )
    encoded[0] = 0xFF
    encoded[148:156] = b"        "
    checksum = sum(encoded[:_BLOCK_SIZE])
    encoded[148:156] = f"{checksum:06o}\0 ".encode("ascii")
    return bytes(encoded)


def _encoded_noncanonical_name_field_member() -> bytes:
    """Return a checksum-valid header with bytes after its name-field NUL."""

    encoded = bytearray(
        _encoded_member(_Member("unsafe/nul-tail.txt", b"must-not-extract"))
    )
    encoded[6] = 0
    encoded[148:156] = b"        "
    checksum = sum(encoded[:_BLOCK_SIZE])
    encoded[148:156] = f"{checksum:06o}\0 ".encode("ascii")
    return bytes(encoded)


def _common_members(profile_id: str) -> tuple[_Member, ...]:
    marker = profile_id.encode("utf-8")
    identical_jsonl = b'{"id":1,"label":"same"}\n'
    long_name = (
        "deep/"
        + "segment-0123456789abcdef/" * 5
        + "prefix-field-report.txt"
    )
    return (
        _Member("docs/readme.txt", b"first-readme|" + marker + b"\n"),
        _Member("records/data.jsonl", identical_jsonl),
        _Member("records/unique.jsonl", b'{"id":2,"label":"unique"}\n'),
        _Member("empty/zero.txt", b""),
        _Member("empty/zero.bin", b""),
        _Member("bin/blob.bin", b"binary|\x00\xff\xc3(|" + marker),
        _Member("nul-type/accepted.txt", b"nul-type|" + marker, b"\0"),
        _Member(long_name, b"prefix-field|" + marker),
        _Member("docs/readme.txt", b"last-readme|" + marker + b"\n", b"\0"),
        _Member("records/data.jsonl", identical_jsonl),
        # Checksum-valid regular records with unsafe, noncanonical names.
        _Member("/absolute.txt", b"must-not-escape"),
        _Member("../parent.txt", b"must-not-escape"),
        _Member("unsafe/../parent.txt", b"must-not-normalize"),
        _Member("unsafe/./dot.txt", b"must-not-normalize"),
        _Member("unsafe//empty-component.txt", b"must-not-normalize"),
        _Member("unsafe/new\nline.txt", b"must-not-line-split"),
        _Member("unsafe/carriage\rreturn.txt", b"must-not-line-split"),
        _Member("unsafe/tab\tname.txt", b"must-not-field-split"),
        _Member("unsafe/delete\x7fname.txt", b"must-not-control-split"),
        # Checksum-valid records of every explicitly rejected broad kind.
        _Member("rejected/hard-link.txt", b"", b"1", "docs/readme.txt"),
        _Member("rejected/symbolic-link.txt", b"", b"2", "docs/readme.txt"),
        _Member("rejected/character-device.txt", b"", b"3"),
        _Member("rejected/block-device.txt", b"", b"4"),
        _Member("rejected/directory.txt", b"", b"5"),
        _Member("rejected/fifo.txt", b"", b"6"),
        _Member("rejected/contiguous.txt", b"payload", b"7"),
        _Member("rejected/pax-header.txt", b"20 path=escape.txt\n", b"x"),
        _Member("rejected/pax-global.txt", b"20 path=escape.txt\n", b"g"),
        _Member("rejected/gnu-long-name.txt", b"escape.txt\0", b"L"),
        _Member("rejected/gnu-long-link.txt", b"escape.txt\0", b"K"),
    )


def _profile_members(profile: ExecutableFixtureProfile) -> tuple[_Member, ...]:
    members = list(_common_members(profile.profile_id))
    if profile.profile_id == "spaces-unicode":
        members.extend(
            (
                _Member("space dir/weekly report.txt", b"space path\n"),
                _Member(
                    "unicode-雪/café.jsonl",
                    '{"unicode":"雪"}\n'.encode("utf-8"),
                ),
            )
        )
    elif profile.profile_id == "leading-dashes-globs":
        members.extend(
            (
                _Member("-leading/[glob]*?/literal?.txt", b"literal glob\n"),
                _Member("-leading/-records.jsonl", b'{"dash":true}\n'),
            )
        )
    elif profile.profile_id == "empty-duplicates":
        members.extend(
            (
                _Member("duplicates/identical-empty.txt", b""),
                _Member("duplicates/identical-empty.txt", b"", b"\0"),
                _Member("duplicates/different.jsonl", b'{"version":1}\n'),
                _Member("duplicates/different.jsonl", b'{"version":2}\n'),
            )
        )
    elif profile.profile_id == "symlinks-ordering":
        members.extend(
            (
                _Member("z-last/report.txt", b"z\n"),
                _Member("a-first/report.jsonl", b'{"order":"a"}\n'),
            )
        )
        members.reverse()
    elif profile.profile_id == "partial-permissions":
        members.extend(
            (
                _Member("permissions/owner-readable.txt", b"mode 0400 archive\n"),
                _Member("permissions/nonempty.jsonl", b'{"partial":true}\n'),
            )
        )
    else:  # pragma: no cover - exact profile validation makes this unreachable
        raise ExecutableFixtureUstarError("unsupported fixture profile")
    return tuple(members)


def _fixture_archive(profile: ExecutableFixtureProfile) -> bytes:
    payload = bytearray()
    for member in _profile_members(profile):
        payload.extend(_encoded_member(member))
    payload.extend(_encoded_invalid_utf8_name_member())
    payload.extend(_encoded_noncanonical_name_field_member())

    if profile.profile_id == "spaces-unicode":
        invalid = bytearray(
            _encoded_member(_Member("after-invalid/checksum.txt", b"ignored"))
        )
        invalid[148] = ord("1") if invalid[148] != ord("1") else ord("2")
        payload.extend(invalid)
        payload.extend(
            _encoded_member(_Member("after-invalid/hidden.txt", b"must-not-appear"))
        )
        payload.extend(b"\0" * (_BLOCK_SIZE * 2))
    elif profile.profile_id == "leading-dashes-globs":
        bad_magic = _Member("after-invalid/magic.txt", b"ignored")
        header = _member_header(bad_magic, magic=b"badar\0")
        payload.extend(header)
        payload.extend(bad_magic.content)
        payload.extend(b"\0" * ((-len(bad_magic.content)) % _BLOCK_SIZE))
        payload.extend(
            _encoded_member(_Member("after-invalid/hidden.txt", b"must-not-appear"))
        )
        payload.extend(b"\0" * (_BLOCK_SIZE * 2))
    elif profile.profile_id == "empty-duplicates":
        partial_header = _member_header(
            _Member("after-truncation/header.txt", b"not-present")
        )
        payload.extend(partial_header[:173])
    elif profile.profile_id == "symlinks-ordering":
        payload.extend(b"\0" * (_BLOCK_SIZE * 2))
    elif profile.profile_id == "partial-permissions":
        truncated = _Member("after-truncation/member.txt", b"short")
        payload.extend(_member_header(truncated, declared_size=1024))
        payload.extend(truncated.content)
    else:  # pragma: no cover - exact profile validation makes this unreachable
        raise ExecutableFixtureUstarError("unsupported fixture profile")
    return bytes(payload)


def _parse_octal_field(field: bytes) -> int | None:
    stripped = field.strip(b"\0 ")
    if not stripped or any(byte < ord("0") or byte > ord("7") for byte in stripped):
        return None
    try:
        return int(stripped, 8)
    except ValueError:  # pragma: no cover - guarded above
        return None


def _text_field(field: bytes) -> str | None:
    raw, separator, tail = field.partition(b"\0")
    if separator and any(tail):
        return None
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None


def _safe_member_name(header: bytes) -> str | None:
    leaf = _text_field(header[0:100])
    prefix = _text_field(header[345:500])
    if leaf is None or prefix is None or not leaf:
        return None
    name = f"{prefix}/{leaf}" if prefix else leaf
    if name.startswith("/") or name.endswith("/"):
        return None
    components = name.split("/")
    if any(component in {"", ".", ".."} for component in components):
        return None
    try:
        # Output definitions additionally require canonical, control-free UTF-8.
        candidate = PurePosixPath(name)
        if candidate.as_posix() != name or any(
            ord(character) < 32 or ord(character) == 127 for character in name
        ):
            return None
        name.encode("utf-8", errors="strict")
    except (UnicodeEncodeError, ValueError):
        return None
    return name


def _parse_safe_regular_members(archive: bytes) -> tuple[_ParsedMember, ...]:
    if type(archive) is not bytes:
        raise ExecutableFixtureUstarError("archive payload must be immutable bytes")
    parsed: list[_ParsedMember] = []
    offset = 0
    ordinal = 0
    while offset < len(archive):
        if len(archive) - offset < _BLOCK_SIZE:
            break
        header = archive[offset : offset + _BLOCK_SIZE]
        if header == b"\0" * _BLOCK_SIZE:
            break
        checksum = _parse_octal_field(header[148:156])
        checksum_header = bytearray(header)
        checksum_header[148:156] = b"        "
        if checksum is None or checksum != sum(checksum_header):
            break
        size = _parse_octal_field(header[124:136])
        if (
            size is None
            or header[257:263] != _USTAR_MAGIC
            or header[263:265] != _USTAR_VERSION
        ):
            break
        padded_size = ((size + _BLOCK_SIZE - 1) // _BLOCK_SIZE) * _BLOCK_SIZE
        data_start = offset + _BLOCK_SIZE
        data_end = data_start + size
        next_offset = data_start + padded_size
        if data_end > len(archive) or next_offset > len(archive):
            break
        name = _safe_member_name(header)
        if name is not None and header[156:157] in _REGULAR_TYPEFLAGS:
            parsed.append(
                _ParsedMember(
                    ordinal=ordinal,
                    name=name,
                    content=archive[data_start:data_end],
                )
            )
        ordinal += 1
        offset = next_offset
    return tuple(parsed)


def _selector_matches(member: _ParsedMember, selector: str) -> bool:
    basename = member.name.rsplit("/", 1)[-1]
    if selector == "all-regular":
        return True
    if selector == "txt-suffix":
        return basename.endswith(".txt")
    if selector == "jsonl-suffix":
        return basename.endswith(".jsonl")
    if selector == "nonempty-regular":
        return len(member.content) != 0
    raise ExecutableFixtureUstarError("unsupported ustar selector")


def _derive_outputs(
    archive: bytes,
    parameters: UstarSafeExtractParameters,
) -> tuple[OracleOutputRecord, ...]:
    groups: dict[str, list[_ParsedMember]] = {}
    for member in _parse_safe_regular_members(archive):
        if _selector_matches(member, parameters.selector):
            groups.setdefault(member.name, []).append(member)

    outputs: list[OracleOutputRecord] = []
    for name, members in groups.items():
        chosen: _ParsedMember | None
        if len(members) == 1:
            chosen = members[0]
        elif parameters.conflict_policy == "reject-duplicates":
            chosen = None
        elif parameters.conflict_policy == "first-entry":
            chosen = members[0]
        elif parameters.conflict_policy == "last-entry":
            chosen = members[-1]
        elif parameters.conflict_policy == "identical-only":
            chosen = (
                members[0]
                if len({item.content for item in members}) == 1
                else None
            )
        elif parameters.conflict_policy == "smallest-sha256":
            chosen = min(
                members,
                key=lambda item: (sha256(item.content).hexdigest(), item.ordinal),
            )
        else:
            raise ExecutableFixtureUstarError("unsupported ustar conflict policy")
        if chosen is not None:
            outputs.append(
                OracleOutputRecord(
                    (OUTPUT_ROOT / name).as_posix(),
                    chosen.content,
                    OUTPUT_MODE,
                )
            )
    outputs.sort(key=lambda output: output.path.encode("utf-8"))
    if not outputs:
        raise ExecutableFixtureUstarError(
            "fixture must retain at least one safe selected archive member"
        )
    return tuple(outputs)


def _fixture_inputs(
    profile: ExecutableFixtureProfile,
    archive: bytes,
) -> tuple[InputFile | InputSymlink, ...]:
    mode_by_profile = {
        "spaces-unicode": 0o640,
        "leading-dashes-globs": 0o604,
        "empty-duplicates": 0o400,
        "symlinks-ordering": 0o444,
        "partial-permissions": 0o400,
    }
    try:
        archive_file = InputFile(
            ARCHIVE_PATH,
            archive,
            mode_by_profile[profile.profile_id],
        )
    except KeyError as exc:  # pragma: no cover - exact profile validation
        raise ExecutableFixtureUstarError("unsupported fixture profile") from exc
    if profile.profile_id == "symlinks-ordering":
        return (
            InputSymlink("input/ignored-archive-link.tar", "archive.tar"),
            archive_file,
        )
    return (archive_file,)


def build_ustar_safe_extract_fixture_bundle(
    task: ExecutableStaticTask,
    profile: ExecutableFixtureProfile,
) -> ExecutableFixtureBundle:
    """Build one nonexecuting content-bound safe-ustar fixture bundle."""

    task, profile, parameters = _validate_task_profile(task, profile)
    archive = _fixture_archive(profile)
    inputs = _fixture_inputs(profile, archive)
    outputs = _derive_outputs(archive, parameters)
    definition = FixtureDefinition(
        fixture_id=f"dev.ustar-safe-extract.{profile.profile_id}",
        inputs=inputs,
        expected_files=tuple(
            ExpectedFile(
                output.path,
                maximum_bytes=len(output.content),
                mode=OUTPUT_MODE,
            )
            for output in outputs
        ),
    )
    oracle = build_trusted_fixture_oracle(
        outputs,
        semantic_verifier_identity="verify-ustar-safe-extract-v1",
    )
    return build_executable_fixture_bundle(
        task_contract_sha256=task.task_contract_sha256,
        profile_sha256=profile.profile_sha256,
        definition=definition,
        oracle=oracle,
    )


__all__ = [
    "USTAR_FIXTURE_GENERATOR_VERSION",
    "ExecutableFixtureUstarError",
    "build_ustar_safe_extract_fixture_bundle",
]
