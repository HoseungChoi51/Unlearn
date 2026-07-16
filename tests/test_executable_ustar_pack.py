from __future__ import annotations

import ast
from dataclasses import dataclass, replace
import io
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import cbds.executable_ustar_pack as ustar  # noqa: E402
from cbds.executable_fixture_bundle import OracleOutputRecord  # noqa: E402
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from cbds.executable_static_types import OpaqueFixtureDescriptor  # noqa: E402
from cbds.executable_ustar_pack import (  # noqa: E402
    USTAR_PACK_DIRECTORY_PERMISSION_ERRORS_COVERED,
    USTAR_PACK_EFFECTIVE_ACCESS_FAILURES_COVERED,
    USTAR_PACK_GENERATOR_VERSION,
    USTAR_PACK_MODE_POLICIES,
    USTAR_PACK_MODE_UNREADABLE_LEAVES_COVERED,
    USTAR_PACK_OUTPUT,
    USTAR_PACK_OUTPUT_MAXIMUM_BYTES,
    USTAR_PACK_SELECTORS,
    USTAR_PACK_SYMLINKS_COVERED,
    USTAR_PACK_VERIFIER_IDENTITY,
    USTAR_PACK_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE,
    USTAR_PACK_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE,
    UstarPackError,
    UstarPackFixtureBundle,
    UstarPackMember,
    UstarPackOracle,
    UstarPackParameters,
    UstarPackTask,
    build_ustar_pack_fixture_bundle,
    build_ustar_pack_tasks,
    compute_ustar_pack_task_sha256,
    derive_ustar_pack_members,
    derive_ustar_pack_output,
    materialize_ustar_pack_fixture,
    reference_ustar_pack_members,
    reference_ustar_pack_output,
    validate_ustar_pack_fixture_bundle,
    validate_ustar_pack_fixture_for_task_profile,
    verify_ustar_pack_fixture_bundle,
    verify_ustar_pack_fixture_for_task_profile,
    verify_ustar_pack_output,
    verify_ustar_pack_workspace,
)
from cbds.executable_workspace import (  # noqa: E402
    ExpectedFile,
    FixtureDefinition,
    InputFile,
    InputSymlink,
)


BLOCK_SIZE = 512
ZERO_BLOCK = b"\0" * BLOCK_SIZE


def _profile(profile_id: str):
    matches = tuple(
        profile
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        if profile.profile_id == profile_id
    )
    if len(matches) != 1:
        raise AssertionError(f"expected one profile named {profile_id!r}")
    return matches[0]


def _read_octal(field: bytes) -> int:
    stripped = field.strip(b" \0")
    if not stripped or any(byte not in b"01234567" for byte in stripped):
        raise AssertionError("test parser encountered an invalid octal field")
    return int(stripped, 8)


def _octal_field(value: int, width: int) -> bytes:
    digits = format(value, "o").encode("ascii")
    if len(digits) >= width:
        raise AssertionError("test octal value does not fit")
    return b"0" * (width - 1 - len(digits)) + digits + b"\0"


def _raw_header_path(header: bytes) -> str:
    name = header[:100].split(b"\0", 1)[0]
    prefix = header[345:500].split(b"\0", 1)[0]
    raw = prefix + (b"/" if prefix else b"") + name
    return raw.decode("utf-8", errors="strict")


@dataclass(frozen=True)
class _ArchiveSegment:
    start: int
    end: int
    path: str
    size: int


def _archive_segments(payload: bytes) -> tuple[tuple[_ArchiveSegment, ...], int]:
    segments: list[_ArchiveSegment] = []
    cursor = 0
    while cursor + BLOCK_SIZE <= len(payload):
        header = payload[cursor : cursor + BLOCK_SIZE]
        if header == ZERO_BLOCK:
            return tuple(segments), cursor
        size = _read_octal(header[124:136])
        end = cursor + BLOCK_SIZE + ((size + BLOCK_SIZE - 1) // BLOCK_SIZE) * BLOCK_SIZE
        if end > len(payload):
            raise AssertionError("test parser encountered a truncated archive")
        segments.append(
            _ArchiveSegment(cursor, end, _raw_header_path(header), size)
        )
        cursor = end
    raise AssertionError("test parser did not find an archive terminator")


def _rechecksum_header(header: bytearray) -> None:
    header[148:156] = b" " * 8
    checksum = sum(header)
    digits = format(checksum, "06o").encode("ascii")
    if len(digits) != 6:
        raise AssertionError("test header checksum does not fit")
    header[148:156] = digits + b"\0 "


def _patch_header_field(
    payload: bytes,
    member_index: int,
    start: int,
    width: int,
    replacement: bytes,
    *,
    recompute_checksum: bool = True,
) -> bytes:
    segments, _terminator = _archive_segments(payload)
    segment = segments[member_index]
    if len(replacement) > width:
        raise AssertionError("test replacement does not fit header field")
    mutated = bytearray(payload)
    header = bytearray(mutated[segment.start : segment.start + BLOCK_SIZE])
    header[start : start + width] = replacement + b"\0" * (
        width - len(replacement)
    )
    if recompute_checksum:
        _rechecksum_header(header)
    mutated[segment.start : segment.start + BLOCK_SIZE] = header
    return bytes(mutated)


def _remove_archive_member(payload: bytes, path: str) -> bytes:
    segments, terminator = _archive_segments(payload)
    matches = tuple(segment for segment in segments if segment.path == path)
    if len(matches) != 1:
        raise AssertionError(f"expected one archive member named {path!r}")
    removed = matches[0]
    return (
        payload[: removed.start]
        + payload[removed.end : terminator]
        + payload[terminator:]
    )


@dataclass(frozen=True)
class _IndependentMember:
    path: str
    content: bytes
    mode: int
    uid: int
    gid: int
    mtime: int
    uname: str
    gname: str


def _parse_with_python_tarfile(payload: bytes) -> tuple[_IndependentMember, ...]:
    observed: list[_IndependentMember] = []
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
        for info in archive.getmembers():
            if not info.isreg():
                raise AssertionError("canonical archive has a non-regular member")
            extracted = archive.extractfile(info)
            if extracted is None:
                raise AssertionError("regular member has no readable payload")
            observed.append(
                _IndependentMember(
                    path=info.name,
                    content=extracted.read(),
                    mode=info.mode,
                    uid=info.uid,
                    gid=info.gid,
                    mtime=info.mtime,
                    uname=info.uname,
                    gname=info.gname,
                )
            )
    return tuple(observed)


def _write_archive(workspace: Path, payload: bytes) -> None:
    output = workspace / "output"
    output.mkdir(mode=0o755)
    os.chmod(output, 0o755)
    archive = output / "archive.tar"
    archive.write_bytes(payload)
    os.chmod(archive, 0o644)


class _StringSubclass(str):
    pass


class _BytesSubclass(bytes):
    pass


class UstarPackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tasks = build_ustar_pack_tasks()
        cls.by_pair = {
            (task.task_id, profile.profile_id): build_ustar_pack_fixture_bundle(
                task, profile
            )
            for task in cls.tasks
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        }

    def task(self, selector: str, mode_policy: str) -> UstarPackTask:
        matches = tuple(
            task
            for task in self.tasks
            if task.parameters.selector == selector
            and task.parameters.archive_mode_policy == mode_policy
        )
        self.assertEqual(len(matches), 1)
        return matches[0]

    def bundle(
        self, selector: str, mode_policy: str, profile_id: str
    ) -> UstarPackFixtureBundle:
        task = self.task(selector, mode_policy)
        return self.by_pair[(task.task_id, profile_id)]

    def test_exact_four_by_five_order_hashes_types_and_authority(self) -> None:
        self.assertEqual(USTAR_PACK_GENERATOR_VERSION, "1.0.0")
        self.assertEqual(len(self.tasks), 20)
        self.assertEqual(
            tuple(
                (
                    task.parameters.selector,
                    task.parameters.archive_mode_policy,
                )
                for task in self.tasks
            ),
            tuple(
                (selector, policy)
                for selector in USTAR_PACK_SELECTORS
                for policy in USTAR_PACK_MODE_POLICIES
            ),
        )
        self.assertEqual(len({task.task_id for task in self.tasks}), 20)
        self.assertEqual(
            len({task.task_contract_sha256 for task in self.tasks}), 20
        )
        self.assertEqual(len({task.graph_sha256 for task in self.tasks}), 20)
        self.assertEqual(build_ustar_pack_tasks(), self.tasks)

        for task in self.tasks:
            with self.subTest(task=task.task_id):
                self.assertIs(type(task), UstarPackTask)
                self.assertIs(type(task.parameters), UstarPackParameters)
                self.assertRegex(task.task_id, r"\Amds-[0-9a-f]{24}\Z")
                self.assertRegex(task.task_contract_sha256, r"\A[0-9a-f]{64}\Z")
                self.assertEqual(
                    task.task_contract_sha256,
                    compute_ustar_pack_task_sha256(
                        task.parameters, task.prompt, task.graph
                    ),
                )
                self.assertIs(task.public, True)
                self.assertIs(task.sealed, False)
                self.assertIs(task.candidate_execution_authorized, False)
                self.assertIs(task.model_selection_eligible, False)
                self.assertIs(task.claim_authorized, False)
                self.assertEqual(len(task.fixtures), 5)
                self.assertTrue(
                    all(type(item) is OpaqueFixtureDescriptor for item in task.fixtures)
                )
                self.assertEqual(
                    task.fixtures,
                    tuple(
                        self.by_pair[(task.task_id, profile.profile_id)].descriptor
                        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
                    ),
                )
                record = task.to_public_record()
                self.assertEqual(record["family_id"], "reproducible-ustar-pack")
                self.assertEqual(record["parameters"], task.parameters.to_record())
                self.assertIs(record["candidate_execution_authorized"], False)
                self.assertIs(record["model_selection_eligible"], False)
                self.assertIs(record["claim_authorized"], False)

    def test_all_one_hundred_bundles_are_deterministic_and_authenticated(self) -> None:
        self.assertEqual(len(self.by_pair), 100)
        self.assertEqual(
            len({item.descriptor.fixture_id for item in self.by_pair.values()}),
            100,
        )
        self.assertEqual(
            len({item.descriptor.fixture_sha256 for item in self.by_pair.values()}),
            100,
        )
        for task in self.tasks:
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                with self.subTest(task=task.task_id, profile=profile.profile_id):
                    bundle = self.by_pair[(task.task_id, profile.profile_id)]
                    self.assertIs(type(bundle), UstarPackFixtureBundle)
                    self.assertIs(type(bundle.oracle), UstarPackOracle)
                    self.assertIs(type(bundle.oracle.outputs), tuple)
                    self.assertEqual(len(bundle.oracle.outputs), 1)
                    self.assertIs(type(bundle.oracle.outputs[0]), OracleOutputRecord)
                    validate_ustar_pack_fixture_bundle(bundle)
                    self.assertTrue(verify_ustar_pack_fixture_bundle(bundle))
                    validate_ustar_pack_fixture_for_task_profile(
                        task, profile, bundle
                    )
                    self.assertTrue(
                        verify_ustar_pack_fixture_for_task_profile(
                            task, profile, bundle
                        )
                    )
                    self.assertEqual(
                        build_ustar_pack_fixture_bundle(task, profile), bundle
                    )
                    self.assertEqual(
                        bundle.definition.expected_files,
                        (
                            ExpectedFile(
                                USTAR_PACK_OUTPUT,
                                USTAR_PACK_OUTPUT_MAXIMUM_BYTES,
                                0o644,
                            ),
                        ),
                    )
                    output = bundle.oracle.outputs[0]
                    self.assertEqual(output.path, USTAR_PACK_OUTPUT)
                    self.assertEqual(output.mode, 0o644)
                    self.assertLessEqual(
                        len(output.content), USTAR_PACK_OUTPUT_MAXIMUM_BYTES
                    )
                    self.assertGreaterEqual(len(output.content), 2 * BLOCK_SIZE)
                    self.assertEqual(len(output.content) % BLOCK_SIZE, 0)
                    self.assertEqual(
                        bundle.oracle.semantic_verifier_identity,
                        USTAR_PACK_VERIFIER_IDENTITY,
                    )
                    self.assertIs(bundle.candidate_execution_authorized, False)
                    self.assertIs(bundle.model_selection_eligible, False)
                    self.assertIs(bundle.claim_authorized, False)

    def test_dual_oracles_and_independent_tarfile_semantics_agree_for_all_100(
        self,
    ) -> None:
        for task in self.tasks:
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                with self.subTest(task=task.task_id, profile=profile.profile_id):
                    bundle = self.by_pair[(task.task_id, profile.profile_id)]
                    primary_members = derive_ustar_pack_members(
                        bundle.definition, task.parameters
                    )
                    reference_members = reference_ustar_pack_members(
                        bundle.definition, task.parameters
                    )
                    primary = derive_ustar_pack_output(
                        bundle.definition, task.parameters
                    )
                    reference = reference_ustar_pack_output(
                        bundle.definition, task.parameters
                    )
                    self.assertEqual(primary_members, reference_members)
                    self.assertEqual(primary, reference)
                    self.assertEqual(primary, bundle.oracle.outputs[0].content)
                    self.assertTrue(
                        verify_ustar_pack_output(
                            bundle.definition, task.parameters, primary
                        )
                    )
                    independent = _parse_with_python_tarfile(primary)
                    self.assertEqual(
                        independent,
                        tuple(
                            _IndependentMember(
                                member.path,
                                member.content,
                                member.mode,
                                0,
                                0,
                                0,
                                "",
                                "",
                            )
                            for member in primary_members
                        ),
                    )
                    segments, terminator = _archive_segments(primary)
                    self.assertEqual(
                        tuple(segment.path for segment in segments),
                        tuple(member.path for member in primary_members),
                    )
                    self.assertGreaterEqual(len(primary) - terminator, 2 * BLOCK_SIZE)
                    self.assertEqual(
                        primary[terminator:],
                        b"\0" * (len(primary) - terminator),
                    )

    def test_fixed_ceiling_does_not_leak_answer_size_and_empty_archives_are_valid(
        self,
    ) -> None:
        empty_bundles = tuple(
            self.by_pair[(task.task_id, "empty-duplicates")]
            for task in self.tasks
        )
        self.assertEqual(len(empty_bundles), 20)
        for task, bundle in zip(self.tasks, empty_bundles, strict=True):
            with self.subTest(task=task.task_id):
                members = derive_ustar_pack_members(
                    bundle.definition, task.parameters
                )
                archive = bundle.oracle.outputs[0].content
                self.assertEqual(members, ())
                self.assertNotEqual(archive, b"")
                self.assertEqual(len(archive), 20 * BLOCK_SIZE)
                self.assertEqual(archive, b"\0" * len(archive))
                self.assertTrue(
                    verify_ustar_pack_output(
                        bundle.definition, task.parameters, archive
                    )
                )
                self.assertEqual(
                    bundle.definition.expected_files[0].maximum_bytes,
                    1024 * 1024,
                )
                self.assertEqual(
                    bundle.definition.expected_files[0].maximum_bytes,
                    USTAR_PACK_OUTPUT_MAXIMUM_BYTES,
                )

        observed_lengths = {
            len(bundle.oracle.outputs[0].content)
            for bundle in self.by_pair.values()
        }
        self.assertGreaterEqual(len(observed_lengths), 1)
        self.assertTrue(
            all(
                bundle.definition.expected_files[0].maximum_bytes
                == USTAR_PACK_OUTPUT_MAXIMUM_BYTES
                for bundle in self.by_pair.values()
            )
        )

    def test_selector_and_mode_policy_axes_are_observable(self) -> None:
        selector_signatures = {}
        for selector in USTAR_PACK_SELECTORS:
            signatures = []
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                task = self.task(selector, "preserve-permission-bits")
                bundle = self.by_pair[(task.task_id, profile.profile_id)]
                signatures.append(
                    tuple(
                        member.path
                        for member in derive_ustar_pack_members(
                            bundle.definition, task.parameters
                        )
                    )
                )
            selector_signatures[selector] = tuple(signatures)
        self.assertEqual(len(set(selector_signatures.values())), 4)
        self.assertTrue(
            all(
                any(signature for signature in signatures)
                for signatures in selector_signatures.values()
            )
        )

        policy_signatures = {}
        for policy in USTAR_PACK_MODE_POLICIES:
            signatures = []
            for selector in USTAR_PACK_SELECTORS:
                for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                    task = self.task(selector, policy)
                    bundle = self.by_pair[(task.task_id, profile.profile_id)]
                    signatures.append(
                        tuple(
                            (member.path, member.mode)
                            for member in derive_ustar_pack_members(
                                bundle.definition, task.parameters
                            )
                        )
                    )
            policy_signatures[policy] = tuple(signatures)
        self.assertEqual(len(set(policy_signatures.values())), 5)

        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
            observed = {
                tuple(
                    member.path
                    for member in derive_ustar_pack_members(
                        self.bundle(
                            selector,
                            "preserve-permission-bits",
                            profile.profile_id,
                        ).definition,
                        self.task(
                            selector, "preserve-permission-bits"
                        ).parameters,
                    )
                )
                for selector in USTAR_PACK_SELECTORS
            }
            with self.subTest(profile=profile.profile_id):
                if profile.profile_id == "empty-duplicates":
                    self.assertEqual(observed, {()})
                else:
                    self.assertGreaterEqual(len(observed), 2)

    def test_profiles_contain_declared_edge_evidence_and_honest_limits(self) -> None:
        task = self.task("all-mode-readable", "preserve-permission-bits")
        definitions = {
            profile.profile_id: self.by_pair[
                (task.task_id, profile.profile_id)
            ].definition
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        }
        for profile_id, definition in definitions.items():
            with self.subTest(profile=profile_id):
                files = tuple(
                    item for item in definition.inputs if type(item) is InputFile
                )
                links = tuple(
                    item
                    for item in definition.inputs
                    if type(item) is InputSymlink
                )
                self.assertTrue(files)
                self.assertTrue(links)
                self.assertTrue(
                    any(item.path.startswith("input/source/") for item in files)
                )
                self.assertTrue(
                    any(item.path.startswith("input/source/") for item in links)
                )

        spaces = definitions["spaces-unicode"].inputs
        self.assertTrue(any(" " in item.path for item in spaces))
        self.assertTrue(
            any(any(ord(character) > 127 for character in item.path) for item in spaces)
        )
        self.assertTrue(
            any(
                len(
                    PurePosixPath(item.path)
                    .relative_to("input/source")
                    .as_posix()
                    .encode("utf-8")
                )
                > 100
                for item in spaces
                if type(item) is InputFile
                and item.path.startswith("input/source/")
            )
        )
        self.assertTrue(
            any(item.path.startswith("input/outside/") for item in spaces)
        )
        self.assertTrue(
            any(
                type(item) is InputFile
                and item.path.startswith("input/outside/")
                and item.mode & 0o111
                for item in spaces
            )
        )

        leading = definitions["leading-dashes-globs"].inputs
        self.assertTrue(
            any(PurePosixPath(item.path).name.startswith("-") for item in leading)
        )
        self.assertTrue(
            any(any(mark in item.path for mark in "*?[]") for item in leading)
        )
        self.assertTrue(
            any(
                type(item) is InputFile
                and PurePosixPath(item.path).name.endswith(".TXT")
                for item in leading
            )
        )
        self.assertTrue(
            any(
                type(item) is InputFile and len(item.content) == 1
                for item in leading
            )
        )
        self.assertTrue(
            any(
                type(item) is InputFile
                and ".txt" in PurePosixPath(item.path).name
                and not PurePosixPath(item.path).name.endswith(".txt")
                for item in leading
            )
        )
        self.assertTrue(
            any(
                type(item) is InputFile
                and PurePosixPath(item.path).name.endswith(".txt")
                and item.mode & 0o011
                and not item.mode & 0o100
                for item in leading
            )
        )
        self.assertTrue(
            {item.mode for item in leading if type(item) is InputFile}
            >= {0o007, 0o070}
        )

        empty = tuple(
            item
            for item in definitions["empty-duplicates"].inputs
            if type(item) is InputFile
        )
        self.assertTrue(any(item.content == b"" for item in empty))
        duplicate_payloads = [item.content for item in empty]
        self.assertLess(len(set(duplicate_payloads)), len(duplicate_payloads))
        self.assertTrue(any(item.mode == 0o111 for item in empty))
        self.assertTrue(all(not item.mode & 0o444 for item in empty))

        ordering = definitions["symlinks-ordering"].inputs
        self.assertNotEqual(
            tuple(item.path for item in ordering),
            tuple(sorted((item.path for item in ordering), key=str.encode)),
        )
        self.assertIs(type(ordering[0]), InputSymlink)

        partial = definitions["partial-permissions"].inputs
        modes = {item.mode for item in partial if type(item) is InputFile}
        self.assertTrue(
            {0o000, 0o004, 0o006, 0o040, 0o055, 0o060, 0o111, 0o400}
            <= modes
        )
        self.assertTrue(
            any(
                type(item) is InputFile and item.mode & 0o444
                for item in partial
            )
        )
        self.assertTrue(
            any(
                type(item) is InputFile and not item.mode & 0o444
                for item in partial
            )
        )
        self.assertIs(USTAR_PACK_SYMLINKS_COVERED, True)
        self.assertIs(USTAR_PACK_MODE_UNREADABLE_LEAVES_COVERED, True)
        self.assertIs(USTAR_PACK_DIRECTORY_PERMISSION_ERRORS_COVERED, False)
        self.assertIs(USTAR_PACK_EFFECTIVE_ACCESS_FAILURES_COVERED, False)
        self.assertIs(
            USTAR_PACK_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE, True
        )
        self.assertIs(
            USTAR_PACK_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE, False
        )

    def test_hand_checked_partial_permission_members_and_all_five_modes(self) -> None:
        expected_paths = (
            "group-readable.txt",
            "group-write.bin",
            "other-readable.bin",
            "other-write.bin",
            "owner-readable.txt",
            "readable-executable.sh",
        )
        expected_modes = {
            "preserve-permission-bits": (
                0o040,
                0o060,
                0o004,
                0o006,
                0o400,
                0o055,
            ),
            "fixed-0644": (0o644,) * 6,
            "fixed-0600": (0o600,) * 6,
            "normalize-preserve-exec": (
                0o644,
                0o644,
                0o644,
                0o644,
                0o644,
                0o755,
            ),
            "fold-class-bits-to-owner": (
                0o400,
                0o600,
                0o400,
                0o600,
                0o400,
                0o500,
            ),
        }
        for policy, modes in expected_modes.items():
            task = self.task("all-mode-readable", policy)
            bundle = self.by_pair[(task.task_id, "partial-permissions")]
            members = derive_ustar_pack_members(
                bundle.definition, task.parameters
            )
            with self.subTest(policy=policy):
                self.assertEqual(
                    tuple(member.path for member in members), expected_paths
                )
                self.assertEqual(tuple(member.mode for member in members), modes)
                self.assertNotIn("permission-denied.txt", expected_paths)
                self.assertNotIn("execute-only.sh", expected_paths)
                self.assertTrue(
                    all(
                        member == reference
                        for member, reference in zip(
                            members,
                            reference_ustar_pack_members(
                                bundle.definition, task.parameters
                            ),
                            strict=True,
                        )
                    )
                )

    def test_every_selector_requires_explicit_utf8_byte_sorting(self) -> None:
        profile_id = "symlinks-ordering"
        for selector in USTAR_PACK_SELECTORS:
            task = self.task(selector, "preserve-permission-bits")
            bundle = self.by_pair[(task.task_id, profile_id)]
            selected_paths = {
                member.path
                for member in derive_ustar_pack_members(
                    bundle.definition,
                    task.parameters,
                )
            }
            source_order = tuple(
                PurePosixPath(*PurePosixPath(item.path).parts[2:]).as_posix()
                for item in bundle.definition.inputs
                if type(item) is InputFile
                and PurePosixPath(*PurePosixPath(item.path).parts[2:]).as_posix()
                in selected_paths
            )
            with self.subTest(selector=selector):
                self.assertGreaterEqual(len(source_order), 2)
                self.assertNotEqual(
                    source_order,
                    tuple(sorted(source_order, key=str.encode)),
                )

    def test_long_path_uses_standard_ustar_prefix_and_name_fields(self) -> None:
        task = self.task("all-mode-readable", "preserve-permission-bits")
        bundle = self.by_pair[(task.task_id, "spaces-unicode")]
        archive = bundle.oracle.outputs[0].content
        segments, _terminator = _archive_segments(archive)
        long_segment = next(
            segment
            for segment in segments
            if len(segment.path.encode("utf-8")) > 100
        )
        header = archive[long_segment.start : long_segment.start + BLOCK_SIZE]
        self.assertNotEqual(header[:100].split(b"\0", 1)[0], b"")
        self.assertNotEqual(header[345:500].split(b"\0", 1)[0], b"")
        self.assertEqual(_raw_header_path(header), long_segment.path)
        self.assertEqual(header[257:263], b"ustar\0")
        self.assertEqual(header[263:265], b"00")
        self.assertEqual(header[156:157], b"0")

    def test_ustar_payload_block_boundaries_and_ignored_links(self) -> None:
        definition = FixtureDefinition(
            fixture_id="fixture.ustar.boundary.reference",
            inputs=(
                InputFile("input/source/boundary/size-511.bin", b"a" * 511, 0o644),
                InputFile("input/source/boundary/size-512.bin", b"b" * 512, 0o644),
                InputFile("input/source/boundary/size-513.bin", b"c" * 513, 0o644),
                InputSymlink("input/source/broken-link", "missing-target"),
                InputSymlink("input/source/directory-link", "boundary"),
            ),
            expected_files=(
                ExpectedFile(
                    USTAR_PACK_OUTPUT,
                    USTAR_PACK_OUTPUT_MAXIMUM_BYTES,
                    0o644,
                ),
            ),
        )
        parameters = UstarPackParameters(
            "all-mode-readable",
            "preserve-permission-bits",
        )
        members = derive_ustar_pack_members(definition, parameters)
        self.assertEqual(
            tuple((member.path, len(member.content)) for member in members),
            (
                ("boundary/size-511.bin", 511),
                ("boundary/size-512.bin", 512),
                ("boundary/size-513.bin", 513),
            ),
        )
        self.assertEqual(members, reference_ustar_pack_members(definition, parameters))
        archive = derive_ustar_pack_output(definition, parameters)
        self.assertEqual(archive, reference_ustar_pack_output(definition, parameters))
        self.assertTrue(verify_ustar_pack_output(definition, parameters, archive))

        segments, _terminator = _archive_segments(archive)
        by_path = {segment.path: segment for segment in segments}
        for path in ("boundary/size-511.bin", "boundary/size-513.bin"):
            segment = by_path[path]
            padding_start = segment.start + BLOCK_SIZE + segment.size
            mutant = bytearray(archive)
            mutant[padding_start] = 1
            with self.subTest(path=path):
                self.assertFalse(
                    verify_ustar_pack_output(
                        definition,
                        parameters,
                        bytes(mutant),
                    )
                )

    def test_semantically_equivalent_extra_zero_block_padding_is_accepted(self) -> None:
        for task in self.tasks:
            for profile_id in ("spaces-unicode", "empty-duplicates"):
                bundle = self.by_pair[(task.task_id, profile_id)]
                canonical = bundle.oracle.outputs[0].content
                alternative = canonical + ZERO_BLOCK
                with self.subTest(task=task.task_id, profile=profile_id):
                    self.assertNotEqual(alternative, canonical)
                    self.assertTrue(
                        verify_ustar_pack_output(
                            bundle.definition, task.parameters, alternative
                        )
                    )
                    self.assertEqual(
                        _parse_with_python_tarfile(alternative),
                        _parse_with_python_tarfile(canonical),
                    )

    def test_posix_nul_regular_typeflag_is_semantically_equivalent(self) -> None:
        task = self.task("all-mode-readable", "preserve-permission-bits")
        bundle = self.by_pair[(task.task_id, "spaces-unicode")]
        canonical = bundle.oracle.outputs[0].content
        alternative = _patch_header_field(
            canonical,
            0,
            156,
            1,
            b"\0",
        )
        self.assertNotEqual(alternative, canonical)
        self.assertTrue(
            verify_ustar_pack_output(
                bundle.definition,
                task.parameters,
                alternative,
            )
        )
        self.assertEqual(
            _parse_with_python_tarfile(alternative),
            _parse_with_python_tarfile(canonical),
        )

    def test_isolated_owner_group_other_permission_mutants_are_killed(self) -> None:
        isolated = (
            (
                "spaces-unicode",
                "portable-archive-prefix-with-enough-characters/"
                "second-prefix-segment-for-ustar-boundary/"
                "long-selected-executable.txt",
                0o700,
            ),
            ("leading-dashes-globs", "group-exec.txt", 0o070),
            ("leading-dashes-globs", "other-exec.txt", 0o007),
        )
        for selector in USTAR_PACK_SELECTORS:
            for policy in USTAR_PACK_MODE_POLICIES:
                task = self.task(selector, policy)
                for profile_id, path, source_mode in isolated:
                    bundle = self.by_pair[(task.task_id, profile_id)]
                    canonical = bundle.oracle.outputs[0].content
                    with self.subTest(
                        selector=selector,
                        policy=policy,
                        profile=profile_id,
                        path=path,
                    ):
                        # All three isolated rwx leaves are nonempty readable,
                        # executable .txt files, so every selector must retain
                        # each one.  Dropping any class therefore exposes an
                        # owner-only or owner+group predicate mutant.
                        missing = _remove_archive_member(canonical, path)
                        self.assertFalse(
                            verify_ustar_pack_output(
                                bundle.definition,
                                task.parameters,
                                missing,
                            )
                        )

                        segments, _terminator = _archive_segments(canonical)
                        member_index = next(
                            index
                            for index, segment in enumerate(segments)
                            if segment.path == path
                        )
                        if policy == "preserve-permission-bits":
                            wrong_modes = tuple(
                                source_mode & ~bit
                                for bit in (0o400, 0o200, 0o100, 0o040,
                                            0o020, 0o010, 0o004, 0o002,
                                            0o001)
                                if source_mode & bit
                            )
                        elif policy == "normalize-preserve-exec":
                            wrong_modes = (0o644,)
                        elif policy == "fold-class-bits-to-owner":
                            wrong_modes = (0o600, 0o500, 0o300)
                        else:
                            wrong_modes = ()
                        for wrong_mode in wrong_modes:
                            mutant = _patch_header_field(
                                canonical,
                                member_index,
                                100,
                                8,
                                _octal_field(wrong_mode, 8),
                            )
                            self.assertFalse(
                                verify_ustar_pack_output(
                                    bundle.definition,
                                    task.parameters,
                                    mutant,
                                )
                            )

    def test_verifier_rejects_structural_header_and_semantic_mutants(self) -> None:
        task = self.task("all-mode-readable", "preserve-permission-bits")
        bundle = self.by_pair[(task.task_id, "partial-permissions")]
        canonical = bundle.oracle.outputs[0].content
        segments, terminator = _archive_segments(canonical)
        self.assertGreaterEqual(len(segments), 4)
        segment_bytes = tuple(
            canonical[segment.start : segment.end] for segment in segments
        )
        zero_tail = canonical[terminator:]

        missing = b"".join(segment_bytes[1:]) + zero_tail
        duplicate = segment_bytes[0] + b"".join(segment_bytes) + zero_tail
        reordered = (
            segment_bytes[1]
            + segment_bytes[0]
            + b"".join(segment_bytes[2:])
            + zero_tail
        )

        extra_segment = _patch_header_field(
            segment_bytes[-1] + zero_tail,
            0,
            0,
            100,
            b"zzzz-extra.txt",
        )[: len(segment_bytes[-1])]
        extra = b"".join(segment_bytes) + extra_segment + zero_tail

        first_nonempty = next(
            segment for segment in segments if segment.size > 0
        )
        payload_mutant = bytearray(canonical)
        payload_mutant[first_nonempty.start + BLOCK_SIZE] ^= 1

        padding_mutant = bytearray(canonical)
        padding_start = (
            first_nonempty.start + BLOCK_SIZE + first_nonempty.size
        )
        self.assertLess(padding_start, first_nonempty.end)
        padding_mutant[padding_start] = 1

        checksum_mutant = bytearray(canonical)
        checksum_mutant[segments[0].start + 148] ^= 1

        mutants = {
            "missing-member": missing,
            "extra-member": extra,
            "duplicate-member": duplicate,
            "reordered-members": reordered,
            "payload": bytes(payload_mutant),
            "nonzero-member-padding": bytes(padding_mutant),
            "checksum": bytes(checksum_mutant),
            "mode": _patch_header_field(
                canonical, 0, 100, 8, _octal_field(0o777, 8)
            ),
            "size": _patch_header_field(
                canonical, 0, 124, 12, _octal_field(0, 12)
            ),
            "typeflag": _patch_header_field(canonical, 0, 156, 1, b"5"),
            "unsafe-path": _patch_header_field(
                canonical, 0, 0, 100, b"../escape.txt"
            ),
            "absolute-path": _patch_header_field(
                canonical, 0, 0, 100, b"/escape.txt"
            ),
            "leading-dot-path": _patch_header_field(
                canonical, 0, 0, 100, b"./escape.txt"
            ),
            "invalid-utf8-path": _patch_header_field(
                canonical, 0, 0, 100, b"invalid-\xff.txt"
            ),
            "uid": _patch_header_field(
                canonical, 0, 108, 8, _octal_field(1, 8)
            ),
            "gid": _patch_header_field(
                canonical, 0, 116, 8, _octal_field(1, 8)
            ),
            "mtime": _patch_header_field(
                canonical, 0, 136, 12, _octal_field(1, 12)
            ),
            "uname": _patch_header_field(canonical, 0, 265, 32, b"root"),
            "gname": _patch_header_field(canonical, 0, 297, 32, b"root"),
            "linkname": _patch_header_field(canonical, 0, 157, 100, b"target"),
            "magic": _patch_header_field(canonical, 0, 257, 6, b"ustar "),
            "version": _patch_header_field(canonical, 0, 263, 2, b"01"),
            "reserved-header": _patch_header_field(
                canonical, 0, 500, 12, b"reserved"
            ),
            "base256-size": _patch_header_field(
                canonical,
                0,
                124,
                12,
                b"\x80" + b"\0" * 11,
            ),
            "nonzero-after-terminator": canonical[:-1] + b"x",
            "missing-zero-block": canonical[: terminator + BLOCK_SIZE],
            "partial-block": canonical + b"\0",
            "oversized": canonical
            + b"\0" * (USTAR_PACK_OUTPUT_MAXIMUM_BYTES - len(canonical) + BLOCK_SIZE),
        }
        for name, mutant in mutants.items():
            with self.subTest(mutant=name):
                self.assertNotEqual(mutant, canonical)
                self.assertFalse(
                    verify_ustar_pack_output(
                        bundle.definition, task.parameters, mutant
                    )
                )

        selector_task = self.task(
            "txt-suffix-mode-readable", "preserve-permission-bits"
        )
        selector_archive = derive_ustar_pack_output(
            bundle.definition, selector_task.parameters
        )
        self.assertNotEqual(selector_archive, canonical)
        self.assertFalse(
            verify_ustar_pack_output(
                bundle.definition, task.parameters, selector_archive
            )
        )

        mode_task = self.task("all-mode-readable", "fixed-0644")
        mode_archive = derive_ustar_pack_output(
            bundle.definition, mode_task.parameters
        )
        self.assertNotEqual(mode_archive, canonical)
        self.assertFalse(
            verify_ustar_pack_output(
                bundle.definition, task.parameters, mode_archive
            )
        )
        self.assertFalse(
            verify_ustar_pack_output(
                bundle.definition,
                task.parameters,
                bytearray(canonical),  # type: ignore[arg-type]
            )
        )
        self.assertFalse(
            verify_ustar_pack_output(
                bundle.definition,
                task.parameters,
                _BytesSubclass(canonical),
            )
        )

    def test_independent_reference_disagreement_is_a_required_fail_closed_gate(
        self,
    ) -> None:
        task = self.task("all-mode-readable", "preserve-permission-bits")
        profile = _profile("spaces-unicode")
        bundle = self.by_pair[(task.task_id, profile.profile_id)]
        expected = bundle.oracle.outputs[0].content
        with mock.patch.object(
            ustar, "reference_ustar_pack_output", return_value=b"corrupt"
        ):
            self.assertFalse(
                verify_ustar_pack_output(
                    bundle.definition, task.parameters, expected
                )
            )
            with self.assertRaisesRegex(UstarPackError, "producers disagree"):
                build_ustar_pack_fixture_bundle(task, profile)
        with mock.patch.object(
            ustar,
            "reference_ustar_pack_members",
            return_value=(UstarPackMember("wrong", b"wrong", 0o644),),
        ):
            self.assertFalse(
                verify_ustar_pack_output(
                    bundle.definition, task.parameters, expected
                )
            )

    def test_cross_task_profile_bundle_and_descriptor_substitution_fail_closed(
        self,
    ) -> None:
        task = self.tasks[0]
        other_task = self.tasks[1]
        profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
        other_profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[1]
        bundle = self.by_pair[(task.task_id, profile.profile_id)]
        other_task_bundle = self.by_pair[
            (other_task.task_id, profile.profile_id)
        ]
        other_profile_bundle = self.by_pair[
            (task.task_id, other_profile.profile_id)
        ]

        self.assertTrue(verify_ustar_pack_fixture_bundle(other_task_bundle))
        self.assertTrue(verify_ustar_pack_fixture_bundle(other_profile_bundle))
        self.assertFalse(
            verify_ustar_pack_fixture_for_task_profile(
                task, profile, other_task_bundle
            )
        )
        self.assertFalse(
            verify_ustar_pack_fixture_for_task_profile(
                task, profile, other_profile_bundle
            )
        )
        self.assertFalse(
            verify_ustar_pack_fixture_for_task_profile(
                other_task, profile, bundle
            )
        )
        self.assertFalse(
            verify_ustar_pack_fixture_for_task_profile(
                task, other_profile, bundle
            )
        )
        self.assertFalse(verify_ustar_pack_fixture_bundle(object()))

        with self.assertRaises(UstarPackError):
            replace(bundle, task_contract_sha256=other_task.task_contract_sha256)
        with self.assertRaises(UstarPackError):
            replace(bundle, profile_sha256=other_profile.profile_sha256)
        with self.assertRaises(UstarPackError):
            replace(bundle, descriptor=other_task_bundle.descriptor)

        swapped_task = replace(task)
        fixtures = list(swapped_task.fixtures)
        fixtures[0], fixtures[1] = fixtures[1], fixtures[0]
        object.__setattr__(swapped_task, "fixtures", tuple(fixtures))
        swapped_task.__post_init__()
        self.assertFalse(
            verify_ustar_pack_fixture_for_task_profile(
                swapped_task, profile, bundle
            )
        )
        with self.assertRaisesRegex(UstarPackError, "descriptor differs"):
            build_ustar_pack_fixture_bundle(swapped_task, profile)

    def test_hostile_exact_type_hash_and_authority_tampering_fail_closed(self) -> None:
        with self.assertRaises(UstarPackError):
            UstarPackParameters(
                _StringSubclass("all-mode-readable"),  # type: ignore[arg-type]
                "fixed-0644",
            )
        with self.assertRaises(UstarPackError):
            UstarPackParameters(
                "all-mode-readable",
                _StringSubclass("fixed-0644"),  # type: ignore[arg-type]
            )

        task = self.tasks[0]
        profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
        canonical = self.by_pair[(task.task_id, profile.profile_id)]

        forged_task = replace(task)
        object.__setattr__(forged_task, "candidate_execution_authorized", True)
        with self.assertRaises(UstarPackError):
            build_ustar_pack_fixture_bundle(forged_task, profile)

        forged_parameters = replace(task.parameters)
        object.__setattr__(forged_parameters, "selector", "outside-contract")
        forged_task = replace(task)
        object.__setattr__(forged_task, "parameters", forged_parameters)
        with self.assertRaises(UstarPackError):
            build_ustar_pack_fixture_bundle(forged_task, profile)

        forged_profile = replace(profile)
        object.__setattr__(forged_profile, "claim_authorized", True)
        with self.assertRaises(UstarPackError):
            build_ustar_pack_fixture_bundle(task, forged_profile)

        for field_name in (
            "candidate_execution_authorized",
            "model_selection_eligible",
            "claim_authorized",
        ):
            forged = build_ustar_pack_fixture_bundle(task, profile)
            object.__setattr__(forged, field_name, True)
            with self.subTest(authority=field_name):
                self.assertFalse(verify_ustar_pack_fixture_bundle(forged))

        forged_digest = build_ustar_pack_fixture_bundle(task, profile)
        object.__setattr__(forged_digest, "fixture_definition_sha256", "0" * 64)
        self.assertFalse(verify_ustar_pack_fixture_bundle(forged_digest))

        forged_descriptor = build_ustar_pack_fixture_bundle(task, profile)
        object.__setattr__(
            forged_descriptor.descriptor, "fixture_sha256", "0" * 64
        )
        self.assertFalse(verify_ustar_pack_fixture_bundle(forged_descriptor))

        forged_oracle = build_ustar_pack_fixture_bundle(task, profile)
        object.__setattr__(forged_oracle.oracle, "oracle_sha256", "0" * 64)
        self.assertFalse(verify_ustar_pack_fixture_bundle(forged_oracle))

        forged_bytes = build_ustar_pack_fixture_bundle(task, profile)
        object.__setattr__(
            forged_bytes.oracle.outputs[0],
            "content",
            _BytesSubclass(forged_bytes.oracle.outputs[0].content),
        )
        self.assertFalse(verify_ustar_pack_fixture_bundle(forged_bytes))

        forged_input = build_ustar_pack_fixture_bundle(task, profile)
        input_file = next(
            item
            for item in forged_input.definition.inputs
            if type(item) is InputFile
        )
        object.__setattr__(input_file, "content", bytearray(input_file.content))
        self.assertFalse(verify_ustar_pack_fixture_bundle(forged_input))

        forged_path = build_ustar_pack_fixture_bundle(task, profile)
        input_file = next(
            item
            for item in forged_path.definition.inputs
            if type(item) is InputFile
        )
        object.__setattr__(input_file, "path", _StringSubclass(input_file.path))
        self.assertFalse(verify_ustar_pack_fixture_bundle(forged_path))

        forged_link = build_ustar_pack_fixture_bundle(task, profile)
        link = next(
            item
            for item in forged_link.definition.inputs
            if type(item) is InputSymlink
        )
        object.__setattr__(link, "target", _StringSubclass(link.target))
        self.assertFalse(verify_ustar_pack_fixture_bundle(forged_link))

        forged_container = build_ustar_pack_fixture_bundle(task, profile)
        object.__setattr__(
            forged_container.definition,
            "inputs",
            list(forged_container.definition.inputs),
        )
        self.assertFalse(verify_ustar_pack_fixture_bundle(forged_container))

        forged_policy = build_ustar_pack_fixture_bundle(task, profile)
        object.__setattr__(
            forged_policy.definition.expected_files[0],
            "maximum_bytes",
            len(forged_policy.oracle.outputs[0].content),
        )
        self.assertFalse(verify_ustar_pack_fixture_bundle(forged_policy))

        record = canonical.commitment_record()
        self.assertNotIn("content", repr(record))
        self.assertEqual(
            record["oracle"]["outputs"][0]["sha256"],  # type: ignore[index]
            canonical.oracle.outputs[0].commitment_record()["sha256"],
        )

    def test_generation_and_semantic_verification_never_invoke_a_process(
        self,
    ) -> None:
        with mock.patch.object(
            subprocess, "run", side_effect=AssertionError("run invoked")
        ), mock.patch.object(
            subprocess, "Popen", side_effect=AssertionError("Popen invoked")
        ), mock.patch.object(
            os, "system", side_effect=AssertionError("system invoked")
        ), mock.patch.object(
            os, "popen", side_effect=AssertionError("popen invoked")
        ):
            tasks = build_ustar_pack_tasks()
            self.assertEqual(len(tasks), 20)
            for task in tasks:
                for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                    bundle = build_ustar_pack_fixture_bundle(task, profile)
                    self.assertTrue(
                        verify_ustar_pack_output(
                            bundle.definition,
                            task.parameters,
                            bundle.oracle.outputs[0].content,
                        )
                    )
                    self.assertEqual(
                        derive_ustar_pack_output(
                            bundle.definition, task.parameters
                        ),
                        reference_ustar_pack_output(
                            bundle.definition, task.parameters
                        ),
                    )

    def test_all_100_authenticated_materializations_reject_missing_and_corrupt(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ordinal = 0
            for task in self.tasks:
                for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                    bundle = self.by_pair[(task.task_id, profile.profile_id)]
                    workspace = root / f"workspace-{ordinal:03d}"
                    ordinal += 1
                    with self.subTest(
                        task=task.task_id, profile=profile.profile_id
                    ):
                        with materialize_ustar_pack_fixture(
                            task, profile, bundle, workspace
                        ) as handle:
                            self.assertFalse(
                                (workspace / USTAR_PACK_OUTPUT).exists()
                            )
                            self.assertFalse(
                                verify_ustar_pack_workspace(
                                    task, profile, bundle, handle
                                )
                            )
                            expected = bundle.oracle.outputs[0].content
                            _write_archive(workspace, expected)
                            self.assertTrue(
                                verify_ustar_pack_workspace(
                                    task, profile, bundle, handle
                                )
                            )
                            corrupt = bytearray(expected)
                            corrupt[0] ^= 1
                            output = workspace / USTAR_PACK_OUTPUT
                            output.write_bytes(corrupt)
                            os.chmod(output, 0o644)
                            self.assertFalse(
                                verify_ustar_pack_workspace(
                                    task, profile, bundle, handle
                                )
                            )
            self.assertEqual(ordinal, 100)

    def test_workspace_verifier_accepts_alternate_padding_and_exact_tree(self) -> None:
        task = self.task("all-mode-readable", "preserve-permission-bits")
        profile = _profile("symlinks-ordering")
        bundle = self.by_pair[(task.task_id, profile.profile_id)]
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            with materialize_ustar_pack_fixture(
                task, profile, bundle, workspace
            ) as handle:
                scan = handle.scan_inputs()
                observed = {entry.path: entry for entry in scan.entries}
                self.assertEqual(observed["input/source/00-link.txt"].kind, "symlink")
                self.assertEqual(
                    observed["input/source/00-link.txt"].symlink_target,
                    "z-last.txt",
                )
                self.assertFalse((workspace / USTAR_PACK_OUTPUT).exists())
                _write_archive(
                    workspace, bundle.oracle.outputs[0].content + ZERO_BLOCK
                )
                self.assertTrue(
                    verify_ustar_pack_workspace(
                        task, profile, bundle, handle
                    )
                )
            self.assertFalse(
                verify_ustar_pack_workspace(task, profile, bundle, handle)
            )

    def test_workspace_input_and_output_mutations_fail_closed(self) -> None:
        task = self.task("all-mode-readable", "preserve-permission-bits")
        profile = _profile("symlinks-ordering")
        bundle = self.by_pair[(task.task_id, profile.profile_id)]

        def mutate_input_bytes(workspace: Path, _temporary: Path) -> None:
            path = workspace / "input/source/z-last.txt"
            path.write_bytes(path.read_bytes() + b"mutant\n")

        def mutate_input_mode(workspace: Path, _temporary: Path) -> None:
            os.chmod(workspace / "input/source/z-last.txt", 0o600)

        def mutate_input_mtime(workspace: Path, _temporary: Path) -> None:
            path = workspace / "input/source/z-last.txt"
            metadata = path.stat(follow_symlinks=False)
            os.utime(
                path,
                ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000),
                follow_symlinks=False,
            )

        def mutate_input_symlink(workspace: Path, _temporary: Path) -> None:
            path = workspace / "input/source/00-link.txt"
            path.unlink()
            path.symlink_to("a-first.bin")

        def add_input(workspace: Path, _temporary: Path) -> None:
            (workspace / "input/source/extra.txt").write_bytes(b"extra")

        def remove_input(workspace: Path, _temporary: Path) -> None:
            (workspace / "input/source/z-last.txt").unlink()

        def add_input_hardlink(workspace: Path, temporary: Path) -> None:
            os.link(
                workspace / "input/source/z-last.txt",
                temporary / "outside-input-link",
            )

        def mutate_output_bytes(workspace: Path, _temporary: Path) -> None:
            path = workspace / USTAR_PACK_OUTPUT
            payload = bytearray(path.read_bytes())
            payload[0] ^= 1
            path.write_bytes(payload)

        def mutate_output_mode(workspace: Path, _temporary: Path) -> None:
            os.chmod(workspace / USTAR_PACK_OUTPUT, 0o600)

        def mutate_output_directory_mode(workspace: Path, _temporary: Path) -> None:
            os.chmod(workspace / "output", 0o700)

        def add_output(workspace: Path, _temporary: Path) -> None:
            (workspace / "output/extra").write_bytes(b"extra")

        def remove_output(workspace: Path, _temporary: Path) -> None:
            (workspace / USTAR_PACK_OUTPUT).unlink()

        def replace_output_with_symlink(workspace: Path, _temporary: Path) -> None:
            path = workspace / USTAR_PACK_OUTPUT
            path.unlink()
            path.symlink_to("../input/source/z-last.txt")

        def add_output_hardlink(workspace: Path, temporary: Path) -> None:
            os.link(
                workspace / USTAR_PACK_OUTPUT,
                temporary / "outside-output-link",
            )

        mutations = (
            ("input-bytes", mutate_input_bytes),
            ("input-mode", mutate_input_mode),
            ("input-mtime", mutate_input_mtime),
            ("input-symlink", mutate_input_symlink),
            ("input-extra", add_input),
            ("input-missing", remove_input),
            ("input-hardlink", add_input_hardlink),
            ("output-bytes", mutate_output_bytes),
            ("output-mode", mutate_output_mode),
            ("output-directory-mode", mutate_output_directory_mode),
            ("output-extra", add_output),
            ("output-missing", remove_output),
            ("output-symlink", replace_output_with_symlink),
            ("output-hardlink", add_output_hardlink),
        )
        for name, mutation in mutations:
            with self.subTest(mutation=name):
                with tempfile.TemporaryDirectory() as temporary:
                    temporary_path = Path(temporary)
                    workspace = temporary_path / "workspace"
                    with materialize_ustar_pack_fixture(
                        task, profile, bundle, workspace
                    ) as handle:
                        _write_archive(
                            workspace, bundle.oracle.outputs[0].content
                        )
                        mutation(workspace, temporary_path)
                        self.assertFalse(
                            verify_ustar_pack_workspace(
                                task, profile, bundle, handle
                            )
                        )

    def test_module_has_no_assert_subprocess_or_frozen_registry_writes(self) -> None:
        source_path = ROOT / "src/cbds/executable_ustar_pack.py"
        source = source_path.read_text(encoding="utf-8")
        parsed = ast.parse(source, filename=str(source_path))
        self.assertFalse(
            any(isinstance(node, ast.Assert) for node in ast.walk(parsed))
        )
        imported_modules = {
            alias.name
            for node in ast.walk(parsed)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported_modules.update(
            node.module or ""
            for node in ast.walk(parsed)
            if isinstance(node, ast.ImportFrom)
        )
        self.assertNotIn("subprocess", imported_modules)
        self.assertNotIn("executable_static_registry", source)
        self.assertNotIn("executable_static_second_registry", source)
        self.assertNotIn("executable_static_third_registry", source)
        self.assertNotIn("executable_fixture_catalog", source)
        self.assertNotIn("development_invocation", source)


if __name__ == "__main__":
    unittest.main()
