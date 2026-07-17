from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import cbds.executable_compressed_archive_roundtrip_verify as archive  # noqa: E402
from cbds.executable_compressed_archive_roundtrip_verify import (  # noqa: E402
    COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_ALLOWED_TOOLS,
    COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_ARCHIVE_PATHS,
    COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_COMPRESSION_FORMATS,
    COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_FILESYSTEM_IDENTITY,
    COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_OUTPUT_IDENTITY,
    COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_REPORT,
    COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_TOOL_HISTORY_OBSERVED,
    COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_VERIFICATION_HISTORY_OBSERVED,
    COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_VERIFICATION_POLICIES,
    COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE,
    CompressedArchiveRoundtripVerifyError,
    CompressedArchiveRoundtripVerifyParameters,
    build_compressed_archive_roundtrip_verify_fixture_bundle,
    build_compressed_archive_roundtrip_verify_tasks,
    compute_compressed_archive_roundtrip_verify_discrimination_sha256,
    decompress_compressed_archive_roundtrip_verify_output,
    derive_compressed_archive_roundtrip_verify_report,
    derive_compressed_archive_roundtrip_verify_state,
    materialize_compressed_archive_roundtrip_verify_fixture,
    reference_compressed_archive_roundtrip_verify_state,
    validate_compressed_archive_roundtrip_verify_fixture_for_task_profile,
    verify_compressed_archive_roundtrip_verify_archive,
    verify_compressed_archive_roundtrip_verify_fixture_bundle,
    verify_compressed_archive_roundtrip_verify_workspace,
)
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from cbds.executable_workspace import InputFile, InputHardlink  # noqa: E402


BLOCK = 512
ZERO_BLOCK = b"\0" * BLOCK


def _segments(payload: bytes) -> tuple[list[tuple[int, int]], int]:
    result: list[tuple[int, int]] = []
    cursor = 0
    while cursor + BLOCK <= len(payload):
        header = payload[cursor : cursor + BLOCK]
        if header == ZERO_BLOCK:
            return result, cursor
        size_wire = header[124:136].strip(b" \0")
        size = int(size_wire, 8) if size_wire else 0
        end = cursor + BLOCK + ((size + BLOCK - 1) // BLOCK) * BLOCK
        if end > len(payload):
            raise AssertionError("truncated test archive")
        result.append((cursor, end))
        cursor = end
    raise AssertionError("missing test archive terminator")


def _rechecksum(payload: bytearray, start: int) -> None:
    header = bytearray(payload[start : start + BLOCK])
    header[148:156] = b" " * 8
    checksum = f"{sum(header):06o}".encode("ascii")
    header[148:156] = checksum + b"\0 "
    payload[start : start + BLOCK] = header


def _patch_header(
    raw: bytes, member: int, offset: int, width: int, value: bytes
) -> bytes:
    segments, _ = _segments(raw)
    start, _end = segments[member]
    mutated = bytearray(raw)
    mutated[start + offset : start + offset + width] = value + b"\0" * (
        width - len(value)
    )
    _rechecksum(mutated, start)
    return bytes(mutated)


def _profile(profile_id: str):
    return next(
        item
        for item in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        if item.profile_id == profile_id
    )


class CompressedArchiveRoundtripVerifyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tasks = build_compressed_archive_roundtrip_verify_tasks()
        cls.bundles = {
            (task.task_id, profile.profile_id):
            build_compressed_archive_roundtrip_verify_fixture_bundle(
                task, profile
            )
            for task in cls.tasks
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        }

    def task(self, format_name: str, policy: str):
        return next(
            task
            for task in self.tasks
            if task.parameters.compression_format == format_name
            and task.parameters.verification_policy == policy
        )

    def test_locked_grid_tools_and_identity(self) -> None:
        self.assertEqual(
            COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_COMPRESSION_FORMATS,
            ("gzip", "bzip2", "xz", "none"),
        )
        self.assertEqual(
            COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_VERIFICATION_POLICIES,
            (
                "archive-digest",
                "member-digests",
                "roundtrip-bytes",
                "roundtrip-bytes-and-modes",
                "strict-all",
            ),
        )
        self.assertEqual(
            COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_ALLOWED_TOOLS,
            ("bzip2", "gzip", "mkdir", "sha256sum", "sort", "tar", "xz"),
        )
        self.assertEqual(
            COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_FILESYSTEM_IDENTITY,
            "archive-roundtrip-source-tree",
        )
        self.assertEqual(
            COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_OUTPUT_IDENTITY,
            "compressed-archive-with-verification-report",
        )
        self.assertEqual(len(self.tasks), 20)
        self.assertEqual(
            tuple(
                (
                    task.parameters.compression_format,
                    task.parameters.verification_policy,
                )
                for task in self.tasks
            ),
            tuple(
                (format_name, policy)
                for format_name in COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_COMPRESSION_FORMATS
                for policy in COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_VERIFICATION_POLICIES
            ),
        )
        self.assertEqual(
            len({task.task_contract_sha256 for task in self.tasks}), 20
        )
        digest = compute_compressed_archive_roundtrip_verify_discrimination_sha256(
            self.tasks
        )
        self.assertRegex(digest, r"^[0-9a-f]{64}$")

    def test_every_bundle_reconstructs_and_binds_two_oracles(self) -> None:
        self.assertEqual(len(self.bundles), 100)
        self.assertEqual(
            len(
                {
                    bundle.descriptor.fixture_sha256
                    for bundle in self.bundles.values()
                }
            ),
            100,
        )
        for task in self.tasks:
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                bundle = self.bundles[(task.task_id, profile.profile_id)]
                with self.subTest(
                    format=task.parameters.compression_format,
                    policy=task.parameters.verification_policy,
                    profile=profile.profile_id,
                ):
                    validate_compressed_archive_roundtrip_verify_fixture_for_task_profile(
                        task, profile, bundle
                    )
                    self.assertTrue(
                        verify_compressed_archive_roundtrip_verify_fixture_bundle(
                            bundle
                        )
                    )
                    primary = derive_compressed_archive_roundtrip_verify_state(
                        bundle.definition, task.parameters
                    )
                    reference = (
                        reference_compressed_archive_roundtrip_verify_state(
                            bundle.definition, task.parameters
                        )
                    )
                    self.assertEqual(primary, reference)
                    self.assertEqual(primary, bundle.oracle.state)
                    self.assertTrue(
                        verify_compressed_archive_roundtrip_verify_archive(
                            bundle.definition,
                            task.parameters,
                            primary.archive,
                        )
                    )

    def test_formats_have_closed_magic_and_single_stream_roundtrip(self) -> None:
        expected_magic = {
            "gzip": b"\x1f\x8b",
            "bzip2": b"BZh",
            "xz": b"\xfd7zXZ\x00",
        }
        for format_name in COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_COMPRESSION_FORMATS:
            task = self.task(format_name, "strict-all")
            bundle = self.bundles[(task.task_id, "spaces-unicode")]
            state = bundle.oracle.state
            with self.subTest(format=format_name):
                self.assertEqual(
                    decompress_compressed_archive_roundtrip_verify_output(
                        state.archive, format_name
                    ),
                    state.raw_archive,
                )
                if format_name == "none":
                    self.assertEqual(state.archive, state.raw_archive)
                    self.assertEqual(state.archive[257:263], b"ustar\0")
                else:
                    self.assertTrue(
                        state.archive.startswith(expected_magic[format_name])
                    )

    def test_canonical_gzip_normalizes_interpreter_specific_os_byte(
        self,
    ) -> None:
        raw = b"cross-version canonical gzip\n"
        canonical = archive._canonical_compress(raw, "gzip")
        platform_header = canonical[:9] + b"\x03" + canonical[10:]
        with mock.patch.object(
            archive.gzip,
            "compress",
            return_value=platform_header,
        ):
            rebuilt = archive._canonical_compress(raw, "gzip")
        self.assertEqual(rebuilt, canonical)
        self.assertEqual(rebuilt[9], 255)
        self.assertEqual(
            decompress_compressed_archive_roundtrip_verify_output(
                rebuilt, "gzip"
            ),
            raw,
        )

    def test_codec_truncation_corruption_concatenation_and_cross_format_die(self) -> None:
        states = {}
        for format_name in COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_COMPRESSION_FORMATS:
            task = self.task(format_name, "strict-all")
            bundle = self.bundles[(task.task_id, "spaces-unicode")]
            states[format_name] = (task, bundle, bundle.oracle.state.archive)

        for format_name in ("gzip", "bzip2", "xz"):
            task, bundle, payload = states[format_name]
            corrupt = bytearray(payload)
            corrupt[len(corrupt) // 2] ^= 1
            mutants = (
                payload[:-1],
                bytes(corrupt),
                payload + payload,
                payload + b"\0\0\0\0",
            )
            for index, mutant in enumerate(mutants):
                with self.subTest(format=format_name, mutant=index):
                    with self.assertRaises(
                        CompressedArchiveRoundtripVerifyError
                    ):
                        decompress_compressed_archive_roundtrip_verify_output(
                            mutant, format_name
                        )
                    self.assertFalse(
                        verify_compressed_archive_roundtrip_verify_archive(
                            bundle.definition, task.parameters, mutant
                        )
                    )

        for expected_format in ("gzip", "bzip2", "xz", "none"):
            task, bundle, _payload = states[expected_format]
            for actual_format in ("gzip", "bzip2", "xz", "none"):
                if actual_format == expected_format:
                    continue
                with self.subTest(
                    expected=expected_format, actual=actual_format
                ):
                    self.assertFalse(
                        verify_compressed_archive_roundtrip_verify_archive(
                            bundle.definition,
                            task.parameters,
                            states[actual_format][2],
                        )
                    )

    def test_codec_byte_caps_fail_before_semantic_admission(self) -> None:
        too_large = (
            b"x"
            * (
                archive.COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_MAXIMUM_ARCHIVE_BYTES
                + 1
            )
        )
        for format_name in COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_COMPRESSION_FORMATS:
            with self.subTest(format=format_name):
                with self.assertRaises(
                    CompressedArchiveRoundtripVerifyError
                ):
                    decompress_compressed_archive_roundtrip_verify_output(
                        too_large, format_name
                    )

        oversized_raw = b"x" * (archive.USTAR_PACK_OUTPUT_MAXIMUM_BYTES + 1)
        for format_name in ("gzip", "bzip2", "xz"):
            compressed = archive._canonical_compress(
                oversized_raw, format_name
            )
            with self.subTest(raw_over_cap=format_name):
                with self.assertRaises(
                    CompressedArchiveRoundtripVerifyError
                ):
                    decompress_compressed_archive_roundtrip_verify_output(
                        compressed, format_name
                    )

    def test_unsafe_type_extension_duplicate_order_metadata_and_padding_die(self) -> None:
        task = self.task("none", "strict-all")
        bundle = self.bundles[(task.task_id, "spaces-unicode")]
        raw = bundle.oracle.state.raw_archive
        segments, terminator = _segments(raw)
        first_start, first_end = segments[0]
        second_start, second_end = segments[1]

        unsafe_path = _patch_header(raw, 0, 0, 100, b"../escape.txt")
        symlink_type = _patch_header(raw, 0, 156, 1, b"2")
        pax_type = _patch_header(raw, 0, 156, 1, b"x")
        wrong_uid = _patch_header(raw, 0, 108, 8, b"0000001")
        wrong_mtime = _patch_header(raw, 0, 136, 12, b"00000000001")
        wrong_mode = _patch_header(raw, 0, 100, 8, b"0000777")
        duplicate = (
            raw[:terminator]
            + raw[first_start:first_end]
            + raw[terminator:]
        )
        missing = raw[:first_start] + raw[first_end:]
        renamed = _patch_header(raw, 0, 0, 100, b"zz-extra.bin")
        extra = (
            raw[:terminator]
            + renamed[first_start:first_end]
            + raw[terminator:]
        )
        unsorted = (
            raw[:first_start]
            + raw[second_start:second_end]
            + raw[first_start:first_end]
            + raw[second_end:]
        )
        padded = bytearray(raw)
        first_size = int(
            padded[first_start + 124 : first_start + 136].strip(b" \0"), 8
        )
        padding = first_start + BLOCK + first_size
        if padding == first_end:
            self.fail("fixture first member unexpectedly has no padding")
        padded[padding] = 1
        mutants = (
            unsafe_path,
            symlink_type,
            pax_type,
            wrong_uid,
            wrong_mtime,
            wrong_mode,
            duplicate,
            missing,
            extra,
            unsorted,
            bytes(padded),
        )
        for index, mutant in enumerate(mutants):
            with self.subTest(mutant=index):
                self.assertFalse(
                    verify_compressed_archive_roundtrip_verify_archive(
                        bundle.definition, task.parameters, mutant
                    )
                )

    def test_reports_are_candidate_relative_and_cross_policy_rejecting(self) -> None:
        profile_id = "leading-dashes-globs"
        for format_name in COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_COMPRESSION_FORMATS:
            reports: dict[str, bytes] = {}
            for policy in COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_VERIFICATION_POLICIES:
                task = self.task(format_name, policy)
                bundle = self.bundles[(task.task_id, profile_id)]
                state = bundle.oracle.state
                report = derive_compressed_archive_roundtrip_verify_report(
                    bundle.definition, task.parameters, state.archive
                )
                self.assertEqual(report, state.report)
                reports[policy] = report
            self.assertEqual(len(set(reports.values())), 5)
            for left, left_report in reports.items():
                for right, right_report in reports.items():
                    with self.subTest(
                        format=format_name, report=left, policy=right
                    ):
                        self.assertEqual(left_report == right_report, left == right)

    def test_manifest_is_authoritative_and_distractors_are_excluded(self) -> None:
        task = self.task("none", "strict-all")
        bundle = self.bundles[(task.task_id, "partial-permissions")]
        paths = tuple(item.relative for item in bundle.oracle.state.records)
        self.assertIn("modes/owner-only.txt", paths)
        self.assertNotIn("ignored/group-only.txt", paths)
        self.assertNotIn("ignored/other-only.txt", paths)
        self.assertNotIn("ignored/no-access.txt", paths)
        self.assertNotIn("ignored/execute-only.sh", paths)
        self.assertTrue(
            all(item.mode & 0o400 for item in bundle.oracle.state.records)
        )

    def test_hardlink_names_become_independent_regular_members(self) -> None:
        task = self.task("none", "strict-all")
        bundle = self.bundles[(task.task_id, "empty-duplicates")]
        inputs = bundle.definition.inputs
        self.assertTrue(any(type(item) is InputHardlink for item in inputs))
        records = {
            item.relative: item for item in bundle.oracle.state.records
        }
        self.assertEqual(
            records["links/00-base.bin"].content,
            records["links/alias.bin"].content,
        )
        members = {
            item.path: item for item in bundle.oracle.state.members
        }
        self.assertEqual(members["links/00-base.bin"].content, members["links/alias.bin"].content)

    def _publish_canonical_state(self, root: Path, bundle, task) -> None:
        state = bundle.oracle.state
        archive_path = COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_ARCHIVE_PATHS[
            task.parameters.compression_format
        ]
        for relative, payload, mode, mtime in (
            (archive_path, state.archive, 0o644, None),
            (COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_REPORT, state.report, 0o644, None),
        ):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            path.chmod(mode)
            if mtime is not None:
                os.utime(path, (mtime, mtime))
        for item in state.records:
            path = root / "output" / "roundtrip" / item.relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(item.content)
            path.chmod(item.mode)
            os.utime(path, (0, 0))
        for path in sorted(
            (item for item in (root / "output").rglob("*") if item.is_dir()),
            reverse=True,
        ):
            path.chmod(0o755)
        (root / "output").chmod(0o755)

    def test_all_100_canonical_workspaces_verify(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            for ordinal, task in enumerate(self.tasks):
                for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                    bundle = self.bundles[(task.task_id, profile.profile_id)]
                    workspace = Path(parent) / f"w-{ordinal}-{profile.profile_id}"
                    handle = materialize_compressed_archive_roundtrip_verify_fixture(
                        task, profile, bundle, workspace
                    )
                    try:
                        self._publish_canonical_state(workspace, bundle, task)
                        with self.subTest(
                            format=task.parameters.compression_format,
                            policy=task.parameters.verification_policy,
                            profile=profile.profile_id,
                        ):
                            self.assertTrue(
                                verify_compressed_archive_roundtrip_verify_workspace(
                                    task, profile, bundle, handle
                                )
                            )
                    finally:
                        handle.close()

    def test_workspace_rejects_output_input_metadata_and_topology_mutation(
        self,
    ) -> None:
        task = self.task("gzip", "strict-all")
        profile = _profile("spaces-unicode")
        bundle = self.bundles[(task.task_id, profile.profile_id)]
        mutators = (
            "report",
            "tree-bytes",
            "archive",
            "input",
            "missing",
            "extra",
            "symlink",
            "mode",
            "mtime",
            "link-count",
        )
        for mutator in mutators:
            with tempfile.TemporaryDirectory() as parent:
                handle = materialize_compressed_archive_roundtrip_verify_fixture(
                    task, profile, bundle, Path(parent) / "workspace"
                )
                try:
                    root = Path(parent) / "workspace"
                    self._publish_canonical_state(root, bundle, task)
                    tree_path = (
                        root
                        / "output"
                        / "roundtrip"
                        / bundle.oracle.state.records[0].relative
                    )
                    if mutator == "report":
                        path = root / COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_REPORT
                    elif mutator == "archive":
                        path = root / COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_ARCHIVE_PATHS["gzip"]
                    elif mutator == "input":
                        path = root / "input" / "source" / "probe" / "plain.txt"
                    else:
                        path = tree_path
                    if mutator in {"report", "tree-bytes", "archive", "input"}:
                        path.write_bytes(path.read_bytes() + b"x")
                    elif mutator == "missing":
                        path.unlink()
                    elif mutator == "extra":
                        extra_path = root / "output" / "unexpected.bin"
                        extra_path.write_bytes(b"unexpected\n")
                        extra_path.chmod(0o644)
                    elif mutator == "symlink":
                        path.unlink()
                        path.symlink_to("../missing-target")
                    elif mutator == "mode":
                        path.chmod(0o777)
                    elif mutator == "mtime":
                        os.utime(path, (1, 1))
                    elif mutator == "link-count":
                        os.link(path, root / "external-hardlink")
                    else:
                        self.fail(f"unknown mutation: {mutator}")
                    with self.subTest(mutator=mutator):
                        self.assertFalse(
                            verify_compressed_archive_roundtrip_verify_workspace(
                                task, profile, bundle, handle
                            )
                        )
                finally:
                    handle.close()

    def test_authority_and_assurance_limits_are_explicit(self) -> None:
        self.assertFalse(
            COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_VERIFICATION_HISTORY_OBSERVED
        )
        self.assertFalse(
            COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_TOOL_HISTORY_OBSERVED
        )
        self.assertFalse(
            COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE
        )
        for task in self.tasks:
            self.assertFalse(task.candidate_execution_authorized)
            self.assertFalse(task.model_selection_eligible)
            self.assertFalse(task.claim_authorized)

    def test_wrong_exact_types_and_forged_bundle_fail_closed(self) -> None:
        self.assertFalse(
            verify_compressed_archive_roundtrip_verify_fixture_bundle(object())
        )
        task = self.tasks[0]
        profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
        bundle = self.bundles[(task.task_id, profile.profile_id)]
        with self.assertRaises(CompressedArchiveRoundtripVerifyError):
            replace(bundle, fixture_definition_sha256="0" * 64)
        with self.assertRaises(CompressedArchiveRoundtripVerifyError):
            CompressedArchiveRoundtripVerifyParameters(
                "zip", "strict-all"  # type: ignore[arg-type]
            )


if __name__ == "__main__":
    unittest.main()
