from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.executable_workspace import (  # noqa: E402
    INPUT_ROOT,
    INITIAL_OUTPUT_POLICY,
    MAX_ENTRIES,
    MAX_FILE_BYTES,
    MAX_INPUT_MTIME_SECONDS,
    MAX_PATH_COMPONENT_UTF8_BYTES,
    MAX_PATH_UTF8_BYTES,
    MAX_TOTAL_BYTES,
    ExpectedFile,
    ExpectedSymlink,
    FixtureDefinition,
    InputFile,
    InputHardlink,
    InputSymlink,
    WorkspaceBaseline,
    WorkspaceClosedError,
    WorkspaceDefinitionError,
    WorkspaceEntry,
    WorkspaceMaterializationError,
    WorkspaceOutputPolicyError,
    WorkspaceOutputReadError,
    WorkspaceScanError,
    compute_workspace_hardlink_group_sha256,
    materialize_fixture,
    validate_expected_output_policy,
)
import cbds.executable_workspace as workspace_module  # noqa: E402
import cbds.static_slice as static_slice  # noqa: E402


def sample_definition() -> FixtureDefinition:
    return FixtureDefinition(
        fixture_id="fixture.workspace-safety",
        inputs=(
            InputFile("input/readable.txt", b"alpha\n", 0o640),
            InputFile("input/nested/locked.bin", b"sealed-input", 0o000),
            InputSymlink("input/nested/link.txt", "locked.bin"),
        ),
        expected_files=(
            ExpectedFile("output.txt", maximum_bytes=128, mode=0o644),
            ExpectedFile("reports/result.json", maximum_bytes=512),
        ),
    )


def by_path(entries: tuple[object, ...]) -> dict[str, object]:
    return {entry.path: entry for entry in entries}  # type: ignore[attr-defined]


class FrozenDefinitionTests(unittest.TestCase):
    def test_legacy_sample_fixture_digest_is_byte_stable(self) -> None:
        self.assertEqual(
            sample_definition().fixture_sha256,
            "71ffe6ae1702c60c8070b08e62f64bdc856b594cdf7c26020a634ccfce0f9774",
        )
        self.assertNotIn(
            "expected_symlinks",
            sample_definition().commitment_record(),
        )
        self.assertNotIn(
            "mtime_seconds",
            InputFile("input/file", b"content").to_record(),
        )
        timed = FixtureDefinition(
            "fixture.timed-input",
            (InputFile("input/file", b"content", mtime_seconds=123),),
            (),
        )
        retimed = replace(
            timed,
            inputs=(
                InputFile(
                    "input/file",
                    b"content",
                    mtime_seconds=124,
                ),
            ),
        )
        self.assertNotEqual(timed.fixture_sha256, retimed.fixture_sha256)

    def test_public_definition_types_are_frozen_and_answer_free(self) -> None:
        regular = InputFile("input/data.txt", b"private fixture bytes", 0o600)
        symlink = InputSymlink("input/data-link", "data.txt")
        expected = ExpectedFile("answer.txt", maximum_bytes=64, mode=0o640)
        definition = FixtureDefinition(
            "fixture.answer-free", (regular, symlink), (expected,)
        )

        with self.assertRaises(FrozenInstanceError):
            regular.path = "input/changed"  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            expected.maximum_bytes = 5  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            definition.inputs = ()  # type: ignore[misc]

        serialized = json.dumps(definition.commitment_record(), sort_keys=True)
        self.assertNotIn("private fixture bytes", serialized)
        self.assertNotIn("expected_answer", serialized)
        self.assertNotIn("answer_sha256", serialized)
        self.assertNotIn("content", expected.to_record())
        self.assertNotIn("sha256", expected.to_record())
        self.assertNotIn(b"private fixture bytes".decode(), repr(regular))
        self.assertEqual(
            definition.commitment_record()["initial_output_policy"],
            INITIAL_OUTPUT_POLICY,
        )

    def test_commitment_is_order_independent_but_binds_every_safety_field(self) -> None:
        left = InputFile("input/a", b"a", 0o600)
        right = InputFile("input/b", b"b", 0o644)
        first = FixtureDefinition(
            "fixture.commitment",
            (left, right),
            (ExpectedFile("z", 7), ExpectedFile("y", 8)),
        )
        reordered = FixtureDefinition(
            "fixture.commitment",
            (right, left),
            (ExpectedFile("y", 8), ExpectedFile("z", 7)),
        )
        changed = FixtureDefinition(
            "fixture.commitment",
            (left, replace(right, mode=0o600)),
            first.expected_files,
        )
        self.assertEqual(first.fixture_sha256, reordered.fixture_sha256)
        self.assertNotEqual(first.fixture_sha256, changed.fixture_sha256)
        self.assertRegex(first.fixture_sha256, r"^[0-9a-f]{64}$")

    def test_hardlink_definition_is_explicit_order_independent_and_bounded(
        self,
    ) -> None:
        source = InputFile("input/0-source.bin", b"shared\x00bytes", 0o400)
        alias = InputHardlink("input/nested/alias.bin", "input/0-source.bin")
        first = FixtureDefinition(
            "fixture.hardlink-definition",
            (source, alias),
            (ExpectedFile("mirror/source.bin", required_link_count=None),),
        )
        reordered = FixtureDefinition(
            "fixture.hardlink-definition",
            (alias, source),
            first.expected_files,
        )
        changed = FixtureDefinition(
            "fixture.hardlink-definition",
            (
                source,
                InputHardlink("input/other.bin", "input/0-source.bin"),
            ),
            first.expected_files,
        )
        self.assertEqual(first.fixture_sha256, reordered.fixture_sha256)
        self.assertNotEqual(first.fixture_sha256, changed.fixture_sha256)
        self.assertEqual(
            alias.to_record(),
            {
                "kind": "hardlink",
                "path": "input/nested/alias.bin",
                "target": "input/0-source.bin",
            },
        )
        self.assertIsNone(
            first.expected_files[0].to_record()["required_link_count"]
        )
        # The default record remains byte-for-byte compatible with the
        # pre-topology contract.
        self.assertEqual(
            ExpectedFile("answer", 7, 0o640).to_record(),
            {
                "path": "answer",
                "maximum_bytes": 7,
                "mode": 0o640,
                "required_kind": "regular",
                "required_link_count": 1,
            },
        )
        self.assertNotIn("expected_symlinks", first.commitment_record())

    def test_expected_symlink_boundary_is_exact_order_independent_and_additive(
        self,
    ) -> None:
        link = ExpectedSymlink("mirror/link", 32)
        first = FixtureDefinition(
            "fixture.expected-symlink",
            (),
            (ExpectedFile("mirror/target.bin", 16),),
            expected_symlinks=(
                ExpectedSymlink("mirror/z-link", 64),
                link,
            ),
        )
        reordered = FixtureDefinition(
            "fixture.expected-symlink",
            (),
            first.expected_files,
            expected_symlinks=tuple(reversed(first.expected_symlinks)),
        )
        changed = replace(
            first,
            expected_symlinks=(
                ExpectedSymlink("mirror/z-link", 64),
                ExpectedSymlink("mirror/link", 31),
            ),
        )
        self.assertEqual(first.fixture_sha256, reordered.fixture_sha256)
        self.assertNotEqual(first.fixture_sha256, changed.fixture_sha256)
        self.assertEqual(
            link.to_record(),
            {
                "path": "mirror/link",
                "maximum_target_utf8_bytes": 32,
                "required_kind": "symlink",
                "required_link_count": 1,
                "target_policy": "canonical-safe-relative-no-parent-v1",
            },
        )
        self.assertEqual(
            [
                item["path"]
                for item in first.commitment_record()["expected_symlinks"]
            ],
            ["mirror/link", "mirror/z-link"],
        )

    def test_hardlink_targets_and_output_link_bounds_fail_closed(self) -> None:
        for path, target in (
            ("input/a", "input/a"),
            ("input/a", "outside/a"),
            ("outside/a", "input/a"),
        ):
            with self.subTest(path=path, target=target), self.assertRaises(
                WorkspaceDefinitionError
            ):
                InputHardlink(path, target)
        with self.assertRaisesRegex(
            WorkspaceDefinitionError, "exact InputFile"
        ):
            FixtureDefinition(
                "fixture.missing-hardlink-target",
                (InputHardlink("input/alias", "input/missing"),),
                (),
            )
        with self.assertRaisesRegex(
            WorkspaceDefinitionError,
            "byte-smallest",
        ):
            FixtureDefinition(
                "fixture.noncanonical-hardlink-anchor",
                (
                    InputHardlink("input/a", "input/b"),
                    InputFile("input/b", b"same"),
                ),
                (),
            )
        with self.assertRaisesRegex(
            WorkspaceDefinitionError, "exact InputFile"
        ):
            FixtureDefinition(
                "fixture.hardlink-target-is-symlink",
                (
                    InputSymlink("input/target", "elsewhere"),
                    InputHardlink("input/alias", "input/target"),
                ),
                (),
            )
        for required in (0, -1, True, MAX_ENTRIES + 1):
            with self.subTest(required=required), self.assertRaises(
                WorkspaceDefinitionError
            ):
                ExpectedFile(  # type: ignore[arg-type]
                    "answer",
                    required_link_count=required,
                )
        valid = compute_workspace_hardlink_group_sha256(
            ("input/a", "input/b"),
            2,
        )
        self.assertRegex(valid, r"^[0-9a-f]{64}$")
        for paths, link_count in (
            ((), 2),
            (("input/b", "input/a"), 2),
            (("input/a", "input/a"), 2),
            (("input/a",), 1),
            (("input/a", "input/b"), 1),
        ):
            with self.subTest(
                paths=paths,
                link_count=link_count,
            ), self.assertRaises(WorkspaceDefinitionError):
                compute_workspace_hardlink_group_sha256(  # type: ignore[arg-type]
                    paths,
                    link_count,
                )

    def test_legacy_multiply_linked_scan_record_remains_revalidatable(self) -> None:
        legacy = WorkspaceEntry(
            path="output.bin",
            kind="file",
            mode=0o640,
            size=3,
            mtime_ns=10,
            link_count=2,
            content_sha256=sha256(b"abc").hexdigest(),
        )
        record = legacy.to_record()
        self.assertNotIn("hardlink_group_sha256", record)
        self.assertEqual(record["link_count"], 2)

    def test_relative_paths_are_canonical_bounded_and_partitioned(self) -> None:
        bad_inputs = (
            "input",
            "elsewhere/file",
            "/input/file",
            "input/../escape",
            "input/./file",
            "input//file",
            "input/file/",
            "input/line\nbreak",
            "input/.cbds-stage-forbidden",
            "input/" + "x" * (MAX_PATH_COMPONENT_UTF8_BYTES + 1),
        )
        for value in bad_inputs:
            with self.subTest(value=value), self.assertRaises(
                WorkspaceDefinitionError
            ):
                InputFile(value, b"")

        for value in ("input/result", "/result", "a/../result", "a//result"):
            with self.subTest(output=value), self.assertRaises(
                WorkspaceDefinitionError
            ):
                ExpectedFile(value)
            with self.subTest(output_symlink=value), self.assertRaises(
                WorkspaceDefinitionError
            ):
                ExpectedSymlink(value)

        for target in ("", "/outside", "../outside", "dir/../outside", "a//b"):
            with self.subTest(target=target), self.assertRaises(
                WorkspaceDefinitionError
            ):
                InputSymlink("input/link", target)
        for maximum in (0, -1, True, MAX_PATH_UTF8_BYTES + 1):
            with self.subTest(maximum=maximum), self.assertRaises(
                WorkspaceDefinitionError
            ):
                ExpectedSymlink(  # type: ignore[arg-type]
                    "mirror/link",
                    maximum,
                )

    def test_file_modes_sizes_and_container_shapes_are_bounded(self) -> None:
        for mode in (-1, 0o1000, True):
            with self.subTest(mode=mode), self.assertRaises(
                WorkspaceDefinitionError
            ):
                InputFile("input/a", b"", mode)  # type: ignore[arg-type]
        with self.assertRaises(WorkspaceDefinitionError):
            InputFile("input/a", bytearray(b"not immutable"))  # type: ignore[arg-type]
        with self.assertRaises(WorkspaceDefinitionError):
            InputFile("input/a", b"x" * (MAX_FILE_BYTES + 1))
        for mtime_seconds in (
            -1,
            True,
            MAX_INPUT_MTIME_SECONDS + 1,
        ):
            with self.subTest(
                mtime_seconds=mtime_seconds
            ), self.assertRaises(WorkspaceDefinitionError):
                InputFile(  # type: ignore[arg-type]
                    "input/a",
                    b"",
                    mtime_seconds=mtime_seconds,
                )

        for size in (-1, MAX_FILE_BYTES + 1, True):
            with self.subTest(size=size), self.assertRaises(
                WorkspaceDefinitionError
            ):
                ExpectedFile("answer", size)  # type: ignore[arg-type]
        with self.assertRaises(WorkspaceDefinitionError):
            ExpectedFile("answer", 1, 0o1000)
        with self.assertRaises(WorkspaceDefinitionError):
            FixtureDefinition("fixture.lists", [], ())  # type: ignore[arg-type]
        with self.assertRaises(WorkspaceDefinitionError):
            FixtureDefinition("fixture.lists", (), [])  # type: ignore[arg-type]
        with self.assertRaises(WorkspaceDefinitionError):
            FixtureDefinition(
                "fixture.symlink-lists",
                (),
                (),
                expected_symlinks=[],  # type: ignore[arg-type]
            )

    def test_materialization_revalidates_low_level_mutated_definitions(self) -> None:
        definition = sample_definition()
        object.__setattr__(definition, "inputs", list(definition.inputs))
        with tempfile.TemporaryDirectory() as temporary, self.assertRaises(
            WorkspaceDefinitionError
        ):
            materialize_fixture(definition, Path(temporary) / "workspace")

    def test_duplicates_leaf_ancestors_counts_and_total_bytes_fail_closed(self) -> None:
        with self.assertRaisesRegex(WorkspaceDefinitionError, "duplicate"):
            FixtureDefinition(
                "fixture.duplicate",
                (InputFile("input/a", b"a"), InputSymlink("input/a", "b")),
                (),
            )
        with self.assertRaisesRegex(WorkspaceDefinitionError, "ancestor"):
            FixtureDefinition(
                "fixture.input-ancestor",
                (InputFile("input/a", b"a"), InputFile("input/a/b", b"b")),
                (),
            )
        with self.assertRaisesRegex(WorkspaceDefinitionError, "ancestor"):
            FixtureDefinition(
                "fixture.output-ancestor",
                (),
                (ExpectedFile("out"), ExpectedFile("out/nested")),
            )
        with self.assertRaisesRegex(WorkspaceDefinitionError, "duplicate"):
            FixtureDefinition(
                "fixture.cross-kind-output-duplicate",
                (),
                (ExpectedFile("out"),),
                expected_symlinks=(ExpectedSymlink("out"),),
            )

        too_many = tuple(ExpectedFile(f"out-{index:04d}", 0) for index in range(MAX_ENTRIES))
        with self.assertRaisesRegex(WorkspaceDefinitionError, "entry limit"):
            FixtureDefinition("fixture.too-many", (), too_many)

        full_inputs = tuple(
            InputFile(f"input/chunk-{index:02d}", b"x" * MAX_FILE_BYTES)
            for index in range(MAX_TOTAL_BYTES // MAX_FILE_BYTES)
        )
        with self.assertRaisesRegex(WorkspaceDefinitionError, "byte limit"):
            FixtureDefinition(
                "fixture.too-large",
                full_inputs,
                (ExpectedFile("one-more", 1),),
            )


class MaterializationAndScanTests(unittest.TestCase):
    @unittest.skipUnless(
        Path("/proc/self/fd").is_dir(),
        "descriptor leak assertion requires procfs",
    )
    def test_hardlink_parent_open_failure_closes_the_first_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "workspace"
            (root / "input/source").mkdir(parents=True)
            (root / "input/destination").mkdir()
            (root / "input/source/file").write_bytes(b"payload")
            root_descriptor = os.open(
                root,
                os.O_RDONLY | os.O_DIRECTORY,
            )
            real_open = static_slice._open_relative_directory
            call_count = 0

            def fail_second_parent(
                descriptor: int,
                path: PurePosixPath,
            ) -> int:
                nonlocal call_count
                call_count += 1
                if call_count == 2:
                    raise OSError("injected destination-parent failure")
                return real_open(descriptor, path)

            try:
                before = len(os.listdir("/proc/self/fd"))
                with mock.patch.object(
                    static_slice,
                    "_open_relative_directory",
                    side_effect=fail_second_parent,
                ), self.assertRaises(OSError):
                    workspace_module._create_input_hardlink(
                        root_descriptor,
                        PurePosixPath("input/source/file"),
                        PurePosixPath("input/destination/alias"),
                    )
                after = len(os.listdir("/proc/self/fd"))
                self.assertEqual(after, before)
            finally:
                os.close(root_descriptor)

    @unittest.skipUnless(
        Path("/proc/self/fd").is_dir(),
        "descriptor leak assertion requires procfs",
    )
    def test_alias_descriptor_setup_failure_closes_the_duplicate(self) -> None:
        definition = FixtureDefinition(
            "fixture.alias-descriptor-failure",
            (
                InputFile("input/0-source", b"payload", 0o000),
                InputHardlink("input/alias", "input/0-source"),
            ),
            (),
        )
        with tempfile.TemporaryDirectory() as temporary:
            before = len(os.listdir("/proc/self/fd"))
            with mock.patch.object(
                workspace_module.os,
                "set_inheritable",
                side_effect=OSError("injected inheritable failure"),
            ), self.assertRaises(WorkspaceMaterializationError):
                materialize_fixture(
                    definition,
                    Path(temporary) / "workspace",
                )
            after = len(os.listdir("/proc/self/fd"))
            self.assertEqual(after, before)

    def test_materializes_exact_projection_and_binds_repeatable_scans(self) -> None:
        definition = sample_definition()
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            with materialize_fixture(definition, workspace) as handle:
                self.assertEqual(handle.workspace, workspace)
                self.assertFalse(handle.closed)
                self.assertEqual(handle.baseline.fixture_sha256, definition.fixture_sha256)
                self.assertEqual(
                    handle.baseline.to_record()["initial_output_policy"],
                    INITIAL_OUTPUT_POLICY,
                )
                self.assertEqual(handle.expected_files, definition.expected_files)
                self.assertEqual(
                    handle.expected_symlinks,
                    definition.expected_symlinks,
                )
                self.assertIsInstance(handle.baseline, WorkspaceBaseline)

                readable = workspace / "input" / "readable.txt"
                locked = workspace / "input" / "nested" / "locked.bin"
                link = workspace / "input" / "nested" / "link.txt"
                self.assertEqual(readable.read_bytes(), b"alpha\n")
                self.assertEqual(stat.S_IMODE(readable.stat().st_mode), 0o640)
                self.assertEqual(stat.S_IMODE(locked.lstat().st_mode), 0o000)
                self.assertTrue(link.is_symlink())
                self.assertEqual(os.readlink(link), "locked.bin")
                self.assertFalse((workspace / "reports").exists())
                self.assertFalse((workspace / "output.txt").exists())

                first_inputs = handle.scan_inputs()
                second_inputs = handle.scan_inputs()
                outputs = handle.scan_outputs()
                self.assertEqual(first_inputs, second_inputs)
                self.assertEqual(
                    first_inputs.entries, handle.baseline.input_entries
                )
                self.assertEqual(
                    first_inputs.tree_sha256, handle.baseline.input_tree_sha256
                )
                self.assertEqual(
                    outputs.entries, handle.baseline.output_scaffold_entries
                )
                self.assertEqual(outputs.entries, ())
                self.assertEqual(
                    outputs.tree_sha256,
                    handle.baseline.output_scaffold_sha256,
                )
                self.assertEqual(
                    outputs.baseline_sha256, handle.baseline.baseline_sha256
                )
                json.dumps(handle.baseline.to_record(), allow_nan=False)
                json.dumps(outputs.to_record(), allow_nan=False)
            self.assertTrue(handle.closed)
            with self.assertRaises(WorkspaceClosedError):
                handle.scan_inputs()
            handle.close()

    @unittest.skipIf(
        os.geteuid() == 0,
        "root can pathname-read every regular file regardless of read bits",
    )
    def test_owner_same_group_and_other_read_bits_use_pinned_descriptors(
        self,
    ) -> None:
        payloads = {
            "input/owner-other.bin": b"owner class denies mode 0004\x00\xff",
            "input/owner-group.bin": b"owner class denies mode 0040\n",
        }
        modes = {
            "input/owner-other.bin": 0o004,
            "input/owner-group.bin": 0o040,
        }
        definition = FixtureDefinition(
            "fixture.owner-class-readability",
            tuple(
                InputFile(path, payloads[path], modes[path])
                for path in payloads
            ),
            (),
        )

        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            with materialize_fixture(definition, workspace) as handle:
                pinned = {
                    item.path: item for item in handle._pinned_regulars
                }
                self.assertEqual(set(pinned), set(payloads))
                original_descriptors = {
                    path: item.descriptor for path, item in pinned.items()
                }

                baseline = by_path(handle.baseline.input_entries)
                first = by_path(handle.scan_inputs().entries)
                second = by_path(handle.scan_inputs().entries)
                for path, payload in payloads.items():
                    with self.subTest(path=path):
                        named = workspace / path
                        metadata = named.stat(follow_symlinks=False)
                        self.assertEqual(metadata.st_uid, os.geteuid())
                        self.assertEqual(stat.S_IMODE(metadata.st_mode), modes[path])
                        self.assertFalse(
                            static_slice._regular_is_effectively_readable(metadata)
                        )
                        with self.assertRaises(PermissionError):
                            named.read_bytes()
                        self.assertEqual(
                            os.pread(
                                pinned[path].descriptor,
                                len(payload),
                                0,
                            ),
                            payload,
                        )
                        expected_digest = sha256(payload).hexdigest()
                        self.assertEqual(
                            baseline[path].content_sha256,
                            expected_digest,
                        )
                        self.assertEqual(first[path], baseline[path])
                        self.assertEqual(second[path], baseline[path])
                        self.assertEqual(first[path].mode, modes[path])

            self.assertTrue(handle.closed)
            for path, item in pinned.items():
                with self.subTest(closed_path=path):
                    self.assertEqual(item.descriptor, -1)
                    with self.assertRaises(OSError):
                        os.fstat(original_descriptors[path])
                    self.assertEqual(
                        stat.S_IMODE((workspace / path).stat().st_mode),
                        modes[path],
                    )
            handle.close()

    def test_expected_output_ancestors_are_initially_absent_candidate_state(self) -> None:
        definition = FixtureDefinition(
            "fixture.no-output-scaffold",
            (),
            (ExpectedFile("deep/candidate/created.txt", maximum_bytes=16),),
        )
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            with materialize_fixture(definition, workspace) as handle:
                self.assertEqual(
                    sorted(path.name for path in workspace.iterdir()), [INPUT_ROOT]
                )
                self.assertFalse((workspace / "deep").exists())
                self.assertEqual(handle.scan_outputs().entries, ())
                self.assertEqual(handle.baseline.output_scaffold_entries, ())

    def test_requires_an_empty_real_no_follow_workspace(self) -> None:
        definition = sample_definition()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            occupied = root / "occupied"
            occupied.mkdir()
            sentinel = occupied / "keep"
            sentinel.write_text("preserve", encoding="utf-8")
            with self.assertRaisesRegex(
                WorkspaceMaterializationError, "must be empty"
            ):
                materialize_fixture(definition, occupied)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve")

            victim = root / "victim"
            victim.mkdir()
            alias = root / "alias"
            alias.symlink_to(victim, target_is_directory=True)
            with self.assertRaises(WorkspaceMaterializationError):
                materialize_fixture(definition, alias)
            self.assertEqual(list(victim.iterdir()), [])

            real_parent = root / "real-parent"
            real_parent.mkdir()
            parent_alias = root / "parent-alias"
            parent_alias.symlink_to(real_parent, target_is_directory=True)
            with self.assertRaises(WorkspaceMaterializationError):
                materialize_fixture(definition, parent_alias / "child")
            self.assertEqual(list(real_parent.iterdir()), [])

    def test_materialization_workspace_swap_cannot_retarget_writes(self) -> None:
        definition = sample_definition()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            parked = root / "parked"
            victim = root / "victim"
            victim.mkdir()
            original_write = os.write
            swapped = False

            def racing_write(descriptor: int, payload: bytes) -> int:
                nonlocal swapped
                if not swapped:
                    swapped = True
                    workspace.rename(parked)
                    workspace.symlink_to(victim, target_is_directory=True)
                return original_write(descriptor, payload)

            with mock.patch.object(
                static_slice.os, "write", side_effect=racing_write
            ):
                with self.assertRaises(WorkspaceMaterializationError):
                    materialize_fixture(definition, workspace)
            self.assertTrue(swapped)
            self.assertEqual(list(victim.iterdir()), [])
            self.assertFalse((victim / INPUT_ROOT).exists())

    def test_final_named_boundary_rejects_mutation_after_baseline_creation(self) -> None:
        definition = sample_definition()
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            original = workspace_module._make_baseline
            mutated = False

            def racing_baseline(*args: object, **kwargs: object) -> WorkspaceBaseline:
                nonlocal mutated
                baseline = original(*args, **kwargs)
                if not mutated:
                    mutated = True
                    (workspace / "input" / "readable.txt").write_bytes(b"raced\n")
                return baseline

            with mock.patch.object(
                workspace_module, "_make_baseline", side_effect=racing_baseline
            ):
                with self.assertRaisesRegex(
                    WorkspaceMaterializationError, "final named boundary"
                ):
                    materialize_fixture(definition, workspace)
            self.assertTrue(mutated)

    def test_final_materialization_double_scan_rejects_between_scan_change(self) -> None:
        definition = sample_definition()
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            original = workspace_module._scan_materialized_projection_once
            calls = 0

            def changing_scan(*args: object, **kwargs: object) -> object:
                nonlocal calls
                result = original(*args, **kwargs)
                calls += 1
                # Call one is the baseline scan; call two is the first half of
                # the final boundary scan.
                if calls == 2:
                    (workspace / "raced-output").write_bytes(b"changed")
                return result

            with mock.patch.object(
                workspace_module,
                "_scan_materialized_projection_once",
                side_effect=changing_scan,
            ):
                with self.assertRaisesRegex(
                    WorkspaceMaterializationError, "final materialization double scan"
                ):
                    materialize_fixture(definition, workspace)
            self.assertEqual(calls, 3)

    def test_named_workspace_replacement_is_rejected_without_visiting_victim(self) -> None:
        definition = sample_definition()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            parked = root / "parked"
            victim = root / "victim"
            victim.mkdir()
            secret = victim / "secret"
            secret.write_bytes(b"outside-secret")
            with materialize_fixture(definition, workspace) as handle:
                workspace.rename(parked)
                workspace.symlink_to(victim, target_is_directory=True)
                with self.assertRaises(WorkspaceScanError):
                    handle.scan_outputs()
            self.assertEqual(secret.read_bytes(), b"outside-secret")

    def test_output_symlink_is_observed_but_never_followed(self) -> None:
        definition = sample_definition()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            victim = root / "outside-secret"
            victim.write_bytes(b"must-not-be-read")
            with materialize_fixture(definition, root / "workspace") as handle:
                output = handle.workspace / "output.txt"
                output.symlink_to(victim)
                with mock.patch.object(
                    static_slice.os,
                    "read",
                    side_effect=AssertionError("regular payload was read"),
                ):
                    scan = handle.scan_outputs()
                entry = by_path(scan.entries)["output.txt"]
                self.assertEqual(entry.kind, "symlink")
                self.assertEqual(entry.symlink_target, str(victim))
                self.assertIsNone(entry.content_sha256)

    def test_hardlink_is_visible_in_both_input_and_output_scans(self) -> None:
        definition = sample_definition()
        with tempfile.TemporaryDirectory() as temporary:
            with materialize_fixture(definition, Path(temporary) / "workspace") as handle:
                source = handle.workspace / "input" / "readable.txt"
                output = handle.workspace / "output.txt"
                os.link(source, output)
                inputs = by_path(handle.scan_inputs().entries)
                outputs = by_path(handle.scan_outputs().entries)
                baseline = by_path(handle.baseline.input_entries)
                self.assertEqual(inputs["input/readable.txt"].link_count, 2)
                self.assertEqual(outputs["output.txt"].link_count, 2)
                self.assertEqual(
                    inputs["input/readable.txt"].content_sha256,
                    outputs["output.txt"].content_sha256,
                )
                self.assertEqual(baseline["input/readable.txt"].link_count, 1)
                self.assertNotEqual(
                    inputs["input/readable.txt"], baseline["input/readable.txt"]
                )

    def test_materialized_input_hardlinks_bind_topology_and_unreadable_bytes(
        self,
    ) -> None:
        payload = b"\x00shared\xff\n"
        definition = FixtureDefinition(
            "fixture.bound-input-hardlinks",
            (
                InputHardlink(
                    "input/z-last/alias.bin",
                    "input/0-source.bin",
                ),
                InputFile(
                    "input/0-source.bin",
                    payload,
                    0o000,
                    mtime_seconds=123_456_789,
                ),
                InputHardlink(
                    "input/a-first/alias.bin",
                    "input/0-source.bin",
                ),
            ),
            (),
        )
        with tempfile.TemporaryDirectory() as temporary:
            with materialize_fixture(
                definition, Path(temporary) / "workspace"
            ) as handle:
                baseline = by_path(handle.baseline.input_entries)
                scanned = by_path(handle.scan_inputs().entries)
                paths = (
                    "input/a-first/alias.bin",
                    "input/0-source.bin",
                    "input/z-last/alias.bin",
                )
                groups = {
                    scanned[path].hardlink_group_sha256 for path in paths
                }
                self.assertEqual(len(groups), 1)
                self.assertNotIn(None, groups)
                for path in paths:
                    self.assertEqual(scanned[path], baseline[path])
                    self.assertEqual(scanned[path].kind, "file")
                    self.assertEqual(scanned[path].mode, 0o000)
                    self.assertEqual(scanned[path].size, len(payload))
                    self.assertEqual(scanned[path].link_count, 3)
                    self.assertEqual(
                        scanned[path].mtime_ns,
                        123_456_789_000_000_000,
                    )
                    self.assertEqual(
                        scanned[path].content_sha256,
                        sha256(payload).hexdigest(),
                    )
                    self.assertEqual(
                        (
                            handle.workspace / path
                        ).lstat().st_ino,
                        (
                            handle.workspace / "input/0-source.bin"
                        ).lstat().st_ino,
                    )

                outside_name = handle.workspace / "outside-hardlink"
                os.link(
                    handle.workspace / "input/0-source.bin",
                    outside_name,
                )
                changed = by_path(handle.scan_inputs().entries)
                self.assertEqual(changed["input/0-source.bin"].link_count, 4)
                self.assertNotEqual(
                    changed["input/0-source.bin"].hardlink_group_sha256,
                    baseline["input/0-source.bin"].hardlink_group_sha256,
                )

    def test_process_local_identity_check_rejects_identical_inode_replacement(
        self,
    ) -> None:
        definition = FixtureDefinition(
            "fixture.input-object-identity",
            (
                InputFile(
                    "input/group/a.bin",
                    b"same-bytes\n",
                    0o640,
                    mtime_seconds=12_345,
                ),
                InputHardlink(
                    "input/group/b.bin",
                    "input/group/a.bin",
                ),
            ),
            (),
        )
        with tempfile.TemporaryDirectory() as temporary:
            with materialize_fixture(
                definition, Path(temporary) / "workspace"
            ) as handle:
                original_scan = handle.scan_inputs()
                handle.validate_input_object_identities(original_scan)
                original_inode = (
                    handle.workspace / "input/group/a.bin"
                ).lstat().st_ino
                parent = handle.workspace / "input/group"
                parent_metadata = parent.stat()

                first = parent / "a.bin"
                second = parent / "b.bin"
                first.unlink()
                second.unlink()
                replacement = handle.workspace / "replacement.bin"
                replacement.write_bytes(b"same-bytes\n")
                replacement.chmod(0o640)
                os.utime(
                    replacement,
                    ns=(
                        12_345_000_000_000,
                        12_345_000_000_000,
                    ),
                )
                os.link(replacement, first)
                os.link(replacement, second)
                replacement.unlink()
                os.utime(
                    parent,
                    ns=(
                        parent_metadata.st_atime_ns,
                        parent_metadata.st_mtime_ns,
                    ),
                )

                replacement_scan = handle.scan_inputs()
                self.assertEqual(replacement_scan, original_scan)
                self.assertNotEqual(first.lstat().st_ino, original_inode)
                with self.assertRaises(WorkspaceScanError):
                    handle.validate_input_object_identities(
                        replacement_scan
                    )

    def test_unreadable_input_is_hashed_without_chmod_and_mutation_is_visible(self) -> None:
        definition = sample_definition()
        with tempfile.TemporaryDirectory() as temporary:
            with materialize_fixture(definition, Path(temporary) / "workspace") as handle:
                path = handle.workspace / "input" / "nested" / "locked.bin"
                baseline = by_path(handle.baseline.input_entries)[
                    "input/nested/locked.bin"
                ]
                first = by_path(handle.scan_inputs().entries)[
                    "input/nested/locked.bin"
                ]
                self.assertEqual(first.content_sha256, sha256(b"sealed-input").hexdigest())
                self.assertEqual(first, baseline)
                self.assertEqual(stat.S_IMODE(path.lstat().st_mode), 0o000)

                metadata = path.lstat()
                path.chmod(0o600)
                path.write_bytes(b"Sealed-input")
                path.chmod(0o000)
                os.utime(
                    path,
                    ns=(metadata.st_atime_ns, metadata.st_mtime_ns),
                    follow_symlinks=False,
                )
                changed = by_path(handle.scan_inputs().entries)[
                    "input/nested/locked.bin"
                ]
                self.assertEqual(stat.S_IMODE(path.lstat().st_mode), 0o000)
                self.assertEqual(changed.size, baseline.size)
                self.assertNotEqual(changed.content_sha256, baseline.content_sha256)

    def test_input_replacement_race_fails_without_following_outside_symlink(self) -> None:
        definition = sample_definition()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            victim = root / "outside.txt"
            victim.write_bytes(b"OUTSIDE_SECRET_MUST_NOT_BE_READ")
            with materialize_fixture(definition, root / "workspace") as handle:
                source = handle.workspace / "input" / "readable.txt"
                original_read = os.read
                swapped = False

                def racing_read(descriptor: int, size: int) -> bytes:
                    nonlocal swapped
                    if not swapped:
                        try:
                            opened = Path(f"/proc/self/fd/{descriptor}").resolve(
                                strict=True
                            )
                        except OSError:
                            opened = None
                        if opened == source:
                            swapped = True
                            source.unlink()
                            source.symlink_to(victim)
                    return original_read(descriptor, size)

                with mock.patch.object(
                    static_slice.os, "read", side_effect=racing_read
                ):
                    with self.assertRaises(WorkspaceScanError):
                        handle.scan_inputs()
                self.assertTrue(swapped)
                self.assertEqual(victim.read_bytes(), b"OUTSIDE_SECRET_MUST_NOT_BE_READ")

    def test_tree_change_between_double_scans_fails_closed(self) -> None:
        definition = sample_definition()
        with tempfile.TemporaryDirectory() as temporary:
            with materialize_fixture(definition, Path(temporary) / "workspace") as handle:
                original = static_slice._scan_tree_descriptor
                calls = 0

                def changing_scan(*args: object, **kwargs: object) -> object:
                    nonlocal calls
                    result = original(*args, **kwargs)
                    calls += 1
                    if calls == 1:
                        (handle.workspace / "raced-output").write_bytes(b"changed")
                    return result

                with mock.patch.object(
                    static_slice,
                    "_scan_tree_descriptor",
                    side_effect=changing_scan,
                ):
                    with self.assertRaises(WorkspaceScanError):
                        handle.scan_outputs()

    def test_oversized_output_is_reported_without_reading_payload(self) -> None:
        definition = sample_definition()
        with tempfile.TemporaryDirectory() as temporary:
            with materialize_fixture(definition, Path(temporary) / "workspace") as handle:
                output = handle.workspace / "output.txt"
                with output.open("wb") as stream:
                    stream.truncate(MAX_FILE_BYTES + 1)
                with mock.patch.object(
                    static_slice.os,
                    "read",
                    side_effect=AssertionError("oversized payload was read"),
                ):
                    scan = handle.scan_outputs()
                entry = by_path(scan.entries)["output.txt"]
                self.assertEqual(entry.size, MAX_FILE_BYTES + 1)
                self.assertIsNone(entry.content_sha256)

    def test_layer_never_invokes_a_subprocess_or_shell(self) -> None:
        definition = sample_definition()
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            subprocess, "run", side_effect=AssertionError("subprocess executed")
        ), mock.patch.object(
            subprocess, "Popen", side_effect=AssertionError("subprocess executed")
        ), mock.patch.object(
            os, "system", side_effect=AssertionError("shell executed")
        ):
            with materialize_fixture(definition, Path(temporary) / "workspace") as handle:
                handle.scan_inputs()
                handle.scan_outputs()


class ExpectedOutputPolicyTests(unittest.TestCase):
    @staticmethod
    def create_valid_outputs(workspace: Path) -> None:
        (workspace / "reports").mkdir(mode=0o755)
        output = workspace / "output.txt"
        output.write_bytes(b"candidate output\n")
        output.chmod(0o644)
        result = workspace / "reports" / "result.json"
        result.write_bytes(b'{"candidate":true}\n')
        result.chmod(0o600)

    def test_exact_regular_outputs_and_required_directories_validate(self) -> None:
        definition = sample_definition()
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            with materialize_fixture(definition, workspace) as handle:
                self.assertEqual(handle.scan_outputs().entries, ())
                self.create_valid_outputs(workspace)
                scan = handle.scan_outputs()
                validated = validate_expected_output_policy(definition, scan)

                self.assertEqual(
                    [entry.path for entry in validated],
                    ["output.txt", "reports/result.json"],
                )
                self.assertTrue(all(entry.kind == "file" for entry in validated))
                self.assertTrue(all(entry.link_count == 1 for entry in validated))
                self.assertTrue(
                    all(entry.content_sha256 is not None for entry in validated)
                )

    def test_topology_opt_in_accepts_and_reads_bound_hardlinked_outputs(
        self,
    ) -> None:
        definition = FixtureDefinition(
            "fixture.hardlinked-outputs",
            (),
            (
                ExpectedFile(
                    "mirror/a.bin",
                    maximum_bytes=32,
                    mode=0o640,
                    required_link_count=None,
                ),
                ExpectedFile(
                    "mirror/b.bin",
                    maximum_bytes=32,
                    mode=0o640,
                    required_link_count=None,
                ),
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            with materialize_fixture(definition, workspace) as handle:
                (workspace / "mirror").mkdir(mode=0o755)
                first = workspace / "mirror/a.bin"
                first.write_bytes(b"shared output\x00\n")
                first.chmod(0o640)
                os.link(first, workspace / "mirror/b.bin")
                scan = handle.scan_outputs()
                validated = validate_expected_output_policy(definition, scan)
                by_name = by_path(validated)
                self.assertEqual(by_name["mirror/a.bin"].link_count, 2)
                self.assertEqual(by_name["mirror/b.bin"].link_count, 2)
                self.assertEqual(
                    by_name["mirror/a.bin"].hardlink_group_sha256,
                    by_name["mirror/b.bin"].hardlink_group_sha256,
                )
                self.assertIsNotNone(
                    by_name["mirror/a.bin"].hardlink_group_sha256
                )
                self.assertEqual(
                    handle.read_output_bytes(scan, "mirror/a.bin"),
                    b"shared output\x00\n",
                )
                self.assertEqual(
                    handle.read_output_bytes(scan, "mirror/b.bin"),
                    b"shared output\x00\n",
                )

    def test_exact_live_and_dangling_output_symlinks_validate_without_egress(
        self,
    ) -> None:
        definition = FixtureDefinition(
            "fixture.exact-output-symlinks",
            (),
            (ExpectedFile("mirror/target.bin", maximum_bytes=16),),
            expected_symlinks=(
                ExpectedSymlink("mirror/live"),
                ExpectedSymlink("mirror/dangling"),
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            with materialize_fixture(definition, workspace) as handle:
                (workspace / "mirror").mkdir(mode=0o755)
                (workspace / "mirror/target.bin").write_bytes(b"target")
                (workspace / "mirror/live").symlink_to("target.bin")
                (workspace / "mirror/dangling").symlink_to("missing.bin")
                scan = handle.scan_outputs()
                validated = validate_expected_output_policy(definition, scan)
                by_name = by_path(validated)
                self.assertEqual(
                    tuple(by_name),
                    (
                        "mirror/dangling",
                        "mirror/live",
                        "mirror/target.bin",
                    ),
                )
                self.assertEqual(
                    by_name["mirror/live"].symlink_target,
                    "target.bin",
                )
                self.assertEqual(
                    by_name["mirror/dangling"].symlink_target,
                    "missing.bin",
                )
                with self.assertRaisesRegex(
                    WorkspaceOutputReadError,
                    "not declared",
                ):
                    handle.read_output_bytes(scan, "mirror/live")
                self.assertEqual(
                    handle.read_output_symlink_target(scan, "mirror/live"),
                    "target.bin",
                )
                self.assertEqual(
                    handle.read_output_symlink_target(
                        scan,
                        "mirror/dangling",
                    ),
                    "missing.bin",
                )

    def test_expected_output_symlink_mutations_fail_closed(self) -> None:
        definition = FixtureDefinition(
            "fixture.output-symlink-mutations",
            (),
            (),
            expected_symlinks=(ExpectedSymlink("mirror/link"),),
        )
        for case in ("missing", "regular", "unsafe-target", "extra"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary) / "workspace"
                with materialize_fixture(definition, workspace) as handle:
                    (workspace / "mirror").mkdir(mode=0o755)
                    if case == "regular":
                        (workspace / "mirror/link").write_bytes(b"target")
                    elif case == "unsafe-target":
                        (workspace / "mirror/link").symlink_to("../outside")
                    elif case == "extra":
                        (workspace / "mirror/link").symlink_to("target")
                        (workspace / "extra").symlink_to("target")
                    with self.assertRaises(WorkspaceOutputPolicyError):
                        validate_expected_output_policy(
                            definition,
                            handle.scan_outputs(),
                        )

    def test_symlink_target_egress_rejects_stale_cross_workspace_and_races(
        self,
    ) -> None:
        definition = FixtureDefinition(
            "fixture.symlink-egress-races",
            (),
            (),
            expected_symlinks=(ExpectedSymlink("mirror/link", 32),),
        )
        with tempfile.TemporaryDirectory() as temporary:
            first_root = Path(temporary) / "first"
            second_root = Path(temporary) / "second"
            with materialize_fixture(
                definition,
                first_root,
            ) as first, materialize_fixture(
                definition,
                second_root,
            ) as second:
                for root in (first_root, second_root):
                    (root / "mirror").mkdir(mode=0o755)
                    (root / "mirror/link").symlink_to("target")
                first_scan = first.scan_outputs()
                second_scan = second.scan_outputs()
                with self.assertRaisesRegex(
                    WorkspaceOutputReadError,
                    "not bound|stale",
                ):
                    second.read_output_symlink_target(
                        first_scan,
                        "mirror/link",
                    )

                (first_root / "mirror/link").unlink()
                (first_root / "mirror/link").symlink_to("changed")
                with self.assertRaisesRegex(
                    WorkspaceOutputReadError,
                    "stale",
                ):
                    first.read_output_symlink_target(
                        first_scan,
                        "mirror/link",
                    )

                real_readlink = workspace_module.os.readlink
                calls = 0

                def racing_readlink(
                    path: object,
                    *,
                    dir_fd: int | None = None,
                ) -> str:
                    nonlocal calls
                    result = real_readlink(path, dir_fd=dir_fd)
                    calls += 1
                    # Two calls establish current_before; mutate immediately
                    # after the descriptor-relative egress read.
                    if calls == 3:
                        assert dir_fd is not None
                        os.unlink(path, dir_fd=dir_fd)
                        os.symlink("raced", path, dir_fd=dir_fd)
                    return result

                with mock.patch.object(
                    workspace_module.os,
                    "readlink",
                    side_effect=racing_readlink,
                ), self.assertRaises(WorkspaceOutputReadError):
                    second.read_output_symlink_target(
                        second_scan,
                        "mirror/link",
                    )

    def test_unrepresentable_output_symlink_target_fails_as_scan_error(
        self,
    ) -> None:
        definition = FixtureDefinition(
            "fixture.invalid-utf8-symlink",
            (),
            (),
            expected_symlinks=(ExpectedSymlink("link"),),
        )
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            with materialize_fixture(definition, workspace) as handle:
                os.symlink(
                    b"\xff",
                    os.fsencode(workspace / "link"),
                )
                with self.assertRaisesRegex(
                    WorkspaceScanError,
                    "unrepresentable",
                ):
                    handle.scan_outputs()

    def test_empty_exact_policy_accepts_only_an_empty_output_scan(self) -> None:
        definition = FixtureDefinition("fixture.empty-outputs", (), ())
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            with materialize_fixture(definition, workspace) as handle:
                self.assertEqual(
                    validate_expected_output_policy(
                        definition, handle.scan_outputs()
                    ),
                    (),
                )
                (workspace / "unexpected").write_bytes(b"x")
                with self.assertRaisesRegex(
                    WorkspaceOutputPolicyError, "extra=unexpected"
                ):
                    validate_expected_output_policy(
                        definition, handle.scan_outputs()
                    )

    def test_missing_and_extra_output_paths_fail_closed(self) -> None:
        definition = sample_definition()
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            with materialize_fixture(definition, workspace) as handle:
                output = workspace / "output.txt"
                output.write_bytes(b"only one")
                output.chmod(0o644)
                with self.assertRaisesRegex(
                    WorkspaceOutputPolicyError, "missing="
                ):
                    validate_expected_output_policy(
                        definition, handle.scan_outputs()
                    )

                (workspace / "reports").mkdir()
                (workspace / "reports" / "result.json").write_bytes(b"{}\n")
                (workspace / "unexpected.txt").write_bytes(b"extra")
                with self.assertRaisesRegex(
                    WorkspaceOutputPolicyError, "extra=unexpected.txt"
                ):
                    validate_expected_output_policy(
                        definition, handle.scan_outputs()
                    )

    def test_symlink_mode_hardlink_and_per_file_limit_are_rejected(self) -> None:
        definition = sample_definition()
        cases = ("symlink", "mode", "directory-mode", "hardlink", "oversized")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary) / "workspace"
                with materialize_fixture(definition, workspace) as handle:
                    self.create_valid_outputs(workspace)
                    output = workspace / "output.txt"
                    result = workspace / "reports" / "result.json"
                    if case == "symlink":
                        output.unlink()
                        output.symlink_to(result)
                        message = "not a no-follow regular file"
                    elif case == "mode":
                        output.chmod(0o600)
                        message = "mode differs"
                    elif case == "directory-mode":
                        (workspace / "reports").chmod(0o700)
                        message = "mode-0755 directory"
                    elif case == "hardlink":
                        result.unlink()
                        os.link(output, result)
                        message = "link count one"
                    else:
                        output.write_bytes(b"x" * 129)
                        message = "per-file byte limit"
                    with self.assertRaisesRegex(
                        WorkspaceOutputPolicyError, message
                    ):
                        validate_expected_output_policy(
                            definition, handle.scan_outputs()
                        )

    def test_policy_rejects_input_scans_and_wrong_definition_types(self) -> None:
        definition = sample_definition()
        with tempfile.TemporaryDirectory() as temporary:
            with materialize_fixture(
                definition, Path(temporary) / "workspace"
            ) as handle:
                with self.assertRaises(WorkspaceOutputPolicyError):
                    validate_expected_output_policy(
                        definition, handle.scan_inputs()
                    )
                with self.assertRaises(WorkspaceOutputPolicyError):
                    validate_expected_output_policy(  # type: ignore[arg-type]
                        object(), handle.scan_outputs()
                    )

    def test_policy_revalidates_scan_content_address_after_low_level_mutation(self) -> None:
        definition = FixtureDefinition("fixture.empty-policy-forgery", (), ())
        with tempfile.TemporaryDirectory() as temporary:
            with materialize_fixture(
                definition, Path(temporary) / "workspace"
            ) as handle:
                scan = handle.scan_outputs()
                object.__setattr__(scan, "tree_sha256", "0" * 64)
                with self.assertRaisesRegex(
                    WorkspaceOutputPolicyError, "closed-contract revalidation"
                ):
                    validate_expected_output_policy(definition, scan)


class OutputEgressTests(unittest.TestCase):
    @staticmethod
    def create_valid_outputs(workspace: Path) -> None:
        ExpectedOutputPolicyTests.create_valid_outputs(workspace)

    def test_reads_only_declared_bytes_from_a_current_bound_output_scan(self) -> None:
        definition = sample_definition()
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            with materialize_fixture(definition, workspace) as handle:
                self.create_valid_outputs(workspace)
                scan = handle.scan_outputs()
                with mock.patch.object(
                    subprocess, "run", side_effect=AssertionError("subprocess executed")
                ), mock.patch.object(
                    subprocess,
                    "Popen",
                    side_effect=AssertionError("subprocess executed"),
                ), mock.patch.object(
                    os, "system", side_effect=AssertionError("shell executed")
                ):
                    self.assertEqual(
                        handle.read_output_bytes(scan, "output.txt"),
                        b"candidate output\n",
                    )
                    self.assertEqual(
                        handle.read_output_bytes(scan, "reports/result.json"),
                        b'{"candidate":true}\n',
                    )
                self.assertEqual(handle.scan_outputs(), scan)

    def test_rejects_stale_cross_workspace_and_resigned_tampered_scans(self) -> None:
        definition = sample_definition()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with materialize_fixture(definition, root / "first") as first, materialize_fixture(
                definition, root / "second"
            ) as second:
                self.create_valid_outputs(first.workspace)
                self.create_valid_outputs(second.workspace)
                first_scan = first.scan_outputs()
                second_scan = second.scan_outputs()
                self.assertNotEqual(
                    first.baseline.baseline_sha256,
                    second.baseline.baseline_sha256,
                )
                with self.assertRaisesRegex(
                    WorkspaceOutputReadError, "not bound"
                ):
                    first.read_output_bytes(second_scan, "output.txt")

                tampered_entries = tuple(
                    replace(entry, content_sha256="0" * 64)
                    if entry.path == "output.txt"
                    else entry
                    for entry in first_scan.entries
                )
                tampered_scan = replace(
                    first_scan,
                    entries=tampered_entries,
                    tree_sha256=workspace_module._entries_digest(
                        "outputs", tampered_entries
                    ),
                )
                with self.assertRaisesRegex(
                    WorkspaceOutputReadError, "stale or does not match"
                ):
                    first.read_output_bytes(tampered_scan, "output.txt")

                output = first.workspace / "output.txt"
                output.write_bytes(b"changed output\n")
                output.chmod(0o644)
                with self.assertRaisesRegex(
                    WorkspaceOutputReadError, "stale or does not match"
                ):
                    first.read_output_bytes(first_scan, "output.txt")

    def test_rejects_input_scans_unsafe_undeclared_and_missing_paths(self) -> None:
        definition = sample_definition()
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            with materialize_fixture(definition, workspace) as handle:
                empty_scan = handle.scan_outputs()
                with self.assertRaisesRegex(
                    WorkspaceOutputReadError, "absent or duplicated"
                ):
                    handle.read_output_bytes(empty_scan, "output.txt")
                with self.assertRaisesRegex(
                    WorkspaceOutputReadError, "outputs WorkspaceScan"
                ):
                    handle.read_output_bytes(handle.scan_inputs(), "output.txt")
                for path in ("../escape", "/absolute", "input/readable.txt"):
                    with self.subTest(path=path), self.assertRaisesRegex(
                        WorkspaceOutputReadError, "canonical safe output path"
                    ):
                        handle.read_output_bytes(empty_scan, path)

                (workspace / "undeclared.txt").write_bytes(b"not declared")
                current = handle.scan_outputs()
                with self.assertRaisesRegex(
                    WorkspaceOutputReadError, "not declared"
                ):
                    handle.read_output_bytes(current, "undeclared.txt")

    def test_rejects_symlink_mode_hardlink_and_oversized_declared_outputs(self) -> None:
        definition = sample_definition()
        cases = ("symlink", "mode", "hardlink", "oversized")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary) / "workspace"
                with materialize_fixture(definition, workspace) as handle:
                    self.create_valid_outputs(workspace)
                    output = workspace / "output.txt"
                    result = workspace / "reports" / "result.json"
                    if case == "symlink":
                        output.unlink()
                        output.symlink_to(result)
                        message = "no-follow regular file"
                    elif case == "mode":
                        output.chmod(0o600)
                        message = "mode differs"
                    elif case == "hardlink":
                        result.unlink()
                        os.link(output, result)
                        message = "link count one"
                    else:
                        output.write_bytes(b"x" * 129)
                        message = "per-file byte limit"
                    scan = handle.scan_outputs()
                    with self.assertRaisesRegex(WorkspaceOutputReadError, message):
                        handle.read_output_bytes(scan, "output.txt")

    def test_post_read_whole_tree_change_is_rejected_before_bytes_escape(self) -> None:
        definition = sample_definition()
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            with materialize_fixture(definition, workspace) as handle:
                self.create_valid_outputs(workspace)
                scan = handle.scan_outputs()
                original = workspace_module._read_output_descriptor
                mutated = False

                def racing_read(*args: object, **kwargs: object) -> bytes:
                    nonlocal mutated
                    payload = original(*args, **kwargs)
                    if not mutated:
                        mutated = True
                        (workspace / "late-extra").write_bytes(b"raced")
                    return payload

                with mock.patch.object(
                    workspace_module,
                    "_read_output_descriptor",
                    side_effect=racing_read,
                ):
                    with self.assertRaisesRegex(
                        WorkspaceOutputReadError, "output tree changed"
                    ):
                        handle.read_output_bytes(scan, "output.txt")
                self.assertTrue(mutated)

    def test_path_replacement_during_read_is_rejected_without_reading_target(self) -> None:
        definition = sample_definition()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            victim = root / "outside-secret"
            victim.write_bytes(b"OUTSIDE_MUST_NOT_BE_READ")
            with materialize_fixture(definition, workspace) as handle:
                self.create_valid_outputs(workspace)
                scan = handle.scan_outputs()
                output = workspace / "output.txt"
                original = workspace_module._read_output_descriptor
                replaced = False

                def replacing_read(*args: object, **kwargs: object) -> bytes:
                    nonlocal replaced
                    payload = original(*args, **kwargs)
                    if not replaced:
                        replaced = True
                        output.unlink()
                        output.symlink_to(victim)
                    return payload

                with mock.patch.object(
                    workspace_module,
                    "_read_output_descriptor",
                    side_effect=replacing_read,
                ):
                    with self.assertRaisesRegex(
                        WorkspaceOutputReadError, "changed while"
                    ):
                        handle.read_output_bytes(scan, "output.txt")
                self.assertTrue(replaced)
                self.assertEqual(victim.read_bytes(), b"OUTSIDE_MUST_NOT_BE_READ")

    def test_closed_handle_rejects_output_egress(self) -> None:
        definition = sample_definition()
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            handle = materialize_fixture(definition, workspace)
            self.create_valid_outputs(workspace)
            scan = handle.scan_outputs()
            handle.close()
            with self.assertRaises(WorkspaceClosedError):
                handle.read_output_bytes(scan, "output.txt")


class LaunchDescriptorTests(unittest.TestCase):
    def test_launch_duplicate_is_same_directory_close_on_exec_and_caller_owned(self) -> None:
        definition = sample_definition()
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            handle = materialize_fixture(definition, workspace)
            descriptor = handle.duplicate_launch_directory()
            try:
                self.assertFalse(os.get_inheritable(descriptor))
                self.assertTrue(stat.S_ISDIR(os.fstat(descriptor).st_mode))
                self.assertEqual(
                    (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino),
                    (workspace.stat().st_dev, workspace.stat().st_ino),
                )
                handle.close()
                self.assertTrue(stat.S_ISDIR(os.fstat(descriptor).st_mode))
            finally:
                os.close(descriptor)

    def test_closed_or_replaced_named_workspace_cannot_mint_launch_descriptor(self) -> None:
        definition = sample_definition()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            handle = materialize_fixture(definition, workspace)
            handle.close()
            with self.assertRaises(WorkspaceClosedError):
                handle.duplicate_launch_directory()

            handle = materialize_fixture(definition, root / "replacement-case")
            workspace = handle.workspace
            moved = root / "moved"
            workspace.rename(moved)
            workspace.mkdir(mode=0o700)
            try:
                with self.assertRaisesRegex(WorkspaceScanError, "no longer names"):
                    handle.duplicate_launch_directory()
            finally:
                handle.close()


class BaselineIntegrityTests(unittest.TestCase):
    def test_baseline_content_address_cannot_be_resigned_locally(self) -> None:
        definition = sample_definition()
        with tempfile.TemporaryDirectory() as temporary:
            with materialize_fixture(definition, Path(temporary) / "workspace") as handle:
                baseline = handle.baseline
                with self.assertRaisesRegex(
                    WorkspaceDefinitionError, "content address"
                ):
                    replace(baseline, baseline_sha256="0" * 64)
                with self.assertRaisesRegex(WorkspaceDefinitionError, "input hash"):
                    replace(baseline, input_tree_sha256="0" * 64)
                with self.assertRaisesRegex(
                    WorkspaceDefinitionError, "initial output path"
                ):
                    replace(
                        baseline,
                        output_scaffold_entries=(baseline.input_entries[0],),
                    )

    def test_no_authorization_or_expected_answer_fields_exist(self) -> None:
        definition = sample_definition()
        definition_fields = set(definition.__dataclass_fields__)
        expected_fields = set(ExpectedFile.__dataclass_fields__)
        baseline_fields = set(WorkspaceBaseline.__dataclass_fields__)
        forbidden = {
            "expected_answer",
            "expected_content",
            "execution_authorized",
            "claim_authorized",
            "training_eligible",
        }
        self.assertFalse(forbidden & definition_fields)
        self.assertFalse(forbidden & expected_fields)
        self.assertFalse(forbidden & baseline_fields)


if __name__ == "__main__":
    unittest.main()
