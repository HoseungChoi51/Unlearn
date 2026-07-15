from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from hashlib import sha256
import json
import os
from pathlib import Path
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
    MAX_PATH_COMPONENT_UTF8_BYTES,
    MAX_TOTAL_BYTES,
    ExpectedFile,
    FixtureDefinition,
    InputFile,
    InputSymlink,
    WorkspaceBaseline,
    WorkspaceClosedError,
    WorkspaceDefinitionError,
    WorkspaceMaterializationError,
    WorkspaceOutputPolicyError,
    WorkspaceOutputReadError,
    WorkspaceScanError,
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

        for target in ("", "/outside", "../outside", "dir/../outside", "a//b"):
            with self.subTest(target=target), self.assertRaises(
                WorkspaceDefinitionError
            ):
                InputSymlink("input/link", target)

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
