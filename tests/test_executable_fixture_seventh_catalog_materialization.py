from __future__ import annotations

import errno
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.executable_case_routed_batch_transform import (  # noqa: E402
    CASE_ROUTED_BATCH_TRANSFORM_FAMILY_ID,
    CaseRoutedBatchTransformFixtureBundle,
    CaseRoutedBatchTransformTask,
    materialize_case_routed_batch_transform_fixture,
    verify_case_routed_batch_transform_workspace,
)
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from cbds.executable_fixture_seventh_catalog import (  # noqa: E402
    SEVENTH_TRANCHE_ADDED_FIXTURE_COUNT,
    build_seventh_tranche_fixture_catalog,
    validate_seventh_tranche_fixture_catalog,
)
from cbds.executable_workspace import InputFile, InputSymlink  # noqa: E402


_DIRECTORY_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_FILE_CREATE_FLAGS = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_FILE_REPLACE_FLAGS = (
    os.O_WRONLY
    | os.O_TRUNC
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)


def _validated_output_parts(path_text: str) -> tuple[str, ...]:
    path = PurePosixPath(path_text)
    if (
        type(path_text) is not str
        or not path_text
        or path.is_absolute()
        or path.as_posix() != path_text
        or not path.parts
        or path.parts[0] == "input"
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise AssertionError("trusted oracle output path is not canonical and safe")
    path_text.encode("utf-8", errors="strict")
    return path.parts


def _write_all(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short descriptor-relative oracle write")
        view = view[written:]


def _open_or_create_directory(parent_descriptor: int, name: str) -> int:
    try:
        os.mkdir(name, 0o755, dir_fd=parent_descriptor)
    except OSError as exc:
        if exc.errno != errno.EEXIST:
            raise
    descriptor = os.open(name, _DIRECTORY_OPEN_FLAGS, dir_fd=parent_descriptor)
    os.fchmod(descriptor, 0o755)
    return descriptor


def _write_trusted_oracle_descriptor_relative(
    workspace: Path,
    bundle: CaseRoutedBatchTransformFixtureBundle,
) -> None:
    root_descriptor = os.open(workspace, _DIRECTORY_OPEN_FLAGS)
    try:
        for output in bundle.oracle.outputs:
            parts = _validated_output_parts(output.path)
            parent_descriptor = os.dup(root_descriptor)
            try:
                for component in parts[:-1]:
                    child_descriptor = _open_or_create_directory(
                        parent_descriptor, component
                    )
                    os.close(parent_descriptor)
                    parent_descriptor = child_descriptor
                file_descriptor = os.open(
                    parts[-1],
                    _FILE_CREATE_FLAGS,
                    output.mode,
                    dir_fd=parent_descriptor,
                )
                try:
                    _write_all(file_descriptor, output.content)
                    os.fchmod(file_descriptor, output.mode)
                finally:
                    os.close(file_descriptor)
            finally:
                os.close(parent_descriptor)
    finally:
        os.close(root_descriptor)


def _replace_output_descriptor_relative(
    workspace: Path,
    path_text: str,
    content: bytes,
    mode: int,
) -> None:
    parts = _validated_output_parts(path_text)
    descriptor = os.open(workspace, _DIRECTORY_OPEN_FLAGS)
    try:
        for component in parts[:-1]:
            child_descriptor = os.open(
                component, _DIRECTORY_OPEN_FLAGS, dir_fd=descriptor
            )
            os.close(descriptor)
            descriptor = child_descriptor
        file_descriptor = os.open(
            parts[-1], _FILE_REPLACE_FLAGS, dir_fd=descriptor
        )
        try:
            _write_all(file_descriptor, content)
            os.fchmod(file_descriptor, mode)
        finally:
            os.close(file_descriptor)
    finally:
        os.close(descriptor)


def _one_byte_mutant(content: bytes) -> bytes:
    if not content:
        return b"\x01"
    mutant = bytearray(content)
    mutant[len(mutant) // 2] ^= 1
    return bytes(mutant)


class SeventhTrancheFullCatalogMaterializationTests(unittest.TestCase):
    def test_all_100_bundles_accept_exact_final_state_and_reject_mutants(self) -> None:
        family_passes: dict[str, int] = {}
        profile_passes: dict[str, int] = {}
        missing_rejections = 0
        exact_acceptances = 0
        corrupted_rejections = 0
        filesystem_mutant_rejections = 0

        with mock.patch.object(
            subprocess,
            "run",
            side_effect=AssertionError("subprocess.run executed"),
        ), mock.patch.object(
            subprocess,
            "Popen",
            side_effect=AssertionError("subprocess.Popen executed"),
        ), mock.patch.object(
            os,
            "system",
            side_effect=AssertionError("os.system executed"),
        ), mock.patch.object(
            os,
            "popen",
            side_effect=AssertionError("os.popen executed"),
        ), tempfile.TemporaryDirectory() as temporary:
            catalog = build_seventh_tranche_fixture_catalog()
            validate_seventh_tranche_fixture_catalog(catalog)
            self.assertEqual(len(catalog.bundles), 100)
            self.assertEqual(SEVENTH_TRANCHE_ADDED_FIXTURE_COUNT, 100)

            root = Path(temporary)
            for index, bundle in enumerate(catalog.bundles):
                task = catalog.registry.added_tasks[index // 5]
                profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[index % 5]
                workspace = root / f"fixture-{index:03d}"
                with self.subTest(
                    index=index,
                    family=task.family_id,
                    profile=profile.profile_id,
                ):
                    self.assertIs(type(task), CaseRoutedBatchTransformTask)
                    self.assertIs(
                        type(bundle), CaseRoutedBatchTransformFixtureBundle
                    )
                    with materialize_case_routed_batch_transform_fixture(
                        task, profile, bundle, workspace
                    ) as handle:
                        self.assertEqual(handle.scan_outputs().entries, ())
                        self.assertFalse(
                            verify_case_routed_batch_transform_workspace(
                                task, profile, bundle, handle
                            )
                        )
                        missing_rejections += 1

                        _write_trusted_oracle_descriptor_relative(
                            workspace, bundle
                        )
                        self.assertTrue(
                            verify_case_routed_batch_transform_workspace(
                                task, profile, bundle, handle
                            )
                        )
                        exact_acceptances += 1

                        output = bundle.oracle.outputs[0]
                        _replace_output_descriptor_relative(
                            workspace,
                            output.path,
                            _one_byte_mutant(output.content),
                            output.mode,
                        )
                        self.assertFalse(
                            verify_case_routed_batch_transform_workspace(
                                task, profile, bundle, handle
                            )
                        )
                        corrupted_rejections += 1

                    family_passes[task.family_id] = (
                        family_passes.get(task.family_id, 0) + 1
                    )
                    profile_passes[profile.profile_id] = (
                        profile_passes.get(profile.profile_id, 0) + 1
                    )

            def reject_representative_mutant(
                name: str,
                bundle_index: int,
                mutate,
            ) -> None:
                nonlocal filesystem_mutant_rejections
                bundle = catalog.bundles[bundle_index]
                task = catalog.registry.added_tasks[bundle_index // 5]
                profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[bundle_index % 5]
                workspace = root / f"mutant-{name}"
                with self.subTest(mutant=name), (
                    materialize_case_routed_batch_transform_fixture(
                        task, profile, bundle, workspace
                    )
                ) as handle:
                    _write_trusted_oracle_descriptor_relative(workspace, bundle)
                    self.assertTrue(
                        verify_case_routed_batch_transform_workspace(
                            task, profile, bundle, handle
                        )
                    )
                    mutate(workspace, bundle)
                    self.assertFalse(
                        verify_case_routed_batch_transform_workspace(
                            task, profile, bundle, handle
                        )
                    )
                    filesystem_mutant_rejections += 1

            def remove_one_output(
                workspace: Path,
                bundle: CaseRoutedBatchTransformFixtureBundle,
            ) -> None:
                (workspace / bundle.oracle.outputs[-1].path).unlink()

            def change_output_mode(
                workspace: Path,
                bundle: CaseRoutedBatchTransformFixtureBundle,
            ) -> None:
                (workspace / bundle.oracle.outputs[0].path).chmod(0o600)

            def add_unexpected_output(
                workspace: Path,
                _bundle: CaseRoutedBatchTransformFixtureBundle,
            ) -> None:
                (workspace / "output/unexpected.bin").write_bytes(b"unexpected")

            def hardlink_output(
                workspace: Path,
                bundle: CaseRoutedBatchTransformFixtureBundle,
            ) -> None:
                os.link(
                    workspace / bundle.oracle.outputs[0].path,
                    workspace / "output/unexpected-hardlink.tsv",
                )

            def replace_output_with_symlink(
                workspace: Path,
                bundle: CaseRoutedBatchTransformFixtureBundle,
            ) -> None:
                target = workspace / bundle.oracle.outputs[0].path
                target.unlink()
                target.symlink_to("status.tsv")

            def mutate_input_file(
                workspace: Path,
                bundle: CaseRoutedBatchTransformFixtureBundle,
            ) -> None:
                selected = next(
                    item
                    for item in bundle.definition.inputs
                    if type(item) is InputFile and item.content
                )
                target = workspace / selected.path
                target.chmod(0o600)
                target.write_bytes(_one_byte_mutant(selected.content))
                target.chmod(selected.mode)

            def mutate_input_symlink(
                workspace: Path,
                bundle: CaseRoutedBatchTransformFixtureBundle,
            ) -> None:
                selected = next(
                    item
                    for item in bundle.definition.inputs
                    if type(item) is InputSymlink
                )
                target = workspace / selected.path
                target.unlink()
                target.symlink_to("different-target.bin")

            reject_representative_mutant("missing-one", 0, remove_one_output)
            reject_representative_mutant("wrong-mode", 0, change_output_mode)
            reject_representative_mutant("unexpected-output", 0, add_unexpected_output)
            reject_representative_mutant("hardlink-output", 0, hardlink_output)
            reject_representative_mutant(
                "symlink-output", 0, replace_output_with_symlink
            )
            reject_representative_mutant("input-file", 0, mutate_input_file)
            reject_representative_mutant("input-symlink", 3, mutate_input_symlink)

        self.assertEqual(
            family_passes,
            {CASE_ROUTED_BATCH_TRANSFORM_FAMILY_ID: 100},
        )
        self.assertEqual(
            profile_passes,
            {
                profile.profile_id: 20
                for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
            },
        )
        self.assertEqual(missing_rejections, 100)
        self.assertEqual(exact_acceptances, 100)
        self.assertEqual(corrupted_rejections, 100)
        self.assertEqual(filesystem_mutant_rejections, 7)


if __name__ == "__main__":
    unittest.main()
