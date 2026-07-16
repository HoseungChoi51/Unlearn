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

from cbds.executable_bounded_retry_state_machine import (  # noqa: E402
    BOUNDED_RETRY_STATE_MACHINE_FAMILY_ID,
    BoundedRetryStateMachineFixtureBundle,
    BoundedRetryStateMachineTask,
    materialize_bounded_retry_state_machine_fixture,
    verify_bounded_retry_state_machine_workspace,
)
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from cbds.executable_fixture_sixth_catalog import (  # noqa: E402
    SIXTH_TRANCHE_ADDED_FIXTURE_COUNT,
    build_sixth_tranche_fixture_catalog,
    validate_sixth_tranche_fixture_catalog,
)


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
    bundle: BoundedRetryStateMachineFixtureBundle,
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


class SixthTrancheFullCatalogMaterializationTests(unittest.TestCase):
    def test_all_100_bundles_accept_exact_final_state_and_reject_mutants(self) -> None:
        family_passes: dict[str, int] = {}
        profile_passes: dict[str, int] = {}
        missing_rejections = 0
        exact_acceptances = 0
        corrupted_rejections = 0
        absent_output_acceptances = 0
        unexpected_path_rejections = 0

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
            catalog = build_sixth_tranche_fixture_catalog()
            validate_sixth_tranche_fixture_catalog(catalog)
            self.assertEqual(len(catalog.bundles), 100)
            self.assertEqual(SIXTH_TRANCHE_ADDED_FIXTURE_COUNT, 100)

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
                    self.assertIs(type(task), BoundedRetryStateMachineTask)
                    self.assertIs(
                        type(bundle), BoundedRetryStateMachineFixtureBundle
                    )
                    with materialize_bounded_retry_state_machine_fixture(
                        task, profile, bundle, workspace
                    ) as handle:
                        self.assertEqual(handle.scan_outputs().entries, ())
                        if not bundle.oracle.outputs:
                            self.assertTrue(
                                verify_bounded_retry_state_machine_workspace(
                                    task, profile, bundle, handle
                                )
                            )
                            exact_acceptances += 1
                            absent_output_acceptances += 1
                            root_descriptor = os.open(
                                workspace, _DIRECTORY_OPEN_FLAGS
                            )
                            try:
                                os.mkdir(
                                    "output", 0o755, dir_fd=root_descriptor
                                )
                            finally:
                                os.close(root_descriptor)
                            self.assertFalse(
                                verify_bounded_retry_state_machine_workspace(
                                    task, profile, bundle, handle
                                )
                            )
                            unexpected_path_rejections += 1
                        else:
                            self.assertFalse(
                                verify_bounded_retry_state_machine_workspace(
                                    task, profile, bundle, handle
                                )
                            )
                            missing_rejections += 1
                            _write_trusted_oracle_descriptor_relative(
                                workspace, bundle
                            )
                            self.assertTrue(
                                verify_bounded_retry_state_machine_workspace(
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
                                verify_bounded_retry_state_machine_workspace(
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

        self.assertEqual(
            family_passes,
            {BOUNDED_RETRY_STATE_MACHINE_FAMILY_ID: 100},
        )
        self.assertEqual(
            profile_passes,
            {
                profile.profile_id: 20
                for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
            },
        )
        self.assertEqual(exact_acceptances, 100)
        self.assertEqual(
            absent_output_acceptances + missing_rejections,
            100,
        )
        self.assertEqual(
            unexpected_path_rejections, absent_output_acceptances
        )
        self.assertEqual(corrupted_rejections, missing_rejections)


if __name__ == "__main__":
    unittest.main()
