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

from cbds.executable_fixture_second_catalog import (  # noqa: E402
    SECOND_TRANCHE_FIXTURE_COUNT,
    build_second_tranche_fixture_catalog,
    validate_second_tranche_fixture_catalog,
)
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from cbds.executable_fixture_verifier import (  # noqa: E402
    verify_executable_fixture,
)
from cbds.executable_workspace import (  # noqa: E402
    InputFile,
    materialize_fixture,
)


FAMILY_ORDER = (
    "line-transform-mirror",
    "mode-normalized-mirror",
    "jsonl-keyed-inner-join",
    "ustar-safe-extract",
    "proc-snapshot-report",
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
    workspace: Path, bundle: object
) -> None:
    """Create every trusted output without following a workspace symlink."""

    root_descriptor = os.open(workspace, _DIRECTORY_OPEN_FLAGS)
    try:
        for output in bundle.oracle.outputs:  # type: ignore[attr-defined]
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


class SecondTrancheFullCatalogMaterializationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = build_second_tranche_fixture_catalog()

    def test_all_500_bundles_materialize_and_verify_without_execution(self) -> None:
        validate_second_tranche_fixture_catalog(self.catalog)
        self.assertEqual(len(self.catalog.bundles), 500)
        self.assertEqual(SECOND_TRANCHE_FIXTURE_COUNT, 500)
        family_passes: dict[str, int] = {}
        profile_passes: dict[str, int] = {}
        partial_family_passes: dict[str, int] = {}
        unreadable_input_bundles = 0
        readonly_output_bundles = 0

        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
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
        ):
            root = Path(temporary)
            for index, bundle in enumerate(self.catalog.bundles):
                task = self.catalog.registry.added_tasks[index // 5]
                profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[index % 5]
                workspace = root / f"fixture-{index:03d}"
                with self.subTest(
                    index=index,
                    family=task.family_id,
                    profile=profile.profile_id,
                ):
                    with materialize_fixture(
                        bundle.definition, workspace
                    ) as handle:
                        self.assertEqual(handle.scan_outputs().entries, ())
                        _write_trusted_oracle_descriptor_relative(
                            workspace, bundle
                        )
                        evidence = verify_executable_fixture(bundle, handle)
                        self.assertTrue(evidence.passed, evidence.failure_code)
                        self.assertIsNone(evidence.failure_code)
                        self.assertEqual(
                            len(evidence.outputs), len(bundle.oracle.outputs)
                        )

                    family_passes[task.family_id] = (
                        family_passes.get(task.family_id, 0) + 1
                    )
                    profile_passes[profile.profile_id] = (
                        profile_passes.get(profile.profile_id, 0) + 1
                    )
                    if profile.profile_id == "partial-permissions":
                        partial_family_passes[task.family_id] = (
                            partial_family_passes.get(task.family_id, 0) + 1
                        )
                    if any(
                        type(item) is InputFile and item.mode & 0o444 == 0
                        for item in bundle.definition.inputs
                    ):
                        unreadable_input_bundles += 1
                    if any(
                        output.mode & 0o222 == 0
                        for output in bundle.oracle.outputs
                    ):
                        readonly_output_bundles += 1

        self.assertEqual(
            family_passes, {family: 100 for family in FAMILY_ORDER}
        )
        self.assertEqual(
            profile_passes,
            {
                profile.profile_id: 100
                for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
            },
        )
        self.assertEqual(
            partial_family_passes, {family: 20 for family in FAMILY_ORDER}
        )
        self.assertGreater(unreadable_input_bundles, 0)
        self.assertGreater(readonly_output_bundles, 0)


if __name__ == "__main__":
    unittest.main()
