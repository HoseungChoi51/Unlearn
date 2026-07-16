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

from cbds.executable_compound_path_query import (  # noqa: E402
    CompoundPathQueryFixtureBundle,
    CompoundPathQueryTask,
    materialize_compound_path_query_fixture,
    verify_compound_path_query_workspace,
)
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from cbds.executable_fixture_third_catalog import (  # noqa: E402
    THIRD_TRANCHE_ADDED_FIXTURE_COUNT,
    build_third_tranche_fixture_catalog,
    validate_third_tranche_fixture_catalog,
)
from cbds.executable_log_aggregation_pipeline import (  # noqa: E402
    LogAggregationFixtureBundle,
    LogAggregationTask,
    materialize_log_aggregation_fixture,
    verify_log_aggregation_workspace,
)


FAMILY_ORDER = (
    "compound-path-query",
    "regex-log-group-aggregation",
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


def _replace_output_descriptor_relative(
    workspace: Path,
    path_text: str,
    content: bytes,
    mode: int,
) -> None:
    """Replace one already-created output through pinned directory handles."""

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
        return b"\x00"
    mutant = bytearray(content)
    mutant[len(mutant) // 2] ^= 1
    return bytes(mutant)


class ThirdTrancheFullCatalogMaterializationTests(unittest.TestCase):
    def test_all_200_bundles_use_local_execution_free_verifiers(self) -> None:
        family_passes: dict[str, int] = {}
        profile_passes: dict[str, int] = {}
        missing_rejections = 0
        corrupted_rejections = 0

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
            catalog = build_third_tranche_fixture_catalog()
            validate_third_tranche_fixture_catalog(catalog)
            self.assertEqual(len(catalog.bundles), 200)
            self.assertEqual(THIRD_TRANCHE_ADDED_FIXTURE_COUNT, 200)

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
                    if type(task) is CompoundPathQueryTask:
                        self.assertIs(type(bundle), CompoundPathQueryFixtureBundle)
                        materialize = materialize_compound_path_query_fixture
                        verify = verify_compound_path_query_workspace
                    elif type(task) is LogAggregationTask:
                        self.assertIs(type(bundle), LogAggregationFixtureBundle)
                        materialize = materialize_log_aggregation_fixture
                        verify = verify_log_aggregation_workspace
                    else:  # pragma: no cover - fail-closed type guard
                        self.fail("third catalog exposed an unknown task type")

                    with materialize(task, profile, bundle, workspace) as handle:
                        self.assertEqual(handle.scan_outputs().entries, ())
                        self.assertFalse(verify(task, profile, bundle, handle))
                        missing_rejections += 1

                        _write_trusted_oracle_descriptor_relative(
                            workspace, bundle
                        )
                        self.assertTrue(verify(task, profile, bundle, handle))

                        first_output = bundle.oracle.outputs[0]
                        _replace_output_descriptor_relative(
                            workspace,
                            first_output.path,
                            _one_byte_mutant(first_output.content),
                            first_output.mode,
                        )
                        self.assertFalse(verify(task, profile, bundle, handle))
                        corrupted_rejections += 1

                    family_passes[task.family_id] = (
                        family_passes.get(task.family_id, 0) + 1
                    )
                    profile_passes[profile.profile_id] = (
                        profile_passes.get(profile.profile_id, 0) + 1
                    )

        self.assertEqual(
            family_passes, {family: 100 for family in FAMILY_ORDER}
        )
        self.assertEqual(
            profile_passes,
            {
                profile.profile_id: 40
                for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
            },
        )
        self.assertEqual(missing_rejections, 200)
        self.assertEqual(corrupted_rejections, 200)


if __name__ == "__main__":
    unittest.main()
