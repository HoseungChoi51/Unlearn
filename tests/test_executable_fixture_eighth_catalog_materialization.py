from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.executable_collision_safe_batch_rename import (  # noqa: E402
    COLLISION_SAFE_BATCH_RENAME_FAMILY_ID,
    COLLISION_SAFE_BATCH_RENAME_LEDGER_OUTPUT,
    CollisionSafeBatchRenameFixtureBundle,
    CollisionSafeBatchRenameTask,
    materialize_collision_safe_batch_rename_fixture,
    verify_collision_safe_batch_rename_workspace,
)
from cbds.executable_fixture_eighth_catalog import (  # noqa: E402
    EIGHTH_TRANCHE_ADDED_FIXTURE_COUNT,
    build_eighth_tranche_fixture_catalog,
    validate_eighth_tranche_fixture_catalog,
)
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from cbds.executable_workspace import InputFile, InputSymlink  # noqa: E402


_REMOVED_OUTCOMES = frozenset({"moved", "coalesced"})


def _write_new_file(path: Path, content: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o755)
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        mode,
    )
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short trusted test write")
            view = view[written:]
        os.fchmod(descriptor, mode)
    finally:
        os.close(descriptor)


def _apply_trusted_oracle_state(
    workspace: Path,
    bundle: CollisionSafeBatchRenameFixtureBundle,
) -> None:
    """Realize the committed final state without executing candidate code."""

    winners = {
        action.output_path: action
        for action in bundle.oracle.actions
        if action.outcome == "moved"
    }
    for action in bundle.oracle.actions:
        if action.outcome == "coalesced":
            (workspace / action.source).unlink()
    for output_path, action in sorted(
        winners.items(), key=lambda item: item[0].encode("utf-8")
    ):
        destination = workspace / output_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.parent.chmod(0o755)
        os.rename(workspace / action.source, destination)

    ledger = next(
        output
        for output in bundle.oracle.outputs
        if output.path == COLLISION_SAFE_BATCH_RENAME_LEDGER_OUTPUT
    )
    _write_new_file(workspace / ledger.path, ledger.content, ledger.mode)

    expected_tree = {
        output.path: output
        for output in bundle.oracle.outputs
        if output.path != COLLISION_SAFE_BATCH_RENAME_LEDGER_OUTPUT
    }
    if set(expected_tree) != set(winners):
        raise AssertionError("oracle outputs and moved representatives differ")
    for path, expected in expected_tree.items():
        target = workspace / path
        if target.read_bytes() != expected.content:
            raise AssertionError("trusted state realization changed output bytes")
        if os.stat(target, follow_symlinks=False).st_mode & 0o777 != expected.mode:
            raise AssertionError("trusted state realization changed output mode")


def _one_byte_mutant(content: bytes) -> bytes:
    if not content:
        return b"\x01"
    value = bytearray(content)
    value[len(value) // 2] ^= 1
    return bytes(value)


class EighthTrancheFullCatalogMaterializationTests(unittest.TestCase):
    def test_all_100_mutating_bundles_accept_exact_state_and_reject_mutants(
        self,
    ) -> None:
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
            catalog = build_eighth_tranche_fixture_catalog()
            validate_eighth_tranche_fixture_catalog(catalog)
            self.assertEqual(len(catalog.bundles), 100)
            self.assertEqual(EIGHTH_TRANCHE_ADDED_FIXTURE_COUNT, 100)

            root = Path(temporary)
            for index, bundle in enumerate(catalog.bundles):
                task = catalog.registry.added_tasks[index // 5]
                profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[index % 5]
                workspace = root / f"fixture-{index:03d}"
                with self.subTest(
                    index=index,
                    rule=task.parameters.rename_rule,
                    policy=task.parameters.collision_policy,
                    profile=profile.profile_id,
                ):
                    self.assertIs(type(task), CollisionSafeBatchRenameTask)
                    self.assertIs(
                        type(bundle), CollisionSafeBatchRenameFixtureBundle
                    )
                    with materialize_collision_safe_batch_rename_fixture(
                        task, profile, bundle, workspace
                    ) as handle:
                        self.assertEqual(handle.scan_outputs().entries, ())
                        self.assertFalse(
                            verify_collision_safe_batch_rename_workspace(
                                task, profile, bundle, handle
                            )
                        )
                        missing_rejections += 1

                        _apply_trusted_oracle_state(workspace, bundle)
                        self.assertTrue(
                            verify_collision_safe_batch_rename_workspace(
                                task, profile, bundle, handle
                            )
                        )
                        exact_acceptances += 1

                        ledger = workspace / COLLISION_SAFE_BATCH_RENAME_LEDGER_OUTPUT
                        original_mode = ledger.stat().st_mode & 0o777
                        ledger.write_bytes(_one_byte_mutant(ledger.read_bytes()))
                        ledger.chmod(original_mode)
                        self.assertFalse(
                            verify_collision_safe_batch_rename_workspace(
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

            def find_bundle(predicate):
                for index, candidate in enumerate(catalog.bundles):
                    task = catalog.registry.added_tasks[index // 5]
                    profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[index % 5]
                    if predicate(task, profile, candidate):
                        return index, task, profile, candidate
                raise AssertionError("no bundle satisfies mutation precondition")

            def reject_mutant(name: str, selected, mutate) -> None:
                nonlocal filesystem_mutant_rejections
                index, task, profile, bundle = selected
                workspace = root / f"mutant-{name}-{index:03d}"
                with self.subTest(mutant=name), (
                    materialize_collision_safe_batch_rename_fixture(
                        task, profile, bundle, workspace
                    )
                ) as handle:
                    _apply_trusted_oracle_state(workspace, bundle)
                    self.assertTrue(
                        verify_collision_safe_batch_rename_workspace(
                            task, profile, bundle, handle
                        )
                    )
                    mutate(workspace, bundle)
                    self.assertFalse(
                        verify_collision_safe_batch_rename_workspace(
                            task, profile, bundle, handle
                        )
                    )
                    filesystem_mutant_rejections += 1

            any_bundle = (0, catalog.registry.added_tasks[0],
                          PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0],
                          catalog.bundles[0])
            with_tree = find_bundle(
                lambda _task, _profile, bundle: any(
                    output.path.startswith("output/tree/")
                    for output in bundle.oracle.outputs
                )
            )
            with_retained = find_bundle(
                lambda _task, _profile, bundle: any(
                    action.outcome not in _REMOVED_OUTCOMES
                    for action in bundle.oracle.actions
                )
            )
            with_removed = find_bundle(
                lambda _task, _profile, bundle: any(
                    action.outcome in _REMOVED_OUTCOMES
                    for action in bundle.oracle.actions
                )
            )
            with_symlink = find_bundle(
                lambda _task, _profile, bundle: any(
                    type(item) is InputSymlink
                    for item in bundle.definition.inputs
                )
            )

            reject_mutant(
                "missing-output",
                any_bundle,
                lambda workspace, _bundle: (
                    workspace / COLLISION_SAFE_BATCH_RENAME_LEDGER_OUTPUT
                ).unlink(),
            )
            reject_mutant(
                "wrong-output-mode",
                any_bundle,
                lambda workspace, _bundle: (
                    workspace / COLLISION_SAFE_BATCH_RENAME_LEDGER_OUTPUT
                ).chmod(0o600),
            )

            def add_unexpected(workspace: Path, _bundle) -> None:
                _write_new_file(
                    workspace / "output/unexpected.bin", b"unexpected", 0o644
                )

            reject_mutant("unexpected-output", any_bundle, add_unexpected)

            def hardlink_output(workspace: Path, bundle) -> None:
                target = workspace / bundle.oracle.outputs[0].path
                outside = workspace.parent / f"{workspace.name}-outside-hardlink"
                os.link(target, outside)

            reject_mutant("hardlink-output", any_bundle, hardlink_output)

            def symlink_output(workspace: Path, _bundle) -> None:
                ledger = workspace / COLLISION_SAFE_BATCH_RENAME_LEDGER_OUTPUT
                ledger.unlink()
                ledger.symlink_to("missing-ledger")

            reject_mutant("symlink-output", any_bundle, symlink_output)

            def change_output_mtime(workspace: Path, bundle) -> None:
                output = next(
                    item
                    for item in bundle.oracle.outputs
                    if item.path.startswith("output/tree/")
                )
                target = workspace / output.path
                metadata = target.stat()
                os.utime(
                    target,
                    ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1),
                )

            reject_mutant("output-mtime", with_tree, change_output_mtime)

            def change_output_bytes(workspace: Path, bundle) -> None:
                output = next(
                    item
                    for item in bundle.oracle.outputs
                    if item.path.startswith("output/tree/")
                )
                target = workspace / output.path
                metadata = target.stat()
                target.chmod(0o600)
                target.write_bytes(_one_byte_mutant(output.content))
                target.chmod(output.mode)
                os.utime(
                    target,
                    ns=(metadata.st_atime_ns, metadata.st_mtime_ns),
                )

            reject_mutant("output-bytes", with_tree, change_output_bytes)

            def change_tree_output_mode(workspace: Path, bundle) -> None:
                output = next(
                    item
                    for item in bundle.oracle.outputs
                    if item.path.startswith("output/tree/")
                )
                replacement = 0o600 if output.mode != 0o600 else 0o400
                (workspace / output.path).chmod(replacement)

            reject_mutant("tree-output-mode", with_tree, change_tree_output_mode)

            def mutate_retained(workspace: Path, bundle) -> None:
                retained = next(
                    action
                    for action in bundle.oracle.actions
                    if action.outcome not in _REMOVED_OUTCOMES
                )
                source = next(
                    item
                    for item in bundle.definition.inputs
                    if type(item) is InputFile and item.path == retained.source
                )
                target = workspace / retained.source
                target.chmod(0o600)
                target.write_bytes(_one_byte_mutant(source.content))
                target.chmod(source.mode)

            reject_mutant("retained-input", with_retained, mutate_retained)

            def recreate_removed(workspace: Path, bundle) -> None:
                removed = next(
                    action
                    for action in bundle.oracle.actions
                    if action.outcome in _REMOVED_OUTCOMES
                )
                source = next(
                    item
                    for item in bundle.definition.inputs
                    if type(item) is InputFile and item.path == removed.source
                )
                _write_new_file(workspace / source.path, source.content, source.mode)

            reject_mutant("recreated-removed-source", with_removed, recreate_removed)

            def remove_retained(workspace: Path, bundle) -> None:
                retained = next(
                    action
                    for action in bundle.oracle.actions
                    if action.outcome not in _REMOVED_OUTCOMES
                )
                (workspace / retained.source).unlink()

            reject_mutant("removed-retained-source", with_retained, remove_retained)

            def mutate_input_symlink(workspace: Path, bundle) -> None:
                selected = next(
                    item
                    for item in bundle.definition.inputs
                    if type(item) is InputSymlink
                )
                target = workspace / selected.path
                target.unlink()
                target.symlink_to("different-target.bin")

            reject_mutant("input-symlink", with_symlink, mutate_input_symlink)

            def mutate_input_directory(workspace: Path, _bundle) -> None:
                (workspace / "input/rename/candidates").chmod(0o700)

            reject_mutant("input-directory-mode", any_bundle, mutate_input_directory)

        self.assertEqual(
            family_passes,
            {COLLISION_SAFE_BATCH_RENAME_FAMILY_ID: 100},
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
        self.assertEqual(filesystem_mutant_rejections, 13)


if __name__ == "__main__":
    unittest.main()
