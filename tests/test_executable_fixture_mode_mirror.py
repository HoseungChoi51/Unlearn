from __future__ import annotations

from dataclasses import fields
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.executable_fixture_bundle import (  # noqa: E402
    ExecutableFixtureBundleError,
    validate_executable_fixture_bundle,
)
from cbds.executable_fixture_mode_mirror import (  # noqa: E402
    ExecutableFixtureModeMirrorError,
    build_mode_normalized_mirror_fixture_bundle,
)
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
    ExecutableFixtureProfile,
)
from cbds.executable_fixture_verifier import (  # noqa: E402
    verify_executable_fixture,
)
from cbds.executable_static_second_registry import (  # noqa: E402
    build_mode_normalized_mirror_tasks,
)
from cbds.executable_static_types import (  # noqa: E402
    ExecutableStaticTask,
    ModeNormalizedMirrorParameters,
)
from cbds.executable_workspace import (  # noqa: E402
    InputFile,
    InputSymlink,
    materialize_fixture,
)


SELECTORS = (
    "all-readable",
    "txt-suffix",
    "any-executable",
    "owner-writable",
)
NORMALIZATIONS = (
    "fixed-0644",
    "fixed-0600",
    "fixed-0444",
    "preserve-exec",
    "fold-class-bits-to-owner",
)


def profile_by_id(profile_id: str) -> ExecutableFixtureProfile:
    matches = tuple(
        profile
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        if profile.profile_id == profile_id
    )
    if len(matches) != 1:
        raise AssertionError(f"expected one fixture profile for {profile_id!r}")
    return matches[0]


def task_by_parameters(
    tasks: tuple[ExecutableStaticTask, ...],
    *,
    selector: str,
    normalization: str,
) -> ExecutableStaticTask:
    matches = tuple(
        task
        for task in tasks
        if task.parameters.selector == selector
        and task.parameters.normalization == normalization
    )
    if len(matches) != 1:
        raise AssertionError(
            "expected one mode-mirror task for "
            f"{selector=!r}, {normalization=!r}"
        )
    return matches[0]


def independent_selected(item: InputFile, selector: str) -> bool:
    if item.mode & 0o444 == 0:
        return False
    if selector == "all-readable":
        return True
    if selector == "txt-suffix":
        return PurePosixPath(item.path).name.endswith(".txt")
    if selector == "any-executable":
        return item.mode & 0o111 != 0
    if selector == "owner-writable":
        return item.mode & 0o200 != 0
    raise AssertionError(f"unknown selector in independent oracle: {selector!r}")


def independent_mode(source_mode: int, normalization: str) -> int:
    if normalization == "fixed-0644":
        return 0o644
    if normalization == "fixed-0600":
        return 0o600
    if normalization == "fixed-0444":
        return 0o444
    if normalization == "preserve-exec":
        return 0o755 if source_mode & 0o111 else 0o644
    if normalization == "fold-class-bits-to-owner":
        collapsed = (
            (source_mode >> 6) | (source_mode >> 3) | source_mode
        ) & 0o7
        return collapsed << 6
    raise AssertionError(
        f"unknown normalization in independent oracle: {normalization!r}"
    )


def independently_derive_outputs(
    task: ExecutableStaticTask, bundle: object
) -> tuple[tuple[str, bytes, int], ...]:
    selected: list[tuple[str, bytes, int]] = []
    for item in bundle.definition.inputs:
        if type(item) is not InputFile:
            continue
        source = PurePosixPath(item.path)
        if source.parts[:2] != ("input", "assets"):
            continue
        if not independent_selected(item, task.parameters.selector):
            continue
        relative = PurePosixPath(*source.parts[2:])
        selected.append(
            (
                (PurePosixPath("output/mirror") / relative).as_posix(),
                item.content,
                independent_mode(item.mode, task.parameters.normalization),
            )
        )
    return tuple(sorted(selected, key=lambda item: item[0].encode("utf-8")))


def exact_clone(instance: object):
    clone = object.__new__(type(instance))
    for field in fields(instance):
        object.__setattr__(clone, field.name, getattr(instance, field.name))
    return clone


def write_trusted_oracle(workspace: Path, bundle: object) -> None:
    for output in bundle.oracle.outputs:
        target = workspace / output.path
        target.parent.mkdir(parents=True, exist_ok=True)
        relative_parent = target.parent.relative_to(workspace)
        current = workspace
        for component in relative_parent.parts:
            current /= component
            current.chmod(0o755)
        target.write_bytes(output.content)
        target.chmod(output.mode)


class ModeNormalizedMirrorFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tasks = build_mode_normalized_mirror_tasks()

    def test_all_20_by_5_bundles_are_exact_deterministic_and_nonexecuting(
        self,
    ) -> None:
        self.assertEqual(len(self.tasks), 20)
        self.assertEqual(
            {
                (task.parameters.selector, task.parameters.normalization)
                for task in self.tasks
            },
            {
                (selector, normalization)
                for selector in SELECTORS
                for normalization in NORMALIZATIONS
            },
        )
        descriptors = []
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
        ):
            for task in self.tasks:
                for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                    with self.subTest(
                        selector=task.parameters.selector,
                        normalization=task.parameters.normalization,
                        profile=profile.profile_id,
                    ):
                        first = build_mode_normalized_mirror_fixture_bundle(
                            task, profile
                        )
                        second = build_mode_normalized_mirror_fixture_bundle(
                            task, profile
                        )
                        self.assertEqual(first, second)
                        validate_executable_fixture_bundle(first)
                        self.assertEqual(
                            first.task_contract_sha256,
                            task.task_contract_sha256,
                        )
                        self.assertEqual(first.profile_sha256, profile.profile_sha256)
                        self.assertEqual(
                            first.oracle.semantic_verifier_identity,
                            "verify-mode-normalized-mirror-v1",
                        )
                        independently_derived = independently_derive_outputs(
                            task, first
                        )
                        observed = tuple(
                            (output.path, output.content, output.mode)
                            for output in first.oracle.outputs
                        )
                        self.assertEqual(observed, independently_derived)
                        self.assertGreater(len(observed), 0)
                        self.assertEqual(
                            tuple(
                                (
                                    policy.path,
                                    policy.maximum_bytes,
                                    policy.mode,
                                )
                                for policy in first.definition.expected_files
                            ),
                            tuple(
                                (path, len(content), mode)
                                for path, content, mode in observed
                            ),
                        )
                        self.assertIs(first.candidate_execution_authorized, False)
                        self.assertIs(first.model_selection_eligible, False)
                        self.assertIs(first.claim_authorized, False)
                        descriptors.append(first.descriptor)

        self.assertEqual(len(descriptors), 100)
        self.assertEqual(len({item.fixture_id for item in descriptors}), 100)
        self.assertEqual(len({item.fixture_sha256 for item in descriptors}), 100)

    def test_profiles_cover_paths_bytes_symlinks_ordering_and_permission_axes(
        self,
    ) -> None:
        task = task_by_parameters(
            self.tasks,
            selector="all-readable",
            normalization="preserve-exec",
        )

        spaces = build_mode_normalized_mirror_fixture_bundle(
            task, profile_by_id("spaces-unicode")
        )
        space_outputs = independently_derive_outputs(task, spaces)
        self.assertTrue(any(" " in path for path, _bytes, _mode in space_outputs))
        self.assertTrue(
            any(
                any(ord(character) > 127 for character in path)
                for path, _bytes, _mode in space_outputs
            )
        )
        self.assertTrue(
            any(
                _raises_unicode_decode(content)
                for _path, content, _mode in space_outputs
            )
        )

        leading = build_mode_normalized_mirror_fixture_bundle(
            task, profile_by_id("leading-dashes-globs")
        )
        leading_paths = [
            path
            for path, _bytes, _mode in independently_derive_outputs(task, leading)
        ]
        self.assertTrue(any("/-" in path for path in leading_paths))
        self.assertTrue(
            any(any(marker in path for marker in "*?[") for path in leading_paths)
        )

        duplicates = build_mode_normalized_mirror_fixture_bundle(
            task, profile_by_id("empty-duplicates")
        )
        duplicate_bytes = [
            content
            for _path, content, _mode in independently_derive_outputs(
                task, duplicates
            )
        ]
        self.assertIn(b"", duplicate_bytes)
        self.assertLess(len(set(duplicate_bytes)), len(duplicate_bytes))

        symlinks = build_mode_normalized_mirror_fixture_bundle(
            task, profile_by_id("symlinks-ordering")
        )
        input_paths = [item.path for item in symlinks.definition.inputs]
        self.assertNotEqual(input_paths, sorted(input_paths, key=str.encode))
        self.assertTrue(
            any(type(item) is InputSymlink for item in symlinks.definition.inputs)
        )
        output_paths = {
            path
            for path, _bytes, _mode in independently_derive_outputs(task, symlinks)
        }
        for item in symlinks.definition.inputs:
            if type(item) is InputSymlink:
                source = PurePosixPath(item.path)
                mirrored = (
                    PurePosixPath("output/mirror")
                    / PurePosixPath(*source.parts[2:])
                ).as_posix()
                self.assertNotIn(mirrored, output_paths)

        partial = build_mode_normalized_mirror_fixture_bundle(
            task, profile_by_id("partial-permissions")
        )
        assets = [
            item
            for item in partial.definition.inputs
            if type(item) is InputFile
            and PurePosixPath(item.path).parts[:2] == ("input", "assets")
        ]
        modes = {item.mode for item in assets}
        self.assertTrue(
            {0o000, 0o400, 0o405, 0o440, 0o450, 0o604}.issubset(modes)
        )
        selected_sources = {
            item.path
            for item in assets
            if item.mode & 0o444
        }
        observed_sources = {
            "input/assets/" + str(PurePosixPath(path).relative_to("output/mirror"))
            for path, _bytes, _mode in independently_derive_outputs(task, partial)
        }
        self.assertEqual(observed_sources, selected_sources)
        self.assertTrue(any(item.mode & 0o100 for item in _all_readable_assets()))
        self.assertTrue(any(item.mode & 0o010 for item in _all_readable_assets()))
        self.assertTrue(any(item.mode & 0o001 for item in _all_readable_assets()))

    def test_selector_and_normalization_rules_are_independently_exercised(
        self,
    ) -> None:
        profile = profile_by_id("spaces-unicode")
        selected_paths: dict[str, set[str]] = {}
        for selector in SELECTORS:
            task = task_by_parameters(
                self.tasks,
                selector=selector,
                normalization="fixed-0644",
            )
            bundle = build_mode_normalized_mirror_fixture_bundle(task, profile)
            expected = independently_derive_outputs(task, bundle)
            observed = tuple(
                (output.path, output.content, output.mode)
                for output in bundle.oracle.outputs
            )
            self.assertEqual(observed, expected)
            selected_paths[selector] = {path for path, _content, _mode in expected}
        self.assertEqual(len(selected_paths["all-readable"]), 3)
        self.assertEqual(len(selected_paths["txt-suffix"]), 1)
        self.assertEqual(len(selected_paths["any-executable"]), 1)
        self.assertEqual(len(selected_paths["owner-writable"]), 2)
        self.assertEqual(len({frozenset(paths) for paths in selected_paths.values()}), 4)

        modes_by_normalization: dict[str, tuple[int, ...]] = {}
        for normalization in NORMALIZATIONS:
            task = task_by_parameters(
                self.tasks,
                selector="all-readable",
                normalization=normalization,
            )
            bundle = build_mode_normalized_mirror_fixture_bundle(task, profile)
            expected = independently_derive_outputs(task, bundle)
            observed = tuple(
                (output.path, output.content, output.mode)
                for output in bundle.oracle.outputs
            )
            self.assertEqual(observed, expected)
            modes_by_normalization[normalization] = tuple(
                mode for _path, _content, mode in observed
            )
        self.assertEqual(set(modes_by_normalization["fixed-0644"]), {0o644})
        self.assertEqual(set(modes_by_normalization["fixed-0600"]), {0o600})
        self.assertEqual(set(modes_by_normalization["fixed-0444"]), {0o444})
        self.assertEqual(set(modes_by_normalization["preserve-exec"]), {0o644, 0o755})
        folded = modes_by_normalization["fold-class-bits-to-owner"]
        self.assertTrue(all(mode & 0o077 == 0 for mode in folded))
        self.assertGreater(len(set(folded)), 1)

    def test_all_100_trusted_trees_materialize_and_verify(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
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
            index = 0
            for task in self.tasks:
                for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                    bundle = build_mode_normalized_mirror_fixture_bundle(
                        task, profile
                    )
                    workspace = root / f"fixture-{index:03d}"
                    index += 1
                    with self.subTest(
                        selector=task.parameters.selector,
                        normalization=task.parameters.normalization,
                        profile=profile.profile_id,
                    ):
                        with materialize_fixture(bundle.definition, workspace) as handle:
                            self.assertEqual(handle.scan_outputs().entries, ())
                            write_trusted_oracle(workspace, bundle)
                            evidence = verify_executable_fixture(bundle, handle)
                            self.assertTrue(evidence.passed, evidence.failure_code)
                            self.assertEqual(
                                tuple(
                                    (output.path, output.mode)
                                    for output in evidence.outputs
                                ),
                                tuple(
                                    (output.path, output.mode)
                                    for output in bundle.oracle.outputs
                                ),
                            )
        self.assertEqual(index, 100)

    def test_rejects_wrong_task_profile_and_frozen_object_bypasses(self) -> None:
        task = task_by_parameters(
            self.tasks,
            selector="any-executable",
            normalization="fold-class-bits-to-owner",
        )
        profile = profile_by_id("spaces-unicode")
        with self.assertRaisesRegex(ExecutableFixtureModeMirrorError, "task must"):
            build_mode_normalized_mirror_fixture_bundle(  # type: ignore[arg-type]
                object(), profile
            )
        with self.assertRaisesRegex(ExecutableFixtureModeMirrorError, "profile must"):
            build_mode_normalized_mirror_fixture_bundle(  # type: ignore[arg-type]
                task, object()
            )

        forged_profile = exact_clone(profile)
        object.__setattr__(forged_profile, "profile_sha256", "0" * 64)
        with self.assertRaisesRegex(
            ExecutableFixtureModeMirrorError, "closed-contract revalidation"
        ):
            build_mode_normalized_mirror_fixture_bundle(task, forged_profile)

        forged_task = exact_clone(task)
        forged_parameters = ModeNormalizedMirrorParameters(
            selector=task.parameters.selector,
            normalization=task.parameters.normalization,
        )
        object.__setattr__(forged_parameters, "selector", "follows-symlinks")
        object.__setattr__(forged_task, "parameters", forged_parameters)
        with self.assertRaisesRegex(
            ExecutableFixtureModeMirrorError, "closed-contract revalidation"
        ):
            build_mode_normalized_mirror_fixture_bundle(forged_task, profile)

    def test_bundle_and_verifier_reject_mode_content_and_input_tampering(self) -> None:
        task = task_by_parameters(
            self.tasks,
            selector="owner-writable",
            normalization="preserve-exec",
        )
        profile = profile_by_id("partial-permissions")

        oracle_tamper = build_mode_normalized_mirror_fixture_bundle(task, profile)
        first_output = oracle_tamper.oracle.outputs[0]
        object.__setattr__(first_output, "content", first_output.content + b"tamper")
        with self.assertRaisesRegex(
            ExecutableFixtureBundleError, "oracle_sha256 does not match"
        ):
            validate_executable_fixture_bundle(oracle_tamper)

        mode_tamper = build_mode_normalized_mirror_fixture_bundle(task, profile)
        mode_output = mode_tamper.oracle.outputs[0]
        object.__setattr__(mode_output, "mode", mode_output.mode ^ 0o100)
        with self.assertRaisesRegex(
            ExecutableFixtureBundleError, "oracle_sha256 does not match"
        ):
            validate_executable_fixture_bundle(mode_tamper)

        input_tamper = build_mode_normalized_mirror_fixture_bundle(task, profile)
        first_input = next(
            item for item in input_tamper.definition.inputs if type(item) is InputFile
        )
        object.__setattr__(first_input, "mode", first_input.mode ^ 0o001)
        with self.assertRaisesRegex(
            ExecutableFixtureBundleError, "fixture_definition_sha256 does not match"
        ):
            validate_executable_fixture_bundle(input_tamper)

        live_bundle = build_mode_normalized_mirror_fixture_bundle(task, profile)
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            with materialize_fixture(live_bundle.definition, workspace) as handle:
                write_trusted_oracle(workspace, live_bundle)
                output = live_bundle.oracle.outputs[0]
                wrong_mode = 0o600 if output.mode != 0o600 else 0o644
                (workspace / output.path).chmod(wrong_mode)
                evidence = verify_executable_fixture(live_bundle, handle)
                self.assertFalse(evidence.passed)
                self.assertEqual(evidence.failure_code, "output-policy-failure")

    def test_optimized_mode_keeps_mode_and_hash_validation(self) -> None:
        code = """
from cbds.executable_fixture_bundle import (
    ExecutableFixtureBundleError,
    validate_executable_fixture_bundle,
)
from cbds.executable_fixture_mode_mirror import build_mode_normalized_mirror_fixture_bundle
from cbds.executable_fixture_profiles import PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
from cbds.executable_static_second_registry import build_mode_normalized_mirror_tasks
tasks = build_mode_normalized_mirror_tasks()
task = next(
    item for item in tasks
    if item.parameters.selector == "any-executable"
    and item.parameters.normalization == "preserve-exec"
)
bundle = build_mode_normalized_mirror_fixture_bundle(
    task, PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
)
validate_executable_fixture_bundle(bundle)
output = bundle.oracle.outputs[0]
object.__setattr__(output, "mode", output.mode ^ 0o100)
try:
    validate_executable_fixture_bundle(bundle)
except ExecutableFixtureBundleError:
    pass
else:
    raise SystemExit(3)
"""
        completed = subprocess.run(
            [sys.executable, "-O", "-c", code],
            cwd=ROOT,
            env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)


def _all_readable_assets() -> tuple[InputFile, ...]:
    task = task_by_parameters(
        ModeNormalizedMirrorFixtureTests.tasks,
        selector="all-readable",
        normalization="fixed-0644",
    )
    selected: list[InputFile] = []
    for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
        bundle = build_mode_normalized_mirror_fixture_bundle(task, profile)
        selected.extend(
            item
            for item in bundle.definition.inputs
            if type(item) is InputFile
            and PurePosixPath(item.path).parts[:2] == ("input", "assets")
            and item.mode & 0o444
        )
    return tuple(selected)


def _raises_unicode_decode(content: bytes) -> bool:
    try:
        content.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return True
    return False


if __name__ == "__main__":
    unittest.main()
