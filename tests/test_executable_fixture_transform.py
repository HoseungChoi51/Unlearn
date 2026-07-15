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
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
    ExecutableFixtureProfile,
)
from cbds.executable_fixture_transform import (  # noqa: E402
    ExecutableFixtureTransformError,
    build_line_transform_mirror_fixture_bundle,
)
from cbds.executable_fixture_verifier import (  # noqa: E402
    verify_executable_fixture,
)
from cbds.executable_static_second_registry import (  # noqa: E402
    build_line_transform_mirror_tasks,
)
from cbds.executable_static_types import (  # noqa: E402
    ExecutableStaticTask,
    LineTransformMirrorParameters,
)
from cbds.executable_workspace import (  # noqa: E402
    InputFile,
    InputSymlink,
    materialize_fixture,
)


SUFFIXES = (".txt", ".jsonl", ".log", ".csv")
TRANSFORMS = (
    "identity",
    "ascii-lower",
    "ascii-upper",
    "tabs-to-four-spaces",
    "delete-carriage-returns",
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
    tasks: tuple[ExecutableStaticTask, ...], *, suffix: str, transform: str
) -> ExecutableStaticTask:
    matches = tuple(
        task
        for task in tasks
        if task.parameters.suffix == suffix
        and task.parameters.transform == transform
    )
    if len(matches) != 1:
        raise AssertionError(
            f"expected one transform task for {suffix=!r}, {transform=!r}"
        )
    return matches[0]


def independent_transform(content: bytes, transform: str) -> bytes:
    if transform == "identity":
        return content
    if transform == "ascii-lower":
        return bytes(
            byte + 32 if ord("A") <= byte <= ord("Z") else byte
            for byte in content
        )
    if transform == "ascii-upper":
        return bytes(
            byte - 32 if ord("a") <= byte <= ord("z") else byte
            for byte in content
        )
    if transform == "tabs-to-four-spaces":
        rebuilt = bytearray()
        for byte in content:
            rebuilt.extend(b"    " if byte == 9 else bytes((byte,)))
        return bytes(rebuilt)
    if transform == "delete-carriage-returns":
        return bytes(byte for byte in content if byte != 13)
    raise AssertionError(f"unknown transform in test oracle: {transform!r}")


def independently_derive_outputs(
    task: ExecutableStaticTask, bundle: object
) -> tuple[tuple[str, bytes, int], ...]:
    selected: list[tuple[str, bytes, int]] = []
    for item in bundle.definition.inputs:
        if type(item) is not InputFile or item.mode & 0o444 == 0:
            continue
        source = PurePosixPath(item.path)
        if source.parts[:2] != ("input", "text"):
            continue
        relative = PurePosixPath(*source.parts[2:])
        if not relative.name.endswith(task.parameters.suffix):
            continue
        selected.append(
            (
                (PurePosixPath("output/mirror") / relative).as_posix(),
                independent_transform(item.content, task.parameters.transform),
                0o644,
            )
        )
    return tuple(sorted(selected, key=lambda item: item[0].encode("utf-8")))


def exact_clone(instance: object):
    clone = object.__new__(type(instance))
    for field in fields(instance):
        object.__setattr__(clone, field.name, getattr(instance, field.name))
    return clone


class LineTransformMirrorFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tasks = build_line_transform_mirror_tasks()

    def test_all_20_by_5_bundles_are_exact_deterministic_and_nonexecuting(
        self,
    ) -> None:
        self.assertEqual(len(self.tasks), 20)
        self.assertEqual(
            {
                (task.parameters.suffix, task.parameters.transform)
                for task in self.tasks
            },
            {(suffix, transform) for suffix in SUFFIXES for transform in TRANSFORMS},
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
                        suffix=task.parameters.suffix,
                        transform=task.parameters.transform,
                        profile=profile.profile_id,
                    ):
                        first = build_line_transform_mirror_fixture_bundle(
                            task, profile
                        )
                        second = build_line_transform_mirror_fixture_bundle(
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
                            "verify-line-transform-mirror-v1",
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
                                policy.path
                                for policy in first.definition.expected_files
                            ),
                            tuple(path for path, _content, _mode in observed),
                        )
                        self.assertTrue(
                            all(
                                policy.mode == 0o644
                                and policy.maximum_bytes == len(content)
                                for policy, (_path, content, _mode) in zip(
                                    first.definition.expected_files,
                                    observed,
                                    strict=True,
                                )
                            )
                        )
                        self.assertIs(first.candidate_execution_authorized, False)
                        self.assertIs(first.model_selection_eligible, False)
                        self.assertIs(first.claim_authorized, False)
                        descriptors.append(first.descriptor)

        self.assertEqual(len(descriptors), 100)
        self.assertEqual(len({item.fixture_id for item in descriptors}), 100)

    def test_profiles_cover_paths_bytes_symlinks_ordering_and_permissions(
        self,
    ) -> None:
        task = task_by_parameters(
            self.tasks,
            suffix=".txt",
            transform="identity",
        )

        spaces = build_line_transform_mirror_fixture_bundle(
            task, profile_by_id("spaces-unicode")
        )
        selected_spaces = independently_derive_outputs(task, spaces)
        self.assertTrue(any(" " in path for path, _content, _mode in selected_spaces))
        self.assertTrue(
            any(
                any(ord(character) > 127 for character in path)
                for path, _content, _mode in selected_spaces
            )
        )
        self.assertTrue(
            any(
                _raises_unicode_decode(content)
                for _path, content, _mode in selected_spaces
            )
        )

        leading = build_line_transform_mirror_fixture_bundle(
            task, profile_by_id("leading-dashes-globs")
        )
        leading_paths = [
            path
            for path, _content, _mode in independently_derive_outputs(
                task, leading
            )
        ]
        self.assertTrue(any("/-" in path for path in leading_paths))
        self.assertTrue(
            any(any(mark in path for mark in "*?[") for path in leading_paths)
        )

        duplicates = build_line_transform_mirror_fixture_bundle(
            task, profile_by_id("empty-duplicates")
        )
        duplicate_contents = [
            content
            for _path, content, _mode in independently_derive_outputs(task, duplicates)
        ]
        self.assertIn(b"", duplicate_contents)
        self.assertLess(len(set(duplicate_contents)), len(duplicate_contents))

        symlinks = build_line_transform_mirror_fixture_bundle(
            task, profile_by_id("symlinks-ordering")
        )
        input_paths = [item.path for item in symlinks.definition.inputs]
        self.assertNotEqual(input_paths, sorted(input_paths, key=str.encode))
        self.assertTrue(
            any(type(item) is InputSymlink for item in symlinks.definition.inputs)
        )
        output_paths = {
            path
            for path, _content, _mode in independently_derive_outputs(
                task, symlinks
            )
        }
        self.assertTrue(
            all(
                not (
                    PurePosixPath("output/mirror")
                    / PurePosixPath(*PurePosixPath(item.path).parts[2:])
                ).as_posix()
                in output_paths
                for item in symlinks.definition.inputs
                if type(item) is InputSymlink
            )
        )

        partial = build_line_transform_mirror_fixture_bundle(
            task, profile_by_id("partial-permissions")
        )
        matching_files = [
            item
            for item in partial.definition.inputs
            if type(item) is InputFile
            and item.path.startswith("input/text/")
            and PurePosixPath(item.path).name.endswith(".txt")
        ]
        self.assertTrue(any(item.mode == 0o000 for item in matching_files))
        self.assertTrue(any(item.mode == 0o404 for item in matching_files))
        self.assertTrue(any(item.mode == 0o400 for item in matching_files))
        partial_outputs = {
            path
            for path, _content, _mode in independently_derive_outputs(
                task, partial
            )
        }
        for item in matching_files:
            mirrored = (
                PurePosixPath("output/mirror")
                / PurePosixPath(*PurePosixPath(item.path).parts[2:])
            ).as_posix()
            self.assertEqual(mirrored in partial_outputs, item.mode & 0o444 != 0)

    def test_all_bundles_materialize_and_accept_the_trusted_oracle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for task_index, task in enumerate(self.tasks):
                for profile_index, profile in enumerate(
                    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
                ):
                    with self.subTest(
                        task=task.task_id,
                        profile=profile.profile_id,
                    ):
                        bundle = build_line_transform_mirror_fixture_bundle(
                            task, profile
                        )
                        workspace = root / f"case-{task_index}-{profile_index}"
                        with materialize_fixture(
                            bundle.definition, workspace
                        ) as handle:
                            for output in bundle.oracle.outputs:
                                target = workspace / output.path
                                target.parent.mkdir(parents=True, exist_ok=True)
                                current = workspace
                                for component in target.parent.relative_to(
                                    workspace
                                ).parts:
                                    current /= component
                                    current.chmod(0o755)
                                target.write_bytes(output.content)
                                target.chmod(output.mode)
                            evidence = verify_executable_fixture(bundle, handle)
                            self.assertTrue(evidence.passed)

    def test_each_transform_is_byte_exact_and_does_not_decode(self) -> None:
        profile = profile_by_id("spaces-unicode")
        results: dict[str, tuple[tuple[str, bytes, int], ...]] = {}
        for transform in TRANSFORMS:
            task = task_by_parameters(
                self.tasks,
                suffix=".jsonl",
                transform=transform,
            )
            bundle = build_line_transform_mirror_fixture_bundle(task, profile)
            observed = tuple(
                (output.path, output.content, output.mode)
                for output in bundle.oracle.outputs
            )
            expected = independently_derive_outputs(task, bundle)
            self.assertEqual(observed, expected)
            results[transform] = observed
        self.assertNotEqual(results["identity"], results["ascii-upper"])
        self.assertNotEqual(results["identity"], results["ascii-lower"])
        self.assertNotEqual(results["identity"], results["tabs-to-four-spaces"])
        self.assertNotEqual(results["identity"], results["delete-carriage-returns"])

    def test_rejects_wrong_task_profile_and_frozen_object_bypasses(self) -> None:
        task = task_by_parameters(
            self.tasks,
            suffix=".log",
            transform="ascii-upper",
        )
        profile = profile_by_id("spaces-unicode")
        with self.assertRaisesRegex(ExecutableFixtureTransformError, "task must"):
            build_line_transform_mirror_fixture_bundle(  # type: ignore[arg-type]
                object(), profile
            )
        with self.assertRaisesRegex(ExecutableFixtureTransformError, "profile must"):
            build_line_transform_mirror_fixture_bundle(  # type: ignore[arg-type]
                task, object()
            )

        forged_profile = exact_clone(profile)
        object.__setattr__(forged_profile, "profile_sha256", "0" * 64)
        with self.assertRaisesRegex(
            ExecutableFixtureTransformError, "closed-contract revalidation"
        ):
            build_line_transform_mirror_fixture_bundle(task, forged_profile)

        forged_task = exact_clone(task)
        forged_parameters = LineTransformMirrorParameters(
            suffix=task.parameters.suffix,
            transform=task.parameters.transform,
        )
        object.__setattr__(forged_parameters, "transform", "unicode-casefold")
        object.__setattr__(forged_task, "parameters", forged_parameters)
        with self.assertRaisesRegex(
            ExecutableFixtureTransformError, "closed-contract revalidation"
        ):
            build_line_transform_mirror_fixture_bundle(forged_task, profile)

    def test_bundle_validation_rejects_oracle_and_input_tampering(self) -> None:
        task = task_by_parameters(
            self.tasks,
            suffix=".csv",
            transform="delete-carriage-returns",
        )
        profile = profile_by_id("partial-permissions")

        oracle_tamper = build_line_transform_mirror_fixture_bundle(task, profile)
        first_output = oracle_tamper.oracle.outputs[0]
        object.__setattr__(first_output, "content", first_output.content + b"tamper")
        with self.assertRaisesRegex(
            ExecutableFixtureBundleError, "oracle_sha256 does not match"
        ):
            validate_executable_fixture_bundle(oracle_tamper)

        input_tamper = build_line_transform_mirror_fixture_bundle(task, profile)
        first_input = next(
            item for item in input_tamper.definition.inputs if type(item) is InputFile
        )
        object.__setattr__(first_input, "content", first_input.content + b"tamper")
        with self.assertRaisesRegex(
            ExecutableFixtureBundleError, "fixture_definition_sha256 does not match"
        ):
            validate_executable_fixture_bundle(input_tamper)


def _raises_unicode_decode(content: bytes) -> bool:
    try:
        content.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return True
    return False


if __name__ == "__main__":
    unittest.main()
