from __future__ import annotations

from dataclasses import replace
from decimal import Decimal
import json
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
    OracleOutputRecord,
    build_executable_fixture_bundle,
    build_trusted_fixture_oracle,
    validate_executable_fixture_bundle,
    verify_executable_fixture_bundle,
)
from cbds.executable_fixture_lines import (  # noqa: E402
    LINE_FIXTURE_GENERATOR_VERSION,
    ExecutableFixtureLineError,
    build_executable_line_fixture_bundle,
)
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from cbds.executable_static_registry import (  # noqa: E402
    build_public_method_development_registry,
)
from cbds.executable_static_types import (  # noqa: E402
    ActiveJsonlLabelsParameters,
    PathSuffixInventoryParameters,
)
from cbds.executable_workspace import (  # noqa: E402
    ExpectedFile,
    FixtureDefinition,
    InputFile,
    InputSymlink,
    materialize_fixture,
)


def _reject_duplicate_members(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate member")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite constant: {value}")


def independent_active_oracle(
    definition: FixtureDefinition,
    parameters: ActiveJsonlLabelsParameters,
) -> bytes:
    labels: set[str] = set()
    for item in definition.inputs:
        if type(item) is not InputFile:
            continue
        if not PurePosixPath(item.path).name.endswith(".jsonl"):
            continue
        if not item.mode & 0o444:
            continue
        for line in item.content.split(b"\n"):
            if not line:
                continue
            try:
                record = json.loads(
                    line.decode("utf-8", errors="strict"),
                    object_pairs_hook=_reject_duplicate_members,
                    parse_float=Decimal,
                    parse_int=int,
                    parse_constant=_reject_constant,
                )
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                continue
            if type(record) is not dict:
                continue
            if parameters.predicate == "active-true":
                selected = record.get("active") is True
            elif parameters.predicate == "enabled-yes":
                selected = record.get("enabled") == "yes"
            elif parameters.predicate == "state-ready":
                selected = record.get("state") == "ready"
            elif parameters.predicate == "deleted-false":
                selected = record.get("deleted") is False
            else:
                score = record.get("score")
                selected = (
                    type(score) is int and score >= 10
                ) or (
                    type(score) is Decimal
                    and score.is_finite()
                    and score >= Decimal(10)
                )
            if not selected:
                continue
            label = record.get(parameters.label_key)
            if type(label) is not str or any(value in label for value in "\0\r\n"):
                continue
            try:
                label.encode("utf-8", errors="strict")
            except UnicodeEncodeError:
                continue
            labels.add(label)
    return b"".join(
        value.encode("utf-8") + b"\n"
        for value in sorted(labels, key=lambda item: item.encode("utf-8"))
    )


def independent_path_oracle(
    definition: FixtureDefinition,
    parameters: PathSuffixInventoryParameters,
) -> bytes:
    selected: list[str] = []
    for item in definition.inputs:
        if type(item) is not InputFile or not item.mode & 0o444:
            continue
        path = PurePosixPath(item.path)
        relative = PurePosixPath(*path.parts[2:])
        if not relative.name.endswith(parameters.suffix):
            continue
        if (
            parameters.maximum_depth != "unbounded"
            and len(relative.parts) > parameters.maximum_depth
        ):
            continue
        selected.append(relative.as_posix())
    return b"".join(
        value.encode("utf-8") + b"\n"
        for value in sorted(selected, key=lambda item: item.encode("utf-8"))
    )


class GeneratedLineBundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = build_public_method_development_registry()
        cls.tasks = tuple(
            task
            for task in cls.registry.tasks
            if task.family_id
            in {"active-jsonl-labels", "path-suffix-inventory"}
        )
        cls.by_pair = {
            (task.task_id, profile.profile_id): build_executable_line_fixture_bundle(
                task, profile
            )
            for task in cls.tasks
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        }

    def bundle_for(self, task: object, profile_id: str):
        return self.by_pair[(task.task_id, profile_id)]  # type: ignore[attr-defined]

    def test_all_40_tasks_times_five_profiles_are_unique_and_deterministic(self) -> None:
        self.assertEqual(LINE_FIXTURE_GENERATOR_VERSION, "1.0.0")
        self.assertEqual(len(self.tasks), 40)
        self.assertEqual(
            {task.family_id: sum(item.family_id == task.family_id for item in self.tasks)
             for task in self.tasks},
            {"active-jsonl-labels": 20, "path-suffix-inventory": 20},
        )
        self.assertEqual(len(self.by_pair), 200)
        descriptors = [bundle.descriptor for bundle in self.by_pair.values()]
        self.assertEqual(len({item.fixture_sha256 for item in descriptors}), 200)
        self.assertEqual(len({item.fixture_id for item in descriptors}), 200)
        empty_oracles = [
            bundle
            for bundle in self.by_pair.values()
            if bundle.oracle.outputs[0].content == b""
        ]
        self.assertTrue(empty_oracles)
        self.assertTrue(
            all(bundle.definition.expected_files[0].maximum_bytes == 0 for bundle in empty_oracles)
        )

        for task in self.tasks:
            generated_for_task = []
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                with self.subTest(task=task.task_id, profile=profile.profile_id):
                    bundle = self.bundle_for(task, profile.profile_id)
                    validate_executable_fixture_bundle(bundle)
                    self.assertTrue(verify_executable_fixture_bundle(bundle))
                    self.assertEqual(bundle.task_contract_sha256, task.task_contract_sha256)
                    self.assertEqual(bundle.profile_sha256, profile.profile_sha256)
                    self.assertEqual(
                        build_executable_line_fixture_bundle(task, profile), bundle
                    )
                    self.assertIs(bundle.candidate_execution_authorized, False)
                    self.assertIs(bundle.model_selection_eligible, False)
                    self.assertIs(bundle.claim_authorized, False)
                    generated_for_task.append(bundle.descriptor.fixture_sha256)
            self.assertEqual(len(set(generated_for_task)), 5)

    def test_every_oracle_is_rederived_independently_from_input_bytes_and_modes(self) -> None:
        for task in self.tasks:
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                with self.subTest(task=task.task_id, profile=profile.profile_id):
                    bundle = self.bundle_for(task, profile.profile_id)
                    output = bundle.oracle.outputs[0]
                    if task.family_id == "active-jsonl-labels":
                        self.assertIs(type(task.parameters), ActiveJsonlLabelsParameters)
                        expected = independent_active_oracle(
                            bundle.definition, task.parameters
                        )
                        path = "output/labels.txt"
                        verifier = "verify-active-jsonl-labels-v1"
                    else:
                        self.assertIs(
                            type(task.parameters), PathSuffixInventoryParameters
                        )
                        expected = independent_path_oracle(
                            bundle.definition, task.parameters
                        )
                        path = "output/paths.txt"
                        verifier = "verify-path-suffix-inventory-v1"
                    self.assertEqual(output.path, path)
                    self.assertEqual(output.content, expected)
                    self.assertEqual(output.mode, 0o644)
                    self.assertEqual(
                        bundle.oracle.semantic_verifier_identity, verifier
                    )
                    self.assertEqual(
                        bundle.definition.expected_files,
                        (
                            ExpectedFile(
                                path,
                                maximum_bytes=len(expected),
                                mode=0o644,
                            ),
                        ),
                    )

    def test_each_profile_has_concrete_family_relevant_edge_case_evidence(self) -> None:
        active_task = next(
            task for task in self.tasks if task.family_id == "active-jsonl-labels"
        )
        path_task = next(
            task for task in self.tasks if task.family_id == "path-suffix-inventory"
        )
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
            active = self.bundle_for(active_task, profile.profile_id).definition
            paths = self.bundle_for(path_task, profile.profile_id).definition
            for definition in (active, paths):
                files = tuple(
                    item for item in definition.inputs if type(item) is InputFile
                )
                links = tuple(
                    item for item in definition.inputs if type(item) is InputSymlink
                )
                self.assertTrue(any(item.mode & 0o444 for item in files))
                self.assertTrue(any(not item.mode & 0o444 for item in files))
                self.assertTrue(links)

            active_files = tuple(
                item for item in active.inputs if type(item) is InputFile
            )
            self.assertTrue(
                any(not item.path.endswith(".jsonl") for item in active_files)
            )
            self.assertTrue(
                any(b"{not-json}" in item.content for item in active_files)
            )
            self.assertTrue(
                any(b'"score":10.5' in item.content for item in active_files)
            )
            path_files = tuple(
                item for item in paths.inputs if type(item) is InputFile
            )
            self.assertTrue(any(item.path.endswith(".bak") for item in path_files))
            depths = {
                len(PurePosixPath(item.path).parts[2:])
                for item in path_files
                if item.mode & 0o444 and not item.path.endswith(".bak")
            }
            self.assertEqual(depths, {1, 2, 3, 4, 5})

            combined_paths = [item.path for item in (*active.inputs, *paths.inputs)]
            if profile.profile_id == "spaces-unicode":
                self.assertTrue(any(" " in path for path in combined_paths))
                self.assertTrue(
                    any(
                        any(ord(char) > 127 for char in path)
                        for path in combined_paths
                    )
                )
            elif profile.profile_id == "leading-dashes-globs":
                self.assertTrue(
                    any(PurePosixPath(path).name.startswith("-") for path in combined_paths)
                )
                self.assertTrue(
                    any(any(char in path for char in "*?[]") for path in combined_paths)
                )
            elif profile.profile_id == "empty-duplicates":
                self.assertTrue(any(item.content == b"" for item in active_files))
                all_lines = [
                    line
                    for item in active_files
                    for line in item.content.split(b"\n")
                    if line
                ]
                self.assertLess(len(set(all_lines)), len(all_lines))
                self.assertTrue(any(item.content == b"" for item in path_files))
                basenames = [PurePosixPath(item.path).name for item in path_files]
                self.assertLess(len(set(basenames)), len(basenames))
            elif profile.profile_id == "symlinks-ordering":
                for definition in (active, paths):
                    observed = [item.path for item in definition.inputs]
                    self.assertNotEqual(observed, sorted(observed, key=str.encode))
            else:
                self.assertEqual(profile.profile_id, "partial-permissions")
                self.assertTrue(any(item.mode == 0 for item in active_files))
                self.assertTrue(any(item.mode == 0 for item in path_files))

    def test_hand_checked_representative_outputs_cover_both_parameter_axes(self) -> None:
        active_label = next(
            task
            for task in self.tasks
            if task.family_id == "active-jsonl-labels"
            and task.parameters.label_key == "label"
            and task.parameters.predicate == "active-true"
        )
        self.assertEqual(
            self.bundle_for(active_label, "spaces-unicode").oracle.outputs[0].content,
            "active-only\ncommon\nspace label\néclair\n".encode("utf-8"),
        )
        active_name = next(
            task
            for task in self.tasks
            if task.family_id == "active-jsonl-labels"
            and task.parameters.label_key == "name"
            and task.parameters.predicate == "score-at-least-10"
        )
        self.assertEqual(
            self.bundle_for(active_name, "spaces-unicode").oracle.outputs[0].content,
            "name common\nname decimal-score\nname score-only\nname with spaces\n이름\n".encode("utf-8"),
        )

        depth_two = next(
            task
            for task in self.tasks
            if task.family_id == "path-suffix-inventory"
            and task.parameters.suffix == ".txt"
            and task.parameters.maximum_depth == 2
        )
        self.assertEqual(
            self.bundle_for(depth_two, "spaces-unicode").oracle.outputs[0].content,
            "dir space/café file.txt\nroot space.txt\n".encode("utf-8"),
        )
        unbounded = next(
            task
            for task in self.tasks
            if task.family_id == "path-suffix-inventory"
            and task.parameters.suffix == ".txt"
            and task.parameters.maximum_depth == "unbounded"
        )
        self.assertEqual(
            self.bundle_for(unbounded, "symlinks-ordering").oracle.outputs[0].content,
            b"a-first/z-file.txt\n"
            b"alpha/z/y/x/file.txt\n"
            b"beta/z/a/file.txt\n"
            b"middle/a/m-file.txt\n"
            b"z-last.txt\n",
        )

    def test_generation_never_invokes_a_process_or_shell(self) -> None:
        with mock.patch.object(
            subprocess, "run", side_effect=AssertionError("subprocess executed")
        ), mock.patch.object(
            subprocess, "Popen", side_effect=AssertionError("subprocess executed")
        ), mock.patch.object(
            os, "system", side_effect=AssertionError("shell executed")
        ):
            for task in self.tasks:
                for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                    build_executable_line_fixture_bundle(task, profile)

    def test_every_profile_materializes_for_each_family_without_output_scaffold(self) -> None:
        representatives = (
            next(
                task
                for task in self.tasks
                if task.family_id == "active-jsonl-labels"
            ),
            next(
                task
                for task in self.tasks
                if task.family_id == "path-suffix-inventory"
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for task in representatives:
                for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                    with self.subTest(
                        family=task.family_id, profile=profile.profile_id
                    ):
                        bundle = self.bundle_for(task, profile.profile_id)
                        workspace = root / task.family_id / profile.profile_id
                        with materialize_fixture(
                            bundle.definition, workspace
                        ) as handle:
                            self.assertTrue(handle.scan_inputs().entries)
                            self.assertEqual(handle.scan_outputs().entries, ())

    def test_input_or_oracle_tampering_changes_identity_and_bypass_is_detected(self) -> None:
        task = next(
            item for item in self.tasks if item.family_id == "active-jsonl-labels"
        )
        profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
        baseline = build_executable_line_fixture_bundle(task, profile)
        first = baseline.definition.inputs[0]
        self.assertIs(type(first), InputFile)
        changed_input = replace(first, content=first.content + b" ")
        changed_definition = FixtureDefinition(
            fixture_id=baseline.definition.fixture_id,
            inputs=(changed_input, *baseline.definition.inputs[1:]),
            expected_files=baseline.definition.expected_files,
        )
        input_variant = build_executable_fixture_bundle(
            task_contract_sha256=task.task_contract_sha256,
            profile_sha256=profile.profile_sha256,
            definition=changed_definition,
            oracle=baseline.oracle,
        )
        self.assertNotEqual(
            input_variant.descriptor.fixture_sha256,
            baseline.descriptor.fixture_sha256,
        )

        original_output = baseline.oracle.outputs[0]
        replacement = bytes([original_output.content[0] ^ 1]) + original_output.content[1:]
        changed_oracle = build_trusted_fixture_oracle(
            (
                OracleOutputRecord(
                    original_output.path, replacement, original_output.mode
                ),
            ),
            semantic_verifier_identity=baseline.oracle.semantic_verifier_identity,
        )
        oracle_variant = build_executable_fixture_bundle(
            task_contract_sha256=task.task_contract_sha256,
            profile_sha256=profile.profile_sha256,
            definition=baseline.definition,
            oracle=changed_oracle,
        )
        self.assertNotEqual(
            oracle_variant.descriptor.fixture_sha256,
            baseline.descriptor.fixture_sha256,
        )

        bypassed = build_executable_line_fixture_bundle(task, profile)
        object.__setattr__(bypassed.definition.inputs[0], "content", bytearray(b"mutable"))
        self.assertFalse(verify_executable_fixture_bundle(bypassed))

    def test_wrong_family_and_noncanonical_task_profile_inputs_fail_closed(self) -> None:
        active = next(
            item for item in self.tasks if item.family_id == "active-jsonl-labels"
        )
        unsupported = next(
            item for item in self.registry.tasks if item.family_id == "manifest-copy"
        )
        profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
        for task_value, profile_value in (
            (unsupported, profile),
            (object(), profile),
            (active, object()),
        ):
            with self.subTest(task=task_value, profile=profile_value):
                with self.assertRaises(ExecutableFixtureLineError):
                    build_executable_line_fixture_bundle(  # type: ignore[arg-type]
                        task_value, profile_value
                    )

        cloned_descriptors = tuple(replace(item) for item in active.fixtures)
        forged_task = replace(active, fixtures=cloned_descriptors)
        object.__setattr__(
            forged_task.fixtures[0], "fixture_id", "fx-" + "0" * 24
        )
        with self.assertRaises(ExecutableFixtureLineError):
            build_executable_line_fixture_bundle(forged_task, profile)

        forged_profile = replace(profile)
        object.__setattr__(forged_profile, "profile_sha256", "0" * 64)
        with self.assertRaises(ExecutableFixtureLineError):
            build_executable_line_fixture_bundle(active, forged_profile)


if __name__ == "__main__":
    unittest.main()
