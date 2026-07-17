from __future__ import annotations

import copy
import os
from pathlib import Path, PurePosixPath
import random
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import cbds.executable_case_routed_batch_transform as routed  # noqa: E402
from cbds.executable_case_routed_batch_transform import (  # noqa: E402
    CASE_ROUTED_BATCH_TRANSFORM_ALLOWED_TOOLS,
    CASE_ROUTED_BATCH_TRANSFORM_ATOMIC_PUBLICATION_HISTORY_OBSERVED,
    CASE_ROUTED_BATCH_TRANSFORM_CANDIDATE_EXIT_STATUS_OBSERVED,
    CASE_ROUTED_BATCH_TRANSFORM_DIRECTORY_PERMISSION_ERRORS_COVERED,
    CASE_ROUTED_BATCH_TRANSFORM_EFFECTIVE_ACCESS_FAILURES_COVERED,
    CASE_ROUTED_BATCH_TRANSFORM_ERRORS_OUTPUT,
    CASE_ROUTED_BATCH_TRANSFORM_FALLBACK_POLICIES,
    CASE_ROUTED_BATCH_TRANSFORM_FAMILY_ID,
    CASE_ROUTED_BATCH_TRANSFORM_OUTPUT_MODE,
    CASE_ROUTED_BATCH_TRANSFORM_READ_SCOPE_OBSERVED,
    CASE_ROUTED_BATCH_TRANSFORM_ROUTE_HISTORY_OBSERVED,
    CASE_ROUTED_BATCH_TRANSFORM_ROUTE_KEYS,
    CASE_ROUTED_BATCH_TRANSFORM_STATUS_OUTPUT,
    CASE_ROUTED_BATCH_TRANSFORM_TOOL_HISTORY_OBSERVED,
    CASE_ROUTED_BATCH_TRANSFORM_TRANSFORM_HISTORY_OBSERVED,
    CASE_ROUTED_BATCH_TRANSFORM_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE,
    CASE_ROUTED_BATCH_TRANSFORM_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE,
    CaseRoutedBatchTransformError,
    CaseRoutedBatchTransformFixtureBundle,
    CaseRoutedBatchTransformParameters,
    CaseRoutedBatchTransformTask,
    build_case_routed_batch_transform_fixture_bundle,
    build_case_routed_batch_transform_tasks,
    derive_case_routed_batch_transform_outputs,
    materialize_case_routed_batch_transform_fixture,
    reference_case_routed_batch_transform_outputs,
    validate_case_routed_batch_transform_fixture_bundle,
    validate_case_routed_batch_transform_fixture_for_task_profile,
    verify_case_routed_batch_transform_fixture_bundle,
    verify_case_routed_batch_transform_fixture_for_task_profile,
    verify_case_routed_batch_transform_outputs,
    verify_case_routed_batch_transform_workspace,
)
from cbds.executable_fixture_bundle import OracleOutputRecord  # noqa: E402
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from cbds.executable_workspace import (  # noqa: E402
    ExpectedFile,
    FixtureDefinition,
    InputFile,
    InputSymlink,
)


def profile_by_id(profile_id: str):
    return next(
        profile
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        if profile.profile_id == profile_id
    )


def task_by_parameters(
    tasks: tuple[CaseRoutedBatchTransformTask, ...],
    route_key: str,
    fallback_policy: str,
) -> CaseRoutedBatchTransformTask:
    return next(
        task
        for task in tasks
        if task.parameters.route_key == route_key
        and task.parameters.fallback_policy == fallback_policy
    )


def output_map(
    bundle: CaseRoutedBatchTransformFixtureBundle,
) -> dict[str, bytes]:
    return {output.path: output.content for output in bundle.oracle.outputs}


def _write_oracle(workspace: Path, bundle: CaseRoutedBatchTransformFixtureBundle) -> None:
    for output in bundle.oracle.outputs:
        target = workspace / output.path
        target.parent.mkdir(parents=True, exist_ok=True)
        current = workspace
        for component in target.parent.relative_to(workspace).parts:
            current /= component
            current.chmod(0o755)
        target.write_bytes(output.content)
        target.chmod(output.mode)


def _manual_upper(content: bytes) -> bytes:
    return bytes(value - 32 if 97 <= value <= 122 else value for value in content)


def _manual_lower(content: bytes) -> bytes:
    return bytes(value + 32 if 65 <= value <= 90 else value for value in content)


def _manual_rot13(content: bytes) -> bytes:
    result = bytearray()
    for value in content:
        if 65 <= value <= 90:
            result.append(((value - 65 + 13) % 26) + 65)
        elif 97 <= value <= 122:
            result.append(((value - 97 + 13) % 26) + 97)
        else:
            result.append(value)
    return bytes(result)


class CaseRoutedBatchTransformTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tasks = build_case_routed_batch_transform_tasks()

    def test_exact_four_by_five_grid_types_and_metadata(self) -> None:
        self.assertEqual(len(self.tasks), 20)
        self.assertEqual(
            tuple(
                (task.parameters.route_key, task.parameters.fallback_policy)
                for task in self.tasks
            ),
            tuple(
                (route_key, fallback)
                for route_key in CASE_ROUTED_BATCH_TRANSFORM_ROUTE_KEYS
                for fallback in CASE_ROUTED_BATCH_TRANSFORM_FALLBACK_POLICIES
            ),
        )
        self.assertTrue(
            all(type(task) is CaseRoutedBatchTransformTask for task in self.tasks)
        )
        self.assertEqual(len({task.task_id for task in self.tasks}), 20)
        self.assertEqual(
            len({task.task_contract_sha256 for task in self.tasks}), 20
        )
        self.assertEqual(len({task.graph_sha256 for task in self.tasks}), 20)
        for task in self.tasks:
            with self.subTest(task=task.task_id):
                task.__post_init__()
                self.assertEqual(task.family_id, CASE_ROUTED_BATCH_TRANSFORM_FAMILY_ID)
                self.assertEqual(task.allowed_tools, CASE_ROUTED_BATCH_TRANSFORM_ALLOWED_TOOLS)
                self.assertEqual(len(task.fixtures), 5)
                self.assertIs(task.public, True)
                self.assertIs(task.sealed, False)
                self.assertIs(task.candidate_execution_authorized, False)
                self.assertIs(task.model_selection_eligible, False)
                self.assertIs(task.claim_authorized, False)

    def test_task_rebuild_is_deterministic_without_published_hash_literals(self) -> None:
        rebuilt = build_case_routed_batch_transform_tasks()
        self.assertEqual(rebuilt, self.tasks)
        self.assertTrue(
            all(
                len(task.task_contract_sha256) == 64
                and len(task.graph_sha256) == 64
                for task in rebuilt
            )
        )

    def test_all_100_bundles_are_deterministic_and_dual_oracle_bound(self) -> None:
        fixture_ids: set[str] = set()
        fixture_hashes: set[str] = set()
        for task in self.tasks:
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                with self.subTest(task=task.task_id, profile=profile.profile_id):
                    first = build_case_routed_batch_transform_fixture_bundle(
                        task, profile
                    )
                    second = build_case_routed_batch_transform_fixture_bundle(
                        task, profile
                    )
                    self.assertEqual(first, second)
                    self.assertIs(type(first), CaseRoutedBatchTransformFixtureBundle)
                    validate_case_routed_batch_transform_fixture_for_task_profile(
                        task, profile, first
                    )
                    self.assertTrue(
                        verify_case_routed_batch_transform_fixture_for_task_profile(
                            task, profile, first
                        )
                    )
                    primary = derive_case_routed_batch_transform_outputs(
                        first.definition, task.parameters
                    )
                    reference = reference_case_routed_batch_transform_outputs(
                        first.definition, task.parameters
                    )
                    self.assertEqual(primary, reference)
                    self.assertEqual(primary, first.oracle.outputs)
                    self.assertTrue(
                        verify_case_routed_batch_transform_outputs(
                            first.definition, task.parameters, primary
                        )
                    )
                    fixture_ids.add(first.descriptor.fixture_id)
                    fixture_hashes.add(first.descriptor.fixture_sha256)
        self.assertEqual(len(fixture_ids), 100)
        self.assertEqual(len(fixture_hashes), 100)

    def test_route_keys_and_fallbacks_are_behaviorally_distinct(self) -> None:
        profile = profile_by_id("spaces-unicode")
        values: dict[tuple[str, str], tuple[tuple[str, bytes], ...]] = {}
        for task in self.tasks:
            bundle = build_case_routed_batch_transform_fixture_bundle(task, profile)
            values[(task.parameters.route_key, task.parameters.fallback_policy)] = tuple(
                (output.path, output.content) for output in bundle.oracle.outputs
            )
        self.assertEqual(len(set(values.values())), 20)

    def test_signal_isolation_records_consult_only_selected_key(self) -> None:
        profile = profile_by_id("leading-dashes-globs")
        expected = {
            "suffix": "suffix-only",
            "record-kind": "kind-only",
            "leading-byte": "leading-only",
            "declared-action": "action-only",
        }
        isolation_ids = set(expected.values())
        for route_key, selected_id in expected.items():
            task = task_by_parameters(self.tasks, route_key, "skip")
            paths = output_map(
                build_case_routed_batch_transform_fixture_bundle(task, profile)
            )
            emitted = {
                identifier
                for identifier in isolation_ids
                if any(path.endswith(f"/{identifier}.out") for path in paths)
            }
            self.assertEqual(emitted, {selected_id})

    def test_complementary_isolation_ignores_three_recognized_other_signals(self) -> None:
        profile = profile_by_id("leading-dashes-globs")
        missing = {
            "suffix": "suffix-missing",
            "record-kind": "kind-missing",
            "leading-byte": "leading-missing",
            "declared-action": "action-missing",
        }
        all_ids = set(missing.values())
        for route_key, missing_id in missing.items():
            task = task_by_parameters(self.tasks, route_key, "skip")
            paths = output_map(
                build_case_routed_batch_transform_fixture_bundle(task, profile)
            )
            emitted = {
                identifier
                for identifier in all_ids
                if any(path.endswith(f"/{identifier}.out") for path in paths)
            }
            self.assertEqual(emitted, all_ids - {missing_id})

    def test_fallback_matrix_has_exact_status_errors_and_payloads(self) -> None:
        profile = profile_by_id("spaces-unicode")
        expected = {
            "skip": (b"batch\tcomplete\t5\t4\t1\t4\t0\n", b"", 4),
            "copy-verbatim": (b"batch\tcomplete\t5\t4\t1\t5\t0\n", b"", 5),
            "reject-batch": (
                b"batch\trejected\t5\t4\t1\t0\t1\n",
                b"rejected\tmystery space\tsuffix\n",
                0,
            ),
            "route-default": (b"batch\tcomplete\t5\t4\t1\t5\t0\n", b"", 5),
            "emit-error-record": (
                b"batch\tcomplete\t5\t4\t1\t4\t1\n",
                b"unmatched\tmystery space\tsuffix\n",
                4,
            ),
        }
        for fallback, (status, errors, payload_count) in expected.items():
            task = task_by_parameters(self.tasks, "suffix", fallback)
            outputs = output_map(
                build_case_routed_batch_transform_fixture_bundle(task, profile)
            )
            self.assertEqual(outputs[CASE_ROUTED_BATCH_TRANSFORM_STATUS_OUTPUT], status)
            self.assertEqual(outputs[CASE_ROUTED_BATCH_TRANSFORM_ERRORS_OUTPUT], errors)
            self.assertEqual(
                sum(path.startswith("output/routes/") for path in outputs),
                payload_count,
            )

    def test_all_recognized_batch_allows_reject_policy_to_complete(self) -> None:
        profile = profile_by_id("symlinks-ordering")
        for route_key in CASE_ROUTED_BATCH_TRANSFORM_ROUTE_KEYS:
            task = task_by_parameters(self.tasks, route_key, "reject-batch")
            outputs = output_map(
                build_case_routed_batch_transform_fixture_bundle(task, profile)
            )
            self.assertEqual(
                outputs[CASE_ROUTED_BATCH_TRANSFORM_STATUS_OUTPUT],
                b"batch\tcomplete\t4\t4\t0\t4\t0\n",
            )
            self.assertEqual(outputs[CASE_ROUTED_BATCH_TRANSFORM_ERRORS_OUTPUT], b"")
            self.assertEqual(
                sum(path.startswith("output/routes/") for path in outputs), 4
            )

    def test_late_unmatched_rejects_without_partial_payloads(self) -> None:
        profile = profile_by_id("partial-permissions")
        task = task_by_parameters(self.tasks, "suffix", "reject-batch")
        bundle = build_case_routed_batch_transform_fixture_bundle(task, profile)
        manifest = next(
            item
            for item in bundle.definition.inputs
            if type(item) is InputFile and item.path.endswith("manifest.tsv")
        )
        self.assertTrue(manifest.content.rstrip(b"\n").endswith(b"preserve"))
        outputs = output_map(bundle)
        self.assertEqual(
            outputs[CASE_ROUTED_BATCH_TRANSFORM_STATUS_OUTPUT],
            b"batch\trejected\t5\t4\t1\t0\t1\n",
        )
        self.assertFalse(any(path.startswith("output/routes/") for path in outputs))

    def test_each_transform_is_byte_exact_and_binary_preserving(self) -> None:
        profile = profile_by_id("partial-permissions")
        task = task_by_parameters(self.tasks, "suffix", "skip")
        bundle = build_case_routed_batch_transform_fixture_bundle(task, profile)
        files = {
            item.path: item.content
            for item in bundle.definition.inputs
            if type(item) is InputFile
        }
        outputs = output_map(bundle)
        self.assertEqual(
            outputs["output/routes/upper/alpha.out"],
            _manual_upper(files["input/batch/payloads/alpha.upper"]),
        )
        self.assertEqual(
            outputs["output/routes/lower/beta.out"],
            _manual_lower(files["input/batch/payloads/beta.lower"]),
        )
        self.assertEqual(
            outputs["output/routes/detab/gamma.out"],
            files["input/batch/payloads/gamma.tabs"].replace(b"\t", b"    "),
        )
        self.assertEqual(
            outputs["output/routes/strip-cr/delta.out"],
            files["input/batch/payloads/delta.crlf"].replace(b"\r", b""),
        )
        self.assertTrue(
            all(b"\x00" in outputs[path] and b"\xff" in outputs[path] for path in outputs if path.startswith("output/routes/"))
        )

    def test_default_rot13_and_verbatim_handle_nul_leading_payload(self) -> None:
        profile = profile_by_id("spaces-unicode")
        copy_task = task_by_parameters(self.tasks, "leading-byte", "copy-verbatim")
        default_task = task_by_parameters(self.tasks, "leading-byte", "route-default")
        copy_bundle = build_case_routed_batch_transform_fixture_bundle(copy_task, profile)
        default_bundle = build_case_routed_batch_transform_fixture_bundle(
            default_task, profile
        )
        source = next(
            item.content
            for item in copy_bundle.definition.inputs
            if type(item) is InputFile and item.path.endswith("mystery café.bin")
        )
        self.assertEqual(source[:1], b"\x00")
        self.assertEqual(
            output_map(copy_bundle)[
                "output/routes/verbatim/mystery space.out"
            ],
            source,
        )
        self.assertEqual(
            output_map(default_bundle)[
                "output/routes/default/mystery space.out"
            ],
            _manual_rot13(source),
        )

    def test_leading_byte_semantics_cover_the_full_byte_domain(self) -> None:
        parameters = CaseRoutedBatchTransformParameters("leading-byte", "skip")
        expected_routes = {
            ord("U"): "upper",
            ord("L"): "lower",
            ord("T"): "detab",
            ord("C"): "strip-cr",
        }
        for value in range(256):
            identifier = f"byte-{value:03d}"
            source_path = f"input/batch/payloads/{identifier}.bin"
            manifest = (
                f"{identifier}\t{source_path}\topaque\tpreserve\n"
            ).encode("ascii")
            definition = FixtureDefinition(
                f"fixture.byte-{value:03d}",
                (
                    InputFile("input/batch/manifest.tsv", manifest, 0o400),
                    InputFile(
                        source_path,
                        bytes((value,)) + b"Ab\t\r\x00\xff",
                        0o400,
                    ),
                ),
                (),
            )
            primary = derive_case_routed_batch_transform_outputs(
                definition, parameters
            )
            reference = reference_case_routed_batch_transform_outputs(
                definition, parameters
            )
            self.assertEqual(primary, reference)
            paths = {output.path for output in primary}
            route = expected_routes.get(value)
            if route is None:
                self.assertEqual(
                    {
                        path
                        for path in paths
                        if path.startswith("output/routes/")
                    },
                    set(),
                )
            else:
                self.assertIn(
                    f"output/routes/{route}/{identifier}.out", paths
                )

    def test_durable_leading_byte_canaries_do_not_skip_to_later_markers(self) -> None:
        task = task_by_parameters(self.tasks, "leading-byte", "skip")
        profile = profile_by_id("leading-dashes-globs")
        outputs = output_map(
            build_case_routed_batch_transform_fixture_bundle(task, profile)
        )
        for identifier in (
            "leading-nul-u",
            "leading-bom-u",
            "leading-lf-u",
            "leading-lower-u",
        ):
            self.assertFalse(
                any(path.endswith(f"/{identifier}.out") for path in outputs)
            )
        self.assertEqual(
            outputs["output/routes/upper/leading-no-final-lf.out"],
            b"UAB",
        )

    def test_reference_engine_does_not_call_primary_route_or_transform(self) -> None:
        task = task_by_parameters(self.tasks, "suffix", "route-default")
        profile = profile_by_id("spaces-unicode")
        bundle = build_case_routed_batch_transform_fixture_bundle(task, profile)
        expected = reference_case_routed_batch_transform_outputs(
            bundle.definition, task.parameters
        )
        with mock.patch.object(
            routed,
            "_primary_route",
            side_effect=AssertionError("reference used primary route"),
        ), mock.patch.object(
            routed,
            "_primary_transform",
            side_effect=AssertionError("reference used primary transform"),
        ), mock.patch.object(
            routed,
            "_validate_identifier_text",
            side_effect=AssertionError("reference used primary ID validator"),
        ), mock.patch.object(
            routed,
            "_validate_source_text",
            side_effect=AssertionError("reference used primary path validator"),
        ), mock.patch.object(
            routed,
            "_payload_output_path",
            side_effect=AssertionError("reference used primary path builder"),
        ):
            observed = reference_case_routed_batch_transform_outputs(
                bundle.definition, task.parameters
            )
        self.assertEqual(observed, expected)

    def test_public_verifier_detects_forced_primary_reference_disagreement(self) -> None:
        task = task_by_parameters(self.tasks, "suffix", "skip")
        profile = profile_by_id("spaces-unicode")
        bundle = build_case_routed_batch_transform_fixture_bundle(task, profile)
        with mock.patch.object(routed, "_primary_route", return_value=None):
            self.assertFalse(
                verify_case_routed_batch_transform_outputs(
                    bundle.definition,
                    task.parameters,
                    bundle.oracle.outputs,
                )
            )

    def test_duplicate_rows_collapse_and_duplicate_payloads_remain_distinct(self) -> None:
        profile = profile_by_id("empty-duplicates")
        task = task_by_parameters(self.tasks, "suffix", "copy-verbatim")
        bundle = build_case_routed_batch_transform_fixture_bundle(task, profile)
        manifest = next(
            item.content
            for item in bundle.definition.inputs
            if type(item) is InputFile and item.path.endswith("manifest.tsv")
        )
        self.assertEqual(manifest.count(b"alpha\t"), 2)
        outputs = output_map(bundle)
        self.assertEqual(
            outputs[CASE_ROUTED_BATCH_TRANSFORM_STATUS_OUTPUT],
            b"batch\tcomplete\t7\t5\t2\t7\t0\n",
        )
        self.assertIn("output/routes/lower/beta-alias.out", outputs)
        self.assertNotEqual(
            "output/routes/lower/beta.out",
            "output/routes/detab/gamma.out",
        )

    def test_empty_manifest_and_physical_order_invariance(self) -> None:
        parameters = CaseRoutedBatchTransformParameters("suffix", "skip")
        empty = FixtureDefinition(
            "fixture.empty-batch",
            (InputFile("input/batch/manifest.tsv", b"", 0o400),),
            (),
        )
        primary = derive_case_routed_batch_transform_outputs(empty, parameters)
        reference = reference_case_routed_batch_transform_outputs(empty, parameters)
        self.assertEqual(primary, reference)
        self.assertEqual(
            {output.path: output.content for output in primary},
            {
                CASE_ROUTED_BATCH_TRANSFORM_ERRORS_OUTPUT: b"",
                CASE_ROUTED_BATCH_TRANSFORM_STATUS_OUTPUT: (
                    b"batch\tcomplete\t0\t0\t0\t0\t0\n"
                ),
            },
        )

        task = task_by_parameters(self.tasks, "suffix", "emit-error-record")
        profile = profile_by_id("spaces-unicode")
        bundle = build_case_routed_batch_transform_fixture_bundle(task, profile)
        manifest_index = next(
            index
            for index, item in enumerate(bundle.definition.inputs)
            if type(item) is InputFile and item.path.endswith("manifest.tsv")
        )
        manifest = bundle.definition.inputs[manifest_index]
        assert type(manifest) is InputFile
        rows = manifest.content.splitlines(keepends=True)
        inputs = list(bundle.definition.inputs)
        inputs[manifest_index] = InputFile(
            manifest.path, b"".join(reversed(rows)), manifest.mode
        )
        permuted = FixtureDefinition(
            "fixture.permuted-order",
            tuple(inputs),
            bundle.definition.expected_files,
        )
        self.assertEqual(
            derive_case_routed_batch_transform_outputs(
                permuted, task.parameters
            ),
            bundle.oracle.outputs,
        )
        self.assertEqual(
            reference_case_routed_batch_transform_outputs(
                permuted, task.parameters
            ),
            bundle.oracle.outputs,
        )

    def test_randomized_valid_batches_keep_oracles_independent(self) -> None:
        generator = random.Random(0xCBDA7)
        suffixes = (".upper", ".lower", ".tabs", ".crlf", ".bin")
        kinds = (
            "uppercase-text",
            "lowercase-text",
            "tabbed-text",
            "crlf-text",
            "opaque",
        )
        actions = (
            "uppercase",
            "lowercase",
            "expand-tabs",
            "delete-cr",
            "preserve",
        )
        for case_index in range(200):
            rows: list[bytes] = []
            inputs: list[InputFile] = []
            record_count = 1 + generator.randrange(5)
            for record_index in range(record_count):
                identifier = f"r-{case_index:03d}-{record_index}"
                suffix = suffixes[generator.randrange(len(suffixes))]
                source = f"input/batch/payloads/{identifier}{suffix}"
                kind = kinds[generator.randrange(len(kinds))]
                action = actions[generator.randrange(len(actions))]
                rows.append(
                    f"{identifier}\t{source}\t{kind}\t{action}\n".encode(
                        "ascii"
                    )
                )
                content = bytes(generator.randrange(256) for _ in range(24))
                inputs.append(InputFile(source, content, 0o400))
            definition = FixtureDefinition(
                f"fixture.random-{case_index:03d}",
                (
                    InputFile(
                        "input/batch/manifest.tsv", b"".join(rows), 0o400
                    ),
                    *inputs,
                ),
                (),
            )
            parameters = CaseRoutedBatchTransformParameters(
                CASE_ROUTED_BATCH_TRANSFORM_ROUTE_KEYS[
                    case_index % len(CASE_ROUTED_BATCH_TRANSFORM_ROUTE_KEYS)
                ],
                CASE_ROUTED_BATCH_TRANSFORM_FALLBACK_POLICIES[
                    (case_index // 4)
                    % len(CASE_ROUTED_BATCH_TRANSFORM_FALLBACK_POLICIES)
                ],
            )
            self.assertEqual(
                derive_case_routed_batch_transform_outputs(
                    definition, parameters
                ),
                reference_case_routed_batch_transform_outputs(
                    definition, parameters
                ),
            )

    def test_profiles_bind_spaces_globs_empty_symlinks_order_and_modes(self) -> None:
        task = task_by_parameters(self.tasks, "suffix", "skip")
        bundles = {
            profile.profile_id: build_case_routed_batch_transform_fixture_bundle(
                task, profile
            )
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        }
        spaces = bundles["spaces-unicode"]
        self.assertTrue(any(" " in item.path for item in spaces.definition.inputs))
        self.assertTrue(
            any(
                any(ord(character) > 127 for character in item.path)
                for item in spaces.definition.inputs
            )
        )
        leading = bundles["leading-dashes-globs"]
        self.assertTrue(any("/-" in item.path for item in leading.definition.inputs))
        self.assertTrue(
            any(any(mark in item.path for mark in "*?[") for item in leading.definition.inputs)
        )
        empty = bundles["empty-duplicates"]
        self.assertTrue(
            any(type(item) is InputFile and item.content == b"" for item in empty.definition.inputs)
        )
        symlinks = bundles["symlinks-ordering"]
        self.assertTrue(any(type(item) is InputSymlink for item in symlinks.definition.inputs))
        manifest = next(
            item.content
            for item in symlinks.definition.inputs
            if type(item) is InputFile and item.path.endswith("manifest.tsv")
        )
        rows = manifest.splitlines()
        self.assertNotEqual(rows, sorted(rows))
        partial = bundles["partial-permissions"]
        modes = {
            item.mode for item in partial.definition.inputs if type(item) is InputFile
        }
        self.assertTrue({0o000, 0o400, 0o440, 0o444}.issubset(modes))

    def test_oracle_records_reject_wrong_order_content_and_types(self) -> None:
        task = task_by_parameters(self.tasks, "declared-action", "route-default")
        profile = profile_by_id("spaces-unicode")
        bundle = build_case_routed_batch_transform_fixture_bundle(task, profile)
        self.assertFalse(
            verify_case_routed_batch_transform_outputs(
                bundle.definition,
                task.parameters,
                tuple(reversed(bundle.oracle.outputs)),
            )
        )
        mutant = list(bundle.oracle.outputs)
        first = mutant[0]
        mutant[0] = OracleOutputRecord(
            first.path, first.content + b"x", first.mode
        )
        self.assertFalse(
            verify_case_routed_batch_transform_outputs(
                bundle.definition, task.parameters, tuple(mutant)
            )
        )
        self.assertFalse(
            verify_case_routed_batch_transform_outputs(
                bundle.definition, task.parameters, list(bundle.oracle.outputs)
            )
        )

    def test_all_100_workspaces_accept_exact_oracles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            passes = 0
            for task_index, task in enumerate(self.tasks):
                for profile_index, profile in enumerate(
                    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
                ):
                    bundle = build_case_routed_batch_transform_fixture_bundle(
                        task, profile
                    )
                    workspace = root / f"case-{task_index:02d}-{profile_index}"
                    with materialize_case_routed_batch_transform_fixture(
                        task, profile, bundle, workspace
                    ) as handle:
                        self.assertEqual(handle.scan_outputs().entries, ())
                        _write_oracle(workspace, bundle)
                        self.assertTrue(
                            verify_case_routed_batch_transform_workspace(
                                task, profile, bundle, handle
                            )
                        )
                        passes += 1
            self.assertEqual(passes, 100)

    def test_workspace_rejects_missing_corrupt_extra_wrong_mode_and_hardlink(self) -> None:
        task = task_by_parameters(self.tasks, "suffix", "skip")
        profile = profile_by_id("spaces-unicode")
        bundle = build_case_routed_batch_transform_fixture_bundle(task, profile)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            workspace = root / "missing"
            with materialize_case_routed_batch_transform_fixture(
                task, profile, bundle, workspace
            ) as handle:
                self.assertFalse(
                    verify_case_routed_batch_transform_workspace(
                        task, profile, bundle, handle
                    )
                )

            workspace = root / "symlink"
            with materialize_case_routed_batch_transform_fixture(
                task, profile, bundle, workspace
            ) as handle:
                _write_oracle(workspace, bundle)
                target = workspace / CASE_ROUTED_BATCH_TRANSFORM_STATUS_OUTPUT
                target.unlink()
                target.symlink_to("errors.tsv")
                self.assertFalse(
                    verify_case_routed_batch_transform_workspace(
                        task, profile, bundle, handle
                    )
                )

            workspace = root / "fifo"
            with materialize_case_routed_batch_transform_fixture(
                task, profile, bundle, workspace
            ) as handle:
                _write_oracle(workspace, bundle)
                target = workspace / CASE_ROUTED_BATCH_TRANSFORM_STATUS_OUTPUT
                target.unlink()
                os.mkfifo(target)
                self.assertFalse(
                    verify_case_routed_batch_transform_workspace(
                        task, profile, bundle, handle
                    )
                )

            workspace = root / "oversize"
            with materialize_case_routed_batch_transform_fixture(
                task, profile, bundle, workspace
            ) as handle:
                _write_oracle(workspace, bundle)
                target = workspace / CASE_ROUTED_BATCH_TRANSFORM_STATUS_OUTPUT
                target.write_bytes(b"x" * (64 * 1024 + 1))
                self.assertFalse(
                    verify_case_routed_batch_transform_workspace(
                        task, profile, bundle, handle
                    )
                )

            workspace = root / "input-mutant"
            with materialize_case_routed_batch_transform_fixture(
                task, profile, bundle, workspace
            ) as handle:
                _write_oracle(workspace, bundle)
                target = workspace / "input/batch/manifest.tsv"
                target.chmod(0o600)
                self.assertFalse(
                    verify_case_routed_batch_transform_workspace(
                        task, profile, bundle, handle
                    )
                )

            workspace = root / "corrupt"
            with materialize_case_routed_batch_transform_fixture(
                task, profile, bundle, workspace
            ) as handle:
                _write_oracle(workspace, bundle)
                target = workspace / bundle.oracle.outputs[0].path
                target.write_bytes(target.read_bytes() + b"x")
                self.assertFalse(
                    verify_case_routed_batch_transform_workspace(
                        task, profile, bundle, handle
                    )
                )

            workspace = root / "extra"
            with materialize_case_routed_batch_transform_fixture(
                task, profile, bundle, workspace
            ) as handle:
                _write_oracle(workspace, bundle)
                (workspace / "output/extra").mkdir()
                self.assertFalse(
                    verify_case_routed_batch_transform_workspace(
                        task, profile, bundle, handle
                    )
                )

            workspace = root / "mode"
            with materialize_case_routed_batch_transform_fixture(
                task, profile, bundle, workspace
            ) as handle:
                _write_oracle(workspace, bundle)
                (workspace / CASE_ROUTED_BATCH_TRANSFORM_STATUS_OUTPUT).chmod(0o600)
                self.assertFalse(
                    verify_case_routed_batch_transform_workspace(
                        task, profile, bundle, handle
                    )
                )

            workspace = root / "hardlink"
            with materialize_case_routed_batch_transform_fixture(
                task, profile, bundle, workspace
            ) as handle:
                _write_oracle(workspace, bundle)
                source = workspace / CASE_ROUTED_BATCH_TRANSFORM_STATUS_OUTPUT
                os.link(source, workspace / "output/status-link.tsv")
                self.assertFalse(
                    verify_case_routed_batch_transform_workspace(
                        task, profile, bundle, handle
                    )
                )

    def test_manifest_domain_rejects_conflicts_missing_sources_and_bad_framing(self) -> None:
        task = task_by_parameters(self.tasks, "suffix", "skip")
        profile = profile_by_id("spaces-unicode")
        bundle = build_case_routed_batch_transform_fixture_bundle(task, profile)
        manifest_index = next(
            index
            for index, item in enumerate(bundle.definition.inputs)
            if type(item) is InputFile and item.path.endswith("manifest.tsv")
        )
        manifest = bundle.definition.inputs[manifest_index]
        assert type(manifest) is InputFile
        bad_values = (
            manifest.content[:-1],
            manifest.content + b"alpha space\tinput/batch/payloads/other.bin\topaque\tpreserve\n",
            manifest.content + b"new\tinput/batch/payloads/missing.bin\topaque\tpreserve\n",
        )
        for raw in bad_values:
            inputs = list(bundle.definition.inputs)
            inputs[manifest_index] = InputFile(manifest.path, raw, manifest.mode)
            definition = FixtureDefinition(
                "fixture.invalid-manifest",
                tuple(inputs),
                (),
            )
            with self.subTest(raw=raw[-40:]), self.assertRaises(
                CaseRoutedBatchTransformError
            ):
                derive_case_routed_batch_transform_outputs(
                    definition, task.parameters
                )

    def test_manifest_and_payload_resource_limits_fail_closed(self) -> None:
        parameters = CaseRoutedBatchTransformParameters("suffix", "skip")
        source = "input/batch/payloads/resource.upper"
        row = f"resource\t{source}\tuppercase-text\tuppercase\n".encode(
            "ascii"
        )
        too_many_rows = FixtureDefinition(
            "fixture.too-many-rows",
            (
                InputFile("input/batch/manifest.tsv", row * 257, 0o400),
                InputFile(source, b"Udata", 0o400),
            ),
            (),
        )
        oversized_payload = FixtureDefinition(
            "fixture.oversized-payload",
            (
                InputFile("input/batch/manifest.tsv", row, 0o400),
                InputFile(source, b"U" * (16 * 1024 + 1), 0o400),
            ),
            (),
        )
        for definition in (too_many_rows, oversized_payload):
            with self.subTest(fixture=definition.fixture_id):
                with self.assertRaises(CaseRoutedBatchTransformError):
                    derive_case_routed_batch_transform_outputs(
                        definition, parameters
                    )
                with self.assertRaises(CaseRoutedBatchTransformError):
                    reference_case_routed_batch_transform_outputs(
                        definition, parameters
                    )

    def test_noncanonical_nested_definition_containers_fail_public_derivations(self) -> None:
        task = task_by_parameters(self.tasks, "suffix", "skip")
        profile = profile_by_id("spaces-unicode")
        bundle = build_case_routed_batch_transform_fixture_bundle(task, profile)
        forged = copy.copy(bundle.definition)
        object.__setattr__(forged, "inputs", list(forged.inputs))
        with self.assertRaises(CaseRoutedBatchTransformError):
            derive_case_routed_batch_transform_outputs(forged, task.parameters)
        with self.assertRaises(CaseRoutedBatchTransformError):
            reference_case_routed_batch_transform_outputs(
                forged, task.parameters
            )
        self.assertFalse(
            verify_case_routed_batch_transform_outputs(
                forged, task.parameters, bundle.oracle.outputs
            )
        )

        forged_policy = copy.copy(bundle.definition)
        object.__setattr__(
            forged_policy,
            "expected_files",
            tuple(reversed(forged_policy.expected_files)),
        )
        with self.assertRaises(CaseRoutedBatchTransformError):
            derive_case_routed_batch_transform_outputs(
                forged_policy, task.parameters
            )
        with self.assertRaises(CaseRoutedBatchTransformError):
            reference_case_routed_batch_transform_outputs(
                forged_policy, task.parameters
            )
        self.assertFalse(
            verify_case_routed_batch_transform_outputs(
                forged_policy, task.parameters, bundle.oracle.outputs
            )
        )

    def test_cross_task_profile_nested_tamper_and_wrong_types_fail_closed(self) -> None:
        task = task_by_parameters(self.tasks, "suffix", "skip")
        other_task = task_by_parameters(self.tasks, "record-kind", "skip")
        profile = profile_by_id("spaces-unicode")
        other_profile = profile_by_id("partial-permissions")
        bundle = build_case_routed_batch_transform_fixture_bundle(task, profile)
        self.assertFalse(
            verify_case_routed_batch_transform_fixture_for_task_profile(
                other_task, profile, bundle
            )
        )
        self.assertFalse(
            verify_case_routed_batch_transform_fixture_for_task_profile(
                task, other_profile, bundle
            )
        )
        self.assertFalse(verify_case_routed_batch_transform_fixture_bundle(object()))
        with self.assertRaises(CaseRoutedBatchTransformError):
            validate_case_routed_batch_transform_fixture_bundle(  # type: ignore[arg-type]
                object()
            )
        tampered = copy.deepcopy(bundle)
        object.__setattr__(
            tampered.oracle.outputs[0],
            "content",
            tampered.oracle.outputs[0].content + b"tamper",
        )
        self.assertFalse(verify_case_routed_batch_transform_fixture_bundle(tampered))

    def test_parameter_task_and_bundle_subclasses_fail(self) -> None:
        class ParameterSubclass(CaseRoutedBatchTransformParameters):
            pass

        with self.assertRaises(CaseRoutedBatchTransformError):
            ParameterSubclass("suffix", "skip")

        class TaskSubclass(CaseRoutedBatchTransformTask):
            pass

        task = self.tasks[0]
        with self.assertRaises(CaseRoutedBatchTransformError):
            TaskSubclass(
                task_id=task.task_id,
                parameters=task.parameters,
                prompt=task.prompt,
                graph=task.graph,
                fixtures=task.fixtures,
                task_contract_sha256=task.task_contract_sha256,
            )

        with self.assertRaises(CaseRoutedBatchTransformError):
            CaseRoutedBatchTransformParameters(  # type: ignore[arg-type]
                "outside", "skip"
            )
        with self.assertRaises(CaseRoutedBatchTransformError):
            CaseRoutedBatchTransformParameters(  # type: ignore[arg-type]
                "suffix", "outside"
            )

    def test_construction_never_executes_processes(self) -> None:
        with mock.patch.object(
            subprocess, "run", side_effect=AssertionError("run executed")
        ), mock.patch.object(
            subprocess, "Popen", side_effect=AssertionError("Popen executed")
        ), mock.patch.object(
            os, "system", side_effect=AssertionError("system executed")
        ), mock.patch.object(
            os, "popen", side_effect=AssertionError("popen executed")
        ):
            tasks = build_case_routed_batch_transform_tasks()
            bundle = build_case_routed_batch_transform_fixture_bundle(
                tasks[0], PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
            )
        self.assertEqual(len(tasks), 20)
        self.assertTrue(verify_case_routed_batch_transform_fixture_bundle(bundle))

    def test_honest_final_state_claim_boundaries_are_explicit(self) -> None:
        self.assertIs(
            CASE_ROUTED_BATCH_TRANSFORM_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE,
            True,
        )
        for value in (
            CASE_ROUTED_BATCH_TRANSFORM_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE,
            CASE_ROUTED_BATCH_TRANSFORM_DIRECTORY_PERMISSION_ERRORS_COVERED,
            CASE_ROUTED_BATCH_TRANSFORM_EFFECTIVE_ACCESS_FAILURES_COVERED,
            CASE_ROUTED_BATCH_TRANSFORM_ROUTE_HISTORY_OBSERVED,
            CASE_ROUTED_BATCH_TRANSFORM_TRANSFORM_HISTORY_OBSERVED,
            CASE_ROUTED_BATCH_TRANSFORM_READ_SCOPE_OBSERVED,
            CASE_ROUTED_BATCH_TRANSFORM_TOOL_HISTORY_OBSERVED,
            CASE_ROUTED_BATCH_TRANSFORM_ATOMIC_PUBLICATION_HISTORY_OBSERVED,
            CASE_ROUTED_BATCH_TRANSFORM_CANDIDATE_EXIT_STATUS_OBSERVED,
        ):
            self.assertIs(value, False)
        prompt = self.tasks[0].prompt
        self.assertIn("satisfy this input domain", prompt)
        self.assertIn("Physical row order is nonsemantic", prompt)
        self.assertIn("do not store it with Bash `read`", prompt)


if __name__ == "__main__":
    unittest.main()
