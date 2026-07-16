from __future__ import annotations

import ast
from dataclasses import replace
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import cbds.executable_pipefail_atomic_report as pipefail  # noqa: E402
from cbds.executable_fixture_bundle import OracleOutputRecord  # noqa: E402
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from cbds.executable_static_types import OpaqueFixtureDescriptor  # noqa: E402
from cbds.executable_workspace import (  # noqa: E402
    ExpectedFile,
    FixtureDefinition,
    InputFile,
    InputSymlink,
)


def _profile(profile_id: str):
    matches = tuple(
        profile
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        if profile.profile_id == profile_id
    )
    if len(matches) != 1:
        raise AssertionError(f"expected one profile named {profile_id!r}")
    return matches[0]


def _input(definition: FixtureDefinition, path: str) -> InputFile:
    matches = tuple(item for item in definition.inputs if item.path == path)
    if len(matches) != 1 or type(matches[0]) is not InputFile:
        raise AssertionError(f"expected one regular input named {path!r}")
    return matches[0]


def _replace_input(
    definition: FixtureDefinition,
    path: str,
    *,
    content: bytes | None = None,
    mode: int | None = None,
) -> FixtureDefinition:
    changed = False
    entries = []
    for item in definition.inputs:
        if item.path == path:
            if type(item) is not InputFile:
                raise AssertionError("test mutation expected a regular input")
            item = replace(
                item,
                content=item.content if content is None else content,
                mode=item.mode if mode is None else mode,
            )
            changed = True
        entries.append(item)
    if not changed:
        raise AssertionError(f"test mutation did not find {path!r}")
    return replace(definition, inputs=tuple(entries))


def _decoded(payload: bytes) -> dict[str, object]:
    if not payload.endswith(b"\n") or payload.count(b"\n") != 1:
        raise AssertionError("report is not exactly one LF-terminated line")
    value = json.loads(payload.decode("utf-8"))
    if type(value) is not dict:
        raise AssertionError("report is not a JSON object")
    canonical = (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    if canonical != payload:
        raise AssertionError("report is not compact canonical JSON")
    return value


def _write_expected(workspace: Path, bundle) -> None:
    if not bundle.oracle.outputs:
        return
    output = workspace / "output"
    output.mkdir(mode=0o755)
    os.chmod(output, 0o755)
    report = output / "report.json"
    report.write_bytes(bundle.oracle.outputs[0].content)
    os.chmod(report, 0o644)


class _StringSubclass(str):
    pass


class _BytesSubclass(bytes):
    pass


class PipefailAtomicReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tasks = pipefail.build_pipefail_atomic_report_tasks()
        cls.by_pair = {
            (task.task_id, profile.profile_id): (
                pipefail.build_pipefail_atomic_report_fixture_bundle(task, profile)
            )
            for task in cls.tasks
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        }

    def task(self, shape: str, policy: str):
        matches = tuple(
            task
            for task in self.tasks
            if task.parameters.pipeline_shape == shape
            and task.parameters.failure_commit_policy == policy
        )
        self.assertEqual(len(matches), 1)
        return matches[0]

    def bundle(self, shape: str, policy: str, profile_id: str):
        task = self.task(shape, policy)
        return self.by_pair[(task.task_id, profile_id)]

    def test_exact_four_by_five_grid_identity_and_authority(self) -> None:
        self.assertEqual(pipefail.PIPEFAIL_ATOMIC_REPORT_GENERATOR_VERSION, "1.0.0")
        self.assertEqual(
            pipefail.PIPEFAIL_ATOMIC_REPORT_PIPELINE_SHAPES,
            (
                "linear-two-stage",
                "linear-four-stage",
                "fan-in-merge",
                "tee-and-reduce",
            ),
        )
        self.assertEqual(
            pipefail.PIPEFAIL_ATOMIC_REPORT_FAILURE_COMMIT_POLICIES,
            (
                "commit-success-only",
                "write-status-always",
                "rollback-on-any-failure",
                "preserve-first-failure",
                "preserve-last-failure",
            ),
        )
        self.assertEqual(
            pipefail.PIPEFAIL_ATOMIC_REPORT_ALLOWED_TOOLS,
            ("awk", "grep", "mkdir", "mv", "sed", "sort"),
        )
        self.assertEqual(len(self.tasks), 20)
        self.assertEqual(
            tuple(
                (
                    task.parameters.pipeline_shape,
                    task.parameters.failure_commit_policy,
                )
                for task in self.tasks
            ),
            tuple(
                (shape, policy)
                for shape in pipefail.PIPEFAIL_ATOMIC_REPORT_PIPELINE_SHAPES
                for policy in pipefail.PIPEFAIL_ATOMIC_REPORT_FAILURE_COMMIT_POLICIES
            ),
        )
        self.assertEqual(len({task.task_id for task in self.tasks}), 20)
        self.assertEqual(len({task.task_contract_sha256 for task in self.tasks}), 20)
        self.assertEqual(len({task.graph_sha256 for task in self.tasks}), 20)
        for task in self.tasks:
            self.assertEqual(task.family_id, "pipefail-atomic-report")
            self.assertEqual(task.filesystem_identity, "pipeline-record-streams")
            self.assertEqual(task.output_identity, "atomic-pipeline-status-json")
            self.assertIs(task.public, True)
            self.assertIs(task.sealed, False)
            self.assertIs(task.candidate_execution_authorized, False)
            self.assertIs(task.model_selection_eligible, False)
            self.assertIs(task.claim_authorized, False)
            self.assertEqual(len(task.fixtures), 5)
            record = task.to_public_record()
            self.assertIs(record["candidate_execution_authorized"], False)
            self.assertIs(record["claim_authorized"], False)
            self.assertNotIn("oracle", record)
            self.assertNotIn("answer", record)

    def test_all_one_hundred_bundles_are_deterministic_and_authenticated(self) -> None:
        self.assertEqual(len(self.by_pair), 100)
        descriptors = set()
        fixture_digests = set()
        for task in self.tasks:
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                bundle = self.by_pair[(task.task_id, profile.profile_id)]
                rebuilt = pipefail.build_pipefail_atomic_report_fixture_bundle(
                    task, profile
                )
                self.assertEqual(bundle, rebuilt)
                self.assertTrue(
                    pipefail.verify_pipefail_atomic_report_fixture_bundle(bundle)
                )
                self.assertTrue(
                    pipefail.verify_pipefail_atomic_report_fixture_for_task_profile(
                        task, profile, bundle
                    )
                )
                self.assertEqual(bundle.descriptor, task.fixtures[
                    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES.index(profile)
                ])
                self.assertIs(bundle.candidate_execution_authorized, False)
                self.assertIs(bundle.model_selection_eligible, False)
                self.assertIs(bundle.claim_authorized, False)
                descriptors.add(bundle.descriptor.fixture_id)
                fixture_digests.add(bundle.fixture_definition_sha256)
                commitment = bundle.commitment_record()
                self.assertIs(commitment["candidate_execution_authorized"], False)
                self.assertIs(commitment["claim_authorized"], False)
                self.assertNotIn("content", repr(commitment))
        self.assertEqual(len(descriptors), 100)
        # Definition commitments intentionally exclude the task contract, so
        # policy cells with the same inputs/output-presence may share one.
        self.assertGreaterEqual(len(fixture_digests), 20)

    def test_both_oracles_agree_for_every_bundle_and_outputs_are_canonical(self) -> None:
        absent = 0
        present = 0
        answer_sizes = set()
        for task in self.tasks:
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                bundle = self.by_pair[(task.task_id, profile.profile_id)]
                primary = pipefail.derive_pipefail_atomic_report_output(
                    bundle.definition, task.parameters
                )
                reference = pipefail.reference_pipefail_atomic_report_output(
                    bundle.definition, task.parameters
                )
                self.assertEqual(primary, reference)
                self.assertTrue(
                    pipefail.verify_pipefail_atomic_report_output(
                        bundle.definition, task.parameters, primary
                    )
                )
                if primary is None:
                    absent += 1
                    self.assertEqual(bundle.definition.expected_files, ())
                    self.assertEqual(bundle.oracle.outputs, ())
                else:
                    present += 1
                    answer_sizes.add(len(primary))
                    self.assertLessEqual(
                        len(primary),
                        pipefail.PIPEFAIL_ATOMIC_REPORT_OUTPUT_MAXIMUM_BYTES,
                    )
                    self.assertEqual(len(bundle.oracle.outputs), 1)
                    self.assertEqual(bundle.oracle.outputs[0].content, primary)
                    prior = _input(
                        bundle.definition, pipefail.PIPEFAIL_ATOMIC_REPORT_PRIOR
                    ).content
                    if primary != prior:
                        _decoded(primary)
                    self.assertEqual(
                        bundle.definition.expected_files,
                        (
                            ExpectedFile(
                                "output/report.json",
                                maximum_bytes=64 * 1024,
                                mode=0o644,
                            ),
                        ),
                    )
        self.assertEqual(absent, 8)
        self.assertEqual(present, 92)
        self.assertGreater(len(answer_sizes), 20)

    def test_success_semantics_are_shape_specific_and_policy_independent(self) -> None:
        expected = {
            "linear-two-stage": [
                {"count": 1, "key": "ALPHA team", "sum": -1},
                {"count": 1, "key": "Alpha team", "sum": 2},
                {"count": 1, "key": "SecondMain", "sum": 4},
                {"count": 1, "key": "ZeroCase", "sum": 0},
                {"count": 1, "key": "βeta", "sum": 3},
            ],
            "linear-four-stage": [
                {"count": 1, "key": "alpha team", "sum": 2},
                {"count": 1, "key": "secondmain", "sum": 4},
                {"count": 1, "key": "βeta", "sum": 3},
            ],
            "fan-in-merge": [
                {"count": 2, "key": "alpha", "sum": 3},
                {"count": 1, "key": "rightupper", "sum": -6},
                {"count": 1, "key": "secondleft", "sum": 1},
                {"count": 1, "key": "two words", "sum": -4},
                {"count": 1, "key": "upper", "sum": 9},
                {"count": 1, "key": "zeta", "sum": 3},
                {"count": 1, "key": "βeta", "sum": 7},
            ],
            "tee-and-reduce": [
                {"count": 2, "key": "alpha team", "sum": 1},
                {"count": 1, "key": "secondmain", "sum": 4},
                {"count": 1, "key": "zerocase", "sum": 0},
                {"count": 1, "key": "βeta", "sum": 3},
            ],
        }
        for shape, expected_result in expected.items():
            outputs = []
            for policy in pipefail.PIPEFAIL_ATOMIC_REPORT_FAILURE_COMMIT_POLICIES:
                bundle = self.bundle(shape, policy, "spaces-unicode")
                payload = bundle.oracle.outputs[0].content
                outputs.append(payload)
                report = _decoded(payload)
                self.assertEqual(report["decision"], "success")
                self.assertEqual(report["shape"], shape)
                self.assertEqual(report["result"], expected_result)
                self.assertIsNone(report["selected_failure"])
                self.assertTrue(
                    all(item["status"] == 0 for item in report["pipeline"])
                )
                if shape == "tee-and-reduce":
                    self.assertEqual(report["audit"], {"count": 5, "sum": 8})
                else:
                    self.assertIsNone(report["audit"])
            self.assertEqual(len(set(outputs)), 1)

    def test_failure_policy_crossovers_first_last_and_prior_bytes(self) -> None:
        for shape in pipefail.PIPEFAIL_ATOMIC_REPORT_PIPELINE_SHAPES:
            commit = self.bundle(
                shape, "commit-success-only", "symlinks-ordering"
            )
            status = self.bundle(
                shape, "write-status-always", "symlinks-ordering"
            )
            rollback = self.bundle(
                shape, "rollback-on-any-failure", "symlinks-ordering"
            )
            first = self.bundle(
                shape, "preserve-first-failure", "symlinks-ordering"
            )
            last = self.bundle(
                shape, "preserve-last-failure", "symlinks-ordering"
            )
            self.assertEqual(commit.oracle.outputs, ())
            self.assertEqual(commit.definition.expected_files, ())
            status_report = _decoded(status.oracle.outputs[0].content)
            first_report = _decoded(first.oracle.outputs[0].content)
            last_report = _decoded(last.oracle.outputs[0].content)
            self.assertEqual(status_report["decision"], "status")
            self.assertEqual(status_report["result"], [])
            self.assertIsNone(status_report["audit"])
            self.assertIsNone(status_report["selected_failure"])
            failures = [
                item for item in status_report["pipeline"] if item["status"] != 0
            ]
            self.assertGreaterEqual(len(failures), 2)
            self.assertGreater(failures[0]["status"], failures[-1]["status"])
            self.assertEqual(
                first_report["selected_failure"],
                {"code": failures[0]["status"], "stage": failures[0]["stage"]},
            )
            self.assertEqual(
                last_report["selected_failure"],
                {"code": failures[-1]["status"], "stage": failures[-1]["stage"]},
            )
            prior = _input(
                rollback.definition, pipefail.PIPEFAIL_ATOMIC_REPORT_PRIOR
            ).content
            self.assertEqual(rollback.oracle.outputs[0].content, prior)
            self.assertNotEqual(status.oracle.outputs[0].content, prior)

    def test_profiles_observe_every_stage_and_declared_edge_cases(self) -> None:
        self.assertIs(pipefail.PIPEFAIL_ATOMIC_REPORT_SYMLINK_DISTRACTORS_COVERED, True)
        self.assertIs(
            pipefail.PIPEFAIL_ATOMIC_REPORT_DIRECTORY_PERMISSION_ERRORS_COVERED,
            False,
        )
        self.assertIs(
            pipefail.PIPEFAIL_ATOMIC_REPORT_EFFECTIVE_ACCESS_FAILURES_COVERED,
            False,
        )
        self.assertIs(
            pipefail.PIPEFAIL_ATOMIC_REPORT_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE,
            True,
        )
        self.assertIs(
            pipefail.PIPEFAIL_ATOMIC_REPORT_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE,
            False,
        )
        self.assertIs(
            pipefail.PIPEFAIL_ATOMIC_REPORT_ATOMIC_PUBLICATION_HISTORY_OBSERVED,
            False,
        )
        self.assertIs(
            pipefail.PIPEFAIL_ATOMIC_REPORT_ATOMIC_PUBLICATION_OBSERVED,
            False,
        )
        self.assertIs(
            pipefail.PIPEFAIL_ATOMIC_REPORT_PIPELINE_STATUS_HISTORY_OBSERVED,
            False,
        )
        self.assertIs(
            pipefail.PIPEFAIL_ATOMIC_REPORT_PIPESTATUS_HISTORY_OBSERVED,
            False,
        )
        self.assertIs(
            pipefail.PIPEFAIL_ATOMIC_REPORT_PIPELINE_TOPOLOGY_HISTORY_OBSERVED,
            False,
        )
        self.assertIs(pipefail.PIPEFAIL_ATOMIC_REPORT_TOOL_HISTORY_OBSERVED, False)
        for shape in pipefail.PIPEFAIL_ATOMIC_REPORT_PIPELINE_SHAPES:
            success_profiles = (
                "spaces-unicode",
                "leading-dashes-globs",
                "empty-duplicates",
            )
            for profile_id in success_profiles:
                report = _decoded(
                    self.bundle(shape, "write-status-always", profile_id)
                    .oracle.outputs[0]
                    .content
                )
                self.assertTrue(all(item["status"] == 0 for item in report["pipeline"]))
            failure_reports = [
                _decoded(
                    self.bundle(shape, "write-status-always", profile_id)
                    .oracle.outputs[0]
                    .content
                )
                for profile_id in ("symlinks-ordering", "partial-permissions")
            ]
            stages = [item["stage"] for item in failure_reports[0]["pipeline"]]
            nonzero_stages = {
                item["stage"]
                for report in failure_reports
                for item in report["pipeline"]
                if item["status"]
            }
            self.assertEqual(nonzero_stages, set(stages))
            for report in failure_reports:
                self.assertGreaterEqual(
                    sum(item["status"] != 0 for item in report["pipeline"]), 2
                )
        ordering = self.bundle(
            "linear-four-stage", "write-status-always", "symlinks-ordering"
        ).definition
        self.assertTrue(any(type(item) is InputSymlink for item in ordering.inputs))
        manifest = _input(ordering, pipefail.PIPEFAIL_ATOMIC_REPORT_SOURCES).content
        self.assertGreater(manifest.find(b"z-last"), -1)
        self.assertLess(manifest.find(b"z-last"), manifest.find(b"a-first"))
        ordering_task = self.task("linear-four-stage", "write-status-always")
        self.assertIn(
            "aggregate result must not depend on their physical row order",
            ordering_task.prompt,
        )
        self.assertIn(
            "source-order:nonsemantic",
            ordering_task.graph.nodes[0].parameters,
        )
        order_invariant = self.bundle(
            "linear-two-stage", "write-status-always", "spaces-unicode"
        )
        order_manifest = _input(
            order_invariant.definition,
            pipefail.PIPEFAIL_ATOMIC_REPORT_SOURCES,
        ).content
        reordered_sources = _replace_input(
            order_invariant.definition,
            pipefail.PIPEFAIL_ATOMIC_REPORT_SOURCES,
            content=b"".join(reversed(order_manifest.splitlines(keepends=True))),
        )
        order_task = self.task("linear-two-stage", "write-status-always")
        self.assertEqual(
            pipefail.derive_pipefail_atomic_report_output(
                reordered_sources, order_task.parameters
            ),
            order_invariant.oracle.outputs[0].content,
        )
        self.assertEqual(
            pipefail.reference_pipefail_atomic_report_output(
                reordered_sources, order_task.parameters
            ),
            order_invariant.oracle.outputs[0].content,
        )
        self.assertIn("exit with status 0", ordering_task.prompt)
        self.assertIn(
            "including byte-exact rollback output",
            ordering_task.prompt,
        )
        self.assertIn(
            "candidate-exit:0-after-policy",
            ordering_task.graph.nodes[3].parameters,
        )
        partial = self.bundle(
            "linear-two-stage", "write-status-always", "partial-permissions"
        ).definition
        modes = {
            item.mode for item in partial.inputs if type(item) is InputFile
        }
        self.assertTrue({0o000, 0o400, 0o600}.issubset(modes))
        empty = self.bundle(
            "linear-two-stage", "write-status-always", "empty-duplicates"
        ).definition
        self.assertTrue(
            any(type(item) is InputFile and item.content == b"" for item in empty.inputs)
        )
        leading = self.bundle(
            "linear-four-stage", "write-status-always", "leading-dashes-globs"
        )
        self.assertEqual(_decoded(leading.oracle.outputs[0].content)["result"], [])
        unlisted = tuple(
            item
            for item in leading.definition.inputs
            if "unlisted" in item.path
        )
        self.assertTrue(any(type(item) is InputFile for item in unlisted))
        self.assertTrue(any(type(item) is InputSymlink for item in unlisted))

    def test_status_parser_requires_completeness_uniqueness_and_canonical_codes(self) -> None:
        task = self.task("linear-four-stage", "write-status-always")
        bundle = self.bundle(
            "linear-four-stage", "write-status-always", "spaces-unicode"
        )
        original = _input(
            bundle.definition, pipefail.PIPEFAIL_ATOMIC_REPORT_STATUSES
        ).content
        rows = original.splitlines(keepends=True)
        reordered = _replace_input(
            bundle.definition,
            pipefail.PIPEFAIL_ATOMIC_REPORT_STATUSES,
            content=b"".join(reversed(rows)),
        )
        # Arbitrary physical row order must canonicalize to the same stage vector.
        self.assertEqual(
            pipefail.derive_pipefail_atomic_report_output(reordered, task.parameters),
            bundle.oracle.outputs[0].content,
        )
        mutants = (
            b"".join(rows[:-1]),
            original + rows[0],
            original.replace(b"select-enabled\t0", b"unknown\t0", 1),
            original.replace(b"select-enabled\t0", b"select-enabled\t01", 1),
            original.replace(b"select-enabled\t0", b"select-enabled\t+1", 1),
            original.replace(b"select-enabled\t0", b"select-enabled\t126", 1),
            original[:-1],
            original + b"\n",
        )
        for mutant in mutants:
            definition = _replace_input(
                bundle.definition,
                pipefail.PIPEFAIL_ATOMIC_REPORT_STATUSES,
                content=mutant,
            )
            with self.subTest(mutant=mutant):
                with self.assertRaises(pipefail.PipefailAtomicReportError):
                    pipefail.derive_pipefail_atomic_report_output(
                        definition, task.parameters
                    )
                with self.assertRaises(pipefail.PipefailAtomicReportError):
                    pipefail.reference_pipefail_atomic_report_output(
                        definition, task.parameters
                    )

    def test_manifest_parser_rejects_role_path_kind_and_mode_mutants(self) -> None:
        task = self.task("linear-two-stage", "write-status-always")
        bundle = self.bundle(
            "linear-two-stage", "write-status-always", "spaces-unicode"
        )
        manifest = _input(
            bundle.definition, pipefail.PIPEFAIL_ATOMIC_REPORT_SOURCES
        ).content
        relative = manifest.splitlines()[0].split(b"\t", 1)[1]
        mutants = (
            b"left\t" + relative + b"\n",
            manifest + manifest,
            b"main\t../escape.tsv\n",
            b"main\t/absolute.tsv\n",
            b"main\t./same.tsv\n",
            b"main\tmissing.tsv\n",
            manifest[:-1],
            b"main\tbad\xff.tsv\n",
            b"main\ttoo\tmany.tsv\n",
        )
        for mutant in mutants:
            definition = _replace_input(
                bundle.definition,
                pipefail.PIPEFAIL_ATOMIC_REPORT_SOURCES,
                content=mutant,
            )
            with self.subTest(mutant=mutant):
                self.assertFalse(
                    pipefail.verify_pipefail_atomic_report_output(
                        definition, task.parameters, bundle.oracle.outputs[0].content
                    )
                )
        source_path = (
            pipefail.PIPEFAIL_ATOMIC_REPORT_DATA_ROOT.as_posix()
            + "/"
            + relative.decode("utf-8")
        )
        unreadable = _replace_input(bundle.definition, source_path, mode=0o040)
        with self.assertRaises(pipefail.PipefailAtomicReportError):
            pipefail.derive_pipefail_atomic_report_output(unreadable, task.parameters)
        symlink_bundle = self.bundle(
            "linear-two-stage", "write-status-always", "symlinks-ordering"
        )
        selected_link = _replace_input(
            symlink_bundle.definition,
            pipefail.PIPEFAIL_ATOMIC_REPORT_SOURCES,
            content=b"main\t00-unlisted-link.tsv\n",
        )
        with self.assertRaises(pipefail.PipefailAtomicReportError):
            pipefail.reference_pipefail_atomic_report_output(
                selected_link, task.parameters
            )

    def test_data_parser_rejects_encoding_control_field_and_integer_mutants(self) -> None:
        task = self.task("linear-two-stage", "write-status-always")
        bundle = self.bundle(
            "linear-two-stage", "write-status-always", "spaces-unicode"
        )
        manifest = _input(
            bundle.definition, pipefail.PIPEFAIL_ATOMIC_REPORT_SOURCES
        ).content
        source_path = (
            pipefail.PIPEFAIL_ATOMIC_REPORT_DATA_ROOT.as_posix()
            + "/"
            + manifest.splitlines()[0].split(b"\t", 1)[1].decode("utf-8")
        )
        for accepted_message in (
            b"message with carriage return\r",
            "message with C1 \u0085 control".encode("utf-8"),
            b'message with "quote" and \\backslash',
        ):
            accepted = _replace_input(
                bundle.definition,
                source_path,
                content=b"yes\tkey\t1\t" + accepted_message + b"\n",
            )
            primary = pipefail.derive_pipefail_atomic_report_output(
                accepted, task.parameters
            )
            reference = pipefail.reference_pipefail_atomic_report_output(
                accepted, task.parameters
            )
            self.assertEqual(primary, reference)
        mutants = (
            b"yes\tkey\t1\tmessage",
            b"yes\tkey\t1\tmessage\textra\n",
            b"maybe\tkey\t1\tmessage\n",
            b"yes\t\t1\tmessage\n",
            b"yes\tkey\t1\t\n",
            b"yes\tbad\x7fkey\t1\tmessage\n",
            "yes\tbad\u0085key\t1\tmessage\n".encode("utf-8"),
            b'yes\tbad"key\t1\tmessage\n',
            b"yes\tbad\\key\t1\tmessage\n",
            b"yes\tbad\xff\t1\tmessage\n",
            b"yes\tkey\t1\tbad\0message\n",
            b"yes\tkey\t+1\tmessage\n",
            b"yes\tkey\t01\tmessage\n",
            b"yes\tkey\t1000001\tmessage\n",
            b"\n",
        )
        for mutant in mutants:
            definition = _replace_input(
                bundle.definition, source_path, content=mutant
            )
            with self.subTest(mutant=mutant):
                with self.assertRaises(pipefail.PipefailAtomicReportError):
                    pipefail.derive_pipefail_atomic_report_output(
                        definition, task.parameters
                    )
                with self.assertRaises(pipefail.PipefailAtomicReportError):
                    pipefail.reference_pipefail_atomic_report_output(
                        definition, task.parameters
                    )

    def test_prior_report_requires_exact_one_line_canonical_json(self) -> None:
        task = self.task("linear-two-stage", "rollback-on-any-failure")
        bundle = self.bundle(
            "linear-two-stage", "rollback-on-any-failure", "symlinks-ordering"
        )
        mutants = (
            b'{"a": 1}\n',
            b'{"a":1,"a":1}\n',
            b'{"a":NaN}\n',
            b'[1,2]\n',
            b'{"a":1}',
            b'{"a":1}\n\n',
            b'{"a":"\xff"}\n',
            b'{"a":' * 2_000 + b"0" + b"}" * 2_000 + b"\n",
            b'{"a":"' + b"x" * (64 * 1024) + b'"}\n',
        )
        for mutant in mutants:
            definition = _replace_input(
                bundle.definition,
                pipefail.PIPEFAIL_ATOMIC_REPORT_PRIOR,
                content=mutant,
            )
            with self.subTest(mutant=mutant):
                self.assertFalse(
                    pipefail.verify_pipefail_atomic_report_output(
                        definition, task.parameters, mutant
                    )
                )

    def test_result_transformations_sorting_duplicates_and_canceling_are_observable(self) -> None:
        expected = {
            "linear-two-stage": {
                "cancel": {"count": 2, "sum": 0},
                "repeat": {"count": 2, "sum": 10},
            },
            "linear-four-stage": {
                "cancel": {"count": 1, "sum": 4},
                "repeat": {"count": 2, "sum": 10},
            },
            "fan-in-merge": {
                "other": {"count": 1, "sum": 2},
                "repeat": {"count": 3, "sum": 0},
            },
            "tee-and-reduce": {
                "cancel": {"count": 2, "sum": 0},
                "repeat": {"count": 2, "sum": 10},
            },
        }
        for shape, records in expected.items():
            report = _decoded(
                self.bundle(shape, "write-status-always", "empty-duplicates")
                .oracle.outputs[0]
                .content
            )
            observed = {
                item["key"]: {"count": item["count"], "sum": item["sum"]}
                for item in report["result"]
            }
            self.assertEqual(observed, records)
            keys = [item["key"] for item in report["result"]]
            self.assertEqual(keys, sorted(keys, key=lambda key: key.encode("utf-8")))
            if shape == "tee-and-reduce":
                self.assertEqual(report["audit"], {"count": 4, "sum": 10})

    def test_output_verifier_kills_json_status_result_and_absence_mutants(self) -> None:
        task = self.task("tee-and-reduce", "preserve-first-failure")
        success = self.bundle(
            "tee-and-reduce", "preserve-first-failure", "spaces-unicode"
        )
        payload = success.oracle.outputs[0].content
        report = _decoded(payload)
        mutants = (
            payload[:-1],
            b" " + payload,
            payload.replace(b'"decision":"success"', b'"decision":"status"', 1),
            payload.replace(b'"status":0', b'"status":1', 1),
            payload.replace(b'"count":5', b'"count":6', 1),
            payload.replace(b'"sum":8', b'"sum":9', 1),
            _BytesSubclass(payload),
        )
        self.assertEqual(report["decision"], "success")
        for mutant in mutants:
            with self.subTest(mutant=mutant[:40]):
                self.assertFalse(
                    pipefail.verify_pipefail_atomic_report_output(
                        success.definition, task.parameters, mutant
                    )
                )
        self.assertFalse(
            pipefail.verify_pipefail_atomic_report_output(
                success.definition, task.parameters, None
            )
        )
        absent_task = self.task("tee-and-reduce", "commit-success-only")
        absent = self.bundle(
            "tee-and-reduce", "commit-success-only", "symlinks-ordering"
        )
        self.assertTrue(
            pipefail.verify_pipefail_atomic_report_output(
                absent.definition, absent_task.parameters, None
            )
        )
        self.assertFalse(
            pipefail.verify_pipefail_atomic_report_output(
                absent.definition, absent_task.parameters, b""
            )
        )

    def test_independent_oracle_disagreement_fails_closed(self) -> None:
        task = self.task("linear-two-stage", "write-status-always")
        profile = _profile("spaces-unicode")
        bundle = self.bundle(
            "linear-two-stage", "write-status-always", "spaces-unicode"
        )
        expected = bundle.oracle.outputs[0].content
        with mock.patch.object(
            pipefail,
            "reference_pipefail_atomic_report_output",
            return_value=expected + b"x",
        ):
            self.assertFalse(
                pipefail.verify_pipefail_atomic_report_output(
                    bundle.definition, task.parameters, expected
                )
            )
            with self.assertRaises(pipefail.PipefailAtomicReportError):
                pipefail.build_pipefail_atomic_report_fixture_bundle(task, profile)

    def test_cross_task_profile_and_authority_tampering_fail_closed(self) -> None:
        task = self.task("linear-two-stage", "write-status-always")
        other_task = self.task("linear-four-stage", "write-status-always")
        profile = _profile("spaces-unicode")
        other_profile = _profile("empty-duplicates")
        bundle = self.bundle(
            "linear-two-stage", "write-status-always", "spaces-unicode"
        )
        self.assertFalse(
            pipefail.verify_pipefail_atomic_report_fixture_for_task_profile(
                other_task, profile, bundle
            )
        )
        self.assertFalse(
            pipefail.verify_pipefail_atomic_report_fixture_for_task_profile(
                task, other_profile, bundle
            )
        )
        with self.assertRaises(pipefail.PipefailAtomicReportError):
            replace(bundle, candidate_execution_authorized=True)
        with self.assertRaises(pipefail.PipefailAtomicReportError):
            replace(bundle, model_selection_eligible=True)
        with self.assertRaises(pipefail.PipefailAtomicReportError):
            replace(bundle, claim_authorized=True)
        with self.assertRaises(pipefail.PipefailAtomicReportError):
            replace(bundle, task_contract_sha256="0" * 64)
        with self.assertRaises(pipefail.PipefailAtomicReportError):
            replace(bundle, fixture_definition_sha256="0" * 64)
        with self.assertRaises(pipefail.PipefailAtomicReportError):
            replace(bundle.oracle, oracle_sha256="0" * 64)
        with self.assertRaises((pipefail.PipefailAtomicReportError, ValueError)):
            replace(bundle.descriptor, fixture_sha256="0" * 64)
        self.assertFalse(pipefail.verify_pipefail_atomic_report_fixture_bundle(object()))

    def test_hostile_exact_types_and_output_policy_mutation_fail_closed(self) -> None:
        with self.assertRaises(pipefail.PipefailAtomicReportError):
            pipefail.PipefailAtomicReportParameters(
                _StringSubclass("linear-two-stage"), "write-status-always"
            )
        with self.assertRaises(pipefail.PipefailAtomicReportError):
            pipefail.PipefailAtomicReportParameters(
                "linear-two-stage", _StringSubclass("write-status-always")
            )
        task = self.task("linear-two-stage", "write-status-always")
        bundle = self.bundle(
            "linear-two-stage", "write-status-always", "spaces-unicode"
        )
        wrong_expected = replace(
            bundle.definition,
            expected_files=(
                ExpectedFile("output/report.json", maximum_bytes=1, mode=0o644),
            ),
        )
        with self.assertRaises(pipefail.PipefailAtomicReportError):
            pipefail.derive_pipefail_atomic_report_output(
                wrong_expected, task.parameters
            )
        absent_task = self.task("linear-two-stage", "commit-success-only")
        absent = self.bundle(
            "linear-two-stage", "commit-success-only", "symlinks-ordering"
        )
        unexpected_report_policy = replace(
            absent.definition,
            expected_files=(
                ExpectedFile("output/report.json", maximum_bytes=64 * 1024, mode=0o644),
            ),
        )
        with self.assertRaises(pipefail.PipefailAtomicReportError):
            pipefail.reference_pipefail_atomic_report_output(
                unexpected_report_policy, absent_task.parameters
            )
        with self.assertRaises(pipefail.PipefailAtomicReportError):
            replace(task, public=False)
        with self.assertRaises(pipefail.PipefailAtomicReportError):
            replace(task, allowed_tools=("awk",))

    def test_randomized_valid_streams_keep_independent_oracles_in_agreement(self) -> None:
        rng = random.Random(0xCBDA70)
        keys = ("alpha", "Bravo", "two words", "βeta", "雪", "zeta")
        for shape in pipefail.PIPEFAIL_ATOMIC_REPORT_PIPELINE_SHAPES:
            task = self.task(shape, "write-status-always")
            base = self.bundle(shape, "write-status-always", "spaces-unicode")
            for iteration in range(100):
                entries = []
                for item in base.definition.inputs:
                    if (
                        type(item) is InputFile
                        and item.path.startswith("input/pipeline/data/")
                    ):
                        rows = []
                        for row_index in range(rng.randrange(0, 12)):
                            rows.append(
                                pipefail._data_row(
                                    rng.choice(("yes", "no")),
                                    rng.choice(keys),
                                    rng.randrange(-25, 26),
                                    f"message {iteration} {row_index}",
                                )
                            )
                        item = replace(item, content=b"".join(rows))
                    entries.append(item)
                definition = replace(base.definition, inputs=tuple(entries))
                primary = pipefail.derive_pipefail_atomic_report_output(
                    definition, task.parameters
                )
                reference = pipefail.reference_pipefail_atomic_report_output(
                    definition, task.parameters
                )
                self.assertEqual(primary, reference)
                self.assertTrue(
                    pipefail.verify_pipefail_atomic_report_output(
                        definition, task.parameters, primary
                    )
                )

    def test_each_single_multi_and_all_stage_failure_vector_keeps_oracles_aligned(
        self,
    ) -> None:
        rng = random.Random(0x51A6E)
        report_policy = (
            ExpectedFile(
                "output/report.json",
                maximum_bytes=64 * 1024,
                mode=0o644,
            ),
        )
        for shape in pipefail.PIPEFAIL_ATOMIC_REPORT_PIPELINE_SHAPES:
            stages = pipefail._STAGES[shape]
            vectors = [(0,) * len(stages)]
            vectors.extend(
                tuple(17 + index if position == index else 0 for position in range(len(stages)))
                for index in range(len(stages))
            )
            vectors.append(
                tuple(31 + index if index in {0, len(stages) - 1} else 0 for index in range(len(stages)))
            )
            vectors.append(tuple(61 + index for index in range(len(stages))))
            self.assertEqual(len(set(vectors)), len(vectors))
            for policy in pipefail.PIPEFAIL_ATOMIC_REPORT_FAILURE_COMMIT_POLICIES:
                task = self.task(shape, policy)
                base = self.bundle(shape, policy, "spaces-unicode")
                for vector in vectors:
                    physical = list(zip(stages, vector, strict=True))
                    rng.shuffle(physical)
                    statuses = b"".join(
                        stage.encode("ascii")
                        + b"\t"
                        + str(code).encode("ascii")
                        + b"\n"
                        for stage, code in physical
                    )
                    definition = _replace_input(
                        base.definition,
                        pipefail.PIPEFAIL_ATOMIC_REPORT_STATUSES,
                        content=statuses,
                    )
                    failure = any(vector)
                    expected_files = (
                        ()
                        if failure and policy == "commit-success-only"
                        else report_policy
                    )
                    definition = replace(
                        definition,
                        expected_files=expected_files,
                    )
                    primary = pipefail.derive_pipefail_atomic_report_output(
                        definition,
                        task.parameters,
                    )
                    reference = pipefail.reference_pipefail_atomic_report_output(
                        definition,
                        task.parameters,
                    )
                    with self.subTest(shape=shape, policy=policy, vector=vector):
                        self.assertEqual(primary, reference)
                        self.assertTrue(
                            pipefail.verify_pipefail_atomic_report_output(
                                definition,
                                task.parameters,
                                primary,
                            )
                        )

    def test_generation_and_verification_never_invoke_a_subprocess(self) -> None:
        task = self.task("fan-in-merge", "preserve-last-failure")
        profile = _profile("partial-permissions")
        bundle = self.bundle(
            "fan-in-merge", "preserve-last-failure", "partial-permissions"
        )
        with mock.patch("subprocess.run", side_effect=AssertionError("process")), mock.patch(
            "subprocess.Popen", side_effect=AssertionError("process")
        ):
            tasks = pipefail.build_pipefail_atomic_report_tasks()
            self.assertEqual(len(tasks), 20)
            rebuilt = pipefail.build_pipefail_atomic_report_fixture_bundle(
                task, profile
            )
            self.assertEqual(rebuilt, bundle)
            self.assertTrue(
                pipefail.verify_pipefail_atomic_report_output(
                    bundle.definition,
                    task.parameters,
                    bundle.oracle.outputs[0].content,
                )
            )

    def test_hash_seed_does_not_change_task_or_fixture_identities(self) -> None:
        script = """
from cbds.executable_pipefail_atomic_report import (
    build_pipefail_atomic_report_fixture_bundle,
    build_pipefail_atomic_report_tasks,
)
from cbds.executable_fixture_profiles import PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
tasks = build_pipefail_atomic_report_tasks()
print('|'.join(task.task_contract_sha256 for task in tasks))
print('|'.join(
    build_pipefail_atomic_report_fixture_bundle(task, profile).descriptor.fixture_sha256
    for task in tasks for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
))
"""
        outputs = []
        for seed in ("0", "1", "17", "999"):
            environment = dict(os.environ)
            environment["PYTHONHASHSEED"] = seed
            environment["PYTHONPATH"] = str(ROOT / "src")
            completed = subprocess.run(
                [sys.executable, "-c", script],
                cwd=ROOT,
                env=environment,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            outputs.append(completed.stdout)
        self.assertEqual(len(set(outputs)), 1)

    def test_all_100_materializations_accept_exact_output_or_exact_absence(self) -> None:
        for task in self.tasks:
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                bundle = self.by_pair[(task.task_id, profile.profile_id)]
                with self.subTest(
                    shape=task.parameters.pipeline_shape,
                    policy=task.parameters.failure_commit_policy,
                    profile=profile.profile_id,
                ), tempfile.TemporaryDirectory() as temporary:
                    workspace = Path(temporary) / "workspace"
                    with pipefail.materialize_pipefail_atomic_report_fixture(
                        task, profile, bundle, workspace
                    ) as handle:
                        _write_expected(workspace, bundle)
                        self.assertTrue(
                            pipefail.verify_pipefail_atomic_report_workspace(
                                task, profile, bundle, handle
                            )
                        )

    def test_workspace_missing_extra_corrupt_symlink_and_input_mutations_fail_closed(self) -> None:
        task = self.task("linear-two-stage", "write-status-always")
        profile = _profile("spaces-unicode")
        bundle = self.bundle(
            "linear-two-stage", "write-status-always", "spaces-unicode"
        )
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "missing"
            with pipefail.materialize_pipefail_atomic_report_fixture(
                task, profile, bundle, workspace
            ) as handle:
                self.assertFalse(
                    pipefail.verify_pipefail_atomic_report_workspace(
                        task, profile, bundle, handle
                    )
                )
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "corrupt"
            with pipefail.materialize_pipefail_atomic_report_fixture(
                task, profile, bundle, workspace
            ) as handle:
                _write_expected(workspace, bundle)
                report = workspace / "output" / "report.json"
                report.write_bytes(bundle.oracle.outputs[0].content + b"x")
                self.assertFalse(
                    pipefail.verify_pipefail_atomic_report_workspace(
                        task, profile, bundle, handle
                    )
                )
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "extra"
            with pipefail.materialize_pipefail_atomic_report_fixture(
                task, profile, bundle, workspace
            ) as handle:
                _write_expected(workspace, bundle)
                (workspace / "output" / "temporary").write_bytes(b"x")
                self.assertFalse(
                    pipefail.verify_pipefail_atomic_report_workspace(
                        task, profile, bundle, handle
                    )
                )
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "symlink"
            with pipefail.materialize_pipefail_atomic_report_fixture(
                task, profile, bundle, workspace
            ) as handle:
                output = workspace / "output"
                output.mkdir(mode=0o755)
                os.symlink("../input/pipeline/prior-report.json", output / "report.json")
                self.assertFalse(
                    pipefail.verify_pipefail_atomic_report_workspace(
                        task, profile, bundle, handle
                    )
                )
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "input-mutant"
            with pipefail.materialize_pipefail_atomic_report_fixture(
                task, profile, bundle, workspace
            ) as handle:
                _write_expected(workspace, bundle)
                source = next(
                    item
                    for item in bundle.definition.inputs
                    if type(item) is InputFile
                    and item.path.startswith("input/pipeline/data/")
                )
                (workspace / source.path).write_bytes(source.content + b"x")
                self.assertFalse(
                    pipefail.verify_pipefail_atomic_report_workspace(
                        task, profile, bundle, handle
                    )
                )
        absent_task = self.task("linear-two-stage", "commit-success-only")
        absent_profile = _profile("symlinks-ordering")
        absent = self.bundle(
            "linear-two-stage", "commit-success-only", "symlinks-ordering"
        )
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "absent-extra-dir"
            with pipefail.materialize_pipefail_atomic_report_fixture(
                absent_task, absent_profile, absent, workspace
            ) as handle:
                (workspace / "output").mkdir()
                self.assertFalse(
                    pipefail.verify_pipefail_atomic_report_workspace(
                        absent_task, absent_profile, absent, handle
                    )
                )

    def test_workspace_rejects_mode_link_size_directory_and_metadata_mutants(
        self,
    ) -> None:
        task = self.task("linear-two-stage", "write-status-always")
        profile = _profile("spaces-unicode")
        bundle = self.bundle(
            "linear-two-stage", "write-status-always", "spaces-unicode"
        )
        source = next(
            item
            for item in bundle.definition.inputs
            if type(item) is InputFile
            and item.path.startswith("input/pipeline/data/")
        )

        def report_mutation(name, mutate) -> None:
            with self.subTest(mutation=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                workspace = root / "workspace"
                with pipefail.materialize_pipefail_atomic_report_fixture(
                    task, profile, bundle, workspace
                ) as handle:
                    _write_expected(workspace, bundle)
                    mutate(root, workspace, workspace / "output" / "report.json")
                    self.assertFalse(
                        pipefail.verify_pipefail_atomic_report_workspace(
                            task, profile, bundle, handle
                        )
                    )

        report_mutation(
            "report-mode",
            lambda _root, _workspace, report: os.chmod(report, 0o600),
        )
        report_mutation(
            "directory-mode",
            lambda _root, workspace, _report: os.chmod(
                workspace / "output", 0o700
            ),
        )
        report_mutation(
            "external-hardlink",
            lambda root, _workspace, report: os.link(report, root / "outside-link"),
        )
        report_mutation(
            "input-external-hardlink",
            lambda root, workspace, _report: os.link(
                workspace / source.path, root / "outside-input-link"
            ),
        )
        report_mutation(
            "top-level-extra",
            lambda _root, workspace, _report: (
                workspace / "top-level-extra"
            ).write_bytes(b"x"),
        )
        report_mutation(
            "report-as-directory",
            lambda _root, _workspace, report: (
                report.unlink(),
                report.mkdir(),
            ),
        )
        report_mutation(
            "oversize",
            lambda _root, _workspace, report: report.write_bytes(
                b"x" * (pipefail.PIPEFAIL_ATOMIC_REPORT_OUTPUT_MAXIMUM_BYTES + 1)
            ),
        )
        report_mutation(
            "truncated",
            lambda _root, _workspace, report: report.write_bytes(
                bundle.oracle.outputs[0].content[:-1]
            ),
        )

        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            with pipefail.materialize_pipefail_atomic_report_fixture(
                task, profile, bundle, workspace
            ) as handle:
                _write_expected(workspace, bundle)
                os.chmod(workspace / source.path, 0o600)
                self.assertFalse(
                    pipefail.verify_pipefail_atomic_report_workspace(
                        task, profile, bundle, handle
                    )
                )
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            with pipefail.materialize_pipefail_atomic_report_fixture(
                task, profile, bundle, workspace
            ) as handle:
                _write_expected(workspace, bundle)
                source_path = workspace / source.path
                observed = source_path.stat()
                os.utime(
                    source_path,
                    ns=(observed.st_atime_ns, observed.st_mtime_ns + 1_000_000),
                )
                self.assertFalse(
                    pipefail.verify_pipefail_atomic_report_workspace(
                        task, profile, bundle, handle
                    )
                )

        link_task = self.task("linear-two-stage", "write-status-always")
        link_profile = _profile("leading-dashes-globs")
        link_bundle = self.bundle(
            "linear-two-stage", "write-status-always", "leading-dashes-globs"
        )
        link = next(
            item
            for item in link_bundle.definition.inputs
            if type(item) is InputSymlink
        )
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            with pipefail.materialize_pipefail_atomic_report_fixture(
                link_task, link_profile, link_bundle, workspace
            ) as handle:
                _write_expected(workspace, link_bundle)
                link_path = workspace / link.path
                link_path.unlink()
                os.symlink("missing-target.tsv", link_path)
                self.assertFalse(
                    pipefail.verify_pipefail_atomic_report_workspace(
                        link_task, link_profile, link_bundle, handle
                    )
                )

    def test_module_has_no_assert_subprocess_or_frozen_registry_write(self) -> None:
        source_path = ROOT / "src" / "cbds" / "executable_pipefail_atomic_report.py"
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(tree)))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        self.assertNotIn("subprocess", imported)
        self.assertNotIn("executable_static_registry", source)
        self.assertNotIn("executable_static_second_registry", source)
        self.assertNotIn("executable_static_third_registry", source)
        self.assertNotIn("executable_static_fourth_registry", source)
        self.assertNotIn("candidate_execution_authorized=True", source)


if __name__ == "__main__":
    unittest.main()
