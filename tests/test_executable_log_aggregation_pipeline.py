from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import cbds.executable_log_aggregation_pipeline as pipeline  # noqa: E402
from cbds.executable_fixture_bundle import OracleOutputRecord  # noqa: E402
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from cbds.executable_log_aggregation_pipeline import (  # noqa: E402
    LOG_AGGREGATION_DIRECTORY_PERMISSION_ERRORS_COVERED,
    LOG_AGGREGATION_EFFECTIVE_ACCESS_FAILURES_COVERED,
    LOG_AGGREGATION_GENERATOR_VERSION,
    LOG_AGGREGATION_MALFORMED_BYTES_COVERED,
    LOG_AGGREGATION_MALFORMED_POLICIES,
    LOG_AGGREGATION_MODE_UNREADABLE_LEAVES_COVERED,
    LOG_AGGREGATION_OUTPUT,
    LOG_AGGREGATION_SEVERITY_ERES,
    LOG_AGGREGATION_SYMLINKS_COVERED,
    LOG_AGGREGATION_UNTERMINATED_ROWS_COVERED,
    LOG_AGGREGATION_VERIFIER_IDENTITY,
    LOG_AGGREGATION_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE,
    LOG_AGGREGATION_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE,
    LogAggregationFixtureBundle,
    LogAggregationOracle,
    LogAggregationParameters,
    LogAggregationPipelineError,
    build_log_aggregation_fixture_bundle,
    build_log_aggregation_tasks,
    derive_log_aggregation_output,
    materialize_log_aggregation_fixture,
    reference_log_aggregation_output,
    validate_log_aggregation_fixture_bundle,
    validate_log_aggregation_fixture_for_task_profile,
    verify_log_aggregation_fixture_bundle,
    verify_log_aggregation_fixture_for_task_profile,
    verify_log_aggregation_output,
    verify_log_aggregation_workspace,
)
from cbds.executable_workspace import (  # noqa: E402
    ExpectedFile,
    FixtureDefinition,
    InputFile,
    InputSymlink,
)


def _profile(profile_id: str):
    return next(
        item
        for item in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        if item.profile_id == profile_id
    )


class _StringSubclass(str):
    pass


class _BytesSubclass(bytes):
    pass


class LogAggregationPipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tasks = build_log_aggregation_tasks()
        cls.by_pair = {
            (task.task_id, profile.profile_id):
            build_log_aggregation_fixture_bundle(task, profile)
            for task in cls.tasks
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        }

    def task(self, severity_ere: str, malformed_policy: str):
        return next(
            item
            for item in self.tasks
            if item.parameters.severity_ere == severity_ere
            and item.parameters.malformed_policy == malformed_policy
        )

    def bundle(self, severity_ere: str, malformed_policy: str, profile_id: str):
        task = self.task(severity_ere, malformed_policy)
        return self.by_pair[(task.task_id, profile_id)]

    def test_grid_is_twenty_unique_staged_nonauthorizing_tasks(self) -> None:
        self.assertEqual(LOG_AGGREGATION_GENERATOR_VERSION, "1.0.0")
        self.assertEqual(len(self.tasks), 20)
        self.assertEqual(
            {
                (task.parameters.severity_ere, task.parameters.malformed_policy)
                for task in self.tasks
            },
            {
                (expression, policy)
                for expression in LOG_AGGREGATION_SEVERITY_ERES
                for policy in LOG_AGGREGATION_MALFORMED_POLICIES
            },
        )
        self.assertEqual(len({task.task_id for task in self.tasks}), 20)
        self.assertEqual(len({task.task_contract_sha256 for task in self.tasks}), 20)
        self.assertEqual(len({task.graph_sha256 for task in self.tasks}), 20)
        self.assertEqual(build_log_aggregation_tasks(), self.tasks)
        for task in self.tasks:
            task.__post_init__()
            self.assertIs(task.public, True)
            self.assertIs(task.sealed, False)
            self.assertIs(task.candidate_execution_authorized, False)
            self.assertIs(task.model_selection_eligible, False)
            self.assertIs(task.claim_authorized, False)
            self.assertEqual(len(task.fixtures), 5)
            self.assertEqual(
                task.fixtures,
                tuple(
                    self.by_pair[(task.task_id, profile.profile_id)].descriptor
                    for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
                ),
            )
            record = task.to_public_record()
            self.assertEqual(record["family_id"], "regex-log-group-aggregation")
            self.assertEqual(record["parameters"], task.parameters.to_record())
            self.assertIs(record["candidate_execution_authorized"], False)
            self.assertIs(record["model_selection_eligible"], False)
            self.assertIs(record["claim_authorized"], False)

    def test_all_one_hundred_bundles_are_deterministic_and_authenticated(self) -> None:
        self.assertEqual(len(self.by_pair), 100)
        self.assertEqual(
            len({bundle.descriptor.fixture_id for bundle in self.by_pair.values()}),
            100,
        )
        for task in self.tasks:
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                with self.subTest(
                    ere=task.parameters.severity_ere,
                    policy=task.parameters.malformed_policy,
                    profile=profile.profile_id,
                ):
                    bundle = self.by_pair[(task.task_id, profile.profile_id)]
                    validate_log_aggregation_fixture_bundle(bundle)
                    self.assertTrue(verify_log_aggregation_fixture_bundle(bundle))
                    validate_log_aggregation_fixture_for_task_profile(
                        task, profile, bundle
                    )
                    self.assertTrue(
                        verify_log_aggregation_fixture_for_task_profile(
                            task, profile, bundle
                        )
                    )
                    self.assertEqual(
                        build_log_aggregation_fixture_bundle(task, profile), bundle
                    )
                    primary = derive_log_aggregation_output(
                        bundle.definition, task.parameters
                    )
                    reference = reference_log_aggregation_output(
                        bundle.definition, task.parameters
                    )
                    self.assertEqual(primary, reference)
                    self.assertEqual(bundle.oracle.outputs[0].content, primary)
                    self.assertEqual(
                        bundle.oracle.semantic_verifier_identity,
                        LOG_AGGREGATION_VERIFIER_IDENTITY,
                    )
                    self.assertEqual(
                        bundle.definition.expected_files,
                        (ExpectedFile(LOG_AGGREGATION_OUTPUT, len(primary), 0o644),),
                    )
                    self.assertIs(bundle.candidate_execution_authorized, False)
                    self.assertIs(bundle.model_selection_eligible, False)
                    self.assertIs(bundle.claim_authorized, False)

    def test_five_malformed_policies_have_hand_checked_distinct_results(self) -> None:
        expected = {
            "skip-row": b"repeat\t3\t9\ntail\t2\t2\n",
            "stop-file": b"repeat\t3\t9\ntail\t1\t2\n",
            "reject-file": b"tail\t1\t2\n",
            "reject-all": b"",
            "count-malformed": (
                b"!malformed\t1\t0\nrepeat\t3\t9\ntail\t2\t2\n"
            ),
        }
        observed = {
            policy: self.bundle(
                "^(INFO|WARN|ERROR)$", policy, "empty-duplicates"
            ).oracle.outputs[0].content
            for policy in LOG_AGGREGATION_MALFORMED_POLICIES
        }
        self.assertEqual(observed, expected)
        self.assertEqual(len(set(observed.values())), 5)

    def test_four_closed_eres_have_distinct_full_match_semantics(self) -> None:
        definition = FixtureDefinition(
            fixture_id="fixture.regex.reference",
            inputs=(
                InputFile(
                    "input/logs/one.log",
                    b"ERROR\te\t1\tm\n"
                    b"WARN\tw\t2\tm\n"
                    b"INFO\ti\t3\tm\n"
                    b"ABCD\ta\t4\tm\n"
                    b"DEBUG\td\t5\tm\n",
                    0o644,
                ),
            ),
            expected_files=(ExpectedFile(LOG_AGGREGATION_OUTPUT, 1024, 0o644),),
        )
        expected = {
            "^ERROR$": b"e\t1\t1\n",
            "^(WARN|ERROR)$": b"e\t1\t1\nw\t1\t2\n",
            "^[A-Z]{4}$": b"a\t1\t4\ni\t1\t3\nw\t1\t2\n",
            "^(INFO|WARN|ERROR)$": b"e\t1\t1\ni\t1\t3\nw\t1\t2\n",
        }
        for expression, output in expected.items():
            parameters = LogAggregationParameters(expression, "skip-row")
            self.assertEqual(
                derive_log_aggregation_output(definition, parameters), output
            )
            self.assertEqual(
                reference_log_aggregation_output(definition, parameters), output
            )

    def test_profiles_realize_declared_edge_cases_and_honest_limits(self) -> None:
        representative = self.task("^ERROR$", "skip-row")
        definitions = {
            profile.profile_id: self.by_pair[
                (representative.task_id, profile.profile_id)
            ].definition
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        }
        spaces = definitions["spaces-unicode"].inputs
        self.assertTrue(any(" " in item.path for item in spaces))
        self.assertTrue(
            any(any(ord(character) > 127 for character in item.path) for item in spaces)
        )
        self.assertTrue(
            any(
                type(item) is InputFile and b"\xff" in item.content
                for item in spaces
            )
        )
        self.assertTrue(
            any(item.path == "input/outside/out-of-root.log" for item in spaces)
        )
        spaces_bytes = b"".join(
            item.content for item in spaces if type(item) is InputFile
        )
        for malformed in (
            b"ERROR\t\t1\tempty group\n",
            b"ERROR\t!reserved\t1\treserved group\n",
            b"ERROR\tnul\0group\t1\tNUL group\n",
            b"ERROR\tbad-group-utf8-\xff\t1\tinvalid group\n",
            b"ERROR\tmessage-nul\t1\tbad\0message\n",
        ):
            self.assertIn(malformed, spaces_bytes)
        self.assertEqual(
            self.bundle(
                "^ERROR$", "count-malformed", "spaces-unicode"
            ).oracle.outputs[0].content,
            "!malformed\t7\t0\nalpha team\t1\t3\nβeta\t1\t7\n".encode(
                "utf-8"
            ),
        )

        leading = definitions["leading-dashes-globs"].inputs
        self.assertTrue(
            any(PurePosixPath(item.path).name.startswith("-") for item in leading)
        )
        self.assertTrue(
            any(any(mark in item.path for mark in "*?[]") for item in leading)
        )
        leading_bytes = b"".join(
            item.content for item in leading if type(item) is InputFile
        )
        self.assertIn(b"ERROR\textra-tab\t1\ttoo\tmany\n", leading_bytes)
        self.assertIn(b"XERROR\tnear-match\t6\tnot ERROR\n", leading_bytes)
        self.assertNotIn(
            b"near-match",
            self.bundle(
                "^ERROR$", "skip-row", "leading-dashes-globs"
            ).oracle.outputs[0].content,
        )

        empty = definitions["empty-duplicates"].inputs
        self.assertTrue(
            any(type(item) is InputFile and item.content == b"" for item in empty)
        )
        duplicate_content = next(
            item.content
            for item in empty
            if type(item) is InputFile and item.path.endswith("duplicates.log")
        )
        self.assertGreaterEqual(duplicate_content.count(b"ERROR\trepeat\t5\tsame\n"), 2)

        ordering = definitions["symlinks-ordering"].inputs
        self.assertNotEqual(
            [item.path for item in ordering],
            sorted((item.path for item in ordering), key=str.encode),
        )
        self.assertTrue(any(type(item) is InputSymlink for item in ordering))
        self.assertTrue(
            any(
                type(item) is InputFile
                and item.content
                and not item.content.endswith(b"\n")
                for item in ordering
            )
        )

        partial = definitions["partial-permissions"].inputs
        modes = {item.mode for item in partial if type(item) is InputFile}
        self.assertTrue({0o000, 0o004, 0o040, 0o400, 0o111} <= modes)
        self.assertIs(LOG_AGGREGATION_MALFORMED_BYTES_COVERED, True)
        self.assertIs(LOG_AGGREGATION_UNTERMINATED_ROWS_COVERED, True)
        self.assertIs(LOG_AGGREGATION_SYMLINKS_COVERED, True)
        self.assertIs(LOG_AGGREGATION_MODE_UNREADABLE_LEAVES_COVERED, True)
        self.assertIs(LOG_AGGREGATION_DIRECTORY_PERMISSION_ERRORS_COVERED, False)
        self.assertIs(LOG_AGGREGATION_EFFECTIVE_ACCESS_FAILURES_COVERED, False)
        self.assertIs(
            LOG_AGGREGATION_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE,
            True,
        )
        self.assertIs(
            LOG_AGGREGATION_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE,
            False,
        )

    def test_mode_bits_suffix_and_symlinks_are_semantically_enforced(self) -> None:
        task = self.task("^ERROR$", "skip-row")
        partial = self.by_pair[(task.task_id, "partial-permissions")]
        self.assertEqual(
            partial.oracle.outputs[0].content,
            b"other\t1\t5\nvisible\t1\t4\n",
        )
        self.assertNotIn(b"hidden", partial.oracle.outputs[0].content)

        spaces = self.by_pair[(task.task_id, "spaces-unicode")]
        self.assertTrue(
            any(type(item) is InputSymlink for item in spaces.definition.inputs)
        )
        self.assertEqual(
            spaces.oracle.outputs[0].content,
            "alpha team\t1\t3\nβeta\t1\t7\n".encode("utf-8"),
        )
        self.assertNotIn(b"not selected", spaces.oracle.outputs[0].content)

    def test_partial_permission_strategy_is_feasible_and_exactly_restored(self) -> None:
        task = self.task("^(INFO|WARN|ERROR)$", "skip-row")
        profile = _profile("partial-permissions")
        bundle = self.by_pair[(task.task_id, profile.profile_id)]
        self.assertIn("chmod", task.allowed_tools)
        self.assertEqual(
            bundle.oracle.outputs[0].content,
            b"other\t2\t7\nvisible\t2\t7\n",
        )
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            with materialize_log_aggregation_fixture(
                task, profile, bundle, workspace
            ) as handle:
                readable = {
                    0o040: workspace / "input/logs/group-readable.log",
                    0o004: workspace / "input/logs/other-readable.log",
                }
                observed_payloads: dict[int, bytes] = {}
                for original_mode, path in readable.items():
                    self.assertEqual(
                        stat.S_IMODE(path.stat(follow_symlinks=False).st_mode),
                        original_mode,
                    )
                    if os.geteuid() != 0:
                        with self.assertRaises(PermissionError):
                            path.read_bytes()
                    try:
                        os.chmod(path, original_mode | stat.S_IRUSR)
                        observed_payloads[original_mode] = path.read_bytes()
                    finally:
                        os.chmod(path, original_mode)
                    self.assertEqual(
                        stat.S_IMODE(path.stat(follow_symlinks=False).st_mode),
                        original_mode,
                    )
                    if os.geteuid() != 0:
                        with self.assertRaises(PermissionError):
                            path.read_bytes()
                self.assertIn(
                    b"ERROR\tvisible\t4\tgroup read\n",
                    observed_payloads[0o040],
                )
                self.assertIn(b"INFO\tother\t2\tother read\n", observed_payloads[0o004])

                excluded = {
                    workspace / "input/logs/permission-denied.log": 0o000,
                    workspace / "input/logs/executable-unreadable.log": 0o111,
                }
                for path, original_mode in excluded.items():
                    self.assertEqual(
                        stat.S_IMODE(path.stat(follow_symlinks=False).st_mode),
                        original_mode,
                    )
                self.assertNotIn(b"hidden", bundle.oracle.outputs[0].content)

                output = workspace / "output"
                output.mkdir(mode=0o755)
                os.chmod(output, 0o755)
                summary = output / "summary.tsv"
                summary.write_bytes(bundle.oracle.outputs[0].content)
                os.chmod(summary, 0o644)
                self.assertTrue(
                    verify_log_aggregation_workspace(
                        task, profile, bundle, handle
                    )
                )

    def test_verifier_rejects_byte_and_structured_output_mutants(self) -> None:
        killed = 0
        for task in self.tasks:
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                bundle = self.by_pair[(task.task_id, profile.profile_id)]
                expected = bundle.oracle.outputs[0].content
                mutants = {
                    expected + b"x",
                    expected[:-1] if expected else b"spurious\n",
                    b"spurious\t1\t0\n" + expected,
                }
                if expected:
                    flipped = bytearray(expected)
                    flipped[len(flipped) // 2] ^= 1
                    mutants.add(bytes(flipped))
                for mutant in mutants:
                    if mutant != expected:
                        self.assertFalse(
                            verify_log_aggregation_output(
                                bundle.definition, task.parameters, mutant
                            )
                        )
                        killed += 1
                self.assertFalse(
                    verify_log_aggregation_output(
                        bundle.definition, task.parameters, bytearray(expected)
                    )
                )
        self.assertGreaterEqual(killed, 300)

    def test_independent_reference_is_a_required_fail_closed_gate(self) -> None:
        task = self.task("^ERROR$", "skip-row")
        profile = _profile("spaces-unicode")
        bundle = self.by_pair[(task.task_id, profile.profile_id)]
        expected = bundle.oracle.outputs[0].content
        self.assertNotEqual(expected, b"corrupt")
        with mock.patch.object(
            pipeline,
            "derive_log_aggregation_output",
            return_value=b"corrupt",
        ):
            self.assertFalse(
                verify_log_aggregation_output(
                    bundle.definition, task.parameters, expected
                )
            )
            with self.assertRaisesRegex(
                LogAggregationPipelineError, "implementations disagree"
            ):
                build_log_aggregation_fixture_bundle(task, profile)
        with mock.patch.object(
            pipeline,
            "reference_log_aggregation_output",
            return_value=b"corrupt",
        ):
            self.assertFalse(
                verify_log_aggregation_output(
                    bundle.definition, task.parameters, expected
                )
            )

    def test_bundle_mutations_and_cross_profile_substitution_are_rejected(self) -> None:
        task = self.task("^(WARN|ERROR)$", "reject-file")
        spaces = _profile("spaces-unicode")
        leading = _profile("leading-dashes-globs")
        bundle = self.by_pair[(task.task_id, spaces.profile_id)]
        self.assertFalse(
            verify_log_aggregation_fixture_for_task_profile(task, leading, bundle)
        )

        mutated_output = OracleOutputRecord(
            LOG_AGGREGATION_OUTPUT,
            bundle.oracle.outputs[0].content + b"mutant\t1\t0\n",
            0o644,
        )
        object.__setattr__(bundle.oracle, "outputs", (mutated_output,))
        self.assertFalse(verify_log_aggregation_fixture_bundle(bundle))
        # Restore shared class fixture before testing deterministic authentication.
        object.__setattr__(
            bundle.oracle,
            "outputs",
            build_log_aggregation_fixture_bundle(task, spaces).oracle.outputs,
        )
        validate_log_aggregation_fixture_for_task_profile(task, spaces, bundle)

        with self.assertRaises(LogAggregationPipelineError):
            replace(
                bundle,
                profile_sha256=leading.profile_sha256,
                descriptor=self.by_pair[
                    (task.task_id, leading.profile_id)
                ].descriptor,
            )

        forged_task = replace(
            task,
            fixtures=(
                task.fixtures[1],
                task.fixtures[0],
                *task.fixtures[2:],
            ),
        )
        forged_task.__post_init__()
        with self.assertRaisesRegex(
            LogAggregationPipelineError,
            "generated descriptor differs",
        ):
            build_log_aggregation_fixture_bundle(forged_task, spaces)

    def test_exact_type_checks_reject_scalar_and_container_subclasses(self) -> None:
        with self.assertRaises(LogAggregationPipelineError):
            LogAggregationParameters(_StringSubclass("^ERROR$"), "skip-row")
        with self.assertRaises(LogAggregationPipelineError):
            LogAggregationParameters("^ERROR$", _StringSubclass("skip-row"))
        task = self.task("^ERROR$", "skip-row")
        with self.assertRaises(LogAggregationPipelineError):
            replace(
                task,
                allowed_tools=(
                    _StringSubclass(task.allowed_tools[0]),
                    *task.allowed_tools[1:],
                ),
            )
        profile = _profile("spaces-unicode")
        bundle = self.by_pair[(task.task_id, profile.profile_id)]
        malicious_file = InputFile("input/logs/exact.log", b"ERROR\tx\t1\tm\n")
        object.__setattr__(
            malicious_file,
            "content",
            _BytesSubclass(malicious_file.content),
        )
        malicious_definition = FixtureDefinition(
            fixture_id="fixture.exact.types",
            inputs=(InputFile("input/logs/safe.log", b"ERROR\tx\t1\tm\n"),),
            expected_files=(ExpectedFile(LOG_AGGREGATION_OUTPUT, 64, 0o644),),
        )
        object.__setattr__(malicious_definition, "inputs", (malicious_file,))
        self.assertFalse(
            verify_log_aggregation_output(
                malicious_definition, task.parameters, bundle.oracle.outputs[0].content
            )
        )
        copied_profile = replace(profile)
        object.__setattr__(
            copied_profile, "profile_id", _StringSubclass(profile.profile_id)
        )
        self.assertFalse(
            verify_log_aggregation_fixture_for_task_profile(
                task, copied_profile, bundle
            )
        )
        self.assertFalse(verify_log_aggregation_fixture_bundle(object()))

    def test_authenticated_materialization_uses_safe_workspace_facade(self) -> None:
        task = self.task("^ERROR$", "skip-row")
        profile = _profile("symlinks-ordering")
        bundle = self.by_pair[(task.task_id, profile.profile_id)]
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            with materialize_log_aggregation_fixture(
                task, profile, bundle, workspace
            ) as handle:
                scan = handle.scan_inputs()
                observed = {entry.path: entry for entry in scan.entries}
                self.assertEqual(
                    observed["input/logs/00-duplicate.log"].kind, "symlink"
                )
                self.assertEqual(
                    observed["input/logs/00-duplicate.log"].symlink_target,
                    "z-last.log",
                )
                self.assertEqual(observed["input/logs/z-last.log"].kind, "file")
                self.assertFalse((workspace / "output" / "summary.tsv").exists())
                self.assertEqual(
                    handle.baseline.fixture_id,
                    bundle.definition.fixture_id,
                )

    def test_workspace_verifier_accepts_only_exact_preserved_tree(self) -> None:
        task = self.task("^ERROR$", "skip-row")
        profile = _profile("symlinks-ordering")
        bundle = self.by_pair[(task.task_id, profile.profile_id)]

        def populate_correct_output(workspace: Path) -> None:
            output = workspace / "output"
            output.mkdir(mode=0o755)
            os.chmod(output, 0o755)
            summary = output / "summary.tsv"
            summary.write_bytes(bundle.oracle.outputs[0].content)
            os.chmod(summary, 0o644)

        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "passing"
            with materialize_log_aggregation_fixture(
                task, profile, bundle, workspace
            ) as handle:
                populate_correct_output(workspace)
                self.assertTrue(
                    verify_log_aggregation_workspace(
                        task, profile, bundle, handle
                    )
                )
            self.assertFalse(
                verify_log_aggregation_workspace(task, profile, bundle, handle)
            )

        def mutate_input_bytes(workspace: Path, _temporary: Path) -> None:
            path = workspace / "input/logs/a-first.log"
            path.write_bytes(path.read_bytes() + b"ERROR\tmutant\t1\tm\n")

        def mutate_input_mode(workspace: Path, _temporary: Path) -> None:
            os.chmod(workspace / "input/logs/a-first.log", 0o600)

        def mutate_input_mtime(workspace: Path, _temporary: Path) -> None:
            path = workspace / "input/logs/a-first.log"
            metadata = path.stat(follow_symlinks=False)
            os.utime(
                path,
                ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000),
                follow_symlinks=False,
            )

        def add_external_input_hard_link(
            workspace: Path,
            temporary: Path,
        ) -> None:
            os.link(
                workspace / "input/logs/a-first.log",
                temporary / "input-outside-link",
            )

        def add_extra_input(workspace: Path, _temporary: Path) -> None:
            (workspace / "input/logs/extra.log").write_bytes(
                b"ERROR\textra\t1\textra\n"
            )

        def remove_input(workspace: Path, _temporary: Path) -> None:
            (workspace / "input/logs/a-first.log").unlink()

        def mutate_input_symlink(workspace: Path, _temporary: Path) -> None:
            path = workspace / "input/logs/00-duplicate.log"
            path.unlink()
            path.symlink_to("a-first.log")

        def add_extra_output(workspace: Path, _temporary: Path) -> None:
            (workspace / "output/extra.txt").write_bytes(b"extra")

        def replace_output_with_symlink(workspace: Path, _temporary: Path) -> None:
            path = workspace / "output/summary.tsv"
            path.unlink()
            path.symlink_to("../../input/logs/a-first.log")

        def add_external_hard_link(workspace: Path, temporary: Path) -> None:
            os.link(workspace / "output/summary.tsv", temporary / "outside-link")

        def mutate_output_mode(workspace: Path, _temporary: Path) -> None:
            os.chmod(workspace / "output/summary.tsv", 0o600)

        def mutate_output_bytes(workspace: Path, _temporary: Path) -> None:
            (workspace / "output/summary.tsv").write_bytes(b"wrong\t1\t0\n")

        def mutate_output_directory_mode(workspace: Path, _temporary: Path) -> None:
            os.chmod(workspace / "output", 0o700)

        mutations = (
            ("input-content", mutate_input_bytes),
            ("input-mode", mutate_input_mode),
            ("input-mtime", mutate_input_mtime),
            ("input-hardlink", add_external_input_hard_link),
            ("input-extra", add_extra_input),
            ("input-missing", remove_input),
            ("input-symlink", mutate_input_symlink),
            ("extra-output", add_extra_output),
            ("output-symlink", replace_output_with_symlink),
            ("output-hardlink", add_external_hard_link),
            ("output-mode", mutate_output_mode),
            ("output-bytes", mutate_output_bytes),
            ("output-directory-mode", mutate_output_directory_mode),
        )
        for name, mutation in mutations:
            with self.subTest(mutation=name):
                with tempfile.TemporaryDirectory() as temporary:
                    temporary_path = Path(temporary)
                    workspace = temporary_path / "workspace"
                    with materialize_log_aggregation_fixture(
                        task, profile, bundle, workspace
                    ) as handle:
                        populate_correct_output(workspace)
                        mutation(workspace, temporary_path)
                        self.assertFalse(
                            verify_log_aggregation_workspace(
                                task, profile, bundle, handle
                            )
                        )

    def test_generation_and_verification_never_invoke_a_process(self) -> None:
        with mock.patch.object(
            subprocess, "run", side_effect=AssertionError("run invoked")
        ), mock.patch.object(
            subprocess, "Popen", side_effect=AssertionError("Popen invoked")
        ), mock.patch.object(
            os, "system", side_effect=AssertionError("system invoked")
        ), mock.patch.object(
            os, "popen", side_effect=AssertionError("popen invoked")
        ):
            tasks = build_log_aggregation_tasks()
            for task in tasks:
                for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                    bundle = build_log_aggregation_fixture_bundle(task, profile)
                    self.assertTrue(
                        verify_log_aggregation_output(
                            bundle.definition,
                            task.parameters,
                            bundle.oracle.outputs[0].content,
                        )
                    )

    def test_module_has_no_assert_statement_or_shared_registry_writes(self) -> None:
        source = (ROOT / "src/cbds/executable_log_aggregation_pipeline.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("assert ", source)
        self.assertNotIn("subprocess", source)
        self.assertNotIn("executable_static_registry", source)
        self.assertNotIn("executable_fixture_catalog", source)
        self.assertNotIn("development_invocation", source)


if __name__ == "__main__":
    unittest.main()
