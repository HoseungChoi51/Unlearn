from __future__ import annotations

from dataclasses import replace
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
    COMPOUND_PATH_EXPRESSIONS,
    COMPOUND_PATH_NAME_PATTERNS,
    COMPOUND_PATH_DIRECTORY_PERMISSION_ERRORS_COVERED,
    COMPOUND_PATH_QUERY_GENERATOR_VERSION,
    COMPOUND_PATH_QUERY_OUTPUT,
    COMPOUND_PATH_QUERY_VERIFIER_IDENTITY,
    CompoundPathQueryError,
    CompoundPathQueryParameters,
    build_compound_path_query_fixture_bundle,
    build_compound_path_query_tasks,
    derive_compound_path_query_output,
    validate_compound_path_query_fixture_bundle,
    validate_compound_path_query_fixture_for_task_profile,
    verify_compound_path_query_fixture_bundle,
    verify_compound_path_query_fixture_for_task_profile,
    verify_compound_path_query_output,
)
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from cbds.executable_workspace import (  # noqa: E402
    ExpectedFile,
    FixtureDefinition,
    InputFile,
    InputSymlink,
    materialize_fixture,
)


def _profile(profile_id: str):
    return next(
        item
        for item in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        if item.profile_id == profile_id
    )


def _independent_pattern(name: str, pattern: str) -> bool:
    # A deliberately separate regular-expression realization of the four
    # frozen GNU-find-style basename patterns.
    expressions = {
        "*.txt": r".*\.txt",
        "report-*": r"report-.*",
        "[a-z]*.log": r"[a-z].*\.log",
        "*.[0-9]": r".*\.[0-9]",
    }
    import re

    return re.fullmatch(expressions[pattern], name, flags=re.ASCII) is not None


def independently_derive_output(
    definition: FixtureDefinition,
    parameters: CompoundPathQueryParameters,
) -> bytes:
    selected: list[str] = []
    for item in definition.inputs:
        path = PurePosixPath(item.path)
        if path.parts[:2] != ("input", "query") or len(path.parts) < 3:
            continue
        relative = PurePosixPath(*path.parts[2:])
        regular = type(item) is InputFile
        link = type(item) is InputSymlink
        readable = regular and (item.mode & 0o444) != 0
        executable = regular and (item.mode & 0o111) != 0
        named = _independent_pattern(relative.name, parameters.name_pattern)
        truth_table = {
            "readable-regular-and-name": readable and named,
            "readable-regular-and-not-name": readable and not named,
            "readable-regular-and-name-or-symlink": (
                readable and named
            ) or link,
            "readable-regular-and-name-or-executable": readable
            and (named or executable),
            "readable-regular-and-name-depth-at-most-three": readable
            and named
            and len(relative.parts) <= 3,
        }
        if truth_table[parameters.expression]:
            selected.append(relative.as_posix())
    return b"".join(
        item.encode("utf-8") + b"\n"
        for item in sorted(selected, key=lambda value: value.encode("utf-8"))
    )


def _output_lines(content: bytes) -> tuple[str, ...]:
    if not content:
        return ()
    if not content.endswith(b"\n"):
        raise ValueError("output lacks final LF")
    return tuple(line.decode("utf-8") for line in content[:-1].split(b"\n"))


class CompoundPathQueryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tasks = build_compound_path_query_tasks()
        cls.by_pair = {
            (task.task_id, profile.profile_id):
            build_compound_path_query_fixture_bundle(task, profile)
            for task in cls.tasks
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        }

    def task(self, pattern: str, expression: str):
        return next(
            item
            for item in self.tasks
            if item.parameters.name_pattern == pattern
            and item.parameters.expression == expression
        )

    def bundle(self, pattern: str, expression: str, profile_id: str):
        task = self.task(pattern, expression)
        return self.by_pair[(task.task_id, profile_id)]

    def test_grid_has_exactly_twenty_hash_bound_nonauthorizing_tasks(self) -> None:
        self.assertEqual(COMPOUND_PATH_QUERY_GENERATOR_VERSION, "1.0.0")
        self.assertEqual(len(self.tasks), 20)
        self.assertEqual(
            {
                (
                    task.parameters.name_pattern,
                    task.parameters.expression,
                )
                for task in self.tasks
            },
            {
                (pattern, expression)
                for pattern in COMPOUND_PATH_NAME_PATTERNS
                for expression in COMPOUND_PATH_EXPRESSIONS
            },
        )
        self.assertEqual(len({task.task_id for task in self.tasks}), 20)
        self.assertEqual(
            len({task.task_contract_sha256 for task in self.tasks}), 20
        )
        self.assertEqual(len({task.graph_sha256 for task in self.tasks}), 20)
        self.assertEqual(build_compound_path_query_tasks(), self.tasks)

        for task in self.tasks:
            with self.subTest(task=task.task_id):
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
                public = task.to_public_record()
                self.assertEqual(public["family_id"], "compound-path-query")
                self.assertEqual(public["parameters"], task.parameters.to_record())
                self.assertIs(public["public"], True)
                self.assertIs(public["sealed"], False)
                self.assertIs(public["claim_authorized"], False)

    def test_all_one_hundred_bundles_are_unique_deterministic_and_independent(self) -> None:
        self.assertEqual(len(self.by_pair), 100)
        self.assertEqual(
            len({bundle.descriptor.fixture_id for bundle in self.by_pair.values()}),
            100,
        )
        for task in self.tasks:
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                with self.subTest(
                    pattern=task.parameters.name_pattern,
                    expression=task.parameters.expression,
                    profile=profile.profile_id,
                ):
                    bundle = self.by_pair[(task.task_id, profile.profile_id)]
                    validate_compound_path_query_fixture_bundle(bundle)
                    self.assertTrue(
                        verify_compound_path_query_fixture_bundle(bundle)
                    )
                    validate_compound_path_query_fixture_for_task_profile(
                        task,
                        profile,
                        bundle,
                    )
                    self.assertTrue(
                        verify_compound_path_query_fixture_for_task_profile(
                            task,
                            profile,
                            bundle,
                        )
                    )
                    self.assertEqual(
                        build_compound_path_query_fixture_bundle(task, profile),
                        bundle,
                    )
                    self.assertEqual(
                        bundle.task_contract_sha256,
                        task.task_contract_sha256,
                    )
                    self.assertEqual(bundle.profile_sha256, profile.profile_sha256)
                    self.assertEqual(
                        bundle.oracle.semantic_verifier_identity,
                        COMPOUND_PATH_QUERY_VERIFIER_IDENTITY,
                    )
                    output = bundle.oracle.outputs[0]
                    independent = independently_derive_output(
                        bundle.definition,
                        task.parameters,
                    )
                    self.assertEqual(output.content, independent)
                    self.assertEqual(output.path, COMPOUND_PATH_QUERY_OUTPUT)
                    self.assertEqual(output.mode, 0o644)
                    self.assertEqual(
                        bundle.definition.expected_files,
                        (
                            ExpectedFile(
                                COMPOUND_PATH_QUERY_OUTPUT,
                                maximum_bytes=len(independent),
                                mode=0o644,
                            ),
                        ),
                    )
                    self.assertEqual(
                        _output_lines(output.content),
                        tuple(
                            sorted(
                                _output_lines(output.content),
                                key=lambda value: value.encode("utf-8"),
                            )
                        ),
                    )
                    self.assertIs(bundle.candidate_execution_authorized, False)
                    self.assertIs(bundle.model_selection_eligible, False)
                    self.assertIs(bundle.claim_authorized, False)

    def test_profiles_contain_concrete_compound_path_edge_evidence(self) -> None:
        representative = self.task("*.txt", "readable-regular-and-name")
        definitions = {
            profile.profile_id: self.by_pair[
                (representative.task_id, profile.profile_id)
            ].definition
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        }
        for profile_id, definition in definitions.items():
            with self.subTest(profile=profile_id):
                files = tuple(
                    item for item in definition.inputs if type(item) is InputFile
                )
                links = tuple(
                    item for item in definition.inputs if type(item) is InputSymlink
                )
                self.assertGreaterEqual(len(links), 2)
                self.assertTrue(any(item.mode & 0o444 for item in files))
                self.assertTrue(any(item.mode == 0 for item in files))
                self.assertTrue(
                    any(item.mode & 0o111 and item.mode & 0o444 for item in files)
                )
                self.assertTrue(
                    any(item.mode & 0o111 and not item.mode & 0o444 for item in files)
                )
                self.assertTrue(
                    any(
                        len(PurePosixPath(item.path).parts[2:]) == 4
                        for item in files
                        if PurePosixPath(item.path).parts[:2] == ("input", "query")
                    )
                )
                self.assertTrue(
                    any(item.path.startswith("input/outside/") for item in files)
                )

        spaces = definitions["spaces-unicode"].inputs
        self.assertTrue(any(" " in item.path for item in spaces))
        self.assertTrue(
            any(any(ord(character) > 127 for character in item.path) for item in spaces)
        )

        leading = definitions["leading-dashes-globs"].inputs
        self.assertTrue(
            any(
                PurePosixPath(item.path).name.startswith("-")
                for item in leading
            )
        )
        self.assertTrue(
            any(any(mark in item.path for mark in "*?[]") for item in leading)
        )

        empty = definitions["empty-duplicates"].inputs
        empty_files = tuple(item for item in empty if type(item) is InputFile)
        self.assertTrue(any(item.content == b"" for item in empty_files))
        basenames = [PurePosixPath(item.path).name for item in empty_files]
        self.assertLess(len(set(basenames)), len(basenames))

        ordering = definitions["symlinks-ordering"].inputs
        observed = [item.path for item in ordering]
        self.assertNotEqual(observed, sorted(observed, key=str.encode))
        self.assertIs(type(ordering[0]), InputSymlink)

        partial = definitions["partial-permissions"].inputs
        # FixtureDefinition has no directory-entry type or directory-mode
        # field.  This family therefore exercises mode-denied leaf files only
        # and explicitly does not claim directory permission-error coverage.
        self.assertIs(COMPOUND_PATH_DIRECTORY_PERMISSION_ERRORS_COVERED, False)
        self.assertGreaterEqual(
            sum(type(item) is InputFile and item.mode == 0 for item in partial),
            4,
        )

    def test_empty_duplicates_has_twenty_genuine_zero_byte_oracles(self) -> None:
        bundles = tuple(
            self.by_pair[(task.task_id, "empty-duplicates")]
            for task in self.tasks
        )
        self.assertEqual(len(bundles), 20)
        self.assertTrue(
            all(bundle.oracle.outputs[0].content == b"" for bundle in bundles)
        )
        self.assertTrue(
            all(
                bundle.definition.expected_files
                == (ExpectedFile(COMPOUND_PATH_QUERY_OUTPUT, 0, 0o644),)
                for bundle in bundles
            )
        )
        for bundle in bundles:
            in_scope = tuple(
                item
                for item in bundle.definition.inputs
                if PurePosixPath(item.path).parts[:2] == ("input", "query")
            )
            self.assertTrue(in_scope)
            self.assertTrue(
                all(
                    type(item) is InputFile and not item.mode & 0o444
                    for item in in_scope
                )
            )
            self.assertTrue(
                verify_compound_path_query_output(
                    bundle.definition,
                    next(
                        task.parameters
                        for task in self.tasks
                        if task.task_contract_sha256
                        == bundle.task_contract_sha256
                    ),
                    b"",
                )
            )

    def test_hand_checked_outputs_cover_patterns_parentheses_and_depth(self) -> None:
        self.assertEqual(
            self.bundle(
                "*.txt",
                "readable-regular-and-name",
                "spaces-unicode",
            ).oracle.outputs[0].content,
            (
                "deep space/é/x/deep snow.txt\n"
                "depth three/slot/plain snow.txt\n"
                "plain café.txt\n"
                "report-café snow.txt\n"
            ).encode("utf-8"),
        )
        self.assertEqual(
            self.bundle(
                "report-*",
                "readable-regular-and-name-depth-at-most-three",
                "spaces-unicode",
            ).oracle.outputs[0].content,
            (
                "depth three/slot/report-雪-three.bin\n"
                "report-café snow.txt\n"
                "report-雪-only.bin\n"
            ).encode("utf-8"),
        )
        self.assertEqual(
            self.bundle(
                "[a-z]*.log",
                "readable-regular-and-name-or-symlink",
                "symlinks-ordering",
            ).oracle.outputs[0].content,
            b"00-linked.txt\n"
            b"a/alpha.log\n"
            b"c/b/alpha-three.log\n"
            b"m/z/y/alpha-deep.log\n"
            b"report-zz-link\n",
        )
        self.assertEqual(
            self.bundle(
                "*.[0-9]",
                "readable-regular-and-name-or-executable",
                "partial-permissions",
            ).oracle.outputs[0].content,
            b"other-worker.bin\n"
            b"partial-worker.bin\n"
            b"partial/a/b/value.3\n"
            b"partial/deeper/data.7\n"
            b"three/a/value.5\n",
        )

    def test_txt_and_report_patterns_have_distinct_shallow_positives(self) -> None:
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
            if profile.profile_id == "empty-duplicates":
                continue
            txt_base = set(
                _output_lines(
                    self.bundle(
                        "*.txt",
                        "readable-regular-and-name",
                        profile.profile_id,
                    ).oracle.outputs[0].content
                )
            )
            report_base = set(
                _output_lines(
                    self.bundle(
                        "report-*",
                        "readable-regular-and-name",
                        profile.profile_id,
                    ).oracle.outputs[0].content
                )
            )
            with self.subTest(profile=profile.profile_id):
                self.assertTrue(
                    any(
                        len(PurePosixPath(path).parts) <= 2
                        for path in txt_base - report_base
                    )
                )
                self.assertTrue(
                    any(
                        len(PurePosixPath(path).parts) <= 2
                        for path in report_base - txt_base
                    )
                )
                for expression in COMPOUND_PATH_EXPRESSIONS:
                    txt = self.bundle(
                        "*.txt", expression, profile.profile_id
                    ).oracle.outputs[0].content
                    report = self.bundle(
                        "report-*", expression, profile.profile_id
                    ).oracle.outputs[0].content
                    self.assertNotEqual(txt, report)

    def test_every_pattern_has_inclusive_depth_three_and_excluded_depth_four(self) -> None:
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
            if profile.profile_id == "empty-duplicates":
                continue
            for pattern in COMPOUND_PATH_NAME_PATTERNS:
                with self.subTest(profile=profile.profile_id, pattern=pattern):
                    unlimited = set(
                        _output_lines(
                            self.bundle(
                                pattern,
                                "readable-regular-and-name",
                                profile.profile_id,
                            ).oracle.outputs[0].content
                        )
                    )
                    limited = set(
                        _output_lines(
                            self.bundle(
                                pattern,
                                "readable-regular-and-name-depth-at-most-three",
                                profile.profile_id,
                            ).oracle.outputs[0].content
                        )
                    )
                    exact_three = {
                        path
                        for path in unlimited
                        if len(PurePosixPath(path).parts) == 3
                    }
                    exact_four = {
                        path
                        for path in unlimited
                        if len(PurePosixPath(path).parts) == 4
                    }
                    self.assertTrue(exact_three)
                    self.assertTrue(exact_four)
                    self.assertTrue(exact_three <= limited)
                    self.assertFalse(exact_four & limited)

    def test_group_and_other_mode_bits_are_semantically_observable(self) -> None:
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
            if profile.profile_id == "empty-duplicates":
                continue
            representative = self.bundle(
                "*.txt",
                "readable-regular-and-name",
                profile.profile_id,
            )
            inputs = tuple(
                item
                for item in representative.definition.inputs
                if type(item) is InputFile
                and PurePosixPath(item.path).parts[:2] == ("input", "query")
            )
            self.assertTrue(any(item.mode == 0o040 for item in inputs))
            self.assertTrue(any(item.mode == 0o004 for item in inputs))
            self.assertTrue(any(item.mode == 0o050 for item in inputs))
            self.assertTrue(any(item.mode == 0o005 for item in inputs))

            for pattern in COMPOUND_PATH_NAME_PATTERNS:
                with self.subTest(profile=profile.profile_id, pattern=pattern):
                    named = set(
                        _output_lines(
                            self.bundle(
                                pattern,
                                "readable-regular-and-name",
                                profile.profile_id,
                            ).oracle.outputs[0].content
                        )
                    )
                    expected_group_other = {
                        PurePosixPath(*PurePosixPath(item.path).parts[2:]).as_posix()
                        for item in inputs
                        if item.mode in {0o040, 0o004}
                        and _independent_pattern(
                            PurePosixPath(item.path).name,
                            pattern,
                        )
                    }
                    self.assertTrue(
                        any(
                            next(
                                item.mode
                                for item in inputs
                                if PurePosixPath(*PurePosixPath(item.path).parts[2:]).as_posix()
                                == path
                            )
                            == 0o040
                            for path in expected_group_other
                        )
                    )
                    self.assertTrue(
                        any(
                            next(
                                item.mode
                                for item in inputs
                                if PurePosixPath(*PurePosixPath(item.path).parts[2:]).as_posix()
                                == path
                            )
                            == 0o004
                            for path in expected_group_other
                        )
                    )
                    self.assertTrue(expected_group_other <= named)

                    executable = set(
                        _output_lines(
                            self.bundle(
                                pattern,
                                "readable-regular-and-name-or-executable",
                                profile.profile_id,
                            ).oracle.outputs[0].content
                        )
                    )
                    expected_exec = {
                        PurePosixPath(*PurePosixPath(item.path).parts[2:]).as_posix()
                        for item in inputs
                        if item.mode in {0o050, 0o005}
                    }
                    self.assertEqual(len(expected_exec), 2)
                    self.assertTrue(expected_exec <= executable)
                    self.assertNotIn("unreadable-executable.bin", executable)

    def test_ascii_range_rejects_uppercase_and_non_ascii_log_decoys(self) -> None:
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
            definition = self.bundle(
                "[a-z]*.log",
                "readable-regular-and-name",
                profile.profile_id,
            ).definition
            paths = {item.path for item in definition.inputs}
            self.assertIn("input/query/decoys/Alpha.log", paths)
            self.assertIn("input/query/decoys/éclair.log", paths)
            selected = set(
                _output_lines(
                    self.bundle(
                        "[a-z]*.log",
                        "readable-regular-and-name",
                        profile.profile_id,
                    ).oracle.outputs[0].content
                )
            )
            self.assertNotIn("decoys/Alpha.log", selected)
            self.assertNotIn("decoys/éclair.log", selected)
            if profile.profile_id != "empty-duplicates":
                complement = set(
                    _output_lines(
                        self.bundle(
                            "[a-z]*.log",
                            "readable-regular-and-not-name",
                            profile.profile_id,
                        ).oracle.outputs[0].content
                    )
                )
                self.assertIn("decoys/Alpha.log", complement)
                self.assertIn("decoys/éclair.log", complement)

    def test_expression_truth_tables_distinguish_all_structured_cases(self) -> None:
        profile_id = "symlinks-ordering"
        for pattern in COMPOUND_PATH_NAME_PATTERNS:
            with self.subTest(pattern=pattern):
                outputs = {
                    expression: set(
                        _output_lines(
                            self.bundle(pattern, expression, profile_id)
                            .oracle.outputs[0]
                            .content
                        )
                    )
                    for expression in COMPOUND_PATH_EXPRESSIONS
                }
                base = outputs["readable-regular-and-name"]
                depth_limited = outputs[
                    "readable-regular-and-name-depth-at-most-three"
                ]
                link_union = outputs[
                    "readable-regular-and-name-or-symlink"
                ]
                executable_union = outputs[
                    "readable-regular-and-name-or-executable"
                ]
                complement = outputs["readable-regular-and-not-name"]
                self.assertTrue(depth_limited < base)
                self.assertTrue(base < link_union)
                self.assertTrue(base < executable_union)
                self.assertIn("zz-worker.bin", executable_union - base)
                self.assertIn("00-linked.txt", link_union - base)
                self.assertIn("report-zz-link", link_union - base)
                self.assertNotIn("unreadable-executable.bin", executable_union)
                self.assertFalse(base & complement)
                self.assertTrue(complement)

    def test_verifier_kills_byte_and_structured_semantic_mutants(self) -> None:
        killed = {
            "missing-line": 0,
            "wrong-order": 0,
            "duplicate-line": 0,
            "outside-root": 0,
            "no-final-lf": 0,
            "follow-symlink": 0,
            "wrong-precedence": 0,
            "depth-off-by-one": 0,
        }
        for task in self.tasks:
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                bundle = self.by_pair[(task.task_id, profile.profile_id)]
                expected = bundle.oracle.outputs[0].content
                lines = list(_output_lines(expected))
                first_or_sentinel = lines[0] if lines else "spurious-empty-result"
                mutants: dict[str, bytes] = {
                    "missing-line": b"".join(
                        item.encode("utf-8") + b"\n" for item in lines[1:]
                    ) if lines else b"spurious-empty-result\n",
                    "wrong-order": b"".join(
                        item.encode("utf-8") + b"\n"
                        for item in reversed(lines)
                    ) if len(lines) > 1 else b"spurious-empty-result\n",
                    "duplicate-line": (
                        expected + first_or_sentinel.encode("utf-8") + b"\n"
                    ),
                    "outside-root": expected + b"../outside/report-outside.txt\n",
                    "no-final-lf": (
                        expected[:-1] if expected else b"spurious-empty-result"
                    ),
                }
                for mutation, content in mutants.items():
                    if content != expected:
                        self.assertFalse(
                            verify_compound_path_query_output(
                                bundle.definition,
                                task.parameters,
                                content,
                            )
                        )
                        killed[mutation] += 1

                if task.parameters.expression == "readable-regular-and-name":
                    followed = tuple(
                        sorted(
                            {*lines, "linked.txt"},
                            key=lambda value: value.encode("utf-8"),
                        )
                    )
                    content = b"".join(
                        item.encode("utf-8") + b"\n" for item in followed
                    )
                    if content != expected:
                        self.assertFalse(
                            verify_compound_path_query_output(
                                bundle.definition, task.parameters, content
                            )
                        )
                        killed["follow-symlink"] += 1

                if (
                    task.parameters.expression
                    == "readable-regular-and-name-or-executable"
                ):
                    precedence = tuple(
                        sorted(
                            {*lines, "unreadable-executable.bin"},
                            key=lambda value: value.encode("utf-8"),
                        )
                    )
                    content = b"".join(
                        item.encode("utf-8") + b"\n" for item in precedence
                    )
                    self.assertFalse(
                        verify_compound_path_query_output(
                            bundle.definition, task.parameters, content
                        )
                    )
                    killed["wrong-precedence"] += 1

                if (
                    task.parameters.expression
                    == "readable-regular-and-name-depth-at-most-three"
                ):
                    unlimited_task = self.task(
                        task.parameters.name_pattern,
                        "readable-regular-and-name",
                    )
                    unlimited = self.by_pair[
                        (unlimited_task.task_id, profile.profile_id)
                    ].oracle.outputs[0].content
                    if unlimited != expected:
                        self.assertFalse(
                            verify_compound_path_query_output(
                                bundle.definition, task.parameters, unlimited
                            )
                        )
                        killed["depth-off-by-one"] += 1

        self.assertTrue(all(count > 0 for count in killed.values()), killed)

    def test_generation_and_python_verification_never_invoke_a_process(self) -> None:
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
            tasks = build_compound_path_query_tasks()
            for task in tasks:
                for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                    bundle = build_compound_path_query_fixture_bundle(task, profile)
                    expected = derive_compound_path_query_output(
                        bundle.definition,
                        task.parameters,
                    )
                    self.assertTrue(
                        verify_compound_path_query_output(
                            bundle.definition,
                            task.parameters,
                            expected,
                        )
                    )

    def test_bundles_materialize_without_output_scaffolding_or_execution(self) -> None:
        task = self.task(
            "report-*",
            "readable-regular-and-name-or-symlink",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                with self.subTest(profile=profile.profile_id):
                    bundle = self.by_pair[(task.task_id, profile.profile_id)]
                    workspace = root / profile.profile_id
                    with materialize_fixture(bundle.definition, workspace) as handle:
                        self.assertTrue(handle.scan_inputs().entries)
                        self.assertEqual(handle.scan_outputs().entries, ())

    def test_nested_tampering_changes_or_invalidates_every_binding(self) -> None:
        task = self.tasks[0]
        profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
        baseline = build_compound_path_query_fixture_bundle(task, profile)
        first = baseline.definition.inputs[0]
        self.assertIs(type(first), InputFile)
        changed_first = replace(first, content=first.content + b"changed")
        changed_definition = FixtureDefinition(
            fixture_id=baseline.definition.fixture_id,
            inputs=(changed_first, *baseline.definition.inputs[1:]),
            expected_files=baseline.definition.expected_files,
        )
        with self.assertRaises(CompoundPathQueryError):
            replace(baseline, definition=changed_definition)

        forged_input = build_compound_path_query_fixture_bundle(task, profile)
        object.__setattr__(
            forged_input.definition.inputs[0],
            "content",
            bytearray(b"mutable bypass"),
        )
        self.assertFalse(verify_compound_path_query_fixture_bundle(forged_input))

        forged_oracle = build_compound_path_query_fixture_bundle(task, profile)
        object.__setattr__(forged_oracle.oracle.outputs[0], "content", b"wrong\n")
        self.assertFalse(verify_compound_path_query_fixture_bundle(forged_oracle))

        forged_descriptor = build_compound_path_query_fixture_bundle(task, profile)
        object.__setattr__(
            forged_descriptor.descriptor,
            "fixture_sha256",
            "0" * 64,
        )
        self.assertFalse(
            verify_compound_path_query_fixture_bundle(forged_descriptor)
        )

    def test_task_profile_authentication_closes_structural_self_hash_seam(self) -> None:
        task = self.tasks[0]
        other_task = self.tasks[1]
        profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
        other_profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[1]
        bundle = self.by_pair[(task.task_id, profile.profile_id)]
        other_profile_bundle = self.by_pair[
            (task.task_id, other_profile.profile_id)
        ]

        # Both objects are internally hash-consistent.  Only deterministic
        # task/profile reconstruction authenticates which one belongs here.
        self.assertTrue(
            verify_compound_path_query_fixture_bundle(other_profile_bundle)
        )
        self.assertFalse(
            verify_compound_path_query_fixture_for_task_profile(
                task,
                profile,
                other_profile_bundle,
            )
        )
        self.assertFalse(
            verify_compound_path_query_fixture_for_task_profile(
                other_task,
                profile,
                bundle,
            )
        )
        self.assertTrue(
            verify_compound_path_query_fixture_for_task_profile(
                task,
                profile,
                bundle,
            )
        )
        self.assertIn(
            "not authentication",
            verify_compound_path_query_fixture_bundle.__doc__ or "",
        )

        swapped_task = replace(task)
        swapped = list(swapped_task.fixtures)
        swapped[0], swapped[1] = swapped[1], swapped[0]
        object.__setattr__(swapped_task, "fixtures", tuple(swapped))
        swapped_task.__post_init__()  # still structurally valid task metadata
        self.assertFalse(
            verify_compound_path_query_fixture_for_task_profile(
                swapped_task,
                profile,
                bundle,
            )
        )

    def test_exact_types_and_authority_bypasses_fail_closed(self) -> None:
        class StringSubclass(str):
            pass

        class BytesSubclass(bytes):
            pass

        with self.assertRaises(CompoundPathQueryError):
            CompoundPathQueryParameters(
                name_pattern=StringSubclass("*.txt"),  # type: ignore[arg-type]
                expression="readable-regular-and-name",
            )

        task = self.tasks[0]
        profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
        bundle = self.by_pair[(task.task_id, profile.profile_id)]
        self.assertFalse(
            verify_compound_path_query_output(
                bundle.definition,
                task.parameters,
                BytesSubclass(bundle.oracle.outputs[0].content),
            )
        )
        self.assertFalse(
            verify_compound_path_query_output(
                bundle.definition,
                task.parameters,
                bytearray(bundle.oracle.outputs[0].content),  # type: ignore[arg-type]
            )
        )

        forged_parameters = replace(task.parameters)
        object.__setattr__(forged_parameters, "name_pattern", "*")
        forged_task = replace(task)
        object.__setattr__(forged_task, "parameters", forged_parameters)
        with self.assertRaises(CompoundPathQueryError):
            build_compound_path_query_fixture_bundle(forged_task, profile)

        forged_profile = replace(profile)
        object.__setattr__(forged_profile, "claim_authorized", True)
        with self.assertRaises(CompoundPathQueryError):
            build_compound_path_query_fixture_bundle(task, forged_profile)

        forged_authority = build_compound_path_query_fixture_bundle(task, profile)
        object.__setattr__(forged_authority, "candidate_execution_authorized", True)
        self.assertFalse(
            verify_compound_path_query_fixture_bundle(forged_authority)
        )

        forged_path = build_compound_path_query_fixture_bundle(task, profile)
        path_input = next(
            item
            for item in forged_path.definition.inputs
            if type(item) is InputFile
        )
        object.__setattr__(path_input, "path", StringSubclass(path_input.path))
        self.assertFalse(verify_compound_path_query_fixture_bundle(forged_path))
        with self.assertRaises(CompoundPathQueryError):
            derive_compound_path_query_output(
                forged_path.definition,
                task.parameters,
            )

        forged_target = build_compound_path_query_fixture_bundle(task, profile)
        link_input = next(
            item
            for item in forged_target.definition.inputs
            if type(item) is InputSymlink
        )
        object.__setattr__(
            link_input,
            "target",
            StringSubclass(link_input.target),
        )
        self.assertFalse(verify_compound_path_query_fixture_bundle(forged_target))

        forged_schema = build_compound_path_query_fixture_bundle(task, profile)
        object.__setattr__(
            forged_schema.definition,
            "schema_version",
            StringSubclass(forged_schema.definition.schema_version),
        )
        self.assertFalse(verify_compound_path_query_fixture_bundle(forged_schema))

        forged_policy = build_compound_path_query_fixture_bundle(task, profile)
        object.__setattr__(
            forged_policy.definition.expected_files[0],
            "path",
            StringSubclass(forged_policy.definition.expected_files[0].path),
        )
        self.assertFalse(verify_compound_path_query_fixture_bundle(forged_policy))

        forged_profile_text = replace(profile)
        object.__setattr__(
            forged_profile_text,
            "profile_sha256",
            StringSubclass(profile.profile_sha256),
        )
        with self.assertRaises(CompoundPathQueryError):
            build_compound_path_query_fixture_bundle(task, forged_profile_text)

    def test_private_commitment_records_do_not_release_answer_bytes(self) -> None:
        bundle = next(iter(self.by_pair.values()))
        record = bundle.commitment_record()
        self.assertNotIn("content", repr(record))
        self.assertNotIn(
            bundle.oracle.outputs[0].content.decode("utf-8"),
            repr(record),
        )
        self.assertEqual(
            record["oracle"]["outputs"][0]["sha256"],  # type: ignore[index]
            bundle.oracle.outputs[0].commitment_record()["sha256"],
        )


if __name__ == "__main__":
    unittest.main()
