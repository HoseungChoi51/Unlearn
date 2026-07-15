from __future__ import annotations

import csv
import io
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import cbds.executable_fixture_csv as csv_fixture  # noqa: E402
from cbds.executable_fixture_bundle import (  # noqa: E402
    validate_executable_fixture_bundle,
)
from cbds.executable_fixture_csv import (  # noqa: E402
    ExecutableFixtureCsvError,
    build_csv_group_totals_fixture_bundle,
)
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from cbds.executable_static_registry import (  # noqa: E402
    build_public_method_development_registry,
)
from cbds.executable_workspace import InputFile, InputSymlink  # noqa: E402


REGISTRY = build_public_method_development_registry()
CSV_TASKS = tuple(
    task for task in REGISTRY.tasks if task.family_id == "csv-group-totals"
)
NON_CSV_TASK = next(
    task for task in REGISTRY.tasks if task.family_id != "csv-group-totals"
)

LAYOUTS = (
    "category-amount-enabled",
    "enabled-category-amount",
    "amount-enabled-category",
    "category-enabled-amount",
)
PREDICATES = (
    "all-valid",
    "enabled-yes",
    "positive-amount",
    "nonempty-category",
    "enabled-and-positive",
)
LAYOUT_FIELDS = {
    "category-amount-enabled": ("category", "amount", "enabled"),
    "enabled-category-amount": ("enabled", "category", "amount"),
    "amount-enabled-category": ("amount", "enabled", "category"),
    "category-enabled-amount": ("category", "enabled", "amount"),
}
PROFILE_CATEGORIES = {
    "spaces-unicode": ("space category", '한글, "분류"'),
    "leading-dashes-globs": ("-leading", "glob[*]?"),
    "empty-duplicates": ("", "duplicate"),
    "symlinks-ordering": ("z-last", "a-first"),
    "partial-permissions": ("readable", "partial"),
}
EMPTY_OUTPUT = b"category,total\n"


def task_by_parameters(*, layout: str, predicate: str):
    matches = tuple(
        task
        for task in CSV_TASKS
        if task.parameters.layout == layout
        and task.parameters.predicate == predicate
    )
    if len(matches) != 1:
        raise AssertionError(
            f"expected one CSV task for layout={layout!r}, predicate={predicate!r}"
        )
    return matches[0]


def profile_by_id(profile_id: str):
    matches = tuple(
        profile
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        if profile.profile_id == profile_id
    )
    if len(matches) != 1:
        raise AssertionError(f"expected one profile for {profile_id!r}")
    return matches[0]


def oracle_content(bundle) -> bytes:
    if len(bundle.oracle.outputs) != 1:
        raise AssertionError("CSV fixture must have exactly one oracle output")
    output = bundle.oracle.outputs[0]
    if output.path != "output/totals.csv":
        raise AssertionError("CSV fixture oracle path changed")
    return output.content


def parse_totals(content: bytes) -> tuple[list[str], dict[str, int]]:
    text = content.decode("utf-8", errors="strict")
    rows = list(csv.reader(io.StringIO(text, newline=""), strict=True))
    if not rows or rows[0] != ["category", "total"]:
        raise AssertionError("CSV oracle has the wrong header")
    categories = [row[0] for row in rows[1:]]
    if any(len(row) != 2 for row in rows[1:]):
        raise AssertionError("CSV oracle row does not have exactly two fields")
    return categories, {row[0]: int(row[1], 10) for row in rows[1:]}


def hand_totals(profile_id: str, predicate: str) -> dict[str, int]:
    first, second = PROFILE_CATEGORIES[profile_id]
    duplicated = profile_id == "empty-duplicates"
    first_all = 25 if duplicated else 15
    first_enabled = 18 if duplicated else 8
    if predicate == "all-valid":
        return {first: first_all, second: 9, "third": 2}
    if predicate == "enabled-yes":
        return {first: first_enabled, second: -2, "third": 2}
    if predicate == "positive-amount":
        return {first: first_all, second: 11, "third": 2}
    if predicate == "nonempty-category":
        totals = {second: 9, "third": 2}
        if first:
            totals[first] = first_all
        return totals
    if predicate == "enabled-and-positive":
        return {first: first_enabled, "third": 2}
    raise AssertionError(f"unrecognized test predicate: {predicate}")


def normalized_valid_rows(bundle) -> tuple[tuple[str, str, str], ...]:
    records: list[tuple[str, str, str]] = []
    for item in bundle.definition.inputs:
        if type(item) is not InputFile or item.path not in {
            "input/records/z records.csv",
            "input/records/nested/a-records.csv",
        }:
            continue
        rows = list(
            csv.reader(
                io.StringIO(item.content.decode("utf-8"), newline=""),
                strict=True,
            )
        )
        header = rows[0]
        positions = {field: index for index, field in enumerate(header)}
        records.extend(
            (
                row[positions["category"]],
                row[positions["amount"]],
                row[positions["enabled"]],
            )
            for row in rows[1:]
        )
    return tuple(records)


class CsvFixtureCatalogTests(unittest.TestCase):
    def test_all_100_bundles_are_deterministic_unique_and_nonexecuting(self) -> None:
        self.assertEqual(len(CSV_TASKS), 20)
        self.assertEqual(
            {
                (task.parameters.layout, task.parameters.predicate)
                for task in CSV_TASKS
            },
            {(layout, predicate) for layout in LAYOUTS for predicate in PREDICATES},
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
            for task in CSV_TASKS:
                for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                    with self.subTest(
                        layout=task.parameters.layout,
                        predicate=task.parameters.predicate,
                        profile=profile.profile_id,
                    ):
                        first = build_csv_group_totals_fixture_bundle(task, profile)
                        second = build_csv_group_totals_fixture_bundle(task, profile)
                        self.assertEqual(first, second)
                        validate_executable_fixture_bundle(first)
                        self.assertEqual(
                            first.task_contract_sha256,
                            task.task_contract_sha256,
                        )
                        self.assertEqual(
                            first.profile_sha256,
                            profile.profile_sha256,
                        )
                        self.assertEqual(
                            first.descriptor.task_contract_sha256,
                            task.task_contract_sha256,
                        )
                        self.assertEqual(len(first.definition.inputs), 8)
                        self.assertEqual(len(first.definition.expected_files), 1)
                        self.assertEqual(
                            first.oracle.semantic_verifier_identity,
                            "verify-csv-group-totals-v1",
                        )
                        self.assertIs(first.candidate_execution_authorized, False)
                        self.assertIs(first.model_selection_eligible, False)
                        self.assertIs(first.claim_authorized, False)
                        self.assertIs(
                            profile.candidate_execution_authorized,
                            False,
                        )
                        descriptors.append(first.descriptor)

        self.assertEqual(len(descriptors), 100)
        self.assertEqual(len({item.fixture_id for item in descriptors}), 100)
        self.assertEqual(len({item.fixture_sha256 for item in descriptors}), 100)

    def test_all_layouts_encode_equivalent_rows_and_outputs(self) -> None:
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
            for predicate in PREDICATES:
                outputs: list[bytes] = []
                normalized_rows: list[tuple[tuple[str, str, str], ...]] = []
                for layout in LAYOUTS:
                    task = task_by_parameters(layout=layout, predicate=predicate)
                    bundle = build_csv_group_totals_fixture_bundle(task, profile)
                    outputs.append(oracle_content(bundle))
                    normalized_rows.append(normalized_valid_rows(bundle))
                    valid_files = tuple(
                        item
                        for item in bundle.definition.inputs
                        if type(item) is InputFile
                        and item.path
                        in {
                            "input/records/z records.csv",
                            "input/records/nested/a-records.csv",
                        }
                    )
                    self.assertEqual(len(valid_files), 2)
                    for item in valid_files:
                        header = next(
                            csv.reader(
                                io.StringIO(
                                    item.content.decode("utf-8"),
                                    newline="",
                                ),
                                strict=True,
                            )
                        )
                        self.assertEqual(header, list(LAYOUT_FIELDS[layout]))
                with self.subTest(
                    profile=profile.profile_id,
                    predicate=predicate,
                ):
                    self.assertEqual(len(set(outputs)), 1)
                    self.assertEqual(len(set(normalized_rows)), 1)


class CsvPredicateSemanticsTests(unittest.TestCase):
    def test_every_profile_predicate_and_layout_matches_hand_totals(self) -> None:
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
            for predicate in PREDICATES:
                expected = hand_totals(profile.profile_id, predicate)
                for layout in LAYOUTS:
                    task = task_by_parameters(layout=layout, predicate=predicate)
                    bundle = build_csv_group_totals_fixture_bundle(task, profile)
                    categories, observed = parse_totals(oracle_content(bundle))
                    with self.subTest(
                        profile=profile.profile_id,
                        predicate=predicate,
                        layout=layout,
                    ):
                        self.assertEqual(observed, expected)
                        self.assertEqual(
                            categories,
                            sorted(expected, key=lambda value: value.encode("utf-8")),
                        )
                        self.assertNotIn("ignored-invalid", observed)

    def test_empty_duplicate_and_quoted_unicode_categories_are_literal(self) -> None:
        task = task_by_parameters(
            layout="category-amount-enabled",
            predicate="all-valid",
        )
        empty = build_csv_group_totals_fixture_bundle(
            task,
            profile_by_id("empty-duplicates"),
        )
        self.assertEqual(
            oracle_content(empty),
            b"category,total\n,25\nduplicate,9\nthird,2\n",
        )

        unicode_bundle = build_csv_group_totals_fixture_bundle(
            task,
            profile_by_id("spaces-unicode"),
        )
        unicode_output = oracle_content(unicode_bundle)
        self.assertEqual(
            unicode_output,
            (
                "category,total\n"
                "space category,15\n"
                "third,2\n"
                '"한글, ""분류""",9\n'
            ).encode("utf-8"),
        )


class CsvInputRejectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.task = task_by_parameters(
            layout="category-amount-enabled",
            predicate="all-valid",
        )
        self.bundle = build_csv_group_totals_fixture_bundle(
            self.task,
            profile_by_id("spaces-unicode"),
        )
        self.inputs = {item.path: item for item in self.bundle.definition.inputs}

    def test_malformed_wrong_header_unreadable_and_symlink_inputs_are_rejected(self) -> None:
        expected_types = {
            "input/records/malformed.csv": InputFile,
            "input/records/wrong-header.csv": InputFile,
            "input/records/empty.csv": InputFile,
            "input/records/unreadable.csv": InputFile,
            "input/records/link.csv": InputSymlink,
        }
        for path, expected_type in expected_types.items():
            item = self.inputs[path]
            self.assertIs(type(item), expected_type)
            with self.subTest(path=path):
                self.assertEqual(
                    csv_fixture._accepted_rows((item,), self.task.parameters),
                    (),
                )
                self.assertEqual(
                    csv_fixture._derive_output((item,), self.task.parameters),
                    EMPTY_OUTPUT,
                )

        malformed = self.inputs["input/records/malformed.csv"]
        self.assertTrue(malformed.content.endswith(b'"unterminated'))
        with self.assertRaises(csv.Error):
            list(
                csv.reader(
                    io.StringIO(malformed.content.decode("utf-8"), newline=""),
                    strict=True,
                )
            )

        wrong_header = self.inputs["input/records/wrong-header.csv"]
        wrong_rows = list(
            csv.reader(
                io.StringIO(wrong_header.content.decode("utf-8"), newline=""),
                strict=True,
            )
        )
        self.assertEqual(wrong_rows[0], ["wrong", "amount", "enabled"])
        self.assertEqual(wrong_rows[1], ["ignored", "1", "yes"])

        self.assertEqual(self.inputs["input/records/empty.csv"].content, b"")

        unreadable = self.inputs["input/records/unreadable.csv"]
        self.assertEqual(unreadable.mode, 0o000)
        readable_control = InputFile(
            unreadable.path,
            unreadable.content,
            0o644,
        )
        self.assertNotEqual(
            csv_fixture._derive_output(
                (readable_control,),
                self.task.parameters,
            ),
            EMPTY_OUTPUT,
        )

        symlink = self.inputs["input/records/link.csv"]
        self.assertEqual(symlink.target, "z records.csv")
        target = self.inputs["input/records/z records.csv"]
        regular_control = InputFile(symlink.path, target.content)
        self.assertNotEqual(
            csv_fixture._derive_output(
                (regular_control,),
                self.task.parameters,
            ),
            EMPTY_OUTPUT,
        )

    def test_non_csv_file_is_not_selected_even_when_its_bytes_are_valid(self) -> None:
        item = self.inputs["input/records/not-selected.txt"]
        self.assertIs(type(item), InputFile)
        self.assertEqual(
            csv_fixture._derive_output((item,), self.task.parameters),
            EMPTY_OUTPUT,
        )
        selected_control = InputFile(
            "input/records/selected.csv",
            item.content,
            item.mode,
        )
        self.assertNotEqual(
            csv_fixture._derive_output(
                (selected_control,),
                self.task.parameters,
            ),
            EMPTY_OUTPUT,
        )


class CsvFixtureBoundaryTests(unittest.TestCase):
    def test_wrong_task_and_profile_types_fail_closed(self) -> None:
        csv_task = CSV_TASKS[0]
        profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
        with self.assertRaisesRegex(
            ExecutableFixtureCsvError,
            "exact csv-group-totals",
        ):
            build_csv_group_totals_fixture_bundle(NON_CSV_TASK, profile)
        with self.assertRaisesRegex(
            ExecutableFixtureCsvError,
            "exact ExecutableFixtureProfile",
        ):
            build_csv_group_totals_fixture_bundle(
                csv_task,
                object(),  # type: ignore[arg-type]
            )
        with self.assertRaisesRegex(
            ExecutableFixtureCsvError,
            "exact csv-group-totals",
        ):
            build_csv_group_totals_fixture_bundle(
                object(),  # type: ignore[arg-type]
                profile,
            )


if __name__ == "__main__":
    unittest.main()
