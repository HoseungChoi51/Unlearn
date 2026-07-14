from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.static_families import (  # noqa: E402
    CHECKSUM_MODE_FAMILY,
    COPY_MAP_FAMILY,
    CSV_TOTALS_FAMILY,
    OUTPUT_DIRECTORY_MODE,
    OUTPUT_FILE_MODE,
    OUTPUT_ROOT,
    FamilyMaterializationError,
    FamilyVerificationError,
    PublicStaticFamilySuite,
    public_development_suites,
)
import cbds.static_families as families  # noqa: E402


def failure_codes(result: object) -> set[str]:
    return {failure.code for failure in result.failures}  # type: ignore[attr-defined]


def write_reference(
    suite: PublicStaticFamilySuite, instance: object
) -> dict[str, bytes]:
    output = instance.workspace / OUTPUT_ROOT  # type: ignore[attr-defined]
    output.mkdir(mode=OUTPUT_DIRECTORY_MODE)
    output.chmod(OUTPUT_DIRECTORY_MODE)
    reference = suite.trusted_reference_files(instance)  # type: ignore[arg-type]
    for relative, payload in reference.items():
        path = output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        current = path.parent
        while current != output.parent:
            current.chmod(OUTPUT_DIRECTORY_MODE)
            if current == output:
                break
            current = current.parent
        path.write_bytes(payload)
        path.chmod(OUTPUT_FILE_MODE)
    return reference


def materialize_at(
    family: str, fixture_index: int, parent: Path, *, answer: bool = False
) -> tuple[PublicStaticFamilySuite, object]:
    suite = PublicStaticFamilySuite(family)  # type: ignore[arg-type]
    instance = suite.materialize(
        suite.descriptors[fixture_index], parent / "workspace"
    )
    if answer:
        write_reference(suite, instance)
    return suite, instance


class FamilyContractTests(unittest.TestCase):
    def test_three_distinct_families_have_five_deterministic_fixtures_each(self) -> None:
        suites = public_development_suites(seed=17)
        repeated = public_development_suites(seed=17)
        changed = public_development_suites(seed=18)

        self.assertEqual(
            tuple(suite.family for suite in suites),
            (COPY_MAP_FAMILY, CSV_TOTALS_FAMILY, CHECKSUM_MODE_FAMILY),
        )
        self.assertEqual(len({suite.task_id for suite in suites}), 3)
        for suite, same, other_seed in zip(suites, repeated, changed, strict=True):
            with self.subTest(family=suite.family):
                self.assertEqual(len(suite.descriptors), 5)
                self.assertEqual(suite.descriptors, same.descriptors)
                self.assertEqual(suite.suite_sha256, same.suite_sha256)
                self.assertNotEqual(suite.descriptors, other_seed.descriptors)
                self.assertEqual(suite.coverage_tags, suite.required_edge_cases)
                self.assertRegex(suite.contract_sha256, r"^[0-9a-f]{64}$")
                self.assertIn("symbolic link", suite.task_prompt)
                self.assertTrue(
                    "without following" in suite.task_prompt
                    or "Do not follow" in suite.task_prompt
                )
                self.assertIn("link count one", suite.task_prompt)
                self.assertIn("initial state", " ".join(suite.task_prompt.split()))

    def test_descriptors_do_not_reveal_fixture_paths_or_answers(self) -> None:
        for suite in public_development_suites():
            for descriptor in suite.descriptors:
                record = descriptor.to_record()
                self.assertEqual(
                    set(record),
                    {
                        "schema_version",
                        "family",
                        "task_id",
                        "task_version",
                        "fixture_id",
                        "fixture_sha256",
                    },
                )
                serialized = json.dumps(record)
                self.assertNotIn("expected", serialized)
                self.assertNotIn("input/", serialized)
                self.assertRegex(descriptor.fixture_id, r"^fx-[0-9a-f]{20}$")

    def test_second_in_module_oracle_kills_committed_answer_mutations(self) -> None:
        for spec in families._SPECS.values():
            definition = spec.definitions(71)[0]
            first = definition.expected[0]
            mutant = replace(
                definition,
                expected=(
                    replace(first, content=first.content + b"reference-mutant"),
                    *definition.expected[1:],
                ),
            )
            with self.subTest(family=spec.family):
                with self.assertRaisesRegex(
                    ValueError, "second in-module oracle disagrees"
                ):
                    families._audit_definition(spec, mutant)

    def test_second_in_module_oracles_use_distinct_implementations(self) -> None:
        self.assertIsNot(families._copy_reference, families._csv_reference)
        self.assertIsNot(families._csv_reference, families._checksum_reference)
        self.assertIn("csv", families._csv_reference.__code__.co_names)
        self.assertIn("reader", families._csv_reference.__code__.co_names)
        self.assertIn("sha256", families._checksum_reference.__code__.co_names)

    def test_copy_fixtures_cover_repetition_and_directory_sources(self) -> None:
        definitions = families._copy_definitions(53)
        basic_files = families._input_files(definitions[0])
        records = [
            json.loads(line)
            for line in basic_files["input/copy-map.jsonl"].content.splitlines()
        ]
        repeated = {"source": "alpha.txt", "destination": "renamed.txt"}
        self.assertEqual(records.count(repeated), 2)
        self.assertIn("repeated_identical_record", definitions[0].cases)

        decoy_files = families._input_files(definitions[3])
        decoy_records = [
            json.loads(line)
            for line in decoy_files["input/copy-map.jsonl"].content.splitlines()
        ]
        self.assertIn(
            {"source": "folder", "destination": "from-directory.txt"},
            decoy_records,
        )
        self.assertIn("input/files/folder/inside.txt", decoy_files)
        self.assertIn("directory_source", definitions[3].cases)
        self.assertNotIn(
            "from-directory.txt", {item.path for item in definitions[3].expected}
        )


class FamilyMaterializationAndReferenceTests(unittest.TestCase):
    def test_every_trusted_reference_passes_twice(self) -> None:
        for suite in public_development_suites(seed=29):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                for index, descriptor in enumerate(suite.descriptors):
                    with self.subTest(family=suite.family, fixture=index):
                        instance = suite.materialize(descriptor, root / str(index))
                        reference = write_reference(suite, instance)
                        first = suite.verify(instance)
                        second = suite.verify(instance)
                        self.assertTrue(first.passed, first.to_record())
                        self.assertEqual(first, second)
                        self.assertEqual(
                            first.expected_file_count, len(reference)
                        )
                        self.assertEqual(
                            first.observed_file_count, len(reference)
                        )
                        self.assertIsNotNone(first.output_tree_sha256)

    def test_instance_is_bound_to_family_seed_and_suite(self) -> None:
        suite = PublicStaticFamilySuite(COPY_MAP_FAMILY, seed=1)
        other = PublicStaticFamilySuite(COPY_MAP_FAMILY, seed=2)
        different_family = PublicStaticFamilySuite(CSV_TOTALS_FAMILY, seed=1)
        with tempfile.TemporaryDirectory() as temporary:
            instance = suite.materialize(suite.descriptors[0], temporary)
            with self.assertRaisesRegex(FamilyVerificationError, "another suite"):
                other.verify(instance)
            with self.assertRaisesRegex(FamilyVerificationError, "another suite"):
                different_family.verify(instance)

    def test_workspace_swap_cannot_redirect_materialization_outside(self) -> None:
        suite = PublicStaticFamilySuite(COPY_MAP_FAMILY)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            parked = root / "parked"
            outside = root / "outside"
            outside.mkdir()
            original_write = os.write
            swapped = False

            def racing_write(descriptor: int, payload: bytes) -> int:
                nonlocal swapped
                if not swapped:
                    swapped = True
                    workspace.rename(parked)
                    workspace.symlink_to(outside, target_is_directory=True)
                return original_write(descriptor, payload)

            with mock.patch.object(
                families.os, "write", side_effect=racing_write
            ):
                with self.assertRaises(FamilyMaterializationError):
                    suite.materialize(suite.descriptors[0], workspace)

            self.assertTrue(swapped)
            self.assertEqual(list(outside.iterdir()), [])
            self.assertFalse((outside / "input/copy-map.jsonl").exists())
            self.assertTrue((parked / "input/copy-map.jsonl").is_file())

    def test_descendant_replacement_fails_without_publishing_fixture_bytes(self) -> None:
        suite = PublicStaticFamilySuite(COPY_MAP_FAMILY)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            parked_input = root / "parked-input"
            original_link = os.link
            replaced = False

            def racing_link(
                source: str,
                destination: str,
                *args: object,
                **kwargs: object,
            ) -> None:
                nonlocal replaced
                if not replaced:
                    replaced = True
                    (workspace / "input").rename(parked_input)
                    (workspace / "input/files/nested").mkdir(parents=True)
                original_link(source, destination, *args, **kwargs)

            with mock.patch.object(
                families._safe.os, "link", side_effect=racing_link
            ):
                with self.assertRaises(FamilyMaterializationError):
                    suite.materialize(suite.descriptors[0], workspace)

            self.assertTrue(replaced)
            self.assertFalse((parked_input / "copy-map.jsonl").exists())
            self.assertFalse((workspace / "input/copy-map.jsonl").exists())
            self.assertEqual(
                [path for path in parked_input.rglob("*") if path.is_file()],
                [],
            )
            self.assertEqual(
                [
                    path
                    for path in workspace.iterdir()
                    if path.name.startswith(".cbds-stage-")
                ],
                [],
            )


class CopyMapMutationTests(unittest.TestCase):
    def test_wrong_copied_bytes_are_killed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, instance = materialize_at(
                COPY_MAP_FAMILY, 0, Path(temporary), answer=True
            )
            (instance.workspace / OUTPUT_ROOT / "renamed.txt").write_bytes(b"wrong\n")
            result = suite.verify(instance)
        self.assertFalse(result.passed)
        self.assertIn("output_entry_mismatch", failure_codes(result))

    def test_missing_nested_destination_and_extra_file_are_killed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, instance = materialize_at(
                COPY_MAP_FAMILY, 0, Path(temporary), answer=True
            )
            (instance.workspace / OUTPUT_ROOT / "deep" / "data.bin").unlink()
            (instance.workspace / OUTPUT_ROOT / "scratch").write_bytes(b"extra")
            result = suite.verify(instance)
        self.assertFalse(result.passed)
        self.assertIn("missing_output_path", failure_codes(result))
        self.assertIn("unexpected_output_path", failure_codes(result))

    def test_symlink_and_hardlink_outputs_are_never_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, instance = materialize_at(
                COPY_MAP_FAMILY, 0, Path(temporary), answer=True
            )
            copied = instance.workspace / OUTPUT_ROOT / "renamed.txt"
            copied.unlink()
            copied.symlink_to("../input/files/alpha.txt")
            result = suite.verify(instance)
            self.assertFalse(result.passed)
            self.assertIn("output_entry_mismatch", failure_codes(result))

        with tempfile.TemporaryDirectory() as temporary:
            suite, instance = materialize_at(
                COPY_MAP_FAMILY, 0, Path(temporary), answer=True
            )
            copied = instance.workspace / OUTPUT_ROOT / "renamed.txt"
            copied.unlink()
            os.link(instance.workspace / "input/files/alpha.txt", copied)
            result = suite.verify(instance)
        self.assertFalse(result.passed)
        self.assertIn("output_entry_mismatch", failure_codes(result))
        self.assertIn("input_entry_changed", failure_codes(result))

    def test_empty_selection_still_requires_real_empty_output_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, instance = materialize_at(
                COPY_MAP_FAMILY, 4, Path(temporary), answer=True
            )
            result = suite.verify(instance)
            self.assertTrue(result.passed, result.to_record())
            (instance.workspace / OUTPUT_ROOT / "invented").touch()
            mutated = suite.verify(instance)
        self.assertFalse(mutated.passed)
        self.assertIn("unexpected_output_path", failure_codes(mutated))


class CsvMutationTests(unittest.TestCase):
    def test_equivalent_rfc4180_quoting_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, instance = materialize_at(
                CSV_TOTALS_FAMILY, 0, Path(temporary)
            )
            output = instance.workspace / OUTPUT_ROOT
            output.mkdir(mode=OUTPUT_DIRECTORY_MODE)
            report = output / "totals.csv"
            report.write_bytes(
                b'"category","total"\n"alpha","5"\n"zeta","4"\n'
            )
            report.chmod(OUTPUT_FILE_MODE)
            result = suite.verify(instance)
        self.assertTrue(result.passed, result.to_record())

    def test_input_recovery_is_file_granular_but_row_errors_are_ignored(self) -> None:
        definition = families._FixtureDefinition(
            "csv-recovery-probe",
            frozenset(),
            (
                families._InputFile(
                    "input/records/valid.csv",
                    b"category,amount,enabled\nkept,2,yes\nshort,3\nbad,+4,yes\n",
                ),
                families._InputFile(
                    "input/records/wrong-header.csv",
                    b"category,amount,active\nleaked-header,10,yes\n",
                ),
                families._InputFile(
                    "input/records/invalid-utf8.csv",
                    b"category,amount,enabled\nleaked-utf8,20,yes\n\xff",
                ),
                families._InputFile(
                    "input/records/late-malformed.csv",
                    b'category,amount,enabled\nleaked-late,30,yes\n"unterminated,1,yes\n',
                ),
                families._InputFile(
                    "input/records/unquoted-quote.csv",
                    b'category,amount,enabled\nleaked-quote,40,yes\nbad"quote,1,yes\n',
                ),
            ),
            (),
        )
        reference = families._csv_reference(definition)
        self.assertEqual(
            reference[0].content, b"category,total\nkept,2\n"
        )

    def test_committed_fixture_contains_a_true_late_csv_syntax_error(self) -> None:
        definition = families._csv_definitions(11)[4]
        files = families._input_files(definition)
        malformed = files["input/records/malformed.csv"].content
        decoded = malformed.decode("utf-8")
        with self.assertRaises(families.csv.Error):
            list(
                families.csv.reader(
                    families.io.StringIO(decoded, newline=""), strict=True
                )
            )
        self.assertEqual(
            families._csv_reference(definition)[0].content,
            b"category,total\n",
        )

        bare_quote = files["input/records/bare-quote.csv"].content.decode(
            "utf-8"
        )
        with self.assertRaises(families._RFC4180Error):
            families._validate_rfc4180_syntax(bare_quote)

    def test_naive_comma_splitting_is_killed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, instance = materialize_at(CSV_TOTALS_FAMILY, 1, Path(temporary))
            output = instance.workspace / OUTPUT_ROOT
            output.mkdir(mode=OUTPUT_DIRECTORY_MODE)
            (output / "totals.csv").write_bytes(
                b"category,total\ncomma,cat,2\nsay hi,3\n"
            )
            (output / "totals.csv").chmod(OUTPUT_FILE_MODE)
            result = suite.verify(instance)
        self.assertFalse(result.passed)
        self.assertIn("output_entry_mismatch", failure_codes(result))

    def test_dquote_in_unquoted_output_field_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, instance = materialize_at(CSV_TOTALS_FAMILY, 1, Path(temporary))
            output = instance.workspace / OUTPUT_ROOT
            output.mkdir(mode=OUTPUT_DIRECTORY_MODE)
            report = output / "totals.csv"
            report.write_bytes(
                b'category,total\n"comma,cat",2\nsay "hi",3\n'
            )
            report.chmod(OUTPUT_FILE_MODE)
            result = suite.verify(instance)

        self.assertFalse(result.passed)
        self.assertIn("output_entry_mismatch", failure_codes(result))

    def test_wrong_aggregate_and_wrong_mode_are_killed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, instance = materialize_at(
                CSV_TOTALS_FAMILY, 0, Path(temporary), answer=True
            )
            report = instance.workspace / OUTPUT_ROOT / "totals.csv"
            report.write_bytes(b"category,total\nalpha,2\nzeta,4\n")
            report.chmod(0o600)
            result = suite.verify(instance)
        self.assertFalse(result.passed)
        self.assertIn("output_entry_mismatch", failure_codes(result))

    def test_crlf_output_is_not_equivalent_to_required_lf(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, instance = materialize_at(
                CSV_TOTALS_FAMILY, 4, Path(temporary), answer=True
            )
            report = instance.workspace / OUTPUT_ROOT / "totals.csv"
            report.write_bytes(b"category,total\r\n")
            result = suite.verify(instance)
        self.assertFalse(result.passed)
        self.assertIn("output_entry_mismatch", failure_codes(result))

    def test_row_order_and_malformed_output_are_killed(self) -> None:
        mutations = (
            b"category,total\nzeta,4\nalpha,5\n",
            b'category,total\n"unterminated,5\n',
            b"category,total\nalpha,5,extra\nzeta,4\n",
            b"category,total\nalpha,\xff\nzeta,4\n",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with tempfile.TemporaryDirectory() as temporary:
                    suite, instance = materialize_at(
                        CSV_TOTALS_FAMILY, 0, Path(temporary), answer=True
                    )
                    report = instance.workspace / OUTPUT_ROOT / "totals.csv"
                    report.write_bytes(mutation)
                    result = suite.verify(instance)
                self.assertFalse(result.passed)
                self.assertIn("output_entry_mismatch", failure_codes(result))


class ChecksumModeMutationTests(unittest.TestCase):
    def test_key_order_and_unicode_escape_variants_are_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, instance = materialize_at(
                CHECKSUM_MODE_FAMILY, 4, Path(temporary), answer=True
            )
            report = instance.workspace / OUTPUT_ROOT / "report.jsonl"
            records = [json.loads(line) for line in report.read_bytes().splitlines()]
            equivalent = (
                "\n".join(
                    json.dumps(
                        {"status": item["status"], "path": item["path"]},
                        ensure_ascii=True,
                        separators=(",", ":"),
                    )
                    for item in records
                )
                + "\n"
            ).encode("ascii")
            report.write_bytes(equivalent)
            result = suite.verify(instance)
        self.assertTrue(result.passed, result.to_record())

    def test_jsonl_shape_types_statuses_and_record_order_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, instance = materialize_at(
                CHECKSUM_MODE_FAMILY, 0, Path(temporary), answer=True
            )
            reference = (
                instance.workspace / OUTPUT_ROOT / "report.jsonl"
            ).read_bytes()
        lines = reference.splitlines()
        first = json.loads(lines[0])
        second = json.loads(lines[1])
        mutations = (
            (
                json.dumps(
                    {"path": first["path"], "status": first["status"], "extra": "x"},
                    separators=(",", ":"),
                ).encode()
                + b"\n"
                + lines[1]
                + b"\n"
            ),
            b'{"path":1,"status":"ok"}\n' + lines[1] + b"\n",
            (
                json.dumps(
                    {"path": first["path"], "status": "invented"},
                    separators=(",", ":"),
                ).encode()
                + b"\n"
                + lines[1]
                + b"\n"
            ),
            lines[1] + b"\n" + lines[0] + b"\n",
            reference.rstrip(b"\n"),
            reference.replace(b"\n", b"\r\n"),
            b'{"path":"a.txt","status":"ok"}\n\xff\n',
            (
                b'{"path":'
                + json.dumps(first["path"]).encode()
                + b',"path":'
                + json.dumps(first["path"]).encode()
                + b',"status":"ok"}\n'
                + lines[1]
                + b"\n"
            ),
        )
        self.assertNotEqual(first, second)
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with tempfile.TemporaryDirectory() as temporary:
                    suite, instance = materialize_at(
                        CHECKSUM_MODE_FAMILY,
                        0,
                        Path(temporary),
                        answer=True,
                    )
                    report = instance.workspace / OUTPUT_ROOT / "report.jsonl"
                    report.write_bytes(mutation)
                    result = suite.verify(instance)
                self.assertFalse(result.passed)
                self.assertIn("output_entry_mismatch", failure_codes(result))

    def test_checksum_status_mutation_is_killed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, instance = materialize_at(
                CHECKSUM_MODE_FAMILY, 1, Path(temporary), answer=True
            )
            report = instance.workspace / OUTPUT_ROOT / "report.jsonl"
            report.write_bytes(b'{"path":"changed.txt","status":"ok"}\n')
            result = suite.verify(instance)
        self.assertFalse(result.passed)
        self.assertIn("output_entry_mismatch", failure_codes(result))

    def test_mode_and_checksum_axes_cannot_be_collapsed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, instance = materialize_at(
                CHECKSUM_MODE_FAMILY, 2, Path(temporary), answer=True
            )
            report = instance.workspace / OUTPUT_ROOT / "report.jsonl"
            report.write_bytes(
                b'{"path":"both.txt","status":"checksum_mismatch"}\n'
                b'{"path":"mode.txt","status":"ok"}\n'
            )
            result = suite.verify(instance)
        self.assertFalse(result.passed)
        self.assertIn("output_entry_mismatch", failure_codes(result))

    def test_unreadable_precedence_is_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, instance = materialize_at(
                CHECKSUM_MODE_FAMILY, 4, Path(temporary), answer=True
            )
            report = instance.workspace / OUTPUT_ROOT / "report.jsonl"
            payload = report.read_bytes().replace(
                b'"status":"unreadable"', b'"status":"ok"'
            )
            report.write_bytes(payload)
            result = suite.verify(instance)
        self.assertFalse(result.passed)
        self.assertIn("output_entry_mismatch", failure_codes(result))


class SharedTrustBoundaryTests(unittest.TestCase):
    def test_input_mutation_and_top_level_scratch_are_killed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, instance = materialize_at(
                CSV_TOTALS_FAMILY, 0, Path(temporary), answer=True
            )
            source = instance.workspace / "input/records/a.csv"
            source.write_bytes(source.read_bytes() + b"late,1,yes\n")
            (instance.workspace / "scratch.tmp").write_bytes(b"left behind")
            result = suite.verify(instance)
        self.assertFalse(result.passed)
        self.assertIn("input_entry_changed", failure_codes(result))
        self.assertIn("unexpected_path", failure_codes(result))

    def test_output_root_symlink_is_rejected_without_following(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            suite, instance = materialize_at(CSV_TOTALS_FAMILY, 0, root)
            outside = root / "outside"
            outside.mkdir()
            (outside / "totals.csv").write_bytes(
                suite.trusted_reference_files(instance)["totals.csv"]
            )
            (instance.workspace / OUTPUT_ROOT).symlink_to(
                outside, target_is_directory=True
            )
            result = suite.verify(instance)
        self.assertFalse(result.passed)
        self.assertIn("output_not_directory", failure_codes(result))

    def test_output_replacement_race_is_detected_without_reading_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            suite, instance = materialize_at(
                CSV_TOTALS_FAMILY, 0, root, answer=True
            )
            report = instance.workspace / OUTPUT_ROOT / "totals.csv"
            victim = root / "outside-secret"
            victim.write_bytes(b"SEALED_SECRET_MUST_NOT_BE_READ")
            original_read = os.read
            swapped = False
            victim_read = False

            def racing_read(descriptor: int, size: int) -> bytes:
                nonlocal swapped, victim_read
                try:
                    opened = Path(f"/proc/self/fd/{descriptor}").resolve(
                        strict=True
                    )
                except OSError:
                    opened = None
                if opened == victim:
                    victim_read = True
                if not swapped and opened == report:
                    swapped = True
                    report.unlink()
                    report.symlink_to(victim)
                return original_read(descriptor, size)

            with mock.patch.object(families._safe.os, "read", side_effect=racing_read):
                result = suite.verify(instance)
        self.assertTrue(swapped)
        self.assertFalse(victim_read)
        self.assertFalse(result.passed)
        self.assertIn("output_scan_error", failure_codes(result))

    def test_semantic_a_b_a_race_cannot_validate_different_scanned_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, instance = materialize_at(
                CSV_TOTALS_FAMILY, 0, Path(temporary), answer=True
            )
            report = instance.workspace / OUTPUT_ROOT / "totals.csv"
            wrong = b"category,total\nalpha,6\nzeta,4\n"
            correct = b"category,total\nalpha,5\nzeta,4\n"
            self.assertEqual(len(wrong), len(correct))
            report.write_bytes(wrong)
            fixed_time = report.stat(follow_symlinks=False)
            original_read = families._read_relative_regular
            raced = False

            def racing_semantic_read(
                root_descriptor: int, relative_text: str
            ) -> tuple[bytes, os.stat_result]:
                nonlocal raced
                report.write_bytes(correct)
                os.utime(
                    report,
                    ns=(fixed_time.st_atime_ns, fixed_time.st_mtime_ns),
                    follow_symlinks=False,
                )
                payload, metadata = original_read(
                    root_descriptor, relative_text
                )
                report.write_bytes(wrong)
                os.utime(
                    report,
                    ns=(fixed_time.st_atime_ns, fixed_time.st_mtime_ns),
                    follow_symlinks=False,
                )
                raced = True
                return payload, metadata

            with mock.patch.object(
                families,
                "_read_relative_regular",
                side_effect=racing_semantic_read,
            ):
                result = suite.verify(instance)

            self.assertTrue(raced)
            self.assertEqual(report.read_bytes(), wrong)

        self.assertFalse(result.passed)
        self.assertIn("output_scan_error", failure_codes(result))
        self.assertIn("output_entry_mismatch", failure_codes(result))

    def test_verification_is_read_only_for_mode_unreadable_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, instance = materialize_at(
                CHECKSUM_MODE_FAMILY, 4, Path(temporary), answer=True
            )
            locked = instance.workspace / "input/assets/-잠금 [x]*?.bin"
            pinned = next(
                item
                for item in instance._pinned_regulars
                if item.path == "input/assets/-잠금 [x]*?.bin"
            )
            before_stat = locked.stat(follow_symlinks=False)
            before = (
                before_stat.st_dev,
                before_stat.st_ino,
                stat.S_IMODE(before_stat.st_mode),
                before_stat.st_nlink,
                before_stat.st_size,
                before_stat.st_mtime_ns,
                before_stat.st_ctime_ns,
            )
            before_bytes = os.pread(
                pinned.descriptor, before_stat.st_size, 0
            )

            first = suite.verify(instance)
            second = suite.verify(instance)

            after_stat = locked.stat(follow_symlinks=False)
            after = (
                after_stat.st_dev,
                after_stat.st_ino,
                stat.S_IMODE(after_stat.st_mode),
                after_stat.st_nlink,
                after_stat.st_size,
                after_stat.st_mtime_ns,
                after_stat.st_ctime_ns,
            )
            after_bytes = os.pread(pinned.descriptor, after_stat.st_size, 0)

        self.assertTrue(first.passed, first.to_record())
        self.assertEqual(first, second)
        self.assertEqual(before, after)
        self.assertEqual(before_bytes, after_bytes)

    def test_aggregate_and_per_entry_output_limits_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, instance = materialize_at(
                CHECKSUM_MODE_FAMILY, 0, Path(temporary), answer=True
            )
            huge = instance.workspace / OUTPUT_ROOT / "huge.sparse"
            with huge.open("wb") as handle:
                handle.truncate(families._safe.MAX_TREE_TOTAL_BYTES + 1)
            huge.chmod(OUTPUT_FILE_MODE)
            result = suite.verify(instance)
        self.assertFalse(result.passed)
        self.assertIn("output_scan_error", failure_codes(result))
        self.assertIn("output_file_unreadable_or_oversized", failure_codes(result))
        self.assertIn("unexpected_output_path", failure_codes(result))

    def test_output_root_and_nested_directory_modes_are_properties(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, instance = materialize_at(
                COPY_MAP_FAMILY, 0, Path(temporary), answer=True
            )
            (instance.workspace / OUTPUT_ROOT).chmod(0o700)
            (instance.workspace / OUTPUT_ROOT / "deep").chmod(0o700)
            result = suite.verify(instance)
        self.assertFalse(result.passed)
        self.assertIn("output_root_mode_mismatch", failure_codes(result))
        self.assertIn("output_entry_mismatch", failure_codes(result))

    def test_result_is_machine_serializable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, instance = materialize_at(
                CHECKSUM_MODE_FAMILY, 0, Path(temporary)
            )
            result = suite.verify(instance)
        self.assertFalse(result.passed)
        self.assertIn("output_missing", failure_codes(result))
        json.dumps(result.to_record(), allow_nan=False)


if __name__ == "__main__":
    unittest.main()
