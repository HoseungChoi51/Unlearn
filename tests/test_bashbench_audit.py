from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.bashbench_audit import (  # noqa: E402
    BashBenchAuditError,
    BashBenchSource,
    COMMAND_EVALUATION,
    COMMAND_HARNESS,
    COMMAND_TEST_CASES,
    REQUIRED_MEMBERS,
    SCRIPT_EVALUATION,
    SCRIPT_HARNESS,
    SCRIPT_TEST_CASES,
    audit_bashbench_projection,
    compute_bashbench_audit_sha256,
    validate_bashbench_audit_report,
    verify_bashbench_audit_sha256,
)


SOURCE_FIELDS: dict[str, object] = {
    "record_id": 18408692,
    "record_revision": 4,
    "record_url": "https://zenodo.org/records/18408692",
    "archive_key": "BashCoder-R1.zip",
    "archive_size_bytes": 1_108_526_600,
    "archive_declared_md5": "e2cef192c89ee8f14fe4c59152f213bf",
    "license_id": "cc-by-4.0",
}


def real_source() -> BashBenchSource:
    return BashBenchSource.release_v1()


class SyntheticProjection:
    """A tiny projection with the same six path identities as the release."""

    def __init__(self, root: Path, *, sentinel: Path | None = None) -> None:
        self.root = root
        sentinel_text = str(sentinel) if sentinel is not None else "must-not-exist"
        self.payloads: dict[str, bytes] = {
            COMMAND_EVALUATION: self.json_bytes(
                [
                    {"input": "list txt"},
                    {"input": "duplicate prompt"},
                    {"input": "duplicate prompt"},
                ]
            ),
            SCRIPT_EVALUATION: self.json_bytes(
                [{"input": "script one"}, {"input": "script two"}]
            ),
            COMMAND_TEST_CASES: self.json_bytes(
                [
                    {
                        "sample_id": 0,
                        "input": "list txt",
                        "validated": True,
                        "test_case": {
                            "test_script": (
                                "#!/usr/bin/env bash\n"
                                f"touch {sentinel_text!r}\n"
                                "./solution.sh --verify\n"
                                "printf '%s\\n' TEST_PASSED\n"
                            ),
                            "is_safe_to_execute": True,
                        },
                    },
                    {
                        "sample_id": 7,
                        "input": "unrelated prompt",
                        "validated": False,
                        "test_case": {
                            "test_script": (
                                "#!/usr/bin/env bash\n"
                                "bash \"$1\"\n"
                                "curl example.invalid\n"
                                "sudo true\n"
                            ),
                            "is_safe_to_execute": False,
                        },
                    },
                    {
                        "sample_id": 7,
                        "input": "duplicate prompt",
                        "validated": None,
                        "test_case": None,
                    },
                ]
            ),
            SCRIPT_TEST_CASES: self.json_bytes(
                [
                    {
                        "sample_id": 10,
                        "input": "script two",
                        "validated": True,
                        "test_case": {
                            "test_script": "printf '%s\\n' TEST_PASSED\n",
                            "is_safe_to_execute": True,
                        },
                    }
                ]
            ),
            COMMAND_HARNESS: self.harness_bytes(sentinel_text, "command"),
            SCRIPT_HARNESS: self.harness_bytes(sentinel_text, "script"),
        }
        self.materialize()

    @staticmethod
    def json_bytes(value: object) -> bytes:
        return json.dumps(value, ensure_ascii=False).encode("utf-8")

    @staticmethod
    def harness_bytes(sentinel: str, label: str) -> bytes:
        # Importing this source would raise after writing the sentinel.  Parsing
        # it as an AST, as the auditor does, is harmless.
        return (
            "from pathlib import Path\n"
            "import subprocess\n"
            f"Path({sentinel!r}).write_text({label!r}, encoding='utf-8')\n"
            "raise RuntimeError('the audit imported upstream code')\n"
            "\n"
            "def execute_test_script(test_path, candidate_path):\n"
            "    return subprocess.run(\n"
            "        ['bash', test_path], capture_output=True, cwd='.', text=True, timeout=30\n"
            "    )\n"
            "\n"
            "def materialize_candidate(candidate):\n"
            "    solution_path = 'solution.sh'\n"
            "    return solution_path, candidate\n"
        ).encode("utf-8")

    def materialize(self) -> None:
        for relative, payload in self.payloads.items():
            self.write(relative, payload)

    def write(self, relative: str, payload: bytes) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)

    def restore(self, relative: str) -> None:
        self.write(relative, self.payloads[relative])


class AuditProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "projection"
        self.sentinel = Path(self.temporary.name) / "upstream-executed"
        self.projection = SyntheticProjection(self.root, sentinel=self.sentinel)

    def audit(self) -> dict[str, object]:
        return audit_bashbench_projection(self.root, source=real_source())

    def test_audit_is_deterministic_self_hashed_and_non_authorizing(self) -> None:
        first = self.audit()
        second = self.audit()

        self.assertEqual(first, second)
        self.assertTrue(verify_bashbench_audit_sha256(first))
        self.assertEqual(
            first["audit_sha256"], compute_bashbench_audit_sha256(first)
        )
        self.assertEqual(validate_bashbench_audit_report(first), first)

        decision = first["decision"]
        self.assertIsInstance(decision, dict)
        self.assertEqual(
            decision["status"], "diagnostic_only_released_harness_rejected"
        )
        for name in (
            "benchmark_eligible",
            "candidate_execution_authorized",
            "model_selection_authorized",
            "claim_authorized",
        ):
            self.assertIs(decision[name], False)

        projection = first["member_projection"]
        self.assertIsInstance(projection, dict)
        self.assertEqual(projection["member_count"], 6)
        self.assertEqual(
            [item["path"] for item in projection["members"]],
            list(REQUIRED_MEMBERS),
        )
        self.assertIs(
            projection["archive_crc_members_rechecked_during_extraction"], False
        )
        self.assertIs(projection["all_members_match_expected_release_v1"], False)
        self.assertEqual(len(projection["expected_release_v1_members"]), 6)
        self.assertNotEqual(
            projection["selected_member_set_sha256"],
            projection["expected_release_v1_member_set_sha256"],
        )
        finding_codes = {item["code"] for item in first["findings"]}
        self.assertIn("selected_projection_not_release_v1_authenticated", finding_codes)

    def test_upstream_python_and_shell_are_never_imported_or_executed(self) -> None:
        report = self.audit()

        self.assertFalse(self.sentinel.exists())
        limitations = report["limitations"]
        self.assertTrue(
            any("executed or imported" in limitation for limitation in limitations)
        )
        for label in ("command", "script"):
            harness = report["released_harness"][label]
            self.assertIs(harness["python_ast_parsed"], True)
            self.assertEqual(harness["execute_test_script_definitions"], 1)
            self.assertEqual(
                harness["execute_test_script_subprocess_invocations"],
                [
                    {
                        "callee": "subprocess.run",
                        "first_argument": ["bash", {"name": "test_path"}],
                        "keyword_names": ["capture_output", "cwd", "text", "timeout"],
                    }
                ],
            )

    def test_reports_candidate_handoff_strings_but_never_proves_handoff(self) -> None:
        report = self.audit()
        released = report["released_data"]
        command_tests = released["command"]["tests"]
        script_tests = released["script"]["tests"]

        self.assertEqual(
            command_tests["candidate_handoff_scan"],
            {
                "literal_solution_sh_references": 1,
                "positional_parameter_lexeme_scripts": 1,
                "scripts_with_test_passed_marker": 1,
            },
        )
        self.assertEqual(
            script_tests["candidate_handoff_scan"]["scripts_with_test_passed_marker"],
            1,
        )
        self.assertEqual(
            command_tests["risk_lexemes"],
            {
                "network_or_package_tool_scripts": 1,
                "privileged_or_service_tool_scripts": 1,
            },
        )

        handoff = report["released_harness"]["candidate_handoff"]
        self.assertEqual(handoff["literal_solution_sh_references_across_test_scripts"], 1)
        self.assertEqual(handoff["harness_candidate_arguments_after_test_path"], 0)
        self.assertIs(handoff["both_harnesses_launch_only_bash_test_path"], True)
        self.assertIs(handoff["candidate_handoff_proven"], False)

    def test_alignment_and_duplicate_evidence_is_derived_from_records(self) -> None:
        report = self.audit()
        command = report["released_data"]["command"]
        alignment = command["alignment"]

        self.assertEqual(alignment["evaluation_records"], 3)
        self.assertEqual(alignment["test_records"], 3)
        self.assertEqual(
            alignment["evaluation_prompt_duplicates"],
            {
                "records": 3,
                "unique_values": 2,
                "duplicate_records_beyond_first": 1,
                "duplicate_groups": 1,
                "maximum_multiplicity": 2,
            },
        )
        self.assertEqual(alignment["index_aligned_prompt_matches"], 2)
        self.assertEqual(alignment["test_records_with_prompt_anywhere_in_evaluation"], 2)
        self.assertEqual(alignment["unique_prompt_intersection"], 2)
        self.assertEqual(alignment["unique_evaluation_only"], 0)
        self.assertEqual(alignment["unique_test_only"], 1)
        self.assertEqual(
            command["tests"]["sample_ids"],
            {
                "integer_ids": 3,
                "unique_integer_ids": 2,
                "minimum_integer_id": 0,
                "maximum_integer_id": 7,
                "id_equals_list_index": 1,
            },
        )
        self.assertEqual(
            command["tests"]["test_case_presence"],
            {"present_nonempty": 2, "missing_or_empty": 1},
        )
        self.assertEqual(
            command["tests"]["is_safe_to_execute_values"],
            {"false": 1, "null": 1, "true": 1},
        )

    def test_strict_json_rejects_duplicates_nonfinite_invalid_utf8_and_shape(self) -> None:
        malformed_payloads = (
            b'[{"input":"first","input":"second"}]',
            b'[{"input":"x","score":NaN}]',
            b'[{"input":"\xff"}]',
            b'{"input":"not-a-list"}',
            b'["not-an-object"]',
        )
        for payload in malformed_payloads:
            with self.subTest(payload=payload):
                self.projection.write(COMMAND_EVALUATION, payload)
                with self.assertRaises(BashBenchAuditError):
                    self.audit()
                self.projection.restore(COMMAND_EVALUATION)

    def test_json_record_fields_and_test_case_shape_fail_closed(self) -> None:
        malformed_values = (
            [{"input": 123}],
            [
                {
                    "sample_id": 0,
                    "input": "x",
                    "validated": True,
                    "test_case": "shell text is not an object",
                }
            ],
            [
                {
                    "sample_id": 0,
                    "input": "x",
                    "validated": True,
                    "test_case": {"test_script": 123, "is_safe_to_execute": True},
                }
            ],
        )
        for index, value in enumerate(malformed_values):
            with self.subTest(index=index):
                member = COMMAND_EVALUATION if index == 0 else COMMAND_TEST_CASES
                self.projection.write(member, SyntheticProjection.json_bytes(value))
                with self.assertRaises(BashBenchAuditError):
                    self.audit()
                self.projection.restore(member)

    def test_required_member_symlink_and_missing_member_are_rejected(self) -> None:
        required = self.root / COMMAND_EVALUATION
        original = required.read_bytes()
        required.unlink()
        target = required.parent / "redirected.json"
        target.write_bytes(original)
        required.symlink_to(target.name)
        with self.assertRaises(BashBenchAuditError):
            self.audit()

        required.unlink()
        with self.assertRaises(BashBenchAuditError):
            self.audit()

    def test_unparseable_python_harness_is_rejected_without_execution(self) -> None:
        self.projection.write(COMMAND_HARNESS, b"def execute_test_script(:\n")
        with self.assertRaises(BashBenchAuditError):
            self.audit()
        self.assertFalse(self.sentinel.exists())


class ReportValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name) / "projection"
        SyntheticProjection(root)
        self.report = audit_bashbench_projection(root, source=real_source())

    @staticmethod
    def rehash(report: dict[str, object]) -> dict[str, object]:
        report["audit_sha256"] = compute_bashbench_audit_sha256(report)
        return report

    def test_tampering_is_rejected_even_when_authorization_tamper_is_rehashed(self) -> None:
        plain_tamper = copy.deepcopy(self.report)
        plain_tamper["limitations"].append("tampered")
        with self.assertRaises(BashBenchAuditError):
            validate_bashbench_audit_report(plain_tamper)

        authorization_tamper = copy.deepcopy(self.report)
        authorization_tamper["decision"]["claim_authorized"] = True
        self.rehash(authorization_tamper)
        self.assertTrue(verify_bashbench_audit_sha256(authorization_tamper))
        with self.assertRaises(BashBenchAuditError):
            validate_bashbench_audit_report(authorization_tamper)

    def test_malformed_identity_keys_decision_and_hash_are_rejected(self) -> None:
        cases: list[dict[str, object] | object] = []

        missing = copy.deepcopy(self.report)
        del missing["findings"]
        cases.append(missing)

        extra = copy.deepcopy(self.report)
        extra["unexpected"] = False
        cases.append(extra)

        wrong_identity = copy.deepcopy(self.report)
        wrong_identity["record_type"] = "cbds.not-the-audit"
        cases.append(self.rehash(wrong_identity))

        malformed_decision = copy.deepcopy(self.report)
        malformed_decision["decision"]["unexpected"] = False
        cases.append(self.rehash(malformed_decision))

        malformed_hash = copy.deepcopy(self.report)
        malformed_hash["audit_sha256"] = "A" * 64
        cases.append(malformed_hash)

        cases.extend(([], "not an object", None))
        for index, value in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(BashBenchAuditError):
                    validate_bashbench_audit_report(value)

    def test_rehashed_source_and_member_provenance_tampering_is_rejected(self) -> None:
        source_tamper = copy.deepcopy(self.report)
        source_tamper["source"]["record_id"] = 1
        self.rehash(source_tamper)
        with self.assertRaisesRegex(BashBenchAuditError, "source identity"):
            validate_bashbench_audit_report(source_tamper)

        expected_tamper = copy.deepcopy(self.report)
        expected_tamper["member_projection"]["expected_release_v1_members"][0][
            "sha256"
        ] = "0" * 64
        expected_tamper["member_projection"][
            "expected_release_v1_member_set_sha256"
        ] = "0" * 64
        self.rehash(expected_tamper)
        with self.assertRaisesRegex(BashBenchAuditError, "expected release"):
            validate_bashbench_audit_report(expected_tamper)

        observed_tamper = copy.deepcopy(self.report)
        observed_tamper["member_projection"]["members"][0]["sha256"] = "0" * 64
        observed_tamper["member_projection"]["selected_member_set_sha256"] = "0" * 64
        self.rehash(observed_tamper)
        with self.assertRaisesRegex(BashBenchAuditError, "selected member commitment"):
            validate_bashbench_audit_report(observed_tamper)

    def test_authenticated_projection_requirement_rejects_synthetic_bytes(self) -> None:
        self.assertEqual(validate_bashbench_audit_report(self.report), self.report)
        with self.assertRaisesRegex(BashBenchAuditError, "not authenticated"):
            validate_bashbench_audit_report(
                self.report, require_authenticated_projection=True
            )


class SourceIdentityTests(unittest.TestCase):
    def test_known_release_identity_is_preserved_without_claiming_archive_rehash(self) -> None:
        source = real_source()
        self.assertEqual(BashBenchSource.release_v1(), source)
        record = source.to_record()
        self.assertEqual(
            record,
            {
                **SOURCE_FIELDS,
                "archive_digest_source": "zenodo_record_metadata",
                "full_archive_digest_recomputed": False,
            },
        )

    def test_source_rejects_invalid_identity_fields(self) -> None:
        cases = (
            {"record_id": True},
            {"record_id": 0},
            {"record_id": 18_408_691},
            {"record_id": 18_408_692.0},
            {"record_revision": True},
            {"record_revision": 0},
            {"record_revision": 5},
            {"record_revision": 4.0},
            {"record_url": "http://zenodo.org/records/18408692"},
            {"record_url": "https://example.com/records/18408692"},
            {"archive_key": "renamed.zip"},
            {"archive_size_bytes": True},
            {"archive_size_bytes": 0},
            {"archive_size_bytes": 1_108_526_599},
            {"archive_size_bytes": 1_108_526_600.0},
            {"archive_declared_md5": "E2CEF192C89EE8F14FE4C59152F213BF"},
            {"archive_declared_md5": "0" * 31},
            {"archive_declared_md5": "0" * 32},
            {"license_id": "mit"},
        )
        for changes in cases:
            fields = dict(SOURCE_FIELDS)
            fields.update(changes)
            with self.subTest(changes=changes):
                with self.assertRaises(BashBenchAuditError):
                    BashBenchSource(**fields)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
