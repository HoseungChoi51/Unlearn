from __future__ import annotations

import copy
import hashlib
from importlib.resources import files as resource_files
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import cbds.task_results as task_results_module
from cbds.task_results import (
    TASK_RESULT_SCHEMA_VERSION,
    TaskResultValidationError,
    fixture_id_set_sha256,
    load_task_result,
    task_result_sha256,
    ordered_fixture_ids_sha256,
    validate_task_result,
    write_task_result,
)


def digest(character: str) -> str:
    return character * 64


def opaque_task_id(label: str) -> str:
    return "task-" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def opaque_fixture_id(label: str) -> str:
    return "fixture-" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def passed_fixture(index: int) -> dict[str, object]:
    return {
        "fixture_id": opaque_fixture_id(f"static-task-001-fx-{index:02d}"),
        "status": "passed",
        "exit_code": 0,
        "stdout_sha256": digest("2"),
        "stderr_sha256": None,
        "stdout_bytes": 10 + index,
        "stderr_bytes": 0,
        "wall_time_ms": 4.5 + index,
        "cpu_time_ms": 2.0 + index,
        "peak_rss_bytes": 8_388_608 + index,
        "peak_workspace_bytes": 4096 + index,
        "peak_pids": 2,
        "peak_open_files": 5,
        "verifier_result_sha256": digest("4"),
    }


def sync_resource_use(result: dict[str, object]) -> None:
    invocations = [
        fixture
        for fixture in result["fixture_outcomes"]  # type: ignore[index]
        if fixture["status"] != "not_run"
    ] + [
        action
        for action in result["action_trace"]  # type: ignore[index]
        if action["status"] in {"passed", "timeout", "runtime_failure", "resource_limit"}
    ]
    if not invocations:
        result["resource_use"] = {
            "container_started": False,
            "scope": "maximum_over_fixture_and_action_invocations",
            "measurement_method": "cgroup-v2-procfs-rusage-v1",
            "measurement_report_sha256": None,
            "wall_time_ms": 0,
            "cpu_time_ms": None,
            "peak_rss_bytes": None,
            "stdout_bytes": 0,
            "stderr_bytes": 0,
            "peak_workspace_bytes": None,
            "peak_pids": None,
            "peak_open_files": None,
            "timed_out": False,
        }
        return
    result["resource_use"] = {
        "container_started": True,
        "scope": "maximum_over_fixture_and_action_invocations",
        "measurement_method": "cgroup-v2-procfs-rusage-v1",
        "measurement_report_sha256": digest("e"),
        **{
            field: max(invocation[field] for invocation in invocations)
            for field in (
                "wall_time_ms",
                "cpu_time_ms",
                "peak_rss_bytes",
                "stdout_bytes",
                "stderr_bytes",
                "peak_workspace_bytes",
                "peak_pids",
                "peak_open_files",
            )
        },
        "timed_out": any(invocation["status"] == "timeout" for invocation in invocations),
    }


def static_result() -> dict[str, object]:
    fixtures = [passed_fixture(index) for index in range(5)]
    result: dict[str, object] = {
        "schema_version": TASK_RESULT_SCHEMA_VERSION,
        "evaluation_id": "method-development-evaluation-0001",
        "evaluation_spec_sha256": digest("e"),
        "run_id": "screening-seed-001",
        "benchmark_id": "cbds-static-v1",
        "prompt_id": opaque_task_id("static-task-001"),
        "task_record_sha256": digest("1"),
        "fixture_ids_sha256": fixture_id_set_sha256(
            fixture["fixture_id"] for fixture in fixtures
        ),
        "ordered_fixture_ids_sha256": ordered_fixture_ids_sha256(
            fixture["fixture_id"] for fixture in fixtures
        ),
        "mode": "static",
        "split_id": "method_development",
        "split_role": "method_development",
        "sealed": False,
        "attempt": 1,
        "prior_attempt_terminal_statuses": [],
        "prior_attempt_result_sha256s": [],
        "action_limit": 0,
        "prompt_tokens": 12,
        "generated_tokens": 6,
        "generated_text_sha256": digest("a"),
        "generated_text_bytes": 24,
        "extraction": {
            "status": "ok",
            "language": "bash",
            "code_sha256": digest("b"),
            "fenced": False,
            "response_bytes": 24,
            "code_bytes": 24,
            "detail_code": None,
        },
        "syntax": {
            "status": "ok",
            "return_code": 0,
            "diagnostic_sha256": None,
        },
        "syntax_duration_ms": 1.25,
        "tool_policy": {
            "status": "allowed",
            "policy_sha256": digest("c"),
            "observed_tools": ["bash", "printf"],
            "disallowed_tools": [],
            "diagnostic_sha256": None,
        },
        "infrastructure_error": None,
        "fixture_outcomes": fixtures,
        "resource_use": {},
        "action_trace": [],
        "terminal_status": "passed",
    }
    sync_resource_use(result)
    return result


def set_not_run(fixture: dict[str, object]) -> None:
    fixture.update(
        {
            "status": "not_run",
            "exit_code": None,
            "stdout_sha256": None,
            "stderr_sha256": None,
            "stdout_bytes": 0,
            "stderr_bytes": 0,
            "wall_time_ms": None,
            "cpu_time_ms": None,
            "peak_rss_bytes": None,
            "peak_workspace_bytes": None,
            "peak_pids": None,
            "peak_open_files": None,
            "verifier_result_sha256": None,
        }
    )


def set_no_execution(result: dict[str, object]) -> None:
    for fixture in result["fixture_outcomes"]:  # type: ignore[index]
        set_not_run(fixture)
    sync_resource_use(result)


def interactive_result() -> dict[str, object]:
    result = static_result()
    result.update(
        {
            "benchmark_id": "cbds-interactive-v1",
            "prompt_id": opaque_task_id("interactive-task-001"),
            "task_record_sha256": digest("d"),
            "mode": "interactive",
            "action_limit": 8,
            "fixture_outcomes": [
                {
                    **passed_fixture(0),
                    "fixture_id": opaque_fixture_id(
                        "interactive-task-001-final-state"
                    ),
                }
            ],
            "action_trace": [
                {
                    "action_index": 0,
                    "action_sha256": digest("5"),
                    "status": "passed",
                    "exit_code": 0,
                    "stdout_sha256": digest("6"),
                    "stderr_sha256": None,
                    "stdout_bytes": 12,
                    "stderr_bytes": 0,
                    "wall_time_ms": 3.0,
                    "cpu_time_ms": 1.5,
                    "peak_rss_bytes": 8_000_000,
                    "peak_workspace_bytes": 2048,
                    "peak_pids": 2,
                    "peak_open_files": 4,
                    "observation_bytes": 12,
                },
                {
                    "action_index": 1,
                    "action_sha256": digest("8"),
                    "status": "passed",
                    "exit_code": 0,
                    "stdout_sha256": digest("9"),
                    "stderr_sha256": None,
                    "stdout_bytes": 8,
                    "stderr_bytes": 0,
                    "wall_time_ms": 2.0,
                    "cpu_time_ms": 1.0,
                    "peak_rss_bytes": 7_000_000,
                    "peak_workspace_bytes": 1024,
                    "peak_pids": 2,
                    "peak_open_files": 4,
                    "observation_bytes": 8,
                },
            ],
        }
    )
    result["fixture_ids_sha256"] = fixture_id_set_sha256(
        fixture["fixture_id"] for fixture in result["fixture_outcomes"]
    )
    result["ordered_fixture_ids_sha256"] = ordered_fixture_ids_sha256(
        fixture["fixture_id"] for fixture in result["fixture_outcomes"]
    )
    sync_resource_use(result)
    return result


class TaskResultValidationTests(unittest.TestCase):
    def test_external_schema_cannot_weaken_the_frozen_contract(self) -> None:
        schema = json.loads(
            resource_files("cbds.schemas")
            .joinpath("task-result.schema.json")
            .read_text(encoding="utf-8")
        )
        schema["additionalProperties"] = True
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "weakened.schema.json"
            path.write_text(json.dumps(schema), encoding="utf-8")
            with self.assertRaisesRegex(
                TaskResultValidationError, "frozen packaged"
            ):
                validate_task_result(static_result(), schema_path=path)

    def test_valid_static_result_and_defensive_copy(self) -> None:
        original = static_result()
        validated = validate_task_result(original)
        self.assertEqual(validated, original)
        self.assertIsNot(validated, original)
        validated["fixture_outcomes"][0]["status"] = "functional_failure"
        self.assertEqual(original["fixture_outcomes"][0]["status"], "passed")

    def test_valid_interactive_result(self) -> None:
        validated = validate_task_result(interactive_result())
        self.assertEqual(validated["mode"], "interactive")
        self.assertEqual(len(validated["action_trace"]), 2)

    def test_prior_attempt_history_is_complete(self) -> None:
        candidate = static_result()
        candidate["attempt"] = 2
        with self.assertRaisesRegex(
            TaskResultValidationError, "one status for every earlier attempt"
        ):
            validate_task_result(candidate)

        candidate["prior_attempt_terminal_statuses"] = ["internal_error"]
        candidate["prior_attempt_result_sha256s"] = [digest("f")]
        validate_task_result(candidate)

    def test_schema_rejects_text_unknown_fields_and_bad_hashes(self) -> None:
        for field, value in (
            ("prompt", "sealed prompt text"),
            ("generated_text", "printf hello"),
            ("fixture_text", {"secret": True}),
        ):
            with self.subTest(field=field):
                candidate = static_result()
                candidate[field] = value
                with self.assertRaisesRegex(
                    TaskResultValidationError, "additional property"
                ):
                    validate_task_result(candidate)

        candidate = static_result()
        candidate["generated_text_sha256"] = "not-a-digest"
        with self.assertRaisesRegex(TaskResultValidationError, "required pattern"):
            validate_task_result(candidate)

        for payload in ("curl /sealed/prompt", "../secret", "tool name"):
            with self.subTest(tool_payload=payload):
                candidate = static_result()
                candidate["tool_policy"]["observed_tools"] = [payload]
                with self.assertRaises(TaskResultValidationError):
                    validate_task_result(candidate)

    def test_static_requires_five_fixtures_and_no_action_trace(self) -> None:
        too_few = static_result()
        too_few["fixture_outcomes"] = too_few["fixture_outcomes"][:4]
        with self.assertRaisesRegex(TaskResultValidationError, "at least five"):
            validate_task_result(too_few)

        with_action = static_result()
        with_action["action_trace"] = interactive_result()["action_trace"][:1]
        with self.assertRaisesRegex(TaskResultValidationError, "cannot contain actions"):
            validate_task_result(with_action)

    def test_interactive_action_limit_and_indices_are_strict(self) -> None:
        wrong_limit = interactive_result()
        wrong_limit["action_limit"] = 7
        with self.assertRaisesRegex(TaskResultValidationError, "frozen limit of eight"):
            validate_task_result(wrong_limit)

        wrong_index = interactive_result()
        wrong_index["action_trace"][1]["action_index"] = 3
        with self.assertRaisesRegex(TaskResultValidationError, "contiguous from zero"):
            validate_task_result(wrong_index)

        repeated_action = interactive_result()
        repeated_action["action_trace"][1]["action_sha256"] = digest("5")
        validate_task_result(repeated_action)

    def test_action_limit_requires_eight_completed_actions(self) -> None:
        candidate = interactive_result()
        template = candidate["action_trace"][0]
        candidate["action_trace"] = [
            {**template, "action_index": index, "action_sha256": digest("5")}
            for index in range(8)
        ]
        set_not_run(candidate["fixture_outcomes"][0])
        candidate["terminal_status"] = "action_limit"
        sync_resource_use(candidate)
        validate_task_result(candidate)

        failed_action = copy.deepcopy(candidate)
        failed_action["action_trace"][-1].update(
            {
                "status": "runtime_failure",
                "exit_code": 1,
            }
        )
        with self.assertRaisesRegex(TaskResultValidationError, "completed actions"):
            validate_task_result(failed_action)

    def test_interactive_execution_failure_must_be_the_final_action(self) -> None:
        candidate = interactive_result()
        set_not_run(candidate["fixture_outcomes"][0])
        candidate["action_trace"][0].update(
            {
                "status": "timeout",
                "exit_code": 124,
            }
        )
        candidate["terminal_status"] = "timeout"
        sync_resource_use(candidate)
        with self.assertRaisesRegex(
            TaskResultValidationError, "sole final non-passing action"
        ):
            validate_task_result(candidate)

    def test_preexecution_failure_requires_consistent_stage_order(self) -> None:
        candidate = static_result()
        candidate["extraction"] = {
            "status": "extraction_failure",
            "language": None,
            "code_sha256": None,
            "fenced": None,
            "response_bytes": 24,
            "code_bytes": 0,
            "detail_code": "malformed_fence",
        }
        candidate["syntax"] = {
            "status": "not_run",
            "return_code": None,
            "diagnostic_sha256": None,
        }
        candidate["syntax_duration_ms"] = None
        candidate["tool_policy"] = {
            **candidate["tool_policy"],
            "status": "not_run",
            "observed_tools": [],
        }
        set_no_execution(candidate)
        candidate["terminal_status"] = "extraction_failure"
        validate_task_result(candidate)

        inconsistent = copy.deepcopy(candidate)
        inconsistent["syntax"]["status"] = "ok"
        with self.assertRaisesRegex(TaskResultValidationError, "must be 'not_run'"):
            validate_task_result(inconsistent)

    def test_disallowed_tool_requires_observation_and_matching_terminal(self) -> None:
        candidate = static_result()
        candidate["tool_policy"] = {
            "status": "disallowed_tool",
            "policy_sha256": digest("c"),
            "observed_tools": ["bash", "curl"],
            "disallowed_tools": ["curl"],
            "diagnostic_sha256": digest("d"),
        }
        set_no_execution(candidate)
        candidate["terminal_status"] = "disallowed_tool"
        validate_task_result(candidate)

        missing = copy.deepcopy(candidate)
        missing["tool_policy"]["observed_tools"] = ["bash"]
        with self.assertRaisesRegex(TaskResultValidationError, "must be observed"):
            validate_task_result(missing)

    def test_interactive_stage_failure_preserves_prior_action_trace(self) -> None:
        candidate = interactive_result()
        candidate["tool_policy"] = {
            "status": "disallowed_tool",
            "policy_sha256": digest("c"),
            "observed_tools": ["curl"],
            "disallowed_tools": ["curl"],
            "diagnostic_sha256": digest("d"),
        }
        set_not_run(candidate["fixture_outcomes"][0])
        candidate["action_trace"][1].update(
            {
                "status": "disallowed_tool",
                "exit_code": None,
                "stdout_sha256": None,
                "stderr_sha256": None,
                "stdout_bytes": 0,
                "stderr_bytes": 0,
                "wall_time_ms": None,
                "cpu_time_ms": None,
                "peak_rss_bytes": None,
                "peak_workspace_bytes": None,
                "peak_pids": None,
                "peak_open_files": None,
                "observation_bytes": 0,
            }
        )
        candidate["terminal_status"] = "disallowed_tool"
        sync_resource_use(candidate)
        validate_task_result(candidate)

        wrong_final = copy.deepcopy(candidate)
        wrong_final["action_trace"][1]["status"] = "syntax_failure"
        with self.assertRaisesRegex(TaskResultValidationError, "must match terminal_status"):
            validate_task_result(wrong_final)

    def test_terminal_status_matches_fixture_and_timeout_resources(self) -> None:
        candidate = static_result()
        set_not_run(candidate["fixture_outcomes"][1])
        set_not_run(candidate["fixture_outcomes"][2])
        set_not_run(candidate["fixture_outcomes"][3])
        set_not_run(candidate["fixture_outcomes"][4])
        candidate["fixture_outcomes"][0].update(
            {
                "status": "timeout",
                "exit_code": None,
                "verifier_result_sha256": None,
            }
        )
        candidate["terminal_status"] = "timeout"
        sync_resource_use(candidate)
        validate_task_result(candidate)

        inconsistent = copy.deepcopy(candidate)
        inconsistent["resource_use"]["timed_out"] = False
        with self.assertRaisesRegex(TaskResultValidationError, "invocation timeout evidence"):
            validate_task_result(inconsistent)

    def test_mixed_execution_failures_collapse_by_frozen_precedence(self) -> None:
        candidate = static_result()
        candidate["fixture_outcomes"][0].update(
            {
                "status": "timeout",
                "exit_code": None,
                "verifier_result_sha256": None,
            }
        )
        candidate["fixture_outcomes"][1]["status"] = "functional_failure"
        candidate["terminal_status"] = "timeout"
        sync_resource_use(candidate)
        validate_task_result(candidate)

        wrong = copy.deepcopy(candidate)
        wrong["terminal_status"] = "functional_failure"
        with self.assertRaisesRegex(
            TaskResultValidationError, "frozen precedence"
        ):
            validate_task_result(wrong)

    def test_internal_error_has_typed_evidence_and_no_completed_fixture(self) -> None:
        relabeled = static_result()
        relabeled["terminal_status"] = "internal_error"
        relabeled["infrastructure_error"] = {
            "stage": "fixture_setup",
            "diagnostic_sha256": digest("d"),
        }
        with self.assertRaisesRegex(
            TaskResultValidationError, "cannot relabel a completed fixture"
        ):
            validate_task_result(relabeled)

        valid = static_result()
        set_no_execution(valid)
        valid["terminal_status"] = "internal_error"
        valid["infrastructure_error"] = {
            "stage": "fixture_setup",
            "diagnostic_sha256": digest("d"),
        }
        validate_task_result(valid)

        fabricated = static_result()
        fabricated["infrastructure_error"] = {
            "stage": "fixture_setup",
            "diagnostic_sha256": digest("d"),
        }
        with self.assertRaisesRegex(
            TaskResultValidationError, "must be null unless"
        ):
            validate_task_result(fabricated)

    def test_verifier_failure_requires_hashed_failure_report(self) -> None:
        candidate = static_result()
        candidate["fixture_outcomes"][0]["status"] = "verifier_failure"
        candidate["terminal_status"] = "verifier_failure"
        sync_resource_use(candidate)
        validate_task_result(candidate)

        missing = copy.deepcopy(candidate)
        missing["fixture_outcomes"][0]["verifier_result_sha256"] = None
        with self.assertRaisesRegex(
            TaskResultValidationError, "required for a functional or verifier"
        ):
            validate_task_result(missing)

    def test_output_hashes_are_bound_to_byte_counts(self) -> None:
        zero_with_arbitrary_hash = static_result()
        zero_with_arbitrary_hash["fixture_outcomes"][0].update(
            {"stdout_bytes": 0, "stdout_sha256": digest("2")}
        )
        sync_resource_use(zero_with_arbitrary_hash)
        with self.assertRaisesRegex(
            TaskResultValidationError, "canonical empty SHA-256"
        ):
            validate_task_result(zero_with_arbitrary_hash)

        nonzero_without_hash = static_result()
        nonzero_without_hash["fixture_outcomes"][0]["stdout_sha256"] = None
        with self.assertRaisesRegex(
            TaskResultValidationError, "nonzero bytes require"
        ):
            validate_task_result(nonzero_without_hash)

    def test_aggregate_resources_are_recomputed_from_measured_invocations(self) -> None:
        spoofed = static_result()
        spoofed["resource_use"]["peak_rss_bytes"] = 1
        with self.assertRaisesRegex(
            TaskResultValidationError, "exactly equal the maximum"
        ):
            validate_task_result(spoofed)

        no_report = static_result()
        no_report["resource_use"]["measurement_report_sha256"] = None
        with self.assertRaisesRegex(
            TaskResultValidationError, "measurement_report_sha256"
        ):
            validate_task_result(no_report)

        zeroed_measurements = static_result()
        for fixture in zeroed_measurements["fixture_outcomes"]:
            fixture["peak_rss_bytes"] = 0
            fixture["peak_pids"] = 0
            fixture["peak_open_files"] = 0
        sync_resource_use(zeroed_measurements)
        with self.assertRaises(TaskResultValidationError):
            validate_task_result(zeroed_measurements)

    def test_detail_codes_and_process_exit_codes_are_bounded(self) -> None:
        arbitrary_detail = static_result()
        arbitrary_detail["extraction"]["detail_code"] = "covert_plaintext"
        with self.assertRaisesRegex(TaskResultValidationError, "must be one of"):
            validate_task_result(arbitrary_detail)

        oversized_exit = static_result()
        oversized_exit["fixture_outcomes"][0]["exit_code"] = 1 << 40
        with self.assertRaisesRegex(TaskResultValidationError, "must be <="):
            validate_task_result(oversized_exit)

    def test_fixture_identifiers_and_nonrun_outputs_are_strict(self) -> None:
        duplicate = static_result()
        duplicate["fixture_outcomes"][1]["fixture_id"] = duplicate[
            "fixture_outcomes"
        ][0]["fixture_id"]
        with self.assertRaisesRegex(TaskResultValidationError, "must be unique"):
            validate_task_result(duplicate)

        nonrun = static_result()
        set_no_execution(nonrun)
        nonrun["terminal_status"] = "internal_error"
        nonrun["fixture_outcomes"][0]["stdout_sha256"] = digest("2")
        with self.assertRaisesRegex(TaskResultValidationError, "cannot have execution outputs"):
            validate_task_result(nonrun)

    def test_passed_fixture_and_action_require_zero_exit_code(self) -> None:
        fixture_failure = static_result()
        fixture_failure["fixture_outcomes"][0]["exit_code"] = 2
        with self.assertRaisesRegex(TaskResultValidationError, "fixture passes"):
            validate_task_result(fixture_failure)

        action_failure = interactive_result()
        action_failure["action_trace"][0]["exit_code"] = None
        with self.assertRaisesRegex(TaskResultValidationError, "action passes"):
            validate_task_result(action_failure)

    def test_byte_accounting_and_durations_are_nonnegative(self) -> None:
        wrong_bytes = static_result()
        wrong_bytes["generated_text_bytes"] = 25
        with self.assertRaisesRegex(TaskResultValidationError, "equal generated_text_bytes"):
            validate_task_result(wrong_bytes)

        negative_fixture = static_result()
        negative_fixture["fixture_outcomes"][0]["wall_time_ms"] = -0.1
        with self.assertRaisesRegex(TaskResultValidationError, "allowed schema"):
            validate_task_result(negative_fixture)

        negative_cpu = static_result()
        negative_cpu["resource_use"]["cpu_time_ms"] = -1
        with self.assertRaisesRegex(TaskResultValidationError, "allowed schema"):
            validate_task_result(negative_cpu)

    def test_canonical_hash_write_load_and_duplicate_key_rejection(self) -> None:
        result = static_result()
        reordered = dict(reversed(list(result.items())))
        self.assertEqual(task_result_sha256(result), task_result_sha256(reordered))

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.json"
            written = write_task_result(path, result)
            self.assertEqual(written, path)
            self.assertEqual(load_task_result(path), result)
            self.assertEqual(
                path.read_bytes(),
                (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode(),
            )

            duplicate_path = Path(directory) / "duplicate.json"
            duplicate_path.write_text(
                '{"schema_version":"3.0.0","schema_version":"3.0.0"}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(TaskResultValidationError, "duplicate object key"):
                load_task_result(duplicate_path)

    def test_repository_and_packaged_schema_are_identical(self) -> None:
        root = Path(__file__).resolve().parents[1]
        self.assertEqual(
            (root / "task-result.schema.json").read_bytes(),
            (root / "src/cbds/schemas/task-result.schema.json").read_bytes(),
        )

    def test_default_schema_uses_packaged_resource_api(self) -> None:
        task_results_module._packaged_schema.cache_clear()
        with patch.object(
            task_results_module, "files", wraps=resource_files
        ) as packaged_files:
            validate_task_result(static_result())
        packaged_files.assert_called_once_with("cbds.schemas")


if __name__ == "__main__":
    unittest.main()
