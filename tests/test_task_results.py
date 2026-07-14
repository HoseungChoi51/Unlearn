from __future__ import annotations

import copy
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
    load_task_result,
    task_result_sha256,
    validate_task_result,
    write_task_result,
)


def digest(character: str) -> str:
    return character * 64


def passed_fixture(index: int) -> dict[str, object]:
    return {
        "fixture_id": f"static-task-001-fx-{index:02d}",
        "status": "passed",
        "exit_code": 0,
        "stdout_sha256": digest("2"),
        "stderr_sha256": digest("3"),
        "wall_time_ms": 4.5 + index,
        "verifier_result_sha256": digest("4"),
    }


def static_result() -> dict[str, object]:
    return {
        "schema_version": TASK_RESULT_SCHEMA_VERSION,
        "run_id": "screening-seed-001",
        "benchmark_id": "cbds-static-v1",
        "prompt_id": "static-task-001",
        "mode": "static",
        "split_id": "method_development",
        "sealed": False,
        "attempt": 1,
        "action_limit": 0,
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
        "tool_policy": {
            "status": "allowed",
            "policy_sha256": digest("c"),
            "observed_tools": ["bash", "printf"],
            "disallowed_tools": [],
            "diagnostic_sha256": None,
        },
        "fixture_outcomes": [passed_fixture(index) for index in range(5)],
        "resource_use": {
            "container_started": True,
            "wall_time_ms": 41.25,
            "cpu_time_ms": 12.5,
            "peak_rss_bytes": 8_388_608,
            "stdout_bytes": 60,
            "stderr_bytes": 0,
            "timed_out": False,
        },
        "action_trace": [],
        "terminal_status": "passed",
    }


def set_not_run(fixture: dict[str, object]) -> None:
    fixture.update(
        {
            "status": "not_run",
            "exit_code": None,
            "stdout_sha256": None,
            "stderr_sha256": None,
            "wall_time_ms": None,
            "verifier_result_sha256": None,
        }
    )


def set_no_execution(result: dict[str, object]) -> None:
    for fixture in result["fixture_outcomes"]:  # type: ignore[index]
        set_not_run(fixture)
    result["resource_use"] = {
        "container_started": False,
        "wall_time_ms": 0,
        "cpu_time_ms": None,
        "peak_rss_bytes": None,
        "stdout_bytes": 0,
        "stderr_bytes": 0,
        "timed_out": False,
    }


def interactive_result() -> dict[str, object]:
    result = static_result()
    result.update(
        {
            "benchmark_id": "cbds-interactive-v1",
            "prompt_id": "interactive-task-001",
            "mode": "interactive",
            "action_limit": 8,
            "fixture_outcomes": [
                {
                    **passed_fixture(0),
                    "fixture_id": "interactive-task-001-final-state",
                }
            ],
            "action_trace": [
                {
                    "action_index": 0,
                    "action_sha256": digest("5"),
                    "status": "passed",
                    "exit_code": 0,
                    "stdout_sha256": digest("6"),
                    "stderr_sha256": digest("7"),
                    "wall_time_ms": 3.0,
                },
                {
                    "action_index": 1,
                    "action_sha256": digest("8"),
                    "status": "passed",
                    "exit_code": 0,
                    "stdout_sha256": digest("9"),
                    "stderr_sha256": digest("0"),
                    "wall_time_ms": 2.0,
                },
            ],
        }
    )
    return result


class TaskResultValidationTests(unittest.TestCase):
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
        candidate["resource_use"]["timed_out"] = True
        with self.assertRaisesRegex(
            TaskResultValidationError, "final action status"
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
                "wall_time_ms": None,
            }
        )
        candidate["terminal_status"] = "disallowed_tool"
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
        candidate["resource_use"]["timed_out"] = True
        candidate["terminal_status"] = "timeout"
        validate_task_result(candidate)

        inconsistent = copy.deepcopy(candidate)
        inconsistent["resource_use"]["timed_out"] = False
        with self.assertRaisesRegex(TaskResultValidationError, "exactly for terminal timeout"):
            validate_task_result(inconsistent)

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
                '{"schema_version":"1.0.0","schema_version":"1.0.0"}',
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
