"""Strict, content-safe records for one terminal benchmark task.

Task-result documents deliberately retain opaque prompt/fixture identifiers,
content commitments, and prior-result hashes, never sealed prompt, fixture,
program, or action text.  JSON Schema handles document shape; the checks below
enforce stage ordering and consistency between the terminal status, fixture
outcomes, action trace, rerun history shape, and resource use.
"""

from __future__ import annotations

import copy
import os
from collections.abc import Iterable, Mapping
from functools import lru_cache
from importlib.resources import as_file, files
from pathlib import Path
from typing import Any

from .manifests import (
    ManifestValidationError,
    _validate_schema,
    atomic_write_json,
    load_document,
    value_sha256,
)


TASK_RESULT_SCHEMA_VERSION = "3.0.0"
_EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

_PREEXECUTION_TERMINAL_STATUSES = frozenset(
    {
        "extraction_failure",
        "truncation",
        "syntax_failure",
        "syntax_check_failure",
        "disallowed_tool",
        "tool_policy_check_failure",
    }
)
_STAGE_TERMINAL_TO_ACTION = {
    "extraction_failure": "extraction_failure",
    "truncation": "truncation",
    "syntax_failure": "syntax_failure",
    "syntax_check_failure": "syntax_check_failure",
    "disallowed_tool": "disallowed_tool",
    "tool_policy_check_failure": "tool_policy_check_failure",
}
_EXECUTION_TERMINAL_TO_OUTCOME = {
    "timeout": "timeout",
    "runtime_failure": "runtime_failure",
    "functional_failure": "functional_failure",
    "resource_limit": "resource_limit",
    "verifier_failure": "verifier_failure",
}
_EXECUTION_FAILURE_PRECEDENCE = (
    "timeout",
    "resource_limit",
    "runtime_failure",
    "verifier_failure",
    "functional_failure",
)
_EXECUTED_ACTION_STATUSES = frozenset(
    {"passed", "timeout", "runtime_failure", "resource_limit"}
)


class TaskResultValidationError(ValueError):
    """Raised with every task-result schema or semantic validation error."""

    def __init__(self, errors: str | Iterable[str]) -> None:
        if isinstance(errors, str):
            normalized = (errors,)
        else:
            normalized = tuple(str(error) for error in errors)
        if not normalized:
            normalized = ("task-result validation failed",)
        self.errors = normalized
        super().__init__("task-result validation failed: " + "; ".join(normalized))


def fixture_id_set_sha256(fixture_ids: Iterable[str]) -> str:
    """Hash a fixture-ID set with stable ordering and domain separation."""

    normalized = sorted(str(fixture_id) for fixture_id in fixture_ids)
    if len(normalized) != len(set(normalized)):
        raise ValueError("fixture_ids must be unique")
    return value_sha256(
        {
            "commitment_type": "cbds.fixture-id-set",
            "version": "1.0.0",
            "fixture_ids": normalized,
        }
    )


def ordered_fixture_ids_sha256(fixture_ids: Iterable[str]) -> str:
    """Hash an exact fixture-ID sequence with domain separation."""

    normalized = [str(fixture_id) for fixture_id in fixture_ids]
    if len(normalized) != len(set(normalized)):
        raise ValueError("fixture_ids must be unique")
    return value_sha256(
        {
            "commitment_type": "cbds.ordered-fixture-id-list",
            "version": "1.0.0",
            "fixture_ids": normalized,
        }
    )


@lru_cache(maxsize=1)
def _packaged_schema() -> dict[str, Any]:
    resource = files("cbds.schemas").joinpath("task-result.schema.json")
    try:
        with as_file(resource) as schema_path:
            loaded = load_document(schema_path)
    except ManifestValidationError as error:  # pragma: no cover - packaging defect
        raise TaskResultValidationError(error.errors) from error
    if not isinstance(loaded, dict):  # pragma: no cover - fixed repository asset
        raise TaskResultValidationError("packaged task-result schema must be an object")
    return loaded


def _load_schema(schema_path: str | os.PathLike[str] | None) -> dict[str, Any]:
    if schema_path is None:
        return _packaged_schema()
    try:
        loaded = load_document(schema_path)
    except ManifestValidationError as error:
        raise TaskResultValidationError(error.errors) from error
    if not isinstance(loaded, dict):
        raise TaskResultValidationError(f"schema {schema_path} must be an object")
    packaged = _packaged_schema()
    if value_sha256(loaded) != value_sha256(packaged):
        raise TaskResultValidationError(
            f"schema {schema_path} does not match the frozen packaged "
            "task-result contract"
        )
    return packaged


def _sorted_unique_strings(
    values: list[str], path: str, errors: list[str]
) -> None:
    if values != sorted(set(values)):
        errors.append(f"{path}: values must be unique and lexicographically sorted")


def _byte_hash_errors(
    digest: str | None,
    byte_count: int,
    path: str,
    errors: list[str],
) -> None:
    """Bind a byte count to either a real content hash or an empty marker."""

    if byte_count == 0:
        if digest not in (None, _EMPTY_SHA256):
            errors.append(
                f"{path}: zero bytes require null or the canonical empty SHA-256"
            )
    elif digest is None or digest == _EMPTY_SHA256:
        errors.append(f"{path}: nonzero bytes require a nonempty-content SHA-256")


def _require_stage(
    actual: str, expected: str, path: str, terminal_status: str, errors: list[str]
) -> None:
    if actual != expected:
        errors.append(
            f"{path}: must be {expected!r} when terminal_status is "
            f"{terminal_status!r}"
        )


def _extraction_errors(result: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    extraction = result["extraction"]
    if extraction["status"] == "ok":
        if extraction["language"] is None:
            errors.append("$.extraction.language: required when extraction succeeds")
        if extraction["code_sha256"] is None:
            errors.append("$.extraction.code_sha256: required when extraction succeeds")
        if extraction["fenced"] is None:
            errors.append("$.extraction.fenced: required when extraction succeeds")
        if extraction["code_bytes"] <= 0:
            errors.append("$.extraction.code_bytes: must be positive when extraction succeeds")
        if extraction["detail_code"] is not None:
            errors.append("$.extraction.detail_code: must be null when extraction succeeds")
    else:
        for field in ("language", "code_sha256", "fenced"):
            if extraction[field] is not None:
                errors.append(
                    f"$.extraction.{field}: must be null when extraction does not succeed"
                )
        if extraction["code_bytes"] != 0:
            errors.append(
                "$.extraction.code_bytes: must be zero when extraction does not succeed"
            )
        if extraction["detail_code"] is None:
            errors.append(
                "$.extraction.detail_code: required when extraction does not succeed"
            )
    if extraction["code_bytes"] > extraction["response_bytes"]:
        errors.append("$.extraction.code_bytes: cannot exceed response_bytes")
    if extraction["response_bytes"] != result["generated_text_bytes"]:
        errors.append(
            "$.extraction.response_bytes: must equal generated_text_bytes"
        )
    _byte_hash_errors(
        extraction["code_sha256"],
        extraction["code_bytes"],
        "$.extraction.code_sha256",
        errors,
    )
    _byte_hash_errors(
        result["generated_text_sha256"],
        result["generated_text_bytes"],
        "$.generated_text_sha256",
        errors,
    )
    return errors


def _syntax_errors(result: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    syntax = result["syntax"]
    if syntax["status"] == "not_run":
        if syntax["return_code"] is not None or syntax["diagnostic_sha256"] is not None:
            errors.append("$.syntax: a non-run syntax check cannot have outputs")
        if result["syntax_duration_ms"] is not None:
            errors.append(
                "$.syntax_duration_ms: must be null when syntax was not run"
            )
    elif syntax["status"] == "ok":
        if result["syntax_duration_ms"] is None:
            errors.append("$.syntax_duration_ms: required when syntax was run")
        if syntax["return_code"] not in (0, None):
            errors.append("$.syntax.return_code: must be zero or null when syntax succeeds")
        if syntax["diagnostic_sha256"] is not None:
            errors.append("$.syntax.diagnostic_sha256: must be null when syntax succeeds")
    else:
        if result["syntax_duration_ms"] is None:
            errors.append("$.syntax_duration_ms: required when syntax was run")
        if syntax["diagnostic_sha256"] is None:
            errors.append(
                "$.syntax.diagnostic_sha256: required when syntax does not succeed"
            )
    return errors


def _tool_policy_errors(result: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    policy = result["tool_policy"]
    observed = policy["observed_tools"]
    disallowed = policy["disallowed_tools"]
    _sorted_unique_strings(observed, "$.tool_policy.observed_tools", errors)
    _sorted_unique_strings(disallowed, "$.tool_policy.disallowed_tools", errors)

    if not set(disallowed).issubset(observed):
        errors.append(
            "$.tool_policy.disallowed_tools: every disallowed tool must be observed"
        )
    if policy["status"] == "not_run":
        if observed or disallowed or policy["diagnostic_sha256"] is not None:
            errors.append("$.tool_policy: a non-run policy check cannot have outputs")
    elif policy["status"] == "allowed":
        if disallowed:
            errors.append(
                "$.tool_policy.disallowed_tools: must be empty when tools are allowed"
            )
        if policy["diagnostic_sha256"] is not None:
            errors.append(
                "$.tool_policy.diagnostic_sha256: must be null when tools are allowed"
            )
    elif policy["status"] == "disallowed_tool":
        if not disallowed:
            errors.append(
                "$.tool_policy.disallowed_tools: cannot be empty for disallowed_tool"
            )
        if policy["diagnostic_sha256"] is None:
            errors.append(
                "$.tool_policy.diagnostic_sha256: required for disallowed_tool"
            )
    elif policy["status"] == "check_failure" and policy["diagnostic_sha256"] is None:
        errors.append("$.tool_policy.diagnostic_sha256: required for check_failure")
    return errors


def _fixture_errors(result: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    fixtures = result["fixture_outcomes"]
    fixture_ids = [fixture["fixture_id"] for fixture in fixtures]
    fixture_ids_are_unique = len(fixture_ids) == len(set(fixture_ids))
    if not fixture_ids_are_unique:
        errors.append("$.fixture_outcomes: fixture_id values must be unique")
    else:
        expected_fixture_ids_sha256 = fixture_id_set_sha256(fixture_ids)
        if result["fixture_ids_sha256"] != expected_fixture_ids_sha256:
            errors.append(
                "$.fixture_ids_sha256: must hash the sorted fixture_id set from "
                "fixture_outcomes"
            )
        expected_ordered_hash = ordered_fixture_ids_sha256(fixture_ids)
        if result["ordered_fixture_ids_sha256"] != expected_ordered_hash:
            errors.append(
                "$.ordered_fixture_ids_sha256: must hash fixture_id values in "
                "fixture_outcomes order"
            )
    if result["mode"] == "static" and len(fixtures) < 5:
        errors.append("$.fixture_outcomes: static tasks require at least five fixtures")

    for index, fixture in enumerate(fixtures):
        path = f"$.fixture_outcomes[{index}]"
        status = fixture["status"]
        nullable_execution_fields = (
            "exit_code",
            "stdout_sha256",
            "stderr_sha256",
            "wall_time_ms",
            "cpu_time_ms",
            "peak_rss_bytes",
            "peak_workspace_bytes",
            "peak_pids",
            "peak_open_files",
        )
        if status == "not_run":
            if any(
                fixture[field] is not None for field in nullable_execution_fields
            ):
                errors.append(f"{path}: a non-run fixture cannot have execution outputs")
            if fixture["stdout_bytes"] != 0 or fixture["stderr_bytes"] != 0:
                errors.append(
                    f"{path}: a non-run fixture must have zero output byte counts"
                )
            if fixture["verifier_result_sha256"] is not None:
                errors.append(f"{path}.verifier_result_sha256: must be null when not run")
            continue

        for field in (
            "wall_time_ms",
            "cpu_time_ms",
            "peak_rss_bytes",
            "peak_workspace_bytes",
            "peak_pids",
            "peak_open_files",
        ):
            if fixture[field] is None:
                errors.append(f"{path}.{field}: required when a fixture was run")
        _byte_hash_errors(
            fixture["stdout_sha256"],
            fixture["stdout_bytes"],
            f"{path}.stdout_sha256",
            errors,
        )
        _byte_hash_errors(
            fixture["stderr_sha256"],
            fixture["stderr_bytes"],
            f"{path}.stderr_sha256",
            errors,
        )
        if status in {"passed", "functional_failure", "verifier_failure"}:
            if fixture["verifier_result_sha256"] is None:
                errors.append(
                    f"{path}.verifier_result_sha256: required for a functional "
                    "or verifier outcome"
                )
        elif fixture["verifier_result_sha256"] is not None:
            errors.append(
                f"{path}.verifier_result_sha256: only valid for functional or "
                "verifier outcomes"
            )
        if status == "passed" and fixture["exit_code"] != 0:
            errors.append(f"{path}.exit_code: must be zero when a fixture passes")
    return errors


def _action_errors(result: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    actions = result["action_trace"]
    if result["mode"] == "static":
        if result["action_limit"] != 0:
            errors.append("$.action_limit: static tasks must use zero")
        if actions:
            errors.append("$.action_trace: static tasks cannot contain actions")
        return errors

    if result["action_limit"] != 8:
        errors.append("$.action_limit: interactive tasks must use the frozen limit of eight")
    if len(actions) > result["action_limit"]:
        errors.append("$.action_trace: exceeds action_limit")
    indices = [action["action_index"] for action in actions]
    if indices != list(range(len(actions))):
        errors.append("$.action_trace: action_index values must be contiguous from zero")

    for index, action in enumerate(actions):
        path = f"$.action_trace[{index}]"
        nullable_execution_fields = (
            "exit_code",
            "stdout_sha256",
            "stderr_sha256",
            "wall_time_ms",
            "cpu_time_ms",
            "peak_rss_bytes",
            "peak_workspace_bytes",
            "peak_pids",
            "peak_open_files",
        )
        if action["status"] in _EXECUTED_ACTION_STATUSES:
            for field in (
                "wall_time_ms",
                "cpu_time_ms",
                "peak_rss_bytes",
                "peak_workspace_bytes",
                "peak_pids",
                "peak_open_files",
            ):
                if action[field] is None:
                    errors.append(f"{path}.{field}: required when an action was run")
            _byte_hash_errors(
                action["stdout_sha256"],
                action["stdout_bytes"],
                f"{path}.stdout_sha256",
                errors,
            )
            _byte_hash_errors(
                action["stderr_sha256"],
                action["stderr_bytes"],
                f"{path}.stderr_sha256",
                errors,
            )
            if action["status"] == "passed" and action["exit_code"] != 0:
                errors.append(f"{path}.exit_code: must be zero when an action passes")
        else:
            if any(
                action[field] is not None for field in nullable_execution_fields
            ):
                errors.append(f"{path}: a rejected action cannot have execution outputs")
            if action["stdout_bytes"] != 0 or action["stderr_bytes"] != 0:
                errors.append(
                    f"{path}: a rejected action must have zero output byte counts"
                )
            if action["observation_bytes"] != 0:
                errors.append(
                    f"{path}.observation_bytes: rejected actions return no observation"
                )
    return errors


def _resource_errors(result: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    resources = result["resource_use"]
    fixtures_executed = any(
        fixture["status"] != "not_run" for fixture in result["fixture_outcomes"]
    )
    actions_executed = any(
        action["status"] in _EXECUTED_ACTION_STATUSES for action in result["action_trace"]
    )
    invocations = [
        fixture
        for fixture in result["fixture_outcomes"]
        if fixture["status"] != "not_run"
    ] + [
        action
        for action in result["action_trace"]
        if action["status"] in _EXECUTED_ACTION_STATUSES
    ]
    if (fixtures_executed or actions_executed) and not resources["container_started"]:
        errors.append(
            "$.resource_use.container_started: must be true when execution outcomes exist"
        )
    if not resources["container_started"]:
        if resources["wall_time_ms"] != 0:
            errors.append("$.resource_use.wall_time_ms: must be zero before container start")
        if resources["cpu_time_ms"] not in (0, None):
            errors.append("$.resource_use.cpu_time_ms: must be zero or null before container start")
        if resources["peak_rss_bytes"] is not None:
            errors.append("$.resource_use.peak_rss_bytes: must be null before container start")
        for field in ("peak_workspace_bytes", "peak_pids", "peak_open_files"):
            if resources[field] is not None:
                errors.append(
                    f"$.resource_use.{field}: must be null before container start"
                )
        if resources["stdout_bytes"] != 0 or resources["stderr_bytes"] != 0:
            errors.append("$.resource_use: output byte counts must be zero before container start")
        if resources["timed_out"]:
            errors.append("$.resource_use.timed_out: cannot be true before container start")
    if invocations:
        if resources["measurement_report_sha256"] is None:
            errors.append(
                "$.resource_use.measurement_report_sha256: required after "
                "sandbox execution"
            )
        maxima = {
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
            if all(invocation[field] is not None for invocation in invocations)
        }
        for field, expected in maxima.items():
            if resources[field] != expected:
                errors.append(
                    f"$.resource_use.{field}: must exactly equal the maximum "
                    "over fixture and accepted-action invocations"
                )
    else:
        if resources["measurement_report_sha256"] is not None:
            errors.append(
                "$.resource_use.measurement_report_sha256: must be null without "
                "an executed invocation"
            )
        expected_empty = {
            "wall_time_ms": 0,
            "cpu_time_ms": None,
            "peak_rss_bytes": None,
            "stdout_bytes": 0,
            "stderr_bytes": 0,
            "peak_workspace_bytes": None,
            "peak_pids": None,
            "peak_open_files": None,
        }
        for field, expected in expected_empty.items():
            if resources[field] != expected:
                errors.append(
                    f"$.resource_use.{field}: must be {expected!r} without "
                    "an executed invocation"
                )
    if (
        result["terminal_status"] in _PREEXECUTION_TERMINAL_STATUSES
        and not fixtures_executed
        and not actions_executed
        and resources["container_started"]
    ):
        errors.append(
            "$.resource_use.container_started: cannot be true before any accepted action"
        )
    invocation_timed_out = any(
        invocation["status"] == "timeout" for invocation in invocations
    )
    if resources["timed_out"] != invocation_timed_out:
        errors.append(
            "$.resource_use.timed_out: must equal the invocation timeout evidence"
        )
    return errors


def _terminal_errors(result: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    terminal = result["terminal_status"]
    extraction = result["extraction"]["status"]
    syntax = result["syntax"]["status"]
    policy = result["tool_policy"]["status"]
    fixture_statuses = [fixture["status"] for fixture in result["fixture_outcomes"]]
    action_statuses = [action["status"] for action in result["action_trace"]]
    infrastructure_error = result["infrastructure_error"]

    if terminal == "internal_error":
        if infrastructure_error is None:
            errors.append(
                "$.infrastructure_error: required for terminal internal_error"
            )
        _require_stage(extraction, "ok", "$.extraction.status", terminal, errors)
        _require_stage(syntax, "ok", "$.syntax.status", terminal, errors)
        _require_stage(policy, "allowed", "$.tool_policy.status", terminal, errors)
        if any(status != "not_run" for status in fixture_statuses):
            errors.append(
                "$.fixture_outcomes: internal_error cannot relabel a completed "
                "fixture outcome"
            )
        if any(status != "passed" for status in action_statuses):
            errors.append(
                "$.action_trace: actions before an infrastructure error must pass"
            )
        if (
            infrastructure_error is not None
            and infrastructure_error["stage"] != "action_loop"
            and action_statuses
        ):
            errors.append(
                "$.action_trace: only an action_loop infrastructure error may "
                "follow completed actions"
            )
        return errors
    if infrastructure_error is not None:
        errors.append(
            "$.infrastructure_error: must be null unless terminal_status is "
            "internal_error"
        )

    stage_expectations = {
        "extraction_failure": ("extraction", extraction, "extraction_failure"),
        "truncation": ("extraction", extraction, "truncation"),
        "syntax_failure": ("syntax", syntax, "syntax_failure"),
        "syntax_check_failure": ("syntax", syntax, "check_failure"),
        "disallowed_tool": ("tool_policy", policy, "disallowed_tool"),
        "tool_policy_check_failure": ("tool_policy", policy, "check_failure"),
    }
    if terminal in stage_expectations:
        name, actual, expected = stage_expectations[terminal]
        _require_stage(actual, expected, f"$.{name}.status", terminal, errors)
        if terminal not in {"extraction_failure", "truncation"}:
            _require_stage(extraction, "ok", "$.extraction.status", terminal, errors)
        else:
            _require_stage(syntax, "not_run", "$.syntax.status", terminal, errors)
            _require_stage(policy, "not_run", "$.tool_policy.status", terminal, errors)
        if terminal in {"syntax_failure", "syntax_check_failure"}:
            _require_stage(policy, "not_run", "$.tool_policy.status", terminal, errors)
        if terminal in {"disallowed_tool", "tool_policy_check_failure"}:
            _require_stage(syntax, "ok", "$.syntax.status", terminal, errors)
        if any(status != "not_run" for status in fixture_statuses):
            errors.append(
                "$.fixture_outcomes: pre-execution terminal failures require all fixtures not_run"
            )
        if result["mode"] == "static":
            if result["action_trace"]:
                errors.append("$.action_trace: static pre-execution failure requires no actions")
            if result["resource_use"]["container_started"]:
                errors.append(
                    "$.resource_use.container_started: static pre-execution failure "
                    "cannot start a container"
                )
        else:
            expected_action = _STAGE_TERMINAL_TO_ACTION[terminal]
            if not action_statuses:
                errors.append(
                    "$.action_trace: an interactive stage failure requires the rejected action"
                )
            else:
                if action_statuses[-1] != expected_action:
                    errors.append(
                        "$.action_trace: final action status must match terminal_status"
                    )
                if any(status != "passed" for status in action_statuses[:-1]):
                    errors.append(
                        "$.action_trace: actions before the rejected action must have passed"
                    )
        return errors

    _require_stage(extraction, "ok", "$.extraction.status", terminal, errors)
    _require_stage(syntax, "ok", "$.syntax.status", terminal, errors)
    _require_stage(policy, "allowed", "$.tool_policy.status", terminal, errors)

    if terminal == "passed":
        if any(status != "passed" for status in fixture_statuses):
            errors.append("$.fixture_outcomes: every fixture must pass for terminal success")
        if any(status != "passed" for status in action_statuses):
            errors.append("$.action_trace: every interactive action must pass for terminal success")
        if not result["resource_use"]["container_started"]:
            errors.append("$.resource_use.container_started: required for terminal success")
    elif terminal in _EXECUTION_TERMINAL_TO_OUTCOME:
        observed_failures = set(fixture_statuses + action_statuses).intersection(
            _EXECUTION_FAILURE_PRECEDENCE
        )
        expected_terminal = next(
            (
                status
                for status in _EXECUTION_FAILURE_PRECEDENCE
                if status in observed_failures
            ),
            None,
        )
        if expected_terminal is None:
            errors.append(
                f"$: terminal_status {terminal!r} requires an execution failure outcome"
            )
        elif terminal != expected_terminal:
            errors.append(
                f"$.terminal_status: must collapse execution outcomes by frozen "
                f"precedence to {expected_terminal!r}"
            )
        failing_action_indices = [
            index for index, status in enumerate(action_statuses) if status != "passed"
        ]
        if failing_action_indices and (
            len(failing_action_indices) != 1
            or failing_action_indices[0] != len(action_statuses) - 1
        ):
            errors.append(
                "$.action_trace: an execution failure must be the sole final "
                "non-passing action"
            )
    elif terminal == "action_limit":
        if result["mode"] != "interactive":
            errors.append("$.terminal_status: action_limit is valid only for interactive tasks")
        if len(result["action_trace"]) != result["action_limit"]:
            errors.append("$.action_trace: action_limit requires a full action trace")
        if any(status != "passed" for status in action_statuses):
            errors.append("$.action_trace: action_limit requires eight completed actions")
    return errors


def _semantic_errors(result: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    expected_prior_attempts = result["attempt"] - 1
    if len(result["prior_attempt_terminal_statuses"]) != expected_prior_attempts:
        errors.append(
            "$.prior_attempt_terminal_statuses: must contain exactly one status "
            "for every earlier attempt "
            f"({expected_prior_attempts} expected)"
        )
    if len(result["prior_attempt_result_sha256s"]) != expected_prior_attempts:
        errors.append(
            "$.prior_attempt_result_sha256s: must contain exactly one canonical "
            "result hash for every earlier attempt "
            f"({expected_prior_attempts} expected)"
        )
    errors.extend(_extraction_errors(result))
    errors.extend(_syntax_errors(result))
    errors.extend(_tool_policy_errors(result))
    errors.extend(_fixture_errors(result))
    errors.extend(_action_errors(result))
    errors.extend(_resource_errors(result))
    errors.extend(_terminal_errors(result))
    return errors


def validate_task_result(
    result: Mapping[str, Any],
    *,
    schema_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Validate one task result and return a defensive deep copy.

    Validation is dependency-free and rejects unknown fields.  The returned
    document contains identifiers and hashes only; the strict schema rejects
    prompt, generated program, fixture, and action text fields.
    """

    if not isinstance(result, Mapping):
        raise TaskResultValidationError("$: task result must be an object")
    candidate = copy.deepcopy(dict(result))
    schema = _load_schema(schema_path)
    try:
        _validate_schema(candidate, schema)
    except ManifestValidationError as error:
        raise TaskResultValidationError(error.errors) from error
    errors = _semantic_errors(candidate)
    if errors:
        raise TaskResultValidationError(errors)
    return candidate


def load_task_result(
    path: str | os.PathLike[str],
    *,
    schema_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Load strict JSON or safe YAML and validate one task result."""

    try:
        loaded = load_document(path)
    except ManifestValidationError as error:
        raise TaskResultValidationError(error.errors) from error
    if not isinstance(loaded, Mapping):
        raise TaskResultValidationError("$: task result must be an object")
    return validate_task_result(loaded, schema_path=schema_path)


def task_result_sha256(
    result: Mapping[str, Any],
    *,
    schema_path: str | os.PathLike[str] | None = None,
) -> str:
    """Return the canonical content hash of a valid task result."""

    return value_sha256(validate_task_result(result, schema_path=schema_path))


def write_task_result(
    path: str | os.PathLike[str],
    result: Mapping[str, Any],
    *,
    schema_path: str | os.PathLike[str] | None = None,
) -> Path:
    """Validate and atomically write canonical JSON for one task result."""

    validated = validate_task_result(result, schema_path=schema_path)
    return atomic_write_json(path, validated, canonical=True)


__all__ = [
    "TASK_RESULT_SCHEMA_VERSION",
    "TaskResultValidationError",
    "fixture_id_set_sha256",
    "ordered_fixture_ids_sha256",
    "load_task_result",
    "task_result_sha256",
    "validate_task_result",
    "write_task_result",
]
