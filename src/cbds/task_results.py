"""Strict, content-safe records for one terminal benchmark task.

Task-result documents deliberately retain prompt identifiers and content
hashes, never sealed prompt, fixture, program, or action text.  JSON Schema
handles document shape; the checks below enforce stage ordering and consistency
between the terminal status, fixture outcomes, action trace, and resource use.
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


TASK_RESULT_SCHEMA_VERSION = "1.0.0"

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
    return loaded


def _sorted_unique_strings(
    values: list[str], path: str, errors: list[str]
) -> None:
    if values != sorted(set(values)):
        errors.append(f"{path}: values must be unique and lexicographically sorted")


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
    return errors


def _syntax_errors(result: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    syntax = result["syntax"]
    if syntax["status"] == "not_run":
        if syntax["return_code"] is not None or syntax["diagnostic_sha256"] is not None:
            errors.append("$.syntax: a non-run syntax check cannot have outputs")
    elif syntax["status"] == "ok":
        if syntax["return_code"] not in (0, None):
            errors.append("$.syntax.return_code: must be zero or null when syntax succeeds")
        if syntax["diagnostic_sha256"] is not None:
            errors.append("$.syntax.diagnostic_sha256: must be null when syntax succeeds")
    elif syntax["diagnostic_sha256"] is None:
        errors.append("$.syntax.diagnostic_sha256: required when syntax does not succeed")
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
    if len(fixture_ids) != len(set(fixture_ids)):
        errors.append("$.fixture_outcomes: fixture_id values must be unique")
    if result["mode"] == "static" and len(fixtures) < 5:
        errors.append("$.fixture_outcomes: static tasks require at least five fixtures")

    for index, fixture in enumerate(fixtures):
        path = f"$.fixture_outcomes[{index}]"
        status = fixture["status"]
        execution_fields = ("exit_code", "stdout_sha256", "stderr_sha256", "wall_time_ms")
        if status == "not_run":
            if any(fixture[field] is not None for field in execution_fields):
                errors.append(f"{path}: a non-run fixture cannot have execution outputs")
            if fixture["verifier_result_sha256"] is not None:
                errors.append(f"{path}.verifier_result_sha256: must be null when not run")
            continue

        for field in ("stdout_sha256", "stderr_sha256", "wall_time_ms"):
            if fixture[field] is None:
                errors.append(f"{path}.{field}: required when a fixture was run")
        if status in {"passed", "functional_failure"}:
            if fixture["verifier_result_sha256"] is None:
                errors.append(
                    f"{path}.verifier_result_sha256: required for a functional outcome"
                )
        elif fixture["verifier_result_sha256"] is not None:
            errors.append(
                f"{path}.verifier_result_sha256: only valid for functional outcomes"
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
        execution_fields = ("exit_code", "stdout_sha256", "stderr_sha256", "wall_time_ms")
        if action["status"] in _EXECUTED_ACTION_STATUSES:
            for field in ("stdout_sha256", "stderr_sha256", "wall_time_ms"):
                if action[field] is None:
                    errors.append(f"{path}.{field}: required when an action was run")
            if action["status"] == "passed" and action["exit_code"] != 0:
                errors.append(f"{path}.exit_code: must be zero when an action passes")
        elif any(action[field] is not None for field in execution_fields):
            errors.append(f"{path}: a rejected action cannot have execution outputs")
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
        if resources["stdout_bytes"] != 0 or resources["stderr_bytes"] != 0:
            errors.append("$.resource_use: output byte counts must be zero before container start")
        if resources["timed_out"]:
            errors.append("$.resource_use.timed_out: cannot be true before container start")
    elif (
        result["terminal_status"] in _PREEXECUTION_TERMINAL_STATUSES
        and not fixtures_executed
        and not actions_executed
    ):
        errors.append(
            "$.resource_use.container_started: cannot be true before any accepted action"
        )
    if resources["timed_out"] != (result["terminal_status"] == "timeout"):
        errors.append(
            "$.resource_use.timed_out: must be true exactly for terminal timeout"
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

    if terminal != "internal_error":
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
        expected = _EXECUTION_TERMINAL_TO_OUTCOME[terminal]
        if expected not in fixture_statuses and expected not in action_statuses:
            errors.append(
                f"$: terminal_status {terminal!r} requires a matching fixture or action outcome"
            )
        allowed_outcomes = {"not_run", "passed", expected}
        unexpected_fixtures = sorted(set(fixture_statuses).difference(allowed_outcomes))
        unexpected_actions = sorted(set(action_statuses).difference(allowed_outcomes))
        if unexpected_fixtures:
            errors.append(
                "$.fixture_outcomes: terminal status does not match outcomes "
                f"{unexpected_fixtures!r}"
            )
        if unexpected_actions:
            errors.append(
                "$.action_trace: terminal status does not match outcomes "
                f"{unexpected_actions!r}"
            )
        if result["mode"] == "interactive" and expected in action_statuses:
            if action_statuses[-1] != expected:
                errors.append(
                    "$.action_trace: final action status must match terminal_status"
                )
            if any(status != "passed" for status in action_statuses[:-1]):
                errors.append(
                    "$.action_trace: actions before the terminal failure must have passed"
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
    "load_task_result",
    "task_result_sha256",
    "validate_task_result",
    "write_task_result",
]
