"""Prospective contracts for scored static and interactive evaluation.

An evaluation spec freezes artifact, benchmark, per-task commitments, decoding,
isolation, resource, failure, analysis, and publication policies before an
evaluator opens a scored split.  It contains only opaque identities, counts,
limits, and hashes: prompts, fixture contents, model responses, measurements,
and outcomes belong elsewhere.

This module validates and hashes contracts.  It never loads a model, opens a
sealed benchmark, starts a container, or executes candidate code.
``artifact.inspection_report_sha256`` binds the external inspector's canonical
``report_sha256``; the validator does not open that report or independently
establish its tensor or architecture claims.
"""

from __future__ import annotations

import copy
from collections.abc import Iterable, Mapping
from functools import lru_cache
from hashlib import sha256
from importlib.resources import as_file, files
import os
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any

from .manifests import (
    ManifestValidationError,
    _validate_schema,
    atomic_write_json,
    canonical_json,
    load_document,
    validate_experiment_manifest,
    value_sha256,
)
from .task_results import (
    TASK_RESULT_SCHEMA_VERSION,
    load_task_result,
    ordered_fixture_ids_sha256,
    validate_task_result,
)


EVALUATION_SPEC_SCHEMA_VERSION = "3.0.0"
FROZEN_PARSER_GRAMMAR = "raw-or-one-triple-backtick-fence"
FROZEN_PARSER_VERSION = "1.0.0"

FROZEN_FENCE_LABELS: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "bash": ("", "bash", "sh", "shell"),
        "python": ("python", "python3", "py"),
    }
)

TERMINAL_STATUSES = (
    "passed",
    "extraction_failure",
    "truncation",
    "syntax_failure",
    "syntax_check_failure",
    "disallowed_tool",
    "tool_policy_check_failure",
    "timeout",
    "runtime_failure",
    "functional_failure",
    "resource_limit",
    "verifier_failure",
    "action_limit",
    "internal_error",
)

FAILURE_PRECEDENCE = (
    "extraction_failure",
    "truncation",
    "syntax_check_failure",
    "syntax_failure",
    "tool_policy_check_failure",
    "disallowed_tool",
    "timeout",
    "resource_limit",
    "runtime_failure",
    "verifier_failure",
    "functional_failure",
    "action_limit",
    "internal_error",
    "passed",
)

_SEALED_ROLES = frozenset({"sealed_id", "sealed_ood"})
_UNSEALED_ROLES = frozenset({"method_development", "shadow_validation"})
_INFRASTRUCTURE_RERUN_STATUSES = (
    "verifier_failure",
    "internal_error",
)
_PREEXECUTION_TERMINAL_STATUSES = frozenset(FAILURE_PRECEDENCE[:6])
FROZEN_BASH_BUILTINS = tuple(
    sorted(
        {
            "alias", "bg", "bind", "break", "builtin", "caller", "cd",
            "command", "compgen", "complete", "continue", "declare", "dirs",
            "disown", "echo", "enable", "eval", "exec", "exit", "export",
            "false", "fc", "fg", "getopts", "hash", "help", "history", "jobs",
            "kill", "let", "local", "logout", "mapfile", "popd", "printf",
            "pushd", "pwd", "read", "readarray", "readonly", "return", "set",
            "shift", "shopt", "source", "test", "times", "trap", "true", "type",
            "typeset", "ulimit", "umask", "unalias", "unset", "wait",
        }
    )
)
_BASH_BUILTIN_SET = frozenset(FROZEN_BASH_BUILTINS)
FROZEN_BASH_NATIVE_EXECUTABLES = tuple(
    sorted(
        {
            "alias", "awk", "basename", "bash", "bg", "bind", "break",
            "builtin", "bunzip2", "bzip2", "caller", "cat", "cd", "chgrp",
            "chmod", "chown", "cksum", "command", "comm", "compgen",
            "complete", "continue", "cp", "csplit", "cut", "date", "dd",
            "declare", "df", "dirname", "dirs", "disown", "du", "echo",
            "enable", "env", "eval", "exec", "exit", "expand", "export",
            "expr", "factor", "false", "fc", "fg", "find", "fmt", "fold",
            "gawk", "getconf", "getent", "getopts", "grep", "groups",
            "gunzip", "gzip", "hash", "head", "help", "history", "id",
            "install", "jobs", "join", "jq", "kill", "let", "ln", "local",
            "logout", "ls", "mapfile", "md5sum", "mkdir", "mkfifo", "mknod",
            "mktemp", "mv", "nice", "nl", "nohup", "nproc", "numfmt", "od",
            "paste", "pathchk", "pgrep", "pkill", "popd", "pr", "printenv",
            "printf", "ps", "pushd", "pwd", "read", "readarray", "readlink",
            "readonly", "realpath", "return", "rm", "rmdir", "sed", "seq",
            "set", "sha1sum", "sha224sum", "sha256sum", "sha384sum",
            "sha512sum", "shift", "shopt", "shred", "shuf", "sleep", "sort",
            "source", "split", "stat", "stdbuf", "sum", "sync", "tac", "tail",
            "tar", "tee", "test", "timeout", "times", "touch", "tr", "trap",
            "true", "truncate", "tsort", "tty", "type", "typeset", "ulimit",
            "umask", "unalias", "uname", "unexpand", "uniq", "unlink", "unset",
            "unxz", "unzip", "wait", "wc", "xargs", "xz", "zip",
        }
    )
)
_BASH_NATIVE_EXECUTABLE_SET = frozenset(FROZEN_BASH_NATIVE_EXECUTABLES)
_PYTHON_PERMITTED_EXECUTABLE_SET = _BASH_NATIVE_EXECUTABLE_SET | frozenset(
    {"python", "python3"}
)
_POLICY_PATHS = (
    ("$.decoding", ("decoding",)),
    ("$.parser", ("parser",)),
    ("$.environment", ("environment",)),
    ("$.tool_policy", ("tool_policy",)),
    ("$.fixture_policy", ("fixture_policy",)),
    ("$.outcome_policy.rerun", ("outcome_policy", "rerun")),
    ("$.outcome_policy.exclusion", ("outcome_policy", "exclusion")),
    ("$.outcome_policy.timeout", ("outcome_policy", "timeout")),
    (
        "$.outcome_policy.failure_taxonomy",
        ("outcome_policy", "failure_taxonomy"),
    ),
    ("$.analysis_plan", ("analysis_plan",)),
    ("$.output_policy", ("output_policy",)),
)

_CONFIRMATORY_PAIRING_UNITS = [
    "training_seed",
    "data_order",
    "teacher_corpus",
    "task",
    "fixture",
]
_RERUN_INVARIANT_FIELDS = (
    "prompt_tokens",
    "generated_tokens",
    "generated_text_sha256",
    "generated_text_bytes",
    "extraction",
    "syntax",
    "syntax_duration_ms",
    "tool_policy",
)


class EvaluationSpecValidationError(ValueError):
    """Raised with all schema or semantic evaluation-contract errors."""

    def __init__(self, errors: str | Iterable[str]) -> None:
        if isinstance(errors, str):
            normalized = (errors,)
        else:
            normalized = tuple(str(error) for error in errors)
        if not normalized:
            normalized = ("evaluation-spec validation failed",)
        self.errors = normalized
        super().__init__(
            "evaluation-spec validation failed: " + "; ".join(normalized)
        )


class TaskResultEvaluationBindingError(ValueError):
    """Raised when a valid task result is not bound to an evaluation spec."""

    def __init__(self, errors: str | Iterable[str]) -> None:
        if isinstance(errors, str):
            normalized = (errors,)
        else:
            normalized = tuple(str(error) for error in errors)
        if not normalized:
            normalized = ("task-result/evaluation-spec binding failed",)
        self.errors = normalized
        super().__init__(
            "task-result/evaluation-spec binding failed: "
            + "; ".join(normalized)
        )


class EvaluationArtifactBindingError(ValueError):
    """Raised when an evaluation artifact disagrees with its completed export."""

    def __init__(self, errors: str | Iterable[str]) -> None:
        if isinstance(errors, str):
            normalized = (errors,)
        else:
            normalized = tuple(str(error) for error in errors)
        if not normalized:
            normalized = ("evaluation/completed-export binding failed",)
        self.errors = normalized
        super().__init__(
            "evaluation/completed-export binding failed: "
            + "; ".join(normalized)
        )


@lru_cache(maxsize=1)
def _packaged_schema() -> dict[str, Any]:
    resource = files("cbds.schemas").joinpath("evaluation-spec.schema.json")
    try:
        with as_file(resource) as schema_path:
            loaded = load_document(schema_path)
    except ManifestValidationError as error:  # pragma: no cover - package defect
        raise EvaluationSpecValidationError(error.errors) from error
    if not isinstance(loaded, dict):  # pragma: no cover - fixed package asset
        raise EvaluationSpecValidationError(
            "packaged evaluation-spec schema must be an object"
        )
    return loaded


@lru_cache(maxsize=1)
def _packaged_task_result_schema_sha256() -> str:
    resource = files("cbds.schemas").joinpath("task-result.schema.json")
    try:
        payload = resource.read_bytes()
    except OSError as error:  # pragma: no cover - package defect
        raise EvaluationSpecValidationError(
            f"cannot read packaged task-result schema: {error}"
        ) from error
    return sha256(payload).hexdigest()


def _load_schema(schema_path: str | os.PathLike[str] | None) -> dict[str, Any]:
    if schema_path is None:
        return _packaged_schema()
    try:
        loaded = load_document(schema_path)
    except ManifestValidationError as error:
        raise EvaluationSpecValidationError(error.errors) from error
    if not isinstance(loaded, dict):
        raise EvaluationSpecValidationError(f"schema {schema_path} must be an object")
    packaged = _packaged_schema()
    if value_sha256(loaded) != value_sha256(packaged):
        raise EvaluationSpecValidationError(
            f"schema {schema_path} does not match the frozen packaged "
            "evaluation-spec contract"
        )
    return packaged


def section_policy_sha256(section: Mapping[str, Any]) -> str:
    """Hash one policy object while excluding its self-referential hash field."""

    if not isinstance(section, Mapping):
        raise TypeError("section must be a mapping")
    candidate = copy.deepcopy(dict(section))
    candidate.pop("policy_sha256", None)
    return value_sha256(candidate)


def ordered_arm_roles_sha256(
    ordered_arm_roles: Iterable[Mapping[str, Any]],
) -> str:
    """Hash the exact preregistered reference/comparison role ordering."""

    if isinstance(ordered_arm_roles, Mapping) or isinstance(
        ordered_arm_roles, (str, bytes)
    ):
        raise ValueError("ordered_arm_roles must be an iterable of two objects")
    normalized: list[dict[str, Any]] = []
    for role in ordered_arm_roles:
        normalized.append(copy.deepcopy(dict(role)))
        if len(normalized) > 2:
            raise ValueError("ordered_arm_roles must contain exactly two entries")
    if len(normalized) != 2:
        raise ValueError("ordered_arm_roles must contain exactly two entries")
    expected_roles = ("reference", "comparison")
    arm_ids: list[str] = []
    for index, (entry, expected_role) in enumerate(
        zip(normalized, expected_roles, strict=True)
    ):
        if set(entry) != {"role", "arm_id"}:
            raise ValueError(
                f"ordered_arm_roles[{index}] must contain exactly role and arm_id"
            )
        if entry["role"] != expected_role:
            raise ValueError(
                f"ordered_arm_roles[{index}].role must be {expected_role!r}"
            )
        arm_id = entry["arm_id"]
        if not isinstance(arm_id, str) or not arm_id:
            raise ValueError(
                f"ordered_arm_roles[{index}].arm_id must be a nonempty string"
            )
        arm_ids.append(arm_id)
    if len(set(arm_ids)) != 2:
        raise ValueError("reference and comparison arm IDs must differ")
    return value_sha256(
        {
            "contract": "cbds.ordered-arm-roles",
            "version": "1.0.0",
            "direction": "comparison_minus_reference",
            "ordered_arm_roles": normalized,
        }
    )


def task_commitment_set_sha256(
    commitments: Iterable[Mapping[str, Any]],
) -> str:
    """Hash a bounded task-commitment set independently of input ordering."""

    normalized = [copy.deepcopy(dict(commitment)) for commitment in commitments]
    normalized.sort(key=lambda commitment: commitment.get("prompt_id", ""))
    return value_sha256(
        {
            "commitment_type": "cbds.evaluation-task-set",
            "version": "1.0.0",
            "commitments": normalized,
        }
    )


def _unique_values(values: Iterable[Any], path: str, errors: list[str]) -> None:
    seen: set[str] = set()
    for index, value in enumerate(values):
        key = canonical_json(value)
        if key in seen:
            errors.append(f"{path}[{index}]: duplicate value {value!r}")
        seen.add(key)


def _nested(spec: Mapping[str, Any], path: tuple[str, ...]) -> Mapping[str, Any]:
    current: Any = spec
    for part in path:
        current = current[part]
    return current


def _policy_hash_errors(spec: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    for label, path in _POLICY_PATHS:
        section = _nested(spec, path)
        expected = section_policy_sha256(section)
        if section["policy_sha256"] != expected:
            errors.append(
                f"{label}.policy_sha256: must hash the policy excluding "
                "policy_sha256"
            )
    return errors


def _benchmark_errors(spec: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    benchmark = spec["benchmark"]
    split = benchmark["split"]
    role = split["role"]

    if benchmark["suite"] != spec["mode"]:
        errors.append("$.benchmark.suite: must equal $.mode")
    if split["sealed"] != split["open_once"]:
        errors.append(
            "$.benchmark.split: sealed and open_once must have the same value"
        )
    if role in _SEALED_ROLES and not (split["sealed"] and split["open_once"]):
        errors.append(
            f"$.benchmark.split: role {role!r} must be sealed and open_once"
        )
    if role in _UNSEALED_ROLES and (split["sealed"] or split["open_once"]):
        errors.append(
            f"$.benchmark.split: role {role!r} must be unsealed and reusable"
        )

    fixtures_per_task = spec["fixture_policy"]["fixtures_per_task"]
    expected_fixtures = benchmark["task_count"] * fixtures_per_task
    if benchmark["fixture_count"] != expected_fixtures:
        errors.append(
            "$.benchmark.fixture_count: must equal task_count multiplied by "
            f"fixture_policy.fixtures_per_task ({expected_fixtures})"
        )
    return errors


def _task_commitment_errors(spec: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    container = spec["task_commitments"]
    commitments = container["commitments"]
    benchmark = spec["benchmark"]
    expected_fixture_count = spec["fixture_policy"]["fixtures_per_task"]

    prompt_ids = [commitment["prompt_id"] for commitment in commitments]
    task_hashes = [commitment["task_record_sha256"] for commitment in commitments]
    fixture_hashes = [commitment["fixture_ids_sha256"] for commitment in commitments]
    ordered_fixture_hashes = [
        commitment["ordered_fixture_ids_sha256"] for commitment in commitments
    ]
    _unique_values(prompt_ids, "$.task_commitments.commitments.prompt_id", errors)
    _unique_values(
        task_hashes,
        "$.task_commitments.commitments.task_record_sha256",
        errors,
    )
    _unique_values(
        fixture_hashes,
        "$.task_commitments.commitments.fixture_ids_sha256",
        errors,
    )
    _unique_values(
        ordered_fixture_hashes,
        "$.task_commitments.commitments.ordered_fixture_ids_sha256",
        errors,
    )
    if prompt_ids != sorted(prompt_ids):
        errors.append(
            "$.task_commitments.commitments: must be ordered by opaque prompt_id"
        )
    if len(commitments) != benchmark["task_count"]:
        errors.append(
            "$.task_commitments.commitments: count must equal benchmark.task_count"
        )
    for index, commitment in enumerate(commitments):
        if commitment["fixture_count"] != expected_fixture_count:
            errors.append(
                f"$.task_commitments.commitments[{index}].fixture_count: must "
                "equal fixture_policy.fixtures_per_task"
            )
    if sum(commitment["fixture_count"] for commitment in commitments) != benchmark[
        "fixture_count"
    ]:
        errors.append(
            "$.task_commitments.commitments: fixture counts must sum to "
            "benchmark.fixture_count"
        )
    expected_hash = task_commitment_set_sha256(commitments)
    if container["commitment_set_sha256"] != expected_hash:
        errors.append(
            "$.task_commitments.commitment_set_sha256: must hash the canonical "
            "ordered task commitments"
        )
    return errors


def _parser_errors(spec: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    parser = spec["parser"]
    if parser["grammar"] != FROZEN_PARSER_GRAMMAR:
        errors.append(
            f"$.parser.grammar: must equal {FROZEN_PARSER_GRAMMAR!r}"
        )
    if parser["version"] != FROZEN_PARSER_VERSION:
        errors.append(
            f"$.parser.version: must equal {FROZEN_PARSER_VERSION!r}"
        )
    expected_labels = {
        language: list(labels) for language, labels in FROZEN_FENCE_LABELS.items()
    }
    if parser["fence_labels"] != expected_labels:
        errors.append("$.parser.fence_labels: must equal the frozen label mapping")
    expected_languages = [parser["program_language"]]
    if parser["allowed_languages"] != expected_languages:
        errors.append(
            "$.parser.allowed_languages: must contain only program_language "
            "in a one-item array"
        )
    return errors


def _decode_and_limit_errors(spec: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    decoding = spec["decoding"]
    limits = spec["limits"]
    _unique_values(decoding["eos_token_ids"], "$.decoding.eos_token_ids", errors)
    _unique_values(decoding["stop_sequences"], "$.decoding.stop_sequences", errors)
    if (
        limits["maximum_prompt_tokens"] + decoding["maximum_new_tokens"]
        > limits["maximum_sequence_tokens"]
    ):
        errors.append(
            "$.limits.maximum_sequence_tokens: must cover maximum prompt plus "
            "maximum generated tokens"
        )
    if limits["kill_grace_seconds"] > limits["fixture_timeout_seconds"]:
        errors.append(
            "$.limits.kill_grace_seconds: cannot exceed fixture_timeout_seconds"
        )
    if spec["mode"] == "static":
        if limits["action_limit"] != 0:
            errors.append("$.limits.action_limit: static evaluation requires zero")
        if limits["observation_bytes"] != 0:
            errors.append("$.limits.observation_bytes: static evaluation requires zero")
    else:
        if limits["action_limit"] != 8:
            errors.append(
                "$.limits.action_limit: interactive evaluation requires the frozen "
                "limit of eight"
            )
        if limits["observation_bytes"] <= 0:
            errors.append(
                "$.limits.observation_bytes: interactive evaluation requires a "
                "positive limit"
            )
    return errors


def _environment_errors(spec: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    environment = spec["environment"]
    workspace = PurePosixPath(environment["working_directory"])
    if (
        not workspace.is_absolute()
        or workspace == PurePosixPath("/")
        or ".." in workspace.parts
        or str(workspace) != environment["working_directory"]
        or environment["working_directory"].startswith("//")
    ):
        errors.append(
            "$.environment.working_directory: must be a normalized non-root "
            "absolute container path"
        )

    variables = environment["variables"]
    _unique_values(
        (entry["name"] for entry in variables),
        "$.environment.variables",
        errors,
    )
    if variables != sorted(variables, key=lambda entry: entry["name"]):
        errors.append("$.environment.variables: must be ordered by name")
    _unique_values(environment["shell_options"], "$.environment.shell_options", errors)

    by_name = {entry["name"]: entry["value"] for entry in variables}
    required_values = {
        "LANG": environment["locale"],
        "LC_ALL": environment["locale"],
        "TZ": environment["timezone"],
        "HOME": environment["working_directory"],
        "TMPDIR": f"{environment['working_directory']}/tmp",
    }
    for name, expected in required_values.items():
        if by_name.get(name) != expected:
            errors.append(
                f"$.environment.variables: must explicitly set {name}={expected!r}"
            )
    if not by_name.get("PATH"):
        errors.append("$.environment.variables: must explicitly set a nonempty PATH")
    return errors


def _tool_errors(spec: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    policy = spec["tool_policy"]
    allowed = policy["allowed_executables"]
    _unique_values(allowed, "$.tool_policy.allowed_executables", errors)
    if allowed != sorted(allowed):
        errors.append("$.tool_policy.allowed_executables: must be sorted")
    if policy["allowlist_sha256"] != value_sha256(allowed):
        errors.append(
            "$.tool_policy.allowlist_sha256: must hash allowed_executables"
        )
    if not policy["shell_builtins_allowed"]:
        listed_builtins = sorted(set(allowed).intersection(_BASH_BUILTIN_SET))
        if listed_builtins:
            errors.append(
                "$.tool_policy.allowed_executables: shell_builtins_allowed=false "
                "forbids frozen Bash built-ins " + ", ".join(listed_builtins)
            )

    if policy["track"] == "bash_native":
        if policy["python_allowed"]:
            errors.append(
                "$.tool_policy.python_allowed: bash_native requires false"
            )
        nonnative = sorted(set(allowed).difference(_BASH_NATIVE_EXECUTABLE_SET))
        if nonnative:
            errors.append(
                "$.tool_policy.allowed_executables: bash_native permits only "
                "the frozen native allowlist; remove " + ", ".join(nonnative)
            )
        if spec["parser"]["program_language"] != "bash":
            errors.append(
                "$.parser.program_language: bash_native requires Bash"
            )
    else:
        if not policy["python_allowed"]:
            errors.append(
                "$.tool_policy.python_allowed: python_permitted requires true"
            )
        nonpermitted = sorted(
            set(allowed).difference(_PYTHON_PERMITTED_EXECUTABLE_SET)
        )
        if nonpermitted:
            errors.append(
                "$.tool_policy.allowed_executables: python_permitted permits "
                "only the frozen native allowlist plus python/python3; remove "
                + ", ".join(nonpermitted)
            )
        if "python3" not in allowed:
            errors.append(
                "$.tool_policy.allowed_executables: python_permitted requires python3"
            )
    if (
        spec["parser"]["program_language"] == "python"
        and policy["track"] != "python_permitted"
    ):
        errors.append(
            "$.tool_policy.track: Python programs require python_permitted"
        )
    return errors


def _outcome_errors(spec: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    outcome = spec["outcome_policy"]
    rerun = outcome["rerun"]
    if rerun["mode"] == "never":
        if rerun["maximum_attempts"] != 1:
            errors.append(
                "$.outcome_policy.rerun.maximum_attempts: never requires one"
            )
        if rerun["eligible_terminal_statuses"]:
            errors.append(
                "$.outcome_policy.rerun.eligible_terminal_statuses: never "
                "requires an empty array"
            )
        if rerun["scored_attempt_rule"] != "first_attempt":
            errors.append(
                "$.outcome_policy.rerun.scored_attempt_rule: never requires "
                "first_attempt"
            )
    else:
        if rerun["maximum_attempts"] < 2:
            errors.append(
                "$.outcome_policy.rerun.maximum_attempts: "
                "infrastructure_only requires at least two"
            )
        if rerun["eligible_terminal_statuses"] != list(
            _INFRASTRUCTURE_RERUN_STATUSES
        ):
            errors.append(
                "$.outcome_policy.rerun.eligible_terminal_statuses: must equal "
                "the frozen infrastructure-only taxonomy"
            )
        if rerun["scored_attempt_rule"] != "first_noninfrastructure_attempt":
            errors.append(
                "$.outcome_policy.rerun.scored_attempt_rule: "
                "infrastructure_only requires first_noninfrastructure_attempt"
            )

    exclusion = outcome["exclusion"]
    reasons = exclusion["allowed_reason_codes"]
    _unique_values(
        reasons,
        "$.outcome_policy.exclusion.allowed_reason_codes",
        errors,
    )
    if reasons != sorted(reasons):
        errors.append(
            "$.outcome_policy.exclusion.allowed_reason_codes: must be sorted"
        )
    if exclusion["mode"] == "none":
        if exclusion["manifest_sha256"] is not None or reasons:
            errors.append(
                "$.outcome_policy.exclusion: none requires a null manifest and "
                "no reason codes"
            )
    else:
        errors.append(
            "$.outcome_policy.exclusion.mode: only fail-closed none is supported "
            "until typed excluded-task records and manifest binding are implemented"
        )

    taxonomy = outcome["failure_taxonomy"]
    if taxonomy["terminal_statuses"] != list(TERMINAL_STATUSES):
        errors.append(
            "$.outcome_policy.failure_taxonomy.terminal_statuses: must equal "
            f"the task-result {TASK_RESULT_SCHEMA_VERSION} statuses"
        )
    if taxonomy["precedence"] != list(FAILURE_PRECEDENCE):
        errors.append(
            "$.outcome_policy.failure_taxonomy.precedence: must equal the "
            "frozen precedence"
        )
    return errors


def _result_and_output_errors(spec: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    contract = spec["task_result"]
    if contract["schema_version"] != TASK_RESULT_SCHEMA_VERSION:
        errors.append(
            f"$.task_result.schema_version: must equal {TASK_RESULT_SCHEMA_VERSION!r}"
        )
    if contract["schema_sha256"] != _packaged_task_result_schema_sha256():
        errors.append(
            "$.task_result.schema_sha256: must match the packaged task-result "
            f"{TASK_RESULT_SCHEMA_VERSION} schema"
        )
    return errors


def _analysis_plan_errors(spec: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    analysis = spec["analysis_plan"]
    benchmark = spec["benchmark"]
    role = benchmark["split"]["role"]
    phase = analysis["phase"]

    if phase == "development":
        if analysis["contrast"] is not None:
            errors.append(
                "$.analysis_plan.contrast: development phase requires null; "
                "confirmatory arm roles are committed by the campaign registry"
            )
        if analysis["lane"] != "development":
            errors.append(
                "$.analysis_plan.lane: development phase requires development lane"
            )
        if role in _SEALED_ROLES:
            errors.append(
                "$.analysis_plan.phase: sealed suites require a confirmatory plan"
            )
        if analysis["success_thresholds"]["rule"] != "development_only":
            errors.append(
                "$.analysis_plan.success_thresholds.rule: development phase "
                "requires development_only"
            )
        if analysis["training_seed_count"] != 1:
            errors.append(
                "$.analysis_plan.training_seed_count: development phase "
                "requires one planned artifact seed"
            )
        if analysis["pairing_units"] != _CONFIRMATORY_PAIRING_UNITS:
            errors.append(
                "$.analysis_plan.pairing_units: development uses the same "
                "explicit seed/data/teacher/task/fixture ordering"
            )
        expected_margins = {
            "static_absolute_points": None,
            "bounded_terminal_absolute_points": 2,
        }
        expected_thresholds = {
            "rule": "development_only",
            "static_gain_absolute_points": 0,
            "serialized_bytes_reduction_fraction": None,
            "physical_parameters_reduction_fraction": None,
            "simultaneous_lower_bound_above_zero": False,
        }
        if analysis["noninferiority_margins"] != expected_margins:
            errors.append(
                "$.analysis_plan.noninferiority_margins: development contract "
                "must use the frozen descriptive margins"
            )
        if analysis["success_thresholds"] != expected_thresholds:
            errors.append(
                "$.analysis_plan.success_thresholds: development contract is "
                "descriptive only"
            )
        return errors

    contrast = analysis["contrast"]
    if contrast is None:
        errors.append(
            "$.analysis_plan.contrast: confirmatory phase requires ordered "
            "reference and comparison arm roles"
        )
    else:
        try:
            expected_roles_hash = ordered_arm_roles_sha256(
                contrast["ordered_arm_roles"]
            )
        except (TypeError, ValueError) as error:
            errors.append(f"$.analysis_plan.contrast: {error}")
        else:
            if contrast["ordered_arm_roles_sha256"] != expected_roles_hash:
                errors.append(
                    "$.analysis_plan.contrast.ordered_arm_roles_sha256: must "
                    "hash the exact reference/comparison role ordering"
                )

    if spec["mode"] != "static":
        errors.append("$.mode: confirmatory primary suites must be static")
    if role not in _SEALED_ROLES:
        errors.append(
            "$.benchmark.split.role: confirmatory phase requires sealed_id or sealed_ood"
        )
    expected_count = {"sealed_id": 1000, "sealed_ood": 500}.get(role)
    if expected_count is not None and benchmark["task_count"] != expected_count:
        errors.append(
            f"$.benchmark.task_count: confirmatory {role} requires {expected_count} tasks"
        )
    if analysis["lane"] not in {"fixed_size", "compression"}:
        errors.append(
            "$.analysis_plan.lane: confirmatory phase requires fixed_size or compression"
        )
    if analysis["training_seed_count"] != 5:
        errors.append(
            "$.analysis_plan.training_seed_count: confirmatory phase requires five"
        )
    if analysis["pairing_units"] != _CONFIRMATORY_PAIRING_UNITS:
        errors.append(
            "$.analysis_plan.pairing_units: must exactly pair seed, data order, "
            "teacher corpus, task, and fixture"
        )

    margins = analysis["noninferiority_margins"]
    thresholds = analysis["success_thresholds"]
    if analysis["lane"] == "fixed_size":
        expected_margins = {
            "static_absolute_points": None,
            "bounded_terminal_absolute_points": 2,
        }
        expected_thresholds = {
            "rule": "fixed_size",
            "static_gain_absolute_points": 3,
            "serialized_bytes_reduction_fraction": None,
            "physical_parameters_reduction_fraction": None,
            "simultaneous_lower_bound_above_zero": True,
        }
    else:
        expected_margins = {
            "static_absolute_points": 1,
            "bounded_terminal_absolute_points": 2,
        }
        expected_thresholds = {
            "rule": "compression_or",
            "static_gain_absolute_points": 3,
            "serialized_bytes_reduction_fraction": 0.25,
            "physical_parameters_reduction_fraction": 0.20,
            "simultaneous_lower_bound_above_zero": True,
        }
    if margins != expected_margins:
        errors.append(
            "$.analysis_plan.noninferiority_margins: does not match the frozen lane contract"
        )
    if thresholds != expected_thresholds:
        errors.append(
            "$.analysis_plan.success_thresholds: does not match the frozen lane contract"
        )
    return errors


def _semantic_errors(spec: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    errors.extend(_benchmark_errors(spec))
    errors.extend(_task_commitment_errors(spec))
    errors.extend(_parser_errors(spec))
    errors.extend(_decode_and_limit_errors(spec))
    errors.extend(_environment_errors(spec))
    errors.extend(_tool_errors(spec))
    errors.extend(_outcome_errors(spec))
    errors.extend(_result_and_output_errors(spec))
    errors.extend(_analysis_plan_errors(spec))
    errors.extend(_policy_hash_errors(spec))
    return errors


def validate_evaluation_spec(
    spec: Mapping[str, Any],
    *,
    schema_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Validate one prospective evaluation spec and return a defensive copy."""

    if not isinstance(spec, Mapping):
        raise EvaluationSpecValidationError("$: evaluation spec must be an object")
    candidate = copy.deepcopy(dict(spec))
    schema = _load_schema(schema_path)
    try:
        _validate_schema(candidate, schema)
    except ManifestValidationError as error:
        raise EvaluationSpecValidationError(error.errors) from error
    errors = _semantic_errors(candidate)
    if errors:
        raise EvaluationSpecValidationError(errors)
    return candidate


def load_evaluation_spec(
    path: str | os.PathLike[str],
    *,
    schema_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Strictly load JSON or optional YAML and validate an evaluation spec."""

    try:
        loaded = load_document(path)
    except ManifestValidationError as error:
        raise EvaluationSpecValidationError(error.errors) from error
    if not isinstance(loaded, Mapping):
        raise EvaluationSpecValidationError("$: evaluation spec must be an object")
    return validate_evaluation_spec(loaded, schema_path=schema_path)


def evaluation_spec_sha256(
    spec: Mapping[str, Any],
    *,
    schema_path: str | os.PathLike[str] | None = None,
) -> str:
    """Return the canonical content hash of a valid evaluation spec."""

    return value_sha256(validate_evaluation_spec(spec, schema_path=schema_path))


def validate_evaluation_spec_against_experiment_manifest(
    spec: Mapping[str, Any],
    completed_record: Mapping[str, Any],
    *,
    evaluation_schema_path: str | os.PathLike[str] | None = None,
    experiment_schema_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Validate an evaluation contract and bind it to one completed export.

    This proves that the artifact evaluated is the dense exported artifact
    named by the completed record.  It does not by itself prove that the
    completed record satisfies its prospective run spec or campaign policy;
    callers must perform that separate lifecycle binding first.
    """

    validated_spec = validate_evaluation_spec(
        spec,
        schema_path=evaluation_schema_path,
    )
    try:
        validated_record = validate_experiment_manifest(
            completed_record,
            schema_path=experiment_schema_path,
        )
    except ManifestValidationError as error:
        raise EvaluationArtifactBindingError(error.errors) from error

    artifact = validated_spec["artifact"]
    exported = validated_record["export"]
    errors: list[str] = []
    expected_record_sha256 = value_sha256(validated_record)
    if artifact["completed_run_id"] != validated_record["run_id"]:
        errors.append(
            "$.artifact.completed_run_id: must exactly match $.run_id in the "
            "completed experiment record"
        )
    if artifact["completed_experiment_record_sha256"] != expected_record_sha256:
        errors.append(
            "$.artifact.completed_experiment_record_sha256: must equal the "
            "canonical completed experiment record hash"
        )

    field_pairs = (
        ("architecture", "architecture"),
        ("training_seed", "seeds.training"),
        ("physical_parameters", "physical_parameters"),
        ("format", "format"),
        ("artifact_sha256", "artifact_sha256"),
        ("bundle_sha256", "bundle_sha256"),
        ("tokenizer_sha256", "tokenizer_sha256"),
        ("inspection_report_sha256", "inspection_report_sha256"),
    )
    for artifact_field, export_field in field_pairs:
        if export_field == "seeds.training":
            exported_value = validated_record["seeds"]["training"]
            record_path = "$.seeds.training"
        else:
            exported_value = exported[export_field]
            record_path = f"$.export.{export_field}"
        if artifact[artifact_field] != exported_value:
            errors.append(
                f"$.artifact.{artifact_field}: must exactly match "
                f"{record_path} in the completed experiment record"
            )
    if errors:
        raise EvaluationArtifactBindingError(errors)
    return validated_spec


def load_evaluation_spec_against_experiment_manifest(
    evaluation_spec_path: str | os.PathLike[str],
    completed_record_path: str | os.PathLike[str],
    *,
    evaluation_schema_path: str | os.PathLike[str] | None = None,
    experiment_schema_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Strictly load and jointly validate an evaluation spec and completed export."""

    spec = load_evaluation_spec(
        evaluation_spec_path,
        schema_path=evaluation_schema_path,
    )
    try:
        record = load_document(completed_record_path)
    except ManifestValidationError as error:
        raise EvaluationArtifactBindingError(error.errors) from error
    if not isinstance(record, Mapping):
        raise EvaluationArtifactBindingError(
            "$: completed experiment record must be an object"
        )
    return validate_evaluation_spec_against_experiment_manifest(
        spec,
        record,
        evaluation_schema_path=evaluation_schema_path,
        experiment_schema_path=experiment_schema_path,
    )


def _task_result_binding_errors(
    result: Mapping[str, Any],
    spec: Mapping[str, Any],
    *,
    allow_later_attempt: bool,
) -> list[str]:
    """Return exact membership, policy, limit, and rerun mismatches."""

    errors: list[str] = []
    benchmark = spec["benchmark"]
    split = benchmark["split"]
    limits = spec["limits"]
    rerun = spec["outcome_policy"]["rerun"]
    commitments = {
        commitment["prompt_id"]: commitment
        for commitment in spec["task_commitments"]["commitments"]
    }

    exact_fields = (
        (
            "$.evaluation_id",
            result["evaluation_id"],
            spec["evaluation_id"],
        ),
        (
            "$.evaluation_spec_sha256",
            result["evaluation_spec_sha256"],
            value_sha256(spec),
        ),
        (
            "$.run_id",
            result["run_id"],
            spec["artifact"]["completed_run_id"],
        ),
        (
            "$.benchmark_id",
            result["benchmark_id"],
            benchmark["benchmark_id"],
        ),
        ("$.mode", result["mode"], spec["mode"]),
        ("$.mode (benchmark suite)", result["mode"], benchmark["suite"]),
        ("$.split_id", result["split_id"], split["name"]),
        ("$.split_role", result["split_role"], split["role"]),
        ("$.sealed", result["sealed"], split["sealed"]),
        ("$.action_limit", result["action_limit"], limits["action_limit"]),
        (
            "$.tool_policy.policy_sha256",
            result["tool_policy"]["policy_sha256"],
            spec["tool_policy"]["policy_sha256"],
        ),
        (
            "$.resource_use.measurement_method",
            result["resource_use"]["measurement_method"],
            spec["execution"]["sandbox_measurement_method"],
        ),
    )
    for path, actual, expected in exact_fields:
        if actual != expected:
            errors.append(f"{path}: {actual!r} does not equal contract value {expected!r}")

    commitment = commitments.get(result["prompt_id"])
    if commitment is None:
        errors.append(
            "$.prompt_id: is not a member of the evaluation task-commitment set"
        )
        expected_fixture_count = spec["fixture_policy"]["fixtures_per_task"]
    else:
        expected_fixture_count = commitment["fixture_count"]
        for field in (
            "task_record_sha256",
            "fixture_ids_sha256",
            "ordered_fixture_ids_sha256",
        ):
            if result[field] != commitment[field]:
                errors.append(
                    f"$.{field}: does not match the committed task inventory"
                )

    if result["extraction"]["status"] == "ok":
        expected_language = spec["parser"]["program_language"]
        if result["extraction"]["language"] != expected_language:
            errors.append(
                "$.extraction.language: does not equal contract program_language "
                f"{expected_language!r}"
            )

    allowed_tools = set(spec["tool_policy"]["allowed_executables"])
    observed_tools = set(result["tool_policy"]["observed_tools"])
    expected_disallowed = sorted(observed_tools.difference(allowed_tools))
    if result["tool_policy"]["disallowed_tools"] != expected_disallowed:
        errors.append(
            "$.tool_policy.disallowed_tools: must exactly equal observed_tools "
            "minus the prospective allowed_executables"
        )
    expected_tool_status = "disallowed_tool" if expected_disallowed else "allowed"
    if result["tool_policy"]["status"] not in {
        expected_tool_status,
        "not_run",
        "check_failure",
    }:
        errors.append(
            "$.tool_policy.status: does not match the observed/allowed tool-set "
            "difference"
        )

    fixture_count = len(result["fixture_outcomes"])
    if fixture_count != expected_fixture_count:
        errors.append(
            "$.fixture_outcomes: count "
            f"{fixture_count} does not equal contract fixtures_per_task "
            f"{expected_fixture_count}"
        )
    observed_fixture_order_hash = ordered_fixture_ids_sha256(
        outcome["fixture_id"] for outcome in result["fixture_outcomes"]
    )
    if commitment is not None and (
        observed_fixture_order_hash != commitment["ordered_fixture_ids_sha256"]
    ):
        errors.append(
            "$.fixture_outcomes: fixture order does not match the committed "
            "ordered fixture-ID sequence"
        )
    fixture_statuses = [
        outcome["status"] for outcome in result["fixture_outcomes"]
    ]
    terminal_status = result["terminal_status"]
    if terminal_status not in _PREEXECUTION_TERMINAL_STATUSES | {"internal_error"}:
        if not spec["fixture_policy"]["stop_after_first_failure"]:
            if "not_run" in fixture_statuses:
                errors.append(
                    "$.fixture_outcomes: stop_after_first_failure=false requires "
                    "every fixture to execute"
                )
        else:
            first_not_run = next(
                (
                    index
                    for index, status in enumerate(fixture_statuses)
                    if status == "not_run"
                ),
                len(fixture_statuses),
            )
            if any(
                status != "not_run" for status in fixture_statuses[first_not_run:]
            ):
                errors.append(
                    "$.fixture_outcomes: non-run fixtures must be one ordered suffix"
                )
            executed_prefix = fixture_statuses[:first_not_run]
            first_failure = next(
                (
                    index
                    for index, status in enumerate(executed_prefix)
                    if status != "passed"
                ),
                None,
            )
            if first_not_run < len(fixture_statuses) and (
                first_failure is None or first_failure != len(executed_prefix) - 1
            ):
                errors.append(
                    "$.fixture_outcomes: a non-run suffix is allowed only "
                    "immediately after the first executed failure"
                )
            if first_failure is not None and first_failure != len(executed_prefix) - 1:
                errors.append(
                    "$.fixture_outcomes: stop_after_first_failure=true forbids "
                    "execution after the first fixture failure"
                )

    maximum_response_bytes = limits["maximum_response_bytes"]
    if (
        result["generated_text_bytes"] > maximum_response_bytes
        and result["terminal_status"] != "truncation"
    ):
        errors.append(
            "$.generated_text_bytes: exceeds limits.maximum_response_bytes "
            "without a truncation terminal status"
        )
    if result["prompt_tokens"] > limits["maximum_prompt_tokens"]:
        errors.append("$.prompt_tokens: exceeds limits.maximum_prompt_tokens")
    if result["generated_tokens"] > spec["decoding"]["maximum_new_tokens"]:
        errors.append(
            "$.generated_tokens: exceeds decoding.maximum_new_tokens"
        )
    if (
        result["prompt_tokens"] + result["generated_tokens"]
        > limits["maximum_sequence_tokens"]
    ):
        errors.append(
            "$: prompt_tokens plus generated_tokens exceeds "
            "limits.maximum_sequence_tokens"
        )
    syntax_duration = result["syntax_duration_ms"]
    syntax_timeout_ms = limits["syntax_timeout_seconds"] * 1000
    if (
        syntax_duration is not None
        and syntax_duration > syntax_timeout_ms
        and result["terminal_status"] != "syntax_check_failure"
    ):
        errors.append(
            "$.syntax_duration_ms: exceeds limits.syntax_timeout_seconds "
            "without syntax_check_failure"
        )

    timeout_ms = limits["fixture_timeout_seconds"] * 1000
    timeout_cleanup_ms = (
        limits["fixture_timeout_seconds"] + limits["kill_grace_seconds"]
    ) * 1000
    timed_invocations = (
        (f"$.fixture_outcomes[{index}]", outcome)
        for index, outcome in enumerate(result["fixture_outcomes"])
        if outcome["status"] != "not_run"
    )
    action_invocations = (
        (f"$.action_trace[{index}]", action)
        for index, action in enumerate(result["action_trace"])
        if action["wall_time_ms"] is not None
    )
    for path, invocation in (*timed_invocations, *action_invocations):
        wall_time_ms = invocation["wall_time_ms"]
        if wall_time_ms is None:  # pragma: no cover - task validator prevents this
            continue
        if invocation["status"] == "timeout":
            if wall_time_ms < timeout_ms:
                errors.append(
                    f"{path}.wall_time_ms: timeout status requires reaching the "
                    "per-invocation fixture_timeout_seconds threshold"
                )
            if wall_time_ms > timeout_cleanup_ms:
                errors.append(
                    f"{path}.wall_time_ms: exceeds timeout plus kill-grace bound"
                )
        elif wall_time_ms > timeout_ms:
            errors.append(
                f"{path}.wall_time_ms: exceeds the per-fixture/action timeout "
                "without a timeout status"
            )

    resources = result["resource_use"]
    if result["terminal_status"] == "timeout":
        if resources["wall_time_ms"] > timeout_cleanup_ms:
            errors.append(
                "$.resource_use.wall_time_ms: maximum invocation wall time "
                "exceeds timeout plus kill-grace bound"
            )
    elif resources["wall_time_ms"] > timeout_ms:
        errors.append(
            "$.resource_use.wall_time_ms: maximum invocation wall time exceeds "
            "the per-fixture/action timeout without a timeout status"
        )
    resource_bounds = (
        ("cpu_time_ms", limits["cpu_time_seconds"] * 1000),
        ("peak_rss_bytes", limits["memory_bytes"]),
        ("stdout_bytes", limits["stdout_bytes"]),
        ("stderr_bytes", limits["stderr_bytes"]),
        ("peak_workspace_bytes", limits["workspace_bytes"]),
        ("peak_pids", limits["pids"]),
        ("peak_open_files", limits["open_files"]),
    )
    for field, bound in resource_bounds:
        observed = resources[field]
        if (
            observed is not None
            and observed > bound
            and result["terminal_status"] not in {"timeout", "resource_limit"}
        ):
            errors.append(
                f"$.resource_use.{field}: exceeds its prospective limit "
                "without resource_limit evidence or its higher-priority timeout"
            )
    for index, action in enumerate(result["action_trace"]):
        if (
            action["observation_bytes"] > limits["observation_bytes"]
            and action["status"] not in {"timeout", "resource_limit"}
        ):
            errors.append(
                f"$.action_trace[{index}].observation_bytes: exceeds the "
                "prospective per-action observation limit"
            )

    invocation_resource_bounds = (
        ("cpu_time_ms", limits["cpu_time_seconds"] * 1000),
        ("peak_rss_bytes", limits["memory_bytes"]),
        ("stdout_bytes", limits["stdout_bytes"]),
        ("stderr_bytes", limits["stderr_bytes"]),
        ("peak_workspace_bytes", limits["workspace_bytes"]),
        ("peak_pids", limits["pids"]),
        ("peak_open_files", limits["open_files"]),
    )
    invocations = (
        *(
            (f"$.fixture_outcomes[{index}]", outcome)
            for index, outcome in enumerate(result["fixture_outcomes"])
            if outcome["status"] != "not_run"
        ),
        *(
            (f"$.action_trace[{index}]", action)
            for index, action in enumerate(result["action_trace"])
            if action["wall_time_ms"] is not None
        ),
    )
    for path, invocation in invocations:
        for field, bound in invocation_resource_bounds:
            observed = invocation[field]
            if (
                observed is not None
                and observed > bound
                and invocation["status"] not in {"timeout", "resource_limit"}
            ):
                errors.append(
                    f"{path}.{field}: exceeds its prospective per-invocation "
                    "limit without resource_limit or higher-priority timeout"
                )

    attempt = result["attempt"]
    maximum_attempts = rerun["maximum_attempts"]
    if attempt > maximum_attempts:
        errors.append(
            f"$.attempt: {attempt} exceeds contract maximum_attempts "
            f"{maximum_attempts}"
        )
    prior_statuses = result["prior_attempt_terminal_statuses"]
    if attempt > 1:
        if not allow_later_attempt:
            errors.append(
                "$.attempt: later attempts require the chain or collection "
                "validator; a single result cannot prove its prior attempts"
            )
        if rerun["mode"] != "infrastructure_only":
            errors.append(
                "$.attempt: a later attempt requires infrastructure_only reruns"
            )
        eligible = set(rerun["eligible_terminal_statuses"])
        for index, status in enumerate(prior_statuses):
            if status not in eligible:
                errors.append(
                    f"$.prior_attempt_terminal_statuses[{index}]: {status!r} "
                    "is not eligible for rerun under the contract"
                )
    return errors


def validate_task_result_against_evaluation_spec(
    result: Mapping[str, Any],
    spec: Mapping[str, Any],
    *,
    task_result_schema_path: str | os.PathLike[str] | None = None,
    evaluation_schema_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Validate both documents and return a bound task-result copy.

    This checks exact task/fixture membership, evaluation identity and digest,
    benchmark routing, parser/tool policy, and prospective limits.  It accepts
    only attempt one; later attempts require the chain or collection validator
    so a result cannot self-assert its rerun history.
    """

    validated_spec = validate_evaluation_spec(
        spec, schema_path=evaluation_schema_path
    )
    validated_result = validate_task_result(
        result, schema_path=task_result_schema_path
    )
    errors = _task_result_binding_errors(
        validated_result,
        validated_spec,
        allow_later_attempt=False,
    )
    if errors:
        raise TaskResultEvaluationBindingError(errors)
    return validated_result


def _validate_task_result_chain_with_validated_spec(
    validated_results: list[dict[str, Any]],
    validated_spec: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Validate chain semantics after both records and the spec were validated.

    This private helper prevents collection validation from revalidating the
    same potentially large evaluation specification once per semantic task.
    Callers must pass only defensive copies returned by the public validators.
    """

    maximum_attempts = validated_spec["outcome_policy"]["rerun"][
        "maximum_attempts"
    ]
    if not validated_results:
        raise TaskResultEvaluationBindingError("$: attempt chain cannot be empty")
    if len(validated_results) > maximum_attempts:
        raise TaskResultEvaluationBindingError(
            "$: attempt chain exceeds outcome_policy.rerun.maximum_attempts"
        )

    errors: list[str] = []
    expected_prompt_id = validated_results[0]["prompt_id"]
    first_result = validated_results[0]
    prior_hashes: list[str] = []
    prior_statuses: list[str] = []
    for index, result in enumerate(validated_results):
        path = f"$[{index}]"
        if result["attempt"] != index + 1:
            errors.append(f"{path}.attempt: attempts must be contiguous from one")
        if result["prompt_id"] != expected_prompt_id:
            errors.append(f"{path}.prompt_id: every attempt must target the same task")
        if index > 0:
            for field in _RERUN_INVARIANT_FIELDS:
                if result[field] != first_result[field]:
                    errors.append(
                        f"{path}.{field}: infrastructure reruns are execution-only "
                        "and must preserve the first attempt value"
                    )
            previous_result = validated_results[index - 1]
            previous_actions = [
                (action["action_index"], action["action_sha256"])
                for action in previous_result["action_trace"]
            ]
            retry_actions = [
                (action["action_index"], action["action_sha256"])
                for action in result["action_trace"]
            ]
            if retry_actions[: len(previous_actions)] != previous_actions:
                errors.append(
                    f"{path}.action_trace: infrastructure reruns must preserve "
                    "all previously generated action hashes as an exact prefix"
                )
            extension_allowed = (
                previous_result["terminal_status"] == "internal_error"
                and previous_result["infrastructure_error"] is not None
                and previous_result["infrastructure_error"]["stage"]
                == "action_loop"
            )
            if len(retry_actions) < len(previous_actions) or (
                len(retry_actions) > len(previous_actions)
                and not extension_allowed
            ):
                errors.append(
                    f"{path}.action_trace: action-sequence extension is allowed "
                    "only after an action_loop internal_error"
                )
        if result["prior_attempt_result_sha256s"] != prior_hashes:
            errors.append(
                f"{path}.prior_attempt_result_sha256s: must exactly equal the "
                "canonical hashes of all earlier results"
            )
        if result["prior_attempt_terminal_statuses"] != prior_statuses:
            errors.append(
                f"{path}.prior_attempt_terminal_statuses: must exactly equal "
                "the statuses of all earlier results"
            )
        errors.extend(
            f"{path}{error[1:]}"
            for error in _task_result_binding_errors(
                result,
                validated_spec,
                allow_later_attempt=True,
            )
        )
        prior_hashes.append(value_sha256(result))
        prior_statuses.append(result["terminal_status"])
    if errors:
        raise TaskResultEvaluationBindingError(errors)
    return validated_results


def validate_task_result_chain_against_evaluation_spec(
    results: Iterable[Mapping[str, Any]],
    spec: Mapping[str, Any],
    *,
    task_result_schema_path: str | os.PathLike[str] | None = None,
    evaluation_schema_path: str | os.PathLike[str] | None = None,
) -> list[dict[str, Any]]:
    """Validate one task's contiguous, content-addressed attempt chain."""

    if isinstance(results, Mapping):
        raise TaskResultEvaluationBindingError(
            "$: an attempt chain must be an iterable of result objects"
        )
    validated_spec = validate_evaluation_spec(
        spec, schema_path=evaluation_schema_path
    )
    maximum_attempts = validated_spec["outcome_policy"]["rerun"][
        "maximum_attempts"
    ]
    validated_results: list[dict[str, Any]] = []
    for index, result in enumerate(results):
        if index >= maximum_attempts:
            raise TaskResultEvaluationBindingError(
                "$: attempt chain exceeds outcome_policy.rerun.maximum_attempts"
            )
        validated_results.append(
            validate_task_result(result, schema_path=task_result_schema_path)
        )
    return _validate_task_result_chain_with_validated_spec(
        validated_results,
        validated_spec,
    )


def validate_task_result_collection_against_evaluation_spec(
    results: Iterable[Mapping[str, Any]],
    spec: Mapping[str, Any],
    *,
    task_result_schema_path: str | os.PathLike[str] | None = None,
    evaluation_schema_path: str | os.PathLike[str] | None = None,
) -> list[dict[str, Any]]:
    """Validate exact task coverage and every task's complete attempt chain."""

    if isinstance(results, Mapping):
        raise TaskResultEvaluationBindingError(
            "$: a result collection must be an iterable of result objects"
        )
    validated_spec = validate_evaluation_spec(
        spec, schema_path=evaluation_schema_path
    )
    task_count = validated_spec["benchmark"]["task_count"]
    maximum_attempts = validated_spec["outcome_policy"]["rerun"][
        "maximum_attempts"
    ]
    maximum_records = task_count * maximum_attempts
    grouped: dict[str, list[Mapping[str, Any]]] = {}
    for index, result in enumerate(results):
        if index >= maximum_records:
            raise TaskResultEvaluationBindingError(
                "$: result collection exceeds task_count times maximum_attempts"
            )
        if not isinstance(result, Mapping):
            raise TaskResultEvaluationBindingError(
                f"$[{index}]: task result must be an object"
            )
        validated_result = validate_task_result(
            result, schema_path=task_result_schema_path
        )
        prompt_id = validated_result.get("prompt_id")
        if not isinstance(prompt_id, str):
            raise TaskResultEvaluationBindingError(
                f"$[{index}].prompt_id: required string is missing"
            )
        grouped.setdefault(prompt_id, []).append(validated_result)

    expected_prompt_ids = {
        commitment["prompt_id"]
        for commitment in validated_spec["task_commitments"]["commitments"]
    }
    actual_prompt_ids = set(grouped)
    errors: list[str] = []
    missing = sorted(expected_prompt_ids - actual_prompt_ids)
    unexpected = sorted(actual_prompt_ids - expected_prompt_ids)
    if missing:
        errors.append(
            "$: result collection is missing committed prompt IDs: "
            + ", ".join(missing)
        )
    if unexpected:
        errors.append(
            "$: result collection contains uncommitted prompt IDs: "
            + ", ".join(unexpected)
        )
    if errors:
        raise TaskResultEvaluationBindingError(errors)

    ordered: list[dict[str, Any]] = []
    for prompt_id in sorted(grouped):
        chain = sorted(grouped[prompt_id], key=lambda result: result.get("attempt", 0))
        validated_chain = _validate_task_result_chain_with_validated_spec(
            chain,
            validated_spec,
        )
        last_result = validated_chain[-1]
        eligible = set(
            validated_spec["outcome_policy"]["rerun"][
                "eligible_terminal_statuses"
            ]
        )
        if (
            last_result["terminal_status"] in eligible
            and len(validated_chain) < maximum_attempts
        ):
            raise TaskResultEvaluationBindingError(
                f"$.prompt_id[{prompt_id!r}]: retry-eligible final result is "
                "not a complete chain before maximum_attempts"
            )
        ordered.extend(validated_chain)
    return ordered


def select_scored_task_results_against_evaluation_spec(
    results: Iterable[Mapping[str, Any]],
    spec: Mapping[str, Any],
    *,
    task_result_schema_path: str | os.PathLike[str] | None = None,
    evaluation_schema_path: str | os.PathLike[str] | None = None,
) -> list[dict[str, Any]]:
    """Return exactly one prospectively scored result per committed task.

    For infrastructure-only reruns this selects the first non-infrastructure
    attempt.  If every allowed attempt is an infrastructure failure, the final
    exhausted attempt is returned and therefore counts as a non-passing task.
    """

    validated_spec = validate_evaluation_spec(
        spec, schema_path=evaluation_schema_path
    )
    validated = validate_task_result_collection_against_evaluation_spec(
        results,
        validated_spec,
        task_result_schema_path=task_result_schema_path,
        evaluation_schema_path=evaluation_schema_path,
    )
    grouped: dict[str, list[dict[str, Any]]] = {}
    for result in validated:
        grouped.setdefault(result["prompt_id"], []).append(result)
    rerun = validated_spec["outcome_policy"]["rerun"]
    eligible = set(rerun["eligible_terminal_statuses"])
    selected: list[dict[str, Any]] = []
    for prompt_id in sorted(grouped):
        chain = grouped[prompt_id]
        if rerun["scored_attempt_rule"] == "first_attempt":
            scored = chain[0]
        else:
            scored = next(
                (
                    result
                    for result in chain
                    if result["terminal_status"] not in eligible
                ),
                chain[-1],
            )
        selected.append(copy.deepcopy(scored))
    return selected


def load_task_result_against_evaluation_spec(
    result_path: str | os.PathLike[str],
    evaluation_spec_path: str | os.PathLike[str],
    *,
    task_result_schema_path: str | os.PathLike[str] | None = None,
    evaluation_schema_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Strictly load and jointly validate a task result and evaluation spec."""

    spec = load_evaluation_spec(
        evaluation_spec_path, schema_path=evaluation_schema_path
    )
    result = load_task_result(
        result_path, schema_path=task_result_schema_path
    )
    return validate_task_result_against_evaluation_spec(
        result,
        spec,
        task_result_schema_path=task_result_schema_path,
        evaluation_schema_path=evaluation_schema_path,
    )


def write_evaluation_spec(
    path: str | os.PathLike[str],
    spec: Mapping[str, Any],
    *,
    schema_path: str | os.PathLike[str] | None = None,
) -> Path:
    """Validate and atomically write canonical JSON for an evaluation spec."""

    validated = validate_evaluation_spec(spec, schema_path=schema_path)
    return atomic_write_json(path, validated, canonical=True)


__all__ = [
    "EVALUATION_SPEC_SCHEMA_VERSION",
    "FAILURE_PRECEDENCE",
    "FROZEN_BASH_BUILTINS",
    "FROZEN_BASH_NATIVE_EXECUTABLES",
    "FROZEN_FENCE_LABELS",
    "FROZEN_PARSER_GRAMMAR",
    "FROZEN_PARSER_VERSION",
    "TASK_RESULT_SCHEMA_VERSION",
    "TERMINAL_STATUSES",
    "EvaluationSpecValidationError",
    "EvaluationArtifactBindingError",
    "TaskResultEvaluationBindingError",
    "evaluation_spec_sha256",
    "load_evaluation_spec",
    "load_evaluation_spec_against_experiment_manifest",
    "load_task_result_against_evaluation_spec",
    "ordered_arm_roles_sha256",
    "section_policy_sha256",
    "select_scored_task_results_against_evaluation_spec",
    "task_commitment_set_sha256",
    "validate_task_result_against_evaluation_spec",
    "validate_task_result_chain_against_evaluation_spec",
    "validate_task_result_collection_against_evaluation_spec",
    "validate_evaluation_spec",
    "validate_evaluation_spec_against_experiment_manifest",
    "write_evaluation_spec",
]
