"""Schema-locked confirmatory analysis for paired binary outcomes.

This module is deliberately an in-memory adapter around :mod:`cbds.statistics`.
It validates the full evaluation-spec mapping supplied by the caller, but does
not open evaluation artifacts or campaign registries. Callers must also pass
the arm/seed projections produced by an already validated campaign registry.
The adapter checks endpoint/context consistency, derives the campaign hashes
again, and refuses to compute if any frozen analysis-plan literal or unit has
drifted.

The analysis-code bytes and revision are caller-supplied provenance evidence.
Their equality with the plan commitment is verified, but that is not an
attestation that those bytes are the Python module currently executing. The
runner and statistics method versions separately identify the in-process
implementation contract.

Likewise, outcome records are caller-supplied binary arm/seed/task cells. This
module checks their exact identities, completeness, and registry/evaluation
membership, but does not derive them from task-result collections or verify a
campaign cube's collection hashes.

The returned decisions cover only the preregistered statistical endpoints.
They are not evidence for artifact-size, hardware, replication, or any other
non-statistical success condition.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
import copy
import math
import re
from typing import Any, Final, Literal

from .evaluation_specs import (
    EvaluationSpecValidationError,
    ordered_arm_roles_sha256,
    validate_evaluation_spec,
)
from .manifests import ManifestValidationError, sha256_bytes, value_sha256
from .statistics import (
    STATISTICS_METHOD_VERSION,
    StatisticsValidationError,
    holm_adjust,
    noninferiority_from_interval,
    paired_sign_flip_randomization,
    summarize_paired_binary,
    two_way_paired_bootstrap,
    validate_paired_binary_outcomes,
)


CONFIRMATORY_ANALYSIS_RUNNER_VERSION: Final[str] = "1.0.0"
_MAX_ANALYSIS_CODE_BYTES: Final[int] = 8 * 1024 * 1024
_MAX_REGISTRY_SEED_RECORDS: Final[int] = 64
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REVISION = re.compile(r"^[0-9a-f]{40,64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")
_SEED_FIELDS: Final[tuple[str, ...]] = (
    "model_initialization",
    "data_order",
    "training",
    "operator_selection",
    "evaluation",
)
_PAIRING_UNITS: Final[list[str]] = [
    "training_seed",
    "data_order",
    "teacher_corpus",
    "task",
    "fixture",
]

Endpoint = Literal["static", "bounded_terminal"]


class ConfirmatoryAnalysisValidationError(ValueError):
    """Raised when bindings or the frozen confirmatory policy do not match."""

    def __init__(self, errors: str | Iterable[str]) -> None:
        if isinstance(errors, str):
            normalized = (errors,)
        else:
            normalized = tuple(str(error) for error in errors)
        if not normalized:
            normalized = ("confirmatory analysis validation failed",)
        self.errors = normalized
        super().__init__(
            "confirmatory analysis validation failed: " + "; ".join(normalized)
        )


def _error(message: str) -> None:
    raise ConfirmatoryAnalysisValidationError(message)


def _require_exact_keys(value: object, expected: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _error(f"{label} must be an object")
    assert isinstance(value, Mapping)
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected, key=lambda item: str(item))
        detail: list[str] = []
        if missing:
            detail.append("missing " + ", ".join(missing))
        if extra:
            detail.append("unexpected " + ", ".join(repr(item) for item in extra))
        _error(f"{label} fields do not match the frozen contract ({'; '.join(detail)})")
    return value


def _require_literal(value: object, expected: object, label: str) -> None:
    if type(value) is not type(expected) or value != expected:
        _error(f"{label} must equal {expected!r}")


def _require_integer(
    value: object, label: str, *, minimum: int, maximum: int
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _error(f"{label} must be an integer between {minimum} and {maximum}")
    assert isinstance(value, int)
    return value


def _require_number(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _error(f"{label} must be a finite number")
    number = float(value)
    if not math.isfinite(number):
        _error(f"{label} must be finite")
    return number


def _require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        _error(f"{label} must be a lowercase SHA-256 digest")
    return value


def _require_revision(value: object, label: str) -> str:
    if not isinstance(value, str) or _REVISION.fullmatch(value) is None:
        _error(f"{label} must be a 40-64 character lowercase hexadecimal revision")
    return value


def _require_identifier(value: object, label: str, *, maximum: int = 192) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or _IDENTIFIER.fullmatch(value) is None
    ):
        _error(f"{label} must be a nonempty bounded identifier")
    return value


def _bounded_list(value: object, label: str, *, maximum: int) -> list[Any]:
    if isinstance(value, Mapping) or isinstance(value, (str, bytes, bytearray)):
        _error(f"{label} must be an iterable, not a mapping or byte/string value")
    try:
        iterator = iter(value)  # type: ignore[arg-type]
    except TypeError as error:
        raise ConfirmatoryAnalysisValidationError(f"{label} must be iterable") from error
    items: list[Any] = []
    for item in iterator:
        items.append(item)
        if len(items) > maximum:
            _error(f"{label} exceeds the {maximum}-item limit")
    return items


def _policy_sha256(plan: Mapping[str, Any]) -> str:
    candidate = copy.deepcopy(dict(plan))
    candidate.pop("policy_sha256", None)
    try:
        return value_sha256(candidate)
    except ManifestValidationError as error:
        raise ConfirmatoryAnalysisValidationError(
            f"analysis_plan is not canonical JSON: {error}"
        ) from error


def _validate_bootstrap_plan(raw: object) -> Mapping[str, Any]:
    plan = _require_exact_keys(
        raw,
        {
            "method",
            "resamples",
            "random_seed",
            "percentile_interpolation",
            "resampling_unit",
            "fixtures_nested_within_task",
            "training_seed_crossed_with_task",
        },
        "analysis_plan.bootstrap",
    )
    _require_literal(
        plan["method"],
        "crossed_seed_task_percentile_bootstrap",
        "analysis_plan.bootstrap.method",
    )
    _require_integer(
        plan["resamples"],
        "analysis_plan.bootstrap.resamples",
        minimum=1_000,
        maximum=1_000_000,
    )
    _require_integer(
        plan["random_seed"],
        "analysis_plan.bootstrap.random_seed",
        minimum=0,
        maximum=(1 << 63) - 1,
    )
    _require_literal(
        plan["percentile_interpolation"],
        "linear_r7",
        "analysis_plan.bootstrap.percentile_interpolation",
    )
    _require_literal(
        plan["resampling_unit"],
        "semantic_task",
        "analysis_plan.bootstrap.resampling_unit",
    )
    _require_literal(
        plan["fixtures_nested_within_task"],
        True,
        "analysis_plan.bootstrap.fixtures_nested_within_task",
    )
    _require_literal(
        plan["training_seed_crossed_with_task"],
        True,
        "analysis_plan.bootstrap.training_seed_crossed_with_task",
    )
    return plan


def _validate_randomization_plan(raw: object) -> Mapping[str, Any]:
    plan = _require_exact_keys(
        raw,
        {
            "method",
            "unit",
            "alternative",
            "exact_max_units",
            "monte_carlo_draws",
            "random_seed",
        },
        "analysis_plan.randomization_test",
    )
    _require_literal(
        plan["method"],
        "paired_sign_flip_randomization",
        "analysis_plan.randomization_test.method",
    )
    _require_literal(plan["unit"], "task", "analysis_plan.randomization_test.unit")
    _require_literal(
        plan["alternative"],
        "two_sided",
        "analysis_plan.randomization_test.alternative",
    )
    _require_literal(
        plan["exact_max_units"],
        20,
        "analysis_plan.randomization_test.exact_max_units",
    )
    _require_integer(
        plan["monte_carlo_draws"],
        "analysis_plan.randomization_test.monte_carlo_draws",
        minimum=100,
        maximum=10_000_000,
    )
    _require_integer(
        plan["random_seed"],
        "analysis_plan.randomization_test.random_seed",
        minimum=0,
        maximum=(1 << 63) - 1,
    )
    return plan


def _validate_multiplicity_plan(raw: object) -> Mapping[str, Any]:
    plan = _require_exact_keys(
        raw,
        {
            "p_values",
            "confidence_intervals",
            "family_size",
            "family_confidence_level",
            "per_contrast_confidence_level",
        },
        "analysis_plan.multiplicity_correction",
    )
    frozen = {
        "p_values": "holm_step_down",
        "confidence_intervals": "bonferroni_simultaneous",
        "family_size": 2,
        "family_confidence_level": 0.95,
        "per_contrast_confidence_level": 0.975,
    }
    for field, expected in frozen.items():
        _require_literal(
            plan[field], expected, f"analysis_plan.multiplicity_correction.{field}"
        )
    return plan


def _validate_lane_contract(plan: Mapping[str, Any]) -> None:
    margins = _require_exact_keys(
        plan["noninferiority_margins"],
        {"static_absolute_points", "bounded_terminal_absolute_points"},
        "analysis_plan.noninferiority_margins",
    )
    thresholds = _require_exact_keys(
        plan["success_thresholds"],
        {
            "rule",
            "static_gain_absolute_points",
            "serialized_bytes_reduction_fraction",
            "physical_parameters_reduction_fraction",
            "simultaneous_lower_bound_above_zero",
        },
        "analysis_plan.success_thresholds",
    )
    # Reject booleans and nonfinite values before exact comparisons, since
    # Python otherwise considers False equal to zero.
    for field in ("static_absolute_points", "bounded_terminal_absolute_points"):
        if margins[field] is not None:
            _require_number(margins[field], f"analysis_plan.noninferiority_margins.{field}")
    _require_number(
        thresholds["static_gain_absolute_points"],
        "analysis_plan.success_thresholds.static_gain_absolute_points",
    )
    for field in (
        "serialized_bytes_reduction_fraction",
        "physical_parameters_reduction_fraction",
    ):
        if thresholds[field] is not None:
            _require_number(thresholds[field], f"analysis_plan.success_thresholds.{field}")
    _require_literal(
        thresholds["simultaneous_lower_bound_above_zero"],
        True,
        "analysis_plan.success_thresholds.simultaneous_lower_bound_above_zero",
    )

    if plan["lane"] == "fixed_size":
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
    if dict(margins) != expected_margins:
        _error("analysis_plan.noninferiority_margins does not match the frozen lane")
    if dict(thresholds) != expected_thresholds:
        _error("analysis_plan.success_thresholds does not match the frozen lane")


def _validate_analysis_plan(raw: object) -> Mapping[str, Any]:
    plan = _require_exact_keys(
        raw,
        {
            "version",
            "phase",
            "lane",
            "external_plan_sha256",
            "analysis_code_revision",
            "analysis_code_sha256",
            "seed_evidence_scope",
            "contrast",
            "training_seed_set_sha256",
            "training_seed_count",
            "pairing_units",
            "metric_unit",
            "points_to_proportion_divisor",
            "bootstrap",
            "randomization_test",
            "multiplicity_correction",
            "confirmatory_lane_contrast_count",
            "noninferiority_margins",
            "success_thresholds",
            "policy_sha256",
        },
        "analysis_plan",
    )
    _require_literal(plan["version"], "1.0.0", "analysis_plan.version")
    _require_literal(plan["phase"], "confirmatory", "analysis_plan.phase")
    if plan["lane"] not in ("fixed_size", "compression"):
        _error("analysis_plan.lane must be fixed_size or compression")
    _require_sha256(plan["external_plan_sha256"], "analysis_plan.external_plan_sha256")
    _require_revision(plan["analysis_code_revision"], "analysis_plan.analysis_code_revision")
    _require_sha256(plan["analysis_code_sha256"], "analysis_plan.analysis_code_sha256")
    _require_literal(
        plan["seed_evidence_scope"],
        "per_artifact_only",
        "analysis_plan.seed_evidence_scope",
    )
    contrast = _require_exact_keys(
        plan["contrast"],
        {
            "version",
            "direction",
            "ordered_arm_roles",
            "ordered_arm_roles_sha256",
        },
        "analysis_plan.contrast",
    )
    _require_literal(
        contrast["version"], "1.0.0", "analysis_plan.contrast.version"
    )
    _require_literal(
        contrast["direction"],
        "comparison_minus_reference",
        "analysis_plan.contrast.direction",
    )
    try:
        expected_roles_hash = ordered_arm_roles_sha256(
            contrast["ordered_arm_roles"]
        )
    except (TypeError, ValueError) as error:
        raise ConfirmatoryAnalysisValidationError(
            f"analysis_plan.contrast: {error}"
        ) from error
    declared_roles_hash = _require_sha256(
        contrast["ordered_arm_roles_sha256"],
        "analysis_plan.contrast.ordered_arm_roles_sha256",
    )
    if declared_roles_hash != expected_roles_hash:
        _error(
            "analysis_plan.contrast.ordered_arm_roles_sha256 does not hash "
            "the ordered roles"
        )
    _require_sha256(
        plan["training_seed_set_sha256"], "analysis_plan.training_seed_set_sha256"
    )
    _require_literal(plan["training_seed_count"], 5, "analysis_plan.training_seed_count")
    if type(plan["pairing_units"]) is not list or plan["pairing_units"] != _PAIRING_UNITS:
        _error("analysis_plan.pairing_units must exactly match the frozen ordered units")
    _require_literal(plan["metric_unit"], "proportion", "analysis_plan.metric_unit")
    _require_literal(
        plan["points_to_proportion_divisor"],
        100,
        "analysis_plan.points_to_proportion_divisor",
    )
    _validate_bootstrap_plan(plan["bootstrap"])
    _validate_randomization_plan(plan["randomization_test"])
    _validate_multiplicity_plan(plan["multiplicity_correction"])
    _require_literal(
        plan["confirmatory_lane_contrast_count"],
        2,
        "analysis_plan.confirmatory_lane_contrast_count",
    )
    _validate_lane_contract(plan)
    declared_policy_hash = _require_sha256(
        plan["policy_sha256"], "analysis_plan.policy_sha256"
    )
    if declared_policy_hash != _policy_sha256(plan):
        _error("analysis_plan.policy_sha256 does not hash the frozen plan")
    return plan


def _validate_code_binding(
    plan: Mapping[str, Any],
    analysis_code_bytes: object,
    analysis_code_revision: object,
) -> tuple[str, str]:
    if type(analysis_code_bytes) is not bytes:
        _error("analysis_code_bytes must be immutable bytes")
    assert isinstance(analysis_code_bytes, bytes)
    if len(analysis_code_bytes) > _MAX_ANALYSIS_CODE_BYTES:
        _error(
            "analysis_code_bytes exceeds the "
            f"{_MAX_ANALYSIS_CODE_BYTES}-byte in-memory limit"
        )
    actual_revision = _require_revision(
        analysis_code_revision, "analysis_code_revision"
    )
    actual_digest = sha256_bytes(analysis_code_bytes)
    if plan["analysis_code_revision"] != actual_revision:
        _error("analysis_code_revision does not match the frozen analysis plan")
    if plan["analysis_code_sha256"] != actual_digest:
        _error("analysis_code_bytes do not match analysis_plan.analysis_code_sha256")
    return actual_revision, actual_digest


def _validate_evaluation_binding(
    raw: object, endpoint: Endpoint
) -> tuple[dict[str, Any], Mapping[str, Any], dict[str, Any]]:
    if not isinstance(raw, Mapping):
        _error("evaluation_spec must be an object")
    try:
        validated = validate_evaluation_spec(raw)
    except EvaluationSpecValidationError as error:
        raise ConfirmatoryAnalysisValidationError(
            tuple(f"evaluation_spec: {item}" for item in error.errors)
        ) from error
    plan = _validate_analysis_plan(validated["analysis_plan"])
    mode = validated["mode"]
    suite = validated["benchmark"]["suite"]
    expected = "static" if endpoint == "static" else "interactive"
    if mode != expected or suite != expected:
        _error(
            f"endpoint {endpoint!r} requires a validated {expected!r} "
            "evaluation mode and benchmark suite"
        )
    context = {
        "evaluation_id": validated["evaluation_id"],
        "evaluation_spec_sha256": value_sha256(validated),
        "mode": mode,
        "benchmark_id": validated["benchmark"]["benchmark_id"],
        "benchmark_suite": suite,
        "benchmark_split_sha256": validated["benchmark"]["split"]["sha256"],
        "task_commitment_set_sha256": validated["task_commitments"][
            "commitment_set_sha256"
        ],
        "task_count": validated["benchmark"]["task_count"],
    }
    return validated, plan, context


def _validate_registry_arm_binding(
    plan: Mapping[str, Any],
    *,
    registry_contrast: object,
    registry_arm_declarations: object,
) -> tuple[str, str, dict[str, Any], list[dict[str, Any]], str]:
    contrast = _require_exact_keys(
        registry_contrast,
        {
            "version",
            "direction",
            "ordered_arm_roles",
            "ordered_arm_roles_sha256",
        },
        "registry_contrast",
    )
    normalized_contrast = copy.deepcopy(dict(contrast))
    _require_literal(
        normalized_contrast["version"], "1.0.0", "registry_contrast.version"
    )
    _require_literal(
        normalized_contrast["direction"],
        "comparison_minus_reference",
        "registry_contrast.direction",
    )
    if normalized_contrast != plan["contrast"]:
        _error("registry_contrast does not exactly match analysis_plan.contrast")
    try:
        roles_hash = ordered_arm_roles_sha256(
            normalized_contrast["ordered_arm_roles"]
        )
    except (TypeError, ValueError) as error:
        raise ConfirmatoryAnalysisValidationError(
            f"registry_contrast: {error}"
        ) from error
    if normalized_contrast["ordered_arm_roles_sha256"] != roles_hash:
        _error("registry_contrast does not hash its exact ordered arm roles")
    roles = normalized_contrast["ordered_arm_roles"]
    reference = roles[0]["arm_id"]
    comparison = roles[1]["arm_id"]

    raw_declarations = _bounded_list(
        registry_arm_declarations,
        "registry_arm_declarations",
        maximum=2,
    )
    if len(raw_declarations) != 2:
        _error("registry_arm_declarations must contain exactly two arms")
    declarations: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_declarations):
        declaration = _require_exact_keys(
            raw,
            {"arm_id", "source_arm_id"},
            f"registry_arm_declarations[{index}]",
        )
        arm_id = _require_identifier(
            declaration["arm_id"],
            f"registry_arm_declarations[{index}].arm_id",
            maximum=128,
        )
        source = declaration["source_arm_id"]
        if source is not None:
            source = _require_identifier(
                source,
                f"registry_arm_declarations[{index}].source_arm_id",
                maximum=128,
            )
        declarations.append({"arm_id": arm_id, "source_arm_id": source})
    if declarations != sorted(declarations, key=lambda item: item["arm_id"]):
        _error("registry_arm_declarations must preserve registry arm_id ordering")
    by_id = {declaration["arm_id"]: declaration for declaration in declarations}
    if set(by_id) != {reference, comparison} or len(by_id) != 2:
        _error(
            "registry_arm_declarations must exactly cover the frozen reference "
            "and comparison arms"
        )
    if by_id[comparison]["source_arm_id"] != reference:
        _error(
            "registry comparison arm source_arm_id must equal the frozen "
            "reference arm ID"
        )
    return reference, comparison, normalized_contrast, declarations, roles_hash


def _validate_registry_seed_binding(
    plan: Mapping[str, Any],
    registry_training_seed_records: object,
    registry_training_seed_set_sha256: object,
) -> tuple[list[dict[str, Any]], str, tuple[int, ...]]:
    raw_records = _bounded_list(
        registry_training_seed_records,
        "registry_training_seed_records",
        maximum=_MAX_REGISTRY_SEED_RECORDS,
    )
    expected_count = plan["training_seed_count"]
    if len(raw_records) != expected_count:
        _error(
            "registry_training_seed_records count does not match "
            "analysis_plan.training_seed_count"
        )
    normalized: list[dict[str, Any]] = []
    training_seeds: list[int] = []
    for index, raw in enumerate(raw_records):
        record = _require_exact_keys(
            raw,
            {"replicate_index", "seeds"},
            f"registry_training_seed_records[{index}]",
        )
        replicate = _require_integer(
            record["replicate_index"],
            f"registry_training_seed_records[{index}].replicate_index",
            minimum=0,
            maximum=63,
        )
        seeds = _require_exact_keys(
            record["seeds"],
            set(_SEED_FIELDS),
            f"registry_training_seed_records[{index}].seeds",
        )
        normalized_seeds = {
            field: _require_integer(
                seeds[field],
                f"registry_training_seed_records[{index}].seeds.{field}",
                minimum=0,
                maximum=(1 << 63) - 1,
            )
            for field in _SEED_FIELDS
        }
        normalized.append(
            {"replicate_index": replicate, "seeds": normalized_seeds}
        )
        training_seeds.append(normalized_seeds["training"])
    expected_indices = list(range(expected_count))
    if [record["replicate_index"] for record in normalized] != expected_indices:
        _error(
            "registry_training_seed_records must be ordered and contain exact "
            f"replicate indices {expected_indices}"
        )
    if len(set(training_seeds)) != len(training_seeds):
        _error("registry training seeds must be unique")
    supplied_hash = _require_sha256(
        registry_training_seed_set_sha256,
        "registry_training_seed_set_sha256",
    )
    derived_hash = value_sha256(normalized)
    if supplied_hash != derived_hash:
        _error(
            "registry_training_seed_set_sha256 is not derived from the exact "
            "registry seed records"
        )
    if plan["training_seed_set_sha256"] != derived_hash:
        _error("registry training-seed set does not match the frozen analysis plan")
    return normalized, derived_hash, tuple(sorted(training_seeds))


def _noninferiority_decision(
    plan: Mapping[str, Any],
    endpoint: Endpoint,
    *,
    lower: float,
    upper: float,
    confidence_level: float,
) -> dict[str, Any]:
    field = (
        "static_absolute_points"
        if endpoint == "static"
        else "bounded_terminal_absolute_points"
    )
    margin_points = plan["noninferiority_margins"][field]
    if margin_points is None:
        return {
            "applicable": False,
            "margin_field": field,
            "reason": "frozen_plan_margin_is_null",
        }
    margin_proportion = float(margin_points) / float(
        plan["points_to_proportion_divisor"]
    )
    decision = noninferiority_from_interval(
        lower_bound=lower,
        upper_bound=upper,
        margin=margin_proportion,
        confidence_level=confidence_level,
    )
    return {
        "applicable": True,
        "margin_field": field,
        "margin_absolute_points": float(margin_points),
        "margin_proportion": margin_proportion,
        "decision": decision,
    }


def run_confirmatory_contrast(
    evaluation_spec: Mapping[str, Any],
    records: Iterable[Mapping[str, object]],
    *,
    contrast_id: str,
    endpoint: Endpoint,
    analysis_code_bytes: bytes,
    analysis_code_revision: str,
    registry_contrast: Mapping[str, Any],
    registry_arm_declarations: Sequence[Mapping[str, Any]],
    registry_training_seed_records: Iterable[Mapping[str, Any]],
    registry_training_seed_set_sha256: str,
) -> dict[str, Any]:
    """Execute one frozen confirmatory contrast entirely in memory.

    The full ``evaluation_spec`` is validated from the supplied mapping; its analysis plan,
    mode, benchmark suite, task commitments, and canonical digest are derived
    rather than accepted as caller assertions. ``registry_contrast``,
    ``registry_arm_declarations``, and
    ``registry_training_seed_records`` must be the exact canonical projections
    used by the validated campaign registry. Arm direction is derived from the
    ordered prospective role declaration, and the comparison arm must directly
    source the reference arm. ``analysis_code_bytes`` and
    ``analysis_code_revision`` prove equality to the prospective provenance
    commitment only; they do not attest the loaded Python implementation.
    """

    identifier = _require_identifier(contrast_id, "contrast_id")
    if endpoint not in ("static", "bounded_terminal"):
        _error("endpoint must be static or bounded_terminal")
    validated_evaluation, plan, bound_evaluation_context = (
        _validate_evaluation_binding(evaluation_spec, endpoint)
    )
    revision, code_hash = _validate_code_binding(
        plan, analysis_code_bytes, analysis_code_revision
    )
    reference, comparison, registry_roles, arm_declarations, roles_hash = (
        _validate_registry_arm_binding(
            plan,
            registry_contrast=registry_contrast,
            registry_arm_declarations=registry_arm_declarations,
        )
    )
    seed_records, seed_hash, training_seeds = _validate_registry_seed_binding(
        plan,
        registry_training_seed_records,
        registry_training_seed_set_sha256,
    )

    try:
        cube = validate_paired_binary_outcomes(
            records,
            reference_arm=reference,
            comparison_arm=comparison,
            minimum_seeds=plan["training_seed_count"],
            minimum_tasks=2,
        )
    except StatisticsValidationError as error:
        raise ConfirmatoryAnalysisValidationError(error.errors) from error
    if cube.seeds != training_seeds:
        _error(
            "paired outcome seeds do not exactly equal the registry-derived "
            "training seeds"
        )
    if validated_evaluation["artifact"]["training_seed"] not in training_seeds:
        _error(
            "evaluation artifact training seed is absent from the "
            "registry-derived training-seed set"
        )
    expected_tasks = tuple(
        sorted(
            (
                commitment["prompt_id"]
                for commitment in validated_evaluation["task_commitments"][
                    "commitments"
                ]
            ),
            key=lambda item: item.encode("utf-8"),
        )
    )
    if cube.tasks != expected_tasks:
        _error(
            "paired outcome tasks do not exactly equal the validated "
            "evaluation-spec task commitments"
        )
    if cube.task_count != validated_evaluation["benchmark"]["task_count"]:
        _error("paired outcome task count does not match the evaluation benchmark")

    bootstrap_plan = plan["bootstrap"]
    randomization_plan = plan["randomization_test"]
    multiplicity = plan["multiplicity_correction"]
    try:
        summary = summarize_paired_binary(cube)
        bootstrap = two_way_paired_bootstrap(
            cube,
            confidence_level=multiplicity["per_contrast_confidence_level"],
            resamples=bootstrap_plan["resamples"],
            random_seed=bootstrap_plan["random_seed"],
        )
        randomization = paired_sign_flip_randomization(
            cube,
            unit=randomization_plan["unit"],
            alternative=randomization_plan["alternative"],
            exact_max_units=randomization_plan["exact_max_units"],
            monte_carlo_draws=randomization_plan["monte_carlo_draws"],
            random_seed=randomization_plan["random_seed"],
        )
    except StatisticsValidationError as error:
        raise ConfirmatoryAnalysisValidationError(error.errors) from error

    estimate = float(bootstrap["estimate"])
    interval = bootstrap["confidence_interval"]
    lower = float(interval["lower"])
    upper = float(interval["upper"])
    point_threshold = float(plan["success_thresholds"]["static_gain_absolute_points"])
    point_threshold /= float(plan["points_to_proportion_divisor"])
    point_decision: dict[str, Any]
    if endpoint == "static":
        point_decision = {
            "applicable": True,
            "threshold_absolute_points": float(
                plan["success_thresholds"]["static_gain_absolute_points"]
            ),
            "threshold_proportion": point_threshold,
            "estimate_proportion": estimate,
            "met": estimate >= point_threshold,
        }
    else:
        point_decision = {
            "applicable": False,
            "reason": "static_gain_threshold_does_not_apply_to_bounded_terminal",
        }
    lower_required = plan["success_thresholds"][
        "simultaneous_lower_bound_above_zero"
    ]
    lower_positive = lower > 0.0
    noninferiority = _noninferiority_decision(
        plan,
        endpoint,
        lower=lower,
        upper=upper,
        confidence_level=multiplicity["per_contrast_confidence_level"],
    )

    result: dict[str, Any] = {
        "record_type": "cbds.confirmatory-contrast",
        "runner_version": CONFIRMATORY_ANALYSIS_RUNNER_VERSION,
        "statistics_method_version": STATISTICS_METHOD_VERSION,
        "contrast_id": identifier,
        "lane": plan["lane"],
        "endpoint": endpoint,
        "direction": "comparison_minus_reference",
        "reference_arm": reference,
        "comparison_arm": comparison,
        "bindings": {
            "analysis_policy_sha256": plan["policy_sha256"],
            "external_plan_sha256": plan["external_plan_sha256"],
            "analysis_code_revision": revision,
            "analysis_code_sha256": code_hash,
            "analysis_code_binding_scope": (
                "caller_supplied_bytes_match_plan_commitment_not_runtime_attestation"
            ),
            "evaluation": bound_evaluation_context,
            "registry_contrast": registry_roles,
            "registry_arm_declarations": arm_declarations,
            "ordered_arm_roles_sha256": roles_hash,
            "registry_training_seed_records": seed_records,
            "training_seed_set_sha256": seed_hash,
            "training_seed_count": len(training_seeds),
        },
        "outcome_evidence_scope": (
            "caller_supplied_binary_cells_identity_bound_not_collection_derived"
        ),
        "outcomes": cube.contract_record(),
        "summary": summary,
        "bootstrap": bootstrap,
        "randomization_test": randomization,
        "raw_p_value": randomization["p_value"],
        "simultaneous_confidence_interval": {
            "method": "bonferroni_simultaneous",
            "family_size": multiplicity["family_size"],
            "family_confidence_level": multiplicity["family_confidence_level"],
            "per_contrast_confidence_level": multiplicity[
                "per_contrast_confidence_level"
            ],
            "lower": lower,
            "upper": upper,
        },
        "decisions": {
            "point_gain": point_decision,
            "simultaneous_lower_bound_above_zero": {
                "required": lower_required,
                "observed": lower_positive,
                "met_if_required": (not lower_required) or lower_positive,
            },
            "noninferiority": noninferiority,
            "holm_family_adjustment_pending": True,
        },
        "scope": "statistical_endpoints_only",
    }
    result["contrast_record_sha256"] = value_sha256(result)
    return result


def _validated_contrast_for_family(raw: object, index: int) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping):
        _error(f"contrasts[{index}] must be a contrast result object")
    result = raw
    expected_keys = {
        "record_type",
        "runner_version",
        "statistics_method_version",
        "contrast_id",
        "lane",
        "endpoint",
        "direction",
        "reference_arm",
        "comparison_arm",
        "bindings",
        "outcome_evidence_scope",
        "outcomes",
        "summary",
        "bootstrap",
        "randomization_test",
        "raw_p_value",
        "simultaneous_confidence_interval",
        "decisions",
        "scope",
        "contrast_record_sha256",
    }
    _require_exact_keys(result, expected_keys, f"contrasts[{index}]")
    _require_literal(
        result["record_type"], "cbds.confirmatory-contrast", f"contrasts[{index}].record_type"
    )
    _require_literal(
        result["runner_version"],
        CONFIRMATORY_ANALYSIS_RUNNER_VERSION,
        f"contrasts[{index}].runner_version",
    )
    _require_literal(
        result["statistics_method_version"],
        STATISTICS_METHOD_VERSION,
        f"contrasts[{index}].statistics_method_version",
    )
    _require_identifier(result["contrast_id"], f"contrasts[{index}].contrast_id")
    if result["lane"] not in ("fixed_size", "compression"):
        _error(f"contrasts[{index}].lane is not confirmatory")
    _require_literal(result["endpoint"], "static", f"contrasts[{index}].endpoint")
    _require_literal(
        result["direction"],
        "comparison_minus_reference",
        f"contrasts[{index}].direction",
    )
    _require_literal(
        result["scope"], "statistical_endpoints_only", f"contrasts[{index}].scope"
    )
    evidence_scope = result["outcome_evidence_scope"]
    if evidence_scope not in (
        "caller_supplied_binary_cells_identity_bound_not_collection_derived",
        "artifact_bound_scored_task_result_collections",
    ):
        _error(f"contrasts[{index}].outcome_evidence_scope is unsupported")
    binding_fields = {
        "analysis_policy_sha256",
        "external_plan_sha256",
        "analysis_code_revision",
        "analysis_code_sha256",
        "analysis_code_binding_scope",
        "evaluation",
        "registry_contrast",
        "registry_arm_declarations",
        "ordered_arm_roles_sha256",
        "registry_training_seed_records",
        "training_seed_set_sha256",
        "training_seed_count",
    }
    if evidence_scope == "artifact_bound_scored_task_result_collections":
        binding_fields.add("artifact_bound_outcome_cube")
    bindings = _require_exact_keys(
        result["bindings"],
        binding_fields,
        f"contrasts[{index}].bindings",
    )
    for field in (
        "analysis_policy_sha256",
        "external_plan_sha256",
        "analysis_code_sha256",
        "ordered_arm_roles_sha256",
        "training_seed_set_sha256",
    ):
        _require_sha256(bindings[field], f"contrasts[{index}].bindings.{field}")
    _require_revision(
        bindings["analysis_code_revision"],
        f"contrasts[{index}].bindings.analysis_code_revision",
    )
    _require_literal(
        bindings["analysis_code_binding_scope"],
        "caller_supplied_bytes_match_plan_commitment_not_runtime_attestation",
        f"contrasts[{index}].bindings.analysis_code_binding_scope",
    )
    if evidence_scope == "artifact_bound_scored_task_result_collections":
        artifact_cube = _require_exact_keys(
            bindings["artifact_bound_outcome_cube"],
            {
                "binder_version",
                "cohort_id",
                "cube_id",
                "campaign_registry_sha256",
                "campaign_policy_sha256",
                "registry_paired_cube_sha256",
                "binary_cells_sha256",
                "bound_cube_record_sha256",
                "outcome_evidence_scope",
                "runtime_attestation",
            },
            f"contrasts[{index}].bindings.artifact_bound_outcome_cube",
        )
        _require_literal(
            artifact_cube["binder_version"],
            "1.0.0",
            f"contrasts[{index}].bindings.artifact_bound_outcome_cube.binder_version",
        )
        _require_identifier(
            artifact_cube["cohort_id"],
            f"contrasts[{index}].bindings.artifact_bound_outcome_cube.cohort_id",
        )
        _require_identifier(
            artifact_cube["cube_id"],
            f"contrasts[{index}].bindings.artifact_bound_outcome_cube.cube_id",
        )
        for field in (
            "campaign_registry_sha256",
            "campaign_policy_sha256",
            "registry_paired_cube_sha256",
            "binary_cells_sha256",
            "bound_cube_record_sha256",
        ):
            _require_sha256(
                artifact_cube[field],
                f"contrasts[{index}].bindings.artifact_bound_outcome_cube.{field}",
            )
        _require_literal(
            artifact_cube["outcome_evidence_scope"],
            "derived_from_jointly_validated_registry_bound_scored_task_results",
            f"contrasts[{index}].bindings.artifact_bound_outcome_cube.outcome_evidence_scope",
        )
        _require_literal(
            artifact_cube["runtime_attestation"],
            "none",
            f"contrasts[{index}].bindings.artifact_bound_outcome_cube.runtime_attestation",
        )
    (
        frozen_reference,
        frozen_comparison,
        frozen_contrast,
        _,
        frozen_roles_hash,
    ) = _validate_registry_arm_binding(
        {"contrast": bindings["registry_contrast"]},
        registry_contrast=bindings["registry_contrast"],
        registry_arm_declarations=bindings["registry_arm_declarations"],
    )
    if result["reference_arm"] != frozen_reference:
        _error(f"contrasts[{index}].reference_arm disagrees with frozen roles")
    if result["comparison_arm"] != frozen_comparison:
        _error(f"contrasts[{index}].comparison_arm disagrees with frozen roles")
    if bindings["ordered_arm_roles_sha256"] != frozen_roles_hash:
        _error(
            f"contrasts[{index}].bindings.ordered_arm_roles_sha256 disagrees "
            "with frozen roles"
        )
    if frozen_contrast["direction"] != result["direction"]:
        _error(f"contrasts[{index}].direction disagrees with frozen roles")
    evaluation = _require_exact_keys(
        bindings["evaluation"],
        {
            "evaluation_id",
            "evaluation_spec_sha256",
            "mode",
            "benchmark_id",
            "benchmark_suite",
            "benchmark_split_sha256",
            "task_commitment_set_sha256",
            "task_count",
        },
        f"contrasts[{index}].bindings.evaluation",
    )
    _require_sha256(
        evaluation["evaluation_spec_sha256"],
        f"contrasts[{index}].bindings.evaluation.evaluation_spec_sha256",
    )
    _require_identifier(
        evaluation["evaluation_id"],
        f"contrasts[{index}].bindings.evaluation.evaluation_id",
    )
    _require_identifier(
        evaluation["benchmark_id"],
        f"contrasts[{index}].bindings.evaluation.benchmark_id",
    )
    _require_sha256(
        evaluation["benchmark_split_sha256"],
        f"contrasts[{index}].bindings.evaluation.benchmark_split_sha256",
    )
    _require_sha256(
        evaluation["task_commitment_set_sha256"],
        f"contrasts[{index}].bindings.evaluation.task_commitment_set_sha256",
    )
    _require_integer(
        evaluation["task_count"],
        f"contrasts[{index}].bindings.evaluation.task_count",
        minimum=1,
        maximum=100_000,
    )
    _require_literal(
        evaluation["mode"],
        "static",
        f"contrasts[{index}].bindings.evaluation.mode",
    )
    _require_literal(
        evaluation["benchmark_suite"],
        "static",
        f"contrasts[{index}].bindings.evaluation.benchmark_suite",
    )
    _require_literal(
        bindings["training_seed_count"],
        5,
        f"contrasts[{index}].bindings.training_seed_count",
    )
    outcome_contract = _require_exact_keys(
        result["outcomes"],
        {
            "contract_version",
            "reference_arm",
            "comparison_arm",
            "seed_count",
            "task_count",
            "cell_count",
            "minimum_seeds",
            "minimum_tasks",
            "fixtures_nested_upstream",
        },
        f"contrasts[{index}].outcomes",
    )
    if outcome_contract["reference_arm"] != frozen_reference:
        _error(f"contrasts[{index}].outcomes.reference_arm disagrees with frozen roles")
    if outcome_contract["comparison_arm"] != frozen_comparison:
        _error(f"contrasts[{index}].outcomes.comparison_arm disagrees with frozen roles")
    if outcome_contract["task_count"] != evaluation["task_count"]:
        _error(f"contrasts[{index}].outcomes.task_count disagrees with evaluation")

    summary = _require_exact_keys(
        result["summary"],
        {
            "method",
            "method_version",
            "policy",
            "per_seed",
            "arm_macro_pass_at_1",
            "paired_difference",
        },
        f"contrasts[{index}].summary",
    )
    _require_literal(
        summary["method"],
        "paired_binary_macro_pass_at_1",
        f"contrasts[{index}].summary.method",
    )
    _require_literal(
        summary["method_version"],
        STATISTICS_METHOD_VERSION,
        f"contrasts[{index}].summary.method_version",
    )
    summary_policy = _require_exact_keys(
        summary["policy"],
        {
            "contract_version",
            "reference_arm",
            "comparison_arm",
            "seed_count",
            "task_count",
            "cell_count",
            "minimum_seeds",
            "minimum_tasks",
            "fixtures_nested_upstream",
            "task_aggregation",
            "seed_aggregation",
            "difference_direction",
        },
        f"contrasts[{index}].summary.policy",
    )
    if summary_policy["reference_arm"] != frozen_reference:
        _error(f"contrasts[{index}].summary.policy.reference_arm disagrees with frozen roles")
    if summary_policy["comparison_arm"] != frozen_comparison:
        _error(f"contrasts[{index}].summary.policy.comparison_arm disagrees with frozen roles")
    _require_literal(
        summary_policy["difference_direction"],
        "comparison_minus_reference",
        f"contrasts[{index}].summary.policy.difference_direction",
    )
    arm_macro = _require_exact_keys(
        summary["arm_macro_pass_at_1"],
        {frozen_reference, frozen_comparison},
        f"contrasts[{index}].summary.arm_macro_pass_at_1",
    )
    for arm_id in (frozen_reference, frozen_comparison):
        _require_number(
            arm_macro[arm_id],
            f"contrasts[{index}].summary.arm_macro_pass_at_1[{arm_id!r}]",
        )
    per_seed = _bounded_list(
        summary["per_seed"], f"contrasts[{index}].summary.per_seed", maximum=64
    )
    for seed_index, seed_summary in enumerate(per_seed):
        entry = _require_exact_keys(
            seed_summary,
            {
                "seed",
                "task_count",
                "pass_at_1",
                "paired_difference_comparison_minus_reference",
            },
            f"contrasts[{index}].summary.per_seed[{seed_index}]",
        )
        _require_exact_keys(
            entry["pass_at_1"],
            {frozen_reference, frozen_comparison},
            f"contrasts[{index}].summary.per_seed[{seed_index}].pass_at_1",
        )
    summary_difference = _require_number(
        summary["paired_difference"],
        f"contrasts[{index}].summary.paired_difference",
    )
    raw_p = _require_number(result["raw_p_value"], f"contrasts[{index}].raw_p_value")
    if not 0.0 <= raw_p <= 1.0:
        _error(f"contrasts[{index}].raw_p_value must lie in [0, 1]")

    bootstrap = _require_exact_keys(
        result["bootstrap"],
        {"method", "method_version", "policy", "estimate", "confidence_interval"},
        f"contrasts[{index}].bootstrap",
    )
    _require_literal(
        bootstrap["method"],
        "crossed_seed_task_percentile_bootstrap",
        f"contrasts[{index}].bootstrap.method",
    )
    _require_literal(
        bootstrap["method_version"],
        STATISTICS_METHOD_VERSION,
        f"contrasts[{index}].bootstrap.method_version",
    )
    estimate = _require_number(
        bootstrap["estimate"], f"contrasts[{index}].bootstrap.estimate"
    )
    # The summary averages per-seed rates while the bootstrap computes the
    # algebraically identical grand mean over cells.  Their floating-point
    # operation orders can differ for real 1,000-task cubes.
    if not math.isclose(summary_difference, estimate, rel_tol=0.0, abs_tol=1e-15):
        _error(f"contrasts[{index}] summary and bootstrap estimates disagree")
    bootstrap_policy = _require_exact_keys(
        bootstrap["policy"],
        {
            "contract_version",
            "reference_arm",
            "comparison_arm",
            "seed_count",
            "task_count",
            "cell_count",
            "minimum_seeds",
            "minimum_tasks",
            "fixtures_nested_upstream",
            "estimand",
            "seed_resampling",
            "task_resampling",
            "pairing",
            "fixture_handling",
            "percentile_interpolation",
            "confidence_level",
            "resamples",
            "random_seed",
            "random_generator",
            "cell_evaluations",
        },
        f"contrasts[{index}].bootstrap.policy",
    )
    for field, expected in {
        "estimand": "macro_pass_at_1_comparison_minus_reference",
        "seed_resampling": "independent_with_replacement",
        "task_resampling": "independent_with_replacement",
        "pairing": "arms_retained_within_each_seed_task_cell",
        "fixture_handling": "already_nested_in_semantic_task_binary_outcome",
        "percentile_interpolation": "linear_r7",
        "confidence_level": 0.975,
        "random_generator": "splitmix64_rejection_v1",
    }.items():
        _require_literal(
            bootstrap_policy[field],
            expected,
            f"contrasts[{index}].bootstrap.policy.{field}",
        )
    if bootstrap_policy["reference_arm"] != frozen_reference:
        _error(
            f"contrasts[{index}].bootstrap.policy.reference_arm disagrees "
            "with frozen roles"
        )
    if bootstrap_policy["comparison_arm"] != frozen_comparison:
        _error(
            f"contrasts[{index}].bootstrap.policy.comparison_arm disagrees "
            "with frozen roles"
        )

    randomization = _require_exact_keys(
        result["randomization_test"],
        {
            "method",
            "method_version",
            "policy",
            "total_units",
            "effective_nonzero_units",
            "observed_paired_difference",
            "p_value",
        },
        f"contrasts[{index}].randomization_test",
    )
    _require_literal(
        randomization["method"],
        "paired_sign_flip_randomization",
        f"contrasts[{index}].randomization_test.method",
    )
    _require_literal(
        randomization["method_version"],
        STATISTICS_METHOD_VERSION,
        f"contrasts[{index}].randomization_test.method_version",
    )
    randomization_policy = _require_exact_keys(
        randomization["policy"],
        {
            "contract_version",
            "reference_arm",
            "comparison_arm",
            "seed_count",
            "task_count",
            "cell_count",
            "minimum_seeds",
            "minimum_tasks",
            "fixtures_nested_upstream",
            "unit",
            "unit_score",
            "alternative",
            "zero_score_units",
            "exact_max_units",
            "mode",
            "permutation_count",
            "monte_carlo_draws",
            "random_seed",
            "random_generator",
            "monte_carlo_correction",
        },
        f"contrasts[{index}].randomization_test.policy",
    )
    for field, expected in {
        "unit": "task",
        "unit_score": "sum_of_comparison_minus_reference_binary_differences",
        "alternative": "two_sided",
        "zero_score_units": "excluded_from_sign_enumeration",
        "exact_max_units": 20,
    }.items():
        _require_literal(
            randomization_policy[field],
            expected,
            f"contrasts[{index}].randomization_test.policy.{field}",
        )
    if randomization_policy["reference_arm"] != frozen_reference:
        _error(
            f"contrasts[{index}].randomization_test.policy.reference_arm "
            "disagrees with frozen roles"
        )
    if randomization_policy["comparison_arm"] != frozen_comparison:
        _error(
            f"contrasts[{index}].randomization_test.policy.comparison_arm "
            "disagrees with frozen roles"
        )
    randomization_p = _require_number(
        randomization["p_value"],
        f"contrasts[{index}].randomization_test.p_value",
    )
    if randomization_p != raw_p:
        _error(f"contrasts[{index}].raw_p_value disagrees with randomization_test")
    observed = _require_number(
        randomization["observed_paired_difference"],
        f"contrasts[{index}].randomization_test.observed_paired_difference",
    )
    if observed != estimate:
        _error(f"contrasts[{index}] bootstrap and randomization estimates disagree")

    interval = _require_exact_keys(
        result["simultaneous_confidence_interval"],
        {
            "method",
            "family_size",
            "family_confidence_level",
            "per_contrast_confidence_level",
            "lower",
            "upper",
        },
        f"contrasts[{index}].simultaneous_confidence_interval",
    )
    for field, expected in {
        "method": "bonferroni_simultaneous",
        "family_size": 2,
        "family_confidence_level": 0.95,
        "per_contrast_confidence_level": 0.975,
    }.items():
        _require_literal(
            interval[field], expected, f"contrasts[{index}].simultaneous_confidence_interval.{field}"
        )
    lower = _require_number(interval["lower"], f"contrasts[{index}].simultaneous_confidence_interval.lower")
    upper = _require_number(interval["upper"], f"contrasts[{index}].simultaneous_confidence_interval.upper")
    if lower > upper:
        _error(f"contrasts[{index}] has an inverted confidence interval")
    bootstrap_interval = _require_exact_keys(
        bootstrap["confidence_interval"],
        {"lower", "upper", "confidence_level"},
        f"contrasts[{index}].bootstrap.confidence_interval",
    )
    if dict(bootstrap_interval) != {
        "lower": lower,
        "upper": upper,
        "confidence_level": 0.975,
    }:
        _error(f"contrasts[{index}] simultaneous interval disagrees with bootstrap")

    decisions = _require_exact_keys(
        result["decisions"],
        {
            "point_gain",
            "simultaneous_lower_bound_above_zero",
            "noninferiority",
            "holm_family_adjustment_pending",
        },
        f"contrasts[{index}].decisions",
    )
    _require_literal(
        decisions["holm_family_adjustment_pending"],
        True,
        f"contrasts[{index}].decisions.holm_family_adjustment_pending",
    )
    expected_point = {
        "applicable": True,
        "threshold_absolute_points": 3.0,
        "threshold_proportion": 0.03,
        "estimate_proportion": estimate,
        "met": estimate >= 0.03,
    }
    if decisions["point_gain"] != expected_point:
        _error(f"contrasts[{index}].decisions.point_gain is not derived from the estimate")
    expected_lower = {
        "required": True,
        "observed": lower > 0.0,
        "met_if_required": lower > 0.0,
    }
    if decisions["simultaneous_lower_bound_above_zero"] != expected_lower:
        _error(
            f"contrasts[{index}].decisions.simultaneous_lower_bound_above_zero "
            "is not derived from the interval"
        )
    if result["lane"] == "fixed_size":
        expected_noninferiority: dict[str, Any] = {
            "applicable": False,
            "margin_field": "static_absolute_points",
            "reason": "frozen_plan_margin_is_null",
        }
    else:
        expected_noninferiority = {
            "applicable": True,
            "margin_field": "static_absolute_points",
            "margin_absolute_points": 1.0,
            "margin_proportion": 0.01,
            "decision": noninferiority_from_interval(
                lower_bound=lower,
                upper_bound=upper,
                margin=0.01,
                confidence_level=0.975,
            ),
        }
    if decisions["noninferiority"] != expected_noninferiority:
        _error(
            f"contrasts[{index}].decisions.noninferiority is not derived from the interval"
        )
    declared_hash = _require_sha256(
        result["contrast_record_sha256"], f"contrasts[{index}].contrast_record_sha256"
    )
    unhashed = copy.deepcopy(dict(result))
    unhashed.pop("contrast_record_sha256")
    if declared_hash != value_sha256(unhashed):
        _error(f"contrasts[{index}].contrast_record_sha256 does not match the result")
    return result


def finalize_confirmatory_family(
    contrasts: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Holm-finalize exactly one fixed-size and one compression contrast.

    Only static target contrasts belong to this preregistered two-lane family.
    Bounded-terminal non-inferiority contrasts are executed individually with
    :func:`run_confirmatory_contrast` and are not silently added to this family.
    """

    materialized = _bounded_list(contrasts, "contrasts", maximum=2)
    if len(materialized) != 2:
        _error("the confirmatory family must contain exactly two contrasts")
    validated = [
        _validated_contrast_for_family(raw, index)
        for index, raw in enumerate(materialized)
    ]
    ids = [result["contrast_id"] for result in validated]
    if len(set(ids)) != 2:
        _error("the confirmatory family requires two unique contrast IDs")
    lanes = {result["lane"] for result in validated}
    if lanes != {"fixed_size", "compression"}:
        _error("the confirmatory family requires one fixed_size and one compression contrast")

    bindings = [result["bindings"] for result in validated]
    evidence_scopes = {
        result["outcome_evidence_scope"] for result in validated
    }
    if len(evidence_scopes) != 1:
        _error("confirmatory family contrasts disagree on outcome evidence scope")
    for field in (
        "analysis_code_revision",
        "analysis_code_sha256",
        "external_plan_sha256",
    ):
        if len({binding[field] for binding in bindings}) != 1:
            _error(f"confirmatory family contrasts disagree on {field}")
    for field in (
        "benchmark_id",
        "benchmark_suite",
        "benchmark_split_sha256",
        "task_commitment_set_sha256",
        "task_count",
    ):
        if len({binding["evaluation"][field] for binding in bindings}) != 1:
            _error(
                "confirmatory family contrasts disagree on evaluation "
                f"{field}"
            )
    if evidence_scopes == {"artifact_bound_scored_task_result_collections"}:
        artifact_bindings = [
            binding["artifact_bound_outcome_cube"] for binding in bindings
        ]
        for field in ("campaign_registry_sha256", "campaign_policy_sha256"):
            if len({binding[field] for binding in artifact_bindings}) != 1:
                _error(
                    "artifact-bound confirmatory family contrasts disagree on "
                    f"{field}"
                )

    lane_order = {"compression": 0, "fixed_size": 1}
    ordered_inputs = sorted(
        validated,
        key=lambda result: (lane_order[result["lane"]], result["contrast_id"]),
    )
    input_contrast_bindings: list[dict[str, Any]] = []
    for result in ordered_inputs:
        binding = result["bindings"]
        evaluation = binding["evaluation"]
        input_binding: dict[str, Any] = {
            "contrast_id": result["contrast_id"],
            "lane": result["lane"],
            "contrast_record_sha256": result["contrast_record_sha256"],
            "analysis_policy_sha256": binding["analysis_policy_sha256"],
            "evaluation_id": evaluation["evaluation_id"],
            "evaluation_spec_sha256": evaluation["evaluation_spec_sha256"],
            "artifact_bound_outcome_cube": None,
        }
        if evidence_scopes == {"artifact_bound_scored_task_result_collections"}:
            input_binding["artifact_bound_outcome_cube"] = copy.deepcopy(
                binding["artifact_bound_outcome_cube"]
            )
        input_contrast_bindings.append(input_binding)

    first_binding = ordered_inputs[0]["bindings"]
    first_evaluation = first_binding["evaluation"]
    shared_source_context: dict[str, Any] = {
        "outcome_evidence_scope": next(iter(evidence_scopes)),
        "analysis_code_revision": first_binding["analysis_code_revision"],
        "analysis_code_sha256": first_binding["analysis_code_sha256"],
        "analysis_code_binding_scope": first_binding[
            "analysis_code_binding_scope"
        ],
        "external_plan_sha256": first_binding["external_plan_sha256"],
        "evaluation": {
            field: copy.deepcopy(first_evaluation[field])
            for field in (
                "benchmark_id",
                "benchmark_suite",
                "benchmark_split_sha256",
                "task_commitment_set_sha256",
                "task_count",
            )
        },
        "campaign_registry_sha256": None,
        "campaign_policy_sha256": None,
    }
    if evidence_scopes == {"artifact_bound_scored_task_result_collections"}:
        first_cube = first_binding["artifact_bound_outcome_cube"]
        shared_source_context["campaign_registry_sha256"] = first_cube[
            "campaign_registry_sha256"
        ]
        shared_source_context["campaign_policy_sha256"] = first_cube[
            "campaign_policy_sha256"
        ]

    input_commitment = {
        "commitment_type": "cbds.confirmatory-family-input-contrasts",
        "version": "1.0.0",
        "ordering": "compression_then_fixed_size",
        "bindings": input_contrast_bindings,
    }

    raw_p_values = {
        result["contrast_id"]: float(result["raw_p_value"])
        for result in validated
    }
    try:
        holm = holm_adjust(raw_p_values, alpha=0.05)
    except StatisticsValidationError as error:
        raise ConfirmatoryAnalysisValidationError(error.errors) from error
    adjusted = {entry["label"]: entry for entry in holm["hypotheses"]}

    decisions: list[dict[str, Any]] = []
    for result in sorted(validated, key=lambda item: item["contrast_id"]):
        contrast_id = result["contrast_id"]
        holm_entry = adjusted[contrast_id]
        interval = result["simultaneous_confidence_interval"]
        point = result["decisions"]["point_gain"]
        lower_positive = interval["lower"] > 0.0
        decisions.append(
            {
                "contrast_id": contrast_id,
                "lane": result["lane"],
                "raw_p_value": result["raw_p_value"],
                "holm_adjusted_p_value": holm_entry["adjusted_p_value"],
                "holm_rejected": holm_entry["rejected"],
                "simultaneous_confidence_interval": copy.deepcopy(interval),
                "point_gain": copy.deepcopy(point),
                "noninferiority": copy.deepcopy(
                    result["decisions"]["noninferiority"]
                ),
                "statistical_positive_gain_criteria_met": (
                    point["applicable"]
                    and point["met"]
                    and lower_positive
                    and holm_entry["rejected"]
                ),
            }
        )

    family: dict[str, Any] = {
        "record_type": "cbds.confirmatory-family",
        "runner_version": CONFIRMATORY_ANALYSIS_RUNNER_VERSION,
        "statistics_method_version": STATISTICS_METHOD_VERSION,
        "family_policy": {
            "contrast_count": 2,
            "lanes": ["compression", "fixed_size"],
            "p_values": "holm_step_down",
            "confidence_intervals": "bonferroni_simultaneous",
            "family_confidence_level": 0.95,
            "per_contrast_confidence_level": 0.975,
        },
        "input_contrast_ordering": "compression_then_fixed_size",
        "input_contrast_bindings": input_contrast_bindings,
        "input_contrast_bindings_sha256": value_sha256(input_commitment),
        "shared_source_context": shared_source_context,
        "holm": holm,
        "decisions": decisions,
        "all_statistical_positive_gain_criteria_met": all(
            decision["statistical_positive_gain_criteria_met"]
            for decision in decisions
        ),
        "scope": "statistical_endpoints_only_not_full_lane_success",
    }
    family["family_record_sha256"] = value_sha256(family)
    return family


__all__ = [
    "CONFIRMATORY_ANALYSIS_RUNNER_VERSION",
    "ConfirmatoryAnalysisValidationError",
    "finalize_confirmatory_family",
    "run_confirmatory_contrast",
]
