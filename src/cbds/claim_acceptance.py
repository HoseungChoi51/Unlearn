"""Fail-closed claim-level acceptance binding for confirmatory lanes.

The binder in this module is intentionally narrower than an end-to-end claim
attestation system.  It accepts only exact, content-addressed evidence
projections and deterministically evaluates the acceptance policy in
``PLAN.md``.  It does *not* treat a digest as proof that a projection was
derived from the completed run, hardware result, or task-result collection
named by that digest.

Consequently a returned record distinguishes two facts:

``acceptance_criteria_met``
    The supplied projections satisfy every numerical and structural rule.

``claim_authorized``
    Always false in this version.  The record enumerates the exact source
    hashes and validator chains that an end-to-end implementation must execute
    before this bit may ever become true.

This separation makes the policy evaluator useful now without manufacturing a
research result from caller-supplied summaries.  Unknown fields, missing
evidence, cross-record identity drift, booleans used as numbers, non-finite
numbers, duplicate roles, and invalid content addresses fail closed.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import copy
import math
import re
from typing import Any, Final, Literal, TypedDict

from .manifests import ManifestValidationError, value_sha256


CLAIM_ACCEPTANCE_BINDER_VERSION: Final[str] = "1.0.0"
CLAIM_EVIDENCE_SCHEMA_VERSION: Final[str] = "1.0.0"
SUB_BILLION_PHYSICAL_PARAMETER_LIMIT: Final[int] = 1_000_000_000
FIXED_SIZE_METADATA_TOLERANCE_BYTES: Final[int] = 0
MAX_COMPARABLE_BYTES_FRACTION: Final[float] = 0.05
PROTECTED_CAPABILITY_MAX_MARGIN_POINTS: Final[float] = 2.0
SIMULTANEOUS_CONFIDENCE_LEVEL: Final[float] = 0.975
_MAX_EVIDENCE_ITEMS: Final[int] = 128
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")

Lane = Literal["fixed_size", "compression"]


class ClaimEvidenceEnvelope(TypedDict):
    """Public shape shared by every evidence object accepted by the binder."""

    record_type: str
    schema_version: str
    lane: Lane
    reference_arm: str
    comparison_arm: str
    evidence_scope: str
    payload: dict[str, Any]
    evidence_sha256: str


class ClaimAcceptanceValidationError(ValueError):
    """Raised when evidence is malformed, ambiguous, or cross-bound wrongly."""

    def __init__(self, errors: str | Iterable[str]) -> None:
        if isinstance(errors, str):
            normalized = (errors,)
        else:
            normalized = tuple(str(error) for error in errors)
        if not normalized:
            normalized = ("claim acceptance validation failed",)
        self.errors = normalized
        super().__init__(
            "claim acceptance validation failed: " + "; ".join(normalized)
        )


_RECORD_SCOPES: Final[dict[str, str]] = {
    "cbds.claim-statistical-evidence": (
        "finalized_artifact_bound_contrast_and_family_projection_not_sources_reopened"
    ),
    "cbds.claim-export-evidence": (
        "completed_export_projection_not_completed_run_or_inspection_derived"
    ),
    "cbds.claim-compute-comparison-evidence": (
        "run_accounting_projection_not_completed_run_derived"
    ),
    "cbds.claim-noninferiority-evidence": (
        "endpoint_projection_not_task_collection_derived"
    ),
    "cbds.claim-hardware-evidence": (
        "hardware_projection_not_hardware_result_derived"
    ),
    "cbds.claim-replication-evidence": (
        "replication_projection_not_campaign_or_task_collection_derived"
    ),
    "cbds.claim-teacher-free-evidence": (
        "teacher_ablation_projection_not_completed_run_or_task_collection_derived"
    ),
}


def _error(message: str) -> None:
    raise ClaimAcceptanceValidationError(message)


def _exact_keys(value: object, expected: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _error(f"{label} must be an object")
    assert isinstance(value, Mapping)
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected, key=lambda item: str(item))
        details: list[str] = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if extra:
            details.append("unexpected " + ", ".join(repr(item) for item in extra))
        _error(f"{label} fields do not match ({'; '.join(details)})")
    return value


def _literal(value: object, expected: object, label: str) -> None:
    if type(value) is not type(expected) or value != expected:
        _error(f"{label} must equal {expected!r}")


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        _error(f"{label} must be a lowercase SHA-256 digest")
    return value


def _identifier(value: object, label: str, *, maximum: int = 192) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or _IDENTIFIER.fullmatch(value) is None
    ):
        _error(f"{label} must be a bounded nonempty identifier")
    return value


def _integer(
    value: object,
    label: str,
    *,
    minimum: int = 0,
    maximum: int = (1 << 63) - 1,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _error(f"{label} must be an integer between {minimum} and {maximum}")
    assert isinstance(value, int)
    return value


def _number(
    value: object,
    label: str,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _error(f"{label} must be a finite number")
    number = float(value)
    if not math.isfinite(number):
        _error(f"{label} must be finite")
    if minimum is not None and number < minimum:
        _error(f"{label} must be at least {minimum}")
    if maximum is not None and number > maximum:
        _error(f"{label} must be at most {maximum}")
    return number


def _bounded_list(value: object, label: str, *, maximum: int) -> list[Any]:
    if isinstance(value, Mapping) or isinstance(value, (str, bytes, bytearray)):
        _error(f"{label} must be an iterable of evidence objects")
    try:
        iterator = iter(value)  # type: ignore[arg-type]
    except TypeError as error:
        raise ClaimAcceptanceValidationError(f"{label} must be iterable") from error
    items: list[Any] = []
    for item in iterator:
        items.append(item)
        if len(items) > maximum:
            _error(f"{label} exceeds the {maximum}-item limit")
    return items


def content_address_claim_evidence(record: Mapping[str, Any]) -> dict[str, Any]:
    """Return a defensive copy with its canonical evidence address attached.

    This helper performs no semantic validation.  It is primarily useful to
    evidence producers and tests; :func:`bind_confirmatory_lane_claim` always
    performs complete type, policy, digest, and cross-record validation.
    """

    if not isinstance(record, Mapping):
        raise ClaimAcceptanceValidationError("evidence record must be an object")
    if "evidence_sha256" in record:
        raise ClaimAcceptanceValidationError(
            "evidence record must omit evidence_sha256 before addressing"
        )
    candidate = copy.deepcopy(dict(record))
    try:
        candidate["evidence_sha256"] = value_sha256(candidate)
    except ManifestValidationError as error:
        raise ClaimAcceptanceValidationError(error.errors) from error
    return candidate


def _envelope(raw: object, record_type: str, label: str) -> dict[str, Any]:
    value = _exact_keys(
        raw,
        {
            "record_type",
            "schema_version",
            "lane",
            "reference_arm",
            "comparison_arm",
            "evidence_scope",
            "payload",
            "evidence_sha256",
        },
        label,
    )
    _literal(value["record_type"], record_type, f"{label}.record_type")
    _literal(
        value["schema_version"],
        CLAIM_EVIDENCE_SCHEMA_VERSION,
        f"{label}.schema_version",
    )
    lane = value["lane"]
    if lane not in ("fixed_size", "compression"):
        _error(f"{label}.lane must be fixed_size or compression")
    _identifier(value["reference_arm"], f"{label}.reference_arm", maximum=128)
    _identifier(value["comparison_arm"], f"{label}.comparison_arm", maximum=128)
    if value["reference_arm"] == value["comparison_arm"]:
        _error(f"{label} reference and comparison arms must differ")
    _literal(
        value["evidence_scope"],
        _RECORD_SCOPES[record_type],
        f"{label}.evidence_scope",
    )
    if not isinstance(value["payload"], Mapping):
        _error(f"{label}.payload must be an object")
    declared = _sha256(value["evidence_sha256"], f"{label}.evidence_sha256")
    unhashed = copy.deepcopy(dict(value))
    unhashed.pop("evidence_sha256")
    try:
        actual = value_sha256(unhashed)
    except ManifestValidationError as error:
        raise ClaimAcceptanceValidationError(
            tuple(f"{label}: {item}" for item in error.errors)
        ) from error
    if declared != actual:
        _error(f"{label}.evidence_sha256 does not hash the exact evidence object")
    return copy.deepcopy(dict(value))


def _validate_interval(raw: object, label: str) -> dict[str, float]:
    value = _exact_keys(
        raw,
        {"confidence_level", "lower", "upper"},
        label,
    )
    confidence = _number(
        value["confidence_level"], label + ".confidence_level", minimum=0.0, maximum=1.0
    )
    _literal(confidence, SIMULTANEOUS_CONFIDENCE_LEVEL, label + ".confidence_level")
    lower = _number(value["lower"], label + ".lower", minimum=-1.0, maximum=1.0)
    upper = _number(value["upper"], label + ".upper", minimum=-1.0, maximum=1.0)
    if lower > upper:
        _error(f"{label} is inverted")
    return {"confidence_level": confidence, "lower": lower, "upper": upper}


def _validate_family_contrast_bindings(raw: object) -> list[dict[str, Any]]:
    items = _bounded_list(
        raw,
        "statistical_evidence.payload.family_contrast_bindings",
        maximum=2,
    )
    if len(items) != 2:
        _error(
            "statistical_evidence.payload.family_contrast_bindings must contain "
            "exactly two contrasts"
        )
    validated: list[dict[str, Any]] = []
    for index, raw_item in enumerate(items):
        label = f"statistical_evidence.payload.family_contrast_bindings[{index}]"
        item = _exact_keys(
            raw_item,
            {
                "contrast_id",
                "lane",
                "contrast_record_sha256",
                "analysis_policy_sha256",
                "evaluation_id",
                "evaluation_spec_sha256",
                "artifact_bound_outcome_cube",
            },
            label,
        )
        _identifier(item["contrast_id"], label + ".contrast_id")
        if item["lane"] not in ("compression", "fixed_size"):
            _error(label + ".lane must be compression or fixed_size")
        for field in (
            "contrast_record_sha256",
            "analysis_policy_sha256",
            "evaluation_spec_sha256",
        ):
            _sha256(item[field], f"{label}.{field}")
        _identifier(item["evaluation_id"], label + ".evaluation_id")
        cube = _exact_keys(
            item["artifact_bound_outcome_cube"],
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
            label + ".artifact_bound_outcome_cube",
        )
        _literal(
            cube["binder_version"],
            "1.0.0",
            label + ".artifact_bound_outcome_cube.binder_version",
        )
        for field in ("cohort_id", "cube_id"):
            _identifier(
                cube[field],
                f"{label}.artifact_bound_outcome_cube.{field}",
            )
        for field in (
            "campaign_registry_sha256",
            "campaign_policy_sha256",
            "registry_paired_cube_sha256",
            "binary_cells_sha256",
            "bound_cube_record_sha256",
        ):
            _sha256(
                cube[field],
                f"{label}.artifact_bound_outcome_cube.{field}",
            )
        _literal(
            cube["outcome_evidence_scope"],
            "derived_from_jointly_validated_registry_bound_scored_task_results",
            label + ".artifact_bound_outcome_cube.outcome_evidence_scope",
        )
        _literal(
            cube["runtime_attestation"],
            "none",
            label + ".artifact_bound_outcome_cube.runtime_attestation",
        )
        normalized = copy.deepcopy(dict(item))
        normalized["artifact_bound_outcome_cube"] = copy.deepcopy(dict(cube))
        validated.append(normalized)

    if [item["lane"] for item in validated] != ["compression", "fixed_size"]:
        _error(
            "statistical_evidence.payload.family_contrast_bindings must be "
            "ordered compression then fixed_size"
        )
    if len({item["contrast_id"] for item in validated}) != 2:
        _error(
            "statistical_evidence.payload.family_contrast_bindings requires "
            "unique contrast IDs"
        )
    if len({item["contrast_record_sha256"] for item in validated}) != 2:
        _error(
            "statistical_evidence.payload.family_contrast_bindings requires "
            "unique contrast records"
        )
    if len(
        {
            item["artifact_bound_outcome_cube"]["bound_cube_record_sha256"]
            for item in validated
        }
    ) != 2:
        _error(
            "statistical_evidence.payload.family_contrast_bindings requires "
            "unique artifact-bound cube records"
        )
    for field in ("campaign_registry_sha256", "campaign_policy_sha256"):
        if len(
            {
                item["artifact_bound_outcome_cube"][field]
                for item in validated
            }
        ) != 1:
            _error(
                "statistical_evidence.payload.family_contrast_bindings "
                f"disagree on {field}"
            )
    return validated


def _validate_statistical(raw: object) -> dict[str, Any]:
    envelope = _envelope(raw, "cbds.claim-statistical-evidence", "statistical_evidence")
    payload = _exact_keys(
        envelope["payload"],
        {
            "family_record_sha256",
            "family_contrast_bindings",
            "family_contrast_bindings_sha256",
            "contrast_record_sha256",
            "contrast_id",
            "primary_benchmark_id",
            "primary_backbone_id",
            "direct_baseline_role",
            "paired_seed_count",
            "estimate_difference_proportion",
            "simultaneous_confidence_interval",
            "holm_adjusted_p_value",
            "outcome_evidence_scope",
            "artifact_bound_binary_cells_sha256",
            "artifact_bound_cube_record_sha256",
            "campaign_registry_sha256",
            "evaluation_spec_sha256",
        },
        "statistical_evidence.payload",
    )
    for field in (
        "family_record_sha256",
        "family_contrast_bindings_sha256",
        "contrast_record_sha256",
        "artifact_bound_binary_cells_sha256",
        "artifact_bound_cube_record_sha256",
        "campaign_registry_sha256",
        "evaluation_spec_sha256",
    ):
        _sha256(payload[field], f"statistical_evidence.payload.{field}")
    family_bindings = _validate_family_contrast_bindings(
        payload["family_contrast_bindings"]
    )
    family_commitment = {
        "commitment_type": "cbds.confirmatory-family-input-contrasts",
        "version": "1.0.0",
        "ordering": "compression_then_fixed_size",
        "bindings": family_bindings,
    }
    if payload["family_contrast_bindings_sha256"] != value_sha256(
        family_commitment
    ):
        _error(
            "statistical_evidence.payload.family_contrast_bindings_sha256 "
            "does not hash the ordered family contrast bindings"
        )
    for field in ("contrast_id", "primary_benchmark_id", "primary_backbone_id"):
        _identifier(payload[field], f"statistical_evidence.payload.{field}")
    expected_role = (
        "strongest_matched_data_matched_flop_dense"
        if envelope["lane"] == "fixed_size"
        else "strongest_task_agnostic_compression_at_comparable_bytes"
    )
    _literal(
        payload["direct_baseline_role"],
        expected_role,
        "statistical_evidence.payload.direct_baseline_role",
    )
    _literal(payload["paired_seed_count"], 5, "statistical_evidence.payload.paired_seed_count")
    estimate = _number(
        payload["estimate_difference_proportion"],
        "statistical_evidence.payload.estimate_difference_proportion",
        minimum=-1.0,
        maximum=1.0,
    )
    interval = _validate_interval(
        payload["simultaneous_confidence_interval"],
        "statistical_evidence.payload.simultaneous_confidence_interval",
    )
    adjusted_p = _number(
        payload["holm_adjusted_p_value"],
        "statistical_evidence.payload.holm_adjusted_p_value",
        minimum=0.0,
        maximum=1.0,
    )
    _literal(
        payload["outcome_evidence_scope"],
        "artifact_bound_scored_task_result_collections",
        "statistical_evidence.payload.outcome_evidence_scope",
    )
    selected = next(
        item for item in family_bindings if item["lane"] == envelope["lane"]
    )
    selected_cube = selected["artifact_bound_outcome_cube"]
    selected_cross_bindings = {
        "contrast_id": selected["contrast_id"],
        "contrast_record_sha256": selected["contrast_record_sha256"],
        "evaluation_spec_sha256": selected["evaluation_spec_sha256"],
        "artifact_bound_binary_cells_sha256": selected_cube[
            "binary_cells_sha256"
        ],
        "artifact_bound_cube_record_sha256": selected_cube[
            "bound_cube_record_sha256"
        ],
        "campaign_registry_sha256": selected_cube["campaign_registry_sha256"],
    }
    for field, expected in selected_cross_bindings.items():
        if payload[field] != expected:
            _error(
                f"statistical_evidence.payload.{field} disagrees with the "
                f"{envelope['lane']} family contrast binding"
            )
    envelope["payload"] = {
        **copy.deepcopy(dict(payload)),
        "family_contrast_bindings": family_bindings,
        "estimate_difference_proportion": estimate,
        "simultaneous_confidence_interval": interval,
        "holm_adjusted_p_value": adjusted_p,
    }
    return envelope


_ARTIFACT_FIELDS: Final[set[str]] = {
    "arm_id",
    "completed_run_sha256",
    "run_spec_sha256",
    "artifact_sha256",
    "bundle_sha256",
    "tokenizer_sha256",
    "inspection_report_sha256",
    "architecture_layout_sha256",
    "precision_layout_sha256",
    "operator_configuration_sha256",
    "architecture",
    "format",
    "physical_parameters",
    "active_parameters",
    "average_weight_bits",
    "weight_bytes",
    "bundle_bytes",
    "teacher_enabled",
    "verified_teacher_corpus_sha256",
}


def _validate_artifact_projection(raw: object, label: str) -> dict[str, Any]:
    value = _exact_keys(raw, _ARTIFACT_FIELDS, label)
    arm_id = _identifier(value["arm_id"], label + ".arm_id", maximum=128)
    for field in (
        "completed_run_sha256",
        "run_spec_sha256",
        "artifact_sha256",
        "bundle_sha256",
        "tokenizer_sha256",
        "inspection_report_sha256",
        "architecture_layout_sha256",
        "precision_layout_sha256",
        "operator_configuration_sha256",
    ):
        _sha256(value[field], f"{label}.{field}")
    _literal(value["architecture"], "dense", label + ".architecture")
    _literal(value["format"], "safetensors", label + ".format")
    physical = _integer(
        value["physical_parameters"], label + ".physical_parameters", minimum=1
    )
    active = _integer(value["active_parameters"], label + ".active_parameters", minimum=1)
    if physical >= SUB_BILLION_PHYSICAL_PARAMETER_LIMIT:
        _error(f"{label}.physical_parameters must be below one billion")
    if active != physical:
        _error(f"{label}.active_parameters must equal physical_parameters for a dense claim")
    average_bits = _number(
        value["average_weight_bits"],
        label + ".average_weight_bits",
        minimum=1.0,
        maximum=64.0,
    )
    weight_bytes = _integer(value["weight_bytes"], label + ".weight_bytes", minimum=1)
    bundle_bytes = _integer(value["bundle_bytes"], label + ".bundle_bytes", minimum=1)
    if weight_bytes > bundle_bytes:
        _error(f"{label}.weight_bytes cannot exceed bundle_bytes")
    if type(value["teacher_enabled"]) is not bool:
        _error(f"{label}.teacher_enabled must be a boolean")
    corpus = value["verified_teacher_corpus_sha256"]
    if value["teacher_enabled"]:
        _sha256(corpus, label + ".verified_teacher_corpus_sha256")
    elif corpus is not None:
        _error(
            f"{label}.verified_teacher_corpus_sha256 must be null when teacher_enabled is false"
        )
    return {
        **copy.deepcopy(dict(value)),
        "arm_id": arm_id,
        "physical_parameters": physical,
        "active_parameters": active,
        "average_weight_bits": average_bits,
        "weight_bytes": weight_bytes,
        "bundle_bytes": bundle_bytes,
    }


def _validate_export(raw: object) -> dict[str, Any]:
    envelope = _envelope(raw, "cbds.claim-export-evidence", "export_evidence")
    payload = _exact_keys(
        envelope["payload"],
        {
            "source_artifact",
            "direct_baseline_artifact",
            "comparison_artifact",
            "fixed_size_metadata_tolerance_bytes",
            "comparable_bytes_tolerance_fraction",
            "comparable_bytes_policy_sha256",
        },
        "export_evidence.payload",
    )
    source = _validate_artifact_projection(
        payload["source_artifact"], "export_evidence.payload.source_artifact"
    )
    reference = _validate_artifact_projection(
        payload["direct_baseline_artifact"],
        "export_evidence.payload.direct_baseline_artifact",
    )
    comparison = _validate_artifact_projection(
        payload["comparison_artifact"],
        "export_evidence.payload.comparison_artifact",
    )
    if reference["arm_id"] != envelope["reference_arm"]:
        _error("export direct baseline arm does not match the evidence reference arm")
    if comparison["arm_id"] != envelope["comparison_arm"]:
        _error("export comparison artifact arm does not match the evidence comparison arm")
    if len({
        source["completed_run_sha256"],
        reference["completed_run_sha256"],
        comparison["completed_run_sha256"],
    }) < 2:
        _error("export evidence must identify at least two distinct completed runs")
    _literal(
        payload["fixed_size_metadata_tolerance_bytes"],
        FIXED_SIZE_METADATA_TOLERANCE_BYTES,
        "export_evidence.payload.fixed_size_metadata_tolerance_bytes",
    )
    tolerance = _number(
        payload["comparable_bytes_tolerance_fraction"],
        "export_evidence.payload.comparable_bytes_tolerance_fraction",
        minimum=0.0,
        maximum=MAX_COMPARABLE_BYTES_FRACTION,
    )
    if envelope["lane"] == "fixed_size" and tolerance != 0.0:
        _error("fixed-size comparable-bytes tolerance must be zero")
    comparability_policy = _sha256(
        payload["comparable_bytes_policy_sha256"],
        "export_evidence.payload.comparable_bytes_policy_sha256",
    )
    if len({source["arm_id"], reference["arm_id"], comparison["arm_id"]}) != 3:
        _error("source, direct-baseline, and comparison artifact arms must be distinct")
    if comparison["artifact_sha256"] in {
        source["artifact_sha256"],
        reference["artifact_sha256"],
    }:
        _error("comparison artifact bytes must differ from source and direct baseline")
    envelope["payload"] = {
        "source_artifact": source,
        "direct_baseline_artifact": reference,
        "comparison_artifact": comparison,
        "fixed_size_metadata_tolerance_bytes": FIXED_SIZE_METADATA_TOLERANCE_BYTES,
        "comparable_bytes_tolerance_fraction": tolerance,
        "comparable_bytes_policy_sha256": comparability_policy,
    }
    return envelope


def _validate_compute(raw: object, index: int) -> dict[str, Any]:
    label = f"compute_comparison_evidence[{index}]"
    envelope = _envelope(raw, "cbds.claim-compute-comparison-evidence", label)
    payload = _exact_keys(
        envelope["payload"],
        {
            "comparison_kind",
            "reference_completed_run_sha256",
            "comparison_completed_run_sha256",
            "reference_target_tokens",
            "comparison_target_tokens",
            "reference_total_flops",
            "comparison_total_flops",
            "performance_evidence_sha256",
            "reference_target_data_sha256",
            "comparison_target_data_sha256",
            "reference_support_data_sha256",
            "comparison_support_data_sha256",
            "reference_teacher_corpus_sha256",
            "comparison_teacher_corpus_sha256",
        },
        label + ".payload",
    )
    if payload["comparison_kind"] not in ("equal_target_tokens", "equal_total_flops"):
        _error(f"{label}.payload.comparison_kind is not recognized")
    for field in (
        "reference_completed_run_sha256",
        "comparison_completed_run_sha256",
        "performance_evidence_sha256",
        "reference_target_data_sha256",
        "comparison_target_data_sha256",
        "reference_support_data_sha256",
        "comparison_support_data_sha256",
    ):
        _sha256(payload[field], f"{label}.payload.{field}")
    for field in ("reference_teacher_corpus_sha256", "comparison_teacher_corpus_sha256"):
        if payload[field] is not None:
            _sha256(payload[field], f"{label}.payload.{field}")
    normalized = copy.deepcopy(dict(payload))
    for field in (
        "reference_target_tokens",
        "comparison_target_tokens",
        "reference_total_flops",
        "comparison_total_flops",
    ):
        normalized[field] = _integer(payload[field], f"{label}.payload.{field}", minimum=1)
    envelope["payload"] = normalized
    return envelope


def _validate_endpoint(
    raw: object,
    label: str,
    *,
    expected_margin_points: float | None = None,
    maximum_margin_points: float | None = None,
) -> dict[str, Any]:
    value = _exact_keys(
        raw,
        {
            "reference_arm",
            "comparison_arm",
            "result_evidence_sha256",
            "estimate_difference_proportion",
            "simultaneous_confidence_interval",
            "margin_absolute_points",
            "prospective_margin_policy_sha256",
        },
        label,
    )
    reference_arm = _identifier(value["reference_arm"], label + ".reference_arm", maximum=128)
    comparison_arm = _identifier(value["comparison_arm"], label + ".comparison_arm", maximum=128)
    if reference_arm == comparison_arm:
        _error(f"{label} reference and comparison arms must differ")
    _sha256(value["result_evidence_sha256"], label + ".result_evidence_sha256")
    _sha256(
        value["prospective_margin_policy_sha256"],
        label + ".prospective_margin_policy_sha256",
    )
    estimate = _number(
        value["estimate_difference_proportion"],
        label + ".estimate_difference_proportion",
        minimum=-1.0,
        maximum=1.0,
    )
    interval = _validate_interval(value["simultaneous_confidence_interval"], label + ".simultaneous_confidence_interval")
    margin = _number(
        value["margin_absolute_points"],
        label + ".margin_absolute_points",
        minimum=0.0,
        maximum=100.0,
    )
    if expected_margin_points is not None:
        _literal(margin, expected_margin_points, label + ".margin_absolute_points")
    if maximum_margin_points is not None and margin > maximum_margin_points:
        _error(
            f"{label}.margin_absolute_points exceeds the binder maximum "
            f"{maximum_margin_points}"
        )
    return {
        **copy.deepcopy(dict(value)),
        "reference_arm": reference_arm,
        "comparison_arm": comparison_arm,
        "estimate_difference_proportion": estimate,
        "simultaneous_confidence_interval": interval,
        "margin_absolute_points": margin,
    }


def _validate_noninferiority(raw: object) -> dict[str, Any]:
    envelope = _envelope(
        raw, "cbds.claim-noninferiority-evidence", "noninferiority_evidence"
    )
    payload = _exact_keys(
        envelope["payload"],
        {
            "bounded_terminal",
            "protected_capability_roster_sha256",
            "protected_capabilities",
            "compression_static_source",
        },
        "noninferiority_evidence.payload",
    )
    bounded = _validate_endpoint(
        payload["bounded_terminal"],
        "noninferiority_evidence.payload.bounded_terminal",
        expected_margin_points=2.0,
    )
    if bounded["reference_arm"] != envelope["reference_arm"] or bounded[
        "comparison_arm"
    ] != envelope["comparison_arm"]:
        _error("bounded-terminal endpoint arms do not match its evidence envelope")
    raw_protected = _bounded_list(
        payload["protected_capabilities"],
        "noninferiority_evidence.payload.protected_capabilities",
        maximum=_MAX_EVIDENCE_ITEMS,
    )
    if not raw_protected:
        _error("noninferiority evidence requires at least one protected capability")
    protected: list[dict[str, Any]] = []
    roster_projection: list[dict[str, Any]] = []
    for index, raw_entry in enumerate(raw_protected):
        label = f"noninferiority_evidence.payload.protected_capabilities[{index}]"
        entry = _exact_keys(raw_entry, {"capability_id", "endpoint"}, label)
        capability_id = _identifier(entry["capability_id"], label + ".capability_id")
        endpoint = _validate_endpoint(
            entry["endpoint"],
            label + ".endpoint",
            maximum_margin_points=PROTECTED_CAPABILITY_MAX_MARGIN_POINTS,
        )
        if endpoint["reference_arm"] != envelope["reference_arm"] or endpoint[
            "comparison_arm"
        ] != envelope["comparison_arm"]:
            _error(f"{label}.endpoint arms do not match the evidence envelope")
        protected.append({"capability_id": capability_id, "endpoint": endpoint})
        roster_projection.append(
            {
                "capability_id": capability_id,
                "margin_absolute_points": endpoint["margin_absolute_points"],
                "prospective_margin_policy_sha256": endpoint[
                    "prospective_margin_policy_sha256"
                ],
            }
        )
    expected_order = sorted(protected, key=lambda item: item["capability_id"].encode("utf-8"))
    if protected != expected_order:
        _error("protected capabilities must be ordered by UTF-8 capability_id")
    ids = [item["capability_id"] for item in protected]
    if len(set(ids)) != len(ids):
        _error("protected capabilities contain duplicate capability IDs")
    declared_roster = _sha256(
        payload["protected_capability_roster_sha256"],
        "noninferiority_evidence.payload.protected_capability_roster_sha256",
    )
    if declared_roster != value_sha256(roster_projection):
        _error("protected capability roster hash is not derived from the exact roster")
    compression_static: dict[str, Any] | None
    if envelope["lane"] == "compression":
        compression_static = _validate_endpoint(
            payload["compression_static_source"],
            "noninferiority_evidence.payload.compression_static_source",
            expected_margin_points=1.0,
        )
        if compression_static["comparison_arm"] != envelope["comparison_arm"]:
            _error("compression static-source endpoint comparison arm is not primary")
    else:
        if payload["compression_static_source"] is not None:
            _error("fixed-size noninferiority evidence must omit compression static source")
        compression_static = None
    envelope["payload"] = {
        "bounded_terminal": bounded,
        "protected_capability_roster_sha256": declared_roster,
        "protected_capabilities": protected,
        "compression_static_source": compression_static,
    }
    return envelope


def _validate_hardware(raw: object) -> dict[str, Any]:
    envelope = _envelope(raw, "cbds.claim-hardware-evidence", "hardware_evidence")
    payload = _exact_keys(
        envelope["payload"],
        {
            "reference_role",
            "reference_completed_run_sha256",
            "comparison_completed_run_sha256",
            "reference_hardware_result_sha256",
            "comparison_hardware_result_sha256",
            "hardware_protocol_sha256",
            "hardware_stratum_sha256",
            "peak_memory_metric",
            "reference_peak_memory_bytes",
            "comparison_peak_memory_bytes",
            "reference_weight_bytes",
            "comparison_weight_bytes",
            "reference_bundle_bytes",
            "comparison_bundle_bytes",
        },
        "hardware_evidence.payload",
    )
    expected_role = "direct_baseline" if envelope["lane"] == "fixed_size" else "precompression_source"
    _literal(payload["reference_role"], expected_role, "hardware_evidence.payload.reference_role")
    for field in (
        "reference_completed_run_sha256",
        "comparison_completed_run_sha256",
        "reference_hardware_result_sha256",
        "comparison_hardware_result_sha256",
        "hardware_protocol_sha256",
        "hardware_stratum_sha256",
    ):
        _sha256(payload[field], f"hardware_evidence.payload.{field}")
    if payload["peak_memory_metric"] not in ("peak_host_rss_bytes", "peak_device_memory_bytes"):
        _error("hardware_evidence.payload.peak_memory_metric is not portable accounting")
    normalized = copy.deepcopy(dict(payload))
    for field in (
        "reference_peak_memory_bytes",
        "comparison_peak_memory_bytes",
        "reference_weight_bytes",
        "comparison_weight_bytes",
        "reference_bundle_bytes",
        "comparison_bundle_bytes",
    ):
        normalized[field] = _integer(payload[field], f"hardware_evidence.payload.{field}", minimum=1)
    envelope["payload"] = normalized
    return envelope


def _validate_replication(raw: object, index: int) -> dict[str, Any]:
    label = f"replication_evidence[{index}]"
    envelope = _envelope(raw, "cbds.claim-replication-evidence", label)
    payload = _exact_keys(
        envelope["payload"],
        {
            "replication_role",
            "benchmark_id",
            "backbone_id",
            "result_evidence_sha256",
            "operator_configuration_sha256",
            "paired_seed_count",
            "estimate_difference_proportion",
            "simultaneous_confidence_interval",
        },
        label + ".payload",
    )
    if payload["replication_role"] not in (
        "runner_up_static",
        "independent_static",
        "independent_interactive",
    ):
        _error(f"{label}.payload.replication_role is not recognized")
    for field in ("benchmark_id", "backbone_id"):
        _identifier(payload[field], f"{label}.payload.{field}")
    for field in ("result_evidence_sha256", "operator_configuration_sha256"):
        _sha256(payload[field], f"{label}.payload.{field}")
    _literal(payload["paired_seed_count"], 5, label + ".payload.paired_seed_count")
    estimate = _number(
        payload["estimate_difference_proportion"],
        label + ".payload.estimate_difference_proportion",
        minimum=-1.0,
        maximum=1.0,
    )
    interval = _validate_interval(
        payload["simultaneous_confidence_interval"],
        label + ".payload.simultaneous_confidence_interval",
    )
    envelope["payload"] = {
        **copy.deepcopy(dict(payload)),
        "estimate_difference_proportion": estimate,
        "simultaneous_confidence_interval": interval,
    }
    return envelope


def _validate_teacher(raw: object) -> dict[str, Any]:
    envelope = _envelope(raw, "cbds.claim-teacher-free-evidence", "teacher_free_evidence")
    payload = _exact_keys(
        envelope["payload"],
        {
            "main_comparison_completed_run_sha256",
            "main_teacher_enabled",
            "main_verified_teacher_corpus_sha256",
            "teacher_free_completed_run_set_sha256",
            "teacher_free_result_evidence_sha256",
            "teacher_free_operator_configuration_sha256",
            "teacher_free_paired_seed_count",
            "teacher_free_estimate_difference_proportion",
        },
        "teacher_free_evidence.payload",
    )
    for field in (
        "main_comparison_completed_run_sha256",
        "teacher_free_completed_run_set_sha256",
        "teacher_free_result_evidence_sha256",
        "teacher_free_operator_configuration_sha256",
    ):
        _sha256(payload[field], f"teacher_free_evidence.payload.{field}")
    if type(payload["main_teacher_enabled"]) is not bool:
        _error("teacher_free_evidence.payload.main_teacher_enabled must be a boolean")
    corpus = payload["main_verified_teacher_corpus_sha256"]
    if payload["main_teacher_enabled"]:
        _sha256(corpus, "teacher_free_evidence.payload.main_verified_teacher_corpus_sha256")
    elif corpus is not None:
        _error("teacher-free main run cannot declare a verified teacher corpus")
    _literal(
        payload["teacher_free_paired_seed_count"],
        5,
        "teacher_free_evidence.payload.teacher_free_paired_seed_count",
    )
    estimate = _number(
        payload["teacher_free_estimate_difference_proportion"],
        "teacher_free_evidence.payload.teacher_free_estimate_difference_proportion",
        minimum=-1.0,
        maximum=1.0,
    )
    envelope["payload"] = {
        **copy.deepcopy(dict(payload)),
        "teacher_free_estimate_difference_proportion": estimate,
    }
    return envelope


def _same_primary_binding(
    primary: Mapping[str, Any], evidence: Mapping[str, Any], label: str
) -> None:
    for field in ("lane", "reference_arm", "comparison_arm"):
        if evidence[field] != primary[field]:
            _error(f"{label}.{field} does not match primary statistical evidence")


def _fractional_distance(left: int, right: int) -> float:
    return abs(float(left) - float(right)) / float(right)


def _endpoint_decision(endpoint: Mapping[str, Any]) -> dict[str, Any]:
    margin_proportion = float(endpoint["margin_absolute_points"]) / 100.0
    lower = float(endpoint["simultaneous_confidence_interval"]["lower"])
    return {
        "reference_arm": endpoint["reference_arm"],
        "comparison_arm": endpoint["comparison_arm"],
        "margin_absolute_points": float(endpoint["margin_absolute_points"]),
        "margin_proportion": margin_proportion,
        "estimate_difference_proportion": float(endpoint["estimate_difference_proportion"]),
        "simultaneous_confidence_interval": copy.deepcopy(
            endpoint["simultaneous_confidence_interval"]
        ),
        "noninferior": lower >= -margin_proportion,
    }


def _authorization_requirements(
    *,
    statistical: Mapping[str, Any],
    export: Mapping[str, Any],
    compute: Mapping[str, Mapping[str, Any]],
    noninferiority: Mapping[str, Any],
    hardware: Mapping[str, Any],
    replications: Mapping[str, Mapping[str, Any]],
    teacher: Mapping[str, Any],
) -> list[dict[str, Any]]:
    stats_payload = statistical["payload"]
    export_payload = export["payload"]
    noninferiority_payload = noninferiority["payload"]
    hardware_payload = hardware["payload"]
    family_contrast_bindings = stats_payload["family_contrast_bindings"]

    endpoint_hashes = [
        noninferiority_payload["bounded_terminal"]["result_evidence_sha256"],
        *(
            item["endpoint"]["result_evidence_sha256"]
            for item in noninferiority_payload["protected_capabilities"]
        ),
    ]
    if noninferiority_payload["compression_static_source"] is not None:
        endpoint_hashes.append(
            noninferiority_payload["compression_static_source"][
                "result_evidence_sha256"
            ]
        )

    requirements = [
        {
            "connection_id": "primary_statistical_cells_and_family",
            "status": "not_executed_end_to_end",
            "required_validator_chain": [
                "cbds.outcome_binding.bind_confirmatory_binary_cube",
                "cbds.outcome_binding.run_confirmatory_contrast_from_collections",
                "cbds.confirmatory_analysis.finalize_confirmatory_family",
            ],
            "required_source_sha256s": sorted(
                {
                    stats_payload["family_record_sha256"],
                    stats_payload["family_contrast_bindings_sha256"],
                    *(
                        item[field]
                        for item in family_contrast_bindings
                        for field in (
                            "contrast_record_sha256",
                            "analysis_policy_sha256",
                            "evaluation_spec_sha256",
                        )
                    ),
                    *(
                        item["artifact_bound_outcome_cube"][field]
                        for item in family_contrast_bindings
                        for field in (
                            "campaign_registry_sha256",
                            "campaign_policy_sha256",
                            "registry_paired_cube_sha256",
                            "binary_cells_sha256",
                            "bound_cube_record_sha256",
                        )
                    ),
                }
            ),
            "missing_source_hash_bindings": [
                "family_record_input_contrast_bindings_not_reopened",
                "family_contrast_records_not_reopened",
                "artifact_bound_cube_records_not_reopened",
                "campaign_registry_document_graph_not_reopened",
                "evaluation_spec_set_not_reopened",
                "task_result_collection_sets_not_reopened",
                "analysis_code_bytes_not_runtime_attested",
            ],
            "projection_evidence_sha256s": [statistical["evidence_sha256"]],
        },
        {
            "connection_id": "completed_export_and_dense_artifact_inspection",
            "status": "not_executed_end_to_end",
            "required_validator_chain": [
                "cbds.run_specs.validate_completed_run_against_campaign",
                "cbds.model_artifacts.verify_inspection_report_sha256",
                "claim binder completed-run/export projection derivation (not implemented)",
            ],
            "required_source_sha256s": sorted(
                {
                    item[field]
                    for item in (
                        export_payload["source_artifact"],
                        export_payload["direct_baseline_artifact"],
                        export_payload["comparison_artifact"],
                    )
                    for field in (
                        "completed_run_sha256",
                        "run_spec_sha256",
                        "artifact_sha256",
                        "bundle_sha256",
                        "tokenizer_sha256",
                        "inspection_report_sha256",
                        "architecture_layout_sha256",
                        "precision_layout_sha256",
                        "operator_configuration_sha256",
                    )
                }
                | {export_payload["comparable_bytes_policy_sha256"]}
            ),
            "missing_source_hash_bindings": [],
            "projection_evidence_sha256s": [export["evidence_sha256"]],
        },
        {
            "connection_id": "equal_target_and_equal_flop_accounting",
            "status": "not_executed_end_to_end",
            "required_validator_chain": [
                "cbds.run_specs.validate_completed_run_against_campaign",
                "claim binder measured-token/FLOP projection derivation (not implemented)",
            ],
            "required_source_sha256s": sorted(
                hash_value
                for hash_value in {
                    evidence["payload"][field]
                    for evidence in compute.values()
                    for field in (
                        "reference_completed_run_sha256",
                        "comparison_completed_run_sha256",
                        "performance_evidence_sha256",
                        "reference_target_data_sha256",
                        "comparison_target_data_sha256",
                        "reference_support_data_sha256",
                        "comparison_support_data_sha256",
                        "reference_teacher_corpus_sha256",
                        "comparison_teacher_corpus_sha256",
                    )
                }
                if hash_value is not None
            ),
            "missing_source_hash_bindings": [],
            "projection_evidence_sha256s": sorted(
                evidence["evidence_sha256"] for evidence in compute.values()
            ),
        },
        {
            "connection_id": "bounded_and_protected_noninferiority",
            "status": "not_executed_end_to_end",
            "required_validator_chain": [
                "cbds.evaluation_specs.validate_task_result_collection_against_evaluation_spec",
                "claim binder bounded/protected collection analysis runner (not implemented)",
                "claim binder protected-roster campaign binding (not implemented)",
            ],
            "required_source_sha256s": sorted(
                {
                    *endpoint_hashes,
                    noninferiority_payload["protected_capability_roster_sha256"],
                    noninferiority_payload["bounded_terminal"][
                        "prospective_margin_policy_sha256"
                    ],
                    *(
                        item["endpoint"]["prospective_margin_policy_sha256"]
                        for item in noninferiority_payload["protected_capabilities"]
                    ),
                    *(
                        [
                            noninferiority_payload["compression_static_source"][
                                "prospective_margin_policy_sha256"
                            ]
                        ]
                        if noninferiority_payload["compression_static_source"]
                        is not None
                        else []
                    ),
                }
            ),
            "missing_source_hash_bindings": [
                "campaign_registry_sha256",
                "bounded_terminal_evaluation_spec_sha256",
                "bounded_terminal_task_result_collection_set_sha256",
                "protected_capability_evaluation_spec_set_sha256",
                "protected_capability_task_result_collection_set_sha256",
            ],
            "projection_evidence_sha256s": [noninferiority["evidence_sha256"]],
        },
        {
            "connection_id": "portable_hardware_peak_memory_and_bytes",
            "status": "not_executed_end_to_end",
            "required_validator_chain": [
                "cbds.manifests.validate_hardware_result_against_experiment_manifest",
                "claim binder paired hardware-stratum projection derivation (not implemented)",
            ],
            "required_source_sha256s": sorted(
                [
                    hardware_payload["reference_hardware_result_sha256"],
                    hardware_payload["comparison_hardware_result_sha256"],
                    hardware_payload["hardware_protocol_sha256"],
                    hardware_payload["hardware_stratum_sha256"],
                    hardware_payload["reference_completed_run_sha256"],
                    hardware_payload["comparison_completed_run_sha256"],
                ]
            ),
            "missing_source_hash_bindings": [],
            "projection_evidence_sha256s": [hardware["evidence_sha256"]],
        },
        {
            "connection_id": "runner_up_and_independent_benchmark_replication",
            "status": "not_executed_end_to_end",
            "required_validator_chain": [
                "cbds.campaign_registry.validate_campaign_registry",
                "cbds.evaluation_specs.validate_task_result_collection_against_evaluation_spec",
                "claim binder replication projection derivation (not implemented)",
            ],
            "required_source_sha256s": sorted(
                evidence["payload"]["result_evidence_sha256"]
                for evidence in replications.values()
            ),
            "missing_source_hash_bindings": [
                "campaign_registry_sha256",
                "replication_evaluation_spec_set_sha256",
                "replication_task_result_collection_set_sha256",
            ],
            "projection_evidence_sha256s": sorted(
                evidence["evidence_sha256"] for evidence in replications.values()
            ),
        },
        {
            "connection_id": "teacher_free_ablation",
            "status": "not_executed_end_to_end",
            "required_validator_chain": [
                "cbds.run_specs.validate_completed_run_against_campaign",
                "cbds.evaluation_specs.validate_task_result_collection_against_evaluation_spec",
                "claim binder teacher-free ablation projection derivation (not implemented)",
            ],
            "required_source_sha256s": sorted(
                [
                    teacher["payload"]["main_comparison_completed_run_sha256"],
                    teacher["payload"]["teacher_free_completed_run_set_sha256"],
                    teacher["payload"]["teacher_free_result_evidence_sha256"],
                    teacher["payload"]["teacher_free_operator_configuration_sha256"],
                    *(
                        [teacher["payload"]["main_verified_teacher_corpus_sha256"]]
                        if teacher["payload"]["main_verified_teacher_corpus_sha256"]
                        is not None
                        else []
                    ),
                ]
            ),
            "missing_source_hash_bindings": ["campaign_registry_sha256"],
            "projection_evidence_sha256s": [teacher["evidence_sha256"]],
        },
    ]
    return requirements


def bind_confirmatory_lane_claim(
    statistical_evidence: Mapping[str, Any],
    export_evidence: Mapping[str, Any],
    compute_comparison_evidence: Iterable[Mapping[str, Any]],
    noninferiority_evidence: Mapping[str, Any],
    hardware_evidence: Mapping[str, Any],
    replication_evidence: Iterable[Mapping[str, Any]],
    teacher_free_evidence: Mapping[str, Any],
) -> dict[str, Any]:
    """Evaluate one fixed-size or compression lane without authorizing a claim.

    Every input must be an exact content-addressed evidence object.  This
    function derives all policy decisions and cross-bindings; it accepts no
    caller-supplied ``passed`` or ``success`` fields.  See the module docstring
    and the returned ``authorization`` section for the deliberately missing
    end-to-end source-derivation step.
    """

    statistical = _validate_statistical(statistical_evidence)
    export = _validate_export(export_evidence)
    noninferiority = _validate_noninferiority(noninferiority_evidence)
    hardware = _validate_hardware(hardware_evidence)
    teacher = _validate_teacher(teacher_free_evidence)

    for label, evidence in (
        ("export_evidence", export),
        ("noninferiority_evidence", noninferiority),
        ("teacher_free_evidence", teacher),
    ):
        _same_primary_binding(statistical, evidence, label)

    raw_compute = _bounded_list(
        compute_comparison_evidence,
        "compute_comparison_evidence",
        maximum=2,
    )
    if len(raw_compute) != 2:
        _error("exactly two compute comparisons are required")
    compute_list = [_validate_compute(item, index) for index, item in enumerate(raw_compute)]
    compute: dict[str, dict[str, Any]] = {}
    for evidence in compute_list:
        kind = evidence["payload"]["comparison_kind"]
        if kind in compute:
            _error(f"duplicate compute comparison kind {kind!r}")
        compute[kind] = evidence
    if set(compute) != {"equal_target_tokens", "equal_total_flops"}:
        _error("compute evidence must contain equal-target and equal-FLOP comparisons")
    for kind, evidence in compute.items():
        if evidence["lane"] != statistical["lane"]:
            _error(f"compute comparison {kind!r} lane does not match primary evidence")
        if evidence["comparison_arm"] != statistical["comparison_arm"]:
            _error(f"compute comparison {kind!r} comparison arm does not match primary evidence")

    raw_replications = _bounded_list(
        replication_evidence, "replication_evidence", maximum=3
    )
    if len(raw_replications) != 3:
        _error("exactly three replication evidence objects are required")
    replication_list = [
        _validate_replication(item, index) for index, item in enumerate(raw_replications)
    ]
    replications: dict[str, dict[str, Any]] = {}
    for evidence in replication_list:
        role = evidence["payload"]["replication_role"]
        if role in replications:
            _error(f"duplicate replication role {role!r}")
        replications[role] = evidence
    expected_roles = {"runner_up_static", "independent_static", "independent_interactive"}
    if set(replications) != expected_roles:
        _error("replication evidence does not exactly cover the frozen roles")
    for role, evidence in replications.items():
        if evidence["lane"] != statistical["lane"]:
            _error(f"replication {role!r} lane does not match primary evidence")

    lane: Lane = statistical["lane"]
    reference_arm = statistical["reference_arm"]
    comparison_arm = statistical["comparison_arm"]
    stats_payload = statistical["payload"]
    export_payload = export["payload"]
    source_artifact = export_payload["source_artifact"]
    reference_artifact = export_payload["direct_baseline_artifact"]
    comparison_artifact = export_payload["comparison_artifact"]

    equal_flops = compute["equal_total_flops"]
    equal_target = compute["equal_target_tokens"]
    _same_primary_binding(statistical, equal_flops, "equal_total_flops evidence")
    if equal_flops["payload"]["performance_evidence_sha256"] != stats_payload["contrast_record_sha256"]:
        _error("equal-FLOP comparison must bind the primary statistical contrast")
    for kind, evidence in compute.items():
        if evidence["payload"]["comparison_completed_run_sha256"] != comparison_artifact["completed_run_sha256"]:
            _error(f"compute comparison {kind!r} does not bind the exported comparison run")
        if evidence["payload"]["comparison_teacher_corpus_sha256"] != comparison_artifact[
            "verified_teacher_corpus_sha256"
        ]:
            _error(f"compute comparison {kind!r} teacher corpus disagrees with export evidence")
    if equal_flops["payload"]["reference_completed_run_sha256"] != reference_artifact["completed_run_sha256"]:
        _error("equal-FLOP comparison does not bind the direct baseline export")
    if equal_flops["payload"]["reference_teacher_corpus_sha256"] != reference_artifact[
        "verified_teacher_corpus_sha256"
    ]:
        _error("equal-FLOP reference teacher corpus disagrees with export evidence")

    if teacher["payload"]["main_comparison_completed_run_sha256"] != comparison_artifact["completed_run_sha256"]:
        _error("teacher-free evidence does not bind the exported comparison run")
    if teacher["payload"]["main_teacher_enabled"] != comparison_artifact["teacher_enabled"]:
        _error("teacher status disagrees between export and teacher-free evidence")
    if teacher["payload"]["main_verified_teacher_corpus_sha256"] != comparison_artifact["verified_teacher_corpus_sha256"]:
        _error("teacher corpus disagrees between export and teacher-free evidence")
    if teacher["payload"]["teacher_free_operator_configuration_sha256"] != comparison_artifact["operator_configuration_sha256"]:
        _error("teacher-free ablation does not use the promoted operator configuration")

    compression_static_endpoint = noninferiority["payload"]["compression_static_source"]
    if compression_static_endpoint is not None and compression_static_endpoint[
        "reference_arm"
    ] != source_artifact["arm_id"]:
        _error("compression static-source endpoint does not bind the source artifact arm")

    hardware_payload = hardware["payload"]
    expected_hardware_reference = reference_artifact if lane == "fixed_size" else source_artifact
    if hardware["lane"] != lane or hardware["comparison_arm"] != comparison_arm:
        _error("hardware lane/comparison arm does not match primary evidence")
    if hardware["reference_arm"] != expected_hardware_reference["arm_id"]:
        _error("hardware evidence reference arm does not match its artifact reference")
    if hardware_payload["reference_completed_run_sha256"] != expected_hardware_reference["completed_run_sha256"]:
        _error("hardware reference does not bind the lane's required artifact reference")
    if hardware_payload["comparison_completed_run_sha256"] != comparison_artifact["completed_run_sha256"]:
        _error("hardware comparison does not bind the exported comparison run")
    for prefix, artifact in (
        ("reference", expected_hardware_reference),
        ("comparison", comparison_artifact),
    ):
        for field in ("weight_bytes", "bundle_bytes"):
            if hardware_payload[f"{prefix}_{field}"] != artifact[field]:
                _error(f"hardware {prefix} {field} disagrees with export evidence")

    primary_config = comparison_artifact["operator_configuration_sha256"]
    primary_benchmark = stats_payload["primary_benchmark_id"]
    primary_backbone = stats_payload["primary_backbone_id"]
    independent_benchmarks: set[str] = set()
    for role, evidence in replications.items():
        payload = evidence["payload"]
        if payload["operator_configuration_sha256"] != primary_config:
            _error(f"replication {role!r} does not use the promoted operator configuration")
        if role == "runner_up_static":
            if payload["backbone_id"] == primary_backbone:
                _error("runner-up replication must use a different backbone")
            if payload["benchmark_id"] != primary_benchmark:
                _error("runner-up replication must use the primary sealed static benchmark")
        else:
            _same_primary_binding(statistical, evidence, f"replication {role!r}")
            if payload["backbone_id"] != primary_backbone:
                _error(f"replication {role!r} must use the primary backbone")
            if payload["benchmark_id"] == primary_benchmark:
                _error(f"replication {role!r} benchmark is not independent")
            independent_benchmarks.add(payload["benchmark_id"])
    if len(independent_benchmarks) != 2:
        _error("independent static and interactive benchmarks must be distinct")

    stats_interval = stats_payload["simultaneous_confidence_interval"]
    statistical_positive = (
        stats_payload["estimate_difference_proportion"] >= 0.03
        and stats_interval["lower"] > 0.0
        and stats_payload["holm_adjusted_p_value"] <= 0.05
    )

    fixed_size_identity_fields = (
        "architecture",
        "format",
        "physical_parameters",
        "active_parameters",
        "average_weight_bits",
        "architecture_layout_sha256",
        "precision_layout_sha256",
        "weight_bytes",
        "bundle_bytes",
        "tokenizer_sha256",
    )
    fixed_size_identity = all(
        comparison_artifact[field] == reference_artifact[field] == source_artifact[field]
        for field in fixed_size_identity_fields
    )
    reference_weight_comparable_fraction = _fractional_distance(
        comparison_artifact["weight_bytes"], reference_artifact["weight_bytes"]
    )
    source_weight_comparable_fraction = _fractional_distance(
        comparison_artifact["weight_bytes"], source_artifact["weight_bytes"]
    )
    reference_bundle_comparable_fraction = _fractional_distance(
        comparison_artifact["bundle_bytes"], reference_artifact["bundle_bytes"]
    )
    source_bundle_comparable_fraction = _fractional_distance(
        comparison_artifact["bundle_bytes"], source_artifact["bundle_bytes"]
    )
    tolerance = export_payload["comparable_bytes_tolerance_fraction"]
    source_bytes_reduction = 1.0 - (
        float(comparison_artifact["weight_bytes"]) / float(source_artifact["weight_bytes"])
    )
    source_bundle_bytes_reduction = 1.0 - (
        float(comparison_artifact["bundle_bytes"]) / float(source_artifact["bundle_bytes"])
    )
    physical_parameter_reduction = 1.0 - (
        float(comparison_artifact["physical_parameters"])
        / float(source_artifact["physical_parameters"])
    )
    direct_baseline_comparable = (
        reference_weight_comparable_fraction <= tolerance
        and reference_bundle_comparable_fraction <= tolerance
    )

    noninferiority_payload = noninferiority["payload"]
    bounded_decision = _endpoint_decision(noninferiority_payload["bounded_terminal"])
    protected_decisions = [
        {
            "capability_id": item["capability_id"],
            **_endpoint_decision(item["endpoint"]),
        }
        for item in noninferiority_payload["protected_capabilities"]
    ]
    all_protected_noninferior = all(item["noninferior"] for item in protected_decisions)
    compression_static_decision = (
        _endpoint_decision(noninferiority_payload["compression_static_source"])
        if noninferiority_payload["compression_static_source"] is not None
        else None
    )
    bytes_reduction_branch = bool(
        lane == "compression"
        and source_bytes_reduction >= 0.25
        and source_bundle_bytes_reduction >= 0.25
        and compression_static_decision is not None
        and compression_static_decision["noninferior"]
    )
    matched_bytes_gain_branch = bool(
        lane == "compression"
        and source_weight_comparable_fraction <= tolerance
        and source_bundle_comparable_fraction <= tolerance
        and compression_static_decision is not None
        and compression_static_decision["estimate_difference_proportion"] >= 0.03
    )

    compute_decisions = {
        "equal_target_tokens": {
            "reference_target_tokens": equal_target["payload"]["reference_target_tokens"],
            "comparison_target_tokens": equal_target["payload"]["comparison_target_tokens"],
            "matched": equal_target["payload"]["reference_target_tokens"]
            == equal_target["payload"]["comparison_target_tokens"],
            "data_sources_matched": (
                equal_target["payload"]["reference_target_data_sha256"]
                == equal_target["payload"]["comparison_target_data_sha256"]
                and equal_target["payload"]["reference_support_data_sha256"]
                == equal_target["payload"]["comparison_support_data_sha256"]
                and equal_target["payload"]["reference_teacher_corpus_sha256"]
                == equal_target["payload"]["comparison_teacher_corpus_sha256"]
            ),
        },
        "equal_total_flops": {
            "reference_total_flops": equal_flops["payload"]["reference_total_flops"],
            "comparison_total_flops": equal_flops["payload"]["comparison_total_flops"],
            "matched": equal_flops["payload"]["reference_total_flops"]
            == equal_flops["payload"]["comparison_total_flops"],
            "data_sources_matched": (
                equal_flops["payload"]["reference_target_data_sha256"]
                == equal_flops["payload"]["comparison_target_data_sha256"]
                and equal_flops["payload"]["reference_support_data_sha256"]
                == equal_flops["payload"]["comparison_support_data_sha256"]
                and equal_flops["payload"]["reference_teacher_corpus_sha256"]
                == equal_flops["payload"]["comparison_teacher_corpus_sha256"]
            ),
        },
    }

    comparable_teacher_corpus = (
        reference_artifact["teacher_enabled"] == comparison_artifact["teacher_enabled"]
        and reference_artifact["verified_teacher_corpus_sha256"]
        == comparison_artifact["verified_teacher_corpus_sha256"]
    )

    hardware_reduction = (
        hardware_payload["comparison_peak_memory_bytes"]
        < hardware_payload["reference_peak_memory_bytes"]
    )
    replication_decisions: dict[str, dict[str, Any]] = {}
    for role, evidence in sorted(replications.items()):
        payload = evidence["payload"]
        lower = payload["simultaneous_confidence_interval"]["lower"]
        if role == "independent_interactive":
            criterion = "noninferior_within_2_absolute_points"
            passed = lower >= -0.02
        else:
            criterion = "positive_effect_with_simultaneous_lower_bound_above_zero"
            passed = payload["estimate_difference_proportion"] > 0.0 and lower > 0.0
        replication_decisions[role] = {
            "benchmark_id": payload["benchmark_id"],
            "backbone_id": payload["backbone_id"],
            "paired_seed_count": payload["paired_seed_count"],
            "estimate_difference_proportion": payload["estimate_difference_proportion"],
            "simultaneous_confidence_interval": copy.deepcopy(
                payload["simultaneous_confidence_interval"]
            ),
            "criterion": criterion,
            "met": passed,
        }
    all_replications = all(item["met"] for item in replication_decisions.values())

    teacher_reported = (
        teacher["payload"]["teacher_free_paired_seed_count"] == 5
        and bool(teacher["payload"]["teacher_free_completed_run_set_sha256"])
        and bool(teacher["payload"]["teacher_free_result_evidence_sha256"])
    )

    if lane == "fixed_size":
        lane_specific = {
            "criterion": "fixed_size_identity",
            "fixed_size_metadata_tolerance_bytes": FIXED_SIZE_METADATA_TOLERANCE_BYTES,
            "identity_fields": list(fixed_size_identity_fields),
            "met": fixed_size_identity,
        }
        lane_artifact_met = fixed_size_identity
        hardware_met = True  # reporting is mandatory; reduction is not a fixed-size condition
    else:
        lane_specific = {
            "criterion": "compression_or",
            "source_weight_bytes_reduction_fraction": source_bytes_reduction,
            "source_bundle_bytes_reduction_fraction": source_bundle_bytes_reduction,
            "source_physical_parameter_reduction_fraction": physical_parameter_reduction,
            "source_weight_bytes_comparability_fraction": source_weight_comparable_fraction,
            "source_bundle_bytes_comparability_fraction": source_bundle_comparable_fraction,
            "direct_baseline_weight_bytes_comparability_fraction": (
                reference_weight_comparable_fraction
            ),
            "direct_baseline_bundle_bytes_comparability_fraction": (
                reference_bundle_comparable_fraction
            ),
            "maximum_comparable_bytes_fraction": tolerance,
            "bytes_reduction_with_static_noninferiority": bytes_reduction_branch,
            "matched_bytes_with_static_gain": matched_bytes_gain_branch,
            "direct_task_agnostic_baseline_comparable": direct_baseline_comparable,
            "met": (bytes_reduction_branch or matched_bytes_gain_branch)
            and direct_baseline_comparable,
            "architectural_compression_20_percent_parameter_reduction": (
                physical_parameter_reduction >= 0.20
            ),
            "architectural_claim_qualified": (
                physical_parameter_reduction >= 0.20
            ),
            "quantization_only_parameter_reduction_claim_forbidden": (
                physical_parameter_reduction < 0.20
            ),
        }
        lane_artifact_met = bool(lane_specific["met"])
        hardware_met = hardware_reduction

    criteria = {
        "primary_statistical_gain": {
            "threshold_absolute_points": 3.0,
            "estimate_difference_proportion": stats_payload[
                "estimate_difference_proportion"
            ],
            "simultaneous_lower_bound": stats_interval["lower"],
            "holm_adjusted_p_value": stats_payload["holm_adjusted_p_value"],
            "met": statistical_positive,
        },
        "dense_sub_billion_export": {
            "architecture": comparison_artifact["architecture"],
            "physical_parameters": comparison_artifact["physical_parameters"],
            "limit_exclusive": SUB_BILLION_PHYSICAL_PARAMETER_LIMIT,
            "met": comparison_artifact["architecture"] == "dense"
            and comparison_artifact["physical_parameters"]
            < SUB_BILLION_PHYSICAL_PARAMETER_LIMIT,
        },
        "lane_artifact_condition": lane_specific,
        "matched_compute": compute_decisions,
        "comparable_teacher_corpus": {
            "reference_teacher_enabled": reference_artifact["teacher_enabled"],
            "comparison_teacher_enabled": comparison_artifact["teacher_enabled"],
            "matched": comparable_teacher_corpus,
        },
        "bounded_terminal_noninferiority": bounded_decision,
        "protected_capability_noninferiority": {
            "roster_sha256": noninferiority_payload[
                "protected_capability_roster_sha256"
            ],
            "capabilities": protected_decisions,
            "all_noninferior": all_protected_noninferior,
        },
        "hardware": {
            "peak_memory_metric": hardware_payload["peak_memory_metric"],
            "reference_peak_memory_bytes": hardware_payload[
                "reference_peak_memory_bytes"
            ],
            "comparison_peak_memory_bytes": hardware_payload[
                "comparison_peak_memory_bytes"
            ],
            "measured_reduction": hardware_reduction,
            "reduction_required": lane == "compression",
            "met": hardware_met,
        },
        "replication": {
            "primary_benchmark_id": primary_benchmark,
            "primary_backbone_id": primary_backbone,
            "replications": replication_decisions,
            "all_met": all_replications,
        },
        "teacher_free": {
            "main_teacher_enabled": teacher["payload"]["main_teacher_enabled"],
            "ablation_or_teacher_free_main_reported": teacher_reported,
            "teacher_free_estimate_difference_proportion": teacher["payload"][
                "teacher_free_estimate_difference_proportion"
            ],
            "positive_effect_not_required_by_plan": True,
            "met": teacher_reported,
        },
    }

    acceptance_criteria_met = all(
        (
            criteria["primary_statistical_gain"]["met"],
            criteria["dense_sub_billion_export"]["met"],
            lane_artifact_met,
            compute_decisions["equal_target_tokens"]["matched"],
            compute_decisions["equal_target_tokens"]["data_sources_matched"],
            compute_decisions["equal_total_flops"]["matched"],
            compute_decisions["equal_total_flops"]["data_sources_matched"],
            comparable_teacher_corpus,
            bounded_decision["noninferior"],
            all_protected_noninferior,
            hardware_met,
            all_replications,
            teacher_reported,
        )
    )

    requirements = _authorization_requirements(
        statistical=statistical,
        export=export,
        compute=compute,
        noninferiority=noninferiority,
        hardware=hardware,
        replications=replications,
        teacher=teacher,
    )
    record: dict[str, Any] = {
        "record_type": "cbds.confirmatory-lane-claim-evaluation",
        "binder_version": CLAIM_ACCEPTANCE_BINDER_VERSION,
        "evidence_schema_version": CLAIM_EVIDENCE_SCHEMA_VERSION,
        "lane": lane,
        "direction": "comparison_minus_reference",
        "reference_arm": reference_arm,
        "comparison_arm": comparison_arm,
        "evidence_addresses": {
            "statistical": statistical["evidence_sha256"],
            "export": export["evidence_sha256"],
            "compute_comparisons": {
                kind: evidence["evidence_sha256"]
                for kind, evidence in sorted(compute.items())
            },
            "noninferiority": noninferiority["evidence_sha256"],
            "hardware": hardware["evidence_sha256"],
            "replications": {
                role: evidence["evidence_sha256"]
                for role, evidence in sorted(replications.items())
            },
            "teacher_free": teacher["evidence_sha256"],
        },
        "criteria": criteria,
        "acceptance_criteria_met": acceptance_criteria_met,
        "authorization": {
            "claim_authorized": False,
            "status": (
                "criteria_met_but_end_to_end_provenance_not_bound"
                if acceptance_criteria_met
                else "criteria_not_met_and_end_to_end_provenance_not_bound"
            ),
            "digest_semantics": (
                "content addresses detect projection mutation but do not prove "
                "derivation from the named source artifacts"
            ),
            "required_connections": requirements,
            "all_required_connections_executed": False,
            "authorization_flip_implemented": False,
        },
        "scope": (
            "deterministic_policy_evaluation_over_explicit_content_addressed_"
            "projections_not_a_lane_success_claim"
        ),
    }
    record["claim_record_sha256"] = value_sha256(record)
    return record


__all__ = [
    "CLAIM_ACCEPTANCE_BINDER_VERSION",
    "CLAIM_EVIDENCE_SCHEMA_VERSION",
    "ClaimAcceptanceValidationError",
    "ClaimEvidenceEnvelope",
    "content_address_claim_evidence",
    "bind_confirmatory_lane_claim",
]
