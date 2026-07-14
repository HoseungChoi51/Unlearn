"""Fail-closed capability-support and signed-transfer screening contracts.

This module validates two caller-supplied, content-addressed projections:

``cbds.capability-audit-spec``
    A prospective audit binding an exact dense model artifact, the protected
    terminal target and prerequisites, every candidate family frozen in
    ``PLAN.md``, objective/executable suite identities, variant coverage, and
    signed-transfer probes.

``cbds.capability-audit-result``
    A completed aggregate of paired binary outcomes.  Aggregate validation is
    deliberately not an attestation that the task-level records named by its
    hashes exist or were evaluated correctly.

The gate can identify candidates that were above the preregistered behavioral
floor *and* exhibited the registered candidate-down/target-up direction in a
paired probe.  It cannot infer irrelevance, dispensability, causal capacity
competition, or acceptable sacrifice, and it never authorizes training or a
research claim.  Those boundaries are literals in every accepted record and
in the returned decision.

Only the Python standard library is used.  Unknown fields, booleans used as
integers, non-finite or floating chance declarations, roster drift, hash
drift, incomplete variant coverage, and inconsistent paired marginals all
fail closed.  The implementation does not rely on ``assert`` so validation is
unchanged under ``python -O``.
"""

from __future__ import annotations

import copy
from hashlib import sha256
import json
import re
from typing import Any, Final


CAPABILITY_AUDIT_SCHEMA_VERSION: Final[str] = "1.0.0"
CAPABILITY_GATE_BINDER_VERSION: Final[str] = "1.0.0"
TARGET_CAPABILITY_ID: Final[str] = "unix-toolbox-terminal-scripting"
PLAN_CANDIDATE_FAMILY_IDS: Final[tuple[str, ...]] = (
    "korean-language-use",
    "mandarin-language-use",
    "spanish-language-use",
    "c-cpp-programming",
    "java-programming",
    "javascript-typescript-programming",
    "rust-programming",
    "sql-execution-database-reasoning",
    "advanced-mathematics",
    "biomedical-factual-knowledge",
    "legal-factual-knowledge",
    "geographic-factual-knowledge",
    "creative-long-form-prose",
)
SOURCE_PLAN_SHA256: Final[str] = (
    "b907788a93af17127152d4028f237e663b99d29b96604a54a60a8cb221abc172"
)
PLAN_CANDIDATE_ROSTER_HASH_DOMAIN: Final[str] = (
    "cbds.capability-audit.plan-candidate-roster.v1"
)
PLAN_CANDIDATE_ROSTER_SHA256: Final[str] = sha256(
    json.dumps(
        {
            "domain": PLAN_CANDIDATE_ROSTER_HASH_DOMAIN,
            "candidate_family_ids": list(PLAN_CANDIDATE_FAMILY_IDS),
        },
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
).hexdigest()

CANDIDATE_ITEM_COUNT: Final[int] = 400
EXECUTABLE_MIN_SUCCESSES: Final[int] = 20
OBJECTIVE_MIN_POINTS_ABOVE_CHANCE: Final[int] = 10
MINIMUM_PROMPT_VARIANTS: Final[int] = 2
MINIMUM_PREFIX_VARIANTS: Final[int] = 2
MAXIMUM_VARIANTS_PER_AXIS: Final[int] = 64
MAXIMUM_PROTECTED_CAPABILITIES: Final[int] = 64
MAXIMUM_CANONICAL_BYTES: Final[int] = 16 * 1024 * 1024
SUB_BILLION_PARAMETER_LIMIT: Final[int] = 1_000_000_000

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")

_SPEC_SCOPE: Final[str] = (
    "prospective_floor_and_signed_transfer_screen_not_irrelevance_or_training_authorization"
)
_RESULT_SCOPE: Final[str] = (
    "completed_aggregate_projection_not_task_level_attestation_or_causal_claim"
)
_CANDIDATE_DESIGNATION: Final[str] = "audited_candidate_not_presumed_irrelevant"
_COVERAGE_RULE: Final[str] = "full_prompt_prefix_cross_product_per_semantic_item"
_REGISTERED_DIRECTION: Final[str] = "candidate_down_target_up"
_ELIGIBILITY_SEMANTICS: Final[str] = (
    "above_floor_and_registered_signed_transfer_direction_for_followup_audit_only"
)

_AUTHORIZATION_FIELDS: Final[tuple[str, ...]] = (
    "irrelevance_inferred",
    "sacrifice_authorized",
    "training_authorized",
    "claim_authorized",
)


class CapabilityAuditValidationError(ValueError):
    """Raised when an audit projection violates the frozen contract."""


def _error(message: str) -> None:
    raise CapabilityAuditValidationError(message)


def _bounded_repr(value: object) -> str:
    rendered = repr(value)
    if len(rendered) <= 160:
        return rendered
    digest = sha256(rendered.encode("utf-8", errors="backslashreplace")).hexdigest()
    return f"<repr_chars={len(rendered)} sha256={digest}>"


def _object(value: object, expected: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict:
        _error(f"{label} must be a JSON object")
    actual = set(value)
    if any(type(key) is not str for key in actual):
        _error(f"{label} keys must be strings")
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        details: list[str] = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if extra:
            details.append("unexpected " + ", ".join(_bounded_repr(item) for item in extra))
        _error(f"{label} fields do not match ({'; '.join(details)})")
    return value


def _list(value: object, label: str, *, minimum: int, maximum: int) -> list[Any]:
    if type(value) is not list:
        _error(f"{label} must be a JSON array")
    if not minimum <= len(value) <= maximum:
        _error(f"{label} must contain between {minimum} and {maximum} items")
    return value


def _literal(value: object, expected: object, label: str) -> None:
    if type(value) is not type(expected) or value != expected:
        _error(f"{label} must equal {_bounded_repr(expected)}")


def _boolean(value: object, label: str) -> bool:
    if type(value) is not bool:
        _error(f"{label} must be a boolean")
    return value


def _integer(
    value: object,
    label: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _error(f"{label} must be an integer between {minimum} and {maximum}")
    return value


def _text(value: object, label: str, *, maximum: int = 256) -> str:
    if type(value) is not str or not 1 <= len(value) <= maximum:
        _error(f"{label} must be a nonempty string of at most {maximum} characters")
    return value


def _identifier(value: object, label: str, *, maximum: int = 192) -> str:
    text = _text(value, label, maximum=maximum)
    if _IDENTIFIER.fullmatch(text) is None:
        _error(f"{label} must be an ASCII identifier")
    return text


def _digest(value: object, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        _error(f"{label} must be a lowercase SHA-256 digest")
    return value


def canonical_json_bytes(value: object) -> bytes:
    """Return deterministic canonical JSON bytes for content addressing."""

    try:
        rendered = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise CapabilityAuditValidationError(
            f"value is not canonical JSON: {type(error).__name__}"
        ) from error
    if len(rendered) > MAXIMUM_CANONICAL_BYTES:
        _error(f"canonical JSON exceeds {MAXIMUM_CANONICAL_BYTES} bytes")
    return rendered


def value_sha256(value: object) -> str:
    """Hash canonical JSON with SHA-256."""

    return sha256(canonical_json_bytes(value)).hexdigest()


def _content_address(record: object, field: str, label: str) -> dict[str, Any]:
    if type(record) is not dict:
        _error(f"{label} must be a JSON object")
    if field in record:
        _error(f"{label} must omit {field} before content addressing")
    candidate = copy.deepcopy(record)
    # Canonicalization here also rejects non-JSON values before the digest is
    # attached.  Semantic validation remains the validator's responsibility.
    candidate[field] = value_sha256(candidate)
    return candidate


def content_address_capability_audit_spec(record: object) -> dict[str, Any]:
    """Return a defensive copy with ``audit_spec_sha256`` attached."""

    return _content_address(record, "audit_spec_sha256", "audit spec")


def content_address_capability_audit_result(record: object) -> dict[str, Any]:
    """Return a defensive copy with ``result_sha256`` attached."""

    return _content_address(record, "result_sha256", "aggregate result")


def _verify_address(record: dict[str, Any], field: str, label: str) -> None:
    declared = _digest(record[field], f"{label}.{field}")
    unsigned = copy.deepcopy(record)
    unsigned.pop(field)
    if value_sha256(unsigned) != declared:
        _error(f"{label}.{field} does not hash the exact record")


def _validate_authorizations(raw: object, label: str) -> dict[str, bool]:
    value = _object(raw, set(_AUTHORIZATION_FIELDS), label)
    normalized: dict[str, bool] = {}
    for field in _AUTHORIZATION_FIELDS:
        flag = _boolean(value[field], f"{label}.{field}")
        if flag:
            _error(f"{label}.{field} must remain false")
        normalized[field] = False
    return normalized


def _validate_model(raw: object) -> dict[str, Any]:
    label = "audit_spec.model"
    value = _object(
        raw,
        {
            "model_id",
            "revision",
            "architecture",
            "physical_parameters",
            "artifact_sha256",
            "model_config_sha256",
            "tokenizer_sha256",
            "inspection_report_sha256",
        },
        label,
    )
    model_id = _text(value["model_id"], label + ".model_id", maximum=256)
    revision = _text(value["revision"], label + ".revision", maximum=256)
    _literal(value["architecture"], "dense", label + ".architecture")
    physical_parameters = _integer(
        value["physical_parameters"],
        label + ".physical_parameters",
        minimum=1,
        maximum=SUB_BILLION_PARAMETER_LIMIT - 1,
    )
    normalized = {
        "model_id": model_id,
        "revision": revision,
        "architecture": "dense",
        "physical_parameters": physical_parameters,
    }
    for field in (
        "artifact_sha256",
        "model_config_sha256",
        "tokenizer_sha256",
        "inspection_report_sha256",
    ):
        normalized[field] = _digest(value[field], f"{label}.{field}")
    return normalized


def _validate_protected(raw: object) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    items = _list(
        raw,
        "audit_spec.protected_capabilities",
        minimum=2,
        maximum=MAXIMUM_PROTECTED_CAPABILITIES,
    )
    normalized: list[dict[str, Any]] = []
    for index, raw_item in enumerate(items):
        label = f"audit_spec.protected_capabilities[{index}]"
        item = _object(
            raw_item,
            {"capability_id", "designation", "suite_sha256", "item_count"},
            label,
        )
        capability_id = _identifier(item["capability_id"], label + ".capability_id")
        designation = item["designation"]
        if designation not in ("protected_target", "protected_prerequisite"):
            _error(
                f"{label}.designation must be protected_target or protected_prerequisite"
            )
        normalized.append(
            {
                "capability_id": capability_id,
                "designation": designation,
                "suite_sha256": _digest(item["suite_sha256"], label + ".suite_sha256"),
                "item_count": _integer(
                    item["item_count"], label + ".item_count", minimum=1, maximum=10_000_000
                ),
            }
        )

    ids = [item["capability_id"] for item in normalized]
    if len(set(ids)) != len(ids):
        _error("audit_spec.protected_capabilities contains duplicate capability IDs")
    targets = [item for item in normalized if item["designation"] == "protected_target"]
    if len(targets) != 1:
        _error("audit_spec.protected_capabilities requires exactly one protected target")
    target = targets[0]
    if target["capability_id"] != TARGET_CAPABILITY_ID:
        _error(
            "audit_spec protected target must be unix-toolbox-terminal-scripting"
        )
    if normalized[0] != target:
        _error("audit_spec protected target must be the first protected capability")
    prerequisites = normalized[1:]
    if any(item["designation"] != "protected_prerequisite" for item in prerequisites):
        _error("all protected capabilities after the target must be prerequisites")
    expected_prerequisites = sorted(
        prerequisites, key=lambda item: item["capability_id"].encode("utf-8")
    )
    if prerequisites != expected_prerequisites:
        _error("protected prerequisites must be ordered by UTF-8 capability_id")
    return normalized, target


def _validate_variant_protocol(raw: object, label: str) -> dict[str, Any]:
    value = _object(
        raw,
        {
            "prompt_variant_count",
            "prefix_variant_count",
            "assignment_sha256",
            "coverage_rule",
        },
        label,
    )
    prompt_count = _integer(
        value["prompt_variant_count"],
        label + ".prompt_variant_count",
        minimum=MINIMUM_PROMPT_VARIANTS,
        maximum=MAXIMUM_VARIANTS_PER_AXIS,
    )
    prefix_count = _integer(
        value["prefix_variant_count"],
        label + ".prefix_variant_count",
        minimum=MINIMUM_PREFIX_VARIANTS,
        maximum=MAXIMUM_VARIANTS_PER_AXIS,
    )
    _literal(value["coverage_rule"], _COVERAGE_RULE, label + ".coverage_rule")
    return {
        "prompt_variant_count": prompt_count,
        "prefix_variant_count": prefix_count,
        "assignment_sha256": _digest(
            value["assignment_sha256"], label + ".assignment_sha256"
        ),
        "coverage_rule": _COVERAGE_RULE,
    }


def _validate_chance(raw: object, evaluation_kind: str, label: str) -> dict[str, Any] | None:
    if evaluation_kind == "executable":
        if raw is not None:
            _error(f"{label} must be null for executable families")
        return None
    value = _object(
        raw,
        {"successes_numerator", "trials_denominator", "basis_sha256"},
        label,
    )
    numerator = _integer(
        value["successes_numerator"],
        label + ".successes_numerator",
        minimum=0,
        maximum=1_000_000,
    )
    denominator = _integer(
        value["trials_denominator"],
        label + ".trials_denominator",
        minimum=1,
        maximum=1_000_000,
    )
    if numerator > denominator:
        _error(f"{label} chance numerator cannot exceed its denominator")
    # A ten-point-above-chance threshold must remain arithmetically possible.
    if numerator * 10 > denominator * 9:
        _error(f"{label} chance must be no greater than 90 percent")
    return {
        "successes_numerator": numerator,
        "trials_denominator": denominator,
        "basis_sha256": _digest(value["basis_sha256"], label + ".basis_sha256"),
    }


def _validate_probe(
    raw: object,
    label: str,
    target: dict[str, Any],
) -> dict[str, Any]:
    value = _object(
        raw,
        {
            "intervention_id",
            "intervention_sha256",
            "pairing_manifest_sha256",
            "target_capability_id",
            "target_suite_sha256",
            "target_item_count",
            "registered_direction",
        },
        label,
    )
    _literal(
        value["target_capability_id"],
        target["capability_id"],
        label + ".target_capability_id",
    )
    _literal(
        value["target_suite_sha256"],
        target["suite_sha256"],
        label + ".target_suite_sha256",
    )
    _literal(
        value["target_item_count"], target["item_count"], label + ".target_item_count"
    )
    _literal(
        value["registered_direction"],
        _REGISTERED_DIRECTION,
        label + ".registered_direction",
    )
    return {
        "intervention_id": _identifier(
            value["intervention_id"], label + ".intervention_id"
        ),
        "intervention_sha256": _digest(
            value["intervention_sha256"], label + ".intervention_sha256"
        ),
        "pairing_manifest_sha256": _digest(
            value["pairing_manifest_sha256"], label + ".pairing_manifest_sha256"
        ),
        "target_capability_id": target["capability_id"],
        "target_suite_sha256": target["suite_sha256"],
        "target_item_count": target["item_count"],
        "registered_direction": _REGISTERED_DIRECTION,
    }


def _validate_candidate_families(
    raw: object,
    target: dict[str, Any],
) -> list[dict[str, Any]]:
    items = _list(
        raw,
        "audit_spec.candidate_families",
        minimum=len(PLAN_CANDIDATE_FAMILY_IDS),
        maximum=len(PLAN_CANDIDATE_FAMILY_IDS),
    )
    normalized: list[dict[str, Any]] = []
    for index, raw_item in enumerate(items):
        label = f"audit_spec.candidate_families[{index}]"
        item = _object(
            raw_item,
            {
                "capability_id",
                "designation",
                "evaluation_kind",
                "suite_sha256",
                "verifier_validation_sha256",
                "item_count",
                "variant_protocol",
                "chance",
                "signed_transfer_probe",
            },
            label,
        )
        capability_id = _identifier(item["capability_id"], label + ".capability_id")
        _literal(
            item["designation"], _CANDIDATE_DESIGNATION, label + ".designation"
        )
        evaluation_kind = item["evaluation_kind"]
        if evaluation_kind not in ("executable", "objective"):
            _error(f"{label}.evaluation_kind must be executable or objective")
        _literal(item["item_count"], CANDIDATE_ITEM_COUNT, label + ".item_count")
        normalized.append(
            {
                "capability_id": capability_id,
                "designation": _CANDIDATE_DESIGNATION,
                "evaluation_kind": evaluation_kind,
                "suite_sha256": _digest(item["suite_sha256"], label + ".suite_sha256"),
                "verifier_validation_sha256": _digest(
                    item["verifier_validation_sha256"],
                    label + ".verifier_validation_sha256",
                ),
                "item_count": CANDIDATE_ITEM_COUNT,
                "variant_protocol": _validate_variant_protocol(
                    item["variant_protocol"], label + ".variant_protocol"
                ),
                "chance": _validate_chance(
                    item["chance"], evaluation_kind, label + ".chance"
                ),
                "signed_transfer_probe": _validate_probe(
                    item["signed_transfer_probe"],
                    label + ".signed_transfer_probe",
                    target,
                ),
            }
        )

    ids = tuple(item["capability_id"] for item in normalized)
    if ids != PLAN_CANDIDATE_FAMILY_IDS:
        _error(
            "audit_spec.candidate_families must contain the exact PLAN roster in frozen order"
        )
    intervention_ids = [
        item["signed_transfer_probe"]["intervention_id"] for item in normalized
    ]
    if len(set(intervention_ids)) != len(intervention_ids):
        _error("candidate families require unique signed-transfer intervention IDs")
    return normalized


def _validate_policy(raw: object) -> dict[str, Any]:
    label = "audit_spec.policy"
    value = _object(
        raw,
        {
            "candidate_item_count",
            "executable_min_successes",
            "objective_min_percentage_points_above_chance",
            "minimum_prompt_variants",
            "minimum_prefix_variants",
            "paired_before_after_required",
            "signed_transfer_required",
            "eligibility_semantics",
        },
        label,
    )
    expected = {
        "candidate_item_count": CANDIDATE_ITEM_COUNT,
        "executable_min_successes": EXECUTABLE_MIN_SUCCESSES,
        "objective_min_percentage_points_above_chance": (
            OBJECTIVE_MIN_POINTS_ABOVE_CHANCE
        ),
        "minimum_prompt_variants": MINIMUM_PROMPT_VARIANTS,
        "minimum_prefix_variants": MINIMUM_PREFIX_VARIANTS,
        "paired_before_after_required": True,
        "signed_transfer_required": True,
        "eligibility_semantics": _ELIGIBILITY_SEMANTICS,
    }
    for field, expected_value in expected.items():
        _literal(value[field], expected_value, f"{label}.{field}")
    return copy.deepcopy(expected)


def validate_capability_audit_spec(raw: object) -> dict[str, Any]:
    """Validate and defensively copy a prospective capability audit spec."""

    label = "audit_spec"
    value = _object(
        raw,
        {
            "record_type",
            "schema_version",
            "audit_id",
            "evidence_scope",
            "source_plan_sha256",
            "candidate_roster_sha256",
            "model",
            "protected_capabilities",
            "candidate_families",
            "policy",
            "authorizations",
            "audit_spec_sha256",
        },
        label,
    )
    _literal(value["record_type"], "cbds.capability-audit-spec", label + ".record_type")
    _literal(
        value["schema_version"],
        CAPABILITY_AUDIT_SCHEMA_VERSION,
        label + ".schema_version",
    )
    audit_id = _identifier(value["audit_id"], label + ".audit_id")
    _literal(value["evidence_scope"], _SPEC_SCOPE, label + ".evidence_scope")
    _literal(
        value["source_plan_sha256"],
        SOURCE_PLAN_SHA256,
        label + ".source_plan_sha256",
    )
    _literal(
        value["candidate_roster_sha256"],
        PLAN_CANDIDATE_ROSTER_SHA256,
        label + ".candidate_roster_sha256",
    )
    model = _validate_model(value["model"])
    protected, target = _validate_protected(value["protected_capabilities"])
    candidates = _validate_candidate_families(value["candidate_families"], target)
    protected_ids = {item["capability_id"] for item in protected}
    if protected_ids.intersection(PLAN_CANDIDATE_FAMILY_IDS):
        _error("candidate families cannot also be designated protected")
    suite_hashes = [item["suite_sha256"] for item in protected]
    suite_hashes.extend(item["suite_sha256"] for item in candidates)
    if len(set(suite_hashes)) != len(suite_hashes):
        _error("every protected and candidate capability requires a distinct suite hash")
    policy = _validate_policy(value["policy"])
    authorizations = _validate_authorizations(
        value["authorizations"], label + ".authorizations"
    )
    _verify_address(value, "audit_spec_sha256", label)
    return {
        "record_type": "cbds.capability-audit-spec",
        "schema_version": CAPABILITY_AUDIT_SCHEMA_VERSION,
        "audit_id": audit_id,
        "evidence_scope": _SPEC_SCOPE,
        "source_plan_sha256": SOURCE_PLAN_SHA256,
        "candidate_roster_sha256": PLAN_CANDIDATE_ROSTER_SHA256,
        "model": model,
        "protected_capabilities": protected,
        "candidate_families": candidates,
        "policy": policy,
        "authorizations": authorizations,
        "audit_spec_sha256": value["audit_spec_sha256"],
    }


def _validate_paired_outcomes(
    raw: object,
    label: str,
    *,
    expected_pair_count: int,
) -> dict[str, Any]:
    value = _object(
        raw,
        {
            "pair_count",
            "both_success",
            "before_only",
            "after_only",
            "both_failure",
            "before_successes",
            "after_successes",
            "task_result_pairs_sha256",
        },
        label,
    )
    pair_count = _integer(
        value["pair_count"], label + ".pair_count", minimum=1, maximum=10_000_000
    )
    if pair_count != expected_pair_count:
        _error(f"{label}.pair_count must equal {expected_pair_count}")
    counts: dict[str, int] = {}
    for field in (
        "both_success",
        "before_only",
        "after_only",
        "both_failure",
        "before_successes",
        "after_successes",
    ):
        counts[field] = _integer(
            value[field], f"{label}.{field}", minimum=0, maximum=pair_count
        )
    if (
        counts["both_success"]
        + counts["before_only"]
        + counts["after_only"]
        + counts["both_failure"]
        != pair_count
    ):
        _error(f"{label} contingency cells must sum to pair_count")
    if counts["before_successes"] != counts["both_success"] + counts["before_only"]:
        _error(f"{label}.before_successes does not match paired cells")
    if counts["after_successes"] != counts["both_success"] + counts["after_only"]:
        _error(f"{label}.after_successes does not match paired cells")
    return {
        "pair_count": pair_count,
        **counts,
        "task_result_pairs_sha256": _digest(
            value["task_result_pairs_sha256"], label + ".task_result_pairs_sha256"
        ),
    }


def _validate_variant_coverage(
    raw: object,
    label: str,
    candidate: dict[str, Any],
) -> dict[str, Any]:
    value = _object(
        raw,
        {
            "semantic_item_count",
            "prompt_variant_count",
            "prefix_variant_count",
            "raw_observation_count",
            "assignment_sha256",
            "coverage_evidence_sha256",
        },
        label,
    )
    protocol = candidate["variant_protocol"]
    _literal(
        value["semantic_item_count"], CANDIDATE_ITEM_COUNT, label + ".semantic_item_count"
    )
    _literal(
        value["prompt_variant_count"],
        protocol["prompt_variant_count"],
        label + ".prompt_variant_count",
    )
    _literal(
        value["prefix_variant_count"],
        protocol["prefix_variant_count"],
        label + ".prefix_variant_count",
    )
    expected_observations = (
        CANDIDATE_ITEM_COUNT
        * protocol["prompt_variant_count"]
        * protocol["prefix_variant_count"]
    )
    _literal(
        value["raw_observation_count"],
        expected_observations,
        label + ".raw_observation_count",
    )
    _literal(
        value["assignment_sha256"],
        protocol["assignment_sha256"],
        label + ".assignment_sha256",
    )
    return {
        "semantic_item_count": CANDIDATE_ITEM_COUNT,
        "prompt_variant_count": protocol["prompt_variant_count"],
        "prefix_variant_count": protocol["prefix_variant_count"],
        "raw_observation_count": expected_observations,
        "assignment_sha256": protocol["assignment_sha256"],
        "coverage_evidence_sha256": _digest(
            value["coverage_evidence_sha256"], label + ".coverage_evidence_sha256"
        ),
    }


def _validate_signed_transfer(
    raw: object,
    label: str,
    candidate: dict[str, Any],
) -> dict[str, Any]:
    value = _object(
        raw,
        {
            "intervention_id",
            "intervention_sha256",
            "pairing_manifest_sha256",
            "target_capability_id",
            "target_suite_sha256",
            "registered_direction",
            "target_before_after",
            "aggregate_evidence_sha256",
        },
        label,
    )
    probe = candidate["signed_transfer_probe"]
    for field in (
        "intervention_id",
        "intervention_sha256",
        "pairing_manifest_sha256",
        "target_capability_id",
        "target_suite_sha256",
        "registered_direction",
    ):
        _literal(value[field], probe[field], f"{label}.{field}")
    target_outcomes = _validate_paired_outcomes(
        value["target_before_after"],
        label + ".target_before_after",
        expected_pair_count=probe["target_item_count"],
    )
    return {
        "intervention_id": probe["intervention_id"],
        "intervention_sha256": probe["intervention_sha256"],
        "pairing_manifest_sha256": probe["pairing_manifest_sha256"],
        "target_capability_id": probe["target_capability_id"],
        "target_suite_sha256": probe["target_suite_sha256"],
        "registered_direction": _REGISTERED_DIRECTION,
        "target_before_after": target_outcomes,
        "aggregate_evidence_sha256": _digest(
            value["aggregate_evidence_sha256"], label + ".aggregate_evidence_sha256"
        ),
    }


def _validate_candidate_result(
    raw: object,
    index: int,
    candidate: dict[str, Any],
) -> dict[str, Any]:
    label = f"aggregate_result.candidate_results[{index}]"
    value = _object(
        raw,
        {
            "capability_id",
            "evaluation_kind",
            "suite_sha256",
            "item_count",
            "variant_coverage",
            "capability_before_after",
            "signed_transfer",
        },
        label,
    )
    for field in ("capability_id", "evaluation_kind", "suite_sha256", "item_count"):
        _literal(value[field], candidate[field], f"{label}.{field}")
    return {
        "capability_id": candidate["capability_id"],
        "evaluation_kind": candidate["evaluation_kind"],
        "suite_sha256": candidate["suite_sha256"],
        "item_count": CANDIDATE_ITEM_COUNT,
        "variant_coverage": _validate_variant_coverage(
            value["variant_coverage"], label + ".variant_coverage", candidate
        ),
        "capability_before_after": _validate_paired_outcomes(
            value["capability_before_after"],
            label + ".capability_before_after",
            expected_pair_count=CANDIDATE_ITEM_COUNT,
        ),
        "signed_transfer": _validate_signed_transfer(
            value["signed_transfer"], label + ".signed_transfer", candidate
        ),
    }


def validate_capability_audit_result(
    audit_spec: object,
    raw: object,
) -> dict[str, Any]:
    """Validate a completed aggregate against its exact prospective spec."""

    spec = validate_capability_audit_spec(audit_spec)
    label = "aggregate_result"
    value = _object(
        raw,
        {
            "record_type",
            "schema_version",
            "completion_status",
            "evidence_scope",
            "audit_spec_sha256",
            "model_binding",
            "candidate_results",
            "authorizations",
            "result_sha256",
        },
        label,
    )
    _literal(
        value["record_type"], "cbds.capability-audit-result", label + ".record_type"
    )
    _literal(
        value["schema_version"],
        CAPABILITY_AUDIT_SCHEMA_VERSION,
        label + ".schema_version",
    )
    _literal(value["completion_status"], "complete", label + ".completion_status")
    _literal(value["evidence_scope"], _RESULT_SCOPE, label + ".evidence_scope")
    _literal(
        value["audit_spec_sha256"],
        spec["audit_spec_sha256"],
        label + ".audit_spec_sha256",
    )
    model_binding = _object(
        value["model_binding"],
        {"artifact_sha256", "tokenizer_sha256", "inspection_report_sha256"},
        label + ".model_binding",
    )
    normalized_binding: dict[str, str] = {}
    for field in ("artifact_sha256", "tokenizer_sha256", "inspection_report_sha256"):
        _literal(
            model_binding[field], spec["model"][field], f"{label}.model_binding.{field}"
        )
        normalized_binding[field] = spec["model"][field]

    raw_results = _list(
        value["candidate_results"],
        label + ".candidate_results",
        minimum=len(PLAN_CANDIDATE_FAMILY_IDS),
        maximum=len(PLAN_CANDIDATE_FAMILY_IDS),
    )
    results = [
        _validate_candidate_result(raw_item, index, spec["candidate_families"][index])
        for index, raw_item in enumerate(raw_results)
    ]
    authorizations = _validate_authorizations(
        value["authorizations"], label + ".authorizations"
    )
    _verify_address(value, "result_sha256", label)
    return {
        "record_type": "cbds.capability-audit-result",
        "schema_version": CAPABILITY_AUDIT_SCHEMA_VERSION,
        "completion_status": "complete",
        "evidence_scope": _RESULT_SCOPE,
        "audit_spec_sha256": spec["audit_spec_sha256"],
        "model_binding": normalized_binding,
        "candidate_results": results,
        "authorizations": authorizations,
        "result_sha256": value["result_sha256"],
    }


def _above_floor(candidate: dict[str, Any], result: dict[str, Any]) -> bool:
    successes = result["capability_before_after"]["before_successes"]
    if candidate["evaluation_kind"] == "executable":
        return successes >= EXECUTABLE_MIN_SUCCESSES
    chance = candidate["chance"]
    if chance is None:  # Defensive: validated objective candidates always have chance.
        return False
    numerator = chance["successes_numerator"]
    denominator = chance["trials_denominator"]
    # Compare percentage-point differences as integers.  This avoids a float
    # boundary around exactly ten points above chance.
    left = (successes * denominator - CANDIDATE_ITEM_COUNT * numerator) * 100
    right = (
        OBJECTIVE_MIN_POINTS_ABOVE_CHANCE
        * CANDIDATE_ITEM_COUNT
        * denominator
    )
    return left >= right


def _registered_signed_direction(result: dict[str, Any]) -> bool:
    capability = result["capability_before_after"]
    target = result["signed_transfer"]["target_before_after"]
    candidate_declined = capability["before_only"] > capability["after_only"]
    target_improved = target["after_only"] > target["before_only"]
    return candidate_declined and target_improved


def evaluate_capability_support_gate(
    audit_spec: object,
    aggregate_result: object,
) -> dict[str, Any]:
    """Return candidates passing the floor and signed-direction screen.

    The returned list is only a follow-up-audit roster.  It is not a training
    allowlist and cannot support an irrelevance, sacrifice, or research claim.
    """

    spec = validate_capability_audit_spec(audit_spec)
    result = validate_capability_audit_result(spec, aggregate_result)
    eligible: list[str] = []
    for candidate, candidate_result in zip(
        spec["candidate_families"], result["candidate_results"], strict=True
    ):
        if _above_floor(candidate, candidate_result) and _registered_signed_direction(
            candidate_result
        ):
            eligible.append(candidate["capability_id"])

    decision: dict[str, Any] = {
        "record_type": "cbds.capability-support-gate-decision",
        "binder_version": CAPABILITY_GATE_BINDER_VERSION,
        "audit_spec_sha256": spec["audit_spec_sha256"],
        "aggregate_result_sha256": result["result_sha256"],
        "evaluated_candidate_count": len(PLAN_CANDIDATE_FAMILY_IDS),
        "eligible_candidate_ids": eligible,
        "eligibility_semantics": _ELIGIBILITY_SEMANTICS,
        "irrelevance_inferred": False,
        "sacrifice_authorized": False,
        "training_authorized": False,
        "claim_authorized": False,
    }
    decision["decision_sha256"] = value_sha256(decision)
    return decision


__all__ = [
    "CAPABILITY_AUDIT_SCHEMA_VERSION",
    "CAPABILITY_GATE_BINDER_VERSION",
    "CANDIDATE_ITEM_COUNT",
    "EXECUTABLE_MIN_SUCCESSES",
    "MINIMUM_PREFIX_VARIANTS",
    "MINIMUM_PROMPT_VARIANTS",
    "OBJECTIVE_MIN_POINTS_ABOVE_CHANCE",
    "PLAN_CANDIDATE_FAMILY_IDS",
    "PLAN_CANDIDATE_ROSTER_HASH_DOMAIN",
    "PLAN_CANDIDATE_ROSTER_SHA256",
    "SOURCE_PLAN_SHA256",
    "TARGET_CAPABILITY_ID",
    "CapabilityAuditValidationError",
    "canonical_json_bytes",
    "content_address_capability_audit_result",
    "content_address_capability_audit_spec",
    "evaluate_capability_support_gate",
    "validate_capability_audit_result",
    "validate_capability_audit_spec",
    "value_sha256",
]
