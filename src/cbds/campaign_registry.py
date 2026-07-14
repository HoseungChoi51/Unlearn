"""Strict, content-addressed validation for complete campaign run registries.

The registry is a cross-document gate, not a second experiment manifest.  It
accepts the immutable campaign policy, every prospective run specification,
every completed experiment record, and (for confirmatory profiles) one bound
evaluation specification per completed seed run.  Optional task-result
collections can upgrade an evaluation cube from prospective coverage to
complete scored coverage.

The frozen campaign policy does not enumerate arms or encode metric-based
promotion and backbone-selection rules.  Consequently this module verifies
the integrity of the registry's declared roster and promotion links, but does
not claim that an arm deserved promotion or that a declared backbone won the
pilot. Confirmatory reference/comparison authority instead comes from every
prospective run spec's campaign contrast role; the registry contrast is only a
checked projection of those immutable inputs. The registry schema requires
these authority boundaries to remain explicit.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import copy
from functools import lru_cache
from importlib.resources import as_file, files
import os
from pathlib import Path
from typing import Any

from .evaluation_specs import (
    EvaluationArtifactBindingError,
    EvaluationSpecValidationError,
    TaskResultEvaluationBindingError,
    ordered_arm_roles_sha256,
    validate_evaluation_spec_against_experiment_manifest,
    validate_task_result_collection_against_evaluation_spec,
)
from .manifests import (
    ManifestValidationError,
    _validate_schema,
    atomic_write_json,
    load_document,
    value_sha256,
)
from .run_specs import (
    CampaignPolicyValidationError,
    CampaignRunValidationError,
    CompletedRunValidationError,
    RunSpecValidationError,
    campaign_policy_sha256,
    run_spec_sha256,
    validate_campaign_policy,
    validate_completed_run_against_campaign,
    validate_run_spec,
    validate_run_spec_against_campaign,
)


CAMPAIGN_REGISTRY_SCHEMA_VERSION = "1.0.0"
_MAX_DOCUMENTS = 65_536
_SEED_FIELDS = (
    "model_initialization",
    "data_order",
    "training",
    "operator_selection",
    "evaluation",
)
_TRAINING_AFFECTING_SEED_FIELDS = _SEED_FIELDS[:-1]
_PROFILE_ORDER = {
    "screening": 0,
    "confirmation": 1,
    "runner_up": 2,
}
_SCOPE = {
    "arm_roster_authority": "registry_declaration",
    "contrast_role_authority": "prospective_run_spec_campaign_fields",
    "promotion_validation": "declared_link_integrity_only",
    "backbone_selection_validation": "declared_identity_only",
    "evaluation_suite_roster_authority": "registry_declaration",
    "training_seed_set_hash_algorithm": (
        "canonical-json-sha256-of-replicate-index-and-all-run-seeds"
    ),
}


class CampaignRegistryValidationError(ValueError):
    """Raised with all detected registry or cross-document contract errors."""

    def __init__(self, errors: str | Iterable[str]) -> None:
        if isinstance(errors, str):
            normalized = (errors,)
        else:
            normalized = tuple(str(error) for error in errors)
        if not normalized:
            normalized = ("campaign-registry validation failed",)
        self.errors = normalized
        super().__init__(
            "campaign-registry validation failed: " + "; ".join(normalized)
        )


@lru_cache(maxsize=1)
def _packaged_schema() -> dict[str, Any]:
    resource = files("cbds.schemas").joinpath("campaign-registry.schema.json")
    try:
        with as_file(resource) as schema_path:
            loaded = load_document(schema_path)
    except ManifestValidationError as error:  # pragma: no cover - package defect
        raise CampaignRegistryValidationError(error.errors) from error
    if not isinstance(loaded, dict):  # pragma: no cover - fixed repository asset
        raise CampaignRegistryValidationError(
            "packaged campaign-registry schema must be an object"
        )
    return loaded


def _load_schema(
    schema_path: str | os.PathLike[str] | None,
) -> dict[str, Any]:
    packaged = _packaged_schema()
    if schema_path is None:
        return packaged
    try:
        loaded = load_document(schema_path)
    except ManifestValidationError as error:
        raise CampaignRegistryValidationError(error.errors) from error
    if not isinstance(loaded, dict):
        raise CampaignRegistryValidationError(
            f"schema {schema_path} must be an object"
        )
    if value_sha256(loaded) != value_sha256(packaged):
        raise CampaignRegistryValidationError(
            f"schema {schema_path} does not match the frozen packaged "
            "campaign-registry contract"
        )
    return packaged


def _nested_errors(prefix: str, error: Exception) -> list[str]:
    nested = getattr(error, "errors", (str(error),))
    return [f"{prefix}: {item}" for item in nested]


def _normalize_documents(
    documents: Mapping[str, Mapping[str, Any]] | Iterable[Mapping[str, Any]],
    *,
    label: str,
    identifier_field: str,
) -> dict[str, Mapping[str, Any]]:
    """Normalize an ID mapping or document sequence without losing duplicates."""

    if isinstance(documents, Mapping):
        raw_items: Iterable[tuple[object, object]] = documents.items()
        keys_are_declared = True
    elif isinstance(documents, (str, bytes)):
        raise CampaignRegistryValidationError(
            f"{label} must be an ID mapping or iterable of objects"
        )
    else:
        try:
            raw_items = enumerate(documents)
        except TypeError as error:
            raise CampaignRegistryValidationError(
                f"{label} must be an ID mapping or iterable of objects"
            ) from error
        keys_are_declared = False

    normalized: dict[str, Mapping[str, Any]] = {}
    for index, (declared_key, document) in enumerate(raw_items):
        if index >= _MAX_DOCUMENTS:
            raise CampaignRegistryValidationError(
                f"{label} exceeds the {_MAX_DOCUMENTS}-document limit"
            )
        if not isinstance(document, Mapping):
            raise CampaignRegistryValidationError(
                f"{label}[{declared_key!r}] must be an object"
            )
        identifier = document.get(identifier_field)
        if not isinstance(identifier, str) or not identifier:
            raise CampaignRegistryValidationError(
                f"{label}[{declared_key!r}].{identifier_field} must be a "
                "nonempty string"
            )
        if keys_are_declared and declared_key != identifier:
            raise CampaignRegistryValidationError(
                f"{label}[{declared_key!r}] key must equal "
                f"{identifier_field} {identifier!r}"
            )
        if identifier in normalized:
            raise CampaignRegistryValidationError(
                f"{label} contains duplicate {identifier_field} {identifier!r}"
            )
        normalized[identifier] = document
    return normalized


def _normalize_result_collections(
    collections: Mapping[str, Iterable[Mapping[str, Any]]]
    | Iterable[Mapping[str, Any]]
    | None,
) -> dict[str, list[Mapping[str, Any]]]:
    """Accept an evaluation-ID mapping or ``evaluation_id/results`` wrappers."""

    if collections is None:
        return {}
    normalized: dict[str, list[Mapping[str, Any]]] = {}
    if isinstance(collections, Mapping):
        raw_items: Iterable[tuple[object, object]] = collections.items()
        wrapped = False
    elif isinstance(collections, (str, bytes)):
        raise CampaignRegistryValidationError(
            "task_result_collections must be a mapping or wrapper sequence"
        )
    else:
        try:
            raw_items = enumerate(collections)
        except TypeError as error:
            raise CampaignRegistryValidationError(
                "task_result_collections must be a mapping or wrapper sequence"
            ) from error
        wrapped = True

    for index, (declared_key, raw) in enumerate(raw_items):
        if index >= _MAX_DOCUMENTS:
            raise CampaignRegistryValidationError(
                "task_result_collections exceeds the document limit"
            )
        if wrapped:
            if not isinstance(raw, Mapping) or set(raw) != {
                "evaluation_id",
                "results",
            }:
                raise CampaignRegistryValidationError(
                    f"task_result_collections[{declared_key!r}] must contain "
                    "exactly evaluation_id and results"
                )
            evaluation_id = raw["evaluation_id"]
            results = raw["results"]
        else:
            evaluation_id = declared_key
            results = raw
        if not isinstance(evaluation_id, str) or not evaluation_id:
            raise CampaignRegistryValidationError(
                "task-result collection evaluation_id must be a nonempty string"
            )
        if evaluation_id in normalized:
            raise CampaignRegistryValidationError(
                f"duplicate task-result collection for {evaluation_id!r}"
            )
        if isinstance(results, Mapping) or isinstance(results, (str, bytes)):
            raise CampaignRegistryValidationError(
                f"task-result collection {evaluation_id!r} must be a sequence"
            )
        try:
            materialized = list(results)  # type: ignore[arg-type]
        except TypeError as error:
            raise CampaignRegistryValidationError(
                f"task-result collection {evaluation_id!r} must be iterable"
            ) from error
        normalized[evaluation_id] = materialized
    return normalized


def _backbone_projection(spec: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "model": copy.deepcopy(spec["model"]),
        "tokenizer": copy.deepcopy(spec["tokenizer"]),
    }


def _capability_source_projection(
    spec: Mapping[str, Any],
) -> dict[str, list[dict[str, Any]]]:
    return {
        group: sorted(
            (
                {
                    "name": entry["name"],
                    "fraction": entry["fraction"],
                    "tokens": entry["tokens"],
                    "data_sha256": entry["data_sha256"],
                }
                for entry in spec["capability_mixture"][group]
            ),
            key=lambda entry: (
                entry["name"],
                entry["data_sha256"],
                entry["fraction"],
                entry["tokens"],
            ),
        )
        for group in ("target", "support")
    }


def _pairing_projection(spec: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "profile": spec["campaign"]["profile"],
        "git_revision": spec["git_revision"],
        "backbone": _backbone_projection(spec),
        "data": copy.deepcopy(spec["data"]),
        "capability_sources": _capability_source_projection(spec),
        "teacher": copy.deepcopy(spec["teacher"]),
        "execution": copy.deepcopy(spec["execution"]),
        "compute_accounting": {
            "revision": spec["compute_budget"]["accounting_revision"],
            "sha256": spec["compute_budget"]["accounting_sha256"],
        },
        "checkpoint_selection": {
            field: copy.deepcopy(spec["checkpoint"][field])
            for field in ("selection_split", "metric", "mode", "tie_breakers", "rule")
        },
    }


def _completed_teacher_projection(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        field: copy.deepcopy(record["teacher"][field])
        for field in (
            "enabled",
            "repository",
            "revision",
            "verified_corpus_sha256",
        )
    }


def campaign_backbone_identity_sha256(spec: Mapping[str, Any]) -> str:
    """Hash the validated pretrained model and tokenizer identity."""

    validated = validate_run_spec(spec)
    return value_sha256(_backbone_projection(validated))


def campaign_pairing_commitments_sha256(spec: Mapping[str, Any]) -> str:
    """Hash non-operator commitments that must be shared inside a cohort."""

    validated = validate_run_spec(spec)
    return value_sha256(_pairing_projection(validated))


def _operator_projection(spec: Mapping[str, Any]) -> dict[str, Any]:
    operator = spec["operator"]
    return {
        "mechanism": operator["mechanism"],
        "family": operator["family"],
        "configuration_sha256": operator["configuration_sha256"],
    }


def _run_protocol_projection(spec: Mapping[str, Any]) -> dict[str, Any]:
    """Project stable per-arm recipe fields while excluding seed-realized payloads."""

    campaign = spec["campaign"]
    operator = spec["operator"]
    return {
        "campaign": {
            "policy_schema_version": campaign["policy_schema_version"],
            "policy_sha256": campaign["policy_sha256"],
            "profile": campaign["profile"],
            "contrast_role": campaign["contrast_role"],
            "declared_seed_count": campaign["declared_seed_count"],
        },
        "stage": spec["stage"],
        "operator_recipe": {
            field: copy.deepcopy(operator[field])
            for field in (
                "mechanism",
                "family",
                "configuration_sha256",
                "dose",
                "selection_strategy",
                "selection_split",
            )
        },
        "optimizer": copy.deepcopy(spec["optimizer"]),
        "training_protocol": copy.deepcopy(spec["training_protocol"]),
        "tokens": copy.deepcopy(spec["tokens"]),
        "compute_budget": copy.deepcopy(spec["compute_budget"]),
        "checkpoint": copy.deepcopy(spec["checkpoint"]),
        "export": copy.deepcopy(spec["export"]),
    }


def campaign_run_protocol_sha256(spec: Mapping[str, Any]) -> str:
    """Hash one validated stable arm/profile recipe, excluding realized selection."""

    validated = validate_run_spec(spec)
    return value_sha256(_run_protocol_projection(validated))


def _seed_tuple(spec: Mapping[str, Any]) -> tuple[int, ...]:
    return tuple(spec["seeds"][field] for field in _SEED_FIELDS)


def _seed_records(
    cohort_runs: list[Mapping[str, Any]],
    specs: Mapping[str, Mapping[str, Any]],
    arm_id: str,
) -> list[dict[str, Any]]:
    selected = sorted(
        (entry for entry in cohort_runs if entry["arm_id"] == arm_id),
        key=lambda entry: entry["replicate_index"],
    )
    return [
        {
            "replicate_index": entry["replicate_index"],
            "seeds": copy.deepcopy(specs[entry["run_id"]]["seeds"]),
        }
        for entry in selected
    ]


def _evaluation_projection(spec: Mapping[str, Any]) -> dict[str, Any]:
    excluded = {"evaluation_id", "created_at", "git_revision", "artifact"}
    return {
        key: copy.deepcopy(value)
        for key, value in spec.items()
        if key not in excluded
    }


def _identifier_errors(
    candidate: Mapping[str, Any],
) -> tuple[dict[str, Mapping[str, Any]], dict[str, Mapping[str, Any]], list[str]]:
    errors: list[str] = []
    arms: dict[str, Mapping[str, Any]] = {}
    for index, arm in enumerate(candidate["arms"]):
        arm_id = arm["arm_id"]
        if arm_id in arms:
            errors.append(f"$.arms[{index}].arm_id: duplicate arm ID {arm_id!r}")
        arms[arm_id] = arm
    if [arm["arm_id"] for arm in candidate["arms"]] != sorted(arms):
        errors.append("$.arms: must be ordered by arm_id")

    cohorts: dict[str, Mapping[str, Any]] = {}
    arm_profiles: set[tuple[str, str]] = set()
    for index, cohort in enumerate(candidate["cohorts"]):
        cohort_id = cohort["cohort_id"]
        if cohort_id in cohorts:
            errors.append(
                f"$.cohorts[{index}].cohort_id: duplicate cohort ID {cohort_id!r}"
            )
        cohorts[cohort_id] = cohort
        if cohort["arm_ids"] != sorted(cohort["arm_ids"]):
            errors.append(f"$.cohorts[{index}].arm_ids: must be sorted")
        for arm_id in cohort["arm_ids"]:
            if arm_id not in arms:
                errors.append(
                    f"$.cohorts[{index}].arm_ids: undeclared arm {arm_id!r}"
                )
            key = (arm_id, cohort["profile"])
            if key in arm_profiles:
                errors.append(
                    f"$.cohorts[{index}]: arm {arm_id!r} appears more than once "
                    f"in profile {cohort['profile']!r}"
                )
            arm_profiles.add(key)
    unused_arms = sorted(set(arms) - {arm_id for arm_id, _ in arm_profiles})
    if unused_arms:
        errors.append(
            "$.arms: every declared arm must participate in at least one cohort; "
            "unused: " + ", ".join(unused_arms)
        )
    for arm_id, arm in arms.items():
        declared_profiles = [
            protocol["profile"] for protocol in arm["run_protocols"]
        ]
        expected_profiles = sorted(
            (
                profile
                for candidate_arm, profile in arm_profiles
                if candidate_arm == arm_id
            ),
            key=_PROFILE_ORDER.__getitem__,
        )
        if declared_profiles != expected_profiles:
            errors.append(
                f"$.arms[{arm_id!r}].run_protocols: must be ordered and contain "
                "exactly one protocol hash for every participating profile"
            )
    if [cohort["cohort_id"] for cohort in candidate["cohorts"]] != sorted(cohorts):
        errors.append("$.cohorts: must be ordered by cohort_id")
    return arms, cohorts, errors


def _arm_lineage_errors(arms: Mapping[str, Mapping[str, Any]]) -> list[str]:
    errors: list[str] = []
    for arm_id, arm in arms.items():
        source = arm["source_arm_id"]
        if source is not None and source not in arms:
            errors.append(
                f"$.arms[{arm_id!r}].source_arm_id: unknown arm {source!r}"
            )
        if source == arm_id:
            errors.append(
                f"$.arms[{arm_id!r}].source_arm_id: an arm cannot source itself"
            )
    for arm_id in arms:
        seen: set[str] = set()
        current: str | None = arm_id
        while current is not None and current in arms:
            if current in seen:
                errors.append(f"$.arms: source-arm lineage contains a cycle at {arm_id!r}")
                break
            seen.add(current)
            source = arms[current]["source_arm_id"]
            current = source if isinstance(source, str) else None
    return errors


def _contrast_role_errors(
    cohorts: Mapping[str, Mapping[str, Any]],
    arms: Mapping[str, Mapping[str, Any]],
) -> list[str]:
    """Validate prospective direction and direct-baseline arm lineage."""

    errors: list[str] = []
    for cohort_id, cohort in cohorts.items():
        contrast = cohort["contrast"]
        confirmatory = cohort["profile"] in ("confirmation", "runner_up")
        if not confirmatory:
            if contrast is not None:
                errors.append(
                    f"$.cohorts[{cohort_id!r}].contrast: screening cohorts "
                    "must use null"
                )
            continue
        if contrast is None:
            errors.append(
                f"$.cohorts[{cohort_id!r}].contrast: confirmatory cohorts "
                "must preregister reference and comparison roles"
            )
            continue
        roles = contrast["ordered_arm_roles"]
        try:
            expected_hash = ordered_arm_roles_sha256(roles)
        except (TypeError, ValueError) as error:
            errors.append(f"$.cohorts[{cohort_id!r}].contrast: {error}")
            continue
        if contrast["ordered_arm_roles_sha256"] != expected_hash:
            errors.append(
                f"$.cohorts[{cohort_id!r}].contrast.ordered_arm_roles_sha256: "
                "must hash the exact ordered roles"
            )
        reference_id = roles[0]["arm_id"]
        comparison_id = roles[1]["arm_id"]
        if {reference_id, comparison_id} != set(cohort["arm_ids"]):
            errors.append(
                f"$.cohorts[{cohort_id!r}].contrast: ordered role arm IDs "
                "must exactly cover cohort.arm_ids"
            )
            continue
        reference = arms.get(reference_id)
        comparison = arms.get(comparison_id)
        if reference is None or comparison is None:
            continue
        if comparison["source_arm_id"] != reference_id:
            errors.append(
                f"$.cohorts[{cohort_id!r}].contrast: comparison arm's "
                "source_arm_id must equal the reference arm ID"
            )
    return errors


def _cohort_link_errors(
    cohorts: Mapping[str, Mapping[str, Any]],
    profiles: Mapping[str, Mapping[str, Any]],
) -> list[str]:
    errors: list[str] = []
    for cohort_id, cohort in cohorts.items():
        profile = profiles[cohort["profile"]]
        expected_role = "runner_up" if cohort["profile"] == "runner_up" else "primary"
        if cohort["backbone_role"] != expected_role:
            errors.append(
                f"$.cohorts[{cohort_id!r}].backbone_role: must be {expected_role!r}"
            )
        source_id = cohort["source_cohort_id"]
        links = cohort["promotion_links"]
        if not profile["fresh_from_profiles"]:
            if source_id is not None or links:
                errors.append(
                    f"$.cohorts[{cohort_id!r}]: initial profile cannot declare "
                    "promotion links"
                )
            continue
        if source_id is None or source_id not in cohorts:
            errors.append(
                f"$.cohorts[{cohort_id!r}].source_cohort_id: must name an "
                "existing source cohort"
            )
            continue
        source = cohorts[source_id]
        if source["profile"] not in profile["fresh_from_profiles"]:
            errors.append(
                f"$.cohorts[{cohort_id!r}].source_cohort_id: source profile is "
                "not permitted by campaign policy fresh_from_profiles"
            )
        if [link["arm_id"] for link in links] != sorted(
            link["arm_id"] for link in links
        ):
            errors.append(
                f"$.cohorts[{cohort_id!r}].promotion_links: must be ordered by arm_id"
            )
        linked = [link["arm_id"] for link in links]
        if linked != cohort["arm_ids"]:
            errors.append(
                f"$.cohorts[{cohort_id!r}].promotion_links: must contain exactly "
                "one link for every cohort arm"
            )
        source_arms = set(source["arm_ids"])
        for link in links:
            if link["source_arm_id"] not in source_arms:
                errors.append(
                    f"$.cohorts[{cohort_id!r}].promotion_links: source arm "
                    f"{link['source_arm_id']!r} is absent from source cohort"
                )
    return errors


def _validate_joint_documents(
    registry_runs: Mapping[str, Mapping[str, Any]],
    raw_specs: Mapping[str, Mapping[str, Any]],
    raw_records: Mapping[str, Mapping[str, Any]],
    policy: Mapping[str, Any],
    *,
    run_spec_schema_path: str | os.PathLike[str] | None,
    campaign_schema_path: str | os.PathLike[str] | None,
    experiment_schema_path: str | os.PathLike[str] | None,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], list[str]]:
    errors: list[str] = []
    expected = set(registry_runs)
    for label, actual in (("run_specs", set(raw_specs)), ("completed_records", set(raw_records))):
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        if missing:
            errors.append(f"{label}: missing registry run IDs: {', '.join(missing)}")
        if extra:
            errors.append(f"{label}: unreferenced extra run IDs: {', '.join(extra)}")
    if errors:
        return {}, {}, errors

    specs: dict[str, dict[str, Any]] = {}
    records: dict[str, dict[str, Any]] = {}
    for run_id in sorted(expected):
        try:
            spec = validate_run_spec_against_campaign(
                raw_specs[run_id],
                policy,
                run_spec_schema_path=run_spec_schema_path,
                campaign_schema_path=campaign_schema_path,
            )
        except (RunSpecValidationError, CampaignRunValidationError) as error:
            errors.extend(_nested_errors(f"run_specs[{run_id!r}]", error))
            continue
        try:
            record = validate_completed_run_against_campaign(
                spec,
                policy,
                raw_records[run_id],
                run_spec_schema_path=run_spec_schema_path,
                campaign_schema_path=campaign_schema_path,
                experiment_schema_path=experiment_schema_path,
            )
        except (CompletedRunValidationError, CampaignRunValidationError) as error:
            errors.extend(_nested_errors(f"completed_records[{run_id!r}]", error))
            continue
        specs[run_id] = spec
        records[run_id] = record
    return specs, records, errors


def _run_and_pairing_errors(
    candidate: Mapping[str, Any],
    arms: Mapping[str, Mapping[str, Any]],
    cohorts: Mapping[str, Mapping[str, Any]],
    profiles: Mapping[str, Mapping[str, Any]],
    specs: Mapping[str, Mapping[str, Any]],
    records: Mapping[str, Mapping[str, Any]],
) -> tuple[dict[str, list[Mapping[str, Any]]], list[str]]:
    errors: list[str] = []
    registry_runs: dict[str, Mapping[str, Any]] = {}
    cells: set[tuple[str, str, int]] = set()
    cohort_runs: dict[str, list[Mapping[str, Any]]] = {
        cohort_id: [] for cohort_id in cohorts
    }
    ordering: list[tuple[str, str, int, str]] = []
    for index, entry in enumerate(candidate["runs"]):
        run_id = entry["run_id"]
        if run_id in registry_runs:
            errors.append(f"$.runs[{index}].run_id: duplicate run ID {run_id!r}")
        registry_runs[run_id] = entry
        ordering.append(
            (
                entry["cohort_id"],
                entry["arm_id"],
                entry["replicate_index"],
                run_id,
            )
        )
        cohort = cohorts.get(entry["cohort_id"])
        if cohort is None:
            errors.append(f"$.runs[{index}].cohort_id: unknown cohort")
            continue
        cohort_runs[entry["cohort_id"]].append(entry)
        if entry["arm_id"] not in cohort["arm_ids"]:
            errors.append(f"$.runs[{index}].arm_id: arm is absent from cohort")
        if entry["profile"] != cohort["profile"]:
            errors.append(f"$.runs[{index}].profile: must match cohort profile")
        cell = (entry["cohort_id"], entry["arm_id"], entry["replicate_index"])
        if cell in cells:
            errors.append(f"$.runs[{index}]: duplicate cohort/arm/replicate cell")
        cells.add(cell)
        if run_id not in specs or run_id not in records:
            continue
        spec = specs[run_id]
        record = records[run_id]
        if entry["run_spec_sha256"] != run_spec_sha256(spec):
            errors.append(f"$.runs[{index}].run_spec_sha256: digest mismatch")
        if entry["completed_record_sha256"] != value_sha256(record):
            errors.append(f"$.runs[{index}].completed_record_sha256: digest mismatch")
        campaign = spec["campaign"]
        if entry["profile"] != campaign["profile"]:
            errors.append(f"$.runs[{index}].profile: must derive from run spec")
        if entry["replicate_index"] != campaign["replicate_index"]:
            errors.append(
                f"$.runs[{index}].replicate_index: must derive from run spec"
            )
        arm = arms.get(entry["arm_id"])
        if arm is not None and arm["operator"] != _operator_projection(spec):
            errors.append(
                f"$.runs[{index}].arm_id: run operator does not match declared arm"
            )
        dense_checks = (
            ("run spec model", spec["model"]),
            (
                "run spec export",
                {
                    "architecture": spec["export"]["architecture"],
                    "physical_parameters": spec["export"]["planned_physical_parameters"],
                },
            ),
            ("completed model", record["model"]),
            ("completed export", record["export"]),
        )
        for label, payload in dense_checks:
            if payload["architecture"] != "dense" or not (
                0 < payload["physical_parameters"] < 1_000_000_000
            ):
                errors.append(
                    f"$.runs[{index}]: {label} must be dense and physically sub-1B"
                )
    if ordering != sorted(ordering):
        errors.append(
            "$.runs: must be ordered by cohort_id, arm_id, replicate_index, run_id"
        )

    for cohort_id, cohort in cohorts.items():
        entries = cohort_runs[cohort_id]
        required = profiles[cohort["profile"]]["required_seed_count"]
        expected_indices = list(range(required))
        prospective_roles_by_arm: dict[str, set[object]] = {}
        for arm_id in cohort["arm_ids"]:
            indices = sorted(
                entry["replicate_index"]
                for entry in entries
                if entry["arm_id"] == arm_id
            )
            if indices != expected_indices:
                errors.append(
                    f"$.cohorts[{cohort_id!r}]: arm {arm_id!r} must contain "
                    f"exact replicate indices {expected_indices}"
                )
            arm_entries = [
                entry
                for entry in entries
                if entry["arm_id"] == arm_id and entry["run_id"] in specs
            ]
            prospective_roles_by_arm[arm_id] = {
                specs[entry["run_id"]]["campaign"]["contrast_role"]
                for entry in arm_entries
            }
            declared_protocols = {
                protocol["profile"]: protocol["run_protocol_sha256"]
                for protocol in arms[arm_id]["run_protocols"]
            }
            protocol_hashes = {
                value_sha256(_run_protocol_projection(specs[entry["run_id"]]))
                for entry in arm_entries
            }
            expected_protocol = declared_protocols.get(cohort["profile"])
            if protocol_hashes != {expected_protocol}:
                errors.append(
                    f"$.arms[{arm_id!r}].run_protocols: all {cohort['profile']!r} "
                    "replicates must exactly match the declared stable run protocol"
                )
        if cohort["profile"] in ("confirmation", "runner_up"):
            authoritative_arms: dict[str, list[str]] = {
                "reference": [],
                "comparison": [],
            }
            for arm_id in cohort["arm_ids"]:
                declared_roles = prospective_roles_by_arm[arm_id]
                if len(declared_roles) != 1 or not declared_roles.issubset(
                    {"reference", "comparison"}
                ):
                    errors.append(
                        f"$.cohorts[{cohort_id!r}]: every prospective run spec "
                        f"for arm {arm_id!r} must declare one identical "
                        "campaign.contrast_role"
                    )
                    continue
                role = next(iter(declared_roles))
                if role == "reference":
                    authoritative_arms["reference"].append(arm_id)
                else:
                    authoritative_arms["comparison"].append(arm_id)
            if any(
                len(authoritative_arms[role]) != 1
                for role in ("reference", "comparison")
            ):
                errors.append(
                    f"$.cohorts[{cohort_id!r}]: prospective run specs must "
                    "derive exactly one all-reference arm and one "
                    "all-comparison arm"
                )
            else:
                reference_id = authoritative_arms["reference"][0]
                comparison_id = authoritative_arms["comparison"][0]
                derived_roles = [
                    {"role": "reference", "arm_id": reference_id},
                    {"role": "comparison", "arm_id": comparison_id},
                ]
                contrast = cohort["contrast"]
                if (
                    contrast is None
                    or contrast["ordered_arm_roles"] != derived_roles
                ):
                    errors.append(
                        f"$.cohorts[{cohort_id!r}].contrast: ordered roles must "
                        "derive from every prospective run spec's "
                        "campaign.contrast_role"
                    )
                comparison = arms.get(comparison_id)
                if (
                    comparison is not None
                    and comparison["source_arm_id"] != reference_id
                ):
                    errors.append(
                        f"$.cohorts[{cohort_id!r}].contrast: prospective "
                        "run-spec roles require the comparison arm's "
                        "source_arm_id to equal the reference arm ID"
                    )
        usable = [entry for entry in entries if entry["run_id"] in specs]
        if not usable:
            continue
        backbone_hashes = {
            value_sha256(_backbone_projection(specs[entry["run_id"]]))
            for entry in usable
        }
        if backbone_hashes != {cohort["backbone_identity_sha256"]}:
            errors.append(
                f"$.cohorts[{cohort_id!r}].backbone_identity_sha256: must "
                "derive identically from every run"
            )
        pairing_hashes = {
            value_sha256(_pairing_projection(specs[entry["run_id"]]))
            for entry in usable
        }
        if pairing_hashes != {cohort["pairing_commitments_sha256"]}:
            errors.append(
                f"$.cohorts[{cohort_id!r}].pairing_commitments_sha256: data, "
                "target/support sources, teacher, execution, model, or tokenizer "
                "commitments are not paired"
            )
        seed_tuples: list[tuple[int, ...]] = []
        paired_seed_records: list[Mapping[str, int]] = []
        for replicate in expected_indices:
            replica = [
                entry for entry in usable if entry["replicate_index"] == replicate
            ]
            seeds = {_seed_tuple(specs[entry["run_id"]]) for entry in replica}
            if len(seeds) != 1:
                errors.append(
                    f"$.cohorts[{cohort_id!r}]: replicate {replicate} must pair "
                    "all run seed fields across arms"
                )
            elif len(replica) == len(cohort["arm_ids"]):
                seed_tuples.append(next(iter(seeds)))
                paired_seed_records.append(specs[replica[0]["run_id"]]["seeds"])
        if len(seed_tuples) == required and len(set(seed_tuples)) != required:
            errors.append(
                f"$.cohorts[{cohort_id!r}]: replicate seed tuples must be distinct"
            )
        if len(paired_seed_records) == required:
            for field in _TRAINING_AFFECTING_SEED_FIELDS:
                values = [record[field] for record in paired_seed_records]
                if len(set(values)) != required:
                    errors.append(
                        f"$.cohorts[{cohort_id!r}]: training-affecting seed field "
                        f"{field!r} must be unique across cohort replicates; "
                        "changing only the evaluation seed does not establish "
                        "fresh training runs"
                    )
        completed_teacher_hashes = {
            value_sha256(_completed_teacher_projection(records[entry["run_id"]]))
            for entry in usable
            if entry["run_id"] in records
        }
        if len(completed_teacher_hashes) != 1:
            errors.append(
                f"$.cohorts[{cohort_id!r}]: all arms and replicates must use "
                "the identical verified teacher corpus across the entire cohort"
            )
        elif (
            len(usable) == len(entries)
            and cohort["completed_pairing_sha256"]
            != next(iter(completed_teacher_hashes))
        ):
            errors.append(
                f"$.cohorts[{cohort_id!r}].completed_pairing_sha256: must derive "
                "from the cohort-wide verified teacher corpus projection"
            )
    return cohort_runs, errors


def _freshness_errors(
    cohort_runs: Mapping[str, list[Mapping[str, Any]]],
    cohorts: Mapping[str, Mapping[str, Any]],
    specs: Mapping[str, Mapping[str, Any]],
) -> list[str]:
    by_profile: dict[str, dict[str, set[int]]] = {}
    for cohort_id, entries in cohort_runs.items():
        profile = cohorts[cohort_id]["profile"]
        for entry in entries:
            if entry["run_id"] in specs:
                seeds = specs[entry["run_id"]]["seeds"]
                profile_seeds = by_profile.setdefault(
                    profile,
                    {field: set() for field in _TRAINING_AFFECTING_SEED_FIELDS},
                )
                for field in _TRAINING_AFFECTING_SEED_FIELDS:
                    profile_seeds[field].add(seeds[field])
    errors: list[str] = []
    profile_names = sorted(by_profile)
    for index, left in enumerate(profile_names):
        for right in profile_names[index + 1 :]:
            for field in _TRAINING_AFFECTING_SEED_FIELDS:
                reused = by_profile[left][field].intersection(
                    by_profile[right][field]
                )
                if reused:
                    errors.append(
                        f"campaign training-affecting seed field {field!r} is "
                        f"reused across phases {left!r} and {right!r}; "
                        "confirmation and runner-up training seeds must be "
                        "field-wise fresh"
                    )
    return errors


def _evaluation_errors(
    candidate: Mapping[str, Any],
    cohorts: Mapping[str, Mapping[str, Any]],
    profiles: Mapping[str, Mapping[str, Any]],
    cohort_runs: Mapping[str, list[Mapping[str, Any]]],
    specs: Mapping[str, Mapping[str, Any]],
    records: Mapping[str, Mapping[str, Any]],
    raw_evaluations: Mapping[str, Mapping[str, Any]],
    raw_collections: Mapping[str, list[Mapping[str, Any]]],
    *,
    evaluation_schema_path: str | os.PathLike[str] | None,
    task_result_schema_path: str | os.PathLike[str] | None,
) -> list[str]:
    errors: list[str] = []
    bindings: dict[str, tuple[Mapping[str, Any], Mapping[str, Any]]] = {}
    for run_index, entry in enumerate(candidate["runs"]):
        run_bindings = entry["evaluations"]
        ordering = [
            (binding["cube_id"], binding["evaluation_id"])
            for binding in run_bindings
        ]
        if ordering != sorted(ordering):
            errors.append(
                f"$.runs[{run_index}].evaluations: must be ordered by cube_id "
                "and evaluation_id"
            )
        cube_ids: set[str] = set()
        for binding_index, binding in enumerate(run_bindings):
            cube_id = binding["cube_id"]
            if cube_id in cube_ids:
                errors.append(
                    f"$.runs[{run_index}].evaluations[{binding_index}].cube_id: "
                    "duplicate cube binding for this run"
                )
            cube_ids.add(cube_id)
            evaluation_id = binding["evaluation_id"]
            if evaluation_id in bindings:
                errors.append(
                    f"$.runs[{run_index}].evaluations[{binding_index}]"
                    ".evaluation_id: duplicate binding"
                )
            bindings[evaluation_id] = (entry, binding)
    expected_ids = set(bindings)
    actual_ids = set(raw_evaluations)
    missing = sorted(expected_ids - actual_ids)
    extra = sorted(actual_ids - expected_ids)
    if missing:
        errors.append("evaluation_specs: missing registry IDs: " + ", ".join(missing))
    if extra:
        errors.append(
            "evaluation_specs: unreferenced extra IDs: " + ", ".join(extra)
        )
    declared_collection_ids = {
        evaluation_id
        for evaluation_id, (_, binding) in bindings.items()
        if binding["task_result_collection_sha256"] is not None
    }
    supplied_collection_ids = set(raw_collections)
    if declared_collection_ids != supplied_collection_ids:
        missing_results = sorted(declared_collection_ids - supplied_collection_ids)
        extra_results = sorted(supplied_collection_ids - declared_collection_ids)
        if missing_results:
            errors.append(
                "task_result_collections: missing registry IDs: "
                + ", ".join(missing_results)
            )
        if extra_results:
            errors.append(
                "task_result_collections: unreferenced extra IDs: "
                + ", ".join(extra_results)
            )
    if errors:
        return errors

    evaluations: dict[str, dict[str, Any]] = {}
    for evaluation_id in sorted(expected_ids):
        entry, binding = bindings[evaluation_id]
        run_id = entry["run_id"]
        if run_id not in records:
            continue
        try:
            evaluation = validate_evaluation_spec_against_experiment_manifest(
                raw_evaluations[evaluation_id],
                records[run_id],
                evaluation_schema_path=evaluation_schema_path,
            )
        except (EvaluationSpecValidationError, EvaluationArtifactBindingError) as error:
            errors.extend(_nested_errors(f"evaluation_specs[{evaluation_id!r}]", error))
            continue
        if binding["evaluation_spec_sha256"] != value_sha256(evaluation):
            errors.append(
                f"evaluation_specs[{evaluation_id!r}]: canonical digest mismatch"
            )
        collection_hash = binding["task_result_collection_sha256"]
        if collection_hash is None:
            if binding["task_result_record_count"] != 0:
                errors.append(
                    f"evaluation_specs[{evaluation_id!r}]: "
                    "task_result_record_count must be zero when no collection "
                    "digest is declared"
                )
        else:
            try:
                collection = validate_task_result_collection_against_evaluation_spec(
                    raw_collections[evaluation_id],
                    evaluation,
                    task_result_schema_path=task_result_schema_path,
                    evaluation_schema_path=evaluation_schema_path,
                )
            except TaskResultEvaluationBindingError as error:
                errors.extend(
                    _nested_errors(
                        f"task_result_collections[{evaluation_id!r}]", error
                    )
                )
                continue
            if collection_hash != value_sha256(collection):
                errors.append(
                    f"task_result_collections[{evaluation_id!r}]: canonical "
                    "collection digest mismatch"
                )
            if binding["task_result_record_count"] != len(collection):
                errors.append(
                    f"task_result_collections[{evaluation_id!r}]: record count mismatch"
                )
        evaluations[evaluation_id] = evaluation

    for cohort_id, cohort in cohorts.items():
        entries = cohort_runs[cohort_id]
        profile = cohort["profile"]
        cubes = cohort["evaluation_cubes"]
        cube_ids = [cube["cube_id"] for cube in cubes]
        if cube_ids != sorted(cube_ids):
            errors.append(
                f"$.cohorts[{cohort_id!r}].evaluation_cubes: must be ordered "
                "by cube_id"
            )
        if len(cube_ids) != len(set(cube_ids)):
            errors.append(
                f"$.cohorts[{cohort_id!r}].evaluation_cubes: duplicate cube_id"
            )
        confirmatory = profile in ("confirmation", "runner_up")
        if not confirmatory:
            if cohort["analysis_lane"] is not None:
                errors.append(
                    f"$.cohorts[{cohort_id!r}].analysis_lane: screening "
                    "cohorts must use null"
                )
            if cubes or any(entry["evaluations"] for entry in entries):
                errors.append(
                    f"$.cohorts[{cohort_id!r}]: screening evaluations are outside "
                    "the confirmatory registry cubes"
                )
            continue
        if len(cohort["arm_ids"]) != 2:
            errors.append(
                f"$.cohorts[{cohort_id!r}].arm_ids: confirmatory evaluation "
                "cubes require exactly two arms (promoted arm and direct baseline)"
            )
            continue
        if cohort["analysis_lane"] not in ("fixed_size", "compression"):
            errors.append(
                f"$.cohorts[{cohort_id!r}].analysis_lane: confirmatory "
                "cohorts must declare fixed_size or compression"
            )
            continue
        if not cubes:
            errors.append(
                f"$.cohorts[{cohort_id!r}]: a confirmatory cohort must declare "
                "at least one evaluation suite cube"
            )
            continue
        expected_cube_ids = set(cube_ids)
        roster_complete = True
        for entry in entries:
            actual = {binding["cube_id"] for binding in entry["evaluations"]}
            if actual != expected_cube_ids or len(entry["evaluations"]) != len(cubes):
                errors.append(
                    f"$.runs[{entry['run_id']!r}].evaluations: must contain exactly "
                    "one binding for every cohort evaluation cube"
                )
                roster_complete = False
        if not roster_complete:
            continue
        required = profiles[profile]["required_seed_count"]
        contrast = cohort["contrast"]
        if contrast is None:  # already reported by the cohort contrast gate
            continue
        reference_arm_id = contrast["ordered_arm_roles"][0]["arm_id"]
        seed_records = _seed_records(entries, specs, reference_arm_id)
        seed_set_hash = value_sha256(seed_records)
        for cube in cubes:
            cube_id = cube["cube_id"]
            cube_pairs = [
                (
                    entry,
                    next(
                        binding
                        for binding in entry["evaluations"]
                        if binding["cube_id"] == cube_id
                    ),
                )
                for entry in entries
            ]
            cube_evaluations = [
                evaluations[binding["evaluation_id"]]
                for _, binding in cube_pairs
                if binding["evaluation_id"] in evaluations
            ]
            if len(cube_evaluations) != len(entries):
                continue
            evaluation_commitments = {
                value_sha256(_evaluation_projection(evaluation))
                for evaluation in cube_evaluations
            }
            if len(evaluation_commitments) != 1:
                errors.append(
                    f"$.cohorts[{cohort_id!r}].evaluation_cubes[{cube_id!r}]: "
                    "benchmark, task, execution, decoding, verifier, or analysis "
                    "commitments are not paired"
                )
            for evaluation in cube_evaluations:
                analysis = evaluation["analysis_plan"]
                if analysis["phase"] != "confirmatory":
                    errors.append(
                        f"evaluation_specs[{evaluation['evaluation_id']!r}]: profile "
                        f"{profile!r} requires a confirmatory evaluation"
                    )
                if analysis["lane"] != cohort["analysis_lane"]:
                    errors.append(
                        f"evaluation_specs[{evaluation['evaluation_id']!r}]: "
                        "analysis lane must match the cohort analysis_lane"
                    )
                if analysis["training_seed_count"] != required:
                    errors.append(
                        f"evaluation_specs[{evaluation['evaluation_id']!r}]: training "
                        "seed count must match campaign profile"
                    )
                if analysis["training_seed_set_sha256"] != seed_set_hash:
                    errors.append(
                        f"evaluation_specs[{evaluation['evaluation_id']!r}]: training "
                        "seed-set hash must derive from all five campaign runs"
                    )
                if analysis["contrast"] != contrast:
                    errors.append(
                        f"evaluation_specs[{evaluation['evaluation_id']!r}]: "
                        "ordered reference/comparison roles must exactly match "
                        "the cohort contrast"
                    )
            first = cube_evaluations[0]
            collection_states = {
                binding["task_result_collection_sha256"] is not None
                for _, binding in cube_pairs
            }
            if len(collection_states) != 1:
                errors.append(
                    f"$.cohorts[{cohort_id!r}].evaluation_cubes[{cube_id!r}]: "
                    "task-result coverage must be all-or-none across the paired cube"
                )
                continue
            complete_results = True in collection_states
            cube_projection = {
                "cube_id": cube_id,
                "cohort_id": cohort_id,
                "profile": profile,
                "arm_ids": copy.deepcopy(cohort["arm_ids"]),
                "contrast": copy.deepcopy(contrast),
                "training_seeds": seed_records,
                "task_count": first["benchmark"]["task_count"],
                "task_commitment_set_sha256": first["task_commitments"][
                    "commitment_set_sha256"
                ],
                "bindings": [
                    {
                        "arm_id": entry["arm_id"],
                        "replicate_index": entry["replicate_index"],
                        "run_id": entry["run_id"],
                        "seeds": copy.deepcopy(specs[entry["run_id"]]["seeds"]),
                        "evaluation_id": binding["evaluation_id"],
                        "evaluation_spec_sha256": binding[
                            "evaluation_spec_sha256"
                        ],
                        "task_result_collection_sha256": binding[
                            "task_result_collection_sha256"
                        ],
                    }
                    for entry, binding in cube_pairs
                ],
            }
            expected_cube = {
                "cube_id": cube_id,
                "benchmark_id": first["benchmark"]["benchmark_id"],
                "benchmark_split_sha256": first["benchmark"]["split"]["sha256"],
                "task_commitment_set_sha256": first["task_commitments"][
                    "commitment_set_sha256"
                ],
                "task_count": first["benchmark"]["task_count"],
                "training_seed_count": required,
                "training_seed_set_sha256": seed_set_hash,
                "ordered_arm_roles_sha256": contrast[
                    "ordered_arm_roles_sha256"
                ],
                "paired_cube_sha256": value_sha256(cube_projection),
                "result_coverage": (
                    "complete_task_results"
                    if complete_results
                    else "evaluation_specs_only"
                ),
            }
            if cube != expected_cube:
                errors.append(
                    f"$.cohorts[{cohort_id!r}].evaluation_cubes[{cube_id!r}]: "
                    "labels, dimensions, coverage, or hashes do not match the "
                    "derived paired cube"
                )
    return errors


def validate_campaign_registry(
    registry: Mapping[str, Any],
    campaign_policy: Mapping[str, Any],
    run_specs: Mapping[str, Mapping[str, Any]] | Iterable[Mapping[str, Any]],
    completed_records: Mapping[str, Mapping[str, Any]]
    | Iterable[Mapping[str, Any]],
    *,
    evaluation_specs: Mapping[str, Mapping[str, Any]]
    | Iterable[Mapping[str, Any]] = (),
    task_result_collections: Mapping[str, Iterable[Mapping[str, Any]]]
    | Iterable[Mapping[str, Any]]
    | None = None,
    registry_schema_path: str | os.PathLike[str] | None = None,
    campaign_schema_path: str | os.PathLike[str] | None = None,
    run_spec_schema_path: str | os.PathLike[str] | None = None,
    experiment_schema_path: str | os.PathLike[str] | None = None,
    evaluation_schema_path: str | os.PathLike[str] | None = None,
    task_result_schema_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Jointly validate one registry and every document it references."""

    if not isinstance(registry, Mapping):
        raise CampaignRegistryValidationError("$: registry must be an object")
    candidate = copy.deepcopy(dict(registry))
    try:
        _validate_schema(candidate, _load_schema(registry_schema_path))
    except ManifestValidationError as error:
        raise CampaignRegistryValidationError(error.errors) from error
    try:
        policy = validate_campaign_policy(
            campaign_policy, schema_path=campaign_schema_path
        )
    except CampaignPolicyValidationError as error:
        raise CampaignRegistryValidationError(error.errors) from error

    errors: list[str] = []
    expected_policy = {
        "policy_id": policy["policy_id"],
        "schema_version": policy["schema_version"],
        "sha256": campaign_policy_sha256(policy),
    }
    if candidate["campaign_policy"] != expected_policy:
        errors.append("$.campaign_policy: must derive from the supplied policy")
    if candidate["scope"] != _SCOPE:
        errors.append("$.scope: must preserve the frozen policy-limitation statement")

    arms, cohorts, identity_errors = _identifier_errors(candidate)
    errors.extend(identity_errors)
    errors.extend(_arm_lineage_errors(arms))
    errors.extend(_contrast_role_errors(cohorts, arms))
    profiles = {profile["name"]: profile for profile in policy["profiles"]}
    errors.extend(_cohort_link_errors(cohorts, profiles))

    registry_run_map: dict[str, Mapping[str, Any]] = {}
    for entry in candidate["runs"]:
        registry_run_map.setdefault(entry["run_id"], entry)
    raw_specs = _normalize_documents(
        run_specs, label="run_specs", identifier_field="run_id"
    )
    raw_records = _normalize_documents(
        completed_records, label="completed_records", identifier_field="run_id"
    )
    raw_evaluations = _normalize_documents(
        evaluation_specs,
        label="evaluation_specs",
        identifier_field="evaluation_id",
    )
    raw_collections = _normalize_result_collections(task_result_collections)
    specs, records, document_errors = _validate_joint_documents(
        registry_run_map,
        raw_specs,
        raw_records,
        policy,
        run_spec_schema_path=run_spec_schema_path,
        campaign_schema_path=campaign_schema_path,
        experiment_schema_path=experiment_schema_path,
    )
    errors.extend(document_errors)
    cohort_runs, run_errors = _run_and_pairing_errors(
        candidate, arms, cohorts, profiles, specs, records
    )
    errors.extend(run_errors)
    errors.extend(_freshness_errors(cohort_runs, cohorts, specs))
    errors.extend(
        _evaluation_errors(
            candidate,
            cohorts,
            profiles,
            cohort_runs,
            specs,
            records,
            raw_evaluations,
            raw_collections,
            evaluation_schema_path=evaluation_schema_path,
            task_result_schema_path=task_result_schema_path,
        )
    )
    if errors:
        raise CampaignRegistryValidationError(errors)
    return candidate


def campaign_registry_sha256(
    registry: Mapping[str, Any],
    campaign_policy: Mapping[str, Any],
    run_specs: Mapping[str, Mapping[str, Any]] | Iterable[Mapping[str, Any]],
    completed_records: Mapping[str, Mapping[str, Any]]
    | Iterable[Mapping[str, Any]],
    **kwargs: Any,
) -> str:
    """Return the canonical hash only after complete joint validation."""

    return value_sha256(
        validate_campaign_registry(
            registry,
            campaign_policy,
            run_specs,
            completed_records,
            **kwargs,
        )
    )


def load_campaign_registry(
    path: str | os.PathLike[str],
    campaign_policy: Mapping[str, Any],
    run_specs: Mapping[str, Mapping[str, Any]] | Iterable[Mapping[str, Any]],
    completed_records: Mapping[str, Mapping[str, Any]]
    | Iterable[Mapping[str, Any]],
    **kwargs: Any,
) -> dict[str, Any]:
    """Strictly load and jointly validate one campaign registry."""

    try:
        loaded = load_document(path)
    except ManifestValidationError as error:
        raise CampaignRegistryValidationError(error.errors) from error
    if not isinstance(loaded, Mapping):
        raise CampaignRegistryValidationError("$: registry must be an object")
    return validate_campaign_registry(
        loaded,
        campaign_policy,
        run_specs,
        completed_records,
        **kwargs,
    )


def write_campaign_registry(
    path: str | os.PathLike[str],
    registry: Mapping[str, Any],
    campaign_policy: Mapping[str, Any],
    run_specs: Mapping[str, Mapping[str, Any]] | Iterable[Mapping[str, Any]],
    completed_records: Mapping[str, Mapping[str, Any]]
    | Iterable[Mapping[str, Any]],
    **kwargs: Any,
) -> Path:
    """Jointly validate and atomically write canonical registry JSON."""

    validated = validate_campaign_registry(
        registry,
        campaign_policy,
        run_specs,
        completed_records,
        **kwargs,
    )
    return atomic_write_json(path, validated, canonical=True)


__all__ = [
    "CAMPAIGN_REGISTRY_SCHEMA_VERSION",
    "CampaignRegistryValidationError",
    "campaign_backbone_identity_sha256",
    "campaign_pairing_commitments_sha256",
    "campaign_registry_sha256",
    "campaign_run_protocol_sha256",
    "load_campaign_registry",
    "validate_campaign_registry",
    "write_campaign_registry",
]
