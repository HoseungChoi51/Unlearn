"""Artifact-bound confirmatory outcome derivation.

This module closes the boundary between executable task-result evidence and
the binary cells consumed by :mod:`cbds.statistics`.  Callers supply the
complete campaign document graph, never binary outcome rows.  The graph is
jointly validated, every result collection is scored under its prospective
evaluation policy, and the resulting arm/training-seed/task cube is hashed.

The binder checks content-addressed records; it does not rerun generated
programs, recompute verifier decisions, or attest the Python process executing
this code.  Those limits are recorded in every returned document.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import copy
from typing import Any, Final

from .campaign_registry import (
    CampaignRegistryValidationError,
    validate_campaign_registry,
)
from .confirmatory_analysis import run_confirmatory_contrast
from .evaluation_specs import (
    TaskResultEvaluationBindingError,
    select_scored_task_results_against_evaluation_spec,
)
from .manifests import value_sha256
from .run_specs import campaign_policy_sha256


OUTCOME_BINDER_VERSION: Final[str] = "1.0.0"
_MAX_DOCUMENTS: Final[int] = 65_536
_MAX_RESULTS_PER_COLLECTION: Final[int] = 100_000
_SEED_FIELDS: Final[tuple[str, ...]] = (
    "model_initialization",
    "data_order",
    "training",
    "operator_selection",
    "evaluation",
)
_TRUST_SCOPE: Final[dict[str, str]] = {
    "source_validation": (
        "joint_campaign_registry_validation_with_frozen_packaged_contracts"
    ),
    "scored_attempt_selection": (
        "prospective_evaluation_outcome_policy_first_scored_attempt"
    ),
    "binary_outcome_derivation": (
        "one_iff_selected_task_result_terminal_status_equals_passed"
    ),
    "task_result_evidence": (
        "content_addressed_harness_records_not_program_reexecution"
    ),
    "verifier_evidence": (
        "record_consistency_and_hash_binding_not_verifier_recomputation"
    ),
    "runtime_attestation": "none",
    "serialized_record_scope": (
        "self_hash_proves_integrity_not_source_provenance_rebind_sources_to_verify"
    ),
}


class OutcomeBindingValidationError(ValueError):
    """Raised when an artifact graph cannot derive one confirmatory cube."""

    def __init__(self, errors: str | Iterable[str]) -> None:
        if isinstance(errors, str):
            normalized = (errors,)
        else:
            normalized = tuple(str(error) for error in errors)
        if not normalized:
            normalized = ("outcome binding validation failed",)
        self.errors = normalized
        super().__init__(
            "outcome binding validation failed: " + "; ".join(normalized)
        )


def _documents(
    raw: Mapping[str, Mapping[str, Any]],
    *,
    label: str,
    identifier_field: str,
) -> dict[str, dict[str, Any]]:
    if not isinstance(raw, Mapping):
        raise OutcomeBindingValidationError(f"{label} must be an ID mapping")
    if len(raw) > _MAX_DOCUMENTS:
        raise OutcomeBindingValidationError(
            f"{label} exceeds the {_MAX_DOCUMENTS}-document limit"
        )
    result: dict[str, dict[str, Any]] = {}
    for declared_id, document in raw.items():
        if not isinstance(declared_id, str) or not declared_id:
            raise OutcomeBindingValidationError(
                f"{label} keys must be nonempty strings"
            )
        if not isinstance(document, Mapping):
            raise OutcomeBindingValidationError(
                f"{label}[{declared_id!r}] must be an object"
            )
        snapshot = copy.deepcopy(dict(document))
        if snapshot.get(identifier_field) != declared_id:
            raise OutcomeBindingValidationError(
                f"{label}[{declared_id!r}] key must equal "
                f"{identifier_field} {snapshot.get(identifier_field)!r}"
            )
        result[declared_id] = snapshot
    return result


def _collections(
    raw: Mapping[str, Iterable[Mapping[str, Any]]],
) -> dict[str, list[dict[str, Any]]]:
    if not isinstance(raw, Mapping):
        raise OutcomeBindingValidationError(
            "task_result_collections must be an evaluation-ID mapping"
        )
    if len(raw) > _MAX_DOCUMENTS:
        raise OutcomeBindingValidationError(
            "task_result_collections exceeds the document limit"
        )
    result: dict[str, list[dict[str, Any]]] = {}
    for evaluation_id, collection in raw.items():
        if not isinstance(evaluation_id, str) or not evaluation_id:
            raise OutcomeBindingValidationError(
                "task-result collection keys must be nonempty strings"
            )
        if isinstance(collection, Mapping) or isinstance(
            collection, (str, bytes, bytearray)
        ):
            raise OutcomeBindingValidationError(
                f"task_result_collections[{evaluation_id!r}] must be an iterable"
            )
        materialized: list[dict[str, Any]] = []
        try:
            iterator = iter(collection)
        except TypeError as error:
            raise OutcomeBindingValidationError(
                f"task_result_collections[{evaluation_id!r}] must be iterable"
            ) from error
        for index, record in enumerate(iterator):
            if index >= _MAX_RESULTS_PER_COLLECTION:
                raise OutcomeBindingValidationError(
                    f"task_result_collections[{evaluation_id!r}] exceeds the "
                    f"{_MAX_RESULTS_PER_COLLECTION}-record limit"
                )
            if not isinstance(record, Mapping):
                raise OutcomeBindingValidationError(
                    f"task_result_collections[{evaluation_id!r}][{index}] "
                    "must be an object"
                )
            materialized.append(copy.deepcopy(dict(record)))
        result[evaluation_id] = materialized
    return result


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 192:
        raise OutcomeBindingValidationError(
            f"{label} must be a nonempty identifier of at most 192 characters"
        )
    return value


def _cell_commitment(
    records: list[dict[str, Any]],
    *,
    cohort_id: str,
    cube_id: str,
    ordered_arm_roles_sha256: str,
    training_seed_set_sha256: str,
    task_commitment_set_sha256: str,
) -> dict[str, Any]:
    return {
        "commitment_type": "cbds.paired-binary-analysis-cells",
        "version": "1.0.0",
        "cohort_id": cohort_id,
        "cube_id": cube_id,
        "direction": "comparison_minus_reference",
        "ordered_arm_roles_sha256": ordered_arm_roles_sha256,
        "training_seed_set_sha256": training_seed_set_sha256,
        "task_commitment_set_sha256": task_commitment_set_sha256,
        "records": records,
    }


def bind_confirmatory_binary_cube(
    registry: Mapping[str, Any],
    campaign_policy: Mapping[str, Any],
    run_specs: Mapping[str, Mapping[str, Any]],
    completed_records: Mapping[str, Mapping[str, Any]],
    evaluation_specs: Mapping[str, Mapping[str, Any]],
    task_result_collections: Mapping[str, Iterable[Mapping[str, Any]]],
    *,
    cohort_id: str,
    cube_id: str,
) -> dict[str, Any]:
    """Derive one complete static confirmatory binary cube from source records.

    ``cohort_id`` and ``cube_id`` select a prospectively registered cube.  No
    outcome rows or pass labels are accepted.  Every source mapping is
    snapshotted before validation so generators and caller mutation cannot
    alter the evidence between binding and derivation.
    """

    selected_cohort_id = _identifier(cohort_id, "cohort_id")
    selected_cube_id = _identifier(cube_id, "cube_id")
    if not isinstance(registry, Mapping):
        raise OutcomeBindingValidationError("registry must be an object")
    if not isinstance(campaign_policy, Mapping):
        raise OutcomeBindingValidationError("campaign_policy must be an object")
    registry_snapshot = copy.deepcopy(dict(registry))
    policy_snapshot = copy.deepcopy(dict(campaign_policy))
    specs = _documents(run_specs, label="run_specs", identifier_field="run_id")
    completions = _documents(
        completed_records,
        label="completed_records",
        identifier_field="run_id",
    )
    evaluations = _documents(
        evaluation_specs,
        label="evaluation_specs",
        identifier_field="evaluation_id",
    )
    collections = _collections(task_result_collections)

    try:
        validated_registry = validate_campaign_registry(
            registry_snapshot,
            policy_snapshot,
            specs,
            completions,
            evaluation_specs=evaluations,
            task_result_collections=collections,
        )
    except CampaignRegistryValidationError as error:
        raise OutcomeBindingValidationError(
            tuple(f"campaign_registry: {item}" for item in error.errors)
        ) from error

    cohorts = [
        item
        for item in validated_registry["cohorts"]
        if item["cohort_id"] == selected_cohort_id
    ]
    if len(cohorts) != 1:
        raise OutcomeBindingValidationError(
            f"cohort_id {selected_cohort_id!r} does not select exactly one cohort"
        )
    cohort = cohorts[0]
    if cohort["profile"] not in ("confirmation", "runner_up"):
        raise OutcomeBindingValidationError(
            "selected cohort must use confirmation or runner_up profile"
        )
    if cohort["analysis_lane"] not in ("fixed_size", "compression"):
        raise OutcomeBindingValidationError(
            "selected cohort must declare a confirmatory analysis lane"
        )
    cubes = [
        item
        for item in cohort["evaluation_cubes"]
        if item["cube_id"] == selected_cube_id
    ]
    if len(cubes) != 1:
        raise OutcomeBindingValidationError(
            f"cube_id {selected_cube_id!r} does not select exactly one cube "
            f"inside cohort {selected_cohort_id!r}"
        )
    cube = cubes[0]
    if cube["result_coverage"] != "complete_task_results":
        raise OutcomeBindingValidationError(
            "selected cube must have complete_task_results coverage"
        )
    contrast = cohort["contrast"]
    if contrast is None:  # pragma: no cover - joint validation rejects this
        raise OutcomeBindingValidationError("selected cohort lacks a contrast")
    roles = contrast["ordered_arm_roles"]
    reference_arm = roles[0]["arm_id"]
    comparison_arm = roles[1]["arm_id"]
    role_by_arm = {reference_arm: "reference", comparison_arm: "comparison"}
    role_order = {reference_arm: 0, comparison_arm: 1}

    entries = [
        entry
        for entry in validated_registry["runs"]
        if entry["cohort_id"] == selected_cohort_id
    ]
    entries.sort(
        key=lambda entry: (
            role_order.get(entry["arm_id"], 99),
            entry["replicate_index"],
            entry["run_id"],
        )
    )
    expected_entry_count = 2 * cube["training_seed_count"]
    if len(entries) != expected_entry_count:
        raise OutcomeBindingValidationError(
            "selected cube does not contain exactly two arms times its "
            "training-seed count"
        )

    cells: list[dict[str, Any]] = []
    source_bindings: list[dict[str, Any]] = []
    expected_tasks: tuple[str, ...] | None = None
    for entry in entries:
        arm_id = entry["arm_id"]
        if arm_id not in role_by_arm:
            raise OutcomeBindingValidationError(
                f"run {entry['run_id']!r} belongs to an arm outside the contrast"
            )
        matching = [
            binding
            for binding in entry["evaluations"]
            if binding["cube_id"] == selected_cube_id
        ]
        if len(matching) != 1:  # pragma: no cover - joint validation rejects this
            raise OutcomeBindingValidationError(
                f"run {entry['run_id']!r} lacks exactly one selected cube binding"
            )
        binding = matching[0]
        evaluation_id = binding["evaluation_id"]
        evaluation = evaluations[evaluation_id]
        if (
            evaluation["mode"] != "static"
            or evaluation["benchmark"]["suite"] != "static"
        ):
            raise OutcomeBindingValidationError(
                "artifact-bound confirmatory analysis currently supports only "
                "the static endpoint"
            )
        try:
            scored = select_scored_task_results_against_evaluation_spec(
                collections[evaluation_id], evaluation
            )
        except TaskResultEvaluationBindingError as error:
            raise OutcomeBindingValidationError(
                tuple(
                    f"task_result_collections[{evaluation_id!r}]: {item}"
                    for item in error.errors
                )
            ) from error
        task_ids = tuple(result["prompt_id"] for result in scored)
        if expected_tasks is None:
            expected_tasks = task_ids
        elif task_ids != expected_tasks:
            raise OutcomeBindingValidationError(
                "all selected collections must expose one identical ordered "
                "semantic-task set"
            )
        if len(scored) != cube["task_count"]:
            raise OutcomeBindingValidationError(
                f"collection {evaluation_id!r} scored task count does not match cube"
            )
        run_spec = specs[entry["run_id"]]
        training_seed = run_spec["seeds"]["training"]
        terminal_counts: dict[str, int] = {}
        for result in scored:
            status = result["terminal_status"]
            terminal_counts[status] = terminal_counts.get(status, 0) + 1
            cells.append(
                {
                    "arm": arm_id,
                    "seed": training_seed,
                    "task": result["prompt_id"],
                    "passed": 1 if status == "passed" else 0,
                }
            )
        selected_hashes = [value_sha256(result) for result in scored]
        source_bindings.append(
            {
                "role": role_by_arm[arm_id],
                "arm_id": arm_id,
                "replicate_index": entry["replicate_index"],
                "run_id": entry["run_id"],
                "training_seed": training_seed,
                "run_spec_sha256": entry["run_spec_sha256"],
                "completed_record_sha256": entry["completed_record_sha256"],
                "evaluation_id": evaluation_id,
                "evaluation_spec_sha256": binding["evaluation_spec_sha256"],
                "task_result_collection_sha256": binding[
                    "task_result_collection_sha256"
                ],
                "task_result_record_count": binding["task_result_record_count"],
                "scored_task_result_count": len(scored),
                "scored_task_result_hashes_sha256": value_sha256(
                    {
                        "commitment_type": "cbds.scored-task-result-hashes",
                        "version": "1.0.0",
                        "hashes": selected_hashes,
                    }
                ),
                "scored_terminal_status_counts": {
                    status: terminal_counts[status]
                    for status in sorted(terminal_counts)
                },
                "scored_attempt_rule": evaluation["outcome_policy"]["rerun"][
                    "scored_attempt_rule"
                ],
                "scored_attempt_policy_sha256": evaluation["outcome_policy"][
                    "rerun"
                ]["policy_sha256"],
            }
        )

    if expected_tasks is None:  # pragma: no cover - confirmatory count is positive
        raise OutcomeBindingValidationError("selected cube has no tasks")
    cells.sort(
        key=lambda cell: (
            role_order[cell["arm"]],
            cell["seed"],
            cell["task"].encode("utf-8"),
        )
    )
    expected_cells = 2 * cube["training_seed_count"] * cube["task_count"]
    if len(cells) != expected_cells:
        raise OutcomeBindingValidationError(
            f"derived {len(cells)} cells but coherent cube requires {expected_cells}"
        )
    cell_keys = {(row["arm"], row["seed"], row["task"]) for row in cells}
    if len(cell_keys) != expected_cells:
        raise OutcomeBindingValidationError(
            "derived cube contains duplicate arm/training-seed/task cells"
        )

    reference_entries = [
        entry for entry in entries if entry["arm_id"] == reference_arm
    ]
    seed_records = [
        {
            "replicate_index": entry["replicate_index"],
            "seeds": {
                field: specs[entry["run_id"]]["seeds"][field]
                for field in _SEED_FIELDS
            },
        }
        for entry in reference_entries
    ]
    arms_by_id = {arm["arm_id"]: arm for arm in validated_registry["arms"]}
    arm_declarations = [
        {
            "arm_id": arm_id,
            "source_arm_id": arms_by_id[arm_id]["source_arm_id"],
        }
        for arm_id in sorted((reference_arm, comparison_arm))
    ]
    representative_binding = source_bindings[0]
    record: dict[str, Any] = {
        "record_type": "cbds.artifact-bound-binary-cube",
        "binder_version": OUTCOME_BINDER_VERSION,
        "cohort_id": selected_cohort_id,
        "cube_id": selected_cube_id,
        "profile": cohort["profile"],
        "lane": cohort["analysis_lane"],
        "direction": "comparison_minus_reference",
        "reference_arm": reference_arm,
        "comparison_arm": comparison_arm,
        "registry_contrast": copy.deepcopy(contrast),
        "registry_arm_declarations": arm_declarations,
        "registry_training_seed_records": seed_records,
        "representative_evaluation_id": representative_binding["evaluation_id"],
        "bindings": {
            "campaign_registry_sha256": value_sha256(validated_registry),
            "campaign_policy_sha256": campaign_policy_sha256(policy_snapshot),
            "registry_paired_cube_sha256": cube["paired_cube_sha256"],
            "training_seed_set_sha256": cube["training_seed_set_sha256"],
            "task_commitment_set_sha256": cube[
                "task_commitment_set_sha256"
            ],
            "ordered_arm_roles_sha256": cube["ordered_arm_roles_sha256"],
            "binary_cells_sha256": value_sha256(
                _cell_commitment(
                    cells,
                    cohort_id=selected_cohort_id,
                    cube_id=selected_cube_id,
                    ordered_arm_roles_sha256=cube[
                        "ordered_arm_roles_sha256"
                    ],
                    training_seed_set_sha256=cube[
                        "training_seed_set_sha256"
                    ],
                    task_commitment_set_sha256=cube[
                        "task_commitment_set_sha256"
                    ],
                )
            ),
        },
        "dimensions": {
            "arm_count": 2,
            "training_seed_count": cube["training_seed_count"],
            "task_count": cube["task_count"],
            "cell_count": len(cells),
        },
        "source_bindings": source_bindings,
        "records": cells,
        "outcome_evidence_scope": (
            "derived_from_jointly_validated_registry_bound_scored_task_results"
        ),
        "trust_scope": copy.deepcopy(_TRUST_SCOPE),
    }
    record["bound_cube_record_sha256"] = value_sha256(record)
    return record


def run_confirmatory_contrast_from_collections(
    registry: Mapping[str, Any],
    campaign_policy: Mapping[str, Any],
    run_specs: Mapping[str, Mapping[str, Any]],
    completed_records: Mapping[str, Mapping[str, Any]],
    evaluation_specs: Mapping[str, Mapping[str, Any]],
    task_result_collections: Mapping[str, Iterable[Mapping[str, Any]]],
    *,
    cohort_id: str,
    cube_id: str,
    contrast_id: str,
    analysis_code_bytes: bytes,
    analysis_code_revision: str,
) -> dict[str, Any]:
    """Bind source collections and immediately run the frozen static analysis.

    There is intentionally no ``records`` argument: binary rows exist only as
    a local product of :func:`bind_confirmatory_binary_cube` and cannot be
    substituted by the caller between artifact validation and analysis.
    """

    # Materialize once here because collection values may be one-shot iterators.
    evaluations = _documents(
        evaluation_specs,
        label="evaluation_specs",
        identifier_field="evaluation_id",
    )
    collections = _collections(task_result_collections)
    bound = bind_confirmatory_binary_cube(
        registry,
        campaign_policy,
        run_specs,
        completed_records,
        evaluations,
        collections,
        cohort_id=cohort_id,
        cube_id=cube_id,
    )
    representative_id = bound["representative_evaluation_id"]
    if representative_id not in evaluations:
        raise OutcomeBindingValidationError(
            "representative evaluation disappeared after source binding"
        )
    result = run_confirmatory_contrast(
        evaluations[representative_id],
        bound["records"],
        contrast_id=contrast_id,
        endpoint="static",
        analysis_code_bytes=analysis_code_bytes,
        analysis_code_revision=analysis_code_revision,
        registry_contrast=bound["registry_contrast"],
        registry_arm_declarations=bound["registry_arm_declarations"],
        registry_training_seed_records=bound[
            "registry_training_seed_records"
        ],
        registry_training_seed_set_sha256=bound["bindings"][
            "training_seed_set_sha256"
        ],
    )
    result["bindings"]["artifact_bound_outcome_cube"] = {
        "binder_version": bound["binder_version"],
        "cohort_id": bound["cohort_id"],
        "cube_id": bound["cube_id"],
        "campaign_registry_sha256": bound["bindings"][
            "campaign_registry_sha256"
        ],
        "campaign_policy_sha256": bound["bindings"][
            "campaign_policy_sha256"
        ],
        "registry_paired_cube_sha256": bound["bindings"][
            "registry_paired_cube_sha256"
        ],
        "binary_cells_sha256": bound["bindings"]["binary_cells_sha256"],
        "bound_cube_record_sha256": bound["bound_cube_record_sha256"],
        "outcome_evidence_scope": bound["outcome_evidence_scope"],
        "runtime_attestation": bound["trust_scope"]["runtime_attestation"],
    }
    result["outcome_evidence_scope"] = (
        "artifact_bound_scored_task_result_collections"
    )
    result.pop("contrast_record_sha256")
    result["contrast_record_sha256"] = value_sha256(result)
    return result


__all__ = [
    "OUTCOME_BINDER_VERSION",
    "OutcomeBindingValidationError",
    "bind_confirmatory_binary_cube",
    "run_confirmatory_contrast_from_collections",
]
