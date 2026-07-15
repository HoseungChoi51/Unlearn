"""Prospective, immutable specifications for train and compression runs.

A run spec records decisions made before execution.  It deliberately excludes
measured FLOPs and final artifact hashes; those belong in a completed
experiment manifest.  JSON Schema validates document shape and the checks in
this module enforce relationships that JSON Schema cannot express portably.
"""

from __future__ import annotations

import copy
import math
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
    canonical_json,
    load_experiment_manifest,
    load_document,
    validate_experiment_manifest,
    value_sha256,
)


RUN_SPEC_SCHEMA_VERSION = "2.0.0"
CAMPAIGN_POLICY_SCHEMA_VERSION = "1.0.0"


class RunSpecValidationError(ValueError):
    """Raised with every schema or semantic error in a prospective run spec."""

    def __init__(self, errors: str | Iterable[str]) -> None:
        if isinstance(errors, str):
            normalized = (errors,)
        else:
            normalized = tuple(str(error) for error in errors)
        if not normalized:
            normalized = ("run-spec validation failed",)
        self.errors = normalized
        super().__init__("run-spec validation failed: " + "; ".join(normalized))


class CompletedRunValidationError(ValueError):
    """Raised when a completed record does not honor its prospective run spec."""

    def __init__(self, errors: str | Iterable[str]) -> None:
        if isinstance(errors, str):
            normalized = (errors,)
        else:
            normalized = tuple(str(error) for error in errors)
        if not normalized:
            normalized = ("completed-run validation failed",)
        self.errors = normalized
        super().__init__("completed-run validation failed: " + "; ".join(normalized))


class CampaignPolicyValidationError(ValueError):
    """Raised when an immutable campaign policy is malformed or inconsistent."""

    def __init__(self, errors: str | Iterable[str]) -> None:
        if isinstance(errors, str):
            normalized = (errors,)
        else:
            normalized = tuple(str(error) for error in errors)
        if not normalized:
            normalized = ("campaign-policy validation failed",)
        self.errors = normalized
        super().__init__("campaign-policy validation failed: " + "; ".join(normalized))


class CampaignRunValidationError(ValueError):
    """Raised when a valid run spec does not satisfy its referenced profile."""

    def __init__(self, errors: str | Iterable[str]) -> None:
        if isinstance(errors, str):
            normalized = (errors,)
        else:
            normalized = tuple(str(error) for error in errors)
        if not normalized:
            normalized = ("campaign-run validation failed",)
        self.errors = normalized
        super().__init__("campaign-run validation failed: " + "; ".join(normalized))


@lru_cache(maxsize=1)
def _packaged_schema() -> dict[str, Any]:
    resource = files("cbds.schemas").joinpath("run-spec.schema.json")
    try:
        with as_file(resource) as schema_path:
            loaded = load_document(schema_path)
    except ManifestValidationError as error:  # pragma: no cover - packaging defect
        raise RunSpecValidationError(error.errors) from error
    if not isinstance(loaded, dict):  # pragma: no cover - fixed repository asset
        raise RunSpecValidationError("packaged run-spec schema must be an object")
    return loaded


@lru_cache(maxsize=1)
def _packaged_campaign_schema() -> dict[str, Any]:
    resource = files("cbds.schemas").joinpath("campaign-policy.schema.json")
    try:
        with as_file(resource) as schema_path:
            loaded = load_document(schema_path)
    except ManifestValidationError as error:  # pragma: no cover - packaging defect
        raise CampaignPolicyValidationError(error.errors) from error
    if not isinstance(loaded, dict):  # pragma: no cover - fixed repository asset
        raise CampaignPolicyValidationError(
            "packaged campaign-policy schema must be an object"
        )
    return loaded


def _load_schema(schema_path: str | os.PathLike[str] | None) -> dict[str, Any]:
    if schema_path is None:
        return _packaged_schema()
    try:
        loaded = load_document(schema_path)
    except ManifestValidationError as error:
        raise RunSpecValidationError(error.errors) from error
    if not isinstance(loaded, dict):
        raise RunSpecValidationError(f"schema {schema_path} must be an object")
    packaged = _packaged_schema()
    if value_sha256(loaded) != value_sha256(packaged):
        raise RunSpecValidationError(
            f"schema {schema_path} does not match the frozen packaged "
            "run-spec contract"
        )
    return packaged


def _load_campaign_schema(
    schema_path: str | os.PathLike[str] | None,
) -> dict[str, Any]:
    if schema_path is None:
        return _packaged_campaign_schema()
    try:
        loaded = load_document(schema_path)
    except ManifestValidationError as error:
        raise CampaignPolicyValidationError(error.errors) from error
    if not isinstance(loaded, dict):
        raise CampaignPolicyValidationError(f"schema {schema_path} must be an object")
    packaged = _packaged_campaign_schema()
    if value_sha256(loaded) != value_sha256(packaged):
        raise CampaignPolicyValidationError(
            f"schema {schema_path} does not match the frozen packaged "
            "campaign-policy contract"
        )
    return packaged


def _unique_values(values: Iterable[Any], path: str, errors: list[str]) -> None:
    seen: set[str] = set()
    for index, value in enumerate(values):
        key = canonical_json(value)
        if key in seen:
            errors.append(f"{path}[{index}]: duplicate value {value!r}")
        seen.add(key)


def _split_errors(spec: Mapping[str, Any]) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    splits = spec["data"]["splits"]
    _unique_values((split["name"] for split in splits), "$.data.splits", errors)
    split_by_name = {split["name"]: split for split in splits}

    for split_index, split in enumerate(splits):
        expected_sealed = split["role"] == "sealed_test"
        if split["sealed"] is not expected_sealed:
            errors.append(
                f"$.data.splits[{split_index}].sealed: must be {expected_sealed} "
                f"when role is {split['role']!r}"
            )

    checkpoint_split = spec["checkpoint"]["selection_split"]
    if checkpoint_split not in split_by_name:
        errors.append(
            "$.checkpoint.selection_split: must name an entry in $.data.splits"
        )
    elif split_by_name[checkpoint_split]["sealed"]:
        errors.append(
            "$.checkpoint.selection_split: cannot select checkpoints on a sealed split"
        )
    elif split_by_name[checkpoint_split]["role"] != "shadow_validation":
        errors.append(
            "$.checkpoint.selection_split: must have role 'shadow_validation'"
        )
    return split_by_name, errors


def _mixture_errors(spec: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    mixture = spec["capability_mixture"]
    target = mixture["target"]
    support = mixture["support"]
    entries = target + support
    _unique_values(
        (entry["name"] for entry in entries),
        "$.capability_mixture",
        errors,
    )

    fraction_sum = math.fsum(entry["fraction"] for entry in entries)
    if not math.isclose(fraction_sum, 1.0, rel_tol=0.0, abs_tol=1e-9):
        errors.append(
            "$.capability_mixture: target and support fractions must sum to 1 "
            f"(got {fraction_sum})"
        )

    tokens = spec["tokens"]
    target_tokens = sum(entry["tokens"] for entry in target)
    support_tokens = sum(entry["tokens"] for entry in support)
    if target_tokens != tokens["target"]:
        errors.append(
            "$.tokens.target: must equal the sum of target capability tokens"
        )
    if support_tokens != tokens["support"]:
        errors.append(
            "$.tokens.support: must equal the sum of support capability tokens"
        )
    if tokens["target"] + tokens["support"] != tokens["mixture_visible"]:
        errors.append(
            "$.tokens.mixture_visible: must equal target plus support tokens"
        )

    for group_name, group in (("target", target), ("support", support)):
        for index, entry in enumerate(group):
            expected = entry["fraction"] * tokens["mixture_visible"]
            if abs(entry["tokens"] - expected) > 1.0:
                errors.append(
                    f"$.capability_mixture.{group_name}[{index}].tokens: must "
                    "match its fraction of mixture_visible within one token"
                )

    if spec["optimizer"]["enabled"]:
        if tokens["optimizer_visible"] != tokens["mixture_visible"]:
            errors.append(
                "$.tokens.optimizer_visible: must equal mixture_visible when "
                "the optimizer is enabled"
            )
    elif tokens["optimizer_visible"] != 0:
        errors.append(
            "$.tokens.optimizer_visible: must be zero when the optimizer is disabled"
        )
    if tokens["teacher_derived"] > tokens["target"]:
        errors.append("$.tokens.teacher_derived: cannot exceed target tokens")
    if tokens["teacher_derived"] > tokens["optimizer_visible"]:
        errors.append(
            "$.tokens.teacher_derived: cannot exceed optimizer_visible tokens"
        )
    return errors


def _teacher_errors(
    spec: Mapping[str, Any], split_by_name: Mapping[str, Any]
) -> list[str]:
    errors: list[str] = []
    teacher = spec["teacher"]
    tokens = spec["tokens"]
    compute = spec["compute_budget"]
    provenance = (
        "repository",
        "revision",
        "checkpoint_sha256",
        "architecture",
        "physical_parameters",
        "generation_policy_sha256",
        "source_split",
    )

    if teacher["enabled"]:
        for field in provenance:
            if teacher[field] is None or teacher[field] == "":
                errors.append(f"$.teacher.{field}: required when teacher is enabled")
        source_split = teacher["source_split"]
        if source_split not in split_by_name:
            errors.append("$.teacher.source_split: must name an entry in $.data.splits")
        elif split_by_name[source_split]["sealed"]:
            errors.append("$.teacher.source_split: cannot use a sealed split")
        elif split_by_name[source_split]["role"] != "training":
            errors.append("$.teacher.source_split: must have role 'training'")
        if teacher["initial_candidates_per_prompt"] <= 0:
            errors.append(
                "$.teacher.initial_candidates_per_prompt: must be positive when enabled"
            )
        if teacher["maximum_candidates_per_prompt"] <= 0:
            errors.append(
                "$.teacher.maximum_candidates_per_prompt: must be positive when enabled"
            )
        if (
            teacher["maximum_candidates_per_prompt"]
            < teacher["initial_candidates_per_prompt"]
        ):
            errors.append(
                "$.teacher.maximum_candidates_per_prompt: cannot be less than "
                "initial_candidates_per_prompt"
            )
        if teacher["verified_only"] is not True:
            errors.append("$.teacher.verified_only: must be true when teacher is enabled")
        if tokens["teacher_derived"] <= 0:
            errors.append("$.tokens.teacher_derived: must be positive when teacher is enabled")
        if compute["teacher_generation_max_flops"] <= 0:
            errors.append(
                "$.compute_budget.teacher_generation_max_flops: must be positive "
                "when teacher is enabled"
            )
    else:
        for field in provenance:
            if teacher[field] is not None:
                errors.append(f"$.teacher.{field}: must be null when teacher is disabled")
        for field in (
            "initial_candidates_per_prompt",
            "maximum_candidates_per_prompt",
        ):
            if teacher[field] != 0:
                errors.append(f"$.teacher.{field}: must be zero when teacher is disabled")
        if teacher["verified_only"] is not False:
            errors.append("$.teacher.verified_only: must be false when teacher is disabled")
        if tokens["teacher_derived"] != 0:
            errors.append("$.tokens.teacher_derived: must be zero when teacher is disabled")
        if compute["teacher_generation_max_flops"] != 0:
            errors.append(
                "$.compute_budget.teacher_generation_max_flops: must be zero "
                "when teacher is disabled"
            )
    return errors


def _operator_errors(
    spec: Mapping[str, Any], split_by_name: Mapping[str, Any]
) -> list[str]:
    errors: list[str] = []
    operator = spec["operator"]
    mechanism = operator["mechanism"]
    selection_strategy = operator["selection_strategy"]
    stage = spec["stage"]
    index_groups = operator["structural_indices"]
    bit_allocations = operator["bit_allocation"]
    factorizations = operator["factorizations"]

    group_keys: set[tuple[str, int | None]] = set()
    layer_required = {"residual_branch", "attention_head", "ffn_channel"}
    layer_forbidden = {"hidden_dimension", "embedding_token", "layer"}
    for group_index, group in enumerate(index_groups):
        key = (group["component"], group["layer"])
        if key in group_keys:
            errors.append(
                f"$.operator.structural_indices[{group_index}]: duplicate "
                "component/layer group"
            )
        group_keys.add(key)
        if group["indices"] != sorted(set(group["indices"])):
            errors.append(
                f"$.operator.structural_indices[{group_index}].indices: must be "
                "unique and increasing"
            )
        if group["component"] in layer_required and group["layer"] is None:
            errors.append(
                f"$.operator.structural_indices[{group_index}].layer: required "
                f"for {group['component']}"
            )
        if group["component"] in layer_forbidden and group["layer"] is not None:
            errors.append(
                f"$.operator.structural_indices[{group_index}].layer: must be "
                f"null for {group['component']}"
            )

    allocation_keys: set[tuple[str, int | None]] = set()
    for allocation_index, allocation in enumerate(bit_allocations):
        key = (allocation["component"], allocation["layer"])
        if key in allocation_keys:
            errors.append(
                f"$.operator.bit_allocation[{allocation_index}]: duplicate "
                "component/layer allocation"
            )
        allocation_keys.add(key)

    factorization_tensor_names: set[str] = set()
    layered_factor_components = {
        "attention_q_proj",
        "attention_k_proj",
        "attention_v_proj",
        "attention_o_proj",
        "ffn_gate_proj",
        "ffn_up_proj",
        "ffn_down_proj",
    }
    unlayered_factor_components = {"embedding", "lm_head"}
    factorization_parameter_savings = 0
    for factorization_index, factorization in enumerate(factorizations):
        tensor_name = factorization["tensor_name"]
        if tensor_name in factorization_tensor_names:
            errors.append(
                f"$.operator.factorizations[{factorization_index}]: duplicate "
                "tensor_name"
            )
        factorization_tensor_names.add(tensor_name)
        if (
            factorization["component"] in layered_factor_components
            and factorization["layer"] is None
        ):
            errors.append(
                f"$.operator.factorizations[{factorization_index}].layer: required "
                f"for {factorization['component']}"
            )
        if (
            factorization["component"] in unlayered_factor_components
            and factorization["layer"] is not None
        ):
            errors.append(
                f"$.operator.factorizations[{factorization_index}].layer: must be "
                f"null for {factorization['component']}"
            )
        dense_parameters = (
            factorization["input_dimension"] * factorization["output_dimension"]
        )
        factor_parameters = factorization["rank"] * (
            factorization["input_dimension"] + factorization["output_dimension"]
        )
        if factor_parameters >= dense_parameters:
            errors.append(
                f"$.operator.factorizations[{factorization_index}].rank: two-factor "
                "decomposition must use fewer parameters than the dense matrix"
            )
        else:
            factorization_parameter_savings += dense_parameters - factor_parameters

    if factorizations:
        expected_physical_parameters = (
            spec["model"]["physical_parameters"] - factorization_parameter_savings
        )
        if spec["export"]["planned_physical_parameters"] != expected_physical_parameters:
            errors.append(
                "$.export.planned_physical_parameters: must equal source physical "
                "parameters minus the committed low-rank factorization savings "
                f"({expected_physical_parameters})"
            )

    selection_split = operator["selection_split"]
    selection_manifest = operator["selection_manifest_sha256"]
    selection_tokens = spec["tokens"]["selection_visible"]
    selection_flops = spec["compute_budget"]["selection_max_flops"]

    no_data_selection = {"none", "random", "uniform"}
    if selection_strategy in no_data_selection:
        if selection_split is not None:
            errors.append(
                f"$.operator.selection_split: must be null for {selection_strategy} selection"
            )
        if selection_tokens != 0:
            errors.append(
                f"$.tokens.selection_visible: must be zero for {selection_strategy} selection"
            )
        if selection_flops != 0:
            errors.append(
                f"$.compute_budget.selection_max_flops: must be zero for "
                f"{selection_strategy} selection"
            )
        if selection_strategy == "random":
            if selection_manifest is None:
                errors.append(
                    "$.operator.selection_manifest_sha256: required for random selection"
                )
        elif selection_manifest is not None:
            errors.append(
                f"$.operator.selection_manifest_sha256: must be null for "
                f"{selection_strategy} selection"
            )
    else:
        for field in ("selection_split", "selection_manifest_sha256"):
            if operator[field] is None:
                errors.append(
                    f"$.operator.{field}: required for {selection_strategy} selection"
                )
        if selection_tokens <= 0:
            errors.append(
                f"$.tokens.selection_visible: must be positive for "
                f"{selection_strategy} selection"
            )
        if selection_flops <= 0:
            errors.append(
                f"$.compute_budget.selection_max_flops: must be positive for "
                f"{selection_strategy} selection"
            )
        if selection_split not in split_by_name:
            errors.append(
                "$.operator.selection_split: must name an entry in $.data.splits"
            )
        elif split_by_name[selection_split]["sealed"]:
            errors.append("$.operator.selection_split: cannot use a sealed split")
        else:
            selection_role = split_by_name[selection_split]["role"]
            allowed_roles = (
                {"training", "diagnostic"}
                if selection_strategy == "task_agnostic"
                else {"operator_selection", "method_development"}
            )
            if selection_role not in allowed_roles:
                errors.append(
                    "$.operator.selection_split: role is incompatible with "
                    f"{selection_strategy} selection; expected one of "
                    f"{sorted(allowed_roles)!r}"
                )

    allowed_strategies = {
        "baseline": {"none"},
        "distill": {"none"},
        "recycle": {"random", "task_agnostic", "target_aware"},
        "prune": {"random", "task_agnostic", "target_aware"},
        "quantize": {"uniform", "task_agnostic", "target_aware"},
        "factorize": {"random", "uniform", "task_agnostic", "target_aware"},
        "hybrid": {"random", "task_agnostic", "target_aware"},
    }
    if selection_strategy not in allowed_strategies[mechanism]:
        errors.append(
            f"$.operator.selection_strategy: {selection_strategy!r} is not valid "
            f"for mechanism {mechanism!r}"
        )

    if mechanism in {"baseline", "distill"}:
        if index_groups or bit_allocations or factorizations:
            errors.append(
                f"$.operator: {mechanism} cannot specify structural indices, bit "
                "allocation, or factorizations"
            )
    elif mechanism in {"recycle", "prune"}:
        if not index_groups:
            errors.append(f"$.operator.structural_indices: required for {mechanism}")
        if bit_allocations:
            errors.append(f"$.operator.bit_allocation: must be empty for {mechanism}")
        if factorizations:
            errors.append(f"$.operator.factorizations: must be empty for {mechanism}")
    elif mechanism == "quantize":
        if index_groups:
            errors.append("$.operator.structural_indices: must be empty for quantize")
        if not bit_allocations:
            errors.append("$.operator.bit_allocation: required for quantize")
        if factorizations:
            errors.append("$.operator.factorizations: must be empty for quantize")
    elif mechanism == "factorize":
        if index_groups:
            errors.append("$.operator.structural_indices: must be empty for factorize")
        if bit_allocations:
            errors.append("$.operator.bit_allocation: must be empty for factorize")
        if not factorizations:
            errors.append("$.operator.factorizations: required for factorize")
    elif mechanism == "hybrid":
        if not bit_allocations:
            errors.append("$.operator.bit_allocation: required for hybrid")
        if bool(index_groups) == bool(factorizations):
            errors.append(
                "$.operator: hybrid requires exactly one non-quant architectural "
                "payload: structural_indices XOR factorizations"
            )

    expected_stage = {
        "baseline": "train",
        "recycle": "train",
        "prune": "compress",
        "quantize": "compress",
        "factorize": "compress",
        "hybrid": "compress",
    }.get(mechanism)
    # Distillation is valid in either lane: it can specialize a fixed-size
    # student or train a smaller student as a genuine compression operator.
    if expected_stage is not None and stage != expected_stage:
        errors.append(
            f"$.stage: mechanism {mechanism!r} requires stage {expected_stage!r}"
        )
    if mechanism == "distill" and not spec["teacher"]["enabled"]:
        errors.append("$.teacher.enabled: must be true for distill")
    return errors


def _optimizer_errors(spec: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    optimizer = spec["optimizer"]
    tokens = spec["tokens"]
    compute = spec["compute_budget"]
    _unique_values(
        (group["name"] for group in optimizer["parameter_groups"]),
        "$.optimizer.parameter_groups",
        errors,
    )
    roles = [group["role"] for group in optimizer["parameter_groups"]]

    nullable_fields = ("name", "epsilon", "gradient_clip", "warmup_fraction", "schedule")
    if optimizer["enabled"]:
        for field in nullable_fields:
            if optimizer[field] is None:
                errors.append(f"$.optimizer.{field}: required when optimizer is enabled")
        if not optimizer["parameter_groups"]:
            errors.append(
                "$.optimizer.parameter_groups: cannot be empty when optimizer is enabled"
            )
        if len(optimizer["betas"]) != 2:
            errors.append("$.optimizer.betas: must contain two values when enabled")
        if optimizer["total_steps"] <= 0:
            errors.append("$.optimizer.total_steps: must be positive when enabled")
        if tokens["optimizer_visible"] <= 0:
            errors.append("$.tokens.optimizer_visible: must be positive when optimizer is enabled")
        if compute["optimization_max_flops"] <= 0:
            errors.append(
                "$.compute_budget.optimization_max_flops: must be positive when "
                "optimizer is enabled"
            )
    else:
        for field in nullable_fields:
            if optimizer[field] is not None:
                errors.append(f"$.optimizer.{field}: must be null when optimizer is disabled")
        if optimizer["parameter_groups"]:
            errors.append("$.optimizer.parameter_groups: must be empty when disabled")
        if optimizer["betas"]:
            errors.append("$.optimizer.betas: must be empty when optimizer is disabled")
        if optimizer["total_steps"] != 0:
            errors.append("$.optimizer.total_steps: must be zero when optimizer is disabled")
        if tokens["optimizer_visible"] != 0:
            errors.append("$.tokens.optimizer_visible: must be zero when optimizer is disabled")
        if compute["optimization_max_flops"] != 0:
            errors.append(
                "$.compute_budget.optimization_max_flops: must be zero when "
                "optimizer is disabled"
            )
    if spec["stage"] == "train" and not optimizer["enabled"]:
        errors.append("$.optimizer.enabled: train stage requires an optimizer")

    freeze_mode = spec["training_protocol"]["freezing"]["mode"]
    if optimizer["enabled"]:
        if freeze_mode == "full_model" and any(
            role != "all_trainable" for role in roles
        ):
            errors.append(
                "$.optimizer.parameter_groups: full_model requires every group "
                "to have role 'all_trainable'"
            )
        elif freeze_mode == "side_only" and any(
            role != "side_branch" for role in roles
        ):
            errors.append(
                "$.optimizer.parameter_groups: side_only requires every group "
                "to have role 'side_branch'"
            )
        elif freeze_mode == "phased":
            if any(role not in {"side_branch", "backbone"} for role in roles):
                errors.append(
                    "$.optimizer.parameter_groups: phased permits only 'side_branch' "
                    "and 'backbone' roles"
                )
            for required_role in ("side_branch", "backbone"):
                if required_role not in roles:
                    errors.append(
                        "$.optimizer.parameter_groups: phased requires at least one "
                        f"group with role {required_role!r}"
                    )
    return errors


def _training_protocol_errors(spec: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    protocol = spec["training_protocol"]
    optimizer_enabled = spec["optimizer"]["enabled"]
    packing = protocol["packing"]
    loss = protocol["loss"]
    freezing = protocol["freezing"]

    batch_fields = (
        "microbatch_size",
        "gradient_accumulation_steps",
        "data_parallel_world_size",
        "effective_batch_size",
    )
    if optimizer_enabled:
        for field in ("training_dtype", "optimizer_state_dtype", "attention_backend"):
            if protocol[field] is None:
                errors.append(
                    f"$.training_protocol.{field}: required when optimizer is enabled"
                )
        for field in ("scheduler_step_unit", "final_partial_accumulation"):
            if protocol[field] is None:
                errors.append(
                    f"$.training_protocol.{field}: required when optimizer is enabled"
                )
        for field in batch_fields:
            if protocol[field] <= 0:
                errors.append(
                    f"$.training_protocol.{field}: must be positive when optimizer is enabled"
                )
        expected_batch = (
            protocol["microbatch_size"]
            * protocol["gradient_accumulation_steps"]
            * protocol["data_parallel_world_size"]
        )
        if protocol["effective_batch_size"] != expected_batch:
            errors.append(
                "$.training_protocol.effective_batch_size: must equal microbatch_size "
                "times gradient_accumulation_steps times data_parallel_world_size"
            )
        if loss["objective"] == "none" or loss["label_scope"] == "none":
            errors.append(
                "$.training_protocol.loss: optimizer-enabled runs require an explicit loss"
            )
        if loss["normalization"] == "none":
            errors.append(
                "$.training_protocol.loss.normalization: optimizer-enabled runs "
                "require an explicit normalization"
            )
        if loss["target_weight"] <= 0 or loss["support_weight"] <= 0:
            errors.append(
                "$.training_protocol.loss: target_weight and support_weight must be "
                "positive when optimizer is enabled"
            )
        if freezing["mode"] == "none":
            errors.append(
                "$.training_protocol.freezing.mode: optimizer-enabled runs cannot use 'none'"
            )
    else:
        for field in ("training_dtype", "optimizer_state_dtype", "attention_backend"):
            if protocol[field] is not None:
                errors.append(
                    f"$.training_protocol.{field}: must be null when optimizer is disabled"
                )
        for field in ("scheduler_step_unit", "final_partial_accumulation"):
            if protocol[field] is not None:
                errors.append(
                    f"$.training_protocol.{field}: must be null when optimizer is disabled"
                )
        for field in batch_fields:
            if protocol[field] != 0:
                errors.append(
                    f"$.training_protocol.{field}: must be zero when optimizer is disabled"
                )
        if protocol["gradient_checkpointing"]:
            errors.append(
                "$.training_protocol.gradient_checkpointing: must be false when "
                "optimizer is disabled"
            )
        if loss != {
            "objective": "none",
            "label_scope": "none",
            "normalization": "none",
            "target_weight": 0,
            "support_weight": 0,
            "kl_weight": 0,
            "anchor_model_sha256": None,
        }:
            errors.append(
                "$.training_protocol.loss: must be the explicit zero/none policy "
                "when optimizer is disabled"
            )
        if freezing != {
            "mode": "none",
            "trainable_parameters_sha256": None,
            "schedule_sha256": None,
        }:
            errors.append(
                "$.training_protocol.freezing: must be the explicit none policy "
                "when optimizer is disabled"
            )

    if packing["enabled"]:
        if packing["strategy"] == "none":
            errors.append(
                "$.training_protocol.packing.strategy: cannot be 'none' when packing is enabled"
            )
        minimum = packing["minimum_sequence_length"]
        maximum = packing["maximum_sequence_length"]
        if minimum is None or maximum is None:
            errors.append(
                "$.training_protocol.packing: sequence-length bounds are required "
                "when packing is enabled"
            )
        elif minimum > maximum:
            errors.append(
                "$.training_protocol.packing: minimum_sequence_length cannot exceed "
                "maximum_sequence_length"
            )
        if maximum != spec["tokens"]["maximum_sequence_length"]:
            errors.append(
                "$.training_protocol.packing.maximum_sequence_length: must equal "
                "$.tokens.maximum_sequence_length"
            )
    else:
        if packing["strategy"] != "none":
            errors.append(
                "$.training_protocol.packing.strategy: must be 'none' when packing is disabled"
            )
        if (
            packing["minimum_sequence_length"] is not None
            or packing["maximum_sequence_length"] is not None
        ):
            errors.append(
                "$.training_protocol.packing: sequence-length bounds must be null "
                "when packing is disabled"
            )

    if loss["objective"] == "causal_cross_entropy":
        if loss["kl_weight"] != 0 or loss["anchor_model_sha256"] is not None:
            errors.append(
                "$.training_protocol.loss: plain causal_cross_entropy requires zero "
                "KL weight and a null anchor"
            )
    elif loss["objective"] == "causal_cross_entropy_with_kl":
        if loss["kl_weight"] <= 0 or loss["anchor_model_sha256"] is None:
            errors.append(
                "$.training_protocol.loss: KL objective requires positive kl_weight "
                "and anchor_model_sha256"
            )

    freeze_mode = freezing["mode"]
    trainable_hash = freezing["trainable_parameters_sha256"]
    schedule_hash = freezing["schedule_sha256"]
    if freeze_mode in {"full_model", "none"}:
        if trainable_hash is not None or schedule_hash is not None:
            errors.append(
                f"$.training_protocol.freezing: {freeze_mode} requires null hashes"
            )
    elif freeze_mode == "side_only":
        if trainable_hash is None or schedule_hash is not None:
            errors.append(
                "$.training_protocol.freezing: side_only requires a trainable-parameter "
                "hash and a null schedule"
            )
    elif freeze_mode == "phased":
        if trainable_hash is None or schedule_hash is None:
            errors.append(
                "$.training_protocol.freezing: phased requires trainable-parameter "
                "and schedule hashes"
            )
    return errors


def _compute_errors(spec: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    compute = spec["compute_budget"]
    components = (
        compute["selection_max_flops"],
        compute["teacher_generation_max_flops"],
        compute["optimization_max_flops"],
        compute["compression_max_flops"],
        compute["export_max_flops"],
    )
    expected = math.fsum(components)
    if not math.isclose(
        compute["total_max_flops"],
        expected,
        rel_tol=1e-12,
        abs_tol=max(1e-6, abs(expected) * 1e-12),
    ):
        errors.append(
            "$.compute_budget.total_max_flops: must equal the sum of component "
            f"budgets ({expected})"
        )
    if spec["stage"] == "train" and compute["compression_max_flops"] != 0:
        errors.append(
            "$.compute_budget.compression_max_flops: must be zero for train stage"
        )
    if spec["stage"] == "compress" and compute["compression_max_flops"] <= 0:
        errors.append(
            "$.compute_budget.compression_max_flops: must be positive for compress stage"
        )
    return errors


def _export_errors(spec: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    source = spec["model"]
    tokenizer = spec["tokenizer"]
    export = spec["export"]
    _unique_values(
        export["runtime_compatibility"], "$.export.runtime_compatibility", errors
    )

    source_required_bits = source["physical_parameters"] * source["serialized_weight_bits"]
    source_available_bits = source["checkpoint_weight_bytes"] * 8
    if source_available_bits + max(1e-6, source_required_bits * 1e-12) < source_required_bits:
        errors.append(
            "$.model.checkpoint_weight_bytes: cannot encode physical_parameters "
            "at serialized_weight_bits"
        )
    if source["checkpoint_weight_bytes"] > source["checkpoint_bundle_bytes"]:
        errors.append(
            "$.model.checkpoint_weight_bytes: cannot exceed checkpoint_bundle_bytes"
        )
    planned_required_bits = (
        export["planned_physical_parameters"]
        * export["planned_average_weight_bits"]
    )
    planned_available_bits = export["maximum_weight_bytes"] * 8
    if planned_available_bits + max(1e-6, planned_required_bits * 1e-12) < planned_required_bits:
        errors.append(
            "$.export.maximum_weight_bytes: cannot encode "
            "planned_physical_parameters at planned_average_weight_bits"
        )
    if export["maximum_weight_bytes"] > export["maximum_bundle_bytes"]:
        errors.append(
            "$.export.maximum_weight_bytes: cannot exceed maximum_bundle_bytes"
        )
    if (
        export["planned_vocabulary_size"] != tokenizer["vocabulary_size"]
        and tokenizer["derived_vocabulary_mapping_sha256"] is None
    ):
        errors.append(
            "$.tokenizer.derived_vocabulary_mapping_sha256: required when the "
            "export changes vocabulary_size"
        )

    expected_intent = "fixed_size" if spec["stage"] == "train" else "compression"
    if export["intent"] != expected_intent:
        errors.append(
            f"$.export.intent: stage {spec['stage']!r} requires {expected_intent!r}"
        )

    dimensions = (
        (
            "planned_physical_parameters",
            export["planned_physical_parameters"],
            source["physical_parameters"],
        ),
        (
            "planned_average_weight_bits",
            export["planned_average_weight_bits"],
            source["serialized_weight_bits"],
        ),
        (
            "maximum_weight_bytes",
            export["maximum_weight_bytes"],
            source["checkpoint_weight_bytes"],
        ),
        (
            "maximum_bundle_bytes",
            export["maximum_bundle_bytes"],
            source["checkpoint_bundle_bytes"],
        ),
        (
            "planned_vocabulary_size",
            export["planned_vocabulary_size"],
            tokenizer["vocabulary_size"],
        ),
    )
    if export["intent"] == "fixed_size":
        for field, planned, original in dimensions:
            if planned != original:
                errors.append(
                    f"$.export.{field}: fixed_size intent must preserve the source value"
                )
    else:
        for field, planned, original in dimensions:
            if planned > original:
                errors.append(
                    f"$.export.{field}: compression intent cannot exceed the source value"
                )
        deployable_dimensions = dimensions[:4]
        if not any(
            planned < original for _, planned, original in deployable_dimensions
        ):
            errors.append(
                "$.export: compression intent must strictly reduce parameters, "
                "precision, weight bytes, or deployable bundle bytes; vocabulary "
                "reduction alone is not a demonstrated footprint reduction"
            )
    return errors


def _semantic_errors(spec: Mapping[str, Any]) -> list[str]:
    split_by_name, errors = _split_errors(spec)
    campaign = spec["campaign"]
    role = campaign["contrast_role"]
    if campaign["profile"] == "screening":
        if role is not None:
            errors.append(
                "$.campaign.contrast_role: screening runs must use null"
            )
    elif role not in ("reference", "comparison"):
        errors.append(
            "$.campaign.contrast_role: confirmation and runner_up runs must "
            "prospectively declare reference or comparison"
        )
    errors.extend(_mixture_errors(spec))
    errors.extend(_teacher_errors(spec, split_by_name))
    errors.extend(_operator_errors(spec, split_by_name))
    errors.extend(_optimizer_errors(spec))
    errors.extend(_training_protocol_errors(spec))
    errors.extend(_compute_errors(spec))
    errors.extend(_export_errors(spec))
    _unique_values(spec["checkpoint"]["tie_breakers"], "$.checkpoint.tie_breakers", errors)
    return errors


_CAMPAIGN_POLICY_ID = "cbds-plan-2026-07-14"
_CAMPAIGN_CREATED_AT = "2026-07-14T00:00:00+09:00"
_CAMPAIGN_SOURCE_PLAN_SHA256 = (
    "8f1aae8e663aad65c5e0b3ebc52a643b7fabca3c4fc6dd4af08578cc66746af0"
)
_CAMPAIGN_PROFILE_CONTRACTS: dict[str, dict[str, Any]] = {
    "screening": {
        "name": "screening",
        "optimizer_visible_tokens": 2_000_000,
        "target_fraction": 0.8,
        "support_fraction": 0.2,
        "required_seed_count": 2,
        "fresh_seed_count": 2,
        "pairing": "paired_across_arms",
        "fresh_from_profiles": [],
    },
    "confirmation": {
        "name": "confirmation",
        "optimizer_visible_tokens": 20_000_000,
        "target_fraction": 0.8,
        "support_fraction": 0.2,
        "required_seed_count": 5,
        "fresh_seed_count": 5,
        "pairing": "fresh_from_screening_and_paired_across_arms",
        "fresh_from_profiles": ["screening"],
    },
    "runner_up": {
        "name": "runner_up",
        "optimizer_visible_tokens": 20_000_000,
        "target_fraction": 0.8,
        "support_fraction": 0.2,
        "required_seed_count": 5,
        "fresh_seed_count": 5,
        "pairing": "fresh_runner_up_and_paired_across_arms",
        "fresh_from_profiles": ["screening", "confirmation"],
    },
}
_CAMPAIGN_OPTIMIZER_CONTRACT: dict[str, Any] = {
    "enabled_required": True,
    "name": "AdamW",
    "betas": [0.9, 0.95],
    "epsilon": 1e-8,
    "parameter_group_weight_decay": 0.1,
    "gradient_clip": 1.0,
    "warmup_fraction": 0.05,
    "schedule": "cosine",
}
_CAMPAIGN_TRAINING_CONTRACT: dict[str, Any] = {
    "training_dtype": "bf16",
    "optimizer_state_dtype": "fp32",
    "label_scope": "assistant_response_tokens",
    "loss_normalization": "actual_supervised_tokens_per_optimizer_update",
    "scheduler_step_unit": "optimizer_update",
    "final_partial_accumulation": "apply_with_actual_supervised_token_denominator",
    "packing_enabled": True,
    "minimum_packed_sequence_length": 1024,
    "maximum_packed_sequence_length": 2048,
}
_CAMPAIGN_LEARNING_RATE_GRIDS: dict[str, list[float]] = {
    "side_only": [1e-4, 3e-4, 1e-3],
    "full_model": [1e-5, 3e-5],
    # A phased run may contain both a side-branch group and a low-rate
    # preserved-backbone group.  The immutable schedule hash records when
    # each group is active; every declared rate must still come from one of
    # the two preregistered grids.
    "phased": [1e-5, 3e-5, 1e-4, 3e-4, 1e-3],
}


def _campaign_policy_errors(policy: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    if policy["policy_id"] != _CAMPAIGN_POLICY_ID:
        errors.append(f"$.policy_id: must equal {_CAMPAIGN_POLICY_ID!r} for schema 1.0.0")
    if policy["created_at"] != _CAMPAIGN_CREATED_AT:
        errors.append(
            f"$.created_at: must equal {_CAMPAIGN_CREATED_AT!r} for schema 1.0.0"
        )
    if policy["source_plan_sha256"] != _CAMPAIGN_SOURCE_PLAN_SHA256:
        errors.append(
            "$.source_plan_sha256: does not identify the PLAN.md used for campaign "
            "policy schema 1.0.0"
        )

    profiles = policy["profiles"]
    _unique_values((profile["name"] for profile in profiles), "$.profiles", errors)
    profile_by_name = {profile["name"]: profile for profile in profiles}
    if set(profile_by_name) != set(_CAMPAIGN_PROFILE_CONTRACTS):
        errors.append(
            "$.profiles: must contain exactly screening, confirmation, and runner_up"
        )
    for name, expected in _CAMPAIGN_PROFILE_CONTRACTS.items():
        if name in profile_by_name and profile_by_name[name] != expected:
            errors.append(f"$.profiles[{name!r}]: does not match the frozen PLAN contract")

    if policy["optimizer"] != _CAMPAIGN_OPTIMIZER_CONTRACT:
        errors.append("$.optimizer: does not match the frozen PLAN contract")
    if policy["training_protocol"] != _CAMPAIGN_TRAINING_CONTRACT:
        errors.append("$.training_protocol: does not match the frozen PLAN contract")
    if policy["learning_rate_grids"] != _CAMPAIGN_LEARNING_RATE_GRIDS:
        errors.append(
            "$.learning_rate_grids: does not match the frozen PLAN contract"
        )
    return errors


def validate_campaign_policy(
    policy: Mapping[str, Any],
    *,
    schema_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Validate and defensively copy the immutable PLAN-derived campaign policy."""

    if not isinstance(policy, Mapping):
        raise CampaignPolicyValidationError("$: campaign policy must be an object")
    candidate = copy.deepcopy(dict(policy))
    schema = _load_campaign_schema(schema_path)
    try:
        _validate_schema(candidate, schema)
    except ManifestValidationError as error:
        raise CampaignPolicyValidationError(error.errors) from error
    errors = _campaign_policy_errors(candidate)
    if errors:
        raise CampaignPolicyValidationError(errors)
    return candidate


def load_campaign_policy(
    path: str | os.PathLike[str],
    *,
    schema_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Strictly load JSON or YAML and validate a campaign policy."""

    try:
        loaded = load_document(path)
    except ManifestValidationError as error:
        raise CampaignPolicyValidationError(error.errors) from error
    if not isinstance(loaded, Mapping):
        raise CampaignPolicyValidationError("$: campaign policy must be an object")
    return validate_campaign_policy(loaded, schema_path=schema_path)


def campaign_policy_sha256(
    policy: Mapping[str, Any],
    *,
    schema_path: str | os.PathLike[str] | None = None,
) -> str:
    """Return the canonical content hash of a valid campaign policy."""

    return value_sha256(validate_campaign_policy(policy, schema_path=schema_path))


def _campaign_run_errors(
    spec: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> list[str]:
    errors: list[str] = []
    campaign = spec["campaign"]
    policy_digest = value_sha256(policy)
    if campaign["policy_schema_version"] != policy["schema_version"]:
        errors.append(
            "$.campaign.policy_schema_version: must match the campaign policy"
        )
    if campaign["policy_sha256"] != policy_digest:
        errors.append("$.campaign.policy_sha256: must match the canonical policy digest")

    profile_by_name = {profile["name"]: profile for profile in policy["profiles"]}
    profile_name = campaign["profile"]
    profile = profile_by_name.get(profile_name)
    if profile is None:  # pragma: no cover - frozen policy validator prevents this
        errors.append("$.campaign.profile: is absent from the campaign policy")
        return errors
    if campaign["declared_seed_count"] != profile["required_seed_count"]:
        errors.append(
            "$.campaign.declared_seed_count: must match the profile's required_seed_count"
        )
    if campaign["replicate_index"] >= profile["required_seed_count"]:
        errors.append(
            "$.campaign.replicate_index: must be less than the profile's "
            "required_seed_count"
        )

    tokens = spec["tokens"]
    if tokens["optimizer_visible"] != profile["optimizer_visible_tokens"]:
        errors.append(
            "$.tokens.optimizer_visible: must match the selected campaign profile"
        )
    target_fraction = math.fsum(
        entry["fraction"] for entry in spec["capability_mixture"]["target"]
    )
    support_fraction = math.fsum(
        entry["fraction"] for entry in spec["capability_mixture"]["support"]
    )
    if not math.isclose(
        target_fraction,
        profile["target_fraction"],
        rel_tol=0.0,
        abs_tol=1e-9,
    ):
        errors.append("$.capability_mixture.target: fraction violates campaign profile")
    if not math.isclose(
        support_fraction,
        profile["support_fraction"],
        rel_tol=0.0,
        abs_tol=1e-9,
    ):
        errors.append("$.capability_mixture.support: fraction violates campaign profile")

    optimizer_contract = policy["optimizer"]
    optimizer = spec["optimizer"]
    if optimizer["enabled"] is not optimizer_contract["enabled_required"]:
        errors.append("$.optimizer.enabled: violates campaign policy")
    for field in (
        "name",
        "betas",
        "epsilon",
        "gradient_clip",
        "warmup_fraction",
        "schedule",
    ):
        if optimizer[field] != optimizer_contract[field]:
            errors.append(f"$.optimizer.{field}: violates campaign policy")

    freeze_mode = spec["training_protocol"]["freezing"]["mode"]
    role_grid = {
        "all_trainable": "full_model",
        "backbone": "full_model",
        "side_branch": "side_only",
    }
    for index, parameter_group in enumerate(optimizer["parameter_groups"]):
        grid_name = role_grid[parameter_group["role"]]
        if parameter_group["learning_rate"] not in policy["learning_rate_grids"][grid_name]:
            errors.append(
                f"$.optimizer.parameter_groups[{index}].learning_rate: must be in "
                f"the campaign {grid_name!r} learning-rate grid for role "
                f"{parameter_group['role']!r}"
            )
        if (
            parameter_group["weight_decay"]
            != optimizer_contract["parameter_group_weight_decay"]
        ):
            errors.append(
                f"$.optimizer.parameter_groups[{index}].weight_decay: must match "
                "the campaign optimizer contract"
            )

    protocol_contract = policy["training_protocol"]
    protocol = spec["training_protocol"]
    if protocol["training_dtype"] != protocol_contract["training_dtype"]:
        errors.append("$.training_protocol.training_dtype: violates campaign policy")
    if protocol["optimizer_state_dtype"] != protocol_contract["optimizer_state_dtype"]:
        errors.append(
            "$.training_protocol.optimizer_state_dtype: violates campaign policy"
        )
    if protocol["loss"]["label_scope"] != protocol_contract["label_scope"]:
        errors.append("$.training_protocol.loss.label_scope: violates campaign policy")
    if protocol["loss"]["normalization"] != protocol_contract["loss_normalization"]:
        errors.append("$.training_protocol.loss.normalization: violates campaign policy")
    if protocol["scheduler_step_unit"] != protocol_contract["scheduler_step_unit"]:
        errors.append("$.training_protocol.scheduler_step_unit: violates campaign policy")
    if (
        protocol["final_partial_accumulation"]
        != protocol_contract["final_partial_accumulation"]
    ):
        errors.append(
            "$.training_protocol.final_partial_accumulation: violates campaign policy"
        )
    packing = protocol["packing"]
    for actual_field, policy_field in (
        ("enabled", "packing_enabled"),
        ("minimum_sequence_length", "minimum_packed_sequence_length"),
        ("maximum_sequence_length", "maximum_packed_sequence_length"),
    ):
        if packing[actual_field] != protocol_contract[policy_field]:
            errors.append(
                f"$.training_protocol.packing.{actual_field}: violates campaign policy"
            )
    return errors


def validate_run_spec_against_campaign(
    spec: Mapping[str, Any],
    policy: Mapping[str, Any],
    *,
    run_spec_schema_path: str | os.PathLike[str] | None = None,
    campaign_schema_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Validate a run spec and bind it to one immutable campaign profile."""

    validated_spec = validate_run_spec(spec, schema_path=run_spec_schema_path)
    validated_policy = validate_campaign_policy(
        policy,
        schema_path=campaign_schema_path,
    )
    errors = _campaign_run_errors(validated_spec, validated_policy)
    if errors:
        raise CampaignRunValidationError(errors)
    return validated_spec


def load_run_spec_against_campaign(
    run_spec_path: str | os.PathLike[str],
    campaign_policy_path: str | os.PathLike[str],
    *,
    run_spec_schema_path: str | os.PathLike[str] | None = None,
    campaign_schema_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Load and jointly validate a run spec and its pinned campaign policy."""

    spec = load_run_spec(run_spec_path, schema_path=run_spec_schema_path)
    policy = load_campaign_policy(
        campaign_policy_path,
        schema_path=campaign_schema_path,
    )
    return validate_run_spec_against_campaign(
        spec,
        policy,
        run_spec_schema_path=run_spec_schema_path,
        campaign_schema_path=campaign_schema_path,
    )


def validate_run_spec(
    spec: Mapping[str, Any],
    *,
    schema_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Validate one prospective run spec and return a defensive deep copy."""

    if not isinstance(spec, Mapping):
        raise RunSpecValidationError("$: run spec must be an object")
    candidate = copy.deepcopy(dict(spec))
    schema = _load_schema(schema_path)
    try:
        _validate_schema(candidate, schema)
    except ManifestValidationError as error:
        raise RunSpecValidationError(error.errors) from error
    errors = _semantic_errors(candidate)
    if errors:
        raise RunSpecValidationError(errors)
    return candidate


def load_run_spec(
    path: str | os.PathLike[str],
    *,
    schema_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Strictly load JSON or YAML and validate a prospective run spec."""

    try:
        loaded = load_document(path)
    except ManifestValidationError as error:
        raise RunSpecValidationError(error.errors) from error
    if not isinstance(loaded, Mapping):
        raise RunSpecValidationError("$: run spec must be an object")
    return validate_run_spec(loaded, schema_path=schema_path)


def run_spec_sha256(
    spec: Mapping[str, Any],
    *,
    schema_path: str | os.PathLike[str] | None = None,
) -> str:
    """Return the canonical content hash of a valid prospective run spec."""

    return value_sha256(validate_run_spec(spec, schema_path=schema_path))


def write_run_spec(
    path: str | os.PathLike[str],
    spec: Mapping[str, Any],
    *,
    schema_path: str | os.PathLike[str] | None = None,
) -> Path:
    """Validate and atomically write canonical JSON for one run spec."""

    validated = validate_run_spec(spec, schema_path=schema_path)
    return atomic_write_json(path, validated, canonical=True)


def _expect_binding_equal(
    errors: list[str],
    path: str,
    actual: Any,
    expected: Any,
) -> None:
    if actual != expected:
        errors.append(f"{path}: must exactly match the prospective run spec")


def _completed_binding_errors(
    spec: Mapping[str, Any],
    record: Mapping[str, Any],
) -> list[str]:
    """Return cross-document errors without conflating plans and measurements."""

    errors: list[str] = []
    spec_sha256 = value_sha256(spec)
    exact_root = {
        "run_id": spec["run_id"],
        "stage": spec["stage"],
        "run_spec_schema_version": spec["schema_version"],
        "run_spec_sha256": spec_sha256,
        "git_revision": spec["git_revision"],
    }
    for field, expected in exact_root.items():
        _expect_binding_equal(errors, f"$.{field}", record[field], expected)

    for field in (
        "repository",
        "revision",
        "inspection_report_sha256",
        "architecture",
        "physical_parameters",
    ):
        _expect_binding_equal(
            errors,
            f"$.model.{field}",
            record["model"][field],
            spec["model"][field],
        )

    for field in (
        "repository",
        "revision",
        "source_sha256",
        "derived_vocabulary_mapping_sha256",
    ):
        _expect_binding_equal(
            errors,
            f"$.tokenizer.{field}",
            record["tokenizer"][field],
            spec["tokenizer"][field],
        )
    _expect_binding_equal(
        errors,
        "$.tokenizer.vocabulary_size",
        record["tokenizer"]["vocabulary_size"],
        spec["export"]["planned_vocabulary_size"],
    )

    for field in ("manifest_sha256", "semantic_graph_sha256", "fixtures_sha256"):
        _expect_binding_equal(
            errors,
            f"$.data.{field}",
            record["data"][field],
            spec["data"][field],
        )
    expected_splits = [
        {
            "name": split["name"],
            "sha256": split["sha256"],
            "sealed": split["sealed"],
            "role": split["role"],
        }
        for split in spec["data"]["splits"]
    ]
    _expect_binding_equal(
        errors,
        "$.data.splits",
        record["data"]["splits"],
        expected_splits,
    )

    for field in ("container_image_digest", "verifier_revision", "verifier_sha256"):
        _expect_binding_equal(
            errors,
            f"$.execution.{field}",
            record["execution"][field],
            spec["execution"][field],
        )

    def capability_projection(entries: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "name": entry["name"],
                "fraction": entry["fraction"],
                "data_sha256": entry["data_sha256"],
            }
            for entry in entries
        ]

    for group in ("target", "support"):
        _expect_binding_equal(
            errors,
            f"$.capability_mixture.{group}",
            record["capability_mixture"][group],
            capability_projection(spec["capability_mixture"][group]),
        )

    for field in ("enabled", "repository", "revision"):
        _expect_binding_equal(
            errors,
            f"$.teacher.{field}",
            record["teacher"][field],
            spec["teacher"][field],
        )

    for field in (
        "mechanism",
        "family",
        "configuration_sha256",
        "dose",
        "selection_strategy",
        "selection_split",
        "structural_indices",
        "bit_allocation",
        "factorizations",
        "selection_manifest_sha256",
    ):
        _expect_binding_equal(
            errors,
            f"$.operator.{field}",
            record["operator"][field],
            spec["operator"][field],
        )

    _expect_binding_equal(errors, "$.optimizer", record["optimizer"], spec["optimizer"])
    _expect_binding_equal(
        errors,
        "$.training_protocol",
        record["training_protocol"],
        spec["training_protocol"],
    )
    _expect_binding_equal(errors, "$.seeds", record["seeds"], spec["seeds"])

    actual_tokens = record["tokens"]
    planned_tokens = spec["tokens"]
    for actual_name, planned_name in (
        ("optimizer_visible", "optimizer_visible"),
        ("teacher_derived", "teacher_derived"),
        ("selection_visible", "selection_visible"),
    ):
        _expect_binding_equal(
            errors,
            f"$.tokens.{actual_name}",
            actual_tokens[actual_name],
            planned_tokens[planned_name],
        )
    optimizer_enabled = spec["optimizer"]["enabled"]
    expected_actual_tokens = {
        "target": planned_tokens["target"] if optimizer_enabled else 0,
        "replay": planned_tokens["support"] if optimizer_enabled else 0,
    }
    for actual_name, expected in expected_actual_tokens.items():
        _expect_binding_equal(
            errors,
            f"$.tokens.{actual_name}",
            actual_tokens[actual_name],
            expected,
        )

    flop_budget_fields = (
        ("selection", "selection_max_flops"),
        ("teacher_generation", "teacher_generation_max_flops"),
        ("training", "optimization_max_flops"),
        ("compression", "compression_max_flops"),
        ("export", "export_max_flops"),
        ("total", "total_max_flops"),
    )
    for measured_name, budget_name in flop_budget_fields:
        if record["flops"][measured_name] > spec["compute_budget"][budget_name]:
            errors.append(
                f"$.flops.{measured_name}: measured FLOPs exceed prospective "
                f"$.compute_budget.{budget_name}"
            )

    for field in ("selection_split", "metric", "mode", "tie_breakers", "rule"):
        _expect_binding_equal(
            errors,
            f"$.checkpoint.{field}",
            record["checkpoint"][field],
            spec["checkpoint"][field],
        )

    for field in ("architecture", "format", "runtime_compatibility"):
        _expect_binding_equal(
            errors,
            f"$.export.{field}",
            record["export"][field],
            spec["export"][field],
        )
    _expect_binding_equal(
        errors,
        "$.export.physical_parameters",
        record["export"]["physical_parameters"],
        spec["export"]["planned_physical_parameters"],
    )
    _expect_binding_equal(
        errors,
        "$.export.average_weight_bits",
        record["export"]["average_weight_bits"],
        spec["export"]["planned_average_weight_bits"],
    )
    _expect_binding_equal(
        errors,
        "$.export.tokenizer_included",
        record["export"]["tokenizer_included"],
        spec["export"]["include_tokenizer"],
    )
    if record["export"]["weight_bytes"] > spec["export"]["maximum_weight_bytes"]:
        errors.append(
            "$.export.weight_bytes: measured bytes exceed prospective "
            "$.export.maximum_weight_bytes"
        )
    if record["export"]["bundle_bytes"] > spec["export"]["maximum_bundle_bytes"]:
        errors.append(
            "$.export.bundle_bytes: measured bytes exceed prospective "
            "$.export.maximum_bundle_bytes"
        )
    if (
        spec["export"]["intent"] == "fixed_size"
        and record["export"]["weight_bytes"]
        != spec["export"]["maximum_weight_bytes"]
    ):
        errors.append(
            "$.export.weight_bytes: fixed_size completion must exactly preserve "
            "the prospectively declared weight bytes"
        )
    if (
        spec["export"]["intent"] == "fixed_size"
        and record["export"]["bundle_bytes"]
        != spec["export"]["maximum_bundle_bytes"]
    ):
        errors.append(
            "$.export.bundle_bytes: fixed_size completion must exactly preserve "
            "the prospectively declared deployable bundle bytes"
        )
    return errors


def validate_completed_run(
    spec: Mapping[str, Any],
    record: Mapping[str, Any],
    *,
    run_spec_schema_path: str | os.PathLike[str] | None = None,
    experiment_schema_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Validate a completed record and prove that it is bound to *spec*.

    Prospective limits remain in the run spec.  The completed record contains
    measured accounting and artifact identities; this function compares the
    two documents without copying planned budgets into measured output.  It is
    a low-level binder and does not establish that the spec names a real
    campaign policy; campaign runs must use
    :func:`validate_completed_run_against_campaign`.
    """

    if not isinstance(record, Mapping):
        raise CompletedRunValidationError("$: completed record must be an object")
    validated_spec = validate_run_spec(spec, schema_path=run_spec_schema_path)
    try:
        validated_record = validate_experiment_manifest(
            record,
            schema_path=experiment_schema_path,
        )
    except ManifestValidationError as error:
        raise CompletedRunValidationError(error.errors) from error
    errors = _completed_binding_errors(validated_spec, validated_record)
    if errors:
        raise CompletedRunValidationError(errors)
    return validated_record


def load_completed_run(
    run_spec_path: str | os.PathLike[str],
    record_path: str | os.PathLike[str],
    *,
    run_spec_schema_path: str | os.PathLike[str] | None = None,
    experiment_schema_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Load and jointly validate a prospective spec and completed record.

    This low-level loader does not validate the spec's campaign-policy digest.
    Campaign runs must use :func:`load_completed_run_against_campaign`.
    """

    spec = load_run_spec(run_spec_path, schema_path=run_spec_schema_path)
    try:
        record = load_experiment_manifest(
            record_path,
            schema_path=experiment_schema_path,
        )
    except ManifestValidationError as error:
        raise CompletedRunValidationError(error.errors) from error
    return validate_completed_run(
        spec,
        record,
        run_spec_schema_path=run_spec_schema_path,
        experiment_schema_path=experiment_schema_path,
    )


def validate_completed_run_against_campaign(
    spec: Mapping[str, Any],
    policy: Mapping[str, Any],
    record: Mapping[str, Any],
    *,
    run_spec_schema_path: str | os.PathLike[str] | None = None,
    campaign_schema_path: str | os.PathLike[str] | None = None,
    experiment_schema_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Validate a completed record only after proving its campaign binding."""

    validated_spec = validate_run_spec_against_campaign(
        spec,
        policy,
        run_spec_schema_path=run_spec_schema_path,
        campaign_schema_path=campaign_schema_path,
    )
    return validate_completed_run(
        validated_spec,
        record,
        run_spec_schema_path=run_spec_schema_path,
        experiment_schema_path=experiment_schema_path,
    )


def load_completed_run_against_campaign(
    run_spec_path: str | os.PathLike[str],
    campaign_policy_path: str | os.PathLike[str],
    record_path: str | os.PathLike[str],
    *,
    run_spec_schema_path: str | os.PathLike[str] | None = None,
    campaign_schema_path: str | os.PathLike[str] | None = None,
    experiment_schema_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Load and jointly validate a policy, prospective spec, and completion."""

    spec = load_run_spec(run_spec_path, schema_path=run_spec_schema_path)
    policy = load_campaign_policy(
        campaign_policy_path,
        schema_path=campaign_schema_path,
    )
    try:
        record = load_experiment_manifest(
            record_path,
            schema_path=experiment_schema_path,
        )
    except ManifestValidationError as error:
        raise CompletedRunValidationError(error.errors) from error
    return validate_completed_run_against_campaign(
        spec,
        policy,
        record,
        run_spec_schema_path=run_spec_schema_path,
        campaign_schema_path=campaign_schema_path,
        experiment_schema_path=experiment_schema_path,
    )


__all__ = [
    "CAMPAIGN_POLICY_SCHEMA_VERSION",
    "CampaignPolicyValidationError",
    "CampaignRunValidationError",
    "CompletedRunValidationError",
    "RUN_SPEC_SCHEMA_VERSION",
    "RunSpecValidationError",
    "campaign_policy_sha256",
    "load_campaign_policy",
    "load_completed_run",
    "load_completed_run_against_campaign",
    "load_run_spec",
    "load_run_spec_against_campaign",
    "run_spec_sha256",
    "validate_campaign_policy",
    "validate_completed_run",
    "validate_completed_run_against_campaign",
    "validate_run_spec",
    "validate_run_spec_against_campaign",
    "write_run_spec",
]
