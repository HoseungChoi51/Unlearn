"""Bind one campaign completion to freshly reopened dense model evidence.

The completed experiment manifest records identities and measured accounting,
but its ordinary validator cannot prove that those fields describe model bytes
on disk.  This module creates a separate companion record that freshly
reinspects the source and exported Safetensors bundles, reconstructs the exact
Qwen2/Qwen3/Llama dense inventories, and reconciles previously saved runtime
reports with those fresh static observations.

The binding is deliberately narrow.  It supports exact floating-point dense
Safetensors exports and never authorizes training, model selection, scoring, or
a claim.  Runtime reports expose aggregate storage and a bounded forward pass;
they do not prove the exact loaded parameter-name/shape/alias graph, parameter
values, that training consumed the source bytes, or the declared nonzero count.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import copy
from hashlib import sha256
import json
import math
import os
import re
from typing import Any, Final

from .dense_checkpoint import inspect_dense_checkpoint
from .dense_checkpoint_binding import (
    DenseCheckpointRunBindingError,
    build_dense_checkpoint_run_binding,
    validate_dense_checkpoint_report_pair,
)
from .manifests import load_document, value_sha256
from .model_artifacts import ModelArtifactInspectionError, inspect_model_artifact
from .model_runtime import (
    ModelRuntimeProbeError,
    validate_runtime_report,
)
from .run_specs import (
    CampaignRunValidationError,
    CompletedRunValidationError,
    campaign_policy_sha256,
    load_campaign_policy,
    load_run_spec,
    run_spec_sha256,
    validate_completed_run_against_campaign,
    validate_run_spec_against_campaign,
)


COMPLETED_MODEL_EVIDENCE_SCHEMA_VERSION: Final[str] = "1.0.0"
COMPLETED_MODEL_EVIDENCE_RECORD_TYPE: Final[str] = (
    "cbds.completed-model-evidence-binding"
)
COMPLETED_MODEL_EVIDENCE_SCOPE: Final[str] = (
    "campaign-completion-to-fresh-static-and-passive-runtime-evidence-v1"
)

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_RUNTIME_DEVICE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:cpu|cuda:(?:0|[1-9][0-9]{0,5}))\Z"
)
_MAXIMUM_JSON_NODES: Final[int] = 250_000
_MAXIMUM_JSON_DEPTH: Final[int] = 32
_MAXIMUM_STRING_BYTES: Final[int] = 1_048_576
_MAXIMUM_CANONICAL_BYTES: Final[int] = 64 * 1024 * 1024
_DTYPE_CONTRACT: Final[dict[str, tuple[int, str]]] = {
    "BF16": (16, "torch.bfloat16"),
    "F16": (16, "torch.float16"),
    "F32": (32, "torch.float32"),
}
_ARCHITECTURE_CLASS_BY_FAMILY: Final[dict[str, str]] = {
    "qwen2": "Qwen2ForCausalLM",
    "qwen3": "Qwen3ForCausalLM",
    "llama": "LlamaForCausalLM",
}
_SUPPORTED_MECHANISMS: Final[frozenset[str]] = frozenset(
    {"baseline", "distill", "recycle", "prune"}
)
_VERIFICATION_FIELDS: Final[tuple[str, ...]] = (
    "campaign_completion_record_contract_validated",
    "prospective_source_dense_binding_validated",
    "source_artifact_freshly_reopened",
    "saved_source_runtime_aggregate_storage_report_reconciled",
    "export_artifact_freshly_reopened",
    "saved_export_runtime_aggregate_storage_report_reconciled",
    "completed_export_identity_and_accounting_reconciled",
    "completed_operator_export_architecture_reconciled",
    "static_fixed_size_or_broad_compression_dimension_rule_reconciled",
)
_LIMITATION_FIELDS: Final[tuple[str, ...]] = (
    "operator_payload_realization_verified",
    "runtime_parameter_graph_equivalence_verified",
    "loaded_parameter_values_verified",
    "training_consumed_source_bytes_verified",
    "nonzero_parameter_count_verified",
    "declared_runtime_compatibility_list_verified",
    "runtime_observations_independently_attested",
    "report_signatures_verified",
    "claim_eligible_data_verified",
)
_AUTHORIZATION_FIELDS: Final[tuple[str, ...]] = (
    "training_authorized",
    "compression_authorized",
    "model_selection_eligible",
    "scored_evaluation_eligible",
    "claim_pipeline_eligible",
    "claim_authorized",
)
_MODEL_PROJECTION_FIELDS: Final[set[str]] = {
    "generic_inspection_report_sha256",
    "dense_checkpoint_report_sha256",
    "runtime_report_sha256",
    "weight_set_sha256",
    "bundle_manifest_sha256",
    "tokenizer_set_sha256",
    "tensor_layout_sha256",
    "tensor_inventory_sha256",
    "runtime_prompt_sha256",
    "runtime_implementation_sha256",
    "runtime_dependency_versions_sha256",
    "runtime_device_placement_sha256",
    "runtime_requested_device",
    "family",
    "architecture_class",
    "parameter_dtype",
    "physical_parameters",
    "serialized_weight_bits",
    "weight_bytes",
    "bundle_bytes",
    "embedding_vocabulary_size",
    "observed_token_id_count",
    "runtime_parameter_bytes",
    "runtime_logits_vocabulary_size",
}
_FIXED_SIZE_FIELDS: Final[tuple[str, ...]] = (
    "family",
    "architecture_class",
    "parameter_dtype",
    "physical_parameters",
    "serialized_weight_bits",
    "weight_bytes",
    "bundle_bytes",
    "embedding_vocabulary_size",
    "observed_token_id_count",
    "tokenizer_set_sha256",
    "tensor_layout_sha256",
    "tensor_inventory_sha256",
)
_BUNDLE_DERIVED_MODEL_FIELDS: Final[tuple[str, ...]] = (
    "generic_inspection_report_sha256",
    "dense_checkpoint_report_sha256",
    "weight_set_sha256",
    "tokenizer_set_sha256",
    "tensor_layout_sha256",
    "tensor_inventory_sha256",
    "family",
    "architecture_class",
    "parameter_dtype",
    "physical_parameters",
    "serialized_weight_bits",
    "weight_bytes",
    "bundle_bytes",
    "embedding_vocabulary_size",
    "observed_token_id_count",
)
_RUNTIME_REPORT_DERIVED_MODEL_FIELDS: Final[tuple[str, ...]] = (
    "runtime_prompt_sha256",
    "runtime_implementation_sha256",
    "runtime_dependency_versions_sha256",
    "runtime_device_placement_sha256",
    "runtime_requested_device",
    "runtime_parameter_bytes",
    "runtime_logits_vocabulary_size",
)


class CompletedModelEvidenceError(ValueError):
    """Raised when completion and freshly reopened model evidence disagree."""

    def __init__(self, errors: str | Iterable[str]) -> None:
        normalized = (errors,) if isinstance(errors, str) else tuple(map(str, errors))
        if not normalized:
            normalized = ("completed model evidence binding failed",)
        self.errors = normalized
        super().__init__(
            "completed model evidence binding failed: " + "; ".join(normalized)
        )


def _passive_json_copy(value: object, *, path: str = "$") -> object:
    nodes = 0

    def visit(item: object, item_path: str, depth: int) -> object:
        nonlocal nodes
        nodes += 1
        if nodes > _MAXIMUM_JSON_NODES:
            raise CompletedModelEvidenceError("input exceeds its JSON node limit")
        if depth > _MAXIMUM_JSON_DEPTH:
            raise CompletedModelEvidenceError("input exceeds its JSON depth limit")
        if item is None or type(item) in {int, bool}:
            return item
        if type(item) is str:
            if len(item.encode("utf-8", errors="strict")) > _MAXIMUM_STRING_BYTES:
                raise CompletedModelEvidenceError(
                    f"{item_path}: exceeds the string byte limit"
                )
            return item
        if type(item) is float:
            if not math.isfinite(item):
                raise CompletedModelEvidenceError(f"{item_path}: is not finite JSON")
            return item
        if type(item) is list:
            return [
                visit(child, f"{item_path}[{index}]", depth + 1)
                for index, child in enumerate(item)
            ]
        if type(item) is dict:
            copied: dict[str, object] = {}
            for key, child in item.items():
                if type(key) is not str:
                    raise CompletedModelEvidenceError(
                        f"{item_path}: contains a non-exact string key"
                    )
                copied[key] = visit(child, f"{item_path}.{key}", depth + 1)
            return copied
        raise CompletedModelEvidenceError(
            f"{item_path}: contains an active or non-JSON value"
        )

    return visit(value, path, 0)


def _canonical_json_bytes(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise CompletedModelEvidenceError(
            "binding value is not canonical finite JSON"
        ) from exc
    if len(encoded) > _MAXIMUM_CANONICAL_BYTES:
        raise CompletedModelEvidenceError(
            "binding value exceeds its canonical byte limit"
        )
    return encoded


def _value_sha256(value: object) -> str:
    return sha256(_canonical_json_bytes(value)).hexdigest()


def _require_sha256(value: object, path: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise CompletedModelEvidenceError(
            f"{path}: must be a lowercase SHA-256 digest"
        )
    return value


def _exact_dict(value: object, fields: set[str], path: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != fields:
        raise CompletedModelEvidenceError(f"{path}: fields are invalid")
    return value


def _fresh_model_projection(
    artifact_dir: str | os.PathLike[str],
    runtime_report: Mapping[str, object],
    *,
    label: str,
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    try:
        inspection_report = inspect_model_artifact(artifact_dir)
        dense_report = inspect_dense_checkpoint(
            artifact_dir,
            expected_inspection_report_sha256=inspection_report["report_sha256"],
        )
        pair = validate_dense_checkpoint_report_pair(
            inspection_report=inspection_report,
            dense_checkpoint_report=dense_report,
        )
        runtime = validate_runtime_report(runtime_report)
    except (
        DenseCheckpointRunBindingError,
        ModelArtifactInspectionError,
        ModelRuntimeProbeError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        raise CompletedModelEvidenceError(f"{label}: {exc}") from exc

    inspection = pair["inspection_projection"]
    dense = pair["dense_checkpoint_report"]
    if type(inspection) is not dict or type(dense) is not dict:
        raise CompletedModelEvidenceError(f"{label}: validated report pair disappeared")
    architecture = dense["architecture"]
    inventory = dense["tensor_inventory"]
    if type(architecture) is not dict or type(inventory) is not dict:
        raise CompletedModelEvidenceError(f"{label}: dense evidence disappeared")
    static = runtime["static_inspection"]
    parameters = runtime["parameters"]
    forward = runtime["forward"]
    qualification = runtime["claim_qualification"]
    classes = runtime["runtime_classes"]
    prompt = runtime["prompt"]
    placement = runtime["device_placement"]
    implementation = runtime["implementation"]
    dependencies = runtime["dependency_versions"]
    if any(
        type(value) is not dict
        for value in (
            static,
            parameters,
            forward,
            qualification,
            classes,
            prompt,
            placement,
            implementation,
            dependencies,
        )
    ):
        raise CompletedModelEvidenceError(f"{label}: runtime evidence disappeared")
    errors: list[str] = []
    expected_static = {
        "inspector_version": inspection_report["inspector_version"],
        "report_sha256": inspection["report_sha256"],
        "bundle_manifest_sha256": inspection["bundle_manifest_sha256"],
        "weight_set_sha256": inspection["weight_set_sha256"],
        "architecture_classification": "dense_consistent",
    }
    for name, expected in expected_static.items():
        if static[name] != expected:
            errors.append(
                f"{label}.runtime.static_inspection.{name}: must match fresh inspection"
            )
    physical_parameters = inventory["physical_parameter_count"]
    if parameters["physical_elements"] != physical_parameters:
        errors.append(
            f"{label}.runtime.parameters.physical_elements: must match dense inventory"
        )
    if parameters["physical_bytes"] != inspection["safetensors_payload_bytes"]:
        errors.append(
            f"{label}.runtime.parameters.physical_bytes: must match fresh payload bytes"
        )
    if (
        parameters["trainable_elements"] != physical_parameters
        or parameters["trainable_bytes"] != parameters["physical_bytes"]
    ):
        errors.append(
            f"{label}.runtime.parameters: exact dense load must expose all parameters trainable"
        )
    expected_runtime_names = inventory["tensor_count"] + (
        1 if architecture["tie_word_embeddings"] else 0
    )
    if (
        parameters["named_tensor_entries"] != expected_runtime_names
        or parameters["unique_physical_spans"] != inventory["tensor_count"]
        or parameters["storage_allocations_referenced"]
        != inventory["tensor_count"]
        or parameters["deduplicated_alias_entries"]
        != (1 if architecture["tie_word_embeddings"] else 0)
    ):
        errors.append(
            f"{label}.runtime.parameters: aggregate tensor/span counts must match "
            "the exact dense inventory and tied-head contract"
        )
    parameter_dtype = inventory["parameter_dtype"]
    dtype_contract = _DTYPE_CONTRACT.get(parameter_dtype)
    if dtype_contract is None:
        errors.append(f"{label}.dense.parameter_dtype: is unsupported")
        bits, runtime_dtype = (0, "")
    else:
        bits, runtime_dtype = dtype_contract
    if parameters["by_dtype"] != [
        {
            "dtype": runtime_dtype,
            "physical_elements": physical_parameters,
            "physical_bytes": parameters["physical_bytes"],
            "trainable_elements": physical_parameters,
            "trainable_bytes": parameters["physical_bytes"],
        }
    ]:
        errors.append(
            f"{label}.runtime.parameters.by_dtype: must match the exact dense dtype"
        )
    if forward["logits_dtype"] != runtime_dtype:
        errors.append(
            f"{label}.runtime.forward.logits_dtype: must match the exact dense dtype"
        )
    if forward["logits_shape"][2] != architecture["vocab_size"]:
        errors.append(
            f"{label}.runtime.forward.logits_shape: vocabulary must match dense config"
        )
    loaded_model_class = classes["loaded_model_class"]
    if (
        type(loaded_model_class) is not str
        or loaded_model_class.rsplit(".", 1)[-1]
        != architecture["architecture_class"]
    ):
        errors.append(
            f"{label}.runtime.runtime_classes.loaded_model_class: must match dense architecture"
        )
    if qualification["sub_billion_dense_runtime_qualified"] is not True:
        errors.append(f"{label}.runtime: did not pass the sub-billion dense runtime gate")
    if errors:
        raise CompletedModelEvidenceError(errors)
    projection = {
        "generic_inspection_report_sha256": inspection["report_sha256"],
        "dense_checkpoint_report_sha256": dense["report_sha256"],
        "runtime_report_sha256": runtime["report_sha256"],
        "weight_set_sha256": inspection["weight_set_sha256"],
        "bundle_manifest_sha256": inspection["bundle_manifest_sha256"],
        "tokenizer_set_sha256": inspection["tokenizer_set_sha256"],
        "tensor_layout_sha256": inspection["tensor_layout_sha256"],
        "tensor_inventory_sha256": inventory["inventory_sha256"],
        "runtime_prompt_sha256": prompt["prompt_sha256"],
        "runtime_implementation_sha256": _value_sha256(implementation),
        "runtime_dependency_versions_sha256": _value_sha256(dependencies),
        "runtime_device_placement_sha256": _value_sha256(placement),
        "runtime_requested_device": placement["requested"],
        "family": architecture["family"],
        "architecture_class": architecture["architecture_class"],
        "parameter_dtype": parameter_dtype,
        "physical_parameters": physical_parameters,
        "serialized_weight_bits": bits,
        "weight_bytes": inspection["safetensors_payload_bytes"],
        "bundle_bytes": inspection["bundle_bytes"],
        "embedding_vocabulary_size": architecture["vocab_size"],
        "observed_token_id_count": inspection["tokenizer_vocab_size"],
        "runtime_parameter_bytes": parameters["physical_bytes"],
        "runtime_logits_vocabulary_size": forward["logits_shape"][2],
    }
    return inspection_report, dense_report, projection


def _fixed_size_projection(model: Mapping[str, object]) -> dict[str, object]:
    return {name: copy.deepcopy(model[name]) for name in _FIXED_SIZE_FIELDS}


def _prune_export_architecture_errors(
    spec: Mapping[str, Any],
    source_dense: Mapping[str, object],
    export_dense: Mapping[str, object],
) -> list[str]:
    """Check the architecture delta implied by a supported prune payload.

    This proves only that the reopened export has the dimensions implied by
    the prospective structural payload.  Static tensors cannot prove which
    source units supplied the exported values, so the companion record keeps
    ``operator_payload_realization_verified`` false.
    """

    source_architecture = source_dense.get("architecture")
    export_architecture = export_dense.get("architecture")
    if type(source_architecture) is not dict or type(export_architecture) is not dict:
        return ["prune architecture evidence disappeared"]
    groups = spec["operator"]["structural_indices"]
    components = {group["component"] for group in groups}
    if len(components) != 1:
        return ["prune payload must use exactly one structural component"]
    component = next(iter(components))
    expected = copy.deepcopy(source_architecture)
    if component == "layer":
        selected = set(groups[0]["indices"])
        expected["num_hidden_layers"] -= len(selected)
    elif component == "ffn_channel":
        removed_per_layer = {len(set(group["indices"])) for group in groups}
        if len(removed_per_layer) != 1:
            return ["FFN prune payload has inconsistent per-layer widths"]
        expected["intermediate_size"] -= next(iter(removed_per_layer))
    elif component == "attention_head":
        removed_per_layer = {len(set(group["indices"])) for group in groups}
        if len(removed_per_layer) != 1:
            return ["attention prune payload has inconsistent per-layer widths"]
        removed_queries = next(iter(removed_per_layer))
        group_size = source_architecture["query_heads_per_key_value_head"]
        if type(group_size) is not int or group_size <= 0:
            return ["source GQA grouping evidence is invalid"]
        expected["num_attention_heads"] -= removed_queries
        expected["num_key_value_heads"] -= removed_queries // group_size
    elif component == "embedding_token":
        return [
            "completed embedding-token pruning requires derived vocabulary-map "
            "replay and is outside this binding scope"
        ]
    else:
        return [
            f"completed {component!r} pruning has no exact export architecture contract"
        ]
    if expected != export_architecture:
        return [
            "fresh export architecture does not realize the prospective "
            f"{component} pruning dimensions"
        ]
    source_inventory = source_dense.get("tensor_inventory")
    export_inventory = export_dense.get("tensor_inventory")
    if type(source_inventory) is not dict or type(export_inventory) is not dict:
        return ["prune tensor inventory evidence disappeared"]
    if source_inventory["parameter_dtype"] != export_inventory["parameter_dtype"]:
        return ["prune export changed parameter dtype without a quantization payload"]
    return []


def compute_completed_model_evidence_binding_sha256(
    record: Mapping[str, object],
) -> str:
    """Hash one exact passive binding after excluding only its self-digest."""

    if type(record) is not dict:
        raise CompletedModelEvidenceError("binding record must be an exact dictionary")
    copied = _passive_json_copy(record)
    if type(copied) is not dict:  # pragma: no cover - exact type established above
        raise CompletedModelEvidenceError("binding record copy is invalid")
    copied.pop("binding_sha256", None)
    return sha256(
        b"cbds.completed-model-evidence-binding.v1\0"
        + _canonical_json_bytes(copied)
    ).hexdigest()


def build_completed_model_evidence_binding(
    spec: Mapping[str, Any],
    policy: Mapping[str, Any],
    completed_record: Mapping[str, Any],
    *,
    source_artifact_dir: str | os.PathLike[str],
    export_artifact_dir: str | os.PathLike[str],
    source_runtime_report: Mapping[str, object],
    export_runtime_report: Mapping[str, object],
) -> dict[str, object]:
    """Freshly reopen and bind source/export evidence to one campaign completion."""

    passive_spec = _passive_json_copy(spec, path="run_spec")
    passive_policy = _passive_json_copy(policy, path="campaign_policy")
    passive_completed = _passive_json_copy(completed_record, path="completed_record")
    passive_source_runtime = _passive_json_copy(
        source_runtime_report, path="source_runtime_report"
    )
    passive_export_runtime = _passive_json_copy(
        export_runtime_report, path="export_runtime_report"
    )
    values = (
        passive_spec,
        passive_policy,
        passive_completed,
        passive_source_runtime,
        passive_export_runtime,
    )
    if any(type(value) is not dict for value in values):
        raise CompletedModelEvidenceError("every document input must be an exact object")
    try:
        validated_spec = validate_run_spec_against_campaign(
            passive_spec, passive_policy
        )
        validated_completed = validate_completed_run_against_campaign(
            validated_spec, passive_policy, passive_completed
        )
    except (CampaignRunValidationError, CompletedRunValidationError) as exc:
        errors = getattr(exc, "errors", (str(exc),))
        raise CompletedModelEvidenceError(errors) from exc
    mechanism = validated_spec["operator"]["mechanism"]
    if mechanism not in _SUPPORTED_MECHANISMS:
        raise CompletedModelEvidenceError(
            "operator mechanism is outside the exact floating dense export scope"
        )
    if validated_completed["export"]["format"] != "safetensors":
        raise CompletedModelEvidenceError(
            "completed export format must be exact flat Safetensors"
        )

    source_inspection, source_dense, source_projection = _fresh_model_projection(
        source_artifact_dir,
        passive_source_runtime,
        label="source",
    )
    try:
        prospective_binding = build_dense_checkpoint_run_binding(
            validated_spec,
            inspection_report=source_inspection,
            dense_checkpoint_report=source_dense,
        )
    except DenseCheckpointRunBindingError as exc:
        raise CompletedModelEvidenceError(
            tuple(f"source prospective binding: {error}" for error in exc.errors)
        ) from exc
    export_inspection, export_dense, export_projection = _fresh_model_projection(
        export_artifact_dir,
        passive_export_runtime,
        label="export",
    )

    exported = validated_completed["export"]
    export_expected = {
        "architecture": "dense",
        "format": "safetensors",
        "artifact_sha256": export_projection["weight_set_sha256"],
        "bundle_sha256": export_projection["bundle_manifest_sha256"],
        "tokenizer_sha256": export_projection["tokenizer_set_sha256"],
        "inspection_report_sha256": export_projection[
            "dense_checkpoint_report_sha256"
        ],
        "physical_parameters": export_projection["physical_parameters"],
        "active_parameters": export_projection["physical_parameters"],
        "average_weight_bits": export_projection["serialized_weight_bits"],
        "weight_bytes": export_projection["weight_bytes"],
        "bundle_bytes": export_projection["bundle_bytes"],
        "tokenizer_included": True,
    }
    errors: list[str] = []
    for name, expected in export_expected.items():
        if exported[name] != expected:
            errors.append(
                f"completed_record.export.{name}: must match freshly reopened export evidence"
            )
    if (
        export_projection["embedding_vocabulary_size"]
        != validated_spec["export"]["planned_vocabulary_size"]
    ):
        errors.append(
            "fresh export embedding vocabulary must equal "
            "run_spec.export.planned_vocabulary_size"
        )
    intent = validated_spec["export"]["intent"]
    fixed_size_preserved = _fixed_size_projection(
        source_projection
    ) == _fixed_size_projection(export_projection)
    if intent == "fixed_size" and not fixed_size_preserved:
        errors.append(
            "fixed-size completion changed an architecture, precision, layout, "
            "tokenizer, parameter-count, or byte-count field"
        )
    if intent == "compression" and not any(
        export_projection[name] < source_projection[name]
        for name in (
            "physical_parameters",
            "serialized_weight_bits",
            "weight_bytes",
            "bundle_bytes",
            "embedding_vocabulary_size",
        )
    ):
        errors.append(
            "compression completion must improve at least one physical deployment dimension"
        )
    if mechanism == "prune":
        errors.extend(
            _prune_export_architecture_errors(
                validated_spec,
                source_dense,
                export_dense,
            )
        )
        if (
            source_projection["tokenizer_set_sha256"]
            != export_projection["tokenizer_set_sha256"]
            or source_projection["observed_token_id_count"]
            != export_projection["observed_token_id_count"]
        ):
            errors.append(
                "supported structural pruning must preserve the exact tokenizer "
                "and observed token-ID range"
            )
    if errors:
        raise CompletedModelEvidenceError(errors)

    try:
        final_source_inspection = inspect_model_artifact(source_artifact_dir)
        final_export_inspection = inspect_model_artifact(export_artifact_dir)
    except (ModelArtifactInspectionError, OSError, TypeError, ValueError) as exc:
        raise CompletedModelEvidenceError(
            "final source/export artifact stability inspection failed"
        ) from exc
    if (
        final_source_inspection != source_inspection
        or final_export_inspection != export_inspection
    ):
        raise CompletedModelEvidenceError(
            "source or export artifact changed during completed-model binding"
        )

    completion_projection = {
        "stage": validated_completed["stage"],
        "mechanism": mechanism,
        "export_intent": intent,
        "export_format": exported["format"],
        "active_parameters": exported["active_parameters"],
        "declared_nonzero_parameters": exported["nonzero_parameters"],
        "runtime_compatibility_sha256": _value_sha256(
            exported["runtime_compatibility"]
        ),
        "fixed_size_layout_fields_preserved": fixed_size_preserved,
    }
    record: dict[str, object] = {
        "schema_version": COMPLETED_MODEL_EVIDENCE_SCHEMA_VERSION,
        "record_type": COMPLETED_MODEL_EVIDENCE_RECORD_TYPE,
        "evidence_scope": COMPLETED_MODEL_EVIDENCE_SCOPE,
        "identities": {
            "campaign_policy_sha256": campaign_policy_sha256(passive_policy),
            "run_spec_sha256": run_spec_sha256(validated_spec),
            "completed_record_sha256": value_sha256(validated_completed),
            "prospective_dense_binding_sha256": prospective_binding[
                "binding_sha256"
            ],
        },
        "source": source_projection,
        "export": export_projection,
        "completion": completion_projection,
        "verification": {name: True for name in _VERIFICATION_FIELDS},
        "limitations": {name: False for name in _LIMITATION_FIELDS},
        "authorizations": {name: False for name in _AUTHORIZATION_FIELDS},
    }
    record["binding_sha256"] = compute_completed_model_evidence_binding_sha256(
        record
    )
    _validate_binding_record(record)
    copied = _passive_json_copy(record)
    if type(copied) is not dict:  # pragma: no cover - exact type established above
        raise CompletedModelEvidenceError("completed binding copy is invalid")
    return copied


def _validate_model_projection(value: object, path: str) -> dict[str, object]:
    model = _exact_dict(value, _MODEL_PROJECTION_FIELDS, path)
    digest_fields = (
        "generic_inspection_report_sha256",
        "dense_checkpoint_report_sha256",
        "runtime_report_sha256",
        "weight_set_sha256",
        "bundle_manifest_sha256",
        "tokenizer_set_sha256",
        "tensor_layout_sha256",
        "tensor_inventory_sha256",
        "runtime_prompt_sha256",
        "runtime_implementation_sha256",
        "runtime_dependency_versions_sha256",
        "runtime_device_placement_sha256",
    )
    for name in digest_fields:
        _require_sha256(model[name], f"{path}.{name}")
    if model["family"] not in _ARCHITECTURE_CLASS_BY_FAMILY:
        raise CompletedModelEvidenceError(f"{path}.family is invalid")
    if (
        type(model["architecture_class"]) is not str
        or model["architecture_class"]
        != _ARCHITECTURE_CLASS_BY_FAMILY[model["family"]]
    ):
        raise CompletedModelEvidenceError(f"{path}.architecture_class is invalid")
    dtype = model["parameter_dtype"]
    if dtype not in _DTYPE_CONTRACT:
        raise CompletedModelEvidenceError(f"{path}.parameter_dtype is invalid")
    expected_bits = _DTYPE_CONTRACT[dtype][0]
    integer_fields = (
        "physical_parameters",
        "weight_bytes",
        "bundle_bytes",
        "embedding_vocabulary_size",
        "observed_token_id_count",
        "runtime_parameter_bytes",
        "runtime_logits_vocabulary_size",
    )
    for name in integer_fields:
        if type(model[name]) is not int or model[name] <= 0:
            raise CompletedModelEvidenceError(f"{path}.{name} is invalid")
    if (
        model["physical_parameters"] >= 1_000_000_000
        or type(model["serialized_weight_bits"]) is not int
        or model["serialized_weight_bits"] != expected_bits
        or model["weight_bytes"] * 8
        != model["physical_parameters"] * expected_bits
        or model["runtime_parameter_bytes"] != model["weight_bytes"]
        or model["bundle_bytes"] < model["weight_bytes"]
        or model["observed_token_id_count"] > model["embedding_vocabulary_size"]
        or model["runtime_logits_vocabulary_size"]
        != model["embedding_vocabulary_size"]
    ):
        raise CompletedModelEvidenceError(f"{path} accounting is inconsistent")
    if (
        type(model["runtime_requested_device"]) is not str
        or _RUNTIME_DEVICE_RE.fullmatch(model["runtime_requested_device"]) is None
    ):
        raise CompletedModelEvidenceError(
            f"{path}.runtime_requested_device is invalid"
        )
    return model


def _validate_binding_record(record: object) -> None:
    top = _exact_dict(
        record,
        {
            "schema_version",
            "record_type",
            "evidence_scope",
            "identities",
            "source",
            "export",
            "completion",
            "verification",
            "limitations",
            "authorizations",
            "binding_sha256",
        },
        "$",
    )
    constants = {
        "schema_version": COMPLETED_MODEL_EVIDENCE_SCHEMA_VERSION,
        "record_type": COMPLETED_MODEL_EVIDENCE_RECORD_TYPE,
        "evidence_scope": COMPLETED_MODEL_EVIDENCE_SCOPE,
    }
    for name, expected in constants.items():
        if top[name] != expected or type(top[name]) is not str:
            raise CompletedModelEvidenceError(f"$.{name} is invalid")
    identities = _exact_dict(
        top["identities"],
        {
            "campaign_policy_sha256",
            "run_spec_sha256",
            "completed_record_sha256",
            "prospective_dense_binding_sha256",
        },
        "$.identities",
    )
    for name, value in identities.items():
        _require_sha256(value, f"$.identities.{name}")
    source = _validate_model_projection(top["source"], "$.source")
    exported = _validate_model_projection(top["export"], "$.export")
    bundle_equal = (
        source["bundle_manifest_sha256"]
        == exported["bundle_manifest_sha256"]
    )
    generic_report_equal = (
        source["generic_inspection_report_sha256"]
        == exported["generic_inspection_report_sha256"]
    )
    dense_report_equal = (
        source["dense_checkpoint_report_sha256"]
        == exported["dense_checkpoint_report_sha256"]
    )
    runtime_report_equal = (
        source["runtime_report_sha256"] == exported["runtime_report_sha256"]
    )
    if bundle_equal and any(
        source[name] != exported[name]
        for name in _BUNDLE_DERIVED_MODEL_FIELDS
    ):
        raise CompletedModelEvidenceError(
            "$.source and $.export claim one bundle identity with inconsistent "
            "static projections"
        )
    if generic_report_equal != bundle_equal or dense_report_equal != bundle_equal:
        raise CompletedModelEvidenceError(
            "$.source and $.export generic/dense report identity equality must "
            "match bundle identity equality"
        )
    if runtime_report_equal and (
        not bundle_equal
        or any(
            source[name] != exported[name]
            for name in _RUNTIME_REPORT_DERIVED_MODEL_FIELDS
        )
    ):
        raise CompletedModelEvidenceError(
            "$.source and $.export claim one runtime-report identity with "
            "inconsistent projections"
        )
    completion = _exact_dict(
        top["completion"],
        {
            "stage",
            "mechanism",
            "export_intent",
            "export_format",
            "active_parameters",
            "declared_nonzero_parameters",
            "runtime_compatibility_sha256",
            "fixed_size_layout_fields_preserved",
        },
        "$.completion",
    )
    if completion["stage"] not in {"train", "compress"}:
        raise CompletedModelEvidenceError("$.completion.stage is invalid")
    if completion["mechanism"] not in _SUPPORTED_MECHANISMS:
        raise CompletedModelEvidenceError("$.completion.mechanism is invalid")
    if completion["export_intent"] not in {"fixed_size", "compression"}:
        raise CompletedModelEvidenceError("$.completion.export_intent is invalid")
    expected_intent = (
        "fixed_size" if completion["stage"] == "train" else "compression"
    )
    if completion["export_intent"] != expected_intent:
        raise CompletedModelEvidenceError(
            "$.completion stage and export_intent are inconsistent"
        )
    # This binding's prospective source qualifier deliberately rejects
    # compressed distillation, so every mechanism accepted by the builder has
    # one exact stage in schema version 1.0.0.
    expected_stage = {
        "baseline": "train",
        "distill": "train",
        "recycle": "train",
        "prune": "compress",
    }[completion["mechanism"]]
    if completion["stage"] != expected_stage:
        raise CompletedModelEvidenceError(
            "$.completion mechanism and stage are inconsistent"
        )
    if completion["mechanism"] == "prune" and any(
        source[name] != exported[name]
        for name in (
            "family",
            "architecture_class",
            "parameter_dtype",
            "embedding_vocabulary_size",
            "observed_token_id_count",
            "tokenizer_set_sha256",
        )
    ):
        raise CompletedModelEvidenceError(
            "$.completion supported structural pruning changed a preserved "
            "architecture or tokenizer field"
        )
    if (
        completion["mechanism"] == "prune"
        and exported["physical_parameters"] >= source["physical_parameters"]
    ):
        raise CompletedModelEvidenceError(
            "$.completion supported structural pruning must reduce physical "
            "parameters"
        )
    if (
        exported["physical_parameters"] != source["physical_parameters"]
        and any(
            exported[name] == source[name]
            for name in (
                "generic_inspection_report_sha256",
                "dense_checkpoint_report_sha256",
                "runtime_report_sha256",
                "weight_set_sha256",
                "bundle_manifest_sha256",
                "tensor_layout_sha256",
                "tensor_inventory_sha256",
            )
        )
    ):
        raise CompletedModelEvidenceError(
            "$.completion changed physical parameters without changing every "
            "affected static/runtime identity"
        )
    if completion["export_format"] != "safetensors":
        raise CompletedModelEvidenceError("$.completion.export_format is invalid")
    if (
        type(completion["active_parameters"]) is not int
        or completion["active_parameters"] != exported["physical_parameters"]
        or type(completion["declared_nonzero_parameters"]) is not int
        or not 0
        <= completion["declared_nonzero_parameters"]
        <= exported["physical_parameters"]
    ):
        raise CompletedModelEvidenceError("$.completion parameter counts are invalid")
    _require_sha256(
        completion["runtime_compatibility_sha256"],
        "$.completion.runtime_compatibility_sha256",
    )
    fixed_size_preserved = _fixed_size_projection(
        source
    ) == _fixed_size_projection(exported)
    if completion["fixed_size_layout_fields_preserved"] is not fixed_size_preserved:
        raise CompletedModelEvidenceError(
            "$.completion.fixed_size_layout_fields_preserved is not derivable"
        )
    if completion["export_intent"] == "fixed_size" and not fixed_size_preserved:
        raise CompletedModelEvidenceError(
            "$.completion fixed-size layout fields are not preserved"
        )
    if completion["export_intent"] == "compression" and not any(
        exported[name] < source[name]
        for name in (
            "physical_parameters",
            "serialized_weight_bits",
            "weight_bytes",
            "bundle_bytes",
            "embedding_vocabulary_size",
        )
    ):
        raise CompletedModelEvidenceError(
            "$.completion compression improves no physical deployment dimension"
        )
    verification = _exact_dict(
        top["verification"], set(_VERIFICATION_FIELDS), "$.verification"
    )
    if any(verification[name] is not True for name in _VERIFICATION_FIELDS):
        raise CompletedModelEvidenceError(
            "$.verification: every completed check must be true"
        )
    limitations = _exact_dict(
        top["limitations"], set(_LIMITATION_FIELDS), "$.limitations"
    )
    if any(limitations[name] is not False for name in _LIMITATION_FIELDS):
        raise CompletedModelEvidenceError(
            "$.limitations: unsupported evidence must remain false"
        )
    authorizations = _exact_dict(
        top["authorizations"], set(_AUTHORIZATION_FIELDS), "$.authorizations"
    )
    if any(authorizations[name] is not False for name in _AUTHORIZATION_FIELDS):
        raise CompletedModelEvidenceError(
            "$.authorizations: every authority field must remain false"
        )
    claimed = _require_sha256(top["binding_sha256"], "$.binding_sha256")
    if claimed != compute_completed_model_evidence_binding_sha256(top):
        raise CompletedModelEvidenceError(
            "$.binding_sha256 does not bind the complete passive record"
        )


def verify_completed_model_evidence_binding(record: object) -> bool:
    """Return whether a passive companion record is structurally self-bound."""

    try:
        copied = _passive_json_copy(record)
        _validate_binding_record(copied)
    except (
        AttributeError,
        CompletedModelEvidenceError,
        KeyError,
        RecursionError,
        TypeError,
        ValueError,
    ):
        return False
    return True


def load_completed_model_evidence_binding(
    run_spec_path: str | os.PathLike[str],
    campaign_policy_path: str | os.PathLike[str],
    completed_record_path: str | os.PathLike[str],
    *,
    source_artifact_dir: str | os.PathLike[str],
    export_artifact_dir: str | os.PathLike[str],
    source_runtime_report_path: str | os.PathLike[str],
    export_runtime_report_path: str | os.PathLike[str],
) -> dict[str, object]:
    """Load bounded documents and build one fresh completed-model binding."""

    spec = load_run_spec(run_spec_path)
    policy = load_campaign_policy(campaign_policy_path)
    completed = load_document(completed_record_path)
    source_runtime = load_document(source_runtime_report_path)
    export_runtime = load_document(export_runtime_report_path)
    if any(
        type(value) is not dict
        for value in (completed, source_runtime, export_runtime)
    ):
        raise CompletedModelEvidenceError(
            "completed record and runtime reports must be exact JSON objects"
        )
    return build_completed_model_evidence_binding(
        spec,
        policy,
        completed,
        source_artifact_dir=source_artifact_dir,
        export_artifact_dir=export_artifact_dir,
        source_runtime_report=source_runtime,
        export_runtime_report=export_runtime,
    )


__all__ = [
    "COMPLETED_MODEL_EVIDENCE_RECORD_TYPE",
    "COMPLETED_MODEL_EVIDENCE_SCHEMA_VERSION",
    "COMPLETED_MODEL_EVIDENCE_SCOPE",
    "CompletedModelEvidenceError",
    "build_completed_model_evidence_binding",
    "compute_completed_model_evidence_binding_sha256",
    "load_completed_model_evidence_binding",
    "verify_completed_model_evidence_binding",
]
