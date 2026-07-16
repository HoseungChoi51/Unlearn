"""Bind a prospective run specification to one qualified dense checkpoint.

The run-spec schema deliberately permits architecture-shaped operator payloads
before a concrete checkpoint is opened.  :mod:`cbds.dense_checkpoint` supplies
the missing architecture-specific evidence: an exact tensor inventory,
structural bounds, GQA grouping, and the matrices that may be factorized.  This
module joins those two contracts without authorizing training, compression,
model selection, scored evaluation, or a research claim.

The generic inspection report is supplied separately so copied source fields
in the dense qualifier are rebound to their original self-hashed report.  The
run spec's ``model.inspection_report_sha256`` names the dense qualifier report,
while ``model.checkpoint_sha256`` names the generic report's complete
Safetensors weight-set identity.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import copy
from fractions import Fraction
from hashlib import sha256
import json
import math
import os
import re
from typing import Any, Final

from .dense_checkpoint import (
    DenseCheckpointQualificationError,
    validate_dense_checkpoint_report,
)
from .model_artifacts import verify_inspection_report_sha256
from .run_specs import RunSpecValidationError, validate_run_spec


DENSE_CHECKPOINT_RUN_BINDING_SCHEMA_VERSION: Final[str] = "1.0.0"
DENSE_CHECKPOINT_RUN_BINDING_RECORD_TYPE: Final[str] = (
    "cbds.dense-checkpoint-run-binding"
)
DENSE_CHECKPOINT_RUN_BINDING_EVIDENCE_SCOPE: Final[str] = (
    "prospective-run-to-static-dense-qualifier-no-execution-authority-v1"
)

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_MAXIMUM_JSON_NODES: Final[int] = 250_000
_MAXIMUM_JSON_DEPTH: Final[int] = 32
_MAXIMUM_JSON_STRING_BYTES: Final[int] = 1_048_576
_MAXIMUM_CANONICAL_BYTES: Final[int] = 64 * 1024 * 1024
_STRUCTURAL_COMPONENTS: Final[frozenset[str]] = frozenset(
    {
        "layer",
        "residual_branch",
        "attention_head",
        "ffn_channel",
        "hidden_dimension",
        "embedding_token",
    }
)
_LAYERED_STRUCTURAL_COMPONENTS: Final[frozenset[str]] = frozenset(
    {"residual_branch", "attention_head", "ffn_channel"}
)
_BOUND_MECHANISMS: Final[frozenset[str]] = frozenset(
    {"baseline", "distill", "recycle", "prune", "quantize", "factorize"}
)
_AUTHORIZATION_FIELDS: Final[tuple[str, ...]] = (
    "training_authorized",
    "compression_authorized",
    "model_selection_eligible",
    "scored_evaluation_eligible",
    "claim_pipeline_eligible",
    "claim_authorized",
)
_VERIFICATION_FIELDS: Final[tuple[str, ...]] = (
    "generic_inspection_rebound",
    "dense_qualifier_validated",
    "model_identity_and_accounting_bound",
    "tokenizer_identity_and_vocabulary_bound",
    "structural_indices_bound",
    "complete_gqa_groups_enforced",
    "structural_export_parameter_count_reconciled",
    "bit_allocations_bound_to_nonoverlapping_tensor_sets",
    "quantization_payload_lower_bound_reconciled",
    "factorizations_bound_to_exact_report_tuples",
)


class DenseCheckpointRunBindingError(ValueError):
    """Raised when a run spec and checkpoint evidence cannot be joined."""

    def __init__(self, errors: str | Iterable[str]) -> None:
        if isinstance(errors, str):
            normalized = (errors,)
        else:
            normalized = tuple(str(error) for error in errors)
        if not normalized:
            normalized = ("dense checkpoint run binding failed",)
        self.errors = normalized
        super().__init__(
            "dense checkpoint run binding failed: " + "; ".join(normalized)
        )


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
        raise DenseCheckpointRunBindingError(
            "binding value is not canonical finite JSON"
        ) from exc
    if len(encoded) > _MAXIMUM_CANONICAL_BYTES:
        raise DenseCheckpointRunBindingError(
            "binding value exceeds its canonical byte limit"
        )
    return encoded


def _value_sha256(value: object) -> str:
    return sha256(_canonical_json_bytes(value)).hexdigest()


def _require_sha256(value: object, path: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise DenseCheckpointRunBindingError(
            f"{path}: must be a lowercase SHA-256 digest"
        )
    return value


def _passive_json_copy(value: object, *, path: str = "$") -> object:
    """Copy only exact passive JSON values without invoking subclass hooks."""

    nodes = 0

    def visit(item: object, item_path: str, depth: int) -> object:
        nonlocal nodes
        nodes += 1
        if nodes > _MAXIMUM_JSON_NODES:
            raise DenseCheckpointRunBindingError(
                f"{path}: exceeds the passive JSON node limit"
            )
        if depth > _MAXIMUM_JSON_DEPTH:
            raise DenseCheckpointRunBindingError(
                f"{path}: exceeds the passive JSON depth limit"
            )
        if item is None or type(item) in {int, bool}:
            return item
        if type(item) is str:
            if len(item.encode("utf-8", errors="strict")) > _MAXIMUM_JSON_STRING_BYTES:
                raise DenseCheckpointRunBindingError(
                    f"{item_path}: exceeds the string byte limit"
                )
            return item
        if type(item) is float:
            if not math.isfinite(item):
                raise DenseCheckpointRunBindingError(
                    f"{item_path}: is not finite JSON"
                )
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
                    raise DenseCheckpointRunBindingError(
                        f"{item_path}: contains a non-exact string key"
                    )
                if len(key.encode("utf-8", errors="strict")) > _MAXIMUM_JSON_STRING_BYTES:
                    raise DenseCheckpointRunBindingError(
                        f"{item_path}: contains an oversized key"
                    )
                copied[key] = visit(child, f"{item_path}.{key}", depth + 1)
            return copied
        raise DenseCheckpointRunBindingError(
            f"{item_path}: contains an active or non-JSON value"
        )

    return visit(value, path, 0)


def _exact_dict(value: object, fields: set[str], path: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != fields:
        raise DenseCheckpointRunBindingError(f"{path}: fields are invalid")
    return value


def _inspection_projection(
    inspection_report: Mapping[str, object],
) -> dict[str, object]:
    """Validate the generic fields consumed by the cross-document binding."""

    if type(inspection_report) is not dict:
        raise DenseCheckpointRunBindingError(
            "inspection_report: must be an exact dictionary"
        )
    passive = _passive_json_copy(inspection_report, path="inspection_report")
    if type(passive) is not dict:  # pragma: no cover - exact type checked above
        raise DenseCheckpointRunBindingError(
            "inspection_report: passive copy is invalid"
        )
    try:
        if not verify_inspection_report_sha256(passive):
            raise DenseCheckpointRunBindingError(
                "inspection_report: self-digest is invalid"
            )
    except (DenseCheckpointRunBindingError, TypeError, ValueError):
        raise
    except (AttributeError, RecursionError) as exc:
        raise DenseCheckpointRunBindingError(
            "inspection_report: cannot verify its self-digest"
        ) from exc

    report_sha256 = _require_sha256(
        passive.get("report_sha256"),
        "inspection_report.report_sha256",
    )
    bundle_manifest_sha256 = _require_sha256(
        passive.get("bundle_manifest_sha256"),
        "inspection_report.bundle_manifest_sha256",
    )
    weight_set_sha256 = _require_sha256(
        passive.get("weight_set_sha256"),
        "inspection_report.weight_set_sha256",
    )
    config = passive.get("config")
    weights = passive.get("weights")
    tokenizer = passive.get("tokenizer")
    architecture = passive.get("architecture")
    files = passive.get("files")
    if type(config) is not dict or type(weights) is not dict:
        raise DenseCheckpointRunBindingError(
            "inspection_report: config or weights record is missing"
        )
    if type(tokenizer) is not dict:
        raise DenseCheckpointRunBindingError(
            "inspection_report.tokenizer: record is missing"
        )
    if (
        type(architecture) is not dict
        or architecture.get("classification") != "dense_consistent"
    ):
        raise DenseCheckpointRunBindingError(
            "inspection_report.architecture: must be dense_consistent"
        )
    if type(files) is not list or not files:
        raise DenseCheckpointRunBindingError(
            "inspection_report.files: must be a nonempty exact list"
        )
    config_sha256 = _require_sha256(
        config.get("sha256"), "inspection_report.config.sha256"
    )
    tensor_layout_sha256 = _require_sha256(
        weights.get("tensor_layout_sha256"),
        "inspection_report.weights.tensor_layout_sha256",
    )
    tokenizer_set_sha256 = _require_sha256(
        tokenizer.get("tokenizer_set_sha256"),
        "inspection_report.tokenizer.tokenizer_set_sha256",
    )
    tokenizer_status = tokenizer.get("status")
    tokenizer_vocab_size = tokenizer.get("locally_inspected_vocab_size")
    tokenizer_config_vocab_size = tokenizer.get("config_vocab_size")
    tokenizer_ids_contiguous = tokenizer.get("token_ids_contiguous_from_zero")
    if (
        tokenizer_status != "json_inspected"
        or type(tokenizer_vocab_size) is not int
        or tokenizer_vocab_size <= 0
        or type(tokenizer_config_vocab_size) is not int
        or tokenizer_config_vocab_size <= 0
        or tokenizer_vocab_size > tokenizer_config_vocab_size
        or tokenizer_ids_contiguous is not True
    ):
        raise DenseCheckpointRunBindingError(
            "inspection_report.tokenizer: must contain an inspectable contiguous "
            "token-ID range no larger than config.vocab_size"
        )
    payload_bytes = weights.get("safetensors_payload_bytes")
    average_bits = weights.get("average_stored_bits_per_element")
    stored_elements = weights.get("stored_tensor_element_count")
    if type(payload_bytes) is not int or payload_bytes <= 0:
        raise DenseCheckpointRunBindingError(
            "inspection_report.weights.safetensors_payload_bytes: is invalid"
        )
    if (
        type(average_bits) not in {int, float}
        or isinstance(average_bits, bool)
        or not math.isfinite(float(average_bits))
        or average_bits <= 0
    ):
        raise DenseCheckpointRunBindingError(
            "inspection_report.weights.average_stored_bits_per_element: is invalid"
        )
    if type(stored_elements) is not int or stored_elements <= 0:
        raise DenseCheckpointRunBindingError(
            "inspection_report.weights.stored_tensor_element_count: is invalid"
        )
    bundle_bytes = 0
    paths: list[str] = []
    for index, raw in enumerate(files):
        if type(raw) is not dict:
            raise DenseCheckpointRunBindingError(
                f"inspection_report.files[{index}]: must be an exact dictionary"
            )
        path = raw.get("path")
        byte_count = raw.get("bytes")
        digest = raw.get("sha256")
        if (
            type(path) is not str
            or not path
            or type(byte_count) is not int
            or byte_count < 0
        ):
            raise DenseCheckpointRunBindingError(
                f"inspection_report.files[{index}]: path or byte count is invalid"
            )
        _require_sha256(digest, f"inspection_report.files[{index}].sha256")
        paths.append(path)
        bundle_bytes += byte_count
    if paths != sorted(set(paths), key=str.encode):
        raise DenseCheckpointRunBindingError(
            "inspection_report.files: paths must be unique and byte-sorted"
        )
    return {
        "report_sha256": report_sha256,
        "bundle_manifest_sha256": bundle_manifest_sha256,
        "weight_set_sha256": weight_set_sha256,
        "config_sha256": config_sha256,
        "tensor_layout_sha256": tensor_layout_sha256,
        "tokenizer_set_sha256": tokenizer_set_sha256,
        "tokenizer_vocab_size": tokenizer_vocab_size,
        "tokenizer_config_vocab_size": tokenizer_config_vocab_size,
        "safetensors_payload_bytes": payload_bytes,
        "bundle_bytes": bundle_bytes,
        "average_stored_bits_per_element": average_bits,
        "stored_tensor_element_count": stored_elements,
        "architecture_classification": "dense_consistent",
    }


def _source_rebinding_errors(
    dense_report: Mapping[str, object],
    inspection: Mapping[str, object],
) -> list[str]:
    errors: list[str] = []
    source = dense_report["source_inspection"]
    if type(source) is not dict:  # defensive after dense report validation
        return ["dense_checkpoint_report.source_inspection: disappeared"]
    fields = (
        "report_sha256",
        "bundle_manifest_sha256",
        "weight_set_sha256",
        "config_sha256",
        "tensor_layout_sha256",
        "safetensors_payload_bytes",
        "bundle_bytes",
        "average_stored_bits_per_element",
    )
    for name in fields:
        if source.get(name) != inspection.get(name):
            errors.append(
                f"dense_checkpoint_report.source_inspection.{name}: must "
                "match the supplied generic inspection report"
            )
    return errors


def validate_dense_checkpoint_report_pair(
    *,
    inspection_report: Mapping[str, object],
    dense_checkpoint_report: Mapping[str, object],
) -> dict[str, object]:
    """Validate and cross-bind one generic inspection and dense qualifier.

    The returned projection is passive and defensive.  This function validates
    report bytes supplied by the caller; it does not reopen the underlying
    model artifact and grants no execution, selection, or claim authority.
    """

    try:
        dense = validate_dense_checkpoint_report(dense_checkpoint_report)
    except DenseCheckpointQualificationError as exc:
        raise DenseCheckpointRunBindingError(
            "dense_checkpoint_report: " + str(exc)
        ) from exc
    passive_inspection = _passive_json_copy(
        inspection_report, path="inspection_report"
    )
    if type(passive_inspection) is not dict:
        raise DenseCheckpointRunBindingError(
            "inspection_report: must be an exact dictionary"
        )
    inspection = _inspection_projection(passive_inspection)
    errors = _source_rebinding_errors(dense, inspection)
    inventory = dense["tensor_inventory"]
    architecture = dense["architecture"]
    if type(inventory) is not dict or type(architecture) is not dict:
        errors.append("dense checkpoint inventory or architecture disappeared")
    else:
        if (
            inventory["physical_parameter_count"]
            != inspection["stored_tensor_element_count"]
        ):
            errors.append(
                "dense_checkpoint_report.tensor_inventory.physical_parameter_count: "
                "must match generic stored tensor elements"
            )
        if architecture["vocab_size"] != inspection["tokenizer_config_vocab_size"]:
            errors.append(
                "dense_checkpoint_report.architecture.vocab_size: must match the "
                "generic inspection tokenizer/config vocabulary"
            )
    if errors:
        raise DenseCheckpointRunBindingError(errors)
    return {
        "inspection_projection": copy.deepcopy(inspection),
        "dense_checkpoint_report": copy.deepcopy(dense),
    }


def _model_binding_errors(
    spec: Mapping[str, Any],
    dense_report: Mapping[str, object],
    inspection: Mapping[str, object],
) -> list[str]:
    errors: list[str] = []
    model = spec["model"]
    tokenizer = spec["tokenizer"]
    inventory = dense_report["tensor_inventory"]
    architecture = dense_report["architecture"]
    if type(inventory) is not dict or type(architecture) is not dict:
        return ["dense checkpoint inventory or architecture disappeared"]
    expected_model = {
        "checkpoint_sha256": inspection["weight_set_sha256"],
        "inspection_report_sha256": dense_report["report_sha256"],
        "physical_parameters": inventory["physical_parameter_count"],
        "serialized_weight_bits": inspection[
            "average_stored_bits_per_element"
        ],
        "checkpoint_weight_bytes": inspection["safetensors_payload_bytes"],
        "checkpoint_bundle_bytes": inspection["bundle_bytes"],
    }
    for name, expected in expected_model.items():
        if model[name] != expected:
            errors.append(
                f"$.model.{name}: must match the qualified dense checkpoint"
            )
    if tokenizer["source_sha256"] != inspection["tokenizer_set_sha256"]:
        errors.append(
            "$.tokenizer.source_sha256: must match the generic inspection's "
            "tokenizer-set identity"
        )
    if tokenizer["vocabulary_size"] != architecture["vocab_size"]:
        errors.append(
            "$.tokenizer.vocabulary_size: must match the qualified architecture"
        )
    if tokenizer["vocabulary_size"] != inspection["tokenizer_config_vocab_size"]:
        errors.append(
            "$.tokenizer.vocabulary_size: must match the model embedding-row "
            "vocabulary recorded by the generic inspection"
        )
    mechanism = spec["operator"]["mechanism"]
    if (
        mechanism in {"prune", "factorize"}
        and spec["export"]["planned_average_weight_bits"]
        != inspection["average_stored_bits_per_element"]
    ):
        errors.append(
            "$.export.planned_average_weight_bits: prune and factorize payloads "
            "must preserve source precision unless an exact quantization payload "
            "is present"
        )
    if mechanism == "distill" and spec["export"]["intent"] == "compression":
        errors.append(
            "$.operator.mechanism: compressed distillation requires a separately "
            "qualified student architecture and cannot use this source-only binder"
        )
    return errors


def _structural_errors(
    spec: Mapping[str, Any], dense_report: Mapping[str, object]
) -> tuple[list[str], str | None, int]:
    errors: list[str] = []
    groups = spec["operator"]["structural_indices"]
    components = {group["component"] for group in groups}
    selected_component = next(iter(components)) if len(components) == 1 else None
    if len(components) > 1:
        errors.append(
            "$.operator.structural_indices: one arm may use only one structural "
            "component vocabulary"
        )
    bounds = dense_report["operator_bounds"]
    architecture = dense_report["architecture"]
    inventory = dense_report["tensor_inventory"]
    if (
        type(bounds) is not dict
        or type(architecture) is not dict
        or type(inventory) is not dict
    ):
        return ["dense checkpoint operator bounds disappeared"], selected_component, 0
    structural = bounds["structural"]
    if type(structural) is not dict:
        return ["dense checkpoint structural bounds disappeared"], selected_component, 0
    layer_count = architecture["num_hidden_layers"]
    removal_mechanism = spec["operator"]["mechanism"] in {"prune", "hybrid"}
    for group_index, group in enumerate(groups):
        component = group["component"]
        path = f"$.operator.structural_indices[{group_index}]"
        if component not in _STRUCTURAL_COMPONENTS or component not in structural:
            errors.append(f"{path}.component: is absent from checkpoint bounds")
            continue
        layer = group["layer"]
        if component in _LAYERED_STRUCTURAL_COMPONENTS:
            if type(layer) is not int or not 0 <= layer < layer_count:
                errors.append(
                    f"{path}.layer: must be an exact layer in [0, {layer_count})"
                )
        elif layer is not None:
            errors.append(f"{path}.layer: must be null for {component}")
        raw_bound = structural[component]
        if type(raw_bound) is not dict:
            errors.append(f"{path}.component: checkpoint bound is malformed")
            continue
        upper = raw_bound.get("exclusive_upper_bound")
        if type(upper) is not int or upper <= 0:
            errors.append(f"{path}.component: checkpoint bound is malformed")
            continue
        indices = group["indices"]
        for index_position, index in enumerate(indices):
            if type(index) is not int or not 0 <= index < upper:
                errors.append(
                    f"{path}.indices[{index_position}]: must be in [0, {upper})"
                )
        if removal_mechanism and len(indices) >= upper:
            errors.append(
                f"{path}.indices: pruning must leave at least one {component} unit"
            )
        if (
            removal_mechanism
            and component == "embedding_token"
            and spec["export"]["planned_vocabulary_size"]
            != upper - len(set(indices))
        ):
            errors.append(
                "$.export.planned_vocabulary_size: embedding-token pruning must "
                "equal source vocabulary minus selected token count"
            )
        if component == "attention_head" and all(
            type(index) is int and 0 <= index < upper for index in indices
        ):
            group_size = raw_bound.get("query_heads_per_key_value_head")
            complete = raw_bound.get("complete_contiguous_gqa_groups_required")
            if type(group_size) is not int or group_size <= 0 or complete is not True:
                errors.append(f"{path}: checkpoint GQA bound is malformed")
                continue
            selected = set(indices)
            for start in range(0, upper, group_size):
                complete_group = set(range(start, start + group_size))
                overlap = selected & complete_group
                if overlap and overlap != complete_group:
                    errors.append(
                        f"{path}.indices: attention heads must select complete "
                        f"contiguous GQA group {sorted(complete_group)!r}"
                    )

    source_vocabulary = architecture["vocab_size"]
    planned_vocabulary = spec["export"]["planned_vocabulary_size"]
    embedding_removal = (
        removal_mechanism
        and bool(groups)
        and selected_component == "embedding_token"
    )
    if not embedding_removal and planned_vocabulary != source_vocabulary:
        errors.append(
            "$.export.planned_vocabulary_size: may change only for an exact "
            "embedding_token pruning payload"
        )

    if not removal_mechanism or not groups:
        return errors, selected_component, 0
    if errors or selected_component is None:
        return errors, selected_component, 0

    source_parameters = inventory["physical_parameter_count"]
    records = inventory["records"]
    if type(source_parameters) is not int or type(records) is not list:
        return ["dense checkpoint tensor inventory disappeared"], selected_component, 0

    removed_parameters = 0
    if selected_component == "layer":
        selected_layers = set(groups[0]["indices"])
        removed_parameters = sum(
            record["stored_elements"]
            for record in records
            if record["layer"] in selected_layers
        )
    elif selected_component == "ffn_channel":
        by_layer = {group["layer"]: group["indices"] for group in groups}
        if set(by_layer) != set(range(layer_count)):
            errors.append(
                "$.operator.structural_indices: physical FFN-width pruning must "
                "specify every layer"
            )
        counts = {len(indices) for indices in by_layer.values()}
        if len(counts) != 1:
            errors.append(
                "$.operator.structural_indices: physical FFN-width pruning must "
                "remove the same channel count from every layer"
            )
        if not errors:
            removed_parameters = sum(
                len(indices) * 3 * architecture["hidden_size"]
                for indices in by_layer.values()
            )
    elif selected_component == "attention_head":
        if architecture["family"] != "qwen3":
            errors.append(
                "$.operator.structural_indices: physical attention-head pruning "
                "is representable by the current exact contract only for Qwen3"
            )
        by_layer = {group["layer"]: group["indices"] for group in groups}
        if set(by_layer) != set(range(layer_count)):
            errors.append(
                "$.operator.structural_indices: physical attention-head pruning "
                "must specify every layer"
            )
        counts = {len(indices) for indices in by_layer.values()}
        if len(counts) != 1:
            errors.append(
                "$.operator.structural_indices: physical attention-head pruning "
                "must remove the same query-head count from every layer"
            )
        if not errors:
            group_size = architecture["query_heads_per_key_value_head"]
            hidden = architecture["hidden_size"]
            head_dim = architecture["head_dim"]
            removed_parameters = sum(
                2
                * (len(indices) + len(indices) // group_size)
                * head_dim
                * hidden
                for indices in by_layer.values()
            )
    elif selected_component == "embedding_token":
        token_count = len(groups[0]["indices"])
        embedding_copies = 1 if architecture["tie_word_embeddings"] else 2
        removed_parameters = (
            token_count * architecture["hidden_size"] * embedding_copies
        )
    else:
        errors.append(
            "$.operator.structural_indices: this component has bounded indices "
            "but no architecture-representable physical export contract"
        )

    if errors:
        return errors, selected_component, 0
    expected_parameters = source_parameters - removed_parameters
    if spec["export"]["planned_physical_parameters"] != expected_parameters:
        errors.append(
            "$.export.planned_physical_parameters: must equal the exact "
            f"architecture-derived structural export count ({expected_parameters})"
        )
    return errors, selected_component, removed_parameters


def _bit_allocation_errors(
    spec: Mapping[str, Any], dense_report: Mapping[str, object]
) -> tuple[list[str], int, float | None]:
    errors: list[str] = []
    allocations = spec["operator"]["bit_allocation"]
    inventory = dense_report["tensor_inventory"]
    bounds = dense_report["operator_bounds"]
    architecture = dense_report["architecture"]
    if type(inventory) is not dict or type(bounds) is not dict or type(architecture) is not dict:
        return ["dense checkpoint bit-allocation evidence disappeared"], 0, None
    records = inventory["records"]
    roles = bounds["tensor_roles"]
    if type(records) is not list or type(roles) is not list:
        return ["dense checkpoint tensor-role evidence disappeared"], 0, None
    role_set = set(roles)
    claimed: set[str] = set()
    assigned_bits: dict[str, int | float] = {}
    source = dense_report["source_inspection"]
    if type(source) is not dict:
        return ["dense checkpoint source precision disappeared"], 0, None
    source_bits = source["average_stored_bits_per_element"]
    strictly_lower = False
    for allocation_index, allocation in enumerate(allocations):
        component = allocation["component"]
        layer = allocation["layer"]
        bits = allocation["bits"]
        path = f"$.operator.bit_allocation[{allocation_index}]"
        if bits > source_bits:
            errors.append(
                f"{path}.bits: cannot exceed source checkpoint precision {source_bits}"
            )
        if component == "all_weights":
            if layer is not None:
                errors.append(f"{path}.layer: all_weights requires null")
            matched = records if layer is None else []
        elif component not in role_set:
            errors.append(
                f"{path}.component: is not an available qualified tensor role"
            )
            matched = []
        else:
            role_records = [item for item in records if item["role"] == component]
            observed_layers = {item["layer"] for item in role_records}
            if observed_layers == {None}:
                if layer is not None:
                    errors.append(
                        f"{path}.layer: unlayered role {component!r} requires null"
                    )
                matched = role_records if layer is None else []
            elif None not in observed_layers:
                if layer is not None and (
                    type(layer) is not int
                    or not 0 <= layer < architecture["num_hidden_layers"]
                ):
                    errors.append(
                        f"{path}.layer: is outside the qualified layer range"
                    )
                matched = [
                    item
                    for item in role_records
                    if layer is None or item["layer"] == layer
                ]
            else:  # pragma: no cover - exact dense report roles never mix scopes
                errors.append(f"{path}.component: role has ambiguous layer scope")
                matched = []
        names = {str(item["name"]) for item in matched}
        if not names:
            errors.append(f"{path}: selector matches no qualified tensor")
        overlap = claimed & names
        if overlap:
            errors.append(
                f"{path}: selector overlaps {len(overlap)} tensor(s) already allocated"
            )
        claimed.update(names)
        for name in names:
            assigned_bits[name] = bits
        if names and bits < source_bits:
            strictly_lower = True
    if allocations and not strictly_lower:
        errors.append(
            "$.operator.bit_allocation: at least one matched tensor selector must "
            "use strictly fewer bits than the source checkpoint"
        )
    lower_bound: float | None = None
    if allocations and not errors:
        total_elements = sum(record["stored_elements"] for record in records)
        payload_bits = sum(
            Fraction(str(assigned_bits.get(record["name"], source_bits)))
            * record["stored_elements"]
            for record in records
        )
        exact_lower_bound = payload_bits / total_elements
        lower_bound = float(exact_lower_bound)
        planned_average = Fraction(
            str(spec["export"]["planned_average_weight_bits"])
        )
        if planned_average < exact_lower_bound:
            errors.append(
                "$.export.planned_average_weight_bits: is below the exact "
                f"selected-plus-unselected payload lower bound ({lower_bound})"
            )
        if (
            spec["operator"]["mechanism"] == "quantize"
            and spec["export"]["planned_physical_parameters"]
            != inventory["physical_parameter_count"]
        ):
            errors.append(
                "$.export.planned_physical_parameters: quantization alone must "
                "preserve the exact physical parameter count"
            )
    return errors, len(claimed), lower_bound


def _factorization_errors(
    spec: Mapping[str, Any], dense_report: Mapping[str, object]
) -> list[str]:
    errors: list[str] = []
    bounds = dense_report["operator_bounds"]
    if type(bounds) is not dict or type(bounds.get("factorizable_matrices")) is not list:
        return ["dense checkpoint factorization bounds disappeared"]
    admitted = {
        _canonical_json_bytes(item)
        for item in bounds["factorizable_matrices"]
        if type(item) is dict
    }
    projection_fields = (
        "tensor_name",
        "component",
        "layer",
        "input_dimension",
        "output_dimension",
    )
    factorizations = spec["operator"]["factorizations"]
    names = [factorization["tensor_name"] for factorization in factorizations]
    if names != sorted(names, key=str.encode):
        errors.append(
            "$.operator.factorizations: tensor names must be in canonical byte order"
        )
    for factorization_index, factorization in enumerate(factorizations):
        projection = {name: factorization[name] for name in projection_fields}
        if _canonical_json_bytes(projection) not in admitted:
            errors.append(
                f"$.operator.factorizations[{factorization_index}]: tensor name, "
                "role, layer, or dimensions do not match an exact qualified matrix"
            )
    return errors


def _validate_and_context(
    spec: Mapping[str, Any],
    *,
    inspection_report: Mapping[str, object],
    dense_checkpoint_report: Mapping[str, object],
    schema_path: str | os.PathLike[str] | None,
) -> tuple[dict[str, Any], dict[str, object], dict[str, object], dict[str, object]]:
    passive_spec = _passive_json_copy(spec, path="run_spec")
    if type(passive_spec) is not dict:
        raise DenseCheckpointRunBindingError("run_spec: must be an exact dictionary")
    try:
        validated_spec = validate_run_spec(passive_spec, schema_path=schema_path)
    except RunSpecValidationError as exc:
        raise DenseCheckpointRunBindingError(
            tuple(f"run_spec: {error}" for error in exc.errors)
        ) from exc
    pair = validate_dense_checkpoint_report_pair(
        inspection_report=inspection_report,
        dense_checkpoint_report=dense_checkpoint_report,
    )
    validated_dense = pair["dense_checkpoint_report"]
    inspection = pair["inspection_projection"]
    if type(validated_dense) is not dict or type(inspection) is not dict:
        raise DenseCheckpointRunBindingError(
            "validated dense checkpoint report pair disappeared"
        )
    errors = _model_binding_errors(validated_spec, validated_dense, inspection)
    if validated_spec["operator"]["mechanism"] == "hybrid":
        errors.append(
            "$.operator.mechanism: hybrid export accounting is not yet "
            "representable by this exact checkpoint binder"
        )
    structural_errors, structural_component, removed_parameters = _structural_errors(
        validated_spec, validated_dense
    )
    errors.extend(structural_errors)
    bit_errors, allocated_tensor_count, quantization_lower_bound = (
        _bit_allocation_errors(
            validated_spec, validated_dense
        )
    )
    errors.extend(bit_errors)
    errors.extend(_factorization_errors(validated_spec, validated_dense))
    if errors:
        raise DenseCheckpointRunBindingError(errors)
    context = {
        "structural_component": structural_component,
        "structural_removed_parameter_count": removed_parameters,
        "allocated_tensor_count": allocated_tensor_count,
        "quantization_payload_lower_bound_average_bits": quantization_lower_bound,
    }
    return validated_spec, validated_dense, inspection, context


def validate_run_spec_against_dense_checkpoint(
    spec: Mapping[str, Any],
    *,
    inspection_report: Mapping[str, object],
    dense_checkpoint_report: Mapping[str, object],
    schema_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Validate a run spec against exact generic and dense checkpoint evidence."""

    validated, _dense, _inspection, _context = _validate_and_context(
        spec,
        inspection_report=inspection_report,
        dense_checkpoint_report=dense_checkpoint_report,
        schema_path=schema_path,
    )
    return copy.deepcopy(validated)


def compute_dense_checkpoint_run_binding_sha256(
    record: Mapping[str, object],
) -> str:
    """Hash one passive binding record, excluding only its self-digest."""

    if type(record) is not dict:
        raise DenseCheckpointRunBindingError("binding record must be an exact dictionary")
    copied = _passive_json_copy(record)
    if type(copied) is not dict:  # pragma: no cover - established above
        raise DenseCheckpointRunBindingError("binding record copy is invalid")
    copied.pop("binding_sha256", None)
    return sha256(
        b"cbds.dense-checkpoint-run-binding.v1\0" + _canonical_json_bytes(copied)
    ).hexdigest()


def build_dense_checkpoint_run_binding(
    spec: Mapping[str, Any],
    *,
    inspection_report: Mapping[str, object],
    dense_checkpoint_report: Mapping[str, object],
    schema_path: str | os.PathLike[str] | None = None,
) -> dict[str, object]:
    """Build a self-hashed, passive, permanently nonauthorizing binding record."""

    validated, dense, inspection, context = _validate_and_context(
        spec,
        inspection_report=inspection_report,
        dense_checkpoint_report=dense_checkpoint_report,
        schema_path=schema_path,
    )
    operator = validated["operator"]
    inventory = dense["tensor_inventory"]
    architecture = dense["architecture"]
    bounds = dense["operator_bounds"]
    if (
        type(inventory) is not dict
        or type(architecture) is not dict
        or type(bounds) is not dict
    ):  # pragma: no cover - dense report validation establishes this
        raise DenseCheckpointRunBindingError("validated dense report disappeared")
    record: dict[str, object] = {
        "schema_version": DENSE_CHECKPOINT_RUN_BINDING_SCHEMA_VERSION,
        "record_type": DENSE_CHECKPOINT_RUN_BINDING_RECORD_TYPE,
        "evidence_scope": DENSE_CHECKPOINT_RUN_BINDING_EVIDENCE_SCOPE,
        "identities": {
            "run_spec_sha256": _value_sha256(validated),
            "generic_inspection_report_sha256": inspection["report_sha256"],
            "dense_checkpoint_report_sha256": dense["report_sha256"],
            "weight_set_sha256": inspection["weight_set_sha256"],
            "bundle_manifest_sha256": inspection["bundle_manifest_sha256"],
            "config_sha256": inspection["config_sha256"],
            "tensor_layout_sha256": inspection["tensor_layout_sha256"],
            "tokenizer_set_sha256": inspection["tokenizer_set_sha256"],
            "tensor_inventory_sha256": inventory["inventory_sha256"],
            "operator_bounds_sha256": _value_sha256(bounds),
            "operator_payload_sha256": _value_sha256(operator),
        },
        "accounting": {
            "physical_parameters": inventory["physical_parameter_count"],
            "serialized_weight_bits": inspection[
                "average_stored_bits_per_element"
            ],
            "checkpoint_weight_bytes": inspection["safetensors_payload_bytes"],
            "checkpoint_bundle_bytes": inspection["bundle_bytes"],
            "vocabulary_size": architecture["vocab_size"],
        },
        "operator": {
            "mechanism": operator["mechanism"],
            "structural_component": context["structural_component"],
            "structural_group_count": len(operator["structural_indices"]),
            "structural_removed_parameter_count": context[
                "structural_removed_parameter_count"
            ],
            "bit_allocation_count": len(operator["bit_allocation"]),
            "bit_allocated_tensor_count": context["allocated_tensor_count"],
            "quantization_payload_lower_bound_average_bits": context[
                "quantization_payload_lower_bound_average_bits"
            ],
            "factorization_count": len(operator["factorizations"]),
        },
        "verification": {name: True for name in _VERIFICATION_FIELDS},
        "authorizations": {name: False for name in _AUTHORIZATION_FIELDS},
    }
    record["binding_sha256"] = compute_dense_checkpoint_run_binding_sha256(record)
    _validate_binding_record(record)
    copied = _passive_json_copy(record)
    if type(copied) is not dict:  # pragma: no cover - established above
        raise DenseCheckpointRunBindingError("binding record copy is invalid")
    return copied


def _validate_binding_record(record: object) -> None:
    top = _exact_dict(
        record,
        {
            "schema_version",
            "record_type",
            "evidence_scope",
            "identities",
            "accounting",
            "operator",
            "verification",
            "authorizations",
            "binding_sha256",
        },
        "$",
    )
    exact = {
        "schema_version": DENSE_CHECKPOINT_RUN_BINDING_SCHEMA_VERSION,
        "record_type": DENSE_CHECKPOINT_RUN_BINDING_RECORD_TYPE,
        "evidence_scope": DENSE_CHECKPOINT_RUN_BINDING_EVIDENCE_SCOPE,
    }
    for name, expected in exact.items():
        if top[name] != expected or type(top[name]) is not str:
            raise DenseCheckpointRunBindingError(f"$.{name}: is invalid")
    identities = _exact_dict(
        top["identities"],
        {
            "run_spec_sha256",
            "generic_inspection_report_sha256",
            "dense_checkpoint_report_sha256",
            "weight_set_sha256",
            "bundle_manifest_sha256",
            "config_sha256",
            "tensor_layout_sha256",
            "tokenizer_set_sha256",
            "tensor_inventory_sha256",
            "operator_bounds_sha256",
            "operator_payload_sha256",
        },
        "$.identities",
    )
    for name, value in identities.items():
        _require_sha256(value, f"$.identities.{name}")
    accounting = _exact_dict(
        top["accounting"],
        {
            "physical_parameters",
            "serialized_weight_bits",
            "checkpoint_weight_bytes",
            "checkpoint_bundle_bytes",
            "vocabulary_size",
        },
        "$.accounting",
    )
    for name in (
        "physical_parameters",
        "checkpoint_weight_bytes",
        "checkpoint_bundle_bytes",
        "vocabulary_size",
    ):
        if type(accounting[name]) is not int or accounting[name] <= 0:
            raise DenseCheckpointRunBindingError(f"$.accounting.{name}: is invalid")
    bits = accounting["serialized_weight_bits"]
    if (
        type(bits) not in {int, float}
        or isinstance(bits, bool)
        or not math.isfinite(float(bits))
        or bits not in {16, 32}
    ):
        raise DenseCheckpointRunBindingError(
            "$.accounting.serialized_weight_bits: is invalid"
        )
    if accounting["checkpoint_weight_bytes"] > accounting["checkpoint_bundle_bytes"]:
        raise DenseCheckpointRunBindingError(
            "$.accounting: checkpoint weight bytes exceed bundle bytes"
        )
    if (
        Fraction(str(bits)) * accounting["physical_parameters"]
        != accounting["checkpoint_weight_bytes"] * 8
    ):
        raise DenseCheckpointRunBindingError(
            "$.accounting: checkpoint weight bytes do not encode the exact "
            "qualified parameter count and precision"
        )
    if accounting["vocabulary_size"] > accounting["physical_parameters"]:
        raise DenseCheckpointRunBindingError(
            "$.accounting: vocabulary size exceeds physical parameter count"
        )
    operator = _exact_dict(
        top["operator"],
        {
            "mechanism",
            "structural_component",
            "structural_group_count",
            "structural_removed_parameter_count",
            "bit_allocation_count",
            "bit_allocated_tensor_count",
            "quantization_payload_lower_bound_average_bits",
            "factorization_count",
        },
        "$.operator",
    )
    if (
        type(operator["mechanism"]) is not str
        or operator["mechanism"] not in _BOUND_MECHANISMS
    ):
        raise DenseCheckpointRunBindingError("$.operator.mechanism: is invalid")
    if operator["structural_component"] is not None and (
        type(operator["structural_component"]) is not str
        or operator["structural_component"] not in _STRUCTURAL_COMPONENTS
    ):
        raise DenseCheckpointRunBindingError(
            "$.operator.structural_component: is invalid"
        )
    for name in (
        "structural_group_count",
        "structural_removed_parameter_count",
        "bit_allocation_count",
        "bit_allocated_tensor_count",
        "factorization_count",
    ):
        if type(operator[name]) is not int or operator[name] < 0:
            raise DenseCheckpointRunBindingError(f"$.operator.{name}: is invalid")
    lower_bound = operator["quantization_payload_lower_bound_average_bits"]
    if lower_bound is not None and (
        type(lower_bound) not in {int, float}
        or isinstance(lower_bound, bool)
        or not math.isfinite(float(lower_bound))
        or lower_bound <= 0
        or lower_bound >= bits
    ):
        raise DenseCheckpointRunBindingError(
            "$.operator.quantization_payload_lower_bound_average_bits: is invalid"
        )
    structural_count = operator["structural_group_count"]
    removed_count = operator["structural_removed_parameter_count"]
    allocation_count = operator["bit_allocation_count"]
    allocated_tensors = operator["bit_allocated_tensor_count"]
    factorization_count = operator["factorization_count"]
    if any(
        count > 4096
        for count in (structural_count, allocation_count, factorization_count)
    ):
        raise DenseCheckpointRunBindingError(
            "$.operator: payload counts exceed the prospective run-spec bounds"
        )
    if removed_count >= accounting["physical_parameters"]:
        raise DenseCheckpointRunBindingError(
            "$.operator.structural_removed_parameter_count: must leave at least "
            "one physical parameter"
        )
    if (
        allocated_tensors > accounting["physical_parameters"]
        or (allocation_count > 0 and allocated_tensors < allocation_count)
    ):
        raise DenseCheckpointRunBindingError(
            "$.operator.bit_allocated_tensor_count: is incompatible with the "
            "allocation count or physical parameter ceiling"
        )
    if (structural_count == 0) != (operator["structural_component"] is None):
        raise DenseCheckpointRunBindingError(
            "$.operator: structural component and group count disagree"
        )
    if (allocation_count == 0) != (allocated_tensors == 0):
        raise DenseCheckpointRunBindingError(
            "$.operator: allocation and allocated-tensor counts disagree"
        )
    if (allocation_count == 0) != (lower_bound is None):
        raise DenseCheckpointRunBindingError(
            "$.operator: allocation count and quantization lower bound disagree"
        )
    mechanism = operator["mechanism"]
    if mechanism in {"baseline", "distill"} and any(
        value != 0
        for value in (
            structural_count,
            removed_count,
            allocation_count,
            factorization_count,
        )
    ):
        raise DenseCheckpointRunBindingError(
            "$.operator: baseline and distill bindings cannot carry operator payloads"
        )
    if mechanism == "recycle" and (
        structural_count <= 0
        or removed_count != 0
        or allocation_count != 0
        or factorization_count != 0
    ):
        raise DenseCheckpointRunBindingError(
            "$.operator: recycle binding payload is inconsistent"
        )
    if mechanism == "prune" and (
        structural_count <= 0
        or removed_count <= 0
        or allocation_count != 0
        or factorization_count != 0
    ):
        raise DenseCheckpointRunBindingError(
            "$.operator: prune binding payload is inconsistent"
        )
    if mechanism == "quantize" and (
        structural_count != 0
        or removed_count != 0
        or allocation_count <= 0
        or allocated_tensors <= 0
        or factorization_count != 0
    ):
        raise DenseCheckpointRunBindingError(
            "$.operator: quantize binding payload is inconsistent"
        )
    if mechanism == "factorize" and (
        structural_count != 0
        or removed_count != 0
        or allocation_count != 0
        or factorization_count <= 0
    ):
        raise DenseCheckpointRunBindingError(
            "$.operator: factorize binding payload is inconsistent"
        )
    verification = _exact_dict(
        top["verification"], set(_VERIFICATION_FIELDS), "$.verification"
    )
    if any(verification[name] is not True for name in _VERIFICATION_FIELDS):
        raise DenseCheckpointRunBindingError(
            "$.verification: every completed binding check must be true"
        )
    authorizations = _exact_dict(
        top["authorizations"], set(_AUTHORIZATION_FIELDS), "$.authorizations"
    )
    if any(authorizations[name] is not False for name in _AUTHORIZATION_FIELDS):
        raise DenseCheckpointRunBindingError(
            "$.authorizations: every authority field must remain false"
        )
    claimed = _require_sha256(top["binding_sha256"], "$.binding_sha256")
    if claimed != compute_dense_checkpoint_run_binding_sha256(top):
        raise DenseCheckpointRunBindingError(
            "$.binding_sha256: does not bind the complete passive record"
        )


def verify_dense_checkpoint_run_binding(record: object) -> bool:
    """Return whether an exact passive binding record is structurally self-bound."""

    try:
        _validate_binding_record(record)
    except (
        AttributeError,
        DenseCheckpointRunBindingError,
        KeyError,
        RecursionError,
        TypeError,
        ValueError,
    ):
        return False
    return True


__all__ = [
    "DENSE_CHECKPOINT_RUN_BINDING_EVIDENCE_SCOPE",
    "DENSE_CHECKPOINT_RUN_BINDING_RECORD_TYPE",
    "DENSE_CHECKPOINT_RUN_BINDING_SCHEMA_VERSION",
    "DenseCheckpointRunBindingError",
    "build_dense_checkpoint_run_binding",
    "compute_dense_checkpoint_run_binding_sha256",
    "validate_dense_checkpoint_report_pair",
    "validate_run_spec_against_dense_checkpoint",
    "verify_dense_checkpoint_run_binding",
]
