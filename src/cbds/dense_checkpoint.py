"""Exact static qualification for the dense backbone-shortlist checkpoints.

The generic :mod:`cbds.model_artifacts` inspector establishes byte identity,
Safetensors well-formedness, and conservative dense-versus-MoE evidence.  It
intentionally does not claim that a checkpoint is architecturally complete.
This module adds that narrower, architecture-specific proof for the three
dense causal-LM families used by the research plan: Qwen2, Qwen3, and Llama.

Qualification is deliberately exact.  The config must name one supported
architecture, every expected parameter must occur once with its derived shape,
and no additional tensor is permitted.  Packed, quantized, low-precision,
mixed-dtype, missing, extra, or wrongly shaped tensors fail closed.  Under
that contract the sum of stored tensor elements is also the reconstructed
count of unique physical network parameters, including embeddings and an
untied output head when present.

The report remains static evidence.  It does not establish runtime parameter
graph equivalence, training correctness, operator validity, campaign
eligibility, model selection, or a research claim.  Existing generic
inspection reports are not modified and retain their original identities.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
from typing import Final

from . import model_artifacts as _generic
from .model_artifacts import (
    InspectionLimits,
    ModelArtifactInspectionError,
    SUB_BILLION_LIMIT,
    inspect_model_artifact,
    verify_inspection_report_sha256,
)


DENSE_CHECKPOINT_SCHEMA_VERSION: Final[str] = "1.0.0"
DENSE_CHECKPOINT_QUALIFIER_VERSION: Final[str] = "1.0.0"
DENSE_CHECKPOINT_RECORD_TYPE: Final[str] = "cbds.dense-checkpoint-qualification"
DENSE_CHECKPOINT_EVIDENCE_SCOPE: Final[str] = (
    "exact-static-qwen2-qwen3-llama-safetensors-inventory-no-runtime-equivalence-v1"
)

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_ACCEPTED_PARAMETER_DTYPES: Final[frozenset[str]] = frozenset(
    {"BF16", "F16", "F32"}
)
_PARAMETER_DTYPE_BITS: Final[dict[str, int]] = {
    "BF16": 16,
    "F16": 16,
    "F32": 32,
}
_AUTHORIZATION_FIELDS: Final[tuple[str, ...]] = (
    "training_authorized",
    "model_selection_eligible",
    "scored_evaluation_eligible",
    "claim_pipeline_eligible",
    "claim_authorized",
)
_MAXIMUM_REPORT_JSON_NODES: Final[int] = 250_000
_MAXIMUM_REPORT_JSON_DEPTH: Final[int] = 32
_MAXIMUM_REPORT_STRING_BYTES: Final[int] = 1_048_576
_MAXIMUM_REPORT_CANONICAL_BYTES: Final[int] = 64 * 1024 * 1024


class DenseCheckpointQualificationError(ValueError):
    """Raised when a checkpoint cannot satisfy the exact dense contract."""


@dataclass(frozen=True, slots=True)
class _ExpectedTensor:
    role: str
    layer: int | None
    shape: tuple[int, ...]
    factor_component: str | None = None

    @property
    def elements(self) -> int:
        value = 1
        for dimension in self.shape:
            value *= dimension
        return value


@dataclass(frozen=True, slots=True)
class _ArchitectureContract:
    family: str
    model_type: str
    architecture_class: str
    hidden_size: int
    intermediate_size: int
    num_hidden_layers: int
    num_attention_heads: int
    num_key_value_heads: int
    head_dim: int
    vocab_size: int
    tie_word_embeddings: bool
    query_projection_bias: bool
    per_head_qk_norm: bool

    @property
    def query_heads_per_key_value_head(self) -> int:
        return self.num_attention_heads // self.num_key_value_heads

    @property
    def query_width(self) -> int:
        return self.num_attention_heads * self.head_dim

    @property
    def key_value_width(self) -> int:
        return self.num_key_value_heads * self.head_dim


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
        raise DenseCheckpointQualificationError(
            "dense checkpoint report is not canonical JSON"
        ) from exc
    if len(encoded) > _MAXIMUM_REPORT_CANONICAL_BYTES:
        raise DenseCheckpointQualificationError(
            "dense checkpoint report exceeds its canonical byte limit"
        )
    return encoded


def _sha256_value(value: object) -> str:
    return sha256(_canonical_json_bytes(value)).hexdigest()


def _require_sha256(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise DenseCheckpointQualificationError(
            f"{label} must be a lowercase SHA-256 digest"
        )
    return value


def _positive_config_int(
    config: Mapping[str, object],
    name: str,
    *,
    maximum: int,
) -> int:
    value = config.get(name)
    if type(value) is not int or not 1 <= value <= maximum:
        raise DenseCheckpointQualificationError(
            f"config.{name} must be a positive bounded exact integer"
        )
    return value


def _architecture_contract(
    config: Mapping[str, object], limits: InspectionLimits
) -> _ArchitectureContract:
    model_type = config.get("model_type")
    architectures = config.get("architectures")
    if (
        type(model_type) is not str
        or type(architectures) is not list
        or len(architectures) != 1
        or type(architectures[0]) is not str
    ):
        raise DenseCheckpointQualificationError(
            "config must declare exactly one supported architecture"
        )
    supported = {
        ("qwen2", "Qwen2ForCausalLM"): ("qwen2", True, False),
        ("qwen3", "Qwen3ForCausalLM"): ("qwen3", False, True),
        ("llama", "LlamaForCausalLM"): ("llama", False, False),
    }
    selected = supported.get((model_type, architectures[0]))
    if selected is None:
        raise DenseCheckpointQualificationError(
            "checkpoint architecture is outside the Qwen2/Qwen3/Llama contract"
        )
    family, query_projection_bias, per_head_qk_norm = selected
    hidden = _positive_config_int(
        config, "hidden_size", maximum=limits.max_dimension
    )
    intermediate = _positive_config_int(
        config, "intermediate_size", maximum=limits.max_dimension
    )
    layers = _positive_config_int(
        config, "num_hidden_layers", maximum=limits.max_model_layers
    )
    attention_heads = _positive_config_int(
        config, "num_attention_heads", maximum=limits.max_dimension
    )
    key_value_heads = _positive_config_int(
        config, "num_key_value_heads", maximum=limits.max_dimension
    )
    vocab = _positive_config_int(config, "vocab_size", maximum=limits.max_dimension)
    tie = config.get("tie_word_embeddings")
    if type(tie) is not bool:
        raise DenseCheckpointQualificationError(
            "config.tie_word_embeddings must be an exact boolean"
        )
    if attention_heads % key_value_heads != 0:
        raise DenseCheckpointQualificationError(
            "query attention heads must form complete key/value-head groups"
        )
    declared_head_dim = config.get("head_dim")
    if family == "qwen3":
        if (
            type(declared_head_dim) is not int
            or not 1 <= declared_head_dim <= limits.max_dimension
        ):
            raise DenseCheckpointQualificationError(
                "Qwen3 requires an explicit positive config.head_dim"
            )
        head_dim = declared_head_dim
    else:
        if hidden % attention_heads != 0:
            raise DenseCheckpointQualificationError(
                "hidden_size must divide evenly across attention heads"
            )
        derived = hidden // attention_heads
        if declared_head_dim is None:
            head_dim = derived
        elif type(declared_head_dim) is int and declared_head_dim == derived:
            head_dim = declared_head_dim
        else:
            raise DenseCheckpointQualificationError(
                "declared head_dim differs from hidden_size/num_attention_heads"
            )
    if family != "qwen3" and attention_heads * head_dim != hidden:
        raise DenseCheckpointQualificationError(
            "supported non-Qwen3 attention width must equal hidden_size"
        )
    return _ArchitectureContract(
        family=family,
        model_type=model_type,
        architecture_class=architectures[0],
        hidden_size=hidden,
        intermediate_size=intermediate,
        num_hidden_layers=layers,
        num_attention_heads=attention_heads,
        num_key_value_heads=key_value_heads,
        head_dim=head_dim,
        vocab_size=vocab,
        tie_word_embeddings=tie,
        query_projection_bias=query_projection_bias,
        per_head_qk_norm=per_head_qk_norm,
    )


def _expected_inventory(
    contract: _ArchitectureContract,
) -> dict[str, _ExpectedTensor]:
    hidden = contract.hidden_size
    intermediate = contract.intermediate_size
    query_width = contract.query_width
    key_value_width = contract.key_value_width
    expected: dict[str, _ExpectedTensor] = {
        "model.embed_tokens.weight": _ExpectedTensor(
            "embedding", None, (contract.vocab_size, hidden), "embedding"
        ),
        "model.norm.weight": _ExpectedTensor("final_norm", None, (hidden,)),
    }
    if not contract.tie_word_embeddings:
        expected["lm_head.weight"] = _ExpectedTensor(
            "lm_head", None, (contract.vocab_size, hidden), "lm_head"
        )
    for layer in range(contract.num_hidden_layers):
        prefix = f"model.layers.{layer}"
        entries = {
            f"{prefix}.input_layernorm.weight": _ExpectedTensor(
                "input_norm", layer, (hidden,)
            ),
            f"{prefix}.post_attention_layernorm.weight": _ExpectedTensor(
                "post_attention_norm", layer, (hidden,)
            ),
            f"{prefix}.mlp.gate_proj.weight": _ExpectedTensor(
                "ffn_gate_proj",
                layer,
                (intermediate, hidden),
                "ffn_gate_proj",
            ),
            f"{prefix}.mlp.up_proj.weight": _ExpectedTensor(
                "ffn_up_proj",
                layer,
                (intermediate, hidden),
                "ffn_up_proj",
            ),
            f"{prefix}.mlp.down_proj.weight": _ExpectedTensor(
                "ffn_down_proj",
                layer,
                (hidden, intermediate),
                "ffn_down_proj",
            ),
            f"{prefix}.self_attn.q_proj.weight": _ExpectedTensor(
                "attention_q_proj",
                layer,
                (query_width, hidden),
                "attention_q_proj",
            ),
            f"{prefix}.self_attn.k_proj.weight": _ExpectedTensor(
                "attention_k_proj",
                layer,
                (key_value_width, hidden),
                "attention_k_proj",
            ),
            f"{prefix}.self_attn.v_proj.weight": _ExpectedTensor(
                "attention_v_proj",
                layer,
                (key_value_width, hidden),
                "attention_v_proj",
            ),
            f"{prefix}.self_attn.o_proj.weight": _ExpectedTensor(
                "attention_o_proj",
                layer,
                (hidden, query_width),
                "attention_o_proj",
            ),
        }
        if contract.query_projection_bias:
            entries.update(
                {
                    f"{prefix}.self_attn.q_proj.bias": _ExpectedTensor(
                        "attention_q_proj_bias", layer, (query_width,)
                    ),
                    f"{prefix}.self_attn.k_proj.bias": _ExpectedTensor(
                        "attention_k_proj_bias", layer, (key_value_width,)
                    ),
                    f"{prefix}.self_attn.v_proj.bias": _ExpectedTensor(
                        "attention_v_proj_bias", layer, (key_value_width,)
                    ),
                }
            )
        if contract.per_head_qk_norm:
            entries.update(
                {
                    f"{prefix}.self_attn.q_norm.weight": _ExpectedTensor(
                        "attention_q_norm", layer, (contract.head_dim,)
                    ),
                    f"{prefix}.self_attn.k_norm.weight": _ExpectedTensor(
                        "attention_k_norm", layer, (contract.head_dim,)
                    ),
                }
            )
        expected.update(entries)
    return expected


def _contract_from_architecture_record(
    architecture: Mapping[str, object],
) -> _ArchitectureContract:
    """Reconstruct a contract from a passive report architecture record."""

    config = {
        "architectures": [architecture["architecture_class"]],
        "model_type": architecture["model_type"],
        "hidden_size": architecture["hidden_size"],
        "intermediate_size": architecture["intermediate_size"],
        "num_hidden_layers": architecture["num_hidden_layers"],
        "num_attention_heads": architecture["num_attention_heads"],
        "num_key_value_heads": architecture["num_key_value_heads"],
        "head_dim": architecture["head_dim"],
        "vocab_size": architecture["vocab_size"],
        "tie_word_embeddings": architecture["tie_word_embeddings"],
    }
    contract = _architecture_contract(config, InspectionLimits())
    if (
        architecture["family"] != contract.family
        or architecture["query_heads_per_key_value_head"]
        != contract.query_heads_per_key_value_head
    ):
        raise DenseCheckpointQualificationError(
            "report architecture family or GQA grouping is not derivable"
        )
    return contract


def _inventory_records(
    expected: Mapping[str, _ExpectedTensor],
    *,
    parameter_dtype: str,
) -> list[dict[str, object]]:
    return [
        {
            "name": name,
            "role": expected[name].role,
            "layer": expected[name].layer,
            "dtype": parameter_dtype,
            "shape": list(expected[name].shape),
            "stored_elements": expected[name].elements,
        }
        for name in sorted(expected, key=str.encode)
    ]


def _operator_bounds(
    contract: _ArchitectureContract,
    expected: Mapping[str, _ExpectedTensor],
) -> dict[str, object]:
    factorizable = [
        {
            "tensor_name": name,
            "component": expected[name].factor_component,
            "layer": expected[name].layer,
            "input_dimension": expected[name].shape[1],
            "output_dimension": expected[name].shape[0],
        }
        for name in sorted(expected, key=str.encode)
        if expected[name].factor_component is not None
    ]
    return {
        "structural": {
            "layer": {
                "exclusive_upper_bound": contract.num_hidden_layers,
            },
            "residual_branch": {
                "exclusive_upper_bound": 2,
                "index_meanings": ["self_attention", "ffn"],
            },
            "attention_head": {
                "exclusive_upper_bound": contract.num_attention_heads,
                "query_heads_per_key_value_head": (
                    contract.query_heads_per_key_value_head
                ),
                "complete_contiguous_gqa_groups_required": True,
            },
            "ffn_channel": {
                "exclusive_upper_bound": contract.intermediate_size,
            },
            "hidden_dimension": {
                "exclusive_upper_bound": contract.hidden_size,
            },
            "embedding_token": {
                "exclusive_upper_bound": contract.vocab_size,
            },
        },
        "factorizable_matrices": factorizable,
        "tensor_roles": sorted(
            {item.role for item in expected.values()}, key=str.encode
        ),
    }


def _passive_json_copy(value: object, *, path: str = "$") -> object:
    """Copy exact passive JSON types without invoking subclass hooks."""

    nodes = 0

    def visit(item: object, item_path: str, depth: int) -> object:
        nonlocal nodes
        nodes += 1
        if nodes > _MAXIMUM_REPORT_JSON_NODES:
            raise DenseCheckpointQualificationError(
                "dense checkpoint report exceeds its JSON node limit"
            )
        if depth > _MAXIMUM_REPORT_JSON_DEPTH:
            raise DenseCheckpointQualificationError(
                "dense checkpoint report exceeds its JSON depth limit"
            )
        if item is None or type(item) in {int, bool}:
            return item
        if type(item) is str:
            if len(item.encode("utf-8", errors="strict")) > _MAXIMUM_REPORT_STRING_BYTES:
                raise DenseCheckpointQualificationError(
                    f"{item_path} exceeds the string byte limit"
                )
            return item
        if type(item) is float:
            if not (float("-inf") < item < float("inf")):
                raise DenseCheckpointQualificationError(
                    f"{item_path} is not finite JSON"
                )
            return item
        if type(item) is list:
            return [
                visit(child, f"{item_path}[{index}]", depth + 1)
                for index, child in enumerate(item)
            ]
        if type(item) is dict:
            result: dict[str, object] = {}
            for key, child in item.items():
                if type(key) is not str:
                    raise DenseCheckpointQualificationError(
                        f"{item_path} has a non-exact string key"
                    )
                if len(key.encode("utf-8", errors="strict")) > _MAXIMUM_REPORT_STRING_BYTES:
                    raise DenseCheckpointQualificationError(
                        f"{item_path} has an oversized key"
                    )
                result[key] = visit(child, f"{item_path}.{key}", depth + 1)
            return result
        raise DenseCheckpointQualificationError(
            f"{item_path} contains an active or non-JSON value"
        )

    return visit(value, path, 0)


def compute_dense_checkpoint_report_sha256(report: Mapping[str, object]) -> str:
    """Recompute the report digest, excluding only ``report_sha256``."""

    if type(report) is not dict:
        raise DenseCheckpointQualificationError("report must be an exact dictionary")
    copied = _passive_json_copy(report)
    if type(copied) is not dict:  # pragma: no cover - established above
        raise DenseCheckpointQualificationError("report copy is invalid")
    copied.pop("report_sha256", None)
    return _sha256_value(copied)


def _validate_report_shape(report: Mapping[str, object]) -> None:
    if type(report) is not dict:
        raise DenseCheckpointQualificationError("report must be an exact dictionary")
    expected_top = {
        "schema_version",
        "qualifier_version",
        "record_type",
        "evidence_scope",
        "source_inspection",
        "architecture",
        "tensor_inventory",
        "operator_bounds",
        "qualification",
        "authorizations",
        "report_sha256",
    }
    if set(report) != expected_top:
        raise DenseCheckpointQualificationError(
            "dense checkpoint report top-level fields differ from the contract"
        )
    exact = {
        "schema_version": DENSE_CHECKPOINT_SCHEMA_VERSION,
        "qualifier_version": DENSE_CHECKPOINT_QUALIFIER_VERSION,
        "record_type": DENSE_CHECKPOINT_RECORD_TYPE,
        "evidence_scope": DENSE_CHECKPOINT_EVIDENCE_SCOPE,
    }
    for name, expected in exact.items():
        if type(report[name]) is not str or report[name] != expected:
            raise DenseCheckpointQualificationError(f"report.{name} is invalid")
    source = report["source_inspection"]
    if type(source) is not dict or set(source) != {
        "report_sha256",
        "bundle_manifest_sha256",
        "weight_set_sha256",
        "config_sha256",
        "tensor_layout_sha256",
        "safetensors_payload_bytes",
        "bundle_bytes",
        "average_stored_bits_per_element",
    }:
        raise DenseCheckpointQualificationError(
            "report.source_inspection fields are invalid"
        )
    for name in (
        "report_sha256",
        "bundle_manifest_sha256",
        "weight_set_sha256",
        "config_sha256",
        "tensor_layout_sha256",
    ):
        _require_sha256(source[name], f"report.source_inspection.{name}")
    for name in ("safetensors_payload_bytes", "bundle_bytes"):
        if type(source[name]) is not int or source[name] <= 0:
            raise DenseCheckpointQualificationError(
                f"report.source_inspection.{name} is invalid"
            )
    bits = source["average_stored_bits_per_element"]
    if (
        type(bits) not in {int, float}
        or isinstance(bits, bool)
        or not float("-inf") < bits < float("inf")
        or bits <= 0
    ):
        raise DenseCheckpointQualificationError(
            "report.source_inspection.average_stored_bits_per_element is invalid"
        )
    if source["safetensors_payload_bytes"] > source["bundle_bytes"]:
        raise DenseCheckpointQualificationError(
            "report source payload bytes exceed complete bundle bytes"
        )
    architecture = report["architecture"]
    architecture_fields = {
        "family",
        "model_type",
        "architecture_class",
        "hidden_size",
        "intermediate_size",
        "num_hidden_layers",
        "num_attention_heads",
        "num_key_value_heads",
        "head_dim",
        "query_heads_per_key_value_head",
        "vocab_size",
        "tie_word_embeddings",
    }
    if type(architecture) is not dict or set(architecture) != architecture_fields:
        raise DenseCheckpointQualificationError("report.architecture fields are invalid")
    if architecture["family"] not in {"qwen2", "qwen3", "llama"}:
        raise DenseCheckpointQualificationError("report architecture family is invalid")
    for name in architecture_fields - {
        "family",
        "model_type",
        "architecture_class",
        "tie_word_embeddings",
    }:
        if type(architecture[name]) is not int or architecture[name] <= 0:
            raise DenseCheckpointQualificationError(
                f"report.architecture.{name} is invalid"
            )
    if type(architecture["tie_word_embeddings"]) is not bool:
        raise DenseCheckpointQualificationError(
            "report.architecture.tie_word_embeddings is invalid"
        )
    contract = _contract_from_architecture_record(architecture)
    expected_inventory = _expected_inventory(contract)
    inventory = report["tensor_inventory"]
    if type(inventory) is not dict or set(inventory) != {
        "tensor_count",
        "physical_parameter_count",
        "parameter_dtype",
        "inventory_sha256",
        "records",
    }:
        raise DenseCheckpointQualificationError(
            "report.tensor_inventory fields are invalid"
        )
    if (
        type(inventory["tensor_count"]) is not int
        or inventory["tensor_count"] <= 0
        or type(inventory["physical_parameter_count"]) is not int
        or inventory["physical_parameter_count"] <= 0
        or type(inventory["parameter_dtype"]) is not str
        or inventory["parameter_dtype"] not in _ACCEPTED_PARAMETER_DTYPES
        or type(inventory["records"]) is not list
        or len(inventory["records"]) != inventory["tensor_count"]
    ):
        raise DenseCheckpointQualificationError(
            "report tensor inventory summary is invalid"
        )
    _require_sha256(inventory["inventory_sha256"], "report inventory digest")
    names: list[str] = []
    elements = 0
    record_fields = {"name", "role", "layer", "dtype", "shape", "stored_elements"}
    for index, raw in enumerate(inventory["records"]):
        if type(raw) is not dict or set(raw) != record_fields:
            raise DenseCheckpointQualificationError(
                f"report.tensor_inventory.records[{index}] fields are invalid"
            )
        if (
            type(raw["name"]) is not str
            or type(raw["role"]) is not str
            or raw["dtype"] != inventory["parameter_dtype"]
            or type(raw["shape"]) is not list
            or not raw["shape"]
            or any(type(item) is not int or item <= 0 for item in raw["shape"])
            or (raw["layer"] is not None and type(raw["layer"]) is not int)
            or type(raw["stored_elements"]) is not int
            or raw["stored_elements"] <= 0
        ):
            raise DenseCheckpointQualificationError(
                f"report.tensor_inventory.records[{index}] is invalid"
            )
        product = 1
        for dimension in raw["shape"]:
            product *= dimension
        if product != raw["stored_elements"]:
            raise DenseCheckpointQualificationError(
                f"report.tensor_inventory.records[{index}] element count is invalid"
            )
        names.append(raw["name"])
        elements += raw["stored_elements"]
    if names != sorted(set(names), key=str.encode):
        raise DenseCheckpointQualificationError(
            "report tensor records must have unique byte-sorted names"
        )
    if elements != inventory["physical_parameter_count"]:
        raise DenseCheckpointQualificationError(
            "report physical parameter total differs from tensor records"
        )
    expected_dtype_bits = _PARAMETER_DTYPE_BITS[inventory["parameter_dtype"]]
    if bits != expected_dtype_bits:
        raise DenseCheckpointQualificationError(
            "report source precision differs from the qualified parameter dtype"
        )
    if source["safetensors_payload_bytes"] * 8 != elements * expected_dtype_bits:
        raise DenseCheckpointQualificationError(
            "report source payload bytes differ from the exact tensor inventory"
        )
    if _sha256_value(inventory["records"]) != inventory["inventory_sha256"]:
        raise DenseCheckpointQualificationError(
            "report inventory_sha256 does not bind the tensor records"
        )
    derived_records = _inventory_records(
        expected_inventory,
        parameter_dtype=inventory["parameter_dtype"],
    )
    if inventory["records"] != derived_records:
        raise DenseCheckpointQualificationError(
            "report tensor records differ from the architecture-derived inventory"
        )
    bounds = report["operator_bounds"]
    if type(bounds) is not dict or set(bounds) != {
        "structural",
        "factorizable_matrices",
        "tensor_roles",
    }:
        raise DenseCheckpointQualificationError("report.operator_bounds is invalid")
    structural = bounds["structural"]
    if type(structural) is not dict or set(structural) != {
        "layer",
        "residual_branch",
        "attention_head",
        "ffn_channel",
        "hidden_dimension",
        "embedding_token",
    }:
        raise DenseCheckpointQualificationError(
            "report structural operator bounds are invalid"
        )
    for name, raw in structural.items():
        if type(raw) is not dict or type(raw.get("exclusive_upper_bound")) is not int:
            raise DenseCheckpointQualificationError(
                f"report structural bound {name!r} is invalid"
            )
    if type(bounds["factorizable_matrices"]) is not list or type(
        bounds["tensor_roles"]
    ) is not list:
        raise DenseCheckpointQualificationError(
            "report factorization or tensor-role bounds are invalid"
        )
    if bounds != _operator_bounds(contract, expected_inventory):
        raise DenseCheckpointQualificationError(
            "report operator bounds differ from the architecture-derived bounds"
        )
    qualification = report["qualification"]
    expected_qualification = {
        "exact_supported_architecture_contract": True,
        "architecture_specific_tensor_inventory_verified": True,
        "unique_physical_parameter_count_reconstructed": True,
        "physical_parameters_below_one_billion": (
            inventory["physical_parameter_count"] < SUB_BILLION_LIMIT
        ),
        "runtime_parameter_graph_equivalence_verified": False,
        "campaign_eligible": False,
    }
    if type(qualification) is not dict or qualification != expected_qualification:
        raise DenseCheckpointQualificationError("report qualification boundary is invalid")
    authorizations = report["authorizations"]
    if (
        type(authorizations) is not dict
        or set(authorizations) != set(_AUTHORIZATION_FIELDS)
        or any(authorizations[name] is not False for name in _AUTHORIZATION_FIELDS)
    ):
        raise DenseCheckpointQualificationError("report authorizations are invalid")
    claimed = _require_sha256(report["report_sha256"], "report.report_sha256")
    if claimed != compute_dense_checkpoint_report_sha256(report):
        raise DenseCheckpointQualificationError(
            "report.report_sha256 does not bind the complete report"
        )


def validate_dense_checkpoint_report(report: Mapping[str, object]) -> dict[str, object]:
    """Return a passive defensive copy after structural and hash validation."""

    copied = _passive_json_copy(report)
    if type(copied) is not dict:  # pragma: no cover - established by validator
        raise DenseCheckpointQualificationError("report copy is invalid")
    _validate_report_shape(copied)
    return copied


def verify_dense_checkpoint_report_sha256(report: object) -> bool:
    """Return whether ``report`` is an exact, self-bound qualification record."""

    try:
        validate_dense_checkpoint_report(report)  # type: ignore[arg-type]
    except (
        AttributeError,
        DenseCheckpointQualificationError,
        KeyError,
        TypeError,
        ValueError,
    ):
        return False
    return True


def _read_config_and_tensors(
    source: str | os.PathLike[str],
    limits: InspectionLimits,
) -> tuple[dict[str, object], tuple[object, ...], tuple[object, ...]]:
    """Reopen the generic inputs and return config, tensors, and inventory shell."""

    root = Path(source)
    try:
        before = _generic._inventory(root, limits)
        by_name = {entry.name: entry for entry in before}
        config_entry = by_name.get("config.json")
        if config_entry is None:
            raise DenseCheckpointQualificationError("artifact is missing config.json")
        config_sha256, config_payload = _generic._read_and_hash(
            config_entry,
            capture=True,
            maximum_bytes=limits.max_config_bytes,
        )
        if config_payload is None:
            raise DenseCheckpointQualificationError("config.json was not captured")
        value = _generic._parse_json(config_payload, label="config.json")
        if type(value) is not dict:
            raise DenseCheckpointQualificationError("config.json must be an object")
        shards = tuple(
            sorted(
                (
                    _generic._inspect_safetensor(entry, limits)
                    for entry in before
                    if entry.name.endswith(".safetensors")
                ),
                key=lambda item: item.path.encode("utf-8"),
            )
        )
        if not shards:
            raise DenseCheckpointQualificationError(
                "artifact contains no Safetensors shards"
            )
        index_entry = by_name.get("model.safetensors.index.json")
        index_payload: bytes | None = None
        if index_entry is not None:
            _digest, index_payload = _generic._read_and_hash(
                index_entry,
                capture=True,
                maximum_bytes=limits.max_index_bytes,
            )
        _generic._validate_shards(shards, index_payload)
        tensors = tuple(
            sorted(
                (tensor for shard in shards for tensor in shard.tensors),
                key=lambda item: item.name.encode("utf-8"),
            )
        )
        after = _generic._inventory(root, limits)
        if [
            (item.name, _generic._fingerprint(item.metadata)) for item in before
        ] != [(item.name, _generic._fingerprint(item.metadata)) for item in after]:
            raise DenseCheckpointQualificationError(
                "artifact changed during dense qualification"
            )
        return (
            {**value, "__cbds_config_sha256": config_sha256},
            tensors,
            before,
        )
    except DenseCheckpointQualificationError:
        raise
    except (ModelArtifactInspectionError, OSError, TypeError, ValueError) as exc:
        raise DenseCheckpointQualificationError(
            "cannot reopen the generic artifact for exact dense qualification"
        ) from exc


def inspect_dense_checkpoint(
    source: str | os.PathLike[str],
    *,
    expected_inspection_report_sha256: str,
    limits: InspectionLimits | None = None,
) -> dict[str, object]:
    """Qualify one exact supported dense checkpoint from a trusted generic pin."""

    expected_report_sha256 = _require_sha256(
        expected_inspection_report_sha256,
        "expected_inspection_report_sha256",
    )
    selected_limits = InspectionLimits() if limits is None else limits
    if type(selected_limits) is not InspectionLimits:
        raise TypeError("limits must be an exact InspectionLimits instance or None")
    try:
        generic = inspect_model_artifact(source, limits=selected_limits)
    except (ModelArtifactInspectionError, OSError, TypeError, ValueError) as exc:
        raise DenseCheckpointQualificationError(
            "generic source inspection failed"
        ) from exc
    if (
        not verify_inspection_report_sha256(generic)
        or generic.get("report_sha256") != expected_report_sha256
    ):
        raise DenseCheckpointQualificationError(
            "generic inspection report differs from its trusted expected digest"
        )
    config_with_digest, tensors, inventory_shell = _read_config_and_tensors(
        source, selected_limits
    )
    config_digest = config_with_digest.pop("__cbds_config_sha256")
    if config_digest != generic["config"]["sha256"]:  # type: ignore[index]
        raise DenseCheckpointQualificationError(
            "reopened config differs from the generic inspection"
        )
    layout_sha256 = _generic._canonical_sequence_sha256(
        tensor.layout_record() for tensor in tensors  # type: ignore[attr-defined]
    )
    if layout_sha256 != generic["weights"]["tensor_layout_sha256"]:  # type: ignore[index]
        raise DenseCheckpointQualificationError(
            "reopened tensor layout differs from the generic inspection"
        )
    generic_files = {
        item["path"]: item for item in generic["files"]  # type: ignore[index]
    }
    if set(generic_files) != {item.name for item in inventory_shell}:  # type: ignore[attr-defined]
        raise DenseCheckpointQualificationError(
            "reopened artifact inventory differs from the generic inspection"
        )
    contract = _architecture_contract(config_with_digest, selected_limits)
    expected = _expected_inventory(contract)
    observed = {tensor.name: tensor for tensor in tensors}  # type: ignore[attr-defined]
    if len(observed) != len(tensors):
        raise DenseCheckpointQualificationError(
            "checkpoint contains a duplicate tensor name"
        )
    missing = sorted(set(expected) - set(observed), key=str.encode)
    extra = sorted(set(observed) - set(expected), key=str.encode)
    if missing or extra:
        summary: list[str] = []
        if missing:
            summary.append("missing=" + ",".join(missing[:8]))
        if extra:
            summary.append("extra=" + ",".join(extra[:8]))
        raise DenseCheckpointQualificationError(
            "checkpoint tensor inventory is not exact (" + "; ".join(summary) + ")"
        )
    dtypes = {tensor.dtype for tensor in tensors}  # type: ignore[attr-defined]
    if len(dtypes) != 1 or not dtypes <= _ACCEPTED_PARAMETER_DTYPES:
        raise DenseCheckpointQualificationError(
            "checkpoint parameters must use one accepted non-packed floating dtype"
        )
    parameter_dtype = next(iter(dtypes))
    records: list[dict[str, object]] = []
    for name in sorted(expected, key=str.encode):
        wanted = expected[name]
        tensor = observed[name]
        shape = tuple(tensor.shape)  # type: ignore[attr-defined]
        if shape != wanted.shape:
            raise DenseCheckpointQualificationError(
                f"tensor {name!r} has shape {shape!r}, expected {wanted.shape!r}"
            )
        if tensor.elements != wanted.elements:  # type: ignore[attr-defined]
            raise DenseCheckpointQualificationError(
                f"tensor {name!r} element count differs from its shape"
            )
        records.append(
            {
                "name": name,
                "role": wanted.role,
                "layer": wanted.layer,
                "dtype": parameter_dtype,
                "shape": list(wanted.shape),
                "stored_elements": wanted.elements,
            }
        )
    physical_parameters = sum(item["stored_elements"] for item in records)
    generic_count = generic["weights"]["stored_tensor_element_count"]  # type: ignore[index]
    if physical_parameters != generic_count:
        raise DenseCheckpointQualificationError(
            "reconstructed parameter count differs from generic stored elements"
        )
    if generic["architecture"]["classification"] != "dense_consistent":  # type: ignore[index]
        raise DenseCheckpointQualificationError(
            "generic inspector did not classify the checkpoint as dense-consistent"
        )
    if generic["quantization"]["logical_count_from_stored_elements_ambiguous"]:  # type: ignore[index]
        raise DenseCheckpointQualificationError(
            "generic inspector found packed or quantized count ambiguity"
        )
    bundle_bytes = sum(item["bytes"] for item in generic["files"])  # type: ignore[index]
    try:
        final_generic = inspect_model_artifact(source, limits=selected_limits)
    except (ModelArtifactInspectionError, OSError, TypeError, ValueError) as exc:
        raise DenseCheckpointQualificationError(
            "final generic source reinspection failed"
        ) from exc
    if final_generic != generic:
        raise DenseCheckpointQualificationError(
            "generic source inspection changed across dense qualification"
        )
    report: dict[str, object] = {
        "schema_version": DENSE_CHECKPOINT_SCHEMA_VERSION,
        "qualifier_version": DENSE_CHECKPOINT_QUALIFIER_VERSION,
        "record_type": DENSE_CHECKPOINT_RECORD_TYPE,
        "evidence_scope": DENSE_CHECKPOINT_EVIDENCE_SCOPE,
        "source_inspection": {
            "report_sha256": generic["report_sha256"],
            "bundle_manifest_sha256": generic["bundle_manifest_sha256"],
            "weight_set_sha256": generic["weight_set_sha256"],
            "config_sha256": generic["config"]["sha256"],  # type: ignore[index]
            "tensor_layout_sha256": layout_sha256,
            "safetensors_payload_bytes": generic["weights"][  # type: ignore[index]
                "safetensors_payload_bytes"
            ],
            "bundle_bytes": bundle_bytes,
            "average_stored_bits_per_element": generic["weights"][  # type: ignore[index]
                "average_stored_bits_per_element"
            ],
        },
        "architecture": {
            "family": contract.family,
            "model_type": contract.model_type,
            "architecture_class": contract.architecture_class,
            "hidden_size": contract.hidden_size,
            "intermediate_size": contract.intermediate_size,
            "num_hidden_layers": contract.num_hidden_layers,
            "num_attention_heads": contract.num_attention_heads,
            "num_key_value_heads": contract.num_key_value_heads,
            "head_dim": contract.head_dim,
            "query_heads_per_key_value_head": (
                contract.query_heads_per_key_value_head
            ),
            "vocab_size": contract.vocab_size,
            "tie_word_embeddings": contract.tie_word_embeddings,
        },
        "tensor_inventory": {
            "tensor_count": len(records),
            "physical_parameter_count": physical_parameters,
            "parameter_dtype": parameter_dtype,
            "inventory_sha256": _sha256_value(records),
            "records": records,
        },
        "operator_bounds": _operator_bounds(contract, expected),
        "qualification": {
            "exact_supported_architecture_contract": True,
            "architecture_specific_tensor_inventory_verified": True,
            "unique_physical_parameter_count_reconstructed": True,
            "physical_parameters_below_one_billion": (
                physical_parameters < SUB_BILLION_LIMIT
            ),
            "runtime_parameter_graph_equivalence_verified": False,
            "campaign_eligible": False,
        },
        "authorizations": {name: False for name in _AUTHORIZATION_FIELDS},
    }
    report["report_sha256"] = compute_dense_checkpoint_report_sha256(report)
    validate_dense_checkpoint_report(report)
    return report


__all__ = [
    "DENSE_CHECKPOINT_EVIDENCE_SCOPE",
    "DENSE_CHECKPOINT_QUALIFIER_VERSION",
    "DENSE_CHECKPOINT_RECORD_TYPE",
    "DENSE_CHECKPOINT_SCHEMA_VERSION",
    "DenseCheckpointQualificationError",
    "compute_dense_checkpoint_report_sha256",
    "inspect_dense_checkpoint",
    "validate_dense_checkpoint_report",
    "verify_dense_checkpoint_report_sha256",
]
