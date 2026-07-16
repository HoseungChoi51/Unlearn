"""Read-only, optional-dependency runtime qualification for local causal LMs.

Static artifact inspection is always completed and hash-validated before
``torch`` or ``transformers`` is imported.  Runtime loading is restricted to
an already-inspected flat local Safetensors directory with remote code disabled
and Hugging Face resolution requested in local-only mode.  The probe performs
one bounded, non-generative forward pass in evaluation/inference mode; it never
samples or writes files.  It does not provide process-level socket isolation.

The optional dependency loader is private and intentionally injectable by
patching in tests, keeping the package and its test suite dependency-free.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from hashlib import sha256
import importlib
import json
import math
import os
from pathlib import Path
import re
from typing import Any, Final

from . import __version__
from . import model_artifacts as _artifacts
from .model_artifacts import (
    InspectionLimits,
    SUB_BILLION_LIMIT,
    inspect_model_artifact,
    verify_inspection_report_sha256,
)


RUNTIME_PROBE_SCHEMA_VERSION: Final[str] = "1.0.0"
RUNTIME_PROBE_VERSION: Final[str] = "1.1.0"
MAX_RUNTIME_TOKEN_CAP: Final[int] = 4_096
MAX_PROMPT_UTF8_BYTES: Final[int] = 64 * 1024
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_CUDA_DEVICE_RE: Final[re.Pattern[str]] = re.compile(
    r"cuda:(0|[1-9][0-9]{0,5})\Z"
)
_MAXIMUM_REPORT_JSON_NODES: Final[int] = 100_000
_MAXIMUM_REPORT_JSON_DEPTH: Final[int] = 24
_MAXIMUM_REPORT_STRING_BYTES: Final[int] = 1_048_576
_MAXIMUM_REPORT_CANONICAL_BYTES: Final[int] = 16 * 1024 * 1024
_TORCH_DTYPE_BYTES: Final[dict[str, int]] = {
    "torch.bool": 1,
    "torch.uint8": 1,
    "torch.int8": 1,
    "torch.float8_e4m3fn": 1,
    "torch.float8_e5m2": 1,
    "torch.int16": 2,
    "torch.float16": 2,
    "torch.bfloat16": 2,
    "torch.int32": 4,
    "torch.float32": 4,
    "torch.complex64": 8,
    "torch.int64": 8,
    "torch.float64": 8,
    "torch.complex128": 16,
}


class ModelRuntimeProbeError(RuntimeError):
    """A fail-closed runtime-probe error with a stable machine code."""

    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"model runtime probe failed [{code}]: {detail}")


@dataclass(frozen=True, slots=True)
class _RuntimeDependencies:
    torch: Any
    transformers: Any


def _load_runtime_dependencies() -> _RuntimeDependencies:
    """Lazily import the two runtime-only dependencies."""

    try:
        torch = importlib.import_module("torch")
        transformers = importlib.import_module("transformers")
    except Exception as exc:
        raise ModelRuntimeProbeError(
            "dependency_unavailable",
            "torch and transformers must both be installed",
        ) from exc
    for name in ("AutoModelForCausalLM", "AutoTokenizer"):
        if not hasattr(transformers, name):
            raise ModelRuntimeProbeError(
                "dependency_incompatible", f"transformers lacks {name}"
            )
    for name in ("inference_mode", "isfinite"):
        if not hasattr(torch, name):
            raise ModelRuntimeProbeError(
                "dependency_incompatible", f"torch lacks {name}"
            )
    return _RuntimeDependencies(torch=torch, transformers=transformers)


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
        raise ModelRuntimeProbeError(
            "runtime_report_invalid",
            "runtime report is not canonical finite JSON",
        ) from exc
    if len(encoded) > _MAXIMUM_REPORT_CANONICAL_BYTES:
        raise ModelRuntimeProbeError(
            "runtime_report_invalid",
            "runtime report exceeds its canonical byte limit",
        )
    return encoded


def _passive_report_copy(value: object, *, path: str = "$") -> object:
    """Copy exact passive JSON values under explicit report resource bounds."""

    nodes = 0

    def visit(item: object, item_path: str, depth: int) -> object:
        nonlocal nodes
        nodes += 1
        if nodes > _MAXIMUM_REPORT_JSON_NODES:
            raise ModelRuntimeProbeError(
                "runtime_report_invalid", "runtime report exceeds its JSON node limit"
            )
        if depth > _MAXIMUM_REPORT_JSON_DEPTH:
            raise ModelRuntimeProbeError(
                "runtime_report_invalid", "runtime report exceeds its JSON depth limit"
            )
        if item is None or type(item) in {int, bool}:
            return item
        if type(item) is str:
            if len(item.encode("utf-8", errors="strict")) > _MAXIMUM_REPORT_STRING_BYTES:
                raise ModelRuntimeProbeError(
                    "runtime_report_invalid",
                    f"{item_path} exceeds the string byte limit",
                )
            return item
        if type(item) is float:
            if not math.isfinite(item):
                raise ModelRuntimeProbeError(
                    "runtime_report_invalid", f"{item_path} is not finite JSON"
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
                    raise ModelRuntimeProbeError(
                        "runtime_report_invalid",
                        f"{item_path} contains a non-exact string key",
                    )
                copied[key] = visit(child, f"{item_path}.{key}", depth + 1)
            return copied
        raise ModelRuntimeProbeError(
            "runtime_report_invalid",
            f"{item_path} contains an active or non-JSON value",
        )

    return visit(value, path, 0)


def _exact_report_dict(
    value: object, fields: set[str], *, path: str
) -> dict[str, object]:
    if type(value) is not dict or set(value) != fields:
        raise ModelRuntimeProbeError(
            "runtime_report_invalid", f"{path} fields are invalid"
        )
    return value


def _runtime_report_sha256(value: object, *, path: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise ModelRuntimeProbeError(
            "runtime_report_invalid", f"{path} must be a lowercase SHA-256"
        )
    return value


def _runtime_report_nonempty_string(value: object, *, path: str) -> str:
    if type(value) is not str or not value:
        raise ModelRuntimeProbeError(
            "runtime_report_invalid", f"{path} must be a nonempty exact string"
        )
    return value


def _runtime_source_sha256() -> str:
    """Bind reports to the exact installed module bytes that produced them."""

    try:
        payload = Path(__file__).read_bytes()
    except OSError as exc:
        raise ModelRuntimeProbeError(
            "implementation_provenance_unavailable",
            "model_runtime.py could not be read for source provenance",
        ) from exc
    return sha256(payload).hexdigest()


def compute_runtime_report_sha256(report: Mapping[str, object]) -> str:
    """Hash canonical JSON after removing only ``report_sha256``."""

    if type(report) is not dict:
        raise TypeError("report must be an exact dictionary")
    copied = _passive_report_copy(report)
    if type(copied) is not dict:  # pragma: no cover - exact type established above
        raise ModelRuntimeProbeError(
            "runtime_report_invalid", "runtime report copy is invalid"
        )
    unsigned = copied
    unsigned.pop("report_sha256", None)
    return sha256(_canonical_json_bytes(unsigned)).hexdigest()


def _validate_tensor_accounting(
    value: object, *, parameters: bool, path: str
) -> dict[str, object]:
    fields = {
        "accounting_basis",
        "named_tensor_entries",
        "unique_physical_spans",
        "deduplicated_alias_entries",
        "storage_allocations_referenced",
        "physical_elements",
        "physical_bytes",
        "by_dtype",
    }
    dtype_fields = {"dtype", "physical_elements", "physical_bytes"}
    if parameters:
        fields.update({"trainable_elements", "trainable_bytes"})
        dtype_fields.update({"trainable_elements", "trainable_bytes"})
    record = _exact_report_dict(value, fields, path=path)
    if record["accounting_basis"] != "union_of_contiguous_untyped_storage_byte_spans":
        raise ModelRuntimeProbeError(
            "runtime_report_invalid", f"{path}.accounting_basis is invalid"
        )
    integer_fields = (
        "named_tensor_entries",
        "unique_physical_spans",
        "deduplicated_alias_entries",
        "storage_allocations_referenced",
        "physical_elements",
        "physical_bytes",
    ) + (("trainable_elements", "trainable_bytes") if parameters else ())
    for name in integer_fields:
        if type(record[name]) is not int or record[name] < 0:
            raise ModelRuntimeProbeError(
                "runtime_report_invalid", f"{path}.{name} is invalid"
            )
    named = record["named_tensor_entries"]
    spans = record["unique_physical_spans"]
    allocations = record["storage_allocations_referenced"]
    if (
        record["deduplicated_alias_entries"] != named - spans
        or allocations > spans
        or spans > named
    ):
        raise ModelRuntimeProbeError(
            "runtime_report_invalid", f"{path} alias/span accounting is inconsistent"
        )
    if parameters and (
        named <= 0
        or spans <= 0
        or allocations <= 0
        or record["physical_elements"] <= 0
        or record["physical_bytes"] <= 0
    ):
        raise ModelRuntimeProbeError(
            "runtime_report_invalid", f"{path} must contain physical parameters"
        )
    by_dtype = record["by_dtype"]
    if type(by_dtype) is not list or len(by_dtype) > 64:
        raise ModelRuntimeProbeError(
            "runtime_report_invalid", f"{path}.by_dtype is invalid"
        )
    dtype_names: list[str] = []
    physical_elements = 0
    physical_bytes = 0
    trainable_elements = 0
    trainable_bytes = 0
    for index, raw in enumerate(by_dtype):
        dtype_record = _exact_report_dict(
            raw, dtype_fields, path=f"{path}.by_dtype[{index}]"
        )
        dtype = _runtime_report_nonempty_string(
            dtype_record["dtype"], path=f"{path}.by_dtype[{index}].dtype"
        )
        element_bytes = _TORCH_DTYPE_BYTES.get(dtype)
        if element_bytes is None:
            raise ModelRuntimeProbeError(
                "runtime_report_invalid",
                f"{path}.by_dtype[{index}].dtype is unsupported",
            )
        for name in dtype_fields - {"dtype"}:
            if type(dtype_record[name]) is not int or dtype_record[name] < 0:
                raise ModelRuntimeProbeError(
                    "runtime_report_invalid",
                    f"{path}.by_dtype[{index}].{name} is invalid",
                )
        if dtype_record["physical_bytes"] != (
            dtype_record["physical_elements"] * element_bytes
        ):
            raise ModelRuntimeProbeError(
                "runtime_report_invalid",
                f"{path}.by_dtype[{index}] byte accounting is inconsistent",
            )
        if parameters:
            if (
                dtype_record["trainable_bytes"]
                != dtype_record["trainable_elements"] * element_bytes
                or dtype_record["trainable_elements"]
                > dtype_record["physical_elements"]
            ):
                raise ModelRuntimeProbeError(
                    "runtime_report_invalid",
                    f"{path}.by_dtype[{index}] trainable accounting is inconsistent",
                )
            trainable_elements += dtype_record["trainable_elements"]
            trainable_bytes += dtype_record["trainable_bytes"]
        dtype_names.append(dtype)
        physical_elements += dtype_record["physical_elements"]
        physical_bytes += dtype_record["physical_bytes"]
    if dtype_names != sorted(set(dtype_names), key=str.encode):
        raise ModelRuntimeProbeError(
            "runtime_report_invalid", f"{path}.by_dtype must be unique and byte-sorted"
        )
    # The producer deliberately retains zero-element tensors in its named,
    # span, allocation, device, and dtype inventories.  Their physical totals
    # are zero, so dtype presence follows span presence rather than whether the
    # byte total happens to be positive.
    if (spans > 0) != bool(by_dtype) or (spans > 0) != (allocations > 0):
        raise ModelRuntimeProbeError(
            "runtime_report_invalid",
            f"{path} span, allocation, or dtype presence is inconsistent",
        )
    if (
        physical_elements != record["physical_elements"]
        or physical_bytes != record["physical_bytes"]
    ):
        raise ModelRuntimeProbeError(
            "runtime_report_invalid", f"{path} dtype totals are inconsistent"
        )
    if parameters and (
        trainable_elements != record["trainable_elements"]
        or trainable_bytes != record["trainable_bytes"]
        or record["trainable_elements"] > record["physical_elements"]
    ):
        raise ModelRuntimeProbeError(
            "runtime_report_invalid", f"{path} trainable totals are inconsistent"
        )
    return record


def validate_runtime_report(report: Mapping[str, object]) -> dict[str, object]:
    """Validate one exact passive runtime report and return a defensive copy.

    This validates the report's internal accounting, loader policy, forward
    shape, qualification projection, and self-digest.  It does not reopen the
    model artifact or prove that the reported runtime observations are honest.
    """

    copied = _passive_report_copy(report)
    top = _exact_report_dict(
        copied,
        {
            "schema_version",
            "runtime_probe_version",
            "report_hash_scope",
            "implementation",
            "static_inspection",
            "dependency_versions",
            "runtime_classes",
            "load_policy",
            "prompt",
            "device_placement",
            "parameters",
            "buffers",
            "forward",
            "claim_qualification",
            "report_sha256",
        },
        path="$",
    )
    constants = {
        "schema_version": RUNTIME_PROBE_SCHEMA_VERSION,
        "runtime_probe_version": RUNTIME_PROBE_VERSION,
        "report_hash_scope": "canonical_json_excluding_report_sha256",
    }
    for name, expected in constants.items():
        if top[name] != expected or type(top[name]) is not str:
            raise ModelRuntimeProbeError(
                "runtime_report_invalid", f"$.{name} is invalid"
            )

    implementation = _exact_report_dict(
        top["implementation"],
        {"package_name", "package_version", "module", "source_sha256"},
        path="$.implementation",
    )
    if implementation["package_name"] != "cbds-research" or implementation[
        "module"
    ] != "cbds.model_runtime":
        raise ModelRuntimeProbeError(
            "runtime_report_invalid", "$.implementation identity is invalid"
        )
    _runtime_report_nonempty_string(
        implementation["package_version"], path="$.implementation.package_version"
    )
    _runtime_report_sha256(
        implementation["source_sha256"], path="$.implementation.source_sha256"
    )

    static = _exact_report_dict(
        top["static_inspection"],
        {
            "inspector_version",
            "report_sha256",
            "bundle_manifest_sha256",
            "weight_set_sha256",
            "architecture_classification",
            "reinspection_match_after_runtime",
        },
        path="$.static_inspection",
    )
    _runtime_report_nonempty_string(
        static["inspector_version"], path="$.static_inspection.inspector_version"
    )
    for name in ("report_sha256", "bundle_manifest_sha256", "weight_set_sha256"):
        _runtime_report_sha256(static[name], path=f"$.static_inspection.{name}")
    if static["architecture_classification"] not in {
        "dense_consistent",
        "moe",
        "ambiguous",
    } or static["reinspection_match_after_runtime"] is not True:
        raise ModelRuntimeProbeError(
            "runtime_report_invalid", "$.static_inspection qualification is invalid"
        )

    versions = _exact_report_dict(
        top["dependency_versions"], {"torch", "transformers"}, path="$.dependency_versions"
    )
    for name in ("torch", "transformers"):
        _runtime_report_nonempty_string(
            versions[name], path=f"$.dependency_versions.{name}"
        )
    classes = _exact_report_dict(
        top["runtime_classes"],
        {
            "transformers_auto_model_class",
            "transformers_auto_tokenizer_class",
            "loaded_model_class",
            "loaded_tokenizer_class",
        },
        path="$.runtime_classes",
    )
    for name, value in classes.items():
        _runtime_report_nonempty_string(value, path=f"$.runtime_classes.{name}")

    load_policy = _exact_report_dict(
        top["load_policy"],
        {
            "local_files_only",
            "trust_remote_code",
            "use_safetensors",
            "flat_local_artifact_required",
            "artifact_writes_permitted",
            "os_socket_isolation_provided",
        },
        path="$.load_policy",
    )
    expected_load_policy = {
        "local_files_only": True,
        "trust_remote_code": False,
        "use_safetensors": True,
        "flat_local_artifact_required": True,
        "artifact_writes_permitted": False,
        "os_socket_isolation_provided": False,
    }
    if load_policy != expected_load_policy:
        raise ModelRuntimeProbeError(
            "runtime_report_invalid", "$.load_policy differs from the probe contract"
        )

    prompt = _exact_report_dict(
        top["prompt"],
        {
            "prompt_sha256",
            "prompt_utf8_bytes",
            "token_cap",
            "observed_tokens",
            "truncation",
        },
        path="$.prompt",
    )
    _runtime_report_sha256(prompt["prompt_sha256"], path="$.prompt.prompt_sha256")
    if (
        type(prompt["prompt_utf8_bytes"]) is not int
        or not 0 <= prompt["prompt_utf8_bytes"] <= MAX_PROMPT_UTF8_BYTES
        or type(prompt["token_cap"]) is not int
        or not 1 <= prompt["token_cap"] <= MAX_RUNTIME_TOKEN_CAP
        or type(prompt["observed_tokens"]) is not int
        or not 1 <= prompt["observed_tokens"] <= prompt["token_cap"]
        or prompt["truncation"] is not False
    ):
        raise ModelRuntimeProbeError(
            "runtime_report_invalid", "$.prompt bounds or truncation are invalid"
        )

    placement = _exact_report_dict(
        top["device_placement"],
        {
            "requested",
            "parameter_devices",
            "buffer_devices",
            "input_device",
            "logits_device",
        },
        path="$.device_placement",
    )
    requested = _runtime_report_nonempty_string(
        placement["requested"], path="$.device_placement.requested"
    )
    if requested != "cpu" and _CUDA_DEVICE_RE.fullmatch(requested) is None:
        raise ModelRuntimeProbeError(
            "runtime_report_invalid",
            "$.device_placement.requested must be exactly 'cpu' or canonical 'cuda:N'",
        )
    parameter_devices = placement["parameter_devices"]
    buffer_devices = placement["buffer_devices"]
    if (
        type(parameter_devices) is not list
        or parameter_devices != [requested]
        or type(buffer_devices) is not list
        or buffer_devices not in ([], [requested])
        or placement["input_device"] != requested
        or placement["logits_device"] != requested
    ):
        raise ModelRuntimeProbeError(
            "runtime_report_invalid", "$.device_placement is inconsistent"
        )

    parameters = _validate_tensor_accounting(
        top["parameters"], parameters=True, path="$.parameters"
    )
    buffers = _validate_tensor_accounting(
        top["buffers"], parameters=False, path="$.buffers"
    )
    # Empty buffers still have a named tensor and device even though they
    # contribute no physical elements or bytes.
    if (buffers["named_tensor_entries"] > 0) != bool(buffer_devices):
        raise ModelRuntimeProbeError(
            "runtime_report_invalid",
            "$.device_placement.buffer_devices disagrees with buffer accounting",
        )

    forward = _exact_report_dict(
        top["forward"],
        {
            "mode",
            "use_cache",
            "input_ids_shape",
            "logits_shape",
            "logits_dtype",
            "logits_finite",
        },
        path="$.forward",
    )
    input_shape = forward["input_ids_shape"]
    logits_shape = forward["logits_shape"]
    observed_tokens = prompt["observed_tokens"]
    if (
        forward["mode"] != "eval_inference_single_forward_no_generation"
        or forward["use_cache"] is not False
        or type(input_shape) is not list
        or input_shape != [1, observed_tokens]
        or type(logits_shape) is not list
        or len(logits_shape) != 3
        or logits_shape[:2] != input_shape
        or type(logits_shape[2]) is not int
        or logits_shape[2] <= 0
        or forward["logits_finite"] is not True
    ):
        raise ModelRuntimeProbeError(
            "runtime_report_invalid", "$.forward shape or execution contract is invalid"
        )
    _runtime_report_nonempty_string(
        forward["logits_dtype"], path="$.forward.logits_dtype"
    )

    qualification = _exact_report_dict(
        top["claim_qualification"],
        {
            "static_density_classification",
            "physical_parameter_elements",
            "physical_parameter_elements_below_one_billion",
            "model_load_succeeded",
            "forward_succeeded",
            "sub_billion_dense_runtime_qualified",
            "ambiguous_static_density_upgraded",
            "scope",
        },
        path="$.claim_qualification",
    )
    physical_parameters = parameters["physical_elements"]
    below_billion = physical_parameters < SUB_BILLION_LIMIT
    expected_qualification = {
        "static_density_classification": static["architecture_classification"],
        "physical_parameter_elements": physical_parameters,
        "physical_parameter_elements_below_one_billion": below_billion,
        "model_load_succeeded": True,
        "forward_succeeded": True,
        "sub_billion_dense_runtime_qualified": (
            static["architecture_classification"] == "dense_consistent"
            and below_billion
        ),
        "ambiguous_static_density_upgraded": False,
        "scope": (
            "physical runtime parameter storage plus one bounded local "
            "causal-LM forward; no capability or benchmark quality claim"
        ),
    }
    if qualification != expected_qualification:
        raise ModelRuntimeProbeError(
            "runtime_report_invalid", "$.claim_qualification is not derivable"
        )
    claimed = _runtime_report_sha256(top["report_sha256"], path="$.report_sha256")
    if claimed != compute_runtime_report_sha256(top):
        raise ModelRuntimeProbeError(
            "runtime_report_invalid", "$.report_sha256 does not bind the report"
        )
    return top


def verify_runtime_report_sha256(report: object) -> bool:
    """Return whether an exact passive runtime report is internally valid."""

    try:
        validate_runtime_report(report)  # type: ignore[arg-type]
    except (AttributeError, ModelRuntimeProbeError, RecursionError, TypeError, ValueError):
        return False
    return True


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ModelRuntimeProbeError("static_report_invalid", f"{label} is not an object")
    return value


def _sha256_field(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ModelRuntimeProbeError(
            "static_report_invalid", f"{label} is not a lowercase SHA-256"
        )
    return value


def _validate_static_report(report: object) -> dict[str, str]:
    if not isinstance(report, Mapping):
        raise ModelRuntimeProbeError(
            "static_report_hash_invalid",
            "the static inspector report hash does not verify",
        )
    try:
        verified = verify_inspection_report_sha256(report)
    except (TypeError, ValueError, OverflowError):
        verified = False
    if not verified:
        raise ModelRuntimeProbeError(
            "static_report_hash_invalid",
            "the static inspector report hash does not verify",
        )
    architecture = _mapping(report.get("architecture"), label="architecture")
    classification = architecture.get("classification")
    if classification not in {"dense_consistent", "moe", "ambiguous"}:
        raise ModelRuntimeProbeError(
            "static_report_invalid", "architecture classification is invalid"
        )
    signals = _mapping(architecture.get("dense_signals"), label="dense_signals")
    no_auto_map = signals.get("no_custom_code_auto_map")
    if not isinstance(no_auto_map, bool):
        raise ModelRuntimeProbeError(
            "static_report_invalid", "custom-code signal is missing"
        )
    if not no_auto_map:
        raise ModelRuntimeProbeError(
            "custom_code_forbidden", "config declares an active auto_map"
        )

    files = report.get("files")
    if not isinstance(files, list):
        raise ModelRuntimeProbeError("static_report_invalid", "files is not an array")
    for item in files:
        record = _mapping(item, label="file record")
        path = record.get("path")
        if not isinstance(path, str):
            raise ModelRuntimeProbeError(
                "static_report_invalid", "file path is not a string"
            )
        if path.endswith(".py"):
            raise ModelRuntimeProbeError(
                "custom_code_forbidden", "local Python implementation files are forbidden"
            )

    config = _mapping(report.get("config"), label="config")
    inspector_version = report.get("inspector_version")
    if not isinstance(inspector_version, str) or not inspector_version:
        raise ModelRuntimeProbeError(
            "static_report_invalid", "inspector_version is missing"
        )
    return {
        "classification": str(classification),
        "report_sha256": _sha256_field(
            report.get("report_sha256"), label="report_sha256"
        ),
        "bundle_manifest_sha256": _sha256_field(
            report.get("bundle_manifest_sha256"),
            label="bundle_manifest_sha256",
        ),
        "weight_set_sha256": _sha256_field(
            report.get("weight_set_sha256"), label="weight_set_sha256"
        ),
        "config_sha256": _sha256_field(config.get("sha256"), label="config.sha256"),
        "inspector_version": inspector_version,
    }


def _read_guarded_config(
    source: str | os.PathLike[str],
    *,
    limits: InspectionLimits,
    expected_sha256: str,
) -> Mapping[str, object]:
    """Re-read the inspected config through the inspector's stable FD path."""

    entries = _artifacts._inventory(Path(source), limits)
    matches = [entry for entry in entries if entry.name == "config.json"]
    if len(matches) != 1:
        raise ModelRuntimeProbeError(
            "artifact_changed", "config.json disappeared after static inspection"
        )
    digest, payload = _artifacts._read_and_hash(
        matches[0], capture=True, maximum_bytes=limits.max_config_bytes
    )
    if digest != expected_sha256 or payload is None:
        raise ModelRuntimeProbeError(
            "artifact_changed", "config.json changed after static inspection"
        )
    parsed = _artifacts._parse_json(payload, label="config.json")
    if not isinstance(parsed, Mapping):
        raise ModelRuntimeProbeError("config_invalid", "config.json is not an object")
    if any(key == "auto_map" for _, key, _ in _artifacts._walk_config(parsed)):
        raise ModelRuntimeProbeError(
            "custom_code_forbidden", "config contains auto_map"
        )
    return parsed


def _artifact_state(
    source: str | os.PathLike[str], limits: InspectionLimits
) -> tuple[
    tuple[int, int, int, int, int, int],
    tuple[tuple[str, tuple[int, int, int, int, int, int]], ...],
]:
    """Capture non-portable metadata solely to detect runtime-side writes."""

    root = Path(source)
    entries = _artifacts._inventory(root, limits)
    try:
        root_fingerprint = _artifacts._fingerprint(root.lstat())
    except OSError as exc:
        raise ModelRuntimeProbeError(
            "artifact_changed", "artifact root became unavailable"
        ) from exc
    return (
        root_fingerprint,
        tuple(
            (entry.name, _artifacts._fingerprint(entry.metadata))
            for entry in entries
        ),
    )


def _dependency_version(module: object, *, name: str) -> str:
    value = getattr(module, "__version__", None)
    if not isinstance(value, str) or not value:
        raise ModelRuntimeProbeError(
            "dependency_incompatible", f"{name} has no string __version__"
        )
    return value


def _qualified_class(value: object) -> str:
    cls = value if isinstance(value, type) else type(value)
    module = getattr(cls, "__module__", None)
    qualname = getattr(cls, "__qualname__", None)
    if not isinstance(module, str) or not isinstance(qualname, str):
        raise ModelRuntimeProbeError(
            "runtime_object_invalid", "runtime object has no stable class identity"
        )
    return f"{module}.{qualname}"


def _normalize_device(torch: object, requested: str) -> str:
    if requested == "cpu":
        return requested
    match = _CUDA_DEVICE_RE.fullmatch(requested) if isinstance(requested, str) else None
    if match is None:
        raise ModelRuntimeProbeError(
            "device_invalid", "device must be exactly 'cpu' or 'cuda:N'"
        )
    cuda = getattr(torch, "cuda", None)
    if cuda is None:
        raise ModelRuntimeProbeError("device_unavailable", "torch has no CUDA runtime")
    try:
        available = cuda.is_available()
        count = cuda.device_count()
    except Exception as exc:
        raise ModelRuntimeProbeError(
            "device_unavailable", "CUDA availability could not be established"
        ) from exc
    index = int(match.group(1))
    if (
        available is not True
        or isinstance(count, bool)
        or not isinstance(count, int)
        or index >= count
    ):
        raise ModelRuntimeProbeError(
            "device_unavailable", "the requested CUDA device is unavailable"
        )
    return requested


def _named_tensors(model: object, method_name: str) -> tuple[tuple[str, object], ...]:
    method = getattr(model, method_name, None)
    if not callable(method):
        raise ModelRuntimeProbeError(
            "model_interface_invalid", f"model lacks {method_name}"
        )
    try:
        values = tuple(method(remove_duplicate=False))
    except Exception as exc:
        raise ModelRuntimeProbeError(
            "model_interface_invalid",
            f"{method_name}(remove_duplicate=False) failed",
        ) from exc
    result: list[tuple[str, object]] = []
    names: set[str] = set()
    for value in values:
        if not isinstance(value, tuple) or len(value) != 2:
            raise ModelRuntimeProbeError(
                "model_interface_invalid", f"{method_name} yielded an invalid entry"
            )
        name, tensor = value
        if not isinstance(name, str) or not name or name in names:
            raise ModelRuntimeProbeError(
                "model_interface_invalid", f"{method_name} yielded an invalid name"
            )
        names.add(name)
        result.append((name, tensor))
    return tuple(result)


@dataclass(frozen=True, slots=True)
class _TensorSpan:
    storage_key: tuple[str, int, int]
    start: int
    end: int
    dtype: str
    element_size: int
    trainable: bool


def _integer_call(value: object, name: str, *, minimum: int) -> int:
    method = getattr(value, name, None)
    if not callable(method):
        raise ModelRuntimeProbeError(
            "tensor_accounting_invalid", f"tensor lacks {name}()"
        )
    try:
        result = method()
    except Exception as exc:
        raise ModelRuntimeProbeError(
            "tensor_accounting_invalid", f"tensor {name}() failed"
        ) from exc
    if isinstance(result, bool) or not isinstance(result, int) or result < minimum:
        raise ModelRuntimeProbeError(
            "tensor_accounting_invalid", f"tensor {name}() is invalid"
        )
    return result


def _tensor_span(tensor: object, *, trainable: bool) -> _TensorSpan:
    numel = _integer_call(tensor, "numel", minimum=0)
    element_size = _integer_call(tensor, "element_size", minimum=1)
    dtype = str(getattr(tensor, "dtype", ""))
    device = str(getattr(tensor, "device", ""))
    if not dtype or not device:
        raise ModelRuntimeProbeError(
            "tensor_accounting_invalid", "tensor dtype or device is missing"
        )
    expected_element_size = _TORCH_DTYPE_BYTES.get(dtype)
    if expected_element_size is None:
        raise ModelRuntimeProbeError(
            "tensor_accounting_ambiguous",
            "tensor dtype is outside the portable runtime-report contract",
        )
    if element_size != expected_element_size:
        raise ModelRuntimeProbeError(
            "tensor_accounting_invalid",
            "tensor element size disagrees with its portable dtype contract",
        )
    contiguous = getattr(tensor, "is_contiguous", None)
    if not callable(contiguous):
        raise ModelRuntimeProbeError(
            "tensor_accounting_invalid", "tensor lacks is_contiguous()"
        )
    try:
        if contiguous() is not True:
            raise ModelRuntimeProbeError(
                "tensor_accounting_ambiguous",
                "non-contiguous tensor storage cannot be counted exactly",
            )
    except ModelRuntimeProbeError:
        raise
    except Exception as exc:
        raise ModelRuntimeProbeError(
            "tensor_accounting_invalid", "tensor contiguity check failed"
        ) from exc

    storage_method = getattr(tensor, "untyped_storage", None)
    if not callable(storage_method):
        raise ModelRuntimeProbeError(
            "tensor_accounting_ambiguous", "tensor has no untyped storage identity"
        )
    try:
        storage = storage_method()
        pointer = storage.data_ptr()
        storage_bytes = storage.nbytes()
    except Exception as exc:
        raise ModelRuntimeProbeError(
            "tensor_accounting_ambiguous", "tensor storage identity is unavailable"
        ) from exc
    if (
        isinstance(pointer, bool)
        or not isinstance(pointer, int)
        or pointer < 0
        or isinstance(storage_bytes, bool)
        or not isinstance(storage_bytes, int)
        or storage_bytes < 0
    ):
        raise ModelRuntimeProbeError(
            "tensor_accounting_invalid", "tensor storage metadata is invalid"
        )
    offset = _integer_call(tensor, "storage_offset", minimum=0)
    start = offset * element_size
    end = start + numel * element_size
    if end > storage_bytes:
        raise ModelRuntimeProbeError(
            "tensor_accounting_invalid", "tensor span exceeds its storage"
        )
    # Empty tensors commonly share a zero data pointer but have no physical
    # elements.  Their object identity prevents a misleading alias count while
    # preserving zero byte totals; object IDs never enter the report.
    identity = id(tensor) if numel == 0 else pointer
    return _TensorSpan(
        storage_key=(device, identity, storage_bytes),
        start=start,
        end=end,
        dtype=dtype,
        element_size=element_size,
        trainable=trainable,
    )


def _merge_intervals(intervals: Iterable[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
    ordered = sorted(intervals)
    merged: list[tuple[int, int]] = []
    for start, end in ordered:
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
        elif end > merged[-1][1]:
            merged[-1] = (merged[-1][0], end)
    return tuple(merged)


def _interval_bytes(intervals: Iterable[tuple[int, int]]) -> int:
    return sum(end - start for start, end in _merge_intervals(intervals))


def _account_tensors(
    named: tuple[tuple[str, object], ...], *, parameters: bool
) -> tuple[dict[str, object], frozenset[str]]:
    spans: list[_TensorSpan] = []
    devices: set[str] = set()
    for _, tensor in named:
        requires_grad = getattr(tensor, "requires_grad", False)
        if parameters and not isinstance(requires_grad, bool):
            raise ModelRuntimeProbeError(
                "tensor_accounting_invalid", "parameter requires_grad is not boolean"
            )
        span = _tensor_span(
            tensor, trainable=bool(requires_grad) if parameters else False
        )
        spans.append(span)
        devices.add(span.storage_key[0])

    dtype_by_storage: dict[tuple[str, int, int], tuple[str, int]] = {}
    all_intervals: dict[str, list[tuple[int, int]]] = {}
    trainable_intervals: dict[str, list[tuple[int, int]]] = {}
    # Storage keys are included in the interval grouping internally so two
    # unrelated allocations with equal offsets are never merged.
    grouped_all: dict[tuple[tuple[str, int, int], str], list[tuple[int, int]]] = {}
    grouped_trainable: dict[
        tuple[tuple[str, int, int], str], list[tuple[int, int]]
    ] = {}
    for span in spans:
        previous = dtype_by_storage.setdefault(
            span.storage_key, (span.dtype, span.element_size)
        )
        if previous != (span.dtype, span.element_size):
            raise ModelRuntimeProbeError(
                "tensor_accounting_ambiguous",
                "one storage is viewed through multiple dtypes",
            )
        grouped_all.setdefault((span.storage_key, span.dtype), []).append(
            (span.start, span.end)
        )
        if span.trainable:
            grouped_trainable.setdefault((span.storage_key, span.dtype), []).append(
                (span.start, span.end)
            )

    for (_, dtype), intervals in grouped_all.items():
        all_intervals.setdefault(dtype, []).append((0, _interval_bytes(intervals)))
    for (_, dtype), intervals in grouped_trainable.items():
        trainable_intervals.setdefault(dtype, []).append(
            (0, _interval_bytes(intervals))
        )

    element_sizes: dict[str, int] = {}
    for span in spans:
        existing = element_sizes.setdefault(span.dtype, span.element_size)
        if existing != span.element_size:
            raise ModelRuntimeProbeError(
                "tensor_accounting_ambiguous", "dtype has inconsistent element sizes"
            )

    by_dtype: list[dict[str, object]] = []
    total_elements = 0
    total_bytes = 0
    trainable_elements = 0
    trainable_bytes = 0
    for dtype in sorted(element_sizes, key=str.encode):
        size = element_sizes[dtype]
        physical = sum(end - start for start, end in all_intervals.get(dtype, ()))
        trainable = sum(
            end - start for start, end in trainable_intervals.get(dtype, ())
        )
        if physical % size or trainable % size:
            raise ModelRuntimeProbeError(
                "tensor_accounting_invalid", "physical bytes are not dtype-aligned"
            )
        record: dict[str, object] = {
            "dtype": dtype,
            "physical_elements": physical // size,
            "physical_bytes": physical,
        }
        if parameters:
            record.update(
                {
                    "trainable_elements": trainable // size,
                    "trainable_bytes": trainable,
                }
            )
        by_dtype.append(record)
        total_elements += physical // size
        total_bytes += physical
        trainable_elements += trainable // size
        trainable_bytes += trainable

    exact_spans = {
        (span.storage_key, span.start, span.end, span.dtype) for span in spans
    }
    report: dict[str, object] = {
        "accounting_basis": "union_of_contiguous_untyped_storage_byte_spans",
        "named_tensor_entries": len(named),
        "unique_physical_spans": len(exact_spans),
        "deduplicated_alias_entries": len(named) - len(exact_spans),
        "storage_allocations_referenced": len({span.storage_key for span in spans}),
        "physical_elements": total_elements,
        "physical_bytes": total_bytes,
        "by_dtype": by_dtype,
    }
    if parameters:
        report.update(
            {
                "trainable_elements": trainable_elements,
                "trainable_bytes": trainable_bytes,
            }
        )
    return report, frozenset(devices)


def account_loaded_model_tensors(model: object) -> dict[str, object]:
    """Return exact physical parameter/buffer storage accounting for a model.

    The function does not import a runtime library and accepts only the same
    conservative, contiguous tensor interface used by the full runtime probe.
    Shared or tied storage spans are counted once even when exposed through
    multiple named tensor wrappers.  It performs no load or forward pass.
    """

    named_parameters = _named_tensors(model, "named_parameters")
    named_buffers = _named_tensors(model, "named_buffers")
    if not named_parameters:
        raise ModelRuntimeProbeError(
            "model_interface_invalid", "loaded model has no parameters"
        )
    parameter_report, parameter_devices = _account_tensors(
        named_parameters, parameters=True
    )
    buffer_report, buffer_devices = _account_tensors(
        named_buffers, parameters=False
    )
    return {
        "parameters": parameter_report,
        "buffers": buffer_report,
        "parameter_devices": sorted(parameter_devices),
        "buffer_devices": sorted(buffer_devices),
    }


def _shape(value: object, *, label: str) -> tuple[int, ...]:
    raw = getattr(value, "shape", None)
    try:
        dimensions = tuple(raw)
    except (TypeError, ValueError) as exc:
        raise ModelRuntimeProbeError(
            "forward_shape_invalid", f"{label} has no valid shape"
        ) from exc
    if not dimensions or any(
        isinstance(item, bool) or not isinstance(item, int) or item < 0
        for item in dimensions
    ):
        raise ModelRuntimeProbeError(
            "forward_shape_invalid", f"{label} shape is invalid"
        )
    return dimensions


def _move_inputs(encoded: object, *, device: str) -> dict[str, object]:
    if not isinstance(encoded, Mapping) or "input_ids" not in encoded:
        raise ModelRuntimeProbeError(
            "tokenizer_output_invalid", "tokenizer did not return input_ids"
        )
    moved: dict[str, object] = {}
    for key, value in encoded.items():
        if not isinstance(key, str) or not key or key == "use_cache":
            raise ModelRuntimeProbeError(
                "tokenizer_output_invalid", "tokenizer returned an invalid input key"
            )
        method = getattr(value, "to", None)
        if not callable(method):
            raise ModelRuntimeProbeError(
                "tokenizer_output_invalid", "tokenizer returned a non-tensor value"
            )
        try:
            moved_value = method(device)
        except Exception as exc:
            raise ModelRuntimeProbeError(
                "device_mismatch", "tokenized input could not be moved"
            ) from exc
        if str(getattr(moved_value, "device", "")) != device:
            raise ModelRuntimeProbeError(
                "device_mismatch", "tokenized input is on the wrong device"
            )
        moved[key] = moved_value
    return moved


def _finite_boolean(torch: object, logits: object) -> bool:
    try:
        value = torch.isfinite(logits)
        value = value.all() if hasattr(value, "all") else value
        value = value.item() if hasattr(value, "item") else value
    except Exception as exc:
        raise ModelRuntimeProbeError(
            "forward_invalid", "logit finiteness check failed"
        ) from exc
    return value is True


def probe_local_causal_lm(
    source: str | os.PathLike[str],
    prompt: str,
    *,
    token_cap: int,
    device: str = "cpu",
    inspection_limits: InspectionLimits | None = None,
) -> dict[str, object]:
    """Qualify one local causal LM with a bounded deterministic forward pass.

    ``token_cap`` is mandatory and truncation is forbidden: a tokenizer result
    above the cap fails before model execution.  The report never contains the
    prompt, host path, tensor values, or memory addresses.
    """

    if not isinstance(prompt, str):
        raise TypeError("prompt must be a string")
    prompt_bytes = prompt.encode("utf-8")
    if len(prompt_bytes) > MAX_PROMPT_UTF8_BYTES:
        raise ModelRuntimeProbeError(
            "prompt_too_large", "prompt exceeds MAX_PROMPT_UTF8_BYTES"
        )
    if (
        isinstance(token_cap, bool)
        or not isinstance(token_cap, int)
        or token_cap <= 0
        or token_cap > MAX_RUNTIME_TOKEN_CAP
    ):
        raise ModelRuntimeProbeError(
            "token_cap_invalid", f"token_cap must be in 1..{MAX_RUNTIME_TOKEN_CAP}"
        )
    if not isinstance(device, str):
        raise TypeError("device must be a string")
    limits = InspectionLimits() if inspection_limits is None else inspection_limits
    if not isinstance(limits, InspectionLimits):
        raise TypeError("inspection_limits must be an InspectionLimits or None")

    # This call is intentionally the first artifact or optional-runtime action.
    static_report = inspect_model_artifact(source, limits=limits)
    static = _validate_static_report(static_report)
    _read_guarded_config(
        source, limits=limits, expected_sha256=static["config_sha256"]
    )
    initial_artifact_state = _artifact_state(source, limits)

    dependencies = _load_runtime_dependencies()
    torch = dependencies.torch
    transformers = dependencies.transformers
    requested_device = _normalize_device(torch, device)
    local_path = str(Path(source).absolute())
    tokenizer_kwargs = {
        "local_files_only": True,
        "trust_remote_code": False,
    }
    model_kwargs = {
        "local_files_only": True,
        "trust_remote_code": False,
        "use_safetensors": True,
    }
    try:
        tokenizer = transformers.AutoTokenizer.from_pretrained(
            local_path, **tokenizer_kwargs
        )
    except Exception as exc:
        raise ModelRuntimeProbeError(
            "tokenizer_load_failed", "local tokenizer loading failed"
        ) from exc
    try:
        encoded = tokenizer(
            prompt,
            return_tensors="pt",
            add_special_tokens=True,
            truncation=False,
        )
    except Exception as exc:
        raise ModelRuntimeProbeError(
            "tokenization_failed", "local tokenizer invocation failed"
        ) from exc
    if not isinstance(encoded, Mapping) or "input_ids" not in encoded:
        raise ModelRuntimeProbeError(
            "tokenizer_output_invalid", "tokenizer did not return input_ids"
        )
    input_shape = _shape(encoded["input_ids"], label="input_ids")
    if len(input_shape) != 2 or input_shape[0] != 1 or input_shape[1] <= 0:
        raise ModelRuntimeProbeError(
            "tokenizer_output_invalid", "input_ids must have shape [1, tokens]"
        )
    observed_tokens = input_shape[1]
    if observed_tokens > token_cap:
        raise ModelRuntimeProbeError(
            "token_cap_exceeded",
            "tokenizer output exceeds token_cap; truncation is forbidden",
        )
    inputs = _move_inputs(encoded, device=requested_device)

    try:
        model = transformers.AutoModelForCausalLM.from_pretrained(
            local_path, **model_kwargs
        )
    except Exception as exc:
        raise ModelRuntimeProbeError(
            "model_load_failed", "local Safetensors causal-LM loading failed"
        ) from exc

    try:
        moved_model = model.to(requested_device)
        if moved_model is not None:
            model = moved_model
        evaluated_model = model.eval()
        if evaluated_model is not None:
            model = evaluated_model
    except Exception as exc:
        raise ModelRuntimeProbeError(
            "device_mismatch", "model could not be placed in evaluation mode"
        ) from exc

    accounting = account_loaded_model_tensors(model)
    parameter_report = accounting["parameters"]
    buffer_report = accounting["buffers"]
    parameter_devices = frozenset(accounting["parameter_devices"])
    buffer_devices = frozenset(accounting["buffer_devices"])
    if parameter_devices != frozenset({requested_device}) or (
        buffer_devices and buffer_devices != frozenset({requested_device})
    ):
        raise ModelRuntimeProbeError(
            "device_mismatch", "model parameters or buffers are on the wrong device"
        )

    try:
        with torch.inference_mode():
            outputs = model(**inputs, use_cache=False)
    except Exception as exc:
        raise ModelRuntimeProbeError(
            "forward_failed", "bounded causal-LM forward failed"
        ) from exc
    logits = (
        outputs.get("logits")
        if isinstance(outputs, Mapping)
        else getattr(outputs, "logits", None)
    )
    if logits is None:
        raise ModelRuntimeProbeError("forward_invalid", "model returned no logits")
    logits_shape = _shape(logits, label="logits")
    if (
        len(logits_shape) != 3
        or logits_shape[0] != 1
        or logits_shape[1] != observed_tokens
        or logits_shape[2] <= 0
    ):
        raise ModelRuntimeProbeError(
            "forward_shape_invalid", "logits must have shape [1, tokens, vocabulary]"
        )
    logits_device = str(getattr(logits, "device", ""))
    if logits_device != requested_device:
        raise ModelRuntimeProbeError(
            "device_mismatch", "logits are on the wrong device"
        )
    if not _finite_boolean(torch, logits):
        raise ModelRuntimeProbeError(
            "nonfinite_logits", "the bounded forward produced non-finite logits"
        )

    # A second strict pass binds the result to an artifact that remained
    # byte-identical while optional dependencies loaded and executed it.
    final_static_report = inspect_model_artifact(source, limits=limits)
    final_static = _validate_static_report(final_static_report)
    final_artifact_state = _artifact_state(source, limits)
    if (
        final_static["report_sha256"] != static["report_sha256"]
        or final_artifact_state != initial_artifact_state
    ):
        raise ModelRuntimeProbeError(
            "artifact_changed", "artifact changed during runtime qualification"
        )

    physical_parameters = parameter_report["physical_elements"]
    if (
        isinstance(physical_parameters, bool)
        or not isinstance(physical_parameters, int)
        or physical_parameters <= 0
    ):
        raise ModelRuntimeProbeError(
            "tensor_accounting_invalid", "physical parameter count is not positive"
        )
    below_billion = physical_parameters < SUB_BILLION_LIMIT
    runtime_qualified = static["classification"] == "dense_consistent" and below_billion

    report: dict[str, object] = {
        "schema_version": RUNTIME_PROBE_SCHEMA_VERSION,
        "runtime_probe_version": RUNTIME_PROBE_VERSION,
        "report_hash_scope": "canonical_json_excluding_report_sha256",
        "implementation": {
            "package_name": "cbds-research",
            "package_version": __version__,
            "module": "cbds.model_runtime",
            "source_sha256": _runtime_source_sha256(),
        },
        "static_inspection": {
            "inspector_version": static["inspector_version"],
            "report_sha256": static["report_sha256"],
            "bundle_manifest_sha256": static["bundle_manifest_sha256"],
            "weight_set_sha256": static["weight_set_sha256"],
            "architecture_classification": static["classification"],
            "reinspection_match_after_runtime": True,
        },
        "dependency_versions": {
            "torch": _dependency_version(torch, name="torch"),
            "transformers": _dependency_version(transformers, name="transformers"),
        },
        "runtime_classes": {
            "transformers_auto_model_class": _qualified_class(
                transformers.AutoModelForCausalLM
            ),
            "transformers_auto_tokenizer_class": _qualified_class(
                transformers.AutoTokenizer
            ),
            "loaded_model_class": _qualified_class(model),
            "loaded_tokenizer_class": _qualified_class(tokenizer),
        },
        "load_policy": {
            "local_files_only": True,
            "trust_remote_code": False,
            "use_safetensors": True,
            "flat_local_artifact_required": True,
            "artifact_writes_permitted": False,
            "os_socket_isolation_provided": False,
        },
        "prompt": {
            "prompt_sha256": sha256(prompt_bytes).hexdigest(),
            "prompt_utf8_bytes": len(prompt_bytes),
            "token_cap": token_cap,
            "observed_tokens": observed_tokens,
            "truncation": False,
        },
        "device_placement": {
            "requested": requested_device,
            "parameter_devices": sorted(parameter_devices),
            "buffer_devices": sorted(buffer_devices),
            "input_device": str(getattr(inputs["input_ids"], "device", "")),
            "logits_device": logits_device,
        },
        "parameters": parameter_report,
        "buffers": buffer_report,
        "forward": {
            "mode": "eval_inference_single_forward_no_generation",
            "use_cache": False,
            "input_ids_shape": list(input_shape),
            "logits_shape": list(logits_shape),
            "logits_dtype": str(getattr(logits, "dtype", "")),
            "logits_finite": True,
        },
        "claim_qualification": {
            "static_density_classification": static["classification"],
            "physical_parameter_elements": physical_parameters,
            "physical_parameter_elements_below_one_billion": below_billion,
            "model_load_succeeded": True,
            "forward_succeeded": True,
            "sub_billion_dense_runtime_qualified": runtime_qualified,
            "ambiguous_static_density_upgraded": False,
            "scope": (
                "physical runtime parameter storage plus one bounded local "
                "causal-LM forward; no capability or benchmark quality claim"
            ),
        },
    }
    report["report_sha256"] = compute_runtime_report_sha256(report)
    # Keep the producer and passive consumer contracts in lockstep.  A future
    # report-field or accounting change must be accepted by the portable
    # validator before the probe can emit it.
    return validate_runtime_report(report)


__all__ = [
    "MAX_PROMPT_UTF8_BYTES",
    "MAX_RUNTIME_TOKEN_CAP",
    "ModelRuntimeProbeError",
    "RUNTIME_PROBE_SCHEMA_VERSION",
    "RUNTIME_PROBE_VERSION",
    "account_loaded_model_tensors",
    "compute_runtime_report_sha256",
    "probe_local_causal_lm",
    "validate_runtime_report",
    "verify_runtime_report_sha256",
]
