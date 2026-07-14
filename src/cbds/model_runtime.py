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
_CUDA_DEVICE_RE: Final[re.Pattern[str]] = re.compile(r"cuda:([0-9]+)\Z")


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
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


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

    if not isinstance(report, Mapping):
        raise TypeError("report must be a mapping")
    unsigned = dict(report)
    unsigned.pop("report_sha256", None)
    return sha256(_canonical_json_bytes(unsigned)).hexdigest()


def verify_runtime_report_sha256(report: Mapping[str, object]) -> bool:
    if not isinstance(report, Mapping):
        raise TypeError("report must be a mapping")
    claimed = report.get("report_sha256")
    return (
        isinstance(claimed, str)
        and _SHA256_RE.fullmatch(claimed) is not None
        and claimed == compute_runtime_report_sha256(report)
    )


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
    return report


__all__ = [
    "MAX_PROMPT_UTF8_BYTES",
    "MAX_RUNTIME_TOKEN_CAP",
    "ModelRuntimeProbeError",
    "RUNTIME_PROBE_SCHEMA_VERSION",
    "RUNTIME_PROBE_VERSION",
    "account_loaded_model_tensors",
    "compute_runtime_report_sha256",
    "probe_local_causal_lm",
    "verify_runtime_report_sha256",
]
