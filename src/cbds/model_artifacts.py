"""Dependency-free inspection of local Hugging Face Safetensors artifacts.

The inspector is deliberately read-only and does not import model code,
``transformers``, ``torch``, or ``safetensors``.  It validates the on-disk
Safetensors layout, binds every regular file to a SHA-256 digest, and reports
what the stored tensors prove.  It does not claim runtime loadability or infer
logical parameter counts from opaque quantized packing.

Only a flat, real directory is accepted.  Symbolic links, subdirectories,
special files, mixed weight formats, malformed JSON, incomplete shard indexes,
and resource-limit violations fail closed.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import re
import stat
from typing import Any, Final, Literal, cast


INSPECTOR_SCHEMA_VERSION: Final[str] = "1.0.0"
INSPECTOR_VERSION: Final[str] = "1.1.0"
SUB_BILLION_LIMIT: Final[int] = 1_000_000_000
_MAX_INLINE_EVIDENCE_BYTES: Final[int] = 512
_MAX_EVIDENCE_SAMPLES: Final[int] = 16
_MAX_TOKEN_ID: Final[int] = (1 << 63) - 1

# Safetensors 0.8 dtype bit widths.  Unknown future dtypes fail closed until
# their packing and alignment semantics are reviewed here.
_DTYPE_BITS: Final[dict[str, int]] = {
    "BOOL": 8,
    "F4": 4,
    "F6_E2M3": 6,
    "F6_E3M2": 6,
    "U8": 8,
    "I8": 8,
    "F8_E5M2": 8,
    "F8_E4M3": 8,
    "F8_E8M0": 8,
    "F8_E4M3FNUZ": 8,
    "F8_E5M2FNUZ": 8,
    "I16": 16,
    "U16": 16,
    "F16": 16,
    "BF16": 16,
    "I32": 32,
    "U32": 32,
    "F32": 32,
    "C64": 64,
    "F64": 64,
    "I64": 64,
    "U64": 64,
}
_SUBBYTE_DTYPES: Final[frozenset[str]] = frozenset(
    {dtype for dtype, bits in _DTYPE_BITS.items() if bits < 8}
)
_LOW_PRECISION_DTYPES: Final[frozenset[str]] = frozenset(
    {dtype for dtype, bits in _DTYPE_BITS.items() if bits < 16}
)
_INTEGER_DTYPES: Final[frozenset[str]] = frozenset(
    dtype for dtype in _DTYPE_BITS if dtype.startswith(("I", "U")) or dtype == "BOOL"
)
_UNSAFE_OR_MIXED_WEIGHT_SUFFIXES: Final[tuple[str, ...]] = (
    ".bin",
    ".ckpt",
    ".h5",
    ".index",
    ".gguf",
    ".msgpack",
    ".npy",
    ".npz",
    ".onnx",
    ".pt",
    ".pth",
)
_TOKENIZER_CONFIGURATION_FILENAMES: Final[frozenset[str]] = frozenset(
    {
        "added_tokens.json",
        "special_tokens_map.json",
        "tokenizer_config.json",
    }
)
_TOKENIZER_DEFINITION_FILENAMES: Final[frozenset[str]] = frozenset(
    {
        "tekken.json",
        "tokenizer.json",
    }
)
_TOKENIZER_VOCABULARY_FILENAMES: Final[frozenset[str]] = frozenset(
    {
        "merges.txt",
        "sentencepiece.model",
        "sentencepiece.bpe.model",
        "spm.model",
        "spiece.model",
        "tokenizer.model",
        "vocab.json",
        "vocab.txt",
    }
)
_PROMPT_TEMPLATE_FILENAMES: Final[frozenset[str]] = frozenset(
    {"chat_template.jinja"}
)
_TOKENIZER_FILENAMES: Final[frozenset[str]] = frozenset(
    _TOKENIZER_CONFIGURATION_FILENAMES
    | _TOKENIZER_DEFINITION_FILENAMES
    | _TOKENIZER_VOCABULARY_FILENAMES
    | _PROMPT_TEMPLATE_FILENAMES
)
_TOKENIZER_CODE_FILENAME_RE: Final[re.Pattern[str]] = re.compile(
    r"^tokenization_[A-Za-z0-9_]+\.py$"
)
_COMPONENT_ORDER: Final[tuple[str, ...]] = (
    "embedding",
    "output_head",
    "attention",
    "ffn",
    "normalization",
    "expert",
    "router",
    "other",
)

_EXPERT_TENSOR_RE = re.compile(
    r"(?:^|\.)(?:experts?|shared_experts?|expert_[0-9]+)\.(?:[0-9]+\.)?",
    re.IGNORECASE,
)
_ROUTER_TENSOR_RE = re.compile(
    r"(?:^|\.)(?:routers?|block_sparse_moe\.gate|moe\.gate)(?:\.|$)",
    re.IGNORECASE,
)
_LAYER_TENSOR_RE = re.compile(
    r"(?:^|\.)(?:layers?|blocks?|h)\.([0-9]+)(?:\.|$)", re.IGNORECASE
)
_MOE_ARCHITECTURE_RE = re.compile(
    r"(?:moe|mixtral|switch|sparse.?expert|expert.?mixture)", re.IGNORECASE
)
_KNOWN_DENSE_ARCHITECTURE_RE = re.compile(
    r"(?:bert|bloom|codegen|falcon|gemma|gpt2|gpt.?neox|llama|mistral|"
    r"olmo|opt|phi|qwen|smollm|starcoder)",
    re.IGNORECASE,
)
_QUANTIZED_TENSOR_RE = re.compile(
    r"(?:^|\.)(?:qweight|qzeros|quant_state|absmax|scales?|zeros?|"
    r"weight_scale(?:_inv)?)(?:\.|$)",
    re.IGNORECASE,
)

_EXPERT_COUNT_KEYS: Final[frozenset[str]] = frozenset(
    {
        "expert_capacity",
        "moe_num_experts",
        "moe_intermediate_size",
        "n_routed_experts",
        "n_shared_experts",
        "num_experts",
        "num_experts_per_tok",
        "num_experts_per_token",
        "num_local_experts",
        "num_selected_experts",
        "num_sparse_experts",
    }
)
_MOE_FLAG_KEYS: Final[frozenset[str]] = frozenset({"is_moe", "use_moe"})
_ROUTER_CONFIG_KEYS: Final[frozenset[str]] = frozenset(
    {
        "decoder_sparse_step",
        "first_k_dense_replace",
        "moe_layer_freq",
        "moe_layer_frequency",
        "norm_topk_prob",
        "output_router_logits",
        "router_aux_loss_coef",
        "router_bias",
        "router_jitter_noise",
        "router_z_loss_coef",
        "scoring_func",
        "topk_method",
    }
)
_CONSERVATIVE_MOE_CONFIG_KEY_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:moe|expert|router)", re.IGNORECASE
)
_MAX_CONFIG_MOE_MARKERS: Final[int] = 4_096
_QUANT_CONFIG_KEYS: Final[frozenset[str]] = frozenset(
    {
        "bits",
        "load_in_4bit",
        "load_in_8bit",
        "quant_method",
        "quantization_config",
    }
)


class ModelArtifactInspectionError(ValueError):
    """Raised when a local artifact cannot be safely or unambiguously inspected."""

    def __init__(self, issues: str | Iterable[str]) -> None:
        if isinstance(issues, str):
            normalized = (issues,)
        else:
            normalized = tuple(str(issue) for issue in issues)
        if not normalized:
            normalized = ("model artifact inspection failed",)
        self.issues = normalized
        super().__init__(
            "model artifact inspection failed:\n- " + "\n- ".join(normalized)
        )


@dataclass(frozen=True, slots=True)
class InspectionLimits:
    """Resource ceilings applied before payload parsing or hashing."""

    max_files: int = 4_096
    max_config_bytes: int = 4 * 1024 * 1024
    max_index_bytes: int = 32 * 1024 * 1024
    max_tokenizer_json_bytes: int = 256 * 1024 * 1024
    max_safetensors_header_bytes: int = 25_000_000
    max_total_header_bytes: int = 100_000_000
    max_total_artifact_bytes: int = 128 * 1024 * 1024 * 1024
    max_tensors: int = 1_000_000
    max_tensor_name_bytes: int = 16 * 1024
    max_tensor_rank: int = 32
    max_model_layers: int = 16_384
    max_dimension: int = (1 << 63) - 1
    max_stored_elements: int = 2_000_000_000_000

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")

    def to_record(self) -> dict[str, int]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


@dataclass(frozen=True, slots=True)
class _TensorRecord:
    name: str
    shard: str
    dtype: str
    bits_per_element: int
    shape: tuple[int, ...]
    begin: int
    end: int
    elements: int
    payload_bytes: int
    component: str

    def layout_record(self) -> dict[str, object]:
        return {
            "name": self.name,
            "shard": self.shard,
            "dtype": self.dtype,
            "bits_per_element": self.bits_per_element,
            "shape": list(self.shape),
            "data_offsets": [self.begin, self.end],
            "stored_elements": self.elements,
            "payload_bytes": self.payload_bytes,
            "component": self.component,
        }


@dataclass(frozen=True, slots=True)
class _SafetensorFile:
    path: str
    file_sha256: str
    file_bytes: int
    header_json_bytes: int
    header_sha256: str
    payload_bytes: int
    metadata: Mapping[str, str] | None
    tensors: tuple[_TensorRecord, ...]


@dataclass(frozen=True, slots=True)
class _InventoryEntry:
    name: str
    path: Path
    metadata: os.stat_result


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise ModelArtifactInspectionError(
            f"inspection report is not canonical JSON: {type(error).__name__}"
        ) from error


def _value_sha256(value: object) -> str:
    return sha256(_canonical_json_bytes(value)).hexdigest()


def _canonical_sequence_sha256(values: Iterable[object]) -> str:
    digest = sha256()
    digest.update(b"[")
    first = True
    for value in values:
        if not first:
            digest.update(b",")
        digest.update(_canonical_json_bytes(value))
        first = False
    digest.update(b"]")
    return digest.hexdigest()


def _bounded_report_value(value: object) -> object:
    payload = _canonical_json_bytes(value)
    if len(payload) <= _MAX_INLINE_EVIDENCE_BYTES:
        return value
    return {
        "canonical_bytes": len(payload),
        "value_sha256": sha256(payload).hexdigest(),
    }


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ModelArtifactInspectionError(
                "duplicate JSON object key " + _bounded_string_identity(key)
            )
        result[key] = value
    return result


def _bounded_string_identity(value: str) -> str:
    """Describe adversarial JSON text without returning its raw contents."""

    payload = value.encode("utf-8", errors="backslashreplace")
    return f"<bytes={len(payload)},sha256={sha256(payload).hexdigest()}>"


def _reject_nonfinite_number(value: str) -> None:
    raise ModelArtifactInspectionError(f"non-finite JSON number {value!r} is forbidden")


def _parse_finite_float(value: str) -> float:
    try:
        parsed = float(value)
    except (OverflowError, ValueError) as error:
        raise ModelArtifactInspectionError(
            "invalid JSON floating-point number "
            + _bounded_string_identity(value)
        ) from error
    if not math.isfinite(parsed):
        raise ModelArtifactInspectionError(
            "non-finite JSON number "
            + _bounded_string_identity(value)
            + " is forbidden"
        )
    return parsed


def _validate_json_unicode(value: object, *, label: str) -> None:
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, str):
            try:
                current.encode("utf-8")
            except UnicodeEncodeError as error:
                raise ModelArtifactInspectionError(
                    f"{label} contains a string that is not a valid Unicode scalar sequence"
                ) from error
        elif isinstance(current, Mapping):
            stack.extend(current.keys())
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)


def _parse_json(payload: bytes, *, label: str, safetensors_header: bool = False) -> object:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ModelArtifactInspectionError(f"{label} is not valid UTF-8") from error
    try:
        decoder = json.JSONDecoder(
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite_number,
            parse_float=_parse_finite_float,
        )
        if safetensors_header:
            if not payload.startswith(b"{"):
                raise ModelArtifactInspectionError(
                    f"{label} must begin with an ASCII object opener"
                )
            value, end = decoder.raw_decode(text)
            if any(character != " " for character in text[end:]):
                raise ModelArtifactInspectionError(
                    f"{label} has non-space bytes after its JSON object"
                )
            _validate_json_unicode(value, label=label)
            return value
        value, end = decoder.raw_decode(text.lstrip())
        trailing = text.lstrip()[end:]
        if trailing.strip():
            raise ModelArtifactInspectionError(f"{label} has trailing non-whitespace data")
        _validate_json_unicode(value, label=label)
        return value
    except ModelArtifactInspectionError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as error:
        raise ModelArtifactInspectionError(
            f"invalid JSON in {label}: {type(error).__name__}"
        ) from error


def _fingerprint(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _open_regular(
    entry: _InventoryEntry,
) -> tuple[object, tuple[int, int, int, int, int, int]]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(entry.path, flags)
    except OSError as error:
        raise ModelArtifactInspectionError(
            f"cannot open artifact file {entry.name!r}: {type(error).__name__}"
        ) from error
    try:
        current = os.fstat(descriptor)
        if not stat.S_ISREG(current.st_mode):
            raise ModelArtifactInspectionError(
                f"artifact entry {entry.name!r} is no longer a regular file"
            )
        if _fingerprint(current) != _fingerprint(entry.metadata):
            raise ModelArtifactInspectionError(
                f"artifact entry {entry.name!r} changed before inspection"
            )
        handle = os.fdopen(descriptor, "rb", closefd=True)
    except BaseException:
        os.close(descriptor)
        raise
    return handle, _fingerprint(current)


def _ensure_stable(
    handle: object,
    expected: tuple[int, int, int, int, int, int],
    label: str,
) -> None:
    try:
        current = os.fstat(handle.fileno())  # type: ignore[attr-defined]
    except OSError as error:
        raise ModelArtifactInspectionError(
            f"cannot re-inspect artifact file {label!r}: {type(error).__name__}"
        ) from error
    if _fingerprint(current) != expected:
        raise ModelArtifactInspectionError(
            f"artifact file {label!r} changed during inspection"
        )


def _read_exact_and_hash(
    handle: object, *, expected_bytes: int, label: str, capture: bool
) -> tuple[str, bytes | None]:
    """Read exactly the snapshotted size and reject shrinkage or growth."""

    digest = sha256()
    remaining = expected_bytes
    chunks: list[bytes] | None = [] if capture else None
    while remaining:
        chunk = handle.read(min(1024 * 1024, remaining))  # type: ignore[attr-defined]
        if not chunk:
            raise ModelArtifactInspectionError(
                f"artifact file {label!r} ended before its snapshotted size"
            )
        digest.update(chunk)
        if chunks is not None:
            chunks.append(chunk)
        remaining -= len(chunk)
    if handle.read(1):  # type: ignore[attr-defined]
        raise ModelArtifactInspectionError(
            f"artifact file {label!r} grew beyond its snapshotted size"
        )
    return digest.hexdigest(), b"".join(chunks) if chunks is not None else None


def _read_and_hash(
    entry: _InventoryEntry, *, capture: bool, maximum_bytes: int | None = None
) -> tuple[str, bytes | None]:
    if maximum_bytes is not None and entry.metadata.st_size > maximum_bytes:
        raise ModelArtifactInspectionError(
            f"artifact file {entry.name!r} exceeds its {maximum_bytes}-byte limit"
        )
    handle, fingerprint = _open_regular(entry)
    try:
        digest, payload = _read_exact_and_hash(
            handle,
            expected_bytes=entry.metadata.st_size,
            label=entry.name,
            capture=capture,
        )
        _ensure_stable(handle, fingerprint, entry.name)
        return digest, payload
    except ModelArtifactInspectionError:
        raise
    except OSError as error:
        raise ModelArtifactInspectionError(
            f"cannot read artifact file {entry.name!r}: {type(error).__name__}"
        ) from error
    finally:
        handle.close()  # type: ignore[attr-defined]


def _inventory(root: Path, limits: InspectionLimits) -> tuple[_InventoryEntry, ...]:
    try:
        root_metadata = root.lstat()
    except OSError as error:
        raise ModelArtifactInspectionError(
            f"cannot inspect model artifact root: {type(error).__name__}"
        ) from error
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        raise ModelArtifactInspectionError(
            "model artifact root must be a real directory, not a symlink"
        )

    entries: list[_InventoryEntry] = []
    total_bytes = 0
    try:
        with os.scandir(root) as iterator:
            for item in iterator:
                if len(entries) >= limits.max_files:
                    raise ModelArtifactInspectionError(
                        f"artifact contains more than {limits.max_files} entries"
                    )
                try:
                    item.name.encode("utf-8")
                except UnicodeEncodeError as error:
                    raise ModelArtifactInspectionError(
                        "artifact contains a filename that is not valid UTF-8"
                    ) from error
                metadata = item.stat(follow_symlinks=False)
                if stat.S_ISLNK(metadata.st_mode):
                    raise ModelArtifactInspectionError(
                        f"artifact entry {item.name!r} must not be a symlink"
                    )
                if stat.S_ISDIR(metadata.st_mode):
                    raise ModelArtifactInspectionError(
                        f"artifact entry {item.name!r} must not be a directory"
                    )
                if not stat.S_ISREG(metadata.st_mode):
                    raise ModelArtifactInspectionError(
                        f"artifact entry {item.name!r} must be a regular file"
                    )
                total_bytes += metadata.st_size
                if total_bytes > limits.max_total_artifact_bytes:
                    raise ModelArtifactInspectionError(
                        "artifact bytes exceed max_total_artifact_bytes"
                    )
                entries.append(
                    _InventoryEntry(item.name, Path(item.path), metadata)
                )
    except ModelArtifactInspectionError:
        raise
    except OSError as error:
        raise ModelArtifactInspectionError(
            f"cannot inventory model artifact: {type(error).__name__}"
        ) from error
    try:
        final_root_metadata = root.lstat()
    except OSError as error:
        raise ModelArtifactInspectionError(
            f"cannot re-inspect model artifact root: {type(error).__name__}"
        ) from error
    if _fingerprint(final_root_metadata) != _fingerprint(root_metadata):
        raise ModelArtifactInspectionError(
            "model artifact root changed during inventory"
        )
    entries.sort(key=lambda entry: entry.name.encode("utf-8"))
    return tuple(entries)


def _checked_elements(shape: list[object], limits: InspectionLimits, label: str) -> int:
    if len(shape) > limits.max_tensor_rank:
        raise ModelArtifactInspectionError(
            f"{label} exceeds max_tensor_rank {limits.max_tensor_rank}"
        )
    elements = 1
    saw_zero = False
    for dimension in shape:
        if isinstance(dimension, bool) or not isinstance(dimension, int) or dimension < 0:
            raise ModelArtifactInspectionError(
                f"{label} shape dimensions must be non-negative integers"
            )
        if dimension > limits.max_dimension:
            raise ModelArtifactInspectionError(
                f"{label} shape dimension exceeds max_dimension"
            )
        if dimension == 0:
            saw_zero = True
            continue
        if not saw_zero:
            if elements > limits.max_stored_elements // dimension:
                raise ModelArtifactInspectionError(
                    f"{label} element count exceeds max_stored_elements"
                )
            elements *= dimension
    return 0 if saw_zero else elements


def _component_for_tensor(name: str) -> str:
    lowered = name.lower()
    if _EXPERT_TENSOR_RE.search(lowered):
        return "expert"
    if _ROUTER_TENSOR_RE.search(lowered):
        return "router"
    if any(marker in lowered for marker in ("embed_tokens", "word_embeddings", ".wte.")):
        return "embedding"
    if any(marker in lowered for marker in ("lm_head", "output_projection", "output_layer")):
        return "output_head"
    if any(
        marker in lowered
        for marker in (
            "self_attn",
            "attention",
            ".attn.",
            "q_proj",
            "k_proj",
            "v_proj",
            "o_proj",
        )
    ):
        return "attention"
    if any(
        marker in lowered
        for marker in (
            ".mlp.",
            "feed_forward",
            "gate_proj",
            "up_proj",
            "down_proj",
            ".fc1.",
            ".fc2.",
            ".c_fc.",
            ".c_proj.",
        )
    ):
        return "ffn"
    if any(marker in lowered for marker in ("norm", "layer_norm", "layernorm", ".ln_")):
        return "normalization"
    return "other"


def _inspect_safetensor(
    entry: _InventoryEntry, limits: InspectionLimits
) -> _SafetensorFile:
    handle, fingerprint = _open_regular(entry)
    try:
        prefix = handle.read(8)  # type: ignore[attr-defined]
        if len(prefix) != 8:
            raise ModelArtifactInspectionError(
                f"safetensors file {entry.name!r} is shorter than its length prefix"
            )
        header_length = int.from_bytes(prefix, "little", signed=False)
        if header_length == 0 or header_length > limits.max_safetensors_header_bytes:
            raise ModelArtifactInspectionError(
                f"safetensors header length for {entry.name!r} is outside the allowed range"
            )
        if 8 + header_length > entry.metadata.st_size:
            raise ModelArtifactInspectionError(
                f"safetensors header for {entry.name!r} extends beyond the file"
            )
        header_payload = handle.read(header_length)  # type: ignore[attr-defined]
        if len(header_payload) != header_length:
            raise ModelArtifactInspectionError(
                f"safetensors header for {entry.name!r} is truncated"
            )
        header_value = _parse_json(
            header_payload,
            label=f"safetensors header {entry.name!r}",
            safetensors_header=True,
        )
        if not isinstance(header_value, dict):
            raise ModelArtifactInspectionError(
                f"safetensors header {entry.name!r} must be an object"
            )
        header = cast(dict[str, object], header_value)
        raw_metadata = header.pop("__metadata__", None)
        metadata: dict[str, str] | None
        if raw_metadata is None:
            metadata = None
        elif isinstance(raw_metadata, dict) and all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in raw_metadata.items()
        ):
            metadata = cast(dict[str, str], raw_metadata)
        else:
            raise ModelArtifactInspectionError(
                f"safetensors metadata in {entry.name!r} must map strings to strings"
            )
        if not header:
            raise ModelArtifactInspectionError(
                f"safetensors file {entry.name!r} contains no tensors"
            )
        if len(header) > limits.max_tensors:
            raise ModelArtifactInspectionError(
                f"safetensors file {entry.name!r} exceeds max_tensors"
            )
        payload_bytes = entry.metadata.st_size - 8 - header_length
        tensors: list[_TensorRecord] = []
        stored_elements = 0
        for name, raw in header.items():
            if not isinstance(name, str) or not name or "\x00" in name:
                raise ModelArtifactInspectionError(
                    f"safetensors file {entry.name!r} has an invalid tensor name"
                )
            label = (
                f"tensor {_bounded_string_identity(name)} in {entry.name!r}"
            )
            try:
                encoded_name = name.encode("utf-8")
            except UnicodeEncodeError as error:
                raise ModelArtifactInspectionError(
                    f"{label} name is not valid UTF-8"
                ) from error
            if len(encoded_name) > limits.max_tensor_name_bytes:
                raise ModelArtifactInspectionError(
                    f"{label} name exceeds max_tensor_name_bytes"
                )
            if not isinstance(raw, dict):
                raise ModelArtifactInspectionError(f"{label} descriptor must be an object")
            if set(raw) != {"dtype", "shape", "data_offsets"}:
                raise ModelArtifactInspectionError(
                    f"{label} descriptor must contain exactly dtype, shape, and data_offsets"
                )
            dtype = raw.get("dtype")
            shape = raw.get("shape")
            offsets = raw.get("data_offsets")
            if not isinstance(dtype, str) or dtype not in _DTYPE_BITS:
                raise ModelArtifactInspectionError(f"{label} has an unsupported dtype")
            if not isinstance(shape, list):
                raise ModelArtifactInspectionError(f"{label} shape must be an array")
            if (
                not isinstance(offsets, list)
                or len(offsets) != 2
                or any(
                    isinstance(value, bool) or not isinstance(value, int)
                    for value in offsets
                )
            ):
                raise ModelArtifactInspectionError(
                    f"{label} data_offsets must contain two integers"
                )
            begin, end = cast(list[int], offsets)
            if begin < 0 or end < begin or end > payload_bytes:
                raise ModelArtifactInspectionError(f"{label} has invalid data_offsets")
            elements = _checked_elements(shape, limits, label)
            stored_elements += elements
            if stored_elements > limits.max_stored_elements:
                raise ModelArtifactInspectionError(
                    f"safetensors file {entry.name!r} exceeds max_stored_elements"
                )
            bits = _DTYPE_BITS[dtype]
            required_bits = elements * bits
            if required_bits % 8:
                raise ModelArtifactInspectionError(
                    f"{label} has a sub-byte shape that is not byte aligned"
                )
            required_bytes = required_bits // 8
            if end - begin != required_bytes:
                raise ModelArtifactInspectionError(
                    f"{label} byte span does not match dtype and shape"
                )
            tensors.append(
                _TensorRecord(
                    name=name,
                    shard=entry.name,
                    dtype=dtype,
                    bits_per_element=bits,
                    shape=tuple(cast(list[int], shape)),
                    begin=begin,
                    end=end,
                    elements=elements,
                    payload_bytes=required_bytes,
                    component=_component_for_tensor(name),
                )
            )

        cursor = 0
        for tensor in sorted(tensors, key=lambda item: (item.begin, item.end, item.name)):
            if tensor.begin < cursor:
                raise ModelArtifactInspectionError(
                    f"safetensors payload ranges overlap in {entry.name!r}"
                )
            if tensor.begin > cursor:
                raise ModelArtifactInspectionError(
                    f"safetensors payload has an unindexed gap in {entry.name!r}"
                )
            cursor = max(cursor, tensor.end)
        if cursor != payload_bytes:
            raise ModelArtifactInspectionError(
                f"safetensors payload is not entirely indexed in {entry.name!r}"
            )

        handle.seek(0)  # type: ignore[attr-defined]
        file_digest, _ = _read_exact_and_hash(
            handle,
            expected_bytes=entry.metadata.st_size,
            label=entry.name,
            capture=False,
        )
        _ensure_stable(handle, fingerprint, entry.name)
        tensors.sort(key=lambda tensor: tensor.name.encode("utf-8"))
        return _SafetensorFile(
            path=entry.name,
            file_sha256=file_digest,
            file_bytes=entry.metadata.st_size,
            header_json_bytes=header_length,
            header_sha256=sha256(header_payload).hexdigest(),
            payload_bytes=payload_bytes,
            metadata=metadata,
            tensors=tuple(tensors),
        )
    except ModelArtifactInspectionError:
        raise
    except OSError as error:
        raise ModelArtifactInspectionError(
            f"cannot inspect safetensors file {entry.name!r}: {type(error).__name__}"
        ) from error
    finally:
        handle.close()  # type: ignore[attr-defined]


def _safe_shard_name(value: object) -> str | None:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        return None
    path = Path(value)
    if path.is_absolute() or len(path.parts) != 1 or path.name != value:
        return None
    if not value.endswith(".safetensors"):
        return None
    return value


def _looks_like_unsafe_or_mixed_weight(name: str) -> bool:
    lowered = name.lower()
    return lowered.endswith(_UNSAFE_OR_MIXED_WEIGHT_SUFFIXES) or bool(
        re.search(r"\.data-[^/]*$", lowered)
    )


def _validate_shards(
    safetensors: tuple[_SafetensorFile, ...], index_payload: bytes | None
) -> dict[str, object]:
    names_to_shards: dict[str, str] = {}
    duplicate_tensors: list[str] = []
    for shard in safetensors:
        for tensor in shard.tensors:
            if tensor.name in names_to_shards:
                duplicate_tensors.append(tensor.name)
            else:
                names_to_shards[tensor.name] = shard.path
    if duplicate_tensors:
        raise ModelArtifactInspectionError(
            "tensor names occur in multiple safetensors shards"
        )

    if index_payload is None:
        if len(safetensors) != 1:
            raise ModelArtifactInspectionError(
                "multiple safetensors files require model.safetensors.index.json"
            )
        return {
            "mode": "single_file",
            "index_path": None,
            "index_sha256": None,
            "weight_map_entries": None,
            "declared_total_size": None,
        }

    value = _parse_json(index_payload, label="model.safetensors.index.json")
    if not isinstance(value, dict) or set(value) != {"metadata", "weight_map"}:
        raise ModelArtifactInspectionError(
            "safetensors index must contain exactly metadata and weight_map objects"
        )
    metadata = value.get("metadata")
    weight_map = value.get("weight_map")
    if not isinstance(metadata, dict) or not isinstance(weight_map, dict) or not weight_map:
        raise ModelArtifactInspectionError(
            "safetensors index metadata and nonempty weight_map must be objects"
        )
    normalized_map: dict[str, str] = {}
    for tensor_name, raw_shard in weight_map.items():
        shard_name = _safe_shard_name(raw_shard)
        if not isinstance(tensor_name, str) or not tensor_name or shard_name is None:
            raise ModelArtifactInspectionError(
                "safetensors index contains an invalid tensor or shard name"
            )
        normalized_map[tensor_name] = shard_name
    actual_shards = {shard.path for shard in safetensors}
    indexed_shards = set(normalized_map.values())
    if indexed_shards != actual_shards:
        raise ModelArtifactInspectionError(
            "safetensors index shard set does not match artifact files"
        )
    if set(normalized_map) != set(names_to_shards):
        raise ModelArtifactInspectionError(
            "safetensors index tensor set does not match shard headers"
        )
    if any(names_to_shards[name] != shard for name, shard in normalized_map.items()):
        raise ModelArtifactInspectionError(
            "safetensors index maps a tensor to the wrong shard"
        )
    declared_total = metadata.get("total_size")
    if declared_total is not None:
        if isinstance(declared_total, bool) or not isinstance(declared_total, int):
            raise ModelArtifactInspectionError(
                "safetensors index metadata.total_size must be an integer"
            )
        actual_total = sum(shard.payload_bytes for shard in safetensors)
        if declared_total != actual_total:
            raise ModelArtifactInspectionError(
                "safetensors index metadata.total_size does not match payload bytes"
            )
    return {
        "mode": "sharded",
        "index_path": "model.safetensors.index.json",
        "index_sha256": sha256(index_payload).hexdigest(),
        "weight_map_entries": len(normalized_map),
        "declared_total_size": declared_total,
    }


def _active_config_value(value: object) -> bool:
    if value is None or value is False or value == 0 or value == "":
        return False
    if isinstance(value, (list, dict, tuple, set)) and not value:
        return False
    return True


def _active_moe_config_key(key: str, value: object) -> bool:
    """Conservatively identify active expert-routing configuration.

    Exact known keys cover common model configurations.  The substring
    fallback intentionally prefers an ambiguous/MoE outcome over a false dense
    claim for future snake-case, camel-case, or vendor-specific variants.
    Values that explicitly disable a feature (false, zero, empty, or null) are
    not active markers.
    """

    if not _active_config_value(value):
        return False
    return (
        key in _EXPERT_COUNT_KEYS
        or key in _MOE_FLAG_KEYS
        or key in _ROUTER_CONFIG_KEYS
        or _CONSERVATIVE_MOE_CONFIG_KEY_RE.search(key) is not None
    )


def _walk_config(config: Mapping[str, object]) -> Iterable[tuple[str, str, object]]:
    stack: list[tuple[str, object]] = [("$", config)]
    while stack:
        path, value = stack.pop()
        if isinstance(value, Mapping):
            for key in sorted(value, reverse=True):
                if isinstance(key, str):
                    child = value[key]
                    yield f"{path}.{key}", key.lower(), child
                    stack.append((f"{path}.{key}", child))
        elif isinstance(value, list):
            for index in range(len(value) - 1, -1, -1):
                stack.append((f"{path}[{index}]", value[index]))


def _name_evidence(names: Iterable[str]) -> dict[str, object]:
    ordered = sorted(set(names), key=str.encode)
    return {
        "count": len(ordered),
        "names_sha256": _value_sha256(ordered),
        "sample_name_hashes": [
            {
                "name_sha256": sha256(name.encode("utf-8")).hexdigest(),
                "utf8_bytes": len(name.encode("utf-8")),
            }
            for name in ordered[:_MAX_EVIDENCE_SAMPLES]
        ],
    }


def _marker_evidence(markers: Iterable[Mapping[str, object]]) -> dict[str, object]:
    ordered = sorted(
        (dict(marker) for marker in markers),
        key=lambda item: cast(str, item["path"]),
    )
    samples = [
        {
            "path": _bounded_report_value(marker["path"]),
            "value": _bounded_report_value(marker["value"]),
        }
        for marker in ordered[:_MAX_EVIDENCE_SAMPLES]
    ]
    return {
        "count": len(ordered),
        "markers_sha256": _value_sha256(ordered),
        "samples": samples,
    }


def _string_set_evidence(values: Iterable[str]) -> dict[str, object]:
    ordered = sorted(set(values), key=str.encode)
    return {
        "count": len(ordered),
        "values_sha256": _value_sha256(ordered),
        "samples": [
            _bounded_report_value(value)
            for value in ordered[:_MAX_EVIDENCE_SAMPLES]
        ],
    }


def _integer_set_evidence(values: set[int]) -> dict[str, object]:
    ordered = sorted(values)
    return {
        "count": len(ordered),
        "values_sha256": _value_sha256(ordered),
        "minimum": ordered[0] if ordered else None,
        "maximum": ordered[-1] if ordered else None,
        "samples": ordered[:_MAX_EVIDENCE_SAMPLES],
    }


def _classify_architecture(
    config: Mapping[str, object],
    tensors: tuple[_TensorRecord, ...],
    limits: InspectionLimits,
) -> dict[str, object]:
    config_moe: list[dict[str, object]] = []
    quant_config: list[dict[str, object]] = []
    architecture_strings: list[str] = []
    for path, key, value in _walk_config(config):
        if key in {"architectures", "model_type"}:
            if isinstance(value, str):
                architecture_strings.append(value)
            elif isinstance(value, list):
                architecture_strings.extend(item for item in value if isinstance(item, str))
        if _active_moe_config_key(key, value):
            if len(config_moe) >= _MAX_CONFIG_MOE_MARKERS:
                raise ModelArtifactInspectionError(
                    "config exceeds the active expert/router marker limit"
                )
            config_moe.append({"path": path, "value": value})
        if key in _QUANT_CONFIG_KEYS and _active_config_value(value):
            quant_config.append({"path": path, "value": value})
    for marker in architecture_strings:
        if _MOE_ARCHITECTURE_RE.search(marker):
            config_moe.append(
                {"path": "$.architectures_or_model_type", "value": marker}
            )

    expert_names = [
        tensor.name for tensor in tensors if _EXPERT_TENSOR_RE.search(tensor.name)
    ]
    router_names = [
        tensor.name for tensor in tensors if _ROUTER_TENSOR_RE.search(tensor.name)
    ]
    tensor_names = [tensor.name for tensor in tensors]
    recognized_dense_markers = sorted(
        {
            marker
            for marker in architecture_strings
            if _KNOWN_DENSE_ARCHITECTURE_RE.search(marker)
            and not _MOE_ARCHITECTURE_RE.search(marker)
        },
        key=str.encode,
    )
    declared_layer_counts = {
        cast(int, config[key])
        for key in ("num_hidden_layers", "n_layer", "num_layers")
        if isinstance(config.get(key), int)
        and not isinstance(config.get(key), bool)
        and cast(int, config[key]) > 0
    }
    if len(declared_layer_counts) > 1:
        raise ModelArtifactInspectionError(
            "config contains inconsistent top-level layer counts"
        )
    declared_layer_count = (
        next(iter(declared_layer_counts)) if declared_layer_counts else None
    )
    if (
        declared_layer_count is not None
        and declared_layer_count > limits.max_model_layers
    ):
        raise ModelArtifactInspectionError("config layer count exceeds max_model_layers")
    observed_layer_indices: set[int] = set()
    attention_layers: set[int] = set()
    ffn_layers: set[int] = set()
    for tensor in tensors:
        match = _LAYER_TENSOR_RE.search(tensor.name)
        if match is None:
            continue
        raw_layer = match.group(1)
        if len(raw_layer) > 19:
            raise ModelArtifactInspectionError(
                "tensor layer index exceeds max_model_layers"
            )
        layer = int(raw_layer)
        if layer >= limits.max_model_layers:
            raise ModelArtifactInspectionError(
                "tensor layer index exceeds max_model_layers"
            )
        observed_layer_indices.add(layer)
        if tensor.component == "attention":
            attention_layers.add(layer)
        if tensor.component == "ffn":
            ffn_layers.add(layer)
    expected_layers = (
        set(range(cast(int, declared_layer_count)))
        if declared_layer_count is not None
        else set()
    )
    custom_auto_map = any(
        key == "auto_map" and _active_config_value(value)
        for _, key, value in _walk_config(config)
    )
    dense_signals = {
        "recognized_dense_architecture_marker": bool(recognized_dense_markers),
        "no_custom_code_auto_map": not custom_auto_map,
        "attention_tensor": any(tensor.component == "attention" for tensor in tensors),
        "dense_ffn_tensor": any(tensor.component == "ffn" for tensor in tensors),
        "embedding_tensor": any(tensor.component == "embedding" for tensor in tensors),
        "indexed_transformer_layer": any(_LAYER_TENSOR_RE.search(name) for name in tensor_names),
        "positive_hidden_size": any(
            key in {"hidden_size", "n_embd", "d_model"}
            and isinstance(value, int)
            and not isinstance(value, bool)
            and value > 0
            for _, key, value in _walk_config(config)
        ),
        "observed_layers_match_declared_count": bool(expected_layers)
        and observed_layer_indices == expected_layers,
        "every_declared_layer_has_attention": bool(expected_layers)
        and attention_layers == expected_layers,
        "every_declared_layer_has_dense_ffn": bool(expected_layers)
        and ffn_layers == expected_layers,
        "attention_and_dense_ffn_tensor_ranks_at_most_two": all(
            len(tensor.shape) <= 2
            for tensor in tensors
            if tensor.component in {"attention", "ffn"}
        ),
        "positive_layer_count": any(
            key in {"num_hidden_layers", "n_layer", "num_layers"}
            and isinstance(value, int)
            and not isinstance(value, bool)
            and value > 0
            for _, key, value in _walk_config(config)
        ),
        "positive_vocab_size": any(
            key == "vocab_size"
            and isinstance(value, int)
            and not isinstance(value, bool)
            and value > 0
            for _, key, value in _walk_config(config)
        ),
    }
    if config_moe or expert_names or router_names:
        classification: Literal["dense_consistent", "moe", "ambiguous"] = "moe"
        reason = "explicit expert/router evidence is present"
    elif all(dense_signals.values()):
        classification = "dense_consistent"
        reason = (
            "observed config and tensor families are consistent with a dense transformer; "
            "checkpoint completeness is not proven"
        )
    else:
        classification = "ambiguous"
        reason = "absence of MoE markers is insufficient without complete dense evidence"
    return {
        "classification": classification,
        "reason": reason,
        "config_moe_evidence": _marker_evidence(config_moe),
        "expert_tensor_evidence": _name_evidence(expert_names),
        "router_tensor_evidence": _name_evidence(router_names),
        "ordinary_gate_proj_is_router_evidence": False,
        "recognized_dense_architecture_marker_evidence": _string_set_evidence(
            recognized_dense_markers
        ),
        "declared_layer_count": declared_layer_count,
        "observed_layer_index_evidence": _integer_set_evidence(
            observed_layer_indices
        ),
        "dense_signals": dense_signals,
        "config_quantization_evidence": _marker_evidence(quant_config),
    }


def _add_tokenizer_issue(issues: list[str], message: str) -> None:
    if message not in issues and len(issues) < _MAX_EVIDENCE_SAMPLES:
        issues.append(message)


def _tokenizer_source_role(name: str) -> str | None:
    """Return the exact tokenizer/prompt identity role for a top-level file."""

    if name in _PROMPT_TEMPLATE_FILENAMES:
        return "prompt_template"
    if name in _TOKENIZER_CONFIGURATION_FILENAMES:
        return "tokenizer_configuration"
    if name in _TOKENIZER_DEFINITION_FILENAMES:
        return "tokenizer_definition"
    if name in _TOKENIZER_VOCABULARY_FILENAMES:
        return "tokenizer_vocabulary"
    if _TOKENIZER_CODE_FILENAME_RE.fullmatch(name) is not None:
        return "tokenizer_implementation"
    return None


def _register_token(
    by_id: dict[int, str],
    by_token: dict[str, int],
    *,
    token: str,
    token_id: int,
    source: str,
    issues: list[str],
) -> None:
    previous_token = by_id.get(token_id)
    previous_id = by_token.get(token)
    if previous_token is not None and previous_token != token:
        _add_tokenizer_issue(
            issues, f"{source} conflicts with another token at ID {token_id}"
        )
        return
    if previous_id is not None and previous_id != token_id:
        _add_tokenizer_issue(
            issues, f"{source} assigns one token to multiple IDs"
        )
        return
    by_id[token_id] = token
    by_token[token] = token_id


def _tokenizer_registry_from_json(
    value: object,
) -> tuple[dict[int, str], dict[str, int], list[str], list[str], bool]:
    evidence: list[str] = []
    issues: list[str] = []
    by_id: dict[int, str] = {}
    by_token: dict[str, int] = {}
    if not isinstance(value, Mapping):
        return by_id, by_token, evidence, ["tokenizer.json root is not an object"], False
    model = value.get("model")
    if not isinstance(model, Mapping):
        return by_id, by_token, evidence, ["tokenizer.json has no inspectable model object"], False
    vocab = model.get("vocab")
    base_vocab_inspected = False
    if isinstance(vocab, Mapping) and vocab:
        for token, token_id in vocab.items():
            if (
                not isinstance(token, str)
                or isinstance(token_id, bool)
                or not isinstance(token_id, int)
                or token_id < 0
                or token_id > _MAX_TOKEN_ID
            ):
                _add_tokenizer_issue(
                    issues, "tokenizer.json vocabulary entries are invalid"
                )
                break
            _register_token(
                by_id,
                by_token,
                token=token,
                token_id=token_id,
                source="tokenizer.json model vocabulary",
                issues=issues,
            )
        evidence.append("tokenizer.json:model.vocab mapping")
        base_vocab_inspected = True
    elif isinstance(vocab, list) and vocab:
        for token_id, item in enumerate(vocab):
            if (
                not isinstance(item, list)
                or len(item) != 2
                or not isinstance(item[0], str)
                or isinstance(item[1], bool)
                or not isinstance(item[1], (int, float))
                or not math.isfinite(item[1])
            ):
                _add_tokenizer_issue(
                    issues,
                    "tokenizer.json positional vocabulary entries must be token/score pairs"
                )
                break
            _register_token(
                by_id,
                by_token,
                token=item[0],
                token_id=token_id,
                source="tokenizer.json positional vocabulary",
                issues=issues,
            )
        evidence.append("tokenizer.json:model.vocab positional token/score list")
        base_vocab_inspected = True
    else:
        _add_tokenizer_issue(
            issues, "tokenizer.json has no nonempty inspectable vocabulary"
        )

    added = value.get("added_tokens")
    if added is not None:
        if not isinstance(added, list):
            _add_tokenizer_issue(
                issues, "tokenizer.json added_tokens is malformed"
            )
        else:
            for item in added:
                token_id = item.get("id") if isinstance(item, Mapping) else None
                token = item.get("content") if isinstance(item, Mapping) else None
                if (
                    isinstance(token_id, bool)
                    or not isinstance(token_id, int)
                    or token_id < 0
                    or token_id > _MAX_TOKEN_ID
                    or not isinstance(token, str)
                ):
                    _add_tokenizer_issue(
                        issues, "tokenizer.json added token record is invalid"
                    )
                    break
                _register_token(
                    by_id,
                    by_token,
                    token=token,
                    token_id=token_id,
                    source="tokenizer.json added token",
                    issues=issues,
                )
            evidence.append("tokenizer.json:added_tokens")
    return by_id, by_token, evidence, issues, base_vocab_inspected


def _auxiliary_added_token_records(
    parsed_json_sources: Mapping[str, object],
) -> tuple[list[tuple[int, str, str]], list[str], list[str]]:
    """Extract auxiliary IDs while retaining token identity for conflict checks."""

    records: list[tuple[int, str, str]] = []
    evidence: list[str] = []
    issues: list[str] = []
    if "added_tokens.json" in parsed_json_sources:
        value = parsed_json_sources["added_tokens.json"]
        if isinstance(value, Mapping):
            for token, token_id in value.items():
                if (
                    not isinstance(token, str)
                    or isinstance(token_id, bool)
                    or not isinstance(token_id, int)
                    or token_id < 0
                    or token_id > _MAX_TOKEN_ID
                ):
                    _add_tokenizer_issue(
                        issues, "added_tokens.json contains an invalid token ID"
                    )
                    break
                records.append((token_id, token, "added_tokens.json"))
            evidence.append("added_tokens.json token-to-ID mapping")
        elif isinstance(value, list):
            for item in value:
                token_id = item.get("id") if isinstance(item, Mapping) else None
                token = item.get("content") if isinstance(item, Mapping) else None
                if token is None and isinstance(item, Mapping):
                    token = item.get("token")
                if (
                    isinstance(token_id, bool)
                    or not isinstance(token_id, int)
                    or token_id < 0
                    or token_id > _MAX_TOKEN_ID
                    or not isinstance(token, str)
                ):
                    _add_tokenizer_issue(
                        issues, "added_tokens.json contains an invalid token record"
                    )
                    break
                records.append((token_id, token, "added_tokens.json"))
            evidence.append("added_tokens.json explicit token records")
        else:
            _add_tokenizer_issue(
                issues, "added_tokens.json does not expose token IDs"
            )

    tokenizer_config = parsed_json_sources.get("tokenizer_config.json")
    if tokenizer_config is not None:
        if not isinstance(tokenizer_config, Mapping):
            _add_tokenizer_issue(
                issues, "tokenizer_config.json root is not an object"
            )
        else:
            decoder = tokenizer_config.get("added_tokens_decoder")
            if decoder is not None:
                if not isinstance(decoder, Mapping):
                    _add_tokenizer_issue(
                        issues,
                        "tokenizer_config.json added_tokens_decoder is not an object"
                    )
                else:
                    for raw_id, descriptor in decoder.items():
                        token = (
                            descriptor.get("content")
                            if isinstance(descriptor, Mapping)
                            else None
                        )
                        if (
                            not isinstance(raw_id, str)
                            or not raw_id.isascii()
                            or not raw_id.isdecimal()
                            or (len(raw_id) > 1 and raw_id.startswith("0"))
                            or len(raw_id) > 19
                            or not isinstance(token, str)
                        ):
                            _add_tokenizer_issue(
                                issues,
                                "tokenizer_config.json added_tokens_decoder has an invalid record"
                            )
                            break
                        token_id = int(raw_id)
                        if token_id > _MAX_TOKEN_ID:
                            _add_tokenizer_issue(
                                issues,
                                "tokenizer_config.json added_tokens_decoder has an invalid record"
                            )
                            break
                        records.append((token_id, token, "tokenizer_config.json"))
                    evidence.append(
                        "tokenizer_config.json added_tokens_decoder IDs"
                    )
    return records, evidence, issues


def _tokenizer_report(
    file_records: Mapping[str, Mapping[str, object]],
    captured: Mapping[str, bytes],
) -> dict[str, object]:
    sources = sorted(
        (name for name in file_records if _tokenizer_source_role(name) is not None),
        key=str.encode,
    )
    source_records = [
        {
            "path": name,
            "role": _tokenizer_source_role(name),
            "bytes": file_records[name]["bytes"],
            "sha256": file_records[name]["sha256"],
        }
        for name in sources
    ]
    source_hash = (
        _value_sha256(
            {
                "domain": "cbds.model_artifact.tokenizer_prompt_set.v2",
                "files": source_records,
            }
        )
        if source_records
        else None
    )
    parsed_json_sources = {
        name: _parse_json(captured[name], label=name)
        for name in sources
        if name.endswith(".json") and name in captured
    }
    by_id: dict[int, str] = {}
    by_token: dict[str, int] = {}
    evidence: list[str] = []
    issues: list[str] = []
    base_vocab_inspected = False
    status = "absent"
    if "tokenizer.json" in captured:
        by_id, by_token, evidence, issues, base_vocab_inspected = (
            _tokenizer_registry_from_json(
                parsed_json_sources["tokenizer.json"]
            )
        )
        status = (
            "json_inspected"
            if base_vocab_inspected and not issues
            else "json_unresolved"
        )
    elif "vocab.json" in captured:
        vocab = parsed_json_sources["vocab.json"]
        if not isinstance(vocab, Mapping) or not vocab:
            _add_tokenizer_issue(
                issues, "vocab.json must contain a nonempty token-to-ID mapping"
            )
        else:
            for token, token_id in vocab.items():
                if (
                    not isinstance(token, str)
                    or isinstance(token_id, bool)
                    or not isinstance(token_id, int)
                    or token_id < 0
                    or token_id > _MAX_TOKEN_ID
                ):
                    _add_tokenizer_issue(
                        issues,
                        "vocab.json must map tokens to non-negative integer IDs"
                    )
                    break
                _register_token(
                    by_id,
                    by_token,
                    token=token,
                    token_id=token_id,
                    source="vocab.json",
                    issues=issues,
                )
        evidence = ["vocab.json token-to-ID mapping"]
        base_vocab_inspected = bool(vocab)
        status = "json_inspected" if base_vocab_inspected and not issues else "json_unresolved"
    elif any(name.endswith(".model") for name in sources):
        status = "opaque_binary_hashed"
        evidence = ["binary tokenizer source requires a format-specific parser"]
    elif sources:
        status = "source_hashed_vocab_unresolved"
        evidence = ["no dependency-free vocabulary source was present"]

    auxiliary_records, auxiliary_evidence, auxiliary_issues = (
        _auxiliary_added_token_records(parsed_json_sources)
    )
    evidence.extend(auxiliary_evidence)
    issues.extend(auxiliary_issues)
    if base_vocab_inspected:
        for token_id, token, source in auxiliary_records:
            _register_token(
                by_id,
                by_token,
                token=token,
                token_id=token_id,
                source=source,
                issues=issues,
            )
    elif auxiliary_records:
        _add_tokenizer_issue(
            issues,
            "auxiliary added-token IDs cannot establish the missing base vocabulary"
        )
    if issues:
        evidence.extend(issues)
        by_id.clear()
        status = "json_unresolved"

    vocab_size: int | None = None
    contiguous = False
    ids = set(by_id)
    if ids:
        maximum = max(ids)
        contiguous = len(ids) == maximum + 1 and min(ids) == 0
        if contiguous:
            vocab_size = maximum + 1
        else:
            evidence.append("observed token IDs are not contiguous from zero")
    return {
        "status": status,
        "source_files": source_records,
        "source_file_count": len(source_records),
        "tokenizer_set_sha256": source_hash,
        "tokenizer_hash_scope": (
            "domain cbds.model_artifact.tokenizer_prompt_set.v2 over canonical "
            "ordered records containing exactly path, role, bytes, and sha256 for "
            "each recognized top-level tokenizer, prompt-template, or conventional "
            "custom-tokenizer implementation source"
        ),
        "tokenizer_identity_scope": {
            "directory_scope": "top-level regular artifact files only",
            "recognized_exact_filenames": sorted(
                _TOKENIZER_FILENAMES, key=str.encode
            ),
            "recognized_filename_patterns": [
                r"^tokenization_[A-Za-z0-9_]+\.py$"
            ],
            "record_fields": ["path", "role", "bytes", "sha256"],
            "content_treatment": (
                "file bytes are hashed exactly; recognized .json files may also "
                "be parsed for bounded vocabulary evidence, while non-JSON "
                "sources are never parsed as JSON"
            ),
            "subdirectory_policy": (
                "subdirectories are rejected by the enclosing flat-artifact "
                "inspector, including multi-template chat_templates directories"
            ),
            "other_top_level_files": (
                "excluded from tokenizer_set_sha256 but retained in the separate "
                "whole-bundle manifest identity"
            ),
        },
        "locally_inspected_vocab_size": vocab_size,
        "observed_unique_token_ids": len(ids) if ids else None,
        "token_ids_contiguous_from_zero": contiguous if ids else None,
        "evidence": evidence,
    }


def _accounting(
    tensors: tuple[_TensorRecord, ...],
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    dtype: defaultdict[str, Counter[str]] = defaultdict(Counter)
    component: defaultdict[str, Counter[str]] = defaultdict(Counter)
    for tensor in tensors:
        dtype[tensor.dtype].update(
            tensors=1,
            stored_elements=tensor.elements,
            payload_bytes=tensor.payload_bytes,
        )
        component[tensor.component].update(
            tensors=1,
            stored_elements=tensor.elements,
            payload_bytes=tensor.payload_bytes,
        )
    dtype_records = [
        {
            "dtype": name,
            "bits_per_element": _DTYPE_BITS[name],
            "tensor_count": values["tensors"],
            "stored_elements": values["stored_elements"],
            "payload_bytes": values["payload_bytes"],
        }
        for name, values in sorted(dtype.items())
    ]
    component_records = [
        {
            "component": name,
            "tensor_count": component[name]["tensors"],
            "stored_elements": component[name]["stored_elements"],
            "payload_bytes": component[name]["payload_bytes"],
        }
        for name in _COMPONENT_ORDER
        if component[name]["tensors"]
    ]
    return dtype_records, component_records


def _config_summary(config: Mapping[str, object]) -> dict[str, object]:
    selected = (
        "architectures",
        "hidden_size",
        "intermediate_size",
        "model_type",
        "num_attention_heads",
        "num_hidden_layers",
        "num_key_value_heads",
        "tie_word_embeddings",
        "vocab_size",
    )
    return {
        key: _bounded_report_value(config[key])
        for key in selected
        if key in config
    }


def compute_inspection_report_sha256(report: Mapping[str, object]) -> str:
    """Recompute the portable report digest, excluding its digest field only."""

    if not isinstance(report, Mapping):
        raise TypeError("report must be a mapping")
    unsigned = dict(report)
    unsigned.pop("report_sha256", None)
    return _value_sha256(unsigned)


def verify_inspection_report_sha256(report: Mapping[str, object]) -> bool:
    """Return whether a report carries its exact canonical digest."""

    if not isinstance(report, Mapping):
        raise TypeError("report must be a mapping")
    claimed = report.get("report_sha256")
    return (
        isinstance(claimed, str)
        and re.fullmatch(r"[0-9a-f]{64}", claimed) is not None
        and claimed == compute_inspection_report_sha256(report)
    )


def inspect_model_artifact(
    source: str | os.PathLike[str], *, limits: InspectionLimits | None = None
) -> dict[str, object]:
    """Inspect one flat local Safetensors model artifact.

    The returned report is portable: it contains relative file names rather
    than the host path.  ``report_sha256`` hashes canonical JSON excluding only
    that field.  ``dense_consistent`` requires positive config and tensor
    evidence, but deliberately does not prove checkpoint completeness or a
    physical parameter count.  A merely marker-free artifact remains
    ``ambiguous``.
    """

    resolved_limits = InspectionLimits() if limits is None else limits
    if not isinstance(resolved_limits, InspectionLimits):
        raise TypeError("limits must be an InspectionLimits instance or None")
    root = Path(source)
    entries = _inventory(root, resolved_limits)
    by_name = {entry.name: entry for entry in entries}
    if "config.json" not in by_name:
        raise ModelArtifactInspectionError("artifact is missing config.json")
    mixed = [
        name
        for name in by_name
        if _looks_like_unsafe_or_mixed_weight(name)
    ]
    if mixed:
        raise ModelArtifactInspectionError(
            "artifact contains a non-Safetensors or mixed-format weight file"
        )
    weight_names = sorted(
        (name for name in by_name if name.endswith(".safetensors")), key=str.encode
    )
    if not weight_names:
        raise ModelArtifactInspectionError("artifact contains no .safetensors weights")

    index_name = "model.safetensors.index.json"
    index_entries = [name for name in by_name if name.endswith(".safetensors.index.json")]
    if index_entries and index_entries != [index_name]:
        raise ModelArtifactInspectionError(
            "artifact has an unsupported or multiple safetensors index name"
        )

    captured: dict[str, bytes] = {}
    file_records: dict[str, dict[str, object]] = {}
    safetensor_files: list[_SafetensorFile] = []
    total_header_bytes = 0
    for entry in entries:
        if entry.name in weight_names:
            inspected = _inspect_safetensor(entry, resolved_limits)
            safetensor_files.append(inspected)
            total_header_bytes += inspected.header_json_bytes
            if total_header_bytes > resolved_limits.max_total_header_bytes:
                raise ModelArtifactInspectionError(
                    "safetensors headers exceed max_total_header_bytes"
                )
            digest = inspected.file_sha256
            role = "weights"
        else:
            maximum: int | None = None
            capture = False
            if entry.name == "config.json":
                maximum = resolved_limits.max_config_bytes
                capture = True
            elif entry.name == index_name:
                maximum = resolved_limits.max_index_bytes
                capture = True
            elif (
                _tokenizer_source_role(entry.name) is not None
                and entry.name.endswith(".json")
            ):
                maximum = resolved_limits.max_tokenizer_json_bytes
                capture = True
            digest, payload = _read_and_hash(
                entry, capture=capture, maximum_bytes=maximum
            )
            if payload is not None:
                captured[entry.name] = payload
            role = (
                "config"
                if entry.name == "config.json"
                else "weights_index"
                if entry.name == index_name
                else cast(str, _tokenizer_source_role(entry.name))
                if _tokenizer_source_role(entry.name) is not None
                else "other"
            )
        file_records[entry.name] = {
            "path": entry.name,
            "role": role,
            "bytes": entry.metadata.st_size,
            "sha256": digest,
        }

    config_value = _parse_json(captured["config.json"], label="config.json")
    if not isinstance(config_value, dict):
        raise ModelArtifactInspectionError("config.json must contain one object")
    config = cast(dict[str, object], config_value)
    safetensor_tuple = tuple(sorted(safetensor_files, key=lambda item: item.path))
    all_tensors = tuple(
        sorted(
            (tensor for shard in safetensor_tuple for tensor in shard.tensors),
            key=lambda tensor: tensor.name.encode("utf-8"),
        )
    )
    if len(all_tensors) > resolved_limits.max_tensors:
        raise ModelArtifactInspectionError("artifact exceeds max_tensors")
    stored_tensor_elements = sum(tensor.elements for tensor in all_tensors)
    if stored_tensor_elements > resolved_limits.max_stored_elements:
        raise ModelArtifactInspectionError("artifact exceeds max_stored_elements")
    shard_report = _validate_shards(safetensor_tuple, captured.get(index_name))
    architecture = _classify_architecture(config, all_tensors, resolved_limits)
    dtype_accounting, component_accounting = _accounting(all_tensors)
    payload_bytes = sum(shard.payload_bytes for shard in safetensor_tuple)
    file_bytes = sum(shard.file_bytes for shard in safetensor_tuple)
    header_json_bytes = sum(shard.header_json_bytes for shard in safetensor_tuple)
    if stored_tensor_elements <= 0:
        raise ModelArtifactInspectionError("artifact contains no stored tensor elements")
    stored_bits = payload_bytes * 8
    average_bits = round(stored_bits / stored_tensor_elements, 12)

    low_precision_names = [
        tensor.name for tensor in all_tensors if tensor.dtype in _LOW_PRECISION_DTYPES
    ]
    packed_names = [
        tensor.name
        for tensor in all_tensors
        if tensor.dtype in _SUBBYTE_DTYPES
        or (
            tensor.dtype in _INTEGER_DTYPES
            and ("weight" in tensor.name.lower() or _QUANTIZED_TENSOR_RE.search(tensor.name))
        )
        or _QUANTIZED_TENSOR_RE.search(tensor.name)
    ]
    config_quantized = bool(
        cast(
            Mapping[str, object], architecture["config_quantization_evidence"]
        )["count"]
    )
    packing_ambiguous = bool(packed_names or config_quantized)
    classification = cast(str, architecture["classification"])
    below_billion = stored_tensor_elements < SUB_BILLION_LIMIT
    stored_representation_matches_dense_elements = (
        classification == "dense_consistent"
        and below_billion
        and not packing_ambiguous
    )
    caveats = [
        "stored_tensor_element_count counts every serialized tensor element, "
        "including buffers, scales, and packing tensors; it is not a "
        "trainable-parameter count",
        "header inspection does not prove runtime loadability, forward "
        "correctness, or exporter completeness",
        "shared, tied, omitted, and auxiliary tensors follow the exporter representation",
    ]
    if packing_ambiguous:
        caveats.append(
            "packed or quantized tensors may encode a different number of "
            "logical weights; format-specific decoding is required before a "
            "physical/logical parameter claim"
        )

    tokenizer = _tokenizer_report(file_records, captured)
    config_vocab = config.get("vocab_size")
    tokenizer["config_vocab_size"] = (
        config_vocab
        if isinstance(config_vocab, int) and not isinstance(config_vocab, bool)
        else None
    )
    local_vocab = tokenizer["locally_inspected_vocab_size"]
    tokenizer["matches_config_vocab_size"] = (
        local_vocab == config_vocab
        if isinstance(local_vocab, int)
        and isinstance(config_vocab, int)
        and not isinstance(config_vocab, bool)
        else None
    )

    shard_records = [
        {
            "path": shard.path,
            "file_sha256": shard.file_sha256,
            "file_bytes": shard.file_bytes,
            "header_prefix_bytes": 8,
            "header_json_bytes": shard.header_json_bytes,
            "header_sha256": shard.header_sha256,
            "payload_bytes": shard.payload_bytes,
            "tensor_count": len(shard.tensors),
            "metadata_entry_count": len(shard.metadata) if shard.metadata else 0,
            "metadata_sha256": (
                _value_sha256(dict(sorted(shard.metadata.items())))
                if shard.metadata
                else None
            ),
        }
        for shard in safetensor_tuple
    ]
    ordered_files = [file_records[name] for name in sorted(file_records, key=str.encode)]
    bundle_identity = [
        {"path": item["path"], "bytes": item["bytes"], "sha256": item["sha256"]}
        for item in ordered_files
    ]
    weight_identity = [
        {"path": item["path"], "bytes": item["bytes"], "sha256": item["sha256"]}
        for item in ordered_files
        if item["role"] in {"weights", "weights_index"}
    ]
    bundle_manifest_hash = _value_sha256(
        {
            "domain": "cbds.model_artifact.bundle_manifest.v1",
            "files": bundle_identity,
        }
    )
    weight_set_hash = _value_sha256(
        {
            "domain": "cbds.model_artifact.weight_set.v1",
            "files": weight_identity,
        }
    )
    report: dict[str, object] = {
        "schema_version": INSPECTOR_SCHEMA_VERSION,
        "inspector_version": INSPECTOR_VERSION,
        "report_hash_scope": "canonical_json_excluding_report_sha256",
        "bundle_manifest_sha256": bundle_manifest_hash,
        "bundle_manifest_hash_scope": (
            "domain-separated canonical JSON of all path/bytes/sha256 records sorted by UTF-8 path"
        ),
        "weight_set_sha256": weight_set_hash,
        "weight_set_hash_scope": (
            "domain-separated canonical JSON of Safetensors and index path/bytes/sha256 records"
        ),
        "resource_limits": resolved_limits.to_record(),
        "config": {
            "path": "config.json",
            "sha256": file_records["config.json"]["sha256"],
            "bytes": file_records["config.json"]["bytes"],
            "declared": _config_summary(config),
        },
        "files": ordered_files,
        "weights": {
            **shard_report,
            "shards": shard_records,
            "tensor_layout_sha256": _canonical_sequence_sha256(
                tensor.layout_record() for tensor in all_tensors
            ),
            "tensor_layout_hash_scope": (
                "canonical_json_of_name_sorted_exact_tensor_layout_records"
            ),
            "tensor_count": len(all_tensors),
            "stored_tensor_element_count": stored_tensor_elements,
            "safetensors_file_bytes": file_bytes,
            "safetensors_header_prefix_bytes": len(safetensor_tuple) * 8,
            "safetensors_header_json_bytes": header_json_bytes,
            "safetensors_payload_bytes": payload_bytes,
            "stored_bits_numerator": stored_bits,
            "stored_elements_denominator": stored_tensor_elements,
            "average_stored_bits_per_element": average_bits,
            "dtype_accounting": dtype_accounting,
            "component_accounting": component_accounting,
        },
        "tokenizer": tokenizer,
        "architecture": architecture,
        "quantization": {
            "low_precision_tensor_evidence": _name_evidence(low_precision_names),
            "packed_or_quantized_tensor_evidence": _name_evidence(packed_names),
            "config_quantization_evidence_present": config_quantized,
            "logical_count_from_stored_elements_ambiguous": packing_ambiguous,
        },
        "claim_qualification": {
            "dense_consistency_evidence_present": classification
            == "dense_consistent",
            "stored_tensor_element_count_below_one_billion": below_billion,
            "packed_logical_count_ambiguous": packing_ambiguous,
            "dense_consistent_with_below_one_billion_stored_elements": (
                stored_representation_matches_dense_elements
            ),
            "architecture_specific_tensor_inventory_verified": False,
            "logical_parameter_count_reconstructed": False,
            "physical_network_parameter_count_qualified": False,
            "scope": (
                "stored Safetensors tensor elements only; no runtime parameter "
                "graph was reconstructed"
            ),
            "caveats": caveats,
        },
    }
    report["report_sha256"] = compute_inspection_report_sha256(report)

    # Detect directory/file replacement after the complete cross-file report
    # has been assembled.  Per-file reads also verify descriptor stability.
    final_entries = _inventory(root, resolved_limits)
    if [(item.name, _fingerprint(item.metadata)) for item in final_entries] != [
        (item.name, _fingerprint(item.metadata)) for item in entries
    ]:
        raise ModelArtifactInspectionError("artifact changed during inspection")
    return report


__all__ = [
    "INSPECTOR_SCHEMA_VERSION",
    "INSPECTOR_VERSION",
    "InspectionLimits",
    "ModelArtifactInspectionError",
    "SUB_BILLION_LIMIT",
    "compute_inspection_report_sha256",
    "inspect_model_artifact",
    "verify_inspection_report_sha256",
]
