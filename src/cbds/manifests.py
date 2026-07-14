"""Immutable experiment manifests and portable hardware-result bundles.

The validators intentionally implement the small JSON Schema subset used by
this repository.  Validation therefore remains available on benchmark hosts
where the optional :mod:`jsonschema` package is not installed.
"""

from __future__ import annotations

import copy
import hashlib
from importlib.resources import files
import json
import math
import os
import re
import stat
import tempfile
from collections.abc import Iterable, Mapping
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any


EXPERIMENT_SCHEMA_VERSION = "2.0.0"
HARDWARE_SCHEMA_VERSION = "2.0.0"
MAX_DOCUMENT_BYTES = 8 * 1024 * 1024
MAX_YAML_ALIASES = 100
_SCHEMA_NAMES = {
    "experiment": "experiment-manifest.schema.json",
    "hardware": "hardware-result.schema.json",
}
_RFC3339_DATETIME = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


class ManifestValidationError(ValueError):
    """Raised when a document violates a schema or cross-field invariant."""

    def __init__(self, errors: str | Iterable[str]) -> None:
        if isinstance(errors, str):
            normalized = (errors,)
        else:
            normalized = tuple(str(error) for error in errors)
        if not normalized:
            normalized = ("manifest validation failed",)
        self.errors = normalized
        super().__init__("; ".join(normalized))


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize *value* to deterministic UTF-8 JSON suitable for hashing."""

    try:
        rendered = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        raise ManifestValidationError(f"value is not canonical JSON: {error}") from error
    return rendered.encode("utf-8")


def canonical_json(value: Any) -> str:
    """Return the canonical JSON representation of *value*."""

    return canonical_json_bytes(value).decode("utf-8")


def sha256_bytes(data: bytes) -> str:
    """Return the lowercase SHA-256 digest of *data*."""

    return hashlib.sha256(data).hexdigest()


def value_sha256(value: Any) -> str:
    """Hash the canonical JSON representation of *value*."""

    return sha256_bytes(canonical_json_bytes(value))


canonical_sha256 = value_sha256


def file_sha256(path: str | os.PathLike[str], *, chunk_size: int = 1024 * 1024) -> str:
    """Stream a file and return its SHA-256 digest."""

    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _bounded_key_identity(key: object) -> str:
    """Describe a mapping key without reflecting unbounded attacker text."""

    if isinstance(key, str):
        encoded = key.encode("utf-8", errors="surrogatepass")
        if len(encoded) <= 128:
            return repr(key)
        return f"<utf8_bytes={len(encoded)} sha256={sha256_bytes(encoded)}>"
    rendered = repr(type(key).__name__)
    return f"<key_type={rendered}>"


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ManifestValidationError(
                f"duplicate object key: {_bounded_key_identity(key)}"
            )
        result[key] = value
    return result


def _load_json(text: str, source: Path) -> Any:
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_json_keys)
    except ManifestValidationError:
        raise
    except json.JSONDecodeError as error:
        raise ManifestValidationError(
            f"invalid JSON in {source}: line {error.lineno}, column {error.colno}: {error.msg}"
        ) from error


def _load_yaml(text: str, source: Path) -> Any:
    try:
        import yaml
    except ImportError as error:  # pragma: no cover - depends on host extras
        raise ManifestValidationError(
            "YAML input requires PyYAML; use JSON or install the optional dependency"
        ) from error

    class UniqueKeySafeLoader(yaml.SafeLoader):
        alias_count = 0

        def compose_node(self, parent: Any, index: Any) -> Any:
            if self.check_event(yaml.AliasEvent):
                self.alias_count += 1
                if self.alias_count > MAX_YAML_ALIASES:
                    raise ManifestValidationError(
                        f"YAML input exceeds the alias limit of {MAX_YAML_ALIASES}"
                    )
            return super().compose_node(parent, index)

    # Manifests use RFC 3339 strings.  Prevent PyYAML from silently converting
    # an unquoted timestamp into a Python datetime, which is not JSON data.
    UniqueKeySafeLoader.yaml_implicit_resolvers = {
        key: [
            resolver
            for resolver in resolvers
            if resolver[0] != "tag:yaml.org,2002:timestamp"
        ]
        for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }

    def construct_mapping(loader: Any, node: Any, deep: bool = False) -> dict[Any, Any]:
        loader.flatten_mapping(node)
        result: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            try:
                duplicate = key in result
            except TypeError as error:
                raise ManifestValidationError(
                    f"unhashable YAML mapping key in {source}"
                ) from error
            if duplicate:
                raise ManifestValidationError(
                    f"duplicate object key: {_bounded_key_identity(key)}"
                )
            result[key] = loader.construct_object(value_node, deep=deep)
        return result

    UniqueKeySafeLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        construct_mapping,
    )
    try:
        return yaml.load(text, Loader=UniqueKeySafeLoader)
    except ManifestValidationError:
        raise
    except yaml.YAMLError as error:
        raise ManifestValidationError(f"invalid YAML in {source}: {error}") from error


def load_document(path: str | os.PathLike[str]) -> Any:
    """Load strict JSON or safe YAML from *path*.

    Duplicate keys are rejected for both formats.  The extension determines
    the parser so that malformed JSON cannot be reinterpreted as YAML.
    """

    source = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(source, flags)
    except (OSError, UnicodeError) as error:
        raise ManifestValidationError(
            f"cannot open document {source}: {type(error).__name__}"
        ) from error
    try:
        with os.fdopen(descriptor, "rb", buffering=0) as handle:
            before = os.fstat(handle.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ManifestValidationError(
                    f"document {source} must be a regular file"
                )
            if before.st_size > MAX_DOCUMENT_BYTES:
                raise ManifestValidationError(
                    f"document {source} exceeds {MAX_DOCUMENT_BYTES} bytes"
                )
            payload = handle.read(MAX_DOCUMENT_BYTES + 1)
            after = os.fstat(handle.fileno())
    except OSError as error:
        raise ManifestValidationError(
            f"cannot read document {source}: {type(error).__name__}"
        ) from error
    fingerprint = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
    if len(payload) > MAX_DOCUMENT_BYTES:
        raise ManifestValidationError(
            f"document {source} exceeds {MAX_DOCUMENT_BYTES} bytes"
        )
    if fingerprint(before) != fingerprint(after) or len(payload) != before.st_size:
        raise ManifestValidationError(f"document {source} changed while being read")
    try:
        text = payload.decode("utf-8")
    except UnicodeError as error:
        raise ManifestValidationError(
            f"document {source} is not valid UTF-8"
        ) from error
    suffix = source.suffix.lower()
    if suffix == ".json":
        return _load_json(text, source)
    if suffix in {".yaml", ".yml"}:
        return _load_yaml(text, source)
    raise ManifestValidationError(
        f"unsupported manifest extension {source.suffix!r}; expected .json, .yaml, or .yml"
    )


def atomic_write_json(
    path: str | os.PathLike[str],
    value: Any,
    *,
    canonical: bool = False,
) -> Path:
    """Atomically replace *path* with deterministic JSON and return its path."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if canonical:
        payload = canonical_json_bytes(value) + b"\n"
    else:
        try:
            payload = (
                json.dumps(
                    value,
                    ensure_ascii=False,
                    allow_nan=False,
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            ).encode("utf-8")
        except (TypeError, ValueError) as error:
            raise ManifestValidationError(f"value is not JSON serializable: {error}") from error

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
    )
    temporary = Path(temporary_name)
    try:
        try:
            destination_mode = stat.S_IMODE(destination.stat().st_mode)
        except FileNotFoundError:
            destination_mode = 0o644
        os.fchmod(descriptor, destination_mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        try:
            directory_fd = os.open(destination.parent, os.O_RDONLY)
        except OSError:  # pragma: no cover - unusual filesystems
            directory_fd = None
        if directory_fd is not None:
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise
    return destination


@lru_cache(maxsize=4)
def _load_repository_schema(name: str) -> dict[str, Any]:
    if name not in _SCHEMA_NAMES:
        raise ValueError(f"unknown schema: {name}")
    resource = files("cbds.schemas").joinpath(_SCHEMA_NAMES[name])
    try:
        text = resource.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ManifestValidationError(
            f"cannot read packaged schema {_SCHEMA_NAMES[name]}: {error}"
        ) from error
    loaded = _load_json(text, Path(_SCHEMA_NAMES[name]))
    if not isinstance(loaded, dict):
        raise ManifestValidationError(
            f"schema {_SCHEMA_NAMES[name]} must be a JSON object"
        )
    return loaded


def _load_schema(
    name: str,
    schema_path: str | os.PathLike[str] | None,
) -> dict[str, Any]:
    if schema_path is None:
        return _load_repository_schema(name)
    loaded = load_document(schema_path)
    if not isinstance(loaded, dict):
        raise ManifestValidationError(f"schema {schema_path} must be a JSON object")
    packaged = _load_repository_schema(name)
    if value_sha256(loaded) != value_sha256(packaged):
        raise ManifestValidationError(
            f"schema {schema_path} does not match the frozen packaged "
            f"{_SCHEMA_NAMES[name]} contract"
        )
    return packaged


def _resolve_local_ref(schema: Mapping[str, Any], reference: str) -> Any:
    if not reference.startswith("#/"):
        raise ManifestValidationError(f"unsupported non-local schema reference: {reference}")
    current: Any = schema
    for raw_part in reference[2:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, Mapping) or part not in current:
            raise ManifestValidationError(f"unresolvable schema reference: {reference}")
        current = current[part]
    return current


def _matches_json_type(value: Any, expected: str) -> bool:
    if expected == "null":
        return value is None
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(value)
        )
    if expected == "string":
        return isinstance(value, str)
    if expected == "array":
        return isinstance(value, list)
    if expected == "object":
        return isinstance(value, Mapping)
    raise ManifestValidationError(f"unsupported JSON Schema type: {expected}")


def _type_label(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, Mapping):
        return "object"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    return type(value).__name__


def _valid_datetime(value: str) -> bool:
    if _RFC3339_DATETIME.fullmatch(value) is None:
        return False
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() is not None


def _json_equal(left: Any, right: Any) -> bool:
    """Apply JSON-Schema value equality without Python's bool/int aliasing."""

    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool) and left == right
    if (
        isinstance(left, (int, float))
        and not isinstance(left, bool)
        and isinstance(right, (int, float))
        and not isinstance(right, bool)
    ):
        return left == right
    if left is None or right is None:
        return left is None and right is None
    if isinstance(left, str) or isinstance(right, str):
        return isinstance(left, str) and isinstance(right, str) and left == right
    if isinstance(left, list) or isinstance(right, list):
        return (
            isinstance(left, list)
            and isinstance(right, list)
            and len(left) == len(right)
            and all(_json_equal(a, b) for a, b in zip(left, right))
        )
    if isinstance(left, Mapping) or isinstance(right, Mapping):
        return (
            isinstance(left, Mapping)
            and isinstance(right, Mapping)
            and set(left) == set(right)
            and all(_json_equal(left[key], right[key]) for key in left)
        )
    return type(left) is type(right) and left == right


def _schema_errors(
    value: Any,
    node: Mapping[str, Any],
    root_schema: Mapping[str, Any],
    path: str = "$",
) -> list[str]:
    if "$ref" in node:
        target = _resolve_local_ref(root_schema, node["$ref"])
        if not isinstance(target, Mapping):
            return [f"{path}: schema reference does not point to an object"]
        return _schema_errors(value, target, root_schema, path)

    if "anyOf" in node:
        branch_errors = [
            _schema_errors(value, branch, root_schema, path)
            for branch in node["anyOf"]
        ]
        if not any(not errors for errors in branch_errors):
            return [f"{path}: does not match any allowed schema"]

    if "const" in node and not _json_equal(value, node["const"]):
        return [f"{path}: must equal {node['const']!r}"]
    if "enum" in node and not any(
        _json_equal(value, candidate) for candidate in node["enum"]
    ):
        return [f"{path}: must be one of {node['enum']!r}"]

    declared_type = node.get("type")
    if declared_type is not None:
        expected_types = [declared_type] if isinstance(declared_type, str) else declared_type
        if not any(_matches_json_type(value, expected) for expected in expected_types):
            return [
                f"{path}: expected {' or '.join(expected_types)}, got {_type_label(value)}"
            ]

    errors: list[str] = []
    if isinstance(value, Mapping):
        required = node.get("required", [])
        for key in required:
            if key not in value:
                errors.append(f"{path}.{key}: required property is missing")
        properties = node.get("properties", {})
        if node.get("additionalProperties") is False:
            for key in value:
                if key not in properties:
                    errors.append(f"{path}.{key}: additional property is not allowed")
        for key, child in properties.items():
            if key in value:
                errors.extend(_schema_errors(value[key], child, root_schema, f"{path}.{key}"))

    if isinstance(value, list):
        if "minItems" in node and len(value) < node["minItems"]:
            errors.append(f"{path}: must contain at least {node['minItems']} items")
        if "maxItems" in node and len(value) > node["maxItems"]:
            errors.append(f"{path}: must contain at most {node['maxItems']} items")
        item_schema = node.get("items")
        if isinstance(item_schema, Mapping):
            for index, item in enumerate(value):
                errors.extend(
                    _schema_errors(item, item_schema, root_schema, f"{path}[{index}]")
                )

    if isinstance(value, str):
        if "minLength" in node and len(value) < node["minLength"]:
            errors.append(f"{path}: string is shorter than {node['minLength']} characters")
        if "maxLength" in node and len(value) > node["maxLength"]:
            errors.append(f"{path}: string is longer than {node['maxLength']} characters")
        if "pattern" in node and re.fullmatch(node["pattern"], value) is None:
            errors.append(f"{path}: does not match required pattern")
        if node.get("format") == "date-time" and not _valid_datetime(value):
            errors.append(f"{path}: must be an RFC 3339 date-time with a timezone")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if not math.isfinite(value):
            errors.append(f"{path}: number must be finite")
        else:
            if "minimum" in node and value < node["minimum"]:
                errors.append(f"{path}: must be >= {node['minimum']}")
            if "maximum" in node and value > node["maximum"]:
                errors.append(f"{path}: must be <= {node['maximum']}")
            if "exclusiveMinimum" in node and value <= node["exclusiveMinimum"]:
                errors.append(f"{path}: must be > {node['exclusiveMinimum']}")
            if "exclusiveMaximum" in node and value >= node["exclusiveMaximum"]:
                errors.append(f"{path}: must be < {node['exclusiveMaximum']}")
    return errors


def _validate_schema(value: Any, schema: Mapping[str, Any]) -> None:
    errors = _schema_errors(value, schema, schema)
    if errors:
        raise ManifestValidationError(errors)


def _unique_values(values: Iterable[Any], path: str, errors: list[str]) -> None:
    seen: set[str] = set()
    for index, value in enumerate(values):
        key = canonical_json(value)
        if key in seen:
            errors.append(f"{path}[{index}]: duplicate value {value!r}")
        seen.add(key)


def _experiment_invariant_errors(manifest: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []

    splits = manifest["data"]["splits"]
    _unique_values((split_["name"] for split_ in splits), "$.data.splits", errors)
    split_by_name = {split_["name"]: split_ for split_ in splits}
    for split_index, split_ in enumerate(splits):
        expected_sealed = split_["role"] == "sealed_test"
        if split_["sealed"] is not expected_sealed:
            errors.append(
                f"$.data.splits[{split_index}].sealed: must be {expected_sealed} "
                f"when role is {split_['role']!r}"
            )
    selection_split = manifest["checkpoint"]["selection_split"]
    if selection_split not in split_by_name:
        errors.append(
            "$.checkpoint.selection_split: must name an entry in $.data.splits"
        )
    elif split_by_name[selection_split]["sealed"]:
        errors.append(
            "$.checkpoint.selection_split: cannot select checkpoints on a sealed split"
        )
    elif split_by_name[selection_split]["role"] != "shadow_validation":
        errors.append(
            "$.checkpoint.selection_split: must have role 'shadow_validation'"
        )

    target = manifest["capability_mixture"]["target"]
    support = manifest["capability_mixture"]["support"]
    entries = target + support
    _unique_values(
        (entry["name"] for entry in entries),
        "$.capability_mixture",
        errors,
    )
    fraction = math.fsum(entry["fraction"] for entry in entries)
    if not math.isclose(fraction, 1.0, rel_tol=0.0, abs_tol=1e-9):
        errors.append(
            f"$.capability_mixture: target and support fractions must sum to 1 (got {fraction})"
        )

    teacher = manifest["teacher"]
    provenance_fields = ("repository", "revision", "verified_corpus_sha256")
    if teacher["enabled"]:
        for field in provenance_fields:
            if teacher[field] is None or teacher[field] == "":
                errors.append(f"$.teacher.{field}: required when the teacher is enabled")
    else:
        for field in provenance_fields:
            if teacher[field] is not None:
                errors.append(f"$.teacher.{field}: must be null when the teacher is disabled")
        if teacher["generation_flops"] != 0:
            errors.append("$.teacher.generation_flops: must be zero when the teacher is disabled")

    operator = manifest["operator"]
    index_groups = operator["structural_indices"]
    group_keys: set[tuple[str, int | None]] = set()
    for group_index, group in enumerate(index_groups):
        group_key = (group["component"], group["layer"])
        if group_key in group_keys:
            errors.append(
                f"$.operator.structural_indices[{group_index}]: duplicate component/layer group"
            )
        group_keys.add(group_key)
        _unique_values(
            group["indices"],
            f"$.operator.structural_indices[{group_index}].indices",
            errors,
        )
    _unique_values(
        (
            (allocation["component"], allocation["layer"])
            for allocation in manifest["operator"]["bit_allocation"]
        ),
        "$.operator.bit_allocation",
        errors,
    )
    factorizations = operator["factorizations"]
    _unique_values(
        (
            factorization["tensor_name"]
            for factorization in factorizations
        ),
        "$.operator.factorizations",
        errors,
    )
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

    mechanism = operator["mechanism"]
    bit_allocations = operator["bit_allocation"]
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
    if expected_stage is not None and manifest["stage"] != expected_stage:
        errors.append(
            f"$.stage: mechanism {mechanism!r} requires stage {expected_stage!r}"
        )
    if operator["mechanism"] == "recycle":
        if operator["archived_weights_sha256"] is None:
            errors.append(
                "$.operator.archived_weights_sha256: required for recycle swap-back evidence"
            )
    elif operator["mechanism"] != "hybrid" and operator["archived_weights_sha256"] is not None:
        errors.append(
            "$.operator.archived_weights_sha256: must be null unless the operator "
            "recycles weights or a hybrid explicitly archives them"
        )

    optimizer = manifest["optimizer"]
    _unique_values(
        (group["name"] for group in optimizer["parameter_groups"]),
        "$.optimizer.parameter_groups",
        errors,
    )
    optimizer_roles = [
        group["role"] for group in optimizer["parameter_groups"]
    ]
    nullable_optimizer_fields = (
        "name",
        "epsilon",
        "gradient_clip",
        "warmup_fraction",
        "schedule",
    )
    if optimizer["enabled"]:
        for field in nullable_optimizer_fields:
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
    else:
        for field in nullable_optimizer_fields:
            if optimizer[field] is not None:
                errors.append(f"$.optimizer.{field}: must be null when optimizer is disabled")
        if optimizer["parameter_groups"]:
            errors.append("$.optimizer.parameter_groups: must be empty when disabled")
        if optimizer["betas"]:
            errors.append("$.optimizer.betas: must be empty when optimizer is disabled")
        if optimizer["total_steps"] != 0:
            errors.append("$.optimizer.total_steps: must be zero when optimizer is disabled")
    if manifest["stage"] == "train" and not optimizer["enabled"]:
        errors.append("$.optimizer.enabled: train stage requires an optimizer")
    freeze_mode = manifest["training_protocol"]["freezing"]["mode"]
    if optimizer["enabled"]:
        if freeze_mode == "full_model" and any(
            role != "all_trainable" for role in optimizer_roles
        ):
            errors.append(
                "$.optimizer.parameter_groups: full_model requires every group "
                "to have role 'all_trainable'"
            )
        elif freeze_mode == "side_only" and any(
            role != "side_branch" for role in optimizer_roles
        ):
            errors.append(
                "$.optimizer.parameter_groups: side_only requires every group "
                "to have role 'side_branch'"
            )
        elif freeze_mode == "phased":
            if any(
                role not in {"side_branch", "backbone"}
                for role in optimizer_roles
            ):
                errors.append(
                    "$.optimizer.parameter_groups: phased permits only 'side_branch' "
                    "and 'backbone' roles"
                )
            for required_role in ("side_branch", "backbone"):
                if required_role not in optimizer_roles:
                    errors.append(
                        "$.optimizer.parameter_groups: phased requires at least one "
                        f"group with role {required_role!r}"
                    )

    tokens = manifest["tokens"]
    if tokens["target"] + tokens["replay"] != tokens["optimizer_visible"]:
        errors.append(
            "$.tokens: optimizer_visible must equal target plus replay tokens"
        )
    if tokens["teacher_derived"] > tokens["target"]:
        errors.append("$.tokens.teacher_derived: cannot exceed target tokens")
    target_fraction = math.fsum(entry["fraction"] for entry in target)
    support_fraction = math.fsum(entry["fraction"] for entry in support)
    expected_target = target_fraction * tokens["optimizer_visible"]
    expected_replay = support_fraction * tokens["optimizer_visible"]
    if abs(tokens["target"] - expected_target) > 1.0:
        errors.append(
            "$.tokens.target: must match the target capability-mixture fraction "
            "within one token"
        )
    if abs(tokens["replay"] - expected_replay) > 1.0:
        errors.append(
            "$.tokens.replay: must match the support capability-mixture fraction "
            "within one token"
        )
    if teacher["enabled"] != (tokens["teacher_derived"] > 0):
        errors.append(
            "$.tokens.teacher_derived: must be positive exactly when teacher.enabled is true"
        )
    if optimizer["enabled"]:
        if tokens["optimizer_visible"] <= 0:
            errors.append(
                "$.tokens.optimizer_visible: must be positive when optimizer is enabled"
            )
    elif tokens["optimizer_visible"] != 0:
        errors.append(
            "$.tokens.optimizer_visible: must be zero when optimizer is disabled"
        )

    flops = manifest["flops"]
    components = (
        flops["selection"],
        flops["teacher_generation"],
        flops["training"],
        flops["compression"],
        flops["export"],
    )
    calculated_total = math.fsum(components)
    if not math.isclose(
        flops["total"],
        calculated_total,
        rel_tol=1e-12,
        abs_tol=max(1e-6, abs(calculated_total) * 1e-12),
    ):
        errors.append(
            f"$.flops.total: must equal the sum of component FLOPs ({calculated_total})"
        )
    if not math.isclose(
        teacher["generation_flops"],
        flops["teacher_generation"],
        rel_tol=1e-12,
        abs_tol=max(1e-6, abs(flops["teacher_generation"]) * 1e-12),
    ):
        errors.append(
            "$.teacher.generation_flops: must equal $.flops.teacher_generation"
        )
    if optimizer["enabled"]:
        if flops["training"] <= 0:
            errors.append("$.flops.training: must be positive when optimizer is enabled")
    elif flops["training"] != 0:
        errors.append("$.flops.training: must be zero when optimizer is disabled")

    exported = manifest["export"]
    if factorizations:
        expected_physical_parameters = (
            manifest["model"]["physical_parameters"]
            - factorization_parameter_savings
        )
        if exported["physical_parameters"] != expected_physical_parameters:
            errors.append(
                "$.export.physical_parameters: must equal source physical parameters "
                "minus the committed low-rank factorization savings "
                f"({expected_physical_parameters})"
            )
    if exported["active_parameters"] > exported["physical_parameters"]:
        errors.append("$.export.active_parameters: cannot exceed physical_parameters")
    if exported["nonzero_parameters"] > exported["physical_parameters"]:
        errors.append("$.export.nonzero_parameters: cannot exceed physical_parameters")
    if exported["weight_bytes"] > exported["bundle_bytes"]:
        errors.append("$.export.weight_bytes: cannot exceed bundle_bytes")
    required_weight_bits = (
        exported["physical_parameters"] * exported["average_weight_bits"]
    )
    available_weight_bits = exported["weight_bytes"] * 8
    if available_weight_bits + max(1e-6, required_weight_bits * 1e-12) < required_weight_bits:
        errors.append(
            "$.export.weight_bytes: cannot encode physical_parameters at the "
            "declared average_weight_bits"
        )
    _unique_values(exported["runtime_compatibility"], "$.export.runtime_compatibility", errors)
    return errors


def validate_experiment_manifest(
    manifest: Mapping[str, Any],
    *,
    schema_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Validate and defensively copy an experiment manifest."""

    candidate = copy.deepcopy(manifest)
    schema = _load_schema("experiment", schema_path)
    _validate_schema(candidate, schema)
    invariant_errors = _experiment_invariant_errors(candidate)
    if invariant_errors:
        raise ManifestValidationError(invariant_errors)
    return candidate


def load_experiment_manifest(
    path: str | os.PathLike[str],
    *,
    schema_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Load and validate an experiment manifest from JSON or YAML."""

    loaded = load_document(path)
    if not isinstance(loaded, Mapping):
        raise ManifestValidationError("$: experiment manifest must be an object")
    return validate_experiment_manifest(loaded, schema_path=schema_path)


_HARDWARE_PROTOCOL_BY_WORKLOAD: dict[str, dict[str, Any]] = {
    "cold_load": {
        "cold_start": True,
        "process_model": "independent_process_per_repetition",
        "warmups": 0,
        "repetitions": 5,
        "synchronized_timing": False,
        "randomized_workload_order": False,
    },
    "token_controlled": {
        "cold_start": False,
        "process_model": "single_loaded_process",
        "warmups": 10,
        "repetitions": 30,
        "synchronized_timing": True,
        "randomized_workload_order": True,
    },
    # The real-terminal protocol scores one deterministic prompt/seed attempt.
    # Its prompt order is randomized at the session level, but it is not a
    # 30-repetition latency microbenchmark.
    "real_terminal": {
        "cold_start": False,
        "process_model": "single_loaded_process",
        "warmups": 0,
        "repetitions": 1,
        "synchronized_timing": True,
        "randomized_workload_order": True,
    },
}

_TOKEN_CONTROLLED_WORKLOADS = frozenset(
    {
        (128, 64),
        (512, 64),
        (2048, 64),
        (128, 256),
        (512, 256),
    }
)


def _hardware_protocol_errors(result: Mapping[str, Any]) -> list[str]:
    """Enforce the exact claim protocol documented in HARDWARE.md."""

    errors: list[str] = []
    workload = result["workload"]
    kind = workload["kind"]
    protocol = result["protocol"]
    measurements = result["measurements"]

    expected = _HARDWARE_PROTOCOL_BY_WORKLOAD[kind]
    for field, expected_value in expected.items():
        if protocol[field] != expected_value:
            errors.append(
                f"$.protocol.{field}: workload kind {kind!r} requires "
                f"{expected_value!r}"
            )

    if kind == "cold_load":
        if workload["prompt_tokens"] != 0:
            errors.append("$.workload.prompt_tokens: cold_load requires zero")
        if workload["generated_tokens"] != 0:
            errors.append("$.workload.generated_tokens: cold_load requires zero")
        if workload.get("prompt_sha256") is not None:
            errors.append("$.workload.prompt_sha256: cold_load requires null")
    else:
        if workload["prompt_tokens"] <= 0:
            errors.append(
                f"$.workload.prompt_tokens: {kind} requires a positive token count"
            )
        if workload.get("prompt_sha256") is None:
            errors.append(f"$.workload.prompt_sha256: {kind} requires a digest")

    if kind == "token_controlled":
        token_shape = (workload["prompt_tokens"], workload["generated_tokens"])
        if token_shape not in _TOKEN_CONTROLLED_WORKLOADS:
            errors.append(
                "$.workload: token_controlled prompt/generated token counts must "
                "match one of the five frozen microbenchmarks"
            )

    required_summaries = (
        {"load_time_ms"}
        if kind == "cold_load"
        else {"first_token_ms", "wall_time_ms"}
    )
    forbidden_summaries = (
        {
            "first_token_ms",
            "prefill_tokens_per_second",
            "decode_tokens_per_second",
            "wall_time_ms",
        }
        if kind == "cold_load"
        else {"load_time_ms"}
    )
    for field in sorted(required_summaries):
        if measurements[field] is None:
            errors.append(
                f"$.measurements.{field}: required for workload kind {kind!r}"
            )
    for field in sorted(forbidden_summaries):
        if measurements[field] is not None:
            errors.append(
                f"$.measurements.{field}: must be null for workload kind {kind!r}"
            )

    prefill_present = measurements["prefill_tokens_per_second"] is not None
    decode_present = measurements["decode_tokens_per_second"] is not None
    if kind != "cold_load" and prefill_present != decode_present:
        errors.append(
            "$.measurements: prefill_tokens_per_second and "
            "decode_tokens_per_second must both be present or both be null"
        )

    if measurements["peak_host_rss_bytes"] is None:
        errors.append("$.measurements.peak_host_rss_bytes: must be measured")

    return errors


def _hardware_invariant_errors(result: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    artifact = result["artifact"]
    if artifact["active_parameters"] > artifact["physical_parameters"]:
        errors.append("$.artifact.active_parameters: cannot exceed physical_parameters")
    if artifact["nonzero_parameters"] > artifact["physical_parameters"]:
        errors.append("$.artifact.nonzero_parameters: cannot exceed physical_parameters")
    if artifact["weight_bytes"] > artifact["bundle_bytes"]:
        errors.append("$.artifact.weight_bytes: cannot exceed bundle_bytes")
    declared_weight_bits = (
        artifact["physical_parameters"] * artifact["average_weight_bits"]
    )
    if artifact["weight_bytes"] * 8 < declared_weight_bits:
        errors.append(
            "$.artifact.weight_bytes: cannot store physical_parameters at the "
            "declared average_weight_bits"
        )

    hardware = result["hardware"]
    if hardware["logical_threads"] < hardware["physical_cores"]:
        errors.append("$.hardware.logical_threads: cannot be less than physical_cores")

    repetitions = result["protocol"]["repetitions"]
    for measurement_name, summary in result["measurements"].items():
        if not isinstance(summary, Mapping) or "sample_count" not in summary:
            continue
        if summary["sample_count"] != repetitions:
            errors.append(
                f"$.measurements.{measurement_name}.sample_count: must equal "
                f"protocol.repetitions ({repetitions})"
            )
        if not (
            summary["minimum"]
            <= summary["median"]
            <= summary["p95"]
            <= summary["maximum"]
        ):
            errors.append(
                f"$.measurements.{measurement_name}: expected minimum <= median <= p95 <= maximum"
            )
        if summary["sample_count"] == 1 and len(
            {
                summary["minimum"],
                summary["median"],
                summary["p95"],
                summary["maximum"],
            }
        ) != 1:
            errors.append(
                f"$.measurements.{measurement_name}: a one-sample summary must "
                "have identical minimum, median, p95, and maximum"
            )

    correctness = result["correctness"]
    successes = correctness.get("functional_successes")
    tasks = correctness.get("functional_tasks")
    if (successes is None) != (tasks is None):
        errors.append(
            "$.correctness: functional_successes and functional_tasks must both be null or present"
        )
    if successes is not None and tasks is not None and successes > tasks:
        errors.append("$.correctness.functional_successes: cannot exceed functional_tasks")
    if correctness["gate_passed"]:
        required_true = ("model_loaded", "accounting_matched")
        optional_true = (
            "token_hash_matched",
            "executable_outcome_matched",
            "unicode_fallback_passed",
        )
        for field in required_true:
            if correctness[field] is not True:
                errors.append(f"$.correctness.{field}: must be true when gate_passed is true")
        for field in optional_true:
            if correctness[field] is False:
                errors.append(f"$.correctness.{field}: cannot be false when gate_passed is true")
        if correctness["errors"]:
            errors.append("$.correctness.errors: must be empty when gate_passed is true")
    errors.extend(_hardware_protocol_errors(result))
    return errors


def validate_hardware_result(
    result: Mapping[str, Any],
    *,
    schema_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Validate and defensively copy one unbound hardware result.

    Standalone validation enforces the exact clean-worktree measurement
    protocol and checks the hardware-result contract.  It does not establish
    that ``artifact.source_manifest_sha256`` names a real completed experiment,
    that the artifact identity/accounting agrees with such a record, or that
    external raw samples and inspection evidence are authentic.  Use
    :func:`validate_hardware_result_against_experiment_manifest` for that
    evidence-chain check.
    """

    candidate = copy.deepcopy(result)
    schema = _load_schema("hardware", schema_path)
    _validate_schema(candidate, schema)
    invariant_errors = _hardware_invariant_errors(candidate)
    if invariant_errors:
        raise ManifestValidationError(invariant_errors)
    return candidate


def validate_hardware_result_against_experiment_manifest(
    result: Mapping[str, Any],
    completed_record: Mapping[str, Any],
    *,
    hardware_schema_path: str | os.PathLike[str] | None = None,
    experiment_schema_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Validate and bind a hardware result to one completed experiment.

    The completed record's canonical JSON hash is the source identity.  Every
    exported artifact identity and size/accounting field consumed by the
    hardware protocol must then match exactly.  The comparison method and dose
    are also taken from the completed operator rather than accepted as mutable
    hardware-run labels.  Both input mappings are validated before any
    cross-document comparison.
    """

    validated_result = validate_hardware_result(
        result,
        schema_path=hardware_schema_path,
    )
    validated_record = validate_experiment_manifest(
        completed_record,
        schema_path=experiment_schema_path,
    )
    artifact = validated_result["artifact"]
    exported = validated_record["export"]
    errors: list[str] = []

    expected_manifest_sha256 = value_sha256(validated_record)
    if artifact["source_manifest_sha256"] != expected_manifest_sha256:
        errors.append(
            "$.artifact.source_manifest_sha256: must equal the canonical "
            "completed experiment manifest hash"
        )

    field_pairs = (
        ("architecture", "architecture"),
        ("format", "format"),
        ("sha256", "artifact_sha256"),
        ("bundle_sha256", "bundle_sha256"),
        ("tokenizer_sha256", "tokenizer_sha256"),
        ("inspection_report_sha256", "inspection_report_sha256"),
        ("weight_bytes", "weight_bytes"),
        ("bundle_bytes", "bundle_bytes"),
        ("physical_parameters", "physical_parameters"),
        ("active_parameters", "active_parameters"),
        ("nonzero_parameters", "nonzero_parameters"),
        ("average_weight_bits", "average_weight_bits"),
    )
    for artifact_field, export_field in field_pairs:
        if not _json_equal(artifact[artifact_field], exported[export_field]):
            errors.append(
                f"$.artifact.{artifact_field}: must exactly match "
                f"$.export.{export_field} in the completed experiment manifest"
            )
    for artifact_field, operator_field in (("method", "family"), ("dose", "dose")):
        if not _json_equal(
            artifact[artifact_field],
            validated_record["operator"][operator_field],
        ):
            errors.append(
                f"$.artifact.{artifact_field}: must exactly match "
                f"$.operator.{operator_field} in the completed experiment manifest"
            )
    if errors:
        raise ManifestValidationError(errors)
    return validated_result


def load_hardware_result(
    path: str | os.PathLike[str],
    *,
    schema_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Load and validate one hardware result from JSON or YAML."""

    loaded = load_document(path)
    if not isinstance(loaded, Mapping):
        raise ManifestValidationError("$: hardware result must be an object")
    return validate_hardware_result(loaded, schema_path=schema_path)


_HARDWARE_OBSERVATION_FIELDS = {
    "temperature_start_c",
    "temperature_end_c",
    "throttling_observed",
}


def _hardware_stratum(result: Mapping[str, Any]) -> dict[str, Any]:
    hardware = {
        key: copy.deepcopy(value)
        for key, value in result["hardware"].items()
        if key not in _HARDWARE_OBSERVATION_FIELDS
    }
    return {
        "hardware": hardware,
        "runtime": copy.deepcopy(result["software"]),
    }


def _artifact_identity(artifact: Mapping[str, Any]) -> tuple[str, ...]:
    return (
        artifact["name"],
        artifact["format"],
        artifact["method"],
        canonical_json(artifact.get("dose")),
        artifact["source_manifest_sha256"],
    )


def _artifact_fingerprint(artifact: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: copy.deepcopy(artifact[key])
        for key in (
            "architecture",
            "sha256",
            "bundle_sha256",
            "tokenizer_sha256",
            "inspection_report_sha256",
            "weight_bytes",
            "bundle_bytes",
            "physical_parameters",
            "active_parameters",
            "nonzero_parameters",
            "average_weight_bits",
        )
    }


def merge_hardware_results(
    sources: Iterable[str | os.PathLike[str] | Mapping[str, Any]]
    | str
    | os.PathLike[str]
    | Mapping[str, Any],
    *,
    output_path: str | os.PathLike[str] | None = None,
    schema_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Validate and merge results without pooling hardware/runtime strata.

    ``sources`` may contain paths or in-memory mappings.  The returned bundle
    is deterministic: strata and results are sorted by their content-derived
    identifiers.  Repeated sessions remain as individual records.
    """

    if isinstance(sources, (str, os.PathLike, Mapping)):
        source_items: Iterable[str | os.PathLike[str] | Mapping[str, Any]] = [sources]
    else:
        source_items = sources

    results: list[dict[str, Any]] = []
    for source in source_items:
        if isinstance(source, Mapping):
            results.append(validate_hardware_result(source, schema_path=schema_path))
        else:
            results.append(load_hardware_result(source, schema_path=schema_path))
    if not results:
        raise ManifestValidationError("at least one hardware result is required")

    versions = {result["schema_version"] for result in results}
    if len(versions) != 1:
        raise ManifestValidationError(
            f"hardware schema versions do not match: {sorted(versions)!r}"
        )

    run_ids: set[str] = set()
    artifact_fingerprints: dict[tuple[str, ...], dict[str, Any]] = {}
    workload_fingerprints: dict[str, dict[str, Any]] = {}
    strata: dict[str, dict[str, Any]] = {}
    for result in results:
        run_id = result["run_id"]
        if run_id in run_ids:
            raise ManifestValidationError(f"duplicate hardware run_id: {run_id}")
        run_ids.add(run_id)

        artifact = result["artifact"]
        artifact_identity = _artifact_identity(artifact)
        fingerprint = _artifact_fingerprint(artifact)
        previous_artifact = artifact_fingerprints.get(artifact_identity)
        if previous_artifact is not None and previous_artifact != fingerprint:
            raise ManifestValidationError(
                "artifact hash/accounting mismatch for comparison identity "
                f"{artifact_identity!r}"
            )
        artifact_fingerprints[artifact_identity] = fingerprint

        workload = result["workload"]
        workload_id = workload["workload_id"]
        previous_workload = workload_fingerprints.get(workload_id)
        if previous_workload is not None and previous_workload != workload:
            raise ManifestValidationError(
                f"workload hash/configuration mismatch for workload_id {workload_id!r}"
            )
        workload_fingerprints[workload_id] = copy.deepcopy(workload)

        stratum = _hardware_stratum(result)
        stratum_id = value_sha256(stratum)
        group = strata.setdefault(
            stratum_id,
            {
                "stratum_sha256": stratum_id,
                **stratum,
                "results": [],
            },
        )
        if group["hardware"] != stratum["hardware"] or group["runtime"] != stratum["runtime"]:
            raise ManifestValidationError("hardware/runtime stratum hash collision")
        group["results"].append(result)

    ordered_strata: list[dict[str, Any]] = []
    for stratum_id in sorted(strata):
        group = strata[stratum_id]
        group["results"].sort(key=lambda result: result["run_id"])
        group["result_count"] = len(group["results"])
        ordered_strata.append(group)
    bundle = {
        "bundle_type": "cbds.hardware-result-collection",
        "schema_version": next(iter(versions)),
        "result_count": len(results),
        "strata": ordered_strata,
    }
    if output_path is not None:
        atomic_write_json(output_path, bundle)
    return bundle


__all__ = [
    "EXPERIMENT_SCHEMA_VERSION",
    "HARDWARE_SCHEMA_VERSION",
    "MAX_DOCUMENT_BYTES",
    "ManifestValidationError",
    "atomic_write_json",
    "canonical_json",
    "canonical_json_bytes",
    "canonical_sha256",
    "file_sha256",
    "load_document",
    "load_experiment_manifest",
    "load_hardware_result",
    "merge_hardware_results",
    "sha256_bytes",
    "validate_experiment_manifest",
    "validate_hardware_result",
    "validate_hardware_result_against_experiment_manifest",
    "value_sha256",
]
