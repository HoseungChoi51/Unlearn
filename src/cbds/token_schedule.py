"""Offline, content-addressed token schedules for the dense-backbone pilot.

The logical training corpus is deliberately tokenizer-independent.  This
module turns one *verified* corpus artifact into a model-specific schedule
without running a trainer.  It records exact visible and supervised token
counts, whole-record selection, EOS and packing boundaries, and hashes of all
derived integer streams.  Prompt and completion text never appears in the
schedule artifact.

Tokenizers are loaded lazily and locally.  Tests and audit programs may inject
an object implementing :class:`TokenizerProtocol`, so importing this module
does not require ``transformers``.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
import ctypes
from dataclasses import dataclass
import errno
from hashlib import sha256
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import struct
import sys
import tempfile
from typing import Any, Final, Protocol, runtime_checkable

from .manifests import canonical_json_bytes, value_sha256
from .training_corpus import (
    TrainingCorpusError,
    validate_training_corpus_artifacts,
)


SCHEDULE_SCHEMA_VERSION: Final[str] = "1.0.0"
SCHEDULE_PREPARER_VERSION: Final[str] = "1.0.0"
OCCURRENCE_SCHEMA_VERSION: Final[str] = "1.0.0"
PACKING_SCHEMA_VERSION: Final[str] = "1.0.0"
MANIFEST_FILE_NAME: Final[str] = "manifest.json"
MANIFEST_SIDECAR_NAME: Final[str] = "manifest.sha256"
OCCURRENCES_FILE_NAME: Final[str] = "occurrences.jsonl"
PACKING_FILE_NAME: Final[str] = "packing.jsonl"
MAX_CORPUS_PARTITION_BYTES: Final[int] = 256 * 1024 * 1024
MAX_MANIFEST_BYTES: Final[int] = 8 * 1024 * 1024
MAX_LEDGER_BYTES: Final[int] = 512 * 1024 * 1024
MAX_RECORDS: Final[int] = 100_000
MAX_VISIBLE_BUDGET: Final[int] = 100_000_000
MAX_TAIL_RESERVE: Final[int] = 1_000_000
MAX_SEQUENCE_LENGTH: Final[int] = 16_384
MAX_TAIL_CANDIDATES: Final[int] = 100_000
MAX_SCHEDULE_OCCURRENCES_PER_PARTITION: Final[int] = 1_000_000
IGNORE_INDEX: Final[int] = -100

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_ID_RE: Final[re.Pattern[str]] = re.compile(r"[a-z0-9][a-z0-9._-]{2,127}\Z")
_TOKENIZER_FILES: Final[frozenset[str]] = frozenset(
    {
        "tokenizer.json",
        "tokenizer_config.json",
        "special_tokens_map.json",
        "added_tokens.json",
        "vocab.json",
        "merges.txt",
        "tokenizer.model",
        "sentencepiece.bpe.model",
        "spiece.model",
    }
)
_CONFIG_KEYS: Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "schedule_id",
        "seed",
        "source_corpus",
        "corpus_eligibility",
        "visible_token_budgets",
        "sequence_length",
        "tail_selection",
        "policies",
    }
)
_SOURCE_KEYS: Final[frozenset[str]] = frozenset(
    {"corpus_sha256", "manifest_sha256"}
)
_BUDGET_KEYS: Final[frozenset[str]] = frozenset({"target", "support"})
_TAIL_KEYS: Final[frozenset[str]] = frozenset(
    {"reserve_visible_tokens", "candidate_occurrences"}
)
_POLICY_KEYS: Final[frozenset[str]] = frozenset(
    {
        "ordering",
        "partition_interleave",
        "oversize_record",
        "tail_exactness",
        "packing",
        "padding",
        "attention",
        "position_ids",
        "labels",
    }
)
_FROZEN_POLICIES: Final[dict[str, str]] = {
    "ordering": "sha256(seed,partition,cycle,record_id)_ascending",
    "partition_interleave": "lowest_consumed_visible_fraction_target_tie",
    "oversize_record": "fail_closed_no_truncation",
    "tail_exactness": "deterministic_01_subset_sum_or_fail_closed",
    "packing": "global_order_greedy_whole_record_no_cross_sequence_split",
    "padding": "right_to_fixed_sequence_length_effective_pad_token",
    "attention": "causal_cross_example_attention_binary_nonpadding_mask_eos_delimited",
    "position_ids": "global_zero_based_monotonic_per_packed_sequence_not_reset_at_example_boundaries_including_padding",
    "labels": "response_tokens_and_explicit_eos_only_prefix_and_padding_ignore_-100",
}
_MANIFEST_KEYS: Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "record_type",
        "preparer",
        "config",
        "config_sha256",
        "source_corpus",
        "tokenizer",
        "renderer",
        "selection",
        "packing",
        "accounting",
        "stream_hashes",
        "files",
        "quality_scope",
        "limitations",
        "schedule_hash_scope",
        "schedule_sha256",
    }
)


class TokenScheduleError(ValueError):
    """Fail-closed schedule preparation or verification error."""

    def __init__(self, issues: str | Iterable[str]) -> None:
        normalized = (issues,) if isinstance(issues, str) else tuple(issues)
        if not normalized:
            normalized = ("token schedule validation failed",)
        self.issues = tuple(str(item) for item in normalized)
        super().__init__("token schedule validation failed:\n- " + "\n- ".join(self.issues))


@runtime_checkable
class TokenizerProtocol(Protocol):
    """Small tokenizer surface used by schedule construction."""

    eos_token_id: int | None
    pad_token_id: int | None
    bos_token_id: int | None
    unk_token_id: int | None
    vocab_size: int

    def __len__(self) -> int: ...

    def encode(self, text: str, *, add_special_tokens: bool = False) -> Sequence[int]: ...

    def get_vocab(self) -> Mapping[str, int]: ...


@dataclass(frozen=True)
class _TokenizedRecord:
    record_id: str
    record_sha256: str
    partition: str
    input_ids: tuple[int, ...]
    labels: tuple[int, ...]
    prefix_tokens: int
    response_tokens: int
    boundary_crossing_tokens: int
    boundary_ignored_response_characters: int

    @property
    def visible_tokens(self) -> int:
        return len(self.input_ids)

    @property
    def supervised_tokens(self) -> int:
        return self.response_tokens + 1


@dataclass(frozen=True)
class _Candidate:
    record: _TokenizedRecord
    stream_ordinal: int
    cycle: int
    rank: int


@dataclass(frozen=True)
class _Selected:
    candidate: _Candidate
    selection_phase: str


def _exact_keys(value: object, expected: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TokenScheduleError(f"{label} must be an object")
    keys = set(value)
    if keys != expected:
        raise TokenScheduleError(
            f"{label} keys differ; missing={sorted(expected - keys)!r}, "
            f"extra={sorted(keys - expected)!r}"
        )
    return value


def _positive_int(value: object, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise TokenScheduleError(f"{label} must be a positive integer")
    if value > maximum:
        raise TokenScheduleError(f"{label} exceeds {maximum}")
    return value


def _sha(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise TokenScheduleError(f"{label} must be a lowercase SHA-256")
    return value


def validate_token_schedule_config(value: object) -> dict[str, Any]:
    """Validate and detach the exact pilot schedule configuration."""

    root = _exact_keys(value, _CONFIG_KEYS, "config")
    if root["schema_version"] != SCHEDULE_SCHEMA_VERSION:
        raise TokenScheduleError(
            f"config.schema_version must equal {SCHEDULE_SCHEMA_VERSION!r}"
        )
    schedule_id = root["schedule_id"]
    if not isinstance(schedule_id, str) or _ID_RE.fullmatch(schedule_id) is None:
        raise TokenScheduleError("config.schedule_id is not a canonical identifier")
    seed = root["seed"]
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise TokenScheduleError("config.seed must be an integer")
    source = _exact_keys(root["source_corpus"], _SOURCE_KEYS, "config.source_corpus")
    corpus_sha = _sha(source["corpus_sha256"], "config.source_corpus.corpus_sha256")
    corpus_manifest_sha = _sha(
        source["manifest_sha256"], "config.source_corpus.manifest_sha256"
    )
    if root["corpus_eligibility"] != "engineering_only_unverified_not_target_policy_accepted":
        raise TokenScheduleError(
            "config.corpus_eligibility must explicitly preserve the corpus as "
            "engineering-only and not target-policy accepted"
        )
    budgets = _exact_keys(
        root["visible_token_budgets"], _BUDGET_KEYS, "config.visible_token_budgets"
    )
    target_budget = _positive_int(
        budgets["target"], "config.visible_token_budgets.target", MAX_VISIBLE_BUDGET
    )
    support_budget = _positive_int(
        budgets["support"], "config.visible_token_budgets.support", MAX_VISIBLE_BUDGET
    )
    sequence_length = _positive_int(
        root["sequence_length"], "config.sequence_length", MAX_SEQUENCE_LENGTH
    )
    tail = _exact_keys(root["tail_selection"], _TAIL_KEYS, "config.tail_selection")
    reserve = _positive_int(
        tail["reserve_visible_tokens"],
        "config.tail_selection.reserve_visible_tokens",
        MAX_TAIL_RESERVE,
    )
    if reserve < sequence_length:
        raise TokenScheduleError("tail reserve must be at least sequence_length")
    candidates = _positive_int(
        tail["candidate_occurrences"],
        "config.tail_selection.candidate_occurrences",
        MAX_TAIL_CANDIDATES,
    )
    policies = _exact_keys(root["policies"], _POLICY_KEYS, "config.policies")
    if dict(policies) != _FROZEN_POLICIES:
        raise TokenScheduleError("config.policies does not equal the frozen pilot policy")
    normalized = {
        "schema_version": SCHEDULE_SCHEMA_VERSION,
        "schedule_id": schedule_id,
        "seed": seed,
        "source_corpus": {
            "corpus_sha256": corpus_sha,
            "manifest_sha256": corpus_manifest_sha,
        },
        "corpus_eligibility": "engineering_only_unverified_not_target_policy_accepted",
        "visible_token_budgets": {
            "target": target_budget,
            "support": support_budget,
        },
        "sequence_length": sequence_length,
        "tail_selection": {
            "reserve_visible_tokens": reserve,
            "candidate_occurrences": candidates,
        },
        "policies": dict(_FROZEN_POLICIES),
    }
    return json.loads(canonical_json_bytes(normalized))


def token_schedule_config_sha256(value: object) -> str:
    return value_sha256(validate_token_schedule_config(value))


def load_local_tokenizer(path: str | os.PathLike[str]) -> TokenizerProtocol:
    """Load a tokenizer without remote code or network resolution."""

    root = Path(path)
    if not root.is_dir() or root.is_symlink():
        raise TokenScheduleError("tokenizer root must be a real local directory")
    try:
        from transformers import AutoTokenizer  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - optional runtime dependency
        raise TokenScheduleError(
            "loading a production tokenizer requires the optional transformers dependency"
        ) from exc
    try:
        tokenizer = AutoTokenizer.from_pretrained(
            str(root.resolve(strict=True)),
            local_files_only=True,
            trust_remote_code=False,
            use_fast=True,
        )
    except Exception as exc:  # pragma: no cover - backend-specific failures
        raise TokenScheduleError(
            f"local tokenizer loading failed: {type(exc).__name__}"
        ) from exc
    return tokenizer


def _fingerprint(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_regular(path: Path, maximum: int, label: str) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NONBLOCK", 0)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:  # pragma: no cover - Linux research requirement
        raise TokenScheduleError("platform lacks O_NOFOLLOW")
    try:
        descriptor = os.open(path, flags | nofollow)
    except OSError as exc:
        raise TokenScheduleError(f"cannot open {label}: {type(exc).__name__}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise TokenScheduleError(f"{label} must be a regular file")
        if before.st_size > maximum:
            raise TokenScheduleError(f"{label} exceeds {maximum} bytes")
        payload = bytearray()
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise TokenScheduleError(f"{label} ended before its snapshotted size")
            payload.extend(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise TokenScheduleError(f"{label} grew during read")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if _fingerprint(before) != _fingerprint(after):
        raise TokenScheduleError(f"{label} changed during read")
    return bytes(payload)


def _strict_json(payload: bytes, label: str) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise TokenScheduleError(f"{label} contains a duplicate object key")
            result[key] = item
        return result

    try:
        return json.loads(
            payload.decode("utf-8", errors="strict"), object_pairs_hook=unique
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TokenScheduleError(f"{label} is not strict UTF-8 JSON") from exc


def _stable_tokenizer_file(path: Path) -> bytes:
    """Read a tokenizer file, allowing a stable HF-cache symlink."""

    try:
        original = path.lstat()
    except OSError as exc:
        raise TokenScheduleError(
            f"cannot inspect tokenizer file {path.name}: {type(exc).__name__}"
        ) from exc
    link_text: str | None = None
    opened = path
    if stat.S_ISLNK(original.st_mode):
        try:
            link_text = os.readlink(path)
            opened = path.resolve(strict=True)
        except OSError as exc:
            raise TokenScheduleError(
                f"cannot resolve tokenizer file {path.name}: {type(exc).__name__}"
            ) from exc
    payload = _read_regular(opened, 128 * 1024 * 1024, f"tokenizer file {path.name}")
    try:
        after = path.lstat()
        if _fingerprint(original) != _fingerprint(after):
            raise TokenScheduleError(f"tokenizer file {path.name} changed during read")
        if link_text is not None and os.readlink(path) != link_text:
            raise TokenScheduleError(f"tokenizer symlink {path.name} changed during read")
    except OSError as exc:
        raise TokenScheduleError(
            f"cannot recheck tokenizer file {path.name}: {type(exc).__name__}"
        ) from exc
    return payload


def _package_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def _tokenizer_identity(
    tokenizer: TokenizerProtocol,
    tokenizer_root: Path,
    *,
    model_embedding_rows: int | None,
) -> dict[str, Any]:
    if not tokenizer_root.is_dir() or tokenizer_root.is_symlink():
        raise TokenScheduleError("tokenizer root must be a real directory")
    files: list[dict[str, Any]] = []
    for name in sorted(_TOKENIZER_FILES):
        path = tokenizer_root / name
        if not path.exists() and not path.is_symlink():
            continue
        payload = _stable_tokenizer_file(path)
        files.append({"path": name, "bytes": len(payload), "sha256": sha256(payload).hexdigest()})
    names = {item["path"] for item in files}
    if "tokenizer_config.json" not in names:
        raise TokenScheduleError("tokenizer_config.json is required for tokenizer identity")
    if not names.intersection(
        {"tokenizer.json", "vocab.json", "tokenizer.model", "sentencepiece.bpe.model", "spiece.model"}
    ):
        raise TokenScheduleError("no supported tokenizer vocabulary file was found")

    config_payload = _stable_tokenizer_file(tokenizer_root / "config.json")
    model_config = _strict_json(config_payload, "model config")
    if not isinstance(model_config, Mapping):
        raise TokenScheduleError("model config must be an object")
    configured_vocab = _positive_int(
        model_config.get("vocab_size"), "model config vocab_size", 10_000_000
    )
    embedding_rows = (
        configured_vocab
        if model_embedding_rows is None
        else _positive_int(model_embedding_rows, "model_embedding_rows", 10_000_000)
    )
    if model_embedding_rows is None:
        embedding_source = "model_config_vocab_size_assumption_not_weight_inspection"
    else:
        embedding_source = "caller_supplied_from_model_artifact_inspection"

    try:
        tokenizer_size = len(tokenizer)
        base_vocab_size = tokenizer.vocab_size
        vocabulary = tokenizer.get_vocab()
    except Exception as exc:
        raise TokenScheduleError(
            f"tokenizer identity inspection failed: {type(exc).__name__}"
        ) from exc
    tokenizer_size = _positive_int(tokenizer_size, "tokenizer length", 10_000_000)
    base_vocab_size = _positive_int(base_vocab_size, "tokenizer vocab_size", 10_000_000)
    if not isinstance(vocabulary, Mapping) or not vocabulary:
        raise TokenScheduleError("tokenizer.get_vocab() must return a nonempty mapping")
    vocab_ids: list[int] = []
    for token, token_id in vocabulary.items():
        if not isinstance(token, str) or isinstance(token_id, bool) or not isinstance(token_id, int):
            raise TokenScheduleError("tokenizer vocabulary must map strings to integers")
        if token_id < 0:
            raise TokenScheduleError("tokenizer vocabulary IDs must be nonnegative")
        vocab_ids.append(token_id)
    if len(vocabulary) != tokenizer_size:
        raise TokenScheduleError("tokenizer length differs from get_vocab() size")
    if max(vocab_ids) >= embedding_rows:
        raise TokenScheduleError("tokenizer vocabulary exceeds model embedding rows")
    if tokenizer_size > embedding_rows:
        raise TokenScheduleError("tokenizer size exceeds model embedding rows")

    special_ids: dict[str, int | None] = {}
    for name in ("bos_token_id", "eos_token_id", "pad_token_id", "unk_token_id"):
        value = getattr(tokenizer, name, None)
        if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
            raise TokenScheduleError(f"tokenizer {name} must be a nonnegative integer or null")
        if isinstance(value, int) and value >= embedding_rows:
            raise TokenScheduleError(f"tokenizer {name} exceeds model embedding rows")
        special_ids[name] = value
    if special_ids["eos_token_id"] is None:
        raise TokenScheduleError("tokenizer eos_token_id is required")
    effective_pad = special_ids["pad_token_id"]
    pad_source = "tokenizer_pad_token_id"
    if effective_pad is None:
        effective_pad = special_ids["eos_token_id"]
        pad_source = "eos_fallback_attention_zero_labels_ignored"

    tokenizer_config = _strict_json(
        _stable_tokenizer_file(tokenizer_root / "tokenizer_config.json"),
        "tokenizer config",
    )
    if not isinstance(tokenizer_config, Mapping):
        raise TokenScheduleError("tokenizer config must be an object")
    runtime_class = f"{type(tokenizer).__module__}.{type(tokenizer).__qualname__}"
    library_name = getattr(tokenizer, "cbds_library_name", None)
    library_version = getattr(tokenizer, "cbds_library_version", None)
    if library_name is None:
        library_name = type(tokenizer).__module__.split(".", 1)[0]
    if not isinstance(library_name, str) or not library_name:
        raise TokenScheduleError("tokenizer library name is unavailable")
    if library_version is None:
        library_version = _package_version(library_name)
    if not isinstance(library_version, str) or not library_version:
        raise TokenScheduleError(
            "tokenizer library version is unavailable; injected tokenizers must expose "
            "cbds_library_version"
        )
    backend_module = None
    backend = getattr(tokenizer, "backend_tokenizer", None)
    if backend is not None:
        backend_module = type(backend).__module__.split(".", 1)[0]
    libraries = {library_name: library_version}
    if backend_module and backend_module != library_name:
        backend_version = _package_version(backend_module)
        if backend_version is not None:
            libraries[backend_module] = backend_version

    return {
        "loading_policy": {
            "local_files_only": True,
            "trust_remote_code": False,
            "use_fast_requested": True,
            "injected_protocol_object": not type(tokenizer).__module__.startswith("transformers"),
        },
        "runtime_class": runtime_class,
        "declared_class": tokenizer_config.get("tokenizer_class"),
        "is_fast": getattr(tokenizer, "is_fast", None),
        "libraries": dict(sorted(libraries.items())),
        "python_version": ".".join(str(part) for part in sys.version_info[:3]),
        "files": files,
        "files_sha256": value_sha256(files),
        "model_config": {
            "path": "config.json",
            "bytes": len(config_payload),
            "sha256": sha256(config_payload).hexdigest(),
            "model_type": model_config.get("model_type"),
            "configured_vocab_size": configured_vocab,
            "input_embedding_rows": embedding_rows,
            "input_embedding_rows_source": embedding_source,
            "tie_word_embeddings": model_config.get("tie_word_embeddings"),
        },
        "sizes": {
            "base_vocab_size": base_vocab_size,
            "tokenizer_size": tokenizer_size,
            "get_vocab_size": len(vocabulary),
            "max_token_id": max(vocab_ids),
            "unused_embedding_rows_at_top": embedding_rows - max(vocab_ids) - 1,
        },
        "special_token_ids": special_ids,
        "effective_pad_token_id": effective_pad,
        "effective_pad_source": pad_source,
    }


def _read_corpus_records(
    root: Path, partition: str, expected_sha256: str
) -> tuple[dict[str, Any], ...]:
    payload = _read_regular(
        root / f"{partition}.jsonl", MAX_CORPUS_PARTITION_BYTES, f"corpus {partition} partition"
    )
    if sha256(payload).hexdigest() != expected_sha256:
        raise TokenScheduleError(
            f"corpus {partition} payload differs from its authenticated identity during tokenization read"
        )
    if not payload or not payload.endswith(b"\n"):
        raise TokenScheduleError(f"corpus {partition} partition must end with LF")
    records: list[dict[str, Any]] = []
    for line in payload.splitlines():
        value = _strict_json(line, f"corpus {partition} record")
        if not isinstance(value, dict):
            raise TokenScheduleError(f"corpus {partition} record must be an object")
        # The corpus verifier already checks the full record contract.  Keep
        # this second read narrowly bound to fields needed for tokenization.
        for key in ("record_id", "record_sha256", "partition", "prompt", "completion"):
            if key not in value:
                raise TokenScheduleError(f"corpus {partition} record lacks {key}")
        if value["partition"] != partition:
            raise TokenScheduleError("corpus record partition changed after verification")
        records.append(value)
        if len(records) > MAX_RECORDS:
            raise TokenScheduleError("corpus partition exceeds record ceiling")
    return tuple(records)


def _renderer_identity(formatting: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        "template": "### Instruction\n{prompt}\n\n### Response\n{completion}",
        "separator": "tokenizer_eos_token",
        "add_eos": True,
        "text_normalization": "crlf_and_cr_to_lf_no_unicode_normalization",
        "loss_scope": "assistant_response_tokens",
    }
    if dict(formatting) != expected:
        raise TokenScheduleError("source corpus formatting is not the frozen neutral renderer")
    renderer = {
        "renderer_version": "1.0.0",
        "source_formatting_sha256": value_sha256(expected),
        "template_sha256": sha256(expected["template"].encode("utf-8")).hexdigest(),
        "component_tokenization": "full_render_once_add_special_tokens_false",
        "response_boundary_assignment": "fast_offsets_token_start_at_or_after_response_start_crossing_token_ignored_exact_prefix_fallback",
        "prefix_template": "### Instruction\n{prompt}\n\n### Response\n",
        "completion_template": "{completion}",
        "explicit_terminal_token": "tokenizer_eos_token_id",
        "source_corpus_loss_scope": "assistant_response_tokens",
        "derived_schedule_label_scope": "assistant_response_tokens_and_explicit_eos_only",
        "normalization": "corpus_pre_normalized_no_additional_normalization",
    }
    return {**renderer, "renderer_sha256": value_sha256(renderer)}


def _encode(tokenizer: TokenizerProtocol, text: str, label: str, embedding_rows: int) -> tuple[int, ...]:
    try:
        encoded = tokenizer.encode(text, add_special_tokens=False)
    except Exception as exc:
        raise TokenScheduleError(f"tokenizer failed on {label}: {type(exc).__name__}") from exc
    if isinstance(encoded, (str, bytes)) or not isinstance(encoded, Sequence):
        raise TokenScheduleError(f"tokenizer output for {label} is not an integer sequence")
    result: list[int] = []
    for token_id in encoded:
        if isinstance(token_id, bool) or not isinstance(token_id, int) or token_id < 0:
            raise TokenScheduleError(f"tokenizer output for {label} contains an invalid ID")
        if token_id >= embedding_rows:
            raise TokenScheduleError(f"tokenizer output for {label} exceeds embedding rows")
        result.append(token_id)
    return tuple(result)


def _encode_with_offsets(
    tokenizer: TokenizerProtocol,
    text: str,
    label: str,
    embedding_rows: int,
) -> tuple[tuple[int, ...], tuple[tuple[int, int], ...] | None]:
    tokenizer_call = getattr(tokenizer, "__call__", None)
    if not callable(tokenizer_call):
        return _encode(tokenizer, text, label, embedding_rows), None
    try:
        encoded = tokenizer_call(
            text,
            add_special_tokens=False,
            return_offsets_mapping=True,
            return_attention_mask=False,
        )
    except (NotImplementedError, TypeError):
        return _encode(tokenizer, text, label, embedding_rows), None
    except Exception as exc:
        raise TokenScheduleError(
            f"tokenizer offset encoding failed on {label}: {type(exc).__name__}"
        ) from exc
    if not isinstance(encoded, Mapping):
        raise TokenScheduleError(f"tokenizer offset output for {label} is not a mapping")
    raw_ids = encoded.get("input_ids")
    raw_offsets = encoded.get("offset_mapping")
    if (
        isinstance(raw_ids, (str, bytes))
        or not isinstance(raw_ids, Sequence)
        or isinstance(raw_offsets, (str, bytes))
        or not isinstance(raw_offsets, Sequence)
    ):
        raise TokenScheduleError(f"tokenizer offset output for {label} lacks sequences")
    ids: list[int] = []
    for token_id in raw_ids:
        if isinstance(token_id, bool) or not isinstance(token_id, int) or token_id < 0:
            raise TokenScheduleError(f"tokenizer offset output for {label} has an invalid ID")
        if token_id >= embedding_rows:
            raise TokenScheduleError(f"tokenizer offset output for {label} exceeds embedding rows")
        ids.append(token_id)
    offsets: list[tuple[int, int]] = []
    previous_start = 0
    for raw_offset in raw_offsets:
        if (
            isinstance(raw_offset, (str, bytes))
            or not isinstance(raw_offset, Sequence)
            or len(raw_offset) != 2
        ):
            raise TokenScheduleError(f"tokenizer offset output for {label} has an invalid span")
        start, end = raw_offset
        if (
            isinstance(start, bool)
            or not isinstance(start, int)
            or isinstance(end, bool)
            or not isinstance(end, int)
            or start < 0
            or end <= start
            or end > len(text)
            or start < previous_start
        ):
            raise TokenScheduleError(f"tokenizer offset output for {label} has an invalid span")
        offsets.append((start, end))
        previous_start = start
    if len(ids) != len(offsets) or not ids:
        raise TokenScheduleError(f"tokenizer IDs and offsets for {label} differ in length")
    return tuple(ids), tuple(offsets)


def _tokenize_records(
    tokenizer: TokenizerProtocol,
    records: Sequence[Mapping[str, Any]],
    partition: str,
    *,
    sequence_length: int,
    embedding_rows: int,
    eos_token_id: int,
) -> tuple[_TokenizedRecord, ...]:
    tokenized: list[_TokenizedRecord] = []
    for index, record in enumerate(records):
        prompt = record["prompt"]
        completion = record["completion"]
        if not isinstance(prompt, str) or not isinstance(completion, str):
            raise TokenScheduleError("corpus prompt/completion changed after verification")
        prefix_text = f"### Instruction\n{prompt}\n\n### Response\n"
        rendered_text = prefix_text + completion
        rendered, offsets = _encode_with_offsets(
            tokenizer, rendered_text, f"{partition} rendered record {index}", embedding_rows
        )
        boundary_crossing_tokens = 0
        ignored_response_characters = 0
        if offsets is not None:
            response_start = len(prefix_text)
            label_mask: list[bool] = []
            for start, end in offsets:
                if end <= response_start:
                    label_mask.append(False)
                elif start >= response_start:
                    label_mask.append(True)
                else:
                    label_mask.append(False)
                    boundary_crossing_tokens += 1
                    ignored_response_characters += end - response_start
            if any(label_mask) and any(
                label_mask[position] and not label_mask[position + 1]
                for position in range(len(label_mask) - 1)
            ):
                raise TokenScheduleError("tokenizer response offsets are not a terminal suffix")
            prefix_count = len(label_mask) - sum(label_mask)
            response_count = sum(label_mask)
        else:
            prefix = _encode(tokenizer, prefix_text, f"{partition} prefix {index}", embedding_rows)
            if not prefix:
                raise TokenScheduleError("neutral renderer prefix tokenized to an empty sequence")
            if len(rendered) < len(prefix) or rendered[: len(prefix)] != prefix:
                raise TokenScheduleError(
                    "tokenizer is not prefix-stable at the response boundary and provides no "
                    "usable offsets; strict response-only labels cannot be assigned"
                )
            prefix_count = len(prefix)
            response_count = len(rendered) - prefix_count
            label_mask = [False] * prefix_count + [True] * response_count
        if response_count <= 0:
            raise TokenScheduleError("a nonempty completion has no wholly response-owned token")
        input_ids = rendered + (eos_token_id,)
        if len(input_ids) > sequence_length:
            raise TokenScheduleError(
                f"record {record['record_id']} has {len(input_ids)} visible tokens, "
                f"exceeding sequence_length={sequence_length}; no truncation is allowed"
            )
        labels = tuple(
            token_id if supervised else IGNORE_INDEX
            for token_id, supervised in zip(rendered, label_mask, strict=True)
        ) + (eos_token_id,)
        tokenized.append(
            _TokenizedRecord(
                record_id=str(record["record_id"]),
                record_sha256=str(record["record_sha256"]),
                partition=partition,
                input_ids=input_ids,
                labels=labels,
                prefix_tokens=prefix_count,
                response_tokens=response_count,
                boundary_crossing_tokens=boundary_crossing_tokens,
                boundary_ignored_response_characters=ignored_response_characters,
            )
        )
    if not tokenized:
        raise TokenScheduleError(f"corpus {partition} partition is empty")
    return tuple(tokenized)


def _ordered_cycle(
    records: Sequence[_TokenizedRecord], seed: int, partition: str, cycle: int
) -> tuple[_TokenizedRecord, ...]:
    def key(record: _TokenizedRecord) -> tuple[bytes, str]:
        material = f"{seed}:{partition}:{cycle}:{record.record_id}".encode("utf-8")
        return sha256(material).digest(), record.record_id

    return tuple(sorted(records, key=key))


def _candidate_stream(
    records: Sequence[_TokenizedRecord], seed: int, partition: str
) -> Iterable[_Candidate]:
    ordinal = 0
    cycle = 0
    while True:
        ordered = _ordered_cycle(records, seed, partition, cycle)
        for rank, record in enumerate(ordered):
            yield _Candidate(record=record, stream_ordinal=ordinal, cycle=cycle, rank=rank)
            ordinal += 1
        cycle += 1


def _tail_subset(candidates: Sequence[_Candidate], target: int) -> tuple[int, ...] | None:
    """Return the deterministic first-reach 0/1 subset of candidate indexes."""

    if target == 0:
        return ()
    reachable = 1
    mask = (1 << (target + 1)) - 1
    previous_sum = [-1] * (target + 1)
    previous_candidate = [-1] * (target + 1)
    for candidate_index, candidate in enumerate(candidates):
        width = candidate.record.visible_tokens
        if width > target:
            continue
        newly = ((reachable << width) & mask) & ~reachable
        pending = newly
        while pending:
            least = pending & -pending
            total = least.bit_length() - 1
            previous_sum[total] = total - width
            previous_candidate[total] = candidate_index
            pending ^= least
        reachable |= newly
        if (reachable >> target) & 1:
            break
    if not ((reachable >> target) & 1):
        return None
    chosen: list[int] = []
    total = target
    while total:
        candidate_index = previous_candidate[total]
        if candidate_index < 0:  # pragma: no cover - invariant guard
            raise TokenScheduleError("tail subset predecessor chain is incomplete")
        chosen.append(candidate_index)
        total = previous_sum[total]
    chosen.reverse()
    return tuple(chosen)


def _select_partition(
    records: Sequence[_TokenizedRecord],
    *,
    seed: int,
    partition: str,
    budget: int,
    reserve: int,
    candidate_occurrences: int,
) -> tuple[_Selected, ...]:
    stream = iter(_candidate_stream(records, seed, partition))
    selected: list[_Selected] = []
    visible = 0
    next_candidate: _Candidate | None = None
    while budget - visible > reserve:
        candidate = next(stream)
        if candidate.record.visible_tokens <= budget - visible - reserve:
            selected.append(_Selected(candidate, "prefix"))
            visible += candidate.record.visible_tokens
            if len(selected) > MAX_SCHEDULE_OCCURRENCES_PER_PARTITION:
                raise TokenScheduleError(
                    f"{partition} schedule exceeds the occurrence ceiling"
                )
        else:
            next_candidate = candidate
            break
    remainder = budget - visible
    tail: list[_Candidate] = []
    if next_candidate is not None:
        tail.append(next_candidate)
    while len(tail) < candidate_occurrences:
        tail.append(next(stream))
    chosen = _tail_subset(tail, remainder)
    if chosen is None:
        lengths_digest = value_sha256([item.record.visible_tokens for item in tail])
        raise TokenScheduleError(
            f"{partition} exact visible-token budget is unreachable within the frozen "
            f"tail candidate window (remaining={remainder}, candidates={len(tail)}, "
            f"lengths_sha256={lengths_digest}); no record was truncated"
        )
    selected.extend(_Selected(tail[index], "tail_exact_subset") for index in chosen)
    if len(selected) > MAX_SCHEDULE_OCCURRENCES_PER_PARTITION:
        raise TokenScheduleError(f"{partition} schedule exceeds the occurrence ceiling")
    total = sum(item.candidate.record.visible_tokens for item in selected)
    if total != budget:  # pragma: no cover - algorithm invariant
        raise TokenScheduleError("exact-sum selection did not reproduce its budget")
    return tuple(selected)


def _interleave(
    target: Sequence[_Selected], support: Sequence[_Selected], target_budget: int, support_budget: int
) -> tuple[_Selected, ...]:
    output: list[_Selected] = []
    target_index = support_index = 0
    target_visible = support_visible = 0
    while target_index < len(target) or support_index < len(support):
        if target_index >= len(target):
            choose_target = False
        elif support_index >= len(support):
            choose_target = True
        else:
            choose_target = target_visible * support_budget <= support_visible * target_budget
        if choose_target:
            selected = target[target_index]
            target_index += 1
            target_visible += selected.candidate.record.visible_tokens
        else:
            selected = support[support_index]
            support_index += 1
            support_visible += selected.candidate.record.visible_tokens
        output.append(selected)
    return tuple(output)


def _uint32_bytes(values: Sequence[int]) -> bytes:
    try:
        return b"".join(struct.pack(">I", value) for value in values)
    except struct.error as exc:
        raise TokenScheduleError("token ID cannot be encoded as uint32") from exc


def _int32_bytes(values: Sequence[int]) -> bytes:
    try:
        return b"".join(struct.pack(">i", value) for value in values)
    except struct.error as exc:
        raise TokenScheduleError("label ID cannot be encoded as int32") from exc


def _jsonl(records: Iterable[Mapping[str, Any]]) -> bytes:
    return b"".join(canonical_json_bytes(record) + b"\n" for record in records)


def _digest_update(digest: Any, payload: bytes) -> None:
    digest.update(payload)


def _build_ledgers(
    selected: Sequence[_Selected],
    *,
    sequence_length: int,
    effective_pad_id: int,
) -> tuple[bytes, bytes, dict[str, Any], dict[str, Any], dict[str, Any]]:
    occurrences: list[dict[str, Any]] = []
    packing: list[dict[str, Any]] = []
    occurrence_counts: Counter[str] = Counter()
    partition_ordinals = {"target": 0, "support": 0}
    selected_token_digest = sha256()
    selected_label_digest = sha256()
    packed_token_digest = sha256()
    packed_label_digest = sha256()
    attention_digest = sha256()
    position_digest = sha256()
    partition_token_digests = {"target": sha256(), "support": sha256()}
    partition_label_digests = {"target": sha256(), "support": sha256()}

    for global_ordinal, item in enumerate(selected):
        record = item.candidate.record
        occurrence = occurrence_counts[record.record_id]
        occurrence_counts[record.record_id] += 1
        input_payload = _uint32_bytes(record.input_ids)
        label_payload = _int32_bytes(record.labels)
        _digest_update(selected_token_digest, input_payload)
        _digest_update(selected_label_digest, label_payload)
        _digest_update(partition_token_digests[record.partition], input_payload)
        _digest_update(partition_label_digests[record.partition], label_payload)
        occurrences.append(
            {
                "schema_version": OCCURRENCE_SCHEMA_VERSION,
                "global_ordinal": global_ordinal,
                "partition": record.partition,
                "partition_ordinal": partition_ordinals[record.partition],
                "record_id": record.record_id,
                "record_sha256": record.record_sha256,
                "record_occurrence": occurrence,
                "selection_phase": item.selection_phase,
                "source_stream": {
                    "ordinal": item.candidate.stream_ordinal,
                    "cycle": item.candidate.cycle,
                    "rank": item.candidate.rank,
                },
                "visible_tokens": record.visible_tokens,
                "supervised_tokens": record.supervised_tokens,
                "prefix_tokens": record.prefix_tokens,
                "response_tokens": record.response_tokens,
                "boundary_crossing_tokens": record.boundary_crossing_tokens,
                "boundary_ignored_response_characters": record.boundary_ignored_response_characters,
                "eos_offset": record.visible_tokens - 1,
                "input_ids_sha256": sha256(input_payload).hexdigest(),
                "labels_sha256": sha256(label_payload).hexdigest(),
            }
        )
        partition_ordinals[record.partition] += 1

    sequence_items: list[tuple[int, _Selected]] = []
    used = 0

    def finish_sequence() -> None:
        nonlocal sequence_items, used
        if not sequence_items:
            return
        sequence_index = len(packing)
        pad = sequence_length - used
        input_ids: list[int] = []
        labels: list[int] = []
        boundaries: list[dict[str, Any]] = []
        offset = 0
        for occurrence_ordinal, selected_item in sequence_items:
            record = selected_item.candidate.record
            start = offset
            input_ids.extend(record.input_ids)
            labels.extend(record.labels)
            offset += record.visible_tokens
            boundaries.append(
                {
                    "occurrence_global_ordinal": occurrence_ordinal,
                    "start": start,
                    "end_exclusive": offset,
                    "eos_position": offset - 1,
                }
            )
        input_ids.extend([effective_pad_id] * pad)
        labels.extend([IGNORE_INDEX] * pad)
        attention = [1] * used + [0] * pad
        positions = list(range(sequence_length))
        input_payload = _uint32_bytes(input_ids)
        label_payload = _int32_bytes(labels)
        attention_payload = bytes(attention)
        position_payload = _uint32_bytes(positions)
        _digest_update(packed_token_digest, input_payload)
        _digest_update(packed_label_digest, label_payload)
        _digest_update(attention_digest, attention_payload)
        _digest_update(position_digest, position_payload)
        packing.append(
            {
                "schema_version": PACKING_SCHEMA_VERSION,
                "sequence_index": sequence_index,
                "sequence_length": sequence_length,
                "visible_tokens": used,
                "padding_tokens": pad,
                "occurrences": boundaries,
                "input_ids_sha256": sha256(input_payload).hexdigest(),
                "labels_sha256": sha256(label_payload).hexdigest(),
                "attention_mask_sha256": sha256(attention_payload).hexdigest(),
                "position_ids_sha256": sha256(position_payload).hexdigest(),
            }
        )
        sequence_items = []
        used = 0

    for ordinal, item in enumerate(selected):
        width = item.candidate.record.visible_tokens
        if used and used + width > sequence_length:
            finish_sequence()
        sequence_items.append((ordinal, item))
        used += width
    finish_sequence()

    accounting: dict[str, Any] = {}
    for partition in ("target", "support"):
        subset = [item.candidate.record for item in selected if item.candidate.record.partition == partition]
        unique = len({record.record_id for record in subset})
        accounting[partition] = {
            "occurrences": len(subset),
            "unique_records": unique,
            "repeated_occurrences": len(subset) - unique,
            "visible_tokens": sum(record.visible_tokens for record in subset),
            "supervised_tokens": sum(record.supervised_tokens for record in subset),
            "prefix_ignored_tokens": sum(record.prefix_tokens for record in subset),
            "explicit_eos_tokens": len(subset),
            "boundary_crossing_tokens": sum(record.boundary_crossing_tokens for record in subset),
            "boundary_ignored_response_characters": sum(
                record.boundary_ignored_response_characters for record in subset
            ),
        }
    padding_tokens = sum(item["padding_tokens"] for item in packing)
    total_visible = sum(item["visible_tokens"] for item in accounting.values())
    accounting["total"] = {
        "occurrences": len(selected),
        "unique_partition_record_pairs": len(
            {(item.candidate.record.partition, item.candidate.record.record_id) for item in selected}
        ),
        "visible_tokens": total_visible,
        "supervised_tokens": sum(item["supervised_tokens"] for item in accounting.values()),
        "packed_sequences": len(packing),
        "packed_token_slots": len(packing) * sequence_length,
        "padding_tokens": padding_tokens,
        "attention_one_tokens": total_visible,
        "attention_zero_tokens": padding_tokens,
    }
    stream_hashes = {
        "encoding": {
            "input_ids": "uint32_big_endian_concatenation",
            "labels": "int32_big_endian_concatenation_ignore_index_-100",
            "attention_mask": "one_unsigned_byte_per_slot",
            "position_ids": "uint32_big_endian_concatenation",
        },
        "selected_visible_input_ids_sha256": selected_token_digest.hexdigest(),
        "selected_visible_labels_sha256": selected_label_digest.hexdigest(),
        "partition_visible_input_ids_sha256": {
            key: digest.hexdigest() for key, digest in partition_token_digests.items()
        },
        "partition_visible_labels_sha256": {
            key: digest.hexdigest() for key, digest in partition_label_digests.items()
        },
        "packed_input_ids_sha256": packed_token_digest.hexdigest(),
        "packed_labels_sha256": packed_label_digest.hexdigest(),
        "packed_attention_mask_sha256": attention_digest.hexdigest(),
        "packed_position_ids_sha256": position_digest.hexdigest(),
    }
    selection_summary = {
        partition: {
            "prefix_occurrences": sum(
                item.selection_phase == "prefix"
                for item in selected
                if item.candidate.record.partition == partition
            ),
            "tail_occurrences": sum(
                item.selection_phase == "tail_exact_subset"
                for item in selected
                if item.candidate.record.partition == partition
            ),
            "maximum_stream_ordinal_used": max(
                item.candidate.stream_ordinal
                for item in selected
                if item.candidate.record.partition == partition
            ),
        }
        for partition in ("target", "support")
    }
    return _jsonl(occurrences), _jsonl(packing), accounting, stream_hashes, selection_summary


def _manifest_bytes(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True)
        + "\n"
    ).encode("utf-8")


def _preparer_identity() -> dict[str, Any]:
    package_root = Path(__file__).resolve(strict=True).parent
    implementation_files: list[dict[str, Any]] = []
    for name in ("manifests.py", "training_corpus.py", "token_schedule.py"):
        payload = _read_regular(
            package_root / name, 4 * 1024 * 1024, f"schedule implementation {name}"
        )
        implementation_files.append(
            {
                "path": f"cbds/{name}",
                "bytes": len(payload),
                "sha256": sha256(payload).hexdigest(),
            }
        )
    return {
        "name": "cbds.token_schedule",
        "version": SCHEDULE_PREPARER_VERSION,
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "implementation_files": implementation_files,
    }


def _file_declaration(path: str, payload: bytes, records: int) -> dict[str, Any]:
    return {
        "path": path,
        "bytes": len(payload),
        "records": records,
        "sha256": sha256(payload).hexdigest(),
    }


def _load_corpus_manifest(root: Path) -> Mapping[str, Any]:
    payload = _read_regular(root / "manifest.json", MAX_MANIFEST_BYTES, "corpus manifest")
    manifest = _strict_json(payload, "corpus manifest")
    if not isinstance(manifest, Mapping):
        raise TokenScheduleError("corpus manifest must be an object")
    return manifest


def _construct_artifact(
    config: Mapping[str, Any],
    *,
    corpus_dir: Path,
    corpus_source_root: Path,
    tokenizer_root: Path,
    tokenizer: TokenizerProtocol,
    model_embedding_rows: int | None,
) -> tuple[dict[str, Any], bytes, bytes, bytes]:
    try:
        corpus_summary = validate_training_corpus_artifacts(
            corpus_dir,
            expected_corpus_sha256=config["source_corpus"]["corpus_sha256"],
            expected_manifest_sha256=config["source_corpus"]["manifest_sha256"],
            source_root=corpus_source_root,
            require_authenticated=True,
        )
    except TrainingCorpusError as exc:
        raise TokenScheduleError(
            f"authenticated corpus verification failed: {exc.issues[0]}"
        ) from exc
    if (
        corpus_summary.get("authenticated") is not True
        or corpus_summary.get("authentication", {}).get("external_pin_verified") is not True
        or corpus_summary.get("authentication", {}).get("source_replay_verified") is not True
    ):
        raise TokenScheduleError(
            "corpus must verify both an external identity pin and raw-source replay"
        )
    corpus_manifest = _load_corpus_manifest(corpus_dir)
    formatting = corpus_manifest.get("formatting")
    if not isinstance(formatting, Mapping):
        raise TokenScheduleError("corpus manifest formatting is unavailable")
    renderer = _renderer_identity(formatting)
    identity = _tokenizer_identity(
        tokenizer, tokenizer_root, model_embedding_rows=model_embedding_rows
    )
    embedding_rows = identity["model_config"]["input_embedding_rows"]
    eos_token_id = identity["special_token_ids"]["eos_token_id"]
    assert isinstance(eos_token_id, int)  # established by identity validation

    source_records = {
        partition: _read_corpus_records(
            corpus_dir, partition, corpus_summary[f"{partition}_file_sha256"]
        )
        for partition in ("target", "support")
    }
    # Close the verify/read race: the retained record bytes are content-bound,
    # and a second full verification proves the artifact did not drift.
    try:
        closing_summary = validate_training_corpus_artifacts(
            corpus_dir,
            expected_corpus_sha256=config["source_corpus"]["corpus_sha256"],
            expected_manifest_sha256=config["source_corpus"]["manifest_sha256"],
            source_root=corpus_source_root,
            require_authenticated=True,
        )
    except TrainingCorpusError as exc:
        raise TokenScheduleError(
            f"closing authenticated corpus verification failed: {exc.issues[0]}"
        ) from exc
    if closing_summary != corpus_summary:
        raise TokenScheduleError("corpus verification summary changed while scheduling")

    tokenized = {
        partition: _tokenize_records(
            tokenizer,
            source_records[partition],
            partition,
            sequence_length=config["sequence_length"],
            embedding_rows=embedding_rows,
            eos_token_id=eos_token_id,
        )
        for partition in ("target", "support")
    }
    selected = {
        partition: _select_partition(
            tokenized[partition],
            seed=config["seed"],
            partition=partition,
            budget=config["visible_token_budgets"][partition],
            reserve=config["tail_selection"]["reserve_visible_tokens"],
            candidate_occurrences=config["tail_selection"]["candidate_occurrences"],
        )
        for partition in ("target", "support")
    }
    global_schedule = _interleave(
        selected["target"],
        selected["support"],
        config["visible_token_budgets"]["target"],
        config["visible_token_budgets"]["support"],
    )
    occurrences_payload, packing_payload, accounting, stream_hashes, selection_summary = _build_ledgers(
        global_schedule,
        sequence_length=config["sequence_length"],
        effective_pad_id=identity["effective_pad_token_id"],
    )
    for partition in ("target", "support"):
        if accounting[partition]["visible_tokens"] != config["visible_token_budgets"][partition]:
            raise TokenScheduleError(f"{partition} visible-token budget did not reproduce")
    files = [
        _file_declaration(OCCURRENCES_FILE_NAME, occurrences_payload, len(global_schedule)),
        _file_declaration(
            PACKING_FILE_NAME, packing_payload, accounting["total"]["packed_sequences"]
        ),
    ]
    source_identity = {
        **corpus_summary,
        "formatting_sha256": value_sha256(formatting),
        "partition_file_sha256s": {
            "target": corpus_summary["target_file_sha256"],
            "support": corpus_summary["support_file_sha256"],
        },
    }
    selection_identity = {
        "algorithm": "deterministic_cycle_order_prefix_plus_bounded_exact_tail",
        "algorithm_version": "1.0.0",
        "seed": config["seed"],
        "tail_selection": config["tail_selection"],
        "partition_summaries": selection_summary,
        "interleave_policy": config["policies"]["partition_interleave"],
    }
    packing_identity = {
        "sequence_length": config["sequence_length"],
        "packing_policy": config["policies"]["packing"],
        "padding_policy": config["policies"]["padding"],
        "attention_policy": config["policies"]["attention"],
        "position_ids_policy": config["policies"]["position_ids"],
        "label_policy": config["policies"]["labels"],
        "ignore_index": IGNORE_INDEX,
        "effective_pad_token_id": identity["effective_pad_token_id"],
        "effective_pad_source": identity["effective_pad_source"],
    }
    core: dict[str, Any] = {
        "schema_version": SCHEDULE_SCHEMA_VERSION,
        "record_type": "cbds.token-schedule-manifest",
        "preparer": _preparer_identity(),
        "config": config,
        "config_sha256": value_sha256(config),
        "source_corpus": source_identity,
        "tokenizer": identity,
        "renderer": renderer,
        "selection": selection_identity,
        "packing": packing_identity,
        "accounting": accounting,
        "stream_hashes": stream_hashes,
        "files": files,
        "quality_scope": {
            "artifact_kind": "prospective_offline_token_schedule",
            "corpus_eligibility": config["corpus_eligibility"],
            "target_policy_accepted": False,
            "training_executed": False,
            "evaluation_executed": False,
            "claim_authorized": False,
        },
        "limitations": [
            "This artifact describes tokenization and packing; it does not attest a trainer execution.",
            "Response-only labels implement the logical corpus assistant-response loss scope; the explicit terminal EOS is supervised.",
            "The target partition retains its upstream-unverified quality label from the source corpus.",
            "The raw single-line target strings have not passed the executable target-policy admission gate.",
            "Exact budgets count non-padding input tokens; padding slots are reported separately.",
        ],
        "schedule_hash_scope": "canonical_json_excluding_schedule_sha256",
    }
    manifest = dict(core)
    manifest["schedule_sha256"] = value_sha256(core)
    return manifest, _manifest_bytes(manifest), occurrences_payload, packing_payload


def _write_new(path: Path, payload: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o644)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise


def _atomic_publish_noreplace(staging: Path, destination: Path) -> None:
    """Atomically publish a staged directory without replacing any inode."""

    try:
        same_parent = staging.parent.resolve(strict=True) == destination.parent.resolve(strict=True)
    except OSError as exc:
        raise TokenScheduleError(
            f"cannot resolve schedule output parent: {type(exc).__name__}"
        ) from exc
    if not same_parent or destination.name in {"", ".", ".."}:
        raise TokenScheduleError("staging and destination must share a safe parent")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:  # pragma: no cover - Linux research requirement
        raise TokenScheduleError("platform lacks O_NOFOLLOW")
    try:
        parent_descriptor = os.open(destination.parent, flags | nofollow)
    except OSError as exc:
        raise TokenScheduleError(
            f"cannot open schedule output parent: {type(exc).__name__}"
        ) from exc
    try:
        try:
            renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
        except AttributeError as exc:  # pragma: no cover - Linux/glibc requirement
            raise TokenScheduleError("platform lacks renameat2") from exc
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            parent_descriptor,
            os.fsencode(staging.name),
            parent_descriptor,
            os.fsencode(destination.name),
            1,  # RENAME_NOREPLACE
        )
        if result != 0:
            error_number = ctypes.get_errno()
            if error_number == errno.EEXIST:
                raise TokenScheduleError("output directory already exists")
            raise TokenScheduleError(
                f"cannot atomically publish schedule artifact: {os.strerror(error_number)}"
            )
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)


def prepare_token_schedule(
    config: object,
    *,
    corpus_dir: str | os.PathLike[str],
    corpus_source_root: str | os.PathLike[str],
    tokenizer_root: str | os.PathLike[str],
    output_dir: str | os.PathLike[str],
    tokenizer: TokenizerProtocol | None = None,
    model_embedding_rows: int | None = None,
) -> dict[str, Any]:
    """Create a new verified-input, tokenizer-specific schedule artifact."""

    validated = validate_token_schedule_config(config)
    tokenizer_path = Path(tokenizer_root)
    active_tokenizer = tokenizer if tokenizer is not None else load_local_tokenizer(tokenizer_path)
    manifest, manifest_payload, occurrences, packing = _construct_artifact(
        validated,
        corpus_dir=Path(corpus_dir),
        corpus_source_root=Path(corpus_source_root),
        tokenizer_root=tokenizer_path,
        tokenizer=active_tokenizer,
        model_embedding_rows=model_embedding_rows,
    )
    sidecar = f"{sha256(manifest_payload).hexdigest()}  {MANIFEST_FILE_NAME}\n".encode("ascii")
    destination = Path(output_dir)
    if destination.exists() or destination.is_symlink():
        raise TokenScheduleError("output directory already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{destination.name}.", dir=destination.parent))
    try:
        _write_new(staging / OCCURRENCES_FILE_NAME, occurrences)
        _write_new(staging / PACKING_FILE_NAME, packing)
        _write_new(staging / MANIFEST_FILE_NAME, manifest_payload)
        _write_new(staging / MANIFEST_SIDECAR_NAME, sidecar)
        _atomic_publish_noreplace(staging, destination)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return {
        "schema_version": SCHEDULE_SCHEMA_VERSION,
        "schedule_id": validated["schedule_id"],
        "schedule_sha256": manifest["schedule_sha256"],
        "manifest_sha256": sha256(manifest_payload).hexdigest(),
        "config_sha256": manifest["config_sha256"],
        "target_visible_tokens": manifest["accounting"]["target"]["visible_tokens"],
        "support_visible_tokens": manifest["accounting"]["support"]["visible_tokens"],
        "total_supervised_tokens": manifest["accounting"]["total"]["supervised_tokens"],
        "packed_sequences": manifest["accounting"]["total"]["packed_sequences"],
        "training_executed": False,
        "claim_authorized": False,
    }


def _artifact_payloads(root: Path) -> tuple[bytes, bytes, bytes, bytes]:
    try:
        metadata = root.lstat()
    except OSError as exc:
        raise TokenScheduleError(f"cannot inspect schedule root: {type(exc).__name__}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise TokenScheduleError("schedule root must be a real directory")
    expected = {
        MANIFEST_FILE_NAME,
        MANIFEST_SIDECAR_NAME,
        OCCURRENCES_FILE_NAME,
        PACKING_FILE_NAME,
    }
    try:
        names = {entry.name for entry in os.scandir(root)}
    except OSError as exc:
        raise TokenScheduleError(f"cannot inventory schedule root: {type(exc).__name__}") from exc
    if names != expected:
        raise TokenScheduleError("schedule root inventory is not exact")
    return (
        _read_regular(root / MANIFEST_FILE_NAME, MAX_MANIFEST_BYTES, "schedule manifest"),
        _read_regular(root / MANIFEST_SIDECAR_NAME, 1024, "schedule manifest sidecar"),
        _read_regular(root / OCCURRENCES_FILE_NAME, MAX_LEDGER_BYTES, "occurrence ledger"),
        _read_regular(root / PACKING_FILE_NAME, MAX_LEDGER_BYTES, "packing ledger"),
    )


def validate_token_schedule_artifacts(
    source: str | os.PathLike[str],
    *,
    corpus_dir: str | os.PathLike[str],
    corpus_source_root: str | os.PathLike[str],
    tokenizer_root: str | os.PathLike[str],
    tokenizer: TokenizerProtocol | None = None,
    model_embedding_rows: int | None = None,
    expected_schedule_sha256: str | None = None,
    expected_manifest_sha256: str | None = None,
) -> dict[str, Any]:
    """Fully rebuild and verify a schedule without returning corpus plaintext."""

    root = Path(source)
    manifest_payload, sidecar, occurrences, packing = _artifact_payloads(root)
    manifest_digest = sha256(manifest_payload).hexdigest()
    if sidecar != f"{manifest_digest}  {MANIFEST_FILE_NAME}\n".encode("ascii"):
        raise TokenScheduleError("schedule manifest sidecar does not verify")
    if expected_manifest_sha256 is not None and _sha(
        expected_manifest_sha256, "expected_manifest_sha256"
    ) != manifest_digest:
        raise TokenScheduleError("schedule manifest SHA-256 differs from external pin")
    manifest = _strict_json(manifest_payload, "schedule manifest")
    if not isinstance(manifest, Mapping) or set(manifest) != _MANIFEST_KEYS:
        raise TokenScheduleError("schedule manifest keys are not exact")
    if manifest["schema_version"] != SCHEDULE_SCHEMA_VERSION:
        raise TokenScheduleError("schedule manifest schema version is invalid")
    if manifest["record_type"] != "cbds.token-schedule-manifest":
        raise TokenScheduleError("schedule manifest record type is invalid")
    if _manifest_bytes(manifest) != manifest_payload:
        raise TokenScheduleError("schedule manifest is not exact canonical pretty JSON")
    declared_schedule = _sha(manifest["schedule_sha256"], "manifest.schedule_sha256")
    unsigned = dict(manifest)
    unsigned.pop("schedule_sha256")
    if manifest["schedule_hash_scope"] != "canonical_json_excluding_schedule_sha256":
        raise TokenScheduleError("schedule hash scope is invalid")
    if value_sha256(unsigned) != declared_schedule:
        raise TokenScheduleError("schedule SHA-256 does not reproduce")
    if expected_schedule_sha256 is not None and _sha(
        expected_schedule_sha256, "expected_schedule_sha256"
    ) != declared_schedule:
        raise TokenScheduleError("schedule SHA-256 differs from external pin")
    quality = manifest.get("quality_scope")
    if (
        not isinstance(quality, Mapping)
        or quality.get("claim_authorized") is not False
        or quality.get("training_executed") is not False
    ):
        raise TokenScheduleError("token schedule cannot attest training or authorize a claim")
    config = validate_token_schedule_config(manifest.get("config"))
    if value_sha256(config) != _sha(manifest.get("config_sha256"), "manifest.config_sha256"):
        raise TokenScheduleError("schedule config SHA-256 does not reproduce")
    active_tokenizer = tokenizer if tokenizer is not None else load_local_tokenizer(tokenizer_root)
    expected_manifest, expected_manifest_payload, expected_occurrences, expected_packing = _construct_artifact(
        config,
        corpus_dir=Path(corpus_dir),
        corpus_source_root=Path(corpus_source_root),
        tokenizer_root=Path(tokenizer_root),
        tokenizer=active_tokenizer,
        model_embedding_rows=model_embedding_rows,
    )
    if manifest_payload != expected_manifest_payload or dict(manifest) != expected_manifest:
        raise TokenScheduleError("schedule manifest differs from deterministic reconstruction")
    if occurrences != expected_occurrences:
        raise TokenScheduleError("occurrence ledger differs from deterministic reconstruction")
    if packing != expected_packing:
        raise TokenScheduleError("packing ledger differs from deterministic reconstruction")
    return {
        "schema_version": SCHEDULE_SCHEMA_VERSION,
        "valid": True,
        "schedule_id": config["schedule_id"],
        "schedule_sha256": declared_schedule,
        "manifest_sha256": manifest_digest,
        "config_sha256": manifest["config_sha256"],
        "source_corpus_sha256": config["source_corpus"]["corpus_sha256"],
        "target_visible_tokens": manifest["accounting"]["target"]["visible_tokens"],
        "support_visible_tokens": manifest["accounting"]["support"]["visible_tokens"],
        "total_supervised_tokens": manifest["accounting"]["total"]["supervised_tokens"],
        "packed_sequences": manifest["accounting"]["total"]["packed_sequences"],
        "training_executed": False,
        "claim_authorized": False,
    }


__all__ = [
    "IGNORE_INDEX",
    "SCHEDULE_PREPARER_VERSION",
    "SCHEDULE_SCHEMA_VERSION",
    "TokenScheduleError",
    "TokenizerProtocol",
    "load_local_tokenizer",
    "prepare_token_schedule",
    "token_schedule_config_sha256",
    "validate_token_schedule_artifacts",
    "validate_token_schedule_config",
]
