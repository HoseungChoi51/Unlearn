"""Fail-closed primitives for the engineering-only dense SFT canary.

The module deliberately has no import-time dependency on PyTorch.  Schedule
materialization starts from a fully authenticated token-schedule artifact and
replays the source corpus; callers cannot supply token tensors, plaintext, or
an ordering.  The training loop is expressed against a small runtime protocol
so its token accounting and hash chain can be tested without a GPU.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import shutil
import stat
import tempfile
from typing import Any, Callable, Iterable, Mapping, Protocol, Sequence

from .manifests import canonical_json_bytes, value_sha256
from .model_artifacts import inspect_model_artifact
from .token_schedule import (
    IGNORE_INDEX,
    TokenizerProtocol,
    _atomic_publish_noreplace,
    _int32_bytes,
    _read_corpus_records,
    _tokenize_records,
    _uint32_bytes,
    validate_token_schedule_artifacts,
)


CANARY_SCHEMA_VERSION = "1.0.0"
LEDGER_SCHEMA_VERSION = "1.0.0"
COMPLETION_FILE_NAME = "completion.json"
LEDGER_FILE_NAME = "step-ledger.jsonl"
MODEL_DIRECTORY_NAME = "model"


class DenseTrainingError(ValueError):
    """Raised when canary inputs or execution violate the frozen contract."""


@dataclass(frozen=True)
class PackedSequence:
    """One exact fixed-width row reconstructed from authenticated artifacts."""

    sequence_index: int
    input_ids: tuple[int, ...]
    attention_mask: tuple[int, ...]
    position_ids: tuple[int, ...]
    labels: tuple[int, ...]
    visible_tokens: int
    supervised_tokens: int

    @property
    def token_slots(self) -> int:
        return len(self.input_ids)


@dataclass(frozen=True)
class MaterializedSchedule:
    """Packed tensors plus portable identities; never corpus plaintext."""

    sequences: tuple[PackedSequence, ...]
    identity: Mapping[str, Any]

    @property
    def total_visible_tokens(self) -> int:
        return sum(row.visible_tokens for row in self.sequences)

    @property
    def total_supervised_tokens(self) -> int:
        return sum(row.supervised_tokens for row in self.sequences)


@dataclass(frozen=True)
class DenseCanaryConfig:
    """Mutable choices for one otherwise frozen dense canary execution."""

    base_learning_rate: float
    microbatch_sequences: int
    accumulation_microbatches: int
    expected_total_visible_tokens: int
    seed: int

    def validated(self) -> "DenseCanaryConfig":
        if not math.isfinite(self.base_learning_rate) or self.base_learning_rate <= 0:
            raise DenseTrainingError("base_learning_rate must be finite and positive")
        for name, value in (
            ("microbatch_sequences", self.microbatch_sequences),
            ("accumulation_microbatches", self.accumulation_microbatches),
            ("expected_total_visible_tokens", self.expected_total_visible_tokens),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise DenseTrainingError(f"{name} must be a positive integer")
        if isinstance(self.seed, bool) or not isinstance(self.seed, int):
            raise DenseTrainingError("seed must be an integer")
        return self

    def to_record(self) -> dict[str, Any]:
        self.validated()
        return {
            "schema_version": CANARY_SCHEMA_VERSION,
            "base_learning_rate": self.base_learning_rate,
            "microbatch_sequences": self.microbatch_sequences,
            "accumulation_microbatches": self.accumulation_microbatches,
            "expected_total_visible_tokens": self.expected_total_visible_tokens,
            "seed": self.seed,
            "precision": "bfloat16_parameters_and_forward",
            "optimizer": {
                "name": "AdamW",
                "state_dtype": "float32",
                "betas": [0.9, 0.95],
                "epsilon": 1e-8,
                "weight_decay": 0.1,
            },
            "gradient_clip_norm": 1.0,
            "loss_normalization": (
                "sum_response_and_explicit_eos_cross_entropy_then_divide_gradients_"
                "by_actual_supervised_tokens_per_optimizer_update"
            ),
            "schedule": {
                "warmup_fraction": "1/20",
                "warmup_update_rounding": "ceiling_to_cover_five_percent_boundary",
                "decay": "cosine_to_zero_over_remaining_optimizer_updates",
                "lr_evaluated_once_before_each_optimizer_update": True,
            },
        }


class TrainingRuntime(Protocol):
    """Runtime boundary used by :func:`run_dense_canary_training`."""

    def zero_grad(self) -> None: ...

    def backward_loss_sum(self, rows: Sequence[PackedSequence]) -> float: ...

    def divide_gradients(self, supervised_tokens: int) -> None: ...

    def clip_grad_norm(self, maximum: float) -> float: ...

    def optimizer_step(self, learning_rate: float) -> None: ...

    def estimate_step_flops(self, token_slots: int) -> int: ...


def _strict_json(payload: bytes, label: str) -> Any:
    try:
        text = payload.decode("utf-8", errors="strict")
        return json.loads(
            text,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite constant {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise DenseTrainingError(f"{label} is not strict UTF-8 JSON") from exc


def _read_jsonl(payload: bytes, label: str) -> tuple[dict[str, Any], ...]:
    if not payload or not payload.endswith(b"\n"):
        raise DenseTrainingError(f"{label} must be nonempty JSONL ending in LF")
    rows: list[dict[str, Any]] = []
    for ordinal, line in enumerate(payload.splitlines()):
        value = _strict_json(line, f"{label} row {ordinal}")
        if not isinstance(value, dict):
            raise DenseTrainingError(f"{label} row {ordinal} must be an object")
        rows.append(value)
    return tuple(rows)


def _require_sha(value: str | None, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise DenseTrainingError(f"{label} must be an externally supplied lowercase SHA-256")
    return value


def _file_bytes(path: Path, label: str, maximum: int = 2_000_000_000) -> bytes:
    try:
        before = path.stat(follow_symlinks=False)
        if not path.is_file() or path.is_symlink() or before.st_size > maximum:
            raise DenseTrainingError(f"{label} is not a bounded regular file")
        payload = path.read_bytes()
        after = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise DenseTrainingError(f"cannot read {label}: {type(exc).__name__}") from exc
    fingerprint = lambda item: (
        item.st_dev,
        item.st_ino,
        item.st_mode,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )
    if fingerprint(before) != fingerprint(after) or len(payload) != before.st_size:
        raise DenseTrainingError(f"{label} changed while it was read")
    return payload


def materialize_packed_schedule(
    schedule_dir: str | os.PathLike[str],
    *,
    corpus_dir: str | os.PathLike[str],
    corpus_source_root: str | os.PathLike[str],
    tokenizer_root: str | os.PathLike[str],
    tokenizer: TokenizerProtocol,
    model_embedding_rows: int,
    expected_schedule_sha256: str,
    expected_manifest_sha256: str,
) -> MaterializedSchedule:
    """Authenticate, source-replay, and reconstruct every packed tensor row.

    Only artifact paths, external hashes, and the tokenizer implementation are
    accepted.  In particular there is no API for caller-provided examples,
    token IDs, labels, or sample order.
    """

    schedule_pin = _require_sha(expected_schedule_sha256, "expected_schedule_sha256")
    manifest_pin = _require_sha(expected_manifest_sha256, "expected_manifest_sha256")
    if (
        isinstance(model_embedding_rows, bool)
        or not isinstance(model_embedding_rows, int)
        or model_embedding_rows <= 1
    ):
        raise DenseTrainingError("model_embedding_rows must be an integer greater than one")

    schedule_root = Path(schedule_dir)
    corpus_root = Path(corpus_dir)
    validation = validate_token_schedule_artifacts(
        schedule_root,
        corpus_dir=corpus_root,
        corpus_source_root=corpus_source_root,
        tokenizer_root=tokenizer_root,
        tokenizer=tokenizer,
        model_embedding_rows=model_embedding_rows,
        expected_schedule_sha256=schedule_pin,
        expected_manifest_sha256=manifest_pin,
    )
    manifest_payload = _file_bytes(schedule_root / "manifest.json", "schedule manifest")
    occurrence_payload = _file_bytes(
        schedule_root / "occurrences.jsonl", "schedule occurrence ledger"
    )
    packing_payload = _file_bytes(schedule_root / "packing.jsonl", "schedule packing ledger")
    if sha256(manifest_payload).hexdigest() != manifest_pin:
        raise DenseTrainingError("schedule manifest changed after authentication")
    manifest = _strict_json(manifest_payload, "schedule manifest")
    if not isinstance(manifest, dict):
        raise DenseTrainingError("schedule manifest must be an object")
    if manifest.get("schedule_sha256") != schedule_pin:
        raise DenseTrainingError("schedule identity differs from the external pin")
    quality = manifest.get("quality_scope")
    if not isinstance(quality, Mapping) or quality.get("target_policy_accepted") is not False:
        raise DenseTrainingError("canary only accepts the explicit engineering-only schedule")
    if quality.get("claim_authorized") is not False:
        raise DenseTrainingError("schedule unexpectedly authorizes claims")

    declared_files = {
        item.get("path"): item
        for item in manifest.get("files", [])
        if isinstance(item, Mapping) and isinstance(item.get("path"), str)
    }
    for name, payload in (
        ("occurrences.jsonl", occurrence_payload),
        ("packing.jsonl", packing_payload),
    ):
        declaration = declared_files.get(name)
        if not isinstance(declaration, Mapping) or declaration.get("sha256") != sha256(payload).hexdigest():
            raise DenseTrainingError(f"{name} differs from the authenticated declaration")

    occurrences = _read_jsonl(occurrence_payload, "occurrence ledger")
    packs = _read_jsonl(packing_payload, "packing ledger")
    config = manifest.get("config")
    tokenizer_identity = manifest.get("tokenizer")
    source_identity = manifest.get("source_corpus")
    if not all(isinstance(value, Mapping) for value in (config, tokenizer_identity, source_identity)):
        raise DenseTrainingError("schedule manifest lacks reconstruction identities")
    assert isinstance(config, Mapping)
    assert isinstance(tokenizer_identity, Mapping)
    assert isinstance(source_identity, Mapping)
    sequence_length = config.get("sequence_length")
    effective_pad_id = tokenizer_identity.get("effective_pad_token_id")
    eos_token_id = tokenizer_identity.get("special_token_ids", {}).get("eos_token_id")
    partition_hashes = source_identity.get("partition_file_sha256s")
    if (
        isinstance(sequence_length, bool)
        or not isinstance(sequence_length, int)
        or sequence_length <= 0
        or isinstance(effective_pad_id, bool)
        or not isinstance(effective_pad_id, int)
        or isinstance(eos_token_id, bool)
        or not isinstance(eos_token_id, int)
        or not isinstance(partition_hashes, Mapping)
    ):
        raise DenseTrainingError("schedule reconstruction parameters are invalid")

    tokenized_by_identity: dict[tuple[str, str, str], Any] = {}
    for partition in ("target", "support"):
        expected_partition_hash = partition_hashes.get(partition)
        if not isinstance(expected_partition_hash, str):
            raise DenseTrainingError("schedule lacks a partition file identity")
        records = _read_corpus_records(corpus_root, partition, expected_partition_hash)
        tokenized = _tokenize_records(
            tokenizer,
            records,
            partition,
            sequence_length=sequence_length,
            embedding_rows=model_embedding_rows,
            eos_token_id=eos_token_id,
        )
        for record in tokenized:
            key = (partition, record.record_id, record.record_sha256)
            if key in tokenized_by_identity:
                raise DenseTrainingError("source replay produced a duplicate record identity")
            tokenized_by_identity[key] = record

    selected: list[Any] = []
    for ordinal, occurrence in enumerate(occurrences):
        if occurrence.get("global_ordinal") != ordinal:
            raise DenseTrainingError("occurrence ledger ordinals are not contiguous")
        key = (
            occurrence.get("partition"),
            occurrence.get("record_id"),
            occurrence.get("record_sha256"),
        )
        record = tokenized_by_identity.get(key)
        if record is None:
            raise DenseTrainingError("occurrence does not resolve to source-replayed tokens")
        input_payload = _uint32_bytes(record.input_ids)
        label_payload = _int32_bytes(record.labels)
        expected_fields = {
            "visible_tokens": record.visible_tokens,
            "supervised_tokens": record.supervised_tokens,
            "input_ids_sha256": sha256(input_payload).hexdigest(),
            "labels_sha256": sha256(label_payload).hexdigest(),
        }
        if any(occurrence.get(name) != value for name, value in expected_fields.items()):
            raise DenseTrainingError("occurrence accounting differs from source replay")
        selected.append(record)

    rows: list[PackedSequence] = []
    consumed_ordinals: list[int] = []
    packed_input_digest = sha256()
    packed_label_digest = sha256()
    packed_attention_digest = sha256()
    packed_position_digest = sha256()
    for sequence_index, pack in enumerate(packs):
        if pack.get("sequence_index") != sequence_index:
            raise DenseTrainingError("packing sequence indices are not contiguous")
        boundaries = pack.get("occurrences")
        if not isinstance(boundaries, list) or not boundaries:
            raise DenseTrainingError("packed sequence has no occurrence boundaries")
        input_ids: list[int] = []
        labels: list[int] = []
        expected_start = 0
        for boundary in boundaries:
            if not isinstance(boundary, Mapping):
                raise DenseTrainingError("packing boundary must be an object")
            ordinal = boundary.get("occurrence_global_ordinal")
            if isinstance(ordinal, bool) or not isinstance(ordinal, int) or not 0 <= ordinal < len(selected):
                raise DenseTrainingError("packing boundary occurrence ordinal is invalid")
            record = selected[ordinal]
            expected_end = expected_start + record.visible_tokens
            if (
                boundary.get("start") != expected_start
                or boundary.get("end_exclusive") != expected_end
                or boundary.get("eos_position") != expected_end - 1
            ):
                raise DenseTrainingError("packing boundary differs from replayed record width")
            input_ids.extend(record.input_ids)
            labels.extend(record.labels)
            consumed_ordinals.append(ordinal)
            expected_start = expected_end
        visible_tokens = len(input_ids)
        padding_tokens = sequence_length - visible_tokens
        if padding_tokens < 0:
            raise DenseTrainingError("packing row exceeds its fixed sequence length")
        input_ids.extend([effective_pad_id] * padding_tokens)
        labels.extend([IGNORE_INDEX] * padding_tokens)
        attention = [1] * visible_tokens + [0] * padding_tokens
        positions = list(range(sequence_length))
        supervised = sum(label != IGNORE_INDEX for label in labels)
        payloads = {
            "input_ids_sha256": _uint32_bytes(input_ids),
            "labels_sha256": _int32_bytes(labels),
            "attention_mask_sha256": bytes(attention),
            "position_ids_sha256": _uint32_bytes(positions),
        }
        if (
            pack.get("sequence_length") != sequence_length
            or pack.get("visible_tokens") != visible_tokens
            or pack.get("padding_tokens") != padding_tokens
            or any(pack.get(name) != sha256(payload).hexdigest() for name, payload in payloads.items())
        ):
            raise DenseTrainingError("packed tensor row differs from its authenticated hashes")
        packed_input_digest.update(payloads["input_ids_sha256"])
        packed_label_digest.update(payloads["labels_sha256"])
        packed_attention_digest.update(payloads["attention_mask_sha256"])
        packed_position_digest.update(payloads["position_ids_sha256"])
        rows.append(
            PackedSequence(
                sequence_index=sequence_index,
                input_ids=tuple(input_ids),
                attention_mask=tuple(attention),
                position_ids=tuple(positions),
                labels=tuple(labels),
                visible_tokens=visible_tokens,
                supervised_tokens=supervised,
            )
        )
    if consumed_ordinals != list(range(len(selected))):
        raise DenseTrainingError("packing does not consume each scheduled occurrence exactly once")
    stream_hashes = manifest.get("stream_hashes")
    observed_stream_hashes = {
        "packed_input_ids_sha256": packed_input_digest.hexdigest(),
        "packed_labels_sha256": packed_label_digest.hexdigest(),
        "packed_attention_mask_sha256": packed_attention_digest.hexdigest(),
        "packed_position_ids_sha256": packed_position_digest.hexdigest(),
    }
    if not isinstance(stream_hashes, Mapping) or any(
        stream_hashes.get(name) != value for name, value in observed_stream_hashes.items()
    ):
        raise DenseTrainingError("reconstructed packed streams differ from the manifest")

    closing_validation = validate_token_schedule_artifacts(
        schedule_root,
        corpus_dir=corpus_root,
        corpus_source_root=corpus_source_root,
        tokenizer_root=tokenizer_root,
        tokenizer=tokenizer,
        model_embedding_rows=model_embedding_rows,
        expected_schedule_sha256=schedule_pin,
        expected_manifest_sha256=manifest_pin,
    )
    if closing_validation != validation:
        raise DenseTrainingError("schedule verification changed during materialization")
    total_visible = sum(row.visible_tokens for row in rows)
    total_supervised = sum(row.supervised_tokens for row in rows)
    accounting = manifest.get("accounting", {}).get("total", {})
    if (
        total_visible != accounting.get("visible_tokens")
        or total_supervised != accounting.get("supervised_tokens")
        or len(rows) != accounting.get("packed_sequences")
    ):
        raise DenseTrainingError("materialized tensor accounting differs from the schedule")
    return MaterializedSchedule(
        sequences=tuple(rows),
        identity={
            **validation,
            "total_visible_tokens": total_visible,
            "total_supervised_tokens": total_supervised,
            "packed_stream_hashes": observed_stream_hashes,
            "corpus_manifest_sha256": config.get("source_corpus", {}).get("manifest_sha256"),
            "tokenizer_identity_sha256": value_sha256(tokenizer_identity),
            "corpus_eligibility": config.get("corpus_eligibility"),
            "target_policy_accepted": False,
            "claim_authorized": False,
        },
    )


def learning_rate_for_update(base: float, update_ordinal: int, total_updates: int) -> float:
    """Return the frozen 5%-warmup/cosine LR for a 1-based update ordinal."""

    if not math.isfinite(base) or base <= 0:
        raise DenseTrainingError("base learning rate must be finite and positive")
    if (
        isinstance(update_ordinal, bool)
        or isinstance(total_updates, bool)
        or not isinstance(update_ordinal, int)
        or not isinstance(total_updates, int)
        or total_updates <= 0
        or not 1 <= update_ordinal <= total_updates
    ):
        raise DenseTrainingError("optimizer update ordinal is invalid")
    warmup_updates = max(1, math.ceil(total_updates / 20))
    if update_ordinal <= warmup_updates:
        return base * update_ordinal / warmup_updates
    decay_updates = total_updates - warmup_updates
    if decay_updates <= 0:
        return base
    progress = (update_ordinal - warmup_updates) / decay_updates
    return base * 0.5 * (1.0 + math.cos(math.pi * progress))


def _chunks(values: Sequence[PackedSequence], width: int) -> tuple[tuple[PackedSequence, ...], ...]:
    return tuple(tuple(values[index : index + width]) for index in range(0, len(values), width))


def run_dense_canary_training(
    schedule: MaterializedSchedule,
    config: DenseCanaryConfig,
    runtime: TrainingRuntime,
    *,
    execution_binding: Mapping[str, Any],
) -> tuple[tuple[dict[str, Any], ...], dict[str, Any]]:
    """Run every packed row once and emit a hash-chained optimizer ledger."""

    resolved = config.validated()
    if not schedule.sequences:
        raise DenseTrainingError("materialized schedule is empty")
    if schedule.total_visible_tokens != resolved.expected_total_visible_tokens:
        raise DenseTrainingError(
            "exact visible-token stop differs from the authenticated schedule; truncation is forbidden"
        )
    configuration = resolved.to_record()
    binding = {
        "domain": "cbds.dense-sft-canary.execution-binding.v1",
        "configuration_sha256": value_sha256(configuration),
        "schedule_identity": dict(schedule.identity),
        "execution": dict(execution_binding),
        "campaign_eligible": False,
        "model_selection_eligible": False,
        "claim_eligible": False,
    }
    binding_sha = value_sha256(binding)
    previous_hash = value_sha256(
        {"domain": "cbds.dense-sft-canary.step-ledger.genesis.v1", "binding_sha256": binding_sha}
    )
    microbatches = _chunks(schedule.sequences, resolved.microbatch_sequences)
    update_groups = tuple(
        microbatches[index : index + resolved.accumulation_microbatches]
        for index in range(0, len(microbatches), resolved.accumulation_microbatches)
    )
    ledger: list[dict[str, Any]] = []
    cumulative_visible = 0
    cumulative_supervised = 0
    cumulative_slots = 0
    cumulative_flops = 0
    for update_index, microbatch_group in enumerate(update_groups):
        update_ordinal = update_index + 1
        runtime.zero_grad()
        loss_sums: list[float] = []
        visible_tokens = 0
        supervised_tokens = 0
        token_slots = 0
        sequence_count = 0
        for rows in microbatch_group:
            observed_loss_sum = runtime.backward_loss_sum(rows)
            if not math.isfinite(observed_loss_sum) or observed_loss_sum < 0:
                raise DenseTrainingError("runtime returned a non-finite or negative loss sum")
            loss_sums.append(observed_loss_sum)
            visible_tokens += sum(row.visible_tokens for row in rows)
            supervised_tokens += sum(row.supervised_tokens for row in rows)
            token_slots += sum(row.token_slots for row in rows)
            sequence_count += len(rows)
        if supervised_tokens <= 0:
            raise DenseTrainingError("optimizer update has no supervised response/EOS tokens")
        runtime.divide_gradients(supervised_tokens)
        gradient_norm = runtime.clip_grad_norm(1.0)
        if not math.isfinite(gradient_norm) or gradient_norm < 0:
            raise DenseTrainingError("runtime returned a non-finite or negative gradient norm")
        learning_rate = learning_rate_for_update(
            resolved.base_learning_rate, update_ordinal, len(update_groups)
        )
        runtime.optimizer_step(learning_rate)
        step_flops = runtime.estimate_step_flops(token_slots)
        if isinstance(step_flops, bool) or not isinstance(step_flops, int) or step_flops < 0:
            raise DenseTrainingError("runtime FLOP estimate must be a nonnegative integer")
        loss_sum = math.fsum(loss_sums)
        loss_mean = loss_sum / supervised_tokens
        cumulative_visible += visible_tokens
        cumulative_supervised += supervised_tokens
        cumulative_slots += token_slots
        cumulative_flops += step_flops
        record: dict[str, Any] = {
            "schema_version": LEDGER_SCHEMA_VERSION,
            "record_type": "cbds.dense-sft-canary.optimizer-update",
            "binding_sha256": binding_sha,
            "update_ordinal": update_ordinal,
            "optimizer_updates_total": len(update_groups),
            "microbatches": len(microbatch_group),
            "sequences": sequence_count,
            "visible_tokens": visible_tokens,
            "supervised_tokens": supervised_tokens,
            "packed_token_slots": token_slots,
            "learning_rate": learning_rate,
            "loss_sum": loss_sum,
            "loss_mean_per_supervised_token": loss_mean,
            "gradient_norm_before_clip": gradient_norm,
            "gradient_clip_norm": 1.0,
            "step_flops": step_flops,
            "flops_kind": "analytical_estimate_not_hardware_measured",
            "cumulative_visible_tokens": cumulative_visible,
            "cumulative_supervised_tokens": cumulative_supervised,
            "cumulative_packed_token_slots": cumulative_slots,
            "cumulative_flops": cumulative_flops,
            "previous_step_sha256": previous_hash,
            "step_hash_scope": "canonical_json_excluding_step_sha256",
        }
        record["step_sha256"] = value_sha256(record)
        previous_hash = record["step_sha256"]
        ledger.append(record)
    if cumulative_visible != schedule.total_visible_tokens:
        raise DenseTrainingError("training did not stop at the exact visible-token total")
    if cumulative_supervised != schedule.total_supervised_tokens:
        raise DenseTrainingError("training supervised-token total differs from reconstruction")
    ledger_payload = b"".join(canonical_json_bytes(row) + b"\n" for row in ledger)
    summary = {
        "schema_version": CANARY_SCHEMA_VERSION,
        "record_type": "cbds.dense-sft-canary.training-summary",
        "status": "completed_engineering_canary",
        "binding": binding,
        "binding_sha256": binding_sha,
        "optimizer_updates": len(ledger),
        "visible_tokens": cumulative_visible,
        "supervised_tokens": cumulative_supervised,
        "packed_token_slots": cumulative_slots,
        "cumulative_flops": cumulative_flops,
        "flop_scope": (
            "analytical_estimate_not_hardware_measured_runtime_formula_in_execution_binding"
        ),
        "ledger_genesis_sha256": ledger[0]["previous_step_sha256"],
        "ledger_final_step_sha256": previous_hash,
        "ledger_payload_sha256": sha256(ledger_payload).hexdigest(),
        "campaign_eligible": False,
        "model_selection_eligible": False,
        "claim_eligible": False,
    }
    summary["summary_sha256"] = value_sha256(summary)
    return tuple(ledger), summary


def ledger_payload(records: Iterable[Mapping[str, Any]]) -> bytes:
    """Serialize ledger records in the exact exported form."""

    return b"".join(canonical_json_bytes(dict(record)) + b"\n" for record in records)


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


def _metadata_fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _open_checkpoint_root(root: Path) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:  # pragma: no cover - Linux research requirement
        raise DenseTrainingError("platform lacks O_NOFOLLOW")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0) | nofollow
    try:
        descriptor = os.open(root, flags)
        metadata = os.fstat(descriptor)
    except OSError as exc:
        raise DenseTrainingError("cannot open checkpoint root without following links") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        os.close(descriptor)
        raise DenseTrainingError("checkpoint root is not a directory")
    return descriptor


def _name_bytes(name: str) -> bytes:
    try:
        return name.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise DenseTrainingError("checkpoint inventory contains a non-UTF-8 file name") from exc


def _open_directory_at(parent_descriptor: int, name: str) -> int:
    _name_bytes(name)
    if name in {"", ".", ".."} or "/" in name or "\x00" in name:
        raise DenseTrainingError("checkpoint inventory contains an unsafe directory name")
    flags = (
        os.O_RDONLY
        | os.O_CLOEXEC
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
        metadata = os.fstat(descriptor)
    except OSError as exc:
        raise DenseTrainingError("checkpoint model directory cannot be opened safely") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        os.close(descriptor)
        raise DenseTrainingError("checkpoint model member is not a directory")
    return descriptor


def _stream_regular_at(
    root_descriptor: int,
    name: str,
    *,
    capture_limit: int | None = None,
    maximum_bytes: int = 8_000_000_000,
) -> tuple[int, str, bytes | None]:
    if (
        not isinstance(name, str)
        or name in {"", ".", ".."}
        or "/" in name
        or "\x00" in name
        or len(_name_bytes(name)) > 512
    ):
        raise DenseTrainingError("checkpoint inventory contains an unsafe file name")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=root_descriptor)
    except OSError as exc:
        raise DenseTrainingError("checkpoint member cannot be opened without following links") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 0
            or before.st_size > maximum_bytes
        ):
            raise DenseTrainingError("checkpoint inventory member is not a bounded regular file")
        if capture_limit is not None and before.st_size > capture_limit:
            raise DenseTrainingError("checkpoint metadata file exceeds its byte limit")
        digest = sha256()
        captured = bytearray() if capture_limit is not None else None
        observed = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            observed += len(chunk)
            if observed > before.st_size:
                raise DenseTrainingError("checkpoint member grew while hashing")
            digest.update(chunk)
            if captured is not None:
                captured.extend(chunk)
        after = os.fstat(descriptor)
        if observed != before.st_size or _metadata_fingerprint(before) != _metadata_fingerprint(after):
            raise DenseTrainingError("checkpoint member changed while hashing")
        return observed, digest.hexdigest(), bytes(captured) if captured is not None else None
    finally:
        os.close(descriptor)


def _content_inventory(root: Path, excluded: frozenset[str]) -> list[dict[str, Any]]:
    """Hash checkpoint files in bounded chunks through stable no-follow FDs."""

    root_descriptor = _open_checkpoint_root(root)
    try:
        before = os.fstat(root_descriptor)
        names = os.listdir(root_descriptor)
        required_root_names = {LEDGER_FILE_NAME, MODEL_DIRECTORY_NAME}
        allowed_root_names = required_root_names | set(excluded)
        if not required_root_names.issubset(names) or set(names) - allowed_root_names:
            raise DenseTrainingError(
                "checkpoint root must contain only model/, step-ledger.jsonl, and completion.json"
            )
        records: list[dict[str, Any]] = []
        total_bytes = 0
        model_descriptor = _open_directory_at(root_descriptor, MODEL_DIRECTORY_NAME)
        try:
            model_before = os.fstat(model_descriptor)
            model_names = os.listdir(model_descriptor)
            if not model_names or len(model_names) > 100_000:
                raise DenseTrainingError("checkpoint model inventory is empty or too large")
            for name in sorted(model_names, key=_name_bytes):
                size, digest, _ = _stream_regular_at(model_descriptor, name)
                total_bytes += size
                if total_bytes > 16_000_000_000:
                    raise DenseTrainingError("checkpoint inventory exceeds the total byte limit")
                records.append(
                    {"path": f"{MODEL_DIRECTORY_NAME}/{name}", "bytes": size, "sha256": digest}
                )
            model_after_names = os.listdir(model_descriptor)
            model_after = os.fstat(model_descriptor)
            if sorted(model_names, key=_name_bytes) != sorted(
                model_after_names, key=_name_bytes
            ) or _metadata_fingerprint(model_before) != _metadata_fingerprint(model_after):
                raise DenseTrainingError("checkpoint model directory changed while hashing")
        finally:
            os.close(model_descriptor)
        size, digest, _ = _stream_regular_at(root_descriptor, LEDGER_FILE_NAME)
        total_bytes += size
        if total_bytes > 16_000_000_000:
            raise DenseTrainingError("checkpoint inventory exceeds the total byte limit")
        records.append({"path": LEDGER_FILE_NAME, "bytes": size, "sha256": digest})
        records.sort(key=lambda item: _name_bytes(item["path"]))
        after_names = os.listdir(root_descriptor)
        after = os.fstat(root_descriptor)
        if sorted(names, key=_name_bytes) != sorted(after_names, key=_name_bytes) or (
            _metadata_fingerprint(before) != _metadata_fingerprint(after)
        ):
            raise DenseTrainingError("checkpoint root changed while hashing")
    finally:
        os.close(root_descriptor)
    if not records:
        raise DenseTrainingError("checkpoint exporter produced no content")
    return records


def _checkpoint_metadata_payload(root: Path, name: str, maximum: int) -> bytes:
    root_descriptor = _open_checkpoint_root(root)
    try:
        _, _, payload = _stream_regular_at(
            root_descriptor, name, capture_limit=maximum, maximum_bytes=maximum
        )
    finally:
        os.close(root_descriptor)
    assert payload is not None
    return payload


def _verify_embedded_hash(
    value: Mapping[str, Any], hash_field: str, label: str
) -> str:
    claimed = _require_sha(value.get(hash_field), f"{label}.{hash_field}")
    unsigned = dict(value)
    unsigned.pop(hash_field, None)
    if value_sha256(unsigned) != claimed:
        raise DenseTrainingError(f"{label} hash does not reproduce")
    return claimed


def _reject_positive_eligibility(value: object, path: str = "completion") -> None:
    protected = {
        "campaign_eligible",
        "model_selection_eligible",
        "claim_eligible",
        "claim_authorized",
        "target_policy_accepted",
        "source_schedule_target_policy_accepted",
    }
    if isinstance(value, Mapping):
        for key, child in value.items():
            if key in protected and child is not False:
                raise DenseTrainingError(f"{path}.{key} must remain false")
            _reject_positive_eligibility(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_positive_eligibility(child, f"{path}[{index}]")


def _exported_model_identity(inspection: Mapping[str, Any]) -> dict[str, Any]:
    try:
        if inspection["architecture"]["classification"] != "dense_consistent":
            raise DenseTrainingError("exported checkpoint is not statically dense-consistent")
        if inspection["quantization"]["logical_count_from_stored_elements_ambiguous"] is not False:
            raise DenseTrainingError("exported checkpoint unexpectedly appears packed or quantized")
        if inspection["claim_qualification"][
            "dense_consistent_with_below_one_billion_stored_elements"
        ] is not True:
            raise DenseTrainingError("exported checkpoint fails the dense sub-billion static gate")
        return {
            "inspection_report_sha256": inspection["report_sha256"],
            "bundle_manifest_sha256": inspection["bundle_manifest_sha256"],
            "weight_set_sha256": inspection["weight_set_sha256"],
            "static_classification": inspection["architecture"]["classification"],
            "tensor_layout_sha256": inspection["weights"]["tensor_layout_sha256"],
            "stored_tensor_elements": inspection["weights"]["stored_tensor_element_count"],
            "safetensors_payload_bytes": inspection["weights"]["safetensors_payload_bytes"],
            "config_sha256": inspection["config"]["sha256"],
        }
    except (KeyError, TypeError) as exc:
        raise DenseTrainingError("model inspector returned an incomplete report") from exc


def validate_published_checkpoint(
    source: str | os.PathLike[str],
    *,
    tensor_hasher: Callable[[Path], str] | None = None,
    expected_model_inspection_sha256: str | None = None,
    expected_schedule_sha256: str | None = None,
    expected_schedule_manifest_sha256: str | None = None,
    model_inspector: Callable[[Path], Mapping[str, Any]] = inspect_model_artifact,
) -> dict[str, Any]:
    """Reopen and validate a complete canary checkpoint without trusting names.

    All files are streamed through stable ``O_NOFOLLOW`` descriptors.  When a
    tensor hasher is supplied, the logical tensor identity is independently
    recomputed in addition to the exact serialized-file inventory.
    """

    root = Path(source)
    completion_payload = _checkpoint_metadata_payload(
        root, COMPLETION_FILE_NAME, 64 * 1024 * 1024
    )
    completion = _strict_json(completion_payload, "checkpoint completion record")
    if not isinstance(completion, dict):
        raise DenseTrainingError("checkpoint completion record must be an object")
    expected_completion_payload = (
        json.dumps(
            completion, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True
        ).encode("utf-8")
        + b"\n"
    )
    if completion_payload != expected_completion_payload:
        raise DenseTrainingError("checkpoint completion record is not canonical JSON")
    if (
        completion.get("schema_version") != CANARY_SCHEMA_VERSION
        or completion.get("record_type") != "cbds.dense-sft-canary.completion"
        or completion.get("status") != "completed_engineering_canary"
    ):
        raise DenseTrainingError("checkpoint completion record type or status is invalid")
    completion_hash = _verify_embedded_hash(
        completion, "completion_sha256", "checkpoint completion"
    )
    _reject_positive_eligibility(completion)

    declared_files = completion.get("checkpoint_files")
    if not isinstance(declared_files, list) or not declared_files:
        raise DenseTrainingError("checkpoint completion lacks a file inventory")
    normalized_files: list[dict[str, Any]] = []
    observed_paths: set[str] = set()
    for ordinal, item in enumerate(declared_files):
        if not isinstance(item, Mapping) or set(item) != {"path", "bytes", "sha256"}:
            raise DenseTrainingError("checkpoint file declaration keys are not exact")
        path = item.get("path")
        size = item.get("bytes")
        digest = item.get("sha256")
        safe_declared_path = path == LEDGER_FILE_NAME or (
            isinstance(path, str)
            and path.startswith(f"{MODEL_DIRECTORY_NAME}/")
            and path.count("/") == 1
            and path.split("/", 1)[1] not in {"", ".", ".."}
            and "\x00" not in path
        )
        if (
            not isinstance(path, str)
            or path in observed_paths
            or path == COMPLETION_FILE_NAME
            or not safe_declared_path
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
        ):
            raise DenseTrainingError("checkpoint file declaration is unsafe")
        observed_paths.add(path)
        normalized_files.append(
            {"path": path, "bytes": size, "sha256": _require_sha(digest, "file sha256")}
        )
        if ordinal and normalized_files[ordinal - 1]["path"].encode("utf-8") >= path.encode("utf-8"):
            raise DenseTrainingError("checkpoint file declarations are not in canonical order")
    actual_files = _content_inventory(root, frozenset({COMPLETION_FILE_NAME}))
    if actual_files != normalized_files:
        raise DenseTrainingError("checkpoint file inventory differs from the completion record")
    content_hash = value_sha256(
        {
            "domain": "cbds.dense-sft-canary.checkpoint-content.v1",
            "files": actual_files,
        }
    )
    if completion.get("checkpoint_content_sha256") != content_hash:
        raise DenseTrainingError("checkpoint content hash does not reproduce")

    observed_exported_model = _exported_model_identity(
        model_inspector(root / MODEL_DIRECTORY_NAME)
    )
    if completion.get("exported_model") != observed_exported_model:
        raise DenseTrainingError("exported model inspection identity does not reproduce")

    ledger_payload_bytes = _checkpoint_metadata_payload(
        root, LEDGER_FILE_NAME, 512 * 1024 * 1024
    )
    ledger_digest = sha256(ledger_payload_bytes).hexdigest()
    if completion.get("ledger_payload_sha256") != ledger_digest:
        raise DenseTrainingError("completion ledger hash differs from the checkpoint ledger")
    ledger_rows = _read_jsonl(ledger_payload_bytes, "checkpoint step ledger")
    canonical_ledger = ledger_payload(ledger_rows)
    if canonical_ledger != ledger_payload_bytes:
        raise DenseTrainingError("checkpoint step ledger is not canonical JSONL")

    summary = completion.get("training_summary")
    if not isinstance(summary, Mapping):
        raise DenseTrainingError("completion lacks its training summary")
    summary_hash = _verify_embedded_hash(summary, "summary_sha256", "training summary")
    _reject_positive_eligibility(summary, "training_summary")
    if (
        summary.get("record_type") != "cbds.dense-sft-canary.training-summary"
        or summary.get("status") != "completed_engineering_canary"
        or summary.get("ledger_payload_sha256") != ledger_digest
    ):
        raise DenseTrainingError("training summary type, status, or ledger hash is invalid")
    binding = summary.get("binding")
    if not isinstance(binding, Mapping):
        raise DenseTrainingError("training summary lacks its execution binding")
    binding_sha = _require_sha(summary.get("binding_sha256"), "summary binding sha256")
    if value_sha256(binding) != binding_sha:
        raise DenseTrainingError("training execution binding hash does not reproduce")
    genesis = value_sha256(
        {
            "domain": "cbds.dense-sft-canary.step-ledger.genesis.v1",
            "binding_sha256": binding_sha,
        }
    )
    if summary.get("ledger_genesis_sha256") != genesis:
        raise DenseTrainingError("training ledger genesis does not reproduce")

    previous = genesis
    cumulative_visible = 0
    cumulative_supervised = 0
    cumulative_slots = 0
    cumulative_flops = 0
    for index, row in enumerate(ledger_rows):
        if (
            row.get("schema_version") != LEDGER_SCHEMA_VERSION
            or row.get("record_type") != "cbds.dense-sft-canary.optimizer-update"
            or row.get("update_ordinal") != index + 1
            or row.get("optimizer_updates_total") != len(ledger_rows)
            or row.get("binding_sha256") != binding_sha
            or row.get("previous_step_sha256") != previous
            or row.get("step_hash_scope") != "canonical_json_excluding_step_sha256"
            or row.get("flops_kind") != "analytical_estimate_not_hardware_measured"
        ):
            raise DenseTrainingError("optimizer ledger chain metadata is invalid")
        step_hash = _verify_embedded_hash(row, "step_sha256", "optimizer ledger row")
        counts: dict[str, int] = {}
        for name in ("visible_tokens", "supervised_tokens", "packed_token_slots", "step_flops"):
            value = row.get(name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise DenseTrainingError("optimizer ledger token/FLOP count is invalid")
            counts[name] = value
        if counts["visible_tokens"] <= 0 or counts["supervised_tokens"] <= 0:
            raise DenseTrainingError("optimizer ledger has an empty training update")
        cumulative_visible += counts["visible_tokens"]
        cumulative_supervised += counts["supervised_tokens"]
        cumulative_slots += counts["packed_token_slots"]
        cumulative_flops += counts["step_flops"]
        if (
            row.get("cumulative_visible_tokens") != cumulative_visible
            or row.get("cumulative_supervised_tokens") != cumulative_supervised
            or row.get("cumulative_packed_token_slots") != cumulative_slots
            or row.get("cumulative_flops") != cumulative_flops
        ):
            raise DenseTrainingError("optimizer ledger cumulative accounting is invalid")
        previous = step_hash
    if (
        summary.get("optimizer_updates") != len(ledger_rows)
        or summary.get("visible_tokens") != cumulative_visible
        or summary.get("supervised_tokens") != cumulative_supervised
        or summary.get("packed_token_slots") != cumulative_slots
        or summary.get("cumulative_flops") != cumulative_flops
        or summary.get("ledger_final_step_sha256") != previous
        or summary.get("flop_scope")
        != "analytical_estimate_not_hardware_measured_runtime_formula_in_execution_binding"
    ):
        raise DenseTrainingError("training summary differs from the verified step ledger")

    declared_tensor_hash = _require_sha(
        completion.get("checkpoint_tensor_sha256"), "checkpoint tensor hash"
    )
    if tensor_hasher is not None:
        observed_tensor_hash = _require_sha(
            tensor_hasher(root / MODEL_DIRECTORY_NAME),
            "recomputed checkpoint tensor hash",
        )
        if observed_tensor_hash != declared_tensor_hash:
            raise DenseTrainingError("checkpoint tensor hash does not reproduce")
        # Close a possible hasher/read race by rechecking every serialized file.
        if _content_inventory(root, frozenset({COMPLETION_FILE_NAME})) != actual_files:
            raise DenseTrainingError("checkpoint content changed during tensor verification")

    source_model = completion.get("source_model")
    source_schedule = completion.get("source_schedule")
    if not isinstance(source_model, Mapping) or not isinstance(source_schedule, Mapping):
        raise DenseTrainingError("completion lacks source model or schedule bindings")
    model_stages: list[Mapping[str, Any]] = []
    for stage in ("initial", "after_load", "final"):
        identity = source_model.get(stage)
        if not isinstance(identity, Mapping):
            raise DenseTrainingError(f"completion lacks the {stage} source-model binding")
        for field in (
            "inspection_report_sha256",
            "bundle_manifest_sha256",
            "weight_set_sha256",
            "tensor_layout_sha256",
            "config_sha256",
        ):
            _require_sha(identity.get(field), f"source model {stage} {field}")
        if identity.get("static_classification") != "dense_consistent":
            raise DenseTrainingError("source model binding is not statically dense-consistent")
        for field in ("stored_tensor_elements", "safetensors_payload_bytes"):
            count = identity.get(field)
            if isinstance(count, bool) or not isinstance(count, int) or count <= 0:
                raise DenseTrainingError("source model binding has invalid static accounting")
        model_stages.append(identity)
    if source_model.get("stable") is not True or any(
        dict(identity) != dict(model_stages[0]) for identity in model_stages[1:]
    ):
        raise DenseTrainingError("source model identities are not stable across execution")
    initial_model = model_stages[0]
    for field in (
        "schedule_sha256",
        "manifest_sha256",
        "config_sha256",
        "source_corpus_sha256",
        "corpus_manifest_sha256",
        "tokenizer_identity_sha256",
    ):
        _require_sha(source_schedule.get(field), f"source schedule {field}")
    if expected_model_inspection_sha256 is not None and initial_model.get(
        "inspection_report_sha256"
    ) != _require_sha(expected_model_inspection_sha256, "expected model inspection sha256"):
        raise DenseTrainingError("completion source model differs from the external pin")
    if expected_schedule_sha256 is not None and source_schedule.get(
        "schedule_sha256"
    ) != _require_sha(expected_schedule_sha256, "expected schedule sha256"):
        raise DenseTrainingError("completion source schedule differs from the external pin")
    if expected_schedule_manifest_sha256 is not None and source_schedule.get(
        "manifest_sha256"
    ) != _require_sha(
        expected_schedule_manifest_sha256, "expected schedule manifest sha256"
    ):
        raise DenseTrainingError("completion source schedule manifest differs from the external pin")
    return {
        "schema_version": CANARY_SCHEMA_VERSION,
        "valid": True,
        "completion_sha256": completion_hash,
        "training_summary_sha256": summary_hash,
        "checkpoint_content_sha256": content_hash,
        "checkpoint_tensor_sha256": declared_tensor_hash,
        "ledger_payload_sha256": ledger_digest,
        "optimizer_updates": len(ledger_rows),
        "visible_tokens": cumulative_visible,
        "supervised_tokens": cumulative_supervised,
        "campaign_eligible": False,
        "model_selection_eligible": False,
        "claim_eligible": False,
    }


def publish_checkpoint_noreplace(
    output_dir: str | os.PathLike[str],
    *,
    ledger_records: Sequence[Mapping[str, Any]],
    completion_base: Mapping[str, Any],
    exporter: Callable[[Path], None],
    tensor_hasher: Callable[[Path], str],
    model_inspector: Callable[[Path], Mapping[str, Any]] = inspect_model_artifact,
) -> dict[str, Any]:
    """Stage, hash, complete, and atomically publish a checkpoint once."""

    destination = Path(output_dir)
    try:
        parent = destination.parent.resolve(strict=True)
    except OSError as exc:
        raise DenseTrainingError("checkpoint output parent must already exist") from exc
    if destination.name in {"", ".", ".."} or destination.exists() or destination.is_symlink():
        raise DenseTrainingError("checkpoint output directory already exists or is unsafe")
    staging = Path(tempfile.mkdtemp(prefix=f".{destination.name}.", dir=parent))
    published = False
    try:
        payload = ledger_payload(ledger_records)
        _write_new(staging / LEDGER_FILE_NAME, payload)
        model_root = staging / MODEL_DIRECTORY_NAME
        model_root.mkdir(mode=0o755)
        exporter(model_root)
        if (staging / COMPLETION_FILE_NAME).exists():
            raise DenseTrainingError("exporter attempted to create the reserved completion record")
        exported_model = _exported_model_identity(model_inspector(model_root))
        tensor_hash = _require_sha(tensor_hasher(model_root), "checkpoint tensor hash")
        files = _content_inventory(staging, frozenset({COMPLETION_FILE_NAME}))
        content_hash = value_sha256(
            {
                "domain": "cbds.dense-sft-canary.checkpoint-content.v1",
                "files": files,
            }
        )
        base = dict(completion_base)
        if "exported_model" in base and base["exported_model"] != exported_model:
            raise DenseTrainingError("caller-supplied exported-model identity differs")
        base["exported_model"] = exported_model
        if any(
            base.get(name) is not False
            for name in ("campaign_eligible", "model_selection_eligible", "claim_eligible")
        ):
            raise DenseTrainingError("completion base must explicitly deny every research eligibility")
        completion: dict[str, Any] = {
            **base,
            "schema_version": CANARY_SCHEMA_VERSION,
            "record_type": "cbds.dense-sft-canary.completion",
            "status": "completed_engineering_canary",
            "checkpoint_tensor_sha256": tensor_hash,
            "checkpoint_tensor_hash_scope": "name_dtype_shape_and_contiguous_tensor_bytes",
            "checkpoint_content_sha256": content_hash,
            "checkpoint_content_hash_scope": (
                "domain-separated canonical file inventory excluding completion.json"
            ),
            "checkpoint_files": files,
            "ledger_payload_sha256": sha256(payload).hexdigest(),
            "campaign_eligible": False,
            "model_selection_eligible": False,
            "claim_eligible": False,
            "limitations": [
                "The source schedule is engineering-only and target-policy-unaccepted.",
                "This canary is not a campaign run, checkpoint-selection input, or research result.",
            ],
            "completion_hash_scope": "canonical_json_excluding_completion_sha256",
        }
        completion["completion_sha256"] = value_sha256(completion)
        _write_new(
            staging / COMPLETION_FILE_NAME,
            json.dumps(
                completion, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True
            ).encode("utf-8")
            + b"\n",
        )
        # Reopen the completed staging tree and verify every serialized file,
        # hash layer, ledger link, and non-claiming eligibility before publish.
        validate_published_checkpoint(
            staging,
            tensor_hasher=tensor_hasher,
            model_inspector=model_inspector,
        )
        _atomic_publish_noreplace(staging, destination)
        published = True
        return completion
    except Exception as exc:
        if isinstance(exc, DenseTrainingError):
            raise
        raise DenseTrainingError(f"checkpoint publication failed: {type(exc).__name__}: {exc}") from exc
    finally:
        if not published:
            shutil.rmtree(staging, ignore_errors=True)


class FP32AdamW:
    """Small AdamW implementation with explicitly FP32 first/second moments."""

    def __init__(self, torch: Any, parameters: Iterable[Any]) -> None:
        self.torch = torch
        self.parameters = tuple(parameters)
        if not self.parameters:
            raise DenseTrainingError("optimizer received no parameters")
        self.states: dict[int, dict[str, Any]] = {}
        self.step_ordinal = 0

    def zero_grad(self) -> None:
        for parameter in self.parameters:
            parameter.grad = None

    def step(self, learning_rate: float) -> None:
        if not math.isfinite(learning_rate) or learning_rate < 0:
            raise DenseTrainingError("optimizer learning rate is invalid")
        self.step_ordinal += 1
        beta1, beta2 = 0.9, 0.95
        correction1 = 1.0 - beta1**self.step_ordinal
        correction2 = 1.0 - beta2**self.step_ordinal
        for parameter in self.parameters:
            gradient = parameter.grad
            if gradient is None:
                continue
            if getattr(gradient, "is_sparse", False):
                raise DenseTrainingError("sparse gradients are unsupported")
            gradient32 = gradient.detach().to(dtype=self.torch.float32)
            state = self.states.get(id(parameter))
            if state is None:
                state = {
                    "exp_avg": self.torch.zeros_like(parameter, dtype=self.torch.float32),
                    "exp_avg_sq": self.torch.zeros_like(parameter, dtype=self.torch.float32),
                }
                self.states[id(parameter)] = state
            exp_avg = state["exp_avg"]
            exp_avg_sq = state["exp_avg_sq"]
            exp_avg.mul_(beta1).add_(gradient32, alpha=1.0 - beta1)
            exp_avg_sq.mul_(beta2).addcmul_(gradient32, gradient32, value=1.0 - beta2)
            with self.torch.no_grad():
                parameter.mul_(1.0 - learning_rate * 0.1)
                denominator = exp_avg_sq.sqrt().div_(math.sqrt(correction2)).add_(1e-8)
                update = exp_avg.div(denominator).mul_(learning_rate / correction1)
                parameter.add_(update.to(dtype=parameter.dtype), alpha=-1.0)

    def state_dtypes(self) -> set[Any]:
        return {
            tensor.dtype
            for state in self.states.values()
            for tensor in (state["exp_avg"], state["exp_avg_sq"])
        }


class TorchDenseRuntime:
    """Concrete BF16 full-model runtime; PyTorch is supplied after offline setup."""

    def __init__(self, torch: Any, model: Any, device: Any) -> None:
        self.torch = torch
        self.model = model
        self.device = device
        self.parameters = tuple(model.parameters())
        if not self.parameters:
            raise DenseTrainingError("loaded model has no parameters")
        for parameter in self.parameters:
            if parameter.dtype != torch.bfloat16:
                raise DenseTrainingError("every model parameter must be BF16")
            if parameter.requires_grad is not True:
                raise DenseTrainingError("every model parameter must be trainable")
        self.parameter_elements = sum(int(parameter.numel()) for parameter in self.parameters)
        if self.parameter_elements >= 1_000_000_000:
            raise DenseTrainingError("runtime model is not below one billion parameters")
        self.optimizer = FP32AdamW(torch, self.parameters)

    def zero_grad(self) -> None:
        self.optimizer.zero_grad()

    def backward_loss_sum(self, rows: Sequence[PackedSequence]) -> float:
        supervised = sum(row.supervised_tokens for row in rows)
        if supervised <= 0:
            raise DenseTrainingError("microbatch has no supervised tokens")
        tensor = self.torch.tensor
        input_ids = tensor([row.input_ids for row in rows], dtype=self.torch.long, device=self.device)
        attention = tensor(
            [row.attention_mask for row in rows], dtype=self.torch.long, device=self.device
        )
        positions = tensor(
            [row.position_ids for row in rows], dtype=self.torch.long, device=self.device
        )
        labels = tensor([row.labels for row in rows], dtype=self.torch.long, device=self.device)
        outputs = self.model(
            input_ids=input_ids,
            attention_mask=attention,
            position_ids=positions,
            labels=labels,
            use_cache=False,
        )
        loss = getattr(outputs, "loss", None)
        if loss is None or loss.numel() != 1 or not bool(self.torch.isfinite(loss)):
            raise DenseTrainingError("model returned a missing or non-finite scalar loss")
        loss_sum = loss * supervised
        loss_sum.backward()
        return float(loss_sum.detach().to(dtype=self.torch.float32).cpu())

    def divide_gradients(self, supervised_tokens: int) -> None:
        if supervised_tokens <= 0:
            raise DenseTrainingError("cannot normalize gradients by zero tokens")
        scale = 1.0 / supervised_tokens
        for parameter in self.parameters:
            if parameter.grad is None:
                raise DenseTrainingError(
                    "a full-model parameter received no gradient for this optimizer update"
                )
            parameter.grad.mul_(scale)

    def clip_grad_norm(self, maximum: float) -> float:
        norm = self.torch.nn.utils.clip_grad_norm_(self.parameters, maximum)
        return float(norm.detach().to(dtype=self.torch.float32).cpu())

    def optimizer_step(self, learning_rate: float) -> None:
        self.optimizer.step(learning_rate)

    def estimate_step_flops(self, token_slots: int) -> int:
        return 6 * self.parameter_elements * token_slots

    def runtime_record(self) -> dict[str, Any]:
        state_dtypes = self.optimizer.state_dtypes()
        if state_dtypes and state_dtypes != {self.torch.float32}:
            raise DenseTrainingError("AdamW moment states are not wholly FP32")
        if self.optimizer.step_ordinal and len(self.optimizer.states) != len(self.parameters):
            raise DenseTrainingError("AdamW does not hold FP32 states for every model parameter")
        return {
            "full_model_trainable": True,
            "parameter_dtype": "bfloat16",
            "optimizer_state_dtype": "float32",
            "physical_parameter_elements": self.parameter_elements,
            "optimizer_state_parameter_tensors": len(self.optimizer.states),
            "flop_estimator": "6_times_runtime_parameter_elements_times_packed_token_slots",
            "flop_estimate_is_hardware_measured": False,
        }


__all__ = [
    "CANARY_SCHEMA_VERSION",
    "COMPLETION_FILE_NAME",
    "DenseCanaryConfig",
    "DenseTrainingError",
    "FP32AdamW",
    "LEDGER_FILE_NAME",
    "MaterializedSchedule",
    "PackedSequence",
    "TorchDenseRuntime",
    "learning_rate_for_update",
    "ledger_payload",
    "materialize_packed_schedule",
    "publish_checkpoint_noreplace",
    "run_dense_canary_training",
    "validate_published_checkpoint",
]
