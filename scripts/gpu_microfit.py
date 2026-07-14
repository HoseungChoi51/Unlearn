#!/usr/bin/env python3
"""Run a local-artifact GPU micro-training fit probe with seeded inputs.

This is an engineering diagnostic, not a benchmark or research endpoint.  It
loads one already-materialized dense Safetensors artifact, performs warm-up
and measured optimizer steps on reproducible synthetic token IDs, and emits a
content-addressed JSON record.  Hugging Face loading is requested offline and
local-only, but this script does not provide OS-level socket isolation.  CUDA
training-trajectory determinism is not guaranteed.  It never evaluates
terminal behavior or writes model weights.
"""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import sys
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.manifests import atomic_write_json, canonical_json_bytes  # noqa: E402
from cbds.model_artifacts import InspectionLimits, inspect_model_artifact  # noqa: E402
from cbds.model_runtime import (  # noqa: E402
    ModelRuntimeProbeError,
    _artifact_state,
    account_loaded_model_tensors,
)


RECORD_VERSION = "1.1.0"


class MicrofitError(ValueError):
    """Raised when the requested probe is unsafe or cannot be qualified."""


def _load_ml_dependencies() -> tuple[Any, Any, Any]:
    """Import the optional GPU stack through one injectable test boundary."""

    try:
        import torch
        import transformers
        from transformers import AutoModelForCausalLM
    except ImportError as error:
        raise MicrofitError("torch and transformers are required") from error
    return torch, transformers, AutoModelForCausalLM


def _inspection_identity(inspection: dict[str, Any]) -> dict[str, Any]:
    """Return the portable content identity recorded at each stability pass."""

    return {
        "inspection_report_sha256": inspection["report_sha256"],
        "bundle_manifest_sha256": inspection["bundle_manifest_sha256"],
        "weight_set_sha256": inspection["weight_set_sha256"],
        "static_classification": inspection["architecture"]["classification"],
        "stored_tensor_elements": inspection["weights"][
            "stored_tensor_element_count"
        ],
        "safetensors_payload_bytes": inspection["weights"][
            "safetensors_payload_bytes"
        ],
    }


def _require_artifact_match(
    *,
    initial_inspection: dict[str, Any],
    initial_state: object,
    observed_inspection: dict[str, Any],
    observed_state: object,
    stage: str,
) -> None:
    if (
        observed_inspection.get("report_sha256")
        != initial_inspection.get("report_sha256")
        or observed_state != initial_state
    ):
        raise MicrofitError(f"artifact changed during microfit {stage}")


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be a positive integer")
    return parsed


def _nonnegative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be a nonnegative integer")
    return parsed


def _finite_positive_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("value must be finite and positive")
    return parsed


def _finite_nonnegative_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed < 0:
        raise argparse.ArgumentTypeError("value must be finite and nonnegative")
    return parsed


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="content-addressed local-only CUDA micro-training probe"
    )
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--expected-inspection-report-sha256")
    parser.add_argument("--batch-size", type=_positive_int, default=1)
    parser.add_argument("--sequence-length", type=_positive_int, default=512)
    parser.add_argument("--warmup-steps", type=_nonnegative_int, default=1)
    parser.add_argument("--measured-steps", type=_positive_int, default=3)
    parser.add_argument("--seed", type=int, default=20260714)
    parser.add_argument("--learning-rate", type=_finite_positive_float, default=1e-5)
    parser.add_argument("--weight-decay", type=_finite_nonnegative_float, default=0.1)
    parser.add_argument("--gradient-clip", type=_finite_positive_float, default=1.0)
    parser.add_argument(
        "--no-gradient-checkpointing",
        action="store_true",
        help="disable activation checkpointing for this diagnostic",
    )
    return parser


def _run(args: argparse.Namespace) -> dict[str, Any]:
    if args.sequence_length > 16_384:
        raise MicrofitError("sequence length exceeds the diagnostic ceiling")
    if args.batch_size > 128:
        raise MicrofitError("batch size exceeds the diagnostic ceiling")
    if args.warmup_steps + args.measured_steps > 100:
        raise MicrofitError("total optimizer steps exceed the diagnostic ceiling")
    if args.output is not None:
        try:
            if args.output.resolve(strict=False).is_relative_to(
                args.artifact_dir.resolve(strict=True)
            ):
                raise MicrofitError("output must be outside the model artifact")
        except OSError as error:
            raise MicrofitError("cannot resolve artifact or output path") from error

    limits = InspectionLimits()
    inspection = inspect_model_artifact(args.artifact_dir, limits=limits)
    inspection_hash = inspection["report_sha256"]
    expected_hash = args.expected_inspection_report_sha256
    if expected_hash is not None and expected_hash != inspection_hash:
        raise MicrofitError("inspection report hash does not match --expected value")
    if inspection["architecture"]["classification"] != "dense_consistent":
        raise MicrofitError("microfit requires a statically dense-consistent artifact")
    if not inspection["claim_qualification"][
        "stored_tensor_element_count_below_one_billion"
    ]:
        raise MicrofitError("artifact is not below the one-billion stored-element gate")
    initial_artifact_state = _artifact_state(args.artifact_dir, limits)

    # Enforce offline behavior before importing the model stack.  The explicit
    # from_pretrained flags below are the primary control; these variables make
    # accidental Hub requests fail closed in supporting libraries as well.
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    os.environ["TOKENIZERS_PARALLELISM"] = "false"
    torch, transformers, AutoModelForCausalLM = _load_ml_dependencies()

    if not torch.cuda.is_available():
        raise MicrofitError("CUDA is not available")
    if not torch.cuda.is_bf16_supported():
        raise MicrofitError("the selected CUDA device does not support BF16")

    torch.manual_seed(args.seed)
    torch.cuda.manual_seed_all(args.seed)
    torch.backends.cuda.matmul.allow_tf32 = False
    torch.backends.cudnn.allow_tf32 = False
    torch.cuda.set_device(0)
    torch.cuda.empty_cache()

    load_started = time.perf_counter()
    model = AutoModelForCausalLM.from_pretrained(
        args.artifact_dir,
        local_files_only=True,
        trust_remote_code=False,
        use_safetensors=True,
        torch_dtype=torch.bfloat16,
    )
    model.to(torch.device("cuda", 0))
    model.train()
    model.config.use_cache = False
    checkpointing = not args.no_gradient_checkpointing
    if checkpointing:
        model.gradient_checkpointing_enable()
    torch.cuda.synchronize()
    load_seconds = time.perf_counter() - load_started

    loaded_inspection = inspect_model_artifact(args.artifact_dir, limits=limits)
    loaded_artifact_state = _artifact_state(args.artifact_dir, limits)
    _require_artifact_match(
        initial_inspection=inspection,
        initial_state=initial_artifact_state,
        observed_inspection=loaded_inspection,
        observed_state=loaded_artifact_state,
        stage="model load",
    )

    accounting = account_loaded_model_tensors(model)
    parameter_accounting = accounting["parameters"]
    buffer_accounting = accounting["buffers"]
    if accounting["parameter_devices"] != ["cuda:0"] or (
        accounting["buffer_devices"]
        and accounting["buffer_devices"] != ["cuda:0"]
    ):
        raise MicrofitError("model tensors are not wholly placed on cuda:0")
    physical_parameters = int(parameter_accounting["physical_elements"])
    parameter_bytes = int(parameter_accounting["physical_bytes"])
    trainable_parameters = int(parameter_accounting["trainable_elements"])
    trainable_bytes = int(parameter_accounting["trainable_bytes"])
    if physical_parameters >= 1_000_000_000:
        raise MicrofitError("runtime parameter graph is not below one billion")

    vocabulary_size = int(model.config.vocab_size)
    if vocabulary_size <= 1:
        raise MicrofitError("model vocabulary size is invalid")
    generator = torch.Generator(device="cpu")
    generator.manual_seed(args.seed)
    input_ids = torch.randint(
        0,
        vocabulary_size,
        (args.batch_size, args.sequence_length),
        generator=generator,
        dtype=torch.long,
        device="cpu",
    )
    input_sha256 = sha256(input_ids.numpy().tobytes(order="C")).hexdigest()
    input_ids = input_ids.to(device=torch.device("cuda", 0), non_blocking=False)
    attention_mask = torch.ones_like(input_ids)
    labels = input_ids.clone()

    optimizer = torch.optim.AdamW(
        model.parameters(),
        lr=args.learning_rate,
        betas=(0.9, 0.95),
        weight_decay=args.weight_decay,
        fused=True,
    )

    def one_step() -> float:
        optimizer.zero_grad(set_to_none=True)
        outputs = model(
            input_ids=input_ids,
            attention_mask=attention_mask,
            labels=labels,
            use_cache=False,
        )
        loss = outputs.loss
        if loss is None or loss.numel() != 1 or not bool(torch.isfinite(loss)):
            raise MicrofitError("training loss is missing or non-finite")
        loss.backward()
        norm = torch.nn.utils.clip_grad_norm_(model.parameters(), args.gradient_clip)
        if not bool(torch.isfinite(norm)):
            raise MicrofitError("gradient norm is non-finite")
        optimizer.step()
        torch.cuda.synchronize()
        return float(loss.detach().cpu())

    warmup_losses = [one_step() for _ in range(args.warmup_steps)]
    torch.cuda.reset_peak_memory_stats()
    measured_started = time.perf_counter()
    measured_losses = [one_step() for _ in range(args.measured_steps)]
    measured_seconds = time.perf_counter() - measured_started
    if measured_seconds <= 0 or not math.isfinite(measured_seconds):
        raise MicrofitError("invalid measured duration")
    tokens = args.batch_size * args.sequence_length * args.measured_steps

    final_inspection = inspect_model_artifact(args.artifact_dir, limits=limits)
    final_artifact_state = _artifact_state(args.artifact_dir, limits)
    _require_artifact_match(
        initial_inspection=inspection,
        initial_state=initial_artifact_state,
        observed_inspection=final_inspection,
        observed_state=final_artifact_state,
        stage="training",
    )

    device = torch.cuda.current_device()
    properties = torch.cuda.get_device_properties(device)
    record: dict[str, Any] = {
        "record_type": "cbds.gpu-microfit",
        "record_version": RECORD_VERSION,
        "status": "completed_engineering_diagnostic",
        "claim_scope": "none",
        "data_scope": "seeded_synthetic_token_ids_only",
        "reproducibility_scope": {
            "synthetic_input_ids_reproducible_from_seed": True,
            "cuda_training_trajectory_determinism_guaranteed": False,
        },
        "network_access": (
            "huggingface_offline_and_local_only_requested;"
            "os_socket_isolation_not_provided"
        ),
        "artifact": {
            "initial": _inspection_identity(inspection),
            "after_load": _inspection_identity(loaded_inspection),
            "final": _inspection_identity(final_inspection),
            "content_and_metadata_match_after_load": True,
            "content_and_metadata_match_after_training": True,
        },
        "runtime": {
            "model_class": type(model).__name__,
            "torch_version": torch.__version__,
            "transformers_version": transformers.__version__,
            "cuda_runtime_version": torch.version.cuda,
            "device_name": properties.name,
            "device_total_memory_bytes": int(properties.total_memory),
            "compute_capability": [int(properties.major), int(properties.minor)],
            "physical_parameter_elements": physical_parameters,
            "parameter_payload_bytes": parameter_bytes,
            "parameter_accounting_by_dtype": parameter_accounting["by_dtype"],
            "trainable_parameter_elements": trainable_parameters,
            "trainable_parameter_payload_bytes": trainable_bytes,
            "buffer_accounting": buffer_accounting,
            "load_seconds": load_seconds,
        },
        "configuration": {
            "batch_size": args.batch_size,
            "sequence_length": args.sequence_length,
            "warmup_steps": args.warmup_steps,
            "measured_steps": args.measured_steps,
            "seed": args.seed,
            "learning_rate": args.learning_rate,
            "weight_decay": args.weight_decay,
            "adam_betas": [0.9, 0.95],
            "gradient_clip": args.gradient_clip,
            "gradient_checkpointing": checkpointing,
            "precision": "bfloat16",
            "tf32_enabled": False,
            "deterministic_algorithms_enforced": False,
            "optimizer": "torch.optim.AdamW(fused=True)",
            "input_ids_sha256": input_sha256,
        },
        "measurements": {
            "warmup_losses": warmup_losses,
            "measured_losses": measured_losses,
            "measured_seconds": measured_seconds,
            "measured_tokens": tokens,
            "optimizer_visible_tokens_per_second": tokens / measured_seconds,
            "milliseconds_per_optimizer_step": (
                measured_seconds * 1000.0 / args.measured_steps
            ),
            "peak_cuda_memory_allocated_bytes": int(
                torch.cuda.max_memory_allocated(device)
            ),
            "peak_cuda_memory_reserved_bytes": int(
                torch.cuda.max_memory_reserved(device)
            ),
        },
        "implementation": {
            "script_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
            "record_hash_scope": (
                "canonical JSON of every field except record_sha256"
            ),
        },
    }
    record["record_sha256"] = sha256(canonical_json_bytes(record)).hexdigest()
    return record


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        record = _run(args)
        if args.output is None:
            print(canonical_json_bytes(record).decode("utf-8"))
        else:
            atomic_write_json(args.output, record)
    except (
        MicrofitError,
        ModelRuntimeProbeError,
        OSError,
        RuntimeError,
        ValueError,
    ) as error:
        print(
            json.dumps(
                {"error": type(error).__name__, "message": str(error)},
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
