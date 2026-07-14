#!/usr/bin/env python3
"""Run a non-claiming, real-text dense SFT engineering canary.

The script consumes only an externally pinned token schedule and its
source-replay inputs.  It is intentionally not a campaign runner, checkpoint
selector, or research endpoint.  Hugging Face loading is local-only with
remote code disabled and Safetensors required.
"""

from __future__ import annotations

import argparse
from hashlib import sha256
import importlib.metadata
import json
import math
import os
from pathlib import Path
import platform
import sys
import time
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.dense_training import (  # noqa: E402
    DenseCanaryConfig,
    DenseTrainingError,
    TorchDenseRuntime,
    materialize_packed_schedule,
    publish_checkpoint_noreplace,
    run_dense_canary_training,
    validate_published_checkpoint,
)
from cbds.manifests import canonical_json_bytes, value_sha256  # noqa: E402
from cbds.model_artifacts import (  # noqa: E402
    InspectionLimits,
    ModelArtifactInspectionError,
    inspect_model_artifact,
)
from cbds.token_schedule import (  # noqa: E402
    TokenScheduleError,
    load_local_tokenizer,
    validate_token_schedule_artifacts,
)


SCRIPT_VERSION = "1.0.0"


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be a positive integer")
    return parsed


def _finite_positive_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("value must be finite and positive")
    return parsed


def _sha(value: str) -> str:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise argparse.ArgumentTypeError("value must be a lowercase SHA-256")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="engineering-only dense SFT canary from an authenticated token schedule"
    )
    parser.add_argument("--model-dir", type=Path, required=True)
    parser.add_argument("--tokenizer-dir", type=Path, required=True)
    parser.add_argument("--schedule-dir", type=Path, required=True)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--corpus-source-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--expected-model-inspection-sha256", type=_sha, required=True)
    parser.add_argument("--expected-schedule-sha256", type=_sha, required=True)
    parser.add_argument("--expected-schedule-manifest-sha256", type=_sha, required=True)
    parser.add_argument("--expected-total-visible-tokens", type=_positive_int, required=True)
    parser.add_argument("--learning-rate", type=_finite_positive_float, required=True)
    parser.add_argument("--microbatch-sequences", type=_positive_int, default=8)
    parser.add_argument("--accumulation-microbatches", type=_positive_int, default=1)
    parser.add_argument("--seed", type=int, default=20260715)
    parser.add_argument(
        "--no-gradient-checkpointing",
        action="store_true",
        help="disable activation checkpointing; all parameters remain trainable",
    )
    return parser


def _load_ml_dependencies() -> tuple[Any, Any, Any, Any]:
    """Import the optional runtime stack through one testable boundary."""

    try:
        import torch
        import transformers
        from safetensors import safe_open
        from transformers import AutoModelForCausalLM
    except ImportError as exc:
        raise DenseTrainingError(
            "torch, transformers, tokenizers, and safetensors are required"
        ) from exc
    return torch, transformers, AutoModelForCausalLM, safe_open


def _load_local_bf16_model(
    auto_model_for_causal_lm: Any, torch: Any, model_dir: Path
) -> Any:
    """Load through one narrow boundary whose safety flags are unit-testable."""

    return auto_model_for_causal_lm.from_pretrained(
        model_dir,
        local_files_only=True,
        trust_remote_code=False,
        use_safetensors=True,
        torch_dtype=torch.bfloat16,
    )


def _package_versions() -> dict[str, str | None]:
    result: dict[str, str | None] = {}
    for name in (
        "torch",
        "transformers",
        "tokenizers",
        "safetensors",
        "huggingface-hub",
        "accelerate",
    ):
        try:
            result[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            result[name] = None
    return result


def _code_identity() -> dict[str, Any]:
    paths = (
        Path(__file__).resolve(),
        ROOT / "src" / "cbds" / "dense_training.py",
        ROOT / "src" / "cbds" / "manifests.py",
        ROOT / "src" / "cbds" / "model_artifacts.py",
        ROOT / "src" / "cbds" / "token_schedule.py",
        ROOT / "src" / "cbds" / "training_corpus.py",
    )
    files = [
        {
            "path": str(path.relative_to(ROOT)),
            "bytes": path.stat().st_size,
            "sha256": sha256(path.read_bytes()).hexdigest(),
        }
        for path in paths
    ]
    return {
        "script_version": SCRIPT_VERSION,
        "files": files,
        "source_set_sha256": value_sha256(
            {"domain": "cbds.dense-sft-canary.source-set.v1", "files": files}
        ),
    }


def _model_identity(inspection: Mapping[str, Any]) -> dict[str, Any]:
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


def _engineering_measurements(
    training_summary: Mapping[str, Any], training_wall_seconds: float, torch: Any
) -> dict[str, Any]:
    """Build descriptive pilot measurements that are prohibited for selection."""

    if not math.isfinite(training_wall_seconds) or training_wall_seconds <= 0:
        raise DenseTrainingError("training wall-clock measurement is invalid")
    optimizer_updates = training_summary.get("optimizer_updates")
    visible_tokens = training_summary.get("visible_tokens")
    supervised_tokens = training_summary.get("supervised_tokens")
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value <= 0
        for value in (optimizer_updates, visible_tokens, supervised_tokens)
    ):
        raise DenseTrainingError("training summary lacks positive pilot counters")
    return {
        "scope": "descriptive_engineering_pilot_recalibration_only",
        "trajectory_determinism_guaranteed": False,
        "campaign_eligible": False,
        "model_selection_eligible": False,
        "claim_eligible": False,
        "training_wall_seconds_monotonic": training_wall_seconds,
        "visible_tokens_per_second": visible_tokens / training_wall_seconds,
        "supervised_tokens_per_second": supervised_tokens / training_wall_seconds,
        "milliseconds_per_optimizer_update": (
            training_wall_seconds * 1000.0 / optimizer_updates
        ),
        "peak_cuda_memory_allocated_bytes": int(torch.cuda.max_memory_allocated(0)),
        "peak_cuda_memory_reserved_bytes": int(torch.cuda.max_memory_reserved(0)),
        "timing_boundary": (
            "after_cuda_synchronize_and_peak_reset_through_training_loop_and_final_synchronize"
        ),
        "selection_use_prohibited": True,
    }


def _ensure_output_separate(output: Path, inputs: tuple[Path, ...]) -> None:
    try:
        requested = output.resolve(strict=False)
        for source in inputs:
            resolved = source.resolve(strict=True)
            if requested == resolved or requested.is_relative_to(resolved):
                raise DenseTrainingError("output directory must be outside every input artifact")
    except OSError as exc:
        raise DenseTrainingError("cannot resolve an input or output path") from exc


def _hash_safetensor_tensors(staging: Path, torch: Any, safe_open: Any) -> str:
    """Hash logical tensors by sorted name, dtype, shape, and exact bytes."""

    tensor_locations: list[tuple[str, Path]] = []
    seen: set[str] = set()
    for path in sorted(staging.glob("*.safetensors"), key=lambda item: item.name.encode("utf-8")):
        with safe_open(str(path), framework="pt", device="cpu") as handle:
            for name in handle.keys():
                if name in seen:
                    raise DenseTrainingError("exported Safetensors contain a duplicate tensor name")
                seen.add(name)
                tensor_locations.append((name, path))
    if not tensor_locations:
        raise DenseTrainingError("checkpoint export contains no Safetensors tensors")
    digest = sha256()
    for name, path in sorted(tensor_locations, key=lambda item: item[0].encode("utf-8")):
        with safe_open(str(path), framework="pt", device="cpu") as handle:
            contiguous = handle.get_tensor(name).detach().cpu().contiguous()
        header = canonical_json_bytes(
            {
                "name": name,
                "dtype": str(contiguous.dtype),
                "shape": [int(item) for item in contiguous.shape],
            }
        )
        raw = contiguous.view(torch.uint8).numpy().tobytes(order="C")
        digest.update(len(header).to_bytes(8, "big"))
        digest.update(header)
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    return digest.hexdigest()


def _run(args: argparse.Namespace) -> dict[str, Any]:
    _ensure_output_separate(
        args.output_dir,
        (
            args.model_dir,
            args.tokenizer_dir,
            args.schedule_dir,
            args.corpus_dir,
            args.corpus_source_root,
        ),
    )
    limits = InspectionLimits()
    initial_inspection = inspect_model_artifact(args.model_dir, limits=limits)
    if initial_inspection["report_sha256"] != args.expected_model_inspection_sha256:
        raise DenseTrainingError("model inspection differs from the external pin")
    if initial_inspection["architecture"]["classification"] != "dense_consistent":
        raise DenseTrainingError("canary requires a statically dense-consistent checkpoint")
    qualification = initial_inspection["claim_qualification"]
    if qualification["dense_consistent_with_below_one_billion_stored_elements"] is not True:
        raise DenseTrainingError("checkpoint fails the dense, unpacked, sub-billion static gate")

    # These variables make supporting Hub libraries fail offline.  The
    # explicit local-only/remote-code flags below remain the primary control.
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    os.environ["TOKENIZERS_PARALLELISM"] = "false"
    torch, transformers, AutoModelForCausalLM, safe_open = _load_ml_dependencies()
    if not torch.cuda.is_available():
        raise DenseTrainingError("CUDA is unavailable")
    if not torch.cuda.is_bf16_supported():
        raise DenseTrainingError("the selected CUDA device does not support BF16")
    torch.cuda.set_device(0)
    torch.manual_seed(args.seed)
    torch.cuda.manual_seed_all(args.seed)
    torch.backends.cuda.matmul.allow_tf32 = False
    torch.backends.cudnn.allow_tf32 = False
    if hasattr(torch, "use_deterministic_algorithms"):
        torch.use_deterministic_algorithms(True)

    tokenizer = load_local_tokenizer(args.tokenizer_dir)
    model = _load_local_bf16_model(AutoModelForCausalLM, torch, args.model_dir)
    device = torch.device("cuda", 0)
    model.to(device)
    model.train()
    model.config.use_cache = False
    for parameter in model.parameters():
        parameter.requires_grad_(True)
    checkpointing = not args.no_gradient_checkpointing
    if checkpointing:
        model.gradient_checkpointing_enable()
    embedding = model.get_input_embeddings()
    embedding_rows = getattr(embedding, "num_embeddings", None)
    if isinstance(embedding_rows, bool) or not isinstance(embedding_rows, int):
        raise DenseTrainingError("runtime input embedding row count is unavailable")

    loaded_inspection = inspect_model_artifact(args.model_dir, limits=limits)
    if loaded_inspection["report_sha256"] != initial_inspection["report_sha256"]:
        raise DenseTrainingError("model artifact changed while loading")
    schedule = materialize_packed_schedule(
        args.schedule_dir,
        corpus_dir=args.corpus_dir,
        corpus_source_root=args.corpus_source_root,
        tokenizer_root=args.tokenizer_dir,
        tokenizer=tokenizer,
        model_embedding_rows=embedding_rows,
        expected_schedule_sha256=args.expected_schedule_sha256,
        expected_manifest_sha256=args.expected_schedule_manifest_sha256,
    )
    configuration = DenseCanaryConfig(
        base_learning_rate=args.learning_rate,
        microbatch_sequences=args.microbatch_sequences,
        accumulation_microbatches=args.accumulation_microbatches,
        expected_total_visible_tokens=args.expected_total_visible_tokens,
        seed=args.seed,
    )
    runtime = TorchDenseRuntime(torch, model, device)
    properties = torch.cuda.get_device_properties(0)
    code = _code_identity()
    dependencies = _package_versions()
    environment = {
        "python_version": platform.python_version(),
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "byteorder": sys.byteorder,
        "torch_version": torch.__version__,
        "transformers_version": transformers.__version__,
        "cuda_runtime_version": torch.version.cuda,
        "device_name": properties.name,
        "device_total_memory_bytes": int(properties.total_memory),
        "compute_capability": [int(properties.major), int(properties.minor)],
        "tf32_enabled": False,
        "deterministic_algorithms_requested": True,
        "network_control": (
            "huggingface_offline_and_local_only_requested_os_socket_isolation_not_provided"
        ),
    }
    execution_binding = {
        "source_model": _model_identity(initial_inspection),
        "code": code,
        "dependencies": dependencies,
        "environment": environment,
        "runtime": runtime.runtime_record(),
        "gradient_checkpointing": checkpointing,
        "model_loader": {
            "local_files_only": True,
            "trust_remote_code": False,
            "use_safetensors": True,
            "torch_dtype": "bfloat16",
        },
        "tokenizer_loader": {
            "local_files_only": True,
            "trust_remote_code": False,
            "use_fast": True,
        },
        "claim_scope": "none_engineering_canary_only",
    }
    torch.cuda.synchronize()
    torch.cuda.reset_peak_memory_stats(0)
    training_started = time.perf_counter()
    ledger, training_summary = run_dense_canary_training(
        schedule, configuration, runtime, execution_binding=execution_binding
    )
    torch.cuda.synchronize()
    training_wall_seconds = time.perf_counter() - training_started
    engineering_measurements = _engineering_measurements(
        training_summary, training_wall_seconds, torch
    )
    final_runtime = runtime.runtime_record()
    if final_runtime["optimizer_state_dtype"] != "float32":
        raise DenseTrainingError("optimizer state dtype attestation failed")

    final_schedule_validation = validate_token_schedule_artifacts(
        args.schedule_dir,
        corpus_dir=args.corpus_dir,
        corpus_source_root=args.corpus_source_root,
        tokenizer_root=args.tokenizer_dir,
        tokenizer=tokenizer,
        model_embedding_rows=embedding_rows,
        expected_schedule_sha256=args.expected_schedule_sha256,
        expected_manifest_sha256=args.expected_schedule_manifest_sha256,
    )
    for key in ("schedule_sha256", "manifest_sha256", "config_sha256", "source_corpus_sha256"):
        if final_schedule_validation.get(key) != schedule.identity.get(key):
            raise DenseTrainingError("schedule identity changed during training")
    final_source_inspection = inspect_model_artifact(args.model_dir, limits=limits)
    if final_source_inspection["report_sha256"] != initial_inspection["report_sha256"]:
        raise DenseTrainingError("source model artifact changed during training")

    completion_base: dict[str, Any] = {
        "training_executed_engineering_canary": True,
        "campaign_eligible": False,
        "model_selection_eligible": False,
        "claim_eligible": False,
        "source_schedule_target_policy_accepted": False,
        "source_model": {
            "initial": _model_identity(initial_inspection),
            "after_load": _model_identity(loaded_inspection),
            "final": _model_identity(final_source_inspection),
            "stable": True,
        },
        "source_schedule": dict(schedule.identity),
        "training_configuration": configuration.to_record(),
        "training_summary": training_summary,
        "engineering_measurements": engineering_measurements,
        "runtime": final_runtime,
        "code": code,
        "dependencies": dependencies,
        "environment": environment,
    }

    def export(model_root: Path) -> None:
        model.save_pretrained(
            model_root,
            safe_serialization=True,
            max_shard_size="5GB",
        )
        tokenizer.save_pretrained(model_root)

    completion = publish_checkpoint_noreplace(
        args.output_dir,
        ledger_records=ledger,
        completion_base=completion_base,
        exporter=export,
        tensor_hasher=lambda staging: _hash_safetensor_tensors(
            staging, torch, safe_open
        ),
    )
    validated_export = validate_published_checkpoint(
        args.output_dir,
        tensor_hasher=lambda checkpoint: _hash_safetensor_tensors(
            checkpoint, torch, safe_open
        ),
        expected_model_inspection_sha256=args.expected_model_inspection_sha256,
        expected_schedule_sha256=args.expected_schedule_sha256,
        expected_schedule_manifest_sha256=args.expected_schedule_manifest_sha256,
    )
    if validated_export["completion_sha256"] != completion["completion_sha256"]:
        raise DenseTrainingError("published completion identity changed after atomic rename")
    return completion


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        completion = _run(args)
    except (
        DenseTrainingError,
        ModelArtifactInspectionError,
        TokenScheduleError,
        OSError,
        RuntimeError,
        ValueError,
    ) as exc:
        print(
            json.dumps(
                {"error": type(exc).__name__, "message": str(exc)},
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 2
    print(canonical_json_bytes(completion).decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
