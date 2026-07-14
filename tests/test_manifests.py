from __future__ import annotations

import copy
import hashlib
import json
import math
import tempfile
import unittest
from pathlib import Path

from cbds.manifests import (
    EXPERIMENT_SCHEMA_VERSION,
    HARDWARE_SCHEMA_VERSION,
    MAX_DOCUMENT_BYTES,
    ManifestValidationError,
    atomic_write_json,
    canonical_json,
    canonical_json_bytes,
    file_sha256,
    load_document,
    load_experiment_manifest,
    merge_hardware_results,
    validate_experiment_manifest,
    validate_hardware_result,
    validate_hardware_result_against_experiment_manifest,
    value_sha256,
)
from cbds.run_specs import (
    CampaignRunValidationError,
    CompletedRunValidationError,
    load_campaign_policy,
    load_completed_run,
    load_completed_run_against_campaign,
    run_spec_sha256,
    validate_completed_run,
    validate_completed_run_against_campaign,
)


ROOT = Path(__file__).resolve().parents[1]
SHA1 = "1" * 40
SHA256 = "a" * 64
OTHER_SHA256 = "b" * 64


def valid_experiment_manifest() -> dict:
    return {
        "schema_version": "2.0.0",
        "experiment_id": "experiment-0001",
        "run_id": "planned-run-0001",
        "stage": "train",
        "run_spec_schema_version": "2.0.0",
        "run_spec_sha256": "0" * 64,
        "created_at": "2026-07-14T12:00:00+09:00",
        "git_revision": SHA1,
        "model": {
            "repository": "Qwen/Qwen3-0.6B-Base",
            "revision": "2" * 40,
            "inspection_report_sha256": "e" * 64,
            "architecture": "dense",
            "physical_parameters": 600_000_000,
        },
        "tokenizer": {
            "repository": "Qwen/Qwen3-0.6B-Base",
            "revision": "2" * 40,
            "source_sha256": "3" * 64,
            "derived_vocabulary_mapping_sha256": None,
            "vocabulary_size": 151_936,
        },
        "data": {
            "manifest_sha256": "4" * 64,
            "semantic_graph_sha256": "5" * 64,
            "fixtures_sha256": "6" * 64,
            "splits": [
                {
                    "name": "training",
                    "sha256": "7" * 64,
                    "sealed": False,
                    "role": "training",
                },
                {
                    "name": "shadow-validation",
                    "sha256": "8" * 64,
                    "sealed": False,
                    "role": "shadow_validation",
                },
                {
                    "name": "operator-selection",
                    "sha256": "9" * 64,
                    "sealed": False,
                    "role": "operator_selection",
                },
            ],
        },
        "execution": {
            "container_image_digest": f"terminal@sha256:{'9' * 64}",
            "verifier_revision": "a" * 40,
            "verifier_sha256": "b" * 64,
        },
        "capability_mixture": {
            "target": [
                {
                    "name": "unix_terminal",
                    "fraction": 0.8,
                    "data_sha256": "c" * 64,
                }
            ],
            "support": [
                {
                    "name": "instruction_comprehension",
                    "fraction": 0.2,
                    "data_sha256": "d" * 64,
                }
            ],
        },
        "teacher": {
            "enabled": True,
            "repository": "HuggingFaceTB/SmolLM3-3B",
            "revision": "e" * 40,
            "verified_corpus_sha256": "f" * 64,
            "generation_flops": 100.0,
        },
        "operator": {
            "mechanism": "recycle",
            "family": "ffn_reset_regrow",
            "configuration_sha256": "0" * 64,
            "dose": 0.1,
            "selection_strategy": "target_aware",
            "selection_split": "operator-selection",
            "structural_indices": [
                {"component": "ffn_channel", "layer": 0, "indices": [1, 2, 3]}
            ],
            "bit_allocation": [],
            "factorizations": [],
            "selection_manifest_sha256": "0" * 64,
            "archived_weights_sha256": "1" * 64,
        },
        "optimizer": {
            "enabled": True,
            "name": "AdamW",
            "parameter_groups": [
                {
                    "name": "backbone",
                    "role": "all_trainable",
                    "learning_rate": 0.00003,
                    "weight_decay": 0.1,
                }
            ],
            "betas": [0.9, 0.95],
            "epsilon": 1e-8,
            "gradient_clip": 1.0,
            "warmup_fraction": 0.05,
            "schedule": "cosine",
            "total_steps": 1_000,
        },
        "training_protocol": {
            "training_dtype": "bf16",
            "optimizer_state_dtype": "fp32",
            "microbatch_size": 8,
            "gradient_accumulation_steps": 1,
            "data_parallel_world_size": 1,
            "effective_batch_size": 8,
            "attention_backend": "sdpa",
            "gradient_checkpointing": True,
            "deterministic_algorithms": True,
            "packing": {
                "enabled": True,
                "strategy": "greedy",
                "minimum_sequence_length": 1024,
                "maximum_sequence_length": 2048,
            },
            "loss": {
                "objective": "causal_cross_entropy",
                "label_scope": "all_non_padding_tokens",
                "target_weight": 1.0,
                "support_weight": 1.0,
                "kl_weight": 0.0,
                "anchor_model_sha256": None,
            },
            "freezing": {
                "mode": "full_model",
                "trainable_parameters_sha256": None,
                "schedule_sha256": None,
            },
        },
        "seeds": {
            "model_initialization": 10,
            "data_order": 11,
            "training": 12,
            "operator_selection": 13,
            "evaluation": 14,
        },
        "tokens": {
            "optimizer_visible": 2_000_000,
            "target": 1_600_000,
            "replay": 400_000,
            "teacher_derived": 500_000,
            "selection_visible": 100_000,
        },
        "flops": {
            "selection": 10.0,
            "teacher_generation": 100.0,
            "training": 200.0,
            "compression": 20.0,
            "export": 5.0,
            "total": 335.0,
        },
        "checkpoint": {
            "selection_split": "shadow-validation",
            "metric": "static_pass_at_1",
            "mode": "max",
            "tie_breakers": ["bounded_terminal", "weight_bytes"],
            "rule": "Highest static pass@1; ties use listed metrics in order.",
        },
        "export": {
            "architecture": "dense",
            "format": "safetensors",
            "runtime_compatibility": ["transformers-sdpa"],
            "physical_parameters": 600_000_000,
            "active_parameters": 600_000_000,
            "nonzero_parameters": 599_000_000,
            "average_weight_bits": 16.0,
            "weight_bytes": 1_200_000_000,
            "bundle_bytes": 1_210_000_000,
            "tokenizer_included": True,
            "artifact_sha256": "2" * 64,
            "bundle_sha256": "3" * 64,
            "tokenizer_sha256": "4" * 64,
            "inspection_report_sha256": "5" * 64,
        },
    }


def completed_record_for_spec(spec: dict) -> dict:
    """Build synthetic measured output that exactly honors a test run spec."""

    record = valid_experiment_manifest()
    record.update(
        {
            "experiment_id": f"completed-{spec['run_id']}",
            "run_id": spec["run_id"],
            "stage": spec["stage"],
            "run_spec_schema_version": spec["schema_version"],
            "run_spec_sha256": run_spec_sha256(spec),
            "git_revision": spec["git_revision"],
        }
    )
    record["model"] = {
        field: spec["model"][field]
        for field in (
            "repository",
            "revision",
            "inspection_report_sha256",
            "architecture",
            "physical_parameters",
        )
    }
    record["tokenizer"] = {
        field: spec["tokenizer"][field]
        for field in (
            "repository",
            "revision",
            "source_sha256",
            "derived_vocabulary_mapping_sha256",
        )
    }
    record["tokenizer"]["vocabulary_size"] = spec["export"][
        "planned_vocabulary_size"
    ]
    record["data"] = {
        "manifest_sha256": spec["data"]["manifest_sha256"],
        "semantic_graph_sha256": spec["data"]["semantic_graph_sha256"],
        "fixtures_sha256": spec["data"]["fixtures_sha256"],
        "splits": copy.deepcopy(spec["data"]["splits"]),
    }
    record["execution"] = {
        field: spec["execution"][field]
        for field in ("container_image_digest", "verifier_revision", "verifier_sha256")
    }
    record["capability_mixture"] = {
        group: [
            {
                "name": entry["name"],
                "fraction": entry["fraction"],
                "data_sha256": entry["data_sha256"],
            }
            for entry in spec["capability_mixture"][group]
        ]
        for group in ("target", "support")
    }
    teacher = spec["teacher"]
    record["teacher"] = {
        "enabled": teacher["enabled"],
        "repository": teacher["repository"],
        "revision": teacher["revision"],
        "verified_corpus_sha256": "f" * 64 if teacher["enabled"] else None,
        "generation_flops": spec["compute_budget"]["teacher_generation_max_flops"],
    }
    operator = spec["operator"]
    record["operator"] = {
        "mechanism": operator["mechanism"],
        "family": operator["family"],
        "configuration_sha256": operator["configuration_sha256"],
        "dose": operator["dose"],
        "selection_strategy": operator["selection_strategy"],
        "selection_split": operator["selection_split"],
        "structural_indices": copy.deepcopy(operator["structural_indices"]),
        "bit_allocation": copy.deepcopy(operator["bit_allocation"]),
        "factorizations": copy.deepcopy(operator["factorizations"]),
        "selection_manifest_sha256": operator["selection_manifest_sha256"],
        "archived_weights_sha256": (
            "e" * 64 if operator["mechanism"] == "recycle" else None
        ),
    }
    record["optimizer"] = copy.deepcopy(spec["optimizer"])
    record["training_protocol"] = copy.deepcopy(spec["training_protocol"])
    record["seeds"] = copy.deepcopy(spec["seeds"])
    optimizer_tokens = spec["tokens"]["optimizer_visible"]
    record["tokens"] = {
        "optimizer_visible": optimizer_tokens,
        "target": spec["tokens"]["target"] if optimizer_tokens else 0,
        "replay": spec["tokens"]["support"] if optimizer_tokens else 0,
        "teacher_derived": spec["tokens"]["teacher_derived"],
        "selection_visible": spec["tokens"]["selection_visible"],
    }
    budget = spec["compute_budget"]
    record["flops"] = {
        "selection": budget["selection_max_flops"],
        "teacher_generation": budget["teacher_generation_max_flops"],
        "training": budget["optimization_max_flops"],
        "compression": budget["compression_max_flops"],
        "export": budget["export_max_flops"],
        "total": budget["total_max_flops"],
    }
    record["checkpoint"] = {
        field: copy.deepcopy(spec["checkpoint"][field])
        for field in ("selection_split", "metric", "mode", "tie_breakers", "rule")
    }
    planned_export = spec["export"]
    record["export"].update(
        {
            "format": planned_export["format"],
            "runtime_compatibility": copy.deepcopy(
                planned_export["runtime_compatibility"]
            ),
            "physical_parameters": planned_export["planned_physical_parameters"],
            "active_parameters": planned_export["planned_physical_parameters"],
            "nonzero_parameters": planned_export["planned_physical_parameters"],
            "average_weight_bits": planned_export["planned_average_weight_bits"],
            "weight_bytes": planned_export["maximum_weight_bytes"],
            "bundle_bytes": planned_export["maximum_bundle_bytes"],
            "tokenizer_included": planned_export["include_tokenizer"],
            "inspection_report_sha256": "6" * 64,
        }
    )
    return record


def summary(sample_count: int = 30) -> dict:
    if sample_count == 1:
        return {
            "sample_count": 1,
            "median": 2.0,
            "p95": 2.0,
            "minimum": 2.0,
            "maximum": 2.0,
        }
    return {
        "sample_count": sample_count,
        "median": 2.0,
        "p95": 3.0,
        "minimum": 1.0,
        "maximum": 4.0,
    }


def valid_hardware_result(run_id: str = "hardware-run-0001") -> dict:
    return {
        "schema_version": "2.0.0",
        "run_id": run_id,
        "created_at": "2026-07-14T12:00:00Z",
        "git_revision": SHA1,
        "dirty_worktree": False,
        "artifact": {
            "name": "qwen-terminal-075",
            "architecture": "dense",
            "format": "gguf",
            "sha256": SHA256,
            "bundle_sha256": OTHER_SHA256,
            "tokenizer_sha256": "c" * 64,
            "inspection_report_sha256": "e" * 64,
            "weight_bytes": 400_000_000,
            "bundle_bytes": 410_000_000,
            "physical_parameters": 450_000_000,
            "active_parameters": 450_000_000,
            "nonzero_parameters": 449_000_000,
            "average_weight_bits": 4.0,
            "method": "task-aware-quantization",
            "dose": "4-bit",
            "source_manifest_sha256": "d" * 64,
        },
        "hardware": {
            "machine_id": "machine-5090-01",
            "class": "nvidia_gpu",
            "device_name": "NVIDIA GeForce RTX 5090",
            "cpu_model": "Test CPU",
            "physical_cores": 8,
            "logical_threads": 16,
            "system_ram_bytes": 64_000_000_000,
            "device_memory_bytes": 32_000_000_000,
            "shared_memory": False,
            "driver": "test-driver-1",
            "firmware_or_runtime": "CUDA test",
            "power_mode": "fixed",
            "power_limit_watts": 400.0,
            "temperature_start_c": 40.0,
            "temperature_end_c": 50.0,
            "throttling_observed": False,
        },
        "software": {
            "operating_system": "Linux",
            "kernel": "6.0-test",
            "engine": "llama.cpp",
            "engine_revision": "engine-rev",
            "backend": "cuda",
            "compiler": "gcc test",
            "build_flags": ["GGML_CUDA=ON"],
            "threads": 8,
            "thread_affinity": None,
            "device_offload": "all",
            "kv_cache_precision": "f16",
            "context_size": 2048,
            "memory_mapping": True,
        },
        "workload": {
            "suite_sha256": "e" * 64,
            "workload_id": "decode-256",
            "kind": "token_controlled",
            "batch_size": 1,
            "prompt_tokens": 512,
            "generated_tokens": 256,
            "seed": 123,
            "deterministic": True,
            "prompt_sha256": "f" * 64,
        },
        "protocol": {
            "cold_start": False,
            "process_model": "single_loaded_process",
            "warmups": 10,
            "repetitions": 30,
            "temperature": 0,
            "synchronized_timing": True,
            "randomized_workload_order": True,
            "filesystem_cache_controlled": None,
        },
        "measurements": {
            "load_time_ms": None,
            "first_token_ms": summary(),
            "prefill_tokens_per_second": summary(),
            "decode_tokens_per_second": summary(),
            "wall_time_ms": summary(),
            "peak_host_rss_bytes": 1_000_000_000,
            "peak_device_memory_bytes": 2_000_000_000,
            "peak_framework_reserved_bytes": None,
            "mean_device_utilization_percent": 75.0,
            "energy_joules": None,
        },
        "correctness": {
            "gate_passed": True,
            "model_loaded": True,
            "accounting_matched": True,
            "token_hash_matched": True,
            "executable_outcome_matched": True,
            "unicode_fallback_passed": True,
            "functional_successes": 10,
            "functional_tasks": 10,
            "errors": [],
        },
        "raw_samples_sha256": "0" * 64,
        "notes": "synthetic test result",
    }


def hardware_result_for_completed_record(
    record: dict, run_id: str = "hardware-run-0001"
) -> dict:
    """Build a synthetic hardware result bound to a completed export."""

    result = valid_hardware_result(run_id)
    exported = record["export"]
    result["artifact"].update(
        {
            "architecture": exported["architecture"],
            "format": exported["format"],
            "sha256": exported["artifact_sha256"],
            "bundle_sha256": exported["bundle_sha256"],
            "tokenizer_sha256": exported["tokenizer_sha256"],
            "inspection_report_sha256": exported["inspection_report_sha256"],
            "weight_bytes": exported["weight_bytes"],
            "bundle_bytes": exported["bundle_bytes"],
            "physical_parameters": exported["physical_parameters"],
            "active_parameters": exported["active_parameters"],
            "nonzero_parameters": exported["nonzero_parameters"],
            "average_weight_bits": exported["average_weight_bits"],
            "method": record["operator"]["family"],
            "dose": record["operator"]["dose"],
            "source_manifest_sha256": value_sha256(record),
        }
    )
    return result


class CanonicalJsonTests(unittest.TestCase):
    def test_packaged_schemas_match_public_repository_copies(self) -> None:
        package_root = ROOT / "src" / "cbds" / "schemas"
        for name in (
            "experiment-manifest.schema.json",
            "hardware-result.schema.json",
        ):
            self.assertEqual(
                (ROOT / name).read_bytes(),
                (package_root / name).read_bytes(),
                f"packaged schema drifted from {name}",
            )
        schema = load_document(ROOT / "experiment-manifest.schema.json")
        self.assertEqual(
            schema["properties"]["schema_version"]["const"],
            EXPERIMENT_SCHEMA_VERSION,
        )
        hardware_schema = load_document(ROOT / "hardware-result.schema.json")
        self.assertEqual(
            hardware_schema["properties"]["schema_version"]["const"],
            HARDWARE_SCHEMA_VERSION,
        )

    def test_completed_schema_carries_full_prospective_execution_contract(self) -> None:
        completed = load_document(ROOT / "experiment-manifest.schema.json")
        prospective = load_document(ROOT / "run-spec.schema.json")
        self.assertEqual(
            completed["$defs"]["trainingProtocol"],
            prospective["$defs"]["trainingProtocol"],
        )
        prospective_operator_fields = set(
            prospective["$defs"]["operator"]["properties"]
        )
        completed_operator = completed["$defs"]["operator"]
        self.assertTrue(
            prospective_operator_fields.issubset(completed_operator["properties"])
        )
        self.assertTrue(
            prospective_operator_fields.issubset(completed_operator["required"])
        )
        self.assertIn(
            "inspection_report_sha256",
            completed["$defs"]["export"]["required"],
        )

    def test_canonical_json_is_order_independent_and_utf8(self) -> None:
        first = {"z": 1, "한글": [True, None]}
        second = {"한글": [True, None], "z": 1}
        self.assertEqual(canonical_json(first), canonical_json(second))
        self.assertEqual(canonical_json_bytes(first), canonical_json(first).encode("utf-8"))
        self.assertEqual(value_sha256(first), value_sha256(second))
        self.assertIn("한글".encode(), canonical_json_bytes(first))

    def test_canonical_json_rejects_nonfinite_numbers(self) -> None:
        with self.assertRaises(ManifestValidationError):
            canonical_json({"bad": math.nan})

    def test_file_hash_and_atomic_write(self) -> None:
        value = {"b": 2, "a": "한글"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "result.json"
            returned = atomic_write_json(path, value)
            self.assertEqual(returned, path)
            self.assertEqual(load_document(path), value)
            self.assertEqual(file_sha256(path), hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(list(path.parent.glob(".*.tmp")), [])

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"a": 1, "a": 2}', encoding="utf-8")
            with self.assertRaisesRegex(ManifestValidationError, "duplicate"):
                load_document(path)

    def test_document_loader_is_bounded_regular_and_content_safe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            oversized = root / "oversized.json"
            with oversized.open("wb") as handle:
                handle.truncate(MAX_DOCUMENT_BYTES + 1)
            with self.assertRaisesRegex(ManifestValidationError, "exceeds"):
                load_document(oversized)

            if hasattr(Path, "symlink_to"):
                target = root / "target.json"
                target.write_text("{}", encoding="utf-8")
                link = root / "link.json"
                link.symlink_to(target)
                with self.assertRaisesRegex(ManifestValidationError, "cannot open"):
                    load_document(link)

            secret = "secret-" + "x" * 100_000
            duplicate = root / "long-duplicate.json"
            duplicate.write_text(
                json.dumps({secret: 1})[:-1] + "," + json.dumps(secret) + ":2}",
                encoding="utf-8",
            )
            with self.assertRaises(ManifestValidationError) as raised:
                load_document(duplicate)
            message = str(raised.exception)
            self.assertNotIn(secret, message)
            self.assertLess(len(message), 512)

    def test_yaml_alias_expansion_is_bounded_when_yaml_support_is_present(self) -> None:
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("PyYAML is not installed")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "aliases.yaml"
            path.write_text(
                "anchor: &shared [1]\nitems:\n" + "  - *shared\n" * 101,
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ManifestValidationError, "alias limit"):
                load_document(path)


class ExperimentManifestTests(unittest.TestCase):
    def test_valid_manifest_and_file_loader(self) -> None:
        manifest = valid_experiment_manifest()
        validated = validate_experiment_manifest(manifest)
        self.assertEqual(validated, manifest)
        self.assertIsNot(validated, manifest)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "experiment.json"
            atomic_write_json(path, manifest)
            self.assertEqual(load_experiment_manifest(path), manifest)

    def test_rejects_mutable_revision_and_unknown_fields(self) -> None:
        manifest = valid_experiment_manifest()
        manifest["model"]["revision"] = "main"
        manifest["model"]["hidden_default"] = True
        with self.assertRaises(ManifestValidationError) as raised:
            validate_experiment_manifest(manifest)
        self.assertIn("revision", str(raised.exception))
        self.assertIn("additional property", str(raised.exception))

    def test_binding_identity_fields_are_mandatory(self) -> None:
        for field in (
            "run_id",
            "stage",
            "run_spec_schema_version",
            "run_spec_sha256",
        ):
            with self.subTest(field=field):
                manifest = valid_experiment_manifest()
                del manifest[field]
                with self.assertRaisesRegex(ManifestValidationError, "required property"):
                    validate_experiment_manifest(manifest)

    def test_completed_execution_and_export_evidence_are_mandatory(self) -> None:
        mutations = []
        for field in (
            "mechanism",
            "configuration_sha256",
            "selection_strategy",
            "selection_split",
        ):
            manifest = valid_experiment_manifest()
            del manifest["operator"][field]
            mutations.append((f"operator.{field}", manifest))

        missing_protocol = valid_experiment_manifest()
        del missing_protocol["training_protocol"]
        mutations.append(("training_protocol", missing_protocol))

        missing_export_inspection = valid_experiment_manifest()
        del missing_export_inspection["export"]["inspection_report_sha256"]
        mutations.append(("export.inspection_report_sha256", missing_export_inspection))

        for expected_path, manifest in mutations:
            with self.subTest(expected_path=expected_path):
                with self.assertRaises(ManifestValidationError) as raised:
                    validate_experiment_manifest(manifest)
                self.assertIn(expected_path.rsplit(".", 1)[-1], str(raised.exception))

    def test_recycle_requires_archived_weight_swap_back_evidence(self) -> None:
        manifest = valid_experiment_manifest()
        manifest["operator"]["archived_weights_sha256"] = None
        with self.assertRaisesRegex(
            ManifestValidationError,
            "required for recycle swap-back evidence",
        ):
            validate_experiment_manifest(manifest)

    def test_completed_operator_factorization_and_hybrid_contracts(self) -> None:
        factorization = {
            "tensor_name": "model.layers.0.mlp.up_proj.weight",
            "component": "ffn_up_proj",
            "layer": 0,
            "input_dimension": 576,
            "output_dimension": 1536,
            "rank": 64,
        }

        factorize = valid_experiment_manifest()
        factorize["stage"] = "compress"
        factorize["operator"].update(
            {
                "mechanism": "factorize",
                "family": "dense_low_rank_svd",
                "structural_indices": [],
                "bit_allocation": [],
                "factorizations": [factorization],
                "archived_weights_sha256": None,
            }
        )
        factorize["export"].update(
            {
                "physical_parameters": 599_250_432,
                "active_parameters": 599_250_432,
                "nonzero_parameters": 599_250_432,
                "weight_bytes": 1_198_500_864,
                "bundle_bytes": 1_208_500_864,
            }
        )
        validate_experiment_manifest(factorize)

        noncompressing = copy.deepcopy(factorize)
        noncompressing["operator"]["factorizations"][0]["rank"] = 512
        with self.assertRaisesRegex(
            ManifestValidationError,
            "must use fewer parameters than the dense matrix",
        ):
            validate_experiment_manifest(noncompressing)

        inconsistent_export = copy.deepcopy(factorize)
        inconsistent_export["export"]["physical_parameters"] -= 1
        with self.assertRaisesRegex(
            ManifestValidationError,
            "committed low-rank factorization savings",
        ):
            validate_experiment_manifest(inconsistent_export)

        hybrid = copy.deepcopy(factorize)
        hybrid["operator"].update(
            {
                "mechanism": "hybrid",
                "family": "factorize_then_quantize",
                "bit_allocation": [
                    {"component": "all_weights", "layer": None, "bits": 4.0}
                ],
            }
        )
        validate_experiment_manifest(hybrid)

        missing_quantization = copy.deepcopy(hybrid)
        missing_quantization["operator"]["bit_allocation"] = []
        with self.assertRaisesRegex(ManifestValidationError, "required for hybrid"):
            validate_experiment_manifest(missing_quantization)

        both_architectures = copy.deepcopy(hybrid)
        both_architectures["operator"]["structural_indices"] = [
            {"component": "ffn_channel", "layer": 0, "indices": [1]}
        ]
        with self.assertRaisesRegex(ManifestValidationError, "XOR"):
            validate_experiment_manifest(both_architectures)

    def test_completed_parameter_group_roles_match_freezing_mode(self) -> None:
        wrong_full_model = valid_experiment_manifest()
        wrong_full_model["optimizer"]["parameter_groups"][0]["role"] = "backbone"
        with self.assertRaisesRegex(
            ManifestValidationError,
            "full_model.*all_trainable",
        ):
            validate_experiment_manifest(wrong_full_model)

        side_only = valid_experiment_manifest()
        side_only["training_protocol"]["freezing"] = {
            "mode": "side_only",
            "trainable_parameters_sha256": "a" * 64,
            "schedule_sha256": None,
        }
        side_only["optimizer"]["parameter_groups"][0].update(
            {"name": "side_branch", "role": "side_branch"}
        )
        validate_experiment_manifest(side_only)

        phased = copy.deepcopy(side_only)
        phased["training_protocol"]["freezing"] = {
            "mode": "phased",
            "trainable_parameters_sha256": "a" * 64,
            "schedule_sha256": "b" * 64,
        }
        phased["optimizer"]["parameter_groups"].append(
            {
                "name": "backbone",
                "role": "backbone",
                "learning_rate": 3e-5,
                "weight_decay": 0.1,
            }
        )
        validate_experiment_manifest(phased)

        missing_backbone = copy.deepcopy(phased)
        missing_backbone["optimizer"]["parameter_groups"].pop()
        with self.assertRaisesRegex(ManifestValidationError, "phased.*backbone"):
            validate_experiment_manifest(missing_backbone)

    def test_run_spec_schema_version_is_a_bounded_semantic_version(self) -> None:
        for value in ("main", "2.0", "02.0.0", "1." + "0" * 40 + ".0"):
            with self.subTest(value=value):
                manifest = valid_experiment_manifest()
                manifest["run_spec_schema_version"] = value
                with self.assertRaises(ManifestValidationError):
                    validate_experiment_manifest(manifest)

    def test_rejects_iso_dates_that_are_not_rfc3339(self) -> None:
        for timestamp in ("2026-07-14 12:00:00+09:00", "2026-07-14T12:00Z"):
            with self.subTest(timestamp=timestamp):
                manifest = valid_experiment_manifest()
                manifest["created_at"] = timestamp
                with self.assertRaisesRegex(ManifestValidationError, "RFC 3339"):
                    validate_experiment_manifest(manifest)

    def test_rejects_accounting_and_provenance_inconsistencies(self) -> None:
        manifest = valid_experiment_manifest()
        manifest["capability_mixture"]["support"][0]["fraction"] = 0.1
        manifest["tokens"]["optimizer_visible"] += 1
        manifest["flops"]["total"] += 2
        manifest["export"]["bundle_bytes"] = 1
        with self.assertRaises(ManifestValidationError) as raised:
            validate_experiment_manifest(manifest)
        message = str(raised.exception)
        self.assertIn("fractions must sum", message)
        self.assertIn("optimizer_visible", message)
        self.assertIn("sum of component FLOPs", message)
        self.assertIn("weight_bytes", message)

    def test_export_weight_bytes_can_encode_declared_parameters_and_precision(self) -> None:
        manifest = valid_experiment_manifest()
        manifest["export"]["weight_bytes"] -= 1
        with self.assertRaisesRegex(
            ManifestValidationError,
            "cannot encode physical_parameters",
        ):
            validate_experiment_manifest(manifest)

    def test_checkpoint_split_must_exist_and_remain_unsealed(self) -> None:
        missing = valid_experiment_manifest()
        missing["checkpoint"]["selection_split"] = "does-not-exist"
        with self.assertRaisesRegex(ManifestValidationError, "must name an entry"):
            validate_experiment_manifest(missing)

        sealed = valid_experiment_manifest()
        sealed["data"]["splits"][1]["sealed"] = True
        with self.assertRaisesRegex(ManifestValidationError, "sealed split"):
            validate_experiment_manifest(sealed)

        wrong_role = valid_experiment_manifest()
        wrong_role["checkpoint"]["selection_split"] = "training"
        with self.assertRaisesRegex(ManifestValidationError, "shadow_validation"):
            validate_experiment_manifest(wrong_role)

        mislabeled = valid_experiment_manifest()
        mislabeled["data"]["splits"][0]["sealed"] = True
        with self.assertRaisesRegex(ManifestValidationError, "must be False"):
            validate_experiment_manifest(mislabeled)

    def test_capability_fractions_must_match_token_accounting(self) -> None:
        manifest = valid_experiment_manifest()
        manifest["tokens"]["target"] = 500_001
        manifest["tokens"]["replay"] = 1_499_999
        with self.assertRaises(ManifestValidationError) as raised:
            validate_experiment_manifest(manifest)
        message = str(raised.exception)
        self.assertIn("tokens.target", message)
        self.assertIn("tokens.replay", message)

    def test_disabled_teacher_must_have_null_provenance_and_zero_tokens(self) -> None:
        manifest = valid_experiment_manifest()
        manifest["teacher"].update(
            {
                "enabled": False,
                "repository": None,
                "revision": None,
                "verified_corpus_sha256": None,
                "generation_flops": 0,
            }
        )
        manifest["tokens"]["teacher_derived"] = 0
        manifest["flops"]["teacher_generation"] = 0
        manifest["flops"]["total"] = 235
        validate_experiment_manifest(manifest)
        manifest["teacher"]["repository"] = "stale/provenance"
        with self.assertRaisesRegex(ManifestValidationError, "must be null"):
            validate_experiment_manifest(manifest)

    def test_disabled_optimizer_is_represented_without_synthetic_training(self) -> None:
        manifest = valid_experiment_manifest()
        manifest["stage"] = "compress"
        manifest["operator"].update(
            {
                "mechanism": "quantize",
                "family": "task_aware_mixed_precision",
                "structural_indices": [],
                "bit_allocation": [
                    {"component": "all_weights", "layer": None, "bits": 4.0}
                ],
                "factorizations": [],
                "archived_weights_sha256": None,
            }
        )
        manifest["teacher"].update(
            {
                "enabled": False,
                "repository": None,
                "revision": None,
                "verified_corpus_sha256": None,
                "generation_flops": 0,
            }
        )
        manifest["optimizer"] = {
            "enabled": False,
            "name": None,
            "parameter_groups": [],
            "betas": [],
            "epsilon": None,
            "gradient_clip": None,
            "warmup_fraction": None,
            "schedule": None,
            "total_steps": 0,
        }
        manifest["training_protocol"] = {
            "training_dtype": None,
            "optimizer_state_dtype": None,
            "microbatch_size": 0,
            "gradient_accumulation_steps": 0,
            "data_parallel_world_size": 0,
            "effective_batch_size": 0,
            "attention_backend": None,
            "gradient_checkpointing": False,
            "deterministic_algorithms": True,
            "packing": {
                "enabled": False,
                "strategy": "none",
                "minimum_sequence_length": None,
                "maximum_sequence_length": None,
            },
            "loss": {
                "objective": "none",
                "label_scope": "none",
                "target_weight": 0,
                "support_weight": 0,
                "kl_weight": 0,
                "anchor_model_sha256": None,
            },
            "freezing": {
                "mode": "none",
                "trainable_parameters_sha256": None,
                "schedule_sha256": None,
            },
        }
        manifest["tokens"].update(
            {
                "optimizer_visible": 0,
                "target": 0,
                "replay": 0,
                "teacher_derived": 0,
            }
        )
        manifest["flops"].update(
            {
                "teacher_generation": 0,
                "training": 0,
                "total": 35,
            }
        )
        validate_experiment_manifest(manifest)

        stale = copy.deepcopy(manifest)
        stale["optimizer"]["name"] = "AdamW"
        stale["flops"]["training"] = 1
        stale["flops"]["total"] += 1
        with self.assertRaises(ManifestValidationError) as raised:
            validate_experiment_manifest(stale)
        self.assertIn("must be null", str(raised.exception))
        self.assertIn("must be zero", str(raised.exception))

    def test_completed_run_is_cryptographically_bound_to_train_and_compress_specs(self) -> None:
        from tests.test_run_specs import (
            valid_compress_spec,
            valid_factorize_spec,
            valid_train_spec,
        )

        for spec in (valid_train_spec(), valid_compress_spec(), valid_factorize_spec()):
            with self.subTest(stage=spec["stage"]):
                record = completed_record_for_spec(spec)
                self.assertEqual(validate_completed_run(spec, record), record)
                with tempfile.TemporaryDirectory() as directory:
                    spec_path = Path(directory) / "run-spec.json"
                    record_path = Path(directory) / "completed.json"
                    atomic_write_json(spec_path, spec)
                    atomic_write_json(record_path, record)
                    self.assertEqual(
                        load_completed_run(spec_path, record_path),
                        record,
                    )

    def test_completed_run_campaign_binding_cannot_be_bypassed(self) -> None:
        from tests.test_run_specs import (
            CAMPAIGN_POLICY,
            spec_for_campaign_profile,
            valid_train_spec,
        )

        policy = load_campaign_policy(CAMPAIGN_POLICY)
        spec = valid_train_spec()
        record = completed_record_for_spec(spec)
        self.assertEqual(
            validate_completed_run_against_campaign(spec, policy, record),
            record,
        )
        with tempfile.TemporaryDirectory() as directory:
            spec_path = Path(directory) / "run-spec.json"
            record_path = Path(directory) / "completed.json"
            atomic_write_json(spec_path, spec)
            atomic_write_json(record_path, record)
            self.assertEqual(
                load_completed_run_against_campaign(
                    spec_path,
                    CAMPAIGN_POLICY,
                    record_path,
                ),
                record,
            )

        fake_policy_spec = copy.deepcopy(spec)
        fake_policy_spec["campaign"]["policy_sha256"] = "f" * 64
        self.assertEqual(
            validate_completed_run(
                fake_policy_spec,
                completed_record_for_spec(fake_policy_spec),
            )["run_id"],
            spec["run_id"],
        )
        with self.assertRaisesRegex(CampaignRunValidationError, "policy_sha256"):
            validate_completed_run_against_campaign(
                fake_policy_spec,
                policy,
                completed_record_for_spec(fake_policy_spec),
            )

        prospective = spec_for_campaign_profile("confirmation")
        completed = completed_record_for_spec(prospective)
        reversed_role = copy.deepcopy(prospective)
        reversed_role["campaign"]["contrast_role"] = "comparison"
        with self.assertRaisesRegex(
            CompletedRunValidationError, "run_spec_sha256"
        ):
            validate_completed_run(reversed_role, completed)

    def test_completed_run_rejects_commitment_drift_and_budget_overrun(self) -> None:
        from tests.test_run_specs import valid_train_spec

        spec = valid_train_spec()
        mutations = []

        wrong_digest = completed_record_for_spec(spec)
        wrong_digest["run_spec_sha256"] = "f" * 64
        mutations.append(("run_spec_sha256", wrong_digest))

        wrong_model = completed_record_for_spec(spec)
        wrong_model["model"]["revision"] = "f" * 40
        mutations.append(("model.revision", wrong_model))

        wrong_inspection = completed_record_for_spec(spec)
        wrong_inspection["model"]["inspection_report_sha256"] = "f" * 64
        mutations.append(("model.inspection_report_sha256", wrong_inspection))

        wrong_operator = completed_record_for_spec(spec)
        wrong_operator["operator"]["family"] = "different_operator"
        mutations.append(("operator.family", wrong_operator))

        wrong_mechanism = completed_record_for_spec(spec)
        wrong_mechanism["operator"]["mechanism"] = "distill"
        mutations.append(("operator.mechanism", wrong_mechanism))

        wrong_configuration = completed_record_for_spec(spec)
        wrong_configuration["operator"]["configuration_sha256"] = "f" * 64
        mutations.append(("operator.configuration_sha256", wrong_configuration))

        wrong_selection_strategy = completed_record_for_spec(spec)
        wrong_selection_strategy["operator"]["selection_strategy"] = "random"
        mutations.append(("operator.selection_strategy", wrong_selection_strategy))

        wrong_selection_split = completed_record_for_spec(spec)
        wrong_selection_split["operator"]["selection_split"] = "training"
        mutations.append(("operator.selection_split", wrong_selection_split))

        wrong_optimizer = completed_record_for_spec(spec)
        wrong_optimizer["optimizer"]["parameter_groups"][0]["learning_rate"] = 1e-4
        mutations.append(("optimizer", wrong_optimizer))

        wrong_optimizer_role = completed_record_for_spec(spec)
        wrong_optimizer_role["optimizer"]["parameter_groups"][0]["role"] = "backbone"
        mutations.append(("optimizer", wrong_optimizer_role))

        wrong_training_protocol = completed_record_for_spec(spec)
        wrong_training_protocol["training_protocol"]["gradient_checkpointing"] = False
        mutations.append(("training_protocol", wrong_training_protocol))

        from tests.test_run_specs import valid_factorize_spec

        factor_spec = valid_factorize_spec()
        wrong_factorization = completed_record_for_spec(factor_spec)
        wrong_factorization["operator"]["factorizations"][0][
            "tensor_name"
        ] = "model.layers.0.mlp.other_up_proj.weight"
        with self.assertRaises(CompletedRunValidationError) as raised:
            validate_completed_run(factor_spec, wrong_factorization)
        self.assertIn("operator.factorizations", str(raised.exception))

        wrong_tokens = completed_record_for_spec(spec)
        wrong_tokens["tokens"]["selection_visible"] += 1
        mutations.append(("tokens.selection_visible", wrong_tokens))

        over_budget = completed_record_for_spec(spec)
        over_budget["flops"]["selection"] += 1
        over_budget["flops"]["total"] += 1
        mutations.append(("flops.selection", over_budget))

        wrong_export = completed_record_for_spec(spec)
        wrong_export["export"]["physical_parameters"] -= 1
        wrong_export["export"]["active_parameters"] -= 1
        wrong_export["export"]["nonzero_parameters"] -= 1
        mutations.append(("export.physical_parameters", wrong_export))

        wrong_vocabulary = completed_record_for_spec(spec)
        wrong_vocabulary["tokenizer"]["vocabulary_size"] -= 1
        mutations.append(("tokenizer.vocabulary_size", wrong_vocabulary))

        oversized_bundle = completed_record_for_spec(spec)
        oversized_bundle["export"]["bundle_bytes"] += 1
        mutations.append(("export.bundle_bytes", oversized_bundle))

        missing_tokenizer = completed_record_for_spec(spec)
        missing_tokenizer["export"]["tokenizer_included"] = False
        mutations.append(("export.tokenizer_included", missing_tokenizer))

        for expected_path, record in mutations:
            with self.subTest(expected_path=expected_path):
                with self.assertRaises(CompletedRunValidationError) as raised:
                    validate_completed_run(spec, record)
                self.assertIn(expected_path, str(raised.exception))

        undersized_fixed_bundle = completed_record_for_spec(spec)
        undersized_fixed_bundle["export"]["bundle_bytes"] -= 1
        with self.assertRaisesRegex(
            CompletedRunValidationError,
            "fixed_size completion.*bundle bytes",
        ):
            validate_completed_run(spec, undersized_fixed_bundle)


class HardwareResultTests(unittest.TestCase):
    def test_paired_hardware_validation_binds_completed_export_evidence(self) -> None:
        from tests.test_run_specs import valid_train_spec

        completed = completed_record_for_spec(valid_train_spec())
        result = hardware_result_for_completed_record(completed)
        validated = validate_hardware_result_against_experiment_manifest(
            result,
            completed,
        )
        self.assertEqual(validated, result)
        self.assertIsNot(validated, result)

        unbound = copy.deepcopy(result)
        unbound["artifact"]["source_manifest_sha256"] = "f" * 64
        self.assertEqual(validate_hardware_result(unbound), unbound)
        with self.assertRaisesRegex(
            ManifestValidationError,
            "source_manifest_sha256",
        ):
            validate_hardware_result_against_experiment_manifest(unbound, completed)

    def test_paired_hardware_validation_rejects_every_export_mismatch(self) -> None:
        from tests.test_run_specs import valid_train_spec

        completed = completed_record_for_spec(valid_train_spec())
        baseline = hardware_result_for_completed_record(completed)
        mutations = (
            ("architecture", "moe"),
            ("format", "other"),
            ("sha256", "f" * 64),
            ("bundle_sha256", "f" * 64),
            ("tokenizer_sha256", "f" * 64),
            ("inspection_report_sha256", "f" * 64),
            ("weight_bytes", baseline["artifact"]["weight_bytes"] + 1),
            ("bundle_bytes", baseline["artifact"]["bundle_bytes"] + 1),
            ("active_parameters", baseline["artifact"]["active_parameters"] - 1),
            ("nonzero_parameters", baseline["artifact"]["nonzero_parameters"] - 1),
            ("average_weight_bits", 15.5),
            ("method", "post-hoc-hardware-label"),
            ("dose", "post-hoc-dose"),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                result = copy.deepcopy(baseline)
                result["artifact"][field] = value
                with self.assertRaises(ManifestValidationError) as raised:
                    validate_hardware_result_against_experiment_manifest(
                        result,
                        completed,
                    )
                self.assertIn(f"artifact.{field}", str(raised.exception))

        result = copy.deepcopy(baseline)
        result["artifact"].update(
            {
                "physical_parameters": baseline["artifact"]["physical_parameters"] - 1,
                "active_parameters": baseline["artifact"]["active_parameters"] - 1,
                "nonzero_parameters": baseline["artifact"]["nonzero_parameters"] - 1,
            }
        )
        with self.assertRaises(ManifestValidationError) as raised:
            validate_hardware_result_against_experiment_manifest(result, completed)
        self.assertIn("artifact.physical_parameters", str(raised.exception))

        missing_dose = copy.deepcopy(baseline)
        del missing_dose["artifact"]["dose"]
        with self.assertRaisesRegex(ManifestValidationError, "dose"):
            validate_hardware_result_against_experiment_manifest(
                missing_dose,
                completed,
            )

    def test_rejects_impossible_artifact_size_accounting(self) -> None:
        result = valid_hardware_result()
        result["artifact"].update(
            {
                "physical_parameters": 600_000_000,
                "active_parameters": 600_000_000,
                "nonzero_parameters": 600_000_000,
                "average_weight_bits": 16.0,
                "weight_bytes": 1,
            }
        )
        with self.assertRaisesRegex(
            ManifestValidationError,
            "cannot store physical_parameters",
        ):
            validate_hardware_result(result)

    def test_external_schema_cannot_weaken_the_frozen_contract(self) -> None:
        schema = load_document(ROOT / "hardware-result.schema.json")
        schema["additionalProperties"] = True
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "weakened.schema.json"
            atomic_write_json(path, schema)
            with self.assertRaisesRegex(ManifestValidationError, "frozen packaged"):
                validate_hardware_result(valid_hardware_result(), schema_path=path)

    def test_json_schema_constants_distinguish_booleans_from_numbers(self) -> None:
        mutations = (
            ("workload", "batch_size", True),
            ("workload", "deterministic", 1),
            ("protocol", "temperature", False),
        )
        for section, field, value in mutations:
            with self.subTest(path=f"{section}.{field}"):
                result = valid_hardware_result()
                result[section][field] = value
                with self.assertRaises(ManifestValidationError):
                    validate_hardware_result(result)

    def test_validates_without_jsonschema_and_honors_explicit_schema(self) -> None:
        result = valid_hardware_result()
        validated = validate_hardware_result(
            result,
            schema_path=ROOT / "hardware-result.schema.json",
        )
        self.assertEqual(validated, result)
        self.assertIsNot(validated, result)

    def test_requires_an_explicit_clean_worktree(self) -> None:
        for mutation in ("missing", True):
            with self.subTest(mutation=mutation):
                result = valid_hardware_result()
                if mutation == "missing":
                    del result["dirty_worktree"]
                else:
                    result["dirty_worktree"] = mutation
                with self.assertRaises(ManifestValidationError):
                    validate_hardware_result(result)

    def test_enforces_exact_token_controlled_protocol(self) -> None:
        mutations = (
            ("cold_start", True),
            ("process_model", "independent_process_per_repetition"),
            ("warmups", 0),
            ("repetitions", 5),
            ("synchronized_timing", False),
            ("randomized_workload_order", False),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                result = valid_hardware_result()
                result["protocol"][field] = value
                with self.assertRaisesRegex(
                    ManifestValidationError,
                    rf"protocol\.{field}",
                ):
                    validate_hardware_result(result)

        result = valid_hardware_result()
        result["workload"]["prompt_tokens"] = 256
        with self.assertRaisesRegex(
            ManifestValidationError,
            "five frozen microbenchmarks",
        ):
            validate_hardware_result(result)

    def test_accepts_exact_cold_load_protocol(self) -> None:
        result = valid_hardware_result()
        result["workload"].update(
            {
                "kind": "cold_load",
                "prompt_tokens": 0,
                "generated_tokens": 0,
                "prompt_sha256": None,
            }
        )
        result["protocol"].update(
            {
                "cold_start": True,
                "process_model": "independent_process_per_repetition",
                "warmups": 0,
                "repetitions": 5,
                "synchronized_timing": False,
                "randomized_workload_order": False,
            }
        )
        result["measurements"].update(
            {
                "load_time_ms": summary(5),
                "first_token_ms": None,
                "prefill_tokens_per_second": None,
                "decode_tokens_per_second": None,
                "wall_time_ms": None,
            }
        )
        self.assertEqual(
            validate_hardware_result(result)["workload"]["kind"],
            "cold_load",
        )

    def test_accepts_exact_real_terminal_protocol(self) -> None:
        result = valid_hardware_result()
        result["workload"]["kind"] = "real_terminal"
        result["protocol"].update(
            {
                "cold_start": False,
                "process_model": "single_loaded_process",
                "warmups": 0,
                "repetitions": 1,
                "synchronized_timing": True,
                "randomized_workload_order": True,
            }
        )
        result["measurements"].update(
            {
                "first_token_ms": summary(1),
                "prefill_tokens_per_second": summary(1),
                "decode_tokens_per_second": summary(1),
                "wall_time_ms": summary(1),
            }
        )
        self.assertEqual(
            validate_hardware_result(result)["protocol"]["repetitions"],
            1,
        )

    def test_enforces_measurement_presence_by_workload(self) -> None:
        mutations = (
            ("load_time_ms", summary()),
            ("first_token_ms", None),
            ("peak_host_rss_bytes", None),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                result = valid_hardware_result()
                result["measurements"][field] = value
                with self.assertRaisesRegex(ManifestValidationError, field):
                    validate_hardware_result(result)

        split_only = valid_hardware_result()
        split_only["measurements"]["decode_tokens_per_second"] = None
        with self.assertRaisesRegex(
            ManifestValidationError,
            "must both be present or both be null",
        ):
            validate_hardware_result(split_only)

    def test_one_sample_summary_must_be_self_consistent(self) -> None:
        result = valid_hardware_result()
        result["workload"]["kind"] = "real_terminal"
        result["protocol"].update(
            {
                "warmups": 0,
                "repetitions": 1,
            }
        )
        for field in (
            "first_token_ms",
            "prefill_tokens_per_second",
            "decode_tokens_per_second",
            "wall_time_ms",
        ):
            result["measurements"][field] = summary(1)
        result["measurements"]["wall_time_ms"]["maximum"] = 3.0
        with self.assertRaisesRegex(
            ManifestValidationError,
            "one-sample summary",
        ):
            validate_hardware_result(result)

    def test_rejects_summary_count_and_order(self) -> None:
        result = valid_hardware_result()
        result["measurements"]["first_token_ms"]["sample_count"] = 2
        result["measurements"]["wall_time_ms"]["p95"] = 0.5
        with self.assertRaises(ManifestValidationError) as raised:
            validate_hardware_result(result)
        self.assertIn("protocol.repetitions", str(raised.exception))
        self.assertIn("minimum <= median", str(raised.exception))

    def test_rejects_false_correctness_under_passed_gate(self) -> None:
        result = valid_hardware_result()
        result["correctness"]["token_hash_matched"] = False
        with self.assertRaisesRegex(ManifestValidationError, "token_hash_matched"):
            validate_hardware_result(result)

    def test_rejects_negative_resource_and_count_measurements(self) -> None:
        paths = (
            ("hardware", "device_memory_bytes"),
            ("hardware", "power_limit_watts"),
            ("measurements", "peak_host_rss_bytes"),
            ("measurements", "peak_device_memory_bytes"),
            ("measurements", "peak_framework_reserved_bytes"),
            ("measurements", "energy_joules"),
            ("correctness", "functional_successes"),
            ("correctness", "functional_tasks"),
        )
        for section, field in paths:
            with self.subTest(path=f"{section}.{field}"):
                result = valid_hardware_result()
                result[section][field] = -1
                with self.assertRaisesRegex(ManifestValidationError, "must be >= 0"):
                    validate_hardware_result(result)

    def test_merge_is_deterministic_and_keeps_strata_separate(self) -> None:
        first = valid_hardware_result("hardware-run-0002")
        second = valid_hardware_result("hardware-run-0001")
        second["hardware"]["temperature_start_c"] = 45.0
        second["hardware"]["temperature_end_c"] = 55.0
        third = valid_hardware_result("hardware-run-0003")
        third["hardware"]["machine_id"] = "machine-cpu-0001"
        third["hardware"]["class"] = "cpu"
        third["hardware"]["device_name"] = "Test CPU"
        third["hardware"]["device_memory_bytes"] = None
        third["hardware"]["shared_memory"] = True
        third["hardware"]["driver"] = "kernel"
        third["hardware"]["firmware_or_runtime"] = None
        third["software"]["backend"] = "cpu"
        third["software"]["device_offload"] = "none"

        merged = merge_hardware_results([first, third, second])
        reversed_merge = merge_hardware_results([second, third, first])
        self.assertEqual(merged, reversed_merge)
        self.assertEqual(merged["result_count"], 3)
        self.assertEqual(len(merged["strata"]), 2)
        run_orders = [
            [result["run_id"] for result in stratum["results"]]
            for stratum in merged["strata"]
        ]
        self.assertIn(["hardware-run-0001", "hardware-run-0002"], run_orders)

    def test_merge_accepts_paths_and_writes_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.json"
            destination = Path(directory) / "merged.json"
            atomic_write_json(source, valid_hardware_result())
            merged = merge_hardware_results(
                [source],
                schema_path=ROOT / "hardware-result.schema.json",
                output_path=destination,
            )
            self.assertEqual(load_document(destination), merged)

    def test_merge_rejects_duplicate_run_ids(self) -> None:
        result = valid_hardware_result()
        with self.assertRaisesRegex(ManifestValidationError, "duplicate hardware run_id"):
            merge_hardware_results([result, copy.deepcopy(result)])

    def test_merge_rejects_artifact_identity_hash_mismatch(self) -> None:
        first = valid_hardware_result("hardware-run-0001")
        second = valid_hardware_result("hardware-run-0002")
        second["artifact"]["sha256"] = "9" * 64
        with self.assertRaisesRegex(ManifestValidationError, "artifact hash/accounting mismatch"):
            merge_hardware_results([first, second])

    def test_merge_rejects_workload_identity_hash_mismatch(self) -> None:
        first = valid_hardware_result("hardware-run-0001")
        second = valid_hardware_result("hardware-run-0002")
        second["workload"]["suite_sha256"] = "9" * 64
        with self.assertRaisesRegex(ManifestValidationError, "workload hash/configuration mismatch"):
            merge_hardware_results([first, second])


if __name__ == "__main__":
    unittest.main()
