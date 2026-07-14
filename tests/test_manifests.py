from __future__ import annotations

import copy
import hashlib
import json
import math
import tempfile
import unittest
from pathlib import Path

from cbds.manifests import (
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
    value_sha256,
)


ROOT = Path(__file__).resolve().parents[1]
SHA1 = "1" * 40
SHA256 = "a" * 64
OTHER_SHA256 = "b" * 64


def valid_experiment_manifest() -> dict:
    return {
        "schema_version": "1.0.0",
        "experiment_id": "experiment-0001",
        "created_at": "2026-07-14T12:00:00+09:00",
        "git_revision": SHA1,
        "model": {
            "repository": "Qwen/Qwen3-0.6B-Base",
            "revision": "2" * 40,
            "architecture": "dense",
            "physical_parameters": 600_000_000,
        },
        "tokenizer": {
            "repository": "Qwen/Qwen3-0.6B-Base",
            "revision": "2" * 40,
            "source_sha256": "3" * 64,
            "derived_vocabulary_mapping_sha256": None,
        },
        "data": {
            "manifest_sha256": "4" * 64,
            "semantic_graph_sha256": "5" * 64,
            "fixtures_sha256": "6" * 64,
            "splits": [
                {"name": "training", "sha256": "7" * 64, "sealed": False},
                {"name": "shadow-validation", "sha256": "8" * 64, "sealed": False},
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
            "family": "ffn_reset_regrow",
            "dose": 0.1,
            "structural_indices": [
                {"component": "ffn_channel", "layer": 0, "indices": [1, 2, 3]}
            ],
            "bit_allocation": [],
            "selection_manifest_sha256": "0" * 64,
            "archived_weights_sha256": "1" * 64,
        },
        "optimizer": {
            "name": "AdamW",
            "parameter_groups": [
                {"name": "backbone", "learning_rate": 0.00003, "weight_decay": 0.1}
            ],
            "betas": [0.9, 0.95],
            "epsilon": 1e-8,
            "gradient_clip": 1.0,
            "warmup_fraction": 0.05,
            "schedule": "cosine",
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
            "format": "safetensors",
            "runtime_compatibility": ["transformers-sdpa"],
            "physical_parameters": 600_000_000,
            "active_parameters": 600_000_000,
            "nonzero_parameters": 599_000_000,
            "average_weight_bits": 16.0,
            "weight_bytes": 1_200_000_000,
            "bundle_bytes": 1_210_000_000,
            "artifact_sha256": "2" * 64,
            "bundle_sha256": "3" * 64,
            "tokenizer_sha256": "4" * 64,
        },
    }


def summary(sample_count: int = 3) -> dict:
    return {
        "sample_count": sample_count,
        "median": 2.0,
        "p95": 3.0,
        "minimum": 1.0,
        "maximum": 4.0,
    }


def valid_hardware_result(run_id: str = "hardware-run-0001") -> dict:
    return {
        "schema_version": "1.0.0",
        "run_id": run_id,
        "created_at": "2026-07-14T12:00:00Z",
        "git_revision": SHA1,
        "dirty_worktree": False,
        "artifact": {
            "name": "qwen-terminal-075",
            "format": "gguf",
            "sha256": SHA256,
            "bundle_sha256": OTHER_SHA256,
            "tokenizer_sha256": "c" * 64,
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
            "warmups": 10,
            "repetitions": 3,
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

    def test_checkpoint_split_must_exist_and_remain_unsealed(self) -> None:
        missing = valid_experiment_manifest()
        missing["checkpoint"]["selection_split"] = "does-not-exist"
        with self.assertRaisesRegex(ManifestValidationError, "must name an entry"):
            validate_experiment_manifest(missing)

        sealed = valid_experiment_manifest()
        sealed["data"]["splits"][1]["sealed"] = True
        with self.assertRaisesRegex(ManifestValidationError, "sealed split"):
            validate_experiment_manifest(sealed)

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


class HardwareResultTests(unittest.TestCase):
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
