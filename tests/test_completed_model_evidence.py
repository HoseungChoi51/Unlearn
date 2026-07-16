from __future__ import annotations

import copy
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.completed_model_evidence import (  # noqa: E402
    CompletedModelEvidenceError,
    build_completed_model_evidence_binding,
    compute_completed_model_evidence_binding_sha256,
    verify_completed_model_evidence_binding,
)
from cbds.dense_checkpoint import inspect_dense_checkpoint  # noqa: E402
from cbds.model_artifacts import inspect_model_artifact  # noqa: E402
from cbds.model_runtime import compute_runtime_report_sha256  # noqa: E402
from cbds.run_specs import load_campaign_policy  # noqa: E402
from tests.test_dense_checkpoint import _make_artifact, _write_json  # noqa: E402
from tests.test_dense_checkpoint_binding import _align_spec  # noqa: E402
from tests.test_manifests import completed_record_for_spec  # noqa: E402
from tests.test_run_specs import (  # noqa: E402
    spec_for_campaign_profile,
    valid_train_spec,
)


_RUNTIME_DTYPE = {
    "BF16": ("torch.bfloat16", "torch.bfloat16"),
    "F16": ("torch.float16", "torch.float16"),
    "F32": ("torch.float32", "torch.float32"),
}


def _write_tokenizer(root: Path, count: int) -> None:
    _write_json(
        root / "tokenizer.json",
        {
            "version": "1.0",
            "model": {
                "type": "BPE",
                "vocab": {f"token-{index}": index for index in range(count)},
            },
            "added_tokens": [],
        },
    )


def _runtime_report(
    generic: dict[str, object], dense: dict[str, object]
) -> dict[str, object]:
    architecture = dense["architecture"]
    inventory = dense["tensor_inventory"]
    parameter_dtype = inventory["parameter_dtype"]
    runtime_dtype, logits_dtype = _RUNTIME_DTYPE[parameter_dtype]
    physical = inventory["physical_parameter_count"]
    physical_bytes = generic["weights"]["safetensors_payload_bytes"]
    tensor_count = inventory["tensor_count"]
    tied_aliases = 1 if architecture["tie_word_embeddings"] else 0
    report: dict[str, object] = {
        "schema_version": "1.0.0",
        "runtime_probe_version": "1.1.0",
        "report_hash_scope": "canonical_json_excluding_report_sha256",
        "implementation": {
            "package_name": "cbds-research",
            "package_version": "0.3.0-test",
            "module": "cbds.model_runtime",
            "source_sha256": "1" * 64,
        },
        "static_inspection": {
            "inspector_version": generic["inspector_version"],
            "report_sha256": generic["report_sha256"],
            "bundle_manifest_sha256": generic["bundle_manifest_sha256"],
            "weight_set_sha256": generic["weight_set_sha256"],
            "architecture_classification": "dense_consistent",
            "reinspection_match_after_runtime": True,
        },
        "dependency_versions": {
            "torch": "test-torch",
            "transformers": "test-transformers",
        },
        "runtime_classes": {
            "transformers_auto_model_class": (
                "transformers.AutoModelForCausalLM"
            ),
            "transformers_auto_tokenizer_class": "transformers.AutoTokenizer",
            "loaded_model_class": (
                "transformers.synthetic." + architecture["architecture_class"]
            ),
            "loaded_tokenizer_class": "transformers.synthetic.TestTokenizer",
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
            "prompt_sha256": "2" * 64,
            "prompt_utf8_bytes": 4,
            "token_cap": 8,
            "observed_tokens": 2,
            "truncation": False,
        },
        "device_placement": {
            "requested": "cpu",
            "parameter_devices": ["cpu"],
            "buffer_devices": [],
            "input_device": "cpu",
            "logits_device": "cpu",
        },
        "parameters": {
            "accounting_basis": (
                "union_of_contiguous_untyped_storage_byte_spans"
            ),
            "named_tensor_entries": tensor_count + tied_aliases,
            "unique_physical_spans": tensor_count,
            "deduplicated_alias_entries": tied_aliases,
            "storage_allocations_referenced": tensor_count,
            "physical_elements": physical,
            "physical_bytes": physical_bytes,
            "trainable_elements": physical,
            "trainable_bytes": physical_bytes,
            "by_dtype": [
                {
                    "dtype": runtime_dtype,
                    "physical_elements": physical,
                    "physical_bytes": physical_bytes,
                    "trainable_elements": physical,
                    "trainable_bytes": physical_bytes,
                }
            ],
        },
        "buffers": {
            "accounting_basis": (
                "union_of_contiguous_untyped_storage_byte_spans"
            ),
            "named_tensor_entries": 0,
            "unique_physical_spans": 0,
            "deduplicated_alias_entries": 0,
            "storage_allocations_referenced": 0,
            "physical_elements": 0,
            "physical_bytes": 0,
            "by_dtype": [],
        },
        "forward": {
            "mode": "eval_inference_single_forward_no_generation",
            "use_cache": False,
            "input_ids_shape": [1, 2],
            "logits_shape": [1, 2, architecture["vocab_size"]],
            "logits_dtype": logits_dtype,
            "logits_finite": True,
        },
        "claim_qualification": {
            "static_density_classification": "dense_consistent",
            "physical_parameter_elements": physical,
            "physical_parameter_elements_below_one_billion": True,
            "model_load_succeeded": True,
            "forward_succeeded": True,
            "sub_billion_dense_runtime_qualified": True,
            "ambiguous_static_density_upgraded": False,
            "scope": (
                "physical runtime parameter storage plus one bounded local "
                "causal-LM forward; no capability or benchmark quality claim"
            ),
        },
    }
    report["report_sha256"] = compute_runtime_report_sha256(report)
    return report


def _flip_last_payload_byte(path: Path) -> None:
    payload = bytearray(path.read_bytes())
    payload[-1] ^= 1
    path.write_bytes(payload)


def _campaign_ffn_prune_spec(
    generic: dict[str, object], dense: dict[str, object]
) -> dict:
    spec = _align_spec(spec_for_campaign_profile("screening"), generic, dense)
    architecture = dense["architecture"]
    layers = architecture["num_hidden_layers"]
    hidden = architecture["hidden_size"]
    removed_parameters = layers * 3 * hidden
    planned_parameters = spec["model"]["physical_parameters"] - removed_parameters
    companion_bytes = (
        spec["model"]["checkpoint_bundle_bytes"]
        - spec["model"]["checkpoint_weight_bytes"]
    )
    spec["run_id"] = "campaign-ffn-prune"
    spec["stage"] = "compress"
    spec["operator"].update(
        {
            "mechanism": "prune",
            "family": "architecture_representable_ffn_pruning",
            "dose": 1,
            "selection_strategy": "random",
            "selection_split": None,
            "selection_manifest_sha256": "7" * 64,
            "structural_indices": [
                {"component": "ffn_channel", "layer": layer, "indices": [0]}
                for layer in range(layers)
            ],
            "bit_allocation": [],
            "factorizations": [],
        }
    )
    spec["compute_budget"]["compression_max_flops"] = 100.0
    spec["compute_budget"]["total_max_flops"] += 100.0
    spec["export"].update(
        {
            "intent": "compression",
            "planned_physical_parameters": planned_parameters,
            "planned_average_weight_bits": spec["model"]["serialized_weight_bits"],
            "maximum_weight_bytes": planned_parameters * 2,
            "maximum_bundle_bytes": planned_parameters * 2 + companion_bytes,
            "planned_vocabulary_size": architecture["vocab_size"],
        }
    )
    return spec


def _completed_for_export(
    spec: dict,
    generic: dict[str, object],
    dense: dict[str, object],
) -> dict:
    completed = completed_record_for_spec(spec)
    physical = dense["tensor_inventory"]["physical_parameter_count"]
    completed["export"].update(
        {
            "artifact_sha256": generic["weight_set_sha256"],
            "bundle_sha256": generic["bundle_manifest_sha256"],
            "tokenizer_sha256": generic["tokenizer"]["tokenizer_set_sha256"],
            "inspection_report_sha256": dense["report_sha256"],
            "physical_parameters": physical,
            "active_parameters": physical,
            "nonzero_parameters": physical,
            "average_weight_bits": generic["weights"][
                "average_stored_bits_per_element"
            ],
            "weight_bytes": generic["weights"]["safetensors_payload_bytes"],
            "bundle_bytes": sum(item["bytes"] for item in generic["files"]),
        }
    )
    return completed


class CompletedModelEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.export = self.root / "export"
        self.source.mkdir()
        self.export.mkdir()
        for root in (self.source, self.export):
            _make_artifact(root, "qwen3")
            # Qwen-style reserved embedding rows are represented by one fewer
            # observed contiguous token ID than config.vocab_size.
            _write_tokenizer(root, 15)
        _flip_last_payload_byte(self.export / "model.safetensors")
        self.source_generic = inspect_model_artifact(self.source)
        self.source_dense = inspect_dense_checkpoint(
            self.source,
            expected_inspection_report_sha256=self.source_generic["report_sha256"],
        )
        self.export_generic = inspect_model_artifact(self.export)
        self.export_dense = inspect_dense_checkpoint(
            self.export,
            expected_inspection_report_sha256=self.export_generic["report_sha256"],
        )
        self.spec = _align_spec(
            valid_train_spec(), self.source_generic, self.source_dense
        )
        self.policy = load_campaign_policy(ROOT / "configs/campaign-policy.json")
        self.completed = completed_record_for_spec(self.spec)
        self.completed["export"].update(
            {
                "artifact_sha256": self.export_generic["weight_set_sha256"],
                "bundle_sha256": self.export_generic["bundle_manifest_sha256"],
                "tokenizer_sha256": self.export_generic["tokenizer"][
                    "tokenizer_set_sha256"
                ],
                "inspection_report_sha256": self.export_dense["report_sha256"],
                "physical_parameters": self.export_dense["tensor_inventory"][
                    "physical_parameter_count"
                ],
                "active_parameters": self.export_dense["tensor_inventory"][
                    "physical_parameter_count"
                ],
                "nonzero_parameters": self.export_dense["tensor_inventory"][
                    "physical_parameter_count"
                ],
                "average_weight_bits": self.export_generic["weights"][
                    "average_stored_bits_per_element"
                ],
                "weight_bytes": self.export_generic["weights"][
                    "safetensors_payload_bytes"
                ],
                "bundle_bytes": sum(
                    item["bytes"] for item in self.export_generic["files"]
                ),
            }
        )
        self.source_runtime = _runtime_report(
            self.source_generic, self.source_dense
        )
        self.export_runtime = _runtime_report(
            self.export_generic, self.export_dense
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def build(self, **changes: object) -> dict[str, object]:
        return build_completed_model_evidence_binding(
            changes.get("spec", self.spec),  # type: ignore[arg-type]
            changes.get("policy", self.policy),  # type: ignore[arg-type]
            changes.get("completed", self.completed),  # type: ignore[arg-type]
            source_artifact_dir=changes.get("source", self.source),  # type: ignore[arg-type]
            export_artifact_dir=changes.get("export", self.export),  # type: ignore[arg-type]
            source_runtime_report=changes.get(  # type: ignore[arg-type]
                "source_runtime", self.source_runtime
            ),
            export_runtime_report=changes.get(  # type: ignore[arg-type]
                "export_runtime", self.export_runtime
            ),
        )

    def assert_rejected(self, **changes: object) -> None:
        with self.assertRaises(CompletedModelEvidenceError):
            self.build(**changes)

    def test_fresh_source_export_binding_is_self_hashed_and_nonauthorizing(self) -> None:
        binding = self.build()
        self.assertTrue(verify_completed_model_evidence_binding(binding))
        self.assertEqual(
            binding["binding_sha256"],
            compute_completed_model_evidence_binding_sha256(binding),
        )
        self.assertNotEqual(
            binding["source"]["weight_set_sha256"],
            binding["export"]["weight_set_sha256"],
        )
        self.assertEqual(binding["source"]["observed_token_id_count"], 15)
        self.assertEqual(binding["source"]["embedding_vocabulary_size"], 16)
        self.assertTrue(all(binding["verification"].values()))
        self.assertTrue(all(value is False for value in binding["limitations"].values()))
        self.assertTrue(all(value is False for value in binding["authorizations"].values()))

    def test_successful_fresh_replay_covers_qwen2_qwen3_and_llama(self) -> None:
        for family, tied in (("qwen2", False), ("qwen3", True), ("llama", True)):
            with self.subTest(family=family), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root / "source"
                exported = root / "export"
                source.mkdir()
                exported.mkdir()
                for artifact in (source, exported):
                    _make_artifact(artifact, family, tied=tied)
                    _write_tokenizer(artifact, 16)
                _flip_last_payload_byte(exported / "model.safetensors")
                source_generic = inspect_model_artifact(source)
                source_dense = inspect_dense_checkpoint(
                    source,
                    expected_inspection_report_sha256=source_generic["report_sha256"],
                )
                export_generic = inspect_model_artifact(exported)
                export_dense = inspect_dense_checkpoint(
                    exported,
                    expected_inspection_report_sha256=export_generic["report_sha256"],
                )
                spec = _align_spec(valid_train_spec(), source_generic, source_dense)
                completed = completed_record_for_spec(spec)
                completed["export"].update(
                    {
                        "artifact_sha256": export_generic["weight_set_sha256"],
                        "bundle_sha256": export_generic["bundle_manifest_sha256"],
                        "tokenizer_sha256": export_generic["tokenizer"][
                            "tokenizer_set_sha256"
                        ],
                        "inspection_report_sha256": export_dense["report_sha256"],
                        "physical_parameters": export_dense["tensor_inventory"][
                            "physical_parameter_count"
                        ],
                        "active_parameters": export_dense["tensor_inventory"][
                            "physical_parameter_count"
                        ],
                        "nonzero_parameters": export_dense["tensor_inventory"][
                            "physical_parameter_count"
                        ],
                        "average_weight_bits": export_generic["weights"][
                            "average_stored_bits_per_element"
                        ],
                        "weight_bytes": export_generic["weights"][
                            "safetensors_payload_bytes"
                        ],
                        "bundle_bytes": sum(
                            item["bytes"] for item in export_generic["files"]
                        ),
                    }
                )
                binding = build_completed_model_evidence_binding(
                    spec,
                    self.policy,
                    completed,
                    source_artifact_dir=source,
                    export_artifact_dir=exported,
                    source_runtime_report=_runtime_report(
                        source_generic, source_dense
                    ),
                    export_runtime_report=_runtime_report(
                        export_generic, export_dense
                    ),
                )
                self.assertEqual(binding["source"]["family"], family)
                self.assertTrue(verify_completed_model_evidence_binding(binding))

    def test_completion_export_identity_and_accounting_mismatches_fail(self) -> None:
        for field in (
            "artifact_sha256",
            "bundle_sha256",
            "tokenizer_sha256",
            "inspection_report_sha256",
            "physical_parameters",
            "active_parameters",
            "average_weight_bits",
            "weight_bytes",
            "bundle_bytes",
        ):
            changed = copy.deepcopy(self.completed)
            value = changed["export"][field]
            changed["export"][field] = (
                "0" * 64 if isinstance(value, str) else value + 1
            )
            with self.subTest(field=field):
                self.assert_rejected(completed=changed)

    def test_runtime_swap_resealed_identity_drift_and_artifact_mutation_fail(self) -> None:
        self.assert_rejected(
            source_runtime=self.export_runtime,
            export_runtime=self.source_runtime,
        )
        changed = copy.deepcopy(self.export_runtime)
        changed["static_inspection"]["weight_set_sha256"] = "f" * 64
        changed["report_sha256"] = compute_runtime_report_sha256(changed)
        self.assert_rejected(export_runtime=changed)

        _flip_last_payload_byte(self.export / "model.safetensors")
        self.assert_rejected()

    def test_runtime_accounting_class_and_vocabulary_mismatches_fail(self) -> None:
        variants = []
        changed = copy.deepcopy(self.export_runtime)
        changed["parameters"]["physical_elements"] += 1
        variants.append(changed)
        changed = copy.deepcopy(self.export_runtime)
        changed["runtime_classes"]["loaded_model_class"] = "wrong.Model"
        variants.append(changed)
        changed = copy.deepcopy(self.export_runtime)
        changed["forward"]["logits_shape"][2] -= 1
        variants.append(changed)
        for index, changed in enumerate(variants):
            changed["report_sha256"] = compute_runtime_report_sha256(changed)
            with self.subTest(index=index):
                self.assert_rejected(export_runtime=changed)

    def test_prune_export_must_realize_selected_architecture_delta(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            intended = root / "intended"
            wrong_dimension = root / "wrong-dimension"
            source.mkdir()
            intended.mkdir()
            wrong_dimension.mkdir()
            _make_artifact(source, "qwen3", tied=False)
            _write_tokenizer(source, 16)

            def reduce_ffn(rows: list[tuple[str, str, list[int]]]) -> None:
                for index, (name, dtype, shape) in enumerate(rows):
                    if ".mlp.gate_proj." in name or ".mlp.up_proj." in name:
                        rows[index] = (name, dtype, [11, 8])
                    elif ".mlp.down_proj." in name:
                        rows[index] = (name, dtype, [8, 11])

            _make_artifact(
                intended,
                "qwen3",
                tied=False,
                config_changes={"intermediate_size": 11},
                tensor_mutator=reduce_ffn,
            )
            _write_tokenizer(intended, 16)

            # Removing three untied vocabulary rows saves the same 48 physical
            # parameters as removing one FFN channel from each of two layers.
            # Aggregate parameter accounting alone therefore cannot distinguish
            # this wrong export from the prospectively selected operator.
            def reduce_vocabulary(rows: list[tuple[str, str, list[int]]]) -> None:
                for index, (name, dtype, shape) in enumerate(rows):
                    if name in {"model.embed_tokens.weight", "lm_head.weight"}:
                        rows[index] = (name, dtype, [13, 8])

            _make_artifact(
                wrong_dimension,
                "qwen3",
                tied=False,
                config_changes={"vocab_size": 13},
                tensor_mutator=reduce_vocabulary,
            )
            _write_tokenizer(wrong_dimension, 13)

            source_generic = inspect_model_artifact(source)
            source_dense = inspect_dense_checkpoint(
                source,
                expected_inspection_report_sha256=source_generic["report_sha256"],
            )
            spec = _campaign_ffn_prune_spec(source_generic, source_dense)

            intended_generic = inspect_model_artifact(intended)
            intended_dense = inspect_dense_checkpoint(
                intended,
                expected_inspection_report_sha256=intended_generic["report_sha256"],
            )
            accepted = build_completed_model_evidence_binding(
                spec,
                self.policy,
                _completed_for_export(spec, intended_generic, intended_dense),
                source_artifact_dir=source,
                export_artifact_dir=intended,
                source_runtime_report=_runtime_report(source_generic, source_dense),
                export_runtime_report=_runtime_report(
                    intended_generic, intended_dense
                ),
            )
            self.assertEqual(accepted["export"]["embedding_vocabulary_size"], 16)
            self.assertFalse(
                accepted["limitations"]["operator_payload_realization_verified"]
            )
            forged = copy.deepcopy(accepted)
            forged["export"]["tokenizer_set_sha256"] = "0" * 64
            forged["binding_sha256"] = (
                compute_completed_model_evidence_binding_sha256(forged)
            )
            self.assertFalse(verify_completed_model_evidence_binding(forged))

            _write_json(
                intended / "tokenizer.json",
                {
                    "version": "1.0",
                    "model": {
                        "type": "BPE",
                        "vocab": {
                            f"taken-{index}": index for index in range(16)
                        },
                    },
                    "added_tokens": [],
                },
            )
            retokenized_generic = inspect_model_artifact(intended)
            retokenized_dense = inspect_dense_checkpoint(
                intended,
                expected_inspection_report_sha256=retokenized_generic[
                    "report_sha256"
                ],
            )
            with self.assertRaisesRegex(
                CompletedModelEvidenceError,
                "preserve the exact tokenizer",
            ):
                build_completed_model_evidence_binding(
                    spec,
                    self.policy,
                    _completed_for_export(
                        spec, retokenized_generic, retokenized_dense
                    ),
                    source_artifact_dir=source,
                    export_artifact_dir=intended,
                    source_runtime_report=_runtime_report(
                        source_generic, source_dense
                    ),
                    export_runtime_report=_runtime_report(
                        retokenized_generic, retokenized_dense
                    ),
                )

            wrong_generic = inspect_model_artifact(wrong_dimension)
            wrong_dense = inspect_dense_checkpoint(
                wrong_dimension,
                expected_inspection_report_sha256=wrong_generic["report_sha256"],
            )
            self.assertEqual(
                wrong_dense["tensor_inventory"]["physical_parameter_count"],
                spec["export"]["planned_physical_parameters"],
            )
            with self.assertRaisesRegex(
                CompletedModelEvidenceError,
                "planned_vocabulary_size|FFN|ffn",
            ):
                build_completed_model_evidence_binding(
                    spec,
                    self.policy,
                    _completed_for_export(spec, wrong_generic, wrong_dense),
                    source_artifact_dir=source,
                    export_artifact_dir=wrong_dimension,
                    source_runtime_report=_runtime_report(
                        source_generic, source_dense
                    ),
                    export_runtime_report=_runtime_report(wrong_generic, wrong_dense),
                )

    def test_active_inputs_and_resealed_binding_forgery_fail(self) -> None:
        class ActiveDict(dict[str, object]):
            def items(self):  # type: ignore[no-untyped-def]
                raise AssertionError("active mapping hook ran")

        self.assert_rejected(completed=ActiveDict(self.completed))
        binding = self.build()
        variants = []
        changed = copy.deepcopy(binding)
        changed["authorizations"]["claim_authorized"] = True
        variants.append(changed)
        changed = copy.deepcopy(binding)
        changed["limitations"]["runtime_parameter_graph_equivalence_verified"] = True
        variants.append(changed)
        changed = copy.deepcopy(binding)
        changed["limitations"]["operator_payload_realization_verified"] = True
        variants.append(changed)
        changed = copy.deepcopy(binding)
        changed["export"]["weight_bytes"] += 1
        changed["export"]["runtime_parameter_bytes"] += 1
        variants.append(changed)
        changed = copy.deepcopy(binding)
        changed["export"]["runtime_requested_device"] = "bogus-device"
        variants.append(changed)
        changed = copy.deepcopy(binding)
        changed["export"]["observed_token_id_count"] -= 1
        variants.append(changed)
        changed = copy.deepcopy(binding)
        changed["export"]["architecture_class"] = "LlamaForCausalLM"
        variants.append(changed)
        changed = copy.deepcopy(binding)
        changed["export"]["serialized_weight_bits"] = 16.0
        variants.append(changed)
        changed = copy.deepcopy(binding)
        changed["export"]["bundle_manifest_sha256"] = binding["source"][
            "bundle_manifest_sha256"
        ]
        variants.append(changed)
        changed = copy.deepcopy(binding)
        changed["export"]["generic_inspection_report_sha256"] = binding["source"][
            "generic_inspection_report_sha256"
        ]
        variants.append(changed)
        changed = copy.deepcopy(binding)
        changed["export"]["dense_checkpoint_report_sha256"] = binding["source"][
            "dense_checkpoint_report_sha256"
        ]
        variants.append(changed)
        changed = copy.deepcopy(binding)
        changed["export"]["runtime_report_sha256"] = binding["source"][
            "runtime_report_sha256"
        ]
        variants.append(changed)
        changed = copy.deepcopy(binding)
        changed["completion"]["stage"] = "compress"
        variants.append(changed)
        changed = copy.deepcopy(binding)
        changed["completion"]["mechanism"] = "prune"
        variants.append(changed)
        changed = copy.deepcopy(binding)
        changed["completion"].update(
            {
                "stage": "compress",
                "mechanism": "prune",
                "export_intent": "compression",
                "fixed_size_layout_fields_preserved": False,
            }
        )
        changed["export"]["bundle_bytes"] -= 1
        variants.append(changed)
        changed = copy.deepcopy(binding)
        changed["completion"].update(
            {
                "stage": "compress",
                "mechanism": "prune",
                "export_intent": "compression",
                "fixed_size_layout_fields_preserved": False,
            }
        )
        changed["export"]["physical_parameters"] -= 1
        changed["export"]["weight_bytes"] -= 2
        changed["export"]["runtime_parameter_bytes"] -= 2
        changed["export"]["bundle_bytes"] -= 2
        changed["completion"]["active_parameters"] -= 1
        changed["completion"]["declared_nonzero_parameters"] -= 1
        variants.append(changed)
        changed = copy.deepcopy(binding)
        changed["completion"]["fixed_size_layout_fields_preserved"] = False
        variants.append(changed)
        for index, changed in enumerate(variants):
            changed["binding_sha256"] = (
                compute_completed_model_evidence_binding_sha256(changed)
            )
            with self.subTest(index=index):
                self.assertFalse(verify_completed_model_evidence_binding(changed))

    def test_optimized_python_retains_fail_closed_verifier(self) -> None:
        source = (ROOT / "src/cbds/completed_model_evidence.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("assert ", source)
        script = (
            "from cbds.completed_model_evidence import "
            "verify_completed_model_evidence_binding as v;"
            "raise SystemExit(0 if v({}) is False else 9)"
        )
        completed = subprocess.run(
            [sys.executable, "-O", "-c", script],
            cwd=ROOT,
            env={"PYTHONPATH": str(ROOT / "src")},
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)


if __name__ == "__main__":
    unittest.main()
