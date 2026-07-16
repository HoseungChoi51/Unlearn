from __future__ import annotations

import copy
import math
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.dense_checkpoint import inspect_dense_checkpoint  # noqa: E402
from cbds.dense_checkpoint_binding import (  # noqa: E402
    DenseCheckpointRunBindingError,
    build_dense_checkpoint_run_binding,
    compute_dense_checkpoint_run_binding_sha256,
    validate_run_spec_against_dense_checkpoint,
    verify_dense_checkpoint_run_binding,
)
from cbds.model_artifacts import inspect_model_artifact  # noqa: E402
from tests.test_dense_checkpoint import _make_artifact, _write_json  # noqa: E402
from tests.test_run_specs import (  # noqa: E402
    valid_compress_spec,
    valid_factorize_spec,
    valid_recycle_spec,
    valid_train_spec,
)


def _source_values(
    generic: dict[str, object], dense: dict[str, object]
) -> dict[str, int | float | str]:
    return {
        "checkpoint_sha256": generic["weight_set_sha256"],
        "inspection_report_sha256": dense["report_sha256"],
        "physical_parameters": dense["tensor_inventory"]["physical_parameter_count"],  # type: ignore[index]
        "serialized_weight_bits": generic["weights"][  # type: ignore[index]
            "average_stored_bits_per_element"
        ],
        "checkpoint_weight_bytes": generic["weights"][  # type: ignore[index]
            "safetensors_payload_bytes"
        ],
        "checkpoint_bundle_bytes": sum(
            item["bytes"] for item in generic["files"]  # type: ignore[index]
        ),
        "tokenizer_source_sha256": generic["tokenizer"][  # type: ignore[index]
            "tokenizer_set_sha256"
        ],
        "vocabulary_size": dense["architecture"]["vocab_size"],  # type: ignore[index]
    }


def _align_spec(
    spec: dict,
    generic: dict[str, object],
    dense: dict[str, object],
) -> dict:
    values = _source_values(generic, dense)
    spec = copy.deepcopy(spec)
    spec["model"].update(
        {
            name: values[name]
            for name in (
                "checkpoint_sha256",
                "inspection_report_sha256",
                "physical_parameters",
                "serialized_weight_bits",
                "checkpoint_weight_bytes",
                "checkpoint_bundle_bytes",
            )
        }
    )
    spec["tokenizer"]["source_sha256"] = values["tokenizer_source_sha256"]
    spec["tokenizer"]["vocabulary_size"] = values["vocabulary_size"]
    spec["export"].update(
        {
            "planned_vocabulary_size": values["vocabulary_size"],
            "planned_physical_parameters": values["physical_parameters"],
        }
    )
    if spec["export"]["intent"] == "fixed_size":
        spec["export"].update(
            {
                "planned_average_weight_bits": values["serialized_weight_bits"],
                "maximum_weight_bytes": values["checkpoint_weight_bytes"],
                "maximum_bundle_bytes": values["checkpoint_bundle_bytes"],
            }
        )
    elif spec["operator"]["mechanism"] == "quantize":
        planned_bits = spec["export"]["planned_average_weight_bits"]
        planned_weight_bytes = int(
            values["physical_parameters"] * planned_bits / 8
        )
        companion_bytes = (
            values["checkpoint_bundle_bytes"] - values["checkpoint_weight_bytes"]
        )
        spec["export"]["maximum_weight_bytes"] = planned_weight_bytes
        spec["export"]["maximum_bundle_bytes"] = (
            planned_weight_bytes + companion_bytes
        )
    return spec


def _factorize_spec(
    generic: dict[str, object], dense: dict[str, object]
) -> dict:
    spec = _align_spec(valid_factorize_spec(), generic, dense)
    matrix = next(
        item
        for item in dense["operator_bounds"]["factorizable_matrices"]  # type: ignore[index]
        if item["component"] == "ffn_up_proj" and item["layer"] == 0
    )
    rank = 2
    factor = {**matrix, "rank": rank}
    spec["operator"]["factorizations"] = [factor]
    dense_parameters = matrix["input_dimension"] * matrix["output_dimension"]
    factor_parameters = rank * (
        matrix["input_dimension"] + matrix["output_dimension"]
    )
    saving = dense_parameters - factor_parameters
    planned = spec["model"]["physical_parameters"] - saving
    spec["export"].update(
        {
            "planned_physical_parameters": planned,
            "planned_average_weight_bits": spec["model"]["serialized_weight_bits"],
            "maximum_weight_bytes": planned * 2,
            "maximum_bundle_bytes": (
                spec["model"]["checkpoint_bundle_bytes"] - saving * 2
            ),
        }
    )
    return spec


def _structural_prune_spec(
    generic: dict[str, object],
    dense: dict[str, object],
    *,
    groups: list[dict[str, object]],
    removed_parameters: int,
    planned_vocabulary_size: int | None = None,
) -> dict:
    spec = _align_spec(valid_compress_spec(), generic, dense)
    spec["operator"].update(
        {
            "mechanism": "prune",
            "family": "architecture_representable_structural_pruning",
            "bit_allocation": [],
            "structural_indices": groups,
        }
    )
    planned = spec["model"]["physical_parameters"] - removed_parameters
    companion_bytes = (
        spec["model"]["checkpoint_bundle_bytes"]
        - spec["model"]["checkpoint_weight_bytes"]
    )
    planned_weight_bytes = math.ceil(
        planned * spec["model"]["serialized_weight_bits"] / 8
    )
    spec["export"].update(
        {
            "planned_physical_parameters": planned,
            "planned_average_weight_bits": spec["model"][
                "serialized_weight_bits"
            ],
            "maximum_weight_bytes": planned_weight_bytes,
            "maximum_bundle_bytes": planned_weight_bytes + companion_bytes,
            "planned_vocabulary_size": (
                spec["tokenizer"]["vocabulary_size"]
                if planned_vocabulary_size is None
                else planned_vocabulary_size
            ),
        }
    )
    return spec


class DenseCheckpointBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        _make_artifact(cls.root, "qwen3")
        _write_json(
            cls.root / "tokenizer.json",
            {
                "version": "1.0",
                "model": {
                    "type": "BPE",
                    "vocab": {f"token-{index}": index for index in range(16)},
                },
                "added_tokens": [],
            },
        )
        cls.generic = inspect_model_artifact(cls.root)
        cls.dense = inspect_dense_checkpoint(
            cls.root,
            expected_inspection_report_sha256=cls.generic["report_sha256"],
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def assert_binding_rejected(self, spec: dict) -> None:
        with self.assertRaises(DenseCheckpointRunBindingError):
            validate_run_spec_against_dense_checkpoint(
                spec,
                inspection_report=self.generic,
                dense_checkpoint_report=self.dense,
            )

    def test_baseline_binds_all_identities_accounting_and_no_authority(self) -> None:
        spec = _align_spec(valid_train_spec(), self.generic, self.dense)
        validated = validate_run_spec_against_dense_checkpoint(
            spec,
            inspection_report=self.generic,
            dense_checkpoint_report=self.dense,
        )
        self.assertEqual(validated, spec)
        validated["model"]["physical_parameters"] = 1
        self.assertNotEqual(validated, spec)
        binding = build_dense_checkpoint_run_binding(
            spec,
            inspection_report=self.generic,
            dense_checkpoint_report=self.dense,
        )
        self.assertTrue(verify_dense_checkpoint_run_binding(binding))
        self.assertEqual(
            binding["binding_sha256"],
            compute_dense_checkpoint_run_binding_sha256(binding),
        )
        self.assertEqual(
            binding["accounting"]["physical_parameters"],  # type: ignore[index]
            self.dense["tensor_inventory"]["physical_parameter_count"],  # type: ignore[index]
        )
        self.assertTrue(all(binding["verification"].values()))  # type: ignore[union-attr]
        self.assertTrue(
            all(value is False for value in binding["authorizations"].values())  # type: ignore[union-attr]
        )

    def test_binding_accepts_exact_qwen2_and_llama_family_inventories(self) -> None:
        for family, tied in (("qwen2", False), ("llama", True)):
            with self.subTest(family=family, tied=tied):
                artifact = self.root / f"{family}-{tied}"
                artifact.mkdir()
                _make_artifact(artifact, family, tied=tied)
                _write_json(
                    artifact / "tokenizer.json",
                    {
                        "version": "1.0",
                        "model": {
                            "type": "BPE",
                            "vocab": {
                                f"token-{index}": index for index in range(16)
                            },
                        },
                        "added_tokens": [],
                    },
                )
                generic = inspect_model_artifact(artifact)
                dense = inspect_dense_checkpoint(
                    artifact,
                    expected_inspection_report_sha256=generic["report_sha256"],
                )
                spec = _align_spec(valid_train_spec(), generic, dense)
                binding = build_dense_checkpoint_run_binding(
                    spec,
                    inspection_report=generic,
                    dense_checkpoint_report=dense,
                )
                self.assertTrue(verify_dense_checkpoint_run_binding(binding))
                roles = set(dense["operator_bounds"]["tensor_roles"])
                self.assertEqual("lm_head" in roles, not tied)
                self.assertEqual("attention_q_proj_bias" in roles, family == "qwen2")

    def test_every_source_identity_and_accounting_mismatch_fails(self) -> None:
        baseline = _align_spec(valid_train_spec(), self.generic, self.dense)
        fields = (
            "checkpoint_sha256",
            "inspection_report_sha256",
            "physical_parameters",
            "serialized_weight_bits",
            "checkpoint_weight_bytes",
            "checkpoint_bundle_bytes",
        )
        for field in fields:
            changed = copy.deepcopy(baseline)
            value = changed["model"][field]
            changed["model"][field] = (
                "0" * 64 if isinstance(value, str) else value + 1
            )
            with self.subTest(field=field):
                self.assert_binding_rejected(changed)
        for field in ("source_sha256", "vocabulary_size"):
            changed = copy.deepcopy(baseline)
            value = changed["tokenizer"][field]
            changed["tokenizer"][field] = (
                "0" * 64 if isinstance(value, str) else value + 1
            )
            with self.subTest(field=field):
                self.assert_binding_rejected(changed)

    def test_reserved_embedding_rows_may_exceed_contiguous_tokenizer_ids(self) -> None:
        artifact = self.root / "mismatched-tokenizer"
        artifact.mkdir()
        _make_artifact(artifact, "qwen3")
        _write_json(
            artifact / "tokenizer.json",
            {
                "version": "1.0",
                "model": {
                    "type": "BPE",
                    "vocab": {f"token-{index}": index for index in range(15)},
                },
                "added_tokens": [],
            },
        )
        generic = inspect_model_artifact(artifact)
        dense = inspect_dense_checkpoint(
            artifact,
            expected_inspection_report_sha256=generic["report_sha256"],
        )
        spec = _align_spec(valid_train_spec(), generic, dense)
        validate_run_spec_against_dense_checkpoint(
            spec,
            inspection_report=generic,
            dense_checkpoint_report=dense,
        )
        self.assertFalse(generic["tokenizer"]["matches_config_vocab_size"])

    def test_tokenizer_id_range_cannot_exceed_model_vocabulary(self) -> None:
        artifact = self.root / "oversized-tokenizer"
        artifact.mkdir()
        _make_artifact(artifact, "qwen3")
        _write_json(
            artifact / "tokenizer.json",
            {
                "version": "1.0",
                "model": {
                    "type": "BPE",
                    "vocab": {f"token-{index}": index for index in range(17)},
                },
                "added_tokens": [],
            },
        )
        generic = inspect_model_artifact(artifact)
        dense = inspect_dense_checkpoint(
            artifact,
            expected_inspection_report_sha256=generic["report_sha256"],
        )
        spec = _align_spec(valid_train_spec(), generic, dense)
        with self.assertRaisesRegex(
            DenseCheckpointRunBindingError,
            "contiguous token-ID range",
        ):
            validate_run_spec_against_dense_checkpoint(
                spec,
                inspection_report=generic,
                dense_checkpoint_report=dense,
            )

    def test_structural_bounds_gqa_and_component_scope(self) -> None:
        valid = _align_spec(valid_recycle_spec(), self.generic, self.dense)
        valid["operator"]["structural_indices"] = [
            {"component": "attention_head", "layer": 0, "indices": [0, 1]}
        ]
        validate_run_spec_against_dense_checkpoint(
            valid,
            inspection_report=self.generic,
            dense_checkpoint_report=self.dense,
        )
        mutations = []
        partial = copy.deepcopy(valid)
        partial["operator"]["structural_indices"][0]["indices"] = [0]
        mutations.append(partial)
        one_past = copy.deepcopy(valid)
        one_past["operator"]["structural_indices"][0]["indices"] = [4, 5]
        mutations.append(one_past)
        bad_layer = copy.deepcopy(valid)
        bad_layer["operator"]["structural_indices"][0]["layer"] = 2
        mutations.append(bad_layer)
        mixed = copy.deepcopy(valid)
        mixed["operator"]["structural_indices"].append(
            {"component": "ffn_channel", "layer": 0, "indices": [0]}
        )
        mutations.append(mixed)
        for index, changed in enumerate(mutations):
            with self.subTest(index=index):
                self.assert_binding_rejected(changed)

    def test_structural_pruning_reconciles_representable_physical_exports(self) -> None:
        architecture = self.dense["architecture"]
        inventory = self.dense["tensor_inventory"]
        hidden = architecture["hidden_size"]
        layers = architecture["num_hidden_layers"]

        ffn_removed = layers * 3 * hidden
        ffn = _structural_prune_spec(
            self.generic,
            self.dense,
            groups=[
                {"component": "ffn_channel", "layer": layer, "indices": [0]}
                for layer in range(layers)
            ],
            removed_parameters=ffn_removed,
        )
        binding = build_dense_checkpoint_run_binding(
            ffn,
            inspection_report=self.generic,
            dense_checkpoint_report=self.dense,
        )
        self.assertEqual(
            binding["operator"]["structural_removed_parameter_count"],  # type: ignore[index]
            ffn_removed,
        )
        impossible = copy.deepcopy(binding)
        impossible["operator"]["structural_removed_parameter_count"] = (  # type: ignore[index]
            impossible["accounting"]["physical_parameters"]  # type: ignore[index]
        )
        impossible["binding_sha256"] = compute_dense_checkpoint_run_binding_sha256(
            impossible
        )
        self.assertFalse(verify_dense_checkpoint_run_binding(impossible))

        head_removed = (
            layers
            * 2
            * (2 + 1)
            * architecture["head_dim"]
            * hidden
        )
        head = _structural_prune_spec(
            self.generic,
            self.dense,
            groups=[
                {
                    "component": "attention_head",
                    "layer": layer,
                    "indices": [0, 1],
                }
                for layer in range(layers)
            ],
            removed_parameters=head_removed,
        )
        validate_run_spec_against_dense_checkpoint(
            head,
            inspection_report=self.generic,
            dense_checkpoint_report=self.dense,
        )

        layer_removed = sum(
            record["stored_elements"]
            for record in inventory["records"]
            if record["layer"] == 0
        )
        layer = _structural_prune_spec(
            self.generic,
            self.dense,
            groups=[{"component": "layer", "layer": None, "indices": [0]}],
            removed_parameters=layer_removed,
        )
        validate_run_spec_against_dense_checkpoint(
            layer,
            inspection_report=self.generic,
            dense_checkpoint_report=self.dense,
        )

        embedding = _structural_prune_spec(
            self.generic,
            self.dense,
            groups=[
                {"component": "embedding_token", "layer": None, "indices": [0]}
            ],
            removed_parameters=hidden,
            planned_vocabulary_size=architecture["vocab_size"] - 1,
        )
        embedding["tokenizer"]["derived_vocabulary_mapping_sha256"] = "d" * 64
        validate_run_spec_against_dense_checkpoint(
            embedding,
            inspection_report=self.generic,
            dense_checkpoint_report=self.dense,
        )

    def test_structural_pruning_rejects_unbacked_savings_and_shapes(self) -> None:
        architecture = self.dense["architecture"]
        hidden = architecture["hidden_size"]
        layers = architecture["num_hidden_layers"]
        valid = _structural_prune_spec(
            self.generic,
            self.dense,
            groups=[
                {"component": "ffn_channel", "layer": layer, "indices": [0]}
                for layer in range(layers)
            ],
            removed_parameters=layers * 3 * hidden,
        )
        exaggerated = copy.deepcopy(valid)
        exaggerated["export"]["planned_physical_parameters"] -= 1
        exaggerated["export"]["maximum_weight_bytes"] -= 2
        exaggerated["export"]["maximum_bundle_bytes"] -= 2
        self.assert_binding_rejected(exaggerated)

        undeclared_quantization = copy.deepcopy(valid)
        undeclared_quantization["export"]["planned_average_weight_bits"] = 8.0
        undeclared_quantization["export"]["maximum_weight_bytes"] = (
            undeclared_quantization["export"]["planned_physical_parameters"]
        )
        undeclared_quantization["export"]["maximum_bundle_bytes"] = (
            undeclared_quantization["export"]["maximum_weight_bytes"]
            + undeclared_quantization["model"]["checkpoint_bundle_bytes"]
            - undeclared_quantization["model"]["checkpoint_weight_bytes"]
        )
        self.assert_binding_rejected(undeclared_quantization)

        missing_layer = copy.deepcopy(valid)
        missing_layer["operator"]["structural_indices"].pop()
        self.assert_binding_rejected(missing_layer)

        unsupported = _structural_prune_spec(
            self.generic,
            self.dense,
            groups=[
                {
                    "component": "residual_branch",
                    "layer": 0,
                    "indices": [0],
                }
            ],
            removed_parameters=1,
        )
        self.assert_binding_rejected(unsupported)

    def test_pruning_cannot_remove_every_unit(self) -> None:
        spec = _align_spec(valid_compress_spec(), self.generic, self.dense)
        spec["operator"].update(
            {
                "mechanism": "prune",
                "family": "structured_head_pruning",
                "bit_allocation": [],
                "structural_indices": [
                    {
                        "component": "attention_head",
                        "layer": 0,
                        "indices": [0, 1, 2, 3],
                    }
                ],
            }
        )
        spec["export"].update(
            {
                "planned_physical_parameters": spec["model"]["physical_parameters"] - 1,
                "planned_average_weight_bits": 16.0,
                "maximum_weight_bytes": spec["model"]["checkpoint_weight_bytes"] - 2,
                "maximum_bundle_bytes": spec["model"]["checkpoint_bundle_bytes"] - 2,
            }
        )
        self.assert_binding_rejected(spec)

    def test_quantization_selectors_are_report_backed_disjoint_and_reducing(self) -> None:
        valid = _align_spec(valid_compress_spec(), self.generic, self.dense)
        validate_run_spec_against_dense_checkpoint(
            valid,
            inspection_report=self.generic,
            dense_checkpoint_report=self.dense,
        )
        unknown = copy.deepcopy(valid)
        unknown["operator"]["bit_allocation"][0]["component"] = "made_up"
        self.assert_binding_rejected(unknown)
        overlap = copy.deepcopy(valid)
        overlap["operator"]["bit_allocation"].append(
            {"component": "embedding", "layer": None, "bits": 4.0}
        )
        self.assert_binding_rejected(overlap)
        high = copy.deepcopy(valid)
        high["operator"]["bit_allocation"][0]["bits"] = 32.0
        self.assert_binding_rejected(high)
        no_op = copy.deepcopy(valid)
        no_op["operator"]["bit_allocation"][0]["bits"] = 16.0
        no_op["export"]["planned_average_weight_bits"] = 16.0
        no_op["export"]["maximum_weight_bytes"] = no_op["model"]["checkpoint_weight_bytes"] - 1
        self.assert_binding_rejected(no_op)

    def test_quantization_reconciles_selected_and_unselected_payload_bits(self) -> None:
        spec = _align_spec(valid_compress_spec(), self.generic, self.dense)
        spec["operator"]["bit_allocation"] = [
            {"component": "attention_q_norm", "layer": 0, "bits": 4.0}
        ]
        records = self.dense["tensor_inventory"]["records"]
        total_elements = sum(record["stored_elements"] for record in records)
        selected_elements = sum(
            record["stored_elements"]
            for record in records
            if record["role"] == "attention_q_norm" and record["layer"] == 0
        )
        source_bits = spec["model"]["serialized_weight_bits"]
        lower_bound = (
            total_elements * source_bits - selected_elements * (source_bits - 4.0)
        ) / total_elements
        companion_bytes = (
            spec["model"]["checkpoint_bundle_bytes"]
            - spec["model"]["checkpoint_weight_bytes"]
        )
        maximum_weight_bytes = math.ceil(total_elements * lower_bound / 8)
        spec["export"].update(
            {
                "planned_average_weight_bits": lower_bound,
                "maximum_weight_bytes": maximum_weight_bytes,
                "maximum_bundle_bytes": maximum_weight_bytes + companion_bytes,
            }
        )
        binding = build_dense_checkpoint_run_binding(
            spec,
            inspection_report=self.generic,
            dense_checkpoint_report=self.dense,
        )
        self.assertAlmostEqual(
            binding["operator"][  # type: ignore[index]
                "quantization_payload_lower_bound_average_bits"
            ],
            lower_bound,
        )
        for field, value in (
            ("bit_allocation_count", 5000),
            ("bit_allocated_tensor_count", 10**100),
            (
                "quantization_payload_lower_bound_average_bits",
                source_bits,
            ),
        ):
            impossible = copy.deepcopy(binding)
            impossible["operator"][field] = value
            impossible["binding_sha256"] = (
                compute_dense_checkpoint_run_binding_sha256(impossible)
            )
            with self.subTest(resealed_field=field):
                self.assertFalse(verify_dense_checkpoint_run_binding(impossible))

        sub_bit = _align_spec(valid_compress_spec(), self.generic, self.dense)
        sub_bit["operator"]["bit_allocation"] = [
            {"component": "all_weights", "layer": None, "bits": 0.5}
        ]
        sub_bit_weight_bytes = math.ceil(total_elements * 0.5 / 8)
        sub_bit["export"].update(
            {
                "planned_average_weight_bits": 0.5,
                "maximum_weight_bytes": sub_bit_weight_bytes,
                "maximum_bundle_bytes": sub_bit_weight_bytes + companion_bytes,
            }
        )
        sub_bit_binding = build_dense_checkpoint_run_binding(
            sub_bit,
            inspection_report=self.generic,
            dense_checkpoint_report=self.dense,
        )
        self.assertTrue(verify_dense_checkpoint_run_binding(sub_bit_binding))

        false_four_bit_claim = copy.deepcopy(spec)
        false_four_bit_claim["export"]["planned_average_weight_bits"] = 4.0
        false_four_bit_claim["export"]["maximum_weight_bytes"] = math.ceil(
            total_elements * 4 / 8
        )
        false_four_bit_claim["export"]["maximum_bundle_bytes"] = (
            false_four_bit_claim["export"]["maximum_weight_bytes"]
            + companion_bytes
        )
        self.assert_binding_rejected(false_four_bit_claim)

        changed_parameter_count = copy.deepcopy(spec)
        changed_parameter_count["export"]["planned_physical_parameters"] -= 1
        self.assert_binding_rejected(changed_parameter_count)

    def test_factorization_must_match_exact_report_matrix(self) -> None:
        valid = _factorize_spec(self.generic, self.dense)
        validate_run_spec_against_dense_checkpoint(
            valid,
            inspection_report=self.generic,
            dense_checkpoint_report=self.dense,
        )
        for field, value in (
            ("tensor_name", "model.layers.0.mlp.unknown.weight"),
            ("component", "ffn_down_proj"),
            ("layer", 1),
            ("input_dimension", 9),
            ("output_dimension", 13),
        ):
            changed = copy.deepcopy(valid)
            changed["operator"]["factorizations"][0][field] = value
            with self.subTest(field=field):
                self.assert_binding_rejected(changed)
        undeclared_quantization = copy.deepcopy(valid)
        undeclared_quantization["export"]["planned_average_weight_bits"] = 8.0
        undeclared_quantization["export"]["maximum_weight_bytes"] = (
            undeclared_quantization["export"]["planned_physical_parameters"]
        )
        undeclared_quantization["export"]["maximum_bundle_bytes"] = (
            undeclared_quantization["export"]["maximum_weight_bytes"]
            + undeclared_quantization["model"]["checkpoint_bundle_bytes"]
            - undeclared_quantization["model"]["checkpoint_weight_bytes"]
        )
        self.assert_binding_rejected(undeclared_quantization)

    def test_active_inputs_and_self_consistent_binding_forgery_fail(self) -> None:
        spec = _align_spec(valid_train_spec(), self.generic, self.dense)

        class ActiveDict(dict[str, object]):
            def items(self):  # type: ignore[no-untyped-def]
                raise AssertionError("active hook ran")

        with self.assertRaises(DenseCheckpointRunBindingError):
            validate_run_spec_against_dense_checkpoint(
                ActiveDict(spec),
                inspection_report=self.generic,
                dense_checkpoint_report=self.dense,
            )
        binding = build_dense_checkpoint_run_binding(
            spec,
            inspection_report=self.generic,
            dense_checkpoint_report=self.dense,
        )
        changed = copy.deepcopy(binding)
        changed["authorizations"]["training_authorized"] = True
        changed["binding_sha256"] = compute_dense_checkpoint_run_binding_sha256(changed)
        self.assertFalse(verify_dense_checkpoint_run_binding(changed))
        changed = copy.deepcopy(binding)
        changed["operator"]["mechanism"] = "invented"
        changed["binding_sha256"] = compute_dense_checkpoint_run_binding_sha256(changed)
        self.assertFalse(verify_dense_checkpoint_run_binding(changed))
        changed = copy.deepcopy(binding)
        changed["operator"]["structural_group_count"] = 1
        changed["binding_sha256"] = compute_dense_checkpoint_run_binding_sha256(changed)
        self.assertFalse(verify_dense_checkpoint_run_binding(changed))
        changed = copy.deepcopy(binding)
        changed["accounting"]["checkpoint_weight_bytes"] += 1
        changed["binding_sha256"] = compute_dense_checkpoint_run_binding_sha256(changed)
        self.assertFalse(verify_dense_checkpoint_run_binding(changed))

    def test_optimized_python_retains_fail_closed_checks(self) -> None:
        source = (ROOT / "src/cbds/dense_checkpoint_binding.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("assert ", source)
        script = (
            "from cbds.dense_checkpoint_binding import verify_dense_checkpoint_run_binding as v;"
            "raise SystemExit(0 if v({}) is False else 7)"
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
