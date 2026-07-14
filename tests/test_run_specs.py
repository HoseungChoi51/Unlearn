from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from cbds.manifests import canonical_json_bytes, load_document
from cbds.run_specs import (
    CAMPAIGN_POLICY_SCHEMA_VERSION,
    RUN_SPEC_SCHEMA_VERSION,
    CampaignPolicyValidationError,
    CampaignRunValidationError,
    RunSpecValidationError,
    campaign_policy_sha256,
    load_campaign_policy,
    load_run_spec_against_campaign,
    load_run_spec,
    run_spec_sha256,
    validate_campaign_policy,
    validate_run_spec_against_campaign,
    validate_run_spec,
    write_run_spec,
)


ROOT = Path(__file__).resolve().parents[1]
SHA1 = "1" * 40
CAMPAIGN_POLICY = ROOT / "configs" / "campaign-policy.json"
EXAMPLE_RUN_SPEC = ROOT / "examples" / "run-spec.example.json"
CAMPAIGN_POLICY_SHA256 = "7f6212d95cdbd45d7db0efbe90af43a03fb6221495d55237b91fdf6c6fc1c7fa"


def valid_train_spec() -> dict:
    return {
        "schema_version": "2.0.0",
        "run_id": "train-run-0001",
        "created_at": "2026-07-14T12:00:00+09:00",
        "git_revision": SHA1,
        "stage": "train",
        "campaign": {
            "policy_schema_version": "1.0.0",
            "policy_sha256": CAMPAIGN_POLICY_SHA256,
            "profile": "screening",
            "contrast_role": None,
            "replicate_index": 0,
            "declared_seed_count": 2,
        },
        "model": {
            "repository": "Qwen/Qwen3-0.6B-Base",
            "revision": "2" * 40,
            "checkpoint_sha256": "3" * 64,
            "inspection_report_sha256": "a" * 64,
            "architecture": "dense",
            "physical_parameters": 600_000_000,
            "serialized_weight_bits": 16.0,
            "checkpoint_weight_bytes": 1_200_000_000,
            "checkpoint_bundle_bytes": 1_210_000_000,
        },
        "tokenizer": {
            "repository": "Qwen/Qwen3-0.6B-Base",
            "revision": "2" * 40,
            "source_sha256": "4" * 64,
            "derived_vocabulary_mapping_sha256": None,
            "vocabulary_size": 151_936,
        },
        "data": {
            "repository": "HoseungChoi51/terminal-suite",
            "revision": "5" * 40,
            "manifest_sha256": "6" * 64,
            "semantic_graph_sha256": "7" * 64,
            "fixtures_sha256": "8" * 64,
            "splits": [
                {
                    "name": "training",
                    "sha256": "9" * 64,
                    "sealed": False,
                    "role": "training",
                },
                {
                    "name": "operator-selection",
                    "sha256": "a" * 64,
                    "sealed": False,
                    "role": "operator_selection",
                },
                {
                    "name": "shadow-validation",
                    "sha256": "b" * 64,
                    "sealed": False,
                    "role": "shadow_validation",
                },
                {
                    "name": "sealed-test",
                    "sha256": "c" * 64,
                    "sealed": True,
                    "role": "sealed_test",
                },
            ],
        },
        "execution": {
            "container_image_repository": "ghcr.io/example/terminal-runner",
            "container_image_digest": f"sha256:{'d' * 64}",
            "container_recipe_revision": "e" * 40,
            "container_recipe_sha256": "f" * 64,
            "verifier_repository": "HoseungChoi51/terminal-verifier",
            "verifier_revision": "0" * 40,
            "verifier_sha256": "1" * 64,
        },
        "capability_mixture": {
            "target": [
                {
                    "name": "unix_terminal",
                    "fraction": 0.8,
                    "tokens": 1_600_000,
                    "data_sha256": "2" * 64,
                }
            ],
            "support": [
                {
                    "name": "instruction_comprehension",
                    "fraction": 0.2,
                    "tokens": 400_000,
                    "data_sha256": "3" * 64,
                }
            ],
        },
        "teacher": {
            "enabled": False,
            "repository": None,
            "revision": None,
            "checkpoint_sha256": None,
            "architecture": None,
            "physical_parameters": None,
            "generation_policy_sha256": None,
            "source_split": None,
            "initial_candidates_per_prompt": 0,
            "maximum_candidates_per_prompt": 0,
            "verified_only": False,
        },
        "operator": {
            "mechanism": "baseline",
            "family": "dense_sft",
            "configuration_sha256": "4" * 64,
            "dose": None,
            "selection_strategy": "none",
            "selection_split": None,
            "selection_manifest_sha256": None,
            "structural_indices": [],
            "bit_allocation": [],
            "factorizations": [],
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
                "minimum_sequence_length": 1_024,
                "maximum_sequence_length": 2_048,
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
            "mixture_visible": 2_000_000,
            "target": 1_600_000,
            "support": 400_000,
            "optimizer_visible": 2_000_000,
            "teacher_derived": 0,
            "selection_visible": 0,
            "maximum_sequence_length": 2_048,
        },
        "compute_budget": {
            "accounting_revision": "5" * 40,
            "accounting_sha256": "6" * 64,
            "selection_max_flops": 0.0,
            "teacher_generation_max_flops": 0.0,
            "optimization_max_flops": 200.0,
            "compression_max_flops": 0.0,
            "export_max_flops": 5.0,
            "total_max_flops": 205.0,
        },
        "checkpoint": {
            "selection_split": "shadow-validation",
            "metric": "static_pass_at_1",
            "mode": "max",
            "tie_breakers": ["bounded_terminal", "weight_bytes"],
            "rule": "Highest static pass@1; apply tie breakers in listed order.",
            "save_every_optimizer_steps": 100,
            "maximum_saved_checkpoints": 3,
        },
        "export": {
            "intent": "fixed_size",
            "architecture": "dense",
            "format": "safetensors",
            "runtime_compatibility": ["transformers-sdpa"],
            "planned_physical_parameters": 600_000_000,
            "planned_average_weight_bits": 16.0,
            "maximum_weight_bytes": 1_200_000_000,
            "maximum_bundle_bytes": 1_210_000_000,
            "planned_vocabulary_size": 151_936,
            "include_tokenizer": True,
        },
    }


def valid_compress_spec() -> dict:
    spec = valid_train_spec()
    spec["run_id"] = "compress-run-0001"
    spec["stage"] = "compress"
    spec["operator"].update(
        {
            "mechanism": "quantize",
            "family": "task_aware_mixed_precision",
            "dose": "4-bit-average",
            "selection_strategy": "target_aware",
            "selection_split": "operator-selection",
            "selection_manifest_sha256": "7" * 64,
            "bit_allocation": [
                {"component": "all_weights", "layer": None, "bits": 4.0}
            ],
        }
    )
    spec["optimizer"] = {
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
    spec["training_protocol"] = {
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
    spec["tokens"]["optimizer_visible"] = 0
    spec["tokens"]["selection_visible"] = 250_000
    spec["compute_budget"].update(
        {
            "selection_max_flops": 10.0,
            "optimization_max_flops": 0.0,
            "compression_max_flops": 100.0,
            "total_max_flops": 115.0,
        }
    )
    spec["checkpoint"].update(
        {
            "save_every_optimizer_steps": 0,
            "maximum_saved_checkpoints": 1,
        }
    )
    spec["export"].update(
        {
            "intent": "compression",
            "planned_average_weight_bits": 4.0,
            "maximum_weight_bytes": 300_000_000,
            "maximum_bundle_bytes": 310_000_000,
        }
    )
    return spec


def valid_factorize_spec() -> dict:
    spec = valid_compress_spec()
    spec["run_id"] = "factorize-run-0001"
    spec["operator"].update(
        {
            "mechanism": "factorize",
            "family": "dense_low_rank_svd",
            "dose": "rank-64",
            "structural_indices": [],
            "bit_allocation": [],
            "factorizations": [
                {
                    "tensor_name": "model.layers.0.mlp.up_proj.weight",
                    "component": "ffn_up_proj",
                    "layer": 0,
                    "input_dimension": 576,
                    "output_dimension": 1536,
                    "rank": 64,
                }
            ],
        }
    )
    spec["export"].update(
        {
            "planned_physical_parameters": 599_250_432,
            "planned_average_weight_bits": 16.0,
            "maximum_weight_bytes": 1_198_500_864,
            "maximum_bundle_bytes": 1_208_500_864,
        }
    )
    return spec


def valid_recycle_spec() -> dict:
    spec = valid_train_spec()
    spec["operator"].update(
        {
            "mechanism": "recycle",
            "family": "ffn_reset_regrow",
            "dose": 0.05,
            "selection_strategy": "target_aware",
            "selection_split": "operator-selection",
            "selection_manifest_sha256": "b" * 64,
            "structural_indices": [
                {"component": "ffn_channel", "layer": 0, "indices": [1, 2, 3]}
            ],
        }
    )
    spec["tokens"]["selection_visible"] = 250_000
    spec["compute_budget"]["selection_max_flops"] = 10.0
    spec["compute_budget"]["total_max_flops"] += 10.0
    return spec


def spec_for_campaign_profile(profile: str, replicate_index: int = 0) -> dict:
    spec = valid_train_spec()
    required_seeds = 2 if profile == "screening" else 5
    optimizer_tokens = 2_000_000 if profile == "screening" else 20_000_000
    spec["campaign"].update(
        {
            "profile": profile,
            "contrast_role": (
                None if profile == "screening" else "reference"
            ),
            "replicate_index": replicate_index,
            "declared_seed_count": required_seeds,
        }
    )
    spec["capability_mixture"]["target"][0]["tokens"] = int(
        optimizer_tokens * 0.8
    )
    spec["capability_mixture"]["support"][0]["tokens"] = int(
        optimizer_tokens * 0.2
    )
    spec["tokens"].update(
        {
            "mixture_visible": optimizer_tokens,
            "target": int(optimizer_tokens * 0.8),
            "support": int(optimizer_tokens * 0.2),
            "optimizer_visible": optimizer_tokens,
        }
    )
    return spec


def enable_teacher(spec: dict) -> None:
    spec["teacher"].update(
        {
            "enabled": True,
            "repository": "HuggingFaceTB/SmolLM3-3B",
            "revision": "8" * 40,
            "checkpoint_sha256": "9" * 64,
            "architecture": "dense",
            "physical_parameters": 3_000_000_000,
            "generation_policy_sha256": "a" * 64,
            "source_split": "training",
            "initial_candidates_per_prompt": 2,
            "maximum_candidates_per_prompt": 4,
            "verified_only": True,
        }
    )
    spec["tokens"]["teacher_derived"] = 500_000
    spec["compute_budget"]["teacher_generation_max_flops"] = 50.0
    spec["compute_budget"]["total_max_flops"] += 50.0


class SchemaContractTests(unittest.TestCase):
    def test_external_schemas_cannot_weaken_frozen_contracts(self) -> None:
        cases = (
            (
                ROOT / "run-spec.schema.json",
                validate_run_spec,
                valid_train_spec(),
                RunSpecValidationError,
            ),
            (
                ROOT / "campaign-policy.schema.json",
                validate_campaign_policy,
                load_document(CAMPAIGN_POLICY),
                CampaignPolicyValidationError,
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            for index, (source, validator, document, error_type) in enumerate(cases):
                with self.subTest(source=source.name):
                    schema = json.loads(source.read_text(encoding="utf-8"))
                    schema["additionalProperties"] = True
                    path = Path(directory) / f"weakened-{index}.schema.json"
                    path.write_text(json.dumps(schema), encoding="utf-8")
                    with self.assertRaisesRegex(error_type, "frozen packaged"):
                        validator(document, schema_path=path)

    def test_root_and_packaged_schemas_are_identical(self) -> None:
        root = ROOT / "run-spec.schema.json"
        packaged = ROOT / "src" / "cbds" / "schemas" / "run-spec.schema.json"
        self.assertEqual(root.read_bytes(), packaged.read_bytes())
        schema = json.loads(root.read_text(encoding="utf-8"))
        self.assertEqual(schema["properties"]["schema_version"]["const"], RUN_SPEC_SCHEMA_VERSION)
        self.assertNotIn("flops", schema["properties"])
        self.assertNotIn("artifact_sha256", schema["$defs"]["export"]["properties"])

    def test_root_and_packaged_campaign_schemas_are_identical(self) -> None:
        root = ROOT / "campaign-policy.schema.json"
        packaged = ROOT / "src" / "cbds" / "schemas" / "campaign-policy.schema.json"
        self.assertEqual(root.read_bytes(), packaged.read_bytes())
        schema = json.loads(root.read_text(encoding="utf-8"))
        self.assertEqual(
            schema["properties"]["schema_version"]["const"],
            CAMPAIGN_POLICY_SCHEMA_VERSION,
        )

    def test_every_object_property_is_explicitly_required(self) -> None:
        schema = load_document(ROOT / "run-spec.schema.json")

        def visit(node: object) -> None:
            if isinstance(node, dict):
                if node.get("type") == "object" and "properties" in node:
                    self.assertEqual(set(node["properties"]), set(node.get("required", [])))
                for value in node.values():
                    visit(value)
            elif isinstance(node, list):
                for value in node:
                    visit(value)

        visit(schema)

    def test_every_campaign_object_property_is_explicitly_required(self) -> None:
        schema = load_document(ROOT / "campaign-policy.schema.json")

        def visit(node: object) -> None:
            if isinstance(node, dict):
                if node.get("type") == "object" and "properties" in node:
                    self.assertEqual(set(node["properties"]), set(node.get("required", [])))
                for value in node.values():
                    visit(value)
            elif isinstance(node, list):
                for value in node:
                    visit(value)

        visit(schema)


class CampaignPolicyTests(unittest.TestCase):
    def test_checked_in_policy_is_valid_content_addressed_and_loadable(self) -> None:
        policy = load_document(CAMPAIGN_POLICY)
        self.assertEqual(validate_campaign_policy(policy), policy)
        self.assertEqual(load_campaign_policy(CAMPAIGN_POLICY), policy)
        self.assertEqual(campaign_policy_sha256(policy), CAMPAIGN_POLICY_SHA256)
        reordered = dict(reversed(list(policy.items())))
        self.assertEqual(campaign_policy_sha256(reordered), CAMPAIGN_POLICY_SHA256)

    def test_policy_contract_cannot_drift_behind_the_same_schema_version(self) -> None:
        policy = load_document(CAMPAIGN_POLICY)
        policy["optimizer"]["betas"] = [0.9, 0.999]
        with self.assertRaisesRegex(
            CampaignPolicyValidationError,
            "frozen PLAN contract",
        ):
            validate_campaign_policy(policy)

        profile_drift = load_document(CAMPAIGN_POLICY)
        profile_drift["profiles"][0]["optimizer_visible_tokens"] += 1
        with self.assertRaisesRegex(
            CampaignPolicyValidationError,
            "frozen PLAN contract",
        ):
            validate_campaign_policy(profile_drift)

        grid_drift = load_document(CAMPAIGN_POLICY)
        grid_drift["learning_rate_grids"]["full_model"] = [0.5]
        with self.assertRaisesRegex(
            CampaignPolicyValidationError,
            "frozen PLAN contract",
        ):
            validate_campaign_policy(grid_drift)

    def test_screening_confirmation_and_runner_up_profiles_bind(self) -> None:
        policy = load_campaign_policy(CAMPAIGN_POLICY)
        for profile, replicate_index in (
            ("screening", 1),
            ("confirmation", 4),
            ("runner_up", 4),
        ):
            with self.subTest(profile=profile):
                spec = spec_for_campaign_profile(profile, replicate_index)
                self.assertEqual(
                    validate_run_spec_against_campaign(spec, policy),
                    spec,
                )

        self.assertEqual(
            load_run_spec_against_campaign(EXAMPLE_RUN_SPEC, CAMPAIGN_POLICY)[
                "campaign"
            ]["profile"],
            "screening",
        )

    def test_campaign_binding_rejects_policy_profile_and_protocol_drift(self) -> None:
        policy = load_campaign_policy(CAMPAIGN_POLICY)
        mutations = []

        bad_digest = valid_train_spec()
        bad_digest["campaign"]["policy_sha256"] = "f" * 64
        mutations.append(("policy_sha256", bad_digest))

        bad_count = valid_train_spec()
        bad_count["campaign"]["declared_seed_count"] = 3
        mutations.append(("declared_seed_count", bad_count))

        bad_index = valid_train_spec()
        bad_index["campaign"]["replicate_index"] = 2
        mutations.append(("replicate_index", bad_index))

        bad_tokens = valid_train_spec()
        bad_tokens["campaign"].update(
            {
                "profile": "confirmation",
                "contrast_role": "reference",
                "declared_seed_count": 5,
            }
        )
        mutations.append(("optimizer_visible", bad_tokens))

        bad_optimizer = valid_train_spec()
        bad_optimizer["optimizer"]["betas"] = [0.9, 0.999]
        mutations.append(("optimizer.betas", bad_optimizer))

        bad_dtype = valid_train_spec()
        bad_dtype["training_protocol"]["training_dtype"] = "fp16"
        mutations.append(("training_dtype", bad_dtype))

        bad_packing = valid_train_spec()
        bad_packing["training_protocol"]["packing"][
            "minimum_sequence_length"
        ] = 512
        mutations.append(("minimum_sequence_length", bad_packing))

        bad_learning_rate = valid_train_spec()
        bad_learning_rate["optimizer"]["parameter_groups"][0][
            "learning_rate"
        ] = 0.5
        mutations.append(("learning_rate", bad_learning_rate))

        for label, spec in mutations:
            with self.subTest(label=label):
                with self.assertRaises(CampaignRunValidationError):
                    validate_run_spec_against_campaign(spec, policy)

    def test_learning_rate_grid_is_selected_by_freezing_mode(self) -> None:
        policy = load_campaign_policy(CAMPAIGN_POLICY)

        side_only = valid_train_spec()
        side_only["optimizer"]["parameter_groups"][0]["role"] = "side_branch"
        side_only["optimizer"]["parameter_groups"][0]["name"] = "side_branch"
        side_only["optimizer"]["parameter_groups"][0]["learning_rate"] = 3e-4
        side_only["training_protocol"]["freezing"] = {
            "mode": "side_only",
            "trainable_parameters_sha256": "a" * 64,
            "schedule_sha256": None,
        }
        validate_run_spec_against_campaign(side_only, policy)

        wrong_side_rate = copy.deepcopy(side_only)
        wrong_side_rate["optimizer"]["parameter_groups"][0][
            "learning_rate"
        ] = 3e-5
        with self.assertRaisesRegex(CampaignRunValidationError, "learning-rate grid"):
            validate_run_spec_against_campaign(wrong_side_rate, policy)

        phased = copy.deepcopy(side_only)
        phased["training_protocol"]["freezing"] = {
            "mode": "phased",
            "trainable_parameters_sha256": "a" * 64,
            "schedule_sha256": "b" * 64,
        }
        phased["optimizer"]["parameter_groups"][0]["name"] = "side_branch"
        phased["optimizer"]["parameter_groups"][0]["role"] = "side_branch"
        phased["optimizer"]["parameter_groups"].append(
            {
                "name": "backbone",
                "role": "backbone",
                "learning_rate": 1e-5,
                "weight_decay": 0.1,
            }
        )
        validate_run_spec_against_campaign(phased, policy)

        no_backbone_rate = copy.deepcopy(phased)
        no_backbone_rate["optimizer"]["parameter_groups"][1][
            "learning_rate"
        ] = 1e-4
        with self.assertRaisesRegex(
            CampaignRunValidationError,
            "full_model.*learning-rate grid.*backbone",
        ):
            validate_run_spec_against_campaign(no_backbone_rate, policy)

    def test_frozen_campaign_requires_adaptation_not_pure_transform(self) -> None:
        spec = valid_compress_spec()
        self.assertEqual(validate_run_spec(spec), spec)
        with self.assertRaisesRegex(
            CampaignRunValidationError,
            "optimizer_visible.*campaign profile|optimizer.enabled",
        ):
            validate_run_spec_against_campaign(
                spec,
                load_campaign_policy(CAMPAIGN_POLICY),
            )


class RunSpecTests(unittest.TestCase):
    def test_valid_train_and_compress_specs(self) -> None:
        for spec in (
            valid_train_spec(),
            valid_compress_spec(),
            valid_factorize_spec(),
        ):
            with self.subTest(stage=spec["stage"]):
                validated = validate_run_spec(spec)
                self.assertEqual(validated, spec)
                self.assertIsNot(validated, spec)
                validated["model"]["repository"] = "changed"
                self.assertNotEqual(validated, spec)

    def test_prospective_contrast_role_is_phase_locked(self) -> None:
        screening = valid_train_spec()
        screening["campaign"]["contrast_role"] = "reference"
        confirmation = spec_for_campaign_profile("confirmation")
        confirmation["campaign"]["contrast_role"] = None

        for spec in (screening, confirmation):
            with self.subTest(profile=spec["campaign"]["profile"]):
                with self.assertRaisesRegex(
                    RunSpecValidationError, "campaign.contrast_role"
                ):
                    validate_run_spec(spec)

        comparison = spec_for_campaign_profile("runner_up")
        comparison["campaign"]["contrast_role"] = "comparison"
        self.assertEqual(validate_run_spec(comparison), comparison)

    def test_explicit_schema_load_hash_and_canonical_atomic_write(self) -> None:
        spec = valid_train_spec()
        reordered = dict(reversed(list(spec.items())))
        self.assertEqual(run_spec_sha256(spec), run_spec_sha256(reordered))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "run.json"
            returned = write_run_spec(
                path,
                spec,
                schema_path=ROOT / "run-spec.schema.json",
            )
            self.assertEqual(returned, path)
            self.assertEqual(path.read_bytes(), canonical_json_bytes(spec) + b"\n")
            self.assertEqual(load_run_spec(path), spec)

    def test_duplicate_keys_are_rejected_in_json_and_yaml(self) -> None:
        documents = {
            "duplicate.json": '{"schema_version":"1.0.0","schema_version":"1.0.0"}',
            "duplicate.yaml": "schema_version: 1.0.0\nschema_version: 1.0.0\n",
        }
        with tempfile.TemporaryDirectory() as directory:
            for filename, content in documents.items():
                with self.subTest(filename=filename):
                    path = Path(directory) / filename
                    path.write_text(content, encoding="utf-8")
                    with self.assertRaisesRegex(RunSpecValidationError, "duplicate"):
                        load_run_spec(path)

    def test_dense_sub_billion_and_immutable_input_identity_are_enforced(self) -> None:
        mutations = (
            ("model", "architecture", "moe"),
            ("model", "physical_parameters", 1_000_000_000),
            ("model", "revision", "main"),
            ("model", "checkpoint_sha256", "mutable"),
            ("model", "inspection_report_sha256", "uninspected"),
            ("tokenizer", "revision", "latest"),
            ("data", "revision", "working-tree"),
            ("execution", "container_image_digest", "latest"),
            ("execution", "verifier_revision", "main"),
        )
        for section, field, value in mutations:
            with self.subTest(path=f"{section}.{field}"):
                spec = valid_train_spec()
                spec[section][field] = value
                with self.assertRaises(RunSpecValidationError):
                    validate_run_spec(spec)

    def test_completed_record_evidence_is_not_part_of_run_spec(self) -> None:
        for section, field in ((None, "flops"), ("export", "artifact_sha256")):
            spec = valid_train_spec()
            if section is None:
                spec[field] = {"measured": 1.0}
            else:
                spec[section][field] = "f" * 64
            with self.subTest(field=field):
                with self.assertRaisesRegex(RunSpecValidationError, "additional property"):
                    validate_run_spec(spec)

    def test_capability_fractions_and_token_budgets_must_agree(self) -> None:
        spec = valid_train_spec()
        spec["capability_mixture"]["support"][0]["fraction"] = 0.1
        spec["capability_mixture"]["target"][0]["tokens"] -= 2
        spec["tokens"]["support"] -= 1
        with self.assertRaises(RunSpecValidationError) as raised:
            validate_run_spec(spec)
        message = str(raised.exception)
        self.assertIn("fractions must sum", message)
        self.assertIn("sum of target capability tokens", message)
        self.assertIn("target plus support", message)
        self.assertIn("match its fraction", message)

    def test_checkpoint_and_operator_selection_must_use_unsealed_splits(self) -> None:
        checkpoint = valid_train_spec()
        checkpoint["checkpoint"]["selection_split"] = "sealed-test"
        with self.assertRaisesRegex(RunSpecValidationError, "sealed split"):
            validate_run_spec(checkpoint)

        operator = valid_compress_spec()
        operator["operator"]["selection_split"] = "sealed-test"
        with self.assertRaisesRegex(RunSpecValidationError, "sealed split"):
            validate_run_spec(operator)

        missing = valid_train_spec()
        missing["checkpoint"]["selection_split"] = "missing"
        with self.assertRaisesRegex(RunSpecValidationError, "must name an entry"):
            validate_run_spec(missing)

    def test_split_roles_are_sealed_and_routed_by_lifecycle(self) -> None:
        checkpoint = valid_train_spec()
        checkpoint["checkpoint"]["selection_split"] = "training"
        with self.assertRaisesRegex(RunSpecValidationError, "shadow_validation"):
            validate_run_spec(checkpoint)

        mislabeled_test = valid_train_spec()
        mislabeled_test["data"]["splits"][3]["sealed"] = False
        with self.assertRaisesRegex(RunSpecValidationError, "must be True"):
            validate_run_spec(mislabeled_test)

        mislabeled_training = valid_train_spec()
        mislabeled_training["data"]["splits"][0]["sealed"] = True
        with self.assertRaisesRegex(RunSpecValidationError, "must be False"):
            validate_run_spec(mislabeled_training)

        teacher = valid_train_spec()
        enable_teacher(teacher)
        teacher["teacher"]["source_split"] = "shadow-validation"
        with self.assertRaisesRegex(RunSpecValidationError, "role 'training'"):
            validate_run_spec(teacher)

        operator = valid_compress_spec()
        operator["operator"]["selection_split"] = "shadow-validation"
        with self.assertRaisesRegex(
            RunSpecValidationError,
            "method_development.*operator_selection",
        ):
            validate_run_spec(operator)

    def test_teacher_plan_is_all_or_nothing_and_distill_requires_it(self) -> None:
        enabled = valid_train_spec()
        enable_teacher(enabled)
        enabled["operator"].update({"mechanism": "distill", "family": "sequence_distill"})
        validate_run_spec(enabled)

        compressed = valid_compress_spec()
        enable_teacher(compressed)
        compressed["operator"].update(
            {
                "mechanism": "distill",
                "family": "smaller_student_sequence_distill",
                "selection_strategy": "none",
                "selection_split": None,
                "selection_manifest_sha256": None,
                "bit_allocation": [],
            }
        )
        compressed["optimizer"] = copy.deepcopy(enabled["optimizer"])
        compressed["training_protocol"] = copy.deepcopy(enabled["training_protocol"])
        compressed["tokens"]["optimizer_visible"] = 2_000_000
        compressed["tokens"]["selection_visible"] = 0
        compressed["compute_budget"]["selection_max_flops"] = 0.0
        compressed["compute_budget"]["optimization_max_flops"] = 200.0
        compressed["compute_budget"]["total_max_flops"] += 190.0
        validate_run_spec(compressed)

        disabled = copy.deepcopy(enabled)
        disabled["teacher"]["enabled"] = False
        with self.assertRaises(RunSpecValidationError) as raised:
            validate_run_spec(disabled)
        self.assertIn("must be null", str(raised.exception))
        self.assertIn("must be true for distill", str(raised.exception))

        sealed = copy.deepcopy(enabled)
        sealed["teacher"]["source_split"] = "sealed-test"
        with self.assertRaisesRegex(RunSpecValidationError, "cannot use a sealed split"):
            validate_run_spec(sealed)

    def test_operator_mechanism_requires_matching_payload_and_stage(self) -> None:
        recycle = valid_recycle_spec()
        validate_run_spec(recycle)

        missing = copy.deepcopy(recycle)
        missing["operator"]["structural_indices"] = []
        with self.assertRaisesRegex(RunSpecValidationError, "required for recycle"):
            validate_run_spec(missing)

        wrong_stage = valid_compress_spec()
        wrong_stage["stage"] = "train"
        with self.assertRaisesRegex(RunSpecValidationError, "requires stage 'compress'"):
            validate_run_spec(wrong_stage)

    def test_factorization_is_typed_low_rank_and_compression_only(self) -> None:
        factorize = valid_factorize_spec()
        validate_run_spec(factorize)

        wrong_stage = copy.deepcopy(factorize)
        wrong_stage["stage"] = "train"
        with self.assertRaisesRegex(RunSpecValidationError, "requires stage 'compress'"):
            validate_run_spec(wrong_stage)

        no_factor = copy.deepcopy(factorize)
        no_factor["operator"]["factorizations"] = []
        with self.assertRaisesRegex(RunSpecValidationError, "required for factorize"):
            validate_run_spec(no_factor)

        noncompressing_rank = copy.deepcopy(factorize)
        noncompressing_rank["operator"]["factorizations"][0]["rank"] = 512
        with self.assertRaisesRegex(
            RunSpecValidationError,
            "must use fewer parameters than the dense matrix",
        ):
            validate_run_spec(noncompressing_rank)

        inconsistent_export = copy.deepcopy(factorize)
        inconsistent_export["export"]["planned_physical_parameters"] -= 1
        inconsistent_export["export"]["maximum_weight_bytes"] -= 2
        with self.assertRaisesRegex(
            RunSpecValidationError,
            "committed low-rank factorization savings",
        ):
            validate_run_spec(inconsistent_export)

        missing_layer = copy.deepcopy(factorize)
        missing_layer["operator"]["factorizations"][0]["layer"] = None
        with self.assertRaisesRegex(RunSpecValidationError, "layer.*required"):
            validate_run_spec(missing_layer)

        duplicate = copy.deepcopy(factorize)
        duplicate["operator"]["factorizations"].append(
            copy.deepcopy(duplicate["operator"]["factorizations"][0])
        )
        with self.assertRaisesRegex(
            RunSpecValidationError,
            "duplicate tensor_name",
        ):
            validate_run_spec(duplicate)

    def test_operator_payloads_are_exclusive_and_hybrid_is_quantized_xor(self) -> None:
        factorization = copy.deepcopy(
            valid_factorize_spec()["operator"]["factorizations"]
        )
        structural = [
            {"component": "ffn_channel", "layer": 0, "indices": [1, 2, 3]}
        ]

        hybrid_structural = valid_compress_spec()
        hybrid_structural["operator"].update(
            {
                "mechanism": "hybrid",
                "family": "prune_then_quantize",
                "structural_indices": structural,
                "factorizations": [],
            }
        )
        validate_run_spec(hybrid_structural)

        hybrid_factorized = valid_compress_spec()
        hybrid_factorized["operator"].update(
            {
                "mechanism": "hybrid",
                "family": "factorize_then_quantize",
                "structural_indices": [],
                "factorizations": factorization,
            }
        )
        hybrid_factorized["export"]["planned_physical_parameters"] = 599_250_432
        validate_run_spec(hybrid_factorized)

        no_quantization = copy.deepcopy(hybrid_structural)
        no_quantization["operator"]["bit_allocation"] = []
        with self.assertRaisesRegex(RunSpecValidationError, "required for hybrid"):
            validate_run_spec(no_quantization)

        no_architecture = copy.deepcopy(hybrid_structural)
        no_architecture["operator"]["structural_indices"] = []
        with self.assertRaisesRegex(RunSpecValidationError, "XOR"):
            validate_run_spec(no_architecture)

        both_architectures = copy.deepcopy(hybrid_structural)
        both_architectures["operator"]["factorizations"] = factorization
        with self.assertRaisesRegex(RunSpecValidationError, "XOR"):
            validate_run_spec(both_architectures)

        irrelevant_payloads = []
        baseline = valid_train_spec()
        baseline["operator"]["factorizations"] = factorization
        irrelevant_payloads.append(("baseline", baseline))

        recycle = valid_recycle_spec()
        recycle["operator"]["factorizations"] = factorization
        irrelevant_payloads.append(("recycle", recycle))

        quantize = valid_compress_spec()
        quantize["operator"]["factorizations"] = factorization
        irrelevant_payloads.append(("quantize", quantize))

        factorize = valid_factorize_spec()
        factorize["operator"]["bit_allocation"] = [
            {"component": "all_weights", "layer": None, "bits": 4.0}
        ]
        irrelevant_payloads.append(("factorize", factorize))

        for mechanism, spec in irrelevant_payloads:
            with self.subTest(mechanism=mechanism):
                with self.assertRaisesRegex(RunSpecValidationError, mechanism):
                    validate_run_spec(spec)

    def test_selection_strategy_controls_data_and_compute_accounting(self) -> None:
        no_selection = valid_train_spec()
        no_selection["tokens"]["selection_visible"] = 1
        no_selection["compute_budget"]["selection_max_flops"] = 1.0
        no_selection["compute_budget"]["total_max_flops"] += 1.0
        with self.assertRaises(RunSpecValidationError) as raised:
            validate_run_spec(no_selection)
        self.assertIn("must be zero for none selection", str(raised.exception))

        random = valid_recycle_spec()
        random["operator"].update(
            {
                "selection_strategy": "random",
                "selection_split": None,
            }
        )
        random["tokens"]["selection_visible"] = 0
        random["compute_budget"]["selection_max_flops"] = 0.0
        random["compute_budget"]["total_max_flops"] -= 10.0
        validate_run_spec(random)

        missing_random_manifest = copy.deepcopy(random)
        missing_random_manifest["operator"]["selection_manifest_sha256"] = None
        with self.assertRaisesRegex(RunSpecValidationError, "required for random"):
            validate_run_spec(missing_random_manifest)

        uniform = valid_compress_spec()
        uniform["operator"].update(
            {
                "selection_strategy": "uniform",
                "selection_split": None,
                "selection_manifest_sha256": None,
            }
        )
        uniform["tokens"]["selection_visible"] = 0
        uniform["compute_budget"]["selection_max_flops"] = 0.0
        uniform["compute_budget"]["total_max_flops"] -= 10.0
        validate_run_spec(uniform)

        task_agnostic = valid_recycle_spec()
        task_agnostic["operator"].update(
            {
                "selection_strategy": "task_agnostic",
                "selection_split": "training",
            }
        )
        validate_run_spec(task_agnostic)

        wrong_role = copy.deepcopy(task_agnostic)
        wrong_role["operator"]["selection_split"] = "operator-selection"
        with self.assertRaisesRegex(RunSpecValidationError, "task_agnostic selection"):
            validate_run_spec(wrong_role)

        zero_target_aware = valid_recycle_spec()
        zero_target_aware["tokens"]["selection_visible"] = 0
        zero_target_aware["compute_budget"]["selection_max_flops"] = 0.0
        zero_target_aware["compute_budget"]["total_max_flops"] -= 10.0
        with self.assertRaises(RunSpecValidationError) as raised:
            validate_run_spec(zero_target_aware)
        self.assertIn("must be positive for target_aware selection", str(raised.exception))

    def test_optimizer_and_compute_budget_are_explicit_and_consistent(self) -> None:
        spec = valid_train_spec()
        spec["optimizer"]["enabled"] = False
        spec["compute_budget"]["total_max_flops"] += 1.0
        with self.assertRaises(RunSpecValidationError) as raised:
            validate_run_spec(spec)
        message = str(raised.exception)
        self.assertIn("must be null when optimizer is disabled", message)
        self.assertIn("requires an optimizer", message)
        self.assertIn("sum of component budgets", message)

        missing_choice = valid_train_spec()
        del missing_choice["optimizer"]["gradient_clip"]
        with self.assertRaisesRegex(RunSpecValidationError, "required property"):
            validate_run_spec(missing_choice)

        partial_mixture = valid_train_spec()
        partial_mixture["tokens"]["optimizer_visible"] -= 1
        with self.assertRaisesRegex(
            RunSpecValidationError,
            "must equal mixture_visible",
        ):
            validate_run_spec(partial_mixture)

    def test_parameter_group_roles_bind_to_freezing_modes(self) -> None:
        missing_role = valid_train_spec()
        del missing_role["optimizer"]["parameter_groups"][0]["role"]
        with self.assertRaisesRegex(RunSpecValidationError, "role.*required property"):
            validate_run_spec(missing_role)

        wrong_full_model = valid_train_spec()
        wrong_full_model["optimizer"]["parameter_groups"][0]["role"] = "backbone"
        with self.assertRaisesRegex(RunSpecValidationError, "full_model.*all_trainable"):
            validate_run_spec(wrong_full_model)

        side_only = valid_train_spec()
        side_only["training_protocol"]["freezing"] = {
            "mode": "side_only",
            "trainable_parameters_sha256": "a" * 64,
            "schedule_sha256": None,
        }
        side_only["optimizer"]["parameter_groups"][0]["role"] = "side_branch"
        side_only["optimizer"]["parameter_groups"][0]["name"] = "side_branch"
        validate_run_spec(side_only)

        wrong_side = copy.deepcopy(side_only)
        wrong_side["optimizer"]["parameter_groups"][0]["role"] = "all_trainable"
        with self.assertRaisesRegex(RunSpecValidationError, "side_only.*side_branch"):
            validate_run_spec(wrong_side)

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
        validate_run_spec(phased)

        missing_backbone = copy.deepcopy(phased)
        missing_backbone["optimizer"]["parameter_groups"].pop()
        with self.assertRaisesRegex(RunSpecValidationError, "phased.*backbone"):
            validate_run_spec(missing_backbone)

        ambiguous = copy.deepcopy(phased)
        ambiguous["optimizer"]["parameter_groups"][0]["role"] = "all_trainable"
        with self.assertRaisesRegex(RunSpecValidationError, "phased permits only"):
            validate_run_spec(ambiguous)

    def test_training_protocol_eliminates_hidden_execution_defaults(self) -> None:
        bad_batch = valid_train_spec()
        bad_batch["training_protocol"]["effective_batch_size"] = 7
        with self.assertRaisesRegex(RunSpecValidationError, "must equal microbatch_size"):
            validate_run_spec(bad_batch)

        bad_packing = valid_train_spec()
        bad_packing["training_protocol"]["packing"]["strategy"] = "none"
        with self.assertRaisesRegex(RunSpecValidationError, "cannot be 'none'"):
            validate_run_spec(bad_packing)

        bad_kl = valid_train_spec()
        bad_kl["training_protocol"]["loss"].update(
            {
                "objective": "causal_cross_entropy_with_kl",
                "kl_weight": 0.0,
                "anchor_model_sha256": None,
            }
        )
        with self.assertRaisesRegex(RunSpecValidationError, "positive kl_weight"):
            validate_run_spec(bad_kl)

        valid_kl = valid_train_spec()
        valid_kl["training_protocol"]["loss"].update(
            {
                "objective": "causal_cross_entropy_with_kl",
                "kl_weight": 0.2,
                "anchor_model_sha256": "f" * 64,
            }
        )
        validate_run_spec(valid_kl)

        bad_freeze = valid_train_spec()
        bad_freeze["training_protocol"]["freezing"].update(
            {
                "mode": "side_only",
                "trainable_parameters_sha256": None,
            }
        )
        with self.assertRaisesRegex(RunSpecValidationError, "side_only requires"):
            validate_run_spec(bad_freeze)

        stale_disabled = valid_compress_spec()
        stale_disabled["training_protocol"]["training_dtype"] = "bf16"
        with self.assertRaisesRegex(
            RunSpecValidationError,
            "must be null when optimizer is disabled",
        ):
            validate_run_spec(stale_disabled)

    def test_export_intent_proves_fixed_size_or_real_compression(self) -> None:
        fixed = valid_train_spec()
        fixed["export"]["planned_average_weight_bits"] = 8.0
        with self.assertRaisesRegex(RunSpecValidationError, "fixed_size intent"):
            validate_run_spec(fixed)

        unchanged = valid_compress_spec()
        unchanged["export"].update(
            {
                "planned_average_weight_bits": 16.0,
                "maximum_weight_bytes": 1_200_000_000,
                "maximum_bundle_bytes": 1_210_000_000,
            }
        )
        with self.assertRaisesRegex(RunSpecValidationError, "strictly reduce"):
            validate_run_spec(unchanged)

        growth = valid_compress_spec()
        growth["export"]["planned_physical_parameters"] += 1
        with self.assertRaisesRegex(RunSpecValidationError, "cannot exceed"):
            validate_run_spec(growth)

        impossible_source = valid_train_spec()
        impossible_source["model"]["checkpoint_weight_bytes"] = 1
        impossible_source["export"]["maximum_weight_bytes"] = 1
        with self.assertRaisesRegex(
            RunSpecValidationError,
            "checkpoint_weight_bytes.*cannot encode|maximum_weight_bytes.*cannot encode",
        ):
            validate_run_spec(impossible_source)

        impossible_export = valid_compress_spec()
        impossible_export["export"]["maximum_weight_bytes"] = 1
        with self.assertRaisesRegex(
            RunSpecValidationError,
            "maximum_weight_bytes.*cannot encode",
        ):
            validate_run_spec(impossible_export)

        impossible_source_bundle = valid_train_spec()
        impossible_source_bundle["model"]["checkpoint_bundle_bytes"] = 1
        with self.assertRaisesRegex(
            RunSpecValidationError,
            "checkpoint_weight_bytes.*checkpoint_bundle_bytes",
        ):
            validate_run_spec(impossible_source_bundle)

        impossible_export_bundle = valid_compress_spec()
        impossible_export_bundle["export"]["maximum_bundle_bytes"] = 1
        with self.assertRaisesRegex(
            RunSpecValidationError,
            "maximum_weight_bytes.*maximum_bundle_bytes",
        ):
            validate_run_spec(impossible_export_bundle)

        external_tokenizer = valid_train_spec()
        external_tokenizer["export"]["include_tokenizer"] = False
        with self.assertRaisesRegex(RunSpecValidationError, "include_tokenizer"):
            validate_run_spec(external_tokenizer)

        vocabulary_only = valid_compress_spec()
        vocabulary_only["export"].update(
            {
                "planned_average_weight_bits": 16.0,
                "maximum_weight_bytes": 1_200_000_000,
                "maximum_bundle_bytes": 1_210_000_000,
                "planned_vocabulary_size": 151_935,
            }
        )
        vocabulary_only["tokenizer"]["derived_vocabulary_mapping_sha256"] = "e" * 64
        with self.assertRaisesRegex(
            RunSpecValidationError,
            "vocabulary reduction alone",
        ):
            validate_run_spec(vocabulary_only)

        missing_mapping = valid_compress_spec()
        missing_mapping["export"]["planned_vocabulary_size"] -= 1
        with self.assertRaisesRegex(
            RunSpecValidationError,
            "derived_vocabulary_mapping_sha256.*required",
        ):
            validate_run_spec(missing_mapping)
        missing_mapping["tokenizer"]["derived_vocabulary_mapping_sha256"] = "e" * 64
        validate_run_spec(missing_mapping)

    def test_structural_indices_allocations_and_tie_breakers_are_unique(self) -> None:
        spec = valid_compress_spec()
        spec["operator"]["bit_allocation"].append(
            {"component": "all_weights", "layer": None, "bits": 8.0}
        )
        spec["checkpoint"]["tie_breakers"].append("weight_bytes")
        with self.assertRaises(RunSpecValidationError) as raised:
            validate_run_spec(spec)
        self.assertIn("duplicate component/layer", str(raised.exception))
        self.assertIn("duplicate value", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
