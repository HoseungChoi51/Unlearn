from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

from cbds.campaign_registry import (
    CAMPAIGN_REGISTRY_SCHEMA_VERSION,
    CampaignRegistryValidationError,
    campaign_backbone_identity_sha256,
    campaign_pairing_commitments_sha256,
    campaign_registry_sha256,
    campaign_run_protocol_sha256,
    load_campaign_registry,
    validate_campaign_registry,
    write_campaign_registry,
)
from cbds.evaluation_specs import (
    section_policy_sha256,
    task_commitment_set_sha256,
    validate_task_result_collection_against_evaluation_spec,
    validate_evaluation_spec,
)
from cbds.manifests import (
    _validate_schema,
    canonical_json_bytes,
    load_document,
    value_sha256,
)
from cbds.run_specs import (
    campaign_policy_sha256,
    load_campaign_policy,
    run_spec_sha256,
)
from tests.test_manifests import completed_record_for_spec
from tests.test_evaluation_specs import (
    bound_static_result,
    contrast_plan,
    valid_confirmatory_spec,
    valid_static_spec,
)
from tests.test_run_specs import (
    CAMPAIGN_POLICY,
    enable_teacher,
    spec_for_campaign_profile,
    valid_recycle_spec,
)


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "campaign-registry.schema.json"
PACKAGED_SCHEMA = ROOT / "src" / "cbds" / "schemas" / SCHEMA.name
EXAMPLE = ROOT / "examples" / "campaign-registry.example.json"
ARM_IDS = ("dense-sft", "recycle-ffn")
SEED_FIELDS = (
    "model_initialization",
    "data_order",
    "training",
    "operator_selection",
    "evaluation",
)


def _operator_for_arm(arm_id: str) -> dict:
    if arm_id == "dense-sft":
        return {
            "mechanism": "baseline",
            "family": "dense_sft",
            "configuration_sha256": "4" * 64,
        }
    recycle = valid_recycle_spec()["operator"]
    return {
        field: recycle[field]
        for field in ("mechanism", "family", "configuration_sha256")
    }


def _run_spec(profile: str, replicate: int, arm_id: str) -> dict:
    spec = spec_for_campaign_profile(profile, replicate)
    short_profile = {
        "screening": "screen",
        "confirmation": "confirm",
        "runner_up": "runner",
    }[profile]
    short_arm = "dense" if arm_id == "dense-sft" else "recycle"
    spec["run_id"] = f"{short_profile}-{short_arm}-{replicate:04d}"
    base_seed = {"screening": 100, "confirmation": 200, "runner_up": 300}[
        profile
    ]
    spec["seeds"] = {
        field: base_seed + replicate * 10 + field_index
        for field_index, field in enumerate(SEED_FIELDS)
    }
    if arm_id == "recycle-ffn":
        recycle = valid_recycle_spec()
        spec["operator"] = copy.deepcopy(recycle["operator"])
        spec["tokens"]["selection_visible"] = recycle["tokens"][
            "selection_visible"
        ]
        spec["compute_budget"]["selection_max_flops"] = recycle[
            "compute_budget"
        ]["selection_max_flops"]
        spec["compute_budget"]["total_max_flops"] += recycle[
            "compute_budget"
        ]["selection_max_flops"]
    if profile != "screening":
        spec["campaign"]["contrast_role"] = (
            "reference" if arm_id == "dense-sft" else "comparison"
        )
    if profile == "runner_up":
        spec["model"].update(
            {
                "repository": "HuggingFaceTB/SmolLM2-360M",
                "revision": "8" * 40,
                "checkpoint_sha256": "8" * 64,
                "inspection_report_sha256": "9" * 64,
            }
        )
        spec["tokenizer"].update(
            {
                "repository": "HuggingFaceTB/SmolLM2-360M",
                "revision": "8" * 40,
                "source_sha256": "9" * 64,
            }
        )
    return spec


def campaign_documents(
    profiles: tuple[str, ...] = ("screening",),
) -> tuple[dict, dict[str, dict], dict[str, dict]]:
    policy = load_campaign_policy(CAMPAIGN_POLICY)
    specs: dict[str, dict] = {}
    records: dict[str, dict] = {}
    for profile in profiles:
        count = 2 if profile == "screening" else 5
        for arm_id in ARM_IDS:
            for replicate in range(count):
                spec = _run_spec(profile, replicate, arm_id)
                specs[spec["run_id"]] = spec
                records[spec["run_id"]] = completed_record_for_spec(spec)
    return policy, specs, records


def _arm_run_protocol(
    specs: dict[str, dict], profile: str, arm_id: str
) -> dict:
    mechanism = "baseline" if arm_id == "dense-sft" else "recycle"
    representative = min(
        (
            spec
            for spec in specs.values()
            if spec["campaign"]["profile"] == profile
            and spec["operator"]["mechanism"] == mechanism
        ),
        key=lambda spec: spec["campaign"]["replicate_index"],
    )
    return {
        "profile": profile,
        "run_protocol_sha256": campaign_run_protocol_sha256(representative),
    }


def _completed_pairing_hash(
    specs: dict[str, dict], records: dict[str, dict], profile: str
) -> str:
    representative = min(
        (
            spec
            for spec in specs.values()
            if spec["campaign"]["profile"] == profile
            and spec["operator"]["mechanism"] == "baseline"
        ),
        key=lambda spec: spec["campaign"]["replicate_index"],
    )
    return value_sha256(
        {
            field: copy.deepcopy(
                records[representative["run_id"]]["teacher"][field]
            )
            for field in (
                "enabled",
                "repository",
                "revision",
                "verified_corpus_sha256",
            )
        }
    )


def screening_registry(
    policy: dict, specs: dict[str, dict], records: dict[str, dict]
) -> dict:
    first = specs["screen-dense-0000"]
    registry = {
        "schema_version": CAMPAIGN_REGISTRY_SCHEMA_VERSION,
        "registry_id": "synthetic-campaign-registry-0001",
        "created_at": "2026-07-14T21:00:00+09:00",
        "campaign_policy": {
            "policy_id": policy["policy_id"],
            "schema_version": policy["schema_version"],
            "sha256": campaign_policy_sha256(policy),
        },
        "scope": {
            "arm_roster_authority": "registry_declaration",
            "contrast_role_authority": (
                "prospective_run_spec_campaign_fields"
            ),
            "promotion_validation": "declared_link_integrity_only",
            "backbone_selection_validation": "declared_identity_only",
            "evaluation_suite_roster_authority": "registry_declaration",
            "training_seed_set_hash_algorithm": (
                "canonical-json-sha256-of-replicate-index-and-all-run-seeds"
            ),
        },
        "arms": [
            {
                "arm_id": "dense-sft",
                "label": "Dense terminal SFT",
                "operator": _operator_for_arm("dense-sft"),
                "run_protocols": [
                    _arm_run_protocol(specs, "screening", "dense-sft")
                ],
                "source_arm_id": None,
            },
            {
                "arm_id": "recycle-ffn",
                "label": "Target-aware FFN recycle",
                "operator": _operator_for_arm("recycle-ffn"),
                "run_protocols": [
                    _arm_run_protocol(specs, "screening", "recycle-ffn")
                ],
                "source_arm_id": "dense-sft",
            },
        ],
        "cohorts": [
            {
                "cohort_id": "screen-primary",
                "profile": "screening",
                "analysis_lane": None,
                "backbone_role": "primary",
                "backbone_label": "Qwen3 0.6B synthetic primary",
                "backbone_identity_sha256": campaign_backbone_identity_sha256(
                    first
                ),
                "pairing_commitments_sha256": (
                    campaign_pairing_commitments_sha256(first)
                ),
                "completed_pairing_sha256": _completed_pairing_hash(
                    specs, records, "screening"
                ),
                "arm_ids": list(ARM_IDS),
                "contrast": None,
                "source_cohort_id": None,
                "promotion_links": [],
                "evaluation_cubes": [],
            }
        ],
        "runs": [],
    }
    for spec in specs.values():
        if spec["campaign"]["profile"] != "screening":
            continue
        arm_id = (
            "dense-sft"
            if spec["operator"]["mechanism"] == "baseline"
            else "recycle-ffn"
        )
        run_id = spec["run_id"]
        registry["runs"].append(
            {
                "run_id": run_id,
                "arm_id": arm_id,
                "cohort_id": "screen-primary",
                "profile": "screening",
                "replicate_index": spec["campaign"]["replicate_index"],
                "run_spec_sha256": run_spec_sha256(spec),
                "completed_record_sha256": value_sha256(records[run_id]),
                "evaluations": [],
            }
        )
    registry["runs"].sort(
        key=lambda entry: (
            entry["cohort_id"],
            entry["arm_id"],
            entry["replicate_index"],
            entry["run_id"],
        )
    )
    return registry


def _confirmatory_template() -> dict:
    """Adapt the shared synthetic fixture to the current frozen P1 contract."""

    spec = valid_confirmatory_spec()
    commitments = spec["task_commitments"]["commitments"]
    for commitment in commitments:
        commitment.setdefault(
            "ordered_fixture_ids_sha256",
            value_sha256({"ordered_fixture_sequence": commitment["prompt_id"]}),
        )
    spec["task_commitments"]["commitment_set_sha256"] = (
        task_commitment_set_sha256(commitments)
    )
    spec["artifact"].setdefault("training_seed", 0)
    spec["execution"].setdefault(
        "sandbox_measurement_method", "cgroup-v2-procfs-rusage-v1"
    )
    spec["execution"].setdefault(
        "sandbox_measurement_implementation_sha256", "1" * 64
    )
    analysis = spec["analysis_plan"]
    analysis.pop("confidence_level", None)
    analysis.update(
        {
            "analysis_code_revision": "1" * 40,
            "analysis_code_sha256": "2" * 64,
            "seed_evidence_scope": "per_artifact_only",
            "metric_unit": "proportion",
            "points_to_proportion_divisor": 100,
            "bootstrap": {
                "method": "crossed_seed_task_percentile_bootstrap",
                "resamples": 1_000,
                "random_seed": 31,
                "percentile_interpolation": "linear_r7",
                "resampling_unit": "semantic_task",
                "fixtures_nested_within_task": True,
                "training_seed_crossed_with_task": True,
            },
            "randomization_test": {
                "method": "paired_sign_flip_randomization",
                "unit": "task",
                "alternative": "two_sided",
                "exact_max_units": 20,
                "monte_carlo_draws": 1_000,
                "random_seed": 32,
            },
            "multiplicity_correction": {
                "p_values": "holm_step_down",
                "confidence_intervals": "bonferroni_simultaneous",
                "family_size": 2,
                "family_confidence_level": 0.95,
                "per_contrast_confidence_level": 0.975,
            },
        }
    )
    thresholds = analysis["success_thresholds"]
    if "adjusted_lower_bound_above_zero" in thresholds:
        thresholds["simultaneous_lower_bound_above_zero"] = thresholds.pop(
            "adjusted_lower_bound_above_zero"
        )
    analysis["policy_sha256"] = section_policy_sha256(analysis)
    return validate_evaluation_spec(spec)


def _seed_records_for_profile(specs: dict[str, dict], profile: str) -> list[dict]:
    selected = sorted(
        (
            spec
            for spec in specs.values()
            if spec["campaign"]["profile"] == profile
            and spec["operator"]["mechanism"] == "baseline"
        ),
        key=lambda spec: spec["campaign"]["replicate_index"],
    )
    return [
        {
            "replicate_index": spec["campaign"]["replicate_index"],
            "seeds": copy.deepcopy(spec["seeds"]),
        }
        for spec in selected
    ]


def confirmation_registry(
    policy: dict,
    specs: dict[str, dict],
    records: dict[str, dict],
) -> tuple[dict, dict[str, dict]]:
    registry = screening_registry(policy, specs, records)
    first = specs["confirm-dense-0000"]
    seed_records = _seed_records_for_profile(specs, "confirmation")
    seed_set_hash = value_sha256(seed_records)
    contrast = contrast_plan("dense-sft", "recycle-ffn")
    template = _confirmatory_template()
    evaluations: dict[str, dict] = {}

    cohort = {
        "cohort_id": "confirm-primary",
        "profile": "confirmation",
        "analysis_lane": "fixed_size",
        "backbone_role": "primary",
        "backbone_label": "Qwen3 0.6B synthetic primary",
        "backbone_identity_sha256": campaign_backbone_identity_sha256(first),
        "pairing_commitments_sha256": campaign_pairing_commitments_sha256(
            first
        ),
        "completed_pairing_sha256": _completed_pairing_hash(
            specs, records, "confirmation"
        ),
        "arm_ids": list(ARM_IDS),
        "contrast": copy.deepcopy(contrast),
        "source_cohort_id": "screen-primary",
        "promotion_links": [
            {"arm_id": arm_id, "source_arm_id": arm_id}
            for arm_id in ARM_IDS
        ],
        "evaluation_cubes": [],
    }
    registry["cohorts"].append(cohort)
    registry["cohorts"].sort(key=lambda entry: entry["cohort_id"])
    for arm in registry["arms"]:
        arm["run_protocols"].append(
            _arm_run_protocol(specs, "confirmation", arm["arm_id"])
        )

    for spec in specs.values():
        if spec["campaign"]["profile"] != "confirmation":
            continue
        run_id = spec["run_id"]
        record = records[run_id]
        arm_id = (
            "dense-sft"
            if spec["operator"]["mechanism"] == "baseline"
            else "recycle-ffn"
        )
        evaluation = copy.deepcopy(template)
        evaluation_id = f"evaluation-{run_id}"
        evaluation["evaluation_id"] = evaluation_id
        exported = record["export"]
        evaluation["artifact"].update(
            {
                "artifact_id": f"artifact-{run_id}",
                "architecture": exported["architecture"],
                "training_seed": record["seeds"]["training"],
                "physical_parameters": exported["physical_parameters"],
                "format": exported["format"],
                "artifact_sha256": exported["artifact_sha256"],
                "bundle_sha256": exported["bundle_sha256"],
                "tokenizer_sha256": exported["tokenizer_sha256"],
                "completed_run_id": run_id,
                "completed_experiment_record_sha256": value_sha256(record),
                "inspection_report_sha256": exported[
                    "inspection_report_sha256"
                ],
            }
        )
        analysis = evaluation["analysis_plan"]
        analysis["training_seed_set_sha256"] = seed_set_hash
        analysis["contrast"] = copy.deepcopy(contrast)
        analysis["policy_sha256"] = section_policy_sha256(analysis)
        evaluation = validate_evaluation_spec(evaluation)
        evaluations[evaluation_id] = evaluation
        registry["runs"].append(
            {
                "run_id": run_id,
                "arm_id": arm_id,
                "cohort_id": "confirm-primary",
                "profile": "confirmation",
                "replicate_index": spec["campaign"]["replicate_index"],
                "run_spec_sha256": run_spec_sha256(spec),
                "completed_record_sha256": value_sha256(record),
                "evaluations": [
                    {
                        "cube_id": "sealed-id-primary",
                        "evaluation_id": evaluation_id,
                        "evaluation_spec_sha256": value_sha256(evaluation),
                        "task_result_collection_sha256": None,
                        "task_result_record_count": 0,
                    }
                ],
            }
        )
    registry["runs"].sort(
        key=lambda entry: (
            entry["cohort_id"],
            entry["arm_id"],
            entry["replicate_index"],
            entry["run_id"],
        )
    )
    confirmation_entries = [
        entry
        for entry in registry["runs"]
        if entry["cohort_id"] == "confirm-primary"
    ]
    cube_projection = {
        "cube_id": "sealed-id-primary",
        "cohort_id": "confirm-primary",
        "profile": "confirmation",
        "arm_ids": list(ARM_IDS),
        "contrast": copy.deepcopy(contrast),
        "training_seeds": seed_records,
        "task_count": template["benchmark"]["task_count"],
        "task_commitment_set_sha256": template["task_commitments"][
            "commitment_set_sha256"
        ],
        "bindings": [
            {
                "arm_id": entry["arm_id"],
                "replicate_index": entry["replicate_index"],
                "run_id": entry["run_id"],
                "seeds": copy.deepcopy(specs[entry["run_id"]]["seeds"]),
                "evaluation_id": entry["evaluations"][0]["evaluation_id"],
                "evaluation_spec_sha256": entry["evaluations"][0][
                    "evaluation_spec_sha256"
                ],
                "task_result_collection_sha256": None,
            }
            for entry in confirmation_entries
        ],
    }
    cohort["evaluation_cubes"] = [{
        "cube_id": "sealed-id-primary",
        "benchmark_id": template["benchmark"]["benchmark_id"],
        "benchmark_split_sha256": template["benchmark"]["split"]["sha256"],
        "task_commitment_set_sha256": template["task_commitments"][
            "commitment_set_sha256"
        ],
        "task_count": template["benchmark"]["task_count"],
        "training_seed_count": 5,
        "training_seed_set_sha256": seed_set_hash,
        "ordered_arm_roles_sha256": contrast["ordered_arm_roles_sha256"],
        "paired_cube_sha256": value_sha256(cube_projection),
        "result_coverage": "evaluation_specs_only",
    }]
    return registry, evaluations


class CampaignRegistrySchemaTests(unittest.TestCase):
    def test_root_packaged_schema_parity_and_strict_objects(self) -> None:
        self.assertEqual(SCHEMA.read_bytes(), PACKAGED_SCHEMA.read_bytes())
        schema = load_document(SCHEMA)
        self.assertEqual(
            schema["properties"]["schema_version"]["const"],
            CAMPAIGN_REGISTRY_SCHEMA_VERSION,
        )

        def visit(node: object) -> None:
            if isinstance(node, dict):
                if node.get("type") == "object" and "properties" in node:
                    self.assertFalse(node.get("additionalProperties", True))
                    self.assertEqual(
                        set(node["properties"]), set(node.get("required", []))
                    )
                for value in node.values():
                    visit(value)
            elif isinstance(node, list):
                for value in node:
                    visit(value)

        visit(schema)

    def test_schema_is_valid_draft_2020_12(self) -> None:
        try:
            from jsonschema import Draft202012Validator
        except ImportError:  # pragma: no cover - optional schema test dependency
            self.skipTest("jsonschema is not installed")
        Draft202012Validator.check_schema(load_document(SCHEMA))

    def test_synthetic_example_is_shape_valid_but_not_result_evidence(self) -> None:
        _validate_schema(load_document(EXAMPLE), load_document(SCHEMA))
        example = load_document(EXAMPLE)
        self.assertTrue(
            all(not entry["evaluations"] for entry in example["runs"])
        )
        self.assertEqual(
            example["scope"]["promotion_validation"],
            "declared_link_integrity_only",
        )

    def test_external_schema_cannot_weaken_frozen_contract(self) -> None:
        policy, specs, records = campaign_documents()
        registry = screening_registry(policy, specs, records)
        schema = load_document(SCHEMA)
        schema["additionalProperties"] = True
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "weakened.schema.json"
            path.write_text(json.dumps(schema), encoding="utf-8")
            with self.assertRaisesRegex(
                CampaignRegistryValidationError, "frozen packaged"
            ):
                validate_campaign_registry(
                    registry,
                    policy,
                    specs,
                    records,
                    registry_schema_path=path,
                )


class CampaignRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy, self.specs, self.records = campaign_documents()
        self.registry = screening_registry(
            self.policy, self.specs, self.records
        )

    def test_complete_screening_registry_mapping_and_sequence_inputs(self) -> None:
        validated = validate_campaign_registry(
            self.registry, self.policy, self.specs, self.records
        )
        from_sequences = validate_campaign_registry(
            self.registry,
            self.policy,
            list(reversed(self.specs.values())),
            list(reversed(self.records.values())),
        )

        self.assertEqual(validated, self.registry)
        self.assertEqual(from_sequences, self.registry)
        self.assertIsNot(validated, self.registry)
        validated["arms"][0]["label"] = "changed"
        self.assertNotEqual(validated, self.registry)

    def test_hash_load_and_canonical_atomic_write(self) -> None:
        digest = campaign_registry_sha256(
            self.registry, self.policy, self.specs, self.records
        )
        self.assertEqual(digest, value_sha256(self.registry))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "registry.json"
            returned = write_campaign_registry(
                path, self.registry, self.policy, self.specs, self.records
            )
            self.assertEqual(returned, path)
            self.assertEqual(
                path.read_bytes(), canonical_json_bytes(self.registry) + b"\n"
            )
            self.assertEqual(
                load_campaign_registry(
                    path, self.policy, self.specs, self.records
                ),
                self.registry,
            )

    def test_rejects_missing_extra_miskeyed_and_duplicate_documents(self) -> None:
        missing_specs = dict(self.specs)
        missing_specs.pop("screen-dense-0000")
        extra_records = dict(self.records)
        extra = copy.deepcopy(next(iter(self.records.values())))
        extra["run_id"] = "unreferenced-run-0001"
        extra_records[extra["run_id"]] = extra
        miskeyed = dict(self.specs)
        miskeyed["wrong-map-key"] = miskeyed.pop("screen-dense-0000")
        duplicate_sequence = [*self.specs.values(), next(iter(self.specs.values()))]

        cases = (
            (missing_specs, self.records),
            (self.specs, extra_records),
            (miskeyed, self.records),
            (duplicate_sequence, list(self.records.values())),
        )
        for specs, records in cases:
            with self.subTest(spec_type=type(specs).__name__):
                with self.assertRaises(CampaignRegistryValidationError):
                    validate_campaign_registry(
                        self.registry, self.policy, specs, records
                    )

    def test_rejects_digest_operator_and_dense_identity_drift(self) -> None:
        bad_digest = copy.deepcopy(self.registry)
        bad_digest["runs"][0]["run_spec_sha256"] = "f" * 64

        wrong_operator = copy.deepcopy(self.registry)
        wrong_operator["arms"][0]["operator"]["family"] = "renamed"

        wrong_backbone = copy.deepcopy(self.registry)
        wrong_backbone["cohorts"][0]["backbone_identity_sha256"] = "f" * 64

        for registry in (bad_digest, wrong_operator, wrong_backbone):
            with self.subTest(mutation=registry):
                with self.assertRaises(CampaignRegistryValidationError):
                    validate_campaign_registry(
                        registry, self.policy, self.specs, self.records
                    )

    def test_requires_exact_replicates_and_all_seed_fields_paired(self) -> None:
        missing_run = copy.deepcopy(self.registry)
        removed = missing_run["runs"].pop()
        specs = dict(self.specs)
        records = dict(self.records)
        specs.pop(removed["run_id"])
        records.pop(removed["run_id"])
        with self.assertRaisesRegex(
            CampaignRegistryValidationError, "exact replicate indices"
        ):
            validate_campaign_registry(missing_run, self.policy, specs, records)

        drift_specs = copy.deepcopy(self.specs)
        run_id = "screen-recycle-0001"
        drift_specs[run_id]["seeds"]["data_order"] += 1
        drift_records = copy.deepcopy(self.records)
        drift_records[run_id] = completed_record_for_spec(drift_specs[run_id])
        drift_registry = copy.deepcopy(self.registry)
        for entry in drift_registry["runs"]:
            if entry["run_id"] == run_id:
                entry["run_spec_sha256"] = run_spec_sha256(drift_specs[run_id])
                entry["completed_record_sha256"] = value_sha256(
                    drift_records[run_id]
                )
        with self.assertRaisesRegex(
            CampaignRegistryValidationError, "all run seed fields"
        ):
            validate_campaign_registry(
                drift_registry, self.policy, drift_specs, drift_records
            )

    def test_evaluation_only_changes_do_not_make_replicates_fresh(self) -> None:
        specs = copy.deepcopy(self.specs)
        for arm_id in ARM_IDS:
            short_arm = "dense" if arm_id == "dense-sft" else "recycle"
            first = specs[f"screen-{short_arm}-0000"]
            second = specs[f"screen-{short_arm}-0001"]
            for field in SEED_FIELDS[:-1]:
                second["seeds"][field] = first["seeds"][field]
        records = {
            run_id: completed_record_for_spec(spec)
            for run_id, spec in specs.items()
        }
        registry = screening_registry(self.policy, specs, records)

        with self.assertRaisesRegex(
            CampaignRegistryValidationError,
            "changing only the evaluation seed does not establish fresh training runs",
        ):
            validate_campaign_registry(registry, self.policy, specs, records)

    def test_stable_run_protocol_rejects_cross_seed_recipe_drift(self) -> None:
        for mutation in ("learning_rate", "training_protocol", "export"):
            specs = copy.deepcopy(self.specs)
            records = copy.deepcopy(self.records)
            registry = copy.deepcopy(self.registry)
            run_id = "screen-dense-0001"
            changed = specs[run_id]
            if mutation == "learning_rate":
                changed["optimizer"]["parameter_groups"][0][
                    "learning_rate"
                ] = 1e-5
            elif mutation == "training_protocol":
                changed["training_protocol"]["microbatch_size"] = 4
                changed["training_protocol"]["effective_batch_size"] = 4
            else:
                changed["export"]["format"] = "gguf"
            records[run_id] = completed_record_for_spec(changed)
            for entry in registry["runs"]:
                if entry["run_id"] == run_id:
                    entry["run_spec_sha256"] = run_spec_sha256(changed)
                    entry["completed_record_sha256"] = value_sha256(
                        records[run_id]
                    )
            with self.subTest(mutation=mutation):
                with self.assertRaisesRegex(
                    CampaignRegistryValidationError, "stable run protocol"
                ):
                    validate_campaign_registry(
                        registry, self.policy, specs, records
                    )

    def test_stable_run_protocol_excludes_seed_realized_selection_payloads(
        self,
    ) -> None:
        specs = copy.deepcopy(self.specs)
        records = copy.deepcopy(self.records)
        registry = copy.deepcopy(self.registry)
        run_id = "screen-recycle-0001"
        original = copy.deepcopy(specs[run_id])
        changed = specs[run_id]
        changed["operator"]["selection_manifest_sha256"] = "e" * 64
        changed["operator"]["structural_indices"][0]["indices"] = [4, 5, 6]
        self.assertEqual(
            campaign_run_protocol_sha256(original),
            campaign_run_protocol_sha256(changed),
        )
        records[run_id] = completed_record_for_spec(changed)
        for entry in registry["runs"]:
            if entry["run_id"] == run_id:
                entry["run_spec_sha256"] = run_spec_sha256(changed)
                entry["completed_record_sha256"] = value_sha256(records[run_id])

        validate_campaign_registry(registry, self.policy, specs, records)

    def test_contrast_role_is_arm_protocol_not_cohort_pairing_material(self) -> None:
        reference = spec_for_campaign_profile("confirmation")
        comparison = copy.deepcopy(reference)
        comparison["campaign"]["contrast_role"] = "comparison"

        self.assertNotEqual(
            campaign_run_protocol_sha256(reference),
            campaign_run_protocol_sha256(comparison),
        )
        self.assertEqual(
            campaign_pairing_commitments_sha256(reference),
            campaign_pairing_commitments_sha256(comparison),
        )

    def test_confirmatory_roles_require_one_uniform_arm_per_role(self) -> None:
        policy, specs, records = campaign_documents(
            ("screening", "confirmation")
        )
        registry, evaluations = confirmation_registry(policy, specs, records)
        for run_id, spec in specs.items():
            if run_id.startswith("confirm-recycle-"):
                spec["campaign"]["contrast_role"] = "reference"
                records[run_id] = completed_record_for_spec(spec)
        recycle = next(
            arm for arm in registry["arms"] if arm["arm_id"] == "recycle-ffn"
        )
        recycle_protocol = next(
            protocol
            for protocol in recycle["run_protocols"]
            if protocol["profile"] == "confirmation"
        )
        recycle_protocol["run_protocol_sha256"] = campaign_run_protocol_sha256(
            specs["confirm-recycle-0000"]
        )
        for entry in registry["runs"]:
            if entry["run_id"].startswith("confirm-recycle-"):
                run_id = entry["run_id"]
                entry["run_spec_sha256"] = run_spec_sha256(specs[run_id])
                entry["completed_record_sha256"] = value_sha256(records[run_id])

        with self.assertRaisesRegex(
            CampaignRegistryValidationError,
            "exactly one all-reference arm and one all-comparison arm",
        ):
            validate_campaign_registry(
                registry,
                policy,
                specs,
                records,
                evaluation_specs=evaluations,
            )

    def test_confirmatory_arm_cannot_mix_roles_across_replicates(self) -> None:
        policy, specs, records = campaign_documents(
            ("screening", "confirmation")
        )
        registry, evaluations = confirmation_registry(policy, specs, records)
        run_id = "confirm-recycle-0004"
        specs[run_id]["campaign"]["contrast_role"] = "reference"
        records[run_id] = completed_record_for_spec(specs[run_id])
        for entry in registry["runs"]:
            if entry["run_id"] == run_id:
                entry["run_spec_sha256"] = run_spec_sha256(specs[run_id])
                entry["completed_record_sha256"] = value_sha256(records[run_id])

        with self.assertRaisesRegex(
            CampaignRegistryValidationError,
            "must declare one identical campaign.contrast_role",
        ):
            validate_campaign_registry(
                registry,
                policy,
                specs,
                records,
                evaluation_specs=evaluations,
            )

    def test_rejects_unpaired_data_teacher_execution_and_backbone_commitments(self) -> None:
        mutations = (
            ("data", "manifest_sha256", "f" * 64),
            ("execution", "verifier_sha256", "f" * 64),
            ("model", "checkpoint_sha256", "f" * 64),
        )
        for section, field, value in mutations:
            specs = copy.deepcopy(self.specs)
            records = copy.deepcopy(self.records)
            registry = copy.deepcopy(self.registry)
            run_id = "screen-recycle-0000"
            specs[run_id][section][field] = value
            records[run_id] = completed_record_for_spec(specs[run_id])
            for entry in registry["runs"]:
                if entry["run_id"] == run_id:
                    entry["run_spec_sha256"] = run_spec_sha256(specs[run_id])
                    entry["completed_record_sha256"] = value_sha256(records[run_id])
            with self.subTest(path=f"{section}.{field}"):
                with self.assertRaisesRegex(
                    CampaignRegistryValidationError,
                    "commitments are not paired|backbone_identity",
                ):
                    validate_campaign_registry(
                        registry, self.policy, specs, records
                    )

    def test_arm_lineage_and_promotion_scope_fail_closed(self) -> None:
        unknown_source = copy.deepcopy(self.registry)
        unknown_source["arms"][1]["source_arm_id"] = "missing-arm"
        cyclic = copy.deepcopy(self.registry)
        cyclic["arms"][0]["source_arm_id"] = "recycle-ffn"
        screening_promotion = copy.deepcopy(self.registry)
        screening_promotion["cohorts"][0]["source_cohort_id"] = "screen-primary"
        screening_promotion["cohorts"][0]["promotion_links"] = [
            {"arm_id": "dense-sft", "source_arm_id": "dense-sft"},
            {"arm_id": "recycle-ffn", "source_arm_id": "recycle-ffn"},
        ]
        altered_scope = copy.deepcopy(self.registry)
        altered_scope["scope"]["promotion_validation"] = (
            "metric_eligibility_proven"
        )

        for registry in (unknown_source, cyclic, screening_promotion, altered_scope):
            with self.subTest(registry=registry):
                with self.assertRaises(CampaignRegistryValidationError):
                    validate_campaign_registry(
                        registry, self.policy, self.specs, self.records
                    )

    def test_pairing_hash_covers_mixture_code_accounting_and_checkpoint_policy(self) -> None:
        base = copy.deepcopy(self.specs["screen-dense-0000"])
        base["capability_mixture"]["target"][0].update(
            {"fraction": 0.4, "tokens": 800_000}
        )
        base["capability_mixture"]["target"].append(
            {
                "name": "terminal_text_processing",
                "fraction": 0.4,
                "tokens": 800_000,
                "data_sha256": "f" * 64,
            }
        )
        redistributed = copy.deepcopy(base)
        redistributed["capability_mixture"]["target"][0].update(
            {"fraction": 0.3, "tokens": 600_000}
        )
        redistributed["capability_mixture"]["target"][1].update(
            {"fraction": 0.5, "tokens": 1_000_000}
        )
        self.assertNotEqual(
            campaign_pairing_commitments_sha256(base),
            campaign_pairing_commitments_sha256(redistributed),
        )

        for section, field, value in (
            (None, "git_revision", "f" * 40),
            ("compute_budget", "accounting_sha256", "f" * 64),
            ("checkpoint", "rule", "Different prospective selection rule."),
        ):
            changed = copy.deepcopy(base)
            if section is None:
                changed[field] = value
            else:
                changed[section][field] = value
            with self.subTest(path=f"{section}.{field}"):
                self.assertNotEqual(
                    campaign_pairing_commitments_sha256(base),
                    campaign_pairing_commitments_sha256(changed),
                )

    def test_completed_teacher_corpus_must_pair_across_arms(self) -> None:
        specs = copy.deepcopy(self.specs)
        for spec in specs.values():
            enable_teacher(spec)
        records = {
            run_id: completed_record_for_spec(spec)
            for run_id, spec in specs.items()
        }
        registry = screening_registry(self.policy, specs, records)
        run_id = "screen-recycle-0000"
        records[run_id]["teacher"]["verified_corpus_sha256"] = "e" * 64
        for entry in registry["runs"]:
            if entry["run_id"] == run_id:
                entry["completed_record_sha256"] = value_sha256(records[run_id])
        with self.assertRaisesRegex(
            CampaignRegistryValidationError, "identical verified teacher corpus"
        ):
            validate_campaign_registry(
                registry, self.policy, specs, records
            )

    def test_completed_teacher_corpus_cannot_drift_by_replicate(self) -> None:
        specs = copy.deepcopy(self.specs)
        for spec in specs.values():
            enable_teacher(spec)
        records = {
            run_id: completed_record_for_spec(spec)
            for run_id, spec in specs.items()
        }
        registry = screening_registry(self.policy, specs, records)
        changed_run_ids = {
            "screen-dense-0001",
            "screen-recycle-0001",
        }
        for run_id in changed_run_ids:
            records[run_id]["teacher"]["verified_corpus_sha256"] = "e" * 64
        for entry in registry["runs"]:
            if entry["run_id"] in changed_run_ids:
                entry["completed_record_sha256"] = value_sha256(
                    records[entry["run_id"]]
                )
        with self.assertRaisesRegex(
            CampaignRegistryValidationError, "across the entire cohort"
        ):
            validate_campaign_registry(
                registry, self.policy, specs, records
            )


class ConfirmatoryEvaluationCubeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy, cls.specs, cls.records = campaign_documents(
            ("screening", "confirmation")
        )
        cls.registry, cls.evaluations = confirmation_registry(
            cls.policy, cls.specs, cls.records
        )

    def test_binds_two_arms_times_five_seed_artifacts_to_one_paired_cube(self) -> None:
        validated = validate_campaign_registry(
            self.registry,
            self.policy,
            self.specs,
            self.records,
            evaluation_specs=self.evaluations,
        )
        cohort = next(
            item
            for item in validated["cohorts"]
            if item["cohort_id"] == "confirm-primary"
        )
        entries = [
            entry
            for entry in validated["runs"]
            if entry["cohort_id"] == "confirm-primary"
        ]

        self.assertEqual(len(entries), 10)
        self.assertEqual(
            len(
                {
                    entry["evaluations"][0]["evaluation_id"]
                    for entry in entries
                }
            ),
            10,
        )
        for arm_id in ARM_IDS:
            self.assertEqual(
                [
                    entry["replicate_index"]
                    for entry in entries
                    if entry["arm_id"] == arm_id
                ],
                [0, 1, 2, 3, 4],
            )
        cube = cohort["evaluation_cubes"][0]
        self.assertEqual(cube["training_seed_count"], 5)
        self.assertEqual(cube["task_count"], 1_000)
        self.assertEqual(
            cube["result_coverage"],
            "evaluation_specs_only",
        )
        self.assertEqual(
            cohort["contrast"], contrast_plan("dense-sft", "recycle-ffn")
        )
        self.assertEqual(
            cube["ordered_arm_roles_sha256"],
            cohort["contrast"]["ordered_arm_roles_sha256"],
        )

    def test_contrast_direction_requires_typed_roles_and_direct_source(self) -> None:
        missing = copy.deepcopy(self.registry)
        cohort = next(
            item
            for item in missing["cohorts"]
            if item["cohort_id"] == "confirm-primary"
        )
        cohort["contrast"] = None
        with self.assertRaisesRegex(
            CampaignRegistryValidationError, "must preregister"
        ):
            validate_campaign_registry(
                missing,
                self.policy,
                self.specs,
                self.records,
                evaluation_specs=self.evaluations,
            )

        unrelated = copy.deepcopy(self.registry)
        comparison = next(
            arm for arm in unrelated["arms"] if arm["arm_id"] == "recycle-ffn"
        )
        comparison["source_arm_id"] = None
        with self.assertRaisesRegex(
            CampaignRegistryValidationError,
            "source_arm_id must equal the reference",
        ):
            validate_campaign_registry(
                unrelated,
                self.policy,
                self.specs,
                self.records,
                evaluation_specs=self.evaluations,
            )

        mismatch = copy.deepcopy(self.evaluations)
        evaluation_id = sorted(mismatch)[0]
        analysis = mismatch[evaluation_id]["analysis_plan"]
        analysis["contrast"] = contrast_plan("recycle-ffn", "dense-sft")
        analysis["policy_sha256"] = section_policy_sha256(analysis)
        mismatch_registry = copy.deepcopy(self.registry)
        for entry in mismatch_registry["runs"]:
            for binding in entry["evaluations"]:
                if binding["evaluation_id"] == evaluation_id:
                    binding["evaluation_spec_sha256"] = value_sha256(
                        mismatch[evaluation_id]
                    )
        with self.assertRaisesRegex(
            CampaignRegistryValidationError, "must exactly match"
        ):
            validate_campaign_registry(
                mismatch_registry,
                self.policy,
                self.specs,
                self.records,
                evaluation_specs=mismatch,
            )

    def test_rehashed_role_reversal_cannot_change_confirmatory_direction(self) -> None:
        registry = copy.deepcopy(self.registry)
        evaluations = copy.deepcopy(self.evaluations)
        reversed_contrast = contrast_plan("recycle-ffn", "dense-sft")
        cohort = next(
            item
            for item in registry["cohorts"]
            if item["cohort_id"] == "confirm-primary"
        )
        cohort["contrast"] = copy.deepcopy(reversed_contrast)
        for arm in registry["arms"]:
            if arm["arm_id"] == "dense-sft":
                arm["source_arm_id"] = "recycle-ffn"
            elif arm["arm_id"] == "recycle-ffn":
                arm["source_arm_id"] = None
        cohort["evaluation_cubes"][0]["ordered_arm_roles_sha256"] = (
            reversed_contrast["ordered_arm_roles_sha256"]
        )
        for evaluation in evaluations.values():
            analysis = evaluation["analysis_plan"]
            analysis["contrast"] = copy.deepcopy(reversed_contrast)
            analysis["policy_sha256"] = section_policy_sha256(analysis)
        for entry in registry["runs"]:
            for binding in entry["evaluations"]:
                evaluation = evaluations[binding["evaluation_id"]]
                binding["evaluation_spec_sha256"] = value_sha256(evaluation)
        entries = [
            entry
            for entry in registry["runs"]
            if entry["cohort_id"] == "confirm-primary"
        ]
        seed_records = _seed_records_for_profile(self.specs, "confirmation")
        first = evaluations[entries[0]["evaluations"][0]["evaluation_id"]]
        cube_projection = {
            "cube_id": "sealed-id-primary",
            "cohort_id": "confirm-primary",
            "profile": "confirmation",
            "arm_ids": copy.deepcopy(cohort["arm_ids"]),
            "contrast": copy.deepcopy(reversed_contrast),
            "training_seeds": seed_records,
            "task_count": first["benchmark"]["task_count"],
            "task_commitment_set_sha256": first["task_commitments"][
                "commitment_set_sha256"
            ],
            "bindings": [
                {
                    "arm_id": entry["arm_id"],
                    "replicate_index": entry["replicate_index"],
                    "run_id": entry["run_id"],
                    "seeds": copy.deepcopy(
                        self.specs[entry["run_id"]]["seeds"]
                    ),
                    "evaluation_id": entry["evaluations"][0]["evaluation_id"],
                    "evaluation_spec_sha256": entry["evaluations"][0][
                        "evaluation_spec_sha256"
                    ],
                    "task_result_collection_sha256": None,
                }
                for entry in entries
            ],
        }
        cohort["evaluation_cubes"][0]["paired_cube_sha256"] = value_sha256(
            cube_projection
        )
        with self.assertRaisesRegex(
            CampaignRegistryValidationError,
            "derive from every prospective run spec",
        ):
            validate_campaign_registry(
                registry,
                self.policy,
                self.specs,
                self.records,
                evaluation_specs=evaluations,
            )

    def test_confirmatory_cube_rejects_more_than_two_contrast_arms(self) -> None:
        registry = copy.deepcopy(self.registry)
        registry["arms"].append(
            {
                "arm_id": "third-control",
                "label": "Third confirmatory control",
                "operator": {
                    "mechanism": "baseline",
                    "family": "third_control",
                    "configuration_sha256": "f" * 64,
                },
                "run_protocols": [
                    {
                        "profile": "confirmation",
                        "run_protocol_sha256": "f" * 64,
                    }
                ],
                "source_arm_id": "dense-sft",
            }
        )
        cohort = next(
            item
            for item in registry["cohorts"]
            if item["cohort_id"] == "confirm-primary"
        )
        cohort["arm_ids"].append("third-control")
        cohort["promotion_links"].append(
            {"arm_id": "third-control", "source_arm_id": "dense-sft"}
        )
        with self.assertRaisesRegex(
            CampaignRegistryValidationError, "require exactly two arms"
        ):
            validate_campaign_registry(
                registry,
                self.policy,
                self.specs,
                self.records,
                evaluation_specs=self.evaluations,
            )

    def test_every_cube_must_match_one_explicit_confirmatory_lane(self) -> None:
        registry = copy.deepcopy(self.registry)
        cohort = next(
            item
            for item in registry["cohorts"]
            if item["cohort_id"] == "confirm-primary"
        )
        cohort["analysis_lane"] = "compression"
        with self.assertRaisesRegex(
            CampaignRegistryValidationError, "lane must match"
        ):
            validate_campaign_registry(
                registry,
                self.policy,
                self.specs,
                self.records,
                evaluation_specs=self.evaluations,
            )

    def test_rejects_missing_or_reused_single_evaluation_artifacts(self) -> None:
        missing = dict(self.evaluations)
        missing.pop(next(iter(missing)))
        with self.assertRaisesRegex(
            CampaignRegistryValidationError, "evaluation_specs: missing"
        ):
            validate_campaign_registry(
                self.registry,
                self.policy,
                self.specs,
                self.records,
                evaluation_specs=missing,
            )

        reused = copy.deepcopy(self.registry)
        confirmation_entries = [
            entry
            for entry in reused["runs"]
            if entry["cohort_id"] == "confirm-primary"
        ]
        confirmation_entries[1]["evaluations"] = copy.deepcopy(
            confirmation_entries[0]["evaluations"]
        )
        with self.assertRaisesRegex(
            CampaignRegistryValidationError, "duplicate binding"
        ):
            validate_campaign_registry(
                reused,
                self.policy,
                self.specs,
                self.records,
                evaluation_specs=self.evaluations,
            )

    def test_cohort_can_declare_multiple_suites_with_one_binding_per_run(self) -> None:
        registry = copy.deepcopy(self.registry)
        evaluations = copy.deepcopy(self.evaluations)
        entries = [
            entry
            for entry in registry["runs"]
            if entry["cohort_id"] == "confirm-primary"
        ]
        for entry in entries:
            primary = entry["evaluations"][0]
            evaluation = copy.deepcopy(evaluations[primary["evaluation_id"]])
            evaluation_id = "secondary-" + primary["evaluation_id"]
            evaluation["evaluation_id"] = evaluation_id
            evaluation["benchmark"]["benchmark_id"] = (
                "generated-terminal-suite-secondary"
            )
            evaluation["benchmark"]["split"].update(
                {
                    "name": "confirmatory-sealed-id-secondary",
                    "sha256": "e" * 64,
                }
            )
            evaluation = validate_evaluation_spec(evaluation)
            evaluations[evaluation_id] = evaluation
            entry["evaluations"].append(
                {
                    "cube_id": "sealed-id-secondary",
                    "evaluation_id": evaluation_id,
                    "evaluation_spec_sha256": value_sha256(evaluation),
                    "task_result_collection_sha256": None,
                    "task_result_record_count": 0,
                }
            )
        seed_records = _seed_records_for_profile(self.specs, "confirmation")
        first = evaluations[entries[0]["evaluations"][1]["evaluation_id"]]
        projection = {
            "cube_id": "sealed-id-secondary",
            "cohort_id": "confirm-primary",
            "profile": "confirmation",
            "arm_ids": list(ARM_IDS),
            "contrast": contrast_plan("dense-sft", "recycle-ffn"),
            "training_seeds": seed_records,
            "task_count": first["benchmark"]["task_count"],
            "task_commitment_set_sha256": first["task_commitments"][
                "commitment_set_sha256"
            ],
            "bindings": [
                {
                    "arm_id": entry["arm_id"],
                    "replicate_index": entry["replicate_index"],
                    "run_id": entry["run_id"],
                    "seeds": copy.deepcopy(self.specs[entry["run_id"]]["seeds"]),
                    "evaluation_id": entry["evaluations"][1]["evaluation_id"],
                    "evaluation_spec_sha256": entry["evaluations"][1][
                        "evaluation_spec_sha256"
                    ],
                    "task_result_collection_sha256": None,
                }
                for entry in entries
            ],
        }
        cohort = next(
            item
            for item in registry["cohorts"]
            if item["cohort_id"] == "confirm-primary"
        )
        cohort["evaluation_cubes"].append(
            {
                "cube_id": "sealed-id-secondary",
                "benchmark_id": first["benchmark"]["benchmark_id"],
                "benchmark_split_sha256": first["benchmark"]["split"]["sha256"],
                "task_commitment_set_sha256": first["task_commitments"][
                    "commitment_set_sha256"
                ],
                "task_count": first["benchmark"]["task_count"],
                "training_seed_count": 5,
                "training_seed_set_sha256": value_sha256(seed_records),
                "ordered_arm_roles_sha256": cohort["contrast"][
                    "ordered_arm_roles_sha256"
                ],
                "paired_cube_sha256": value_sha256(projection),
                "result_coverage": "evaluation_specs_only",
            }
        )

        validated = validate_campaign_registry(
            registry,
            self.policy,
            self.specs,
            self.records,
            evaluation_specs=evaluations,
        )
        confirmed = next(
            item
            for item in validated["cohorts"]
            if item["cohort_id"] == "confirm-primary"
        )
        self.assertEqual(
            [cube["cube_id"] for cube in confirmed["evaluation_cubes"]],
            ["sealed-id-primary", "sealed-id-secondary"],
        )

    def test_evaluation_seed_set_hash_and_cube_dimensions_are_derived(self) -> None:
        evaluations = copy.deepcopy(self.evaluations)
        registry = copy.deepcopy(self.registry)
        evaluation_id = sorted(evaluations)[0]
        evaluation = evaluations[evaluation_id]
        evaluation["analysis_plan"]["training_seed_set_sha256"] = "f" * 64
        evaluation["analysis_plan"]["policy_sha256"] = section_policy_sha256(
            evaluation["analysis_plan"]
        )
        for entry in registry["runs"]:
            if (
                entry["evaluations"]
                and entry["evaluations"][0]["evaluation_id"] == evaluation_id
            ):
                entry["evaluations"][0]["evaluation_spec_sha256"] = value_sha256(
                    evaluation
                )
        with self.assertRaisesRegex(
            CampaignRegistryValidationError, "seed-set hash"
        ):
            validate_campaign_registry(
                registry,
                self.policy,
                self.specs,
                self.records,
                evaluation_specs=evaluations,
            )

        wrong_cube = copy.deepcopy(self.registry)
        cohort = next(
            item
            for item in wrong_cube["cohorts"]
            if item["cohort_id"] == "confirm-primary"
        )
        cohort["evaluation_cubes"][0]["task_count"] = 999
        with self.assertRaisesRegex(
            CampaignRegistryValidationError, "dimensions"
        ):
            validate_campaign_registry(
                wrong_cube,
                self.policy,
                self.specs,
                self.records,
                evaluation_specs=self.evaluations,
            )

    def test_confirmation_seed_tuple_cannot_reuse_screening_phase(self) -> None:
        specs = copy.deepcopy(self.specs)
        records = copy.deepcopy(self.records)
        registry = copy.deepcopy(self.registry)
        evaluations = copy.deepcopy(self.evaluations)
        for arm_id in ARM_IDS:
            confirm_run = (
                "confirm-dense-0000"
                if arm_id == "dense-sft"
                else "confirm-recycle-0000"
            )
            screen_run = (
                "screen-dense-0000"
                if arm_id == "dense-sft"
                else "screen-recycle-0000"
            )
            specs[confirm_run]["seeds"] = copy.deepcopy(specs[screen_run]["seeds"])
            records[confirm_run] = completed_record_for_spec(specs[confirm_run])
            for entry in registry["runs"]:
                if entry["run_id"] == confirm_run:
                    entry["run_spec_sha256"] = run_spec_sha256(specs[confirm_run])
                    entry["completed_record_sha256"] = value_sha256(records[confirm_run])
        with self.assertRaisesRegex(
            CampaignRegistryValidationError, "reused across phases"
        ):
            validate_campaign_registry(
                registry,
                self.policy,
                specs,
                records,
                evaluation_specs=evaluations,
            )

    def test_confirmation_training_seeds_are_fresh_even_when_evaluation_differs(
        self,
    ) -> None:
        policy, specs, records = campaign_documents(
            ("screening", "confirmation")
        )
        for arm_id in ARM_IDS:
            short_arm = "dense" if arm_id == "dense-sft" else "recycle"
            for replicate in range(2):
                screening = specs[f"screen-{short_arm}-{replicate:04d}"]
                confirmation = specs[f"confirm-{short_arm}-{replicate:04d}"]
                for field in SEED_FIELDS[:-1]:
                    confirmation["seeds"][field] = screening["seeds"][field]
                self.assertNotEqual(
                    confirmation["seeds"]["evaluation"],
                    screening["seeds"]["evaluation"],
                )
                records[confirmation["run_id"]] = completed_record_for_spec(
                    confirmation
                )
        registry, evaluations = confirmation_registry(policy, specs, records)

        with self.assertRaisesRegex(
            CampaignRegistryValidationError,
            "reused across phases.*field-wise fresh",
        ):
            validate_campaign_registry(
                registry,
                policy,
                specs,
                records,
                evaluation_specs=evaluations,
            )

    def test_cross_phase_freshness_compares_matching_seed_fields_only(self) -> None:
        policy, specs, records = campaign_documents(
            ("screening", "confirmation")
        )
        cross_domain_value = specs["screen-dense-0000"]["seeds"]["data_order"]
        self.assertNotIn(
            cross_domain_value,
            {
                specs["screen-dense-0000"]["seeds"]["model_initialization"],
                specs["screen-dense-0001"]["seeds"]["model_initialization"],
            },
        )
        for short_arm in ("dense", "recycle"):
            confirmation = specs[f"confirm-{short_arm}-0000"]
            confirmation["seeds"]["model_initialization"] = cross_domain_value
            records[confirmation["run_id"]] = completed_record_for_spec(
                confirmation
            )
        registry, evaluations = confirmation_registry(policy, specs, records)

        validate_campaign_registry(
            registry,
            policy,
            specs,
            records,
            evaluation_specs=evaluations,
        )

    def test_task_result_collection_hash_input_is_canonical_order_invariant(self) -> None:
        spec = valid_static_spec()
        results = [bound_static_result(spec, index) for index in range(2)]
        forward = validate_task_result_collection_against_evaluation_spec(
            results, spec
        )
        reverse = validate_task_result_collection_against_evaluation_spec(
            list(reversed(results)), spec
        )
        self.assertEqual(forward, reverse)
        self.assertEqual(value_sha256(forward), value_sha256(reverse))


if __name__ == "__main__":
    unittest.main()
