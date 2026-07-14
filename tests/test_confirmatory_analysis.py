from __future__ import annotations

import copy
from hashlib import sha256
import inspect
import unittest

from cbds.confirmatory_analysis import (
    CONFIRMATORY_ANALYSIS_RUNNER_VERSION,
    ConfirmatoryAnalysisValidationError,
    finalize_confirmatory_family,
    run_confirmatory_contrast,
)
from cbds.evaluation_specs import section_policy_sha256
from cbds.manifests import value_sha256
from cbds.statistics import STATISTICS_METHOD_VERSION
from tests.test_evaluation_specs import contrast_plan, valid_confirmatory_spec


CODE = b"cbds confirmatory analysis implementation\n"
REVISION = "a" * 40
ARM_IDS = ["dense-reference", "specialized-comparison"]
SEED_FIELDS = (
    "model_initialization",
    "data_order",
    "training",
    "operator_selection",
    "evaluation",
)


def seed_records() -> list[dict]:
    return [
        {
            "replicate_index": replicate,
            "seeds": {
                field: 10_000 + replicate * 100 + offset
                for offset, field in enumerate(SEED_FIELDS)
            },
        }
        for replicate in range(5)
    ]


def evaluation_spec(lane: str) -> dict:
    spec = valid_confirmatory_spec(role="sealed_ood", lane=lane)
    analysis = spec["analysis_plan"]
    analysis["analysis_code_revision"] = REVISION
    analysis["analysis_code_sha256"] = sha256(CODE).hexdigest()
    analysis["contrast"] = contrast_plan(*ARM_IDS)
    analysis["training_seed_set_sha256"] = value_sha256(seed_records())
    analysis["policy_sha256"] = section_policy_sha256(analysis)
    spec["artifact"]["training_seed"] = seed_records()[0]["seeds"]["training"]
    return spec


def outcomes(spec: dict, *, improve: bool = True) -> list[dict]:
    records: list[dict] = []
    tasks = [
        commitment["prompt_id"]
        for commitment in spec["task_commitments"]["commitments"]
    ]
    for seed_record in seed_records():
        training_seed = seed_record["seeds"]["training"]
        for task in tasks:
            records.append(
                {
                    "arm": "dense-reference",
                    "seed": training_seed,
                    "task": task,
                    "passed": 0 if improve else 1,
                }
            )
            records.append(
                {
                    "arm": "specialized-comparison",
                    "seed": training_seed,
                    "task": task,
                    "passed": 1 if improve else 0,
                }
            )
    return records


def invoke(spec: dict, records: list[dict] | None = None, **overrides: object) -> dict:
    seeds = seed_records()
    arguments: dict[str, object] = {
        "contrast_id": "test-confirmatory-contrast",
        "endpoint": "static",
        "analysis_code_bytes": CODE,
        "analysis_code_revision": REVISION,
        "registry_contrast": copy.deepcopy(spec["analysis_plan"]["contrast"]),
        "registry_arm_declarations": [
            {"arm_id": "dense-reference", "source_arm_id": None},
            {
                "arm_id": "specialized-comparison",
                "source_arm_id": "dense-reference",
            },
        ],
        "registry_training_seed_records": seeds,
        "registry_training_seed_set_sha256": value_sha256(seeds),
    }
    arguments.update(overrides)
    return run_confirmatory_contrast(
        spec,
        outcomes(spec) if records is None else records,
        **arguments,  # type: ignore[arg-type]
    )


_RUN_CACHE: dict[str, dict] = {}


def run(lane: str, *, endpoint: str = "static", contrast_id: str | None = None) -> dict:
    if endpoint == "static" and lane in _RUN_CACHE:
        result = copy.deepcopy(_RUN_CACHE[lane])
        result["contrast_id"] = contrast_id or f"{lane}-contrast"
        unhashed = copy.deepcopy(result)
        unhashed.pop("contrast_record_sha256")
        result["contrast_record_sha256"] = value_sha256(unhashed)
        return result
    records = seed_records()
    spec = evaluation_spec(lane)
    result = invoke(
        spec,
        contrast_id=contrast_id or f"{lane}-contrast",
        endpoint=endpoint,
        registry_training_seed_records=records,
        registry_training_seed_set_sha256=value_sha256(records),
    )
    if endpoint == "static":
        _RUN_CACHE[lane] = copy.deepcopy(result)
    return result


class ConfirmatoryContrastTests(unittest.TestCase):
    def test_executes_frozen_static_plan_with_derived_bindings(self) -> None:
        result = run("compression")
        self.assertEqual(result["runner_version"], CONFIRMATORY_ANALYSIS_RUNNER_VERSION)
        self.assertEqual(result["statistics_method_version"], STATISTICS_METHOD_VERSION)
        self.assertEqual(result["bootstrap"]["policy"]["confidence_level"], 0.975)
        self.assertEqual(
            result["bootstrap"]["policy"]["percentile_interpolation"], "linear_r7"
        )
        self.assertEqual(result["randomization_test"]["policy"]["unit"], "task")
        self.assertNotIn("reference_arm", inspect.signature(run_confirmatory_contrast).parameters)
        self.assertNotIn("comparison_arm", inspect.signature(run_confirmatory_contrast).parameters)
        self.assertEqual(result["reference_arm"], "dense-reference")
        self.assertEqual(result["comparison_arm"], "specialized-comparison")
        self.assertGreaterEqual(result["raw_p_value"], 0.0)
        self.assertLessEqual(result["raw_p_value"], 1.0)
        self.assertEqual(result["simultaneous_confidence_interval"]["lower"], 1.0)
        self.assertTrue(result["decisions"]["point_gain"]["met"])
        noninferiority = result["decisions"]["noninferiority"]
        self.assertEqual(noninferiority["margin_absolute_points"], 1.0)
        self.assertEqual(noninferiority["margin_proportion"], 0.01)
        self.assertTrue(noninferiority["decision"]["noninferior"])
        self.assertTrue(result["decisions"]["holm_family_adjustment_pending"])
        self.assertEqual(
            result["bindings"]["analysis_code_binding_scope"],
            "caller_supplied_bytes_match_plan_commitment_not_runtime_attestation",
        )
        self.assertEqual(
            result["outcome_evidence_scope"],
            "caller_supplied_binary_cells_identity_bound_not_collection_derived",
        )
        self.assertEqual(result["bindings"]["evaluation"]["mode"], "static")
        self.assertEqual(result["bindings"]["evaluation"]["benchmark_suite"], "static")
        self.assertEqual(result["bindings"]["evaluation"]["task_count"], 500)
        self.assertEqual(
            len(result["bindings"]["evaluation"]["evaluation_spec_sha256"]),
            64,
        )
        self.assertEqual(
            result["bindings"]["training_seed_set_sha256"],
            value_sha256(seed_records()),
        )
        unhashed = copy.deepcopy(result)
        digest = unhashed.pop("contrast_record_sha256")
        self.assertEqual(digest, value_sha256(unhashed))

    def test_bounded_terminal_rejects_current_static_confirmatory_spec(self) -> None:
        with self.assertRaisesRegex(
            ConfirmatoryAnalysisValidationError,
            "requires a validated 'interactive' evaluation",
        ):
            run("fixed_size", endpoint="bounded_terminal")

    def test_fixed_size_static_noninferiority_is_explicitly_not_applicable(self) -> None:
        result = run("fixed_size")
        self.assertEqual(
            result["decisions"]["noninferiority"],
            {
                "applicable": False,
                "margin_field": "static_absolute_points",
                "reason": "frozen_plan_margin_is_null",
            },
        )

    def test_code_bytes_and_revision_are_both_bound(self) -> None:
        spec = evaluation_spec("fixed_size")
        with self.assertRaisesRegex(
            ConfirmatoryAnalysisValidationError, "analysis_code_bytes"
        ):
            invoke(
                spec,
                analysis_code_bytes=b"different",
            )
        with self.assertRaisesRegex(
            ConfirmatoryAnalysisValidationError, "analysis_code_revision"
        ):
            invoke(
                spec,
                analysis_code_revision="c" * 40,
            )
        with self.assertRaisesRegex(
            ConfirmatoryAnalysisValidationError, "immutable bytes"
        ):
            invoke(
                spec,
                analysis_code_bytes=bytearray(CODE),  # type: ignore[arg-type]
            )

    def test_arm_content_and_hash_are_both_bound(self) -> None:
        spec = evaluation_spec("fixed_size")
        bad_hash = copy.deepcopy(spec["analysis_plan"]["contrast"])
        bad_hash["ordered_arm_roles_sha256"] = "f" * 64
        with self.assertRaisesRegex(
            ConfirmatoryAnalysisValidationError, "does not exactly match"
        ):
            invoke(
                spec,
                registry_contrast=bad_hash,
            )
        reversed_roles = contrast_plan(
            "specialized-comparison", "dense-reference"
        )
        with self.assertRaisesRegex(
            ConfirmatoryAnalysisValidationError, "does not exactly match"
        ):
            invoke(
                spec,
                registry_contrast=reversed_roles,
            )
        with self.assertRaisesRegex(
            ConfirmatoryAnalysisValidationError, "source_arm_id"
        ):
            invoke(
                spec,
                registry_arm_declarations=[
                    {"arm_id": "dense-reference", "source_arm_id": None},
                    {
                        "arm_id": "specialized-comparison",
                        "source_arm_id": None,
                    },
                ],
            )

    def test_seed_content_hash_and_outcome_membership_are_all_bound(self) -> None:
        spec = evaluation_spec("fixed_size")
        seeds = seed_records()
        with self.assertRaisesRegex(
            ConfirmatoryAnalysisValidationError, "not derived from the exact"
        ):
            invoke(
                spec,
                registry_training_seed_records=seeds,
                registry_training_seed_set_sha256="f" * 64,
            )
        reversed_seeds = list(reversed(seeds))
        with self.assertRaisesRegex(
            ConfirmatoryAnalysisValidationError, "ordered and contain exact"
        ):
            invoke(
                spec,
                registry_training_seed_records=reversed_seeds,
                registry_training_seed_set_sha256=value_sha256(reversed_seeds),
            )
        wrong_outcomes = outcomes(spec)
        wrong_outcomes[0]["seed"] += 999
        with self.assertRaisesRegex(
            ConfirmatoryAnalysisValidationError, "missing .*paired"
        ):
            invoke(
                spec,
                wrong_outcomes,
                registry_training_seed_records=seeds,
                registry_training_seed_set_sha256=value_sha256(seeds),
            )

        wrong_tasks = outcomes(spec)
        original_task = wrong_tasks[0]["task"]
        replacement_task = "task-" + "f" * 64
        for record in wrong_tasks:
            if record["task"] == original_task:
                record["task"] = replacement_task
        with self.assertRaisesRegex(
            ConfirmatoryAnalysisValidationError, "task commitments"
        ):
            invoke(spec, wrong_tasks)

        wrong_artifact = copy.deepcopy(spec)
        wrong_artifact["artifact"]["training_seed"] = 999_999
        with self.assertRaisesRegex(
            ConfirmatoryAnalysisValidationError, "artifact training seed"
        ):
            invoke(wrong_artifact)

    def test_fails_closed_on_method_version_name_and_unit_drift(self) -> None:
        mutations = [
            (("version",), "1.0.1"),
            (("metric_unit",), "percentage_points"),
            (("points_to_proportion_divisor",), 1),
            (("bootstrap", "method"), "ordinary_bootstrap"),
            (("bootstrap", "percentile_interpolation"), "nearest"),
            (("bootstrap", "resampling_unit"), "fixture"),
            (("randomization_test", "method"), "paired_t_test"),
            (("randomization_test", "unit"), "seed"),
            (("randomization_test", "alternative"), "greater"),
            (("multiplicity_correction", "p_values"), "none"),
            (("multiplicity_correction", "per_contrast_confidence_level"), 0.95),
            (("confirmatory_lane_contrast_count",), 3),
        ]
        for path, replacement in mutations:
            with self.subTest(path=path):
                mutated = evaluation_spec("fixed_size")
                analysis = mutated["analysis_plan"]
                target = analysis
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = replacement
                analysis["policy_sha256"] = section_policy_sha256(analysis)
                with self.assertRaises(ConfirmatoryAnalysisValidationError):
                    invoke(
                        mutated,
                    )

    def test_rejects_policy_hash_and_lane_contract_drift(self) -> None:
        bad_hash = evaluation_spec("fixed_size")
        bad_hash["analysis_plan"]["policy_sha256"] = "f" * 64
        with self.assertRaisesRegex(
            ConfirmatoryAnalysisValidationError, "policy_sha256"
        ):
            invoke(
                bad_hash,
            )

        bad_threshold = evaluation_spec("fixed_size")
        bad_analysis = bad_threshold["analysis_plan"]
        bad_analysis["success_thresholds"]["static_gain_absolute_points"] = 0
        bad_analysis["policy_sha256"] = section_policy_sha256(bad_analysis)
        with self.assertRaisesRegex(
            ConfirmatoryAnalysisValidationError, "frozen lane"
        ):
            invoke(
                bad_threshold,
            )

    def test_upstream_statistics_limits_and_completeness_remain_enforced(self) -> None:
        too_large_code = b"x" * (8 * 1024 * 1024 + 1)
        oversized_plan = evaluation_spec("fixed_size")
        oversized_analysis = oversized_plan["analysis_plan"]
        oversized_analysis["analysis_code_sha256"] = sha256(too_large_code).hexdigest()
        oversized_analysis["policy_sha256"] = section_policy_sha256(
            oversized_analysis
        )
        with self.assertRaisesRegex(
            ConfirmatoryAnalysisValidationError, "in-memory limit"
        ):
            invoke(
                oversized_plan,
                analysis_code_bytes=too_large_code,
            )

        complete_spec = evaluation_spec("fixed_size")
        incomplete = outcomes(complete_spec)
        incomplete.pop()
        with self.assertRaisesRegex(
            ConfirmatoryAnalysisValidationError, "missing 1 paired"
        ):
            invoke(
                complete_spec,
                incomplete,
            )


class ConfirmatoryFamilyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixed = run(
            "fixed_size", contrast_id="fixed-size-primary-contrast"
        )
        cls.compression = run(
            "compression", contrast_id="compression-primary-contrast"
        )

    def test_finalizes_exact_two_lane_family_with_holm(self) -> None:
        family = finalize_confirmatory_family([self.fixed, self.compression])
        self.assertEqual(family["holm"]["policy"]["family_size"], 2)
        self.assertEqual(family["holm"]["policy"]["alpha"], 0.05)
        self.assertEqual(len(family["decisions"]), 2)
        self.assertEqual(
            [binding["lane"] for binding in family["input_contrast_bindings"]],
            ["compression", "fixed_size"],
        )
        expected_by_lane = {
            result["lane"]: result for result in (self.fixed, self.compression)
        }
        for binding in family["input_contrast_bindings"]:
            source = expected_by_lane[binding["lane"]]
            self.assertEqual(binding["contrast_id"], source["contrast_id"])
            self.assertEqual(
                binding["contrast_record_sha256"],
                source["contrast_record_sha256"],
            )
            self.assertEqual(
                binding["evaluation_spec_sha256"],
                source["bindings"]["evaluation"]["evaluation_spec_sha256"],
            )
        self.assertEqual(
            family["input_contrast_bindings_sha256"],
            value_sha256(
                {
                    "commitment_type": "cbds.confirmatory-family-input-contrasts",
                    "version": "1.0.0",
                    "ordering": "compression_then_fixed_size",
                    "bindings": family["input_contrast_bindings"],
                }
            ),
        )
        self.assertEqual(
            family["shared_source_context"]["analysis_code_sha256"],
            self.fixed["bindings"]["analysis_code_sha256"],
        )
        self.assertTrue(family["all_statistical_positive_gain_criteria_met"])
        holm_by_label = {
            item["label"]: item for item in family["holm"]["hypotheses"]
        }
        for decision in family["decisions"]:
            holm_decision = holm_by_label[decision["contrast_id"]]
            self.assertEqual(
                decision["raw_p_value"], holm_decision["raw_p_value"]
            )
            self.assertEqual(
                decision["holm_adjusted_p_value"],
                holm_decision["adjusted_p_value"],
            )
            self.assertTrue(decision["holm_rejected"])
            self.assertEqual(
                decision["simultaneous_confidence_interval"][
                    "per_contrast_confidence_level"
                ],
                0.975,
            )
        unhashed = copy.deepcopy(family)
        digest = unhashed.pop("family_record_sha256")
        self.assertEqual(digest, value_sha256(unhashed))

    def test_artifact_bound_family_retains_both_cube_source_sets(self) -> None:
        def artifact_bound(result: dict, marker: str) -> dict:
            candidate = copy.deepcopy(result)
            candidate["outcome_evidence_scope"] = (
                "artifact_bound_scored_task_result_collections"
            )
            candidate["bindings"]["artifact_bound_outcome_cube"] = {
                "binder_version": "1.0.0",
                "cohort_id": f"cohort-{candidate['lane']}",
                "cube_id": f"cube-{candidate['lane']}",
                "campaign_registry_sha256": "8" * 64,
                "campaign_policy_sha256": "9" * 64,
                "registry_paired_cube_sha256": marker * 64,
                "binary_cells_sha256": marker * 64,
                "bound_cube_record_sha256": marker * 64,
                "outcome_evidence_scope": (
                    "derived_from_jointly_validated_registry_bound_scored_"
                    "task_results"
                ),
                "runtime_attestation": "none",
            }
            unhashed = copy.deepcopy(candidate)
            unhashed.pop("contrast_record_sha256")
            candidate["contrast_record_sha256"] = value_sha256(unhashed)
            return candidate

        fixed = artifact_bound(self.fixed, "a")
        compression = artifact_bound(self.compression, "b")
        family = finalize_confirmatory_family([fixed, compression])
        self.assertEqual(
            family["shared_source_context"]["campaign_registry_sha256"],
            "8" * 64,
        )
        by_lane = {
            binding["lane"]: binding
            for binding in family["input_contrast_bindings"]
        }
        self.assertEqual(
            by_lane["fixed_size"]["artifact_bound_outcome_cube"][
                "bound_cube_record_sha256"
            ],
            "a" * 64,
        )
        self.assertEqual(
            by_lane["compression"]["artifact_bound_outcome_cube"][
                "bound_cube_record_sha256"
            ],
            "b" * 64,
        )

    def test_rejects_wrong_family_size_duplicate_lane_and_bounded_endpoint(self) -> None:
        with self.assertRaisesRegex(
            ConfirmatoryAnalysisValidationError, "exactly two"
        ):
            finalize_confirmatory_family([self.fixed])
        with self.assertRaisesRegex(
            ConfirmatoryAnalysisValidationError, "2-item limit"
        ):
            finalize_confirmatory_family([self.fixed, self.compression, self.fixed])
        duplicate_lane = run(
            "fixed_size", contrast_id="second-fixed-primary-contrast"
        )
        with self.assertRaisesRegex(
            ConfirmatoryAnalysisValidationError, "one fixed_size and one compression"
        ):
            finalize_confirmatory_family([self.fixed, duplicate_lane])
        bounded = copy.deepcopy(self.compression)
        bounded["endpoint"] = "bounded_terminal"
        bounded["bindings"]["evaluation"]["mode"] = "interactive"
        bounded["bindings"]["evaluation"]["benchmark_suite"] = "interactive"
        unhashed = copy.deepcopy(bounded)
        unhashed.pop("contrast_record_sha256")
        bounded["contrast_record_sha256"] = value_sha256(unhashed)
        with self.assertRaisesRegex(
            ConfirmatoryAnalysisValidationError, "endpoint"
        ):
            finalize_confirmatory_family([self.fixed, bounded])

    def test_rejects_tampering_and_analysis_code_disagreement(self) -> None:
        tampered = copy.deepcopy(self.compression)
        tampered["raw_p_value"] = 0.9
        with self.assertRaisesRegex(
            ConfirmatoryAnalysisValidationError,
            "raw_p_value|contrast_record_sha256",
        ):
            finalize_confirmatory_family([self.fixed, tampered])

        other_code = copy.deepcopy(self.compression)
        other_code["bindings"]["analysis_code_revision"] = "c" * 40
        unhashed = copy.deepcopy(other_code)
        unhashed.pop("contrast_record_sha256")
        other_code["contrast_record_sha256"] = value_sha256(unhashed)
        with self.assertRaisesRegex(
            ConfirmatoryAnalysisValidationError, "analysis_code_revision"
        ):
            finalize_confirmatory_family([self.fixed, other_code])

        other_benchmark = copy.deepcopy(self.compression)
        other_benchmark["bindings"]["evaluation"]["benchmark_split_sha256"] = (
            "d" * 64
        )
        unhashed = copy.deepcopy(other_benchmark)
        unhashed.pop("contrast_record_sha256")
        other_benchmark["contrast_record_sha256"] = value_sha256(unhashed)
        with self.assertRaisesRegex(
            ConfirmatoryAnalysisValidationError, "benchmark_split_sha256"
        ):
            finalize_confirmatory_family([self.fixed, other_benchmark])

    def test_rejects_rehashed_direction_and_summary_tampering(self) -> None:
        def rehash(result: dict) -> dict:
            unhashed = copy.deepcopy(result)
            unhashed.pop("contrast_record_sha256")
            result["contrast_record_sha256"] = value_sha256(unhashed)
            return result

        mutations: list[tuple[str, dict, str]] = []

        top_level = copy.deepcopy(self.compression)
        top_level["reference_arm"] = "specialized-comparison"
        top_level["comparison_arm"] = "dense-reference"
        mutations.append(("top_level", rehash(top_level), "frozen roles"))

        outcomes_tampered = copy.deepcopy(self.compression)
        outcomes_tampered["outcomes"]["reference_arm"] = (
            "specialized-comparison"
        )
        mutations.append(("outcomes", rehash(outcomes_tampered), "outcomes.reference_arm"))

        summary_policy = copy.deepcopy(self.compression)
        summary_policy["summary"]["policy"]["difference_direction"] = (
            "reference_minus_comparison"
        )
        mutations.append(("summary_policy", rehash(summary_policy), "difference_direction"))

        summary_keys = copy.deepcopy(self.compression)
        summary_keys["summary"]["arm_macro_pass_at_1"] = {
            "specialized-comparison": 1.0,
            "unregistered-arm": 0.0,
        }
        mutations.append(("summary_keys", rehash(summary_keys), "arm_macro_pass_at_1"))

        bootstrap_roles = copy.deepcopy(self.compression)
        bootstrap_roles["bootstrap"]["policy"]["reference_arm"] = (
            "specialized-comparison"
        )
        mutations.append(("bootstrap", rehash(bootstrap_roles), "bootstrap.policy.reference_arm"))

        randomization_roles = copy.deepcopy(self.compression)
        randomization_roles["randomization_test"]["policy"][
            "comparison_arm"
        ] = "dense-reference"
        mutations.append(
            (
                "randomization",
                rehash(randomization_roles),
                "randomization_test.policy.comparison_arm",
            )
        )

        contrast_version = copy.deepcopy(self.compression)
        contrast_version["bindings"]["registry_contrast"]["version"] = "2.0.0"
        mutations.append(("contrast_version", rehash(contrast_version), "registry_contrast.version"))

        contrast_direction = copy.deepcopy(self.compression)
        contrast_direction["bindings"]["registry_contrast"]["direction"] = (
            "reference_minus_comparison"
        )
        mutations.append(
            (
                "contrast_direction",
                rehash(contrast_direction),
                "registry_contrast.direction",
            )
        )

        for label, mutated, message in mutations:
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    ConfirmatoryAnalysisValidationError, message
                ):
                    finalize_confirmatory_family([self.fixed, mutated])


if __name__ == "__main__":
    unittest.main()
