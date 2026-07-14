from __future__ import annotations

import copy
from hashlib import sha256
import inspect
import unittest
from unittest.mock import patch

from cbds.campaign_registry import CampaignRegistryValidationError
from cbds.confirmatory_analysis import _validated_contrast_for_family
from cbds.evaluation_specs import (
    TaskResultEvaluationBindingError,
    section_policy_sha256,
    select_scored_task_results_against_evaluation_spec,
    validate_evaluation_spec,
)
from cbds.manifests import value_sha256
from cbds.outcome_binding import (
    OutcomeBindingValidationError,
    bind_confirmatory_binary_cube,
    run_confirmatory_contrast_from_collections,
)
from cbds.statistics import validate_paired_binary_outcomes
from cbds.task_results import fixture_id_set_sha256, ordered_fixture_ids_sha256
from tests.test_campaign_registry import (
    ARM_IDS,
    _seed_records_for_profile,
    campaign_documents,
    confirmation_registry,
)
from tests.test_evaluation_specs import contrast_plan
from tests.test_task_results import opaque_fixture_id, opaque_task_id, static_result


CODE = b"cbds artifact-bound confirmatory analysis implementation\n"
REVISION = "1" * 40


def complete_confirmatory_documents() -> tuple[dict, dict, dict, dict, dict, dict]:
    policy, specs, completed = campaign_documents(
        ("screening", "confirmation")
    )
    registry, evaluations = confirmation_registry(policy, specs, completed)
    # Bind the actual analysis-code bytes used by the collection-driven wrapper.
    for evaluation_id, raw in list(evaluations.items()):
        evaluation = copy.deepcopy(raw)
        analysis = evaluation["analysis_plan"]
        analysis["analysis_code_revision"] = REVISION
        analysis["analysis_code_sha256"] = sha256(CODE).hexdigest()
        analysis["policy_sha256"] = section_policy_sha256(analysis)
        evaluations[evaluation_id] = validate_evaluation_spec(evaluation)
    for entry in registry["runs"]:
        for binding in entry["evaluations"]:
            binding["evaluation_spec_sha256"] = value_sha256(
                evaluations[binding["evaluation_id"]]
            )

    collections: dict[str, list[dict]] = {}
    confirmation_entries = [
        entry
        for entry in registry["runs"]
        if entry["cohort_id"] == "confirm-primary"
    ]
    task_rank = {
        commitment["prompt_id"]: index
        for index, commitment in enumerate(
            next(iter(evaluations.values()))["task_commitments"]["commitments"]
        )
    }
    for entry in confirmation_entries:
        binding = entry["evaluations"][0]
        evaluation = evaluations[binding["evaluation_id"]]
        is_comparison = entry["arm_id"] == "recycle-ffn"
        collection: list[dict] = []
        for commitment in evaluation["task_commitments"]["commitments"]:
            rank = task_rank[commitment["prompt_id"]]
            base_pass = rank % 2 == 0
            # Comparison adds exactly 40 successes without changing task identity.
            passed = base_pass or (is_comparison and rank < 80)
            # These are the projections returned by the mocked, independently
            # tested collection validator/selector in the derivation tests.
            collection.append(
                {
                    "prompt_id": commitment["prompt_id"],
                    "terminal_status": "passed" if passed else "functional_failure",
                }
            )
        collections[binding["evaluation_id"]] = collection
        binding["task_result_collection_sha256"] = value_sha256(collection)
        binding["task_result_record_count"] = len(collection)

    cohort = next(
        item
        for item in registry["cohorts"]
        if item["cohort_id"] == "confirm-primary"
    )
    seed_records = _seed_records_for_profile(specs, "confirmation")
    template = evaluations[confirmation_entries[0]["evaluations"][0]["evaluation_id"]]
    cube_projection = {
        "cube_id": "sealed-id-primary",
        "cohort_id": "confirm-primary",
        "profile": "confirmation",
        "arm_ids": list(ARM_IDS),
        "contrast": contrast_plan("dense-sft", "recycle-ffn"),
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
                "task_result_collection_sha256": entry["evaluations"][0][
                    "task_result_collection_sha256"
                ],
            }
            for entry in confirmation_entries
        ],
    }
    cohort["evaluation_cubes"][0]["paired_cube_sha256"] = value_sha256(
        cube_projection
    )
    cohort["evaluation_cubes"][0]["result_coverage"] = "complete_task_results"
    return registry, policy, specs, completed, evaluations, collections


def _refresh_confirmatory_cube_commitment(
    registry: dict,
    specs: dict[str, dict],
) -> None:
    confirmation_entries = [
        entry
        for entry in registry["runs"]
        if entry["cohort_id"] == "confirm-primary"
    ]
    cohort = next(
        item
        for item in registry["cohorts"]
        if item["cohort_id"] == "confirm-primary"
    )
    cube = cohort["evaluation_cubes"][0]
    seed_records = _seed_records_for_profile(specs, "confirmation")
    cube_projection = {
        "cube_id": cube["cube_id"],
        "cohort_id": cohort["cohort_id"],
        "profile": cohort["profile"],
        "arm_ids": list(ARM_IDS),
        "contrast": copy.deepcopy(cohort["contrast"]),
        "training_seeds": seed_records,
        "task_count": cube["task_count"],
        "task_commitment_set_sha256": cube["task_commitment_set_sha256"],
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
                "task_result_collection_sha256": entry["evaluations"][0][
                    "task_result_collection_sha256"
                ],
            }
            for entry in confirmation_entries
        ],
    }
    cube["paired_cube_sha256"] = value_sha256(cube_projection)
    cube["result_coverage"] = "complete_task_results"


def _bound_confirmatory_static_result(
    evaluation: dict,
    commitment: dict,
    task_index: int,
) -> dict:
    result = static_result()
    fixture_ids = [
        opaque_fixture_id(
            f"confirmatory-sealed_id-{task_index}-fixture-{fixture_index}"
        )
        for fixture_index in range(commitment["fixture_count"])
    ]
    if commitment["prompt_id"] != opaque_task_id(
        f"confirmatory-sealed_id-{task_index}"
    ):
        raise AssertionError("confirmatory prompt identity does not match task index")
    for fixture, fixture_id in zip(result["fixture_outcomes"], fixture_ids):
        fixture["fixture_id"] = fixture_id
    split = evaluation["benchmark"]["split"]
    result.update(
        {
            "evaluation_id": evaluation["evaluation_id"],
            "evaluation_spec_sha256": value_sha256(evaluation),
            "run_id": evaluation["artifact"]["completed_run_id"],
            "benchmark_id": evaluation["benchmark"]["benchmark_id"],
            "mode": evaluation["mode"],
            "split_id": split["name"],
            "split_role": split["role"],
            "sealed": split["sealed"],
            "prompt_id": commitment["prompt_id"],
            "task_record_sha256": commitment["task_record_sha256"],
            "fixture_ids_sha256": fixture_id_set_sha256(fixture_ids),
            "ordered_fixture_ids_sha256": ordered_fixture_ids_sha256(
                fixture_ids
            ),
            "action_limit": evaluation["limits"]["action_limit"],
        }
    )
    result["tool_policy"]["policy_sha256"] = evaluation["tool_policy"][
        "policy_sha256"
    ]
    return result


def complete_schema_valid_confirmatory_documents() -> (
    tuple[dict, dict, dict, dict, dict, dict]
):
    registry, policy, specs, completed, evaluations, _ = (
        complete_confirmatory_documents()
    )
    collections: dict[str, list[dict]] = {}
    confirmation_entries = [
        entry
        for entry in registry["runs"]
        if entry["cohort_id"] == "confirm-primary"
    ]
    task_rank = {
        commitment["prompt_id"]: index
        for index, commitment in enumerate(
            next(iter(evaluations.values()))["task_commitments"]["commitments"]
        )
    }
    task_index_by_prompt = {
        opaque_task_id(f"confirmatory-sealed_id-{task_index}"): task_index
        for task_index in range(1_000)
    }
    for entry in confirmation_entries:
        binding = entry["evaluations"][0]
        evaluation = evaluations[binding["evaluation_id"]]
        is_comparison = entry["arm_id"] == "recycle-ffn"
        collection: list[dict] = []
        for index, commitment in enumerate(
            evaluation["task_commitments"]["commitments"]
        ):
            task_index = task_index_by_prompt[commitment["prompt_id"]]
            result = _bound_confirmatory_static_result(
                evaluation,
                commitment,
                task_index,
            )
            rank = task_rank[commitment["prompt_id"]]
            passed = rank % 2 == 0 or (is_comparison and rank < 80)
            if not passed:
                result["fixture_outcomes"][0]["status"] = "functional_failure"
                result["terminal_status"] = "functional_failure"
            collection.append(result)
        collections[binding["evaluation_id"]] = collection
        binding["task_result_collection_sha256"] = value_sha256(collection)
        binding["task_result_record_count"] = len(collection)
    _refresh_confirmatory_cube_commitment(registry, specs)
    return registry, policy, specs, completed, evaluations, collections


class ArtifactBoundOutcomeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        (
            cls.registry,
            cls.policy,
            cls.specs,
            cls.completed,
            cls.evaluations,
            cls.collections,
        ) = complete_confirmatory_documents()
        # Campaign and collection validators have their own exhaustive suites.
        # Keep this 10,000-cell derivation test bounded by substituting their
        # already-validated return values; separate tests below prove the binder
        # invokes and propagates the joint authority boundary.
        with patch(
            "cbds.outcome_binding.validate_campaign_registry",
            return_value=copy.deepcopy(cls.registry),
        ) as joint, patch(
            "cbds.outcome_binding.select_scored_task_results_against_evaluation_spec",
            side_effect=lambda collection, evaluation: copy.deepcopy(collection),
        ) as selector:
            cls.bound = bind_confirmatory_binary_cube(
                cls.registry,
                cls.policy,
                cls.specs,
                cls.completed,
                cls.evaluations,
                cls.collections,
                cohort_id="confirm-primary",
                cube_id="sealed-id-primary",
            )
        assert joint.call_count == 1
        assert selector.call_count == 10

    def test_derives_complete_canonical_binary_cube_from_scored_results(self) -> None:
        bound = self.bound
        self.assertEqual(
            bound["dimensions"],
            {
                "arm_count": 2,
                "training_seed_count": 5,
                "task_count": 1_000,
                "cell_count": 10_000,
            },
        )
        self.assertEqual(len(bound["source_bindings"]), 10)
        self.assertTrue(
            all(
                binding["scored_task_result_count"] == 1_000
                for binding in bound["source_bindings"]
            )
        )
        cube = validate_paired_binary_outcomes(
            bound["records"],
            reference_arm="dense-sft",
            comparison_arm="recycle-ffn",
            minimum_seeds=5,
            minimum_tasks=1_000,
        )
        self.assertEqual(cube.cell_count, 10_000)
        self.assertEqual(
            bound["outcome_evidence_scope"],
            "derived_from_jointly_validated_registry_bound_scored_task_results",
        )
        self.assertEqual(bound["trust_scope"]["runtime_attestation"], "none")
        self.assertIn("not_verifier_recomputation", bound["trust_scope"]["verifier_evidence"])
        unhashed = copy.deepcopy(bound)
        digest = unhashed.pop("bound_cube_record_sha256")
        self.assertEqual(digest, value_sha256(unhashed))

    def test_binary_labels_equal_selected_terminal_status_not_caller_labels(self) -> None:
        first_binding = self.bound["source_bindings"][0]
        evaluation_id = first_binding["evaluation_id"]
        source_by_task = {
            result["prompt_id"]: result["terminal_status"]
            for result in self.collections[evaluation_id]
        }
        derived = {
            row["task"]: row["passed"]
            for row in self.bound["records"]
            if row["arm"] == first_binding["arm_id"]
            and row["seed"] == first_binding["training_seed"]
        }
        self.assertEqual(
            derived,
            {
                task: 1 if status == "passed" else 0
                for task, status in source_by_task.items()
            },
        )

    def test_analysis_api_has_no_binary_row_injection_parameter(self) -> None:
        parameters = inspect.signature(
            run_confirmatory_contrast_from_collections
        ).parameters
        for forbidden in ("records", "rows", "cells", "outcomes"):
            self.assertNotIn(forbidden, parameters)

    def test_missing_collection_fails_closed_at_joint_registry_boundary(self) -> None:
        missing = dict(self.collections)
        missing.pop(next(iter(missing)))
        with self.assertRaisesRegex(
            OutcomeBindingValidationError, "missing registry IDs"
        ):
            bind_confirmatory_binary_cube(
                self.registry,
                self.policy,
                self.specs,
                self.completed,
                self.evaluations,
                missing,
                cohort_id="confirm-primary",
                cube_id="sealed-id-primary",
            )

    def test_joint_validation_rejection_is_not_bypassed_by_derivation(self) -> None:
        with patch(
            "cbds.outcome_binding.validate_campaign_registry",
            side_effect=CampaignRegistryValidationError(
                "collection canonical digest mismatch"
            ),
        ) as joint, patch(
            "cbds.outcome_binding.select_scored_task_results_against_evaluation_spec"
        ) as selector:
            with self.assertRaisesRegex(
                OutcomeBindingValidationError, "canonical digest mismatch"
            ):
                bind_confirmatory_binary_cube(
                    self.registry,
                    self.policy,
                    self.specs,
                    self.completed,
                    self.evaluations,
                    self.collections,
                    cohort_id="confirm-primary",
                    cube_id="sealed-id-primary",
                )
        self.assertEqual(joint.call_count, 1)
        selector.assert_not_called()

    def test_collection_driven_runner_binds_analysis_to_derived_cube_hash(self) -> None:
        with patch(
            "cbds.outcome_binding.bind_confirmatory_binary_cube",
            return_value=copy.deepcopy(self.bound),
        ):
            result = run_confirmatory_contrast_from_collections(
                self.registry,
                self.policy,
                self.specs,
                self.completed,
                self.evaluations,
                {},
                cohort_id="confirm-primary",
                cube_id="sealed-id-primary",
                contrast_id="artifact-bound-fixed-size",
                analysis_code_bytes=CODE,
                analysis_code_revision=REVISION,
            )
        binding = result["bindings"]["artifact_bound_outcome_cube"]
        self.assertEqual(
            result["outcome_evidence_scope"],
            "artifact_bound_scored_task_result_collections",
        )
        self.assertEqual(
            binding["bound_cube_record_sha256"],
            self.bound["bound_cube_record_sha256"],
        )
        self.assertEqual(binding["runtime_attestation"], "none")
        unhashed = copy.deepcopy(result)
        digest = unhashed.pop("contrast_record_sha256")
        self.assertEqual(digest, value_sha256(unhashed))
        self.assertIs(_validated_contrast_for_family(result, 0), result)


class UnmockedArtifactBoundOutcomeIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        (
            cls.registry,
            cls.policy,
            cls.specs,
            cls.completed,
            cls.evaluations,
            cls.collections,
        ) = complete_schema_valid_confirmatory_documents()
        cls.result = run_confirmatory_contrast_from_collections(
            cls.registry,
            cls.policy,
            cls.specs,
            cls.completed,
            cls.evaluations,
            cls.collections,
            cohort_id="confirm-primary",
            cube_id="sealed-id-primary",
            contrast_id="unmocked-artifact-bound-fixed-size",
            analysis_code_bytes=CODE,
            analysis_code_revision=REVISION,
        )

    def test_real_task_results_flow_through_registry_selection_cube_and_contrast(
        self,
    ) -> None:
        result = self.result
        self.assertEqual(
            result["outcome_evidence_scope"],
            "artifact_bound_scored_task_result_collections",
        )
        self.assertAlmostEqual(result["bootstrap"]["estimate"], 0.04)
        self.assertTrue(result["decisions"]["point_gain"]["met"])
        artifact_cube = result["bindings"]["artifact_bound_outcome_cube"]
        self.assertEqual(artifact_cube["runtime_attestation"], "none")
        self.assertEqual(len(artifact_cube["binary_cells_sha256"]), 64)
        unhashed = copy.deepcopy(result)
        declared = unhashed.pop("contrast_record_sha256")
        self.assertEqual(declared, value_sha256(unhashed))

    def test_collection_content_tamper_fails_at_registry_digest_seam(self) -> None:
        collections = copy.deepcopy(self.collections)
        evaluation_id = sorted(collections)[0]
        collections[evaluation_id][0]["generated_text_sha256"] = "f" * 64
        with self.assertRaisesRegex(
            OutcomeBindingValidationError,
            "task_result_collection_sha256|canonical collection digest",
        ):
            bind_confirmatory_binary_cube(
                self.registry,
                self.policy,
                self.specs,
                self.completed,
                self.evaluations,
                collections,
                cohort_id="confirm-primary",
                cube_id="sealed-id-primary",
            )

    def test_rehashed_collection_cannot_substitute_evaluation_identity(self) -> None:
        evaluation_id = sorted(self.collections)[0]
        collection = copy.deepcopy(self.collections[evaluation_id])
        collection[0]["evaluation_spec_sha256"] = "f" * 64
        with self.assertRaisesRegex(
            TaskResultEvaluationBindingError,
            "evaluation_spec_sha256",
        ):
            select_scored_task_results_against_evaluation_spec(
                collection,
                self.evaluations[evaluation_id],
            )


if __name__ == "__main__":
    unittest.main()
