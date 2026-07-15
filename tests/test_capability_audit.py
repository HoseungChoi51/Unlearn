from __future__ import annotations

import copy
import hashlib
import math
import unittest
from pathlib import Path

from cbds.capability_audit import (
    PLAN_CANDIDATE_FAMILY_IDS,
    PLAN_CANDIDATE_ROSTER_HASH_DOMAIN,
    PLAN_CANDIDATE_ROSTER_SHA256,
    SOURCE_PLAN_SHA256,
    CapabilityAuditValidationError,
    content_address_capability_audit_result,
    content_address_capability_audit_spec,
    evaluate_capability_support_gate,
    validate_capability_audit_result,
    validate_capability_audit_spec,
    value_sha256,
)


ROOT = Path(__file__).resolve().parents[1]
OBJECTIVE_IDS = {
    "korean-language-use",
    "mandarin-language-use",
    "spanish-language-use",
    "advanced-mathematics",
    "biomedical-factual-knowledge",
    "legal-factual-knowledge",
    "geographic-factual-knowledge",
    "creative-long-form-prose",
}


def digest(number: int) -> str:
    return format(number, "064x")


def authorizations() -> dict[str, bool]:
    return {
        "irrelevance_inferred": False,
        "sacrifice_authorized": False,
        "training_authorized": False,
        "claim_authorized": False,
    }


def valid_spec() -> dict:
    candidates = []
    for index, capability_id in enumerate(PLAN_CANDIDATE_FAMILY_IDS):
        objective = capability_id in OBJECTIVE_IDS
        candidates.append(
            {
                "capability_id": capability_id,
                "designation": "audited_candidate_not_presumed_irrelevant",
                "evaluation_kind": "objective" if objective else "executable",
                "suite_sha256": digest(100 + index),
                "verifier_validation_sha256": digest(200 + index),
                "item_count": 400,
                "variant_protocol": {
                    "prompt_variant_count": 2,
                    "prefix_variant_count": 2,
                    "assignment_sha256": digest(300 + index),
                    "coverage_rule": (
                        "full_prompt_prefix_cross_product_per_semantic_item"
                    ),
                },
                "chance": (
                    {
                        "successes_numerator": 1,
                        "trials_denominator": 4,
                        "basis_sha256": digest(400 + index),
                    }
                    if objective
                    else None
                ),
                "signed_transfer_probe": {
                    "intervention_id": f"probe-{index:02d}",
                    "intervention_sha256": digest(500 + index),
                    "pairing_manifest_sha256": digest(600 + index),
                    "target_capability_id": "unix-toolbox-terminal-scripting",
                    "target_suite_sha256": digest(1),
                    "target_item_count": 400,
                    "registered_direction": "candidate_down_target_up",
                },
            }
        )
    return content_address_capability_audit_spec(
        {
            "record_type": "cbds.capability-audit-spec",
            "schema_version": "1.0.0",
            "audit_id": "qwen3-capability-audit-v1",
            "evidence_scope": (
                "prospective_floor_and_signed_transfer_screen_not_irrelevance_"
                "or_training_authorization"
            ),
            "source_plan_sha256": SOURCE_PLAN_SHA256,
            "candidate_roster_sha256": PLAN_CANDIDATE_ROSTER_SHA256,
            "model": {
                "model_id": "Qwen/Qwen3-0.6B-Base",
                "revision": "da87bfb608c14b7cf20ba1ce41287e8de496c0cd",
                "architecture": "dense",
                "physical_parameters": 596_049_920,
                "artifact_sha256": digest(10),
                "model_config_sha256": digest(11),
                "tokenizer_sha256": digest(12),
                "inspection_report_sha256": digest(13),
            },
            "protected_capabilities": [
                {
                    "capability_id": "unix-toolbox-terminal-scripting",
                    "designation": "protected_target",
                    "suite_sha256": digest(1),
                    "item_count": 400,
                },
                {
                    "capability_id": "english-instruction-comprehension",
                    "designation": "protected_prerequisite",
                    "suite_sha256": digest(2),
                    "item_count": 400,
                },
                {
                    "capability_id": "python-standard-library-scripting",
                    "designation": "protected_prerequisite",
                    "suite_sha256": digest(3),
                    "item_count": 400,
                },
            ],
            "candidate_families": candidates,
            "policy": {
                "candidate_item_count": 400,
                "executable_min_successes": 20,
                "objective_min_percentage_points_above_chance": 10,
                "minimum_prompt_variants": 2,
                "minimum_prefix_variants": 2,
                "paired_before_after_required": True,
                "signed_transfer_required": True,
                "eligibility_semantics": (
                    "above_floor_and_registered_signed_transfer_direction_for_followup_audit_only"
                ),
            },
            "authorizations": authorizations(),
        }
    )


def paired(pair_count: int, before: int, after: int, evidence: int) -> dict:
    both_success = min(before, after)
    before_only = before - both_success
    after_only = after - both_success
    both_failure = pair_count - max(before, after)
    return {
        "pair_count": pair_count,
        "both_success": both_success,
        "before_only": before_only,
        "after_only": after_only,
        "both_failure": both_failure,
        "before_successes": before,
        "after_successes": after,
        "task_result_pairs_sha256": digest(evidence),
    }


def valid_result(spec: dict) -> dict:
    candidate_results = []
    for index, candidate in enumerate(spec["candidate_families"]):
        before = 150 if candidate["evaluation_kind"] == "objective" else 40
        candidate_results.append(
            {
                "capability_id": candidate["capability_id"],
                "evaluation_kind": candidate["evaluation_kind"],
                "suite_sha256": candidate["suite_sha256"],
                "item_count": 400,
                "variant_coverage": {
                    "semantic_item_count": 400,
                    "prompt_variant_count": 2,
                    "prefix_variant_count": 2,
                    "raw_observation_count": 1600,
                    "assignment_sha256": candidate["variant_protocol"][
                        "assignment_sha256"
                    ],
                    "coverage_evidence_sha256": digest(700 + index),
                },
                "capability_before_after": paired(
                    400, before, before - 10, 800 + index
                ),
                "signed_transfer": {
                    "intervention_id": candidate["signed_transfer_probe"][
                        "intervention_id"
                    ],
                    "intervention_sha256": candidate["signed_transfer_probe"][
                        "intervention_sha256"
                    ],
                    "pairing_manifest_sha256": candidate["signed_transfer_probe"][
                        "pairing_manifest_sha256"
                    ],
                    "target_capability_id": "unix-toolbox-terminal-scripting",
                    "target_suite_sha256": digest(1),
                    "registered_direction": "candidate_down_target_up",
                    "target_before_after": paired(400, 100, 110, 900 + index),
                    "aggregate_evidence_sha256": digest(1000 + index),
                },
            }
        )
    return content_address_capability_audit_result(
        {
            "record_type": "cbds.capability-audit-result",
            "schema_version": "1.0.0",
            "completion_status": "complete",
            "evidence_scope": (
                "completed_aggregate_projection_not_task_level_attestation_or_causal_claim"
            ),
            "audit_spec_sha256": spec["audit_spec_sha256"],
            "model_binding": {
                "artifact_sha256": spec["model"]["artifact_sha256"],
                "tokenizer_sha256": spec["model"]["tokenizer_sha256"],
                "inspection_report_sha256": spec["model"][
                    "inspection_report_sha256"
                ],
            },
            "candidate_results": candidate_results,
            "authorizations": authorizations(),
        }
    )


def resign_spec(spec: dict) -> dict:
    unsigned = copy.deepcopy(spec)
    unsigned.pop("audit_spec_sha256", None)
    return content_address_capability_audit_spec(unsigned)


def resign_result(result: dict) -> dict:
    unsigned = copy.deepcopy(result)
    unsigned.pop("result_sha256", None)
    return content_address_capability_audit_result(unsigned)


class CapabilityAuditContractTests(unittest.TestCase):
    def test_source_plan_pin_identifies_exact_plan_bytes(self) -> None:
        self.assertEqual(
            SOURCE_PLAN_SHA256,
            hashlib.sha256((ROOT / "PLAN.md").read_bytes()).hexdigest(),
        )

    def setUp(self) -> None:
        self.spec = valid_spec()
        self.result = valid_result(self.spec)

    def test_valid_contract_returns_only_followup_candidates_and_false_authorizations(
        self,
    ) -> None:
        validated_spec = validate_capability_audit_spec(self.spec)
        validated_result = validate_capability_audit_result(self.spec, self.result)
        decision = evaluate_capability_support_gate(self.spec, self.result)
        self.assertEqual(validated_spec, self.spec)
        self.assertEqual(validated_result, self.result)
        self.assertEqual(
            decision["eligible_candidate_ids"], list(PLAN_CANDIDATE_FAMILY_IDS)
        )
        self.assertEqual(decision["evaluated_candidate_count"], 13)
        for field in (
            "irrelevance_inferred",
            "sacrifice_authorized",
            "training_authorized",
            "claim_authorized",
        ):
            self.assertFalse(decision[field])
        unsigned = dict(decision)
        declared = unsigned.pop("decision_sha256")
        self.assertEqual(declared, value_sha256(unsigned))

    def test_validation_and_content_addressing_are_defensive(self) -> None:
        validated = validate_capability_audit_spec(self.spec)
        validated["model"]["model_id"] = "mutated"
        self.assertEqual(self.spec["model"]["model_id"], "Qwen/Qwen3-0.6B-Base")
        unsigned = copy.deepcopy(self.spec)
        unsigned.pop("audit_spec_sha256")
        addressed = content_address_capability_audit_spec(unsigned)
        unsigned["model"]["model_id"] = "later-mutation"
        self.assertEqual(addressed["model"]["model_id"], "Qwen/Qwen3-0.6B-Base")

    def test_content_hash_tampering_fails_for_both_records(self) -> None:
        tampered_spec = copy.deepcopy(self.spec)
        tampered_spec["audit_id"] = "tampered"
        with self.assertRaisesRegex(CapabilityAuditValidationError, "does not hash"):
            validate_capability_audit_spec(tampered_spec)
        tampered_result = copy.deepcopy(self.result)
        tampered_result["candidate_results"][0]["capability_before_after"][
            "before_successes"
        ] += 1
        with self.assertRaisesRegex(
            CapabilityAuditValidationError, "does not match|does not hash"
        ):
            validate_capability_audit_result(self.spec, tampered_result)

    def test_unknown_and_missing_fields_fail_at_nested_levels(self) -> None:
        mutations = []
        extra = copy.deepcopy(self.spec)
        extra["model"]["unregistered"] = "field"
        mutations.append(extra)
        missing = copy.deepcopy(self.spec)
        del missing["candidate_families"][0]["verifier_validation_sha256"]
        mutations.append(missing)
        nested = copy.deepcopy(self.spec)
        nested["candidate_families"][0]["variant_protocol"]["note"] = "extra"
        mutations.append(nested)
        for mutation in mutations:
            with self.subTest(keys=mutation.keys()):
                mutation = resign_spec(mutation)
                with self.assertRaisesRegex(CapabilityAuditValidationError, "fields do not match"):
                    validate_capability_audit_spec(mutation)

    def test_exact_plan_candidate_roster_and_order_are_required(self) -> None:
        missing = copy.deepcopy(self.spec)
        missing["candidate_families"].pop()
        with self.assertRaisesRegex(CapabilityAuditValidationError, "13"):
            validate_capability_audit_spec(resign_spec(missing))
        reordered = copy.deepcopy(self.spec)
        reordered["candidate_families"][0], reordered["candidate_families"][1] = (
            reordered["candidate_families"][1],
            reordered["candidate_families"][0],
        )
        with self.assertRaisesRegex(CapabilityAuditValidationError, "exact PLAN roster"):
            validate_capability_audit_spec(resign_spec(reordered))

    def test_resigned_source_plan_drift_fails(self) -> None:
        spec = copy.deepcopy(self.spec)
        spec["source_plan_sha256"] = digest(9997)
        with self.assertRaisesRegex(CapabilityAuditValidationError, "source_plan_sha256"):
            validate_capability_audit_spec(resign_spec(spec))

    def test_roster_digest_is_domain_separated_and_resigned_drift_fails(self) -> None:
        expected = value_sha256(
            {
                "domain": PLAN_CANDIDATE_ROSTER_HASH_DOMAIN,
                "candidate_family_ids": list(PLAN_CANDIDATE_FAMILY_IDS),
            }
        )
        self.assertEqual(PLAN_CANDIDATE_ROSTER_SHA256, expected)
        self.assertNotEqual(
            PLAN_CANDIDATE_ROSTER_SHA256,
            value_sha256(list(PLAN_CANDIDATE_FAMILY_IDS)),
        )
        spec = copy.deepcopy(self.spec)
        spec["candidate_roster_sha256"] = digest(9996)
        with self.assertRaisesRegex(
            CapabilityAuditValidationError, "candidate_roster_sha256"
        ):
            validate_capability_audit_spec(resign_spec(spec))

    def test_every_candidate_requires_exactly_400_semantic_items(self) -> None:
        for count in (399, 401, True):
            spec = copy.deepcopy(self.spec)
            spec["candidate_families"][0]["item_count"] = count
            with self.subTest(count=count), self.assertRaisesRegex(
                CapabilityAuditValidationError, "item_count"
            ):
                validate_capability_audit_spec(resign_spec(spec))

    def test_multiple_prompt_and_prefix_variants_are_mandatory(self) -> None:
        for field in ("prompt_variant_count", "prefix_variant_count"):
            spec = copy.deepcopy(self.spec)
            spec["candidate_families"][0]["variant_protocol"][field] = 1
            with self.subTest(field=field), self.assertRaisesRegex(
                CapabilityAuditValidationError, field
            ):
                validate_capability_audit_spec(resign_spec(spec))

    def test_completed_result_must_prove_full_registered_variant_coverage(self) -> None:
        for field, value in (
            ("raw_observation_count", 1599),
            ("prompt_variant_count", 3),
            ("assignment_sha256", digest(9999)),
        ):
            result = copy.deepcopy(self.result)
            result["candidate_results"][0]["variant_coverage"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(
                CapabilityAuditValidationError, field
            ):
                validate_capability_audit_result(self.spec, resign_result(result))

    def test_executable_and_objective_chance_contracts_are_disjoint(self) -> None:
        executable_index = PLAN_CANDIDATE_FAMILY_IDS.index("c-cpp-programming")
        executable = copy.deepcopy(self.spec)
        executable["candidate_families"][executable_index]["chance"] = {
            "successes_numerator": 1,
            "trials_denominator": 4,
            "basis_sha256": digest(9998),
        }
        with self.assertRaisesRegex(CapabilityAuditValidationError, "null for executable"):
            validate_capability_audit_spec(resign_spec(executable))
        objective = copy.deepcopy(self.spec)
        objective["candidate_families"][0]["chance"] = None
        with self.assertRaisesRegex(CapabilityAuditValidationError, "JSON object"):
            validate_capability_audit_spec(resign_spec(objective))

    def test_objective_chance_must_be_explicit_exact_rational(self) -> None:
        for chance in (
            0.25,
            {
                "successes_numerator": True,
                "trials_denominator": 4,
                "basis_sha256": digest(5),
            },
            {
                "successes_numerator": 10,
                "trials_denominator": 10,
                "basis_sha256": digest(5),
            },
        ):
            spec = copy.deepcopy(self.spec)
            spec["candidate_families"][0]["chance"] = chance
            with self.subTest(chance=chance), self.assertRaises(
                CapabilityAuditValidationError
            ):
                validate_capability_audit_spec(resign_spec(spec))

    def test_executable_floor_is_inclusive_at_20_successes(self) -> None:
        index = PLAN_CANDIDATE_FAMILY_IDS.index("c-cpp-programming")
        result = copy.deepcopy(self.result)
        result["candidate_results"][index]["capability_before_after"] = paired(
            400, 20, 19, 5000
        )
        decision = evaluate_capability_support_gate(self.spec, resign_result(result))
        self.assertIn("c-cpp-programming", decision["eligible_candidate_ids"])

        result["candidate_results"][index]["capability_before_after"] = paired(
            400, 19, 18, 5001
        )
        decision = evaluate_capability_support_gate(self.spec, resign_result(result))
        self.assertNotIn("c-cpp-programming", decision["eligible_candidate_ids"])
        self.assertFalse(decision["claim_authorized"])

    def test_objective_floor_is_exactly_ten_points_above_declared_chance(self) -> None:
        result = copy.deepcopy(self.result)
        result["candidate_results"][0]["capability_before_after"] = paired(
            400, 140, 139, 5100
        )
        decision = evaluate_capability_support_gate(self.spec, resign_result(result))
        self.assertIn("korean-language-use", decision["eligible_candidate_ids"])

        result["candidate_results"][0]["capability_before_after"] = paired(
            400, 139, 138, 5101
        )
        decision = evaluate_capability_support_gate(self.spec, resign_result(result))
        self.assertNotIn("korean-language-use", decision["eligible_candidate_ids"])

    def test_floor_without_registered_signed_direction_is_not_eligible(self) -> None:
        cases = (
            (40, 50, 100, 110),
            (40, 30, 100, 100),
            (40, 30, 110, 100),
        )
        for before, after, target_before, target_after in cases:
            result = copy.deepcopy(self.result)
            result["candidate_results"][3]["capability_before_after"] = paired(
                400, before, after, 5200
            )
            result["candidate_results"][3]["signed_transfer"][
                "target_before_after"
            ] = paired(400, target_before, target_after, 5201)
            decision = evaluate_capability_support_gate(self.spec, resign_result(result))
            with self.subTest(case=(before, after, target_before, target_after)):
                self.assertNotIn("c-cpp-programming", decision["eligible_candidate_ids"])
                self.assertFalse(decision["training_authorized"])

    def test_floor_results_never_infer_irrelevance_sacrifice_or_authority(self) -> None:
        result = copy.deepcopy(self.result)
        for index, candidate_result in enumerate(result["candidate_results"]):
            candidate_result["capability_before_after"] = paired(
                400, 0, 0, 5300 + index
            )
        decision = evaluate_capability_support_gate(self.spec, resign_result(result))
        self.assertEqual(decision["eligible_candidate_ids"], [])
        for field in (
            "irrelevance_inferred",
            "sacrifice_authorized",
            "training_authorized",
            "claim_authorized",
        ):
            self.assertIs(decision[field], False)

    def test_resigned_true_authorization_flags_still_fail_closed(self) -> None:
        for field in (
            "irrelevance_inferred",
            "sacrifice_authorized",
            "training_authorized",
            "claim_authorized",
        ):
            spec = copy.deepcopy(self.spec)
            spec["authorizations"][field] = True
            with self.subTest(record="spec", field=field), self.assertRaisesRegex(
                CapabilityAuditValidationError, "must remain false"
            ):
                validate_capability_audit_spec(resign_spec(spec))
            result = copy.deepcopy(self.result)
            result["authorizations"][field] = True
            with self.subTest(record="result", field=field), self.assertRaisesRegex(
                CapabilityAuditValidationError, "must remain false"
            ):
                validate_capability_audit_result(self.spec, resign_result(result))

    def test_model_must_be_exact_dense_and_sub_billion(self) -> None:
        for field, value in (
            ("architecture", "moe"),
            ("physical_parameters", 1_000_000_000),
            ("artifact_sha256", "A" * 64),
        ):
            spec = copy.deepcopy(self.spec)
            spec["model"][field] = value
            with self.subTest(field=field), self.assertRaises(
                CapabilityAuditValidationError
            ):
                validate_capability_audit_spec(resign_spec(spec))

    def test_result_model_and_suite_hashes_must_match_spec_exactly(self) -> None:
        model = copy.deepcopy(self.result)
        model["model_binding"]["artifact_sha256"] = digest(7000)
        with self.assertRaisesRegex(CapabilityAuditValidationError, "artifact_sha256"):
            validate_capability_audit_result(self.spec, resign_result(model))
        suite = copy.deepcopy(self.result)
        suite["candidate_results"][0]["suite_sha256"] = digest(7001)
        with self.assertRaisesRegex(CapabilityAuditValidationError, "suite_sha256"):
            validate_capability_audit_result(self.spec, resign_result(suite))

    def test_protected_target_and_prerequisite_designations_are_mandatory(self) -> None:
        duplicate_target = copy.deepcopy(self.spec)
        duplicate_target["protected_capabilities"][1]["designation"] = "protected_target"
        with self.assertRaisesRegex(CapabilityAuditValidationError, "exactly one"):
            validate_capability_audit_spec(resign_spec(duplicate_target))
        wrong_target = copy.deepcopy(self.spec)
        wrong_target["protected_capabilities"][0]["capability_id"] = "other-target"
        with self.assertRaisesRegex(CapabilityAuditValidationError, "unix-toolbox"):
            validate_capability_audit_spec(resign_spec(wrong_target))
        unsorted = copy.deepcopy(self.spec)
        unsorted["protected_capabilities"][1], unsorted["protected_capabilities"][2] = (
            unsorted["protected_capabilities"][2],
            unsorted["protected_capabilities"][1],
        )
        with self.assertRaisesRegex(CapabilityAuditValidationError, "ordered"):
            validate_capability_audit_spec(resign_spec(unsorted))

    def test_candidate_and_protected_suite_hashes_cannot_alias(self) -> None:
        spec = copy.deepcopy(self.spec)
        spec["candidate_families"][0]["suite_sha256"] = spec[
            "protected_capabilities"
        ][0]["suite_sha256"]
        with self.assertRaisesRegex(CapabilityAuditValidationError, "distinct suite hash"):
            validate_capability_audit_spec(resign_spec(spec))

    def test_completed_result_requires_every_candidate_in_frozen_order(self) -> None:
        missing = copy.deepcopy(self.result)
        missing["candidate_results"].pop()
        with self.assertRaisesRegex(CapabilityAuditValidationError, "13"):
            validate_capability_audit_result(self.spec, resign_result(missing))
        reordered = copy.deepcopy(self.result)
        reordered["candidate_results"][0], reordered["candidate_results"][1] = (
            reordered["candidate_results"][1],
            reordered["candidate_results"][0],
        )
        with self.assertRaisesRegex(CapabilityAuditValidationError, "capability_id"):
            validate_capability_audit_result(self.spec, resign_result(reordered))

    def test_paired_cells_and_marginals_are_recomputed(self) -> None:
        cases = []
        bad_sum = copy.deepcopy(self.result)
        bad_sum["candidate_results"][0]["capability_before_after"]["both_failure"] -= 1
        cases.append(bad_sum)
        bad_before = copy.deepcopy(self.result)
        bad_before["candidate_results"][0]["capability_before_after"][
            "before_successes"
        ] -= 1
        cases.append(bad_before)
        bool_count = copy.deepcopy(self.result)
        bool_count["candidate_results"][0]["capability_before_after"][
            "before_only"
        ] = True
        cases.append(bool_count)
        for case in cases:
            with self.subTest(), self.assertRaises(CapabilityAuditValidationError):
                validate_capability_audit_result(self.spec, resign_result(case))

    def test_signed_transfer_probe_identity_and_target_pair_count_are_bound(self) -> None:
        intervention = copy.deepcopy(self.result)
        intervention["candidate_results"][0]["signed_transfer"][
            "intervention_sha256"
        ] = digest(8000)
        with self.assertRaisesRegex(CapabilityAuditValidationError, "intervention_sha256"):
            validate_capability_audit_result(self.spec, resign_result(intervention))
        target = copy.deepcopy(self.result)
        target["candidate_results"][0]["signed_transfer"]["target_before_after"] = paired(
            399, 100, 110, 8001
        )
        with self.assertRaisesRegex(CapabilityAuditValidationError, "pair_count"):
            validate_capability_audit_result(self.spec, resign_result(target))

    def test_result_must_bind_the_exact_spec_and_be_complete(self) -> None:
        wrong_spec = copy.deepcopy(self.result)
        wrong_spec["audit_spec_sha256"] = digest(9000)
        with self.assertRaisesRegex(CapabilityAuditValidationError, "audit_spec_sha256"):
            validate_capability_audit_result(self.spec, resign_result(wrong_spec))
        incomplete = copy.deepcopy(self.result)
        incomplete["completion_status"] = "partial"
        with self.assertRaisesRegex(CapabilityAuditValidationError, "completion_status"):
            validate_capability_audit_result(self.spec, resign_result(incomplete))

    def test_policy_thresholds_cannot_be_relaxed_by_resigning(self) -> None:
        for field, value in (
            ("candidate_item_count", 399),
            ("executable_min_successes", 19),
            ("objective_min_percentage_points_above_chance", 9),
            ("signed_transfer_required", False),
        ):
            spec = copy.deepcopy(self.spec)
            spec["policy"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(
                CapabilityAuditValidationError, field
            ):
                validate_capability_audit_spec(resign_spec(spec))

    def test_non_json_or_non_finite_content_cannot_be_addressed(self) -> None:
        for bad in (math.nan, math.inf, {1, 2}):
            record = {"bad": bad}
            with self.subTest(bad=type(bad).__name__), self.assertRaises(
                CapabilityAuditValidationError
            ):
                content_address_capability_audit_spec(record)


if __name__ == "__main__":
    unittest.main()
