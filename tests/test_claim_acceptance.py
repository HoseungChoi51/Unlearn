from __future__ import annotations

import copy
import unittest

from cbds.claim_acceptance import (
    CLAIM_ACCEPTANCE_BINDER_VERSION,
    ClaimAcceptanceValidationError,
    bind_confirmatory_lane_claim,
    content_address_claim_evidence,
)
from cbds.manifests import value_sha256


SHA = {
    name: format(index, "064x")
    for index, name in enumerate(
        (
            "family",
            "contrast",
            "source_run",
            "reference_run",
            "comparison_run",
            "source_spec",
            "reference_spec",
            "comparison_spec",
            "source_artifact",
            "reference_artifact",
            "comparison_artifact",
            "source_bundle",
            "reference_bundle",
            "comparison_bundle",
            "tokenizer",
            "source_inspection",
            "reference_inspection",
            "comparison_inspection",
            "precision_layout",
            "reference_config",
            "comparison_config",
            "equal_target_result",
            "bounded_result",
            "protected_result_a",
            "protected_result_b",
            "margin_policy",
            "compression_static_result",
            "hardware_reference",
            "hardware_comparison",
            "hardware_protocol",
            "hardware_stratum",
            "runner_result",
            "independent_static_result",
            "independent_interactive_result",
            "teacher_run_set",
            "teacher_result",
            "target_data",
            "support_data",
            "comparability_policy",
            "artifact_bound_cells",
            "artifact_bound_cube",
            "campaign_registry",
            "campaign_policy",
            "evaluation_spec",
            "compression_contrast",
            "compression_analysis_policy",
            "compression_evaluation_spec",
            "compression_cells",
            "compression_cube",
            "compression_paired_cube",
            "fixed_size_contrast",
            "fixed_size_analysis_policy",
            "fixed_size_evaluation_spec",
            "fixed_size_cells",
            "fixed_size_cube",
            "fixed_size_paired_cube",
            "source_architecture_layout",
            "compressed_architecture_layout",
        ),
        start=1,
    )
}

SCOPES = {
    "cbds.claim-statistical-evidence": (
        "finalized_artifact_bound_contrast_and_family_projection_not_sources_reopened"
    ),
    "cbds.claim-export-evidence": (
        "completed_export_projection_not_completed_run_or_inspection_derived"
    ),
    "cbds.claim-compute-comparison-evidence": (
        "run_accounting_projection_not_completed_run_derived"
    ),
    "cbds.claim-noninferiority-evidence": (
        "endpoint_projection_not_task_collection_derived"
    ),
    "cbds.claim-hardware-evidence": (
        "hardware_projection_not_hardware_result_derived"
    ),
    "cbds.claim-replication-evidence": (
        "replication_projection_not_campaign_or_task_collection_derived"
    ),
    "cbds.claim-teacher-free-evidence": (
        "teacher_ablation_projection_not_completed_run_or_task_collection_derived"
    ),
}


def envelope(
    record_type: str,
    lane: str,
    payload: dict,
    *,
    reference_arm: str = "direct-baseline",
    comparison_arm: str = "promoted-candidate",
) -> dict:
    return content_address_claim_evidence(
        {
            "record_type": record_type,
            "schema_version": "1.0.0",
            "lane": lane,
            "reference_arm": reference_arm,
            "comparison_arm": comparison_arm,
            "evidence_scope": SCOPES[record_type],
            "payload": payload,
        }
    )


def interval(lower: float, upper: float) -> dict:
    return {"confidence_level": 0.975, "lower": lower, "upper": upper}


def endpoint(
    result_sha256: str,
    *,
    estimate: float = 0.0,
    lower: float = -0.01,
    upper: float = 0.01,
    margin: float = 2.0,
    reference_arm: str = "direct-baseline",
    comparison_arm: str = "promoted-candidate",
) -> dict:
    return {
        "reference_arm": reference_arm,
        "comparison_arm": comparison_arm,
        "result_evidence_sha256": result_sha256,
        "estimate_difference_proportion": estimate,
        "simultaneous_confidence_interval": interval(lower, upper),
        "margin_absolute_points": margin,
        "prospective_margin_policy_sha256": SHA["margin_policy"],
    }


def artifact(
    arm_id: str,
    prefix: str,
    *,
    physical_parameters: int,
    weight_bytes: int,
    bundle_bytes: int,
    average_weight_bits: float = 16.0,
    teacher_enabled: bool = False,
) -> dict:
    return {
        "arm_id": arm_id,
        "completed_run_sha256": SHA[f"{prefix}_run"],
        "run_spec_sha256": SHA[f"{prefix}_spec"],
        "artifact_sha256": SHA[f"{prefix}_artifact"],
        "bundle_sha256": SHA[f"{prefix}_bundle"],
        "tokenizer_sha256": SHA["tokenizer"],
        "inspection_report_sha256": SHA[f"{prefix}_inspection"],
        "architecture_layout_sha256": (
            SHA["source_architecture_layout"]
            if physical_parameters == 600_000_000
            else SHA["compressed_architecture_layout"]
        ),
        "precision_layout_sha256": SHA["precision_layout"],
        "operator_configuration_sha256": (
            SHA["comparison_config"]
            if prefix == "comparison"
            else SHA["reference_config"]
        ),
        "architecture": "dense",
        "format": "safetensors",
        "physical_parameters": physical_parameters,
        "active_parameters": physical_parameters,
        "average_weight_bits": average_weight_bits,
        "weight_bytes": weight_bytes,
        "bundle_bytes": bundle_bytes,
        "teacher_enabled": teacher_enabled,
        "verified_teacher_corpus_sha256": SHA["teacher_result"] if teacher_enabled else None,
    }


def family_contrast_bindings() -> list[dict]:
    bindings: list[dict] = []
    for lane in ("compression", "fixed_size"):
        bindings.append(
            {
                "contrast_id": f"{lane}-primary",
                "lane": lane,
                "contrast_record_sha256": SHA[f"{lane}_contrast"],
                "analysis_policy_sha256": SHA[f"{lane}_analysis_policy"],
                "evaluation_id": f"{lane}-evaluation",
                "evaluation_spec_sha256": SHA[f"{lane}_evaluation_spec"],
                "artifact_bound_outcome_cube": {
                    "binder_version": "1.0.0",
                    "cohort_id": f"{lane}-cohort",
                    "cube_id": f"{lane}-cube",
                    "campaign_registry_sha256": SHA["campaign_registry"],
                    "campaign_policy_sha256": SHA["campaign_policy"],
                    "registry_paired_cube_sha256": SHA[
                        f"{lane}_paired_cube"
                    ],
                    "binary_cells_sha256": SHA[f"{lane}_cells"],
                    "bound_cube_record_sha256": SHA[f"{lane}_cube"],
                    "outcome_evidence_scope": (
                        "derived_from_jointly_validated_registry_bound_scored_"
                        "task_results"
                    ),
                    "runtime_attestation": "none",
                },
            }
        )
    return bindings


def evidence_bundle(lane: str = "fixed_size") -> dict[str, object]:
    if lane == "fixed_size":
        source = artifact(
            "pretrained-source",
            "source",
            physical_parameters=600_000_000,
            weight_bytes=1_200_000_000,
            bundle_bytes=1_210_000_000,
        )
        reference = artifact(
            "direct-baseline",
            "reference",
            physical_parameters=600_000_000,
            weight_bytes=1_200_000_000,
            bundle_bytes=1_210_000_000,
        )
        comparison = artifact(
            "promoted-candidate",
            "comparison",
            physical_parameters=600_000_000,
            weight_bytes=1_200_000_000,
            bundle_bytes=1_210_000_000,
        )
        compression_static = None
        tolerance = 0.0
    else:
        source = artifact(
            "pretrained-source",
            "source",
            physical_parameters=600_000_000,
            weight_bytes=1_200_000_000,
            bundle_bytes=1_210_000_000,
        )
        reference = artifact(
            "direct-baseline",
            "reference",
            physical_parameters=450_000_000,
            weight_bytes=900_000_000,
            bundle_bytes=910_000_000,
        )
        comparison = artifact(
            "promoted-candidate",
            "comparison",
            physical_parameters=450_000_000,
            weight_bytes=900_000_000,
            bundle_bytes=900_000_000,
        )
        compression_static = endpoint(
            SHA["compression_static_result"],
            estimate=0.0,
            lower=-0.005,
            upper=0.01,
            margin=1.0,
            reference_arm="pretrained-source",
        )
        tolerance = 0.05

    family_bindings = family_contrast_bindings()
    selected_statistical_binding = next(
        binding for binding in family_bindings if binding["lane"] == lane
    )
    selected_cube = selected_statistical_binding["artifact_bound_outcome_cube"]
    family_binding_commitment = {
        "commitment_type": "cbds.confirmatory-family-input-contrasts",
        "version": "1.0.0",
        "ordering": "compression_then_fixed_size",
        "bindings": family_bindings,
    }
    statistical = envelope(
        "cbds.claim-statistical-evidence",
        lane,
        {
            "family_record_sha256": SHA["family"],
            "family_contrast_bindings": family_bindings,
            "family_contrast_bindings_sha256": value_sha256(
                family_binding_commitment
            ),
            "contrast_record_sha256": selected_statistical_binding[
                "contrast_record_sha256"
            ],
            "contrast_id": f"{lane}-primary",
            "primary_benchmark_id": "sealed-static-primary",
            "primary_backbone_id": "primary-backbone",
            "direct_baseline_role": (
                "strongest_matched_data_matched_flop_dense"
                if lane == "fixed_size"
                else "strongest_task_agnostic_compression_at_comparable_bytes"
            ),
            "paired_seed_count": 5,
            "estimate_difference_proportion": 0.04,
            "simultaneous_confidence_interval": interval(0.01, 0.07),
            "holm_adjusted_p_value": 0.04,
            "outcome_evidence_scope": (
                "artifact_bound_scored_task_result_collections"
            ),
            "artifact_bound_binary_cells_sha256": selected_cube[
                "binary_cells_sha256"
            ],
            "artifact_bound_cube_record_sha256": selected_cube[
                "bound_cube_record_sha256"
            ],
            "campaign_registry_sha256": SHA["campaign_registry"],
            "evaluation_spec_sha256": selected_statistical_binding[
                "evaluation_spec_sha256"
            ],
        },
    )
    export = envelope(
        "cbds.claim-export-evidence",
        lane,
        {
            "source_artifact": source,
            "direct_baseline_artifact": reference,
            "comparison_artifact": comparison,
            "fixed_size_metadata_tolerance_bytes": 0,
            "comparable_bytes_tolerance_fraction": tolerance,
            "comparable_bytes_policy_sha256": SHA["comparability_policy"],
        },
    )
    compute = [
        envelope(
            "cbds.claim-compute-comparison-evidence",
            lane,
            {
                "comparison_kind": "equal_target_tokens",
                "reference_completed_run_sha256": SHA["source_run"],
                "comparison_completed_run_sha256": SHA["comparison_run"],
                "reference_target_tokens": 16_000_000,
                "comparison_target_tokens": 16_000_000,
                "reference_total_flops": 900,
                "comparison_total_flops": 1_000,
                "performance_evidence_sha256": SHA["equal_target_result"],
                "reference_target_data_sha256": SHA["target_data"],
                "comparison_target_data_sha256": SHA["target_data"],
                "reference_support_data_sha256": SHA["support_data"],
                "comparison_support_data_sha256": SHA["support_data"],
                "reference_teacher_corpus_sha256": None,
                "comparison_teacher_corpus_sha256": None,
            },
            reference_arm="ordinary-dense-sft",
        ),
        envelope(
            "cbds.claim-compute-comparison-evidence",
            lane,
            {
                "comparison_kind": "equal_total_flops",
                "reference_completed_run_sha256": SHA["reference_run"],
                "comparison_completed_run_sha256": SHA["comparison_run"],
                "reference_target_tokens": 18_000_000,
                "comparison_target_tokens": 16_000_000,
                "reference_total_flops": 1_000,
                "comparison_total_flops": 1_000,
                "performance_evidence_sha256": selected_statistical_binding[
                    "contrast_record_sha256"
                ],
                "reference_target_data_sha256": SHA["target_data"],
                "comparison_target_data_sha256": SHA["target_data"],
                "reference_support_data_sha256": SHA["support_data"],
                "comparison_support_data_sha256": SHA["support_data"],
                "reference_teacher_corpus_sha256": None,
                "comparison_teacher_corpus_sha256": None,
            },
        ),
    ]
    protected = [
        {
            "capability_id": "english-instruction",
            "endpoint": endpoint(SHA["protected_result_a"], lower=-0.01),
        },
        {
            "capability_id": "python-scripting",
            "endpoint": endpoint(SHA["protected_result_b"], lower=-0.005),
        },
    ]
    roster = [
        {
            "capability_id": item["capability_id"],
            "margin_absolute_points": item["endpoint"]["margin_absolute_points"],
            "prospective_margin_policy_sha256": item["endpoint"][
                "prospective_margin_policy_sha256"
            ],
        }
        for item in protected
    ]
    noninferiority = envelope(
        "cbds.claim-noninferiority-evidence",
        lane,
        {
            "bounded_terminal": endpoint(SHA["bounded_result"], lower=-0.01),
            "protected_capability_roster_sha256": value_sha256(roster),
            "protected_capabilities": protected,
            "compression_static_source": compression_static,
        },
    )
    hardware_reference = reference if lane == "fixed_size" else source
    hardware = envelope(
        "cbds.claim-hardware-evidence",
        lane,
        {
            "reference_role": "direct_baseline" if lane == "fixed_size" else "precompression_source",
            "reference_completed_run_sha256": hardware_reference["completed_run_sha256"],
            "comparison_completed_run_sha256": comparison["completed_run_sha256"],
            "reference_hardware_result_sha256": SHA["hardware_reference"],
            "comparison_hardware_result_sha256": SHA["hardware_comparison"],
            "hardware_protocol_sha256": SHA["hardware_protocol"],
            "hardware_stratum_sha256": SHA["hardware_stratum"],
            "peak_memory_metric": "peak_device_memory_bytes",
            "reference_peak_memory_bytes": 2_000_000_000,
            "comparison_peak_memory_bytes": (
                2_000_000_000 if lane == "fixed_size" else 1_500_000_000
            ),
            "reference_weight_bytes": hardware_reference["weight_bytes"],
            "comparison_weight_bytes": comparison["weight_bytes"],
            "reference_bundle_bytes": hardware_reference["bundle_bytes"],
            "comparison_bundle_bytes": comparison["bundle_bytes"],
        },
        reference_arm=(
            "direct-baseline" if lane == "fixed_size" else "pretrained-source"
        ),
    )
    replications = [
        envelope(
            "cbds.claim-replication-evidence",
            lane,
            {
                "replication_role": "runner_up_static",
                "benchmark_id": "sealed-static-primary",
                "backbone_id": "runner-up-backbone",
                "result_evidence_sha256": SHA["runner_result"],
                "operator_configuration_sha256": SHA["comparison_config"],
                "paired_seed_count": 5,
                "estimate_difference_proportion": 0.02,
                "simultaneous_confidence_interval": interval(0.001, 0.04),
            },
            reference_arm="runner-up-direct-baseline",
            comparison_arm="runner-up-promoted-candidate",
        ),
        envelope(
            "cbds.claim-replication-evidence",
            lane,
            {
                "replication_role": "independent_static",
                "benchmark_id": "bashbench-independent",
                "backbone_id": "primary-backbone",
                "result_evidence_sha256": SHA["independent_static_result"],
                "operator_configuration_sha256": SHA["comparison_config"],
                "paired_seed_count": 5,
                "estimate_difference_proportion": 0.02,
                "simultaneous_confidence_interval": interval(0.001, 0.04),
            },
        ),
        envelope(
            "cbds.claim-replication-evidence",
            lane,
            {
                "replication_role": "independent_interactive",
                "benchmark_id": "intercode-bash-independent",
                "backbone_id": "primary-backbone",
                "result_evidence_sha256": SHA["independent_interactive_result"],
                "operator_configuration_sha256": SHA["comparison_config"],
                "paired_seed_count": 5,
                "estimate_difference_proportion": -0.005,
                "simultaneous_confidence_interval": interval(-0.015, 0.005),
            },
        ),
    ]
    teacher = envelope(
        "cbds.claim-teacher-free-evidence",
        lane,
        {
            "main_comparison_completed_run_sha256": SHA["comparison_run"],
            "main_teacher_enabled": False,
            "main_verified_teacher_corpus_sha256": None,
            "teacher_free_completed_run_set_sha256": SHA["teacher_run_set"],
            "teacher_free_result_evidence_sha256": SHA["teacher_result"],
            "teacher_free_operator_configuration_sha256": SHA["comparison_config"],
            "teacher_free_paired_seed_count": 5,
            "teacher_free_estimate_difference_proportion": 0.025,
        },
    )
    return {
        "statistical_evidence": statistical,
        "export_evidence": export,
        "compute_comparison_evidence": compute,
        "noninferiority_evidence": noninferiority,
        "hardware_evidence": hardware,
        "replication_evidence": replications,
        "teacher_free_evidence": teacher,
    }


def readdress(record: dict) -> dict:
    candidate = copy.deepcopy(record)
    candidate.pop("evidence_sha256")
    return content_address_claim_evidence(candidate)


def bind(bundle: dict[str, object]) -> dict:
    return bind_confirmatory_lane_claim(**bundle)  # type: ignore[arg-type]


class ClaimAcceptanceHappyPathTests(unittest.TestCase):
    def test_fixed_size_criteria_met_but_claim_is_not_authorized(self) -> None:
        result = bind(evidence_bundle("fixed_size"))
        self.assertEqual(result["binder_version"], CLAIM_ACCEPTANCE_BINDER_VERSION)
        self.assertTrue(result["acceptance_criteria_met"])
        self.assertTrue(result["criteria"]["lane_artifact_condition"]["met"])
        self.assertTrue(result["criteria"]["matched_compute"]["equal_target_tokens"]["matched"])
        self.assertTrue(result["criteria"]["matched_compute"]["equal_total_flops"]["matched"])
        self.assertFalse(result["authorization"]["claim_authorized"])
        self.assertFalse(result["authorization"]["authorization_flip_implemented"])
        self.assertEqual(
            result["authorization"]["status"],
            "criteria_met_but_end_to_end_provenance_not_bound",
        )
        self.assertEqual(len(result["authorization"]["required_connections"]), 7)
        self.assertEqual(
            {item["connection_id"] for item in result["authorization"]["required_connections"]},
            {
                "primary_statistical_cells_and_family",
                "completed_export_and_dense_artifact_inspection",
                "equal_target_and_equal_flop_accounting",
                "bounded_and_protected_noninferiority",
                "portable_hardware_peak_memory_and_bytes",
                "runner_up_and_independent_benchmark_replication",
                "teacher_free_ablation",
            },
        )
        unhashed = copy.deepcopy(result)
        declared = unhashed.pop("claim_record_sha256")
        self.assertEqual(declared, value_sha256(unhashed))
        primary_connection = next(
            item
            for item in result["authorization"]["required_connections"]
            if item["connection_id"] == "primary_statistical_cells_and_family"
        )
        self.assertEqual(
            primary_connection["required_validator_chain"],
            [
                "cbds.outcome_binding.bind_confirmatory_binary_cube",
                "cbds.outcome_binding.run_confirmatory_contrast_from_collections",
                "cbds.confirmatory_analysis.finalize_confirmatory_family",
            ],
        )
        self.assertIn(
            "family_contrast_records_not_reopened",
            primary_connection["missing_source_hash_bindings"],
        )
        self.assertIn(
            SHA["fixed_size_contrast"],
            primary_connection["required_source_sha256s"],
        )
        self.assertIn(
            SHA["compression_contrast"],
            primary_connection["required_source_sha256s"],
        )

    def test_compression_bytes_branch_and_memory_reduction(self) -> None:
        result = bind(evidence_bundle("compression"))
        lane = result["criteria"]["lane_artifact_condition"]
        self.assertTrue(result["acceptance_criteria_met"])
        self.assertTrue(lane["bytes_reduction_with_static_noninferiority"])
        self.assertAlmostEqual(lane["source_weight_bytes_reduction_fraction"], 0.25)
        self.assertTrue(lane["architectural_claim_qualified"])
        self.assertTrue(result["criteria"]["hardware"]["measured_reduction"])
        self.assertFalse(result["authorization"]["claim_authorized"])

    def test_compression_matched_bytes_gain_branch(self) -> None:
        bundle = evidence_bundle("compression")
        export = copy.deepcopy(bundle["export_evidence"])
        source = export["payload"]["source_artifact"]
        comparison = export["payload"]["comparison_artifact"]
        source["physical_parameters"] = comparison["physical_parameters"]
        source["active_parameters"] = comparison["active_parameters"]
        source["weight_bytes"] = comparison["weight_bytes"]
        source["bundle_bytes"] = comparison["bundle_bytes"]
        bundle["export_evidence"] = readdress(export)
        noninferiority = copy.deepcopy(bundle["noninferiority_evidence"])
        static = noninferiority["payload"]["compression_static_source"]
        static["estimate_difference_proportion"] = 0.03
        static["simultaneous_confidence_interval"] = interval(0.001, 0.06)
        bundle["noninferiority_evidence"] = readdress(noninferiority)
        hardware = copy.deepcopy(bundle["hardware_evidence"])
        hardware["payload"]["reference_weight_bytes"] = comparison["weight_bytes"]
        hardware["payload"]["reference_bundle_bytes"] = comparison["bundle_bytes"]
        bundle["hardware_evidence"] = readdress(hardware)
        result = bind(bundle)
        lane = result["criteria"]["lane_artifact_condition"]
        self.assertFalse(lane["bytes_reduction_with_static_noninferiority"])
        self.assertTrue(lane["matched_bytes_with_static_gain"])
        self.assertTrue(result["acceptance_criteria_met"])

    def test_quantization_only_compression_is_valid_but_not_parameter_reduction(self) -> None:
        bundle = evidence_bundle("compression")
        export = copy.deepcopy(bundle["export_evidence"])
        for role in ("direct_baseline_artifact", "comparison_artifact"):
            artifact_record = export["payload"][role]
            artifact_record["physical_parameters"] = 600_000_000
            artifact_record["active_parameters"] = 600_000_000
            artifact_record["average_weight_bits"] = 4.0
            artifact_record["architecture_layout_sha256"] = SHA[
                "source_architecture_layout"
            ]
        bundle["export_evidence"] = readdress(export)
        result = bind(bundle)
        lane = result["criteria"]["lane_artifact_condition"]
        self.assertTrue(result["acceptance_criteria_met"])
        self.assertFalse(lane["architectural_claim_qualified"])
        self.assertTrue(lane["quantization_only_parameter_reduction_claim_forbidden"])


class ClaimAcceptanceCriteriaTests(unittest.TestCase):
    def test_failed_statistical_threshold_returns_false_not_success(self) -> None:
        bundle = evidence_bundle()
        statistical = copy.deepcopy(bundle["statistical_evidence"])
        statistical["payload"]["estimate_difference_proportion"] = 0.029
        bundle["statistical_evidence"] = readdress(statistical)
        result = bind(bundle)
        self.assertFalse(result["criteria"]["primary_statistical_gain"]["met"])
        self.assertFalse(result["acceptance_criteria_met"])
        self.assertFalse(result["authorization"]["claim_authorized"])

    def test_fixed_size_identity_includes_bundle_tokenizer_and_precision(self) -> None:
        for field, value in (
            ("bundle_bytes", 1_210_000_001),
            ("tokenizer_sha256", "f" * 64),
            ("average_weight_bits", 15.0),
            ("precision_layout_sha256", "f" * 64),
        ):
            with self.subTest(field=field):
                bundle = evidence_bundle()
                export = copy.deepcopy(bundle["export_evidence"])
                export["payload"]["comparison_artifact"][field] = value
                bundle["export_evidence"] = readdress(export)
                if field == "bundle_bytes":
                    hardware = copy.deepcopy(bundle["hardware_evidence"])
                    hardware["payload"]["comparison_bundle_bytes"] = value
                    bundle["hardware_evidence"] = readdress(hardware)
                result = bind(bundle)
                self.assertFalse(result["criteria"]["lane_artifact_condition"]["met"])
                self.assertFalse(result["acceptance_criteria_met"])

    def test_fixed_size_architecture_layout_drift_fails_identity_criteria(self) -> None:
        bundle = evidence_bundle()
        export = copy.deepcopy(bundle["export_evidence"])
        export["payload"]["comparison_artifact"]["architecture_layout_sha256"] = (
            "f" * 64
        )
        bundle["export_evidence"] = readdress(export)
        result = bind(bundle)
        self.assertFalse(result["criteria"]["lane_artifact_condition"]["met"])
        self.assertIn(
            "architecture_layout_sha256",
            result["criteria"]["lane_artifact_condition"]["identity_fields"],
        )
        self.assertFalse(result["acceptance_criteria_met"])
        self.assertFalse(result["authorization"]["claim_authorized"])

    def test_compute_data_sources_are_part_of_matching(self) -> None:
        bundle = evidence_bundle()
        records = copy.deepcopy(bundle["compute_comparison_evidence"])
        records[0]["payload"]["comparison_support_data_sha256"] = "f" * 64
        records[0] = readdress(records[0])
        bundle["compute_comparison_evidence"] = records
        result = bind(bundle)
        self.assertFalse(
            result["criteria"]["matched_compute"]["equal_target_tokens"][
                "data_sources_matched"
            ]
        )
        self.assertFalse(result["acceptance_criteria_met"])

    def test_comparable_teacher_corpus_is_required(self) -> None:
        bundle = evidence_bundle()
        export = copy.deepcopy(bundle["export_evidence"])
        comparison = export["payload"]["comparison_artifact"]
        comparison["teacher_enabled"] = True
        comparison["verified_teacher_corpus_sha256"] = SHA["teacher_result"]
        bundle["export_evidence"] = readdress(export)
        teacher = copy.deepcopy(bundle["teacher_free_evidence"])
        teacher["payload"]["main_teacher_enabled"] = True
        teacher["payload"]["main_verified_teacher_corpus_sha256"] = SHA["teacher_result"]
        bundle["teacher_free_evidence"] = readdress(teacher)
        compute = copy.deepcopy(bundle["compute_comparison_evidence"])
        for index, evidence in enumerate(compute):
            evidence["payload"]["comparison_teacher_corpus_sha256"] = SHA[
                "teacher_result"
            ]
            compute[index] = readdress(evidence)
        bundle["compute_comparison_evidence"] = compute
        result = bind(bundle)
        self.assertFalse(result["criteria"]["comparable_teacher_corpus"]["matched"])
        self.assertFalse(result["acceptance_criteria_met"])

    def test_compute_mismatch_fails_criteria(self) -> None:
        for kind, field in (
            ("equal_target_tokens", "comparison_target_tokens"),
            ("equal_total_flops", "comparison_total_flops"),
        ):
            with self.subTest(kind=kind):
                bundle = evidence_bundle()
                records = copy.deepcopy(bundle["compute_comparison_evidence"])
                target = next(item for item in records if item["payload"]["comparison_kind"] == kind)
                target["payload"][field] += 1
                records[records.index(target)] = readdress(target)
                bundle["compute_comparison_evidence"] = records
                result = bind(bundle)
                self.assertFalse(result["criteria"]["matched_compute"][kind]["matched"])
                self.assertFalse(result["acceptance_criteria_met"])

    def test_bounded_and_protected_noninferiority_are_both_required(self) -> None:
        for target in ("bounded", "protected"):
            with self.subTest(target=target):
                bundle = evidence_bundle()
                evidence = copy.deepcopy(bundle["noninferiority_evidence"])
                if target == "bounded":
                    evidence["payload"]["bounded_terminal"]["simultaneous_confidence_interval"] = interval(-0.021, 0.01)
                else:
                    evidence["payload"]["protected_capabilities"][0]["endpoint"]["simultaneous_confidence_interval"] = interval(-0.021, 0.01)
                bundle["noninferiority_evidence"] = readdress(evidence)
                result = bind(bundle)
                self.assertFalse(result["acceptance_criteria_met"])

    def test_compression_requires_peak_memory_reduction(self) -> None:
        bundle = evidence_bundle("compression")
        hardware = copy.deepcopy(bundle["hardware_evidence"])
        hardware["payload"]["comparison_peak_memory_bytes"] = 2_000_000_000
        bundle["hardware_evidence"] = readdress(hardware)
        result = bind(bundle)
        self.assertFalse(result["criteria"]["hardware"]["met"])
        self.assertFalse(result["acceptance_criteria_met"])

    def test_each_replication_role_has_a_derived_gate(self) -> None:
        for role in ("runner_up_static", "independent_static", "independent_interactive"):
            with self.subTest(role=role):
                bundle = evidence_bundle()
                records = copy.deepcopy(bundle["replication_evidence"])
                target = next(item for item in records if item["payload"]["replication_role"] == role)
                target["payload"]["simultaneous_confidence_interval"] = (
                    interval(-0.001, 0.03)
                    if role != "independent_interactive"
                    else interval(-0.021, 0.01)
                )
                records[records.index(target)] = readdress(target)
                bundle["replication_evidence"] = records
                result = bind(bundle)
                self.assertFalse(result["criteria"]["replication"]["replications"][role]["met"])
                self.assertFalse(result["acceptance_criteria_met"])


class ClaimAcceptanceAdversarialTests(unittest.TestCase):
    def assert_invalid(self, bundle: dict[str, object], pattern: str) -> None:
        with self.assertRaisesRegex(ClaimAcceptanceValidationError, pattern):
            bind(bundle)

    def test_unrehash_tampering_is_rejected(self) -> None:
        bundle = evidence_bundle()
        bundle["statistical_evidence"]["payload"]["estimate_difference_proportion"] = 1.0
        self.assert_invalid(bundle, "evidence_sha256 does not hash")

    def test_caller_supplied_cell_scope_is_rejected_even_when_rehashed(self) -> None:
        bundle = evidence_bundle()
        statistical = copy.deepcopy(bundle["statistical_evidence"])
        statistical["payload"]["outcome_evidence_scope"] = (
            "caller_supplied_binary_cells_identity_bound_not_collection_derived"
        )
        bundle["statistical_evidence"] = readdress(statistical)
        self.assert_invalid(
            bundle,
            "outcome_evidence_scope must equal "
            "'artifact_bound_scored_task_result_collections'",
        )

    def test_family_contrasts_must_be_complete_ordered_and_content_addressed(self) -> None:
        for mutation, pattern in (
            ("missing", "exactly two contrasts"),
            ("reordered", "ordered compression then fixed_size"),
            ("digest", "does not hash the ordered family contrast bindings"),
        ):
            with self.subTest(mutation=mutation):
                bundle = evidence_bundle()
                statistical = copy.deepcopy(bundle["statistical_evidence"])
                bindings = statistical["payload"]["family_contrast_bindings"]
                if mutation == "missing":
                    bindings.pop()
                    statistical["payload"]["family_contrast_bindings_sha256"] = (
                        value_sha256(
                            {
                                "commitment_type": (
                                    "cbds.confirmatory-family-input-contrasts"
                                ),
                                "version": "1.0.0",
                                "ordering": "compression_then_fixed_size",
                                "bindings": bindings,
                            }
                        )
                    )
                elif mutation == "reordered":
                    bindings.reverse()
                    statistical["payload"]["family_contrast_bindings_sha256"] = (
                        value_sha256(
                            {
                                "commitment_type": (
                                    "cbds.confirmatory-family-input-contrasts"
                                ),
                                "version": "1.0.0",
                                "ordering": "compression_then_fixed_size",
                                "bindings": bindings,
                            }
                        )
                    )
                else:
                    statistical["payload"]["family_contrast_bindings_sha256"] = (
                        "f" * 64
                    )
                bundle["statistical_evidence"] = readdress(statistical)
                self.assert_invalid(bundle, pattern)

    def test_selected_lane_must_match_its_family_contrast_source(self) -> None:
        bundle = evidence_bundle()
        statistical = copy.deepcopy(bundle["statistical_evidence"])
        statistical["payload"]["contrast_record_sha256"] = SHA[
            "compression_contrast"
        ]
        bundle["statistical_evidence"] = readdress(statistical)
        self.assert_invalid(bundle, "disagrees with the fixed_size family contrast")

    def test_unknown_fields_are_rejected_even_when_rehashed(self) -> None:
        bundle = evidence_bundle()
        evidence = copy.deepcopy(bundle["hardware_evidence"])
        evidence["payload"]["caller_says_passed"] = True
        bundle["hardware_evidence"] = readdress(evidence)
        self.assert_invalid(bundle, "unexpected 'caller_says_passed'")

    def test_rehashed_cross_arm_attack_is_rejected(self) -> None:
        bundle = evidence_bundle()
        evidence = copy.deepcopy(bundle["noninferiority_evidence"])
        evidence["comparison_arm"] = "different-candidate"
        bundle["noninferiority_evidence"] = readdress(evidence)
        self.assert_invalid(bundle, "endpoint arms do not match")

    def test_rehashed_completed_run_substitution_is_rejected(self) -> None:
        bundle = evidence_bundle()
        records = copy.deepcopy(bundle["compute_comparison_evidence"])
        records[0]["payload"]["comparison_completed_run_sha256"] = "f" * 64
        records[0] = readdress(records[0])
        bundle["compute_comparison_evidence"] = records
        self.assert_invalid(bundle, "does not bind the exported comparison run")

    def test_primary_contrast_must_be_the_equal_flop_result(self) -> None:
        bundle = evidence_bundle()
        records = copy.deepcopy(bundle["compute_comparison_evidence"])
        records[1]["payload"]["performance_evidence_sha256"] = "f" * 64
        records[1] = readdress(records[1])
        bundle["compute_comparison_evidence"] = records
        self.assert_invalid(bundle, "equal-FLOP comparison must bind")

    def test_compression_hardware_reference_arm_is_the_source(self) -> None:
        bundle = evidence_bundle("compression")
        evidence = copy.deepcopy(bundle["hardware_evidence"])
        evidence["reference_arm"] = "direct-baseline"
        bundle["hardware_evidence"] = readdress(evidence)
        self.assert_invalid(bundle, "reference arm does not match its artifact reference")

    def test_compression_static_endpoint_must_bind_source_arm(self) -> None:
        bundle = evidence_bundle("compression")
        evidence = copy.deepcopy(bundle["noninferiority_evidence"])
        evidence["payload"]["compression_static_source"]["reference_arm"] = (
            "direct-baseline"
        )
        bundle["noninferiority_evidence"] = readdress(evidence)
        self.assert_invalid(bundle, "does not bind the source artifact arm")

    def test_runner_up_uses_primary_sealed_benchmark(self) -> None:
        bundle = evidence_bundle()
        records = copy.deepcopy(bundle["replication_evidence"])
        runner = next(
            item
            for item in records
            if item["payload"]["replication_role"] == "runner_up_static"
        )
        runner["payload"]["benchmark_id"] = "different-static-benchmark"
        records[records.index(runner)] = readdress(runner)
        bundle["replication_evidence"] = records
        self.assert_invalid(bundle, "must use the primary sealed static benchmark")

    def test_boolean_cannot_smuggle_numeric_evidence(self) -> None:
        bundle = evidence_bundle()
        evidence = copy.deepcopy(bundle["export_evidence"])
        evidence["payload"]["comparison_artifact"]["physical_parameters"] = True
        bundle["export_evidence"] = readdress(evidence)
        self.assert_invalid(bundle, "physical_parameters must be an integer")

    def test_dense_sub_billion_scope_is_enforced(self) -> None:
        bundle = evidence_bundle()
        evidence = copy.deepcopy(bundle["export_evidence"])
        artifact_record = evidence["payload"]["comparison_artifact"]
        artifact_record["physical_parameters"] = 1_000_000_000
        artifact_record["active_parameters"] = 1_000_000_000
        bundle["export_evidence"] = readdress(evidence)
        self.assert_invalid(bundle, "must be below one billion")

    def test_moe_artifact_is_not_accepted(self) -> None:
        bundle = evidence_bundle()
        evidence = copy.deepcopy(bundle["export_evidence"])
        evidence["payload"]["comparison_artifact"]["architecture"] = "moe"
        bundle["export_evidence"] = readdress(evidence)
        self.assert_invalid(bundle, "architecture must equal 'dense'")

    def test_protected_roster_hash_is_derived(self) -> None:
        bundle = evidence_bundle()
        evidence = copy.deepcopy(bundle["noninferiority_evidence"])
        evidence["payload"]["protected_capability_roster_sha256"] = "f" * 64
        bundle["noninferiority_evidence"] = readdress(evidence)
        self.assert_invalid(bundle, "roster hash is not derived")

    def test_protected_margin_cannot_be_made_vacuous(self) -> None:
        bundle = evidence_bundle()
        evidence = copy.deepcopy(bundle["noninferiority_evidence"])
        evidence["payload"]["protected_capabilities"][0]["endpoint"]["margin_absolute_points"] = 99.0
        roster = [
            {
                "capability_id": item["capability_id"],
                "margin_absolute_points": item["endpoint"]["margin_absolute_points"],
                "prospective_margin_policy_sha256": item["endpoint"]["prospective_margin_policy_sha256"],
            }
            for item in evidence["payload"]["protected_capabilities"]
        ]
        evidence["payload"]["protected_capability_roster_sha256"] = value_sha256(roster)
        bundle["noninferiority_evidence"] = readdress(evidence)
        self.assert_invalid(bundle, "exceeds the binder maximum")

    def test_replication_requires_exact_role_roster(self) -> None:
        bundle = evidence_bundle()
        bundle["replication_evidence"] = bundle["replication_evidence"][:2]
        self.assert_invalid(bundle, "exactly three replication")

    def test_teacher_status_is_cross_bound_to_export(self) -> None:
        bundle = evidence_bundle()
        evidence = copy.deepcopy(bundle["teacher_free_evidence"])
        evidence["payload"]["main_teacher_enabled"] = True
        evidence["payload"]["main_verified_teacher_corpus_sha256"] = SHA["teacher_result"]
        bundle["teacher_free_evidence"] = readdress(evidence)
        self.assert_invalid(bundle, "teacher status disagrees")

    def test_independent_benchmarks_cannot_alias_primary_or_each_other(self) -> None:
        for alias in ("primary", "each_other"):
            with self.subTest(alias=alias):
                bundle = evidence_bundle()
                records = copy.deepcopy(bundle["replication_evidence"])
                static = next(item for item in records if item["payload"]["replication_role"] == "independent_static")
                interactive = next(item for item in records if item["payload"]["replication_role"] == "independent_interactive")
                if alias == "primary":
                    static["payload"]["benchmark_id"] = "sealed-static-primary"
                    records[records.index(static)] = readdress(static)
                    pattern = "benchmark is not independent"
                else:
                    interactive["payload"]["benchmark_id"] = static["payload"]["benchmark_id"]
                    records[records.index(interactive)] = readdress(interactive)
                    pattern = "must be distinct"
                bundle["replication_evidence"] = records
                self.assert_invalid(bundle, pattern)

    def test_address_helper_refuses_double_addressing(self) -> None:
        with self.assertRaisesRegex(ClaimAcceptanceValidationError, "must omit"):
            content_address_claim_evidence(evidence_bundle()["statistical_evidence"])


if __name__ == "__main__":
    unittest.main()
