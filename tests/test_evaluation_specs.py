from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import cbds.evaluation_specs as evaluation_specs_module

from cbds.evaluation_specs import (
    EVALUATION_SPEC_SCHEMA_VERSION,
    FAILURE_PRECEDENCE,
    FROZEN_FENCE_LABELS,
    TASK_RESULT_SCHEMA_VERSION,
    TERMINAL_STATUSES,
    EvaluationArtifactBindingError,
    EvaluationSpecValidationError,
    TaskResultEvaluationBindingError,
    evaluation_spec_sha256,
    load_evaluation_spec,
    load_evaluation_spec_against_experiment_manifest,
    load_task_result_against_evaluation_spec,
    ordered_arm_roles_sha256,
    section_policy_sha256,
    select_scored_task_results_against_evaluation_spec,
    task_commitment_set_sha256,
    validate_evaluation_spec,
    validate_evaluation_spec_against_experiment_manifest,
    validate_task_result_against_evaluation_spec,
    validate_task_result_chain_against_evaluation_spec,
    validate_task_result_collection_against_evaluation_spec,
    write_evaluation_spec,
)
from cbds.manifests import (
    atomic_write_json,
    canonical_json_bytes,
    file_sha256,
    value_sha256,
)
from cbds.task_results import (
    fixture_id_set_sha256,
    ordered_fixture_ids_sha256,
    task_result_sha256,
)
from tests.test_task_results import (
    opaque_fixture_id,
    opaque_task_id,
    set_not_run,
    sync_resource_use,
)


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "evaluation-spec.schema.json"
PACKAGED_SCHEMA_PATH = ROOT / "src" / "cbds" / "schemas" / SCHEMA_PATH.name
EXAMPLE_PATH = ROOT / "examples" / "evaluation-spec.example.json"

_POLICY_PATHS = (
    ("decoding",),
    ("parser",),
    ("environment",),
    ("tool_policy",),
    ("fixture_policy",),
    ("outcome_policy", "rerun"),
    ("outcome_policy", "exclusion"),
    ("outcome_policy", "timeout"),
    ("outcome_policy", "failure_taxonomy"),
    ("analysis_plan",),
    ("output_policy",),
)


def _nested(spec: dict[str, object], path: tuple[str, ...]) -> dict[str, object]:
    current: object = spec
    for part in path:
        assert isinstance(current, dict)
        current = current[part]
    assert isinstance(current, dict)
    return current


def _rehash(spec: dict[str, object], *paths: tuple[str, ...]) -> None:
    selected = paths or _POLICY_PATHS
    for path in selected:
        section = _nested(spec, path)
        section["policy_sha256"] = section_policy_sha256(section)


def contrast_plan(
    reference_arm_id: str = "dense-reference",
    comparison_arm_id: str = "specialized-comparison",
) -> dict[str, object]:
    roles = [
        {"role": "reference", "arm_id": reference_arm_id},
        {"role": "comparison", "arm_id": comparison_arm_id},
    ]
    return {
        "version": "1.0.0",
        "direction": "comparison_minus_reference",
        "ordered_arm_roles": roles,
        "ordered_arm_roles_sha256": ordered_arm_roles_sha256(roles),
    }


def _fixture_ids_for_commitment(commitment: dict[str, object]) -> list[str]:
    for task_index in range(2):
        if commitment["prompt_id"] == opaque_task_id(
            f"evaluation-task-{task_index}"
        ):
            count = commitment["fixture_count"]
            assert isinstance(count, int)
            return [
                opaque_fixture_id(
                    f"evaluation-task-{task_index}-fixture-{fixture_index}"
                )
                for fixture_index in range(count)
            ]
    raise AssertionError("unknown synthetic task commitment")


def valid_static_spec() -> dict[str, object]:
    hashes = iter(f"{digit:064x}"[-64:] for digit in range(1, 100))
    allowed_executables = ["bash", "find", "jq", "printf", "sort"]
    fixture_count_per_task = 5
    commitments: list[dict[str, object]] = []
    for task_index in range(2):
        fixture_ids = [
            opaque_fixture_id(
                f"evaluation-task-{task_index}-fixture-{fixture_index}"
            )
            for fixture_index in range(fixture_count_per_task)
        ]
        commitments.append({
            "prompt_id": opaque_task_id(f"evaluation-task-{task_index}"),
            "task_record_sha256": value_sha256(
                {"synthetic_task_record": task_index}
            ),
            "fixture_ids_sha256": fixture_id_set_sha256(fixture_ids),
            "ordered_fixture_ids_sha256": ordered_fixture_ids_sha256(
                fixture_ids
            ),
            "fixture_count": fixture_count_per_task,
        })
    commitments.sort(key=lambda commitment: commitment["prompt_id"])
    spec: dict[str, object] = {
        "schema_version": EVALUATION_SPEC_SCHEMA_VERSION,
        "evaluation_id": "development-static-evaluation-0001",
        "created_at": "2026-07-14T19:00:00+09:00",
        "git_revision": "1" * 40,
        "mode": "static",
        "artifact": {
            "artifact_id": "dense-terminal-artifact-0001",
            "architecture": "dense",
            "training_seed": 12,
            "physical_parameters": 600_000_000,
            "format": "safetensors",
            "artifact_sha256": next(hashes),
            "bundle_sha256": next(hashes),
            "tokenizer_sha256": next(hashes),
            "completed_run_id": "screening-seed-001",
            "completed_experiment_record_sha256": next(hashes),
            "inspection_report_sha256": next(hashes),
        },
        "benchmark": {
            "benchmark_id": "generated-terminal-suite-v1",
            "repository": "HoseungChoi51/terminal-suite",
            "revision": "2" * 40,
            "dataset_sha256": next(hashes),
            "manifest_sha256": next(hashes),
            "semantic_graph_sha256": next(hashes),
            "tasks_sha256": next(hashes),
            "fixtures_sha256": next(hashes),
            "suite": "static",
            "split": {
                "name": "method-development-static",
                "role": "method_development",
                "sha256": next(hashes),
                "sealed": False,
                "open_once": False,
            },
            "task_count": 2,
            "fixture_count": 10,
        },
        "task_commitments": {
            "version": "1.0.0",
            "hash_algorithm": "canonical-json-sha256",
            "commitments": commitments,
            "commitment_set_sha256": task_commitment_set_sha256(commitments),
        },
        "execution": {
            "runtime": "podman",
            "runtime_version": "5.2.2",
            "runtime_executable_sha256": next(hashes),
            "rootless_required": True,
            "container_image_repository": "ghcr.io/example/cbds-evaluator",
            "container_image_digest": "sha256:" + next(hashes),
            "container_recipe_revision": "3" * 40,
            "container_recipe_sha256": next(hashes),
            "verifier_repository": "HoseungChoi51/terminal-verifier",
            "verifier_revision": "4" * 40,
            "verifier_sha256": next(hashes),
            "sandbox_measurement_method": "cgroup-v2-procfs-rusage-v1",
            "sandbox_measurement_implementation_sha256": next(hashes),
            "sandbox_policy_sha256": next(hashes),
        },
        "decoding": {
            "algorithm": "greedy",
            "do_sample": False,
            "num_beams": 1,
            "num_return_sequences": 1,
            "maximum_new_tokens": 1024,
            "eos_token_ids": [1, 2],
            "pad_token_id": 0,
            "stop_sequences": [],
            "tokenizer_add_special_tokens": True,
            "skip_special_tokens": True,
            "clean_up_tokenization_spaces": False,
            "prompt_serialization_sha256": next(hashes),
            "policy_sha256": "0" * 64,
        },
        "parser": {
            "grammar": "raw-or-one-triple-backtick-fence",
            "version": "1.0.0",
            "raw_default_language": "bash",
            "program_language": "bash",
            "allowed_languages": ["bash"],
            "fence_labels": {
                language: list(labels)
                for language, labels in FROZEN_FENCE_LABELS.items()
            },
            "surrounding_prose_allowed": False,
            "multiple_fences_allowed": False,
            "newline_normalization": "crlf-and-cr-to-lf",
            "nul_allowed": False,
            "empty_program_allowed": False,
            "policy_sha256": "0" * 64,
        },
        "limits": {
            "maximum_prompt_tokens": 1024,
            "maximum_sequence_tokens": 2048,
            "maximum_response_bytes": 65536,
            "syntax_timeout_seconds": 5,
            "fixture_timeout_seconds": 10,
            "kill_grace_seconds": 1,
            "cpu_time_seconds": 10,
            "memory_bytes": 536_870_912,
            "pids": 64,
            "open_files": 64,
            "stdout_bytes": 1_048_576,
            "stderr_bytes": 1_048_576,
            "workspace_bytes": 67_108_864,
            "action_limit": 0,
            "observation_bytes": 0,
        },
        "environment": {
            "locale": "C.UTF-8",
            "timezone": "UTC",
            "umask": 0o077,
            "uid": 65534,
            "gid": 65534,
            "working_directory": "/workspace",
            "inherit_host_environment": False,
            "variables": [
                {"name": "HOME", "value": "/workspace"},
                {"name": "LANG", "value": "C.UTF-8"},
                {"name": "LC_ALL", "value": "C.UTF-8"},
                {
                    "name": "PATH",
                    "value": "/usr/local/bin:/usr/bin:/bin",
                },
                {"name": "TMPDIR", "value": "/workspace/tmp"},
                {"name": "TZ", "value": "UTC"},
            ],
            "shell_options": ["pipefail"],
            "network": "none",
            "read_only_root": True,
            "no_new_privileges": True,
            "capabilities_added": [],
            "host_mounts_allowed": False,
            "container_socket_allowed": False,
            "policy_sha256": "0" * 64,
        },
        "tool_policy": {
            "version": "1.0.0",
            "track": "bash_native",
            "allowlist_sha256": value_sha256(allowed_executables),
            "allowed_executables": allowed_executables,
            "shell_builtins_allowed": True,
            "python_allowed": False,
            "perl_allowed": False,
            "compilers_allowed": False,
            "network_tools_allowed": False,
            "resolution": "exact-basename-allowlist",
            "unknown_tool_action": "fail",
            "policy_sha256": "0" * 64,
        },
        "fixture_policy": {
            "fixtures_per_task": 5,
            "aggregation": "all_must_pass",
            "fixture_order": "deterministic_sha256",
            "fixture_order_sha256": next(hashes),
            "fresh_workspace_per_fixture": True,
            "state_property_checks_required": True,
            "independent_reference_required": True,
            "stop_after_first_failure": False,
            "policy_sha256": "0" * 64,
        },
        "outcome_policy": {
            "rerun": {
                "version": "1.0.0",
                "mode": "never",
                "maximum_attempts": 1,
                "eligible_terminal_statuses": [],
                "scored_attempt_rule": "first_attempt",
                "policy_sha256": "0" * 64,
            },
            "exclusion": {
                "version": "1.0.0",
                "mode": "none",
                "manifest_sha256": None,
                "allowed_reason_codes": [],
                "locked_before_sealed_open": True,
                "policy_sha256": "0" * 64,
            },
            "timeout": {
                "version": "1.0.0",
                "syntax_timeout_status": "syntax_check_failure",
                "fixture_timeout_status": "timeout",
                "action_timeout_status": "timeout",
                "counts_as_failure": True,
                "rerunnable": False,
                "policy_sha256": "0" * 64,
            },
            "failure_taxonomy": {
                "version": "1.0.0",
                "terminal_statuses": list(TERMINAL_STATUSES),
                "precedence": list(FAILURE_PRECEDENCE),
                "policy_sha256": "0" * 64,
            },
        },
        "task_result": {
            "schema_version": TASK_RESULT_SCHEMA_VERSION,
            "schema_sha256": file_sha256(ROOT / "task-result.schema.json"),
            "record_format": "canonical-json",
            "record_hash_algorithm": "sha256",
        },
        "seeds": {
            "generation": 10,
            "task_order": 11,
            "fixture_order": 12,
            "action_loop": 13,
            "environment": 14,
            "rerun": 15,
        },
        "analysis_plan": {
            "version": "1.0.0",
            "phase": "development",
            "lane": "development",
            "external_plan_sha256": "d" * 64,
            "analysis_code_revision": "a" * 40,
            "analysis_code_sha256": "b" * 64,
            "seed_evidence_scope": "per_artifact_only",
            "contrast": None,
            "training_seed_set_sha256": "f" * 64,
            "training_seed_count": 1,
            "pairing_units": [
                "training_seed",
                "data_order",
                "teacher_corpus",
                "task",
                "fixture",
            ],
            "metric_unit": "proportion",
            "points_to_proportion_divisor": 100,
            "bootstrap": {
                "method": "crossed_seed_task_percentile_bootstrap",
                "resamples": 1000,
                "random_seed": 101,
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
                "monte_carlo_draws": 100000,
                "random_seed": 102,
            },
            "multiplicity_correction": {
                "p_values": "holm_step_down",
                "confidence_intervals": "bonferroni_simultaneous",
                "family_size": 2,
                "family_confidence_level": 0.95,
                "per_contrast_confidence_level": 0.975,
            },
            "confirmatory_lane_contrast_count": 2,
            "noninferiority_margins": {
                "static_absolute_points": None,
                "bounded_terminal_absolute_points": 2,
            },
            "success_thresholds": {
                "rule": "development_only",
                "static_gain_absolute_points": 0,
                "serialized_bytes_reduction_fraction": None,
                "physical_parameters_reduction_fraction": None,
                "simultaneous_lower_bound_above_zero": False,
            },
            "policy_sha256": "0" * 64,
        },
        "output_policy": {
            "version": "1.0.0",
            "hash_algorithm": "sha256",
            "hash_input": "raw_bytes",
            "text_encoding": "utf-8",
            "generated_text": "hash_and_byte_count_only",
            "extracted_code": "hash_only",
            "stdout": "hash_and_byte_count_only",
            "stderr": "hash_and_byte_count_only",
            "diagnostics": "hash_only",
            "verifier_results": "hash_only",
            "action_payloads": "hash_only",
            "retain_plaintext": False,
            "sealed_identifiers_only": True,
            "task_result_record_hash": "canonical-json-sha256",
            "policy_sha256": "0" * 64,
        },
    }
    _rehash(spec)
    return spec


def bound_static_result(
    spec: dict[str, object], commitment_index: int = 0
) -> dict[str, object]:
    from tests.test_task_results import static_result

    result = static_result()
    benchmark = _nested(spec, ("benchmark",))
    split = _nested(spec, ("benchmark", "split"))
    commitment = _nested(spec, ("task_commitments",))["commitments"][
        commitment_index
    ]
    assert isinstance(commitment, dict)
    fixture_ids = _fixture_ids_for_commitment(commitment)
    for fixture, fixture_id in zip(result["fixture_outcomes"], fixture_ids):
        fixture["fixture_id"] = fixture_id
    result.update(
        {
            "evaluation_id": spec["evaluation_id"],
            "evaluation_spec_sha256": evaluation_spec_sha256(spec),
            "run_id": _nested(spec, ("artifact",))["completed_run_id"],
            "benchmark_id": benchmark["benchmark_id"],
            "mode": spec["mode"],
            "split_id": split["name"],
            "split_role": split["role"],
            "sealed": split["sealed"],
            "prompt_id": commitment["prompt_id"],
            "task_record_sha256": commitment["task_record_sha256"],
            "fixture_ids_sha256": fixture_id_set_sha256(fixture_ids),
            "ordered_fixture_ids_sha256": ordered_fixture_ids_sha256(
                fixture_ids
            ),
            "action_limit": _nested(spec, ("limits",))["action_limit"],
        }
    )
    result["tool_policy"]["policy_sha256"] = _nested(  # type: ignore[index]
        spec, ("tool_policy",)
    )["policy_sha256"]
    return result


def bound_interactive_result(
    spec: dict[str, object], commitment_index: int = 0
) -> dict[str, object]:
    from tests.test_task_results import interactive_result, sync_resource_use

    result = interactive_result()
    benchmark = _nested(spec, ("benchmark",))
    split = _nested(spec, ("benchmark", "split"))
    commitment = _nested(spec, ("task_commitments",))["commitments"][
        commitment_index
    ]
    assert isinstance(commitment, dict)
    result.update(
        {
            "evaluation_id": spec["evaluation_id"],
            "evaluation_spec_sha256": evaluation_spec_sha256(spec),
            "run_id": _nested(spec, ("artifact",))["completed_run_id"],
            "benchmark_id": benchmark["benchmark_id"],
            "mode": spec["mode"],
            "split_id": split["name"],
            "split_role": split["role"],
            "sealed": split["sealed"],
            "prompt_id": commitment["prompt_id"],
            "task_record_sha256": commitment["task_record_sha256"],
            "action_limit": _nested(spec, ("limits",))["action_limit"],
        }
    )
    fixture = result["fixture_outcomes"][0]  # type: ignore[index]
    count = _nested(spec, ("fixture_policy",))["fixtures_per_task"]
    assert isinstance(count, int)
    fixture_ids = _fixture_ids_for_commitment(commitment)
    result["fixture_outcomes"] = [
        {
            **copy.deepcopy(fixture),
            "fixture_id": fixture_ids[index],
        }
        for index in range(count)
    ]
    result["fixture_ids_sha256"] = fixture_id_set_sha256(fixture_ids)
    result["ordered_fixture_ids_sha256"] = ordered_fixture_ids_sha256(
        fixture_ids
    )
    result["tool_policy"]["policy_sha256"] = _nested(  # type: ignore[index]
        spec, ("tool_policy",)
    )["policy_sha256"]
    sync_resource_use(result)
    return result


def mark_internal_error(result: dict[str, object]) -> None:
    for fixture in result["fixture_outcomes"]:  # type: ignore[index]
        set_not_run(fixture)
    result["infrastructure_error"] = {
        "stage": "action_loop" if result["mode"] == "interactive" else "fixture_setup",
        "diagnostic_sha256": "d" * 64,
    }
    result["terminal_status"] = "internal_error"
    sync_resource_use(result)


def evaluation_bound_to_completed_record() -> tuple[dict[str, object], dict]:
    from tests.test_manifests import valid_experiment_manifest

    spec = valid_static_spec()
    record = valid_experiment_manifest()
    artifact = _nested(spec, ("artifact",))
    exported = record["export"]
    artifact.update(
        {
            "architecture": exported["architecture"],
            "training_seed": record["seeds"]["training"],
            "physical_parameters": exported["physical_parameters"],
            "format": exported["format"],
            "artifact_sha256": exported["artifact_sha256"],
            "bundle_sha256": exported["bundle_sha256"],
            "tokenizer_sha256": exported["tokenizer_sha256"],
            "completed_run_id": record["run_id"],
            "inspection_report_sha256": exported["inspection_report_sha256"],
            "completed_experiment_record_sha256": value_sha256(record),
        }
    )
    return spec, record


def valid_interactive_spec() -> dict[str, object]:
    spec = valid_static_spec()
    spec["evaluation_id"] = "interactive-confirmation-0001"
    spec["mode"] = "interactive"
    benchmark = _nested(spec, ("benchmark",))
    benchmark["suite"] = "interactive"
    benchmark["split"] = {
        "name": "independent-interactive",
        "role": "independent_benchmark",
        "sha256": "a" * 64,
        "sealed": False,
        "open_once": False,
    }
    limits = _nested(spec, ("limits",))
    limits["action_limit"] = 8
    limits["observation_bytes"] = 65536
    tool_policy = _nested(spec, ("tool_policy",))
    allowed = [*tool_policy["allowed_executables"], "python3"]
    allowed.sort()
    tool_policy["track"] = "python_permitted"
    tool_policy["python_allowed"] = True
    tool_policy["allowed_executables"] = allowed
    tool_policy["allowlist_sha256"] = value_sha256(allowed)
    rerun = _nested(spec, ("outcome_policy", "rerun"))
    rerun["mode"] = "infrastructure_only"
    rerun["maximum_attempts"] = 2
    rerun["eligible_terminal_statuses"] = [
        "verifier_failure",
        "internal_error",
    ]
    rerun["scored_attempt_rule"] = "first_noninfrastructure_attempt"
    _rehash(
        spec,
        ("tool_policy",),
        ("outcome_policy", "rerun"),
    )
    return spec


def valid_confirmatory_spec(
    role: str = "sealed_id", lane: str = "fixed_size"
) -> dict[str, object]:
    spec = valid_static_spec()
    count = 1000 if role == "sealed_id" else 500
    commitments: list[dict[str, object]] = []
    for task_index in range(count):
        prompt_id = opaque_task_id(f"confirmatory-{role}-{task_index}")
        fixture_ids = [
            opaque_fixture_id(
                f"confirmatory-{role}-{task_index}-fixture-{fixture_index}"
            )
            for fixture_index in range(5)
        ]
        commitments.append(
            {
                "prompt_id": prompt_id,
                "task_record_sha256": value_sha256(
                    {"confirmatory_task": role, "index": task_index}
                ),
                "fixture_ids_sha256": fixture_id_set_sha256(fixture_ids),
                "ordered_fixture_ids_sha256": ordered_fixture_ids_sha256(
                    fixture_ids
                ),
                "fixture_count": 5,
            }
        )
    commitments.sort(key=lambda commitment: commitment["prompt_id"])
    benchmark = _nested(spec, ("benchmark",))
    benchmark["split"] = {
        "name": f"confirmatory-{role}",
        "role": role,
        "sha256": "f" * 64,
        "sealed": True,
        "open_once": True,
    }
    benchmark["task_count"] = count
    benchmark["fixture_count"] = count * 5
    task_commitments = _nested(spec, ("task_commitments",))
    task_commitments["commitments"] = commitments
    task_commitments["commitment_set_sha256"] = task_commitment_set_sha256(
        commitments
    )
    analysis = _nested(spec, ("analysis_plan",))
    analysis.update(
        {
            "phase": "confirmatory",
            "lane": lane,
            "contrast": contrast_plan(),
            "training_seed_count": 5,
        }
    )
    if lane == "fixed_size":
        analysis["noninferiority_margins"] = {
            "static_absolute_points": None,
            "bounded_terminal_absolute_points": 2,
        }
        analysis["success_thresholds"] = {
            "rule": "fixed_size",
            "static_gain_absolute_points": 3,
            "serialized_bytes_reduction_fraction": None,
            "physical_parameters_reduction_fraction": None,
            "simultaneous_lower_bound_above_zero": True,
        }
    else:
        analysis["noninferiority_margins"] = {
            "static_absolute_points": 1,
            "bounded_terminal_absolute_points": 2,
        }
        analysis["success_thresholds"] = {
            "rule": "compression_or",
            "static_gain_absolute_points": 3,
            "serialized_bytes_reduction_fraction": 0.25,
            "physical_parameters_reduction_fraction": 0.20,
            "simultaneous_lower_bound_above_zero": True,
        }
    _rehash(spec, ("analysis_plan",))
    return spec


class EvaluationSpecTests(unittest.TestCase):
    def test_task_commitments_are_bounded_canonical_and_exact(self) -> None:
        spec = valid_static_spec()
        commitments = _nested(spec, ("task_commitments",))["commitments"]
        reversed_spec = copy.deepcopy(spec)
        reversed_commitments = _nested(
            reversed_spec, ("task_commitments",)
        )["commitments"]
        reversed_commitments.reverse()
        _nested(reversed_spec, ("task_commitments",))[
            "commitment_set_sha256"
        ] = task_commitment_set_sha256(reversed_commitments)
        with self.assertRaisesRegex(
            EvaluationSpecValidationError, "ordered by opaque prompt_id"
        ):
            validate_evaluation_spec(reversed_spec)

        duplicate = copy.deepcopy(spec)
        duplicate_commitments = _nested(
            duplicate, ("task_commitments",)
        )["commitments"]
        duplicate_commitments[1]["task_record_sha256"] = duplicate_commitments[0][
            "task_record_sha256"
        ]
        _nested(duplicate, ("task_commitments",))[
            "commitment_set_sha256"
        ] = task_commitment_set_sha256(duplicate_commitments)
        with self.assertRaisesRegex(
            EvaluationSpecValidationError, "duplicate value"
        ):
            validate_evaluation_spec(duplicate)

        bad_set_hash = copy.deepcopy(spec)
        _nested(bad_set_hash, ("task_commitments",))[
            "commitment_set_sha256"
        ] = "f" * 64
        with self.assertRaisesRegex(
            EvaluationSpecValidationError, "commitment_set_sha256"
        ):
            validate_evaluation_spec(bad_set_hash)

    def test_confirmatory_analysis_contracts_are_exact(self) -> None:
        for role, lane, count in (
            ("sealed_id", "fixed_size", 1000),
            ("sealed_ood", "compression", 500),
        ):
            with self.subTest(role=role, lane=lane):
                spec = valid_confirmatory_spec(role, lane)
                self.assertEqual(validate_evaluation_spec(spec), spec)
                self.assertEqual(_nested(spec, ("benchmark",))["task_count"], count)

        wrong_count = valid_confirmatory_spec()
        _nested(wrong_count, ("benchmark",))["task_count"] = 999
        with self.assertRaisesRegex(
            EvaluationSpecValidationError, "requires 1000 tasks"
        ):
            validate_evaluation_spec(wrong_count)

        wrong_pairing = valid_confirmatory_spec()
        analysis = _nested(wrong_pairing, ("analysis_plan",))
        analysis["pairing_units"] = list(reversed(analysis["pairing_units"]))
        _rehash(wrong_pairing, ("analysis_plan",))
        with self.assertRaisesRegex(
            EvaluationSpecValidationError, "exactly pair"
        ):
            validate_evaluation_spec(wrong_pairing)

        wrong_margin = valid_confirmatory_spec(lane="compression")
        _nested(wrong_margin, ("analysis_plan",))[
            "noninferiority_margins"
        ]["static_absolute_points"] = 2
        _rehash(wrong_margin, ("analysis_plan",))
        with self.assertRaisesRegex(
            EvaluationSpecValidationError, "frozen lane contract"
        ):
            validate_evaluation_spec(wrong_margin)

    def test_contrast_roles_are_ordered_hashed_and_phase_locked(self) -> None:
        roles = [
            {"role": "reference", "arm_id": "dense-sft"},
            {"role": "comparison", "arm_id": "recycle-ffn"},
        ]
        self.assertEqual(
            ordered_arm_roles_sha256(roles),
            "4d3a4897eb4be2828a0e4f015cf41a29e608a0cfe93991e8214cf36ede795e2c",
        )
        with self.assertRaisesRegex(ValueError, "role must be 'reference'"):
            ordered_arm_roles_sha256(list(reversed(roles)))

        development = valid_static_spec()
        _nested(development, ("analysis_plan",))["contrast"] = contrast_plan()
        _rehash(development, ("analysis_plan",))
        with self.assertRaisesRegex(
            EvaluationSpecValidationError, "development phase requires null"
        ):
            validate_evaluation_spec(development)

        missing = valid_confirmatory_spec()
        _nested(missing, ("analysis_plan",))["contrast"] = None
        _rehash(missing, ("analysis_plan",))
        with self.assertRaisesRegex(
            EvaluationSpecValidationError, "requires ordered"
        ):
            validate_evaluation_spec(missing)

        mutations: list[tuple[str, list[dict[str, str]], bool]] = [
            ("reversed", list(reversed(copy.deepcopy(roles))), True),
            (
                "duplicate_roles",
                [
                    {"role": "reference", "arm_id": "dense-sft"},
                    {"role": "reference", "arm_id": "recycle-ffn"},
                ],
                True,
            ),
            (
                "duplicate_arm_ids",
                [
                    {"role": "reference", "arm_id": "dense-sft"},
                    {"role": "comparison", "arm_id": "dense-sft"},
                ],
                True,
            ),
            ("wrong_hash", copy.deepcopy(roles), False),
        ]
        for label, mutated_roles, retain_bad_hash in mutations:
            with self.subTest(label=label):
                spec = valid_confirmatory_spec()
                contrast = _nested(spec, ("analysis_plan",))["contrast"]
                contrast["ordered_arm_roles"] = mutated_roles
                if retain_bad_hash:
                    contrast["ordered_arm_roles_sha256"] = "f" * 64
                else:
                    contrast["ordered_arm_roles_sha256"] = "e" * 64
                _rehash(spec, ("analysis_plan",))
                with self.assertRaises(EvaluationSpecValidationError):
                    validate_evaluation_spec(spec)

    def test_development_plan_cannot_label_a_sealed_suite(self) -> None:
        spec = valid_static_spec()
        split = _nested(spec, ("benchmark", "split"))
        split.update({"role": "sealed_id", "sealed": True, "open_once": True})
        with self.assertRaisesRegex(
            EvaluationSpecValidationError, "confirmatory plan"
        ):
            validate_evaluation_spec(spec)

    def test_analysis_code_rng_units_and_simultaneous_inference_are_locked(self) -> None:
        mutations = (
            (("analysis_plan",), "analysis_code_revision", "not-a-revision"),
            (("analysis_plan", "bootstrap"), "percentile_interpolation", "nearest"),
            (("analysis_plan", "randomization_test"), "unit", "semantic_task"),
            (
                ("analysis_plan", "multiplicity_correction"),
                "per_contrast_confidence_level",
                0.95,
            ),
            (("analysis_plan",), "points_to_proportion_divisor", 1),
            (
                ("analysis_plan", "success_thresholds"),
                "static_gain_absolute_points",
                1,
            ),
        )
        for path, field, value in mutations:
            with self.subTest(path=path, field=field):
                spec = valid_static_spec()
                _nested(spec, path)[field] = value
                _rehash(spec, ("analysis_plan",))
                with self.assertRaises(EvaluationSpecValidationError):
                    validate_evaluation_spec(spec)

    def test_evaluation_artifact_exactly_binds_to_completed_export(self) -> None:
        spec, record = evaluation_bound_to_completed_record()
        self.assertEqual(
            validate_evaluation_spec_against_experiment_manifest(spec, record),
            spec,
        )

        mutations = (
            ("completed_run_id", "different-run-0001"),
            ("completed_experiment_record_sha256", "f" * 64),
            ("training_seed", record["seeds"]["training"] + 1),
            ("physical_parameters", record["export"]["physical_parameters"] - 1),
            ("format", "gguf"),
            ("artifact_sha256", "a" * 64),
            ("bundle_sha256", "b" * 64),
            ("tokenizer_sha256", "c" * 64),
            ("inspection_report_sha256", "d" * 64),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                changed = copy.deepcopy(spec)
                _nested(changed, ("artifact",))[field] = value
                with self.assertRaisesRegex(
                    EvaluationArtifactBindingError,
                    field,
                ):
                    validate_evaluation_spec_against_experiment_manifest(
                        changed,
                        record,
                    )

    def test_load_evaluation_artifact_binding(self) -> None:
        spec, record = evaluation_bound_to_completed_record()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spec_path = root / "evaluation.json"
            record_path = root / "completed.json"
            atomic_write_json(spec_path, spec)
            atomic_write_json(record_path, record)
            self.assertEqual(
                load_evaluation_spec_against_experiment_manifest(
                    spec_path,
                    record_path,
                ),
                spec,
            )

    def test_frozen_parser_mapping_is_not_mutable_global_state(self) -> None:
        with self.assertRaises(TypeError):
            FROZEN_FENCE_LABELS["bash"] = ("bash",)  # type: ignore[index]

    def test_valid_static_and_interactive_contracts(self) -> None:
        for factory in (valid_static_spec, valid_interactive_spec):
            with self.subTest(factory=factory.__name__):
                spec = factory()
                validated = validate_evaluation_spec(spec)
                self.assertEqual(validated, spec)
                self.assertIsNot(validated, spec)
                _nested(validated, ("artifact",))["format"] = "changed"
                self.assertNotEqual(validated, spec)

        python_spec = valid_interactive_spec()
        parser = _nested(python_spec, ("parser",))
        parser["program_language"] = "python"
        parser["allowed_languages"] = ["python"]
        _rehash(python_spec, ("parser",))
        self.assertEqual(validate_evaluation_spec(python_spec), python_spec)

    def test_dense_sub_billion_artifact_and_completed_record_are_required(self) -> None:
        mutations = (
            ("architecture", "moe"),
            ("physical_parameters", 1_000_000_000),
            ("completed_experiment_record_sha256", "mutable"),
            ("inspection_report_sha256", "mutable"),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                spec = valid_static_spec()
                _nested(spec, ("artifact",))[field] = value
                with self.assertRaises(EvaluationSpecValidationError):
                    validate_evaluation_spec(spec)

    def test_benchmark_is_content_safe_and_role_routing_is_semantic(self) -> None:
        for field in ("prompt", "prompt_text", "fixtures"):
            with self.subTest(field=field):
                spec = valid_static_spec()
                _nested(spec, ("benchmark",))[field] = "hidden content"
                with self.assertRaises(EvaluationSpecValidationError):
                    validate_evaluation_spec(spec)

        mutations = (
            ("sealed", True),
            ("open_once", True),
            ("role", "sealed_id"),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                spec = valid_static_spec()
                _nested(spec, ("benchmark", "split"))[field] = value
                with self.assertRaisesRegex(
                    EvaluationSpecValidationError, "benchmark.split"
                ):
                    validate_evaluation_spec(spec)

        spec = valid_static_spec()
        _nested(spec, ("benchmark",))["suite"] = "interactive"
        with self.assertRaisesRegex(EvaluationSpecValidationError, "must equal"):
            validate_evaluation_spec(spec)

    def test_fixed_parser_policy_is_enforced_semantically(self) -> None:
        mutations = (
            ("allowed_languages", ["bash", "python"]),
            (
                "fence_labels",
                {"bash": ["", "bash", "shell", "zsh"], "python": ["py", "python", "python3"]},
            ),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                spec = valid_static_spec()
                parser = _nested(spec, ("parser",))
                parser[field] = value
                _rehash(spec, ("parser",))
                with self.assertRaisesRegex(EvaluationSpecValidationError, "parser"):
                    validate_evaluation_spec(spec)

    def test_deterministic_decode_and_mode_limits_have_no_hidden_branch(self) -> None:
        mutations = (
            (("decoding",), "do_sample", True),
            (("decoding",), "num_return_sequences", 2),
            (("limits",), "maximum_sequence_tokens", 1500),
            (("limits",), "maximum_response_bytes", 16_777_217),
            (("limits",), "syntax_timeout_seconds", 1e308),
            (("limits",), "action_limit", 1),
            (("limits",), "observation_bytes", 1),
        )
        for path, field, value in mutations:
            with self.subTest(field=field):
                spec = valid_static_spec()
                _nested(spec, path)[field] = value
                if path == ("decoding",):
                    _rehash(spec, path)
                with self.assertRaises(EvaluationSpecValidationError):
                    validate_evaluation_spec(spec)

        interactive = valid_interactive_spec()
        _nested(interactive, ("limits",))["action_limit"] = 7
        with self.assertRaisesRegex(
            EvaluationSpecValidationError, "frozen limit of eight"
        ):
            validate_evaluation_spec(interactive)

    def test_prompt_serialization_identity_is_required_and_policy_bound(self) -> None:
        spec = valid_static_spec()
        del _nested(spec, ("decoding",))["prompt_serialization_sha256"]
        with self.assertRaises(EvaluationSpecValidationError):
            validate_evaluation_spec(spec)

        spec = valid_static_spec()
        _nested(spec, ("decoding",))["prompt_serialization_sha256"] = "f" * 64
        with self.assertRaisesRegex(EvaluationSpecValidationError, "policy_sha256"):
            validate_evaluation_spec(spec)

    def test_fixture_count_and_all_pass_contract_are_fixed(self) -> None:
        spec = valid_static_spec()
        _nested(spec, ("benchmark",))["fixture_count"] = 9
        with self.assertRaisesRegex(EvaluationSpecValidationError, "fixture_count"):
            validate_evaluation_spec(spec)

        spec = valid_static_spec()
        fixture_policy = _nested(spec, ("fixture_policy",))
        fixture_policy["aggregation"] = "majority"
        _rehash(spec, ("fixture_policy",))
        with self.assertRaises(EvaluationSpecValidationError):
            validate_evaluation_spec(spec)

    def test_environment_and_tool_allowlist_are_complete_and_hashed(self) -> None:
        spec = valid_static_spec()
        variables = _nested(spec, ("environment",))["variables"]
        assert isinstance(variables, list)
        variables[:] = [entry for entry in variables if entry["name"] != "LC_ALL"]
        _rehash(spec, ("environment",))
        with self.assertRaisesRegex(EvaluationSpecValidationError, "LC_ALL"):
            validate_evaluation_spec(spec)

        spec = valid_static_spec()
        tool_policy = _nested(spec, ("tool_policy",))
        tool_policy["allowed_executables"] = ["bash", "python3"]
        tool_policy["allowlist_sha256"] = value_sha256(
            tool_policy["allowed_executables"]
        )
        _rehash(spec, ("tool_policy",))
        with self.assertRaisesRegex(EvaluationSpecValidationError, "bash_native"):
            validate_evaluation_spec(spec)

        for forbidden in (
            "gcc", "cc", "clang", "c++", "g++", "rustc", "go", "javac",
            "dotnet", "curl", "wget", "nc", "netcat", "ssh", "scp", "sftp",
            "telnet", "socat", "ftp",
        ):
            with self.subTest(forbidden=forbidden):
                candidate = valid_static_spec()
                tool_policy = _nested(candidate, ("tool_policy",))
                allowed = sorted([*tool_policy["allowed_executables"], forbidden])
                tool_policy["allowed_executables"] = allowed
                tool_policy["allowlist_sha256"] = value_sha256(allowed)
                _rehash(candidate, ("tool_policy",))
                with self.assertRaisesRegex(
                    EvaluationSpecValidationError, "frozen native allowlist"
                ):
                    validate_evaluation_spec(candidate)

        builtins_disabled = valid_static_spec()
        tool_policy = _nested(builtins_disabled, ("tool_policy",))
        tool_policy["shell_builtins_allowed"] = False
        _rehash(builtins_disabled, ("tool_policy",))
        with self.assertRaisesRegex(
            EvaluationSpecValidationError, "forbids frozen Bash built-ins"
        ):
            validate_evaluation_spec(builtins_disabled)

    def test_rerun_exclusion_timeout_and_failure_taxonomy_are_immutable(self) -> None:
        spec = valid_static_spec()
        rerun = _nested(spec, ("outcome_policy", "rerun"))
        rerun["maximum_attempts"] = 2
        _rehash(spec, ("outcome_policy", "rerun"))
        with self.assertRaisesRegex(EvaluationSpecValidationError, "never requires one"):
            validate_evaluation_spec(spec)

        spec = valid_static_spec()
        exclusion = _nested(spec, ("outcome_policy", "exclusion"))
        exclusion["manifest_sha256"] = "a" * 64
        _rehash(spec, ("outcome_policy", "exclusion"))
        with self.assertRaisesRegex(EvaluationSpecValidationError, "null manifest"):
            validate_evaluation_spec(spec)

        unsupported = valid_static_spec()
        exclusion = _nested(unsupported, ("outcome_policy", "exclusion"))
        exclusion.update(
            {
                "mode": "preregistered_manifest",
                "manifest_sha256": "a" * 64,
                "allowed_reason_codes": ["verifier_audit"],
            }
        )
        _rehash(unsupported, ("outcome_policy", "exclusion"))
        with self.assertRaisesRegex(
            EvaluationSpecValidationError, "only fail-closed none"
        ):
            validate_evaluation_spec(unsupported)

        spec = valid_static_spec()
        taxonomy = _nested(spec, ("outcome_policy", "failure_taxonomy"))
        taxonomy["precedence"] = list(reversed(FAILURE_PRECEDENCE))
        _rehash(spec, ("outcome_policy", "failure_taxonomy"))
        with self.assertRaisesRegex(EvaluationSpecValidationError, "frozen precedence"):
            validate_evaluation_spec(spec)

        spec = valid_static_spec()
        timeout = _nested(spec, ("outcome_policy", "timeout"))
        timeout["rerunnable"] = True
        _rehash(spec, ("outcome_policy", "timeout"))
        with self.assertRaises(EvaluationSpecValidationError):
            validate_evaluation_spec(spec)

    def test_task_result_schema_and_hash_only_output_policy_are_pinned(self) -> None:
        spec = valid_static_spec()
        _nested(spec, ("task_result",))["schema_sha256"] = "f" * 64
        with self.assertRaisesRegex(EvaluationSpecValidationError, "packaged"):
            validate_evaluation_spec(spec)

        spec = valid_static_spec()
        output = _nested(spec, ("output_policy",))
        output["retain_plaintext"] = True
        _rehash(spec, ("output_policy",))
        with self.assertRaises(EvaluationSpecValidationError):
            validate_evaluation_spec(spec)

    def test_task_result_is_exactly_bound_to_static_and_interactive_specs(self) -> None:
        static_spec = valid_static_spec()
        static_result = bound_static_result(static_spec)
        self.assertEqual(
            validate_task_result_against_evaluation_spec(static_result, static_spec),
            static_result,
        )

        interactive_spec = valid_interactive_spec()
        first_attempt = bound_interactive_result(interactive_spec)
        mark_internal_error(first_attempt)
        interactive_result = bound_interactive_result(interactive_spec)
        interactive_result["attempt"] = 2
        interactive_result["prior_attempt_terminal_statuses"] = ["internal_error"]
        interactive_result["prior_attempt_result_sha256s"] = [
            task_result_sha256(first_attempt)
        ]
        with self.assertRaisesRegex(
            TaskResultEvaluationBindingError, "chain or collection"
        ):
            validate_task_result_against_evaluation_spec(
                interactive_result, interactive_spec
            )
        self.assertEqual(
            validate_task_result_chain_against_evaluation_spec(
                [first_attempt, interactive_result], interactive_spec
            ),
            [first_attempt, interactive_result],
        )

    def test_task_result_identity_and_execution_contract_mismatches_fail(self) -> None:
        spec = valid_static_spec()
        mutations = (
            ("evaluation_id", "another-evaluation"),
            ("evaluation_spec_sha256", "f" * 64),
            ("run_id", "another-run-0001"),
            ("benchmark_id", "another-benchmark"),
            ("split_id", "another-split"),
            ("split_role", "shadow_validation"),
            ("sealed", True),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                result = bound_static_result(spec)
                result[field] = value
                with self.assertRaisesRegex(
                    TaskResultEvaluationBindingError, field
                ):
                    validate_task_result_against_evaluation_spec(result, spec)

        wrong_policy = bound_static_result(spec)
        wrong_policy["tool_policy"]["policy_sha256"] = "f" * 64
        with self.assertRaisesRegex(
            TaskResultEvaluationBindingError, "tool_policy.policy_sha256"
        ):
            validate_task_result_against_evaluation_spec(wrong_policy, spec)

        wrong_language = bound_static_result(spec)
        wrong_language["extraction"]["language"] = "python"
        with self.assertRaisesRegex(
            TaskResultEvaluationBindingError, "extraction.language"
        ):
            validate_task_result_against_evaluation_spec(wrong_language, spec)

    def test_observed_tool_set_is_derived_from_the_spec_allowlist(self) -> None:
        spec = valid_static_spec()
        for forbidden in ("curl", "gcc"):
            with self.subTest(forbidden=forbidden):
                result = bound_static_result(spec)
                result["tool_policy"]["observed_tools"] = sorted(
                    ["bash", forbidden]
                )
                with self.assertRaisesRegex(
                    TaskResultEvaluationBindingError, "observed_tools minus"
                ):
                    validate_task_result_against_evaluation_spec(result, spec)

    def test_task_result_must_match_committed_task_and_fixture_set(self) -> None:
        spec = valid_static_spec()

        unknown_task = bound_static_result(spec)
        unknown_task["prompt_id"] = opaque_task_id("fabricated-task")
        with self.assertRaisesRegex(
            TaskResultEvaluationBindingError, "task-commitment set"
        ):
            validate_task_result_against_evaluation_spec(unknown_task, spec)

        wrong_task_hash = bound_static_result(spec)
        wrong_task_hash["task_record_sha256"] = "f" * 64
        with self.assertRaisesRegex(
            TaskResultEvaluationBindingError, "task_record_sha256"
        ):
            validate_task_result_against_evaluation_spec(wrong_task_hash, spec)

        wrong_fixture_set = bound_static_result(spec)
        wrong_fixture_set["fixture_outcomes"][0]["fixture_id"] = opaque_fixture_id(
            "fabricated-fixture"
        )
        wrong_fixture_set["fixture_ids_sha256"] = fixture_id_set_sha256(
            fixture["fixture_id"]
            for fixture in wrong_fixture_set["fixture_outcomes"]
        )
        wrong_fixture_set["ordered_fixture_ids_sha256"] = ordered_fixture_ids_sha256(
            fixture["fixture_id"]
            for fixture in wrong_fixture_set["fixture_outcomes"]
        )
        with self.assertRaisesRegex(
            TaskResultEvaluationBindingError, "fixture_ids_sha256"
        ):
            validate_task_result_against_evaluation_spec(wrong_fixture_set, spec)

        reordered = bound_static_result(spec)
        reordered["fixture_outcomes"].reverse()
        reordered["ordered_fixture_ids_sha256"] = ordered_fixture_ids_sha256(
            fixture["fixture_id"] for fixture in reordered["fixture_outcomes"]
        )
        with self.assertRaisesRegex(
            TaskResultEvaluationBindingError, "ordered_fixture_ids_sha256"
        ):
            validate_task_result_against_evaluation_spec(reordered, spec)

    def test_task_result_limits_cannot_be_bypassed_by_passed_status(self) -> None:
        spec = valid_static_spec()
        limits = _nested(spec, ("limits",))
        mutations = (
            ("cpu_time_ms", limits["cpu_time_seconds"] * 1000 + 1),
            ("peak_rss_bytes", limits["memory_bytes"] + 1),
            ("stdout_bytes", limits["stdout_bytes"] + 1),
            ("stderr_bytes", limits["stderr_bytes"] + 1),
            ("peak_workspace_bytes", limits["workspace_bytes"] + 1),
            ("peak_pids", limits["pids"] + 1),
            ("peak_open_files", limits["open_files"] + 1),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                result = bound_static_result(spec)
                result["fixture_outcomes"][0][field] = value
                if field == "stderr_bytes":
                    result["fixture_outcomes"][0]["stderr_sha256"] = "d" * 64
                sync_resource_use(result)
                with self.assertRaisesRegex(
                    TaskResultEvaluationBindingError, field
                ):
                    validate_task_result_against_evaluation_spec(result, spec)

        oversized = bound_static_result(spec)
        oversized["generated_text_bytes"] = limits["maximum_response_bytes"] + 1
        oversized["extraction"]["response_bytes"] = oversized[
            "generated_text_bytes"
        ]
        with self.assertRaisesRegex(
            TaskResultEvaluationBindingError, "maximum_response_bytes"
        ):
            validate_task_result_against_evaluation_spec(oversized, spec)

        prompt_over = bound_static_result(spec)
        prompt_over["prompt_tokens"] = limits["maximum_prompt_tokens"] + 1
        with self.assertRaisesRegex(
            TaskResultEvaluationBindingError, "maximum_prompt_tokens"
        ):
            validate_task_result_against_evaluation_spec(prompt_over, spec)

        generation_over = bound_static_result(spec)
        generation_over["generated_tokens"] = (
            _nested(spec, ("decoding",))["maximum_new_tokens"] + 1
        )
        with self.assertRaisesRegex(
            TaskResultEvaluationBindingError, "maximum_new_tokens"
        ):
            validate_task_result_against_evaluation_spec(generation_over, spec)

        syntax_over = bound_static_result(spec)
        syntax_over["syntax_duration_ms"] = limits["syntax_timeout_seconds"] * 1000 + 1
        with self.assertRaisesRegex(
            TaskResultEvaluationBindingError, "syntax_timeout_seconds"
        ):
            validate_task_result_against_evaluation_spec(syntax_over, spec)

        slow = bound_static_result(spec)
        slow["fixture_outcomes"][0]["wall_time_ms"] = (
            limits["fixture_timeout_seconds"] * 1000 + 1
        )
        sync_resource_use(slow)
        with self.assertRaisesRegex(
            TaskResultEvaluationBindingError, "per-fixture/action timeout"
        ):
            validate_task_result_against_evaluation_spec(slow, spec)

        joint_timeout_resource = bound_static_result(spec)
        joint_timeout_resource["fixture_outcomes"][0].update(
            {
                "status": "timeout",
                "exit_code": None,
                "verifier_result_sha256": None,
                "wall_time_ms": limits["fixture_timeout_seconds"] * 1000,
                "cpu_time_ms": limits["cpu_time_seconds"] * 1000 + 1,
            }
        )
        joint_timeout_resource["terminal_status"] = "timeout"
        sync_resource_use(joint_timeout_resource)
        self.assertEqual(
            validate_task_result_against_evaluation_spec(
                joint_timeout_resource, spec
            ),
            joint_timeout_resource,
        )

        interactive_spec = valid_interactive_spec()
        excessive_observation = bound_interactive_result(interactive_spec)
        excessive_observation["action_trace"][0]["observation_bytes"] = (
            _nested(interactive_spec, ("limits",))["observation_bytes"] + 1
        )
        with self.assertRaisesRegex(
            TaskResultEvaluationBindingError, "observation limit"
        ):
            validate_task_result_against_evaluation_spec(
                excessive_observation, interactive_spec
            )

    def test_attempt_chain_hashes_statuses_and_collection_coverage_are_exact(self) -> None:
        spec = valid_interactive_spec()
        first = bound_interactive_result(spec)
        mark_internal_error(first)
        second = bound_interactive_result(spec)
        second["attempt"] = 2
        second["prior_attempt_terminal_statuses"] = ["internal_error"]
        second["prior_attempt_result_sha256s"] = [task_result_sha256(first)]
        self.assertEqual(
            validate_task_result_chain_against_evaluation_spec(
                [first, second], spec
            ),
            [first, second],
        )

        bad_hash = copy.deepcopy(second)
        bad_hash["prior_attempt_result_sha256s"] = ["f" * 64]
        with self.assertRaisesRegex(
            TaskResultEvaluationBindingError, "canonical hashes"
        ):
            validate_task_result_chain_against_evaluation_spec(
                [first, bad_hash], spec
            )

        bad_status = copy.deepcopy(second)
        bad_status["prior_attempt_terminal_statuses"] = ["verifier_failure"]
        with self.assertRaisesRegex(
            TaskResultEvaluationBindingError, "statuses of all earlier"
        ):
            validate_task_result_chain_against_evaluation_spec(
                [first, bad_status], spec
            )

        static_spec = valid_static_spec()
        collection = [
            bound_static_result(static_spec, index)
            for index in range(2)
        ]
        self.assertEqual(
            validate_task_result_collection_against_evaluation_spec(
                collection, static_spec
            ),
            sorted(collection, key=lambda result: result["prompt_id"]),
        )
        with self.assertRaisesRegex(
            TaskResultEvaluationBindingError, "missing committed prompt IDs"
        ):
            validate_task_result_collection_against_evaluation_spec(
                collection[:1], static_spec
            )

    def test_collection_reuses_one_validated_spec_without_weakening_binding(self) -> None:
        spec = valid_static_spec()
        collection = [bound_static_result(spec, index) for index in range(2)]
        with patch.object(
            evaluation_specs_module,
            "validate_evaluation_spec",
            wraps=evaluation_specs_module.validate_evaluation_spec,
        ) as validator:
            selected = validate_task_result_collection_against_evaluation_spec(
                collection,
                spec,
            )
        self.assertEqual(
            selected,
            sorted(collection, key=lambda result: result["prompt_id"]),
        )
        self.assertEqual(validator.call_count, 1)

        tampered = copy.deepcopy(collection)
        tampered[0]["task_record_sha256"] = "f" * 64
        with self.assertRaisesRegex(
            TaskResultEvaluationBindingError,
            "task_record_sha256",
        ):
            validate_task_result_collection_against_evaluation_spec(
                tampered,
                spec,
            )

    def test_fixture_stop_policy_and_committed_order_are_enforced(self) -> None:
        run_all = valid_static_spec()
        incomplete = bound_static_result(run_all)
        incomplete["fixture_outcomes"][0]["status"] = "functional_failure"
        set_not_run(incomplete["fixture_outcomes"][-1])
        incomplete["terminal_status"] = "functional_failure"
        sync_resource_use(incomplete)
        with self.assertRaisesRegex(
            TaskResultEvaluationBindingError, "requires every fixture"
        ):
            validate_task_result_against_evaluation_spec(incomplete, run_all)

        stop_early = valid_static_spec()
        fixture_policy = _nested(stop_early, ("fixture_policy",))
        fixture_policy["stop_after_first_failure"] = True
        _rehash(stop_early, ("fixture_policy",))
        stopped = bound_static_result(stop_early)
        stopped["fixture_outcomes"][1]["status"] = "functional_failure"
        for fixture in stopped["fixture_outcomes"][2:]:
            set_not_run(fixture)
        stopped["terminal_status"] = "functional_failure"
        sync_resource_use(stopped)
        self.assertEqual(
            validate_task_result_against_evaluation_spec(stopped, stop_early),
            stopped,
        )

        executed_after_failure = copy.deepcopy(stopped)
        executed_after_failure["fixture_outcomes"][2] = copy.deepcopy(
            bound_static_result(stop_early)["fixture_outcomes"][2]
        )
        sync_resource_use(executed_after_failure)
        with self.assertRaisesRegex(
            TaskResultEvaluationBindingError, "forbids execution after"
        ):
            validate_task_result_against_evaluation_spec(
                executed_after_failure, stop_early
            )

    def test_reruns_are_execution_only_and_scored_selection_is_total(self) -> None:
        spec = valid_interactive_spec()
        first = bound_interactive_result(spec, 0)
        mark_internal_error(first)
        changed_program = bound_interactive_result(spec, 0)
        changed_program["attempt"] = 2
        changed_program["generated_text_sha256"] = "f" * 64
        changed_program["extraction"]["code_sha256"] = "e" * 64
        changed_program["prior_attempt_terminal_statuses"] = ["internal_error"]
        changed_program["prior_attempt_result_sha256s"] = [
            task_result_sha256(first)
        ]
        with self.assertRaisesRegex(
            TaskResultEvaluationBindingError, "execution-only"
        ):
            validate_task_result_chain_against_evaluation_spec(
                [first, changed_program], spec
            )

        changed_action = bound_interactive_result(spec, 0)
        changed_action["attempt"] = 2
        changed_action["action_trace"][0]["action_sha256"] = "f" * 64
        changed_action["prior_attempt_terminal_statuses"] = ["internal_error"]
        changed_action["prior_attempt_result_sha256s"] = [
            task_result_sha256(first)
        ]
        with self.assertRaisesRegex(
            TaskResultEvaluationBindingError, "exact prefix"
        ):
            validate_task_result_chain_against_evaluation_spec(
                [first, changed_action], spec
            )

        extended = bound_interactive_result(spec, 0)
        extra_action = copy.deepcopy(extended["action_trace"][0])
        extra_action.update({"action_index": 2, "action_sha256": "d" * 64})
        extended["action_trace"].append(extra_action)
        extended["attempt"] = 2
        extended["prior_attempt_terminal_statuses"] = ["internal_error"]
        extended["prior_attempt_result_sha256s"] = [task_result_sha256(first)]
        sync_resource_use(extended)
        self.assertEqual(
            validate_task_result_chain_against_evaluation_spec(
                [first, extended], spec
            ),
            [first, extended],
        )

        verifier_first = bound_interactive_result(spec, 0)
        verifier_first["fixture_outcomes"][0]["status"] = "verifier_failure"
        verifier_first["terminal_status"] = "verifier_failure"
        sync_resource_use(verifier_first)
        forbidden_extension = copy.deepcopy(extended)
        forbidden_extension["prior_attempt_terminal_statuses"] = [
            "verifier_failure"
        ]
        forbidden_extension["prior_attempt_result_sha256s"] = [
            task_result_sha256(verifier_first)
        ]
        with self.assertRaisesRegex(
            TaskResultEvaluationBindingError, "extension is allowed only"
        ):
            validate_task_result_chain_against_evaluation_spec(
                [verifier_first, forbidden_extension], spec
            )

        unfinished_other = bound_interactive_result(spec, 1)
        with self.assertRaisesRegex(
            TaskResultEvaluationBindingError, "not a complete chain"
        ):
            validate_task_result_collection_against_evaluation_spec(
                [first, unfinished_other], spec
            )

        task0_second = bound_interactive_result(spec, 0)
        task0_second["attempt"] = 2
        task0_second["prior_attempt_terminal_statuses"] = ["internal_error"]
        task0_second["prior_attempt_result_sha256s"] = [task_result_sha256(first)]

        task1_first = bound_interactive_result(spec, 1)
        mark_internal_error(task1_first)
        task1_second = copy.deepcopy(task1_first)
        task1_second["attempt"] = 2
        task1_second["prior_attempt_terminal_statuses"] = ["internal_error"]
        task1_second["prior_attempt_result_sha256s"] = [
            task_result_sha256(task1_first)
        ]
        selected = select_scored_task_results_against_evaluation_spec(
            [first, task0_second, task1_first, task1_second], spec
        )
        self.assertEqual(len(selected), 2)
        by_prompt = {result["prompt_id"]: result for result in selected}
        self.assertEqual(by_prompt[first["prompt_id"]]["terminal_status"], "passed")
        self.assertEqual(
            by_prompt[task1_first["prompt_id"]]["terminal_status"],
            "internal_error",
        )
        self.assertEqual(by_prompt[task1_first["prompt_id"]]["attempt"], 2)

    def test_task_result_fixture_mode_action_and_rerun_mismatches_fail(self) -> None:
        static_spec = valid_static_spec()
        too_many = bound_static_result(static_spec)
        extra_fixture = copy.deepcopy(too_many["fixture_outcomes"][0])
        extra_fixture["fixture_id"] = opaque_fixture_id("static-task-001-fx-extra")
        too_many["fixture_outcomes"].append(extra_fixture)
        too_many["fixture_ids_sha256"] = fixture_id_set_sha256(
            fixture["fixture_id"] for fixture in too_many["fixture_outcomes"]
        )
        too_many["ordered_fixture_ids_sha256"] = ordered_fixture_ids_sha256(
            fixture["fixture_id"] for fixture in too_many["fixture_outcomes"]
        )
        with self.assertRaisesRegex(
            TaskResultEvaluationBindingError, "fixtures_per_task"
        ):
            validate_task_result_against_evaluation_spec(too_many, static_spec)

        later_attempt = bound_static_result(static_spec)
        later_attempt["attempt"] = 2
        later_attempt["prior_attempt_terminal_statuses"] = ["internal_error"]
        later_attempt["prior_attempt_result_sha256s"] = ["f" * 64]
        with self.assertRaisesRegex(
            TaskResultEvaluationBindingError, "maximum_attempts"
        ):
            validate_task_result_against_evaluation_spec(later_attempt, static_spec)

        interactive_spec = valid_interactive_spec()
        ineligible_rerun = bound_interactive_result(interactive_spec)
        ineligible_rerun["attempt"] = 2
        ineligible_rerun["prior_attempt_terminal_statuses"] = ["passed"]
        ineligible_rerun["prior_attempt_result_sha256s"] = ["f" * 64]
        with self.assertRaisesRegex(
            TaskResultEvaluationBindingError, "not eligible for rerun"
        ):
            validate_task_result_against_evaluation_spec(
                ineligible_rerun, interactive_spec
            )

        wrong_mode_and_limit = bound_interactive_result(interactive_spec)
        wrong_mode_and_limit.update(
            {
                "evaluation_id": static_spec["evaluation_id"],
                "evaluation_spec_sha256": evaluation_spec_sha256(static_spec),
                "benchmark_id": _nested(static_spec, ("benchmark",))[
                    "benchmark_id"
                ],
                "split_id": _nested(static_spec, ("benchmark", "split"))["name"],
                "split_role": _nested(static_spec, ("benchmark", "split"))[
                    "role"
                ],
                "sealed": True,
            }
        )
        wrong_mode_and_limit["tool_policy"]["policy_sha256"] = _nested(
            static_spec, ("tool_policy",)
        )["policy_sha256"]
        with self.assertRaisesRegex(
            TaskResultEvaluationBindingError, "benchmark suite"
        ):
            validate_task_result_against_evaluation_spec(
                wrong_mode_and_limit, static_spec
            )

    def test_joint_loader_validates_both_documents(self) -> None:
        spec = valid_static_spec()
        result = bound_static_result(spec)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spec_path = root / "evaluation.json"
            result_path = root / "result.json"
            spec_path.write_text(json.dumps(spec), encoding="utf-8")
            result_path.write_text(json.dumps(result), encoding="utf-8")
            self.assertEqual(
                load_task_result_against_evaluation_spec(result_path, spec_path),
                result,
            )

    def test_policy_hashes_detect_unsealed_changes(self) -> None:
        spec = valid_static_spec()
        _nested(spec, ("decoding",))["maximum_new_tokens"] = 512
        with self.assertRaisesRegex(EvaluationSpecValidationError, "policy_sha256"):
            validate_evaluation_spec(spec)

    def test_strict_load_canonical_hash_and_atomic_write(self) -> None:
        spec = valid_static_spec()
        reordered = dict(reversed(list(spec.items())))
        self.assertEqual(
            evaluation_spec_sha256(spec), evaluation_spec_sha256(reordered)
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            duplicate = root / "duplicate.json"
            duplicate.write_text(
                '{"schema_version":"1.0.0","schema_version":"1.0.0"}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(EvaluationSpecValidationError, "duplicate"):
                load_evaluation_spec(duplicate)

            target = root / "nested" / "evaluation.json"
            returned = write_evaluation_spec(target, spec, schema_path=SCHEMA_PATH)
            self.assertEqual(returned, target)
            self.assertEqual(target.read_bytes(), canonical_json_bytes(spec) + b"\n")
            self.assertEqual(load_evaluation_spec(target), spec)


class EvaluationSchemaContractTests(unittest.TestCase):
    def test_external_schema_cannot_weaken_the_frozen_contract(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        schema["additionalProperties"] = True
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "weakened.schema.json"
            path.write_text(json.dumps(schema), encoding="utf-8")
            with self.assertRaisesRegex(
                EvaluationSpecValidationError, "frozen packaged"
            ):
                validate_evaluation_spec(valid_static_spec(), schema_path=path)

    def test_repository_example_is_valid_and_content_addressed(self) -> None:
        example = load_evaluation_spec(EXAMPLE_PATH)
        completed_path = ROOT / "examples" / "experiment-manifest.example.json"
        completed = json.loads(completed_path.read_text(encoding="utf-8"))
        self.assertEqual(
            validate_evaluation_spec_against_experiment_manifest(
                example,
                completed,
            ),
            example,
        )
        self.assertEqual(
            evaluation_spec_sha256(example),
            "79cf5be3ea246b98fbfe87264ce7d006c41d97a2d2e6356e36de96a883ade9aa",
        )

    def test_root_and_packaged_schemas_are_byte_identical(self) -> None:
        self.assertEqual(SCHEMA_PATH.read_bytes(), PACKAGED_SCHEMA_PATH.read_bytes())

    def test_every_object_property_is_explicitly_required(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

        def visit(node: object, path: str = "$") -> None:
            if isinstance(node, dict):
                if node.get("type") == "object" and "properties" in node:
                    self.assertFalse(node.get("additionalProperties", True), path)
                    self.assertEqual(
                        set(node["properties"]), set(node.get("required", [])), path
                    )
                for key, value in node.items():
                    visit(value, f"{path}.{key}")
            elif isinstance(node, list):
                for index, value in enumerate(node):
                    visit(value, f"{path}[{index}]")

        visit(schema)


if __name__ == "__main__":
    unittest.main()
