from __future__ import annotations

from copy import deepcopy
import json
import math
import unittest

from cbds.statistics import (
    OUTCOME_CONTRACT_VERSION,
    STATISTICS_METHOD_VERSION,
    PairedBinaryOutcomes,
    StatisticsValidationError,
    holm_adjust,
    noninferiority_from_interval,
    paired_sign_flip_randomization,
    summarize_paired_binary,
    two_way_paired_bootstrap,
    validate_paired_binary_outcomes,
)


REFERENCE = (
    (1, 0, 1, 0),
    (1, 1, 0, 0),
    (0, 1, 0, 0),
)
COMPARISON = (
    (1, 1, 1, 0),
    (1, 1, 1, 0),
    (1, 1, 0, 1),
)
SEEDS = (11, 22, 33)
TASKS = ("task-a", "task-b", "task-c", "task-d")


def outcome_records() -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for arm, matrix in (("dense", REFERENCE), ("tccr", COMPARISON)):
        for seed_index, seed in enumerate(SEEDS):
            for task_index, task in enumerate(TASKS):
                records.append(
                    {
                        "arm": arm,
                        "seed": seed,
                        "task": task,
                        "passed": matrix[seed_index][task_index],
                    }
                )
    return records


def validated_outcomes() -> PairedBinaryOutcomes:
    return validate_paired_binary_outcomes(
        outcome_records(), reference_arm="dense", comparison_arm="tccr"
    )


class ValidationTests(unittest.TestCase):
    def test_normalizes_complete_cube_independent_of_record_order(self) -> None:
        cube = validate_paired_binary_outcomes(
            reversed(outcome_records()),
            reference_arm="dense",
            comparison_arm="tccr",
        )

        self.assertEqual(cube.seeds, SEEDS)
        self.assertEqual(cube.tasks, TASKS)
        self.assertEqual(cube.reference, REFERENCE)
        self.assertEqual(cube.comparison, COMPARISON)
        self.assertEqual(cube.seed_count, 3)
        self.assertEqual(cube.task_count, 4)
        self.assertEqual(cube.cell_count, 24)
        self.assertEqual(
            cube.contract_record(),
            {
                "contract_version": OUTCOME_CONTRACT_VERSION,
                "reference_arm": "dense",
                "comparison_arm": "tccr",
                "seed_count": 3,
                "task_count": 4,
                "cell_count": 24,
                "minimum_seeds": 2,
                "minimum_tasks": 2,
                "fixtures_nested_upstream": True,
            },
        )

    def test_accepts_boolean_binary_outcomes_and_normalizes_to_integers(self) -> None:
        records = outcome_records()
        for record in records:
            record["passed"] = bool(record["passed"])
        cube = validate_paired_binary_outcomes(
            records, reference_arm="dense", comparison_arm="tccr"
        )
        self.assertEqual(cube.reference, REFERENCE)
        self.assertTrue(
            all(type(value) is int for row in cube.comparison for value in row)
        )

    def test_rejects_missing_and_duplicate_paired_cells(self) -> None:
        missing = outcome_records()[:-1]
        duplicate = outcome_records()
        duplicate.append(deepcopy(duplicate[0]))
        for records in (missing, duplicate):
            with self.subTest(record_count=len(records)):
                with self.assertRaises(StatisticsValidationError):
                    validate_paired_binary_outcomes(
                        records, reference_arm="dense", comparison_arm="tccr"
                    )

    def test_rejects_nonbinary_outcomes_including_nonfinite_values(self) -> None:
        for invalid in (2, -1, 0.0, 1.0, math.nan, math.inf, "1", None):
            records = outcome_records()
            records[0]["passed"] = invalid
            with self.subTest(invalid=invalid):
                with self.assertRaises(StatisticsValidationError):
                    validate_paired_binary_outcomes(
                        records, reference_arm="dense", comparison_arm="tccr"
                    )

    def test_rejects_insufficient_seed_or_task_replication(self) -> None:
        one_seed = [record for record in outcome_records() if record["seed"] == 11]
        one_task = [record for record in outcome_records() if record["task"] == "task-a"]
        for records in (one_seed, one_task):
            with self.subTest(record_count=len(records)):
                with self.assertRaises(StatisticsValidationError):
                    validate_paired_binary_outcomes(
                        records, reference_arm="dense", comparison_arm="tccr"
                    )

    def test_rejects_malformed_rows_arms_seeds_and_container(self) -> None:
        malformed_cases: list[object] = []
        extra = outcome_records()
        extra[0]["fixture"] = "not-allowed"
        malformed_cases.append(extra)
        wrong_arm = outcome_records()
        wrong_arm[0]["arm"] = "random"
        malformed_cases.append(wrong_arm)
        boolean_seed = outcome_records()
        boolean_seed[0]["seed"] = True
        malformed_cases.append(boolean_seed)
        malformed_cases.extend(({"arm": "dense"}, "not-records", [None]))

        for records in malformed_cases:
            with self.subTest(records_type=type(records).__name__):
                with self.assertRaises(StatisticsValidationError):
                    validate_paired_binary_outcomes(
                        records,  # type: ignore[arg-type]
                        reference_arm="dense",
                        comparison_arm="tccr",
                    )

        with self.assertRaises(StatisticsValidationError):
            validate_paired_binary_outcomes(
                outcome_records(), reference_arm="dense", comparison_arm="dense"
            )
        with self.assertRaises(StatisticsValidationError):
            validate_paired_binary_outcomes(
                outcome_records(),
                reference_arm="dense",
                comparison_arm="tccr",
                minimum_seeds=1,
            )

    def test_consumers_reject_manually_constructed_invalid_cube(self) -> None:
        malformed = PairedBinaryOutcomes(
            "dense",
            "tccr",
            (1, 2),
            ("a", "b"),
            ((True, 0), (0, 1)),  # type: ignore[arg-type]
            ((1, 0), (0, 1)),
            2,
            2,
        )
        with self.assertRaises(StatisticsValidationError):
            summarize_paired_binary(malformed)
        with self.assertRaises(StatisticsValidationError):
            summarize_paired_binary("not-a-cube")  # type: ignore[arg-type]


class SummaryTests(unittest.TestCase):
    def test_macro_pass_at_one_and_paired_difference_golden(self) -> None:
        result = summarize_paired_binary(validated_outcomes())

        self.assertEqual(result["method"], "paired_binary_macro_pass_at_1")
        self.assertEqual(result["method_version"], STATISTICS_METHOD_VERSION)
        self.assertAlmostEqual(result["arm_macro_pass_at_1"]["dense"], 5 / 12)
        self.assertAlmostEqual(result["arm_macro_pass_at_1"]["tccr"], 9 / 12)
        self.assertAlmostEqual(result["paired_difference"], 1 / 3)
        self.assertEqual(
            [entry["paired_difference_comparison_minus_reference"] for entry in result["per_seed"]],
            [0.25, 0.25, 0.5],
        )
        self.assertEqual(result["policy"]["difference_direction"], "comparison_minus_reference")
        json.dumps(result, allow_nan=False, sort_keys=True)

    def test_swapping_arm_roles_negates_the_paired_estimand(self) -> None:
        forward = summarize_paired_binary(validated_outcomes())
        reversed_cube = validate_paired_binary_outcomes(
            outcome_records(), reference_arm="tccr", comparison_arm="dense"
        )
        reverse = summarize_paired_binary(reversed_cube)

        self.assertEqual(reverse["paired_difference"], -forward["paired_difference"])
        self.assertEqual(
            reverse["arm_macro_pass_at_1"]["dense"],
            forward["arm_macro_pass_at_1"]["dense"],
        )
        self.assertEqual(
            reverse["arm_macro_pass_at_1"]["tccr"],
            forward["arm_macro_pass_at_1"]["tccr"],
        )


class BootstrapTests(unittest.TestCase):
    def test_crossed_bootstrap_is_deterministic_and_records_policy(self) -> None:
        first = two_way_paired_bootstrap(
            validated_outcomes(), resamples=2_000, random_seed=12_345
        )
        second = two_way_paired_bootstrap(
            validated_outcomes(), resamples=2_000, random_seed=12_345
        )

        self.assertEqual(first, second)
        self.assertEqual(first["method_version"], STATISTICS_METHOD_VERSION)
        self.assertEqual(first["estimate"], 1 / 3)
        self.assertEqual(first["policy"]["resamples"], 2_000)
        self.assertEqual(first["policy"]["random_seed"], 12_345)
        self.assertEqual(first["policy"]["cell_evaluations"], 24_000)
        self.assertEqual(first["policy"]["seed_resampling"], "independent_with_replacement")
        self.assertEqual(first["policy"]["task_resampling"], "independent_with_replacement")
        self.assertEqual(first["confidence_interval"]["lower"], 0.0)
        self.assertEqual(first["confidence_interval"]["upper"], 2 / 3)
        json.dumps(first, allow_nan=False, sort_keys=True)

    def test_bootstrap_rejects_invalid_policy_parameters(self) -> None:
        cube = validated_outcomes()
        invalid_calls = (
            {"resamples": 99, "random_seed": 0},
            {"resamples": True, "random_seed": 0},
            {"resamples": 1_000_001, "random_seed": 0},
            {"resamples": 100, "random_seed": -1},
            {"resamples": 100, "random_seed": 1 << 64},
            {"resamples": 100, "random_seed": 0, "confidence_level": 0.0},
            {"resamples": 100, "random_seed": 0, "confidence_level": 1.0},
            {"resamples": 100, "random_seed": 0, "confidence_level": math.nan},
        )
        for kwargs in invalid_calls:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(StatisticsValidationError):
                    two_way_paired_bootstrap(cube, **kwargs)  # type: ignore[arg-type]


class RandomizationTests(unittest.TestCase):
    def test_exact_seed_sign_flip_golden(self) -> None:
        result = paired_sign_flip_randomization(validated_outcomes(), unit="seed")

        self.assertEqual(result["method"], "paired_sign_flip_randomization")
        self.assertEqual(result["method_version"], STATISTICS_METHOD_VERSION)
        self.assertEqual(result["total_units"], 3)
        self.assertEqual(result["effective_nonzero_units"], 3)
        self.assertEqual(result["observed_paired_difference"], 1 / 3)
        self.assertEqual(result["p_value"], 0.25)
        self.assertEqual(result["policy"]["mode"], "exact")
        self.assertEqual(result["policy"]["permutation_count"], 8)
        self.assertIsNone(result["policy"]["random_seed"])

    def test_exact_task_sign_flip_and_one_sided_alternative(self) -> None:
        two_sided = paired_sign_flip_randomization(
            validated_outcomes(), unit="task"
        )
        greater = paired_sign_flip_randomization(
            validated_outcomes(), unit="seed", alternative="greater"
        )
        self.assertEqual(two_sided["effective_nonzero_units"], 4)
        self.assertEqual(two_sided["p_value"], 0.125)
        self.assertEqual(greater["p_value"], 0.125)

    def test_monte_carlo_sign_flip_is_deterministic_golden(self) -> None:
        kwargs = {
            "unit": "task",
            "exact_max_units": 2,
            "monte_carlo_draws": 1_000,
            "random_seed": 7,
        }
        first = paired_sign_flip_randomization(validated_outcomes(), **kwargs)  # type: ignore[arg-type]
        second = paired_sign_flip_randomization(validated_outcomes(), **kwargs)  # type: ignore[arg-type]

        self.assertEqual(first, second)
        self.assertEqual(first["policy"]["mode"], "deterministic_monte_carlo")
        self.assertEqual(first["policy"]["monte_carlo_correction"], "plus_one")
        self.assertEqual(first["policy"]["monte_carlo_draws"], 1_000)
        self.assertEqual(first["policy"]["random_seed"], 7)
        self.assertEqual(first["p_value"], 0.11888111888111888)
        json.dumps(first, allow_nan=False, sort_keys=True)

    def test_randomization_rejects_invalid_or_incomplete_policy(self) -> None:
        cube = validated_outcomes()
        invalid_calls = (
            {"unit": "fixture"},
            {"alternative": "different"},
            {"exact_max_units": 0},
            {"exact_max_units": 21},
            {"monte_carlo_draws": 99},
            {"random_seed": -1},
            {"unit": "task", "exact_max_units": 2},
            {"unit": "task", "exact_max_units": 2, "monte_carlo_draws": 100},
            {
                "unit": "task",
                "exact_max_units": 2,
                "monte_carlo_draws": 99,
                "random_seed": 0,
            },
            {
                "unit": "task",
                "exact_max_units": 2,
                "monte_carlo_draws": 100,
                "random_seed": -1,
            },
        )
        for kwargs in invalid_calls:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(StatisticsValidationError):
                    paired_sign_flip_randomization(cube, **kwargs)  # type: ignore[arg-type]


class HolmTests(unittest.TestCase):
    def test_holm_adjustment_and_step_down_decisions_golden(self) -> None:
        result = holm_adjust([("b", 0.04), ("a", 0.01), ("c", 0.03)])
        hypotheses = {item["label"]: item for item in result["hypotheses"]}

        self.assertEqual(result["method"], "holm_step_down")
        self.assertEqual(result["method_version"], STATISTICS_METHOD_VERSION)
        self.assertEqual(hypotheses["a"]["rank"], 1)
        self.assertEqual(hypotheses["c"]["rank"], 2)
        self.assertEqual(hypotheses["b"]["rank"], 3)
        self.assertAlmostEqual(hypotheses["a"]["adjusted_p_value"], 0.03)
        self.assertAlmostEqual(hypotheses["b"]["adjusted_p_value"], 0.06)
        self.assertAlmostEqual(hypotheses["c"]["adjusted_p_value"], 0.06)
        self.assertTrue(hypotheses["a"]["rejected"])
        self.assertFalse(hypotheses["b"]["rejected"])
        self.assertFalse(hypotheses["c"]["rejected"])

    def test_holm_ties_are_ordered_by_utf8_label(self) -> None:
        result = holm_adjust({"z": 0.01, "a": 0.01})
        ranks = {item["label"]: item["rank"] for item in result["hypotheses"]}
        self.assertEqual(ranks, {"a": 1, "z": 2})

    def test_holm_rejects_invalid_families(self) -> None:
        invalid_families = (
            [],
            [("a", 0.1), ("a", 0.2)],
            [("a", -0.1)],
            [("a", 1.1)],
            [("a", math.nan)],
            [("a", math.inf)],
            [("a", True)],
            [("", 0.1)],
            [("a", 0.1, "extra")],
        )
        for family in invalid_families:
            with self.subTest(family=family):
                with self.assertRaises(StatisticsValidationError):
                    holm_adjust(family)  # type: ignore[arg-type]
        for alpha in (0.0, 1.0, math.nan, True):
            with self.subTest(alpha=alpha):
                with self.assertRaises(StatisticsValidationError):
                    holm_adjust({"a": 0.1}, alpha=alpha)  # type: ignore[arg-type]


class NoninferiorityTests(unittest.TestCase):
    def test_noninferiority_uses_strict_lower_bound_rule(self) -> None:
        passing = noninferiority_from_interval(
            lower_bound=-0.019,
            upper_bound=0.01,
            margin=0.02,
            confidence_level=0.95,
        )
        boundary = noninferiority_from_interval(
            lower_bound=-0.02,
            upper_bound=0.01,
            margin=0.02,
            confidence_level=0.95,
        )

        self.assertTrue(passing["noninferior"])
        self.assertFalse(boundary["noninferior"])
        self.assertEqual(passing["method_version"], STATISTICS_METHOD_VERSION)
        self.assertEqual(
            passing["policy"]["decision_rule"],
            "lower_bound_strictly_greater_than_negative_margin",
        )
        json.dumps(passing, allow_nan=False, sort_keys=True)

    def test_noninferiority_rejects_invalid_intervals_and_policy(self) -> None:
        invalid_calls = (
            {"lower_bound": 0.1, "upper_bound": 0.0, "margin": 0.02, "confidence_level": 0.95},
            {"lower_bound": 0.0, "upper_bound": 0.1, "margin": 0.0, "confidence_level": 0.95},
            {"lower_bound": 0.0, "upper_bound": 0.1, "margin": -0.1, "confidence_level": 0.95},
            {"lower_bound": math.nan, "upper_bound": 0.1, "margin": 0.1, "confidence_level": 0.95},
            {"lower_bound": 0.0, "upper_bound": math.inf, "margin": 0.1, "confidence_level": 0.95},
            {"lower_bound": 0.0, "upper_bound": 0.1, "margin": 0.1, "confidence_level": 1.0},
        )
        for kwargs in invalid_calls:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(StatisticsValidationError):
                    noninferiority_from_interval(**kwargs)


if __name__ == "__main__":
    unittest.main()
