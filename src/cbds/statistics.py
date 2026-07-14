"""Deterministic confirmatory statistics for paired binary task outcomes.

This module contains no research results and performs no file or network I/O.
It validates a complete arm-by-training-seed-by-semantic-task outcome cube,
where each binary task outcome already aggregates all of that task's fixtures.
All resampling policies and pseudo-random seeds are explicit in returned
machine-readable records.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import math
from typing import Any, Final, Literal


STATISTICS_METHOD_VERSION: Final[str] = "1.0.0"
OUTCOME_CONTRACT_VERSION: Final[str] = "paired-binary-semantic-task-v1"
_MAX_CELLS: Final[int] = 2_000_000
_MAX_RESAMPLES: Final[int] = 1_000_000
_MAX_BOOTSTRAP_CELL_EVALUATIONS: Final[int] = 100_000_000
_MAX_MONTE_CARLO_DRAWS: Final[int] = 10_000_000
_MAX_EXACT_UNITS: Final[int] = 20
_UINT64_MASK: Final[int] = (1 << 64) - 1

RandomizationUnit = Literal["seed", "task", "seed_task"]
Alternative = Literal["two_sided", "greater", "less"]


class StatisticsValidationError(ValueError):
    """Raised when an input or statistical policy fails closed validation."""

    def __init__(self, errors: str | Iterable[str]) -> None:
        if isinstance(errors, str):
            normalized = (errors,)
        else:
            normalized = tuple(str(error) for error in errors)
        if not normalized:
            normalized = ("statistics validation failed",)
        self.errors = normalized
        super().__init__("statistics validation failed: " + "; ".join(normalized))


@dataclass(frozen=True, slots=True)
class PairedBinaryOutcomes:
    """Validated complete paired outcome cube.

    Matrices are indexed first by ``seeds`` and then by ``tasks``. Values are
    normalized integers in ``{0, 1}``; tuple nesting makes the validated cube
    immutable without external dependencies.
    """

    reference_arm: str
    comparison_arm: str
    seeds: tuple[int, ...]
    tasks: tuple[str, ...]
    reference: tuple[tuple[int, ...], ...]
    comparison: tuple[tuple[int, ...], ...]
    minimum_seeds: int
    minimum_tasks: int

    @property
    def seed_count(self) -> int:
        return len(self.seeds)

    @property
    def task_count(self) -> int:
        return len(self.tasks)

    @property
    def cell_count(self) -> int:
        return 2 * self.seed_count * self.task_count

    def contract_record(self) -> dict[str, Any]:
        """Return content-free validation policy and cube dimensions."""

        return {
            "contract_version": OUTCOME_CONTRACT_VERSION,
            "reference_arm": self.reference_arm,
            "comparison_arm": self.comparison_arm,
            "seed_count": self.seed_count,
            "task_count": self.task_count,
            "cell_count": self.cell_count,
            "minimum_seeds": self.minimum_seeds,
            "minimum_tasks": self.minimum_tasks,
            "fixtures_nested_upstream": True,
        }


class _SplitMix64:
    """Small, fully specified deterministic generator with unbiased randbelow."""

    __slots__ = ("state",)

    def __init__(self, seed: int) -> None:
        self.state = seed & _UINT64_MASK

    def next_u64(self) -> int:
        self.state = (self.state + 0x9E3779B97F4A7C15) & _UINT64_MASK
        value = self.state
        value = ((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9) & _UINT64_MASK
        value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & _UINT64_MASK
        return (value ^ (value >> 31)) & _UINT64_MASK

    def randbelow(self, upper: int) -> int:
        if upper <= 0:
            raise ValueError("upper must be positive")
        limit = (1 << 64) - ((1 << 64) % upper)
        while True:
            value = self.next_u64()
            if value < limit:
                return value % upper


def _validate_identifier(value: object, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise StatisticsValidationError(
            f"{label} must be a nonempty string of at most {maximum} characters"
        )
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise StatisticsValidationError(
            f"{label} must contain valid Unicode scalar values"
        ) from error
    return value


def _validate_positive_integer(
    value: object,
    label: str,
    *,
    minimum: int = 1,
    maximum: int | None = None,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise StatisticsValidationError(f"{label} must be an integer >= {minimum}")
    if maximum is not None and value > maximum:
        raise StatisticsValidationError(f"{label} must be <= {maximum}")
    return value


def _validate_probability(
    value: object, label: str, *, allow_endpoints: bool
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise StatisticsValidationError(f"{label} must be a finite number")
    number = float(value)
    if not math.isfinite(number):
        raise StatisticsValidationError(f"{label} must be finite")
    valid = 0.0 <= number <= 1.0 if allow_endpoints else 0.0 < number < 1.0
    if not valid:
        interval = "[0, 1]" if allow_endpoints else "(0, 1)"
        raise StatisticsValidationError(f"{label} must lie in {interval}")
    return number


def _validate_random_seed(value: object, label: str = "random_seed") -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > _UINT64_MASK
    ):
        raise StatisticsValidationError(
            f"{label} must be an integer between 0 and 2^64-1"
        )
    return value


def validate_paired_binary_outcomes(
    records: Iterable[Mapping[str, object]],
    *,
    reference_arm: str,
    comparison_arm: str,
    minimum_seeds: int = 2,
    minimum_tasks: int = 2,
) -> PairedBinaryOutcomes:
    """Validate and normalize a complete paired outcome cube.

    Each input mapping must contain exactly ``arm``, ``seed``, ``task``, and
    ``passed``. A complete Cartesian cell must exist for both named arms at
    every observed training-seed and semantic-task combination.
    """

    reference = _validate_identifier(reference_arm, "reference_arm", 128)
    comparison = _validate_identifier(comparison_arm, "comparison_arm", 128)
    if reference == comparison:
        raise StatisticsValidationError("reference_arm and comparison_arm must differ")
    required_seeds = _validate_positive_integer(
        minimum_seeds, "minimum_seeds", minimum=2, maximum=100_000
    )
    required_tasks = _validate_positive_integer(
        minimum_tasks, "minimum_tasks", minimum=2, maximum=1_000_000
    )
    if isinstance(records, Mapping) or isinstance(records, (str, bytes)):
        raise StatisticsValidationError("records must be an iterable of mappings")

    cells: dict[tuple[str, int, str], int] = {}
    seeds: set[int] = set()
    tasks: set[str] = set()
    allowed_arms = {reference, comparison}
    expected_keys = {"arm", "seed", "task", "passed"}
    try:
        iterator = iter(records)
    except TypeError as error:
        raise StatisticsValidationError("records must be iterable") from error
    for index, raw in enumerate(iterator):
        if not isinstance(raw, Mapping):
            raise StatisticsValidationError(f"records[{index}] must be a mapping")
        if set(raw) != expected_keys:
            raise StatisticsValidationError(
                f"records[{index}] must contain exactly arm, passed, seed, and task"
            )
        arm = _validate_identifier(raw["arm"], f"records[{index}].arm", 128)
        if arm not in allowed_arms:
            raise StatisticsValidationError(
                f"records[{index}].arm is not one of the two declared arms"
            )
        seed_value = raw["seed"]
        if (
            isinstance(seed_value, bool)
            or not isinstance(seed_value, int)
            or seed_value < 0
            or seed_value > (1 << 63) - 1
        ):
            raise StatisticsValidationError(
                f"records[{index}].seed must be an integer between 0 and 2^63-1"
            )
        task = _validate_identifier(raw["task"], f"records[{index}].task", 512)
        passed = raw["passed"]
        if isinstance(passed, bool):
            normalized = int(passed)
        elif isinstance(passed, int) and not isinstance(passed, bool) and passed in (0, 1):
            normalized = passed
        else:
            raise StatisticsValidationError(
                f"records[{index}].passed must be boolean or integer 0/1"
            )
        key = (arm, seed_value, task)
        if key in cells:
            raise StatisticsValidationError(
                f"records[{index}] duplicates an arm/seed/task cell"
            )
        cells[key] = normalized
        seeds.add(seed_value)
        tasks.add(task)
        if len(cells) > _MAX_CELLS:
            raise StatisticsValidationError(
                f"outcome cube exceeds the {_MAX_CELLS}-cell validation limit"
            )

    if len(seeds) < required_seeds:
        raise StatisticsValidationError(
            f"outcome cube has {len(seeds)} seeds; at least {required_seeds} are required"
        )
    if len(tasks) < required_tasks:
        raise StatisticsValidationError(
            f"outcome cube has {len(tasks)} tasks; at least {required_tasks} are required"
        )
    ordered_seeds = tuple(sorted(seeds))
    ordered_tasks = tuple(sorted(tasks, key=lambda item: item.encode("utf-8")))
    expected_cell_count = 2 * len(ordered_seeds) * len(ordered_tasks)
    if expected_cell_count > _MAX_CELLS:
        raise StatisticsValidationError(
            f"complete outcome cube exceeds the {_MAX_CELLS}-cell limit"
        )
    if len(cells) != expected_cell_count:
        missing_count = sum(
            (arm, seed, task) not in cells
            for arm in (reference, comparison)
            for seed in ordered_seeds
            for task in ordered_tasks
        )
        raise StatisticsValidationError(
            "outcome cube is missing "
            f"{missing_count} paired arm/seed/task cell(s)"
        )

    reference_matrix = tuple(
        tuple(cells[(reference, seed, task)] for task in ordered_tasks)
        for seed in ordered_seeds
    )
    comparison_matrix = tuple(
        tuple(cells[(comparison, seed, task)] for task in ordered_tasks)
        for seed in ordered_seeds
    )
    return PairedBinaryOutcomes(
        reference,
        comparison,
        ordered_seeds,
        ordered_tasks,
        reference_matrix,
        comparison_matrix,
        required_seeds,
        required_tasks,
    )


def _require_dataset(data: object) -> PairedBinaryOutcomes:
    if not isinstance(data, PairedBinaryOutcomes):
        raise StatisticsValidationError(
            "data must be returned by validate_paired_binary_outcomes"
        )
    # Defend against manually constructed malformed instances despite frozen fields.
    if (
        not isinstance(data.reference_arm, str)
        or not data.reference_arm
        or not isinstance(data.comparison_arm, str)
        or not data.comparison_arm
        or data.reference_arm == data.comparison_arm
        or data.seed_count < 2
        or data.task_count < 2
        or len(set(data.seeds)) != data.seed_count
        or len(set(data.tasks)) != data.task_count
        or any(isinstance(seed, bool) or not isinstance(seed, int) for seed in data.seeds)
        or any(not isinstance(task, str) or not task for task in data.tasks)
        or len(data.reference) != data.seed_count
        or len(data.comparison) != data.seed_count
        or any(len(row) != data.task_count for row in data.reference)
        or any(len(row) != data.task_count for row in data.comparison)
        or any(
            type(value) is not int or value not in (0, 1)
            for row in data.reference
            for value in row
        )
        or any(
            type(value) is not int or value not in (0, 1)
            for row in data.comparison
            for value in row
        )
    ):
        raise StatisticsValidationError("validated outcome object is internally invalid")
    return data


def summarize_paired_binary(data: PairedBinaryOutcomes) -> dict[str, Any]:
    """Compute per-seed and arm-level macro pass@1 and paired difference."""

    cube = _require_dataset(data)
    per_seed: list[dict[str, Any]] = []
    reference_rates: list[float] = []
    comparison_rates: list[float] = []
    for index, seed in enumerate(cube.seeds):
        reference_rate = math.fsum(cube.reference[index]) / cube.task_count
        comparison_rate = math.fsum(cube.comparison[index]) / cube.task_count
        reference_rates.append(reference_rate)
        comparison_rates.append(comparison_rate)
        per_seed.append(
            {
                "seed": seed,
                "task_count": cube.task_count,
                "pass_at_1": {
                    cube.reference_arm: reference_rate,
                    cube.comparison_arm: comparison_rate,
                },
                "paired_difference_comparison_minus_reference": (
                    comparison_rate - reference_rate
                ),
            }
        )
    reference_macro = math.fsum(reference_rates) / cube.seed_count
    comparison_macro = math.fsum(comparison_rates) / cube.seed_count
    return {
        "method": "paired_binary_macro_pass_at_1",
        "method_version": STATISTICS_METHOD_VERSION,
        "policy": {
            **cube.contract_record(),
            "task_aggregation": "macro_within_training_seed",
            "seed_aggregation": "macro_across_training_seeds",
            "difference_direction": "comparison_minus_reference",
        },
        "per_seed": per_seed,
        "arm_macro_pass_at_1": {
            cube.reference_arm: reference_macro,
            cube.comparison_arm: comparison_macro,
        },
        "paired_difference": comparison_macro - reference_macro,
    }


def _linear_percentile(sorted_values: list[float], probability: float) -> float:
    if not sorted_values:
        raise StatisticsValidationError("percentile input cannot be empty")
    position = (len(sorted_values) - 1) * probability
    lower_index = math.floor(position)
    upper_index = math.ceil(position)
    lower = sorted_values[lower_index]
    upper = sorted_values[upper_index]
    if lower_index == upper_index:
        return lower
    return lower + (position - lower_index) * (upper - lower)


def two_way_paired_bootstrap(
    data: PairedBinaryOutcomes,
    *,
    confidence_level: float = 0.95,
    resamples: int,
    random_seed: int,
) -> dict[str, Any]:
    """Crossed bootstrap over independently resampled seeds and tasks."""

    cube = _require_dataset(data)
    confidence = _validate_probability(
        confidence_level, "confidence_level", allow_endpoints=False
    )
    draw_count = _validate_positive_integer(
        resamples, "resamples", minimum=100, maximum=_MAX_RESAMPLES
    )
    seed_value = _validate_random_seed(random_seed)
    evaluations = draw_count * cube.seed_count * cube.task_count
    if evaluations > _MAX_BOOTSTRAP_CELL_EVALUATIONS:
        raise StatisticsValidationError(
            "bootstrap policy exceeds the bounded cell-evaluation limit of "
            f"{_MAX_BOOTSTRAP_CELL_EVALUATIONS}"
        )

    differences = tuple(
        tuple(
            cube.comparison[seed_index][task_index]
            - cube.reference[seed_index][task_index]
            for task_index in range(cube.task_count)
        )
        for seed_index in range(cube.seed_count)
    )
    observed = (
        math.fsum(value for row in differences for value in row)
        / (cube.seed_count * cube.task_count)
    )
    generator = _SplitMix64(seed_value)
    estimates: list[float] = []
    denominator = cube.seed_count * cube.task_count
    for _ in range(draw_count):
        sampled_seeds = [
            generator.randbelow(cube.seed_count) for _ in range(cube.seed_count)
        ]
        sampled_tasks = [
            generator.randbelow(cube.task_count) for _ in range(cube.task_count)
        ]
        total = 0
        for seed_index in sampled_seeds:
            row = differences[seed_index]
            for task_index in sampled_tasks:
                total += row[task_index]
        estimates.append(total / denominator)
    estimates.sort()
    alpha = 1.0 - confidence
    lower = _linear_percentile(estimates, alpha / 2.0)
    upper = _linear_percentile(estimates, 1.0 - alpha / 2.0)
    if not all(math.isfinite(value) for value in (observed, lower, upper)):
        raise StatisticsValidationError("bootstrap produced a nonfinite estimate")
    return {
        "method": "crossed_seed_task_percentile_bootstrap",
        "method_version": STATISTICS_METHOD_VERSION,
        "policy": {
            **cube.contract_record(),
            "estimand": "macro_pass_at_1_comparison_minus_reference",
            "seed_resampling": "independent_with_replacement",
            "task_resampling": "independent_with_replacement",
            "pairing": "arms_retained_within_each_seed_task_cell",
            "fixture_handling": "already_nested_in_semantic_task_binary_outcome",
            "percentile_interpolation": "linear_r7",
            "confidence_level": confidence,
            "resamples": draw_count,
            "random_seed": seed_value,
            "random_generator": "splitmix64_rejection_v1",
            "cell_evaluations": evaluations,
        },
        "estimate": observed,
        "confidence_interval": {
            "lower": lower,
            "upper": upper,
            "confidence_level": confidence,
        },
    }


def _randomization_scores(
    cube: PairedBinaryOutcomes, unit: RandomizationUnit
) -> tuple[int, ...]:
    differences = tuple(
        tuple(
            cube.comparison[seed_index][task_index]
            - cube.reference[seed_index][task_index]
            for task_index in range(cube.task_count)
        )
        for seed_index in range(cube.seed_count)
    )
    if unit == "seed":
        return tuple(sum(row) for row in differences)
    if unit == "task":
        return tuple(
            sum(differences[seed_index][task_index] for seed_index in range(cube.seed_count))
            for task_index in range(cube.task_count)
        )
    return tuple(value for row in differences for value in row)


def _is_extreme(total: int, observed: int, alternative: Alternative) -> bool:
    if alternative == "two_sided":
        return abs(total) >= abs(observed)
    if alternative == "greater":
        return total >= observed
    return total <= observed


def paired_sign_flip_randomization(
    data: PairedBinaryOutcomes,
    *,
    unit: RandomizationUnit = "seed",
    alternative: Alternative = "two_sided",
    exact_max_units: int = _MAX_EXACT_UNITS,
    monte_carlo_draws: int | None = None,
    random_seed: int | None = None,
) -> dict[str, Any]:
    """Run an exact or deterministic Monte Carlo paired sign-flip test."""

    cube = _require_dataset(data)
    if unit not in ("seed", "task", "seed_task"):
        raise StatisticsValidationError("unit must be seed, task, or seed_task")
    if alternative not in ("two_sided", "greater", "less"):
        raise StatisticsValidationError(
            "alternative must be two_sided, greater, or less"
        )
    exact_limit = _validate_positive_integer(
        exact_max_units,
        "exact_max_units",
        minimum=1,
        maximum=_MAX_EXACT_UNITS,
    )
    validated_draws = (
        None
        if monte_carlo_draws is None
        else _validate_positive_integer(
            monte_carlo_draws,
            "monte_carlo_draws",
            minimum=100,
            maximum=_MAX_MONTE_CARLO_DRAWS,
        )
    )
    validated_seed = (
        None if random_seed is None else _validate_random_seed(random_seed)
    )
    scores = _randomization_scores(cube, unit)
    nonzero = tuple(score for score in scores if score != 0)
    observed_total = sum(nonzero)
    observed_difference = (
        math.fsum(
            cube.comparison[seed_index][task_index]
            - cube.reference[seed_index][task_index]
            for seed_index in range(cube.seed_count)
            for task_index in range(cube.task_count)
        )
        / (cube.seed_count * cube.task_count)
    )

    if len(nonzero) <= exact_limit:
        permutation_count = 1 << len(nonzero)
        extreme = 0
        for mask in range(permutation_count):
            total = sum(
                score if mask & (1 << index) else -score
                for index, score in enumerate(nonzero)
            )
            extreme += _is_extreme(total, observed_total, alternative)
        p_value = extreme / permutation_count
        mode = "exact"
        used_draws: int | None = None
        used_seed: int | None = None
        correction = "none_complete_enumeration"
    else:
        if monte_carlo_draws is None:
            raise StatisticsValidationError(
                "monte_carlo_draws is required when effective units exceed exact_max_units"
            )
        if random_seed is None:
            raise StatisticsValidationError(
                "random_seed is required for Monte Carlo randomization"
            )
        used_draws = validated_draws
        used_seed = validated_seed
        # The presence checks above make these values concrete here.
        assert used_draws is not None
        assert used_seed is not None
        generator = _SplitMix64(used_seed)
        extreme = 0
        for _ in range(used_draws):
            total = sum(
                score if generator.next_u64() & 1 else -score
                for score in nonzero
            )
            extreme += _is_extreme(total, observed_total, alternative)
        p_value = (extreme + 1) / (used_draws + 1)
        permutation_count = None
        mode = "deterministic_monte_carlo"
        correction = "plus_one"

    if not math.isfinite(p_value) or not 0.0 <= p_value <= 1.0:
        raise StatisticsValidationError("randomization produced an invalid p-value")
    return {
        "method": "paired_sign_flip_randomization",
        "method_version": STATISTICS_METHOD_VERSION,
        "policy": {
            **cube.contract_record(),
            "unit": unit,
            "unit_score": "sum_of_comparison_minus_reference_binary_differences",
            "alternative": alternative,
            "zero_score_units": "excluded_from_sign_enumeration",
            "exact_max_units": exact_limit,
            "mode": mode,
            "permutation_count": permutation_count,
            "monte_carlo_draws": used_draws,
            "random_seed": used_seed,
            "random_generator": (
                None if mode == "exact" else "splitmix64_rejection_v1"
            ),
            "monte_carlo_correction": correction,
        },
        "total_units": len(scores),
        "effective_nonzero_units": len(nonzero),
        "observed_paired_difference": observed_difference,
        "p_value": p_value,
    }


def holm_adjust(
    p_values: Mapping[str, float] | Iterable[tuple[str, float]],
    *,
    alpha: float = 0.05,
) -> dict[str, Any]:
    """Apply Holm's step-down family-wise p-value adjustment."""

    family_alpha = _validate_probability(alpha, "alpha", allow_endpoints=False)
    items = list(p_values.items()) if isinstance(p_values, Mapping) else list(p_values)
    if not items:
        raise StatisticsValidationError("p_values must contain at least one hypothesis")
    normalized: list[tuple[str, float]] = []
    labels: set[str] = set()
    for index, item in enumerate(items):
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            raise StatisticsValidationError(
                f"p_values[{index}] must be a (label, p_value) pair"
            )
        label = _validate_identifier(item[0], f"p_values[{index}].label", 256)
        if label in labels:
            raise StatisticsValidationError(f"duplicate hypothesis label at index {index}")
        labels.add(label)
        probability = _validate_probability(
            item[1], f"p_values[{index}].p_value", allow_endpoints=True
        )
        normalized.append((label, probability))

    ordered = sorted(normalized, key=lambda item: (item[1], item[0].encode("utf-8")))
    family_size = len(ordered)
    adjusted_by_label: dict[str, float] = {}
    rank_by_label: dict[str, int] = {}
    running = 0.0
    continue_rejecting = True
    rejected: dict[str, bool] = {}
    thresholds: dict[str, float] = {}
    for zero_rank, (label, probability) in enumerate(ordered):
        rank = zero_rank + 1
        multiplier = family_size - zero_rank
        running = max(running, min(1.0, multiplier * probability))
        adjusted_by_label[label] = running
        rank_by_label[label] = rank
        threshold = family_alpha / multiplier
        thresholds[label] = threshold
        reject = continue_rejecting and probability <= threshold
        rejected[label] = reject
        if not reject:
            continue_rejecting = False

    hypotheses = [
        {
            "label": label,
            "rank": rank_by_label[label],
            "raw_p_value": probability,
            "adjusted_p_value": adjusted_by_label[label],
            "step_down_threshold": thresholds[label],
            "rejected": rejected[label],
        }
        for label, probability in sorted(normalized, key=lambda item: item[0].encode("utf-8"))
    ]
    return {
        "method": "holm_step_down",
        "method_version": STATISTICS_METHOD_VERSION,
        "policy": {
            "alpha": family_alpha,
            "family_size": family_size,
            "ordering": "raw_p_value_then_utf8_label",
            "adjustment": "max_previous_of_remaining_hypotheses_times_raw_p",
            "rejection_rule": "sequential_raw_p_less_than_or_equal_alpha_over_remaining",
        },
        "hypotheses": hypotheses,
    }


def noninferiority_from_interval(
    *,
    lower_bound: float,
    upper_bound: float,
    margin: float,
    confidence_level: float,
) -> dict[str, Any]:
    """Decide non-inferiority for a comparison-minus-reference interval."""

    values: dict[str, float] = {}
    for label, raw in (
        ("lower_bound", lower_bound),
        ("upper_bound", upper_bound),
        ("margin", margin),
    ):
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            raise StatisticsValidationError(f"{label} must be a finite number")
        value = float(raw)
        if not math.isfinite(value):
            raise StatisticsValidationError(f"{label} must be finite")
        values[label] = value
    confidence = _validate_probability(
        confidence_level, "confidence_level", allow_endpoints=False
    )
    if values["lower_bound"] > values["upper_bound"]:
        raise StatisticsValidationError("lower_bound cannot exceed upper_bound")
    if values["margin"] <= 0:
        raise StatisticsValidationError("margin must be strictly positive")
    threshold = -values["margin"]
    decision = values["lower_bound"] > threshold
    return {
        "method": "confidence_interval_noninferiority",
        "method_version": STATISTICS_METHOD_VERSION,
        "policy": {
            "estimand_direction": "comparison_minus_reference",
            "margin_interpretation": "maximum_tolerated_absolute_decline",
            "decision_rule": "lower_bound_strictly_greater_than_negative_margin",
            "confidence_level": confidence,
            "margin": values["margin"],
            "noninferiority_threshold": threshold,
        },
        "confidence_interval": {
            "lower": values["lower_bound"],
            "upper": values["upper_bound"],
        },
        "noninferior": decision,
    }


__all__ = [
    "OUTCOME_CONTRACT_VERSION",
    "STATISTICS_METHOD_VERSION",
    "PairedBinaryOutcomes",
    "StatisticsValidationError",
    "holm_adjust",
    "noninferiority_from_interval",
    "paired_sign_flip_randomization",
    "summarize_paired_binary",
    "two_way_paired_bootstrap",
    "validate_paired_binary_outcomes",
]
