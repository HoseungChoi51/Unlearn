"""Additive registry for two independently constructed development families.

The first two executable-static registries are immutable.  This module binds
the exact family-local compound-path and log-aggregation contracts as a third
40-task addition without broadening their frozen v1 shared type unions.  It
contains public method-development commitments only and grants no execution,
model-selection, scored-evaluation, or claim authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Final, TypeAlias

from .executable_compound_path_query import (
    COMPOUND_PATH_EXPRESSIONS,
    COMPOUND_PATH_NAME_PATTERNS,
    CompoundPathQueryTask,
    build_compound_path_query_tasks,
)
from .executable_fixture_profiles import PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
from .executable_log_aggregation_pipeline import (
    LOG_AGGREGATION_MALFORMED_POLICIES,
    LOG_AGGREGATION_SEVERITY_ERES,
    LogAggregationTask,
    build_log_aggregation_tasks,
)
from .executable_static_types import domain_sha256


THIRD_TRANCHE_REGISTRY_SCHEMA_VERSION: Final[str] = "1.0.0"
THIRD_TRANCHE_REGISTRY_VERSION: Final[str] = "1.0.0"
THIRD_TRANCHE_ADDED_TASK_COUNT: Final[int] = 40
THIRD_TRANCHE_CUMULATIVE_TASK_COUNT: Final[int] = 240
FROZEN_FIRST_REGISTRY_SHA256: Final[str] = (
    "ada6043b345e48f69ad602581030aab1bafcb3ff9dc453f9d02342faaf6a7f9a"
)
FROZEN_FIRST_SUITE_SHA256: Final[str] = (
    "eb64bb4cdb60ab8e0e228f688cf54810fae2ef56768e8b34ac039bdc1aec42ae"
)
FROZEN_SECOND_ADDED_REGISTRY_SHA256: Final[str] = (
    "27e4721036c4870fec463e880cb3a36fcd72ebe530368cb45179f600ee694ab4"
)
FROZEN_SECOND_CUMULATIVE_SUITE_SHA256: Final[str] = (
    "0020c1e5c7907d979d7fa97dead79f199fff59d97184c33fae81bc98df3ef8fb"
)
THIRD_TRANCHE_FAMILY_ORDER: Final[tuple[str, ...]] = (
    "compound-path-query",
    "regex-log-group-aggregation",
)

ThirdTrancheTask: TypeAlias = CompoundPathQueryTask | LogAggregationTask
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")


class ThirdTrancheRegistryError(ValueError):
    """Raised when the additive registry is not exactly reproducible."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def build_third_tranche_added_tasks() -> tuple[ThirdTrancheTask, ...]:
    """Build both 20-task family grids in canonical order."""

    tasks: tuple[ThirdTrancheTask, ...] = (
        *build_compound_path_query_tasks(),
        *build_log_aggregation_tasks(),
    )
    _validate_added_tasks(tasks)
    return tasks


def _validate_added_tasks(tasks: object) -> tuple[ThirdTrancheTask, ...]:
    if (
        type(tasks) is not tuple
        or len(tasks) != THIRD_TRANCHE_ADDED_TASK_COUNT
        or any(
            type(task) not in {CompoundPathQueryTask, LogAggregationTask}
            for task in tasks
        )
    ):
        raise ThirdTrancheRegistryError(
            "third tranche requires exactly 40 exact family-local task values"
        )
    selected = tasks
    if any(type(task) is not CompoundPathQueryTask for task in selected[:20]):
        raise ThirdTrancheRegistryError("compound-path tasks are out of order")
    if any(type(task) is not LogAggregationTask for task in selected[20:]):
        raise ThirdTrancheRegistryError("log-aggregation tasks are out of order")
    try:
        for task in selected:
            task.__post_init__()
    except (AttributeError, TypeError, ValueError) as exc:
        raise ThirdTrancheRegistryError("third-tranche task validation failed") from exc

    expected_compound = tuple(
        (pattern, expression)
        for pattern in COMPOUND_PATH_NAME_PATTERNS
        for expression in COMPOUND_PATH_EXPRESSIONS
    )
    observed_compound = tuple(
        (task.parameters.name_pattern, task.parameters.expression)
        for task in selected[:20]
    )
    expected_logs = tuple(
        (severity, policy)
        for severity in LOG_AGGREGATION_SEVERITY_ERES
        for policy in LOG_AGGREGATION_MALFORMED_POLICIES
    )
    observed_logs = tuple(
        (task.parameters.severity_ere, task.parameters.malformed_policy)
        for task in selected[20:]
    )
    if observed_compound != expected_compound or observed_logs != expected_logs:
        raise ThirdTrancheRegistryError("third-tranche parameter grids are incomplete")
    if (
        len({task.task_id for task in selected}) != THIRD_TRANCHE_ADDED_TASK_COUNT
        or len({task.task_contract_sha256 for task in selected})
        != THIRD_TRANCHE_ADDED_TASK_COUNT
        or len({task.graph_sha256 for task in selected})
        != THIRD_TRANCHE_ADDED_TASK_COUNT
        or any(len(task.fixtures) != len(PUBLIC_DEVELOPMENT_FIXTURE_PROFILES) for task in selected)
    ):
        raise ThirdTrancheRegistryError("third-tranche identities are not unique")
    return selected


def _registry_payload(tasks: tuple[ThirdTrancheTask, ...]) -> dict[str, object]:
    selected = _validate_added_tasks(tasks)
    return {
        "schema_version": THIRD_TRANCHE_REGISTRY_SCHEMA_VERSION,
        "registry_version": THIRD_TRANCHE_REGISTRY_VERSION,
        "record_type": "cbds.executable-static-third-tranche-registry",
        "base_added_registry_sha256": FROZEN_SECOND_ADDED_REGISTRY_SHA256,
        "base_cumulative_suite_sha256": FROZEN_SECOND_CUMULATIVE_SUITE_SHA256,
        "base_cumulative_task_count": 200,
        "added_task_count": THIRD_TRANCHE_ADDED_TASK_COUNT,
        "cumulative_task_count": THIRD_TRANCHE_CUMULATIVE_TASK_COUNT,
        "fixture_profile_sha256": [
            profile.profile_sha256
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        ],
        "added_tasks": [task.to_public_record() for task in selected],
        "public_method_development": True,
        "sealed": False,
        "candidate_execution_authorized": False,
        "model_selection_eligible": False,
        "claim_authorized": False,
    }


def compute_third_tranche_registry_sha256(
    tasks: tuple[ThirdTrancheTask, ...],
) -> str:
    return domain_sha256(
        "cbds.executable-static.third-tranche-registry.v1",
        _registry_payload(tasks),
    )


def compute_third_tranche_cumulative_suite_sha256(
    tasks: tuple[ThirdTrancheTask, ...],
    registry_sha256: str,
) -> str:
    _validate_added_tasks(tasks)
    if not _is_sha256(registry_sha256):
        raise ThirdTrancheRegistryError("third-tranche registry digest is invalid")
    if registry_sha256 != compute_third_tranche_registry_sha256(tasks):
        raise ThirdTrancheRegistryError("registry digest does not bind the tasks")
    return domain_sha256(
        "cbds.executable-static.third-tranche-cumulative-suite.v1",
        {
            "base_cumulative_suite_sha256": FROZEN_SECOND_CUMULATIVE_SUITE_SHA256,
            "added_registry_sha256": registry_sha256,
            "cumulative_task_count": THIRD_TRANCHE_CUMULATIVE_TASK_COUNT,
        },
    )


@dataclass(frozen=True, slots=True)
class ThirdTrancheTaskRegistry:
    added_tasks: tuple[ThirdTrancheTask, ...]
    registry_sha256: str
    cumulative_suite_sha256: str
    schema_version: str = THIRD_TRANCHE_REGISTRY_SCHEMA_VERSION
    registry_version: str = THIRD_TRANCHE_REGISTRY_VERSION
    base_added_registry_sha256: str = FROZEN_SECOND_ADDED_REGISTRY_SHA256
    base_cumulative_suite_sha256: str = FROZEN_SECOND_CUMULATIVE_SUITE_SHA256
    public_method_development: bool = True
    sealed: bool = False
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_third_tranche_task_registry(self)

    def to_hash_only_record(self) -> dict[str, object]:
        validate_third_tranche_task_registry(self)
        return {
            "schema_version": self.schema_version,
            "registry_version": self.registry_version,
            "record_type": "cbds.executable-static-third-tranche-registry-hashes",
            "base_added_registry_sha256": self.base_added_registry_sha256,
            "base_cumulative_suite_sha256": self.base_cumulative_suite_sha256,
            "base_cumulative_task_count": 200,
            "added_task_count": len(self.added_tasks),
            "cumulative_task_count": THIRD_TRANCHE_CUMULATIVE_TASK_COUNT,
            "family_task_counts": {
                family: sum(task.family_id == family for task in self.added_tasks)
                for family in THIRD_TRANCHE_FAMILY_ORDER
            },
            "task_contract_sha256": [
                task.task_contract_sha256 for task in self.added_tasks
            ],
            "graph_sha256": [task.graph_sha256 for task in self.added_tasks],
            "registry_sha256": self.registry_sha256,
            "cumulative_suite_sha256": self.cumulative_suite_sha256,
            "public_method_development": True,
            "sealed": False,
            "candidate_execution_authorized": False,
            "model_selection_eligible": False,
            "claim_authorized": False,
        }


def validate_third_tranche_task_registry(
    registry: ThirdTrancheTaskRegistry,
) -> None:
    if type(registry) is not ThirdTrancheTaskRegistry:
        raise ThirdTrancheRegistryError(
            "registry must be an exact ThirdTrancheTaskRegistry"
        )
    if (
        type(registry.schema_version) is not str
        or registry.schema_version != THIRD_TRANCHE_REGISTRY_SCHEMA_VERSION
        or type(registry.registry_version) is not str
        or registry.registry_version != THIRD_TRANCHE_REGISTRY_VERSION
        or not _is_sha256(registry.base_added_registry_sha256)
        or registry.base_added_registry_sha256
        != FROZEN_SECOND_ADDED_REGISTRY_SHA256
        or not _is_sha256(registry.base_cumulative_suite_sha256)
        or registry.base_cumulative_suite_sha256
        != FROZEN_SECOND_CUMULATIVE_SUITE_SHA256
        or not _is_sha256(registry.registry_sha256)
        or not _is_sha256(registry.cumulative_suite_sha256)
        or registry.public_method_development is not True
        or registry.sealed is not False
        or registry.candidate_execution_authorized is not False
        or registry.model_selection_eligible is not False
        or registry.claim_authorized is not False
    ):
        raise ThirdTrancheRegistryError("third-tranche registry metadata is invalid")
    tasks = _validate_added_tasks(registry.added_tasks)
    expected_registry = compute_third_tranche_registry_sha256(tasks)
    if registry.registry_sha256 != expected_registry:
        raise ThirdTrancheRegistryError("third-tranche registry digest is invalid")
    expected_suite = compute_third_tranche_cumulative_suite_sha256(
        tasks, expected_registry
    )
    if registry.cumulative_suite_sha256 != expected_suite:
        raise ThirdTrancheRegistryError("cumulative suite digest is invalid")


def build_third_tranche_task_registry() -> ThirdTrancheTaskRegistry:
    tasks = build_third_tranche_added_tasks()
    _validate_live_base_and_global_uniqueness(tasks)
    registry_sha256 = compute_third_tranche_registry_sha256(tasks)
    suite_sha256 = compute_third_tranche_cumulative_suite_sha256(
        tasks, registry_sha256
    )
    return ThirdTrancheTaskRegistry(
        added_tasks=tasks,
        registry_sha256=registry_sha256,
        cumulative_suite_sha256=suite_sha256,
    )


def _validate_live_base_and_global_uniqueness(
    tasks: tuple[ThirdTrancheTask, ...],
) -> None:
    """Rebuild both frozen predecessors before publishing a new addition."""

    from .executable_static_registry import build_public_method_development_registry
    from .executable_static_second_registry import build_second_tranche_task_registry

    first = build_public_method_development_registry()
    second = build_second_tranche_task_registry()
    if (
        first.registry_sha256 != FROZEN_FIRST_REGISTRY_SHA256
        or first.suite_sha256 != FROZEN_FIRST_SUITE_SHA256
        or second.registry_sha256 != FROZEN_SECOND_ADDED_REGISTRY_SHA256
        or second.cumulative_suite_sha256
        != FROZEN_SECOND_CUMULATIVE_SUITE_SHA256
    ):
        raise ThirdTrancheRegistryError(
            "a live predecessor registry differs from its frozen base"
        )
    all_tasks = (*first.tasks, *second.added_tasks, *_validate_added_tasks(tasks))
    if (
        len(all_tasks) != THIRD_TRANCHE_CUMULATIVE_TASK_COUNT
        or len({task.task_id for task in all_tasks}) != len(all_tasks)
        or len({task.task_contract_sha256 for task in all_tasks}) != len(all_tasks)
        or len({task.graph_sha256 for task in all_tasks}) != len(all_tasks)
    ):
        raise ThirdTrancheRegistryError(
            "third-tranche tasks collide with a frozen predecessor"
        )


__all__ = [
    "FROZEN_FIRST_REGISTRY_SHA256",
    "FROZEN_FIRST_SUITE_SHA256",
    "FROZEN_SECOND_ADDED_REGISTRY_SHA256",
    "FROZEN_SECOND_CUMULATIVE_SUITE_SHA256",
    "THIRD_TRANCHE_ADDED_TASK_COUNT",
    "THIRD_TRANCHE_CUMULATIVE_TASK_COUNT",
    "THIRD_TRANCHE_FAMILY_ORDER",
    "THIRD_TRANCHE_REGISTRY_SCHEMA_VERSION",
    "THIRD_TRANCHE_REGISTRY_VERSION",
    "ThirdTrancheRegistryError",
    "ThirdTrancheTaskRegistry",
    "build_third_tranche_added_tasks",
    "build_third_tranche_task_registry",
    "compute_third_tranche_cumulative_suite_sha256",
    "compute_third_tranche_registry_sha256",
    "validate_third_tranche_task_registry",
]
