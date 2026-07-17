"""Additive registry for bounded dependency-DAG execution planning.

The first thirteen executable-static registries remain immutable.  This
module binds the exact family-local DAG contract as a fourteenth 20-task
addition.  Its predecessor is the non-recursive, hash-neutral through-
thirteenth evidence snapshot: every historical task is built once per call,
and no historical publication builder is called recursively.

This record is public method-development metadata only.  It grants no
candidate execution, model-selection, scored-evaluation, or claim authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Final, TypeAlias

from .executable_dependency_dag_execution_plan import (
    DEPENDENCY_DAG_EXECUTION_PLAN_GRAPH_ENCODINGS,
    DEPENDENCY_DAG_EXECUTION_PLAN_TIE_BREAK_POLICIES,
    DependencyDagExecutionPlanTask,
    build_dependency_dag_execution_plan_tasks,
)
from .executable_fixture_profiles import PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
from .executable_static_types import domain_sha256
from .executable_thirteenth_predecessor_evidence import (
    FROZEN_THIRTEENTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_THIRTEENTH_REGISTRY_SHA256,
    THIRTEENTH_PREFIX_TASK_COUNT,
    ThirteenthPrefixTaskEvidence,
    build_thirteenth_prefix_task_evidence,
    validate_thirteenth_prefix_task_evidence,
)


FOURTEENTH_TRANCHE_REGISTRY_SCHEMA_VERSION: Final[str] = "1.0.0"
FOURTEENTH_TRANCHE_REGISTRY_VERSION: Final[str] = "1.0.0"
FOURTEENTH_TRANCHE_ADDED_TASK_COUNT: Final[int] = 20
FOURTEENTH_TRANCHE_CUMULATIVE_TASK_COUNT: Final[int] = 460
FOURTEENTH_TRANCHE_FAMILY_ORDER: Final[tuple[str, ...]] = (
    "dependency-dag-execution-plan",
)

FROZEN_FOURTEENTH_REGISTRY_SHA256: Final[str] = (
    "c79de716570fe600f2dd7b1e3569456e6f42774d70143a309809410ad8097709"
)
FROZEN_FOURTEENTH_CUMULATIVE_SUITE_SHA256: Final[str] = (
    "497aac2c69daf2ff05e28b1f132090f3a380ce8ce215b63869a846d576616cf9"
)

FourteenthTrancheTask: TypeAlias = DependencyDagExecutionPlanTask
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")


class FourteenthTrancheRegistryError(ValueError):
    """Raised when the fourteenth additive registry is not reproducible."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def build_fourteenth_tranche_added_tasks() -> tuple[
    FourteenthTrancheTask, ...
]:
    """Build the exact family-local 20-task grid in canonical order."""

    tasks = build_dependency_dag_execution_plan_tasks()
    _validate_added_tasks(tasks)
    return tasks


def _validate_added_tasks(
    tasks: object,
) -> tuple[FourteenthTrancheTask, ...]:
    if (
        type(tasks) is not tuple
        or len(tasks) != FOURTEENTH_TRANCHE_ADDED_TASK_COUNT
        or any(
            type(task) is not DependencyDagExecutionPlanTask
            for task in tasks
        )
    ):
        raise FourteenthTrancheRegistryError(
            "fourteenth tranche requires exactly 20 exact "
            "DependencyDagExecutionPlanTask values"
        )
    selected = tasks
    try:
        for task in selected:
            task.__post_init__()
    except (AttributeError, TypeError, ValueError) as exc:
        raise FourteenthTrancheRegistryError(
            "fourteenth-tranche task validation failed"
        ) from exc

    expected_grid = tuple(
        (graph_encoding, tie_break_policy)
        for graph_encoding in DEPENDENCY_DAG_EXECUTION_PLAN_GRAPH_ENCODINGS
        for tie_break_policy in DEPENDENCY_DAG_EXECUTION_PLAN_TIE_BREAK_POLICIES
    )
    observed_grid = tuple(
        (
            task.parameters.graph_encoding,
            task.parameters.tie_break_policy,
        )
        for task in selected
    )
    if observed_grid != expected_grid:
        raise FourteenthTrancheRegistryError(
            "fourteenth-tranche parameter grid is incomplete or out of order"
        )
    if (
        len({task.task_id for task in selected})
        != FOURTEENTH_TRANCHE_ADDED_TASK_COUNT
        or len({task.task_contract_sha256 for task in selected})
        != FOURTEENTH_TRANCHE_ADDED_TASK_COUNT
        or len({task.graph_sha256 for task in selected})
        != FOURTEENTH_TRANCHE_ADDED_TASK_COUNT
        or any(
            len(task.fixtures) != len(PUBLIC_DEVELOPMENT_FIXTURE_PROFILES)
            for task in selected
        )
    ):
        raise FourteenthTrancheRegistryError(
            "fourteenth-tranche task identities are not unique"
        )
    return selected


def _registry_payload(
    tasks: tuple[FourteenthTrancheTask, ...],
) -> dict[str, object]:
    selected = _validate_added_tasks(tasks)
    return {
        "schema_version": FOURTEENTH_TRANCHE_REGISTRY_SCHEMA_VERSION,
        "registry_version": FOURTEENTH_TRANCHE_REGISTRY_VERSION,
        "record_type": (
            "cbds.executable-static-fourteenth-tranche-registry"
        ),
        "base_added_registry_sha256": FROZEN_THIRTEENTH_REGISTRY_SHA256,
        "base_cumulative_suite_sha256": (
            FROZEN_THIRTEENTH_CUMULATIVE_SUITE_SHA256
        ),
        "base_cumulative_task_count": THIRTEENTH_PREFIX_TASK_COUNT,
        "added_task_count": FOURTEENTH_TRANCHE_ADDED_TASK_COUNT,
        "cumulative_task_count": FOURTEENTH_TRANCHE_CUMULATIVE_TASK_COUNT,
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


def compute_fourteenth_tranche_registry_sha256(
    tasks: tuple[FourteenthTrancheTask, ...],
) -> str:
    return domain_sha256(
        "cbds.executable-static.fourteenth-tranche-registry.v1",
        _registry_payload(tasks),
    )


def compute_fourteenth_tranche_cumulative_suite_sha256(
    tasks: tuple[FourteenthTrancheTask, ...],
    registry_sha256: str,
) -> str:
    _validate_added_tasks(tasks)
    if not _is_sha256(registry_sha256):
        raise FourteenthTrancheRegistryError(
            "fourteenth-tranche registry digest is invalid"
        )
    if registry_sha256 != compute_fourteenth_tranche_registry_sha256(tasks):
        raise FourteenthTrancheRegistryError(
            "registry digest does not bind the fourteenth-tranche tasks"
        )
    return domain_sha256(
        "cbds.executable-static.fourteenth-tranche-cumulative-suite.v1",
        {
            "base_cumulative_suite_sha256": (
                FROZEN_THIRTEENTH_CUMULATIVE_SUITE_SHA256
            ),
            "added_registry_sha256": registry_sha256,
            "cumulative_task_count": (
                FOURTEENTH_TRANCHE_CUMULATIVE_TASK_COUNT
            ),
        },
    )


@dataclass(frozen=True, slots=True)
class FourteenthTrancheTaskRegistry:
    added_tasks: tuple[FourteenthTrancheTask, ...]
    registry_sha256: str
    cumulative_suite_sha256: str
    schema_version: str = FOURTEENTH_TRANCHE_REGISTRY_SCHEMA_VERSION
    registry_version: str = FOURTEENTH_TRANCHE_REGISTRY_VERSION
    base_added_registry_sha256: str = FROZEN_THIRTEENTH_REGISTRY_SHA256
    base_cumulative_suite_sha256: str = (
        FROZEN_THIRTEENTH_CUMULATIVE_SUITE_SHA256
    )
    public_method_development: bool = True
    sealed: bool = False
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_fourteenth_tranche_task_registry(self)

    def to_hash_only_record(self) -> dict[str, object]:
        validate_fourteenth_tranche_task_registry(self)
        return {
            "schema_version": self.schema_version,
            "registry_version": self.registry_version,
            "record_type": (
                "cbds.executable-static-fourteenth-tranche-registry-hashes"
            ),
            "base_added_registry_sha256": (
                self.base_added_registry_sha256
            ),
            "base_cumulative_suite_sha256": (
                self.base_cumulative_suite_sha256
            ),
            "base_cumulative_task_count": THIRTEENTH_PREFIX_TASK_COUNT,
            "added_task_count": len(self.added_tasks),
            "cumulative_task_count": (
                FOURTEENTH_TRANCHE_CUMULATIVE_TASK_COUNT
            ),
            "family_task_counts": {
                family: sum(
                    task.family_id == family for task in self.added_tasks
                )
                for family in FOURTEENTH_TRANCHE_FAMILY_ORDER
            },
            "task_contract_sha256": [
                task.task_contract_sha256 for task in self.added_tasks
            ],
            "graph_sha256": [
                task.graph_sha256 for task in self.added_tasks
            ],
            "registry_sha256": self.registry_sha256,
            "cumulative_suite_sha256": self.cumulative_suite_sha256,
            "public_method_development": True,
            "sealed": False,
            "candidate_execution_authorized": False,
            "model_selection_eligible": False,
            "claim_authorized": False,
        }


def validate_fourteenth_tranche_task_registry(
    registry: FourteenthTrancheTaskRegistry,
) -> None:
    if type(registry) is not FourteenthTrancheTaskRegistry:
        raise FourteenthTrancheRegistryError(
            "registry must be an exact FourteenthTrancheTaskRegistry"
        )
    if (
        type(registry.schema_version) is not str
        or registry.schema_version
        != FOURTEENTH_TRANCHE_REGISTRY_SCHEMA_VERSION
        or type(registry.registry_version) is not str
        or registry.registry_version
        != FOURTEENTH_TRANCHE_REGISTRY_VERSION
        or not _is_sha256(registry.base_added_registry_sha256)
        or registry.base_added_registry_sha256
        != FROZEN_THIRTEENTH_REGISTRY_SHA256
        or not _is_sha256(registry.base_cumulative_suite_sha256)
        or registry.base_cumulative_suite_sha256
        != FROZEN_THIRTEENTH_CUMULATIVE_SUITE_SHA256
        or not _is_sha256(registry.registry_sha256)
        or not _is_sha256(registry.cumulative_suite_sha256)
        or registry.public_method_development is not True
        or registry.sealed is not False
        or registry.candidate_execution_authorized is not False
        or registry.model_selection_eligible is not False
        or registry.claim_authorized is not False
    ):
        raise FourteenthTrancheRegistryError(
            "fourteenth-tranche registry metadata is invalid"
        )
    tasks = _validate_added_tasks(registry.added_tasks)
    expected_registry = compute_fourteenth_tranche_registry_sha256(tasks)
    if (
        registry.registry_sha256 != expected_registry
        or registry.registry_sha256
        != FROZEN_FOURTEENTH_REGISTRY_SHA256
    ):
        raise FourteenthTrancheRegistryError(
            "fourteenth-tranche registry digest is invalid"
        )
    expected_suite = compute_fourteenth_tranche_cumulative_suite_sha256(
        tasks,
        expected_registry,
    )
    if (
        registry.cumulative_suite_sha256 != expected_suite
        or registry.cumulative_suite_sha256
        != FROZEN_FOURTEENTH_CUMULATIVE_SUITE_SHA256
    ):
        raise FourteenthTrancheRegistryError(
            "fourteenth-tranche cumulative suite digest is invalid"
        )


def _validate_live_base_and_global_uniqueness(
    tasks: tuple[FourteenthTrancheTask, ...],
    evidence: ThirteenthPrefixTaskEvidence | None = None,
) -> None:
    """Rebuild the through-thirteenth prefix once and reject all collisions."""

    try:
        selected_evidence = (
            build_thirteenth_prefix_task_evidence()
            if evidence is None
            else evidence
        )
        validate_thirteenth_prefix_task_evidence(selected_evidence)
    except (AttributeError, TypeError, ValueError) as exc:
        raise FourteenthTrancheRegistryError(
            "through-thirteenth predecessor evidence could not be established"
        ) from exc
    if (
        selected_evidence.total_task_count != THIRTEENTH_PREFIX_TASK_COUNT
        or selected_evidence.terminal_registry_sha256
        != FROZEN_THIRTEENTH_REGISTRY_SHA256
        or selected_evidence.terminal_cumulative_suite_sha256
        != FROZEN_THIRTEENTH_CUMULATIVE_SUITE_SHA256
    ):
        raise FourteenthTrancheRegistryError(
            "the live thirteenth prefix differs from its frozen identity"
        )
    selected_tasks = _validate_added_tasks(tasks)
    all_tasks = (*selected_evidence.tasks, *selected_tasks)
    if (
        len(all_tasks) != FOURTEENTH_TRANCHE_CUMULATIVE_TASK_COUNT
        or len({task.task_id for task in all_tasks}) != len(all_tasks)
        or len({task.task_contract_sha256 for task in all_tasks})
        != len(all_tasks)
        or len({task.graph_sha256 for task in all_tasks}) != len(all_tasks)
    ):
        raise FourteenthTrancheRegistryError(
            "fourteenth-tranche tasks collide with a frozen predecessor"
        )
    if any(
        task is predecessor
        for task in selected_tasks
        for predecessor in selected_evidence.tasks
    ):
        raise FourteenthTrancheRegistryError(
            "fourteenth-tranche tasks must be freshly owned additions"
        )


def build_fourteenth_tranche_task_registry(
    predecessor_evidence: ThirteenthPrefixTaskEvidence | None = None,
) -> FourteenthTrancheTaskRegistry:
    """Build the fourteenth registry, optionally reusing one exact prefix."""

    tasks = build_fourteenth_tranche_added_tasks()
    _validate_live_base_and_global_uniqueness(
        tasks, predecessor_evidence
    )
    registry_sha256 = compute_fourteenth_tranche_registry_sha256(tasks)
    cumulative_suite_sha256 = (
        compute_fourteenth_tranche_cumulative_suite_sha256(
            tasks,
            registry_sha256,
        )
    )
    return FourteenthTrancheTaskRegistry(
        added_tasks=tasks,
        registry_sha256=registry_sha256,
        cumulative_suite_sha256=cumulative_suite_sha256,
    )


__all__ = [
    "FROZEN_FOURTEENTH_CUMULATIVE_SUITE_SHA256",
    "FROZEN_FOURTEENTH_REGISTRY_SHA256",
    "FROZEN_THIRTEENTH_CUMULATIVE_SUITE_SHA256",
    "FROZEN_THIRTEENTH_REGISTRY_SHA256",
    "FOURTEENTH_TRANCHE_ADDED_TASK_COUNT",
    "FOURTEENTH_TRANCHE_CUMULATIVE_TASK_COUNT",
    "FOURTEENTH_TRANCHE_FAMILY_ORDER",
    "FOURTEENTH_TRANCHE_REGISTRY_SCHEMA_VERSION",
    "FOURTEENTH_TRANCHE_REGISTRY_VERSION",
    "FourteenthTrancheRegistryError",
    "FourteenthTrancheTask",
    "FourteenthTrancheTaskRegistry",
    "build_fourteenth_tranche_added_tasks",
    "build_fourteenth_tranche_task_registry",
    "compute_fourteenth_tranche_cumulative_suite_sha256",
    "compute_fourteenth_tranche_registry_sha256",
    "validate_fourteenth_tranche_task_registry",
]
