"""Additive registry for synthetic process-lifecycle delta reporting.

The first fourteen executable-static registries remain immutable.  This
module binds the exact family-local process-lifecycle contract as a fifteenth
20-task addition.  Its predecessor is the non-recursive, hash-neutral
through-fourteenth evidence snapshot: every historical task is built once per
call, and no historical publication builder is called recursively.

This record is public method-development metadata only.  It grants no
candidate execution, model-selection, scored-evaluation, or claim authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Final, TypeAlias

from .executable_fixture_profiles import PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
from .executable_fourteenth_predecessor_evidence import (
    FROZEN_FOURTEENTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_FOURTEENTH_REGISTRY_SHA256,
    FOURTEENTH_PREFIX_TASK_COUNT,
    FourteenthPrefixTaskEvidence,
    build_fourteenth_prefix_task_evidence,
    validate_fourteenth_prefix_task_evidence,
)
from .executable_process_lifecycle_delta import (
    PROCESS_LIFECYCLE_DELTA_SELECTION_POLICIES,
    PROCESS_LIFECYCLE_DELTA_SNAPSHOT_PAIRS,
    ProcessLifecycleDeltaTask,
    build_process_lifecycle_delta_tasks,
)
from .executable_static_types import domain_sha256


FIFTEENTH_TRANCHE_REGISTRY_SCHEMA_VERSION: Final[str] = "1.0.0"
FIFTEENTH_TRANCHE_REGISTRY_VERSION: Final[str] = "1.0.0"
FIFTEENTH_TRANCHE_ADDED_TASK_COUNT: Final[int] = 20
FIFTEENTH_TRANCHE_CUMULATIVE_TASK_COUNT: Final[int] = 480
FIFTEENTH_TRANCHE_FAMILY_ORDER: Final[tuple[str, ...]] = (
    "process-lifecycle-delta",
)

FROZEN_FIFTEENTH_REGISTRY_SHA256: Final[str] = (
    "2d2773bcab7f83c99638541803516d893d3749b6c7b1b0091c6633f1c54493a5"
)
FROZEN_FIFTEENTH_CUMULATIVE_SUITE_SHA256: Final[str] = (
    "fce6939985a541c0bdb0e9f456b0e713f835b283a001e8a0f124047abe6ad99a"
)

FifteenthTrancheTask: TypeAlias = ProcessLifecycleDeltaTask
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")


class FifteenthTrancheRegistryError(ValueError):
    """Raised when the fifteenth additive registry is not reproducible."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def build_fifteenth_tranche_added_tasks() -> tuple[
    FifteenthTrancheTask, ...
]:
    """Build the exact family-local 20-task grid in canonical order."""

    tasks = build_process_lifecycle_delta_tasks()
    _validate_added_tasks(tasks)
    return tasks


def _validate_added_tasks(
    tasks: object,
) -> tuple[FifteenthTrancheTask, ...]:
    if (
        type(tasks) is not tuple
        or len(tasks) != FIFTEENTH_TRANCHE_ADDED_TASK_COUNT
        or any(type(task) is not ProcessLifecycleDeltaTask for task in tasks)
    ):
        raise FifteenthTrancheRegistryError(
            "fifteenth tranche requires exactly 20 exact "
            "ProcessLifecycleDeltaTask values"
        )
    selected = tasks
    try:
        for task in selected:
            task.__post_init__()
    except (AttributeError, TypeError, ValueError) as exc:
        raise FifteenthTrancheRegistryError(
            "fifteenth-tranche task validation failed"
        ) from exc

    expected_grid = tuple(
        (snapshot_pair, selection_policy)
        for snapshot_pair in PROCESS_LIFECYCLE_DELTA_SNAPSHOT_PAIRS
        for selection_policy in PROCESS_LIFECYCLE_DELTA_SELECTION_POLICIES
    )
    observed_grid = tuple(
        (
            task.parameters.snapshot_pair,
            task.parameters.selection_policy,
        )
        for task in selected
    )
    if observed_grid != expected_grid:
        raise FifteenthTrancheRegistryError(
            "fifteenth-tranche parameter grid is incomplete or out of order"
        )
    if (
        len({task.task_id for task in selected})
        != FIFTEENTH_TRANCHE_ADDED_TASK_COUNT
        or len({task.task_contract_sha256 for task in selected})
        != FIFTEENTH_TRANCHE_ADDED_TASK_COUNT
        or len({task.graph_sha256 for task in selected})
        != FIFTEENTH_TRANCHE_ADDED_TASK_COUNT
        or any(
            len(task.fixtures) != len(PUBLIC_DEVELOPMENT_FIXTURE_PROFILES)
            for task in selected
        )
    ):
        raise FifteenthTrancheRegistryError(
            "fifteenth-tranche task identities are not unique"
        )
    return selected


def _registry_payload(
    tasks: tuple[FifteenthTrancheTask, ...],
) -> dict[str, object]:
    selected = _validate_added_tasks(tasks)
    return {
        "schema_version": FIFTEENTH_TRANCHE_REGISTRY_SCHEMA_VERSION,
        "registry_version": FIFTEENTH_TRANCHE_REGISTRY_VERSION,
        "record_type": (
            "cbds.executable-static-fifteenth-tranche-registry"
        ),
        "base_added_registry_sha256": FROZEN_FOURTEENTH_REGISTRY_SHA256,
        "base_cumulative_suite_sha256": (
            FROZEN_FOURTEENTH_CUMULATIVE_SUITE_SHA256
        ),
        "base_cumulative_task_count": FOURTEENTH_PREFIX_TASK_COUNT,
        "added_task_count": FIFTEENTH_TRANCHE_ADDED_TASK_COUNT,
        "cumulative_task_count": FIFTEENTH_TRANCHE_CUMULATIVE_TASK_COUNT,
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


def compute_fifteenth_tranche_registry_sha256(
    tasks: tuple[FifteenthTrancheTask, ...],
) -> str:
    return domain_sha256(
        "cbds.executable-static.fifteenth-tranche-registry.v1",
        _registry_payload(tasks),
    )


def compute_fifteenth_tranche_cumulative_suite_sha256(
    tasks: tuple[FifteenthTrancheTask, ...],
    registry_sha256: str,
) -> str:
    _validate_added_tasks(tasks)
    if not _is_sha256(registry_sha256):
        raise FifteenthTrancheRegistryError(
            "fifteenth-tranche registry digest is invalid"
        )
    if registry_sha256 != compute_fifteenth_tranche_registry_sha256(tasks):
        raise FifteenthTrancheRegistryError(
            "registry digest does not bind the fifteenth-tranche tasks"
        )
    return domain_sha256(
        "cbds.executable-static.fifteenth-tranche-cumulative-suite.v1",
        {
            "base_cumulative_suite_sha256": (
                FROZEN_FOURTEENTH_CUMULATIVE_SUITE_SHA256
            ),
            "added_registry_sha256": registry_sha256,
            "cumulative_task_count": (
                FIFTEENTH_TRANCHE_CUMULATIVE_TASK_COUNT
            ),
        },
    )


@dataclass(frozen=True, slots=True)
class FifteenthTrancheTaskRegistry:
    added_tasks: tuple[FifteenthTrancheTask, ...]
    registry_sha256: str
    cumulative_suite_sha256: str
    schema_version: str = FIFTEENTH_TRANCHE_REGISTRY_SCHEMA_VERSION
    registry_version: str = FIFTEENTH_TRANCHE_REGISTRY_VERSION
    base_added_registry_sha256: str = FROZEN_FOURTEENTH_REGISTRY_SHA256
    base_cumulative_suite_sha256: str = (
        FROZEN_FOURTEENTH_CUMULATIVE_SUITE_SHA256
    )
    public_method_development: bool = True
    sealed: bool = False
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_fifteenth_tranche_task_registry(self)

    def to_hash_only_record(self) -> dict[str, object]:
        validate_fifteenth_tranche_task_registry(self)
        return {
            "schema_version": self.schema_version,
            "registry_version": self.registry_version,
            "record_type": (
                "cbds.executable-static-fifteenth-tranche-registry-hashes"
            ),
            "base_added_registry_sha256": (
                self.base_added_registry_sha256
            ),
            "base_cumulative_suite_sha256": (
                self.base_cumulative_suite_sha256
            ),
            "base_cumulative_task_count": FOURTEENTH_PREFIX_TASK_COUNT,
            "added_task_count": len(self.added_tasks),
            "cumulative_task_count": (
                FIFTEENTH_TRANCHE_CUMULATIVE_TASK_COUNT
            ),
            "family_task_counts": {
                family: sum(
                    task.family_id == family for task in self.added_tasks
                )
                for family in FIFTEENTH_TRANCHE_FAMILY_ORDER
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


def validate_fifteenth_tranche_task_registry(
    registry: FifteenthTrancheTaskRegistry,
) -> None:
    if type(registry) is not FifteenthTrancheTaskRegistry:
        raise FifteenthTrancheRegistryError(
            "registry must be an exact FifteenthTrancheTaskRegistry"
        )
    if (
        type(registry.schema_version) is not str
        or registry.schema_version
        != FIFTEENTH_TRANCHE_REGISTRY_SCHEMA_VERSION
        or type(registry.registry_version) is not str
        or registry.registry_version
        != FIFTEENTH_TRANCHE_REGISTRY_VERSION
        or not _is_sha256(registry.base_added_registry_sha256)
        or registry.base_added_registry_sha256
        != FROZEN_FOURTEENTH_REGISTRY_SHA256
        or not _is_sha256(registry.base_cumulative_suite_sha256)
        or registry.base_cumulative_suite_sha256
        != FROZEN_FOURTEENTH_CUMULATIVE_SUITE_SHA256
        or not _is_sha256(registry.registry_sha256)
        or not _is_sha256(registry.cumulative_suite_sha256)
        or registry.public_method_development is not True
        or registry.sealed is not False
        or registry.candidate_execution_authorized is not False
        or registry.model_selection_eligible is not False
        or registry.claim_authorized is not False
    ):
        raise FifteenthTrancheRegistryError(
            "fifteenth-tranche registry metadata is invalid"
        )
    tasks = _validate_added_tasks(registry.added_tasks)
    expected_registry = compute_fifteenth_tranche_registry_sha256(tasks)
    if (
        registry.registry_sha256 != expected_registry
        or registry.registry_sha256 != FROZEN_FIFTEENTH_REGISTRY_SHA256
    ):
        raise FifteenthTrancheRegistryError(
            "fifteenth-tranche registry digest is invalid"
        )
    expected_suite = compute_fifteenth_tranche_cumulative_suite_sha256(
        tasks,
        expected_registry,
    )
    if (
        registry.cumulative_suite_sha256 != expected_suite
        or registry.cumulative_suite_sha256
        != FROZEN_FIFTEENTH_CUMULATIVE_SUITE_SHA256
    ):
        raise FifteenthTrancheRegistryError(
            "fifteenth-tranche cumulative suite digest is invalid"
        )


def _validate_live_base_and_global_uniqueness(
    tasks: tuple[FifteenthTrancheTask, ...],
    evidence: FourteenthPrefixTaskEvidence | None = None,
) -> None:
    """Rebuild the through-fourteenth prefix once and reject all collisions."""

    try:
        selected_evidence = (
            build_fourteenth_prefix_task_evidence()
            if evidence is None
            else evidence
        )
        validate_fourteenth_prefix_task_evidence(selected_evidence)
    except (AttributeError, TypeError, ValueError) as exc:
        raise FifteenthTrancheRegistryError(
            "through-fourteenth predecessor evidence could not be established"
        ) from exc
    if (
        selected_evidence.total_task_count != FOURTEENTH_PREFIX_TASK_COUNT
        or selected_evidence.terminal_registry_sha256
        != FROZEN_FOURTEENTH_REGISTRY_SHA256
        or selected_evidence.terminal_cumulative_suite_sha256
        != FROZEN_FOURTEENTH_CUMULATIVE_SUITE_SHA256
    ):
        raise FifteenthTrancheRegistryError(
            "the live fourteenth prefix differs from its frozen identity"
        )
    selected_tasks = _validate_added_tasks(tasks)
    all_tasks = (*selected_evidence.tasks, *selected_tasks)
    if (
        len(all_tasks) != FIFTEENTH_TRANCHE_CUMULATIVE_TASK_COUNT
        or len({task.task_id for task in all_tasks}) != len(all_tasks)
        or len({task.task_contract_sha256 for task in all_tasks})
        != len(all_tasks)
        or len({task.graph_sha256 for task in all_tasks}) != len(all_tasks)
    ):
        raise FifteenthTrancheRegistryError(
            "fifteenth-tranche tasks collide with a frozen predecessor"
        )
    if any(
        task is predecessor
        for task in selected_tasks
        for predecessor in selected_evidence.tasks
    ):
        raise FifteenthTrancheRegistryError(
            "fifteenth-tranche tasks must be freshly owned additions"
        )


def build_fifteenth_tranche_task_registry(
    predecessor_evidence: FourteenthPrefixTaskEvidence | None = None,
) -> FifteenthTrancheTaskRegistry:
    """Build the fifteenth registry, optionally reusing one exact prefix."""

    tasks = build_fifteenth_tranche_added_tasks()
    _validate_live_base_and_global_uniqueness(
        tasks, predecessor_evidence
    )
    registry_sha256 = compute_fifteenth_tranche_registry_sha256(tasks)
    cumulative_suite_sha256 = (
        compute_fifteenth_tranche_cumulative_suite_sha256(
            tasks,
            registry_sha256,
        )
    )
    return FifteenthTrancheTaskRegistry(
        added_tasks=tasks,
        registry_sha256=registry_sha256,
        cumulative_suite_sha256=cumulative_suite_sha256,
    )


__all__ = [
    "FIFTEENTH_TRANCHE_ADDED_TASK_COUNT",
    "FIFTEENTH_TRANCHE_CUMULATIVE_TASK_COUNT",
    "FIFTEENTH_TRANCHE_FAMILY_ORDER",
    "FIFTEENTH_TRANCHE_REGISTRY_SCHEMA_VERSION",
    "FIFTEENTH_TRANCHE_REGISTRY_VERSION",
    "FROZEN_FIFTEENTH_CUMULATIVE_SUITE_SHA256",
    "FROZEN_FIFTEENTH_REGISTRY_SHA256",
    "FROZEN_FOURTEENTH_CUMULATIVE_SUITE_SHA256",
    "FROZEN_FOURTEENTH_REGISTRY_SHA256",
    "FifteenthTrancheRegistryError",
    "FifteenthTrancheTask",
    "FifteenthTrancheTaskRegistry",
    "build_fifteenth_tranche_added_tasks",
    "build_fifteenth_tranche_task_registry",
    "compute_fifteenth_tranche_cumulative_suite_sha256",
    "compute_fifteenth_tranche_registry_sha256",
    "validate_fifteenth_tranche_task_registry",
]
