"""Additive registry for the bounded-retry-state-machine family.

The first five executable-static registries remain immutable.  This module
binds the exact family-local bounded-retry contract as a sixth 20-task
addition without widening a frozen shared task union.  It contains public
method-development commitments only and grants no execution, model-selection,
scored-evaluation, or claim authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Final, TypeAlias

from .executable_bounded_retry_state_machine import (
    BOUNDED_RETRY_STATE_MACHINE_RETRY_POLICIES,
    BOUNDED_RETRY_STATE_MACHINE_TRANSITION_MODELS,
    BoundedRetryStateMachineTask,
    build_bounded_retry_state_machine_tasks,
)
from .executable_fixture_profiles import PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
from .executable_static_types import domain_sha256


SIXTH_TRANCHE_REGISTRY_SCHEMA_VERSION: Final[str] = "1.0.0"
SIXTH_TRANCHE_REGISTRY_VERSION: Final[str] = "1.0.0"
SIXTH_TRANCHE_ADDED_TASK_COUNT: Final[int] = 20
SIXTH_TRANCHE_CUMULATIVE_TASK_COUNT: Final[int] = 300
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
FROZEN_THIRD_ADDED_REGISTRY_SHA256: Final[str] = (
    "66a9ef43a6387f5f94f511aec3357f0e625427d161a0c6da0d9590a837761237"
)
FROZEN_THIRD_CUMULATIVE_SUITE_SHA256: Final[str] = (
    "3a578668805bbdfdfaf3400483640bb29504591604ed1c9c28cf8f9bb0362fb3"
)
FROZEN_FOURTH_ADDED_REGISTRY_SHA256: Final[str] = (
    "3dc5512139361a275afaf0b57b94528961615f9b4eee22ee6c333cc7d8bf4ea5"
)
FROZEN_FOURTH_CUMULATIVE_SUITE_SHA256: Final[str] = (
    "668ab9c942888d568c80aaa27bee340ad8a10faf3493a6983bf068d79b134651"
)
FROZEN_FIFTH_ADDED_REGISTRY_SHA256: Final[str] = (
    "d562d462814b7fc6413e0e085d16f66def28157c1a6361adf28cd3d42eb5f88c"
)
FROZEN_FIFTH_CUMULATIVE_SUITE_SHA256: Final[str] = (
    "27ea8064a72453a4e7a4bc52b125a924139088cd1c20d417a867aa9ddda96e00"
)
SIXTH_TRANCHE_FAMILY_ORDER: Final[tuple[str, ...]] = (
    "bounded-retry-state-machine",
)

SixthTrancheTask: TypeAlias = BoundedRetryStateMachineTask
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")


class SixthTrancheRegistryError(ValueError):
    """Raised when the sixth additive registry is not reproducible."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def build_sixth_tranche_added_tasks() -> tuple[SixthTrancheTask, ...]:
    """Build the exact family-local 20-task grid in canonical order."""

    tasks = build_bounded_retry_state_machine_tasks()
    _validate_added_tasks(tasks)
    return tasks


def _validate_added_tasks(tasks: object) -> tuple[SixthTrancheTask, ...]:
    if (
        type(tasks) is not tuple
        or len(tasks) != SIXTH_TRANCHE_ADDED_TASK_COUNT
        or any(type(task) is not BoundedRetryStateMachineTask for task in tasks)
    ):
        raise SixthTrancheRegistryError(
            "sixth tranche requires exactly 20 exact "
            "BoundedRetryStateMachineTask values"
        )
    selected = tasks
    try:
        for task in selected:
            task.__post_init__()
    except (AttributeError, TypeError, ValueError) as exc:
        raise SixthTrancheRegistryError(
            "sixth-tranche task validation failed"
        ) from exc

    expected_grid = tuple(
        (transition_model, retry_policy)
        for transition_model in BOUNDED_RETRY_STATE_MACHINE_TRANSITION_MODELS
        for retry_policy in BOUNDED_RETRY_STATE_MACHINE_RETRY_POLICIES
    )
    observed_grid = tuple(
        (task.parameters.transition_model, task.parameters.retry_policy)
        for task in selected
    )
    if observed_grid != expected_grid:
        raise SixthTrancheRegistryError(
            "sixth-tranche parameter grid is incomplete or out of order"
        )
    if (
        len({task.task_id for task in selected})
        != SIXTH_TRANCHE_ADDED_TASK_COUNT
        or len({task.task_contract_sha256 for task in selected})
        != SIXTH_TRANCHE_ADDED_TASK_COUNT
        or len({task.graph_sha256 for task in selected})
        != SIXTH_TRANCHE_ADDED_TASK_COUNT
        or any(
            len(task.fixtures) != len(PUBLIC_DEVELOPMENT_FIXTURE_PROFILES)
            for task in selected
        )
    ):
        raise SixthTrancheRegistryError(
            "sixth-tranche task identities are not unique"
        )
    return selected


def _registry_payload(
    tasks: tuple[SixthTrancheTask, ...],
) -> dict[str, object]:
    selected = _validate_added_tasks(tasks)
    return {
        "schema_version": SIXTH_TRANCHE_REGISTRY_SCHEMA_VERSION,
        "registry_version": SIXTH_TRANCHE_REGISTRY_VERSION,
        "record_type": "cbds.executable-static-sixth-tranche-registry",
        "base_added_registry_sha256": FROZEN_FIFTH_ADDED_REGISTRY_SHA256,
        "base_cumulative_suite_sha256": (
            FROZEN_FIFTH_CUMULATIVE_SUITE_SHA256
        ),
        "base_cumulative_task_count": 280,
        "added_task_count": SIXTH_TRANCHE_ADDED_TASK_COUNT,
        "cumulative_task_count": SIXTH_TRANCHE_CUMULATIVE_TASK_COUNT,
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


def compute_sixth_tranche_registry_sha256(
    tasks: tuple[SixthTrancheTask, ...],
) -> str:
    return domain_sha256(
        "cbds.executable-static.sixth-tranche-registry.v1",
        _registry_payload(tasks),
    )


def compute_sixth_tranche_cumulative_suite_sha256(
    tasks: tuple[SixthTrancheTask, ...],
    registry_sha256: str,
) -> str:
    _validate_added_tasks(tasks)
    if not _is_sha256(registry_sha256):
        raise SixthTrancheRegistryError(
            "sixth-tranche registry digest is invalid"
        )
    if registry_sha256 != compute_sixth_tranche_registry_sha256(tasks):
        raise SixthTrancheRegistryError(
            "registry digest does not bind the sixth-tranche tasks"
        )
    return domain_sha256(
        "cbds.executable-static.sixth-tranche-cumulative-suite.v1",
        {
            "base_cumulative_suite_sha256": (
                FROZEN_FIFTH_CUMULATIVE_SUITE_SHA256
            ),
            "added_registry_sha256": registry_sha256,
            "cumulative_task_count": SIXTH_TRANCHE_CUMULATIVE_TASK_COUNT,
        },
    )


@dataclass(frozen=True, slots=True)
class SixthTrancheTaskRegistry:
    added_tasks: tuple[SixthTrancheTask, ...]
    registry_sha256: str
    cumulative_suite_sha256: str
    schema_version: str = SIXTH_TRANCHE_REGISTRY_SCHEMA_VERSION
    registry_version: str = SIXTH_TRANCHE_REGISTRY_VERSION
    base_added_registry_sha256: str = FROZEN_FIFTH_ADDED_REGISTRY_SHA256
    base_cumulative_suite_sha256: str = (
        FROZEN_FIFTH_CUMULATIVE_SUITE_SHA256
    )
    public_method_development: bool = True
    sealed: bool = False
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_sixth_tranche_task_registry(self)

    def to_hash_only_record(self) -> dict[str, object]:
        validate_sixth_tranche_task_registry(self)
        return {
            "schema_version": self.schema_version,
            "registry_version": self.registry_version,
            "record_type": (
                "cbds.executable-static-sixth-tranche-registry-hashes"
            ),
            "base_added_registry_sha256": self.base_added_registry_sha256,
            "base_cumulative_suite_sha256": self.base_cumulative_suite_sha256,
            "base_cumulative_task_count": 280,
            "added_task_count": len(self.added_tasks),
            "cumulative_task_count": SIXTH_TRANCHE_CUMULATIVE_TASK_COUNT,
            "family_task_counts": {
                family: sum(
                    task.family_id == family for task in self.added_tasks
                )
                for family in SIXTH_TRANCHE_FAMILY_ORDER
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


def validate_sixth_tranche_task_registry(
    registry: SixthTrancheTaskRegistry,
) -> None:
    if type(registry) is not SixthTrancheTaskRegistry:
        raise SixthTrancheRegistryError(
            "registry must be an exact SixthTrancheTaskRegistry"
        )
    if (
        type(registry.schema_version) is not str
        or registry.schema_version != SIXTH_TRANCHE_REGISTRY_SCHEMA_VERSION
        or type(registry.registry_version) is not str
        or registry.registry_version != SIXTH_TRANCHE_REGISTRY_VERSION
        or not _is_sha256(registry.base_added_registry_sha256)
        or registry.base_added_registry_sha256
        != FROZEN_FIFTH_ADDED_REGISTRY_SHA256
        or not _is_sha256(registry.base_cumulative_suite_sha256)
        or registry.base_cumulative_suite_sha256
        != FROZEN_FIFTH_CUMULATIVE_SUITE_SHA256
        or not _is_sha256(registry.registry_sha256)
        or not _is_sha256(registry.cumulative_suite_sha256)
        or registry.public_method_development is not True
        or registry.sealed is not False
        or registry.candidate_execution_authorized is not False
        or registry.model_selection_eligible is not False
        or registry.claim_authorized is not False
    ):
        raise SixthTrancheRegistryError(
            "sixth-tranche registry metadata is invalid"
        )
    tasks = _validate_added_tasks(registry.added_tasks)
    expected_registry = compute_sixth_tranche_registry_sha256(tasks)
    if registry.registry_sha256 != expected_registry:
        raise SixthTrancheRegistryError(
            "sixth-tranche registry digest is invalid"
        )
    expected_suite = compute_sixth_tranche_cumulative_suite_sha256(
        tasks, expected_registry
    )
    if registry.cumulative_suite_sha256 != expected_suite:
        raise SixthTrancheRegistryError(
            "sixth-tranche cumulative suite digest is invalid"
        )


def _validate_live_base_and_global_uniqueness(
    tasks: tuple[SixthTrancheTask, ...],
) -> None:
    """Rebuild all frozen predecessors before publishing the addition."""

    from .executable_static_registry import build_public_method_development_registry
    from .executable_static_second_registry import build_second_tranche_task_registry
    from .executable_static_third_registry import build_third_tranche_task_registry
    from .executable_static_fourth_registry import build_fourth_tranche_task_registry
    from .executable_static_fifth_registry import build_fifth_tranche_task_registry

    first = build_public_method_development_registry()
    second = build_second_tranche_task_registry()
    third = build_third_tranche_task_registry()
    fourth = build_fourth_tranche_task_registry()
    fifth = build_fifth_tranche_task_registry()
    if (
        first.registry_sha256 != FROZEN_FIRST_REGISTRY_SHA256
        or first.suite_sha256 != FROZEN_FIRST_SUITE_SHA256
        or second.registry_sha256 != FROZEN_SECOND_ADDED_REGISTRY_SHA256
        or second.cumulative_suite_sha256
        != FROZEN_SECOND_CUMULATIVE_SUITE_SHA256
        or third.registry_sha256 != FROZEN_THIRD_ADDED_REGISTRY_SHA256
        or third.cumulative_suite_sha256
        != FROZEN_THIRD_CUMULATIVE_SUITE_SHA256
        or fourth.registry_sha256 != FROZEN_FOURTH_ADDED_REGISTRY_SHA256
        or fourth.cumulative_suite_sha256
        != FROZEN_FOURTH_CUMULATIVE_SUITE_SHA256
        or fifth.registry_sha256 != FROZEN_FIFTH_ADDED_REGISTRY_SHA256
        or fifth.cumulative_suite_sha256
        != FROZEN_FIFTH_CUMULATIVE_SUITE_SHA256
    ):
        raise SixthTrancheRegistryError(
            "a live predecessor registry differs from its frozen identity"
        )
    all_tasks = (
        *first.tasks,
        *second.added_tasks,
        *third.added_tasks,
        *fourth.added_tasks,
        *fifth.added_tasks,
        *_validate_added_tasks(tasks),
    )
    if (
        len(all_tasks) != SIXTH_TRANCHE_CUMULATIVE_TASK_COUNT
        or len({task.task_id for task in all_tasks}) != len(all_tasks)
        or len({task.task_contract_sha256 for task in all_tasks})
        != len(all_tasks)
        or len({task.graph_sha256 for task in all_tasks}) != len(all_tasks)
    ):
        raise SixthTrancheRegistryError(
            "sixth-tranche tasks collide with a frozen predecessor"
        )


def build_sixth_tranche_task_registry() -> SixthTrancheTaskRegistry:
    tasks = build_sixth_tranche_added_tasks()
    _validate_live_base_and_global_uniqueness(tasks)
    registry_sha256 = compute_sixth_tranche_registry_sha256(tasks)
    cumulative_suite_sha256 = compute_sixth_tranche_cumulative_suite_sha256(
        tasks, registry_sha256
    )
    return SixthTrancheTaskRegistry(
        added_tasks=tasks,
        registry_sha256=registry_sha256,
        cumulative_suite_sha256=cumulative_suite_sha256,
    )


__all__ = [
    "FROZEN_FIRST_REGISTRY_SHA256",
    "FROZEN_FIRST_SUITE_SHA256",
    "FROZEN_SECOND_ADDED_REGISTRY_SHA256",
    "FROZEN_SECOND_CUMULATIVE_SUITE_SHA256",
    "FROZEN_THIRD_ADDED_REGISTRY_SHA256",
    "FROZEN_THIRD_CUMULATIVE_SUITE_SHA256",
    "FROZEN_FOURTH_ADDED_REGISTRY_SHA256",
    "FROZEN_FOURTH_CUMULATIVE_SUITE_SHA256",
    "FROZEN_FIFTH_ADDED_REGISTRY_SHA256",
    "FROZEN_FIFTH_CUMULATIVE_SUITE_SHA256",
    "SIXTH_TRANCHE_ADDED_TASK_COUNT",
    "SIXTH_TRANCHE_CUMULATIVE_TASK_COUNT",
    "SIXTH_TRANCHE_FAMILY_ORDER",
    "SIXTH_TRANCHE_REGISTRY_SCHEMA_VERSION",
    "SIXTH_TRANCHE_REGISTRY_VERSION",
    "SixthTrancheRegistryError",
    "SixthTrancheTaskRegistry",
    "build_sixth_tranche_added_tasks",
    "build_sixth_tranche_task_registry",
    "compute_sixth_tranche_cumulative_suite_sha256",
    "compute_sixth_tranche_registry_sha256",
    "validate_sixth_tranche_task_registry",
]
