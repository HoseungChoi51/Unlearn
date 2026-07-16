"""Additive registry for the reproducible-ustar-pack development family.

The first three executable-static registries remain immutable.  This module
binds the exact family-local ustar-pack contract as a fourth 20-task addition
without widening a frozen shared task union.  It contains public
method-development commitments only and grants no execution, model-selection,
scored-evaluation, or claim authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Final, TypeAlias

from .executable_fixture_profiles import PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
from .executable_static_types import domain_sha256
from .executable_ustar_pack import (
    USTAR_PACK_MODE_POLICIES,
    USTAR_PACK_SELECTORS,
    UstarPackTask,
    build_ustar_pack_tasks,
)


FOURTH_TRANCHE_REGISTRY_SCHEMA_VERSION: Final[str] = "1.0.0"
FOURTH_TRANCHE_REGISTRY_VERSION: Final[str] = "1.0.0"
FOURTH_TRANCHE_ADDED_TASK_COUNT: Final[int] = 20
FOURTH_TRANCHE_CUMULATIVE_TASK_COUNT: Final[int] = 260
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
FOURTH_TRANCHE_FAMILY_ORDER: Final[tuple[str, ...]] = (
    "reproducible-ustar-pack",
)

FourthTrancheTask: TypeAlias = UstarPackTask
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")


class FourthTrancheRegistryError(ValueError):
    """Raised when the fourth additive registry is not reproducible."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def build_fourth_tranche_added_tasks() -> tuple[FourthTrancheTask, ...]:
    """Build the exact family-local 20-task grid in canonical order."""

    tasks = build_ustar_pack_tasks()
    _validate_added_tasks(tasks)
    return tasks


def _validate_added_tasks(
    tasks: object,
) -> tuple[FourthTrancheTask, ...]:
    if (
        type(tasks) is not tuple
        or len(tasks) != FOURTH_TRANCHE_ADDED_TASK_COUNT
        or any(type(task) is not UstarPackTask for task in tasks)
    ):
        raise FourthTrancheRegistryError(
            "fourth tranche requires exactly 20 exact UstarPackTask values"
        )
    selected = tasks
    try:
        for task in selected:
            task.__post_init__()
    except (AttributeError, TypeError, ValueError) as exc:
        raise FourthTrancheRegistryError(
            "fourth-tranche task validation failed"
        ) from exc

    expected_grid = tuple(
        (selector, mode_policy)
        for selector in USTAR_PACK_SELECTORS
        for mode_policy in USTAR_PACK_MODE_POLICIES
    )
    observed_grid = tuple(
        (task.parameters.selector, task.parameters.archive_mode_policy)
        for task in selected
    )
    if observed_grid != expected_grid:
        raise FourthTrancheRegistryError(
            "fourth-tranche parameter grid is incomplete or out of order"
        )
    if (
        len({task.task_id for task in selected})
        != FOURTH_TRANCHE_ADDED_TASK_COUNT
        or len({task.task_contract_sha256 for task in selected})
        != FOURTH_TRANCHE_ADDED_TASK_COUNT
        or len({task.graph_sha256 for task in selected})
        != FOURTH_TRANCHE_ADDED_TASK_COUNT
        or any(
            len(task.fixtures) != len(PUBLIC_DEVELOPMENT_FIXTURE_PROFILES)
            for task in selected
        )
    ):
        raise FourthTrancheRegistryError(
            "fourth-tranche task identities are not unique"
        )
    return selected


def _registry_payload(
    tasks: tuple[FourthTrancheTask, ...],
) -> dict[str, object]:
    selected = _validate_added_tasks(tasks)
    return {
        "schema_version": FOURTH_TRANCHE_REGISTRY_SCHEMA_VERSION,
        "registry_version": FOURTH_TRANCHE_REGISTRY_VERSION,
        "record_type": "cbds.executable-static-fourth-tranche-registry",
        "base_added_registry_sha256": FROZEN_THIRD_ADDED_REGISTRY_SHA256,
        "base_cumulative_suite_sha256": (
            FROZEN_THIRD_CUMULATIVE_SUITE_SHA256
        ),
        "base_cumulative_task_count": 240,
        "added_task_count": FOURTH_TRANCHE_ADDED_TASK_COUNT,
        "cumulative_task_count": FOURTH_TRANCHE_CUMULATIVE_TASK_COUNT,
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


def compute_fourth_tranche_registry_sha256(
    tasks: tuple[FourthTrancheTask, ...],
) -> str:
    return domain_sha256(
        "cbds.executable-static.fourth-tranche-registry.v1",
        _registry_payload(tasks),
    )


def compute_fourth_tranche_cumulative_suite_sha256(
    tasks: tuple[FourthTrancheTask, ...],
    registry_sha256: str,
) -> str:
    _validate_added_tasks(tasks)
    if not _is_sha256(registry_sha256):
        raise FourthTrancheRegistryError(
            "fourth-tranche registry digest is invalid"
        )
    if registry_sha256 != compute_fourth_tranche_registry_sha256(tasks):
        raise FourthTrancheRegistryError(
            "registry digest does not bind the fourth-tranche tasks"
        )
    return domain_sha256(
        "cbds.executable-static.fourth-tranche-cumulative-suite.v1",
        {
            "base_cumulative_suite_sha256": (
                FROZEN_THIRD_CUMULATIVE_SUITE_SHA256
            ),
            "added_registry_sha256": registry_sha256,
            "cumulative_task_count": FOURTH_TRANCHE_CUMULATIVE_TASK_COUNT,
        },
    )


@dataclass(frozen=True, slots=True)
class FourthTrancheTaskRegistry:
    added_tasks: tuple[FourthTrancheTask, ...]
    registry_sha256: str
    cumulative_suite_sha256: str
    schema_version: str = FOURTH_TRANCHE_REGISTRY_SCHEMA_VERSION
    registry_version: str = FOURTH_TRANCHE_REGISTRY_VERSION
    base_added_registry_sha256: str = FROZEN_THIRD_ADDED_REGISTRY_SHA256
    base_cumulative_suite_sha256: str = (
        FROZEN_THIRD_CUMULATIVE_SUITE_SHA256
    )
    public_method_development: bool = True
    sealed: bool = False
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_fourth_tranche_task_registry(self)

    def to_hash_only_record(self) -> dict[str, object]:
        validate_fourth_tranche_task_registry(self)
        return {
            "schema_version": self.schema_version,
            "registry_version": self.registry_version,
            "record_type": (
                "cbds.executable-static-fourth-tranche-registry-hashes"
            ),
            "base_added_registry_sha256": self.base_added_registry_sha256,
            "base_cumulative_suite_sha256": self.base_cumulative_suite_sha256,
            "base_cumulative_task_count": 240,
            "added_task_count": len(self.added_tasks),
            "cumulative_task_count": FOURTH_TRANCHE_CUMULATIVE_TASK_COUNT,
            "family_task_counts": {
                family: sum(
                    task.family_id == family for task in self.added_tasks
                )
                for family in FOURTH_TRANCHE_FAMILY_ORDER
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


def validate_fourth_tranche_task_registry(
    registry: FourthTrancheTaskRegistry,
) -> None:
    if type(registry) is not FourthTrancheTaskRegistry:
        raise FourthTrancheRegistryError(
            "registry must be an exact FourthTrancheTaskRegistry"
        )
    if (
        type(registry.schema_version) is not str
        or registry.schema_version != FOURTH_TRANCHE_REGISTRY_SCHEMA_VERSION
        or type(registry.registry_version) is not str
        or registry.registry_version != FOURTH_TRANCHE_REGISTRY_VERSION
        or not _is_sha256(registry.base_added_registry_sha256)
        or registry.base_added_registry_sha256
        != FROZEN_THIRD_ADDED_REGISTRY_SHA256
        or not _is_sha256(registry.base_cumulative_suite_sha256)
        or registry.base_cumulative_suite_sha256
        != FROZEN_THIRD_CUMULATIVE_SUITE_SHA256
        or not _is_sha256(registry.registry_sha256)
        or not _is_sha256(registry.cumulative_suite_sha256)
        or registry.public_method_development is not True
        or registry.sealed is not False
        or registry.candidate_execution_authorized is not False
        or registry.model_selection_eligible is not False
        or registry.claim_authorized is not False
    ):
        raise FourthTrancheRegistryError(
            "fourth-tranche registry metadata is invalid"
        )
    tasks = _validate_added_tasks(registry.added_tasks)
    expected_registry = compute_fourth_tranche_registry_sha256(tasks)
    if registry.registry_sha256 != expected_registry:
        raise FourthTrancheRegistryError(
            "fourth-tranche registry digest is invalid"
        )
    expected_suite = compute_fourth_tranche_cumulative_suite_sha256(
        tasks, expected_registry
    )
    if registry.cumulative_suite_sha256 != expected_suite:
        raise FourthTrancheRegistryError(
            "fourth-tranche cumulative suite digest is invalid"
        )


def _validate_live_base_and_global_uniqueness(
    tasks: tuple[FourthTrancheTask, ...],
) -> None:
    """Rebuild all frozen predecessors before publishing the addition."""

    from .executable_static_registry import build_public_method_development_registry
    from .executable_static_second_registry import build_second_tranche_task_registry
    from .executable_static_third_registry import build_third_tranche_task_registry

    first = build_public_method_development_registry()
    second = build_second_tranche_task_registry()
    third = build_third_tranche_task_registry()
    if (
        first.registry_sha256 != FROZEN_FIRST_REGISTRY_SHA256
        or first.suite_sha256 != FROZEN_FIRST_SUITE_SHA256
        or second.registry_sha256 != FROZEN_SECOND_ADDED_REGISTRY_SHA256
        or second.cumulative_suite_sha256
        != FROZEN_SECOND_CUMULATIVE_SUITE_SHA256
        or third.registry_sha256 != FROZEN_THIRD_ADDED_REGISTRY_SHA256
        or third.cumulative_suite_sha256
        != FROZEN_THIRD_CUMULATIVE_SUITE_SHA256
    ):
        raise FourthTrancheRegistryError(
            "a live predecessor registry differs from its frozen identity"
        )
    all_tasks = (
        *first.tasks,
        *second.added_tasks,
        *third.added_tasks,
        *_validate_added_tasks(tasks),
    )
    if (
        len(all_tasks) != FOURTH_TRANCHE_CUMULATIVE_TASK_COUNT
        or len({task.task_id for task in all_tasks}) != len(all_tasks)
        or len({task.task_contract_sha256 for task in all_tasks})
        != len(all_tasks)
        or len({task.graph_sha256 for task in all_tasks}) != len(all_tasks)
    ):
        raise FourthTrancheRegistryError(
            "fourth-tranche tasks collide with a frozen predecessor"
        )


def build_fourth_tranche_task_registry() -> FourthTrancheTaskRegistry:
    tasks = build_fourth_tranche_added_tasks()
    _validate_live_base_and_global_uniqueness(tasks)
    registry_sha256 = compute_fourth_tranche_registry_sha256(tasks)
    cumulative_suite_sha256 = compute_fourth_tranche_cumulative_suite_sha256(
        tasks, registry_sha256
    )
    return FourthTrancheTaskRegistry(
        added_tasks=tasks,
        registry_sha256=registry_sha256,
        cumulative_suite_sha256=cumulative_suite_sha256,
    )


__all__ = [
    "FOURTH_TRANCHE_ADDED_TASK_COUNT",
    "FOURTH_TRANCHE_CUMULATIVE_TASK_COUNT",
    "FOURTH_TRANCHE_FAMILY_ORDER",
    "FOURTH_TRANCHE_REGISTRY_SCHEMA_VERSION",
    "FOURTH_TRANCHE_REGISTRY_VERSION",
    "FROZEN_FIRST_REGISTRY_SHA256",
    "FROZEN_FIRST_SUITE_SHA256",
    "FROZEN_SECOND_ADDED_REGISTRY_SHA256",
    "FROZEN_SECOND_CUMULATIVE_SUITE_SHA256",
    "FROZEN_THIRD_ADDED_REGISTRY_SHA256",
    "FROZEN_THIRD_CUMULATIVE_SUITE_SHA256",
    "FourthTrancheRegistryError",
    "FourthTrancheTaskRegistry",
    "build_fourth_tranche_added_tasks",
    "build_fourth_tranche_task_registry",
    "compute_fourth_tranche_cumulative_suite_sha256",
    "compute_fourth_tranche_registry_sha256",
    "validate_fourth_tranche_task_registry",
]
