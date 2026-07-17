"""Additive registry for the collision-safe-batch-rename family.

The first seven executable-static registries remain immutable.  This module
binds the exact family-local batch-rename contract as an eighth 20-task
addition without widening any frozen shared task union.  It contains public
method-development commitments only and grants no execution, model-selection,
scored-evaluation, or research-claim authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Final, TypeAlias

from .executable_collision_safe_batch_rename import (
    COLLISION_SAFE_BATCH_RENAME_COLLISION_POLICIES,
    COLLISION_SAFE_BATCH_RENAME_RENAME_RULES,
    CollisionSafeBatchRenameTask,
    build_collision_safe_batch_rename_tasks,
)
from .executable_fixture_profiles import PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
from .executable_static_types import domain_sha256


EIGHTH_TRANCHE_REGISTRY_SCHEMA_VERSION: Final[str] = "1.0.0"
EIGHTH_TRANCHE_REGISTRY_VERSION: Final[str] = "1.0.0"
EIGHTH_TRANCHE_ADDED_TASK_COUNT: Final[int] = 20
EIGHTH_TRANCHE_CUMULATIVE_TASK_COUNT: Final[int] = 340

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
FROZEN_SIXTH_ADDED_REGISTRY_SHA256: Final[str] = (
    "14280b3cbc8a96c919a57a325b5795c381cba86b2a31934f7069821b7ff4e3c4"
)
FROZEN_SIXTH_CUMULATIVE_SUITE_SHA256: Final[str] = (
    "db6d00278664f5a72834ebf0297411564da8b98a75d08eb2c2e9cf706dc985b1"
)
FROZEN_SEVENTH_ADDED_REGISTRY_SHA256: Final[str] = (
    "14aa05939c2ac2f4954196968003254dee39175f1d1d94e32213b8a74cfff19e"
)
FROZEN_SEVENTH_CUMULATIVE_SUITE_SHA256: Final[str] = (
    "341b50a83305a9e0c64ada387eee461209ca75d1083e34fe2887a608179de131"
)
EIGHTH_TRANCHE_FAMILY_ORDER: Final[tuple[str, ...]] = (
    "collision-safe-batch-rename",
)

EighthTrancheTask: TypeAlias = CollisionSafeBatchRenameTask
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")


class EighthTrancheRegistryError(ValueError):
    """Raised when the eighth additive registry is not reproducible."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def build_eighth_tranche_added_tasks() -> tuple[EighthTrancheTask, ...]:
    """Build the exact family-local 20-task grid in canonical order."""

    tasks = build_collision_safe_batch_rename_tasks()
    _validate_added_tasks(tasks)
    return tasks


def _validate_added_tasks(
    tasks: object,
) -> tuple[EighthTrancheTask, ...]:
    if (
        type(tasks) is not tuple
        or len(tasks) != EIGHTH_TRANCHE_ADDED_TASK_COUNT
        or any(type(task) is not CollisionSafeBatchRenameTask for task in tasks)
    ):
        raise EighthTrancheRegistryError(
            "eighth tranche requires exactly 20 exact "
            "CollisionSafeBatchRenameTask values"
        )
    selected = tasks
    try:
        for task in selected:
            task.__post_init__()
    except (AttributeError, TypeError, ValueError) as exc:
        raise EighthTrancheRegistryError(
            "eighth-tranche task validation failed"
        ) from exc

    expected_grid = tuple(
        (rename_rule, collision_policy)
        for rename_rule in COLLISION_SAFE_BATCH_RENAME_RENAME_RULES
        for collision_policy in COLLISION_SAFE_BATCH_RENAME_COLLISION_POLICIES
    )
    observed_grid = tuple(
        (task.parameters.rename_rule, task.parameters.collision_policy)
        for task in selected
    )
    if observed_grid != expected_grid:
        raise EighthTrancheRegistryError(
            "eighth-tranche parameter grid is incomplete or out of order"
        )
    if (
        len({task.task_id for task in selected})
        != EIGHTH_TRANCHE_ADDED_TASK_COUNT
        or len({task.task_contract_sha256 for task in selected})
        != EIGHTH_TRANCHE_ADDED_TASK_COUNT
        or len({task.graph_sha256 for task in selected})
        != EIGHTH_TRANCHE_ADDED_TASK_COUNT
        or any(
            len(task.fixtures) != len(PUBLIC_DEVELOPMENT_FIXTURE_PROFILES)
            for task in selected
        )
    ):
        raise EighthTrancheRegistryError(
            "eighth-tranche task identities are not unique"
        )
    return selected


def _registry_payload(
    tasks: tuple[EighthTrancheTask, ...],
) -> dict[str, object]:
    selected = _validate_added_tasks(tasks)
    return {
        "schema_version": EIGHTH_TRANCHE_REGISTRY_SCHEMA_VERSION,
        "registry_version": EIGHTH_TRANCHE_REGISTRY_VERSION,
        "record_type": "cbds.executable-static-eighth-tranche-registry",
        "base_added_registry_sha256": FROZEN_SEVENTH_ADDED_REGISTRY_SHA256,
        "base_cumulative_suite_sha256": (
            FROZEN_SEVENTH_CUMULATIVE_SUITE_SHA256
        ),
        "base_cumulative_task_count": 320,
        "added_task_count": EIGHTH_TRANCHE_ADDED_TASK_COUNT,
        "cumulative_task_count": EIGHTH_TRANCHE_CUMULATIVE_TASK_COUNT,
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


def compute_eighth_tranche_registry_sha256(
    tasks: tuple[EighthTrancheTask, ...],
) -> str:
    return domain_sha256(
        "cbds.executable-static.eighth-tranche-registry.v1",
        _registry_payload(tasks),
    )


def compute_eighth_tranche_cumulative_suite_sha256(
    tasks: tuple[EighthTrancheTask, ...],
    registry_sha256: str,
) -> str:
    _validate_added_tasks(tasks)
    if not _is_sha256(registry_sha256):
        raise EighthTrancheRegistryError(
            "eighth-tranche registry digest is invalid"
        )
    if registry_sha256 != compute_eighth_tranche_registry_sha256(tasks):
        raise EighthTrancheRegistryError(
            "registry digest does not bind the eighth-tranche tasks"
        )
    return domain_sha256(
        "cbds.executable-static.eighth-tranche-cumulative-suite.v1",
        {
            "base_cumulative_suite_sha256": (
                FROZEN_SEVENTH_CUMULATIVE_SUITE_SHA256
            ),
            "added_registry_sha256": registry_sha256,
            "cumulative_task_count": EIGHTH_TRANCHE_CUMULATIVE_TASK_COUNT,
        },
    )


@dataclass(frozen=True, slots=True)
class EighthTrancheTaskRegistry:
    added_tasks: tuple[EighthTrancheTask, ...]
    registry_sha256: str
    cumulative_suite_sha256: str
    schema_version: str = EIGHTH_TRANCHE_REGISTRY_SCHEMA_VERSION
    registry_version: str = EIGHTH_TRANCHE_REGISTRY_VERSION
    base_added_registry_sha256: str = FROZEN_SEVENTH_ADDED_REGISTRY_SHA256
    base_cumulative_suite_sha256: str = (
        FROZEN_SEVENTH_CUMULATIVE_SUITE_SHA256
    )
    public_method_development: bool = True
    sealed: bool = False
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_eighth_tranche_task_registry(self)

    def to_hash_only_record(self) -> dict[str, object]:
        validate_eighth_tranche_task_registry(self)
        return {
            "schema_version": self.schema_version,
            "registry_version": self.registry_version,
            "record_type": (
                "cbds.executable-static-eighth-tranche-registry-hashes"
            ),
            "base_added_registry_sha256": self.base_added_registry_sha256,
            "base_cumulative_suite_sha256": self.base_cumulative_suite_sha256,
            "base_cumulative_task_count": 320,
            "added_task_count": len(self.added_tasks),
            "cumulative_task_count": EIGHTH_TRANCHE_CUMULATIVE_TASK_COUNT,
            "family_task_counts": {
                family: sum(
                    task.family_id == family for task in self.added_tasks
                )
                for family in EIGHTH_TRANCHE_FAMILY_ORDER
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


def validate_eighth_tranche_task_registry(
    registry: EighthTrancheTaskRegistry,
) -> None:
    if type(registry) is not EighthTrancheTaskRegistry:
        raise EighthTrancheRegistryError(
            "registry must be an exact EighthTrancheTaskRegistry"
        )
    if (
        type(registry.schema_version) is not str
        or registry.schema_version != EIGHTH_TRANCHE_REGISTRY_SCHEMA_VERSION
        or type(registry.registry_version) is not str
        or registry.registry_version != EIGHTH_TRANCHE_REGISTRY_VERSION
        or not _is_sha256(registry.base_added_registry_sha256)
        or registry.base_added_registry_sha256
        != FROZEN_SEVENTH_ADDED_REGISTRY_SHA256
        or not _is_sha256(registry.base_cumulative_suite_sha256)
        or registry.base_cumulative_suite_sha256
        != FROZEN_SEVENTH_CUMULATIVE_SUITE_SHA256
        or not _is_sha256(registry.registry_sha256)
        or not _is_sha256(registry.cumulative_suite_sha256)
        or registry.public_method_development is not True
        or registry.sealed is not False
        or registry.candidate_execution_authorized is not False
        or registry.model_selection_eligible is not False
        or registry.claim_authorized is not False
    ):
        raise EighthTrancheRegistryError(
            "eighth-tranche registry metadata is invalid"
        )
    tasks = _validate_added_tasks(registry.added_tasks)
    expected_registry = compute_eighth_tranche_registry_sha256(tasks)
    if registry.registry_sha256 != expected_registry:
        raise EighthTrancheRegistryError(
            "eighth-tranche registry digest is invalid"
        )
    expected_suite = compute_eighth_tranche_cumulative_suite_sha256(
        tasks, expected_registry
    )
    if registry.cumulative_suite_sha256 != expected_suite:
        raise EighthTrancheRegistryError(
            "eighth-tranche cumulative suite digest is invalid"
        )


def _validate_live_base_and_global_uniqueness(
    tasks: tuple[EighthTrancheTask, ...],
) -> None:
    """Rebuild every frozen predecessor before publishing the addition."""

    from .executable_static_registry import (
        build_public_method_development_registry,
    )
    from .executable_static_second_registry import (
        build_second_tranche_task_registry,
    )
    from .executable_static_third_registry import (
        build_third_tranche_task_registry,
    )
    from .executable_static_fourth_registry import (
        build_fourth_tranche_task_registry,
    )
    from .executable_static_fifth_registry import (
        build_fifth_tranche_task_registry,
    )
    from .executable_static_sixth_registry import (
        build_sixth_tranche_task_registry,
    )
    from .executable_static_seventh_registry import (
        build_seventh_tranche_task_registry,
    )

    first = build_public_method_development_registry()
    second = build_second_tranche_task_registry()
    third = build_third_tranche_task_registry()
    fourth = build_fourth_tranche_task_registry()
    fifth = build_fifth_tranche_task_registry()
    sixth = build_sixth_tranche_task_registry()
    seventh = build_seventh_tranche_task_registry()
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
        or sixth.registry_sha256 != FROZEN_SIXTH_ADDED_REGISTRY_SHA256
        or sixth.cumulative_suite_sha256
        != FROZEN_SIXTH_CUMULATIVE_SUITE_SHA256
        or seventh.registry_sha256 != FROZEN_SEVENTH_ADDED_REGISTRY_SHA256
        or seventh.cumulative_suite_sha256
        != FROZEN_SEVENTH_CUMULATIVE_SUITE_SHA256
    ):
        raise EighthTrancheRegistryError(
            "a live predecessor registry differs from its frozen identity"
        )
    all_tasks = (
        *first.tasks,
        *second.added_tasks,
        *third.added_tasks,
        *fourth.added_tasks,
        *fifth.added_tasks,
        *sixth.added_tasks,
        *seventh.added_tasks,
        *_validate_added_tasks(tasks),
    )
    if (
        len(all_tasks) != EIGHTH_TRANCHE_CUMULATIVE_TASK_COUNT
        or len({task.task_id for task in all_tasks}) != len(all_tasks)
        or len({task.task_contract_sha256 for task in all_tasks})
        != len(all_tasks)
        or len({task.graph_sha256 for task in all_tasks}) != len(all_tasks)
    ):
        raise EighthTrancheRegistryError(
            "eighth-tranche tasks collide with a frozen predecessor"
        )


def build_eighth_tranche_task_registry() -> EighthTrancheTaskRegistry:
    tasks = build_eighth_tranche_added_tasks()
    _validate_live_base_and_global_uniqueness(tasks)
    registry_sha256 = compute_eighth_tranche_registry_sha256(tasks)
    cumulative_suite_sha256 = compute_eighth_tranche_cumulative_suite_sha256(
        tasks, registry_sha256
    )
    return EighthTrancheTaskRegistry(
        added_tasks=tasks,
        registry_sha256=registry_sha256,
        cumulative_suite_sha256=cumulative_suite_sha256,
    )


__all__ = [
    "EIGHTH_TRANCHE_ADDED_TASK_COUNT",
    "EIGHTH_TRANCHE_CUMULATIVE_TASK_COUNT",
    "EIGHTH_TRANCHE_FAMILY_ORDER",
    "EIGHTH_TRANCHE_REGISTRY_SCHEMA_VERSION",
    "EIGHTH_TRANCHE_REGISTRY_VERSION",
    "EighthTrancheRegistryError",
    "EighthTrancheTaskRegistry",
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
    "FROZEN_SIXTH_ADDED_REGISTRY_SHA256",
    "FROZEN_SIXTH_CUMULATIVE_SUITE_SHA256",
    "FROZEN_SEVENTH_ADDED_REGISTRY_SHA256",
    "FROZEN_SEVENTH_CUMULATIVE_SUITE_SHA256",
    "build_eighth_tranche_added_tasks",
    "build_eighth_tranche_task_registry",
    "compute_eighth_tranche_cumulative_suite_sha256",
    "compute_eighth_tranche_registry_sha256",
    "validate_eighth_tranche_task_registry",
]
