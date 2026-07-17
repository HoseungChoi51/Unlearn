"""Additive registry for bounded nested-JSON schema migration.

The first twelve executable-static registries remain immutable.  This module
binds the exact family-local migration contract as a thirteenth 20-task
addition.  Its predecessor is the non-recursive, hash-neutral through-
twelfth evidence snapshot: every historical task is built once per call,
and no historical publication builder is called recursively.

This record is public method-development metadata only.  It grants no
candidate execution, model-selection, scored-evaluation, or claim authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Final, TypeAlias

from .executable_fixture_profiles import PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
from .executable_nested_json_schema_migration import (
    NESTED_JSON_SCHEMA_MIGRATION_INPUT_SHAPES,
    NESTED_JSON_SCHEMA_MIGRATION_POLICIES,
    NestedJsonSchemaMigrationTask,
    build_nested_json_schema_migration_tasks,
)
from .executable_static_types import domain_sha256
from .executable_twelfth_predecessor_evidence import (
    FROZEN_TWELFTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_TWELFTH_REGISTRY_SHA256,
    TWELFTH_PREFIX_TASK_COUNT,
    TwelfthPrefixTaskEvidence,
    build_twelfth_prefix_task_evidence,
    validate_twelfth_prefix_task_evidence,
)


THIRTEENTH_TRANCHE_REGISTRY_SCHEMA_VERSION: Final[str] = "1.0.0"
THIRTEENTH_TRANCHE_REGISTRY_VERSION: Final[str] = "1.0.0"
THIRTEENTH_TRANCHE_ADDED_TASK_COUNT: Final[int] = 20
THIRTEENTH_TRANCHE_CUMULATIVE_TASK_COUNT: Final[int] = 440
THIRTEENTH_TRANCHE_FAMILY_ORDER: Final[tuple[str, ...]] = (
    "nested-json-schema-migration",
)

FROZEN_THIRTEENTH_REGISTRY_SHA256: Final[str] = (
    "01990ca4355ef20736861d7bb7753e09e5ccbbfbddf8d21c4ffce3a451d83873"
)
FROZEN_THIRTEENTH_CUMULATIVE_SUITE_SHA256: Final[str] = (
    "bb7b78b68879eb32d4849bb5d82cac7a90b0695dc3fa72b9836dd7b6e70863e0"
)

ThirteenthTrancheTask: TypeAlias = NestedJsonSchemaMigrationTask
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")


class ThirteenthTrancheRegistryError(ValueError):
    """Raised when the thirteenth additive registry is not reproducible."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def build_thirteenth_tranche_added_tasks() -> tuple[
    ThirteenthTrancheTask, ...
]:
    """Build the exact family-local 20-task grid in canonical order."""

    tasks = build_nested_json_schema_migration_tasks()
    _validate_added_tasks(tasks)
    return tasks


def _validate_added_tasks(
    tasks: object,
) -> tuple[ThirteenthTrancheTask, ...]:
    if (
        type(tasks) is not tuple
        or len(tasks) != THIRTEENTH_TRANCHE_ADDED_TASK_COUNT
        or any(type(task) is not NestedJsonSchemaMigrationTask for task in tasks)
    ):
        raise ThirteenthTrancheRegistryError(
            "thirteenth tranche requires exactly 20 exact "
            "NestedJsonSchemaMigrationTask values"
        )
    selected = tasks
    try:
        for task in selected:
            task.__post_init__()
    except (AttributeError, TypeError, ValueError) as exc:
        raise ThirteenthTrancheRegistryError(
            "thirteenth-tranche task validation failed"
        ) from exc

    expected_grid = tuple(
        (input_shape, migration_policy)
        for input_shape in NESTED_JSON_SCHEMA_MIGRATION_INPUT_SHAPES
        for migration_policy in NESTED_JSON_SCHEMA_MIGRATION_POLICIES
    )
    observed_grid = tuple(
        (task.parameters.input_shape, task.parameters.migration_policy)
        for task in selected
    )
    if observed_grid != expected_grid:
        raise ThirteenthTrancheRegistryError(
            "thirteenth-tranche parameter grid is incomplete or out of order"
        )
    if (
        len({task.task_id for task in selected})
        != THIRTEENTH_TRANCHE_ADDED_TASK_COUNT
        or len({task.task_contract_sha256 for task in selected})
        != THIRTEENTH_TRANCHE_ADDED_TASK_COUNT
        or len({task.graph_sha256 for task in selected})
        != THIRTEENTH_TRANCHE_ADDED_TASK_COUNT
        or any(
            len(task.fixtures) != len(PUBLIC_DEVELOPMENT_FIXTURE_PROFILES)
            for task in selected
        )
    ):
        raise ThirteenthTrancheRegistryError(
            "thirteenth-tranche task identities are not unique"
        )
    return selected


def _registry_payload(
    tasks: tuple[ThirteenthTrancheTask, ...],
) -> dict[str, object]:
    selected = _validate_added_tasks(tasks)
    return {
        "schema_version": THIRTEENTH_TRANCHE_REGISTRY_SCHEMA_VERSION,
        "registry_version": THIRTEENTH_TRANCHE_REGISTRY_VERSION,
        "record_type": (
            "cbds.executable-static-thirteenth-tranche-registry"
        ),
        "base_added_registry_sha256": FROZEN_TWELFTH_REGISTRY_SHA256,
        "base_cumulative_suite_sha256": (
            FROZEN_TWELFTH_CUMULATIVE_SUITE_SHA256
        ),
        "base_cumulative_task_count": TWELFTH_PREFIX_TASK_COUNT,
        "added_task_count": THIRTEENTH_TRANCHE_ADDED_TASK_COUNT,
        "cumulative_task_count": THIRTEENTH_TRANCHE_CUMULATIVE_TASK_COUNT,
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


def compute_thirteenth_tranche_registry_sha256(
    tasks: tuple[ThirteenthTrancheTask, ...],
) -> str:
    return domain_sha256(
        "cbds.executable-static.thirteenth-tranche-registry.v1",
        _registry_payload(tasks),
    )


def compute_thirteenth_tranche_cumulative_suite_sha256(
    tasks: tuple[ThirteenthTrancheTask, ...],
    registry_sha256: str,
) -> str:
    _validate_added_tasks(tasks)
    if not _is_sha256(registry_sha256):
        raise ThirteenthTrancheRegistryError(
            "thirteenth-tranche registry digest is invalid"
        )
    if registry_sha256 != compute_thirteenth_tranche_registry_sha256(tasks):
        raise ThirteenthTrancheRegistryError(
            "registry digest does not bind the thirteenth-tranche tasks"
        )
    return domain_sha256(
        "cbds.executable-static.thirteenth-tranche-cumulative-suite.v1",
        {
            "base_cumulative_suite_sha256": (
                FROZEN_TWELFTH_CUMULATIVE_SUITE_SHA256
            ),
            "added_registry_sha256": registry_sha256,
            "cumulative_task_count": (
                THIRTEENTH_TRANCHE_CUMULATIVE_TASK_COUNT
            ),
        },
    )


@dataclass(frozen=True, slots=True)
class ThirteenthTrancheTaskRegistry:
    added_tasks: tuple[ThirteenthTrancheTask, ...]
    registry_sha256: str
    cumulative_suite_sha256: str
    schema_version: str = THIRTEENTH_TRANCHE_REGISTRY_SCHEMA_VERSION
    registry_version: str = THIRTEENTH_TRANCHE_REGISTRY_VERSION
    base_added_registry_sha256: str = FROZEN_TWELFTH_REGISTRY_SHA256
    base_cumulative_suite_sha256: str = (
        FROZEN_TWELFTH_CUMULATIVE_SUITE_SHA256
    )
    public_method_development: bool = True
    sealed: bool = False
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_thirteenth_tranche_task_registry(self)

    def to_hash_only_record(self) -> dict[str, object]:
        validate_thirteenth_tranche_task_registry(self)
        return {
            "schema_version": self.schema_version,
            "registry_version": self.registry_version,
            "record_type": (
                "cbds.executable-static-thirteenth-tranche-registry-hashes"
            ),
            "base_added_registry_sha256": (
                self.base_added_registry_sha256
            ),
            "base_cumulative_suite_sha256": (
                self.base_cumulative_suite_sha256
            ),
            "base_cumulative_task_count": TWELFTH_PREFIX_TASK_COUNT,
            "added_task_count": len(self.added_tasks),
            "cumulative_task_count": (
                THIRTEENTH_TRANCHE_CUMULATIVE_TASK_COUNT
            ),
            "family_task_counts": {
                family: sum(
                    task.family_id == family for task in self.added_tasks
                )
                for family in THIRTEENTH_TRANCHE_FAMILY_ORDER
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


def validate_thirteenth_tranche_task_registry(
    registry: ThirteenthTrancheTaskRegistry,
) -> None:
    if type(registry) is not ThirteenthTrancheTaskRegistry:
        raise ThirteenthTrancheRegistryError(
            "registry must be an exact ThirteenthTrancheTaskRegistry"
        )
    if (
        type(registry.schema_version) is not str
        or registry.schema_version
        != THIRTEENTH_TRANCHE_REGISTRY_SCHEMA_VERSION
        or type(registry.registry_version) is not str
        or registry.registry_version
        != THIRTEENTH_TRANCHE_REGISTRY_VERSION
        or not _is_sha256(registry.base_added_registry_sha256)
        or registry.base_added_registry_sha256
        != FROZEN_TWELFTH_REGISTRY_SHA256
        or not _is_sha256(registry.base_cumulative_suite_sha256)
        or registry.base_cumulative_suite_sha256
        != FROZEN_TWELFTH_CUMULATIVE_SUITE_SHA256
        or not _is_sha256(registry.registry_sha256)
        or not _is_sha256(registry.cumulative_suite_sha256)
        or registry.public_method_development is not True
        or registry.sealed is not False
        or registry.candidate_execution_authorized is not False
        or registry.model_selection_eligible is not False
        or registry.claim_authorized is not False
    ):
        raise ThirteenthTrancheRegistryError(
            "thirteenth-tranche registry metadata is invalid"
        )
    tasks = _validate_added_tasks(registry.added_tasks)
    expected_registry = compute_thirteenth_tranche_registry_sha256(tasks)
    if (
        registry.registry_sha256 != expected_registry
        or registry.registry_sha256
        != FROZEN_THIRTEENTH_REGISTRY_SHA256
    ):
        raise ThirteenthTrancheRegistryError(
            "thirteenth-tranche registry digest is invalid"
        )
    expected_suite = compute_thirteenth_tranche_cumulative_suite_sha256(
        tasks,
        expected_registry,
    )
    if (
        registry.cumulative_suite_sha256 != expected_suite
        or registry.cumulative_suite_sha256
        != FROZEN_THIRTEENTH_CUMULATIVE_SUITE_SHA256
    ):
        raise ThirteenthTrancheRegistryError(
            "thirteenth-tranche cumulative suite digest is invalid"
        )


def _validate_live_base_and_global_uniqueness(
    tasks: tuple[ThirteenthTrancheTask, ...],
    evidence: TwelfthPrefixTaskEvidence | None = None,
) -> None:
    """Rebuild the through-twelfth prefix once and reject all collisions."""

    try:
        selected_evidence = (
            build_twelfth_prefix_task_evidence()
            if evidence is None
            else evidence
        )
        validate_twelfth_prefix_task_evidence(selected_evidence)
    except (AttributeError, TypeError, ValueError) as exc:
        raise ThirteenthTrancheRegistryError(
            "through-twelfth predecessor evidence could not be established"
        ) from exc
    if (
        selected_evidence.total_task_count != TWELFTH_PREFIX_TASK_COUNT
        or selected_evidence.terminal_registry_sha256
        != FROZEN_TWELFTH_REGISTRY_SHA256
        or selected_evidence.terminal_cumulative_suite_sha256
        != FROZEN_TWELFTH_CUMULATIVE_SUITE_SHA256
    ):
        raise ThirteenthTrancheRegistryError(
            "the live twelfth prefix differs from its frozen identity"
        )
    selected_tasks = _validate_added_tasks(tasks)
    all_tasks = (*selected_evidence.tasks, *selected_tasks)
    if (
        len(all_tasks) != THIRTEENTH_TRANCHE_CUMULATIVE_TASK_COUNT
        or len({task.task_id for task in all_tasks}) != len(all_tasks)
        or len({task.task_contract_sha256 for task in all_tasks})
        != len(all_tasks)
        or len({task.graph_sha256 for task in all_tasks}) != len(all_tasks)
    ):
        raise ThirteenthTrancheRegistryError(
            "thirteenth-tranche tasks collide with a frozen predecessor"
        )
    if any(
        task is predecessor
        for task in selected_tasks
        for predecessor in selected_evidence.tasks
    ):
        raise ThirteenthTrancheRegistryError(
            "thirteenth-tranche tasks must be freshly owned additions"
        )


def build_thirteenth_tranche_task_registry(
    predecessor_evidence: TwelfthPrefixTaskEvidence | None = None,
) -> ThirteenthTrancheTaskRegistry:
    """Build the thirteenth registry, optionally reusing one exact prefix."""

    tasks = build_thirteenth_tranche_added_tasks()
    _validate_live_base_and_global_uniqueness(
        tasks, predecessor_evidence
    )
    registry_sha256 = compute_thirteenth_tranche_registry_sha256(tasks)
    cumulative_suite_sha256 = (
        compute_thirteenth_tranche_cumulative_suite_sha256(
            tasks,
            registry_sha256,
        )
    )
    return ThirteenthTrancheTaskRegistry(
        added_tasks=tasks,
        registry_sha256=registry_sha256,
        cumulative_suite_sha256=cumulative_suite_sha256,
    )


__all__ = [
    "FROZEN_THIRTEENTH_CUMULATIVE_SUITE_SHA256",
    "FROZEN_THIRTEENTH_REGISTRY_SHA256",
    "FROZEN_TWELFTH_CUMULATIVE_SUITE_SHA256",
    "FROZEN_TWELFTH_REGISTRY_SHA256",
    "THIRTEENTH_TRANCHE_ADDED_TASK_COUNT",
    "THIRTEENTH_TRANCHE_CUMULATIVE_TASK_COUNT",
    "THIRTEENTH_TRANCHE_FAMILY_ORDER",
    "THIRTEENTH_TRANCHE_REGISTRY_SCHEMA_VERSION",
    "THIRTEENTH_TRANCHE_REGISTRY_VERSION",
    "ThirteenthTrancheRegistryError",
    "ThirteenthTrancheTask",
    "ThirteenthTrancheTaskRegistry",
    "build_thirteenth_tranche_added_tasks",
    "build_thirteenth_tranche_task_registry",
    "compute_thirteenth_tranche_cumulative_suite_sha256",
    "compute_thirteenth_tranche_registry_sha256",
    "validate_thirteenth_tranche_task_registry",
]
