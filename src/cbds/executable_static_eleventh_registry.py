"""Additive registry for checksum repair planning.

The first ten executable-static registries remain immutable.  This module
binds the exact family-local checksum-repair contract as an eleventh 20-task
addition.  Its predecessor is the non-recursive, hash-neutral through-tenth
evidence snapshot: every historical task is built once per call, and no
historical publication builder is called recursively.

This record is public method-development metadata only.  It grants no
candidate execution, model-selection, scored-evaluation, or claim authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Final, TypeAlias

from .executable_checksum_repair_plan import (
    CHECKSUM_REPAIR_PLAN_MANIFEST_LAYOUTS,
    CHECKSUM_REPAIR_PLAN_REPAIR_POLICIES,
    ChecksumRepairPlanTask,
    build_checksum_repair_plan_tasks,
)
from .executable_fixture_profiles import PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
from .executable_static_types import domain_sha256
from .executable_tenth_predecessor_evidence import (
    FROZEN_TENTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_TENTH_REGISTRY_SHA256,
    TENTH_PREFIX_TASK_COUNT,
    TenthPrefixTaskEvidence,
    build_tenth_prefix_task_evidence,
    validate_tenth_prefix_task_evidence,
)


ELEVENTH_TRANCHE_REGISTRY_SCHEMA_VERSION: Final[str] = "1.0.0"
ELEVENTH_TRANCHE_REGISTRY_VERSION: Final[str] = "1.0.0"
ELEVENTH_TRANCHE_ADDED_TASK_COUNT: Final[int] = 20
ELEVENTH_TRANCHE_CUMULATIVE_TASK_COUNT: Final[int] = 400
ELEVENTH_TRANCHE_FAMILY_ORDER: Final[tuple[str, ...]] = (
    "checksum-repair-plan",
)

EleventhTrancheTask: TypeAlias = ChecksumRepairPlanTask
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")


class EleventhTrancheRegistryError(ValueError):
    """Raised when the eleventh additive registry is not reproducible."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def build_eleventh_tranche_added_tasks() -> tuple[
    EleventhTrancheTask, ...
]:
    """Build the exact family-local 20-task grid in canonical order."""

    tasks = build_checksum_repair_plan_tasks()
    _validate_added_tasks(tasks)
    return tasks


def _validate_added_tasks(
    tasks: object,
) -> tuple[EleventhTrancheTask, ...]:
    if (
        type(tasks) is not tuple
        or len(tasks) != ELEVENTH_TRANCHE_ADDED_TASK_COUNT
        or any(type(task) is not ChecksumRepairPlanTask for task in tasks)
    ):
        raise EleventhTrancheRegistryError(
            "eleventh tranche requires exactly 20 exact "
            "ChecksumRepairPlanTask values"
        )
    selected = tasks
    try:
        for task in selected:
            task.__post_init__()
    except (AttributeError, TypeError, ValueError) as exc:
        raise EleventhTrancheRegistryError(
            "eleventh-tranche task validation failed"
        ) from exc

    expected_grid = tuple(
        (manifest_layout, repair_policy)
        for manifest_layout in CHECKSUM_REPAIR_PLAN_MANIFEST_LAYOUTS
        for repair_policy in CHECKSUM_REPAIR_PLAN_REPAIR_POLICIES
    )
    observed_grid = tuple(
        (
            task.parameters.manifest_layout,
            task.parameters.repair_policy,
        )
        for task in selected
    )
    if observed_grid != expected_grid:
        raise EleventhTrancheRegistryError(
            "eleventh-tranche parameter grid is incomplete or out of order"
        )
    if (
        len({task.task_id for task in selected})
        != ELEVENTH_TRANCHE_ADDED_TASK_COUNT
        or len({task.task_contract_sha256 for task in selected})
        != ELEVENTH_TRANCHE_ADDED_TASK_COUNT
        or len({task.graph_sha256 for task in selected})
        != ELEVENTH_TRANCHE_ADDED_TASK_COUNT
        or any(
            len(task.fixtures) != len(PUBLIC_DEVELOPMENT_FIXTURE_PROFILES)
            for task in selected
        )
    ):
        raise EleventhTrancheRegistryError(
            "eleventh-tranche task identities are not unique"
        )
    return selected


def _registry_payload(
    tasks: tuple[EleventhTrancheTask, ...],
) -> dict[str, object]:
    selected = _validate_added_tasks(tasks)
    return {
        "schema_version": ELEVENTH_TRANCHE_REGISTRY_SCHEMA_VERSION,
        "registry_version": ELEVENTH_TRANCHE_REGISTRY_VERSION,
        "record_type": (
            "cbds.executable-static-eleventh-tranche-registry"
        ),
        "base_added_registry_sha256": FROZEN_TENTH_REGISTRY_SHA256,
        "base_cumulative_suite_sha256": (
            FROZEN_TENTH_CUMULATIVE_SUITE_SHA256
        ),
        "base_cumulative_task_count": TENTH_PREFIX_TASK_COUNT,
        "added_task_count": ELEVENTH_TRANCHE_ADDED_TASK_COUNT,
        "cumulative_task_count": ELEVENTH_TRANCHE_CUMULATIVE_TASK_COUNT,
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


def compute_eleventh_tranche_registry_sha256(
    tasks: tuple[EleventhTrancheTask, ...],
) -> str:
    return domain_sha256(
        "cbds.executable-static.eleventh-tranche-registry.v1",
        _registry_payload(tasks),
    )


def compute_eleventh_tranche_cumulative_suite_sha256(
    tasks: tuple[EleventhTrancheTask, ...],
    registry_sha256: str,
) -> str:
    _validate_added_tasks(tasks)
    if not _is_sha256(registry_sha256):
        raise EleventhTrancheRegistryError(
            "eleventh-tranche registry digest is invalid"
        )
    if registry_sha256 != compute_eleventh_tranche_registry_sha256(tasks):
        raise EleventhTrancheRegistryError(
            "registry digest does not bind the eleventh-tranche tasks"
        )
    return domain_sha256(
        "cbds.executable-static.eleventh-tranche-cumulative-suite.v1",
        {
            "base_cumulative_suite_sha256": (
                FROZEN_TENTH_CUMULATIVE_SUITE_SHA256
            ),
            "added_registry_sha256": registry_sha256,
            "cumulative_task_count": (
                ELEVENTH_TRANCHE_CUMULATIVE_TASK_COUNT
            ),
        },
    )


@dataclass(frozen=True, slots=True)
class EleventhTrancheTaskRegistry:
    added_tasks: tuple[EleventhTrancheTask, ...]
    registry_sha256: str
    cumulative_suite_sha256: str
    schema_version: str = ELEVENTH_TRANCHE_REGISTRY_SCHEMA_VERSION
    registry_version: str = ELEVENTH_TRANCHE_REGISTRY_VERSION
    base_added_registry_sha256: str = FROZEN_TENTH_REGISTRY_SHA256
    base_cumulative_suite_sha256: str = (
        FROZEN_TENTH_CUMULATIVE_SUITE_SHA256
    )
    public_method_development: bool = True
    sealed: bool = False
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_eleventh_tranche_task_registry(self)

    def to_hash_only_record(self) -> dict[str, object]:
        validate_eleventh_tranche_task_registry(self)
        return {
            "schema_version": self.schema_version,
            "registry_version": self.registry_version,
            "record_type": (
                "cbds.executable-static-eleventh-tranche-registry-hashes"
            ),
            "base_added_registry_sha256": (
                self.base_added_registry_sha256
            ),
            "base_cumulative_suite_sha256": (
                self.base_cumulative_suite_sha256
            ),
            "base_cumulative_task_count": TENTH_PREFIX_TASK_COUNT,
            "added_task_count": len(self.added_tasks),
            "cumulative_task_count": (
                ELEVENTH_TRANCHE_CUMULATIVE_TASK_COUNT
            ),
            "family_task_counts": {
                family: sum(
                    task.family_id == family for task in self.added_tasks
                )
                for family in ELEVENTH_TRANCHE_FAMILY_ORDER
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


def validate_eleventh_tranche_task_registry(
    registry: EleventhTrancheTaskRegistry,
) -> None:
    if type(registry) is not EleventhTrancheTaskRegistry:
        raise EleventhTrancheRegistryError(
            "registry must be an exact EleventhTrancheTaskRegistry"
        )
    if (
        type(registry.schema_version) is not str
        or registry.schema_version
        != ELEVENTH_TRANCHE_REGISTRY_SCHEMA_VERSION
        or type(registry.registry_version) is not str
        or registry.registry_version
        != ELEVENTH_TRANCHE_REGISTRY_VERSION
        or not _is_sha256(registry.base_added_registry_sha256)
        or registry.base_added_registry_sha256
        != FROZEN_TENTH_REGISTRY_SHA256
        or not _is_sha256(registry.base_cumulative_suite_sha256)
        or registry.base_cumulative_suite_sha256
        != FROZEN_TENTH_CUMULATIVE_SUITE_SHA256
        or not _is_sha256(registry.registry_sha256)
        or not _is_sha256(registry.cumulative_suite_sha256)
        or registry.public_method_development is not True
        or registry.sealed is not False
        or registry.candidate_execution_authorized is not False
        or registry.model_selection_eligible is not False
        or registry.claim_authorized is not False
    ):
        raise EleventhTrancheRegistryError(
            "eleventh-tranche registry metadata is invalid"
        )
    tasks = _validate_added_tasks(registry.added_tasks)
    expected_registry = compute_eleventh_tranche_registry_sha256(tasks)
    if registry.registry_sha256 != expected_registry:
        raise EleventhTrancheRegistryError(
            "eleventh-tranche registry digest is invalid"
        )
    expected_suite = compute_eleventh_tranche_cumulative_suite_sha256(
        tasks,
        expected_registry,
    )
    if registry.cumulative_suite_sha256 != expected_suite:
        raise EleventhTrancheRegistryError(
            "eleventh-tranche cumulative suite digest is invalid"
        )


def _validate_live_base_and_global_uniqueness(
    tasks: tuple[EleventhTrancheTask, ...],
    evidence: TenthPrefixTaskEvidence | None = None,
) -> None:
    """Rebuild the through-tenth prefix once and reject all collisions."""

    try:
        selected_evidence = (
            build_tenth_prefix_task_evidence()
            if evidence is None
            else evidence
        )
        validate_tenth_prefix_task_evidence(selected_evidence)
    except (AttributeError, TypeError, ValueError) as exc:
        raise EleventhTrancheRegistryError(
            "through-tenth predecessor evidence could not be established"
        ) from exc
    if (
        selected_evidence.total_task_count != TENTH_PREFIX_TASK_COUNT
        or selected_evidence.terminal_registry_sha256
        != FROZEN_TENTH_REGISTRY_SHA256
        or selected_evidence.terminal_cumulative_suite_sha256
        != FROZEN_TENTH_CUMULATIVE_SUITE_SHA256
    ):
        raise EleventhTrancheRegistryError(
            "the live tenth prefix differs from its frozen identity"
        )
    selected_tasks = _validate_added_tasks(tasks)
    all_tasks = (*selected_evidence.tasks, *selected_tasks)
    if (
        len(all_tasks) != ELEVENTH_TRANCHE_CUMULATIVE_TASK_COUNT
        or len({task.task_id for task in all_tasks}) != len(all_tasks)
        or len({task.task_contract_sha256 for task in all_tasks})
        != len(all_tasks)
        or len({task.graph_sha256 for task in all_tasks}) != len(all_tasks)
    ):
        raise EleventhTrancheRegistryError(
            "eleventh-tranche tasks collide with a frozen predecessor"
        )
    if any(
        task is predecessor
        for task in selected_tasks
        for predecessor in selected_evidence.tasks
    ):
        raise EleventhTrancheRegistryError(
            "eleventh-tranche tasks must be freshly owned additions"
        )


def build_eleventh_tranche_task_registry(
    predecessor_evidence: TenthPrefixTaskEvidence | None = None,
) -> EleventhTrancheTaskRegistry:
    """Build the eleventh registry, optionally reusing one exact prefix."""

    tasks = build_eleventh_tranche_added_tasks()
    _validate_live_base_and_global_uniqueness(
        tasks, predecessor_evidence
    )
    registry_sha256 = compute_eleventh_tranche_registry_sha256(tasks)
    cumulative_suite_sha256 = (
        compute_eleventh_tranche_cumulative_suite_sha256(
            tasks,
            registry_sha256,
        )
    )
    return EleventhTrancheTaskRegistry(
        added_tasks=tasks,
        registry_sha256=registry_sha256,
        cumulative_suite_sha256=cumulative_suite_sha256,
    )


__all__ = [
    "ELEVENTH_TRANCHE_ADDED_TASK_COUNT",
    "ELEVENTH_TRANCHE_CUMULATIVE_TASK_COUNT",
    "ELEVENTH_TRANCHE_FAMILY_ORDER",
    "ELEVENTH_TRANCHE_REGISTRY_SCHEMA_VERSION",
    "ELEVENTH_TRANCHE_REGISTRY_VERSION",
    "FROZEN_TENTH_CUMULATIVE_SUITE_SHA256",
    "FROZEN_TENTH_REGISTRY_SHA256",
    "EleventhTrancheRegistryError",
    "EleventhTrancheTask",
    "EleventhTrancheTaskRegistry",
    "build_eleventh_tranche_added_tasks",
    "build_eleventh_tranche_task_registry",
    "compute_eleventh_tranche_cumulative_suite_sha256",
    "compute_eleventh_tranche_registry_sha256",
    "validate_eleventh_tranche_task_registry",
]
