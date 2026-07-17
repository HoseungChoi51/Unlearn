"""Additive registry for JSONL/CSV enrichment composition.

The first eleven executable-static registries remain immutable.  This module
binds the exact family-local enrichment contract as a twelfth 20-task
addition.  Its predecessor is the non-recursive, hash-neutral through-
eleventh evidence snapshot: every historical task is built once per call,
and no historical publication builder is called recursively.

This record is public method-development metadata only.  It grants no
candidate execution, model-selection, scored-evaluation, or claim authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Final, TypeAlias

from .executable_eleventh_predecessor_evidence import (
    ELEVENTH_PREFIX_TASK_COUNT,
    FROZEN_ELEVENTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_ELEVENTH_REGISTRY_SHA256,
    EleventhPrefixTaskEvidence,
    build_eleventh_prefix_task_evidence,
    validate_eleventh_prefix_task_evidence,
)
from .executable_fixture_profiles import PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
from .executable_jsonl_csv_enrichment_compose import (
    JSONL_CSV_ENRICHMENT_COMPOSE_JOIN_LAYOUTS,
    JSONL_CSV_ENRICHMENT_COMPOSE_MISSING_FIELD_POLICIES,
    JsonlCsvEnrichmentComposeTask,
    build_jsonl_csv_enrichment_compose_tasks,
)
from .executable_static_types import domain_sha256


TWELFTH_TRANCHE_REGISTRY_SCHEMA_VERSION: Final[str] = "1.0.0"
TWELFTH_TRANCHE_REGISTRY_VERSION: Final[str] = "1.0.0"
TWELFTH_TRANCHE_ADDED_TASK_COUNT: Final[int] = 20
TWELFTH_TRANCHE_CUMULATIVE_TASK_COUNT: Final[int] = 420
TWELFTH_TRANCHE_FAMILY_ORDER: Final[tuple[str, ...]] = (
    "jsonl-csv-enrichment-compose",
)
FROZEN_TWELFTH_REGISTRY_SHA256: Final[str] = (
    "a9733f220a7bdfb8435841eff875c9fd7b1dbadbee6de2d2aa0646750164f862"
)
FROZEN_TWELFTH_CUMULATIVE_SUITE_SHA256: Final[str] = (
    "32ec82cf193f364946def16462e52217176093d0a3f6399d574c9faf66eaa4a1"
)

TwelfthTrancheTask: TypeAlias = JsonlCsvEnrichmentComposeTask
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")


class TwelfthTrancheRegistryError(ValueError):
    """Raised when the twelfth additive registry is not reproducible."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def build_twelfth_tranche_added_tasks() -> tuple[
    TwelfthTrancheTask, ...
]:
    """Build the exact family-local 20-task grid in canonical order."""

    tasks = build_jsonl_csv_enrichment_compose_tasks()
    _validate_added_tasks(tasks)
    return tasks


def _validate_added_tasks(
    tasks: object,
) -> tuple[TwelfthTrancheTask, ...]:
    if (
        type(tasks) is not tuple
        or len(tasks) != TWELFTH_TRANCHE_ADDED_TASK_COUNT
        or any(
            type(task) is not JsonlCsvEnrichmentComposeTask
            for task in tasks
        )
    ):
        raise TwelfthTrancheRegistryError(
            "twelfth tranche requires exactly 20 exact "
            "JsonlCsvEnrichmentComposeTask values"
        )
    selected = tasks
    try:
        for task in selected:
            task.__post_init__()
    except (AttributeError, TypeError, ValueError) as exc:
        raise TwelfthTrancheRegistryError(
            "twelfth-tranche task validation failed"
        ) from exc

    expected_grid = tuple(
        (join_layout, missing_field_policy)
        for join_layout in JSONL_CSV_ENRICHMENT_COMPOSE_JOIN_LAYOUTS
        for missing_field_policy in (
            JSONL_CSV_ENRICHMENT_COMPOSE_MISSING_FIELD_POLICIES
        )
    )
    observed_grid = tuple(
        (
            task.parameters.join_layout,
            task.parameters.missing_field_policy,
        )
        for task in selected
    )
    if observed_grid != expected_grid:
        raise TwelfthTrancheRegistryError(
            "twelfth-tranche parameter grid is incomplete or out of order"
        )
    if (
        len({task.task_id for task in selected})
        != TWELFTH_TRANCHE_ADDED_TASK_COUNT
        or len({task.task_contract_sha256 for task in selected})
        != TWELFTH_TRANCHE_ADDED_TASK_COUNT
        or len({task.graph_sha256 for task in selected})
        != TWELFTH_TRANCHE_ADDED_TASK_COUNT
        or any(
            len(task.fixtures) != len(PUBLIC_DEVELOPMENT_FIXTURE_PROFILES)
            for task in selected
        )
    ):
        raise TwelfthTrancheRegistryError(
            "twelfth-tranche task identities are not unique"
        )
    return selected


def _registry_payload(
    tasks: tuple[TwelfthTrancheTask, ...],
) -> dict[str, object]:
    selected = _validate_added_tasks(tasks)
    return {
        "schema_version": TWELFTH_TRANCHE_REGISTRY_SCHEMA_VERSION,
        "registry_version": TWELFTH_TRANCHE_REGISTRY_VERSION,
        "record_type": (
            "cbds.executable-static-twelfth-tranche-registry"
        ),
        "base_added_registry_sha256": FROZEN_ELEVENTH_REGISTRY_SHA256,
        "base_cumulative_suite_sha256": (
            FROZEN_ELEVENTH_CUMULATIVE_SUITE_SHA256
        ),
        "base_cumulative_task_count": ELEVENTH_PREFIX_TASK_COUNT,
        "added_task_count": TWELFTH_TRANCHE_ADDED_TASK_COUNT,
        "cumulative_task_count": TWELFTH_TRANCHE_CUMULATIVE_TASK_COUNT,
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


def compute_twelfth_tranche_registry_sha256(
    tasks: tuple[TwelfthTrancheTask, ...],
) -> str:
    return domain_sha256(
        "cbds.executable-static.twelfth-tranche-registry.v1",
        _registry_payload(tasks),
    )


def compute_twelfth_tranche_cumulative_suite_sha256(
    tasks: tuple[TwelfthTrancheTask, ...],
    registry_sha256: str,
) -> str:
    _validate_added_tasks(tasks)
    if not _is_sha256(registry_sha256):
        raise TwelfthTrancheRegistryError(
            "twelfth-tranche registry digest is invalid"
        )
    if registry_sha256 != compute_twelfth_tranche_registry_sha256(tasks):
        raise TwelfthTrancheRegistryError(
            "registry digest does not bind the twelfth-tranche tasks"
        )
    return domain_sha256(
        "cbds.executable-static.twelfth-tranche-cumulative-suite.v1",
        {
            "base_cumulative_suite_sha256": (
                FROZEN_ELEVENTH_CUMULATIVE_SUITE_SHA256
            ),
            "added_registry_sha256": registry_sha256,
            "cumulative_task_count": (
                TWELFTH_TRANCHE_CUMULATIVE_TASK_COUNT
            ),
        },
    )


@dataclass(frozen=True, slots=True)
class TwelfthTrancheTaskRegistry:
    added_tasks: tuple[TwelfthTrancheTask, ...]
    registry_sha256: str
    cumulative_suite_sha256: str
    schema_version: str = TWELFTH_TRANCHE_REGISTRY_SCHEMA_VERSION
    registry_version: str = TWELFTH_TRANCHE_REGISTRY_VERSION
    base_added_registry_sha256: str = FROZEN_ELEVENTH_REGISTRY_SHA256
    base_cumulative_suite_sha256: str = (
        FROZEN_ELEVENTH_CUMULATIVE_SUITE_SHA256
    )
    public_method_development: bool = True
    sealed: bool = False
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_twelfth_tranche_task_registry(self)

    def to_hash_only_record(self) -> dict[str, object]:
        validate_twelfth_tranche_task_registry(self)
        return {
            "schema_version": self.schema_version,
            "registry_version": self.registry_version,
            "record_type": (
                "cbds.executable-static-twelfth-tranche-registry-hashes"
            ),
            "base_added_registry_sha256": (
                self.base_added_registry_sha256
            ),
            "base_cumulative_suite_sha256": (
                self.base_cumulative_suite_sha256
            ),
            "base_cumulative_task_count": ELEVENTH_PREFIX_TASK_COUNT,
            "added_task_count": len(self.added_tasks),
            "cumulative_task_count": (
                TWELFTH_TRANCHE_CUMULATIVE_TASK_COUNT
            ),
            "family_task_counts": {
                family: sum(
                    task.family_id == family for task in self.added_tasks
                )
                for family in TWELFTH_TRANCHE_FAMILY_ORDER
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


def validate_twelfth_tranche_task_registry(
    registry: TwelfthTrancheTaskRegistry,
) -> None:
    if type(registry) is not TwelfthTrancheTaskRegistry:
        raise TwelfthTrancheRegistryError(
            "registry must be an exact TwelfthTrancheTaskRegistry"
        )
    if (
        type(registry.schema_version) is not str
        or registry.schema_version
        != TWELFTH_TRANCHE_REGISTRY_SCHEMA_VERSION
        or type(registry.registry_version) is not str
        or registry.registry_version != TWELFTH_TRANCHE_REGISTRY_VERSION
        or not _is_sha256(registry.base_added_registry_sha256)
        or registry.base_added_registry_sha256
        != FROZEN_ELEVENTH_REGISTRY_SHA256
        or not _is_sha256(registry.base_cumulative_suite_sha256)
        or registry.base_cumulative_suite_sha256
        != FROZEN_ELEVENTH_CUMULATIVE_SUITE_SHA256
        or not _is_sha256(registry.registry_sha256)
        or not _is_sha256(registry.cumulative_suite_sha256)
        or registry.public_method_development is not True
        or registry.sealed is not False
        or registry.candidate_execution_authorized is not False
        or registry.model_selection_eligible is not False
        or registry.claim_authorized is not False
    ):
        raise TwelfthTrancheRegistryError(
            "twelfth-tranche registry metadata is invalid"
        )
    tasks = _validate_added_tasks(registry.added_tasks)
    expected_registry = compute_twelfth_tranche_registry_sha256(tasks)
    if (
        registry.registry_sha256 != expected_registry
        or registry.registry_sha256 != FROZEN_TWELFTH_REGISTRY_SHA256
    ):
        raise TwelfthTrancheRegistryError(
            "twelfth-tranche registry digest is invalid"
        )
    expected_suite = compute_twelfth_tranche_cumulative_suite_sha256(
        tasks,
        expected_registry,
    )
    if (
        registry.cumulative_suite_sha256 != expected_suite
        or registry.cumulative_suite_sha256
        != FROZEN_TWELFTH_CUMULATIVE_SUITE_SHA256
    ):
        raise TwelfthTrancheRegistryError(
            "twelfth-tranche cumulative suite digest is invalid"
        )


def _validate_live_base_and_global_uniqueness(
    tasks: tuple[TwelfthTrancheTask, ...],
    evidence: EleventhPrefixTaskEvidence | None = None,
) -> None:
    """Rebuild the through-eleventh prefix once and reject all collisions."""

    try:
        selected_evidence = (
            build_eleventh_prefix_task_evidence()
            if evidence is None
            else evidence
        )
        validate_eleventh_prefix_task_evidence(selected_evidence)
    except (AttributeError, TypeError, ValueError) as exc:
        raise TwelfthTrancheRegistryError(
            "through-eleventh predecessor evidence could not be established"
        ) from exc
    if (
        selected_evidence.total_task_count != ELEVENTH_PREFIX_TASK_COUNT
        or selected_evidence.terminal_registry_sha256
        != FROZEN_ELEVENTH_REGISTRY_SHA256
        or selected_evidence.terminal_cumulative_suite_sha256
        != FROZEN_ELEVENTH_CUMULATIVE_SUITE_SHA256
    ):
        raise TwelfthTrancheRegistryError(
            "the live eleventh prefix differs from its frozen identity"
        )
    selected_tasks = _validate_added_tasks(tasks)
    all_tasks = (*selected_evidence.tasks, *selected_tasks)
    if (
        len(all_tasks) != TWELFTH_TRANCHE_CUMULATIVE_TASK_COUNT
        or len({task.task_id for task in all_tasks}) != len(all_tasks)
        or len({task.task_contract_sha256 for task in all_tasks})
        != len(all_tasks)
        or len({task.graph_sha256 for task in all_tasks}) != len(all_tasks)
    ):
        raise TwelfthTrancheRegistryError(
            "twelfth-tranche tasks collide with a frozen predecessor"
        )
    if any(
        task is predecessor
        for task in selected_tasks
        for predecessor in selected_evidence.tasks
    ):
        raise TwelfthTrancheRegistryError(
            "twelfth-tranche tasks must be freshly owned additions"
        )


def build_twelfth_tranche_task_registry(
    predecessor_evidence: EleventhPrefixTaskEvidence | None = None,
) -> TwelfthTrancheTaskRegistry:
    """Build the twelfth registry, optionally reusing one exact prefix."""

    tasks = build_twelfth_tranche_added_tasks()
    _validate_live_base_and_global_uniqueness(
        tasks, predecessor_evidence
    )
    registry_sha256 = compute_twelfth_tranche_registry_sha256(tasks)
    cumulative_suite_sha256 = (
        compute_twelfth_tranche_cumulative_suite_sha256(
            tasks,
            registry_sha256,
        )
    )
    return TwelfthTrancheTaskRegistry(
        added_tasks=tasks,
        registry_sha256=registry_sha256,
        cumulative_suite_sha256=cumulative_suite_sha256,
    )


__all__ = [
    "FROZEN_ELEVENTH_CUMULATIVE_SUITE_SHA256",
    "FROZEN_ELEVENTH_REGISTRY_SHA256",
    "FROZEN_TWELFTH_CUMULATIVE_SUITE_SHA256",
    "FROZEN_TWELFTH_REGISTRY_SHA256",
    "TWELFTH_TRANCHE_ADDED_TASK_COUNT",
    "TWELFTH_TRANCHE_CUMULATIVE_TASK_COUNT",
    "TWELFTH_TRANCHE_FAMILY_ORDER",
    "TWELFTH_TRANCHE_REGISTRY_SCHEMA_VERSION",
    "TWELFTH_TRANCHE_REGISTRY_VERSION",
    "TwelfthTrancheRegistryError",
    "TwelfthTrancheTask",
    "TwelfthTrancheTaskRegistry",
    "build_twelfth_tranche_added_tasks",
    "build_twelfth_tranche_task_registry",
    "compute_twelfth_tranche_cumulative_suite_sha256",
    "compute_twelfth_tranche_registry_sha256",
    "validate_twelfth_tranche_task_registry",
]
