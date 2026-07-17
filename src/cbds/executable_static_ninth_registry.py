"""Additive registry for the hardlink-deduplicated-mirror family.

The first eight executable-static registries remain immutable.  This module
binds the exact family-local hardlink contract as a ninth 20-task addition and
uses the hash-neutral linear predecessor evidence path so each earlier task is
rebuilt once.  The record is public method-development metadata only: it
grants no execution, model-selection, scored-evaluation, or claim authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Final, TypeAlias

from .executable_fixture_profiles import PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
from .executable_hardlink_deduplicated_mirror import (
    HARDLINK_DEDUPLICATED_MIRROR_EQUIVALENCE_KEYS,
    HARDLINK_DEDUPLICATED_MIRROR_OWNER_POLICIES,
    HardlinkDeduplicatedMirrorTask,
    build_hardlink_deduplicated_mirror_tasks,
)
from .executable_linear_predecessor_evidence import (
    FROZEN_PREDECESSOR_CUMULATIVE_SUITE_SHA256,
    FROZEN_PREDECESSOR_REGISTRY_SHA256,
    LINEAR_PREDECESSOR_TASK_COUNT,
    LinearTaskPredecessorEvidence,
    build_linear_task_predecessor_evidence,
    validate_linear_task_predecessor_evidence,
)
from .executable_static_types import domain_sha256


NINTH_TRANCHE_REGISTRY_SCHEMA_VERSION: Final[str] = "1.0.0"
NINTH_TRANCHE_REGISTRY_VERSION: Final[str] = "1.0.0"
NINTH_TRANCHE_ADDED_TASK_COUNT: Final[int] = 20
NINTH_TRANCHE_CUMULATIVE_TASK_COUNT: Final[int] = 360
NINTH_TRANCHE_FAMILY_ORDER: Final[tuple[str, ...]] = (
    "hardlink-deduplicated-mirror",
)

FROZEN_EIGHTH_ADDED_REGISTRY_SHA256: Final[str] = (
    "8ef6879c5b6f4198c1b0ff2acfcffe89b6cbdd418a9aa2af2eefedfb12994736"
)
FROZEN_EIGHTH_CUMULATIVE_SUITE_SHA256: Final[str] = (
    "b22742179e3ce3b7331469de9db0a75ddbae81a3340e2b814c8a7ab34233f0f0"
)

NinthTrancheTask: TypeAlias = HardlinkDeduplicatedMirrorTask
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")


class NinthTrancheRegistryError(ValueError):
    """Raised when the ninth additive registry is not reproducible."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def build_ninth_tranche_added_tasks() -> tuple[NinthTrancheTask, ...]:
    """Build the exact family-local 20-task grid in canonical order."""

    tasks = build_hardlink_deduplicated_mirror_tasks()
    _validate_added_tasks(tasks)
    return tasks


def _validate_added_tasks(
    tasks: object,
) -> tuple[NinthTrancheTask, ...]:
    if (
        type(tasks) is not tuple
        or len(tasks) != NINTH_TRANCHE_ADDED_TASK_COUNT
        or any(type(task) is not HardlinkDeduplicatedMirrorTask for task in tasks)
    ):
        raise NinthTrancheRegistryError(
            "ninth tranche requires exactly 20 exact "
            "HardlinkDeduplicatedMirrorTask values"
        )
    selected = tasks
    try:
        for task in selected:
            task.__post_init__()
    except (AttributeError, TypeError, ValueError) as exc:
        raise NinthTrancheRegistryError(
            "ninth-tranche task validation failed"
        ) from exc

    expected_grid = tuple(
        (equivalence_key, owner_policy)
        for equivalence_key in HARDLINK_DEDUPLICATED_MIRROR_EQUIVALENCE_KEYS
        for owner_policy in HARDLINK_DEDUPLICATED_MIRROR_OWNER_POLICIES
    )
    observed_grid = tuple(
        (
            task.parameters.equivalence_key,
            task.parameters.owner_policy,
        )
        for task in selected
    )
    if observed_grid != expected_grid:
        raise NinthTrancheRegistryError(
            "ninth-tranche parameter grid is incomplete or out of order"
        )
    if (
        len({task.task_id for task in selected})
        != NINTH_TRANCHE_ADDED_TASK_COUNT
        or len({task.task_contract_sha256 for task in selected})
        != NINTH_TRANCHE_ADDED_TASK_COUNT
        or len({task.graph_sha256 for task in selected})
        != NINTH_TRANCHE_ADDED_TASK_COUNT
        or any(
            len(task.fixtures) != len(PUBLIC_DEVELOPMENT_FIXTURE_PROFILES)
            for task in selected
        )
    ):
        raise NinthTrancheRegistryError(
            "ninth-tranche task identities are not unique"
        )
    return selected


def _registry_payload(
    tasks: tuple[NinthTrancheTask, ...],
) -> dict[str, object]:
    selected = _validate_added_tasks(tasks)
    return {
        "schema_version": NINTH_TRANCHE_REGISTRY_SCHEMA_VERSION,
        "registry_version": NINTH_TRANCHE_REGISTRY_VERSION,
        "record_type": "cbds.executable-static-ninth-tranche-registry",
        "base_added_registry_sha256": FROZEN_EIGHTH_ADDED_REGISTRY_SHA256,
        "base_cumulative_suite_sha256": (
            FROZEN_EIGHTH_CUMULATIVE_SUITE_SHA256
        ),
        "base_cumulative_task_count": LINEAR_PREDECESSOR_TASK_COUNT,
        "added_task_count": NINTH_TRANCHE_ADDED_TASK_COUNT,
        "cumulative_task_count": NINTH_TRANCHE_CUMULATIVE_TASK_COUNT,
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


def compute_ninth_tranche_registry_sha256(
    tasks: tuple[NinthTrancheTask, ...],
) -> str:
    return domain_sha256(
        "cbds.executable-static.ninth-tranche-registry.v1",
        _registry_payload(tasks),
    )


def compute_ninth_tranche_cumulative_suite_sha256(
    tasks: tuple[NinthTrancheTask, ...],
    registry_sha256: str,
) -> str:
    _validate_added_tasks(tasks)
    if not _is_sha256(registry_sha256):
        raise NinthTrancheRegistryError(
            "ninth-tranche registry digest is invalid"
        )
    if registry_sha256 != compute_ninth_tranche_registry_sha256(tasks):
        raise NinthTrancheRegistryError(
            "registry digest does not bind the ninth-tranche tasks"
        )
    return domain_sha256(
        "cbds.executable-static.ninth-tranche-cumulative-suite.v1",
        {
            "base_cumulative_suite_sha256": (
                FROZEN_EIGHTH_CUMULATIVE_SUITE_SHA256
            ),
            "added_registry_sha256": registry_sha256,
            "cumulative_task_count": NINTH_TRANCHE_CUMULATIVE_TASK_COUNT,
        },
    )


@dataclass(frozen=True, slots=True)
class NinthTrancheTaskRegistry:
    added_tasks: tuple[NinthTrancheTask, ...]
    registry_sha256: str
    cumulative_suite_sha256: str
    schema_version: str = NINTH_TRANCHE_REGISTRY_SCHEMA_VERSION
    registry_version: str = NINTH_TRANCHE_REGISTRY_VERSION
    base_added_registry_sha256: str = FROZEN_EIGHTH_ADDED_REGISTRY_SHA256
    base_cumulative_suite_sha256: str = (
        FROZEN_EIGHTH_CUMULATIVE_SUITE_SHA256
    )
    public_method_development: bool = True
    sealed: bool = False
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_ninth_tranche_task_registry(self)

    def to_hash_only_record(self) -> dict[str, object]:
        validate_ninth_tranche_task_registry(self)
        return {
            "schema_version": self.schema_version,
            "registry_version": self.registry_version,
            "record_type": (
                "cbds.executable-static-ninth-tranche-registry-hashes"
            ),
            "base_added_registry_sha256": self.base_added_registry_sha256,
            "base_cumulative_suite_sha256": (
                self.base_cumulative_suite_sha256
            ),
            "base_cumulative_task_count": LINEAR_PREDECESSOR_TASK_COUNT,
            "added_task_count": len(self.added_tasks),
            "cumulative_task_count": NINTH_TRANCHE_CUMULATIVE_TASK_COUNT,
            "family_task_counts": {
                family: sum(
                    task.family_id == family for task in self.added_tasks
                )
                for family in NINTH_TRANCHE_FAMILY_ORDER
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


def validate_ninth_tranche_task_registry(
    registry: NinthTrancheTaskRegistry,
) -> None:
    if type(registry) is not NinthTrancheTaskRegistry:
        raise NinthTrancheRegistryError(
            "registry must be an exact NinthTrancheTaskRegistry"
        )
    if (
        type(registry.schema_version) is not str
        or registry.schema_version != NINTH_TRANCHE_REGISTRY_SCHEMA_VERSION
        or type(registry.registry_version) is not str
        or registry.registry_version != NINTH_TRANCHE_REGISTRY_VERSION
        or not _is_sha256(registry.base_added_registry_sha256)
        or registry.base_added_registry_sha256
        != FROZEN_EIGHTH_ADDED_REGISTRY_SHA256
        or not _is_sha256(registry.base_cumulative_suite_sha256)
        or registry.base_cumulative_suite_sha256
        != FROZEN_EIGHTH_CUMULATIVE_SUITE_SHA256
        or not _is_sha256(registry.registry_sha256)
        or not _is_sha256(registry.cumulative_suite_sha256)
        or registry.public_method_development is not True
        or registry.sealed is not False
        or registry.candidate_execution_authorized is not False
        or registry.model_selection_eligible is not False
        or registry.claim_authorized is not False
    ):
        raise NinthTrancheRegistryError(
            "ninth-tranche registry metadata is invalid"
        )
    tasks = _validate_added_tasks(registry.added_tasks)
    expected_registry = compute_ninth_tranche_registry_sha256(tasks)
    if registry.registry_sha256 != expected_registry:
        raise NinthTrancheRegistryError(
            "ninth-tranche registry digest is invalid"
        )
    expected_suite = compute_ninth_tranche_cumulative_suite_sha256(
        tasks,
        expected_registry,
    )
    if registry.cumulative_suite_sha256 != expected_suite:
        raise NinthTrancheRegistryError(
            "ninth-tranche cumulative suite digest is invalid"
        )


def _validate_live_base_and_global_uniqueness(
    tasks: tuple[NinthTrancheTask, ...],
    evidence: LinearTaskPredecessorEvidence | None = None,
) -> None:
    """Rebuild each predecessor once and reject global identity collisions."""

    try:
        selected_evidence = (
            build_linear_task_predecessor_evidence()
            if evidence is None
            else evidence
        )
        validate_linear_task_predecessor_evidence(selected_evidence)
    except (AttributeError, TypeError, ValueError) as exc:
        raise NinthTrancheRegistryError(
            "linear predecessor evidence could not be established"
        ) from exc
    if (
        selected_evidence.total_task_count != LINEAR_PREDECESSOR_TASK_COUNT
        or selected_evidence.terminal_registry_sha256
        != FROZEN_EIGHTH_ADDED_REGISTRY_SHA256
        or selected_evidence.terminal_cumulative_suite_sha256
        != FROZEN_EIGHTH_CUMULATIVE_SUITE_SHA256
        or FROZEN_PREDECESSOR_REGISTRY_SHA256[-1]
        != FROZEN_EIGHTH_ADDED_REGISTRY_SHA256
        or FROZEN_PREDECESSOR_CUMULATIVE_SUITE_SHA256[-1]
        != FROZEN_EIGHTH_CUMULATIVE_SUITE_SHA256
    ):
        raise NinthTrancheRegistryError(
            "a live predecessor registry differs from its frozen identity"
        )
    all_tasks = (
        *selected_evidence.tasks,
        *_validate_added_tasks(tasks),
    )
    if (
        len(all_tasks) != NINTH_TRANCHE_CUMULATIVE_TASK_COUNT
        or len({task.task_id for task in all_tasks}) != len(all_tasks)
        or len({task.task_contract_sha256 for task in all_tasks})
        != len(all_tasks)
        or len({task.graph_sha256 for task in all_tasks}) != len(all_tasks)
    ):
        raise NinthTrancheRegistryError(
            "ninth-tranche tasks collide with a frozen predecessor"
        )


def build_ninth_tranche_task_registry(
    predecessor_evidence: LinearTaskPredecessorEvidence | None = None,
) -> NinthTrancheTaskRegistry:
    """Build the ninth registry, optionally reusing exact linear evidence."""

    tasks = build_ninth_tranche_added_tasks()
    _validate_live_base_and_global_uniqueness(
        tasks, predecessor_evidence
    )
    registry_sha256 = compute_ninth_tranche_registry_sha256(tasks)
    cumulative_suite_sha256 = compute_ninth_tranche_cumulative_suite_sha256(
        tasks,
        registry_sha256,
    )
    return NinthTrancheTaskRegistry(
        added_tasks=tasks,
        registry_sha256=registry_sha256,
        cumulative_suite_sha256=cumulative_suite_sha256,
    )


__all__ = [
    "FROZEN_EIGHTH_ADDED_REGISTRY_SHA256",
    "FROZEN_EIGHTH_CUMULATIVE_SUITE_SHA256",
    "NINTH_TRANCHE_ADDED_TASK_COUNT",
    "NINTH_TRANCHE_CUMULATIVE_TASK_COUNT",
    "NINTH_TRANCHE_FAMILY_ORDER",
    "NINTH_TRANCHE_REGISTRY_SCHEMA_VERSION",
    "NINTH_TRANCHE_REGISTRY_VERSION",
    "NinthTrancheRegistryError",
    "NinthTrancheTaskRegistry",
    "build_ninth_tranche_added_tasks",
    "build_ninth_tranche_task_registry",
    "compute_ninth_tranche_cumulative_suite_sha256",
    "compute_ninth_tranche_registry_sha256",
    "validate_ninth_tranche_task_registry",
]
