"""Additive registry for compressed archive roundtrip verification.

The first nine executable-static registries remain immutable.  This module
binds the exact family-local compressed-archive contract as a tenth 20-task
addition.  Its predecessor is the non-recursive, hash-neutral through-ninth
evidence snapshot: every historical task is built once per call, and no
historical publication builder is called recursively.

This record is public method-development metadata only.  It grants no
candidate execution, model-selection, scored-evaluation, or claim authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Final, TypeAlias

from .executable_compressed_archive_roundtrip_verify import (
    COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_COMPRESSION_FORMATS,
    COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_VERIFICATION_POLICIES,
    CompressedArchiveRoundtripVerifyTask,
    build_compressed_archive_roundtrip_verify_tasks,
)
from .executable_fixture_profiles import PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
from .executable_ninth_predecessor_evidence import (
    FROZEN_NINTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_NINTH_REGISTRY_SHA256,
    NINTH_PREFIX_TASK_COUNT,
    NinthPrefixTaskEvidence,
    build_ninth_prefix_task_evidence,
    validate_ninth_prefix_task_evidence,
)
from .executable_static_types import domain_sha256


TENTH_TRANCHE_REGISTRY_SCHEMA_VERSION: Final[str] = "1.0.0"
TENTH_TRANCHE_REGISTRY_VERSION: Final[str] = "1.0.0"
TENTH_TRANCHE_ADDED_TASK_COUNT: Final[int] = 20
TENTH_TRANCHE_CUMULATIVE_TASK_COUNT: Final[int] = 380
TENTH_TRANCHE_FAMILY_ORDER: Final[tuple[str, ...]] = (
    "compressed-archive-roundtrip-verify",
)

TenthTrancheTask: TypeAlias = CompressedArchiveRoundtripVerifyTask
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")


class TenthTrancheRegistryError(ValueError):
    """Raised when the tenth additive registry is not reproducible."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def build_tenth_tranche_added_tasks() -> tuple[TenthTrancheTask, ...]:
    """Build the exact family-local 20-task grid in canonical order."""

    tasks = build_compressed_archive_roundtrip_verify_tasks()
    _validate_added_tasks(tasks)
    return tasks


def _validate_added_tasks(
    tasks: object,
) -> tuple[TenthTrancheTask, ...]:
    if (
        type(tasks) is not tuple
        or len(tasks) != TENTH_TRANCHE_ADDED_TASK_COUNT
        or any(
            type(task) is not CompressedArchiveRoundtripVerifyTask
            for task in tasks
        )
    ):
        raise TenthTrancheRegistryError(
            "tenth tranche requires exactly 20 exact "
            "CompressedArchiveRoundtripVerifyTask values"
        )
    selected = tasks
    try:
        for task in selected:
            task.__post_init__()
    except (AttributeError, TypeError, ValueError) as exc:
        raise TenthTrancheRegistryError(
            "tenth-tranche task validation failed"
        ) from exc

    expected_grid = tuple(
        (compression_format, verification_policy)
        for compression_format in (
            COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_COMPRESSION_FORMATS
        )
        for verification_policy in (
            COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_VERIFICATION_POLICIES
        )
    )
    observed_grid = tuple(
        (
            task.parameters.compression_format,
            task.parameters.verification_policy,
        )
        for task in selected
    )
    if observed_grid != expected_grid:
        raise TenthTrancheRegistryError(
            "tenth-tranche parameter grid is incomplete or out of order"
        )
    if (
        len({task.task_id for task in selected})
        != TENTH_TRANCHE_ADDED_TASK_COUNT
        or len({task.task_contract_sha256 for task in selected})
        != TENTH_TRANCHE_ADDED_TASK_COUNT
        or len({task.graph_sha256 for task in selected})
        != TENTH_TRANCHE_ADDED_TASK_COUNT
        or any(
            len(task.fixtures) != len(PUBLIC_DEVELOPMENT_FIXTURE_PROFILES)
            for task in selected
        )
    ):
        raise TenthTrancheRegistryError(
            "tenth-tranche task identities are not unique"
        )
    return selected


def _registry_payload(
    tasks: tuple[TenthTrancheTask, ...],
) -> dict[str, object]:
    selected = _validate_added_tasks(tasks)
    return {
        "schema_version": TENTH_TRANCHE_REGISTRY_SCHEMA_VERSION,
        "registry_version": TENTH_TRANCHE_REGISTRY_VERSION,
        "record_type": "cbds.executable-static-tenth-tranche-registry",
        "base_added_registry_sha256": FROZEN_NINTH_REGISTRY_SHA256,
        "base_cumulative_suite_sha256": (
            FROZEN_NINTH_CUMULATIVE_SUITE_SHA256
        ),
        "base_cumulative_task_count": NINTH_PREFIX_TASK_COUNT,
        "added_task_count": TENTH_TRANCHE_ADDED_TASK_COUNT,
        "cumulative_task_count": TENTH_TRANCHE_CUMULATIVE_TASK_COUNT,
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


def compute_tenth_tranche_registry_sha256(
    tasks: tuple[TenthTrancheTask, ...],
) -> str:
    return domain_sha256(
        "cbds.executable-static.tenth-tranche-registry.v1",
        _registry_payload(tasks),
    )


def compute_tenth_tranche_cumulative_suite_sha256(
    tasks: tuple[TenthTrancheTask, ...],
    registry_sha256: str,
) -> str:
    _validate_added_tasks(tasks)
    if not _is_sha256(registry_sha256):
        raise TenthTrancheRegistryError(
            "tenth-tranche registry digest is invalid"
        )
    if registry_sha256 != compute_tenth_tranche_registry_sha256(tasks):
        raise TenthTrancheRegistryError(
            "registry digest does not bind the tenth-tranche tasks"
        )
    return domain_sha256(
        "cbds.executable-static.tenth-tranche-cumulative-suite.v1",
        {
            "base_cumulative_suite_sha256": (
                FROZEN_NINTH_CUMULATIVE_SUITE_SHA256
            ),
            "added_registry_sha256": registry_sha256,
            "cumulative_task_count": TENTH_TRANCHE_CUMULATIVE_TASK_COUNT,
        },
    )


@dataclass(frozen=True, slots=True)
class TenthTrancheTaskRegistry:
    added_tasks: tuple[TenthTrancheTask, ...]
    registry_sha256: str
    cumulative_suite_sha256: str
    schema_version: str = TENTH_TRANCHE_REGISTRY_SCHEMA_VERSION
    registry_version: str = TENTH_TRANCHE_REGISTRY_VERSION
    base_added_registry_sha256: str = FROZEN_NINTH_REGISTRY_SHA256
    base_cumulative_suite_sha256: str = (
        FROZEN_NINTH_CUMULATIVE_SUITE_SHA256
    )
    public_method_development: bool = True
    sealed: bool = False
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_tenth_tranche_task_registry(self)

    def to_hash_only_record(self) -> dict[str, object]:
        validate_tenth_tranche_task_registry(self)
        return {
            "schema_version": self.schema_version,
            "registry_version": self.registry_version,
            "record_type": (
                "cbds.executable-static-tenth-tranche-registry-hashes"
            ),
            "base_added_registry_sha256": self.base_added_registry_sha256,
            "base_cumulative_suite_sha256": (
                self.base_cumulative_suite_sha256
            ),
            "base_cumulative_task_count": NINTH_PREFIX_TASK_COUNT,
            "added_task_count": len(self.added_tasks),
            "cumulative_task_count": TENTH_TRANCHE_CUMULATIVE_TASK_COUNT,
            "family_task_counts": {
                family: sum(
                    task.family_id == family for task in self.added_tasks
                )
                for family in TENTH_TRANCHE_FAMILY_ORDER
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


def validate_tenth_tranche_task_registry(
    registry: TenthTrancheTaskRegistry,
) -> None:
    if type(registry) is not TenthTrancheTaskRegistry:
        raise TenthTrancheRegistryError(
            "registry must be an exact TenthTrancheTaskRegistry"
        )
    if (
        type(registry.schema_version) is not str
        or registry.schema_version != TENTH_TRANCHE_REGISTRY_SCHEMA_VERSION
        or type(registry.registry_version) is not str
        or registry.registry_version != TENTH_TRANCHE_REGISTRY_VERSION
        or not _is_sha256(registry.base_added_registry_sha256)
        or registry.base_added_registry_sha256
        != FROZEN_NINTH_REGISTRY_SHA256
        or not _is_sha256(registry.base_cumulative_suite_sha256)
        or registry.base_cumulative_suite_sha256
        != FROZEN_NINTH_CUMULATIVE_SUITE_SHA256
        or not _is_sha256(registry.registry_sha256)
        or not _is_sha256(registry.cumulative_suite_sha256)
        or registry.public_method_development is not True
        or registry.sealed is not False
        or registry.candidate_execution_authorized is not False
        or registry.model_selection_eligible is not False
        or registry.claim_authorized is not False
    ):
        raise TenthTrancheRegistryError(
            "tenth-tranche registry metadata is invalid"
        )
    tasks = _validate_added_tasks(registry.added_tasks)
    expected_registry = compute_tenth_tranche_registry_sha256(tasks)
    if registry.registry_sha256 != expected_registry:
        raise TenthTrancheRegistryError(
            "tenth-tranche registry digest is invalid"
        )
    expected_suite = compute_tenth_tranche_cumulative_suite_sha256(
        tasks,
        expected_registry,
    )
    if registry.cumulative_suite_sha256 != expected_suite:
        raise TenthTrancheRegistryError(
            "tenth-tranche cumulative suite digest is invalid"
        )


def _validate_live_base_and_global_uniqueness(
    tasks: tuple[TenthTrancheTask, ...],
    evidence: NinthPrefixTaskEvidence | None = None,
) -> None:
    """Rebuild the through-ninth prefix once and reject all collisions."""

    try:
        selected_evidence = (
            build_ninth_prefix_task_evidence()
            if evidence is None
            else evidence
        )
        validate_ninth_prefix_task_evidence(selected_evidence)
    except (AttributeError, TypeError, ValueError) as exc:
        raise TenthTrancheRegistryError(
            "through-ninth predecessor evidence could not be established"
        ) from exc
    if (
        selected_evidence.total_task_count != NINTH_PREFIX_TASK_COUNT
        or selected_evidence.terminal_registry_sha256
        != FROZEN_NINTH_REGISTRY_SHA256
        or selected_evidence.terminal_cumulative_suite_sha256
        != FROZEN_NINTH_CUMULATIVE_SUITE_SHA256
    ):
        raise TenthTrancheRegistryError(
            "the live ninth prefix differs from its frozen identity"
        )
    selected_tasks = _validate_added_tasks(tasks)
    all_tasks = (*selected_evidence.tasks, *selected_tasks)
    if (
        len(all_tasks) != TENTH_TRANCHE_CUMULATIVE_TASK_COUNT
        or len({task.task_id for task in all_tasks}) != len(all_tasks)
        or len({task.task_contract_sha256 for task in all_tasks})
        != len(all_tasks)
        or len({task.graph_sha256 for task in all_tasks}) != len(all_tasks)
    ):
        raise TenthTrancheRegistryError(
            "tenth-tranche tasks collide with a frozen predecessor"
        )
    if any(
        task is predecessor
        for task in selected_tasks
        for predecessor in selected_evidence.tasks
    ):
        raise TenthTrancheRegistryError(
            "tenth-tranche tasks must be freshly owned additions"
        )


def build_tenth_tranche_task_registry(
    predecessor_evidence: NinthPrefixTaskEvidence | None = None,
) -> TenthTrancheTaskRegistry:
    """Build the tenth registry, optionally reusing one exact prefix."""

    tasks = build_tenth_tranche_added_tasks()
    _validate_live_base_and_global_uniqueness(
        tasks, predecessor_evidence
    )
    registry_sha256 = compute_tenth_tranche_registry_sha256(tasks)
    cumulative_suite_sha256 = compute_tenth_tranche_cumulative_suite_sha256(
        tasks,
        registry_sha256,
    )
    return TenthTrancheTaskRegistry(
        added_tasks=tasks,
        registry_sha256=registry_sha256,
        cumulative_suite_sha256=cumulative_suite_sha256,
    )


__all__ = [
    "FROZEN_NINTH_CUMULATIVE_SUITE_SHA256",
    "FROZEN_NINTH_REGISTRY_SHA256",
    "TENTH_TRANCHE_ADDED_TASK_COUNT",
    "TENTH_TRANCHE_CUMULATIVE_TASK_COUNT",
    "TENTH_TRANCHE_FAMILY_ORDER",
    "TENTH_TRANCHE_REGISTRY_SCHEMA_VERSION",
    "TENTH_TRANCHE_REGISTRY_VERSION",
    "TenthTrancheRegistryError",
    "TenthTrancheTask",
    "TenthTrancheTaskRegistry",
    "build_tenth_tranche_added_tasks",
    "build_tenth_tranche_task_registry",
    "compute_tenth_tranche_cumulative_suite_sha256",
    "compute_tenth_tranche_registry_sha256",
    "validate_tenth_tranche_task_registry",
]
