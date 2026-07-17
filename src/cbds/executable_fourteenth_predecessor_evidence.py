"""Hash-neutral non-recursive evidence through the fourteenth tranche.

The frozen ``executable_thirteenth_predecessor_evidence`` module deliberately
ends at the thirteenth tranche because its 440-task and 2,200-fixture
identities are inputs to the fourteenth registry and catalog.  This module
extends that evidence without changing it: one through-thirteenth task
snapshot is reused to build the fourteenth registry, and the same task
snapshot is then reused to build the through-thirteenth fixture evidence and
fourteenth local catalog.

The resulting prefix is suitable as predecessor evidence for a fifteenth
additive tranche.  No historical recursive publication builder is called,
and no new record, hash domain, or digest is introduced.  Every build is
call-scoped and uncached; the terminal identities are the already frozen
fourteenth registry, cumulative suite, and catalog hashes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

from .executable_fixture_fourteenth_catalog import (
    FROZEN_FOURTEENTH_CATALOG_SHA256,
    FOURTEENTH_TRANCHE_ADDED_FIXTURE_COUNT,
    FOURTEENTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT,
    FourteenthTrancheFixtureCatalog,
    build_fourteenth_tranche_fixture_catalog_local,
)
from .executable_fixture_profiles import (
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from .executable_static_fourteenth_registry import (
    FROZEN_FOURTEENTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_FOURTEENTH_REGISTRY_SHA256,
    FOURTEENTH_TRANCHE_ADDED_TASK_COUNT,
    FOURTEENTH_TRANCHE_CUMULATIVE_TASK_COUNT,
    FOURTEENTH_TRANCHE_FAMILY_ORDER,
    FourteenthTrancheTaskRegistry,
    build_fourteenth_tranche_task_registry,
    validate_fourteenth_tranche_task_registry,
)
from .executable_thirteenth_predecessor_evidence import (
    FROZEN_THIRTEENTH_CATALOG_SHA256,
    THIRTEENTH_PREFIX_FAMILY_ORDER,
    THIRTEENTH_PREFIX_FIXTURE_COUNT,
    THIRTEENTH_PREFIX_PROFILE_COUNT,
    THIRTEENTH_PREFIX_TASK_COUNT,
    ThirteenthPrefixFixtureEvidence,
    ThirteenthPrefixTaskEvidence,
    build_thirteenth_prefix_fixture_evidence,
    build_thirteenth_prefix_task_evidence,
    validate_thirteenth_prefix_fixture_evidence,
    validate_thirteenth_prefix_task_evidence,
)


FOURTEENTH_PREFIX_TASK_COUNT: Final[int] = (
    FOURTEENTH_TRANCHE_CUMULATIVE_TASK_COUNT
)
FOURTEENTH_PREFIX_FIXTURE_COUNT: Final[int] = (
    FOURTEENTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT
)
FOURTEENTH_PREFIX_PROFILE_COUNT: Final[int] = THIRTEENTH_PREFIX_PROFILE_COUNT
FOURTEENTH_PREFIX_FAMILY_ORDER: Final[tuple[str, ...]] = (
    *THIRTEENTH_PREFIX_FAMILY_ORDER,
    *FOURTEENTH_TRANCHE_FAMILY_ORDER,
)


class FourteenthPredecessorEvidenceError(ValueError):
    """Raised when the through-fourteenth prefix differs from its frozen chain."""


@dataclass(frozen=True, slots=True)
class FourteenthPrefixTaskEvidence:
    """Fresh first-through-fourteenth task evidence for a later registry."""

    thirteenth_evidence: ThirteenthPrefixTaskEvidence = field(repr=False)
    fourteenth_registry: FourteenthTrancheTaskRegistry = field(repr=False)
    tasks: tuple[object, ...] = field(repr=False)
    total_task_count: int = FOURTEENTH_PREFIX_TASK_COUNT
    terminal_registry_sha256: str = FROZEN_FOURTEENTH_REGISTRY_SHA256
    terminal_cumulative_suite_sha256: str = (
        FROZEN_FOURTEENTH_CUMULATIVE_SUITE_SHA256
    )

    def __post_init__(self) -> None:
        validate_fourteenth_prefix_task_evidence(self)

    @property
    def registries(self) -> tuple[object, ...]:
        """Return all fourteen registries as a fresh tuple."""

        return (
            *self.thirteenth_evidence.registries,
            self.fourteenth_registry,
        )


def _observed_family_order(tasks: tuple[object, ...]) -> tuple[str, ...]:
    try:
        return tuple(
            task.family_id
            for index, task in enumerate(tasks)
            if index == 0 or task.family_id != tasks[index - 1].family_id
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise FourteenthPredecessorEvidenceError(
            "through-fourteenth task family order cannot be inspected"
        ) from exc


def validate_fourteenth_prefix_task_evidence(
    evidence: FourteenthPrefixTaskEvidence,
) -> None:
    """Validate the exact task prefix without rebuilding a task."""

    if type(evidence) is not FourteenthPrefixTaskEvidence:
        raise FourteenthPredecessorEvidenceError(
            "task evidence must be an exact FourteenthPrefixTaskEvidence"
        )
    if type(evidence.thirteenth_evidence) is not ThirteenthPrefixTaskEvidence:
        raise FourteenthPredecessorEvidenceError(
            "task evidence has the wrong thirteenth-prefix type"
        )
    if type(evidence.fourteenth_registry) is not FourteenthTrancheTaskRegistry:
        raise FourteenthPredecessorEvidenceError(
            "task evidence has the wrong fourteenth registry type"
        )
    try:
        validate_thirteenth_prefix_task_evidence(
            evidence.thirteenth_evidence
        )
        validate_fourteenth_tranche_task_registry(
            evidence.fourteenth_registry
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise FourteenthPredecessorEvidenceError(
            "a through-fourteenth task component is invalid"
        ) from exc

    thirteenth = evidence.thirteenth_evidence
    fourteenth = evidence.fourteenth_registry
    if (
        thirteenth.total_task_count != THIRTEENTH_PREFIX_TASK_COUNT
        or fourteenth.base_added_registry_sha256
        != thirteenth.terminal_registry_sha256
        or fourteenth.base_cumulative_suite_sha256
        != thirteenth.terminal_cumulative_suite_sha256
        or fourteenth.registry_sha256
        != FROZEN_FOURTEENTH_REGISTRY_SHA256
        or fourteenth.cumulative_suite_sha256
        != FROZEN_FOURTEENTH_CUMULATIVE_SUITE_SHA256
        or len(fourteenth.added_tasks)
        != FOURTEENTH_TRANCHE_ADDED_TASK_COUNT
    ):
        raise FourteenthPredecessorEvidenceError(
            "fourteenth registry does not extend the frozen "
            "thirteenth-prefix evidence"
        )

    expected_tasks = (*thirteenth.tasks, *fourteenth.added_tasks)
    if (
        type(evidence.tasks) is not tuple
        or len(evidence.tasks) != len(expected_tasks)
        or any(
            observed is not expected
            for observed, expected in zip(
                evidence.tasks,
                expected_tasks,
                strict=True,
            )
        )
    ):
        raise FourteenthPredecessorEvidenceError(
            "cumulative tasks are not the exact prefix concatenation"
        )
    if any(
        task is predecessor
        for task in fourteenth.added_tasks
        for predecessor in thirteenth.tasks
    ):
        raise FourteenthPredecessorEvidenceError(
            "fourteenth tasks do not have fresh object ownership"
        )
    if (
        type(evidence.total_task_count) is not int
        or evidence.total_task_count != FOURTEENTH_PREFIX_TASK_COUNT
        or len(evidence.tasks) != FOURTEENTH_PREFIX_TASK_COUNT
        or type(evidence.terminal_registry_sha256) is not str
        or evidence.terminal_registry_sha256
        != FROZEN_FOURTEENTH_REGISTRY_SHA256
        or evidence.terminal_registry_sha256
        != fourteenth.registry_sha256
        or type(evidence.terminal_cumulative_suite_sha256) is not str
        or evidence.terminal_cumulative_suite_sha256
        != FROZEN_FOURTEENTH_CUMULATIVE_SUITE_SHA256
        or evidence.terminal_cumulative_suite_sha256
        != fourteenth.cumulative_suite_sha256
    ):
        raise FourteenthPredecessorEvidenceError(
            "through-fourteenth task metadata differs from the frozen chain"
        )

    try:
        task_ids = tuple(task.task_id for task in evidence.tasks)
        task_contracts = tuple(
            task.task_contract_sha256 for task in evidence.tasks
        )
        graph_hashes = tuple(task.graph_sha256 for task in evidence.tasks)
    except (AttributeError, TypeError, ValueError) as exc:
        raise FourteenthPredecessorEvidenceError(
            "through-fourteenth task identities cannot be inspected"
        ) from exc
    if (
        len(set(task_ids)) != FOURTEENTH_PREFIX_TASK_COUNT
        or len(set(task_contracts)) != FOURTEENTH_PREFIX_TASK_COUNT
        or len(set(graph_hashes)) != FOURTEENTH_PREFIX_TASK_COUNT
        or _observed_family_order(evidence.tasks)
        != FOURTEENTH_PREFIX_FAMILY_ORDER
    ):
        raise FourteenthPredecessorEvidenceError(
            "task identities collide or family order is not canonical"
        )


def verify_fourteenth_prefix_task_evidence(evidence: object) -> bool:
    """Return whether ``evidence`` is the exact through-fourteenth prefix."""

    try:
        validate_fourteenth_prefix_task_evidence(  # type: ignore[arg-type]
            evidence
        )
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def build_fourteenth_prefix_task_evidence(
    thirteenth_evidence: ThirteenthPrefixTaskEvidence | None = None,
) -> FourteenthPrefixTaskEvidence:
    """Build the first thirteen once and append one non-recursive registry."""

    selected_thirteenth = (
        build_thirteenth_prefix_task_evidence()
        if thirteenth_evidence is None
        else thirteenth_evidence
    )
    validate_thirteenth_prefix_task_evidence(selected_thirteenth)
    fourteenth = build_fourteenth_tranche_task_registry(
        selected_thirteenth
    )
    return FourteenthPrefixTaskEvidence(
        thirteenth_evidence=selected_thirteenth,
        fourteenth_registry=fourteenth,
        tasks=(*selected_thirteenth.tasks, *fourteenth.added_tasks),
    )


@dataclass(frozen=True, slots=True)
class FourteenthPrefixFixtureEvidence:
    """Fresh first-through-fourteenth fixture evidence for a later catalog."""

    task_evidence: FourteenthPrefixTaskEvidence = field(repr=False)
    thirteenth_evidence: ThirteenthPrefixFixtureEvidence = field(repr=False)
    fourteenth_catalog: FourteenthTrancheFixtureCatalog = field(repr=False)
    bundles: tuple[object, ...] = field(repr=False)
    total_fixture_count: int = FOURTEENTH_PREFIX_FIXTURE_COUNT
    profiles_per_task: int = FOURTEENTH_PREFIX_PROFILE_COUNT
    terminal_catalog_sha256: str = FROZEN_FOURTEENTH_CATALOG_SHA256

    def __post_init__(self) -> None:
        validate_fourteenth_prefix_fixture_evidence(self)

    @property
    def catalogs(self) -> tuple[object, ...]:
        """Return all fourteen catalogs as a fresh tuple."""

        return (
            *self.thirteenth_evidence.catalogs,
            self.fourteenth_catalog,
        )


def validate_fourteenth_prefix_fixture_evidence(
    evidence: FourteenthPrefixFixtureEvidence,
) -> None:
    """Validate the exact fixture prefix and every task/profile binding."""

    if type(evidence) is not FourteenthPrefixFixtureEvidence:
        raise FourteenthPredecessorEvidenceError(
            "fixture evidence must be an exact "
            "FourteenthPrefixFixtureEvidence"
        )
    if type(evidence.task_evidence) is not FourteenthPrefixTaskEvidence:
        raise FourteenthPredecessorEvidenceError(
            "fixture evidence has the wrong task-prefix type"
        )
    if (
        type(evidence.thirteenth_evidence)
        is not ThirteenthPrefixFixtureEvidence
    ):
        raise FourteenthPredecessorEvidenceError(
            "fixture evidence has the wrong thirteenth fixture type"
        )
    if (
        type(evidence.fourteenth_catalog)
        is not FourteenthTrancheFixtureCatalog
    ):
        raise FourteenthPredecessorEvidenceError(
            "fixture evidence has the wrong fourteenth catalog type"
        )
    try:
        validate_fourteenth_prefix_task_evidence(evidence.task_evidence)
        validate_thirteenth_prefix_fixture_evidence(
            evidence.thirteenth_evidence
        )
        fourteenth_record = (
            evidence.fourteenth_catalog.to_hash_only_record()
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise FourteenthPredecessorEvidenceError(
            "a through-fourteenth fixture component is invalid"
        ) from exc

    tasks = evidence.task_evidence
    thirteenth = evidence.thirteenth_evidence
    fourteenth = evidence.fourteenth_catalog
    if (
        thirteenth.task_evidence is not tasks.thirteenth_evidence
        or thirteenth.total_fixture_count
        != THIRTEENTH_PREFIX_FIXTURE_COUNT
        or thirteenth.terminal_catalog_sha256
        != FROZEN_THIRTEENTH_CATALOG_SHA256
        or fourteenth.registry is not tasks.fourteenth_registry
        or fourteenth.base_fixture_catalog_sha256
        != thirteenth.terminal_catalog_sha256
        or fourteenth.catalog_sha256
        != FROZEN_FOURTEENTH_CATALOG_SHA256
        or fourteenth_record.get("catalog_sha256")
        != FROZEN_FOURTEENTH_CATALOG_SHA256
        or len(fourteenth.bundles)
        != FOURTEENTH_TRANCHE_ADDED_FIXTURE_COUNT
    ):
        raise FourteenthPredecessorEvidenceError(
            "fourteenth catalog does not extend the exact thirteenth fixture "
            "evidence"
        )

    expected_bundles = (*thirteenth.bundles, *fourteenth.bundles)
    if (
        type(evidence.bundles) is not tuple
        or len(evidence.bundles) != len(expected_bundles)
        or any(
            observed is not expected
            for observed, expected in zip(
                evidence.bundles,
                expected_bundles,
                strict=True,
            )
        )
    ):
        raise FourteenthPredecessorEvidenceError(
            "cumulative fixtures are not the exact prefix concatenation"
        )
    if any(
        bundle is predecessor
        for bundle in fourteenth.bundles
        for predecessor in thirteenth.bundles
    ):
        raise FourteenthPredecessorEvidenceError(
            "fourteenth fixtures do not have fresh object ownership"
        )
    if (
        type(evidence.total_fixture_count) is not int
        or evidence.total_fixture_count
        != FOURTEENTH_PREFIX_FIXTURE_COUNT
        or len(evidence.bundles) != FOURTEENTH_PREFIX_FIXTURE_COUNT
        or type(evidence.profiles_per_task) is not int
        or evidence.profiles_per_task
        != FOURTEENTH_PREFIX_PROFILE_COUNT
        or len(evidence.bundles)
        != len(tasks.tasks) * evidence.profiles_per_task
        or type(evidence.terminal_catalog_sha256) is not str
        or evidence.terminal_catalog_sha256
        != FROZEN_FOURTEENTH_CATALOG_SHA256
        or evidence.terminal_catalog_sha256
        != fourteenth.catalog_sha256
        or len(PUBLIC_DEVELOPMENT_FIXTURE_PROFILES)
        != FOURTEENTH_PREFIX_PROFILE_COUNT
    ):
        raise FourteenthPredecessorEvidenceError(
            "through-fourteenth fixture metadata differs from the frozen chain"
        )

    fixture_ids: set[str] = set()
    fixture_hashes: set[str] = set()
    try:
        for index, bundle in enumerate(evidence.bundles):
            task = tasks.tasks[index // FOURTEENTH_PREFIX_PROFILE_COUNT]
            profile_index = index % FOURTEENTH_PREFIX_PROFILE_COUNT
            profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[profile_index]
            if (
                bundle.task_contract_sha256
                != task.task_contract_sha256
                or bundle.profile_sha256 != profile.profile_sha256
                or bundle.descriptor != task.fixtures[profile_index]
                or bundle.candidate_execution_authorized is not False
                or bundle.model_selection_eligible is not False
                or bundle.claim_authorized is not False
            ):
                raise FourteenthPredecessorEvidenceError(
                    "fixture order, descriptor binding, or authority is invalid"
                )
            fixture_ids.add(bundle.descriptor.fixture_id)
            fixture_hashes.add(bundle.descriptor.fixture_sha256)
    except (AttributeError, TypeError, ValueError) as exc:
        if isinstance(exc, FourteenthPredecessorEvidenceError):
            raise
        raise FourteenthPredecessorEvidenceError(
            "through-fourteenth fixture identities cannot be inspected"
        ) from exc
    if (
        len(fixture_ids) != FOURTEENTH_PREFIX_FIXTURE_COUNT
        or len(fixture_hashes) != FOURTEENTH_PREFIX_FIXTURE_COUNT
    ):
        raise FourteenthPredecessorEvidenceError(
            "fixture identities collide across the through-fourteenth prefix"
        )


def verify_fourteenth_prefix_fixture_evidence(evidence: object) -> bool:
    """Return whether ``evidence`` is the exact through-fourteenth prefix."""

    try:
        validate_fourteenth_prefix_fixture_evidence(  # type: ignore[arg-type]
            evidence
        )
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def build_fourteenth_prefix_fixture_evidence(
    task_evidence: FourteenthPrefixTaskEvidence | None = None,
) -> FourteenthPrefixFixtureEvidence:
    """Build each first-through-fourteenth catalog locally exactly once."""

    selected_tasks = (
        build_fourteenth_prefix_task_evidence()
        if task_evidence is None
        else task_evidence
    )
    validate_fourteenth_prefix_task_evidence(selected_tasks)
    thirteenth = build_thirteenth_prefix_fixture_evidence(
        selected_tasks.thirteenth_evidence
    )
    fourteenth = build_fourteenth_tranche_fixture_catalog_local(
        selected_tasks.fourteenth_registry
    )
    return FourteenthPrefixFixtureEvidence(
        task_evidence=selected_tasks,
        thirteenth_evidence=thirteenth,
        fourteenth_catalog=fourteenth,
        bundles=(*thirteenth.bundles, *fourteenth.bundles),
    )


__all__ = [
    "FROZEN_FOURTEENTH_CATALOG_SHA256",
    "FROZEN_FOURTEENTH_CUMULATIVE_SUITE_SHA256",
    "FROZEN_FOURTEENTH_REGISTRY_SHA256",
    "FOURTEENTH_PREFIX_FAMILY_ORDER",
    "FOURTEENTH_PREFIX_FIXTURE_COUNT",
    "FOURTEENTH_PREFIX_PROFILE_COUNT",
    "FOURTEENTH_PREFIX_TASK_COUNT",
    "FourteenthPredecessorEvidenceError",
    "FourteenthPrefixFixtureEvidence",
    "FourteenthPrefixTaskEvidence",
    "build_fourteenth_prefix_fixture_evidence",
    "build_fourteenth_prefix_task_evidence",
    "validate_fourteenth_prefix_fixture_evidence",
    "validate_fourteenth_prefix_task_evidence",
    "verify_fourteenth_prefix_fixture_evidence",
    "verify_fourteenth_prefix_task_evidence",
]
