"""Hash-neutral non-recursive evidence through the thirteenth tranche.

The frozen ``executable_twelfth_predecessor_evidence`` module deliberately
ends at the twelfth tranche because its 420-task and 2,100-fixture identities
are inputs to the thirteenth registry and catalog.  This module extends that
evidence without changing it: one through-twelfth task snapshot is reused to
build the thirteenth registry, and the same task snapshot is then reused to
build the through-twelfth fixture evidence and thirteenth local catalog.

The resulting prefix is suitable as predecessor evidence for a fourteenth
additive tranche.  No historical recursive publication builder is called,
and no new record, hash domain, or digest is introduced.  Every build is
call-scoped and uncached; the terminal identities are the already frozen
thirteenth registry, cumulative suite, and catalog hashes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

from .executable_fixture_profiles import (
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from .executable_fixture_thirteenth_catalog import (
    FROZEN_THIRTEENTH_CATALOG_SHA256,
    THIRTEENTH_TRANCHE_ADDED_FIXTURE_COUNT,
    THIRTEENTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT,
    ThirteenthTrancheFixtureCatalog,
    build_thirteenth_tranche_fixture_catalog_local,
)
from .executable_static_thirteenth_registry import (
    FROZEN_THIRTEENTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_THIRTEENTH_REGISTRY_SHA256,
    THIRTEENTH_TRANCHE_ADDED_TASK_COUNT,
    THIRTEENTH_TRANCHE_CUMULATIVE_TASK_COUNT,
    THIRTEENTH_TRANCHE_FAMILY_ORDER,
    ThirteenthTrancheTaskRegistry,
    build_thirteenth_tranche_task_registry,
    validate_thirteenth_tranche_task_registry,
)
from .executable_twelfth_predecessor_evidence import (
    FROZEN_TWELFTH_CATALOG_SHA256,
    TWELFTH_PREFIX_FAMILY_ORDER,
    TWELFTH_PREFIX_FIXTURE_COUNT,
    TWELFTH_PREFIX_PROFILE_COUNT,
    TWELFTH_PREFIX_TASK_COUNT,
    TwelfthPrefixFixtureEvidence,
    TwelfthPrefixTaskEvidence,
    build_twelfth_prefix_fixture_evidence,
    build_twelfth_prefix_task_evidence,
    validate_twelfth_prefix_fixture_evidence,
    validate_twelfth_prefix_task_evidence,
)


THIRTEENTH_PREFIX_TASK_COUNT: Final[int] = (
    THIRTEENTH_TRANCHE_CUMULATIVE_TASK_COUNT
)
THIRTEENTH_PREFIX_FIXTURE_COUNT: Final[int] = (
    THIRTEENTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT
)
THIRTEENTH_PREFIX_PROFILE_COUNT: Final[int] = TWELFTH_PREFIX_PROFILE_COUNT
THIRTEENTH_PREFIX_FAMILY_ORDER: Final[tuple[str, ...]] = (
    *TWELFTH_PREFIX_FAMILY_ORDER,
    *THIRTEENTH_TRANCHE_FAMILY_ORDER,
)


class ThirteenthPredecessorEvidenceError(ValueError):
    """Raised when the through-thirteenth prefix differs from its frozen chain."""


@dataclass(frozen=True, slots=True)
class ThirteenthPrefixTaskEvidence:
    """Fresh first-through-thirteenth task evidence for a later registry."""

    twelfth_evidence: TwelfthPrefixTaskEvidence = field(repr=False)
    thirteenth_registry: ThirteenthTrancheTaskRegistry = field(repr=False)
    tasks: tuple[object, ...] = field(repr=False)
    total_task_count: int = THIRTEENTH_PREFIX_TASK_COUNT
    terminal_registry_sha256: str = FROZEN_THIRTEENTH_REGISTRY_SHA256
    terminal_cumulative_suite_sha256: str = (
        FROZEN_THIRTEENTH_CUMULATIVE_SUITE_SHA256
    )

    def __post_init__(self) -> None:
        validate_thirteenth_prefix_task_evidence(self)

    @property
    def registries(self) -> tuple[object, ...]:
        """Return all thirteen registries as a fresh tuple."""

        return (
            *self.twelfth_evidence.registries,
            self.thirteenth_registry,
        )


def _observed_family_order(tasks: tuple[object, ...]) -> tuple[str, ...]:
    try:
        return tuple(
            task.family_id
            for index, task in enumerate(tasks)
            if index == 0 or task.family_id != tasks[index - 1].family_id
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise ThirteenthPredecessorEvidenceError(
            "through-thirteenth task family order cannot be inspected"
        ) from exc


def validate_thirteenth_prefix_task_evidence(
    evidence: ThirteenthPrefixTaskEvidence,
) -> None:
    """Validate the exact task prefix without rebuilding a task."""

    if type(evidence) is not ThirteenthPrefixTaskEvidence:
        raise ThirteenthPredecessorEvidenceError(
            "task evidence must be an exact ThirteenthPrefixTaskEvidence"
        )
    if type(evidence.twelfth_evidence) is not TwelfthPrefixTaskEvidence:
        raise ThirteenthPredecessorEvidenceError(
            "task evidence has the wrong twelfth-prefix type"
        )
    if type(evidence.thirteenth_registry) is not ThirteenthTrancheTaskRegistry:
        raise ThirteenthPredecessorEvidenceError(
            "task evidence has the wrong thirteenth registry type"
        )
    try:
        validate_twelfth_prefix_task_evidence(evidence.twelfth_evidence)
        validate_thirteenth_tranche_task_registry(
            evidence.thirteenth_registry
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise ThirteenthPredecessorEvidenceError(
            "a through-thirteenth task component is invalid"
        ) from exc

    twelfth = evidence.twelfth_evidence
    thirteenth = evidence.thirteenth_registry
    if (
        twelfth.total_task_count != TWELFTH_PREFIX_TASK_COUNT
        or thirteenth.base_added_registry_sha256
        != twelfth.terminal_registry_sha256
        or thirteenth.base_cumulative_suite_sha256
        != twelfth.terminal_cumulative_suite_sha256
        or thirteenth.registry_sha256
        != FROZEN_THIRTEENTH_REGISTRY_SHA256
        or thirteenth.cumulative_suite_sha256
        != FROZEN_THIRTEENTH_CUMULATIVE_SUITE_SHA256
        or len(thirteenth.added_tasks)
        != THIRTEENTH_TRANCHE_ADDED_TASK_COUNT
    ):
        raise ThirteenthPredecessorEvidenceError(
            "thirteenth registry does not extend the frozen "
            "twelfth-prefix evidence"
        )

    expected_tasks = (*twelfth.tasks, *thirteenth.added_tasks)
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
        raise ThirteenthPredecessorEvidenceError(
            "cumulative tasks are not the exact prefix concatenation"
        )
    if any(
        task is predecessor
        for task in thirteenth.added_tasks
        for predecessor in twelfth.tasks
    ):
        raise ThirteenthPredecessorEvidenceError(
            "thirteenth tasks do not have fresh object ownership"
        )
    if (
        type(evidence.total_task_count) is not int
        or evidence.total_task_count != THIRTEENTH_PREFIX_TASK_COUNT
        or len(evidence.tasks) != THIRTEENTH_PREFIX_TASK_COUNT
        or type(evidence.terminal_registry_sha256) is not str
        or evidence.terminal_registry_sha256
        != FROZEN_THIRTEENTH_REGISTRY_SHA256
        or evidence.terminal_registry_sha256
        != thirteenth.registry_sha256
        or type(evidence.terminal_cumulative_suite_sha256) is not str
        or evidence.terminal_cumulative_suite_sha256
        != FROZEN_THIRTEENTH_CUMULATIVE_SUITE_SHA256
        or evidence.terminal_cumulative_suite_sha256
        != thirteenth.cumulative_suite_sha256
    ):
        raise ThirteenthPredecessorEvidenceError(
            "through-thirteenth task metadata differs from the frozen chain"
        )

    try:
        task_ids = tuple(task.task_id for task in evidence.tasks)
        task_contracts = tuple(
            task.task_contract_sha256 for task in evidence.tasks
        )
        graph_hashes = tuple(task.graph_sha256 for task in evidence.tasks)
    except (AttributeError, TypeError, ValueError) as exc:
        raise ThirteenthPredecessorEvidenceError(
            "through-thirteenth task identities cannot be inspected"
        ) from exc
    if (
        len(set(task_ids)) != THIRTEENTH_PREFIX_TASK_COUNT
        or len(set(task_contracts)) != THIRTEENTH_PREFIX_TASK_COUNT
        or len(set(graph_hashes)) != THIRTEENTH_PREFIX_TASK_COUNT
        or _observed_family_order(evidence.tasks)
        != THIRTEENTH_PREFIX_FAMILY_ORDER
    ):
        raise ThirteenthPredecessorEvidenceError(
            "task identities collide or family order is not canonical"
        )


def verify_thirteenth_prefix_task_evidence(evidence: object) -> bool:
    """Return whether ``evidence`` is the exact through-thirteenth prefix."""

    try:
        validate_thirteenth_prefix_task_evidence(  # type: ignore[arg-type]
            evidence
        )
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def build_thirteenth_prefix_task_evidence(
    twelfth_evidence: TwelfthPrefixTaskEvidence | None = None,
) -> ThirteenthPrefixTaskEvidence:
    """Build the first twelve once and append one non-recursive registry."""

    selected_twelfth = (
        build_twelfth_prefix_task_evidence()
        if twelfth_evidence is None
        else twelfth_evidence
    )
    validate_twelfth_prefix_task_evidence(selected_twelfth)
    thirteenth = build_thirteenth_tranche_task_registry(
        selected_twelfth
    )
    return ThirteenthPrefixTaskEvidence(
        twelfth_evidence=selected_twelfth,
        thirteenth_registry=thirteenth,
        tasks=(*selected_twelfth.tasks, *thirteenth.added_tasks),
    )


@dataclass(frozen=True, slots=True)
class ThirteenthPrefixFixtureEvidence:
    """Fresh first-through-thirteenth fixture evidence for a later catalog."""

    task_evidence: ThirteenthPrefixTaskEvidence = field(repr=False)
    twelfth_evidence: TwelfthPrefixFixtureEvidence = field(repr=False)
    thirteenth_catalog: ThirteenthTrancheFixtureCatalog = field(repr=False)
    bundles: tuple[object, ...] = field(repr=False)
    total_fixture_count: int = THIRTEENTH_PREFIX_FIXTURE_COUNT
    profiles_per_task: int = THIRTEENTH_PREFIX_PROFILE_COUNT
    terminal_catalog_sha256: str = FROZEN_THIRTEENTH_CATALOG_SHA256

    def __post_init__(self) -> None:
        validate_thirteenth_prefix_fixture_evidence(self)

    @property
    def catalogs(self) -> tuple[object, ...]:
        """Return all thirteen catalogs as a fresh tuple."""

        return (
            *self.twelfth_evidence.catalogs,
            self.thirteenth_catalog,
        )


def validate_thirteenth_prefix_fixture_evidence(
    evidence: ThirteenthPrefixFixtureEvidence,
) -> None:
    """Validate the exact fixture prefix and every task/profile binding."""

    if type(evidence) is not ThirteenthPrefixFixtureEvidence:
        raise ThirteenthPredecessorEvidenceError(
            "fixture evidence must be an exact "
            "ThirteenthPrefixFixtureEvidence"
        )
    if type(evidence.task_evidence) is not ThirteenthPrefixTaskEvidence:
        raise ThirteenthPredecessorEvidenceError(
            "fixture evidence has the wrong task-prefix type"
        )
    if type(evidence.twelfth_evidence) is not TwelfthPrefixFixtureEvidence:
        raise ThirteenthPredecessorEvidenceError(
            "fixture evidence has the wrong twelfth fixture type"
        )
    if (
        type(evidence.thirteenth_catalog)
        is not ThirteenthTrancheFixtureCatalog
    ):
        raise ThirteenthPredecessorEvidenceError(
            "fixture evidence has the wrong thirteenth catalog type"
        )
    try:
        validate_thirteenth_prefix_task_evidence(evidence.task_evidence)
        validate_twelfth_prefix_fixture_evidence(
            evidence.twelfth_evidence
        )
        thirteenth_record = (
            evidence.thirteenth_catalog.to_hash_only_record()
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise ThirteenthPredecessorEvidenceError(
            "a through-thirteenth fixture component is invalid"
        ) from exc

    tasks = evidence.task_evidence
    twelfth = evidence.twelfth_evidence
    thirteenth = evidence.thirteenth_catalog
    if (
        twelfth.task_evidence is not tasks.twelfth_evidence
        or twelfth.total_fixture_count != TWELFTH_PREFIX_FIXTURE_COUNT
        or twelfth.terminal_catalog_sha256
        != FROZEN_TWELFTH_CATALOG_SHA256
        or thirteenth.registry is not tasks.thirteenth_registry
        or thirteenth.base_fixture_catalog_sha256
        != twelfth.terminal_catalog_sha256
        or thirteenth.catalog_sha256
        != FROZEN_THIRTEENTH_CATALOG_SHA256
        or thirteenth_record.get("catalog_sha256")
        != FROZEN_THIRTEENTH_CATALOG_SHA256
        or len(thirteenth.bundles)
        != THIRTEENTH_TRANCHE_ADDED_FIXTURE_COUNT
    ):
        raise ThirteenthPredecessorEvidenceError(
            "thirteenth catalog does not extend the exact twelfth fixture "
            "evidence"
        )

    expected_bundles = (*twelfth.bundles, *thirteenth.bundles)
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
        raise ThirteenthPredecessorEvidenceError(
            "cumulative fixtures are not the exact prefix concatenation"
        )
    if any(
        bundle is predecessor
        for bundle in thirteenth.bundles
        for predecessor in twelfth.bundles
    ):
        raise ThirteenthPredecessorEvidenceError(
            "thirteenth fixtures do not have fresh object ownership"
        )
    if (
        type(evidence.total_fixture_count) is not int
        or evidence.total_fixture_count
        != THIRTEENTH_PREFIX_FIXTURE_COUNT
        or len(evidence.bundles) != THIRTEENTH_PREFIX_FIXTURE_COUNT
        or type(evidence.profiles_per_task) is not int
        or evidence.profiles_per_task
        != THIRTEENTH_PREFIX_PROFILE_COUNT
        or len(evidence.bundles)
        != len(tasks.tasks) * evidence.profiles_per_task
        or type(evidence.terminal_catalog_sha256) is not str
        or evidence.terminal_catalog_sha256
        != FROZEN_THIRTEENTH_CATALOG_SHA256
        or evidence.terminal_catalog_sha256
        != thirteenth.catalog_sha256
        or len(PUBLIC_DEVELOPMENT_FIXTURE_PROFILES)
        != THIRTEENTH_PREFIX_PROFILE_COUNT
    ):
        raise ThirteenthPredecessorEvidenceError(
            "through-thirteenth fixture metadata differs from the frozen chain"
        )

    fixture_ids: set[str] = set()
    fixture_hashes: set[str] = set()
    try:
        for index, bundle in enumerate(evidence.bundles):
            task = tasks.tasks[index // THIRTEENTH_PREFIX_PROFILE_COUNT]
            profile_index = index % THIRTEENTH_PREFIX_PROFILE_COUNT
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
                raise ThirteenthPredecessorEvidenceError(
                    "fixture order, descriptor binding, or authority is invalid"
                )
            fixture_ids.add(bundle.descriptor.fixture_id)
            fixture_hashes.add(bundle.descriptor.fixture_sha256)
    except (AttributeError, TypeError, ValueError) as exc:
        if isinstance(exc, ThirteenthPredecessorEvidenceError):
            raise
        raise ThirteenthPredecessorEvidenceError(
            "through-thirteenth fixture identities cannot be inspected"
        ) from exc
    if (
        len(fixture_ids) != THIRTEENTH_PREFIX_FIXTURE_COUNT
        or len(fixture_hashes) != THIRTEENTH_PREFIX_FIXTURE_COUNT
    ):
        raise ThirteenthPredecessorEvidenceError(
            "fixture identities collide across the through-thirteenth prefix"
        )


def verify_thirteenth_prefix_fixture_evidence(evidence: object) -> bool:
    """Return whether ``evidence`` is the exact through-thirteenth prefix."""

    try:
        validate_thirteenth_prefix_fixture_evidence(  # type: ignore[arg-type]
            evidence
        )
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def build_thirteenth_prefix_fixture_evidence(
    task_evidence: ThirteenthPrefixTaskEvidence | None = None,
) -> ThirteenthPrefixFixtureEvidence:
    """Build each first-through-thirteenth catalog locally exactly once."""

    selected_tasks = (
        build_thirteenth_prefix_task_evidence()
        if task_evidence is None
        else task_evidence
    )
    validate_thirteenth_prefix_task_evidence(selected_tasks)
    twelfth = build_twelfth_prefix_fixture_evidence(
        selected_tasks.twelfth_evidence
    )
    thirteenth = build_thirteenth_tranche_fixture_catalog_local(
        selected_tasks.thirteenth_registry
    )
    return ThirteenthPrefixFixtureEvidence(
        task_evidence=selected_tasks,
        twelfth_evidence=twelfth,
        thirteenth_catalog=thirteenth,
        bundles=(*twelfth.bundles, *thirteenth.bundles),
    )


__all__ = [
    "FROZEN_THIRTEENTH_CATALOG_SHA256",
    "FROZEN_THIRTEENTH_CUMULATIVE_SUITE_SHA256",
    "FROZEN_THIRTEENTH_REGISTRY_SHA256",
    "THIRTEENTH_PREFIX_FAMILY_ORDER",
    "THIRTEENTH_PREFIX_FIXTURE_COUNT",
    "THIRTEENTH_PREFIX_PROFILE_COUNT",
    "THIRTEENTH_PREFIX_TASK_COUNT",
    "ThirteenthPredecessorEvidenceError",
    "ThirteenthPrefixFixtureEvidence",
    "ThirteenthPrefixTaskEvidence",
    "build_thirteenth_prefix_fixture_evidence",
    "build_thirteenth_prefix_task_evidence",
    "validate_thirteenth_prefix_fixture_evidence",
    "validate_thirteenth_prefix_task_evidence",
    "verify_thirteenth_prefix_fixture_evidence",
    "verify_thirteenth_prefix_task_evidence",
]
