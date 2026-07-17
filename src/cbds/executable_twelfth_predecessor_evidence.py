"""Hash-neutral non-recursive evidence through the twelfth tranche.

The frozen ``executable_eleventh_predecessor_evidence`` module deliberately
ends at the eleventh tranche because its 400-task and 2,000-fixture
identities are inputs to the twelfth registry and catalog.  This module
extends that evidence without changing it: one through-eleventh task
snapshot is reused to build the twelfth registry, and the same task snapshot
is then reused to build the through-eleventh fixture evidence and twelfth
local catalog.

The resulting prefix is suitable as predecessor evidence for a thirteenth
additive tranche.  No historical recursive publication builder is called,
and no new record, hash domain, or digest is introduced.  Every build is
call-scoped and uncached; the terminal identities are the already frozen
twelfth registry, cumulative suite, and catalog hashes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

from .executable_eleventh_predecessor_evidence import (
    ELEVENTH_PREFIX_FAMILY_ORDER,
    ELEVENTH_PREFIX_FIXTURE_COUNT,
    ELEVENTH_PREFIX_PROFILE_COUNT,
    ELEVENTH_PREFIX_TASK_COUNT,
    FROZEN_ELEVENTH_CATALOG_SHA256,
    EleventhPrefixFixtureEvidence,
    EleventhPrefixTaskEvidence,
    build_eleventh_prefix_fixture_evidence,
    build_eleventh_prefix_task_evidence,
    validate_eleventh_prefix_fixture_evidence,
    validate_eleventh_prefix_task_evidence,
)
from .executable_fixture_profiles import (
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from .executable_fixture_twelfth_catalog import (
    TWELFTH_TRANCHE_ADDED_FIXTURE_COUNT,
    TWELFTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT,
    TwelfthTrancheFixtureCatalog,
    build_twelfth_tranche_fixture_catalog_local,
)
from .executable_static_twelfth_registry import (
    FROZEN_TWELFTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_TWELFTH_REGISTRY_SHA256,
    TWELFTH_TRANCHE_ADDED_TASK_COUNT,
    TWELFTH_TRANCHE_CUMULATIVE_TASK_COUNT,
    TWELFTH_TRANCHE_FAMILY_ORDER,
    TwelfthTrancheTaskRegistry,
    build_twelfth_tranche_task_registry,
    validate_twelfth_tranche_task_registry,
)


TWELFTH_PREFIX_TASK_COUNT: Final[int] = (
    TWELFTH_TRANCHE_CUMULATIVE_TASK_COUNT
)
TWELFTH_PREFIX_FIXTURE_COUNT: Final[int] = (
    TWELFTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT
)
TWELFTH_PREFIX_PROFILE_COUNT: Final[int] = ELEVENTH_PREFIX_PROFILE_COUNT
TWELFTH_PREFIX_FAMILY_ORDER: Final[tuple[str, ...]] = (
    *ELEVENTH_PREFIX_FAMILY_ORDER,
    *TWELFTH_TRANCHE_FAMILY_ORDER,
)

# The catalog digest is already frozen by the checked twelfth catalog report
# and its tests.  Naming it here introduces no new digest or hash domain.
FROZEN_TWELFTH_CATALOG_SHA256: Final[str] = (
    "98cf6ffa48cbe11ece96195450335e5be9a3d0898d54e91396d0c2756171f169"
)


class TwelfthPredecessorEvidenceError(ValueError):
    """Raised when the through-twelfth prefix differs from its frozen chain."""


@dataclass(frozen=True, slots=True)
class TwelfthPrefixTaskEvidence:
    """Fresh first-through-twelfth task evidence for a thirteenth registry."""

    eleventh_evidence: EleventhPrefixTaskEvidence = field(repr=False)
    twelfth_registry: TwelfthTrancheTaskRegistry = field(repr=False)
    tasks: tuple[object, ...] = field(repr=False)
    total_task_count: int = TWELFTH_PREFIX_TASK_COUNT
    terminal_registry_sha256: str = FROZEN_TWELFTH_REGISTRY_SHA256
    terminal_cumulative_suite_sha256: str = (
        FROZEN_TWELFTH_CUMULATIVE_SUITE_SHA256
    )

    def __post_init__(self) -> None:
        validate_twelfth_prefix_task_evidence(self)

    @property
    def registries(self) -> tuple[object, ...]:
        """Return all twelve registries without retaining a mutable cache."""

        return (
            *self.eleventh_evidence.registries,
            self.twelfth_registry,
        )


def _observed_family_order(tasks: tuple[object, ...]) -> tuple[str, ...]:
    try:
        return tuple(
            task.family_id
            for index, task in enumerate(tasks)
            if index == 0 or task.family_id != tasks[index - 1].family_id
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise TwelfthPredecessorEvidenceError(
            "through-twelfth task family order cannot be inspected"
        ) from exc


def validate_twelfth_prefix_task_evidence(
    evidence: TwelfthPrefixTaskEvidence,
) -> None:
    """Validate the exact task prefix without rebuilding a task."""

    if type(evidence) is not TwelfthPrefixTaskEvidence:
        raise TwelfthPredecessorEvidenceError(
            "task evidence must be an exact TwelfthPrefixTaskEvidence"
        )
    if type(evidence.eleventh_evidence) is not EleventhPrefixTaskEvidence:
        raise TwelfthPredecessorEvidenceError(
            "task evidence has the wrong eleventh-prefix type"
        )
    if type(evidence.twelfth_registry) is not TwelfthTrancheTaskRegistry:
        raise TwelfthPredecessorEvidenceError(
            "task evidence has the wrong twelfth registry type"
        )
    try:
        validate_eleventh_prefix_task_evidence(evidence.eleventh_evidence)
        validate_twelfth_tranche_task_registry(evidence.twelfth_registry)
    except (AttributeError, TypeError, ValueError) as exc:
        raise TwelfthPredecessorEvidenceError(
            "a through-twelfth task component is invalid"
        ) from exc

    eleventh = evidence.eleventh_evidence
    twelfth = evidence.twelfth_registry
    if (
        eleventh.total_task_count != ELEVENTH_PREFIX_TASK_COUNT
        or twelfth.base_added_registry_sha256
        != eleventh.terminal_registry_sha256
        or twelfth.base_cumulative_suite_sha256
        != eleventh.terminal_cumulative_suite_sha256
        or twelfth.registry_sha256 != FROZEN_TWELFTH_REGISTRY_SHA256
        or twelfth.cumulative_suite_sha256
        != FROZEN_TWELFTH_CUMULATIVE_SUITE_SHA256
        or len(twelfth.added_tasks) != TWELFTH_TRANCHE_ADDED_TASK_COUNT
    ):
        raise TwelfthPredecessorEvidenceError(
            "twelfth registry does not extend the frozen eleventh-prefix "
            "evidence"
        )

    expected_tasks = (*eleventh.tasks, *twelfth.added_tasks)
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
        raise TwelfthPredecessorEvidenceError(
            "cumulative tasks are not the exact prefix concatenation"
        )
    if any(
        task is predecessor
        for task in twelfth.added_tasks
        for predecessor in eleventh.tasks
    ):
        raise TwelfthPredecessorEvidenceError(
            "twelfth tasks do not have fresh object ownership"
        )
    if (
        type(evidence.total_task_count) is not int
        or evidence.total_task_count != TWELFTH_PREFIX_TASK_COUNT
        or len(evidence.tasks) != TWELFTH_PREFIX_TASK_COUNT
        or type(evidence.terminal_registry_sha256) is not str
        or evidence.terminal_registry_sha256
        != FROZEN_TWELFTH_REGISTRY_SHA256
        or evidence.terminal_registry_sha256 != twelfth.registry_sha256
        or type(evidence.terminal_cumulative_suite_sha256) is not str
        or evidence.terminal_cumulative_suite_sha256
        != FROZEN_TWELFTH_CUMULATIVE_SUITE_SHA256
        or evidence.terminal_cumulative_suite_sha256
        != twelfth.cumulative_suite_sha256
    ):
        raise TwelfthPredecessorEvidenceError(
            "through-twelfth task metadata differs from the frozen chain"
        )

    try:
        task_ids = tuple(task.task_id for task in evidence.tasks)
        task_contracts = tuple(
            task.task_contract_sha256 for task in evidence.tasks
        )
        graph_hashes = tuple(task.graph_sha256 for task in evidence.tasks)
    except (AttributeError, TypeError, ValueError) as exc:
        raise TwelfthPredecessorEvidenceError(
            "through-twelfth task identities cannot be inspected"
        ) from exc
    if (
        len(set(task_ids)) != TWELFTH_PREFIX_TASK_COUNT
        or len(set(task_contracts)) != TWELFTH_PREFIX_TASK_COUNT
        or len(set(graph_hashes)) != TWELFTH_PREFIX_TASK_COUNT
        or _observed_family_order(evidence.tasks)
        != TWELFTH_PREFIX_FAMILY_ORDER
    ):
        raise TwelfthPredecessorEvidenceError(
            "task identities collide or family order is not canonical"
        )


def verify_twelfth_prefix_task_evidence(evidence: object) -> bool:
    """Return whether ``evidence`` is the exact through-twelfth task prefix."""

    try:
        validate_twelfth_prefix_task_evidence(  # type: ignore[arg-type]
            evidence
        )
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def build_twelfth_prefix_task_evidence(
    eleventh_evidence: EleventhPrefixTaskEvidence | None = None,
) -> TwelfthPrefixTaskEvidence:
    """Build the first eleven once and append one non-recursive registry."""

    selected_eleventh = (
        build_eleventh_prefix_task_evidence()
        if eleventh_evidence is None
        else eleventh_evidence
    )
    validate_eleventh_prefix_task_evidence(selected_eleventh)
    twelfth = build_twelfth_tranche_task_registry(selected_eleventh)
    return TwelfthPrefixTaskEvidence(
        eleventh_evidence=selected_eleventh,
        twelfth_registry=twelfth,
        tasks=(*selected_eleventh.tasks, *twelfth.added_tasks),
    )


@dataclass(frozen=True, slots=True)
class TwelfthPrefixFixtureEvidence:
    """Fresh first-through-twelfth fixture evidence for a thirteenth catalog."""

    task_evidence: TwelfthPrefixTaskEvidence = field(repr=False)
    eleventh_evidence: EleventhPrefixFixtureEvidence = field(repr=False)
    twelfth_catalog: TwelfthTrancheFixtureCatalog = field(repr=False)
    bundles: tuple[object, ...] = field(repr=False)
    total_fixture_count: int = TWELFTH_PREFIX_FIXTURE_COUNT
    profiles_per_task: int = TWELFTH_PREFIX_PROFILE_COUNT
    terminal_catalog_sha256: str = FROZEN_TWELFTH_CATALOG_SHA256

    def __post_init__(self) -> None:
        validate_twelfth_prefix_fixture_evidence(self)

    @property
    def catalogs(self) -> tuple[object, ...]:
        """Return all twelve catalogs without retaining a mutable cache."""

        return (
            *self.eleventh_evidence.catalogs,
            self.twelfth_catalog,
        )


def validate_twelfth_prefix_fixture_evidence(
    evidence: TwelfthPrefixFixtureEvidence,
) -> None:
    """Validate the exact fixture prefix and every task/profile binding."""

    if type(evidence) is not TwelfthPrefixFixtureEvidence:
        raise TwelfthPredecessorEvidenceError(
            "fixture evidence must be an exact TwelfthPrefixFixtureEvidence"
        )
    if type(evidence.task_evidence) is not TwelfthPrefixTaskEvidence:
        raise TwelfthPredecessorEvidenceError(
            "fixture evidence has the wrong task-prefix type"
        )
    if type(evidence.eleventh_evidence) is not EleventhPrefixFixtureEvidence:
        raise TwelfthPredecessorEvidenceError(
            "fixture evidence has the wrong eleventh fixture type"
        )
    if type(evidence.twelfth_catalog) is not TwelfthTrancheFixtureCatalog:
        raise TwelfthPredecessorEvidenceError(
            "fixture evidence has the wrong twelfth catalog type"
        )
    try:
        validate_twelfth_prefix_task_evidence(evidence.task_evidence)
        validate_eleventh_prefix_fixture_evidence(evidence.eleventh_evidence)
        twelfth_record = evidence.twelfth_catalog.to_hash_only_record()
    except (AttributeError, TypeError, ValueError) as exc:
        raise TwelfthPredecessorEvidenceError(
            "a through-twelfth fixture component is invalid"
        ) from exc

    tasks = evidence.task_evidence
    eleventh = evidence.eleventh_evidence
    twelfth = evidence.twelfth_catalog
    if (
        eleventh.task_evidence is not tasks.eleventh_evidence
        or eleventh.total_fixture_count != ELEVENTH_PREFIX_FIXTURE_COUNT
        or eleventh.terminal_catalog_sha256
        != FROZEN_ELEVENTH_CATALOG_SHA256
        or twelfth.registry is not tasks.twelfth_registry
        or twelfth.base_fixture_catalog_sha256
        != eleventh.terminal_catalog_sha256
        or twelfth.catalog_sha256 != FROZEN_TWELFTH_CATALOG_SHA256
        or twelfth_record.get("catalog_sha256")
        != FROZEN_TWELFTH_CATALOG_SHA256
        or len(twelfth.bundles)
        != TWELFTH_TRANCHE_ADDED_FIXTURE_COUNT
    ):
        raise TwelfthPredecessorEvidenceError(
            "twelfth catalog does not extend the exact eleventh fixture "
            "evidence"
        )

    expected_bundles = (*eleventh.bundles, *twelfth.bundles)
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
        raise TwelfthPredecessorEvidenceError(
            "cumulative fixtures are not the exact prefix concatenation"
        )
    if any(
        bundle is predecessor
        for bundle in twelfth.bundles
        for predecessor in eleventh.bundles
    ):
        raise TwelfthPredecessorEvidenceError(
            "twelfth fixtures do not have fresh object ownership"
        )
    if (
        type(evidence.total_fixture_count) is not int
        or evidence.total_fixture_count != TWELFTH_PREFIX_FIXTURE_COUNT
        or len(evidence.bundles) != TWELFTH_PREFIX_FIXTURE_COUNT
        or type(evidence.profiles_per_task) is not int
        or evidence.profiles_per_task != TWELFTH_PREFIX_PROFILE_COUNT
        or len(evidence.bundles)
        != len(tasks.tasks) * evidence.profiles_per_task
        or type(evidence.terminal_catalog_sha256) is not str
        or evidence.terminal_catalog_sha256
        != FROZEN_TWELFTH_CATALOG_SHA256
        or evidence.terminal_catalog_sha256 != twelfth.catalog_sha256
    ):
        raise TwelfthPredecessorEvidenceError(
            "through-twelfth fixture metadata differs from the frozen chain"
        )

    fixture_ids: set[str] = set()
    fixture_hashes: set[str] = set()
    try:
        for index, bundle in enumerate(evidence.bundles):
            task = tasks.tasks[index // TWELFTH_PREFIX_PROFILE_COUNT]
            profile_index = index % TWELFTH_PREFIX_PROFILE_COUNT
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
                raise TwelfthPredecessorEvidenceError(
                    "fixture order, descriptor binding, or authority is invalid"
                )
            fixture_ids.add(bundle.descriptor.fixture_id)
            fixture_hashes.add(bundle.descriptor.fixture_sha256)
    except (AttributeError, TypeError, ValueError) as exc:
        if isinstance(exc, TwelfthPredecessorEvidenceError):
            raise
        raise TwelfthPredecessorEvidenceError(
            "through-twelfth fixture identities cannot be inspected"
        ) from exc
    if (
        len(fixture_ids) != TWELFTH_PREFIX_FIXTURE_COUNT
        or len(fixture_hashes) != TWELFTH_PREFIX_FIXTURE_COUNT
    ):
        raise TwelfthPredecessorEvidenceError(
            "fixture identities collide across the through-twelfth prefix"
        )


def verify_twelfth_prefix_fixture_evidence(evidence: object) -> bool:
    """Return whether ``evidence`` is the exact through-twelfth prefix."""

    try:
        validate_twelfth_prefix_fixture_evidence(  # type: ignore[arg-type]
            evidence
        )
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def build_twelfth_prefix_fixture_evidence(
    task_evidence: TwelfthPrefixTaskEvidence | None = None,
) -> TwelfthPrefixFixtureEvidence:
    """Build each first-through-twelfth catalog locally exactly once."""

    selected_tasks = (
        build_twelfth_prefix_task_evidence()
        if task_evidence is None
        else task_evidence
    )
    validate_twelfth_prefix_task_evidence(selected_tasks)
    eleventh = build_eleventh_prefix_fixture_evidence(
        selected_tasks.eleventh_evidence
    )
    twelfth = build_twelfth_tranche_fixture_catalog_local(
        selected_tasks.twelfth_registry
    )
    return TwelfthPrefixFixtureEvidence(
        task_evidence=selected_tasks,
        eleventh_evidence=eleventh,
        twelfth_catalog=twelfth,
        bundles=(*eleventh.bundles, *twelfth.bundles),
    )


__all__ = [
    "FROZEN_TWELFTH_CATALOG_SHA256",
    "FROZEN_TWELFTH_CUMULATIVE_SUITE_SHA256",
    "FROZEN_TWELFTH_REGISTRY_SHA256",
    "TWELFTH_PREFIX_FAMILY_ORDER",
    "TWELFTH_PREFIX_FIXTURE_COUNT",
    "TWELFTH_PREFIX_PROFILE_COUNT",
    "TWELFTH_PREFIX_TASK_COUNT",
    "TwelfthPredecessorEvidenceError",
    "TwelfthPrefixFixtureEvidence",
    "TwelfthPrefixTaskEvidence",
    "build_twelfth_prefix_fixture_evidence",
    "build_twelfth_prefix_task_evidence",
    "validate_twelfth_prefix_fixture_evidence",
    "validate_twelfth_prefix_task_evidence",
    "verify_twelfth_prefix_fixture_evidence",
    "verify_twelfth_prefix_task_evidence",
]
