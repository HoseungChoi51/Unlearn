"""Hash-neutral non-recursive evidence through the eleventh tranche.

The frozen ``executable_tenth_predecessor_evidence`` module deliberately
ends at the tenth tranche because its 380-task and 1,900-fixture identities
are inputs to the eleventh registry and coverage v4.  This module extends
that evidence without changing it: one first-through-tenth task snapshot is
reused to build the eleventh registry, and the same task snapshot is then
reused to build the first-through-tenth fixture evidence and the eleventh
local catalog.

The resulting prefix is suitable as predecessor evidence for a twelfth
additive tranche.  No historical recursive publication builder is called,
and no new record or digest is introduced.  Every build is call-scoped and
uncached; the terminal identities are the already frozen eleventh registry,
cumulative suite, and catalog hashes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

from .executable_fixture_eleventh_catalog import (
    ELEVENTH_TRANCHE_ADDED_FIXTURE_COUNT,
    ELEVENTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT,
    EleventhTrancheFixtureCatalog,
    build_eleventh_tranche_fixture_catalog_local,
)
from .executable_fixture_profiles import (
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from .executable_static_eleventh_registry import (
    ELEVENTH_TRANCHE_ADDED_TASK_COUNT,
    ELEVENTH_TRANCHE_CUMULATIVE_TASK_COUNT,
    ELEVENTH_TRANCHE_FAMILY_ORDER,
    EleventhTrancheTaskRegistry,
    build_eleventh_tranche_task_registry,
    validate_eleventh_tranche_task_registry,
)
from .executable_tenth_predecessor_evidence import (
    FROZEN_TENTH_CATALOG_SHA256,
    TENTH_PREFIX_FAMILY_ORDER,
    TENTH_PREFIX_FIXTURE_COUNT,
    TENTH_PREFIX_PROFILE_COUNT,
    TENTH_PREFIX_TASK_COUNT,
    TenthPrefixFixtureEvidence,
    TenthPrefixTaskEvidence,
    build_tenth_prefix_fixture_evidence,
    build_tenth_prefix_task_evidence,
    validate_tenth_prefix_fixture_evidence,
    validate_tenth_prefix_task_evidence,
)


ELEVENTH_PREFIX_TASK_COUNT: Final[int] = (
    ELEVENTH_TRANCHE_CUMULATIVE_TASK_COUNT
)
ELEVENTH_PREFIX_FIXTURE_COUNT: Final[int] = (
    ELEVENTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT
)
ELEVENTH_PREFIX_PROFILE_COUNT: Final[int] = TENTH_PREFIX_PROFILE_COUNT
ELEVENTH_PREFIX_FAMILY_ORDER: Final[tuple[str, ...]] = (
    *TENTH_PREFIX_FAMILY_ORDER,
    *ELEVENTH_TRANCHE_FAMILY_ORDER,
)

FROZEN_ELEVENTH_REGISTRY_SHA256: Final[str] = (
    "bd0c14880eb25fa80100c317fa41086c45c59147407a67f03981831bcfdfc100"
)
FROZEN_ELEVENTH_CUMULATIVE_SUITE_SHA256: Final[str] = (
    "f62ba1c1214fc48f194a5dea9c69c04962cc14dbdccfc38640cf4eee833018cb"
)
FROZEN_ELEVENTH_CATALOG_SHA256: Final[str] = (
    "cd4221870ba4bfd5ade5098bddccc15af47865930bf173f05141194f3e0b8177"
)


class EleventhPredecessorEvidenceError(ValueError):
    """Raised when the through-eleventh prefix differs from its frozen chain."""


@dataclass(frozen=True, slots=True)
class EleventhPrefixTaskEvidence:
    """Fresh first-through-eleventh task evidence for a twelfth registry."""

    tenth_evidence: TenthPrefixTaskEvidence = field(repr=False)
    eleventh_registry: EleventhTrancheTaskRegistry = field(repr=False)
    tasks: tuple[object, ...] = field(repr=False)
    total_task_count: int = ELEVENTH_PREFIX_TASK_COUNT
    terminal_registry_sha256: str = FROZEN_ELEVENTH_REGISTRY_SHA256
    terminal_cumulative_suite_sha256: str = (
        FROZEN_ELEVENTH_CUMULATIVE_SUITE_SHA256
    )

    def __post_init__(self) -> None:
        validate_eleventh_prefix_task_evidence(self)

    @property
    def registries(self) -> tuple[object, ...]:
        """Return all eleven registries without retaining a mutable cache."""

        return (*self.tenth_evidence.registries, self.eleventh_registry)


def validate_eleventh_prefix_task_evidence(
    evidence: EleventhPrefixTaskEvidence,
) -> None:
    """Validate the exact task prefix without rebuilding a task."""

    if type(evidence) is not EleventhPrefixTaskEvidence:
        raise EleventhPredecessorEvidenceError(
            "task evidence must be an exact EleventhPrefixTaskEvidence"
        )
    if type(evidence.tenth_evidence) is not TenthPrefixTaskEvidence:
        raise EleventhPredecessorEvidenceError(
            "task evidence has the wrong tenth-prefix type"
        )
    if type(evidence.eleventh_registry) is not EleventhTrancheTaskRegistry:
        raise EleventhPredecessorEvidenceError(
            "task evidence has the wrong eleventh registry type"
        )
    try:
        validate_tenth_prefix_task_evidence(evidence.tenth_evidence)
        validate_eleventh_tranche_task_registry(evidence.eleventh_registry)
    except (AttributeError, TypeError, ValueError) as exc:
        raise EleventhPredecessorEvidenceError(
            "a through-eleventh task component is invalid"
        ) from exc

    tenth = evidence.tenth_evidence
    eleventh = evidence.eleventh_registry
    if (
        tenth.total_task_count != TENTH_PREFIX_TASK_COUNT
        or eleventh.base_added_registry_sha256
        != tenth.terminal_registry_sha256
        or eleventh.base_cumulative_suite_sha256
        != tenth.terminal_cumulative_suite_sha256
        or eleventh.registry_sha256 != FROZEN_ELEVENTH_REGISTRY_SHA256
        or eleventh.cumulative_suite_sha256
        != FROZEN_ELEVENTH_CUMULATIVE_SUITE_SHA256
        or len(eleventh.added_tasks) != ELEVENTH_TRANCHE_ADDED_TASK_COUNT
    ):
        raise EleventhPredecessorEvidenceError(
            "eleventh registry does not extend the frozen tenth-prefix "
            "evidence"
        )

    expected_tasks = (*tenth.tasks, *eleventh.added_tasks)
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
        raise EleventhPredecessorEvidenceError(
            "cumulative tasks are not the exact prefix concatenation"
        )
    if (
        type(evidence.total_task_count) is not int
        or evidence.total_task_count != ELEVENTH_PREFIX_TASK_COUNT
        or len(evidence.tasks) != ELEVENTH_PREFIX_TASK_COUNT
        or type(evidence.terminal_registry_sha256) is not str
        or evidence.terminal_registry_sha256
        != FROZEN_ELEVENTH_REGISTRY_SHA256
        or evidence.terminal_registry_sha256 != eleventh.registry_sha256
        or type(evidence.terminal_cumulative_suite_sha256) is not str
        or evidence.terminal_cumulative_suite_sha256
        != FROZEN_ELEVENTH_CUMULATIVE_SUITE_SHA256
        or evidence.terminal_cumulative_suite_sha256
        != eleventh.cumulative_suite_sha256
    ):
        raise EleventhPredecessorEvidenceError(
            "through-eleventh task metadata differs from the frozen chain"
        )

    try:
        task_ids = tuple(task.task_id for task in evidence.tasks)
        task_contracts = tuple(
            task.task_contract_sha256 for task in evidence.tasks
        )
        graph_hashes = tuple(task.graph_sha256 for task in evidence.tasks)
        observed_family_order = tuple(
            task.family_id
            for index, task in enumerate(evidence.tasks)
            if index == 0
            or task.family_id != evidence.tasks[index - 1].family_id
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise EleventhPredecessorEvidenceError(
            "through-eleventh task identities cannot be inspected"
        ) from exc
    if (
        len(set(task_ids)) != ELEVENTH_PREFIX_TASK_COUNT
        or len(set(task_contracts)) != ELEVENTH_PREFIX_TASK_COUNT
        or len(set(graph_hashes)) != ELEVENTH_PREFIX_TASK_COUNT
        or observed_family_order != ELEVENTH_PREFIX_FAMILY_ORDER
    ):
        raise EleventhPredecessorEvidenceError(
            "task identities collide or family order is not canonical"
        )


def verify_eleventh_prefix_task_evidence(evidence: object) -> bool:
    """Return whether ``evidence`` is the exact through-eleventh task prefix."""

    try:
        validate_eleventh_prefix_task_evidence(  # type: ignore[arg-type]
            evidence
        )
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def build_eleventh_prefix_task_evidence(
    tenth_evidence: TenthPrefixTaskEvidence | None = None,
) -> EleventhPrefixTaskEvidence:
    """Build the first ten once and append one non-recursive registry."""

    selected_tenth = (
        build_tenth_prefix_task_evidence()
        if tenth_evidence is None
        else tenth_evidence
    )
    validate_tenth_prefix_task_evidence(selected_tenth)
    eleventh = build_eleventh_tranche_task_registry(selected_tenth)
    return EleventhPrefixTaskEvidence(
        tenth_evidence=selected_tenth,
        eleventh_registry=eleventh,
        tasks=(*selected_tenth.tasks, *eleventh.added_tasks),
    )


@dataclass(frozen=True, slots=True)
class EleventhPrefixFixtureEvidence:
    """Fresh first-through-eleventh fixture evidence for a twelfth catalog."""

    task_evidence: EleventhPrefixTaskEvidence = field(repr=False)
    tenth_evidence: TenthPrefixFixtureEvidence = field(repr=False)
    eleventh_catalog: EleventhTrancheFixtureCatalog = field(repr=False)
    bundles: tuple[object, ...] = field(repr=False)
    total_fixture_count: int = ELEVENTH_PREFIX_FIXTURE_COUNT
    profiles_per_task: int = ELEVENTH_PREFIX_PROFILE_COUNT
    terminal_catalog_sha256: str = FROZEN_ELEVENTH_CATALOG_SHA256

    def __post_init__(self) -> None:
        validate_eleventh_prefix_fixture_evidence(self)

    @property
    def catalogs(self) -> tuple[object, ...]:
        """Return all eleven catalogs without retaining a mutable cache."""

        return (*self.tenth_evidence.catalogs, self.eleventh_catalog)


def validate_eleventh_prefix_fixture_evidence(
    evidence: EleventhPrefixFixtureEvidence,
) -> None:
    """Validate the exact fixture prefix and every task/profile binding."""

    if type(evidence) is not EleventhPrefixFixtureEvidence:
        raise EleventhPredecessorEvidenceError(
            "fixture evidence must be an exact EleventhPrefixFixtureEvidence"
        )
    if type(evidence.task_evidence) is not EleventhPrefixTaskEvidence:
        raise EleventhPredecessorEvidenceError(
            "fixture evidence has the wrong task-prefix type"
        )
    if type(evidence.tenth_evidence) is not TenthPrefixFixtureEvidence:
        raise EleventhPredecessorEvidenceError(
            "fixture evidence has the wrong tenth fixture type"
        )
    if type(evidence.eleventh_catalog) is not EleventhTrancheFixtureCatalog:
        raise EleventhPredecessorEvidenceError(
            "fixture evidence has the wrong eleventh catalog type"
        )
    try:
        validate_eleventh_prefix_task_evidence(evidence.task_evidence)
        validate_tenth_prefix_fixture_evidence(evidence.tenth_evidence)
        eleventh_record = evidence.eleventh_catalog.to_hash_only_record()
    except (AttributeError, TypeError, ValueError) as exc:
        raise EleventhPredecessorEvidenceError(
            "a through-eleventh fixture component is invalid"
        ) from exc

    tasks = evidence.task_evidence
    tenth = evidence.tenth_evidence
    eleventh = evidence.eleventh_catalog
    if (
        tenth.task_evidence is not tasks.tenth_evidence
        or tenth.total_fixture_count != TENTH_PREFIX_FIXTURE_COUNT
        or tenth.terminal_catalog_sha256 != FROZEN_TENTH_CATALOG_SHA256
        or eleventh.registry is not tasks.eleventh_registry
        or eleventh.base_fixture_catalog_sha256
        != tenth.terminal_catalog_sha256
        or eleventh.catalog_sha256 != FROZEN_ELEVENTH_CATALOG_SHA256
        or eleventh_record.get("catalog_sha256")
        != FROZEN_ELEVENTH_CATALOG_SHA256
        or len(eleventh.bundles)
        != ELEVENTH_TRANCHE_ADDED_FIXTURE_COUNT
    ):
        raise EleventhPredecessorEvidenceError(
            "eleventh catalog does not extend the exact tenth fixture "
            "evidence"
        )

    expected_bundles = (*tenth.bundles, *eleventh.bundles)
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
        raise EleventhPredecessorEvidenceError(
            "cumulative fixtures are not the exact prefix concatenation"
        )
    if (
        type(evidence.total_fixture_count) is not int
        or evidence.total_fixture_count != ELEVENTH_PREFIX_FIXTURE_COUNT
        or len(evidence.bundles) != ELEVENTH_PREFIX_FIXTURE_COUNT
        or type(evidence.profiles_per_task) is not int
        or evidence.profiles_per_task != ELEVENTH_PREFIX_PROFILE_COUNT
        or len(evidence.bundles)
        != len(tasks.tasks) * evidence.profiles_per_task
        or type(evidence.terminal_catalog_sha256) is not str
        or evidence.terminal_catalog_sha256
        != FROZEN_ELEVENTH_CATALOG_SHA256
        or evidence.terminal_catalog_sha256 != eleventh.catalog_sha256
    ):
        raise EleventhPredecessorEvidenceError(
            "through-eleventh fixture metadata differs from the frozen chain"
        )

    fixture_ids: set[str] = set()
    fixture_hashes: set[str] = set()
    try:
        for index, bundle in enumerate(evidence.bundles):
            task = tasks.tasks[index // ELEVENTH_PREFIX_PROFILE_COUNT]
            profile_index = index % ELEVENTH_PREFIX_PROFILE_COUNT
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
                raise EleventhPredecessorEvidenceError(
                    "fixture order, descriptor binding, or authority is invalid"
                )
            fixture_ids.add(bundle.descriptor.fixture_id)
            fixture_hashes.add(bundle.descriptor.fixture_sha256)
    except (AttributeError, TypeError, ValueError) as exc:
        if isinstance(exc, EleventhPredecessorEvidenceError):
            raise
        raise EleventhPredecessorEvidenceError(
            "through-eleventh fixture identities cannot be inspected"
        ) from exc
    if (
        len(fixture_ids) != ELEVENTH_PREFIX_FIXTURE_COUNT
        or len(fixture_hashes) != ELEVENTH_PREFIX_FIXTURE_COUNT
    ):
        raise EleventhPredecessorEvidenceError(
            "fixture identities collide across the through-eleventh prefix"
        )


def verify_eleventh_prefix_fixture_evidence(evidence: object) -> bool:
    """Return whether ``evidence`` is the exact through-eleventh prefix."""

    try:
        validate_eleventh_prefix_fixture_evidence(  # type: ignore[arg-type]
            evidence
        )
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def build_eleventh_prefix_fixture_evidence(
    task_evidence: EleventhPrefixTaskEvidence | None = None,
) -> EleventhPrefixFixtureEvidence:
    """Build each first-through-eleventh catalog locally exactly once."""

    selected_tasks = (
        build_eleventh_prefix_task_evidence()
        if task_evidence is None
        else task_evidence
    )
    validate_eleventh_prefix_task_evidence(selected_tasks)
    tenth = build_tenth_prefix_fixture_evidence(
        selected_tasks.tenth_evidence
    )
    eleventh = build_eleventh_tranche_fixture_catalog_local(
        selected_tasks.eleventh_registry
    )
    return EleventhPrefixFixtureEvidence(
        task_evidence=selected_tasks,
        tenth_evidence=tenth,
        eleventh_catalog=eleventh,
        bundles=(*tenth.bundles, *eleventh.bundles),
    )


__all__ = [
    "ELEVENTH_PREFIX_FAMILY_ORDER",
    "ELEVENTH_PREFIX_FIXTURE_COUNT",
    "ELEVENTH_PREFIX_PROFILE_COUNT",
    "ELEVENTH_PREFIX_TASK_COUNT",
    "FROZEN_ELEVENTH_CATALOG_SHA256",
    "FROZEN_ELEVENTH_CUMULATIVE_SUITE_SHA256",
    "FROZEN_ELEVENTH_REGISTRY_SHA256",
    "EleventhPredecessorEvidenceError",
    "EleventhPrefixFixtureEvidence",
    "EleventhPrefixTaskEvidence",
    "build_eleventh_prefix_fixture_evidence",
    "build_eleventh_prefix_task_evidence",
    "validate_eleventh_prefix_fixture_evidence",
    "validate_eleventh_prefix_task_evidence",
    "verify_eleventh_prefix_fixture_evidence",
    "verify_eleventh_prefix_task_evidence",
]
