"""Hash-neutral non-recursive evidence through the tenth tranche.

The frozen ``executable_ninth_predecessor_evidence`` module deliberately
ends at the ninth tranche because its 360-task and 1,800-fixture identities
are inputs to the tenth registry and coverage v3.  This module extends that
evidence without changing it: one first-through-ninth snapshot is reused to
build the tenth registry, and the same task snapshot is then reused to build
the first-through-ninth fixture evidence and the tenth local catalog.

The resulting prefix is suitable as predecessor evidence for an eleventh
additive tranche.  No historical recursive publication builder is called,
and no new record or digest is introduced.  Every build is call-scoped and
uncached; the terminal identities are the already frozen tenth registry,
cumulative suite, and catalog hashes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

from .executable_fixture_profiles import (
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from .executable_fixture_tenth_catalog import (
    TENTH_TRANCHE_ADDED_FIXTURE_COUNT,
    TENTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT,
    TenthTrancheFixtureCatalog,
    build_tenth_tranche_fixture_catalog_local,
)
from .executable_ninth_predecessor_evidence import (
    FROZEN_NINTH_CATALOG_SHA256,
    NINTH_PREFIX_FAMILY_ORDER,
    NINTH_PREFIX_FIXTURE_COUNT,
    NINTH_PREFIX_PROFILE_COUNT,
    NINTH_PREFIX_TASK_COUNT,
    NinthPrefixFixtureEvidence,
    NinthPrefixTaskEvidence,
    build_ninth_prefix_fixture_evidence,
    build_ninth_prefix_task_evidence,
    validate_ninth_prefix_fixture_evidence,
    validate_ninth_prefix_task_evidence,
)
from .executable_static_tenth_registry import (
    TENTH_TRANCHE_ADDED_TASK_COUNT,
    TENTH_TRANCHE_CUMULATIVE_TASK_COUNT,
    TENTH_TRANCHE_FAMILY_ORDER,
    TenthTrancheTaskRegistry,
    build_tenth_tranche_task_registry,
    validate_tenth_tranche_task_registry,
)


TENTH_PREFIX_TASK_COUNT: Final[int] = TENTH_TRANCHE_CUMULATIVE_TASK_COUNT
TENTH_PREFIX_FIXTURE_COUNT: Final[int] = (
    TENTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT
)
TENTH_PREFIX_PROFILE_COUNT: Final[int] = NINTH_PREFIX_PROFILE_COUNT
TENTH_PREFIX_FAMILY_ORDER: Final[tuple[str, ...]] = (
    *NINTH_PREFIX_FAMILY_ORDER,
    *TENTH_TRANCHE_FAMILY_ORDER,
)

FROZEN_TENTH_REGISTRY_SHA256: Final[str] = (
    "0d07fd82de275ffd9dc274b97a6fa02fdd0620f83d5ee90a2bea0ad64f06f0ab"
)
FROZEN_TENTH_CUMULATIVE_SUITE_SHA256: Final[str] = (
    "629119116c53a0be2cc7cacb5461ae13de7d50f29b0a129707a840089ab48d2f"
)
FROZEN_TENTH_CATALOG_SHA256: Final[str] = (
    "5a29ea69111028fe69322d892e061a723ab53fb857ce4077cca924e314a4f4d6"
)


class TenthPredecessorEvidenceError(ValueError):
    """Raised when the through-tenth prefix differs from its frozen chain."""


@dataclass(frozen=True, slots=True)
class TenthPrefixTaskEvidence:
    """Fresh first-through-tenth task evidence for an eleventh registry."""

    ninth_evidence: NinthPrefixTaskEvidence = field(repr=False)
    tenth_registry: TenthTrancheTaskRegistry = field(repr=False)
    tasks: tuple[object, ...] = field(repr=False)
    total_task_count: int = TENTH_PREFIX_TASK_COUNT
    terminal_registry_sha256: str = FROZEN_TENTH_REGISTRY_SHA256
    terminal_cumulative_suite_sha256: str = (
        FROZEN_TENTH_CUMULATIVE_SUITE_SHA256
    )

    def __post_init__(self) -> None:
        validate_tenth_prefix_task_evidence(self)

    @property
    def registries(self) -> tuple[object, ...]:
        """Return all ten registries without retaining a mutable cache."""

        return (*self.ninth_evidence.registries, self.tenth_registry)


def validate_tenth_prefix_task_evidence(
    evidence: TenthPrefixTaskEvidence,
) -> None:
    """Validate the exact task prefix without rebuilding a task."""

    if type(evidence) is not TenthPrefixTaskEvidence:
        raise TenthPredecessorEvidenceError(
            "task evidence must be an exact TenthPrefixTaskEvidence"
        )
    if type(evidence.ninth_evidence) is not NinthPrefixTaskEvidence:
        raise TenthPredecessorEvidenceError(
            "task evidence has the wrong ninth-prefix type"
        )
    if type(evidence.tenth_registry) is not TenthTrancheTaskRegistry:
        raise TenthPredecessorEvidenceError(
            "task evidence has the wrong tenth registry type"
        )
    try:
        validate_ninth_prefix_task_evidence(evidence.ninth_evidence)
        validate_tenth_tranche_task_registry(evidence.tenth_registry)
    except (AttributeError, TypeError, ValueError) as exc:
        raise TenthPredecessorEvidenceError(
            "a through-tenth task component is invalid"
        ) from exc

    ninth = evidence.ninth_evidence
    tenth = evidence.tenth_registry
    if (
        ninth.total_task_count != NINTH_PREFIX_TASK_COUNT
        or tenth.base_added_registry_sha256
        != ninth.terminal_registry_sha256
        or tenth.base_cumulative_suite_sha256
        != ninth.terminal_cumulative_suite_sha256
        or tenth.registry_sha256 != FROZEN_TENTH_REGISTRY_SHA256
        or tenth.cumulative_suite_sha256
        != FROZEN_TENTH_CUMULATIVE_SUITE_SHA256
        or len(tenth.added_tasks) != TENTH_TRANCHE_ADDED_TASK_COUNT
    ):
        raise TenthPredecessorEvidenceError(
            "tenth registry does not extend the frozen ninth-prefix evidence"
        )

    expected_tasks = (*ninth.tasks, *tenth.added_tasks)
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
        raise TenthPredecessorEvidenceError(
            "cumulative tasks are not the exact prefix concatenation"
        )
    if (
        type(evidence.total_task_count) is not int
        or evidence.total_task_count != TENTH_PREFIX_TASK_COUNT
        or len(evidence.tasks) != TENTH_PREFIX_TASK_COUNT
        or type(evidence.terminal_registry_sha256) is not str
        or evidence.terminal_registry_sha256
        != FROZEN_TENTH_REGISTRY_SHA256
        or evidence.terminal_registry_sha256 != tenth.registry_sha256
        or type(evidence.terminal_cumulative_suite_sha256) is not str
        or evidence.terminal_cumulative_suite_sha256
        != FROZEN_TENTH_CUMULATIVE_SUITE_SHA256
        or evidence.terminal_cumulative_suite_sha256
        != tenth.cumulative_suite_sha256
    ):
        raise TenthPredecessorEvidenceError(
            "through-tenth task metadata differs from the frozen chain"
        )

    try:
        task_ids = tuple(task.task_id for task in evidence.tasks)
        task_contracts = tuple(
            task.task_contract_sha256 for task in evidence.tasks
        )
        graph_hashes = tuple(
            task.graph_sha256 for task in evidence.tasks
        )
        observed_family_order = tuple(
            task.family_id
            for index, task in enumerate(evidence.tasks)
            if index == 0
            or task.family_id != evidence.tasks[index - 1].family_id
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise TenthPredecessorEvidenceError(
            "through-tenth task identities cannot be inspected"
        ) from exc
    if (
        len(set(task_ids)) != TENTH_PREFIX_TASK_COUNT
        or len(set(task_contracts)) != TENTH_PREFIX_TASK_COUNT
        or len(set(graph_hashes)) != TENTH_PREFIX_TASK_COUNT
        or observed_family_order != TENTH_PREFIX_FAMILY_ORDER
    ):
        raise TenthPredecessorEvidenceError(
            "task identities collide or family order is not canonical"
        )


def verify_tenth_prefix_task_evidence(evidence: object) -> bool:
    """Return whether ``evidence`` is the exact through-tenth task prefix."""

    try:
        validate_tenth_prefix_task_evidence(  # type: ignore[arg-type]
            evidence
        )
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def build_tenth_prefix_task_evidence(
    ninth_evidence: NinthPrefixTaskEvidence | None = None,
) -> TenthPrefixTaskEvidence:
    """Build the first nine once and append one non-recursive tenth registry."""

    selected_ninth = (
        build_ninth_prefix_task_evidence()
        if ninth_evidence is None
        else ninth_evidence
    )
    validate_ninth_prefix_task_evidence(selected_ninth)
    tenth = build_tenth_tranche_task_registry(selected_ninth)
    return TenthPrefixTaskEvidence(
        ninth_evidence=selected_ninth,
        tenth_registry=tenth,
        tasks=(*selected_ninth.tasks, *tenth.added_tasks),
    )


@dataclass(frozen=True, slots=True)
class TenthPrefixFixtureEvidence:
    """Fresh first-through-tenth fixture evidence for an eleventh catalog."""

    task_evidence: TenthPrefixTaskEvidence = field(repr=False)
    ninth_evidence: NinthPrefixFixtureEvidence = field(repr=False)
    tenth_catalog: TenthTrancheFixtureCatalog = field(repr=False)
    bundles: tuple[object, ...] = field(repr=False)
    total_fixture_count: int = TENTH_PREFIX_FIXTURE_COUNT
    profiles_per_task: int = TENTH_PREFIX_PROFILE_COUNT
    terminal_catalog_sha256: str = FROZEN_TENTH_CATALOG_SHA256

    def __post_init__(self) -> None:
        validate_tenth_prefix_fixture_evidence(self)

    @property
    def catalogs(self) -> tuple[object, ...]:
        """Return all ten catalogs without retaining a mutable cache."""

        return (*self.ninth_evidence.catalogs, self.tenth_catalog)


def validate_tenth_prefix_fixture_evidence(
    evidence: TenthPrefixFixtureEvidence,
) -> None:
    """Validate the exact fixture prefix and every task/profile binding."""

    if type(evidence) is not TenthPrefixFixtureEvidence:
        raise TenthPredecessorEvidenceError(
            "fixture evidence must be an exact TenthPrefixFixtureEvidence"
        )
    if type(evidence.task_evidence) is not TenthPrefixTaskEvidence:
        raise TenthPredecessorEvidenceError(
            "fixture evidence has the wrong task-prefix type"
        )
    if type(evidence.ninth_evidence) is not NinthPrefixFixtureEvidence:
        raise TenthPredecessorEvidenceError(
            "fixture evidence has the wrong ninth fixture type"
        )
    if type(evidence.tenth_catalog) is not TenthTrancheFixtureCatalog:
        raise TenthPredecessorEvidenceError(
            "fixture evidence has the wrong tenth catalog type"
        )
    try:
        validate_tenth_prefix_task_evidence(evidence.task_evidence)
        validate_ninth_prefix_fixture_evidence(evidence.ninth_evidence)
        tenth_record = evidence.tenth_catalog.to_hash_only_record()
    except (AttributeError, TypeError, ValueError) as exc:
        raise TenthPredecessorEvidenceError(
            "a through-tenth fixture component is invalid"
        ) from exc

    tasks = evidence.task_evidence
    ninth = evidence.ninth_evidence
    tenth = evidence.tenth_catalog
    if (
        ninth.task_evidence is not tasks.ninth_evidence
        or ninth.total_fixture_count != NINTH_PREFIX_FIXTURE_COUNT
        or ninth.terminal_catalog_sha256 != FROZEN_NINTH_CATALOG_SHA256
        or tenth.registry is not tasks.tenth_registry
        or tenth.base_fixture_catalog_sha256
        != ninth.terminal_catalog_sha256
        or tenth.catalog_sha256 != FROZEN_TENTH_CATALOG_SHA256
        or tenth_record.get("catalog_sha256")
        != FROZEN_TENTH_CATALOG_SHA256
        or len(tenth.bundles) != TENTH_TRANCHE_ADDED_FIXTURE_COUNT
    ):
        raise TenthPredecessorEvidenceError(
            "tenth catalog does not extend the exact ninth fixture evidence"
        )

    expected_bundles = (*ninth.bundles, *tenth.bundles)
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
        raise TenthPredecessorEvidenceError(
            "cumulative fixtures are not the exact prefix concatenation"
        )
    if (
        type(evidence.total_fixture_count) is not int
        or evidence.total_fixture_count != TENTH_PREFIX_FIXTURE_COUNT
        or len(evidence.bundles) != TENTH_PREFIX_FIXTURE_COUNT
        or type(evidence.profiles_per_task) is not int
        or evidence.profiles_per_task != TENTH_PREFIX_PROFILE_COUNT
        or len(evidence.bundles)
        != len(tasks.tasks) * evidence.profiles_per_task
        or type(evidence.terminal_catalog_sha256) is not str
        or evidence.terminal_catalog_sha256
        != FROZEN_TENTH_CATALOG_SHA256
        or evidence.terminal_catalog_sha256 != tenth.catalog_sha256
    ):
        raise TenthPredecessorEvidenceError(
            "through-tenth fixture metadata differs from the frozen chain"
        )

    fixture_ids: set[str] = set()
    fixture_hashes: set[str] = set()
    try:
        for index, bundle in enumerate(evidence.bundles):
            task = tasks.tasks[index // TENTH_PREFIX_PROFILE_COUNT]
            profile_index = index % TENTH_PREFIX_PROFILE_COUNT
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
                raise TenthPredecessorEvidenceError(
                    "fixture order, descriptor binding, or authority is invalid"
                )
            fixture_ids.add(bundle.descriptor.fixture_id)
            fixture_hashes.add(bundle.descriptor.fixture_sha256)
    except (AttributeError, TypeError, ValueError) as exc:
        if isinstance(exc, TenthPredecessorEvidenceError):
            raise
        raise TenthPredecessorEvidenceError(
            "through-tenth fixture identities cannot be inspected"
        ) from exc
    if (
        len(fixture_ids) != TENTH_PREFIX_FIXTURE_COUNT
        or len(fixture_hashes) != TENTH_PREFIX_FIXTURE_COUNT
    ):
        raise TenthPredecessorEvidenceError(
            "fixture identities collide across the through-tenth prefix"
        )


def verify_tenth_prefix_fixture_evidence(evidence: object) -> bool:
    """Return whether ``evidence`` is the exact through-tenth fixture prefix."""

    try:
        validate_tenth_prefix_fixture_evidence(  # type: ignore[arg-type]
            evidence
        )
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def build_tenth_prefix_fixture_evidence(
    task_evidence: TenthPrefixTaskEvidence | None = None,
) -> TenthPrefixFixtureEvidence:
    """Build each first-through-tenth catalog locally exactly once."""

    selected_tasks = (
        build_tenth_prefix_task_evidence()
        if task_evidence is None
        else task_evidence
    )
    validate_tenth_prefix_task_evidence(selected_tasks)
    ninth = build_ninth_prefix_fixture_evidence(
        selected_tasks.ninth_evidence
    )
    tenth = build_tenth_tranche_fixture_catalog_local(
        selected_tasks.tenth_registry
    )
    return TenthPrefixFixtureEvidence(
        task_evidence=selected_tasks,
        ninth_evidence=ninth,
        tenth_catalog=tenth,
        bundles=(*ninth.bundles, *tenth.bundles),
    )


__all__ = [
    "FROZEN_TENTH_CATALOG_SHA256",
    "FROZEN_TENTH_CUMULATIVE_SUITE_SHA256",
    "FROZEN_TENTH_REGISTRY_SHA256",
    "TENTH_PREFIX_FAMILY_ORDER",
    "TENTH_PREFIX_FIXTURE_COUNT",
    "TENTH_PREFIX_PROFILE_COUNT",
    "TENTH_PREFIX_TASK_COUNT",
    "TenthPredecessorEvidenceError",
    "TenthPrefixFixtureEvidence",
    "TenthPrefixTaskEvidence",
    "build_tenth_prefix_fixture_evidence",
    "build_tenth_prefix_task_evidence",
    "validate_tenth_prefix_fixture_evidence",
    "validate_tenth_prefix_task_evidence",
    "verify_tenth_prefix_fixture_evidence",
    "verify_tenth_prefix_task_evidence",
]
