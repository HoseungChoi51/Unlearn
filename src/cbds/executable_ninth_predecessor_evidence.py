"""Hash-neutral non-recursive evidence through the ninth tranche.

The frozen ``executable_linear_predecessor_evidence`` module deliberately
ends at the eighth tranche because its 340-task and 1,700-fixture identities
are inputs to the ninth registry and coverage v2.  This module extends that
evidence without changing it: one first-through-eighth snapshot is reused to
build the ninth registry, and the same task snapshot is then reused to build
the first-through-eighth fixture evidence and the ninth local catalog.

The resulting prefix is suitable as predecessor evidence for a tenth
additive tranche.  No historical recursive publication builder is called,
and no new record or digest is introduced.  Every build is call-scoped and
uncached; the terminal identities are the already frozen ninth registry,
cumulative suite, and catalog hashes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

from .executable_fixture_ninth_catalog import (
    NINTH_TRANCHE_ADDED_FIXTURE_COUNT,
    NINTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT,
    NinthTrancheFixtureCatalog,
    build_ninth_tranche_fixture_catalog_local,
)
from .executable_fixture_profiles import (
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from .executable_linear_predecessor_evidence import (
    FROZEN_PREDECESSOR_CATALOG_SHA256,
    LINEAR_PREDECESSOR_FAMILY_ORDER,
    LINEAR_PREDECESSOR_FIXTURE_COUNT,
    LINEAR_PREDECESSOR_PROFILE_COUNT,
    LINEAR_PREDECESSOR_TASK_COUNT,
    LinearFixturePredecessorEvidence,
    LinearTaskPredecessorEvidence,
    build_linear_fixture_predecessor_evidence,
    build_linear_task_predecessor_evidence,
    validate_linear_fixture_predecessor_evidence,
    validate_linear_task_predecessor_evidence,
)
from .executable_static_ninth_registry import (
    NINTH_TRANCHE_ADDED_TASK_COUNT,
    NINTH_TRANCHE_CUMULATIVE_TASK_COUNT,
    NINTH_TRANCHE_FAMILY_ORDER,
    NinthTrancheTaskRegistry,
    build_ninth_tranche_task_registry,
    validate_ninth_tranche_task_registry,
)


NINTH_PREFIX_TASK_COUNT: Final[int] = NINTH_TRANCHE_CUMULATIVE_TASK_COUNT
NINTH_PREFIX_FIXTURE_COUNT: Final[int] = (
    NINTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT
)
NINTH_PREFIX_PROFILE_COUNT: Final[int] = LINEAR_PREDECESSOR_PROFILE_COUNT
NINTH_PREFIX_FAMILY_ORDER: Final[tuple[str, ...]] = (
    *LINEAR_PREDECESSOR_FAMILY_ORDER,
    *NINTH_TRANCHE_FAMILY_ORDER,
)

FROZEN_NINTH_REGISTRY_SHA256: Final[str] = (
    "ff886754b054445a90ad30197d004e4071dba72bf0af17931d05e461c7e90703"
)
FROZEN_NINTH_CUMULATIVE_SUITE_SHA256: Final[str] = (
    "d0647e24f29abd59f8c2d6b2ac2a404aee78b92c780f8be4f9b16d200885843b"
)
FROZEN_NINTH_CATALOG_SHA256: Final[str] = (
    "56932666f2641b5947e1801378b233dd5f37f568e4f2b4c6aa171bad115b09d8"
)


class NinthPredecessorEvidenceError(ValueError):
    """Raised when the through-ninth prefix differs from its frozen chain."""


@dataclass(frozen=True, slots=True)
class NinthPrefixTaskEvidence:
    """Fresh first-through-ninth task evidence for a tenth registry."""

    linear_evidence: LinearTaskPredecessorEvidence = field(repr=False)
    ninth_registry: NinthTrancheTaskRegistry = field(repr=False)
    tasks: tuple[object, ...] = field(repr=False)
    total_task_count: int = NINTH_PREFIX_TASK_COUNT
    terminal_registry_sha256: str = FROZEN_NINTH_REGISTRY_SHA256
    terminal_cumulative_suite_sha256: str = (
        FROZEN_NINTH_CUMULATIVE_SUITE_SHA256
    )

    def __post_init__(self) -> None:
        validate_ninth_prefix_task_evidence(self)

    @property
    def registries(self) -> tuple[object, ...]:
        """Return all nine registries without retaining a mutable cache."""

        return (*self.linear_evidence.registries, self.ninth_registry)


def validate_ninth_prefix_task_evidence(
    evidence: NinthPrefixTaskEvidence,
) -> None:
    """Validate the exact task prefix without rebuilding a task."""

    if type(evidence) is not NinthPrefixTaskEvidence:
        raise NinthPredecessorEvidenceError(
            "task evidence must be an exact NinthPrefixTaskEvidence"
        )
    if type(evidence.linear_evidence) is not LinearTaskPredecessorEvidence:
        raise NinthPredecessorEvidenceError(
            "task evidence has the wrong linear predecessor type"
        )
    if type(evidence.ninth_registry) is not NinthTrancheTaskRegistry:
        raise NinthPredecessorEvidenceError(
            "task evidence has the wrong ninth registry type"
        )
    try:
        validate_linear_task_predecessor_evidence(
            evidence.linear_evidence
        )
        validate_ninth_tranche_task_registry(evidence.ninth_registry)
    except (AttributeError, TypeError, ValueError) as exc:
        raise NinthPredecessorEvidenceError(
            "a through-ninth task component is invalid"
        ) from exc

    linear = evidence.linear_evidence
    ninth = evidence.ninth_registry
    if (
        linear.total_task_count != LINEAR_PREDECESSOR_TASK_COUNT
        or ninth.base_added_registry_sha256
        != linear.terminal_registry_sha256
        or ninth.base_cumulative_suite_sha256
        != linear.terminal_cumulative_suite_sha256
        or ninth.registry_sha256 != FROZEN_NINTH_REGISTRY_SHA256
        or ninth.cumulative_suite_sha256
        != FROZEN_NINTH_CUMULATIVE_SUITE_SHA256
        or len(ninth.added_tasks) != NINTH_TRANCHE_ADDED_TASK_COUNT
    ):
        raise NinthPredecessorEvidenceError(
            "ninth registry does not extend the frozen linear task evidence"
        )

    expected_tasks = (*linear.tasks, *ninth.added_tasks)
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
        raise NinthPredecessorEvidenceError(
            "cumulative tasks are not the exact prefix concatenation"
        )
    if (
        type(evidence.total_task_count) is not int
        or evidence.total_task_count != NINTH_PREFIX_TASK_COUNT
        or len(evidence.tasks) != NINTH_PREFIX_TASK_COUNT
        or type(evidence.terminal_registry_sha256) is not str
        or evidence.terminal_registry_sha256
        != FROZEN_NINTH_REGISTRY_SHA256
        or evidence.terminal_registry_sha256 != ninth.registry_sha256
        or type(evidence.terminal_cumulative_suite_sha256) is not str
        or evidence.terminal_cumulative_suite_sha256
        != FROZEN_NINTH_CUMULATIVE_SUITE_SHA256
        or evidence.terminal_cumulative_suite_sha256
        != ninth.cumulative_suite_sha256
    ):
        raise NinthPredecessorEvidenceError(
            "through-ninth task metadata differs from the frozen chain"
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
        raise NinthPredecessorEvidenceError(
            "through-ninth task identities cannot be inspected"
        ) from exc
    if (
        len(set(task_ids)) != NINTH_PREFIX_TASK_COUNT
        or len(set(task_contracts)) != NINTH_PREFIX_TASK_COUNT
        or len(set(graph_hashes)) != NINTH_PREFIX_TASK_COUNT
        or observed_family_order != NINTH_PREFIX_FAMILY_ORDER
    ):
        raise NinthPredecessorEvidenceError(
            "task identities collide or family order is not canonical"
        )


def verify_ninth_prefix_task_evidence(evidence: object) -> bool:
    """Return whether ``evidence`` is the exact through-ninth task prefix."""

    try:
        validate_ninth_prefix_task_evidence(  # type: ignore[arg-type]
            evidence
        )
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def build_ninth_prefix_task_evidence(
    linear_evidence: LinearTaskPredecessorEvidence | None = None,
) -> NinthPrefixTaskEvidence:
    """Build the first eight once and append one non-recursive ninth registry."""

    selected_linear = (
        build_linear_task_predecessor_evidence()
        if linear_evidence is None
        else linear_evidence
    )
    validate_linear_task_predecessor_evidence(selected_linear)
    ninth = build_ninth_tranche_task_registry(selected_linear)
    return NinthPrefixTaskEvidence(
        linear_evidence=selected_linear,
        ninth_registry=ninth,
        tasks=(*selected_linear.tasks, *ninth.added_tasks),
    )


@dataclass(frozen=True, slots=True)
class NinthPrefixFixtureEvidence:
    """Fresh first-through-ninth fixture evidence for a tenth catalog."""

    task_evidence: NinthPrefixTaskEvidence = field(repr=False)
    linear_evidence: LinearFixturePredecessorEvidence = field(repr=False)
    ninth_catalog: NinthTrancheFixtureCatalog = field(repr=False)
    bundles: tuple[object, ...] = field(repr=False)
    total_fixture_count: int = NINTH_PREFIX_FIXTURE_COUNT
    profiles_per_task: int = NINTH_PREFIX_PROFILE_COUNT
    terminal_catalog_sha256: str = FROZEN_NINTH_CATALOG_SHA256

    def __post_init__(self) -> None:
        validate_ninth_prefix_fixture_evidence(self)

    @property
    def catalogs(self) -> tuple[object, ...]:
        """Return all nine catalogs without retaining a mutable cache."""

        return (*self.linear_evidence.catalogs, self.ninth_catalog)


def validate_ninth_prefix_fixture_evidence(
    evidence: NinthPrefixFixtureEvidence,
) -> None:
    """Validate the exact fixture prefix and every task/profile binding."""

    if type(evidence) is not NinthPrefixFixtureEvidence:
        raise NinthPredecessorEvidenceError(
            "fixture evidence must be an exact NinthPrefixFixtureEvidence"
        )
    if type(evidence.task_evidence) is not NinthPrefixTaskEvidence:
        raise NinthPredecessorEvidenceError(
            "fixture evidence has the wrong task-prefix type"
        )
    if type(evidence.linear_evidence) is not LinearFixturePredecessorEvidence:
        raise NinthPredecessorEvidenceError(
            "fixture evidence has the wrong linear fixture type"
        )
    if type(evidence.ninth_catalog) is not NinthTrancheFixtureCatalog:
        raise NinthPredecessorEvidenceError(
            "fixture evidence has the wrong ninth catalog type"
        )
    try:
        validate_ninth_prefix_task_evidence(evidence.task_evidence)
        validate_linear_fixture_predecessor_evidence(
            evidence.linear_evidence
        )
        ninth_record = evidence.ninth_catalog.to_hash_only_record()
    except (AttributeError, TypeError, ValueError) as exc:
        raise NinthPredecessorEvidenceError(
            "a through-ninth fixture component is invalid"
        ) from exc

    tasks = evidence.task_evidence
    linear = evidence.linear_evidence
    ninth = evidence.ninth_catalog
    if (
        linear.task_evidence is not tasks.linear_evidence
        or linear.total_fixture_count != LINEAR_PREDECESSOR_FIXTURE_COUNT
        or linear.terminal_catalog_sha256
        != FROZEN_PREDECESSOR_CATALOG_SHA256[-1]
        or ninth.registry is not tasks.ninth_registry
        or ninth.base_fixture_catalog_sha256
        != linear.terminal_catalog_sha256
        or ninth.catalog_sha256 != FROZEN_NINTH_CATALOG_SHA256
        or ninth_record.get("catalog_sha256")
        != FROZEN_NINTH_CATALOG_SHA256
        or len(ninth.bundles) != NINTH_TRANCHE_ADDED_FIXTURE_COUNT
    ):
        raise NinthPredecessorEvidenceError(
            "ninth catalog does not extend the exact linear fixture evidence"
        )

    expected_bundles = (*linear.bundles, *ninth.bundles)
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
        raise NinthPredecessorEvidenceError(
            "cumulative fixtures are not the exact prefix concatenation"
        )
    if (
        type(evidence.total_fixture_count) is not int
        or evidence.total_fixture_count != NINTH_PREFIX_FIXTURE_COUNT
        or len(evidence.bundles) != NINTH_PREFIX_FIXTURE_COUNT
        or type(evidence.profiles_per_task) is not int
        or evidence.profiles_per_task != NINTH_PREFIX_PROFILE_COUNT
        or len(evidence.bundles)
        != len(tasks.tasks) * evidence.profiles_per_task
        or type(evidence.terminal_catalog_sha256) is not str
        or evidence.terminal_catalog_sha256
        != FROZEN_NINTH_CATALOG_SHA256
        or evidence.terminal_catalog_sha256 != ninth.catalog_sha256
    ):
        raise NinthPredecessorEvidenceError(
            "through-ninth fixture metadata differs from the frozen chain"
        )

    fixture_ids: set[str] = set()
    fixture_hashes: set[str] = set()
    try:
        for index, bundle in enumerate(evidence.bundles):
            task = tasks.tasks[index // NINTH_PREFIX_PROFILE_COUNT]
            profile_index = index % NINTH_PREFIX_PROFILE_COUNT
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
                raise NinthPredecessorEvidenceError(
                    "fixture order, descriptor binding, or authority is invalid"
                )
            fixture_ids.add(bundle.descriptor.fixture_id)
            fixture_hashes.add(bundle.descriptor.fixture_sha256)
    except (AttributeError, TypeError, ValueError) as exc:
        if isinstance(exc, NinthPredecessorEvidenceError):
            raise
        raise NinthPredecessorEvidenceError(
            "through-ninth fixture identities cannot be inspected"
        ) from exc
    if (
        len(fixture_ids) != NINTH_PREFIX_FIXTURE_COUNT
        or len(fixture_hashes) != NINTH_PREFIX_FIXTURE_COUNT
    ):
        raise NinthPredecessorEvidenceError(
            "fixture identities collide across the through-ninth prefix"
        )


def verify_ninth_prefix_fixture_evidence(evidence: object) -> bool:
    """Return whether ``evidence`` is the exact through-ninth fixture prefix."""

    try:
        validate_ninth_prefix_fixture_evidence(  # type: ignore[arg-type]
            evidence
        )
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def build_ninth_prefix_fixture_evidence(
    task_evidence: NinthPrefixTaskEvidence | None = None,
) -> NinthPrefixFixtureEvidence:
    """Build each first-through-ninth catalog locally exactly once."""

    selected_tasks = (
        build_ninth_prefix_task_evidence()
        if task_evidence is None
        else task_evidence
    )
    validate_ninth_prefix_task_evidence(selected_tasks)
    linear = build_linear_fixture_predecessor_evidence(
        selected_tasks.linear_evidence
    )
    ninth = build_ninth_tranche_fixture_catalog_local(
        selected_tasks.ninth_registry
    )
    return NinthPrefixFixtureEvidence(
        task_evidence=selected_tasks,
        linear_evidence=linear,
        ninth_catalog=ninth,
        bundles=(*linear.bundles, *ninth.bundles),
    )


__all__ = [
    "FROZEN_NINTH_CATALOG_SHA256",
    "FROZEN_NINTH_CUMULATIVE_SUITE_SHA256",
    "FROZEN_NINTH_REGISTRY_SHA256",
    "NINTH_PREFIX_FAMILY_ORDER",
    "NINTH_PREFIX_FIXTURE_COUNT",
    "NINTH_PREFIX_PROFILE_COUNT",
    "NINTH_PREFIX_TASK_COUNT",
    "NinthPredecessorEvidenceError",
    "NinthPrefixFixtureEvidence",
    "NinthPrefixTaskEvidence",
    "build_ninth_prefix_fixture_evidence",
    "build_ninth_prefix_task_evidence",
    "validate_ninth_prefix_fixture_evidence",
    "validate_ninth_prefix_task_evidence",
    "verify_ninth_prefix_fixture_evidence",
    "verify_ninth_prefix_task_evidence",
]
