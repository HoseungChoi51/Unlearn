"""Linear, hash-neutral evidence for the first eight executable tranches.

The historical third-through-eighth registry builders rebuild every earlier
registry before admitting their own tranche.  Calling those builders in
sequence therefore repeats predecessor generation.  This module instead
builds each tranche's tasks exactly once, uses the public tranche-local hash
and validation APIs, and performs the cross-tranche checks once over the
resulting 340-task sequence.

Fixture evidence follows the same pattern.  The first and second catalogs use
their existing direct paths with an explicit local registry.  The third
through eighth use public local-catalog adapters that generate and validate
only their own bundles, preserving the historical recursive builders for
standalone publication checks.  One final pass verifies task/profile order and
global fixture identity uniqueness across all 1,700 bundles.

Both evidence objects are deliberately hash-neutral: they introduce no new
record type or digest and only carry already frozen identities.  Every build
owns fresh, call-scoped objects; this module has no mutable cache.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final, TypeAlias

from .executable_fixture_catalog import (
    FIRST_TRANCHE_FIXTURE_COUNT,
    FirstTrancheFixtureCatalog,
    build_first_tranche_fixture_catalog,
)
from .executable_fixture_eighth_catalog import (
    EIGHTH_TRANCHE_ADDED_FIXTURE_COUNT,
    EIGHTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT,
    EighthTrancheFixtureCatalog,
    build_eighth_tranche_fixture_catalog_local,
)
from .executable_fixture_fifth_catalog import (
    FIFTH_TRANCHE_ADDED_FIXTURE_COUNT,
    FIFTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT,
    FifthTrancheFixtureCatalog,
    build_fifth_tranche_fixture_catalog_local,
)
from .executable_fixture_fourth_catalog import (
    FOURTH_TRANCHE_ADDED_FIXTURE_COUNT,
    FOURTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT,
    FourthTrancheFixtureCatalog,
    build_fourth_tranche_fixture_catalog_local,
)
from .executable_fixture_profiles import (
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from .executable_fixture_second_catalog import (
    SECOND_TRANCHE_ADDED_FIXTURE_COUNT,
    SECOND_TRANCHE_CUMULATIVE_FIXTURE_COUNT,
    SecondTrancheFixtureCatalog,
    build_second_tranche_fixture_catalog,
)
from .executable_fixture_seventh_catalog import (
    SEVENTH_TRANCHE_ADDED_FIXTURE_COUNT,
    SEVENTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT,
    SeventhTrancheFixtureCatalog,
    build_seventh_tranche_fixture_catalog_local,
)
from .executable_fixture_sixth_catalog import (
    SIXTH_TRANCHE_ADDED_FIXTURE_COUNT,
    SIXTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT,
    SixthTrancheFixtureCatalog,
    build_sixth_tranche_fixture_catalog_local,
)
from .executable_fixture_third_catalog import (
    THIRD_TRANCHE_ADDED_FIXTURE_COUNT,
    THIRD_TRANCHE_CUMULATIVE_FIXTURE_COUNT,
    ThirdTrancheFixtureCatalog,
    build_third_tranche_fixture_catalog_local,
)
from .executable_static_eighth_registry import (
    EIGHTH_TRANCHE_ADDED_TASK_COUNT,
    EIGHTH_TRANCHE_CUMULATIVE_TASK_COUNT,
    EighthTrancheTaskRegistry,
    build_eighth_tranche_added_tasks,
    compute_eighth_tranche_cumulative_suite_sha256,
    compute_eighth_tranche_registry_sha256,
    validate_eighth_tranche_task_registry,
)
from .executable_static_fifth_registry import (
    FIFTH_TRANCHE_ADDED_TASK_COUNT,
    FIFTH_TRANCHE_CUMULATIVE_TASK_COUNT,
    FifthTrancheTaskRegistry,
    build_fifth_tranche_added_tasks,
    compute_fifth_tranche_cumulative_suite_sha256,
    compute_fifth_tranche_registry_sha256,
    validate_fifth_tranche_task_registry,
)
from .executable_static_fourth_registry import (
    FOURTH_TRANCHE_ADDED_TASK_COUNT,
    FOURTH_TRANCHE_CUMULATIVE_TASK_COUNT,
    FourthTrancheTaskRegistry,
    build_fourth_tranche_added_tasks,
    compute_fourth_tranche_cumulative_suite_sha256,
    compute_fourth_tranche_registry_sha256,
    validate_fourth_tranche_task_registry,
)
from .executable_static_registry import (
    build_public_method_development_registry,
)
from .executable_static_second_registry import (
    SECOND_TRANCHE_ADDED_TASK_COUNT,
    SECOND_TRANCHE_CUMULATIVE_TASK_COUNT,
    SecondTrancheTaskRegistry,
    build_second_tranche_added_tasks,
    compute_second_tranche_cumulative_suite_sha256,
    compute_second_tranche_registry_sha256,
    validate_second_tranche_task_registry,
)
from .executable_static_seventh_registry import (
    SEVENTH_TRANCHE_ADDED_TASK_COUNT,
    SEVENTH_TRANCHE_CUMULATIVE_TASK_COUNT,
    SeventhTrancheTaskRegistry,
    build_seventh_tranche_added_tasks,
    compute_seventh_tranche_cumulative_suite_sha256,
    compute_seventh_tranche_registry_sha256,
    validate_seventh_tranche_task_registry,
)
from .executable_static_sixth_registry import (
    SIXTH_TRANCHE_ADDED_TASK_COUNT,
    SIXTH_TRANCHE_CUMULATIVE_TASK_COUNT,
    SixthTrancheTaskRegistry,
    build_sixth_tranche_added_tasks,
    compute_sixth_tranche_cumulative_suite_sha256,
    compute_sixth_tranche_registry_sha256,
    validate_sixth_tranche_task_registry,
)
from .executable_static_third_registry import (
    THIRD_TRANCHE_ADDED_TASK_COUNT,
    THIRD_TRANCHE_CUMULATIVE_TASK_COUNT,
    ThirdTrancheTaskRegistry,
    build_third_tranche_added_tasks,
    compute_third_tranche_cumulative_suite_sha256,
    compute_third_tranche_registry_sha256,
    validate_third_tranche_task_registry,
)
from .executable_static_types import ExecutableStaticRegistry


LINEAR_PREDECESSOR_TRANCHE_ORDER: Final[tuple[str, ...]] = (
    "first",
    "second",
    "third",
    "fourth",
    "fifth",
    "sixth",
    "seventh",
    "eighth",
)
LINEAR_PREDECESSOR_ADDED_TASK_COUNTS: Final[tuple[int, ...]] = (
    100,
    SECOND_TRANCHE_ADDED_TASK_COUNT,
    THIRD_TRANCHE_ADDED_TASK_COUNT,
    FOURTH_TRANCHE_ADDED_TASK_COUNT,
    FIFTH_TRANCHE_ADDED_TASK_COUNT,
    SIXTH_TRANCHE_ADDED_TASK_COUNT,
    SEVENTH_TRANCHE_ADDED_TASK_COUNT,
    EIGHTH_TRANCHE_ADDED_TASK_COUNT,
)
LINEAR_PREDECESSOR_CUMULATIVE_TASK_COUNTS: Final[tuple[int, ...]] = (
    100,
    SECOND_TRANCHE_CUMULATIVE_TASK_COUNT,
    THIRD_TRANCHE_CUMULATIVE_TASK_COUNT,
    FOURTH_TRANCHE_CUMULATIVE_TASK_COUNT,
    FIFTH_TRANCHE_CUMULATIVE_TASK_COUNT,
    SIXTH_TRANCHE_CUMULATIVE_TASK_COUNT,
    SEVENTH_TRANCHE_CUMULATIVE_TASK_COUNT,
    EIGHTH_TRANCHE_CUMULATIVE_TASK_COUNT,
)
LINEAR_PREDECESSOR_TASK_COUNT: Final[int] = 340
LINEAR_PREDECESSOR_PROFILE_COUNT: Final[int] = 5
LINEAR_PREDECESSOR_ADDED_FIXTURE_COUNTS: Final[tuple[int, ...]] = (
    FIRST_TRANCHE_FIXTURE_COUNT,
    SECOND_TRANCHE_ADDED_FIXTURE_COUNT,
    THIRD_TRANCHE_ADDED_FIXTURE_COUNT,
    FOURTH_TRANCHE_ADDED_FIXTURE_COUNT,
    FIFTH_TRANCHE_ADDED_FIXTURE_COUNT,
    SIXTH_TRANCHE_ADDED_FIXTURE_COUNT,
    SEVENTH_TRANCHE_ADDED_FIXTURE_COUNT,
    EIGHTH_TRANCHE_ADDED_FIXTURE_COUNT,
)
LINEAR_PREDECESSOR_CUMULATIVE_FIXTURE_COUNTS: Final[tuple[int, ...]] = (
    FIRST_TRANCHE_FIXTURE_COUNT,
    SECOND_TRANCHE_CUMULATIVE_FIXTURE_COUNT,
    THIRD_TRANCHE_CUMULATIVE_FIXTURE_COUNT,
    FOURTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT,
    FIFTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT,
    SIXTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT,
    SEVENTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT,
    EIGHTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT,
)
LINEAR_PREDECESSOR_FIXTURE_COUNT: Final[int] = 1_700

FROZEN_PREDECESSOR_REGISTRY_SHA256: Final[tuple[str, ...]] = (
    "ada6043b345e48f69ad602581030aab1bafcb3ff9dc453f9d02342faaf6a7f9a",
    "27e4721036c4870fec463e880cb3a36fcd72ebe530368cb45179f600ee694ab4",
    "66a9ef43a6387f5f94f511aec3357f0e625427d161a0c6da0d9590a837761237",
    "3dc5512139361a275afaf0b57b94528961615f9b4eee22ee6c333cc7d8bf4ea5",
    "d562d462814b7fc6413e0e085d16f66def28157c1a6361adf28cd3d42eb5f88c",
    "14280b3cbc8a96c919a57a325b5795c381cba86b2a31934f7069821b7ff4e3c4",
    "14aa05939c2ac2f4954196968003254dee39175f1d1d94e32213b8a74cfff19e",
    "8ef6879c5b6f4198c1b0ff2acfcffe89b6cbdd418a9aa2af2eefedfb12994736",
)
FROZEN_PREDECESSOR_CUMULATIVE_SUITE_SHA256: Final[tuple[str, ...]] = (
    "eb64bb4cdb60ab8e0e228f688cf54810fae2ef56768e8b34ac039bdc1aec42ae",
    "0020c1e5c7907d979d7fa97dead79f199fff59d97184c33fae81bc98df3ef8fb",
    "3a578668805bbdfdfaf3400483640bb29504591604ed1c9c28cf8f9bb0362fb3",
    "668ab9c942888d568c80aaa27bee340ad8a10faf3493a6983bf068d79b134651",
    "27ea8064a72453a4e7a4bc52b125a924139088cd1c20d417a867aa9ddda96e00",
    "db6d00278664f5a72834ebf0297411564da8b98a75d08eb2c2e9cf706dc985b1",
    "341b50a83305a9e0c64ada387eee461209ca75d1083e34fe2887a608179de131",
    "b22742179e3ce3b7331469de9db0a75ddbae81a3340e2b814c8a7ab34233f0f0",
)
FROZEN_PREDECESSOR_CATALOG_SHA256: Final[tuple[str, ...]] = (
    "1fc71f89830739a53b69d771b7d0bd6a79a4d78ff698b1c1c2258211e7776c99",
    "e2ad6a3124491bc25410d40278400aeac9cd8791a9f08a530c823d5f14c09e18",
    "01554367fd68c36b2f509b8b50b270b0aa7d5e6de3fa55db15a14cf4ec68c26b",
    "54ff2e17645edfc7887fc39b437340ffe8d736b83001d0265612271c2a3b1d46",
    "cb24e42fc27500fa5076224dfc195a6fe2a4b08752724f09ff944961aa7221db",
    "9042968ead33dd098870d21582bc3114706d3af3841bdb3ab7a0d40c5727d990",
    "99dcf8918151a5a87bdeea8f51bde8ad6e10063b46419a334d7d8b211310e6d8",
    "05e4b90408a0970dfded597e5ee7813386bfdaed50a1cea301148eaabd83c297",
)
LINEAR_PREDECESSOR_FAMILY_ORDER: Final[tuple[str, ...]] = (
    "active-jsonl-labels",
    "manifest-copy",
    "csv-group-totals",
    "checksum-manifest",
    "path-suffix-inventory",
    "line-transform-mirror",
    "mode-normalized-mirror",
    "jsonl-keyed-inner-join",
    "ustar-safe-extract",
    "proc-snapshot-report",
    "compound-path-query",
    "regex-log-group-aggregation",
    "reproducible-ustar-pack",
    "pipefail-atomic-report",
    "bounded-retry-state-machine",
    "case-routed-batch-transform",
    "collision-safe-batch-rename",
)

PredecessorTaskRegistry: TypeAlias = (
    ExecutableStaticRegistry
    | SecondTrancheTaskRegistry
    | ThirdTrancheTaskRegistry
    | FourthTrancheTaskRegistry
    | FifthTrancheTaskRegistry
    | SixthTrancheTaskRegistry
    | SeventhTrancheTaskRegistry
    | EighthTrancheTaskRegistry
)
PredecessorFixtureCatalog: TypeAlias = (
    FirstTrancheFixtureCatalog
    | SecondTrancheFixtureCatalog
    | ThirdTrancheFixtureCatalog
    | FourthTrancheFixtureCatalog
    | FifthTrancheFixtureCatalog
    | SixthTrancheFixtureCatalog
    | SeventhTrancheFixtureCatalog
    | EighthTrancheFixtureCatalog
)

_REGISTRY_TYPES: Final[tuple[type[object], ...]] = (
    ExecutableStaticRegistry,
    SecondTrancheTaskRegistry,
    ThirdTrancheTaskRegistry,
    FourthTrancheTaskRegistry,
    FifthTrancheTaskRegistry,
    SixthTrancheTaskRegistry,
    SeventhTrancheTaskRegistry,
    EighthTrancheTaskRegistry,
)
_CATALOG_TYPES: Final[tuple[type[object], ...]] = (
    FirstTrancheFixtureCatalog,
    SecondTrancheFixtureCatalog,
    ThirdTrancheFixtureCatalog,
    FourthTrancheFixtureCatalog,
    FifthTrancheFixtureCatalog,
    SixthTrancheFixtureCatalog,
    SeventhTrancheFixtureCatalog,
    EighthTrancheFixtureCatalog,
)


class LinearPredecessorEvidenceError(ValueError):
    """Raised when linear task or fixture evidence differs from its chain."""


def _registry_tasks(registry: PredecessorTaskRegistry) -> tuple[object, ...]:
    if type(registry) is ExecutableStaticRegistry:
        return registry.tasks
    return registry.added_tasks


def _registry_cumulative_suite_sha256(
    registry: PredecessorTaskRegistry,
) -> str:
    if type(registry) is ExecutableStaticRegistry:
        return registry.suite_sha256
    return registry.cumulative_suite_sha256


def _validate_registry(registry: PredecessorTaskRegistry) -> None:
    try:
        if type(registry) is ExecutableStaticRegistry:
            registry.__post_init__()
        elif type(registry) is SecondTrancheTaskRegistry:
            validate_second_tranche_task_registry(registry)
        elif type(registry) is ThirdTrancheTaskRegistry:
            validate_third_tranche_task_registry(registry)
        elif type(registry) is FourthTrancheTaskRegistry:
            validate_fourth_tranche_task_registry(registry)
        elif type(registry) is FifthTrancheTaskRegistry:
            validate_fifth_tranche_task_registry(registry)
        elif type(registry) is SixthTrancheTaskRegistry:
            validate_sixth_tranche_task_registry(registry)
        elif type(registry) is SeventhTrancheTaskRegistry:
            validate_seventh_tranche_task_registry(registry)
        elif type(registry) is EighthTrancheTaskRegistry:
            validate_eighth_tranche_task_registry(registry)
        else:
            raise LinearPredecessorEvidenceError(
                "registry is outside the first-through-eighth exact types"
            )
    except (AttributeError, TypeError, ValueError) as exc:
        if isinstance(exc, LinearPredecessorEvidenceError):
            raise
        raise LinearPredecessorEvidenceError(
            "a tranche registry failed local validation"
        ) from exc


@dataclass(frozen=True, slots=True)
class TaskTrancheEvidence:
    """One locally validated tranche and its existing frozen identities."""

    tranche: str
    registry: PredecessorTaskRegistry = field(repr=False)
    tasks: tuple[object, ...] = field(repr=False)
    registry_sha256: str
    cumulative_suite_sha256: str
    added_task_count: int
    cumulative_task_count: int

    def __post_init__(self) -> None:
        _validate_task_tranche_evidence(self)


def _validate_task_tranche_evidence(evidence: object) -> TaskTrancheEvidence:
    if type(evidence) is not TaskTrancheEvidence:
        raise LinearPredecessorEvidenceError(
            "tranche evidence must be an exact TaskTrancheEvidence"
        )
    if type(evidence.tranche) is not str:
        raise LinearPredecessorEvidenceError("tranche name must be an exact string")
    try:
        index = LINEAR_PREDECESSOR_TRANCHE_ORDER.index(evidence.tranche)
    except ValueError as exc:
        raise LinearPredecessorEvidenceError(
            "tranche name is outside the frozen order"
        ) from exc
    if type(evidence.registry) is not _REGISTRY_TYPES[index]:
        raise LinearPredecessorEvidenceError(
            "tranche registry has the wrong exact type"
        )
    _validate_registry(evidence.registry)
    registry_tasks = _registry_tasks(evidence.registry)
    if type(evidence.tasks) is not tuple or evidence.tasks is not registry_tasks:
        raise LinearPredecessorEvidenceError(
            "tranche tasks must be the registry's exact task tuple"
        )
    expected_registry_sha256 = FROZEN_PREDECESSOR_REGISTRY_SHA256[index]
    expected_suite_sha256 = (
        FROZEN_PREDECESSOR_CUMULATIVE_SUITE_SHA256[index]
    )
    if (
        type(evidence.registry_sha256) is not str
        or evidence.registry_sha256 != expected_registry_sha256
        or evidence.registry.registry_sha256 != expected_registry_sha256
        or type(evidence.cumulative_suite_sha256) is not str
        or evidence.cumulative_suite_sha256 != expected_suite_sha256
        or _registry_cumulative_suite_sha256(evidence.registry)
        != expected_suite_sha256
        or type(evidence.added_task_count) is not int
        or evidence.added_task_count
        != LINEAR_PREDECESSOR_ADDED_TASK_COUNTS[index]
        or evidence.added_task_count != len(evidence.tasks)
        or type(evidence.cumulative_task_count) is not int
        or evidence.cumulative_task_count
        != LINEAR_PREDECESSOR_CUMULATIVE_TASK_COUNTS[index]
    ):
        raise LinearPredecessorEvidenceError(
            "tranche hash or count differs from the frozen chain"
        )
    return evidence


@dataclass(frozen=True, slots=True)
class LinearTaskPredecessorEvidence:
    """Fresh first-through-eighth evidence suitable for a ninth registry."""

    tranches: tuple[TaskTrancheEvidence, ...] = field(repr=False)
    tasks: tuple[object, ...] = field(repr=False)
    total_task_count: int = LINEAR_PREDECESSOR_TASK_COUNT
    terminal_registry_sha256: str = FROZEN_PREDECESSOR_REGISTRY_SHA256[-1]
    terminal_cumulative_suite_sha256: str = (
        FROZEN_PREDECESSOR_CUMULATIVE_SUITE_SHA256[-1]
    )

    def __post_init__(self) -> None:
        validate_linear_task_predecessor_evidence(self)

    @property
    def registries(self) -> tuple[PredecessorTaskRegistry, ...]:
        """Return registries in frozen ordinal order without retaining a cache."""

        return tuple(tranche.registry for tranche in self.tranches)


def validate_linear_task_predecessor_evidence(
    evidence: LinearTaskPredecessorEvidence,
) -> None:
    """Validate the complete frozen chain without rebuilding any task."""

    if type(evidence) is not LinearTaskPredecessorEvidence:
        raise LinearPredecessorEvidenceError(
            "evidence must be an exact LinearTaskPredecessorEvidence"
        )
    if (
        type(evidence.tranches) is not tuple
        or len(evidence.tranches) != len(LINEAR_PREDECESSOR_TRANCHE_ORDER)
        or any(
            type(tranche) is not TaskTrancheEvidence
            for tranche in evidence.tranches
        )
    ):
        raise LinearPredecessorEvidenceError(
            "evidence requires exactly eight exact tranche values"
        )
    for tranche in evidence.tranches:
        _validate_task_tranche_evidence(tranche)
    if (
        tuple(tranche.tranche for tranche in evidence.tranches)
        != LINEAR_PREDECESSOR_TRANCHE_ORDER
    ):
        raise LinearPredecessorEvidenceError("tranche order is not canonical")

    expected_tasks = tuple(
        task
        for tranche in evidence.tranches
        for task in tranche.tasks
    )
    if type(evidence.tasks) is not tuple or evidence.tasks != expected_tasks:
        raise LinearPredecessorEvidenceError(
            "cumulative tasks are not the canonical tranche concatenation"
        )
    if (
        type(evidence.total_task_count) is not int
        or evidence.total_task_count != LINEAR_PREDECESSOR_TASK_COUNT
        or len(evidence.tasks) != LINEAR_PREDECESSOR_TASK_COUNT
        or type(evidence.terminal_registry_sha256) is not str
        or evidence.terminal_registry_sha256
        != FROZEN_PREDECESSOR_REGISTRY_SHA256[-1]
        or type(evidence.terminal_cumulative_suite_sha256) is not str
        or evidence.terminal_cumulative_suite_sha256
        != FROZEN_PREDECESSOR_CUMULATIVE_SUITE_SHA256[-1]
    ):
        raise LinearPredecessorEvidenceError(
            "cumulative metadata differs from the frozen chain"
        )

    task_ids = tuple(task.task_id for task in evidence.tasks)
    task_contracts = tuple(
        task.task_contract_sha256 for task in evidence.tasks
    )
    graph_hashes = tuple(task.graph_sha256 for task in evidence.tasks)
    if (
        len(set(task_ids)) != LINEAR_PREDECESSOR_TASK_COUNT
        or len(set(task_contracts)) != LINEAR_PREDECESSOR_TASK_COUNT
        or len(set(graph_hashes)) != LINEAR_PREDECESSOR_TASK_COUNT
    ):
        raise LinearPredecessorEvidenceError(
            "task identities collide across frozen tranches"
        )
    observed_family_order = tuple(
        family
        for index, family in enumerate(
            task.family_id for task in evidence.tasks
        )
        if index == 0 or family != evidence.tasks[index - 1].family_id
    )
    if observed_family_order != LINEAR_PREDECESSOR_FAMILY_ORDER:
        raise LinearPredecessorEvidenceError(
            "cross-tranche family order is not canonical"
        )


def verify_linear_task_predecessor_evidence(evidence: object) -> bool:
    """Return whether ``evidence`` is the exact frozen linear task chain."""

    try:
        validate_linear_task_predecessor_evidence(evidence)  # type: ignore[arg-type]
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def _tranche_evidence(
    tranche: str,
    registry: PredecessorTaskRegistry,
    cumulative_task_count: int,
) -> TaskTrancheEvidence:
    tasks = _registry_tasks(registry)
    return TaskTrancheEvidence(
        tranche=tranche,
        registry=registry,
        tasks=tasks,
        registry_sha256=registry.registry_sha256,
        cumulative_suite_sha256=_registry_cumulative_suite_sha256(registry),
        added_task_count=len(tasks),
        cumulative_task_count=cumulative_task_count,
    )


def build_linear_task_predecessor_evidence(
) -> LinearTaskPredecessorEvidence:
    """Build each first-through-eighth task tranche exactly once.

    Only the first registry's direct builder is called.  Later registries are
    assembled from their public added-task, digest, and exact registry APIs,
    avoiding every recursive ``build_*_tranche_task_registry`` function.
    """

    first = build_public_method_development_registry()

    second_tasks = build_second_tranche_added_tasks()
    second_registry_sha256 = compute_second_tranche_registry_sha256(
        second_tasks
    )
    second = SecondTrancheTaskRegistry(
        added_tasks=second_tasks,
        registry_sha256=second_registry_sha256,
        cumulative_suite_sha256=(
            compute_second_tranche_cumulative_suite_sha256(
                second_tasks, second_registry_sha256
            )
        ),
    )

    third_tasks = build_third_tranche_added_tasks()
    third_registry_sha256 = compute_third_tranche_registry_sha256(third_tasks)
    third = ThirdTrancheTaskRegistry(
        added_tasks=third_tasks,
        registry_sha256=third_registry_sha256,
        cumulative_suite_sha256=(
            compute_third_tranche_cumulative_suite_sha256(
                third_tasks, third_registry_sha256
            )
        ),
    )

    fourth_tasks = build_fourth_tranche_added_tasks()
    fourth_registry_sha256 = compute_fourth_tranche_registry_sha256(
        fourth_tasks
    )
    fourth = FourthTrancheTaskRegistry(
        added_tasks=fourth_tasks,
        registry_sha256=fourth_registry_sha256,
        cumulative_suite_sha256=(
            compute_fourth_tranche_cumulative_suite_sha256(
                fourth_tasks, fourth_registry_sha256
            )
        ),
    )

    fifth_tasks = build_fifth_tranche_added_tasks()
    fifth_registry_sha256 = compute_fifth_tranche_registry_sha256(fifth_tasks)
    fifth = FifthTrancheTaskRegistry(
        added_tasks=fifth_tasks,
        registry_sha256=fifth_registry_sha256,
        cumulative_suite_sha256=(
            compute_fifth_tranche_cumulative_suite_sha256(
                fifth_tasks, fifth_registry_sha256
            )
        ),
    )

    sixth_tasks = build_sixth_tranche_added_tasks()
    sixth_registry_sha256 = compute_sixth_tranche_registry_sha256(sixth_tasks)
    sixth = SixthTrancheTaskRegistry(
        added_tasks=sixth_tasks,
        registry_sha256=sixth_registry_sha256,
        cumulative_suite_sha256=(
            compute_sixth_tranche_cumulative_suite_sha256(
                sixth_tasks, sixth_registry_sha256
            )
        ),
    )

    seventh_tasks = build_seventh_tranche_added_tasks()
    seventh_registry_sha256 = compute_seventh_tranche_registry_sha256(
        seventh_tasks
    )
    seventh = SeventhTrancheTaskRegistry(
        added_tasks=seventh_tasks,
        registry_sha256=seventh_registry_sha256,
        cumulative_suite_sha256=(
            compute_seventh_tranche_cumulative_suite_sha256(
                seventh_tasks, seventh_registry_sha256
            )
        ),
    )

    eighth_tasks = build_eighth_tranche_added_tasks()
    eighth_registry_sha256 = compute_eighth_tranche_registry_sha256(
        eighth_tasks
    )
    eighth = EighthTrancheTaskRegistry(
        added_tasks=eighth_tasks,
        registry_sha256=eighth_registry_sha256,
        cumulative_suite_sha256=(
            compute_eighth_tranche_cumulative_suite_sha256(
                eighth_tasks, eighth_registry_sha256
            )
        ),
    )

    registries: tuple[PredecessorTaskRegistry, ...] = (
        first,
        second,
        third,
        fourth,
        fifth,
        sixth,
        seventh,
        eighth,
    )
    tranches = tuple(
        _tranche_evidence(
            tranche,
            registry,
            cumulative_task_count,
        )
        for tranche, registry, cumulative_task_count in zip(
            LINEAR_PREDECESSOR_TRANCHE_ORDER,
            registries,
            LINEAR_PREDECESSOR_CUMULATIVE_TASK_COUNTS,
            strict=True,
        )
    )
    tasks = tuple(task for tranche in tranches for task in tranche.tasks)
    return LinearTaskPredecessorEvidence(
        tranches=tranches,
        tasks=tasks,
    )


def _catalog_registry(
    catalog: PredecessorFixtureCatalog,
) -> PredecessorTaskRegistry:
    if type(catalog) is FirstTrancheFixtureCatalog:
        return catalog.source_registry
    return catalog.registry


@dataclass(frozen=True, slots=True)
class FixtureTrancheEvidence:
    """One locally built catalog bound to its task-tranche evidence."""

    tranche: str
    task_tranche: TaskTrancheEvidence = field(repr=False)
    catalog: PredecessorFixtureCatalog = field(repr=False)
    bundles: tuple[object, ...] = field(repr=False)
    catalog_sha256: str
    added_fixture_count: int
    cumulative_fixture_count: int

    def __post_init__(self) -> None:
        _validate_fixture_tranche_evidence(self)


def _validate_fixture_tranche_evidence(
    evidence: object,
) -> FixtureTrancheEvidence:
    if type(evidence) is not FixtureTrancheEvidence:
        raise LinearPredecessorEvidenceError(
            "fixture tranche must be an exact FixtureTrancheEvidence"
        )
    if type(evidence.tranche) is not str:
        raise LinearPredecessorEvidenceError(
            "fixture tranche name must be an exact string"
        )
    try:
        index = LINEAR_PREDECESSOR_TRANCHE_ORDER.index(evidence.tranche)
    except ValueError as exc:
        raise LinearPredecessorEvidenceError(
            "fixture tranche name is outside the frozen order"
        ) from exc
    task_tranche = _validate_task_tranche_evidence(evidence.task_tranche)
    if task_tranche.tranche != evidence.tranche:
        raise LinearPredecessorEvidenceError(
            "fixture and task tranche names differ"
        )
    if type(evidence.catalog) is not _CATALOG_TYPES[index]:
        raise LinearPredecessorEvidenceError(
            "fixture catalog has the wrong exact tranche type"
        )
    catalog_registry = _catalog_registry(evidence.catalog)
    if index == 0:
        if catalog_registry != task_tranche.registry:
            raise LinearPredecessorEvidenceError(
                "first fixture catalog is not bound to first task evidence"
            )
    elif catalog_registry is not task_tranche.registry:
        raise LinearPredecessorEvidenceError(
            "fixture catalog does not retain its exact local registry"
        )
    if (
        type(evidence.bundles) is not tuple
        or evidence.bundles is not evidence.catalog.bundles
    ):
        raise LinearPredecessorEvidenceError(
            "fixture evidence must retain the catalog's exact bundle tuple"
        )
    if (
        type(evidence.catalog_sha256) is not str
        or evidence.catalog_sha256
        != FROZEN_PREDECESSOR_CATALOG_SHA256[index]
        or evidence.catalog.catalog_sha256 != evidence.catalog_sha256
        or type(evidence.added_fixture_count) is not int
        or evidence.added_fixture_count
        != LINEAR_PREDECESSOR_ADDED_FIXTURE_COUNTS[index]
        or evidence.added_fixture_count != len(evidence.bundles)
        or type(evidence.cumulative_fixture_count) is not int
        or evidence.cumulative_fixture_count
        != LINEAR_PREDECESSOR_CUMULATIVE_FIXTURE_COUNTS[index]
        or evidence.catalog.public_method_development is not True
        or evidence.catalog.sealed is not False
        or evidence.catalog.candidate_execution_authorized is not False
        or evidence.catalog.model_selection_eligible is not False
        or evidence.catalog.claim_authorized is not False
    ):
        raise LinearPredecessorEvidenceError(
            "fixture catalog hash, count, or authority differs from the frozen chain"
        )

    expected_count = (
        len(task_tranche.tasks) * LINEAR_PREDECESSOR_PROFILE_COUNT
    )
    if len(evidence.bundles) != expected_count:
        raise LinearPredecessorEvidenceError(
            "fixture count does not equal tasks by public profiles"
        )
    fixture_ids: set[str] = set()
    fixture_hashes: set[str] = set()
    try:
        for bundle_index, bundle in enumerate(evidence.bundles):
            task = task_tranche.tasks[
                bundle_index // LINEAR_PREDECESSOR_PROFILE_COUNT
            ]
            profile_index = (
                bundle_index % LINEAR_PREDECESSOR_PROFILE_COUNT
            )
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
                raise LinearPredecessorEvidenceError(
                    "fixture order, descriptor binding, or authority is invalid"
                )
            fixture_ids.add(bundle.descriptor.fixture_id)
            fixture_hashes.add(bundle.descriptor.fixture_sha256)
    except (AttributeError, TypeError, ValueError) as exc:
        if isinstance(exc, LinearPredecessorEvidenceError):
            raise
        raise LinearPredecessorEvidenceError(
            "fixture bundle structure is invalid"
        ) from exc
    if (
        len(fixture_ids) != len(evidence.bundles)
        or len(fixture_hashes) != len(evidence.bundles)
    ):
        raise LinearPredecessorEvidenceError(
            "fixture identities collide within a tranche"
        )
    return evidence


@dataclass(frozen=True, slots=True)
class LinearFixturePredecessorEvidence:
    """Fresh first-through-eighth fixture evidence for a ninth catalog."""

    task_evidence: LinearTaskPredecessorEvidence = field(repr=False)
    tranches: tuple[FixtureTrancheEvidence, ...] = field(repr=False)
    bundles: tuple[object, ...] = field(repr=False)
    total_fixture_count: int = LINEAR_PREDECESSOR_FIXTURE_COUNT
    profiles_per_task: int = LINEAR_PREDECESSOR_PROFILE_COUNT
    terminal_catalog_sha256: str = FROZEN_PREDECESSOR_CATALOG_SHA256[-1]

    def __post_init__(self) -> None:
        validate_linear_fixture_predecessor_evidence(self)

    @property
    def catalogs(self) -> tuple[PredecessorFixtureCatalog, ...]:
        """Return catalogs in ordinal order without retaining a cache."""

        return tuple(tranche.catalog for tranche in self.tranches)


def validate_linear_fixture_predecessor_evidence(
    evidence: LinearFixturePredecessorEvidence,
) -> None:
    """Validate all frozen catalog evidence without regenerating bundles."""

    if type(evidence) is not LinearFixturePredecessorEvidence:
        raise LinearPredecessorEvidenceError(
            "fixture evidence must be an exact LinearFixturePredecessorEvidence"
        )
    validate_linear_task_predecessor_evidence(evidence.task_evidence)
    if (
        type(evidence.tranches) is not tuple
        or len(evidence.tranches) != len(LINEAR_PREDECESSOR_TRANCHE_ORDER)
        or any(
            type(tranche) is not FixtureTrancheEvidence
            for tranche in evidence.tranches
        )
    ):
        raise LinearPredecessorEvidenceError(
            "fixture evidence requires exactly eight exact tranche values"
        )
    for index, tranche in enumerate(evidence.tranches):
        _validate_fixture_tranche_evidence(tranche)
        if tranche.task_tranche is not evidence.task_evidence.tranches[index]:
            raise LinearPredecessorEvidenceError(
                "fixture tranche does not retain its task evidence"
            )
    if (
        tuple(tranche.tranche for tranche in evidence.tranches)
        != LINEAR_PREDECESSOR_TRANCHE_ORDER
    ):
        raise LinearPredecessorEvidenceError(
            "fixture tranche order is not canonical"
        )

    expected_bundles = tuple(
        bundle
        for tranche in evidence.tranches
        for bundle in tranche.bundles
    )
    if type(evidence.bundles) is not tuple or evidence.bundles != expected_bundles:
        raise LinearPredecessorEvidenceError(
            "cumulative bundles are not the canonical tranche concatenation"
        )
    if (
        type(evidence.total_fixture_count) is not int
        or evidence.total_fixture_count != LINEAR_PREDECESSOR_FIXTURE_COUNT
        or len(evidence.bundles) != LINEAR_PREDECESSOR_FIXTURE_COUNT
        or type(evidence.profiles_per_task) is not int
        or evidence.profiles_per_task != LINEAR_PREDECESSOR_PROFILE_COUNT
        or type(evidence.terminal_catalog_sha256) is not str
        or evidence.terminal_catalog_sha256
        != FROZEN_PREDECESSOR_CATALOG_SHA256[-1]
    ):
        raise LinearPredecessorEvidenceError(
            "cumulative fixture metadata differs from the frozen chain"
        )
    fixture_ids = {
        bundle.descriptor.fixture_id for bundle in evidence.bundles
    }
    fixture_hashes = {
        bundle.descriptor.fixture_sha256 for bundle in evidence.bundles
    }
    if (
        len(fixture_ids) != LINEAR_PREDECESSOR_FIXTURE_COUNT
        or len(fixture_hashes) != LINEAR_PREDECESSOR_FIXTURE_COUNT
    ):
        raise LinearPredecessorEvidenceError(
            "fixture identities collide across frozen tranches"
        )


def verify_linear_fixture_predecessor_evidence(evidence: object) -> bool:
    """Return whether ``evidence`` is the exact frozen linear fixture chain."""

    try:
        validate_linear_fixture_predecessor_evidence(  # type: ignore[arg-type]
            evidence
        )
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def _fixture_tranche_evidence(
    tranche: str,
    task_tranche: TaskTrancheEvidence,
    catalog: PredecessorFixtureCatalog,
    cumulative_fixture_count: int,
) -> FixtureTrancheEvidence:
    return FixtureTrancheEvidence(
        tranche=tranche,
        task_tranche=task_tranche,
        catalog=catalog,
        bundles=catalog.bundles,
        catalog_sha256=catalog.catalog_sha256,
        added_fixture_count=len(catalog.bundles),
        cumulative_fixture_count=cumulative_fixture_count,
    )


def build_linear_fixture_predecessor_evidence(
    task_evidence: LinearTaskPredecessorEvidence | None = None,
) -> LinearFixturePredecessorEvidence:
    """Build every first-through-eighth catalog once without predecessors."""

    selected_tasks = (
        build_linear_task_predecessor_evidence()
        if task_evidence is None
        else task_evidence
    )
    validate_linear_task_predecessor_evidence(selected_tasks)
    task_tranches = selected_tasks.tranches

    first = build_first_tranche_fixture_catalog(
        task_tranches[0].registry  # type: ignore[arg-type]
    )
    second = build_second_tranche_fixture_catalog(
        task_tranches[1].registry  # type: ignore[arg-type]
    )
    third = build_third_tranche_fixture_catalog_local(
        task_tranches[2].registry  # type: ignore[arg-type]
    )
    fourth = build_fourth_tranche_fixture_catalog_local(
        task_tranches[3].registry  # type: ignore[arg-type]
    )
    fifth = build_fifth_tranche_fixture_catalog_local(
        task_tranches[4].registry  # type: ignore[arg-type]
    )
    sixth = build_sixth_tranche_fixture_catalog_local(
        task_tranches[5].registry  # type: ignore[arg-type]
    )
    seventh = build_seventh_tranche_fixture_catalog_local(
        task_tranches[6].registry  # type: ignore[arg-type]
    )
    eighth = build_eighth_tranche_fixture_catalog_local(
        task_tranches[7].registry  # type: ignore[arg-type]
    )
    catalogs: tuple[PredecessorFixtureCatalog, ...] = (
        first,
        second,
        third,
        fourth,
        fifth,
        sixth,
        seventh,
        eighth,
    )
    tranches = tuple(
        _fixture_tranche_evidence(
            tranche,
            task_tranche,
            catalog,
            cumulative_fixture_count,
        )
        for (
            tranche,
            task_tranche,
            catalog,
            cumulative_fixture_count,
        ) in zip(
            LINEAR_PREDECESSOR_TRANCHE_ORDER,
            task_tranches,
            catalogs,
            LINEAR_PREDECESSOR_CUMULATIVE_FIXTURE_COUNTS,
            strict=True,
        )
    )
    bundles = tuple(
        bundle for tranche in tranches for bundle in tranche.bundles
    )
    return LinearFixturePredecessorEvidence(
        task_evidence=selected_tasks,
        tranches=tranches,
        bundles=bundles,
    )


__all__ = [
    "FROZEN_PREDECESSOR_CATALOG_SHA256",
    "FROZEN_PREDECESSOR_CUMULATIVE_SUITE_SHA256",
    "FROZEN_PREDECESSOR_REGISTRY_SHA256",
    "LINEAR_PREDECESSOR_ADDED_FIXTURE_COUNTS",
    "LINEAR_PREDECESSOR_ADDED_TASK_COUNTS",
    "LINEAR_PREDECESSOR_CUMULATIVE_FIXTURE_COUNTS",
    "LINEAR_PREDECESSOR_CUMULATIVE_TASK_COUNTS",
    "LINEAR_PREDECESSOR_FAMILY_ORDER",
    "LINEAR_PREDECESSOR_FIXTURE_COUNT",
    "LINEAR_PREDECESSOR_PROFILE_COUNT",
    "LINEAR_PREDECESSOR_TASK_COUNT",
    "LINEAR_PREDECESSOR_TRANCHE_ORDER",
    "FixtureTrancheEvidence",
    "LinearFixturePredecessorEvidence",
    "LinearPredecessorEvidenceError",
    "LinearTaskPredecessorEvidence",
    "PredecessorFixtureCatalog",
    "PredecessorTaskRegistry",
    "TaskTrancheEvidence",
    "build_linear_fixture_predecessor_evidence",
    "build_linear_task_predecessor_evidence",
    "validate_linear_fixture_predecessor_evidence",
    "validate_linear_task_predecessor_evidence",
    "verify_linear_fixture_predecessor_evidence",
    "verify_linear_task_predecessor_evidence",
]
