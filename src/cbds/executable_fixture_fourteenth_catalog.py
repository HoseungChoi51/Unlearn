"""Hash-bound fourteenth catalog for dependency-DAG planning fixtures.

The catalog preserves the frozen first-through-thirteenth publication
chain, binds the exact fourteenth 20-task grid against five public
development profiles, and commits to 100 new fixture/oracle bindings.  Its
public projection contains hashes and counts, never fixture bytes, paths,
prompts, or oracle answers.

The full builder obtains one through-thirteenth task snapshot and passes
that same snapshot into the non-recursive through-thirteenth fixture
builder.  No recursive thirteenth registry or catalog publication builder
is used.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Final, TypeAlias

from .executable_dependency_dag_execution_plan import (
    DEPENDENCY_DAG_EXECUTION_PLAN_FAMILY_ID,
    DEPENDENCY_DAG_EXECUTION_PLAN_GENERATOR_VERSION,
    DEPENDENCY_DAG_EXECUTION_PLAN_PROVED_MAXIMUM_TOTAL_OUTPUT_BYTES,
    DEPENDENCY_DAG_EXECUTION_PLAN_VERIFIER_IDENTITY,
    DependencyDagExecutionPlanFixtureBundle,
    DependencyDagExecutionPlanTask,
    build_dependency_dag_execution_plan_fixture_bundle,
    validate_dependency_dag_execution_plan_fixture_bundle,
    validate_dependency_dag_execution_plan_fixture_for_task_profile,
)
from .executable_fixture_profiles import (
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
    ExecutableFixtureProfile,
)
from .executable_static_fourteenth_registry import (
    FOURTEENTH_TRANCHE_ADDED_TASK_COUNT,
    FOURTEENTH_TRANCHE_CUMULATIVE_TASK_COUNT,
    FOURTEENTH_TRANCHE_FAMILY_ORDER,
    FourteenthTrancheTask,
    FourteenthTrancheTaskRegistry,
    build_fourteenth_tranche_task_registry,
    validate_fourteenth_tranche_task_registry,
)
from .executable_static_types import domain_sha256
from .executable_thirteenth_predecessor_evidence import (
    FROZEN_THIRTEENTH_CATALOG_SHA256,
    FROZEN_THIRTEENTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_THIRTEENTH_REGISTRY_SHA256,
    THIRTEENTH_PREFIX_FIXTURE_COUNT,
    THIRTEENTH_PREFIX_TASK_COUNT,
    ThirteenthPrefixFixtureEvidence,
    build_thirteenth_prefix_fixture_evidence,
    build_thirteenth_prefix_task_evidence,
    validate_thirteenth_prefix_fixture_evidence,
    validate_thirteenth_prefix_task_evidence,
)


FOURTEENTH_TRANCHE_CATALOG_SCHEMA_VERSION: Final[str] = "1.0.0"
FOURTEENTH_TRANCHE_CATALOG_VERSION: Final[str] = "1.0.0"
FOURTEENTH_TRANCHE_PROFILE_COUNT: Final[int] = 5
FOURTEENTH_TRANCHE_ADDED_FIXTURE_COUNT: Final[int] = 100
FOURTEENTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT: Final[int] = 2_300
FOURTEENTH_TRANCHE_FIXTURE_COUNT: Final[int] = (
    FOURTEENTH_TRANCHE_ADDED_FIXTURE_COUNT
)

FROZEN_FOURTEENTH_CATALOG_SHA256: Final[str] = (
    "11b25fb47af89945a80080b6c42d2fe315076384f3929555c1909cd7c318534b"
)

FourteenthTrancheFixtureBundle: TypeAlias = (
    DependencyDagExecutionPlanFixtureBundle
)
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")


class FourteenthTrancheFixtureCatalogError(ValueError):
    """Raised when the fourteenth additive catalog is not reproducible."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def _build_bundle(
    task: FourteenthTrancheTask,
    profile: ExecutableFixtureProfile,
) -> FourteenthTrancheFixtureBundle:
    if type(task) is not DependencyDagExecutionPlanTask:
        raise FourteenthTrancheFixtureCatalogError(
            "task type is outside the fourteenth tranche"
        )
    bundle = build_dependency_dag_execution_plan_fixture_bundle(
        task, profile
    )
    validate_dependency_dag_execution_plan_fixture_for_task_profile(
        task, profile, bundle
    )
    return bundle


def _validate_bundle(
    task: FourteenthTrancheTask,
    profile: ExecutableFixtureProfile,
    bundle: object,
    *,
    regenerate: bool,
) -> FourteenthTrancheFixtureBundle:
    try:
        if type(task) is not DependencyDagExecutionPlanTask:
            raise FourteenthTrancheFixtureCatalogError(
                "fourteenth-tranche task has the wrong exact type"
            )
        if type(bundle) is not DependencyDagExecutionPlanFixtureBundle:
            raise FourteenthTrancheFixtureCatalogError(
                "dependency-DAG task has the wrong bundle type"
            )
        validate_dependency_dag_execution_plan_fixture_bundle(bundle)
        validate_dependency_dag_execution_plan_fixture_for_task_profile(
            task, profile, bundle
        )
    except (AttributeError, TypeError, ValueError) as exc:
        if isinstance(exc, FourteenthTrancheFixtureCatalogError):
            raise
        raise FourteenthTrancheFixtureCatalogError(
            "family-local bundle validation failed"
        ) from exc
    selected = bundle
    if regenerate and selected != _build_bundle(task, profile):
        raise FourteenthTrancheFixtureCatalogError(
            "bundle differs from deterministic family generation"
        )
    return selected


def _validate_inputs(
    registry: object,
    bundles: object,
    *,
    regenerate: bool,
) -> tuple[
    FourteenthTrancheTaskRegistry,
    tuple[FourteenthTrancheFixtureBundle, ...],
]:
    if type(registry) is not FourteenthTrancheTaskRegistry:
        raise FourteenthTrancheFixtureCatalogError(
            "registry must be an exact FourteenthTrancheTaskRegistry"
        )
    try:
        validate_fourteenth_tranche_task_registry(registry)
    except (AttributeError, TypeError, ValueError) as exc:
        raise FourteenthTrancheFixtureCatalogError(
            "fourteenth registry is invalid"
        ) from exc
    if (
        type(bundles) is not tuple
        or len(bundles) != FOURTEENTH_TRANCHE_ADDED_FIXTURE_COUNT
        or any(
            type(bundle) is not DependencyDagExecutionPlanFixtureBundle
            for bundle in bundles
        )
    ):
        raise FourteenthTrancheFixtureCatalogError(
            "fourteenth catalog requires exactly 100 exact "
            "DependencyDagExecutionPlanFixtureBundle values"
        )

    fixture_ids: set[str] = set()
    fixture_hashes: set[str] = set()
    for index, raw_bundle in enumerate(bundles):
        task = registry.added_tasks[
            index // FOURTEENTH_TRANCHE_PROFILE_COUNT
        ]
        profile_index = index % FOURTEENTH_TRANCHE_PROFILE_COUNT
        profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[profile_index]
        bundle = _validate_bundle(
            task, profile, raw_bundle, regenerate=regenerate
        )
        if (
            bundle.task_contract_sha256 != task.task_contract_sha256
            or bundle.profile_sha256 != profile.profile_sha256
            or task.fixtures[profile_index] != bundle.descriptor
            or bundle.candidate_execution_authorized is not False
            or bundle.model_selection_eligible is not False
            or bundle.claim_authorized is not False
        ):
            raise FourteenthTrancheFixtureCatalogError(
                "bundle order, descriptor, or authority boundary is invalid"
            )
        fixture_ids.add(bundle.descriptor.fixture_id)
        fixture_hashes.add(bundle.descriptor.fixture_sha256)
    if (
        len(fixture_ids) != FOURTEENTH_TRANCHE_ADDED_FIXTURE_COUNT
        or len(fixture_hashes) != FOURTEENTH_TRANCHE_ADDED_FIXTURE_COUNT
    ):
        raise FourteenthTrancheFixtureCatalogError(
            "fourteenth-tranche fixture identities are not unique"
        )
    return registry, bundles


def _task_hash_record(task: FourteenthTrancheTask) -> dict[str, str]:
    return {
        "family_id": task.family_id,
        "task_contract_sha256": task.task_contract_sha256,
        "graph_sha256": task.graph_sha256,
    }


def _fixture_hash_record(
    bundle: FourteenthTrancheFixtureBundle,
) -> dict[str, str]:
    return {
        "task_contract_sha256": bundle.task_contract_sha256,
        "profile_sha256": bundle.profile_sha256,
        "fixture_definition_sha256": bundle.fixture_definition_sha256,
        "trusted_oracle_sha256": bundle.oracle.oracle_sha256,
        "fixture_sha256": bundle.descriptor.fixture_sha256,
    }


def _catalog_payload(
    registry: FourteenthTrancheTaskRegistry,
    bundles: tuple[FourteenthTrancheFixtureBundle, ...],
) -> dict[str, object]:
    return {
        "schema_version": FOURTEENTH_TRANCHE_CATALOG_SCHEMA_VERSION,
        "catalog_version": FOURTEENTH_TRANCHE_CATALOG_VERSION,
        "record_type": (
            "cbds.executable-fixture-fourteenth-tranche-catalog"
        ),
        "base_fixture_catalog_sha256": FROZEN_THIRTEENTH_CATALOG_SHA256,
        "added_registry_sha256": registry.registry_sha256,
        "cumulative_suite_sha256": registry.cumulative_suite_sha256,
        "base_cumulative_task_count": THIRTEENTH_PREFIX_TASK_COUNT,
        "added_task_count": FOURTEENTH_TRANCHE_ADDED_TASK_COUNT,
        "cumulative_task_count": FOURTEENTH_TRANCHE_CUMULATIVE_TASK_COUNT,
        "profiles_per_task": FOURTEENTH_TRANCHE_PROFILE_COUNT,
        "base_cumulative_fixture_count": THIRTEENTH_PREFIX_FIXTURE_COUNT,
        "added_fixture_count": FOURTEENTH_TRANCHE_ADDED_FIXTURE_COUNT,
        "cumulative_fixture_count": (
            FOURTEENTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT
        ),
        "profile_sha256": [
            profile.profile_sha256
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        ],
        "family_task_counts": {
            family: sum(
                task.family_id == family for task in registry.added_tasks
            )
            for family in FOURTEENTH_TRANCHE_FAMILY_ORDER
        },
        "family_fixture_counts": {
            family: sum(
                task.family_id == family for task in registry.added_tasks
            )
            * FOURTEENTH_TRANCHE_PROFILE_COUNT
            for family in FOURTEENTH_TRANCHE_FAMILY_ORDER
        },
        "family_generators": [
            {
                "family_id": DEPENDENCY_DAG_EXECUTION_PLAN_FAMILY_ID,
                "generator_version": (
                    DEPENDENCY_DAG_EXECUTION_PLAN_GENERATOR_VERSION
                ),
                "semantic_verifier_identity": (
                    DEPENDENCY_DAG_EXECUTION_PLAN_VERIFIER_IDENTITY
                ),
                "output_maximum_bytes": (
                    DEPENDENCY_DAG_EXECUTION_PLAN_PROVED_MAXIMUM_TOTAL_OUTPUT_BYTES
                ),
            }
        ],
        "added_tasks": [
            _task_hash_record(task) for task in registry.added_tasks
        ],
        "added_fixtures": [
            _fixture_hash_record(bundle) for bundle in bundles
        ],
        "public_method_development": True,
        "sealed": False,
        "independent_human_review_attested": False,
        "candidate_execution_authorized": False,
        "model_selection_eligible": False,
        "claim_authorized": False,
    }


def _catalog_digest(
    registry: FourteenthTrancheTaskRegistry,
    bundles: tuple[FourteenthTrancheFixtureBundle, ...],
) -> str:
    return domain_sha256(
        "cbds.executable-fixture.fourteenth-tranche-catalog.v1",
        _catalog_payload(registry, bundles),
    )


def compute_fourteenth_tranche_fixture_catalog_sha256(
    registry: FourteenthTrancheTaskRegistry,
    bundles: tuple[FourteenthTrancheFixtureBundle, ...],
) -> str:
    selected_registry, selected_bundles = _validate_inputs(
        registry, bundles, regenerate=True
    )
    return _catalog_digest(selected_registry, selected_bundles)


@dataclass(frozen=True, slots=True)
class FourteenthTrancheFixtureCatalog:
    registry: FourteenthTrancheTaskRegistry = field(repr=False)
    bundles: tuple[FourteenthTrancheFixtureBundle, ...] = field(repr=False)
    catalog_sha256: str
    schema_version: str = FOURTEENTH_TRANCHE_CATALOG_SCHEMA_VERSION
    catalog_version: str = FOURTEENTH_TRANCHE_CATALOG_VERSION
    base_fixture_catalog_sha256: str = FROZEN_THIRTEENTH_CATALOG_SHA256
    public_method_development: bool = True
    sealed: bool = False
    independent_human_review_attested: bool = False
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_fourteenth_tranche_fixture_catalog(self)

    def to_hash_only_record(self) -> dict[str, object]:
        _validate_catalog_snapshot(self)
        return {
            **_catalog_payload(self.registry, self.bundles),
            "catalog_sha256": self.catalog_sha256,
        }


def _validate_metadata(
    catalog: object,
) -> FourteenthTrancheFixtureCatalog:
    if type(catalog) is not FourteenthTrancheFixtureCatalog:
        raise FourteenthTrancheFixtureCatalogError(
            "catalog must be an exact FourteenthTrancheFixtureCatalog"
        )
    if (
        type(catalog.schema_version) is not str
        or catalog.schema_version
        != FOURTEENTH_TRANCHE_CATALOG_SCHEMA_VERSION
        or type(catalog.catalog_version) is not str
        or catalog.catalog_version != FOURTEENTH_TRANCHE_CATALOG_VERSION
        or not _is_sha256(catalog.base_fixture_catalog_sha256)
        or catalog.base_fixture_catalog_sha256
        != FROZEN_THIRTEENTH_CATALOG_SHA256
        or not _is_sha256(catalog.catalog_sha256)
        or catalog.public_method_development is not True
        or catalog.sealed is not False
        or catalog.independent_human_review_attested is not False
        or catalog.candidate_execution_authorized is not False
        or catalog.model_selection_eligible is not False
        or catalog.claim_authorized is not False
    ):
        raise FourteenthTrancheFixtureCatalogError(
            "fourteenth-tranche catalog metadata is invalid"
        )
    return catalog


def validate_fourteenth_tranche_fixture_catalog(
    catalog: FourteenthTrancheFixtureCatalog,
) -> None:
    selected = _validate_metadata(catalog)
    registry, bundles = _validate_inputs(
        selected.registry, selected.bundles, regenerate=True
    )
    if (
        selected.catalog_sha256 != _catalog_digest(registry, bundles)
        or selected.catalog_sha256 != FROZEN_FOURTEENTH_CATALOG_SHA256
    ):
        raise FourteenthTrancheFixtureCatalogError(
            "fourteenth-tranche catalog digest is invalid"
        )


def _validate_catalog_snapshot(
    catalog: FourteenthTrancheFixtureCatalog,
) -> None:
    selected = _validate_metadata(catalog)
    registry, bundles = _validate_inputs(
        selected.registry, selected.bundles, regenerate=False
    )
    if (
        selected.catalog_sha256 != _catalog_digest(registry, bundles)
        or selected.catalog_sha256 != FROZEN_FOURTEENTH_CATALOG_SHA256
    ):
        raise FourteenthTrancheFixtureCatalogError(
            "fourteenth-tranche catalog digest is invalid"
        )


def verify_fourteenth_tranche_fixture_catalog(catalog: object) -> bool:
    try:
        validate_fourteenth_tranche_fixture_catalog(
            catalog  # type: ignore[arg-type]
        )
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def _validate_live_base_and_global_uniqueness(
    registry: FourteenthTrancheTaskRegistry,
    bundles: tuple[FourteenthTrancheFixtureBundle, ...],
    evidence: ThirteenthPrefixFixtureEvidence,
) -> None:
    """Admit the exact thirteenth prefix and reject cross-chain collisions."""

    try:
        validate_thirteenth_prefix_fixture_evidence(evidence)
    except (AttributeError, TypeError, ValueError) as exc:
        raise FourteenthTrancheFixtureCatalogError(
            "through-thirteenth fixture evidence could not be established"
        ) from exc
    if (
        evidence.total_fixture_count != THIRTEENTH_PREFIX_FIXTURE_COUNT
        or evidence.terminal_catalog_sha256
        != FROZEN_THIRTEENTH_CATALOG_SHA256
        or evidence.task_evidence.terminal_registry_sha256
        != FROZEN_THIRTEENTH_REGISTRY_SHA256
        or evidence.task_evidence.terminal_cumulative_suite_sha256
        != FROZEN_THIRTEENTH_CUMULATIVE_SUITE_SHA256
        or registry.base_added_registry_sha256
        != evidence.task_evidence.terminal_registry_sha256
        or registry.base_cumulative_suite_sha256
        != evidence.task_evidence.terminal_cumulative_suite_sha256
    ):
        raise FourteenthTrancheFixtureCatalogError(
            "a live predecessor differs from its frozen thirteenth identity"
        )
    all_bundles = (*evidence.bundles, *bundles)
    if (
        len(all_bundles) != FOURTEENTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT
        or len({bundle.descriptor.fixture_id for bundle in all_bundles})
        != len(all_bundles)
        or len(
            {
                bundle.descriptor.fixture_sha256
                for bundle in all_bundles
            }
        )
        != len(all_bundles)
    ):
        raise FourteenthTrancheFixtureCatalogError(
            "fourteenth-tranche fixtures collide with a frozen predecessor"
        )
    if any(
        bundle is predecessor
        for bundle in bundles
        for predecessor in evidence.bundles
    ):
        raise FourteenthTrancheFixtureCatalogError(
            "fourteenth-tranche fixtures must be freshly owned additions"
        )


def build_fourteenth_tranche_fixture_catalog_local(
    registry: FourteenthTrancheTaskRegistry,
) -> FourteenthTrancheFixtureCatalog:
    """Build only fourteenth bundles without predecessor reconstruction."""

    if type(registry) is not FourteenthTrancheTaskRegistry:
        raise TypeError(
            "registry must be an exact FourteenthTrancheTaskRegistry"
        )
    validate_fourteenth_tranche_task_registry(registry)
    bundles = tuple(
        _build_bundle(task, profile)
        for task in registry.added_tasks
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
    )
    selected_registry, selected_bundles = _validate_inputs(
        registry, bundles, regenerate=False
    )
    digest = _catalog_digest(selected_registry, selected_bundles)

    catalog = object.__new__(FourteenthTrancheFixtureCatalog)
    values: dict[str, object] = {
        "registry": selected_registry,
        "bundles": selected_bundles,
        "catalog_sha256": digest,
        "schema_version": FOURTEENTH_TRANCHE_CATALOG_SCHEMA_VERSION,
        "catalog_version": FOURTEENTH_TRANCHE_CATALOG_VERSION,
        "base_fixture_catalog_sha256": FROZEN_THIRTEENTH_CATALOG_SHA256,
        "public_method_development": True,
        "sealed": False,
        "independent_human_review_attested": False,
        "candidate_execution_authorized": False,
        "model_selection_eligible": False,
        "claim_authorized": False,
    }
    for name, value in values.items():
        object.__setattr__(catalog, name, value)
    _validate_catalog_snapshot(catalog)
    return catalog


def build_fourteenth_tranche_fixture_catalog(
    registry: FourteenthTrancheTaskRegistry | None = None,
) -> FourteenthTrancheFixtureCatalog:
    """Build the catalog over one shared through-thirteenth snapshot."""

    task_evidence = build_thirteenth_prefix_task_evidence()
    validate_thirteenth_prefix_task_evidence(task_evidence)
    live_registry = build_fourteenth_tranche_task_registry(task_evidence)
    selected_registry = live_registry if registry is None else registry
    if type(selected_registry) is not FourteenthTrancheTaskRegistry:
        raise TypeError(
            "registry must be an exact FourteenthTrancheTaskRegistry"
        )
    validate_fourteenth_tranche_task_registry(selected_registry)
    if selected_registry != live_registry:
        raise FourteenthTrancheFixtureCatalogError(
            "supplied registry differs from the live collision-checked addition"
        )
    fixture_evidence = build_thirteenth_prefix_fixture_evidence(
        task_evidence
    )
    catalog = build_fourteenth_tranche_fixture_catalog_local(
        selected_registry
    )
    _validate_live_base_and_global_uniqueness(
        selected_registry, catalog.bundles, fixture_evidence
    )
    return catalog


__all__ = [
    "FROZEN_FOURTEENTH_CATALOG_SHA256",
    "FROZEN_THIRTEENTH_CATALOG_SHA256",
    "FOURTEENTH_TRANCHE_ADDED_FIXTURE_COUNT",
    "FOURTEENTH_TRANCHE_CATALOG_SCHEMA_VERSION",
    "FOURTEENTH_TRANCHE_CATALOG_VERSION",
    "FOURTEENTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT",
    "FOURTEENTH_TRANCHE_FIXTURE_COUNT",
    "FOURTEENTH_TRANCHE_PROFILE_COUNT",
    "FourteenthTrancheFixtureBundle",
    "FourteenthTrancheFixtureCatalog",
    "FourteenthTrancheFixtureCatalogError",
    "build_fourteenth_tranche_fixture_catalog",
    "build_fourteenth_tranche_fixture_catalog_local",
    "compute_fourteenth_tranche_fixture_catalog_sha256",
    "validate_fourteenth_tranche_fixture_catalog",
    "verify_fourteenth_tranche_fixture_catalog",
]
