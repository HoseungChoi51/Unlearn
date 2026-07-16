"""Hash-bound third additive catalog for two public development families.

The catalog preserves the first and second tranche identities, authenticates
40 family-local task contracts against five public profiles, and commits to
200 newly generated fixture/oracle bindings.  The hash-only projection omits
fixture and answer bytes; their deterministic source remains public.  This is
public, unsealed method-development data and never authorizes candidate
execution, model selection, scoring, or a research claim.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Final, TypeAlias

from .executable_compound_path_query import (
    COMPOUND_PATH_QUERY_GENERATOR_VERSION,
    COMPOUND_PATH_QUERY_OUTPUT_MAXIMUM_BYTES,
    COMPOUND_PATH_QUERY_VERIFIER_IDENTITY,
    CompoundPathQueryFixtureBundle,
    CompoundPathQueryTask,
    build_compound_path_query_fixture_bundle,
    validate_compound_path_query_fixture_bundle,
    validate_compound_path_query_fixture_for_task_profile,
)
from .executable_fixture_profiles import (
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
    ExecutableFixtureProfile,
)
from .executable_log_aggregation_pipeline import (
    LOG_AGGREGATION_GENERATOR_VERSION,
    LOG_AGGREGATION_OUTPUT_MAXIMUM_BYTES,
    LOG_AGGREGATION_VERIFIER_IDENTITY,
    LogAggregationFixtureBundle,
    LogAggregationTask,
    build_log_aggregation_fixture_bundle,
    validate_log_aggregation_fixture_bundle,
    validate_log_aggregation_fixture_for_task_profile,
)
from .executable_static_third_registry import (
    THIRD_TRANCHE_ADDED_TASK_COUNT,
    THIRD_TRANCHE_CUMULATIVE_TASK_COUNT,
    THIRD_TRANCHE_FAMILY_ORDER,
    ThirdTrancheTask,
    ThirdTrancheTaskRegistry,
    build_third_tranche_task_registry,
    validate_third_tranche_task_registry,
)
from .executable_static_types import domain_sha256


THIRD_TRANCHE_CATALOG_SCHEMA_VERSION: Final[str] = "1.0.0"
THIRD_TRANCHE_CATALOG_VERSION: Final[str] = "1.0.0"
THIRD_TRANCHE_PROFILE_COUNT: Final[int] = 5
THIRD_TRANCHE_ADDED_FIXTURE_COUNT: Final[int] = 200
THIRD_TRANCHE_CUMULATIVE_FIXTURE_COUNT: Final[int] = 1_200
THIRD_TRANCHE_FIXTURE_COUNT: Final[int] = THIRD_TRANCHE_ADDED_FIXTURE_COUNT
FROZEN_FIRST_CATALOG_SHA256: Final[str] = (
    "1fc71f89830739a53b69d771b7d0bd6a79a4d78ff698b1c1c2258211e7776c99"
)
FROZEN_SECOND_CATALOG_SHA256: Final[str] = (
    "e2ad6a3124491bc25410d40278400aeac9cd8791a9f08a530c823d5f14c09e18"
)

ThirdTrancheFixtureBundle: TypeAlias = (
    CompoundPathQueryFixtureBundle | LogAggregationFixtureBundle
)
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")


class ThirdTrancheFixtureCatalogError(ValueError):
    """Raised when the additive catalog is not exactly reproducible."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def _build_bundle(
    task: ThirdTrancheTask,
    profile: ExecutableFixtureProfile,
) -> ThirdTrancheFixtureBundle:
    if type(task) is CompoundPathQueryTask:
        bundle = build_compound_path_query_fixture_bundle(task, profile)
        validate_compound_path_query_fixture_for_task_profile(task, profile, bundle)
        return bundle
    if type(task) is LogAggregationTask:
        bundle = build_log_aggregation_fixture_bundle(task, profile)
        validate_log_aggregation_fixture_for_task_profile(task, profile, bundle)
        return bundle
    raise ThirdTrancheFixtureCatalogError("task type is outside the third tranche")


def _validate_bundle(
    task: ThirdTrancheTask,
    profile: ExecutableFixtureProfile,
    bundle: object,
    *,
    regenerate: bool,
) -> ThirdTrancheFixtureBundle:
    try:
        if type(task) is CompoundPathQueryTask:
            if type(bundle) is not CompoundPathQueryFixtureBundle:
                raise ThirdTrancheFixtureCatalogError(
                    "compound-path task has the wrong bundle type"
                )
            validate_compound_path_query_fixture_bundle(bundle)
            validate_compound_path_query_fixture_for_task_profile(
                task, profile, bundle
            )
        elif type(task) is LogAggregationTask:
            if type(bundle) is not LogAggregationFixtureBundle:
                raise ThirdTrancheFixtureCatalogError(
                    "log-aggregation task has the wrong bundle type"
                )
            validate_log_aggregation_fixture_bundle(bundle)
            validate_log_aggregation_fixture_for_task_profile(task, profile, bundle)
        else:
            raise ThirdTrancheFixtureCatalogError(
                "third-tranche task has the wrong exact type"
            )
    except (AttributeError, TypeError, ValueError) as exc:
        if isinstance(exc, ThirdTrancheFixtureCatalogError):
            raise
        raise ThirdTrancheFixtureCatalogError(
            "family-local bundle validation failed"
        ) from exc
    selected = bundle
    if regenerate and selected != _build_bundle(task, profile):
        raise ThirdTrancheFixtureCatalogError(
            "bundle differs from deterministic family generation"
        )
    return selected


def _validate_inputs(
    registry: object,
    bundles: object,
    *,
    regenerate: bool,
) -> tuple[ThirdTrancheTaskRegistry, tuple[ThirdTrancheFixtureBundle, ...]]:
    if type(registry) is not ThirdTrancheTaskRegistry:
        raise ThirdTrancheFixtureCatalogError(
            "registry must be an exact ThirdTrancheTaskRegistry"
        )
    try:
        validate_third_tranche_task_registry(registry)
    except (AttributeError, TypeError, ValueError) as exc:
        raise ThirdTrancheFixtureCatalogError("third registry is invalid") from exc
    if (
        type(bundles) is not tuple
        or len(bundles) != THIRD_TRANCHE_ADDED_FIXTURE_COUNT
        or any(
            type(bundle)
            not in {CompoundPathQueryFixtureBundle, LogAggregationFixtureBundle}
            for bundle in bundles
        )
    ):
        raise ThirdTrancheFixtureCatalogError(
            "third catalog requires exactly 200 exact family-local bundles"
        )

    fixture_ids: set[str] = set()
    fixture_hashes: set[str] = set()
    for index, raw_bundle in enumerate(bundles):
        task = registry.added_tasks[index // THIRD_TRANCHE_PROFILE_COUNT]
        profile_index = index % THIRD_TRANCHE_PROFILE_COUNT
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
            raise ThirdTrancheFixtureCatalogError(
                "bundle order, descriptor, or authority boundary is invalid"
            )
        fixture_ids.add(bundle.descriptor.fixture_id)
        fixture_hashes.add(bundle.descriptor.fixture_sha256)
    if (
        len(fixture_ids) != THIRD_TRANCHE_ADDED_FIXTURE_COUNT
        or len(fixture_hashes) != THIRD_TRANCHE_ADDED_FIXTURE_COUNT
    ):
        raise ThirdTrancheFixtureCatalogError(
            "third-tranche fixture identities are not unique"
        )
    return registry, bundles


def _task_hash_record(task: ThirdTrancheTask) -> dict[str, str]:
    return {
        "family_id": task.family_id,
        "task_contract_sha256": task.task_contract_sha256,
        "graph_sha256": task.graph_sha256,
    }


def _fixture_hash_record(bundle: ThirdTrancheFixtureBundle) -> dict[str, str]:
    return {
        "task_contract_sha256": bundle.task_contract_sha256,
        "profile_sha256": bundle.profile_sha256,
        "fixture_definition_sha256": bundle.fixture_definition_sha256,
        "trusted_oracle_sha256": bundle.oracle.oracle_sha256,
        "fixture_sha256": bundle.descriptor.fixture_sha256,
    }


def _catalog_payload(
    registry: ThirdTrancheTaskRegistry,
    bundles: tuple[ThirdTrancheFixtureBundle, ...],
) -> dict[str, object]:
    return {
        "schema_version": THIRD_TRANCHE_CATALOG_SCHEMA_VERSION,
        "catalog_version": THIRD_TRANCHE_CATALOG_VERSION,
        "record_type": "cbds.executable-fixture-third-tranche-catalog",
        "base_fixture_catalog_sha256": FROZEN_SECOND_CATALOG_SHA256,
        "added_registry_sha256": registry.registry_sha256,
        "cumulative_suite_sha256": registry.cumulative_suite_sha256,
        "base_cumulative_task_count": 200,
        "added_task_count": THIRD_TRANCHE_ADDED_TASK_COUNT,
        "cumulative_task_count": THIRD_TRANCHE_CUMULATIVE_TASK_COUNT,
        "profiles_per_task": THIRD_TRANCHE_PROFILE_COUNT,
        "base_cumulative_fixture_count": 1_000,
        "added_fixture_count": THIRD_TRANCHE_ADDED_FIXTURE_COUNT,
        "cumulative_fixture_count": THIRD_TRANCHE_CUMULATIVE_FIXTURE_COUNT,
        "profile_sha256": [
            profile.profile_sha256
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        ],
        "family_task_counts": {
            family: sum(task.family_id == family for task in registry.added_tasks)
            for family in THIRD_TRANCHE_FAMILY_ORDER
        },
        "family_fixture_counts": {
            family: sum(task.family_id == family for task in registry.added_tasks)
            * THIRD_TRANCHE_PROFILE_COUNT
            for family in THIRD_TRANCHE_FAMILY_ORDER
        },
        "family_generators": [
            {
                "family_id": "compound-path-query",
                "generator_version": COMPOUND_PATH_QUERY_GENERATOR_VERSION,
                "semantic_verifier_identity": (
                    COMPOUND_PATH_QUERY_VERIFIER_IDENTITY
                ),
                "output_maximum_bytes": (
                    COMPOUND_PATH_QUERY_OUTPUT_MAXIMUM_BYTES
                ),
            },
            {
                "family_id": "regex-log-group-aggregation",
                "generator_version": LOG_AGGREGATION_GENERATOR_VERSION,
                "semantic_verifier_identity": (
                    LOG_AGGREGATION_VERIFIER_IDENTITY
                ),
                "output_maximum_bytes": LOG_AGGREGATION_OUTPUT_MAXIMUM_BYTES,
            },
        ],
        "added_tasks": [_task_hash_record(task) for task in registry.added_tasks],
        "added_fixtures": [_fixture_hash_record(bundle) for bundle in bundles],
        "public_method_development": True,
        "sealed": False,
        "independent_human_review_attested": False,
        "candidate_execution_authorized": False,
        "model_selection_eligible": False,
        "claim_authorized": False,
    }


def _catalog_digest(
    registry: ThirdTrancheTaskRegistry,
    bundles: tuple[ThirdTrancheFixtureBundle, ...],
) -> str:
    return domain_sha256(
        "cbds.executable-fixture.third-tranche-catalog.v1",
        _catalog_payload(registry, bundles),
    )


def compute_third_tranche_fixture_catalog_sha256(
    registry: ThirdTrancheTaskRegistry,
    bundles: tuple[ThirdTrancheFixtureBundle, ...],
) -> str:
    selected_registry, selected_bundles = _validate_inputs(
        registry, bundles, regenerate=True
    )
    return _catalog_digest(selected_registry, selected_bundles)


@dataclass(frozen=True, slots=True)
class ThirdTrancheFixtureCatalog:
    registry: ThirdTrancheTaskRegistry = field(repr=False)
    bundles: tuple[ThirdTrancheFixtureBundle, ...] = field(repr=False)
    catalog_sha256: str
    schema_version: str = THIRD_TRANCHE_CATALOG_SCHEMA_VERSION
    catalog_version: str = THIRD_TRANCHE_CATALOG_VERSION
    base_fixture_catalog_sha256: str = FROZEN_SECOND_CATALOG_SHA256
    public_method_development: bool = True
    sealed: bool = False
    independent_human_review_attested: bool = False
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_third_tranche_fixture_catalog(self)

    def to_hash_only_record(self) -> dict[str, object]:
        _validate_catalog_snapshot(self)
        return {
            **_catalog_payload(self.registry, self.bundles),
            "catalog_sha256": self.catalog_sha256,
        }


def _validate_metadata(catalog: object) -> ThirdTrancheFixtureCatalog:
    if type(catalog) is not ThirdTrancheFixtureCatalog:
        raise ThirdTrancheFixtureCatalogError(
            "catalog must be an exact ThirdTrancheFixtureCatalog"
        )
    if (
        type(catalog.schema_version) is not str
        or catalog.schema_version != THIRD_TRANCHE_CATALOG_SCHEMA_VERSION
        or type(catalog.catalog_version) is not str
        or catalog.catalog_version != THIRD_TRANCHE_CATALOG_VERSION
        or not _is_sha256(catalog.base_fixture_catalog_sha256)
        or catalog.base_fixture_catalog_sha256 != FROZEN_SECOND_CATALOG_SHA256
        or not _is_sha256(catalog.catalog_sha256)
        or catalog.public_method_development is not True
        or catalog.sealed is not False
        or catalog.independent_human_review_attested is not False
        or catalog.candidate_execution_authorized is not False
        or catalog.model_selection_eligible is not False
        or catalog.claim_authorized is not False
    ):
        raise ThirdTrancheFixtureCatalogError("catalog metadata is invalid")
    return catalog


def validate_third_tranche_fixture_catalog(
    catalog: ThirdTrancheFixtureCatalog,
) -> None:
    selected = _validate_metadata(catalog)
    registry, bundles = _validate_inputs(
        selected.registry, selected.bundles, regenerate=True
    )
    if selected.catalog_sha256 != _catalog_digest(registry, bundles):
        raise ThirdTrancheFixtureCatalogError("catalog digest is invalid")


def _validate_catalog_snapshot(catalog: ThirdTrancheFixtureCatalog) -> None:
    selected = _validate_metadata(catalog)
    registry, bundles = _validate_inputs(
        selected.registry, selected.bundles, regenerate=False
    )
    if selected.catalog_sha256 != _catalog_digest(registry, bundles):
        raise ThirdTrancheFixtureCatalogError("catalog digest is invalid")


def verify_third_tranche_fixture_catalog(catalog: object) -> bool:
    try:
        validate_third_tranche_fixture_catalog(catalog)  # type: ignore[arg-type]
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def _validate_live_base_and_global_uniqueness(
    bundles: tuple[ThirdTrancheFixtureBundle, ...],
) -> None:
    from .executable_fixture_catalog import build_first_tranche_fixture_catalog
    from .executable_fixture_second_catalog import build_second_tranche_fixture_catalog
    from .executable_static_registry import build_public_method_development_registry

    first = build_first_tranche_fixture_catalog(
        build_public_method_development_registry()
    )
    second = build_second_tranche_fixture_catalog()
    if (
        first.catalog_sha256 != FROZEN_FIRST_CATALOG_SHA256
        or second.catalog_sha256 != FROZEN_SECOND_CATALOG_SHA256
    ):
        raise ThirdTrancheFixtureCatalogError(
            "a live predecessor catalog differs from its frozen base"
        )
    all_bundles = (*first.bundles, *second.bundles, *bundles)
    if (
        len(all_bundles) != THIRD_TRANCHE_CUMULATIVE_FIXTURE_COUNT
        or len({bundle.descriptor.fixture_id for bundle in all_bundles})
        != len(all_bundles)
        or len({bundle.descriptor.fixture_sha256 for bundle in all_bundles})
        != len(all_bundles)
    ):
        raise ThirdTrancheFixtureCatalogError(
            "third-tranche fixtures collide with a frozen predecessor"
        )


def build_third_tranche_fixture_catalog(
    registry: ThirdTrancheTaskRegistry | None = None,
) -> ThirdTrancheFixtureCatalog:
    selected_registry = (
        build_third_tranche_task_registry() if registry is None else registry
    )
    if type(selected_registry) is not ThirdTrancheTaskRegistry:
        raise TypeError("registry must be an exact ThirdTrancheTaskRegistry")
    validate_third_tranche_task_registry(selected_registry)
    bundles = tuple(
        _build_bundle(task, profile)
        for task in selected_registry.added_tasks
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
    )
    selected_registry, selected_bundles = _validate_inputs(
        selected_registry, bundles, regenerate=False
    )
    _validate_live_base_and_global_uniqueness(selected_bundles)
    digest = _catalog_digest(selected_registry, selected_bundles)

    # Avoid a second 200-bundle regeneration after every value was produced by
    # the closed builders and checked above.  Public construction and explicit
    # validation remain exhaustive.
    catalog = object.__new__(ThirdTrancheFixtureCatalog)
    values: dict[str, object] = {
        "registry": selected_registry,
        "bundles": selected_bundles,
        "catalog_sha256": digest,
        "schema_version": THIRD_TRANCHE_CATALOG_SCHEMA_VERSION,
        "catalog_version": THIRD_TRANCHE_CATALOG_VERSION,
        "base_fixture_catalog_sha256": FROZEN_SECOND_CATALOG_SHA256,
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


__all__ = [
    "FROZEN_FIRST_CATALOG_SHA256",
    "FROZEN_SECOND_CATALOG_SHA256",
    "THIRD_TRANCHE_ADDED_FIXTURE_COUNT",
    "THIRD_TRANCHE_CATALOG_SCHEMA_VERSION",
    "THIRD_TRANCHE_CATALOG_VERSION",
    "THIRD_TRANCHE_CUMULATIVE_FIXTURE_COUNT",
    "THIRD_TRANCHE_FIXTURE_COUNT",
    "THIRD_TRANCHE_PROFILE_COUNT",
    "ThirdTrancheFixtureCatalog",
    "ThirdTrancheFixtureCatalogError",
    "build_third_tranche_fixture_catalog",
    "compute_third_tranche_fixture_catalog_sha256",
    "validate_third_tranche_fixture_catalog",
    "verify_third_tranche_fixture_catalog",
]
