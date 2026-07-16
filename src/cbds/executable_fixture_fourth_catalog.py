"""Hash-bound fourth catalog for reproducible-ustar-pack fixtures.

The catalog preserves the first three tranche identities, authenticates the
exact 20-task family-local grid against five public profiles, and commits to
100 newly generated fixture/oracle bindings.  Its hash-only projection omits
fixture, oracle, prompt, and path bytes.  This is public, unsealed
method-development data and never authorizes candidate execution, model
selection, scoring, or a research claim.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Final, TypeAlias

from .executable_fixture_profiles import (
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
    ExecutableFixtureProfile,
)
from .executable_static_fourth_registry import (
    FOURTH_TRANCHE_ADDED_TASK_COUNT,
    FOURTH_TRANCHE_CUMULATIVE_TASK_COUNT,
    FOURTH_TRANCHE_FAMILY_ORDER,
    FourthTrancheTask,
    FourthTrancheTaskRegistry,
    build_fourth_tranche_task_registry,
    validate_fourth_tranche_task_registry,
)
from .executable_static_types import domain_sha256
from .executable_ustar_pack import (
    USTAR_PACK_FAMILY_ID,
    USTAR_PACK_GENERATOR_VERSION,
    USTAR_PACK_OUTPUT_MAXIMUM_BYTES,
    USTAR_PACK_VERIFIER_IDENTITY,
    UstarPackFixtureBundle,
    UstarPackTask,
    build_ustar_pack_fixture_bundle,
    validate_ustar_pack_fixture_bundle,
    validate_ustar_pack_fixture_for_task_profile,
)


FOURTH_TRANCHE_CATALOG_SCHEMA_VERSION: Final[str] = "1.0.0"
FOURTH_TRANCHE_CATALOG_VERSION: Final[str] = "1.0.0"
FOURTH_TRANCHE_PROFILE_COUNT: Final[int] = 5
FOURTH_TRANCHE_ADDED_FIXTURE_COUNT: Final[int] = 100
FOURTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT: Final[int] = 1_300
FOURTH_TRANCHE_FIXTURE_COUNT: Final[int] = FOURTH_TRANCHE_ADDED_FIXTURE_COUNT
FROZEN_FIRST_CATALOG_SHA256: Final[str] = (
    "1fc71f89830739a53b69d771b7d0bd6a79a4d78ff698b1c1c2258211e7776c99"
)
FROZEN_SECOND_CATALOG_SHA256: Final[str] = (
    "e2ad6a3124491bc25410d40278400aeac9cd8791a9f08a530c823d5f14c09e18"
)
FROZEN_THIRD_CATALOG_SHA256: Final[str] = (
    "01554367fd68c36b2f509b8b50b270b0aa7d5e6de3fa55db15a14cf4ec68c26b"
)

FourthTrancheFixtureBundle: TypeAlias = UstarPackFixtureBundle
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")


class FourthTrancheFixtureCatalogError(ValueError):
    """Raised when the fourth additive catalog is not reproducible."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def _build_bundle(
    task: FourthTrancheTask,
    profile: ExecutableFixtureProfile,
) -> FourthTrancheFixtureBundle:
    if type(task) is not UstarPackTask:
        raise FourthTrancheFixtureCatalogError(
            "task type is outside the fourth tranche"
        )
    bundle = build_ustar_pack_fixture_bundle(task, profile)
    validate_ustar_pack_fixture_for_task_profile(task, profile, bundle)
    return bundle


def _validate_bundle(
    task: FourthTrancheTask,
    profile: ExecutableFixtureProfile,
    bundle: object,
    *,
    regenerate: bool,
) -> FourthTrancheFixtureBundle:
    try:
        if type(task) is not UstarPackTask:
            raise FourthTrancheFixtureCatalogError(
                "fourth-tranche task has the wrong exact type"
            )
        if type(bundle) is not UstarPackFixtureBundle:
            raise FourthTrancheFixtureCatalogError(
                "ustar-pack task has the wrong bundle type"
            )
        validate_ustar_pack_fixture_bundle(bundle)
        validate_ustar_pack_fixture_for_task_profile(task, profile, bundle)
    except (AttributeError, TypeError, ValueError) as exc:
        if isinstance(exc, FourthTrancheFixtureCatalogError):
            raise
        raise FourthTrancheFixtureCatalogError(
            "family-local bundle validation failed"
        ) from exc
    selected = bundle
    if regenerate and selected != _build_bundle(task, profile):
        raise FourthTrancheFixtureCatalogError(
            "bundle differs from deterministic family generation"
        )
    return selected


def _validate_inputs(
    registry: object,
    bundles: object,
    *,
    regenerate: bool,
) -> tuple[
    FourthTrancheTaskRegistry,
    tuple[FourthTrancheFixtureBundle, ...],
]:
    if type(registry) is not FourthTrancheTaskRegistry:
        raise FourthTrancheFixtureCatalogError(
            "registry must be an exact FourthTrancheTaskRegistry"
        )
    try:
        validate_fourth_tranche_task_registry(registry)
    except (AttributeError, TypeError, ValueError) as exc:
        raise FourthTrancheFixtureCatalogError(
            "fourth registry is invalid"
        ) from exc
    if (
        type(bundles) is not tuple
        or len(bundles) != FOURTH_TRANCHE_ADDED_FIXTURE_COUNT
        or any(type(bundle) is not UstarPackFixtureBundle for bundle in bundles)
    ):
        raise FourthTrancheFixtureCatalogError(
            "fourth catalog requires exactly 100 exact UstarPackFixtureBundle values"
        )

    fixture_ids: set[str] = set()
    fixture_hashes: set[str] = set()
    for index, raw_bundle in enumerate(bundles):
        task = registry.added_tasks[index // FOURTH_TRANCHE_PROFILE_COUNT]
        profile_index = index % FOURTH_TRANCHE_PROFILE_COUNT
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
            raise FourthTrancheFixtureCatalogError(
                "bundle order, descriptor, or authority boundary is invalid"
            )
        fixture_ids.add(bundle.descriptor.fixture_id)
        fixture_hashes.add(bundle.descriptor.fixture_sha256)
    if (
        len(fixture_ids) != FOURTH_TRANCHE_ADDED_FIXTURE_COUNT
        or len(fixture_hashes) != FOURTH_TRANCHE_ADDED_FIXTURE_COUNT
    ):
        raise FourthTrancheFixtureCatalogError(
            "fourth-tranche fixture identities are not unique"
        )
    return registry, bundles


def _task_hash_record(task: FourthTrancheTask) -> dict[str, str]:
    return {
        "family_id": task.family_id,
        "task_contract_sha256": task.task_contract_sha256,
        "graph_sha256": task.graph_sha256,
    }


def _fixture_hash_record(
    bundle: FourthTrancheFixtureBundle,
) -> dict[str, str]:
    return {
        "task_contract_sha256": bundle.task_contract_sha256,
        "profile_sha256": bundle.profile_sha256,
        "fixture_definition_sha256": bundle.fixture_definition_sha256,
        "trusted_oracle_sha256": bundle.oracle.oracle_sha256,
        "fixture_sha256": bundle.descriptor.fixture_sha256,
    }


def _catalog_payload(
    registry: FourthTrancheTaskRegistry,
    bundles: tuple[FourthTrancheFixtureBundle, ...],
) -> dict[str, object]:
    return {
        "schema_version": FOURTH_TRANCHE_CATALOG_SCHEMA_VERSION,
        "catalog_version": FOURTH_TRANCHE_CATALOG_VERSION,
        "record_type": "cbds.executable-fixture-fourth-tranche-catalog",
        "base_fixture_catalog_sha256": FROZEN_THIRD_CATALOG_SHA256,
        "added_registry_sha256": registry.registry_sha256,
        "cumulative_suite_sha256": registry.cumulative_suite_sha256,
        "base_cumulative_task_count": 240,
        "added_task_count": FOURTH_TRANCHE_ADDED_TASK_COUNT,
        "cumulative_task_count": FOURTH_TRANCHE_CUMULATIVE_TASK_COUNT,
        "profiles_per_task": FOURTH_TRANCHE_PROFILE_COUNT,
        "base_cumulative_fixture_count": 1_200,
        "added_fixture_count": FOURTH_TRANCHE_ADDED_FIXTURE_COUNT,
        "cumulative_fixture_count": FOURTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT,
        "profile_sha256": [
            profile.profile_sha256
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        ],
        "family_task_counts": {
            family: sum(
                task.family_id == family for task in registry.added_tasks
            )
            for family in FOURTH_TRANCHE_FAMILY_ORDER
        },
        "family_fixture_counts": {
            family: sum(
                task.family_id == family for task in registry.added_tasks
            )
            * FOURTH_TRANCHE_PROFILE_COUNT
            for family in FOURTH_TRANCHE_FAMILY_ORDER
        },
        "family_generators": [
            {
                "family_id": USTAR_PACK_FAMILY_ID,
                "generator_version": USTAR_PACK_GENERATOR_VERSION,
                "semantic_verifier_identity": USTAR_PACK_VERIFIER_IDENTITY,
                "output_maximum_bytes": USTAR_PACK_OUTPUT_MAXIMUM_BYTES,
            },
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
    registry: FourthTrancheTaskRegistry,
    bundles: tuple[FourthTrancheFixtureBundle, ...],
) -> str:
    return domain_sha256(
        "cbds.executable-fixture.fourth-tranche-catalog.v1",
        _catalog_payload(registry, bundles),
    )


def compute_fourth_tranche_fixture_catalog_sha256(
    registry: FourthTrancheTaskRegistry,
    bundles: tuple[FourthTrancheFixtureBundle, ...],
) -> str:
    selected_registry, selected_bundles = _validate_inputs(
        registry, bundles, regenerate=True
    )
    return _catalog_digest(selected_registry, selected_bundles)


@dataclass(frozen=True, slots=True)
class FourthTrancheFixtureCatalog:
    registry: FourthTrancheTaskRegistry = field(repr=False)
    bundles: tuple[FourthTrancheFixtureBundle, ...] = field(repr=False)
    catalog_sha256: str
    schema_version: str = FOURTH_TRANCHE_CATALOG_SCHEMA_VERSION
    catalog_version: str = FOURTH_TRANCHE_CATALOG_VERSION
    base_fixture_catalog_sha256: str = FROZEN_THIRD_CATALOG_SHA256
    public_method_development: bool = True
    sealed: bool = False
    independent_human_review_attested: bool = False
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_fourth_tranche_fixture_catalog(self)

    def to_hash_only_record(self) -> dict[str, object]:
        _validate_catalog_snapshot(self)
        return {
            **_catalog_payload(self.registry, self.bundles),
            "catalog_sha256": self.catalog_sha256,
        }


def _validate_metadata(catalog: object) -> FourthTrancheFixtureCatalog:
    if type(catalog) is not FourthTrancheFixtureCatalog:
        raise FourthTrancheFixtureCatalogError(
            "catalog must be an exact FourthTrancheFixtureCatalog"
        )
    if (
        type(catalog.schema_version) is not str
        or catalog.schema_version != FOURTH_TRANCHE_CATALOG_SCHEMA_VERSION
        or type(catalog.catalog_version) is not str
        or catalog.catalog_version != FOURTH_TRANCHE_CATALOG_VERSION
        or not _is_sha256(catalog.base_fixture_catalog_sha256)
        or catalog.base_fixture_catalog_sha256 != FROZEN_THIRD_CATALOG_SHA256
        or not _is_sha256(catalog.catalog_sha256)
        or catalog.public_method_development is not True
        or catalog.sealed is not False
        or catalog.independent_human_review_attested is not False
        or catalog.candidate_execution_authorized is not False
        or catalog.model_selection_eligible is not False
        or catalog.claim_authorized is not False
    ):
        raise FourthTrancheFixtureCatalogError(
            "fourth-tranche catalog metadata is invalid"
        )
    return catalog


def validate_fourth_tranche_fixture_catalog(
    catalog: FourthTrancheFixtureCatalog,
) -> None:
    selected = _validate_metadata(catalog)
    registry, bundles = _validate_inputs(
        selected.registry, selected.bundles, regenerate=True
    )
    if selected.catalog_sha256 != _catalog_digest(registry, bundles):
        raise FourthTrancheFixtureCatalogError(
            "fourth-tranche catalog digest is invalid"
        )


def _validate_catalog_snapshot(catalog: FourthTrancheFixtureCatalog) -> None:
    selected = _validate_metadata(catalog)
    registry, bundles = _validate_inputs(
        selected.registry, selected.bundles, regenerate=False
    )
    if selected.catalog_sha256 != _catalog_digest(registry, bundles):
        raise FourthTrancheFixtureCatalogError(
            "fourth-tranche catalog digest is invalid"
        )


def verify_fourth_tranche_fixture_catalog(catalog: object) -> bool:
    try:
        validate_fourth_tranche_fixture_catalog(catalog)  # type: ignore[arg-type]
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def _validate_live_base_and_global_uniqueness(
    bundles: tuple[FourthTrancheFixtureBundle, ...],
) -> None:
    from .executable_fixture_catalog import build_first_tranche_fixture_catalog
    from .executable_fixture_second_catalog import build_second_tranche_fixture_catalog
    from .executable_fixture_third_catalog import build_third_tranche_fixture_catalog
    from .executable_static_registry import build_public_method_development_registry

    first = build_first_tranche_fixture_catalog(
        build_public_method_development_registry()
    )
    second = build_second_tranche_fixture_catalog()
    third = build_third_tranche_fixture_catalog()
    if (
        first.catalog_sha256 != FROZEN_FIRST_CATALOG_SHA256
        or second.catalog_sha256 != FROZEN_SECOND_CATALOG_SHA256
        or third.catalog_sha256 != FROZEN_THIRD_CATALOG_SHA256
    ):
        raise FourthTrancheFixtureCatalogError(
            "a live predecessor catalog differs from its frozen identity"
        )
    all_bundles = (*first.bundles, *second.bundles, *third.bundles, *bundles)
    if (
        len(all_bundles) != FOURTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT
        or len({bundle.descriptor.fixture_id for bundle in all_bundles})
        != len(all_bundles)
        or len({bundle.descriptor.fixture_sha256 for bundle in all_bundles})
        != len(all_bundles)
    ):
        raise FourthTrancheFixtureCatalogError(
            "fourth-tranche fixtures collide with a frozen predecessor"
        )


def build_fourth_tranche_fixture_catalog(
    registry: FourthTrancheTaskRegistry | None = None,
) -> FourthTrancheFixtureCatalog:
    selected_registry = (
        build_fourth_tranche_task_registry() if registry is None else registry
    )
    if type(selected_registry) is not FourthTrancheTaskRegistry:
        raise TypeError("registry must be an exact FourthTrancheTaskRegistry")
    validate_fourth_tranche_task_registry(selected_registry)
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

    # All values came from closed builders and were checked above.  Avoid a
    # second deterministic rebuild while preserving exhaustive public
    # validation through validate_fourth_tranche_fixture_catalog().
    catalog = object.__new__(FourthTrancheFixtureCatalog)
    values: dict[str, object] = {
        "registry": selected_registry,
        "bundles": selected_bundles,
        "catalog_sha256": digest,
        "schema_version": FOURTH_TRANCHE_CATALOG_SCHEMA_VERSION,
        "catalog_version": FOURTH_TRANCHE_CATALOG_VERSION,
        "base_fixture_catalog_sha256": FROZEN_THIRD_CATALOG_SHA256,
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
    "FOURTH_TRANCHE_ADDED_FIXTURE_COUNT",
    "FOURTH_TRANCHE_CATALOG_SCHEMA_VERSION",
    "FOURTH_TRANCHE_CATALOG_VERSION",
    "FOURTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT",
    "FOURTH_TRANCHE_FIXTURE_COUNT",
    "FOURTH_TRANCHE_PROFILE_COUNT",
    "FROZEN_FIRST_CATALOG_SHA256",
    "FROZEN_SECOND_CATALOG_SHA256",
    "FROZEN_THIRD_CATALOG_SHA256",
    "FourthTrancheFixtureCatalog",
    "FourthTrancheFixtureCatalogError",
    "build_fourth_tranche_fixture_catalog",
    "compute_fourth_tranche_fixture_catalog_sha256",
    "validate_fourth_tranche_fixture_catalog",
    "verify_fourth_tranche_fixture_catalog",
]
