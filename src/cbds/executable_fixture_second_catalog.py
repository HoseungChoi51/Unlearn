"""Additive 500-bundle catalog for the second executable-static tranche.

This catalog never rewrites or embeds the private first-tranche catalog.  It
binds that frozen catalog by digest, validates 100 new task contracts under the
same five public profiles, and reports cumulative counts of 200 semantic tasks
and 1,000 concrete fixture bundles.  It does not execute candidates or confer
model-selection, scored-evaluation, or claim authority.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

from .executable_fixture_bundle import (
    ExecutableFixtureBundle,
    validate_executable_fixture_bundle,
)
from .executable_fixture_catalog import build_fixture_bundle_for_task_profile
from .executable_fixture_profiles import PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
from .executable_static_second_registry import (
    FROZEN_FIRST_REGISTRY_SHA256,
    FROZEN_FIRST_SUITE_SHA256,
    SECOND_TRANCHE_ADDED_TASK_COUNT,
    SECOND_TRANCHE_CUMULATIVE_TASK_COUNT,
    SecondTrancheTaskRegistry,
    build_second_tranche_task_registry,
    validate_second_tranche_task_registry,
)
from .executable_static_types import domain_sha256


SECOND_TRANCHE_CATALOG_SCHEMA_VERSION: Final[str] = "1.0.0"
SECOND_TRANCHE_CATALOG_VERSION: Final[str] = "1.0.0"
SECOND_TRANCHE_PROFILE_COUNT: Final[int] = 5
SECOND_TRANCHE_ADDED_FIXTURE_COUNT: Final[int] = (
    SECOND_TRANCHE_ADDED_TASK_COUNT * SECOND_TRANCHE_PROFILE_COUNT
)
SECOND_TRANCHE_CUMULATIVE_FIXTURE_COUNT: Final[int] = 1_000
SECOND_TRANCHE_FIXTURE_COUNT: Final[int] = SECOND_TRANCHE_ADDED_FIXTURE_COUNT
FROZEN_FIRST_CATALOG_SHA256: Final[str] = (
    "1fc71f89830739a53b69d771b7d0bd6a79a4d78ff698b1c1c2258211e7776c99"
)
SECOND_TRANCHE_FAMILY_ORDER: Final[tuple[str, ...]] = (
    "line-transform-mirror",
    "mode-normalized-mirror",
    "jsonl-keyed-inner-join",
    "ustar-safe-extract",
    "proc-snapshot-report",
)


def _is_exact_lower_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


class ExecutableFixtureSecondCatalogError(ValueError):
    """Raised when the additive catalog fails exact regeneration."""


def _entry_hash_record(bundle: ExecutableFixtureBundle) -> dict[str, str]:
    return {
        "task_contract_sha256": bundle.task_contract_sha256,
        "profile_sha256": bundle.profile_sha256,
        "fixture_definition_sha256": bundle.fixture_definition_sha256,
        "trusted_oracle_sha256": bundle.oracle.oracle_sha256,
        "fixture_sha256": bundle.descriptor.fixture_sha256,
    }


def _task_hash_record(task: object) -> dict[str, str]:
    return {
        "family_id": task.family_id,
        "task_contract_sha256": task.task_contract_sha256,
        "graph_sha256": task.graph_sha256,
    }


def _catalog_payload(
    registry: SecondTrancheTaskRegistry,
    bundles: tuple[ExecutableFixtureBundle, ...],
) -> dict[str, object]:
    return {
        "schema_version": SECOND_TRANCHE_CATALOG_SCHEMA_VERSION,
        "catalog_version": SECOND_TRANCHE_CATALOG_VERSION,
        "record_type": "cbds.executable-fixture-second-tranche-catalog",
        "base_registry_sha256": FROZEN_FIRST_REGISTRY_SHA256,
        "base_suite_sha256": FROZEN_FIRST_SUITE_SHA256,
        "base_fixture_catalog_sha256": FROZEN_FIRST_CATALOG_SHA256,
        "added_registry_sha256": registry.registry_sha256,
        "cumulative_suite_sha256": registry.cumulative_suite_sha256,
        "added_task_count": SECOND_TRANCHE_ADDED_TASK_COUNT,
        "cumulative_task_count": SECOND_TRANCHE_CUMULATIVE_TASK_COUNT,
        "profiles_per_task": SECOND_TRANCHE_PROFILE_COUNT,
        "added_fixture_count": SECOND_TRANCHE_ADDED_FIXTURE_COUNT,
        "cumulative_fixture_count": SECOND_TRANCHE_CUMULATIVE_FIXTURE_COUNT,
        "profile_sha256": [
            profile.profile_sha256
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        ],
        "family_task_counts": {
            family: sum(
                task.family_id == family for task in registry.added_tasks
            )
            for family in SECOND_TRANCHE_FAMILY_ORDER
        },
        "family_fixture_counts": {
            family: sum(
                task.family_id == family for task in registry.added_tasks
            )
            * SECOND_TRANCHE_PROFILE_COUNT
            for family in SECOND_TRANCHE_FAMILY_ORDER
        },
        "added_tasks": [
            _task_hash_record(task) for task in registry.added_tasks
        ],
        "added_fixtures": [_entry_hash_record(bundle) for bundle in bundles],
        "public_method_development": True,
        "sealed": False,
        "candidate_execution_authorized": False,
        "model_selection_eligible": False,
        "claim_authorized": False,
    }


def _validate_inputs(
    registry: object,
    bundles: object,
    *,
    regenerate: bool,
) -> tuple[SecondTrancheTaskRegistry, tuple[ExecutableFixtureBundle, ...]]:
    if type(registry) is not SecondTrancheTaskRegistry:
        raise ExecutableFixtureSecondCatalogError(
            "registry must be an exact SecondTrancheTaskRegistry"
        )
    try:
        validate_second_tranche_task_registry(registry)
    except (AttributeError, TypeError, ValueError) as exc:
        raise ExecutableFixtureSecondCatalogError(
            "second-tranche task registry is invalid"
        ) from exc
    if (
        type(bundles) is not tuple
        or len(bundles) != SECOND_TRANCHE_ADDED_FIXTURE_COUNT
        or any(type(bundle) is not ExecutableFixtureBundle for bundle in bundles)
    ):
        raise ExecutableFixtureSecondCatalogError(
            "second-tranche catalog requires exactly 500 exact bundles"
        )

    fixture_ids: set[str] = set()
    fixture_hashes: set[str] = set()
    for index, bundle in enumerate(bundles):
        task = registry.added_tasks[index // SECOND_TRANCHE_PROFILE_COUNT]
        profile_index = index % SECOND_TRANCHE_PROFILE_COUNT
        profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[profile_index]
        try:
            validate_executable_fixture_bundle(bundle)
        except (AttributeError, TypeError, ValueError) as exc:
            raise ExecutableFixtureSecondCatalogError(
                "second-tranche bundle is invalid"
            ) from exc
        if (
            bundle.task_contract_sha256 != task.task_contract_sha256
            or bundle.profile_sha256 != profile.profile_sha256
            or task.fixtures[profile_index] != bundle.descriptor
        ):
            raise ExecutableFixtureSecondCatalogError(
                "second-tranche bundle order or descriptor binding is invalid"
            )
        if regenerate:
            expected = build_fixture_bundle_for_task_profile(task, profile)
            if bundle != expected:
                raise ExecutableFixtureSecondCatalogError(
                    "second-tranche bundle differs from deterministic generation"
                )
        if (
            bundle.candidate_execution_authorized is not False
            or bundle.model_selection_eligible is not False
            or bundle.claim_authorized is not False
        ):
            raise ExecutableFixtureSecondCatalogError(
                "second-tranche bundle crosses its authority boundary"
            )
        fixture_ids.add(bundle.descriptor.fixture_id)
        fixture_hashes.add(bundle.descriptor.fixture_sha256)
    if (
        len(fixture_ids) != SECOND_TRANCHE_ADDED_FIXTURE_COUNT
        or len(fixture_hashes) != SECOND_TRANCHE_ADDED_FIXTURE_COUNT
    ):
        raise ExecutableFixtureSecondCatalogError(
            "second-tranche fixture identities are not globally unique"
        )
    return registry, bundles


def compute_second_tranche_fixture_catalog_sha256(
    registry: SecondTrancheTaskRegistry,
    bundles: tuple[ExecutableFixtureBundle, ...],
) -> str:
    selected_registry, selected_bundles = _validate_inputs(
        registry,
        bundles,
        regenerate=True,
    )
    return _catalog_digest(selected_registry, selected_bundles)


def _catalog_digest(
    registry: SecondTrancheTaskRegistry,
    bundles: tuple[ExecutableFixtureBundle, ...],
) -> str:
    return domain_sha256(
        "cbds.executable-fixture.second-tranche-catalog.v1",
        _catalog_payload(registry, bundles),
    )


@dataclass(frozen=True, slots=True)
class SecondTrancheFixtureCatalog:
    registry: SecondTrancheTaskRegistry = field(repr=False)
    bundles: tuple[ExecutableFixtureBundle, ...] = field(repr=False)
    catalog_sha256: str
    schema_version: str = SECOND_TRANCHE_CATALOG_SCHEMA_VERSION
    catalog_version: str = SECOND_TRANCHE_CATALOG_VERSION
    base_registry_sha256: str = FROZEN_FIRST_REGISTRY_SHA256
    base_suite_sha256: str = FROZEN_FIRST_SUITE_SHA256
    base_fixture_catalog_sha256: str = FROZEN_FIRST_CATALOG_SHA256
    public_method_development: bool = True
    sealed: bool = False
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_second_tranche_fixture_catalog(self)

    def to_hash_only_record(self) -> dict[str, object]:
        _validate_second_tranche_catalog_snapshot(self)
        return {
            **_catalog_payload(self.registry, self.bundles),
            "catalog_sha256": self.catalog_sha256,
        }


def validate_second_tranche_fixture_catalog(
    catalog: SecondTrancheFixtureCatalog,
) -> None:
    """Exhaustively regenerate every bundle and validate the catalog."""

    _validate_second_tranche_catalog_metadata(catalog)
    registry, bundles = _validate_inputs(
        catalog.registry,
        catalog.bundles,
        regenerate=True,
    )
    expected = _catalog_digest(registry, bundles)
    if catalog.catalog_sha256 != expected:
        raise ExecutableFixtureSecondCatalogError(
            "second-tranche catalog digest is invalid"
        )


def _validate_second_tranche_catalog_metadata(
    catalog: SecondTrancheFixtureCatalog,
) -> None:
    if type(catalog) is not SecondTrancheFixtureCatalog:
        raise ExecutableFixtureSecondCatalogError(
            "catalog must be an exact SecondTrancheFixtureCatalog"
        )
    if (
        type(catalog.schema_version) is not str
        or catalog.schema_version != SECOND_TRANCHE_CATALOG_SCHEMA_VERSION
        or type(catalog.catalog_version) is not str
        or catalog.catalog_version != SECOND_TRANCHE_CATALOG_VERSION
        or not _is_exact_lower_sha256(catalog.base_registry_sha256)
        or catalog.base_registry_sha256 != FROZEN_FIRST_REGISTRY_SHA256
        or not _is_exact_lower_sha256(catalog.base_suite_sha256)
        or catalog.base_suite_sha256 != FROZEN_FIRST_SUITE_SHA256
        or not _is_exact_lower_sha256(catalog.base_fixture_catalog_sha256)
        or catalog.base_fixture_catalog_sha256 != FROZEN_FIRST_CATALOG_SHA256
        or not _is_exact_lower_sha256(catalog.catalog_sha256)
        or catalog.public_method_development is not True
        or catalog.sealed is not False
        or catalog.candidate_execution_authorized is not False
        or catalog.model_selection_eligible is not False
        or catalog.claim_authorized is not False
    ):
        raise ExecutableFixtureSecondCatalogError(
            "second-tranche catalog metadata is invalid"
        )


def _validate_second_tranche_catalog_snapshot(
    catalog: SecondTrancheFixtureCatalog,
) -> None:
    """Validate a previously admitted catalog without rerunning generators."""

    _validate_second_tranche_catalog_metadata(catalog)
    registry, bundles = _validate_inputs(
        catalog.registry,
        catalog.bundles,
        regenerate=False,
    )
    expected = _catalog_digest(registry, bundles)
    if catalog.catalog_sha256 != expected:
        raise ExecutableFixtureSecondCatalogError(
            "second-tranche catalog digest is invalid"
        )


def verify_second_tranche_fixture_catalog(catalog: object) -> bool:
    """Return whether ``catalog`` is an exact, fully regenerated value."""

    try:
        validate_second_tranche_fixture_catalog(catalog)  # type: ignore[arg-type]
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def build_second_tranche_fixture_catalog(
    registry: SecondTrancheTaskRegistry | None = None,
) -> SecondTrancheFixtureCatalog:
    selected_registry = (
        build_second_tranche_task_registry() if registry is None else registry
    )
    if type(selected_registry) is not SecondTrancheTaskRegistry:
        raise TypeError("registry must be an exact SecondTrancheTaskRegistry")
    validate_second_tranche_task_registry(selected_registry)
    bundles = tuple(
        build_fixture_bundle_for_task_profile(task, profile)
        for task in selected_registry.added_tasks
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
    )
    digest = _catalog_digest(selected_registry, bundles)

    # Every component above was produced by the closed builders in this call.
    # Admit that exact snapshot once without paying for a second 500-bundle
    # regeneration. Direct public construction remains exhaustively validated.
    catalog = object.__new__(SecondTrancheFixtureCatalog)
    values: dict[str, object] = {
        "registry": selected_registry,
        "bundles": bundles,
        "catalog_sha256": digest,
        "schema_version": SECOND_TRANCHE_CATALOG_SCHEMA_VERSION,
        "catalog_version": SECOND_TRANCHE_CATALOG_VERSION,
        "base_registry_sha256": FROZEN_FIRST_REGISTRY_SHA256,
        "base_suite_sha256": FROZEN_FIRST_SUITE_SHA256,
        "base_fixture_catalog_sha256": FROZEN_FIRST_CATALOG_SHA256,
        "public_method_development": True,
        "sealed": False,
        "candidate_execution_authorized": False,
        "model_selection_eligible": False,
        "claim_authorized": False,
    }
    for field_name, value in values.items():
        object.__setattr__(catalog, field_name, value)
    _validate_second_tranche_catalog_snapshot(catalog)
    return catalog


__all__ = [
    "FROZEN_FIRST_CATALOG_SHA256",
    "SECOND_TRANCHE_ADDED_FIXTURE_COUNT",
    "SECOND_TRANCHE_CATALOG_SCHEMA_VERSION",
    "SECOND_TRANCHE_CATALOG_VERSION",
    "SECOND_TRANCHE_CUMULATIVE_FIXTURE_COUNT",
    "SECOND_TRANCHE_FAMILY_ORDER",
    "SECOND_TRANCHE_FIXTURE_COUNT",
    "ExecutableFixtureSecondCatalogError",
    "SecondTrancheFixtureCatalog",
    "build_second_tranche_fixture_catalog",
    "compute_second_tranche_fixture_catalog_sha256",
    "validate_second_tranche_fixture_catalog",
    "verify_second_tranche_fixture_catalog",
]
