"""Hash-bound fifth catalog for pipefail-atomic-report fixtures.

The catalog preserves the first four tranche identities, authenticates the
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
from .executable_static_fifth_registry import (
    FIFTH_TRANCHE_ADDED_TASK_COUNT,
    FIFTH_TRANCHE_CUMULATIVE_TASK_COUNT,
    FIFTH_TRANCHE_FAMILY_ORDER,
    FifthTrancheTask,
    FifthTrancheTaskRegistry,
    build_fifth_tranche_task_registry,
    validate_fifth_tranche_task_registry,
)
from .executable_static_types import domain_sha256
from .executable_pipefail_atomic_report import (
    PIPEFAIL_ATOMIC_REPORT_FAMILY_ID,
    PIPEFAIL_ATOMIC_REPORT_GENERATOR_VERSION,
    PIPEFAIL_ATOMIC_REPORT_OUTPUT_MAXIMUM_BYTES,
    PIPEFAIL_ATOMIC_REPORT_VERIFIER_IDENTITY,
    PipefailAtomicReportFixtureBundle,
    PipefailAtomicReportTask,
    build_pipefail_atomic_report_fixture_bundle,
    validate_pipefail_atomic_report_fixture_bundle,
    validate_pipefail_atomic_report_fixture_for_task_profile,
)


FIFTH_TRANCHE_CATALOG_SCHEMA_VERSION: Final[str] = "1.0.0"
FIFTH_TRANCHE_CATALOG_VERSION: Final[str] = "1.0.0"
FIFTH_TRANCHE_PROFILE_COUNT: Final[int] = 5
FIFTH_TRANCHE_ADDED_FIXTURE_COUNT: Final[int] = 100
FIFTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT: Final[int] = 1_400
FIFTH_TRANCHE_FIXTURE_COUNT: Final[int] = FIFTH_TRANCHE_ADDED_FIXTURE_COUNT
FROZEN_FIRST_CATALOG_SHA256: Final[str] = (
    "1fc71f89830739a53b69d771b7d0bd6a79a4d78ff698b1c1c2258211e7776c99"
)
FROZEN_SECOND_CATALOG_SHA256: Final[str] = (
    "e2ad6a3124491bc25410d40278400aeac9cd8791a9f08a530c823d5f14c09e18"
)
FROZEN_THIRD_CATALOG_SHA256: Final[str] = (
    "01554367fd68c36b2f509b8b50b270b0aa7d5e6de3fa55db15a14cf4ec68c26b"
)
FROZEN_FOURTH_CATALOG_SHA256: Final[str] = (
    "54ff2e17645edfc7887fc39b437340ffe8d736b83001d0265612271c2a3b1d46"
)

FifthTrancheFixtureBundle: TypeAlias = PipefailAtomicReportFixtureBundle
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")


class FifthTrancheFixtureCatalogError(ValueError):
    """Raised when the fifth additive catalog is not reproducible."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def _build_bundle(
    task: FifthTrancheTask,
    profile: ExecutableFixtureProfile,
) -> FifthTrancheFixtureBundle:
    if type(task) is not PipefailAtomicReportTask:
        raise FifthTrancheFixtureCatalogError(
            "task type is outside the fifth tranche"
        )
    bundle = build_pipefail_atomic_report_fixture_bundle(task, profile)
    validate_pipefail_atomic_report_fixture_for_task_profile(task, profile, bundle)
    return bundle


def _validate_bundle(
    task: FifthTrancheTask,
    profile: ExecutableFixtureProfile,
    bundle: object,
    *,
    regenerate: bool,
) -> FifthTrancheFixtureBundle:
    try:
        if type(task) is not PipefailAtomicReportTask:
            raise FifthTrancheFixtureCatalogError(
                "fifth-tranche task has the wrong exact type"
            )
        if type(bundle) is not PipefailAtomicReportFixtureBundle:
            raise FifthTrancheFixtureCatalogError(
                "pipefail-atomic-report task has the wrong bundle type"
            )
        validate_pipefail_atomic_report_fixture_bundle(bundle)
        validate_pipefail_atomic_report_fixture_for_task_profile(task, profile, bundle)
    except (AttributeError, TypeError, ValueError) as exc:
        if isinstance(exc, FifthTrancheFixtureCatalogError):
            raise
        raise FifthTrancheFixtureCatalogError(
            "family-local bundle validation failed"
        ) from exc
    selected = bundle
    if regenerate and selected != _build_bundle(task, profile):
        raise FifthTrancheFixtureCatalogError(
            "bundle differs from deterministic family generation"
        )
    return selected


def _validate_inputs(
    registry: object,
    bundles: object,
    *,
    regenerate: bool,
) -> tuple[
    FifthTrancheTaskRegistry,
    tuple[FifthTrancheFixtureBundle, ...],
]:
    if type(registry) is not FifthTrancheTaskRegistry:
        raise FifthTrancheFixtureCatalogError(
            "registry must be an exact FifthTrancheTaskRegistry"
        )
    try:
        validate_fifth_tranche_task_registry(registry)
    except (AttributeError, TypeError, ValueError) as exc:
        raise FifthTrancheFixtureCatalogError(
            "fifth registry is invalid"
        ) from exc
    if (
        type(bundles) is not tuple
        or len(bundles) != FIFTH_TRANCHE_ADDED_FIXTURE_COUNT
        or any(type(bundle) is not PipefailAtomicReportFixtureBundle for bundle in bundles)
    ):
        raise FifthTrancheFixtureCatalogError(
            "fifth catalog requires exactly 100 exact PipefailAtomicReportFixtureBundle values"
        )

    fixture_ids: set[str] = set()
    fixture_hashes: set[str] = set()
    for index, raw_bundle in enumerate(bundles):
        task = registry.added_tasks[index // FIFTH_TRANCHE_PROFILE_COUNT]
        profile_index = index % FIFTH_TRANCHE_PROFILE_COUNT
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
            raise FifthTrancheFixtureCatalogError(
                "bundle order, descriptor, or authority boundary is invalid"
            )
        fixture_ids.add(bundle.descriptor.fixture_id)
        fixture_hashes.add(bundle.descriptor.fixture_sha256)
    if (
        len(fixture_ids) != FIFTH_TRANCHE_ADDED_FIXTURE_COUNT
        or len(fixture_hashes) != FIFTH_TRANCHE_ADDED_FIXTURE_COUNT
    ):
        raise FifthTrancheFixtureCatalogError(
            "fifth-tranche fixture identities are not unique"
        )
    return registry, bundles


def _task_hash_record(task: FifthTrancheTask) -> dict[str, str]:
    return {
        "family_id": task.family_id,
        "task_contract_sha256": task.task_contract_sha256,
        "graph_sha256": task.graph_sha256,
    }


def _fixture_hash_record(
    bundle: FifthTrancheFixtureBundle,
) -> dict[str, str]:
    return {
        "task_contract_sha256": bundle.task_contract_sha256,
        "profile_sha256": bundle.profile_sha256,
        "fixture_definition_sha256": bundle.fixture_definition_sha256,
        "trusted_oracle_sha256": bundle.oracle.oracle_sha256,
        "fixture_sha256": bundle.descriptor.fixture_sha256,
    }


def _catalog_payload(
    registry: FifthTrancheTaskRegistry,
    bundles: tuple[FifthTrancheFixtureBundle, ...],
) -> dict[str, object]:
    return {
        "schema_version": FIFTH_TRANCHE_CATALOG_SCHEMA_VERSION,
        "catalog_version": FIFTH_TRANCHE_CATALOG_VERSION,
        "record_type": "cbds.executable-fixture-fifth-tranche-catalog",
        "base_fixture_catalog_sha256": FROZEN_FOURTH_CATALOG_SHA256,
        "added_registry_sha256": registry.registry_sha256,
        "cumulative_suite_sha256": registry.cumulative_suite_sha256,
        "base_cumulative_task_count": 260,
        "added_task_count": FIFTH_TRANCHE_ADDED_TASK_COUNT,
        "cumulative_task_count": FIFTH_TRANCHE_CUMULATIVE_TASK_COUNT,
        "profiles_per_task": FIFTH_TRANCHE_PROFILE_COUNT,
        "base_cumulative_fixture_count": 1_300,
        "added_fixture_count": FIFTH_TRANCHE_ADDED_FIXTURE_COUNT,
        "cumulative_fixture_count": FIFTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT,
        "profile_sha256": [
            profile.profile_sha256
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        ],
        "family_task_counts": {
            family: sum(
                task.family_id == family for task in registry.added_tasks
            )
            for family in FIFTH_TRANCHE_FAMILY_ORDER
        },
        "family_fixture_counts": {
            family: sum(
                task.family_id == family for task in registry.added_tasks
            )
            * FIFTH_TRANCHE_PROFILE_COUNT
            for family in FIFTH_TRANCHE_FAMILY_ORDER
        },
        "family_generators": [
            {
                "family_id": PIPEFAIL_ATOMIC_REPORT_FAMILY_ID,
                "generator_version": PIPEFAIL_ATOMIC_REPORT_GENERATOR_VERSION,
                "semantic_verifier_identity": PIPEFAIL_ATOMIC_REPORT_VERIFIER_IDENTITY,
                "output_maximum_bytes": PIPEFAIL_ATOMIC_REPORT_OUTPUT_MAXIMUM_BYTES,
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
    registry: FifthTrancheTaskRegistry,
    bundles: tuple[FifthTrancheFixtureBundle, ...],
) -> str:
    return domain_sha256(
        "cbds.executable-fixture.fifth-tranche-catalog.v1",
        _catalog_payload(registry, bundles),
    )


def compute_fifth_tranche_fixture_catalog_sha256(
    registry: FifthTrancheTaskRegistry,
    bundles: tuple[FifthTrancheFixtureBundle, ...],
) -> str:
    selected_registry, selected_bundles = _validate_inputs(
        registry, bundles, regenerate=True
    )
    return _catalog_digest(selected_registry, selected_bundles)


@dataclass(frozen=True, slots=True)
class FifthTrancheFixtureCatalog:
    registry: FifthTrancheTaskRegistry = field(repr=False)
    bundles: tuple[FifthTrancheFixtureBundle, ...] = field(repr=False)
    catalog_sha256: str
    schema_version: str = FIFTH_TRANCHE_CATALOG_SCHEMA_VERSION
    catalog_version: str = FIFTH_TRANCHE_CATALOG_VERSION
    base_fixture_catalog_sha256: str = FROZEN_FOURTH_CATALOG_SHA256
    public_method_development: bool = True
    sealed: bool = False
    independent_human_review_attested: bool = False
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_fifth_tranche_fixture_catalog(self)

    def to_hash_only_record(self) -> dict[str, object]:
        _validate_catalog_snapshot(self)
        return {
            **_catalog_payload(self.registry, self.bundles),
            "catalog_sha256": self.catalog_sha256,
        }


def _validate_metadata(catalog: object) -> FifthTrancheFixtureCatalog:
    if type(catalog) is not FifthTrancheFixtureCatalog:
        raise FifthTrancheFixtureCatalogError(
            "catalog must be an exact FifthTrancheFixtureCatalog"
        )
    if (
        type(catalog.schema_version) is not str
        or catalog.schema_version != FIFTH_TRANCHE_CATALOG_SCHEMA_VERSION
        or type(catalog.catalog_version) is not str
        or catalog.catalog_version != FIFTH_TRANCHE_CATALOG_VERSION
        or not _is_sha256(catalog.base_fixture_catalog_sha256)
        or catalog.base_fixture_catalog_sha256 != FROZEN_FOURTH_CATALOG_SHA256
        or not _is_sha256(catalog.catalog_sha256)
        or catalog.public_method_development is not True
        or catalog.sealed is not False
        or catalog.independent_human_review_attested is not False
        or catalog.candidate_execution_authorized is not False
        or catalog.model_selection_eligible is not False
        or catalog.claim_authorized is not False
    ):
        raise FifthTrancheFixtureCatalogError(
            "fifth-tranche catalog metadata is invalid"
        )
    return catalog


def validate_fifth_tranche_fixture_catalog(
    catalog: FifthTrancheFixtureCatalog,
) -> None:
    selected = _validate_metadata(catalog)
    registry, bundles = _validate_inputs(
        selected.registry, selected.bundles, regenerate=True
    )
    if selected.catalog_sha256 != _catalog_digest(registry, bundles):
        raise FifthTrancheFixtureCatalogError(
            "fifth-tranche catalog digest is invalid"
        )


def _validate_catalog_snapshot(catalog: FifthTrancheFixtureCatalog) -> None:
    selected = _validate_metadata(catalog)
    registry, bundles = _validate_inputs(
        selected.registry, selected.bundles, regenerate=False
    )
    if selected.catalog_sha256 != _catalog_digest(registry, bundles):
        raise FifthTrancheFixtureCatalogError(
            "fifth-tranche catalog digest is invalid"
        )


def verify_fifth_tranche_fixture_catalog(catalog: object) -> bool:
    try:
        validate_fifth_tranche_fixture_catalog(catalog)  # type: ignore[arg-type]
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def _validate_live_base_and_global_uniqueness(
    bundles: tuple[FifthTrancheFixtureBundle, ...],
) -> None:
    from .executable_fixture_catalog import build_first_tranche_fixture_catalog
    from .executable_fixture_fourth_catalog import build_fourth_tranche_fixture_catalog
    from .executable_fixture_second_catalog import build_second_tranche_fixture_catalog
    from .executable_fixture_third_catalog import build_third_tranche_fixture_catalog
    from .executable_static_registry import build_public_method_development_registry

    first = build_first_tranche_fixture_catalog(
        build_public_method_development_registry()
    )
    second = build_second_tranche_fixture_catalog()
    third = build_third_tranche_fixture_catalog()
    fourth = build_fourth_tranche_fixture_catalog()
    if (
        first.catalog_sha256 != FROZEN_FIRST_CATALOG_SHA256
        or second.catalog_sha256 != FROZEN_SECOND_CATALOG_SHA256
        or third.catalog_sha256 != FROZEN_THIRD_CATALOG_SHA256
        or fourth.catalog_sha256 != FROZEN_FOURTH_CATALOG_SHA256
    ):
        raise FifthTrancheFixtureCatalogError(
            "a live predecessor catalog differs from its frozen identity"
        )
    all_bundles = (
        *first.bundles,
        *second.bundles,
        *third.bundles,
        *fourth.bundles,
        *bundles,
    )
    if (
        len(all_bundles) != FIFTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT
        or len({bundle.descriptor.fixture_id for bundle in all_bundles})
        != len(all_bundles)
        or len({bundle.descriptor.fixture_sha256 for bundle in all_bundles})
        != len(all_bundles)
    ):
        raise FifthTrancheFixtureCatalogError(
            "fifth-tranche fixtures collide with a frozen predecessor"
        )


def build_fifth_tranche_fixture_catalog_local(
    registry: FifthTrancheTaskRegistry,
) -> FifthTrancheFixtureCatalog:
    """Build only this tranche without rebuilding predecessor catalogs."""

    if type(registry) is not FifthTrancheTaskRegistry:
        raise TypeError("registry must be an exact FifthTrancheTaskRegistry")
    selected_registry = registry
    validate_fifth_tranche_task_registry(selected_registry)
    bundles = tuple(
        _build_bundle(task, profile)
        for task in selected_registry.added_tasks
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
    )
    selected_registry, selected_bundles = _validate_inputs(
        selected_registry, bundles, regenerate=False
    )
    digest = _catalog_digest(selected_registry, selected_bundles)

    # All values came from closed builders and were checked above.  Avoid a
    # second deterministic rebuild while preserving exhaustive public
    # validation through validate_fifth_tranche_fixture_catalog().
    catalog = object.__new__(FifthTrancheFixtureCatalog)
    values: dict[str, object] = {
        "registry": selected_registry,
        "bundles": selected_bundles,
        "catalog_sha256": digest,
        "schema_version": FIFTH_TRANCHE_CATALOG_SCHEMA_VERSION,
        "catalog_version": FIFTH_TRANCHE_CATALOG_VERSION,
        "base_fixture_catalog_sha256": FROZEN_FOURTH_CATALOG_SHA256,
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


def build_fifth_tranche_fixture_catalog(
    registry: FifthTrancheTaskRegistry | None = None,
) -> FifthTrancheFixtureCatalog:
    selected_registry = (
        build_fifth_tranche_task_registry() if registry is None else registry
    )
    catalog = build_fifth_tranche_fixture_catalog_local(selected_registry)
    _validate_live_base_and_global_uniqueness(catalog.bundles)
    return catalog


__all__ = [
    "FIFTH_TRANCHE_ADDED_FIXTURE_COUNT",
    "FIFTH_TRANCHE_CATALOG_SCHEMA_VERSION",
    "FIFTH_TRANCHE_CATALOG_VERSION",
    "FIFTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT",
    "FIFTH_TRANCHE_FIXTURE_COUNT",
    "FIFTH_TRANCHE_PROFILE_COUNT",
    "FROZEN_FIRST_CATALOG_SHA256",
    "FROZEN_SECOND_CATALOG_SHA256",
    "FROZEN_THIRD_CATALOG_SHA256",
    "FROZEN_FOURTH_CATALOG_SHA256",
    "FifthTrancheFixtureCatalog",
    "FifthTrancheFixtureCatalogError",
    "build_fifth_tranche_fixture_catalog",
    "build_fifth_tranche_fixture_catalog_local",
    "compute_fifth_tranche_fixture_catalog_sha256",
    "validate_fifth_tranche_fixture_catalog",
    "verify_fifth_tranche_fixture_catalog",
]
