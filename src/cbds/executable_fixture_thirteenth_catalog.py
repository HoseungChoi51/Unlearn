"""Hash-bound thirteenth catalog for nested-JSON migration fixtures.

The catalog preserves the frozen first-through-twelfth publication chain,
binds the exact thirteenth 20-task grid against five public development
profiles, and commits to 100 new fixture/oracle bindings.  Its public
projection contains hashes and counts, never fixture bytes, paths, prompts,
or oracle answers.

The full builder obtains one through-twelfth task snapshot and passes that
same snapshot into the non-recursive through-twelfth fixture builder.  No
recursive twelfth registry or catalog publication builder is used.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Final, TypeAlias

from .executable_fixture_profiles import (
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
    ExecutableFixtureProfile,
)
from .executable_nested_json_schema_migration import (
    NESTED_JSON_SCHEMA_MIGRATION_FAMILY_ID,
    NESTED_JSON_SCHEMA_MIGRATION_GENERATOR_VERSION,
    NESTED_JSON_SCHEMA_MIGRATION_PROVED_MAXIMUM_TOTAL_OUTPUT_BYTES,
    NESTED_JSON_SCHEMA_MIGRATION_VERIFIER_IDENTITY,
    NestedJsonSchemaMigrationFixtureBundle,
    NestedJsonSchemaMigrationTask,
    build_nested_json_schema_migration_fixture_bundle,
    validate_nested_json_schema_migration_fixture_bundle,
    validate_nested_json_schema_migration_fixture_for_task_profile,
)
from .executable_static_thirteenth_registry import (
    THIRTEENTH_TRANCHE_ADDED_TASK_COUNT,
    THIRTEENTH_TRANCHE_CUMULATIVE_TASK_COUNT,
    THIRTEENTH_TRANCHE_FAMILY_ORDER,
    ThirteenthTrancheTask,
    ThirteenthTrancheTaskRegistry,
    build_thirteenth_tranche_task_registry,
    validate_thirteenth_tranche_task_registry,
)
from .executable_static_types import domain_sha256
from .executable_twelfth_predecessor_evidence import (
    FROZEN_TWELFTH_CATALOG_SHA256,
    FROZEN_TWELFTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_TWELFTH_REGISTRY_SHA256,
    TWELFTH_PREFIX_FIXTURE_COUNT,
    TWELFTH_PREFIX_TASK_COUNT,
    TwelfthPrefixFixtureEvidence,
    build_twelfth_prefix_fixture_evidence,
    build_twelfth_prefix_task_evidence,
    validate_twelfth_prefix_fixture_evidence,
    validate_twelfth_prefix_task_evidence,
)


THIRTEENTH_TRANCHE_CATALOG_SCHEMA_VERSION: Final[str] = "1.0.0"
THIRTEENTH_TRANCHE_CATALOG_VERSION: Final[str] = "1.0.0"
THIRTEENTH_TRANCHE_PROFILE_COUNT: Final[int] = 5
THIRTEENTH_TRANCHE_ADDED_FIXTURE_COUNT: Final[int] = 100
THIRTEENTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT: Final[int] = 2_200
THIRTEENTH_TRANCHE_FIXTURE_COUNT: Final[int] = (
    THIRTEENTH_TRANCHE_ADDED_FIXTURE_COUNT
)
FROZEN_THIRTEENTH_CATALOG_SHA256: Final[str] = (
    "25142ebdc014f4d4a53bba34bb9ffeaffa6f87789169180fe0caab69b02fcb9f"
)

ThirteenthTrancheFixtureBundle: TypeAlias = (
    NestedJsonSchemaMigrationFixtureBundle
)
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")


class ThirteenthTrancheFixtureCatalogError(ValueError):
    """Raised when the thirteenth additive catalog is not reproducible."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def _build_bundle(
    task: ThirteenthTrancheTask,
    profile: ExecutableFixtureProfile,
) -> ThirteenthTrancheFixtureBundle:
    if type(task) is not NestedJsonSchemaMigrationTask:
        raise ThirteenthTrancheFixtureCatalogError(
            "task type is outside the thirteenth tranche"
        )
    bundle = build_nested_json_schema_migration_fixture_bundle(
        task, profile
    )
    validate_nested_json_schema_migration_fixture_for_task_profile(
        task, profile, bundle
    )
    return bundle


def _validate_bundle(
    task: ThirteenthTrancheTask,
    profile: ExecutableFixtureProfile,
    bundle: object,
    *,
    regenerate: bool,
) -> ThirteenthTrancheFixtureBundle:
    try:
        if type(task) is not NestedJsonSchemaMigrationTask:
            raise ThirteenthTrancheFixtureCatalogError(
                "thirteenth-tranche task has the wrong exact type"
            )
        if type(bundle) is not NestedJsonSchemaMigrationFixtureBundle:
            raise ThirteenthTrancheFixtureCatalogError(
                "nested-migration task has the wrong bundle type"
            )
        validate_nested_json_schema_migration_fixture_bundle(bundle)
        validate_nested_json_schema_migration_fixture_for_task_profile(
            task, profile, bundle
        )
    except (AttributeError, TypeError, ValueError) as exc:
        if isinstance(exc, ThirteenthTrancheFixtureCatalogError):
            raise
        raise ThirteenthTrancheFixtureCatalogError(
            "family-local bundle validation failed"
        ) from exc
    selected = bundle
    if regenerate and selected != _build_bundle(task, profile):
        raise ThirteenthTrancheFixtureCatalogError(
            "bundle differs from deterministic family generation"
        )
    return selected


def _validate_inputs(
    registry: object,
    bundles: object,
    *,
    regenerate: bool,
) -> tuple[
    ThirteenthTrancheTaskRegistry,
    tuple[ThirteenthTrancheFixtureBundle, ...],
]:
    if type(registry) is not ThirteenthTrancheTaskRegistry:
        raise ThirteenthTrancheFixtureCatalogError(
            "registry must be an exact ThirteenthTrancheTaskRegistry"
        )
    try:
        validate_thirteenth_tranche_task_registry(registry)
    except (AttributeError, TypeError, ValueError) as exc:
        raise ThirteenthTrancheFixtureCatalogError(
            "thirteenth registry is invalid"
        ) from exc
    if (
        type(bundles) is not tuple
        or len(bundles) != THIRTEENTH_TRANCHE_ADDED_FIXTURE_COUNT
        or any(
            type(bundle) is not NestedJsonSchemaMigrationFixtureBundle
            for bundle in bundles
        )
    ):
        raise ThirteenthTrancheFixtureCatalogError(
            "thirteenth catalog requires exactly 100 exact "
            "NestedJsonSchemaMigrationFixtureBundle values"
        )

    fixture_ids: set[str] = set()
    fixture_hashes: set[str] = set()
    for index, raw_bundle in enumerate(bundles):
        task = registry.added_tasks[
            index // THIRTEENTH_TRANCHE_PROFILE_COUNT
        ]
        profile_index = index % THIRTEENTH_TRANCHE_PROFILE_COUNT
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
            raise ThirteenthTrancheFixtureCatalogError(
                "bundle order, descriptor, or authority boundary is invalid"
            )
        fixture_ids.add(bundle.descriptor.fixture_id)
        fixture_hashes.add(bundle.descriptor.fixture_sha256)
    if (
        len(fixture_ids) != THIRTEENTH_TRANCHE_ADDED_FIXTURE_COUNT
        or len(fixture_hashes) != THIRTEENTH_TRANCHE_ADDED_FIXTURE_COUNT
    ):
        raise ThirteenthTrancheFixtureCatalogError(
            "thirteenth-tranche fixture identities are not unique"
        )
    return registry, bundles


def _task_hash_record(task: ThirteenthTrancheTask) -> dict[str, str]:
    return {
        "family_id": task.family_id,
        "task_contract_sha256": task.task_contract_sha256,
        "graph_sha256": task.graph_sha256,
    }


def _fixture_hash_record(
    bundle: ThirteenthTrancheFixtureBundle,
) -> dict[str, str]:
    return {
        "task_contract_sha256": bundle.task_contract_sha256,
        "profile_sha256": bundle.profile_sha256,
        "fixture_definition_sha256": bundle.fixture_definition_sha256,
        "trusted_oracle_sha256": bundle.oracle.oracle_sha256,
        "fixture_sha256": bundle.descriptor.fixture_sha256,
    }


def _catalog_payload(
    registry: ThirteenthTrancheTaskRegistry,
    bundles: tuple[ThirteenthTrancheFixtureBundle, ...],
) -> dict[str, object]:
    return {
        "schema_version": THIRTEENTH_TRANCHE_CATALOG_SCHEMA_VERSION,
        "catalog_version": THIRTEENTH_TRANCHE_CATALOG_VERSION,
        "record_type": (
            "cbds.executable-fixture-thirteenth-tranche-catalog"
        ),
        "base_fixture_catalog_sha256": FROZEN_TWELFTH_CATALOG_SHA256,
        "added_registry_sha256": registry.registry_sha256,
        "cumulative_suite_sha256": registry.cumulative_suite_sha256,
        "base_cumulative_task_count": TWELFTH_PREFIX_TASK_COUNT,
        "added_task_count": THIRTEENTH_TRANCHE_ADDED_TASK_COUNT,
        "cumulative_task_count": THIRTEENTH_TRANCHE_CUMULATIVE_TASK_COUNT,
        "profiles_per_task": THIRTEENTH_TRANCHE_PROFILE_COUNT,
        "base_cumulative_fixture_count": TWELFTH_PREFIX_FIXTURE_COUNT,
        "added_fixture_count": THIRTEENTH_TRANCHE_ADDED_FIXTURE_COUNT,
        "cumulative_fixture_count": (
            THIRTEENTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT
        ),
        "profile_sha256": [
            profile.profile_sha256
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        ],
        "family_task_counts": {
            family: sum(
                task.family_id == family for task in registry.added_tasks
            )
            for family in THIRTEENTH_TRANCHE_FAMILY_ORDER
        },
        "family_fixture_counts": {
            family: sum(
                task.family_id == family for task in registry.added_tasks
            )
            * THIRTEENTH_TRANCHE_PROFILE_COUNT
            for family in THIRTEENTH_TRANCHE_FAMILY_ORDER
        },
        "family_generators": [
            {
                "family_id": NESTED_JSON_SCHEMA_MIGRATION_FAMILY_ID,
                "generator_version": (
                    NESTED_JSON_SCHEMA_MIGRATION_GENERATOR_VERSION
                ),
                "semantic_verifier_identity": (
                    NESTED_JSON_SCHEMA_MIGRATION_VERIFIER_IDENTITY
                ),
                "output_maximum_bytes": (
                    NESTED_JSON_SCHEMA_MIGRATION_PROVED_MAXIMUM_TOTAL_OUTPUT_BYTES
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
    registry: ThirteenthTrancheTaskRegistry,
    bundles: tuple[ThirteenthTrancheFixtureBundle, ...],
) -> str:
    return domain_sha256(
        "cbds.executable-fixture.thirteenth-tranche-catalog.v1",
        _catalog_payload(registry, bundles),
    )


def compute_thirteenth_tranche_fixture_catalog_sha256(
    registry: ThirteenthTrancheTaskRegistry,
    bundles: tuple[ThirteenthTrancheFixtureBundle, ...],
) -> str:
    selected_registry, selected_bundles = _validate_inputs(
        registry, bundles, regenerate=True
    )
    return _catalog_digest(selected_registry, selected_bundles)


@dataclass(frozen=True, slots=True)
class ThirteenthTrancheFixtureCatalog:
    registry: ThirteenthTrancheTaskRegistry = field(repr=False)
    bundles: tuple[ThirteenthTrancheFixtureBundle, ...] = field(repr=False)
    catalog_sha256: str
    schema_version: str = THIRTEENTH_TRANCHE_CATALOG_SCHEMA_VERSION
    catalog_version: str = THIRTEENTH_TRANCHE_CATALOG_VERSION
    base_fixture_catalog_sha256: str = FROZEN_TWELFTH_CATALOG_SHA256
    public_method_development: bool = True
    sealed: bool = False
    independent_human_review_attested: bool = False
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_thirteenth_tranche_fixture_catalog(self)

    def to_hash_only_record(self) -> dict[str, object]:
        _validate_catalog_snapshot(self)
        return {
            **_catalog_payload(self.registry, self.bundles),
            "catalog_sha256": self.catalog_sha256,
        }


def _validate_metadata(
    catalog: object,
) -> ThirteenthTrancheFixtureCatalog:
    if type(catalog) is not ThirteenthTrancheFixtureCatalog:
        raise ThirteenthTrancheFixtureCatalogError(
            "catalog must be an exact ThirteenthTrancheFixtureCatalog"
        )
    if (
        type(catalog.schema_version) is not str
        or catalog.schema_version
        != THIRTEENTH_TRANCHE_CATALOG_SCHEMA_VERSION
        or type(catalog.catalog_version) is not str
        or catalog.catalog_version != THIRTEENTH_TRANCHE_CATALOG_VERSION
        or not _is_sha256(catalog.base_fixture_catalog_sha256)
        or catalog.base_fixture_catalog_sha256
        != FROZEN_TWELFTH_CATALOG_SHA256
        or not _is_sha256(catalog.catalog_sha256)
        or catalog.public_method_development is not True
        or catalog.sealed is not False
        or catalog.independent_human_review_attested is not False
        or catalog.candidate_execution_authorized is not False
        or catalog.model_selection_eligible is not False
        or catalog.claim_authorized is not False
    ):
        raise ThirteenthTrancheFixtureCatalogError(
            "thirteenth-tranche catalog metadata is invalid"
        )
    return catalog


def validate_thirteenth_tranche_fixture_catalog(
    catalog: ThirteenthTrancheFixtureCatalog,
) -> None:
    selected = _validate_metadata(catalog)
    registry, bundles = _validate_inputs(
        selected.registry, selected.bundles, regenerate=True
    )
    if (
        selected.catalog_sha256 != _catalog_digest(registry, bundles)
        or selected.catalog_sha256 != FROZEN_THIRTEENTH_CATALOG_SHA256
    ):
        raise ThirteenthTrancheFixtureCatalogError(
            "thirteenth-tranche catalog digest is invalid"
        )


def _validate_catalog_snapshot(
    catalog: ThirteenthTrancheFixtureCatalog,
) -> None:
    selected = _validate_metadata(catalog)
    registry, bundles = _validate_inputs(
        selected.registry, selected.bundles, regenerate=False
    )
    if (
        selected.catalog_sha256 != _catalog_digest(registry, bundles)
        or selected.catalog_sha256 != FROZEN_THIRTEENTH_CATALOG_SHA256
    ):
        raise ThirteenthTrancheFixtureCatalogError(
            "thirteenth-tranche catalog digest is invalid"
        )


def verify_thirteenth_tranche_fixture_catalog(catalog: object) -> bool:
    try:
        validate_thirteenth_tranche_fixture_catalog(
            catalog  # type: ignore[arg-type]
        )
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def _validate_live_base_and_global_uniqueness(
    registry: ThirteenthTrancheTaskRegistry,
    bundles: tuple[ThirteenthTrancheFixtureBundle, ...],
    evidence: TwelfthPrefixFixtureEvidence,
) -> None:
    """Admit the exact twelfth prefix and reject cross-chain collisions."""

    try:
        validate_twelfth_prefix_fixture_evidence(evidence)
    except (AttributeError, TypeError, ValueError) as exc:
        raise ThirteenthTrancheFixtureCatalogError(
            "through-twelfth fixture evidence could not be established"
        ) from exc
    if (
        evidence.total_fixture_count != TWELFTH_PREFIX_FIXTURE_COUNT
        or evidence.terminal_catalog_sha256
        != FROZEN_TWELFTH_CATALOG_SHA256
        or evidence.task_evidence.terminal_registry_sha256
        != FROZEN_TWELFTH_REGISTRY_SHA256
        or evidence.task_evidence.terminal_cumulative_suite_sha256
        != FROZEN_TWELFTH_CUMULATIVE_SUITE_SHA256
        or registry.base_added_registry_sha256
        != evidence.task_evidence.terminal_registry_sha256
        or registry.base_cumulative_suite_sha256
        != evidence.task_evidence.terminal_cumulative_suite_sha256
    ):
        raise ThirteenthTrancheFixtureCatalogError(
            "a live predecessor differs from its frozen twelfth identity"
        )
    all_bundles = (*evidence.bundles, *bundles)
    if (
        len(all_bundles) != THIRTEENTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT
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
        raise ThirteenthTrancheFixtureCatalogError(
            "thirteenth-tranche fixtures collide with a frozen predecessor"
        )
    if any(
        bundle is predecessor
        for bundle in bundles
        for predecessor in evidence.bundles
    ):
        raise ThirteenthTrancheFixtureCatalogError(
            "thirteenth-tranche fixtures must be freshly owned additions"
        )


def build_thirteenth_tranche_fixture_catalog_local(
    registry: ThirteenthTrancheTaskRegistry,
) -> ThirteenthTrancheFixtureCatalog:
    """Build only thirteenth bundles without predecessor reconstruction."""

    if type(registry) is not ThirteenthTrancheTaskRegistry:
        raise TypeError(
            "registry must be an exact ThirteenthTrancheTaskRegistry"
        )
    validate_thirteenth_tranche_task_registry(registry)
    bundles = tuple(
        _build_bundle(task, profile)
        for task in registry.added_tasks
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
    )
    selected_registry, selected_bundles = _validate_inputs(
        registry, bundles, regenerate=False
    )
    digest = _catalog_digest(selected_registry, selected_bundles)

    catalog = object.__new__(ThirteenthTrancheFixtureCatalog)
    values: dict[str, object] = {
        "registry": selected_registry,
        "bundles": selected_bundles,
        "catalog_sha256": digest,
        "schema_version": THIRTEENTH_TRANCHE_CATALOG_SCHEMA_VERSION,
        "catalog_version": THIRTEENTH_TRANCHE_CATALOG_VERSION,
        "base_fixture_catalog_sha256": FROZEN_TWELFTH_CATALOG_SHA256,
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


def build_thirteenth_tranche_fixture_catalog(
    registry: ThirteenthTrancheTaskRegistry | None = None,
) -> ThirteenthTrancheFixtureCatalog:
    """Build the catalog over one shared through-twelfth snapshot."""

    task_evidence = build_twelfth_prefix_task_evidence()
    validate_twelfth_prefix_task_evidence(task_evidence)
    live_registry = build_thirteenth_tranche_task_registry(task_evidence)
    selected_registry = live_registry if registry is None else registry
    if type(selected_registry) is not ThirteenthTrancheTaskRegistry:
        raise TypeError(
            "registry must be an exact ThirteenthTrancheTaskRegistry"
        )
    validate_thirteenth_tranche_task_registry(selected_registry)
    if selected_registry != live_registry:
        raise ThirteenthTrancheFixtureCatalogError(
            "supplied registry differs from the live collision-checked addition"
        )
    fixture_evidence = build_twelfth_prefix_fixture_evidence(
        task_evidence
    )
    catalog = build_thirteenth_tranche_fixture_catalog_local(
        selected_registry
    )
    _validate_live_base_and_global_uniqueness(
        selected_registry, catalog.bundles, fixture_evidence
    )
    return catalog


__all__ = [
    "FROZEN_THIRTEENTH_CATALOG_SHA256",
    "FROZEN_TWELFTH_CATALOG_SHA256",
    "THIRTEENTH_TRANCHE_ADDED_FIXTURE_COUNT",
    "THIRTEENTH_TRANCHE_CATALOG_SCHEMA_VERSION",
    "THIRTEENTH_TRANCHE_CATALOG_VERSION",
    "THIRTEENTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT",
    "THIRTEENTH_TRANCHE_FIXTURE_COUNT",
    "THIRTEENTH_TRANCHE_PROFILE_COUNT",
    "ThirteenthTrancheFixtureBundle",
    "ThirteenthTrancheFixtureCatalog",
    "ThirteenthTrancheFixtureCatalogError",
    "build_thirteenth_tranche_fixture_catalog",
    "build_thirteenth_tranche_fixture_catalog_local",
    "compute_thirteenth_tranche_fixture_catalog_sha256",
    "validate_thirteenth_tranche_fixture_catalog",
    "verify_thirteenth_tranche_fixture_catalog",
]
