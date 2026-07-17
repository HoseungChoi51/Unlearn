"""Hash-bound twelfth catalog for enrichment-composition fixtures.

The catalog preserves the frozen first-through-eleventh publication chain,
binds the exact twelfth 20-task grid against five public development
profiles, and commits to 100 new fixture/oracle bindings.  Its public
projection contains hashes and counts, never fixture bytes, paths, prompts,
or oracle answers.

The full builder obtains one through-eleventh task snapshot and passes that
same snapshot into the non-recursive through-eleventh fixture builder.  No
recursive eleventh registry or catalog publication builder is used.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Final, TypeAlias

from .executable_eleventh_predecessor_evidence import (
    ELEVENTH_PREFIX_FIXTURE_COUNT,
    ELEVENTH_PREFIX_TASK_COUNT,
    FROZEN_ELEVENTH_CATALOG_SHA256,
    FROZEN_ELEVENTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_ELEVENTH_REGISTRY_SHA256,
    EleventhPrefixFixtureEvidence,
    build_eleventh_prefix_fixture_evidence,
    build_eleventh_prefix_task_evidence,
    validate_eleventh_prefix_fixture_evidence,
    validate_eleventh_prefix_task_evidence,
)
from .executable_fixture_profiles import (
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
    ExecutableFixtureProfile,
)
from .executable_jsonl_csv_enrichment_compose import (
    JSONL_CSV_ENRICHMENT_COMPOSE_FAMILY_ID,
    JSONL_CSV_ENRICHMENT_COMPOSE_GENERATOR_VERSION,
    JSONL_CSV_ENRICHMENT_COMPOSE_OUTPUT_MAXIMUM_BYTES,
    JSONL_CSV_ENRICHMENT_COMPOSE_VERIFIER_IDENTITY,
    JsonlCsvEnrichmentComposeFixtureBundle,
    JsonlCsvEnrichmentComposeTask,
    build_jsonl_csv_enrichment_compose_fixture_bundle,
    validate_jsonl_csv_enrichment_compose_fixture_bundle,
    validate_jsonl_csv_enrichment_compose_fixture_for_task_profile,
)
from .executable_static_twelfth_registry import (
    TWELFTH_TRANCHE_ADDED_TASK_COUNT,
    TWELFTH_TRANCHE_CUMULATIVE_TASK_COUNT,
    TWELFTH_TRANCHE_FAMILY_ORDER,
    TwelfthTrancheTask,
    TwelfthTrancheTaskRegistry,
    build_twelfth_tranche_task_registry,
    validate_twelfth_tranche_task_registry,
)
from .executable_static_types import domain_sha256


TWELFTH_TRANCHE_CATALOG_SCHEMA_VERSION: Final[str] = "1.0.0"
TWELFTH_TRANCHE_CATALOG_VERSION: Final[str] = "1.0.0"
TWELFTH_TRANCHE_PROFILE_COUNT: Final[int] = 5
TWELFTH_TRANCHE_ADDED_FIXTURE_COUNT: Final[int] = 100
TWELFTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT: Final[int] = 2_100
TWELFTH_TRANCHE_FIXTURE_COUNT: Final[int] = (
    TWELFTH_TRANCHE_ADDED_FIXTURE_COUNT
)

TwelfthTrancheFixtureBundle: TypeAlias = (
    JsonlCsvEnrichmentComposeFixtureBundle
)
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")


class TwelfthTrancheFixtureCatalogError(ValueError):
    """Raised when the twelfth additive catalog is not reproducible."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def _build_bundle(
    task: TwelfthTrancheTask,
    profile: ExecutableFixtureProfile,
) -> TwelfthTrancheFixtureBundle:
    if type(task) is not JsonlCsvEnrichmentComposeTask:
        raise TwelfthTrancheFixtureCatalogError(
            "task type is outside the twelfth tranche"
        )
    bundle = build_jsonl_csv_enrichment_compose_fixture_bundle(
        task, profile
    )
    validate_jsonl_csv_enrichment_compose_fixture_for_task_profile(
        task, profile, bundle
    )
    return bundle


def _validate_bundle(
    task: TwelfthTrancheTask,
    profile: ExecutableFixtureProfile,
    bundle: object,
    *,
    regenerate: bool,
) -> TwelfthTrancheFixtureBundle:
    try:
        if type(task) is not JsonlCsvEnrichmentComposeTask:
            raise TwelfthTrancheFixtureCatalogError(
                "twelfth-tranche task has the wrong exact type"
            )
        if type(bundle) is not JsonlCsvEnrichmentComposeFixtureBundle:
            raise TwelfthTrancheFixtureCatalogError(
                "enrichment-compose task has the wrong bundle type"
            )
        validate_jsonl_csv_enrichment_compose_fixture_bundle(bundle)
        validate_jsonl_csv_enrichment_compose_fixture_for_task_profile(
            task, profile, bundle
        )
    except (AttributeError, TypeError, ValueError) as exc:
        if isinstance(exc, TwelfthTrancheFixtureCatalogError):
            raise
        raise TwelfthTrancheFixtureCatalogError(
            "family-local bundle validation failed"
        ) from exc
    selected = bundle
    if regenerate and selected != _build_bundle(task, profile):
        raise TwelfthTrancheFixtureCatalogError(
            "bundle differs from deterministic family generation"
        )
    return selected


def _validate_inputs(
    registry: object,
    bundles: object,
    *,
    regenerate: bool,
) -> tuple[
    TwelfthTrancheTaskRegistry,
    tuple[TwelfthTrancheFixtureBundle, ...],
]:
    if type(registry) is not TwelfthTrancheTaskRegistry:
        raise TwelfthTrancheFixtureCatalogError(
            "registry must be an exact TwelfthTrancheTaskRegistry"
        )
    try:
        validate_twelfth_tranche_task_registry(registry)
    except (AttributeError, TypeError, ValueError) as exc:
        raise TwelfthTrancheFixtureCatalogError(
            "twelfth registry is invalid"
        ) from exc
    if (
        type(bundles) is not tuple
        or len(bundles) != TWELFTH_TRANCHE_ADDED_FIXTURE_COUNT
        or any(
            type(bundle) is not JsonlCsvEnrichmentComposeFixtureBundle
            for bundle in bundles
        )
    ):
        raise TwelfthTrancheFixtureCatalogError(
            "twelfth catalog requires exactly 100 exact "
            "JsonlCsvEnrichmentComposeFixtureBundle values"
        )

    fixture_ids: set[str] = set()
    fixture_hashes: set[str] = set()
    for index, raw_bundle in enumerate(bundles):
        task = registry.added_tasks[
            index // TWELFTH_TRANCHE_PROFILE_COUNT
        ]
        profile_index = index % TWELFTH_TRANCHE_PROFILE_COUNT
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
            raise TwelfthTrancheFixtureCatalogError(
                "bundle order, descriptor, or authority boundary is invalid"
            )
        fixture_ids.add(bundle.descriptor.fixture_id)
        fixture_hashes.add(bundle.descriptor.fixture_sha256)
    if (
        len(fixture_ids) != TWELFTH_TRANCHE_ADDED_FIXTURE_COUNT
        or len(fixture_hashes) != TWELFTH_TRANCHE_ADDED_FIXTURE_COUNT
    ):
        raise TwelfthTrancheFixtureCatalogError(
            "twelfth-tranche fixture identities are not unique"
        )
    return registry, bundles


def _task_hash_record(task: TwelfthTrancheTask) -> dict[str, str]:
    return {
        "family_id": task.family_id,
        "task_contract_sha256": task.task_contract_sha256,
        "graph_sha256": task.graph_sha256,
    }


def _fixture_hash_record(
    bundle: TwelfthTrancheFixtureBundle,
) -> dict[str, str]:
    return {
        "task_contract_sha256": bundle.task_contract_sha256,
        "profile_sha256": bundle.profile_sha256,
        "fixture_definition_sha256": bundle.fixture_definition_sha256,
        "trusted_oracle_sha256": bundle.oracle.oracle_sha256,
        "fixture_sha256": bundle.descriptor.fixture_sha256,
    }


def _catalog_payload(
    registry: TwelfthTrancheTaskRegistry,
    bundles: tuple[TwelfthTrancheFixtureBundle, ...],
) -> dict[str, object]:
    return {
        "schema_version": TWELFTH_TRANCHE_CATALOG_SCHEMA_VERSION,
        "catalog_version": TWELFTH_TRANCHE_CATALOG_VERSION,
        "record_type": (
            "cbds.executable-fixture-twelfth-tranche-catalog"
        ),
        "base_fixture_catalog_sha256": FROZEN_ELEVENTH_CATALOG_SHA256,
        "added_registry_sha256": registry.registry_sha256,
        "cumulative_suite_sha256": registry.cumulative_suite_sha256,
        "base_cumulative_task_count": ELEVENTH_PREFIX_TASK_COUNT,
        "added_task_count": TWELFTH_TRANCHE_ADDED_TASK_COUNT,
        "cumulative_task_count": TWELFTH_TRANCHE_CUMULATIVE_TASK_COUNT,
        "profiles_per_task": TWELFTH_TRANCHE_PROFILE_COUNT,
        "base_cumulative_fixture_count": ELEVENTH_PREFIX_FIXTURE_COUNT,
        "added_fixture_count": TWELFTH_TRANCHE_ADDED_FIXTURE_COUNT,
        "cumulative_fixture_count": (
            TWELFTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT
        ),
        "profile_sha256": [
            profile.profile_sha256
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        ],
        "family_task_counts": {
            family: sum(
                task.family_id == family for task in registry.added_tasks
            )
            for family in TWELFTH_TRANCHE_FAMILY_ORDER
        },
        "family_fixture_counts": {
            family: sum(
                task.family_id == family for task in registry.added_tasks
            )
            * TWELFTH_TRANCHE_PROFILE_COUNT
            for family in TWELFTH_TRANCHE_FAMILY_ORDER
        },
        "family_generators": [
            {
                "family_id": JSONL_CSV_ENRICHMENT_COMPOSE_FAMILY_ID,
                "generator_version": (
                    JSONL_CSV_ENRICHMENT_COMPOSE_GENERATOR_VERSION
                ),
                "semantic_verifier_identity": (
                    JSONL_CSV_ENRICHMENT_COMPOSE_VERIFIER_IDENTITY
                ),
                "output_maximum_bytes": (
                    JSONL_CSV_ENRICHMENT_COMPOSE_OUTPUT_MAXIMUM_BYTES
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
    registry: TwelfthTrancheTaskRegistry,
    bundles: tuple[TwelfthTrancheFixtureBundle, ...],
) -> str:
    return domain_sha256(
        "cbds.executable-fixture.twelfth-tranche-catalog.v1",
        _catalog_payload(registry, bundles),
    )


def compute_twelfth_tranche_fixture_catalog_sha256(
    registry: TwelfthTrancheTaskRegistry,
    bundles: tuple[TwelfthTrancheFixtureBundle, ...],
) -> str:
    selected_registry, selected_bundles = _validate_inputs(
        registry, bundles, regenerate=True
    )
    return _catalog_digest(selected_registry, selected_bundles)


@dataclass(frozen=True, slots=True)
class TwelfthTrancheFixtureCatalog:
    registry: TwelfthTrancheTaskRegistry = field(repr=False)
    bundles: tuple[TwelfthTrancheFixtureBundle, ...] = field(repr=False)
    catalog_sha256: str
    schema_version: str = TWELFTH_TRANCHE_CATALOG_SCHEMA_VERSION
    catalog_version: str = TWELFTH_TRANCHE_CATALOG_VERSION
    base_fixture_catalog_sha256: str = FROZEN_ELEVENTH_CATALOG_SHA256
    public_method_development: bool = True
    sealed: bool = False
    independent_human_review_attested: bool = False
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_twelfth_tranche_fixture_catalog(self)

    def to_hash_only_record(self) -> dict[str, object]:
        _validate_catalog_snapshot(self)
        return {
            **_catalog_payload(self.registry, self.bundles),
            "catalog_sha256": self.catalog_sha256,
        }


def _validate_metadata(
    catalog: object,
) -> TwelfthTrancheFixtureCatalog:
    if type(catalog) is not TwelfthTrancheFixtureCatalog:
        raise TwelfthTrancheFixtureCatalogError(
            "catalog must be an exact TwelfthTrancheFixtureCatalog"
        )
    if (
        catalog.schema_version != TWELFTH_TRANCHE_CATALOG_SCHEMA_VERSION
        or catalog.catalog_version != TWELFTH_TRANCHE_CATALOG_VERSION
        or not _is_sha256(catalog.base_fixture_catalog_sha256)
        or catalog.base_fixture_catalog_sha256
        != FROZEN_ELEVENTH_CATALOG_SHA256
        or not _is_sha256(catalog.catalog_sha256)
        or catalog.public_method_development is not True
        or catalog.sealed is not False
        or catalog.independent_human_review_attested is not False
        or catalog.candidate_execution_authorized is not False
        or catalog.model_selection_eligible is not False
        or catalog.claim_authorized is not False
    ):
        raise TwelfthTrancheFixtureCatalogError(
            "twelfth-tranche catalog metadata is invalid"
        )
    return catalog


def validate_twelfth_tranche_fixture_catalog(
    catalog: TwelfthTrancheFixtureCatalog,
) -> None:
    selected = _validate_metadata(catalog)
    registry, bundles = _validate_inputs(
        selected.registry, selected.bundles, regenerate=True
    )
    if selected.catalog_sha256 != _catalog_digest(registry, bundles):
        raise TwelfthTrancheFixtureCatalogError(
            "twelfth-tranche catalog digest is invalid"
        )


def _validate_catalog_snapshot(
    catalog: TwelfthTrancheFixtureCatalog,
) -> None:
    selected = _validate_metadata(catalog)
    registry, bundles = _validate_inputs(
        selected.registry, selected.bundles, regenerate=False
    )
    if selected.catalog_sha256 != _catalog_digest(registry, bundles):
        raise TwelfthTrancheFixtureCatalogError(
            "twelfth-tranche catalog digest is invalid"
        )


def verify_twelfth_tranche_fixture_catalog(catalog: object) -> bool:
    try:
        validate_twelfth_tranche_fixture_catalog(
            catalog  # type: ignore[arg-type]
        )
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def _validate_live_base_and_global_uniqueness(
    registry: TwelfthTrancheTaskRegistry,
    bundles: tuple[TwelfthTrancheFixtureBundle, ...],
    evidence: EleventhPrefixFixtureEvidence,
) -> None:
    """Admit the exact eleventh prefix and reject cross-chain collisions."""

    try:
        validate_eleventh_prefix_fixture_evidence(evidence)
    except (AttributeError, TypeError, ValueError) as exc:
        raise TwelfthTrancheFixtureCatalogError(
            "through-eleventh fixture evidence could not be established"
        ) from exc
    if (
        evidence.total_fixture_count != ELEVENTH_PREFIX_FIXTURE_COUNT
        or evidence.terminal_catalog_sha256
        != FROZEN_ELEVENTH_CATALOG_SHA256
        or evidence.task_evidence.terminal_registry_sha256
        != FROZEN_ELEVENTH_REGISTRY_SHA256
        or evidence.task_evidence.terminal_cumulative_suite_sha256
        != FROZEN_ELEVENTH_CUMULATIVE_SUITE_SHA256
        or registry.base_added_registry_sha256
        != evidence.task_evidence.terminal_registry_sha256
        or registry.base_cumulative_suite_sha256
        != evidence.task_evidence.terminal_cumulative_suite_sha256
    ):
        raise TwelfthTrancheFixtureCatalogError(
            "a live predecessor differs from its frozen eleventh identity"
        )
    all_bundles = (*evidence.bundles, *bundles)
    if (
        len(all_bundles) != TWELFTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT
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
        raise TwelfthTrancheFixtureCatalogError(
            "twelfth-tranche fixtures collide with a frozen predecessor"
        )
    if any(
        bundle is predecessor
        for bundle in bundles
        for predecessor in evidence.bundles
    ):
        raise TwelfthTrancheFixtureCatalogError(
            "twelfth-tranche fixtures must be freshly owned additions"
        )


def build_twelfth_tranche_fixture_catalog_local(
    registry: TwelfthTrancheTaskRegistry,
) -> TwelfthTrancheFixtureCatalog:
    """Build only twelfth-tranche bundles without predecessor reconstruction."""

    if type(registry) is not TwelfthTrancheTaskRegistry:
        raise TypeError(
            "registry must be an exact TwelfthTrancheTaskRegistry"
        )
    validate_twelfth_tranche_task_registry(registry)
    bundles = tuple(
        _build_bundle(task, profile)
        for task in registry.added_tasks
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
    )
    selected_registry, selected_bundles = _validate_inputs(
        registry, bundles, regenerate=False
    )
    digest = _catalog_digest(selected_registry, selected_bundles)

    catalog = object.__new__(TwelfthTrancheFixtureCatalog)
    values: dict[str, object] = {
        "registry": selected_registry,
        "bundles": selected_bundles,
        "catalog_sha256": digest,
        "schema_version": TWELFTH_TRANCHE_CATALOG_SCHEMA_VERSION,
        "catalog_version": TWELFTH_TRANCHE_CATALOG_VERSION,
        "base_fixture_catalog_sha256": FROZEN_ELEVENTH_CATALOG_SHA256,
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


def build_twelfth_tranche_fixture_catalog(
    registry: TwelfthTrancheTaskRegistry | None = None,
) -> TwelfthTrancheFixtureCatalog:
    """Build the twelfth catalog over one shared through-eleventh snapshot."""

    task_evidence = build_eleventh_prefix_task_evidence()
    validate_eleventh_prefix_task_evidence(task_evidence)
    live_registry = build_twelfth_tranche_task_registry(task_evidence)
    selected_registry = live_registry if registry is None else registry
    if type(selected_registry) is not TwelfthTrancheTaskRegistry:
        raise TypeError(
            "registry must be an exact TwelfthTrancheTaskRegistry"
        )
    validate_twelfth_tranche_task_registry(selected_registry)
    if selected_registry != live_registry:
        raise TwelfthTrancheFixtureCatalogError(
            "supplied registry differs from the live collision-checked addition"
        )
    fixture_evidence = build_eleventh_prefix_fixture_evidence(
        task_evidence
    )
    catalog = build_twelfth_tranche_fixture_catalog_local(
        selected_registry
    )
    _validate_live_base_and_global_uniqueness(
        selected_registry, catalog.bundles, fixture_evidence
    )
    return catalog


__all__ = [
    "FROZEN_ELEVENTH_CATALOG_SHA256",
    "TWELFTH_TRANCHE_ADDED_FIXTURE_COUNT",
    "TWELFTH_TRANCHE_CATALOG_SCHEMA_VERSION",
    "TWELFTH_TRANCHE_CATALOG_VERSION",
    "TWELFTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT",
    "TWELFTH_TRANCHE_FIXTURE_COUNT",
    "TWELFTH_TRANCHE_PROFILE_COUNT",
    "TwelfthTrancheFixtureBundle",
    "TwelfthTrancheFixtureCatalog",
    "TwelfthTrancheFixtureCatalogError",
    "build_twelfth_tranche_fixture_catalog",
    "build_twelfth_tranche_fixture_catalog_local",
    "compute_twelfth_tranche_fixture_catalog_sha256",
    "validate_twelfth_tranche_fixture_catalog",
    "verify_twelfth_tranche_fixture_catalog",
]
