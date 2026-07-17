"""Hash-bound eleventh catalog for checksum repair-plan fixtures.

The catalog preserves the frozen first-through-tenth publication chain,
binds the exact eleventh 20-task grid against five public development
profiles, and commits to 100 new fixture/oracle bindings.  Its public
projection contains hashes and counts, never fixture bytes, paths, prompts,
or oracle answers.

The full builder obtains one through-tenth task snapshot and passes that same
snapshot into the non-recursive through-tenth fixture builder.  No recursive
tenth registry or catalog publication builder is used.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Final, TypeAlias

from .executable_checksum_repair_plan import (
    CHECKSUM_REPAIR_PLAN_FAMILY_ID,
    CHECKSUM_REPAIR_PLAN_GENERATOR_VERSION,
    CHECKSUM_REPAIR_PLAN_OUTPUT_MAXIMUM_BYTES,
    CHECKSUM_REPAIR_PLAN_VERIFIER_IDENTITY,
    ChecksumRepairPlanFixtureBundle,
    ChecksumRepairPlanTask,
    build_checksum_repair_plan_fixture_bundle,
    validate_checksum_repair_plan_fixture_bundle,
    validate_checksum_repair_plan_fixture_for_task_profile,
)
from .executable_fixture_profiles import (
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
    ExecutableFixtureProfile,
)
from .executable_static_eleventh_registry import (
    ELEVENTH_TRANCHE_ADDED_TASK_COUNT,
    ELEVENTH_TRANCHE_CUMULATIVE_TASK_COUNT,
    ELEVENTH_TRANCHE_FAMILY_ORDER,
    EleventhTrancheTask,
    EleventhTrancheTaskRegistry,
    build_eleventh_tranche_task_registry,
    validate_eleventh_tranche_task_registry,
)
from .executable_static_types import domain_sha256
from .executable_tenth_predecessor_evidence import (
    FROZEN_TENTH_CATALOG_SHA256,
    FROZEN_TENTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_TENTH_REGISTRY_SHA256,
    TENTH_PREFIX_FIXTURE_COUNT,
    TENTH_PREFIX_TASK_COUNT,
    TenthPrefixFixtureEvidence,
    build_tenth_prefix_fixture_evidence,
    build_tenth_prefix_task_evidence,
    validate_tenth_prefix_fixture_evidence,
    validate_tenth_prefix_task_evidence,
)


ELEVENTH_TRANCHE_CATALOG_SCHEMA_VERSION: Final[str] = "1.0.0"
ELEVENTH_TRANCHE_CATALOG_VERSION: Final[str] = "1.0.0"
ELEVENTH_TRANCHE_PROFILE_COUNT: Final[int] = 5
ELEVENTH_TRANCHE_ADDED_FIXTURE_COUNT: Final[int] = 100
ELEVENTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT: Final[int] = 2_000
ELEVENTH_TRANCHE_FIXTURE_COUNT: Final[int] = (
    ELEVENTH_TRANCHE_ADDED_FIXTURE_COUNT
)

EleventhTrancheFixtureBundle: TypeAlias = ChecksumRepairPlanFixtureBundle
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")


class EleventhTrancheFixtureCatalogError(ValueError):
    """Raised when the eleventh additive catalog is not reproducible."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def _build_bundle(
    task: EleventhTrancheTask,
    profile: ExecutableFixtureProfile,
) -> EleventhTrancheFixtureBundle:
    if type(task) is not ChecksumRepairPlanTask:
        raise EleventhTrancheFixtureCatalogError(
            "task type is outside the eleventh tranche"
        )
    bundle = build_checksum_repair_plan_fixture_bundle(task, profile)
    validate_checksum_repair_plan_fixture_for_task_profile(
        task, profile, bundle
    )
    return bundle


def _validate_bundle(
    task: EleventhTrancheTask,
    profile: ExecutableFixtureProfile,
    bundle: object,
    *,
    regenerate: bool,
) -> EleventhTrancheFixtureBundle:
    try:
        if type(task) is not ChecksumRepairPlanTask:
            raise EleventhTrancheFixtureCatalogError(
                "eleventh-tranche task has the wrong exact type"
            )
        if type(bundle) is not ChecksumRepairPlanFixtureBundle:
            raise EleventhTrancheFixtureCatalogError(
                "checksum-repair task has the wrong bundle type"
            )
        validate_checksum_repair_plan_fixture_bundle(bundle)
        validate_checksum_repair_plan_fixture_for_task_profile(
            task, profile, bundle
        )
    except (AttributeError, TypeError, ValueError) as exc:
        if isinstance(exc, EleventhTrancheFixtureCatalogError):
            raise
        raise EleventhTrancheFixtureCatalogError(
            "family-local bundle validation failed"
        ) from exc
    selected = bundle
    if regenerate and selected != _build_bundle(task, profile):
        raise EleventhTrancheFixtureCatalogError(
            "bundle differs from deterministic family generation"
        )
    return selected


def _validate_inputs(
    registry: object,
    bundles: object,
    *,
    regenerate: bool,
) -> tuple[
    EleventhTrancheTaskRegistry,
    tuple[EleventhTrancheFixtureBundle, ...],
]:
    if type(registry) is not EleventhTrancheTaskRegistry:
        raise EleventhTrancheFixtureCatalogError(
            "registry must be an exact EleventhTrancheTaskRegistry"
        )
    try:
        validate_eleventh_tranche_task_registry(registry)
    except (AttributeError, TypeError, ValueError) as exc:
        raise EleventhTrancheFixtureCatalogError(
            "eleventh registry is invalid"
        ) from exc
    if (
        type(bundles) is not tuple
        or len(bundles) != ELEVENTH_TRANCHE_ADDED_FIXTURE_COUNT
        or any(
            type(bundle) is not ChecksumRepairPlanFixtureBundle
            for bundle in bundles
        )
    ):
        raise EleventhTrancheFixtureCatalogError(
            "eleventh catalog requires exactly 100 exact "
            "ChecksumRepairPlanFixtureBundle values"
        )

    fixture_ids: set[str] = set()
    fixture_hashes: set[str] = set()
    for index, raw_bundle in enumerate(bundles):
        task = registry.added_tasks[
            index // ELEVENTH_TRANCHE_PROFILE_COUNT
        ]
        profile_index = index % ELEVENTH_TRANCHE_PROFILE_COUNT
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
            raise EleventhTrancheFixtureCatalogError(
                "bundle order, descriptor, or authority boundary is invalid"
            )
        fixture_ids.add(bundle.descriptor.fixture_id)
        fixture_hashes.add(bundle.descriptor.fixture_sha256)
    if (
        len(fixture_ids) != ELEVENTH_TRANCHE_ADDED_FIXTURE_COUNT
        or len(fixture_hashes) != ELEVENTH_TRANCHE_ADDED_FIXTURE_COUNT
    ):
        raise EleventhTrancheFixtureCatalogError(
            "eleventh-tranche fixture identities are not unique"
        )
    return registry, bundles


def _task_hash_record(task: EleventhTrancheTask) -> dict[str, str]:
    return {
        "family_id": task.family_id,
        "task_contract_sha256": task.task_contract_sha256,
        "graph_sha256": task.graph_sha256,
    }


def _fixture_hash_record(
    bundle: EleventhTrancheFixtureBundle,
) -> dict[str, str]:
    return {
        "task_contract_sha256": bundle.task_contract_sha256,
        "profile_sha256": bundle.profile_sha256,
        "fixture_definition_sha256": bundle.fixture_definition_sha256,
        "trusted_oracle_sha256": bundle.oracle.oracle_sha256,
        "fixture_sha256": bundle.descriptor.fixture_sha256,
    }


def _catalog_payload(
    registry: EleventhTrancheTaskRegistry,
    bundles: tuple[EleventhTrancheFixtureBundle, ...],
) -> dict[str, object]:
    return {
        "schema_version": ELEVENTH_TRANCHE_CATALOG_SCHEMA_VERSION,
        "catalog_version": ELEVENTH_TRANCHE_CATALOG_VERSION,
        "record_type": (
            "cbds.executable-fixture-eleventh-tranche-catalog"
        ),
        "base_fixture_catalog_sha256": FROZEN_TENTH_CATALOG_SHA256,
        "added_registry_sha256": registry.registry_sha256,
        "cumulative_suite_sha256": registry.cumulative_suite_sha256,
        "base_cumulative_task_count": TENTH_PREFIX_TASK_COUNT,
        "added_task_count": ELEVENTH_TRANCHE_ADDED_TASK_COUNT,
        "cumulative_task_count": ELEVENTH_TRANCHE_CUMULATIVE_TASK_COUNT,
        "profiles_per_task": ELEVENTH_TRANCHE_PROFILE_COUNT,
        "base_cumulative_fixture_count": TENTH_PREFIX_FIXTURE_COUNT,
        "added_fixture_count": ELEVENTH_TRANCHE_ADDED_FIXTURE_COUNT,
        "cumulative_fixture_count": (
            ELEVENTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT
        ),
        "profile_sha256": [
            profile.profile_sha256
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        ],
        "family_task_counts": {
            family: sum(
                task.family_id == family for task in registry.added_tasks
            )
            for family in ELEVENTH_TRANCHE_FAMILY_ORDER
        },
        "family_fixture_counts": {
            family: sum(
                task.family_id == family for task in registry.added_tasks
            )
            * ELEVENTH_TRANCHE_PROFILE_COUNT
            for family in ELEVENTH_TRANCHE_FAMILY_ORDER
        },
        "family_generators": [
            {
                "family_id": CHECKSUM_REPAIR_PLAN_FAMILY_ID,
                "generator_version": CHECKSUM_REPAIR_PLAN_GENERATOR_VERSION,
                "semantic_verifier_identity": (
                    CHECKSUM_REPAIR_PLAN_VERIFIER_IDENTITY
                ),
                "output_maximum_bytes": (
                    CHECKSUM_REPAIR_PLAN_OUTPUT_MAXIMUM_BYTES
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
    registry: EleventhTrancheTaskRegistry,
    bundles: tuple[EleventhTrancheFixtureBundle, ...],
) -> str:
    return domain_sha256(
        "cbds.executable-fixture.eleventh-tranche-catalog.v1",
        _catalog_payload(registry, bundles),
    )


def compute_eleventh_tranche_fixture_catalog_sha256(
    registry: EleventhTrancheTaskRegistry,
    bundles: tuple[EleventhTrancheFixtureBundle, ...],
) -> str:
    selected_registry, selected_bundles = _validate_inputs(
        registry, bundles, regenerate=True
    )
    return _catalog_digest(selected_registry, selected_bundles)


@dataclass(frozen=True, slots=True)
class EleventhTrancheFixtureCatalog:
    registry: EleventhTrancheTaskRegistry = field(repr=False)
    bundles: tuple[EleventhTrancheFixtureBundle, ...] = field(repr=False)
    catalog_sha256: str
    schema_version: str = ELEVENTH_TRANCHE_CATALOG_SCHEMA_VERSION
    catalog_version: str = ELEVENTH_TRANCHE_CATALOG_VERSION
    base_fixture_catalog_sha256: str = FROZEN_TENTH_CATALOG_SHA256
    public_method_development: bool = True
    sealed: bool = False
    independent_human_review_attested: bool = False
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_eleventh_tranche_fixture_catalog(self)

    def to_hash_only_record(self) -> dict[str, object]:
        _validate_catalog_snapshot(self)
        return {
            **_catalog_payload(self.registry, self.bundles),
            "catalog_sha256": self.catalog_sha256,
        }


def _validate_metadata(
    catalog: object,
) -> EleventhTrancheFixtureCatalog:
    if type(catalog) is not EleventhTrancheFixtureCatalog:
        raise EleventhTrancheFixtureCatalogError(
            "catalog must be an exact EleventhTrancheFixtureCatalog"
        )
    if (
        catalog.schema_version
        != ELEVENTH_TRANCHE_CATALOG_SCHEMA_VERSION
        or catalog.catalog_version != ELEVENTH_TRANCHE_CATALOG_VERSION
        or not _is_sha256(catalog.base_fixture_catalog_sha256)
        or catalog.base_fixture_catalog_sha256
        != FROZEN_TENTH_CATALOG_SHA256
        or not _is_sha256(catalog.catalog_sha256)
        or catalog.public_method_development is not True
        or catalog.sealed is not False
        or catalog.independent_human_review_attested is not False
        or catalog.candidate_execution_authorized is not False
        or catalog.model_selection_eligible is not False
        or catalog.claim_authorized is not False
    ):
        raise EleventhTrancheFixtureCatalogError(
            "eleventh-tranche catalog metadata is invalid"
        )
    return catalog


def validate_eleventh_tranche_fixture_catalog(
    catalog: EleventhTrancheFixtureCatalog,
) -> None:
    selected = _validate_metadata(catalog)
    registry, bundles = _validate_inputs(
        selected.registry, selected.bundles, regenerate=True
    )
    if selected.catalog_sha256 != _catalog_digest(registry, bundles):
        raise EleventhTrancheFixtureCatalogError(
            "eleventh-tranche catalog digest is invalid"
        )


def _validate_catalog_snapshot(
    catalog: EleventhTrancheFixtureCatalog,
) -> None:
    selected = _validate_metadata(catalog)
    registry, bundles = _validate_inputs(
        selected.registry, selected.bundles, regenerate=False
    )
    if selected.catalog_sha256 != _catalog_digest(registry, bundles):
        raise EleventhTrancheFixtureCatalogError(
            "eleventh-tranche catalog digest is invalid"
        )


def verify_eleventh_tranche_fixture_catalog(catalog: object) -> bool:
    try:
        validate_eleventh_tranche_fixture_catalog(
            catalog  # type: ignore[arg-type]
        )
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def _validate_live_base_and_global_uniqueness(
    registry: EleventhTrancheTaskRegistry,
    bundles: tuple[EleventhTrancheFixtureBundle, ...],
    evidence: TenthPrefixFixtureEvidence,
) -> None:
    """Admit the exact tenth prefix and reject all cross-chain collisions."""

    try:
        validate_tenth_prefix_fixture_evidence(evidence)
    except (AttributeError, TypeError, ValueError) as exc:
        raise EleventhTrancheFixtureCatalogError(
            "through-tenth fixture evidence could not be established"
        ) from exc
    if (
        evidence.total_fixture_count != TENTH_PREFIX_FIXTURE_COUNT
        or evidence.terminal_catalog_sha256
        != FROZEN_TENTH_CATALOG_SHA256
        or evidence.task_evidence.terminal_registry_sha256
        != FROZEN_TENTH_REGISTRY_SHA256
        or evidence.task_evidence.terminal_cumulative_suite_sha256
        != FROZEN_TENTH_CUMULATIVE_SUITE_SHA256
        or registry.base_added_registry_sha256
        != evidence.task_evidence.terminal_registry_sha256
        or registry.base_cumulative_suite_sha256
        != evidence.task_evidence.terminal_cumulative_suite_sha256
    ):
        raise EleventhTrancheFixtureCatalogError(
            "a live predecessor differs from its frozen tenth identity"
        )
    all_bundles = (*evidence.bundles, *bundles)
    if (
        len(all_bundles) != ELEVENTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT
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
        raise EleventhTrancheFixtureCatalogError(
            "eleventh-tranche fixtures collide with a frozen predecessor"
        )
    if any(
        bundle is predecessor
        for bundle in bundles
        for predecessor in evidence.bundles
    ):
        raise EleventhTrancheFixtureCatalogError(
            "eleventh-tranche fixtures must be freshly owned additions"
        )


def build_eleventh_tranche_fixture_catalog_local(
    registry: EleventhTrancheTaskRegistry,
) -> EleventhTrancheFixtureCatalog:
    """Build only eleventh-tranche bundles without predecessor reconstruction."""

    if type(registry) is not EleventhTrancheTaskRegistry:
        raise TypeError(
            "registry must be an exact EleventhTrancheTaskRegistry"
        )
    validate_eleventh_tranche_task_registry(registry)
    bundles = tuple(
        _build_bundle(task, profile)
        for task in registry.added_tasks
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
    )
    selected_registry, selected_bundles = _validate_inputs(
        registry, bundles, regenerate=False
    )
    digest = _catalog_digest(selected_registry, selected_bundles)

    catalog = object.__new__(EleventhTrancheFixtureCatalog)
    values: dict[str, object] = {
        "registry": selected_registry,
        "bundles": selected_bundles,
        "catalog_sha256": digest,
        "schema_version": ELEVENTH_TRANCHE_CATALOG_SCHEMA_VERSION,
        "catalog_version": ELEVENTH_TRANCHE_CATALOG_VERSION,
        "base_fixture_catalog_sha256": FROZEN_TENTH_CATALOG_SHA256,
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


def build_eleventh_tranche_fixture_catalog(
    registry: EleventhTrancheTaskRegistry | None = None,
) -> EleventhTrancheFixtureCatalog:
    """Build the eleventh catalog over one shared through-tenth snapshot."""

    task_evidence = build_tenth_prefix_task_evidence()
    validate_tenth_prefix_task_evidence(task_evidence)
    live_registry = build_eleventh_tranche_task_registry(task_evidence)
    selected_registry = live_registry if registry is None else registry
    if type(selected_registry) is not EleventhTrancheTaskRegistry:
        raise TypeError(
            "registry must be an exact EleventhTrancheTaskRegistry"
        )
    validate_eleventh_tranche_task_registry(selected_registry)
    if selected_registry != live_registry:
        raise EleventhTrancheFixtureCatalogError(
            "supplied registry differs from the live collision-checked addition"
        )
    fixture_evidence = build_tenth_prefix_fixture_evidence(task_evidence)
    catalog = build_eleventh_tranche_fixture_catalog_local(
        selected_registry
    )
    _validate_live_base_and_global_uniqueness(
        selected_registry, catalog.bundles, fixture_evidence
    )
    return catalog


__all__ = [
    "ELEVENTH_TRANCHE_ADDED_FIXTURE_COUNT",
    "ELEVENTH_TRANCHE_CATALOG_SCHEMA_VERSION",
    "ELEVENTH_TRANCHE_CATALOG_VERSION",
    "ELEVENTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT",
    "ELEVENTH_TRANCHE_FIXTURE_COUNT",
    "ELEVENTH_TRANCHE_PROFILE_COUNT",
    "FROZEN_TENTH_CATALOG_SHA256",
    "EleventhTrancheFixtureBundle",
    "EleventhTrancheFixtureCatalog",
    "EleventhTrancheFixtureCatalogError",
    "build_eleventh_tranche_fixture_catalog",
    "build_eleventh_tranche_fixture_catalog_local",
    "compute_eleventh_tranche_fixture_catalog_sha256",
    "validate_eleventh_tranche_fixture_catalog",
    "verify_eleventh_tranche_fixture_catalog",
]
