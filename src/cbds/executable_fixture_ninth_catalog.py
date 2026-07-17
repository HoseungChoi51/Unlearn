"""Hash-bound ninth catalog for hardlink-deduplicated-mirror fixtures.

The catalog preserves the frozen first-through-eighth catalog chain, binds the
exact ninth 20-task grid against five public profiles, and commits to 100 new
fixture/oracle bindings.  Its public projection contains hashes and counts,
never fixture bytes, paths, prompts, or oracle answers.

The full builder obtains one linear predecessor task snapshot and passes that
same snapshot into the linear fixture-evidence builder.  Consequently the
first eight task tranches are reconstructed once and the first eight catalogs
are each built locally once; no historical recursive catalog builder is used.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Final, TypeAlias

from .executable_fixture_profiles import (
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
    ExecutableFixtureProfile,
)
from .executable_hardlink_deduplicated_mirror import (
    HARDLINK_DEDUPLICATED_MIRROR_FAMILY_ID,
    HARDLINK_DEDUPLICATED_MIRROR_GENERATOR_VERSION,
    HARDLINK_DEDUPLICATED_MIRROR_REPORT_MAXIMUM_BYTES,
    HARDLINK_DEDUPLICATED_MIRROR_VERIFIER_IDENTITY,
    HardlinkDeduplicatedMirrorFixtureBundle,
    HardlinkDeduplicatedMirrorTask,
    build_hardlink_deduplicated_mirror_fixture_bundle,
    validate_hardlink_deduplicated_mirror_fixture_bundle,
    validate_hardlink_deduplicated_mirror_fixture_for_task_profile,
)
from .executable_linear_predecessor_evidence import (
    FROZEN_PREDECESSOR_CATALOG_SHA256,
    LINEAR_PREDECESSOR_FIXTURE_COUNT,
    LINEAR_PREDECESSOR_TASK_COUNT,
    LinearFixturePredecessorEvidence,
    LinearTaskPredecessorEvidence,
    build_linear_fixture_predecessor_evidence,
    build_linear_task_predecessor_evidence,
    validate_linear_fixture_predecessor_evidence,
    validate_linear_task_predecessor_evidence,
)
from .executable_static_ninth_registry import (
    FROZEN_EIGHTH_ADDED_REGISTRY_SHA256,
    FROZEN_EIGHTH_CUMULATIVE_SUITE_SHA256,
    NINTH_TRANCHE_ADDED_TASK_COUNT,
    NINTH_TRANCHE_CUMULATIVE_TASK_COUNT,
    NINTH_TRANCHE_FAMILY_ORDER,
    NinthTrancheTask,
    NinthTrancheTaskRegistry,
    build_ninth_tranche_added_tasks,
    compute_ninth_tranche_cumulative_suite_sha256,
    compute_ninth_tranche_registry_sha256,
    validate_ninth_tranche_task_registry,
)
from .executable_static_types import domain_sha256


NINTH_TRANCHE_CATALOG_SCHEMA_VERSION: Final[str] = "1.0.0"
NINTH_TRANCHE_CATALOG_VERSION: Final[str] = "1.0.0"
NINTH_TRANCHE_PROFILE_COUNT: Final[int] = 5
NINTH_TRANCHE_ADDED_FIXTURE_COUNT: Final[int] = 100
NINTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT: Final[int] = 1_800
NINTH_TRANCHE_FIXTURE_COUNT: Final[int] = NINTH_TRANCHE_ADDED_FIXTURE_COUNT

FROZEN_EIGHTH_CATALOG_SHA256: Final[str] = (
    FROZEN_PREDECESSOR_CATALOG_SHA256[-1]
)

NinthTrancheFixtureBundle: TypeAlias = (
    HardlinkDeduplicatedMirrorFixtureBundle
)
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")


class NinthTrancheFixtureCatalogError(ValueError):
    """Raised when the ninth additive catalog is not reproducible."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def _build_bundle(
    task: NinthTrancheTask,
    profile: ExecutableFixtureProfile,
) -> NinthTrancheFixtureBundle:
    if type(task) is not HardlinkDeduplicatedMirrorTask:
        raise NinthTrancheFixtureCatalogError(
            "task type is outside the ninth tranche"
        )
    bundle = build_hardlink_deduplicated_mirror_fixture_bundle(task, profile)
    validate_hardlink_deduplicated_mirror_fixture_for_task_profile(
        task, profile, bundle
    )
    return bundle


def _validate_bundle(
    task: NinthTrancheTask,
    profile: ExecutableFixtureProfile,
    bundle: object,
    *,
    regenerate: bool,
) -> NinthTrancheFixtureBundle:
    try:
        if type(task) is not HardlinkDeduplicatedMirrorTask:
            raise NinthTrancheFixtureCatalogError(
                "ninth-tranche task has the wrong exact type"
            )
        if type(bundle) is not HardlinkDeduplicatedMirrorFixtureBundle:
            raise NinthTrancheFixtureCatalogError(
                "hardlink mirror task has the wrong bundle type"
            )
        validate_hardlink_deduplicated_mirror_fixture_bundle(bundle)
        validate_hardlink_deduplicated_mirror_fixture_for_task_profile(
            task, profile, bundle
        )
    except (AttributeError, TypeError, ValueError) as exc:
        if isinstance(exc, NinthTrancheFixtureCatalogError):
            raise
        raise NinthTrancheFixtureCatalogError(
            "family-local bundle validation failed"
        ) from exc
    selected = bundle
    if regenerate and selected != _build_bundle(task, profile):
        raise NinthTrancheFixtureCatalogError(
            "bundle differs from deterministic family generation"
        )
    return selected


def _validate_inputs(
    registry: object,
    bundles: object,
    *,
    regenerate: bool,
) -> tuple[
    NinthTrancheTaskRegistry,
    tuple[NinthTrancheFixtureBundle, ...],
]:
    if type(registry) is not NinthTrancheTaskRegistry:
        raise NinthTrancheFixtureCatalogError(
            "registry must be an exact NinthTrancheTaskRegistry"
        )
    try:
        validate_ninth_tranche_task_registry(registry)
    except (AttributeError, TypeError, ValueError) as exc:
        raise NinthTrancheFixtureCatalogError(
            "ninth registry is invalid"
        ) from exc
    if (
        type(bundles) is not tuple
        or len(bundles) != NINTH_TRANCHE_ADDED_FIXTURE_COUNT
        or any(
            type(bundle) is not HardlinkDeduplicatedMirrorFixtureBundle
            for bundle in bundles
        )
    ):
        raise NinthTrancheFixtureCatalogError(
            "ninth catalog requires exactly 100 exact "
            "HardlinkDeduplicatedMirrorFixtureBundle values"
        )

    fixture_ids: set[str] = set()
    fixture_hashes: set[str] = set()
    for index, raw_bundle in enumerate(bundles):
        task = registry.added_tasks[index // NINTH_TRANCHE_PROFILE_COUNT]
        profile_index = index % NINTH_TRANCHE_PROFILE_COUNT
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
            raise NinthTrancheFixtureCatalogError(
                "bundle order, descriptor, or authority boundary is invalid"
            )
        fixture_ids.add(bundle.descriptor.fixture_id)
        fixture_hashes.add(bundle.descriptor.fixture_sha256)
    if (
        len(fixture_ids) != NINTH_TRANCHE_ADDED_FIXTURE_COUNT
        or len(fixture_hashes) != NINTH_TRANCHE_ADDED_FIXTURE_COUNT
    ):
        raise NinthTrancheFixtureCatalogError(
            "ninth-tranche fixture identities are not unique"
        )
    return registry, bundles


def _task_hash_record(task: NinthTrancheTask) -> dict[str, str]:
    return {
        "family_id": task.family_id,
        "task_contract_sha256": task.task_contract_sha256,
        "graph_sha256": task.graph_sha256,
    }


def _fixture_hash_record(
    bundle: NinthTrancheFixtureBundle,
) -> dict[str, str]:
    return {
        "task_contract_sha256": bundle.task_contract_sha256,
        "profile_sha256": bundle.profile_sha256,
        "fixture_definition_sha256": bundle.fixture_definition_sha256,
        "trusted_oracle_sha256": bundle.oracle.oracle_sha256,
        "fixture_sha256": bundle.descriptor.fixture_sha256,
    }


def _catalog_payload(
    registry: NinthTrancheTaskRegistry,
    bundles: tuple[NinthTrancheFixtureBundle, ...],
) -> dict[str, object]:
    return {
        "schema_version": NINTH_TRANCHE_CATALOG_SCHEMA_VERSION,
        "catalog_version": NINTH_TRANCHE_CATALOG_VERSION,
        "record_type": "cbds.executable-fixture-ninth-tranche-catalog",
        "base_fixture_catalog_sha256": FROZEN_EIGHTH_CATALOG_SHA256,
        "added_registry_sha256": registry.registry_sha256,
        "cumulative_suite_sha256": registry.cumulative_suite_sha256,
        "base_cumulative_task_count": LINEAR_PREDECESSOR_TASK_COUNT,
        "added_task_count": NINTH_TRANCHE_ADDED_TASK_COUNT,
        "cumulative_task_count": NINTH_TRANCHE_CUMULATIVE_TASK_COUNT,
        "profiles_per_task": NINTH_TRANCHE_PROFILE_COUNT,
        "base_cumulative_fixture_count": LINEAR_PREDECESSOR_FIXTURE_COUNT,
        "added_fixture_count": NINTH_TRANCHE_ADDED_FIXTURE_COUNT,
        "cumulative_fixture_count": NINTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT,
        "profile_sha256": [
            profile.profile_sha256
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        ],
        "family_task_counts": {
            family: sum(
                task.family_id == family for task in registry.added_tasks
            )
            for family in NINTH_TRANCHE_FAMILY_ORDER
        },
        "family_fixture_counts": {
            family: sum(
                task.family_id == family for task in registry.added_tasks
            )
            * NINTH_TRANCHE_PROFILE_COUNT
            for family in NINTH_TRANCHE_FAMILY_ORDER
        },
        "family_generators": [
            {
                "family_id": HARDLINK_DEDUPLICATED_MIRROR_FAMILY_ID,
                "generator_version": (
                    HARDLINK_DEDUPLICATED_MIRROR_GENERATOR_VERSION
                ),
                "semantic_verifier_identity": (
                    HARDLINK_DEDUPLICATED_MIRROR_VERIFIER_IDENTITY
                ),
                "output_maximum_bytes": (
                    HARDLINK_DEDUPLICATED_MIRROR_REPORT_MAXIMUM_BYTES
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
    registry: NinthTrancheTaskRegistry,
    bundles: tuple[NinthTrancheFixtureBundle, ...],
) -> str:
    return domain_sha256(
        "cbds.executable-fixture.ninth-tranche-catalog.v1",
        _catalog_payload(registry, bundles),
    )


def compute_ninth_tranche_fixture_catalog_sha256(
    registry: NinthTrancheTaskRegistry,
    bundles: tuple[NinthTrancheFixtureBundle, ...],
) -> str:
    selected_registry, selected_bundles = _validate_inputs(
        registry, bundles, regenerate=True
    )
    return _catalog_digest(selected_registry, selected_bundles)


@dataclass(frozen=True, slots=True)
class NinthTrancheFixtureCatalog:
    registry: NinthTrancheTaskRegistry = field(repr=False)
    bundles: tuple[NinthTrancheFixtureBundle, ...] = field(repr=False)
    catalog_sha256: str
    schema_version: str = NINTH_TRANCHE_CATALOG_SCHEMA_VERSION
    catalog_version: str = NINTH_TRANCHE_CATALOG_VERSION
    base_fixture_catalog_sha256: str = FROZEN_EIGHTH_CATALOG_SHA256
    public_method_development: bool = True
    sealed: bool = False
    independent_human_review_attested: bool = False
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_ninth_tranche_fixture_catalog(self)

    def to_hash_only_record(self) -> dict[str, object]:
        _validate_catalog_snapshot(self)
        return {
            **_catalog_payload(self.registry, self.bundles),
            "catalog_sha256": self.catalog_sha256,
        }


def _validate_metadata(
    catalog: object,
) -> NinthTrancheFixtureCatalog:
    if type(catalog) is not NinthTrancheFixtureCatalog:
        raise NinthTrancheFixtureCatalogError(
            "catalog must be an exact NinthTrancheFixtureCatalog"
        )
    if (
        catalog.schema_version != NINTH_TRANCHE_CATALOG_SCHEMA_VERSION
        or catalog.catalog_version != NINTH_TRANCHE_CATALOG_VERSION
        or not _is_sha256(catalog.base_fixture_catalog_sha256)
        or catalog.base_fixture_catalog_sha256
        != FROZEN_EIGHTH_CATALOG_SHA256
        or not _is_sha256(catalog.catalog_sha256)
        or catalog.public_method_development is not True
        or catalog.sealed is not False
        or catalog.independent_human_review_attested is not False
        or catalog.candidate_execution_authorized is not False
        or catalog.model_selection_eligible is not False
        or catalog.claim_authorized is not False
    ):
        raise NinthTrancheFixtureCatalogError(
            "ninth-tranche catalog metadata is invalid"
        )
    return catalog


def validate_ninth_tranche_fixture_catalog(
    catalog: NinthTrancheFixtureCatalog,
) -> None:
    selected = _validate_metadata(catalog)
    registry, bundles = _validate_inputs(
        selected.registry, selected.bundles, regenerate=True
    )
    if selected.catalog_sha256 != _catalog_digest(registry, bundles):
        raise NinthTrancheFixtureCatalogError(
            "ninth-tranche catalog digest is invalid"
        )


def _validate_catalog_snapshot(
    catalog: NinthTrancheFixtureCatalog,
) -> None:
    selected = _validate_metadata(catalog)
    registry, bundles = _validate_inputs(
        selected.registry, selected.bundles, regenerate=False
    )
    if selected.catalog_sha256 != _catalog_digest(registry, bundles):
        raise NinthTrancheFixtureCatalogError(
            "ninth-tranche catalog digest is invalid"
        )


def verify_ninth_tranche_fixture_catalog(catalog: object) -> bool:
    try:
        validate_ninth_tranche_fixture_catalog(
            catalog  # type: ignore[arg-type]
        )
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def _build_registry_from_task_evidence(
    evidence: LinearTaskPredecessorEvidence,
) -> NinthTrancheTaskRegistry:
    """Build the ninth registry without rebuilding predecessor tasks."""

    validate_linear_task_predecessor_evidence(evidence)
    if (
        evidence.total_task_count != LINEAR_PREDECESSOR_TASK_COUNT
        or evidence.terminal_registry_sha256
        != FROZEN_EIGHTH_ADDED_REGISTRY_SHA256
        or evidence.terminal_cumulative_suite_sha256
        != FROZEN_EIGHTH_CUMULATIVE_SUITE_SHA256
    ):
        raise NinthTrancheFixtureCatalogError(
            "linear task evidence does not admit the frozen eighth registry"
        )
    tasks = build_ninth_tranche_added_tasks()
    all_tasks = (*evidence.tasks, *tasks)
    if (
        len(all_tasks) != NINTH_TRANCHE_CUMULATIVE_TASK_COUNT
        or len({task.task_id for task in all_tasks}) != len(all_tasks)
        or len({task.task_contract_sha256 for task in all_tasks})
        != len(all_tasks)
        or len({task.graph_sha256 for task in all_tasks}) != len(all_tasks)
    ):
        raise NinthTrancheFixtureCatalogError(
            "ninth tasks collide with a frozen predecessor"
        )
    registry_sha256 = compute_ninth_tranche_registry_sha256(tasks)
    return NinthTrancheTaskRegistry(
        added_tasks=tasks,
        registry_sha256=registry_sha256,
        cumulative_suite_sha256=(
            compute_ninth_tranche_cumulative_suite_sha256(
                tasks, registry_sha256
            )
        ),
    )


def _validate_live_base_and_global_uniqueness(
    registry: NinthTrancheTaskRegistry,
    bundles: tuple[NinthTrancheFixtureBundle, ...],
    evidence: LinearFixturePredecessorEvidence,
) -> None:
    """Admit the exact frozen chain and reject every cross-chain collision."""

    try:
        validate_linear_fixture_predecessor_evidence(evidence)
    except (AttributeError, TypeError, ValueError) as exc:
        raise NinthTrancheFixtureCatalogError(
            "linear predecessor fixture evidence could not be established"
        ) from exc
    if (
        evidence.total_fixture_count != LINEAR_PREDECESSOR_FIXTURE_COUNT
        or evidence.terminal_catalog_sha256
        != FROZEN_EIGHTH_CATALOG_SHA256
        or tuple(
            tranche.catalog_sha256 for tranche in evidence.tranches
        )
        != FROZEN_PREDECESSOR_CATALOG_SHA256
        or evidence.task_evidence.terminal_registry_sha256
        != registry.base_added_registry_sha256
        or evidence.task_evidence.terminal_cumulative_suite_sha256
        != registry.base_cumulative_suite_sha256
    ):
        raise NinthTrancheFixtureCatalogError(
            "a live predecessor differs from its frozen identity"
        )
    all_bundles = (*evidence.bundles, *bundles)
    if (
        len(all_bundles) != NINTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT
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
        raise NinthTrancheFixtureCatalogError(
            "ninth-tranche fixtures collide with a frozen predecessor"
        )


def build_ninth_tranche_fixture_catalog_local(
    registry: NinthTrancheTaskRegistry,
) -> NinthTrancheFixtureCatalog:
    """Build only ninth-tranche bundles without predecessor reconstruction."""

    if type(registry) is not NinthTrancheTaskRegistry:
        raise TypeError("registry must be an exact NinthTrancheTaskRegistry")
    validate_ninth_tranche_task_registry(registry)
    bundles = tuple(
        _build_bundle(task, profile)
        for task in registry.added_tasks
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
    )
    selected_registry, selected_bundles = _validate_inputs(
        registry, bundles, regenerate=False
    )
    digest = _catalog_digest(selected_registry, selected_bundles)

    catalog = object.__new__(NinthTrancheFixtureCatalog)
    values: dict[str, object] = {
        "registry": selected_registry,
        "bundles": selected_bundles,
        "catalog_sha256": digest,
        "schema_version": NINTH_TRANCHE_CATALOG_SCHEMA_VERSION,
        "catalog_version": NINTH_TRANCHE_CATALOG_VERSION,
        "base_fixture_catalog_sha256": FROZEN_EIGHTH_CATALOG_SHA256,
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


def build_ninth_tranche_fixture_catalog(
    registry: NinthTrancheTaskRegistry | None = None,
) -> NinthTrancheFixtureCatalog:
    """Build the ninth catalog over one shared linear predecessor snapshot."""

    task_evidence = build_linear_task_predecessor_evidence()
    selected_registry = (
        _build_registry_from_task_evidence(task_evidence)
        if registry is None
        else registry
    )
    if type(selected_registry) is not NinthTrancheTaskRegistry:
        raise TypeError("registry must be an exact NinthTrancheTaskRegistry")
    validate_ninth_tranche_task_registry(selected_registry)
    fixture_evidence = build_linear_fixture_predecessor_evidence(
        task_evidence
    )
    catalog = build_ninth_tranche_fixture_catalog_local(selected_registry)
    _validate_live_base_and_global_uniqueness(
        selected_registry, catalog.bundles, fixture_evidence
    )
    return catalog


__all__ = [
    "FROZEN_EIGHTH_CATALOG_SHA256",
    "NINTH_TRANCHE_ADDED_FIXTURE_COUNT",
    "NINTH_TRANCHE_CATALOG_SCHEMA_VERSION",
    "NINTH_TRANCHE_CATALOG_VERSION",
    "NINTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT",
    "NINTH_TRANCHE_FIXTURE_COUNT",
    "NINTH_TRANCHE_PROFILE_COUNT",
    "NinthTrancheFixtureCatalog",
    "NinthTrancheFixtureCatalogError",
    "NinthTrancheFixtureBundle",
    "build_ninth_tranche_fixture_catalog",
    "build_ninth_tranche_fixture_catalog_local",
    "compute_ninth_tranche_fixture_catalog_sha256",
    "validate_ninth_tranche_fixture_catalog",
    "verify_ninth_tranche_fixture_catalog",
]
