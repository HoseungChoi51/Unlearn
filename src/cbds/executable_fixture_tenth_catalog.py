"""Hash-bound tenth catalog for compressed archive roundtrip fixtures.

The catalog preserves the frozen first-through-ninth publication chain,
binds the exact tenth 20-task grid against five public development profiles,
and commits to 100 new fixture/oracle bindings.  Its public projection
contains hashes and counts, never fixture bytes, paths, prompts, or oracle
answers.

The full builder obtains one through-ninth task snapshot and passes that same
snapshot into the non-recursive through-ninth fixture builder.  No recursive
ninth registry or catalog publication builder is used.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Final, TypeAlias

from .executable_compressed_archive_roundtrip_verify import (
    COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_FAMILY_ID,
    COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_GENERATOR_VERSION,
    COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_MAXIMUM_ARCHIVE_BYTES,
    COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_VERIFIER_IDENTITY,
    CompressedArchiveRoundtripVerifyFixtureBundle,
    CompressedArchiveRoundtripVerifyTask,
    build_compressed_archive_roundtrip_verify_fixture_bundle,
    validate_compressed_archive_roundtrip_verify_fixture_bundle,
    validate_compressed_archive_roundtrip_verify_fixture_for_task_profile,
)
from .executable_fixture_profiles import (
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
    ExecutableFixtureProfile,
)
from .executable_ninth_predecessor_evidence import (
    FROZEN_NINTH_CATALOG_SHA256,
    FROZEN_NINTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_NINTH_REGISTRY_SHA256,
    NINTH_PREFIX_FIXTURE_COUNT,
    NINTH_PREFIX_TASK_COUNT,
    NinthPrefixFixtureEvidence,
    build_ninth_prefix_fixture_evidence,
    build_ninth_prefix_task_evidence,
    validate_ninth_prefix_fixture_evidence,
    validate_ninth_prefix_task_evidence,
)
from .executable_static_tenth_registry import (
    TENTH_TRANCHE_ADDED_TASK_COUNT,
    TENTH_TRANCHE_CUMULATIVE_TASK_COUNT,
    TENTH_TRANCHE_FAMILY_ORDER,
    TenthTrancheTask,
    TenthTrancheTaskRegistry,
    build_tenth_tranche_task_registry,
    validate_tenth_tranche_task_registry,
)
from .executable_static_types import domain_sha256


TENTH_TRANCHE_CATALOG_SCHEMA_VERSION: Final[str] = "1.0.0"
TENTH_TRANCHE_CATALOG_VERSION: Final[str] = "1.0.0"
TENTH_TRANCHE_PROFILE_COUNT: Final[int] = 5
TENTH_TRANCHE_ADDED_FIXTURE_COUNT: Final[int] = 100
TENTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT: Final[int] = 1_900
TENTH_TRANCHE_FIXTURE_COUNT: Final[int] = TENTH_TRANCHE_ADDED_FIXTURE_COUNT

TenthTrancheFixtureBundle: TypeAlias = (
    CompressedArchiveRoundtripVerifyFixtureBundle
)
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")


class TenthTrancheFixtureCatalogError(ValueError):
    """Raised when the tenth additive catalog is not reproducible."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def _build_bundle(
    task: TenthTrancheTask,
    profile: ExecutableFixtureProfile,
) -> TenthTrancheFixtureBundle:
    if type(task) is not CompressedArchiveRoundtripVerifyTask:
        raise TenthTrancheFixtureCatalogError(
            "task type is outside the tenth tranche"
        )
    bundle = build_compressed_archive_roundtrip_verify_fixture_bundle(
        task, profile
    )
    validate_compressed_archive_roundtrip_verify_fixture_for_task_profile(
        task, profile, bundle
    )
    return bundle


def _validate_bundle(
    task: TenthTrancheTask,
    profile: ExecutableFixtureProfile,
    bundle: object,
    *,
    regenerate: bool,
) -> TenthTrancheFixtureBundle:
    try:
        if type(task) is not CompressedArchiveRoundtripVerifyTask:
            raise TenthTrancheFixtureCatalogError(
                "tenth-tranche task has the wrong exact type"
            )
        if type(bundle) is not CompressedArchiveRoundtripVerifyFixtureBundle:
            raise TenthTrancheFixtureCatalogError(
                "compressed archive task has the wrong bundle type"
            )
        validate_compressed_archive_roundtrip_verify_fixture_bundle(bundle)
        validate_compressed_archive_roundtrip_verify_fixture_for_task_profile(
            task, profile, bundle
        )
    except (AttributeError, TypeError, ValueError) as exc:
        if isinstance(exc, TenthTrancheFixtureCatalogError):
            raise
        raise TenthTrancheFixtureCatalogError(
            "family-local bundle validation failed"
        ) from exc
    selected = bundle
    if regenerate and selected != _build_bundle(task, profile):
        raise TenthTrancheFixtureCatalogError(
            "bundle differs from deterministic family generation"
        )
    return selected


def _validate_inputs(
    registry: object,
    bundles: object,
    *,
    regenerate: bool,
) -> tuple[
    TenthTrancheTaskRegistry,
    tuple[TenthTrancheFixtureBundle, ...],
]:
    if type(registry) is not TenthTrancheTaskRegistry:
        raise TenthTrancheFixtureCatalogError(
            "registry must be an exact TenthTrancheTaskRegistry"
        )
    try:
        validate_tenth_tranche_task_registry(registry)
    except (AttributeError, TypeError, ValueError) as exc:
        raise TenthTrancheFixtureCatalogError(
            "tenth registry is invalid"
        ) from exc
    if (
        type(bundles) is not tuple
        or len(bundles) != TENTH_TRANCHE_ADDED_FIXTURE_COUNT
        or any(
            type(bundle) is not CompressedArchiveRoundtripVerifyFixtureBundle
            for bundle in bundles
        )
    ):
        raise TenthTrancheFixtureCatalogError(
            "tenth catalog requires exactly 100 exact "
            "CompressedArchiveRoundtripVerifyFixtureBundle values"
        )

    fixture_ids: set[str] = set()
    fixture_hashes: set[str] = set()
    for index, raw_bundle in enumerate(bundles):
        task = registry.added_tasks[index // TENTH_TRANCHE_PROFILE_COUNT]
        profile_index = index % TENTH_TRANCHE_PROFILE_COUNT
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
            raise TenthTrancheFixtureCatalogError(
                "bundle order, descriptor, or authority boundary is invalid"
            )
        fixture_ids.add(bundle.descriptor.fixture_id)
        fixture_hashes.add(bundle.descriptor.fixture_sha256)
    if (
        len(fixture_ids) != TENTH_TRANCHE_ADDED_FIXTURE_COUNT
        or len(fixture_hashes) != TENTH_TRANCHE_ADDED_FIXTURE_COUNT
    ):
        raise TenthTrancheFixtureCatalogError(
            "tenth-tranche fixture identities are not unique"
        )
    return registry, bundles


def _task_hash_record(task: TenthTrancheTask) -> dict[str, str]:
    return {
        "family_id": task.family_id,
        "task_contract_sha256": task.task_contract_sha256,
        "graph_sha256": task.graph_sha256,
    }


def _fixture_hash_record(
    bundle: TenthTrancheFixtureBundle,
) -> dict[str, str]:
    return {
        "task_contract_sha256": bundle.task_contract_sha256,
        "profile_sha256": bundle.profile_sha256,
        "fixture_definition_sha256": bundle.fixture_definition_sha256,
        "trusted_oracle_sha256": bundle.oracle.oracle_sha256,
        "fixture_sha256": bundle.descriptor.fixture_sha256,
    }


def _catalog_payload(
    registry: TenthTrancheTaskRegistry,
    bundles: tuple[TenthTrancheFixtureBundle, ...],
) -> dict[str, object]:
    return {
        "schema_version": TENTH_TRANCHE_CATALOG_SCHEMA_VERSION,
        "catalog_version": TENTH_TRANCHE_CATALOG_VERSION,
        "record_type": "cbds.executable-fixture-tenth-tranche-catalog",
        "base_fixture_catalog_sha256": FROZEN_NINTH_CATALOG_SHA256,
        "added_registry_sha256": registry.registry_sha256,
        "cumulative_suite_sha256": registry.cumulative_suite_sha256,
        "base_cumulative_task_count": NINTH_PREFIX_TASK_COUNT,
        "added_task_count": TENTH_TRANCHE_ADDED_TASK_COUNT,
        "cumulative_task_count": TENTH_TRANCHE_CUMULATIVE_TASK_COUNT,
        "profiles_per_task": TENTH_TRANCHE_PROFILE_COUNT,
        "base_cumulative_fixture_count": NINTH_PREFIX_FIXTURE_COUNT,
        "added_fixture_count": TENTH_TRANCHE_ADDED_FIXTURE_COUNT,
        "cumulative_fixture_count": TENTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT,
        "profile_sha256": [
            profile.profile_sha256
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        ],
        "family_task_counts": {
            family: sum(
                task.family_id == family for task in registry.added_tasks
            )
            for family in TENTH_TRANCHE_FAMILY_ORDER
        },
        "family_fixture_counts": {
            family: sum(
                task.family_id == family for task in registry.added_tasks
            )
            * TENTH_TRANCHE_PROFILE_COUNT
            for family in TENTH_TRANCHE_FAMILY_ORDER
        },
        "family_generators": [
            {
                "family_id": COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_FAMILY_ID,
                "generator_version": (
                    COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_GENERATOR_VERSION
                ),
                "semantic_verifier_identity": (
                    COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_VERIFIER_IDENTITY
                ),
                "output_maximum_bytes": (
                    COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_MAXIMUM_ARCHIVE_BYTES
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
    registry: TenthTrancheTaskRegistry,
    bundles: tuple[TenthTrancheFixtureBundle, ...],
) -> str:
    return domain_sha256(
        "cbds.executable-fixture.tenth-tranche-catalog.v1",
        _catalog_payload(registry, bundles),
    )


def compute_tenth_tranche_fixture_catalog_sha256(
    registry: TenthTrancheTaskRegistry,
    bundles: tuple[TenthTrancheFixtureBundle, ...],
) -> str:
    selected_registry, selected_bundles = _validate_inputs(
        registry, bundles, regenerate=True
    )
    return _catalog_digest(selected_registry, selected_bundles)


@dataclass(frozen=True, slots=True)
class TenthTrancheFixtureCatalog:
    registry: TenthTrancheTaskRegistry = field(repr=False)
    bundles: tuple[TenthTrancheFixtureBundle, ...] = field(repr=False)
    catalog_sha256: str
    schema_version: str = TENTH_TRANCHE_CATALOG_SCHEMA_VERSION
    catalog_version: str = TENTH_TRANCHE_CATALOG_VERSION
    base_fixture_catalog_sha256: str = FROZEN_NINTH_CATALOG_SHA256
    public_method_development: bool = True
    sealed: bool = False
    independent_human_review_attested: bool = False
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_tenth_tranche_fixture_catalog(self)

    def to_hash_only_record(self) -> dict[str, object]:
        _validate_catalog_snapshot(self)
        return {
            **_catalog_payload(self.registry, self.bundles),
            "catalog_sha256": self.catalog_sha256,
        }


def _validate_metadata(
    catalog: object,
) -> TenthTrancheFixtureCatalog:
    if type(catalog) is not TenthTrancheFixtureCatalog:
        raise TenthTrancheFixtureCatalogError(
            "catalog must be an exact TenthTrancheFixtureCatalog"
        )
    if (
        catalog.schema_version != TENTH_TRANCHE_CATALOG_SCHEMA_VERSION
        or catalog.catalog_version != TENTH_TRANCHE_CATALOG_VERSION
        or not _is_sha256(catalog.base_fixture_catalog_sha256)
        or catalog.base_fixture_catalog_sha256
        != FROZEN_NINTH_CATALOG_SHA256
        or not _is_sha256(catalog.catalog_sha256)
        or catalog.public_method_development is not True
        or catalog.sealed is not False
        or catalog.independent_human_review_attested is not False
        or catalog.candidate_execution_authorized is not False
        or catalog.model_selection_eligible is not False
        or catalog.claim_authorized is not False
    ):
        raise TenthTrancheFixtureCatalogError(
            "tenth-tranche catalog metadata is invalid"
        )
    return catalog


def validate_tenth_tranche_fixture_catalog(
    catalog: TenthTrancheFixtureCatalog,
) -> None:
    selected = _validate_metadata(catalog)
    registry, bundles = _validate_inputs(
        selected.registry, selected.bundles, regenerate=True
    )
    if selected.catalog_sha256 != _catalog_digest(registry, bundles):
        raise TenthTrancheFixtureCatalogError(
            "tenth-tranche catalog digest is invalid"
        )


def _validate_catalog_snapshot(
    catalog: TenthTrancheFixtureCatalog,
) -> None:
    selected = _validate_metadata(catalog)
    registry, bundles = _validate_inputs(
        selected.registry, selected.bundles, regenerate=False
    )
    if selected.catalog_sha256 != _catalog_digest(registry, bundles):
        raise TenthTrancheFixtureCatalogError(
            "tenth-tranche catalog digest is invalid"
        )


def verify_tenth_tranche_fixture_catalog(catalog: object) -> bool:
    try:
        validate_tenth_tranche_fixture_catalog(
            catalog  # type: ignore[arg-type]
        )
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def _validate_live_base_and_global_uniqueness(
    registry: TenthTrancheTaskRegistry,
    bundles: tuple[TenthTrancheFixtureBundle, ...],
    evidence: NinthPrefixFixtureEvidence,
) -> None:
    """Admit the exact ninth prefix and reject all cross-chain collisions."""

    try:
        validate_ninth_prefix_fixture_evidence(evidence)
    except (AttributeError, TypeError, ValueError) as exc:
        raise TenthTrancheFixtureCatalogError(
            "through-ninth fixture evidence could not be established"
        ) from exc
    if (
        evidence.total_fixture_count != NINTH_PREFIX_FIXTURE_COUNT
        or evidence.terminal_catalog_sha256
        != FROZEN_NINTH_CATALOG_SHA256
        or evidence.task_evidence.terminal_registry_sha256
        != FROZEN_NINTH_REGISTRY_SHA256
        or evidence.task_evidence.terminal_cumulative_suite_sha256
        != FROZEN_NINTH_CUMULATIVE_SUITE_SHA256
        or registry.base_added_registry_sha256
        != evidence.task_evidence.terminal_registry_sha256
        or registry.base_cumulative_suite_sha256
        != evidence.task_evidence.terminal_cumulative_suite_sha256
    ):
        raise TenthTrancheFixtureCatalogError(
            "a live predecessor differs from its frozen ninth identity"
        )
    all_bundles = (*evidence.bundles, *bundles)
    if (
        len(all_bundles) != TENTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT
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
        raise TenthTrancheFixtureCatalogError(
            "tenth-tranche fixtures collide with a frozen predecessor"
        )
    if any(
        bundle is predecessor
        for bundle in bundles
        for predecessor in evidence.bundles
    ):
        raise TenthTrancheFixtureCatalogError(
            "tenth-tranche fixtures must be freshly owned additions"
        )


def build_tenth_tranche_fixture_catalog_local(
    registry: TenthTrancheTaskRegistry,
) -> TenthTrancheFixtureCatalog:
    """Build only tenth-tranche bundles without predecessor reconstruction."""

    if type(registry) is not TenthTrancheTaskRegistry:
        raise TypeError("registry must be an exact TenthTrancheTaskRegistry")
    validate_tenth_tranche_task_registry(registry)
    bundles = tuple(
        _build_bundle(task, profile)
        for task in registry.added_tasks
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
    )
    selected_registry, selected_bundles = _validate_inputs(
        registry, bundles, regenerate=False
    )
    digest = _catalog_digest(selected_registry, selected_bundles)

    catalog = object.__new__(TenthTrancheFixtureCatalog)
    values: dict[str, object] = {
        "registry": selected_registry,
        "bundles": selected_bundles,
        "catalog_sha256": digest,
        "schema_version": TENTH_TRANCHE_CATALOG_SCHEMA_VERSION,
        "catalog_version": TENTH_TRANCHE_CATALOG_VERSION,
        "base_fixture_catalog_sha256": FROZEN_NINTH_CATALOG_SHA256,
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


def build_tenth_tranche_fixture_catalog(
    registry: TenthTrancheTaskRegistry | None = None,
) -> TenthTrancheFixtureCatalog:
    """Build the tenth catalog over one shared through-ninth snapshot."""

    task_evidence = build_ninth_prefix_task_evidence()
    validate_ninth_prefix_task_evidence(task_evidence)
    live_registry = build_tenth_tranche_task_registry(task_evidence)
    selected_registry = (
        live_registry if registry is None else registry
    )
    if type(selected_registry) is not TenthTrancheTaskRegistry:
        raise TypeError("registry must be an exact TenthTrancheTaskRegistry")
    validate_tenth_tranche_task_registry(selected_registry)
    if selected_registry != live_registry:
        raise TenthTrancheFixtureCatalogError(
            "supplied registry differs from the live collision-checked addition"
        )
    fixture_evidence = build_ninth_prefix_fixture_evidence(task_evidence)
    catalog = build_tenth_tranche_fixture_catalog_local(selected_registry)
    _validate_live_base_and_global_uniqueness(
        selected_registry, catalog.bundles, fixture_evidence
    )
    return catalog


__all__ = [
    "FROZEN_NINTH_CATALOG_SHA256",
    "TENTH_TRANCHE_ADDED_FIXTURE_COUNT",
    "TENTH_TRANCHE_CATALOG_SCHEMA_VERSION",
    "TENTH_TRANCHE_CATALOG_VERSION",
    "TENTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT",
    "TENTH_TRANCHE_FIXTURE_COUNT",
    "TENTH_TRANCHE_PROFILE_COUNT",
    "TenthTrancheFixtureBundle",
    "TenthTrancheFixtureCatalog",
    "TenthTrancheFixtureCatalogError",
    "build_tenth_tranche_fixture_catalog",
    "build_tenth_tranche_fixture_catalog_local",
    "compute_tenth_tranche_fixture_catalog_sha256",
    "validate_tenth_tranche_fixture_catalog",
    "verify_tenth_tranche_fixture_catalog",
]
