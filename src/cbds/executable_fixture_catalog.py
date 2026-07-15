"""First-tranche catalog and closed executable-family fixture dispatcher.

The catalog binds every task in one validated 100-task method-development
registry to each of the five closed public edge-case profiles.  It owns no
execution path: building and validating it only derives fixture bytes and
trusted oracle bytes in memory.  Its export is deliberately hash-only so the
private fixture and oracle contents are not disclosed by catalog metadata.
The dispatch table also serves separately hash-bound additive tranches; those
tasks never enter the immutable first-tranche registry or catalog below.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Final

from .executable_fixture_bundle import (
    ExecutableFixtureBundle,
    validate_executable_fixture_bundle,
)
from .executable_fixture_csv import build_csv_group_totals_fixture_bundle
from .executable_fixture_lines import build_executable_line_fixture_bundle
from .executable_fixture_profiles import (
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
    ExecutableFixtureProfile,
)
from .executable_fixture_records import (
    build_checksum_manifest_fixture_bundle,
    build_manifest_copy_fixture_bundle,
)
from .executable_fixture_transform import (
    build_line_transform_mirror_fixture_bundle,
)
from .executable_static_types import (
    ActiveJsonlLabelsParameters,
    ChecksumManifestParameters,
    CsvGroupTotalsParameters,
    ExecutableStaticRegistry,
    ExecutableStaticTask,
    JsonlKeyedInnerJoinParameters,
    LineTransformMirrorParameters,
    ManifestCopyParameters,
    ModeNormalizedMirrorParameters,
    OpaqueFixtureDescriptor,
    PathSuffixInventoryParameters,
    ProcSnapshotReportParameters,
    UstarSafeExtractParameters,
    domain_sha256,
)


EXECUTABLE_FIXTURE_CATALOG_SCHEMA_VERSION: Final[str] = "1.0.0"
EXECUTABLE_FIXTURE_CATALOG_VERSION: Final[str] = "1.0.0"
FIRST_TRANCHE_TASK_COUNT: Final[int] = 100
FIRST_TRANCHE_PROFILE_COUNT: Final[int] = 5
FIRST_TRANCHE_FIXTURE_COUNT: Final[int] = (
    FIRST_TRANCHE_TASK_COUNT * FIRST_TRANCHE_PROFILE_COUNT
)

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")


class ExecutableFixtureCatalogError(ValueError):
    """Raised when the closed first-tranche catalog fails validation."""


def _validate_profile(profile: object) -> ExecutableFixtureProfile:
    if type(profile) is not ExecutableFixtureProfile:
        raise ExecutableFixtureCatalogError(
            "profile must be an exact ExecutableFixtureProfile"
        )
    try:
        rebuilt = ExecutableFixtureProfile(
            profile_id=profile.profile_id,
            cases=profile.cases,
            profile_sha256=profile.profile_sha256,
            profile_version=profile.profile_version,
            public_method_development=profile.public_method_development,
            sealed=profile.sealed,
            candidate_execution_authorized=profile.candidate_execution_authorized,
            model_selection_eligible=profile.model_selection_eligible,
            claim_authorized=profile.claim_authorized,
        )
    except (TypeError, ValueError) as exc:
        raise ExecutableFixtureCatalogError(
            "profile contains invalid or forged nested values"
        ) from exc
    if rebuilt not in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
        raise ExecutableFixtureCatalogError(
            "profile is outside the closed public development profile set"
        )
    return rebuilt


def _rebuild_task(task: object) -> ExecutableStaticTask:
    if type(task) is not ExecutableStaticTask:
        raise ExecutableFixtureCatalogError(
            "source registry tasks must be exact ExecutableStaticTask values"
        )
    parameters = task.parameters
    try:
        if type(parameters) is ActiveJsonlLabelsParameters:
            rebuilt_parameters = ActiveJsonlLabelsParameters(
                label_key=parameters.label_key,
                predicate=parameters.predicate,
            )
        elif type(parameters) is ManifestCopyParameters:
            rebuilt_parameters = ManifestCopyParameters(
                selector=parameters.selector,
                collision_policy=parameters.collision_policy,
            )
        elif type(parameters) is CsvGroupTotalsParameters:
            rebuilt_parameters = CsvGroupTotalsParameters(
                layout=parameters.layout,
                predicate=parameters.predicate,
            )
        elif type(parameters) is ChecksumManifestParameters:
            rebuilt_parameters = ChecksumManifestParameters(
                layout=parameters.layout,
                policy=parameters.policy,
            )
        elif type(parameters) is PathSuffixInventoryParameters:
            rebuilt_parameters = PathSuffixInventoryParameters(
                suffix=parameters.suffix,
                maximum_depth=parameters.maximum_depth,
            )
        elif type(parameters) is LineTransformMirrorParameters:
            rebuilt_parameters = LineTransformMirrorParameters(
                suffix=parameters.suffix,
                transform=parameters.transform,
            )
        elif type(parameters) is ModeNormalizedMirrorParameters:
            rebuilt_parameters = ModeNormalizedMirrorParameters(
                selector=parameters.selector,
                normalization=parameters.normalization,
            )
        elif type(parameters) is JsonlKeyedInnerJoinParameters:
            rebuilt_parameters = JsonlKeyedInnerJoinParameters(
                key=parameters.key,
                duplicate_policy=parameters.duplicate_policy,
            )
        elif type(parameters) is UstarSafeExtractParameters:
            rebuilt_parameters = UstarSafeExtractParameters(
                selector=parameters.selector,
                conflict_policy=parameters.conflict_policy,
            )
        elif type(parameters) is ProcSnapshotReportParameters:
            rebuilt_parameters = ProcSnapshotReportParameters(
                view=parameters.view,
                predicate=parameters.predicate,
            )
        else:
            raise ValueError("parameters are outside the closed family types")

        if type(task.fixtures) is not tuple:
            raise ValueError("task fixtures are not an exact tuple")
        descriptor_values: list[OpaqueFixtureDescriptor] = []
        for descriptor in task.fixtures:
            if type(descriptor) is not OpaqueFixtureDescriptor:
                raise ValueError("task fixture is not an exact opaque descriptor")
            descriptor_values.append(
                OpaqueFixtureDescriptor(
                    fixture_id=descriptor.fixture_id,
                    fixture_sha256=descriptor.fixture_sha256,
                    task_contract_sha256=descriptor.task_contract_sha256,
                    schema_version=descriptor.schema_version,
                )
            )
        descriptors = tuple(descriptor_values)
        return ExecutableStaticTask(
            task_id=task.task_id,
            family_id=task.family_id,
            family_version=task.family_version,
            parameters=rebuilt_parameters,
            prompt=task.prompt,
            graph=task.graph,
            filesystem_identity=task.filesystem_identity,
            output_identity=task.output_identity,
            allowed_tools=task.allowed_tools,
            fixtures=descriptors,
            task_contract_sha256=task.task_contract_sha256,
            split_role=task.split_role,
            public=task.public,
            sealed=task.sealed,
            claim_authorized=task.claim_authorized,
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise ExecutableFixtureCatalogError(
            "source task contains invalid or forged nested values"
        ) from exc


def _validate_source_registry(registry: object) -> ExecutableStaticRegistry:
    if type(registry) is not ExecutableStaticRegistry:
        raise ExecutableFixtureCatalogError(
            "source_registry must be an exact ExecutableStaticRegistry"
        )
    if type(registry.tasks) is not tuple:
        raise ExecutableFixtureCatalogError(
            "source registry tasks must be an exact tuple"
        )
    rebuilt_tasks = tuple(_rebuild_task(task) for task in registry.tasks)
    try:
        rebuilt = ExecutableStaticRegistry(
            tasks=rebuilt_tasks,
            registry_sha256=registry.registry_sha256,
            suite_sha256=registry.suite_sha256,
            schema_version=registry.schema_version,
            split_role=registry.split_role,
            public=registry.public,
            sealed=registry.sealed,
            claim_authorized=registry.claim_authorized,
        )
    except (TypeError, ValueError) as exc:
        raise ExecutableFixtureCatalogError(
            "source registry is not a valid 100-task public development registry"
        ) from exc
    if rebuilt.tasks != registry.tasks:
        raise ExecutableFixtureCatalogError(
            "source registry task reconstruction changed its content"
        )
    return rebuilt


def build_fixture_bundle_for_task_profile(
    task: ExecutableStaticTask,
    profile: ExecutableFixtureProfile,
) -> ExecutableFixtureBundle:
    """Dispatch one exact task/profile pair through the closed family table."""

    rebuilt_task = _rebuild_task(task)
    rebuilt_profile = _validate_profile(profile)
    try:
        if (
            rebuilt_task.family_id == "active-jsonl-labels"
            and type(rebuilt_task.parameters) is ActiveJsonlLabelsParameters
        ):
            bundle = build_executable_line_fixture_bundle(
                rebuilt_task, rebuilt_profile
            )
        elif (
            rebuilt_task.family_id == "manifest-copy"
            and type(rebuilt_task.parameters) is ManifestCopyParameters
        ):
            bundle = build_manifest_copy_fixture_bundle(
                rebuilt_task, rebuilt_profile
            )
        elif (
            rebuilt_task.family_id == "csv-group-totals"
            and type(rebuilt_task.parameters) is CsvGroupTotalsParameters
        ):
            bundle = build_csv_group_totals_fixture_bundle(
                rebuilt_task, rebuilt_profile
            )
        elif (
            rebuilt_task.family_id == "checksum-manifest"
            and type(rebuilt_task.parameters) is ChecksumManifestParameters
        ):
            bundle = build_checksum_manifest_fixture_bundle(
                rebuilt_task, rebuilt_profile
            )
        elif (
            rebuilt_task.family_id == "path-suffix-inventory"
            and type(rebuilt_task.parameters) is PathSuffixInventoryParameters
        ):
            bundle = build_executable_line_fixture_bundle(
                rebuilt_task, rebuilt_profile
            )
        elif (
            rebuilt_task.family_id == "line-transform-mirror"
            and type(rebuilt_task.parameters) is LineTransformMirrorParameters
        ):
            bundle = build_line_transform_mirror_fixture_bundle(
                rebuilt_task, rebuilt_profile
            )
        elif (
            rebuilt_task.family_id == "mode-normalized-mirror"
            and type(rebuilt_task.parameters) is ModeNormalizedMirrorParameters
        ):
            from .executable_fixture_mode_mirror import (
                build_mode_normalized_mirror_fixture_bundle,
            )

            bundle = build_mode_normalized_mirror_fixture_bundle(
                rebuilt_task, rebuilt_profile
            )
        elif (
            rebuilt_task.family_id == "jsonl-keyed-inner-join"
            and type(rebuilt_task.parameters) is JsonlKeyedInnerJoinParameters
        ):
            from .executable_fixture_join import (
                build_jsonl_keyed_inner_join_fixture_bundle,
            )

            bundle = build_jsonl_keyed_inner_join_fixture_bundle(
                rebuilt_task, rebuilt_profile
            )
        elif (
            rebuilt_task.family_id == "ustar-safe-extract"
            and type(rebuilt_task.parameters) is UstarSafeExtractParameters
        ):
            from .executable_fixture_ustar import (
                build_ustar_safe_extract_fixture_bundle,
            )

            bundle = build_ustar_safe_extract_fixture_bundle(
                rebuilt_task, rebuilt_profile
            )
        elif (
            rebuilt_task.family_id == "proc-snapshot-report"
            and type(rebuilt_task.parameters) is ProcSnapshotReportParameters
        ):
            from .executable_fixture_proc_snapshot import (
                build_proc_snapshot_report_fixture_bundle,
            )

            bundle = build_proc_snapshot_report_fixture_bundle(
                rebuilt_task, rebuilt_profile
            )
        else:
            raise ExecutableFixtureCatalogError(
                "task family and parameter type are outside the dispatch table"
            )
        validate_executable_fixture_bundle(bundle)
    except (TypeError, ValueError) as exc:
        if isinstance(exc, ExecutableFixtureCatalogError):
            raise
        raise ExecutableFixtureCatalogError(
            "family fixture generator rejected the task/profile pair"
        ) from exc
    if (
        bundle.task_contract_sha256 != rebuilt_task.task_contract_sha256
        or bundle.profile_sha256 != rebuilt_profile.profile_sha256
        or bundle.descriptor.task_contract_sha256
        != rebuilt_task.task_contract_sha256
    ):
        raise ExecutableFixtureCatalogError(
            "generated bundle is not bound to the requested task/profile pair"
        )
    return bundle


def _entry_hash_record(bundle: ExecutableFixtureBundle) -> dict[str, str]:
    return {
        "task_contract_sha256": bundle.task_contract_sha256,
        "profile_sha256": bundle.profile_sha256,
        "fixture_definition_sha256": bundle.fixture_definition_sha256,
        "trusted_oracle_sha256": bundle.oracle.oracle_sha256,
        "fixture_sha256": bundle.descriptor.fixture_sha256,
    }


def _catalog_hash_payload(
    source_registry: ExecutableStaticRegistry,
    bundles: tuple[ExecutableFixtureBundle, ...],
) -> dict[str, object]:
    return {
        "schema_version": EXECUTABLE_FIXTURE_CATALOG_SCHEMA_VERSION,
        "catalog_version": EXECUTABLE_FIXTURE_CATALOG_VERSION,
        "source_registry_sha256": source_registry.registry_sha256,
        "source_suite_sha256": source_registry.suite_sha256,
        "task_count": FIRST_TRANCHE_TASK_COUNT,
        "profiles_per_task": FIRST_TRANCHE_PROFILE_COUNT,
        "fixture_count": FIRST_TRANCHE_FIXTURE_COUNT,
        "profile_sha256": [
            profile.profile_sha256
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        ],
        "fixtures": [_entry_hash_record(bundle) for bundle in bundles],
        "public_method_development": True,
        "sealed": False,
        "candidate_execution_authorized": False,
        "model_selection_eligible": False,
        "claim_authorized": False,
    }


def _compute_catalog_sha256_unchecked(
    source_registry: ExecutableStaticRegistry,
    bundles: tuple[ExecutableFixtureBundle, ...],
) -> str:
    return domain_sha256(
        "cbds.executable-fixture.first-tranche-catalog.v1",
        _catalog_hash_payload(source_registry, bundles),
    )


def _validate_catalog_inputs(
    source_registry: object,
    bundles: object,
) -> tuple[ExecutableStaticRegistry, tuple[ExecutableFixtureBundle, ...]]:
    registry = _validate_source_registry(source_registry)
    if type(bundles) is not tuple or any(
        type(bundle) is not ExecutableFixtureBundle for bundle in bundles
    ):
        raise ExecutableFixtureCatalogError(
            "bundles must be an exact tuple of ExecutableFixtureBundle values"
        )
    if len(bundles) != FIRST_TRANCHE_FIXTURE_COUNT:
        raise ExecutableFixtureCatalogError(
            "first-tranche catalog must contain exactly 500 bundles"
        )

    fixture_ids: set[str] = set()
    fixture_hashes: set[str] = set()
    for index, bundle in enumerate(bundles):
        task = registry.tasks[index // FIRST_TRANCHE_PROFILE_COUNT]
        profile_index = index % FIRST_TRANCHE_PROFILE_COUNT
        profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[profile_index]
        validate_executable_fixture_bundle(bundle)
        if (
            bundle.task_contract_sha256 != task.task_contract_sha256
            or bundle.profile_sha256 != profile.profile_sha256
        ):
            raise ExecutableFixtureCatalogError(
                "catalog bundle order is not task-major/profile-minor canonical order"
            )
        expected = build_fixture_bundle_for_task_profile(task, profile)
        if bundle != expected:
            raise ExecutableFixtureCatalogError(
                "catalog bundle differs from deterministic family generation"
            )
        if task.fixtures[profile_index] != bundle.descriptor:
            raise ExecutableFixtureCatalogError(
                "source registry fixture descriptor is not content-bound to the catalog"
            )
        if (
            bundle.candidate_execution_authorized is not False
            or bundle.model_selection_eligible is not False
            or bundle.claim_authorized is not False
        ):
            raise ExecutableFixtureCatalogError(
                "catalog bundle crosses its authority boundary"
            )
        fixture_ids.add(bundle.descriptor.fixture_id)
        fixture_hashes.add(bundle.descriptor.fixture_sha256)
    if (
        len(fixture_ids) != FIRST_TRANCHE_FIXTURE_COUNT
        or len(fixture_hashes) != FIRST_TRANCHE_FIXTURE_COUNT
    ):
        raise ExecutableFixtureCatalogError(
            "catalog fixture identities are not globally unique"
        )
    return registry, bundles


def compute_first_tranche_fixture_catalog_sha256(
    source_registry: ExecutableStaticRegistry,
    bundles: tuple[ExecutableFixtureBundle, ...],
) -> str:
    """Validate and hash the complete private catalog without exposing bytes."""

    registry, selected = _validate_catalog_inputs(source_registry, bundles)
    return _compute_catalog_sha256_unchecked(registry, selected)


@dataclass(frozen=True, slots=True)
class FirstTrancheFixtureCatalog:
    """Private validated 500-bundle catalog with a hash-only projection."""

    source_registry: ExecutableStaticRegistry = field(repr=False)
    bundles: tuple[ExecutableFixtureBundle, ...] = field(repr=False)
    catalog_sha256: str
    schema_version: str = EXECUTABLE_FIXTURE_CATALOG_SCHEMA_VERSION
    catalog_version: str = EXECUTABLE_FIXTURE_CATALOG_VERSION
    public_method_development: bool = True
    sealed: bool = False
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        _validate_first_tranche_fixture_catalog_fields(self)

    def to_hash_only_record(self) -> dict[str, object]:
        """Return commitments and authority flags, never fixture/oracle bytes."""

        validate_first_tranche_fixture_catalog(self)
        return {
            "record_type": "cbds.executable-fixture-first-tranche-catalog",
            **_catalog_hash_payload(self.source_registry, self.bundles),
            "catalog_sha256": self.catalog_sha256,
        }


def _validate_first_tranche_fixture_catalog_fields(
    catalog: FirstTrancheFixtureCatalog,
) -> None:
    if type(catalog) is not FirstTrancheFixtureCatalog:
        raise ExecutableFixtureCatalogError(
            "catalog must be an exact FirstTrancheFixtureCatalog"
        )
    if catalog.schema_version != EXECUTABLE_FIXTURE_CATALOG_SCHEMA_VERSION:
        raise ExecutableFixtureCatalogError("catalog schema_version is unsupported")
    if catalog.catalog_version != EXECUTABLE_FIXTURE_CATALOG_VERSION:
        raise ExecutableFixtureCatalogError("catalog_version is unsupported")
    if (
        catalog.public_method_development is not True
        or catalog.sealed is not False
        or catalog.candidate_execution_authorized is not False
        or catalog.model_selection_eligible is not False
        or catalog.claim_authorized is not False
    ):
        raise ExecutableFixtureCatalogError(
            "catalog cannot authorize execution, model selection, or claims"
        )
    if type(catalog.catalog_sha256) is not str or _SHA256_RE.fullmatch(
        catalog.catalog_sha256
    ) is None:
        raise ExecutableFixtureCatalogError(
            "catalog_sha256 must be a lowercase SHA-256"
        )
    registry, bundles = _validate_catalog_inputs(
        catalog.source_registry, catalog.bundles
    )
    expected = _compute_catalog_sha256_unchecked(registry, bundles)
    if catalog.catalog_sha256 != expected:
        raise ExecutableFixtureCatalogError(
            "catalog_sha256 does not match catalog content"
        )


def validate_first_tranche_fixture_catalog(
    catalog: FirstTrancheFixtureCatalog,
) -> None:
    """Revalidate all nested values, generation bindings, order, and hashes."""

    _validate_first_tranche_fixture_catalog_fields(catalog)


def verify_first_tranche_fixture_catalog(catalog: object) -> bool:
    """Return whether a value is the exact closed first-tranche catalog."""

    try:
        validate_first_tranche_fixture_catalog(catalog)  # type: ignore[arg-type]
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def build_first_tranche_fixture_catalog(
    source_registry: ExecutableStaticRegistry,
) -> FirstTrancheFixtureCatalog:
    """Build all 100 tasks by five profiles without executing candidate code."""

    registry = _validate_source_registry(source_registry)
    bundles = tuple(
        build_fixture_bundle_for_task_profile(task, profile)
        for task in registry.tasks
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
    )
    digest = _compute_catalog_sha256_unchecked(registry, bundles)
    return FirstTrancheFixtureCatalog(
        source_registry=registry,
        bundles=bundles,
        catalog_sha256=digest,
    )


__all__ = [
    "EXECUTABLE_FIXTURE_CATALOG_SCHEMA_VERSION",
    "EXECUTABLE_FIXTURE_CATALOG_VERSION",
    "FIRST_TRANCHE_FIXTURE_COUNT",
    "FIRST_TRANCHE_PROFILE_COUNT",
    "FIRST_TRANCHE_TASK_COUNT",
    "ExecutableFixtureCatalogError",
    "FirstTrancheFixtureCatalog",
    "build_first_tranche_fixture_catalog",
    "build_fixture_bundle_for_task_profile",
    "compute_first_tranche_fixture_catalog_sha256",
    "validate_first_tranche_fixture_catalog",
    "verify_first_tranche_fixture_catalog",
]
