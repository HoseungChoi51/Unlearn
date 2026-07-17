"""Auditable migration evidence from development coverage v4 to v5.

The migration changes exactly one of 25 family values.  It proves that the
planned JSONL/CSV enrichment contract is preserved during promotion, that all
other family values are identical, and that the source and promotion records
are exact append-only extensions.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import json
import os
from pathlib import Path
import re
from typing import Final

from . import executable_development_coverage as coverage_v1
from . import executable_development_coverage_v4 as coverage_v4
from . import executable_development_coverage_v5 as coverage_v5
from .executable_development_coverage import (
    CoverageFamily,
    CoverageParameterAxis,
    SourceRegistryCommitment,
)
from .executable_static_types import domain_sha256
from .manifests import ManifestValidationError, canonical_json_bytes


COVERAGE_V4_TO_V5_MIGRATION_SCHEMA_VERSION: Final[str] = "1.0.0"
COVERAGE_V4_TO_V5_MIGRATION_VERSION: Final[str] = "1.0.0"
COVERAGE_V4_TO_V5_MIGRATION_CONFIG_RELATIVE_PATH: Final[str] = (
    "configs/executable-method-development-coverage-v4-to-v5-migration.json"
)
MAXIMUM_COVERAGE_V4_TO_V5_MIGRATION_CONFIG_BYTES: Final[int] = 64 * 1024

FROZEN_V4_JSONL_CSV_FAMILY_SHA256: Final[str] = (
    "bc13048228af8c3f819275855bfd9b9a0da76bd3b59fe3509382037ea7bf0441"
)
FROZEN_V5_JSONL_CSV_FAMILY_SHA256: Final[str] = (
    "f6865c02a7386e85e4abd1ddbfb4dc615dd016cd3738452913d0e49e6476f49d"
)
FROZEN_COVERAGE_V4_TO_V5_MIGRATION_SHA256: Final[str] = (
    "7119bbf14ae74047a555483fc7e6e3a9d74ce46cdcb741a13aa5da34a66e1cea"
)
MIGRATION_REASON_CODES: Final[tuple[str, ...]] = (
    "planned-contract-preserved",
    "canonical-grid-integration",
    "jsonl-csv-enrichment-discrimination",
    "twelfth-tranche-integration",
    "prior-promotion-history-preserved",
)

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_AUTHORITY_FALSE_FIELDS: Final[tuple[str, ...]] = (
    "sealed",
    "scored",
    "candidate_execution_authorized",
    "scored_evaluation_authorized",
    "model_selection_eligible",
    "claim_authorized",
)


class ExecutableDevelopmentCoverageV4ToV5MigrationError(ValueError):
    """Raised when the v4-to-v5 migration evidence is not exact."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class ExecutableDevelopmentCoverageV4ToV5Migration:
    from_coverage_sha256: str
    to_coverage_sha256: str
    old_family_sha256: str
    new_family_sha256: str
    preserved_promotion_history: tuple[
        coverage_v5.CoveragePromotionEvidence, ...
    ]
    promotion_evidence: coverage_v5.CoveragePromotionEvidence
    preserved_parameter_axes: tuple[
        CoverageParameterAxis, CoverageParameterAxis
    ]
    preserved_solution_track: str
    preserved_allowed_tools: tuple[str, ...]
    preserved_filesystem_schema: str
    preserved_output_contract: str
    preserved_capability_tags: tuple[str, ...]
    new_source_registry_commitment: SourceRegistryCommitment
    unchanged_family_sha256: tuple[str, ...]
    migration_sha256: str
    schema_version: str = COVERAGE_V4_TO_V5_MIGRATION_SCHEMA_VERSION
    migration_version: str = COVERAGE_V4_TO_V5_MIGRATION_VERSION
    public_method_development: bool = True
    sealed: bool = False
    scored: bool = False
    candidate_execution_authorized: bool = False
    scored_evaluation_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_executable_development_coverage_v4_to_v5_migration(self)

    def to_hash_only_record(self) -> dict[str, object]:
        validate_executable_development_coverage_v4_to_v5_migration(self)
        return _migration_record(self)


def _migration_record(
    migration: ExecutableDevelopmentCoverageV4ToV5Migration,
) -> dict[str, object]:
    return {
        "schema_version": migration.schema_version,
        "migration_version": migration.migration_version,
        "record_type": (
            "cbds.executable-method-development-coverage-v4-to-v5-migration"
        ),
        "from": {
            "coverage_version": coverage_v4.COVERAGE_V4_VERSION,
            "coverage_sha256": migration.from_coverage_sha256,
            "config_relative_path": (
                coverage_v4.COVERAGE_V4_CONFIG_RELATIVE_PATH
            ),
            "config_bytes_sha256": (
                coverage_v5.PREDECESSOR_CONFIG_BYTES_SHA256
            ),
            "config_byte_count": coverage_v5.PREDECESSOR_CONFIG_BYTE_COUNT,
            "git_commit": coverage_v5.PREDECESSOR_GIT_COMMIT,
        },
        "to": {
            "coverage_version": coverage_v5.COVERAGE_V5_VERSION,
            "coverage_sha256": migration.to_coverage_sha256,
            "config_relative_path": (
                coverage_v5.COVERAGE_V5_CONFIG_RELATIVE_PATH
            ),
        },
        "changed_family_count": 1,
        "unchanged_family_count": 24,
        "changed_family_id": "jsonl-csv-enrichment-compose",
        "old_lifecycle_state": "planned",
        "new_lifecycle_state": "integrated",
        "old_family_sha256": migration.old_family_sha256,
        "new_family_sha256": migration.new_family_sha256,
        "preserved_parameter_axes": [
            axis.to_record() for axis in migration.preserved_parameter_axes
        ],
        "preserved_solution_track": migration.preserved_solution_track,
        "preserved_allowed_tools": list(migration.preserved_allowed_tools),
        "preserved_filesystem_schema": (
            migration.preserved_filesystem_schema
        ),
        "preserved_output_contract": migration.preserved_output_contract,
        "preserved_capability_tags": list(
            migration.preserved_capability_tags
        ),
        "preserved_promotion_history": [
            evidence.to_record()
            for evidence in migration.preserved_promotion_history
        ],
        "promotion_evidence": migration.promotion_evidence.to_record(),
        "new_source_registry_commitment": (
            migration.new_source_registry_commitment.to_record()
        ),
        "reason_codes": list(MIGRATION_REASON_CODES),
        "unchanged_family_sha256": list(
            migration.unchanged_family_sha256
        ),
        "migration_sha256": migration.migration_sha256,
        "public_method_development": migration.public_method_development,
        "sealed": migration.sealed,
        "scored": migration.scored,
        "candidate_execution_authorized": (
            migration.candidate_execution_authorized
        ),
        "scored_evaluation_authorized": (
            migration.scored_evaluation_authorized
        ),
        "model_selection_eligible": migration.model_selection_eligible,
        "claim_authorized": migration.claim_authorized,
    }


def compute_executable_development_coverage_v4_to_v5_migration_sha256(
    record: object,
) -> str:
    if type(record) is not dict:
        raise ExecutableDevelopmentCoverageV4ToV5MigrationError(
            "migration hash input must be an exact object"
        )
    payload = dict(record)
    payload.pop("migration_sha256", None)
    return domain_sha256(
        "cbds.executable-method-development-coverage."
        "v4-to-v5-migration.v1",
        payload,
    )


def _preserved_contract(family: CoverageFamily) -> dict[str, object]:
    return {
        "family_id": family.family_id,
        "task_count": family.task_count,
        "parameter_axes": [
            axis.to_record() for axis in family.parameter_axes
        ],
        "solution_track": family.solution_track,
        "allowed_tools": list(family.allowed_tools),
        "filesystem_schema": family.filesystem_schema,
        "output_contract": family.output_contract,
        "capability_tags": list(family.capability_tags),
    }


@lru_cache(maxsize=1)
def _migration_component_snapshot_bytes() -> bytes:
    """Cache only canonical primitive migration evidence."""

    old_coverage = coverage_v4.build_executable_development_coverage_v4()
    new_coverage = coverage_v5.build_executable_development_coverage_v5()
    if (
        old_coverage.coverage_sha256
        != coverage_v5.PREDECESSOR_COVERAGE_SHA256
        or new_coverage.coverage_sha256
        != coverage_v5.FROZEN_COVERAGE_V5_SHA256
        or new_coverage.hardlink_discrimination_sha256
        != old_coverage.hardlink_discrimination_sha256
        or new_coverage.source_registry_commitments[:-1]
        != old_coverage.source_registry_commitments
        or len(new_coverage.source_registry_commitments)
        != len(old_coverage.source_registry_commitments) + 1
        or len(new_coverage.promotion_history) != 3
        or [
            item.to_record()
            for item in new_coverage.promotion_history[:-1]
        ]
        != [item.to_record() for item in old_coverage.promotion_history]
    ):
        raise ExecutableDevelopmentCoverageV4ToV5MigrationError(
            "live v4/v5 chain is not an exact append-only migration"
        )
    index = coverage_v5.JSONL_CSV_FAMILY_INDEX
    old_family = old_coverage.families[index]
    new_family = new_coverage.families[index]
    if (
        old_family.family_sha256
        != FROZEN_V4_JSONL_CSV_FAMILY_SHA256
        or new_family.family_sha256
        != FROZEN_V5_JSONL_CSV_FAMILY_SHA256
        or old_family.lifecycle_state != "planned"
        or new_family.lifecycle_state != "integrated"
        or old_family.integrated_task_set_sha256 is not None
        or new_family.integrated_task_set_sha256
        != coverage_v5.FROZEN_JSONL_CSV_TASK_SET_SHA256
        or _preserved_contract(old_family)
        != _preserved_contract(new_family)
    ):
        raise ExecutableDevelopmentCoverageV4ToV5MigrationError(
            "JSONL/CSV family promotion did not preserve its planned contract"
        )
    unchanged: list[str] = []
    for family_index, (old, new) in enumerate(
        zip(old_coverage.families, new_coverage.families, strict=True)
    ):
        if family_index == index:
            if old == new:
                raise ExecutableDevelopmentCoverageV4ToV5MigrationError(
                    "changed JSONL/CSV family is unexpectedly identical"
                )
            continue
        if old != new:
            raise ExecutableDevelopmentCoverageV4ToV5MigrationError(
                "a family outside the JSONL/CSV promotion changed"
            )
        unchanged.append(old.family_sha256)
    if len(unchanged) != 24 or len(set(unchanged)) != 24:
        raise ExecutableDevelopmentCoverageV4ToV5MigrationError(
            "unchanged-family evidence is incomplete"
        )
    return canonical_json_bytes(
        {
            "old_family": old_family.to_record(),
            "new_family": new_family.to_record(),
            "preserved_promotion_history": [
                item.to_record()
                for item in new_coverage.promotion_history[:-1]
            ],
            "promotion_evidence": (
                new_coverage.promotion_history[-1].to_record()
            ),
            "new_source_registry_commitment": (
                new_coverage.source_registry_commitments[-1].to_record()
            ),
            "unchanged_family_sha256": unchanged,
        }
    )


def _migration_components() -> tuple[
    CoverageFamily,
    CoverageFamily,
    tuple[
        coverage_v5.CoveragePromotionEvidence,
        coverage_v5.CoveragePromotionEvidence,
    ],
    coverage_v5.CoveragePromotionEvidence,
    SourceRegistryCommitment,
    tuple[str, ...],
]:
    try:
        snapshot = json.loads(_migration_component_snapshot_bytes())
        if type(snapshot) is not dict:
            raise TypeError("snapshot must be an object")
        old_family = coverage_v1._family_from_record(snapshot["old_family"])
        new_family = coverage_v1._family_from_record(snapshot["new_family"])
        history_value = snapshot["preserved_promotion_history"]
        if type(history_value) is not list or len(history_value) != 2:
            raise TypeError("preserved history must contain two entries")
        history = tuple(
            coverage_v5._promotion_from_record(item)
            for item in history_value
        )
        promotion = coverage_v5._promotion_from_record(
            snapshot["promotion_evidence"]
        )
        source = coverage_v1._source_from_record(
            snapshot["new_source_registry_commitment"]
        )
        unchanged_value = snapshot["unchanged_family_sha256"]
        if (
            type(unchanged_value) is not list
            or any(type(value) is not str for value in unchanged_value)
        ):
            raise TypeError("unchanged evidence must be a string list")
        unchanged = tuple(unchanged_value)
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise ExecutableDevelopmentCoverageV4ToV5MigrationError(
            "internal migration snapshot cannot be reconstructed"
        ) from exc
    return (
        old_family,
        new_family,
        history,  # type: ignore[return-value]
        promotion,
        source,
        unchanged,
    )


def validate_executable_development_coverage_v4_to_v5_migration(
    migration: ExecutableDevelopmentCoverageV4ToV5Migration,
) -> None:
    if (
        type(migration)
        is not ExecutableDevelopmentCoverageV4ToV5Migration
    ):
        raise ExecutableDevelopmentCoverageV4ToV5MigrationError(
            "migration must have its exact type"
        )
    if (
        migration.schema_version
        != COVERAGE_V4_TO_V5_MIGRATION_SCHEMA_VERSION
        or migration.migration_version
        != COVERAGE_V4_TO_V5_MIGRATION_VERSION
        or migration.public_method_development is not True
        or any(
            getattr(migration, name) is not False
            for name in _AUTHORITY_FALSE_FIELDS
        )
    ):
        raise ExecutableDevelopmentCoverageV4ToV5MigrationError(
            "migration metadata or authority boundary is invalid"
        )
    old, new, history, promotion, source, unchanged = (
        _migration_components()
    )
    if (
        migration.from_coverage_sha256
        != coverage_v5.PREDECESSOR_COVERAGE_SHA256
        or migration.to_coverage_sha256
        != coverage_v5.FROZEN_COVERAGE_V5_SHA256
        or migration.old_family_sha256 != old.family_sha256
        or migration.new_family_sha256 != new.family_sha256
        or type(migration.preserved_promotion_history) is not tuple
        or migration.preserved_promotion_history != history
        or any(
            type(item) is not coverage_v5.CoveragePromotionEvidence
            for item in migration.preserved_promotion_history
        )
        or type(migration.promotion_evidence)
        is not coverage_v5.CoveragePromotionEvidence
        or migration.promotion_evidence != promotion
        or type(migration.preserved_parameter_axes) is not tuple
        or migration.preserved_parameter_axes != old.parameter_axes
        or migration.preserved_solution_track != old.solution_track
        or type(migration.preserved_allowed_tools) is not tuple
        or migration.preserved_allowed_tools != old.allowed_tools
        or migration.preserved_filesystem_schema != old.filesystem_schema
        or migration.preserved_output_contract != old.output_contract
        or type(migration.preserved_capability_tags) is not tuple
        or migration.preserved_capability_tags != old.capability_tags
        or type(migration.new_source_registry_commitment)
        is not SourceRegistryCommitment
        or migration.new_source_registry_commitment != source
        or type(migration.unchanged_family_sha256) is not tuple
        or migration.unchanged_family_sha256 != unchanged
        or any(
            not _is_sha256(value)
            for value in (
                migration.from_coverage_sha256,
                migration.to_coverage_sha256,
                migration.old_family_sha256,
                migration.new_family_sha256,
                *migration.unchanged_family_sha256,
            )
        )
    ):
        raise ExecutableDevelopmentCoverageV4ToV5MigrationError(
            "migration identities differ from live v4/v5 evidence"
        )
    for evidence in migration.preserved_promotion_history:
        evidence.__post_init__()
    migration.promotion_evidence.__post_init__()
    for axis in migration.preserved_parameter_axes:
        axis.__post_init__()
    migration.new_source_registry_commitment.__post_init__()
    record = _migration_record(migration)
    if (
        not _is_sha256(migration.migration_sha256)
        or migration.migration_sha256
        != FROZEN_COVERAGE_V4_TO_V5_MIGRATION_SHA256
        or migration.migration_sha256
        != compute_executable_development_coverage_v4_to_v5_migration_sha256(
            record
        )
    ):
        raise ExecutableDevelopmentCoverageV4ToV5MigrationError(
            "migration digest is invalid"
        )


def build_executable_development_coverage_v4_to_v5_migration(
) -> ExecutableDevelopmentCoverageV4ToV5Migration:
    old, new, history, promotion, source, unchanged = (
        _migration_components()
    )
    provisional = ExecutableDevelopmentCoverageV4ToV5Migration.__new__(
        ExecutableDevelopmentCoverageV4ToV5Migration
    )
    values: dict[str, object] = {
        "from_coverage_sha256": coverage_v5.PREDECESSOR_COVERAGE_SHA256,
        "to_coverage_sha256": coverage_v5.FROZEN_COVERAGE_V5_SHA256,
        "old_family_sha256": old.family_sha256,
        "new_family_sha256": new.family_sha256,
        "preserved_promotion_history": history,
        "promotion_evidence": promotion,
        "preserved_parameter_axes": old.parameter_axes,
        "preserved_solution_track": old.solution_track,
        "preserved_allowed_tools": old.allowed_tools,
        "preserved_filesystem_schema": old.filesystem_schema,
        "preserved_output_contract": old.output_contract,
        "preserved_capability_tags": old.capability_tags,
        "new_source_registry_commitment": source,
        "unchanged_family_sha256": unchanged,
        "migration_sha256": "0" * 64,
        "schema_version": COVERAGE_V4_TO_V5_MIGRATION_SCHEMA_VERSION,
        "migration_version": COVERAGE_V4_TO_V5_MIGRATION_VERSION,
        "public_method_development": True,
        "sealed": False,
        "scored": False,
        "candidate_execution_authorized": False,
        "scored_evaluation_authorized": False,
        "model_selection_eligible": False,
        "claim_authorized": False,
    }
    for name, value in values.items():
        object.__setattr__(provisional, name, value)
    digest = (
        compute_executable_development_coverage_v4_to_v5_migration_sha256(
            _migration_record(provisional)
        )
    )
    return ExecutableDevelopmentCoverageV4ToV5Migration(
        from_coverage_sha256=coverage_v5.PREDECESSOR_COVERAGE_SHA256,
        to_coverage_sha256=coverage_v5.FROZEN_COVERAGE_V5_SHA256,
        old_family_sha256=old.family_sha256,
        new_family_sha256=new.family_sha256,
        preserved_promotion_history=history,
        promotion_evidence=promotion,
        preserved_parameter_axes=old.parameter_axes,
        preserved_solution_track=old.solution_track,
        preserved_allowed_tools=old.allowed_tools,
        preserved_filesystem_schema=old.filesystem_schema,
        preserved_output_contract=old.output_contract,
        preserved_capability_tags=old.capability_tags,
        new_source_registry_commitment=source,
        unchanged_family_sha256=unchanged,
        migration_sha256=digest,
    )


def _reject_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ExecutableDevelopmentCoverageV4ToV5MigrationError(
                "migration JSON contains a duplicate object key"
            )
        result[key] = value
    return result


def load_executable_development_coverage_v4_to_v5_migration(
    path: str | os.PathLike[str],
) -> ExecutableDevelopmentCoverageV4ToV5Migration:
    """Load only the exact canonical checked migration projection."""

    try:
        source = Path(os.fspath(path))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ExecutableDevelopmentCoverageV4ToV5MigrationError(
            "migration config path is invalid"
        ) from exc
    try:
        payload = coverage_v5._read_stable_regular(
            source,
            MAXIMUM_COVERAGE_V4_TO_V5_MIGRATION_CONFIG_BYTES,
        )
    except coverage_v5.ExecutableDevelopmentCoverageV5Error as exc:
        raise ExecutableDevelopmentCoverageV4ToV5MigrationError(
            "cannot read migration as a stable regular file"
        ) from exc
    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ExecutableDevelopmentCoverageV4ToV5MigrationError(
                    "migration JSON contains non-finite number "
                    f"{token}"
                )
            ),
        )
        canonical = canonical_json_bytes(value) + b"\n"
    except ExecutableDevelopmentCoverageV4ToV5MigrationError:
        raise
    except (
        ManifestValidationError,
        UnicodeDecodeError,
        UnicodeEncodeError,
        json.JSONDecodeError,
        RecursionError,
        TypeError,
        ValueError,
    ) as exc:
        raise ExecutableDevelopmentCoverageV4ToV5MigrationError(
            "migration config is not strict canonical JSON"
        ) from exc
    if payload != canonical:
        raise ExecutableDevelopmentCoverageV4ToV5MigrationError(
            "migration config is not canonical JSON plus LF"
        )
    expected = (
        build_executable_development_coverage_v4_to_v5_migration()
    )
    if payload != (
        executable_development_coverage_v4_to_v5_migration_config_bytes()
    ):
        raise ExecutableDevelopmentCoverageV4ToV5MigrationError(
            "checked migration differs from the central projection"
        )
    return expected


@lru_cache(maxsize=1)
def executable_development_coverage_v4_to_v5_migration_config_bytes(
) -> bytes:
    """Return immutable canonical bytes for deterministic publication."""

    return (
        canonical_json_bytes(
            build_executable_development_coverage_v4_to_v5_migration()
            .to_hash_only_record()
        )
        + b"\n"
    )


__all__ = [
    "COVERAGE_V4_TO_V5_MIGRATION_CONFIG_RELATIVE_PATH",
    "COVERAGE_V4_TO_V5_MIGRATION_SCHEMA_VERSION",
    "COVERAGE_V4_TO_V5_MIGRATION_VERSION",
    "FROZEN_COVERAGE_V4_TO_V5_MIGRATION_SHA256",
    "FROZEN_V4_JSONL_CSV_FAMILY_SHA256",
    "FROZEN_V5_JSONL_CSV_FAMILY_SHA256",
    "MAXIMUM_COVERAGE_V4_TO_V5_MIGRATION_CONFIG_BYTES",
    "MIGRATION_REASON_CODES",
    "ExecutableDevelopmentCoverageV4ToV5Migration",
    "ExecutableDevelopmentCoverageV4ToV5MigrationError",
    "build_executable_development_coverage_v4_to_v5_migration",
    "compute_executable_development_coverage_v4_to_v5_migration_sha256",
    "executable_development_coverage_v4_to_v5_migration_config_bytes",
    "load_executable_development_coverage_v4_to_v5_migration",
    "validate_executable_development_coverage_v4_to_v5_migration",
]
