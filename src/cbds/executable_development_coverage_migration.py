"""Auditable migration evidence from development coverage v1 to v2.

The migration changes exactly one of 25 family declarations.  It records why
the exploratory hardlink grid could not be promoted as written, proves that
the other 24 family records are byte-semantically unchanged, and binds the
implemented ninth registry and its 20 distinct fixture-oracle-derived
signatures.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
from typing import Final

from . import executable_development_coverage as coverage_v1
from . import executable_development_coverage_v2 as coverage_v2
from .executable_development_coverage import CoverageParameterAxis
from .executable_static_types import domain_sha256
from .manifests import ManifestValidationError, canonical_json_bytes


COVERAGE_MIGRATION_SCHEMA_VERSION: Final[str] = "1.0.0"
COVERAGE_MIGRATION_VERSION: Final[str] = "1.0.0"
COVERAGE_MIGRATION_CONFIG_RELATIVE_PATH: Final[str] = (
    "configs/executable-method-development-coverage-v1-to-v2-migration.json"
)
MAXIMUM_COVERAGE_MIGRATION_CONFIG_BYTES: Final[int] = 64 * 1024

FROZEN_COVERAGE_V2_SHA256: Final[str] = (
    "7406480a1dc06bc99d1e36fde1a328a490d6cc8d6b96ee38c924a902acbf9abd"
)
FROZEN_V1_HARDLINK_FAMILY_SHA256: Final[str] = (
    "962199c9d4bebf6fd7dee376d05e75d4b82b0b9bfd82221b2fceb378fba00ff1"
)
FROZEN_V2_HARDLINK_FAMILY_SHA256: Final[str] = (
    "e5220935eae1a67271733903252629df7b71a3fb01cc116ad9d86ce5e12738cc"
)
MIGRATION_REASON_CODES: Final[tuple[str, ...]] = (
    "redundant-equivalence-key",
    "nondeterministic-discovery-order",
    "nonorthogonal-link-policy",
    "implemented-grid-discrimination",
    "ninth-tranche-integration",
)
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")


class ExecutableDevelopmentCoverageMigrationError(ValueError):
    """Raised when the v1-to-v2 migration evidence is not exact."""


@dataclass(frozen=True, slots=True)
class ExecutableDevelopmentCoverageMigration:
    from_coverage_sha256: str
    to_coverage_sha256: str
    old_family_sha256: str
    new_family_sha256: str
    new_task_set_sha256: str
    discrimination_sha256: str
    unchanged_family_sha256: tuple[str, ...]
    migration_sha256: str
    schema_version: str = COVERAGE_MIGRATION_SCHEMA_VERSION
    migration_version: str = COVERAGE_MIGRATION_VERSION
    public_method_development: bool = True
    sealed: bool = False
    scored: bool = False
    candidate_execution_authorized: bool = False
    scored_evaluation_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_executable_development_coverage_migration(self)

    def to_hash_only_record(self) -> dict[str, object]:
        validate_executable_development_coverage_migration(self)
        return _migration_record(self)


def _axes_record(
    axes: tuple[CoverageParameterAxis, CoverageParameterAxis],
) -> list[dict[str, object]]:
    return [axis.to_record() for axis in axes]


def _migration_record(
    migration: ExecutableDevelopmentCoverageMigration,
) -> dict[str, object]:
    old_axes = (
        CoverageParameterAxis(
            "equivalence_key",
            (
                "sha256",
                "size-and-sha256",
                "mode-and-sha256",
                "declared-content-id",
            ),
        ),
        CoverageParameterAxis(
            "link_policy",
            (
                "smallest-path-owner",
                "first-discovered-owner",
                "preserve-existing-groups",
                "regular-files-only",
                "reject-cross-mode-group",
            ),
        ),
    )
    new_axes = (
        CoverageParameterAxis(
            "equivalence_key",
            (
                "sha256",
                "mode-and-sha256",
                "suffix-and-sha256",
                "declared-group-and-sha256",
            ),
        ),
        CoverageParameterAxis(
            "owner_policy",
            (
                "smallest-path",
                "largest-path",
                "oldest-mtime",
                "newest-mtime",
                "manifest-priority",
            ),
        ),
    )
    return {
        "schema_version": migration.schema_version,
        "migration_version": migration.migration_version,
        "record_type": (
            "cbds.executable-method-development-coverage-migration"
        ),
        "from": {
            "coverage_version": coverage_v1.COVERAGE_VERSION,
            "coverage_sha256": migration.from_coverage_sha256,
            "config_relative_path": (
                coverage_v1.COVERAGE_CONFIG_RELATIVE_PATH
            ),
            "config_bytes_sha256": (
                coverage_v2.PREDECESSOR_CONFIG_BYTES_SHA256
            ),
            "config_byte_count": (
                coverage_v2.PREDECESSOR_CONFIG_BYTE_COUNT
            ),
            "git_commit": coverage_v2.PREDECESSOR_GIT_COMMIT,
        },
        "to": {
            "coverage_version": coverage_v2.COVERAGE_V2_VERSION,
            "coverage_sha256": migration.to_coverage_sha256,
            "config_relative_path": (
                coverage_v2.COVERAGE_V2_CONFIG_RELATIVE_PATH
            ),
        },
        "changed_family_count": 1,
        "unchanged_family_count": 24,
        "changed_family_id": "hardlink-deduplicated-mirror",
        "old_lifecycle_state": "planned",
        "new_lifecycle_state": "integrated",
        "old_family_sha256": migration.old_family_sha256,
        "new_family_sha256": migration.new_family_sha256,
        "old_parameter_axes": _axes_record(old_axes),
        "new_parameter_axes": _axes_record(new_axes),
        "new_task_set_sha256": migration.new_task_set_sha256,
        "discrimination_sha256": migration.discrimination_sha256,
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


def compute_executable_development_coverage_migration_sha256(
    record: object,
) -> str:
    if type(record) is not dict:
        raise ExecutableDevelopmentCoverageMigrationError(
            "migration hash input must be an exact object"
        )
    payload = dict(record)
    payload.pop("migration_sha256", None)
    return domain_sha256(
        "cbds.executable-method-development-coverage.migration.v1",
        payload,
    )


def _expected_values() -> tuple[
    tuple[str, ...],
    str,
    str,
    str,
]:
    old_families, _old_sources = coverage_v2._linear_v1_components()
    new_coverage = coverage_v2.build_executable_development_coverage_v2()
    if new_coverage.coverage_sha256 != FROZEN_COVERAGE_V2_SHA256:
        raise ExecutableDevelopmentCoverageMigrationError(
            "live v2 coverage differs from the frozen migration target"
        )
    index = coverage_v2.HARDLINK_FAMILY_INDEX
    old_family = old_families[index]
    new_family = new_coverage.families[index]
    if (
        old_family.family_sha256 != FROZEN_V1_HARDLINK_FAMILY_SHA256
        or new_family.family_sha256 != FROZEN_V2_HARDLINK_FAMILY_SHA256
        or old_family.lifecycle_state != "planned"
        or new_family.lifecycle_state != "integrated"
    ):
        raise ExecutableDevelopmentCoverageMigrationError(
            "hardlink family identities differ from the migration lock"
        )
    unchanged: list[str] = []
    for family_index, (old, new) in enumerate(
        zip(old_families, new_coverage.families, strict=True)
    ):
        if family_index == index:
            if old == new:
                raise ExecutableDevelopmentCoverageMigrationError(
                    "changed hardlink family is unexpectedly identical"
                )
            continue
        if old != new:
            raise ExecutableDevelopmentCoverageMigrationError(
                "a family outside the hardlink migration changed"
            )
        unchanged.append(old.family_sha256)
    if len(unchanged) != 24 or len(set(unchanged)) != 24:
        raise ExecutableDevelopmentCoverageMigrationError(
            "unchanged-family evidence is incomplete"
        )
    return (
        tuple(unchanged),
        old_family.family_sha256,
        new_family.family_sha256,
        new_coverage.hardlink_discrimination_sha256,
    )


def validate_executable_development_coverage_migration(
    migration: ExecutableDevelopmentCoverageMigration,
) -> None:
    if type(migration) is not ExecutableDevelopmentCoverageMigration:
        raise ExecutableDevelopmentCoverageMigrationError(
            "migration must have its exact type"
        )
    if (
        migration.schema_version != COVERAGE_MIGRATION_SCHEMA_VERSION
        or migration.migration_version != COVERAGE_MIGRATION_VERSION
        or migration.public_method_development is not True
        or migration.sealed is not False
        or migration.scored is not False
        or migration.candidate_execution_authorized is not False
        or migration.scored_evaluation_authorized is not False
        or migration.model_selection_eligible is not False
        or migration.claim_authorized is not False
    ):
        raise ExecutableDevelopmentCoverageMigrationError(
            "migration metadata or authority boundary is invalid"
        )
    unchanged, old_family, new_family, discrimination = _expected_values()
    if (
        migration.from_coverage_sha256
        != coverage_v2.PREDECESSOR_COVERAGE_SHA256
        or migration.to_coverage_sha256 != FROZEN_COVERAGE_V2_SHA256
        or migration.old_family_sha256 != old_family
        or migration.new_family_sha256 != new_family
        or migration.new_task_set_sha256
        != coverage_v2.FROZEN_HARDLINK_TASK_SET_SHA256
        or migration.discrimination_sha256 != discrimination
        or type(migration.unchanged_family_sha256) is not tuple
        or migration.unchanged_family_sha256 != unchanged
        or any(
            not (type(value) is str and _SHA256_RE.fullmatch(value))
            for value in (
                migration.from_coverage_sha256,
                migration.to_coverage_sha256,
                migration.old_family_sha256,
                migration.new_family_sha256,
                migration.new_task_set_sha256,
                migration.discrimination_sha256,
                *migration.unchanged_family_sha256,
            )
        )
    ):
        raise ExecutableDevelopmentCoverageMigrationError(
            "migration identities differ from live v1/v2 evidence"
        )
    record = _migration_record(migration)
    if (
        type(migration.migration_sha256) is not str
        or _SHA256_RE.fullmatch(migration.migration_sha256) is None
        or migration.migration_sha256
        != compute_executable_development_coverage_migration_sha256(record)
    ):
        raise ExecutableDevelopmentCoverageMigrationError(
            "migration digest is invalid"
        )


def build_executable_development_coverage_migration(
) -> ExecutableDevelopmentCoverageMigration:
    unchanged, old_family, new_family, discrimination = _expected_values()
    provisional = ExecutableDevelopmentCoverageMigration.__new__(
        ExecutableDevelopmentCoverageMigration
    )
    values: dict[str, object] = {
        "from_coverage_sha256": (
            coverage_v2.PREDECESSOR_COVERAGE_SHA256
        ),
        "to_coverage_sha256": FROZEN_COVERAGE_V2_SHA256,
        "old_family_sha256": old_family,
        "new_family_sha256": new_family,
        "new_task_set_sha256": (
            coverage_v2.FROZEN_HARDLINK_TASK_SET_SHA256
        ),
        "discrimination_sha256": discrimination,
        "unchanged_family_sha256": unchanged,
        "migration_sha256": "0" * 64,
        "schema_version": COVERAGE_MIGRATION_SCHEMA_VERSION,
        "migration_version": COVERAGE_MIGRATION_VERSION,
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
        compute_executable_development_coverage_migration_sha256(
            _migration_record(provisional)
        )
    )
    return ExecutableDevelopmentCoverageMigration(
        from_coverage_sha256=coverage_v2.PREDECESSOR_COVERAGE_SHA256,
        to_coverage_sha256=FROZEN_COVERAGE_V2_SHA256,
        old_family_sha256=old_family,
        new_family_sha256=new_family,
        new_task_set_sha256=coverage_v2.FROZEN_HARDLINK_TASK_SET_SHA256,
        discrimination_sha256=discrimination,
        unchanged_family_sha256=unchanged,
        migration_sha256=digest,
    )


def _reject_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ExecutableDevelopmentCoverageMigrationError(
                "migration JSON contains a duplicate object key"
            )
        result[key] = value
    return result


def load_executable_development_coverage_migration(
    path: str | os.PathLike[str],
) -> ExecutableDevelopmentCoverageMigration:
    """Load only the exact canonical checked migration projection."""

    try:
        source = Path(os.fspath(path))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ExecutableDevelopmentCoverageMigrationError(
            "migration config path is invalid"
        ) from exc
    try:
        payload = coverage_v2._read_stable_regular(
            source,
            MAXIMUM_COVERAGE_MIGRATION_CONFIG_BYTES,
        )
    except coverage_v2.ExecutableDevelopmentCoverageV2Error as exc:
        raise ExecutableDevelopmentCoverageMigrationError(
            "cannot read migration as a stable regular file"
        ) from exc
    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ExecutableDevelopmentCoverageMigrationError(
                    "migration JSON contains non-finite number "
                    f"{token}"
                )
            ),
        )
        canonical = canonical_json_bytes(value) + b"\n"
    except ExecutableDevelopmentCoverageMigrationError:
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
        raise ExecutableDevelopmentCoverageMigrationError(
            "migration config is not strict canonical JSON"
        ) from exc
    if payload != canonical:
        raise ExecutableDevelopmentCoverageMigrationError(
            "migration config is not canonical JSON plus LF"
        )
    expected = build_executable_development_coverage_migration()
    if payload != (
        canonical_json_bytes(expected.to_hash_only_record()) + b"\n"
    ):
        raise ExecutableDevelopmentCoverageMigrationError(
            "checked migration differs from the central projection"
        )
    return expected


def executable_development_coverage_migration_config_bytes() -> bytes:
    return (
        canonical_json_bytes(
            build_executable_development_coverage_migration().to_hash_only_record()
        )
        + b"\n"
    )


__all__ = [
    "COVERAGE_MIGRATION_CONFIG_RELATIVE_PATH",
    "COVERAGE_MIGRATION_SCHEMA_VERSION",
    "COVERAGE_MIGRATION_VERSION",
    "FROZEN_COVERAGE_V2_SHA256",
    "FROZEN_V1_HARDLINK_FAMILY_SHA256",
    "FROZEN_V2_HARDLINK_FAMILY_SHA256",
    "MAXIMUM_COVERAGE_MIGRATION_CONFIG_BYTES",
    "MIGRATION_REASON_CODES",
    "ExecutableDevelopmentCoverageMigration",
    "ExecutableDevelopmentCoverageMigrationError",
    "build_executable_development_coverage_migration",
    "compute_executable_development_coverage_migration_sha256",
    "executable_development_coverage_migration_config_bytes",
    "load_executable_development_coverage_migration",
    "validate_executable_development_coverage_migration",
]
