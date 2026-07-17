"""Backward-linked v6 coverage lock for 500 development specifications.

Version 6 promotes only ``nested-json-schema-migration`` from the v5 planning
record.  The other 24 family values, first twelve source commitments, and
first three promotion-history records remain exact.  The thirteenth registry
and family-local task/discrimination identities are re-derived from live
method-development builders before the immutable projection is admitted.

This is public method-development metadata.  It is not sealed, scored,
candidate-executable, model-selection eligible, or claim authorizing.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from hashlib import sha256
import json
import os
from pathlib import Path
import re
from typing import Final

from . import executable_development_coverage as coverage_v1
from . import executable_development_coverage_v2 as coverage_v2
from . import executable_development_coverage_v3 as coverage_v3
from . import executable_development_coverage_v4 as coverage_v4
from . import executable_development_coverage_v5 as coverage_v5
from .executable_development_coverage import (
    CoverageFamily,
    CoverageParameterAxis,
    SourceRegistryCommitment,
)
from .executable_nested_json_schema_migration import (
    NESTED_JSON_SCHEMA_MIGRATION_ALLOWED_TOOLS,
    NESTED_JSON_SCHEMA_MIGRATION_FAMILY_ID,
    NESTED_JSON_SCHEMA_MIGRATION_FILESYSTEM_IDENTITY,
    NESTED_JSON_SCHEMA_MIGRATION_INPUT_SHAPES,
    NESTED_JSON_SCHEMA_MIGRATION_OUTPUT_IDENTITY,
    NESTED_JSON_SCHEMA_MIGRATION_POLICIES,
    compute_nested_json_schema_migration_discrimination_sha256,
)
from .executable_static_thirteenth_registry import (
    FROZEN_THIRTEENTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_THIRTEENTH_REGISTRY_SHA256,
    THIRTEENTH_TRANCHE_ADDED_TASK_COUNT,
    THIRTEENTH_TRANCHE_CUMULATIVE_TASK_COUNT,
    build_thirteenth_tranche_task_registry,
)
from .executable_static_types import domain_sha256
from . import hash_only_report_publication as report_publication
from .manifests import ManifestValidationError, canonical_json_bytes


COVERAGE_V6_SCHEMA_VERSION: Final[str] = "6.0.0"
COVERAGE_V6_VERSION: Final[str] = "6.0.0"
COVERAGE_V6_SUITE_ID: Final[str] = "cbds-executable-method-development-v6"
COVERAGE_V6_CONFIG_RELATIVE_PATH: Final[str] = (
    "configs/executable-method-development-coverage-v6.json"
)
MAXIMUM_COVERAGE_V6_CONFIG_BYTES: Final[int] = 256 * 1024

FAMILY_COUNT: Final[int] = 25
TASKS_PER_FAMILY: Final[int] = 20
TOTAL_TASK_COUNT: Final[int] = 500
INTEGRATED_FAMILY_COUNT: Final[int] = 22
INTEGRATED_TASK_COUNT: Final[int] = 440
PLANNED_FAMILY_COUNT: Final[int] = 3
PLANNED_TASK_COUNT: Final[int] = 60

CANONICAL_FAMILY_ORDER: Final[tuple[str, ...]] = (
    coverage_v5.CANONICAL_FAMILY_ORDER
)
NESTED_JSON_FAMILY_INDEX: Final[int] = CANONICAL_FAMILY_ORDER.index(
    NESTED_JSON_SCHEMA_MIGRATION_FAMILY_ID
)
NEXT_PLANNED_FAMILY_ID: Final[str] = "dependency-dag-execution-plan"

PREDECESSOR_COVERAGE_SHA256: Final[str] = (
    "e5987525654e384c2696908bf147e8224ad3bdc1fb2e0bbc3856a4f23cdca8b9"
)
PREDECESSOR_CONFIG_BYTES_SHA256: Final[str] = (
    "cfb91bef706fc1c4fd4f95d7891f42e3ec058bbaba28997a22a0f72614d6268f"
)
PREDECESSOR_CONFIG_BYTE_COUNT: Final[int] = 25_241
PREDECESSOR_GIT_COMMIT: Final[str] = (
    "12462612c6a2557a9518cf94185d0a787f9a05b3"
)

FROZEN_NESTED_JSON_TASK_SET_SHA256: Final[str] = (
    "2ab692e66a3090b5d05a204b18f4fdb99ddc822cdbaa5b7912b7ac2166680e0b"
)
FROZEN_NESTED_JSON_DISCRIMINATION_SHA256: Final[str] = (
    "416907543c373f36e55098c514fbe17aeef0192d9e5dc43cd025bed809a0ad42"
)
FROZEN_COVERAGE_V6_SHA256: Final[str] = (
    "044f026b67a531613b1034b27056f1b6f91e1d95ae8902108428e67a6a9c31cf"
)

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{40}\Z")
_AUTHORITY_FALSE_FIELDS: Final[tuple[str, ...]] = (
    "sealed",
    "scored",
    "candidate_execution_authorized",
    "scored_evaluation_authorized",
    "model_selection_eligible",
    "claim_authorized",
    "independent_human_review_attested",
)
_ARCHIVE_PROMOTION_VALUES: Final[tuple[str, ...]] = (
    "compressed-archive-roundtrip-verify",
    "planned",
    "integrated",
    "tenth-tranche",
    coverage_v3.FROZEN_ARCHIVE_TASK_SET_SHA256,
    coverage_v3.FROZEN_ARCHIVE_DISCRIMINATION_SHA256,
)
_CHECKSUM_PROMOTION_VALUES: Final[tuple[str, ...]] = (
    "checksum-repair-plan",
    "planned",
    "integrated",
    "eleventh-tranche",
    coverage_v4.FROZEN_CHECKSUM_TASK_SET_SHA256,
    coverage_v4.FROZEN_CHECKSUM_DISCRIMINATION_SHA256,
)
_JSONL_CSV_PROMOTION_VALUES: Final[tuple[str, ...]] = (
    "jsonl-csv-enrichment-compose",
    "planned",
    "integrated",
    "twelfth-tranche",
    coverage_v5.FROZEN_JSONL_CSV_TASK_SET_SHA256,
    coverage_v5.FROZEN_JSONL_CSV_DISCRIMINATION_SHA256,
)
_NESTED_JSON_PROMOTION_VALUES: Final[tuple[str, ...]] = (
    NESTED_JSON_SCHEMA_MIGRATION_FAMILY_ID,
    "planned",
    "integrated",
    "thirteenth-tranche",
    FROZEN_NESTED_JSON_TASK_SET_SHA256,
    FROZEN_NESTED_JSON_DISCRIMINATION_SHA256,
)


class ExecutableDevelopmentCoverageV6Error(ValueError):
    """Raised when the v6 coverage projection is not exact."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class PredecessorCoverageV5Commitment:
    """Exact identity of the superseded v5 checked artifact."""

    coverage_sha256: str = PREDECESSOR_COVERAGE_SHA256
    config_bytes_sha256: str = PREDECESSOR_CONFIG_BYTES_SHA256
    config_byte_count: int = PREDECESSOR_CONFIG_BYTE_COUNT
    git_commit: str = PREDECESSOR_GIT_COMMIT
    coverage_version: str = coverage_v5.COVERAGE_V5_VERSION
    config_relative_path: str = coverage_v5.COVERAGE_V5_CONFIG_RELATIVE_PATH

    def __post_init__(self) -> None:
        if (
            type(self) is not PredecessorCoverageV5Commitment
            or not _is_sha256(self.coverage_sha256)
            or self.coverage_sha256 != PREDECESSOR_COVERAGE_SHA256
            or not _is_sha256(self.config_bytes_sha256)
            or self.config_bytes_sha256 != PREDECESSOR_CONFIG_BYTES_SHA256
            or type(self.config_byte_count) is not int
            or self.config_byte_count != PREDECESSOR_CONFIG_BYTE_COUNT
            or type(self.git_commit) is not str
            or _COMMIT_RE.fullmatch(self.git_commit) is None
            or self.git_commit != PREDECESSOR_GIT_COMMIT
            or type(self.coverage_version) is not str
            or self.coverage_version != coverage_v5.COVERAGE_V5_VERSION
            or type(self.config_relative_path) is not str
            or self.config_relative_path
            != coverage_v5.COVERAGE_V5_CONFIG_RELATIVE_PATH
        ):
            raise ExecutableDevelopmentCoverageV6Error(
                "v5 predecessor commitment is invalid"
            )

    def to_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "coverage_version": self.coverage_version,
            "coverage_sha256": self.coverage_sha256,
            "config_relative_path": self.config_relative_path,
            "config_bytes_sha256": self.config_bytes_sha256,
            "config_byte_count": self.config_byte_count,
            "git_commit": self.git_commit,
        }


@dataclass(frozen=True, slots=True)
class CoveragePromotionEvidence:
    """One exact event in the append-only promotion history."""

    family_id: str
    old_lifecycle_state: str
    new_lifecycle_state: str
    source_tranche_id: str
    task_set_sha256: str
    discrimination_sha256: str

    def __post_init__(self) -> None:
        values = (
            self.family_id,
            self.old_lifecycle_state,
            self.new_lifecycle_state,
            self.source_tranche_id,
            self.task_set_sha256,
            self.discrimination_sha256,
        )
        if (
            type(self) is not CoveragePromotionEvidence
            or any(type(value) is not str for value in values)
            or values
            not in (
                _ARCHIVE_PROMOTION_VALUES,
                _CHECKSUM_PROMOTION_VALUES,
                _JSONL_CSV_PROMOTION_VALUES,
                _NESTED_JSON_PROMOTION_VALUES,
            )
            or not _is_sha256(self.task_set_sha256)
            or not _is_sha256(self.discrimination_sha256)
        ):
            raise ExecutableDevelopmentCoverageV6Error(
                "promotion-history evidence is invalid"
            )

    def to_record(self) -> dict[str, str]:
        self.__post_init__()
        return {
            "family_id": self.family_id,
            "old_lifecycle_state": self.old_lifecycle_state,
            "new_lifecycle_state": self.new_lifecycle_state,
            "source_tranche_id": self.source_tranche_id,
            "task_set_sha256": self.task_set_sha256,
            "discrimination_sha256": self.discrimination_sha256,
        }


@dataclass(frozen=True, slots=True)
class ExecutableDevelopmentCoverageV6:
    families: tuple[CoverageFamily, ...]
    source_registry_commitments: tuple[SourceRegistryCommitment, ...]
    predecessor: PredecessorCoverageV5Commitment
    hardlink_discrimination_sha256: str
    promotion_history: tuple[
        CoveragePromotionEvidence,
        CoveragePromotionEvidence,
        CoveragePromotionEvidence,
        CoveragePromotionEvidence,
    ]
    coverage_sha256: str
    schema_version: str = COVERAGE_V6_SCHEMA_VERSION
    coverage_version: str = COVERAGE_V6_VERSION
    suite_id: str = COVERAGE_V6_SUITE_ID
    public_method_development: bool = True
    sealed: bool = False
    scored: bool = False
    candidate_execution_authorized: bool = False
    scored_evaluation_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False
    independent_human_review_attested: bool = False

    def __post_init__(self) -> None:
        validate_executable_development_coverage_v6(self)

    def to_hash_only_record(self) -> dict[str, object]:
        validate_executable_development_coverage_v6(self)
        return _coverage_record(self)


def _promotion_from_record(value: object) -> CoveragePromotionEvidence:
    if type(value) is not dict or set(value) != {
        "family_id",
        "old_lifecycle_state",
        "new_lifecycle_state",
        "source_tranche_id",
        "task_set_sha256",
        "discrimination_sha256",
    }:
        raise ExecutableDevelopmentCoverageV6Error(
            "internal promotion snapshot is invalid"
        )
    try:
        return CoveragePromotionEvidence(
            value["family_id"],
            value["old_lifecycle_state"],
            value["new_lifecycle_state"],
            value["source_tranche_id"],
            value["task_set_sha256"],
            value["discrimination_sha256"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ExecutableDevelopmentCoverageV6Error(
            "internal promotion snapshot cannot be reconstructed"
        ) from exc


def _promote_nested_json_family(
    planned: CoverageFamily,
    task_set_sha256: str,
) -> CoverageFamily:
    if (
        type(planned) is not CoverageFamily
        or planned.family_id != NESTED_JSON_SCHEMA_MIGRATION_FAMILY_ID
        or planned.lifecycle_state != "planned"
        or planned.integrated_task_set_sha256 is not None
        or planned.parameter_axes
        != (
            CoverageParameterAxis(
                "input_shape",
                NESTED_JSON_SCHEMA_MIGRATION_INPUT_SHAPES,
            ),
            CoverageParameterAxis(
                "migration_policy",
                NESTED_JSON_SCHEMA_MIGRATION_POLICIES,
            ),
        )
        or planned.solution_track != "python-permitted"
        or planned.allowed_tools
        != NESTED_JSON_SCHEMA_MIGRATION_ALLOWED_TOOLS
        or planned.filesystem_schema
        != NESTED_JSON_SCHEMA_MIGRATION_FILESYSTEM_IDENTITY
        or planned.output_contract
        != NESTED_JSON_SCHEMA_MIGRATION_OUTPUT_IDENTITY
        or task_set_sha256 != FROZEN_NESTED_JSON_TASK_SET_SHA256
    ):
        raise ExecutableDevelopmentCoverageV6Error(
            "v5 nested-JSON planning contract differs from the live family"
        )
    core = {
        "family_id": planned.family_id,
        "lifecycle_state": "integrated",
        "task_count": planned.task_count,
        "parameter_axes": [
            axis.to_record() for axis in planned.parameter_axes
        ],
        "solution_track": planned.solution_track,
        "allowed_tools": list(planned.allowed_tools),
        "filesystem_schema": planned.filesystem_schema,
        "output_contract": planned.output_contract,
        "capability_tags": list(planned.capability_tags),
        "integrated_task_set_sha256": task_set_sha256,
    }
    return CoverageFamily(
        family_id=planned.family_id,
        lifecycle_state="integrated",
        task_count=planned.task_count,
        parameter_axes=planned.parameter_axes,
        solution_track=planned.solution_track,
        allowed_tools=planned.allowed_tools,
        filesystem_schema=planned.filesystem_schema,
        output_contract=planned.output_contract,
        capability_tags=planned.capability_tags,
        integrated_task_set_sha256=task_set_sha256,
        family_sha256=domain_sha256(
            "cbds.executable-method-development-coverage.family.v1",
            core,
        ),
    )


@lru_cache(maxsize=1)
def _live_component_snapshot_bytes() -> bytes:
    """Cache primitive evidence only, so callers receive fresh objects."""

    predecessor = coverage_v5.build_executable_development_coverage_v5()
    predecessor_bytes = (
        coverage_v5.executable_development_coverage_v5_config_bytes()
    )
    if (
        predecessor.coverage_sha256 != PREDECESSOR_COVERAGE_SHA256
        or len(predecessor_bytes) != PREDECESSOR_CONFIG_BYTE_COUNT
        or sha256(predecessor_bytes).hexdigest()
        != PREDECESSOR_CONFIG_BYTES_SHA256
    ):
        raise ExecutableDevelopmentCoverageV6Error(
            "live v5 coverage differs from the frozen predecessor"
        )
    thirteenth = build_thirteenth_tranche_task_registry()
    if (
        thirteenth.registry_sha256
        != FROZEN_THIRTEENTH_REGISTRY_SHA256
        or thirteenth.cumulative_suite_sha256
        != FROZEN_THIRTEENTH_CUMULATIVE_SUITE_SHA256
        or len(thirteenth.added_tasks)
        != THIRTEENTH_TRANCHE_ADDED_TASK_COUNT
        or THIRTEENTH_TRANCHE_CUMULATIVE_TASK_COUNT
        != INTEGRATED_TASK_COUNT
    ):
        raise ExecutableDevelopmentCoverageV6Error(
            "live thirteenth registry differs from the frozen v6 source"
        )
    task_set_sha256 = coverage_v2._task_set_sha256(
        NESTED_JSON_SCHEMA_MIGRATION_FAMILY_ID,
        thirteenth.added_tasks,
    )
    discrimination_sha256 = (
        compute_nested_json_schema_migration_discrimination_sha256(
            thirteenth.added_tasks
        )
    )
    if (
        task_set_sha256 != FROZEN_NESTED_JSON_TASK_SET_SHA256
        or discrimination_sha256
        != FROZEN_NESTED_JSON_DISCRIMINATION_SHA256
    ):
        raise ExecutableDevelopmentCoverageV6Error(
            "live nested-JSON promotion evidence differs from v6"
        )
    promoted = _promote_nested_json_family(
        predecessor.families[NESTED_JSON_FAMILY_INDEX],
        task_set_sha256,
    )
    families = (
        *predecessor.families[:NESTED_JSON_FAMILY_INDEX],
        promoted,
        *predecessor.families[NESTED_JSON_FAMILY_INDEX + 1 :],
    )
    if any(
        old != new
        for index, (old, new) in enumerate(
            zip(predecessor.families, families, strict=True)
        )
        if index != NESTED_JSON_FAMILY_INDEX
    ):
        raise ExecutableDevelopmentCoverageV6Error(
            "a family outside the nested-JSON promotion changed"
        )
    sources = (
        *predecessor.source_registry_commitments,
        SourceRegistryCommitment(
            "thirteenth-tranche",
            len(thirteenth.added_tasks),
            INTEGRATED_TASK_COUNT,
            thirteenth.registry_sha256,
            thirteenth.cumulative_suite_sha256,
        ),
    )
    prior_history = tuple(
        _promotion_from_record(item.to_record())
        for item in predecessor.promotion_history
    )
    promotion = CoveragePromotionEvidence(
        NESTED_JSON_SCHEMA_MIGRATION_FAMILY_ID,
        "planned",
        "integrated",
        "thirteenth-tranche",
        task_set_sha256,
        discrimination_sha256,
    )
    return canonical_json_bytes(
        {
            "v6_families": [item.to_record() for item in families],
            "v6_sources": [item.to_record() for item in sources],
            "hardlink_discrimination_sha256": (
                predecessor.hardlink_discrimination_sha256
            ),
            "promotion_history": [
                *(item.to_record() for item in prior_history),
                promotion.to_record(),
            ],
        }
    )


def _component_snapshot() -> dict[str, object]:
    value = json.loads(_live_component_snapshot_bytes())
    if type(value) is not dict:
        raise ExecutableDevelopmentCoverageV6Error(
            "internal component snapshot is invalid"
        )
    return value


def _families_from_snapshot(value: object) -> tuple[CoverageFamily, ...]:
    if type(value) is not list:
        raise ExecutableDevelopmentCoverageV6Error(
            "internal family snapshot is invalid"
        )
    try:
        return tuple(coverage_v1._family_from_record(item) for item in value)
    except (AttributeError, TypeError, ValueError) as exc:
        raise ExecutableDevelopmentCoverageV6Error(
            "internal family snapshot cannot be reconstructed"
        ) from exc


def _sources_from_snapshot(
    value: object,
) -> tuple[SourceRegistryCommitment, ...]:
    if type(value) is not list:
        raise ExecutableDevelopmentCoverageV6Error(
            "internal source snapshot is invalid"
        )
    try:
        return tuple(coverage_v1._source_from_record(item) for item in value)
    except (AttributeError, TypeError, ValueError) as exc:
        raise ExecutableDevelopmentCoverageV6Error(
            "internal source snapshot cannot be reconstructed"
        ) from exc


def _live_v6_components() -> tuple[
    tuple[CoverageFamily, ...],
    tuple[SourceRegistryCommitment, ...],
    str,
    tuple[
        CoveragePromotionEvidence,
        CoveragePromotionEvidence,
        CoveragePromotionEvidence,
        CoveragePromotionEvidence,
    ],
]:
    snapshot = _component_snapshot()
    hardlink = snapshot.get("hardlink_discrimination_sha256")
    promotions = snapshot.get("promotion_history")
    if (
        type(hardlink) is not str
        or hardlink != coverage_v2.FROZEN_HARDLINK_DISCRIMINATION_SHA256
        or type(promotions) is not list
        or len(promotions) != 4
    ):
        raise ExecutableDevelopmentCoverageV6Error(
            "internal v6 evidence snapshot is invalid"
        )
    history = tuple(_promotion_from_record(item) for item in promotions)
    return (
        _families_from_snapshot(snapshot.get("v6_families")),
        _sources_from_snapshot(snapshot.get("v6_sources")),
        hardlink,
        history,  # type: ignore[return-value]
    )


def _coverage_record(
    coverage: ExecutableDevelopmentCoverageV6,
) -> dict[str, object]:
    return {
        "schema_version": coverage.schema_version,
        "coverage_version": coverage.coverage_version,
        "record_type": "cbds.executable-method-development-coverage-hashes",
        "suite_id": coverage.suite_id,
        "family_count": FAMILY_COUNT,
        "tasks_per_family": TASKS_PER_FAMILY,
        "total_task_count": TOTAL_TASK_COUNT,
        "integrated_family_count": INTEGRATED_FAMILY_COUNT,
        "integrated_task_count": INTEGRATED_TASK_COUNT,
        "planned_family_count": PLANNED_FAMILY_COUNT,
        "planned_task_count": PLANNED_TASK_COUNT,
        "canonical_family_order": list(CANONICAL_FAMILY_ORDER),
        "predecessor": coverage.predecessor.to_record(),
        "source_registry_commitments": [
            item.to_record()
            for item in coverage.source_registry_commitments
        ],
        "families": [item.to_record() for item in coverage.families],
        "hardlink_discrimination_sha256": (
            coverage.hardlink_discrimination_sha256
        ),
        "promotion_history": [
            item.to_record() for item in coverage.promotion_history
        ],
        "coverage_sha256": coverage.coverage_sha256,
        "public_method_development": coverage.public_method_development,
        "sealed": coverage.sealed,
        "scored": coverage.scored,
        "candidate_execution_authorized": (
            coverage.candidate_execution_authorized
        ),
        "scored_evaluation_authorized": (
            coverage.scored_evaluation_authorized
        ),
        "model_selection_eligible": coverage.model_selection_eligible,
        "claim_authorized": coverage.claim_authorized,
        "independent_human_review_attested": (
            coverage.independent_human_review_attested
        ),
    }


def compute_executable_development_coverage_v6_sha256(
    record: object,
) -> str:
    if type(record) is not dict:
        raise ExecutableDevelopmentCoverageV6Error(
            "v6 coverage hash input must be an exact object"
        )
    payload = dict(record)
    payload.pop("coverage_sha256", None)
    return domain_sha256(
        "cbds.executable-method-development-coverage.v6",
        payload,
    )


def validate_executable_development_coverage_v6(
    coverage: ExecutableDevelopmentCoverageV6,
) -> None:
    if type(coverage) is not ExecutableDevelopmentCoverageV6:
        raise ExecutableDevelopmentCoverageV6Error(
            "coverage must be an exact ExecutableDevelopmentCoverageV6"
        )
    if (
        type(coverage.schema_version) is not str
        or coverage.schema_version != COVERAGE_V6_SCHEMA_VERSION
        or type(coverage.coverage_version) is not str
        or coverage.coverage_version != COVERAGE_V6_VERSION
        or type(coverage.suite_id) is not str
        or coverage.suite_id != COVERAGE_V6_SUITE_ID
        or coverage.public_method_development is not True
        or any(
            getattr(coverage, name) is not False
            for name in _AUTHORITY_FALSE_FIELDS
        )
        or type(coverage.predecessor)
        is not PredecessorCoverageV5Commitment
    ):
        raise ExecutableDevelopmentCoverageV6Error(
            "v6 metadata, predecessor, or authority boundary is invalid"
        )
    coverage.predecessor.__post_init__()
    expected_families, expected_sources, hardlink, history = (
        _live_v6_components()
    )
    if (
        type(coverage.families) is not tuple
        or any(
            type(item) is not CoverageFamily
            for item in coverage.families
        )
        or coverage.families != expected_families
        or type(coverage.source_registry_commitments) is not tuple
        or any(
            type(item) is not SourceRegistryCommitment
            for item in coverage.source_registry_commitments
        )
        or coverage.source_registry_commitments != expected_sources
        or coverage.hardlink_discrimination_sha256 != hardlink
        or not _is_sha256(coverage.hardlink_discrimination_sha256)
        or type(coverage.promotion_history) is not tuple
        or coverage.promotion_history != history
        or len(coverage.promotion_history) != 4
        or any(
            type(item) is not CoveragePromotionEvidence
            for item in coverage.promotion_history
        )
    ):
        raise ExecutableDevelopmentCoverageV6Error(
            "v6 live families, sources, or history differ"
        )
    for item in coverage.promotion_history:
        item.__post_init__()
    for item in coverage.families:
        item.__post_init__()
    for item in coverage.source_registry_commitments:
        item.__post_init__()
    if (
        len(coverage.families) != FAMILY_COUNT
        or tuple(item.family_id for item in coverage.families)
        != CANONICAL_FAMILY_ORDER
        or tuple(item.lifecycle_state for item in coverage.families)
        != ("integrated",) * INTEGRATED_FAMILY_COUNT
        + ("planned",) * PLANNED_FAMILY_COUNT
        or coverage.families[INTEGRATED_FAMILY_COUNT].family_id
        != NEXT_PLANNED_FAMILY_ID
        or sum(item.task_count for item in coverage.families)
        != TOTAL_TASK_COUNT
        or len(coverage.source_registry_commitments) != 13
        or tuple(
            item.cumulative_task_count
            for item in coverage.source_registry_commitments
        )
        != (
            100,
            200,
            240,
            260,
            280,
            300,
            320,
            340,
            360,
            380,
            400,
            420,
            440,
        )
        or coverage.source_registry_commitments[-1].tranche_id
        != "thirteenth-tranche"
        or coverage.source_registry_commitments[-1].registry_sha256
        != FROZEN_THIRTEENTH_REGISTRY_SHA256
        or coverage.source_registry_commitments[
            -1
        ].cumulative_suite_sha256
        != FROZEN_THIRTEENTH_CUMULATIVE_SUITE_SHA256
        or tuple(item.family_id for item in coverage.promotion_history)
        != (
            "compressed-archive-roundtrip-verify",
            "checksum-repair-plan",
            "jsonl-csv-enrichment-compose",
            NESTED_JSON_SCHEMA_MIGRATION_FAMILY_ID,
        )
    ):
        raise ExecutableDevelopmentCoverageV6Error(
            "v6 coverage partition, source chain, or order is invalid"
        )
    record = _coverage_record(coverage)
    if (
        not _is_sha256(coverage.coverage_sha256)
        or coverage.coverage_sha256 != FROZEN_COVERAGE_V6_SHA256
        or coverage.coverage_sha256
        != compute_executable_development_coverage_v6_sha256(record)
    ):
        raise ExecutableDevelopmentCoverageV6Error(
            "v6 coverage digest is invalid"
        )


def build_executable_development_coverage_v6(
) -> ExecutableDevelopmentCoverageV6:
    families, sources, hardlink, history = _live_v6_components()
    predecessor = PredecessorCoverageV5Commitment()
    provisional = ExecutableDevelopmentCoverageV6.__new__(
        ExecutableDevelopmentCoverageV6
    )
    values: dict[str, object] = {
        "families": families,
        "source_registry_commitments": sources,
        "predecessor": predecessor,
        "hardlink_discrimination_sha256": hardlink,
        "promotion_history": history,
        "coverage_sha256": "0" * 64,
        "schema_version": COVERAGE_V6_SCHEMA_VERSION,
        "coverage_version": COVERAGE_V6_VERSION,
        "suite_id": COVERAGE_V6_SUITE_ID,
        "public_method_development": True,
        "sealed": False,
        "scored": False,
        "candidate_execution_authorized": False,
        "scored_evaluation_authorized": False,
        "model_selection_eligible": False,
        "claim_authorized": False,
        "independent_human_review_attested": False,
    }
    for name, value in values.items():
        object.__setattr__(provisional, name, value)
    digest = compute_executable_development_coverage_v6_sha256(
        _coverage_record(provisional)
    )
    return ExecutableDevelopmentCoverageV6(
        families=families,
        source_registry_commitments=sources,
        predecessor=predecessor,
        hardlink_discrimination_sha256=hardlink,
        promotion_history=history,
        coverage_sha256=digest,
    )


def _reject_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ExecutableDevelopmentCoverageV6Error(
                "v6 coverage JSON contains a duplicate object key"
            )
        result[key] = value
    return result


def _read_stable_regular(
    path: Path,
    maximum_bytes: int = MAXIMUM_COVERAGE_V6_CONFIG_BYTES,
) -> bytes:
    try:
        payload = report_publication.read_existing_regular(path, maximum_bytes)
    except (
        report_publication.HashOnlyReportPublicationError,
        OSError,
        TypeError,
        ValueError,
        UnicodeError,
    ) as exc:
        raise ExecutableDevelopmentCoverageV6Error(
            "cannot read v6 coverage as a stable regular file"
        ) from exc
    if payload is None:
        raise ExecutableDevelopmentCoverageV6Error(
            "v6 coverage config does not exist as a stable regular file"
        )
    return payload


def load_executable_development_coverage_v6(
    path: str | os.PathLike[str],
) -> ExecutableDevelopmentCoverageV6:
    """Load only the exact canonical checked v6 projection."""

    try:
        source = Path(os.fspath(path))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ExecutableDevelopmentCoverageV6Error(
            "v6 coverage config path is invalid"
        ) from exc
    payload = _read_stable_regular(source)
    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ExecutableDevelopmentCoverageV6Error(
                    "v6 coverage JSON contains non-finite number "
                    f"{token}"
                )
            ),
        )
        canonical = canonical_json_bytes(value) + b"\n"
    except ExecutableDevelopmentCoverageV6Error:
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
        raise ExecutableDevelopmentCoverageV6Error(
            "v6 coverage config is not strict canonical JSON"
        ) from exc
    if payload != canonical:
        raise ExecutableDevelopmentCoverageV6Error(
            "v6 coverage config is not canonical JSON plus LF"
        )
    expected = build_executable_development_coverage_v6()
    if payload != executable_development_coverage_v6_config_bytes():
        raise ExecutableDevelopmentCoverageV6Error(
            "checked v6 config differs from the central projection"
        )
    return expected


@lru_cache(maxsize=1)
def executable_development_coverage_v6_config_bytes() -> bytes:
    """Return immutable canonical bytes for deterministic publication."""

    return (
        canonical_json_bytes(
            build_executable_development_coverage_v6().to_hash_only_record()
        )
        + b"\n"
    )


__all__ = [
    "CANONICAL_FAMILY_ORDER",
    "COVERAGE_V6_CONFIG_RELATIVE_PATH",
    "COVERAGE_V6_SCHEMA_VERSION",
    "COVERAGE_V6_SUITE_ID",
    "COVERAGE_V6_VERSION",
    "FAMILY_COUNT",
    "FROZEN_COVERAGE_V6_SHA256",
    "FROZEN_NESTED_JSON_DISCRIMINATION_SHA256",
    "FROZEN_NESTED_JSON_TASK_SET_SHA256",
    "FROZEN_THIRTEENTH_CUMULATIVE_SUITE_SHA256",
    "FROZEN_THIRTEENTH_REGISTRY_SHA256",
    "INTEGRATED_FAMILY_COUNT",
    "INTEGRATED_TASK_COUNT",
    "MAXIMUM_COVERAGE_V6_CONFIG_BYTES",
    "NESTED_JSON_FAMILY_INDEX",
    "NEXT_PLANNED_FAMILY_ID",
    "PLANNED_FAMILY_COUNT",
    "PLANNED_TASK_COUNT",
    "PREDECESSOR_CONFIG_BYTE_COUNT",
    "PREDECESSOR_CONFIG_BYTES_SHA256",
    "PREDECESSOR_COVERAGE_SHA256",
    "PREDECESSOR_GIT_COMMIT",
    "TASKS_PER_FAMILY",
    "TOTAL_TASK_COUNT",
    "CoveragePromotionEvidence",
    "ExecutableDevelopmentCoverageV6",
    "ExecutableDevelopmentCoverageV6Error",
    "PredecessorCoverageV5Commitment",
    "build_executable_development_coverage_v6",
    "compute_executable_development_coverage_v6_sha256",
    "executable_development_coverage_v6_config_bytes",
    "load_executable_development_coverage_v6",
    "validate_executable_development_coverage_v6",
]
