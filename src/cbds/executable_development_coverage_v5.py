"""Backward-linked v5 coverage lock for 500 development specifications.

Version 5 promotes only ``jsonl-csv-enrichment-compose`` from the v4 planning
record.  The other 24 family values, the first eleven source commitments, and
the first two promotion-history records remain exact.  The twelfth registry
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
from .executable_development_coverage import (
    CoverageFamily,
    CoverageParameterAxis,
    SourceRegistryCommitment,
)
from .executable_jsonl_csv_enrichment_compose import (
    JSONL_CSV_ENRICHMENT_COMPOSE_ALLOWED_TOOLS,
    JSONL_CSV_ENRICHMENT_COMPOSE_FAMILY_ID,
    JSONL_CSV_ENRICHMENT_COMPOSE_FILESYSTEM_IDENTITY,
    JSONL_CSV_ENRICHMENT_COMPOSE_JOIN_LAYOUTS,
    JSONL_CSV_ENRICHMENT_COMPOSE_MISSING_FIELD_POLICIES,
    JSONL_CSV_ENRICHMENT_COMPOSE_OUTPUT_IDENTITY,
    compute_jsonl_csv_enrichment_compose_discrimination_sha256,
)
from .executable_static_twelfth_registry import (
    TWELFTH_TRANCHE_ADDED_TASK_COUNT,
    TWELFTH_TRANCHE_CUMULATIVE_TASK_COUNT,
    build_twelfth_tranche_task_registry,
)
from .executable_static_types import domain_sha256
from . import hash_only_report_publication as report_publication
from .manifests import ManifestValidationError, canonical_json_bytes


COVERAGE_V5_SCHEMA_VERSION: Final[str] = "5.0.0"
COVERAGE_V5_VERSION: Final[str] = "5.0.0"
COVERAGE_V5_SUITE_ID: Final[str] = "cbds-executable-method-development-v5"
COVERAGE_V5_CONFIG_RELATIVE_PATH: Final[str] = (
    "configs/executable-method-development-coverage-v5.json"
)
MAXIMUM_COVERAGE_V5_CONFIG_BYTES: Final[int] = 256 * 1024

FAMILY_COUNT: Final[int] = 25
TASKS_PER_FAMILY: Final[int] = 20
TOTAL_TASK_COUNT: Final[int] = 500
INTEGRATED_FAMILY_COUNT: Final[int] = 21
INTEGRATED_TASK_COUNT: Final[int] = 420
PLANNED_FAMILY_COUNT: Final[int] = 4
PLANNED_TASK_COUNT: Final[int] = 80

CANONICAL_FAMILY_ORDER: Final[tuple[str, ...]] = (
    coverage_v4.CANONICAL_FAMILY_ORDER
)
JSONL_CSV_FAMILY_INDEX: Final[int] = CANONICAL_FAMILY_ORDER.index(
    JSONL_CSV_ENRICHMENT_COMPOSE_FAMILY_ID
)
NEXT_PLANNED_FAMILY_ID: Final[str] = "nested-json-schema-migration"

PREDECESSOR_COVERAGE_SHA256: Final[str] = (
    "1bd7a4b6ab721404f1d1eb7a64718ba7df783998bf16cd603afb86eb2420d67c"
)
PREDECESSOR_CONFIG_BYTES_SHA256: Final[str] = (
    "d003a5748da855257aa93e0c6e1b7a4be2de393ec5faa0dcb32d74156f40b3d7"
)
PREDECESSOR_CONFIG_BYTE_COUNT: Final[int] = 24_590
PREDECESSOR_GIT_COMMIT: Final[str] = (
    "948bbe1d0e4e0940e61ba89557f215a2a37d8194"
)

FROZEN_TWELFTH_REGISTRY_SHA256: Final[str] = (
    "a9733f220a7bdfb8435841eff875c9fd7b1dbadbee6de2d2aa0646750164f862"
)
FROZEN_TWELFTH_CUMULATIVE_SUITE_SHA256: Final[str] = (
    "32ec82cf193f364946def16462e52217176093d0a3f6399d574c9faf66eaa4a1"
)
FROZEN_JSONL_CSV_TASK_SET_SHA256: Final[str] = (
    "60a8ab6770bae6de43d430db9e3edf136f28f0a0ad2dacfd09b627ce19cf75c3"
)
FROZEN_JSONL_CSV_DISCRIMINATION_SHA256: Final[str] = (
    "732c1438a4337d2043ee85e2eb4e9e7c437a0051eb1a828cdac6139845db0e94"
)
FROZEN_COVERAGE_V5_SHA256: Final[str] = (
    "e5987525654e384c2696908bf147e8224ad3bdc1fb2e0bbc3856a4f23cdca8b9"
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
    JSONL_CSV_ENRICHMENT_COMPOSE_FAMILY_ID,
    "planned",
    "integrated",
    "twelfth-tranche",
    FROZEN_JSONL_CSV_TASK_SET_SHA256,
    FROZEN_JSONL_CSV_DISCRIMINATION_SHA256,
)


class ExecutableDevelopmentCoverageV5Error(ValueError):
    """Raised when the v5 coverage projection is not exact."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class PredecessorCoverageV4Commitment:
    """Exact identity of the superseded v4 checked artifact."""

    coverage_sha256: str = PREDECESSOR_COVERAGE_SHA256
    config_bytes_sha256: str = PREDECESSOR_CONFIG_BYTES_SHA256
    config_byte_count: int = PREDECESSOR_CONFIG_BYTE_COUNT
    git_commit: str = PREDECESSOR_GIT_COMMIT
    coverage_version: str = coverage_v4.COVERAGE_V4_VERSION
    config_relative_path: str = coverage_v4.COVERAGE_V4_CONFIG_RELATIVE_PATH

    def __post_init__(self) -> None:
        if (
            type(self) is not PredecessorCoverageV4Commitment
            or self.coverage_sha256 != PREDECESSOR_COVERAGE_SHA256
            or self.config_bytes_sha256 != PREDECESSOR_CONFIG_BYTES_SHA256
            or type(self.config_byte_count) is not int
            or self.config_byte_count != PREDECESSOR_CONFIG_BYTE_COUNT
            or type(self.git_commit) is not str
            or _COMMIT_RE.fullmatch(self.git_commit) is None
            or self.git_commit != PREDECESSOR_GIT_COMMIT
            or self.coverage_version != coverage_v4.COVERAGE_V4_VERSION
            or self.config_relative_path
            != coverage_v4.COVERAGE_V4_CONFIG_RELATIVE_PATH
        ):
            raise ExecutableDevelopmentCoverageV5Error(
                "v4 predecessor commitment is invalid"
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
            or values
            not in (
                _ARCHIVE_PROMOTION_VALUES,
                _CHECKSUM_PROMOTION_VALUES,
                _JSONL_CSV_PROMOTION_VALUES,
            )
            or not _is_sha256(self.task_set_sha256)
            or not _is_sha256(self.discrimination_sha256)
        ):
            raise ExecutableDevelopmentCoverageV5Error(
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
class ExecutableDevelopmentCoverageV5:
    families: tuple[CoverageFamily, ...]
    source_registry_commitments: tuple[SourceRegistryCommitment, ...]
    predecessor: PredecessorCoverageV4Commitment
    hardlink_discrimination_sha256: str
    promotion_history: tuple[
        CoveragePromotionEvidence,
        CoveragePromotionEvidence,
        CoveragePromotionEvidence,
    ]
    coverage_sha256: str
    schema_version: str = COVERAGE_V5_SCHEMA_VERSION
    coverage_version: str = COVERAGE_V5_VERSION
    suite_id: str = COVERAGE_V5_SUITE_ID
    public_method_development: bool = True
    sealed: bool = False
    scored: bool = False
    candidate_execution_authorized: bool = False
    scored_evaluation_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False
    independent_human_review_attested: bool = False

    def __post_init__(self) -> None:
        validate_executable_development_coverage_v5(self)

    def to_hash_only_record(self) -> dict[str, object]:
        validate_executable_development_coverage_v5(self)
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
        raise ExecutableDevelopmentCoverageV5Error(
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
        raise ExecutableDevelopmentCoverageV5Error(
            "internal promotion snapshot cannot be reconstructed"
        ) from exc


def _promote_jsonl_csv_family(
    planned: CoverageFamily,
    task_set_sha256: str,
) -> CoverageFamily:
    if (
        type(planned) is not CoverageFamily
        or planned.family_id != JSONL_CSV_ENRICHMENT_COMPOSE_FAMILY_ID
        or planned.lifecycle_state != "planned"
        or planned.integrated_task_set_sha256 is not None
        or planned.parameter_axes
        != (
            CoverageParameterAxis(
                "join_layout",
                JSONL_CSV_ENRICHMENT_COMPOSE_JOIN_LAYOUTS,
            ),
            CoverageParameterAxis(
                "missing_field_policy",
                JSONL_CSV_ENRICHMENT_COMPOSE_MISSING_FIELD_POLICIES,
            ),
        )
        or planned.solution_track != "bash-native"
        or planned.allowed_tools != JSONL_CSV_ENRICHMENT_COMPOSE_ALLOWED_TOOLS
        or planned.filesystem_schema
        != JSONL_CSV_ENRICHMENT_COMPOSE_FILESYSTEM_IDENTITY
        or planned.output_contract
        != JSONL_CSV_ENRICHMENT_COMPOSE_OUTPUT_IDENTITY
        or task_set_sha256 != FROZEN_JSONL_CSV_TASK_SET_SHA256
    ):
        raise ExecutableDevelopmentCoverageV5Error(
            "v4 JSONL/CSV planning contract differs from the live family"
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
    """Cache primitive evidence only, so callers always receive fresh objects."""

    predecessor = coverage_v4.build_executable_development_coverage_v4()
    predecessor_bytes = (
        coverage_v4.executable_development_coverage_v4_config_bytes()
    )
    if (
        predecessor.coverage_sha256 != PREDECESSOR_COVERAGE_SHA256
        or len(predecessor_bytes) != PREDECESSOR_CONFIG_BYTE_COUNT
        or sha256(predecessor_bytes).hexdigest()
        != PREDECESSOR_CONFIG_BYTES_SHA256
    ):
        raise ExecutableDevelopmentCoverageV5Error(
            "live v4 coverage differs from the frozen predecessor"
        )
    twelfth = build_twelfth_tranche_task_registry()
    if (
        twelfth.registry_sha256 != FROZEN_TWELFTH_REGISTRY_SHA256
        or twelfth.cumulative_suite_sha256
        != FROZEN_TWELFTH_CUMULATIVE_SUITE_SHA256
        or len(twelfth.added_tasks) != TWELFTH_TRANCHE_ADDED_TASK_COUNT
        or TWELFTH_TRANCHE_CUMULATIVE_TASK_COUNT != INTEGRATED_TASK_COUNT
    ):
        raise ExecutableDevelopmentCoverageV5Error(
            "live twelfth registry differs from the frozen v5 source"
        )
    task_set_sha256 = coverage_v2._task_set_sha256(
        JSONL_CSV_ENRICHMENT_COMPOSE_FAMILY_ID,
        twelfth.added_tasks,
    )
    discrimination_sha256 = (
        compute_jsonl_csv_enrichment_compose_discrimination_sha256(
            twelfth.added_tasks
        )
    )
    if (
        task_set_sha256 != FROZEN_JSONL_CSV_TASK_SET_SHA256
        or discrimination_sha256
        != FROZEN_JSONL_CSV_DISCRIMINATION_SHA256
    ):
        raise ExecutableDevelopmentCoverageV5Error(
            "live JSONL/CSV promotion evidence differs from v5"
        )
    promoted = _promote_jsonl_csv_family(
        predecessor.families[JSONL_CSV_FAMILY_INDEX],
        task_set_sha256,
    )
    families = (
        *predecessor.families[:JSONL_CSV_FAMILY_INDEX],
        promoted,
        *predecessor.families[JSONL_CSV_FAMILY_INDEX + 1 :],
    )
    if any(
        old != new
        for index, (old, new) in enumerate(
            zip(predecessor.families, families, strict=True)
        )
        if index != JSONL_CSV_FAMILY_INDEX
    ):
        raise ExecutableDevelopmentCoverageV5Error(
            "a family outside the JSONL/CSV promotion changed"
        )
    sources = (
        *predecessor.source_registry_commitments,
        SourceRegistryCommitment(
            "twelfth-tranche",
            len(twelfth.added_tasks),
            INTEGRATED_TASK_COUNT,
            twelfth.registry_sha256,
            twelfth.cumulative_suite_sha256,
        ),
    )
    prior_history = tuple(
        _promotion_from_record(item.to_record())
        for item in predecessor.promotion_history
    )
    promotion = CoveragePromotionEvidence(
        JSONL_CSV_ENRICHMENT_COMPOSE_FAMILY_ID,
        "planned",
        "integrated",
        "twelfth-tranche",
        task_set_sha256,
        discrimination_sha256,
    )
    return canonical_json_bytes(
        {
            "predecessor_families": [
                item.to_record() for item in predecessor.families
            ],
            "predecessor_sources": [
                item.to_record()
                for item in predecessor.source_registry_commitments
            ],
            "predecessor_history": [
                item.to_record() for item in predecessor.promotion_history
            ],
            "v5_families": [item.to_record() for item in families],
            "v5_sources": [item.to_record() for item in sources],
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
        raise ExecutableDevelopmentCoverageV5Error(
            "internal component snapshot is invalid"
        )
    return value


def _families_from_snapshot(value: object) -> tuple[CoverageFamily, ...]:
    if type(value) is not list:
        raise ExecutableDevelopmentCoverageV5Error(
            "internal family snapshot is invalid"
        )
    try:
        return tuple(coverage_v1._family_from_record(item) for item in value)
    except (AttributeError, TypeError, ValueError) as exc:
        raise ExecutableDevelopmentCoverageV5Error(
            "internal family snapshot cannot be reconstructed"
        ) from exc


def _sources_from_snapshot(
    value: object,
) -> tuple[SourceRegistryCommitment, ...]:
    if type(value) is not list:
        raise ExecutableDevelopmentCoverageV5Error(
            "internal source snapshot is invalid"
        )
    try:
        return tuple(coverage_v1._source_from_record(item) for item in value)
    except (AttributeError, TypeError, ValueError) as exc:
        raise ExecutableDevelopmentCoverageV5Error(
            "internal source snapshot cannot be reconstructed"
        ) from exc


def _live_v5_components() -> tuple[
    tuple[CoverageFamily, ...],
    tuple[SourceRegistryCommitment, ...],
    str,
    tuple[
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
        or len(promotions) != 3
    ):
        raise ExecutableDevelopmentCoverageV5Error(
            "internal v5 evidence snapshot is invalid"
        )
    history = tuple(_promotion_from_record(item) for item in promotions)
    return (
        _families_from_snapshot(snapshot.get("v5_families")),
        _sources_from_snapshot(snapshot.get("v5_sources")),
        hardlink,
        history,  # type: ignore[return-value]
    )


def _coverage_record(
    coverage: ExecutableDevelopmentCoverageV5,
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


def compute_executable_development_coverage_v5_sha256(
    record: object,
) -> str:
    if type(record) is not dict:
        raise ExecutableDevelopmentCoverageV5Error(
            "v5 coverage hash input must be an exact object"
        )
    payload = dict(record)
    payload.pop("coverage_sha256", None)
    return domain_sha256(
        "cbds.executable-method-development-coverage.v5",
        payload,
    )


def validate_executable_development_coverage_v5(
    coverage: ExecutableDevelopmentCoverageV5,
) -> None:
    if type(coverage) is not ExecutableDevelopmentCoverageV5:
        raise ExecutableDevelopmentCoverageV5Error(
            "coverage must be an exact ExecutableDevelopmentCoverageV5"
        )
    if (
        coverage.schema_version != COVERAGE_V5_SCHEMA_VERSION
        or coverage.coverage_version != COVERAGE_V5_VERSION
        or coverage.suite_id != COVERAGE_V5_SUITE_ID
        or coverage.public_method_development is not True
        or any(
            getattr(coverage, name) is not False
            for name in _AUTHORITY_FALSE_FIELDS
        )
        or type(coverage.predecessor)
        is not PredecessorCoverageV4Commitment
    ):
        raise ExecutableDevelopmentCoverageV5Error(
            "v5 metadata, predecessor, or authority boundary is invalid"
        )
    coverage.predecessor.__post_init__()
    expected_families, expected_sources, hardlink, history = (
        _live_v5_components()
    )
    if (
        type(coverage.families) is not tuple
        or coverage.families != expected_families
        or type(coverage.source_registry_commitments) is not tuple
        or coverage.source_registry_commitments != expected_sources
        or coverage.hardlink_discrimination_sha256 != hardlink
        or not _is_sha256(coverage.hardlink_discrimination_sha256)
        or type(coverage.promotion_history) is not tuple
        or coverage.promotion_history != history
        or len(coverage.promotion_history) != 3
        or any(
            type(item) is not CoveragePromotionEvidence
            for item in coverage.promotion_history
        )
    ):
        raise ExecutableDevelopmentCoverageV5Error(
            "v5 live families, sources, or history differ"
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
        or len(coverage.source_registry_commitments) != 12
        or tuple(
            item.cumulative_task_count
            for item in coverage.source_registry_commitments
        )
        != (100, 200, 240, 260, 280, 300, 320, 340, 360, 380, 400, 420)
        or coverage.source_registry_commitments[-1].tranche_id
        != "twelfth-tranche"
        or coverage.source_registry_commitments[-1].registry_sha256
        != FROZEN_TWELFTH_REGISTRY_SHA256
        or coverage.source_registry_commitments[
            -1
        ].cumulative_suite_sha256
        != FROZEN_TWELFTH_CUMULATIVE_SUITE_SHA256
        or tuple(item.family_id for item in coverage.promotion_history)
        != (
            "compressed-archive-roundtrip-verify",
            "checksum-repair-plan",
            JSONL_CSV_ENRICHMENT_COMPOSE_FAMILY_ID,
        )
    ):
        raise ExecutableDevelopmentCoverageV5Error(
            "v5 coverage partition, source chain, or order is invalid"
        )
    record = _coverage_record(coverage)
    if (
        not _is_sha256(coverage.coverage_sha256)
        or coverage.coverage_sha256 != FROZEN_COVERAGE_V5_SHA256
        or coverage.coverage_sha256
        != compute_executable_development_coverage_v5_sha256(record)
    ):
        raise ExecutableDevelopmentCoverageV5Error(
            "v5 coverage digest is invalid"
        )


def build_executable_development_coverage_v5(
) -> ExecutableDevelopmentCoverageV5:
    families, sources, hardlink, history = _live_v5_components()
    predecessor = PredecessorCoverageV4Commitment()
    provisional = ExecutableDevelopmentCoverageV5.__new__(
        ExecutableDevelopmentCoverageV5
    )
    values: dict[str, object] = {
        "families": families,
        "source_registry_commitments": sources,
        "predecessor": predecessor,
        "hardlink_discrimination_sha256": hardlink,
        "promotion_history": history,
        "coverage_sha256": "0" * 64,
        "schema_version": COVERAGE_V5_SCHEMA_VERSION,
        "coverage_version": COVERAGE_V5_VERSION,
        "suite_id": COVERAGE_V5_SUITE_ID,
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
    digest = compute_executable_development_coverage_v5_sha256(
        _coverage_record(provisional)
    )
    return ExecutableDevelopmentCoverageV5(
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
            raise ExecutableDevelopmentCoverageV5Error(
                "v5 coverage JSON contains a duplicate object key"
            )
        result[key] = value
    return result


def _read_stable_regular(
    path: Path,
    maximum_bytes: int = MAXIMUM_COVERAGE_V5_CONFIG_BYTES,
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
        raise ExecutableDevelopmentCoverageV5Error(
            "cannot read v5 coverage as a stable regular file"
        ) from exc
    if payload is None:
        raise ExecutableDevelopmentCoverageV5Error(
            "v5 coverage config does not exist as a stable regular file"
        )
    return payload


def load_executable_development_coverage_v5(
    path: str | os.PathLike[str],
) -> ExecutableDevelopmentCoverageV5:
    """Load only the exact canonical checked v5 projection."""

    try:
        source = Path(os.fspath(path))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ExecutableDevelopmentCoverageV5Error(
            "v5 coverage config path is invalid"
        ) from exc
    payload = _read_stable_regular(source)
    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ExecutableDevelopmentCoverageV5Error(
                    "v5 coverage JSON contains non-finite number "
                    f"{token}"
                )
            ),
        )
        canonical = canonical_json_bytes(value) + b"\n"
    except ExecutableDevelopmentCoverageV5Error:
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
        raise ExecutableDevelopmentCoverageV5Error(
            "v5 coverage config is not strict canonical JSON"
        ) from exc
    if payload != canonical:
        raise ExecutableDevelopmentCoverageV5Error(
            "v5 coverage config is not canonical JSON plus LF"
        )
    expected = build_executable_development_coverage_v5()
    if payload != executable_development_coverage_v5_config_bytes():
        raise ExecutableDevelopmentCoverageV5Error(
            "checked v5 config differs from the central projection"
        )
    return expected


@lru_cache(maxsize=1)
def executable_development_coverage_v5_config_bytes() -> bytes:
    """Return immutable canonical bytes for deterministic publication."""

    return (
        canonical_json_bytes(
            build_executable_development_coverage_v5().to_hash_only_record()
        )
        + b"\n"
    )


__all__ = [
    "CANONICAL_FAMILY_ORDER",
    "COVERAGE_V5_CONFIG_RELATIVE_PATH",
    "COVERAGE_V5_SCHEMA_VERSION",
    "COVERAGE_V5_SUITE_ID",
    "COVERAGE_V5_VERSION",
    "FAMILY_COUNT",
    "FROZEN_COVERAGE_V5_SHA256",
    "FROZEN_JSONL_CSV_DISCRIMINATION_SHA256",
    "FROZEN_JSONL_CSV_TASK_SET_SHA256",
    "FROZEN_TWELFTH_CUMULATIVE_SUITE_SHA256",
    "FROZEN_TWELFTH_REGISTRY_SHA256",
    "INTEGRATED_FAMILY_COUNT",
    "INTEGRATED_TASK_COUNT",
    "JSONL_CSV_FAMILY_INDEX",
    "MAXIMUM_COVERAGE_V5_CONFIG_BYTES",
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
    "ExecutableDevelopmentCoverageV5",
    "ExecutableDevelopmentCoverageV5Error",
    "PredecessorCoverageV4Commitment",
    "build_executable_development_coverage_v5",
    "compute_executable_development_coverage_v5_sha256",
    "executable_development_coverage_v5_config_bytes",
    "load_executable_development_coverage_v5",
    "validate_executable_development_coverage_v5",
]
