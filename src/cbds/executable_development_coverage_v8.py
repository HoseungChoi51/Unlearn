"""Backward-linked v8 coverage lock for 500 development specifications.

Version 8 promotes only ``process-lifecycle-delta`` from the v7 planning
record.  The other 24 family values, first fourteen source commitments, and
first five promotion-history records remain exact.  The fifteenth registry
and family-local task/discrimination identities are re-derived from live
method-development builders before admission.

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
from . import executable_development_coverage_v6 as coverage_v6
from . import executable_development_coverage_v7 as coverage_v7
from .executable_development_coverage import (
    CoverageFamily,
    CoverageParameterAxis,
    SourceRegistryCommitment,
)
from .executable_process_lifecycle_delta import (
    PROCESS_LIFECYCLE_DELTA_ALLOWED_TOOLS,
    PROCESS_LIFECYCLE_DELTA_FAMILY_ID,
    PROCESS_LIFECYCLE_DELTA_FILESYSTEM_IDENTITY,
    PROCESS_LIFECYCLE_DELTA_OUTPUT_IDENTITY,
    PROCESS_LIFECYCLE_DELTA_SELECTION_POLICIES,
    PROCESS_LIFECYCLE_DELTA_SNAPSHOT_PAIRS,
    compute_process_lifecycle_delta_discrimination_sha256,
)
from .executable_static_fifteenth_registry import (
    FIFTEENTH_TRANCHE_ADDED_TASK_COUNT,
    FIFTEENTH_TRANCHE_CUMULATIVE_TASK_COUNT,
    FROZEN_FIFTEENTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_FIFTEENTH_REGISTRY_SHA256,
    build_fifteenth_tranche_task_registry,
)
from .executable_static_types import domain_sha256
from . import hash_only_report_publication as report_publication
from .manifests import ManifestValidationError, canonical_json_bytes


COVERAGE_V8_SCHEMA_VERSION: Final[str] = "8.0.0"
COVERAGE_V8_VERSION: Final[str] = "8.0.0"
COVERAGE_V8_SUITE_ID: Final[str] = "cbds-executable-method-development-v8"
COVERAGE_V8_CONFIG_RELATIVE_PATH: Final[str] = (
    "configs/executable-method-development-coverage-v8.json"
)
MAXIMUM_COVERAGE_V8_CONFIG_BYTES: Final[int] = 256 * 1024

FAMILY_COUNT: Final[int] = 25
TASKS_PER_FAMILY: Final[int] = 20
TOTAL_TASK_COUNT: Final[int] = 500
INTEGRATED_FAMILY_COUNT: Final[int] = 24
INTEGRATED_TASK_COUNT: Final[int] = 480
PLANNED_FAMILY_COUNT: Final[int] = 1
PLANNED_TASK_COUNT: Final[int] = 20

CANONICAL_FAMILY_ORDER: Final[tuple[str, ...]] = (
    coverage_v7.CANONICAL_FAMILY_ORDER
)
PROCESS_LIFECYCLE_FAMILY_INDEX: Final[int] = CANONICAL_FAMILY_ORDER.index(
    PROCESS_LIFECYCLE_DELTA_FAMILY_ID
)
NEXT_PLANNED_FAMILY_ID: Final[str] = "symlink-aware-tree-reconcile"

PREDECESSOR_COVERAGE_SHA256: Final[str] = (
    "177a97767a528db74951a191282f6d719a34c8a136a21086940dfbd92e5bb569"
)
PREDECESSOR_CONFIG_BYTES_SHA256: Final[str] = (
    "3742f632c7b5b18f8851d8ce198fe6eebd6ae6dbb1e3cf68a37633d67452f7bc"
)
PREDECESSOR_CONFIG_BYTE_COUNT: Final[int] = 26_558
PREDECESSOR_GIT_COMMIT: Final[str] = (
    "199eba7759cf49215a4e1da09dc59d2c175ee41f"
)

# Frozen from the accepted core/canary and catalog/report chain.
FROZEN_PROCESS_LIFECYCLE_TASK_SET_SHA256: Final[str] = (
    "2add107b1b16270837968e477662f721faef4ea32b4432b5efe41c5af8097d4d"
)
FROZEN_PROCESS_LIFECYCLE_DISCRIMINATION_SHA256: Final[str] = (
    "1a94ccdd0d75698973f172daa5a90e660747718969b05f0d6b414ac934c7e383"
)
FROZEN_COVERAGE_V8_SHA256: Final[str] = (
    "606ba0a90adc8f19cafd7495ab24ff117f31edb653b4b3cf8b6917a14b70ad05"
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
    "nested-json-schema-migration",
    "planned",
    "integrated",
    "thirteenth-tranche",
    coverage_v6.FROZEN_NESTED_JSON_TASK_SET_SHA256,
    coverage_v6.FROZEN_NESTED_JSON_DISCRIMINATION_SHA256,
)
_DEPENDENCY_DAG_PROMOTION_VALUES: Final[tuple[str, ...]] = (
    "dependency-dag-execution-plan",
    "planned",
    "integrated",
    "fourteenth-tranche",
    coverage_v7.FROZEN_DEPENDENCY_DAG_TASK_SET_SHA256,
    coverage_v7.FROZEN_DEPENDENCY_DAG_DISCRIMINATION_SHA256,
)
_PROCESS_LIFECYCLE_PROMOTION_VALUES: Final[tuple[str, ...]] = (
    PROCESS_LIFECYCLE_DELTA_FAMILY_ID,
    "planned",
    "integrated",
    "fifteenth-tranche",
    FROZEN_PROCESS_LIFECYCLE_TASK_SET_SHA256,
    FROZEN_PROCESS_LIFECYCLE_DISCRIMINATION_SHA256,
)


class ExecutableDevelopmentCoverageV8Error(ValueError):
    """Raised when the v8 coverage projection is not exact."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class PredecessorCoverageV7Commitment:
    """Exact identity of the superseded v7 checked artifact."""

    coverage_sha256: str = PREDECESSOR_COVERAGE_SHA256
    config_bytes_sha256: str = PREDECESSOR_CONFIG_BYTES_SHA256
    config_byte_count: int = PREDECESSOR_CONFIG_BYTE_COUNT
    git_commit: str = PREDECESSOR_GIT_COMMIT
    coverage_version: str = coverage_v7.COVERAGE_V7_VERSION
    config_relative_path: str = coverage_v7.COVERAGE_V7_CONFIG_RELATIVE_PATH

    def __post_init__(self) -> None:
        if (
            type(self) is not PredecessorCoverageV7Commitment
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
            or self.coverage_version != coverage_v7.COVERAGE_V7_VERSION
            or type(self.config_relative_path) is not str
            or self.config_relative_path
            != coverage_v7.COVERAGE_V7_CONFIG_RELATIVE_PATH
        ):
            raise ExecutableDevelopmentCoverageV8Error(
                "v7 predecessor commitment is invalid"
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
                _DEPENDENCY_DAG_PROMOTION_VALUES,
                _PROCESS_LIFECYCLE_PROMOTION_VALUES,
            )
            or not _is_sha256(self.task_set_sha256)
            or not _is_sha256(self.discrimination_sha256)
        ):
            raise ExecutableDevelopmentCoverageV8Error(
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
class ExecutableDevelopmentCoverageV8:
    families: tuple[CoverageFamily, ...]
    source_registry_commitments: tuple[SourceRegistryCommitment, ...]
    predecessor: PredecessorCoverageV7Commitment
    hardlink_discrimination_sha256: str
    promotion_history: tuple[
        CoveragePromotionEvidence,
        CoveragePromotionEvidence,
        CoveragePromotionEvidence,
        CoveragePromotionEvidence,
        CoveragePromotionEvidence,
        CoveragePromotionEvidence,
    ]
    coverage_sha256: str
    schema_version: str = COVERAGE_V8_SCHEMA_VERSION
    coverage_version: str = COVERAGE_V8_VERSION
    suite_id: str = COVERAGE_V8_SUITE_ID
    public_method_development: bool = True
    sealed: bool = False
    scored: bool = False
    candidate_execution_authorized: bool = False
    scored_evaluation_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False
    independent_human_review_attested: bool = False

    def __post_init__(self) -> None:
        validate_executable_development_coverage_v8(self)

    def to_hash_only_record(self) -> dict[str, object]:
        validate_executable_development_coverage_v8(self)
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
        raise ExecutableDevelopmentCoverageV8Error(
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
        raise ExecutableDevelopmentCoverageV8Error(
            "internal promotion snapshot cannot be reconstructed"
        ) from exc


def _promote_process_lifecycle_family(
    planned: CoverageFamily,
    task_set_sha256: str,
) -> CoverageFamily:
    expected_axes = (
        CoverageParameterAxis(
            "snapshot_pair",
            PROCESS_LIFECYCLE_DELTA_SNAPSHOT_PAIRS,
        ),
        CoverageParameterAxis(
            "selection_policy",
            PROCESS_LIFECYCLE_DELTA_SELECTION_POLICIES,
        ),
    )
    if (
        type(planned) is not CoverageFamily
        or planned.family_id != PROCESS_LIFECYCLE_DELTA_FAMILY_ID
        or planned.lifecycle_state != "planned"
        or planned.integrated_task_set_sha256 is not None
        or planned.parameter_axes != expected_axes
        or planned.solution_track != "bash-native"
        or planned.allowed_tools != PROCESS_LIFECYCLE_DELTA_ALLOWED_TOOLS
        or planned.filesystem_schema
        != PROCESS_LIFECYCLE_DELTA_FILESYSTEM_IDENTITY
        or planned.output_contract
        != PROCESS_LIFECYCLE_DELTA_OUTPUT_IDENTITY
        or task_set_sha256 != FROZEN_PROCESS_LIFECYCLE_TASK_SET_SHA256
    ):
        raise ExecutableDevelopmentCoverageV8Error(
            "v7 process-lifecycle planning contract differs from the live "
            "family"
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

    predecessor = coverage_v7.build_executable_development_coverage_v7()
    predecessor_bytes = (
        coverage_v7.executable_development_coverage_v7_config_bytes()
    )
    if (
        predecessor.coverage_sha256 != PREDECESSOR_COVERAGE_SHA256
        or len(predecessor_bytes) != PREDECESSOR_CONFIG_BYTE_COUNT
        or sha256(predecessor_bytes).hexdigest()
        != PREDECESSOR_CONFIG_BYTES_SHA256
    ):
        raise ExecutableDevelopmentCoverageV8Error(
            "live v7 coverage differs from the frozen predecessor"
        )
    fifteenth = build_fifteenth_tranche_task_registry()
    if (
        fifteenth.registry_sha256
        != FROZEN_FIFTEENTH_REGISTRY_SHA256
        or fifteenth.cumulative_suite_sha256
        != FROZEN_FIFTEENTH_CUMULATIVE_SUITE_SHA256
        or len(fifteenth.added_tasks)
        != FIFTEENTH_TRANCHE_ADDED_TASK_COUNT
        or FIFTEENTH_TRANCHE_CUMULATIVE_TASK_COUNT
        != INTEGRATED_TASK_COUNT
    ):
        raise ExecutableDevelopmentCoverageV8Error(
            "live fifteenth registry differs from the frozen v8 source"
        )
    task_set_sha256 = coverage_v2._task_set_sha256(
        PROCESS_LIFECYCLE_DELTA_FAMILY_ID,
        fifteenth.added_tasks,
    )
    discrimination_sha256 = (
        compute_process_lifecycle_delta_discrimination_sha256(
            fifteenth.added_tasks
        )
    )
    if (
        task_set_sha256 != FROZEN_PROCESS_LIFECYCLE_TASK_SET_SHA256
        or discrimination_sha256
        != FROZEN_PROCESS_LIFECYCLE_DISCRIMINATION_SHA256
    ):
        raise ExecutableDevelopmentCoverageV8Error(
            "live process-lifecycle promotion evidence differs from v8"
        )
    promoted = _promote_process_lifecycle_family(
        predecessor.families[PROCESS_LIFECYCLE_FAMILY_INDEX],
        task_set_sha256,
    )
    families = (
        *predecessor.families[:PROCESS_LIFECYCLE_FAMILY_INDEX],
        promoted,
        *predecessor.families[PROCESS_LIFECYCLE_FAMILY_INDEX + 1 :],
    )
    if any(
        old != new
        for index, (old, new) in enumerate(
            zip(predecessor.families, families, strict=True)
        )
        if index != PROCESS_LIFECYCLE_FAMILY_INDEX
    ):
        raise ExecutableDevelopmentCoverageV8Error(
            "a family outside the process-lifecycle promotion changed"
        )
    sources = (
        *predecessor.source_registry_commitments,
        SourceRegistryCommitment(
            "fifteenth-tranche",
            len(fifteenth.added_tasks),
            INTEGRATED_TASK_COUNT,
            fifteenth.registry_sha256,
            fifteenth.cumulative_suite_sha256,
        ),
    )
    prior_history = tuple(
        _promotion_from_record(item.to_record())
        for item in predecessor.promotion_history
    )
    promotion = CoveragePromotionEvidence(
        PROCESS_LIFECYCLE_DELTA_FAMILY_ID,
        "planned",
        "integrated",
        "fifteenth-tranche",
        task_set_sha256,
        discrimination_sha256,
    )
    return canonical_json_bytes(
        {
            "v8_families": [item.to_record() for item in families],
            "v8_sources": [item.to_record() for item in sources],
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
        raise ExecutableDevelopmentCoverageV8Error(
            "internal component snapshot is invalid"
        )
    return value


def _families_from_snapshot(value: object) -> tuple[CoverageFamily, ...]:
    if type(value) is not list:
        raise ExecutableDevelopmentCoverageV8Error(
            "internal family snapshot is invalid"
        )
    try:
        return tuple(coverage_v1._family_from_record(item) for item in value)
    except (AttributeError, TypeError, ValueError) as exc:
        raise ExecutableDevelopmentCoverageV8Error(
            "internal family snapshot cannot be reconstructed"
        ) from exc


def _sources_from_snapshot(
    value: object,
) -> tuple[SourceRegistryCommitment, ...]:
    if type(value) is not list:
        raise ExecutableDevelopmentCoverageV8Error(
            "internal source snapshot is invalid"
        )
    try:
        return tuple(coverage_v1._source_from_record(item) for item in value)
    except (AttributeError, TypeError, ValueError) as exc:
        raise ExecutableDevelopmentCoverageV8Error(
            "internal source snapshot cannot be reconstructed"
        ) from exc


def _live_v8_components() -> tuple[
    tuple[CoverageFamily, ...],
    tuple[SourceRegistryCommitment, ...],
    str,
    tuple[
        CoveragePromotionEvidence,
        CoveragePromotionEvidence,
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
        or len(promotions) != 6
    ):
        raise ExecutableDevelopmentCoverageV8Error(
            "internal v8 evidence snapshot is invalid"
        )
    history = tuple(_promotion_from_record(item) for item in promotions)
    return (
        _families_from_snapshot(snapshot.get("v8_families")),
        _sources_from_snapshot(snapshot.get("v8_sources")),
        hardlink,
        history,  # type: ignore[return-value]
    )


def _coverage_record(
    coverage: ExecutableDevelopmentCoverageV8,
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


def compute_executable_development_coverage_v8_sha256(
    record: object,
) -> str:
    if type(record) is not dict:
        raise ExecutableDevelopmentCoverageV8Error(
            "v8 coverage hash input must be an exact object"
        )
    payload = dict(record)
    payload.pop("coverage_sha256", None)
    return domain_sha256(
        "cbds.executable-method-development-coverage.v8",
        payload,
    )


def validate_executable_development_coverage_v8(
    coverage: ExecutableDevelopmentCoverageV8,
) -> None:
    if type(coverage) is not ExecutableDevelopmentCoverageV8:
        raise ExecutableDevelopmentCoverageV8Error(
            "coverage must be an exact ExecutableDevelopmentCoverageV8"
        )
    if (
        type(coverage.schema_version) is not str
        or coverage.schema_version != COVERAGE_V8_SCHEMA_VERSION
        or type(coverage.coverage_version) is not str
        or coverage.coverage_version != COVERAGE_V8_VERSION
        or type(coverage.suite_id) is not str
        or coverage.suite_id != COVERAGE_V8_SUITE_ID
        or coverage.public_method_development is not True
        or any(
            getattr(coverage, name) is not False
            for name in _AUTHORITY_FALSE_FIELDS
        )
        or type(coverage.predecessor)
        is not PredecessorCoverageV7Commitment
    ):
        raise ExecutableDevelopmentCoverageV8Error(
            "v8 metadata, predecessor, or authority boundary is invalid"
        )
    coverage.predecessor.__post_init__()
    expected_families, expected_sources, hardlink, history = (
        _live_v8_components()
    )
    if (
        type(coverage.families) is not tuple
        or any(type(item) is not CoverageFamily for item in coverage.families)
        or coverage.families != expected_families
        or type(coverage.source_registry_commitments) is not tuple
        or any(
            type(item) is not SourceRegistryCommitment
            for item in coverage.source_registry_commitments
        )
        or coverage.source_registry_commitments != expected_sources
        or type(coverage.hardlink_discrimination_sha256) is not str
        or coverage.hardlink_discrimination_sha256 != hardlink
        or not _is_sha256(coverage.hardlink_discrimination_sha256)
        or type(coverage.promotion_history) is not tuple
        or coverage.promotion_history != history
        or len(coverage.promotion_history) != 6
        or any(
            type(item) is not CoveragePromotionEvidence
            for item in coverage.promotion_history
        )
    ):
        raise ExecutableDevelopmentCoverageV8Error(
            "v8 live families, sources, or history differ"
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
        or len(coverage.source_registry_commitments) != 15
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
            460,
            480,
        )
        or coverage.source_registry_commitments[-1].tranche_id
        != "fifteenth-tranche"
        or coverage.source_registry_commitments[-1].registry_sha256
        != FROZEN_FIFTEENTH_REGISTRY_SHA256
        or coverage.source_registry_commitments[
            -1
        ].cumulative_suite_sha256
        != FROZEN_FIFTEENTH_CUMULATIVE_SUITE_SHA256
        or tuple(item.family_id for item in coverage.promotion_history)
        != (
            "compressed-archive-roundtrip-verify",
            "checksum-repair-plan",
            "jsonl-csv-enrichment-compose",
            "nested-json-schema-migration",
            "dependency-dag-execution-plan",
            PROCESS_LIFECYCLE_DELTA_FAMILY_ID,
        )
    ):
        raise ExecutableDevelopmentCoverageV8Error(
            "v8 coverage partition, source chain, or order is invalid"
        )
    record = _coverage_record(coverage)
    if (
        not _is_sha256(coverage.coverage_sha256)
        or coverage.coverage_sha256 != FROZEN_COVERAGE_V8_SHA256
        or coverage.coverage_sha256
        != compute_executable_development_coverage_v8_sha256(record)
    ):
        raise ExecutableDevelopmentCoverageV8Error(
            "v8 coverage digest is invalid"
        )


def build_executable_development_coverage_v8(
) -> ExecutableDevelopmentCoverageV8:
    families, sources, hardlink, history = _live_v8_components()
    predecessor = PredecessorCoverageV7Commitment()
    provisional = ExecutableDevelopmentCoverageV8.__new__(
        ExecutableDevelopmentCoverageV8
    )
    values: dict[str, object] = {
        "families": families,
        "source_registry_commitments": sources,
        "predecessor": predecessor,
        "hardlink_discrimination_sha256": hardlink,
        "promotion_history": history,
        "coverage_sha256": "0" * 64,
        "schema_version": COVERAGE_V8_SCHEMA_VERSION,
        "coverage_version": COVERAGE_V8_VERSION,
        "suite_id": COVERAGE_V8_SUITE_ID,
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
    digest = compute_executable_development_coverage_v8_sha256(
        _coverage_record(provisional)
    )
    return ExecutableDevelopmentCoverageV8(
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
            raise ExecutableDevelopmentCoverageV8Error(
                "v8 coverage JSON contains a duplicate object key"
            )
        result[key] = value
    return result


def _read_stable_regular(
    path: Path,
    maximum_bytes: int = MAXIMUM_COVERAGE_V8_CONFIG_BYTES,
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
        raise ExecutableDevelopmentCoverageV8Error(
            "cannot read v8 coverage as a stable regular file"
        ) from exc
    if payload is None:
        raise ExecutableDevelopmentCoverageV8Error(
            "v8 coverage config does not exist as a stable regular file"
        )
    return payload


def load_executable_development_coverage_v8(
    path: str | os.PathLike[str],
) -> ExecutableDevelopmentCoverageV8:
    """Load only the exact canonical checked v8 projection."""

    try:
        source = Path(os.fspath(path))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ExecutableDevelopmentCoverageV8Error(
            "v8 coverage config path is invalid"
        ) from exc
    payload = _read_stable_regular(source)
    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ExecutableDevelopmentCoverageV8Error(
                    "v8 coverage JSON contains non-finite number "
                    f"{token}"
                )
            ),
        )
        canonical = canonical_json_bytes(value) + b"\n"
    except ExecutableDevelopmentCoverageV8Error:
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
        raise ExecutableDevelopmentCoverageV8Error(
            "v8 coverage config is not strict canonical JSON"
        ) from exc
    if payload != canonical:
        raise ExecutableDevelopmentCoverageV8Error(
            "v8 coverage config is not canonical JSON plus LF"
        )
    expected = build_executable_development_coverage_v8()
    if payload != executable_development_coverage_v8_config_bytes():
        raise ExecutableDevelopmentCoverageV8Error(
            "checked v8 config differs from the central projection"
        )
    return expected


@lru_cache(maxsize=1)
def executable_development_coverage_v8_config_bytes() -> bytes:
    """Return immutable canonical bytes for deterministic publication."""

    return (
        canonical_json_bytes(
            build_executable_development_coverage_v8().to_hash_only_record()
        )
        + b"\n"
    )


__all__ = [
    "CANONICAL_FAMILY_ORDER",
    "COVERAGE_V8_CONFIG_RELATIVE_PATH",
    "COVERAGE_V8_SCHEMA_VERSION",
    "COVERAGE_V8_SUITE_ID",
    "COVERAGE_V8_VERSION",
    "FAMILY_COUNT",
    "FROZEN_COVERAGE_V8_SHA256",
    "FROZEN_FIFTEENTH_CUMULATIVE_SUITE_SHA256",
    "FROZEN_FIFTEENTH_REGISTRY_SHA256",
    "FROZEN_PROCESS_LIFECYCLE_DISCRIMINATION_SHA256",
    "FROZEN_PROCESS_LIFECYCLE_TASK_SET_SHA256",
    "INTEGRATED_FAMILY_COUNT",
    "INTEGRATED_TASK_COUNT",
    "MAXIMUM_COVERAGE_V8_CONFIG_BYTES",
    "NEXT_PLANNED_FAMILY_ID",
    "PLANNED_FAMILY_COUNT",
    "PLANNED_TASK_COUNT",
    "PREDECESSOR_CONFIG_BYTE_COUNT",
    "PREDECESSOR_CONFIG_BYTES_SHA256",
    "PREDECESSOR_COVERAGE_SHA256",
    "PREDECESSOR_GIT_COMMIT",
    "PROCESS_LIFECYCLE_FAMILY_INDEX",
    "TASKS_PER_FAMILY",
    "TOTAL_TASK_COUNT",
    "CoveragePromotionEvidence",
    "ExecutableDevelopmentCoverageV8",
    "ExecutableDevelopmentCoverageV8Error",
    "PredecessorCoverageV7Commitment",
    "build_executable_development_coverage_v8",
    "compute_executable_development_coverage_v8_sha256",
    "executable_development_coverage_v8_config_bytes",
    "load_executable_development_coverage_v8",
    "validate_executable_development_coverage_v8",
]
