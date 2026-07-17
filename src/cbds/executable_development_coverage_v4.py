"""Backward-linked v4 coverage lock for 500 development specifications.

Version 4 promotes only ``checksum-repair-plan`` from the version-3 planning
record.  It preserves the other 24 family values exactly, appends the live
eleventh registry, and turns the former singular archive promotion evidence
into an ordered history whose first entry is byte-for-byte equivalent to the
v3 evidence and whose second entry binds the checksum task set and
discrimination digest.

The record remains public method-development metadata.  It is not sealed,
scored, candidate-executable, model-selection eligible, or claim authorizing.
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
from .executable_checksum_repair_plan import (
    CHECKSUM_REPAIR_PLAN_ALLOWED_TOOLS,
    CHECKSUM_REPAIR_PLAN_FAMILY_ID,
    CHECKSUM_REPAIR_PLAN_FILESYSTEM_IDENTITY,
    CHECKSUM_REPAIR_PLAN_MANIFEST_LAYOUTS,
    CHECKSUM_REPAIR_PLAN_OUTPUT_IDENTITY,
    CHECKSUM_REPAIR_PLAN_REPAIR_POLICIES,
    compute_checksum_repair_plan_discrimination_sha256,
)
from .executable_development_coverage import (
    CoverageFamily,
    CoverageParameterAxis,
    SourceRegistryCommitment,
)
from .executable_static_eleventh_registry import (
    ELEVENTH_TRANCHE_ADDED_TASK_COUNT,
    ELEVENTH_TRANCHE_CUMULATIVE_TASK_COUNT,
    build_eleventh_tranche_task_registry,
)
from .executable_static_types import domain_sha256
from . import hash_only_report_publication as report_publication
from .manifests import ManifestValidationError, canonical_json_bytes


COVERAGE_V4_SCHEMA_VERSION: Final[str] = "4.0.0"
COVERAGE_V4_VERSION: Final[str] = "4.0.0"
COVERAGE_V4_SUITE_ID: Final[str] = (
    "cbds-executable-method-development-v4"
)
COVERAGE_V4_CONFIG_RELATIVE_PATH: Final[str] = (
    "configs/executable-method-development-coverage-v4.json"
)
MAXIMUM_COVERAGE_V4_CONFIG_BYTES: Final[int] = 256 * 1024

FAMILY_COUNT: Final[int] = 25
TASKS_PER_FAMILY: Final[int] = 20
TOTAL_TASK_COUNT: Final[int] = 500
INTEGRATED_FAMILY_COUNT: Final[int] = 20
INTEGRATED_TASK_COUNT: Final[int] = 400
PLANNED_FAMILY_COUNT: Final[int] = 5
PLANNED_TASK_COUNT: Final[int] = 100

CANONICAL_FAMILY_ORDER: Final[tuple[str, ...]] = (
    coverage_v3.CANONICAL_FAMILY_ORDER
)
CHECKSUM_FAMILY_INDEX: Final[int] = CANONICAL_FAMILY_ORDER.index(
    CHECKSUM_REPAIR_PLAN_FAMILY_ID
)

PREDECESSOR_COVERAGE_SHA256: Final[str] = (
    "b37f48c98e7216c78ddf74d0ce6f6d74cd095575f20f53de6bf30018b2180d79"
)
PREDECESSOR_CONFIG_BYTES_SHA256: Final[str] = (
    "de241ad1e4536fa595f99acf0ef05a3e423418876298c576abe87249c018bc0a"
)
PREDECESSOR_CONFIG_BYTE_COUNT: Final[int] = 23_943
PREDECESSOR_GIT_COMMIT: Final[str] = (
    "af6885da48d91c52d60c81f2c65440ff60b18712"
)

FROZEN_ELEVENTH_REGISTRY_SHA256: Final[str] = (
    "bd0c14880eb25fa80100c317fa41086c45c59147407a67f03981831bcfdfc100"
)
FROZEN_ELEVENTH_CUMULATIVE_SUITE_SHA256: Final[str] = (
    "f62ba1c1214fc48f194a5dea9c69c04962cc14dbdccfc38640cf4eee833018cb"
)
FROZEN_CHECKSUM_TASK_SET_SHA256: Final[str] = (
    "e52fb74ece2a94baa9bd1b2f6da25ca103839e1e9666361fe5406c34a36b9bb0"
)
FROZEN_CHECKSUM_DISCRIMINATION_SHA256: Final[str] = (
    "f71ba70f0a4d004bed235e897a73c1222c6d2687e4eeb842c008f7878e9457aa"
)
FROZEN_COVERAGE_V4_SHA256: Final[str] = (
    "1bd7a4b6ab721404f1d1eb7a64718ba7df783998bf16cd603afb86eb2420d67c"
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
    CHECKSUM_REPAIR_PLAN_FAMILY_ID,
    "planned",
    "integrated",
    "eleventh-tranche",
    FROZEN_CHECKSUM_TASK_SET_SHA256,
    FROZEN_CHECKSUM_DISCRIMINATION_SHA256,
)


class ExecutableDevelopmentCoverageV4Error(ValueError):
    """Raised when the v4 coverage projection is not exact."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class PredecessorCoverageV3Commitment:
    """Exact immutable identity of the superseded v3 coverage record."""

    coverage_sha256: str = PREDECESSOR_COVERAGE_SHA256
    config_bytes_sha256: str = PREDECESSOR_CONFIG_BYTES_SHA256
    config_byte_count: int = PREDECESSOR_CONFIG_BYTE_COUNT
    git_commit: str = PREDECESSOR_GIT_COMMIT
    coverage_version: str = coverage_v3.COVERAGE_V3_VERSION
    config_relative_path: str = coverage_v3.COVERAGE_V3_CONFIG_RELATIVE_PATH

    def __post_init__(self) -> None:
        if (
            type(self) is not PredecessorCoverageV3Commitment
            or self.coverage_sha256 != PREDECESSOR_COVERAGE_SHA256
            or self.config_bytes_sha256
            != PREDECESSOR_CONFIG_BYTES_SHA256
            or type(self.config_byte_count) is not int
            or self.config_byte_count != PREDECESSOR_CONFIG_BYTE_COUNT
            or type(self.git_commit) is not str
            or _COMMIT_RE.fullmatch(self.git_commit) is None
            or self.git_commit != PREDECESSOR_GIT_COMMIT
            or self.coverage_version != coverage_v3.COVERAGE_V3_VERSION
            or self.config_relative_path
            != coverage_v3.COVERAGE_V3_CONFIG_RELATIVE_PATH
        ):
            raise ExecutableDevelopmentCoverageV4Error(
                "v3 predecessor commitment is invalid"
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
    """One exact ordered family-promotion event."""

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
            )
            or not _is_sha256(self.task_set_sha256)
            or not _is_sha256(self.discrimination_sha256)
        ):
            raise ExecutableDevelopmentCoverageV4Error(
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
class ExecutableDevelopmentCoverageV4:
    families: tuple[CoverageFamily, ...]
    source_registry_commitments: tuple[SourceRegistryCommitment, ...]
    predecessor: PredecessorCoverageV3Commitment
    hardlink_discrimination_sha256: str
    promotion_history: tuple[
        CoveragePromotionEvidence, CoveragePromotionEvidence
    ]
    coverage_sha256: str
    schema_version: str = COVERAGE_V4_SCHEMA_VERSION
    coverage_version: str = COVERAGE_V4_VERSION
    suite_id: str = COVERAGE_V4_SUITE_ID
    public_method_development: bool = True
    sealed: bool = False
    scored: bool = False
    candidate_execution_authorized: bool = False
    scored_evaluation_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False
    independent_human_review_attested: bool = False

    def __post_init__(self) -> None:
        validate_executable_development_coverage_v4(self)

    def to_hash_only_record(self) -> dict[str, object]:
        validate_executable_development_coverage_v4(self)
        return _coverage_record(self)


def _promote_checksum_family(
    planned: CoverageFamily,
    task_set_sha256: str,
) -> CoverageFamily:
    if (
        type(planned) is not CoverageFamily
        or planned.family_id != CHECKSUM_REPAIR_PLAN_FAMILY_ID
        or planned.lifecycle_state != "planned"
        or planned.integrated_task_set_sha256 is not None
        or planned.parameter_axes
        != (
            CoverageParameterAxis(
                "manifest_layout",
                CHECKSUM_REPAIR_PLAN_MANIFEST_LAYOUTS,
            ),
            CoverageParameterAxis(
                "repair_policy",
                CHECKSUM_REPAIR_PLAN_REPAIR_POLICIES,
            ),
        )
        or planned.solution_track != "bash-native"
        or planned.allowed_tools != CHECKSUM_REPAIR_PLAN_ALLOWED_TOOLS
        or planned.filesystem_schema
        != CHECKSUM_REPAIR_PLAN_FILESYSTEM_IDENTITY
        or planned.output_contract != CHECKSUM_REPAIR_PLAN_OUTPUT_IDENTITY
        or task_set_sha256 != FROZEN_CHECKSUM_TASK_SET_SHA256
    ):
        raise ExecutableDevelopmentCoverageV4Error(
            "v3 checksum planning contract differs from the live family"
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


def _promotion_from_record(
    value: object,
) -> CoveragePromotionEvidence:
    if type(value) is not dict or set(value) != {
        "family_id",
        "old_lifecycle_state",
        "new_lifecycle_state",
        "source_tranche_id",
        "task_set_sha256",
        "discrimination_sha256",
    }:
        raise ExecutableDevelopmentCoverageV4Error(
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
        raise ExecutableDevelopmentCoverageV4Error(
            "internal promotion snapshot cannot be reconstructed"
        ) from exc


@lru_cache(maxsize=1)
def _live_component_snapshot_bytes() -> bytes:
    """Cache only canonical primitive evidence, never mutable objects."""

    predecessor = coverage_v3.build_executable_development_coverage_v3()
    predecessor_bytes = (
        coverage_v3.executable_development_coverage_v3_config_bytes()
    )
    if (
        predecessor.coverage_sha256 != PREDECESSOR_COVERAGE_SHA256
        or len(predecessor_bytes) != PREDECESSOR_CONFIG_BYTE_COUNT
        or sha256(predecessor_bytes).hexdigest()
        != PREDECESSOR_CONFIG_BYTES_SHA256
    ):
        raise ExecutableDevelopmentCoverageV4Error(
            "live v3 coverage differs from the frozen predecessor"
        )

    eleventh = build_eleventh_tranche_task_registry()
    if (
        eleventh.registry_sha256
        != FROZEN_ELEVENTH_REGISTRY_SHA256
        or eleventh.cumulative_suite_sha256
        != FROZEN_ELEVENTH_CUMULATIVE_SUITE_SHA256
        or len(eleventh.added_tasks)
        != ELEVENTH_TRANCHE_ADDED_TASK_COUNT
        or ELEVENTH_TRANCHE_CUMULATIVE_TASK_COUNT
        != INTEGRATED_TASK_COUNT
    ):
        raise ExecutableDevelopmentCoverageV4Error(
            "live eleventh registry differs from the frozen v4 source"
        )
    task_set_sha256 = coverage_v2._task_set_sha256(
        CHECKSUM_REPAIR_PLAN_FAMILY_ID,
        eleventh.added_tasks,
    )
    discrimination_sha256 = (
        compute_checksum_repair_plan_discrimination_sha256(
            eleventh.added_tasks
        )
    )
    if (
        task_set_sha256 != FROZEN_CHECKSUM_TASK_SET_SHA256
        or discrimination_sha256
        != FROZEN_CHECKSUM_DISCRIMINATION_SHA256
    ):
        raise ExecutableDevelopmentCoverageV4Error(
            "live checksum promotion evidence differs from v4"
        )

    planned = predecessor.families[CHECKSUM_FAMILY_INDEX]
    promoted = _promote_checksum_family(planned, task_set_sha256)
    families = (
        *predecessor.families[:CHECKSUM_FAMILY_INDEX],
        promoted,
        *predecessor.families[CHECKSUM_FAMILY_INDEX + 1 :],
    )
    if any(
        old != new
        for index, (old, new) in enumerate(
            zip(predecessor.families, families, strict=True)
        )
        if index != CHECKSUM_FAMILY_INDEX
    ):
        raise ExecutableDevelopmentCoverageV4Error(
            "a family outside the checksum promotion changed"
        )
    sources = (
        *predecessor.source_registry_commitments,
        SourceRegistryCommitment(
            "eleventh-tranche",
            len(eleventh.added_tasks),
            INTEGRATED_TASK_COUNT,
            eleventh.registry_sha256,
            eleventh.cumulative_suite_sha256,
        ),
    )
    archive = _promotion_from_record(
        predecessor.promotion_evidence.to_record()
    )
    checksum = CoveragePromotionEvidence(
        CHECKSUM_REPAIR_PLAN_FAMILY_ID,
        "planned",
        "integrated",
        "eleventh-tranche",
        task_set_sha256,
        discrimination_sha256,
    )
    return canonical_json_bytes(
        {
            "predecessor_families": [
                family.to_record() for family in predecessor.families
            ],
            "predecessor_sources": [
                source.to_record()
                for source in predecessor.source_registry_commitments
            ],
            "v4_families": [
                family.to_record() for family in families
            ],
            "v4_sources": [
                source.to_record() for source in sources
            ],
            "hardlink_discrimination_sha256": (
                predecessor.hardlink_discrimination_sha256
            ),
            "promotion_history": [
                archive.to_record(),
                checksum.to_record(),
            ],
        }
    )


def _component_snapshot() -> dict[str, object]:
    value = json.loads(_live_component_snapshot_bytes())
    if type(value) is not dict:
        raise ExecutableDevelopmentCoverageV4Error(
            "internal component snapshot is invalid"
        )
    return value


def _families_from_snapshot(
    value: object,
) -> tuple[CoverageFamily, ...]:
    if type(value) is not list:
        raise ExecutableDevelopmentCoverageV4Error(
            "internal family snapshot is invalid"
        )
    try:
        return tuple(
            coverage_v1._family_from_record(record) for record in value
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise ExecutableDevelopmentCoverageV4Error(
            "internal family snapshot cannot be reconstructed"
        ) from exc


def _sources_from_snapshot(
    value: object,
) -> tuple[SourceRegistryCommitment, ...]:
    if type(value) is not list:
        raise ExecutableDevelopmentCoverageV4Error(
            "internal source snapshot is invalid"
        )
    try:
        return tuple(
            coverage_v1._source_from_record(record) for record in value
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise ExecutableDevelopmentCoverageV4Error(
            "internal source snapshot cannot be reconstructed"
        ) from exc


def _live_v4_components() -> tuple[
    tuple[CoverageFamily, ...],
    tuple[SourceRegistryCommitment, ...],
    str,
    tuple[CoveragePromotionEvidence, CoveragePromotionEvidence],
]:
    """Return a fresh v4 object graph from immutable cached bytes."""

    snapshot = _component_snapshot()
    hardlink = snapshot.get("hardlink_discrimination_sha256")
    promotions = snapshot.get("promotion_history")
    if (
        type(hardlink) is not str
        or hardlink != coverage_v2.FROZEN_HARDLINK_DISCRIMINATION_SHA256
        or type(promotions) is not list
        or len(promotions) != 2
    ):
        raise ExecutableDevelopmentCoverageV4Error(
            "internal v4 evidence snapshot is invalid"
        )
    history = (
        _promotion_from_record(promotions[0]),
        _promotion_from_record(promotions[1]),
    )
    return (
        _families_from_snapshot(snapshot.get("v4_families")),
        _sources_from_snapshot(snapshot.get("v4_sources")),
        hardlink,
        history,
    )


def _coverage_record(
    coverage: ExecutableDevelopmentCoverageV4,
) -> dict[str, object]:
    return {
        "schema_version": coverage.schema_version,
        "coverage_version": coverage.coverage_version,
        "record_type": (
            "cbds.executable-method-development-coverage-hashes"
        ),
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
            source.to_record()
            for source in coverage.source_registry_commitments
        ],
        "families": [
            family.to_record() for family in coverage.families
        ],
        "hardlink_discrimination_sha256": (
            coverage.hardlink_discrimination_sha256
        ),
        "promotion_history": [
            evidence.to_record()
            for evidence in coverage.promotion_history
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


def compute_executable_development_coverage_v4_sha256(
    record: object,
) -> str:
    if type(record) is not dict:
        raise ExecutableDevelopmentCoverageV4Error(
            "v4 coverage hash input must be an exact object"
        )
    payload = dict(record)
    payload.pop("coverage_sha256", None)
    return domain_sha256(
        "cbds.executable-method-development-coverage.v4",
        payload,
    )


def validate_executable_development_coverage_v4(
    coverage: ExecutableDevelopmentCoverageV4,
) -> None:
    if type(coverage) is not ExecutableDevelopmentCoverageV4:
        raise ExecutableDevelopmentCoverageV4Error(
            "coverage must be an exact ExecutableDevelopmentCoverageV4"
        )
    if (
        coverage.schema_version != COVERAGE_V4_SCHEMA_VERSION
        or coverage.coverage_version != COVERAGE_V4_VERSION
        or coverage.suite_id != COVERAGE_V4_SUITE_ID
        or coverage.public_method_development is not True
        or any(
            getattr(coverage, name) is not False
            for name in _AUTHORITY_FALSE_FIELDS
        )
    ):
        raise ExecutableDevelopmentCoverageV4Error(
            "v4 metadata or authority boundary is invalid"
        )
    if type(coverage.predecessor) is not PredecessorCoverageV3Commitment:
        raise ExecutableDevelopmentCoverageV4Error(
            "v4 predecessor has the wrong exact type"
        )
    coverage.predecessor.__post_init__()
    if (
        type(coverage.promotion_history) is not tuple
        or len(coverage.promotion_history) != 2
        or any(
            type(item) is not CoveragePromotionEvidence
            for item in coverage.promotion_history
        )
    ):
        raise ExecutableDevelopmentCoverageV4Error(
            "v4 promotion history has the wrong exact shape"
        )
    for evidence in coverage.promotion_history:
        evidence.__post_init__()
    (
        expected_families,
        expected_sources,
        expected_hardlink,
        expected_history,
    ) = _live_v4_components()
    if (
        type(coverage.families) is not tuple
        or coverage.families != expected_families
        or type(coverage.source_registry_commitments) is not tuple
        or coverage.source_registry_commitments != expected_sources
        or coverage.hardlink_discrimination_sha256 != expected_hardlink
        or not _is_sha256(coverage.hardlink_discrimination_sha256)
        or coverage.promotion_history != expected_history
        or tuple(
            item.family_id for item in coverage.promotion_history
        )
        != (
            "compressed-archive-roundtrip-verify",
            CHECKSUM_REPAIR_PLAN_FAMILY_ID,
        )
    ):
        raise ExecutableDevelopmentCoverageV4Error(
            "v4 live families, sources, or history differ"
        )
    for family in coverage.families:
        family.__post_init__()
    for source in coverage.source_registry_commitments:
        source.__post_init__()
    if (
        len(coverage.families) != FAMILY_COUNT
        or tuple(family.family_id for family in coverage.families)
        != CANONICAL_FAMILY_ORDER
        or tuple(
            family.lifecycle_state for family in coverage.families
        )
        != ("integrated",) * INTEGRATED_FAMILY_COUNT
        + ("planned",) * PLANNED_FAMILY_COUNT
        or sum(family.task_count for family in coverage.families)
        != TOTAL_TASK_COUNT
        or len(coverage.source_registry_commitments) != 11
        or tuple(
            source.cumulative_task_count
            for source in coverage.source_registry_commitments
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
        )
        or coverage.source_registry_commitments[-1].tranche_id
        != "eleventh-tranche"
        or coverage.source_registry_commitments[-1].registry_sha256
        != FROZEN_ELEVENTH_REGISTRY_SHA256
        or coverage.source_registry_commitments[
            -1
        ].cumulative_suite_sha256
        != FROZEN_ELEVENTH_CUMULATIVE_SUITE_SHA256
    ):
        raise ExecutableDevelopmentCoverageV4Error(
            "v4 coverage partition, source chain, or order is invalid"
        )
    record = _coverage_record(coverage)
    if (
        not _is_sha256(coverage.coverage_sha256)
        or coverage.coverage_sha256 != FROZEN_COVERAGE_V4_SHA256
        or coverage.coverage_sha256
        != compute_executable_development_coverage_v4_sha256(record)
    ):
        raise ExecutableDevelopmentCoverageV4Error(
            "v4 coverage digest is invalid"
        )


def build_executable_development_coverage_v4(
) -> ExecutableDevelopmentCoverageV4:
    families, sources, hardlink, history = _live_v4_components()
    predecessor = PredecessorCoverageV3Commitment()
    provisional = ExecutableDevelopmentCoverageV4.__new__(
        ExecutableDevelopmentCoverageV4
    )
    values: dict[str, object] = {
        "families": families,
        "source_registry_commitments": sources,
        "predecessor": predecessor,
        "hardlink_discrimination_sha256": hardlink,
        "promotion_history": history,
        "coverage_sha256": "0" * 64,
        "schema_version": COVERAGE_V4_SCHEMA_VERSION,
        "coverage_version": COVERAGE_V4_VERSION,
        "suite_id": COVERAGE_V4_SUITE_ID,
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
    digest = compute_executable_development_coverage_v4_sha256(
        _coverage_record(provisional)
    )
    return ExecutableDevelopmentCoverageV4(
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
            raise ExecutableDevelopmentCoverageV4Error(
                "v4 coverage JSON contains a duplicate object key"
            )
        result[key] = value
    return result


def _read_stable_regular(
    path: Path,
    maximum_bytes: int = MAXIMUM_COVERAGE_V4_CONFIG_BYTES,
) -> bytes:
    try:
        payload = report_publication.read_existing_regular(
            path,
            maximum_bytes,
        )
    except (
        report_publication.HashOnlyReportPublicationError,
        OSError,
        TypeError,
        ValueError,
        UnicodeError,
    ) as exc:
        raise ExecutableDevelopmentCoverageV4Error(
            "cannot read v4 coverage as a stable regular file"
        ) from exc
    if payload is None:
        raise ExecutableDevelopmentCoverageV4Error(
            "v4 coverage config does not exist as a stable regular file"
        )
    return payload


def load_executable_development_coverage_v4(
    path: str | os.PathLike[str],
) -> ExecutableDevelopmentCoverageV4:
    """Load only the exact canonical checked v4 projection."""

    try:
        source = Path(os.fspath(path))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ExecutableDevelopmentCoverageV4Error(
            "v4 coverage config path is invalid"
        ) from exc
    payload = _read_stable_regular(source)
    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ExecutableDevelopmentCoverageV4Error(
                    "v4 coverage JSON contains non-finite number "
                    f"{token}"
                )
            ),
        )
        canonical = canonical_json_bytes(value) + b"\n"
    except ExecutableDevelopmentCoverageV4Error:
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
        raise ExecutableDevelopmentCoverageV4Error(
            "v4 coverage config is not strict canonical JSON"
        ) from exc
    if payload != canonical:
        raise ExecutableDevelopmentCoverageV4Error(
            "v4 coverage config is not canonical JSON plus LF"
        )
    expected = build_executable_development_coverage_v4()
    if payload != executable_development_coverage_v4_config_bytes():
        raise ExecutableDevelopmentCoverageV4Error(
            "checked v4 config differs from the central projection"
        )
    return expected


@lru_cache(maxsize=1)
def executable_development_coverage_v4_config_bytes() -> bytes:
    """Return cached immutable canonical bytes for deterministic publication."""

    return (
        canonical_json_bytes(
            build_executable_development_coverage_v4()
            .to_hash_only_record()
        )
        + b"\n"
    )


__all__ = [
    "CANONICAL_FAMILY_ORDER",
    "CHECKSUM_FAMILY_INDEX",
    "COVERAGE_V4_CONFIG_RELATIVE_PATH",
    "COVERAGE_V4_SCHEMA_VERSION",
    "COVERAGE_V4_SUITE_ID",
    "COVERAGE_V4_VERSION",
    "FAMILY_COUNT",
    "FROZEN_CHECKSUM_DISCRIMINATION_SHA256",
    "FROZEN_CHECKSUM_TASK_SET_SHA256",
    "FROZEN_COVERAGE_V4_SHA256",
    "FROZEN_ELEVENTH_CUMULATIVE_SUITE_SHA256",
    "FROZEN_ELEVENTH_REGISTRY_SHA256",
    "INTEGRATED_FAMILY_COUNT",
    "INTEGRATED_TASK_COUNT",
    "MAXIMUM_COVERAGE_V4_CONFIG_BYTES",
    "PLANNED_FAMILY_COUNT",
    "PLANNED_TASK_COUNT",
    "PREDECESSOR_CONFIG_BYTE_COUNT",
    "PREDECESSOR_CONFIG_BYTES_SHA256",
    "PREDECESSOR_COVERAGE_SHA256",
    "PREDECESSOR_GIT_COMMIT",
    "TASKS_PER_FAMILY",
    "TOTAL_TASK_COUNT",
    "CoveragePromotionEvidence",
    "ExecutableDevelopmentCoverageV4",
    "ExecutableDevelopmentCoverageV4Error",
    "PredecessorCoverageV3Commitment",
    "build_executable_development_coverage_v4",
    "compute_executable_development_coverage_v4_sha256",
    "executable_development_coverage_v4_config_bytes",
    "load_executable_development_coverage_v4",
    "validate_executable_development_coverage_v4",
]
