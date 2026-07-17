"""Backward-linked v3 coverage lock for 500 development specifications.

Version 3 promotes only ``compressed-archive-roundtrip-verify`` from the
version-2 planning record.  It preserves the other 24 family values exactly,
appends the live tenth registry, retains the prior hardlink discrimination
commitment, and adds generic promotion evidence binding the archive task set
to its family-local discrimination digest.

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
from .executable_compressed_archive_roundtrip_verify import (
    COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_ALLOWED_TOOLS,
    COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_COMPRESSION_FORMATS,
    COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_FAMILY_ID,
    COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_FILESYSTEM_IDENTITY,
    COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_OUTPUT_IDENTITY,
    COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_VERIFICATION_POLICIES,
    compute_compressed_archive_roundtrip_verify_discrimination_sha256,
)
from .executable_development_coverage import (
    CoverageFamily,
    CoverageParameterAxis,
    SourceRegistryCommitment,
)
from .executable_static_tenth_registry import (
    TENTH_TRANCHE_ADDED_TASK_COUNT,
    TENTH_TRANCHE_CUMULATIVE_TASK_COUNT,
    build_tenth_tranche_task_registry,
)
from .executable_static_types import domain_sha256
from . import hash_only_report_publication as report_publication
from .manifests import ManifestValidationError, canonical_json_bytes


COVERAGE_V3_SCHEMA_VERSION: Final[str] = "3.0.0"
COVERAGE_V3_VERSION: Final[str] = "3.0.0"
COVERAGE_V3_SUITE_ID: Final[str] = (
    "cbds-executable-method-development-v3"
)
COVERAGE_V3_CONFIG_RELATIVE_PATH: Final[str] = (
    "configs/executable-method-development-coverage-v3.json"
)
MAXIMUM_COVERAGE_V3_CONFIG_BYTES: Final[int] = 256 * 1024

FAMILY_COUNT: Final[int] = 25
TASKS_PER_FAMILY: Final[int] = 20
TOTAL_TASK_COUNT: Final[int] = 500
INTEGRATED_FAMILY_COUNT: Final[int] = 19
INTEGRATED_TASK_COUNT: Final[int] = 380
PLANNED_FAMILY_COUNT: Final[int] = 6
PLANNED_TASK_COUNT: Final[int] = 120

CANONICAL_FAMILY_ORDER: Final[tuple[str, ...]] = (
    coverage_v2.CANONICAL_FAMILY_ORDER
)
ARCHIVE_FAMILY_INDEX: Final[int] = CANONICAL_FAMILY_ORDER.index(
    COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_FAMILY_ID
)

PREDECESSOR_COVERAGE_SHA256: Final[str] = (
    "7406480a1dc06bc99d1e36fde1a328a490d6cc8d6b96ee38c924a902acbf9abd"
)
PREDECESSOR_CONFIG_BYTES_SHA256: Final[str] = (
    "b7c130b4b6436eb833548e69261da3ded1519c9680d82dc1e59063dd4af92ac9"
)
PREDECESSOR_CONFIG_BYTE_COUNT: Final[int] = 23_267
PREDECESSOR_GIT_COMMIT: Final[str] = (
    "33119f824e8ab0d4d60538d58ba9e5c477e4804d"
)

FROZEN_TENTH_REGISTRY_SHA256: Final[str] = (
    "0d07fd82de275ffd9dc274b97a6fa02fdd0620f83d5ee90a2bea0ad64f06f0ab"
)
FROZEN_TENTH_CUMULATIVE_SUITE_SHA256: Final[str] = (
    "629119116c53a0be2cc7cacb5461ae13de7d50f29b0a129707a840089ab48d2f"
)
FROZEN_ARCHIVE_TASK_SET_SHA256: Final[str] = (
    "450ba507f0672e3a47ca6d495a6553d07294c605f94b3c5f03aa111d42bf771a"
)
FROZEN_ARCHIVE_DISCRIMINATION_SHA256: Final[str] = (
    "ae95eef5802c010e70e338d257f5d0f3d01a39fa5cf471f945a8b75f554faa21"
)
FROZEN_COVERAGE_V3_SHA256: Final[str] = (
    "b37f48c98e7216c78ddf74d0ce6f6d74cd095575f20f53de6bf30018b2180d79"
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


class ExecutableDevelopmentCoverageV3Error(ValueError):
    """Raised when the v3 coverage projection is not exact."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class PredecessorCoverageV2Commitment:
    """Exact immutable identity of the superseded v2 planning record."""

    coverage_sha256: str = PREDECESSOR_COVERAGE_SHA256
    config_bytes_sha256: str = PREDECESSOR_CONFIG_BYTES_SHA256
    config_byte_count: int = PREDECESSOR_CONFIG_BYTE_COUNT
    git_commit: str = PREDECESSOR_GIT_COMMIT
    coverage_version: str = coverage_v2.COVERAGE_V2_VERSION
    config_relative_path: str = coverage_v2.COVERAGE_V2_CONFIG_RELATIVE_PATH

    def __post_init__(self) -> None:
        if (
            type(self) is not PredecessorCoverageV2Commitment
            or self.coverage_sha256 != PREDECESSOR_COVERAGE_SHA256
            or self.config_bytes_sha256
            != PREDECESSOR_CONFIG_BYTES_SHA256
            or type(self.config_byte_count) is not int
            or self.config_byte_count != PREDECESSOR_CONFIG_BYTE_COUNT
            or type(self.git_commit) is not str
            or _COMMIT_RE.fullmatch(self.git_commit) is None
            or self.git_commit != PREDECESSOR_GIT_COMMIT
            or self.coverage_version != coverage_v2.COVERAGE_V2_VERSION
            or self.config_relative_path
            != coverage_v2.COVERAGE_V2_CONFIG_RELATIVE_PATH
        ):
            raise ExecutableDevelopmentCoverageV3Error(
                "v2 predecessor commitment is invalid"
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
    """Generic source and lifecycle evidence for one family promotion."""

    family_id: str
    old_lifecycle_state: str
    new_lifecycle_state: str
    source_tranche_id: str
    task_set_sha256: str
    discrimination_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self) is not CoveragePromotionEvidence
            or self.family_id
            != COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_FAMILY_ID
            or self.old_lifecycle_state != "planned"
            or self.new_lifecycle_state != "integrated"
            or self.source_tranche_id != "tenth-tranche"
            or self.task_set_sha256 != FROZEN_ARCHIVE_TASK_SET_SHA256
            or self.discrimination_sha256
            != FROZEN_ARCHIVE_DISCRIMINATION_SHA256
            or not _is_sha256(self.task_set_sha256)
            or not _is_sha256(self.discrimination_sha256)
        ):
            raise ExecutableDevelopmentCoverageV3Error(
                "integrated-family promotion evidence is invalid"
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
class ExecutableDevelopmentCoverageV3:
    families: tuple[CoverageFamily, ...]
    source_registry_commitments: tuple[SourceRegistryCommitment, ...]
    predecessor: PredecessorCoverageV2Commitment
    hardlink_discrimination_sha256: str
    promotion_evidence: CoveragePromotionEvidence
    coverage_sha256: str
    schema_version: str = COVERAGE_V3_SCHEMA_VERSION
    coverage_version: str = COVERAGE_V3_VERSION
    suite_id: str = COVERAGE_V3_SUITE_ID
    public_method_development: bool = True
    sealed: bool = False
    scored: bool = False
    candidate_execution_authorized: bool = False
    scored_evaluation_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False
    independent_human_review_attested: bool = False

    def __post_init__(self) -> None:
        validate_executable_development_coverage_v3(self)

    def to_hash_only_record(self) -> dict[str, object]:
        validate_executable_development_coverage_v3(self)
        return _coverage_record(self)


def _promote_archive_family(
    planned: CoverageFamily,
    task_set_sha256: str,
) -> CoverageFamily:
    if (
        type(planned) is not CoverageFamily
        or planned.family_id
        != COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_FAMILY_ID
        or planned.lifecycle_state != "planned"
        or planned.integrated_task_set_sha256 is not None
        or planned.parameter_axes
        != (
            CoverageParameterAxis(
                "compression_format",
                COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_COMPRESSION_FORMATS,
            ),
            CoverageParameterAxis(
                "verification_policy",
                COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_VERIFICATION_POLICIES,
            ),
        )
        or planned.solution_track != "bash-native"
        or planned.allowed_tools
        != COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_ALLOWED_TOOLS
        or planned.filesystem_schema
        != COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_FILESYSTEM_IDENTITY
        or planned.output_contract
        != COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_OUTPUT_IDENTITY
        or task_set_sha256 != FROZEN_ARCHIVE_TASK_SET_SHA256
    ):
        raise ExecutableDevelopmentCoverageV3Error(
            "v2 archive planning contract differs from the live family"
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
    """Cache immutable serialized evidence and never returned objects."""

    predecessor = coverage_v2.build_executable_development_coverage_v2()
    predecessor_bytes = (
        coverage_v2.executable_development_coverage_v2_config_bytes()
    )
    if (
        predecessor.coverage_sha256 != PREDECESSOR_COVERAGE_SHA256
        or len(predecessor_bytes) != PREDECESSOR_CONFIG_BYTE_COUNT
        or sha256(predecessor_bytes).hexdigest()
        != PREDECESSOR_CONFIG_BYTES_SHA256
    ):
        raise ExecutableDevelopmentCoverageV3Error(
            "live v2 coverage differs from the frozen predecessor"
        )

    tenth = build_tenth_tranche_task_registry()
    if (
        tenth.registry_sha256 != FROZEN_TENTH_REGISTRY_SHA256
        or tenth.cumulative_suite_sha256
        != FROZEN_TENTH_CUMULATIVE_SUITE_SHA256
        or len(tenth.added_tasks) != TENTH_TRANCHE_ADDED_TASK_COUNT
        or TENTH_TRANCHE_CUMULATIVE_TASK_COUNT
        != INTEGRATED_TASK_COUNT
    ):
        raise ExecutableDevelopmentCoverageV3Error(
            "live tenth registry differs from the frozen v3 source"
        )
    task_set_sha256 = coverage_v2._task_set_sha256(
        COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_FAMILY_ID,
        tenth.added_tasks,
    )
    discrimination_sha256 = (
        compute_compressed_archive_roundtrip_verify_discrimination_sha256(
            tenth.added_tasks
        )
    )
    if (
        task_set_sha256 != FROZEN_ARCHIVE_TASK_SET_SHA256
        or discrimination_sha256
        != FROZEN_ARCHIVE_DISCRIMINATION_SHA256
    ):
        raise ExecutableDevelopmentCoverageV3Error(
            "live archive promotion evidence differs from v3"
        )

    planned = predecessor.families[ARCHIVE_FAMILY_INDEX]
    promoted = _promote_archive_family(planned, task_set_sha256)
    families = (
        *predecessor.families[:ARCHIVE_FAMILY_INDEX],
        promoted,
        *predecessor.families[ARCHIVE_FAMILY_INDEX + 1 :],
    )
    if any(
        old != new
        for index, (old, new) in enumerate(
            zip(predecessor.families, families, strict=True)
        )
        if index != ARCHIVE_FAMILY_INDEX
    ):
        raise ExecutableDevelopmentCoverageV3Error(
            "a family outside the archive promotion changed"
        )
    sources = (
        *predecessor.source_registry_commitments,
        SourceRegistryCommitment(
            "tenth-tranche",
            len(tenth.added_tasks),
            INTEGRATED_TASK_COUNT,
            tenth.registry_sha256,
            tenth.cumulative_suite_sha256,
        ),
    )
    promotion = CoveragePromotionEvidence(
        COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_FAMILY_ID,
        "planned",
        "integrated",
        "tenth-tranche",
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
            "v3_families": [
                family.to_record() for family in families
            ],
            "v3_sources": [
                source.to_record() for source in sources
            ],
            "hardlink_discrimination_sha256": (
                predecessor.hardlink_discrimination_sha256
            ),
            "promotion_evidence": promotion.to_record(),
        }
    )


def _component_snapshot() -> dict[str, object]:
    value = json.loads(_live_component_snapshot_bytes())
    if type(value) is not dict:
        raise ExecutableDevelopmentCoverageV3Error(
            "internal component snapshot is invalid"
        )
    return value


def _families_from_snapshot(
    value: object,
) -> tuple[CoverageFamily, ...]:
    if type(value) is not list:
        raise ExecutableDevelopmentCoverageV3Error(
            "internal family snapshot is invalid"
        )
    try:
        return tuple(
            coverage_v1._family_from_record(record) for record in value
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise ExecutableDevelopmentCoverageV3Error(
            "internal family snapshot cannot be reconstructed"
        ) from exc


def _sources_from_snapshot(
    value: object,
) -> tuple[SourceRegistryCommitment, ...]:
    if type(value) is not list:
        raise ExecutableDevelopmentCoverageV3Error(
            "internal source snapshot is invalid"
        )
    try:
        return tuple(
            coverage_v1._source_from_record(record) for record in value
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise ExecutableDevelopmentCoverageV3Error(
            "internal source snapshot cannot be reconstructed"
        ) from exc


def _promotion_from_snapshot(
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
        raise ExecutableDevelopmentCoverageV3Error(
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
        raise ExecutableDevelopmentCoverageV3Error(
            "internal promotion snapshot cannot be reconstructed"
        ) from exc


def _live_v2_components() -> tuple[
    tuple[CoverageFamily, ...],
    tuple[SourceRegistryCommitment, ...],
]:
    """Return a fresh v2 object graph from immutable live evidence."""

    snapshot = _component_snapshot()
    return (
        _families_from_snapshot(snapshot.get("predecessor_families")),
        _sources_from_snapshot(snapshot.get("predecessor_sources")),
    )


def _live_v3_components() -> tuple[
    tuple[CoverageFamily, ...],
    tuple[SourceRegistryCommitment, ...],
    str,
    CoveragePromotionEvidence,
]:
    """Return a fresh v3 object graph from immutable cached evidence."""

    snapshot = _component_snapshot()
    hardlink = snapshot.get("hardlink_discrimination_sha256")
    if (
        type(hardlink) is not str
        or hardlink != coverage_v2.FROZEN_HARDLINK_DISCRIMINATION_SHA256
    ):
        raise ExecutableDevelopmentCoverageV3Error(
            "internal hardlink evidence snapshot is invalid"
        )
    return (
        _families_from_snapshot(snapshot.get("v3_families")),
        _sources_from_snapshot(snapshot.get("v3_sources")),
        hardlink,
        _promotion_from_snapshot(snapshot.get("promotion_evidence")),
    )


def _coverage_record(
    coverage: ExecutableDevelopmentCoverageV3,
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
        "promotion_evidence": coverage.promotion_evidence.to_record(),
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


def compute_executable_development_coverage_v3_sha256(
    record: object,
) -> str:
    if type(record) is not dict:
        raise ExecutableDevelopmentCoverageV3Error(
            "v3 coverage hash input must be an exact object"
        )
    payload = dict(record)
    payload.pop("coverage_sha256", None)
    return domain_sha256(
        "cbds.executable-method-development-coverage.v3",
        payload,
    )


def validate_executable_development_coverage_v3(
    coverage: ExecutableDevelopmentCoverageV3,
) -> None:
    if type(coverage) is not ExecutableDevelopmentCoverageV3:
        raise ExecutableDevelopmentCoverageV3Error(
            "coverage must be an exact ExecutableDevelopmentCoverageV3"
        )
    if (
        coverage.schema_version != COVERAGE_V3_SCHEMA_VERSION
        or coverage.coverage_version != COVERAGE_V3_VERSION
        or coverage.suite_id != COVERAGE_V3_SUITE_ID
        or coverage.public_method_development is not True
        or any(
            getattr(coverage, name) is not False
            for name in _AUTHORITY_FALSE_FIELDS
        )
    ):
        raise ExecutableDevelopmentCoverageV3Error(
            "v3 metadata or authority boundary is invalid"
        )
    if type(coverage.predecessor) is not PredecessorCoverageV2Commitment:
        raise ExecutableDevelopmentCoverageV3Error(
            "v3 predecessor has the wrong exact type"
        )
    coverage.predecessor.__post_init__()
    if (
        type(coverage.promotion_evidence)
        is not CoveragePromotionEvidence
    ):
        raise ExecutableDevelopmentCoverageV3Error(
            "v3 promotion evidence has the wrong exact type"
        )
    coverage.promotion_evidence.__post_init__()
    (
        expected_families,
        expected_sources,
        expected_hardlink,
        expected_promotion,
    ) = _live_v3_components()
    if (
        type(coverage.families) is not tuple
        or coverage.families != expected_families
        or type(coverage.source_registry_commitments) is not tuple
        or coverage.source_registry_commitments != expected_sources
        or coverage.hardlink_discrimination_sha256 != expected_hardlink
        or not _is_sha256(coverage.hardlink_discrimination_sha256)
        or coverage.promotion_evidence != expected_promotion
    ):
        raise ExecutableDevelopmentCoverageV3Error(
            "v3 live families, sources, or evidence differ"
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
        or len(coverage.source_registry_commitments) != 10
        or tuple(
            source.cumulative_task_count
            for source in coverage.source_registry_commitments
        )
        != (100, 200, 240, 260, 280, 300, 320, 340, 360, 380)
        or coverage.source_registry_commitments[-1].tranche_id
        != "tenth-tranche"
        or coverage.source_registry_commitments[-1].registry_sha256
        != FROZEN_TENTH_REGISTRY_SHA256
        or coverage.source_registry_commitments[-1].cumulative_suite_sha256
        != FROZEN_TENTH_CUMULATIVE_SUITE_SHA256
    ):
        raise ExecutableDevelopmentCoverageV3Error(
            "v3 coverage partition, source chain, or order is invalid"
        )
    record = _coverage_record(coverage)
    if (
        not _is_sha256(coverage.coverage_sha256)
        or coverage.coverage_sha256 != FROZEN_COVERAGE_V3_SHA256
        or coverage.coverage_sha256
        != compute_executable_development_coverage_v3_sha256(record)
    ):
        raise ExecutableDevelopmentCoverageV3Error(
            "v3 coverage digest is invalid"
        )


def build_executable_development_coverage_v3(
) -> ExecutableDevelopmentCoverageV3:
    families, sources, hardlink, promotion = _live_v3_components()
    predecessor = PredecessorCoverageV2Commitment()
    provisional = ExecutableDevelopmentCoverageV3.__new__(
        ExecutableDevelopmentCoverageV3
    )
    values: dict[str, object] = {
        "families": families,
        "source_registry_commitments": sources,
        "predecessor": predecessor,
        "hardlink_discrimination_sha256": hardlink,
        "promotion_evidence": promotion,
        "coverage_sha256": "0" * 64,
        "schema_version": COVERAGE_V3_SCHEMA_VERSION,
        "coverage_version": COVERAGE_V3_VERSION,
        "suite_id": COVERAGE_V3_SUITE_ID,
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
    digest = compute_executable_development_coverage_v3_sha256(
        _coverage_record(provisional)
    )
    return ExecutableDevelopmentCoverageV3(
        families=families,
        source_registry_commitments=sources,
        predecessor=predecessor,
        hardlink_discrimination_sha256=hardlink,
        promotion_evidence=promotion,
        coverage_sha256=digest,
    )


def _reject_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ExecutableDevelopmentCoverageV3Error(
                "v3 coverage JSON contains a duplicate object key"
            )
        result[key] = value
    return result


def _read_stable_regular(
    path: Path,
    maximum_bytes: int = MAXIMUM_COVERAGE_V3_CONFIG_BYTES,
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
        raise ExecutableDevelopmentCoverageV3Error(
            "cannot read v3 coverage as a stable regular file"
        ) from exc
    if payload is None:
        raise ExecutableDevelopmentCoverageV3Error(
            "v3 coverage config does not exist as a stable regular file"
        )
    return payload


def load_executable_development_coverage_v3(
    path: str | os.PathLike[str],
) -> ExecutableDevelopmentCoverageV3:
    """Load only the exact canonical checked v3 projection."""

    try:
        source = Path(os.fspath(path))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ExecutableDevelopmentCoverageV3Error(
            "v3 coverage config path is invalid"
        ) from exc
    payload = _read_stable_regular(source)
    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ExecutableDevelopmentCoverageV3Error(
                    "v3 coverage JSON contains non-finite number "
                    f"{token}"
                )
            ),
        )
        canonical = canonical_json_bytes(value) + b"\n"
    except ExecutableDevelopmentCoverageV3Error:
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
        raise ExecutableDevelopmentCoverageV3Error(
            "v3 coverage config is not strict canonical JSON"
        ) from exc
    if payload != canonical:
        raise ExecutableDevelopmentCoverageV3Error(
            "v3 coverage config is not canonical JSON plus LF"
        )
    expected = build_executable_development_coverage_v3()
    if payload != (
        canonical_json_bytes(expected.to_hash_only_record()) + b"\n"
    ):
        raise ExecutableDevelopmentCoverageV3Error(
            "checked v3 config differs from the central projection"
        )
    return expected


def executable_development_coverage_v3_config_bytes() -> bytes:
    """Return the exact checked artifact bytes for deterministic generation."""

    return (
        canonical_json_bytes(
            build_executable_development_coverage_v3().to_hash_only_record()
        )
        + b"\n"
    )


# Backward-compatible direct alias for the initial implementation name.
IntegratedFamilyPromotionEvidence = CoveragePromotionEvidence


__all__ = [
    "ARCHIVE_FAMILY_INDEX",
    "CANONICAL_FAMILY_ORDER",
    "COVERAGE_V3_CONFIG_RELATIVE_PATH",
    "COVERAGE_V3_SCHEMA_VERSION",
    "COVERAGE_V3_SUITE_ID",
    "COVERAGE_V3_VERSION",
    "FAMILY_COUNT",
    "FROZEN_ARCHIVE_DISCRIMINATION_SHA256",
    "FROZEN_ARCHIVE_TASK_SET_SHA256",
    "FROZEN_COVERAGE_V3_SHA256",
    "FROZEN_TENTH_CUMULATIVE_SUITE_SHA256",
    "FROZEN_TENTH_REGISTRY_SHA256",
    "INTEGRATED_FAMILY_COUNT",
    "INTEGRATED_TASK_COUNT",
    "MAXIMUM_COVERAGE_V3_CONFIG_BYTES",
    "PLANNED_FAMILY_COUNT",
    "PLANNED_TASK_COUNT",
    "PREDECESSOR_CONFIG_BYTE_COUNT",
    "PREDECESSOR_CONFIG_BYTES_SHA256",
    "PREDECESSOR_COVERAGE_SHA256",
    "PREDECESSOR_GIT_COMMIT",
    "TASKS_PER_FAMILY",
    "TOTAL_TASK_COUNT",
    "ExecutableDevelopmentCoverageV3",
    "ExecutableDevelopmentCoverageV3Error",
    "CoveragePromotionEvidence",
    "IntegratedFamilyPromotionEvidence",
    "PredecessorCoverageV2Commitment",
    "build_executable_development_coverage_v3",
    "compute_executable_development_coverage_v3_sha256",
    "executable_development_coverage_v3_config_bytes",
    "load_executable_development_coverage_v3",
    "validate_executable_development_coverage_v3",
]
