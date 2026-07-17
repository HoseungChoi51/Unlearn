"""Backward-linked v2 coverage lock for 500 development specifications.

Version 1 recorded ``hardlink-deduplicated-mirror`` as a planned family with
an exploratory grid.  Implementation showed that several cells in that grid
were observationally redundant or nondeterministic.  Version 2 preserves the
v1 bytes as historical evidence, promotes the implemented and fully
discriminable 4-by-5 grid, and binds the ninth live registry.

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
from .executable_development_coverage import (
    CoverageFamily,
    CoverageParameterAxis,
    SourceRegistryCommitment,
)
from .executable_hardlink_deduplicated_mirror import (
    HARDLINK_DEDUPLICATED_MIRROR_ALLOWED_TOOLS,
    HARDLINK_DEDUPLICATED_MIRROR_EQUIVALENCE_KEYS,
    HARDLINK_DEDUPLICATED_MIRROR_FILESYSTEM_IDENTITY,
    HARDLINK_DEDUPLICATED_MIRROR_OUTPUT_IDENTITY,
    HARDLINK_DEDUPLICATED_MIRROR_OWNER_POLICIES,
    compute_hardlink_deduplicated_mirror_discrimination_sha256,
)
from .executable_linear_predecessor_evidence import (
    LINEAR_PREDECESSOR_FAMILY_ORDER,
    LinearTaskPredecessorEvidence,
    build_linear_task_predecessor_evidence,
)
from .executable_static_ninth_registry import (
    build_ninth_tranche_task_registry,
)
from .executable_static_types import domain_sha256
from . import hash_only_report_publication as report_publication
from .manifests import (
    ManifestValidationError,
    canonical_json_bytes,
)


COVERAGE_V2_SCHEMA_VERSION: Final[str] = "2.0.0"
COVERAGE_V2_VERSION: Final[str] = "2.0.0"
COVERAGE_V2_SUITE_ID: Final[str] = (
    "cbds-executable-method-development-v2"
)
COVERAGE_V2_CONFIG_RELATIVE_PATH: Final[str] = (
    "configs/executable-method-development-coverage-v2.json"
)
MAXIMUM_COVERAGE_V2_CONFIG_BYTES: Final[int] = 256 * 1024

FAMILY_COUNT: Final[int] = 25
TASKS_PER_FAMILY: Final[int] = 20
TOTAL_TASK_COUNT: Final[int] = 500
INTEGRATED_FAMILY_COUNT: Final[int] = 18
INTEGRATED_TASK_COUNT: Final[int] = 360
PLANNED_FAMILY_COUNT: Final[int] = 7
PLANNED_TASK_COUNT: Final[int] = 140

CANONICAL_FAMILY_ORDER: Final[tuple[str, ...]] = (
    coverage_v1.CANONICAL_FAMILY_ORDER
)
HARDLINK_FAMILY_INDEX: Final[int] = CANONICAL_FAMILY_ORDER.index(
    "hardlink-deduplicated-mirror"
)

PREDECESSOR_COVERAGE_SHA256: Final[str] = (
    "6c215d9eaf5581aaa146d6814a9d40621a57459c5af98ae4ca625caff10c9c8c"
)
PREDECESSOR_CONFIG_BYTES_SHA256: Final[str] = (
    "46f98f54ef5682ce0adc3854557ecfe8ed092fd5e916935bc27702edb4e86efa"
)
PREDECESSOR_CONFIG_BYTE_COUNT: Final[int] = 22_495
PREDECESSOR_GIT_COMMIT: Final[str] = (
    "32a703fca7b0b55357cc66ed90f67e83e390025d"
)

FROZEN_NINTH_REGISTRY_SHA256: Final[str] = (
    "ff886754b054445a90ad30197d004e4071dba72bf0af17931d05e461c7e90703"
)
FROZEN_NINTH_CUMULATIVE_SUITE_SHA256: Final[str] = (
    "d0647e24f29abd59f8c2d6b2ac2a404aee78b92c780f8be4f9b16d200885843b"
)
FROZEN_HARDLINK_TASK_SET_SHA256: Final[str] = (
    "0415daa5f9bccfcd75b621ef4ae71c9e79a5b7c19763ceb470e5ef21169706d1"
)
FROZEN_HARDLINK_DISCRIMINATION_SHA256: Final[str] = (
    "1a0c0d23bb262c1d94250a92574c89af6c6333da08d58be715e1b5d1f4940435"
)
FROZEN_COVERAGE_V2_SHA256: Final[str] = (
    "7406480a1dc06bc99d1e36fde1a328a490d6cc8d6b96ee38c924a902acbf9abd"
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


class ExecutableDevelopmentCoverageV2Error(ValueError):
    """Raised when the v2 coverage projection is not exact."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def _task_set_sha256(family_id: str, tasks: tuple[object, ...]) -> str:
    return domain_sha256(
        "cbds.executable-method-development-coverage."
        "integrated-task-set.v1",
        {
            "family_id": family_id,
            "task_count": len(tasks),
            "task_id": [getattr(task, "task_id") for task in tasks],
            "task_contract_sha256": [
                getattr(task, "task_contract_sha256") for task in tasks
            ],
            "graph_sha256": [
                getattr(task, "graph_sha256") for task in tasks
            ],
        },
    )


@dataclass(frozen=True, slots=True)
class PredecessorCoverageCommitment:
    """Exact immutable identity of the superseded v1 planning record."""

    coverage_sha256: str = PREDECESSOR_COVERAGE_SHA256
    config_bytes_sha256: str = PREDECESSOR_CONFIG_BYTES_SHA256
    config_byte_count: int = PREDECESSOR_CONFIG_BYTE_COUNT
    git_commit: str = PREDECESSOR_GIT_COMMIT
    coverage_version: str = coverage_v1.COVERAGE_VERSION
    config_relative_path: str = coverage_v1.COVERAGE_CONFIG_RELATIVE_PATH

    def __post_init__(self) -> None:
        if (
            type(self) is not PredecessorCoverageCommitment
            or self.coverage_sha256 != PREDECESSOR_COVERAGE_SHA256
            or self.config_bytes_sha256
            != PREDECESSOR_CONFIG_BYTES_SHA256
            or type(self.config_byte_count) is not int
            or self.config_byte_count != PREDECESSOR_CONFIG_BYTE_COUNT
            or type(self.git_commit) is not str
            or _COMMIT_RE.fullmatch(self.git_commit) is None
            or self.git_commit != PREDECESSOR_GIT_COMMIT
            or self.coverage_version != coverage_v1.COVERAGE_VERSION
            or self.config_relative_path
            != coverage_v1.COVERAGE_CONFIG_RELATIVE_PATH
        ):
            raise ExecutableDevelopmentCoverageV2Error(
                "v1 predecessor commitment is invalid"
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
class ExecutableDevelopmentCoverageV2:
    families: tuple[CoverageFamily, ...]
    source_registry_commitments: tuple[SourceRegistryCommitment, ...]
    predecessor: PredecessorCoverageCommitment
    hardlink_discrimination_sha256: str
    coverage_sha256: str
    schema_version: str = COVERAGE_V2_SCHEMA_VERSION
    coverage_version: str = COVERAGE_V2_VERSION
    suite_id: str = COVERAGE_V2_SUITE_ID
    public_method_development: bool = True
    sealed: bool = False
    scored: bool = False
    candidate_execution_authorized: bool = False
    scored_evaluation_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False
    independent_human_review_attested: bool = False

    def __post_init__(self) -> None:
        validate_executable_development_coverage_v2(self)

    def to_hash_only_record(self) -> dict[str, object]:
        validate_executable_development_coverage_v2(self)
        return _coverage_record(self)


def _family_core_record(
    family_id: str,
    lifecycle_state: str,
    parameter_axes: tuple[CoverageParameterAxis, CoverageParameterAxis],
    solution_track: str,
    allowed_tools: tuple[str, ...],
    filesystem_schema: str,
    output_contract: str,
    capability_tags: tuple[str, ...],
    integrated_task_set_sha256: str | None,
) -> dict[str, object]:
    return {
        "family_id": family_id,
        "lifecycle_state": lifecycle_state,
        "task_count": TASKS_PER_FAMILY,
        "parameter_axes": [axis.to_record() for axis in parameter_axes],
        "solution_track": solution_track,
        "allowed_tools": list(allowed_tools),
        "filesystem_schema": filesystem_schema,
        "output_contract": output_contract,
        "capability_tags": list(capability_tags),
        "integrated_task_set_sha256": integrated_task_set_sha256,
    }


def _make_hardlink_family(task_set_sha256: str) -> CoverageFamily:
    if task_set_sha256 != FROZEN_HARDLINK_TASK_SET_SHA256:
        raise ExecutableDevelopmentCoverageV2Error(
            "hardlink task-set identity differs from the frozen v2 value"
        )
    axes = (
        CoverageParameterAxis(
            "equivalence_key",
            HARDLINK_DEDUPLICATED_MIRROR_EQUIVALENCE_KEYS,
        ),
        CoverageParameterAxis(
            "owner_policy",
            HARDLINK_DEDUPLICATED_MIRROR_OWNER_POLICIES,
        ),
    )
    capability_tags = (
        "content-deduplication",
        "filesystem-mutation",
        "hard-links",
        "tree-mirroring",
    )
    core = _family_core_record(
        "hardlink-deduplicated-mirror",
        "integrated",
        axes,
        "bash-native",
        HARDLINK_DEDUPLICATED_MIRROR_ALLOWED_TOOLS,
        HARDLINK_DEDUPLICATED_MIRROR_FILESYSTEM_IDENTITY,
        HARDLINK_DEDUPLICATED_MIRROR_OUTPUT_IDENTITY,
        capability_tags,
        task_set_sha256,
    )
    return CoverageFamily(
        family_id="hardlink-deduplicated-mirror",
        lifecycle_state="integrated",
        task_count=TASKS_PER_FAMILY,
        parameter_axes=axes,
        solution_track="bash-native",
        allowed_tools=HARDLINK_DEDUPLICATED_MIRROR_ALLOWED_TOOLS,
        filesystem_schema=HARDLINK_DEDUPLICATED_MIRROR_FILESYSTEM_IDENTITY,
        output_contract=HARDLINK_DEDUPLICATED_MIRROR_OUTPUT_IDENTITY,
        capability_tags=capability_tags,
        integrated_task_set_sha256=task_set_sha256,
        family_sha256=domain_sha256(
            "cbds.executable-method-development-coverage.family.v1",
            core,
        ),
    )


def _build_linear_v1_components(
    evidence: LinearTaskPredecessorEvidence,
) -> tuple[
    tuple[CoverageFamily, ...],
    tuple[SourceRegistryCommitment, ...],
]:
    """Reconstruct the v1 projection from the linear frozen task chain."""

    integrated_specs = coverage_v1._FAMILY_SPECS[
        : coverage_v1.INTEGRATED_FAMILY_COUNT
    ]
    if tuple(spec.family_id for spec in integrated_specs) != (
        LINEAR_PREDECESSOR_FAMILY_ORDER
    ):
        raise ExecutableDevelopmentCoverageV2Error(
            "v1 family declarations differ from linear predecessor order"
        )
    task_sets: dict[str, str] = {}
    offset = 0
    for spec in integrated_specs:
        tasks = tuple(
            evidence.tasks[offset : offset + coverage_v1.TASKS_PER_FAMILY]
        )
        offset += coverage_v1.TASKS_PER_FAMILY
        if (
            len(tasks) != coverage_v1.TASKS_PER_FAMILY
            or {getattr(task, "family_id", None) for task in tasks}
            != {spec.family_id}
            or {
                getattr(task, "filesystem_identity", None)
                for task in tasks
            }
            != {spec.filesystem_schema}
            or {
                getattr(task, "output_identity", None) for task in tasks
            }
            != {spec.output_contract}
            or {
                getattr(task, "allowed_tools", None) for task in tasks
            }
            != {spec.allowed_tools}
        ):
            raise ExecutableDevelopmentCoverageV2Error(
                f"linear v1 family {spec.family_id} differs from its contract"
            )
        expected_parameters = tuple(
            (spec.family_id, left, right)
            for left in spec.parameter_axes[0].values
            for right in spec.parameter_axes[1].values
        )
        observed_parameters: list[tuple[object, object, object]] = []
        for task in tasks:
            parameter = task.parameters.to_record()
            expected_keys = {
                "parameter_type",
                spec.parameter_axes[0].axis_name,
                spec.parameter_axes[1].axis_name,
            }
            if type(parameter) is not dict or set(parameter) != expected_keys:
                raise ExecutableDevelopmentCoverageV2Error(
                    f"linear v1 parameter schema differs for {spec.family_id}"
                )
            observed_parameters.append(
                (
                    parameter["parameter_type"],
                    parameter[spec.parameter_axes[0].axis_name],
                    parameter[spec.parameter_axes[1].axis_name],
                )
            )
        if tuple(observed_parameters) != expected_parameters:
            raise ExecutableDevelopmentCoverageV2Error(
                f"linear v1 parameter grid differs for {spec.family_id}"
            )
        task_sets[spec.family_id] = _task_set_sha256(
            spec.family_id, tasks
        )
    if offset != coverage_v1.INTEGRATED_TASK_COUNT:
        raise ExecutableDevelopmentCoverageV2Error(
            "linear v1 task partition is incomplete"
        )

    families = tuple(
        coverage_v1._make_family(
            spec,
            task_sets.get(spec.family_id),
        )
        for spec in coverage_v1._FAMILY_SPECS
    )
    sources = tuple(
        SourceRegistryCommitment(
            f"{tranche.tranche}-tranche",
            tranche.added_task_count,
            tranche.cumulative_task_count,
            tranche.registry_sha256,
            tranche.cumulative_suite_sha256,
        )
        for tranche in evidence.tranches
    )
    predecessor_record: dict[str, object] = {
        "schema_version": coverage_v1.COVERAGE_SCHEMA_VERSION,
        "coverage_version": coverage_v1.COVERAGE_VERSION,
        "record_type": (
            "cbds.executable-method-development-coverage-hashes"
        ),
        "suite_id": coverage_v1.COVERAGE_SUITE_ID,
        "family_count": coverage_v1.FAMILY_COUNT,
        "tasks_per_family": coverage_v1.TASKS_PER_FAMILY,
        "total_task_count": coverage_v1.TOTAL_TASK_COUNT,
        "integrated_family_count": coverage_v1.INTEGRATED_FAMILY_COUNT,
        "integrated_task_count": coverage_v1.INTEGRATED_TASK_COUNT,
        "planned_family_count": coverage_v1.PLANNED_FAMILY_COUNT,
        "planned_task_count": coverage_v1.PLANNED_TASK_COUNT,
        "canonical_family_order": list(
            coverage_v1.CANONICAL_FAMILY_ORDER
        ),
        "source_registry_commitments": [
            source.to_record() for source in sources
        ],
        "families": [family.to_record() for family in families],
        "coverage_sha256": PREDECESSOR_COVERAGE_SHA256,
        "public_method_development": True,
        "sealed": False,
        "scored": False,
        "candidate_execution_authorized": False,
        "scored_evaluation_authorized": False,
        "model_selection_eligible": False,
        "claim_authorized": False,
        "independent_human_review_attested": False,
    }
    if (
        coverage_v1.compute_executable_development_coverage_sha256(
            predecessor_record
        )
        != PREDECESSOR_COVERAGE_SHA256
    ):
        raise ExecutableDevelopmentCoverageV2Error(
            "linear reconstruction does not reproduce the frozen v1 digest"
        )
    return families, sources


@lru_cache(maxsize=1)
def _live_component_snapshot_bytes() -> bytes:
    """Cache only immutable serialized evidence, never returned objects."""

    evidence = build_linear_task_predecessor_evidence()
    predecessor_families, predecessor_sources = (
        _build_linear_v1_components(evidence)
    )
    ninth = build_ninth_tranche_task_registry(evidence)
    if (
        ninth.registry_sha256 != FROZEN_NINTH_REGISTRY_SHA256
        or ninth.cumulative_suite_sha256
        != FROZEN_NINTH_CUMULATIVE_SUITE_SHA256
        or len(ninth.added_tasks) != TASKS_PER_FAMILY
    ):
        raise ExecutableDevelopmentCoverageV2Error(
            "live ninth registry differs from the frozen v2 source"
        )
    task_set_sha256 = _task_set_sha256(
        "hardlink-deduplicated-mirror", ninth.added_tasks
    )
    if task_set_sha256 != FROZEN_HARDLINK_TASK_SET_SHA256:
        raise ExecutableDevelopmentCoverageV2Error(
            "live hardlink task set differs from the frozen v2 source"
        )
    discrimination_sha256 = (
        compute_hardlink_deduplicated_mirror_discrimination_sha256(
            ninth.added_tasks
        )
    )
    if (
        discrimination_sha256
        != FROZEN_HARDLINK_DISCRIMINATION_SHA256
    ):
        raise ExecutableDevelopmentCoverageV2Error(
            "live hardlink discrimination evidence differs from v2"
        )

    old_hardlink = predecessor_families[HARDLINK_FAMILY_INDEX]
    if (
        old_hardlink.family_id != "hardlink-deduplicated-mirror"
        or old_hardlink.lifecycle_state != "planned"
        or old_hardlink.integrated_task_set_sha256 is not None
    ):
        raise ExecutableDevelopmentCoverageV2Error(
            "v1 hardlink planning cell is not the expected predecessor"
        )
    families = (
        *predecessor_families[:HARDLINK_FAMILY_INDEX],
        _make_hardlink_family(task_set_sha256),
        *predecessor_families[HARDLINK_FAMILY_INDEX + 1 :],
    )
    sources = (
        *predecessor_sources,
        SourceRegistryCommitment(
            "ninth-tranche",
            len(ninth.added_tasks),
            INTEGRATED_TASK_COUNT,
            ninth.registry_sha256,
            ninth.cumulative_suite_sha256,
        ),
    )
    return canonical_json_bytes(
        {
            "predecessor_families": [
                family.to_record() for family in predecessor_families
            ],
            "predecessor_sources": [
                source.to_record() for source in predecessor_sources
            ],
            "v2_families": [
                family.to_record() for family in families
            ],
            "v2_sources": [
                source.to_record() for source in sources
            ],
            "hardlink_discrimination_sha256": discrimination_sha256,
        }
    )


def _component_snapshot() -> dict[str, object]:
    """Decode a fresh object graph from the immutable cached bytes."""

    value = json.loads(_live_component_snapshot_bytes())
    if type(value) is not dict:
        raise ExecutableDevelopmentCoverageV2Error(
            "internal component snapshot is invalid"
        )
    return value


def _families_from_snapshot(
    value: object,
) -> tuple[CoverageFamily, ...]:
    if type(value) is not list:
        raise ExecutableDevelopmentCoverageV2Error(
            "internal family snapshot is invalid"
        )
    try:
        return tuple(
            coverage_v1._family_from_record(record)
            for record in value
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise ExecutableDevelopmentCoverageV2Error(
            "internal family snapshot cannot be reconstructed"
        ) from exc


def _sources_from_snapshot(
    value: object,
) -> tuple[SourceRegistryCommitment, ...]:
    if type(value) is not list:
        raise ExecutableDevelopmentCoverageV2Error(
            "internal source snapshot is invalid"
        )
    try:
        return tuple(
            coverage_v1._source_from_record(record)
            for record in value
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise ExecutableDevelopmentCoverageV2Error(
            "internal source snapshot cannot be reconstructed"
        ) from exc


def _linear_v1_components() -> tuple[
    tuple[CoverageFamily, ...],
    tuple[SourceRegistryCommitment, ...],
]:
    """Return a fresh v1 object graph from immutable live evidence."""

    snapshot = _component_snapshot()
    return (
        _families_from_snapshot(snapshot.get("predecessor_families")),
        _sources_from_snapshot(snapshot.get("predecessor_sources")),
    )


def _live_v2_components() -> tuple[
    tuple[CoverageFamily, ...],
    tuple[SourceRegistryCommitment, ...],
    str,
]:
    """Return a fresh v2 object graph from immutable cached evidence."""

    snapshot = _component_snapshot()
    discrimination = snapshot.get(
        "hardlink_discrimination_sha256"
    )
    if (
        type(discrimination) is not str
        or discrimination != FROZEN_HARDLINK_DISCRIMINATION_SHA256
    ):
        raise ExecutableDevelopmentCoverageV2Error(
            "internal discrimination snapshot is invalid"
        )
    return (
        _families_from_snapshot(snapshot.get("v2_families")),
        _sources_from_snapshot(snapshot.get("v2_sources")),
        discrimination,
    )


def _coverage_record(
    coverage: ExecutableDevelopmentCoverageV2,
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


def compute_executable_development_coverage_v2_sha256(
    record: object,
) -> str:
    if type(record) is not dict:
        raise ExecutableDevelopmentCoverageV2Error(
            "v2 coverage hash input must be an exact object"
        )
    payload = dict(record)
    payload.pop("coverage_sha256", None)
    return domain_sha256(
        "cbds.executable-method-development-coverage.v2",
        payload,
    )


def validate_executable_development_coverage_v2(
    coverage: ExecutableDevelopmentCoverageV2,
) -> None:
    if type(coverage) is not ExecutableDevelopmentCoverageV2:
        raise ExecutableDevelopmentCoverageV2Error(
            "coverage must be an exact ExecutableDevelopmentCoverageV2"
        )
    if (
        coverage.schema_version != COVERAGE_V2_SCHEMA_VERSION
        or coverage.coverage_version != COVERAGE_V2_VERSION
        or coverage.suite_id != COVERAGE_V2_SUITE_ID
        or coverage.public_method_development is not True
        or any(
            getattr(coverage, name) is not False
            for name in _AUTHORITY_FALSE_FIELDS
        )
    ):
        raise ExecutableDevelopmentCoverageV2Error(
            "v2 metadata or authority boundary is invalid"
        )
    if type(coverage.predecessor) is not PredecessorCoverageCommitment:
        raise ExecutableDevelopmentCoverageV2Error(
            "v2 predecessor has the wrong exact type"
        )
    coverage.predecessor.__post_init__()
    expected_families, expected_sources, expected_discrimination = (
        _live_v2_components()
    )
    if (
        type(coverage.families) is not tuple
        or coverage.families != expected_families
        or type(coverage.source_registry_commitments) is not tuple
        or coverage.source_registry_commitments != expected_sources
        or coverage.hardlink_discrimination_sha256
        != expected_discrimination
        or not _is_sha256(coverage.hardlink_discrimination_sha256)
    ):
        raise ExecutableDevelopmentCoverageV2Error(
            "v2 live families, sources, or discrimination evidence differ"
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
        or len(coverage.source_registry_commitments) != 9
        or coverage.source_registry_commitments[-1].cumulative_task_count
        != INTEGRATED_TASK_COUNT
    ):
        raise ExecutableDevelopmentCoverageV2Error(
            "v2 coverage partition or order is invalid"
        )
    record = _coverage_record(coverage)
    if (
        not _is_sha256(coverage.coverage_sha256)
        or coverage.coverage_sha256 != FROZEN_COVERAGE_V2_SHA256
        or coverage.coverage_sha256
        != compute_executable_development_coverage_v2_sha256(record)
    ):
        raise ExecutableDevelopmentCoverageV2Error(
            "v2 coverage digest is invalid"
        )


def build_executable_development_coverage_v2(
) -> ExecutableDevelopmentCoverageV2:
    families, sources, discrimination = _live_v2_components()
    predecessor = PredecessorCoverageCommitment()
    provisional = ExecutableDevelopmentCoverageV2.__new__(
        ExecutableDevelopmentCoverageV2
    )
    values: dict[str, object] = {
        "families": families,
        "source_registry_commitments": sources,
        "predecessor": predecessor,
        "hardlink_discrimination_sha256": discrimination,
        "coverage_sha256": "0" * 64,
        "schema_version": COVERAGE_V2_SCHEMA_VERSION,
        "coverage_version": COVERAGE_V2_VERSION,
        "suite_id": COVERAGE_V2_SUITE_ID,
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
    digest = compute_executable_development_coverage_v2_sha256(
        _coverage_record(provisional)
    )
    return ExecutableDevelopmentCoverageV2(
        families=families,
        source_registry_commitments=sources,
        predecessor=predecessor,
        hardlink_discrimination_sha256=discrimination,
        coverage_sha256=digest,
    )


def _reject_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ExecutableDevelopmentCoverageV2Error(
                "v2 coverage JSON contains a duplicate object key"
            )
        result[key] = value
    return result


def _read_stable_regular(
    path: Path,
    maximum_bytes: int = MAXIMUM_COVERAGE_V2_CONFIG_BYTES,
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
        raise ExecutableDevelopmentCoverageV2Error(
            "cannot read v2 coverage as a stable regular file"
        ) from exc
    if payload is None:
        raise ExecutableDevelopmentCoverageV2Error(
            "v2 coverage config does not exist as a stable regular file"
        )
    return payload


def load_executable_development_coverage_v2(
    path: str | os.PathLike[str],
) -> ExecutableDevelopmentCoverageV2:
    """Load only the exact canonical checked v2 projection."""

    try:
        source = Path(os.fspath(path))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ExecutableDevelopmentCoverageV2Error(
            "v2 coverage config path is invalid"
        ) from exc
    payload = _read_stable_regular(source)
    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ExecutableDevelopmentCoverageV2Error(
                    "v2 coverage JSON contains non-finite number "
                    f"{token}"
                )
            ),
        )
        canonical = canonical_json_bytes(value) + b"\n"
    except ExecutableDevelopmentCoverageV2Error:
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
        raise ExecutableDevelopmentCoverageV2Error(
            "v2 coverage config is not strict canonical JSON"
        ) from exc
    if payload != canonical:
        raise ExecutableDevelopmentCoverageV2Error(
            "v2 coverage config is not canonical JSON plus LF"
        )
    expected = build_executable_development_coverage_v2()
    expected_bytes = canonical_json_bytes(
        expected.to_hash_only_record()
    ) + b"\n"
    if payload != expected_bytes:
        raise ExecutableDevelopmentCoverageV2Error(
            "checked v2 config differs from the central projection"
        )
    return expected


def executable_development_coverage_v2_config_bytes() -> bytes:
    """Return the exact checked artifact bytes for deterministic generation."""

    return (
        canonical_json_bytes(
            build_executable_development_coverage_v2().to_hash_only_record()
        )
        + b"\n"
    )


__all__ = [
    "CANONICAL_FAMILY_ORDER",
    "COVERAGE_V2_CONFIG_RELATIVE_PATH",
    "COVERAGE_V2_SCHEMA_VERSION",
    "COVERAGE_V2_SUITE_ID",
    "COVERAGE_V2_VERSION",
    "FAMILY_COUNT",
    "FROZEN_COVERAGE_V2_SHA256",
    "FROZEN_HARDLINK_DISCRIMINATION_SHA256",
    "FROZEN_HARDLINK_TASK_SET_SHA256",
    "FROZEN_NINTH_CUMULATIVE_SUITE_SHA256",
    "FROZEN_NINTH_REGISTRY_SHA256",
    "HARDLINK_FAMILY_INDEX",
    "INTEGRATED_FAMILY_COUNT",
    "INTEGRATED_TASK_COUNT",
    "MAXIMUM_COVERAGE_V2_CONFIG_BYTES",
    "PLANNED_FAMILY_COUNT",
    "PLANNED_TASK_COUNT",
    "PREDECESSOR_CONFIG_BYTE_COUNT",
    "PREDECESSOR_CONFIG_BYTES_SHA256",
    "PREDECESSOR_COVERAGE_SHA256",
    "PREDECESSOR_GIT_COMMIT",
    "TASKS_PER_FAMILY",
    "TOTAL_TASK_COUNT",
    "ExecutableDevelopmentCoverageV2",
    "ExecutableDevelopmentCoverageV2Error",
    "PredecessorCoverageCommitment",
    "build_executable_development_coverage_v2",
    "compute_executable_development_coverage_v2_sha256",
    "executable_development_coverage_v2_config_bytes",
    "load_executable_development_coverage_v2",
    "validate_executable_development_coverage_v2",
]
