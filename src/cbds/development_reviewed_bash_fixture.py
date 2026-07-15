"""One fixed, reviewed Bash fixture for development supervisor integration.

This module closes only the trusted-controller half of one public development
case.  It rebuilds and exhaustively admits the immutable first-tranche catalog,
selects one exact fixture, and binds one source-reviewed Bash response through
the frozen V1 response parser and invocation protocol.  It can materialize the
authenticated fixture, but it never executes the reviewed program or grants
candidate, scoring, model-selection, or claim authority.

The case is intentionally private: it retains the admitted catalog, selected
fixture definition, and trusted oracle bytes.  Only :meth:`to_audit_record`
provides answer-free audit metadata.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import os
from typing import Final

from .development_invocation import (
    DevelopmentCatalogAdmission,
    DevelopmentInvocation,
    admit_development_catalog,
    build_development_invocation,
    verify_development_invocation,
)
from .executable_fixture_bundle import (
    ExecutableFixtureBundle,
    validate_executable_fixture_bundle,
)
from .executable_fixture_catalog import (
    FirstTrancheFixtureCatalog,
    build_first_tranche_fixture_catalog,
    validate_first_tranche_fixture_catalog,
)
from .executable_fixture_profiles import (
    ExecutableFixtureProfile,
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from .executable_static_registry import build_public_method_development_registry
from .executable_static_types import (
    ExecutableStaticTask,
    PathSuffixInventoryParameters,
    domain_sha256,
)
from .executable_workspace import WorkspaceHandle, materialize_fixture


DEVELOPMENT_REVIEWED_BASH_FIXTURE_SCHEMA_VERSION: Final[str] = "1.0.0"
DEVELOPMENT_REVIEWED_BASH_FIXTURE_RECORD_TYPE: Final[str] = (
    "cbds.development-reviewed-bash-fixture"
)
DEVELOPMENT_REVIEWED_BASH_FIXTURE_REVIEW_SCOPE: Final[str] = (
    "fixed-source-review-no-execution-v1"
)

FROZEN_REVIEWED_BASH_RESPONSE: Final[str] = (
    "```bash\n"
    "set -euo pipefail\n"
    "umask 022\n"
    "export LC_ALL=C\n"
    "mkdir -p -- output\n"
    "find input/tree -type f -perm /0444 -name '*.txt' "
    "-printf '%P\\n' | sort > output/paths.txt\n"
    "```"
)
FROZEN_REVIEWED_BASH_PROGRAM: Final[bytes] = (
    b"set -euo pipefail\n"
    b"umask 022\n"
    b"export LC_ALL=C\n"
    b"mkdir -p -- output\n"
    b"find input/tree -type f -perm /0444 -name '*.txt' "
    b"-printf '%P\\n' | sort > output/paths.txt"
)
FROZEN_REVIEWED_EXTERNAL_COMMANDS: Final[tuple[str, ...]] = (
    "find",
    "mkdir",
    "sort",
)

FROZEN_FIRST_CATALOG_SHA256: Final[str] = (
    "1fc71f89830739a53b69d771b7d0bd6a79a4d78ff698b1c1c2258211e7776c99"
)
FROZEN_FIRST_REGISTRY_SHA256: Final[str] = (
    "ada6043b345e48f69ad602581030aab1bafcb3ff9dc453f9d02342faaf6a7f9a"
)
FROZEN_FIRST_SUITE_SHA256: Final[str] = (
    "eb64bb4cdb60ab8e0e228f688cf54810fae2ef56768e8b34ac039bdc1aec42ae"
)
FROZEN_FIRST_ADMISSION_SHA256: Final[str] = (
    "28fad8b1e689c72dc3b28dcae1302902d44251d73a91cd59205c6a8864257a15"
)
FROZEN_REVIEWED_TASK_ID: Final[str] = "mds-430e6191c6e68f0bf27a8011"
FROZEN_REVIEWED_TASK_SHA256: Final[str] = (
    "430e6191c6e68f0bf27a801191a88a4a5992819d1dbcb7f6e9416618f2cee3e8"
)
FROZEN_REVIEWED_GRAPH_SHA256: Final[str] = (
    "30ee42639d65f59e4f2e0aee850ca16a6be65c6787e6a251fcb85cd4432192fd"
)
FROZEN_REVIEWED_PROFILE_ID: Final[str] = "spaces-unicode"
FROZEN_REVIEWED_PROFILE_SHA256: Final[str] = (
    "c7f5a2ad4aefa57c50a321aba1c2955ae28b310362c69c6db7a3c3a99507900e"
)
FROZEN_REVIEWED_FIXTURE_ID: Final[str] = "fx-76eaff5362963ac05fc4391f"
FROZEN_REVIEWED_FIXTURE_SHA256: Final[str] = (
    "76eaff5362963ac05fc4391f636b5ec2ceef59adf8faa35980b867b7c0e1b47d"
)
FROZEN_REVIEWED_FIXTURE_DEFINITION_SHA256: Final[str] = (
    "a85534990ead9f2c06e6a64424abf4da90d01dcb59b290c69af15827568685a9"
)
FROZEN_REVIEWED_ORACLE_SHA256: Final[str] = (
    "4835baf575c37d04cac30a2141895e5ab8d7a0f162a13ea667fc9c9282f5e69e"
)
FROZEN_REVIEWED_VERIFIER_IDENTITY: Final[str] = (
    "verify-path-suffix-inventory-v1"
)
FROZEN_REVIEWED_RESPONSE_SHA256: Final[str] = (
    "1e3344331974528b24198615f19ee4cdb458a56fffbe28d933f32635b0c104a4"
)
FROZEN_REVIEWED_PROGRAM_SHA256: Final[str] = (
    "535ad00b0aec6109c14b9c66e3c13ba694818cdfb9b7a92f7c72f1570cd67ef3"
)
FROZEN_REVIEWED_INVOCATION_SHA256: Final[str] = (
    "373815dde82c7eafc1e4796c320c04d93c1f30209c1350e827e6d3bc85e94a94"
)
FROZEN_REVIEWED_CASE_SHA256: Final[str] = (
    "d5908a48b190de4c60179f94fc6c04dc2607f062c33df223969180373cd15f92"
)


class DevelopmentReviewedBashFixtureError(ValueError):
    """Raised when the fixed reviewed fixture or any nested identity drifts."""


@dataclass(frozen=True, slots=True)
class DevelopmentReviewedBashFixtureCase:
    """Private typed handle for the single reviewed, nonexecuting case."""

    catalog_admission: DevelopmentCatalogAdmission = field(repr=False)
    task: ExecutableStaticTask = field(repr=False)
    profile: ExecutableFixtureProfile = field(repr=False)
    bundle: ExecutableFixtureBundle = field(repr=False)
    invocation: DevelopmentInvocation = field(repr=False)
    reviewed_external_commands: tuple[str, ...]
    case_sha256: str
    schema_version: str = DEVELOPMENT_REVIEWED_BASH_FIXTURE_SCHEMA_VERSION
    review_scope: str = DEVELOPMENT_REVIEWED_BASH_FIXTURE_REVIEW_SCOPE
    candidate_execution_authorized: bool = False
    candidate_executed: bool = False
    scored_evaluation_eligible: bool = False
    model_selection_eligible: bool = False
    claim_pipeline_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_development_reviewed_bash_fixture_case(self)

    @property
    def catalog(self) -> FirstTrancheFixtureCatalog:
        return self.catalog_admission.catalog

    @property
    def response(self) -> bytes:
        return self.invocation.response

    @property
    def program(self) -> bytes:
        return self.invocation.program

    def to_audit_record(self) -> dict[str, object]:
        """Return answer-free metadata without fixture, oracle, or source bytes."""

        validate_development_reviewed_bash_fixture_case(self)
        return {
            **_case_identity_record(self),
            "case_sha256": self.case_sha256,
        }


def _case_identity_record(
    case: DevelopmentReviewedBashFixtureCase,
) -> dict[str, object]:
    admission = case.catalog_admission
    task = case.task
    profile = case.profile
    bundle = case.bundle
    invocation = case.invocation
    return {
        "schema_version": case.schema_version,
        "record_type": DEVELOPMENT_REVIEWED_BASH_FIXTURE_RECORD_TYPE,
        "review_scope": case.review_scope,
        "catalog_sha256": admission.catalog_sha256,
        "catalog_admission_sha256": admission.admission_sha256,
        "registry_sha256": admission.registry_sha256,
        "suite_sha256": admission.suite_sha256,
        "task_id": task.task_id,
        "family_id": task.family_id,
        "task_contract_sha256": task.task_contract_sha256,
        "graph_sha256": task.graph_sha256,
        "parameters": task.parameters.to_record(),
        "profile_id": profile.profile_id,
        "profile_sha256": profile.profile_sha256,
        "fixture_id": bundle.descriptor.fixture_id,
        "fixture_sha256": bundle.descriptor.fixture_sha256,
        "fixture_definition_sha256": bundle.fixture_definition_sha256,
        "oracle_sha256": bundle.oracle.oracle_sha256,
        "semantic_verifier_identity": bundle.oracle.semantic_verifier_identity,
        "invocation_sha256": invocation.invocation_sha256,
        "response_sha256": sha256(invocation.response).hexdigest(),
        "response_bytes": len(invocation.response),
        "program_sha256": invocation.program_sha256,
        "program_bytes": len(invocation.program),
        "fenced": invocation.fenced,
        "allowed_tools": list(task.allowed_tools),
        "reviewed_external_commands": list(case.reviewed_external_commands),
        "candidate_execution_authorized": case.candidate_execution_authorized,
        "candidate_executed": case.candidate_executed,
        "scored_evaluation_eligible": case.scored_evaluation_eligible,
        "model_selection_eligible": case.model_selection_eligible,
        "claim_pipeline_eligible": case.claim_pipeline_eligible,
        "claim_authorized": case.claim_authorized,
    }


def _validate_exact_frozen_identities(
    case: DevelopmentReviewedBashFixtureCase,
) -> None:
    admission = case.catalog_admission
    task = case.task
    profile = case.profile
    bundle = case.bundle
    invocation = case.invocation
    exact = (
        (admission.catalog_sha256, FROZEN_FIRST_CATALOG_SHA256, "catalog"),
        (admission.registry_sha256, FROZEN_FIRST_REGISTRY_SHA256, "registry"),
        (admission.suite_sha256, FROZEN_FIRST_SUITE_SHA256, "suite"),
        (admission.admission_sha256, FROZEN_FIRST_ADMISSION_SHA256, "admission"),
        (task.task_id, FROZEN_REVIEWED_TASK_ID, "task_id"),
        (task.task_contract_sha256, FROZEN_REVIEWED_TASK_SHA256, "task"),
        (task.graph_sha256, FROZEN_REVIEWED_GRAPH_SHA256, "graph"),
        (profile.profile_id, FROZEN_REVIEWED_PROFILE_ID, "profile_id"),
        (profile.profile_sha256, FROZEN_REVIEWED_PROFILE_SHA256, "profile"),
        (bundle.descriptor.fixture_id, FROZEN_REVIEWED_FIXTURE_ID, "fixture_id"),
        (bundle.descriptor.fixture_sha256, FROZEN_REVIEWED_FIXTURE_SHA256, "fixture"),
        (
            bundle.fixture_definition_sha256,
            FROZEN_REVIEWED_FIXTURE_DEFINITION_SHA256,
            "fixture_definition",
        ),
        (bundle.oracle.oracle_sha256, FROZEN_REVIEWED_ORACLE_SHA256, "oracle"),
        (
            bundle.oracle.semantic_verifier_identity,
            FROZEN_REVIEWED_VERIFIER_IDENTITY,
            "semantic_verifier",
        ),
        (
            invocation.invocation_sha256,
            FROZEN_REVIEWED_INVOCATION_SHA256,
            "invocation",
        ),
        (
            sha256(invocation.response).hexdigest(),
            FROZEN_REVIEWED_RESPONSE_SHA256,
            "response",
        ),
        (invocation.program_sha256, FROZEN_REVIEWED_PROGRAM_SHA256, "program"),
    )
    for observed, expected, label in exact:
        if type(observed) is not str or observed != expected:
            raise DevelopmentReviewedBashFixtureError(
                f"reviewed {label} identity differs from its frozen value"
            )


def validate_development_reviewed_bash_fixture_case(
    case: DevelopmentReviewedBashFixtureCase,
) -> None:
    """Exhaustively revalidate the private case and all frozen bindings."""

    if type(case) is not DevelopmentReviewedBashFixtureCase:
        raise DevelopmentReviewedBashFixtureError(
            "case must be an exact DevelopmentReviewedBashFixtureCase"
        )
    if (
        type(case.schema_version) is not str
        or case.schema_version != DEVELOPMENT_REVIEWED_BASH_FIXTURE_SCHEMA_VERSION
        or type(case.review_scope) is not str
        or case.review_scope != DEVELOPMENT_REVIEWED_BASH_FIXTURE_REVIEW_SCOPE
        or type(case.reviewed_external_commands) is not tuple
        or case.reviewed_external_commands != FROZEN_REVIEWED_EXTERNAL_COMMANDS
        or any(type(command) is not str for command in case.reviewed_external_commands)
        or type(case.case_sha256) is not str
        or case.case_sha256 != FROZEN_REVIEWED_CASE_SHA256
        or case.candidate_execution_authorized is not False
        or case.candidate_executed is not False
        or case.scored_evaluation_eligible is not False
        or case.model_selection_eligible is not False
        or case.claim_pipeline_eligible is not False
        or case.claim_authorized is not False
    ):
        raise DevelopmentReviewedBashFixtureError(
            "reviewed case metadata or authority boundary is invalid"
        )
    if type(case.catalog_admission) is not DevelopmentCatalogAdmission:
        raise DevelopmentReviewedBashFixtureError("catalog admission type is invalid")
    if type(case.task) is not ExecutableStaticTask:
        raise DevelopmentReviewedBashFixtureError("task type is invalid")
    if type(case.task.parameters) is not PathSuffixInventoryParameters:
        raise DevelopmentReviewedBashFixtureError("task parameters type is invalid")
    if type(case.profile) is not ExecutableFixtureProfile:
        raise DevelopmentReviewedBashFixtureError("profile type is invalid")
    if type(case.bundle) is not ExecutableFixtureBundle:
        raise DevelopmentReviewedBashFixtureError("fixture bundle type is invalid")
    if type(case.invocation) is not DevelopmentInvocation:
        raise DevelopmentReviewedBashFixtureError("invocation type is invalid")

    try:
        case.task.__post_init__()
        case.profile.__post_init__()
        validate_executable_fixture_bundle(case.bundle)
        if not verify_development_invocation(case.invocation):
            raise DevelopmentReviewedBashFixtureError(
                "reviewed invocation failed validation"
            )
    except DevelopmentReviewedBashFixtureError:
        raise
    except (AttributeError, TypeError, UnicodeError, ValueError) as exc:
        raise DevelopmentReviewedBashFixtureError(
            "reviewed case nested validation failed"
        ) from exc

    parameters = case.task.parameters
    if (
        parameters.suffix != ".txt"
        or parameters.maximum_depth != "unbounded"
        or case.task.family_id != "path-suffix-inventory"
        or case.task.allowed_tools != FROZEN_REVIEWED_EXTERNAL_COMMANDS
        or any(
            command not in case.task.allowed_tools
            for command in case.reviewed_external_commands
        )
        or case.task.public is not True
        or case.task.sealed is not False
        or case.task.claim_authorized is not False
        or case.profile.public_method_development is not True
        or case.profile.sealed is not False
        or case.profile.candidate_execution_authorized is not False
        or case.profile.model_selection_eligible is not False
        or case.profile.claim_authorized is not False
        or case.bundle.candidate_execution_authorized is not False
        or case.bundle.model_selection_eligible is not False
        or case.bundle.claim_authorized is not False
    ):
        raise DevelopmentReviewedBashFixtureError(
            "reviewed task, profile, bundle, or tool policy is invalid"
        )
    if (
        case.invocation.catalog_admission is not case.catalog_admission
        or case.invocation.task is not case.task
        or case.invocation.profile is not case.profile
        or case.invocation.bundle is not case.bundle
        or case.invocation.response != FROZEN_REVIEWED_BASH_RESPONSE.encode("utf-8")
        or case.invocation.program != FROZEN_REVIEWED_BASH_PROGRAM
        or case.invocation.response_bytes != len(case.invocation.response)
        or case.invocation.fenced is not True
        or case.invocation.candidate_execution_authorized is not False
        or case.invocation.candidate_executed is not False
        or case.invocation.scored_evaluation_eligible is not False
        or case.invocation.model_selection_eligible is not False
        or case.invocation.claim_pipeline_eligible is not False
    ):
        raise DevelopmentReviewedBashFixtureError(
            "reviewed invocation does not retain the exact selected case"
        )
    if not any(task is case.task for task in case.catalog.source_registry.tasks):
        raise DevelopmentReviewedBashFixtureError("selected task left the catalog")
    if not any(bundle is case.bundle for bundle in case.catalog.bundles):
        raise DevelopmentReviewedBashFixtureError("selected fixture left the catalog")

    _validate_exact_frozen_identities(case)
    try:
        # This is deliberately after the cheap selected-case checks: valid
        # cases still rederive all 500 catalog members, while obvious forgeries
        # fail without making validation an avoidable denial-of-service lever.
        validate_first_tranche_fixture_catalog(case.catalog)
        case.catalog_admission.__post_init__()
    except (AttributeError, TypeError, UnicodeError, ValueError) as exc:
        raise DevelopmentReviewedBashFixtureError(
            "reviewed catalog admission failed exhaustive validation"
        ) from exc
    try:
        rebuilt_invocation = build_development_invocation(
            case.catalog_admission,
            fixture_id=FROZEN_REVIEWED_FIXTURE_ID,
            response_text=FROZEN_REVIEWED_BASH_RESPONSE,
        )
    except (TypeError, UnicodeError, ValueError) as exc:
        raise DevelopmentReviewedBashFixtureError(
            "reviewed invocation cannot be deterministically reconstructed"
        ) from exc
    if rebuilt_invocation.to_protocol_record() != case.invocation.to_protocol_record():
        raise DevelopmentReviewedBashFixtureError(
            "reviewed parser or invocation binding changed"
        )

    expected_case_sha256 = domain_sha256(
        "cbds.development-reviewed-bash-fixture.case.v1",
        _case_identity_record(case),
    )
    if expected_case_sha256 != case.case_sha256:
        raise DevelopmentReviewedBashFixtureError(
            "reviewed case SHA-256 does not bind its identities"
        )


def verify_development_reviewed_bash_fixture_case(case: object) -> bool:
    """Return whether an object is the exact frozen reviewed private case."""

    try:
        validate_development_reviewed_bash_fixture_case(case)  # type: ignore[arg-type]
    except (AttributeError, TypeError, UnicodeError, ValueError):
        return False
    return True


def build_development_reviewed_bash_fixture_case(
) -> DevelopmentReviewedBashFixtureCase:
    """Rebuild, exhaustively admit, select, and bind the one reviewed case."""

    registry = build_public_method_development_registry()
    catalog = build_first_tranche_fixture_catalog(registry)
    admission = admit_development_catalog(catalog)

    tasks = tuple(
        task
        for task in catalog.source_registry.tasks
        if task.family_id == "path-suffix-inventory"
        and type(task.parameters) is PathSuffixInventoryParameters
        and task.parameters.suffix == ".txt"
        and task.parameters.maximum_depth == "unbounded"
    )
    if len(tasks) != 1:
        raise DevelopmentReviewedBashFixtureError(
            "frozen reviewed task selection is not unique"
        )
    task = tasks[0]
    profiles = tuple(
        profile
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        if profile.profile_id == FROZEN_REVIEWED_PROFILE_ID
        and profile.profile_sha256 == FROZEN_REVIEWED_PROFILE_SHA256
    )
    if len(profiles) != 1:
        raise DevelopmentReviewedBashFixtureError(
            "frozen reviewed profile selection is not unique"
        )
    profile = profiles[0]
    bundles = tuple(
        bundle
        for bundle in catalog.bundles
        if bundle.task_contract_sha256 == task.task_contract_sha256
        and bundle.profile_sha256 == profile.profile_sha256
        and bundle.descriptor.fixture_id == FROZEN_REVIEWED_FIXTURE_ID
    )
    if len(bundles) != 1:
        raise DevelopmentReviewedBashFixtureError(
            "frozen reviewed fixture selection is not unique"
        )
    bundle = bundles[0]
    invocation = build_development_invocation(
        admission,
        fixture_id=bundle.descriptor.fixture_id,
        response_text=FROZEN_REVIEWED_BASH_RESPONSE,
    )
    return DevelopmentReviewedBashFixtureCase(
        catalog_admission=admission,
        task=task,
        profile=profile,
        bundle=bundle,
        invocation=invocation,
        reviewed_external_commands=FROZEN_REVIEWED_EXTERNAL_COMMANDS,
        case_sha256=FROZEN_REVIEWED_CASE_SHA256,
    )


def materialize_development_reviewed_bash_fixture(
    case: DevelopmentReviewedBashFixtureCase,
    workspace: str | os.PathLike[str],
) -> WorkspaceHandle:
    """Authenticate then descriptor-relatively materialize the reviewed bundle."""

    validate_development_reviewed_bash_fixture_case(case)
    return materialize_fixture(case.bundle.definition, workspace)


__all__ = [
    "DEVELOPMENT_REVIEWED_BASH_FIXTURE_RECORD_TYPE",
    "DEVELOPMENT_REVIEWED_BASH_FIXTURE_REVIEW_SCOPE",
    "DEVELOPMENT_REVIEWED_BASH_FIXTURE_SCHEMA_VERSION",
    "DevelopmentReviewedBashFixtureCase",
    "DevelopmentReviewedBashFixtureError",
    "FROZEN_FIRST_ADMISSION_SHA256",
    "FROZEN_FIRST_CATALOG_SHA256",
    "FROZEN_FIRST_REGISTRY_SHA256",
    "FROZEN_FIRST_SUITE_SHA256",
    "FROZEN_REVIEWED_BASH_PROGRAM",
    "FROZEN_REVIEWED_BASH_RESPONSE",
    "FROZEN_REVIEWED_CASE_SHA256",
    "FROZEN_REVIEWED_EXTERNAL_COMMANDS",
    "FROZEN_REVIEWED_FIXTURE_DEFINITION_SHA256",
    "FROZEN_REVIEWED_FIXTURE_ID",
    "FROZEN_REVIEWED_FIXTURE_SHA256",
    "FROZEN_REVIEWED_GRAPH_SHA256",
    "FROZEN_REVIEWED_INVOCATION_SHA256",
    "FROZEN_REVIEWED_ORACLE_SHA256",
    "FROZEN_REVIEWED_PROFILE_ID",
    "FROZEN_REVIEWED_PROFILE_SHA256",
    "FROZEN_REVIEWED_PROGRAM_SHA256",
    "FROZEN_REVIEWED_RESPONSE_SHA256",
    "FROZEN_REVIEWED_TASK_ID",
    "FROZEN_REVIEWED_TASK_SHA256",
    "FROZEN_REVIEWED_VERIFIER_IDENTITY",
    "build_development_reviewed_bash_fixture_case",
    "materialize_development_reviewed_bash_fixture",
    "validate_development_reviewed_bash_fixture_case",
    "verify_development_reviewed_bash_fixture_case",
]
