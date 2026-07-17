"""Catalog-bound, non-executing public-development invocation frames.

This module closes the identity gap between the executable-static fixture
catalog and the future development supervisor.  It can select one exact
public method-development fixture, apply the frozen response parser, and
construct a canonical request containing the Bash program and answer-free
fixture inputs.  It does not launch a process, expose oracle answers, or grant
execution, model-selection, scored-evaluation, or claim authority.

The binary framing is deliberately small and deterministic: an eight-byte
magic, an unsigned 64-bit big-endian payload length, and canonical UTF-8 JSON.
Decoding revalidates every derivable hash and reconstructs the fixture
definition from the transmitted input bytes.  A separate blocked-result frame
exists so callers can exercise both directions of the protocol without
inventing a successful execution result before a trusted supervisor exists.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from hashlib import sha256
import json
import re
import struct
from typing import Final, NoReturn

from .executable_fixture_bundle import (
    ExecutableFixtureBundle,
    compute_fixture_definition_semantic_sha256,
    validate_executable_fixture_bundle,
)
from .executable_fixture_catalog import (
    FIRST_TRANCHE_FIXTURE_COUNT,
    FIRST_TRANCHE_TASK_COUNT,
    FirstTrancheFixtureCatalog,
    validate_first_tranche_fixture_catalog,
)
from .executable_fixture_profiles import (
    ExecutableFixtureProfile,
    fixture_profile_by_sha256,
)
from .executable_static_types import ExecutableStaticTask, domain_sha256
from .executable_workspace import ExpectedFile, FixtureDefinition, InputFile, InputSymlink
from .response import DEFAULT_MAX_RESPONSE_BYTES, ProgramLanguage, ResponseStatus, parse_response


DEVELOPMENT_INVOCATION_SCHEMA_VERSION: Final[str] = "1.0.0"
DEVELOPMENT_INVOCATION_PROTOCOL: Final[str] = "cbds-public-development-v1"
DEVELOPMENT_INVOCATION_KIND: Final[str] = "cbds-development-invocation"
DEVELOPMENT_BLOCKED_RESULT_KIND: Final[str] = "cbds-development-blocked-result"

INVOCATION_FRAME_MAGIC: Final[bytes] = b"CBDSINV1"
BLOCKED_RESULT_FRAME_MAGIC: Final[bytes] = b"CBDSRES1"
FRAME_HEADER_BYTES: Final[int] = 16
MAXIMUM_FRAME_PAYLOAD_BYTES: Final[int] = 24 * 1024 * 1024
MAXIMUM_BLOCKERS: Final[int] = 64
MAXIMUM_BLOCKER_UTF8_BYTES: Final[int] = 256
MAXIMUM_JSON_NODES: Final[int] = 100_000
MAXIMUM_JSON_DEPTH: Final[int] = 32
MAXIMUM_JSON_STRING_BYTES: Final[int] = 24 * 1024 * 1024
MAXIMUM_JSON_PREPARSE_MARKERS: Final[int] = 2 * MAXIMUM_JSON_NODES

FROZEN_FIRST_TRANCHE_REGISTRY_SHA256: Final[str] = (
    "ada6043b345e48f69ad602581030aab1bafcb3ff9dc453f9d02342faaf6a7f9a"
)
FROZEN_FIRST_TRANCHE_SUITE_SHA256: Final[str] = (
    "eb64bb4cdb60ab8e0e228f688cf54810fae2ef56768e8b34ac039bdc1aec42ae"
)
FROZEN_FIRST_TRANCHE_CATALOG_SHA256: Final[str] = (
    "1fc71f89830739a53b69d771b7d0bd6a79a4d78ff698b1c1c2258211e7776c99"
)
FROZEN_FIRST_TRANCHE_ADMISSION_SHA256: Final[str] = (
    "28fad8b1e689c72dc3b28dcae1302902d44251d73a91cd59205c6a8864257a15"
)

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_TASK_ID_RE: Final[re.Pattern[str]] = re.compile(r"mds-[0-9a-f]{24}\Z")
_FIXTURE_ID_RE: Final[re.Pattern[str]] = re.compile(r"fx-[0-9a-f]{24}\Z")
_FAMILY_RE: Final[re.Pattern[str]] = re.compile(r"[a-z][a-z0-9-]{2,63}\Z")
_TOOL_RE: Final[re.Pattern[str]] = re.compile(r"[a-z0-9][a-z0-9._+-]{0,63}\Z")
_BLOCKER_RE: Final[re.Pattern[str]] = re.compile(r"blocked_[a-z0-9_]{3,127}\Z")


class DevelopmentInvocationError(ValueError):
    """Raised when an invocation or protocol frame fails closed validation."""


class DevelopmentInvocationBlocked(RuntimeError):
    """Raised if a caller mistakes this non-executing contract for a runner."""

    def __init__(self, blockers: tuple[str, ...]) -> None:
        self.blockers = blockers
        super().__init__(
            "development invocation is not executable: " + ", ".join(blockers)
        )


@dataclass(frozen=True, slots=True)
class DevelopmentCatalogAdmission:
    """One exhaustively validated admission of the frozen first catalog.

    Admission is deliberately separate from per-invocation validation: the
    expensive deterministic regeneration happens once, while later operations
    still revalidate the selected task and fixture bundle against fixed golden
    catalog, registry, and suite identities.
    """

    catalog: FirstTrancheFixtureCatalog = field(repr=False)
    catalog_sha256: str
    registry_sha256: str
    suite_sha256: str
    member_bindings: tuple[tuple[str, str], ...] = field(repr=False)
    admission_sha256: str

    def __post_init__(self) -> None:
        _validate_catalog_admission(self)


def _catalog_admission_sha256(
    *,
    catalog_sha256: str,
    registry_sha256: str,
    suite_sha256: str,
    member_bindings: tuple[tuple[str, str], ...],
) -> str:
    return domain_sha256(
        "cbds.development-invocation.catalog-admission.v2",
        {
            "catalog_sha256": catalog_sha256,
            "registry_sha256": registry_sha256,
            "suite_sha256": suite_sha256,
            "member_bindings": [
                {"fixture_id": fixture_id, "binding_sha256": binding_sha256}
                for fixture_id, binding_sha256 in member_bindings
            ],
        },
    )


def _catalog_member_binding_sha256(
    bundle: ExecutableFixtureBundle,
    task: ExecutableStaticTask,
) -> str:
    validate_executable_fixture_bundle(bundle)
    task.__post_init__()
    if bundle.task_contract_sha256 != task.task_contract_sha256:
        raise DevelopmentInvocationError("catalog member task and bundle disagree")
    return domain_sha256(
        "cbds.development-invocation.catalog-member.v1",
        {
            "bundle": bundle.commitment_record(),
            "task": task.to_public_record(),
        },
    )


def _build_catalog_member_bindings(
    catalog: FirstTrancheFixtureCatalog,
) -> tuple[tuple[str, str], ...]:
    rows: list[tuple[str, str]] = []
    for bundle in catalog.bundles:
        matches = tuple(
            task
            for task in catalog.source_registry.tasks
            if task.task_contract_sha256 == bundle.task_contract_sha256
        )
        if len(matches) != 1:
            raise DevelopmentInvocationError(
                "catalog fixture task binding is not unique"
            )
        rows.append(
            (
                bundle.descriptor.fixture_id,
                _catalog_member_binding_sha256(bundle, matches[0]),
            )
        )
    return tuple(sorted(rows, key=lambda row: row[0].encode("ascii")))


def _validate_catalog_admission(admission: DevelopmentCatalogAdmission) -> None:
    if type(admission) is not DevelopmentCatalogAdmission:
        raise DevelopmentInvocationError(
            "catalog admission must be exact DevelopmentCatalogAdmission"
        )
    if type(admission.catalog) is not FirstTrancheFixtureCatalog:
        raise DevelopmentInvocationError("catalog admission catalog type is invalid")
    exact = {
        "catalog_sha256": FROZEN_FIRST_TRANCHE_CATALOG_SHA256,
        "registry_sha256": FROZEN_FIRST_TRANCHE_REGISTRY_SHA256,
        "suite_sha256": FROZEN_FIRST_TRANCHE_SUITE_SHA256,
    }
    for name, expected in exact.items():
        if getattr(admission, name) != expected:
            raise DevelopmentInvocationError(
                f"catalog admission field {name!r} is not the frozen identity"
            )
    catalog = admission.catalog
    if (
        catalog.catalog_sha256 != admission.catalog_sha256
        or catalog.source_registry.registry_sha256 != admission.registry_sha256
        or catalog.source_registry.suite_sha256 != admission.suite_sha256
        or type(catalog.bundles) is not tuple
        or len(catalog.bundles) != FIRST_TRANCHE_FIXTURE_COUNT
        or any(type(bundle) is not ExecutableFixtureBundle for bundle in catalog.bundles)
        or type(catalog.source_registry.tasks) is not tuple
        or len(catalog.source_registry.tasks) != FIRST_TRANCHE_TASK_COUNT
        or any(
            type(task) is not ExecutableStaticTask
            for task in catalog.source_registry.tasks
        )
        or catalog.public_method_development is not True
        or catalog.sealed is not False
        or catalog.candidate_execution_authorized is not False
        or catalog.model_selection_eligible is not False
        or catalog.claim_authorized is not False
    ):
        raise DevelopmentInvocationError("catalog admission shell changed")
    bindings = admission.member_bindings
    if (
        type(bindings) is not tuple
        or len(bindings) != FIRST_TRANCHE_FIXTURE_COUNT
        or any(
            type(row) is not tuple
            or len(row) != 2
            or type(row[0]) is not str
            or _FIXTURE_ID_RE.fullmatch(row[0]) is None
            or type(row[1]) is not str
            or _SHA256_RE.fullmatch(row[1]) is None
            for row in bindings
        )
        or tuple(sorted(bindings, key=lambda row: row[0].encode("ascii")))
        != bindings
        or len({row[0] for row in bindings}) != FIRST_TRANCHE_FIXTURE_COUNT
    ):
        raise DevelopmentInvocationError("catalog admission members are invalid")
    try:
        current_ids = tuple(
            sorted(
                (bundle.descriptor.fixture_id for bundle in catalog.bundles),
                key=str.encode,
            )
        )
    except (AttributeError, TypeError, UnicodeEncodeError, ValueError) as exc:
        raise DevelopmentInvocationError(
            "catalog admission membership is unreadable"
        ) from exc
    if current_ids != tuple(row[0] for row in bindings):
        raise DevelopmentInvocationError("catalog admission membership changed")
    expected_admission = _catalog_admission_sha256(
        **exact,
        member_bindings=bindings,
    )
    if (
        admission.admission_sha256 != expected_admission
        or admission.admission_sha256 != FROZEN_FIRST_TRANCHE_ADMISSION_SHA256
    ):
        raise DevelopmentInvocationError("catalog admission SHA-256 is invalid")


def _validate_selected_catalog_member(
    admission: DevelopmentCatalogAdmission,
    bundle: ExecutableFixtureBundle,
    task: ExecutableStaticTask,
) -> None:
    try:
        fixture_id = bundle.descriptor.fixture_id
    except AttributeError as exc:
        raise DevelopmentInvocationError("selected fixture identity is invalid") from exc
    matches = tuple(
        binding_sha256
        for admitted_fixture_id, binding_sha256 in admission.member_bindings
        if admitted_fixture_id == fixture_id
    )
    if len(matches) != 1:
        raise DevelopmentInvocationError("selected fixture is not admitted")
    try:
        current_binding = _catalog_member_binding_sha256(bundle, task)
    except (AttributeError, TypeError, UnicodeError, ValueError) as exc:
        raise DevelopmentInvocationError(
            "selected catalog member is invalid"
        ) from exc
    if matches[0] != current_binding:
        raise DevelopmentInvocationError("selected catalog member changed after admission")


def admit_development_catalog(
    catalog: FirstTrancheFixtureCatalog,
) -> DevelopmentCatalogAdmission:
    """Exhaustively validate the frozen catalog once for repeated handoffs."""

    if type(catalog) is not FirstTrancheFixtureCatalog:
        raise TypeError("catalog must be an exact FirstTrancheFixtureCatalog")
    validate_first_tranche_fixture_catalog(catalog)
    values = {
        "catalog_sha256": catalog.catalog_sha256,
        "registry_sha256": catalog.source_registry.registry_sha256,
        "suite_sha256": catalog.source_registry.suite_sha256,
    }
    if values != {
        "catalog_sha256": FROZEN_FIRST_TRANCHE_CATALOG_SHA256,
        "registry_sha256": FROZEN_FIRST_TRANCHE_REGISTRY_SHA256,
        "suite_sha256": FROZEN_FIRST_TRANCHE_SUITE_SHA256,
    }:
        raise DevelopmentInvocationError("catalog differs from frozen first tranche")
    member_bindings = _build_catalog_member_bindings(catalog)
    return DevelopmentCatalogAdmission(
        catalog=catalog,
        member_bindings=member_bindings,
        admission_sha256=_catalog_admission_sha256(
            **values,
            member_bindings=member_bindings,
        ),
        **values,
    )


def _coerce_catalog_admission(
    value: FirstTrancheFixtureCatalog | DevelopmentCatalogAdmission,
) -> DevelopmentCatalogAdmission:
    if type(value) is DevelopmentCatalogAdmission:
        _validate_catalog_admission(value)
        return value
    if type(value) is FirstTrancheFixtureCatalog:
        return admit_development_catalog(value)
    raise TypeError(
        "catalog must be a FirstTrancheFixtureCatalog or DevelopmentCatalogAdmission"
    )


@dataclass(frozen=True, slots=True)
class DevelopmentInvocation:
    """Private trusted handle for building an answer-free request frame.

    The handle deliberately retains the admitted catalog and selected bundle,
    so it transitively retains trusted-oracle bytes.  It must stay inside the
    trusted controller and must never be handed to a candidate or serialized.
    Only :meth:`to_protocol_record`, :meth:`to_audit_record`, and the canonical
    frame encoder provide boundary-safe projections; each excludes oracle
    answer bytes.
    """

    catalog_admission: DevelopmentCatalogAdmission = field(repr=False)
    task: ExecutableStaticTask = field(repr=False)
    profile: ExecutableFixtureProfile = field(repr=False)
    bundle: ExecutableFixtureBundle = field(repr=False)
    response: bytes = field(repr=False)
    program: bytes = field(repr=False)
    response_bytes: int
    fenced: bool
    invocation_sha256: str
    schema_version: str = DEVELOPMENT_INVOCATION_SCHEMA_VERSION
    protocol: str = DEVELOPMENT_INVOCATION_PROTOCOL
    candidate_execution_authorized: bool = False
    candidate_executed: bool = False
    scored_evaluation_eligible: bool = False
    model_selection_eligible: bool = False
    claim_pipeline_eligible: bool = False

    def __post_init__(self) -> None:
        _validate_invocation(self)

    @property
    def program_sha256(self) -> str:
        return sha256(self.program).hexdigest()

    @property
    def catalog(self) -> FirstTrancheFixtureCatalog:
        return self.catalog_admission.catalog

    def to_protocol_record(self) -> dict[str, object]:
        """Return the private request record used only for supervisor handoff."""

        _validate_invocation(self)
        return _invocation_protocol_record(self, include_self_digest=True)

    def to_audit_record(self) -> dict[str, object]:
        """Return a hash-only record without program, fixture, or oracle bytes."""

        _validate_invocation(self)
        definition = self.bundle.definition
        return {
            "schema_version": self.schema_version,
            "protocol": self.protocol,
            "kind": DEVELOPMENT_INVOCATION_KIND,
            "catalog_sha256": self.catalog_admission.catalog_sha256,
            "catalog_admission_sha256": (
                self.catalog_admission.admission_sha256
            ),
            "task_id": self.task.task_id,
            "family_id": self.task.family_id,
            "task_contract_sha256": self.task.task_contract_sha256,
            "graph_sha256": self.task.graph_sha256,
            "profile_id": self.profile.profile_id,
            "profile_sha256": self.profile.profile_sha256,
            "fixture_id": self.bundle.descriptor.fixture_id,
            "fixture_sha256": self.bundle.descriptor.fixture_sha256,
            "fixture_definition_sha256": self.bundle.fixture_definition_sha256,
            "semantic_verifier_identity": (
                self.bundle.oracle.semantic_verifier_identity
            ),
            "allowed_tools": list(self.task.allowed_tools),
            "allowed_tools_sha256": _allowed_tools_sha256(self.task.allowed_tools),
            "program_bytes": len(self.program),
            "program_sha256": self.program_sha256,
            "response_bytes": self.response_bytes,
            "response_sha256": sha256(self.response).hexdigest(),
            "fenced": self.fenced,
            "input_entry_count": len(definition.inputs),
            "expected_file_count": len(definition.expected_files),
            "invocation_sha256": self.invocation_sha256,
            "candidate_execution_authorized": False,
            "candidate_executed": False,
            "scored_evaluation_eligible": False,
            "model_selection_eligible": False,
            "claim_pipeline_eligible": False,
        }


def build_development_invocation(
    catalog: FirstTrancheFixtureCatalog | DevelopmentCatalogAdmission,
    *,
    fixture_id: str,
    response_text: str,
    maximum_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    was_truncated: bool = False,
) -> DevelopmentInvocation:
    """Build one exact, parsed, still-unauthorized development invocation."""

    admission = _coerce_catalog_admission(catalog)
    selected_catalog = admission.catalog
    if type(fixture_id) is not str or _FIXTURE_ID_RE.fullmatch(fixture_id) is None:
        raise DevelopmentInvocationError("fixture_id must be a canonical fixture id")
    if type(response_text) is not str:
        raise TypeError("response_text must be a string")
    if (
        type(maximum_response_bytes) is not int
        or maximum_response_bytes <= 0
        or maximum_response_bytes > DEFAULT_MAX_RESPONSE_BYTES
    ):
        raise DevelopmentInvocationError(
            "maximum_response_bytes exceeds the frozen response ceiling"
        )

    parsed = parse_response(
        response_text,
        max_bytes=maximum_response_bytes,
        was_truncated=was_truncated,
    )
    if parsed.status is not ResponseStatus.OK or parsed.code is None:
        raise DevelopmentInvocationError(
            f"response parser rejected the candidate: {parsed.status.value}"
        )
    if parsed.language is not ProgramLanguage.BASH:
        raise DevelopmentInvocationError("development invocation accepts Bash only")
    response = response_text.encode("utf-8", errors="strict")
    program = parsed.code.encode("utf-8", errors="strict")

    # Reject nonmembers cheaply before the exhaustive 500-bundle regeneration.
    # Exact tuple/entry checks prevent active containers from being traversed.
    if type(selected_catalog.bundles) is not tuple or any(
        type(bundle) is not ExecutableFixtureBundle
        for bundle in selected_catalog.bundles
    ):
        raise DevelopmentInvocationError("catalog bundle container is invalid")
    matches = tuple(
        bundle
        for bundle in selected_catalog.bundles
        if bundle.descriptor.fixture_id == fixture_id
    )
    if len(matches) != 1:
        raise DevelopmentInvocationError(
            "fixture_id is not a unique member of the validated catalog"
        )
    bundle = matches[0]
    validate_executable_fixture_bundle(bundle)
    task_matches = tuple(
        task
        for task in selected_catalog.source_registry.tasks
        if task.task_contract_sha256 == bundle.task_contract_sha256
    )
    if len(task_matches) != 1:
        raise DevelopmentInvocationError(
            "fixture task is not uniquely bound to the catalog registry"
        )
    task = task_matches[0]
    try:
        profile = fixture_profile_by_sha256(bundle.profile_sha256)
    except ValueError as exc:
        raise DevelopmentInvocationError(
            "fixture profile is outside the closed development profiles"
        ) from exc

    provisional = object.__new__(DevelopmentInvocation)
    for name, value in (
        ("catalog_admission", admission),
        ("task", task),
        ("profile", profile),
        ("bundle", bundle),
        ("response", response),
        ("program", program),
        ("response_bytes", parsed.response_bytes),
        ("fenced", parsed.fenced),
        ("invocation_sha256", "0" * 64),
        ("schema_version", DEVELOPMENT_INVOCATION_SCHEMA_VERSION),
        ("protocol", DEVELOPMENT_INVOCATION_PROTOCOL),
        ("candidate_execution_authorized", False),
        ("candidate_executed", False),
        ("scored_evaluation_eligible", False),
        ("model_selection_eligible", False),
        ("claim_pipeline_eligible", False),
    ):
        object.__setattr__(provisional, name, value)
    digest = _compute_invocation_sha256_unchecked(provisional)
    return DevelopmentInvocation(
        catalog_admission=admission,
        task=task,
        profile=profile,
        bundle=bundle,
        response=response,
        program=program,
        response_bytes=parsed.response_bytes,
        fenced=parsed.fenced,
        invocation_sha256=digest,
    )


def _validate_invocation(invocation: DevelopmentInvocation) -> None:
    if type(invocation) is not DevelopmentInvocation:
        raise DevelopmentInvocationError(
            "invocation must be an exact DevelopmentInvocation"
        )
    try:
        _validate_catalog_admission(invocation.catalog_admission)
    except (AttributeError, TypeError, ValueError) as exc:
        raise DevelopmentInvocationError(
            "invocation catalog admission is invalid"
        ) from exc
    if type(invocation.task) is not ExecutableStaticTask:
        raise DevelopmentInvocationError("invocation task type is invalid")
    invocation.task.__post_init__()
    if type(invocation.profile) is not ExecutableFixtureProfile:
        raise DevelopmentInvocationError("invocation profile type is invalid")
    invocation.profile.__post_init__()
    if type(invocation.bundle) is not ExecutableFixtureBundle:
        raise DevelopmentInvocationError("invocation bundle type is invalid")
    validate_executable_fixture_bundle(invocation.bundle)
    if not any(
        task is invocation.task for task in invocation.catalog.source_registry.tasks
    ):
        raise DevelopmentInvocationError("invocation task is not in the catalog")
    if not any(bundle is invocation.bundle for bundle in invocation.catalog.bundles):
        raise DevelopmentInvocationError("invocation bundle is not in the catalog")
    if invocation.bundle.task_contract_sha256 != invocation.task.task_contract_sha256:
        raise DevelopmentInvocationError("invocation task and bundle do not match")
    if invocation.bundle.profile_sha256 != invocation.profile.profile_sha256:
        raise DevelopmentInvocationError("invocation profile and bundle do not match")
    _validate_selected_catalog_member(
        invocation.catalog_admission,
        invocation.bundle,
        invocation.task,
    )
    _validate_extracted_program_bytes(invocation.program)
    if type(invocation.response) is not bytes or not invocation.response:
        raise DevelopmentInvocationError("response must be nonempty immutable bytes")
    if len(invocation.response) > DEFAULT_MAX_RESPONSE_BYTES:
        raise DevelopmentInvocationError("response exceeds the frozen response ceiling")
    try:
        response_text = invocation.response.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise DevelopmentInvocationError("response is not valid UTF-8") from exc
    reparsed = parse_response(
        response_text,
        max_bytes=DEFAULT_MAX_RESPONSE_BYTES,
    )
    if (
        reparsed.status is not ResponseStatus.OK
        or reparsed.language is not ProgramLanguage.BASH
        or reparsed.code is None
        or reparsed.code.encode("utf-8") != invocation.program
        or reparsed.response_bytes != invocation.response_bytes
        or reparsed.fenced != invocation.fenced
    ):
        raise DevelopmentInvocationError(
            "response metadata or extracted program differs from frozen parser output"
        )
    if type(invocation.response_bytes) is not int or invocation.response_bytes <= 0:
        raise DevelopmentInvocationError("response_bytes must be positive")
    if invocation.response_bytes > DEFAULT_MAX_RESPONSE_BYTES:
        raise DevelopmentInvocationError("response_bytes exceeds the frozen ceiling")
    if len(invocation.program) > invocation.response_bytes:
        raise DevelopmentInvocationError("program bytes exceed source response bytes")
    if type(invocation.fenced) is not bool:
        raise DevelopmentInvocationError("fenced must be boolean")
    if invocation.schema_version != DEVELOPMENT_INVOCATION_SCHEMA_VERSION:
        raise DevelopmentInvocationError("invocation schema_version is unsupported")
    if invocation.protocol != DEVELOPMENT_INVOCATION_PROTOCOL:
        raise DevelopmentInvocationError("invocation protocol is unsupported")
    for name in (
        "candidate_execution_authorized",
        "candidate_executed",
        "scored_evaluation_eligible",
        "model_selection_eligible",
        "claim_pipeline_eligible",
    ):
        if getattr(invocation, name) is not False:
            raise DevelopmentInvocationError(
                "development invocation cannot authorize execution or claims"
            )
    _require_sha256(invocation.invocation_sha256, "invocation_sha256")
    if invocation.invocation_sha256 != _compute_invocation_sha256_unchecked(invocation):
        raise DevelopmentInvocationError(
            "invocation_sha256 does not match invocation content"
        )


def verify_development_invocation(invocation: object) -> bool:
    """Return whether a private invocation and all catalog bindings validate."""

    try:
        _validate_invocation(invocation)  # type: ignore[arg-type]
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def _allowed_tools_sha256(tools: tuple[str, ...]) -> str:
    if (
        type(tools) is not tuple
        or not tools
        or tuple(sorted(set(tools))) != tools
        or any(type(tool) is not str or _TOOL_RE.fullmatch(tool) is None for tool in tools)
    ):
        raise DevelopmentInvocationError("allowed_tools are not canonical")
    return domain_sha256(
        "cbds.development-invocation.allowed-tools.v1",
        {"allowed_tools": list(tools)},
    )


def _validate_extracted_program_bytes(value: object) -> str:
    """Require the transmitted code to be a fixed point of the frozen parser."""

    if type(value) is not bytes or not value:
        raise DevelopmentInvocationError("program must be nonempty immutable bytes")
    if len(value) > DEFAULT_MAX_RESPONSE_BYTES:
        raise DevelopmentInvocationError("program exceeds the frozen response ceiling")
    try:
        text = value.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise DevelopmentInvocationError("program is not valid UTF-8") from exc
    parsed = parse_response(text, max_bytes=DEFAULT_MAX_RESPONSE_BYTES)
    if (
        parsed.status is not ResponseStatus.OK
        or parsed.language is not ProgramLanguage.BASH
        or parsed.code != text
        or parsed.fenced is not False
        or parsed.code_bytes != len(value)
    ):
        raise DevelopmentInvocationError(
            "program is not a fixed point of the frozen Bash response parser"
        )
    return text


def _input_protocol_record(entry: InputFile | InputSymlink) -> dict[str, object]:
    if type(entry) is InputFile:
        entry.__post_init__()
        if entry.mtime_seconds is not None:
            raise DevelopmentInvocationError(
                "invocation protocol v1 does not carry committed input mtimes"
            )
        return {
            "kind": "file",
            "path": entry.path,
            "mode": entry.mode,
            "size": len(entry.content),
            "sha256": sha256(entry.content).hexdigest(),
            "content_base64": base64.b64encode(entry.content).decode("ascii"),
        }
    if type(entry) is InputSymlink:
        entry.__post_init__()
        return {"kind": "symlink", "path": entry.path, "target": entry.target}
    raise DevelopmentInvocationError("fixture input type is invalid")


def _invocation_protocol_record(
    invocation: DevelopmentInvocation,
    *,
    include_self_digest: bool,
) -> dict[str, object]:
    definition = invocation.bundle.definition
    definition.__post_init__()
    record: dict[str, object] = {
        "schema_version": DEVELOPMENT_INVOCATION_SCHEMA_VERSION,
        "protocol": DEVELOPMENT_INVOCATION_PROTOCOL,
        "kind": DEVELOPMENT_INVOCATION_KIND,
        "catalog_sha256": invocation.catalog_admission.catalog_sha256,
        "catalog_admission_sha256": (
            invocation.catalog_admission.admission_sha256
        ),
        "task": {
            "task_id": invocation.task.task_id,
            "family_id": invocation.task.family_id,
            "task_contract_sha256": invocation.task.task_contract_sha256,
            "graph_sha256": invocation.task.graph_sha256,
        },
        "profile": {
            "profile_id": invocation.profile.profile_id,
            "profile_sha256": invocation.profile.profile_sha256,
        },
        "fixture": {
            "fixture_id": invocation.bundle.descriptor.fixture_id,
            "fixture_sha256": invocation.bundle.descriptor.fixture_sha256,
            "fixture_definition_sha256": invocation.bundle.fixture_definition_sha256,
            "semantic_verifier_identity": (
                invocation.bundle.oracle.semantic_verifier_identity
            ),
        },
        "tool_policy": {
            "allowed_tools": list(invocation.task.allowed_tools),
            "allowed_tools_sha256": _allowed_tools_sha256(
                invocation.task.allowed_tools
            ),
            "enforced": False,
        },
        "program": {
            "encoding": "utf-8",
            "content_base64": base64.b64encode(invocation.program).decode("ascii"),
            "bytes": len(invocation.program),
            "sha256": invocation.program_sha256,
            "response_base64": base64.b64encode(invocation.response).decode("ascii"),
            "response_sha256": sha256(invocation.response).hexdigest(),
            "response_bytes": invocation.response_bytes,
            "fenced": invocation.fenced,
        },
        "workspace": {
            "fixture_definition_sha256": invocation.bundle.fixture_definition_sha256,
            "initial_output_policy": "all-paths-outside-input-absent",
            "inputs": [_input_protocol_record(entry) for entry in definition.inputs],
            "expected_files": [
                expected.to_record() for expected in definition.expected_files
            ],
        },
        "candidate_execution_authorized": False,
        "candidate_executed": False,
        "scored_evaluation_eligible": False,
        "model_selection_eligible": False,
        "claim_pipeline_eligible": False,
    }
    if include_self_digest:
        record["invocation_sha256"] = invocation.invocation_sha256
    return record


def _compute_invocation_sha256_unchecked(invocation: DevelopmentInvocation) -> str:
    return domain_sha256(
        "cbds.development-invocation.request.v1",
        _invocation_protocol_record(invocation, include_self_digest=False),
    )


def encode_development_invocation_frame(
    invocation: DevelopmentInvocation,
) -> bytes:
    """Encode one canonical private request frame without executing it."""

    _validate_invocation(invocation)
    payload = _canonical_json_bytes(
        _invocation_protocol_record(invocation, include_self_digest=True)
    )
    return _encode_frame(INVOCATION_FRAME_MAGIC, payload)


def decode_development_invocation_frame(
    frame: bytes,
    *,
    catalog: FirstTrancheFixtureCatalog | DevelopmentCatalogAdmission,
) -> dict[str, object]:
    """Strictly decode and independently revalidate one invocation frame."""

    payload = _decode_frame(frame, expected_magic=INVOCATION_FRAME_MAGIC)
    record = _decode_canonical_json_object(payload)
    validate_development_invocation_record_against_catalog(record, catalog)
    return record


def _validate_invocation_protocol_record(record: dict[str, object]) -> None:
    expected_top = {
        "schema_version",
        "protocol",
        "kind",
        "catalog_sha256",
        "catalog_admission_sha256",
        "task",
        "profile",
        "fixture",
        "tool_policy",
        "program",
        "workspace",
        "candidate_execution_authorized",
        "candidate_executed",
        "scored_evaluation_eligible",
        "model_selection_eligible",
        "claim_pipeline_eligible",
        "invocation_sha256",
    }
    if type(record) is not dict or set(record) != expected_top:
        raise DevelopmentInvocationError("invocation record shape is invalid")
    exact = {
        "schema_version": DEVELOPMENT_INVOCATION_SCHEMA_VERSION,
        "protocol": DEVELOPMENT_INVOCATION_PROTOCOL,
        "kind": DEVELOPMENT_INVOCATION_KIND,
        "candidate_execution_authorized": False,
        "candidate_executed": False,
        "scored_evaluation_eligible": False,
        "model_selection_eligible": False,
        "claim_pipeline_eligible": False,
    }
    for name, expected in exact.items():
        if record.get(name) != expected:
            raise DevelopmentInvocationError(f"invocation field {name!r} is invalid")
    _require_sha256(record.get("catalog_sha256"), "catalog_sha256")
    _require_sha256(
        record.get("catalog_admission_sha256"),
        "catalog_admission_sha256",
    )
    task = _exact_object(
        record.get("task"),
        {"task_id", "family_id", "task_contract_sha256", "graph_sha256"},
        "task",
    )
    if type(task.get("task_id")) is not str or _TASK_ID_RE.fullmatch(task["task_id"]) is None:
        raise DevelopmentInvocationError("task_id is invalid")
    if type(task.get("family_id")) is not str or _FAMILY_RE.fullmatch(task["family_id"]) is None:
        raise DevelopmentInvocationError("family_id is invalid")
    task_hash = _require_sha256(task.get("task_contract_sha256"), "task_contract_sha256")
    if task["task_id"] != f"mds-{task_hash[:24]}":
        raise DevelopmentInvocationError("task_id is not derived from task contract")
    _require_sha256(task.get("graph_sha256"), "graph_sha256")

    profile = _exact_object(
        record.get("profile"), {"profile_id", "profile_sha256"}, "profile"
    )
    profile_hash = _require_sha256(profile.get("profile_sha256"), "profile_sha256")
    if type(profile.get("profile_id")) is not str:
        raise DevelopmentInvocationError("profile_id is invalid")
    try:
        known_profile = fixture_profile_by_sha256(profile_hash)
    except ValueError as exc:
        raise DevelopmentInvocationError("profile commitment is unknown") from exc
    if profile["profile_id"] != known_profile.profile_id:
        raise DevelopmentInvocationError("profile_id and profile_sha256 disagree")

    fixture = _exact_object(
        record.get("fixture"),
        {
            "fixture_id",
            "fixture_sha256",
            "fixture_definition_sha256",
            "semantic_verifier_identity",
        },
        "fixture",
    )
    fixture_hash = _require_sha256(fixture.get("fixture_sha256"), "fixture_sha256")
    definition_hash = _require_sha256(
        fixture.get("fixture_definition_sha256"), "fixture_definition_sha256"
    )
    fixture_id = fixture.get("fixture_id")
    if type(fixture_id) is not str or _FIXTURE_ID_RE.fullmatch(fixture_id) is None:
        raise DevelopmentInvocationError("fixture_id is invalid")
    if fixture_id != f"fx-{fixture_hash[:24]}":
        raise DevelopmentInvocationError("fixture_id is not derived from fixture hash")
    verifier = fixture.get("semantic_verifier_identity")
    if type(verifier) is not str or not verifier.startswith("verify-"):
        raise DevelopmentInvocationError("semantic verifier identity is invalid")

    tool_policy = _exact_object(
        record.get("tool_policy"),
        {"allowed_tools", "allowed_tools_sha256", "enforced"},
        "tool_policy",
    )
    if tool_policy.get("enforced") is not False:
        raise DevelopmentInvocationError("tool policy cannot claim enforcement")
    tools_raw = tool_policy.get("allowed_tools")
    if type(tools_raw) is not list or any(type(tool) is not str for tool in tools_raw):
        raise DevelopmentInvocationError("allowed_tools must be a string array")
    tools = tuple(tools_raw)
    if tool_policy.get("allowed_tools_sha256") != _allowed_tools_sha256(tools):
        raise DevelopmentInvocationError("allowed_tools_sha256 is invalid")

    program = _exact_object(
        record.get("program"),
        {
            "encoding",
            "content_base64",
            "bytes",
            "sha256",
            "response_base64",
            "response_sha256",
            "response_bytes",
            "fenced",
        },
        "program",
    )
    if program.get("encoding") != "utf-8":
        raise DevelopmentInvocationError("program encoding is invalid")
    program_bytes = _decode_base64(program.get("content_base64"), "program content")
    _validate_extracted_program_bytes(program_bytes)
    if (
        type(program.get("bytes")) is not int
        or program["bytes"] != len(program_bytes)
        or len(program_bytes) > DEFAULT_MAX_RESPONSE_BYTES
    ):
        raise DevelopmentInvocationError("program byte count is invalid")
    if program.get("sha256") != sha256(program_bytes).hexdigest():
        raise DevelopmentInvocationError("program SHA-256 is invalid")
    response_bytes = _decode_base64(
        program.get("response_base64"), "source response"
    )
    if (
        not response_bytes
        or len(response_bytes) > DEFAULT_MAX_RESPONSE_BYTES
        or program.get("response_sha256") != sha256(response_bytes).hexdigest()
    ):
        raise DevelopmentInvocationError("source response identity is invalid")
    if (
        type(program.get("response_bytes")) is not int
        or program["response_bytes"] <= 0
        or program["response_bytes"] != len(response_bytes)
        or len(program_bytes) > program["response_bytes"]
    ):
        raise DevelopmentInvocationError("response byte count is invalid")
    if type(program.get("fenced")) is not bool:
        raise DevelopmentInvocationError("program fenced flag is invalid")
    try:
        response_text = response_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise DevelopmentInvocationError("source response is not UTF-8") from exc
    reparsed = parse_response(
        response_text,
        max_bytes=DEFAULT_MAX_RESPONSE_BYTES,
    )
    if (
        reparsed.status is not ResponseStatus.OK
        or reparsed.language is not ProgramLanguage.BASH
        or reparsed.code is None
        or reparsed.code.encode("utf-8") != program_bytes
        or reparsed.response_bytes != program["response_bytes"]
        or reparsed.fenced != program["fenced"]
    ):
        raise DevelopmentInvocationError(
            "source response does not reproduce the transmitted parser result"
        )

    workspace = _exact_object(
        record.get("workspace"),
        {"fixture_definition_sha256", "initial_output_policy", "inputs", "expected_files"},
        "workspace",
    )
    if workspace.get("fixture_definition_sha256") != definition_hash:
        raise DevelopmentInvocationError("workspace fixture definition hash disagrees")
    if workspace.get("initial_output_policy") != "all-paths-outside-input-absent":
        raise DevelopmentInvocationError("workspace initial output policy is invalid")
    definition = _definition_from_protocol_record(
        fixture_id=fixture_id,
        inputs=workspace.get("inputs"),
        expected_files=workspace.get("expected_files"),
    )
    if compute_fixture_definition_semantic_sha256(definition) != definition_hash:
        raise DevelopmentInvocationError("fixture definition SHA-256 is invalid")
    invocation_hash = _require_sha256(
        record.get("invocation_sha256"), "invocation_sha256"
    )
    unsigned = dict(record)
    del unsigned["invocation_sha256"]
    expected_invocation = domain_sha256(
        "cbds.development-invocation.request.v1", unsigned
    )
    if invocation_hash != expected_invocation:
        raise DevelopmentInvocationError("invocation SHA-256 is invalid")


def validate_development_invocation_record_against_catalog(
    record: dict[str, object],
    catalog: FirstTrancheFixtureCatalog | DevelopmentCatalogAdmission,
) -> None:
    """Bind a structurally valid request to one exact frozen catalog member."""

    _validate_invocation_protocol_record(record)
    admission = _coerce_catalog_admission(catalog)
    selected_catalog = admission.catalog
    if record.get("catalog_sha256") != admission.catalog_sha256:
        raise DevelopmentInvocationError("invocation names a different catalog")
    if record.get("catalog_admission_sha256") != admission.admission_sha256:
        raise DevelopmentInvocationError(
            "invocation names a different catalog admission"
        )
    fixture = record["fixture"]
    if type(fixture) is not dict:  # defensive after structural validation
        raise DevelopmentInvocationError("fixture object disappeared")
    fixture_id = fixture["fixture_id"]
    matches = tuple(
        bundle
        for bundle in selected_catalog.bundles
        if bundle.descriptor.fixture_id == fixture_id
    )
    if len(matches) != 1:
        raise DevelopmentInvocationError(
            "invocation fixture is not a unique catalog member"
        )
    bundle = matches[0]
    validate_executable_fixture_bundle(bundle)
    task_matches = tuple(
        task
        for task in selected_catalog.source_registry.tasks
        if task.task_contract_sha256 == bundle.task_contract_sha256
    )
    if len(task_matches) != 1:
        raise DevelopmentInvocationError("catalog task binding is not unique")
    task = task_matches[0]
    task.__post_init__()
    try:
        profile = fixture_profile_by_sha256(bundle.profile_sha256)
        profile.__post_init__()
    except (TypeError, ValueError) as exc:
        raise DevelopmentInvocationError(
            "catalog member profile is invalid"
        ) from exc
    _validate_selected_catalog_member(admission, bundle, task)
    expected_fixture = {
        "fixture_id": bundle.descriptor.fixture_id,
        "fixture_sha256": bundle.descriptor.fixture_sha256,
        "fixture_definition_sha256": bundle.fixture_definition_sha256,
        "semantic_verifier_identity": bundle.oracle.semantic_verifier_identity,
    }
    if fixture != expected_fixture:
        raise DevelopmentInvocationError("invocation fixture differs from catalog")
    expected_task = {
        "task_id": task.task_id,
        "family_id": task.family_id,
        "task_contract_sha256": task.task_contract_sha256,
        "graph_sha256": task.graph_sha256,
    }
    if record.get("task") != expected_task:
        raise DevelopmentInvocationError("invocation task differs from catalog")
    expected_profile = {
        "profile_id": profile.profile_id,
        "profile_sha256": profile.profile_sha256,
    }
    if record.get("profile") != expected_profile:
        raise DevelopmentInvocationError("invocation profile differs from catalog")
    expected_tool_policy = {
        "allowed_tools": list(task.allowed_tools),
        "allowed_tools_sha256": _allowed_tools_sha256(task.allowed_tools),
        "enforced": False,
    }
    if record.get("tool_policy") != expected_tool_policy:
        raise DevelopmentInvocationError("invocation tool policy differs from catalog")
    expected_workspace = {
        "fixture_definition_sha256": bundle.fixture_definition_sha256,
        "initial_output_policy": "all-paths-outside-input-absent",
        "inputs": [_input_protocol_record(entry) for entry in bundle.definition.inputs],
        "expected_files": [
            expected.to_record() for expected in bundle.definition.expected_files
        ],
    }
    if record.get("workspace") != expected_workspace:
        raise DevelopmentInvocationError("invocation workspace differs from catalog")


def _definition_from_protocol_record(
    *, fixture_id: str, inputs: object, expected_files: object
) -> FixtureDefinition:
    if type(inputs) is not list:
        raise DevelopmentInvocationError("workspace inputs must be an array")
    selected_inputs: list[InputFile | InputSymlink] = []
    for raw in inputs:
        if type(raw) is not dict:
            raise DevelopmentInvocationError("workspace input must be an object")
        kind = raw.get("kind")
        if kind == "file":
            if set(raw) != {"kind", "path", "mode", "size", "sha256", "content_base64"}:
                raise DevelopmentInvocationError("workspace file input shape is invalid")
            content = _decode_base64(raw.get("content_base64"), "workspace file content")
            if type(raw.get("size")) is not int or raw["size"] != len(content):
                raise DevelopmentInvocationError("workspace file size is invalid")
            if raw.get("sha256") != sha256(content).hexdigest():
                raise DevelopmentInvocationError("workspace file SHA-256 is invalid")
            try:
                selected_inputs.append(
                    InputFile(path=raw.get("path"), content=content, mode=raw.get("mode"))  # type: ignore[arg-type]
                )
            except (TypeError, ValueError) as exc:
                raise DevelopmentInvocationError("workspace file input is invalid") from exc
        elif kind == "symlink":
            if set(raw) != {"kind", "path", "target"}:
                raise DevelopmentInvocationError("workspace symlink input shape is invalid")
            try:
                selected_inputs.append(
                    InputSymlink(path=raw.get("path"), target=raw.get("target"))  # type: ignore[arg-type]
                )
            except (TypeError, ValueError) as exc:
                raise DevelopmentInvocationError("workspace symlink input is invalid") from exc
        else:
            raise DevelopmentInvocationError("workspace input kind is invalid")
    if type(expected_files) is not list:
        raise DevelopmentInvocationError("expected_files must be an array")
    selected_expected: list[ExpectedFile] = []
    for raw in expected_files:
        if type(raw) is not dict or set(raw) != {
            "path", "maximum_bytes", "mode", "required_kind", "required_link_count"
        }:
            raise DevelopmentInvocationError("expected file policy shape is invalid")
        if raw.get("required_kind") != "regular" or raw.get("required_link_count") != 1:
            raise DevelopmentInvocationError("expected file kind policy is invalid")
        try:
            selected_expected.append(
                ExpectedFile(
                    path=raw.get("path"),  # type: ignore[arg-type]
                    maximum_bytes=raw.get("maximum_bytes"),  # type: ignore[arg-type]
                    mode=raw.get("mode"),  # type: ignore[arg-type]
                )
            )
        except (TypeError, ValueError) as exc:
            raise DevelopmentInvocationError("expected file policy is invalid") from exc
    try:
        return FixtureDefinition(
            fixture_id=fixture_id,
            inputs=tuple(selected_inputs),
            expected_files=tuple(selected_expected),
        )
    except (TypeError, ValueError) as exc:
        raise DevelopmentInvocationError("workspace fixture definition is invalid") from exc


def build_blocked_development_result(
    invocation: DevelopmentInvocation,
    blockers: tuple[str, ...],
) -> dict[str, object]:
    """Build the only result state admitted before a supervisor exists."""

    _validate_invocation(invocation)
    selected = _validate_blockers(blockers)
    record: dict[str, object] = {
        "schema_version": DEVELOPMENT_INVOCATION_SCHEMA_VERSION,
        "protocol": DEVELOPMENT_INVOCATION_PROTOCOL,
        "kind": DEVELOPMENT_BLOCKED_RESULT_KIND,
        "invocation_sha256": invocation.invocation_sha256,
        "status": "candidate_execution_blocked",
        "blockers": list(selected),
        "candidate_executed": False,
        "stdout_captured": False,
        "stderr_captured": False,
        "workspace_scanned": False,
        "functional_verification_performed": False,
        "scored_evaluation_eligible": False,
        "model_selection_eligible": False,
        "claim_pipeline_eligible": False,
    }
    record["result_sha256"] = _blocked_result_sha256(record)
    return record


def encode_blocked_development_result_frame(record: dict[str, object]) -> bytes:
    """Validate and encode a canonical blocked-result frame."""

    _validate_blocked_result_record(record)
    return _encode_frame(BLOCKED_RESULT_FRAME_MAGIC, _canonical_json_bytes(record))


def decode_blocked_development_result_frame(
    frame: bytes,
    *,
    expected_invocation_sha256: str,
) -> dict[str, object]:
    """Decode the only pre-supervisor result type: execution blocked."""

    payload = _decode_frame(frame, expected_magic=BLOCKED_RESULT_FRAME_MAGIC)
    record = _decode_canonical_json_object(payload)
    _validate_blocked_result_record(record)
    expected = _require_sha256(
        expected_invocation_sha256, "expected_invocation_sha256"
    )
    if record.get("invocation_sha256") != expected:
        raise DevelopmentInvocationError(
            "blocked result is bound to a different invocation"
        )
    return record


def _blocked_result_sha256(record: dict[str, object]) -> str:
    unsigned = dict(record)
    unsigned.pop("result_sha256", None)
    return domain_sha256("cbds.development-invocation.blocked-result.v1", unsigned)


def _validate_blocked_result_record(record: dict[str, object]) -> None:
    expected = {
        "schema_version", "protocol", "kind", "invocation_sha256", "status",
        "blockers", "candidate_executed", "stdout_captured", "stderr_captured",
        "workspace_scanned", "functional_verification_performed",
        "scored_evaluation_eligible", "model_selection_eligible",
        "claim_pipeline_eligible", "result_sha256",
    }
    if type(record) is not dict or set(record) != expected:
        raise DevelopmentInvocationError("blocked result shape is invalid")
    exact = {
        "schema_version": DEVELOPMENT_INVOCATION_SCHEMA_VERSION,
        "protocol": DEVELOPMENT_INVOCATION_PROTOCOL,
        "kind": DEVELOPMENT_BLOCKED_RESULT_KIND,
        "status": "candidate_execution_blocked",
        "candidate_executed": False,
        "stdout_captured": False,
        "stderr_captured": False,
        "workspace_scanned": False,
        "functional_verification_performed": False,
        "scored_evaluation_eligible": False,
        "model_selection_eligible": False,
        "claim_pipeline_eligible": False,
    }
    for name, value in exact.items():
        if record.get(name) != value:
            raise DevelopmentInvocationError(f"blocked result field {name!r} is invalid")
    _require_sha256(record.get("invocation_sha256"), "invocation_sha256")
    blockers_raw = record.get("blockers")
    if type(blockers_raw) is not list or any(type(item) is not str for item in blockers_raw):
        raise DevelopmentInvocationError("blocked result blockers are invalid")
    _validate_blockers(tuple(blockers_raw))
    digest = _require_sha256(record.get("result_sha256"), "result_sha256")
    if digest != _blocked_result_sha256(record):
        raise DevelopmentInvocationError("blocked result SHA-256 is invalid")


def refuse_development_invocation(
    invocation: DevelopmentInvocation,
    blockers: tuple[str, ...],
) -> NoReturn:
    """Explicitly demonstrate that this protocol cannot launch a candidate."""

    _validate_invocation(invocation)
    raise DevelopmentInvocationBlocked(_validate_blockers(blockers))


def _validate_blockers(blockers: tuple[str, ...]) -> tuple[str, ...]:
    if (
        type(blockers) is not tuple
        or not blockers
        or len(blockers) > MAXIMUM_BLOCKERS
        or tuple(dict.fromkeys(blockers)) != blockers
    ):
        raise DevelopmentInvocationError("blockers must be a nonempty unique tuple")
    for blocker in blockers:
        if (
            type(blocker) is not str
            or _BLOCKER_RE.fullmatch(blocker) is None
            or len(blocker.encode("utf-8")) > MAXIMUM_BLOCKER_UTF8_BYTES
        ):
            raise DevelopmentInvocationError("blocker identity is invalid")
    return blockers


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise DevelopmentInvocationError("value is not canonical JSON") from exc


def _decode_canonical_json_object(payload: bytes) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise DevelopmentInvocationError("JSON contains a duplicate key")
            result[key] = value
        return result

    _prevalidate_json_structure(payload)
    try:
        text = payload.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(
                DevelopmentInvocationError(f"invalid JSON constant {token}")
            ),
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ) as exc:
        raise DevelopmentInvocationError("frame payload is not strict UTF-8 JSON") from exc
    if type(value) is not dict:
        raise DevelopmentInvocationError("frame payload must be a JSON object")
    _validate_plain_json_bounds(value)
    try:
        canonical = _canonical_json_bytes(value)
    except RecursionError as exc:  # defensive after the explicit depth bound
        raise DevelopmentInvocationError("frame JSON nesting is invalid") from exc
    if canonical != payload:
        raise DevelopmentInvocationError("frame payload is not canonical JSON")
    return value


def _prevalidate_json_structure(payload: bytes) -> None:
    """Bound possible container depth and node growth before ``json.loads``.

    Every additional JSON value requires either a container opener or a comma
    separating it from a sibling.  A valid tree with at most ``N`` decoded
    nodes therefore contains fewer than ``2N`` of these markers.  Enforcing
    that loose upper bound before allocation limits hostile frames to a small
    constant factor of the exact post-parse node ceiling; the exact walk below
    still enforces ``MAXIMUM_JSON_NODES``.
    """

    if type(payload) is not bytes or not payload:
        raise DevelopmentInvocationError("frame payload must be nonempty bytes")
    depth = 0
    markers = 0
    in_string = False
    escaped = False
    for byte in payload:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:  # backslash
                escaped = True
            elif byte == 0x22:  # quote
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte in {0x7B, 0x5B}:  # { [
            depth += 1
            markers += 1
            if depth > MAXIMUM_JSON_DEPTH:
                raise DevelopmentInvocationError(
                    "frame JSON exceeds preparsing depth bound"
                )
        elif byte in {0x7D, 0x5D}:  # } ]
            depth -= 1
            if depth < 0:
                raise DevelopmentInvocationError(
                    "frame JSON has an unmatched closing delimiter"
                )
        elif byte == 0x2C:  # comma
            markers += 1
        if markers > MAXIMUM_JSON_PREPARSE_MARKERS:
            raise DevelopmentInvocationError(
                "frame JSON exceeds preparsing allocation bound"
            )


def _validate_plain_json_bounds(value: object) -> None:
    """Bound decoded container growth before schema-specific reconstruction."""

    nodes = 0
    stack: list[tuple[object, int]] = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAXIMUM_JSON_NODES or depth > MAXIMUM_JSON_DEPTH:
            raise DevelopmentInvocationError("frame JSON exceeds structural bounds")
        if type(item) is dict:
            for key, nested in item.items():  # type: ignore[union-attr]
                if (
                    type(key) is not str
                    or _strict_utf8_length(key, "frame JSON key")
                    > MAXIMUM_JSON_STRING_BYTES
                ):
                    raise DevelopmentInvocationError("frame JSON key is invalid")
                stack.append((nested, depth + 1))
        elif type(item) is list:
            stack.extend((nested, depth + 1) for nested in item)  # type: ignore[union-attr]
        elif type(item) is str:
            if (
                _strict_utf8_length(item, "frame JSON string")
                > MAXIMUM_JSON_STRING_BYTES
            ):
                raise DevelopmentInvocationError("frame JSON string exceeds bounds")
        elif type(item) not in {int, bool} and item is not None:
            raise DevelopmentInvocationError(
                "frame JSON contains a noncanonical scalar"
            )


def _strict_utf8_length(value: str, what: str) -> int:
    try:
        return len(value.encode("utf-8", errors="strict"))
    except UnicodeEncodeError as exc:
        raise DevelopmentInvocationError(f"{what} is not valid Unicode text") from exc


def _encode_frame(magic: bytes, payload: bytes) -> bytes:
    if type(magic) is not bytes or len(magic) != 8:
        raise DevelopmentInvocationError("frame magic is invalid")
    if type(payload) is not bytes or not payload:
        raise DevelopmentInvocationError("frame payload must be nonempty bytes")
    if len(payload) > MAXIMUM_FRAME_PAYLOAD_BYTES:
        raise DevelopmentInvocationError("frame payload exceeds the fixed byte limit")
    return magic + struct.pack(">Q", len(payload)) + payload


def _decode_frame(frame: bytes, *, expected_magic: bytes) -> bytes:
    if type(frame) is not bytes:
        raise TypeError("frame must be immutable bytes")
    if len(frame) < FRAME_HEADER_BYTES:
        raise DevelopmentInvocationError("frame is shorter than its header")
    if frame[:8] != expected_magic:
        raise DevelopmentInvocationError("frame magic is invalid")
    declared = struct.unpack(">Q", frame[8:16])[0]
    if declared == 0 or declared > MAXIMUM_FRAME_PAYLOAD_BYTES:
        raise DevelopmentInvocationError("frame payload length is outside bounds")
    if len(frame) != FRAME_HEADER_BYTES + declared:
        raise DevelopmentInvocationError("frame length does not match its header")
    return frame[FRAME_HEADER_BYTES:]


def _exact_object(value: object, keys: set[str], what: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise DevelopmentInvocationError(f"{what} object shape is invalid")
    return value


def _decode_base64(value: object, what: str) -> bytes:
    if type(value) is not str or not value.isascii():
        raise DevelopmentInvocationError(f"{what} base64 is invalid")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise DevelopmentInvocationError(f"{what} base64 is invalid") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise DevelopmentInvocationError(f"{what} base64 is not canonical")
    return decoded


def _require_sha256(value: object, what: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise DevelopmentInvocationError(f"{what} must be lowercase SHA-256")
    return value


__all__ = [
    "BLOCKED_RESULT_FRAME_MAGIC",
    "DEVELOPMENT_BLOCKED_RESULT_KIND",
    "DEVELOPMENT_INVOCATION_KIND",
    "DEVELOPMENT_INVOCATION_PROTOCOL",
    "DEVELOPMENT_INVOCATION_SCHEMA_VERSION",
    "FRAME_HEADER_BYTES",
    "FROZEN_FIRST_TRANCHE_ADMISSION_SHA256",
    "FROZEN_FIRST_TRANCHE_CATALOG_SHA256",
    "FROZEN_FIRST_TRANCHE_REGISTRY_SHA256",
    "FROZEN_FIRST_TRANCHE_SUITE_SHA256",
    "INVOCATION_FRAME_MAGIC",
    "MAXIMUM_FRAME_PAYLOAD_BYTES",
    "MAXIMUM_JSON_DEPTH",
    "MAXIMUM_JSON_NODES",
    "DevelopmentCatalogAdmission",
    "DevelopmentInvocation",
    "DevelopmentInvocationBlocked",
    "DevelopmentInvocationError",
    "admit_development_catalog",
    "build_blocked_development_result",
    "build_development_invocation",
    "decode_blocked_development_result_frame",
    "decode_development_invocation_frame",
    "encode_blocked_development_result_frame",
    "encode_development_invocation_frame",
    "refuse_development_invocation",
    "validate_development_invocation_record_against_catalog",
    "verify_development_invocation",
]
