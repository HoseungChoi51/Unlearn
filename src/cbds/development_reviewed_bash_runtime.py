"""One pinned, non-authorizing Bash runtime case for development integration.

This module composes the source-manifest, materialization, and sealed-FD
snapshot boundaries for exactly four source-reviewed host executables: Bash,
find, sort, and mkdir.  The executable digests and the complete supported
ELF closure are pinned to the development host on which this case was
reviewed.  A different host fails closed instead of silently defining a new
runtime.

The supported closure remains deliberately narrow.  It covers ``PT_INTERP``
and ``DT_NEEDED`` resolution through one explicit library search directory;
it does not establish Bash runtime-data or ``dlopen`` closure, external trust
in the executable semantics, namespace projection, launch handoff, candidate
execution, scoring, model selection, or claim authority.  The returned case
owns sealed regular-payload descriptors and is therefore a context manager.
Its audit projection contains identities and counts, never runtime payloads,
descriptor numbers, a fixture, a candidate program, or oracle answers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import fcntl
from hashlib import sha256
import os
from pathlib import Path
from typing import Final

from .development_runtime_bundle import (
    DevelopmentRuntimeBundleError,
    DevelopmentRuntimeExecutable,
    build_development_runtime_bundle_manifest,
    canonical_development_runtime_json_bytes,
    validate_development_runtime_bundle_manifest,
    verify_development_runtime_bundle_sha256,
)
from .development_runtime_fd_snapshot import (
    DevelopmentRuntimeFdSlot,
    DevelopmentRuntimeFdSnapshot,
    DevelopmentRuntimeFdSnapshotError,
    snapshot_development_runtime_for_launch,
    verify_development_runtime_fd_snapshot_structure,
)
from .development_runtime_materializer import (
    DevelopmentRuntimeMaterializationError,
    DevelopmentRuntimeMaterializationEvidence,
    DevelopmentRuntimeMaterializedDirectory,
    DevelopmentRuntimeMaterializedEntry,
    materialize_development_runtime_bundle,
    verify_development_runtime_materialization_evidence_structure,
)


DEVELOPMENT_REVIEWED_BASH_RUNTIME_SCHEMA_VERSION: Final[str] = "1.0.0"
DEVELOPMENT_REVIEWED_BASH_RUNTIME_RECORD_TYPE: Final[str] = (
    "cbds.development-reviewed-bash-runtime"
)
DEVELOPMENT_REVIEWED_BASH_RUNTIME_REVIEW_SCOPE: Final[str] = (
    "pinned-host-elf-closure-and-sealed-payloads-no-launch-v1"
)

FROZEN_REVIEWED_BASH_RUNTIME_ALLOWED_SOURCE_ROOTS: Final[tuple[str, ...]] = (
    "/usr",
    "/lib64",
)
FROZEN_REVIEWED_BASH_RUNTIME_LIBRARY_SEARCH_DIRECTORIES: Final[
    tuple[str, ...]
] = ("/usr/lib/x86_64-linux-gnu",)
FROZEN_REVIEWED_BASH_RUNTIME_EXECUTABLE_SPECS: Final[
    tuple[tuple[str, str, str], ...]
] = (
    (
        "bash",
        "/usr/bin/bash",
        "3efccc187bafa75ff1e37d246270ab3e7aa559f242c7a52bf3ec2a1b5450bdbd",
    ),
    (
        "find",
        "/usr/bin/find",
        "efe4843f166525b02f328f0c456a884d6a597f32d2c78cd615b6be0b64279bcf",
    ),
    (
        "sort",
        "/usr/bin/sort",
        "48893b0fb21436b54619db80486e83ef39dfccaf1aefe83dfa00c02d6146e8c0",
    ),
    (
        "mkdir",
        "/usr/bin/mkdir",
        "48893b0fb21436b54619db80486e83ef39dfccaf1aefe83dfa00c02d6146e8c0",
    ),
)

FROZEN_REVIEWED_BASH_RUNTIME_MANIFEST_SHA256: Final[str] = (
    "e48eebc05818b2e5ba27520687db9f02de8d7d5ec118abbcdbcf8d794abcd606"
)
FROZEN_REVIEWED_BASH_RUNTIME_PROJECTION_SHA256: Final[str] = (
    "ec2b93321b4465bf64250dfb41896b40a0189366a9c400cb541d47aee05b75dd"
)
FROZEN_REVIEWED_BASH_RUNTIME_SNAPSHOT_INDEX_SHA256: Final[str] = (
    "bb83bf65abedad62bb7c87dd89afb82bee13ec5788139e87278abb88f43109eb"
)
FROZEN_REVIEWED_BASH_RUNTIME_DIRECTORY_COUNT: Final[int] = 9
FROZEN_REVIEWED_BASH_RUNTIME_ENTRY_COUNT: Final[int] = 17
FROZEN_REVIEWED_BASH_RUNTIME_REGULAR_FILE_COUNT: Final[int] = 11
FROZEN_REVIEWED_BASH_RUNTIME_SYMLINK_COUNT: Final[int] = 6
FROZEN_REVIEWED_BASH_RUNTIME_REGULAR_PAYLOAD_BYTES: Final[int] = 29_399_408


class DevelopmentReviewedBashRuntimeError(ValueError):
    """Raised when the pinned runtime or one of its bindings fails closed."""


def _runtime_executables() -> tuple[DevelopmentRuntimeExecutable, ...]:
    return tuple(
        DevelopmentRuntimeExecutable(
            name=name,
            source_path=source_path,
            expected_sha256=expected_sha256,
        )
        for name, source_path, expected_sha256 in (
            FROZEN_REVIEWED_BASH_RUNTIME_EXECUTABLE_SPECS
        )
    )


def _case_identity_record_from_parts(
    evidence: DevelopmentRuntimeMaterializationEvidence,
    snapshot: DevelopmentRuntimeFdSnapshot,
    case: "DevelopmentReviewedBashRuntimeCase | None",
) -> dict[str, object]:
    def selected(name: str, default: object) -> object:
        return default if case is None else getattr(case, name)

    return {
        "schema_version": selected(
            "schema_version",
            DEVELOPMENT_REVIEWED_BASH_RUNTIME_SCHEMA_VERSION,
        ),
        "record_type": DEVELOPMENT_REVIEWED_BASH_RUNTIME_RECORD_TYPE,
        "review_scope": selected(
            "review_scope",
            DEVELOPMENT_REVIEWED_BASH_RUNTIME_REVIEW_SCOPE,
        ),
        "executables": [
            {
                "name": name,
                "source_path": source_path,
                "expected_sha256": expected_sha256,
            }
            for name, source_path, expected_sha256 in (
                FROZEN_REVIEWED_BASH_RUNTIME_EXECUTABLE_SPECS
            )
        ],
        "allowed_source_roots": list(
            FROZEN_REVIEWED_BASH_RUNTIME_ALLOWED_SOURCE_ROOTS
        ),
        "library_search_directories": list(
            FROZEN_REVIEWED_BASH_RUNTIME_LIBRARY_SEARCH_DIRECTORIES
        ),
        "source_manifest_sha256": evidence.source_manifest_sha256,
        "materialization_evidence_sha256": evidence.evidence_sha256,
        "source_projection_sha256": evidence.projection_sha256,
        "first_materialization_scan_sha256": evidence.first_scan_sha256,
        "second_materialization_scan_sha256": evidence.second_scan_sha256,
        "snapshot_index_sha256": snapshot.snapshot_index_sha256,
        "snapshot_sha256": snapshot.snapshot_sha256,
        "directory_count": snapshot.directory_count,
        "entry_count": snapshot.entry_count,
        "regular_file_count": snapshot.regular_file_count,
        "symlink_count": snapshot.symlink_count,
        "regular_payload_bytes": snapshot.regular_payload_bytes,
        "source_manifest_rebuilt_and_verified": (
            selected("source_manifest_rebuilt_and_verified", True)
        ),
        "runtime_bundle_materialized": selected(
            "runtime_bundle_materialized", True
        ),
        "sealed_regular_payloads_verified": (
            selected("sealed_regular_payloads_verified", True)
        ),
        "same_uid_snapshot_payload_mutation_resistant": (
            selected("same_uid_snapshot_payload_mutation_resistant", True)
        ),
        "runtime_data_and_dlopen_closure_verified": (
            selected("runtime_data_and_dlopen_closure_verified", False)
        ),
        "externally_trusted_runtime_executables": (
            selected("externally_trusted_runtime_executables", False)
        ),
        "same_uid_materialized_tree_mutation_resistant": (
            selected("same_uid_materialized_tree_mutation_resistant", False)
        ),
        "namespace_runtime_closure_verified": (
            selected("namespace_runtime_closure_verified", False)
        ),
        "fd_bound_launch_handoff": selected("fd_bound_launch_handoff", False),
        "launch_eligible": selected("launch_eligible", False),
        "candidate_execution_authorized": selected(
            "candidate_execution_authorized", False
        ),
        "candidate_executed": selected("candidate_executed", False),
        "scored_evaluation_eligible": selected(
            "scored_evaluation_eligible", False
        ),
        "model_selection_eligible": selected("model_selection_eligible", False),
        "claim_pipeline_eligible": selected("claim_pipeline_eligible", False),
        "claim_authorized": selected("claim_authorized", False),
    }


def _case_identity_record(
    case: "DevelopmentReviewedBashRuntimeCase",
) -> dict[str, object]:
    return _case_identity_record_from_parts(
        case._materialization,
        case._snapshot,
        case,
    )


def _case_sha256(case: "DevelopmentReviewedBashRuntimeCase") -> str:
    return sha256(
        b"cbds.development-reviewed-bash-runtime.case.v1\0"
        + canonical_development_runtime_json_bytes(_case_identity_record(case))
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class DevelopmentReviewedBashRuntimeCase:
    """Private owner of one materialized runtime and its sealed payload FDs."""

    _manifest: dict[str, object] = field(repr=False, compare=False)
    _materialization: DevelopmentRuntimeMaterializationEvidence = field(
        repr=False,
        compare=False,
    )
    _snapshot: DevelopmentRuntimeFdSnapshot = field(repr=False, compare=False)
    case_sha256: str
    schema_version: str = DEVELOPMENT_REVIEWED_BASH_RUNTIME_SCHEMA_VERSION
    review_scope: str = DEVELOPMENT_REVIEWED_BASH_RUNTIME_REVIEW_SCOPE
    source_manifest_rebuilt_and_verified: bool = True
    runtime_bundle_materialized: bool = True
    sealed_regular_payloads_verified: bool = True
    same_uid_snapshot_payload_mutation_resistant: bool = True
    runtime_data_and_dlopen_closure_verified: bool = False
    externally_trusted_runtime_executables: bool = False
    same_uid_materialized_tree_mutation_resistant: bool = False
    namespace_runtime_closure_verified: bool = False
    fd_bound_launch_handoff: bool = False
    launch_eligible: bool = False
    candidate_execution_authorized: bool = False
    candidate_executed: bool = False
    scored_evaluation_eligible: bool = False
    model_selection_eligible: bool = False
    claim_pipeline_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_development_reviewed_bash_runtime_case(self)

    @property
    def closed(self) -> bool:
        return self._snapshot.closed

    @property
    def directories(
        self,
    ) -> tuple[DevelopmentRuntimeMaterializedDirectory, ...]:
        return self._snapshot.directories

    @property
    def entries(self) -> tuple[DevelopmentRuntimeMaterializedEntry, ...]:
        return self._snapshot.entries

    @property
    def regular_slots(self) -> tuple[DevelopmentRuntimeFdSlot, ...]:
        return self._snapshot.regular_slots

    @property
    def snapshot_sha256(self) -> str:
        return self._snapshot.snapshot_sha256

    def duplicate_regular_fd(self, destination_path: str) -> int:
        """Return a caller-owned read descriptor for one sealed payload."""

        validate_development_reviewed_bash_runtime_case(self)
        try:
            return self._snapshot.duplicate_regular_fd(destination_path)
        except (DevelopmentRuntimeFdSnapshotError, OSError, TypeError, ValueError) as exc:
            raise DevelopmentReviewedBashRuntimeError(
                "cannot duplicate a reviewed runtime payload descriptor"
            ) from exc

    def to_audit_record(self) -> dict[str, object]:
        """Return identities and boundaries without payloads or descriptors."""

        validate_development_reviewed_bash_runtime_case(self)
        return {**_case_identity_record(self), "case_sha256": self.case_sha256}

    def close(self) -> None:
        """Release the owned snapshot descriptors; repeated close is safe."""

        self._snapshot.close()

    def __enter__(self) -> "DevelopmentReviewedBashRuntimeCase":
        validate_development_reviewed_bash_runtime_case(self)
        if self.closed:
            raise DevelopmentReviewedBashRuntimeError(
                "reviewed Bash runtime case is already closed"
            )
        return self

    def __exit__(
        self,
        _exc_type: object,
        _exc: object,
        _traceback: object,
    ) -> None:
        self.close()

    def __copy__(self) -> "DevelopmentReviewedBashRuntimeCase":
        raise DevelopmentReviewedBashRuntimeError(
            "reviewed runtime descriptor ownership cannot be copied"
        )

    def __deepcopy__(self, _memo: object) -> "DevelopmentReviewedBashRuntimeCase":
        raise DevelopmentReviewedBashRuntimeError(
            "reviewed runtime descriptor ownership cannot be copied"
        )

    def __del__(self) -> None:  # pragma: no cover - best-effort finalizer
        try:
            self.close()
        except BaseException:
            pass


def build_development_reviewed_bash_runtime_manifest() -> dict[str, object]:
    """Rebuild the reviewed host closure and require its frozen identity."""

    try:
        manifest = build_development_runtime_bundle_manifest(
            _runtime_executables(),
            allowed_source_roots=(
                FROZEN_REVIEWED_BASH_RUNTIME_ALLOWED_SOURCE_ROOTS
            ),
            library_search_directories=(
                FROZEN_REVIEWED_BASH_RUNTIME_LIBRARY_SEARCH_DIRECTORIES
            ),
        )
        if (
            manifest.get("manifest_sha256")
            != FROZEN_REVIEWED_BASH_RUNTIME_MANIFEST_SHA256
        ):
            raise DevelopmentReviewedBashRuntimeError(
                "current host runtime differs from the frozen reviewed manifest"
            )
        validate_development_runtime_bundle_manifest(manifest)
    except DevelopmentReviewedBashRuntimeError:
        raise
    except (DevelopmentRuntimeBundleError, OSError, TypeError, ValueError) as exc:
        raise DevelopmentReviewedBashRuntimeError(
            "current host cannot reproduce the frozen reviewed Bash runtime"
        ) from exc
    return manifest


def validate_development_reviewed_bash_runtime_case(
    case: DevelopmentReviewedBashRuntimeCase,
) -> None:
    """Validate every static and dynamic identity without replaying answers."""

    if type(case) is not DevelopmentReviewedBashRuntimeCase:
        raise DevelopmentReviewedBashRuntimeError(
            "case must be an exact DevelopmentReviewedBashRuntimeCase"
        )
    exact: dict[str, object] = {
        "schema_version": DEVELOPMENT_REVIEWED_BASH_RUNTIME_SCHEMA_VERSION,
        "review_scope": DEVELOPMENT_REVIEWED_BASH_RUNTIME_REVIEW_SCOPE,
        "source_manifest_rebuilt_and_verified": True,
        "runtime_bundle_materialized": True,
        "sealed_regular_payloads_verified": True,
        "same_uid_snapshot_payload_mutation_resistant": True,
        "runtime_data_and_dlopen_closure_verified": False,
        "externally_trusted_runtime_executables": False,
        "same_uid_materialized_tree_mutation_resistant": False,
        "namespace_runtime_closure_verified": False,
        "fd_bound_launch_handoff": False,
        "launch_eligible": False,
        "candidate_execution_authorized": False,
        "candidate_executed": False,
        "scored_evaluation_eligible": False,
        "model_selection_eligible": False,
        "claim_pipeline_eligible": False,
        "claim_authorized": False,
    }
    for name, expected in exact.items():
        observed = getattr(case, name)
        if type(observed) is not type(expected) or observed != expected:
            raise DevelopmentReviewedBashRuntimeError(
                f"reviewed runtime field {name!r} is invalid"
            )
    if type(case.case_sha256) is not str or len(case.case_sha256) != 64:
        raise DevelopmentReviewedBashRuntimeError("case_sha256 is invalid")
    if any(character not in "0123456789abcdef" for character in case.case_sha256):
        raise DevelopmentReviewedBashRuntimeError("case_sha256 is invalid")
    if type(case._manifest) is not dict:
        raise DevelopmentReviewedBashRuntimeError(
            "runtime manifest must remain an exact private dictionary"
        )
    if (
        not verify_development_runtime_bundle_sha256(case._manifest)
        or case._manifest.get("manifest_sha256")
        != FROZEN_REVIEWED_BASH_RUNTIME_MANIFEST_SHA256
    ):
        raise DevelopmentReviewedBashRuntimeError(
            "runtime source manifest identity is invalid"
        )
    closure = case._manifest.get("closure")
    if (
        type(closure) is not dict
        or closure.get("runtime_data_and_dlopen_closure_verified") is not False
        or case._manifest.get("allowed_source_roots") != ["/lib64", "/usr"]
        or case._manifest.get("library_search_directories")
        != list(FROZEN_REVIEWED_BASH_RUNTIME_LIBRARY_SEARCH_DIRECTORIES)
    ):
        raise DevelopmentReviewedBashRuntimeError(
            "runtime source closure declaration is invalid"
        )
    for field_name in (
        "runtime_bundle_materialized",
        "launch_eligible",
        "candidate_execution_authorized",
        "claim_pipeline_eligible",
        "scored_evaluation_eligible",
    ):
        if case._manifest.get(field_name) is not False:
            raise DevelopmentReviewedBashRuntimeError(
                "source manifest improperly grants authority"
            )
    if (
        type(case._materialization) is not DevelopmentRuntimeMaterializationEvidence
        or not verify_development_runtime_materialization_evidence_structure(
            case._materialization
        )
        or type(case._snapshot) is not DevelopmentRuntimeFdSnapshot
        or not verify_development_runtime_fd_snapshot_structure(case._snapshot)
    ):
        raise DevelopmentReviewedBashRuntimeError(
            "runtime materialization or snapshot structure is invalid"
        )
    evidence = case._materialization
    snapshot = case._snapshot
    if (
        evidence.source_manifest_sha256
        != FROZEN_REVIEWED_BASH_RUNTIME_MANIFEST_SHA256
        or snapshot.source_manifest_sha256 != evidence.source_manifest_sha256
        or snapshot.source_evidence_sha256 != evidence.evidence_sha256
        or snapshot.source_projection_sha256 != evidence.projection_sha256
        or evidence.projection_sha256
        != FROZEN_REVIEWED_BASH_RUNTIME_PROJECTION_SHA256
        or snapshot.snapshot_index_sha256
        != FROZEN_REVIEWED_BASH_RUNTIME_SNAPSHOT_INDEX_SHA256
        or snapshot.directories != evidence.directories
        or snapshot.entries != evidence.entries
    ):
        raise DevelopmentReviewedBashRuntimeError(
            "runtime manifest, materialization, and snapshot are not bound"
        )
    expected_counts = {
        "directory_count": FROZEN_REVIEWED_BASH_RUNTIME_DIRECTORY_COUNT,
        "entry_count": FROZEN_REVIEWED_BASH_RUNTIME_ENTRY_COUNT,
        "regular_file_count": FROZEN_REVIEWED_BASH_RUNTIME_REGULAR_FILE_COUNT,
        "symlink_count": FROZEN_REVIEWED_BASH_RUNTIME_SYMLINK_COUNT,
        "regular_payload_bytes": (
            FROZEN_REVIEWED_BASH_RUNTIME_REGULAR_PAYLOAD_BYTES
        ),
    }
    for name, expected in expected_counts.items():
        if getattr(evidence, name) != expected or getattr(snapshot, name) != expected:
            raise DevelopmentReviewedBashRuntimeError(
                f"runtime count {name!r} differs from its frozen value"
            )
    if not snapshot.closed:
        try:
            snapshot.__post_init__()
        except (
            DevelopmentRuntimeFdSnapshotError,
            OSError,
            TypeError,
            ValueError,
        ) as exc:
            raise DevelopmentReviewedBashRuntimeError(
                "open runtime snapshot descriptors failed validation"
            ) from exc
    if _case_sha256(case) != case.case_sha256:
        raise DevelopmentReviewedBashRuntimeError(
            "case_sha256 does not bind the runtime identities"
        )


def verify_development_reviewed_bash_runtime_case(case: object) -> bool:
    """Return whether an object is the exact reviewed runtime case."""

    try:
        validate_development_reviewed_bash_runtime_case(case)  # type: ignore[arg-type]
    except (
        AttributeError,
        DevelopmentReviewedBashRuntimeError,
        DevelopmentRuntimeFdSnapshotError,
        DevelopmentRuntimeMaterializationError,
        OSError,
        TypeError,
        ValueError,
    ):
        return False
    return True


def materialize_development_reviewed_bash_runtime(
    destination: str | os.PathLike[str],
) -> DevelopmentReviewedBashRuntimeCase:
    """Materialize and seal the one pinned runtime without authorizing launch."""

    manifest = build_development_reviewed_bash_runtime_manifest()
    snapshot: DevelopmentRuntimeFdSnapshot | None = None
    try:
        evidence = materialize_development_runtime_bundle(
            manifest,
            destination,
            expected_manifest_sha256=(
                FROZEN_REVIEWED_BASH_RUNTIME_MANIFEST_SHA256
            ),
        )
        snapshot = snapshot_development_runtime_for_launch(
            manifest,
            evidence,
            expected_manifest_sha256=(
                FROZEN_REVIEWED_BASH_RUNTIME_MANIFEST_SHA256
            ),
        )
        digest = sha256(
            b"cbds.development-reviewed-bash-runtime.case.v1\0"
            + canonical_development_runtime_json_bytes(
                _case_identity_record_from_parts(evidence, snapshot, None)
            )
        ).hexdigest()
        case = DevelopmentReviewedBashRuntimeCase(
            _manifest=manifest,
            _materialization=evidence,
            _snapshot=snapshot,
            case_sha256=digest,
        )
        snapshot = None
        return case
    except DevelopmentReviewedBashRuntimeError:
        raise
    except (
        DevelopmentRuntimeFdSnapshotError,
        DevelopmentRuntimeMaterializationError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        raise DevelopmentReviewedBashRuntimeError(
            "cannot construct the sealed reviewed Bash runtime case"
        ) from exc
    finally:
        if snapshot is not None:
            snapshot.close()


def development_reviewed_bash_runtime_host_compatibility() -> tuple[bool, str]:
    """Report whether this interpreter and host match the frozen prerequisites."""

    primitives = (
        (os, "memfd_create"),
        (os, "MFD_CLOEXEC"),
        (os, "MFD_ALLOW_SEALING"),
        (fcntl, "F_ADD_SEALS"),
        (fcntl, "F_GET_SEALS"),
        (fcntl, "F_SEAL_WRITE"),
        (fcntl, "F_SEAL_GROW"),
        (fcntl, "F_SEAL_SHRINK"),
        (fcntl, "F_SEAL_SEAL"),
    )
    missing = tuple(name for owner, name in primitives if not hasattr(owner, name))
    if missing:
        return False, "missing Linux sealed-memfd primitives: " + ", ".join(missing)
    if not Path("/proc/self/fd").is_dir():
        return False, "/proc/self/fd is unavailable"
    descriptor: int | None = None
    try:
        creator = getattr(os, "memfd_create")
        create_flags = getattr(os, "MFD_CLOEXEC") | getattr(
            os, "MFD_ALLOW_SEALING"
        )
        content_seals = (
            getattr(fcntl, "F_SEAL_WRITE")
            | getattr(fcntl, "F_SEAL_GROW")
            | getattr(fcntl, "F_SEAL_SHRINK")
        )
        required_seals = content_seals | getattr(fcntl, "F_SEAL_SEAL")
        descriptor = creator("cbds-reviewed-bash-runtime-probe", create_flags)
        os.write(descriptor, b"x")
        fcntl.fcntl(descriptor, getattr(fcntl, "F_ADD_SEALS"), content_seals)
        fcntl.fcntl(
            descriptor,
            getattr(fcntl, "F_ADD_SEALS"),
            getattr(fcntl, "F_SEAL_SEAL"),
        )
        if (
            os.get_inheritable(descriptor)
            or fcntl.fcntl(descriptor, getattr(fcntl, "F_GET_SEALS"))
            != required_seals
        ):
            return False, "Linux sealed-memfd behavior differs from the requirement"
    except (AttributeError, OSError, TypeError, ValueError) as exc:
        return False, "Linux sealed-memfd probe failed: " + type(exc).__name__
    finally:
        if descriptor is not None:
            os.close(descriptor)
    try:
        build_development_reviewed_bash_runtime_manifest()
    except DevelopmentReviewedBashRuntimeError as exc:
        return False, str(exc)
    return True, "compatible"


__all__ = [
    "DEVELOPMENT_REVIEWED_BASH_RUNTIME_RECORD_TYPE",
    "DEVELOPMENT_REVIEWED_BASH_RUNTIME_REVIEW_SCOPE",
    "DEVELOPMENT_REVIEWED_BASH_RUNTIME_SCHEMA_VERSION",
    "DevelopmentReviewedBashRuntimeCase",
    "DevelopmentReviewedBashRuntimeError",
    "FROZEN_REVIEWED_BASH_RUNTIME_ALLOWED_SOURCE_ROOTS",
    "FROZEN_REVIEWED_BASH_RUNTIME_DIRECTORY_COUNT",
    "FROZEN_REVIEWED_BASH_RUNTIME_ENTRY_COUNT",
    "FROZEN_REVIEWED_BASH_RUNTIME_EXECUTABLE_SPECS",
    "FROZEN_REVIEWED_BASH_RUNTIME_LIBRARY_SEARCH_DIRECTORIES",
    "FROZEN_REVIEWED_BASH_RUNTIME_MANIFEST_SHA256",
    "FROZEN_REVIEWED_BASH_RUNTIME_PROJECTION_SHA256",
    "FROZEN_REVIEWED_BASH_RUNTIME_REGULAR_FILE_COUNT",
    "FROZEN_REVIEWED_BASH_RUNTIME_REGULAR_PAYLOAD_BYTES",
    "FROZEN_REVIEWED_BASH_RUNTIME_SNAPSHOT_INDEX_SHA256",
    "FROZEN_REVIEWED_BASH_RUNTIME_SYMLINK_COUNT",
    "build_development_reviewed_bash_runtime_manifest",
    "development_reviewed_bash_runtime_host_compatibility",
    "materialize_development_reviewed_bash_runtime",
    "validate_development_reviewed_bash_runtime_case",
    "verify_development_reviewed_bash_runtime_case",
]
