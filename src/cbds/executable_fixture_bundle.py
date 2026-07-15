"""Private, content-derived binding for one executable-static fixture.

The public registry currently carries opaque fixture descriptors, while
``FixtureDefinition`` owns the actual answer-free filesystem commitment.  This
module connects those two identities to a frozen trusted oracle without
executing candidate code or authorizing model selection or a research claim.

The human-readable ``FixtureDefinition.fixture_id`` is deliberately excluded
from every content identity.  It may label a fixture in logs, but it cannot be
used as a salt to manufacture a distinct semantic fixture.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import re
from typing import Final, Literal, TypeAlias

from .executable_static_types import (
    EXECUTABLE_STATIC_SCHEMA_VERSION,
    OpaqueFixtureDescriptor,
    domain_sha256,
)
from .executable_workspace import (
    ExpectedFile,
    FixtureDefinition,
    InputFile,
    InputSymlink,
)


EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION: Final[str] = "1.0.0"
EXECUTABLE_FIXTURE_BINDING_VERSION: Final[str] = "1.0.0"

SemanticVerifierIdentity: TypeAlias = Literal[
    "verify-active-jsonl-labels-v1",
    "verify-manifest-copy-tree-v1",
    "verify-csv-group-totals-v1",
    "verify-checksum-manifest-v1",
    "verify-path-suffix-inventory-v1",
    "verify-line-transform-mirror-v1",
    "verify-mode-normalized-mirror-v1",
    "verify-jsonl-keyed-inner-join-v1",
    "verify-ustar-safe-extract-v1",
    "verify-proc-snapshot-report-v1",
]

SEMANTIC_VERIFIER_IDENTITIES: Final[frozenset[str]] = frozenset(
    {
        "verify-active-jsonl-labels-v1",
        "verify-manifest-copy-tree-v1",
        "verify-csv-group-totals-v1",
        "verify-checksum-manifest-v1",
        "verify-path-suffix-inventory-v1",
        "verify-line-transform-mirror-v1",
        "verify-mode-normalized-mirror-v1",
        "verify-jsonl-keyed-inner-join-v1",
        "verify-ustar-safe-extract-v1",
        "verify-proc-snapshot-report-v1",
    }
)

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")


class ExecutableFixtureBundleError(ValueError):
    """Raised when a private fixture binding fails closed validation."""


def _validate_sha256(value: object, field_name: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise ExecutableFixtureBundleError(
            f"{field_name} must be a lowercase SHA-256"
        )
    return value


def _validate_semantic_verifier(value: object) -> SemanticVerifierIdentity:
    try:
        accepted = type(value) is str and value in SEMANTIC_VERIFIER_IDENTITIES
    except TypeError:
        accepted = False
    if not accepted:
        raise ExecutableFixtureBundleError(
            "semantic_verifier_identity is outside the closed verifier set"
        )
    return value  # type: ignore[return-value]


@dataclass(frozen=True, slots=True)
class OracleOutputRecord:
    """Trusted bytes and mode for one expected independent regular file."""

    path: str
    content: bytes = field(repr=False)
    mode: int = 0o644

    def __post_init__(self) -> None:
        _validate_oracle_output_fields(self)

    def commitment_record(self) -> dict[str, object]:
        return {
            "path": self.path,
            "required_kind": "regular",
            "required_link_count": 1,
            "mode": self.mode,
            "size": len(self.content),
            "sha256": sha256(self.content).hexdigest(),
        }


def _validate_oracle_output_fields(output: OracleOutputRecord) -> None:
    if type(output.path) is not str:
        raise ExecutableFixtureBundleError("oracle output path must be a string")
    if type(output.content) is not bytes:
        raise ExecutableFixtureBundleError(
            "oracle output content must be immutable bytes"
        )
    # Reuse the public output-policy type for canonical path, size, and mode
    # bounds.  This does not add an answer or modify the workspace.
    try:
        ExpectedFile(
            path=output.path,
            maximum_bytes=len(output.content),
            mode=output.mode,
        )
    except ValueError as exc:
        raise ExecutableFixtureBundleError(
            "oracle output path, size, or mode is invalid"
        ) from exc


def _validate_oracle_outputs(
    outputs: object,
) -> tuple[OracleOutputRecord, ...]:
    if type(outputs) is not tuple or any(
        type(output) is not OracleOutputRecord for output in outputs
    ):
        raise ExecutableFixtureBundleError(
            "oracle outputs must be an exact tuple of OracleOutputRecord values"
        )
    for output in outputs:
        _validate_oracle_output_fields(output)
    paths = [output.path for output in outputs]
    if len(paths) != len(set(paths)):
        raise ExecutableFixtureBundleError("oracle output paths are not unique")
    if paths != sorted(paths, key=str.encode):
        raise ExecutableFixtureBundleError(
            "oracle outputs must be canonically sorted by UTF-8 path bytes"
        )
    return outputs


def compute_trusted_oracle_sha256(
    outputs: tuple[OracleOutputRecord, ...],
    semantic_verifier_identity: SemanticVerifierIdentity,
) -> str:
    selected = _validate_oracle_outputs(outputs)
    verifier = _validate_semantic_verifier(semantic_verifier_identity)
    return domain_sha256(
        "cbds.executable-fixture.trusted-oracle.v1",
        {
            "schema_version": EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION,
            "semantic_verifier_identity": verifier,
            "outputs": [output.commitment_record() for output in selected],
        },
    )


@dataclass(frozen=True, slots=True)
class TrustedFixtureOracle:
    """Frozen private oracle carrying exact bytes plus semantic verifier choice."""

    outputs: tuple[OracleOutputRecord, ...]
    semantic_verifier_identity: SemanticVerifierIdentity
    oracle_sha256: str
    schema_version: str = EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION:
            raise ExecutableFixtureBundleError("oracle schema_version is unsupported")
        _validate_oracle_outputs(self.outputs)
        _validate_semantic_verifier(self.semantic_verifier_identity)
        _validate_sha256(self.oracle_sha256, "oracle_sha256")
        expected = compute_trusted_oracle_sha256(
            self.outputs, self.semantic_verifier_identity
        )
        if self.oracle_sha256 != expected:
            raise ExecutableFixtureBundleError(
                "oracle_sha256 does not match trusted oracle content"
            )

    def commitment_record(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "record_type": "cbds.executable-fixture-trusted-oracle",
            "semantic_verifier_identity": self.semantic_verifier_identity,
            "outputs": [output.commitment_record() for output in self.outputs],
            "oracle_sha256": self.oracle_sha256,
        }


def build_trusted_fixture_oracle(
    outputs: tuple[OracleOutputRecord, ...],
    *,
    semantic_verifier_identity: SemanticVerifierIdentity,
) -> TrustedFixtureOracle:
    """Build a self-addressed frozen oracle without executing any program."""

    digest = compute_trusted_oracle_sha256(outputs, semantic_verifier_identity)
    return TrustedFixtureOracle(
        outputs=outputs,
        semantic_verifier_identity=semantic_verifier_identity,
        oracle_sha256=digest,
    )


def _validate_definition_type(definition: object) -> FixtureDefinition:
    if type(definition) is not FixtureDefinition:
        raise ExecutableFixtureBundleError(
            "definition must be an exact FixtureDefinition"
        )
    if type(definition.inputs) is not tuple or any(
        type(item) not in {InputFile, InputSymlink} for item in definition.inputs
    ):
        raise ExecutableFixtureBundleError(
            "definition inputs must contain exact immutable workspace input types"
        )
    if type(definition.expected_files) is not tuple or any(
        type(item) is not ExpectedFile for item in definition.expected_files
    ):
        raise ExecutableFixtureBundleError(
            "definition expected_files must contain exact ExpectedFile values"
        )
    try:
        # Reconstruct for validation so frozen-object bypasses in nested input or
        # policy records cannot survive a later bundle verification.
        FixtureDefinition(
            fixture_id=definition.fixture_id,
            inputs=definition.inputs,
            expected_files=definition.expected_files,
            schema_version=definition.schema_version,
        )
    except ValueError as exc:
        raise ExecutableFixtureBundleError(
            "definition contains invalid nested fixture fields"
        ) from exc
    return definition


def fixture_definition_semantic_record(
    definition: FixtureDefinition,
) -> dict[str, object]:
    """Return the answer-free fixture semantics without its arbitrary label."""

    selected = _validate_definition_type(definition)
    record = selected.commitment_record()
    if "fixture_id" not in record:
        raise ExecutableFixtureBundleError(
            "FixtureDefinition commitment lacks its removable fixture label"
        )
    del record["fixture_id"]
    record["record_type"] = "cbds.executable-fixture-definition-semantics"
    return record


def compute_fixture_definition_semantic_sha256(
    definition: FixtureDefinition,
) -> str:
    return domain_sha256(
        "cbds.executable-fixture.definition-semantics.v1",
        fixture_definition_semantic_record(definition),
    )


def _validate_oracle_against_definition(
    definition: FixtureDefinition,
    oracle: TrustedFixtureOracle,
) -> None:
    expected = {policy.path: policy for policy in definition.expected_files}
    observed = {output.path: output for output in oracle.outputs}
    if set(observed) != set(expected):
        raise ExecutableFixtureBundleError(
            "oracle output paths do not exactly match ExpectedFile policy"
        )
    for path, policy in expected.items():
        output = observed[path]
        if len(output.content) > policy.maximum_bytes:
            raise ExecutableFixtureBundleError(
                f"oracle output exceeds ExpectedFile maximum_bytes: {path}"
            )
        if policy.mode is not None and output.mode != policy.mode:
            raise ExecutableFixtureBundleError(
                f"oracle output mode differs from ExpectedFile policy: {path}"
            )


def compute_bound_fixture_sha256(
    *,
    task_contract_sha256: str,
    profile_sha256: str,
    fixture_definition_sha256: str,
    oracle_sha256: str,
) -> str:
    """Compute the one public fixture identity from all private commitments."""

    return domain_sha256(
        "cbds.executable-fixture.bound-identity.v1",
        {
            "schema_version": EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION,
            "binding_version": EXECUTABLE_FIXTURE_BINDING_VERSION,
            "task_contract_sha256": _validate_sha256(
                task_contract_sha256, "task_contract_sha256"
            ),
            "profile_sha256": _validate_sha256(profile_sha256, "profile_sha256"),
            "fixture_definition_sha256": _validate_sha256(
                fixture_definition_sha256, "fixture_definition_sha256"
            ),
            "oracle_sha256": _validate_sha256(oracle_sha256, "oracle_sha256"),
        },
    )


@dataclass(frozen=True, slots=True)
class ExecutableFixtureBundle:
    """Validated private binding and its public opaque descriptor."""

    task_contract_sha256: str
    profile_sha256: str
    definition: FixtureDefinition = field(repr=False)
    fixture_definition_sha256: str
    oracle: TrustedFixtureOracle = field(repr=False)
    descriptor: OpaqueFixtureDescriptor
    schema_version: str = EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        _validate_executable_fixture_bundle_fields(self)

    def to_opaque_descriptor(self) -> OpaqueFixtureDescriptor:
        """Return the already validated immutable public projection."""

        validate_executable_fixture_bundle(self)
        return self.descriptor

    def commitment_record(self) -> dict[str, object]:
        """Return a private hash-only audit record; no answer bytes are exposed."""

        validate_executable_fixture_bundle(self)
        return {
            "schema_version": self.schema_version,
            "record_type": "cbds.executable-fixture-private-binding",
            "binding_version": EXECUTABLE_FIXTURE_BINDING_VERSION,
            "task_contract_sha256": self.task_contract_sha256,
            "profile_sha256": self.profile_sha256,
            "fixture_definition_sha256": self.fixture_definition_sha256,
            "oracle": self.oracle.commitment_record(),
            "descriptor": self.descriptor.to_public_record(),
            "candidate_execution_authorized": self.candidate_execution_authorized,
            "model_selection_eligible": self.model_selection_eligible,
            "claim_authorized": self.claim_authorized,
        }


def _validate_executable_fixture_bundle_fields(
    bundle: ExecutableFixtureBundle,
) -> None:
    if type(bundle) is not ExecutableFixtureBundle:
        raise ExecutableFixtureBundleError(
            "bundle must be an exact ExecutableFixtureBundle"
        )
    if bundle.schema_version != EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION:
        raise ExecutableFixtureBundleError("bundle schema_version is unsupported")
    task_hash = _validate_sha256(
        bundle.task_contract_sha256, "task_contract_sha256"
    )
    profile_hash = _validate_sha256(bundle.profile_sha256, "profile_sha256")
    definition = _validate_definition_type(bundle.definition)
    if type(bundle.oracle) is not TrustedFixtureOracle:
        raise ExecutableFixtureBundleError(
            "oracle must be an exact TrustedFixtureOracle"
        )
    if bundle.oracle.schema_version != EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION:
        raise ExecutableFixtureBundleError("oracle schema_version is unsupported")
    # Recompute rather than trusting that a frozen nested value was not forged
    # through object.__setattr__ or deserialization bypasses.
    expected_oracle_hash = compute_trusted_oracle_sha256(
        bundle.oracle.outputs, bundle.oracle.semantic_verifier_identity
    )
    if bundle.oracle.oracle_sha256 != expected_oracle_hash:
        raise ExecutableFixtureBundleError(
            "oracle_sha256 does not match trusted oracle content"
        )
    definition_hash = compute_fixture_definition_semantic_sha256(definition)
    _validate_sha256(
        bundle.fixture_definition_sha256, "fixture_definition_sha256"
    )
    if bundle.fixture_definition_sha256 != definition_hash:
        raise ExecutableFixtureBundleError(
            "fixture_definition_sha256 does not match definition semantics"
        )
    _validate_oracle_against_definition(definition, bundle.oracle)
    if type(bundle.descriptor) is not OpaqueFixtureDescriptor:
        raise ExecutableFixtureBundleError(
            "descriptor must be an exact OpaqueFixtureDescriptor"
        )
    if bundle.descriptor.schema_version != EXECUTABLE_STATIC_SCHEMA_VERSION:
        raise ExecutableFixtureBundleError("descriptor schema_version is unsupported")
    fixture_hash = compute_bound_fixture_sha256(
        task_contract_sha256=task_hash,
        profile_sha256=profile_hash,
        fixture_definition_sha256=definition_hash,
        oracle_sha256=expected_oracle_hash,
    )
    if (
        bundle.descriptor.fixture_sha256 != fixture_hash
        or bundle.descriptor.fixture_id != f"fx-{fixture_hash[:24]}"
        or bundle.descriptor.task_contract_sha256 != task_hash
    ):
        raise ExecutableFixtureBundleError(
            "opaque fixture descriptor does not match bound fixture content"
        )
    if (
        bundle.candidate_execution_authorized is not False
        or bundle.model_selection_eligible is not False
        or bundle.claim_authorized is not False
    ):
        raise ExecutableFixtureBundleError(
            "fixture binding cannot authorize execution, model selection, or claims"
        )


def validate_executable_fixture_bundle(bundle: ExecutableFixtureBundle) -> None:
    """Recompute every derivable private and public binding."""

    _validate_executable_fixture_bundle_fields(bundle)


def verify_executable_fixture_bundle(bundle: object) -> bool:
    """Return whether all exact types, policies, flags, and hashes validate."""

    try:
        validate_executable_fixture_bundle(bundle)  # type: ignore[arg-type]
    except (ExecutableFixtureBundleError, TypeError, ValueError):
        return False
    return True


def build_executable_fixture_bundle(
    *,
    task_contract_sha256: str,
    profile_sha256: str,
    definition: FixtureDefinition,
    oracle: TrustedFixtureOracle,
) -> ExecutableFixtureBundle:
    """Build one private bundle and its content-derived public descriptor."""

    task_hash = _validate_sha256(task_contract_sha256, "task_contract_sha256")
    profile_hash = _validate_sha256(profile_sha256, "profile_sha256")
    selected_definition = _validate_definition_type(definition)
    if type(oracle) is not TrustedFixtureOracle:
        raise ExecutableFixtureBundleError(
            "oracle must be an exact TrustedFixtureOracle"
        )
    definition_hash = compute_fixture_definition_semantic_sha256(
        selected_definition
    )
    _validate_oracle_against_definition(selected_definition, oracle)
    fixture_hash = compute_bound_fixture_sha256(
        task_contract_sha256=task_hash,
        profile_sha256=profile_hash,
        fixture_definition_sha256=definition_hash,
        oracle_sha256=oracle.oracle_sha256,
    )
    descriptor = OpaqueFixtureDescriptor(
        fixture_id=f"fx-{fixture_hash[:24]}",
        fixture_sha256=fixture_hash,
        task_contract_sha256=task_hash,
    )
    return ExecutableFixtureBundle(
        task_contract_sha256=task_hash,
        profile_sha256=profile_hash,
        definition=selected_definition,
        fixture_definition_sha256=definition_hash,
        oracle=oracle,
        descriptor=descriptor,
    )


def validate_opaque_fixture_descriptor(
    bundle: ExecutableFixtureBundle,
    descriptor: OpaqueFixtureDescriptor,
) -> None:
    """Require an external public descriptor to equal the private binding."""

    validate_executable_fixture_bundle(bundle)
    if type(descriptor) is not OpaqueFixtureDescriptor:
        raise ExecutableFixtureBundleError(
            "descriptor must be an exact OpaqueFixtureDescriptor"
        )
    if descriptor != bundle.descriptor:
        raise ExecutableFixtureBundleError(
            "descriptor differs from the bound fixture descriptor"
        )


__all__ = [
    "EXECUTABLE_FIXTURE_BINDING_VERSION",
    "EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION",
    "SEMANTIC_VERIFIER_IDENTITIES",
    "ExecutableFixtureBundle",
    "ExecutableFixtureBundleError",
    "OracleOutputRecord",
    "SemanticVerifierIdentity",
    "TrustedFixtureOracle",
    "build_executable_fixture_bundle",
    "build_trusted_fixture_oracle",
    "compute_bound_fixture_sha256",
    "compute_fixture_definition_semantic_sha256",
    "compute_trusted_oracle_sha256",
    "fixture_definition_semantic_record",
    "validate_executable_fixture_bundle",
    "validate_opaque_fixture_descriptor",
    "verify_executable_fixture_bundle",
]
