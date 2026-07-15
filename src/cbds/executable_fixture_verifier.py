"""Read-only semantic verification for bound executable-static fixtures.

This module consumes an already materialized :class:`WorkspaceHandle`.  It
never starts a candidate, shell, parser subprocess, or external verifier.  The
only byte egress is ``WorkspaceHandle.read_output_bytes``, after exact input and
output-policy checks, and every result is frozen content-addressed evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import PurePosixPath
import re
from typing import Final, Literal, TypeAlias

from .executable_fixture_bundle import (
    ExecutableFixtureBundle,
    ExecutableFixtureBundleError,
    OracleOutputRecord,
    SEMANTIC_VERIFIER_IDENTITIES,
    SemanticVerifierIdentity,
    validate_executable_fixture_bundle,
)
from .executable_static_types import domain_sha256
from .executable_workspace import (
    ExecutableWorkspaceError,
    ExpectedFile,
    WorkspaceBaseline,
    WorkspaceEntry,
    WorkspaceHandle,
    WorkspaceScan,
    validate_expected_output_policy,
)


EXECUTABLE_FIXTURE_VERIFIER_SCHEMA_VERSION: Final[str] = "1.0.0"
EXECUTABLE_FIXTURE_VERIFIER_VERSION: Final[str] = "1.0.0"

VerificationFailureCode: TypeAlias = Literal[
    "workspace-binding-mismatch",
    "workspace-scan-failure",
    "input-baseline-mismatch",
    "output-policy-failure",
    "output-read-failure",
    "oracle-mode-mismatch",
    "trusted-oracle-invalid",
    "malformed-semantic-output",
    "semantic-mismatch",
]

VERIFICATION_FAILURE_CODES: Final[frozenset[str]] = frozenset(
    {
        "workspace-binding-mismatch",
        "workspace-scan-failure",
        "input-baseline-mismatch",
        "output-policy-failure",
        "output-read-failure",
        "oracle-mode-mismatch",
        "trusted-oracle-invalid",
        "malformed-semantic-output",
        "semantic-mismatch",
    }
)

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_FIXTURE_ID_RE: Final[re.Pattern[str]] = re.compile(r"fx-[0-9a-f]{24}\Z")
_CANONICAL_INTEGER_RE: Final[re.Pattern[str]] = re.compile(r"-?(?:0|[1-9][0-9]*)\Z")
_CHECKSUM_STATUSES: Final[frozenset[str]] = frozenset(
    {
        "ok",
        "checksum_mismatch",
        "mode_mismatch",
        "checksum_and_mode_mismatch",
        "unavailable",
        "missing",
        "not_regular",
        "unreadable",
        "symlink",
        "directory",
    }
)
_SINGLE_OUTPUT_BY_VERIFIER: Final[tuple[tuple[str, str], ...]] = (
    ("verify-active-jsonl-labels-v1", "output/labels.txt"),
    ("verify-csv-group-totals-v1", "output/totals.csv"),
    ("verify-checksum-manifest-v1", "output/report.jsonl"),
    ("verify-path-suffix-inventory-v1", "output/paths.txt"),
    ("verify-jsonl-keyed-inner-join-v1", "output/joined.jsonl"),
    ("verify-proc-snapshot-report-v1", "output/processes.jsonl"),
)


class ExecutableFixtureVerificationError(ValueError):
    """Raised only when verifier preconditions or evidence contracts are invalid."""


class _MalformedSemanticOutput(ValueError):
    """Internal marker for a syntactically invalid semantic output."""


@dataclass(frozen=True, slots=True)
class VerifiedOutputObservation:
    """Content identity of one safely released declared output."""

    path: str
    mode: int
    size: int
    content_sha256: str

    def __post_init__(self) -> None:
        if type(self.path) is not str or not self.path:
            raise ExecutableFixtureVerificationError(
                "verified output path must be nonempty text"
            )
        if type(self.mode) is not int or not 0 <= self.mode <= 0o777:
            raise ExecutableFixtureVerificationError(
                "verified output mode must contain only permission bits"
            )
        if type(self.size) is not int or self.size < 0:
            raise ExecutableFixtureVerificationError(
                "verified output size must be nonnegative"
            )
        _validate_sha256(self.content_sha256, "content_sha256")
        try:
            ExpectedFile(path=self.path, maximum_bytes=self.size, mode=self.mode)
        except ValueError as exc:
            raise ExecutableFixtureVerificationError(
                "verified output observation is outside output policy bounds"
            ) from exc

    def to_record(self) -> dict[str, object]:
        return {
            "path": self.path,
            "mode": self.mode,
            "size": self.size,
            "content_sha256": self.content_sha256,
        }


def _validate_sha256(value: object, field_name: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise ExecutableFixtureVerificationError(
            f"{field_name} must be lowercase SHA-256"
        )
    return value


def _validate_optional_sha256(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    return _validate_sha256(value, field_name)


def _evidence_core(
    *,
    fixture_id: str,
    fixture_sha256: str,
    task_contract_sha256: str,
    oracle_sha256: str,
    workspace_baseline_sha256: str,
    semantic_verifier_identity: SemanticVerifierIdentity,
    passed: bool,
    failure_code: VerificationFailureCode | None,
    input_tree_sha256: str | None,
    output_tree_sha256: str | None,
    outputs: tuple[VerifiedOutputObservation, ...],
    candidate_execution_authorized: bool,
    model_selection_eligible: bool,
    claim_authorized: bool,
) -> dict[str, object]:
    return {
        "schema_version": EXECUTABLE_FIXTURE_VERIFIER_SCHEMA_VERSION,
        "verifier_version": EXECUTABLE_FIXTURE_VERIFIER_VERSION,
        "record_type": "cbds.executable-fixture-verification-evidence",
        "fixture_id": fixture_id,
        "fixture_sha256": fixture_sha256,
        "task_contract_sha256": task_contract_sha256,
        "oracle_sha256": oracle_sha256,
        "workspace_baseline_sha256": workspace_baseline_sha256,
        "semantic_verifier_identity": semantic_verifier_identity,
        "passed": passed,
        "failure_code": failure_code,
        "input_tree_sha256": input_tree_sha256,
        "output_tree_sha256": output_tree_sha256,
        "outputs": [output.to_record() for output in outputs],
        "candidate_execution_authorized": candidate_execution_authorized,
        "model_selection_eligible": model_selection_eligible,
        "claim_authorized": claim_authorized,
    }


@dataclass(frozen=True, slots=True)
class FixtureVerificationEvidence:
    """Frozen pass/failure evidence that cannot authorize downstream use."""

    fixture_id: str
    fixture_sha256: str
    task_contract_sha256: str
    oracle_sha256: str
    workspace_baseline_sha256: str
    semantic_verifier_identity: SemanticVerifierIdentity
    passed: bool
    failure_code: VerificationFailureCode | None
    input_tree_sha256: str | None
    output_tree_sha256: str | None
    outputs: tuple[VerifiedOutputObservation, ...]
    evidence_sha256: str
    schema_version: str = EXECUTABLE_FIXTURE_VERIFIER_SCHEMA_VERSION
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        if self.schema_version != EXECUTABLE_FIXTURE_VERIFIER_SCHEMA_VERSION:
            raise ExecutableFixtureVerificationError(
                "verification evidence schema_version is unsupported"
            )
        if (
            type(self.fixture_id) is not str
            or _FIXTURE_ID_RE.fullmatch(self.fixture_id) is None
        ):
            raise ExecutableFixtureVerificationError("fixture_id is invalid")
        for field_name, value in (
            ("fixture_sha256", self.fixture_sha256),
            ("task_contract_sha256", self.task_contract_sha256),
            ("oracle_sha256", self.oracle_sha256),
            ("workspace_baseline_sha256", self.workspace_baseline_sha256),
            ("evidence_sha256", self.evidence_sha256),
        ):
            _validate_sha256(value, field_name)
        if self.fixture_id != f"fx-{self.fixture_sha256[:24]}":
            raise ExecutableFixtureVerificationError(
                "fixture_id is not derived from fixture_sha256"
            )
        if (
            type(self.semantic_verifier_identity) is not str
            or self.semantic_verifier_identity not in SEMANTIC_VERIFIER_IDENTITIES
        ):
            raise ExecutableFixtureVerificationError(
                "semantic_verifier_identity is outside the closed verifier set"
            )
        _validate_optional_sha256(self.input_tree_sha256, "input_tree_sha256")
        _validate_optional_sha256(self.output_tree_sha256, "output_tree_sha256")
        if type(self.passed) is not bool:
            raise ExecutableFixtureVerificationError("passed must be an exact bool")
        if self.passed:
            if self.failure_code is not None:
                raise ExecutableFixtureVerificationError(
                    "passing evidence cannot carry a failure_code"
                )
            if self.input_tree_sha256 is None or self.output_tree_sha256 is None:
                raise ExecutableFixtureVerificationError(
                    "passing evidence requires both stable tree identities"
                )
        elif self.failure_code not in VERIFICATION_FAILURE_CODES:
            raise ExecutableFixtureVerificationError(
                "failing evidence requires a closed failure_code"
            )
        if type(self.outputs) is not tuple or any(
            type(output) is not VerifiedOutputObservation for output in self.outputs
        ):
            raise ExecutableFixtureVerificationError(
                "evidence outputs must be an exact observation tuple"
            )
        for output in self.outputs:
            output.__post_init__()
        paths = [output.path for output in self.outputs]
        if len(paths) != len(set(paths)) or paths != sorted(paths, key=str.encode):
            raise ExecutableFixtureVerificationError(
                "evidence outputs must be uniquely path-sorted"
            )
        required_single_path = dict(_SINGLE_OUTPUT_BY_VERIFIER).get(
            self.semantic_verifier_identity
        )
        if required_single_path is not None:
            if any(path != required_single_path for path in paths):
                raise ExecutableFixtureVerificationError(
                    "evidence output path differs from its verifier contract"
                )
            if self.passed and paths != [required_single_path]:
                raise ExecutableFixtureVerificationError(
                    "passing evidence lacks its required output observation"
                )
        if (
            self.candidate_execution_authorized is not False
            or self.model_selection_eligible is not False
            or self.claim_authorized is not False
        ):
            raise ExecutableFixtureVerificationError(
                "verification evidence cannot authorize execution, selection, or claims"
            )
        expected = domain_sha256(
            "cbds.executable-fixture.verification-evidence.v1",
            self._core_record(),
        )
        if self.evidence_sha256 != expected:
            raise ExecutableFixtureVerificationError(
                "evidence_sha256 does not match verification evidence"
            )

    def _core_record(self) -> dict[str, object]:
        return _evidence_core(
            fixture_id=self.fixture_id,
            fixture_sha256=self.fixture_sha256,
            task_contract_sha256=self.task_contract_sha256,
            oracle_sha256=self.oracle_sha256,
            workspace_baseline_sha256=self.workspace_baseline_sha256,
            semantic_verifier_identity=self.semantic_verifier_identity,
            passed=self.passed,
            failure_code=self.failure_code,
            input_tree_sha256=self.input_tree_sha256,
            output_tree_sha256=self.output_tree_sha256,
            outputs=self.outputs,
            candidate_execution_authorized=self.candidate_execution_authorized,
            model_selection_eligible=self.model_selection_eligible,
            claim_authorized=self.claim_authorized,
        )

    def to_record(self) -> dict[str, object]:
        validate_fixture_verification_evidence_structure(self)
        return {**self._core_record(), "evidence_sha256": self.evidence_sha256}


def validate_fixture_verification_evidence_structure(
    evidence: FixtureVerificationEvidence,
) -> None:
    """Recompute the structure and self-hash of an unauthenticated record.

    This does not prove that the verifier ran or that the hashes describe a
    real workspace.  Use the bundle-binding validator as an additional check,
    or rerun :func:`verify_executable_fixture` for functional evidence.
    """

    if type(evidence) is not FixtureVerificationEvidence:
        raise ExecutableFixtureVerificationError(
            "evidence must be an exact FixtureVerificationEvidence"
        )
    evidence.__post_init__()


def is_structurally_valid_fixture_verification_evidence(evidence: object) -> bool:
    """Return whether an evidence value is structurally self-consistent only."""

    try:
        validate_fixture_verification_evidence_structure(  # type: ignore[arg-type]
            evidence
        )
    except (ExecutableFixtureVerificationError, TypeError, ValueError):
        return False
    return True


def validate_fixture_verification_evidence_binding(
    evidence: FixtureVerificationEvidence,
    bundle: ExecutableFixtureBundle,
) -> None:
    """Bind structural evidence to one validated private fixture bundle.

    Binding still is not cryptographic provenance and cannot replace rerunning
    the verifier over workspace bytes.  It prevents records for a different
    fixture, task, oracle, or verifier from being confused with this bundle.
    """

    validate_fixture_verification_evidence_structure(evidence)
    if type(bundle) is not ExecutableFixtureBundle:
        raise ExecutableFixtureVerificationError(
            "bundle must be an exact ExecutableFixtureBundle"
        )
    try:
        validate_executable_fixture_bundle(bundle)
    except (ExecutableFixtureBundleError, TypeError, ValueError) as exc:
        raise ExecutableFixtureVerificationError(
            "fixture bundle failed binding revalidation"
        ) from exc
    expected_identity = (
        bundle.descriptor.fixture_id,
        bundle.descriptor.fixture_sha256,
        bundle.task_contract_sha256,
        bundle.oracle.oracle_sha256,
        bundle.oracle.semantic_verifier_identity,
    )
    observed_identity = (
        evidence.fixture_id,
        evidence.fixture_sha256,
        evidence.task_contract_sha256,
        evidence.oracle_sha256,
        evidence.semantic_verifier_identity,
    )
    if observed_identity != expected_identity:
        raise ExecutableFixtureVerificationError(
            "verification evidence is bound to a different fixture bundle"
        )
    oracle_by_path = {output.path: output for output in bundle.oracle.outputs}
    observed_by_path = {output.path: output for output in evidence.outputs}
    if not set(observed_by_path).issubset(oracle_by_path):
        raise ExecutableFixtureVerificationError(
            "verification evidence observes an undeclared oracle path"
        )
    if evidence.passed and set(observed_by_path) != set(oracle_by_path):
        raise ExecutableFixtureVerificationError(
            "passing evidence does not observe every oracle output"
        )
    exact_bytes = evidence.semantic_verifier_identity in {
        "verify-active-jsonl-labels-v1",
        "verify-manifest-copy-tree-v1",
        "verify-path-suffix-inventory-v1",
        "verify-line-transform-mirror-v1",
        "verify-mode-normalized-mirror-v1",
        "verify-ustar-safe-extract-v1",
    }
    for path, observation in observed_by_path.items():
        oracle = oracle_by_path[path]
        if observation.mode != oracle.mode:
            raise ExecutableFixtureVerificationError(
                "verification evidence mode differs from its oracle"
            )
        if evidence.passed and exact_bytes and (
            observation.size != len(oracle.content)
            or observation.content_sha256 != sha256(oracle.content).hexdigest()
        ):
            raise ExecutableFixtureVerificationError(
                "passing exact-byte evidence differs from its oracle"
            )


def is_fixture_verification_evidence_bound(
    evidence: object, bundle: object
) -> bool:
    """Return whether structural evidence is consistently bound to a bundle."""

    try:
        validate_fixture_verification_evidence_binding(
            evidence, bundle  # type: ignore[arg-type]
        )
    except (ExecutableFixtureVerificationError, TypeError, ValueError):
        return False
    return True


def _make_evidence(
    bundle: ExecutableFixtureBundle,
    baseline: WorkspaceBaseline,
    *,
    passed: bool,
    failure_code: VerificationFailureCode | None,
    input_tree_sha256: str | None = None,
    output_tree_sha256: str | None = None,
    outputs: tuple[VerifiedOutputObservation, ...] = (),
) -> FixtureVerificationEvidence:
    common = {
        "fixture_id": bundle.descriptor.fixture_id,
        "fixture_sha256": bundle.descriptor.fixture_sha256,
        "task_contract_sha256": bundle.task_contract_sha256,
        "oracle_sha256": bundle.oracle.oracle_sha256,
        "workspace_baseline_sha256": baseline.baseline_sha256,
        "semantic_verifier_identity": bundle.oracle.semantic_verifier_identity,
        "passed": passed,
        "failure_code": failure_code,
        "input_tree_sha256": input_tree_sha256,
        "output_tree_sha256": output_tree_sha256,
        "outputs": outputs,
        "candidate_execution_authorized": False,
        "model_selection_eligible": False,
        "claim_authorized": False,
    }
    digest = domain_sha256(
        "cbds.executable-fixture.verification-evidence.v1",
        _evidence_core(**common),  # type: ignore[arg-type]
    )
    return FixtureVerificationEvidence(
        **common,  # type: ignore[arg-type]
        evidence_sha256=digest,
    )


def _expected_policy_records(
    bundle: ExecutableFixtureBundle,
) -> tuple[dict[str, object], ...]:
    return tuple(
        sorted(
            (item.to_record() for item in bundle.definition.expected_files),
            key=lambda item: str(item["path"]).encode("utf-8"),
        )
    )


def _workspace_is_bound_to_bundle(
    bundle: ExecutableFixtureBundle, handle: WorkspaceHandle
) -> bool:
    baseline = handle.baseline
    handle_policy = tuple(
        sorted(
            (item.to_record() for item in handle.expected_files),
            key=lambda item: str(item["path"]).encode("utf-8"),
        )
    )
    return (
        baseline.fixture_id == bundle.definition.fixture_id
        and baseline.fixture_sha256 == bundle.definition.fixture_sha256
        and handle_policy == _expected_policy_records(bundle)
        and not baseline.output_scaffold_entries
    )


def _input_scan_matches_baseline(
    scan: WorkspaceScan, baseline: WorkspaceBaseline
) -> bool:
    return (
        scan.scope == "inputs"
        and scan.baseline_sha256 == baseline.baseline_sha256
        and scan.entries == baseline.input_entries
        and scan.tree_sha256 == baseline.input_tree_sha256
    )


def _read_declared_outputs(
    handle: WorkspaceHandle,
    scan: WorkspaceScan,
    entries: tuple[WorkspaceEntry, ...],
    oracle_outputs: tuple[OracleOutputRecord, ...],
) -> tuple[
    dict[str, bytes],
    tuple[VerifiedOutputObservation, ...],
    bool,
]:
    entries_by_path = {entry.path: entry for entry in entries}
    payloads: dict[str, bytes] = {}
    observations: list[VerifiedOutputObservation] = []
    modes_match = True
    for oracle in oracle_outputs:
        entry = entries_by_path[oracle.path]
        payload = handle.read_output_bytes(scan, oracle.path)
        digest = sha256(payload).hexdigest()
        if (
            len(payload) != entry.size
            or entry.content_sha256 != digest
        ):
            raise ExecutableWorkspaceError(
                "released output bytes differ from their stable scan"
            )
        payloads[oracle.path] = payload
        observations.append(
            VerifiedOutputObservation(
                path=oracle.path,
                mode=entry.mode,
                size=len(payload),
                content_sha256=digest,
            )
        )
        modes_match = modes_match and entry.mode == oracle.mode
    return payloads, tuple(observations), modes_match


def _parse_lf_rfc4180_rows(payload: bytes) -> tuple[tuple[str, ...], ...]:
    if not payload or not payload.endswith(b"\n") or b"\r" in payload:
        raise _MalformedSemanticOutput("CSV requires nonempty LF-terminated data")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise _MalformedSemanticOutput("CSV is not UTF-8") from exc

    rows: list[tuple[str, ...]] = []
    index = 0
    while index < len(text):
        row: list[str] = []
        while True:
            field: list[str] = []
            if text[index] == '"':
                index += 1
                while True:
                    if index >= len(text):
                        raise _MalformedSemanticOutput(
                            "CSV quoted field is unterminated"
                        )
                    character = text[index]
                    if character == '"':
                        if index + 1 < len(text) and text[index + 1] == '"':
                            field.append('"')
                            index += 2
                            continue
                        index += 1
                        break
                    field.append(character)
                    index += 1
                if index >= len(text) or text[index] not in {",", "\n"}:
                    raise _MalformedSemanticOutput(
                        "CSV has data after a closing quote"
                    )
            else:
                while index < len(text) and text[index] not in {",", "\n"}:
                    if text[index] == '"':
                        raise _MalformedSemanticOutput(
                            "CSV has an unescaped quote in an unquoted field"
                        )
                    field.append(text[index])
                    index += 1
                if index >= len(text):
                    raise _MalformedSemanticOutput("CSV record lacks its final LF")
            row.append("".join(field))
            delimiter = text[index]
            index += 1
            if delimiter == "\n":
                break
        rows.append(tuple(row))
    return tuple(rows)


def _parse_csv_semantics(payload: bytes) -> tuple[tuple[str, int], ...]:
    if not payload.startswith(b"category,total\n"):
        raise _MalformedSemanticOutput(
            "CSV header bytes are not exactly category,total"
        )
    rows = _parse_lf_rfc4180_rows(payload)
    if not rows or rows[0] != ("category", "total"):
        raise _MalformedSemanticOutput("CSV header is not exactly category,total")
    records: list[tuple[str, int]] = []
    previous: bytes | None = None
    seen: set[str] = set()
    for row in rows[1:]:
        if len(row) != 2:
            raise _MalformedSemanticOutput("CSV data row does not have two fields")
        category, total_text = row
        if category in seen:
            raise _MalformedSemanticOutput("CSV category is duplicated")
        encoded = category.encode("utf-8")
        if previous is not None and encoded <= previous:
            raise _MalformedSemanticOutput(
                "CSV categories are not strictly byte-sorted"
            )
        if (
            len(total_text) > 128
            or _CANONICAL_INTEGER_RE.fullmatch(total_text) is None
        ):
            raise _MalformedSemanticOutput("CSV total is not a canonical integer")
        try:
            total = int(total_text, 10)
        except ValueError as exc:
            raise _MalformedSemanticOutput(
                "CSV integer is outside parser bounds"
            ) from exc
        if str(total) != total_text:
            raise _MalformedSemanticOutput("CSV total has a noncanonical spelling")
        seen.add(category)
        previous = encoded
        records.append((category, total))
    return tuple(records)


def _reject_json_constant(value: str) -> object:
    raise _MalformedSemanticOutput(f"unsupported JSON constant: {value}")


def _reject_json_float(_value: str) -> object:
    raise _MalformedSemanticOutput(
        "JSON numbers must use canonical safe-integer syntax"
    )


def _safe_json_integer(value: str) -> int:
    if len(value) > 17:
        raise _MalformedSemanticOutput("JSON integer exceeds its parser bound")
    parsed = int(value, 10)
    if str(parsed) != value or abs(parsed) > 9_007_199_254_740_991:
        raise _MalformedSemanticOutput(
            "JSON integer is not canonical or exceeds the safe range"
        )
    return parsed


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    keys = [key for key, _value in pairs]
    if len(keys) != len(set(keys)):
        raise _MalformedSemanticOutput("JSON object contains a duplicate key")
    return dict(pairs)


def _parse_checksum_jsonl_semantics(
    payload: bytes,
) -> tuple[tuple[str, str], ...]:
    if payload == b"":
        return ()
    if not payload.endswith(b"\n") or b"\r" in payload:
        raise _MalformedSemanticOutput("JSONL requires LF-terminated records")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise _MalformedSemanticOutput("JSONL is not UTF-8") from exc
    records: list[tuple[str, str]] = []
    previous: bytes | None = None
    for line in text[:-1].split("\n"):
        if not line.strip():
            raise _MalformedSemanticOutput("JSONL contains a blank record")
        try:
            value = json.loads(
                line,
                object_pairs_hook=_strict_json_object,
                parse_constant=_reject_json_constant,
            )
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            if isinstance(exc, _MalformedSemanticOutput):
                raise
            raise _MalformedSemanticOutput("JSONL record is malformed") from exc
        if type(value) is not dict or set(value) != {"path", "status"}:
            raise _MalformedSemanticOutput(
                "JSONL record must contain exactly path and status"
            )
        path = value["path"]
        status = value["status"]
        if type(path) is not str or type(status) is not str:
            raise _MalformedSemanticOutput("JSONL path and status must be strings")
        try:
            encoded = path.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise _MalformedSemanticOutput(
                "JSONL path is not scalar UTF-8 text"
            ) from exc
        relative = PurePosixPath(path)
        if (
            not path
            or relative.is_absolute()
            or relative.as_posix() != path
            or any(part in {"", ".", ".."} for part in relative.parts)
            or any(ord(character) < 32 or ord(character) == 127 for character in path)
        ):
            raise _MalformedSemanticOutput(
                "JSONL path is not a canonical safe relative POSIX path"
            )
        if status not in _CHECKSUM_STATUSES:
            raise _MalformedSemanticOutput("JSONL status is outside the closed set")
        if previous is not None and encoded < previous:
            raise _MalformedSemanticOutput("JSONL paths are not byte-sorted")
        previous = encoded
        records.append((path, status))
    return tuple(records)


def _canonical_json_line(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise _MalformedSemanticOutput(
            "JSONL record cannot be represented as canonical JSON"
        ) from exc


def _parse_strict_jsonl_values(payload: bytes) -> tuple[tuple[bytes, object], ...]:
    if payload == b"":
        return ()
    if not payload.endswith(b"\n") or b"\r" in payload or b"\0" in payload:
        raise _MalformedSemanticOutput(
            "JSONL requires NUL-free, CR-free, LF-terminated records"
        )
    raw_lines = payload[:-1].split(b"\n")
    records: list[tuple[bytes, object]] = []
    for raw_line in raw_lines:
        if not raw_line:
            raise _MalformedSemanticOutput("JSONL contains a blank record")
        try:
            text = raw_line.decode("utf-8", errors="strict")
            value = json.loads(
                text,
                object_pairs_hook=_strict_json_object,
                parse_constant=_reject_json_constant,
                parse_float=_reject_json_float,
                parse_int=_safe_json_integer,
            )
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            TypeError,
            ValueError,
            RecursionError,
        ) as exc:
            if isinstance(exc, _MalformedSemanticOutput):
                raise
            raise _MalformedSemanticOutput("JSONL record is malformed") from exc
        canonical = _canonical_json_line(value)
        records.append((canonical, value))
    return tuple(records)


def _parse_join_jsonl_semantics(payload: bytes) -> tuple[bytes, ...]:
    records = _parse_strict_jsonl_values(payload)
    result: list[bytes] = []
    previous_key: bytes | None = None
    allowed_keys = ("id", "key", "name", "slug")
    for canonical, value in records:
        if type(value) is not dict or set(value) != {"key", "left", "right"}:
            raise _MalformedSemanticOutput(
                "join row must contain exactly key, left, and right"
            )
        key = value["key"]
        left = value["left"]
        right = value["right"]
        if (
            type(key) is not str
            or any(character in key for character in "\0\r\n")
            or type(left) is not dict
            or type(right) is not dict
        ):
            raise _MalformedSemanticOutput("join row values have invalid types")
        try:
            key_bytes = key.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise _MalformedSemanticOutput("join key is not scalar UTF-8") from exc
        matching_fields = tuple(
            field
            for field in allowed_keys
            if left.get(field) == key and right.get(field) == key
        )
        if not matching_fields:
            raise _MalformedSemanticOutput(
                "join row does not preserve a supported shared key"
            )
        if previous_key is not None and key_bytes < previous_key:
            raise _MalformedSemanticOutput("join rows are not key-byte-sorted")
        previous_key = key_bytes
        result.append(canonical)
    return tuple(result)


def _plain_nonnegative_integer(value: object) -> bool:
    return type(value) is int and value >= 0


def _parse_proc_jsonl_semantics(payload: bytes) -> tuple[bytes, ...]:
    records = _parse_strict_jsonl_values(payload)
    result: list[bytes] = []
    previous_pid = 0
    for canonical, value in records:
        if type(value) is not dict:
            raise _MalformedSemanticOutput("process row must be a JSON object")
        keys = set(value)
        pid = value.get("pid")
        if not _plain_nonnegative_integer(pid) or pid == 0 or pid <= previous_pid:
            raise _MalformedSemanticOutput(
                "process rows require unique increasing positive PIDs"
            )
        if keys == {"pid", "ppid", "state"}:
            if (
                not _plain_nonnegative_integer(value.get("ppid"))
                or value.get("state") not in {"R", "S", "D", "Z", "T", "I"}
            ):
                raise _MalformedSemanticOutput("process identity row is invalid")
        elif keys == {"pid", "uid"}:
            if not _plain_nonnegative_integer(value.get("uid")):
                raise _MalformedSemanticOutput("process ownership row is invalid")
        elif keys == {"pid", "rss_kib"}:
            if not _plain_nonnegative_integer(value.get("rss_kib")):
                raise _MalformedSemanticOutput("process memory row is invalid")
        elif keys == {"pid", "comm", "argv"}:
            comm = value.get("comm")
            argv = value.get("argv")
            if (
                type(comm) is not str
                or any(character in comm for character in "\0\r\n")
                or type(argv) is not list
                or any(
                    type(argument) is not str
                    or not argument
                    or "\0" in argument
                    for argument in argv
                )
            ):
                raise _MalformedSemanticOutput("process command row is invalid")
        else:
            raise _MalformedSemanticOutput("process row shape is outside closed views")
        previous_pid = pid
        result.append(canonical)
    return tuple(result)


def _parse_sorted_line_semantics(
    payload: bytes, *, relative_paths: bool
) -> tuple[str, ...]:
    if payload == b"":
        return ()
    if not payload.endswith(b"\n") or b"\r" in payload or b"\0" in payload:
        raise _MalformedSemanticOutput(
            "line output must be NUL-free and LF-terminated"
        )
    raw_lines = payload[:-1].split(b"\n")
    values: list[str] = []
    previous: bytes | None = None
    for raw in raw_lines:
        try:
            value = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise _MalformedSemanticOutput("line output is not UTF-8") from exc
        if previous is not None and raw <= previous:
            raise _MalformedSemanticOutput(
                "line output is not strictly sorted and deduplicated"
            )
        if relative_paths:
            path = PurePosixPath(value)
            if (
                not value
                or path.is_absolute()
                or path.as_posix() != value
                or any(part in {"", ".", ".."} for part in path.parts)
            ):
                raise _MalformedSemanticOutput(
                    "path line is not a canonical safe relative POSIX path"
                )
        values.append(value)
        previous = raw
    return tuple(values)


def _semantic_outputs_match(
    identity: SemanticVerifierIdentity,
    actual: dict[str, bytes],
    oracle_outputs: tuple[OracleOutputRecord, ...],
) -> tuple[bool, bool]:
    """Return ``(oracle_valid, actual_matches)`` for one closed verifier."""

    required_path = next(
        (
            path
            for verifier_identity, path in _SINGLE_OUTPUT_BY_VERIFIER
            if verifier_identity == identity
        ),
        None,
    )
    if required_path is not None and tuple(
        output.path for output in oracle_outputs
    ) != (required_path,):
        return False, False

    if identity in {
        "verify-manifest-copy-tree-v1",
        "verify-line-transform-mirror-v1",
        "verify-mode-normalized-mirror-v1",
        "verify-ustar-safe-extract-v1",
    }:
        return True, all(
            actual[output.path] == output.content for output in oracle_outputs
        )

    if identity in {
        "verify-active-jsonl-labels-v1",
        "verify-path-suffix-inventory-v1",
    }:
        relative_paths = identity == "verify-path-suffix-inventory-v1"
        try:
            for output in oracle_outputs:
                _parse_sorted_line_semantics(
                    output.content, relative_paths=relative_paths
                )
        except _MalformedSemanticOutput:
            return False, False
        return True, all(
            actual[output.path] == output.content for output in oracle_outputs
        )

    if identity == "verify-csv-group-totals-v1":
        parser = _parse_csv_semantics
    elif identity == "verify-checksum-manifest-v1":
        parser = _parse_checksum_jsonl_semantics
    elif identity == "verify-jsonl-keyed-inner-join-v1":
        parser = _parse_join_jsonl_semantics
    elif identity == "verify-proc-snapshot-report-v1":
        parser = _parse_proc_jsonl_semantics
    else:
        return False, False
    oracle_semantics: dict[str, object] = {}
    try:
        for output in oracle_outputs:
            oracle_semantics[output.path] = parser(output.content)
    except _MalformedSemanticOutput:
        return False, False
    try:
        actual_semantics = {
            output.path: parser(actual[output.path]) for output in oracle_outputs
        }
    except _MalformedSemanticOutput:
        return True, False
    return True, actual_semantics == oracle_semantics


def _actual_semantics_are_well_formed(
    identity: SemanticVerifierIdentity,
    actual: dict[str, bytes],
    oracle_outputs: tuple[OracleOutputRecord, ...],
) -> bool:
    if identity == "verify-csv-group-totals-v1":
        parser = _parse_csv_semantics
    elif identity == "verify-checksum-manifest-v1":
        parser = _parse_checksum_jsonl_semantics
    elif identity == "verify-jsonl-keyed-inner-join-v1":
        parser = _parse_join_jsonl_semantics
    elif identity == "verify-proc-snapshot-report-v1":
        parser = _parse_proc_jsonl_semantics
    elif identity in {
        "verify-active-jsonl-labels-v1",
        "verify-path-suffix-inventory-v1",
    }:
        relative_paths = identity == "verify-path-suffix-inventory-v1"
        try:
            for output in oracle_outputs:
                _parse_sorted_line_semantics(
                    actual[output.path], relative_paths=relative_paths
                )
        except _MalformedSemanticOutput:
            return False
        return True
    elif identity in {
        "verify-manifest-copy-tree-v1",
        "verify-line-transform-mirror-v1",
        "verify-mode-normalized-mirror-v1",
        "verify-ustar-safe-extract-v1",
    }:
        return True
    else:
        return False
    try:
        for output in oracle_outputs:
            parser(actual[output.path])
    except _MalformedSemanticOutput:
        return False
    return True


def verify_executable_fixture(
    bundle: ExecutableFixtureBundle,
    handle: WorkspaceHandle,
) -> FixtureVerificationEvidence:
    """Verify one current workspace without executing any program.

    Invalid bundle or handle *types* are precondition errors.  Once those
    contracts validate, workspace, policy, read, syntax, and semantic outcomes
    are returned as content-addressed evidence with distinct failure codes.
    """

    if type(bundle) is not ExecutableFixtureBundle:
        raise ExecutableFixtureVerificationError(
            "bundle must be an exact ExecutableFixtureBundle"
        )
    if type(handle) is not WorkspaceHandle:
        raise ExecutableFixtureVerificationError(
            "handle must be an exact WorkspaceHandle"
        )
    try:
        validate_executable_fixture_bundle(bundle)
    except (ExecutableFixtureBundleError, TypeError, ValueError) as exc:
        raise ExecutableFixtureVerificationError(
            "fixture bundle failed precondition revalidation"
        ) from exc

    baseline = handle.baseline
    if not _workspace_is_bound_to_bundle(bundle, handle):
        return _make_evidence(
            bundle,
            baseline,
            passed=False,
            failure_code="workspace-binding-mismatch",
        )

    try:
        input_scan = handle.scan_inputs()
    except ExecutableWorkspaceError:
        return _make_evidence(
            bundle,
            baseline,
            passed=False,
            failure_code="workspace-scan-failure",
        )
    if not _input_scan_matches_baseline(input_scan, baseline):
        return _make_evidence(
            bundle,
            baseline,
            passed=False,
            failure_code="input-baseline-mismatch",
            input_tree_sha256=input_scan.tree_sha256,
        )

    try:
        output_scan = handle.scan_outputs()
    except ExecutableWorkspaceError:
        return _make_evidence(
            bundle,
            baseline,
            passed=False,
            failure_code="workspace-scan-failure",
            input_tree_sha256=input_scan.tree_sha256,
        )
    try:
        output_entries = validate_expected_output_policy(
            bundle.definition, output_scan
        )
    except ExecutableWorkspaceError:
        return _make_evidence(
            bundle,
            baseline,
            passed=False,
            failure_code="output-policy-failure",
            input_tree_sha256=input_scan.tree_sha256,
            output_tree_sha256=output_scan.tree_sha256,
        )

    try:
        payloads, observations, modes_match = _read_declared_outputs(
            handle,
            output_scan,
            output_entries,
            bundle.oracle.outputs,
        )
    except (ExecutableWorkspaceError, OSError, ValueError):
        return _make_evidence(
            bundle,
            baseline,
            passed=False,
            failure_code="output-read-failure",
            input_tree_sha256=input_scan.tree_sha256,
            output_tree_sha256=output_scan.tree_sha256,
        )

    try:
        final_input_scan = handle.scan_inputs()
        final_output_scan = handle.scan_outputs()
    except ExecutableWorkspaceError:
        return _make_evidence(
            bundle,
            baseline,
            passed=False,
            failure_code="workspace-scan-failure",
            input_tree_sha256=input_scan.tree_sha256,
            output_tree_sha256=output_scan.tree_sha256,
            outputs=observations,
        )
    if not _input_scan_matches_baseline(final_input_scan, baseline):
        return _make_evidence(
            bundle,
            baseline,
            passed=False,
            failure_code="input-baseline-mismatch",
            input_tree_sha256=final_input_scan.tree_sha256,
            output_tree_sha256=final_output_scan.tree_sha256,
            outputs=observations,
        )
    if final_output_scan != output_scan:
        return _make_evidence(
            bundle,
            baseline,
            passed=False,
            failure_code="output-read-failure",
            input_tree_sha256=final_input_scan.tree_sha256,
            output_tree_sha256=final_output_scan.tree_sha256,
            outputs=observations,
        )
    if not modes_match:
        return _make_evidence(
            bundle,
            baseline,
            passed=False,
            failure_code="oracle-mode-mismatch",
            input_tree_sha256=final_input_scan.tree_sha256,
            output_tree_sha256=final_output_scan.tree_sha256,
            outputs=observations,
        )

    oracle_valid, semantic_match = _semantic_outputs_match(
        bundle.oracle.semantic_verifier_identity,
        payloads,
        bundle.oracle.outputs,
    )
    if not oracle_valid:
        failure_code: VerificationFailureCode = "trusted-oracle-invalid"
    elif not semantic_match:
        failure_code = (
            "semantic-mismatch"
            if _actual_semantics_are_well_formed(
                bundle.oracle.semantic_verifier_identity,
                payloads,
                bundle.oracle.outputs,
            )
            else "malformed-semantic-output"
        )
    else:
        return _make_evidence(
            bundle,
            baseline,
            passed=True,
            failure_code=None,
            input_tree_sha256=final_input_scan.tree_sha256,
            output_tree_sha256=final_output_scan.tree_sha256,
            outputs=observations,
        )
    return _make_evidence(
        bundle,
        baseline,
        passed=False,
        failure_code=failure_code,
        input_tree_sha256=final_input_scan.tree_sha256,
        output_tree_sha256=final_output_scan.tree_sha256,
        outputs=observations,
    )


__all__ = [
    "EXECUTABLE_FIXTURE_VERIFIER_SCHEMA_VERSION",
    "EXECUTABLE_FIXTURE_VERIFIER_VERSION",
    "VERIFICATION_FAILURE_CODES",
    "ExecutableFixtureVerificationError",
    "FixtureVerificationEvidence",
    "VerificationFailureCode",
    "VerifiedOutputObservation",
    "is_fixture_verification_evidence_bound",
    "is_structurally_valid_fixture_verification_evidence",
    "validate_fixture_verification_evidence_binding",
    "validate_fixture_verification_evidence_structure",
    "verify_executable_fixture",
]
