"""Fixed binary protocol for one reviewed, descriptor-bound Bash canary.

This module defines transport only.  It does not open descriptors, construct a
namespace, execute Bash, verify a workspace, score a task, or authorize a
synthesized candidate.  A future native supervisor may consume the request
from standard input, read the reviewed program and fixture pack from the fixed
descriptor slots below, and write a workspace snapshot to its fixed output
descriptor.  The request binds those payloads and the complete runtime/policy
identity; the result repeats every identity and binds the complete request.

The SHA-256 fields provide content binding, not provenance or external trust.
Both canonical record projections therefore permanently deny execution,
scoring, model-selection, and claim authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, IntFlag
from hashlib import sha256
import json
import struct
from typing import Final


DEVELOPMENT_CANDIDATE_PROTOCOL_VERSION: Final[int] = 1
DEVELOPMENT_CANDIDATE_REQUEST_MAGIC: Final[bytes] = b"CBDSBRQ1"
DEVELOPMENT_CANDIDATE_RESULT_MAGIC: Final[bytes] = b"CBDSBRS1"
DEVELOPMENT_CANDIDATE_REQUEST_BYTES: Final[int] = 384
DEVELOPMENT_CANDIDATE_RESULT_BYTES: Final[int] = 512
DEVELOPMENT_CANDIDATE_RESULT_HASHED_PREFIX_BYTES: Final[int] = 480

# Fixed descriptor roles for the future native implementation.  The runtime
# itself is projected before the supervisor starts and is bound by its snapshot
# digest rather than by a serialized, process-local descriptor number.  The
# protocol version fixes these roles; the descriptor integers are not repeated
# in the request frame.
DEVELOPMENT_CANDIDATE_PROGRAM_FD: Final[int] = 3
DEVELOPMENT_CANDIDATE_FIXTURE_BUNDLE_FD: Final[int] = 4
DEVELOPMENT_CANDIDATE_WORKSPACE_SNAPSHOT_FD: Final[int] = 5

DEVELOPMENT_CANDIDATE_MINIMUM_WALL_TIMEOUT_USEC: Final[int] = 10_000
DEVELOPMENT_CANDIDATE_MAXIMUM_WALL_TIMEOUT_USEC: Final[int] = 3_600_000_000
DEVELOPMENT_CANDIDATE_MINIMUM_CPU_TIME_USEC: Final[int] = 1_000
DEVELOPMENT_CANDIDATE_MAXIMUM_CPU_TIME_USEC: Final[int] = 3_600_000_000
DEVELOPMENT_CANDIDATE_MAXIMUM_PROGRAM_BYTES: Final[int] = 64 * 1024
DEVELOPMENT_CANDIDATE_MAXIMUM_STREAM_CAP_BYTES: Final[int] = 1024 * 1024
DEVELOPMENT_CANDIDATE_MAXIMUM_WORKSPACE_SNAPSHOT_BYTES: Final[int] = 64 * 1024 * 1024

# Request layout.  Keep these exported offsets synchronized with the native C
# implementation; every multibyte integer is little-endian.
DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_MAGIC: Final[int] = 0
DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_VERSION: Final[int] = 8
DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_RESERVED_U32: Final[int] = 12
DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_PROGRAM_BYTES: Final[int] = 16
DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_WALL_TIMEOUT_USEC: Final[int] = 24
DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_CPU_TIME_LIMIT_USEC: Final[int] = 32
DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_STDOUT_CAP_BYTES: Final[int] = 40
DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_STDERR_CAP_BYTES: Final[int] = 48
DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_WORKSPACE_SNAPSHOT_CAP_BYTES: Final[int] = 56
DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_NONCE: Final[int] = 64
DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_INVOCATION_SHA256: Final[int] = 96
DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_PROGRAM_SHA256: Final[int] = 128
DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_FIXTURE_DEFINITION_SHA256: Final[int] = 160
DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_WORKSPACE_BASELINE_SHA256: Final[int] = 192
DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_RUNTIME_SNAPSHOT_SHA256: Final[int] = 224
DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_ALLOWED_TOOLS_SHA256: Final[int] = 256
DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_POLICY_SHA256: Final[int] = 288
DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_RESERVED: Final[int] = 320
DEVELOPMENT_CANDIDATE_REQUEST_RESERVED_BYTES: Final[int] = 64

# Result layout.  The result digest covers bytes [0, 480).
DEVELOPMENT_CANDIDATE_RESULT_OFFSET_MAGIC: Final[int] = 0
DEVELOPMENT_CANDIDATE_RESULT_OFFSET_VERSION: Final[int] = 8
DEVELOPMENT_CANDIDATE_RESULT_OFFSET_OUTCOME: Final[int] = 12
DEVELOPMENT_CANDIDATE_RESULT_OFFSET_PROCESS_STATUS: Final[int] = 16
DEVELOPMENT_CANDIDATE_RESULT_OFFSET_CHILD_EXIT_CODE: Final[int] = 20
DEVELOPMENT_CANDIDATE_RESULT_OFFSET_CHILD_SIGNAL: Final[int] = 24
DEVELOPMENT_CANDIDATE_RESULT_OFFSET_FLAGS: Final[int] = 28
DEVELOPMENT_CANDIDATE_RESULT_OFFSET_STDOUT_OBSERVED: Final[int] = 32
DEVELOPMENT_CANDIDATE_RESULT_OFFSET_STDERR_OBSERVED: Final[int] = 40
DEVELOPMENT_CANDIDATE_RESULT_OFFSET_WAIT4_USER_CPU_USEC: Final[int] = 48
DEVELOPMENT_CANDIDATE_RESULT_OFFSET_WAIT4_SYS_CPU_USEC: Final[int] = 56
DEVELOPMENT_CANDIDATE_RESULT_OFFSET_WALL_USEC: Final[int] = 64
DEVELOPMENT_CANDIDATE_RESULT_OFFSET_DESCENDANTS_REAPED: Final[int] = 72
DEVELOPMENT_CANDIDATE_RESULT_OFFSET_RESERVED_U32: Final[int] = 76
DEVELOPMENT_CANDIDATE_RESULT_OFFSET_WORKSPACE_SNAPSHOT_BYTES: Final[int] = 80
DEVELOPMENT_CANDIDATE_RESULT_OFFSET_RESERVED: Final[int] = 88
DEVELOPMENT_CANDIDATE_RESULT_RESERVED_BYTES: Final[int] = 8
DEVELOPMENT_CANDIDATE_RESULT_OFFSET_REQUEST_SHA256: Final[int] = 96
DEVELOPMENT_CANDIDATE_RESULT_OFFSET_NONCE: Final[int] = 128
DEVELOPMENT_CANDIDATE_RESULT_OFFSET_INVOCATION_SHA256: Final[int] = 160
DEVELOPMENT_CANDIDATE_RESULT_OFFSET_PROGRAM_SHA256: Final[int] = 192
DEVELOPMENT_CANDIDATE_RESULT_OFFSET_FIXTURE_DEFINITION_SHA256: Final[int] = 224
DEVELOPMENT_CANDIDATE_RESULT_OFFSET_WORKSPACE_BASELINE_SHA256: Final[int] = 256
DEVELOPMENT_CANDIDATE_RESULT_OFFSET_RUNTIME_SNAPSHOT_SHA256: Final[int] = 288
DEVELOPMENT_CANDIDATE_RESULT_OFFSET_ALLOWED_TOOLS_SHA256: Final[int] = 320
DEVELOPMENT_CANDIDATE_RESULT_OFFSET_POLICY_SHA256: Final[int] = 352
DEVELOPMENT_CANDIDATE_RESULT_OFFSET_STDOUT_SHA256: Final[int] = 384
DEVELOPMENT_CANDIDATE_RESULT_OFFSET_STDERR_SHA256: Final[int] = 416
DEVELOPMENT_CANDIDATE_RESULT_OFFSET_WORKSPACE_SNAPSHOT_SHA256: Final[int] = 448
DEVELOPMENT_CANDIDATE_RESULT_OFFSET_RESULT_SHA256: Final[int] = 480

_ZERO_U32: Final[bytes] = b"\0" * 4
_ZERO_REQUEST_RESERVED: Final[bytes] = b"\0" * DEVELOPMENT_CANDIDATE_REQUEST_RESERVED_BYTES
_ZERO_RESULT_RESERVED: Final[bytes] = b"\0" * DEVELOPMENT_CANDIDATE_RESULT_RESERVED_BYTES
_ZERO_SHA256: Final[bytes] = b"\0" * 32
_EMPTY_SHA256: Final[bytes] = sha256(b"").digest()
_U32_MAX: Final[int] = (1 << 32) - 1
_U64_MAX: Final[int] = (1 << 64) - 1


class DevelopmentCandidateProtocolError(ValueError):
    """Raised when a candidate-canary request or result fails closed."""


class DevelopmentCandidateOutcome(IntEnum):
    """The complete terminal-outcome vocabulary for the reviewed canary."""

    NORMAL = 1
    NONZERO = 2
    SIGNAL = 3
    WALL_TIMEOUT = 4
    CPU_LIMIT = 5
    STDOUT_OVERFLOW = 6
    STDERR_OVERFLOW = 7
    WORKSPACE_SNAPSHOT_OVERFLOW = 8
    SUPERVISOR_ERROR = 9


class DevelopmentCandidateProcessStatus(IntEnum):
    """The exact wait status shape for the primary candidate process."""

    NOT_REAPED = 0
    EXITED = 1
    SIGNALED = 2


class DevelopmentCandidateFlag(IntFlag):
    """Independent supervisor observations represented in the result frame."""

    REQUEST_VALIDATED = 1 << 0
    PROGRAM_DESCRIPTOR_VALIDATED = 1 << 1
    FIXTURE_DESCRIPTOR_VALIDATED = 1 << 2
    RUNTIME_SNAPSHOT_VALIDATED = 1 << 3
    WORKSPACE_BASELINE_VALIDATED = 1 << 4
    ALLOWED_TOOLS_VALIDATED = 1 << 5
    POLICY_VALIDATED = 1 << 6
    CHILD_NO_NEW_PRIVS = 1 << 7
    CHILD_DUMPABLE_DISABLED = 1 << 8
    CHILD_SECCOMP_INSTALLED = 1 << 9
    PRIMARY_REAPED = 1 << 10
    ALL_DESCENDANTS_REAPED = 1 << 11
    SOLE_PID1 = 1 << 12
    STDOUT_OVERFLOW = 1 << 13
    STDERR_OVERFLOW = 1 << 14
    WALL_LIMIT_REACHED = 1 << 15
    CPU_LIMIT_REACHED = 1 << 16
    WORKSPACE_SNAPSHOT_WRITTEN = 1 << 17
    WORKSPACE_SNAPSHOT_OVERFLOW = 1 << 18


DEVELOPMENT_CANDIDATE_KNOWN_FLAGS: Final[DevelopmentCandidateFlag] = (
    DevelopmentCandidateFlag.REQUEST_VALIDATED
    | DevelopmentCandidateFlag.PROGRAM_DESCRIPTOR_VALIDATED
    | DevelopmentCandidateFlag.FIXTURE_DESCRIPTOR_VALIDATED
    | DevelopmentCandidateFlag.RUNTIME_SNAPSHOT_VALIDATED
    | DevelopmentCandidateFlag.WORKSPACE_BASELINE_VALIDATED
    | DevelopmentCandidateFlag.ALLOWED_TOOLS_VALIDATED
    | DevelopmentCandidateFlag.POLICY_VALIDATED
    | DevelopmentCandidateFlag.CHILD_NO_NEW_PRIVS
    | DevelopmentCandidateFlag.CHILD_DUMPABLE_DISABLED
    | DevelopmentCandidateFlag.CHILD_SECCOMP_INSTALLED
    | DevelopmentCandidateFlag.PRIMARY_REAPED
    | DevelopmentCandidateFlag.ALL_DESCENDANTS_REAPED
    | DevelopmentCandidateFlag.SOLE_PID1
    | DevelopmentCandidateFlag.STDOUT_OVERFLOW
    | DevelopmentCandidateFlag.STDERR_OVERFLOW
    | DevelopmentCandidateFlag.WALL_LIMIT_REACHED
    | DevelopmentCandidateFlag.CPU_LIMIT_REACHED
    | DevelopmentCandidateFlag.WORKSPACE_SNAPSHOT_WRITTEN
    | DevelopmentCandidateFlag.WORKSPACE_SNAPSHOT_OVERFLOW
)

DEVELOPMENT_CANDIDATE_SETUP_FLAGS: Final[DevelopmentCandidateFlag] = (
    DevelopmentCandidateFlag.REQUEST_VALIDATED
    | DevelopmentCandidateFlag.PROGRAM_DESCRIPTOR_VALIDATED
    | DevelopmentCandidateFlag.FIXTURE_DESCRIPTOR_VALIDATED
    | DevelopmentCandidateFlag.RUNTIME_SNAPSHOT_VALIDATED
    | DevelopmentCandidateFlag.WORKSPACE_BASELINE_VALIDATED
    | DevelopmentCandidateFlag.ALLOWED_TOOLS_VALIDATED
    | DevelopmentCandidateFlag.POLICY_VALIDATED
    | DevelopmentCandidateFlag.CHILD_NO_NEW_PRIVS
    | DevelopmentCandidateFlag.CHILD_DUMPABLE_DISABLED
    | DevelopmentCandidateFlag.CHILD_SECCOMP_INSTALLED
)

DEVELOPMENT_CANDIDATE_CLEANUP_FLAGS: Final[DevelopmentCandidateFlag] = (
    DevelopmentCandidateFlag.PRIMARY_REAPED
    | DevelopmentCandidateFlag.ALL_DESCENDANTS_REAPED
    | DevelopmentCandidateFlag.SOLE_PID1
)

# A result may truthfully observe more than one resource condition.  For
# example, cleanup after stdout overflow may carry final wall/CPU measurements
# across their ceilings, or both stream readers may reach cap-plus-one in the
# same polling turn.  The outcome stays singular through this fixed priority.
# A supervisor error is an explicit override and is handled separately.
DEVELOPMENT_CANDIDATE_RESOURCE_OUTCOME_PRECEDENCE: Final[
    tuple[DevelopmentCandidateOutcome, ...]
] = (
    DevelopmentCandidateOutcome.WORKSPACE_SNAPSHOT_OVERFLOW,
    DevelopmentCandidateOutcome.STDOUT_OVERFLOW,
    DevelopmentCandidateOutcome.STDERR_OVERFLOW,
    DevelopmentCandidateOutcome.CPU_LIMIT,
    DevelopmentCandidateOutcome.WALL_TIMEOUT,
)


def _plain_int(value: object, minimum: int, maximum: int, what: str) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise DevelopmentCandidateProtocolError(
            f"{what} must be a plain integer in [{minimum}, {maximum}]"
        )
    return value


def _exact_digest(value: object, what: str) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        raise DevelopmentCandidateProtocolError(f"{what} must be exactly 32 bytes")
    if value == _ZERO_SHA256:
        raise DevelopmentCandidateProtocolError(f"{what} must not be all zero")
    return value


def _exact_nonce(value: object) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        raise DevelopmentCandidateProtocolError("nonce must be exactly 32 bytes")
    if value == _ZERO_SHA256:
        raise DevelopmentCandidateProtocolError("nonce must not be all zero")
    return value


def _outcome(value: object) -> DevelopmentCandidateOutcome:
    if type(value) is not DevelopmentCandidateOutcome:
        raise DevelopmentCandidateProtocolError(
            "outcome must be exact DevelopmentCandidateOutcome"
        )
    return value


def _process_status(value: object) -> DevelopmentCandidateProcessStatus:
    if type(value) is not DevelopmentCandidateProcessStatus:
        raise DevelopmentCandidateProtocolError(
            "process_status must be exact DevelopmentCandidateProcessStatus"
        )
    return value


def _flags(value: object) -> DevelopmentCandidateFlag:
    if type(value) is not DevelopmentCandidateFlag:
        raise DevelopmentCandidateProtocolError(
            "flags must be exact DevelopmentCandidateFlag"
        )
    unknown = int(value) & ~int(DEVELOPMENT_CANDIDATE_KNOWN_FLAGS)
    if unknown:
        raise DevelopmentCandidateProtocolError("flags contain an unknown bit")
    return value


def _has(flags: DevelopmentCandidateFlag, flag: DevelopmentCandidateFlag) -> bool:
    return bool(flags & flag)


def _canonical_bytes(value: dict[str, object]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class DevelopmentCandidateRequest:
    """One exact request for a descriptor-bound reviewed Bash canary."""

    program_bytes: int
    wall_timeout_usec: int
    cpu_time_limit_usec: int
    stdout_cap_bytes: int
    stderr_cap_bytes: int
    workspace_snapshot_cap_bytes: int
    nonce: bytes
    invocation_sha256: bytes
    program_sha256: bytes
    fixture_definition_sha256: bytes
    workspace_baseline_sha256: bytes
    runtime_snapshot_sha256: bytes
    allowed_tools_sha256: bytes
    policy_sha256: bytes

    def __post_init__(self) -> None:
        _plain_int(
            self.program_bytes,
            1,
            DEVELOPMENT_CANDIDATE_MAXIMUM_PROGRAM_BYTES,
            "program_bytes",
        )
        _plain_int(
            self.wall_timeout_usec,
            DEVELOPMENT_CANDIDATE_MINIMUM_WALL_TIMEOUT_USEC,
            DEVELOPMENT_CANDIDATE_MAXIMUM_WALL_TIMEOUT_USEC,
            "wall_timeout_usec",
        )
        _plain_int(
            self.cpu_time_limit_usec,
            DEVELOPMENT_CANDIDATE_MINIMUM_CPU_TIME_USEC,
            DEVELOPMENT_CANDIDATE_MAXIMUM_CPU_TIME_USEC,
            "cpu_time_limit_usec",
        )
        for name in ("stdout_cap_bytes", "stderr_cap_bytes"):
            _plain_int(
                getattr(self, name),
                1,
                DEVELOPMENT_CANDIDATE_MAXIMUM_STREAM_CAP_BYTES,
                name,
            )
        _plain_int(
            self.workspace_snapshot_cap_bytes,
            1,
            DEVELOPMENT_CANDIDATE_MAXIMUM_WORKSPACE_SNAPSHOT_BYTES,
            "workspace_snapshot_cap_bytes",
        )
        _exact_nonce(self.nonce)
        for name in (
            "invocation_sha256",
            "program_sha256",
            "fixture_definition_sha256",
            "workspace_baseline_sha256",
            "runtime_snapshot_sha256",
            "allowed_tools_sha256",
            "policy_sha256",
        ):
            _exact_digest(getattr(self, name), name)

    @property
    def request_sha256(self) -> bytes:
        return sha256(encode_development_candidate_request(self)).digest()

    def to_record(self) -> dict[str, object]:
        return development_candidate_request_record(self)

    def canonical_record_bytes(self) -> bytes:
        return canonical_development_candidate_request_record_bytes(self)


@dataclass(frozen=True, slots=True)
class DevelopmentCandidateResult:
    """One self-consistent result which still requires request binding."""

    outcome: DevelopmentCandidateOutcome
    process_status: DevelopmentCandidateProcessStatus
    child_exit_code: int
    child_signal: int
    flags: DevelopmentCandidateFlag
    stdout_observed: int
    stderr_observed: int
    wait4_user_cpu_usec: int
    wait4_sys_cpu_usec: int
    wall_usec: int
    descendants_reaped: int
    workspace_snapshot_bytes: int
    request_sha256: bytes
    nonce: bytes
    invocation_sha256: bytes
    program_sha256: bytes
    fixture_definition_sha256: bytes
    workspace_baseline_sha256: bytes
    runtime_snapshot_sha256: bytes
    allowed_tools_sha256: bytes
    policy_sha256: bytes
    stdout_sha256: bytes
    stderr_sha256: bytes
    workspace_snapshot_sha256: bytes
    result_sha256: bytes

    def __post_init__(self) -> None:
        _validate_result_self(self)

    def to_record(self) -> dict[str, object]:
        return development_candidate_result_record(self)

    def canonical_record_bytes(self) -> bytes:
        return canonical_development_candidate_result_record_bytes(self)


def encode_development_candidate_request(request: DevelopmentCandidateRequest) -> bytes:
    """Encode one request into the exact 384-byte little-endian layout."""

    if type(request) is not DevelopmentCandidateRequest:
        raise DevelopmentCandidateProtocolError(
            "request must be exact DevelopmentCandidateRequest"
        )
    request.__post_init__()
    frame = bytearray(DEVELOPMENT_CANDIDATE_REQUEST_BYTES)
    frame[DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_MAGIC:8] = (
        DEVELOPMENT_CANDIDATE_REQUEST_MAGIC
    )
    struct.pack_into(
        "<IIQQQQQQ",
        frame,
        DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_VERSION,
        DEVELOPMENT_CANDIDATE_PROTOCOL_VERSION,
        0,
        request.program_bytes,
        request.wall_timeout_usec,
        request.cpu_time_limit_usec,
        request.stdout_cap_bytes,
        request.stderr_cap_bytes,
        request.workspace_snapshot_cap_bytes,
    )
    fields = (
        (DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_NONCE, request.nonce),
        (DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_INVOCATION_SHA256, request.invocation_sha256),
        (DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_PROGRAM_SHA256, request.program_sha256),
        (
            DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_FIXTURE_DEFINITION_SHA256,
            request.fixture_definition_sha256,
        ),
        (
            DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_WORKSPACE_BASELINE_SHA256,
            request.workspace_baseline_sha256,
        ),
        (
            DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_RUNTIME_SNAPSHOT_SHA256,
            request.runtime_snapshot_sha256,
        ),
        (
            DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_ALLOWED_TOOLS_SHA256,
            request.allowed_tools_sha256,
        ),
        (DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_POLICY_SHA256, request.policy_sha256),
    )
    for offset, payload in fields:
        frame[offset:offset + 32] = payload
    return bytes(frame)


def parse_development_candidate_request(frame: bytes) -> DevelopmentCandidateRequest:
    """Parse and strictly validate one exact request frame."""

    if type(frame) is not bytes:
        raise DevelopmentCandidateProtocolError("request frame must be exact bytes")
    if len(frame) != DEVELOPMENT_CANDIDATE_REQUEST_BYTES:
        raise DevelopmentCandidateProtocolError(
            f"request frame must be exactly {DEVELOPMENT_CANDIDATE_REQUEST_BYTES} bytes"
        )
    if frame[:8] != DEVELOPMENT_CANDIDATE_REQUEST_MAGIC:
        raise DevelopmentCandidateProtocolError("request magic is invalid")
    if frame[DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_RESERVED_U32:16] != _ZERO_U32:
        raise DevelopmentCandidateProtocolError("request reserved u32 is not zero")
    if frame[DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_RESERVED:] != _ZERO_REQUEST_RESERVED:
        raise DevelopmentCandidateProtocolError("request reserved bytes are not zero")
    (
        version,
        reserved_u32,
        program_bytes,
        wall_timeout_usec,
        cpu_time_limit_usec,
        stdout_cap_bytes,
        stderr_cap_bytes,
        workspace_snapshot_cap_bytes,
    ) = struct.unpack_from("<IIQQQQQQ", frame, DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_VERSION)
    if version != DEVELOPMENT_CANDIDATE_PROTOCOL_VERSION or reserved_u32 != 0:
        raise DevelopmentCandidateProtocolError("request version or reserved field is invalid")
    request = DevelopmentCandidateRequest(
        program_bytes=program_bytes,
        wall_timeout_usec=wall_timeout_usec,
        cpu_time_limit_usec=cpu_time_limit_usec,
        stdout_cap_bytes=stdout_cap_bytes,
        stderr_cap_bytes=stderr_cap_bytes,
        workspace_snapshot_cap_bytes=workspace_snapshot_cap_bytes,
        nonce=frame[64:96],
        invocation_sha256=frame[96:128],
        program_sha256=frame[128:160],
        fixture_definition_sha256=frame[160:192],
        workspace_baseline_sha256=frame[192:224],
        runtime_snapshot_sha256=frame[224:256],
        allowed_tools_sha256=frame[256:288],
        policy_sha256=frame[288:320],
    )
    if encode_development_candidate_request(request) != frame:
        raise DevelopmentCandidateProtocolError("request does not round-trip canonically")
    return request


def _validate_process_shape(result: DevelopmentCandidateResult) -> None:
    reaped = _has(result.flags, DevelopmentCandidateFlag.PRIMARY_REAPED)
    if result.process_status is DevelopmentCandidateProcessStatus.NOT_REAPED:
        if result.child_exit_code != -1 or result.child_signal != 0 or reaped:
            raise DevelopmentCandidateProtocolError(
                "not_reaped status has an invalid exit/signal/reaping shape"
            )
    elif result.process_status is DevelopmentCandidateProcessStatus.EXITED:
        if not 0 <= result.child_exit_code <= 255 or result.child_signal != 0 or not reaped:
            raise DevelopmentCandidateProtocolError(
                "exited status has an invalid exit/signal/reaping shape"
            )
    elif result.process_status is DevelopmentCandidateProcessStatus.SIGNALED:
        if result.child_exit_code != -1 or not 1 <= result.child_signal <= 64 or not reaped:
            raise DevelopmentCandidateProtocolError(
                "signaled status has an invalid exit/signal/reaping shape"
            )
    else:  # pragma: no cover - exact enum validation makes this unreachable
        raise DevelopmentCandidateProtocolError("unsupported process status")
    if reaped and result.descendants_reaped < 1:
        raise DevelopmentCandidateProtocolError(
            "primary_reaped requires descendants_reaped >= 1"
        )


def _validate_result_self(result: DevelopmentCandidateResult) -> None:
    if type(result) is not DevelopmentCandidateResult:
        raise DevelopmentCandidateProtocolError(
            "result must be exact DevelopmentCandidateResult"
        )
    _outcome(result.outcome)
    _process_status(result.process_status)
    _plain_int(result.child_exit_code, -1, 255, "child_exit_code")
    _plain_int(result.child_signal, 0, 64, "child_signal")
    flags = _flags(result.flags)
    for name in (
        "stdout_observed",
        "stderr_observed",
        "wait4_user_cpu_usec",
        "wait4_sys_cpu_usec",
        "wall_usec",
        "workspace_snapshot_bytes",
    ):
        _plain_int(getattr(result, name), 0, _U64_MAX, name)
    _plain_int(result.descendants_reaped, 0, _U32_MAX, "descendants_reaped")
    if result.wait4_user_cpu_usec + result.wait4_sys_cpu_usec > _U64_MAX:
        raise DevelopmentCandidateProtocolError("cumulative wait4 CPU overflows u64")
    _exact_nonce(result.nonce)
    for name in (
        "request_sha256",
        "invocation_sha256",
        "program_sha256",
        "fixture_definition_sha256",
        "workspace_baseline_sha256",
        "runtime_snapshot_sha256",
        "allowed_tools_sha256",
        "policy_sha256",
        "stdout_sha256",
        "stderr_sha256",
        "workspace_snapshot_sha256",
        "result_sha256",
    ):
        _exact_digest(getattr(result, name), name)
    if not _has(flags, DevelopmentCandidateFlag.REQUEST_VALIDATED):
        raise DevelopmentCandidateProtocolError("result does not report request validation")
    if _has(flags, DevelopmentCandidateFlag.ALL_DESCENDANTS_REAPED) and not _has(
        flags, DevelopmentCandidateFlag.PRIMARY_REAPED
    ):
        raise DevelopmentCandidateProtocolError(
            "all_descendants_reaped requires primary_reaped"
        )
    if _has(flags, DevelopmentCandidateFlag.SOLE_PID1) and not _has(
        flags, DevelopmentCandidateFlag.ALL_DESCENDANTS_REAPED
    ):
        raise DevelopmentCandidateProtocolError(
            "sole_pid1 requires all_descendants_reaped"
        )
    written = _has(flags, DevelopmentCandidateFlag.WORKSPACE_SNAPSHOT_WRITTEN)
    workspace_overflow = _has(
        flags, DevelopmentCandidateFlag.WORKSPACE_SNAPSHOT_OVERFLOW
    )
    if written and workspace_overflow:
        raise DevelopmentCandidateProtocolError(
            "workspace snapshot cannot be both complete and overflowed"
        )
    if (written or workspace_overflow) and not _has(
        flags, DevelopmentCandidateFlag.SOLE_PID1
    ):
        raise DevelopmentCandidateProtocolError(
            "workspace snapshot requires sole_pid1 quiescence"
        )
    if not written and not workspace_overflow:
        if (
            result.workspace_snapshot_bytes != 0
            or result.workspace_snapshot_sha256 != _EMPTY_SHA256
        ):
            raise DevelopmentCandidateProtocolError(
                "absent workspace snapshot must use zero bytes and the empty digest"
            )
    for count, digest, label in (
        (result.stdout_observed, result.stdout_sha256, "stdout"),
        (result.stderr_observed, result.stderr_sha256, "stderr"),
        (
            result.workspace_snapshot_bytes,
            result.workspace_snapshot_sha256,
            "workspace snapshot",
        ),
    ):
        if count == 0 and digest != _EMPTY_SHA256:
            raise DevelopmentCandidateProtocolError(
                f"zero-byte {label} must use the empty SHA-256"
            )
    _validate_process_shape(result)
    expected_result_sha256 = sha256(_encode_result_prefix_unchecked(result)).digest()
    if result.result_sha256 != expected_result_sha256:
        raise DevelopmentCandidateProtocolError(
            "result_sha256 does not hash the exact first 480 result bytes"
        )


def _validate_identity_binding(
    result: DevelopmentCandidateResult,
    request: DevelopmentCandidateRequest,
) -> None:
    expected_request_sha256 = sha256(
        encode_development_candidate_request(request)
    ).digest()
    if result.request_sha256 != expected_request_sha256:
        raise DevelopmentCandidateProtocolError(
            "result request_sha256 does not bind the exact request"
        )
    for name in (
        "nonce",
        "invocation_sha256",
        "program_sha256",
        "fixture_definition_sha256",
        "workspace_baseline_sha256",
        "runtime_snapshot_sha256",
        "allowed_tools_sha256",
        "policy_sha256",
    ):
        if getattr(result, name) != getattr(request, name):
            raise DevelopmentCandidateProtocolError(
                f"result {name} does not bind the exact request"
            )


def validate_development_candidate_result_binding(
    result: DevelopmentCandidateResult,
    *,
    request: DevelopmentCandidateRequest,
) -> None:
    """Bind one typed result to the exact request and all request limits."""

    if type(result) is not DevelopmentCandidateResult:
        raise DevelopmentCandidateProtocolError(
            "result must be exact DevelopmentCandidateResult"
        )
    if type(request) is not DevelopmentCandidateRequest:
        raise DevelopmentCandidateProtocolError(
            "request must be exact DevelopmentCandidateRequest"
        )
    request.__post_init__()
    result.__post_init__()
    _validate_identity_binding(result, request)

    stream_specs = (
        (
            "stdout",
            result.stdout_observed,
            request.stdout_cap_bytes,
            DevelopmentCandidateFlag.STDOUT_OVERFLOW,
        ),
        (
            "stderr",
            result.stderr_observed,
            request.stderr_cap_bytes,
            DevelopmentCandidateFlag.STDERR_OVERFLOW,
        ),
    )
    for label, observed, cap, flag in stream_specs:
        if observed > cap + 1:
            raise DevelopmentCandidateProtocolError(
                f"{label}_observed exceeds the exact cap-plus-one ceiling"
            )
        if _has(result.flags, flag) != (observed == cap + 1):
            raise DevelopmentCandidateProtocolError(
                f"{label} overflow flag disagrees with cap-plus-one capture"
            )

    workspace_overflow = _has(
        result.flags, DevelopmentCandidateFlag.WORKSPACE_SNAPSHOT_OVERFLOW
    )
    if result.workspace_snapshot_bytes > request.workspace_snapshot_cap_bytes + 1:
        raise DevelopmentCandidateProtocolError(
            "workspace snapshot exceeds the exact cap-plus-one ceiling"
        )
    if workspace_overflow != (
        result.workspace_snapshot_bytes == request.workspace_snapshot_cap_bytes + 1
    ):
        raise DevelopmentCandidateProtocolError(
            "workspace snapshot overflow flag disagrees with cap-plus-one capture"
        )

    cumulative_cpu = result.wait4_user_cpu_usec + result.wait4_sys_cpu_usec
    wall_reached = result.wall_usec >= request.wall_timeout_usec
    cpu_reached = cumulative_cpu >= request.cpu_time_limit_usec
    wall_reported = _has(result.flags, DevelopmentCandidateFlag.WALL_LIMIT_REACHED)
    cpu_reported = _has(result.flags, DevelopmentCandidateFlag.CPU_LIMIT_REACHED)
    non_wall_incident_reported = (
        _has(result.flags, DevelopmentCandidateFlag.STDOUT_OVERFLOW)
        or _has(result.flags, DevelopmentCandidateFlag.STDERR_OVERFLOW)
        or workspace_overflow
        or cpu_reported
    )
    non_cpu_incident_reported = (
        _has(result.flags, DevelopmentCandidateFlag.STDOUT_OVERFLOW)
        or _has(result.flags, DevelopmentCandidateFlag.STDERR_OVERFLOW)
        or workspace_overflow
        or wall_reported
    )
    if wall_reported and not wall_reached:
        raise DevelopmentCandidateProtocolError(
            "wall limit flag requires measured wall time at the ceiling"
        )
    if wall_reached and not wall_reported and not non_wall_incident_reported:
        raise DevelopmentCandidateProtocolError(
            "unexplained wall-limit crossing omits the wall-limit flag"
        )
    if cpu_reported and not cpu_reached:
        raise DevelopmentCandidateProtocolError(
            "CPU limit flag requires cumulative wait4 CPU at the ceiling"
        )
    if cpu_reached and not cpu_reported and not non_cpu_incident_reported:
        raise DevelopmentCandidateProtocolError(
            "unexplained CPU-limit crossing omits the CPU-limit flag"
        )

    incident_active = {
        DevelopmentCandidateOutcome.WORKSPACE_SNAPSHOT_OVERFLOW: workspace_overflow,
        DevelopmentCandidateOutcome.STDOUT_OVERFLOW: _has(
            result.flags, DevelopmentCandidateFlag.STDOUT_OVERFLOW
        ),
        DevelopmentCandidateOutcome.STDERR_OVERFLOW: _has(
            result.flags, DevelopmentCandidateFlag.STDERR_OVERFLOW
        ),
        DevelopmentCandidateOutcome.CPU_LIMIT: cpu_reported,
        DevelopmentCandidateOutcome.WALL_TIMEOUT: wall_reported,
    }
    active_incidents = tuple(
        outcome
        for outcome in DEVELOPMENT_CANDIDATE_RESOURCE_OUTCOME_PRECEDENCE
        if incident_active[outcome]
    )
    if result.outcome is DevelopmentCandidateOutcome.SUPERVISOR_ERROR:
        # Infrastructure failure overrides any partial resource observations.
        pass
    elif active_incidents:
        if result.outcome is not active_incidents[0]:
            raise DevelopmentCandidateProtocolError(
                "resource outcome violates the fixed incident precedence"
            )
    else:
        expected = {
            DevelopmentCandidateProcessStatus.EXITED: (
                DevelopmentCandidateOutcome.NORMAL
                if result.child_exit_code == 0
                else DevelopmentCandidateOutcome.NONZERO
            ),
            DevelopmentCandidateProcessStatus.SIGNALED: DevelopmentCandidateOutcome.SIGNAL,
        }.get(result.process_status)
        if expected is None or result.outcome is not expected:
            raise DevelopmentCandidateProtocolError(
                "process status does not match the exact outcome"
            )
    if result.outcome is not DevelopmentCandidateOutcome.SUPERVISOR_ERROR:
        required = DEVELOPMENT_CANDIDATE_SETUP_FLAGS | DEVELOPMENT_CANDIDATE_CLEANUP_FLAGS
        if result.flags & required != required:
            raise DevelopmentCandidateProtocolError(
                "non-error outcome omits mandatory setup or cleanup evidence"
            )
        if workspace_overflow:
            if _has(result.flags, DevelopmentCandidateFlag.WORKSPACE_SNAPSHOT_WRITTEN):
                raise DevelopmentCandidateProtocolError(
                    "overflowed workspace snapshot cannot be marked complete"
                )
        elif not _has(
            result.flags, DevelopmentCandidateFlag.WORKSPACE_SNAPSHOT_WRITTEN
        ):
            raise DevelopmentCandidateProtocolError(
                "non-error outcome requires a complete post-run workspace snapshot"
            )


def _encode_result_prefix_unchecked(result: DevelopmentCandidateResult) -> bytes:
    prefix = bytearray(DEVELOPMENT_CANDIDATE_RESULT_HASHED_PREFIX_BYTES)
    prefix[:8] = DEVELOPMENT_CANDIDATE_RESULT_MAGIC
    struct.pack_into(
        "<IIIiIIQQQQQIIQ",
        prefix,
        DEVELOPMENT_CANDIDATE_RESULT_OFFSET_VERSION,
        DEVELOPMENT_CANDIDATE_PROTOCOL_VERSION,
        int(result.outcome),
        int(result.process_status),
        result.child_exit_code,
        result.child_signal,
        int(result.flags),
        result.stdout_observed,
        result.stderr_observed,
        result.wait4_user_cpu_usec,
        result.wait4_sys_cpu_usec,
        result.wall_usec,
        result.descendants_reaped,
        0,
        result.workspace_snapshot_bytes,
    )
    fields = (
        (96, result.request_sha256),
        (128, result.nonce),
        (160, result.invocation_sha256),
        (192, result.program_sha256),
        (224, result.fixture_definition_sha256),
        (256, result.workspace_baseline_sha256),
        (288, result.runtime_snapshot_sha256),
        (320, result.allowed_tools_sha256),
        (352, result.policy_sha256),
        (384, result.stdout_sha256),
        (416, result.stderr_sha256),
        (448, result.workspace_snapshot_sha256),
    )
    for offset, payload in fields:
        prefix[offset:offset + 32] = payload
    return bytes(prefix)


def parse_development_candidate_result(
    frame: bytes,
    *,
    request: DevelopmentCandidateRequest,
) -> DevelopmentCandidateResult:
    """Parse one exact 512-byte result and bind it to ``request``."""

    if type(frame) is not bytes:
        raise DevelopmentCandidateProtocolError("result frame must be exact bytes")
    if len(frame) != DEVELOPMENT_CANDIDATE_RESULT_BYTES:
        raise DevelopmentCandidateProtocolError(
            f"result frame must be exactly {DEVELOPMENT_CANDIDATE_RESULT_BYTES} bytes"
        )
    if frame[:8] != DEVELOPMENT_CANDIDATE_RESULT_MAGIC:
        raise DevelopmentCandidateProtocolError("result magic is invalid")
    if frame[76:80] != _ZERO_U32:
        raise DevelopmentCandidateProtocolError("result reserved u32 is not zero")
    if frame[88:96] != _ZERO_RESULT_RESERVED:
        raise DevelopmentCandidateProtocolError("result reserved bytes are not zero")
    if frame[480:512] != sha256(frame[:480]).digest():
        raise DevelopmentCandidateProtocolError("result_sha256 is invalid")
    (
        version,
        outcome_code,
        process_status_code,
        child_exit_code,
        child_signal,
        flag_bits,
        stdout_observed,
        stderr_observed,
        wait4_user_cpu_usec,
        wait4_sys_cpu_usec,
        wall_usec,
        descendants_reaped,
        reserved_u32,
        workspace_snapshot_bytes,
    ) = struct.unpack_from("<IIIiIIQQQQQIIQ", frame, 8)
    if version != DEVELOPMENT_CANDIDATE_PROTOCOL_VERSION or reserved_u32 != 0:
        raise DevelopmentCandidateProtocolError("result version or reserved field is invalid")
    try:
        outcome = DevelopmentCandidateOutcome(outcome_code)
    except ValueError as exc:
        raise DevelopmentCandidateProtocolError("result outcome code is invalid") from exc
    try:
        process_status = DevelopmentCandidateProcessStatus(process_status_code)
    except ValueError as exc:
        raise DevelopmentCandidateProtocolError(
            "result process-status code is invalid"
        ) from exc
    if flag_bits & ~int(DEVELOPMENT_CANDIDATE_KNOWN_FLAGS):
        raise DevelopmentCandidateProtocolError("result flags contain an unknown bit")
    result = DevelopmentCandidateResult(
        outcome=outcome,
        process_status=process_status,
        child_exit_code=child_exit_code,
        child_signal=child_signal,
        flags=DevelopmentCandidateFlag(flag_bits),
        stdout_observed=stdout_observed,
        stderr_observed=stderr_observed,
        wait4_user_cpu_usec=wait4_user_cpu_usec,
        wait4_sys_cpu_usec=wait4_sys_cpu_usec,
        wall_usec=wall_usec,
        descendants_reaped=descendants_reaped,
        workspace_snapshot_bytes=workspace_snapshot_bytes,
        request_sha256=frame[96:128],
        nonce=frame[128:160],
        invocation_sha256=frame[160:192],
        program_sha256=frame[192:224],
        fixture_definition_sha256=frame[224:256],
        workspace_baseline_sha256=frame[256:288],
        runtime_snapshot_sha256=frame[288:320],
        allowed_tools_sha256=frame[320:352],
        policy_sha256=frame[352:384],
        stdout_sha256=frame[384:416],
        stderr_sha256=frame[416:448],
        workspace_snapshot_sha256=frame[448:480],
        result_sha256=frame[480:512],
    )
    validate_development_candidate_result_binding(result, request=request)
    return result


def development_candidate_request_record(
    request: DevelopmentCandidateRequest,
) -> dict[str, object]:
    """Return the canonical, descriptor-free, nonauthorizing request record."""

    if type(request) is not DevelopmentCandidateRequest:
        raise DevelopmentCandidateProtocolError(
            "request must be exact DevelopmentCandidateRequest"
        )
    frame = encode_development_candidate_request(request)
    return {
        "record_type": "cbds-development-reviewed-bash-canary-request",
        "protocol_version": DEVELOPMENT_CANDIDATE_PROTOCOL_VERSION,
        "wire_magic": DEVELOPMENT_CANDIDATE_REQUEST_MAGIC.decode("ascii"),
        "wire_bytes": DEVELOPMENT_CANDIDATE_REQUEST_BYTES,
        "descriptor_contract": {
            "program_fd": DEVELOPMENT_CANDIDATE_PROGRAM_FD,
            "fixture_bundle_fd": DEVELOPMENT_CANDIDATE_FIXTURE_BUNDLE_FD,
            "workspace_snapshot_fd": DEVELOPMENT_CANDIDATE_WORKSPACE_SNAPSHOT_FD,
        },
        "program_bytes": request.program_bytes,
        "wall_timeout_usec": request.wall_timeout_usec,
        "cpu_time_limit_usec": request.cpu_time_limit_usec,
        "stdout_cap_bytes": request.stdout_cap_bytes,
        "stderr_cap_bytes": request.stderr_cap_bytes,
        "workspace_snapshot_cap_bytes": request.workspace_snapshot_cap_bytes,
        "nonce_hex": request.nonce.hex(),
        "invocation_sha256": request.invocation_sha256.hex(),
        "program_sha256": request.program_sha256.hex(),
        "fixture_definition_sha256": request.fixture_definition_sha256.hex(),
        "workspace_baseline_sha256": request.workspace_baseline_sha256.hex(),
        "runtime_snapshot_sha256": request.runtime_snapshot_sha256.hex(),
        "allowed_tools_sha256": request.allowed_tools_sha256.hex(),
        "policy_sha256": request.policy_sha256.hex(),
        "request_sha256": sha256(frame).hexdigest(),
        "candidate_execution_authorized": False,
        "scored_evaluation_eligible": False,
        "model_selection_eligible": False,
        "claim_pipeline_eligible": False,
        "claim_authorized": False,
    }


def development_candidate_result_record(
    result: DevelopmentCandidateResult,
) -> dict[str, object]:
    """Return the canonical, descriptor-free, nonauthorizing result record."""

    if type(result) is not DevelopmentCandidateResult:
        raise DevelopmentCandidateProtocolError(
            "result must be exact DevelopmentCandidateResult"
        )
    result.__post_init__()
    flag_names = [
        flag.name.lower()
        for flag in DevelopmentCandidateFlag
        if _has(result.flags, flag)
    ]
    return {
        "record_type": "cbds-development-reviewed-bash-canary-result",
        "protocol_version": DEVELOPMENT_CANDIDATE_PROTOCOL_VERSION,
        "wire_magic": DEVELOPMENT_CANDIDATE_RESULT_MAGIC.decode("ascii"),
        "wire_bytes": DEVELOPMENT_CANDIDATE_RESULT_BYTES,
        "outcome": result.outcome.name.lower(),
        "outcome_code": int(result.outcome),
        "process_status": result.process_status.name.lower(),
        "process_status_code": int(result.process_status),
        "child_exit_code": result.child_exit_code,
        "child_signal": result.child_signal,
        "flags": flag_names,
        "flags_bits": int(result.flags),
        "stdout_observed": result.stdout_observed,
        "stderr_observed": result.stderr_observed,
        "wait4_user_cpu_usec": result.wait4_user_cpu_usec,
        "wait4_sys_cpu_usec": result.wait4_sys_cpu_usec,
        "wait4_total_cpu_usec": (
            result.wait4_user_cpu_usec + result.wait4_sys_cpu_usec
        ),
        "wall_usec": result.wall_usec,
        "descendants_reaped": result.descendants_reaped,
        "workspace_snapshot_bytes": result.workspace_snapshot_bytes,
        "request_sha256": result.request_sha256.hex(),
        "nonce_hex": result.nonce.hex(),
        "invocation_sha256": result.invocation_sha256.hex(),
        "program_sha256": result.program_sha256.hex(),
        "fixture_definition_sha256": result.fixture_definition_sha256.hex(),
        "workspace_baseline_sha256": result.workspace_baseline_sha256.hex(),
        "runtime_snapshot_sha256": result.runtime_snapshot_sha256.hex(),
        "allowed_tools_sha256": result.allowed_tools_sha256.hex(),
        "policy_sha256": result.policy_sha256.hex(),
        "stdout_sha256": result.stdout_sha256.hex(),
        "stderr_sha256": result.stderr_sha256.hex(),
        "workspace_snapshot_sha256": result.workspace_snapshot_sha256.hex(),
        "result_sha256": result.result_sha256.hex(),
        "candidate_execution_authorized": False,
        "scored_evaluation_eligible": False,
        "model_selection_eligible": False,
        "claim_pipeline_eligible": False,
        "claim_authorized": False,
    }


def canonical_development_candidate_request_record_bytes(
    request: DevelopmentCandidateRequest,
) -> bytes:
    return _canonical_bytes(development_candidate_request_record(request))


def canonical_development_candidate_result_record_bytes(
    result: DevelopmentCandidateResult,
) -> bytes:
    return _canonical_bytes(development_candidate_result_record(result))


def _encode_development_candidate_result_for_tests(
    request: DevelopmentCandidateRequest,
    *,
    outcome: DevelopmentCandidateOutcome = DevelopmentCandidateOutcome.NORMAL,
    process_status: DevelopmentCandidateProcessStatus = DevelopmentCandidateProcessStatus.EXITED,
    child_exit_code: int = 0,
    child_signal: int = 0,
    flags: DevelopmentCandidateFlag = (
        DEVELOPMENT_CANDIDATE_SETUP_FLAGS
        | DEVELOPMENT_CANDIDATE_CLEANUP_FLAGS
        | DevelopmentCandidateFlag.WORKSPACE_SNAPSHOT_WRITTEN
    ),
    stdout_observed: int = 0,
    stderr_observed: int = 0,
    wait4_user_cpu_usec: int = 0,
    wait4_sys_cpu_usec: int = 0,
    wall_usec: int = 1,
    descendants_reaped: int = 1,
    workspace_snapshot_bytes: int = 0,
    request_sha256: bytes | None = None,
    nonce: bytes | None = None,
    invocation_sha256: bytes | None = None,
    program_sha256: bytes | None = None,
    fixture_definition_sha256: bytes | None = None,
    workspace_baseline_sha256: bytes | None = None,
    runtime_snapshot_sha256: bytes | None = None,
    allowed_tools_sha256: bytes | None = None,
    policy_sha256: bytes | None = None,
    stdout_sha256: bytes = _EMPTY_SHA256,
    stderr_sha256: bytes = _EMPTY_SHA256,
    workspace_snapshot_sha256: bytes = _EMPTY_SHA256,
) -> bytes:
    """Private test-only encoder; production code only parses result frames."""

    if type(request) is not DevelopmentCandidateRequest:
        raise DevelopmentCandidateProtocolError(
            "request must be exact DevelopmentCandidateRequest"
        )
    request.__post_init__()
    values: dict[str, object] = {
        "outcome": outcome,
        "process_status": process_status,
        "child_exit_code": child_exit_code,
        "child_signal": child_signal,
        "flags": flags,
        "stdout_observed": stdout_observed,
        "stderr_observed": stderr_observed,
        "wait4_user_cpu_usec": wait4_user_cpu_usec,
        "wait4_sys_cpu_usec": wait4_sys_cpu_usec,
        "wall_usec": wall_usec,
        "descendants_reaped": descendants_reaped,
        "workspace_snapshot_bytes": workspace_snapshot_bytes,
        "request_sha256": request.request_sha256 if request_sha256 is None else request_sha256,
        "nonce": request.nonce if nonce is None else nonce,
        "invocation_sha256": (
            request.invocation_sha256 if invocation_sha256 is None else invocation_sha256
        ),
        "program_sha256": request.program_sha256 if program_sha256 is None else program_sha256,
        "fixture_definition_sha256": (
            request.fixture_definition_sha256
            if fixture_definition_sha256 is None
            else fixture_definition_sha256
        ),
        "workspace_baseline_sha256": (
            request.workspace_baseline_sha256
            if workspace_baseline_sha256 is None
            else workspace_baseline_sha256
        ),
        "runtime_snapshot_sha256": (
            request.runtime_snapshot_sha256
            if runtime_snapshot_sha256 is None
            else runtime_snapshot_sha256
        ),
        "allowed_tools_sha256": (
            request.allowed_tools_sha256
            if allowed_tools_sha256 is None
            else allowed_tools_sha256
        ),
        "policy_sha256": request.policy_sha256 if policy_sha256 is None else policy_sha256,
        "stdout_sha256": stdout_sha256,
        "stderr_sha256": stderr_sha256,
        "workspace_snapshot_sha256": workspace_snapshot_sha256,
    }
    provisional = object.__new__(DevelopmentCandidateResult)
    for name, value in values.items():
        object.__setattr__(provisional, name, value)
    object.__setattr__(provisional, "result_sha256", _EMPTY_SHA256)
    prefix = _encode_result_prefix_unchecked(provisional)
    digest = sha256(prefix).digest()
    result = DevelopmentCandidateResult(
        **values,  # type: ignore[arg-type]
        result_sha256=digest,
    )
    validate_development_candidate_result_binding(result, request=request)
    return prefix + digest


__all__ = [
    name
    for name in tuple(globals())
    if name.startswith("DEVELOPMENT_CANDIDATE_")
] + [
    "DevelopmentCandidateFlag",
    "DevelopmentCandidateOutcome",
    "DevelopmentCandidateProcessStatus",
    "DevelopmentCandidateProtocolError",
    "DevelopmentCandidateRequest",
    "DevelopmentCandidateResult",
    "canonical_development_candidate_request_record_bytes",
    "canonical_development_candidate_result_record_bytes",
    "development_candidate_request_record",
    "development_candidate_result_record",
    "encode_development_candidate_request",
    "parse_development_candidate_request",
    "parse_development_candidate_result",
    "validate_development_candidate_result_binding",
]
