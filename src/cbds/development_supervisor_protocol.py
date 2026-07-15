"""Fixed binary protocol for the candidate-free supervisor canary.

The protocol in this module carries only one of nine frozen canary scenarios
and resource/capture ceilings.  It has no program, argv, environment, fixture,
verifier, score, or arbitrary payload field.  It therefore cannot authorize a
synthesized-candidate launch.  Its purpose is to make a future supervisor's
PID-1, reaping, timeout, capture, and seccomp canaries unambiguous at the byte
boundary.

Requests are exactly 64 little-endian bytes.  Results are exactly 256 bytes
and bind both the complete request and its nonce.  Parsing never searches a
stream for a frame: callers must provide the one exact result-frame payload.
The private result encoder is test-only; production code consumes results only
through :func:`parse_development_supervisor_result`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, IntFlag
from hashlib import sha256
import json
import struct
from typing import Final


DEVELOPMENT_SUPERVISOR_PROTOCOL_VERSION: Final[int] = 1
DEVELOPMENT_SUPERVISOR_REQUEST_MAGIC: Final[bytes] = b"CBDSCRQ1"
DEVELOPMENT_SUPERVISOR_RESULT_MAGIC: Final[bytes] = b"CBDSSRS1"
DEVELOPMENT_SUPERVISOR_REQUEST_BYTES: Final[int] = 64
DEVELOPMENT_SUPERVISOR_RESULT_BYTES: Final[int] = 256
DEVELOPMENT_SUPERVISOR_RESULT_HASHED_PREFIX_BYTES: Final[int] = 224
DEVELOPMENT_SUPERVISOR_MINIMUM_TIMEOUT_MS: Final[int] = 10
DEVELOPMENT_SUPERVISOR_MAXIMUM_TIMEOUT_MS: Final[int] = 5_000
DEVELOPMENT_SUPERVISOR_MAXIMUM_STREAM_CAP_BYTES: Final[int] = 1024 * 1024

_ZERO_U32: Final[bytes] = b"\0" * 4
_ZERO_RESULT_RESERVED: Final[bytes] = b"\0" * 16
_ZERO_NONCE: Final[bytes] = b"\0" * 32
_U32_MAX: Final[int] = (1 << 32) - 1
_U64_MAX: Final[int] = (1 << 64) - 1
_I32_MIN: Final[int] = -(1 << 31)
_I32_MAX: Final[int] = (1 << 31) - 1


class DevelopmentSupervisorProtocolError(ValueError):
    """Raised when a request or result violates the frozen wire protocol."""


class DevelopmentSupervisorScenario(IntEnum):
    """The complete candidate-free canary scenario vocabulary."""

    NORMAL = 1
    DOUBLE_FORK_SETSID = 2
    ZOMBIE = 3
    WALL_TIMEOUT = 4
    STDOUT_FLOOD = 5
    STDERR_FLOOD = 6
    CPU_FANOUT = 7
    FORBIDDEN_SYSCALL = 8
    RESULT_FRAME_SPOOF = 9


class DevelopmentSupervisorOutcome(IntEnum):
    """The complete supervisor terminal-outcome vocabulary."""

    NORMAL = 1
    NONZERO = 2
    SIGNAL = 3
    WALL_TIMEOUT = 4
    STDOUT_OVERFLOW = 5
    STDERR_OVERFLOW = 6
    SUPERVISOR_ERROR = 7


class DevelopmentSupervisorFlag(IntFlag):
    """Independently reported supervisor observations."""

    REQUEST_VALIDATED = 1 << 0
    PID1_VERIFIED = 1 << 1
    NO_NEW_PRIVS = 1 << 2
    DUMPABLE_DISABLED = 1 << 3
    SECCOMP_INSTALLED = 1 << 4
    STDOUT_OVERFLOW = 1 << 5
    STDERR_OVERFLOW = 1 << 6
    TIMED_OUT = 1 << 7
    PRIMARY_REAPED = 1 << 8
    ALL_DESCENDANTS_REAPED = 1 << 9
    SOLE_PID1 = 1 << 10
    TERMINATION_SIGNAL_RECEIVED = 1 << 11


DEVELOPMENT_SUPERVISOR_KNOWN_FLAGS: Final[DevelopmentSupervisorFlag] = (
    DevelopmentSupervisorFlag.REQUEST_VALIDATED
    | DevelopmentSupervisorFlag.PID1_VERIFIED
    | DevelopmentSupervisorFlag.NO_NEW_PRIVS
    | DevelopmentSupervisorFlag.DUMPABLE_DISABLED
    | DevelopmentSupervisorFlag.SECCOMP_INSTALLED
    | DevelopmentSupervisorFlag.STDOUT_OVERFLOW
    | DevelopmentSupervisorFlag.STDERR_OVERFLOW
    | DevelopmentSupervisorFlag.TIMED_OUT
    | DevelopmentSupervisorFlag.PRIMARY_REAPED
    | DevelopmentSupervisorFlag.ALL_DESCENDANTS_REAPED
    | DevelopmentSupervisorFlag.SOLE_PID1
    | DevelopmentSupervisorFlag.TERMINATION_SIGNAL_RECEIVED
)


def _plain_int_in_range(value: object, minimum: int, maximum: int, label: str) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise DevelopmentSupervisorProtocolError(
            f"{label} must be a plain integer in [{minimum}, {maximum}]"
        )
    return value


def _exact_bytes(value: object, length: int, label: str) -> bytes:
    if type(value) is not bytes or len(value) != length:
        raise DevelopmentSupervisorProtocolError(
            f"{label} must be exactly {length} bytes"
        )
    return value


def _scenario(value: object, label: str = "scenario") -> DevelopmentSupervisorScenario:
    if type(value) is not DevelopmentSupervisorScenario:
        raise DevelopmentSupervisorProtocolError(
            f"{label} must be an exact DevelopmentSupervisorScenario"
        )
    return value


def _outcome(value: object) -> DevelopmentSupervisorOutcome:
    if type(value) is not DevelopmentSupervisorOutcome:
        raise DevelopmentSupervisorProtocolError(
            "outcome must be an exact DevelopmentSupervisorOutcome"
        )
    return value


def _flags(value: object) -> DevelopmentSupervisorFlag:
    if type(value) is not DevelopmentSupervisorFlag:
        raise DevelopmentSupervisorProtocolError(
            "flags must be an exact DevelopmentSupervisorFlag"
        )
    if int(value) & ~int(DEVELOPMENT_SUPERVISOR_KNOWN_FLAGS):
        raise DevelopmentSupervisorProtocolError("flags contain an unknown bit")
    return value


def _canonical_record_bytes(record: dict[str, object]) -> bytes:
    return json.dumps(
        record,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class DevelopmentSupervisorRequest:
    """One exact candidate-free supervisor canary request."""

    scenario: DevelopmentSupervisorScenario
    timeout_ms: int
    stdout_cap: int
    stderr_cap: int
    nonce: bytes

    def __post_init__(self) -> None:
        _scenario(self.scenario)
        _plain_int_in_range(
            self.timeout_ms,
            DEVELOPMENT_SUPERVISOR_MINIMUM_TIMEOUT_MS,
            DEVELOPMENT_SUPERVISOR_MAXIMUM_TIMEOUT_MS,
            "timeout_ms",
        )
        _plain_int_in_range(
            self.stdout_cap,
            1,
            DEVELOPMENT_SUPERVISOR_MAXIMUM_STREAM_CAP_BYTES,
            "stdout_cap",
        )
        _plain_int_in_range(
            self.stderr_cap,
            1,
            DEVELOPMENT_SUPERVISOR_MAXIMUM_STREAM_CAP_BYTES,
            "stderr_cap",
        )
        nonce = _exact_bytes(self.nonce, 32, "nonce")
        if nonce == _ZERO_NONCE:
            raise DevelopmentSupervisorProtocolError("nonce must not be all zero")

    @property
    def request_sha256(self) -> bytes:
        return sha256(encode_development_supervisor_request(self)).digest()

    def to_record(self) -> dict[str, object]:
        return development_supervisor_request_record(self)

    def canonical_record_bytes(self) -> bytes:
        return canonical_development_supervisor_request_record_bytes(self)


@dataclass(frozen=True, slots=True)
class DevelopmentSupervisorResult:
    """A structurally and semantically validated supervisor result."""

    scenario: DevelopmentSupervisorScenario
    outcome: DevelopmentSupervisorOutcome
    child_exit_code: int
    child_signal: int
    flags: DevelopmentSupervisorFlag
    stdout_observed: int
    stderr_observed: int
    descendants_reaped: int
    user_cpu_usec: int
    sys_cpu_usec: int
    wall_usec: int
    request_sha256: bytes
    stdout_sha256: bytes
    stderr_sha256: bytes
    nonce: bytes
    result_sha256: bytes

    def __post_init__(self) -> None:
        _scenario(self.scenario)
        _outcome(self.outcome)
        _plain_int_in_range(self.child_exit_code, _I32_MIN, _I32_MAX, "child_exit_code")
        _plain_int_in_range(self.child_signal, 0, _U32_MAX, "child_signal")
        _flags(self.flags)
        _plain_int_in_range(self.stdout_observed, 0, _U64_MAX, "stdout_observed")
        _plain_int_in_range(self.stderr_observed, 0, _U64_MAX, "stderr_observed")
        _plain_int_in_range(self.descendants_reaped, 0, _U32_MAX, "descendants_reaped")
        _plain_int_in_range(self.user_cpu_usec, 0, _U64_MAX, "user_cpu_usec")
        _plain_int_in_range(self.sys_cpu_usec, 0, _U64_MAX, "sys_cpu_usec")
        _plain_int_in_range(self.wall_usec, 0, _U64_MAX, "wall_usec")
        _exact_bytes(self.request_sha256, 32, "request_sha256")
        _exact_bytes(self.stdout_sha256, 32, "stdout_sha256")
        _exact_bytes(self.stderr_sha256, 32, "stderr_sha256")
        nonce = _exact_bytes(self.nonce, 32, "nonce")
        if nonce == _ZERO_NONCE:
            raise DevelopmentSupervisorProtocolError("result nonce must not be all zero")
        declared_result_sha256 = _exact_bytes(
            self.result_sha256, 32, "result_sha256"
        )
        if sha256(_encode_result_prefix(self)).digest() != declared_result_sha256:
            raise DevelopmentSupervisorProtocolError(
                "result_sha256 does not hash the exact first 224 result bytes"
            )

    def to_record(self) -> dict[str, object]:
        return development_supervisor_result_record(self)

    def canonical_record_bytes(self) -> bytes:
        return canonical_development_supervisor_result_record_bytes(self)


def encode_development_supervisor_request(
    request: DevelopmentSupervisorRequest,
) -> bytes:
    """Encode one request into the exact 64-byte little-endian frame."""

    if type(request) is not DevelopmentSupervisorRequest:
        raise DevelopmentSupervisorProtocolError(
            "request must be exact DevelopmentSupervisorRequest"
        )
    request.__post_init__()
    frame = bytearray(DEVELOPMENT_SUPERVISOR_REQUEST_BYTES)
    frame[0:8] = DEVELOPMENT_SUPERVISOR_REQUEST_MAGIC
    struct.pack_into(
        "<IIIIII",
        frame,
        8,
        DEVELOPMENT_SUPERVISOR_PROTOCOL_VERSION,
        int(request.scenario),
        request.timeout_ms,
        request.stdout_cap,
        request.stderr_cap,
        0,
    )
    frame[32:64] = request.nonce
    return bytes(frame)


def _decode_scenario(code: int) -> DevelopmentSupervisorScenario:
    try:
        scenario = DevelopmentSupervisorScenario(code)
    except ValueError as exc:
        raise DevelopmentSupervisorProtocolError(
            f"result scenario code {code} is unknown"
        ) from exc
    if type(scenario) is not DevelopmentSupervisorScenario:
        raise DevelopmentSupervisorProtocolError("decoded result scenario is invalid")
    return scenario


def _decode_outcome(code: int) -> DevelopmentSupervisorOutcome:
    try:
        outcome = DevelopmentSupervisorOutcome(code)
    except ValueError as exc:
        raise DevelopmentSupervisorProtocolError(
            f"result outcome code {code} is unknown"
        ) from exc
    if type(outcome) is not DevelopmentSupervisorOutcome:
        raise DevelopmentSupervisorProtocolError("decoded result outcome is invalid")
    return outcome


def _decode_flags(bits: int) -> DevelopmentSupervisorFlag:
    if bits & ~int(DEVELOPMENT_SUPERVISOR_KNOWN_FLAGS):
        raise DevelopmentSupervisorProtocolError("result flags contain an unknown bit")
    return DevelopmentSupervisorFlag(bits)


def _has_flag(flags: DevelopmentSupervisorFlag, flag: DevelopmentSupervisorFlag) -> bool:
    return bool(flags & flag)


def _validate_child_status(result: DevelopmentSupervisorResult) -> None:
    primary_reaped = _has_flag(
        result.flags, DevelopmentSupervisorFlag.PRIMARY_REAPED
    )
    if primary_reaped:
        if result.descendants_reaped < 1:
            raise DevelopmentSupervisorProtocolError(
                "primary_reaped requires descendants_reaped >= 1"
            )
        exited = 0 <= result.child_exit_code <= 255 and result.child_signal == 0
        signaled = result.child_exit_code == -1 and result.child_signal > 0
        if not (exited or signaled):
            raise DevelopmentSupervisorProtocolError(
                "reaped primary child has an invalid exit-code/signal pair"
            )
    elif result.child_exit_code != -1 or result.child_signal != 0:
        raise DevelopmentSupervisorProtocolError(
            "unreaped primary child must use exit_code=-1 and signal=0"
        )


def _validate_result_semantics(
    result: DevelopmentSupervisorResult,
    request: DevelopmentSupervisorRequest,
) -> None:
    flags = result.flags
    if not _has_flag(flags, DevelopmentSupervisorFlag.REQUEST_VALIDATED):
        raise DevelopmentSupervisorProtocolError(
            "result does not report request validation"
        )
    if _has_flag(flags, DevelopmentSupervisorFlag.SOLE_PID1) and not _has_flag(
        flags, DevelopmentSupervisorFlag.PID1_VERIFIED
    ):
        raise DevelopmentSupervisorProtocolError(
            "sole_pid1 requires pid1_verified"
        )
    if _has_flag(
        flags, DevelopmentSupervisorFlag.ALL_DESCENDANTS_REAPED
    ) and not _has_flag(flags, DevelopmentSupervisorFlag.PRIMARY_REAPED):
        raise DevelopmentSupervisorProtocolError(
            "all_descendants_reaped requires primary_reaped"
        )

    _validate_child_status(result)

    stdout_overflow = _has_flag(flags, DevelopmentSupervisorFlag.STDOUT_OVERFLOW)
    stderr_overflow = _has_flag(flags, DevelopmentSupervisorFlag.STDERR_OVERFLOW)
    timed_out = _has_flag(flags, DevelopmentSupervisorFlag.TIMED_OUT)
    if stdout_overflow != (result.stdout_observed > request.stdout_cap):
        raise DevelopmentSupervisorProtocolError(
            "stdout overflow flag disagrees with the request cap"
        )
    if stderr_overflow != (result.stderr_observed > request.stderr_cap):
        raise DevelopmentSupervisorProtocolError(
            "stderr overflow flag disagrees with the request cap"
        )

    incident_count = int(stdout_overflow) + int(stderr_overflow) + int(timed_out)
    outcome = result.outcome
    if outcome is DevelopmentSupervisorOutcome.NORMAL:
        if (
            result.child_exit_code != 0
            or result.child_signal != 0
            or incident_count != 0
            or not _has_flag(flags, DevelopmentSupervisorFlag.PRIMARY_REAPED)
        ):
            raise DevelopmentSupervisorProtocolError(
                "normal outcome has inconsistent child status or incident flags"
            )
    elif outcome is DevelopmentSupervisorOutcome.NONZERO:
        if (
            result.child_exit_code <= 0
            or result.child_signal != 0
            or incident_count != 0
            or not _has_flag(flags, DevelopmentSupervisorFlag.PRIMARY_REAPED)
        ):
            raise DevelopmentSupervisorProtocolError(
                "nonzero outcome has inconsistent child status or incident flags"
            )
    elif outcome is DevelopmentSupervisorOutcome.SIGNAL:
        if (
            result.child_exit_code != -1
            or result.child_signal == 0
            or incident_count != 0
            or not _has_flag(flags, DevelopmentSupervisorFlag.PRIMARY_REAPED)
        ):
            raise DevelopmentSupervisorProtocolError(
                "signal outcome has inconsistent child status or incident flags"
            )
    elif outcome is DevelopmentSupervisorOutcome.WALL_TIMEOUT:
        if not timed_out or stdout_overflow or stderr_overflow:
            raise DevelopmentSupervisorProtocolError(
                "wall_timeout outcome requires only the timed_out incident flag"
            )
    elif outcome is DevelopmentSupervisorOutcome.STDOUT_OVERFLOW:
        if not stdout_overflow or stderr_overflow or timed_out:
            raise DevelopmentSupervisorProtocolError(
                "stdout_overflow outcome has inconsistent incident flags"
            )
    elif outcome is DevelopmentSupervisorOutcome.STDERR_OVERFLOW:
        if not stderr_overflow or stdout_overflow or timed_out:
            raise DevelopmentSupervisorProtocolError(
                "stderr_overflow outcome has inconsistent incident flags"
            )
    elif outcome is DevelopmentSupervisorOutcome.SUPERVISOR_ERROR:
        if incident_count != 0:
            raise DevelopmentSupervisorProtocolError(
                "supervisor_error cannot relabel a timeout or stream overflow"
            )
    else:  # pragma: no cover - exact enum validation makes this unreachable
        raise DevelopmentSupervisorProtocolError("unsupported result outcome")


def validate_development_supervisor_result_binding(
    result: DevelopmentSupervisorResult,
    *,
    request: DevelopmentSupervisorRequest,
) -> None:
    """Validate a typed result against the exact request it answers.

    This is required when validating persisted typed evidence.  Parsing an
    original frame already performs the same checks, but a dataclass can also
    be reconstructed independently of that parser and therefore must never be
    trusted on its self-digest alone.
    """

    if type(result) is not DevelopmentSupervisorResult:
        raise DevelopmentSupervisorProtocolError(
            "result must be exact DevelopmentSupervisorResult"
        )
    if type(request) is not DevelopmentSupervisorRequest:
        raise DevelopmentSupervisorProtocolError(
            "request must be exact DevelopmentSupervisorRequest"
        )
    request.__post_init__()
    result.__post_init__()
    if result.scenario is not request.scenario:
        raise DevelopmentSupervisorProtocolError(
            "typed result scenario does not bind the exact request"
        )
    expected_request_sha256 = sha256(
        encode_development_supervisor_request(request)
    ).digest()
    if result.request_sha256 != expected_request_sha256:
        raise DevelopmentSupervisorProtocolError(
            "typed result request_sha256 does not bind the exact request"
        )
    if result.nonce != request.nonce:
        raise DevelopmentSupervisorProtocolError(
            "typed result nonce does not bind the exact request"
        )
    _validate_result_semantics(result, request)


def _encode_result_prefix(result: DevelopmentSupervisorResult) -> bytes:
    prefix = bytearray(DEVELOPMENT_SUPERVISOR_RESULT_HASHED_PREFIX_BYTES)
    prefix[0:8] = DEVELOPMENT_SUPERVISOR_RESULT_MAGIC
    struct.pack_into(
        "<IIIiII",
        prefix,
        8,
        DEVELOPMENT_SUPERVISOR_PROTOCOL_VERSION,
        int(result.scenario),
        int(result.outcome),
        result.child_exit_code,
        result.child_signal,
        int(result.flags),
    )
    struct.pack_into(
        "<QQIIQQQ",
        prefix,
        32,
        result.stdout_observed,
        result.stderr_observed,
        result.descendants_reaped,
        0,
        result.user_cpu_usec,
        result.sys_cpu_usec,
        result.wall_usec,
    )
    prefix[80:96] = _ZERO_RESULT_RESERVED
    prefix[96:128] = result.request_sha256
    prefix[128:160] = result.stdout_sha256
    prefix[160:192] = result.stderr_sha256
    prefix[192:224] = result.nonce
    return bytes(prefix)


def parse_development_supervisor_result(
    frame: bytes,
    *,
    request: DevelopmentSupervisorRequest,
) -> DevelopmentSupervisorResult:
    """Parse one exact result frame and bind it to ``request``.

    The result digest, request digest, nonce, scenario, reserved bytes, known
    flag mask, capture limits, child status, and terminal-outcome semantics all
    validate before a typed result is returned.
    """

    if type(frame) is not bytes:
        raise DevelopmentSupervisorProtocolError("result frame must be exact bytes")
    if len(frame) != DEVELOPMENT_SUPERVISOR_RESULT_BYTES:
        raise DevelopmentSupervisorProtocolError(
            f"result frame must be exactly {DEVELOPMENT_SUPERVISOR_RESULT_BYTES} bytes"
        )
    if type(request) is not DevelopmentSupervisorRequest:
        raise DevelopmentSupervisorProtocolError(
            "request must be exact DevelopmentSupervisorRequest"
        )
    request.__post_init__()
    if frame[0:8] != DEVELOPMENT_SUPERVISOR_RESULT_MAGIC:
        raise DevelopmentSupervisorProtocolError("result magic is invalid")
    if frame[80:96] != _ZERO_RESULT_RESERVED:
        raise DevelopmentSupervisorProtocolError("result reserved16 bytes are not zero")
    if frame[224:256] != sha256(frame[:224]).digest():
        raise DevelopmentSupervisorProtocolError("result_sha256 is invalid")

    version, scenario_code, outcome_code, child_exit_code, child_signal, flag_bits = (
        struct.unpack_from("<IIIiII", frame, 8)
    )
    if version != DEVELOPMENT_SUPERVISOR_PROTOCOL_VERSION:
        raise DevelopmentSupervisorProtocolError("result version is invalid")
    scenario = _decode_scenario(scenario_code)
    if scenario is not request.scenario:
        raise DevelopmentSupervisorProtocolError(
            "result scenario does not match the exact request"
        )
    outcome = _decode_outcome(outcome_code)
    flags = _decode_flags(flag_bits)
    (
        stdout_observed,
        stderr_observed,
        descendants_reaped,
        reserved_u32,
        user_cpu_usec,
        sys_cpu_usec,
        wall_usec,
    ) = struct.unpack_from("<QQIIQQQ", frame, 32)
    if reserved_u32 != 0 or frame[52:56] != _ZERO_U32:
        raise DevelopmentSupervisorProtocolError("result reserved u32 is not zero")

    expected_request_sha256 = sha256(
        encode_development_supervisor_request(request)
    ).digest()
    if frame[96:128] != expected_request_sha256:
        raise DevelopmentSupervisorProtocolError(
            "result request_sha256 does not bind the exact request"
        )
    if frame[192:224] != request.nonce:
        raise DevelopmentSupervisorProtocolError(
            "result nonce does not bind the exact request"
        )

    result = DevelopmentSupervisorResult(
        scenario=scenario,
        outcome=outcome,
        child_exit_code=child_exit_code,
        child_signal=child_signal,
        flags=flags,
        stdout_observed=stdout_observed,
        stderr_observed=stderr_observed,
        descendants_reaped=descendants_reaped,
        user_cpu_usec=user_cpu_usec,
        sys_cpu_usec=sys_cpu_usec,
        wall_usec=wall_usec,
        request_sha256=frame[96:128],
        stdout_sha256=frame[128:160],
        stderr_sha256=frame[160:192],
        nonce=frame[192:224],
        result_sha256=frame[224:256],
    )
    validate_development_supervisor_result_binding(result, request=request)
    return result


def development_supervisor_request_record(
    request: DevelopmentSupervisorRequest,
) -> dict[str, object]:
    """Return the canonical, descriptor-free request audit record."""

    if type(request) is not DevelopmentSupervisorRequest:
        raise DevelopmentSupervisorProtocolError(
            "request must be exact DevelopmentSupervisorRequest"
        )
    frame = encode_development_supervisor_request(request)
    return {
        "record_type": "cbds-development-supervisor-canary-request",
        "protocol_version": DEVELOPMENT_SUPERVISOR_PROTOCOL_VERSION,
        "wire_magic": DEVELOPMENT_SUPERVISOR_REQUEST_MAGIC.decode("ascii"),
        "wire_bytes": DEVELOPMENT_SUPERVISOR_REQUEST_BYTES,
        "scenario": request.scenario.name.lower(),
        "scenario_code": int(request.scenario),
        "timeout_ms": request.timeout_ms,
        "stdout_cap": request.stdout_cap,
        "stderr_cap": request.stderr_cap,
        "nonce_hex": request.nonce.hex(),
        "request_sha256": sha256(frame).hexdigest(),
        "candidate_program_present": False,
        "candidate_execution_authorized": False,
        "scored_evaluation_eligible": False,
        "claim_pipeline_eligible": False,
    }


def development_supervisor_result_record(
    result: DevelopmentSupervisorResult,
) -> dict[str, object]:
    """Return the canonical, descriptor-free parsed-result audit record."""

    if type(result) is not DevelopmentSupervisorResult:
        raise DevelopmentSupervisorProtocolError(
            "result must be exact DevelopmentSupervisorResult"
        )
    result.__post_init__()
    flag_names = [
        flag.name.lower()
        for flag in DevelopmentSupervisorFlag
        if _has_flag(result.flags, flag)
    ]
    return {
        "record_type": "cbds-development-supervisor-canary-result",
        "protocol_version": DEVELOPMENT_SUPERVISOR_PROTOCOL_VERSION,
        "wire_magic": DEVELOPMENT_SUPERVISOR_RESULT_MAGIC.decode("ascii"),
        "wire_bytes": DEVELOPMENT_SUPERVISOR_RESULT_BYTES,
        "scenario": result.scenario.name.lower(),
        "scenario_code": int(result.scenario),
        "outcome": result.outcome.name.lower(),
        "outcome_code": int(result.outcome),
        "child_exit_code": result.child_exit_code,
        "child_signal": result.child_signal,
        "flags": flag_names,
        "flags_bits": int(result.flags),
        "stdout_observed": result.stdout_observed,
        "stderr_observed": result.stderr_observed,
        "descendants_reaped": result.descendants_reaped,
        "user_cpu_usec": result.user_cpu_usec,
        "sys_cpu_usec": result.sys_cpu_usec,
        "wall_usec": result.wall_usec,
        "request_sha256": result.request_sha256.hex(),
        "stdout_sha256": result.stdout_sha256.hex(),
        "stderr_sha256": result.stderr_sha256.hex(),
        "nonce_hex": result.nonce.hex(),
        "result_sha256": result.result_sha256.hex(),
        "candidate_program_present": False,
        "candidate_execution_authorized": False,
        "scored_evaluation_eligible": False,
        "claim_pipeline_eligible": False,
    }


def canonical_development_supervisor_request_record_bytes(
    request: DevelopmentSupervisorRequest,
) -> bytes:
    """Return deterministic UTF-8 JSON bytes for a request audit record."""

    return _canonical_record_bytes(development_supervisor_request_record(request))


def canonical_development_supervisor_result_record_bytes(
    result: DevelopmentSupervisorResult,
) -> bytes:
    """Return deterministic UTF-8 JSON bytes for a parsed result record."""

    return _canonical_record_bytes(development_supervisor_result_record(result))


def _encode_development_supervisor_result_for_tests(
    request: DevelopmentSupervisorRequest,
    *,
    outcome: DevelopmentSupervisorOutcome = DevelopmentSupervisorOutcome.NORMAL,
    child_exit_code: int = 0,
    child_signal: int = 0,
    flags: DevelopmentSupervisorFlag = (
        DevelopmentSupervisorFlag.REQUEST_VALIDATED
        | DevelopmentSupervisorFlag.PRIMARY_REAPED
        | DevelopmentSupervisorFlag.ALL_DESCENDANTS_REAPED
    ),
    stdout_observed: int = 0,
    stderr_observed: int = 0,
    descendants_reaped: int = 1,
    user_cpu_usec: int = 0,
    sys_cpu_usec: int = 0,
    wall_usec: int = 0,
    stdout_sha256: bytes = sha256(b"").digest(),
    stderr_sha256: bytes = sha256(b"").digest(),
) -> bytes:
    """Build a result frame solely for protocol tests.

    A production supervisor must implement this layout independently; exposing
    this helper publicly would let controller code fabricate supervisor
    evidence.  The function therefore remains private and is intentionally
    named as test-only.
    """

    if type(request) is not DevelopmentSupervisorRequest:
        raise DevelopmentSupervisorProtocolError(
            "request must be exact DevelopmentSupervisorRequest"
        )
    request.__post_init__()
    _outcome(outcome)
    _flags(flags)
    _plain_int_in_range(child_exit_code, _I32_MIN, _I32_MAX, "child_exit_code")
    _plain_int_in_range(child_signal, 0, _U32_MAX, "child_signal")
    _plain_int_in_range(stdout_observed, 0, _U64_MAX, "stdout_observed")
    _plain_int_in_range(stderr_observed, 0, _U64_MAX, "stderr_observed")
    _plain_int_in_range(descendants_reaped, 0, _U32_MAX, "descendants_reaped")
    _plain_int_in_range(user_cpu_usec, 0, _U64_MAX, "user_cpu_usec")
    _plain_int_in_range(sys_cpu_usec, 0, _U64_MAX, "sys_cpu_usec")
    _plain_int_in_range(wall_usec, 0, _U64_MAX, "wall_usec")
    _exact_bytes(stdout_sha256, 32, "stdout_sha256")
    _exact_bytes(stderr_sha256, 32, "stderr_sha256")

    # Create the prefix directly so the immutable result can verify its own
    # final digest when it is parsed.
    prefix = bytearray(DEVELOPMENT_SUPERVISOR_RESULT_HASHED_PREFIX_BYTES)
    prefix[0:8] = DEVELOPMENT_SUPERVISOR_RESULT_MAGIC
    struct.pack_into(
        "<IIIiII",
        prefix,
        8,
        DEVELOPMENT_SUPERVISOR_PROTOCOL_VERSION,
        int(request.scenario),
        int(outcome),
        child_exit_code,
        child_signal,
        int(flags),
    )
    struct.pack_into(
        "<QQIIQQQ",
        prefix,
        32,
        stdout_observed,
        stderr_observed,
        descendants_reaped,
        0,
        user_cpu_usec,
        sys_cpu_usec,
        wall_usec,
    )
    prefix[80:96] = _ZERO_RESULT_RESERVED
    prefix[96:128] = sha256(encode_development_supervisor_request(request)).digest()
    prefix[128:160] = stdout_sha256
    prefix[160:192] = stderr_sha256
    prefix[192:224] = request.nonce
    frame = bytes(prefix) + sha256(prefix).digest()
    if len(frame) != DEVELOPMENT_SUPERVISOR_RESULT_BYTES:
        raise DevelopmentSupervisorProtocolError(
            "internal test-only result encoder produced the wrong size"
        )
    return frame


__all__ = [
    "DEVELOPMENT_SUPERVISOR_KNOWN_FLAGS",
    "DEVELOPMENT_SUPERVISOR_MAXIMUM_STREAM_CAP_BYTES",
    "DEVELOPMENT_SUPERVISOR_MAXIMUM_TIMEOUT_MS",
    "DEVELOPMENT_SUPERVISOR_MINIMUM_TIMEOUT_MS",
    "DEVELOPMENT_SUPERVISOR_PROTOCOL_VERSION",
    "DEVELOPMENT_SUPERVISOR_REQUEST_BYTES",
    "DEVELOPMENT_SUPERVISOR_REQUEST_MAGIC",
    "DEVELOPMENT_SUPERVISOR_RESULT_BYTES",
    "DEVELOPMENT_SUPERVISOR_RESULT_HASHED_PREFIX_BYTES",
    "DEVELOPMENT_SUPERVISOR_RESULT_MAGIC",
    "DevelopmentSupervisorFlag",
    "DevelopmentSupervisorOutcome",
    "DevelopmentSupervisorProtocolError",
    "DevelopmentSupervisorRequest",
    "DevelopmentSupervisorResult",
    "DevelopmentSupervisorScenario",
    "canonical_development_supervisor_request_record_bytes",
    "canonical_development_supervisor_result_record_bytes",
    "development_supervisor_request_record",
    "development_supervisor_result_record",
    "encode_development_supervisor_request",
    "parse_development_supervisor_result",
    "validate_development_supervisor_result_binding",
]
