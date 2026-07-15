from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError, replace
from hashlib import sha256
import inspect
import json
from pathlib import Path
import struct
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import cbds.development_supervisor_protocol as protocol  # noqa: E402
from cbds.development_supervisor_protocol import (  # noqa: E402
    DEVELOPMENT_SUPERVISOR_KNOWN_FLAGS,
    DEVELOPMENT_SUPERVISOR_MAXIMUM_STREAM_CAP_BYTES,
    DEVELOPMENT_SUPERVISOR_MAXIMUM_TIMEOUT_MS,
    DEVELOPMENT_SUPERVISOR_MINIMUM_TIMEOUT_MS,
    DEVELOPMENT_SUPERVISOR_PROTOCOL_VERSION,
    DEVELOPMENT_SUPERVISOR_REQUEST_BYTES,
    DEVELOPMENT_SUPERVISOR_REQUEST_MAGIC,
    DEVELOPMENT_SUPERVISOR_RESULT_BYTES,
    DEVELOPMENT_SUPERVISOR_RESULT_HASHED_PREFIX_BYTES,
    DEVELOPMENT_SUPERVISOR_RESULT_MAGIC,
    DevelopmentSupervisorFlag,
    DevelopmentSupervisorOutcome,
    DevelopmentSupervisorProtocolError,
    DevelopmentSupervisorRequest,
    DevelopmentSupervisorScenario,
    canonical_development_supervisor_request_record_bytes,
    canonical_development_supervisor_result_record_bytes,
    development_supervisor_request_record,
    development_supervisor_result_record,
    encode_development_supervisor_request,
    parse_development_supervisor_result,
    validate_development_supervisor_result_binding,
)


NONCE = bytes(range(1, 33))
EMPTY_SHA256 = sha256(b"").digest()
BASE_SUCCESS_FLAGS = (
    DevelopmentSupervisorFlag.REQUEST_VALIDATED
    | DevelopmentSupervisorFlag.PRIMARY_REAPED
    | DevelopmentSupervisorFlag.ALL_DESCENDANTS_REAPED
)


def make_request(
    scenario: DevelopmentSupervisorScenario = DevelopmentSupervisorScenario.NORMAL,
    *,
    timeout_ms: int = 250,
    stdout_cap: int = 4096,
    stderr_cap: int = 8192,
    nonce: bytes = NONCE,
) -> DevelopmentSupervisorRequest:
    return DevelopmentSupervisorRequest(
        scenario=scenario,
        timeout_ms=timeout_ms,
        stdout_cap=stdout_cap,
        stderr_cap=stderr_cap,
        nonce=nonce,
    )


def encode_result(
    request: DevelopmentSupervisorRequest,
    **overrides: object,
) -> bytes:
    values: dict[str, object] = {
        "outcome": DevelopmentSupervisorOutcome.NORMAL,
        "child_exit_code": 0,
        "child_signal": 0,
        "flags": BASE_SUCCESS_FLAGS,
        "stdout_observed": 0,
        "stderr_observed": 0,
        "descendants_reaped": 1,
        "user_cpu_usec": 11,
        "sys_cpu_usec": 12,
        "wall_usec": 13,
        "stdout_sha256": EMPTY_SHA256,
        "stderr_sha256": EMPTY_SHA256,
    }
    values.update(overrides)
    return protocol._encode_development_supervisor_result_for_tests(  # noqa: SLF001
        request,
        **values,  # type: ignore[arg-type]
    )


def reseal(frame: bytes) -> bytes:
    prefix = frame[:DEVELOPMENT_SUPERVISOR_RESULT_HASHED_PREFIX_BYTES]
    if len(prefix) != DEVELOPMENT_SUPERVISOR_RESULT_HASHED_PREFIX_BYTES:
        raise RuntimeError("test frame prefix has the wrong length")
    return prefix + sha256(prefix).digest()


def mutate_bytes(
    frame: bytes,
    offset: int,
    payload: bytes,
    *,
    reseal_digest: bool = True,
) -> bytes:
    changed = bytearray(frame)
    changed[offset : offset + len(payload)] = payload
    result = bytes(changed)
    return reseal(result) if reseal_digest else result


def mutate_u32(frame: bytes, offset: int, value: int) -> bytes:
    return mutate_bytes(frame, offset, struct.pack("<I", value))


def mutate_i32(frame: bytes, offset: int, value: int) -> bytes:
    return mutate_bytes(frame, offset, struct.pack("<i", value))


def mutate_u64(frame: bytes, offset: int, value: int) -> bytes:
    return mutate_bytes(frame, offset, struct.pack("<Q", value))


class SupervisorRequestProtocolTests(unittest.TestCase):
    def test_request_layout_is_exact_little_endian_and_content_bound(self) -> None:
        request = make_request()
        frame = encode_development_supervisor_request(request)

        self.assertIs(type(frame), bytes)
        self.assertEqual(len(frame), DEVELOPMENT_SUPERVISOR_REQUEST_BYTES)
        self.assertEqual(frame[0:8], DEVELOPMENT_SUPERVISOR_REQUEST_MAGIC)
        self.assertEqual(
            struct.unpack_from("<IIIIII", frame, 8),
            (
                DEVELOPMENT_SUPERVISOR_PROTOCOL_VERSION,
                1,
                250,
                4096,
                8192,
                0,
            ),
        )
        self.assertEqual(frame[28:32], b"\0" * 4)
        self.assertEqual(frame[32:64], NONCE)
        self.assertEqual(request.request_sha256, sha256(frame).digest())

    def test_every_frozen_scenario_has_its_exact_wire_code(self) -> None:
        expected = {
            DevelopmentSupervisorScenario.NORMAL: 1,
            DevelopmentSupervisorScenario.DOUBLE_FORK_SETSID: 2,
            DevelopmentSupervisorScenario.ZOMBIE: 3,
            DevelopmentSupervisorScenario.WALL_TIMEOUT: 4,
            DevelopmentSupervisorScenario.STDOUT_FLOOD: 5,
            DevelopmentSupervisorScenario.STDERR_FLOOD: 6,
            DevelopmentSupervisorScenario.CPU_FANOUT: 7,
            DevelopmentSupervisorScenario.FORBIDDEN_SYSCALL: 8,
            DevelopmentSupervisorScenario.RESULT_FRAME_SPOOF: 9,
        }
        self.assertEqual(dict(expected), {item: item.value for item in expected})
        for scenario, code in expected.items():
            with self.subTest(scenario=scenario):
                frame = encode_development_supervisor_request(make_request(scenario))
                self.assertEqual(struct.unpack_from("<I", frame, 12)[0], code)

    def test_request_bounds_are_inclusive(self) -> None:
        for timeout in (
            DEVELOPMENT_SUPERVISOR_MINIMUM_TIMEOUT_MS,
            DEVELOPMENT_SUPERVISOR_MAXIMUM_TIMEOUT_MS,
        ):
            with self.subTest(timeout=timeout):
                self.assertEqual(make_request(timeout_ms=timeout).timeout_ms, timeout)
        for cap in (1, DEVELOPMENT_SUPERVISOR_MAXIMUM_STREAM_CAP_BYTES):
            with self.subTest(cap=cap):
                request = make_request(stdout_cap=cap, stderr_cap=cap)
                self.assertEqual(request.stdout_cap, cap)
                self.assertEqual(request.stderr_cap, cap)

    def test_request_rejects_out_of_range_and_non_plain_integers(self) -> None:
        cases = (
            {"timeout_ms": 9},
            {"timeout_ms": 5001},
            {"timeout_ms": True},
            {"timeout_ms": 10.0},
            {"stdout_cap": 0},
            {"stdout_cap": 1_048_577},
            {"stdout_cap": False},
            {"stderr_cap": 0},
            {"stderr_cap": 1_048_577},
            {"stderr_cap": True},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                with self.assertRaises(DevelopmentSupervisorProtocolError):
                    make_request(**changes)  # type: ignore[arg-type]

    def test_request_requires_exact_enum_and_exact_nonzero_32_byte_nonce(self) -> None:
        with self.assertRaisesRegex(
            DevelopmentSupervisorProtocolError, "exact DevelopmentSupervisorScenario"
        ):
            DevelopmentSupervisorRequest(  # type: ignore[arg-type]
                scenario=1,
                timeout_ms=10,
                stdout_cap=1,
                stderr_cap=1,
                nonce=NONCE,
            )
        for nonce in (
            b"x" * 31,
            b"x" * 33,
            b"\0" * 32,
            bytearray(NONCE),
            memoryview(NONCE),
            "x" * 32,
        ):
            with self.subTest(nonce_type=type(nonce), nonce_length=len(nonce)):
                with self.assertRaises(DevelopmentSupervisorProtocolError):
                    make_request(nonce=nonce)  # type: ignore[arg-type]

        embedded_zero = b"\0" + b"x" * 31
        self.assertEqual(make_request(nonce=embedded_zero).nonce, embedded_zero)

    def test_request_is_immutable_and_encoder_rejects_nonexact_objects(self) -> None:
        request = make_request()
        with self.assertRaises(FrozenInstanceError):
            request.timeout_ms = 999  # type: ignore[misc]
        for value in (object(), {"scenario": 1}, None, True):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    DevelopmentSupervisorProtocolError, "exact DevelopmentSupervisorRequest"
                ):
                    encode_development_supervisor_request(value)  # type: ignore[arg-type]

    def test_request_record_is_canonical_and_permanently_nonauthorizing(self) -> None:
        request = make_request(DevelopmentSupervisorScenario.RESULT_FRAME_SPOOF)
        record = development_supervisor_request_record(request)
        payload = canonical_development_supervisor_request_record_bytes(request)

        self.assertEqual(record, request.to_record())
        self.assertEqual(payload, request.canonical_record_bytes())
        self.assertEqual(json.loads(payload), record)
        self.assertNotIn(b" ", payload)
        self.assertEqual(record["wire_magic"], "CBDSCRQ1")
        self.assertEqual(record["scenario"], "result_frame_spoof")
        self.assertEqual(record["nonce_hex"], NONCE.hex())
        self.assertEqual(
            record["request_sha256"],
            sha256(encode_development_supervisor_request(request)).hexdigest(),
        )
        for field in (
            "candidate_program_present",
            "candidate_execution_authorized",
            "scored_evaluation_eligible",
            "claim_pipeline_eligible",
        ):
            self.assertIs(record[field], False)


class SupervisorResultProtocolTests(unittest.TestCase):
    def test_normal_result_layout_offsets_hashes_and_request_binding(self) -> None:
        request = make_request()
        stdout_digest = sha256(b"fixed stdout").digest()
        stderr_digest = sha256(b"fixed stderr").digest()
        flags = (
            BASE_SUCCESS_FLAGS
            | DevelopmentSupervisorFlag.PID1_VERIFIED
            | DevelopmentSupervisorFlag.NO_NEW_PRIVS
            | DevelopmentSupervisorFlag.DUMPABLE_DISABLED
            | DevelopmentSupervisorFlag.SECCOMP_INSTALLED
            | DevelopmentSupervisorFlag.SOLE_PID1
        )
        frame = encode_result(
            request,
            flags=flags,
            stdout_observed=12,
            stderr_observed=12,
            descendants_reaped=7,
            user_cpu_usec=101,
            sys_cpu_usec=202,
            wall_usec=303,
            stdout_sha256=stdout_digest,
            stderr_sha256=stderr_digest,
        )

        self.assertEqual(len(frame), DEVELOPMENT_SUPERVISOR_RESULT_BYTES)
        self.assertEqual(frame[0:8], DEVELOPMENT_SUPERVISOR_RESULT_MAGIC)
        self.assertEqual(
            struct.unpack_from("<IIIiII", frame, 8),
            (1, 1, 1, 0, 0, int(flags)),
        )
        self.assertEqual(
            struct.unpack_from("<QQIIQQQ", frame, 32),
            (12, 12, 7, 0, 101, 202, 303),
        )
        self.assertEqual(frame[52:56], b"\0" * 4)
        self.assertEqual(frame[80:96], b"\0" * 16)
        self.assertEqual(frame[96:128], request.request_sha256)
        self.assertEqual(frame[128:160], stdout_digest)
        self.assertEqual(frame[160:192], stderr_digest)
        self.assertEqual(frame[192:224], NONCE)
        self.assertEqual(frame[224:256], sha256(frame[:224]).digest())

        result = parse_development_supervisor_result(frame, request=request)
        self.assertIs(result.scenario, DevelopmentSupervisorScenario.NORMAL)
        self.assertIs(result.outcome, DevelopmentSupervisorOutcome.NORMAL)
        self.assertEqual(result.flags, flags)
        self.assertEqual(result.request_sha256, request.request_sha256)
        self.assertEqual(result.result_sha256, sha256(frame[:224]).digest())
        self.assertEqual(result.descendants_reaped, 7)

    def test_all_scenarios_round_trip_but_remain_request_bound(self) -> None:
        for scenario in DevelopmentSupervisorScenario:
            with self.subTest(scenario=scenario):
                request = make_request(scenario)
                frame = encode_result(request)
                result = parse_development_supervisor_result(frame, request=request)
                self.assertIs(result.scenario, scenario)

                other_scenario = (
                    DevelopmentSupervisorScenario.NORMAL
                    if scenario is not DevelopmentSupervisorScenario.NORMAL
                    else DevelopmentSupervisorScenario.ZOMBIE
                )
                with self.assertRaisesRegex(
                    DevelopmentSupervisorProtocolError, "scenario"
                ):
                    parse_development_supervisor_result(
                        frame, request=make_request(other_scenario)
                    )

    def test_reconstructed_typed_result_remains_bound_to_its_request(self) -> None:
        original = make_request(nonce=b"a" * 32)
        result = parse_development_supervisor_result(
            encode_result(original),
            request=original,
        )
        validate_development_supervisor_result_binding(result, request=original)
        for changed in (
            make_request(nonce=b"b" * 32),
            make_request(timeout_ms=original.timeout_ms + 1, nonce=b"a" * 32),
        ):
            with self.subTest(changed=changed):
                with self.assertRaisesRegex(
                    DevelopmentSupervisorProtocolError,
                    "request_sha256|nonce",
                ):
                    validate_development_supervisor_result_binding(
                        result,
                        request=changed,
                    )

    def test_every_outcome_has_one_unambiguous_valid_status_shape(self) -> None:
        request = make_request(stdout_cap=8, stderr_cap=9)
        cases = (
            ({}, DevelopmentSupervisorOutcome.NORMAL),
            (
                {
                    "outcome": DevelopmentSupervisorOutcome.NONZERO,
                    "child_exit_code": 7,
                },
                DevelopmentSupervisorOutcome.NONZERO,
            ),
            (
                {
                    "outcome": DevelopmentSupervisorOutcome.SIGNAL,
                    "child_exit_code": -1,
                    "child_signal": 9,
                },
                DevelopmentSupervisorOutcome.SIGNAL,
            ),
            (
                {
                    "outcome": DevelopmentSupervisorOutcome.WALL_TIMEOUT,
                    "child_exit_code": -1,
                    "child_signal": 9,
                    "flags": BASE_SUCCESS_FLAGS | DevelopmentSupervisorFlag.TIMED_OUT,
                },
                DevelopmentSupervisorOutcome.WALL_TIMEOUT,
            ),
            (
                {
                    "outcome": DevelopmentSupervisorOutcome.STDOUT_OVERFLOW,
                    "child_exit_code": -1,
                    "child_signal": 9,
                    "flags": BASE_SUCCESS_FLAGS
                    | DevelopmentSupervisorFlag.STDOUT_OVERFLOW,
                    "stdout_observed": 9,
                },
                DevelopmentSupervisorOutcome.STDOUT_OVERFLOW,
            ),
            (
                {
                    "outcome": DevelopmentSupervisorOutcome.STDERR_OVERFLOW,
                    "child_exit_code": -1,
                    "child_signal": 9,
                    "flags": BASE_SUCCESS_FLAGS
                    | DevelopmentSupervisorFlag.STDERR_OVERFLOW,
                    "stderr_observed": 10,
                },
                DevelopmentSupervisorOutcome.STDERR_OVERFLOW,
            ),
            (
                {
                    "outcome": DevelopmentSupervisorOutcome.SUPERVISOR_ERROR,
                    "child_exit_code": -1,
                    "child_signal": 0,
                    "flags": DevelopmentSupervisorFlag.REQUEST_VALIDATED,
                    "descendants_reaped": 0,
                },
                DevelopmentSupervisorOutcome.SUPERVISOR_ERROR,
            ),
        )
        for arguments, expected in cases:
            with self.subTest(outcome=expected):
                result = parse_development_supervisor_result(
                    encode_result(request, **arguments), request=request
                )
                self.assertIs(result.outcome, expected)

    def test_result_record_is_canonical_complete_and_nonauthorizing(self) -> None:
        request = make_request()
        flags = BASE_SUCCESS_FLAGS | DevelopmentSupervisorFlag.NO_NEW_PRIVS
        result = parse_development_supervisor_result(
            encode_result(request, flags=flags), request=request
        )
        record = development_supervisor_result_record(result)
        payload = canonical_development_supervisor_result_record_bytes(result)

        self.assertEqual(result.to_record(), record)
        self.assertEqual(result.canonical_record_bytes(), payload)
        self.assertEqual(json.loads(payload), record)
        self.assertEqual(record["wire_magic"], "CBDSSRS1")
        self.assertEqual(record["flags_bits"], int(flags))
        self.assertEqual(
            record["flags"],
            ["request_validated", "no_new_privs", "primary_reaped", "all_descendants_reaped"],
        )
        self.assertEqual(record["request_sha256"], request.request_sha256.hex())
        self.assertEqual(record["stdout_sha256"], EMPTY_SHA256.hex())
        self.assertEqual(record["result_sha256"], result.result_sha256.hex())
        for field in (
            "candidate_program_present",
            "candidate_execution_authorized",
            "scored_evaluation_eligible",
            "claim_pipeline_eligible",
        ):
            self.assertIs(record[field], False)

    def test_result_is_immutable_and_rejects_nonexact_replacements(self) -> None:
        request = make_request()
        result = parse_development_supervisor_result(
            encode_result(request), request=request
        )
        with self.assertRaises(FrozenInstanceError):
            result.wall_usec = 99  # type: ignore[misc]
        mutations = (
            {"scenario": 1},
            {"outcome": 1},
            {"flags": int(result.flags)},
            {"stdout_observed": True},
            {"child_signal": False},
            {"request_sha256": bytearray(result.request_sha256)},
            {"nonce": b"\0" * 32},
            {"result_sha256": b"x" * 32},
        )
        for changes in mutations:
            with self.subTest(changes=changes):
                with self.assertRaises(DevelopmentSupervisorProtocolError):
                    replace(result, **changes)


class SupervisorResultAdversarialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.request = make_request()
        self.frame = encode_result(self.request)

    def assert_rejected(self, frame: bytes, pattern: str) -> None:
        with self.assertRaisesRegex(DevelopmentSupervisorProtocolError, pattern):
            parse_development_supervisor_result(frame, request=self.request)

    def test_frame_requires_exact_bytes_and_exact_length_without_stream_search(self) -> None:
        for value in (bytearray(self.frame), memoryview(self.frame), "x" * 256, None):
            with self.subTest(value_type=type(value)):
                with self.assertRaisesRegex(
                    DevelopmentSupervisorProtocolError, "exact bytes"
                ):
                    parse_development_supervisor_result(  # type: ignore[arg-type]
                        value, request=self.request
                    )
        for frame in (
            self.frame[:-1],
            self.frame + b"x",
            b"candidate-prefix" + self.frame,
            self.frame + self.frame,
        ):
            with self.subTest(length=len(frame)):
                self.assert_rejected(frame, "exactly 256")

    def test_magic_version_reserved_and_result_digest_mutations_fail(self) -> None:
        self.assert_rejected(
            mutate_bytes(self.frame, 0, b"BADMAGIC"), "magic"
        )
        self.assert_rejected(mutate_u32(self.frame, 8, 2), "version")
        self.assert_rejected(mutate_u32(self.frame, 52, 1), "reserved u32")
        self.assert_rejected(
            mutate_bytes(self.frame, 80, b"x", reseal_digest=True), "reserved16"
        )
        bad_digest = mutate_bytes(
            self.frame, 224, b"x", reseal_digest=False
        )
        self.assert_rejected(bad_digest, "result_sha256")

    def test_unknown_scenario_outcome_and_flag_bits_fail_even_when_resealed(self) -> None:
        self.assert_rejected(mutate_u32(self.frame, 12, 0), "scenario code")
        self.assert_rejected(mutate_u32(self.frame, 12, 10), "scenario code")
        self.assert_rejected(mutate_u32(self.frame, 16, 0), "outcome code")
        self.assert_rejected(mutate_u32(self.frame, 16, 8), "outcome code")
        self.assert_rejected(
            mutate_u32(self.frame, 28, 1 << 12), "unknown bit"
        )
        self.assertEqual(int(DEVELOPMENT_SUPERVISOR_KNOWN_FLAGS), (1 << 12) - 1)

    def test_request_digest_nonce_and_scenario_prevent_result_frame_spoofing(self) -> None:
        changed_request_hash = mutate_bytes(self.frame, 96, b"x" * 32)
        self.assert_rejected(changed_request_hash, "request_sha256")

        changed_nonce = mutate_bytes(self.frame, 192, b"y" * 32)
        self.assert_rejected(changed_nonce, "nonce")

        spoof_request = make_request(
            timeout_ms=self.request.timeout_ms + 1,
            nonce=b"z" * 32,
        )
        with self.assertRaisesRegex(
            DevelopmentSupervisorProtocolError, "request_sha256|nonce"
        ):
            parse_development_supervisor_result(
                self.frame, request=spoof_request
            )

        with self.assertRaisesRegex(
            DevelopmentSupervisorProtocolError, "exact DevelopmentSupervisorRequest"
        ):
            parse_development_supervisor_result(  # type: ignore[arg-type]
                self.frame, request={"nonce": NONCE}
            )

    def test_request_validated_pid1_and_reaping_flag_dependencies_are_strict(self) -> None:
        no_request = encode_result(
            self.request,
            flags=(
                DevelopmentSupervisorFlag.PRIMARY_REAPED
                | DevelopmentSupervisorFlag.ALL_DESCENDANTS_REAPED
            ),
        )
        self.assert_rejected(no_request, "request validation")

        sole_without_pid1 = encode_result(
            self.request,
            flags=BASE_SUCCESS_FLAGS | DevelopmentSupervisorFlag.SOLE_PID1,
        )
        self.assert_rejected(sole_without_pid1, "sole_pid1")

        all_without_primary = encode_result(
            self.request,
            outcome=DevelopmentSupervisorOutcome.SUPERVISOR_ERROR,
            child_exit_code=-1,
            flags=(
                DevelopmentSupervisorFlag.REQUEST_VALIDATED
                | DevelopmentSupervisorFlag.ALL_DESCENDANTS_REAPED
            ),
        )
        self.assert_rejected(all_without_primary, "primary_reaped")

    def test_child_status_requires_one_exact_reaped_or_unreaped_shape(self) -> None:
        invalid_frames = (
            (
                encode_result(self.request, child_exit_code=-1, child_signal=0),
                "reaped primary",
            ),
            (
                encode_result(self.request, child_exit_code=1, child_signal=9),
                "reaped primary",
            ),
            (
                encode_result(
                    self.request,
                    outcome=DevelopmentSupervisorOutcome.SUPERVISOR_ERROR,
                    child_exit_code=0,
                    child_signal=0,
                    flags=DevelopmentSupervisorFlag.REQUEST_VALIDATED,
                ),
                "unreaped primary",
            ),
        )
        for frame, pattern in invalid_frames:
            with self.subTest(pattern=pattern):
                self.assert_rejected(frame, pattern)

    def test_primary_reaped_requires_counting_at_least_the_primary_child(self) -> None:
        missing_count = encode_result(self.request, descendants_reaped=0)
        self.assert_rejected(missing_count, "descendants_reaped >= 1")

        result = parse_development_supervisor_result(
            encode_result(self.request, descendants_reaped=1),
            request=self.request,
        )
        self.assertEqual(result.descendants_reaped, 1)

    def test_reaped_normal_exit_code_is_exactly_unsigned_eight_bit(self) -> None:
        accepted = parse_development_supervisor_result(
            encode_result(
                self.request,
                outcome=DevelopmentSupervisorOutcome.NONZERO,
                child_exit_code=255,
            ),
            request=self.request,
        )
        self.assertEqual(accepted.child_exit_code, 255)

        for exit_code in (-2, 256, 2**31 - 1):
            with self.subTest(exit_code=exit_code):
                invalid = encode_result(
                    self.request,
                    outcome=DevelopmentSupervisorOutcome.NONZERO,
                    child_exit_code=exit_code,
                )
                self.assert_rejected(invalid, "exit-code/signal pair")

        signaled = parse_development_supervisor_result(
            encode_result(
                self.request,
                outcome=DevelopmentSupervisorOutcome.SIGNAL,
                child_exit_code=-1,
                child_signal=9,
            ),
            request=self.request,
        )
        self.assertEqual((signaled.child_exit_code, signaled.child_signal), (-1, 9))

    def test_normal_nonzero_and_signal_outcomes_cannot_relabel_status(self) -> None:
        cases = (
            (
                encode_result(self.request, child_exit_code=2),
                "normal outcome",
            ),
            (
                encode_result(
                    self.request,
                    outcome=DevelopmentSupervisorOutcome.NONZERO,
                    child_exit_code=0,
                ),
                "nonzero outcome",
            ),
            (
                encode_result(
                    self.request,
                    outcome=DevelopmentSupervisorOutcome.SIGNAL,
                    child_exit_code=0,
                    child_signal=0,
                ),
                "signal outcome",
            ),
        )
        for frame, pattern in cases:
            with self.subTest(pattern=pattern):
                self.assert_rejected(frame, pattern)

    def test_observed_counts_flags_and_overflow_outcomes_must_agree(self) -> None:
        request = make_request(stdout_cap=8, stderr_cap=9)
        cases = (
            (
                encode_result(request, stdout_observed=9),
                "stdout overflow flag",
            ),
            (
                encode_result(
                    request,
                    flags=BASE_SUCCESS_FLAGS
                    | DevelopmentSupervisorFlag.STDOUT_OVERFLOW,
                    stdout_observed=8,
                ),
                "stdout overflow flag",
            ),
            (
                encode_result(request, stderr_observed=10),
                "stderr overflow flag",
            ),
            (
                encode_result(
                    request,
                    flags=BASE_SUCCESS_FLAGS
                    | DevelopmentSupervisorFlag.STDERR_OVERFLOW,
                    stderr_observed=9,
                ),
                "stderr overflow flag",
            ),
            (
                encode_result(
                    request,
                    outcome=DevelopmentSupervisorOutcome.STDOUT_OVERFLOW,
                    child_exit_code=-1,
                    child_signal=9,
                    flags=BASE_SUCCESS_FLAGS
                    | DevelopmentSupervisorFlag.STDERR_OVERFLOW,
                    stderr_observed=10,
                ),
                "stdout_overflow outcome",
            ),
            (
                encode_result(
                    request,
                    outcome=DevelopmentSupervisorOutcome.STDERR_OVERFLOW,
                    child_exit_code=-1,
                    child_signal=9,
                    flags=BASE_SUCCESS_FLAGS
                    | DevelopmentSupervisorFlag.STDOUT_OVERFLOW,
                    stdout_observed=9,
                ),
                "stderr_overflow outcome",
            ),
        )
        for frame, pattern in cases:
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(DevelopmentSupervisorProtocolError, pattern):
                    parse_development_supervisor_result(frame, request=request)

    def test_timeout_and_supervisor_error_cannot_relabel_other_incidents(self) -> None:
        missing_timeout = encode_result(
            self.request,
            outcome=DevelopmentSupervisorOutcome.WALL_TIMEOUT,
            child_exit_code=-1,
            child_signal=9,
        )
        self.assert_rejected(missing_timeout, "wall_timeout")

        timeout_as_normal = encode_result(
            self.request,
            flags=BASE_SUCCESS_FLAGS | DevelopmentSupervisorFlag.TIMED_OUT,
        )
        self.assert_rejected(timeout_as_normal, "normal outcome")

        timeout_as_error = encode_result(
            self.request,
            outcome=DevelopmentSupervisorOutcome.SUPERVISOR_ERROR,
            child_exit_code=-1,
            child_signal=0,
            flags=(
                DevelopmentSupervisorFlag.REQUEST_VALIDATED
                | DevelopmentSupervisorFlag.TIMED_OUT
            ),
        )
        self.assert_rejected(timeout_as_error, "cannot relabel")

    def test_every_semantic_mutation_is_checked_after_digest_verification(self) -> None:
        normal_exit_nonzero = mutate_i32(self.frame, 20, 5)
        self.assertEqual(
            normal_exit_nonzero[224:256],
            sha256(normal_exit_nonzero[:224]).digest(),
        )
        self.assert_rejected(normal_exit_nonzero, "normal outcome")

        stdout_over_cap = mutate_u64(
            self.frame, 32, self.request.stdout_cap + 1
        )
        self.assertEqual(
            stdout_over_cap[224:256], sha256(stdout_over_cap[:224]).digest()
        )
        self.assert_rejected(stdout_over_cap, "stdout overflow flag")

    def test_protocol_module_contains_no_assert_based_validation(self) -> None:
        source = inspect.getsource(protocol)
        tree = ast.parse(source)
        assertions = [node for node in ast.walk(tree) if isinstance(node, ast.Assert)]
        self.assertEqual(assertions, [])


if __name__ == "__main__":
    unittest.main()
