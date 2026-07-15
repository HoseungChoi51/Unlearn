from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError, replace
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import cbds.development_candidate_protocol as protocol  # noqa: E402
from cbds.development_candidate_protocol import (  # noqa: E402
    DEVELOPMENT_CANDIDATE_CLEANUP_FLAGS,
    DEVELOPMENT_CANDIDATE_FIXTURE_BUNDLE_FD,
    DEVELOPMENT_CANDIDATE_KNOWN_FLAGS,
    DEVELOPMENT_CANDIDATE_MAXIMUM_CPU_TIME_USEC,
    DEVELOPMENT_CANDIDATE_MAXIMUM_PROGRAM_BYTES,
    DEVELOPMENT_CANDIDATE_MAXIMUM_STREAM_CAP_BYTES,
    DEVELOPMENT_CANDIDATE_MAXIMUM_WALL_TIMEOUT_USEC,
    DEVELOPMENT_CANDIDATE_MAXIMUM_WORKSPACE_SNAPSHOT_BYTES,
    DEVELOPMENT_CANDIDATE_MINIMUM_CPU_TIME_USEC,
    DEVELOPMENT_CANDIDATE_MINIMUM_WALL_TIMEOUT_USEC,
    DEVELOPMENT_CANDIDATE_PROGRAM_FD,
    DEVELOPMENT_CANDIDATE_PROTOCOL_VERSION,
    DEVELOPMENT_CANDIDATE_REQUEST_BYTES,
    DEVELOPMENT_CANDIDATE_REQUEST_MAGIC,
    DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_ALLOWED_TOOLS_SHA256,
    DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_CPU_TIME_LIMIT_USEC,
    DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_FIXTURE_DEFINITION_SHA256,
    DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_INVOCATION_SHA256,
    DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_MAGIC,
    DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_NONCE,
    DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_POLICY_SHA256,
    DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_PROGRAM_BYTES,
    DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_PROGRAM_SHA256,
    DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_RESERVED,
    DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_RESERVED_U32,
    DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_RUNTIME_SNAPSHOT_SHA256,
    DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_STDERR_CAP_BYTES,
    DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_STDOUT_CAP_BYTES,
    DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_VERSION,
    DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_WALL_TIMEOUT_USEC,
    DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_WORKSPACE_BASELINE_SHA256,
    DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_WORKSPACE_SNAPSHOT_CAP_BYTES,
    DEVELOPMENT_CANDIDATE_RESOURCE_OUTCOME_PRECEDENCE,
    DEVELOPMENT_CANDIDATE_REQUEST_RESERVED_BYTES,
    DEVELOPMENT_CANDIDATE_RESULT_BYTES,
    DEVELOPMENT_CANDIDATE_RESULT_HASHED_PREFIX_BYTES,
    DEVELOPMENT_CANDIDATE_RESULT_MAGIC,
    DEVELOPMENT_CANDIDATE_RESULT_OFFSET_ALLOWED_TOOLS_SHA256,
    DEVELOPMENT_CANDIDATE_RESULT_OFFSET_CHILD_EXIT_CODE,
    DEVELOPMENT_CANDIDATE_RESULT_OFFSET_CHILD_SIGNAL,
    DEVELOPMENT_CANDIDATE_RESULT_OFFSET_DESCENDANTS_REAPED,
    DEVELOPMENT_CANDIDATE_RESULT_OFFSET_FIXTURE_DEFINITION_SHA256,
    DEVELOPMENT_CANDIDATE_RESULT_OFFSET_FLAGS,
    DEVELOPMENT_CANDIDATE_RESULT_OFFSET_INVOCATION_SHA256,
    DEVELOPMENT_CANDIDATE_RESULT_OFFSET_MAGIC,
    DEVELOPMENT_CANDIDATE_RESULT_OFFSET_NONCE,
    DEVELOPMENT_CANDIDATE_RESULT_OFFSET_OUTCOME,
    DEVELOPMENT_CANDIDATE_RESULT_OFFSET_POLICY_SHA256,
    DEVELOPMENT_CANDIDATE_RESULT_OFFSET_PROCESS_STATUS,
    DEVELOPMENT_CANDIDATE_RESULT_OFFSET_PROGRAM_SHA256,
    DEVELOPMENT_CANDIDATE_RESULT_OFFSET_REQUEST_SHA256,
    DEVELOPMENT_CANDIDATE_RESULT_OFFSET_RESERVED,
    DEVELOPMENT_CANDIDATE_RESULT_OFFSET_RESERVED_U32,
    DEVELOPMENT_CANDIDATE_RESULT_OFFSET_RESULT_SHA256,
    DEVELOPMENT_CANDIDATE_RESULT_OFFSET_RUNTIME_SNAPSHOT_SHA256,
    DEVELOPMENT_CANDIDATE_RESULT_OFFSET_STDERR_OBSERVED,
    DEVELOPMENT_CANDIDATE_RESULT_OFFSET_STDERR_SHA256,
    DEVELOPMENT_CANDIDATE_RESULT_OFFSET_STDOUT_OBSERVED,
    DEVELOPMENT_CANDIDATE_RESULT_OFFSET_STDOUT_SHA256,
    DEVELOPMENT_CANDIDATE_RESULT_OFFSET_VERSION,
    DEVELOPMENT_CANDIDATE_RESULT_OFFSET_WAIT4_SYS_CPU_USEC,
    DEVELOPMENT_CANDIDATE_RESULT_OFFSET_WAIT4_USER_CPU_USEC,
    DEVELOPMENT_CANDIDATE_RESULT_OFFSET_WALL_USEC,
    DEVELOPMENT_CANDIDATE_RESULT_OFFSET_WORKSPACE_BASELINE_SHA256,
    DEVELOPMENT_CANDIDATE_RESULT_OFFSET_WORKSPACE_SNAPSHOT_BYTES,
    DEVELOPMENT_CANDIDATE_RESULT_OFFSET_WORKSPACE_SNAPSHOT_SHA256,
    DEVELOPMENT_CANDIDATE_RESULT_RESERVED_BYTES,
    DEVELOPMENT_CANDIDATE_SETUP_FLAGS,
    DEVELOPMENT_CANDIDATE_WORKSPACE_SNAPSHOT_FD,
    DevelopmentCandidateFlag,
    DevelopmentCandidateOutcome,
    DevelopmentCandidateProcessStatus,
    DevelopmentCandidateProtocolError,
    DevelopmentCandidateRequest,
    canonical_development_candidate_request_record_bytes,
    canonical_development_candidate_result_record_bytes,
    development_candidate_request_record,
    development_candidate_result_record,
    encode_development_candidate_request,
    parse_development_candidate_request,
    parse_development_candidate_result,
    validate_development_candidate_result_binding,
)


EMPTY_SHA256 = sha256(b"").digest()


def digest(label: str) -> bytes:
    return sha256(label.encode("ascii")).digest()


def make_request(**changes: object) -> DevelopmentCandidateRequest:
    values: dict[str, object] = {
        "program_bytes": 123,
        "wall_timeout_usec": 1_000_000,
        "cpu_time_limit_usec": 500_000,
        "stdout_cap_bytes": 8,
        "stderr_cap_bytes": 9,
        "workspace_snapshot_cap_bytes": 10,
        "nonce": bytes(range(1, 33)),
        "invocation_sha256": digest("invocation"),
        "program_sha256": digest("program"),
        "fixture_definition_sha256": digest("fixture"),
        "workspace_baseline_sha256": digest("baseline"),
        "runtime_snapshot_sha256": digest("runtime"),
        "allowed_tools_sha256": digest("tools"),
        "policy_sha256": digest("policy"),
    }
    values.update(changes)
    return DevelopmentCandidateRequest(**values)  # type: ignore[arg-type]


def make_result_frame(
    request: DevelopmentCandidateRequest | None = None,
    **changes: object,
) -> bytes:
    selected = make_request() if request is None else request
    return protocol._encode_development_candidate_result_for_tests(  # noqa: SLF001
        selected,
        **changes,  # type: ignore[arg-type]
    )


def reseal_result(frame: bytes) -> bytes:
    prefix = frame[:DEVELOPMENT_CANDIDATE_RESULT_HASHED_PREFIX_BYTES]
    return prefix + sha256(prefix).digest()


def mutate_result_bytes(frame: bytes, offset: int, payload: bytes) -> bytes:
    changed = bytearray(frame)
    changed[offset:offset + len(payload)] = payload
    return reseal_result(bytes(changed))


def mutate_result_u32(frame: bytes, offset: int, value: int) -> bytes:
    return mutate_result_bytes(frame, offset, struct.pack("<I", value))


def mutate_result_i32(frame: bytes, offset: int, value: int) -> bytes:
    return mutate_result_bytes(frame, offset, struct.pack("<i", value))


def mutate_result_u64(frame: bytes, offset: int, value: int) -> bytes:
    return mutate_result_bytes(frame, offset, struct.pack("<Q", value))


class CandidateRequestProtocolTests(unittest.TestCase):
    def test_request_layout_offsets_and_fixed_descriptor_contract_are_exact(self) -> None:
        request = make_request()
        frame = encode_development_candidate_request(request)

        self.assertEqual(len(frame), DEVELOPMENT_CANDIDATE_REQUEST_BYTES)
        self.assertEqual(frame[:8], DEVELOPMENT_CANDIDATE_REQUEST_MAGIC)
        self.assertEqual(DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_MAGIC, 0)
        self.assertEqual(DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_VERSION, 8)
        self.assertEqual(DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_RESERVED_U32, 12)
        self.assertEqual(
            struct.unpack_from("<IIQQQQQQ", frame, 8),
            (
                DEVELOPMENT_CANDIDATE_PROTOCOL_VERSION,
                0,
                request.program_bytes,
                request.wall_timeout_usec,
                request.cpu_time_limit_usec,
                request.stdout_cap_bytes,
                request.stderr_cap_bytes,
                request.workspace_snapshot_cap_bytes,
            ),
        )
        self.assertEqual(frame[320:], b"\0" * DEVELOPMENT_CANDIDATE_REQUEST_RESERVED_BYTES)
        identities = (
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
        for offset, expected in identities:
            with self.subTest(offset=offset):
                self.assertEqual(frame[offset:offset + 32], expected)
        self.assertEqual(
            (
                DEVELOPMENT_CANDIDATE_PROGRAM_FD,
                DEVELOPMENT_CANDIDATE_FIXTURE_BUNDLE_FD,
                DEVELOPMENT_CANDIDATE_WORKSPACE_SNAPSHOT_FD,
            ),
            (3, 4, 5),
        )

    def test_every_request_numeric_offset_is_exported_and_aligned(self) -> None:
        self.assertEqual(DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_PROGRAM_BYTES, 16)
        self.assertEqual(DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_WALL_TIMEOUT_USEC, 24)
        self.assertEqual(DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_CPU_TIME_LIMIT_USEC, 32)
        self.assertEqual(DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_STDOUT_CAP_BYTES, 40)
        self.assertEqual(DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_STDERR_CAP_BYTES, 48)
        self.assertEqual(
            DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_WORKSPACE_SNAPSHOT_CAP_BYTES,
            56,
        )
        self.assertEqual(DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_RESERVED, 320)

    def test_request_round_trips_and_is_immutable(self) -> None:
        request = make_request()
        frame = encode_development_candidate_request(request)
        parsed = parse_development_candidate_request(frame)

        self.assertEqual(parsed, request)
        self.assertEqual(parsed.request_sha256, sha256(frame).digest())
        with self.assertRaises(FrozenInstanceError):
            parsed.program_bytes = 1  # type: ignore[misc]
        for value in (bytearray(frame), memoryview(frame), None, "x"):
            with self.subTest(value_type=type(value)):
                with self.assertRaises(DevelopmentCandidateProtocolError):
                    parse_development_candidate_request(value)  # type: ignore[arg-type]

    def test_request_numeric_bounds_are_inclusive(self) -> None:
        cases = (
            {"program_bytes": 1},
            {"program_bytes": DEVELOPMENT_CANDIDATE_MAXIMUM_PROGRAM_BYTES},
            {"wall_timeout_usec": DEVELOPMENT_CANDIDATE_MINIMUM_WALL_TIMEOUT_USEC},
            {"wall_timeout_usec": DEVELOPMENT_CANDIDATE_MAXIMUM_WALL_TIMEOUT_USEC},
            {"cpu_time_limit_usec": DEVELOPMENT_CANDIDATE_MINIMUM_CPU_TIME_USEC},
            {"cpu_time_limit_usec": DEVELOPMENT_CANDIDATE_MAXIMUM_CPU_TIME_USEC},
            {"stdout_cap_bytes": 1},
            {"stderr_cap_bytes": DEVELOPMENT_CANDIDATE_MAXIMUM_STREAM_CAP_BYTES},
            {"workspace_snapshot_cap_bytes": 1},
            {
                "workspace_snapshot_cap_bytes": (
                    DEVELOPMENT_CANDIDATE_MAXIMUM_WORKSPACE_SNAPSHOT_BYTES
                )
            },
        )
        for changes in cases:
            with self.subTest(changes=changes):
                self.assertIsInstance(make_request(**changes), DevelopmentCandidateRequest)

    def test_request_rejects_out_of_range_and_non_plain_numeric_types(self) -> None:
        cases = (
            {"program_bytes": 0},
            {"program_bytes": DEVELOPMENT_CANDIDATE_MAXIMUM_PROGRAM_BYTES + 1},
            {"program_bytes": True},
            {"program_bytes": 1.0},
            {"wall_timeout_usec": DEVELOPMENT_CANDIDATE_MINIMUM_WALL_TIMEOUT_USEC - 1},
            {"wall_timeout_usec": DEVELOPMENT_CANDIDATE_MAXIMUM_WALL_TIMEOUT_USEC + 1},
            {"cpu_time_limit_usec": DEVELOPMENT_CANDIDATE_MINIMUM_CPU_TIME_USEC - 1},
            {"cpu_time_limit_usec": DEVELOPMENT_CANDIDATE_MAXIMUM_CPU_TIME_USEC + 1},
            {"stdout_cap_bytes": 0},
            {"stdout_cap_bytes": False},
            {"stderr_cap_bytes": DEVELOPMENT_CANDIDATE_MAXIMUM_STREAM_CAP_BYTES + 1},
            {"workspace_snapshot_cap_bytes": 0},
            {
                "workspace_snapshot_cap_bytes": (
                    DEVELOPMENT_CANDIDATE_MAXIMUM_WORKSPACE_SNAPSHOT_BYTES + 1
                )
            },
        )
        for changes in cases:
            with self.subTest(changes=changes):
                with self.assertRaises(DevelopmentCandidateProtocolError):
                    make_request(**changes)

    def test_request_requires_exact_nonzero_nonce_and_digest_bytes(self) -> None:
        fields = (
            "nonce",
            "invocation_sha256",
            "program_sha256",
            "fixture_definition_sha256",
            "workspace_baseline_sha256",
            "runtime_snapshot_sha256",
            "allowed_tools_sha256",
            "policy_sha256",
        )
        for field in fields:
            for value in (b"x" * 31, b"x" * 33, b"\0" * 32, bytearray(b"x" * 32)):
                with self.subTest(field=field, value_type=type(value), length=len(value)):
                    with self.assertRaises(DevelopmentCandidateProtocolError):
                        make_request(**{field: value})

    def test_request_parser_rejects_magic_version_reserved_and_length_changes(self) -> None:
        frame = encode_development_candidate_request(make_request())
        variants: list[bytes] = [frame[:-1], frame + b"x"]
        changed = bytearray(frame)
        changed[0] ^= 1
        variants.append(bytes(changed))
        changed = bytearray(frame)
        struct.pack_into("<I", changed, 8, 2)
        variants.append(bytes(changed))
        for offset in (12, 320, 383):
            changed = bytearray(frame)
            changed[offset] = 1
            variants.append(bytes(changed))
        for variant in variants:
            with self.subTest(length=len(variant), prefix=variant[:8]):
                with self.assertRaises(DevelopmentCandidateProtocolError):
                    parse_development_candidate_request(variant)

    def test_every_request_identity_byte_is_part_of_request_hash(self) -> None:
        request = make_request()
        frame = encode_development_candidate_request(request)
        original_digest = request.request_sha256
        for offset in range(DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_NONCE, 320):
            changed = bytearray(frame)
            changed[offset] ^= 1
            parsed = parse_development_candidate_request(bytes(changed))
            with self.subTest(offset=offset):
                self.assertNotEqual(parsed.request_sha256, original_digest)

    def test_request_canonical_record_is_complete_and_permanently_nonauthorizing(self) -> None:
        request = make_request()
        record = development_candidate_request_record(request)
        payload = canonical_development_candidate_request_record_bytes(request)

        self.assertEqual(request.to_record(), record)
        self.assertEqual(request.canonical_record_bytes(), payload)
        self.assertEqual(json.loads(payload), record)
        self.assertNotIn(b" ", payload)
        self.assertEqual(record["wire_magic"], "CBDSBRQ1")
        self.assertEqual(record["request_sha256"], request.request_sha256.hex())
        self.assertEqual(
            record["descriptor_contract"],
            {"program_fd": 3, "fixture_bundle_fd": 4, "workspace_snapshot_fd": 5},
        )
        for field in (
            "candidate_execution_authorized",
            "scored_evaluation_eligible",
            "model_selection_eligible",
            "claim_pipeline_eligible",
            "claim_authorized",
        ):
            self.assertIs(record[field], False)


class CandidateResultProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.request = make_request()
        self.frame = make_result_frame(self.request)

    def test_result_layout_offsets_hashes_and_repeated_identities_are_exact(self) -> None:
        frame = self.frame
        self.assertEqual(len(frame), DEVELOPMENT_CANDIDATE_RESULT_BYTES)
        self.assertEqual(frame[:8], DEVELOPMENT_CANDIDATE_RESULT_MAGIC)
        self.assertEqual(DEVELOPMENT_CANDIDATE_RESULT_OFFSET_MAGIC, 0)
        self.assertEqual(DEVELOPMENT_CANDIDATE_RESULT_OFFSET_VERSION, 8)
        self.assertEqual(
            struct.unpack_from("<IIIiIIQQQQQIIQ", frame, 8),
            (
                1,
                1,
                1,
                0,
                0,
                int(
                    DEVELOPMENT_CANDIDATE_SETUP_FLAGS
                    | DEVELOPMENT_CANDIDATE_CLEANUP_FLAGS
                    | DevelopmentCandidateFlag.WORKSPACE_SNAPSHOT_WRITTEN
                ),
                0,
                0,
                0,
                0,
                1,
                1,
                0,
                0,
            ),
        )
        self.assertEqual(frame[76:80], b"\0" * 4)
        self.assertEqual(frame[88:96], b"\0" * DEVELOPMENT_CANDIDATE_RESULT_RESERVED_BYTES)
        expected = (
            (DEVELOPMENT_CANDIDATE_RESULT_OFFSET_REQUEST_SHA256, self.request.request_sha256),
            (DEVELOPMENT_CANDIDATE_RESULT_OFFSET_NONCE, self.request.nonce),
            (
                DEVELOPMENT_CANDIDATE_RESULT_OFFSET_INVOCATION_SHA256,
                self.request.invocation_sha256,
            ),
            (DEVELOPMENT_CANDIDATE_RESULT_OFFSET_PROGRAM_SHA256, self.request.program_sha256),
            (
                DEVELOPMENT_CANDIDATE_RESULT_OFFSET_FIXTURE_DEFINITION_SHA256,
                self.request.fixture_definition_sha256,
            ),
            (
                DEVELOPMENT_CANDIDATE_RESULT_OFFSET_WORKSPACE_BASELINE_SHA256,
                self.request.workspace_baseline_sha256,
            ),
            (
                DEVELOPMENT_CANDIDATE_RESULT_OFFSET_RUNTIME_SNAPSHOT_SHA256,
                self.request.runtime_snapshot_sha256,
            ),
            (
                DEVELOPMENT_CANDIDATE_RESULT_OFFSET_ALLOWED_TOOLS_SHA256,
                self.request.allowed_tools_sha256,
            ),
            (DEVELOPMENT_CANDIDATE_RESULT_OFFSET_POLICY_SHA256, self.request.policy_sha256),
            (DEVELOPMENT_CANDIDATE_RESULT_OFFSET_STDOUT_SHA256, EMPTY_SHA256),
            (DEVELOPMENT_CANDIDATE_RESULT_OFFSET_STDERR_SHA256, EMPTY_SHA256),
            (
                DEVELOPMENT_CANDIDATE_RESULT_OFFSET_WORKSPACE_SNAPSHOT_SHA256,
                EMPTY_SHA256,
            ),
        )
        for offset, payload in expected:
            with self.subTest(offset=offset):
                self.assertEqual(frame[offset:offset + 32], payload)
        self.assertEqual(
            frame[DEVELOPMENT_CANDIDATE_RESULT_OFFSET_RESULT_SHA256:],
            sha256(frame[:DEVELOPMENT_CANDIDATE_RESULT_HASHED_PREFIX_BYTES]).digest(),
        )

    def test_every_result_numeric_offset_is_exported_and_aligned(self) -> None:
        expected = (
            (DEVELOPMENT_CANDIDATE_RESULT_OFFSET_OUTCOME, 12),
            (DEVELOPMENT_CANDIDATE_RESULT_OFFSET_PROCESS_STATUS, 16),
            (DEVELOPMENT_CANDIDATE_RESULT_OFFSET_CHILD_EXIT_CODE, 20),
            (DEVELOPMENT_CANDIDATE_RESULT_OFFSET_CHILD_SIGNAL, 24),
            (DEVELOPMENT_CANDIDATE_RESULT_OFFSET_FLAGS, 28),
            (DEVELOPMENT_CANDIDATE_RESULT_OFFSET_STDOUT_OBSERVED, 32),
            (DEVELOPMENT_CANDIDATE_RESULT_OFFSET_STDERR_OBSERVED, 40),
            (DEVELOPMENT_CANDIDATE_RESULT_OFFSET_WAIT4_USER_CPU_USEC, 48),
            (DEVELOPMENT_CANDIDATE_RESULT_OFFSET_WAIT4_SYS_CPU_USEC, 56),
            (DEVELOPMENT_CANDIDATE_RESULT_OFFSET_WALL_USEC, 64),
            (DEVELOPMENT_CANDIDATE_RESULT_OFFSET_DESCENDANTS_REAPED, 72),
            (DEVELOPMENT_CANDIDATE_RESULT_OFFSET_RESERVED_U32, 76),
            (DEVELOPMENT_CANDIDATE_RESULT_OFFSET_WORKSPACE_SNAPSHOT_BYTES, 80),
            (DEVELOPMENT_CANDIDATE_RESULT_OFFSET_RESERVED, 88),
        )
        for actual, required in expected:
            with self.subTest(required=required):
                self.assertEqual(actual, required)

    def test_result_round_trips_and_binds_the_exact_request(self) -> None:
        result = parse_development_candidate_result(self.frame, request=self.request)
        validate_development_candidate_result_binding(result, request=self.request)
        self.assertIs(result.outcome, DevelopmentCandidateOutcome.NORMAL)
        self.assertIs(result.process_status, DevelopmentCandidateProcessStatus.EXITED)
        self.assertEqual(result.request_sha256, self.request.request_sha256)
        self.assertEqual(result.result_sha256, sha256(self.frame[:480]).digest())
        with self.assertRaises(FrozenInstanceError):
            result.wall_usec = 9  # type: ignore[misc]

    def test_all_outcome_and_process_status_shapes_have_one_valid_encoding(self) -> None:
        base = DEVELOPMENT_CANDIDATE_SETUP_FLAGS | DEVELOPMENT_CANDIDATE_CLEANUP_FLAGS
        complete = base | DevelopmentCandidateFlag.WORKSPACE_SNAPSHOT_WRITTEN
        cases: tuple[tuple[dict[str, object], DevelopmentCandidateOutcome], ...] = (
            ({}, DevelopmentCandidateOutcome.NORMAL),
            (
                {"outcome": DevelopmentCandidateOutcome.NONZERO, "child_exit_code": 7},
                DevelopmentCandidateOutcome.NONZERO,
            ),
            (
                {
                    "outcome": DevelopmentCandidateOutcome.SIGNAL,
                    "process_status": DevelopmentCandidateProcessStatus.SIGNALED,
                    "child_exit_code": -1,
                    "child_signal": 15,
                },
                DevelopmentCandidateOutcome.SIGNAL,
            ),
            (
                {
                    "outcome": DevelopmentCandidateOutcome.WALL_TIMEOUT,
                    "process_status": DevelopmentCandidateProcessStatus.SIGNALED,
                    "child_exit_code": -1,
                    "child_signal": 9,
                    "flags": complete | DevelopmentCandidateFlag.WALL_LIMIT_REACHED,
                    "wall_usec": self.request.wall_timeout_usec,
                },
                DevelopmentCandidateOutcome.WALL_TIMEOUT,
            ),
            (
                {
                    "outcome": DevelopmentCandidateOutcome.CPU_LIMIT,
                    "process_status": DevelopmentCandidateProcessStatus.SIGNALED,
                    "child_exit_code": -1,
                    "child_signal": 9,
                    "flags": complete | DevelopmentCandidateFlag.CPU_LIMIT_REACHED,
                    "wait4_user_cpu_usec": self.request.cpu_time_limit_usec,
                },
                DevelopmentCandidateOutcome.CPU_LIMIT,
            ),
            (
                {
                    "outcome": DevelopmentCandidateOutcome.STDOUT_OVERFLOW,
                    "process_status": DevelopmentCandidateProcessStatus.SIGNALED,
                    "child_exit_code": -1,
                    "child_signal": 9,
                    "flags": complete | DevelopmentCandidateFlag.STDOUT_OVERFLOW,
                    "stdout_observed": self.request.stdout_cap_bytes + 1,
                    "stdout_sha256": digest("stdout-prefix"),
                },
                DevelopmentCandidateOutcome.STDOUT_OVERFLOW,
            ),
            (
                {
                    "outcome": DevelopmentCandidateOutcome.STDERR_OVERFLOW,
                    "process_status": DevelopmentCandidateProcessStatus.SIGNALED,
                    "child_exit_code": -1,
                    "child_signal": 9,
                    "flags": complete | DevelopmentCandidateFlag.STDERR_OVERFLOW,
                    "stderr_observed": self.request.stderr_cap_bytes + 1,
                    "stderr_sha256": digest("stderr-prefix"),
                },
                DevelopmentCandidateOutcome.STDERR_OVERFLOW,
            ),
            (
                {
                    "outcome": DevelopmentCandidateOutcome.WORKSPACE_SNAPSHOT_OVERFLOW,
                    "flags": base | DevelopmentCandidateFlag.WORKSPACE_SNAPSHOT_OVERFLOW,
                    "workspace_snapshot_bytes": (
                        self.request.workspace_snapshot_cap_bytes + 1
                    ),
                    "workspace_snapshot_sha256": digest("workspace-prefix"),
                },
                DevelopmentCandidateOutcome.WORKSPACE_SNAPSHOT_OVERFLOW,
            ),
            (
                {
                    "outcome": DevelopmentCandidateOutcome.SUPERVISOR_ERROR,
                    "process_status": DevelopmentCandidateProcessStatus.NOT_REAPED,
                    "child_exit_code": -1,
                    "flags": DevelopmentCandidateFlag.REQUEST_VALIDATED,
                    "descendants_reaped": 0,
                },
                DevelopmentCandidateOutcome.SUPERVISOR_ERROR,
            ),
        )
        for changes, expected in cases:
            with self.subTest(expected=expected):
                result = parse_development_candidate_result(
                    make_result_frame(self.request, **changes),
                    request=self.request,
                )
                self.assertIs(result.outcome, expected)

    def test_result_requires_exact_bytes_length_magic_version_and_reserved_regions(self) -> None:
        for value in (bytearray(self.frame), memoryview(self.frame), None, "x"):
            with self.subTest(value_type=type(value)):
                with self.assertRaises(DevelopmentCandidateProtocolError):
                    parse_development_candidate_result(value, request=self.request)  # type: ignore[arg-type]
        variants = (
            self.frame[:-1],
            self.frame + b"x",
            mutate_result_bytes(self.frame, 0, b"BADMAGIC"),
            mutate_result_u32(self.frame, 8, 2),
            mutate_result_u32(self.frame, 76, 1),
            mutate_result_bytes(self.frame, 88, b"x"),
            mutate_result_bytes(self.frame, 95, b"x"),
        )
        for frame in variants:
            with self.subTest(length=len(frame)):
                with self.assertRaises(DevelopmentCandidateProtocolError):
                    parse_development_candidate_result(frame, request=self.request)

    def test_every_single_byte_prefix_mutation_fails_without_a_new_result_digest(self) -> None:
        for offset in range(DEVELOPMENT_CANDIDATE_RESULT_HASHED_PREFIX_BYTES):
            changed = bytearray(self.frame)
            changed[offset] ^= 1
            with self.subTest(offset=offset):
                with self.assertRaises(DevelopmentCandidateProtocolError):
                    parse_development_candidate_result(bytes(changed), request=self.request)

    def test_resealed_unknown_enum_and_flag_values_fail(self) -> None:
        variants = (
            mutate_result_u32(self.frame, 12, 0),
            mutate_result_u32(self.frame, 12, 10),
            mutate_result_u32(self.frame, 16, 3),
            mutate_result_u32(self.frame, 28, 1 << 31),
        )
        for frame in variants:
            with self.subTest(header=frame[8:32]):
                with self.assertRaises(DevelopmentCandidateProtocolError):
                    parse_development_candidate_result(frame, request=self.request)
        self.assertEqual(int(DEVELOPMENT_CANDIDATE_KNOWN_FLAGS), (1 << 19) - 1)

    def test_every_repeated_request_identity_rejects_resealed_spoofing(self) -> None:
        offsets = (
            DEVELOPMENT_CANDIDATE_RESULT_OFFSET_REQUEST_SHA256,
            DEVELOPMENT_CANDIDATE_RESULT_OFFSET_NONCE,
            DEVELOPMENT_CANDIDATE_RESULT_OFFSET_INVOCATION_SHA256,
            DEVELOPMENT_CANDIDATE_RESULT_OFFSET_PROGRAM_SHA256,
            DEVELOPMENT_CANDIDATE_RESULT_OFFSET_FIXTURE_DEFINITION_SHA256,
            DEVELOPMENT_CANDIDATE_RESULT_OFFSET_WORKSPACE_BASELINE_SHA256,
            DEVELOPMENT_CANDIDATE_RESULT_OFFSET_RUNTIME_SNAPSHOT_SHA256,
            DEVELOPMENT_CANDIDATE_RESULT_OFFSET_ALLOWED_TOOLS_SHA256,
            DEVELOPMENT_CANDIDATE_RESULT_OFFSET_POLICY_SHA256,
        )
        for offset in offsets:
            changed = bytearray(self.frame)
            changed[offset] ^= 1
            frame = reseal_result(bytes(changed))
            with self.subTest(offset=offset):
                with self.assertRaises(DevelopmentCandidateProtocolError):
                    parse_development_candidate_result(frame, request=self.request)

    def test_typed_result_cannot_be_rebound_to_another_request(self) -> None:
        result = parse_development_candidate_result(self.frame, request=self.request)
        requests = (
            make_request(nonce=b"z" * 32),
            make_request(program_bytes=self.request.program_bytes + 1),
            make_request(policy_sha256=digest("other-policy")),
        )
        for changed in requests:
            with self.subTest(changed=changed):
                with self.assertRaises(DevelopmentCandidateProtocolError):
                    validate_development_candidate_result_binding(result, request=changed)

    def test_stream_capture_uses_exact_cap_plus_one_semantics(self) -> None:
        valid_at_cap = make_result_frame(
            self.request,
            stdout_observed=self.request.stdout_cap_bytes,
            stdout_sha256=digest("at-cap"),
        )
        parse_development_candidate_result(valid_at_cap, request=self.request)

        invalid = (
            mutate_result_u64(
                valid_at_cap,
                DEVELOPMENT_CANDIDATE_RESULT_OFFSET_STDOUT_OBSERVED,
                self.request.stdout_cap_bytes + 1,
            ),
            mutate_result_u64(
                valid_at_cap,
                DEVELOPMENT_CANDIDATE_RESULT_OFFSET_STDOUT_OBSERVED,
                self.request.stdout_cap_bytes + 2,
            ),
            mutate_result_u64(
                self.frame,
                DEVELOPMENT_CANDIDATE_RESULT_OFFSET_STDERR_OBSERVED,
                self.request.stderr_cap_bytes + 1,
            ),
        )
        for frame in invalid:
            with self.subTest(observed=frame[32:48]):
                with self.assertRaises(DevelopmentCandidateProtocolError):
                    parse_development_candidate_result(frame, request=self.request)

        overflow = make_result_frame(
            self.request,
            outcome=DevelopmentCandidateOutcome.STDOUT_OVERFLOW,
            process_status=DevelopmentCandidateProcessStatus.SIGNALED,
            child_exit_code=-1,
            child_signal=9,
            flags=(
                DEVELOPMENT_CANDIDATE_SETUP_FLAGS
                | DEVELOPMENT_CANDIDATE_CLEANUP_FLAGS
                | DevelopmentCandidateFlag.WORKSPACE_SNAPSHOT_WRITTEN
                | DevelopmentCandidateFlag.STDOUT_OVERFLOW
            ),
            stdout_observed=self.request.stdout_cap_bytes + 1,
            stdout_sha256=digest("cap-plus-one"),
        )
        parsed = parse_development_candidate_result(overflow, request=self.request)
        self.assertEqual(parsed.stdout_observed, self.request.stdout_cap_bytes + 1)

    def test_wall_and_cumulative_wait4_cpu_flags_require_real_crossings(self) -> None:
        variants = (
            mutate_result_u64(
                self.frame,
                DEVELOPMENT_CANDIDATE_RESULT_OFFSET_WALL_USEC,
                self.request.wall_timeout_usec,
            ),
            mutate_result_u64(
                self.frame,
                DEVELOPMENT_CANDIDATE_RESULT_OFFSET_WAIT4_USER_CPU_USEC,
                self.request.cpu_time_limit_usec,
            ),
        )
        for frame in variants:
            with self.subTest(frame_header=frame[48:72]):
                with self.assertRaises(DevelopmentCandidateProtocolError):
                    parse_development_candidate_result(frame, request=self.request)

        cpu = make_result_frame(
            self.request,
            outcome=DevelopmentCandidateOutcome.CPU_LIMIT,
            process_status=DevelopmentCandidateProcessStatus.SIGNALED,
            child_exit_code=-1,
            child_signal=9,
            flags=(
                DEVELOPMENT_CANDIDATE_SETUP_FLAGS
                | DEVELOPMENT_CANDIDATE_CLEANUP_FLAGS
                | DevelopmentCandidateFlag.WORKSPACE_SNAPSHOT_WRITTEN
                | DevelopmentCandidateFlag.CPU_LIMIT_REACHED
            ),
            wait4_user_cpu_usec=self.request.cpu_time_limit_usec - 1,
            wait4_sys_cpu_usec=1,
        )
        parsed = parse_development_candidate_result(cpu, request=self.request)
        self.assertEqual(
            parsed.wait4_user_cpu_usec + parsed.wait4_sys_cpu_usec,
            self.request.cpu_time_limit_usec,
        )

    def test_multiple_resource_incidents_use_fixed_outcome_precedence(self) -> None:
        valid = make_result_frame(
            self.request,
            outcome=DevelopmentCandidateOutcome.STDOUT_OVERFLOW,
            process_status=DevelopmentCandidateProcessStatus.SIGNALED,
            child_exit_code=-1,
            child_signal=9,
            flags=(
                DEVELOPMENT_CANDIDATE_SETUP_FLAGS
                | DEVELOPMENT_CANDIDATE_CLEANUP_FLAGS
                | DevelopmentCandidateFlag.WORKSPACE_SNAPSHOT_WRITTEN
                | DevelopmentCandidateFlag.STDOUT_OVERFLOW
            ),
            stdout_observed=self.request.stdout_cap_bytes + 1,
            stdout_sha256=digest("stdout"),
        )
        wrong_outcome = mutate_result_u32(
            valid,
            DEVELOPMENT_CANDIDATE_RESULT_OFFSET_OUTCOME,
            int(DevelopmentCandidateOutcome.STDERR_OVERFLOW),
        )
        two_incidents = mutate_result_u64(
            valid,
            DEVELOPMENT_CANDIDATE_RESULT_OFFSET_WALL_USEC,
            self.request.wall_timeout_usec,
        )
        two_incidents = mutate_result_u32(
            two_incidents,
            DEVELOPMENT_CANDIDATE_RESULT_OFFSET_FLAGS,
            struct.unpack_from("<I", two_incidents, 28)[0]
            | int(DevelopmentCandidateFlag.WALL_LIMIT_REACHED),
        )
        with self.assertRaises(DevelopmentCandidateProtocolError):
            parse_development_candidate_result(wrong_outcome, request=self.request)
        parsed = parse_development_candidate_result(two_incidents, request=self.request)
        self.assertIs(parsed.outcome, DevelopmentCandidateOutcome.STDOUT_OVERFLOW)
        self.assertEqual(
            DEVELOPMENT_CANDIDATE_RESOURCE_OUTCOME_PRECEDENCE,
            (
                DevelopmentCandidateOutcome.WORKSPACE_SNAPSHOT_OVERFLOW,
                DevelopmentCandidateOutcome.STDOUT_OVERFLOW,
                DevelopmentCandidateOutcome.STDERR_OVERFLOW,
                DevelopmentCandidateOutcome.CPU_LIMIT,
                DevelopmentCandidateOutcome.WALL_TIMEOUT,
            ),
        )

        relabeled = mutate_result_u32(
            two_incidents,
            DEVELOPMENT_CANDIDATE_RESULT_OFFSET_OUTCOME,
            int(DevelopmentCandidateOutcome.WALL_TIMEOUT),
        )
        with self.assertRaises(DevelopmentCandidateProtocolError):
            parse_development_candidate_result(relabeled, request=self.request)

        workspace_and_stdout = make_result_frame(
            self.request,
            outcome=DevelopmentCandidateOutcome.WORKSPACE_SNAPSHOT_OVERFLOW,
            process_status=DevelopmentCandidateProcessStatus.SIGNALED,
            child_exit_code=-1,
            child_signal=9,
            flags=(
                DEVELOPMENT_CANDIDATE_SETUP_FLAGS
                | DEVELOPMENT_CANDIDATE_CLEANUP_FLAGS
                | DevelopmentCandidateFlag.STDOUT_OVERFLOW
                | DevelopmentCandidateFlag.WORKSPACE_SNAPSHOT_OVERFLOW
            ),
            stdout_observed=self.request.stdout_cap_bytes + 1,
            stdout_sha256=digest("stdout-before-snapshot"),
            workspace_snapshot_bytes=self.request.workspace_snapshot_cap_bytes + 1,
            workspace_snapshot_sha256=digest("workspace-prefix"),
        )
        parsed = parse_development_candidate_result(
            workspace_and_stdout, request=self.request
        )
        self.assertIs(
            parsed.outcome,
            DevelopmentCandidateOutcome.WORKSPACE_SNAPSHOT_OVERFLOW,
        )

    def test_cleanup_measurements_may_cross_unreported_secondary_limits(self) -> None:
        frame = make_result_frame(
            self.request,
            outcome=DevelopmentCandidateOutcome.STDOUT_OVERFLOW,
            process_status=DevelopmentCandidateProcessStatus.SIGNALED,
            child_exit_code=-1,
            child_signal=9,
            flags=(
                DEVELOPMENT_CANDIDATE_SETUP_FLAGS
                | DEVELOPMENT_CANDIDATE_CLEANUP_FLAGS
                | DevelopmentCandidateFlag.WORKSPACE_SNAPSHOT_WRITTEN
                | DevelopmentCandidateFlag.STDOUT_OVERFLOW
            ),
            stdout_observed=self.request.stdout_cap_bytes + 1,
            stdout_sha256=digest("stdout-trigger"),
            wall_usec=self.request.wall_timeout_usec,
            wait4_user_cpu_usec=self.request.cpu_time_limit_usec,
        )
        parsed = parse_development_candidate_result(frame, request=self.request)
        self.assertIs(parsed.outcome, DevelopmentCandidateOutcome.STDOUT_OVERFLOW)
        self.assertFalse(
            parsed.flags & DevelopmentCandidateFlag.WALL_LIMIT_REACHED
        )
        self.assertFalse(
            parsed.flags & DevelopmentCandidateFlag.CPU_LIMIT_REACHED
        )

    def test_process_status_exit_signal_and_reaping_shapes_are_strict(self) -> None:
        variants = (
            mutate_result_i32(self.frame, DEVELOPMENT_CANDIDATE_RESULT_OFFSET_CHILD_EXIT_CODE, -1),
            mutate_result_u32(self.frame, DEVELOPMENT_CANDIDATE_RESULT_OFFSET_CHILD_SIGNAL, 9),
            mutate_result_u32(
                self.frame,
                DEVELOPMENT_CANDIDATE_RESULT_OFFSET_PROCESS_STATUS,
                int(DevelopmentCandidateProcessStatus.NOT_REAPED),
            ),
            mutate_result_u32(
                self.frame,
                DEVELOPMENT_CANDIDATE_RESULT_OFFSET_DESCENDANTS_REAPED,
                0,
            ),
        )
        for frame in variants:
            with self.subTest(status=frame[16:28]):
                with self.assertRaises(DevelopmentCandidateProtocolError):
                    parse_development_candidate_result(frame, request=self.request)

    def test_nonerror_outcomes_require_all_setup_cleanup_and_workspace_evidence(self) -> None:
        original_flags = struct.unpack_from("<I", self.frame, 28)[0]
        for missing in (
            DevelopmentCandidateFlag.PROGRAM_DESCRIPTOR_VALIDATED,
            DevelopmentCandidateFlag.FIXTURE_DESCRIPTOR_VALIDATED,
            DevelopmentCandidateFlag.RUNTIME_SNAPSHOT_VALIDATED,
            DevelopmentCandidateFlag.WORKSPACE_BASELINE_VALIDATED,
            DevelopmentCandidateFlag.ALLOWED_TOOLS_VALIDATED,
            DevelopmentCandidateFlag.POLICY_VALIDATED,
            DevelopmentCandidateFlag.CHILD_NO_NEW_PRIVS,
            DevelopmentCandidateFlag.CHILD_DUMPABLE_DISABLED,
            DevelopmentCandidateFlag.CHILD_SECCOMP_INSTALLED,
            DevelopmentCandidateFlag.ALL_DESCENDANTS_REAPED,
            DevelopmentCandidateFlag.SOLE_PID1,
            DevelopmentCandidateFlag.WORKSPACE_SNAPSHOT_WRITTEN,
        ):
            frame = mutate_result_u32(
                self.frame,
                DEVELOPMENT_CANDIDATE_RESULT_OFFSET_FLAGS,
                original_flags & ~int(missing),
            )
            with self.subTest(missing=missing):
                with self.assertRaises(DevelopmentCandidateProtocolError):
                    parse_development_candidate_result(frame, request=self.request)

    def test_workspace_snapshot_written_overflow_and_absent_shapes_are_distinct(self) -> None:
        overflow = make_result_frame(
            self.request,
            outcome=DevelopmentCandidateOutcome.WORKSPACE_SNAPSHOT_OVERFLOW,
            flags=(
                DEVELOPMENT_CANDIDATE_SETUP_FLAGS
                | DEVELOPMENT_CANDIDATE_CLEANUP_FLAGS
                | DevelopmentCandidateFlag.WORKSPACE_SNAPSHOT_OVERFLOW
            ),
            workspace_snapshot_bytes=self.request.workspace_snapshot_cap_bytes + 1,
            workspace_snapshot_sha256=digest("workspace-prefix"),
        )
        parse_development_candidate_result(overflow, request=self.request)
        invalid = (
            mutate_result_u64(
                overflow,
                DEVELOPMENT_CANDIDATE_RESULT_OFFSET_WORKSPACE_SNAPSHOT_BYTES,
                self.request.workspace_snapshot_cap_bytes,
            ),
            mutate_result_u64(
                overflow,
                DEVELOPMENT_CANDIDATE_RESULT_OFFSET_WORKSPACE_SNAPSHOT_BYTES,
                self.request.workspace_snapshot_cap_bytes + 2,
            ),
        )
        for frame in invalid:
            with self.assertRaises(DevelopmentCandidateProtocolError):
                parse_development_candidate_result(frame, request=self.request)

    def test_zero_byte_payloads_require_empty_sha256(self) -> None:
        for offset in (
            DEVELOPMENT_CANDIDATE_RESULT_OFFSET_STDOUT_SHA256,
            DEVELOPMENT_CANDIDATE_RESULT_OFFSET_STDERR_SHA256,
            DEVELOPMENT_CANDIDATE_RESULT_OFFSET_WORKSPACE_SNAPSHOT_SHA256,
        ):
            frame = mutate_result_bytes(self.frame, offset, digest(f"wrong-{offset}"))
            with self.subTest(offset=offset):
                with self.assertRaises(DevelopmentCandidateProtocolError):
                    parse_development_candidate_result(frame, request=self.request)

    def test_result_canonical_record_is_complete_and_permanently_nonauthorizing(self) -> None:
        result = parse_development_candidate_result(self.frame, request=self.request)
        record = development_candidate_result_record(result)
        payload = canonical_development_candidate_result_record_bytes(result)

        self.assertEqual(result.to_record(), record)
        self.assertEqual(result.canonical_record_bytes(), payload)
        self.assertEqual(json.loads(payload), record)
        self.assertNotIn(b" ", payload)
        self.assertEqual(record["wire_magic"], "CBDSBRS1")
        self.assertEqual(record["wait4_total_cpu_usec"], 0)
        self.assertEqual(record["request_sha256"], self.request.request_sha256.hex())
        for field in (
            "candidate_execution_authorized",
            "scored_evaluation_eligible",
            "model_selection_eligible",
            "claim_pipeline_eligible",
            "claim_authorized",
        ):
            self.assertIs(record[field], False)

    def test_result_rejects_nonexact_typed_fields_and_is_immutable(self) -> None:
        result = parse_development_candidate_result(self.frame, request=self.request)
        mutations = (
            {"outcome": 1},
            {"process_status": 1},
            {"flags": int(result.flags)},
            {"stdout_observed": True},
            {"child_signal": False},
            {"request_sha256": bytearray(result.request_sha256)},
            {"nonce": b"\0" * 32},
            {"result_sha256": digest("wrong-result")},
        )
        for changes in mutations:
            with self.subTest(changes=changes):
                with self.assertRaises(DevelopmentCandidateProtocolError):
                    replace(result, **changes)


class CandidateProtocolSafetyTests(unittest.TestCase):
    def test_protocol_exports_no_execution_launch_or_runner_api(self) -> None:
        exported = set(protocol.__all__)
        self.assertNotIn("_encode_development_candidate_result_for_tests", exported)
        for forbidden in (
            "execute_development_candidate",
            "run_development_candidate",
            "launch_development_candidate",
        ):
            self.assertNotIn(forbidden, exported)
            self.assertFalse(hasattr(protocol, forbidden))

    def test_security_validation_does_not_use_python_assert_statements(self) -> None:
        source = Path(protocol.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(tree)))

    def test_invalid_input_still_fails_under_optimized_python(self) -> None:
        code = "\n".join(
            (
                "from hashlib import sha256",
                "from cbds.development_candidate_protocol import DevelopmentCandidateRequest, DevelopmentCandidateProtocolError",
                "d = sha256(b'x').digest()",
                "try:",
                "    DevelopmentCandidateRequest(program_bytes=True, wall_timeout_usec=10000, cpu_time_limit_usec=1000, stdout_cap_bytes=1, stderr_cap_bytes=1, workspace_snapshot_cap_bytes=1, nonce=b'n'*32, invocation_sha256=d, program_sha256=d, fixture_definition_sha256=d, workspace_baseline_sha256=d, runtime_snapshot_sha256=d, allowed_tools_sha256=d, policy_sha256=d)",
                "except DevelopmentCandidateProtocolError:",
                "    raise SystemExit(0)",
                "raise SystemExit(9)",
            )
        )
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(ROOT / "src")
        completed = subprocess.run(
            (sys.executable, "-O", "-c", code),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            timeout=10,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", "replace"))


if __name__ == "__main__":
    unittest.main()
