from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from hashlib import sha256
import fcntl
import inspect
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import cbds.development_fd_handoff_canary as canary
from cbds.development_fd_handoff_canary import (
    DevelopmentFdHandoffCanaryError,
    run_development_fd_handoff_canary,
    verify_development_fd_handoff_canary_evidence,
)
from cbds.development_runtime_bundle import (
    DevelopmentRuntimeExecutable,
    build_development_runtime_bundle_manifest,
)
from cbds.development_runtime_fd_snapshot import (
    snapshot_development_runtime_for_launch,
)
from cbds.development_runtime_materializer import (
    materialize_development_runtime_bundle,
)


def _minimal_static_elf() -> bytes:
    identity = b"\x7fELF" + bytes((2, 1, 1, 0)) + b"\0" * 8
    header = struct.pack(
        "<HHIQQQIHHHHHH",
        2,
        62,
        1,
        0,
        64,
        0,
        0,
        64,
        56,
        1,
        0,
        0,
        0,
    )
    program = struct.pack(
        "<IIQQQQQQ",
        1,
        5,
        0,
        0,
        0,
        120,
        120,
        4096,
    )
    payload = identity + header + program
    if len(payload) != 120:
        raise RuntimeError("test ELF layout changed")
    return payload


class _RuntimeCase:
    def __init__(self, root: Path) -> None:
        self.source = root / "source"
        self.source.mkdir()
        self.payload = _minimal_static_elf()
        self.regular = self.source / "runtime.bin"
        self.regular.write_bytes(self.payload)
        self.regular.chmod(0o555)
        self.alias = self.source / "tool"
        self.alias.symlink_to("runtime.bin")
        self.manifest = build_development_runtime_bundle_manifest(
            (
                DevelopmentRuntimeExecutable(
                    name="tool",
                    source_path=str(self.alias),
                    expected_sha256=sha256(self.payload).hexdigest(),
                ),
            ),
            allowed_source_roots=(str(self.source),),
            library_search_directories=(str(self.source),),
        )
        self.evidence = materialize_development_runtime_bundle(
            self.manifest,
            root / "runtime-root",
            expected_manifest_sha256=self.manifest["manifest_sha256"],
        )

    def snapshot(self):
        return snapshot_development_runtime_for_launch(
            self.manifest,
            self.evidence,
            expected_manifest_sha256=self.manifest["manifest_sha256"],
        )


def _sealed_memfd(payload: bytes, *, seal: bool) -> int:
    descriptor = os.memfd_create(
        "cbds-canary-test",
        os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
    )
    try:
        written = os.write(descriptor, payload)
        if written != len(payload):
            raise RuntimeError("short test memfd write")
        if seal:
            required = (
                fcntl.F_SEAL_SEAL
                | fcntl.F_SEAL_SHRINK
                | fcntl.F_SEAL_GROW
                | fcntl.F_SEAL_WRITE
            )
            fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, required)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _private_child_probe(
    descriptor: int,
    *,
    pass_descriptor: bool,
    helper_source: str,
) -> dict[str, object]:
    executable_path, _digest, _identity, executable_descriptor = (
        canary._open_interpreter_identity()
    )
    try:
        return canary._bounded_child_probe(
            executable_path,
            executable_descriptor,
            descriptor,
            pass_descriptor=pass_descriptor,
            helper_source=helper_source,
        )
    finally:
        os.close(executable_descriptor)


class DevelopmentFdHandoffCanaryTests(unittest.TestCase):
    def test_canary_proves_only_exact_subprocess_sealed_payload_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            with case.snapshot() as snapshot:
                evidence = run_development_fd_handoff_canary(snapshot)

                regular = next(
                    entry for entry in snapshot.entries if entry.kind == "regular"
                )
                self.assertEqual(evidence.destination_path, regular.destination_path)
                self.assertEqual(evidence.expected_size, len(case.payload))
                self.assertEqual(
                    evidence.expected_content_sha256,
                    sha256(case.payload).hexdigest(),
                )
                self.assertEqual(
                    evidence.source_snapshot_sha256,
                    snapshot.snapshot_sha256,
                )
                self.assertEqual(evidence.negative_child_open_fds, (0, 1, 2))
                self.assertEqual(evidence.positive_child_open_fds[:3], (0, 1, 2))
                self.assertGreaterEqual(
                    evidence.positive_child_open_fds[3],
                    canary.HANDOFF_DESCRIPTOR_FLOOR,
                )
                self.assertTrue(evidence.source_descriptor_cloexec_verified)
                self.assertTrue(evidence.negative_exec_descriptor_absence_verified)
                self.assertTrue(evidence.explicit_pass_fds_survival_verified)
                self.assertTrue(evidence.inherited_descriptor_exact_binding_verified)
                self.assertTrue(evidence.inherited_descriptor_exclusivity_verified)
                self.assertTrue(evidence.sealed_payload_handoff_verified)
                self.assertTrue(evidence.subprocess_fd_handoff_verified)
                self.assertTrue(evidence.helper_source_binding_verified)
                self.assertTrue(evidence.child_executable_fd_binding_verified)
                self.assertTrue(evidence.fixed_probe_child_executed)
                self.assertFalse(evidence.externally_trusted_child_executable)
                self.assertFalse(evidence.harmless_probe_child_executed)
                self.assertFalse(evidence.systemd_scope_handoff_verified)
                self.assertFalse(evidence.bubblewrap_handoff_verified)
                self.assertFalse(evidence.namespace_runtime_closure_verified)
                self.assertFalse(evidence.materialized_mode_handoff_verified)
                self.assertFalse(evidence.fd_bound_launch_handoff)
                self.assertFalse(evidence.runtime_launch_performed)
                self.assertFalse(evidence.launch_eligible)
                self.assertFalse(evidence.candidate_program_present)
                self.assertFalse(evidence.candidate_execution_authorized)
                self.assertFalse(evidence.candidate_executed)
                self.assertFalse(evidence.scored_evaluation_eligible)
                self.assertFalse(evidence.claim_pipeline_eligible)
                self.assertTrue(
                    verify_development_fd_handoff_canary_evidence(evidence)
                )
                self.assertEqual(
                    evidence.to_record()["evidence_sha256"],
                    evidence.evidence_sha256,
                )
                self.assertEqual(len(evidence.helper_source_sha256), 64)
                self.assertEqual(len(evidence.child_executable_sha256), 64)
                with self.assertRaises(FrozenInstanceError):
                    evidence.launch_eligible = True  # type: ignore[misc]

    def test_parent_inheritable_fds_are_closed_and_memfd_offset_is_irrelevant(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            with case.snapshot() as snapshot:
                regular = next(
                    entry for entry in snapshot.entries if entry.kind == "regular"
                )
                duplicate = snapshot.duplicate_regular_fd(regular.destination_path)
                read_fd, write_fd = os.pipe()
                try:
                    os.lseek(duplicate, len(case.payload), os.SEEK_SET)
                    os.set_inheritable(read_fd, True)
                    os.set_inheritable(write_fd, True)
                    with mock.patch.object(
                        type(snapshot),
                        "duplicate_regular_fd",
                        return_value=duplicate,
                    ):
                        evidence = run_development_fd_handoff_canary(snapshot)
                    duplicate = -1
                    self.assertEqual(
                        evidence.negative_child_open_fds,
                        (0, 1, 2),
                    )
                    self.assertEqual(len(evidence.positive_child_open_fds), 4)
                    self.assertEqual(
                        evidence.child_content_sha256,
                        sha256(case.payload).hexdigest(),
                    )
                finally:
                    if duplicate >= 0:
                        os.close(duplicate)
                    os.close(read_fd)
                    os.close(write_fd)

    def test_closed_snapshot_and_non_snapshot_inputs_fail_before_child_launch(self) -> None:
        signature = inspect.signature(run_development_fd_handoff_canary)
        self.assertEqual(tuple(signature.parameters), ("snapshot",))
        with mock.patch.object(
            canary.subprocess,
            "Popen",
            side_effect=AssertionError("child launched"),
        ):
            with self.assertRaises(DevelopmentFdHandoffCanaryError):
                run_development_fd_handoff_canary(object())  # type: ignore[arg-type]

        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            snapshot = case.snapshot()
            with snapshot:
                self.assertFalse(snapshot.closed)
            self.assertTrue(snapshot.closed)
            with mock.patch.object(
                canary.subprocess,
                "Popen",
                side_effect=AssertionError("child launched"),
            ):
                with self.assertRaisesRegex(
                    DevelopmentFdHandoffCanaryError,
                    "already closed",
                ):
                    run_development_fd_handoff_canary(snapshot)

    def test_missing_platform_primitive_fails_before_descriptor_or_child(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            with case.snapshot() as snapshot:
                with (
                    mock.patch.object(fcntl, "F_GET_SEALS", None),
                    mock.patch.object(
                        type(snapshot),
                        "duplicate_regular_fd",
                        side_effect=AssertionError("descriptor duplicated"),
                    ),
                    mock.patch.object(
                        canary.subprocess,
                        "Popen",
                        side_effect=AssertionError("child launched"),
                    ),
                ):
                    with self.assertRaisesRegex(
                        DevelopmentFdHandoffCanaryError,
                        "primitive F_GET_SEALS is unavailable",
                    ):
                        run_development_fd_handoff_canary(snapshot)

    def test_unsealed_or_content_mismatched_memfd_fails_before_child(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            with case.snapshot() as snapshot:
                unsealed = _sealed_memfd(case.payload, seal=False)
                with (
                    mock.patch.object(
                        type(snapshot),
                        "duplicate_regular_fd",
                        return_value=unsealed,
                    ),
                    mock.patch.object(
                        canary.subprocess,
                        "Popen",
                        side_effect=AssertionError("child launched"),
                    ),
                ):
                    with self.assertRaisesRegex(
                        DevelopmentFdHandoffCanaryError,
                        "seals differ",
                    ):
                        run_development_fd_handoff_canary(snapshot)
                with self.assertRaises(OSError):
                    os.fstat(unsealed)

                altered = bytes((case.payload[0] ^ 1,)) + case.payload[1:]
                mismatched = _sealed_memfd(altered, seal=True)
                with (
                    mock.patch.object(
                        type(snapshot),
                        "duplicate_regular_fd",
                        return_value=mismatched,
                    ),
                    mock.patch.object(
                        canary.subprocess,
                        "Popen",
                        side_effect=AssertionError("child launched"),
                    ),
                ):
                    with self.assertRaisesRegex(
                        DevelopmentFdHandoffCanaryError,
                        "digest differs",
                    ):
                        run_development_fd_handoff_canary(snapshot)
                with self.assertRaises(OSError):
                    os.fstat(mismatched)

    def test_child_binding_mismatch_and_authority_forgery_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            with case.snapshot() as snapshot:
                with mock.patch.object(
                    canary,
                    "_bounded_child_probe",
                    side_effect=(
                        {"open_fds": [0, 1, 2], "state": "closed"},
                        {"open_fds": [0, 1, 2], "state": "open"},
                    ),
                ):
                    with self.assertRaisesRegex(
                        DevelopmentFdHandoffCanaryError,
                        "unexpected record",
                    ):
                        run_development_fd_handoff_canary(snapshot)

                evidence = run_development_fd_handoff_canary(snapshot)
                with self.assertRaises(DevelopmentFdHandoffCanaryError):
                    replace(evidence, launch_eligible=True)
                with self.assertRaises(DevelopmentFdHandoffCanaryError):
                    replace(evidence, evidence_sha256="0" * 64)
                self.assertFalse(
                    verify_development_fd_handoff_canary_evidence(object())
                )

    def test_child_frame_output_and_time_are_strictly_bounded(self) -> None:
        descriptor = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
        try:
            with self.assertRaisesRegex(
                DevelopmentFdHandoffCanaryError,
                "stdout exceeded its byte bound",
            ):
                _private_child_probe(
                    descriptor,
                    pass_descriptor=False,
                    helper_source="import sys; sys.stdout.write('x' * 5000)",
                )
            with mock.patch.object(
                canary,
                "HANDOFF_PROBE_TIMEOUT_SECONDS",
                0.05,
            ):
                with self.assertRaisesRegex(
                    DevelopmentFdHandoffCanaryError,
                    "timed out",
                ):
                    _private_child_probe(
                        descriptor,
                        pass_descriptor=False,
                        helper_source="import time; time.sleep(1)",
                    )
        finally:
            os.close(descriptor)

    def test_child_frame_rejects_duplicate_keys_and_non_integer_numbers(self) -> None:
        descriptor = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
        try:
            for frame in (
                r'''import sys; sys.stdout.write('{"state":"closed","state":"closed"}\n')''',
                r'''import sys; sys.stdout.write('{"state":1.0}\n')''',
            ):
                with self.subTest(frame=frame):
                    with self.assertRaisesRegex(
                        DevelopmentFdHandoffCanaryError,
                        "malformed bounded frame",
                    ):
                        _private_child_probe(
                            descriptor,
                            pass_descriptor=False,
                            helper_source=frame,
                        )
        finally:
            os.close(descriptor)

    def test_top_level_binds_helper_source_before_launch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            with case.snapshot() as snapshot, mock.patch.object(
                canary,
                "_HELPER_SOURCE",
                canary._HELPER_SOURCE + "\n# changed after import\n",
            ), mock.patch.object(
                canary.subprocess,
                "Popen",
                side_effect=AssertionError("child launched"),
            ):
                with self.assertRaisesRegex(
                    DevelopmentFdHandoffCanaryError,
                    "helper source differs from its frozen digest",
                ):
                    run_development_fd_handoff_canary(snapshot)

    def test_child_exec_uses_the_pinned_interpreter_descriptor(self) -> None:
        observed: list[tuple[str, tuple[int, ...]]] = []
        original = canary.subprocess.Popen

        def inspect_popen(*args, **kwargs):
            executable = kwargs.get("executable")
            passed = kwargs.get("pass_fds")
            if type(executable) is not str or not executable.startswith(
                "/proc/self/fd/"
            ):
                raise RuntimeError("child did not use an executable FD path")
            if type(passed) is not tuple:
                raise RuntimeError("child pass_fds is not an exact tuple")
            executable_fd = int(executable.rsplit("/", 1)[1])
            if executable_fd not in passed:
                raise RuntimeError("pinned executable FD was not inherited")
            observed.append((executable, passed))
            return original(*args, **kwargs)

        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            with case.snapshot() as snapshot, mock.patch.object(
                canary.subprocess,
                "Popen",
                side_effect=inspect_popen,
            ):
                evidence = run_development_fd_handoff_canary(snapshot)
                self.assertTrue(evidence.child_executable_fd_binding_verified)
        self.assertEqual(len(observed), 2)
        self.assertTrue(all(len(passed) in {1, 2} for _path, passed in observed))

    def test_module_has_no_assert_dependent_safety_checks(self) -> None:
        source = Path(canary.__file__).read_text(encoding="utf-8")
        self.assertNotIn("assert ", source)


if __name__ == "__main__":
    unittest.main()
