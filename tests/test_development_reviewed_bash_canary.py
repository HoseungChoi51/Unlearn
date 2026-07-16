from __future__ import annotations

import ast
from dataclasses import fields
import fcntl
from hashlib import sha256
import inspect
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import cbds.development_reviewed_bash_canary as canary  # noqa: E402
import cbds.development_candidate_protocol as protocol  # noqa: E402
from cbds.development_reviewed_bash_canary import (  # noqa: E402
    DEVELOPMENT_REVIEWED_BASH_MOUNT_FD_START,
    DEVELOPMENT_REVIEWED_BASH_NATIVE_FIXTURE_IDENTITY_FD,
    DEVELOPMENT_REVIEWED_BASH_NATIVE_PROGRAM_FD,
    DEVELOPMENT_REVIEWED_BASH_NATIVE_SOURCE_SHA256,
    DEVELOPMENT_REVIEWED_BASH_NATIVE_WORKSPACE_SNAPSHOT_FD,
    DevelopmentReviewedBashCanaryEvidence,
    DevelopmentReviewedBashCanaryError,
    DevelopmentReviewedBashCanaryProcessResult,
    build_development_reviewed_bash_canary_argv,
    run_development_reviewed_bash_canary,
    verify_development_reviewed_bash_canary_evidence,
)
from cbds.development_reviewed_bash_policy import (  # noqa: E402
    DEVELOPMENT_REVIEWED_BASH_HOSTNAME,
    DEVELOPMENT_REVIEWED_BASH_LAUNCHER_FSIZE_MAX_BYTES,
    DEVELOPMENT_REVIEWED_BASH_PROGRAM_PATH,
    DEVELOPMENT_REVIEWED_BASH_SUPERVISOR_PATH,
    DEVELOPMENT_REVIEWED_BASH_WORKSPACE_PATH,
)
from cbds.development_reviewed_bash_runtime import (  # noqa: E402
    development_reviewed_bash_runtime_host_compatibility,
    materialize_development_reviewed_bash_runtime,
)


_SNAPSHOT_HEADER = struct.Struct("<8sII")
_SNAPSHOT_ENTRY = struct.Struct("<B3sIIQ")


def _workspace_snapshot_bytes(root: Path) -> bytes:
    records: list[tuple[int, int, bytes, bytes]] = []

    def visit(path: Path, relative: bytes) -> None:
        metadata = os.lstat(path)
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISDIR(metadata.st_mode):
            records.append((1, mode, relative, b""))
            children = sorted(
                os.scandir(path),
                key=lambda item: item.name.encode("utf-8"),
            )
            for child in children:
                if not relative and child.name == "input":
                    continue
                name = child.name.encode("utf-8")
                nested = name if not relative else relative + b"/" + name
                visit(Path(child.path), nested)
        elif stat.S_ISREG(metadata.st_mode):
            records.append((2, mode, relative, path.read_bytes()))
        elif stat.S_ISLNK(metadata.st_mode):
            records.append(
                (3, mode, relative, os.readlink(path).encode("utf-8"))
            )
        else:
            raise AssertionError("test workspace contains an unsupported object")

    visit(root, b"")
    encoded = bytearray(_SNAPSHOT_HEADER.pack(b"CBDSWSN1", 1, len(records)))
    for kind, mode, path, payload in records:
        encoded.extend(
            _SNAPSHOT_ENTRY.pack(
                kind,
                b"\0\0\0",
                mode,
                len(path),
                len(payload),
            )
        )
        encoded.extend(path)
        encoded.extend(payload)
    return bytes(encoded)


def _write_oracle_output(workspace: Path, fixture: object) -> None:
    bundle = fixture.bundle  # type: ignore[attr-defined]
    for output in bundle.oracle.outputs:
        target = workspace / output.path
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        target.write_bytes(output.content)
        os.chmod(target, output.mode)


def _successful_injected_result(**changes: object):
    def runner(
        _argv: tuple[str, ...],
        *,
        request: object,
        workspace_handle: object,
        fixture_case: object,
        **_context: object,
    ) -> DevelopmentReviewedBashCanaryProcessResult:
        workspace = workspace_handle.workspace  # type: ignore[attr-defined]
        _write_oracle_output(workspace, fixture_case)
        raw = _workspace_snapshot_bytes(workspace)
        selected_raw = changes.get("returned_snapshot", raw)
        if changes.get("append_returned_snapshot") is True:
            selected_raw = raw + b"x"
        frame_raw = changes.get("framed_snapshot", raw)
        frame = protocol._encode_development_candidate_result_for_tests(  # noqa: SLF001
            request,
            workspace_snapshot_bytes=len(frame_raw),
            workspace_snapshot_sha256=sha256(frame_raw).digest(),
        )
        if changes.get("corrupt_result") is True:
            frame = b"X" + frame[1:]
        if changes.get("mutate_workspace_after_snapshot") is True:
            target = workspace / "output" / "paths.txt"
            target.write_bytes(b"wrong\n")
        return DevelopmentReviewedBashCanaryProcessResult(
            returncode=0,
            stdout=frame,
            workspace_snapshot=selected_raw,
        )

    return runner


class ReviewedBashCanaryStaticTests(unittest.TestCase):
    def test_public_surface_accepts_no_program_command_argv_or_fixture(self) -> None:
        run_parameters = inspect.signature(
            run_development_reviewed_bash_canary
        ).parameters
        self.assertEqual(tuple(run_parameters), ("nonce",))
        self.assertNotIn(
            "_exercise_development_reviewed_bash_canary_with_runner_for_tests",
            canary.__all__,
        )
        self.assertNotIn("ReviewedBashCanaryRunner", canary.__all__)
        with self.assertRaisesRegex(
            DevelopmentReviewedBashCanaryError,
            "built-in runner",
        ):
            canary._run_development_reviewed_bash_canary_impl(  # noqa: SLF001
                nonce=bytes(range(1, 33)),
                runner=lambda *_args, **_kwargs: DevelopmentReviewedBashCanaryProcessResult(0),
                export_evidence=True,
            )
        builder_parameters = inspect.signature(
            build_development_reviewed_bash_canary_argv
        ).parameters
        for forbidden in (
            "program",
            "command",
            "argv",
            "fixture",
            "response",
            "verifier",
            "score",
        ):
            self.assertNotIn(forbidden, builder_parameters)
            self.assertNotIn(forbidden, run_parameters)

    def test_native_roles_source_pin_and_authority_defaults_are_exact(self) -> None:
        self.assertEqual(
            (
                DEVELOPMENT_REVIEWED_BASH_NATIVE_PROGRAM_FD,
                DEVELOPMENT_REVIEWED_BASH_NATIVE_FIXTURE_IDENTITY_FD,
                DEVELOPMENT_REVIEWED_BASH_NATIVE_WORKSPACE_SNAPSHOT_FD,
                DEVELOPMENT_REVIEWED_BASH_MOUNT_FD_START,
            ),
            (3, 4, 5, 6),
        )
        source = ROOT / "native" / "cbds-development-candidate-supervisor.c"
        from hashlib import sha256

        self.assertEqual(
            sha256(source.read_bytes()).hexdigest(),
            DEVELOPMENT_REVIEWED_BASH_NATIVE_SOURCE_SHA256,
        )
        evidence_fields = {item.name: item for item in fields(DevelopmentReviewedBashCanaryEvidence)}
        for name in (
            "runtime_data_and_dlopen_closure_verified",
            "externally_trusted_native_source",
            "externally_trusted_supervisor",
            "externally_trusted_runtime",
            "externally_trusted_bwrap",
            "externally_trusted_systemd",
            "general_bash_seccomp_policy_verified",
            "exact_tool_policy_enforced",
            "production_cumulative_cpu_enforcement_verified",
            "candidate_execution_authorized",
            "candidate_executed",
            "scored_evaluation_eligible",
            "model_selection_eligible",
            "claim_pipeline_eligible",
            "claim_authorized",
        ):
            self.assertIs(evidence_fields[name].default, False)
        self.assertFalse(verify_development_reviewed_bash_canary_evidence(object()))

    def test_security_checks_do_not_use_python_assert(self) -> None:
        tree = ast.parse(Path(canary.__file__).read_text(encoding="utf-8"))
        self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(tree)))

    def test_reaped_outer_process_is_never_signaled_but_unit_cleanup_is_unconditional(self) -> None:
        class ReapedProcess:
            pid = 987654321

            def __init__(self) -> None:
                self.kill_calls = 0
                self.wait_calls = 0

            def poll(self) -> int:
                return 0

            def kill(self) -> None:
                self.kill_calls += 1

            def wait(self, timeout: float) -> int:
                self.wait_calls += 1
                self.assert_timeout = timeout
                return 0

        process = ReapedProcess()
        unit = "cbds-reviewed-bash-canary-v1-" + "2" * 32 + ".service"
        with mock.patch.object(canary, "_stop_and_verify_unit") as stop, mock.patch.object(
            canary.os, "killpg"
        ) as killpg:
            canary._terminate_and_reap(  # noqa: SLF001
                process,  # type: ignore[arg-type]
                systemctl=object(),  # type: ignore[arg-type]
                unit_name=unit,
            )
        stop.assert_called_once_with(mock.ANY, unit)
        killpg.assert_not_called()
        self.assertEqual(process.kill_calls, 0)
        self.assertEqual(process.wait_calls, 1)

    def test_snapshot_sink_is_sealed_only_after_stable_bounded_read(self) -> None:
        if not hasattr(os, "memfd_create"):
            self.skipTest("Linux memfd_create is unavailable")
        descriptor = canary._workspace_snapshot_sink()  # noqa: SLF001
        payload = b"CBDSWSN1" + b"x" * 32
        try:
            os.write(descriptor, payload)
            self.assertEqual(
                fcntl.fcntl(descriptor, fcntl.F_GET_SEALS),
                0,
            )
            self.assertEqual(
                canary._read_snapshot_sink(descriptor),  # noqa: SLF001
                payload,
            )
            expected = (
                fcntl.F_SEAL_WRITE
                | fcntl.F_SEAL_GROW
                | fcntl.F_SEAL_SHRINK
                | fcntl.F_SEAL_SEAL
            )
            self.assertEqual(fcntl.fcntl(descriptor, fcntl.F_GET_SEALS), expected)
            with self.assertRaises(OSError):
                os.pwrite(descriptor, b"z", 0)
        finally:
            os.close(descriptor)


class ReviewedBashCanaryArgvTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compatible, reason = development_reviewed_bash_runtime_host_compatibility()
        if not compatible:
            raise unittest.SkipTest("reviewed runtime unavailable: " + reason)

    def test_exact_builder_preserves_native_roles_and_projects_only_fixed_case(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with materialize_development_reviewed_bash_runtime(
                Path(temporary) / "runtime"
            ) as runtime:
                runtime_fds = tuple(range(100, 100 + len(runtime.regular_slots)))
                argv = build_development_reviewed_bash_canary_argv(
                    runtime,
                    controller_pid=12345,
                    program_controller_fd=71,
                    fixture_identity_controller_fd=72,
                    workspace_snapshot_controller_fd=73,
                    program_projection_controller_fd=74,
                    workspace_controller_fd=75,
                    runtime_controller_fds=runtime_fds,
                    supervisor_controller_fd=76,
                    bwrap_controller_fd=77,
                    unit_name="cbds-reviewed-bash-canary-v1-" + "1" * 32 + ".service",
                )
                self.assertLessEqual(
                    max(slot.size for slot in runtime.regular_slots),
                    DEVELOPMENT_REVIEWED_BASH_LAUNCHER_FSIZE_MAX_BYTES,
                )
        properties = [
            argv[index + 1]
            for index, item in enumerate(argv[:-1])
            if item == "--property"
        ]
        self.assertIn(
            "LimitFSIZE="
            + str(DEVELOPMENT_REVIEWED_BASH_LAUNCHER_FSIZE_MAX_BYTES),
            properties,
        )
        self.assertNotIn("LimitFSIZE=1048576", properties)
        openfiles = [
            argv[index + 1]
            for index, item in enumerate(argv[:-1])
            if item == "--property" and argv[index + 1].startswith("OpenFile=")
        ]
        self.assertEqual(
            [item.split(":", 2)[1] for item in openfiles[:3]],
            [
                "cbds-reviewed-program-native",
                "cbds-reviewed-fixture-identity",
                "cbds-reviewed-workspace-snapshot",
            ],
        )
        self.assertTrue(openfiles[0].endswith(":read-only"))
        self.assertTrue(openfiles[1].endswith(":read-only"))
        self.assertTrue(openfiles[2].endswith(":truncate"))
        program_bind = argv.index(DEVELOPMENT_REVIEWED_BASH_PROGRAM_PATH)
        self.assertEqual(
            argv[program_bind - 2:program_bind + 1],
            ("--ro-bind-data", "6", DEVELOPMENT_REVIEWED_BASH_PROGRAM_PATH),
        )
        workspace_bind = argv.index(DEVELOPMENT_REVIEWED_BASH_WORKSPACE_PATH)
        self.assertEqual(
            argv[workspace_bind - 2:workspace_bind + 1],
            ("--bind-fd", "7", DEVELOPMENT_REVIEWED_BASH_WORKSPACE_PATH),
        )
        self.assertIn(DEVELOPMENT_REVIEWED_BASH_HOSTNAME, argv)
        self.assertEqual(argv[-1], DEVELOPMENT_REVIEWED_BASH_SUPERVISOR_PATH)
        self.assertNotIn("-c", argv)
        normalized = canary._normalized_launch_argv(argv)  # noqa: SLF001
        self.assertIn("@controller-bwrap-fd", normalized)
        self.assertFalse(any("/proc/12345/fd/" in item for item in normalized))

    def test_complete_contract_rebuild_rejects_limit_env_mount_order_and_inventory_tampering(self) -> None:
        expected = canary._expected_normalized_launch_contract()  # noqa: SLF001
        variants: list[tuple[str, tuple[str, ...]]] = []

        values = list(expected)
        limit = values.index("MemoryMax=134217728")
        del values[limit - 1:limit + 1]
        variants.append(("omitted-limit", tuple(values)))

        values = list(expected)
        locale = values.index("LC_ALL")
        values[locale + 1] = "C.UTF-8"
        variants.append(("changed-environment", tuple(values)))

        values = list(expected)
        device = values.index("--dev")
        del values[device:device + 2]
        variants.append(("omitted-mount", tuple(values)))

        values = list(expected)
        first = values.index(
            "OpenFile=@controller-fd:cbds-reviewed-program-native:read-only"
        )
        second = values.index(
            "OpenFile=@controller-fd:cbds-reviewed-fixture-identity:read-only"
        )
        values[first], values[second] = values[second], values[first]
        variants.append(("changed-order", tuple(values)))

        variants.append(("extra-inventory", (*expected, "--unexpected")))

        with mock.patch.object(
            canary,
            "_expected_normalized_launch_contract",
            return_value=expected,
        ):
            canary._validate_normalized_launch_contract(expected)  # noqa: SLF001
            for label, changed in variants:
                with self.subTest(label=label), self.assertRaises(
                    DevelopmentReviewedBashCanaryError
                ):
                    canary._validate_normalized_launch_contract(changed)  # noqa: SLF001


class ReviewedBashCanaryInjectedFailureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compatible, reason = development_reviewed_bash_runtime_host_compatibility()
        if not compatible:
            raise unittest.SkipTest("reviewed runtime unavailable: " + reason)

    def exercise(self, runner: object) -> None:
        canary._exercise_development_reviewed_bash_canary_with_runner_for_tests(  # noqa: SLF001
            nonce=bytes(range(1, 33)),
            runner=runner,  # type: ignore[arg-type]
        )

    def test_private_injected_success_mints_no_evidence(self) -> None:
        self.assertIsNone(self.exercise(_successful_injected_result()))

    def test_result_snapshot_parser_and_workspace_mismatches_fail_closed(self) -> None:
        invalid_archive = b"not-a-snapshot!"
        cases = (
            ("corrupt-result", _successful_injected_result(corrupt_result=True)),
            (
                "result-snapshot-binding",
                _successful_injected_result(append_returned_snapshot=True),
            ),
            (
                "snapshot-parser",
                _successful_injected_result(
                    returned_snapshot=invalid_archive,
                    framed_snapshot=invalid_archive,
                ),
            ),
            (
                "workspace-comparison",
                _successful_injected_result(mutate_workspace_after_snapshot=True),
            ),
        )
        for label, runner in cases:
            with self.subTest(label=label), self.assertRaises(
                DevelopmentReviewedBashCanaryError
            ):
                self.exercise(runner)


@unittest.skipUnless(
    os.environ.get("CBDS_RUN_REVIEWED_BASH_CANARY_LIVE") == "1",
    "set CBDS_RUN_REVIEWED_BASH_CANARY_LIVE=1 for the rootless live canary",
)
class ReviewedBashCanaryLiveTests(unittest.TestCase):
    def test_fixed_reviewed_program_runs_and_candidate_remains_false(self) -> None:
        evidence = run_development_reviewed_bash_canary(
            nonce=bytes(range(1, 33))
        )
        self.assertTrue(verify_development_reviewed_bash_canary_evidence(evidence))
        self.assertTrue(evidence.reviewed_program_executed)
        self.assertTrue(evidence.fixture_verification.passed)
        self.assertFalse(evidence.candidate_executed)
        self.assertFalse(evidence.candidate_execution_authorized)
        self.assertFalse(evidence.scored_evaluation_eligible)
        self.assertFalse(evidence.model_selection_eligible)
        self.assertFalse(evidence.claim_authorized)

        def forge(**changes: object) -> DevelopmentReviewedBashCanaryEvidence:
            value = object.__new__(DevelopmentReviewedBashCanaryEvidence)
            for item in fields(DevelopmentReviewedBashCanaryEvidence):
                object.__setattr__(
                    value,
                    item.name,
                    changes.get(item.name, getattr(evidence, item.name)),
                )
            object.__setattr__(value, "evidence_sha256", "0" * 64)
            object.__setattr__(
                value,
                "evidence_sha256",
                canary._compute_evidence_sha256(value),  # noqa: SLF001
            )
            return value

        shortened = tuple(
            item
            for item in evidence.launch_contract_argv
            if item != "MemorySwapMax=0"
        )
        launch_forgery = forge(
            launch_contract_argv=shortened,
            launch_contract_sha256=sha256(
                canary._canonical(list(shortened))  # noqa: SLF001
            ).hexdigest(),
        )
        provenance_forgery = forge(runner_injected=True)
        baseline_forgery = forge(workspace_baseline_sha256="f" * 64)
        for label, changed in (
            ("launch", launch_forgery),
            ("provenance", provenance_forgery),
            ("workspace-binding", baseline_forgery),
        ):
            with self.subTest(label=label):
                self.assertFalse(
                    verify_development_reviewed_bash_canary_evidence(changed)
                )


if __name__ == "__main__":
    unittest.main()
