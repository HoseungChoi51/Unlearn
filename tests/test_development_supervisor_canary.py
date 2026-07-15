from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError, replace
from hashlib import sha256
import inspect
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import cbds.development_supervisor_canary as canary  # noqa: E402
from cbds.development_supervisor_canary import (  # noqa: E402
    DEVELOPMENT_SUPERVISOR_CANARY_PATH,
    DEVELOPMENT_SUPERVISOR_CANARY_SCENARIOS,
    DevelopmentSupervisorCanaryError,
    DevelopmentSupervisorCanaryProcessResult,
    build_development_supervisor_canary_argv,
    build_development_supervisor_systemd_canary_argv,
    run_development_supervisor_lifecycle_canary,
    verify_development_supervisor_canary_evidence,
)
from cbds.development_supervisor_protocol import (  # noqa: E402
    DevelopmentSupervisorFlag,
    DevelopmentSupervisorOutcome,
    DevelopmentSupervisorProtocolError,
    DevelopmentSupervisorRequest,
    DevelopmentSupervisorScenario,
    _encode_development_supervisor_result_for_tests,
)


def _hash_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _native_source_sha256() -> str:
    return _hash_file(ROOT / "native" / "cbds-development-supervisor.c")


class _NativeCase:
    def __init__(self, root: Path) -> None:
        compiler = shutil.which("gcc")
        if compiler is None:
            raise unittest.SkipTest("gcc is unavailable")
        self.binary = root / "cbds-development-supervisor"
        completed = subprocess.run(
            (
                compiler,
                "-std=gnu17",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-static-pie",
                str(ROOT / "native" / "cbds-development-supervisor.c"),
                "-o",
                str(self.binary),
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        if completed.returncode != 0:
            raise unittest.SkipTest(
                "static supervisor compilation is unavailable: "
                + completed.stderr.decode("utf-8", errors="replace")[:300]
            )
        self.binary.chmod(0o555)
        self.binary_sha256 = _hash_file(self.binary)
        self.fake_bwrap = root / "bwrap-fixed"
        self.fake_bwrap.write_bytes(b"fixed test bwrap executable\n")
        self.fake_bwrap.chmod(0o555)


def _result_values(
    request: DevelopmentSupervisorRequest,
) -> tuple[
    DevelopmentSupervisorOutcome,
    int,
    int,
    DevelopmentSupervisorFlag,
    bytes,
    bytes,
    int,
    int,
    int,
]:
    mandatory = (
        DevelopmentSupervisorFlag.REQUEST_VALIDATED
        | DevelopmentSupervisorFlag.PID1_VERIFIED
        | DevelopmentSupervisorFlag.NO_NEW_PRIVS
        | DevelopmentSupervisorFlag.DUMPABLE_DISABLED
        | DevelopmentSupervisorFlag.SECCOMP_INSTALLED
        | DevelopmentSupervisorFlag.PRIMARY_REAPED
        | DevelopmentSupervisorFlag.ALL_DESCENDANTS_REAPED
        | DevelopmentSupervisorFlag.SOLE_PID1
    )
    scenario = request.scenario
    stdout = b""
    stderr = b""
    exit_code = 0
    child_signal = 0
    reaped = 1
    user_cpu = 0
    wall_usec = 1
    outcome = DevelopmentSupervisorOutcome.NORMAL
    flags = mandatory
    if scenario is DevelopmentSupervisorScenario.NORMAL:
        stdout = b"child-normal-stdout\n"
        stderr = b"child-normal-stderr\n"
    elif scenario is DevelopmentSupervisorScenario.DOUBLE_FORK_SETSID:
        stdout = b"escape-ready\n"
        reaped = 3
    elif scenario is DevelopmentSupervisorScenario.ZOMBIE:
        stdout = b"zombie-ready\n"
        reaped = 2
    elif scenario is DevelopmentSupervisorScenario.WALL_TIMEOUT:
        outcome = DevelopmentSupervisorOutcome.WALL_TIMEOUT
        flags |= DevelopmentSupervisorFlag.TIMED_OUT
        exit_code = -1
        child_signal = int(signal.SIGKILL)
        wall_usec = request.timeout_ms * 1000
    elif scenario is DevelopmentSupervisorScenario.STDOUT_FLOOD:
        outcome = DevelopmentSupervisorOutcome.STDOUT_OVERFLOW
        flags |= DevelopmentSupervisorFlag.STDOUT_OVERFLOW
        stdout = b"O" * (request.stdout_cap + 1)
        exit_code = 31
    elif scenario is DevelopmentSupervisorScenario.STDERR_FLOOD:
        outcome = DevelopmentSupervisorOutcome.STDERR_OVERFLOW
        flags |= DevelopmentSupervisorFlag.STDERR_OVERFLOW
        stderr = b"E" * (request.stderr_cap + 1)
        exit_code = 32
    elif scenario is DevelopmentSupervisorScenario.CPU_FANOUT:
        outcome = DevelopmentSupervisorOutcome.WALL_TIMEOUT
        flags |= DevelopmentSupervisorFlag.TIMED_OUT
        exit_code = -1
        child_signal = int(signal.SIGKILL)
        reaped = 4
        user_cpu = 1
        wall_usec = request.timeout_ms * 1000
    elif scenario is DevelopmentSupervisorScenario.FORBIDDEN_SYSCALL:
        outcome = DevelopmentSupervisorOutcome.SIGNAL
        exit_code = -1
        child_signal = int(signal.SIGSYS)
    elif scenario is DevelopmentSupervisorScenario.RESULT_FRAME_SPOOF:
        stdout = b"CBDSSRS1-child-spoof\n"
    else:  # pragma: no cover - enum is closed
        raise AssertionError(scenario)
    return (
        outcome,
        exit_code,
        child_signal,
        flags,
        stdout,
        stderr,
        reaped,
        user_cpu,
        wall_usec,
    )


def _frame_for(request: DevelopmentSupervisorRequest) -> bytes:
    (
        outcome,
        exit_code,
        child_signal,
        flags,
        stdout,
        stderr,
        reaped,
        user_cpu,
        wall_usec,
    ) = _result_values(request)
    return _encode_development_supervisor_result_for_tests(
        request,
        outcome=outcome,
        child_exit_code=exit_code,
        child_signal=child_signal,
        flags=flags,
        stdout_observed=len(stdout),
        stderr_observed=len(stderr),
        descendants_reaped=reaped,
        user_cpu_usec=user_cpu,
        wall_usec=wall_usec,
        stdout_sha256=sha256(stdout).digest(),
        stderr_sha256=sha256(stderr).digest(),
    )


def _fixed_runner(capture: list[tuple] | None = None):
    def runner(argv, **kwargs):
        if capture is not None:
            os.fstat(kwargs["supervisor_fd"])
            os.fstat(kwargs["bwrap"].descriptor)
            capture.append((argv, kwargs["request"], kwargs["supervisor_fd"]))
        return DevelopmentSupervisorCanaryProcessResult(
            returncode=0,
            stdout=_frame_for(kwargs["request"]),
        )

    return runner


def _spawn_fixed_outer_helper(
    *,
    stdout_bytes: int = 0,
    stderr_bytes: int = 0,
    linger: bool = False,
) -> subprocess.Popen[bytes]:
    """Start a candidate-free local pipe peer for direct outer-runner tests."""

    script = (
        "import sys, time\n"
        "sys.stdin.buffer.read()\n"
        "sys.stdout.buffer.write(b'S' * int(sys.argv[1]))\n"
        "sys.stderr.buffer.write(b'E' * int(sys.argv[2]))\n"
        "sys.stdout.buffer.flush()\n"
        "sys.stderr.buffer.flush()\n"
        "if sys.argv[3] == '1': time.sleep(60)\n"
    )
    return subprocess.Popen(
        (
            sys.executable,
            "-c",
            script,
            str(stdout_bytes),
            str(stderr_bytes),
            "1" if linger else "0",
        ),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        close_fds=True,
        start_new_session=True,
    )


def _dispose_fixed_outer_helper(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            process.kill()
        try:
            process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:  # pragma: no cover - defensive cleanup
            process.kill()
            process.wait(timeout=2.0)
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None and not stream.closed:
            stream.close()


def _fixed_outer_runner_call() -> tuple[tuple[str, ...], dict[str, object]]:
    request = DevelopmentSupervisorRequest(
        scenario=DevelopmentSupervisorScenario.NORMAL,
        timeout_ms=10,
        stdout_cap=1024,
        stderr_cap=1024,
        nonce=bytes(range(1, 33)),
    )
    bwrap = canary._PinnedFile(
        path="/usr/bin/bwrap",
        size=1,
        sha256="0" * 64,
        identity=(1, 2, 3, 4, 5, 6),
        descriptor=72,
    )
    systemd_run = canary._PinnedFile(
        path="/usr/bin/systemd-run",
        size=1,
        sha256="0" * 64,
        identity=(1, 2, 3, 4, 5, 6),
        descriptor=73,
    )
    systemctl = canary._PinnedFile(
        path="/usr/bin/systemctl",
        size=1,
        sha256="0" * 64,
        identity=(1, 2, 3, 4, 5, 6),
        descriptor=74,
    )
    unit_name = "cbds-supervisor-canary-v1-" + "1" * 32 + "-1.service"
    supervisor_fd = 71
    argv = build_development_supervisor_systemd_canary_argv(
        controller_pid=os.getpid(),
        supervisor_controller_fd=supervisor_fd,
        bwrap_controller_fd=bwrap.descriptor,
        unit_name=unit_name,
        systemd_run_path=systemd_run.path,
    )
    return argv, {
        "request_frame": canary.encode_development_supervisor_request(request),
        "request": request,
        "bwrap": bwrap,
        "supervisor_fd": supervisor_fd,
        "systemd_run": systemd_run,
        "systemctl": systemctl,
        "unit_name": unit_name,
    }


class DevelopmentSupervisorCanaryTests(unittest.TestCase):
    def test_native_source_compiles_strictly_and_refuses_non_pid1(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _NativeCase(Path(temporary))
            request = DevelopmentSupervisorRequest(
                scenario=DevelopmentSupervisorScenario.NORMAL,
                timeout_ms=100,
                stdout_cap=1024,
                stderr_cap=1024,
                nonce=bytes(range(1, 33)),
            )
            from cbds.development_supervisor_protocol import (  # noqa: PLC0415
                encode_development_supervisor_request,
            )

            completed = subprocess.run(
                (str(case.binary),),
                input=encode_development_supervisor_request(request),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=2,
                check=False,
            )
            self.assertEqual(completed.returncode, 111)
            self.assertEqual(completed.stdout, b"")
            self.assertEqual(completed.stderr, b"")

    def test_builder_is_fixed_candidate_free_and_uses_ro_bind_data(self) -> None:
        argv = build_development_supervisor_canary_argv(
            supervisor_fd=71,
            bwrap_path="/usr/bin/bwrap",
        )
        self.assertEqual(argv[0], "/usr/bin/bwrap")
        self.assertIn("--as-pid-1", argv)
        self.assertIn("--unshare-all", argv)
        self.assertIn("--ro-bind-data", argv)
        bind = argv.index("--ro-bind-data")
        self.assertEqual(argv[bind + 1 : bind + 3], ("71", DEVELOPMENT_SUPERVISOR_CANARY_PATH))
        self.assertNotIn("--ro-bind", argv)
        self.assertNotIn("--bind", argv)
        self.assertNotIn("/usr", argv)
        self.assertEqual(argv[-1], DEVELOPMENT_SUPERVISOR_CANARY_PATH)
        parameters = inspect.signature(
            run_development_supervisor_lifecycle_canary
        ).parameters
        self.assertEqual(
            tuple(parameters),
            (
                "supervisor_executable",
                "expected_native_source_sha256",
                "expected_supervisor_sha256",
                "bwrap",
                "suite_nonce",
                "runner",
            ),
        )
        forbidden = {"candidate", "program", "command", "argv", "fixture", "score"}
        self.assertFalse(forbidden & set(parameters))

        systemd_argv = build_development_supervisor_systemd_canary_argv(
            controller_pid=12345,
            supervisor_controller_fd=71,
            bwrap_controller_fd=72,
            unit_name=(
                "cbds-supervisor-canary-v1-" + "1" * 32 + "-1.service"
            ),
        )
        for property_value in (
            "MemoryMax=67108864",
            "MemorySwapMax=0",
            "TasksMax=32",
            "CPUQuota=100%",
            "LimitNOFILE=1024",
            "RuntimeMaxSec=5s",
            "KillMode=control-group",
            "NoNewPrivileges=yes",
        ):
            self.assertIn(property_value, systemd_argv)
        self.assertIn(
            "OpenFile=/proc/12345/fd/71:cbds-supervisor-v1:read-only",
            systemd_argv,
        )
        self.assertIn("/proc/12345/fd/72", systemd_argv)

        actual_build = (
            "/usr/bin/gcc",
            *canary._BUILD_ARGUMENTS,
            (
                "-ffile-prefix-map=/proc/self/fd/71="
                + str(canary._SOURCE_PATH)
            ),
            "-x",
            "c",
            "/proc/self/fd/71",
            "-o",
            "/tmp/cbds-supervisor-output",
        )
        self.assertEqual(
            canary._normalized_build_contract(actual_build),
            (
                "/usr/bin/gcc",
                *canary._BUILD_ARGUMENTS,
                (
                    "-ffile-prefix-map=@source-fd="
                    + str(canary._SOURCE_PATH)
                ),
                "-x",
                "c",
                str(canary._SOURCE_PATH),
                "-o",
                "@build-output",
            ),
        )
        with self.assertRaisesRegex(
            DevelopmentSupervisorCanaryError,
            "build argv",
        ):
            canary._normalized_build_contract(
                (*actual_build[:-3], str(canary._SOURCE_PATH), *actual_build[-2:])
            )

    def test_injected_complete_suite_is_valid_but_mints_no_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _NativeCase(Path(temporary))
            captured: list[tuple] = []
            evidence = run_development_supervisor_lifecycle_canary(
                str(case.binary),
                expected_native_source_sha256=_native_source_sha256(),
                expected_supervisor_sha256=case.binary_sha256,
                bwrap=str(case.fake_bwrap),
                suite_nonce=bytes(range(1, 33)),
                runner=_fixed_runner(captured),
            )

        self.assertEqual(
            tuple(item.request.scenario for item in evidence.scenarios),
            DEVELOPMENT_SUPERVISOR_CANARY_SCENARIOS,
        )
        self.assertEqual(len(captured), 9)
        self.assertTrue(evidence.runner_injected)
        self.assertFalse(evidence.default_runner_invoked)
        self.assertTrue(evidence.exact_result_frames_validated)
        self.assertTrue(evidence.reported_pid1_for_all_scenarios)
        self.assertTrue(evidence.reported_all_descendants_reaped_for_all_scenarios)
        self.assertTrue(evidence.systemd_cgroup_envelope_requested)
        self.assertEqual(evidence.suite_nonce_hex, bytes(range(1, 33)).hex())
        self.assertEqual(
            evidence.suite_nonce_sha256,
            sha256(bytes(range(1, 33))).hexdigest(),
        )
        self.assertIn("@build-output", evidence.build_contract_argv)
        self.assertIn("@controller-bwrap-fd", evidence.launch_contract_argv)
        self.assertIn("@service-supervisor-fd", evidence.launch_contract_argv)
        for name in (
            "externally_trusted_native_source",
            "externally_trusted_supervisor_binary",
            "externally_trusted_bwrap",
            "externally_trusted_systemd",
            "fixed_supervisor_executed_verified",
            "trusted_pid1_supervisor_implemented",
            "child_seccomp_filter_implemented",
            "cumulative_cpu_time_enforced",
            "exact_tool_policy_enforced",
            "runtime_data_and_dlopen_closure_verified",
            "candidate_execution_authorized",
            "candidate_executed",
            "scored_evaluation_eligible",
            "model_selection_eligible",
            "claim_pipeline_eligible",
        ):
            with self.subTest(name=name):
                self.assertFalse(getattr(evidence, name))
        self.assertTrue(verify_development_supervisor_canary_evidence(evidence))
        self.assertEqual(evidence.to_record()["evidence_sha256"], evidence.evidence_sha256)
        for _argv, _request, descriptor in captured:
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_bad_static_binary_pin_and_writable_source_fail_before_runner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _NativeCase(Path(temporary))
            with self.assertRaisesRegex(DevelopmentSupervisorCanaryError, "caller pin"):
                run_development_supervisor_lifecycle_canary(
                    str(case.binary),
                    expected_native_source_sha256=_native_source_sha256(),
                    expected_supervisor_sha256="0" * 64,
                    bwrap=str(case.fake_bwrap),
                    runner=lambda *_args, **_kwargs: self.fail("runner called"),
                )
            case.binary.chmod(0o755)
            with self.assertRaisesRegex(DevelopmentSupervisorCanaryError, "static ELF"):
                run_development_supervisor_lifecycle_canary(
                    str(case.binary),
                    expected_native_source_sha256=_native_source_sha256(),
                    expected_supervisor_sha256=case.binary_sha256,
                    bwrap=str(case.fake_bwrap),
                    runner=lambda *_args, **_kwargs: self.fail("runner called"),
                )

    def test_malformed_outer_results_fail_closed(self) -> None:
        variants = (
            DevelopmentSupervisorCanaryProcessResult(returncode=None, launch_error=True),
            DevelopmentSupervisorCanaryProcessResult(returncode=None, timed_out=True),
            DevelopmentSupervisorCanaryProcessResult(returncode=None, output_truncated=True),
            DevelopmentSupervisorCanaryProcessResult(returncode=1),
            DevelopmentSupervisorCanaryProcessResult(returncode=0, stdout=b"short"),
            DevelopmentSupervisorCanaryProcessResult(
                returncode=0,
                stdout=b"x" * 256,
                stderr=b"diagnostic",
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            case = _NativeCase(Path(temporary))
            for variant in variants:
                with self.subTest(variant=variant):
                    with self.assertRaises(
                        (DevelopmentSupervisorCanaryError, ValueError)
                    ):
                        run_development_supervisor_lifecycle_canary(
                            str(case.binary),
                            expected_native_source_sha256=_native_source_sha256(),
                            expected_supervisor_sha256=case.binary_sha256,
                            bwrap=str(case.fake_bwrap),
                            suite_nonce=bytes(range(1, 33)),
                            runner=lambda *_args, _value=variant, **_kwargs: _value,
                        )

    def test_wrong_fixed_observation_and_unknown_runner_type_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _NativeCase(Path(temporary))

            def wrong_stream(_argv, **kwargs):
                request = kwargs["request"]
                frame = _encode_development_supervisor_result_for_tests(
                    request,
                    outcome=DevelopmentSupervisorOutcome.NORMAL,
                    child_exit_code=0,
                    flags=(
                        DevelopmentSupervisorFlag.REQUEST_VALIDATED
                        | DevelopmentSupervisorFlag.PID1_VERIFIED
                        | DevelopmentSupervisorFlag.NO_NEW_PRIVS
                        | DevelopmentSupervisorFlag.DUMPABLE_DISABLED
                        | DevelopmentSupervisorFlag.SECCOMP_INSTALLED
                        | DevelopmentSupervisorFlag.PRIMARY_REAPED
                        | DevelopmentSupervisorFlag.ALL_DESCENDANTS_REAPED
                        | DevelopmentSupervisorFlag.SOLE_PID1
                    ),
                    descendants_reaped=1,
                    wall_usec=1,
                )
                return DevelopmentSupervisorCanaryProcessResult(
                    returncode=0,
                    stdout=frame,
                )

            with self.assertRaisesRegex(DevelopmentSupervisorCanaryError, "stream identity"):
                run_development_supervisor_lifecycle_canary(
                    str(case.binary),
                    expected_native_source_sha256=_native_source_sha256(),
                    expected_supervisor_sha256=case.binary_sha256,
                    bwrap=str(case.fake_bwrap),
                    suite_nonce=bytes(range(1, 33)),
                    runner=wrong_stream,
                )
            with self.assertRaisesRegex(DevelopmentSupervisorCanaryError, "wrong type"):
                run_development_supervisor_lifecycle_canary(
                    str(case.binary),
                    expected_native_source_sha256=_native_source_sha256(),
                    expected_supervisor_sha256=case.binary_sha256,
                    bwrap=str(case.fake_bwrap),
                    suite_nonce=bytes(range(1, 33)),
                    runner=lambda *_args, **_kwargs: object(),
                )

    def test_evidence_is_frozen_and_authority_forgery_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _NativeCase(Path(temporary))
            evidence = run_development_supervisor_lifecycle_canary(
                str(case.binary),
                expected_native_source_sha256=_native_source_sha256(),
                expected_supervisor_sha256=case.binary_sha256,
                bwrap=str(case.fake_bwrap),
                suite_nonce=bytes(range(1, 33)),
                runner=_fixed_runner(),
            )
        for kwargs in (
            {"trusted_pid1_supervisor_implemented": True},
            {"child_seccomp_filter_implemented": True},
            {"candidate_execution_authorized": True},
            {"claim_pipeline_eligible": True},
            {"evidence_sha256": "0" * 64},
            {"suite_nonce_hex": (b"z" * 32).hex()},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(DevelopmentSupervisorCanaryError):
                    replace(evidence, **kwargs)
        with self.assertRaises(FrozenInstanceError):
            evidence.candidate_execution_authorized = True  # type: ignore[misc]
        self.assertFalse(verify_development_supervisor_canary_evidence(object()))
        mismatched_request = canary._fixed_request(
            evidence.scenarios[0].request.scenario,
            b"z" * 32,
        )
        with self.assertRaises(DevelopmentSupervisorProtocolError):
            canary._construct_scenario_evidence(
                mismatched_request,
                evidence.scenarios[0].result,
            )

        def rehashed_forgery(**changes):
            forged = object.__new__(type(evidence))
            for field in evidence.__dataclass_fields__:
                object.__setattr__(
                    forged,
                    field,
                    changes.get(field, getattr(evidence, field)),
                )
            object.__setattr__(
                forged,
                "evidence_sha256",
                canary._compute_evidence_sha256(forged),
            )
            return forged

        forged_source = rehashed_forgery(
            native_source_path="/definitely/not/the/fixed/source.c",
        )
        self.assertFalse(
            verify_development_supervisor_canary_evidence(forged_source)
        )
        forged_default_runner = rehashed_forgery(
            runner_injected=False,
            default_runner_invoked=True,
            bwrap_path="/definitely/not/the/system/bwrap",
        )
        self.assertFalse(
            verify_development_supervisor_canary_evidence(forged_default_runner)
        )

    def test_rehashed_launch_contract_mutation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _NativeCase(Path(temporary))
            evidence = run_development_supervisor_lifecycle_canary(
                str(case.binary),
                expected_native_source_sha256=_native_source_sha256(),
                expected_supervisor_sha256=case.binary_sha256,
                bwrap=str(case.fake_bwrap),
                suite_nonce=bytes(range(1, 33)),
                runner=_fixed_runner(),
            )
        forged = object.__new__(type(evidence))
        for field in evidence.__dataclass_fields__:
            object.__setattr__(forged, field, getattr(evidence, field))
        mutated = list(evidence.launch_contract_argv)
        mutated.insert(-1, "--share-net")
        object.__setattr__(forged, "launch_contract_argv", tuple(mutated))
        object.__setattr__(
            forged,
            "launch_contract_sha256",
            sha256(canary.canonical_development_runtime_json_bytes(mutated)).hexdigest(),
        )
        object.__setattr__(forged, "evidence_sha256", canary._compute_evidence_sha256(forged))
        with self.assertRaisesRegex(DevelopmentSupervisorCanaryError, "fixed template"):
            canary._validate_evidence(forged)
        self.assertFalse(verify_development_supervisor_canary_evidence(forged))

    @unittest.skipUnless(
        os.environ.get("CBDS_RUN_LIVE_SUPERVISOR_CANARY") == "1",
        "set CBDS_RUN_LIVE_SUPERVISOR_CANARY=1 for rootless namespace integration",
    )
    def test_live_rootless_namespace_suite(self) -> None:
        bwrap = shutil.which("bwrap")
        if bwrap is None:
            self.skipTest("bwrap is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            case = _NativeCase(Path(temporary))
            evidence = run_development_supervisor_lifecycle_canary(
                str(case.binary),
                expected_native_source_sha256=_native_source_sha256(),
                expected_supervisor_sha256=case.binary_sha256,
                bwrap=bwrap,
                suite_nonce=bytes(range(1, 33)),
            )
        self.assertTrue(verify_development_supervisor_canary_evidence(evidence))
        self.assertFalse(evidence.runner_injected)
        self.assertTrue(evidence.default_runner_invoked)

    def test_security_checks_do_not_use_python_assert_statements(self) -> None:
        source = Path(canary.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(tree)))

    def test_outer_cleanup_never_swallows_an_unreaped_process(self) -> None:
        class StuckProcess:
            pid = 12345

            def wait(self, timeout):
                raise subprocess.TimeoutExpired(("fixed",), timeout)

            def kill(self):
                return None

        with mock.patch.object(canary.os, "killpg", return_value=None):
            with self.assertRaisesRegex(
                DevelopmentSupervisorCanaryError,
                "could not be reaped",
            ):
                canary._terminate_and_reap(StuckProcess())  # type: ignore[arg-type]

    def test_outer_cleanup_requires_quiescent_transient_unit(self) -> None:
        unit_name = "cbds-supervisor-canary-v1-" + "1" * 32 + "-1.service"
        systemctl = canary._PinnedFile(
            path="/usr/bin/systemctl",
            size=1,
            sha256="0" * 64,
            identity=(1, 2, 3, 4, 5, 6),
            descriptor=71,
        )

        class FinishedProcess:
            pid = 12345

            def __init__(self) -> None:
                self.returncode = None
                self.wait_calls = 0

            def wait(self, timeout):
                self.wait_calls += 1
                self.returncode = -int(signal.SIGKILL)
                return self.returncode

            def kill(self):
                self.returncode = -int(signal.SIGKILL)

        inactive = subprocess.CompletedProcess(
            ("systemctl",),
            0,
            stdout=(
                b"LoadState=not-found\n"
                b"SubState=dead\n"
                b"ControlGroup=\n"
                b"ActiveState=inactive\n"
            ),
            stderr=b"",
        )
        action = subprocess.CompletedProcess(("systemctl",), 0)
        process = FinishedProcess()
        with (
            mock.patch.object(
                canary.subprocess,
                "run",
                side_effect=(action, action, inactive),
            ) as run,
            mock.patch.object(canary.os, "killpg", return_value=None),
        ):
            canary._terminate_and_reap(
                process,  # type: ignore[arg-type]
                systemctl=systemctl,
                unit_name=unit_name,
            )
        self.assertEqual(process.wait_calls, 1)
        self.assertEqual(run.call_count, 3)
        self.assertIn("kill", run.call_args_list[0].args[0])
        self.assertIn("stop", run.call_args_list[1].args[0])
        self.assertIn("show", run.call_args_list[2].args[0])

        active = subprocess.CompletedProcess(
            ("systemctl",),
            0,
            stdout=(
                b"LoadState=loaded\n"
                b"ActiveState=active\n"
                b"SubState=running\n"
                b"ControlGroup=/user.slice/escape.service\n"
            ),
            stderr=b"",
        )
        process = FinishedProcess()
        with (
            mock.patch.object(
                canary.subprocess,
                "run",
                side_effect=(action, action, active),
            ),
            mock.patch.object(canary.os, "killpg", return_value=None),
        ):
            with self.assertRaisesRegex(
                DevelopmentSupervisorCanaryError,
                "not inactive and quiescent",
            ):
                canary._terminate_and_reap(
                    process,  # type: ignore[arg-type]
                    systemctl=systemctl,
                    unit_name=unit_name,
                )
        self.assertEqual(process.wait_calls, 1)

    def test_direct_outer_capture_uses_cap_plus_one_and_reaps(self) -> None:
        cases = (
            (257, 0, b"S" * 256, b""),
            (0, 4097, b"", b"E" * 4096),
        )
        for stdout_bytes, stderr_bytes, expected_stdout, expected_stderr in cases:
            with self.subTest(
                stdout_bytes=stdout_bytes,
                stderr_bytes=stderr_bytes,
            ):
                process = _spawn_fixed_outer_helper(
                    stdout_bytes=stdout_bytes,
                    stderr_bytes=stderr_bytes,
                )
                self.addCleanup(_dispose_fixed_outer_helper, process)
                argv, arguments = _fixed_outer_runner_call()
                with (
                    mock.patch.object(
                        canary.subprocess,
                        "Popen",
                        return_value=process,
                    ) as popen,
                    mock.patch.object(
                        canary,
                        "_stop_and_verify_unit",
                    ) as stop_unit,
                ):
                    result = canary._run_fixed_process(argv, **arguments)

                self.assertTrue(result.output_truncated)
                self.assertFalse(result.timed_out)
                self.assertEqual(result.stdout, expected_stdout)
                self.assertEqual(result.stderr, expected_stderr)
                self.assertIsNotNone(result.returncode)
                self.assertIsNotNone(process.poll())
                self.assertTrue(process.stdin.closed)
                self.assertTrue(process.stdout.closed)
                self.assertTrue(process.stderr.closed)
                stop_unit.assert_called_once_with(
                    arguments["systemctl"],
                    arguments["unit_name"],
                )
                self.assertEqual(
                    popen.call_args.kwargs["executable"],
                    "/proc/self/fd/73",
                )
                self.assertEqual(popen.call_args.kwargs["pass_fds"], (73,))

    def test_direct_outer_deadline_times_out_and_reaps(self) -> None:
        process = _spawn_fixed_outer_helper(linger=True)
        self.addCleanup(_dispose_fixed_outer_helper, process)
        argv, arguments = _fixed_outer_runner_call()
        with (
            mock.patch.object(
                canary.subprocess,
                "Popen",
                return_value=process,
            ),
            mock.patch.object(
                canary,
                "_stop_and_verify_unit",
            ) as stop_unit,
            mock.patch.object(canary, "monotonic", side_effect=(0.0, 3.0)),
        ):
            result = canary._run_fixed_process(argv, **arguments)

        self.assertTrue(result.timed_out)
        self.assertFalse(result.output_truncated)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"")
        self.assertIsNotNone(result.returncode)
        self.assertIsNotNone(process.poll())
        self.assertTrue(process.stdin.closed)
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)
        stop_unit.assert_called_once_with(
            arguments["systemctl"],
            arguments["unit_name"],
        )

    def test_direct_outer_normal_completion_fails_on_unit_nonquiescence(self) -> None:
        process = _spawn_fixed_outer_helper(stdout_bytes=256)
        self.addCleanup(_dispose_fixed_outer_helper, process)
        argv, arguments = _fixed_outer_runner_call()
        with (
            mock.patch.object(
                canary.subprocess,
                "Popen",
                return_value=process,
            ),
            mock.patch.object(
                canary,
                "_stop_and_verify_unit",
                side_effect=DevelopmentSupervisorCanaryError(
                    "transient supervisor unit is not inactive and quiescent"
                ),
            ) as stop_unit,
        ):
            with self.assertRaisesRegex(
                DevelopmentSupervisorCanaryError,
                "not inactive and quiescent",
            ):
                canary._run_fixed_process(argv, **arguments)

        self.assertIsNotNone(process.poll())
        self.assertTrue(process.stdin.closed)
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)
        stop_unit.assert_called_once_with(
            arguments["systemctl"],
            arguments["unit_name"],
        )

    def test_rebuild_closes_built_descriptor_after_post_open_failure(self) -> None:
        source = canary._open_pinned_file(
            str(canary._SOURCE_PATH),
            what="native supervisor source",
            executable=False,
            maximum_bytes=4 * 1024 * 1024,
        )
        compiler = canary._open_pinned_file(
            canary._COMPILER_PATH,
            what="fixed supervisor compiler",
            executable=True,
            maximum_bytes=canary._MAXIMUM_EXECUTABLE_BYTES,
        )
        opened: list[int] = []
        original_open = canary._open_pinned_file

        def recording_open(*args, **kwargs):
            value = original_open(*args, **kwargs)
            if kwargs.get("what") == "rebuilt supervisor executable":
                opened.append(value.descriptor)
            return value

        try:
            with (
                mock.patch.object(
                    canary,
                    "_open_pinned_file",
                    side_effect=recording_open,
                ),
                mock.patch.object(
                    canary,
                    "_verify_pinned_file",
                    side_effect=DevelopmentSupervisorCanaryError(
                        "post-open source identity failure"
                    ),
                ),
            ):
                with self.assertRaisesRegex(
                    DevelopmentSupervisorCanaryError,
                    "post-open source identity failure",
                ):
                    canary._rebuild_fixed_supervisor(source, compiler)
            self.assertEqual(len(opened), 1)
            with self.assertRaises(OSError):
                os.fstat(opened[0])
        finally:
            os.close(source.descriptor)
            os.close(compiler.descriptor)


if __name__ == "__main__":
    unittest.main()
