from __future__ import annotations

import copy
from hashlib import sha256
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.development_preflight import (  # noqa: E402
    CANARY_UNIT,
    DEVELOPMENT_BACKEND,
    DEVELOPMENT_SCOPE,
    DevelopmentCommandResult,
    DevelopmentExecutableIdentity,
    DevelopmentPreflightLimits,
    HARMELESS_CANARY_STDIN,
    build_harmless_canary_argv,
    compute_development_preflight_sha256,
    inspect_development_backend,
    verify_development_preflight_sha256,
)


def identity(name: str) -> DevelopmentExecutableIdentity:
    return DevelopmentExecutableIdentity(
        name=name,
        resolved_path=f"/usr/bin/{name}",
        bytes=100 + len(name),
        sha256=sha256(name.encode()).hexdigest(),
    )


def stable_probe(
    name: str, _search_path: str, _maximum: int
) -> DevelopmentExecutableIdentity:
    return identity(name)


def passing_observation(workspace_bytes: int) -> bytes:
    return (
        json.dumps(
            {
                "schema_version": "1.0.0",
                "uid": 65534,
                "gid": 65534,
                "cap_eff": "0000000000000000",
                "no_new_privs": 1,
                "seccomp": 0,
                "interface_count": 1,
                "non_loopback_interfaces": 0,
                "workspace_type": "tmpfs",
                "workspace_capacity_bytes": workspace_bytes,
                "nested_userns_succeeded": 0,
                "root_writable": 0,
                "host_home_visible": 0,
                "host_sys_visible": 0,
            },
            separators=(",", ":"),
        )
        + "\n"
    ).encode()


class LimitsAndArgvTests(unittest.TestCase):
    def test_limits_reject_boolean_and_unsafe_values(self) -> None:
        for kwargs in (
            {"timeout_seconds": True},
            {"workspace_bytes": 1},
            {"pids": 1},
            {"open_files": 2},
            {"cpu_quota_percent": 1001},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    DevelopmentPreflightLimits(**kwargs)

    def test_canary_argv_is_fixed_isolated_and_stdin_driven(self) -> None:
        limits = DevelopmentPreflightLimits(
            memory_bytes=64 * 1024 * 1024,
            workspace_bytes=8 * 1024 * 1024,
            pids=12,
            open_files=24,
        )
        argv = build_harmless_canary_argv(
            systemd_run="/usr/bin/systemd-run",
            bwrap="/usr/bin/bwrap",
            bash="/usr/bin/bash",
            limits=limits,
        )

        self.assertEqual(argv[0], "/usr/bin/systemd-run")
        self.assertIn(f"--unit={CANARY_UNIT}", argv)
        self.assertIn("MemoryMax=67108864", argv)
        self.assertIn("MemorySwapMax=0", argv)
        self.assertIn("TasksMax=12", argv)
        self.assertIn("LimitNOFILE=24", argv)
        self.assertIn("KillMode=control-group", argv)
        self.assertIn("NoNewPrivileges=yes", argv)
        self.assertIn("RestrictAddressFamilies=AF_UNIX AF_NETLINK", argv)
        self.assertIn("--unshare-all", argv)
        self.assertIn("--unshare-user", argv)
        self.assertIn("--disable-userns", argv)
        self.assertIn("--assert-userns-disabled", argv)
        self.assertIn("--die-with-parent", argv)
        self.assertIn("--new-session", argv)
        self.assertIn("--clearenv", argv)
        self.assertIn("--ro-bind", argv)
        self.assertNotIn("--bind", argv)
        self.assertIn("--tmpfs", argv)
        root_chmod = len(argv) - 1 - tuple(reversed(argv)).index("--chmod")
        self.assertEqual(argv[root_chmod + 1 : root_chmod + 3], ("0555", "/"))
        workspace_size_index = argv.index("--size")
        self.assertEqual(argv[workspace_size_index + 1], str(8 * 1024 * 1024))
        self.assertNotIn("/home", argv)
        self.assertNotIn("/sys", argv)
        self.assertEqual(
            argv[-4:], ("/usr/bin/bash", "--noprofile", "--norc", "-s")
        )
        self.assertFalse(
            any(HARMELESS_CANARY_STDIN.decode() in argument for argument in argv)
        )

    def test_canary_builder_rejects_relative_or_outside_usr_bash(self) -> None:
        with self.assertRaises(ValueError):
            build_harmless_canary_argv(
                systemd_run="systemd-run",
                bwrap="/usr/bin/bwrap",
                bash="/usr/bin/bash",
            )
        with self.assertRaises(ValueError):
            build_harmless_canary_argv(
                systemd_run="/usr/bin/systemd-run",
                bwrap="/usr/bin/bwrap",
                bash="/opt/bash",
            )


class PreflightTests(unittest.TestCase):
    def test_default_is_metadata_only_and_never_calls_runner(self) -> None:
        called = False

        def forbidden_runner(*_args: object, **_kwargs: object) -> object:
            nonlocal called
            called = True
            raise AssertionError("runner must not be called")

        report = inspect_development_backend(
            executable_probe=stable_probe,
            runner=forbidden_runner,  # type: ignore[arg-type]
        )

        self.assertFalse(called)
        self.assertEqual(report["backend"], DEVELOPMENT_BACKEND)
        self.assertEqual(report["scope"], DEVELOPMENT_SCOPE)
        self.assertEqual(report["canary"]["status"], "not_requested")  # type: ignore[index]
        self.assertFalse(report["candidate_execution_authorized"])
        self.assertFalse(report["scored_evaluation_eligible"])
        self.assertFalse(report["claim_pipeline_eligible"])
        self.assertFalse(report["tool_policy_enforced"])
        blockers = report["decision"]["blockers"]  # type: ignore[index]
        self.assertIn("blocked_harmless_canary_not_run", blockers)
        self.assertIn("blocked_trusted_pid1_supervisor_missing", blockers)
        self.assertIn("blocked_child_seccomp_filter_missing", blockers)
        self.assertTrue(verify_development_preflight_sha256(report))

    def test_explicit_canary_gets_only_fixed_stdin_and_still_cannot_authorize(self) -> None:
        limits = DevelopmentPreflightLimits(workspace_bytes=4 * 1024 * 1024)
        calls: list[tuple[tuple[str, ...], dict[str, object]]] = []

        def runner(
            argv: tuple[str, ...], **kwargs: object
        ) -> DevelopmentCommandResult:
            calls.append((argv, kwargs))
            return DevelopmentCommandResult(
                returncode=0,
                stdout=passing_observation(limits.workspace_bytes),
            )

        report = inspect_development_backend(
            run_harmless_canary=True,
            limits=limits,
            executable_probe=stable_probe,
            runner=runner,
        )

        self.assertEqual(len(calls), 1)
        argv, kwargs = calls[0]
        self.assertEqual(kwargs["stdin"], HARMELESS_CANARY_STDIN)
        self.assertEqual(kwargs["unit"], CANARY_UNIT)
        self.assertFalse(any("uid=$(" in item for item in argv))
        self.assertEqual(report["canary"]["status"], "passed")  # type: ignore[index]
        self.assertFalse(report["candidate_execution_authorized"])
        blockers = report["decision"]["blockers"]  # type: ignore[index]
        self.assertNotIn("blocked_harmless_canary_not_run", blockers)
        self.assertIn("blocked_child_seccomp_filter_missing", blockers)
        self.assertTrue(verify_development_preflight_sha256(report))

    def test_missing_executable_prevents_explicit_canary(self) -> None:
        calls = 0

        def probe(
            name: str, search_path: str, maximum: int
        ) -> DevelopmentExecutableIdentity:
            if name == "bwrap":
                raise OSError("missing")
            return stable_probe(name, search_path, maximum)

        def runner(*_args: object, **_kwargs: object) -> DevelopmentCommandResult:
            nonlocal calls
            calls += 1
            return DevelopmentCommandResult(returncode=0)

        report = inspect_development_backend(
            run_harmless_canary=True,
            executable_probe=probe,
            runner=runner,
        )

        self.assertEqual(calls, 0)
        self.assertEqual(
            report["canary"]["status"],  # type: ignore[index]
            "not_run_unverified_executable",
        )
        self.assertIn(
            "blocked_bwrap_unverified",
            report["decision"]["blockers"],  # type: ignore[index]
        )

    def test_malformed_or_unsafe_canary_output_fails_closed(self) -> None:
        outputs = (
            b'{"uid":65534,"uid":65534}\n',
            passing_observation(16 * 1024 * 1024).replace(
                b'"non_loopback_interfaces":0',
                b'"non_loopback_interfaces":1',
            ),
        )
        for output in outputs:
            with self.subTest(output=output):
                report = inspect_development_backend(
                    run_harmless_canary=True,
                    executable_probe=stable_probe,
                    runner=lambda *_args, **_kwargs: DevelopmentCommandResult(
                        returncode=0, stdout=output
                    ),
                )
                self.assertNotEqual(report["canary"]["status"], "passed")  # type: ignore[index]
                self.assertIn(
                    "blocked_harmless_canary_failed",
                    report["decision"]["blockers"],  # type: ignore[index]
                )
                self.assertFalse(report["candidate_execution_authorized"])

    def test_executable_swap_after_canary_is_bound_into_decision(self) -> None:
        calls: dict[str, int] = {}

        def changing_probe(
            name: str, _search_path: str, _maximum: int
        ) -> DevelopmentExecutableIdentity:
            calls[name] = calls.get(name, 0) + 1
            current = identity(name)
            if name == "bwrap" and calls[name] > 1:
                return DevelopmentExecutableIdentity(
                    name=name,
                    resolved_path=current.resolved_path,
                    bytes=current.bytes,
                    sha256="f" * 64,
                )
            return current

        report = inspect_development_backend(executable_probe=changing_probe)
        self.assertFalse(report["all_executables_stable"])
        self.assertIn(
            "blocked_bwrap_changed",
            report["decision"]["blockers"],  # type: ignore[index]
        )

    def test_report_digest_rejects_mutation(self) -> None:
        report = inspect_development_backend(executable_probe=stable_probe)
        self.assertTrue(verify_development_preflight_sha256(report))
        mutated = copy.deepcopy(report)
        mutated["candidate_execution_authorized"] = True
        self.assertFalse(verify_development_preflight_sha256(mutated))
        mutated["report_sha256"] = compute_development_preflight_sha256(mutated)
        self.assertTrue(verify_development_preflight_sha256(mutated))


if __name__ == "__main__":
    unittest.main()
