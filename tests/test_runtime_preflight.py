from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.runtime_preflight import (  # noqa: E402
    CommandProbeResult,
    ExecutableIdentity,
    HostCgroupEvidence,
    PreflightLimits,
    RuntimePreflightError,
    build_preflight_argv,
    compute_preflight_report_sha256,
    inspect_container_runtime,
    verify_preflight_report_sha256,
)
from cbds import runtime_preflight  # noqa: E402


IMAGE = "registry.example/cbds/eval@sha256:" + "a" * 64
OTHER_IMAGE = "registry.example/cbds/eval@sha256:" + "b" * 64


def json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def executable(runtime: str, _path: str, _maximum: int) -> ExecutableIdentity:
    return ExecutableIdentity(f"/opt/bin/{runtime}", "c" * 64, 12345)


def cgroup(_maximum: int) -> HostCgroupEvidence:
    return HostCgroupEvidence(
        "verified", "v2", ("cpu", "io", "memory", "pids"), "d" * 64
    )


class FakeRunner:
    def __init__(self, results: dict[str, CommandProbeResult] | None = None) -> None:
        defaults = {
            "version": CommandProbeResult(
                0,
                json_bytes(
                    {
                        "Client": {"Version": "27.5.1"},
                        "Server": {"Version": "27.5.1"},
                    }
                ),
            ),
            "info": CommandProbeResult(
                0,
                json_bytes(
                    {
                        "Rootless": True,
                        "SecurityOptions": ["name=rootless"],
                        "CgroupVersion": "2",
                        "CgroupDriver": "systemd",
                    }
                ),
            ),
            "image_inspect": CommandProbeResult(
                0, json_bytes([{"RepoDigests": [IMAGE]}])
            ),
        }
        if results:
            defaults.update(results)
        self.results = defaults
        self.calls: list[tuple[tuple[str, ...], dict[str, object]]] = []

    def __call__(self, argv: tuple[str, ...], **kwargs: object) -> CommandProbeResult:
        self.calls.append((argv, kwargs))
        command_index = 2 if argv[1:2] == ("--remote=false",) else 1
        if argv[command_index] == "version":
            return self.results["version"]
        if argv[command_index] == "info":
            return self.results["info"]
        if argv[command_index : command_index + 2] == ("image", "inspect"):
            return self.results["image_inspect"]
        raise AssertionError(f"unexpected argv: {argv!r}")


class RuntimePreflightHappyPathTests(unittest.TestCase):
    def test_rootless_pinned_local_runtime_is_only_canary_eligible(self) -> None:
        runner = FakeRunner()
        report = inspect_container_runtime(
            "docker",
            IMAGE,
            runner=runner,
            executable_probe=executable,
            cgroup_probe=cgroup,
            environ={"PATH": "/attacker", "TOKEN": "secret"},
        )

        self.assertEqual(
            report["decision"]["status"],  # type: ignore[index]
            "eligible_for_benign_canary",
        )
        self.assertFalse(report["untrusted_execution_authorized"])
        self.assertEqual(report["executable"]["resolved_path"], "/opt/bin/docker")  # type: ignore[index]
        self.assertEqual(report["executable"]["sha256"], "c" * 64)  # type: ignore[index]
        self.assertTrue(report["engine"]["service_reachable"])  # type: ignore[index]
        self.assertEqual(
            report["engine"]["rootless_status"],  # type: ignore[index]
            "verified_rootless",
        )
        self.assertTrue(report["image"]["exact_repo_digest_match"])  # type: ignore[index]
        self.assertTrue(verify_preflight_report_sha256(report))
        self.assertEqual(len(runner.calls), 3)

        for _argv, kwargs in runner.calls:
            self.assertEqual(kwargs["timeout_seconds"], 5.0)
            self.assertEqual(kwargs["max_output_bytes"], 1024 * 1024)
            environment = kwargs["env"]
            self.assertIsInstance(environment, dict)
            self.assertNotIn("TOKEN", environment)
            self.assertNotEqual(environment["PATH"], "/attacker")

    def test_podman_engine_native_fields_are_supported(self) -> None:
        runner = FakeRunner(
            {
                "version": CommandProbeResult(0, json_bytes({"Version": "5.4.2"})),
                "info": CommandProbeResult(
                    0,
                    json_bytes(
                        {
                            "host": {
                                "security": {"rootless": True},
                                "cgroupVersion": "v2",
                                "cgroupManager": "systemd",
                            }
                        }
                    ),
                ),
            }
        )
        report = inspect_container_runtime(
            "podman",
            IMAGE,
            runner=runner,
            executable_probe=executable,
            cgroup_probe=cgroup,
            environ={"XDG_RUNTIME_DIR": f"/run/user/{os.getuid()}"},
        )
        self.assertEqual(report["decision"]["status"], "eligible_for_benign_canary")  # type: ignore[index]
        self.assertEqual(
            report["engine"]["rootless_evidence_source"],  # type: ignore[index]
            "info.host.security.rootless",
        )


class RuntimePreflightFailureTests(unittest.TestCase):
    def test_missing_executable_fails_closed_without_command_calls(self) -> None:
        runner = FakeRunner()
        with patch("cbds.runtime_preflight.shutil.which", return_value=None):
            report = inspect_container_runtime(
                "docker", IMAGE, runner=runner, cgroup_probe=cgroup, environ={}
            )
        self.assertEqual(report["decision"]["status"], "blocked_runtime_missing")  # type: ignore[index]
        self.assertEqual(runner.calls, [])
        self.assertTrue(verify_preflight_report_sha256(report))

    def test_rootful_runtime_is_rejected_even_when_everything_else_matches(self) -> None:
        runner = FakeRunner(
            {
                "info": CommandProbeResult(
                    0,
                    json_bytes(
                        {
                            "Rootless": False,
                            "CgroupVersion": 2,
                            "CgroupDriver": "systemd",
                        }
                    ),
                )
            }
        )
        report = inspect_container_runtime(
            "docker",
            IMAGE,
            runner=runner,
            executable_probe=executable,
            cgroup_probe=cgroup,
            environ={},
        )
        self.assertEqual(report["decision"]["status"], "blocked_rootful_runtime")  # type: ignore[index]
        self.assertIn("blocked_rootful_runtime", report["decision"]["blockers"])  # type: ignore[index]

    def test_contradictory_or_malformed_rootless_evidence_fails_closed(self) -> None:
        for options in (["name=rootless"], ["name=rootless", {"bad": True}]):
            with self.subTest(options=options):
                runner = FakeRunner(
                    {
                        "info": CommandProbeResult(
                            0,
                            json_bytes(
                                {
                                    "Rootless": False,
                                    "SecurityOptions": options,
                                    "CgroupVersion": 2,
                                    "CgroupDriver": "systemd",
                                }
                            ),
                        )
                    }
                )
                report = inspect_container_runtime(
                    "docker",
                    IMAGE,
                    runner=runner,
                    executable_probe=executable,
                    cgroup_probe=cgroup,
                    environ={},
                )
                self.assertNotEqual(
                    report["decision"]["status"],  # type: ignore[index]
                    "eligible_for_benign_canary",
                )
                self.assertIn(
                    "blocked_rootless_unverified",
                    report["decision"]["blockers"],  # type: ignore[index]
                )

    def test_missing_or_malformed_cgroup_manager_blocks_canary(self) -> None:
        for manager in (None, ["bad"], "cgroupfs"):
            with self.subTest(manager=manager):
                info: dict[str, object] = {
                    "Rootless": True,
                    "CgroupVersion": 2,
                }
                if manager is not None:
                    info["CgroupDriver"] = manager
                report = inspect_container_runtime(
                    "docker",
                    IMAGE,
                    runner=FakeRunner(
                        {"info": CommandProbeResult(0, json_bytes(info))}
                    ),
                    executable_probe=executable,
                    cgroup_probe=cgroup,
                    environ={},
                )
                self.assertIn(
                    "blocked_engine_cgroup_unverified",
                    report["decision"]["blockers"],  # type: ignore[index]
                )

    def test_malformed_output_fails_closed_and_is_not_retained(self) -> None:
        secret = b'{"Client":{"Version":"secret"}'
        runner = FakeRunner({"version": CommandProbeResult(0, secret)})
        report = inspect_container_runtime(
            "docker",
            IMAGE,
            runner=runner,
            executable_probe=executable,
            cgroup_probe=cgroup,
            environ={},
        )
        self.assertEqual(report["decision"]["status"], "blocked_version_probe")  # type: ignore[index]
        encoded = json_bytes(report)
        self.assertNotIn(secret, encoded)
        self.assertEqual(
            report["probes"]["version"]["stdout_sha256"],  # type: ignore[index]
            sha256(secret).hexdigest(),
        )

    def test_docker_version_requires_both_client_and_server_identity(self) -> None:
        report = inspect_container_runtime(
            "docker",
            IMAGE,
            runner=FakeRunner(
                {
                    "version": CommandProbeResult(
                        0, json_bytes({"Client": {"Version": "27.5.1"}})
                    )
                }
            ),
            executable_probe=executable,
            cgroup_probe=cgroup,
            environ={},
        )
        self.assertFalse(report["engine"]["version_fields_valid"])  # type: ignore[index]
        self.assertIn(
            "blocked_version_probe",
            report["decision"]["blockers"],  # type: ignore[index]
        )

    def test_executable_replacement_during_probes_fails_closed(self) -> None:
        calls = 0

        def changing_executable(
            runtime: str, _path: str, _maximum: int
        ) -> ExecutableIdentity:
            nonlocal calls
            calls += 1
            return ExecutableIdentity(
                f"/opt/bin/{runtime}",
                ("c" if calls == 1 else "e") * 64,
                12345,
            )

        report = inspect_container_runtime(
            "docker",
            IMAGE,
            runner=FakeRunner(),
            executable_probe=changing_executable,
            cgroup_probe=cgroup,
            environ={},
        )
        self.assertFalse(report["executable"]["stable_after_probes"])  # type: ignore[index]
        self.assertIn(
            "blocked_executable_changed",
            report["decision"]["blockers"],  # type: ignore[index]
        )

    def test_oversized_injected_output_fails_closed_and_is_bounded_in_report(self) -> None:
        limits = PreflightLimits(max_output_bytes=32)
        runner = FakeRunner(
            {"info": CommandProbeResult(0, b"x" * 100, b"y" * 100)}
        )
        report = inspect_container_runtime(
            "docker",
            IMAGE,
            limits=limits,
            runner=runner,
            executable_probe=executable,
            cgroup_probe=cgroup,
            environ={},
        )
        observation = report["probes"]["info"]  # type: ignore[index]
        self.assertEqual(observation["status"], "output_limit_exceeded")
        self.assertEqual(observation["stdout_bytes"], 32)
        self.assertEqual(observation["stderr_bytes"], 32)
        self.assertEqual(report["decision"]["status"], "blocked_probe_output_limit")  # type: ignore[index]
        self.assertNotIn("x" * 33, json.dumps(report))
        self.assertNotIn("y" * 33, json.dumps(report))

    def test_timeout_fails_closed(self) -> None:
        runner = FakeRunner(
            {"info": CommandProbeResult(None, timed_out=True)}
        )
        report = inspect_container_runtime(
            "docker",
            IMAGE,
            runner=runner,
            executable_probe=executable,
            cgroup_probe=cgroup,
            environ={},
        )
        self.assertEqual(report["decision"]["status"], "blocked_probe_timeout")  # type: ignore[index]
        self.assertEqual(report["probes"]["info"]["status"], "timeout")  # type: ignore[index]

    def test_local_digest_mismatch_is_distinct(self) -> None:
        runner = FakeRunner(
            {
                "image_inspect": CommandProbeResult(
                    0, json_bytes([{"RepoDigests": [OTHER_IMAGE]}])
                )
            }
        )
        report = inspect_container_runtime(
            "docker",
            IMAGE,
            runner=runner,
            executable_probe=executable,
            cgroup_probe=cgroup,
            environ={},
        )
        self.assertEqual(
            report["decision"]["status"], "blocked_image_digest_mismatch"  # type: ignore[index]
        )
        self.assertFalse(report["image"]["exact_repo_digest_match"])  # type: ignore[index]
        self.assertFalse(report["image"]["raw_repo_digests_retained"])  # type: ignore[index]

    def test_missing_controller_blocks_canary(self) -> None:
        def incomplete_cgroup(_maximum: int) -> HostCgroupEvidence:
            return HostCgroupEvidence("verified", "v2", ("cpu", "memory"), "e" * 64)

        report = inspect_container_runtime(
            "docker",
            IMAGE,
            runner=FakeRunner(),
            executable_probe=executable,
            cgroup_probe=incomplete_cgroup,
            environ={},
        )
        self.assertEqual(report["decision"]["status"], "blocked_cgroup_controllers")  # type: ignore[index]
        self.assertEqual(
            report["host_cgroup"]["missing_required_controllers"], ["pids"]  # type: ignore[index]
        )

    def test_host_probe_uses_the_current_cgroup_not_root_controllers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "cgroup"
            current = root / "user.slice" / "scope"
            current.mkdir(parents=True)
            (root / "cgroup.controllers").write_text(
                "cpu memory pids\n", encoding="ascii"
            )
            (current / "cgroup.controllers").write_text(
                "memory pids\n", encoding="ascii"
            )
            membership = Path(directory) / "self.cgroup"
            membership.write_text("0::/user.slice/scope\n", encoding="ascii")
            evidence = runtime_preflight._probe_cgroup(
                16 * 1024,
                membership_path=membership,
                cgroup_root=root,
            )
        self.assertEqual(evidence.status, "verified")
        self.assertEqual(evidence.controllers, ("memory", "pids"))
        report = inspect_container_runtime(
            "docker",
            IMAGE,
            runner=FakeRunner(),
            executable_probe=executable,
            cgroup_probe=lambda _maximum: evidence,
            environ={},
        )
        self.assertIn(
            "blocked_cgroup_controllers",
            report["decision"]["blockers"],  # type: ignore[index]
        )


class RuntimePreflightContractTests(unittest.TestCase):
    def test_argv_allowlist_has_only_read_only_metadata_commands(self) -> None:
        commands = build_preflight_argv("docker", "/usr/bin/docker", IMAGE)
        self.assertEqual(set(commands), {"version", "info", "image_inspect"})
        self.assertEqual(commands["version"][:2], ("/usr/bin/docker", "version"))
        self.assertEqual(commands["info"][:2], ("/usr/bin/docker", "info"))
        self.assertEqual(
            commands["image_inspect"][:3],
            ("/usr/bin/docker", "image", "inspect"),
        )
        for argv in commands.values():
            self.assertNotIn("run", argv)
            self.assertNotIn("pull", argv)
            self.assertNotIn("start", argv)
            self.assertNotIn("create", argv)
            self.assertNotIn("build", argv)
        podman = build_preflight_argv("podman", "/usr/bin/podman", IMAGE)
        for argv in podman.values():
            self.assertEqual(argv[:2], ("/usr/bin/podman", "--remote=false"))

    def test_requires_exact_untagged_repository_digest_and_known_runtime(self) -> None:
        invalid = (
            "ubuntu:latest",
            "ubuntu:22.04@sha256:" + "a" * 64,
            "localhost:5000@sha256:" + "a" * 64,
            "ubuntu@sha256:" + "A" * 64,
            "ubuntu@sha256:abc",
            "ubuntu @sha256:" + "a" * 64,
            "a" * 513,
        )
        for image in invalid:
            with self.subTest(image=image):
                with self.assertRaises(RuntimePreflightError):
                    inspect_container_runtime("docker", image)
        with self.assertRaises(RuntimePreflightError):
            inspect_container_runtime("nerdctl", IMAGE)
        self.assertEqual(
            inspect_container_runtime(
                "docker",
                "localhost:5000/repo@sha256:" + "a" * 64,
                runner=FakeRunner(),
                executable_probe=executable,
                cgroup_probe=cgroup,
                environ={},
            )["runtime"],
            "docker",
        )

    def test_report_hash_is_canonical_and_tamper_evident(self) -> None:
        report = inspect_container_runtime(
            "docker",
            IMAGE,
            runner=FakeRunner(),
            executable_probe=executable,
            cgroup_probe=cgroup,
            environ={},
        )
        digest = report["report_sha256"]
        self.assertEqual(digest, compute_preflight_report_sha256(report))
        reordered = dict(reversed(list(report.items())))
        self.assertEqual(digest, compute_preflight_report_sha256(reordered))
        tampered = dict(report)
        tampered["runtime"] = "podman"
        self.assertFalse(verify_preflight_report_sha256(tampered))

    def test_remote_or_secret_environment_is_scrubbed(self) -> None:
        runner = FakeRunner()
        inspect_container_runtime(
            "docker",
            IMAGE,
            runner=runner,
            executable_probe=executable,
            cgroup_probe=cgroup,
            environ={
                "DOCKER_HOST": "tcp://attacker.example:2375",
                "DOCKER_CONTEXT": "remote",
                "AWS_SECRET_ACCESS_KEY": "secret",
            },
        )
        for _argv, kwargs in runner.calls:
            environment = kwargs["env"]
            self.assertNotIn("DOCKER_HOST", environment)
            self.assertNotIn("DOCKER_CONTEXT", environment)
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", environment)


if __name__ == "__main__":
    unittest.main()
