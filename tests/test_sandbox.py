from __future__ import annotations

from dataclasses import FrozenInstanceError
import unittest

from cbds.response import ProgramLanguage
from cbds.sandbox import ContainerRuntime, SandboxConfig, build_sandbox_argv


PINNED_IMAGE = "registry.example/cbds/eval@sha256:" + "a" * 64


class SandboxConfigTests(unittest.TestCase):
    def test_config_is_immutable_and_normalizes_runtime_enum(self) -> None:
        config = SandboxConfig(image=PINNED_IMAGE, runtime="podman")  # type: ignore[arg-type]
        self.assertEqual(config.runtime, ContainerRuntime.PODMAN)
        with self.assertRaises(FrozenInstanceError):
            config.image = "changed"  # type: ignore[misc]

    def test_requires_digest_pinned_image(self) -> None:
        invalid = (
            "ubuntu:latest",
            "ubuntu@sha256:abc",
            "ubuntu:22.04@sha256:" + "a" * 64,
            "ubuntu@sha256:" + "A" * 64,
            "ubuntu @sha256:" + "a" * 64,
            "ubuntu@sha512:" + "a" * 64,
            "ubuntu@sha256:" + "a" * 64 + " --privileged",
        )
        for image in invalid:
            with self.subTest(image=image):
                with self.assertRaises(ValueError):
                    SandboxConfig(image=image)

    def test_rejects_root_ids_unsafe_workspace_and_invalid_limits(self) -> None:
        invalid_fields = (
            {"uid": 0},
            {"gid": 0},
            {"workspace": "/"},
            {"workspace": "relative"},
            {"workspace": "/work:evil"},
            {"workspace": "/work/../host"},
            {"workspace": "/workspace/"},
            {"workspace": "//workspace"},
            {"cpu_count": 0},
            {"cpu_count": float("nan")},
            {"memory_bytes": 1024},
            {"pids_limit": 0},
            {"output_bytes": 0},
            {"timeout_seconds": 0},
            {"tmpfs_bytes": 1024},
            {"open_files_limit": 2},
            {"umask": 0o1000},
            {"locale": "C\n--privileged"},
        )
        for fields in invalid_fields:
            with self.subTest(fields=fields):
                with self.assertRaises(ValueError):
                    SandboxConfig(image=PINNED_IMAGE, **fields)

class BuildSandboxArgvTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = SandboxConfig(
            image=PINNED_IMAGE,
            cpu_count=0.5,
            memory_bytes=128 * 1024 * 1024,
            pids_limit=32,
            tmpfs_bytes=16 * 1024 * 1024,
            output_bytes=4096,
            timeout_seconds=7,
            kill_grace_seconds=2,
            open_files_limit=20,
            uid=12345,
            gid=12346,
            umask=0o027,
        )

    def test_constructs_hardened_docker_argv(self) -> None:
        argv = build_sandbox_argv(self.config)

        self.assertIsInstance(argv, tuple)
        self.assertEqual(argv[:2], ("docker", "run"))
        required = {
            "--rm",
            "--interactive",
            "--init",
            "--network=none",
            "--pull=never",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--ipc=none",
            "--user=12345:12346",
            "--pids-limit=32",
            "--cpus=0.5",
            f"--memory={128 * 1024 * 1024}",
            f"--memory-swap={128 * 1024 * 1024}",
            "--stop-timeout=2",
            "--ulimit=nofile=20:20",
            "--ulimit=nproc=32:32",
            "--ulimit=core=0:0",
            "--workdir=/workspace",
            "--hostname=cbds-sandbox",
        }
        self.assertTrue(required.issubset(set(argv)))

        tmpfs = next(value for value in argv if value.startswith("--tmpfs="))
        self.assertIn("/workspace:rw,nosuid,nodev", tmpfs)
        self.assertNotIn("noexec", tmpfs)
        self.assertIn(f"size={16 * 1024 * 1024}", tmpfs)
        self.assertIn("uid=12345,gid=12346", tmpfs)

    def test_fixes_environment_umask_timeout_and_output_limit(self) -> None:
        argv = build_sandbox_argv(self.config)
        expected_env = {
            "--env=LANG=C.UTF-8",
            "--env=LC_ALL=C.UTF-8",
            "--env=TZ=UTC",
            "--env=HOME=/workspace",
            "--env=TMPDIR=/workspace/tmp",
            "--env=BASH_ENV=/dev/null",
            "--env=ENV=/dev/null",
            "--env=PYTHONHASHSEED=0",
        }
        self.assertTrue(expected_env.issubset(set(argv)))
        image_index = argv.index(PINNED_IMAGE)
        self.assertEqual(argv[image_index + 1 : image_index + 3], ("/usr/bin/env", "-i"))
        self.assertIn("LANG=C.UTF-8", argv[image_index + 3 :])

        runner = argv[-1]
        self.assertIn("umask 027", runner)
        self.assertIn("timeout --signal=TERM --kill-after=2s 7s", runner)
        self.assertEqual(runner.count("head -c 4096"), 2)

    def test_uses_stdin_and_contains_no_host_mount_or_socket(self) -> None:
        model_program = "echo NEVER_EMBED_MODEL_OUTPUT"
        argv = build_sandbox_argv(self.config)
        joined = "\n".join(argv)

        forbidden_tokens = ("--volume", "--mount", "-v", "docker.sock", "/var/run")
        for token in forbidden_tokens:
            with self.subTest(token=token):
                self.assertNotIn(token, argv)
                self.assertNotIn(token, joined)
        self.assertNotIn(model_program, joined)
        self.assertIn("/bin/bash --noprofile --norc -s", argv[-1])

    def test_python_uses_isolated_stdin_interpreter(self) -> None:
        argv = build_sandbox_argv(self.config, ProgramLanguage.PYTHON)
        self.assertIn("/usr/bin/python3 -I -", argv[-1])

    def test_podman_runtime_changes_only_client_selection(self) -> None:
        podman = SandboxConfig(image=PINNED_IMAGE, runtime=ContainerRuntime.PODMAN)
        argv = build_sandbox_argv(podman)
        self.assertEqual(argv[0], "podman")
        self.assertEqual(argv[1], "run")

    def test_rejects_invalid_arguments(self) -> None:
        with self.assertRaises(TypeError):
            build_sandbox_argv(PINNED_IMAGE)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            build_sandbox_argv(self.config, "ruby")  # type: ignore[arg-type]

    def test_argv_is_deterministic(self) -> None:
        self.assertEqual(build_sandbox_argv(self.config), build_sandbox_argv(self.config))


if __name__ == "__main__":
    unittest.main()
