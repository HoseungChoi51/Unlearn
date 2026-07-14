from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.development_executor import (  # noqa: E402
    DEVELOPMENT_SUPERVISOR,
    DevelopmentExecutionBlocked,
    DevelopmentExecutionError,
    DevelopmentExecutionPolicy,
    PublicDevelopmentRequest,
    build_development_launch_argv,
    compute_development_execution_sha256,
    execute_public_development_candidate,
    prepare_public_development_execution,
    verify_development_execution_sha256,
)
from cbds.development_preflight import (  # noqa: E402
    DevelopmentExecutableIdentity,
    inspect_development_backend,
)
from cbds.static_families import (  # noqa: E402
    COPY_MAP_FAMILY,
    PublicStaticFamilySuite,
)


def stable_probe(
    name: str, _search_path: str, _maximum: int
) -> DevelopmentExecutableIdentity:
    return DevelopmentExecutableIdentity(
        name=name,
        resolved_path=f"/usr/bin/{name}",
        bytes=100,
        sha256=(name.encode().hex() + "0" * 64)[:64],
    )


def request() -> PublicDevelopmentRequest:
    suite = PublicStaticFamilySuite(COPY_MAP_FAMILY)
    descriptor = suite.descriptors[0]
    return PublicDevelopmentRequest(
        family=COPY_MAP_FAMILY,
        fixture_id=descriptor.fixture_id,
        fixture_sha256=descriptor.fixture_sha256,
    )


def preflight() -> dict[str, object]:
    return inspect_development_backend(executable_probe=stable_probe)


class RequestAndPolicyTests(unittest.TestCase):
    def test_real_public_descriptor_is_accepted(self) -> None:
        item = request()
        self.assertEqual(item.split_role, "method_development")
        self.assertTrue(item.public_fixture)
        self.assertFalse(item.sealed)
        self.assertEqual(item.program_language, "bash")

    def test_nonpublic_sealed_shadow_and_python_requests_are_rejected(self) -> None:
        valid = request()
        mutations = (
            {"family": "private-family"},
            {"split_role": "shadow_validation"},
            {"public_fixture": False},
            {"sealed": True},
            {"program_language": "python"},
            {"fixture_id": "fixture-secret"},
        )
        baseline = valid.to_record()
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                candidate = {**baseline, **mutation}
                with self.assertRaises(ValueError):
                    PublicDevelopmentRequest(**candidate)  # type: ignore[arg-type]

    def test_policy_rejects_invalid_limits(self) -> None:
        for kwargs in (
            {"fixture_timeout_seconds": True},
            {"kill_grace_seconds": 11},
            {"workspace_bytes": 1},
            {"uid": 0},
            {"stdout_bytes": 0},
            {"cpu_quota_percent": 1001},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    DevelopmentExecutionPolicy(**kwargs)


class LaunchPlanTests(unittest.TestCase):
    def test_fixed_launch_has_no_rw_host_bind_and_requires_pid1_isolation(self) -> None:
        policy = DevelopmentExecutionPolicy(
            workspace_bytes=8 * 1024 * 1024,
            memory_bytes=64 * 1024 * 1024,
            pids=16,
            open_files=32,
        )
        argv = build_development_launch_argv(policy)

        self.assertEqual(argv[0], "/usr/bin/systemd-run")
        self.assertIn("MemoryMax=67108864", argv)
        self.assertIn("MemorySwapMax=0", argv)
        self.assertIn("TasksMax=16", argv)
        self.assertIn("LimitNOFILE=32", argv)
        self.assertIn("OOMPolicy=kill", argv)
        self.assertIn("KillMode=control-group", argv)
        self.assertIn("NoNewPrivileges=yes", argv)
        self.assertIn("RestrictAddressFamilies=AF_UNIX AF_NETLINK", argv)
        self.assertIn("--unshare-all", argv)
        self.assertIn("--disable-userns", argv)
        self.assertIn("--assert-userns-disabled", argv)
        self.assertIn("--as-pid-1", argv)
        self.assertIn("--die-with-parent", argv)
        self.assertIn("--clearenv", argv)
        self.assertNotIn("--bind", argv)
        self.assertIn("--ro-bind", argv)
        self.assertIn("--tmpfs", argv)
        root_chmod = len(argv) - 1 - tuple(reversed(argv)).index("--chmod")
        self.assertEqual(argv[root_chmod + 1 : root_chmod + 3], ("0555", "/"))
        self.assertEqual(argv[argv.index("--size") + 1], str(8 * 1024 * 1024))
        self.assertNotIn("/home", argv)
        self.assertNotIn("/sys", argv)
        self.assertIn(DEVELOPMENT_SUPERVISOR, argv)

    def test_builder_rejects_untrusted_or_misaligned_paths(self) -> None:
        with self.assertRaises(DevelopmentExecutionError):
            build_development_launch_argv(systemd_run="systemd-run")
        with self.assertRaises(DevelopmentExecutionError):
            build_development_launch_argv(
                supervisor_bundle="/opt/cbds-development",
                supervisor="/tmp/supervisor",
            )

    def test_plan_is_content_safe_and_permanently_blocked(self) -> None:
        marker = "SECRET_PROGRAM_MARKER_9173"
        program = f"printf '%s\\n' {marker}\n"
        plan = prepare_public_development_execution(
            request(), program, preflight()
        )
        serialized = json.dumps(plan, sort_keys=True)

        self.assertNotIn(marker, serialized)
        self.assertFalse(plan["candidate_execution_authorized"])
        self.assertFalse(plan["candidate_executed"])
        self.assertFalse(plan["scored_evaluation_eligible"])
        self.assertFalse(plan["claim_pipeline_eligible"])
        self.assertFalse(plan["tool_policy_enforced"])
        self.assertFalse(plan["trusted_pid1_supervisor_implemented"])
        self.assertFalse(plan["child_seccomp_filter_implemented"])
        self.assertEqual(plan["program_plaintext_retained"], False)
        argv = plan["launch"]["argv"]  # type: ignore[index]
        self.assertFalse(any(marker in argument for argument in argv))
        self.assertEqual(plan["launch"]["host_read_write_binds"], [])  # type: ignore[index]
        blockers = plan["decision"]["blockers"]  # type: ignore[index]
        self.assertIn("blocked_trusted_pid1_supervisor_missing", blockers)
        self.assertIn("blocked_child_seccomp_filter_missing", blockers)
        self.assertIn("blocked_candidate_execution_not_implemented", blockers)
        self.assertTrue(verify_development_execution_sha256(plan))

    def test_execution_entrypoint_always_raises_before_launch(self) -> None:
        program = "printf safe\n"
        plan = prepare_public_development_execution(
            request(), program, preflight()
        )
        with self.assertRaises(DevelopmentExecutionBlocked) as captured:
            execute_public_development_candidate(plan, program)
        self.assertIn(
            "blocked_trusted_pid1_supervisor_missing", captured.exception.blockers
        )

    def test_program_mismatch_and_plan_mutation_fail_before_blocked_result(self) -> None:
        program = "printf safe\n"
        plan = prepare_public_development_execution(
            request(), program, preflight()
        )
        with self.assertRaises(DevelopmentExecutionError):
            execute_public_development_candidate(plan, "printf other\n")

        mutated = copy.deepcopy(plan)
        mutated["candidate_execution_authorized"] = True
        mutated["record_sha256"] = compute_development_execution_sha256(mutated)
        with self.assertRaises(DevelopmentExecutionError):
            execute_public_development_candidate(mutated, program)

    def test_forged_preflight_authorization_is_rejected_even_with_valid_digest(self) -> None:
        from cbds.development_preflight import compute_development_preflight_sha256

        forged = preflight()
        forged["candidate_execution_authorized"] = True
        forged["report_sha256"] = compute_development_preflight_sha256(forged)
        with self.assertRaises(DevelopmentExecutionError):
            prepare_public_development_execution(request(), "true\n", forged)

    def test_unverified_preflight_executable_cannot_produce_a_plan(self) -> None:
        def missing_probe(
            name: str, search_path: str, maximum: int
        ) -> DevelopmentExecutableIdentity:
            if name == "bwrap":
                raise OSError("missing")
            return stable_probe(name, search_path, maximum)

        blocked = inspect_development_backend(executable_probe=missing_probe)
        with self.assertRaises(DevelopmentExecutionError):
            prepare_public_development_execution(request(), "true\n", blocked)

    def test_oversize_empty_and_nontext_programs_are_rejected(self) -> None:
        selected = preflight()
        policy = DevelopmentExecutionPolicy(maximum_program_bytes=4)
        for program in ("", "12345", "bad\x00program", b"\xff", object()):
            with self.subTest(program=program):
                with self.assertRaises((DevelopmentExecutionError, TypeError)):
                    prepare_public_development_execution(
                        request(), program, selected, policy=policy  # type: ignore[arg-type]
                    )


if __name__ == "__main__":
    unittest.main()
