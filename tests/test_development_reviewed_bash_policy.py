from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.development_candidate_protocol import (  # noqa: E402
    DEVELOPMENT_CANDIDATE_PROTOCOL_VERSION,
)
from cbds.development_candidate_workspace_snapshot import (  # noqa: E402
    DEVELOPMENT_CANDIDATE_WORKSPACE_OUTPUT_PROJECTION_SCOPE,
)
from cbds.development_reviewed_bash_policy import (  # noqa: E402
    DEVELOPMENT_REVIEWED_BASH_CHILD_ARGV,
    DEVELOPMENT_REVIEWED_BASH_CHILD_FSIZE_MAX_BYTES,
    DEVELOPMENT_REVIEWED_BASH_CPU_TIME_LIMIT_USEC,
    DEVELOPMENT_REVIEWED_BASH_GID,
    DEVELOPMENT_REVIEWED_BASH_HOSTNAME,
    DEVELOPMENT_REVIEWED_BASH_LAUNCHER_FSIZE_MAX_BYTES,
    DEVELOPMENT_REVIEWED_BASH_POLICY_SCOPE,
    DEVELOPMENT_REVIEWED_BASH_UID,
    DEVELOPMENT_REVIEWED_BASH_WALL_TIMEOUT_USEC,
    DevelopmentReviewedBashPolicyError,
    canonical_development_reviewed_bash_policy_bytes,
    development_reviewed_bash_policy_record,
    development_reviewed_bash_policy_sha256,
    validate_development_reviewed_bash_policy_record,
)


class DevelopmentReviewedBashPolicyTests(unittest.TestCase):
    def test_policy_is_canonical_complete_and_nonauthorizing(self) -> None:
        record = development_reviewed_bash_policy_record()
        validate_development_reviewed_bash_policy_record(record)
        payload = canonical_development_reviewed_bash_policy_bytes()
        self.assertEqual(json.loads(payload), record)
        self.assertEqual(sha256(payload).hexdigest(), development_reviewed_bash_policy_sha256())
        self.assertEqual(record["scope"], DEVELOPMENT_REVIEWED_BASH_POLICY_SCOPE)
        self.assertEqual(
            record["candidate_protocol_version"],
            DEVELOPMENT_CANDIDATE_PROTOCOL_VERSION,
        )
        namespace = record["namespace"]
        self.assertEqual(namespace["uid"], DEVELOPMENT_REVIEWED_BASH_UID)  # type: ignore[index]
        self.assertEqual(namespace["gid"], DEVELOPMENT_REVIEWED_BASH_GID)  # type: ignore[index]
        self.assertEqual(namespace["hostname"], DEVELOPMENT_REVIEWED_BASH_HOSTNAME)  # type: ignore[index]
        child = record["child"]
        self.assertEqual(child["argv"], list(DEVELOPMENT_REVIEWED_BASH_CHILD_ARGV))  # type: ignore[index]
        self.assertIs(child["dumpable_disabled_before_exec_only"], True)  # type: ignore[index]
        self.assertEqual(  # type: ignore[index]
            child["fsize_limit_bytes"],
            DEVELOPMENT_REVIEWED_BASH_CHILD_FSIZE_MAX_BYTES,
        )
        self.assertIs(  # type: ignore[index]
            child["fsize_limit_installed_by_native_before_exec"], True
        )
        self.assertIs(child["general_bash_seccomp_policy_verified"], False)  # type: ignore[index]
        limits = record["limits"]
        self.assertEqual(limits["wall_timeout_usec"], DEVELOPMENT_REVIEWED_BASH_WALL_TIMEOUT_USEC)  # type: ignore[index]
        self.assertEqual(limits["cpu_time_limit_usec"], DEVELOPMENT_REVIEWED_BASH_CPU_TIME_LIMIT_USEC)  # type: ignore[index]
        self.assertEqual(  # type: ignore[index]
            limits["launcher_fsize_max_bytes"],
            DEVELOPMENT_REVIEWED_BASH_LAUNCHER_FSIZE_MAX_BYTES,
        )
        self.assertEqual(  # type: ignore[index]
            limits["child_fsize_max_bytes"],
            DEVELOPMENT_REVIEWED_BASH_CHILD_FSIZE_MAX_BYTES,
        )
        self.assertGreater(
            DEVELOPMENT_REVIEWED_BASH_LAUNCHER_FSIZE_MAX_BYTES,
            DEVELOPMENT_REVIEWED_BASH_CHILD_FSIZE_MAX_BYTES,
        )
        self.assertEqual(  # type: ignore[index]
            limits["launcher_fsize_scope"],
            "bubblewrap-runtime-projection-and-native-supervisor",
        )
        snapshot = record["workspace_snapshot"]
        self.assertEqual(  # type: ignore[index]
            snapshot["scope"],
            DEVELOPMENT_CANDIDATE_WORKSPACE_OUTPUT_PROJECTION_SCOPE,
        )
        self.assertIs(snapshot["input_projection_serialized"], False)  # type: ignore[index]
        self.assertIs(  # type: ignore[index]
            snapshot["input_baseline_revalidated_after_cgroup_quiescence"],
            True,
        )
        self.assertIs(  # type: ignore[index]
            snapshot["output_projection_compared_to_pinned_workspace"],
            True,
        )
        boundary = record["evidence_boundaries"]
        for name in (
            "runtime_data_and_dlopen_closure_verified",
            "externally_trusted_launchers",
            "externally_trusted_runtime",
            "general_exact_tool_policy_enforced",
            "production_cumulative_cpu_enforcement_verified",
            "arbitrary_candidate_input_supported",
            "candidate_execution_authorized",
            "scored_evaluation_eligible",
            "model_selection_eligible",
            "claim_pipeline_eligible",
            "claim_authorized",
        ):
            self.assertIs(boundary[name], False)  # type: ignore[index]

    def test_any_nested_mutation_fails_exact_validation(self) -> None:
        mutations = []
        changed = deepcopy(development_reviewed_bash_policy_record())
        changed["scope"] = "other"
        mutations.append(changed)
        changed = deepcopy(development_reviewed_bash_policy_record())
        changed["namespace"]["uid"] = 0  # type: ignore[index]
        mutations.append(changed)
        changed = deepcopy(development_reviewed_bash_policy_record())
        changed["child"]["argv"].append("-c")  # type: ignore[index,union-attr]
        mutations.append(changed)
        changed = deepcopy(development_reviewed_bash_policy_record())
        changed["evidence_boundaries"]["claim_authorized"] = True  # type: ignore[index]
        mutations.append(changed)
        for changed in mutations:
            with self.subTest(keys=tuple(changed)):
                with self.assertRaises(DevelopmentReviewedBashPolicyError):
                    validate_development_reviewed_bash_policy_record(changed)

    def test_active_or_subclass_json_types_fail_before_their_hooks_run(self) -> None:
        class ActiveDict(dict[str, object]):
            def __eq__(self, other: object) -> bool:
                raise AssertionError("active dictionary equality ran")

        class ActiveList(list[object]):
            def __iter__(self):  # type: ignore[no-untyped-def]
                raise AssertionError("active list iteration ran")

        class ActiveString(str):
            def __eq__(self, other: object) -> bool:
                raise AssertionError("active string equality ran")

            __hash__ = str.__hash__

        class ActiveInteger(int):
            def __eq__(self, other: object) -> bool:
                raise AssertionError("active integer equality ran")

            __hash__ = int.__hash__

        values: list[object] = []
        values.append(ActiveDict(development_reviewed_bash_policy_record()))

        changed = development_reviewed_bash_policy_record()
        changed["child"]["argv"] = ActiveList(  # type: ignore[index]
            changed["child"]["argv"]  # type: ignore[index]
        )
        values.append(changed)

        changed = development_reviewed_bash_policy_record()
        changed["paths"]["workspace"] = ActiveString("/workspace")  # type: ignore[index]
        values.append(changed)

        changed = development_reviewed_bash_policy_record()
        changed["limits"]["tasks_max"] = ActiveInteger(32)  # type: ignore[index]
        values.append(changed)

        changed = development_reviewed_bash_policy_record()
        changed[ActiveString("unexpected")] = False
        values.append(changed)

        for value in values:
            with self.subTest(active_type=type(value).__name__):
                with self.assertRaises(DevelopmentReviewedBashPolicyError):
                    validate_development_reviewed_bash_policy_record(value)  # type: ignore[arg-type]

    def test_policy_and_snapshot_parser_share_one_projection_scope_constant(self) -> None:
        record = development_reviewed_bash_policy_record()
        self.assertIs(
            record["workspace_snapshot"]["scope"],  # type: ignore[index]
            DEVELOPMENT_CANDIDATE_WORKSPACE_OUTPUT_PROJECTION_SCOPE,
        )

    def test_module_is_safe_under_opposite_optimization_mode(self) -> None:
        opposite = ("-O",) if sys.flags.optimize == 0 else ()
        script = (
            "from cbds.development_reviewed_bash_policy import "
            "development_reviewed_bash_policy_record as r, "
            "validate_development_reviewed_bash_policy_record as v, "
            "development_reviewed_bash_policy_sha256 as h; "
            "x=r(); v(x); raise SystemExit(0 if len(h()) == 64 else 7)"
        )
        completed = subprocess.run(
            [sys.executable, *opposite, "-c", script],
            cwd=ROOT,
            env={"PYTHONPATH": str(ROOT / "src")},
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)


if __name__ == "__main__":
    unittest.main()
