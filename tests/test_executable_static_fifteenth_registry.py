from __future__ import annotations

import ast
import copy
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import cbds.executable_static_fifteenth_registry as registry_module  # noqa: E402
from cbds.executable_fourteenth_predecessor_evidence import (  # noqa: E402
    FROZEN_FOURTEENTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_FOURTEENTH_REGISTRY_SHA256,
    FOURTEENTH_PREFIX_TASK_COUNT,
    build_fourteenth_prefix_task_evidence,
)
from cbds.executable_process_lifecycle_delta import (  # noqa: E402
    PROCESS_LIFECYCLE_DELTA_SELECTION_POLICIES,
    PROCESS_LIFECYCLE_DELTA_SNAPSHOT_PAIRS,
    ProcessLifecycleDeltaTask,
)
from cbds.executable_static_fifteenth_registry import (  # noqa: E402
    FIFTEENTH_TRANCHE_ADDED_TASK_COUNT,
    FIFTEENTH_TRANCHE_CUMULATIVE_TASK_COUNT,
    FIFTEENTH_TRANCHE_FAMILY_ORDER,
    FROZEN_FIFTEENTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_FIFTEENTH_REGISTRY_SHA256,
    FifteenthTrancheRegistryError,
    build_fifteenth_tranche_added_tasks,
    build_fifteenth_tranche_task_registry,
    compute_fifteenth_tranche_cumulative_suite_sha256,
    compute_fifteenth_tranche_registry_sha256,
    validate_fifteenth_tranche_task_registry,
)
from cbds.executable_static_types import domain_sha256  # noqa: E402


EXPECTED_FOURTEENTH_REGISTRY_SHA256 = (
    "c79de716570fe600f2dd7b1e3569456e6f42774d70143a309809410ad8097709"
)
EXPECTED_FOURTEENTH_CUMULATIVE_SUITE_SHA256 = (
    "497aac2c69daf2ff05e28b1f132090f3a380ce8ce215b63869a846d576616cf9"
)
EXPECTED_FIFTEENTH_REGISTRY_SHA256 = (
    "2d2773bcab7f83c99638541803516d893d3749b6c7b1b0091c6633f1c54493a5"
)
EXPECTED_FIFTEENTH_CUMULATIVE_SUITE_SHA256 = (
    "fce6939985a541c0bdb0e9f456b0e713f835b283a001e8a0f124047abe6ad99a"
)


class FifteenthTrancheTaskGridTests(unittest.TestCase):
    def test_grid_is_complete_exact_and_digest_computation_is_available(
        self,
    ) -> None:
        tasks = build_fifteenth_tranche_added_tasks()
        self.assertEqual(len(tasks), FIFTEENTH_TRANCHE_ADDED_TASK_COUNT)
        self.assertEqual(FIFTEENTH_TRANCHE_ADDED_TASK_COUNT, 20)
        self.assertEqual(FIFTEENTH_TRANCHE_CUMULATIVE_TASK_COUNT, 480)
        self.assertEqual(
            FIFTEENTH_TRANCHE_FAMILY_ORDER,
            ("process-lifecycle-delta",),
        )
        self.assertTrue(
            all(type(task) is ProcessLifecycleDeltaTask for task in tasks)
        )
        self.assertEqual(
            tuple(
                (
                    task.parameters.snapshot_pair,
                    task.parameters.selection_policy,
                )
                for task in tasks
            ),
            tuple(
                (snapshot_pair, selection_policy)
                for snapshot_pair in (
                    PROCESS_LIFECYCLE_DELTA_SNAPSHOT_PAIRS
                )
                for selection_policy in (
                    PROCESS_LIFECYCLE_DELTA_SELECTION_POLICIES
                )
            ),
        )
        self.assertEqual(len({task.task_id for task in tasks}), 20)
        self.assertEqual(
            len({task.task_contract_sha256 for task in tasks}), 20
        )
        self.assertEqual(len({task.graph_sha256 for task in tasks}), 20)
        registry_sha256 = compute_fifteenth_tranche_registry_sha256(tasks)
        suite_sha256 = (
            compute_fifteenth_tranche_cumulative_suite_sha256(
                tasks, registry_sha256
            )
        )
        self.assertRegex(registry_sha256, r"[0-9a-f]{64}\Z")
        self.assertRegex(suite_sha256, r"[0-9a-f]{64}\Z")
        self.assertNotEqual(registry_sha256, suite_sha256)


class FifteenthTrancheTaskRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.predecessors = build_fourteenth_prefix_task_evidence()
        cls.registry = build_fifteenth_tranche_task_registry(
            cls.predecessors
        )

    def assert_registry_invalid(self, registry: object) -> None:
        with self.assertRaises(
            (FifteenthTrancheRegistryError, TypeError, ValueError)
        ):
            validate_fifteenth_tranche_task_registry(  # type: ignore[arg-type]
                registry
            )

    def test_grid_has_exact_type_order_and_unique_identities(self) -> None:
        tasks = self.registry.added_tasks
        self.assertEqual(len(tasks), FIFTEENTH_TRANCHE_ADDED_TASK_COUNT)
        self.assertTrue(
            all(type(task) is ProcessLifecycleDeltaTask for task in tasks)
        )
        self.assertEqual(
            tuple(
                (
                    task.parameters.snapshot_pair,
                    task.parameters.selection_policy,
                )
                for task in tasks
            ),
            tuple(
                (snapshot_pair, selection_policy)
                for snapshot_pair in (
                    PROCESS_LIFECYCLE_DELTA_SNAPSHOT_PAIRS
                )
                for selection_policy in (
                    PROCESS_LIFECYCLE_DELTA_SELECTION_POLICIES
                )
            ),
        )
        self.assertEqual(len({task.task_id for task in tasks}), 20)
        self.assertEqual(
            len({task.task_contract_sha256 for task in tasks}), 20
        )
        self.assertEqual(len({task.graph_sha256 for task in tasks}), 20)
        for task in tasks:
            task.__post_init__()
            self.assertIs(task.public, True)
            self.assertIs(task.sealed, False)
            self.assertIs(task.candidate_execution_authorized, False)
            self.assertIs(task.model_selection_eligible, False)
            self.assertIs(task.claim_authorized, False)
            self.assertEqual(len(task.fixtures), 5)

    def test_hashes_are_frozen_and_domain_separated(self) -> None:
        tasks = self.registry.added_tasks
        self.assertEqual(
            FROZEN_FOURTEENTH_REGISTRY_SHA256,
            EXPECTED_FOURTEENTH_REGISTRY_SHA256,
        )
        self.assertEqual(
            FROZEN_FOURTEENTH_CUMULATIVE_SUITE_SHA256,
            EXPECTED_FOURTEENTH_CUMULATIVE_SUITE_SHA256,
        )
        self.assertEqual(
            self.registry.registry_sha256,
            EXPECTED_FIFTEENTH_REGISTRY_SHA256,
        )
        self.assertEqual(
            self.registry.registry_sha256,
            FROZEN_FIFTEENTH_REGISTRY_SHA256,
        )
        self.assertEqual(
            self.registry.cumulative_suite_sha256,
            EXPECTED_FIFTEENTH_CUMULATIVE_SUITE_SHA256,
        )
        self.assertEqual(
            self.registry.cumulative_suite_sha256,
            FROZEN_FIFTEENTH_CUMULATIVE_SUITE_SHA256,
        )
        self.assertEqual(
            self.registry.registry_sha256,
            compute_fifteenth_tranche_registry_sha256(tasks),
        )
        self.assertEqual(
            self.registry.cumulative_suite_sha256,
            compute_fifteenth_tranche_cumulative_suite_sha256(
                tasks, self.registry.registry_sha256
            ),
        )
        self.assertEqual(
            self.registry.cumulative_suite_sha256,
            domain_sha256(
                "cbds.executable-static."
                "fifteenth-tranche-cumulative-suite.v1",
                {
                    "base_cumulative_suite_sha256": (
                        EXPECTED_FOURTEENTH_CUMULATIVE_SUITE_SHA256
                    ),
                    "added_registry_sha256": (
                        EXPECTED_FIFTEENTH_REGISTRY_SHA256
                    ),
                    "cumulative_task_count": 480,
                },
            ),
        )
        wrong_domain = domain_sha256(
            "cbds.executable-static.fourteenth-tranche-cumulative-suite.v1",
            {
                "base_cumulative_suite_sha256": (
                    EXPECTED_FOURTEENTH_CUMULATIVE_SUITE_SHA256
                ),
                "added_registry_sha256": (
                    EXPECTED_FIFTEENTH_REGISTRY_SHA256
                ),
                "cumulative_task_count": 480,
            },
        )
        self.assertNotEqual(
            self.registry.cumulative_suite_sha256, wrong_domain
        )

    def test_exact_fourteenth_anchors_and_global_uniqueness(self) -> None:
        self.assertEqual(FOURTEENTH_PREFIX_TASK_COUNT, 460)
        self.assertEqual(
            self.predecessors.terminal_registry_sha256,
            EXPECTED_FOURTEENTH_REGISTRY_SHA256,
        )
        self.assertEqual(
            self.predecessors.terminal_cumulative_suite_sha256,
            EXPECTED_FOURTEENTH_CUMULATIVE_SUITE_SHA256,
        )
        self.assertEqual(
            self.registry.base_added_registry_sha256,
            EXPECTED_FOURTEENTH_REGISTRY_SHA256,
        )
        self.assertEqual(
            self.registry.base_cumulative_suite_sha256,
            EXPECTED_FOURTEENTH_CUMULATIVE_SUITE_SHA256,
        )
        tasks = (*self.predecessors.tasks, *self.registry.added_tasks)
        self.assertEqual(len(tasks), 480)
        self.assertEqual(len({task.task_id for task in tasks}), 480)
        self.assertEqual(
            len({task.task_contract_sha256 for task in tasks}), 480
        )
        self.assertEqual(len({task.graph_sha256 for task in tasks}), 480)

    def test_supplied_prefix_is_reused_without_rebuild(self) -> None:
        with mock.patch.object(
            registry_module,
            "build_fourteenth_prefix_task_evidence",
            side_effect=AssertionError("through-fourteenth prefix rebuilt"),
        ):
            rebuilt = build_fifteenth_tranche_task_registry(
                self.predecessors
            )
        self.assertEqual(rebuilt, self.registry)

    def test_repeated_builds_have_fresh_addition_ownership(self) -> None:
        first = build_fifteenth_tranche_added_tasks()
        second = build_fifteenth_tranche_added_tasks()
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        for left, right in zip(first, second, strict=True):
            self.assertIsNot(left, right)
            self.assertIsNot(left.parameters, right.parameters)
            self.assertTrue(
                all(left is not item for item in self.predecessors.tasks)
            )

    def test_global_identity_collision_is_rejected(self) -> None:
        colliding = copy.copy(self.predecessors)
        object.__setattr__(
            colliding,
            "tasks",
            (
                *self.predecessors.tasks[:-1],
                self.registry.added_tasks[0],
            ),
        )
        with (
            mock.patch.object(
                registry_module,
                "validate_fourteenth_prefix_task_evidence",
                return_value=None,
            ),
            self.assertRaisesRegex(
                FifteenthTrancheRegistryError,
                "collide with a frozen predecessor",
            ),
        ):
            registry_module._validate_live_base_and_global_uniqueness(  # noqa: SLF001
                self.registry.added_tasks,
                colliding,
            )

    def test_hash_projection_and_identity_mutations_fail_closed(self) -> None:
        record = self.registry.to_hash_only_record()
        self.assertEqual(
            record["record_type"],
            "cbds.executable-static-fifteenth-tranche-registry-hashes",
        )
        self.assertEqual(record["base_cumulative_task_count"], 460)
        self.assertEqual(record["added_task_count"], 20)
        self.assertEqual(record["cumulative_task_count"], 480)
        self.assertEqual(
            record["family_task_counts"],
            {"process-lifecycle-delta": 20},
        )
        self.assertIs(record["public_method_development"], True)
        for key in (
            "sealed",
            "candidate_execution_authorized",
            "model_selection_eligible",
            "claim_authorized",
        ):
            self.assertIs(record[key], False)

        reordered = copy.copy(self.registry)
        object.__setattr__(
            reordered,
            "added_tasks",
            (
                self.registry.added_tasks[1],
                self.registry.added_tasks[0],
                *self.registry.added_tasks[2:],
            ),
        )
        self.assert_registry_invalid(reordered)

        hostile = copy.deepcopy(self.registry)
        object.__setattr__(
            hostile.added_tasks[0].parameters,
            "snapshot_pair",
            "live-proc",
        )
        self.assert_registry_invalid(hostile)

        permuted = copy.deepcopy(self.registry)
        first = permuted.added_tasks[0]
        object.__setattr__(
            first,
            "fixtures",
            (
                first.fixtures[1],
                first.fixtures[0],
                *first.fixtures[2:],
            ),
        )
        alternate_registry_sha256 = (
            compute_fifteenth_tranche_registry_sha256(
                permuted.added_tasks
            )
        )
        alternate_suite_sha256 = (
            compute_fifteenth_tranche_cumulative_suite_sha256(
                permuted.added_tasks,
                alternate_registry_sha256,
            )
        )
        object.__setattr__(
            permuted, "registry_sha256", alternate_registry_sha256
        )
        object.__setattr__(
            permuted,
            "cumulative_suite_sha256",
            alternate_suite_sha256,
        )
        self.assertNotEqual(
            alternate_registry_sha256,
            EXPECTED_FIFTEENTH_REGISTRY_SHA256,
        )
        self.assert_registry_invalid(permuted)

        for field in (
            "base_added_registry_sha256",
            "base_cumulative_suite_sha256",
            "registry_sha256",
            "cumulative_suite_sha256",
        ):
            with self.subTest(field=field):
                forged_identity = copy.copy(self.registry)
                object.__setattr__(
                    forged_identity,
                    field,
                    "f" * 64,
                )
                self.assert_registry_invalid(forged_identity)
        self.assert_registry_invalid(object())

    def test_every_authority_mutation_fails_closed(self) -> None:
        for field, value in (
            ("public_method_development", False),
            ("sealed", True),
            ("candidate_execution_authorized", True),
            ("model_selection_eligible", True),
            ("claim_authorized", True),
        ):
            with self.subTest(field=field):
                forged = copy.copy(self.registry)
                object.__setattr__(forged, field, value)
                self.assert_registry_invalid(forged)

    def test_source_has_no_recursive_builder_cache_or_assert(self) -> None:
        source_path = (
            ROOT / "src/cbds/executable_static_fifteenth_registry.py"
        )
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported_names = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            for alias in node.names
        }
        self.assertIn(
            "build_fourteenth_prefix_task_evidence", imported_names
        )
        self.assertNotIn(
            "build_fourteenth_tranche_task_registry", imported_names
        )
        self.assertFalse(
            any(
                name.startswith("build_")
                and name.endswith("_tranche_task_registry")
                for name in imported_names
            )
        )
        self.assertNotIn("@lru_cache", source)
        self.assertNotIn("@cache", source)
        self.assertNotIn("functools", source)
        self.assertFalse(
            any(isinstance(node, ast.Assert) for node in ast.walk(tree))
        )


if __name__ == "__main__":
    unittest.main()
