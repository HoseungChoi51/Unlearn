from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import cbds.executable_static_fourteenth_registry as registry_module  # noqa: E402
from cbds.executable_dependency_dag_execution_plan import (  # noqa: E402
    DEPENDENCY_DAG_EXECUTION_PLAN_GRAPH_ENCODINGS,
    DEPENDENCY_DAG_EXECUTION_PLAN_TIE_BREAK_POLICIES,
    DependencyDagExecutionPlanTask,
    compute_dependency_dag_execution_plan_discrimination_sha256,
)
from cbds.executable_static_fourteenth_registry import (  # noqa: E402
    FROZEN_FOURTEENTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_FOURTEENTH_REGISTRY_SHA256,
    FOURTEENTH_TRANCHE_ADDED_TASK_COUNT,
    FOURTEENTH_TRANCHE_CUMULATIVE_TASK_COUNT,
    FOURTEENTH_TRANCHE_FAMILY_ORDER,
    FourteenthTrancheRegistryError,
    build_fourteenth_tranche_added_tasks,
    build_fourteenth_tranche_task_registry,
    compute_fourteenth_tranche_cumulative_suite_sha256,
    compute_fourteenth_tranche_registry_sha256,
    validate_fourteenth_tranche_task_registry,
)
from cbds.executable_static_types import domain_sha256  # noqa: E402
from cbds.executable_thirteenth_predecessor_evidence import (  # noqa: E402
    FROZEN_THIRTEENTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_THIRTEENTH_REGISTRY_SHA256,
    THIRTEENTH_PREFIX_TASK_COUNT,
    build_thirteenth_prefix_task_evidence,
)


EXPECTED_DEPENDENCY_DAG_TASK_SET_SHA256 = (
    "57860e84d15ba33575b12b365f1f541b2537051a12e45f3ca470f1d14819c279"
)
EXPECTED_DEPENDENCY_DAG_DISCRIMINATION_SHA256 = (
    "25c9f68985ed918a6e8fe9d36b4b6d8a9bd34bb2cd9b039dff82a9276658c82c"
)
EXPECTED_FOURTEENTH_REGISTRY_SHA256 = (
    "c79de716570fe600f2dd7b1e3569456e6f42774d70143a309809410ad8097709"
)
EXPECTED_FOURTEENTH_CUMULATIVE_SUITE_SHA256 = (
    "497aac2c69daf2ff05e28b1f132090f3a380ce8ce215b63869a846d576616cf9"
)

class FourteenthTrancheTaskGridTests(unittest.TestCase):
    def test_grid_is_complete_exact_and_digest_computation_is_available(
        self,
    ) -> None:
        tasks = build_fourteenth_tranche_added_tasks()
        self.assertEqual(len(tasks), FOURTEENTH_TRANCHE_ADDED_TASK_COUNT)
        self.assertEqual(FOURTEENTH_TRANCHE_ADDED_TASK_COUNT, 20)
        self.assertEqual(FOURTEENTH_TRANCHE_CUMULATIVE_TASK_COUNT, 460)
        self.assertEqual(
            FOURTEENTH_TRANCHE_FAMILY_ORDER,
            ("dependency-dag-execution-plan",),
        )
        self.assertTrue(
            all(type(task) is DependencyDagExecutionPlanTask for task in tasks)
        )
        self.assertEqual(
            tuple(
                (
                    task.parameters.graph_encoding,
                    task.parameters.tie_break_policy,
                )
                for task in tasks
            ),
            tuple(
                (graph_encoding, tie_break_policy)
                for graph_encoding in (
                    DEPENDENCY_DAG_EXECUTION_PLAN_GRAPH_ENCODINGS
                )
                for tie_break_policy in (
                    DEPENDENCY_DAG_EXECUTION_PLAN_TIE_BREAK_POLICIES
                )
            ),
        )
        self.assertEqual(len({task.task_id for task in tasks}), 20)
        self.assertEqual(
            len({task.task_contract_sha256 for task in tasks}), 20
        )
        self.assertEqual(len({task.graph_sha256 for task in tasks}), 20)
        registry_sha256 = compute_fourteenth_tranche_registry_sha256(tasks)
        suite_sha256 = (
            compute_fourteenth_tranche_cumulative_suite_sha256(
                tasks, registry_sha256
            )
        )
        self.assertRegex(registry_sha256, r"[0-9a-f]{64}\Z")
        self.assertRegex(suite_sha256, r"[0-9a-f]{64}\Z")
        self.assertNotEqual(registry_sha256, suite_sha256)

class FourteenthTrancheTaskRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.predecessors = build_thirteenth_prefix_task_evidence()
        cls.registry = build_fourteenth_tranche_task_registry(
            cls.predecessors
        )

    def assert_registry_invalid(self, registry: object) -> None:
        with self.assertRaises(
            (FourteenthTrancheRegistryError, TypeError, ValueError)
        ):
            validate_fourteenth_tranche_task_registry(  # type: ignore[arg-type]
                registry
            )

    def test_grid_has_exact_type_order_and_unique_identities(self) -> None:
        tasks = self.registry.added_tasks
        self.assertEqual(len(tasks), FOURTEENTH_TRANCHE_ADDED_TASK_COUNT)
        self.assertTrue(
            all(type(task) is DependencyDagExecutionPlanTask for task in tasks)
        )
        self.assertEqual(
            tuple(
                (
                    task.parameters.graph_encoding,
                    task.parameters.tie_break_policy,
                )
                for task in tasks
            ),
            tuple(
                (graph_encoding, tie_break_policy)
                for graph_encoding in (
                    DEPENDENCY_DAG_EXECUTION_PLAN_GRAPH_ENCODINGS
                )
                for tie_break_policy in (
                    DEPENDENCY_DAG_EXECUTION_PLAN_TIE_BREAK_POLICIES
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
            self.registry.registry_sha256,
            EXPECTED_FOURTEENTH_REGISTRY_SHA256,
        )
        self.assertEqual(
            self.registry.registry_sha256,
            FROZEN_FOURTEENTH_REGISTRY_SHA256,
        )
        self.assertEqual(
            self.registry.cumulative_suite_sha256,
            EXPECTED_FOURTEENTH_CUMULATIVE_SUITE_SHA256,
        )
        self.assertEqual(
            self.registry.cumulative_suite_sha256,
            FROZEN_FOURTEENTH_CUMULATIVE_SUITE_SHA256,
        )
        self.assertEqual(
            self.registry.registry_sha256,
            compute_fourteenth_tranche_registry_sha256(tasks),
        )
        self.assertEqual(
            self.registry.cumulative_suite_sha256,
            compute_fourteenth_tranche_cumulative_suite_sha256(
                tasks, self.registry.registry_sha256
            ),
        )
        self.assertEqual(
            domain_sha256(
                (
                    "cbds.executable-method-development-coverage."
                    "integrated-task-set.v1"
                ),
                {
                    "family_id": "dependency-dag-execution-plan",
                    "task_count": len(tasks),
                    "task_id": [task.task_id for task in tasks],
                    "task_contract_sha256": [
                        task.task_contract_sha256 for task in tasks
                    ],
                    "graph_sha256": [
                        task.graph_sha256 for task in tasks
                    ],
                },
            ),
            EXPECTED_DEPENDENCY_DAG_TASK_SET_SHA256,
        )
        self.assertEqual(
            compute_dependency_dag_execution_plan_discrimination_sha256(
                tasks
            ),
            EXPECTED_DEPENDENCY_DAG_DISCRIMINATION_SHA256,
        )

    def test_exact_thirteenth_anchors_and_global_uniqueness(self) -> None:
        self.assertEqual(THIRTEENTH_PREFIX_TASK_COUNT, 440)
        self.assertEqual(
            self.predecessors.terminal_registry_sha256,
            FROZEN_THIRTEENTH_REGISTRY_SHA256,
        )
        self.assertEqual(
            self.predecessors.terminal_cumulative_suite_sha256,
            FROZEN_THIRTEENTH_CUMULATIVE_SUITE_SHA256,
        )
        self.assertEqual(
            self.registry.base_added_registry_sha256,
            FROZEN_THIRTEENTH_REGISTRY_SHA256,
        )
        self.assertEqual(
            self.registry.base_cumulative_suite_sha256,
            FROZEN_THIRTEENTH_CUMULATIVE_SUITE_SHA256,
        )
        tasks = (*self.predecessors.tasks, *self.registry.added_tasks)
        self.assertEqual(len(tasks), 460)
        self.assertEqual(len({task.task_id for task in tasks}), 460)
        self.assertEqual(
            len({task.task_contract_sha256 for task in tasks}), 460
        )
        self.assertEqual(len({task.graph_sha256 for task in tasks}), 460)

    def test_supplied_prefix_is_reused_without_rebuild(self) -> None:
        with mock.patch.object(
            registry_module,
            "build_thirteenth_prefix_task_evidence",
            side_effect=AssertionError("through-thirteenth prefix rebuilt"),
        ):
            rebuilt = build_fourteenth_tranche_task_registry(
                self.predecessors
            )
        self.assertEqual(rebuilt, self.registry)

    def test_repeated_builds_have_fresh_addition_ownership(self) -> None:
        first = build_fourteenth_tranche_added_tasks()
        second = build_fourteenth_tranche_added_tasks()
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        for left, right in zip(first, second, strict=True):
            self.assertIsNot(left, right)
            self.assertIsNot(left.parameters, right.parameters)
            self.assertTrue(
                all(left is not item for item in self.predecessors.tasks)
            )

    def test_hash_projection_and_mutations_fail_closed(self) -> None:
        record = self.registry.to_hash_only_record()
        self.assertEqual(
            record["record_type"],
            "cbds.executable-static-fourteenth-tranche-registry-hashes",
        )
        self.assertEqual(record["base_cumulative_task_count"], 440)
        self.assertEqual(record["added_task_count"], 20)
        self.assertEqual(record["cumulative_task_count"], 460)
        self.assertEqual(
            record["family_task_counts"],
            {"dependency-dag-execution-plan": 20},
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
            "graph_encoding",
            "yaml-adjacency",
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
            compute_fourteenth_tranche_registry_sha256(
                permuted.added_tasks
            )
        )
        alternate_suite_sha256 = (
            compute_fourteenth_tranche_cumulative_suite_sha256(
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
            EXPECTED_FOURTEENTH_REGISTRY_SHA256,
        )
        self.assert_registry_invalid(permuted)

        forged = copy.copy(self.registry)
        object.__setattr__(
            forged, "candidate_execution_authorized", True
        )
        self.assert_registry_invalid(forged)
        self.assert_registry_invalid(object())


if __name__ == "__main__":
    unittest.main()
