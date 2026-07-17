from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import cbds.executable_static_thirteenth_registry as registry_module  # noqa: E402
from cbds.executable_nested_json_schema_migration import (  # noqa: E402
    NESTED_JSON_SCHEMA_MIGRATION_INPUT_SHAPES,
    NESTED_JSON_SCHEMA_MIGRATION_POLICIES,
    NestedJsonSchemaMigrationTask,
    compute_nested_json_schema_migration_discrimination_sha256,
)
from cbds.executable_static_thirteenth_registry import (  # noqa: E402
    FROZEN_THIRTEENTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_THIRTEENTH_REGISTRY_SHA256,
    THIRTEENTH_TRANCHE_ADDED_TASK_COUNT,
    THIRTEENTH_TRANCHE_CUMULATIVE_TASK_COUNT,
    THIRTEENTH_TRANCHE_FAMILY_ORDER,
    ThirteenthTrancheRegistryError,
    build_thirteenth_tranche_added_tasks,
    build_thirteenth_tranche_task_registry,
    compute_thirteenth_tranche_cumulative_suite_sha256,
    compute_thirteenth_tranche_registry_sha256,
    validate_thirteenth_tranche_task_registry,
)
from cbds.executable_static_types import domain_sha256  # noqa: E402
from cbds.executable_twelfth_predecessor_evidence import (  # noqa: E402
    FROZEN_TWELFTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_TWELFTH_REGISTRY_SHA256,
    TWELFTH_PREFIX_TASK_COUNT,
    build_twelfth_prefix_task_evidence,
)


EXPECTED_NESTED_JSON_MIGRATION_TASK_SET_SHA256 = (
    "2ab692e66a3090b5d05a204b18f4fdb99ddc822cdbaa5b7912b7ac2166680e0b"
)
EXPECTED_NESTED_JSON_MIGRATION_DISCRIMINATION_SHA256 = (
    "416907543c373f36e55098c514fbe17aeef0192d9e5dc43cd025bed809a0ad42"
)
EXPECTED_THIRTEENTH_REGISTRY_SHA256 = (
    "01990ca4355ef20736861d7bb7753e09e5ccbbfbddf8d21c4ffce3a451d83873"
)
EXPECTED_THIRTEENTH_CUMULATIVE_SUITE_SHA256 = (
    "bb7b78b68879eb32d4849bb5d82cac7a90b0695dc3fa72b9836dd7b6e70863e0"
)


class ThirteenthTrancheTaskRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.predecessors = build_twelfth_prefix_task_evidence()
        cls.registry = build_thirteenth_tranche_task_registry(
            cls.predecessors
        )

    def assert_registry_invalid(self, registry: object) -> None:
        with self.assertRaises(
            (ThirteenthTrancheRegistryError, TypeError, ValueError)
        ):
            validate_thirteenth_tranche_task_registry(  # type: ignore[arg-type]
                registry
            )

    def test_grid_has_exact_type_order_and_unique_identities(self) -> None:
        tasks = self.registry.added_tasks
        self.assertEqual(len(tasks), THIRTEENTH_TRANCHE_ADDED_TASK_COUNT)
        self.assertEqual(THIRTEENTH_TRANCHE_ADDED_TASK_COUNT, 20)
        self.assertEqual(THIRTEENTH_TRANCHE_CUMULATIVE_TASK_COUNT, 440)
        self.assertEqual(
            THIRTEENTH_TRANCHE_FAMILY_ORDER,
            ("nested-json-schema-migration",),
        )
        self.assertTrue(
            all(
                type(task) is NestedJsonSchemaMigrationTask
                for task in tasks
            )
        )
        self.assertEqual(
            tuple(
                (
                    task.parameters.input_shape,
                    task.parameters.migration_policy,
                )
                for task in tasks
            ),
            tuple(
                (input_shape, migration_policy)
                for input_shape in (
                    NESTED_JSON_SCHEMA_MIGRATION_INPUT_SHAPES
                )
                for migration_policy in (
                    NESTED_JSON_SCHEMA_MIGRATION_POLICIES
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
            EXPECTED_THIRTEENTH_REGISTRY_SHA256,
        )
        self.assertEqual(
            self.registry.registry_sha256,
            FROZEN_THIRTEENTH_REGISTRY_SHA256,
        )
        self.assertEqual(
            self.registry.cumulative_suite_sha256,
            EXPECTED_THIRTEENTH_CUMULATIVE_SUITE_SHA256,
        )
        self.assertEqual(
            self.registry.cumulative_suite_sha256,
            FROZEN_THIRTEENTH_CUMULATIVE_SUITE_SHA256,
        )
        self.assertEqual(
            self.registry.registry_sha256,
            compute_thirteenth_tranche_registry_sha256(tasks),
        )
        self.assertEqual(
            self.registry.cumulative_suite_sha256,
            compute_thirteenth_tranche_cumulative_suite_sha256(
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
                    "family_id": "nested-json-schema-migration",
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
            EXPECTED_NESTED_JSON_MIGRATION_TASK_SET_SHA256,
        )
        self.assertEqual(
            compute_nested_json_schema_migration_discrimination_sha256(
                tasks
            ),
            EXPECTED_NESTED_JSON_MIGRATION_DISCRIMINATION_SHA256,
        )

    def test_exact_twelfth_anchors_and_global_uniqueness(self) -> None:
        self.assertEqual(TWELFTH_PREFIX_TASK_COUNT, 420)
        self.assertEqual(
            self.predecessors.terminal_registry_sha256,
            FROZEN_TWELFTH_REGISTRY_SHA256,
        )
        self.assertEqual(
            self.predecessors.terminal_cumulative_suite_sha256,
            FROZEN_TWELFTH_CUMULATIVE_SUITE_SHA256,
        )
        self.assertEqual(
            self.registry.base_added_registry_sha256,
            FROZEN_TWELFTH_REGISTRY_SHA256,
        )
        self.assertEqual(
            self.registry.base_cumulative_suite_sha256,
            FROZEN_TWELFTH_CUMULATIVE_SUITE_SHA256,
        )
        tasks = (*self.predecessors.tasks, *self.registry.added_tasks)
        self.assertEqual(len(tasks), 440)
        self.assertEqual(len({task.task_id for task in tasks}), 440)
        self.assertEqual(
            len({task.task_contract_sha256 for task in tasks}), 440
        )
        self.assertEqual(len({task.graph_sha256 for task in tasks}), 440)

    def test_supplied_prefix_is_reused_without_rebuild(self) -> None:
        with mock.patch.object(
            registry_module,
            "build_twelfth_prefix_task_evidence",
            side_effect=AssertionError("through-twelfth prefix rebuilt"),
        ):
            rebuilt = build_thirteenth_tranche_task_registry(
                self.predecessors
            )
        self.assertEqual(rebuilt, self.registry)

    def test_repeated_builds_have_fresh_addition_ownership(self) -> None:
        first = build_thirteenth_tranche_added_tasks()
        second = build_thirteenth_tranche_added_tasks()
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
            "cbds.executable-static-thirteenth-tranche-registry-hashes",
        )
        self.assertEqual(record["base_cumulative_task_count"], 420)
        self.assertEqual(record["added_task_count"], 20)
        self.assertEqual(record["cumulative_task_count"], 440)
        self.assertEqual(
            record["family_task_counts"],
            {"nested-json-schema-migration": 20},
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
            "input_shape",
            "yaml-object",
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
            compute_thirteenth_tranche_registry_sha256(
                permuted.added_tasks
            )
        )
        alternate_suite_sha256 = (
            compute_thirteenth_tranche_cumulative_suite_sha256(
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
            EXPECTED_THIRTEENTH_REGISTRY_SHA256,
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
