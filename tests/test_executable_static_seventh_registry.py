from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.executable_case_routed_batch_transform import (  # noqa: E402
    CASE_ROUTED_BATCH_TRANSFORM_FALLBACK_POLICIES,
    CASE_ROUTED_BATCH_TRANSFORM_ROUTE_KEYS,
    CaseRoutedBatchTransformTask,
)
from cbds.executable_static_fifth_registry import (  # noqa: E402
    build_fifth_tranche_task_registry,
)
from cbds.executable_static_fourth_registry import (  # noqa: E402
    build_fourth_tranche_task_registry,
)
from cbds.executable_static_registry import (  # noqa: E402
    build_public_method_development_registry,
)
from cbds.executable_static_second_registry import (  # noqa: E402
    build_second_tranche_task_registry,
)
from cbds.executable_static_seventh_registry import (  # noqa: E402
    FROZEN_FIRST_REGISTRY_SHA256,
    FROZEN_FIRST_SUITE_SHA256,
    FROZEN_SECOND_ADDED_REGISTRY_SHA256,
    FROZEN_SECOND_CUMULATIVE_SUITE_SHA256,
    FROZEN_THIRD_ADDED_REGISTRY_SHA256,
    FROZEN_THIRD_CUMULATIVE_SUITE_SHA256,
    FROZEN_FOURTH_ADDED_REGISTRY_SHA256,
    FROZEN_FOURTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_FIFTH_ADDED_REGISTRY_SHA256,
    FROZEN_FIFTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_SIXTH_ADDED_REGISTRY_SHA256,
    FROZEN_SIXTH_CUMULATIVE_SUITE_SHA256,
    SEVENTH_TRANCHE_ADDED_TASK_COUNT,
    SEVENTH_TRANCHE_CUMULATIVE_TASK_COUNT,
    SEVENTH_TRANCHE_FAMILY_ORDER,
    SeventhTrancheRegistryError,
    build_seventh_tranche_added_tasks,
    build_seventh_tranche_task_registry,
    compute_seventh_tranche_cumulative_suite_sha256,
    compute_seventh_tranche_registry_sha256,
    validate_seventh_tranche_task_registry,
)
from cbds.executable_static_sixth_registry import (  # noqa: E402
    build_sixth_tranche_task_registry,
)
from cbds.executable_static_third_registry import (  # noqa: E402
    build_third_tranche_task_registry,
)
from cbds.executable_static_types import domain_sha256  # noqa: E402


EXPECTED_CASE_ROUTED_BATCH_TRANSFORM_TASK_SET_SHA256 = (
    "e68a7e4614424e76fa35d4c0650e500469b971f1a5010d309115b0c225b7b2e6"
)
EXPECTED_SEVENTH_REGISTRY_SHA256 = (
    "14aa05939c2ac2f4954196968003254dee39175f1d1d94e32213b8a74cfff19e"
)
EXPECTED_SEVENTH_CUMULATIVE_SUITE_SHA256 = (
    "341b50a83305a9e0c64ada387eee461209ca75d1083e34fe2887a608179de131"
)


class _SpoofedString(str):
    def __eq__(self, _other: object) -> bool:
        return True

    def __ne__(self, _other: object) -> bool:
        return False

    __hash__ = str.__hash__


class SeventhTrancheTaskRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = build_seventh_tranche_task_registry()
        cls.first = build_public_method_development_registry()
        cls.second = build_second_tranche_task_registry()
        cls.third = build_third_tranche_task_registry()
        cls.fourth = build_fourth_tranche_task_registry()
        cls.fifth = build_fifth_tranche_task_registry()
        cls.sixth = build_sixth_tranche_task_registry()

    def assert_registry_invalid(self, registry: object) -> None:
        with self.assertRaises(
            (SeventhTrancheRegistryError, TypeError, ValueError)
        ):
            validate_seventh_tranche_task_registry(  # type: ignore[arg-type]
                registry
            )

    def test_grid_has_exact_type_order_and_unique_identities(self) -> None:
        tasks = self.registry.added_tasks
        self.assertEqual(len(tasks), SEVENTH_TRANCHE_ADDED_TASK_COUNT)
        self.assertEqual(SEVENTH_TRANCHE_ADDED_TASK_COUNT, 20)
        self.assertEqual(SEVENTH_TRANCHE_CUMULATIVE_TASK_COUNT, 320)
        self.assertEqual(
            SEVENTH_TRANCHE_FAMILY_ORDER,
            ("case-routed-batch-transform",),
        )
        self.assertTrue(
            all(type(task) is CaseRoutedBatchTransformTask for task in tasks)
        )
        self.assertEqual(
            tuple(
                (
                    task.parameters.route_key,
                    task.parameters.fallback_policy,
                )
                for task in tasks
            ),
            tuple(
                (route_key, fallback_policy)
                for route_key in CASE_ROUTED_BATCH_TRANSFORM_ROUTE_KEYS
                for fallback_policy in (
                    CASE_ROUTED_BATCH_TRANSFORM_FALLBACK_POLICIES
                )
            ),
        )
        self.assertEqual(len({task.task_id for task in tasks}), 20)
        self.assertEqual(len({task.task_contract_sha256 for task in tasks}), 20)
        self.assertEqual(len({task.graph_sha256 for task in tasks}), 20)
        for task in tasks:
            with self.subTest(task_id=task.task_id):
                task.__post_init__()
                self.assertIs(task.public, True)
                self.assertIs(task.sealed, False)
                self.assertIs(task.candidate_execution_authorized, False)
                self.assertIs(task.model_selection_eligible, False)
                self.assertIs(task.claim_authorized, False)
                self.assertEqual(len(task.fixtures), 5)

    def test_rebuild_is_deterministic_and_new_hashes_are_frozen(self) -> None:
        self.assertEqual(
            build_seventh_tranche_added_tasks(), self.registry.added_tasks
        )
        rebuilt = build_seventh_tranche_task_registry()
        self.assertEqual(rebuilt, self.registry)
        self.assertEqual(
            rebuilt.registry_sha256,
            EXPECTED_SEVENTH_REGISTRY_SHA256,
        )
        self.assertEqual(
            rebuilt.cumulative_suite_sha256,
            EXPECTED_SEVENTH_CUMULATIVE_SUITE_SHA256,
        )
        self.assertEqual(
            rebuilt.registry_sha256,
            compute_seventh_tranche_registry_sha256(rebuilt.added_tasks),
        )
        self.assertEqual(
            rebuilt.cumulative_suite_sha256,
            compute_seventh_tranche_cumulative_suite_sha256(
                rebuilt.added_tasks,
                rebuilt.registry_sha256,
            ),
        )
        self.assertEqual(
            domain_sha256(
                (
                    "cbds.executable-method-development-coverage."
                    "integrated-task-set.v1"
                ),
                {
                    "family_id": "case-routed-batch-transform",
                    "task_count": len(rebuilt.added_tasks),
                    "task_id": [task.task_id for task in rebuilt.added_tasks],
                    "task_contract_sha256": [
                        task.task_contract_sha256
                        for task in rebuilt.added_tasks
                    ],
                    "graph_sha256": [
                        task.graph_sha256 for task in rebuilt.added_tasks
                    ],
                },
            ),
            EXPECTED_CASE_ROUTED_BATCH_TRANSFORM_TASK_SET_SHA256,
        )

    def test_all_predecessor_identities_are_live_and_unchanged(self) -> None:
        self.assertEqual(
            self.first.registry_sha256, FROZEN_FIRST_REGISTRY_SHA256
        )
        self.assertEqual(self.first.suite_sha256, FROZEN_FIRST_SUITE_SHA256)
        self.assertEqual(
            self.second.registry_sha256,
            FROZEN_SECOND_ADDED_REGISTRY_SHA256,
        )
        self.assertEqual(
            self.second.cumulative_suite_sha256,
            FROZEN_SECOND_CUMULATIVE_SUITE_SHA256,
        )
        self.assertEqual(
            self.third.registry_sha256,
            FROZEN_THIRD_ADDED_REGISTRY_SHA256,
        )
        self.assertEqual(
            self.third.cumulative_suite_sha256,
            FROZEN_THIRD_CUMULATIVE_SUITE_SHA256,
        )
        self.assertEqual(
            self.fourth.registry_sha256,
            FROZEN_FOURTH_ADDED_REGISTRY_SHA256,
        )
        self.assertEqual(
            self.fourth.cumulative_suite_sha256,
            FROZEN_FOURTH_CUMULATIVE_SUITE_SHA256,
        )
        self.assertEqual(
            self.fifth.registry_sha256,
            FROZEN_FIFTH_ADDED_REGISTRY_SHA256,
        )
        self.assertEqual(
            self.fifth.cumulative_suite_sha256,
            FROZEN_FIFTH_CUMULATIVE_SUITE_SHA256,
        )
        self.assertEqual(
            self.sixth.registry_sha256,
            FROZEN_SIXTH_ADDED_REGISTRY_SHA256,
        )
        self.assertEqual(
            self.sixth.cumulative_suite_sha256,
            FROZEN_SIXTH_CUMULATIVE_SUITE_SHA256,
        )
        self.assertEqual(
            self.registry.base_added_registry_sha256,
            self.sixth.registry_sha256,
        )
        self.assertEqual(
            self.registry.base_cumulative_suite_sha256,
            self.sixth.cumulative_suite_sha256,
        )

    def test_all_320_task_identities_are_globally_unique(self) -> None:
        tasks = (
            *self.first.tasks,
            *self.second.added_tasks,
            *self.third.added_tasks,
            *self.fourth.added_tasks,
            *self.fifth.added_tasks,
            *self.sixth.added_tasks,
            *self.registry.added_tasks,
        )
        self.assertEqual(len(tasks), SEVENTH_TRANCHE_CUMULATIVE_TASK_COUNT)
        self.assertEqual(len({task.task_id for task in tasks}), len(tasks))
        self.assertEqual(
            len({task.task_contract_sha256 for task in tasks}), len(tasks)
        )
        self.assertEqual(len({task.graph_sha256 for task in tasks}), len(tasks))

    def test_hash_projection_is_public_unsealed_and_nonauthorizing(self) -> None:
        record = self.registry.to_hash_only_record()
        self.assertEqual(
            record["record_type"],
            "cbds.executable-static-seventh-tranche-registry-hashes",
        )
        self.assertEqual(record["base_cumulative_task_count"], 300)
        self.assertEqual(record["added_task_count"], 20)
        self.assertEqual(record["cumulative_task_count"], 320)
        self.assertEqual(
            record["family_task_counts"],
            {"case-routed-batch-transform": 20},
        )
        self.assertIs(record["public_method_development"], True)
        self.assertIs(record["sealed"], False)
        self.assertIs(record["candidate_execution_authorized"], False)
        self.assertIs(record["model_selection_eligible"], False)
        self.assertIs(record["claim_authorized"], False)

    def test_mutations_wrong_types_and_hostile_strings_fail_closed(self) -> None:
        wrong_container = copy.copy(self.registry)
        object.__setattr__(
            wrong_container, "added_tasks", list(self.registry.added_tasks)
        )
        self.assert_registry_invalid(wrong_container)

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

        hostile_task = copy.deepcopy(self.registry)
        object.__setattr__(
            hostile_task.added_tasks[0].parameters,
            "route_key",
            "outside-contract",
        )
        self.assert_registry_invalid(hostile_task)

        wrong_task_type = copy.copy(self.registry)
        object.__setattr__(
            wrong_task_type,
            "added_tasks",
            (self.sixth.added_tasks[0], *self.registry.added_tasks[1:]),
        )
        self.assert_registry_invalid(wrong_task_type)

        forged_authority = copy.copy(self.registry)
        object.__setattr__(
            forged_authority, "candidate_execution_authorized", True
        )
        self.assert_registry_invalid(forged_authority)

        spoofed_digest = copy.copy(self.registry)
        object.__setattr__(
            spoofed_digest,
            "registry_sha256",
            _SpoofedString(self.registry.registry_sha256),
        )
        self.assert_registry_invalid(spoofed_digest)
        self.assert_registry_invalid(object())


if __name__ == "__main__":
    unittest.main()
