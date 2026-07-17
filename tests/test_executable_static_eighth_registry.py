from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.executable_collision_safe_batch_rename import (  # noqa: E402
    COLLISION_SAFE_BATCH_RENAME_COLLISION_POLICIES,
    COLLISION_SAFE_BATCH_RENAME_RENAME_RULES,
    CollisionSafeBatchRenameTask,
)
from cbds.executable_static_eighth_registry import (  # noqa: E402
    EIGHTH_TRANCHE_ADDED_TASK_COUNT,
    EIGHTH_TRANCHE_CUMULATIVE_TASK_COUNT,
    EIGHTH_TRANCHE_FAMILY_ORDER,
    EighthTrancheRegistryError,
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
    FROZEN_SEVENTH_ADDED_REGISTRY_SHA256,
    FROZEN_SEVENTH_CUMULATIVE_SUITE_SHA256,
    build_eighth_tranche_added_tasks,
    build_eighth_tranche_task_registry,
    compute_eighth_tranche_cumulative_suite_sha256,
    compute_eighth_tranche_registry_sha256,
    validate_eighth_tranche_task_registry,
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
    build_seventh_tranche_task_registry,
)
from cbds.executable_static_sixth_registry import (  # noqa: E402
    build_sixth_tranche_task_registry,
)
from cbds.executable_static_third_registry import (  # noqa: E402
    build_third_tranche_task_registry,
)
from cbds.executable_static_types import domain_sha256  # noqa: E402


EXPECTED_COLLISION_SAFE_BATCH_RENAME_TASK_SET_SHA256 = (
    "6c563074579359d666faaae2aebf69019c74521e8946cea6a2fe19a756c744cd"
)
EXPECTED_EIGHTH_REGISTRY_SHA256 = (
    "8ef6879c5b6f4198c1b0ff2acfcffe89b6cbdd418a9aa2af2eefedfb12994736"
)
EXPECTED_EIGHTH_CUMULATIVE_SUITE_SHA256 = (
    "b22742179e3ce3b7331469de9db0a75ddbae81a3340e2b814c8a7ab34233f0f0"
)


class _SpoofedString(str):
    def __eq__(self, _other: object) -> bool:
        return True

    def __ne__(self, _other: object) -> bool:
        return False

    __hash__ = str.__hash__


class EighthTrancheTaskRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = build_eighth_tranche_task_registry()
        cls.first = build_public_method_development_registry()
        cls.second = build_second_tranche_task_registry()
        cls.third = build_third_tranche_task_registry()
        cls.fourth = build_fourth_tranche_task_registry()
        cls.fifth = build_fifth_tranche_task_registry()
        cls.sixth = build_sixth_tranche_task_registry()
        cls.seventh = build_seventh_tranche_task_registry()

    def assert_registry_invalid(self, registry: object) -> None:
        with self.assertRaises(
            (EighthTrancheRegistryError, TypeError, ValueError)
        ):
            validate_eighth_tranche_task_registry(  # type: ignore[arg-type]
                registry
            )

    def test_grid_has_exact_type_order_and_unique_identities(self) -> None:
        tasks = self.registry.added_tasks
        self.assertEqual(len(tasks), EIGHTH_TRANCHE_ADDED_TASK_COUNT)
        self.assertEqual(EIGHTH_TRANCHE_ADDED_TASK_COUNT, 20)
        self.assertEqual(EIGHTH_TRANCHE_CUMULATIVE_TASK_COUNT, 340)
        self.assertEqual(
            EIGHTH_TRANCHE_FAMILY_ORDER,
            ("collision-safe-batch-rename",),
        )
        self.assertTrue(
            all(type(task) is CollisionSafeBatchRenameTask for task in tasks)
        )
        self.assertEqual(
            tuple(
                (
                    task.parameters.rename_rule,
                    task.parameters.collision_policy,
                )
                for task in tasks
            ),
            tuple(
                (rename_rule, collision_policy)
                for rename_rule in COLLISION_SAFE_BATCH_RENAME_RENAME_RULES
                for collision_policy in (
                    COLLISION_SAFE_BATCH_RENAME_COLLISION_POLICIES
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
            build_eighth_tranche_added_tasks(), self.registry.added_tasks
        )
        rebuilt = build_eighth_tranche_task_registry()
        self.assertEqual(rebuilt, self.registry)
        self.assertEqual(
            rebuilt.registry_sha256,
            EXPECTED_EIGHTH_REGISTRY_SHA256,
        )
        self.assertEqual(
            rebuilt.cumulative_suite_sha256,
            EXPECTED_EIGHTH_CUMULATIVE_SUITE_SHA256,
        )
        self.assertEqual(
            rebuilt.registry_sha256,
            compute_eighth_tranche_registry_sha256(rebuilt.added_tasks),
        )
        self.assertEqual(
            rebuilt.cumulative_suite_sha256,
            compute_eighth_tranche_cumulative_suite_sha256(
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
                    "family_id": "collision-safe-batch-rename",
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
            EXPECTED_COLLISION_SAFE_BATCH_RENAME_TASK_SET_SHA256,
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
            self.seventh.registry_sha256,
            FROZEN_SEVENTH_ADDED_REGISTRY_SHA256,
        )
        self.assertEqual(
            self.seventh.cumulative_suite_sha256,
            FROZEN_SEVENTH_CUMULATIVE_SUITE_SHA256,
        )
        self.assertEqual(
            self.registry.base_added_registry_sha256,
            self.seventh.registry_sha256,
        )
        self.assertEqual(
            self.registry.base_cumulative_suite_sha256,
            self.seventh.cumulative_suite_sha256,
        )

    def test_all_340_task_identities_are_globally_unique(self) -> None:
        tasks = (
            *self.first.tasks,
            *self.second.added_tasks,
            *self.third.added_tasks,
            *self.fourth.added_tasks,
            *self.fifth.added_tasks,
            *self.sixth.added_tasks,
            *self.seventh.added_tasks,
            *self.registry.added_tasks,
        )
        self.assertEqual(len(tasks), EIGHTH_TRANCHE_CUMULATIVE_TASK_COUNT)
        self.assertEqual(len({task.task_id for task in tasks}), len(tasks))
        self.assertEqual(
            len({task.task_contract_sha256 for task in tasks}), len(tasks)
        )
        self.assertEqual(len({task.graph_sha256 for task in tasks}), len(tasks))

    def test_hash_projection_is_public_unsealed_and_nonauthorizing(self) -> None:
        record = self.registry.to_hash_only_record()
        self.assertEqual(
            record["record_type"],
            "cbds.executable-static-eighth-tranche-registry-hashes",
        )
        self.assertEqual(record["base_cumulative_task_count"], 320)
        self.assertEqual(record["added_task_count"], 20)
        self.assertEqual(record["cumulative_task_count"], 340)
        self.assertEqual(
            record["family_task_counts"],
            {"collision-safe-batch-rename": 20},
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
            "rename_rule",
            "outside-contract",
        )
        self.assert_registry_invalid(hostile_task)

        wrong_task_type = copy.copy(self.registry)
        object.__setattr__(
            wrong_task_type,
            "added_tasks",
            (self.seventh.added_tasks[0], *self.registry.added_tasks[1:]),
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
