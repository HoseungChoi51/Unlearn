from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.executable_static_fifth_registry import (  # noqa: E402
    FIFTH_TRANCHE_ADDED_TASK_COUNT,
    FIFTH_TRANCHE_CUMULATIVE_TASK_COUNT,
    FIFTH_TRANCHE_FAMILY_ORDER,
    FROZEN_FIRST_REGISTRY_SHA256,
    FROZEN_FIRST_SUITE_SHA256,
    FROZEN_SECOND_ADDED_REGISTRY_SHA256,
    FROZEN_SECOND_CUMULATIVE_SUITE_SHA256,
    FROZEN_THIRD_ADDED_REGISTRY_SHA256,
    FROZEN_THIRD_CUMULATIVE_SUITE_SHA256,
    FROZEN_FOURTH_ADDED_REGISTRY_SHA256,
    FROZEN_FOURTH_CUMULATIVE_SUITE_SHA256,
    FifthTrancheRegistryError,
    build_fifth_tranche_added_tasks,
    build_fifth_tranche_task_registry,
    compute_fifth_tranche_cumulative_suite_sha256,
    compute_fifth_tranche_registry_sha256,
    validate_fifth_tranche_task_registry,
)
from cbds.executable_static_registry import (  # noqa: E402
    build_public_method_development_registry,
)
from cbds.executable_static_second_registry import (  # noqa: E402
    build_second_tranche_task_registry,
)
from cbds.executable_static_third_registry import (  # noqa: E402
    build_third_tranche_task_registry,
)
from cbds.executable_static_fourth_registry import (  # noqa: E402
    build_fourth_tranche_task_registry,
)
from cbds.executable_pipefail_atomic_report import (  # noqa: E402
    PIPEFAIL_ATOMIC_REPORT_FAILURE_COMMIT_POLICIES,
    PIPEFAIL_ATOMIC_REPORT_PIPELINE_SHAPES,
    PipefailAtomicReportTask,
)


EXPECTED_FIFTH_REGISTRY_SHA256 = (
    "d562d462814b7fc6413e0e085d16f66def28157c1a6361adf28cd3d42eb5f88c"
)
EXPECTED_FIFTH_CUMULATIVE_SUITE_SHA256 = (
    "27ea8064a72453a4e7a4bc52b125a924139088cd1c20d417a867aa9ddda96e00"
)


class _SpoofedString(str):
    def __eq__(self, _other: object) -> bool:
        return True

    def __ne__(self, _other: object) -> bool:
        return False

    __hash__ = str.__hash__


class FifthTrancheTaskRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = build_fifth_tranche_task_registry()
        cls.first = build_public_method_development_registry()
        cls.second = build_second_tranche_task_registry()
        cls.third = build_third_tranche_task_registry()
        cls.fourth = build_fourth_tranche_task_registry()

    def assert_registry_invalid(self, registry: object) -> None:
        with self.assertRaises(
            (FifthTrancheRegistryError, TypeError, ValueError)
        ):
            validate_fifth_tranche_task_registry(  # type: ignore[arg-type]
                registry
            )

    def test_grid_has_exact_type_order_and_unique_identities(self) -> None:
        tasks = self.registry.added_tasks
        self.assertEqual(len(tasks), FIFTH_TRANCHE_ADDED_TASK_COUNT)
        self.assertEqual(FIFTH_TRANCHE_ADDED_TASK_COUNT, 20)
        self.assertEqual(FIFTH_TRANCHE_CUMULATIVE_TASK_COUNT, 280)
        self.assertEqual(
            FIFTH_TRANCHE_FAMILY_ORDER,
            ("pipefail-atomic-report",),
        )
        self.assertTrue(all(type(task) is PipefailAtomicReportTask for task in tasks))
        self.assertEqual(
            tuple(
                (
                    task.parameters.pipeline_shape,
                    task.parameters.failure_commit_policy,
                )
                for task in tasks
            ),
            tuple(
                (pipeline_shape, policy)
                for pipeline_shape in PIPEFAIL_ATOMIC_REPORT_PIPELINE_SHAPES
                for policy in PIPEFAIL_ATOMIC_REPORT_FAILURE_COMMIT_POLICIES
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
            build_fifth_tranche_added_tasks(), self.registry.added_tasks
        )
        rebuilt = build_fifth_tranche_task_registry()
        self.assertEqual(rebuilt, self.registry)
        self.assertEqual(
            rebuilt.registry_sha256,
            EXPECTED_FIFTH_REGISTRY_SHA256,
        )
        self.assertEqual(
            rebuilt.cumulative_suite_sha256,
            EXPECTED_FIFTH_CUMULATIVE_SUITE_SHA256,
        )
        self.assertEqual(
            rebuilt.registry_sha256,
            compute_fifth_tranche_registry_sha256(rebuilt.added_tasks),
        )
        self.assertEqual(
            rebuilt.cumulative_suite_sha256,
            compute_fifth_tranche_cumulative_suite_sha256(
                rebuilt.added_tasks,
                rebuilt.registry_sha256,
            ),
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
            self.registry.base_added_registry_sha256,
            self.fourth.registry_sha256,
        )
        self.assertEqual(
            self.registry.base_cumulative_suite_sha256,
            self.fourth.cumulative_suite_sha256,
        )

    def test_all_280_task_identities_are_globally_unique(self) -> None:
        tasks = (
            *self.first.tasks,
            *self.second.added_tasks,
            *self.third.added_tasks,
            *self.fourth.added_tasks,
            *self.registry.added_tasks,
        )
        self.assertEqual(len(tasks), FIFTH_TRANCHE_CUMULATIVE_TASK_COUNT)
        self.assertEqual(len({task.task_id for task in tasks}), len(tasks))
        self.assertEqual(
            len({task.task_contract_sha256 for task in tasks}), len(tasks)
        )
        self.assertEqual(len({task.graph_sha256 for task in tasks}), len(tasks))

    def test_hash_projection_is_public_unsealed_and_nonauthorizing(self) -> None:
        record = self.registry.to_hash_only_record()
        self.assertEqual(
            record["record_type"],
            "cbds.executable-static-fifth-tranche-registry-hashes",
        )
        self.assertEqual(record["base_cumulative_task_count"], 260)
        self.assertEqual(record["added_task_count"], 20)
        self.assertEqual(record["cumulative_task_count"], 280)
        self.assertEqual(
            record["family_task_counts"],
            {"pipefail-atomic-report": 20},
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
            "pipeline_shape",
            "outside-contract",
        )
        self.assert_registry_invalid(hostile_task)

        wrong_task_type = copy.copy(self.registry)
        object.__setattr__(
            wrong_task_type,
            "added_tasks",
            (self.fourth.added_tasks[0], *self.registry.added_tasks[1:]),
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
