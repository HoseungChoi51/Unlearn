from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import cbds.executable_static_eleventh_registry as eleventh_registry  # noqa: E402
from cbds.executable_checksum_repair_plan import (  # noqa: E402
    CHECKSUM_REPAIR_PLAN_MANIFEST_LAYOUTS,
    CHECKSUM_REPAIR_PLAN_REPAIR_POLICIES,
    ChecksumRepairPlanTask,
)
from cbds.executable_static_eleventh_registry import (  # noqa: E402
    ELEVENTH_TRANCHE_ADDED_TASK_COUNT,
    ELEVENTH_TRANCHE_CUMULATIVE_TASK_COUNT,
    ELEVENTH_TRANCHE_FAMILY_ORDER,
    EleventhTrancheRegistryError,
    build_eleventh_tranche_added_tasks,
    build_eleventh_tranche_task_registry,
    compute_eleventh_tranche_cumulative_suite_sha256,
    compute_eleventh_tranche_registry_sha256,
    validate_eleventh_tranche_task_registry,
)
from cbds.executable_static_types import domain_sha256  # noqa: E402
from cbds.executable_tenth_predecessor_evidence import (  # noqa: E402
    FROZEN_TENTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_TENTH_REGISTRY_SHA256,
    TENTH_PREFIX_TASK_COUNT,
    build_tenth_prefix_task_evidence,
)


EXPECTED_CHECKSUM_REPAIR_TASK_SET_SHA256 = (
    "e52fb74ece2a94baa9bd1b2f6da25ca103839e1e9666361fe5406c34a36b9bb0"
)
EXPECTED_ELEVENTH_REGISTRY_SHA256 = (
    "bd0c14880eb25fa80100c317fa41086c45c59147407a67f03981831bcfdfc100"
)
EXPECTED_ELEVENTH_CUMULATIVE_SUITE_SHA256 = (
    "f62ba1c1214fc48f194a5dea9c69c04962cc14dbdccfc38640cf4eee833018cb"
)


class EleventhTrancheTaskRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.predecessors = build_tenth_prefix_task_evidence()
        cls.registry = build_eleventh_tranche_task_registry(
            cls.predecessors
        )

    def assert_registry_invalid(self, registry: object) -> None:
        with self.assertRaises(
            (EleventhTrancheRegistryError, TypeError, ValueError)
        ):
            validate_eleventh_tranche_task_registry(  # type: ignore[arg-type]
                registry
            )

    def test_grid_has_exact_type_order_and_unique_identities(self) -> None:
        tasks = self.registry.added_tasks
        self.assertEqual(len(tasks), ELEVENTH_TRANCHE_ADDED_TASK_COUNT)
        self.assertEqual(ELEVENTH_TRANCHE_ADDED_TASK_COUNT, 20)
        self.assertEqual(ELEVENTH_TRANCHE_CUMULATIVE_TASK_COUNT, 400)
        self.assertEqual(
            ELEVENTH_TRANCHE_FAMILY_ORDER,
            ("checksum-repair-plan",),
        )
        self.assertTrue(
            all(type(task) is ChecksumRepairPlanTask for task in tasks)
        )
        self.assertEqual(
            tuple(
                (
                    task.parameters.manifest_layout,
                    task.parameters.repair_policy,
                )
                for task in tasks
            ),
            tuple(
                (manifest_layout, repair_policy)
                for manifest_layout in CHECKSUM_REPAIR_PLAN_MANIFEST_LAYOUTS
                for repair_policy in CHECKSUM_REPAIR_PLAN_REPAIR_POLICIES
            ),
        )
        self.assertEqual(len({task.task_id for task in tasks}), 20)
        self.assertEqual(len({task.task_contract_sha256 for task in tasks}), 20)
        self.assertEqual(len({task.graph_sha256 for task in tasks}), 20)
        for task in tasks:
            task.__post_init__()
            self.assertIs(task.public, True)
            self.assertIs(task.sealed, False)
            self.assertIs(task.candidate_execution_authorized, False)
            self.assertIs(task.model_selection_eligible, False)
            self.assertIs(task.claim_authorized, False)
            self.assertEqual(len(task.fixtures), 5)

    def test_hashes_are_frozen_and_domain_separated_as_eleventh(self) -> None:
        tasks = self.registry.added_tasks
        self.assertEqual(
            self.registry.registry_sha256,
            EXPECTED_ELEVENTH_REGISTRY_SHA256,
        )
        self.assertEqual(
            self.registry.cumulative_suite_sha256,
            EXPECTED_ELEVENTH_CUMULATIVE_SUITE_SHA256,
        )
        self.assertEqual(
            self.registry.registry_sha256,
            compute_eleventh_tranche_registry_sha256(tasks),
        )
        self.assertEqual(
            self.registry.cumulative_suite_sha256,
            compute_eleventh_tranche_cumulative_suite_sha256(
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
                    "family_id": "checksum-repair-plan",
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
            EXPECTED_CHECKSUM_REPAIR_TASK_SET_SHA256,
        )

    def test_exact_tenth_anchors_and_global_uniqueness(self) -> None:
        self.assertEqual(TENTH_PREFIX_TASK_COUNT, 380)
        self.assertEqual(
            self.predecessors.terminal_registry_sha256,
            FROZEN_TENTH_REGISTRY_SHA256,
        )
        self.assertEqual(
            self.predecessors.terminal_cumulative_suite_sha256,
            FROZEN_TENTH_CUMULATIVE_SUITE_SHA256,
        )
        self.assertEqual(
            self.registry.base_added_registry_sha256,
            FROZEN_TENTH_REGISTRY_SHA256,
        )
        self.assertEqual(
            self.registry.base_cumulative_suite_sha256,
            FROZEN_TENTH_CUMULATIVE_SUITE_SHA256,
        )
        tasks = (*self.predecessors.tasks, *self.registry.added_tasks)
        self.assertEqual(len(tasks), 400)
        self.assertEqual(len({task.task_id for task in tasks}), 400)
        self.assertEqual(
            len({task.task_contract_sha256 for task in tasks}), 400
        )
        self.assertEqual(len({task.graph_sha256 for task in tasks}), 400)

    def test_supplied_prefix_is_reused_without_rebuild(self) -> None:
        with mock.patch.object(
            eleventh_registry,
            "build_tenth_prefix_task_evidence",
            side_effect=AssertionError("through-tenth prefix rebuilt"),
        ):
            rebuilt = build_eleventh_tranche_task_registry(
                self.predecessors
            )
        self.assertEqual(rebuilt, self.registry)

    def test_default_build_passes_live_ninth_evidence_into_tenth(self) -> None:
        import cbds.executable_tenth_predecessor_evidence as prefix

        real = prefix.build_tenth_tranche_task_registry
        seen: list[object] = []

        def checked(evidence=None):
            self.assertIsNotNone(evidence)
            seen.append(evidence)
            return real(evidence)

        with mock.patch.object(
            prefix,
            "build_tenth_tranche_task_registry",
            side_effect=checked,
        ):
            rebuilt = build_eleventh_tranche_task_registry()
        self.assertEqual(rebuilt, self.registry)
        self.assertEqual(len(seen), 1)

    def test_repeated_builds_have_fresh_addition_ownership(self) -> None:
        first = build_eleventh_tranche_added_tasks()
        second = build_eleventh_tranche_added_tasks()
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
            "cbds.executable-static-eleventh-tranche-registry-hashes",
        )
        self.assertEqual(record["base_cumulative_task_count"], 380)
        self.assertEqual(record["added_task_count"], 20)
        self.assertEqual(record["cumulative_task_count"], 400)
        self.assertEqual(
            record["family_task_counts"],
            {"checksum-repair-plan": 20},
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
            "manifest_layout",
            "yaml",
        )
        self.assert_registry_invalid(hostile)

        forged = copy.copy(self.registry)
        object.__setattr__(forged, "candidate_execution_authorized", True)
        self.assert_registry_invalid(forged)
        self.assert_registry_invalid(object())


if __name__ == "__main__":
    unittest.main()
