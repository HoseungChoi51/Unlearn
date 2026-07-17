from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.executable_hardlink_deduplicated_mirror import (  # noqa: E402
    HARDLINK_DEDUPLICATED_MIRROR_EQUIVALENCE_KEYS,
    HARDLINK_DEDUPLICATED_MIRROR_OWNER_POLICIES,
    HardlinkDeduplicatedMirrorTask,
)
from cbds.executable_linear_predecessor_evidence import (  # noqa: E402
    build_linear_task_predecessor_evidence,
)
from cbds.executable_static_ninth_registry import (  # noqa: E402
    FROZEN_EIGHTH_ADDED_REGISTRY_SHA256,
    FROZEN_EIGHTH_CUMULATIVE_SUITE_SHA256,
    NINTH_TRANCHE_ADDED_TASK_COUNT,
    NINTH_TRANCHE_CUMULATIVE_TASK_COUNT,
    NINTH_TRANCHE_FAMILY_ORDER,
    NinthTrancheRegistryError,
    build_ninth_tranche_added_tasks,
    build_ninth_tranche_task_registry,
    compute_ninth_tranche_cumulative_suite_sha256,
    compute_ninth_tranche_registry_sha256,
    validate_ninth_tranche_task_registry,
)
from cbds.executable_static_types import domain_sha256  # noqa: E402


# Frozen only after the complete family grid and fixture descriptors passed.
EXPECTED_HARDLINK_TASK_SET_SHA256 = (
    "0415daa5f9bccfcd75b621ef4ae71c9e79a5b7c19763ceb470e5ef21169706d1"
)
EXPECTED_NINTH_REGISTRY_SHA256 = (
    "ff886754b054445a90ad30197d004e4071dba72bf0af17931d05e461c7e90703"
)
EXPECTED_NINTH_CUMULATIVE_SUITE_SHA256 = (
    "d0647e24f29abd59f8c2d6b2ac2a404aee78b92c780f8be4f9b16d200885843b"
)


class NinthTrancheTaskRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = build_ninth_tranche_task_registry()
        cls.predecessors = build_linear_task_predecessor_evidence()

    def assert_registry_invalid(self, registry: object) -> None:
        with self.assertRaises(
            (NinthTrancheRegistryError, TypeError, ValueError)
        ):
            validate_ninth_tranche_task_registry(  # type: ignore[arg-type]
                registry
            )

    def test_grid_has_exact_type_order_and_unique_identities(self) -> None:
        tasks = self.registry.added_tasks
        self.assertEqual(len(tasks), NINTH_TRANCHE_ADDED_TASK_COUNT)
        self.assertEqual(NINTH_TRANCHE_ADDED_TASK_COUNT, 20)
        self.assertEqual(NINTH_TRANCHE_CUMULATIVE_TASK_COUNT, 360)
        self.assertEqual(
            NINTH_TRANCHE_FAMILY_ORDER,
            ("hardlink-deduplicated-mirror",),
        )
        self.assertTrue(
            all(type(task) is HardlinkDeduplicatedMirrorTask for task in tasks)
        )
        self.assertEqual(
            tuple(
                (
                    task.parameters.equivalence_key,
                    task.parameters.owner_policy,
                )
                for task in tasks
            ),
            tuple(
                (equivalence_key, owner_policy)
                for equivalence_key in (
                    HARDLINK_DEDUPLICATED_MIRROR_EQUIVALENCE_KEYS
                )
                for owner_policy in (
                    HARDLINK_DEDUPLICATED_MIRROR_OWNER_POLICIES
                )
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

    def test_rebuild_is_deterministic_and_hashes_are_frozen(self) -> None:
        self.assertEqual(
            build_ninth_tranche_added_tasks(),
            self.registry.added_tasks,
        )
        rebuilt = build_ninth_tranche_task_registry()
        self.assertEqual(rebuilt, self.registry)
        self.assertEqual(
            rebuilt.registry_sha256,
            EXPECTED_NINTH_REGISTRY_SHA256,
        )
        self.assertEqual(
            rebuilt.cumulative_suite_sha256,
            EXPECTED_NINTH_CUMULATIVE_SUITE_SHA256,
        )
        self.assertEqual(
            rebuilt.registry_sha256,
            compute_ninth_tranche_registry_sha256(rebuilt.added_tasks),
        )
        self.assertEqual(
            rebuilt.cumulative_suite_sha256,
            compute_ninth_tranche_cumulative_suite_sha256(
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
                    "family_id": "hardlink-deduplicated-mirror",
                    "task_count": len(rebuilt.added_tasks),
                    "task_id": [
                        task.task_id for task in rebuilt.added_tasks
                    ],
                    "task_contract_sha256": [
                        task.task_contract_sha256
                        for task in rebuilt.added_tasks
                    ],
                    "graph_sha256": [
                        task.graph_sha256 for task in rebuilt.added_tasks
                    ],
                },
            ),
            EXPECTED_HARDLINK_TASK_SET_SHA256,
        )

    def test_linear_base_is_live_unchanged_and_globally_unique(self) -> None:
        self.assertEqual(
            self.predecessors.terminal_registry_sha256,
            FROZEN_EIGHTH_ADDED_REGISTRY_SHA256,
        )
        self.assertEqual(
            self.predecessors.terminal_cumulative_suite_sha256,
            FROZEN_EIGHTH_CUMULATIVE_SUITE_SHA256,
        )
        self.assertEqual(
            self.registry.base_added_registry_sha256,
            FROZEN_EIGHTH_ADDED_REGISTRY_SHA256,
        )
        self.assertEqual(
            self.registry.base_cumulative_suite_sha256,
            FROZEN_EIGHTH_CUMULATIVE_SUITE_SHA256,
        )
        tasks = (*self.predecessors.tasks, *self.registry.added_tasks)
        self.assertEqual(len(tasks), 360)
        self.assertEqual(len({task.task_id for task in tasks}), len(tasks))
        self.assertEqual(
            len({task.task_contract_sha256 for task in tasks}),
            len(tasks),
        )
        self.assertEqual(
            len({task.graph_sha256 for task in tasks}),
            len(tasks),
        )

    def test_recursive_predecessor_registry_builders_are_not_called(self) -> None:
        paths = tuple(
            (
                f"cbds.executable_static_{ordinal}_registry."
                f"build_{ordinal}_tranche_task_registry"
            )
            for ordinal in (
                "second",
                "third",
                "fourth",
                "fifth",
                "sixth",
                "seventh",
                "eighth",
            )
        )
        patches = [
            patch(path, side_effect=AssertionError("recursive builder called"))
            for path in paths
        ]
        try:
            for selected in patches:
                selected.start()
            rebuilt = build_ninth_tranche_task_registry()
        finally:
            for selected in reversed(patches):
                selected.stop()
        self.assertEqual(rebuilt, self.registry)

    def test_supplied_linear_evidence_is_reused_without_rebuild(self) -> None:
        with patch(
            (
                "cbds.executable_static_ninth_registry."
                "build_linear_task_predecessor_evidence"
            ),
            side_effect=AssertionError("linear predecessor rebuilt"),
        ):
            rebuilt = build_ninth_tranche_task_registry(
                self.predecessors
            )
        self.assertEqual(rebuilt, self.registry)

    def test_hash_projection_is_public_unsealed_and_nonauthorizing(self) -> None:
        record = self.registry.to_hash_only_record()
        self.assertEqual(
            record["record_type"],
            "cbds.executable-static-ninth-tranche-registry-hashes",
        )
        self.assertEqual(record["base_cumulative_task_count"], 340)
        self.assertEqual(record["added_task_count"], 20)
        self.assertEqual(record["cumulative_task_count"], 360)
        self.assertEqual(
            record["family_task_counts"],
            {"hardlink-deduplicated-mirror": 20},
        )
        self.assertIs(record["public_method_development"], True)
        for key in (
            "sealed",
            "candidate_execution_authorized",
            "model_selection_eligible",
            "claim_authorized",
        ):
            self.assertIs(record[key], False)

    def test_mutations_and_wrong_types_fail_closed(self) -> None:
        wrong_container = copy.copy(self.registry)
        object.__setattr__(
            wrong_container,
            "added_tasks",
            list(self.registry.added_tasks),
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

        hostile = copy.deepcopy(self.registry)
        object.__setattr__(
            hostile.added_tasks[0].parameters,
            "equivalence_key",
            "outside-contract",
        )
        self.assert_registry_invalid(hostile)

        forged = copy.copy(self.registry)
        object.__setattr__(forged, "candidate_execution_authorized", True)
        self.assert_registry_invalid(forged)
        self.assert_registry_invalid(object())


if __name__ == "__main__":
    unittest.main()
