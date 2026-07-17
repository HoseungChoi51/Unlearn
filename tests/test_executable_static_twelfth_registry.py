from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import cbds.executable_static_twelfth_registry as twelfth_registry  # noqa: E402
from cbds.executable_eleventh_predecessor_evidence import (  # noqa: E402
    ELEVENTH_PREFIX_TASK_COUNT,
    FROZEN_ELEVENTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_ELEVENTH_REGISTRY_SHA256,
    build_eleventh_prefix_task_evidence,
)
from cbds.executable_jsonl_csv_enrichment_compose import (  # noqa: E402
    JSONL_CSV_ENRICHMENT_COMPOSE_JOIN_LAYOUTS,
    JSONL_CSV_ENRICHMENT_COMPOSE_MISSING_FIELD_POLICIES,
    JsonlCsvEnrichmentComposeTask,
    compute_jsonl_csv_enrichment_compose_discrimination_sha256,
)
from cbds.executable_static_twelfth_registry import (  # noqa: E402
    TWELFTH_TRANCHE_ADDED_TASK_COUNT,
    TWELFTH_TRANCHE_CUMULATIVE_TASK_COUNT,
    TWELFTH_TRANCHE_FAMILY_ORDER,
    TwelfthTrancheRegistryError,
    build_twelfth_tranche_added_tasks,
    build_twelfth_tranche_task_registry,
    compute_twelfth_tranche_cumulative_suite_sha256,
    compute_twelfth_tranche_registry_sha256,
    validate_twelfth_tranche_task_registry,
)
from cbds.executable_static_types import domain_sha256  # noqa: E402


EXPECTED_JSONL_CSV_ENRICHMENT_TASK_SET_SHA256 = (
    "60a8ab6770bae6de43d430db9e3edf136f28f0a0ad2dacfd09b627ce19cf75c3"
)
EXPECTED_JSONL_CSV_ENRICHMENT_DISCRIMINATION_SHA256 = (
    "732c1438a4337d2043ee85e2eb4e9e7c437a0051eb1a828cdac6139845db0e94"
)
EXPECTED_TWELFTH_REGISTRY_SHA256 = (
    "a9733f220a7bdfb8435841eff875c9fd7b1dbadbee6de2d2aa0646750164f862"
)
EXPECTED_TWELFTH_CUMULATIVE_SUITE_SHA256 = (
    "32ec82cf193f364946def16462e52217176093d0a3f6399d574c9faf66eaa4a1"
)


class TwelfthTrancheTaskRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.predecessors = build_eleventh_prefix_task_evidence()
        cls.registry = build_twelfth_tranche_task_registry(
            cls.predecessors
        )

    def assert_registry_invalid(self, registry: object) -> None:
        with self.assertRaises(
            (TwelfthTrancheRegistryError, TypeError, ValueError)
        ):
            validate_twelfth_tranche_task_registry(  # type: ignore[arg-type]
                registry
            )

    def test_grid_has_exact_type_order_and_unique_identities(self) -> None:
        tasks = self.registry.added_tasks
        self.assertEqual(len(tasks), TWELFTH_TRANCHE_ADDED_TASK_COUNT)
        self.assertEqual(TWELFTH_TRANCHE_ADDED_TASK_COUNT, 20)
        self.assertEqual(TWELFTH_TRANCHE_CUMULATIVE_TASK_COUNT, 420)
        self.assertEqual(
            TWELFTH_TRANCHE_FAMILY_ORDER,
            ("jsonl-csv-enrichment-compose",),
        )
        self.assertTrue(
            all(
                type(task) is JsonlCsvEnrichmentComposeTask
                for task in tasks
            )
        )
        self.assertEqual(
            tuple(
                (
                    task.parameters.join_layout,
                    task.parameters.missing_field_policy,
                )
                for task in tasks
            ),
            tuple(
                (join_layout, missing_field_policy)
                for join_layout in (
                    JSONL_CSV_ENRICHMENT_COMPOSE_JOIN_LAYOUTS
                )
                for missing_field_policy in (
                    JSONL_CSV_ENRICHMENT_COMPOSE_MISSING_FIELD_POLICIES
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

    def test_hashes_are_frozen_and_domain_separated_as_twelfth(self) -> None:
        tasks = self.registry.added_tasks
        self.assertEqual(
            self.registry.registry_sha256,
            EXPECTED_TWELFTH_REGISTRY_SHA256,
        )
        self.assertEqual(
            self.registry.cumulative_suite_sha256,
            EXPECTED_TWELFTH_CUMULATIVE_SUITE_SHA256,
        )
        self.assertEqual(
            self.registry.registry_sha256,
            compute_twelfth_tranche_registry_sha256(tasks),
        )
        self.assertEqual(
            self.registry.cumulative_suite_sha256,
            compute_twelfth_tranche_cumulative_suite_sha256(
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
                    "family_id": "jsonl-csv-enrichment-compose",
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
            EXPECTED_JSONL_CSV_ENRICHMENT_TASK_SET_SHA256,
        )
        self.assertEqual(
            compute_jsonl_csv_enrichment_compose_discrimination_sha256(
                tasks
            ),
            EXPECTED_JSONL_CSV_ENRICHMENT_DISCRIMINATION_SHA256,
        )

    def test_exact_eleventh_anchors_and_global_uniqueness(self) -> None:
        self.assertEqual(ELEVENTH_PREFIX_TASK_COUNT, 400)
        self.assertEqual(
            self.predecessors.terminal_registry_sha256,
            FROZEN_ELEVENTH_REGISTRY_SHA256,
        )
        self.assertEqual(
            self.predecessors.terminal_cumulative_suite_sha256,
            FROZEN_ELEVENTH_CUMULATIVE_SUITE_SHA256,
        )
        self.assertEqual(
            self.registry.base_added_registry_sha256,
            FROZEN_ELEVENTH_REGISTRY_SHA256,
        )
        self.assertEqual(
            self.registry.base_cumulative_suite_sha256,
            FROZEN_ELEVENTH_CUMULATIVE_SUITE_SHA256,
        )
        tasks = (*self.predecessors.tasks, *self.registry.added_tasks)
        self.assertEqual(len(tasks), 420)
        self.assertEqual(len({task.task_id for task in tasks}), 420)
        self.assertEqual(
            len({task.task_contract_sha256 for task in tasks}), 420
        )
        self.assertEqual(len({task.graph_sha256 for task in tasks}), 420)

    def test_supplied_prefix_is_reused_without_rebuild(self) -> None:
        with mock.patch.object(
            twelfth_registry,
            "build_eleventh_prefix_task_evidence",
            side_effect=AssertionError("through-eleventh prefix rebuilt"),
        ):
            rebuilt = build_twelfth_tranche_task_registry(
                self.predecessors
            )
        self.assertEqual(rebuilt, self.registry)

    def test_default_build_passes_live_tenth_evidence_into_eleventh(
        self,
    ) -> None:
        import cbds.executable_eleventh_predecessor_evidence as prefix

        real = prefix.build_eleventh_tranche_task_registry
        seen: list[object] = []

        def checked(evidence=None):
            self.assertIsNotNone(evidence)
            seen.append(evidence)
            return real(evidence)

        with mock.patch.object(
            prefix,
            "build_eleventh_tranche_task_registry",
            side_effect=checked,
        ):
            rebuilt = build_twelfth_tranche_task_registry()
        self.assertEqual(rebuilt, self.registry)
        self.assertEqual(len(seen), 1)

    def test_repeated_builds_have_fresh_addition_ownership(self) -> None:
        first = build_twelfth_tranche_added_tasks()
        second = build_twelfth_tranche_added_tasks()
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
            "cbds.executable-static-twelfth-tranche-registry-hashes",
        )
        self.assertEqual(record["base_cumulative_task_count"], 400)
        self.assertEqual(record["added_task_count"], 20)
        self.assertEqual(record["cumulative_task_count"], 420)
        self.assertEqual(
            record["family_task_counts"],
            {"jsonl-csv-enrichment-compose": 20},
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
            "join_layout",
            "yaml-left",
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
            compute_twelfth_tranche_registry_sha256(
                permuted.added_tasks
            )
        )
        alternate_suite_sha256 = (
            compute_twelfth_tranche_cumulative_suite_sha256(
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
            EXPECTED_TWELFTH_REGISTRY_SHA256,
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
