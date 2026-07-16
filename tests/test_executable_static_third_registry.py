from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.executable_compound_path_query import (  # noqa: E402
    COMPOUND_PATH_EXPRESSIONS,
    COMPOUND_PATH_NAME_PATTERNS,
    CompoundPathQueryTask,
)
from cbds.executable_log_aggregation_pipeline import (  # noqa: E402
    LOG_AGGREGATION_MALFORMED_POLICIES,
    LOG_AGGREGATION_SEVERITY_ERES,
    LogAggregationTask,
)
from cbds.executable_static_registry import (  # noqa: E402
    build_public_method_development_registry,
)
from cbds.executable_static_second_registry import (  # noqa: E402
    build_second_tranche_task_registry,
)
from cbds.executable_static_third_registry import (  # noqa: E402
    FROZEN_FIRST_REGISTRY_SHA256,
    FROZEN_FIRST_SUITE_SHA256,
    FROZEN_SECOND_ADDED_REGISTRY_SHA256,
    FROZEN_SECOND_CUMULATIVE_SUITE_SHA256,
    THIRD_TRANCHE_ADDED_TASK_COUNT,
    THIRD_TRANCHE_CUMULATIVE_TASK_COUNT,
    THIRD_TRANCHE_FAMILY_ORDER,
    ThirdTrancheRegistryError,
    build_third_tranche_added_tasks,
    build_third_tranche_task_registry,
    compute_third_tranche_cumulative_suite_sha256,
    compute_third_tranche_registry_sha256,
    validate_third_tranche_task_registry,
)


class _SpoofedString(str):
    def __eq__(self, _other: object) -> bool:
        return True

    def __ne__(self, _other: object) -> bool:
        return False

    __hash__ = str.__hash__


class ThirdTrancheTaskRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = build_third_tranche_task_registry()
        cls.first = build_public_method_development_registry()
        cls.second = build_second_tranche_task_registry()

    def assert_registry_invalid(self, registry: object) -> None:
        with self.assertRaises((ThirdTrancheRegistryError, TypeError, ValueError)):
            validate_third_tranche_task_registry(registry)  # type: ignore[arg-type]

    def test_added_grids_have_exact_types_order_and_unique_identities(self) -> None:
        tasks = self.registry.added_tasks
        self.assertEqual(len(tasks), THIRD_TRANCHE_ADDED_TASK_COUNT)
        self.assertEqual(THIRD_TRANCHE_ADDED_TASK_COUNT, 40)
        self.assertEqual(THIRD_TRANCHE_CUMULATIVE_TASK_COUNT, 240)
        self.assertEqual(
            THIRD_TRANCHE_FAMILY_ORDER,
            ("compound-path-query", "regex-log-group-aggregation"),
        )
        self.assertTrue(
            all(type(task) is CompoundPathQueryTask for task in tasks[:20])
        )
        self.assertTrue(all(type(task) is LogAggregationTask for task in tasks[20:]))
        self.assertEqual(
            tuple(task.family_id for task in tasks),
            tuple(family for family in THIRD_TRANCHE_FAMILY_ORDER for _ in range(20)),
        )
        self.assertEqual(
            tuple(
                (task.parameters.name_pattern, task.parameters.expression)
                for task in tasks[:20]
            ),
            tuple(
                (pattern, expression)
                for pattern in COMPOUND_PATH_NAME_PATTERNS
                for expression in COMPOUND_PATH_EXPRESSIONS
            ),
        )
        self.assertEqual(
            tuple(
                (task.parameters.severity_ere, task.parameters.malformed_policy)
                for task in tasks[20:]
            ),
            tuple(
                (severity, policy)
                for severity in LOG_AGGREGATION_SEVERITY_ERES
                for policy in LOG_AGGREGATION_MALFORMED_POLICIES
            ),
        )
        self.assertEqual(len({task.task_id for task in tasks}), 40)
        self.assertEqual(len({task.task_contract_sha256 for task in tasks}), 40)
        self.assertEqual(len({task.graph_sha256 for task in tasks}), 40)
        for task in tasks:
            with self.subTest(task_id=task.task_id):
                task.__post_init__()
                self.assertIs(task.public, True)
                self.assertIs(task.sealed, False)
                self.assertIs(task.claim_authorized, False)
                self.assertEqual(len(task.fixtures), 5)

    def test_rebuild_is_deterministic_and_digests_bind_exact_tasks(self) -> None:
        self.assertEqual(build_third_tranche_added_tasks(), self.registry.added_tasks)
        rebuilt = build_third_tranche_task_registry()
        self.assertEqual(rebuilt, self.registry)
        self.assertEqual(
            rebuilt.registry_sha256,
            compute_third_tranche_registry_sha256(rebuilt.added_tasks),
        )
        self.assertEqual(
            rebuilt.cumulative_suite_sha256,
            compute_third_tranche_cumulative_suite_sha256(
                rebuilt.added_tasks,
                rebuilt.registry_sha256,
            ),
        )

    def test_frozen_second_identities_are_live_and_unchanged(self) -> None:
        self.assertEqual(
            self.first.registry_sha256,
            FROZEN_FIRST_REGISTRY_SHA256,
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
            self.registry.base_added_registry_sha256,
            self.second.registry_sha256,
        )
        self.assertEqual(
            self.registry.base_cumulative_suite_sha256,
            self.second.cumulative_suite_sha256,
        )

    def test_all_240_task_identities_are_globally_unique(self) -> None:
        tasks = (
            *self.first.tasks,
            *self.second.added_tasks,
            *self.registry.added_tasks,
        )
        self.assertEqual(len(tasks), THIRD_TRANCHE_CUMULATIVE_TASK_COUNT)
        self.assertEqual(len({task.task_id for task in tasks}), len(tasks))
        self.assertEqual(
            len({task.task_contract_sha256 for task in tasks}), len(tasks)
        )
        self.assertEqual(len({task.graph_sha256 for task in tasks}), len(tasks))

    def test_hash_projection_is_public_unsealed_and_nonauthorizing(self) -> None:
        record = self.registry.to_hash_only_record()
        self.assertEqual(
            record["record_type"],
            "cbds.executable-static-third-tranche-registry-hashes",
        )
        self.assertEqual(record["added_task_count"], 40)
        self.assertEqual(record["cumulative_task_count"], 240)
        self.assertEqual(
            record["family_task_counts"],
            {family: 20 for family in THIRD_TRANCHE_FAMILY_ORDER},
        )
        self.assertIs(record["public_method_development"], True)
        self.assertIs(record["sealed"], False)
        self.assertIs(record["candidate_execution_authorized"], False)
        self.assertIs(record["model_selection_eligible"], False)
        self.assertIs(record["claim_authorized"], False)

    def test_mutations_wrong_types_and_hostile_strings_fail_closed(self) -> None:
        wrong_container = copy.copy(self.registry)
        object.__setattr__(wrong_container, "added_tasks", list(self.registry.added_tasks))
        self.assert_registry_invalid(wrong_container)

        reordered = copy.copy(self.registry)
        object.__setattr__(
            reordered,
            "added_tasks",
            (
                self.registry.added_tasks[20],
                *self.registry.added_tasks[1:20],
                self.registry.added_tasks[0],
                *self.registry.added_tasks[21:],
            ),
        )
        self.assert_registry_invalid(reordered)

        hostile_task = copy.deepcopy(self.registry)
        parameters = hostile_task.added_tasks[0].parameters
        object.__setattr__(parameters, "name_pattern", "outside-contract")
        self.assert_registry_invalid(hostile_task)

        wrong_task_type = copy.copy(self.registry)
        object.__setattr__(
            wrong_task_type,
            "added_tasks",
            (object(), *self.registry.added_tasks[1:]),
        )
        self.assert_registry_invalid(wrong_task_type)

        forged_authority = copy.copy(self.registry)
        object.__setattr__(forged_authority, "candidate_execution_authorized", True)
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
