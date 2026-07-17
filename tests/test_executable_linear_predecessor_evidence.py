from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import importlib
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import cbds.executable_linear_predecessor_evidence as linear  # noqa: E402
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from cbds.executable_linear_predecessor_evidence import (  # noqa: E402
    FROZEN_PREDECESSOR_CATALOG_SHA256,
    FROZEN_PREDECESSOR_CUMULATIVE_SUITE_SHA256,
    FROZEN_PREDECESSOR_REGISTRY_SHA256,
    LINEAR_PREDECESSOR_ADDED_FIXTURE_COUNTS,
    LINEAR_PREDECESSOR_ADDED_TASK_COUNTS,
    LINEAR_PREDECESSOR_CUMULATIVE_FIXTURE_COUNTS,
    LINEAR_PREDECESSOR_CUMULATIVE_TASK_COUNTS,
    LINEAR_PREDECESSOR_FAMILY_ORDER,
    LINEAR_PREDECESSOR_FIXTURE_COUNT,
    LINEAR_PREDECESSOR_PROFILE_COUNT,
    LINEAR_PREDECESSOR_TASK_COUNT,
    LINEAR_PREDECESSOR_TRANCHE_ORDER,
    LinearPredecessorEvidenceError,
    build_linear_fixture_predecessor_evidence,
    build_linear_task_predecessor_evidence,
    validate_linear_fixture_predecessor_evidence,
    validate_linear_task_predecessor_evidence,
    verify_linear_fixture_predecessor_evidence,
    verify_linear_task_predecessor_evidence,
)


class LinearTaskPredecessorEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.evidence = build_linear_task_predecessor_evidence()

    def test_all_frozen_hashes_counts_and_order_are_preserved(self) -> None:
        evidence = self.evidence
        validate_linear_task_predecessor_evidence(evidence)
        self.assertTrue(verify_linear_task_predecessor_evidence(evidence))
        self.assertEqual(
            tuple(tranche.tranche for tranche in evidence.tranches),
            LINEAR_PREDECESSOR_TRANCHE_ORDER,
        )
        self.assertEqual(
            tuple(tranche.added_task_count for tranche in evidence.tranches),
            LINEAR_PREDECESSOR_ADDED_TASK_COUNTS,
        )
        self.assertEqual(
            tuple(
                tranche.cumulative_task_count
                for tranche in evidence.tranches
            ),
            LINEAR_PREDECESSOR_CUMULATIVE_TASK_COUNTS,
        )
        self.assertEqual(
            tuple(tranche.registry_sha256 for tranche in evidence.tranches),
            FROZEN_PREDECESSOR_REGISTRY_SHA256,
        )
        self.assertEqual(
            tuple(
                tranche.cumulative_suite_sha256
                for tranche in evidence.tranches
            ),
            FROZEN_PREDECESSOR_CUMULATIVE_SUITE_SHA256,
        )
        self.assertEqual(evidence.total_task_count, 340)
        self.assertEqual(LINEAR_PREDECESSOR_TASK_COUNT, 340)
        self.assertEqual(len(evidence.tasks), 340)
        self.assertEqual(
            evidence.terminal_registry_sha256,
            FROZEN_PREDECESSOR_REGISTRY_SHA256[-1],
        )
        self.assertEqual(
            evidence.terminal_cumulative_suite_sha256,
            FROZEN_PREDECESSOR_CUMULATIVE_SUITE_SHA256[-1],
        )
        self.assertEqual(
            tuple(
                family
                for index, family in enumerate(
                    task.family_id for task in evidence.tasks
                )
                if index == 0
                or family != evidence.tasks[index - 1].family_id
            ),
            LINEAR_PREDECESSOR_FAMILY_ORDER,
        )
        self.assertEqual(len({task.task_id for task in evidence.tasks}), 340)
        self.assertEqual(
            len(
                {
                    task.task_contract_sha256
                    for task in evidence.tasks
                }
            ),
            340,
        )
        self.assertEqual(
            len({task.graph_sha256 for task in evidence.tasks}),
            340,
        )

    def test_build_uses_each_local_task_builder_once(self) -> None:
        function_names = (
            "build_public_method_development_registry",
            "build_second_tranche_added_tasks",
            "build_third_tranche_added_tasks",
            "build_fourth_tranche_added_tasks",
            "build_fifth_tranche_added_tasks",
            "build_sixth_tranche_added_tasks",
            "build_seventh_tranche_added_tasks",
            "build_eighth_tranche_added_tasks",
        )
        patches = [
            patch.object(
                linear,
                name,
                wraps=getattr(linear, name),
            )
            for name in function_names
        ]
        mocks = []
        try:
            for selected_patch in patches:
                mocks.append(selected_patch.start())
            evidence = build_linear_task_predecessor_evidence()
        finally:
            for selected_patch in reversed(patches):
                selected_patch.stop()
        self.assertEqual(len(evidence.tasks), 340)
        self.assertTrue(all(mock.call_count == 1 for mock in mocks))

    def test_recursive_registry_builders_are_not_needed(self) -> None:
        recursive_builder_paths = (
            (
                "cbds.executable_static_second_registry."
                "build_second_tranche_task_registry"
            ),
            (
                "cbds.executable_static_third_registry."
                "build_third_tranche_task_registry"
            ),
            (
                "cbds.executable_static_fourth_registry."
                "build_fourth_tranche_task_registry"
            ),
            (
                "cbds.executable_static_fifth_registry."
                "build_fifth_tranche_task_registry"
            ),
            (
                "cbds.executable_static_sixth_registry."
                "build_sixth_tranche_task_registry"
            ),
            (
                "cbds.executable_static_seventh_registry."
                "build_seventh_tranche_task_registry"
            ),
            (
                "cbds.executable_static_eighth_registry."
                "build_eighth_tranche_task_registry"
            ),
        )
        patches = [
            patch(path, side_effect=AssertionError("recursive builder called"))
            for path in recursive_builder_paths
        ]
        try:
            for selected_patch in patches:
                selected_patch.start()
            evidence = build_linear_task_predecessor_evidence()
        finally:
            for selected_patch in reversed(patches):
                selected_patch.stop()
        self.assertTrue(verify_linear_task_predecessor_evidence(evidence))

    def test_repeated_calls_own_fresh_scoped_objects(self) -> None:
        first = self.evidence
        second = build_linear_task_predecessor_evidence()
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first.tranches, second.tranches)
        self.assertIsNot(first.tasks, second.tasks)
        for left, right in zip(first.tranches, second.tranches, strict=True):
            self.assertIsNot(left, right)
            self.assertIsNot(left.registry, right.registry)
            self.assertIsNot(left.tasks, right.tasks)
            self.assertIsNot(left.tasks[0], right.tasks[0])
        self.assertIsNot(first.registries, first.registries)

    def test_evidence_is_frozen_and_rejects_order_or_identity_changes(self) -> None:
        with self.assertRaises(FrozenInstanceError):
            self.evidence.total_task_count = 0  # type: ignore[misc]
        with self.assertRaises(LinearPredecessorEvidenceError):
            replace(
                self.evidence,
                tasks=tuple(reversed(self.evidence.tasks)),
            )
        with self.assertRaises(LinearPredecessorEvidenceError):
            replace(
                self.evidence,
                terminal_registry_sha256="0" * 64,
            )
        self.assertFalse(verify_linear_task_predecessor_evidence(object()))


class LinearFixturePredecessorEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.task_evidence = build_linear_task_predecessor_evidence()
        cls.evidence = build_linear_fixture_predecessor_evidence(
            cls.task_evidence
        )

    def test_all_catalog_hashes_counts_order_and_identities_are_frozen(
        self,
    ) -> None:
        evidence = self.evidence
        validate_linear_fixture_predecessor_evidence(evidence)
        self.assertTrue(verify_linear_fixture_predecessor_evidence(evidence))
        self.assertIs(evidence.task_evidence, self.task_evidence)
        self.assertEqual(
            tuple(tranche.tranche for tranche in evidence.tranches),
            LINEAR_PREDECESSOR_TRANCHE_ORDER,
        )
        self.assertEqual(
            tuple(
                tranche.added_fixture_count
                for tranche in evidence.tranches
            ),
            LINEAR_PREDECESSOR_ADDED_FIXTURE_COUNTS,
        )
        self.assertEqual(
            tuple(
                tranche.cumulative_fixture_count
                for tranche in evidence.tranches
            ),
            LINEAR_PREDECESSOR_CUMULATIVE_FIXTURE_COUNTS,
        )
        self.assertEqual(
            tuple(tranche.catalog_sha256 for tranche in evidence.tranches),
            FROZEN_PREDECESSOR_CATALOG_SHA256,
        )
        self.assertEqual(LINEAR_PREDECESSOR_PROFILE_COUNT, 5)
        self.assertEqual(evidence.profiles_per_task, 5)
        self.assertEqual(LINEAR_PREDECESSOR_FIXTURE_COUNT, 1_700)
        self.assertEqual(evidence.total_fixture_count, 1_700)
        self.assertEqual(len(evidence.bundles), 1_700)
        self.assertEqual(
            evidence.terminal_catalog_sha256,
            FROZEN_PREDECESSOR_CATALOG_SHA256[-1],
        )
        self.assertEqual(
            len(
                {
                    bundle.descriptor.fixture_id
                    for bundle in evidence.bundles
                }
            ),
            1_700,
        )
        self.assertEqual(
            len(
                {
                    bundle.descriptor.fixture_sha256
                    for bundle in evidence.bundles
                }
            ),
            1_700,
        )
        for fixture_tranche, task_tranche in zip(
            evidence.tranches,
            evidence.task_evidence.tranches,
            strict=True,
        ):
            self.assertIs(fixture_tranche.task_tranche, task_tranche)
            self.assertIs(
                fixture_tranche.bundles,
                fixture_tranche.catalog.bundles,
            )
            self.assertEqual(
                tuple(
                    bundle.task_contract_sha256
                    for bundle in fixture_tranche.bundles[::5]
                ),
                tuple(
                    task.task_contract_sha256
                    for task in task_tranche.tasks
                ),
            )
            self.assertTrue(
                all(
                    bundle.profile_sha256
                    == PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[
                        index % 5
                    ].profile_sha256
                    for index, bundle in enumerate(
                        fixture_tranche.bundles
                    )
                )
            )

    def test_each_local_builder_runs_once_and_recursive_builders_are_unused(
        self,
    ) -> None:
        local_function_names = (
            "build_first_tranche_fixture_catalog",
            "build_second_tranche_fixture_catalog",
            "build_third_tranche_fixture_catalog_local",
            "build_fourth_tranche_fixture_catalog_local",
            "build_fifth_tranche_fixture_catalog_local",
            "build_sixth_tranche_fixture_catalog_local",
            "build_seventh_tranche_fixture_catalog_local",
            "build_eighth_tranche_fixture_catalog_local",
        )
        recursive_builder_paths = (
            (
                "cbds.executable_fixture_third_catalog."
                "build_third_tranche_fixture_catalog"
            ),
            (
                "cbds.executable_fixture_fourth_catalog."
                "build_fourth_tranche_fixture_catalog"
            ),
            (
                "cbds.executable_fixture_fifth_catalog."
                "build_fifth_tranche_fixture_catalog"
            ),
            (
                "cbds.executable_fixture_sixth_catalog."
                "build_sixth_tranche_fixture_catalog"
            ),
            (
                "cbds.executable_fixture_seventh_catalog."
                "build_seventh_tranche_fixture_catalog"
            ),
            (
                "cbds.executable_fixture_eighth_catalog."
                "build_eighth_tranche_fixture_catalog"
            ),
        )
        local_patches = [
            patch.object(
                linear,
                name,
                wraps=getattr(linear, name),
            )
            for name in local_function_names
        ]
        recursive_patches = [
            patch(path, side_effect=AssertionError("recursive builder called"))
            for path in recursive_builder_paths
        ]
        local_mocks = []
        try:
            for selected_patch in local_patches:
                local_mocks.append(selected_patch.start())
            for selected_patch in recursive_patches:
                selected_patch.start()
            evidence = build_linear_fixture_predecessor_evidence(
                self.task_evidence
            )
        finally:
            for selected_patch in reversed(recursive_patches):
                selected_patch.stop()
            for selected_patch in reversed(local_patches):
                selected_patch.stop()
        self.assertTrue(
            verify_linear_fixture_predecessor_evidence(evidence)
        )
        self.assertTrue(all(mock.call_count == 1 for mock in local_mocks))
        self.assertIsNot(evidence, self.evidence)
        self.assertIsNot(evidence.tranches, self.evidence.tranches)
        self.assertIsNot(evidence.bundles, self.evidence.bundles)
        for left, right in zip(
            evidence.tranches,
            self.evidence.tranches,
            strict=True,
        ):
            self.assertIsNot(left, right)
            self.assertIsNot(left.catalog, right.catalog)
            self.assertIsNot(left.bundles, right.bundles)
            self.assertIsNot(left.bundles[0], right.bundles[0])
        self.assertIsNot(evidence.catalogs, evidence.catalogs)

    def test_legacy_builders_retain_the_predecessor_admission_check(
        self,
    ) -> None:
        for index, ordinal in enumerate(
            LINEAR_PREDECESSOR_TRANCHE_ORDER[2:],
            start=2,
        ):
            with self.subTest(tranche=ordinal):
                module = importlib.import_module(
                    f"cbds.executable_fixture_{ordinal}_catalog"
                )
                local_name = (
                    f"build_{ordinal}_tranche_fixture_catalog_local"
                )
                legacy_name = f"build_{ordinal}_tranche_fixture_catalog"
                catalog = self.evidence.tranches[index].catalog
                registry = self.task_evidence.tranches[index].registry
                with (
                    patch.object(
                        module,
                        local_name,
                        return_value=catalog,
                    ) as local_builder,
                    patch.object(
                        module,
                        "_validate_live_base_and_global_uniqueness",
                    ) as predecessor_check,
                ):
                    rebuilt = getattr(module, legacy_name)(registry)
                self.assertIs(rebuilt, catalog)
                local_builder.assert_called_once_with(registry)
                predecessor_check.assert_called_once_with(catalog.bundles)

    def test_fixture_evidence_is_frozen_and_rejects_mutation(self) -> None:
        with self.assertRaises(FrozenInstanceError):
            self.evidence.total_fixture_count = 0  # type: ignore[misc]
        with self.assertRaises(LinearPredecessorEvidenceError):
            replace(
                self.evidence,
                bundles=tuple(reversed(self.evidence.bundles)),
            )
        with self.assertRaises(LinearPredecessorEvidenceError):
            replace(
                self.evidence,
                terminal_catalog_sha256="0" * 64,
            )
        self.assertFalse(
            verify_linear_fixture_predecessor_evidence(object())
        )


if __name__ == "__main__":
    unittest.main()
