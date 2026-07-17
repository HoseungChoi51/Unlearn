from __future__ import annotations

import copy
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import cbds.executable_ninth_predecessor_evidence as prefix  # noqa: E402
from cbds.executable_linear_predecessor_evidence import (  # noqa: E402
    LINEAR_PREDECESSOR_FIXTURE_COUNT,
    LINEAR_PREDECESSOR_TASK_COUNT,
)
from cbds.executable_ninth_predecessor_evidence import (  # noqa: E402
    FROZEN_NINTH_CATALOG_SHA256,
    FROZEN_NINTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_NINTH_REGISTRY_SHA256,
    NINTH_PREFIX_FAMILY_ORDER,
    NINTH_PREFIX_FIXTURE_COUNT,
    NINTH_PREFIX_PROFILE_COUNT,
    NINTH_PREFIX_TASK_COUNT,
    NinthPredecessorEvidenceError,
    build_ninth_prefix_fixture_evidence,
    build_ninth_prefix_task_evidence,
    validate_ninth_prefix_fixture_evidence,
    validate_ninth_prefix_task_evidence,
    verify_ninth_prefix_fixture_evidence,
    verify_ninth_prefix_task_evidence,
)


_RECURSIVE_PUBLICATION_BUILDERS = (
    "cbds.executable_static_second_registry.build_second_tranche_task_registry",
    "cbds.executable_static_third_registry.build_third_tranche_task_registry",
    "cbds.executable_static_fourth_registry.build_fourth_tranche_task_registry",
    "cbds.executable_static_fifth_registry.build_fifth_tranche_task_registry",
    "cbds.executable_static_sixth_registry.build_sixth_tranche_task_registry",
    "cbds.executable_static_seventh_registry.build_seventh_tranche_task_registry",
    "cbds.executable_static_eighth_registry.build_eighth_tranche_task_registry",
    "cbds.executable_fixture_third_catalog.build_third_tranche_fixture_catalog",
    "cbds.executable_fixture_fourth_catalog.build_fourth_tranche_fixture_catalog",
    "cbds.executable_fixture_fifth_catalog.build_fifth_tranche_fixture_catalog",
    "cbds.executable_fixture_sixth_catalog.build_sixth_tranche_fixture_catalog",
    "cbds.executable_fixture_seventh_catalog.build_seventh_tranche_fixture_catalog",
    "cbds.executable_fixture_eighth_catalog.build_eighth_tranche_fixture_catalog",
    "cbds.executable_fixture_ninth_catalog.build_ninth_tranche_fixture_catalog",
)


class NinthPredecessorEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        captured: dict[str, object] = {}
        real_linear_tasks = prefix.build_linear_task_predecessor_evidence
        real_ninth_registry = prefix.build_ninth_tranche_task_registry
        real_linear_fixtures = (
            prefix.build_linear_fixture_predecessor_evidence
        )
        real_ninth_catalog = (
            prefix.build_ninth_tranche_fixture_catalog_local
        )

        def linear_tasks():
            evidence = real_linear_tasks()
            captured["linear_tasks"] = evidence
            captured["linear_task_calls"] = (
                int(captured.get("linear_task_calls", 0)) + 1
            )
            return evidence

        def ninth_registry(linear_evidence=None):
            captured["registry_argument"] = linear_evidence
            registry = real_ninth_registry(linear_evidence)
            captured["ninth_registry"] = registry
            captured["registry_calls"] = (
                int(captured.get("registry_calls", 0)) + 1
            )
            return registry

        def linear_fixtures(linear_evidence=None):
            captured["fixture_argument"] = linear_evidence
            evidence = real_linear_fixtures(linear_evidence)
            captured["linear_fixtures"] = evidence
            captured["linear_fixture_calls"] = (
                int(captured.get("linear_fixture_calls", 0)) + 1
            )
            return evidence

        def ninth_catalog(registry):
            captured["catalog_argument"] = registry
            catalog = real_ninth_catalog(registry)
            captured["ninth_catalog"] = catalog
            captured["catalog_calls"] = (
                int(captured.get("catalog_calls", 0)) + 1
            )
            return catalog

        with ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    prefix,
                    "build_linear_task_predecessor_evidence",
                    side_effect=linear_tasks,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    prefix,
                    "build_ninth_tranche_task_registry",
                    side_effect=ninth_registry,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    prefix,
                    "build_linear_fixture_predecessor_evidence",
                    side_effect=linear_fixtures,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    prefix,
                    "build_ninth_tranche_fixture_catalog_local",
                    side_effect=ninth_catalog,
                )
            )
            for path in _RECURSIVE_PUBLICATION_BUILDERS:
                stack.enter_context(
                    mock.patch(
                        path,
                        side_effect=AssertionError(
                            "recursive publication builder called: "
                            f"{path}"
                        ),
                    )
                )
            cls.fixture_evidence = build_ninth_prefix_fixture_evidence()

        cls.task_evidence = cls.fixture_evidence.task_evidence
        cls.linear_tasks = captured["linear_tasks"]
        cls.linear_fixtures = captured["linear_fixtures"]
        cls.ninth_registry = captured["ninth_registry"]
        cls.ninth_catalog = captured["ninth_catalog"]
        cls.registry_argument = captured["registry_argument"]
        cls.fixture_argument = captured["fixture_argument"]
        cls.catalog_argument = captured["catalog_argument"]
        cls.linear_task_calls = captured["linear_task_calls"]
        cls.registry_calls = captured["registry_calls"]
        cls.linear_fixture_calls = captured["linear_fixture_calls"]
        cls.catalog_calls = captured["catalog_calls"]

    def test_builds_each_component_once_and_reuses_exact_evidence(self) -> None:
        self.assertEqual(self.linear_task_calls, 1)
        self.assertEqual(self.registry_calls, 1)
        self.assertEqual(self.linear_fixture_calls, 1)
        self.assertEqual(self.catalog_calls, 1)
        self.assertIs(self.registry_argument, self.linear_tasks)
        self.assertIs(self.fixture_argument, self.linear_tasks)
        self.assertIs(self.catalog_argument, self.ninth_registry)
        self.assertIs(
            self.task_evidence.linear_evidence,
            self.linear_tasks,
        )
        self.assertIs(
            self.fixture_evidence.linear_evidence,
            self.linear_fixtures,
        )
        self.assertIs(
            self.fixture_evidence.ninth_catalog,
            self.ninth_catalog,
        )
        self.assertIs(
            self.linear_fixtures.task_evidence,
            self.linear_tasks,
        )

    def test_exact_terminal_hashes_counts_and_family_order(self) -> None:
        validate_ninth_prefix_task_evidence(self.task_evidence)
        validate_ninth_prefix_fixture_evidence(self.fixture_evidence)
        self.assertTrue(
            verify_ninth_prefix_task_evidence(self.task_evidence)
        )
        self.assertTrue(
            verify_ninth_prefix_fixture_evidence(self.fixture_evidence)
        )
        self.assertEqual(LINEAR_PREDECESSOR_TASK_COUNT, 340)
        self.assertEqual(LINEAR_PREDECESSOR_FIXTURE_COUNT, 1_700)
        self.assertEqual(NINTH_PREFIX_TASK_COUNT, 360)
        self.assertEqual(NINTH_PREFIX_FIXTURE_COUNT, 1_800)
        self.assertEqual(NINTH_PREFIX_PROFILE_COUNT, 5)
        self.assertEqual(len(self.task_evidence.tasks), 360)
        self.assertEqual(len(self.fixture_evidence.bundles), 1_800)
        self.assertEqual(
            self.task_evidence.terminal_registry_sha256,
            FROZEN_NINTH_REGISTRY_SHA256,
        )
        self.assertEqual(
            self.task_evidence.terminal_cumulative_suite_sha256,
            FROZEN_NINTH_CUMULATIVE_SUITE_SHA256,
        )
        self.assertEqual(
            self.fixture_evidence.terminal_catalog_sha256,
            FROZEN_NINTH_CATALOG_SHA256,
        )
        self.assertEqual(
            tuple(
                task.family_id
                for index, task in enumerate(self.task_evidence.tasks)
                if index == 0
                or task.family_id
                != self.task_evidence.tasks[index - 1].family_id
            ),
            NINTH_PREFIX_FAMILY_ORDER,
        )
        self.assertEqual(len(self.task_evidence.registries), 9)
        self.assertEqual(len(self.fixture_evidence.catalogs), 9)
        self.assertIsNot(
            self.task_evidence.registries,
            self.task_evidence.registries,
        )
        self.assertIsNot(
            self.fixture_evidence.catalogs,
            self.fixture_evidence.catalogs,
        )

    def test_task_and_fixture_identities_are_globally_unique(self) -> None:
        tasks = self.task_evidence.tasks
        bundles = self.fixture_evidence.bundles
        self.assertEqual(len({task.task_id for task in tasks}), 360)
        self.assertEqual(
            len({task.task_contract_sha256 for task in tasks}),
            360,
        )
        self.assertEqual(len({task.graph_sha256 for task in tasks}), 360)
        self.assertEqual(
            len({bundle.descriptor.fixture_id for bundle in bundles}),
            1_800,
        )
        self.assertEqual(
            len(
                {
                    bundle.descriptor.fixture_sha256
                    for bundle in bundles
                }
            ),
            1_800,
        )
        for index, bundle in enumerate(bundles):
            task = tasks[index // NINTH_PREFIX_PROFILE_COUNT]
            self.assertEqual(
                bundle.task_contract_sha256,
                task.task_contract_sha256,
            )
            self.assertEqual(
                bundle.descriptor,
                task.fixtures[index % NINTH_PREFIX_PROFILE_COUNT],
            )

    def test_supplied_task_evidence_is_reused_without_task_rebuild(self) -> None:
        with (
            mock.patch.object(
                prefix,
                "build_ninth_prefix_task_evidence",
                side_effect=AssertionError("task prefix rebuilt"),
            ),
            mock.patch.object(
                prefix,
                "build_linear_fixture_predecessor_evidence",
                return_value=self.linear_fixtures,
            ) as linear_builder,
            mock.patch.object(
                prefix,
                "build_ninth_tranche_fixture_catalog_local",
                return_value=self.ninth_catalog,
            ) as ninth_builder,
        ):
            rebuilt = build_ninth_prefix_fixture_evidence(
                self.task_evidence
            )
        self.assertEqual(rebuilt, self.fixture_evidence)
        self.assertIsNot(rebuilt, self.fixture_evidence)
        self.assertIsNot(
            rebuilt.bundles,
            self.fixture_evidence.bundles,
        )
        self.assertIs(rebuilt.task_evidence, self.task_evidence)
        self.assertIs(rebuilt.linear_evidence, self.linear_fixtures)
        self.assertIs(rebuilt.ninth_catalog, self.ninth_catalog)
        linear_builder.assert_called_once_with(
            self.task_evidence.linear_evidence
        )
        ninth_builder.assert_called_once_with(
            self.task_evidence.ninth_registry
        )

    def test_repeated_task_builds_own_fresh_objects(self) -> None:
        rebuilt = build_ninth_prefix_task_evidence()
        self.assertEqual(rebuilt, self.task_evidence)
        self.assertIsNot(rebuilt, self.task_evidence)
        self.assertIsNot(
            rebuilt.linear_evidence,
            self.task_evidence.linear_evidence,
        )
        self.assertIsNot(
            rebuilt.ninth_registry,
            self.task_evidence.ninth_registry,
        )
        self.assertIsNot(rebuilt.tasks, self.task_evidence.tasks)
        self.assertIsNot(
            rebuilt.tasks[0],
            self.task_evidence.tasks[0],
        )
        self.assertIsNot(
            rebuilt.tasks[-1],
            self.task_evidence.tasks[-1],
        )

    def test_evidence_is_frozen_and_mutations_fail_closed(self) -> None:
        with self.assertRaises(FrozenInstanceError):
            self.task_evidence.total_task_count = 0  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            self.fixture_evidence.total_fixture_count = 0  # type: ignore[misc]
        with self.assertRaises(NinthPredecessorEvidenceError):
            replace(
                self.task_evidence,
                tasks=tuple(reversed(self.task_evidence.tasks)),
            )
        with self.assertRaises(NinthPredecessorEvidenceError):
            replace(
                self.task_evidence,
                terminal_registry_sha256="0" * 64,
            )
        with self.assertRaises(NinthPredecessorEvidenceError):
            replace(
                self.fixture_evidence,
                bundles=tuple(reversed(self.fixture_evidence.bundles)),
            )
        with self.assertRaises(NinthPredecessorEvidenceError):
            replace(
                self.fixture_evidence,
                terminal_catalog_sha256="0" * 64,
            )

        hostile = copy.copy(self.task_evidence)
        object.__setattr__(
            hostile,
            "terminal_cumulative_suite_sha256",
            "0" * 64,
        )
        with self.assertRaises(NinthPredecessorEvidenceError):
            validate_ninth_prefix_task_evidence(hostile)
        self.assertFalse(verify_ninth_prefix_task_evidence(hostile))
        self.assertFalse(verify_ninth_prefix_task_evidence(object()))
        self.assertFalse(verify_ninth_prefix_fixture_evidence(object()))


if __name__ == "__main__":
    unittest.main()
