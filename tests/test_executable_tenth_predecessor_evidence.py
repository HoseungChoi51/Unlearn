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

import cbds.executable_tenth_predecessor_evidence as prefix  # noqa: E402
from cbds.executable_ninth_predecessor_evidence import (  # noqa: E402
    NINTH_PREFIX_FIXTURE_COUNT,
    NINTH_PREFIX_TASK_COUNT,
)
from cbds.executable_tenth_predecessor_evidence import (  # noqa: E402
    FROZEN_TENTH_CATALOG_SHA256,
    FROZEN_TENTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_TENTH_REGISTRY_SHA256,
    TENTH_PREFIX_FAMILY_ORDER,
    TENTH_PREFIX_FIXTURE_COUNT,
    TENTH_PREFIX_PROFILE_COUNT,
    TENTH_PREFIX_TASK_COUNT,
    TenthPredecessorEvidenceError,
    build_tenth_prefix_fixture_evidence,
    build_tenth_prefix_task_evidence,
    validate_tenth_prefix_fixture_evidence,
    validate_tenth_prefix_task_evidence,
    verify_tenth_prefix_fixture_evidence,
    verify_tenth_prefix_task_evidence,
)


class TenthPredecessorEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        captured: dict[str, object] = {}
        real_ninth_tasks = prefix.build_ninth_prefix_task_evidence
        real_tenth_registry = prefix.build_tenth_tranche_task_registry
        real_ninth_fixtures = prefix.build_ninth_prefix_fixture_evidence
        real_tenth_catalog = (
            prefix.build_tenth_tranche_fixture_catalog_local
        )

        def ninth_tasks():
            evidence = real_ninth_tasks()
            captured["ninth_tasks"] = evidence
            captured["ninth_task_calls"] = (
                int(captured.get("ninth_task_calls", 0)) + 1
            )
            return evidence

        def tenth_registry(ninth_evidence=None):
            captured["registry_argument"] = ninth_evidence
            registry = real_tenth_registry(ninth_evidence)
            captured["tenth_registry"] = registry
            captured["registry_calls"] = (
                int(captured.get("registry_calls", 0)) + 1
            )
            return registry

        def ninth_fixtures(ninth_evidence=None):
            captured["fixture_argument"] = ninth_evidence
            evidence = real_ninth_fixtures(ninth_evidence)
            captured["ninth_fixtures"] = evidence
            captured["ninth_fixture_calls"] = (
                int(captured.get("ninth_fixture_calls", 0)) + 1
            )
            return evidence

        def tenth_catalog(registry):
            captured["catalog_argument"] = registry
            catalog = real_tenth_catalog(registry)
            captured["tenth_catalog"] = catalog
            captured["catalog_calls"] = (
                int(captured.get("catalog_calls", 0)) + 1
            )
            return catalog

        with ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    prefix,
                    "build_ninth_prefix_task_evidence",
                    side_effect=ninth_tasks,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    prefix,
                    "build_tenth_tranche_task_registry",
                    side_effect=tenth_registry,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    prefix,
                    "build_ninth_prefix_fixture_evidence",
                    side_effect=ninth_fixtures,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    prefix,
                    "build_tenth_tranche_fixture_catalog_local",
                    side_effect=tenth_catalog,
                )
            )
            stack.enter_context(
                mock.patch(
                    "cbds.executable_fixture_tenth_catalog."
                    "build_tenth_tranche_fixture_catalog",
                    side_effect=AssertionError(
                        "recursive tenth publication builder called"
                    ),
                )
            )
            cls.fixture_evidence = build_tenth_prefix_fixture_evidence()

        cls.task_evidence = cls.fixture_evidence.task_evidence
        cls.ninth_tasks = captured["ninth_tasks"]
        cls.ninth_fixtures = captured["ninth_fixtures"]
        cls.tenth_registry = captured["tenth_registry"]
        cls.tenth_catalog = captured["tenth_catalog"]
        cls.registry_argument = captured["registry_argument"]
        cls.fixture_argument = captured["fixture_argument"]
        cls.catalog_argument = captured["catalog_argument"]
        cls.ninth_task_calls = captured["ninth_task_calls"]
        cls.registry_calls = captured["registry_calls"]
        cls.ninth_fixture_calls = captured["ninth_fixture_calls"]
        cls.catalog_calls = captured["catalog_calls"]

    def test_builds_each_component_once_and_reuses_exact_evidence(self) -> None:
        self.assertEqual(self.ninth_task_calls, 1)
        self.assertEqual(self.registry_calls, 1)
        self.assertEqual(self.ninth_fixture_calls, 1)
        self.assertEqual(self.catalog_calls, 1)
        self.assertIs(self.registry_argument, self.ninth_tasks)
        self.assertIs(self.fixture_argument, self.ninth_tasks)
        self.assertIs(self.catalog_argument, self.tenth_registry)
        self.assertIs(
            self.task_evidence.ninth_evidence,
            self.ninth_tasks,
        )
        self.assertIs(
            self.fixture_evidence.ninth_evidence,
            self.ninth_fixtures,
        )
        self.assertIs(
            self.fixture_evidence.tenth_catalog,
            self.tenth_catalog,
        )
        self.assertIs(
            self.ninth_fixtures.task_evidence,
            self.ninth_tasks,
        )

    def test_exact_terminal_hashes_counts_and_family_order(self) -> None:
        validate_tenth_prefix_task_evidence(self.task_evidence)
        validate_tenth_prefix_fixture_evidence(self.fixture_evidence)
        self.assertTrue(
            verify_tenth_prefix_task_evidence(self.task_evidence)
        )
        self.assertTrue(
            verify_tenth_prefix_fixture_evidence(self.fixture_evidence)
        )
        self.assertEqual(NINTH_PREFIX_TASK_COUNT, 360)
        self.assertEqual(NINTH_PREFIX_FIXTURE_COUNT, 1_800)
        self.assertEqual(TENTH_PREFIX_TASK_COUNT, 380)
        self.assertEqual(TENTH_PREFIX_FIXTURE_COUNT, 1_900)
        self.assertEqual(TENTH_PREFIX_PROFILE_COUNT, 5)
        self.assertEqual(len(self.task_evidence.tasks), 380)
        self.assertEqual(len(self.fixture_evidence.bundles), 1_900)
        self.assertEqual(
            self.task_evidence.terminal_registry_sha256,
            FROZEN_TENTH_REGISTRY_SHA256,
        )
        self.assertEqual(
            self.task_evidence.terminal_cumulative_suite_sha256,
            FROZEN_TENTH_CUMULATIVE_SUITE_SHA256,
        )
        self.assertEqual(
            self.fixture_evidence.terminal_catalog_sha256,
            FROZEN_TENTH_CATALOG_SHA256,
        )
        self.assertEqual(
            tuple(
                task.family_id
                for index, task in enumerate(self.task_evidence.tasks)
                if index == 0
                or task.family_id
                != self.task_evidence.tasks[index - 1].family_id
            ),
            TENTH_PREFIX_FAMILY_ORDER,
        )
        self.assertEqual(len(self.task_evidence.registries), 10)
        self.assertEqual(len(self.fixture_evidence.catalogs), 10)
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
        self.assertEqual(len({task.task_id for task in tasks}), 380)
        self.assertEqual(
            len({task.task_contract_sha256 for task in tasks}),
            380,
        )
        self.assertEqual(len({task.graph_sha256 for task in tasks}), 380)
        self.assertEqual(
            len({bundle.descriptor.fixture_id for bundle in bundles}),
            1_900,
        )
        self.assertEqual(
            len(
                {
                    bundle.descriptor.fixture_sha256
                    for bundle in bundles
                }
            ),
            1_900,
        )
        for index, bundle in enumerate(bundles):
            task = tasks[index // TENTH_PREFIX_PROFILE_COUNT]
            self.assertEqual(
                bundle.task_contract_sha256,
                task.task_contract_sha256,
            )
            self.assertEqual(
                bundle.descriptor,
                task.fixtures[index % TENTH_PREFIX_PROFILE_COUNT],
            )

    def test_supplied_task_evidence_is_reused_without_task_rebuild(self) -> None:
        with (
            mock.patch.object(
                prefix,
                "build_tenth_prefix_task_evidence",
                side_effect=AssertionError("task prefix rebuilt"),
            ),
            mock.patch.object(
                prefix,
                "build_ninth_prefix_fixture_evidence",
                return_value=self.ninth_fixtures,
            ) as ninth_builder,
            mock.patch.object(
                prefix,
                "build_tenth_tranche_fixture_catalog_local",
                return_value=self.tenth_catalog,
            ) as tenth_builder,
        ):
            rebuilt = build_tenth_prefix_fixture_evidence(
                self.task_evidence
            )
        self.assertEqual(rebuilt, self.fixture_evidence)
        self.assertIsNot(rebuilt, self.fixture_evidence)
        self.assertIsNot(
            rebuilt.bundles,
            self.fixture_evidence.bundles,
        )
        self.assertIs(rebuilt.task_evidence, self.task_evidence)
        self.assertIs(rebuilt.ninth_evidence, self.ninth_fixtures)
        self.assertIs(rebuilt.tenth_catalog, self.tenth_catalog)
        ninth_builder.assert_called_once_with(
            self.task_evidence.ninth_evidence
        )
        tenth_builder.assert_called_once_with(
            self.task_evidence.tenth_registry
        )

    def test_repeated_task_builds_own_fresh_objects(self) -> None:
        rebuilt = build_tenth_prefix_task_evidence()
        self.assertEqual(rebuilt, self.task_evidence)
        self.assertIsNot(rebuilt, self.task_evidence)
        self.assertIsNot(
            rebuilt.ninth_evidence,
            self.task_evidence.ninth_evidence,
        )
        self.assertIsNot(
            rebuilt.tenth_registry,
            self.task_evidence.tenth_registry,
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
        with self.assertRaises(TenthPredecessorEvidenceError):
            replace(
                self.task_evidence,
                tasks=tuple(reversed(self.task_evidence.tasks)),
            )
        with self.assertRaises(TenthPredecessorEvidenceError):
            replace(
                self.task_evidence,
                terminal_registry_sha256="0" * 64,
            )
        with self.assertRaises(TenthPredecessorEvidenceError):
            replace(
                self.fixture_evidence,
                bundles=tuple(reversed(self.fixture_evidence.bundles)),
            )
        with self.assertRaises(TenthPredecessorEvidenceError):
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
        with self.assertRaises(TenthPredecessorEvidenceError):
            validate_tenth_prefix_task_evidence(hostile)
        self.assertFalse(verify_tenth_prefix_task_evidence(hostile))
        self.assertFalse(verify_tenth_prefix_task_evidence(object()))
        self.assertFalse(verify_tenth_prefix_fixture_evidence(object()))


if __name__ == "__main__":
    unittest.main()
