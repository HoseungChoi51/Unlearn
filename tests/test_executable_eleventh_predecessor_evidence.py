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

import cbds.executable_eleventh_predecessor_evidence as prefix  # noqa: E402
from cbds.executable_eleventh_predecessor_evidence import (  # noqa: E402
    ELEVENTH_PREFIX_FAMILY_ORDER,
    ELEVENTH_PREFIX_FIXTURE_COUNT,
    ELEVENTH_PREFIX_PROFILE_COUNT,
    ELEVENTH_PREFIX_TASK_COUNT,
    FROZEN_ELEVENTH_CATALOG_SHA256,
    FROZEN_ELEVENTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_ELEVENTH_REGISTRY_SHA256,
    EleventhPredecessorEvidenceError,
    build_eleventh_prefix_fixture_evidence,
    build_eleventh_prefix_task_evidence,
    validate_eleventh_prefix_fixture_evidence,
    validate_eleventh_prefix_task_evidence,
    verify_eleventh_prefix_fixture_evidence,
    verify_eleventh_prefix_task_evidence,
)
from cbds.executable_tenth_predecessor_evidence import (  # noqa: E402
    TENTH_PREFIX_FIXTURE_COUNT,
    TENTH_PREFIX_TASK_COUNT,
)


_FORBIDDEN_RECURSIVE_PUBLICATION_BUILDERS = (
    "cbds.executable_fixture_eleventh_catalog."
    "build_eleventh_tranche_fixture_catalog",
    "cbds.executable_fixture_tenth_catalog."
    "build_tenth_tranche_fixture_catalog",
    "cbds.executable_fixture_ninth_catalog."
    "build_ninth_tranche_fixture_catalog",
)


class EleventhPredecessorEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        captured: dict[str, object] = {}
        real_tenth_tasks = prefix.build_tenth_prefix_task_evidence
        real_eleventh_registry = (
            prefix.build_eleventh_tranche_task_registry
        )
        real_tenth_fixtures = prefix.build_tenth_prefix_fixture_evidence
        real_eleventh_catalog = (
            prefix.build_eleventh_tranche_fixture_catalog_local
        )

        def tenth_tasks():
            evidence = real_tenth_tasks()
            captured["tenth_tasks"] = evidence
            captured["tenth_task_calls"] = (
                int(captured.get("tenth_task_calls", 0)) + 1
            )
            return evidence

        def eleventh_registry(tenth_evidence=None):
            captured["registry_argument"] = tenth_evidence
            registry = real_eleventh_registry(tenth_evidence)
            captured["eleventh_registry"] = registry
            captured["registry_calls"] = (
                int(captured.get("registry_calls", 0)) + 1
            )
            return registry

        def tenth_fixtures(tenth_evidence=None):
            captured["fixture_argument"] = tenth_evidence
            evidence = real_tenth_fixtures(tenth_evidence)
            captured["tenth_fixtures"] = evidence
            captured["tenth_fixture_calls"] = (
                int(captured.get("tenth_fixture_calls", 0)) + 1
            )
            return evidence

        def eleventh_catalog(registry):
            captured["catalog_argument"] = registry
            catalog = real_eleventh_catalog(registry)
            captured["eleventh_catalog"] = catalog
            captured["catalog_calls"] = (
                int(captured.get("catalog_calls", 0)) + 1
            )
            return catalog

        with ExitStack() as stack:
            forbidden = tuple(
                stack.enter_context(
                    mock.patch(
                        path,
                        side_effect=AssertionError(
                            f"recursive publication builder called: {path}"
                        ),
                    )
                )
                for path in _FORBIDDEN_RECURSIVE_PUBLICATION_BUILDERS
            )
            stack.enter_context(
                mock.patch.object(
                    prefix,
                    "build_tenth_prefix_task_evidence",
                    side_effect=tenth_tasks,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    prefix,
                    "build_eleventh_tranche_task_registry",
                    side_effect=eleventh_registry,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    prefix,
                    "build_tenth_prefix_fixture_evidence",
                    side_effect=tenth_fixtures,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    prefix,
                    "build_eleventh_tranche_fixture_catalog_local",
                    side_effect=eleventh_catalog,
                )
            )
            cls.fixture_evidence = (
                build_eleventh_prefix_fixture_evidence()
            )
            captured["forbidden_calls"] = tuple(
                item.call_count for item in forbidden
            )

        cls.task_evidence = cls.fixture_evidence.task_evidence
        cls.tenth_tasks = captured["tenth_tasks"]
        cls.tenth_fixtures = captured["tenth_fixtures"]
        cls.eleventh_registry = captured["eleventh_registry"]
        cls.eleventh_catalog = captured["eleventh_catalog"]
        cls.registry_argument = captured["registry_argument"]
        cls.fixture_argument = captured["fixture_argument"]
        cls.catalog_argument = captured["catalog_argument"]
        cls.tenth_task_calls = captured["tenth_task_calls"]
        cls.registry_calls = captured["registry_calls"]
        cls.tenth_fixture_calls = captured["tenth_fixture_calls"]
        cls.catalog_calls = captured["catalog_calls"]
        cls.forbidden_calls = captured["forbidden_calls"]

    def test_builds_each_component_once_and_reuses_exact_evidence(self) -> None:
        self.assertEqual(self.tenth_task_calls, 1)
        self.assertEqual(self.registry_calls, 1)
        self.assertEqual(self.tenth_fixture_calls, 1)
        self.assertEqual(self.catalog_calls, 1)
        self.assertIs(self.registry_argument, self.tenth_tasks)
        self.assertIs(self.fixture_argument, self.tenth_tasks)
        self.assertIs(self.catalog_argument, self.eleventh_registry)
        self.assertIs(
            self.task_evidence.tenth_evidence,
            self.tenth_tasks,
        )
        self.assertIs(
            self.fixture_evidence.tenth_evidence,
            self.tenth_fixtures,
        )
        self.assertIs(
            self.fixture_evidence.eleventh_catalog,
            self.eleventh_catalog,
        )
        self.assertIs(
            self.tenth_fixtures.task_evidence,
            self.tenth_tasks,
        )

    def test_exact_terminal_hashes_counts_and_family_order(self) -> None:
        validate_eleventh_prefix_task_evidence(self.task_evidence)
        validate_eleventh_prefix_fixture_evidence(self.fixture_evidence)
        self.assertTrue(
            verify_eleventh_prefix_task_evidence(self.task_evidence)
        )
        self.assertTrue(
            verify_eleventh_prefix_fixture_evidence(
                self.fixture_evidence
            )
        )
        self.assertEqual(TENTH_PREFIX_TASK_COUNT, 380)
        self.assertEqual(TENTH_PREFIX_FIXTURE_COUNT, 1_900)
        self.assertEqual(ELEVENTH_PREFIX_TASK_COUNT, 400)
        self.assertEqual(ELEVENTH_PREFIX_FIXTURE_COUNT, 2_000)
        self.assertEqual(ELEVENTH_PREFIX_PROFILE_COUNT, 5)
        self.assertEqual(len(self.task_evidence.tasks), 400)
        self.assertEqual(len(self.fixture_evidence.bundles), 2_000)
        self.assertEqual(
            self.task_evidence.terminal_registry_sha256,
            FROZEN_ELEVENTH_REGISTRY_SHA256,
        )
        self.assertEqual(
            self.task_evidence.terminal_cumulative_suite_sha256,
            FROZEN_ELEVENTH_CUMULATIVE_SUITE_SHA256,
        )
        self.assertEqual(
            self.fixture_evidence.terminal_catalog_sha256,
            FROZEN_ELEVENTH_CATALOG_SHA256,
        )
        self.assertEqual(
            tuple(
                task.family_id
                for index, task in enumerate(self.task_evidence.tasks)
                if index == 0
                or task.family_id
                != self.task_evidence.tasks[index - 1].family_id
            ),
            ELEVENTH_PREFIX_FAMILY_ORDER,
        )
        self.assertEqual(len(self.task_evidence.registries), 11)
        self.assertEqual(len(self.fixture_evidence.catalogs), 11)
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
        self.assertEqual(len({task.task_id for task in tasks}), 400)
        self.assertEqual(
            len({task.task_contract_sha256 for task in tasks}),
            400,
        )
        self.assertEqual(len({task.graph_sha256 for task in tasks}), 400)
        self.assertEqual(
            len({bundle.descriptor.fixture_id for bundle in bundles}),
            2_000,
        )
        self.assertEqual(
            len(
                {
                    bundle.descriptor.fixture_sha256
                    for bundle in bundles
                }
            ),
            2_000,
        )
        for index, bundle in enumerate(bundles):
            task = tasks[index // ELEVENTH_PREFIX_PROFILE_COUNT]
            self.assertEqual(
                bundle.task_contract_sha256,
                task.task_contract_sha256,
            )
            self.assertEqual(
                bundle.descriptor,
                task.fixtures[index % ELEVENTH_PREFIX_PROFILE_COUNT],
            )
            self.assertIs(
                bundle.candidate_execution_authorized,
                False,
            )
            self.assertIs(bundle.model_selection_eligible, False)
            self.assertIs(bundle.claim_authorized, False)

    def test_recursive_publication_builders_are_never_called(self) -> None:
        self.assertEqual(
            self.forbidden_calls,
            (0,) * len(_FORBIDDEN_RECURSIVE_PUBLICATION_BUILDERS),
        )

    def test_supplied_task_evidence_is_reused_without_task_rebuild(self) -> None:
        with (
            mock.patch.object(
                prefix,
                "build_eleventh_prefix_task_evidence",
                side_effect=AssertionError("task prefix rebuilt"),
            ),
            mock.patch.object(
                prefix,
                "build_tenth_prefix_fixture_evidence",
                return_value=self.tenth_fixtures,
            ) as tenth_builder,
            mock.patch.object(
                prefix,
                "build_eleventh_tranche_fixture_catalog_local",
                return_value=self.eleventh_catalog,
            ) as eleventh_builder,
        ):
            rebuilt = build_eleventh_prefix_fixture_evidence(
                self.task_evidence
            )
        self.assertEqual(rebuilt, self.fixture_evidence)
        self.assertIsNot(rebuilt, self.fixture_evidence)
        self.assertIsNot(
            rebuilt.bundles,
            self.fixture_evidence.bundles,
        )
        self.assertIs(rebuilt.task_evidence, self.task_evidence)
        self.assertIs(rebuilt.tenth_evidence, self.tenth_fixtures)
        self.assertIs(rebuilt.eleventh_catalog, self.eleventh_catalog)
        tenth_builder.assert_called_once_with(
            self.task_evidence.tenth_evidence
        )
        eleventh_builder.assert_called_once_with(
            self.task_evidence.eleventh_registry
        )

    def test_supplied_tenth_task_prefix_is_reused_without_rebuild(self) -> None:
        with mock.patch.object(
            prefix,
            "build_tenth_prefix_task_evidence",
            side_effect=AssertionError("tenth prefix rebuilt"),
        ):
            rebuilt = build_eleventh_prefix_task_evidence(
                self.tenth_tasks
            )
        self.assertEqual(rebuilt, self.task_evidence)
        self.assertIsNot(rebuilt, self.task_evidence)
        self.assertIs(rebuilt.tenth_evidence, self.tenth_tasks)

    def test_repeated_task_builds_own_fresh_objects(self) -> None:
        rebuilt = build_eleventh_prefix_task_evidence()
        self.assertEqual(rebuilt, self.task_evidence)
        self.assertIsNot(rebuilt, self.task_evidence)
        self.assertIsNot(
            rebuilt.tenth_evidence,
            self.task_evidence.tenth_evidence,
        )
        self.assertIsNot(
            rebuilt.eleventh_registry,
            self.task_evidence.eleventh_registry,
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
        for task in rebuilt.eleventh_registry.added_tasks:
            self.assertTrue(
                all(task is not predecessor for predecessor in self.tenth_tasks.tasks)
            )

    def test_evidence_is_frozen_and_mutations_fail_closed(self) -> None:
        with self.assertRaises(FrozenInstanceError):
            self.task_evidence.total_task_count = 0  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            self.fixture_evidence.total_fixture_count = 0  # type: ignore[misc]
        with self.assertRaises(EleventhPredecessorEvidenceError):
            replace(
                self.task_evidence,
                tasks=tuple(reversed(self.task_evidence.tasks)),
            )
        with self.assertRaises(EleventhPredecessorEvidenceError):
            replace(
                self.task_evidence,
                terminal_registry_sha256="0" * 64,
            )
        with self.assertRaises(EleventhPredecessorEvidenceError):
            replace(
                self.fixture_evidence,
                bundles=tuple(reversed(self.fixture_evidence.bundles)),
            )
        with self.assertRaises(EleventhPredecessorEvidenceError):
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
        with self.assertRaises(EleventhPredecessorEvidenceError):
            validate_eleventh_prefix_task_evidence(hostile)
        self.assertFalse(verify_eleventh_prefix_task_evidence(hostile))
        self.assertFalse(verify_eleventh_prefix_task_evidence(object()))
        self.assertFalse(
            verify_eleventh_prefix_fixture_evidence(object())
        )


if __name__ == "__main__":
    unittest.main()
