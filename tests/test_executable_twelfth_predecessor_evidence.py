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

import cbds.executable_twelfth_predecessor_evidence as prefix  # noqa: E402
from cbds.executable_eleventh_predecessor_evidence import (  # noqa: E402
    ELEVENTH_PREFIX_FIXTURE_COUNT,
    ELEVENTH_PREFIX_TASK_COUNT,
)
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from cbds.executable_twelfth_predecessor_evidence import (  # noqa: E402
    FROZEN_TWELFTH_CATALOG_SHA256,
    FROZEN_TWELFTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_TWELFTH_REGISTRY_SHA256,
    TWELFTH_PREFIX_FAMILY_ORDER,
    TWELFTH_PREFIX_FIXTURE_COUNT,
    TWELFTH_PREFIX_PROFILE_COUNT,
    TWELFTH_PREFIX_TASK_COUNT,
    TwelfthPredecessorEvidenceError,
    build_twelfth_prefix_fixture_evidence,
    build_twelfth_prefix_task_evidence,
    validate_twelfth_prefix_fixture_evidence,
    validate_twelfth_prefix_task_evidence,
    verify_twelfth_prefix_fixture_evidence,
    verify_twelfth_prefix_task_evidence,
)


_FORBIDDEN_RECURSIVE_PUBLICATION_BUILDERS = (
    "cbds.executable_fixture_twelfth_catalog."
    "build_twelfth_tranche_fixture_catalog",
    "cbds.executable_fixture_eleventh_catalog."
    "build_eleventh_tranche_fixture_catalog",
    "cbds.executable_fixture_tenth_catalog."
    "build_tenth_tranche_fixture_catalog",
    "cbds.executable_fixture_ninth_catalog."
    "build_ninth_tranche_fixture_catalog",
)


class TwelfthPredecessorEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        captured: dict[str, object] = {}
        real_eleventh_tasks = prefix.build_eleventh_prefix_task_evidence
        real_twelfth_registry = (
            prefix.build_twelfth_tranche_task_registry
        )
        real_eleventh_fixtures = (
            prefix.build_eleventh_prefix_fixture_evidence
        )
        real_twelfth_catalog = (
            prefix.build_twelfth_tranche_fixture_catalog_local
        )

        def eleventh_tasks():
            evidence = real_eleventh_tasks()
            captured["eleventh_tasks"] = evidence
            captured["eleventh_task_calls"] = (
                int(captured.get("eleventh_task_calls", 0)) + 1
            )
            return evidence

        def twelfth_registry(eleventh_evidence=None):
            captured["registry_argument"] = eleventh_evidence
            registry = real_twelfth_registry(eleventh_evidence)
            captured["twelfth_registry"] = registry
            captured["registry_calls"] = (
                int(captured.get("registry_calls", 0)) + 1
            )
            return registry

        def eleventh_fixtures(eleventh_evidence=None):
            captured["fixture_argument"] = eleventh_evidence
            evidence = real_eleventh_fixtures(eleventh_evidence)
            captured["eleventh_fixtures"] = evidence
            captured["eleventh_fixture_calls"] = (
                int(captured.get("eleventh_fixture_calls", 0)) + 1
            )
            return evidence

        def twelfth_catalog(registry):
            captured["catalog_argument"] = registry
            catalog = real_twelfth_catalog(registry)
            captured["twelfth_catalog"] = catalog
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
                    "build_eleventh_prefix_task_evidence",
                    side_effect=eleventh_tasks,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    prefix,
                    "build_twelfth_tranche_task_registry",
                    side_effect=twelfth_registry,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    prefix,
                    "build_eleventh_prefix_fixture_evidence",
                    side_effect=eleventh_fixtures,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    prefix,
                    "build_twelfth_tranche_fixture_catalog_local",
                    side_effect=twelfth_catalog,
                )
            )
            cls.fixture_evidence = (
                build_twelfth_prefix_fixture_evidence()
            )
            captured["forbidden_calls"] = tuple(
                item.call_count for item in forbidden
            )

        cls.task_evidence = cls.fixture_evidence.task_evidence
        cls.eleventh_tasks = captured["eleventh_tasks"]
        cls.eleventh_fixtures = captured["eleventh_fixtures"]
        cls.twelfth_registry = captured["twelfth_registry"]
        cls.twelfth_catalog = captured["twelfth_catalog"]
        cls.registry_argument = captured["registry_argument"]
        cls.fixture_argument = captured["fixture_argument"]
        cls.catalog_argument = captured["catalog_argument"]
        cls.eleventh_task_calls = captured["eleventh_task_calls"]
        cls.registry_calls = captured["registry_calls"]
        cls.eleventh_fixture_calls = captured["eleventh_fixture_calls"]
        cls.catalog_calls = captured["catalog_calls"]
        cls.forbidden_calls = captured["forbidden_calls"]

    def test_builds_each_component_once_and_reuses_exact_evidence(self) -> None:
        self.assertEqual(self.eleventh_task_calls, 1)
        self.assertEqual(self.registry_calls, 1)
        self.assertEqual(self.eleventh_fixture_calls, 1)
        self.assertEqual(self.catalog_calls, 1)
        self.assertIs(self.registry_argument, self.eleventh_tasks)
        self.assertIs(self.fixture_argument, self.eleventh_tasks)
        self.assertIs(self.catalog_argument, self.twelfth_registry)
        self.assertIs(
            self.task_evidence.eleventh_evidence,
            self.eleventh_tasks,
        )
        self.assertIs(
            self.fixture_evidence.eleventh_evidence,
            self.eleventh_fixtures,
        )
        self.assertIs(
            self.fixture_evidence.twelfth_catalog,
            self.twelfth_catalog,
        )
        self.assertIs(
            self.eleventh_fixtures.task_evidence,
            self.eleventh_tasks,
        )

    def test_exact_terminal_hashes_counts_and_family_order(self) -> None:
        validate_twelfth_prefix_task_evidence(self.task_evidence)
        validate_twelfth_prefix_fixture_evidence(self.fixture_evidence)
        self.assertTrue(
            verify_twelfth_prefix_task_evidence(self.task_evidence)
        )
        self.assertTrue(
            verify_twelfth_prefix_fixture_evidence(
                self.fixture_evidence
            )
        )
        self.assertEqual(ELEVENTH_PREFIX_TASK_COUNT, 400)
        self.assertEqual(ELEVENTH_PREFIX_FIXTURE_COUNT, 2_000)
        self.assertEqual(TWELFTH_PREFIX_TASK_COUNT, 420)
        self.assertEqual(TWELFTH_PREFIX_FIXTURE_COUNT, 2_100)
        self.assertEqual(TWELFTH_PREFIX_PROFILE_COUNT, 5)
        self.assertEqual(len(self.task_evidence.tasks), 420)
        self.assertEqual(len(self.fixture_evidence.bundles), 2_100)
        self.assertEqual(
            self.task_evidence.terminal_registry_sha256,
            FROZEN_TWELFTH_REGISTRY_SHA256,
        )
        self.assertEqual(
            self.task_evidence.terminal_cumulative_suite_sha256,
            FROZEN_TWELFTH_CUMULATIVE_SUITE_SHA256,
        )
        self.assertEqual(
            self.fixture_evidence.terminal_catalog_sha256,
            FROZEN_TWELFTH_CATALOG_SHA256,
        )
        self.assertEqual(
            self.twelfth_catalog.catalog_sha256,
            FROZEN_TWELFTH_CATALOG_SHA256,
        )
        self.assertEqual(
            tuple(
                task.family_id
                for index, task in enumerate(self.task_evidence.tasks)
                if index == 0
                or task.family_id
                != self.task_evidence.tasks[index - 1].family_id
            ),
            TWELFTH_PREFIX_FAMILY_ORDER,
        )
        self.assertEqual(len(self.task_evidence.registries), 12)
        self.assertEqual(len(self.fixture_evidence.catalogs), 12)
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
        self.assertEqual(len({task.task_id for task in tasks}), 420)
        self.assertEqual(
            len({task.task_contract_sha256 for task in tasks}),
            420,
        )
        self.assertEqual(len({task.graph_sha256 for task in tasks}), 420)
        self.assertEqual(
            len({bundle.descriptor.fixture_id for bundle in bundles}),
            2_100,
        )
        self.assertEqual(
            len(
                {
                    bundle.descriptor.fixture_sha256
                    for bundle in bundles
                }
            ),
            2_100,
        )
        for index, bundle in enumerate(bundles):
            task = tasks[index // TWELFTH_PREFIX_PROFILE_COUNT]
            profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[
                index % TWELFTH_PREFIX_PROFILE_COUNT
            ]
            self.assertEqual(
                bundle.task_contract_sha256,
                task.task_contract_sha256,
            )
            self.assertEqual(bundle.profile_sha256, profile.profile_sha256)
            self.assertEqual(
                bundle.descriptor,
                task.fixtures[index % TWELFTH_PREFIX_PROFILE_COUNT],
            )
            self.assertIs(bundle.candidate_execution_authorized, False)
            self.assertIs(bundle.model_selection_eligible, False)
            self.assertIs(bundle.claim_authorized, False)

    def test_prefix_and_twelfth_additions_have_exact_object_ownership(
        self,
    ) -> None:
        self.assertEqual(
            self.task_evidence.tasks[:ELEVENTH_PREFIX_TASK_COUNT],
            self.eleventh_tasks.tasks,
        )
        for observed, expected in zip(
            self.task_evidence.tasks[:ELEVENTH_PREFIX_TASK_COUNT],
            self.eleventh_tasks.tasks,
            strict=True,
        ):
            self.assertIs(observed, expected)
        for observed, expected in zip(
            self.task_evidence.tasks[ELEVENTH_PREFIX_TASK_COUNT:],
            self.twelfth_registry.added_tasks,
            strict=True,
        ):
            self.assertIs(observed, expected)
            self.assertTrue(
                all(
                    observed is not predecessor
                    for predecessor in self.eleventh_tasks.tasks
                )
            )

        for observed, expected in zip(
            self.fixture_evidence.bundles[
                :ELEVENTH_PREFIX_FIXTURE_COUNT
            ],
            self.eleventh_fixtures.bundles,
            strict=True,
        ):
            self.assertIs(observed, expected)
        for observed, expected in zip(
            self.fixture_evidence.bundles[
                ELEVENTH_PREFIX_FIXTURE_COUNT:
            ],
            self.twelfth_catalog.bundles,
            strict=True,
        ):
            self.assertIs(observed, expected)
            self.assertTrue(
                all(
                    observed is not predecessor
                    for predecessor in self.eleventh_fixtures.bundles
                )
            )

    def test_recursive_publication_builders_are_never_called(self) -> None:
        self.assertEqual(
            self.forbidden_calls,
            (0,) * len(_FORBIDDEN_RECURSIVE_PUBLICATION_BUILDERS),
        )
        source = (
            ROOT
            / "src/cbds/executable_twelfth_predecessor_evidence.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("domain_sha256", source)
        self.assertNotIn("@lru_cache", source)
        self.assertNotIn("def compute_", source)

    def test_supplied_task_evidence_is_reused_without_task_rebuild(self) -> None:
        with (
            mock.patch.object(
                prefix,
                "build_twelfth_prefix_task_evidence",
                side_effect=AssertionError("task prefix rebuilt"),
            ),
            mock.patch.object(
                prefix,
                "build_eleventh_prefix_fixture_evidence",
                return_value=self.eleventh_fixtures,
            ) as eleventh_builder,
            mock.patch.object(
                prefix,
                "build_twelfth_tranche_fixture_catalog_local",
                return_value=self.twelfth_catalog,
            ) as twelfth_builder,
        ):
            rebuilt = build_twelfth_prefix_fixture_evidence(
                self.task_evidence
            )
        self.assertEqual(rebuilt, self.fixture_evidence)
        self.assertIsNot(rebuilt, self.fixture_evidence)
        self.assertIsNot(rebuilt.bundles, self.fixture_evidence.bundles)
        self.assertIs(rebuilt.task_evidence, self.task_evidence)
        self.assertIs(rebuilt.eleventh_evidence, self.eleventh_fixtures)
        self.assertIs(rebuilt.twelfth_catalog, self.twelfth_catalog)
        eleventh_builder.assert_called_once_with(
            self.task_evidence.eleventh_evidence
        )
        twelfth_builder.assert_called_once_with(
            self.task_evidence.twelfth_registry
        )

    def test_supplied_eleventh_prefix_is_reused_with_fresh_twelfth_tasks(
        self,
    ) -> None:
        with mock.patch.object(
            prefix,
            "build_eleventh_prefix_task_evidence",
            side_effect=AssertionError("eleventh prefix rebuilt"),
        ):
            rebuilt = build_twelfth_prefix_task_evidence(
                self.eleventh_tasks
            )
        self.assertEqual(rebuilt, self.task_evidence)
        self.assertIsNot(rebuilt, self.task_evidence)
        self.assertIs(rebuilt.eleventh_evidence, self.eleventh_tasks)
        self.assertIsNot(
            rebuilt.twelfth_registry,
            self.task_evidence.twelfth_registry,
        )
        self.assertIsNot(rebuilt.tasks, self.task_evidence.tasks)
        for left, right in zip(
            rebuilt.twelfth_registry.added_tasks,
            self.task_evidence.twelfth_registry.added_tasks,
            strict=True,
        ):
            self.assertEqual(left, right)
            self.assertIsNot(left, right)

    def test_evidence_is_frozen_and_mutations_fail_closed(self) -> None:
        with self.assertRaises(FrozenInstanceError):
            self.task_evidence.total_task_count = 0  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            self.fixture_evidence.total_fixture_count = 0  # type: ignore[misc]
        with self.assertRaises(TwelfthPredecessorEvidenceError):
            replace(
                self.task_evidence,
                tasks=tuple(reversed(self.task_evidence.tasks)),
            )
        with self.assertRaises(TwelfthPredecessorEvidenceError):
            replace(
                self.task_evidence,
                terminal_registry_sha256="0" * 64,
            )
        with self.assertRaises(TwelfthPredecessorEvidenceError):
            replace(
                self.fixture_evidence,
                bundles=tuple(reversed(self.fixture_evidence.bundles)),
            )
        with self.assertRaises(TwelfthPredecessorEvidenceError):
            replace(
                self.fixture_evidence,
                terminal_catalog_sha256="0" * 64,
            )

        hostile_task = copy.copy(self.task_evidence)
        object.__setattr__(
            hostile_task,
            "terminal_cumulative_suite_sha256",
            "0" * 64,
        )
        with self.assertRaises(TwelfthPredecessorEvidenceError):
            validate_twelfth_prefix_task_evidence(hostile_task)
        self.assertFalse(verify_twelfth_prefix_task_evidence(hostile_task))

        relinked_task = copy.copy(self.task_evidence)
        object.__setattr__(
            relinked_task,
            "eleventh_evidence",
            copy.copy(self.task_evidence.eleventh_evidence),
        )
        relinked_fixture = copy.copy(self.fixture_evidence)
        object.__setattr__(
            relinked_fixture,
            "task_evidence",
            relinked_task,
        )
        with self.assertRaises(TwelfthPredecessorEvidenceError):
            validate_twelfth_prefix_fixture_evidence(relinked_fixture)
        self.assertFalse(
            verify_twelfth_prefix_fixture_evidence(relinked_fixture)
        )
        self.assertFalse(verify_twelfth_prefix_task_evidence(object()))
        self.assertFalse(
            verify_twelfth_prefix_fixture_evidence(object())
        )


if __name__ == "__main__":
    unittest.main()
