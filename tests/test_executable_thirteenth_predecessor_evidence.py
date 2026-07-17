from __future__ import annotations

import ast
import copy
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields, replace
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import cbds.executable_thirteenth_predecessor_evidence as prefix  # noqa: E402
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from cbds.executable_thirteenth_predecessor_evidence import (  # noqa: E402
    FROZEN_THIRTEENTH_CATALOG_SHA256,
    FROZEN_THIRTEENTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_THIRTEENTH_REGISTRY_SHA256,
    THIRTEENTH_PREFIX_FAMILY_ORDER,
    THIRTEENTH_PREFIX_FIXTURE_COUNT,
    THIRTEENTH_PREFIX_PROFILE_COUNT,
    THIRTEENTH_PREFIX_TASK_COUNT,
    ThirteenthPredecessorEvidenceError,
    build_thirteenth_prefix_fixture_evidence,
    build_thirteenth_prefix_task_evidence,
    validate_thirteenth_prefix_fixture_evidence,
    validate_thirteenth_prefix_task_evidence,
    verify_thirteenth_prefix_fixture_evidence,
    verify_thirteenth_prefix_task_evidence,
)
from cbds.executable_twelfth_predecessor_evidence import (  # noqa: E402
    TWELFTH_PREFIX_FIXTURE_COUNT,
    TWELFTH_PREFIX_TASK_COUNT,
)


_FORBIDDEN_RECURSIVE_PUBLICATION_BUILDERS = (
    "cbds.executable_fixture_thirteenth_catalog."
    "build_thirteenth_tranche_fixture_catalog",
    "cbds.executable_fixture_twelfth_catalog."
    "build_twelfth_tranche_fixture_catalog",
    "cbds.executable_fixture_eleventh_catalog."
    "build_eleventh_tranche_fixture_catalog",
    "cbds.executable_fixture_tenth_catalog."
    "build_tenth_tranche_fixture_catalog",
)


def _populated_subclass_copy(value: object) -> object:
    """Return an equal populated subclass instance without invoking validation."""

    hostile_type = type(
        f"Hostile{type(value).__name__}",
        (type(value),),
        {},
    )
    hostile = object.__new__(hostile_type)
    for item in fields(value):
        object.__setattr__(hostile, item.name, getattr(value, item.name))
    return hostile


def _is_full_catalog_publication_builder(name: str) -> bool:
    return (
        name.startswith("build_")
        and name.endswith("_tranche_fixture_catalog")
    )


class ThirteenthPredecessorEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        captured: dict[str, object] = {}
        real_twelfth_tasks = prefix.build_twelfth_prefix_task_evidence
        real_thirteenth_registry = (
            prefix.build_thirteenth_tranche_task_registry
        )
        real_twelfth_fixtures = (
            prefix.build_twelfth_prefix_fixture_evidence
        )
        real_thirteenth_catalog = (
            prefix.build_thirteenth_tranche_fixture_catalog_local
        )

        def twelfth_tasks():
            evidence = real_twelfth_tasks()
            captured["twelfth_tasks"] = evidence
            captured["twelfth_task_calls"] = (
                int(captured.get("twelfth_task_calls", 0)) + 1
            )
            return evidence

        def thirteenth_registry(twelfth_evidence=None):
            captured["registry_argument"] = twelfth_evidence
            registry = real_thirteenth_registry(twelfth_evidence)
            captured["thirteenth_registry"] = registry
            captured["registry_calls"] = (
                int(captured.get("registry_calls", 0)) + 1
            )
            return registry

        def twelfth_fixtures(twelfth_evidence=None):
            captured["fixture_argument"] = twelfth_evidence
            evidence = real_twelfth_fixtures(twelfth_evidence)
            captured["twelfth_fixtures"] = evidence
            captured["twelfth_fixture_calls"] = (
                int(captured.get("twelfth_fixture_calls", 0)) + 1
            )
            return evidence

        def thirteenth_catalog(registry):
            captured["catalog_argument"] = registry
            catalog = real_thirteenth_catalog(registry)
            captured["thirteenth_catalog"] = catalog
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
                            f"recursive publication builder called: {path}",
                        ),
                    )
                )
                for path in _FORBIDDEN_RECURSIVE_PUBLICATION_BUILDERS
            )
            stack.enter_context(
                mock.patch.object(
                    prefix,
                    "build_twelfth_prefix_task_evidence",
                    side_effect=twelfth_tasks,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    prefix,
                    "build_thirteenth_tranche_task_registry",
                    side_effect=thirteenth_registry,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    prefix,
                    "build_twelfth_prefix_fixture_evidence",
                    side_effect=twelfth_fixtures,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    prefix,
                    "build_thirteenth_tranche_fixture_catalog_local",
                    side_effect=thirteenth_catalog,
                )
            )
            cls.fixture_evidence = (
                build_thirteenth_prefix_fixture_evidence()
            )
            captured["forbidden_calls"] = tuple(
                item.call_count for item in forbidden
            )

        cls.task_evidence = cls.fixture_evidence.task_evidence
        cls.twelfth_tasks = captured["twelfth_tasks"]
        cls.twelfth_fixtures = captured["twelfth_fixtures"]
        cls.thirteenth_registry = captured["thirteenth_registry"]
        cls.thirteenth_catalog = captured["thirteenth_catalog"]
        cls.registry_argument = captured["registry_argument"]
        cls.fixture_argument = captured["fixture_argument"]
        cls.catalog_argument = captured["catalog_argument"]
        cls.twelfth_task_calls = captured["twelfth_task_calls"]
        cls.registry_calls = captured["registry_calls"]
        cls.twelfth_fixture_calls = captured["twelfth_fixture_calls"]
        cls.catalog_calls = captured["catalog_calls"]
        cls.forbidden_calls = captured["forbidden_calls"]

    def test_builds_each_component_once_and_reuses_exact_evidence(self) -> None:
        self.assertEqual(self.twelfth_task_calls, 1)
        self.assertEqual(self.registry_calls, 1)
        self.assertEqual(self.twelfth_fixture_calls, 1)
        self.assertEqual(self.catalog_calls, 1)
        self.assertIs(self.registry_argument, self.twelfth_tasks)
        self.assertIs(self.fixture_argument, self.twelfth_tasks)
        self.assertIs(
            self.catalog_argument,
            self.thirteenth_registry,
        )
        self.assertIs(
            self.task_evidence.twelfth_evidence,
            self.twelfth_tasks,
        )
        self.assertIs(
            self.fixture_evidence.twelfth_evidence,
            self.twelfth_fixtures,
        )
        self.assertIs(
            self.fixture_evidence.thirteenth_catalog,
            self.thirteenth_catalog,
        )
        self.assertIs(
            self.twelfth_fixtures.task_evidence,
            self.twelfth_tasks,
        )

    def test_exact_terminal_hashes_counts_and_family_order(self) -> None:
        validate_thirteenth_prefix_task_evidence(self.task_evidence)
        validate_thirteenth_prefix_fixture_evidence(
            self.fixture_evidence
        )
        self.assertTrue(
            verify_thirteenth_prefix_task_evidence(self.task_evidence)
        )
        self.assertTrue(
            verify_thirteenth_prefix_fixture_evidence(
                self.fixture_evidence
            )
        )
        self.assertEqual(TWELFTH_PREFIX_TASK_COUNT, 420)
        self.assertEqual(TWELFTH_PREFIX_FIXTURE_COUNT, 2_100)
        self.assertEqual(THIRTEENTH_PREFIX_TASK_COUNT, 440)
        self.assertEqual(THIRTEENTH_PREFIX_FIXTURE_COUNT, 2_200)
        self.assertEqual(THIRTEENTH_PREFIX_PROFILE_COUNT, 5)
        self.assertEqual(len(self.task_evidence.tasks), 440)
        self.assertEqual(len(self.fixture_evidence.bundles), 2_200)
        self.assertEqual(
            self.task_evidence.terminal_registry_sha256,
            FROZEN_THIRTEENTH_REGISTRY_SHA256,
        )
        self.assertEqual(
            self.task_evidence.terminal_cumulative_suite_sha256,
            FROZEN_THIRTEENTH_CUMULATIVE_SUITE_SHA256,
        )
        self.assertEqual(
            self.fixture_evidence.terminal_catalog_sha256,
            FROZEN_THIRTEENTH_CATALOG_SHA256,
        )
        self.assertEqual(
            self.thirteenth_catalog.catalog_sha256,
            FROZEN_THIRTEENTH_CATALOG_SHA256,
        )
        self.assertEqual(
            tuple(
                task.family_id
                for index, task in enumerate(self.task_evidence.tasks)
                if index == 0
                or task.family_id
                != self.task_evidence.tasks[index - 1].family_id
            ),
            THIRTEENTH_PREFIX_FAMILY_ORDER,
        )
        self.assertEqual(len(self.task_evidence.registries), 13)
        self.assertEqual(len(self.fixture_evidence.catalogs), 13)
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
        self.assertEqual(len({task.task_id for task in tasks}), 440)
        self.assertEqual(
            len({task.task_contract_sha256 for task in tasks}),
            440,
        )
        self.assertEqual(len({task.graph_sha256 for task in tasks}), 440)
        self.assertEqual(
            len({bundle.descriptor.fixture_id for bundle in bundles}),
            2_200,
        )
        self.assertEqual(
            len(
                {
                    bundle.descriptor.fixture_sha256
                    for bundle in bundles
                }
            ),
            2_200,
        )
        for index, bundle in enumerate(bundles):
            task = tasks[index // THIRTEENTH_PREFIX_PROFILE_COUNT]
            profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[
                index % THIRTEENTH_PREFIX_PROFILE_COUNT
            ]
            self.assertEqual(
                bundle.task_contract_sha256,
                task.task_contract_sha256,
            )
            self.assertEqual(bundle.profile_sha256, profile.profile_sha256)
            self.assertEqual(
                bundle.descriptor,
                task.fixtures[index % THIRTEENTH_PREFIX_PROFILE_COUNT],
            )
            self.assertIs(bundle.candidate_execution_authorized, False)
            self.assertIs(bundle.model_selection_eligible, False)
            self.assertIs(bundle.claim_authorized, False)

    def test_prefix_and_thirteenth_additions_have_exact_ownership(
        self,
    ) -> None:
        for observed, expected in zip(
            self.task_evidence.tasks[:TWELFTH_PREFIX_TASK_COUNT],
            self.twelfth_tasks.tasks,
            strict=True,
        ):
            self.assertIs(observed, expected)
        for observed, expected in zip(
            self.task_evidence.tasks[TWELFTH_PREFIX_TASK_COUNT:],
            self.thirteenth_registry.added_tasks,
            strict=True,
        ):
            self.assertIs(observed, expected)
            self.assertTrue(
                all(
                    observed is not predecessor
                    for predecessor in self.twelfth_tasks.tasks
                )
            )

        for observed, expected in zip(
            self.fixture_evidence.bundles[
                :TWELFTH_PREFIX_FIXTURE_COUNT
            ],
            self.twelfth_fixtures.bundles,
            strict=True,
        ):
            self.assertIs(observed, expected)
        for observed, expected in zip(
            self.fixture_evidence.bundles[
                TWELFTH_PREFIX_FIXTURE_COUNT:
            ],
            self.thirteenth_catalog.bundles,
            strict=True,
        ):
            self.assertIs(observed, expected)
            self.assertTrue(
                all(
                    observed is not predecessor
                    for predecessor in self.twelfth_fixtures.bundles
                )
            )

    def test_no_recursive_builder_cache_hash_domain_or_assert(self) -> None:
        self.assertEqual(
            self.forbidden_calls,
            (0,) * len(_FORBIDDEN_RECURSIVE_PUBLICATION_BUILDERS),
        )
        source_path = (
            ROOT
            / "src/cbds/executable_thirteenth_predecessor_evidence.py"
        )
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported_full_builders = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            for alias in node.names
            if _is_full_catalog_publication_builder(alias.name)
        }
        referenced_full_attributes = {
            node.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
            and _is_full_catalog_publication_builder(node.attr)
        }
        directly_called_full_builders = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and _is_full_catalog_publication_builder(node.func.id)
        }
        self.assertEqual(imported_full_builders, set())
        self.assertEqual(referenced_full_attributes, set())
        self.assertEqual(directly_called_full_builders, set())
        self.assertIn(
            "build_thirteenth_tranche_fixture_catalog_local",
            {
                alias.name
                for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom)
                for alias in node.names
            },
        )
        self.assertNotIn("domain_sha256", source)
        self.assertNotIn("@lru_cache", source)
        self.assertNotIn("@cache", source)
        self.assertNotIn("functools", source)
        self.assertNotIn("hashlib", source)
        self.assertNotIn("def compute_", source)
        self.assertFalse(
            any(isinstance(node, ast.Assert) for node in ast.walk(tree))
        )

    def test_repeated_no_argument_task_builds_are_fully_fresh(self) -> None:
        first = build_thirteenth_prefix_task_evidence()
        second = build_thirteenth_prefix_task_evidence()
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first.twelfth_evidence, second.twelfth_evidence)
        self.assertIsNot(
            first.thirteenth_registry,
            second.thirteenth_registry,
        )
        self.assertIsNot(first.tasks, second.tasks)
        self.assertEqual(len(first.tasks), len(second.tasks))
        for left, right in zip(first.tasks, second.tasks, strict=True):
            self.assertEqual(left, right)
            self.assertIsNot(left, right)

    def test_additional_no_argument_fixture_build_is_uncached(self) -> None:
        with (
            mock.patch.object(
                prefix,
                "build_thirteenth_prefix_task_evidence",
                return_value=self.task_evidence,
            ) as task_builder,
            mock.patch.object(
                prefix,
                "build_twelfth_prefix_fixture_evidence",
                return_value=self.twelfth_fixtures,
            ) as twelfth_builder,
            mock.patch.object(
                prefix,
                "build_thirteenth_tranche_fixture_catalog_local",
                return_value=self.thirteenth_catalog,
            ) as thirteenth_builder,
        ):
            rebuilt = build_thirteenth_prefix_fixture_evidence()
        self.assertEqual(rebuilt, self.fixture_evidence)
        self.assertIsNot(rebuilt, self.fixture_evidence)
        self.assertIsNot(rebuilt.bundles, self.fixture_evidence.bundles)
        self.assertIs(rebuilt.task_evidence, self.task_evidence)
        self.assertIs(rebuilt.twelfth_evidence, self.twelfth_fixtures)
        self.assertIs(
            rebuilt.thirteenth_catalog,
            self.thirteenth_catalog,
        )
        task_builder.assert_called_once_with()
        twelfth_builder.assert_called_once_with(
            self.task_evidence.twelfth_evidence
        )
        thirteenth_builder.assert_called_once_with(
            self.task_evidence.thirteenth_registry
        )

    def test_supplied_task_evidence_is_reused_without_task_rebuild(self) -> None:
        with (
            mock.patch.object(
                prefix,
                "build_thirteenth_prefix_task_evidence",
                side_effect=AssertionError("task prefix rebuilt"),
            ),
            mock.patch.object(
                prefix,
                "build_twelfth_prefix_fixture_evidence",
                return_value=self.twelfth_fixtures,
            ) as twelfth_builder,
            mock.patch.object(
                prefix,
                "build_thirteenth_tranche_fixture_catalog_local",
                return_value=self.thirteenth_catalog,
            ) as thirteenth_builder,
        ):
            rebuilt = build_thirteenth_prefix_fixture_evidence(
                self.task_evidence
            )
        self.assertEqual(rebuilt, self.fixture_evidence)
        self.assertIsNot(rebuilt, self.fixture_evidence)
        self.assertIsNot(rebuilt.bundles, self.fixture_evidence.bundles)
        self.assertIs(rebuilt.task_evidence, self.task_evidence)
        self.assertIs(rebuilt.twelfth_evidence, self.twelfth_fixtures)
        self.assertIs(
            rebuilt.thirteenth_catalog,
            self.thirteenth_catalog,
        )
        twelfth_builder.assert_called_once_with(
            self.task_evidence.twelfth_evidence
        )
        thirteenth_builder.assert_called_once_with(
            self.task_evidence.thirteenth_registry
        )

    def test_supplied_twelfth_prefix_gets_fresh_thirteenth_tasks(self) -> None:
        with mock.patch.object(
            prefix,
            "build_twelfth_prefix_task_evidence",
            side_effect=AssertionError("twelfth prefix rebuilt"),
        ):
            rebuilt = build_thirteenth_prefix_task_evidence(
                self.twelfth_tasks
            )
        self.assertEqual(rebuilt, self.task_evidence)
        self.assertIsNot(rebuilt, self.task_evidence)
        self.assertIs(rebuilt.twelfth_evidence, self.twelfth_tasks)
        self.assertIsNot(
            rebuilt.thirteenth_registry,
            self.task_evidence.thirteenth_registry,
        )
        self.assertIsNot(rebuilt.tasks, self.task_evidence.tasks)
        for left, right in zip(
            rebuilt.thirteenth_registry.added_tasks,
            self.task_evidence.thirteenth_registry.added_tasks,
            strict=True,
        ):
            self.assertEqual(left, right)
            self.assertIsNot(left, right)

    def test_evidence_is_frozen_exact_typed_and_fails_closed(self) -> None:
        with self.assertRaises(FrozenInstanceError):
            self.task_evidence.total_task_count = 0  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            self.fixture_evidence.total_fixture_count = 0  # type: ignore[misc]
        with self.assertRaises(ThirteenthPredecessorEvidenceError):
            replace(
                self.task_evidence,
                tasks=tuple(reversed(self.task_evidence.tasks)),
            )
        with self.assertRaises(ThirteenthPredecessorEvidenceError):
            replace(
                self.task_evidence,
                total_task_count=True,
            )
        with self.assertRaises(ThirteenthPredecessorEvidenceError):
            replace(
                self.task_evidence,
                terminal_registry_sha256="0" * 64,
            )
        with self.assertRaises(ThirteenthPredecessorEvidenceError):
            replace(
                self.task_evidence,
                tasks=list(self.task_evidence.tasks),  # type: ignore[arg-type]
            )
        with self.assertRaises(ThirteenthPredecessorEvidenceError):
            replace(
                self.fixture_evidence,
                bundles=tuple(reversed(self.fixture_evidence.bundles)),
            )
        with self.assertRaises(ThirteenthPredecessorEvidenceError):
            replace(
                self.fixture_evidence,
                profiles_per_task=True,
            )
        with self.assertRaises(ThirteenthPredecessorEvidenceError):
            replace(
                self.fixture_evidence,
                terminal_catalog_sha256="0" * 64,
            )
        with self.assertRaises(ThirteenthPredecessorEvidenceError):
            replace(
                self.fixture_evidence,
                bundles=list(  # type: ignore[arg-type]
                    self.fixture_evidence.bundles
                ),
            )

        hostile_task = copy.copy(self.task_evidence)
        object.__setattr__(
            hostile_task,
            "terminal_cumulative_suite_sha256",
            "0" * 64,
        )
        with self.assertRaises(ThirteenthPredecessorEvidenceError):
            validate_thirteenth_prefix_task_evidence(hostile_task)
        self.assertFalse(
            verify_thirteenth_prefix_task_evidence(hostile_task)
        )

        relinked_task = copy.copy(self.task_evidence)
        object.__setattr__(
            relinked_task,
            "twelfth_evidence",
            copy.copy(self.task_evidence.twelfth_evidence),
        )
        relinked_fixture = copy.copy(self.fixture_evidence)
        object.__setattr__(
            relinked_fixture,
            "task_evidence",
            relinked_task,
        )
        with self.assertRaises(ThirteenthPredecessorEvidenceError):
            validate_thirteenth_prefix_fixture_evidence(relinked_fixture)
        self.assertFalse(
            verify_thirteenth_prefix_fixture_evidence(relinked_fixture)
        )
        self.assertFalse(
            verify_thirteenth_prefix_task_evidence(object())
        )
        self.assertFalse(
            verify_thirteenth_prefix_fixture_evidence(object())
        )

    def test_populated_outer_and_component_subclasses_are_rejected(
        self,
    ) -> None:
        hostile_task_outer = _populated_subclass_copy(
            self.task_evidence
        )
        with self.assertRaises(ThirteenthPredecessorEvidenceError):
            validate_thirteenth_prefix_task_evidence(  # type: ignore[arg-type]
                hostile_task_outer
            )
        self.assertFalse(
            verify_thirteenth_prefix_task_evidence(hostile_task_outer)
        )

        hostile_fixture_outer = _populated_subclass_copy(
            self.fixture_evidence
        )
        with self.assertRaises(ThirteenthPredecessorEvidenceError):
            validate_thirteenth_prefix_fixture_evidence(  # type: ignore[arg-type]
                hostile_fixture_outer
            )
        self.assertFalse(
            verify_thirteenth_prefix_fixture_evidence(
                hostile_fixture_outer
            )
        )

        hostile_twelfth_tasks = _populated_subclass_copy(
            self.twelfth_tasks
        )
        relinked_task = copy.copy(self.task_evidence)
        object.__setattr__(
            relinked_task,
            "twelfth_evidence",
            hostile_twelfth_tasks,
        )
        with self.assertRaises(ThirteenthPredecessorEvidenceError):
            validate_thirteenth_prefix_task_evidence(relinked_task)

        hostile_registry = _populated_subclass_copy(
            self.thirteenth_registry
        )
        relinked_task = copy.copy(self.task_evidence)
        object.__setattr__(
            relinked_task,
            "thirteenth_registry",
            hostile_registry,
        )
        with self.assertRaises(ThirteenthPredecessorEvidenceError):
            validate_thirteenth_prefix_task_evidence(relinked_task)

        hostile_twelfth_fixtures = _populated_subclass_copy(
            self.twelfth_fixtures
        )
        relinked_fixture = copy.copy(self.fixture_evidence)
        object.__setattr__(
            relinked_fixture,
            "twelfth_evidence",
            hostile_twelfth_fixtures,
        )
        with self.assertRaises(ThirteenthPredecessorEvidenceError):
            validate_thirteenth_prefix_fixture_evidence(
                relinked_fixture
            )

        hostile_catalog = _populated_subclass_copy(
            self.thirteenth_catalog
        )
        relinked_fixture = copy.copy(self.fixture_evidence)
        object.__setattr__(
            relinked_fixture,
            "thirteenth_catalog",
            hostile_catalog,
        )
        with self.assertRaises(ThirteenthPredecessorEvidenceError):
            validate_thirteenth_prefix_fixture_evidence(
                relinked_fixture
            )

    def test_equal_but_distinct_tasks_and_bundles_are_rejected(
        self,
    ) -> None:
        original_task = self.thirteenth_registry.added_tasks[0]
        copied_task = copy.copy(original_task)
        self.assertEqual(copied_task, original_task)
        self.assertIsNot(copied_task, original_task)
        copied_registry = copy.copy(self.thirteenth_registry)
        object.__setattr__(
            copied_registry,
            "added_tasks",
            (
                copied_task,
                *self.thirteenth_registry.added_tasks[1:],
            ),
        )
        relinked_task = copy.copy(self.task_evidence)
        object.__setattr__(
            relinked_task,
            "thirteenth_registry",
            copied_registry,
        )
        with self.assertRaisesRegex(
            ThirteenthPredecessorEvidenceError,
            "exact prefix concatenation",
        ):
            validate_thirteenth_prefix_task_evidence(relinked_task)
        self.assertFalse(
            verify_thirteenth_prefix_task_evidence(relinked_task)
        )

        original_bundle = self.thirteenth_catalog.bundles[0]
        copied_bundle = copy.copy(original_bundle)
        self.assertEqual(copied_bundle, original_bundle)
        self.assertIsNot(copied_bundle, original_bundle)
        copied_catalog = copy.copy(self.thirteenth_catalog)
        object.__setattr__(
            copied_catalog,
            "bundles",
            (
                copied_bundle,
                *self.thirteenth_catalog.bundles[1:],
            ),
        )
        relinked_fixture = copy.copy(self.fixture_evidence)
        object.__setattr__(
            relinked_fixture,
            "thirteenth_catalog",
            copied_catalog,
        )
        with self.assertRaisesRegex(
            ThirteenthPredecessorEvidenceError,
            "exact prefix concatenation",
        ):
            validate_thirteenth_prefix_fixture_evidence(
                relinked_fixture
            )
        self.assertFalse(
            verify_thirteenth_prefix_fixture_evidence(
                relinked_fixture
            )
        )

    def test_equal_but_distinct_component_links_are_rejected(
        self,
    ) -> None:
        copied_registry = copy.copy(self.thirteenth_registry)
        self.assertEqual(copied_registry, self.thirteenth_registry)
        self.assertIsNot(copied_registry, self.thirteenth_registry)
        copied_catalog = copy.copy(self.thirteenth_catalog)
        object.__setattr__(
            copied_catalog,
            "registry",
            copied_registry,
        )
        relinked_fixture = copy.copy(self.fixture_evidence)
        object.__setattr__(
            relinked_fixture,
            "thirteenth_catalog",
            copied_catalog,
        )
        with self.assertRaisesRegex(
            ThirteenthPredecessorEvidenceError,
            "does not extend the exact twelfth fixture evidence",
        ):
            validate_thirteenth_prefix_fixture_evidence(
                relinked_fixture
            )
        self.assertFalse(
            verify_thirteenth_prefix_fixture_evidence(
                relinked_fixture
            )
        )

        copied_twelfth_tasks = copy.copy(self.twelfth_tasks)
        copied_twelfth_fixtures = copy.copy(self.twelfth_fixtures)
        object.__setattr__(
            copied_twelfth_fixtures,
            "task_evidence",
            copied_twelfth_tasks,
        )
        relinked_fixture = copy.copy(self.fixture_evidence)
        object.__setattr__(
            relinked_fixture,
            "twelfth_evidence",
            copied_twelfth_fixtures,
        )
        with self.assertRaisesRegex(
            ThirteenthPredecessorEvidenceError,
            "does not extend the exact twelfth fixture evidence",
        ):
            validate_thirteenth_prefix_fixture_evidence(
                relinked_fixture
            )
        self.assertFalse(
            verify_thirteenth_prefix_fixture_evidence(
                relinked_fixture
            )
        )


if __name__ == "__main__":
    unittest.main()
