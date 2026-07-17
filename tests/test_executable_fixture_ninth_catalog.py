from __future__ import annotations

from dataclasses import replace
from contextlib import ExitStack
from unittest import mock
import unittest

import cbds.executable_fixture_ninth_catalog as ninth_catalog
from cbds.executable_fixture_ninth_catalog import (
    FROZEN_EIGHTH_CATALOG_SHA256,
    NINTH_TRANCHE_ADDED_FIXTURE_COUNT,
    NINTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT,
    NINTH_TRANCHE_FIXTURE_COUNT,
    NINTH_TRANCHE_PROFILE_COUNT,
    NinthTrancheFixtureCatalogError,
    build_ninth_tranche_fixture_catalog,
    build_ninth_tranche_fixture_catalog_local,
    compute_ninth_tranche_fixture_catalog_sha256,
    validate_ninth_tranche_fixture_catalog,
    verify_ninth_tranche_fixture_catalog,
)
from cbds.executable_fixture_profiles import (
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from cbds.executable_hardlink_deduplicated_mirror import (
    HardlinkDeduplicatedMirrorFixtureBundle,
    HardlinkDeduplicatedMirrorTask,
)
from cbds.executable_linear_predecessor_evidence import (
    FROZEN_PREDECESSOR_CATALOG_SHA256,
    LINEAR_PREDECESSOR_FIXTURE_COUNT,
    LINEAR_PREDECESSOR_TASK_COUNT,
    LinearFixturePredecessorEvidence,
    build_linear_fixture_predecessor_evidence,
    build_linear_task_predecessor_evidence,
)


_RECURSIVE_BUILDER_PATHS = (
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
    "cbds.executable_static_ninth_registry.build_ninth_tranche_task_registry",
)


def _contains_bytes(value: object) -> bool:
    if type(value) is bytes:
        return True
    if type(value) is dict:
        return any(
            _contains_bytes(key) or _contains_bytes(item)
            for key, item in value.items()
        )
    if type(value) in {list, tuple}:
        return any(_contains_bytes(item) for item in value)
    return False


class NinthTrancheFixtureCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        captured: dict[str, object] = {}
        real_task_builder = build_linear_task_predecessor_evidence
        real_fixture_builder = build_linear_fixture_predecessor_evidence

        def task_builder():
            evidence = real_task_builder()
            captured["task_evidence"] = evidence
            captured["task_calls"] = int(captured.get("task_calls", 0)) + 1
            return evidence

        def fixture_builder(task_evidence=None):
            captured["fixture_argument"] = task_evidence
            evidence = real_fixture_builder(task_evidence)
            captured["fixture_evidence"] = evidence
            captured["fixture_calls"] = int(
                captured.get("fixture_calls", 0)
            ) + 1
            return evidence

        with ExitStack() as stack:
            recursive_mocks = tuple(
                stack.enter_context(
                    mock.patch(
                        path,
                        side_effect=AssertionError(
                            f"recursive builder called: {path}"
                        ),
                    )
                )
                for path in _RECURSIVE_BUILDER_PATHS
            )
            stack.enter_context(
                mock.patch.object(
                    ninth_catalog,
                    "build_linear_task_predecessor_evidence",
                    side_effect=task_builder,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    ninth_catalog,
                    "build_linear_fixture_predecessor_evidence",
                    side_effect=fixture_builder,
                )
            )
            cls.catalog = build_ninth_tranche_fixture_catalog()
            captured["recursive_calls"] = tuple(
                value.call_count for value in recursive_mocks
            )
        cls.task_evidence = captured["task_evidence"]
        cls.fixture_evidence = captured["fixture_evidence"]
        cls.fixture_argument = captured["fixture_argument"]
        cls.task_calls = captured["task_calls"]
        cls.fixture_calls = captured["fixture_calls"]
        cls.recursive_calls = captured["recursive_calls"]
        cls.record = cls.catalog.to_hash_only_record()

    def test_exact_counts_types_and_task_major_profile_minor_order(self) -> None:
        tasks = self.catalog.registry.added_tasks
        bundles = self.catalog.bundles
        self.assertEqual(len(tasks), 20)
        self.assertEqual(len(bundles), NINTH_TRANCHE_ADDED_FIXTURE_COUNT)
        self.assertEqual(NINTH_TRANCHE_ADDED_FIXTURE_COUNT, 100)
        self.assertEqual(NINTH_TRANCHE_FIXTURE_COUNT, 100)
        self.assertEqual(NINTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT, 1_800)
        self.assertEqual(NINTH_TRANCHE_PROFILE_COUNT, 5)
        self.assertTrue(
            all(type(task) is HardlinkDeduplicatedMirrorTask for task in tasks)
        )
        self.assertTrue(
            all(
                type(bundle) is HardlinkDeduplicatedMirrorFixtureBundle
                for bundle in bundles
            )
        )
        for index, bundle in enumerate(bundles):
            task = tasks[index // NINTH_TRANCHE_PROFILE_COUNT]
            profile_index = index % NINTH_TRANCHE_PROFILE_COUNT
            profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[profile_index]
            self.assertEqual(
                bundle.task_contract_sha256, task.task_contract_sha256
            )
            self.assertEqual(bundle.profile_sha256, profile.profile_sha256)
            self.assertEqual(bundle.descriptor, task.fixtures[profile_index])
            self.assertIs(bundle.candidate_execution_authorized, False)
            self.assertIs(bundle.model_selection_eligible, False)
            self.assertIs(bundle.claim_authorized, False)

    def test_frozen_predecessor_is_admitted_once_and_shared(self) -> None:
        self.assertEqual(self.task_calls, 1)
        self.assertEqual(self.fixture_calls, 1)
        self.assertIs(self.fixture_argument, self.task_evidence)
        self.assertIs(
            self.fixture_evidence.task_evidence, self.task_evidence
        )
        self.assertEqual(
            self.task_evidence.total_task_count,
            LINEAR_PREDECESSOR_TASK_COUNT,
        )
        self.assertEqual(
            self.fixture_evidence.total_fixture_count,
            LINEAR_PREDECESSOR_FIXTURE_COUNT,
        )
        self.assertEqual(
            tuple(
                tranche.catalog_sha256
                for tranche in self.fixture_evidence.tranches
            ),
            FROZEN_PREDECESSOR_CATALOG_SHA256,
        )
        self.assertEqual(
            self.fixture_evidence.terminal_catalog_sha256,
            FROZEN_EIGHTH_CATALOG_SHA256,
        )
        self.assertEqual(
            self.catalog.base_fixture_catalog_sha256,
            FROZEN_EIGHTH_CATALOG_SHA256,
        )

    def test_fixture_identities_are_globally_unique_across_1800(self) -> None:
        all_bundles = (
            *self.fixture_evidence.bundles,
            *self.catalog.bundles,
        )
        self.assertEqual(
            len(all_bundles), NINTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT
        )
        self.assertEqual(
            len({item.descriptor.fixture_id for item in all_bundles}),
            len(all_bundles),
        )
        self.assertEqual(
            len({item.descriptor.fixture_sha256 for item in all_bundles}),
            len(all_bundles),
        )

    def test_recursive_publication_builders_are_never_called(self) -> None:
        self.assertEqual(
            self.recursive_calls,
            (0,) * len(_RECURSIVE_BUILDER_PATHS),
        )

    def test_digest_is_deterministic_and_hash_only(self) -> None:
        validate_ninth_tranche_fixture_catalog(self.catalog)
        self.assertTrue(
            verify_ninth_tranche_fixture_catalog(self.catalog)
        )
        self.assertEqual(
            self.catalog.catalog_sha256,
            compute_ninth_tranche_fixture_catalog_sha256(
                self.catalog.registry,
                self.catalog.bundles,
            ),
        )
        local = build_ninth_tranche_fixture_catalog_local(
            self.catalog.registry
        )
        self.assertEqual(local, self.catalog)
        self.assertFalse(_contains_bytes(self.record))
        self.assertEqual(
            self.record["base_fixture_catalog_sha256"],
            FROZEN_EIGHTH_CATALOG_SHA256,
        )
        self.assertEqual(self.record["added_fixture_count"], 100)
        self.assertEqual(self.record["cumulative_fixture_count"], 1_800)
        self.assertEqual(
            self.record["catalog_sha256"], self.catalog.catalog_sha256
        )

    def test_frozen_hash_and_type_tampering_fail_closed(self) -> None:
        self.assertFalse(verify_ninth_tranche_fixture_catalog(object()))
        with self.assertRaises(NinthTrancheFixtureCatalogError):
            replace(
                self.catalog,
                base_fixture_catalog_sha256="0" * 64,
            )
        forged = object.__new__(LinearFixturePredecessorEvidence)
        for name in (
            "task_evidence",
            "tranches",
            "bundles",
            "total_fixture_count",
            "profiles_per_task",
        ):
            object.__setattr__(
                forged, name, getattr(self.fixture_evidence, name)
            )
        object.__setattr__(forged, "terminal_catalog_sha256", "0" * 64)
        with self.assertRaises(NinthTrancheFixtureCatalogError):
            ninth_catalog._validate_live_base_and_global_uniqueness(
                self.catalog.registry,
                self.catalog.bundles,
                forged,
            )


if __name__ == "__main__":
    unittest.main()
