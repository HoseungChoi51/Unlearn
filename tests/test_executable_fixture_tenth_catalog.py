from __future__ import annotations

import copy
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import cbds.executable_fixture_tenth_catalog as tenth_catalog  # noqa: E402
from cbds.executable_compressed_archive_roundtrip_verify import (  # noqa: E402
    COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_MAXIMUM_ARCHIVE_BYTES,
    CompressedArchiveRoundtripVerifyFixtureBundle,
    CompressedArchiveRoundtripVerifyTask,
)
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from cbds.executable_fixture_tenth_catalog import (  # noqa: E402
    TENTH_TRANCHE_ADDED_FIXTURE_COUNT,
    TENTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT,
    TENTH_TRANCHE_FIXTURE_COUNT,
    TENTH_TRANCHE_PROFILE_COUNT,
    TenthTrancheFixtureCatalogError,
    build_tenth_tranche_fixture_catalog,
    build_tenth_tranche_fixture_catalog_local,
    compute_tenth_tranche_fixture_catalog_sha256,
    validate_tenth_tranche_fixture_catalog,
    verify_tenth_tranche_fixture_catalog,
)
from cbds.executable_ninth_predecessor_evidence import (  # noqa: E402
    FROZEN_NINTH_CATALOG_SHA256,
    FROZEN_NINTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_NINTH_REGISTRY_SHA256,
    NINTH_PREFIX_FIXTURE_COUNT,
    NINTH_PREFIX_TASK_COUNT,
    build_ninth_prefix_fixture_evidence,
    build_ninth_prefix_task_evidence,
)


EXPECTED_TENTH_CATALOG_SHA256 = (
    "5a29ea69111028fe69322d892e061a723ab53fb857ce4077cca924e314a4f4d6"
)

_FORBIDDEN_RECURSIVE_PUBLICATION_BUILDERS = (
    "cbds.executable_fixture_ninth_catalog.build_ninth_tranche_fixture_catalog",
    "cbds.executable_fixture_eighth_catalog.build_eighth_tranche_fixture_catalog",
    "cbds.executable_fixture_seventh_catalog.build_seventh_tranche_fixture_catalog",
    "cbds.executable_fixture_sixth_catalog.build_sixth_tranche_fixture_catalog",
    "cbds.executable_fixture_fifth_catalog.build_fifth_tranche_fixture_catalog",
    "cbds.executable_fixture_fourth_catalog.build_fourth_tranche_fixture_catalog",
    "cbds.executable_fixture_third_catalog.build_third_tranche_fixture_catalog",
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


class TenthTrancheFixtureCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        captured: dict[str, object] = {}
        real_task_builder = build_ninth_prefix_task_evidence
        real_fixture_builder = build_ninth_prefix_fixture_evidence

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
                    tenth_catalog,
                    "build_ninth_prefix_task_evidence",
                    side_effect=task_builder,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    tenth_catalog,
                    "build_ninth_prefix_fixture_evidence",
                    side_effect=fixture_builder,
                )
            )
            cls.catalog = build_tenth_tranche_fixture_catalog()
            captured["forbidden_calls"] = tuple(
                item.call_count for item in forbidden
            )

        cls.task_evidence = captured["task_evidence"]
        cls.fixture_evidence = captured["fixture_evidence"]
        cls.fixture_argument = captured["fixture_argument"]
        cls.task_calls = captured["task_calls"]
        cls.fixture_calls = captured["fixture_calls"]
        cls.forbidden_calls = captured["forbidden_calls"]
        cls.record = cls.catalog.to_hash_only_record()

    def test_exact_counts_types_and_task_major_profile_minor_order(self) -> None:
        tasks = self.catalog.registry.added_tasks
        bundles = self.catalog.bundles
        self.assertEqual(len(tasks), 20)
        self.assertEqual(len(bundles), TENTH_TRANCHE_ADDED_FIXTURE_COUNT)
        self.assertEqual(TENTH_TRANCHE_ADDED_FIXTURE_COUNT, 100)
        self.assertEqual(TENTH_TRANCHE_FIXTURE_COUNT, 100)
        self.assertEqual(TENTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT, 1_900)
        self.assertEqual(TENTH_TRANCHE_PROFILE_COUNT, 5)
        self.assertTrue(
            all(
                type(task) is CompressedArchiveRoundtripVerifyTask
                for task in tasks
            )
        )
        self.assertTrue(
            all(
                type(bundle)
                is CompressedArchiveRoundtripVerifyFixtureBundle
                for bundle in bundles
            )
        )
        for index, bundle in enumerate(bundles):
            task = tasks[index // TENTH_TRANCHE_PROFILE_COUNT]
            profile_index = index % TENTH_TRANCHE_PROFILE_COUNT
            profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[profile_index]
            self.assertEqual(
                bundle.task_contract_sha256, task.task_contract_sha256
            )
            self.assertEqual(bundle.profile_sha256, profile.profile_sha256)
            self.assertEqual(bundle.descriptor, task.fixtures[profile_index])
            self.assertIs(bundle.candidate_execution_authorized, False)
            self.assertIs(bundle.model_selection_eligible, False)
            self.assertIs(bundle.claim_authorized, False)

    def test_exact_through_ninth_prefix_is_built_once_and_shared(self) -> None:
        self.assertEqual(self.task_calls, 1)
        self.assertEqual(self.fixture_calls, 1)
        self.assertIs(self.fixture_argument, self.task_evidence)
        self.assertIs(
            self.fixture_evidence.task_evidence, self.task_evidence
        )
        self.assertEqual(
            self.task_evidence.total_task_count, NINTH_PREFIX_TASK_COUNT
        )
        self.assertEqual(
            self.fixture_evidence.total_fixture_count,
            NINTH_PREFIX_FIXTURE_COUNT,
        )
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
            self.catalog.base_fixture_catalog_sha256,
            "56932666f2641b5947e1801378b233dd5f37f568e4f2b4c6aa171bad115b09d8",
        )

    def test_fixture_identities_are_globally_unique_across_1900(self) -> None:
        all_bundles = (
            *self.fixture_evidence.bundles,
            *self.catalog.bundles,
        )
        self.assertEqual(
            len(all_bundles), TENTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT
        )
        self.assertEqual(
            len({item.descriptor.fixture_id for item in all_bundles}),
            len(all_bundles),
        )
        self.assertEqual(
            len(
                {
                    item.descriptor.fixture_sha256
                    for item in all_bundles
                }
            ),
            len(all_bundles),
        )

    def test_recursive_publication_builders_are_never_called(self) -> None:
        self.assertEqual(
            self.forbidden_calls,
            (0,) * len(_FORBIDDEN_RECURSIVE_PUBLICATION_BUILDERS),
        )

    def test_catalog_digest_is_frozen_hash_only_and_nonauthorizing(self) -> None:
        self.assertEqual(
            self.catalog.catalog_sha256,
            EXPECTED_TENTH_CATALOG_SHA256,
        )
        self.assertEqual(
            self.catalog.catalog_sha256,
            compute_tenth_tranche_fixture_catalog_sha256(
                self.catalog.registry,
                self.catalog.bundles,
            ),
        )
        self.assertTrue(verify_tenth_tranche_fixture_catalog(self.catalog))
        self.assertFalse(_contains_bytes(self.record))
        self.assertEqual(
            self.record["record_type"],
            "cbds.executable-fixture-tenth-tranche-catalog",
        )
        self.assertEqual(self.record["base_cumulative_task_count"], 360)
        self.assertEqual(self.record["added_task_count"], 20)
        self.assertEqual(self.record["cumulative_task_count"], 380)
        self.assertEqual(self.record["base_cumulative_fixture_count"], 1_800)
        self.assertEqual(self.record["added_fixture_count"], 100)
        self.assertEqual(self.record["cumulative_fixture_count"], 1_900)
        self.assertEqual(
            self.record["family_generators"],
            [
                {
                    "family_id": "compressed-archive-roundtrip-verify",
                    "generator_version": "1.0.0",
                    "semantic_verifier_identity": (
                        "verify-compressed-archive-roundtrip-v1"
                    ),
                    "output_maximum_bytes": (
                        COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_MAXIMUM_ARCHIVE_BYTES
                    ),
                }
            ],
        )
        self.assertIs(self.record["public_method_development"], True)
        for key in (
            "sealed",
            "independent_human_review_attested",
            "candidate_execution_authorized",
            "model_selection_eligible",
            "claim_authorized",
        ):
            self.assertIs(self.record[key], False)

    def test_local_rebuild_is_deterministic_with_fresh_bundle_ownership(self) -> None:
        rebuilt = build_tenth_tranche_fixture_catalog_local(
            self.catalog.registry
        )
        self.assertEqual(rebuilt, self.catalog)
        self.assertIsNot(rebuilt, self.catalog)
        self.assertIs(rebuilt.registry, self.catalog.registry)
        self.assertIsNot(rebuilt.bundles, self.catalog.bundles)
        for left, right in zip(
            rebuilt.bundles, self.catalog.bundles, strict=True
        ):
            self.assertIsNot(left, right)
            self.assertTrue(
                all(
                    left is not predecessor
                    for predecessor in self.fixture_evidence.bundles
                )
            )

    def test_tampering_wrong_types_and_forged_prefix_fail_closed(self) -> None:
        self.assertFalse(verify_tenth_tranche_fixture_catalog(object()))
        with self.assertRaises(TenthTrancheFixtureCatalogError):
            replace(
                self.catalog,
                base_fixture_catalog_sha256="0" * 64,
            )

        reordered = copy.copy(self.catalog)
        object.__setattr__(
            reordered,
            "bundles",
            (
                self.catalog.bundles[1],
                self.catalog.bundles[0],
                *self.catalog.bundles[2:],
            ),
        )
        with self.assertRaises(TenthTrancheFixtureCatalogError):
            validate_tenth_tranche_fixture_catalog(reordered)

        forged = copy.copy(self.fixture_evidence)
        object.__setattr__(forged, "terminal_catalog_sha256", "0" * 64)
        with self.assertRaises(TenthTrancheFixtureCatalogError):
            tenth_catalog._validate_live_base_and_global_uniqueness(
                self.catalog.registry,
                self.catalog.bundles,
                forged,
            )


if __name__ == "__main__":
    unittest.main()
