from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.executable_compound_path_query import (  # noqa: E402
    CompoundPathQueryFixtureBundle,
    CompoundPathQueryTask,
)
from cbds.executable_fixture_catalog import (  # noqa: E402
    build_first_tranche_fixture_catalog,
)
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from cbds.executable_fixture_second_catalog import (  # noqa: E402
    build_second_tranche_fixture_catalog,
)
from cbds.executable_fixture_third_catalog import (  # noqa: E402
    FROZEN_FIRST_CATALOG_SHA256,
    FROZEN_SECOND_CATALOG_SHA256,
    THIRD_TRANCHE_ADDED_FIXTURE_COUNT,
    THIRD_TRANCHE_CUMULATIVE_FIXTURE_COUNT,
    THIRD_TRANCHE_FIXTURE_COUNT,
    THIRD_TRANCHE_PROFILE_COUNT,
    ThirdTrancheFixtureCatalogError,
    build_third_tranche_fixture_catalog,
    compute_third_tranche_fixture_catalog_sha256,
    validate_third_tranche_fixture_catalog,
    verify_third_tranche_fixture_catalog,
)
from cbds.executable_log_aggregation_pipeline import (  # noqa: E402
    LogAggregationFixtureBundle,
    LogAggregationTask,
)
from cbds.executable_static_registry import (  # noqa: E402
    build_public_method_development_registry,
)
from cbds.executable_static_third_registry import (  # noqa: E402
    THIRD_TRANCHE_FAMILY_ORDER,
)


TASK_HASH_KEYS = {
    "family_id",
    "task_contract_sha256",
    "graph_sha256",
}
FIXTURE_HASH_KEYS = {
    "task_contract_sha256",
    "profile_sha256",
    "fixture_definition_sha256",
    "trusted_oracle_sha256",
    "fixture_sha256",
}


class _SpoofedString(str):
    def __eq__(self, _other: object) -> bool:
        return True

    def __ne__(self, _other: object) -> bool:
        return False

    __hash__ = str.__hash__


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


def _contains_key(value: object, target: str) -> bool:
    if type(value) is dict:
        return target in value or any(
            _contains_key(item, target) for item in value.values()
        )
    if type(value) in {list, tuple}:
        return any(_contains_key(item, target) for item in value)
    return False


def _canonical_bytes(record: dict[str, object]) -> bytes:
    return (
        json.dumps(
            record,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


class ThirdTrancheFixtureCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = build_third_tranche_fixture_catalog()
        cls.record = cls.catalog.to_hash_only_record()
        cls.first = build_first_tranche_fixture_catalog(
            build_public_method_development_registry()
        )
        cls.second = build_second_tranche_fixture_catalog()

    def assert_catalog_invalid(self, catalog: object) -> None:
        self.assertFalse(verify_third_tranche_fixture_catalog(catalog))
        with self.assertRaises(
            (ThirdTrancheFixtureCatalogError, TypeError, ValueError)
        ):
            validate_third_tranche_fixture_catalog(catalog)  # type: ignore[arg-type]

    def test_exact_task_and_bundle_types_are_task_major_profile_minor(self) -> None:
        tasks = self.catalog.registry.added_tasks
        bundles = self.catalog.bundles
        self.assertEqual(len(tasks), 40)
        self.assertEqual(len(bundles), THIRD_TRANCHE_ADDED_FIXTURE_COUNT)
        self.assertEqual(THIRD_TRANCHE_ADDED_FIXTURE_COUNT, 200)
        self.assertEqual(THIRD_TRANCHE_FIXTURE_COUNT, 200)
        self.assertEqual(THIRD_TRANCHE_CUMULATIVE_FIXTURE_COUNT, 1_200)
        self.assertEqual(THIRD_TRANCHE_PROFILE_COUNT, 5)
        self.assertTrue(
            all(type(task) is CompoundPathQueryTask for task in tasks[:20])
        )
        self.assertTrue(all(type(task) is LogAggregationTask for task in tasks[20:]))
        self.assertTrue(
            all(
                type(bundle) is CompoundPathQueryFixtureBundle
                for bundle in bundles[:100]
            )
        )
        self.assertTrue(
            all(type(bundle) is LogAggregationFixtureBundle for bundle in bundles[100:])
        )

        fixture_ids: set[str] = set()
        fixture_hashes: set[str] = set()
        for index, bundle in enumerate(bundles):
            task = tasks[index // THIRD_TRANCHE_PROFILE_COUNT]
            profile_index = index % THIRD_TRANCHE_PROFILE_COUNT
            profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[profile_index]
            with self.subTest(task=task.task_id, profile=profile.profile_id):
                self.assertEqual(bundle.task_contract_sha256, task.task_contract_sha256)
                self.assertEqual(bundle.profile_sha256, profile.profile_sha256)
                self.assertEqual(bundle.descriptor, task.fixtures[profile_index])
                self.assertIs(bundle.candidate_execution_authorized, False)
                self.assertIs(bundle.model_selection_eligible, False)
                self.assertIs(bundle.claim_authorized, False)
                fixture_ids.add(bundle.descriptor.fixture_id)
                fixture_hashes.add(bundle.descriptor.fixture_sha256)
        self.assertEqual(len(fixture_ids), 200)
        self.assertEqual(len(fixture_hashes), 200)

    def test_rebuild_is_deterministic_hash_bound_and_never_executes(self) -> None:
        with mock.patch.object(
            subprocess,
            "run",
            side_effect=AssertionError("subprocess.run executed"),
        ), mock.patch.object(
            subprocess,
            "Popen",
            side_effect=AssertionError("subprocess.Popen executed"),
        ), mock.patch.object(
            os,
            "system",
            side_effect=AssertionError("os.system executed"),
        ), mock.patch.object(
            os,
            "popen",
            side_effect=AssertionError("os.popen executed"),
        ):
            rebuilt = build_third_tranche_fixture_catalog()
            rebuilt_record = rebuilt.to_hash_only_record()
        self.assertEqual(rebuilt, self.catalog)
        self.assertEqual(rebuilt_record, self.record)
        self.assertEqual(_canonical_bytes(rebuilt_record), _canonical_bytes(self.record))
        self.assertEqual(
            rebuilt.catalog_sha256,
            compute_third_tranche_fixture_catalog_sha256(
                rebuilt.registry,
                rebuilt.bundles,
            ),
        )

    def test_frozen_second_catalog_is_live_and_unchanged(self) -> None:
        self.assertEqual(
            self.first.catalog_sha256,
            FROZEN_FIRST_CATALOG_SHA256,
        )
        self.assertEqual(
            self.second.catalog_sha256,
            FROZEN_SECOND_CATALOG_SHA256,
        )
        self.assertEqual(
            self.catalog.base_fixture_catalog_sha256,
            self.second.catalog_sha256,
        )
        self.assertEqual(
            self.record["base_fixture_catalog_sha256"],
            self.second.catalog_sha256,
        )

    def test_all_1200_fixture_identities_are_globally_unique(self) -> None:
        bundles = (
            *self.first.bundles,
            *self.second.bundles,
            *self.catalog.bundles,
        )
        self.assertEqual(len(bundles), THIRD_TRANCHE_CUMULATIVE_FIXTURE_COUNT)
        self.assertEqual(
            len({bundle.descriptor.fixture_id for bundle in bundles}), len(bundles)
        )
        self.assertEqual(
            len({bundle.descriptor.fixture_sha256 for bundle in bundles}),
            len(bundles),
        )

    def test_projection_is_hash_only_nonauthorizing_and_not_review_attested(
        self,
    ) -> None:
        record = self.record
        self.assertFalse(_contains_bytes(record))
        self.assertEqual(
            record["record_type"],
            "cbds.executable-fixture-third-tranche-catalog",
        )
        self.assertEqual(record["added_task_count"], 40)
        self.assertEqual(record["cumulative_task_count"], 240)
        self.assertEqual(record["added_fixture_count"], 200)
        self.assertEqual(record["cumulative_fixture_count"], 1_200)
        self.assertEqual(record["profiles_per_task"], 5)
        self.assertEqual(
            record["family_task_counts"],
            {family: 20 for family in THIRD_TRANCHE_FAMILY_ORDER},
        )
        self.assertEqual(
            record["family_fixture_counts"],
            {family: 100 for family in THIRD_TRANCHE_FAMILY_ORDER},
        )
        self.assertEqual(
            record["profile_sha256"],
            [
                profile.profile_sha256
                for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
            ],
        )
        self.assertEqual(
            record["family_generators"],
            [
                {
                    "family_id": "compound-path-query",
                    "generator_version": "1.1.0",
                    "semantic_verifier_identity": (
                        "verify-compound-path-query-v1"
                    ),
                    "output_maximum_bytes": 65_536,
                },
                {
                    "family_id": "regex-log-group-aggregation",
                    "generator_version": "1.1.0",
                    "semantic_verifier_identity": (
                        "verify-regex-log-group-aggregation-v1"
                    ),
                    "output_maximum_bytes": 65_536,
                },
            ],
        )

        task_records = record["added_tasks"]
        self.assertEqual(len(task_records), 40)
        for task_record in task_records:
            self.assertEqual(set(task_record), TASK_HASH_KEYS)
        fixture_records = record["added_fixtures"]
        self.assertEqual(len(fixture_records), 200)
        for fixture_record in fixture_records:
            self.assertEqual(set(fixture_record), FIXTURE_HASH_KEYS)
            self.assertTrue(
                all(
                    type(value) is str and len(value) == 64
                    for value in fixture_record.values()
                )
            )
        for key in (
            "content",
            "inputs",
            "outputs",
            "prompt",
            "answer",
            "response",
        ):
            self.assertFalse(_contains_key(record, key))
        encoded = _canonical_bytes(record).decode("utf-8")
        self.assertNotIn("input/", encoded)
        self.assertNotIn("output/", encoded)
        self.assertIs(record["public_method_development"], True)
        self.assertIs(record["sealed"], False)
        self.assertIs(record["independent_human_review_attested"], False)
        self.assertIs(record["candidate_execution_authorized"], False)
        self.assertIs(record["model_selection_eligible"], False)
        self.assertIs(record["claim_authorized"], False)
        self.assertEqual(record["catalog_sha256"], self.catalog.catalog_sha256)

    def test_order_nested_metadata_type_and_hostile_mutations_fail_closed(self) -> None:
        wrong_container = copy.copy(self.catalog)
        object.__setattr__(wrong_container, "bundles", list(self.catalog.bundles))
        self.assert_catalog_invalid(wrong_container)

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
        self.assert_catalog_invalid(reordered)

        nested_tamper = copy.copy(self.catalog)
        forged_bundle = copy.deepcopy(self.catalog.bundles[0])
        output = forged_bundle.oracle.outputs[0]
        object.__setattr__(output, "content", output.content + b"forged")
        object.__setattr__(
            nested_tamper,
            "bundles",
            (forged_bundle, *self.catalog.bundles[1:]),
        )
        self.assert_catalog_invalid(nested_tamper)

        wrong_bundle_type = copy.copy(self.catalog)
        object.__setattr__(
            wrong_bundle_type,
            "bundles",
            (object(), *self.catalog.bundles[1:]),
        )
        self.assert_catalog_invalid(wrong_bundle_type)

        forged_review = copy.copy(self.catalog)
        object.__setattr__(forged_review, "independent_human_review_attested", True)
        self.assert_catalog_invalid(forged_review)

        forged_authority = copy.copy(self.catalog)
        object.__setattr__(forged_authority, "claim_authorized", True)
        self.assert_catalog_invalid(forged_authority)

        spoofed_digest = copy.copy(self.catalog)
        object.__setattr__(
            spoofed_digest,
            "catalog_sha256",
            _SpoofedString(self.catalog.catalog_sha256),
        )
        self.assert_catalog_invalid(spoofed_digest)
        self.assert_catalog_invalid(object())


if __name__ == "__main__":
    unittest.main()
