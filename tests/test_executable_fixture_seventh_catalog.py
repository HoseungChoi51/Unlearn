from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.executable_case_routed_batch_transform import (  # noqa: E402
    CASE_ROUTED_BATCH_TRANSFORM_FAMILY_ID,
    CaseRoutedBatchTransformFixtureBundle,
    CaseRoutedBatchTransformTask,
)
from cbds.executable_fixture_catalog import (  # noqa: E402
    build_first_tranche_fixture_catalog,
)
from cbds.executable_fixture_fifth_catalog import (  # noqa: E402
    build_fifth_tranche_fixture_catalog,
)
from cbds.executable_fixture_fourth_catalog import (  # noqa: E402
    build_fourth_tranche_fixture_catalog,
)
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from cbds.executable_fixture_second_catalog import (  # noqa: E402
    build_second_tranche_fixture_catalog,
)
from cbds.executable_fixture_seventh_catalog import (  # noqa: E402
    FROZEN_FIRST_CATALOG_SHA256,
    FROZEN_SECOND_CATALOG_SHA256,
    FROZEN_THIRD_CATALOG_SHA256,
    FROZEN_FOURTH_CATALOG_SHA256,
    FROZEN_FIFTH_CATALOG_SHA256,
    FROZEN_SIXTH_CATALOG_SHA256,
    SEVENTH_TRANCHE_ADDED_FIXTURE_COUNT,
    SEVENTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT,
    SEVENTH_TRANCHE_FIXTURE_COUNT,
    SEVENTH_TRANCHE_PROFILE_COUNT,
    SeventhTrancheFixtureCatalogError,
    build_seventh_tranche_fixture_catalog,
    compute_seventh_tranche_fixture_catalog_sha256,
    validate_seventh_tranche_fixture_catalog,
    verify_seventh_tranche_fixture_catalog,
)
from cbds.executable_fixture_sixth_catalog import (  # noqa: E402
    build_sixth_tranche_fixture_catalog,
)
from cbds.executable_fixture_third_catalog import (  # noqa: E402
    build_third_tranche_fixture_catalog,
)
from cbds.executable_static_registry import (  # noqa: E402
    build_public_method_development_registry,
)


_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
EXPECTED_SEVENTH_CATALOG_SHA256 = (
    "99dcf8918151a5a87bdeea8f51bde8ad6e10063b46419a334d7d8b211310e6d8"
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


class SeventhTrancheFixtureCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = build_seventh_tranche_fixture_catalog()
        cls.record = cls.catalog.to_hash_only_record()
        cls.first = build_first_tranche_fixture_catalog(
            build_public_method_development_registry()
        )
        cls.second = build_second_tranche_fixture_catalog()
        cls.third = build_third_tranche_fixture_catalog()
        cls.fourth = build_fourth_tranche_fixture_catalog()
        cls.fifth = build_fifth_tranche_fixture_catalog()
        cls.sixth = build_sixth_tranche_fixture_catalog()

    def assert_catalog_invalid(self, catalog: object) -> None:
        self.assertFalse(verify_seventh_tranche_fixture_catalog(catalog))
        with self.assertRaises(
            (SeventhTrancheFixtureCatalogError, TypeError, ValueError)
        ):
            validate_seventh_tranche_fixture_catalog(  # type: ignore[arg-type]
                catalog
            )

    def test_exact_types_are_task_major_profile_minor(self) -> None:
        tasks = self.catalog.registry.added_tasks
        bundles = self.catalog.bundles
        self.assertEqual(len(tasks), 20)
        self.assertEqual(len(bundles), SEVENTH_TRANCHE_ADDED_FIXTURE_COUNT)
        self.assertEqual(SEVENTH_TRANCHE_ADDED_FIXTURE_COUNT, 100)
        self.assertEqual(SEVENTH_TRANCHE_FIXTURE_COUNT, 100)
        self.assertEqual(SEVENTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT, 1_600)
        self.assertEqual(SEVENTH_TRANCHE_PROFILE_COUNT, 5)
        self.assertTrue(
            all(type(task) is CaseRoutedBatchTransformTask for task in tasks)
        )
        self.assertTrue(
            all(
                type(bundle) is CaseRoutedBatchTransformFixtureBundle
                for bundle in bundles
            )
        )

        fixture_ids: set[str] = set()
        fixture_hashes: set[str] = set()
        for index, bundle in enumerate(bundles):
            task = tasks[index // SEVENTH_TRANCHE_PROFILE_COUNT]
            profile_index = index % SEVENTH_TRANCHE_PROFILE_COUNT
            profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[profile_index]
            with self.subTest(task=task.task_id, profile=profile.profile_id):
                self.assertEqual(
                    bundle.task_contract_sha256, task.task_contract_sha256
                )
                self.assertEqual(bundle.profile_sha256, profile.profile_sha256)
                self.assertEqual(bundle.descriptor, task.fixtures[profile_index])
                self.assertIs(bundle.candidate_execution_authorized, False)
                self.assertIs(bundle.model_selection_eligible, False)
                self.assertIs(bundle.claim_authorized, False)
                fixture_ids.add(bundle.descriptor.fixture_id)
                fixture_hashes.add(bundle.descriptor.fixture_sha256)
        self.assertEqual(len(fixture_ids), 100)
        self.assertEqual(len(fixture_hashes), 100)

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
            rebuilt = build_seventh_tranche_fixture_catalog()
            rebuilt_record = rebuilt.to_hash_only_record()
        self.assertEqual(rebuilt, self.catalog)
        self.assertEqual(rebuilt_record, self.record)
        self.assertEqual(
            _canonical_bytes(rebuilt_record), _canonical_bytes(self.record)
        )
        self.assertEqual(
            rebuilt.catalog_sha256,
            EXPECTED_SEVENTH_CATALOG_SHA256,
        )
        self.assertEqual(
            rebuilt.catalog_sha256,
            compute_seventh_tranche_fixture_catalog_sha256(
                rebuilt.registry,
                rebuilt.bundles,
            ),
        )

    def test_all_predecessor_catalogs_are_live_and_unchanged(self) -> None:
        self.assertEqual(
            self.first.catalog_sha256, FROZEN_FIRST_CATALOG_SHA256
        )
        self.assertEqual(
            self.second.catalog_sha256, FROZEN_SECOND_CATALOG_SHA256
        )
        self.assertEqual(
            self.third.catalog_sha256, FROZEN_THIRD_CATALOG_SHA256
        )
        self.assertEqual(
            self.fourth.catalog_sha256, FROZEN_FOURTH_CATALOG_SHA256
        )
        self.assertEqual(
            self.fifth.catalog_sha256, FROZEN_FIFTH_CATALOG_SHA256
        )
        self.assertEqual(
            self.sixth.catalog_sha256, FROZEN_SIXTH_CATALOG_SHA256
        )
        self.assertEqual(
            self.catalog.base_fixture_catalog_sha256,
            self.sixth.catalog_sha256,
        )
        self.assertEqual(
            self.record["base_fixture_catalog_sha256"],
            self.sixth.catalog_sha256,
        )

    def test_all_1600_fixture_identities_are_globally_unique(self) -> None:
        bundles = (
            *self.first.bundles,
            *self.second.bundles,
            *self.third.bundles,
            *self.fourth.bundles,
            *self.fifth.bundles,
            *self.sixth.bundles,
            *self.catalog.bundles,
        )
        self.assertEqual(len(bundles), SEVENTH_TRANCHE_CUMULATIVE_FIXTURE_COUNT)
        self.assertEqual(
            len({bundle.descriptor.fixture_id for bundle in bundles}),
            len(bundles),
        )
        self.assertEqual(
            len({bundle.descriptor.fixture_sha256 for bundle in bundles}),
            len(bundles),
        )

    def test_projection_binds_generator_and_is_hash_only(self) -> None:
        record = self.record
        self.assertFalse(_contains_bytes(record))
        self.assertEqual(
            record["record_type"],
            "cbds.executable-fixture-seventh-tranche-catalog",
        )
        self.assertEqual(record["base_cumulative_task_count"], 300)
        self.assertEqual(record["added_task_count"], 20)
        self.assertEqual(record["cumulative_task_count"], 320)
        self.assertEqual(record["base_cumulative_fixture_count"], 1_500)
        self.assertEqual(record["added_fixture_count"], 100)
        self.assertEqual(record["cumulative_fixture_count"], 1_600)
        self.assertEqual(record["profiles_per_task"], 5)
        self.assertEqual(
            record["family_task_counts"],
            {CASE_ROUTED_BATCH_TRANSFORM_FAMILY_ID: 20},
        )
        self.assertEqual(
            record["family_fixture_counts"],
            {CASE_ROUTED_BATCH_TRANSFORM_FAMILY_ID: 100},
        )
        self.assertEqual(
            record["profile_sha256"],
            [
                profile.profile_sha256
                for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
            ],
        )
        generators = record["family_generators"]
        self.assertEqual(len(generators), 1)
        self.assertEqual(
            set(generators[0]),
            {
                "family_id",
                "generator_version",
                "semantic_verifier_identity",
                "output_maximum_bytes",
            },
        )
        self.assertEqual(
            generators[0]["family_id"],
            CASE_ROUTED_BATCH_TRANSFORM_FAMILY_ID,
        )

        task_records = record["added_tasks"]
        self.assertEqual(len(task_records), 20)
        for task_record in task_records:
            self.assertEqual(set(task_record), TASK_HASH_KEYS)
        fixture_records = record["added_fixtures"]
        self.assertEqual(len(fixture_records), 100)
        for fixture_record in fixture_records:
            self.assertEqual(set(fixture_record), FIXTURE_HASH_KEYS)
            self.assertTrue(
                all(
                    type(value) is str and _SHA256_RE.fullmatch(value)
                    for value in fixture_record.values()
                )
            )
        for key in (
            "content",
            "inputs",
            "outputs",
            "prompt",
            "path",
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

    def test_order_nested_type_authority_and_spoof_mutations_fail(self) -> None:
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
        bundle_index = next(
            index
            for index, bundle in enumerate(self.catalog.bundles)
            if bundle.oracle.outputs
        )
        forged_bundle = copy.deepcopy(self.catalog.bundles[bundle_index])
        output = forged_bundle.oracle.outputs[0]
        object.__setattr__(output, "content", output.content + b"forged")
        object.__setattr__(
            nested_tamper,
            "bundles",
            (
                *self.catalog.bundles[:bundle_index],
                forged_bundle,
                *self.catalog.bundles[bundle_index + 1 :],
            ),
        )
        self.assert_catalog_invalid(nested_tamper)

        noncanonical_definition = copy.copy(self.catalog)
        forged_definition_bundle = copy.deepcopy(self.catalog.bundles[0])
        object.__setattr__(
            forged_definition_bundle.definition,
            "inputs",
            list(forged_definition_bundle.definition.inputs),
        )
        object.__setattr__(
            noncanonical_definition,
            "bundles",
            (
                forged_definition_bundle,
                *self.catalog.bundles[1:],
            ),
        )
        self.assert_catalog_invalid(noncanonical_definition)

        wrong_bundle_type = copy.copy(self.catalog)
        object.__setattr__(
            wrong_bundle_type,
            "bundles",
            (self.sixth.bundles[0], *self.catalog.bundles[1:]),
        )
        self.assert_catalog_invalid(wrong_bundle_type)

        forged_review = copy.copy(self.catalog)
        object.__setattr__(
            forged_review, "independent_human_review_attested", True
        )
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
