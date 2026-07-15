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

from cbds.executable_fixture_catalog import (  # noqa: E402
    FIRST_TRANCHE_FIXTURE_COUNT,
    ExecutableFixtureCatalogError,
    build_first_tranche_fixture_catalog,
    build_fixture_bundle_for_task_profile,
    compute_first_tranche_fixture_catalog_sha256,
    validate_first_tranche_fixture_catalog,
    verify_first_tranche_fixture_catalog,
)
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from cbds.executable_static_registry import (  # noqa: E402
    build_public_method_development_registry,
)


REGISTRY = build_public_method_development_registry()
CATALOG = build_first_tranche_fixture_catalog(REGISTRY)


def _contains_bytes(value: object) -> bool:
    if isinstance(value, bytes):
        return True
    if type(value) is dict:
        return any(
            _contains_bytes(key) or _contains_bytes(item)
            for key, item in value.items()
        )
    if type(value) in {list, tuple}:
        return any(_contains_bytes(item) for item in value)
    return False


class FirstTrancheFixtureCatalogTests(unittest.TestCase):
    def test_catalog_is_exact_complete_and_canonically_ordered(self) -> None:
        validate_first_tranche_fixture_catalog(CATALOG)
        self.assertEqual(len(REGISTRY.tasks), 100)
        self.assertEqual(len(CATALOG.bundles), FIRST_TRANCHE_FIXTURE_COUNT)
        self.assertEqual(FIRST_TRANCHE_FIXTURE_COUNT, 500)

        fixture_ids = set()
        fixture_hashes = set()
        family_counts: dict[str, int] = {}
        for index, bundle in enumerate(CATALOG.bundles):
            task = REGISTRY.tasks[index // 5]
            profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[index % 5]
            self.assertEqual(bundle.task_contract_sha256, task.task_contract_sha256)
            self.assertEqual(bundle.profile_sha256, profile.profile_sha256)
            self.assertEqual(
                bundle.descriptor.task_contract_sha256,
                task.task_contract_sha256,
            )
            self.assertEqual(task.fixtures[index % 5], bundle.descriptor)
            self.assertIs(bundle.candidate_execution_authorized, False)
            self.assertIs(bundle.model_selection_eligible, False)
            self.assertIs(bundle.claim_authorized, False)
            fixture_ids.add(bundle.descriptor.fixture_id)
            fixture_hashes.add(bundle.descriptor.fixture_sha256)
            family_counts[task.family_id] = family_counts.get(task.family_id, 0) + 1

        self.assertEqual(len(fixture_ids), 500)
        self.assertEqual(len(fixture_hashes), 500)
        self.assertEqual(
            family_counts,
            {
                "active-jsonl-labels": 100,
                "manifest-copy": 100,
                "csv-group-totals": 100,
                "checksum-manifest": 100,
                "path-suffix-inventory": 100,
            },
        )

    def test_rebuild_and_identity_are_deterministic(self) -> None:
        rebuilt = build_first_tranche_fixture_catalog(REGISTRY)
        self.assertEqual(rebuilt, CATALOG)
        self.assertEqual(
            CATALOG.catalog_sha256,
            compute_first_tranche_fixture_catalog_sha256(
                CATALOG.source_registry, CATALOG.bundles
            ),
        )

    def test_catalog_projection_is_hash_only_and_nonauthorizing(self) -> None:
        record = CATALOG.to_hash_only_record()
        self.assertFalse(_contains_bytes(record))
        self.assertEqual(record["record_type"], "cbds.executable-fixture-first-tranche-catalog")
        self.assertEqual(record["fixture_count"], 500)
        self.assertEqual(record["catalog_sha256"], CATALOG.catalog_sha256)
        self.assertIs(record["public_method_development"], True)
        self.assertIs(record["sealed"], False)
        self.assertIs(record["candidate_execution_authorized"], False)
        self.assertIs(record["model_selection_eligible"], False)
        self.assertIs(record["claim_authorized"], False)
        fixtures = record["fixtures"]
        self.assertIs(type(fixtures), list)
        self.assertEqual(len(fixtures), 500)
        expected_keys = {
            "task_contract_sha256",
            "profile_sha256",
            "fixture_definition_sha256",
            "trusted_oracle_sha256",
            "fixture_sha256",
        }
        for entry in fixtures:
            self.assertEqual(set(entry), expected_keys)
            self.assertTrue(all(len(value) == 64 for value in entry.values()))
        encoded = json.dumps(record, sort_keys=True)
        self.assertNotIn("oracle output content", encoded)
        self.assertNotIn("space payload", encoded)

    def test_catalog_build_never_invokes_an_execution_api(self) -> None:
        with mock.patch.object(
            subprocess, "run", side_effect=AssertionError("subprocess.run called")
        ), mock.patch.object(
            subprocess, "Popen", side_effect=AssertionError("subprocess.Popen called")
        ), mock.patch.object(
            os, "system", side_effect=AssertionError("os.system called")
        ):
            rebuilt = build_first_tranche_fixture_catalog(REGISTRY)
        self.assertEqual(rebuilt.catalog_sha256, CATALOG.catalog_sha256)

    def test_dispatch_rejects_wrong_exact_types_and_forged_profiles(self) -> None:
        task = REGISTRY.tasks[0]
        profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
        with self.assertRaisesRegex(
            ExecutableFixtureCatalogError, "ExecutableStaticTask"
        ):
            build_fixture_bundle_for_task_profile(object(), profile)  # type: ignore[arg-type]

        forged_profile = copy.deepcopy(profile)
        object.__setattr__(forged_profile, "profile_sha256", "0" * 64)
        with self.assertRaisesRegex(
            ExecutableFixtureCatalogError, "forged nested values"
        ):
            build_fixture_bundle_for_task_profile(task, forged_profile)

        forged_task = copy.deepcopy(task)
        object.__setattr__(forged_task.parameters, "predicate", "outside-contract")
        with self.assertRaisesRegex(
            ExecutableFixtureCatalogError, "forged nested values"
        ):
            build_fixture_bundle_for_task_profile(forged_task, profile)

    def test_wrong_containers_order_and_nested_forgery_fail_closed(self) -> None:
        wrong_container = copy.copy(CATALOG)
        object.__setattr__(wrong_container, "bundles", list(CATALOG.bundles))
        self.assertFalse(verify_first_tranche_fixture_catalog(wrong_container))

        reordered = copy.copy(CATALOG)
        object.__setattr__(
            reordered,
            "bundles",
            (CATALOG.bundles[1], CATALOG.bundles[0], *CATALOG.bundles[2:]),
        )
        self.assertFalse(verify_first_tranche_fixture_catalog(reordered))

        nested_forgery = copy.deepcopy(CATALOG)
        output = nested_forgery.bundles[0].oracle.outputs[0]
        object.__setattr__(output, "content", output.content + b"forged")
        self.assertFalse(verify_first_tranche_fixture_catalog(nested_forgery))

    def test_catalog_hash_and_authority_tampering_fail_closed(self) -> None:
        forged_hash = copy.copy(CATALOG)
        object.__setattr__(forged_hash, "catalog_sha256", "0" * 64)
        self.assertFalse(verify_first_tranche_fixture_catalog(forged_hash))

        forged_authority = copy.copy(CATALOG)
        object.__setattr__(forged_authority, "candidate_execution_authorized", True)
        self.assertFalse(verify_first_tranche_fixture_catalog(forged_authority))

        self.assertFalse(verify_first_tranche_fixture_catalog(object()))

    def test_optimized_mode_keeps_validation_checks(self) -> None:
        code = """
from cbds.executable_fixture_catalog import (
    build_first_tranche_fixture_catalog,
    verify_first_tranche_fixture_catalog,
)
from cbds.executable_static_registry import build_public_method_development_registry
catalog = build_first_tranche_fixture_catalog(build_public_method_development_registry())
if not verify_first_tranche_fixture_catalog(catalog):
    raise SystemExit(2)
object.__setattr__(catalog, "claim_authorized", True)
if verify_first_tranche_fixture_catalog(catalog):
    raise SystemExit(3)
"""
        completed = subprocess.run(
            [sys.executable, "-O", "-c", code],
            cwd=ROOT,
            env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()
