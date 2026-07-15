from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

SCRIPT_PATH = ROOT / "scripts" / "build_executable_second_tranche_catalog.py"
SCRIPT_SPEC = importlib.util.spec_from_file_location(
    "cbds_build_executable_second_tranche_catalog",
    SCRIPT_PATH,
)
assert SCRIPT_SPEC is not None and SCRIPT_SPEC.loader is not None
REPORT_SCRIPT = importlib.util.module_from_spec(SCRIPT_SPEC)
sys.modules[SCRIPT_SPEC.name] = REPORT_SCRIPT
SCRIPT_SPEC.loader.exec_module(REPORT_SCRIPT)

from cbds.executable_fixture_catalog import (  # noqa: E402
    ExecutableFixtureCatalogError,
    build_first_tranche_fixture_catalog,
    build_fixture_bundle_for_task_profile,
)
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from cbds.executable_fixture_second_catalog import (  # noqa: E402
    FROZEN_FIRST_CATALOG_SHA256,
    SECOND_TRANCHE_ADDED_FIXTURE_COUNT,
    SECOND_TRANCHE_CUMULATIVE_FIXTURE_COUNT,
    SECOND_TRANCHE_FAMILY_ORDER,
    SECOND_TRANCHE_FIXTURE_COUNT,
    ExecutableFixtureSecondCatalogError,
    build_second_tranche_fixture_catalog,
    compute_second_tranche_fixture_catalog_sha256,
    validate_second_tranche_fixture_catalog,
    verify_second_tranche_fixture_catalog,
)
from cbds.executable_static_registry import (  # noqa: E402
    build_public_method_development_registry,
)
from cbds.executable_static_second_registry import (  # noqa: E402
    FROZEN_FIRST_REGISTRY_SHA256,
    FROZEN_FIRST_SUITE_SHA256,
    JOIN_DUPLICATE_POLICIES,
    JOIN_KEYS,
    LINE_TRANSFORMS,
    LINE_TRANSFORM_SUFFIXES,
    MODE_MIRROR_SELECTORS,
    MODE_NORMALIZATIONS,
    PROC_SNAPSHOT_PREDICATES,
    PROC_SNAPSHOT_VIEWS,
    USTAR_CONFLICT_POLICIES,
    USTAR_SELECTORS,
    validate_second_tranche_task_registry,
)


FAMILY_ORDER = SECOND_TRANCHE_FAMILY_ORDER
FIXTURE_HASH_KEYS = {
    "task_contract_sha256",
    "profile_sha256",
    "fixture_definition_sha256",
    "trusted_oracle_sha256",
    "fixture_sha256",
}
TASK_HASH_KEYS = {
    "family_id",
    "task_contract_sha256",
    "graph_sha256",
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
            indent=2,
        )
        + "\n"
    ).encode("utf-8")


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


class SecondTrancheFixtureCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = build_second_tranche_fixture_catalog()
        cls.record = cls.catalog.to_hash_only_record()
        cls.payload = _canonical_bytes(cls.record)

    def assert_catalog_invalid(self, catalog: object) -> None:
        self.assertFalse(verify_second_tranche_fixture_catalog(catalog))
        with self.assertRaises(
            (ExecutableFixtureSecondCatalogError, TypeError, ValueError)
        ):
            validate_second_tranche_fixture_catalog(catalog)  # type: ignore[arg-type]

    def test_added_task_grid_is_exact_unique_and_canonically_ordered(self) -> None:
        validate_second_tranche_fixture_catalog(self.catalog)
        tasks = self.catalog.registry.added_tasks
        self.assertEqual(len(tasks), 100)
        self.assertEqual(
            tuple(task.family_id for task in tasks),
            tuple(family for family in FAMILY_ORDER for _index in range(20)),
        )
        self.assertEqual(
            tuple(
                (task.parameters.suffix, task.parameters.transform)
                for task in tasks[:20]
            ),
            tuple(
                (suffix, transform)
                for suffix in LINE_TRANSFORM_SUFFIXES
                for transform in LINE_TRANSFORMS
            ),
        )
        self.assertEqual(
            tuple(
                (task.parameters.selector, task.parameters.normalization)
                for task in tasks[20:40]
            ),
            tuple(
                (selector, normalization)
                for selector in MODE_MIRROR_SELECTORS
                for normalization in MODE_NORMALIZATIONS
            ),
        )
        self.assertEqual(
            tuple(
                (task.parameters.key, task.parameters.duplicate_policy)
                for task in tasks[40:60]
            ),
            tuple(
                (key, policy)
                for key in JOIN_KEYS
                for policy in JOIN_DUPLICATE_POLICIES
            ),
        )
        self.assertEqual(
            tuple(
                (task.parameters.selector, task.parameters.conflict_policy)
                for task in tasks[60:80]
            ),
            tuple(
                (selector, policy)
                for selector in USTAR_SELECTORS
                for policy in USTAR_CONFLICT_POLICIES
            ),
        )
        self.assertEqual(
            tuple(
                (task.parameters.view, task.parameters.predicate)
                for task in tasks[80:]
            ),
            tuple(
                (view, predicate)
                for view in PROC_SNAPSHOT_VIEWS
                for predicate in PROC_SNAPSHOT_PREDICATES
            ),
        )
        self.assertEqual(len({task.task_id for task in tasks}), 100)
        self.assertEqual(
            len({task.task_contract_sha256 for task in tasks}), 100
        )
        self.assertEqual(len({task.graph_sha256 for task in tasks}), 100)
        for task in tasks:
            self.assertIs(task.public, True)
            self.assertIs(task.sealed, False)
            self.assertIs(task.claim_authorized, False)

    def test_500_bundles_are_canonical_unique_and_nonauthorizing(self) -> None:
        bundles = self.catalog.bundles
        tasks = self.catalog.registry.added_tasks
        self.assertEqual(len(bundles), 500)
        self.assertEqual(SECOND_TRANCHE_ADDED_FIXTURE_COUNT, 500)
        self.assertEqual(SECOND_TRANCHE_FIXTURE_COUNT, 500)
        self.assertEqual(SECOND_TRANCHE_CUMULATIVE_FIXTURE_COUNT, 1_000)
        fixture_ids: set[str] = set()
        fixture_hashes: set[str] = set()
        for index, bundle in enumerate(bundles):
            task = tasks[index // 5]
            profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[index % 5]
            with self.subTest(
                family=task.family_id,
                task=task.task_id,
                profile=profile.profile_id,
            ):
                self.assertEqual(
                    bundle.task_contract_sha256,
                    task.task_contract_sha256,
                )
                self.assertEqual(bundle.profile_sha256, profile.profile_sha256)
                self.assertEqual(task.fixtures[index % 5], bundle.descriptor)
                self.assertIs(bundle.candidate_execution_authorized, False)
                self.assertIs(bundle.model_selection_eligible, False)
                self.assertIs(bundle.claim_authorized, False)
                fixture_ids.add(bundle.descriptor.fixture_id)
                fixture_hashes.add(bundle.descriptor.fixture_sha256)
        self.assertEqual(len(fixture_ids), 500)
        self.assertEqual(len(fixture_hashes), 500)

    def test_exact_regeneration_is_deterministic_and_never_executes(self) -> None:
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
            rebuilt = build_second_tranche_fixture_catalog()
            rebuilt_record = rebuilt.to_hash_only_record()
        self.assertEqual(rebuilt, self.catalog)
        self.assertEqual(rebuilt_record, self.record)
        self.assertEqual(_canonical_bytes(rebuilt_record), self.payload)
        self.assertEqual(
            rebuilt.catalog_sha256,
            compute_second_tranche_fixture_catalog_sha256(
                rebuilt.registry,
                rebuilt.bundles,
            ),
        )

    def test_frozen_first_tranche_digests_are_rebuilt_and_unchanged(self) -> None:
        first_registry = build_public_method_development_registry()
        first_catalog = build_first_tranche_fixture_catalog(first_registry)
        self.assertEqual(
            first_registry.registry_sha256, FROZEN_FIRST_REGISTRY_SHA256
        )
        self.assertEqual(first_registry.suite_sha256, FROZEN_FIRST_SUITE_SHA256)
        self.assertEqual(
            first_catalog.catalog_sha256, FROZEN_FIRST_CATALOG_SHA256
        )
        self.assertEqual(
            self.catalog.registry.base_registry_sha256,
            first_registry.registry_sha256,
        )
        self.assertEqual(
            self.catalog.registry.base_suite_sha256,
            first_registry.suite_sha256,
        )
        self.assertEqual(
            self.catalog.base_fixture_catalog_sha256,
            first_catalog.catalog_sha256,
        )
        self.assertEqual(
            self.record["base_fixture_catalog_sha256"],
            first_catalog.catalog_sha256,
        )
        self.assertTrue(
            set(FAMILY_ORDER).isdisjoint(
                {task.family_id for task in first_registry.tasks}
            )
        )

    def test_projection_is_canonical_hash_only_and_nonauthorizing(self) -> None:
        self.assertFalse(_contains_bytes(self.record))
        self.assertEqual(
            self.record["record_type"],
            "cbds.executable-fixture-second-tranche-catalog",
        )
        self.assertEqual(self.record["added_task_count"], 100)
        self.assertEqual(self.record["cumulative_task_count"], 200)
        self.assertEqual(self.record["added_fixture_count"], 500)
        self.assertEqual(self.record["cumulative_fixture_count"], 1_000)
        self.assertEqual(self.record["profiles_per_task"], 5)
        self.assertEqual(
            self.record["family_task_counts"],
            {family: 20 for family in FAMILY_ORDER},
        )
        self.assertEqual(
            self.record["family_fixture_counts"],
            {family: 100 for family in FAMILY_ORDER},
        )
        self.assertEqual(
            self.record["profile_sha256"],
            [
                profile.profile_sha256
                for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
            ],
        )
        task_records = self.record["added_tasks"]
        self.assertEqual(len(task_records), 100)
        for index, task_record in enumerate(task_records):
            self.assertEqual(set(task_record), TASK_HASH_KEYS)
            task = self.catalog.registry.added_tasks[index]
            self.assertEqual(task_record["family_id"], task.family_id)
            self.assertEqual(
                task_record["task_contract_sha256"],
                task.task_contract_sha256,
            )
            self.assertEqual(task_record["graph_sha256"], task.graph_sha256)

        fixtures = self.record["added_fixtures"]
        self.assertEqual(len(fixtures), 500)
        for index, fixture in enumerate(fixtures):
            self.assertEqual(set(fixture), FIXTURE_HASH_KEYS)
            self.assertTrue(
                all(len(value) == 64 for value in fixture.values())
            )
            bundle = self.catalog.bundles[index]
            self.assertEqual(
                fixture["task_contract_sha256"],
                bundle.task_contract_sha256,
            )
            self.assertEqual(
                fixture["profile_sha256"], bundle.profile_sha256
            )
            self.assertEqual(
                fixture["fixture_sha256"],
                bundle.descriptor.fixture_sha256,
            )
        for key in (
            "content",
            "inputs",
            "outputs",
            "prompt",
            "answer",
            "response",
        ):
            self.assertFalse(_contains_key(self.record, key))
        encoded = self.payload.decode("utf-8")
        self.assertNotIn("input/", encoded)
        self.assertNotIn("output/", encoded)
        self.assertIs(self.record["public_method_development"], True)
        self.assertIs(self.record["sealed"], False)
        self.assertIs(self.record["candidate_execution_authorized"], False)
        self.assertIs(self.record["model_selection_eligible"], False)
        self.assertIs(self.record["claim_authorized"], False)
        self.assertEqual(
            self.record["catalog_sha256"], self.catalog.catalog_sha256
        )
        parsed = json.loads(
            self.payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"nonfinite JSON constant: {value}")
            ),
        )
        self.assertEqual(parsed, self.record)
        self.assertEqual(_canonical_bytes(parsed), self.payload)

    def test_report_builder_serializes_only_the_central_projection(self) -> None:
        with mock.patch.object(
            REPORT_SCRIPT,
            "build_second_tranche_fixture_catalog",
            return_value=self.catalog,
        ) as central_builder:
            observed = REPORT_SCRIPT.canonical_second_tranche_catalog_bytes()
        central_builder.assert_called_once_with()
        self.assertEqual(observed, self.payload)

    def test_order_nested_hash_and_authority_tampering_fail_closed(self) -> None:
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

        forged_hash = copy.copy(self.catalog)
        object.__setattr__(forged_hash, "catalog_sha256", "0" * 64)
        self.assert_catalog_invalid(forged_hash)

        forged_authority = copy.copy(self.catalog)
        object.__setattr__(
            forged_authority, "candidate_execution_authorized", True
        )
        self.assert_catalog_invalid(forged_authority)
        self.assert_catalog_invalid(object())

    def test_frozen_task_and_profile_bypasses_fail_closed(self) -> None:
        forged_catalog = copy.copy(self.catalog)
        forged_registry = copy.deepcopy(self.catalog.registry)
        parameters = forged_registry.added_tasks[0].parameters
        object.__setattr__(parameters, "transform", "outside-contract")
        object.__setattr__(forged_catalog, "registry", forged_registry)
        self.assert_catalog_invalid(forged_catalog)

        task = self.catalog.registry.added_tasks[0]
        forged_profile = copy.deepcopy(PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0])
        object.__setattr__(forged_profile, "profile_sha256", "0" * 64)
        with self.assertRaisesRegex(
            ExecutableFixtureCatalogError,
            "forged nested values",
        ):
            build_fixture_bundle_for_task_profile(task, forged_profile)

    def test_hostile_string_subclasses_cannot_spoof_nested_or_outer_hashes(
        self,
    ) -> None:
        forged_registry = copy.deepcopy(self.catalog.registry)
        forged_task = forged_registry.added_tasks[0]
        object.__setattr__(
            forged_task,
            "task_contract_sha256",
            _SpoofedString("0" * 64),
        )
        with self.assertRaises(ValueError):
            forged_task.__post_init__()
        with self.assertRaises(ValueError):
            validate_second_tranche_task_registry(forged_registry)

        forged_catalog = copy.copy(self.catalog)
        object.__setattr__(
            forged_catalog,
            "catalog_sha256",
            _SpoofedString(self.catalog.catalog_sha256),
        )
        self.assert_catalog_invalid(forged_catalog)

        descriptor = copy.deepcopy(self.catalog.bundles[0].descriptor)
        object.__setattr__(
            descriptor,
            "fixture_sha256",
            _SpoofedString(descriptor.fixture_sha256),
        )
        with self.assertRaises(ValueError):
            descriptor.__post_init__()

    def test_atomic_report_publication_is_idempotent_and_no_replace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "nested" / "second-catalog.json"
            REPORT_SCRIPT.atomic_publish_noreplace(report, self.payload)
            first_stat = report.stat()
            self.assertEqual(report.read_bytes(), self.payload)
            self.assertEqual(stat.S_IMODE(first_stat.st_mode), 0o644)
            self.assertEqual(
                list(report.parent.glob(f".{report.name}.*.tmp")), []
            )

            REPORT_SCRIPT.atomic_publish_noreplace(report, self.payload)
            self.assertEqual(report.stat().st_ino, first_stat.st_ino)
            with self.assertRaisesRegex(
                REPORT_SCRIPT.SecondTrancheCatalogPublicationError,
                "differs",
            ):
                REPORT_SCRIPT.atomic_publish_noreplace(
                    report, self.payload + b"different"
                )
            self.assertEqual(report.read_bytes(), self.payload)
            self.assertEqual(
                list(report.parent.glob(f".{report.name}.*.tmp")), []
            )

    def test_cli_uses_central_projection_and_checks_caller_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            REPORT_SCRIPT,
            "canonical_second_tranche_catalog_bytes",
            return_value=self.payload,
        ):
            report = Path(temporary) / "caller" / "manifest.json"
            self.assertEqual(REPORT_SCRIPT.main(["--output", str(report)]), 0)
            self.assertEqual(
                REPORT_SCRIPT.main(
                    ["--output", str(report), "--check"]
                ),
                0,
            )
            self.assertEqual(report.read_bytes(), self.payload)

            missing = Path(temporary) / "missing.json"
            with self.assertRaisesRegex(SystemExit, "does not exist"):
                REPORT_SCRIPT.main(
                    ["--output", str(missing), "--check"]
                )
            report.write_bytes(b"different\n")
            with self.assertRaisesRegex(SystemExit, "differs"):
                REPORT_SCRIPT.main(["--output", str(report)])
            self.assertEqual(report.read_bytes(), b"different\n")

    def test_optimized_mode_keeps_central_catalog_validation_checks(self) -> None:
        code = """
from cbds.executable_fixture_second_catalog import (
    build_second_tranche_fixture_catalog,
    validate_second_tranche_fixture_catalog,
    verify_second_tranche_fixture_catalog,
)
catalog = build_second_tranche_fixture_catalog()
validate_second_tranche_fixture_catalog(catalog)
if not verify_second_tranche_fixture_catalog(catalog):
    raise SystemExit(2)
if len(catalog.registry.added_tasks) != 100 or len(catalog.bundles) != 500:
    raise SystemExit(3)
object.__setattr__(catalog, "claim_authorized", True)
if verify_second_tranche_fixture_catalog(catalog):
    raise SystemExit(4)
"""
        completed = subprocess.run(
            [sys.executable, "-O", "-c", code],
            cwd=ROOT,
            env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()
