from __future__ import annotations

import copy
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import cbds.hash_only_report_publication as report_publication  # noqa: E402
from cbds.executable_development_coverage_migration import (  # noqa: E402
    COVERAGE_MIGRATION_CONFIG_RELATIVE_PATH,
    MIGRATION_REASON_CODES,
    ExecutableDevelopmentCoverageMigrationError,
    build_executable_development_coverage_migration,
    executable_development_coverage_migration_config_bytes,
    load_executable_development_coverage_migration,
    validate_executable_development_coverage_migration,
)
from cbds.executable_development_coverage_v2 import (  # noqa: E402
    CANONICAL_FAMILY_ORDER,
    COVERAGE_V2_CONFIG_RELATIVE_PATH,
    FROZEN_HARDLINK_DISCRIMINATION_SHA256,
    FROZEN_HARDLINK_TASK_SET_SHA256,
    FROZEN_NINTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_NINTH_REGISTRY_SHA256,
    HARDLINK_FAMILY_INDEX,
    PREDECESSOR_CONFIG_BYTE_COUNT,
    PREDECESSOR_CONFIG_BYTES_SHA256,
    PREDECESSOR_COVERAGE_SHA256,
    PREDECESSOR_GIT_COMMIT,
    ExecutableDevelopmentCoverageV2Error,
    build_executable_development_coverage_v2,
    executable_development_coverage_v2_config_bytes,
    load_executable_development_coverage_v2,
    validate_executable_development_coverage_v2,
)


V1_CONFIG = ROOT / "configs/executable-method-development-coverage-v1.json"
V2_CONFIG = ROOT / COVERAGE_V2_CONFIG_RELATIVE_PATH
MIGRATION_CONFIG = ROOT / COVERAGE_MIGRATION_CONFIG_RELATIVE_PATH
EXPECTED_V2_COVERAGE_SHA256 = (
    "7406480a1dc06bc99d1e36fde1a328a490d6cc8d6b96ee38c924a902acbf9abd"
)
EXPECTED_V2_CONFIG_BYTES_SHA256 = (
    "b7c130b4b6436eb833548e69261da3ded1519c9680d82dc1e59063dd4af92ac9"
)
EXPECTED_V2_CONFIG_BYTE_COUNT = 23_267
EXPECTED_MIGRATION_SHA256 = (
    "eb2b577e8449438c734174f361dea5c2c1ced9a3a68be383413dc6e727b8526f"
)
EXPECTED_MIGRATION_CONFIG_BYTES_SHA256 = (
    "d99434137605374ad8e60fed3418078d625fb33dc8ce2e2d20b37e6576d6e643"
)
EXPECTED_MIGRATION_CONFIG_BYTE_COUNT = 3_865
EXPECTED_V1_HARDLINK_FAMILY_SHA256 = (
    "962199c9d4bebf6fd7dee376d05e75d4b82b0b9bfd82221b2fceb378fba00ff1"
)
EXPECTED_V2_HARDLINK_FAMILY_SHA256 = (
    "e5220935eae1a67271733903252629df7b71a3fb01cc116ad9d86ce5e12738cc"
)


class ExecutableDevelopmentCoverageV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.coverage = build_executable_development_coverage_v2()
        cls.migration = (
            build_executable_development_coverage_migration()
        )
        cls.v2_bytes = executable_development_coverage_v2_config_bytes()
        cls.migration_bytes = (
            executable_development_coverage_migration_config_bytes()
        )

    def test_v2_artifact_is_exact_deterministic_projection(self) -> None:
        self.assertEqual(
            self.coverage.coverage_sha256,
            EXPECTED_V2_COVERAGE_SHA256,
        )
        self.assertEqual(len(self.v2_bytes), EXPECTED_V2_CONFIG_BYTE_COUNT)
        self.assertEqual(
            sha256(self.v2_bytes).hexdigest(),
            EXPECTED_V2_CONFIG_BYTES_SHA256,
        )
        self.assertEqual(V2_CONFIG.read_bytes(), self.v2_bytes)
        self.assertEqual(
            load_executable_development_coverage_v2(V2_CONFIG),
            self.coverage,
        )
        self.assertEqual(
            build_executable_development_coverage_v2(), self.coverage
        )

    def test_v1_is_preserved_and_v2_is_backward_linked(self) -> None:
        v1_bytes = V1_CONFIG.read_bytes()
        self.assertEqual(len(v1_bytes), PREDECESSOR_CONFIG_BYTE_COUNT)
        self.assertEqual(
            sha256(v1_bytes).hexdigest(),
            PREDECESSOR_CONFIG_BYTES_SHA256,
        )
        predecessor = self.coverage.predecessor
        self.assertEqual(
            predecessor.coverage_sha256, PREDECESSOR_COVERAGE_SHA256
        )
        self.assertEqual(
            predecessor.config_bytes_sha256,
            PREDECESSOR_CONFIG_BYTES_SHA256,
        )
        self.assertEqual(
            predecessor.config_byte_count, PREDECESSOR_CONFIG_BYTE_COUNT
        )
        self.assertEqual(predecessor.git_commit, PREDECESSOR_GIT_COMMIT)

    def test_exact_18_integrated_7_planned_partition(self) -> None:
        families = self.coverage.families
        self.assertEqual(len(families), 25)
        self.assertEqual(
            tuple(family.family_id for family in families),
            CANONICAL_FAMILY_ORDER,
        )
        self.assertEqual(
            tuple(family.lifecycle_state for family in families),
            ("integrated",) * 18 + ("planned",) * 7,
        )
        self.assertEqual(sum(family.task_count for family in families), 500)
        self.assertEqual(
            tuple(
                source.cumulative_task_count
                for source in self.coverage.source_registry_commitments
            ),
            (100, 200, 240, 260, 280, 300, 320, 340, 360),
        )
        ninth = self.coverage.source_registry_commitments[-1]
        self.assertEqual(ninth.tranche_id, "ninth-tranche")
        self.assertEqual(
            ninth.registry_sha256, FROZEN_NINTH_REGISTRY_SHA256
        )
        self.assertEqual(
            ninth.cumulative_suite_sha256,
            FROZEN_NINTH_CUMULATIVE_SUITE_SHA256,
        )

    def test_hardlink_grid_is_integrated_and_fully_discriminated(self) -> None:
        family = self.coverage.families[HARDLINK_FAMILY_INDEX]
        self.assertEqual(family.lifecycle_state, "integrated")
        self.assertEqual(
            family.integrated_task_set_sha256,
            FROZEN_HARDLINK_TASK_SET_SHA256,
        )
        self.assertEqual(
            self.coverage.hardlink_discrimination_sha256,
            FROZEN_HARDLINK_DISCRIMINATION_SHA256,
        )
        self.assertEqual(
            family.parameter_axes[0].axis_name, "equivalence_key"
        )
        self.assertEqual(
            family.parameter_axes[0].values,
            (
                "sha256",
                "mode-and-sha256",
                "suffix-and-sha256",
                "declared-group-and-sha256",
            ),
        )
        self.assertEqual(
            family.parameter_axes[1].axis_name, "owner_policy"
        )
        self.assertEqual(
            family.parameter_axes[1].values,
            (
                "smallest-path",
                "largest-path",
                "oldest-mtime",
                "newest-mtime",
                "manifest-priority",
            ),
        )
        self.assertEqual(
            family.family_sha256,
            EXPECTED_V2_HARDLINK_FAMILY_SHA256,
        )

    def test_migration_changes_exactly_one_family(self) -> None:
        record = self.migration.to_hash_only_record()
        self.assertEqual(
            self.migration.migration_sha256,
            EXPECTED_MIGRATION_SHA256,
        )
        self.assertEqual(
            self.migration.old_family_sha256,
            EXPECTED_V1_HARDLINK_FAMILY_SHA256,
        )
        self.assertEqual(
            self.migration.new_family_sha256,
            EXPECTED_V2_HARDLINK_FAMILY_SHA256,
        )
        self.assertEqual(record["changed_family_count"], 1)
        self.assertEqual(record["unchanged_family_count"], 24)
        self.assertEqual(
            tuple(record["reason_codes"]), MIGRATION_REASON_CODES
        )
        self.assertEqual(
            len(self.migration.unchanged_family_sha256), 24
        )
        self.assertEqual(
            len(set(self.migration.unchanged_family_sha256)), 24
        )
        self.assertEqual(
            len(self.migration_bytes),
            EXPECTED_MIGRATION_CONFIG_BYTE_COUNT,
        )
        self.assertEqual(
            sha256(self.migration_bytes).hexdigest(),
            EXPECTED_MIGRATION_CONFIG_BYTES_SHA256,
        )
        self.assertEqual(
            MIGRATION_CONFIG.read_bytes(), self.migration_bytes
        )
        self.assertEqual(
            load_executable_development_coverage_migration(
                MIGRATION_CONFIG
            ),
            self.migration,
        )

    def test_authority_and_identity_mutations_fail_closed(self) -> None:
        hostile_coverage = copy.copy(self.coverage)
        object.__setattr__(hostile_coverage, "sealed", True)
        with self.assertRaises(ExecutableDevelopmentCoverageV2Error):
            validate_executable_development_coverage_v2(
                hostile_coverage
            )
        wrong_discrimination = copy.copy(self.coverage)
        object.__setattr__(
            wrong_discrimination,
            "hardlink_discrimination_sha256",
            "0" * 64,
        )
        with self.assertRaises(ExecutableDevelopmentCoverageV2Error):
            validate_executable_development_coverage_v2(
                wrong_discrimination
            )

        hostile_migration = copy.copy(self.migration)
        object.__setattr__(
            hostile_migration, "claim_authorized", True
        )
        with self.assertRaises(
            ExecutableDevelopmentCoverageMigrationError
        ):
            validate_executable_development_coverage_migration(
                hostile_migration
            )

    def test_cached_live_evidence_returns_fresh_unpoisonable_objects(
        self,
    ) -> None:
        victim = build_executable_development_coverage_v2()
        object.__setattr__(
            victim.families[0],
            "filesystem_schema",
            "poisoned-schema",
        )
        rebuilt = build_executable_development_coverage_v2()
        self.assertEqual(rebuilt, self.coverage)
        self.assertEqual(
            rebuilt.coverage_sha256, EXPECTED_V2_COVERAGE_SHA256
        )
        self.assertIsNot(rebuilt.families[0], victim.families[0])
        with self.assertRaises(ExecutableDevelopmentCoverageV2Error):
            validate_executable_development_coverage_v2(victim)

    def test_loaders_reject_noncanonical_duplicate_and_symlink_inputs(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            noncanonical = root / "noncanonical.json"
            value = json.loads(self.v2_bytes)
            noncanonical.write_text(
                json.dumps(value, indent=2) + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(ExecutableDevelopmentCoverageV2Error):
                load_executable_development_coverage_v2(noncanonical)

            duplicate = root / "duplicate.json"
            duplicate.write_bytes(
                b'{"schema_version":"2.0.0",'
                b'"schema_version":"2.0.0"}\n'
            )
            with self.assertRaises(ExecutableDevelopmentCoverageV2Error):
                load_executable_development_coverage_v2(duplicate)

            symlink = root / "coverage-link.json"
            symlink.symlink_to(V2_CONFIG)
            with self.assertRaises(ExecutableDevelopmentCoverageV2Error):
                load_executable_development_coverage_v2(symlink)

            migration_noncanonical = root / "migration-pretty.json"
            migration_noncanonical.write_text(
                json.dumps(json.loads(self.migration_bytes), indent=2)
                + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(
                ExecutableDevelopmentCoverageMigrationError
            ):
                load_executable_development_coverage_migration(
                    migration_noncanonical
                )

            migration_duplicate = root / "migration-duplicate.json"
            migration_duplicate.write_bytes(
                b'{"schema_version":"1.0.0",'
                b'"schema_version":"1.0.0"}\n'
            )
            with self.assertRaises(
                ExecutableDevelopmentCoverageMigrationError
            ):
                load_executable_development_coverage_migration(
                    migration_duplicate
                )

            migration_symlink = root / "migration-link.json"
            migration_symlink.symlink_to(MIGRATION_CONFIG)
            with self.assertRaises(
                ExecutableDevelopmentCoverageMigrationError
            ):
                load_executable_development_coverage_migration(
                    migration_symlink
                )

        with self.assertRaises(ExecutableDevelopmentCoverageV2Error):
            load_executable_development_coverage_v2(Path("bad\0path"))
        with self.assertRaises(
            ExecutableDevelopmentCoverageMigrationError
        ):
            load_executable_development_coverage_migration(
                Path("bad\0path")
            )

    def test_loaders_require_published_file_shape(self) -> None:
        loaders = (
            (
                "v2",
                self.v2_bytes,
                load_executable_development_coverage_v2,
                ExecutableDevelopmentCoverageV2Error,
            ),
            (
                "migration",
                self.migration_bytes,
                load_executable_development_coverage_migration,
                ExecutableDevelopmentCoverageMigrationError,
            ),
        )
        for label, payload, loader, error_type in loaders:
            with self.subTest(loader=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                wrong_mode = root / "wrong-mode.json"
                wrong_mode.write_bytes(payload)
                wrong_mode.chmod(0o600)
                with self.assertRaises(error_type):
                    loader(wrong_mode)

                anchor = root / "anchor.json"
                anchor.write_bytes(payload)
                anchor.chmod(0o644)
                linked = root / "linked.json"
                os.link(anchor, linked)
                with self.assertRaises(error_type):
                    loader(linked)

    def test_loaders_reject_parent_displacement_during_read(self) -> None:
        if os.name != "posix":
            self.skipTest("descriptor-relative parent races require POSIX")
        loaders = (
            (
                "v2",
                self.v2_bytes,
                load_executable_development_coverage_v2,
                ExecutableDevelopmentCoverageV2Error,
            ),
            (
                "migration",
                self.migration_bytes,
                load_executable_development_coverage_migration,
                ExecutableDevelopmentCoverageMigrationError,
            ),
        )
        for label, payload, loader, error_type in loaders:
            with self.subTest(loader=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                parent = root / "parent"
                parent.mkdir()
                parked = root / "parked"
                path = parent / "artifact.json"
                path.write_bytes(payload)
                path.chmod(0o644)
                real_read = report_publication.os.read
                displaced = False

                def read_then_displace(
                    descriptor: int,
                    size: int,
                ) -> bytes:
                    nonlocal displaced
                    result = real_read(descriptor, size)
                    if not displaced:
                        parent.rename(parked)
                        parent.mkdir()
                        path.write_bytes(b"different\n")
                        path.chmod(0o644)
                        displaced = True
                    return result

                with mock.patch.object(
                    report_publication.os,
                    "read",
                    side_effect=read_then_displace,
                ), self.assertRaises(error_type):
                    loader(path)

                self.assertTrue(displaced)
                self.assertEqual(
                    (parked / path.name).read_bytes(),
                    payload,
                )
                self.assertEqual(path.read_bytes(), b"different\n")

    def test_root_and_packaged_schemas_match_and_validate_artifacts(
        self,
    ) -> None:
        pairs = (
            (
                ROOT
                / "executable-method-development-coverage-v2.schema.json",
                ROOT
                / "src/cbds/schemas/"
                "executable-method-development-coverage-v2.schema.json",
                json.loads(self.v2_bytes),
            ),
            (
                ROOT
                / "executable-method-development-coverage-migration."
                "schema.json",
                ROOT
                / "src/cbds/schemas/"
                "executable-method-development-coverage-migration."
                "schema.json",
                json.loads(self.migration_bytes),
            ),
        )
        try:
            from jsonschema import Draft202012Validator
        except ImportError:
            Draft202012Validator = None  # type: ignore[assignment]
        for root_schema, packaged_schema, instance in pairs:
            self.assertEqual(
                root_schema.read_bytes(), packaged_schema.read_bytes()
            )
            schema = json.loads(root_schema.read_bytes())
            if Draft202012Validator is not None:
                Draft202012Validator.check_schema(schema)
                Draft202012Validator(schema).validate(instance)
        if Draft202012Validator is not None:
            v2_schema = json.loads(pairs[0][0].read_bytes())
            bad_v2 = copy.deepcopy(pairs[0][2])
            bad_v2["families"][0][
                "integrated_task_set_sha256"
            ] = None
            self.assertTrue(
                list(
                    Draft202012Validator(v2_schema).iter_errors(
                        bad_v2
                    )
                )
            )
            bad_predecessor = copy.deepcopy(pairs[0][2])
            bad_predecessor["predecessor"][
                "coverage_sha256"
            ] = "0" * 64
            self.assertTrue(
                list(
                    Draft202012Validator(v2_schema).iter_errors(
                        bad_predecessor
                    )
                )
            )
            migration_schema = json.loads(pairs[1][0].read_bytes())
            bad_migration = copy.deepcopy(pairs[1][2])
            bad_migration["old_parameter_axes"][0]["values"] = []
            self.assertTrue(
                list(
                    Draft202012Validator(
                        migration_schema
                    ).iter_errors(bad_migration)
                )
            )


if __name__ == "__main__":
    unittest.main()
