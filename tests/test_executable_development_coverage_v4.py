from __future__ import annotations

import copy
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import cbds.hash_only_report_publication as report_publication  # noqa: E402
from cbds.executable_development_coverage_v3 import (  # noqa: E402
    build_executable_development_coverage_v3,
)
from cbds.executable_development_coverage_v3_to_v4_migration import (  # noqa: E402
    COVERAGE_V3_TO_V4_MIGRATION_CONFIG_RELATIVE_PATH,
    FROZEN_V3_CHECKSUM_FAMILY_SHA256,
    FROZEN_V4_CHECKSUM_FAMILY_SHA256,
    MIGRATION_REASON_CODES,
    ExecutableDevelopmentCoverageV3ToV4MigrationError,
    build_executable_development_coverage_v3_to_v4_migration,
    executable_development_coverage_v3_to_v4_migration_config_bytes,
    load_executable_development_coverage_v3_to_v4_migration,
    validate_executable_development_coverage_v3_to_v4_migration,
)
from cbds.executable_development_coverage_v4 import (  # noqa: E402
    CANONICAL_FAMILY_ORDER,
    CHECKSUM_FAMILY_INDEX,
    COVERAGE_V4_CONFIG_RELATIVE_PATH,
    FROZEN_CHECKSUM_DISCRIMINATION_SHA256,
    FROZEN_CHECKSUM_TASK_SET_SHA256,
    FROZEN_ELEVENTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_ELEVENTH_REGISTRY_SHA256,
    PREDECESSOR_CONFIG_BYTE_COUNT,
    PREDECESSOR_CONFIG_BYTES_SHA256,
    PREDECESSOR_COVERAGE_SHA256,
    PREDECESSOR_GIT_COMMIT,
    CoveragePromotionEvidence,
    ExecutableDevelopmentCoverageV4Error,
    build_executable_development_coverage_v4,
    executable_development_coverage_v4_config_bytes,
    load_executable_development_coverage_v4,
    validate_executable_development_coverage_v4,
)


V3_CONFIG = ROOT / "configs/executable-method-development-coverage-v3.json"
V4_CONFIG = ROOT / COVERAGE_V4_CONFIG_RELATIVE_PATH
MIGRATION_CONFIG = (
    ROOT / COVERAGE_V3_TO_V4_MIGRATION_CONFIG_RELATIVE_PATH
)
EXPECTED_V4_COVERAGE_SHA256 = (
    "1bd7a4b6ab721404f1d1eb7a64718ba7df783998bf16cd603afb86eb2420d67c"
)
EXPECTED_V4_CONFIG_BYTES_SHA256 = (
    "d003a5748da855257aa93e0c6e1b7a4be2de393ec5faa0dcb32d74156f40b3d7"
)
EXPECTED_V4_CONFIG_BYTE_COUNT = 24_590
EXPECTED_MIGRATION_SHA256 = (
    "667e31ef974829a5114544b1f1164f25c0f7515f67ef5600c979e85a3bcc3d8b"
)
EXPECTED_MIGRATION_CONFIG_BYTES_SHA256 = (
    "a1a783544d76f471688afe5f45eaf0f16c30a6ce04c36d1d5a438d6c8e439b7f"
)
EXPECTED_MIGRATION_CONFIG_BYTE_COUNT = 4_701
FROZEN_HISTORICAL_ARTIFACTS = {
    "configs/executable-method-development-coverage-v1.json": (
        22_495,
        "46f98f54ef5682ce0adc3854557ecfe8ed092fd5e916935bc27702edb4e86efa",
    ),
    "configs/executable-method-development-coverage-v2.json": (
        23_267,
        "b7c130b4b6436eb833548e69261da3ded1519c9680d82dc1e59063dd4af92ac9",
    ),
    "configs/executable-method-development-coverage-v3.json": (
        23_943,
        "de241ad1e4536fa595f99acf0ef05a3e423418876298c576abe87249c018bc0a",
    ),
    (
        "configs/executable-method-development-coverage-"
        "v1-to-v2-migration.json"
    ): (
        3_865,
        "d99434137605374ad8e60fed3418078d625fb33dc8ce2e2d20b37e6576d6e643",
    ),
    (
        "configs/executable-method-development-coverage-"
        "v2-to-v3-migration.json"
    ): (
        4_358,
        "77820327bc105d367d8d737c110e53e8183ce786650ecb4c1699991412cb6683",
    ),
}


class ExecutableDevelopmentCoverageV4Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.v3 = build_executable_development_coverage_v3()
        cls.coverage = build_executable_development_coverage_v4()
        cls.migration = (
            build_executable_development_coverage_v3_to_v4_migration()
        )
        cls.v4_bytes = executable_development_coverage_v4_config_bytes()
        cls.migration_bytes = (
            executable_development_coverage_v3_to_v4_migration_config_bytes()
        )

    def test_v4_artifact_is_exact_deterministic_projection(self) -> None:
        self.assertEqual(
            self.coverage.coverage_sha256,
            EXPECTED_V4_COVERAGE_SHA256,
        )
        self.assertEqual(
            len(self.v4_bytes), EXPECTED_V4_CONFIG_BYTE_COUNT
        )
        self.assertEqual(
            sha256(self.v4_bytes).hexdigest(),
            EXPECTED_V4_CONFIG_BYTES_SHA256,
        )
        self.assertEqual(V4_CONFIG.read_bytes(), self.v4_bytes)
        self.assertEqual(
            load_executable_development_coverage_v4(V4_CONFIG),
            self.coverage,
        )
        self.assertEqual(
            build_executable_development_coverage_v4(),
            self.coverage,
        )

    def test_all_historical_artifact_bytes_are_preserved(self) -> None:
        for relative_path, (expected_size, expected_sha256) in (
            FROZEN_HISTORICAL_ARTIFACTS.items()
        ):
            with self.subTest(path=relative_path):
                payload = (ROOT / relative_path).read_bytes()
                self.assertEqual(len(payload), expected_size)
                self.assertEqual(
                    sha256(payload).hexdigest(), expected_sha256
                )

    def test_v3_is_exactly_backward_linked(self) -> None:
        v3_bytes = V3_CONFIG.read_bytes()
        self.assertEqual(len(v3_bytes), PREDECESSOR_CONFIG_BYTE_COUNT)
        self.assertEqual(
            sha256(v3_bytes).hexdigest(),
            PREDECESSOR_CONFIG_BYTES_SHA256,
        )
        predecessor = self.coverage.predecessor
        self.assertEqual(
            predecessor.coverage_sha256,
            PREDECESSOR_COVERAGE_SHA256,
        )
        self.assertEqual(
            predecessor.config_bytes_sha256,
            PREDECESSOR_CONFIG_BYTES_SHA256,
        )
        self.assertEqual(
            predecessor.config_byte_count,
            PREDECESSOR_CONFIG_BYTE_COUNT,
        )
        self.assertEqual(predecessor.git_commit, PREDECESSOR_GIT_COMMIT)

    def test_exact_20_integrated_5_planned_partition(self) -> None:
        families = self.coverage.families
        self.assertEqual(len(families), 25)
        self.assertEqual(
            tuple(family.family_id for family in families),
            CANONICAL_FAMILY_ORDER,
        )
        self.assertEqual(
            tuple(family.lifecycle_state for family in families),
            ("integrated",) * 20 + ("planned",) * 5,
        )
        self.assertEqual(sum(family.task_count for family in families), 500)
        self.assertEqual(
            tuple(
                source.cumulative_task_count
                for source in self.coverage.source_registry_commitments
            ),
            (100, 200, 240, 260, 280, 300, 320, 340, 360, 380, 400),
        )
        eleventh = self.coverage.source_registry_commitments[-1]
        self.assertEqual(eleventh.tranche_id, "eleventh-tranche")
        self.assertEqual(eleventh.added_task_count, 20)
        self.assertEqual(
            eleventh.registry_sha256,
            FROZEN_ELEVENTH_REGISTRY_SHA256,
        )
        self.assertEqual(
            eleventh.cumulative_suite_sha256,
            FROZEN_ELEVENTH_CUMULATIVE_SUITE_SHA256,
        )

    def test_promotion_history_preserves_archive_and_appends_checksum(
        self,
    ) -> None:
        history = self.coverage.promotion_history
        self.assertEqual(len(history), 2)
        self.assertTrue(
            all(type(item) is CoveragePromotionEvidence for item in history)
        )
        self.assertEqual(
            history[0].to_record(),
            self.v3.promotion_evidence.to_record(),
        )
        checksum = history[1]
        self.assertEqual(checksum.family_id, "checksum-repair-plan")
        self.assertEqual(checksum.old_lifecycle_state, "planned")
        self.assertEqual(checksum.new_lifecycle_state, "integrated")
        self.assertEqual(checksum.source_tranche_id, "eleventh-tranche")
        self.assertEqual(
            checksum.task_set_sha256,
            FROZEN_CHECKSUM_TASK_SET_SHA256,
        )
        self.assertEqual(
            checksum.discrimination_sha256,
            FROZEN_CHECKSUM_DISCRIMINATION_SHA256,
        )
        family = self.coverage.families[CHECKSUM_FAMILY_INDEX]
        self.assertEqual(
            family.integrated_task_set_sha256,
            checksum.task_set_sha256,
        )

    def test_migration_changes_only_checksum_and_preserves_contract(
        self,
    ) -> None:
        old = self.v3.families[CHECKSUM_FAMILY_INDEX]
        new = self.coverage.families[CHECKSUM_FAMILY_INDEX]
        self.assertEqual(old.lifecycle_state, "planned")
        self.assertEqual(new.lifecycle_state, "integrated")
        self.assertEqual(
            old.family_sha256, FROZEN_V3_CHECKSUM_FAMILY_SHA256
        )
        self.assertEqual(
            new.family_sha256, FROZEN_V4_CHECKSUM_FAMILY_SHA256
        )
        self.assertEqual(old.parameter_axes, new.parameter_axes)
        self.assertEqual(old.solution_track, new.solution_track)
        self.assertEqual(old.allowed_tools, new.allowed_tools)
        self.assertEqual(old.filesystem_schema, new.filesystem_schema)
        self.assertEqual(old.output_contract, new.output_contract)
        self.assertEqual(old.capability_tags, new.capability_tags)
        self.assertIsNone(old.integrated_task_set_sha256)
        self.assertEqual(
            new.integrated_task_set_sha256,
            FROZEN_CHECKSUM_TASK_SET_SHA256,
        )
        for index, (before, after) in enumerate(
            zip(self.v3.families, self.coverage.families, strict=True)
        ):
            if index == CHECKSUM_FAMILY_INDEX:
                self.assertNotEqual(before, after)
            else:
                self.assertEqual(before, after)
        self.assertEqual(
            self.coverage.source_registry_commitments[:-1],
            self.v3.source_registry_commitments,
        )

    def test_migration_artifact_proves_history_and_invariance(
        self,
    ) -> None:
        record = self.migration.to_hash_only_record()
        self.assertEqual(
            self.migration.migration_sha256,
            EXPECTED_MIGRATION_SHA256,
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
            tuple(
                item.to_record()
                for item in self.migration.preserved_promotion_history
            ),
            (self.v3.promotion_evidence.to_record(),),
        )
        self.assertEqual(
            self.migration.promotion_evidence,
            self.coverage.promotion_history[-1],
        )
        self.assertEqual(
            self.migration.preserved_parameter_axes,
            self.v3.families[CHECKSUM_FAMILY_INDEX].parameter_axes,
        )
        self.assertEqual(
            self.migration.new_source_registry_commitment,
            self.coverage.source_registry_commitments[-1],
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
            load_executable_development_coverage_v3_to_v4_migration(
                MIGRATION_CONFIG
            ),
            self.migration,
        )

    def test_authority_history_and_evidence_mutations_fail_closed(
        self,
    ) -> None:
        hostile = copy.copy(self.coverage)
        object.__setattr__(hostile, "sealed", True)
        with self.assertRaises(ExecutableDevelopmentCoverageV4Error):
            validate_executable_development_coverage_v4(hostile)

        reordered = copy.copy(self.coverage)
        object.__setattr__(
            reordered,
            "promotion_history",
            tuple(reversed(self.coverage.promotion_history)),
        )
        with self.assertRaises(ExecutableDevelopmentCoverageV4Error):
            validate_executable_development_coverage_v4(reordered)

        poisoned = copy.copy(self.coverage)
        checksum = copy.copy(self.coverage.promotion_history[-1])
        object.__setattr__(checksum, "source_tranche_id", "tenth-tranche")
        object.__setattr__(
            poisoned,
            "promotion_history",
            (self.coverage.promotion_history[0], checksum),
        )
        with self.assertRaises(ExecutableDevelopmentCoverageV4Error):
            validate_executable_development_coverage_v4(poisoned)

        hostile_migration = copy.copy(self.migration)
        object.__setattr__(
            hostile_migration,
            "claim_authorized",
            True,
        )
        with self.assertRaises(
            ExecutableDevelopmentCoverageV3ToV4MigrationError
        ):
            validate_executable_development_coverage_v3_to_v4_migration(
                hostile_migration
            )

    def test_cached_bytes_yield_fresh_unpoisonable_objects(self) -> None:
        self.assertIs(
            executable_development_coverage_v4_config_bytes(),
            executable_development_coverage_v4_config_bytes(),
        )
        self.assertIs(
            executable_development_coverage_v3_to_v4_migration_config_bytes(),
            executable_development_coverage_v3_to_v4_migration_config_bytes(),
        )
        victim = build_executable_development_coverage_v4()
        object.__setattr__(
            victim.families[0],
            "filesystem_schema",
            "poisoned-schema",
        )
        object.__setattr__(
            victim.promotion_history[-1],
            "source_tranche_id",
            "poisoned-tranche",
        )
        rebuilt = build_executable_development_coverage_v4()
        self.assertEqual(rebuilt, self.coverage)
        self.assertIsNot(rebuilt.families[0], victim.families[0])
        self.assertIsNot(
            rebuilt.promotion_history[-1],
            victim.promotion_history[-1],
        )
        with self.assertRaises(ExecutableDevelopmentCoverageV4Error):
            validate_executable_development_coverage_v4(victim)

        migration_victim = (
            build_executable_development_coverage_v3_to_v4_migration()
        )
        object.__setattr__(
            migration_victim.new_source_registry_commitment,
            "tranche_id",
            "poisoned-tranche",
        )
        migration_rebuilt = (
            build_executable_development_coverage_v3_to_v4_migration()
        )
        self.assertEqual(migration_rebuilt, self.migration)
        self.assertIsNot(
            migration_rebuilt.new_source_registry_commitment,
            migration_victim.new_source_registry_commitment,
        )
        with self.assertRaises(
            ExecutableDevelopmentCoverageV3ToV4MigrationError
        ):
            validate_executable_development_coverage_v3_to_v4_migration(
                migration_victim
            )

    def test_loaders_reject_noncanonical_duplicate_and_symlink_inputs(
        self,
    ) -> None:
        loaders = (
            (
                "v4",
                self.v4_bytes,
                load_executable_development_coverage_v4,
                ExecutableDevelopmentCoverageV4Error,
                V4_CONFIG,
            ),
            (
                "migration",
                self.migration_bytes,
                load_executable_development_coverage_v3_to_v4_migration,
                ExecutableDevelopmentCoverageV3ToV4MigrationError,
                MIGRATION_CONFIG,
            ),
        )
        for label, payload, loader, error_type, target in loaders:
            with self.subTest(loader=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                noncanonical = root / "noncanonical.json"
                noncanonical.write_text(
                    json.dumps(json.loads(payload), indent=2) + "\n",
                    encoding="utf-8",
                )
                with self.assertRaises(error_type):
                    loader(noncanonical)

                duplicate = root / "duplicate.json"
                duplicate.write_bytes(
                    b'{"schema_version":"1.0.0",'
                    b'"schema_version":"1.0.0"}\n'
                )
                with self.assertRaises(error_type):
                    loader(duplicate)

                symlink = root / "artifact-link.json"
                symlink.symlink_to(target)
                with self.assertRaises(error_type):
                    loader(symlink)

        with self.assertRaises(ExecutableDevelopmentCoverageV4Error):
            load_executable_development_coverage_v4(Path("bad\0path"))
        with self.assertRaises(
            ExecutableDevelopmentCoverageV3ToV4MigrationError
        ):
            load_executable_development_coverage_v3_to_v4_migration(
                Path("bad\0path")
            )

    def test_loaders_require_published_file_shape(self) -> None:
        loaders = (
            (
                self.v4_bytes,
                load_executable_development_coverage_v4,
                ExecutableDevelopmentCoverageV4Error,
            ),
            (
                self.migration_bytes,
                load_executable_development_coverage_v3_to_v4_migration,
                ExecutableDevelopmentCoverageV3ToV4MigrationError,
            ),
        )
        for payload, loader, error_type in loaders:
            with tempfile.TemporaryDirectory() as directory:
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
                self.v4_bytes,
                load_executable_development_coverage_v4,
                ExecutableDevelopmentCoverageV4Error,
            ),
            (
                self.migration_bytes,
                load_executable_development_coverage_v3_to_v4_migration,
                ExecutableDevelopmentCoverageV3ToV4MigrationError,
            ),
        )
        for payload, loader, error_type in loaders:
            with tempfile.TemporaryDirectory() as directory:
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
                / "executable-method-development-coverage-v4.schema.json",
                ROOT
                / "src/cbds/schemas/"
                "executable-method-development-coverage-v4.schema.json",
                json.loads(self.v4_bytes),
            ),
            (
                ROOT
                / "executable-method-development-coverage-v3-to-v4-"
                "migration.schema.json",
                ROOT
                / "src/cbds/schemas/"
                "executable-method-development-coverage-v3-to-v4-"
                "migration.schema.json",
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
            coverage_schema = json.loads(pairs[0][0].read_bytes())
            missing_archive = copy.deepcopy(pairs[0][2])
            missing_archive["promotion_history"] = (
                missing_archive["promotion_history"][1:]
            )
            self.assertTrue(
                list(
                    Draft202012Validator(
                        coverage_schema
                    ).iter_errors(missing_archive)
                )
            )
            migration_schema = json.loads(pairs[1][0].read_bytes())
            bad_contract = copy.deepcopy(pairs[1][2])
            bad_contract["preserved_allowed_tools"] = ["sha256sum"]
            self.assertTrue(
                list(
                    Draft202012Validator(
                        migration_schema
                    ).iter_errors(bad_contract)
                )
            )

    def test_build_script_check_mode(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(
                    ROOT
                    / "scripts/build_executable_development_coverage_v4.py"
                ),
                "--check",
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            completed.returncode,
            0,
            msg=completed.stdout + completed.stderr,
        )


if __name__ == "__main__":
    unittest.main()
