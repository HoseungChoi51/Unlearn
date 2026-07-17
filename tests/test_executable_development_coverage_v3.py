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
from cbds.executable_development_coverage_v2 import (  # noqa: E402
    FROZEN_HARDLINK_DISCRIMINATION_SHA256,
    build_executable_development_coverage_v2,
)
from cbds.executable_development_coverage_v2_to_v3_migration import (  # noqa: E402
    COVERAGE_V2_TO_V3_MIGRATION_CONFIG_RELATIVE_PATH,
    FROZEN_V2_ARCHIVE_FAMILY_SHA256,
    FROZEN_V3_ARCHIVE_FAMILY_SHA256,
    MIGRATION_REASON_CODES,
    ExecutableDevelopmentCoverageV2ToV3MigrationError,
    build_executable_development_coverage_v2_to_v3_migration,
    executable_development_coverage_v2_to_v3_migration_config_bytes,
    load_executable_development_coverage_v2_to_v3_migration,
    validate_executable_development_coverage_v2_to_v3_migration,
)
from cbds.executable_development_coverage_v3 import (  # noqa: E402
    ARCHIVE_FAMILY_INDEX,
    CANONICAL_FAMILY_ORDER,
    COVERAGE_V3_CONFIG_RELATIVE_PATH,
    FROZEN_ARCHIVE_DISCRIMINATION_SHA256,
    FROZEN_ARCHIVE_TASK_SET_SHA256,
    FROZEN_TENTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_TENTH_REGISTRY_SHA256,
    PREDECESSOR_CONFIG_BYTE_COUNT,
    PREDECESSOR_CONFIG_BYTES_SHA256,
    PREDECESSOR_COVERAGE_SHA256,
    PREDECESSOR_GIT_COMMIT,
    CoveragePromotionEvidence,
    ExecutableDevelopmentCoverageV3Error,
    build_executable_development_coverage_v3,
    executable_development_coverage_v3_config_bytes,
    load_executable_development_coverage_v3,
    validate_executable_development_coverage_v3,
)


V2_CONFIG = ROOT / "configs/executable-method-development-coverage-v2.json"
V3_CONFIG = ROOT / COVERAGE_V3_CONFIG_RELATIVE_PATH
MIGRATION_CONFIG = (
    ROOT / COVERAGE_V2_TO_V3_MIGRATION_CONFIG_RELATIVE_PATH
)
EXPECTED_V3_COVERAGE_SHA256 = (
    "b37f48c98e7216c78ddf74d0ce6f6d74cd095575f20f53de6bf30018b2180d79"
)
EXPECTED_V3_CONFIG_BYTES_SHA256 = (
    "de241ad1e4536fa595f99acf0ef05a3e423418876298c576abe87249c018bc0a"
)
EXPECTED_V3_CONFIG_BYTE_COUNT = 23_943
EXPECTED_MIGRATION_SHA256 = (
    "8e36252576376d86ddb0a4f3b399dfdd66377b0ed026369bbf799edf104818a2"
)
EXPECTED_MIGRATION_CONFIG_BYTES_SHA256 = (
    "77820327bc105d367d8d737c110e53e8183ce786650ecb4c1699991412cb6683"
)
EXPECTED_MIGRATION_CONFIG_BYTE_COUNT = 4_358


class ExecutableDevelopmentCoverageV3Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.v2 = build_executable_development_coverage_v2()
        cls.coverage = build_executable_development_coverage_v3()
        cls.migration = (
            build_executable_development_coverage_v2_to_v3_migration()
        )
        cls.v3_bytes = executable_development_coverage_v3_config_bytes()
        cls.migration_bytes = (
            executable_development_coverage_v2_to_v3_migration_config_bytes()
        )

    def test_v3_artifact_is_exact_deterministic_projection(self) -> None:
        self.assertEqual(
            self.coverage.coverage_sha256,
            EXPECTED_V3_COVERAGE_SHA256,
        )
        self.assertEqual(
            len(self.v3_bytes), EXPECTED_V3_CONFIG_BYTE_COUNT
        )
        self.assertEqual(
            sha256(self.v3_bytes).hexdigest(),
            EXPECTED_V3_CONFIG_BYTES_SHA256,
        )
        self.assertEqual(V3_CONFIG.read_bytes(), self.v3_bytes)
        self.assertEqual(
            load_executable_development_coverage_v3(V3_CONFIG),
            self.coverage,
        )
        self.assertEqual(
            build_executable_development_coverage_v3(), self.coverage
        )

    def test_v2_bytes_are_preserved_and_v3_is_backward_linked(
        self,
    ) -> None:
        v2_bytes = V2_CONFIG.read_bytes()
        self.assertEqual(len(v2_bytes), PREDECESSOR_CONFIG_BYTE_COUNT)
        self.assertEqual(
            sha256(v2_bytes).hexdigest(),
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

    def test_exact_19_integrated_6_planned_partition(self) -> None:
        families = self.coverage.families
        self.assertEqual(len(families), 25)
        self.assertEqual(
            tuple(family.family_id for family in families),
            CANONICAL_FAMILY_ORDER,
        )
        self.assertEqual(
            tuple(family.lifecycle_state for family in families),
            ("integrated",) * 19 + ("planned",) * 6,
        )
        self.assertEqual(sum(family.task_count for family in families), 500)
        self.assertEqual(
            tuple(
                source.cumulative_task_count
                for source in self.coverage.source_registry_commitments
            ),
            (100, 200, 240, 260, 280, 300, 320, 340, 360, 380),
        )
        tenth = self.coverage.source_registry_commitments[-1]
        self.assertEqual(tenth.tranche_id, "tenth-tranche")
        self.assertEqual(tenth.added_task_count, 20)
        self.assertEqual(
            tenth.registry_sha256, FROZEN_TENTH_REGISTRY_SHA256
        )
        self.assertEqual(
            tenth.cumulative_suite_sha256,
            FROZEN_TENTH_CUMULATIVE_SUITE_SHA256,
        )

    def test_generic_promotion_evidence_binds_transition_and_source(
        self,
    ) -> None:
        evidence = self.coverage.promotion_evidence
        self.assertIs(type(evidence), CoveragePromotionEvidence)
        self.assertEqual(
            evidence.family_id,
            "compressed-archive-roundtrip-verify",
        )
        self.assertEqual(evidence.old_lifecycle_state, "planned")
        self.assertEqual(evidence.new_lifecycle_state, "integrated")
        self.assertEqual(evidence.source_tranche_id, "tenth-tranche")
        self.assertEqual(
            evidence.task_set_sha256,
            FROZEN_ARCHIVE_TASK_SET_SHA256,
        )
        self.assertEqual(
            evidence.discrimination_sha256,
            FROZEN_ARCHIVE_DISCRIMINATION_SHA256,
        )
        archive = self.coverage.families[ARCHIVE_FAMILY_INDEX]
        self.assertEqual(
            archive.integrated_task_set_sha256,
            evidence.task_set_sha256,
        )
        self.assertEqual(
            self.coverage.hardlink_discrimination_sha256,
            FROZEN_HARDLINK_DISCRIMINATION_SHA256,
        )

    def test_migration_changes_only_archive_and_preserves_contract(
        self,
    ) -> None:
        old = self.v2.families[ARCHIVE_FAMILY_INDEX]
        new = self.coverage.families[ARCHIVE_FAMILY_INDEX]
        self.assertEqual(old.lifecycle_state, "planned")
        self.assertEqual(new.lifecycle_state, "integrated")
        self.assertEqual(
            old.family_sha256, FROZEN_V2_ARCHIVE_FAMILY_SHA256
        )
        self.assertEqual(
            new.family_sha256, FROZEN_V3_ARCHIVE_FAMILY_SHA256
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
            FROZEN_ARCHIVE_TASK_SET_SHA256,
        )
        for index, (before, after) in enumerate(
            zip(self.v2.families, self.coverage.families, strict=True)
        ):
            if index == ARCHIVE_FAMILY_INDEX:
                self.assertNotEqual(before, after)
            else:
                self.assertEqual(before, after)
        self.assertEqual(
            self.coverage.source_registry_commitments[:-1],
            self.v2.source_registry_commitments,
        )

    def test_migration_artifact_proves_exact_invariance(self) -> None:
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
            self.migration.preserved_parameter_axes,
            self.v2.families[ARCHIVE_FAMILY_INDEX].parameter_axes,
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
            load_executable_development_coverage_v2_to_v3_migration(
                MIGRATION_CONFIG
            ),
            self.migration,
        )

    def test_authority_and_evidence_mutations_fail_closed(self) -> None:
        hostile = copy.copy(self.coverage)
        object.__setattr__(hostile, "sealed", True)
        with self.assertRaises(ExecutableDevelopmentCoverageV3Error):
            validate_executable_development_coverage_v3(hostile)

        wrong_promotion = copy.copy(self.coverage)
        poisoned_evidence = copy.copy(
            self.coverage.promotion_evidence
        )
        object.__setattr__(
            poisoned_evidence,
            "source_tranche_id",
            "ninth-tranche",
        )
        object.__setattr__(
            wrong_promotion,
            "promotion_evidence",
            poisoned_evidence,
        )
        with self.assertRaises(ExecutableDevelopmentCoverageV3Error):
            validate_executable_development_coverage_v3(
                wrong_promotion
            )

        hostile_migration = copy.copy(self.migration)
        object.__setattr__(
            hostile_migration,
            "claim_authorized",
            True,
        )
        with self.assertRaises(
            ExecutableDevelopmentCoverageV2ToV3MigrationError
        ):
            validate_executable_development_coverage_v2_to_v3_migration(
                hostile_migration
            )

    def test_cached_evidence_returns_fresh_unpoisonable_objects(
        self,
    ) -> None:
        victim = build_executable_development_coverage_v3()
        object.__setattr__(
            victim.families[0],
            "filesystem_schema",
            "poisoned-schema",
        )
        object.__setattr__(
            victim.promotion_evidence,
            "source_tranche_id",
            "poisoned-tranche",
        )
        rebuilt = build_executable_development_coverage_v3()
        self.assertEqual(rebuilt, self.coverage)
        self.assertIsNot(rebuilt.families[0], victim.families[0])
        self.assertIsNot(
            rebuilt.promotion_evidence,
            victim.promotion_evidence,
        )
        with self.assertRaises(ExecutableDevelopmentCoverageV3Error):
            validate_executable_development_coverage_v3(victim)

        migration_victim = (
            build_executable_development_coverage_v2_to_v3_migration()
        )
        object.__setattr__(
            migration_victim.new_source_registry_commitment,
            "tranche_id",
            "poisoned-tranche",
        )
        migration_rebuilt = (
            build_executable_development_coverage_v2_to_v3_migration()
        )
        self.assertEqual(migration_rebuilt, self.migration)
        self.assertIsNot(
            migration_rebuilt.new_source_registry_commitment,
            migration_victim.new_source_registry_commitment,
        )
        with self.assertRaises(
            ExecutableDevelopmentCoverageV2ToV3MigrationError
        ):
            validate_executable_development_coverage_v2_to_v3_migration(
                migration_victim
            )

    def test_loaders_reject_noncanonical_duplicate_and_symlink_inputs(
        self,
    ) -> None:
        loaders = (
            (
                "v3",
                self.v3_bytes,
                load_executable_development_coverage_v3,
                ExecutableDevelopmentCoverageV3Error,
            ),
            (
                "migration",
                self.migration_bytes,
                load_executable_development_coverage_v2_to_v3_migration,
                ExecutableDevelopmentCoverageV2ToV3MigrationError,
            ),
        )
        for label, payload, loader, error_type in loaders:
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
                target = V3_CONFIG if label == "v3" else MIGRATION_CONFIG
                symlink.symlink_to(target)
                with self.assertRaises(error_type):
                    loader(symlink)

        with self.assertRaises(ExecutableDevelopmentCoverageV3Error):
            load_executable_development_coverage_v3(Path("bad\0path"))
        with self.assertRaises(
            ExecutableDevelopmentCoverageV2ToV3MigrationError
        ):
            load_executable_development_coverage_v2_to_v3_migration(
                Path("bad\0path")
            )

    def test_loaders_require_published_file_shape(self) -> None:
        loaders = (
            (
                self.v3_bytes,
                load_executable_development_coverage_v3,
                ExecutableDevelopmentCoverageV3Error,
            ),
            (
                self.migration_bytes,
                load_executable_development_coverage_v2_to_v3_migration,
                ExecutableDevelopmentCoverageV2ToV3MigrationError,
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
                self.v3_bytes,
                load_executable_development_coverage_v3,
                ExecutableDevelopmentCoverageV3Error,
            ),
            (
                self.migration_bytes,
                load_executable_development_coverage_v2_to_v3_migration,
                ExecutableDevelopmentCoverageV2ToV3MigrationError,
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
                / "executable-method-development-coverage-v3.schema.json",
                ROOT
                / "src/cbds/schemas/"
                "executable-method-development-coverage-v3.schema.json",
                json.loads(self.v3_bytes),
            ),
            (
                ROOT
                / "executable-method-development-coverage-v2-to-v3-"
                "migration.schema.json",
                ROOT
                / "src/cbds/schemas/"
                "executable-method-development-coverage-v2-to-v3-"
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
            bad_promotion = copy.deepcopy(pairs[0][2])
            bad_promotion["promotion_evidence"][
                "source_tranche_id"
            ] = "ninth-tranche"
            self.assertTrue(
                list(
                    Draft202012Validator(
                        coverage_schema
                    ).iter_errors(bad_promotion)
                )
            )
            migration_schema = json.loads(pairs[1][0].read_bytes())
            bad_contract = copy.deepcopy(pairs[1][2])
            bad_contract["preserved_allowed_tools"] = ["tar"]
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
                    / "scripts/build_executable_development_coverage_v3.py"
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
