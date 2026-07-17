from __future__ import annotations

import ast
import copy
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.executable_development_coverage_v4 import (  # noqa: E402
    build_executable_development_coverage_v4,
)
from cbds.executable_development_coverage_v4_to_v5_migration import (  # noqa: E402
    COVERAGE_V4_TO_V5_MIGRATION_CONFIG_RELATIVE_PATH,
    FROZEN_V4_JSONL_CSV_FAMILY_SHA256,
    FROZEN_V5_JSONL_CSV_FAMILY_SHA256,
    MIGRATION_REASON_CODES,
    ExecutableDevelopmentCoverageV4ToV5MigrationError,
    build_executable_development_coverage_v4_to_v5_migration,
    executable_development_coverage_v4_to_v5_migration_config_bytes,
    load_executable_development_coverage_v4_to_v5_migration,
    validate_executable_development_coverage_v4_to_v5_migration,
)
from cbds.executable_development_coverage_v5 import (  # noqa: E402
    CANONICAL_FAMILY_ORDER,
    COVERAGE_V5_CONFIG_RELATIVE_PATH,
    FROZEN_JSONL_CSV_DISCRIMINATION_SHA256,
    FROZEN_JSONL_CSV_TASK_SET_SHA256,
    FROZEN_TWELFTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_TWELFTH_REGISTRY_SHA256,
    JSONL_CSV_FAMILY_INDEX,
    NEXT_PLANNED_FAMILY_ID,
    PREDECESSOR_CONFIG_BYTE_COUNT,
    PREDECESSOR_CONFIG_BYTES_SHA256,
    PREDECESSOR_COVERAGE_SHA256,
    PREDECESSOR_GIT_COMMIT,
    CoveragePromotionEvidence,
    ExecutableDevelopmentCoverageV5Error,
    build_executable_development_coverage_v5,
    executable_development_coverage_v5_config_bytes,
    load_executable_development_coverage_v5,
    validate_executable_development_coverage_v5,
)
from cbds.hash_only_report_publication import (  # noqa: E402
    HashOnlyReportPublicationError,
)


V4_CONFIG = ROOT / "configs/executable-method-development-coverage-v4.json"
V5_CONFIG = ROOT / COVERAGE_V5_CONFIG_RELATIVE_PATH
MIGRATION_CONFIG = (
    ROOT / COVERAGE_V4_TO_V5_MIGRATION_CONFIG_RELATIVE_PATH
)
EXPECTED_COVERAGE_SHA256 = (
    "e5987525654e384c2696908bf147e8224ad3bdc1fb2e0bbc3856a4f23cdca8b9"
)
EXPECTED_COVERAGE_BYTES_SHA256 = (
    "cfb91bef706fc1c4fd4f95d7891f42e3ec058bbaba28997a22a0f72614d6268f"
)
EXPECTED_COVERAGE_BYTE_COUNT = 25_241
EXPECTED_MIGRATION_SHA256 = (
    "7119bbf14ae74047a555483fc7e6e3a9d74ce46cdcb741a13aa5da34a66e1cea"
)
EXPECTED_MIGRATION_BYTES_SHA256 = (
    "f1d4566d17c7b51b3649000f896272ca56ec2f6d32fe5563aa4751c4a6fa563f"
)
EXPECTED_MIGRATION_BYTE_COUNT = 5_052


class ExecutableDevelopmentCoverageV5Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.v4 = build_executable_development_coverage_v4()
        cls.v5 = build_executable_development_coverage_v5()
        cls.migration = (
            build_executable_development_coverage_v4_to_v5_migration()
        )
        cls.v5_bytes = executable_development_coverage_v5_config_bytes()
        cls.migration_bytes = (
            executable_development_coverage_v4_to_v5_migration_config_bytes()
        )

    def test_exact_canonical_artifact_identities(self) -> None:
        self.assertEqual(
            self.v5.coverage_sha256, EXPECTED_COVERAGE_SHA256
        )
        self.assertEqual(len(self.v5_bytes), EXPECTED_COVERAGE_BYTE_COUNT)
        self.assertEqual(
            sha256(self.v5_bytes).hexdigest(),
            EXPECTED_COVERAGE_BYTES_SHA256,
        )
        self.assertEqual(V5_CONFIG.read_bytes(), self.v5_bytes)
        self.assertEqual(
            load_executable_development_coverage_v5(V5_CONFIG), self.v5
        )
        self.assertEqual(
            self.migration.migration_sha256,
            EXPECTED_MIGRATION_SHA256,
        )
        self.assertEqual(
            len(self.migration_bytes), EXPECTED_MIGRATION_BYTE_COUNT
        )
        self.assertEqual(
            sha256(self.migration_bytes).hexdigest(),
            EXPECTED_MIGRATION_BYTES_SHA256,
        )
        self.assertEqual(
            MIGRATION_CONFIG.read_bytes(), self.migration_bytes
        )
        self.assertEqual(
            load_executable_development_coverage_v4_to_v5_migration(
                MIGRATION_CONFIG
            ),
            self.migration,
        )

    def test_predecessor_bytes_and_creation_commit_are_exact(self) -> None:
        payload = V4_CONFIG.read_bytes()
        self.assertEqual(len(payload), PREDECESSOR_CONFIG_BYTE_COUNT)
        self.assertEqual(
            sha256(payload).hexdigest(),
            PREDECESSOR_CONFIG_BYTES_SHA256,
        )
        predecessor = self.v5.predecessor
        self.assertEqual(
            predecessor.coverage_sha256, PREDECESSOR_COVERAGE_SHA256
        )
        self.assertEqual(
            predecessor.config_bytes_sha256,
            PREDECESSOR_CONFIG_BYTES_SHA256,
        )
        self.assertEqual(predecessor.git_commit, PREDECESSOR_GIT_COMMIT)
        self.assertEqual(
            PREDECESSOR_CONFIG_BYTES_SHA256,
            "d003a5748da855257aa93e0c6e1b7a4be2de393ec5faa0dcb32d74156f40b3d7",
        )

    def test_exact_21_integrated_4_planned_partition(self) -> None:
        self.assertEqual(len(self.v5.families), 25)
        self.assertEqual(
            tuple(item.family_id for item in self.v5.families),
            CANONICAL_FAMILY_ORDER,
        )
        self.assertEqual(
            tuple(item.lifecycle_state for item in self.v5.families),
            ("integrated",) * 21 + ("planned",) * 4,
        )
        self.assertEqual(
            self.v5.families[21].family_id, NEXT_PLANNED_FAMILY_ID
        )
        self.assertEqual(
            sum(item.task_count for item in self.v5.families), 500
        )
        self.assertEqual(
            tuple(
                item.cumulative_task_count
                for item in self.v5.source_registry_commitments
            ),
            (100, 200, 240, 260, 280, 300, 320, 340, 360, 380, 400, 420),
        )

    def test_source_and_history_are_exact_append_only_extensions(self) -> None:
        self.assertEqual(
            self.v5.source_registry_commitments[:-1],
            self.v4.source_registry_commitments,
        )
        twelfth = self.v5.source_registry_commitments[-1]
        self.assertEqual(twelfth.tranche_id, "twelfth-tranche")
        self.assertEqual(twelfth.added_task_count, 20)
        self.assertEqual(
            twelfth.registry_sha256, FROZEN_TWELFTH_REGISTRY_SHA256
        )
        self.assertEqual(
            twelfth.cumulative_suite_sha256,
            FROZEN_TWELFTH_CUMULATIVE_SUITE_SHA256,
        )
        self.assertEqual(
            tuple(item.to_record() for item in self.v5.promotion_history[:-1]),
            tuple(item.to_record() for item in self.v4.promotion_history),
        )
        self.assertTrue(
            all(
                type(item) is CoveragePromotionEvidence
                for item in self.v5.promotion_history
            )
        )
        promotion = self.v5.promotion_history[-1]
        self.assertEqual(
            promotion.family_id, "jsonl-csv-enrichment-compose"
        )
        self.assertEqual(promotion.source_tranche_id, "twelfth-tranche")
        self.assertEqual(
            promotion.task_set_sha256, FROZEN_JSONL_CSV_TASK_SET_SHA256
        )
        self.assertEqual(
            promotion.discrimination_sha256,
            FROZEN_JSONL_CSV_DISCRIMINATION_SHA256,
        )

    def test_migration_changes_only_one_family_and_preserves_contract(
        self,
    ) -> None:
        old = self.v4.families[JSONL_CSV_FAMILY_INDEX]
        new = self.v5.families[JSONL_CSV_FAMILY_INDEX]
        self.assertEqual(
            old.family_sha256, FROZEN_V4_JSONL_CSV_FAMILY_SHA256
        )
        self.assertEqual(
            new.family_sha256, FROZEN_V5_JSONL_CSV_FAMILY_SHA256
        )
        self.assertEqual(old.lifecycle_state, "planned")
        self.assertEqual(new.lifecycle_state, "integrated")
        self.assertIsNone(old.integrated_task_set_sha256)
        self.assertEqual(
            new.integrated_task_set_sha256,
            FROZEN_JSONL_CSV_TASK_SET_SHA256,
        )
        for attribute in (
            "parameter_axes",
            "solution_track",
            "allowed_tools",
            "filesystem_schema",
            "output_contract",
            "capability_tags",
        ):
            self.assertEqual(
                getattr(old, attribute), getattr(new, attribute)
            )
        changed = []
        for index, (before, after) in enumerate(
            zip(self.v4.families, self.v5.families, strict=True)
        ):
            if before != after:
                changed.append(index)
        self.assertEqual(changed, [JSONL_CSV_FAMILY_INDEX])
        self.assertEqual(
            self.migration.unchanged_family_sha256,
            tuple(
                item.family_sha256
                for index, item in enumerate(self.v4.families)
                if index != JSONL_CSV_FAMILY_INDEX
            ),
        )

    def test_migration_binds_all_append_only_evidence(self) -> None:
        record = self.migration.to_hash_only_record()
        self.assertEqual(record["changed_family_count"], 1)
        self.assertEqual(record["unchanged_family_count"], 24)
        self.assertEqual(tuple(record["reason_codes"]), MIGRATION_REASON_CODES)
        self.assertEqual(
            self.migration.preserved_promotion_history,
            self.v5.promotion_history[:-1],
        )
        self.assertEqual(
            self.migration.promotion_evidence,
            self.v5.promotion_history[-1],
        )
        self.assertEqual(
            self.migration.new_source_registry_commitment,
            self.v5.source_registry_commitments[-1],
        )
        self.assertEqual(
            len(set(self.migration.unchanged_family_sha256)), 24
        )

    def test_authority_history_and_family_mutations_fail_closed(self) -> None:
        hostile = copy.copy(self.v5)
        object.__setattr__(hostile, "sealed", True)
        with self.assertRaises(ExecutableDevelopmentCoverageV5Error):
            validate_executable_development_coverage_v5(hostile)
        reordered = copy.copy(self.v5)
        object.__setattr__(
            reordered,
            "promotion_history",
            tuple(reversed(self.v5.promotion_history)),
        )
        with self.assertRaises(ExecutableDevelopmentCoverageV5Error):
            validate_executable_development_coverage_v5(reordered)
        wrong_family = copy.copy(self.v5)
        families = list(self.v5.families)
        families[0], families[1] = families[1], families[0]
        object.__setattr__(wrong_family, "families", tuple(families))
        with self.assertRaises(ExecutableDevelopmentCoverageV5Error):
            validate_executable_development_coverage_v5(wrong_family)
        hostile_migration = copy.copy(self.migration)
        object.__setattr__(hostile_migration, "claim_authorized", True)
        with self.assertRaises(
            ExecutableDevelopmentCoverageV4ToV5MigrationError
        ):
            validate_executable_development_coverage_v4_to_v5_migration(
                hostile_migration
            )

    def test_cached_bytes_return_fresh_unpoisonable_objects(self) -> None:
        self.assertIs(
            executable_development_coverage_v5_config_bytes(),
            executable_development_coverage_v5_config_bytes(),
        )
        victim = build_executable_development_coverage_v5()
        object.__setattr__(
            victim.families[0], "filesystem_schema", "poisoned-schema"
        )
        object.__setattr__(
            victim.promotion_history[-1],
            "source_tranche_id",
            "poisoned-tranche",
        )
        rebuilt = build_executable_development_coverage_v5()
        self.assertEqual(rebuilt, self.v5)
        self.assertIsNot(rebuilt.families[0], victim.families[0])
        self.assertIsNot(
            rebuilt.promotion_history[-1],
            victim.promotion_history[-1],
        )
        with self.assertRaises(ExecutableDevelopmentCoverageV5Error):
            validate_executable_development_coverage_v5(victim)
        migration_victim = (
            build_executable_development_coverage_v4_to_v5_migration()
        )
        object.__setattr__(
            migration_victim.new_source_registry_commitment,
            "tranche_id",
            "poisoned-tranche",
        )
        migration_rebuilt = (
            build_executable_development_coverage_v4_to_v5_migration()
        )
        self.assertEqual(migration_rebuilt, self.migration)
        self.assertIsNot(
            migration_rebuilt.new_source_registry_commitment,
            migration_victim.new_source_registry_commitment,
        )

    def test_loaders_reject_noncanonical_duplicate_and_nonfinite_json(
        self,
    ) -> None:
        loaders = (
            (
                self.v5_bytes,
                load_executable_development_coverage_v5,
                ExecutableDevelopmentCoverageV5Error,
            ),
            (
                self.migration_bytes,
                load_executable_development_coverage_v4_to_v5_migration,
                ExecutableDevelopmentCoverageV4ToV5MigrationError,
            ),
        )
        for payload, loader, error_type in loaders:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                noncanonical = root / "noncanonical.json"
                noncanonical.write_text(
                    json.dumps(json.loads(payload), indent=2) + "\n",
                    encoding="utf-8",
                )
                noncanonical.chmod(0o644)
                with self.assertRaises(error_type):
                    loader(noncanonical)
                duplicate = root / "duplicate.json"
                duplicate.write_bytes(
                    b'{"schema_version":"1.0.0",'
                    b'"schema_version":"1.0.0"}\n'
                )
                duplicate.chmod(0o644)
                with self.assertRaises(error_type):
                    loader(duplicate)
                nonfinite = root / "nonfinite.json"
                nonfinite.write_bytes(b'{"value":NaN}\n')
                nonfinite.chmod(0o644)
                with self.assertRaises(error_type):
                    loader(nonfinite)

    def test_loaders_require_hardened_regular_files(self) -> None:
        loaders = (
            (
                self.v5_bytes,
                load_executable_development_coverage_v5,
                ExecutableDevelopmentCoverageV5Error,
            ),
            (
                self.migration_bytes,
                load_executable_development_coverage_v4_to_v5_migration,
                ExecutableDevelopmentCoverageV4ToV5MigrationError,
            ),
        )
        for payload, loader, error_type in loaders:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                anchor = root / "anchor.json"
                anchor.write_bytes(payload)
                anchor.chmod(0o644)
                linked = root / "linked.json"
                os.link(anchor, linked)
                with self.assertRaises(error_type):
                    loader(linked)
                symlink = root / "symlink.json"
                symlink.symlink_to(anchor)
                with self.assertRaises(error_type):
                    loader(symlink)
                wrong_mode = root / "wrong-mode.json"
                wrong_mode.write_bytes(payload)
                wrong_mode.chmod(0o600)
                with self.assertRaises(error_type):
                    loader(wrong_mode)
                directory_path = root / "directory"
                directory_path.mkdir()
                with self.assertRaises(error_type):
                    loader(directory_path)
        with self.assertRaises(ExecutableDevelopmentCoverageV5Error):
            load_executable_development_coverage_v5(Path("bad\0path"))

    def test_root_and_packaged_schemas_match_and_validate(self) -> None:
        pairs = (
            (
                ROOT
                / "executable-method-development-coverage-v5.schema.json",
                ROOT
                / "src/cbds/schemas/"
                "executable-method-development-coverage-v5.schema.json",
                json.loads(self.v5_bytes),
            ),
            (
                ROOT
                / "executable-method-development-coverage-v4-to-v5-"
                "migration.schema.json",
                ROOT
                / "src/cbds/schemas/"
                "executable-method-development-coverage-v4-to-v5-"
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
            bad_coverage = copy.deepcopy(pairs[0][2])
            bad_coverage["integrated_task_count"] = 400
            self.assertTrue(
                list(
                    Draft202012Validator(
                        coverage_schema
                    ).iter_errors(bad_coverage)
                )
            )
            migration_schema = json.loads(pairs[1][0].read_bytes())
            bad_migration = copy.deepcopy(pairs[1][2])
            bad_migration["preserved_allowed_tools"] = ["jq"]
            self.assertTrue(
                list(
                    Draft202012Validator(
                        migration_schema
                    ).iter_errors(bad_migration)
                )
            )

    def test_publication_builder_is_no_replace_and_checkable(self) -> None:
        script = (
            ROOT / "scripts/build_executable_development_coverage_v5.py"
        )
        spec = importlib.util.spec_from_file_location(
            "_cbds_coverage_v5_builder", script
        )
        if spec is None or spec.loader is None:
            self.fail("coverage-v5 builder module could not be loaded")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            coverage = root / "coverage.json"
            migration = root / "migration.json"
            arguments = [
                "--coverage-output",
                str(coverage),
                "--migration-output",
                str(migration),
            ]
            self.assertEqual(module.main(arguments), 0)
            self.assertEqual(coverage.read_bytes(), self.v5_bytes)
            self.assertEqual(migration.read_bytes(), self.migration_bytes)
            self.assertEqual(module.main(arguments), 0)
            coverage.write_bytes(b"different-existing-artifact\n")
            coverage.chmod(0o644)
            with self.assertRaises(HashOnlyReportPublicationError):
                module.main(arguments)
            self.assertEqual(
                coverage.read_bytes(), b"different-existing-artifact\n"
            )
            coverage.write_bytes(self.v5_bytes)
            coverage.chmod(0o644)
            self.assertEqual(module.main([*arguments, "--check"]), 0)

    def test_checked_files_and_source_have_hardened_shape(self) -> None:
        for path in (V5_CONFIG, MIGRATION_CONFIG):
            metadata = path.stat()
            self.assertTrue(stat.S_ISREG(metadata.st_mode))
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o644)
            self.assertEqual(metadata.st_nlink, 1)
        script = (
            ROOT / "scripts/build_executable_development_coverage_v5.py"
        )
        self.assertEqual(stat.S_IMODE(script.stat().st_mode), 0o755)

        for relative in (
            "src/cbds/executable_development_coverage_v5.py",
            "src/cbds/executable_development_coverage_v4_to_v5_migration.py",
        ):
            tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Dict):
                    continue
                keys = [
                    key.value
                    for key in node.keys
                    if isinstance(key, ast.Constant)
                    and isinstance(key.value, str)
                ]
                self.assertEqual(
                    len(keys),
                    len(set(keys)),
                    msg=f"duplicate literal dict key in {relative}",
                )


if __name__ == "__main__":
    unittest.main()
