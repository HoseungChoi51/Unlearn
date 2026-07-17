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

from cbds.executable_development_coverage_v6 import (  # noqa: E402
    build_executable_development_coverage_v6,
)
from cbds.executable_development_coverage_v6_to_v7_migration import (  # noqa: E402
    COVERAGE_V6_TO_V7_MIGRATION_CONFIG_RELATIVE_PATH,
    FROZEN_V6_DEPENDENCY_DAG_FAMILY_SHA256,
    FROZEN_V7_DEPENDENCY_DAG_FAMILY_SHA256,
    MIGRATION_REASON_CODES,
    ExecutableDevelopmentCoverageV6ToV7MigrationError,
    build_executable_development_coverage_v6_to_v7_migration,
    executable_development_coverage_v6_to_v7_migration_config_bytes,
    load_executable_development_coverage_v6_to_v7_migration,
    validate_executable_development_coverage_v6_to_v7_migration,
)
from cbds.executable_development_coverage_v7 import (  # noqa: E402
    CANONICAL_FAMILY_ORDER,
    COVERAGE_V7_CONFIG_RELATIVE_PATH,
    DEPENDENCY_DAG_FAMILY_INDEX,
    FROZEN_DEPENDENCY_DAG_DISCRIMINATION_SHA256,
    FROZEN_DEPENDENCY_DAG_TASK_SET_SHA256,
    FROZEN_FOURTEENTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_FOURTEENTH_REGISTRY_SHA256,
    NEXT_PLANNED_FAMILY_ID,
    PREDECESSOR_CONFIG_BYTE_COUNT,
    PREDECESSOR_CONFIG_BYTES_SHA256,
    PREDECESSOR_COVERAGE_SHA256,
    PREDECESSOR_GIT_COMMIT,
    CoveragePromotionEvidence,
    ExecutableDevelopmentCoverageV7Error,
    build_executable_development_coverage_v7,
    executable_development_coverage_v7_config_bytes,
    load_executable_development_coverage_v7,
    validate_executable_development_coverage_v7,
)
from cbds.executable_development_coverage import (  # noqa: E402
    CoverageFamily,
    CoverageParameterAxis,
    SourceRegistryCommitment,
)
from cbds.hash_only_report_publication import (  # noqa: E402
    HashOnlyReportPublicationError,
)


V6_CONFIG = ROOT / "configs/executable-method-development-coverage-v6.json"
V7_CONFIG = ROOT / COVERAGE_V7_CONFIG_RELATIVE_PATH
MIGRATION_CONFIG = (
    ROOT / COVERAGE_V6_TO_V7_MIGRATION_CONFIG_RELATIVE_PATH
)
EXPECTED_COVERAGE_SHA256 = (
    "177a97767a528db74951a191282f6d719a34c8a136a21086940dfbd92e5bb569"
)
EXPECTED_COVERAGE_BYTES_SHA256 = (
    "3742f632c7b5b18f8851d8ce198fe6eebd6ae6dbb1e3cf68a37633d67452f7bc"
)
EXPECTED_COVERAGE_BYTE_COUNT = 26_558
EXPECTED_MIGRATION_SHA256 = (
    "7b1822b390fae8c78bf991d0b348b7033a6d0e33e6fa2318ecdf5a0ae060bee8"
)
EXPECTED_MIGRATION_BYTES_SHA256 = (
    "ee03276d08386a52a1220bba8de4b6d25a245ab550d4c278c29cef0a1bcf2adc"
)
EXPECTED_MIGRATION_BYTE_COUNT = 5_744


class _EqualString(str):
    pass


class _EqualCoverageFamily(CoverageFamily):
    def __post_init__(self) -> None:
        pass

    def __eq__(self, other: object) -> bool:
        return isinstance(other, CoverageFamily)


class _EqualSourceRegistryCommitment(SourceRegistryCommitment):
    def __post_init__(self) -> None:
        pass

    def __eq__(self, other: object) -> bool:
        return isinstance(other, SourceRegistryCommitment)


class _EqualCoverageParameterAxis(CoverageParameterAxis):
    def __post_init__(self) -> None:
        pass

    def __eq__(self, other: object) -> bool:
        return isinstance(other, CoverageParameterAxis)


class ExecutableDevelopmentCoverageV7Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.v6 = build_executable_development_coverage_v6()
        cls.v7 = build_executable_development_coverage_v7()
        cls.migration = (
            build_executable_development_coverage_v6_to_v7_migration()
        )
        cls.v7_bytes = executable_development_coverage_v7_config_bytes()
        cls.migration_bytes = (
            executable_development_coverage_v6_to_v7_migration_config_bytes()
        )

    def test_exact_canonical_artifact_identities(self) -> None:
        self.assertEqual(
            self.v7.coverage_sha256, EXPECTED_COVERAGE_SHA256
        )
        self.assertEqual(len(self.v7_bytes), EXPECTED_COVERAGE_BYTE_COUNT)
        self.assertEqual(
            sha256(self.v7_bytes).hexdigest(),
            EXPECTED_COVERAGE_BYTES_SHA256,
        )
        self.assertEqual(V7_CONFIG.read_bytes(), self.v7_bytes)
        self.assertEqual(
            load_executable_development_coverage_v7(V7_CONFIG), self.v7
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
            load_executable_development_coverage_v6_to_v7_migration(
                MIGRATION_CONFIG
            ),
            self.migration,
        )

    def test_predecessor_bytes_and_creation_commit_are_exact(self) -> None:
        payload = V6_CONFIG.read_bytes()
        self.assertEqual(len(payload), PREDECESSOR_CONFIG_BYTE_COUNT)
        self.assertEqual(
            sha256(payload).hexdigest(),
            PREDECESSOR_CONFIG_BYTES_SHA256,
        )
        predecessor = self.v7.predecessor
        self.assertEqual(
            predecessor.coverage_sha256, PREDECESSOR_COVERAGE_SHA256
        )
        self.assertEqual(
            predecessor.config_bytes_sha256,
            PREDECESSOR_CONFIG_BYTES_SHA256,
        )
        self.assertEqual(predecessor.git_commit, PREDECESSOR_GIT_COMMIT)
        self.assertEqual(
            PREDECESSOR_GIT_COMMIT,
            "ddcbd2ed73277b06b73bd199544c3b444dbcb80e",
        )

    def test_exact_23_integrated_2_planned_partition(self) -> None:
        self.assertEqual(len(self.v7.families), 25)
        self.assertEqual(
            tuple(item.family_id for item in self.v7.families),
            CANONICAL_FAMILY_ORDER,
        )
        self.assertEqual(
            tuple(item.lifecycle_state for item in self.v7.families),
            ("integrated",) * 23 + ("planned",) * 2,
        )
        self.assertEqual(
            self.v7.families[23].family_id, NEXT_PLANNED_FAMILY_ID
        )
        self.assertEqual(
            sum(item.task_count for item in self.v7.families), 500
        )
        self.assertEqual(
            tuple(
                item.cumulative_task_count
                for item in self.v7.source_registry_commitments
            ),
            (
                100,
                200,
                240,
                260,
                280,
                300,
                320,
                340,
                360,
                380,
                400,
                420,
                440,
                460,
            ),
        )

    def test_source_and_history_are_exact_append_only_extensions(self) -> None:
        self.assertEqual(
            self.v7.source_registry_commitments[:-1],
            self.v6.source_registry_commitments,
        )
        fourteenth = self.v7.source_registry_commitments[-1]
        self.assertEqual(fourteenth.tranche_id, "fourteenth-tranche")
        self.assertEqual(fourteenth.added_task_count, 20)
        self.assertEqual(
            fourteenth.registry_sha256,
            FROZEN_FOURTEENTH_REGISTRY_SHA256,
        )
        self.assertEqual(
            fourteenth.cumulative_suite_sha256,
            FROZEN_FOURTEENTH_CUMULATIVE_SUITE_SHA256,
        )
        self.assertEqual(
            tuple(item.to_record() for item in self.v7.promotion_history[:-1]),
            tuple(item.to_record() for item in self.v6.promotion_history),
        )
        self.assertTrue(
            all(
                type(item) is CoveragePromotionEvidence
                for item in self.v7.promotion_history
            )
        )
        promotion = self.v7.promotion_history[-1]
        self.assertEqual(
            promotion.family_id, "dependency-dag-execution-plan"
        )
        self.assertEqual(
            promotion.source_tranche_id, "fourteenth-tranche"
        )
        self.assertEqual(
            promotion.task_set_sha256,
            FROZEN_DEPENDENCY_DAG_TASK_SET_SHA256,
        )
        self.assertEqual(
            promotion.discrimination_sha256,
            FROZEN_DEPENDENCY_DAG_DISCRIMINATION_SHA256,
        )

    def test_migration_changes_only_one_family_and_preserves_contract(
        self,
    ) -> None:
        old = self.v6.families[DEPENDENCY_DAG_FAMILY_INDEX]
        new = self.v7.families[DEPENDENCY_DAG_FAMILY_INDEX]
        self.assertEqual(
            old.family_sha256,
            FROZEN_V6_DEPENDENCY_DAG_FAMILY_SHA256,
        )
        self.assertEqual(
            new.family_sha256,
            FROZEN_V7_DEPENDENCY_DAG_FAMILY_SHA256,
        )
        self.assertEqual(old.lifecycle_state, "planned")
        self.assertEqual(new.lifecycle_state, "integrated")
        self.assertIsNone(old.integrated_task_set_sha256)
        self.assertEqual(
            new.integrated_task_set_sha256,
            FROZEN_DEPENDENCY_DAG_TASK_SET_SHA256,
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
        changed = [
            index
            for index, (before, after) in enumerate(
                zip(self.v6.families, self.v7.families, strict=True)
            )
            if before != after
        ]
        self.assertEqual(changed, [DEPENDENCY_DAG_FAMILY_INDEX])
        self.assertEqual(
            self.migration.unchanged_family_sha256,
            tuple(
                item.family_sha256
                for index, item in enumerate(self.v6.families)
                if index != DEPENDENCY_DAG_FAMILY_INDEX
            ),
        )

    def test_migration_binds_all_append_only_evidence(self) -> None:
        record = self.migration.to_hash_only_record()
        self.assertEqual(record["changed_family_count"], 1)
        self.assertEqual(record["unchanged_family_count"], 24)
        self.assertEqual(tuple(record["reason_codes"]), MIGRATION_REASON_CODES)
        self.assertEqual(
            self.migration.preserved_promotion_history,
            self.v7.promotion_history[:-1],
        )
        self.assertEqual(
            self.migration.promotion_evidence,
            self.v7.promotion_history[-1],
        )
        self.assertEqual(
            self.migration.new_source_registry_commitment,
            self.v7.source_registry_commitments[-1],
        )
        self.assertEqual(
            len(set(self.migration.unchanged_family_sha256)), 24
        )

    def test_authority_history_and_family_mutations_fail_closed(self) -> None:
        hostile = copy.copy(self.v7)
        object.__setattr__(hostile, "sealed", True)
        with self.assertRaises(ExecutableDevelopmentCoverageV7Error):
            validate_executable_development_coverage_v7(hostile)
        reordered = copy.copy(self.v7)
        object.__setattr__(
            reordered,
            "promotion_history",
            tuple(reversed(self.v7.promotion_history)),
        )
        with self.assertRaises(ExecutableDevelopmentCoverageV7Error):
            validate_executable_development_coverage_v7(reordered)
        wrong_family = copy.copy(self.v7)
        families = list(self.v7.families)
        families[0], families[1] = families[1], families[0]
        object.__setattr__(wrong_family, "families", tuple(families))
        with self.assertRaises(ExecutableDevelopmentCoverageV7Error):
            validate_executable_development_coverage_v7(wrong_family)
        hostile_migration = copy.copy(self.migration)
        object.__setattr__(hostile_migration, "claim_authorized", True)
        with self.assertRaises(
            ExecutableDevelopmentCoverageV6ToV7MigrationError
        ):
            validate_executable_development_coverage_v6_to_v7_migration(
                hostile_migration
            )

    def test_equal_subclasses_cannot_claim_exact_owned_evidence(self) -> None:
        for attribute in ("schema_version", "coverage_version", "suite_id"):
            hostile = copy.copy(self.v7)
            object.__setattr__(
                hostile,
                attribute,
                _EqualString(getattr(hostile, attribute)),
            )
            with self.assertRaises(ExecutableDevelopmentCoverageV7Error):
                validate_executable_development_coverage_v7(hostile)

        original_family = self.v7.families[0]
        equal_family = _EqualCoverageFamily(
            original_family.family_id,
            original_family.lifecycle_state,
            original_family.task_count,
            original_family.parameter_axes,
            original_family.solution_track,
            original_family.allowed_tools,
            original_family.filesystem_schema,
            original_family.output_contract,
            original_family.capability_tags,
            original_family.integrated_task_set_sha256,
            original_family.family_sha256,
        )
        hostile = copy.copy(self.v7)
        families = list(self.v7.families)
        families[0] = equal_family
        object.__setattr__(hostile, "families", tuple(families))
        with self.assertRaises(ExecutableDevelopmentCoverageV7Error):
            validate_executable_development_coverage_v7(hostile)

        original_source = self.v7.source_registry_commitments[0]
        equal_source = _EqualSourceRegistryCommitment(
            original_source.tranche_id,
            original_source.added_task_count,
            original_source.cumulative_task_count,
            original_source.registry_sha256,
            original_source.cumulative_suite_sha256,
        )
        hostile = copy.copy(self.v7)
        sources = list(self.v7.source_registry_commitments)
        sources[0] = equal_source
        object.__setattr__(
            hostile, "source_registry_commitments", tuple(sources)
        )
        with self.assertRaises(ExecutableDevelopmentCoverageV7Error):
            validate_executable_development_coverage_v7(hostile)

        original_axis = self.migration.preserved_parameter_axes[0]
        equal_axis = _EqualCoverageParameterAxis(
            original_axis.axis_name,
            original_axis.values,
        )
        hostile_migration = copy.copy(self.migration)
        object.__setattr__(
            hostile_migration,
            "preserved_parameter_axes",
            (equal_axis, self.migration.preserved_parameter_axes[1]),
        )
        with self.assertRaises(
            ExecutableDevelopmentCoverageV6ToV7MigrationError
        ):
            validate_executable_development_coverage_v6_to_v7_migration(
                hostile_migration
            )

    def test_cached_bytes_return_fresh_unpoisonable_objects(self) -> None:
        self.assertIs(
            executable_development_coverage_v7_config_bytes(),
            executable_development_coverage_v7_config_bytes(),
        )
        victim = build_executable_development_coverage_v7()
        object.__setattr__(
            victim.families[0], "filesystem_schema", "poisoned-schema"
        )
        object.__setattr__(
            victim.promotion_history[-1],
            "source_tranche_id",
            "poisoned-tranche",
        )
        rebuilt = build_executable_development_coverage_v7()
        self.assertEqual(rebuilt, self.v7)
        self.assertIsNot(rebuilt.families[0], victim.families[0])
        self.assertIsNot(
            rebuilt.promotion_history[-1],
            victim.promotion_history[-1],
        )
        with self.assertRaises(ExecutableDevelopmentCoverageV7Error):
            validate_executable_development_coverage_v7(victim)
        migration_victim = (
            build_executable_development_coverage_v6_to_v7_migration()
        )
        object.__setattr__(
            migration_victim.new_source_registry_commitment,
            "tranche_id",
            "poisoned-tranche",
        )
        migration_rebuilt = (
            build_executable_development_coverage_v6_to_v7_migration()
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
                self.v7_bytes,
                load_executable_development_coverage_v7,
                ExecutableDevelopmentCoverageV7Error,
            ),
            (
                self.migration_bytes,
                load_executable_development_coverage_v6_to_v7_migration,
                ExecutableDevelopmentCoverageV6ToV7MigrationError,
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
                self.v7_bytes,
                load_executable_development_coverage_v7,
                ExecutableDevelopmentCoverageV7Error,
            ),
            (
                self.migration_bytes,
                load_executable_development_coverage_v6_to_v7_migration,
                ExecutableDevelopmentCoverageV6ToV7MigrationError,
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
        with self.assertRaises(ExecutableDevelopmentCoverageV7Error):
            load_executable_development_coverage_v7(Path("bad\0path"))

    def test_root_and_packaged_schemas_match_and_validate(self) -> None:
        pairs = (
            (
                ROOT
                / "executable-method-development-coverage-v7.schema.json",
                ROOT
                / "src/cbds/schemas/"
                "executable-method-development-coverage-v7.schema.json",
                json.loads(self.v7_bytes),
            ),
            (
                ROOT
                / "executable-method-development-coverage-v6-to-v7-"
                "migration.schema.json",
                ROOT
                / "src/cbds/schemas/"
                "executable-method-development-coverage-v6-to-v7-"
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
            bad_coverage["integrated_task_count"] = 440
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
            ROOT / "scripts/build_executable_development_coverage_v7.py"
        )
        spec = importlib.util.spec_from_file_location(
            "_cbds_coverage_v7_builder", script
        )
        if spec is None or spec.loader is None:
            self.fail("coverage-v7 builder module could not be loaded")
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
            self.assertEqual(coverage.read_bytes(), self.v7_bytes)
            self.assertEqual(migration.read_bytes(), self.migration_bytes)
            self.assertEqual(module.main(arguments), 0)
            coverage.write_bytes(b"different-existing-artifact\n")
            coverage.chmod(0o644)
            with self.assertRaises(HashOnlyReportPublicationError):
                module.main(arguments)
            self.assertEqual(
                coverage.read_bytes(), b"different-existing-artifact\n"
            )
            coverage.write_bytes(self.v7_bytes)
            coverage.chmod(0o644)
            self.assertEqual(module.main([*arguments, "--check"]), 0)

    def test_checked_files_and_source_have_hardened_shape(self) -> None:
        for path in (V7_CONFIG, MIGRATION_CONFIG):
            metadata = path.stat()
            self.assertTrue(stat.S_ISREG(metadata.st_mode))
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o644)
            self.assertEqual(metadata.st_nlink, 1)
        script = (
            ROOT / "scripts/build_executable_development_coverage_v7.py"
        )
        self.assertEqual(stat.S_IMODE(script.stat().st_mode), 0o755)

        for relative in (
            "src/cbds/executable_development_coverage_v7.py",
            "src/cbds/executable_development_coverage_v6_to_v7_migration.py",
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
