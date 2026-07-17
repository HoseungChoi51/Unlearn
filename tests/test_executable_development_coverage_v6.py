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

from cbds.executable_development_coverage_v5 import (  # noqa: E402
    build_executable_development_coverage_v5,
)
from cbds.executable_development_coverage_v5_to_v6_migration import (  # noqa: E402
    COVERAGE_V5_TO_V6_MIGRATION_CONFIG_RELATIVE_PATH,
    FROZEN_V5_NESTED_JSON_FAMILY_SHA256,
    FROZEN_V6_NESTED_JSON_FAMILY_SHA256,
    MIGRATION_REASON_CODES,
    ExecutableDevelopmentCoverageV5ToV6MigrationError,
    build_executable_development_coverage_v5_to_v6_migration,
    executable_development_coverage_v5_to_v6_migration_config_bytes,
    load_executable_development_coverage_v5_to_v6_migration,
    validate_executable_development_coverage_v5_to_v6_migration,
)
from cbds.executable_development_coverage_v6 import (  # noqa: E402
    CANONICAL_FAMILY_ORDER,
    COVERAGE_V6_CONFIG_RELATIVE_PATH,
    FROZEN_NESTED_JSON_DISCRIMINATION_SHA256,
    FROZEN_NESTED_JSON_TASK_SET_SHA256,
    FROZEN_THIRTEENTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_THIRTEENTH_REGISTRY_SHA256,
    NESTED_JSON_FAMILY_INDEX,
    NEXT_PLANNED_FAMILY_ID,
    PREDECESSOR_CONFIG_BYTE_COUNT,
    PREDECESSOR_CONFIG_BYTES_SHA256,
    PREDECESSOR_COVERAGE_SHA256,
    PREDECESSOR_GIT_COMMIT,
    CoveragePromotionEvidence,
    ExecutableDevelopmentCoverageV6Error,
    build_executable_development_coverage_v6,
    executable_development_coverage_v6_config_bytes,
    load_executable_development_coverage_v6,
    validate_executable_development_coverage_v6,
)
from cbds.hash_only_report_publication import (  # noqa: E402
    HashOnlyReportPublicationError,
)
from cbds.executable_development_coverage import (  # noqa: E402
    CoverageFamily,
    CoverageParameterAxis,
    SourceRegistryCommitment,
)


V5_CONFIG = ROOT / "configs/executable-method-development-coverage-v5.json"
V6_CONFIG = ROOT / COVERAGE_V6_CONFIG_RELATIVE_PATH
MIGRATION_CONFIG = (
    ROOT / COVERAGE_V5_TO_V6_MIGRATION_CONFIG_RELATIVE_PATH
)
EXPECTED_COVERAGE_SHA256 = (
    "044f026b67a531613b1034b27056f1b6f91e1d95ae8902108428e67a6a9c31cf"
)
EXPECTED_COVERAGE_BYTES_SHA256 = (
    "e526485ba7b34c0325ff6809dcee428c251cd25dd34e907ca3b2eff56c174d68"
)
EXPECTED_COVERAGE_BYTE_COUNT = 25_899
EXPECTED_MIGRATION_SHA256 = (
    "5c345bc6860f5c9ff70dba656d3cc1204acb705a0d2c4526b4031364313d7e90"
)
EXPECTED_MIGRATION_BYTES_SHA256 = (
    "31f99bd95165b44cdd5aa4d9bc668b1fcf559a1d621a56c14c80a8d1c5521a8e"
)
EXPECTED_MIGRATION_BYTE_COUNT = 5_423


class _EqualString(str):
    pass


class _EqualCoverageFamily(CoverageFamily):
    def __post_init__(self) -> None:
        pass

    def __eq__(self, other: object) -> bool:
        return isinstance(other, CoverageFamily)

    def to_record(self) -> dict[str, object]:
        return {
            "family_id": self.family_id,
            "lifecycle_state": self.lifecycle_state,
            "task_count": self.task_count,
            "parameter_axes": [
                axis.to_record() for axis in self.parameter_axes
            ],
            "solution_track": self.solution_track,
            "allowed_tools": list(self.allowed_tools),
            "filesystem_schema": self.filesystem_schema,
            "output_contract": self.output_contract,
            "capability_tags": list(self.capability_tags),
            "integrated_task_set_sha256": (
                self.integrated_task_set_sha256
            ),
            "family_sha256": self.family_sha256,
        }


class _EqualSourceRegistryCommitment(SourceRegistryCommitment):
    def __post_init__(self) -> None:
        pass

    def __eq__(self, other: object) -> bool:
        return isinstance(other, SourceRegistryCommitment)

    def to_record(self) -> dict[str, object]:
        return {
            "tranche_id": self.tranche_id,
            "added_task_count": self.added_task_count,
            "cumulative_task_count": self.cumulative_task_count,
            "registry_sha256": self.registry_sha256,
            "cumulative_suite_sha256": self.cumulative_suite_sha256,
        }


class _EqualCoverageParameterAxis(CoverageParameterAxis):
    def __post_init__(self) -> None:
        pass

    def __eq__(self, other: object) -> bool:
        return isinstance(other, CoverageParameterAxis)

    def to_record(self) -> dict[str, object]:
        return {
            "axis_name": self.axis_name,
            "values": list(self.values),
        }


class ExecutableDevelopmentCoverageV6Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.v5 = build_executable_development_coverage_v5()
        cls.v6 = build_executable_development_coverage_v6()
        cls.migration = (
            build_executable_development_coverage_v5_to_v6_migration()
        )
        cls.v6_bytes = executable_development_coverage_v6_config_bytes()
        cls.migration_bytes = (
            executable_development_coverage_v5_to_v6_migration_config_bytes()
        )

    def test_exact_canonical_artifact_identities(self) -> None:
        self.assertEqual(
            self.v6.coverage_sha256, EXPECTED_COVERAGE_SHA256
        )
        self.assertEqual(len(self.v6_bytes), EXPECTED_COVERAGE_BYTE_COUNT)
        self.assertEqual(
            sha256(self.v6_bytes).hexdigest(),
            EXPECTED_COVERAGE_BYTES_SHA256,
        )
        self.assertEqual(V6_CONFIG.read_bytes(), self.v6_bytes)
        self.assertEqual(
            load_executable_development_coverage_v6(V6_CONFIG), self.v6
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
            load_executable_development_coverage_v5_to_v6_migration(
                MIGRATION_CONFIG
            ),
            self.migration,
        )

    def test_predecessor_bytes_and_creation_commit_are_exact(self) -> None:
        payload = V5_CONFIG.read_bytes()
        self.assertEqual(len(payload), PREDECESSOR_CONFIG_BYTE_COUNT)
        self.assertEqual(
            sha256(payload).hexdigest(),
            PREDECESSOR_CONFIG_BYTES_SHA256,
        )
        predecessor = self.v6.predecessor
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
            "cfb91bef706fc1c4fd4f95d7891f42e3ec058bbaba28997a22a0f72614d6268f",
        )

    def test_exact_22_integrated_3_planned_partition(self) -> None:
        self.assertEqual(len(self.v6.families), 25)
        self.assertEqual(
            tuple(item.family_id for item in self.v6.families),
            CANONICAL_FAMILY_ORDER,
        )
        self.assertEqual(
            tuple(item.lifecycle_state for item in self.v6.families),
            ("integrated",) * 22 + ("planned",) * 3,
        )
        self.assertEqual(
            self.v6.families[22].family_id, NEXT_PLANNED_FAMILY_ID
        )
        self.assertEqual(
            sum(item.task_count for item in self.v6.families), 500
        )
        self.assertEqual(
            tuple(
                item.cumulative_task_count
                for item in self.v6.source_registry_commitments
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
            ),
        )

    def test_source_and_history_are_exact_append_only_extensions(self) -> None:
        self.assertEqual(
            self.v6.source_registry_commitments[:-1],
            self.v5.source_registry_commitments,
        )
        thirteenth = self.v6.source_registry_commitments[-1]
        self.assertEqual(thirteenth.tranche_id, "thirteenth-tranche")
        self.assertEqual(thirteenth.added_task_count, 20)
        self.assertEqual(
            thirteenth.registry_sha256,
            FROZEN_THIRTEENTH_REGISTRY_SHA256,
        )
        self.assertEqual(
            thirteenth.cumulative_suite_sha256,
            FROZEN_THIRTEENTH_CUMULATIVE_SUITE_SHA256,
        )
        self.assertEqual(
            tuple(item.to_record() for item in self.v6.promotion_history[:-1]),
            tuple(item.to_record() for item in self.v5.promotion_history),
        )
        self.assertTrue(
            all(
                type(item) is CoveragePromotionEvidence
                for item in self.v6.promotion_history
            )
        )
        promotion = self.v6.promotion_history[-1]
        self.assertEqual(
            promotion.family_id, "nested-json-schema-migration"
        )
        self.assertEqual(promotion.source_tranche_id, "thirteenth-tranche")
        self.assertEqual(
            promotion.task_set_sha256,
            FROZEN_NESTED_JSON_TASK_SET_SHA256,
        )
        self.assertEqual(
            promotion.discrimination_sha256,
            FROZEN_NESTED_JSON_DISCRIMINATION_SHA256,
        )

    def test_migration_changes_only_one_family_and_preserves_contract(
        self,
    ) -> None:
        old = self.v5.families[NESTED_JSON_FAMILY_INDEX]
        new = self.v6.families[NESTED_JSON_FAMILY_INDEX]
        self.assertEqual(
            old.family_sha256, FROZEN_V5_NESTED_JSON_FAMILY_SHA256
        )
        self.assertEqual(
            new.family_sha256, FROZEN_V6_NESTED_JSON_FAMILY_SHA256
        )
        self.assertEqual(old.lifecycle_state, "planned")
        self.assertEqual(new.lifecycle_state, "integrated")
        self.assertIsNone(old.integrated_task_set_sha256)
        self.assertEqual(
            new.integrated_task_set_sha256,
            FROZEN_NESTED_JSON_TASK_SET_SHA256,
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
            zip(self.v5.families, self.v6.families, strict=True)
        ):
            if before != after:
                changed.append(index)
        self.assertEqual(changed, [NESTED_JSON_FAMILY_INDEX])
        self.assertEqual(
            self.migration.unchanged_family_sha256,
            tuple(
                item.family_sha256
                for index, item in enumerate(self.v5.families)
                if index != NESTED_JSON_FAMILY_INDEX
            ),
        )

    def test_migration_binds_all_append_only_evidence(self) -> None:
        record = self.migration.to_hash_only_record()
        self.assertEqual(record["changed_family_count"], 1)
        self.assertEqual(record["unchanged_family_count"], 24)
        self.assertEqual(tuple(record["reason_codes"]), MIGRATION_REASON_CODES)
        self.assertEqual(
            self.migration.preserved_promotion_history,
            self.v6.promotion_history[:-1],
        )
        self.assertEqual(
            self.migration.promotion_evidence,
            self.v6.promotion_history[-1],
        )
        self.assertEqual(
            self.migration.new_source_registry_commitment,
            self.v6.source_registry_commitments[-1],
        )
        self.assertEqual(
            len(set(self.migration.unchanged_family_sha256)), 24
        )

    def test_authority_history_and_family_mutations_fail_closed(self) -> None:
        hostile = copy.copy(self.v6)
        object.__setattr__(hostile, "sealed", True)
        with self.assertRaises(ExecutableDevelopmentCoverageV6Error):
            validate_executable_development_coverage_v6(hostile)
        reordered = copy.copy(self.v6)
        object.__setattr__(
            reordered,
            "promotion_history",
            tuple(reversed(self.v6.promotion_history)),
        )
        with self.assertRaises(ExecutableDevelopmentCoverageV6Error):
            validate_executable_development_coverage_v6(reordered)
        wrong_family = copy.copy(self.v6)
        families = list(self.v6.families)
        families[0], families[1] = families[1], families[0]
        object.__setattr__(wrong_family, "families", tuple(families))
        with self.assertRaises(ExecutableDevelopmentCoverageV6Error):
            validate_executable_development_coverage_v6(wrong_family)
        hostile_migration = copy.copy(self.migration)
        object.__setattr__(hostile_migration, "claim_authorized", True)
        with self.assertRaises(
            ExecutableDevelopmentCoverageV5ToV6MigrationError
        ):
            validate_executable_development_coverage_v5_to_v6_migration(
                hostile_migration
            )

    def test_equal_subclasses_cannot_claim_exact_owned_evidence(self) -> None:
        for attribute in ("schema_version", "coverage_version", "suite_id"):
            hostile = copy.copy(self.v6)
            object.__setattr__(
                hostile,
                attribute,
                _EqualString(getattr(hostile, attribute)),
            )
            with self.assertRaises(ExecutableDevelopmentCoverageV6Error):
                validate_executable_development_coverage_v6(hostile)

        for attribute in (
            "coverage_sha256",
            "config_bytes_sha256",
            "coverage_version",
            "config_relative_path",
        ):
            predecessor = copy.copy(self.v6.predecessor)
            object.__setattr__(
                predecessor,
                attribute,
                _EqualString(getattr(predecessor, attribute)),
            )
            with self.assertRaises(ExecutableDevelopmentCoverageV6Error):
                predecessor.__post_init__()

        for attribute in (
            "family_id",
            "old_lifecycle_state",
            "new_lifecycle_state",
            "source_tranche_id",
        ):
            promotion = copy.copy(self.v6.promotion_history[-1])
            object.__setattr__(
                promotion,
                attribute,
                _EqualString(getattr(promotion, attribute)),
            )
            with self.assertRaises(ExecutableDevelopmentCoverageV6Error):
                promotion.__post_init__()

        original_family = self.v6.families[0]
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
        hostile = copy.copy(self.v6)
        families = list(self.v6.families)
        families[0] = equal_family
        object.__setattr__(hostile, "families", tuple(families))
        with self.assertRaises(ExecutableDevelopmentCoverageV6Error):
            validate_executable_development_coverage_v6(hostile)

        original_source = self.v6.source_registry_commitments[0]
        equal_source = _EqualSourceRegistryCommitment(
            original_source.tranche_id,
            original_source.added_task_count,
            original_source.cumulative_task_count,
            original_source.registry_sha256,
            original_source.cumulative_suite_sha256,
        )
        hostile = copy.copy(self.v6)
        sources = list(self.v6.source_registry_commitments)
        sources[0] = equal_source
        object.__setattr__(
            hostile, "source_registry_commitments", tuple(sources)
        )
        with self.assertRaises(ExecutableDevelopmentCoverageV6Error):
            validate_executable_development_coverage_v6(hostile)

        for attribute in (
            "schema_version",
            "migration_version",
            "preserved_solution_track",
            "preserved_filesystem_schema",
            "preserved_output_contract",
        ):
            hostile_migration = copy.copy(self.migration)
            object.__setattr__(
                hostile_migration,
                attribute,
                _EqualString(getattr(hostile_migration, attribute)),
            )
            with self.assertRaises(
                ExecutableDevelopmentCoverageV5ToV6MigrationError
            ):
                validate_executable_development_coverage_v5_to_v6_migration(
                    hostile_migration
                )

        hostile_migration = copy.copy(self.migration)
        tools = list(hostile_migration.preserved_allowed_tools)
        tools[0] = _EqualString(tools[0])
        object.__setattr__(
            hostile_migration, "preserved_allowed_tools", tuple(tools)
        )
        with self.assertRaises(
            ExecutableDevelopmentCoverageV5ToV6MigrationError
        ):
            validate_executable_development_coverage_v5_to_v6_migration(
                hostile_migration
            )

        hostile_migration = copy.copy(self.migration)
        tags = list(hostile_migration.preserved_capability_tags)
        tags[0] = _EqualString(tags[0])
        object.__setattr__(
            hostile_migration, "preserved_capability_tags", tuple(tags)
        )
        with self.assertRaises(
            ExecutableDevelopmentCoverageV5ToV6MigrationError
        ):
            validate_executable_development_coverage_v5_to_v6_migration(
                hostile_migration
            )

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
            ExecutableDevelopmentCoverageV5ToV6MigrationError
        ):
            validate_executable_development_coverage_v5_to_v6_migration(
                hostile_migration
            )

    def test_cached_bytes_return_fresh_unpoisonable_objects(self) -> None:
        self.assertIs(
            executable_development_coverage_v6_config_bytes(),
            executable_development_coverage_v6_config_bytes(),
        )
        victim = build_executable_development_coverage_v6()
        object.__setattr__(
            victim.families[0], "filesystem_schema", "poisoned-schema"
        )
        object.__setattr__(
            victim.promotion_history[-1],
            "source_tranche_id",
            "poisoned-tranche",
        )
        rebuilt = build_executable_development_coverage_v6()
        self.assertEqual(rebuilt, self.v6)
        self.assertIsNot(rebuilt.families[0], victim.families[0])
        self.assertIsNot(
            rebuilt.promotion_history[-1],
            victim.promotion_history[-1],
        )
        with self.assertRaises(ExecutableDevelopmentCoverageV6Error):
            validate_executable_development_coverage_v6(victim)
        migration_victim = (
            build_executable_development_coverage_v5_to_v6_migration()
        )
        object.__setattr__(
            migration_victim.new_source_registry_commitment,
            "tranche_id",
            "poisoned-tranche",
        )
        migration_rebuilt = (
            build_executable_development_coverage_v5_to_v6_migration()
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
                self.v6_bytes,
                load_executable_development_coverage_v6,
                ExecutableDevelopmentCoverageV6Error,
            ),
            (
                self.migration_bytes,
                load_executable_development_coverage_v5_to_v6_migration,
                ExecutableDevelopmentCoverageV5ToV6MigrationError,
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
                self.v6_bytes,
                load_executable_development_coverage_v6,
                ExecutableDevelopmentCoverageV6Error,
            ),
            (
                self.migration_bytes,
                load_executable_development_coverage_v5_to_v6_migration,
                ExecutableDevelopmentCoverageV5ToV6MigrationError,
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
        with self.assertRaises(ExecutableDevelopmentCoverageV6Error):
            load_executable_development_coverage_v6(Path("bad\0path"))

    def test_root_and_packaged_schemas_match_and_validate(self) -> None:
        pairs = (
            (
                ROOT
                / "executable-method-development-coverage-v6.schema.json",
                ROOT
                / "src/cbds/schemas/"
                "executable-method-development-coverage-v6.schema.json",
                json.loads(self.v6_bytes),
            ),
            (
                ROOT
                / "executable-method-development-coverage-v5-to-v6-"
                "migration.schema.json",
                ROOT
                / "src/cbds/schemas/"
                "executable-method-development-coverage-v5-to-v6-"
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
            ROOT / "scripts/build_executable_development_coverage_v6.py"
        )
        spec = importlib.util.spec_from_file_location(
            "_cbds_coverage_v6_builder", script
        )
        if spec is None or spec.loader is None:
            self.fail("coverage-v6 builder module could not be loaded")
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
            self.assertEqual(coverage.read_bytes(), self.v6_bytes)
            self.assertEqual(migration.read_bytes(), self.migration_bytes)
            self.assertEqual(module.main(arguments), 0)
            coverage.write_bytes(b"different-existing-artifact\n")
            coverage.chmod(0o644)
            with self.assertRaises(HashOnlyReportPublicationError):
                module.main(arguments)
            self.assertEqual(
                coverage.read_bytes(), b"different-existing-artifact\n"
            )
            coverage.write_bytes(self.v6_bytes)
            coverage.chmod(0o644)
            self.assertEqual(module.main([*arguments, "--check"]), 0)

    def test_checked_files_and_source_have_hardened_shape(self) -> None:
        for path in (V6_CONFIG, MIGRATION_CONFIG):
            metadata = path.stat()
            self.assertTrue(stat.S_ISREG(metadata.st_mode))
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o644)
            self.assertEqual(metadata.st_nlink, 1)
        script = (
            ROOT / "scripts/build_executable_development_coverage_v6.py"
        )
        self.assertEqual(stat.S_IMODE(script.stat().st_mode), 0o755)

        for relative in (
            "src/cbds/executable_development_coverage_v6.py",
            "src/cbds/executable_development_coverage_v5_to_v6_migration.py",
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
