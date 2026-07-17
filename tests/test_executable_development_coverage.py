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

import cbds.executable_development_coverage as coverage_module  # noqa: E402
from cbds.executable_development_coverage import (  # noqa: E402
    CANONICAL_FAMILY_ORDER,
    COVERAGE_CONFIG_RELATIVE_PATH,
    CoverageFamily,
    CoverageParameterAxis,
    ExecutableDevelopmentCoverage,
    ExecutableDevelopmentCoverageError,
    FAMILY_COUNT,
    INTEGRATED_FAMILY_COUNT,
    INTEGRATED_TASK_COUNT,
    MAXIMUM_COVERAGE_CONFIG_BYTES,
    PLANNED_FAMILY_COUNT,
    PLANNED_TASK_COUNT,
    TASKS_PER_FAMILY,
    TOTAL_TASK_COUNT,
    build_executable_development_coverage,
    compute_executable_development_coverage_sha256,
    load_executable_development_coverage,
    validate_executable_development_coverage,
)
from cbds.manifests import canonical_json_bytes  # noqa: E402
from cbds.evaluation_specs import FROZEN_BASH_NATIVE_EXECUTABLES  # noqa: E402


CONFIG = ROOT / COVERAGE_CONFIG_RELATIVE_PATH
EXPECTED_COVERAGE_SHA256 = (
    "6c215d9eaf5581aaa146d6814a9d40621a57459c5af98ae4ca625caff10c9c8c"
)
EXPECTED_CONFIG_BYTES_SHA256 = (
    "46f98f54ef5682ce0adc3854557ecfe8ed092fd5e916935bc27702edb4e86efa"
)
EXPECTED_USTAR_TASK_SET_SHA256 = (
    "be044d13053e62e0a9f609e1654048de4c7b422e9bc93c659f0d265ddfd4e283"
)
EXPECTED_PIPEFAIL_TASK_SET_SHA256 = (
    "fc974695fe967094bcba6c6f8ff8c267c86f64215de78c43a8e693bed1252562"
)
EXPECTED_BOUNDED_RETRY_TASK_SET_SHA256 = (
    "112e9d079a1b21b2d371e61d48af2401649b23aeff11a45e4d2dcbe847e1541c"
)
EXPECTED_CASE_ROUTED_TASK_SET_SHA256 = (
    "e68a7e4614424e76fa35d4c0650e500469b971f1a5010d309115b0c225b7b2e6"
)
EXPECTED_COLLISION_SAFE_BATCH_RENAME_TASK_SET_SHA256 = (
    "6c563074579359d666faaae2aebf69019c74521e8946cea6a2fe19a756c744cd"
)
EXPECTED_EXISTING_ORDER = (
    "active-jsonl-labels",
    "manifest-copy",
    "csv-group-totals",
    "checksum-manifest",
    "path-suffix-inventory",
    "line-transform-mirror",
    "mode-normalized-mirror",
    "jsonl-keyed-inner-join",
    "ustar-safe-extract",
    "proc-snapshot-report",
    "compound-path-query",
    "regex-log-group-aggregation",
)


def domain_sha256(domain: str, value: object) -> str:
    return sha256(
        domain.encode("ascii") + b"\0" + canonical_json_bytes(value)
    ).hexdigest()


def rehash_record(record: dict[str, object]) -> None:
    families = record["families"]
    assert type(families) is list
    for family in families:
        assert type(family) is dict
        core = dict(family)
        core.pop("family_sha256")
        family["family_sha256"] = domain_sha256(
            "cbds.executable-method-development-coverage.family.v1",
            core,
        )
    record["coverage_sha256"] = compute_executable_development_coverage_sha256(
        record
    )


class CoverageContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.coverage = build_executable_development_coverage()
        cls.record = cls.coverage.to_hash_only_record()

    def test_builder_is_deterministic_and_checked_file_is_exact_projection(self) -> None:
        second = build_executable_development_coverage()
        self.assertEqual(second, self.coverage)
        self.assertRegex(self.coverage.coverage_sha256, r"^[0-9a-f]{64}$")
        self.assertEqual(
            self.coverage.coverage_sha256,
            compute_executable_development_coverage_sha256(self.record),
        )
        self.assertEqual(
            self.coverage.coverage_sha256,
            EXPECTED_COVERAGE_SHA256,
        )
        expected_bytes = canonical_json_bytes(self.record) + b"\n"
        self.assertEqual(CONFIG.read_bytes(), expected_bytes)
        self.assertEqual(
            sha256(CONFIG.read_bytes()).hexdigest(),
            EXPECTED_CONFIG_BYTES_SHA256,
        )
        self.assertEqual(
            load_executable_development_coverage(CONFIG),
            self.coverage,
        )

    def test_exact_500_task_partition_and_canonical_family_order(self) -> None:
        self.assertEqual(FAMILY_COUNT, 25)
        self.assertEqual(TASKS_PER_FAMILY, 20)
        self.assertEqual(TOTAL_TASK_COUNT, 500)
        self.assertEqual(INTEGRATED_FAMILY_COUNT, 17)
        self.assertEqual(INTEGRATED_TASK_COUNT, 340)
        self.assertEqual(PLANNED_FAMILY_COUNT, 8)
        self.assertEqual(PLANNED_TASK_COUNT, 160)
        self.assertEqual(25 * 20, 500)
        self.assertEqual(17 * 20, 340)
        self.assertEqual(8 * 20, 160)
        self.assertEqual(
            tuple(family.family_id for family in self.coverage.families),
            CANONICAL_FAMILY_ORDER,
        )
        self.assertEqual(CANONICAL_FAMILY_ORDER[:12], EXPECTED_EXISTING_ORDER)
        self.assertEqual(
            tuple(family.lifecycle_state for family in self.coverage.families),
            ("integrated",) * 17 + ("planned",) * 8,
        )
        self.assertEqual(
            sum(family.task_count for family in self.coverage.families), 500
        )

    def test_every_family_is_an_explicit_distinct_four_by_five_grid(self) -> None:
        cells: set[tuple[str, object, object]] = set()
        for family in self.coverage.families:
            self.assertEqual(family.task_count, 20)
            self.assertEqual(len(family.parameter_axes), 2)
            self.assertEqual(
                tuple(len(axis.values) for axis in family.parameter_axes),
                (4, 5),
            )
            self.assertNotEqual(
                family.parameter_axes[0].axis_name,
                family.parameter_axes[1].axis_name,
            )
            for left in family.parameter_axes[0].values:
                for right in family.parameter_axes[1].values:
                    cells.add((family.family_id, left, right))
        self.assertEqual(len(cells), 500)
        self.assertEqual(
            len(
                {
                    tuple(axis.axis_name for axis in family.parameter_axes)
                    for family in self.coverage.families
                }
            ),
            25,
        )
        self.assertEqual(
            len({family.filesystem_schema for family in self.coverage.families}),
            25,
        )
        self.assertEqual(
            len({family.output_contract for family in self.coverage.families}),
            25,
        )
        self.assertEqual(
            len({family.family_sha256 for family in self.coverage.families}),
            25,
        )

    def test_existing_families_bind_live_task_sets_and_frozen_registries(self) -> None:
        integrated = self.coverage.families[:17]
        planned = self.coverage.families[17:]
        self.assertTrue(
            all(family.integrated_task_set_sha256 is not None for family in integrated)
        )
        self.assertTrue(
            all(family.integrated_task_set_sha256 is None for family in planned)
        )
        self.assertEqual(
            len({family.integrated_task_set_sha256 for family in integrated}), 17
        )
        sources = self.coverage.source_registry_commitments
        self.assertEqual(
            tuple(source.added_task_count for source in sources),
            (100, 100, 40, 20, 20, 20, 20, 20),
        )
        self.assertEqual(
            tuple(source.cumulative_task_count for source in sources),
            (100, 200, 240, 260, 280, 300, 320, 340),
        )
        self.assertEqual(
            tuple(source.registry_sha256 for source in sources),
            (
                "ada6043b345e48f69ad602581030aab1bafcb3ff9dc453f9d02342faaf6a7f9a",
                "27e4721036c4870fec463e880cb3a36fcd72ebe530368cb45179f600ee694ab4",
                "66a9ef43a6387f5f94f511aec3357f0e625427d161a0c6da0d9590a837761237",
                "3dc5512139361a275afaf0b57b94528961615f9b4eee22ee6c333cc7d8bf4ea5",
                "d562d462814b7fc6413e0e085d16f66def28157c1a6361adf28cd3d42eb5f88c",
                "14280b3cbc8a96c919a57a325b5795c381cba86b2a31934f7069821b7ff4e3c4",
                "14aa05939c2ac2f4954196968003254dee39175f1d1d94e32213b8a74cfff19e",
                "8ef6879c5b6f4198c1b0ff2acfcffe89b6cbdd418a9aa2af2eefedfb12994736",
            ),
        )
        self.assertEqual(sources[-1].tranche_id, "eighth-tranche")
        self.assertEqual(
            sources[-1].cumulative_suite_sha256,
            "b22742179e3ce3b7331469de9db0a75ddbae81a3340e2b814c8a7ab34233f0f0",
        )

    def test_thirteenth_integrated_family_is_the_exact_ustar_grid(self) -> None:
        family = self.coverage.families[12]
        self.assertEqual(family.family_id, "reproducible-ustar-pack")
        self.assertEqual(family.lifecycle_state, "integrated")
        self.assertEqual(
            family.integrated_task_set_sha256,
            EXPECTED_USTAR_TASK_SET_SHA256,
        )
        self.assertEqual(
            family.parameter_axes,
            (
                CoverageParameterAxis(
                    "selector",
                    (
                        "all-mode-readable",
                        "txt-suffix-mode-readable",
                        "nonempty-mode-readable",
                        "executable-mode-readable",
                    ),
                ),
                CoverageParameterAxis(
                    "archive_mode_policy",
                    (
                        "preserve-permission-bits",
                        "fixed-0644",
                        "fixed-0600",
                        "normalize-preserve-exec",
                        "fold-class-bits-to-owner",
                    ),
                ),
            ),
        )
        self.assertEqual(family.solution_track, "bash-native")
        self.assertEqual(
            family.allowed_tools,
            ("chmod", "find", "mkdir", "sort", "stat", "tar"),
        )
        self.assertEqual(family.filesystem_schema, "recursive-source-tree-v1")
        self.assertEqual(family.output_contract, "reproducible-posix-ustar-v1")

    def test_fourteenth_integrated_family_is_the_exact_pipefail_grid(self) -> None:
        family = self.coverage.families[13]
        self.assertEqual(family.family_id, "pipefail-atomic-report")
        self.assertEqual(family.lifecycle_state, "integrated")
        self.assertEqual(
            family.integrated_task_set_sha256,
            EXPECTED_PIPEFAIL_TASK_SET_SHA256,
        )
        self.assertEqual(
            family.parameter_axes,
            (
                CoverageParameterAxis(
                    "pipeline_shape",
                    (
                        "linear-two-stage",
                        "linear-four-stage",
                        "fan-in-merge",
                        "tee-and-reduce",
                    ),
                ),
                CoverageParameterAxis(
                    "failure_commit_policy",
                    (
                        "commit-success-only",
                        "write-status-always",
                        "rollback-on-any-failure",
                        "preserve-first-failure",
                        "preserve-last-failure",
                    ),
                ),
            ),
        )
        self.assertEqual(family.solution_track, "bash-native")
        self.assertEqual(
            family.allowed_tools,
            ("awk", "grep", "mkdir", "mv", "sed", "sort"),
        )
        self.assertEqual(family.filesystem_schema, "pipeline-record-streams")
        self.assertEqual(family.output_contract, "atomic-pipeline-status-json")

    def test_fifteenth_integrated_family_is_the_exact_bounded_retry_grid(self) -> None:
        family = self.coverage.families[14]
        self.assertEqual(family.family_id, "bounded-retry-state-machine")
        self.assertEqual(family.lifecycle_state, "integrated")
        self.assertEqual(
            family.integrated_task_set_sha256,
            EXPECTED_BOUNDED_RETRY_TASK_SET_SHA256,
        )
        self.assertEqual(
            family.parameter_axes,
            (
                CoverageParameterAxis(
                    "transition_model",
                    ("linear", "branching", "cyclic-bounded", "compensating"),
                ),
                CoverageParameterAxis(
                    "retry_policy",
                    (
                        "never",
                        "fixed-two",
                        "fixed-four",
                        "until-terminal",
                        "retry-transient-only",
                    ),
                ),
            ),
        )
        self.assertEqual(family.solution_track, "bash-native")
        self.assertEqual(family.allowed_tools, ("awk", "mkdir", "sort"))
        self.assertEqual(family.filesystem_schema, "workflow-event-ledger")
        self.assertEqual(
            family.output_contract, "terminal-state-and-attempt-report"
        )

    def test_sixteenth_integrated_family_is_the_exact_case_routed_grid(self) -> None:
        family = self.coverage.families[15]
        self.assertEqual(family.family_id, "case-routed-batch-transform")
        self.assertEqual(family.lifecycle_state, "integrated")
        self.assertEqual(
            family.integrated_task_set_sha256,
            EXPECTED_CASE_ROUTED_TASK_SET_SHA256,
        )
        self.assertEqual(
            family.parameter_axes,
            (
                CoverageParameterAxis(
                    "route_key",
                    ("suffix", "record-kind", "leading-byte", "declared-action"),
                ),
                CoverageParameterAxis(
                    "fallback_policy",
                    (
                        "skip",
                        "copy-verbatim",
                        "reject-batch",
                        "route-default",
                        "emit-error-record",
                    ),
                ),
            ),
        )
        self.assertEqual(family.solution_track, "bash-native")
        self.assertEqual(
            family.allowed_tools,
            ("awk", "mkdir", "sed", "sort", "tr"),
        )
        self.assertEqual(family.filesystem_schema, "routed-text-batch")
        self.assertEqual(
            family.output_contract, "route-partitioned-transform-tree"
        )

    def test_seventeenth_integrated_family_is_the_exact_collision_safe_rename_grid(
        self,
    ) -> None:
        family = self.coverage.families[16]
        self.assertEqual(family.family_id, "collision-safe-batch-rename")
        self.assertEqual(family.lifecycle_state, "integrated")
        self.assertEqual(
            family.integrated_task_set_sha256,
            EXPECTED_COLLISION_SAFE_BATCH_RENAME_TASK_SET_SHA256,
        )
        self.assertEqual(
            family.parameter_axes,
            (
                CoverageParameterAxis(
                    "rename_rule",
                    (
                        "lowercase-basename",
                        "numbered-prefix",
                        "suffix-rewrite",
                        "manifest-mapping",
                    ),
                ),
                CoverageParameterAxis(
                    "collision_policy",
                    (
                        "reject-all",
                        "skip-collisions",
                        "stable-first",
                        "stable-last",
                        "identical-files-coalesce",
                    ),
                ),
            ),
        )
        self.assertEqual(family.solution_track, "bash-native")
        self.assertEqual(
            family.allowed_tools,
            ("find", "mkdir", "mv", "sort", "stat"),
        )
        self.assertEqual(family.filesystem_schema, "rename-candidate-tree")
        self.assertEqual(
            family.output_contract, "atomic-renamed-tree-and-ledger"
        )

    def test_planned_roster_covers_requested_domains_and_python_track(self) -> None:
        planned = self.coverage.families[17:]
        by_id = {family.family_id: family for family in planned}
        self.assertEqual(planned[0].family_id, "hardlink-deduplicated-mirror")
        required = {
            "hardlink-deduplicated-mirror",
            "compressed-archive-roundtrip-verify",
            "checksum-repair-plan",
            "jsonl-csv-enrichment-compose",
            "process-lifecycle-delta",
            "symlink-aware-tree-reconcile",
        }
        self.assertTrue(required.issubset(by_id))
        python_families = [
            family for family in planned if family.solution_track == "python-permitted"
        ]
        self.assertGreaterEqual(len(python_families), 2)
        self.assertTrue(
            all("python3" in family.allowed_tools for family in python_families)
        )
        bash_families = [
            family for family in self.coverage.families
            if family.solution_track == "bash-native"
        ]
        self.assertTrue(
            all("python3" not in family.allowed_tools for family in bash_families)
        )
        native_tools = set(FROZEN_BASH_NATIVE_EXECUTABLES)
        for family in self.coverage.families:
            permitted = native_tools | (
                {"python3"} if family.solution_track == "python-permitted" else set()
            )
            self.assertTrue(set(family.allowed_tools).issubset(permitted))
        self.assertEqual(
            by_id["jsonl-csv-enrichment-compose"].allowed_tools,
            ("awk", "jq", "mkdir", "sort"),
        )

    def test_hash_only_closed_record_and_authority_boundary(self) -> None:
        self.assertEqual(
            set(self.record),
            {
                "schema_version",
                "coverage_version",
                "record_type",
                "suite_id",
                "family_count",
                "tasks_per_family",
                "total_task_count",
                "integrated_family_count",
                "integrated_task_count",
                "planned_family_count",
                "planned_task_count",
                "canonical_family_order",
                "source_registry_commitments",
                "families",
                "coverage_sha256",
                "public_method_development",
                "sealed",
                "scored",
                "candidate_execution_authorized",
                "scored_evaluation_authorized",
                "model_selection_eligible",
                "claim_authorized",
                "independent_human_review_attested",
            },
        )
        self.assertTrue(self.record["public_method_development"])
        for key in (
            "sealed",
            "scored",
            "candidate_execution_authorized",
            "scored_evaluation_authorized",
            "model_selection_eligible",
            "claim_authorized",
            "independent_human_review_attested",
        ):
            self.assertIs(self.record[key], False)
        rendered = canonical_json_bytes(self.record)
        for forbidden in (b'"prompt"', b'"fixture"', b'"oracle"', b'"content"'):
            self.assertNotIn(forbidden, rendered)

    def test_exact_types_and_subclasses_fail_closed(self) -> None:
        with self.assertRaises(ExecutableDevelopmentCoverageError):
            CoverageParameterAxis("bad", (True, 2, 3, 4))

        class AxisSubclass(CoverageParameterAxis):
            pass

        with self.assertRaises(ExecutableDevelopmentCoverageError):
            AxisSubclass("bad", ("a", "b", "c", "d"))

        with self.assertRaises(ExecutableDevelopmentCoverageError):
            CoverageParameterAxis("bad", ["a", "b", "c", "d"])  # type: ignore[arg-type]

        family = self.coverage.families[0]
        with self.assertRaises(ExecutableDevelopmentCoverageError):
            CoverageFamily(
                family_id=family.family_id,
                lifecycle_state=family.lifecycle_state,
                task_count=True,  # type: ignore[arg-type]
                parameter_axes=family.parameter_axes,
                solution_track=family.solution_track,
                allowed_tools=family.allowed_tools,
                filesystem_schema=family.filesystem_schema,
                output_contract=family.output_contract,
                capability_tags=family.capability_tags,
                integrated_task_set_sha256=family.integrated_task_set_sha256,
                family_sha256=family.family_sha256,
            )

        class CoverageSubclass(ExecutableDevelopmentCoverage):
            pass

        with self.assertRaises(ExecutableDevelopmentCoverageError):
            CoverageSubclass(
                families=self.coverage.families,
                source_registry_commitments=self.coverage.source_registry_commitments,
                coverage_sha256=self.coverage.coverage_sha256,
            )
        validate_executable_development_coverage(self.coverage)


class CoverageLoaderAdversarialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.record = build_executable_development_coverage().to_hash_only_record()
        cls.canonical = canonical_json_bytes(cls.record) + b"\n"

    def assert_rejected(self, payload: bytes) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "coverage.json"
            path.write_bytes(payload)
            with self.assertRaises(ExecutableDevelopmentCoverageError):
                load_executable_development_coverage(path)

    def test_duplicate_nonfinite_invalid_utf8_and_malformed_json_are_rejected(self) -> None:
        duplicate = self.canonical.replace(
            b'"sealed":false',
            b'"sealed":false,"sealed":false',
            1,
        )
        nonfinite = self.canonical.replace(b'"family_count":25', b'"family_count":NaN', 1)
        invalid_utf8 = self.canonical[:-2] + b"\xff\n"
        malformed = self.canonical[:-2] + b"\n"
        for payload in (duplicate, nonfinite, invalid_utf8, malformed):
            with self.subTest(payload=payload[-32:]):
                self.assert_rejected(payload)

    def test_deeply_nested_json_is_wrapped_in_the_coverage_error_type(self) -> None:
        payload = b"[" * 4_000 + b"0" + b"]" * 4_000 + b"\n"
        self.assertLess(len(payload), MAXIMUM_COVERAGE_CONFIG_BYTES)
        self.assert_rejected(payload)

    def test_noncanonical_bytes_are_rejected(self) -> None:
        pretty = json.dumps(self.record, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"
        for payload in (
            self.canonical[:-1],
            self.canonical + b"\n",
            b" " + self.canonical,
            pretty,
        ):
            with self.subTest(size=len(payload)):
                self.assert_rejected(payload)

    def test_closed_schema_exact_scalar_types_and_rehashed_tamper_are_rejected(self) -> None:
        mutations: list[dict[str, object]] = []

        extra = copy.deepcopy(self.record)
        extra["extra"] = False
        mutations.append(extra)

        boolean_count = copy.deepcopy(self.record)
        boolean_count["family_count"] = True
        mutations.append(boolean_count)

        authority = copy.deepcopy(self.record)
        authority["sealed"] = True
        mutations.append(authority)

        family_tamper = copy.deepcopy(self.record)
        families = family_tamper["families"]
        assert type(families) is list and type(families[12]) is dict
        families[12]["allowed_tools"].append("touch")  # type: ignore[union-attr]
        rehash_record(family_tamper)
        mutations.append(family_tamper)

        source_tamper = copy.deepcopy(self.record)
        sources = source_tamper["source_registry_commitments"]
        assert type(sources) is list and type(sources[0]) is dict
        sources[0]["added_task_count"] = 99
        rehash_record(source_tamper)
        mutations.append(source_tamper)

        for record in mutations:
            record["coverage_sha256"] = compute_executable_development_coverage_sha256(record)
            with self.subTest(keys=tuple(record)):
                self.assert_rejected(canonical_json_bytes(record) + b"\n")

    def test_symlink_parent_symlink_directory_fifo_and_missing_path_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real.json"
            real.write_bytes(self.canonical)
            link = root / "link.json"
            link.symlink_to(real)
            with self.assertRaises(ExecutableDevelopmentCoverageError):
                load_executable_development_coverage(link)

            real_parent = root / "real-parent"
            real_parent.mkdir()
            nested = real_parent / "coverage.json"
            nested.write_bytes(self.canonical)
            linked_parent = root / "linked-parent"
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            with self.assertRaises(ExecutableDevelopmentCoverageError):
                load_executable_development_coverage(linked_parent / "coverage.json")

            with self.assertRaises(ExecutableDevelopmentCoverageError):
                load_executable_development_coverage(root)
            with self.assertRaises(ExecutableDevelopmentCoverageError):
                load_executable_development_coverage(root / "missing.json")

            fifo = root / "coverage.fifo"
            os.mkfifo(fifo)
            with self.assertRaises(ExecutableDevelopmentCoverageError):
                load_executable_development_coverage(fifo)

    def test_resource_limit_is_enforced_before_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "coverage.json"
            with path.open("wb") as handle:
                handle.truncate(MAXIMUM_COVERAGE_CONFIG_BYTES + 1)
            with self.assertRaisesRegex(
                ExecutableDevelopmentCoverageError, "byte limit"
            ):
                load_executable_development_coverage(path)

    def test_growth_during_read_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "coverage.json"
            path.write_bytes(self.canonical)
            real_read = os.read
            mutated = False

            def racing_read(descriptor: int, size: int) -> bytes:
                nonlocal mutated
                result = real_read(descriptor, size)
                if not mutated:
                    mutated = True
                    with path.open("ab") as handle:
                        handle.write(b" ")
                return result

            with mock.patch.object(coverage_module.os, "read", side_effect=racing_read):
                with self.assertRaisesRegex(
                    ExecutableDevelopmentCoverageError,
                    "grew|changed",
                ):
                    load_executable_development_coverage(path)

    def test_platform_without_no_follow_support_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "coverage.json"
            path.write_bytes(self.canonical)
            with mock.patch.object(coverage_module.os, "O_NOFOLLOW", None):
                with self.assertRaisesRegex(
                    ExecutableDevelopmentCoverageError, "no-follow|O_NOFOLLOW"
                ):
                    load_executable_development_coverage(path)


if __name__ == "__main__":
    unittest.main()
