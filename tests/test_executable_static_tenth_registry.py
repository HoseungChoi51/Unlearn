from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import cbds.executable_static_tenth_registry as tenth_registry  # noqa: E402
from cbds.executable_compressed_archive_roundtrip_verify import (  # noqa: E402
    COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_COMPRESSION_FORMATS,
    COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_VERIFICATION_POLICIES,
    CompressedArchiveRoundtripVerifyTask,
)
from cbds.executable_ninth_predecessor_evidence import (  # noqa: E402
    FROZEN_NINTH_CUMULATIVE_SUITE_SHA256,
    FROZEN_NINTH_REGISTRY_SHA256,
    NINTH_PREFIX_TASK_COUNT,
    build_ninth_prefix_task_evidence,
)
from cbds.executable_static_tenth_registry import (  # noqa: E402
    TENTH_TRANCHE_ADDED_TASK_COUNT,
    TENTH_TRANCHE_CUMULATIVE_TASK_COUNT,
    TENTH_TRANCHE_FAMILY_ORDER,
    TenthTrancheRegistryError,
    build_tenth_tranche_added_tasks,
    build_tenth_tranche_task_registry,
    compute_tenth_tranche_cumulative_suite_sha256,
    compute_tenth_tranche_registry_sha256,
    validate_tenth_tranche_task_registry,
)
from cbds.executable_static_types import domain_sha256  # noqa: E402


EXPECTED_ARCHIVE_TASK_SET_SHA256 = (
    "450ba507f0672e3a47ca6d495a6553d07294c605f94b3c5f03aa111d42bf771a"
)
EXPECTED_TENTH_REGISTRY_SHA256 = (
    "0d07fd82de275ffd9dc274b97a6fa02fdd0620f83d5ee90a2bea0ad64f06f0ab"
)
EXPECTED_TENTH_CUMULATIVE_SUITE_SHA256 = (
    "629119116c53a0be2cc7cacb5461ae13de7d50f29b0a129707a840089ab48d2f"
)


class TenthTrancheTaskRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.predecessors = build_ninth_prefix_task_evidence()
        cls.registry = build_tenth_tranche_task_registry(cls.predecessors)

    def assert_registry_invalid(self, registry: object) -> None:
        with self.assertRaises(
            (TenthTrancheRegistryError, TypeError, ValueError)
        ):
            validate_tenth_tranche_task_registry(  # type: ignore[arg-type]
                registry
            )

    def test_grid_has_exact_type_order_and_unique_identities(self) -> None:
        tasks = self.registry.added_tasks
        self.assertEqual(len(tasks), TENTH_TRANCHE_ADDED_TASK_COUNT)
        self.assertEqual(TENTH_TRANCHE_ADDED_TASK_COUNT, 20)
        self.assertEqual(TENTH_TRANCHE_CUMULATIVE_TASK_COUNT, 380)
        self.assertEqual(
            TENTH_TRANCHE_FAMILY_ORDER,
            ("compressed-archive-roundtrip-verify",),
        )
        self.assertTrue(
            all(
                type(task) is CompressedArchiveRoundtripVerifyTask
                for task in tasks
            )
        )
        self.assertEqual(
            tuple(
                (
                    task.parameters.compression_format,
                    task.parameters.verification_policy,
                )
                for task in tasks
            ),
            tuple(
                (compression_format, verification_policy)
                for compression_format in (
                    COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_COMPRESSION_FORMATS
                )
                for verification_policy in (
                    COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_VERIFICATION_POLICIES
                )
            ),
        )
        self.assertEqual(len({task.task_id for task in tasks}), 20)
        self.assertEqual(len({task.task_contract_sha256 for task in tasks}), 20)
        self.assertEqual(len({task.graph_sha256 for task in tasks}), 20)
        for task in tasks:
            task.__post_init__()
            self.assertIs(task.public, True)
            self.assertIs(task.sealed, False)
            self.assertIs(task.candidate_execution_authorized, False)
            self.assertIs(task.model_selection_eligible, False)
            self.assertIs(task.claim_authorized, False)
            self.assertEqual(len(task.fixtures), 5)

    def test_hashes_are_frozen_and_domain_separated_as_tenth(self) -> None:
        tasks = self.registry.added_tasks
        self.assertEqual(
            self.registry.registry_sha256,
            EXPECTED_TENTH_REGISTRY_SHA256,
        )
        self.assertEqual(
            self.registry.cumulative_suite_sha256,
            EXPECTED_TENTH_CUMULATIVE_SUITE_SHA256,
        )
        self.assertEqual(
            self.registry.registry_sha256,
            compute_tenth_tranche_registry_sha256(tasks),
        )
        self.assertEqual(
            self.registry.cumulative_suite_sha256,
            compute_tenth_tranche_cumulative_suite_sha256(
                tasks, self.registry.registry_sha256
            ),
        )
        self.assertEqual(
            domain_sha256(
                (
                    "cbds.executable-method-development-coverage."
                    "integrated-task-set.v1"
                ),
                {
                    "family_id": "compressed-archive-roundtrip-verify",
                    "task_count": len(tasks),
                    "task_id": [task.task_id for task in tasks],
                    "task_contract_sha256": [
                        task.task_contract_sha256 for task in tasks
                    ],
                    "graph_sha256": [
                        task.graph_sha256 for task in tasks
                    ],
                },
            ),
            EXPECTED_ARCHIVE_TASK_SET_SHA256,
        )

    def test_exact_ninth_anchors_and_global_uniqueness(self) -> None:
        self.assertEqual(NINTH_PREFIX_TASK_COUNT, 360)
        self.assertEqual(
            self.predecessors.terminal_registry_sha256,
            FROZEN_NINTH_REGISTRY_SHA256,
        )
        self.assertEqual(
            self.predecessors.terminal_cumulative_suite_sha256,
            FROZEN_NINTH_CUMULATIVE_SUITE_SHA256,
        )
        self.assertEqual(
            self.registry.base_added_registry_sha256,
            "ff886754b054445a90ad30197d004e4071dba72bf0af17931d05e461c7e90703",
        )
        self.assertEqual(
            self.registry.base_cumulative_suite_sha256,
            "d0647e24f29abd59f8c2d6b2ac2a404aee78b92c780f8be4f9b16d200885843b",
        )
        tasks = (*self.predecessors.tasks, *self.registry.added_tasks)
        self.assertEqual(len(tasks), 380)
        self.assertEqual(len({task.task_id for task in tasks}), 380)
        self.assertEqual(
            len({task.task_contract_sha256 for task in tasks}), 380
        )
        self.assertEqual(len({task.graph_sha256 for task in tasks}), 380)

    def test_supplied_prefix_is_reused_without_rebuild(self) -> None:
        with mock.patch.object(
            tenth_registry,
            "build_ninth_prefix_task_evidence",
            side_effect=AssertionError("through-ninth prefix rebuilt"),
        ):
            rebuilt = build_tenth_tranche_task_registry(self.predecessors)
        self.assertEqual(rebuilt, self.registry)

    def test_default_build_passes_live_linear_evidence_into_ninth(self) -> None:
        import cbds.executable_ninth_predecessor_evidence as prefix

        real = prefix.build_ninth_tranche_task_registry
        seen: list[object] = []

        def checked(evidence=None):
            self.assertIsNotNone(evidence)
            seen.append(evidence)
            return real(evidence)

        with mock.patch.object(
            prefix,
            "build_ninth_tranche_task_registry",
            side_effect=checked,
        ):
            rebuilt = build_tenth_tranche_task_registry()
        self.assertEqual(rebuilt, self.registry)
        self.assertEqual(len(seen), 1)

    def test_repeated_builds_have_fresh_addition_ownership(self) -> None:
        first = build_tenth_tranche_added_tasks()
        second = build_tenth_tranche_added_tasks()
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        for left, right in zip(first, second, strict=True):
            self.assertIsNot(left, right)
            self.assertIsNot(left.parameters, right.parameters)
            self.assertTrue(
                all(left is not item for item in self.predecessors.tasks)
            )

    def test_hash_projection_and_mutations_fail_closed(self) -> None:
        record = self.registry.to_hash_only_record()
        self.assertEqual(
            record["record_type"],
            "cbds.executable-static-tenth-tranche-registry-hashes",
        )
        self.assertEqual(record["base_cumulative_task_count"], 360)
        self.assertEqual(record["added_task_count"], 20)
        self.assertEqual(record["cumulative_task_count"], 380)
        self.assertEqual(
            record["family_task_counts"],
            {"compressed-archive-roundtrip-verify": 20},
        )
        self.assertIs(record["public_method_development"], True)
        for key in (
            "sealed",
            "candidate_execution_authorized",
            "model_selection_eligible",
            "claim_authorized",
        ):
            self.assertIs(record[key], False)

        reordered = copy.copy(self.registry)
        object.__setattr__(
            reordered,
            "added_tasks",
            (
                self.registry.added_tasks[1],
                self.registry.added_tasks[0],
                *self.registry.added_tasks[2:],
            ),
        )
        self.assert_registry_invalid(reordered)

        hostile = copy.deepcopy(self.registry)
        object.__setattr__(
            hostile.added_tasks[0].parameters,
            "compression_format",
            "zip",
        )
        self.assert_registry_invalid(hostile)

        forged = copy.copy(self.registry)
        object.__setattr__(forged, "candidate_execution_authorized", True)
        self.assert_registry_invalid(forged)
        self.assert_registry_invalid(object())


if __name__ == "__main__":
    unittest.main()
